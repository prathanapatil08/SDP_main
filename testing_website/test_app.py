import csv
import msvcrt
import re
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import psutil
import streamlit as st
from streamlit_autorefresh import st_autorefresh


BASE_DIR = Path(__file__).resolve().parent.parent
FLASK_SCRIPT = BASE_DIR / "app" / "main.py"
SELF_HEALING_SCRIPT = BASE_DIR / "app" / "self_healing.py"
ANOMALY_SCRIPT = BASE_DIR / "ml" / "detect_anomalies.py"
ROOT_CAUSE_SCRIPT = BASE_DIR / "ml" / "root_cause.py"
METRICS_FILE = BASE_DIR / "data" / "metrics.csv"
MONITOR_SCRIPT = BASE_DIR / "app" / "monitor.py"
MONITOR_LOG_FILE = BASE_DIR / "logs" / "monitor.log"
MONITOR_LOCK_FILE = BASE_DIR / "logs" / "monitor-start.lock"
ANOMALY_FILE = BASE_DIR / "data" / "anomaly_results.csv"
FLASK_URL = "http://127.0.0.1:5000/health"
MAX_LOAD_SECONDS = 30
MAX_MEMORY_LOAD_MB = 64
DEFAULT_MEMORY_LOAD_MB = 32
MIN_AVAILABLE_MEMORY_MIB = 512
MIN_AI_MEMORY_MIB = 512
MIN_RCA_MEMORY_MIB = 256
WORKER_READY_MARKER = "AIOPS_WORKLOAD_READY"
_monitor_start_lock = threading.Lock()

CPU_WORKER = """
import sys
import time

duration = float(sys.argv[1])
deadline = time.monotonic() + duration
values = range(20_000)
accumulator = 0
ready = False
last_report = time.monotonic()
while time.monotonic() < deadline:
    for value in values:
        accumulator = (accumulator * 33 + value * value) & 0xFFFFFFFF
    if not ready:
        print("AIOPS_WORKLOAD_READY", flush=True)
        ready = True
    now = time.monotonic()
    if now - last_report >= 1:
        print(f"AIOPS_CPU_SECONDS:{time.process_time():.6f}", flush=True)
        last_report = now
"""

MEMORY_WORKER = """
import sys
import time
import psutil

duration = float(sys.argv[1])
size_mb = int(sys.argv[2])
if not 1 <= size_mb <= 64:
    raise ValueError("Memory workload must be between 1 and 64 MB.")
size = size_mb * 1_000_000
payload = bytearray(size)
for offset in range(0, size, 4096):
    payload[offset] = 1
print(
    f"AIOPS_MEMORY_RSS_MIB:{psutil.Process().memory_info().rss / (1024 * 1024):.2f}",
    flush=True,
)
print("AIOPS_WORKLOAD_READY", flush=True)
deadline = time.monotonic() + duration
while time.monotonic() < deadline:
    time.sleep(0.25)
del payload
"""


class LoadManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._script_lock = threading.Lock()
        self._processes = {}
        self._states = {"cpu": "stopped", "memory": "stopped"}
        self._auto_stopped = []
        self._resource_samples = {
            "cpu": {"before": None, "during": None, "after": None},
            "memory": {"before": None, "during": None, "after": None},
        }
        self._diagnostics = {
            kind: {
                "button_click_received": False,
                "workload_function_executed": False,
                "process_creation_succeeded": False,
                "pid": None,
                "process_running": False,
                "cpu_usage_percent": None,
                "psutil_cpu_usage_percent": None,
                "memory_rss_mib": None,
                "memory_allocated_mb": None,
                "exit_code": None,
                "error": None,
            }
            for kind in ("cpu", "memory")
        }
        self._cpu_samples = []
        self._worker_memory_rss_mib = None
        self._script_job = None
        self._next_script_job_id = 1

    def note_button_click(self, kind):
        with self._lock:
            self._diagnostics[kind]["button_click_received"] = True

    def start_script(self, script, timeout, arguments=None):
        if not self._script_lock.acquire(blocking=False):
            raise RuntimeError("Another project analysis or recovery script is already running.")
        try:
            minimum_memory = None
            if Path(script).resolve() == ANOMALY_SCRIPT.resolve():
                minimum_memory = MIN_AI_MEMORY_MIB
            elif Path(script).resolve() == ROOT_CAUSE_SCRIPT.resolve():
                minimum_memory = MIN_RCA_MEMORY_MIB
            if minimum_memory is not None:
                available_mib = psutil.virtual_memory().available / (1024 * 1024)
                if available_mib < minimum_memory:
                    raise RuntimeError(
                        f"Analysis requires at least {minimum_memory} MiB available RAM; "
                        f"current available memory is {available_mib:.0f} MiB."
                    )
        except (OSError, RuntimeError, ValueError, psutil.Error):
            self._script_lock.release()
            raise

        with self._lock:
            job = {
                "id": self._next_script_job_id,
                "script": Path(script).resolve(),
                "state": "running",
                "result": None,
                "error": None,
            }
            self._next_script_job_id += 1
            self._script_job = job

        def execute():
            try:
                result = subprocess.run(
                    [sys.executable, str(script)] + list(arguments or []),
                    cwd=str(BASE_DIR),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                )
                with self._lock:
                    job["result"] = result
                    job["state"] = "completed"
            except Exception as error:
                with self._lock:
                    job["error"] = error
                    job["state"] = "failed"
            finally:
                self._script_lock.release()

        worker = threading.Thread(target=execute, daemon=True)
        try:
            worker.start()
        except (OSError, RuntimeError):
            with self._lock:
                if self._script_job is job:
                    self._script_job = None
            self._script_lock.release()
            raise
        return job["id"]

    def script_job(self):
        with self._lock:
            return None if self._script_job is None else dict(self._script_job)

    def state(self, kind):
        with self._lock:
            process = self._processes.get(kind)
            if process is not None and process.poll() is None:
                self._diagnostics[kind]["process_running"] = True
                return "running"
            if self._states[kind] == "running":
                self._states[kind] = "stopped"
                if process is not None:
                    self._diagnostics[kind]["exit_code"] = process.returncode
                self._diagnostics[kind]["process_running"] = False
                self._resource_samples[kind]["after"] = read_system_usage()
                self._auto_stopped.append(kind)
            return self._states[kind]

    def workload_pid(self, kind):
        with self._lock:
            process = self._processes.get(kind)
            return process.pid if process is not None and process.poll() is None else None

    def diagnostics(self, kind):
        with self._lock:
            process = self._processes.get(kind)
            diagnostics = self._diagnostics[kind]
            if process is not None:
                exit_code = process.poll()
                diagnostics["process_running"] = exit_code is None
                if exit_code is not None:
                    diagnostics["exit_code"] = exit_code
                if exit_code is None:
                    try:
                        worker = psutil.Process(process.pid)
                        diagnostics["psutil_cpu_usage_percent"] = (
                            worker.cpu_percent()
                        )
                        diagnostics["memory_rss_mib"] = (
                            worker.memory_info().rss / (1024 * 1024)
                        )
                    except psutil.Error as error:
                        diagnostics["error"] = str(error)
                if kind == "memory" and self._worker_memory_rss_mib is not None:
                    diagnostics["memory_rss_mib"] = self._worker_memory_rss_mib
                if kind == "cpu" and len(self._cpu_samples) >= 2:
                    previous, latest = self._cpu_samples[-2:]
                    elapsed = latest[0] - previous[0]
                    if elapsed > 0:
                        diagnostics["cpu_usage_percent"] = (
                            (latest[1] - previous[1]) / elapsed * 100
                        )
            return dict(diagnostics)

    def workload_cpu_percent(self, kind):
        return self.diagnostics(kind)["cpu_usage_percent"]

    def consume_auto_stops(self):
        with self._lock:
            stopped = self._auto_stopped[:]
            self._auto_stopped.clear()
            return stopped

    def resource_samples(self, kind):
        with self._lock:
            return dict(self._resource_samples[kind])

    def record_during_usage(self, kind, usage, process_cpu_percent=None):
        with self._lock:
            if self._states[kind] == "running":
                process = self._processes.get(kind)
                self._resource_samples[kind]["during"] = {
                    **usage,
                    "process_cpu_percent": process_cpu_percent,
                    "pid": process.pid
                    if process is not None and process.poll() is None
                    else None,
                }

    def start(self, kind, duration, memory_mb=DEFAULT_MEMORY_LOAD_MB):
        if kind not in ("cpu", "memory"):
            raise ValueError("Unknown workload type.")
        with self._lock:
            diagnostics = self._diagnostics[kind]
            diagnostics.update(
                workload_function_executed=True,
                process_creation_succeeded=False,
                pid=None,
                process_running=False,
                cpu_usage_percent=None,
                psutil_cpu_usage_percent=None,
                memory_rss_mib=None,
                memory_allocated_mb=memory_mb if kind == "memory" else None,
                exit_code=None,
                error=None,
            )
            process = None
            try:
                if not 1 <= duration <= MAX_LOAD_SECONDS:
                    raise ValueError(
                        f"Workload duration must be at most {MAX_LOAD_SECONDS} seconds."
                    )
                if kind == "memory" and not 1 <= memory_mb <= MAX_MEMORY_LOAD_MB:
                    raise ValueError(
                        f"Memory allocation must be between 1 and {MAX_MEMORY_LOAD_MB} MB."
                    )
                if any(
                    process.poll() is None
                    for process in self._processes.values()
                ):
                    raise RuntimeError(
                        "A load test is already running. Stop it before starting another."
                    )

                if kind == "memory":
                    available_mib = psutil.virtual_memory().available / (1024 * 1024)
                    allocation_mib = memory_mb * 1_000_000 / (1024 * 1024)
                    required_mib = allocation_mib + MIN_AVAILABLE_MEMORY_MIB
                    if available_mib < required_mib:
                        raise RuntimeError(
                            f"Memory test requires at least {required_mib:.0f} MiB available "
                            f"({memory_mb} MB allocation plus {MIN_AVAILABLE_MEMORY_MIB} MiB safety reserve); "
                            f"current available memory is {available_mib:.0f} MiB."
                        )

                code = CPU_WORKER if kind == "cpu" else MEMORY_WORKER
                args = [sys.executable, "-c", code, str(duration)]
                if kind == "memory":
                    args.append(str(memory_mb))

                creationflags = (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                before = read_system_usage()
                process = subprocess.Popen(
                    args,
                    cwd=str(BASE_DIR),
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    creationflags=creationflags,
                )
                diagnostics.update(
                    process_creation_succeeded=True,
                    pid=process.pid,
                )
                self._processes[kind] = process
                output_lines = []
                ready_event = threading.Event()
                self._cpu_samples = []
                self._worker_memory_rss_mib = None

                def capture_output():
                    if process.stdout is None:
                        return
                    try:
                        for output_line in process.stdout:
                            line = output_line.rstrip()
                            if line == WORKER_READY_MARKER:
                                ready_event.set()
                                continue
                            elif kind == "cpu" and line.startswith(
                                "AIOPS_CPU_SECONDS:"
                            ):
                                try:
                                    cpu_seconds = float(line.split(":", 1)[1])
                                    self._cpu_samples.append(
                                        (time.monotonic(), cpu_seconds)
                                    )
                                except ValueError:
                                    output_lines.append(line)
                            elif kind == "memory" and line.startswith(
                                "AIOPS_MEMORY_RSS_MIB:"
                            ):
                                try:
                                    self._worker_memory_rss_mib = float(
                                        line.split(":", 1)[1]
                                    )
                                except ValueError:
                                    output_lines.append(line)
                            elif line:
                                output_lines.append(line)
                    finally:
                        process.stdout.close()
                        exit_code = process.poll()
                        if exit_code is not None:
                            with self._lock:
                                diagnostics["process_running"] = False
                                diagnostics["exit_code"] = exit_code
                                if exit_code != 0 and self._states[kind] == "running":
                                    diagnostics["error"] = (
                                        "\n".join(output_lines).strip()
                                        or f"{kind.title()} worker exited with code {exit_code}."
                                    )

                output_reader = threading.Thread(
                    target=capture_output,
                    name=f"{kind}-workload-output-{process.pid}",
                    daemon=True,
                )
                output_reader.start()
                if not ready_event.wait(timeout=1):
                    error_detail = "\n".join(output_lines).strip()
                    reason = (
                        f"{kind.title()} worker did not report readiness within 1 second."
                    )
                    if process.poll() is not None:
                        reason = (
                            f"{kind.title()} worker exited before reporting readiness "
                            f"(exit code {process.returncode})."
                        )
                    if error_detail:
                        reason = f"{reason}\nWorker output:\n{error_detail}"
                    raise RuntimeError(reason)

                self._states[kind] = "running"
                diagnostics["process_running"] = process.poll() is None
                if not diagnostics["process_running"]:
                    diagnostics["exit_code"] = process.returncode
                    raise RuntimeError(
                        f"{kind.title()} worker exited immediately after creation "
                        f"(exit code {process.returncode})."
                    )
                self._resource_samples[kind] = {
                    "before": {**before, "process_cpu_percent": None, "pid": None},
                    "during": None,
                    "after": None,
                }
                if kind == "cpu":
                    psutil.Process(process.pid).cpu_percent()
            except (OSError, RuntimeError, ValueError, psutil.Error) as error:
                diagnostics["error"] = str(error)
                if process is not None:
                    if process.poll() is None:
                        process.terminate()
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=5)
                    diagnostics["exit_code"] = process.returncode
                    diagnostics["process_running"] = False
                    self._states[kind] = "stopped"
                elif diagnostics["pid"] is None:
                    diagnostics["process_running"] = False
                raise

    def stop(self, kind):
        with self._lock:
            process = self._processes.get(kind)
            if process is None or process.poll() is not None:
                if self._states[kind] == "running":
                    self._states[kind] = "stopped"
                if process is not None:
                    self._diagnostics[kind]["exit_code"] = process.returncode
                self._diagnostics[kind]["process_running"] = False
                return False

            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            self._states[kind] = "stopped"
            self._diagnostics[kind].update(
                process_running=False,
                exit_code=process.returncode,
            )
            after = read_system_usage()
            self._resource_samples[kind]["after"] = {
                **after,
                "process_cpu_percent": None,
                "pid": process.pid,
            }
            return True

    def stop_all(self):
        return {
            kind: self.stop(kind)
            for kind in ("cpu", "memory")
        }


@st.cache_resource(show_spinner=False)
def get_load_manager():
    return LoadManager()


def read_system_usage():
    cpu_percent = psutil.cpu_percent(interval=None)
    memory = psutil.virtual_memory()
    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "cpu_usage": cpu_percent,
        "memory_usage": memory.percent,
        "available_memory_mb": round(memory.available / (1024 * 1024), 2),
    }


def monitoring_process_pids():
    pids = []
    for process in psutil.process_iter(["pid", "name"]):
        try:
            if (process.info["name"] or "").lower() not in ("python.exe", "pythonw.exe"):
                continue
            arguments = process.cmdline()
            for argument in arguments:
                candidate = Path(argument)
                if candidate.name.lower() != MONITOR_SCRIPT.name.lower():
                    continue
                if not candidate.is_absolute():
                    working_directory = Path(process.cwd() or BASE_DIR)
                    candidate = working_directory / candidate
                if candidate.resolve() == MONITOR_SCRIPT.resolve():
                    pids.append(process.info["pid"])
                    break
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            continue
        except (psutil.AccessDenied, OSError):
            continue
    return pids


def ensure_monitor_running():
    with _monitor_start_lock:
        pids = monitoring_process_pids()
        if pids:
            return pids

        MONITOR_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with MONITOR_LOCK_FILE.open("a+b") as lock_file:
            if lock_file.seek(0, 2) == 0:
                lock_file.write(b"\0")
                lock_file.flush()
            lock_file.seek(0)
            try:
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                for _ in range(30):
                    pids = monitoring_process_pids()
                    if pids:
                        return pids
                    time.sleep(0.1)
                raise RuntimeError(
                    "Another control-panel session is starting the monitor, "
                    "but its process could not be verified."
                )

            try:
                pids = monitoring_process_pids()
                if pids:
                    return pids

                creationflags = (
                    getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                    | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                with MONITOR_LOG_FILE.open("a", encoding="utf-8") as monitor_log:
                    process = subprocess.Popen(
                        [sys.executable, str(MONITOR_SCRIPT)],
                        cwd=str(BASE_DIR),
                        stdin=subprocess.DEVNULL,
                        stdout=monitor_log,
                        stderr=subprocess.STDOUT,
                        creationflags=creationflags,
                    )

                for _ in range(30):
                    if process.poll() is not None:
                        raise RuntimeError(
                            "The monitoring process exited during startup. "
                            f"See {MONITOR_LOG_FILE} for details."
                        )
                    pids = monitoring_process_pids()
                    if pids:
                        return pids
                    time.sleep(0.1)

                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                raise RuntimeError(
                    "The monitoring process started but could not be verified. "
                    f"See {MONITOR_LOG_FILE} for details."
                )
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)


def read_latest_metric_row():
    if not METRICS_FILE.exists():
        return None
    with METRICS_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        latest = None
        for row in reader:
            latest = row
    return latest


def format_csv_metric(row, column, unit):
    if not row or row.get(column) is None:
        return "Unavailable"
    try:
        return f"{float(row[column]):.1f}{unit}"
    except (TypeError, ValueError):
        return "Invalid CSV value"


def flask_is_healthy():
    try:
        with urlopen(FLASK_URL, timeout=1) as response:
            return response.status == 200
    except (URLError, TimeoutError, OSError):
        return False


def _is_project_flask_process(process):
    try:
        command_line = process.cmdline()
        working_directory = Path(process.cwd())
    except psutil.NoSuchProcess:
        return False
    except psutil.AccessDenied as error:
        raise RuntimeError(
            f"Cannot safely inspect process {process.pid}; access was denied."
        ) from error

    for argument in command_line:
        candidate = Path(argument)
        if candidate.name.lower() != FLASK_SCRIPT.name.lower():
            continue
        if not candidate.is_absolute():
            candidate = working_directory / candidate
        try:
            if candidate.resolve() == FLASK_SCRIPT.resolve():
                return True
        except OSError:
            continue
    return False


def stop_project_flask():
    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied as error:
        raise RuntimeError(
            "Windows denied access to the port-5000 process list; Flask was not stopped."
        ) from error

    listener_pids = {
        connection.pid
        for connection in connections
        if connection.laddr
        and connection.laddr.port == 5000
        and connection.status == psutil.CONN_LISTEN
    }
    if not listener_pids:
        return False

    project_processes = []
    for pid in listener_pids:
        if pid is None:
            raise RuntimeError(
                "A port-5000 listener has no visible process ID; refusing to stop an unidentified process."
            )
        try:
            process = psutil.Process(pid)
            if _is_project_flask_process(process):
                project_processes.append(process)
        except psutil.NoSuchProcess:
            continue

    if not project_processes:
        raise RuntimeError(
            "Port 5000 is in use, but its listener is not this project's app/main.py. "
            "For safety, it was left running."
        )

    for process in project_processes:
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as error:
            raise RuntimeError(
                f"Windows denied permission to stop project Flask process {process.pid}."
            ) from error

    _, alive = psutil.wait_procs(project_processes, timeout=5)
    for process in alive:
        try:
            process.kill()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as error:
            raise RuntimeError(
                f"Windows denied permission to finish stopping Flask process {process.pid}."
            ) from error

    if alive:
        _, still_alive = psutil.wait_procs(alive, timeout=5)
        if still_alive:
            raise RuntimeError("The project Flask process did not stop after termination.")

    return True


def run_project_script(script, timeout=45, arguments=None):
    return get_load_manager().start_script(script, timeout, arguments)


def count_anomalies():
    with ANOMALY_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or "status" not in reader.fieldnames:
            raise RuntimeError("The anomaly results file has no status column.")
        rows = list(reader)
    return len(rows), sum(row.get("status") == "Anomaly" for row in rows)


def latest_incident():
    incident_file = BASE_DIR / "data" / "incident_reports.csv"
    if not incident_file.exists():
        return None
    with incident_file.open("r", newline="", encoding="utf-8-sig") as file:
        rows = list(csv.DictReader(file))
    return rows[-1] if rows else None


def parse_rca_output(output):
    severity_match = re.search(r"Incident Severity:\s*(.+)", output)
    if not severity_match:
        return None
    confidence_match = re.search(
        r"Root Cause Confidence:\s*(\d+)%", output
    )

    def section(start, end):
        match = re.search(
            rf"{re.escape(start)}\s*\n(.*?)(?=\n{re.escape(end)}|\Z)",
            output,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if not match:
            return []
        return [
            line.strip().lstrip("- ").strip()
            for line in match.group(1).splitlines()
            if line.strip()
        ]

    return {
        "severity": severity_match.group(1).strip(),
        "confidence": (
            int(confidence_match.group(1))
            if confidence_match
            else None
        ),
        "timeline": section("Incident Timeline:", "Detected Symptoms:"),
        "symptoms": section("Detected Symptoms:", "Supporting Evidence:"),
        "evidence": section("Supporting Evidence:", "Root Cause Confidence:"),
        "confidence_basis": section(
            "Confidence Basis:", "Possible Root Cause:"
        ),
        "causes": section("Possible Root Cause:", "Recommended Actions:"),
        "recommendations": section("Recommended Actions:", "Incident report saved to:"),
    }


def add_history(action, success, details):
    st.session_state.history.insert(
        0,
        {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "result": "Success" if success else "Failed",
            "details": details,
        },
    )
    del st.session_state.history[100:]


def render_workload_diagnostics(manager, kind):
    diagnostics = manager.diagnostics(kind)
    st.caption(
        f"Diagnostics · button click received: "
        f"{'Yes' if diagnostics['button_click_received'] else 'No'} · workload function executed: "
        f"{'Yes' if diagnostics['workload_function_executed'] else 'No'}"
    )
    st.caption(
        f"Process created: {'Yes' if diagnostics['process_creation_succeeded'] else 'No'} · "
        f"PID: {diagnostics['pid'] if diagnostics['pid'] is not None else '—'} · "
        f"Process running: {'Yes' if diagnostics['process_running'] else 'No'} · "
        f"Exit code: {diagnostics['exit_code'] if diagnostics['exit_code'] is not None else '—'}"
    )
    if kind == "cpu":
        cpu_usage = diagnostics["cpu_usage_percent"]
        st.caption(
            f"CPU worker process usage: "
            f"{f'{cpu_usage:.1f}%' if cpu_usage is not None else 'unavailable'}"
        )
        psutil_cpu = diagnostics["psutil_cpu_usage_percent"]
        st.caption(
            f"psutil.Process CPU sample: "
            f"{f'{psutil_cpu:.1f}%' if psutil_cpu is not None else 'unavailable'}"
        )
    else:
        memory_usage = diagnostics["memory_rss_mib"]
        st.caption(
            f"Memory allocation confirmed by worker: "
            f"{diagnostics['memory_allocated_mb']} MB · resident usage: "
            f"{f'{memory_usage:.1f} MiB' if memory_usage is not None else 'unavailable'}"
        )
    if diagnostics["error"]:
        with st.expander(f"Full {kind} workload error", expanded=True):
            st.code(diagnostics["error"])


st.set_page_config(
    page_title="AIOps Testing Control Panel",
    page_icon="🧪",
    layout="wide",
)

st_autorefresh(interval=5000, key="testing_panel_refresh")
st.session_state.setdefault("history", [])

st.markdown(
    """
    <style>
    .stApp { background: #f4f7fb; color: #000; }
    [data-testid="stHeader"] { background: rgba(244, 247, 251, 0.86); }
    .block-container { max-width: 1440px; padding-top: 2rem; padding-bottom: 3rem; }
    .hero {
        padding: 2rem 2.2rem; border-radius: 24px; color: white;
        background: radial-gradient(circle at 88% 16%, rgba(52, 211, 153, .38), transparent 25%),
                    radial-gradient(circle at 12% 100%, rgba(96, 165, 250, .4), transparent 34%),
                    linear-gradient(120deg, #111b3c, #164e63 58%, #0f766e);
        margin: .25rem 0 1.5rem; box-shadow: 0 18px 45px rgba(17, 35, 63, .18);
    }
    .hero h1 { color: white; font-size: 2.35rem; letter-spacing: -.04em; }
    .hero p { color: #000; margin-bottom: 0; font-size: 1.05rem; }
    .stApp p,
    .stApp label,
    .stApp small,
    .stApp li,
    .stApp a,
    .stApp [data-testid="stCaptionContainer"],
    .stApp [data-testid="stAlert"],
    .stApp [data-testid="stMetricLabel"],
    .stApp [data-testid="stMetricValue"],
    div.stButton > button {
        color: #000 !important;
    }
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #ffffff, #f1f8fb);
        border: 1px solid #dce8f1; border-radius: 18px;
        padding: 1rem 1.15rem; box-shadow: 0 7px 22px rgba(25, 55, 90, .07);
    }
    [data-testid="stMetricLabel"] { font-weight: 650; }
    div.stButton > button {
        border-radius: 12px; min-height: 2.8rem; font-weight: 650;
        border: 1px solid #cbd9e6; transition: transform .15s ease, box-shadow .15s ease;
    }
    div.stButton > button:hover { transform: translateY(-1px); box-shadow: 0 7px 16px rgba(25, 55, 90, .13); }
    [data-testid="stVerticalBlockBorderWrapper"] { border-radius: 18px; border-color: #d9e5ef; }
    [data-testid="stAlert"] { border-radius: 14px; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class="hero">
      <h1>🧪 AIOps Testing Control Panel</h1>
      <p>Safe, bounded real-machine tests for CPU, memory, monitoring, anomaly detection,
      root-cause analysis, and recovery.</p>
    </div>
    """,
    unsafe_allow_html=True,
)

manager = get_load_manager()
cpu_state = manager.state("cpu")
memory_state = manager.state("memory")
flask_healthy = flask_is_healthy()
available_memory_mib = psutil.virtual_memory().available / (1024 * 1024)
live_usage = read_system_usage()
cpu_worker_pid = manager.workload_pid("cpu")
memory_worker_pid = manager.workload_pid("memory")
cpu_worker_percent = manager.workload_cpu_percent("cpu")
if cpu_state == "running":
    manager.record_during_usage("cpu", live_usage, cpu_worker_percent)
if memory_state == "running":
    manager.record_during_usage("memory", live_usage)
try:
    monitor_pids = ensure_monitor_running()
except (OSError, RuntimeError) as error:
    monitor_pids = monitoring_process_pids()
    st.error(f"Could not ensure monitoring is running: {error}")
try:
    metrics_age_seconds = max(0, time.time() - METRICS_FILE.stat().st_mtime)
except FileNotFoundError:
    metrics_age_seconds = None
except OSError as error:
    metrics_age_seconds = None
    st.error(f"Could not inspect monitoring data freshness: {error}")
try:
    latest_metric_row = read_latest_metric_row()
except (OSError, UnicodeError, csv.Error) as error:
    latest_metric_row = None
    st.error(f"Could not read the latest monitoring CSV row: {error}")
script_job = manager.script_job()
script_running = script_job is not None and script_job["state"] == "running"
st.session_state.setdefault("ai_status", "Not run")
st.session_state.setdefault("rca_status", "Not run")

for kind in manager.consume_auto_stops():
    workload_name = "CPU" if kind == "cpu" else "Memory"
    add_history(
        f"{kind.upper()} workload stopped",
        True,
        f"{workload_name} workload stopped automatically after its selected duration.",
    )
    st.success(f"{workload_name} load stopped successfully!")

if script_job and script_job["state"] != "running":
    if st.session_state.get("handled_script_job_id") != script_job["id"]:
        result = script_job["result"]
        error = script_job["error"]
        output = ""
        if result is not None:
            output = "\n".join(
                part.strip()
                for part in (result.stdout, result.stderr)
                if part and part.strip()
            )

        action_names = {
            ANOMALY_SCRIPT: "Run AI Anomaly Detection",
            ROOT_CAUSE_SCRIPT: "Run Root Cause Analysis",
            SELF_HEALING_SCRIPT: "Run Recovery Policy",
        }
        action = action_names[script_job["script"]]
        success = error is None and result is not None and result.returncode == 0
        details = ""
        if success and script_job["script"] == SELF_HEALING_SCRIPT:
            recovery_result = re.search(
                r"^Recovery result:\s*(.+)$",
                output,
                flags=re.MULTILINE,
            )
            outcome = recovery_result.group(1).strip() if recovery_result else ""
            if outcome == "RECOVERED":
                success = flask_is_healthy()
                details = (
                    "RECOVERED: Flask health check passed."
                    if success
                    else "Recovery script returned success, but Flask health check failed."
                )
            else:
                details = "\n".join(
                    line
                    for line in output.splitlines()
                    if line.startswith(
                        (
                            "Incident:",
                            "Probable cause:",
                            "Policy decision:",
                            "Verification:",
                            "Escalation:",
                            "Approval source timestamp:",
                            "Top memory consumers:",
                            "Recovery result:",
                        )
                    )
                ) or "Recovery policy completed without a recovery result."

            if outcome == "APPROVAL_REQUIRED":
                approval_timestamp = re.search(
                    r"^Approval source timestamp:\s*(.+)$",
                    output,
                    flags=re.MULTILINE,
                )
                if approval_timestamp:
                    st.session_state.pending_memory_restart_timestamp = (
                        approval_timestamp.group(1).strip()
                    )
            else:
                st.session_state.pop("pending_memory_restart_timestamp", None)
        elif success and script_job["script"] == ANOMALY_SCRIPT:
            try:
                total, anomalies = count_anomalies()
                details = f"{anomalies} anomalies across {total} readings."
            except (OSError, csv.Error, RuntimeError) as count_error:
                details = f"Detection completed; could not read its result summary: {count_error}"
        elif result is not None and result.returncode != 0:
            details = (
                output
                if script_job["script"] == SELF_HEALING_SCRIPT and output
                else result.stderr.strip()
                or f"Script exited with code {result.returncode}."
            )
        elif error is not None:
            details = (
                f"Script exceeded its 45-second timeout."
                if isinstance(error, subprocess.TimeoutExpired)
                else str(error)
            )
            if isinstance(error, subprocess.TimeoutExpired):
                partial_parts = (error.stdout, error.stderr)
                output = "\n".join(
                    part.decode(errors="replace") if isinstance(part, bytes) else part
                    for part in partial_parts
                    if part
                ).strip()

        if script_job["script"] == ANOMALY_SCRIPT:
            st.session_state.ai_status = "Completed" if success else "Failed"
        elif script_job["script"] == ROOT_CAUSE_SCRIPT:
            st.session_state.rca_status = "Completed" if success else "Failed"

        if success:
            if script_job["script"] == SELF_HEALING_SCRIPT:
                if details.startswith("RECOVERED:"):
                    st.success(details)
                else:
                    st.info(f"Recovery policy completed:\n\n{details}")
            elif script_job["script"] == ANOMALY_SCRIPT:
                st.success("AI anomaly detection completed successfully.")
            else:
                st.success("Root cause analysis completed successfully.")
            add_history(action, True, details or "Completed successfully.")
        else:
            failure = details or "Script failed."
            st.error(f"{action} failed: {failure}")
            add_history(action, False, failure)
        incident = None
        if script_job["script"] == ROOT_CAUSE_SCRIPT:
            try:
                incident = latest_incident()
            except (OSError, UnicodeError, csv.Error) as incident_error:
                st.error(f"Could not refresh incident information: {incident_error}")

        st.session_state.script_completion = {
            "id": script_job["id"],
            "script": script_job["script"],
            "success": success,
            "output": output,
            "details": details,
            "incident": incident,
            "report": parse_rca_output(output)
            if script_job["script"] == ROOT_CAUSE_SCRIPT
            else None,
        }
        st.session_state.handled_script_job_id = script_job["id"]

status_columns = st.columns(3)
with status_columns[0]:
    flask_status = st.empty()
    flask_status.metric("Flask · port 5000", "Healthy" if flask_healthy else "Stopped")
with status_columns[1]:
    cpu_status = st.empty()
    cpu_status.metric("CPU test", cpu_state.title())
with status_columns[2]:
    memory_status = st.empty()
    memory_status.metric("Memory test", memory_state.title())

st.subheader("Actual system resource usage")
if st.button("Refresh live status", type="secondary"):
    st.toast("Workload and monitoring status refreshed.", icon="🔄")
usage_columns = st.columns(3)
system_cpu_metric = usage_columns[0].empty()
system_cpu_metric.metric("System CPU utilization", f"{live_usage['cpu_usage']:.1f}%")
worker_cpu_metric = usage_columns[1].empty()
worker_cpu_metric.metric(
    "CPU workload process utilization",
    f"{cpu_worker_percent:.1f}%" if cpu_worker_percent is not None else "Not running",
)
system_memory_metric = usage_columns[2].empty()
system_memory_metric.metric("System memory utilization", f"{live_usage['memory_usage']:.1f}%")
available_memory_metric = st.empty()
available_memory_metric.metric(
    "Available system memory",
    f"{live_usage['available_memory_mb']:.0f} MB",
)
cpu_pid_caption = st.empty()
if cpu_worker_pid is not None:
    cpu_pid_caption.caption(f"CPU worker PID: {cpu_worker_pid} · One worker process.")
memory_pid_caption = st.empty()
if memory_worker_pid is not None:
    memory_pid_caption.caption(f"Memory worker PID: {memory_worker_pid}")
st.caption(
    "System CPU and worker CPU are different measurements. One worker can use a full core "
    "without total system CPU reaching 85%. RCA's existing high-CPU threshold is 85% system CPU."
)
st.caption("Live system readings are real psutil values. The existing monitor saves system readings to data/metrics.csv.")
st.subheader("Monitoring integration")
monitor_columns = st.columns(4)
monitor_columns[0].metric(
    "Monitoring process",
    "Running" if monitor_pids else "Not running",
)
monitor_columns[1].metric(
    "Latest CSV timestamp",
    latest_metric_row.get("timestamp", "Unavailable")
    if latest_metric_row
    else "Unavailable",
)
monitor_columns[2].metric(
    "Latest CSV CPU",
    format_csv_metric(latest_metric_row, "cpu_usage", "%"),
)
monitor_columns[3].metric(
    "Latest CSV memory",
    format_csv_metric(latest_metric_row, "memory_usage", "%"),
)
st.caption(
    f"Available memory in latest CSV row: "
    f"{latest_metric_row.get('available_memory_mb', 'Unavailable')} MB · "
    f"Monitor PID(s): {', '.join(map(str, monitor_pids)) if monitor_pids else 'none'}"
)

usage_rows = []
for kind, label in (("cpu", "CPU workload"), ("memory", "Memory workload")):
    for phase in ("before", "during", "after"):
        usage = manager.resource_samples(kind)[phase]
        if usage is not None:
            usage_rows.append(
                {
                    "Workload": label,
                    "Phase": phase.title(),
                    "Timestamp": usage["timestamp"],
                    "System CPU": f"{usage['cpu_usage']:.1f}%",
                    "Worker CPU": (
                        f"{usage['process_cpu_percent']:.1f}%"
                        if usage.get("process_cpu_percent") is not None
                        else "—"
                    ),
                    "Worker PID": (
                        str(usage["pid"]) if usage.get("pid") is not None else "—"
                    ),
                    "System memory": f"{usage['memory_usage']:.1f}%",
                }
            )
if usage_rows:
    st.dataframe(usage_rows, hide_index=True, width="stretch")

if metrics_age_seconds is None or metrics_age_seconds > 15:
    st.warning(
        "Monitoring has started but has not written a fresh reading yet."
    )
else:
    st.caption(f"Monitoring data is fresh (updated {metrics_age_seconds:.0f} seconds ago).")

script_status_columns = st.columns(2)
with script_status_columns[0]:
    ai_status_metric = st.empty()
    ai_status_metric.metric("AI detection", st.session_state.ai_status)
with script_status_columns[1]:
    rca_status_metric = st.empty()
    rca_status_metric.metric("Root cause analysis", st.session_state.rca_status)

if script_running:
    st.info(f"Running {script_job['script'].name} in the background...")
completion = st.session_state.get("script_completion")
if completion:
    if completion["script"] == ANOMALY_SCRIPT and completion["success"]:
        try:
            total, anomalies = count_anomalies()
            st.caption(f"Anomalies detected: {anomalies} · Readings analyzed: {total}")
        except (OSError, csv.Error, RuntimeError) as error:
            st.error(f"Could not display anomaly results: {error}")
    elif completion["script"] == ROOT_CAUSE_SCRIPT and completion["incident"]:
        st.subheader("Latest incident report")
        st.dataframe([completion["incident"]], hide_index=True, width="stretch")
        if completion["report"]:
            st.metric("Incident severity", completion["report"]["severity"])
            if completion["report"]["confidence"] is not None:
                st.metric(
                    "RCA evidence confidence",
                    f"{completion['report']['confidence']}%",
                )
                st.caption(
                    "Heuristic evidence score, not a calibrated probability."
                )
            st.markdown("**Detected symptoms**")
            for symptom in completion["report"]["symptoms"]:
                st.write(f"- {symptom}")
            st.markdown("**Incident timeline**")
            for event in completion["report"]["timeline"]:
                st.write(f"- {event}")
            st.markdown("**Supporting evidence**")
            for evidence in completion["report"]["evidence"]:
                st.write(f"- {evidence}")
            st.markdown("**Possible root cause**")
            for cause in completion["report"]["causes"]:
                st.write(f"- {cause}")
            st.markdown("**Confidence basis**")
            for basis in completion["report"]["confidence_basis"]:
                st.write(f"- {basis}")
            st.markdown("**Recommendations**")
            for recommendation in completion["report"]["recommendations"]:
                st.write(f"- {recommendation}")
    elif completion["script"] == SELF_HEALING_SCRIPT and completion["success"]:
        flask_status.metric("Flask · port 5000", "Healthy")
    if completion["output"]:
        with st.expander(f"Output: {completion['script'].name}", expanded=True):
            st.code(completion["output"])

st.divider()

load_columns = st.columns(2)
with load_columns[0]:
    with st.container(border=True):
        st.subheader("⚙️ CPU workload")
        st.write("One worker process, one CPU core at most, with an automatic stop.")
        cpu_duration = st.selectbox(
            "CPU test duration",
            options=(15, 30),
            format_func=lambda value: f"{value} seconds",
            key="cpu_duration",
        )
        if st.button(
            "Start CPU Load",
            type="primary",
            disabled=cpu_state == "running" or memory_state == "running",
            width="stretch",
        ):
            manager.note_button_click("cpu")
            try:
                manager.start("cpu", cpu_duration)
                diagnostics = manager.diagnostics("cpu")
                if not diagnostics["process_running"]:
                    raise RuntimeError(
                        diagnostics["error"]
                        or "CPU worker did not remain alive after startup."
                    )
                cpu_state = "running"
                cpu_worker_pid = manager.workload_pid("cpu")
                cpu_worker_percent = manager.workload_cpu_percent("cpu")
                live_usage = read_system_usage()
                manager.record_during_usage("cpu", live_usage, cpu_worker_percent)
                system_cpu_metric.metric(
                    "System CPU utilization",
                    f"{live_usage['cpu_usage']:.1f}%",
                )
                worker_cpu_metric.metric(
                    "CPU workload process utilization",
                    f"{cpu_worker_percent:.1f}%"
                    if cpu_worker_percent is not None
                    else "Not running",
                )
                system_memory_metric.metric(
                    "System memory utilization",
                    f"{live_usage['memory_usage']:.1f}%",
                )
                available_memory_metric.metric(
                    "Available system memory",
                    f"{live_usage['available_memory_mb']:.0f} MB",
                )
                if cpu_worker_pid is not None:
                    cpu_pid_caption.caption(
                        f"CPU worker PID: {cpu_worker_pid} · One worker process."
                    )
                cpu_status.metric("CPU test", "Running")
                add_history("Start CPU Load", True, f"Started for up to {cpu_duration} seconds.")
                st.toast("CPU load started successfully!", icon="✅")
                st.success("CPU load started successfully!")
            except (OSError, RuntimeError, ValueError, psutil.Error) as error:
                add_history("Start CPU Load", False, str(error))
                st.toast(f"Could not start CPU workload: {error}", icon="❌")
                st.error(f"Could not start CPU workload: {error}")
        if st.button(
            "Stop CPU Load",
            disabled=cpu_state != "running",
            width="stretch",
        ):
            try:
                stopped = manager.stop("cpu")
                details = "CPU load stopped successfully!" if stopped else "No active CPU workload."
                cpu_state = "stopped"
                cpu_status.metric("CPU test", "Stopped")
                after_usage = manager.resource_samples("cpu")["after"]
                if after_usage is not None:
                    system_cpu_metric.metric(
                        "System CPU utilization",
                        f"{after_usage['cpu_usage']:.1f}%",
                    )
                    system_memory_metric.metric(
                        "System memory utilization",
                        f"{after_usage['memory_usage']:.1f}%",
                    )
                worker_cpu_metric.metric("CPU workload process utilization", "Not running")
                cpu_pid_caption.empty()
                add_history("Stop CPU Load", stopped, details)
                (st.success if stopped else st.info)(details)
            except (OSError, subprocess.TimeoutExpired) as error:
                add_history("Stop CPU Load", False, str(error))
                st.error(f"Could not stop CPU workload: {error}")
        render_workload_diagnostics(manager, "cpu")

with load_columns[1]:
    with st.container(border=True):
        st.subheader("🧠 Memory workload")
        st.write(
            f"Choose an allocation up to {MAX_MEMORY_LOAD_MB} MB. The workload "
            "touches each memory page and keeps it allocated until stopped."
        )
        memory_size_mb = st.selectbox(
            "Memory allocation",
            options=(16, 32, 48, 64),
            index=1,
            format_func=lambda value: f"{value} MB",
            key="memory_size_mb",
        )
        allocation_memory_mib = memory_size_mb * 1_000_000 / (1024 * 1024)
        required_memory_mib = allocation_memory_mib + MIN_AVAILABLE_MEMORY_MIB
        st.caption(f"Available now: {available_memory_mib:.0f} MiB.")
        if available_memory_mib < required_memory_mib:
            st.warning(
                f"Memory test needs at least {required_memory_mib} MiB available "
                f"({memory_size_mb} MB allocation plus safety reserve)."
            )
        memory_duration = st.selectbox(
            "Memory test duration",
            options=(15, 30),
            format_func=lambda value: f"{value} seconds",
            key="memory_duration",
        )
        st.caption("Automatically releases memory after the selected duration; only one load test can run at a time.")
        if st.button(
            "Start Memory Load",
            type="primary",
            disabled=cpu_state == "running"
            or memory_state == "running",
            width="stretch",
        ):
            manager.note_button_click("memory")
            try:
                manager.start("memory", memory_duration, memory_mb=memory_size_mb)
                diagnostics = manager.diagnostics("memory")
                if not diagnostics["process_running"]:
                    raise RuntimeError(
                        diagnostics["error"]
                        or "Memory worker did not remain alive after startup."
                    )
                memory_state = "running"
                memory_worker_pid = manager.workload_pid("memory")
                live_usage = read_system_usage()
                manager.record_during_usage("memory", live_usage)
                system_cpu_metric.metric(
                    "System CPU utilization",
                    f"{live_usage['cpu_usage']:.1f}%",
                )
                system_memory_metric.metric(
                    "System memory utilization",
                    f"{live_usage['memory_usage']:.1f}%",
                )
                available_memory_metric.metric(
                    "Available system memory",
                    f"{live_usage['available_memory_mb']:.0f} MB",
                )
                if memory_worker_pid is not None:
                    memory_pid_caption.caption(f"Memory worker PID: {memory_worker_pid}")
                memory_status.metric("Memory test", "Running")
                add_history(
                    "Start Memory Load",
                    True,
                    f"Allocated and touched {memory_size_mb} MB for up to {memory_duration} seconds.",
                )
                st.toast(
                    f"Memory load started successfully! Allocated {memory_size_mb} MB.",
                    icon="✅",
                )
                st.success(f"Memory load started successfully! Allocated {memory_size_mb} MB.")
            except (OSError, RuntimeError, ValueError, psutil.Error) as error:
                add_history("Start Memory Load", False, str(error))
                st.toast(f"Could not start memory workload: {error}", icon="❌")
                st.error(f"Could not start memory workload: {error}")
        if st.button(
            "Stop Memory Load",
            disabled=memory_state != "running",
            width="stretch",
        ):
            try:
                stopped = manager.stop("memory")
                details = "Memory load stopped successfully!" if stopped else "No active memory workload."
                memory_state = "stopped"
                memory_status.metric("Memory test", "Stopped")
                memory_pid_caption.empty()
                after_usage = manager.resource_samples("memory")["after"]
                if after_usage is not None:
                    system_cpu_metric.metric(
                        "System CPU utilization",
                        f"{after_usage['cpu_usage']:.1f}%",
                    )
                    system_memory_metric.metric(
                        "System memory utilization",
                        f"{after_usage['memory_usage']:.1f}%",
                    )
                add_history("Stop Memory Load", stopped, details)
                (st.success if stopped else st.info)(details)
            except (OSError, subprocess.TimeoutExpired) as error:
                add_history("Stop Memory Load", False, str(error))
                st.error(f"Could not stop memory workload: {error}")
        render_workload_diagnostics(manager, "memory")

st.divider()
flask_columns = st.columns(2)
with flask_columns[0]:
    with st.container(border=True):
        st.subheader("🌐 Flask availability")
        st.write("Only stops the listener when it can verify it is this project's `app/main.py`.")
        if st.button(
            "Stop Flask Application",
            width="stretch",
        ):
            try:
                stopped_process = stop_project_flask()
                is_stopped = not flask_is_healthy()
                if is_stopped:
                    flask_status.metric("Flask · port 5000", "Stopped")
                    if stopped_process:
                        add_history(
                            "Stop Flask Application",
                            True,
                            "Flask application stopped successfully!",
                        )
                        st.success("Flask application stopped successfully!")
                    else:
                        add_history(
                            "Stop Flask Application",
                            True,
                            "Flask application was already stopped.",
                        )
                        st.info("Flask application is already stopped.")

                    try:
                        with st.status(
                            "Flask stopped. Recovering automatically...",
                            expanded=True,
                        ) as recovery_status:
                            recovery_status.write(
                                "Starting the Flask self-healing process."
                            )
                            run_project_script(SELF_HEALING_SCRIPT, timeout=45)
                            st.session_state.pop("script_completion", None)
                            recovery_status.update(
                                label="Flask recovery is running",
                                state="running",
                                expanded=False,
                            )
                        st.info(
                            "Flask recovery is running. This panel will show "
                            "whether it succeeds automatically."
                        )
                    except (OSError, RuntimeError, ValueError) as error:
                        add_history(
                            "Automatically Recover Flask Application",
                            False,
                            str(error),
                        )
                        st.error(f"Could not start automatic Flask recovery: {error}")
                else:
                    add_history("Stop Flask Application", False, "Flask still responds after stop request.")
                    st.error("Flask still responds after the stop request.")
            except (OSError, RuntimeError) as error:
                add_history("Stop Flask Application", False, str(error))
                st.error(f"Could not safely stop Flask: {error}")

with flask_columns[1]:
    with st.container(border=True):
        st.subheader("🧠 AI anomaly detection")
        st.write("Runs the existing Isolation Forest script on collected monitoring data.")
        st.warning(
            "The detector appends only unseen metric timestamps; existing anomaly results are preserved."
        )
        if available_memory_mib < MIN_AI_MEMORY_MIB:
            st.warning(
                f"AI detection is disabled below {MIN_AI_MEMORY_MIB} MiB available RAM."
            )
        if st.button(
            "Run AI Anomaly Detection",
            type="primary",
            disabled=script_running or available_memory_mib < MIN_AI_MEMORY_MIB,
            width="stretch",
        ):
            try:
                run_project_script(ANOMALY_SCRIPT)
                st.session_state.pop("script_completion", None)
                st.session_state.ai_status = "Running"
                ai_status_metric.metric("AI detection", "Running")
                add_history("Run AI Anomaly Detection", True, "Analysis started.")
                st.info("Anomaly detection started in the background.")
            except (OSError, RuntimeError, ValueError) as error:
                add_history("Run AI Anomaly Detection", False, str(error))
                st.error(f"Could not complete anomaly detection: {error}")

with st.container(border=True):
    st.subheader("🛡️ Policy-based recovery")
    st.write(
        "This button runs the policy once on demand; the monitor also runs it "
        "automatically. Confirmed Flask outages are restarted, API failures get "
        "bounded retries, and high-memory restarts require approval. CPU and disk "
        "incidents remain diagnostic only; disk files are never deleted."
    )
    pending_memory_restart = st.session_state.get(
        "pending_memory_restart_timestamp"
    )
    if pending_memory_restart:
        try:
            latest_memory_usage = float(latest_metric_row["memory_usage"])
        except (KeyError, TypeError, ValueError):
            latest_memory_usage = None
        st.warning(
            "The last policy run diagnosed high memory and withheld restart. "
            f"Approval was requested for reading {pending_memory_restart}."
        )
        if (
            latest_memory_usage is not None
            and latest_memory_usage >= 90
            and metrics_age_seconds is not None
            and metrics_age_seconds <= 30
        ):
            st.caption(
                f"Fresh reading still shows {latest_memory_usage:.1f}% memory. "
                "The approval expires after 30 seconds and is revalidated by the policy."
            )
            if st.button(
                "Approve high-memory Flask restart",
                disabled=script_running,
                width="stretch",
            ):
                try:
                    run_project_script(
                        SELF_HEALING_SCRIPT,
                        timeout=45,
                        arguments=[
                            "--approve-high-memory-restart",
                            "--approved-source-timestamp",
                            pending_memory_restart,
                        ],
                    )
                    st.session_state.pop("script_completion", None)
                    st.session_state.pop(
                        "pending_memory_restart_timestamp", None
                    )
                    add_history(
                        "Approve high-memory Flask restart",
                        True,
                        "Approval submitted; policy will revalidate health and memory.",
                    )
                    st.info("Approved recovery is running.")
                except (OSError, RuntimeError, ValueError) as error:
                    add_history(
                        "Approve high-memory Flask restart",
                        False,
                        str(error),
                    )
                    st.error(f"Could not start approved recovery: {error}")
        else:
            st.warning(
                "Approval is disabled because the latest memory reading is "
                "not fresh or is below the high-memory threshold. Run the policy again."
            )

    if st.button(
        "Run Recovery Policy",
        type="primary",
        disabled=script_running,
        width="stretch",
    ):
        try:
            run_project_script(SELF_HEALING_SCRIPT, timeout=45)
            st.session_state.pop("script_completion", None)
            st.info("Recovery policy started; this run will report its evidence and action.")
        except (OSError, RuntimeError, ValueError) as error:
            add_history("Run Recovery Policy", False, str(error))
            st.error(f"Could not start the recovery policy: {error}")

with st.container(border=True):
    st.subheader("🧭 Root cause analysis")
    st.write("Runs the existing RCA module against the project's real metrics and AI results.")
    st.caption("The existing RCA script may append a report to data/incident_reports.csv.")
    if available_memory_mib < MIN_RCA_MEMORY_MIB:
        st.warning(
            f"Root cause analysis is disabled below {MIN_RCA_MEMORY_MIB} MiB available RAM."
        )
    if st.button(
        "Run Root Cause Analysis",
        type="primary",
        disabled=script_running or available_memory_mib < MIN_RCA_MEMORY_MIB,
        width="stretch",
    ):
        try:
            run_project_script(ROOT_CAUSE_SCRIPT)
            st.session_state.pop("script_completion", None)
            st.session_state.rca_status = "Running"
            rca_status_metric.metric("Root cause analysis", "Running")
            add_history("Run Root Cause Analysis", True, "Analysis started.")
            st.info("Root cause analysis started in the background.")
        except (OSError, RuntimeError, ValueError) as error:
            add_history("Run Root Cause Analysis", False, str(error))
            st.error(f"Could not run root cause analysis: {error}")

st.divider()
history_columns = st.columns([1, 4])
with history_columns[0]:
    st.subheader("Execution history")
with history_columns[1]:
    if st.button("Stop All Tests", type="secondary", width="stretch"):
        try:
            stopped = manager.stop_all()
            cpu_state = manager.state("cpu")
            memory_state = manager.state("memory")
            cpu_status.metric("CPU test", cpu_state.title())
            memory_status.metric("Memory test", memory_state.title())
            completed_kinds = [
                kind for kind, was_stopped in stopped.items() if was_stopped
            ]
            after_usage = next(
                (
                    manager.resource_samples(kind)["after"]
                    for kind in reversed(completed_kinds)
                    if manager.resource_samples(kind)["after"] is not None
                ),
                None,
            )
            if after_usage is not None:
                system_cpu_metric.metric(
                    "System CPU utilization",
                    f"{after_usage['cpu_usage']:.1f}%",
                )
                system_memory_metric.metric(
                    "System memory utilization",
                    f"{after_usage['memory_usage']:.1f}%",
                )
            if stopped["cpu"]:
                worker_cpu_metric.metric(
                    "CPU workload process utilization",
                    "Not running",
                )
                cpu_pid_caption.empty()
            if stopped["memory"]:
                memory_pid_caption.empty()
            stopped_names = [kind.upper() for kind, was_stopped in stopped.items() if was_stopped]
            details = (
                f"Stopped: {', '.join(stopped_names)}."
                if stopped_names
                else "No active CPU or memory tests."
            )
            add_history("Stop All Tests", True, details)
            st.success(details)
        except (OSError, subprocess.TimeoutExpired) as error:
            add_history("Stop All Tests", False, str(error))
            st.error(f"Could not stop all workloads: {error}")

if st.session_state.history:
    st.dataframe(
        st.session_state.history,
        hide_index=True,
        width="stretch",
    )
else:
    st.info("Actions performed in this browser session will appear here.")
