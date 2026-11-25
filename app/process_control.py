import json
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import psutil


BASE_DIR = Path(__file__).resolve().parent.parent
MAIN_FILE = BASE_DIR / "app" / "main.py"
METRICS_URL = "http://127.0.0.1:5000/metrics"


def _process_from_metrics():
    try:
        with urlopen(METRICS_URL, timeout=1) as response:
            metrics = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, OSError):
        return None
    except json.JSONDecodeError as error:
        raise RuntimeError(
            "Port 5000 responded with invalid metrics; refusing to stop an unverified process."
        ) from error

    pid = metrics.get("application_process_pid") if isinstance(metrics, dict) else None
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise RuntimeError(
            "Port 5000 did not report a valid application PID; refusing to stop an unverified process."
        )

    try:
        process = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return None
    try:
        is_project_process = is_project_flask_process(process)
    except psutil.AccessDenied as error:
        raise RuntimeError(
            f"Cannot verify the Flask process reported by port 5000 (PID {pid})."
        ) from error
    if not is_project_process:
        raise RuntimeError(
            f"Port 5000 reported PID {pid}, but it is not this project's app/main.py; "
            "the process was left untouched."
        )
    return process


def is_project_flask_process(process):
    try:
        command_line = process.cmdline()
        working_directory = Path(process.cwd())
    except psutil.NoSuchProcess:
        return False

    for argument in command_line:
        candidate = Path(argument)
        if candidate.name.lower() != MAIN_FILE.name.lower():
            continue
        if not candidate.is_absolute():
            candidate = working_directory / candidate
        try:
            if candidate.resolve() == MAIN_FILE.resolve():
                return True
        except OSError:
            continue
    return False


def _listens_on_flask_port(process):
    return any(
        connection.laddr
        and connection.laddr.port == 5000
        and connection.status == psutil.CONN_LISTEN
        for connection in process.net_connections(kind="inet")
    )


def project_flask_processes():
    process = _process_from_metrics()
    if process is not None:
        return [process]

    project_processes = []
    inaccessible_pids = []
    for process in psutil.process_iter(["pid", "name"]):
        if (process.info.get("name") or "").lower() not in {
            "python.exe",
            "pythonw.exe",
        }:
            continue
        try:
            if is_project_flask_process(process) and _listens_on_flask_port(process):
                project_processes.append(process)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            inaccessible_pids.append(process.pid)

    if not project_processes and inaccessible_pids:
        raise RuntimeError(
            "Could not safely verify whether a Python process is this project's Flask app; "
            f"access was denied for PID(s): {', '.join(map(str, inaccessible_pids))}."
        )
    return project_processes


def stop_project_flask():
    processes = project_flask_processes()
    for process in processes:
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as error:
            raise RuntimeError(
                f"Permission denied while stopping project Flask PID {process.pid}."
            ) from error

    _, alive = psutil.wait_procs(processes, timeout=5)
    for process in alive:
        try:
            process.kill()
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as error:
            raise RuntimeError(
                f"Permission denied while finishing Flask PID {process.pid} shutdown."
            ) from error

    if alive:
        _, still_alive = psutil.wait_procs(alive, timeout=5)
        if still_alive:
            raise RuntimeError("Project Flask did not stop after termination.")
    return bool(processes)
