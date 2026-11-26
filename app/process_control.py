import json
import os
import subprocess
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import psutil


BASE_DIR = Path(__file__).resolve().parent.parent
MAIN_FILE = BASE_DIR / "app" / "main.py"
METRICS_URL = "http://127.0.0.1:5000/metrics"
PROCESS_STOP_TIMEOUT_SECONDS = 5
DEMO_APPLICATION_LAUNCHERS = {
    "APP-SDP-DEMO-ECOMMERCE": ("ecommerce", 5101),
    "APP-SDP-DEMO-STREAMING": ("streaming", 5102),
}
DEMO_APPLICATION_SCRIPT = BASE_DIR / "testing_website" / "demo_app.py"


def _normalized_path(value):
    if not value:
        return None
    try:
        return str(Path(value).resolve()).casefold()
    except (OSError, RuntimeError, TypeError, ValueError):
        return str(value).casefold()


def _demo_application_launch_arguments(application):
    application_id = application.get("application_id")
    configuration = DEMO_APPLICATION_LAUNCHERS.get(application_id)
    if configuration is None:
        return []
    service, port = configuration
    expected_directory = (
        BASE_DIR / "data" / "demo_services" / str(application_id).casefold()
    )
    expected_url = f"http://127.0.0.1:{port}"
    if (
        application.get("application_type") != "CONTROLLED_LOCAL_APPLICATION"
        or application.get("url") != expected_url
        or application.get("endpoint_path") != "/health"
        or _normalized_path(application.get("process_working_directory"))
        != _normalized_path(expected_directory)
        or not DEMO_APPLICATION_SCRIPT.is_file()
    ):
        raise RuntimeError(
            "The registered demo application does not match its fixed local launcher."
        )
    return [str(DEMO_APPLICATION_SCRIPT), "--service", service, "--port", str(port)]


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


def verify_registered_application_process(
    application,
    expected_pid=None,
    process_provider=psutil,
):
    if not (
        application.get("owned_by_platform")
        and application.get("process_monitoring_permitted")
        and application.get("automatic_recovery_permitted")
    ):
        raise RuntimeError(
            "Process control requires platform ownership and explicit process "
            "monitoring and automatic recovery permissions."
        )

    application_id = application.get("application_id")
    if application_id == "APP-SDP-FLASK-5000":
        processes = project_flask_processes()
        if len(processes) > 1:
            raise RuntimeError(
                "Multiple project Flask processes were found; process control "
                "was withheld."
            )
        if not processes:
            return None
        process = processes[0]
        if expected_pid is not None and process.pid != expected_pid:
            raise RuntimeError(
                "The live Flask PID does not match the latest owned-process "
                "telemetry; process control was withheld."
            )
        if not is_project_flask_process(process):
            raise RuntimeError(
                "The Flask process identity no longer matches this project."
            )
        return process
    if application.get("application_type") != "CONTROLLED_LOCAL_APPLICATION":
        raise RuntimeError(
            "Process restart is restricted to controlled local applications."
        )

    expected_name = str(application.get("process_name") or "").casefold()
    executable_path = application.get("process_executable_path")
    working_directory = application.get("process_working_directory")
    if not (expected_name and executable_path and working_directory):
        raise RuntimeError(
            "Restart requires a registered process name, executable path, "
            "and working directory."
        )

    expected_executable = _normalized_path(executable_path)
    expected_directory = _normalized_path(working_directory)
    matches = []
    inaccessible_pids = []
    for process in process_provider.process_iter(["pid", "name", "exe", "cwd"]):
        try:
            info = process.info
            process_name = str(info.get("name") or "").casefold()
            if process_name != expected_name:
                continue
            executable = _normalized_path(info.get("exe"))
            directory = _normalized_path(info.get("cwd"))
            if executable != expected_executable or directory != expected_directory:
                continue
            if process.pid == os.getpid():
                raise RuntimeError(
                    "The registered process identity matches the recovery worker "
                    "itself; process control was withheld."
                )
            if expected_pid is not None and process.pid != expected_pid:
                raise RuntimeError(
                    "The matching process PID differs from the latest telemetry; "
                    "process control was withheld."
                )
            matches.append(process)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied:
            inaccessible_pids.append(process.pid)
        except psutil.ZombieProcess:
            continue

    if inaccessible_pids:
        raise RuntimeError(
            "Could not safely verify process identity because access was denied "
            f"for PID(s): {', '.join(map(str, inaccessible_pids))}."
        )
    if len(matches) > 1:
        raise RuntimeError(
            "The registered process identity matches multiple processes; "
            "process control was withheld."
        )
    return matches[0] if matches else None


def stop_registered_application(
    application,
    expected_pid=None,
    process_provider=psutil,
):
    if application.get("application_id") == "APP-SDP-FLASK-5000":
        if expected_pid is not None:
            process = verify_registered_application_process(
                application,
                expected_pid=expected_pid,
                process_provider=process_provider,
            )
            if process is None:
                return False
        return stop_project_flask()

    if expected_pid is None:
        raise RuntimeError(
            "Stopping a local process requires its PID from current application telemetry."
        )
    process = verify_registered_application_process(
        application,
        expected_pid=expected_pid,
        process_provider=process_provider,
    )
    if process is None:
        return False
    try:
        process.terminate()
        process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
        return True
    except psutil.NoSuchProcess:
        return True
    except psutil.TimeoutExpired:
        try:
            process.kill()
            process.wait(timeout=PROCESS_STOP_TIMEOUT_SECONDS)
        except psutil.NoSuchProcess:
            return True
        except psutil.TimeoutExpired as error:
            raise RuntimeError(
                f"Owned application process PID {process.pid} did not stop."
            ) from error
        except (psutil.AccessDenied, OSError) as error:
            raise RuntimeError(
                f"Could not finish stopping verified application PID "
                f"{process.pid}: {error}"
            ) from error
        return True
    except (psutil.AccessDenied, OSError) as error:
        raise RuntimeError(
            f"Could not stop verified application PID {process.pid}: {error}"
        ) from error


def restart_registered_application(
    application,
    expected_pid=None,
    process_provider=psutil,
    popen_function=None,
):
    if not (
        application.get("owned_by_platform")
        and application.get("process_monitoring_permitted")
        and application.get("automatic_recovery_permitted")
    ):
        raise RuntimeError(
            "Restart requires platform ownership and explicit process "
            "monitoring and automatic recovery permissions."
        )

    if application.get("application_id") == "APP-SDP-FLASK-5000":
        from app.self_healing import restart_flask

        restart_flask()
        processes = verify_registered_application_process(
            application,
            process_provider=process_provider,
        )
        return processes.pid
    if application.get("application_type") != "CONTROLLED_LOCAL_APPLICATION":
        raise RuntimeError(
            "Process restart is restricted to controlled local applications."
        )

    executable_value = application.get("process_executable_path")
    working_directory_value = application.get("process_working_directory")
    process_name = str(application.get("process_name") or "")
    if not (executable_value and working_directory_value and process_name):
        raise RuntimeError(
            "Restart requires a registered process name, executable path, "
            "and working directory."
        )

    executable = Path(executable_value)
    working_directory = Path(working_directory_value)
    if not executable.is_absolute() or not executable.is_file():
        raise RuntimeError(
            "The registered executable must be an existing absolute file path."
        )
    if not working_directory.is_absolute() or not working_directory.is_dir():
        raise RuntimeError(
            "The registered working directory must be an existing absolute directory."
        )
    if executable.name.casefold() != process_name.casefold():
        raise RuntimeError(
            "The registered process name does not match the executable filename."
        )

    current_process = verify_registered_application_process(
        application,
        expected_pid=expected_pid,
        process_provider=process_provider,
    )
    if current_process is not None:
        if expected_pid is None:
            raise RuntimeError(
                "The running process PID is not backed by current application telemetry."
            )
        stop_registered_application(
            application,
            expected_pid=current_process.pid,
            process_provider=process_provider,
        )

    creation_flags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    start_process = popen_function or subprocess.Popen
    command = [str(executable)]
    command.extend(_demo_application_launch_arguments(application))
    try:
        process = start_process(
            command,
            cwd=str(working_directory),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
            creationflags=creation_flags if os.name == "nt" else 0,
        )
    except OSError as error:
        raise RuntimeError(
            f"Could not start the registered application executable: {error}"
        ) from error
    if process.poll() is not None:
        raise RuntimeError(
            "The registered application process exited immediately after launch."
        )
    return process.pid
