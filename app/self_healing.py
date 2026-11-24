import argparse
import csv
import errno
import msvcrt
import os
import subprocess
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import psutil

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import incident_management

MAIN_FILE = BASE_DIR / "app" / "main.py"
METRICS_FILE = BASE_DIR / "data" / "metrics.csv"
INCIDENT_FILE = BASE_DIR / "data" / "incident_reports.csv"
LOG_FILE = BASE_DIR / "logs" / "self_healing_log.csv"
FLASK_LOG_FILE = BASE_DIR / "logs" / "flask-recovery.log"
APP_URL = "http://127.0.0.1:5000/health"
API_URL = "http://127.0.0.1:5000/"

CPU_ALERT_THRESHOLD = 85
MEMORY_ALERT_THRESHOLD = 90
DISK_ALERT_THRESHOLD = 90
API_ERROR_THRESHOLD = 5
API_RESPONSE_THRESHOLD_MS = 1000
METRICS_MAX_AGE_SECONDS = 30
HIGH_MEMORY_APPROVAL_MAX_AGE_SECONDS = 30
FLASK_START_TIMEOUT_SECONDS = 10
AUTOMATIC_RECOVERY_COOLDOWN_SECONDS = 60

LOG_COLUMNS = [
    "timestamp",
    "incident",
    "probable_cause",
    "policy_decision",
    "action",
    "result",
    "verification",
    "escalation",
]
POLICY_METRIC_COLUMNS = {
    "timestamp",
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "response_time_ms",
    "api_error_rate",
}
AUTOMATIC_RECOVERY_LOCK_FILE = BASE_DIR / "logs" / "automatic-recovery.lock"


def check_endpoint(url):
    try:
        with urlopen(url, timeout=3) as response:
            return 200 <= response.status < 400
    except (URLError, TimeoutError, OSError):
        return False


def check_application():
    return check_endpoint(APP_URL)


def check_api():
    return check_endpoint(API_URL)


def retry_check(check, attempts=3):
    for attempt in range(attempts):
        if check():
            return True
        if attempt + 1 < attempts:
            time.sleep(0.5)
    return False


def read_latest_metrics():
    if not METRICS_FILE.exists():
        return None, set(POLICY_METRIC_COLUMNS)

    with METRICS_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        columns = set(reader.fieldnames or [])
        latest = None
        for row in reader:
            latest = row

    return latest, POLICY_METRIC_COLUMNS.difference(columns)


def read_matching_incident(source_timestamp):
    if not source_timestamp or not INCIDENT_FILE.exists():
        return None

    with INCIDENT_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        if not reader.fieldnames or not {
            "source_timestamp",
            "root_cause",
        }.issubset(reader.fieldnames):
            return None
        matching = None
        for row in reader:
            if row.get("source_timestamp") == source_timestamp:
                matching = row
    return matching


def numeric_value(row, column):
    if not row:
        return None
    try:
        return float(row[column])
    except (KeyError, TypeError, ValueError):
        return None


def automatic_recovery_signal_active(app_status, metrics):
    if app_status != "Healthy":
        return True

    thresholds = (
        ("cpu_usage", CPU_ALERT_THRESHOLD),
        ("memory_usage", MEMORY_ALERT_THRESHOLD),
        ("disk_usage", DISK_ALERT_THRESHOLD),
        ("response_time_ms", API_RESPONSE_THRESHOLD_MS),
        ("api_error_rate", API_ERROR_THRESHOLD),
    )
    for column, threshold in thresholds:
        value = numeric_value(metrics, column)
        if value is not None and value >= threshold:
            return True
    return False


def run_automatic_policy_if_needed(app_status, metrics, now=None):
    AUTOMATIC_RECOVERY_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    current_time = time.time() if now is None else now
    with AUTOMATIC_RECOVERY_LOCK_FILE.open("a+b") as lock_file:
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b"\0")
            lock_file.flush()
        lock_file.seek(0)
        try:
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            if error.errno in (errno.EACCES, errno.EDEADLK):
                return None
            raise

        try:
            if not automatic_recovery_signal_active(app_status, metrics):
                lock_file.seek(1)
                lock_file.truncate(1)
                lock_file.flush()
                return None

            lock_file.seek(1)
            saved_attempt = lock_file.read().decode("ascii").strip()
            if saved_attempt:
                try:
                    elapsed = current_time - float(saved_attempt)
                except ValueError as error:
                    raise RuntimeError(
                        "Automatic recovery cooldown state is invalid."
                    ) from error
                if 0 <= elapsed < AUTOMATIC_RECOVERY_COOLDOWN_SECONDS:
                    return None

            lock_file.seek(1)
            lock_file.truncate(1)
            lock_file.write(f"{current_time:.6f}".encode("ascii"))
            lock_file.flush()
            return run_policy_safely()
        finally:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)


def metrics_age_seconds(row):
    if not row or not row.get("timestamp"):
        return None
    try:
        timestamp = datetime.fromisoformat(row["timestamp"])
    except ValueError:
        return None

    now = datetime.now(timestamp.tzinfo) if timestamp.tzinfo else datetime.now()
    age = (now - timestamp).total_seconds()
    return age if age >= 0 else None


def ensure_log_schema():
    if not LOG_FILE.exists():
        return

    with LOG_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        existing_columns = reader.fieldnames or []
        columns = LOG_COLUMNS + [
            column for column in existing_columns if column not in LOG_COLUMNS
        ]
        if columns == existing_columns:
            return
        rows = list(reader)

    with tempfile.NamedTemporaryFile(
        "w",
        newline="",
        encoding="utf-8",
        dir=LOG_FILE.parent,
        delete=False,
    ) as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
        temporary_file = file.name
    os.replace(temporary_file, LOG_FILE)


def current_log_columns():
    if not LOG_FILE.exists():
        return LOG_COLUMNS
    with LOG_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        return csv.DictReader(file).fieldnames or LOG_COLUMNS


def write_log(
    incident,
    probable_cause,
    policy_decision,
    action,
    result,
    verification,
    escalation="",
    source_timestamp=None,
):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    ensure_log_schema()
    columns = current_log_columns()

    with LOG_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        if file.tell() == 0:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "incident": incident,
                "probable_cause": probable_cause,
                "policy_decision": policy_decision,
                "action": action,
                "result": result,
                "verification": verification,
                "escalation": escalation,
            }
        )
    if source_timestamp:
        incident_management.record_recovery_attempt(
            source_timestamp,
            action,
            result,
            "; ".join(
                item for item in (policy_decision, verification, escalation) if item
            ),
        )


def current_incident(metrics, incident_report):
    if incident_report and incident_report.get("root_cause"):
        return incident_report["root_cause"]
    if not metrics:
        return "Application health check failed"

    symptoms = []
    memory = numeric_value(metrics, "memory_usage")
    cpu = numeric_value(metrics, "cpu_usage")
    disk = numeric_value(metrics, "disk_usage")
    response = numeric_value(metrics, "response_time_ms")
    errors = numeric_value(metrics, "api_error_rate")
    if memory is not None and memory >= MEMORY_ALERT_THRESHOLD:
        symptoms.append(f"memory usage {memory:.1f}%")
    if cpu is not None and cpu >= CPU_ALERT_THRESHOLD:
        symptoms.append(f"CPU usage {cpu:.1f}%")
    if disk is not None and disk >= DISK_ALERT_THRESHOLD:
        symptoms.append(f"disk usage {disk:.1f}%")
    if response is not None and response >= API_RESPONSE_THRESHOLD_MS:
        symptoms.append(f"API response time {response:.0f} ms")
    if errors is not None and errors >= API_ERROR_THRESHOLD:
        symptoms.append(f"API error rate {errors:.1f}%")
    return ", ".join(symptoms) if symptoms else "No active threshold incident"


def top_memory_consumers(limit=5):
    processes = []
    for process in psutil.process_iter(["pid", "name"]):
        try:
            processes.append(
                {
                    "pid": process.info["pid"],
                    "name": process.info["name"] or "unknown",
                    "memory_mib": process.memory_info().rss / (1024 * 1024),
                }
            )
        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            OSError,
        ):
            continue
    return sorted(
        processes,
        key=lambda process: process["memory_mib"],
        reverse=True,
    )[:limit]


def top_cpu_consumers(limit=5):
    samples = []
    for process in psutil.process_iter(["pid", "name"]):
        try:
            process.cpu_percent(interval=None)
            samples.append(process)
        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            OSError,
        ):
            continue

    time.sleep(0.5)
    consumers = []
    for process in samples:
        try:
            consumers.append(
                {
                    "pid": process.pid,
                    "name": process.name() or "unknown",
                    "cpu_percent": process.cpu_percent(interval=None),
                }
            )
        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            OSError,
        ):
            continue

    return sorted(
        consumers,
        key=lambda process: process["cpu_percent"],
        reverse=True,
    )[:limit]


def large_temporary_files(limit=10, minimum_size_mb=10):
    temporary_root = Path(tempfile.gettempdir())
    large_files = []
    scan_errors = []
    inspected = 0
    max_files_to_inspect = 5000

    def record_scan_error(error):
        scan_errors.append(str(error))

    for current, _, filenames in os.walk(
        temporary_root,
        onerror=record_scan_error,
        followlinks=False,
    ):
        for filename in filenames:
            inspected += 1
            if inspected > max_files_to_inspect:
                scan_errors.append(
                    f"Scan capped at {max_files_to_inspect} files."
                )
                break
            path = Path(current) / filename
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                size = path.stat().st_size
                if size >= minimum_size_mb * 1024 * 1024:
                    large_files.append(
                        {
                            "path": str(path),
                            "size_mb": size / (1024 * 1024),
                        }
                    )
            except OSError as error:
                scan_errors.append(f"{path}: {error}")
        if inspected > max_files_to_inspect:
            break

    large_files.sort(key=lambda item: item["size_mb"], reverse=True)
    return large_files[:limit], scan_errors


def is_project_flask_process(process):
    command_line = process.cmdline()
    working_directory = Path(process.cwd())
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


def project_flask_listeners():
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError) as error:
        raise RuntimeError(
            "Cannot safely inspect port 5000 listeners; refusing to start or stop Flask."
        ) from error

    listener_pids = {
        connection.pid
        for connection in connections
        if connection.laddr
        and connection.laddr.port == 5000
        and connection.status == psutil.CONN_LISTEN
    }
    if None in listener_pids:
        raise RuntimeError(
            "Port 5000 has a listener with an unknown PID; refusing to alter it."
        )

    project_processes = []
    for pid in listener_pids:
        try:
            process = psutil.Process(pid)
            if not is_project_flask_process(process):
                raise RuntimeError(
                    f"Port 5000 is owned by PID {pid}, not this project's app/main.py; "
                    "the process was left untouched."
                )
            project_processes.append(process)
        except psutil.NoSuchProcess:
            continue
        except psutil.AccessDenied as error:
            raise RuntimeError(
                f"Cannot verify port-5000 listener PID {pid}; refusing to alter it."
            ) from error

    return project_processes


def stop_project_flask():
    processes = project_flask_listeners()
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
            raise RuntimeError(
                "Project Flask did not stop; recovery was not started."
            )
    return bool(processes)


def rollback_started_process(process):
    if process.poll() is not None:
        return "The newly started process had already exited."

    try:
        process.terminate()
        process.wait(timeout=3)
        return "The unverified process was terminated."
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)
        return "The unverified process was force-stopped after graceful termination timed out."
    except OSError as error:
        return f"Could not stop the unverified process: {error}"


def start_flask_and_verify():
    if project_flask_listeners():
        raise RuntimeError(
            "A project Flask listener is still present; refusing to start a duplicate."
        )

    FLASK_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    creation_flags = (
        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
    )
    with FLASK_LOG_FILE.open("ab") as flask_log:
        process = subprocess.Popen(
            [sys.executable, str(MAIN_FILE)],
            cwd=str(BASE_DIR),
            stdin=subprocess.DEVNULL,
            stdout=flask_log,
            stderr=subprocess.STDOUT,
            creationflags=creation_flags,
        )

    deadline = time.monotonic() + FLASK_START_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        time.sleep(min(1, max(0, deadline - time.monotonic())))
        if check_application():
            return
        if process.poll() is not None:
            break

    rollback_result = rollback_started_process(process)
    raise RuntimeError(
        "Flask did not pass its health check after restart. "
        f"Rollback: {rollback_result} See {FLASK_LOG_FILE}."
    )


def restart_flask():
    stop_project_flask()
    start_flask_and_verify()
    if not retry_check(check_application, attempts=2):
        raise RuntimeError("Flask did not remain healthy after restart verification.")


def emit_result(result, decision, verification="", escalation=""):
    print(f"Policy decision: {decision}")
    if verification:
        print(f"Verification: {verification}")
    if escalation:
        print(f"Escalation: {escalation}")
    print(f"Recovery result: {result}")


def run_policy(approve_high_memory_restart=False, approved_source_timestamp=None):
    metrics, missing_columns = read_latest_metrics()
    source_timestamp = metrics.get("timestamp") if metrics else None
    incident_report = read_matching_incident(source_timestamp)
    incident = current_incident(metrics, incident_report)
    probable_cause = (
        incident_report.get("root_cause")
        if incident_report and incident_report.get("root_cause")
        else incident
    )

    print("Incident:", incident)
    print("Probable cause:", probable_cause)

    if not retry_check(check_application):
        decision = "Restart Flask because all health-check retries failed."
        try:
            restart_flask()
            write_log(
                incident,
                probable_cause,
                decision,
                "Start Flask application",
                "Recovery successful",
                "Health endpoint returned HTTP 200 after restart.",
                source_timestamp=source_timestamp,
            )
            emit_result(
                "RECOVERED",
                decision,
                "Flask health check passed after restart.",
            )
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            escalation = (
                f"Recovery failed: {error}. Local escalation recorded for administrator review."
            )
            write_log(
                incident,
                probable_cause,
                decision,
                "Start Flask application",
                "Recovery failed",
                "Health check did not verify recovery.",
                escalation,
                source_timestamp=source_timestamp,
            )
            emit_result("ESCALATED", decision, "Recovery failed.", escalation)
            return False

    metric_age = metrics_age_seconds(metrics)
    metrics_fresh = (
        metric_age is not None
        and metric_age <= METRICS_MAX_AGE_SECONDS
        and not missing_columns
    )
    if not metrics_fresh:
        details = (
            "Metrics are unavailable or stale; metric-based remediation was withheld. "
            f"Missing columns: {', '.join(sorted(missing_columns)) or 'none'}; "
            f"age: {metric_age if metric_age is not None else 'unknown'} seconds."
        )
        write_log(
            incident,
            probable_cause,
            "No metric action; stale or incomplete data",
            "None",
            "No action taken",
            details,
            source_timestamp=source_timestamp,
        )
        emit_result("NO_ACTION", details)
        return True

    memory = numeric_value(metrics, "memory_usage")
    cpu = numeric_value(metrics, "cpu_usage")
    disk = numeric_value(metrics, "disk_usage")
    response_time = numeric_value(metrics, "response_time_ms")
    error_rate = numeric_value(metrics, "api_error_rate")

    if memory is not None and memory >= MEMORY_ALERT_THRESHOLD:
        consumers = top_memory_consumers()
        consumer_summary = ", ".join(
            f"{item['name']} PID {item['pid']} "
            f"({item['memory_mib']:.1f} MiB)"
            for item in consumers
        ) or "No visible process data"
        cause = probable_cause or (
            f"System memory usage is {memory:.1f}%; top consumers: {consumer_summary}."
        )
        decision = (
            "Restart is permitted only with explicit approval for this incident."
        )

        if not approve_high_memory_restart:
            verification = (
                f"Flask health is available; memory is {memory:.1f}%. "
                f"Top process RSS: {consumer_summary}."
            )
            write_log(
                incident,
                cause,
                decision,
                "Diagnose memory; restart withheld",
                "Approval required",
                verification,
                source_timestamp=source_timestamp,
            )
            print("Approval source timestamp:", source_timestamp or "unavailable")
            print("Top memory consumers:", consumer_summary)
            emit_result("APPROVAL_REQUIRED", decision, verification)
            return True

        approval_age = (
            metrics_age_seconds({"timestamp": approved_source_timestamp})
            if approved_source_timestamp
            else None
        )
        live_memory = psutil.virtual_memory().percent
        if (
            approval_age is None
            or approval_age > HIGH_MEMORY_APPROVAL_MAX_AGE_SECONDS
            or approved_source_timestamp != source_timestamp
            or memory < MEMORY_ALERT_THRESHOLD
            or live_memory < MEMORY_ALERT_THRESHOLD
        ):
            verification = (
                "Approval expired, the source incident changed, or high memory no longer "
                "meets policy; no restart performed."
            )
            write_log(
                incident,
                cause,
                "Explicit approval rejected by revalidation",
                "None",
                "No action taken",
                verification,
                source_timestamp=source_timestamp,
            )
            emit_result("NO_ACTION", "Approval failed safety revalidation.", verification)
            return True

        decision = (
            "Explicit approval received; restart Flask after fresh high-memory revalidation."
        )
        try:
            if not retry_check(check_application, attempts=2):
                raise RuntimeError(
                    "Flask health failed during approval; crash recovery must be rerun."
                )
            restart_flask()
            write_log(
                incident,
                cause,
                decision,
                "Restart Flask after approved high memory",
                "Recovery successful",
                "Health endpoint returned HTTP 200 after restart.",
                source_timestamp=source_timestamp,
            )
            emit_result(
                "RECOVERED",
                decision,
                "Flask health check passed after approved restart.",
            )
            return True
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            escalation = (
                f"Approved restart failed: {error}. Local escalation recorded "
                "for administrator review."
            )
            write_log(
                incident,
                cause,
                decision,
                "Restart Flask after approved high memory",
                "Recovery failed",
                "Health check did not verify recovery.",
                escalation,
                source_timestamp=source_timestamp,
            )
            emit_result("ESCALATED", decision, "Recovery failed.", escalation)
            return False

    if cpu is not None and cpu >= CPU_ALERT_THRESHOLD:
        consumers = top_cpu_consumers()
        diagnosis = ", ".join(
            f"{item['name']} PID {item['pid']} ({item['cpu_percent']:.1f}%)"
            for item in consumers
        ) or "No visible process data"
        verification = f"Top CPU consumers sampled: {diagnosis}."
        write_log(
            incident,
            probable_cause,
            "Diagnostic only; no process termination is permitted",
            "Identify CPU-consuming processes",
            "Diagnosis completed",
            verification,
            source_timestamp=source_timestamp,
        )
        emit_result("DIAGNOSED", "CPU process diagnosis only.", verification)
        return True

    if disk is not None and disk >= DISK_ALERT_THRESHOLD:
        large_files, scan_errors = large_temporary_files()
        file_summary = "; ".join(
            f"{item['path']} ({item['size_mb']:.1f} MB)"
            for item in large_files
        ) or "No temporary files larger than 10 MB were found."
        verification = (
            f"Scanned the system temp directory; no files were deleted. {file_summary}"
        )
        if scan_errors:
            verification += f" Scan notices: {'; '.join(scan_errors[:3])}"
        write_log(
            incident,
            probable_cause,
            "Diagnostic only; no file deletion is permitted",
            "Identify large temporary files",
            "Diagnosis completed",
            verification,
            source_timestamp=source_timestamp,
        )
        emit_result("DIAGNOSED", "Disk diagnostic only.", verification)
        return True

    api_failure = (
        (error_rate is not None and error_rate >= API_ERROR_THRESHOLD)
        or (
            response_time is not None
            and response_time >= API_RESPONSE_THRESHOLD_MS
        )
    )
    if api_failure:
        api_recovered = retry_check(check_api)
        health_recovered = retry_check(check_application, attempts=2)
        if api_recovered and health_recovered:
            verification = "API and service health both passed retry checks."
            write_log(
                incident,
                probable_cause,
                "Retry API and verify service health; no restart unless health fails",
                "Retry API request",
                "Retry verified",
                verification,
                source_timestamp=source_timestamp,
            )
            emit_result("RETRIED", "API retry completed.", verification)
            return True

        escalation = (
            "API retry failed while service recovery was not verified. "
            "Local escalation recorded for administrator review."
        )
        verification = (
            f"API retry healthy: {api_recovered}; service health: {health_recovered}."
        )
        write_log(
            incident,
            probable_cause,
            "Retry API and verify service health",
            "Retry API request",
            "Retry failed",
            verification,
            escalation,
            source_timestamp=source_timestamp,
        )
        emit_result("ESCALATED", "API retry failed.", verification, escalation)
        return False

    write_log(
        incident,
        probable_cause,
        "No recovery policy triggered",
        "None",
        "No recovery needed",
        "Service health and fresh metrics are within configured policy.",
        source_timestamp=source_timestamp,
    )
    emit_result(
        "NO_ACTION",
        "No recovery policy triggered.",
        "Service is healthy and metrics are below configured thresholds.",
    )
    return True


def main():
    parser = argparse.ArgumentParser(description="Run the SDP recovery policy once.")
    parser.add_argument(
        "--approve-high-memory-restart",
        action="store_true",
        help="Approve a high-memory Flask restart for this policy run.",
    )
    parser.add_argument(
        "--approved-source-timestamp",
        help="Timestamp of the high-memory incident approved in the control panel.",
    )
    arguments = parser.parse_args()
    return 0 if run_policy_safely(
        approve_high_memory_restart=arguments.approve_high_memory_restart,
        approved_source_timestamp=arguments.approved_source_timestamp,
    ) else 1


def run_policy_safely(
    approve_high_memory_restart=False,
    approved_source_timestamp=None,
):
    try:
        return run_policy(
            approve_high_memory_restart=approve_high_memory_restart,
            approved_source_timestamp=approved_source_timestamp,
        )
    except (OSError, RuntimeError, csv.Error, psutil.Error, ValueError) as error:
        escalation = (
            f"Policy evaluation failed: {error}. Local escalation recorded "
            "for administrator review."
        )
        write_log(
            "Policy evaluation",
            "Unable to complete policy evaluation",
            "No remediation action authorized",
            "None",
            "Policy failed",
            "Policy could not verify inputs or action safety.",
            escalation,
        )
        emit_result("ESCALATED", "Policy evaluation failed.", escalation=escalation)
        return False


if __name__ == "__main__":
    sys.exit(main())
