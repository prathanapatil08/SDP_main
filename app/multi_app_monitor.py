import json
import logging
import socket
import ssl
import threading
import time
from contextlib import closing
from datetime import datetime, timezone
from http.client import HTTPException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

import psutil

from app.application_registry import get_application, get_applications
from app.database import connect, initialize_database


LOGGER = logging.getLogger(__name__)
DEFAULT_REQUEST_TIMEOUT_SECONDS = 5.0
MAX_REQUEST_TIMEOUT_SECONDS = 15.0
DEFAULT_STOP_TIMEOUT_SECONDS = 20.0
SUPERVISOR_INTERVAL_SECONDS = 1.0
SUPPORTED_APPLICATION_TYPES = {
    "HTTP_WEBSITE",
    "HTTPS_WEBSITE",
    "REST_API",
    "CONTROLLED_LOCAL_APPLICATION",
}
def _utc_timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _application_url(application):
    base_url = str(application.get("url") or "").strip()
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("Monitoring only supports absolute HTTP or HTTPS URLs.")

    endpoint_path = str(application.get("endpoint_path") or "").strip()
    if endpoint_path:
        base_url = urljoin(base_url.rstrip("/") + "/", endpoint_path.lstrip("/"))
    final_url = urlparse(base_url)
    if final_url.scheme not in ("http", "https") or not final_url.netloc:
        raise ValueError("Application endpoint must use HTTP or HTTPS.")
    return base_url


def _process_monitoring_allowed(application):
    return (
        bool(application.get("owned_by_platform"))
        and bool(application.get("process_monitoring_permitted"))
    )


def _normalized_path(value):
    if not value:
        return None
    try:
        return str(Path(value).resolve()).casefold()
    except (OSError, RuntimeError, TypeError, ValueError):
        return str(value).casefold()


def find_owned_process(application, process_provider=psutil):
    if not _process_monitoring_allowed(application):
        return None, "Process monitoring is not permitted for this application."

    expected_executable = _normalized_path(
        application.get("process_executable_path")
    )
    expected_working_directory = _normalized_path(
        application.get("process_working_directory")
    )
    expected_name = str(application.get("process_name") or "").casefold()
    if not (expected_executable or expected_working_directory):
        return None, (
            "Process metrics were withheld because no verifiable executable "
            "path or working directory is configured."
        )

    matches = []
    for process in process_provider.process_iter(["pid", "name", "exe", "cwd"]):
        try:
            info = process.info
            process_name = str(info.get("name") or "").casefold()
            executable = _normalized_path(info.get("exe"))
            working_directory = _normalized_path(info.get("cwd"))
            if expected_name and process_name != expected_name:
                continue
            if expected_executable and executable != expected_executable:
                continue
            if (
                expected_working_directory
                and working_directory != expected_working_directory
            ):
                continue
            matches.append(process)
        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            OSError,
        ):
            continue

    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, "Process identity matched multiple processes; metrics withheld."
    return None, "No process matched the registered owned-application identity."


def _process_metrics(application, process_provider=psutil):
    if not _process_monitoring_allowed(application):
        return {
            "cpu_usage": None,
            "memory_usage": None,
            "process_id": None,
            "process_status": None,
            "process_memory_mb": None,
            "process_cpu_percent": None,
            "process_error": None,
        }

    process, error = find_owned_process(application, process_provider)
    if process is None:
        return {
            "cpu_usage": None,
            "memory_usage": None,
            "process_id": None,
            "process_status": None,
            "process_memory_mb": None,
            "process_cpu_percent": None,
            "process_error": error,
        }
    try:
        memory = process.memory_info()
        memory_mb = memory.rss / (1024 * 1024)
        memory_percent = process.memory_percent()
        cpu_percent = process.cpu_percent(interval=None)
        return {
            "cpu_usage": cpu_percent,
            "memory_usage": memory_percent,
            "process_id": process.pid,
            "process_status": process.status(),
            "process_memory_mb": memory_mb,
            "process_cpu_percent": cpu_percent,
            "process_error": None,
        }
    except (
        psutil.AccessDenied,
        psutil.NoSuchProcess,
        psutil.ZombieProcess,
        OSError,
    ) as error:
        return {
            "cpu_usage": None,
            "memory_usage": None,
            "process_id": None,
            "process_status": None,
            "process_memory_mb": None,
            "process_cpu_percent": None,
            "process_error": str(error),
        }


def _failure_kind(error):
    if isinstance(error, (socket.timeout, TimeoutError)):
        return "timeout"
    if isinstance(error, URLError):
        if isinstance(error.reason, (socket.timeout, TimeoutError)):
            return "timeout"
        if isinstance(error.reason, ssl.SSLError):
            return "ssl_error"
        return "connection_error"
    if isinstance(error, (ConnectionError, OSError, ssl.SSLError, HTTPException)):
        return "connection_error"
    return "request_error"


def store_application_telemetry(reading, db_path=None, source="multi_app_monitor"):
    application_id = str(reading.get("application_id") or "").strip()
    timestamp = str(reading.get("timestamp") or "").strip()
    if not application_id:
        raise ValueError("Telemetry reading must include application_id.")
    if not timestamp:
        raise ValueError("Telemetry reading must include timestamp.")
    created_at = str(reading.get("created_at") or _utc_timestamp())
    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO application_telemetry (
                application_id, source, timestamp, data_json,
                is_simulated, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                application_id,
                source,
                timestamp,
                json.dumps(reading, separators=(",", ":"), allow_nan=False),
                1 if reading.get("is_simulated") else 0,
                created_at,
            ),
        )


class ApplicationMonitor:
    def __init__(
        self,
        db_path=None,
        request_timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
        request_function=None,
        process_provider=psutil,
        is_simulated=False,
        simulation_id=None,
        telemetry_source="multi_app_monitor",
    ):
        if not isinstance(is_simulated, bool):
            raise ValueError("is_simulated must be a boolean.")
        self.db_path = db_path
        self.request_timeout = min(
            max(float(request_timeout), 0.1),
            MAX_REQUEST_TIMEOUT_SECONDS,
        )
        self.request_function = request_function or urlopen
        self.process_provider = process_provider
        self.is_simulated = is_simulated
        self.simulation_id = simulation_id
        self.telemetry_source = telemetry_source
        self._states = {}
        self._state_lock = threading.Lock()
        initialize_database(db_path)

    def _state_for(self, application_id):
        with self._state_lock:
            return self._states.setdefault(
                application_id,
                {
                    "consecutive_failure_count": 0,
                    "last_successful_response_time_ms": None,
                },
            )

    def _request_metrics(self, application, state):
        started = time.perf_counter()
        result = {
            "availability": False,
            "http_status_code": None,
            "response_time_ms": None,
            "request_success": False,
            "connection_error": False,
            "timeout_error": False,
            "failure_type": None,
            "consecutive_failure_count": state["consecutive_failure_count"],
            "last_successful_response_time_ms":
                state["last_successful_response_time_ms"],
            "error_details": None,
        }
        try:
            url = _application_url(application)
            request = Request(
                url,
                headers={"User-Agent": "SDP-AIOps-Monitor/1.0"},
                method="GET",
            )
            request_function = self.request_function
            if request_function is urlopen:
                from app.browser_discovery import (
                    is_browser_discovered_application,
                    safe_discovery_urlopen,
                )

                if is_browser_discovered_application(
                    application["application_id"],
                    db_path=self.db_path,
                ):
                    request_function = safe_discovery_urlopen
            with request_function(
                request,
                timeout=self.request_timeout,
            ) as response:
                status_code = int(response.status)
            elapsed_ms = (time.perf_counter() - started) * 1000
            success = 200 <= status_code < 400
            result.update(
                availability=True,
                http_status_code=status_code,
                response_time_ms=elapsed_ms,
                request_success=success,
                failure_type=None if success else "http_error",
                error_details=(
                    None if success else f"HTTP request returned status {status_code}."
                ),
            )
        except HTTPError as error:
            elapsed_ms = (time.perf_counter() - started) * 1000
            result.update(
                availability=True,
                http_status_code=error.code,
                response_time_ms=elapsed_ms,
                request_success=False,
                failure_type="http_error",
                error_details=f"HTTP request returned status {error.code}.",
            )
            if error.fp is not None:
                error.close()
        except (
            URLError,
            TimeoutError,
            socket.timeout,
            OSError,
            ssl.SSLError,
            HTTPException,
            ValueError,
        ) as error:
            failure_type = _failure_kind(error)
            result.update(
                response_time_ms=(time.perf_counter() - started) * 1000,
                request_success=False,
                connection_error=failure_type in {
                    "connection_error",
                    "ssl_error",
                },
                timeout_error=failure_type == "timeout",
                failure_type=failure_type,
                error_details=str(error),
            )

        if result["request_success"]:
            state["consecutive_failure_count"] = 0
            state["last_successful_response_time_ms"] = result["response_time_ms"]
        else:
            state["consecutive_failure_count"] += 1
        result["consecutive_failure_count"] = state["consecutive_failure_count"]
        result["last_successful_response_time_ms"] = (
            state["last_successful_response_time_ms"]
        )
        return result

    def collect_reading(self, application):
        timestamp = _utc_timestamp()
        application_id = application["application_id"]
        state = self._state_for(application_id)
        app_type = str(application.get("application_type") or "").upper()

        reading = {
            "application_id": application_id,
            "timestamp": timestamp,
            "availability": False,
            "http_status_code": None,
            "response_time_ms": None,
            "request_success": False,
            "connection_error": False,
            "timeout_error": False,
            "failure_type": None,
            "consecutive_failure_count": state["consecutive_failure_count"],
            "last_successful_response_time_ms":
                state["last_successful_response_time_ms"],
            "cpu_usage": None,
            "memory_usage": None,
            "process_id": None,
            "process_status": None,
            "process_memory_mb": None,
            "process_cpu_percent": None,
            "error_details": None,
            "is_simulated": self.is_simulated,
            "simulation_id": self.simulation_id,
        }

        if app_type not in SUPPORTED_APPLICATION_TYPES:
            reading.update(
                failure_type="unsupported_application_type",
                error_details=f"Unsupported application type: {app_type}",
            )
            state["consecutive_failure_count"] += 1
            reading["consecutive_failure_count"] = (
                state["consecutive_failure_count"]
            )
        else:
            try:
                reading.update(self._request_metrics(application, state))
            except Exception as error:
                LOGGER.exception(
                    "Failed to collect HTTP telemetry for application %s",
                    application_id,
                )
                state["consecutive_failure_count"] += 1
                reading.update(
                    availability=False,
                    request_success=False,
                    failure_type="monitor_error",
                    error_details=str(error),
                    consecutive_failure_count=state["consecutive_failure_count"],
                )

        if _process_monitoring_allowed(application):
            try:
                process_values = _process_metrics(
                    application,
                    self.process_provider,
                )
            except Exception as error:
                LOGGER.exception(
                    "Could not collect owned process telemetry for %s",
                    application_id,
                )
                process_values = {
                    "cpu_usage": None,
                    "memory_usage": None,
                    "process_id": None,
                    "process_status": None,
                    "process_memory_mb": None,
                    "process_cpu_percent": None,
                    "process_error": str(error),
                }
            reading.update(process_values)
            if process_values["process_error"]:
                reading["error_details"] = (
                    f"{reading['error_details']}; "
                    if reading["error_details"]
                    else ""
                ) + process_values["process_error"]

        reading["created_at"] = _utc_timestamp()
        self.store_reading(reading)
        return reading

    def store_reading(self, reading):
        store_application_telemetry(
            reading,
            db_path=self.db_path,
            source=self.telemetry_source,
        )

    def monitor_once(self, application_id):
        application = get_application(application_id, db_path=self.db_path)
        if application is None:
            raise KeyError(f"Application not found: {application_id}")
        if not application["active"]:
            return None
        return self.collect_reading(application)


class MultiApplicationMonitor:
    def __init__(
        self,
        db_path=None,
        request_timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
        request_function=None,
        process_provider=psutil,
        supervisor_interval=SUPERVISOR_INTERVAL_SECONDS,
    ):
        self.engine = ApplicationMonitor(
            db_path=db_path,
            request_timeout=request_timeout,
            request_function=request_function,
            process_provider=process_provider,
        )
        self.db_path = db_path
        self.supervisor_interval = max(0.1, float(supervisor_interval))
        self._excluded_application_ids = set()
        self._workers = {}
        self._workers_lock = threading.Lock()
        self._supervisor_stop = threading.Event()
        self._supervisor = None

    @property
    def worker_ids(self):
        with self._workers_lock:
            return tuple(self._workers)

    def start(self, exclude_application_ids=()):
        self._excluded_application_ids.update(exclude_application_ids)
        with self._workers_lock:
            if self._supervisor and self._supervisor.is_alive():
                pass
            else:
                self._supervisor_stop.clear()
                self._supervisor = threading.Thread(
                    target=self._supervise,
                    name="sdp-multi-app-supervisor",
                    daemon=True,
                )
                self._supervisor.start()
        self.refresh()
        return self

    def refresh(self):
        applications = get_applications(
            db_path=self.db_path,
            include_inactive=False,
        )
        enabled_ids = {
            application["application_id"]
            for application in applications
            if application["application_id"] not in self._excluded_application_ids
        }
        with self._workers_lock:
            for application_id in enabled_ids:
                worker = self._workers.get(application_id)
                if worker and worker[0].is_alive():
                    continue
                stop_event = threading.Event()
                thread = threading.Thread(
                    target=self._run_application,
                    args=(application_id, stop_event),
                    name=f"sdp-monitor-{application_id}",
                    daemon=True,
                )
                self._workers[application_id] = (thread, stop_event)
                thread.start()

            for application_id in set(self._workers).difference(enabled_ids):
                _, stop_event = self._workers[application_id]
                stop_event.set()
        return self.worker_ids

    def _run_application(self, application_id, stop_event):
        while not stop_event.is_set():
            try:
                application = get_application(
                    application_id,
                    db_path=self.db_path,
                )
                if application is None or not application["active"]:
                    return
                self.engine.collect_reading(application)
                try:
                    from ml.detect_anomalies import analyze_application

                    detection = analyze_application(
                        application_id,
                        db_path=self.db_path,
                    )
                except Exception:
                    LOGGER.exception(
                        "Anomaly detection failed for application %s; "
                        "monitoring will continue.",
                        application_id,
                    )
                else:
                    for anomaly in detection.get("anomalies", []):
                        try:
                            from ml.application_root_cause import (
                                generate_application_rca,
                            )

                            generate_application_rca(
                                application_id,
                                source_timestamp=anomaly["timestamp"],
                                db_path=self.db_path,
                            )
                        except Exception:
                            LOGGER.exception(
                                "Root cause analysis failed for application %s "
                                "at %s; monitoring will continue.",
                                application_id,
                                anomaly.get("timestamp"),
                            )
                        try:
                            from app.incident_management import (
                                process_application_anomaly,
                            )

                            incident_id = process_application_anomaly(
                                application_id,
                                anomaly["timestamp"],
                                db_path=self.db_path,
                            )
                        except Exception:
                            LOGGER.exception(
                                "Incident processing failed for application %s "
                                "at %s; monitoring will continue.",
                                application_id,
                                anomaly.get("timestamp"),
                            )
                        else:
                            if incident_id:
                                try:
                                    from app.recovery_framework import process_incident

                                    process_incident(
                                        incident_id,
                                        db_path=self.db_path,
                                    )
                                except Exception:
                                    LOGGER.exception(
                                        "Recovery processing failed for application %s "
                                        "at %s; monitoring will continue.",
                                        application_id,
                                        anomaly.get("timestamp"),
                                    )
                interval = max(
                    1,
                    int(application["monitoring_interval_seconds"]),
                )
            except Exception:
                LOGGER.exception(
                    "Monitoring worker failed for application %s",
                    application_id,
                )
                try:
                    application = get_application(
                        application_id,
                        db_path=self.db_path,
                    )
                    interval = max(
                        1,
                        int(application["monitoring_interval_seconds"]),
                    ) if application else 1
                except Exception:
                    LOGGER.exception(
                        "Could not reload monitoring interval for application %s",
                        application_id,
                    )
                    interval = 1
            stop_event.wait(interval)

    def _supervise(self):
        while not self._supervisor_stop.wait(self.supervisor_interval):
            try:
                self.refresh()
            except Exception:
                LOGGER.exception("Could not refresh multi-application workers.")

    def stop(self, timeout=DEFAULT_STOP_TIMEOUT_SECONDS):
        self._supervisor_stop.set()
        with self._workers_lock:
            workers = list(self._workers.values())
            supervisor = self._supervisor
        for _, stop_event in workers:
            stop_event.set()
        deadline = time.monotonic() + max(0.0, timeout)
        for thread, _ in workers:
            thread.join(max(0.0, deadline - time.monotonic()))
        if supervisor and supervisor is not threading.current_thread():
            supervisor.join(max(0.0, deadline - time.monotonic()))
        with self._workers_lock:
            self._workers.clear()
        return True


_default_monitor_lock = threading.Lock()
_default_monitor = None


def start_monitoring(
    db_path=None,
    request_timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
    exclude_application_ids=(),
):
    global _default_monitor
    with _default_monitor_lock:
        if _default_monitor is None:
            _default_monitor = MultiApplicationMonitor(
                db_path=db_path,
                request_timeout=request_timeout,
            )
        return _default_monitor.start(
            exclude_application_ids=exclude_application_ids,
        )


def stop_monitoring(timeout=DEFAULT_STOP_TIMEOUT_SECONDS):
    global _default_monitor
    with _default_monitor_lock:
        monitor = _default_monitor
        _default_monitor = None
    if monitor is not None:
        return monitor.stop(timeout=timeout)
    return False


def monitor_application_once(
    application_id,
    db_path=None,
    request_timeout=DEFAULT_REQUEST_TIMEOUT_SECONDS,
    request_function=None,
    process_provider=psutil,
    is_simulated=False,
    simulation_id=None,
    telemetry_source="multi_app_monitor",
):
    return ApplicationMonitor(
        db_path=db_path,
        request_timeout=request_timeout,
        request_function=request_function,
        process_provider=process_provider,
        is_simulated=is_simulated,
        simulation_id=simulation_id,
        telemetry_source=telemetry_source,
    ).monitor_once(application_id)
