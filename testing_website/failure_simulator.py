import json
import logging
import threading
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from app.application_registry import get_application
from app.multi_app_monitor import find_owned_process
from testing_website.demo_app import (
    DEMO_APPLICATIONS,
    MAX_CPU_PERCENT,
    MAX_DELAY_MS,
    MAX_FAULT_DURATION_SECONDS,
    MAX_MEMORY_MB,
    get_demo_application_manager,
)
from testing_website.simulation_store import (
    finish_simulation_event,
    get_simulation_event,
    list_simulation_events,
    start_simulation_event,
)


LOGGER = logging.getLogger(__name__)
SUPPORTED_SCENARIOS = (
    "cpu_load",
    "memory_pressure",
    "api_latency",
    "http_errors",
    "application_downtime",
    "database_delay",
    "worker_failure",
)


def _integer(value, field, minimum, maximum):
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer.")
    try:
        converted = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be an integer.") from error
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field} must be an integer.")
    if not minimum <= converted <= maximum:
        raise ValueError(f"{field} must be between {minimum} and {maximum}.")
    return converted


def _validate_target(application_id, db_path):
    if application_id not in DEMO_APPLICATIONS:
        raise ValueError("Faults are restricted to registered SDP demo applications.")
    application = get_application(application_id, db_path=db_path)
    if (
        application is None
        or not application["active"]
        or not application["owned_by_platform"]
        or not application["process_monitoring_permitted"]
        or not application["automatic_recovery_permitted"]
        or application["application_type"] != "CONTROLLED_LOCAL_APPLICATION"
    ):
        raise ValueError(
            "Fault injection requires an active, controlled, platform-owned demo application."
        )
    expected = DEMO_APPLICATIONS[application_id]
    parsed = urlparse(application["url"])
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != expected["port"]
    ):
        raise ValueError("Fault targets must use the fixed loopback demo endpoint.")
    process, error = find_owned_process(application)
    if process is None:
        raise RuntimeError(error or "The registered demo process could not be verified.")
    return application, expected


def _validate_configuration(scenario, configuration, demo):
    if not isinstance(configuration, dict):
        raise ValueError("configuration must be a mapping.")
    supported_fields = {
        "cpu_load": {"duration_seconds", "cpu_percent"},
        "memory_pressure": {"duration_seconds", "memory_mb"},
        "api_latency": {"duration_seconds", "delay_ms", "endpoint"},
        "http_errors": {"duration_seconds", "endpoint"},
        "application_downtime": {"duration_seconds"},
        "database_delay": {"duration_seconds", "delay_ms", "endpoint"},
        "worker_failure": {"duration_seconds", "endpoint"},
    }
    if scenario not in supported_fields:
        raise ValueError(f"Unsupported fault scenario: {scenario}.")
    unknown = set(configuration).difference(supported_fields[scenario])
    if unknown:
        raise ValueError(
            "Unsupported scenario configuration field(s): "
            + ", ".join(sorted(unknown))
        )
    duration = _integer(
        configuration.get("duration_seconds", 5),
        "duration_seconds",
        1,
        MAX_FAULT_DURATION_SECONDS,
    )
    validated = {"duration_seconds": duration}
    if scenario == "cpu_load":
        validated["cpu_percent"] = _integer(
            configuration.get("cpu_percent", 30),
            "cpu_percent",
            1,
            MAX_CPU_PERCENT,
        )
    elif scenario == "memory_pressure":
        validated["memory_mb"] = _integer(
            configuration.get("memory_mb", 16),
            "memory_mb",
            1,
            MAX_MEMORY_MB,
        )
    elif scenario in {"api_latency", "database_delay"}:
        validated["delay_ms"] = _integer(
            configuration.get("delay_ms", 1000),
            "delay_ms",
            1,
            MAX_DELAY_MS,
        )

    if scenario in {
        "api_latency",
        "http_errors",
        "database_delay",
        "worker_failure",
    }:
        endpoint = configuration.get("endpoint", "/health")
        if not isinstance(endpoint, str) or endpoint not in demo["paths"]:
            raise ValueError("endpoint must be a path registered for the demo application.")
        validated["endpoint"] = endpoint
    return validated


def _control_request(application, method, payload=None):
    parsed = urlparse(application["url"])
    if parsed.scheme != "http" or parsed.hostname != "127.0.0.1":
        raise ValueError("Simulation controls may only target loopback services.")
    data = (
        json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if payload is not None
        else None
    )
    request = Request(
        application["url"].rstrip("/") + "/__simulation__/faults",
        data=data,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    with urlopen(request, timeout=2) as response:
        body = response.read(4096)
        if response.status < 200 or response.status >= 300:
            raise RuntimeError(
                f"Demo service control returned HTTP {response.status}."
            )
    return json.loads(body.decode("utf-8")) if body else {}


class FailureSimulator:
    def __init__(self, db_path=None, application_manager=None):
        self.db_path = db_path
        self.application_manager = application_manager or get_demo_application_manager(
            db_path
        )
        self._lock = threading.RLock()
        self._active = {}

    def start_simulation(
        self,
        application_id,
        scenario,
        configuration=None,
        *,
        confirm=False,
    ):
        if confirm is not True:
            raise ValueError("Explicit confirmation is required before fault injection.")
        if scenario not in SUPPORTED_SCENARIOS:
            raise ValueError(f"Unsupported fault scenario: {scenario}.")
        configuration = dict(configuration or {})
        application = self.application_manager.ensure_application(application_id)
        application, demo = _validate_target(application_id, self.db_path)
        validated = _validate_configuration(scenario, configuration, demo)

        with self._lock:
            if application_id in self._active:
                raise RuntimeError(
                    "A fault simulation is already active for this application."
                )
            simulation_id = start_simulation_event(
                application_id,
                scenario,
                {
                    "configuration": validated,
                    "affected_endpoint": validated.get("endpoint", "/health"),
                    "workload_details": None,
                    "error_details": None,
                    "cleanup_result": "pending",
                },
                db_path=self.db_path,
            )
            timer = threading.Timer(
                validated["duration_seconds"],
                self.stop_simulation,
                args=(simulation_id, "duration limit"),
            )
            timer.daemon = True
            state = {
                "simulation_id": simulation_id,
                "application_id": application_id,
                "application": application,
                "scenario": scenario,
                "configuration": validated,
                "timer": timer,
                "stopping": False,
            }
            self._active[application_id] = state

        try:
            if scenario == "application_downtime":
                stopped = self.application_manager.stop_application(application_id)
                if not stopped:
                    raise RuntimeError("The controlled demo process was not running.")
            else:
                _control_request(
                    application,
                    "POST",
                    {"scenario": scenario, "configuration": validated},
                )
            timer.start()
        except (OSError, RuntimeError, URLError, ValueError) as error:
            cleanup_result = "No cleanup was needed."
            cleanup_error = None
            try:
                if scenario == "application_downtime":
                    self.application_manager.restart_application(application_id)
                    cleanup_result = "Stopped demo process restarted and health-checked."
                else:
                    try:
                        _control_request(application, "DELETE")
                        cleanup_result = "Partially started fault resources were cleared."
                    except (OSError, RuntimeError, URLError, ValueError):
                        self.application_manager.restart_application(application_id)
                        cleanup_result = (
                            "Demo process restarted through registered process control."
                        )
            except (OSError, RuntimeError, URLError, ValueError) as cleanup_exception:
                cleanup_error = str(cleanup_exception)
                cleanup_result = "Cleanup failed."
                LOGGER.exception(
                    "Cleanup after failed simulation start %s failed",
                    simulation_id,
                )
            try:
                finish_simulation_event(
                    simulation_id,
                    status="Failed",
                    updates={
                        "ended_at": None,
                        "error_details": str(error),
                        "cleanup_error": cleanup_error,
                        "cleanup_result": cleanup_result,
                    },
                    db_path=self.db_path,
                )
            except (OSError, RuntimeError, ValueError):
                LOGGER.exception(
                    "Could not record failed simulation %s",
                    simulation_id,
                )
            finally:
                with self._lock:
                    self._active.pop(application_id, None)
            LOGGER.exception(
                "Could not start controlled fault %s for %s",
                scenario,
                application_id,
            )
            raise

        LOGGER.info(
            "Started simulation %s (%s) for %s",
            simulation_id,
            scenario,
            application_id,
        )
        return simulation_id

    def stop_simulation(self, simulation_id, reason="operator stop"):
        with self._lock:
            state = next(
                (
                    value
                    for value in self._active.values()
                    if value["simulation_id"] == simulation_id
                ),
                None,
            )
            if state is None or state["stopping"]:
                return False
            state["stopping"] = True
            timer = state["timer"]
            timer.cancel()

        cleanup_result = ""
        error_details = ""
        try:
            if state["scenario"] == "application_downtime":
                self.application_manager.restart_application(
                    state["application_id"]
                )
                cleanup_result = "Stopped process restarted and health-checked."
            else:
                try:
                    _control_request(state["application"], "DELETE")
                    cleanup_result = "In-process fault workers stopped and resources released."
                except (OSError, RuntimeError, URLError, ValueError):
                    self.application_manager.restart_application(
                        state["application_id"]
                    )
                    cleanup_result = (
                        "Demo process restarted through registered process control."
                    )
        except (OSError, RuntimeError, URLError, ValueError) as error:
            error_details = str(error)
            cleanup_result = "Cleanup failed."
            LOGGER.exception(
                "Simulation %s cleanup failed",
                simulation_id,
            )

        status = (
            "Failed"
            if error_details
            else "Completed"
            if reason == "duration limit"
            else "Stopped"
        )
        try:
            finish_simulation_event(
                simulation_id,
                status=status,
                updates={
                    "cleanup_result": cleanup_result,
                    "error_details": error_details or None,
                    "stopped_by": reason,
                },
                db_path=self.db_path,
            )
            result = get_simulation_event(simulation_id, db_path=self.db_path)
        finally:
            with self._lock:
                self._active.pop(state["application_id"], None)
        LOGGER.info(
            "Stopped simulation %s with status %s (%s)",
            simulation_id,
            status,
            cleanup_result,
        )
        return result

    def emergency_stop(self):
        with self._lock:
            simulation_ids = [
                value["simulation_id"] for value in self._active.values()
            ]
        results = {}
        for simulation_id in simulation_ids:
            try:
                results[simulation_id] = self.stop_simulation(
                    simulation_id,
                    "emergency stop",
                )
            except (OSError, RuntimeError, URLError, ValueError) as error:
                LOGGER.exception(
                    "Emergency stop failed for simulation %s",
                    simulation_id,
                )
                results[simulation_id] = {"error": str(error)}
        return results

    def active_simulations(self):
        with self._lock:
            return [
                {
                    "simulation_id": state["simulation_id"],
                    "application_id": state["application_id"],
                    "scenario": state["scenario"],
                    "configuration": dict(state["configuration"]),
                }
                for state in self._active.values()
            ]

    def get_simulation(self, simulation_id):
        return get_simulation_event(simulation_id, db_path=self.db_path)

    def history(self, application_id=None, limit=100):
        return list_simulation_events(
            application_id=application_id,
            limit=limit,
            db_path=self.db_path,
        )
