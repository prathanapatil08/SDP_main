import argparse
import gc
import logging
import os
import sqlite3
import subprocess
import threading
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from flask import Flask, jsonify, request


BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in os.sys.path:
    os.sys.path.insert(0, str(BASE_DIR))

from app.application_registry import get_application, register_application, update_application
from app.database import get_database_path, initialize_database
from app.multi_app_monitor import find_owned_process


LOGGER = logging.getLogger(__name__)
MAX_FAULT_DURATION_SECONDS = 30
MAX_CPU_PERCENT = 50
MAX_MEMORY_MB = 64
MAX_DELAY_MS = 5000
DEMO_APPLICATIONS = {
    "APP-SDP-DEMO-ECOMMERCE": {
        "service": "ecommerce",
        "name": "SDP E-commerce Demo",
        "port": 5101,
        "paths": (
            "/health",
            "/products",
            "/products/1",
            "/products/2",
            "/search",
            "/cart",
            "/worker",
        ),
    },
    "APP-SDP-DEMO-STREAMING": {
        "service": "streaming",
        "name": "SDP Video Streaming Demo",
        "port": 5102,
        "paths": (
            "/health",
            "/videos",
            "/videos/1",
            "/videos/2",
            "/stream/1",
            "/stream/2",
            "/worker",
        ),
    },
}
DEMO_SCRIPT = Path(__file__).resolve()
DEMO_RUNTIME_ROOT = BASE_DIR / "data" / "demo_services"


def _is_loopback_request():
    return request.remote_addr in {"127.0.0.1", "::1"}


def _valid_duration(value):
    if isinstance(value, bool):
        raise ValueError("duration_seconds must be an integer.")
    try:
        duration = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError("duration_seconds must be an integer.") from error
    if not 1 <= duration <= MAX_FAULT_DURATION_SECONDS:
        raise ValueError(
            f"duration_seconds must be between 1 and {MAX_FAULT_DURATION_SECONDS}."
        )
    return duration


class FaultState:
    def __init__(self):
        self._lock = threading.RLock()
        self._faults = {}
        self._workers = {}

    def _start_worker(self, scenario, duration, worker):
        stop_event = threading.Event()
        ready_event = threading.Event()
        errors = []

        def run():
            try:
                worker(stop_event, ready_event)
            except (MemoryError, OSError, RuntimeError) as error:
                errors.append(str(error))
                LOGGER.exception("Demo fault worker %s failed", scenario)
            finally:
                with self._lock:
                    self._workers.pop(scenario, None)

        thread = threading.Thread(
            target=run,
            name=f"sdp-demo-{scenario}",
            daemon=True,
        )
        self._workers[scenario] = (stop_event, thread)
        thread.start()
        if not ready_event.wait(timeout=2):
            stop_event.set()
            thread.join(timeout=2)
            self._workers.pop(scenario, None)
            raise RuntimeError(f"{scenario} worker did not become ready.")
        if errors:
            raise RuntimeError(errors[0])

        timer = threading.Timer(duration, self.clear, args=(scenario,))
        timer.daemon = True
        self._faults[scenario] = {
            "ends_at": time.monotonic() + duration,
            "timer": timer,
            "stop_event": stop_event,
            "configuration": {},
        }
        timer.start()

    def apply(self, scenario, configuration):
        duration = _valid_duration(configuration.get("duration_seconds"))
        with self._lock:
            if self._faults:
                raise RuntimeError("Only one fault may be active per demo application.")

            if scenario == "cpu_load":
                cpu_percent = configuration.get("cpu_percent", 30)
                if (
                    isinstance(cpu_percent, bool)
                    or not isinstance(cpu_percent, int)
                    or not 1 <= cpu_percent <= MAX_CPU_PERCENT
                ):
                    raise ValueError(
                        f"cpu_percent must be between 1 and {MAX_CPU_PERCENT}."
                    )

                def cpu_worker(stop_event, ready_event):
                    ready_event.set()
                    cycle = 0.1
                    busy_seconds = cycle * cpu_percent / 100
                    while not stop_event.is_set():
                        deadline = time.perf_counter() + busy_seconds
                        while (
                            time.perf_counter() < deadline
                            and not stop_event.is_set()
                        ):
                            pass
                        stop_event.wait(cycle - busy_seconds)

                self._start_worker(scenario, duration, cpu_worker)
                self._faults[scenario]["configuration"] = {
                    "cpu_percent": cpu_percent,
                    "duration_seconds": duration,
                }
                return

            if scenario == "memory_pressure":
                memory_mb = configuration.get("memory_mb", 16)
                if (
                    isinstance(memory_mb, bool)
                    or not isinstance(memory_mb, int)
                    or not 1 <= memory_mb <= MAX_MEMORY_MB
                ):
                    raise ValueError(
                        f"memory_mb must be between 1 and {MAX_MEMORY_MB}."
                    )

                def memory_worker(stop_event, ready_event):
                    payload = bytearray(memory_mb * 1_000_000)
                    for offset in range(0, len(payload), 4096):
                        payload[offset] = 1
                    ready_event.set()
                    try:
                        stop_event.wait(duration)
                    finally:
                        payload = None
                        gc.collect()

                self._start_worker(scenario, duration, memory_worker)
                self._faults[scenario]["configuration"] = {
                    "memory_mb": memory_mb,
                    "duration_seconds": duration,
                }
                return

            if scenario in {"api_latency", "database_delay"}:
                delay_ms = configuration.get("delay_ms", 1000)
                if (
                    isinstance(delay_ms, bool)
                    or not isinstance(delay_ms, int)
                    or not 1 <= delay_ms <= MAX_DELAY_MS
                ):
                    raise ValueError(
                        f"delay_ms must be between 1 and {MAX_DELAY_MS}."
                    )
                endpoint = configuration.get("endpoint", "/health")
                if not isinstance(endpoint, str) or not endpoint.startswith("/"):
                    raise ValueError("endpoint must be an absolute local path.")
                self._faults[scenario] = {
                    "ends_at": time.monotonic() + duration,
                    "timer": threading.Timer(
                        duration,
                        self.clear,
                        args=(scenario,),
                    ),
                    "configuration": {
                        "delay_ms": delay_ms,
                        "endpoint": endpoint,
                        "duration_seconds": duration,
                    },
                }
                self._faults[scenario]["timer"].daemon = True
                self._faults[scenario]["timer"].start()
                return

            if scenario in {"http_errors", "worker_failure"}:
                endpoint = configuration.get("endpoint", "/health")
                if not isinstance(endpoint, str) or not endpoint.startswith("/"):
                    raise ValueError("endpoint must be an absolute local path.")
                timer = threading.Timer(
                    duration,
                    self.clear,
                    args=(scenario,),
                )
                timer.daemon = True
                self._faults[scenario] = {
                    "ends_at": time.monotonic() + duration,
                    "timer": timer,
                    "configuration": {
                        "endpoint": endpoint,
                        "duration_seconds": duration,
                    },
                }
                timer.start()
                return
            raise ValueError(f"Unsupported in-process fault scenario: {scenario}.")

    def effects_for(self, endpoint):
        effects = []
        with self._lock:
            expired = [
                scenario
                for scenario, details in self._faults.items()
                if details["ends_at"] <= time.monotonic()
            ]
        for scenario in expired:
            self.clear(scenario)

        with self._lock:
            for scenario, details in self._faults.items():
                configuration = details["configuration"]
                if scenario == "worker_failure" and endpoint in {
                    configuration["endpoint"],
                    "/worker",
                }:
                    return {"http_error": 503, "scenario": scenario}
                if configuration.get("endpoint") not in (None, endpoint):
                    continue
                if scenario == "http_errors":
                    return {"http_error": 500, "scenario": scenario}
                if scenario == "api_latency":
                    effects.append(configuration["delay_ms"] / 1000)
        return {"delays": effects}

    def database_delay_ms_for(self, endpoint):
        with self._lock:
            for scenario, details in self._faults.items():
                configuration = details["configuration"]
                if (
                    scenario == "database_delay"
                    and configuration.get("endpoint") == endpoint
                ):
                    return configuration["delay_ms"]
        return 0

    def clear(self, scenario=None):
        with self._lock:
            targets = (
                list(self._faults)
                if scenario is None
                else [scenario] if scenario in self._faults else []
            )
            workers = []
            cleanup_errors = []
            for name in targets:
                details = self._faults.pop(name)
                timer = details.get("timer")
                if timer:
                    timer.cancel()
                worker = self._workers.pop(name, None)
                if worker:
                    stop_event, thread = worker
                    stop_event.set()
                    workers.append((name, thread))
        for name, thread in workers:
            if thread is not threading.current_thread():
                thread.join(timeout=2)
            if thread.is_alive():
                cleanup_errors.append(f"{name} worker did not stop.")
        if cleanup_errors:
            raise RuntimeError("; ".join(cleanup_errors))
        return targets

    def active_faults(self):
        with self._lock:
            return {
                name: dict(details["configuration"])
                for name, details in self._faults.items()
            }


PRODUCTS = [
    {"id": 1, "name": "Demo headphones", "price": 49.99, "stock": 12},
    {"id": 2, "name": "Demo keyboard", "price": 79.99, "stock": 8},
]
VIDEOS = [
    {"id": 1, "title": "AIOps overview", "duration_seconds": 180},
    {"id": 2, "title": "Monitoring basics", "duration_seconds": 240},
]


def _simulate_database_operation(faults, endpoint):
    delay_ms = faults.database_delay_ms_for(endpoint)
    if delay_ms:
        time.sleep(delay_ms / 1000)


def create_demo_app(service):
    if service not in {"ecommerce", "streaming"}:
        raise ValueError("service must be ecommerce or streaming.")
    app = Flask(f"sdp_{service}_demo")
    faults = FaultState()
    app.config["SIMULATION_STATE"] = faults

    @app.before_request
    def apply_simulated_effects():
        if request.path.startswith("/__simulation__/"):
            if not _is_loopback_request():
                return jsonify({"error": "Simulation controls are loopback-only."}), 403
            return None
        effects = faults.effects_for(request.path)
        if effects.get("http_error"):
            return jsonify(
                {
                    "error": "Controlled simulated HTTP error.",
                    "simulated": True,
                }
            ), effects["http_error"]
        if effects.get("delays"):
            time.sleep(sum(effects["delays"]))
        return None

    @app.get("/health")
    def health():
        _simulate_database_operation(faults, "/health")
        if faults.active_faults().get("worker_failure"):
            return jsonify({"status": "degraded", "service": service}), 503
        return jsonify({"status": "healthy", "service": service}), 200

    @app.get("/worker")
    def worker_health():
        _simulate_database_operation(faults, "/worker")
        effects = faults.effects_for("/worker")
        status = effects.get("http_error", 200)
        return jsonify({"status": "healthy" if status == 200 else "unavailable"}), status

    if service == "ecommerce":
        @app.get("/products")
        def products():
            _simulate_database_operation(faults, "/products")
            return jsonify({"products": PRODUCTS})

        @app.get("/products/<int:product_id>")
        def product_details(product_id):
            _simulate_database_operation(faults, request.path)
            product = next((item for item in PRODUCTS if item["id"] == product_id), None)
            if product is None:
                return jsonify({"error": "Product not found."}), 404
            return jsonify({"product": product})

        @app.get("/search")
        def search():
            _simulate_database_operation(faults, "/search")
            query = request.args.get("q", "").strip().casefold()
            matches = [
                item for item in PRODUCTS if query in item["name"].casefold()
            ]
            return jsonify({"query": query, "products": matches})

        @app.get("/cart")
        def cart():
            _simulate_database_operation(faults, "/cart")
            return jsonify(
                {
                    "items": [{"product_id": 1, "quantity": 1}],
                    "currency": "USD",
                }
            )
    else:
        @app.get("/videos")
        def videos():
            _simulate_database_operation(faults, "/videos")
            return jsonify({"videos": VIDEOS})

        @app.get("/videos/<int:video_id>")
        def video_metadata(video_id):
            _simulate_database_operation(faults, request.path)
            video = next((item for item in VIDEOS if item["id"] == video_id), None)
            if video is None:
                return jsonify({"error": "Video not found."}), 404
            return jsonify({"video": video})

        @app.get("/stream/<int:video_id>")
        def stream_simulation(video_id):
            _simulate_database_operation(faults, request.path)
            video = next((item for item in VIDEOS if item["id"] == video_id), None)
            if video is None:
                return jsonify({"error": "Video not found."}), 404
            return jsonify(
                {
                    "video_id": video_id,
                    "streaming": True,
                    "simulated_chunks": 4,
                }
            )

    @app.post("/__simulation__/faults")
    def start_fault():
        if request.remote_addr not in {"127.0.0.1", "::1"}:
            return jsonify({"error": "Simulation controls are loopback-only."}), 403
        payload = request.get_json(silent=False)
        if not isinstance(payload, dict) or set(payload).difference(
            {"scenario", "configuration"}
        ):
            return jsonify({"error": "Invalid simulation request."}), 400
        scenario = payload.get("scenario")
        configuration = payload.get("configuration", {})
        if not isinstance(configuration, dict):
            return jsonify({"error": "configuration must be an object."}), 400
        if scenario in {"api_latency", "database_delay", "http_errors", "worker_failure"}:
            endpoint = configuration.get("endpoint", "/health")
            service_paths = DEMO_APPLICATIONS[
                "APP-SDP-DEMO-ECOMMERCE"
                if service == "ecommerce"
                else "APP-SDP-DEMO-STREAMING"
            ]["paths"]
            if endpoint not in service_paths:
                return jsonify({"error": "Endpoint is not part of this demo service."}), 400
        try:
            faults.apply(scenario, configuration)
        except (RuntimeError, ValueError) as error:
            return jsonify({"error": str(error)}), 400
        return jsonify(
            {
                "status": "running",
                "scenario": scenario,
                "active_faults": faults.active_faults(),
            }
        ), 202

    @app.delete("/__simulation__/faults")
    def clear_faults():
        try:
            cleared = faults.clear()
        except RuntimeError as error:
            return jsonify({"error": str(error)}), 500
        return jsonify({"status": "cleared", "scenarios": cleared})

    @app.get("/__simulation__/faults")
    def get_faults():
        return jsonify({"active_faults": faults.active_faults()})

    return app


class DemoApplicationManager:
    def __init__(self, db_path=None, startup_timeout_seconds=10):
        self.db_path = db_path
        self.startup_timeout_seconds = min(
            max(float(startup_timeout_seconds), 1),
            30,
        )
        self._lock = threading.RLock()
        self._processes = {}
        self._started_by_manager = set()
        initialize_database(db_path)

    @staticmethod
    def _runtime_directory(application_id):
        path = DEMO_RUNTIME_ROOT / application_id.casefold()
        path.mkdir(parents=True, exist_ok=True)
        return path.resolve()

    def _application_record(self, application_id):
        configuration = DEMO_APPLICATIONS[application_id]
        runtime_directory = self._runtime_directory(application_id)
        expected = {
            "name": configuration["name"],
            "url": f"http://127.0.0.1:{configuration['port']}",
            "application_type": "CONTROLLED_LOCAL_APPLICATION",
            "owned_by_platform": True,
            "process_monitoring_permitted": True,
            "automatic_recovery_permitted": True,
            "process_name": Path(os.sys.executable).name,
            "process_executable_path": str(Path(os.sys.executable).resolve()),
            "process_working_directory": str(runtime_directory),
            "endpoint_path": "/health",
        }
        current = get_application(application_id, db_path=self.db_path)
        if current is None:
            return None
        for field, value in expected.items():
            if current.get(field) != value:
                raise RuntimeError(
                    f"Registered demo application {application_id} has an "
                    f"unexpected {field}; refusing to control it."
                )
        if not current["active"]:
            current = update_application(
                application_id,
                db_path=self.db_path,
                active=True,
            )
        return current

    @staticmethod
    def _health_check(url):
        with urlopen(f"{url}/health", timeout=1) as response:
            return response.status == 200

    def _ensure_recovery_policy(self, application_id):
        from app.recovery_policy import (
            RECOVERY_ACTION_RESTART,
            RECOVERY_ACTION_RETRY,
            configure_recovery_policy,
            get_recovery_policy,
        )

        if get_recovery_policy(application_id, db_path=self.db_path) is None:
            configure_recovery_policy(
                application_id,
                automatic_recovery_enabled=True,
                permitted_actions=(
                    RECOVERY_ACTION_RETRY,
                    RECOVERY_ACTION_RESTART,
                ),
                required_approval_level="high_risk",
                max_retry_attempts=1,
                cooldown_seconds=30,
                verification_timeout_seconds=3,
                db_path=self.db_path,
            )

    def ensure_application(self, application_id):
        if application_id not in DEMO_APPLICATIONS:
            raise ValueError("Only the registered SDP demo applications are supported.")
        with self._lock:
            application = self._application_record(application_id)
            if application is not None:
                process, error = find_owned_process(application)
                if process is not None:
                    if not self._health_check(application["url"]):
                        raise RuntimeError(
                            f"Demo service {application_id} process is running but unhealthy."
                        )
                    self._ensure_recovery_policy(application_id)
                    return application
                if error and any(
                    marker in error.casefold()
                    for marker in ("multiple processes", "access denied")
                ):
                    raise RuntimeError(error)

            configuration = DEMO_APPLICATIONS[application_id]
            runtime_directory = self._runtime_directory(application_id)
            command = [
                str(Path(os.sys.executable).resolve()),
                str(DEMO_SCRIPT),
                "--service",
                configuration["service"],
                "--port",
                str(configuration["port"]),
            ]
            log_path = runtime_directory / "service.log"
            log_file = log_path.open("a", encoding="utf-8")
            try:
                process_handle = subprocess.Popen(
                    command,
                    cwd=str(runtime_directory),
                    stdin=subprocess.DEVNULL,
                    stdout=log_file,
                    stderr=subprocess.STDOUT,
                    shell=False,
                    creationflags=(
                        getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
                        | getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    ),
                )
            except OSError:
                log_file.close()
                raise
            log_file.close()
            self._processes[application_id] = process_handle
            self._started_by_manager.add(application_id)

        service_url = f"http://127.0.0.1:{configuration['port']}"
        deadline = time.monotonic() + self.startup_timeout_seconds
        last_error = None
        healthy = False
        while time.monotonic() < deadline:
            if process_handle.poll() is not None:
                break
            try:
                if self._health_check(service_url):
                    healthy = True
                    break
            except (URLError, TimeoutError, OSError) as error:
                last_error = error
            time.sleep(0.1)

        if process_handle.poll() is not None or not healthy:
            process_handle.terminate()
            try:
                process_handle.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process_handle.kill()
                process_handle.wait(timeout=3)
            self._processes.pop(application_id, None)
            self._started_by_manager.discard(application_id)
            message = f"Demo service {application_id} failed to become healthy."
            if last_error:
                message += f" Last health-check error: {last_error}"
            raise RuntimeError(message)

        if application is None:
            try:
                application = register_application(
                    name=configuration["name"],
                    url=service_url,
                    application_type="CONTROLLED_LOCAL_APPLICATION",
                    monitoring_interval_seconds=2,
                    owned_by_platform=True,
                    process_monitoring_permitted=True,
                    automatic_recovery_permitted=True,
                    process_name=Path(os.sys.executable).name,
                    process_executable_path=str(Path(os.sys.executable).resolve()),
                    process_working_directory=str(runtime_directory),
                    endpoint_path="/health",
                    application_id=application_id,
                    db_path=self.db_path,
                )
            except (OSError, RuntimeError, sqlite3.Error, ValueError, KeyError):
                process_handle.terminate()
                try:
                    process_handle.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process_handle.kill()
                    process_handle.wait(timeout=3)
                self._processes.pop(application_id, None)
                self._started_by_manager.discard(application_id)
                raise
        else:
            application = update_application(
                application_id,
                db_path=self.db_path,
                active=True,
            )
        process, error = find_owned_process(application)
        if process is None or process.pid != process_handle.pid:
            process_handle.terminate()
            process_handle.wait(timeout=3)
            raise RuntimeError(
                f"Started demo service {application_id} did not match its "
                f"registered process identity: {error or 'PID mismatch'}"
            )
        self._ensure_recovery_policy(application_id)
        return application

    def stop_application(self, application_id):
        if application_id not in DEMO_APPLICATIONS:
            raise ValueError("Only the registered SDP demo applications are supported.")
        from app.process_control import stop_registered_application

        application = get_application(application_id, db_path=self.db_path)
        if application is None or not application["owned_by_platform"]:
            raise RuntimeError("The demo application is not registered as owned.")
        process, error = find_owned_process(application)
        if process is None:
            if error and "multiple processes" in error.casefold():
                raise RuntimeError(error)
            return False
        stopped = stop_registered_application(
            application,
            expected_pid=process.pid,
        )
        if stopped:
            with self._lock:
                self._processes.pop(application_id, None)
        return stopped

    def restart_application(self, application_id):
        if application_id not in DEMO_APPLICATIONS:
            raise ValueError("Only the registered SDP demo applications are supported.")
        from app.process_control import restart_registered_application

        application = get_application(application_id, db_path=self.db_path)
        if application is None or not application["owned_by_platform"]:
            raise RuntimeError("The demo application is not registered as owned.")
        restart_registered_application(application)
        deadline = time.monotonic() + self.startup_timeout_seconds
        while time.monotonic() < deadline:
            try:
                if self._health_check(application["url"]):
                    return True
            except (URLError, TimeoutError, OSError):
                pass
            time.sleep(0.1)
        raise RuntimeError(f"Demo service {application_id} did not recover after restart.")

    def shutdown(self):
        stopped = {}
        for application_id in tuple(self._started_by_manager):
            try:
                stopped[application_id] = self.stop_application(application_id)
            except (OSError, RuntimeError, ValueError) as error:
                LOGGER.exception(
                    "Could not safely stop demo service %s",
                    application_id,
                )
                stopped[application_id] = str(error)
        self._started_by_manager.clear()
        return stopped


_manager_lock = threading.Lock()
_managers = {}


def get_demo_application_manager(db_path=None):
    database_path = get_database_path(db_path).resolve()
    key = str(database_path)
    with _manager_lock:
        if key not in _managers:
            _managers[key] = DemoApplicationManager(db_path=database_path)
        return _managers[key]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", required=True, choices=("ecommerce", "streaming"))
    parser.add_argument("--port", required=True, type=int)
    arguments = parser.parse_args()
    expected_port = next(
        config["port"]
        for config in DEMO_APPLICATIONS.values()
        if config["service"] == arguments.service
    )
    if arguments.port != expected_port:
        raise SystemExit("Demo service port does not match the fixed local configuration.")
    create_demo_app(arguments.service).run(
        host="127.0.0.1",
        port=arguments.port,
        threaded=True,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
