import logging
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

from app.application_registry import get_application
from app.multi_app_monitor import find_owned_process
from testing_website.demo_app import DEMO_APPLICATIONS
from testing_website.simulation_store import (
    finish_simulation_event,
    start_simulation_event,
)


LOGGER = logging.getLogger(__name__)
MAX_WORKLOAD_DURATION_SECONDS = 60
MAX_REQUEST_RATE_PER_SECOND = 20
MAX_CONCURRENT_REQUESTS = 8
REQUEST_TIMEOUT_SECONDS = 3
WORKLOAD_PATTERNS = {
    "normal": {"rate": 2, "concurrency": 1},
    "high_volume": {"rate": 20, "concurrency": 4},
    "concurrent": {"rate": 10, "concurrency": 8},
    "repeated": {"rate": 5, "concurrency": 2},
    "endpoint_mix": {"rate": 5, "concurrency": 3},
}
def _validate_target(application_id, db_path):
    if application_id not in DEMO_APPLICATIONS:
        raise ValueError("Workloads are restricted to registered SDP demo applications.")
    application = get_application(application_id, db_path=db_path)
    if (
        application is None
        or not application["active"]
        or not application["owned_by_platform"]
        or not application["process_monitoring_permitted"]
        or not application["automatic_recovery_permitted"]
    ):
        raise ValueError("Workloads require an active, controlled, owned demo application.")
    expected = DEMO_APPLICATIONS[application_id]
    parsed = urlparse(application["url"])
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port != expected["port"]
    ):
        raise ValueError("Workload targets must be the fixed loopback demo endpoint.")
    process, error = find_owned_process(application)
    if process is None:
        raise RuntimeError(error or "The registered demo process could not be verified.")
    return application, expected


def _validate_endpoint(endpoint, allowed_paths):
    if not isinstance(endpoint, str) or not endpoint.startswith("/"):
        raise ValueError("Each endpoint must be a local absolute path.")
    parsed = urlparse(endpoint)
    if parsed.scheme or parsed.netloc or parsed.fragment:
        raise ValueError("Endpoint URLs must not contain a host or fragment.")
    if parsed.path not in allowed_paths:
        raise ValueError(f"Endpoint is not registered for this demo: {parsed.path}")
    if parsed.path != "/search" and parsed.query:
        raise ValueError("Query parameters are supported only by the search endpoint.")
    if parsed.path == "/search" and len(parsed.query) > 100:
        raise ValueError("Search query parameters exceed the safe length limit.")
    return endpoint


def _integer(value, name, minimum, maximum):
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer.")
    try:
        number = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer.") from error
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{name} must be an integer.")
    if not minimum <= number <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return number


class WorkloadTask:
    def __init__(
        self,
        application_id,
        application,
        simulation_id,
        db_path,
        endpoints,
        duration_seconds,
        request_rate,
        concurrency,
        pattern,
    ):
        self.task_id = uuid.uuid4().hex
        self.application_id = application_id
        self.application = application
        self.simulation_id = simulation_id
        self.db_path = db_path
        self.endpoints = tuple(endpoints)
        self.duration_seconds = duration_seconds
        self.request_rate = request_rate
        self.concurrency = concurrency
        self.pattern = pattern
        self._stop_event = threading.Event()
        self._lock = threading.Lock()
        self._state = "Running"
        self._summary = None
        self._thread = threading.Thread(
            target=self._run,
            name=f"sdp-workload-{self.task_id[:8]}",
            daemon=True,
        )

    @property
    def state(self):
        with self._lock:
            return self._state

    def start(self):
        self._thread.start()
        return self

    def stop(self, timeout=5):
        self._stop_event.set()
        self._thread.join(timeout=max(0.0, timeout))
        if self._thread.is_alive():
            raise RuntimeError("Workload did not stop within the requested timeout.")
        return self.summary

    @property
    def summary(self):
        with self._lock:
            return dict(self._summary) if self._summary else None

    def _request(self, endpoint):
        target_url = urljoin(
            self.application["url"].rstrip("/") + "/",
            endpoint.lstrip("/"),
        )
        started = time.perf_counter()
        try:
            request = Request(
                target_url,
                headers={"User-Agent": "SDP-Controlled-Workload/1.0"},
                method="GET",
            )
            with urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
                status = int(response.status)
            elapsed_ms = (time.perf_counter() - started) * 1000
            return status, elapsed_ms, None
        except HTTPError as error:
            elapsed_ms = (time.perf_counter() - started) * 1000
            error.close()
            return error.code, elapsed_ms, str(error)
        except (URLError, TimeoutError, OSError) as error:
            elapsed_ms = (time.perf_counter() - started) * 1000
            return None, elapsed_ms, str(error)

    def _record_result(self, result, totals):
        status, response_ms, error = result
        totals["total_requests"] += 1
        totals["max_response_time_ms"] = max(
            totals["max_response_time_ms"],
            response_ms,
        )
        totals["response_time_sum_ms"] += response_ms
        if status is not None and 200 <= status < 400:
            totals["successful_requests"] += 1
        else:
            totals["failed_requests"] += 1
            if error and not totals["last_error"]:
                totals["last_error"] = error

    def _run(self):
        started_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        started_clock = time.monotonic()
        deadline = started_clock + self.duration_seconds
        interval = 1 / self.request_rate
        next_request_at = started_clock
        totals = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "response_time_sum_ms": 0.0,
            "max_response_time_ms": 0.0,
            "last_error": "",
        }
        pending = set()
        index = 0
        executor = ThreadPoolExecutor(
            max_workers=self.concurrency,
            thread_name_prefix="sdp-workload-request",
        )
        try:
            while not self._stop_event.is_set() and time.monotonic() < deadline:
                completed = {future for future in pending if future.done()}
                for future in completed:
                    pending.remove(future)
                    try:
                        self._record_result(future.result(), totals)
                    except (OSError, RuntimeError, ValueError) as error:
                        self._record_result((None, 0.0, str(error)), totals)

                now = time.monotonic()
                if now >= next_request_at and len(pending) < self.concurrency:
                    endpoint = self.endpoints[index % len(self.endpoints)]
                    pending.add(executor.submit(self._request, endpoint))
                    index += 1
                    next_request_at = now + interval
                    continue
                wait_seconds = min(
                    0.05,
                    max(0.0, next_request_at - now),
                    max(0.0, deadline - now),
                )
                if pending and len(pending) >= self.concurrency:
                    wait(pending, timeout=max(wait_seconds, 0.01), return_when=FIRST_COMPLETED)
                else:
                    self._stop_event.wait(wait_seconds)

            for future in pending:
                try:
                    self._record_result(future.result(), totals)
                except (OSError, RuntimeError, ValueError) as error:
                    self._record_result((None, 0.0, str(error)), totals)
        finally:
            executor.shutdown(wait=True, cancel_futures=True)

        ended_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        elapsed_seconds = max(time.monotonic() - started_clock, 0.001)
        total_requests = totals["total_requests"]
        summary = {
            "simulation_id": self.simulation_id,
            "application_id": self.application_id,
            "pattern": self.pattern,
            "started_at": started_at,
            "ended_at": ended_at,
            "duration_seconds": round(elapsed_seconds, 3),
            "configured_duration_seconds": self.duration_seconds,
            "request_rate_per_second": self.request_rate,
            "concurrency": self.concurrency,
            "endpoints": list(self.endpoints),
            "total_requests": total_requests,
            "successful_requests": totals["successful_requests"],
            "failed_requests": totals["failed_requests"],
            "average_response_time_ms": (
                round(totals["response_time_sum_ms"] / total_requests, 3)
                if total_requests
                else None
            ),
            "maximum_response_time_ms": (
                round(totals["max_response_time_ms"], 3)
                if total_requests
                else None
            ),
            "throughput_requests_per_second": round(
                total_requests / elapsed_seconds,
                3,
            ),
            "error_details": totals["last_error"] or None,
        }
        status = "Stopped" if self._stop_event.is_set() else "Completed"
        try:
            finish_simulation_event(
                self.simulation_id,
                status=status,
                updates={"workload_details": summary},
                db_path=self.db_path,
            )
        except (OSError, RuntimeError, ValueError):
            LOGGER.exception(
                "Could not finalize workload simulation %s",
                self.simulation_id,
            )
        with self._lock:
            self._summary = summary
            self._state = status


class WorkloadGenerator:
    def __init__(self, db_path=None):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._tasks = {}

    def start(
        self,
        application_id,
        *,
        pattern="normal",
        duration_seconds=10,
        request_rate_per_second=None,
        concurrency=None,
        endpoints=None,
        confirm=False,
    ):
        if confirm is not True:
            raise ValueError("Explicit confirmation is required to start a workload.")
        if pattern not in WORKLOAD_PATTERNS:
            raise ValueError(
                "pattern must be normal, high_volume, concurrent, repeated, or endpoint_mix."
            )
        application, demo = _validate_target(application_id, self.db_path)
        defaults = WORKLOAD_PATTERNS[pattern]
        duration = _integer(
            duration_seconds,
            "duration_seconds",
            1,
            MAX_WORKLOAD_DURATION_SECONDS,
        )
        rate = _integer(
            defaults["rate"] if request_rate_per_second is None else request_rate_per_second,
            "request_rate_per_second",
            1,
            MAX_REQUEST_RATE_PER_SECOND,
        )
        workers = _integer(
            defaults["concurrency"] if concurrency is None else concurrency,
            "concurrency",
            1,
            MAX_CONCURRENT_REQUESTS,
        )
        selected_endpoints = endpoints or ["/health"]
        if isinstance(selected_endpoints, str):
            selected_endpoints = [selected_endpoints]
        if not isinstance(selected_endpoints, (list, tuple)) or not selected_endpoints:
            raise ValueError("endpoints must be a non-empty list of local paths.")
        selected_endpoints = [
            _validate_endpoint(endpoint, demo["paths"])
            for endpoint in selected_endpoints
        ]
        if pattern == "endpoint_mix" and endpoints is None:
            selected_endpoints = list(demo["paths"][:4])
        elif pattern == "repeated" and endpoints is None:
            selected_endpoints = ["/health"]
        if pattern == "high_volume" and duration > 30:
            raise ValueError("High-volume workloads are limited to 30 seconds.")

        with self._lock:
            if any(task.state == "Running" and task.application_id == application_id
                   for task in self._tasks.values()):
                raise RuntimeError("A workload is already active for this demo application.")
            event_id = start_simulation_event(
                application_id,
                f"workload:{pattern}",
                {
                    "configuration": {
                        "pattern": pattern,
                        "duration_seconds": duration,
                        "request_rate_per_second": rate,
                        "concurrency": workers,
                        "endpoints": selected_endpoints,
                    },
                    "affected_endpoint": ", ".join(selected_endpoints),
                },
                db_path=self.db_path,
            )
            task = WorkloadTask(
                application_id,
                application,
                event_id,
                self.db_path,
                selected_endpoints,
                duration,
                rate,
                workers,
                pattern,
            )
            self._tasks[task.task_id] = task
            try:
                task.start()
            except RuntimeError:
                finish_simulation_event(
                    event_id,
                    status="Failed",
                    updates={
                        "error_details": "Workload worker could not be started.",
                    },
                    db_path=self.db_path,
                )
                del self._tasks[task.task_id]
                raise
        return task.task_id

    def stop(self, task_id, timeout=5):
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            raise KeyError(f"Workload not found: {task_id}")
        return task.stop(timeout=timeout)

    def get(self, task_id):
        with self._lock:
            task = self._tasks.get(task_id)
        if task is None:
            return None
        return {
            "task_id": task.task_id,
            "simulation_id": task.simulation_id,
            "application_id": task.application_id,
            "status": task.state,
            "summary": task.summary,
        }

    def stop_all(self, timeout=5):
        with self._lock:
            task_ids = list(self._tasks)
        results = {}
        for task_id in task_ids:
            task = self._tasks[task_id]
            if task.state == "Running":
                results[task_id] = task.stop(timeout=timeout)
        return results

