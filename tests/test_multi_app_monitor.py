import json
import socket
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from unittest.mock import Mock, patch

from app.application_registry import register_application, update_application
from app.database import connect, initialize_database
from app.multi_app_monitor import (
    ApplicationMonitor,
    MultiApplicationMonitor,
)


class FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class FakeProcess:
    pid = 4321
    info = {
        "pid": pid,
        "name": "worker.exe",
        "exe": r"C:\owned\worker.exe",
        "cwd": r"C:\owned",
    }

    def memory_info(self):
        return SimpleNamespace(rss=50 * 1024 * 1024)

    def memory_percent(self):
        return 2.5

    def cpu_percent(self, interval=None):
        return 12.5

    def status(self):
        return "running"


class FakeProcessProvider:
    def __init__(self, processes):
        self.processes = processes
        self.process_iter_calls = 0

    def process_iter(self, attrs):
        self.process_iter_calls += 1
        return iter(self.processes)


class MultiApplicationMonitorTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "monitor.sqlite3"
        initialize_database(self.database)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def register(self, name, url, **kwargs):
        return register_application(
            name=name,
            url=url,
            application_type=kwargs.pop("application_type", "REST_API"),
            db_path=self.database,
            **kwargs,
        )

    def read_rows(self):
        with closing(connect(self.database)) as connection:
            return [
                dict(row)
                for row in connection.execute(
                    """
                    SELECT application_id, timestamp, data_json
                    FROM application_telemetry
                    ORDER BY application_id
                    """
                ).fetchall()
            ]

    @staticmethod
    def wait_for(predicate, timeout=3.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return predicate()

    def test_multiple_enabled_apps_are_monitored_and_disabled_apps_skipped(self):
        first = self.register(
            "First API",
            "http://127.0.0.1:8001/health",
            monitoring_interval_seconds=10,
        )
        second = self.register(
            "Second API",
            "https://api.example.test/health",
            monitoring_interval_seconds=10,
        )
        disabled = self.register(
            "Disabled API",
            "http://127.0.0.1:8003/health",
            monitoring_enabled=False,
        )
        request = Mock(return_value=FakeResponse(200))
        monitor = MultiApplicationMonitor(
            db_path=self.database,
            request_function=request,
            supervisor_interval=0.1,
        )

        monitor.start()
        self.assertTrue(self.wait_for(lambda: len(self.read_rows()) >= 2))
        monitor.refresh()
        self.assertEqual(set(monitor.worker_ids), {
            first["application_id"],
            second["application_id"],
        })
        self.assertNotIn(disabled["application_id"], monitor.worker_ids)

        rows = self.read_rows()
        self.assertEqual(
            {row["application_id"] for row in rows},
            {first["application_id"], second["application_id"]},
        )
        monitor.stop()

    def test_http_success_and_failure_metrics_are_stored(self):
        application = self.register(
            "Status API",
            "https://api.example.test/health",
        )
        statuses = iter((200, 503, 404))
        monitor = ApplicationMonitor(
            db_path=self.database,
            request_function=lambda request, timeout: FakeResponse(next(statuses)),
        )

        success = monitor.monitor_once(application["application_id"])
        server_error = monitor.monitor_once(application["application_id"])
        not_found = monitor.monitor_once(application["application_id"])

        self.assertTrue(success["availability"])
        self.assertTrue(success["request_success"])
        self.assertEqual(success["http_status_code"], 200)
        self.assertFalse(server_error["request_success"])
        self.assertEqual(server_error["failure_type"], "http_error")
        self.assertEqual(server_error["consecutive_failure_count"], 1)
        self.assertEqual(not_found["http_status_code"], 404)
        self.assertEqual(not_found["consecutive_failure_count"], 2)
        self.assertEqual(not_found["last_successful_response_time_ms"],
                         success["response_time_ms"])

        stored = [json.loads(row["data_json"]) for row in self.read_rows()]
        self.assertEqual(len(stored), 3)
        self.assertTrue(all(item["application_id"] == application["application_id"]
                            for item in stored))

    def test_connection_failure_and_timeout_are_distinguished(self):
        application = self.register(
            "Unreachable API",
            "http://127.0.0.1:8999/health",
        )
        errors = iter(
            (
                URLError(ConnectionRefusedError("refused")),
                URLError(socket.timeout("timed out")),
            )
        )
        timeouts = []

        def fail_request(request, timeout):
            timeouts.append(timeout)
            raise next(errors)

        monitor = ApplicationMonitor(
            db_path=self.database,
            request_timeout=999,
            request_function=fail_request,
        )
        connection_failure = monitor.monitor_once(application["application_id"])
        timeout = monitor.monitor_once(application["application_id"])

        self.assertFalse(connection_failure["availability"])
        self.assertTrue(connection_failure["connection_error"])
        self.assertEqual(connection_failure["failure_type"], "connection_error")
        self.assertTrue(timeout["timeout_error"])
        self.assertEqual(timeout["failure_type"], "timeout")
        self.assertEqual(timeout["consecutive_failure_count"], 2)
        self.assertEqual(timeouts, [15.0, 15.0])

    def test_http_error_response_is_available_but_request_fails(self):
        application = self.register(
            "Failing API",
            "https://api.example.test/health",
        )

        def http_error(request, timeout):
            raise HTTPError(request.full_url, 500, "Internal Server Error", {}, None)

        monitor = ApplicationMonitor(
            db_path=self.database,
            request_function=http_error,
        )
        reading = monitor.monitor_once(application["application_id"])

        self.assertTrue(reading["availability"])
        self.assertFalse(reading["request_success"])
        self.assertEqual(reading["http_status_code"], 500)
        self.assertFalse(reading["connection_error"])

    def test_owned_local_app_collects_process_metrics_after_identity_check(self):
        application = self.register(
            "Owned Worker",
            "http://127.0.0.1:8100/health",
            application_type="CONTROLLED_LOCAL_APPLICATION",
            owned_by_platform=True,
            process_monitoring_permitted=True,
            process_name="worker.exe",
            process_executable_path=r"C:\owned\worker.exe",
            process_working_directory=r"C:\owned",
        )
        process_provider = FakeProcessProvider([FakeProcess()])
        monitor = ApplicationMonitor(
            db_path=self.database,
            request_function=lambda request, timeout: FakeResponse(200),
            process_provider=process_provider,
        )

        reading = monitor.monitor_once(application["application_id"])

        self.assertEqual(reading["process_id"], 4321)
        self.assertEqual(reading["process_status"], "running")
        self.assertAlmostEqual(reading["process_memory_mb"], 50)
        self.assertEqual(reading["cpu_usage"], 12.5)
        self.assertEqual(reading["memory_usage"], 2.5)
        self.assertEqual(process_provider.process_iter_calls, 1)

    def test_external_website_never_enumerates_processes(self):
        application = self.register(
            "External Website",
            "https://example.test/",
            application_type="HTTPS_WEBSITE",
        )
        process_provider = FakeProcessProvider([FakeProcess()])
        monitor = ApplicationMonitor(
            db_path=self.database,
            request_function=lambda request, timeout: FakeResponse(200),
            process_provider=process_provider,
        )

        reading = monitor.monitor_once(application["application_id"])

        self.assertIsNone(reading["process_id"])
        self.assertIsNone(reading["cpu_usage"])
        self.assertEqual(process_provider.process_iter_calls, 0)

    def test_process_metrics_are_withheld_if_identity_is_not_unique(self):
        application = self.register(
            "Owned Worker",
            "http://127.0.0.1:8100/health",
            application_type="CONTROLLED_LOCAL_APPLICATION",
            owned_by_platform=True,
            process_monitoring_permitted=True,
            process_name="worker.exe",
            process_working_directory=r"C:\owned",
        )
        provider = FakeProcessProvider([FakeProcess(), FakeProcess()])
        monitor = ApplicationMonitor(
            db_path=self.database,
            request_function=lambda request, timeout: FakeResponse(200),
            process_provider=provider,
        )

        reading = monitor.monitor_once(application["application_id"])

        self.assertIsNone(reading["process_id"])
        self.assertIn("multiple processes", reading["error_details"])

    def test_unsupported_scheme_is_not_requested_and_recorded_as_failure(self):
        application = self.register(
            "Unsupported Endpoint",
            "ftp://example.test/file",
            application_type="CONTROLLED_LOCAL_APPLICATION",
        )
        request = Mock()
        monitor = ApplicationMonitor(
            db_path=self.database,
            request_function=request,
        )

        reading = monitor.monitor_once(application["application_id"])

        request.assert_not_called()
        self.assertFalse(reading["availability"])
        self.assertEqual(reading["failure_type"], "request_error")
        self.assertIn("HTTP or HTTPS", reading["error_details"])

    def test_one_worker_failure_does_not_stop_other_application(self):
        failing = self.register(
            "Failing endpoint",
            "http://127.0.0.1:8999/health",
            monitoring_interval_seconds=10,
        )
        healthy = self.register(
            "Healthy endpoint",
            "http://127.0.0.1:8101/health",
            monitoring_interval_seconds=10,
        )

        def request_for_app(request, timeout):
            if "8999" in request.full_url:
                raise URLError(ConnectionError("unavailable"))
            return FakeResponse(200)

        monitor = MultiApplicationMonitor(
            db_path=self.database,
            request_function=request_for_app,
            supervisor_interval=0.1,
        )
        monitor.start()

        def both_readings_saved():
            return {
                row["application_id"] for row in self.read_rows()
            } == {failing["application_id"], healthy["application_id"]}

        self.assertTrue(self.wait_for(both_readings_saved))
        self.assertEqual(set(monitor.worker_ids), {
            failing["application_id"],
            healthy["application_id"],
        })
        self.assertTrue(all(thread.is_alive() for thread, _ in monitor._workers.values()))
        readings = {
            item["application_id"]: item
            for item in (
                json.loads(row["data_json"]) for row in self.read_rows()
            )
        }
        self.assertFalse(readings[failing["application_id"]]["request_success"])
        self.assertTrue(readings[healthy["application_id"]]["request_success"])
        monitor.stop()

    def test_anomaly_detection_failure_does_not_stop_monitor_workers(self):
        first = self.register(
            "Detector failure API",
            "http://127.0.0.1:8111/health",
            monitoring_interval_seconds=10,
        )
        second = self.register(
            "Detector healthy API",
            "http://127.0.0.1:8112/health",
            monitoring_interval_seconds=10,
        )
        analyzed = set()

        def analyze(application_id, db_path=None):
            analyzed.add(application_id)
            if application_id == first["application_id"]:
                raise RuntimeError("controlled detector failure")
            return {"status": "insufficient_data"}

        monitor = MultiApplicationMonitor(
            db_path=self.database,
            request_function=lambda request, timeout: FakeResponse(200),
            supervisor_interval=0.1,
        )
        with patch("ml.detect_anomalies.analyze_application", side_effect=analyze):
            monitor.start()
            self.assertTrue(
                self.wait_for(
                    lambda: analyzed
                    == {first["application_id"], second["application_id"]}
                )
            )
            self.assertEqual(
                {row["application_id"] for row in self.read_rows()},
                {first["application_id"], second["application_id"]},
            )
            self.assertTrue(
                all(
                    thread.is_alive()
                    for thread, _ in monitor._workers.values()
                )
            )
            monitor.stop()

    def test_monitor_start_is_idempotent_and_does_not_duplicate_workers(self):
        application = self.register(
            "Single API",
            "http://127.0.0.1:8102/health",
            monitoring_interval_seconds=10,
        )
        monitor = MultiApplicationMonitor(
            db_path=self.database,
            request_function=lambda request, timeout: FakeResponse(200),
            supervisor_interval=0.1,
        )

        monitor.start()
        first_workers = dict(monitor._workers)
        monitor.start()
        monitor.refresh()

        self.assertEqual(monitor.worker_ids, (application["application_id"],))
        self.assertIs(
            monitor._workers[application["application_id"]][0],
            first_workers[application["application_id"]][0],
        )
        monitor.stop()

    def test_monitoring_disabled_after_start_stops_worker(self):
        application = self.register(
            "Toggle API",
            "http://127.0.0.1:8103/health",
            monitoring_interval_seconds=10,
        )
        monitor = MultiApplicationMonitor(
            db_path=self.database,
            request_function=lambda request, timeout: FakeResponse(200),
            supervisor_interval=0.1,
        )
        monitor.start()
        self.assertTrue(self.wait_for(lambda: bool(self.read_rows())))

        update_application(
            application["application_id"],
            db_path=self.database,
            monitoring_enabled=False,
        )
        self.assertTrue(
            self.wait_for(
                lambda: not monitor._workers[
                    application["application_id"]
                ][0].is_alive()
            )
        )
        monitor.stop()


if __name__ == "__main__":
    unittest.main()
