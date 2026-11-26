import tempfile
import threading
import time
import unittest
from contextlib import ExitStack, closing
from unittest.mock import Mock, patch

from werkzeug.serving import make_server

from app.application_registry import register_application
from app.database import connect, initialize_database
from app.incident_management import process_application_anomaly
from app.multi_app_monitor import monitor_application_once
from app.recovery_framework import process_incident
from app.recovery_policy import (
    RECOVERY_ACTION_RETRY,
    configure_recovery_policy,
)
from ml.application_root_cause import generate_application_rca
from ml.detect_anomalies import analyze_application
from testing_website.demo_app import DEMO_APPLICATIONS, FaultState, create_demo_app
from testing_website.failure_simulator import FailureSimulator
from testing_website.simulation_store import (
    finish_simulation_event,
    get_simulation_event,
    start_simulation_event,
)
from testing_website.test_scenarios import run_scenario
from testing_website.workload_generator import (
    WorkloadGenerator,
    WorkloadTask,
)


class ControlledSimulationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.db_path = f"{self.temporary_directory.name}\\simulation.sqlite3"
        initialize_database(self.db_path)

    def tearDown(self):
        self.temporary_directory.cleanup()

    def _register_external_application(self, application_id="APP-TEST-EXTERNAL"):
        return register_application(
            name="External monitor-only test application",
            url="http://127.0.0.1:5999",
            application_type="REST_API",
            application_id=application_id,
            db_path=self.db_path,
        )

    def test_demo_routes_and_fault_effects_are_controlled(self):
        app = create_demo_app("ecommerce")
        state = app.config["SIMULATION_STATE"]
        client = app.test_client()

        self.assertEqual(client.get("/health").status_code, 200)
        self.assertEqual(client.get("/products").status_code, 200)
        self.assertEqual(client.get("/products/999").status_code, 404)

        state.apply(
            "http_errors",
            {"duration_seconds": 5, "endpoint": "/health"},
        )
        response = client.get("/health")
        self.assertEqual(response.status_code, 500)
        self.assertTrue(response.get_json()["simulated"])
        state.clear()
        self.assertEqual(client.get("/health").status_code, 200)

    def test_fault_limits_are_enforced_and_memory_is_released(self):
        state = FaultState()
        with self.assertRaises(ValueError):
            state.apply(
                "cpu_load",
                {"duration_seconds": 5, "cpu_percent": 51},
            )
        with self.assertRaises(ValueError):
            state.apply(
                "memory_pressure",
                {"duration_seconds": 5, "memory_mb": 65},
            )
        self.assertEqual(state.active_faults(), {})

        state.apply(
            "cpu_load",
            {"duration_seconds": 5, "cpu_percent": 10},
        )
        state.clear()
        self.assertEqual(state._workers, {})

        state.apply(
            "memory_pressure",
            {"duration_seconds": 5, "memory_mb": 1},
        )
        state.clear()
        self.assertEqual(state.active_faults(), {})
        self.assertEqual(state._workers, {})

    def test_latency_fault_is_removed_by_cleanup(self):
        app = create_demo_app("ecommerce")
        state = app.config["SIMULATION_STATE"]
        client = app.test_client()
        state.apply(
            "api_latency",
            {
                "duration_seconds": 5,
                "delay_ms": 100,
                "endpoint": "/health",
            },
        )

        started = time.perf_counter()
        self.assertEqual(client.get("/health").status_code, 200)
        self.assertGreaterEqual(time.perf_counter() - started, 0.02)
        state.clear()
        started = time.perf_counter()
        self.assertEqual(client.get("/health").status_code, 200)
        self.assertLess(time.perf_counter() - started, 0.05)

    def test_database_delay_is_applied_at_demo_data_access(self):
        app = create_demo_app("ecommerce")
        state = app.config["SIMULATION_STATE"]
        client = app.test_client()
        state.apply(
            "database_delay",
            {
                "duration_seconds": 5,
                "delay_ms": 100,
                "endpoint": "/products",
            },
        )
        started = time.perf_counter()
        self.assertEqual(client.get("/products").status_code, 200)
        self.assertGreaterEqual(time.perf_counter() - started, 0.08)
        started = time.perf_counter()
        self.assertEqual(client.get("/health").status_code, 200)
        self.assertLess(time.perf_counter() - started, 0.05)
        state.clear()

    def test_workloads_are_restricted_to_owned_demo_ids(self):
        self._register_external_application()
        with self.assertRaises(ValueError):
            WorkloadGenerator(self.db_path).start(
                "APP-TEST-EXTERNAL",
                confirm=True,
            )

        application_id = "APP-SDP-DEMO-ECOMMERCE"
        application = register_application(
            name="Unowned spoofed demo identity",
            url="http://127.0.0.1:5101",
            application_type="REST_API",
            application_id=application_id,
            db_path=self.db_path,
        )
        with self.assertRaises(ValueError):
            WorkloadGenerator(self.db_path).start(
                application_id,
                confirm=True,
            )
        manager = Mock()
        manager.ensure_application.return_value = application
        with self.assertRaises(ValueError):
            FailureSimulator(
                self.db_path,
                application_manager=manager,
            ).start_simulation(
                application_id,
                "api_latency",
                {"duration_seconds": 1, "delay_ms": 10},
                confirm=True,
            )

    def test_fault_simulator_requires_confirmation_and_supports_emergency_stop(self):
        application_id = "APP-SDP-DEMO-ECOMMERCE"
        self._register_external_application(application_id)
        application = {
            "application_id": application_id,
            "url": "http://127.0.0.1:5101",
        }
        manager = Mock()
        manager.ensure_application.return_value = application
        simulator = FailureSimulator(
            db_path=self.db_path,
            application_manager=manager,
        )
        with self.assertRaises(ValueError):
            simulator.start_simulation(
                application_id,
                "api_latency",
                {"duration_seconds": 2, "delay_ms": 50},
            )
        with ExitStack() as stack:
            stack.enter_context(patch(
                "testing_website.failure_simulator._validate_target",
                return_value=(application, DEMO_APPLICATIONS[application_id]),
            ))
            control = stack.enter_context(
                patch("testing_website.failure_simulator._control_request")
            )
            simulation_id = simulator.start_simulation(
                application_id,
                "api_latency",
                {"duration_seconds": 2, "delay_ms": 50},
                confirm=True,
            )
            self.assertEqual(len(simulator.active_simulations()), 1)
            stopped = simulator.emergency_stop()
        self.assertIn(simulation_id, stopped)
        self.assertEqual(stopped[simulation_id]["status"], "Stopped")
        self.assertEqual([call.args[1] for call in control.call_args_list], ["POST", "DELETE"])

    def test_fault_simulator_stops_at_configured_duration(self):
        application_id = "APP-SDP-DEMO-ECOMMERCE"
        self._register_external_application(application_id)
        application = {
            "application_id": application_id,
            "url": "http://127.0.0.1:5101",
        }
        manager = Mock()
        manager.ensure_application.return_value = application
        simulator = FailureSimulator(
            db_path=self.db_path,
            application_manager=manager,
        )
        with ExitStack() as stack:
            stack.enter_context(patch(
                "testing_website.failure_simulator._validate_target",
                return_value=(application, DEMO_APPLICATIONS[application_id]),
            ))
            stack.enter_context(
                patch("testing_website.failure_simulator._control_request")
            )
            simulation_id = simulator.start_simulation(
                application_id,
                "api_latency",
                {"duration_seconds": 1, "delay_ms": 50},
                confirm=True,
            )
            deadline = time.monotonic() + 3
            while simulator.active_simulations() and time.monotonic() < deadline:
                time.sleep(0.02)
        event = get_simulation_event(simulation_id, db_path=self.db_path)
        self.assertEqual(event["status"], "Completed")
        self.assertEqual(event["details"]["stopped_by"], "duration limit")

    def test_workload_records_bounded_request_metrics(self):
        self._register_external_application("APP-TEST-WORKLOAD")
        app = create_demo_app("ecommerce")
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            application = {
                "application_id": "APP-TEST-WORKLOAD",
                "url": f"http://127.0.0.1:{server.server_port}",
            }
            simulation_id = start_simulation_event(
                "APP-TEST-WORKLOAD",
                "workload:test",
                {"configuration": {"duration_seconds": 1}},
                db_path=self.db_path,
            )
            task = WorkloadTask(
                "APP-TEST-WORKLOAD",
                application,
                simulation_id,
                self.db_path,
                ["/health"],
                1,
                4,
                1,
                "test",
            ).start()
            summary = task.stop(timeout=4)
            self.assertGreater(summary["total_requests"], 0)
            self.assertEqual(
                summary["successful_requests"] + summary["failed_requests"],
                summary["total_requests"],
            )
            self.assertGreater(summary["throughput_requests_per_second"], 0)
            saved = get_simulation_event(simulation_id, db_path=self.db_path)
            self.assertEqual(
                saved["details"]["workload_details"]["total_requests"],
                summary["total_requests"],
            )
        finally:
            server.shutdown()
            thread.join(timeout=2)

    def test_simulation_telemetry_is_separately_tagged(self):
        application = self._register_external_application("APP-TEST-TELEMETRY")

        class FakeResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                del _args
                return False

        def fake_request(*args, **kwargs):
            del args, kwargs
            return FakeResponse()

        reading = monitor_application_once(
            application["application_id"],
            db_path=self.db_path,
            request_function=fake_request,
            is_simulated=True,
            simulation_id=71,
            telemetry_source="controlled_simulation",
        )
        self.assertTrue(reading["request_success"])
        with closing(connect(self.db_path)) as connection:
            rows = connection.execute(
                """
                SELECT source, is_simulated, data_json
                FROM application_telemetry
                WHERE application_id = ?
                """,
                (application["application_id"],),
            ).fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source"], "controlled_simulation")
        self.assertEqual(rows[0]["is_simulated"], 1)
        self.assertIn('"simulation_id":71', rows[0]["data_json"])

    def test_scenario_runs_pipeline_and_persists_observed_stages(self):
        application = self._register_external_application(
            "APP-SDP-DEMO-ECOMMERCE"
        )
        simulation_ids = []

        def fake_monitor(_application_id, **kwargs):
            del _application_id
            simulation_id = kwargs.get("simulation_id")
            if simulation_id is not None:
                simulation_ids.append(simulation_id)
            return {
                "application_id": application["application_id"],
                "request_success": True,
                "http_status_code": 200,
                "availability": True,
            }

        def fake_detection(*_args, **_kwargs):
            del _args, _kwargs
            return {
                "status": "analyzed",
                "results": [
                    {
                        "timestamp": "2025-01-01T00:00:00+00:00",
                        "prediction": "Anomaly",
                        "is_simulated": True,
                        "simulation_id": simulation_ids[0],
                    }
                ],
            }

        with ExitStack() as stack:
            get_manager = stack.enter_context(patch(
                "testing_website.test_scenarios.get_demo_application_manager"
            ))
            stack.enter_context(patch(
                "testing_website.test_scenarios.monitor_application_once",
                side_effect=fake_monitor,
            ))
            stack.enter_context(patch(
                "testing_website.test_scenarios.analyze_application",
                side_effect=fake_detection,
            ))
            generate_rca = stack.enter_context(patch(
                "testing_website.test_scenarios.generate_application_rca",
                return_value={"report_id": 45, "root_cause": "test evidence"},
            ))
            create_incident = stack.enter_context(patch(
                "testing_website.test_scenarios.process_application_anomaly",
                return_value="INC-TEST-1",
            ))
            recover = stack.enter_context(patch(
                "testing_website.test_scenarios.process_incident",
                return_value={"decision": "NO_ACTION", "reason": "test result"},
            ))
            get_manager.return_value.ensure_application.return_value = application
            summary = run_scenario(
                "normal_operation",
                application["application_id"],
                db_path=self.db_path,
                confirm=True,
            )

        generate_rca.assert_called_once()
        create_incident.assert_called_once()
        recover.assert_called_once_with("INC-TEST-1", db_path=self.db_path)
        self.assertEqual(summary["incidents_created"], ["INC-TEST-1"])
        self.assertTrue(summary["final_application_health"])
        self.assertEqual(summary["stage_results"]["rca_reports"], 1)
        saved = get_simulation_event(
            summary["simulation_id"],
            db_path=self.db_path,
        )
        self.assertEqual(saved["status"], "Completed")
        self.assertEqual(
            saved["details"]["scenario_summary"]["incidents_created"],
            ["INC-TEST-1"],
        )

    def test_local_fault_flows_through_detection_rca_incident_and_recovery(self):
        app = create_demo_app("ecommerce")
        faults = app.config["SIMULATION_STATE"]
        server = make_server("127.0.0.1", 0, app)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        application_id = "APP-SDP-DEMO-ECOMMERCE"
        register_application(
            name="Controlled local e-commerce integration test",
            url=f"http://127.0.0.1:{server.server_port}",
            application_type="CONTROLLED_LOCAL_APPLICATION",
            owned_by_platform=True,
            automatic_recovery_permitted=True,
            endpoint_path="/health",
            application_id=application_id,
            db_path=self.db_path,
        )
        configure_recovery_policy(
            application_id,
            automatic_recovery_enabled=True,
            permitted_actions=(RECOVERY_ACTION_RETRY,),
            required_approval_level="none",
            max_retry_attempts=1,
            cooldown_seconds=0,
            verification_timeout_seconds=1,
            db_path=self.db_path,
        )
        simulation_id = None
        try:
            for _ in range(100):
                monitor_application_once(
                    application_id,
                    db_path=self.db_path,
                    request_timeout=3,
                    telemetry_source="controlled_integration_test",
                )

            simulation_id = start_simulation_event(
                application_id,
                "http_errors",
                {
                    "configuration": {
                        "duration_seconds": 5,
                        "endpoint": "/health",
                    },
                    "affected_endpoint": "/health",
                },
                db_path=self.db_path,
            )
            faults.apply(
                "http_errors",
                {"duration_seconds": 5, "endpoint": "/health"},
            )
            failed_reading = monitor_application_once(
                application_id,
                db_path=self.db_path,
                request_timeout=3,
                is_simulated=True,
                simulation_id=simulation_id,
                telemetry_source="controlled_integration_test",
            )
            self.assertEqual(failed_reading["http_status_code"], 500)

            detection = analyze_application(
                application_id,
                db_path=self.db_path,
                include_simulated=True,
            )
            anomaly = next(
                result
                for result in detection["results"]
                if result.get("simulation_id") == simulation_id
            )
            self.assertEqual(anomaly["prediction"], "Anomaly")

            rca = generate_application_rca(
                application_id,
                source_timestamp=failed_reading["timestamp"],
                db_path=self.db_path,
                include_simulated=True,
            )
            self.assertIsNotNone(rca["report_id"])
            incident_id = process_application_anomaly(
                application_id,
                failed_reading["timestamp"],
                db_path=self.db_path,
                include_simulated=True,
            )
            self.assertIsNotNone(incident_id)
            recovery = process_incident(incident_id, db_path=self.db_path)
            self.assertEqual(recovery["decision"], "ESCALATED")

            faults.clear()
            final_reading = monitor_application_once(
                application_id,
                db_path=self.db_path,
                request_timeout=3,
                is_simulated=True,
                simulation_id=simulation_id,
                telemetry_source="controlled_integration_test",
            )
            self.assertEqual(final_reading["http_status_code"], 200)
            with closing(connect(self.db_path)) as connection:
                recovery_count = connection.execute(
                    """
                    SELECT COUNT(*) AS attempt_count
                    FROM recovery_attempts
                    WHERE incident_id = ?
                    """,
                    (incident_id,),
                ).fetchone()["attempt_count"]
                real_reading_count = connection.execute(
                    """
                    SELECT COUNT(*) AS reading_count
                    FROM application_telemetry
                    WHERE application_id = ? AND is_simulated = 0
                    """,
                    (application_id,),
                ).fetchone()["reading_count"]
            self.assertEqual(recovery_count, 1)
            self.assertEqual(real_reading_count, 100)
            finish_simulation_event(
                simulation_id,
                status="Completed",
                updates={"cleanup_result": "Controlled fault state cleared."},
                db_path=self.db_path,
            )
        finally:
            faults.clear()
            server.shutdown()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
