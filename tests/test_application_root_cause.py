import json
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from app.application_registry import register_application
from app.database import connect, initialize_database
from app.dependency_mapping import (
    add_application_dependency,
    get_application_dependency_closure,
)
from app.multi_app_monitor import MultiApplicationMonitor
from ml.application_root_cause import (
    generate_application_rca,
    get_application_rca_history,
    get_application_rca_report,
    get_latest_application_rca,
)
from ml.root_cause import generate_application_rca as root_module_rca


class ApplicationRootCauseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "rca.sqlite3"
        initialize_database(self.database)
        self.app_a = self.register_application("Application A")
        self.app_b = self.register_application("Application B")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def register_application(
        self,
        name,
        owned=False,
        process_monitoring=False,
        application_type="REST_API",
    ):
        return register_application(
            name=name,
            url=(
                f"local://{name.replace(' ', '-').casefold()}"
                if application_type == "CONTROLLED_LOCAL_APPLICATION"
                else f"https://{name.replace(' ', '').casefold()}.example.test/health"
            ),
            application_type=application_type,
            owned_by_platform=owned,
            process_monitoring_permitted=process_monitoring,
            process_name="controlled-test-app" if process_monitoring else None,
            db_path=self.database,
        )

    @staticmethod
    def timestamp(index=0):
        return (
            datetime(2026, 1, 1, tzinfo=timezone.utc)
            + timedelta(minutes=index)
        ).isoformat()

    def insert_telemetry(self, application_id, timestamp, **overrides):
        payload = {
            "application_id": application_id,
            "timestamp": timestamp,
            "availability": True,
            "http_status_code": 200,
            "response_time_ms": 100.0,
            "request_success": True,
            "connection_error": False,
            "timeout_error": False,
            "consecutive_failure_count": 0,
            "cpu_usage": None,
            "memory_usage": None,
            "process_id": None,
            "process_status": None,
            "process_memory_mb": None,
            "process_cpu_percent": None,
            "error_details": None,
            "is_simulated": False,
        }
        payload.update(overrides)
        with closing(connect(self.database)) as connection, connection:
            connection.execute(
                """
                INSERT INTO application_telemetry (
                    application_id, source, timestamp, data_json,
                    is_simulated, created_at
                ) VALUES (?, 'test', ?, ?, 0, ?)
                """,
                (
                    application_id,
                    timestamp,
                    json.dumps(payload),
                    timestamp,
                ),
            )

    def insert_anomaly(self, application_id, timestamp, severity="High"):
        details = {
            "application_id": application_id,
            "timestamp": timestamp,
            "prediction": "Anomaly",
            "severity": severity,
            "metrics_responsible": ["Response time"],
            "explanation": "Application reading exceeded its baseline.",
        }
        with closing(connect(self.database)) as connection, connection:
            connection.execute(
                """
                INSERT INTO anomaly_results (
                    application_id, timestamp, prediction, anomaly_score,
                    status, data_json, is_simulated, created_at
                ) VALUES (?, ?, 'Anomaly', -0.2, ?, ?, 0, ?)
                """,
                (
                    application_id,
                    timestamp,
                    severity,
                    json.dumps(details),
                    timestamp,
                ),
            )

    def test_application_data_is_separated_and_slow_response_is_investigated(self):
        application_a_id = self.app_a["application_id"]
        application_b_id = self.app_b["application_id"]
        timestamp = self.timestamp()
        self.insert_telemetry(application_a_id, timestamp, response_time_ms=100.0)
        self.insert_telemetry(application_b_id, timestamp, response_time_ms=1800.0)
        self.insert_anomaly(application_b_id, timestamp)

        report_a = generate_application_rca(
            application_a_id, timestamp, db_path=self.database
        )
        report_b = generate_application_rca(
            application_b_id, timestamp, db_path=self.database
        )

        self.assertNotIn("response_time_ms", report_a["related_abnormal_metrics"])
        self.assertEqual(report_b["application_id"], application_b_id)
        self.assertIn("response_time_ms", report_b["related_abnormal_metrics"])
        self.assertIn(
            "response time",
            report_b["suspected_root_cause"].casefold(),
        )
        self.assertEqual(report_b["anomaly_id"], 1)

    def test_repeated_http_failures_and_error_details_are_reported(self):
        application_id = self.app_a["application_id"]
        timestamps = [self.timestamp(0), self.timestamp(1)]
        for timestamp in timestamps:
            self.insert_telemetry(
                application_id,
                timestamp,
                availability=False,
                http_status_code=503,
                request_success=False,
                connection_error=True,
                consecutive_failure_count=2,
                error_details="upstream connection refused",
            )

        report = generate_application_rca(
            application_id,
            timestamps[-1],
            db_path=self.database,
        )

        self.assertIn("http_status_code", report["related_abnormal_metrics"])
        self.assertTrue(
            any("error details" in item.casefold() for item in report["supporting_evidence"])
        )
        self.assertTrue(report["ranked_causes"])
        self.assertIn(report["ranked_causes"][0]["classification"], {"likely", "possible"})

    def test_permitted_owned_process_cpu_and_memory_are_investigated(self):
        application = self.register_application(
            "Owned local",
            owned=True,
            process_monitoring=True,
            application_type="CONTROLLED_LOCAL_APPLICATION",
        )
        application_id = application["application_id"]
        self.insert_telemetry(application_id, self.timestamp(), cpu_usage=96.0)

        report = generate_application_rca(
            application_id,
            self.timestamp(),
            db_path=self.database,
        )

        self.assertIn("cpu_usage", report["related_abnormal_metrics"])
        self.assertIn("CPU", report["suspected_root_cause"])

    def test_external_process_metrics_are_not_attributed_as_resource_causes(self):
        application_id = self.app_a["application_id"]
        timestamp = self.timestamp()
        self.insert_telemetry(
            application_id,
            timestamp,
            cpu_usage=99.0,
            memory_usage=99.0,
            process_cpu_percent=100.0,
            process_memory_mb=500.0,
        )

        report = generate_application_rca(
            application_id,
            timestamp,
            db_path=self.database,
        )

        self.assertNotIn("cpu_usage", report["related_abnormal_metrics"])
        self.assertNotIn("memory_usage", report["related_abnormal_metrics"])
        self.assertNotIn("process_memory_mb", report["related_abnormal_metrics"])

    def test_process_memory_growth_is_investigated_for_owned_application(self):
        application = self.register_application(
            "Owned memory app",
            owned=True,
            process_monitoring=True,
            application_type="CONTROLLED_LOCAL_APPLICATION",
        )
        application_id = application["application_id"]
        self.insert_telemetry(
            application_id,
            self.timestamp(0),
            process_memory_mb=100.0,
        )
        self.insert_telemetry(
            application_id,
            self.timestamp(1),
            process_memory_mb=150.0,
        )

        report = generate_application_rca(
            application_id,
            self.timestamp(1),
            db_path=self.database,
        )

        self.assertIn("process_memory_mb", report["related_abnormal_metrics"])

    def test_dependency_health_is_evidence_based_and_cycles_are_rejected(self):
        app_id = self.app_a["application_id"]
        dependency = self.register_application("Dependency")
        dependency_id = dependency["application_id"]
        add_application_dependency(
            app_id,
            dependency_id,
            db_path=self.database,
        )
        with self.assertRaisesRegex(ValueError, "circular"):
            add_application_dependency(
                dependency_id,
                app_id,
                db_path=self.database,
            )
        self.assertEqual(
            len(get_application_dependency_closure(app_id, db_path=self.database)),
            1,
        )

        timestamp = self.timestamp()
        self.insert_telemetry(
            app_id,
            timestamp,
            availability=False,
            request_success=False,
            connection_error=True,
        )
        self.insert_telemetry(
            dependency_id,
            timestamp,
            availability=False,
            request_success=False,
            connection_error=True,
        )

        report = generate_application_rca(
            app_id,
            timestamp,
            db_path=self.database,
        )

        self.assertEqual(report["related_dependencies"][0]["health"], "unhealthy")
        self.assertTrue(
            any(cause["category"] == "dependency" for cause in report["ranked_causes"])
        )

    def test_database_issue_is_reported_only_when_database_telemetry_exists(self):
        application_id = self.app_a["application_id"]
        timestamp = self.timestamp()
        self.insert_telemetry(
            application_id,
            timestamp,
            database_available=False,
            database_error_count=3,
        )

        report = generate_application_rca(
            application_id,
            timestamp,
            db_path=self.database,
        )

        self.assertIn("database_available", report["related_abnormal_metrics"])
        self.assertTrue(
            any(cause["category"] == "database" for cause in report["ranked_causes"])
        )

    def test_insufficient_evidence_is_explicit_and_not_fabricated(self):
        empty_app_id = self.app_a["application_id"]
        no_data = generate_application_rca(empty_app_id, db_path=self.database)
        self.assertEqual(no_data["status"], "insufficient_evidence")
        self.assertIsNone(no_data["report_id"])
        self.assertEqual(no_data["confidence_score"], 0.0)

        timestamp = self.timestamp()
        self.insert_telemetry(empty_app_id, timestamp, response_time_ms=None)
        report = generate_application_rca(
            empty_app_id,
            timestamp,
            db_path=self.database,
        )
        self.assertEqual(report["status"], "insufficient_evidence")
        self.assertFalse(report["ranked_causes"])
        self.assertEqual(report["confidence_score"], 0.0)

    def test_reports_persist_retrieve_and_deduplicate_by_application_timestamp(self):
        application_id = self.app_a["application_id"]
        timestamp = self.timestamp()
        self.insert_telemetry(application_id, timestamp, http_status_code=500)
        with closing(connect(self.database)) as connection, connection:
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, application_id, source_timestamp, created_at,
                    updated_at, severity, status, title, root_cause,
                    recommended_action
                ) VALUES (?, ?, ?, ?, ?, 'High', 'Open', ?, ?, ?)
                """,
                (
                    "INC-RCA-TEST",
                    application_id,
                    timestamp,
                    timestamp,
                    timestamp,
                    "HTTP failure",
                    "Application returned HTTP 500",
                    "Inspect application logs",
                ),
            )

        first = root_module_rca(
            application_id,
            timestamp,
            db_path=self.database,
        )
        second = generate_application_rca(
            application_id,
            timestamp,
            db_path=self.database,
        )

        self.assertEqual(first["report_id"], second["report_id"])
        self.assertEqual(first["incident_id"], "INC-RCA-TEST")
        self.assertGreaterEqual(first["confidence_score"], 0.0)
        self.assertLessEqual(first["confidence_score"], 1.0)
        self.assertEqual(
            get_application_rca_report(first["report_id"], db_path=self.database)[
                "application_id"
            ],
            application_id,
        )
        self.assertEqual(
            get_latest_application_rca(application_id, db_path=self.database)[
                "report_id"
            ],
            first["report_id"],
        )
        history = get_application_rca_history(application_id, db_path=self.database)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["details"]["anomaly_id"], None)

    def test_telemetry_error_does_not_change_other_app_report(self):
        app_a = self.app_a["application_id"]
        app_b = self.app_b["application_id"]
        self.insert_telemetry(
            app_a,
            self.timestamp(),
            error_details="simulated parse error",
        )
        self.insert_telemetry(
            app_b,
            self.timestamp(),
            response_time_ms=1600.0,
        )

        def malformed_json(application_id):
            if application_id == app_a:
                with closing(connect(self.database)) as connection, connection:
                    connection.execute(
                        """
                        UPDATE application_telemetry SET data_json = '{'
                        WHERE application_id = ?
                        """,
                        (app_a,),
                    )
            return generate_application_rca(
                application_id,
                self.timestamp(),
                db_path=self.database,
            )

        report_a = malformed_json(app_a)
        report_b = malformed_json(app_b)

        self.assertEqual(report_a["status"], "insufficient_evidence")
        self.assertIn("response_time_ms", report_b["related_abnormal_metrics"])

    def test_rca_failure_for_one_monitor_worker_does_not_stop_another(self):
        monitor = MultiApplicationMonitor(db_path=self.database)
        monitor.engine.collect_reading = Mock()
        anomaly = {"timestamp": self.timestamp(), "severity": "High"}

        class OneCycleEvent:
            def __init__(self):
                self.cycles = 0

            def is_set(self):
                return self.cycles > 0

            def wait(self, interval):
                self.waited_interval = interval
                self.cycles += 1
                return True

        with patch(
            "ml.detect_anomalies.analyze_application",
            return_value={"anomalies": [anomaly]},
        ), patch(
            "ml.application_root_cause.generate_application_rca",
            side_effect=[RuntimeError("controlled RCA failure"), {"report_id": 1}],
        ) as generate_rca:
            with patch(
                "app.incident_management.process_application_anomaly",
                return_value="INC-TEST",
            ) as process_incident:
                monitor._run_application(
                    self.app_a["application_id"],
                    OneCycleEvent(),
                )
                monitor._run_application(
                    self.app_b["application_id"],
                    OneCycleEvent(),
                )

        self.assertEqual(generate_rca.call_count, 2)
        self.assertEqual(process_incident.call_count, 2)
        self.assertEqual(monitor.engine.collect_reading.call_count, 2)


if __name__ == "__main__":
    unittest.main()
