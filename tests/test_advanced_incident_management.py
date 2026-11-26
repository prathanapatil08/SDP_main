import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from app.application_registry import register_application
from app.database import connect, initialize_database
from app.multi_app_monitor import MultiApplicationMonitor
from app.incident_management import (
    INCIDENT_SEVERITIES,
    add_investigation_note,
    acknowledge_incident,
    change_incident_severity,
    close_incident,
    get_incident,
    get_incident_timeline,
    list_incidents,
    process_application_anomaly,
    reopen_incident,
    resolve_incident,
    start_investigation,
    update_incident_status,
)


class AdvancedIncidentManagementTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            ignore_cleanup_errors=True
        )
        self.database = Path(self.temporary_directory.name) / "incidents.sqlite3"
        initialize_database(self.database)
        self.app_a = self.register_application("Application A")
        self.app_b = self.register_application("Application B")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def register_application(self, name):
        normalized = name.replace(" ", "").casefold()
        return register_application(
            name=name,
            url=f"https://{normalized}.example.test/health",
            application_type="REST_API",
            db_path=self.database,
        )

    @staticmethod
    def timestamp(index=0):
        return (
            datetime(2026, 11, 1, tzinfo=timezone.utc)
            + timedelta(minutes=index)
        ).isoformat()

    def insert_anomaly(self, application_id, timestamp, **overrides):
        payload = {
            "application_id": application_id,
            "timestamp": timestamp,
            "prediction": "Anomaly",
            "anomaly_score": -0.25,
            "severity": "Medium",
            "availability": True,
            "http_status_code": 200,
            "response_time_ms": 1500.0,
            "request_success": True,
            "connection_error": False,
            "timeout_error": False,
            "consecutive_failure_count": 0,
            "cpu_usage": None,
            "memory_usage": None,
            "process_cpu_percent": None,
            "metrics_responsible": ["Response time"],
            "explanation": "Response time exceeded the learned baseline.",
        }
        payload.update(overrides)
        with closing(connect(self.database)) as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO anomaly_results (
                    application_id, timestamp, prediction, anomaly_score,
                    status, data_json, is_simulated, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    application_id,
                    timestamp,
                    payload["prediction"],
                    payload["anomaly_score"],
                    payload["severity"],
                    json.dumps(payload),
                    timestamp,
                ),
            )
        return cursor.lastrowid

    def insert_rca_report(
        self,
        application_id,
        timestamp,
        anomaly_id,
        *,
        severity="High",
        category="response_time",
        root_cause="Application response time is elevated.",
    ):
        details = {
            "application_id": application_id,
            "incident_id": None,
            "anomaly_id": anomaly_id,
            "source_timestamp": timestamp,
            "suspected_root_cause": root_cause,
            "ranked_causes": [
                {
                    "category": category,
                    "cause": root_cause,
                    "related_dependencies": [],
                    "supporting_evidence": ["Controlled test RCA evidence."],
                }
            ],
            "related_dependencies": [],
            "confidence_score": 0.72,
            "supporting_evidence": ["Controlled test RCA evidence."],
            "recommended_action": "Inspect the affected application.",
        }
        with closing(connect(self.database)) as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO root_cause_reports (
                    application_id, incident_id, source_timestamp, severity,
                    root_cause, recommended_action, data_json,
                    is_simulated, created_at
                ) VALUES (?, NULL, ?, ?, ?, ?, ?, 0, ?)
                """,
                (
                    application_id,
                    timestamp,
                    severity,
                    root_cause,
                    details["recommended_action"],
                    json.dumps(details),
                    timestamp,
                ),
            )
        return cursor.lastrowid

    def process(self, application_id, timestamp, **kwargs):
        return process_application_anomaly(
            application_id,
            timestamp,
            db_path=self.database,
            **kwargs,
        )

    def test_incidents_are_isolated_by_application(self):
        timestamp = self.timestamp()
        app_a_id = self.app_a["application_id"]
        app_b_id = self.app_b["application_id"]
        self.insert_anomaly(app_a_id, timestamp, response_time_ms=1700.0)
        self.insert_anomaly(
            app_b_id,
            timestamp,
            http_status_code=503,
            request_success=False,
            response_time_ms=400.0,
            metrics_responsible=["HTTP status"],
            severity="High",
        )

        incident_a = self.process(app_a_id, timestamp)
        incident_b = self.process(app_b_id, timestamp)

        self.assertNotEqual(incident_a, incident_b)
        self.assertEqual(
            [item["incident_id"] for item in list_incidents(
                self.database,
                application_id=app_a_id,
            )],
            [incident_a],
        )
        self.assertEqual(
            [item["incident_id"] for item in list_incidents(
                self.database,
                application_id=app_b_id,
            )],
            [incident_b],
        )

    def test_repeated_same_problem_updates_one_incident_and_severity_history(self):
        application_id = self.app_a["application_id"]
        first_timestamp = self.timestamp(0)
        second_timestamp = self.timestamp(1)
        first_anomaly = self.insert_anomaly(
            application_id,
            first_timestamp,
            severity="Medium",
            response_time_ms=1500.0,
        )
        second_anomaly = self.insert_anomaly(
            application_id,
            second_timestamp,
            severity="High",
            response_time_ms=3200.0,
        )

        incident_id = self.process(application_id, first_timestamp)
        repeated_id = self.process(application_id, second_timestamp)
        same_reading_id = self.process(application_id, second_timestamp)
        incident = get_incident(incident_id, db_path=self.database)
        timeline = get_incident_timeline(incident_id, db_path=self.database)

        self.assertEqual(incident_id, repeated_id)
        self.assertEqual(incident_id, same_reading_id)
        self.assertEqual(incident["occurrence_count"], 2)
        self.assertEqual(incident["severity"], "High")
        self.assertEqual(incident["anomaly_id"], second_anomaly)
        self.assertIn(
            "severity_changed",
            [event["event_type"] for event in timeline],
        )
        self.assertEqual(
            len([event for event in timeline if event["event_type"] == "anomaly_detected"]),
            2,
        )
        self.assertNotEqual(first_anomaly, second_anomaly)

    def test_unrelated_http_failure_does_not_merge_with_latency_incident(self):
        application_id = self.app_a["application_id"]
        latency_timestamp = self.timestamp(0)
        http_timestamp = self.timestamp(1)
        self.insert_anomaly(
            application_id,
            latency_timestamp,
            response_time_ms=1800.0,
        )
        self.insert_anomaly(
            application_id,
            http_timestamp,
            http_status_code=503,
            request_success=False,
            response_time_ms=300.0,
            metrics_responsible=["HTTP status"],
            severity="High",
        )

        latency_incident = self.process(application_id, latency_timestamp)
        http_incident = self.process(application_id, http_timestamp)

        self.assertNotEqual(latency_incident, http_incident)
        self.assertEqual(len(list_incidents(self.database)), 2)

    def test_resolved_problem_later_creates_a_new_incident(self):
        application_id = self.app_a["application_id"]
        first_timestamp = self.timestamp(0)
        later_timestamp = self.timestamp(20)
        self.insert_anomaly(application_id, first_timestamp)
        self.insert_anomaly(application_id, later_timestamp)

        first_id = self.process(application_id, first_timestamp)
        self.assertTrue(resolve_incident(first_id, db_path=self.database))
        second_id = self.process(application_id, later_timestamp)

        self.assertNotEqual(first_id, second_id)
        self.assertEqual(len(list_incidents(self.database)), 2)

    def test_configurable_minimum_severity_skips_low_anomaly_by_default(self):
        application_id = self.app_a["application_id"]
        timestamp = self.timestamp()
        self.insert_anomaly(
            application_id,
            timestamp,
            severity="Low",
            response_time_ms=500.0,
        )

        self.assertIsNone(self.process(application_id, timestamp))
        self.assertEqual(list_incidents(self.database), [])
        incident_id = self.process(
            application_id,
            timestamp,
            minimum_severity="Low",
        )
        self.assertIsNotNone(incident_id)
        self.assertEqual(
            get_incident(incident_id, db_path=self.database)["severity"],
            "Low",
        )

    def test_availability_and_owned_resource_evidence_raise_severity(self):
        external_id = self.app_a["application_id"]
        unavailable_timestamp = self.timestamp()
        self.insert_anomaly(
            external_id,
            unavailable_timestamp,
            availability=False,
            request_success=False,
            connection_error=True,
            severity="Low",
        )
        unavailable_id = self.process(external_id, unavailable_timestamp)
        self.assertEqual(
            get_incident(unavailable_id, db_path=self.database)["severity"],
            "High",
        )

        owned = register_application(
            name="Owned app",
            url="local://owned-app",
            application_type="CONTROLLED_LOCAL_APPLICATION",
            owned_by_platform=True,
            process_monitoring_permitted=True,
            process_name="controlled-owned-app",
            db_path=self.database,
        )
        resource_timestamp = self.timestamp(1)
        self.insert_anomaly(
            owned["application_id"],
            resource_timestamp,
            severity="Low",
            cpu_usage=98.0,
            metrics_responsible=["Process CPU usage"],
        )
        resource_id = self.process(owned["application_id"], resource_timestamp)
        self.assertEqual(
            get_incident(resource_id, db_path=self.database)["severity"],
            "Critical",
        )

    def test_rca_and_anomaly_links_are_stored_and_timeline_is_audited(self):
        application_id = self.app_a["application_id"]
        timestamp = self.timestamp()
        anomaly_id = self.insert_anomaly(
            application_id,
            timestamp,
            response_time_ms=1800.0,
        )
        rca_id = self.insert_rca_report(
            application_id,
            timestamp,
            anomaly_id,
        )

        incident_id = self.process(application_id, timestamp)
        incident = get_incident(incident_id, db_path=self.database)
        timeline = get_incident_timeline(incident_id, db_path=self.database)
        with closing(connect(self.database)) as connection:
            rca = connection.execute(
                "SELECT incident_id FROM root_cause_reports WHERE report_id = ?",
                (rca_id,),
            ).fetchone()

        self.assertEqual(incident["anomaly_id"], anomaly_id)
        self.assertEqual(incident["rca_report_id"], rca_id)
        self.assertEqual(rca["incident_id"], incident_id)
        self.assertEqual(
            {event["event_type"] for event in timeline},
            {"created", "anomaly_detected", "rca_generated"},
        )
        self.assertTrue(
            all(
                event["application_id"] == application_id
                for event in timeline
            )
        )

    def test_incident_is_created_when_rca_is_unavailable(self):
        application_id = self.app_a["application_id"]
        timestamp = self.timestamp()
        self.insert_anomaly(
            application_id,
            timestamp,
            severity="High",
            http_status_code=503,
            request_success=False,
            response_time_ms=300.0,
            metrics_responsible=["HTTP status"],
        )

        incident_id = self.process(application_id, timestamp)
        incident = get_incident(incident_id, db_path=self.database)
        timeline = get_incident_timeline(incident_id, db_path=self.database)

        self.assertIsNone(incident["rca_report_id"])
        self.assertIn("Response time", incident["root_cause"])
        self.assertIn(
            "anomaly_detected",
            [event["event_type"] for event in timeline],
        )

    def test_lifecycle_notes_filters_and_invalid_transitions(self):
        application_id = self.app_a["application_id"]
        timestamp = self.timestamp()
        self.insert_anomaly(application_id, timestamp)
        incident_id = self.process(application_id, timestamp)

        self.assertTrue(acknowledge_incident(incident_id, self.database))
        self.assertEqual(
            get_incident(incident_id, self.database)["status"],
            "Acknowledged",
        )
        self.assertTrue(start_investigation(incident_id, self.database))
        self.assertTrue(add_investigation_note(
            incident_id,
            "Checked service logs and request traces.",
            self.database,
        ))
        self.assertTrue(update_incident_status(
            incident_id,
            "Monitoring",
            self.database,
        ))
        self.assertTrue(resolve_incident(incident_id, self.database))
        resolved_at = get_incident(incident_id, self.database)["resolved_at"]
        self.assertTrue(close_incident(incident_id, self.database))
        closed = get_incident(incident_id, self.database)
        self.assertEqual(closed["resolved_at"], resolved_at)
        self.assertIsNotNone(closed["closed_at"])
        self.assertTrue(reopen_incident(incident_id, self.database))
        reopened = get_incident(incident_id, self.database)
        self.assertEqual(reopened["status"], "Open")
        self.assertIsNone(reopened["resolved_at"])
        self.assertIsNone(reopened["closed_at"])
        with self.assertRaisesRegex(ValueError, "transition"):
            update_incident_status(incident_id, "Closed", self.database)

        self.assertTrue(
            change_incident_severity(incident_id, "Critical", self.database)
        )
        self.assertEqual(
            len(list_incidents(
                self.database,
                application_id=application_id,
                severity="Critical",
                status="Open",
            )),
            1,
        )
        self.assertIn(
            "investigation_note",
            [
                event["event_type"]
                for event in get_incident_timeline(incident_id, self.database)
            ],
        )
        self.assertEqual(INCIDENT_SEVERITIES, ("Low", "Medium", "High", "Critical"))

    def test_failed_incident_processing_for_one_application_isolated(self):
        app_a_id = self.app_a["application_id"]
        app_b_id = self.app_b["application_id"]
        timestamp = self.timestamp()
        self.insert_anomaly(app_a_id, timestamp)
        self.insert_anomaly(app_b_id, timestamp)
        with closing(connect(self.database)) as connection, connection:
            connection.execute(
                """
                UPDATE anomaly_results SET data_json = '{'
                WHERE application_id = ?
                """,
                (app_a_id,),
            )

        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            self.process(app_a_id, timestamp)
        incident_id = self.process(app_b_id, timestamp)

        self.assertIsNotNone(incident_id)
        self.assertEqual(
            list_incidents(self.database, application_id=app_b_id)[0][
                "incident_id"
            ],
            incident_id,
        )
        self.assertEqual(list_incidents(self.database, application_id=app_a_id), [])

    def test_monitor_continues_when_one_application_incident_processing_fails(self):
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
            return_value={"report_id": 10},
        ), patch(
            "app.incident_management.process_application_anomaly",
            side_effect=[RuntimeError("controlled incident failure"), "INC-TEST"],
        ) as process_incident:
            monitor._run_application(
                self.app_a["application_id"],
                OneCycleEvent(),
            )
            monitor._run_application(
                self.app_b["application_id"],
                OneCycleEvent(),
            )

        self.assertEqual(process_incident.call_count, 2)
        self.assertEqual(monitor.engine.collect_reading.call_count, 2)

    def test_old_incident_rows_and_events_survive_phase_five_migration(self):
        legacy_database = Path(self.temporary_directory.name) / "legacy.sqlite3"
        with sqlite3.connect(legacy_database) as connection:
            connection.executescript(
                """
                CREATE TABLE incidents (
                    incident_id TEXT PRIMARY KEY,
                    source_timestamp TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('Open', 'Investigating', 'Resolved')
                    ),
                    title TEXT NOT NULL,
                    root_cause TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    acknowledged_at TEXT,
                    resolved_at TEXT,
                    resolution_time_seconds REAL
                );
                CREATE TABLE incident_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL
                        REFERENCES incidents(incident_id) ON DELETE CASCADE,
                    occurred_at TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT '',
                    source_key TEXT
                );
                INSERT INTO incidents (
                    incident_id, source_timestamp, created_at, updated_at,
                    severity, status, title, root_cause, recommended_action
                ) VALUES (
                    'INC-HISTORY-1', '2026-11-01T00:00:00+00:00',
                    '2026-11-01T00:00:00+00:00',
                    '2026-11-01T00:00:00+00:00',
                    'Warning', 'Open', 'Historical incident',
                    'Historical root cause', 'Historical action'
                );
                INSERT INTO incident_events (
                    incident_id, occurred_at, event_type, summary
                ) VALUES (
                    'INC-HISTORY-1', '2026-11-01T00:00:00+00:00',
                    'detected', 'Historical anomaly event'
                );
                """
            )

        initialize_database(legacy_database)
        with closing(connect(legacy_database)) as connection:
            incident = connection.execute(
                """
                SELECT incident_id, status, occurrence_count, source_timestamp
                FROM incidents WHERE incident_id = 'INC-HISTORY-1'
                """
            ).fetchone()
            event_count = connection.execute(
                """
                SELECT COUNT(*) AS count FROM incident_events
                WHERE incident_id = 'INC-HISTORY-1'
                """
            ).fetchone()["count"]
            foreign_key_errors = connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()

        self.assertEqual(incident["status"], "Open")
        self.assertEqual(incident["occurrence_count"], 1)
        self.assertEqual(incident["source_timestamp"], "2026-11-01T00:00:00+00:00")
        self.assertEqual(event_count, 1)
        self.assertEqual(foreign_key_errors, [])
        self.assertTrue(acknowledge_incident("INC-HISTORY-1", legacy_database))
        self.assertEqual(
            get_incident("INC-HISTORY-1", legacy_database)["status"],
            "Acknowledged",
        )


if __name__ == "__main__":
    unittest.main()
