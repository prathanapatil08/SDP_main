import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from app import incident_management


class IncidentManagementTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "incidents.sqlite3"
        self.report = {
            "source_timestamp": "2026-11-21 10:00:00",
            "severity": "Critical",
            "root_cause": "Application is unreachable",
            "recommended_action": "Inspect service health.",
        }

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_report_creation_is_idempotent_and_records_timeline(self):
        incident_id = incident_management.create_incident_from_report(
            self.report, self.database
        )
        repeated_id = incident_management.create_incident_from_report(
            self.report, self.database
        )

        self.assertEqual(incident_id, repeated_id)
        incidents = incident_management.list_incidents(self.database)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["status"], "Open")
        timeline = incident_management.get_incident_timeline(
            incident_id, self.database
        )
        self.assertEqual(
            [event["event_type"] for event in timeline],
            ["detected", "diagnosed"],
        )

    def test_sync_imports_non_normal_history_idempotently_and_preserves_event_times(self):
        report = {
            **self.report,
            "timestamp": "2026-11-21 10:00:05",
        }

        first_sync = incident_management.sync_reports([report], self.database)
        second_sync = incident_management.sync_reports([report], self.database)

        self.assertEqual(first_sync, second_sync)
        self.assertEqual(len(incident_management.list_incidents(self.database)), 1)
        timeline = incident_management.get_incident_timeline(
            first_sync[0], self.database
        )
        self.assertEqual(
            [event["event_type"] for event in timeline],
            ["detected", "diagnosed"],
        )
        self.assertLess(
            timeline[0]["occurred_at"],
            timeline[1]["occurred_at"],
        )
        elapsed = (
            datetime.fromisoformat(timeline[1]["occurred_at"])
            - datetime.fromisoformat(timeline[0]["occurred_at"])
        )
        self.assertEqual(
            elapsed.total_seconds(),
            5,
        )

    def test_dependency_correlation_is_saved_in_diagnosis_timeline(self):
        correlation = (
            "Possible shared upstream cause: Host resources may contribute "
            "to Flask API symptoms."
        )
        incident_id = incident_management.create_incident_from_report(
            {
                **self.report,
                "dependency_correlation": correlation,
            },
            self.database,
        )

        timeline = incident_management.get_incident_timeline(
            incident_id, self.database
        )

        self.assertIn(correlation, timeline[-1]["details"])

    def test_acknowledgement_recovery_and_resolution_are_tracked(self):
        incident_id = incident_management.create_incident_from_report(
            self.report, self.database
        )
        self.assertTrue(
            incident_management.acknowledge_incident(
                incident_id, self.database
            )
        )
        self.assertFalse(
            incident_management.acknowledge_incident(
                incident_id, self.database
            )
        )
        self.assertTrue(
            incident_management.record_recovery_attempt(
                self.report["source_timestamp"],
                "Retry API request",
                "Retry verified",
                "Health checks passed.",
                self.database,
            )
        )
        self.assertTrue(
            incident_management.update_incident_status(
                incident_id, "Resolved", self.database
            )
        )

        incident = incident_management.list_incidents(self.database)[0]
        self.assertEqual(incident["status"], "Resolved")
        self.assertIsNotNone(incident["acknowledged_at"])
        self.assertGreaterEqual(incident["resolution_time_seconds"], 0)
        self.assertEqual(incident["recovery_attempts"], 1)
        self.assertEqual(
            [
                event["event_type"]
                for event in incident_management.get_incident_timeline(
                    incident_id, self.database
                )
            ],
            ["detected", "diagnosed", "acknowledged", "recovery_attempt", "resolved"],
        )

    def test_normal_report_does_not_create_incident(self):
        self.report["severity"] = "Normal"

        self.assertIsNone(
            incident_management.create_incident_from_report(
                self.report, self.database
            )
        )
        self.assertEqual(incident_management.list_incidents(self.database), [])

    def test_detection_is_opened_before_root_cause_analysis(self):
        metrics = {
            "timestamp": self.report["source_timestamp"],
            "cpu_usage": 96,
            "memory_usage": 70,
            "application_status": "Healthy",
        }
        incident_id = incident_management.record_anomaly_detection(
            metrics, self.database
        )
        self.assertEqual(
            [
                event["event_type"]
                for event in incident_management.get_incident_timeline(
                    incident_id, self.database
                )
            ],
            ["detected"],
        )

        diagnosed_id = incident_management.create_incident_from_report(
            self.report, self.database
        )
        incident = incident_management.list_incidents(self.database)[0]
        self.assertEqual(diagnosed_id, incident_id)
        self.assertEqual(incident["severity"], "Critical")
        self.assertEqual(
            [
                event["event_type"]
                for event in incident_management.get_incident_timeline(
                    incident_id, self.database
                )
            ],
            ["detected", "diagnosed"],
        )

    def test_invalid_status_is_rejected(self):
        incident_id = incident_management.create_incident_from_report(
            self.report, self.database
        )

        with self.assertRaises(ValueError):
            incident_management.update_incident_status(
                incident_id, "Closed", self.database
            )


if __name__ == "__main__":
    unittest.main()
