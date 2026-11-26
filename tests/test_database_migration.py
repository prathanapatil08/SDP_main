import sqlite3
import tempfile
import unittest
from pathlib import Path

from app.application_registry import (
    LEGACY_FLASK_APPLICATION_ID,
    migrate_existing_flask_application,
)
from app.database import initialize_database, table_names


EXPECTED_PHASE_ONE_TABLES = {
    "applications",
    "application_endpoints",
    "application_processes",
    "application_dependencies",
    "application_telemetry",
    "anomaly_results",
    "root_cause_reports",
    "recovery_policies",
    "recovery_attempts",
    "approval_requests",
    "simulation_events",
    "incidents",
    "incident_events",
}


class DatabaseMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.database = Path(self.temporary_directory.name) / "data.sqlite3"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_initialize_creates_all_required_tables(self):
        initialize_database(self.database)
        names = set(table_names(self.database))
        self.assertTrue(EXPECTED_PHASE_ONE_TABLES.issubset(names))

    def test_existing_legacy_incident_records_are_preserved(self):
        with sqlite3.connect(self.database) as connection:
            connection.executescript(
                """
                CREATE TABLE incidents (
                    incident_id TEXT PRIMARY KEY,
                    source_timestamp TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    title TEXT NOT NULL,
                    root_cause TEXT NOT NULL,
                    recommended_action TEXT NOT NULL,
                    acknowledged_at TEXT,
                    resolved_at TEXT,
                    resolution_time_seconds REAL
                );
                CREATE TABLE incident_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
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
                    'INC-LEGACY-1', '2026-11-21 10:00:00',
                    '2026-11-21T10:00:00+00:00',
                    '2026-11-21T10:00:00+00:00',
                    'Warning', 'Open', 'Legacy incident',
                    'Legacy root cause', 'Legacy action'
                );
                INSERT INTO incident_events (
                    incident_id, occurred_at, event_type, summary
                ) VALUES (
                    'INC-LEGACY-1', '2026-11-21T10:00:00+00:00',
                    'detected', 'Legacy anomaly'
                );
                """
            )

        migrate_existing_flask_application(db_path=self.database)

        with sqlite3.connect(self.database) as connection:
            incident = connection.execute(
                "SELECT incident_id, application_id, title "
                "FROM incidents"
            ).fetchone()
            event = connection.execute(
                "SELECT event_type, application_id FROM incident_events"
            ).fetchone()
            incident_columns = {
                row[1]
                for row in connection.execute(
                    "PRAGMA table_info(incidents)"
                ).fetchall()
            }

        self.assertEqual(incident[0], "INC-LEGACY-1")
        self.assertEqual(incident[1], LEGACY_FLASK_APPLICATION_ID)
        self.assertEqual(incident[2], "Legacy incident")
        self.assertEqual(event[0], "detected")
        self.assertEqual(event[1], LEGACY_FLASK_APPLICATION_ID)
        self.assertIn("application_id", incident_columns)


if __name__ == "__main__":
    unittest.main()
