import json
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from app.application_registry import register_application
from app.database import connect, initialize_database
from app.incident_management import (
    get_incident,
    get_incident_timeline,
    process_application_anomaly,
)
from app.multi_app_monitor import MultiApplicationMonitor
from app.process_control import (
    restart_registered_application,
    verify_registered_application_process,
)
from app.recovery_framework import (
    approve_recovery_request,
    create_approval_request,
    execute_approved_recovery,
    expire_pending_approvals,
    get_approval_history,
    get_recovery_history,
    process_incident,
    reject_recovery_request,
)
from app.recovery_policy import (
    RECOVERY_ACTION_RESTART,
    RECOVERY_ACTION_RETRY,
    configure_recovery_policy,
    get_recovery_policy,
)


class EmptyProcessProvider:
    @staticmethod
    def process_iter(_attributes):
        return []


class FakeOwnedProcessProvider:
    def __init__(self, process_id=7412):
        executable = Path(sys.executable).resolve()
        working_directory = Path(__file__).resolve().parents[1]
        self.process = SimpleNamespace(
            pid=process_id,
            info={
                "name": executable.name,
                "exe": str(executable),
                "cwd": str(working_directory),
            },
            memory_info=lambda: SimpleNamespace(rss=1024 * 1024),
            memory_percent=lambda: 1.0,
            cpu_percent=lambda interval=None: 1.0,
            status=lambda: "running",
        )

    def process_iter(self, _attributes):
        return [self.process]


class MockResponse:
    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class AutonomousRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(
            ignore_cleanup_errors=True
        )
        self.database = Path(self.temporary_directory.name) / "recovery.sqlite3"
        initialize_database(self.database)
        self.application = self.register_owned_application("Owned local app")
        self.application_id = self.application["application_id"]

    def tearDown(self):
        self.temporary_directory.cleanup()

    def register_owned_application(self, name, automatic_recovery_permitted=True):
        return register_application(
            name=name,
            url="http://127.0.0.1:18080/health",
            application_type="CONTROLLED_LOCAL_APPLICATION",
            monitoring_interval_seconds=2,
            owned_by_platform=True,
            process_monitoring_permitted=True,
            automatic_recovery_permitted=automatic_recovery_permitted,
            process_name=Path(sys.executable).name,
            process_executable_path=sys.executable,
            process_working_directory=str(Path(__file__).resolve().parents[1]),
            db_path=self.database,
        )

    def create_incident(self, application_id=None, *, status_code=503):
        application_id = application_id or self.application_id
        timestamp = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        anomaly = {
            "application_id": application_id,
            "timestamp": timestamp,
            "prediction": "Anomaly",
            "anomaly_score": -0.5,
            "severity": "High",
            "availability": status_code is not None,
            "http_status_code": status_code,
            "response_time_ms": 120.0,
            "request_success": False,
            "connection_error": status_code is None,
            "timeout_error": False,
            "consecutive_failure_count": 2,
            "cpu_usage": None,
            "memory_usage": None,
            "process_cpu_percent": None,
            "metrics_responsible": ["Availability"],
            "explanation": "Controlled recovery test outage.",
        }
        with closing(connect(self.database)) as connection, connection:
            cursor = connection.execute(
                """
                INSERT INTO anomaly_results (
                    application_id, timestamp, prediction, anomaly_score,
                    status, data_json, is_simulated, created_at
                ) VALUES (?, ?, 'Anomaly', -0.5, 'High', ?, 0, ?)
                """,
                (application_id, timestamp, json.dumps(anomaly), timestamp),
            )
            anomaly_id = cursor.lastrowid
            rca = {
                "application_id": application_id,
                "anomaly_id": anomaly_id,
                "source_timestamp": timestamp,
                "suspected_root_cause": "Application endpoint is unavailable.",
                "ranked_causes": [
                    {
                        "category": "availability",
                        "cause": "Application endpoint is unavailable.",
                        "related_dependencies": [],
                        "supporting_evidence": ["Controlled HTTP failure."],
                    }
                ],
                "related_dependencies": [],
            }
            connection.execute(
                """
                INSERT INTO root_cause_reports (
                    application_id, incident_id, source_timestamp, severity,
                    root_cause, recommended_action, data_json,
                    is_simulated, created_at
                ) VALUES (?, NULL, ?, 'High', ?, ?, ?, 0, ?)
                """,
                (
                    application_id,
                    timestamp,
                    "Application endpoint is unavailable.",
                    "Retry the health check and inspect the local service.",
                    json.dumps(rca),
                    timestamp,
                ),
            )
        incident_id = process_application_anomaly(
            application_id,
            timestamp,
            db_path=self.database,
        )
        return incident_id

    def configure_policy(
        self,
        *,
        actions=(RECOVERY_ACTION_RETRY,),
        automatic=True,
        approval="high_risk",
        maximum=3,
        cooldown=0,
        verification_timeout=1.0,
    ):
        return configure_recovery_policy(
            self.application_id,
            automatic_recovery_enabled=automatic,
            permitted_actions=actions,
            required_approval_level=approval,
            max_retry_attempts=maximum,
            cooldown_seconds=cooldown,
            verification_timeout_seconds=verification_timeout,
            db_path=self.database,
        )

    @staticmethod
    def request_with_statuses(statuses):
        statuses = iter(statuses)

        def request(_request, timeout):
            if timeout <= 0:
                raise AssertionError("Health checks must have a positive timeout.")
            return MockResponse(next(statuses, 200))

        return request

    def test_policy_validation_persistence_and_external_rejection(self):
        with self.assertRaises(ValueError):
            configure_recovery_policy(
                self.application_id,
                automatic_recovery_enabled=True,
                permitted_actions=("run-shell-command",),
                db_path=self.database,
            )
        with self.assertRaises(ValueError):
            configure_recovery_policy(
                self.application_id,
                automatic_recovery_enabled=True,
                permitted_actions=(RECOVERY_ACTION_RETRY,),
                max_retry_attempts=0,
                db_path=self.database,
            )

        policy = self.configure_policy(
            actions=(RECOVERY_ACTION_RETRY, RECOVERY_ACTION_RESTART),
        )
        self.assertEqual(policy.max_retry_attempts, 3)
        self.assertEqual(
            get_recovery_policy(self.application_id, db_path=self.database),
            policy,
        )

        external = register_application(
            name="External website",
            url="https://external.example.test/health",
            db_path=self.database,
        )
        with self.assertRaisesRegex(ValueError, "platform-owned"):
            configure_recovery_policy(
                external["application_id"],
                automatic_recovery_enabled=True,
                permitted_actions=(RECOVERY_ACTION_RETRY,),
                db_path=self.database,
            )

    def test_automatic_retry_is_bounded_and_resolves_only_after_health_check(self):
        incident_id = self.create_incident()
        self.configure_policy(maximum=3)

        result = process_incident(
            incident_id,
            db_path=self.database,
            request_function=self.request_with_statuses([503, 200]),
            process_provider=FakeOwnedProcessProvider(),
        )

        self.assertEqual(result["decision"], "RETRY_REQUEST")
        self.assertTrue(result["success"])
        self.assertEqual(result["retry_count"], 1)
        self.assertEqual(get_incident(incident_id, db_path=self.database)["status"], "Resolved")
        attempts = get_recovery_history(
            application_id=self.application_id,
            incident_id=incident_id,
            db_path=self.database,
        )
        self.assertEqual(len(attempts), 1)
        self.assertEqual(attempts[0]["result"], "Retry verified")
        self.assertEqual(attempts[0]["retry_count"], 1)
        event_types = [
            event["event_type"]
            for event in get_incident_timeline(incident_id, db_path=self.database)
        ]
        self.assertIn("recovery_attempt", event_types)
        self.assertIn("resolved", event_types)

    def test_approved_manual_retry_needs_no_automatic_recovery_permission(self):
        application = self.register_owned_application(
            "Manual-only local app",
            automatic_recovery_permitted=False,
        )
        application_id = application["application_id"]
        incident_id = self.create_incident(application_id)
        configure_recovery_policy(
            application_id,
            automatic_recovery_enabled=False,
            permitted_actions=(RECOVERY_ACTION_RETRY,),
            required_approval_level="none",
            max_retry_attempts=1,
            cooldown_seconds=0,
            verification_timeout_seconds=1,
            db_path=self.database,
        )

        pending = process_incident(
            incident_id,
            db_path=self.database,
            request_function=self.request_with_statuses([503]),
            process_provider=FakeOwnedProcessProvider(),
        )
        self.assertEqual(pending["decision"], "REQUIRES_APPROVAL")
        approve_recovery_request(
            pending["approval_id"],
            decided_by="operator-1",
            details="Approved one bounded health retry.",
            db_path=self.database,
        )

        completed = execute_approved_recovery(
            pending["approval_id"],
            db_path=self.database,
            request_function=self.request_with_statuses([503, 200]),
            process_provider=FakeOwnedProcessProvider(),
        )

        self.assertTrue(completed["success"])
        self.assertEqual(completed["decision"], "RETRY_REQUEST")

    def test_failed_retry_escalates_without_resolving_incident(self):
        incident_id = self.create_incident()
        self.configure_policy(maximum=2)

        result = process_incident(
            incident_id,
            db_path=self.database,
            request_function=self.request_with_statuses([503, 503, 503]),
            process_provider=EmptyProcessProvider(),
        )

        self.assertEqual(result["decision"], "ESCALATED")
        self.assertEqual(get_incident(incident_id, db_path=self.database)["status"], "Open")
        attempt = get_recovery_history(
            incident_id=incident_id,
            db_path=self.database,
        )[0]
        self.assertEqual(attempt["result"], "Recovery failed")
        self.assertEqual(attempt["retry_count"], 2)
        self.assertTrue(attempt["error_details"])

    def test_restart_requires_approval_then_revalidates_and_verifies(self):
        incident_id = self.create_incident()
        self.configure_policy(
            actions=(RECOVERY_ACTION_RESTART,),
            approval="high_risk",
            maximum=1,
        )
        for offset in (2, 1):
            timestamp = (
                datetime.now(timezone.utc) - timedelta(seconds=offset)
            ).isoformat(timespec="microseconds")
            with closing(connect(self.database)) as connection, connection:
                connection.execute(
                    """
                    INSERT INTO application_telemetry (
                        application_id, source, timestamp, data_json,
                        is_simulated, created_at
                    ) VALUES (?, 'test', ?, ?, 0, ?)
                    """,
                    (
                        self.application_id,
                        timestamp,
                        json.dumps(
                            {
                                "timestamp": timestamp,
                                "availability": False,
                                "request_success": False,
                                "http_status_code": None,
                                "response_time_ms": 40,
                            }
                        ),
                        timestamp,
                    ),
                )

        restart = Mock(return_value=4321)
        process_verification = Mock(return_value=SimpleNamespace(pid=4321))
        with patch(
            "app.recovery_framework.restart_registered_application",
            restart,
        ), patch(
            "app.recovery_framework.verify_registered_application_process",
            process_verification,
        ):
            pending = process_incident(
                incident_id,
                db_path=self.database,
                request_function=self.request_with_statuses([503]),
                process_provider=FakeOwnedProcessProvider(),
            )
            self.assertEqual(pending["decision"], "REQUIRES_APPROVAL")
            self.assertEqual(restart.call_count, 0)

            decision = approve_recovery_request(
                pending["approval_id"],
                decided_by="operator-1",
                details="Approved controlled local restart.",
                db_path=self.database,
            )
            self.assertEqual(decision["status"], "Approved")
            completed = execute_approved_recovery(
                pending["approval_id"],
                db_path=self.database,
                request_function=self.request_with_statuses([503, 200]),
                process_provider=FakeOwnedProcessProvider(),
            )

        self.assertEqual(completed["decision"], "RESTART_APPLICATION")
        self.assertTrue(completed["success"])
        self.assertEqual(restart.call_count, 1)
        self.assertEqual(get_incident(incident_id, db_path=self.database)["status"], "Resolved")
        events = get_incident_timeline(incident_id, db_path=self.database)
        event_types = [event["event_type"] for event in events]
        self.assertIn("approval_requested", event_types)
        self.assertIn("approval_approved", event_types)
        self.assertIn("recovery_attempt", event_types)

    def test_rejected_approval_cannot_be_executed(self):
        incident_id = self.create_incident()
        self.configure_policy(automatic=False, actions=(RECOVERY_ACTION_RETRY,))
        approval_id = create_approval_request(
            self.application_id,
            incident_id,
            RECOVERY_ACTION_RETRY,
            "Manual-only retry.",
            db_path=self.database,
        )
        rejected = reject_recovery_request(
            approval_id,
            decided_by="operator-2",
            details="Wait for investigation.",
            db_path=self.database,
        )

        self.assertEqual(rejected["status"], "Rejected")
        with self.assertRaisesRegex(ValueError, "approved"):
            execute_approved_recovery(approval_id, db_path=self.database)
        self.assertEqual(
            get_approval_history(
                incident_id=incident_id,
                db_path=self.database,
            )[0]["status"],
            "Rejected",
        )

    def test_pending_approval_expiration_is_audited(self):
        incident_id = self.create_incident()
        self.configure_policy(automatic=False, actions=(RECOVERY_ACTION_RETRY,))
        approval_id = create_approval_request(
            self.application_id,
            incident_id,
            RECOVERY_ACTION_RETRY,
            "Manual-only retry.",
            expires_in_seconds=1,
            db_path=self.database,
        )
        expired = expire_pending_approvals(
            db_path=self.database,
            now=datetime.now(timezone.utc) + timedelta(seconds=2),
        )

        self.assertEqual(expired, [approval_id])
        self.assertEqual(
            get_approval_history(
                incident_id=incident_id,
                db_path=self.database,
            )[0]["status"],
            "Expired",
        )
        self.assertIn(
            "approval_expired",
            [
                event["event_type"]
                for event in get_incident_timeline(
                    incident_id,
                    db_path=self.database,
                )
            ],
        )

    def test_cooldown_and_retry_limit_prevent_repeated_actions(self):
        incident_id = self.create_incident()
        self.configure_policy(
            maximum=1,
            cooldown=120,
        )
        attempted_at = datetime.now(timezone.utc).isoformat(timespec="microseconds")
        with closing(connect(self.database)) as connection, connection:
            connection.execute(
                """
                INSERT INTO recovery_attempts (
                    application_id, incident_id, action, result, verification,
                    details, attempted_at, completed_at, retry_count
                ) VALUES (?, ?, ?, 'Recovery failed', '', '', ?, ?, 1)
                """,
                (
                    self.application_id,
                    incident_id,
                    RECOVERY_ACTION_RETRY,
                    attempted_at,
                    attempted_at,
                ),
            )

        result = process_incident(
            incident_id,
            db_path=self.database,
            request_function=self.request_with_statuses([503]),
            process_provider=EmptyProcessProvider(),
        )
        self.assertEqual(result["decision"], "COOLDOWN")
        self.assertEqual(
            len(get_recovery_history(incident_id=incident_id, db_path=self.database)),
            1,
        )

        self.configure_policy(maximum=1, cooldown=0)
        result = process_incident(
            incident_id,
            db_path=self.database,
            request_function=self.request_with_statuses([503]),
            process_provider=EmptyProcessProvider(),
        )
        self.assertEqual(result["decision"], "ESCALATED")
        self.assertEqual(
            len(get_recovery_history(incident_id=incident_id, db_path=self.database)),
            1,
        )

    def test_failed_restart_verification_does_not_repeat_restart_loop(self):
        incident_id = self.create_incident()
        self.configure_policy(
            actions=(RECOVERY_ACTION_RESTART,),
            approval="none",
            maximum=1,
            verification_timeout=0.1,
        )
        with closing(connect(self.database)) as connection, connection:
            connection.execute(
                "UPDATE incidents SET occurrence_count = 2 WHERE incident_id = ?",
                (incident_id,),
            )
        restart = Mock(return_value=9876)
        process_verification = Mock(return_value=SimpleNamespace(pid=9876))
        request = self.request_with_statuses([503, 503, 503, 503])
        with patch(
            "app.recovery_framework.restart_registered_application",
            restart,
        ), patch(
            "app.recovery_framework.verify_registered_application_process",
            process_verification,
        ), patch(
            "app.recovery_framework.stop_registered_application",
            return_value=True,
        ):
            first = process_incident(
                incident_id,
                db_path=self.database,
                request_function=request,
                process_provider=FakeOwnedProcessProvider(),
            )
            second = process_incident(
                incident_id,
                db_path=self.database,
                request_function=request,
                process_provider=FakeOwnedProcessProvider(),
            )

        self.assertEqual(first["decision"], "ESCALATED")
        self.assertEqual(second["decision"], "ESCALATED")
        self.assertEqual(restart.call_count, 1)
        self.assertEqual(
            get_recovery_history(incident_id=incident_id, db_path=self.database)[0][
                "result"
            ],
            "Verification failed",
        )

    def test_process_identity_requires_registered_name_executable_directory_and_pid(self):
        executable = Path(sys.executable).resolve()
        working_directory = Path(__file__).resolve().parents[1]
        expected = SimpleNamespace(
            pid=7412,
            info={
                "name": executable.name,
                "exe": str(executable),
                "cwd": str(working_directory),
            },
        )
        provider = SimpleNamespace(process_iter=Mock(return_value=[expected]))
        application = {
            **self.application,
            "process_name": executable.name,
            "process_executable_path": str(executable),
            "process_working_directory": str(working_directory),
        }

        process = verify_registered_application_process(
            application,
            expected_pid=7412,
            process_provider=provider,
        )
        self.assertIs(process, expected)
        with self.assertRaisesRegex(RuntimeError, "PID differs"):
            verify_registered_application_process(
                application,
                expected_pid=7413,
                process_provider=provider,
            )

    def test_restart_invokes_only_registered_executable_without_a_shell(self):
        started_process = SimpleNamespace(pid=8877, poll=lambda: None)
        popen = Mock(return_value=started_process)

        process_id = restart_registered_application(
            self.application,
            process_provider=EmptyProcessProvider(),
            popen_function=popen,
        )

        self.assertEqual(process_id, 8877)
        args, kwargs = popen.call_args
        self.assertEqual(args[0], [sys.executable])
        self.assertEqual(
            kwargs["cwd"],
            self.application["process_working_directory"],
        )
        self.assertFalse(kwargs["shell"])

    def test_recovery_schema_migration_preserves_existing_history(self):
        legacy_database = Path(self.temporary_directory.name) / "legacy.sqlite3"
        with closing(sqlite3.connect(legacy_database)) as connection:
            connection.executescript(
                """
                CREATE TABLE recovery_attempts (
                    recovery_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    application_id TEXT NOT NULL,
                    incident_id TEXT,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    verification TEXT NOT NULL DEFAULT '',
                    details TEXT NOT NULL DEFAULT '',
                    attempted_at TEXT NOT NULL,
                    completed_at TEXT
                );
                CREATE TABLE approval_requests (
                    approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    application_id TEXT NOT NULL,
                    incident_id TEXT,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'Pending',
                    requested_by TEXT,
                    requested_at TEXT NOT NULL,
                    decided_at TEXT,
                    expires_at TEXT,
                    details TEXT NOT NULL DEFAULT ''
                );
                INSERT INTO recovery_attempts (
                    application_id, incident_id, action, result, verification,
                    details, attempted_at, completed_at
                ) VALUES (
                    'APP-LEGACY', 'INC-LEGACY', 'Retry request', 'Retry verified',
                    'HTTP 200', 'legacy attempt', '2026-01-01T00:00:00+00:00',
                    '2026-01-01T00:00:01+00:00'
                );
                INSERT INTO approval_requests (
                    application_id, incident_id, action, status, requested_by,
                    requested_at, decided_at, expires_at, details
                ) VALUES (
                    'APP-LEGACY', 'INC-LEGACY', 'Restart', 'Approved', 'operator',
                    '2026-01-01T00:00:00+00:00',
                    '2026-01-01T00:00:01+00:00',
                    '2026-01-01T00:05:00+00:00', 'legacy approval'
                );
                """
            )
            connection.commit()

        initialize_database(legacy_database)
        with closing(connect(legacy_database)) as connection:
            attempt = connection.execute(
                "SELECT * FROM recovery_attempts"
            ).fetchone()
            approval = connection.execute(
                "SELECT * FROM approval_requests"
            ).fetchone()
            attempt_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(recovery_attempts)"
                )
            }
            approval_columns = {
                row["name"]
                for row in connection.execute(
                    "PRAGMA table_info(approval_requests)"
                )
            }

        self.assertEqual(attempt["details"], "legacy attempt")
        self.assertEqual(attempt["retry_count"], 0)
        self.assertEqual(approval["details"], "legacy approval")
        self.assertEqual(approval["decided_by"], None)
        self.assertIn("approval_id", attempt_columns)
        self.assertIn("decision_details", approval_columns)

    def test_recovery_failure_for_one_application_does_not_stop_another(self):
        second = self.register_owned_application("Second local app")
        monitor = MultiApplicationMonitor(db_path=self.database)
        monitor.engine.collect_reading = Mock()
        anomaly = {"timestamp": datetime.now(timezone.utc).isoformat()}

        class OneCycleEvent:
            def __init__(self):
                self.cycles = 0

            def is_set(self):
                return self.cycles > 0

            def wait(self, _interval):
                self.cycles += 1
                return True

        with patch(
            "ml.detect_anomalies.analyze_application",
            return_value={"anomalies": [anomaly]},
        ), patch(
            "ml.application_root_cause.generate_application_rca",
            return_value={"report_id": 1},
        ), patch(
            "app.incident_management.process_application_anomaly",
            side_effect=["INC-A", "INC-B"],
        ), patch(
            "app.recovery_framework.process_incident",
            side_effect=[RuntimeError("controlled recovery failure"), {"decision": "NO_ACTION"}],
        ) as process_recovery:
            monitor._run_application(
                self.application_id,
                OneCycleEvent(),
            )
            monitor._run_application(
                second["application_id"],
                OneCycleEvent(),
            )

        self.assertEqual(process_recovery.call_count, 2)
        self.assertEqual(monitor.engine.collect_reading.call_count, 2)


if __name__ == "__main__":
    unittest.main()
