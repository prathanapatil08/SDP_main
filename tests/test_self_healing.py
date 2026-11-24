import contextlib
import io
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import call, patch

from app import self_healing


class RecoveryPolicyTests(unittest.TestCase):
    def setUp(self):
        self.metrics = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_usage": "25",
            "memory_usage": "92",
            "disk_usage": "50",
            "response_time_ms": "100",
            "api_error_rate": "0",
        }

    @patch.object(self_healing, "write_log")
    @patch.object(self_healing, "top_memory_consumers", return_value=[])
    @patch.object(self_healing, "metrics_age_seconds", return_value=0)
    @patch.object(self_healing, "read_matching_incident", return_value=None)
    @patch.object(self_healing, "read_latest_metrics")
    @patch.object(self_healing, "retry_check", return_value=True)
    @patch.object(self_healing, "restart_flask")
    def test_high_memory_restart_is_withheld_without_approval(
        self,
        restart_flask,
        retry_check,
        read_latest_metrics,
        read_matching_incident,
        metrics_age_seconds,
        top_memory_consumers,
        write_log,
    ):
        read_latest_metrics.return_value = (self.metrics, set())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self_healing.run_policy()

        self.assertTrue(result)
        self.assertIn("Recovery result: APPROVAL_REQUIRED", output.getvalue())
        restart_flask.assert_not_called()
        retry_check.assert_called_once()
        read_matching_incident.assert_called_once()
        metrics_age_seconds.assert_called_once()
        top_memory_consumers.assert_called_once()
        write_log.assert_called_once()

    @patch.object(self_healing, "write_log")
    @patch.object(self_healing, "restart_flask")
    @patch.object(self_healing, "retry_check", side_effect=[True, True])
    @patch.object(self_healing, "read_matching_incident", return_value=None)
    @patch.object(self_healing, "read_latest_metrics")
    @patch.object(self_healing, "metrics_age_seconds", return_value=0)
    @patch.object(self_healing.psutil, "virtual_memory")
    def test_approved_high_memory_restart_is_revalidated(
        self,
        virtual_memory,
        metrics_age_seconds,
        read_latest_metrics,
        read_matching_incident,
        retry_check,
        restart_flask,
        write_log,
    ):
        read_latest_metrics.return_value = (self.metrics, set())
        virtual_memory.return_value.percent = 92
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self_healing.run_policy(
                approve_high_memory_restart=True,
                approved_source_timestamp=self.metrics["timestamp"],
            )

        self.assertTrue(result)
        self.assertIn("Recovery result: RECOVERED", output.getvalue())
        metrics_age_seconds.assert_has_calls(
            [
                call(self.metrics),
                call({"timestamp": self.metrics["timestamp"]}),
            ]
        )
        read_matching_incident.assert_called_once()
        retry_check.assert_has_calls(
            [
                call(self_healing.check_application),
                call(
                    self_healing.check_application,
                    attempts=2,
                ),
            ]
        )
        restart_flask.assert_called_once()
        write_log.assert_called_once()

    @patch.object(self_healing, "write_log")
    @patch.object(self_healing, "restart_flask")
    @patch.object(self_healing, "retry_check", return_value=True)
    @patch.object(self_healing, "read_matching_incident", return_value=None)
    @patch.object(self_healing, "read_latest_metrics")
    @patch.object(self_healing, "metrics_age_seconds", side_effect=[0, 31])
    def test_expired_high_memory_approval_is_rejected(
        self,
        metrics_age_seconds,
        read_latest_metrics,
        read_matching_incident,
        retry_check,
        restart_flask,
        write_log,
    ):
        read_latest_metrics.return_value = (self.metrics, set())
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self_healing.run_policy(
                approve_high_memory_restart=True,
                approved_source_timestamp=self.metrics["timestamp"],
            )

        self.assertTrue(result)
        self.assertIn("Recovery result: NO_ACTION", output.getvalue())
        metrics_age_seconds.assert_has_calls(
            [
                call(self.metrics),
                call({"timestamp": self.metrics["timestamp"]}),
            ]
        )
        read_matching_incident.assert_called_once()
        retry_check.assert_called_once()
        restart_flask.assert_not_called()
        write_log.assert_called_once()

    @patch.object(self_healing, "write_log")
    @patch.object(self_healing, "restart_flask")
    @patch.object(self_healing, "retry_check", return_value=True)
    @patch.object(self_healing, "read_matching_incident", return_value=None)
    @patch.object(self_healing, "read_latest_metrics")
    @patch.object(self_healing, "metrics_age_seconds", return_value=0)
    @patch.object(self_healing.psutil, "virtual_memory")
    def test_approval_for_different_incident_is_rejected(
        self,
        virtual_memory,
        metrics_age_seconds,
        read_latest_metrics,
        read_matching_incident,
        retry_check,
        restart_flask,
        write_log,
    ):
        read_latest_metrics.return_value = (self.metrics, set())
        virtual_memory.return_value.percent = 92
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self_healing.run_policy(
                approve_high_memory_restart=True,
                approved_source_timestamp="2026-11-21 09:59:30",
            )

        self.assertTrue(result)
        self.assertIn("Recovery result: NO_ACTION", output.getvalue())
        self.assertIn("source incident changed", output.getvalue())
        restart_flask.assert_not_called()
        write_log.assert_called_once()

    @patch.object(self_healing, "write_log")
    @patch.object(
        self_healing,
        "retry_check",
        side_effect=[False, False, False],
    )
    @patch.object(
        self_healing,
        "restart_flask",
        side_effect=RuntimeError("test restart failure"),
    )
    @patch.object(self_healing, "read_latest_metrics", return_value=(None, set()))
    def test_failed_crash_recovery_is_escalated(
        self,
        read_latest_metrics,
        restart_flask,
        retry_check,
        write_log,
    ):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = self_healing.run_policy()

        self.assertFalse(result)
        self.assertIn("Recovery result: ESCALATED", output.getvalue())
        read_latest_metrics.assert_called_once()
        restart_flask.assert_called_once()
        retry_check.assert_called_once()
        write_log.assert_called_once()
        self.assertIn("test restart failure", write_log.call_args.args[-1])


class AutomaticRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.metrics = {
            "cpu_usage": "25",
            "memory_usage": "50",
            "disk_usage": "50",
            "response_time_ms": "100",
            "api_error_rate": "0",
        }
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary_directory.cleanup)
        self.lock_file = Path(self.temporary_directory.name) / "recovery.lock"

    @patch.object(self_healing, "run_policy_safely", return_value=True)
    def test_unreachable_application_triggers_automatic_policy(self, run_policy):
        with patch.object(self_healing, "AUTOMATIC_RECOVERY_LOCK_FILE", self.lock_file):
            result = self_healing.run_automatic_policy_if_needed(
                "Unreachable",
                self.metrics,
                now=100,
            )

        self.assertTrue(result)
        run_policy.assert_called_once_with()

    @patch.object(self_healing, "run_policy_safely", return_value=True)
    def test_threshold_signal_is_rate_limited_across_calls(self, run_policy):
        metrics = dict(self.metrics, memory_usage="92.3")
        with patch.object(self_healing, "AUTOMATIC_RECOVERY_LOCK_FILE", self.lock_file):
            first_result = self_healing.run_automatic_policy_if_needed(
                "Healthy",
                metrics,
                now=100,
            )
            second_result = self_healing.run_automatic_policy_if_needed(
                "Healthy",
                metrics,
                now=110,
            )

        self.assertTrue(first_result)
        self.assertIsNone(second_result)
        run_policy.assert_called_once_with()

    @patch.object(self_healing, "run_policy_safely", return_value=True)
    def test_cleared_signal_allows_a_new_incident_immediately(self, run_policy):
        high_memory_metrics = dict(self.metrics, memory_usage="92.3")
        with patch.object(self_healing, "AUTOMATIC_RECOVERY_LOCK_FILE", self.lock_file):
            self_healing.run_automatic_policy_if_needed(
                "Healthy",
                high_memory_metrics,
                now=100,
            )
            cleared_result = self_healing.run_automatic_policy_if_needed(
                "Healthy",
                self.metrics,
                now=101,
            )
            new_incident_result = self_healing.run_automatic_policy_if_needed(
                "Healthy",
                high_memory_metrics,
                now=102,
            )

        self.assertIsNone(cleared_result)
        self.assertTrue(new_incident_result)
        self.assertEqual(run_policy.call_count, 2)


if __name__ == "__main__":
    unittest.main()
