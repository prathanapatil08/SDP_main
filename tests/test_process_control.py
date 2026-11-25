import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from app import process_control


class ProjectFlaskProcessTests(unittest.TestCase):
    def setUp(self):
        self.process = MagicMock()
        self.process.pid = 1234
        self.process.info = {"name": "python.exe"}
        self.process.cmdline.return_value = [str(process_control.MAIN_FILE)]
        self.process.cwd.return_value = str(process_control.BASE_DIR)
        self.process.net_connections.return_value = [
            SimpleNamespace(
                laddr=SimpleNamespace(port=5000),
                status=process_control.psutil.CONN_LISTEN,
            )
        ]

    def test_uses_metrics_pid_to_find_project_flask_without_global_port_scan(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = (
            b'{"application_process_pid": 1234}'
        )

        with patch.object(process_control, "urlopen", return_value=response):
            with patch.object(
                process_control.psutil, "Process", return_value=self.process
            ):
                with patch.object(
                    process_control.psutil, "process_iter"
                ) as process_iter:
                    processes = process_control.project_flask_processes()

        self.assertEqual(processes, [self.process])
        process_iter.assert_not_called()

    def test_falls_back_to_matching_project_process_when_metrics_are_unavailable(self):
        with patch.object(
            process_control, "urlopen", side_effect=URLError("server stopped")
        ):
            with patch.object(
                process_control.psutil,
                "process_iter",
                return_value=[self.process],
            ):
                processes = process_control.project_flask_processes()

        self.assertEqual(processes, [self.process])

    def test_refuses_to_stop_pid_reported_for_a_different_application(self):
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = (
            b'{"application_process_pid": 1234}'
        )
        self.process.cmdline.return_value = [r"D:\other\main.py"]

        with patch.object(process_control, "urlopen", return_value=response):
            with patch.object(
                process_control.psutil, "Process", return_value=self.process
            ):
                with patch.object(
                    process_control.psutil, "process_iter"
                ) as process_iter:
                    with self.assertRaises(RuntimeError):
                        process_control.project_flask_processes()

        process_iter.assert_not_called()

    def test_stop_reports_success_when_verified_process_terminates(self):
        with patch.object(
            process_control, "project_flask_processes", return_value=[self.process]
        ):
            with patch.object(
                process_control.psutil, "wait_procs", return_value=([], [])
            ):
                stopped = process_control.stop_project_flask()

        self.assertTrue(stopped)
        self.process.terminate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
