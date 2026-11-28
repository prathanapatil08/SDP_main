import unittest
from types import SimpleNamespace

from app.browser_process_metrics import sample_chrome_process_metrics


class FakeChromeProcess:
    def __init__(self, pid, username, memory_mib, cpu_samples):
        self.pid = pid
        self.info = {"name": "chrome.exe", "username": username}
        self.memory_mib = memory_mib
        self.cpu_samples = iter(cpu_samples)

    def create_time(self):
        return 100.0

    def cpu_times(self):
        return next(self.cpu_samples)

    def memory_info(self):
        return SimpleNamespace(rss=self.memory_mib * 1024 * 1024)


class FakeProcessProvider:
    def __init__(self, processes):
        self.processes = processes

    def process_iter(self, attrs):
        return iter(self.processes)

    def cpu_count(self, logical=True):
        return 4

    def virtual_memory(self):
        return SimpleNamespace(total=8 * 1024 * 1024 * 1024)


class BrowserProcessMetricsTests(unittest.TestCase):
    def test_aggregates_only_current_users_chrome_processes(self):
        processes = [
            FakeChromeProcess(
                1,
                "DESKTOP\\Admin",
                256,
                [
                    SimpleNamespace(user=1.0, system=0.25),
                    SimpleNamespace(user=1.4, system=0.35),
                ],
            ),
            FakeChromeProcess(
                2,
                "Admin",
                128,
                [
                    SimpleNamespace(user=2.0, system=0.5),
                    SimpleNamespace(user=2.1, system=0.55),
                ],
            ),
            FakeChromeProcess(
                3,
                "OtherUser",
                2048,
                [
                    SimpleNamespace(user=5.0, system=1.0),
                    SimpleNamespace(user=6.0, system=1.0),
                ],
            ),
        ]
        ticks = iter((10.0, 10.25))
        slept = []

        result = sample_chrome_process_metrics(
            process_provider=FakeProcessProvider(processes),
            current_user="Admin",
            sleep=slept.append,
            clock=lambda: next(ticks),
        )

        self.assertAlmostEqual(result["cpu_percent"], 65.0)
        self.assertAlmostEqual(result["memory_mib"], 384.0)
        self.assertAlmostEqual(result["memory_percent"], 4.6875)
        self.assertEqual(result["process_count"], 2)
        self.assertIsNone(result["error"])
        self.assertIsNone(result["warning"])
        self.assertEqual(slept, [0.25])

    def test_reports_when_no_current_user_chrome_process_exists(self):
        result = sample_chrome_process_metrics(
            process_provider=FakeProcessProvider([]),
            current_user="Admin",
            sleep=lambda _: self.fail("No sampling is needed without processes."),
        )

        self.assertIsNone(result["cpu_percent"])
        self.assertIsNone(result["memory_mib"])
        self.assertEqual(result["process_count"], 0)
        self.assertIn("No Chrome processes", result["error"])

    def test_rejects_nonpositive_sample_interval(self):
        with self.assertRaises(ValueError):
            sample_chrome_process_metrics(sample_interval=0)


if __name__ == "__main__":
    unittest.main()
