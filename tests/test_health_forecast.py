import unittest
from datetime import datetime, timedelta

from app.health_forecast import forecast_threshold_crossings


class HealthForecastTests(unittest.TestCase):
    def readings(self, memory_values):
        start = datetime.now().astimezone()
        rows = []
        for index, memory in enumerate(memory_values):
            rows.append(
                {
                    "timestamp": (start + timedelta(seconds=index * 20)).isoformat(),
                    "cpu_usage": 20,
                    "memory_usage": memory,
                    "disk_usage": 40,
                    "response_time_ms": 100,
                    "api_error_rate": 0,
                }
            )
        return rows

    def test_rising_memory_warns_when_threshold_is_projected_within_horizon(self):
        result = forecast_threshold_crossings(
            self.readings([60, 62, 64, 66, 68, 70, 72, 74, 76, 78])
        )

        self.assertEqual(
            [warning["metric"] for warning in result["warnings"]],
            ["memory_usage"],
        )
        self.assertGreater(result["warnings"][0]["minutes_to_threshold"], 0)
        self.assertLessEqual(result["warnings"][0]["minutes_to_threshold"], 30)

    def test_stable_and_falling_metrics_do_not_raise_forecasts(self):
        result = forecast_threshold_crossings(
            self.readings([80, 78, 76, 74, 72, 70, 68, 66])
        )

        self.assertEqual(result["warnings"], [])

    def test_insufficient_history_does_not_claim_a_forecast(self):
        result = forecast_threshold_crossings(self.readings([60, 65, 70, 75, 80]))

        self.assertEqual(result["warnings"], [])
        self.assertIn("Memory utilization", result["insufficient_metrics"])

    def test_already_exceeded_threshold_is_left_to_threshold_alerts(self):
        result = forecast_threshold_crossings(
            self.readings([80, 82, 84, 86, 88, 90, 92, 94])
        )

        self.assertEqual(result["warnings"], [])
        self.assertIn("Memory utilization", result["eligible_metrics"])


if __name__ == "__main__":
    unittest.main()
