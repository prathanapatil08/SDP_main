import unittest

from app.health_policy import resource_severity


class ResourceSeverityTests(unittest.TestCase):
    def test_normal_through_91_percent(self):
        self.assertEqual(resource_severity(91), "Normal")

    def test_warning_above_91_through_94_percent(self):
        self.assertEqual(resource_severity(91.1), "Warning")
        self.assertEqual(resource_severity(92), "Warning")
        self.assertEqual(resource_severity(94), "Warning")
        self.assertEqual(resource_severity(94.9), "Warning")

    def test_critical_at_95_percent(self):
        self.assertEqual(resource_severity(95), "Critical")

    def test_invalid_readings_are_unknown(self):
        self.assertEqual(resource_severity(None), "Unknown")
        self.assertEqual(resource_severity(float("nan")), "Unknown")


if __name__ == "__main__":
    unittest.main()
