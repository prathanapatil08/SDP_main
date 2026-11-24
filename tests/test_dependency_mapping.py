import unittest

from app.dependency_mapping import (
    SERVICE_DEPENDENCIES,
    correlate_component_events,
    dependency_rows,
)


class DependencyMappingTests(unittest.TestCase):
    def test_upstream_host_pressure_correlates_with_dependent_api_failure(self):
        correlations = correlate_component_events(
            [
                {
                    "component": "host_resources",
                    "status": "critical",
                    "summary": "CPU 98%, memory 97%",
                },
                {
                    "component": "flask_api",
                    "status": "unavailable",
                    "summary": "Health endpoint failed.",
                },
            ]
        )

        self.assertEqual(len(correlations), 1)
        self.assertEqual(correlations[0]["root_component"], "host_resources")
        self.assertEqual(
            correlations[0]["affected_components"],
            ["flask_api"],
        )
        self.assertEqual(correlations[0]["confidence"], "possible")

    def test_unrelated_component_failures_are_not_correlated(self):
        correlations = correlate_component_events(
            [
                {
                    "component": "flask_api",
                    "status": "unavailable",
                    "summary": "Health endpoint failed.",
                },
                {
                    "component": "incident_ledger",
                    "status": "unavailable",
                    "summary": "SQLite query failed.",
                },
            ]
        )

        self.assertEqual(correlations, [])

    def test_incident_ledger_failure_is_correlated_with_its_controls(self):
        correlations = correlate_component_events(
            [
                {
                    "component": "incident_ledger",
                    "status": "unavailable",
                    "summary": "SQLite query failed.",
                },
                {
                    "component": "incident_management_ui",
                    "status": "degraded",
                    "summary": "Incident controls are unavailable.",
                },
            ]
        )

        self.assertEqual(len(correlations), 1)
        self.assertEqual(
            correlations[0]["root_component"],
            "incident_ledger",
        )
        self.assertIn(
            "incident_management_ui",
            correlations[0]["affected_components"],
        )

    def test_dependency_map_exposes_only_declared_project_components(self):
        rows = dependency_rows({"flask_api": "Unavailable"})
        row_by_component = {row["Component"]: row for row in rows}

        self.assertIn("Flask API", row_by_component)
        self.assertEqual(
            row_by_component["Flask API"]["Depends on"],
            "Host resources",
        )
        self.assertIn("Incident ledger (SQLite)", row_by_component)
        self.assertNotIn("Database service", SERVICE_DEPENDENCIES)


if __name__ == "__main__":
    unittest.main()
