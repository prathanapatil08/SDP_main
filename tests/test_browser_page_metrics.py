import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from app.browser_discovery import (
    configure_discovery,
    discover_website,
    generate_pairing_code,
    pair_extension,
)
from app.database import connect, initialize_database
from app.main import app as flask_app
from app.multi_app_monitor import store_application_telemetry
from app.recovery_framework import _recent_telemetry
from dashboard.ops_dashboard import _browser_page_metric_rows, _latest_readings
from ml.application_root_cause import _load_application_evidence
from ml.detect_anomalies import ApplicationAnomalyDetector


EXTENSION_ORIGIN = "chrome-extension://" + "a" * 32


def _measurement(origin, hostname, **overrides):
    payload = {
        "origin": origin,
        "page_url": origin,
        "hostname": hostname,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "measurement_interval_seconds": 30,
        "javascript_heap_used_bytes": 64 * 1024 * 1024,
        "javascript_heap_available": True,
        "long_task_count": 2,
        "total_long_task_duration_ms": 80.5,
        "long_tasks_available": True,
    }
    payload.update(overrides)
    return payload


class BrowserPageMetricsTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "metrics.sqlite3"
        initialize_database(self.database)
        self.previous_database_path = flask_app.config.get("SDP_DATABASE_PATH")
        flask_app.config["SDP_DATABASE_PATH"] = self.database
        self.client = flask_app.test_client()
        configure_discovery(
            mode="enabled",
            automatic_registration=True,
            automatic_monitoring=True,
            db_path=self.database,
        )
        self.token = pair_extension(
            generate_pairing_code(self.database),
            EXTENSION_ORIGIN,
            db_path=self.database,
        )
        from app import browser_discovery

        with browser_discovery._rate_lock:
            browser_discovery._rate_hits.clear()

    def tearDown(self):
        if self.previous_database_path is None:
            flask_app.config.pop("SDP_DATABASE_PATH", None)
        else:
            flask_app.config["SDP_DATABASE_PATH"] = self.previous_database_path
        self.temporary_directory.cleanup()

    def post_metrics(self, payload):
        return self.client.post(
            "/api/discovery/page-metrics",
            json=payload,
            headers={
                "Origin": EXTENSION_ORIGIN,
                "Authorization": f"Bearer {self.token}",
            },
        )

    def test_api_accepts_multiple_sites_and_associates_each_application(self):
        for origin, hostname in (
            ("https://alpha.example.test", "alpha.example.test"),
            ("https://beta.example.test", "beta.example.test"),
        ):
            discover_website(origin, db_path=self.database)
            response = self.post_metrics(_measurement(origin, hostname))
            self.assertEqual(response.status_code, 200, response.json)
            self.assertEqual(response.json["origin"], origin)
            self.assertTrue(response.json["application_id"])

        with closing(connect(self.database)) as connection:
            rows = connection.execute(
                """
                SELECT a.url, t.application_id, t.source, t.data_json
                FROM application_telemetry AS t
                JOIN applications AS a ON a.application_id = t.application_id
                WHERE t.source = 'browser_page_metrics'
                ORDER BY a.url
                """
            ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(
            {row["url"] for row in rows},
            {"https://alpha.example.test", "https://beta.example.test"},
        )
        self.assertTrue(all(row["application_id"] for row in rows))

    def test_unsupported_apis_are_saved_as_unavailable_not_zero(self):
        origin = "https://unsupported.example.test"
        discover_website(origin, db_path=self.database)
        payload = _measurement(
            origin,
            "unsupported.example.test",
            javascript_heap_used_bytes=None,
            javascript_heap_available=False,
            long_task_count=None,
            total_long_task_duration_ms=None,
            long_tasks_available=False,
        )
        response = self.post_metrics(payload)
        self.assertEqual(response.status_code, 200, response.json)

        row = _browser_page_metric_rows({
            "applications": [],
            "telemetry": [{
                "application_id": response.json["application_id"],
                "source": "browser_page_metrics",
                "timestamp": response.json["timestamp"],
                "data": payload,
            }],
        })[0]
        self.assertEqual(row["JavaScript heap usage"], "Unavailable")
        self.assertEqual(row["Long-task count"], "Unavailable")
        self.assertEqual(row["Total long-task duration"], "Unavailable")
        self.assertIn("heap: Unavailable", row["Measurement availability"])

    def test_partial_api_support_preserves_available_metric(self):
        origin = "https://partial.example.test"
        discover_website(origin, db_path=self.database)
        payload = _measurement(
            origin,
            "partial.example.test",
            javascript_heap_used_bytes=None,
            javascript_heap_available=False,
        )
        response = self.post_metrics(payload)
        self.assertEqual(response.status_code, 200, response.json)
        row = _browser_page_metric_rows({
            "applications": [],
            "telemetry": [{
                "application_id": response.json["application_id"],
                "source": "browser_page_metrics",
                "timestamp": response.json["timestamp"],
                "data": payload,
            }],
        })[0]
        self.assertEqual(row["JavaScript heap usage"], "Unavailable")
        self.assertEqual(row["Long-task count"], "2")
        self.assertIn("long tasks: Available", row["Measurement availability"])

    def test_invalid_or_missing_metrics_are_rejected(self):
        origin = "https://invalid.example.test"
        discover_website(origin, db_path=self.database)
        invalid_payloads = (
            {**_measurement(origin, "invalid.example.test"), "long_task_count": -1},
            {**_measurement(origin, "invalid.example.test"), "javascript_heap_used_bytes": float("nan")},
            {
                key: value
                for key, value in _measurement(origin, "invalid.example.test").items()
                if key != "long_task_count"
            },
            {**_measurement(origin, "other.example.test")},
            {**_measurement(origin, "invalid.example.test", page_url=origin + "/private")},
            {**_measurement(origin, "invalid.example.test", timestamp="not-a-time")},
            {**_measurement(origin, "invalid.example.test", measurement_interval_seconds=0)},
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                response = self.post_metrics(payload)
                self.assertEqual(response.status_code, 400)

    def test_page_metrics_route_requires_extension_authentication(self):
        origin = "https://auth.example.test"
        discover_website(origin, db_path=self.database)
        response = self.client.post(
            "/api/discovery/page-metrics",
            json=_measurement(origin, "auth.example.test"),
            headers={"Origin": EXTENSION_ORIGIN},
        )
        self.assertEqual(response.status_code, 401)

    def test_pending_site_cannot_submit_telemetry(self):
        configure_discovery(
            automatic_registration=False,
            automatic_monitoring=False,
            db_path=self.database,
        )
        origin = "https://pending.example.test"
        discover_website(origin, db_path=self.database)
        response = self.post_metrics(_measurement(origin, "pending.example.test"))
        self.assertEqual(response.status_code, 400)

    def test_dashboard_rows_filter_by_website_and_show_available_values(self):
        snapshot = {
            "applications": [],
            "telemetry": [
                {
                    "application_id": "alpha",
                    "source": "browser_page_metrics",
                    "timestamp": "2026-11-28T10:00:00+00:00",
                    "data": _measurement(
                        "https://alpha.example.test",
                        "alpha.example.test",
                    ),
                },
                {
                    "application_id": "beta",
                    "source": "browser_page_metrics",
                    "timestamp": "2026-11-28T10:01:00+00:00",
                    "data": _measurement(
                        "https://beta.example.test",
                        "beta.example.test",
                    ),
                },
            ],
        }
        all_rows = _browser_page_metric_rows(snapshot)
        self.assertEqual(len(all_rows), 2)
        self.assertEqual(all_rows[0]["Website hostname"], "beta.example.test")
        self.assertEqual(
            all_rows[0]["JavaScript heap usage"],
            "64.0 MiB",
        )
        self.assertEqual(all_rows[0]["Long-task count"], "2")
        self.assertIn("80.5 ms", all_rows[0]["Total long-task duration"])

        alpha_rows = _browser_page_metric_rows(
            snapshot,
            "https://alpha.example.test",
        )
        self.assertEqual(len(alpha_rows), 1)
        self.assertEqual(alpha_rows[0]["Website hostname"], "alpha.example.test")

    def test_page_readings_do_not_replace_health_or_model_telemetry(self):
        origin = "https://pipeline.example.test"
        application = discover_website(origin, db_path=self.database)
        page_timestamp = datetime.now(timezone.utc)
        health_timestamp = (
            page_timestamp.replace(microsecond=0).isoformat()
        )
        health_reading = {
            "application_id": application["application_id"],
            "timestamp": health_timestamp,
            "request_success": True,
            "response_time_ms": 42.0,
            "cpu_usage": None,
            "memory_usage": None,
        }
        store_application_telemetry(
            health_reading,
            db_path=self.database,
            source="multi_app_monitor",
        )
        page_payload = _measurement(
            origin,
            "pipeline.example.test",
            timestamp=page_timestamp.isoformat(),
        )
        response = self.post_metrics(page_payload)
        self.assertEqual(response.status_code, 200, response.json)

        detector = ApplicationAnomalyDetector(db_path=self.database)
        anomaly_rows, _ = detector._load_telemetry(application["application_id"])
        rca_rows, _, _ = _load_application_evidence(
            application["application_id"],
            None,
            self.database,
        )
        recovery_rows = _recent_telemetry(
            application["application_id"],
            self.database,
            limit=1,
        )
        self.assertEqual([row["timestamp"] for row in anomaly_rows], [health_timestamp])
        self.assertEqual(
            [row["timestamp"] for row in rca_rows],
            [health_timestamp],
        )
        self.assertEqual(recovery_rows[0]["timestamp"], health_timestamp)

        dashboard_snapshot = {
            "applications": [],
            "telemetry": [
                {
                    "application_id": application["application_id"],
                    "source": "browser_page_metrics",
                    "timestamp": page_payload["timestamp"],
                    "data": page_payload,
                },
                {
                    "application_id": application["application_id"],
                    "source": "multi_app_monitor",
                    "timestamp": health_timestamp,
                    "data": health_reading,
                },
            ],
        }
        self.assertEqual(
            _latest_readings(dashboard_snapshot)[
                application["application_id"]
            ]["source"],
            "multi_app_monitor",
        )


if __name__ == "__main__":
    unittest.main()
