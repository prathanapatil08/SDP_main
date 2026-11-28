import json
import tempfile
import time
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import Mock, patch

from app.application_registry import get_application, register_application
from app.browser_discovery import (
    DiscoveryDisabledError,
    _safe_public_target,
    approve_discovery,
    configure_discovery,
    discover_website,
    exclude_discovery,
    generate_pairing_code,
    get_discovery_history,
    get_discovery_settings,
    ignore_discovery,
    list_discovered_applications,
    list_open_tabs,
    normalize_origin,
    pair_extension,
    restore_discovery,
)
from app.database import connect, initialize_database
from app.main import app as flask_app
from app.multi_app_monitor import MultiApplicationMonitor


EXTENSION_ORIGIN = "chrome-extension://" + "a" * 32


class FakeResponse:
    def __init__(self, status=200):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


class BrowserDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "discovery.sqlite3"
        initialize_database(self.database)
        self.previous_database_path = flask_app.config.get("SDP_DATABASE_PATH")
        flask_app.config["SDP_DATABASE_PATH"] = self.database
        self.client = flask_app.test_client()
        from app import browser_discovery

        with browser_discovery._rate_lock:
            browser_discovery._rate_hits.clear()

    def tearDown(self):
        if self.previous_database_path is None:
            flask_app.config.pop("SDP_DATABASE_PATH", None)
        else:
            flask_app.config["SDP_DATABASE_PATH"] = self.previous_database_path
        self.temporary_directory.cleanup()

    def enable_discovery(self, **settings):
        return configure_discovery(
            mode="enabled",
            db_path=self.database,
            **settings,
        )

    def pair(self):
        code = generate_pairing_code(self.database)
        token = pair_extension(code, EXTENSION_ORIGIN, db_path=self.database)
        return token

    def authorized_post(self, path, token, body):
        return self.client.post(
            path,
            json=body,
            headers={
                "Origin": EXTENSION_ORIGIN,
                "Authorization": f"Bearer {token}",
            },
        )

    def test_origin_normalization_strips_default_port_and_rejects_url_details(self):
        origin, hostname = normalize_origin("HTTPS://WWW.Example.com:443/")
        self.assertEqual(origin, "https://www.example.com")
        self.assertEqual(hostname, "www.example.com")

        for value in (
            "https://example.com/products?item=1",
            "https://user:password@example.com",
            "file:///C:/private.txt",
            "http://127.0.0.1",
            "http://[::1]",
            "http://localhost",
            "https://example.com#fragment",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_origin(value)

    def test_discovery_requires_enabled_mode_and_stores_only_origin(self):
        with self.assertRaises(DiscoveryDisabledError):
            discover_website(
                "https://www.example.test/",
                db_path=self.database,
            )

        self.enable_discovery()
        result = discover_website(
            "https://www.example.test/",
            db_path=self.database,
        )
        self.assertEqual(result["origin"], "https://www.example.test")
        self.assertEqual(result["registration_status"], "pending_approval")
        rows = list_discovered_applications(db_path=self.database)
        self.assertEqual(len(rows), 1)
        self.assertNotIn("account", json.dumps(rows))
        self.assertNotIn("private", json.dumps(get_discovery_history(db_path=self.database)))

    def test_duplicate_visits_reuse_discovery_and_do_not_duplicate_history(self):
        self.enable_discovery()
        first = discover_website("https://example.test/", db_path=self.database)
        second = discover_website("https://EXAMPLE.test:443/", db_path=self.database)
        self.assertEqual(first["origin"], second["origin"])
        self.assertEqual(len(list_discovered_applications(db_path=self.database)), 1)
        events = get_discovery_history(db_path=self.database)
        self.assertEqual(sum(event["event_type"] == "discovered" for event in events), 1)

    def test_automatic_registration_reuses_registry_and_disables_privileged_actions(self):
        self.enable_discovery(
            automatic_registration=True,
            automatic_monitoring=False,
        )
        first = discover_website("https://shop.example.test/", db_path=self.database)
        second = discover_website("https://shop.example.test/", db_path=self.database)
        self.assertEqual(first["application_id"], second["application_id"])
        application = get_application(first["application_id"], self.database)
        self.assertEqual(application["application_type"], "HTTPS_WEBSITE")
        self.assertFalse(application["active"])
        self.assertFalse(application["owned_by_platform"])
        self.assertFalse(application["process_monitoring_permitted"])
        self.assertFalse(application["automatic_recovery_permitted"])

    def test_existing_application_is_matched_by_origin_even_with_health_path(self):
        existing = register_application(
            "Existing API",
            "https://service.example.test/health",
            application_type="HTTPS_WEBSITE",
            db_path=self.database,
        )
        self.enable_discovery(automatic_registration=True)
        discovered = discover_website(
            "https://service.example.test/",
            db_path=self.database,
        )
        self.assertEqual(discovered["application_id"], existing["application_id"])
        self.assertEqual(discovered["registration_status"], "existing")
        self.assertEqual(
            len([app for app in list_discovered_applications(db_path=self.database)]),
            1,
        )

    def test_approval_ignore_and_exclusion_controls_preserve_history(self):
        self.enable_discovery()
        discover_website("https://approve.example.test/", db_path=self.database)
        approved = approve_discovery(
            "https://approve.example.test/",
            db_path=self.database,
        )
        self.assertEqual(approved["registration_status"], "registered")

        excluded = exclude_discovery(
            "https://approve.example.test/",
            db_path=self.database,
        )
        self.assertTrue(excluded["excluded_at"])
        self.assertFalse(get_application(approved["application_id"], self.database)["active"])
        restored = restore_discovery(
            "https://approve.example.test/",
            db_path=self.database,
        )
        self.assertIsNone(restored["excluded_at"])

        discover_website("https://ignore.example.test/", db_path=self.database)
        ignored = ignore_discovery(
            "https://ignore.example.test/",
            db_path=self.database,
        )
        self.assertEqual(ignored["registration_status"], "ignored")
        self.assertGreaterEqual(len(get_discovery_history(db_path=self.database)), 4)

    def test_enabling_automatic_registration_registers_existing_pending_sites(self):
        self.enable_discovery()
        discover_website("https://pending.example.test/", db_path=self.database)
        configure_discovery(
            automatic_registration=True,
            automatic_monitoring=True,
            db_path=self.database,
        )
        row = list_discovered_applications(db_path=self.database)[0]
        self.assertEqual(row["registration_status"], "registered")
        self.assertEqual(row["monitoring_status"], "enabled")
        application = get_application(row["application_id"], self.database)
        self.assertTrue(application["active"])

    def test_pause_and_disable_block_new_discoveries_without_removing_records(self):
        self.enable_discovery()
        discover_website("https://first.example.test/", db_path=self.database)
        configure_discovery(mode="paused", db_path=self.database)
        with self.assertRaises(DiscoveryDisabledError):
            discover_website("https://paused.example.test/", db_path=self.database)
        configure_discovery(mode="disabled", db_path=self.database)
        with self.assertRaises(DiscoveryDisabledError):
            discover_website("https://disabled.example.test/", db_path=self.database)
        self.assertEqual(len(list_discovered_applications(db_path=self.database)), 1)
        self.assertEqual(get_discovery_settings(self.database)["mode"], "disabled")

    def test_pairing_is_single_use_and_api_rejects_missing_or_wrong_authentication(self):
        code = generate_pairing_code(self.database)
        token = pair_extension(code, EXTENSION_ORIGIN, db_path=self.database)
        with self.assertRaisesRegex(ValueError, "invalid or expired"):
            pair_extension(code, EXTENSION_ORIGIN, db_path=self.database)

        missing_auth = self.client.post(
            "/api/discovery/register",
            json={"origin": "https://auth.example.test"},
            headers={"Origin": EXTENSION_ORIGIN},
        )
        self.assertEqual(missing_auth.status_code, 401)

        wrong_auth = self.authorized_post(
            "/api/discovery/register",
            "not-the-token",
            {"origin": "https://auth.example.test"},
        )
        self.assertEqual(wrong_auth.status_code, 401)

        response = self.client.get(
            "/api/discovery/status",
            headers={
                "Origin": EXTENSION_ORIGIN,
                "Authorization": f"Bearer {token}",
            },
        )
        self.assertEqual(response.status_code, 200)

    def test_api_origin_validation_and_database_persistence(self):
        token = self.pair()
        self.enable_discovery(automatic_registration=True)
        response = self.authorized_post(
            "/api/discovery/register",
            token,
            {"origin": "https://youtube.example.test/watch?v=secret"},
        )
        self.assertEqual(response.status_code, 400)
        accepted = self.authorized_post(
            "/api/discovery/register",
            token,
            {"origin": "https://youtube.example.test/"},
        )
        self.assertEqual(accepted.status_code, 200)
        row = list_discovered_applications(db_path=self.database)[0]
        self.assertEqual(row["registration_status"], "registered")
        with closing(connect(self.database)) as connection:
            stored = connection.execute(
                "SELECT origin FROM discovered_applications"
            ).fetchone()["origin"]
        self.assertEqual(stored, "https://youtube.example.test")

    def test_open_tab_scan_discovers_and_counts_only_canonical_origins(self):
        token = self.pair()
        self.enable_discovery(automatic_registration=True, automatic_monitoring=True)
        response = self.authorized_post(
            "/api/discovery/open-tabs",
            token,
            {
                "origins": [
                    "https://one.example.test",
                    "https://two.example.test",
                    "https://one.example.test",
                ],
            },
        )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["tab_count"], 3)
        self.assertEqual(response.json["website_count"], 2)
        self.assertEqual(response.json["skipped_private"], 0)

        rows = list_open_tabs(db_path=self.database)
        self.assertEqual(
            {row["hostname"]: row["tab_count"] for row in rows},
            {"one.example.test": 2, "two.example.test": 1},
        )
        self.assertEqual(len(list_discovered_applications(db_path=self.database)), 2)

    def test_open_tab_scan_rejects_paths_and_oversized_snapshots(self):
        token = self.pair()
        self.enable_discovery(automatic_registration=True)
        path_response = self.authorized_post(
            "/api/discovery/open-tabs",
            token,
            {"origins": ["https://example.test/private"]},
        )
        large_response = self.authorized_post(
            "/api/discovery/open-tabs",
            token,
            {"origins": ["https://example.test"] * 1001},
        )
        self.assertEqual(path_response.status_code, 400)
        self.assertIn(large_response.status_code, (400, 413))
        self.assertEqual(list_open_tabs(db_path=self.database), [])

    def test_open_tab_scan_skips_local_and_private_origins(self):
        token = self.pair()
        self.enable_discovery(automatic_registration=True)
        response = self.authorized_post(
            "/api/discovery/open-tabs",
            token,
            {
                "origins": [
                    "http://127.0.0.1:8501",
                    "http://localhost:5000",
                    "https://public.example.test",
                ],
            },
        )
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["tab_count"], 3)
        self.assertEqual(response.json["website_count"], 1)
        self.assertEqual(response.json["skipped_private"], 2)
        self.assertEqual(
            [row["hostname"] for row in list_open_tabs(db_path=self.database)],
            ["public.example.test"],
        )

    def test_authenticated_operator_api_actions_and_history(self):
        token = self.pair()
        self.enable_discovery()
        discovered = self.authorized_post(
            "/api/discovery/register",
            token,
            {"origin": "https://actions.example.test"},
        )
        self.assertEqual(discovered.status_code, 200)
        origin = discovered.json["origin"]

        approved = self.authorized_post(
            "/api/discovery/approve",
            token,
            {"origin": origin},
        )
        self.assertEqual(approved.status_code, 200)
        excluded = self.authorized_post(
            "/api/discovery/exclude",
            token,
            {"origin": origin},
        )
        self.assertEqual(excluded.status_code, 200)
        restored = self.authorized_post(
            "/api/discovery/restore",
            token,
            {"origin": origin},
        )
        self.assertEqual(restored.status_code, 200)
        applications = self.client.get(
            "/api/discovery/applications",
            headers={
                "Origin": EXTENSION_ORIGIN,
                "Authorization": f"Bearer {token}",
            },
        )
        history = self.client.get(
            "/api/discovery/history",
            headers={
                "Origin": EXTENSION_ORIGIN,
                "Authorization": f"Bearer {token}",
            },
        )
        self.assertEqual(applications.status_code, 200)
        self.assertEqual(history.status_code, 200)
        self.assertEqual(len(applications.json["applications"]), 1)
        self.assertIn(
            "exclusion_restored",
            {event["event_type"] for event in history.json["history"]},
        )

    def test_extension_cors_is_restricted_and_pairing_rate_limited(self):
        code = generate_pairing_code(self.database)
        preflight = self.client.options(
            "/api/discovery/pair",
            headers={
                "Origin": EXTENSION_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        self.assertEqual(preflight.status_code, 204)
        self.assertEqual(
            preflight.headers["Access-Control-Allow-Origin"],
            EXTENSION_ORIGIN,
        )
        disallowed = self.client.options(
            "/api/discovery/pair",
            headers={"Origin": "https://evil.example"},
        )
        self.assertEqual(disallowed.status_code, 403)

        from app import browser_discovery

        with patch.object(browser_discovery, "PAIRING_LIMIT", 1):
            paired = self.client.post(
                "/api/discovery/pair",
                json={"code": code},
                headers={"Origin": EXTENSION_ORIGIN},
            )
            self.assertEqual(paired.status_code, 200)
            limited = self.client.post(
                "/api/discovery/pair",
                json={"code": code},
                headers={"Origin": EXTENSION_ORIGIN},
            )
        self.assertEqual(limited.status_code, 429)

    def test_discovery_api_rate_limit(self):
        from app import browser_discovery

        token = self.pair()
        self.enable_discovery()
        with patch.object(browser_discovery, "REQUEST_LIMIT", 1):
            first = self.authorized_post(
                "/api/discovery/register",
                token,
                {"origin": "https://rate.example.test"},
            )
            second = self.authorized_post(
                "/api/discovery/register",
                token,
                {"origin": "https://rate.example.test"},
            )
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 429)

    def test_registered_discovery_is_picked_up_by_existing_monitor_pipeline(self):
        self.enable_discovery(
            automatic_registration=True,
            automatic_monitoring=True,
        )
        registered = discover_website(
            "https://monitor.example.test/",
            db_path=self.database,
        )
        request = Mock(return_value=FakeResponse(200))
        monitor = MultiApplicationMonitor(
            db_path=self.database,
            request_function=request,
            supervisor_interval=0.1,
        )
        monitor.start()
        try:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                with closing(connect(self.database)) as connection:
                    row = connection.execute(
                        """
                        SELECT data_json FROM application_telemetry
                        WHERE application_id = ?
                        """,
                        (registered["application_id"],),
                    ).fetchone()
                if row:
                    break
                time.sleep(0.02)
            self.assertIsNotNone(row)
            reading = json.loads(row["data_json"])
            self.assertTrue(reading["availability"])
            self.assertIsNone(reading["process_id"])
            self.assertEqual(request.call_count, 1)
        finally:
            monitor.stop()

    def test_monitor_target_validation_rejects_private_dns_and_allows_public_dns(self):
        private = ("127.0.0.1", 0, 0, 0, ("127.0.0.1", 443))
        with patch(
            "app.browser_discovery.socket.getaddrinfo",
            return_value=[private],
        ):
            self.assertFalse(_safe_public_target("https://public.example.test"))
        globally_routable = ("8.8.8.8", 0, 0, 0, ("8.8.8.8", 443))
        with patch(
            "app.browser_discovery.socket.getaddrinfo",
            return_value=[globally_routable],
        ):
            self.assertTrue(_safe_public_target("https://public.example.test"))

    def test_extension_permissions_are_limited_and_incognito_is_disabled(self):
        extension_directory = Path(__file__).resolve().parent.parent / "browser_extension"
        manifest = json.loads((extension_directory / "manifest.json").read_text())
        self.assertEqual(manifest["manifest_version"], 3)
        self.assertEqual(manifest["incognito"], "not_allowed")
        self.assertEqual(
            set(manifest["permissions"]),
            {"webNavigation", "storage", "scripting"},
        )
        self.assertEqual(set(manifest["optional_permissions"]), {"tabs"})
        self.assertEqual(set(manifest["optional_permissions"]), {"tabs"})
        self.assertEqual(
            set(manifest["host_permissions"]),
            {"http://127.0.0.1:5001/*"},
        )
        self.assertEqual(
            set(manifest["optional_host_permissions"]),
            {"http://*/*", "https://*/*"},
        )
        background = (extension_directory / "background.js").read_text()
        self.assertIn("origin,", background)
        self.assertNotIn("cookies", background)


if __name__ == "__main__":
    unittest.main()
