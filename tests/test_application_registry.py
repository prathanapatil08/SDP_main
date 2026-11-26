import tempfile
import unittest
from pathlib import Path

from app.application_registry import (
    LEGACY_FLASK_APPLICATION_ID,
    deactivate_application,
    generate_application_id,
    get_application,
    get_applications,
    migrate_existing_flask_application,
    register_application,
    remove_application,
    update_application,
)


class ApplicationRegistryTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "registry.sqlite3"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_register_get_update_and_deactivate_application(self):
        application = register_application(
            name="Customer API",
            url="https://api.example.com",
            application_type="REST_API",
            monitoring_interval_seconds=10,
            db_path=self.database,
        )

        self.assertEqual(application["name"], "Customer API")
        self.assertEqual(application["application_type"], "REST_API")
        self.assertTrue(application["active"])
        self.assertFalse(application["owned_by_platform"])
        self.assertIsNotNone(application["application_id"])

        updated = update_application(
            application["application_id"],
            db_path=self.database,
            name="Customer API Production",
            monitoring_interval_seconds=30,
            monitoring_enabled=False,
        )
        self.assertEqual(updated["name"], "Customer API Production")
        self.assertEqual(updated["monitoring_interval_seconds"], 30)
        self.assertFalse(updated["active"])

        self.assertTrue(
            deactivate_application(
                application["application_id"],
                db_path=self.database,
            )
        )
        self.assertFalse(
            deactivate_application(
                application["application_id"],
                db_path=self.database,
            )
        )
        self.assertEqual(
            len(get_applications(self.database, include_inactive=True)),
            1,
        )

    def test_generated_application_ids_are_unique(self):
        first = generate_application_id()
        second = generate_application_id()
        self.assertNotEqual(first, second)
        self.assertTrue(first.startswith("APP-"))
        self.assertTrue(second.startswith("APP-"))

    def test_external_application_cannot_enable_ownership_sensitive_actions(self):
        with self.assertRaisesRegex(ValueError, "require platform ownership"):
            register_application(
                name="External Website",
                url="https://example.com",
                application_type="HTTPS_WEBSITE",
                owned_by_platform=False,
                process_monitoring_permitted=True,
                db_path=self.database,
            )

        with self.assertRaisesRegex(ValueError, "require platform ownership"):
            register_application(
                name="External API",
                url="https://api.example.com",
                application_type="HTTPS_WEBSITE",
                owned_by_platform=False,
                automatic_recovery_permitted=True,
                db_path=self.database,
            )

    def test_owned_local_application_requires_process_identity(self):
        with self.assertRaisesRegex(ValueError, "process name or executable"):
            register_application(
                name="Local Worker",
                url="http://127.0.0.1:7000",
                application_type="CONTROLLED_LOCAL_APPLICATION",
                owned_by_platform=True,
                process_monitoring_permitted=True,
                db_path=self.database,
            )

        application = register_application(
            name="Local Worker",
            url="http://127.0.0.1:7000",
            application_type="CONTROLLED_LOCAL_APPLICATION",
            owned_by_platform=True,
            process_monitoring_permitted=True,
            process_name="worker.exe",
            db_path=self.database,
        )
        self.assertTrue(application["owned_by_platform"])
        self.assertTrue(application["process_monitoring_permitted"])

    def test_remove_requires_deactivation_and_is_safe_with_records(self):
        application = register_application(
            name="Temporary API",
            url="http://127.0.0.1:7100",
            application_type="REST_API",
            db_path=self.database,
        )
        application_id = application["application_id"]

        with self.assertRaisesRegex(ValueError, "Deactivate"):
            remove_application(application_id, db_path=self.database)

        deactivate_application(application_id, db_path=self.database)
        self.assertTrue(remove_application(application_id, db_path=self.database))
        self.assertIsNone(
            get_application(application_id, db_path=self.database)
        )


class ExistingFlaskMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "migration.sqlite3"

    def tearDown(self):
        self.temporary_directory.cleanup()

    def test_existing_flask_application_is_registered_once_and_is_owned(self):
        first = migrate_existing_flask_application(db_path=self.database)
        second = migrate_existing_flask_application(db_path=self.database)

        self.assertEqual(first["application_id"], LEGACY_FLASK_APPLICATION_ID)
        self.assertEqual(first["application_id"], second["application_id"])
        self.assertTrue(second["owned_by_platform"])
        self.assertTrue(second["process_monitoring_permitted"])
        self.assertTrue(second["automatic_recovery_permitted"])
        applications = get_applications(
            self.database,
            include_inactive=True,
        )
        matching = [
            application
            for application in applications
            if application["application_id"] == LEGACY_FLASK_APPLICATION_ID
        ]
        self.assertEqual(len(matching), 1)


if __name__ == "__main__":
    unittest.main()
