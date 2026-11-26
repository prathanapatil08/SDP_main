import json
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

from sklearn.ensemble import IsolationForest

from app.application_registry import register_application
from app.database import connect, initialize_database
from ml.detect_anomalies import (
    AnomalyModelConfig,
    ApplicationAnomalyDetector,
    get_anomaly_history,
)

UNSET = object()


class ApplicationAnomalyDetectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database = Path(self.temporary_directory.name) / "anomalies.sqlite3"
        initialize_database(self.database)
        self.application_a = self.register_application("Application A")
        self.application_b = self.register_application("Application B")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def register_application(self, name):
        return register_application(
            name=name,
            url=f"https://{name.replace(' ', '').casefold()}.example.test/health",
            application_type="REST_API",
            db_path=self.database,
        )

    def insert_readings(
        self,
        application_id,
        count,
        response_time=UNSET,
        cpu_usage=None,
        memory_usage=None,
        start_index=0,
    ):
        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        with closing(connect(self.database)) as connection, connection:
            for index in range(start_index, start_index + count):
                reading_time = base_time + timedelta(seconds=index)
                response = 100.0 + index % 4 if response_time is UNSET else response_time
                payload = {
                    "application_id": application_id,
                    "timestamp": reading_time.isoformat(),
                    "availability": True,
                    "http_status_code": 200,
                    "response_time_ms": response,
                    "request_success": True,
                    "connection_error": False,
                    "timeout_error": False,
                    "consecutive_failure_count": 0,
                    "cpu_usage": cpu_usage,
                    "memory_usage": memory_usage,
                    "process_id": None,
                    "process_status": None,
                    "process_memory_mb": None,
                    "process_cpu_percent": None,
                    "error_details": None,
                    "is_simulated": False,
                }
                connection.execute(
                    """
                    INSERT INTO application_telemetry (
                        application_id, source, timestamp, data_json,
                        is_simulated, created_at
                    ) VALUES (?, 'test', ?, ?, 0, ?)
                    """,
                    (
                        application_id,
                        reading_time.isoformat(),
                        json.dumps(payload),
                        reading_time.isoformat(),
                    ),
                )

    def detector(self, **kwargs):
        return ApplicationAnomalyDetector(
            db_path=self.database,
            config=AnomalyModelConfig(**kwargs),
        )

    def test_application_models_train_on_separate_data(self):
        self.insert_readings(self.application_a["application_id"], 100)
        self.insert_readings(
            self.application_b["application_id"],
            100,
            response_time=500.0,
        )
        detector = self.detector()

        result_a = detector.analyze_application(
            self.application_a["application_id"]
        )
        result_b = detector.analyze_application(
            self.application_b["application_id"]
        )
        model_a = detector.model_info(self.application_a["application_id"])
        model_b = detector.model_info(self.application_b["application_id"])

        self.assertEqual(result_a["status"], "analyzed")
        self.assertEqual(result_b["status"], "analyzed")
        self.assertEqual(model_a["training_sample_count"], 100)
        self.assertEqual(model_b["training_sample_count"], 100)
        self.assertEqual(model_a["algorithm"], "IsolationForest")
        self.assertEqual(model_b["algorithm"], "IsolationForest")
        self.assertEqual(model_a["model_version"], 1)
        self.assertEqual(model_b["model_version"], 1)
        self.assertEqual(
            {
                row["application_id"]
                for row in get_anomaly_history(
                    self.application_a["application_id"],
                    db_path=self.database,
                )
            },
            {self.application_a["application_id"]},
        )

    def test_insufficient_history_does_not_train_or_write_results(self):
        application_id = self.application_a["application_id"]
        self.insert_readings(application_id, 99)

        result = self.detector().analyze_application(application_id)

        self.assertEqual(result["status"], "insufficient_data")
        self.assertEqual(result["available_sample_count"], 99)
        self.assertIsNone(self.detector().model_info(application_id))
        self.assertEqual(get_anomaly_history(application_id, db_path=self.database), [])

    def test_normal_reading_is_classified_as_normal_and_persisted(self):
        application_id = self.application_a["application_id"]
        self.insert_readings(application_id, 100)
        detector = self.detector()
        detector.analyze_application(application_id)

        self.insert_readings(
            application_id,
            1,
            response_time=101.0,
            start_index=100,
        )
        result = detector.analyze_application(application_id)

        self.assertEqual(result["analyzed_count"], 1)
        self.assertEqual(result["results"][0]["prediction"], "Normal")
        self.assertEqual(result["results"][0]["severity"], "Normal")
        history = get_anomaly_history(application_id, db_path=self.database)
        self.assertEqual(history[0]["prediction"], "Normal")
        self.assertEqual(history[0]["details"]["model"]["algorithm"], "IsolationForest")

    def test_unusual_response_time_is_detected_with_noncritical_severity(self):
        application_id = self.application_a["application_id"]
        self.insert_readings(application_id, 100)
        detector = self.detector()
        detector.analyze_application(application_id)

        self.insert_readings(
            application_id,
            1,
            response_time=1500.0,
            start_index=100,
        )
        result = detector.analyze_application(application_id)

        self.assertEqual(result["anomaly_count"], 1)
        anomaly = result["anomalies"][0]
        self.assertEqual(anomaly["prediction"], "Anomaly")
        self.assertIn(anomaly["severity"], {"Low", "Medium", "High", "Critical"})
        self.assertIn("Response time", anomaly["metrics_responsible"])
        self.assertIn("learned baseline", anomaly["explanation"])
        self.assertNotEqual(anomaly["severity"], "Critical")

    def test_external_missing_cpu_and_memory_are_not_imputed_as_zero(self):
        application_id = self.application_a["application_id"]
        self.insert_readings(
            application_id,
            100,
            cpu_usage=None,
            memory_usage=None,
        )

        detector = self.detector()
        result = detector.analyze_application(application_id)
        model = detector.model_info(application_id)

        self.assertEqual(result["status"], "analyzed")
        self.assertNotIn("cpu_usage", model["features"])
        self.assertNotIn("memory_usage", model["features"])

    def test_missing_values_are_imputed_from_the_same_application_history(self):
        application_id = self.application_a["application_id"]
        self.insert_readings(application_id, 99)
        self.insert_readings(
            application_id,
            1,
            response_time=None,
            start_index=99,
        )

        result = self.detector().analyze_application(application_id)

        self.assertEqual(result["status"], "analyzed")
        self.assertEqual(result["available_sample_count"], 100)

    def test_model_is_reused_and_retrained_after_configured_new_data(self):
        application_id = self.application_a["application_id"]
        self.insert_readings(application_id, 100)
        fit_calls = []

        def counting_factory(**configuration):
            fit_calls.append(configuration)
            return IsolationForest(**configuration)

        detector = ApplicationAnomalyDetector(
            db_path=self.database,
            config=AnomalyModelConfig(retrain_after_samples=2),
            model_factory=counting_factory,
        )
        first = detector.analyze_application(application_id)
        version = first["model_version"]

        self.insert_readings(
            application_id,
            1,
            response_time=100.0,
            start_index=100,
        )
        restarted_detector = ApplicationAnomalyDetector(
            db_path=self.database,
            config=AnomalyModelConfig(retrain_after_samples=2),
            model_factory=counting_factory,
        )
        reused = restarted_detector.analyze_application(application_id)
        self.assertFalse(reused["model_trained"])
        self.assertEqual(reused["model_version"], version)
        self.assertEqual(len(fit_calls), 1)

        self.insert_readings(
            application_id,
            1,
            response_time=102.0,
            start_index=101,
        )
        retrained = detector.analyze_application(application_id)
        self.assertTrue(retrained["model_trained"])
        self.assertEqual(retrained["model_version"], version + 1)
        self.assertEqual(len(fit_calls), 2)

    def test_failure_for_one_application_does_not_block_another(self):
        self.insert_readings(self.application_a["application_id"], 100)
        self.insert_readings(self.application_b["application_id"], 100)
        factory_calls = []

        def fail_first_train(**configuration):
            factory_calls.append(configuration)
            if len(factory_calls) == 1:
                raise RuntimeError("controlled training failure")
            return IsolationForest(**configuration)

        detector = ApplicationAnomalyDetector(
            db_path=self.database,
            model_factory=fail_first_train,
        )
        with self.assertRaisesRegex(RuntimeError, "controlled training failure"):
            detector.analyze_application(self.application_a["application_id"])

        result_b = detector.analyze_application(
            self.application_b["application_id"]
        )

        self.assertEqual(result_b["status"], "analyzed")
        self.assertEqual(
            result_b["application_id"],
            self.application_b["application_id"],
        )
        self.assertIsNone(detector.model_info(self.application_a["application_id"]))
        self.assertIsNotNone(detector.model_info(self.application_b["application_id"]))


if __name__ == "__main__":
    unittest.main()
