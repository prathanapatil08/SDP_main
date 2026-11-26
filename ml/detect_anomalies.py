import json
import logging
import math
import os
import pickle
import sqlite3
import sys
import tempfile
import threading
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import incident_management
from app.application_registry import get_applications
from app.database import DATABASE_FILE, connect, initialize_database


LOGGER = logging.getLogger(__name__)
DATA_FILE = BASE_DIR / "data" / "metrics.csv"
OUTPUT_FILE = BASE_DIR / "data" / "anomaly_results.csv"
MODEL_ALGORITHM = "IsolationForest"
MODEL_FORMAT_VERSION = 1

LEGACY_FEATURES = [
    "cpu_usage",
    "memory_usage",
    "available_memory_mb",
    "disk_usage",
    "network_sent_bytes_per_sec",
    "network_received_bytes_per_sec",
    "response_time_ms",
    "api_error_rate",
    "request_throughput_rps",
    "application_available",
    "application_process_memory_percent",
]

APPLICATION_FEATURE_LABELS = {
    "response_time_ms": "Response time",
    "http_status_code": "HTTP status",
    "availability": "Availability",
    "request_success": "Request success",
    "request_failure": "Request failure",
    "connection_error": "Connection error",
    "timeout_error": "Request timeout",
    "consecutive_failure_count": "Consecutive failures",
    "cpu_usage": "Process CPU usage",
    "memory_usage": "Process memory usage",
    "process_cpu_percent": "Process CPU usage",
    "process_memory_mb": "Process memory consumption",
    "process_status_running": "Process status",
}

@dataclass(frozen=True)
class AnomalyModelConfig:
    n_estimators: int = 100
    contamination: float = 0.05
    random_state: int = 42
    min_samples: int = 100
    retrain_after_samples: int = 100

    def __post_init__(self):
        if self.n_estimators < 1:
            raise ValueError("n_estimators must be positive.")
        if not 0 < float(self.contamination) <= 0.5:
            raise ValueError("contamination must be greater than 0 and at most 0.5.")
        if self.min_samples < 2:
            raise ValueError("min_samples must be at least 2.")
        if self.retrain_after_samples < 1:
            raise ValueError("retrain_after_samples must be positive.")

    def as_dict(self):
        return {
            "n_estimators": int(self.n_estimators),
            "contamination": float(self.contamination),
            "random_state": int(self.random_state),
            "min_samples": int(self.min_samples),
            "retrain_after_samples": int(self.retrain_after_samples),
        }


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _numeric(value):
    if value is None:
        return np.nan
    if isinstance(value, bool):
        return float(value)
    try:
        result = float(value)
    except (TypeError, ValueError):
        return np.nan
    return result if math.isfinite(result) else np.nan


def _bool_numeric(value):
    if value is None:
        return np.nan
    if isinstance(value, bool):
        return float(value)
    return _numeric(value)


def _telemetry_features(payload):
    request_success = _bool_numeric(payload.get("request_success"))
    request_failure = (
        1.0 - request_success if not math.isnan(request_success) else np.nan
    )
    process_status = payload.get("process_status")
    process_status_running = (
        1.0
        if str(process_status).casefold() == "running"
        else 0.0
        if process_status is not None
        else np.nan
    )
    return {
        "response_time_ms": _numeric(payload.get("response_time_ms")),
        "http_status_code": _numeric(payload.get("http_status_code")),
        "availability": _bool_numeric(payload.get("availability")),
        "request_success": request_success,
        "request_failure": request_failure,
        "connection_error": _bool_numeric(payload.get("connection_error")),
        "timeout_error": _bool_numeric(payload.get("timeout_error")),
        "consecutive_failure_count": _numeric(
            payload.get("consecutive_failure_count")
        ),
        "cpu_usage": _numeric(payload.get("cpu_usage")),
        "memory_usage": _numeric(payload.get("memory_usage")),
        "process_cpu_percent": _numeric(payload.get("process_cpu_percent")),
        "process_memory_mb": _numeric(payload.get("process_memory_mb")),
        "process_status_running": process_status_running,
    }


def _feature_frame(telemetry_rows):
    records = []
    for row in telemetry_rows:
        try:
            payload = json.loads(row["data_json"])
        except (TypeError, json.JSONDecodeError):
            LOGGER.warning(
                "Skipping malformed telemetry for application %s at %s",
                row["application_id"],
                row["timestamp"],
            )
            continue
        if not isinstance(payload, dict):
            LOGGER.warning(
                "Skipping non-object telemetry for application %s at %s",
                row["application_id"],
                row["timestamp"],
            )
            continue
        values = _telemetry_features(payload)
        values["timestamp"] = row["timestamp"]
        values["payload"] = payload
        values["is_simulated"] = bool(row.get("is_simulated", 0))
        records.append(values)

    if not records:
        return pd.DataFrame()
    frame = pd.DataFrame.from_records(records).set_index("timestamp")
    feature_columns = [
        column
        for column in APPLICATION_FEATURE_LABELS
        if column in frame.columns and frame[column].notna().any()
    ]
    if not feature_columns:
        return pd.DataFrame(index=frame.index)
    frame[feature_columns] = frame[feature_columns].apply(
        pd.to_numeric,
        errors="coerce",
    )
    frame = frame.dropna(subset=feature_columns, how="all")
    frame.attrs["feature_columns"] = feature_columns
    return frame


def _matrix_and_medians(frame, features, medians=None):
    matrix = frame[features].apply(pd.to_numeric, errors="coerce")
    if medians is None:
        medians = {
            column: float(matrix[column].median())
            for column in features
            if matrix[column].notna().any()
        }
    active_features = [column for column in features if column in medians]
    matrix = matrix[active_features].fillna(
        pd.Series(medians).reindex(active_features)
    )
    return matrix, medians, active_features


def _training_bounds(matrix):
    bounds = {}
    for column in matrix.columns:
        lower = float(matrix[column].quantile(0.25))
        upper = float(matrix[column].quantile(0.75))
        spread = upper - lower
        bounds[column] = {
            "lower": lower - 1.5 * spread,
            "upper": upper + 1.5 * spread,
        }
    return bounds


def _result_severity(score, payload, is_anomaly):
    if not is_anomaly:
        return "Normal"

    strength = max(0.0, -float(score))
    if strength >= 0.25:
        severity = "Critical"
    elif strength >= 0.12:
        severity = "High"
    elif strength >= 0.05:
        severity = "Medium"
    else:
        severity = "Low"

    consecutive_failures = _numeric(payload.get("consecutive_failure_count"))
    status_code = _numeric(payload.get("http_status_code"))
    response_time = _numeric(payload.get("response_time_ms"))
    unavailable = payload.get("availability") is False
    failed_request = payload.get("request_success") is False
    cpu = _numeric(payload.get("cpu_usage"))
    memory = _numeric(payload.get("memory_usage"))
    rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

    if (unavailable and consecutive_failures >= 3) or consecutive_failures >= 5:
        severity = "Critical"
    elif (
        (unavailable and consecutive_failures >= 2)
        or (status_code >= 500 and consecutive_failures >= 2)
        or (cpu >= 99)
        or (memory >= 99)
    ):
        severity = "High"
    elif (
        unavailable
        or failed_request
        or status_code >= 500
        or cpu >= 95
        or memory >= 95
    ):
        severity = max((severity, "Medium"), key=lambda item: rank[item])
    if response_time >= 2500:
        severity = "Critical"
    elif response_time >= 1000:
        severity = max((severity, "High"), key=lambda item: rank[item])
    return severity


def _responsible_metrics(payload, feature_values, bounds):
    responsible = []
    for feature, value in feature_values.items():
        if pd.isna(value) or feature not in bounds:
            continue
        limits = bounds[feature]
        is_outlier = value < limits["lower"] or value > limits["upper"]
        if is_outlier:
            label = APPLICATION_FEATURE_LABELS.get(feature, feature)
            if label not in responsible:
                responsible.append(label)

    if payload.get("availability") is False and "Availability" not in responsible:
        responsible.append("Availability")
    if payload.get("request_success") is False and "Request success" not in responsible:
        responsible.append("Request success")
    if _numeric(payload.get("http_status_code")) >= 500:
        if "HTTP status" not in responsible:
            responsible.append("HTTP status")
    return responsible


class ApplicationAnomalyDetector:
    def __init__(self, db_path=None, config=None, model_factory=IsolationForest):
        self.db_path = db_path
        self.config = (
            config
            if isinstance(config, AnomalyModelConfig)
            else AnomalyModelConfig(**(config or {}))
        )
        self.model_factory = model_factory
        self._locks = {}
        self._locks_guard = threading.Lock()
        self._model_cache = {}
        initialize_database(db_path)

    def _lock_for(self, application_id):
        with self._locks_guard:
            return self._locks.setdefault(application_id, threading.Lock())

    def _load_telemetry(self, application_id, include_simulated=False):
        with closing(connect(self.db_path)) as connection:
            rows = connection.execute(
                """
                SELECT application_id, timestamp, data_json, is_simulated
                FROM application_telemetry
                WHERE application_id = ?
                  AND (? = 1 OR is_simulated = 0)
                ORDER BY timestamp
                """,
                (application_id, 1 if include_simulated else 0),
            ).fetchall()
            processed = {
                row["timestamp"]
                for row in connection.execute(
                    """
                    SELECT timestamp FROM anomaly_results
                    WHERE application_id = ?
                      AND (? = 1 OR is_simulated = 0)
                    """,
                    (application_id, 1 if include_simulated else 0),
                ).fetchall()
            }
        return [dict(row) for row in rows], processed

    def _load_model_record(self, application_id):
        with closing(connect(self.db_path)) as connection:
            row = connection.execute(
                """
                SELECT * FROM application_models WHERE application_id = ?
                """,
                (application_id,),
            ).fetchone()
        return dict(row) if row else None

    def _persist_model(
        self,
        application_id,
        model,
        features,
        medians,
        bounds,
        training_sample_count,
        trained_through_timestamp,
        previous_version,
    ):
        now = _utc_now()
        model_version = previous_version + 1
        config_json = json.dumps(self.config.as_dict(), sort_keys=True)
        model_blob = pickle.dumps(model, protocol=pickle.HIGHEST_PROTOCOL)
        with closing(connect(self.db_path)) as connection, connection:
            connection.execute(
                """
                INSERT INTO application_models (
                    application_id, algorithm, model_version, model_blob,
                    features_json, medians_json, bounds_json, config_json,
                    training_sample_count, trained_through_timestamp,
                    trained_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(application_id) DO UPDATE SET
                    algorithm = excluded.algorithm,
                    model_version = excluded.model_version,
                    model_blob = excluded.model_blob,
                    features_json = excluded.features_json,
                    medians_json = excluded.medians_json,
                    bounds_json = excluded.bounds_json,
                    config_json = excluded.config_json,
                    training_sample_count = excluded.training_sample_count,
                    trained_through_timestamp = excluded.trained_through_timestamp,
                    trained_at = excluded.trained_at,
                    updated_at = excluded.updated_at
                """,
                (
                    application_id,
                    MODEL_ALGORITHM,
                    model_version,
                    sqlite3.Binary(model_blob),
                    json.dumps(features),
                    json.dumps(medians, sort_keys=True),
                    json.dumps(bounds, sort_keys=True),
                    config_json,
                    training_sample_count,
                    trained_through_timestamp,
                    now,
                    now,
                ),
            )
        record = {
            "application_id": application_id,
            "algorithm": MODEL_ALGORITHM,
            "model_version": model_version,
            "features_json": json.dumps(features),
            "medians_json": json.dumps(medians, sort_keys=True),
            "bounds_json": json.dumps(bounds, sort_keys=True),
            "config_json": config_json,
            "training_sample_count": training_sample_count,
            "trained_through_timestamp": trained_through_timestamp,
            "trained_at": now,
            "updated_at": now,
        }
        self._model_cache[application_id] = (
            model_version,
            now,
            model,
        )
        return model, record, True

    def _get_or_train_model(self, application_id, frame, features):
        matrix, medians, active_features = _matrix_and_medians(frame, features)
        if not active_features:
            return None, None, False
        sample_count = len(matrix)
        if sample_count < self.config.min_samples:
            return None, None, False

        model_record = self._load_model_record(application_id)
        config_json = json.dumps(self.config.as_dict(), sort_keys=True)
        should_retrain = (
            model_record is None
            or model_record["config_json"] != config_json
            or model_record["features_json"] != json.dumps(active_features)
            or sample_count
            >= model_record["training_sample_count"]
            + self.config.retrain_after_samples
        )
        if not should_retrain:
            cached = self._model_cache.get(application_id)
            if (
                cached
                and cached[0] == model_record["model_version"]
                and cached[1] == model_record["trained_at"]
            ):
                return cached[2], model_record, False
            model = pickle.loads(model_record["model_blob"])
            if not isinstance(model, IsolationForest):
                raise ValueError(
                    f"Stored model for {application_id} is not an Isolation Forest."
                )
            self._model_cache[application_id] = (
                model_record["model_version"],
                model_record["trained_at"],
                model,
            )
            return model, model_record, False

        model_matrix, medians, active_features = _matrix_and_medians(
            frame,
            features,
            medians=medians,
        )
        model = self.model_factory(
            n_estimators=self.config.n_estimators,
            contamination=self.config.contamination,
            random_state=self.config.random_state,
        )
        model.fit(model_matrix)
        bounds = _training_bounds(model_matrix)
        previous_version = (
            int(model_record["model_version"]) if model_record else 0
        )
        model, model_record, _ = self._persist_model(
            application_id,
            model,
            active_features,
            medians,
            bounds,
            len(model_matrix),
            str(frame.index[-1]),
            previous_version,
        )
        return model, model_record, True

    def _save_results(self, application_id, frame, timestamps, model, model_record):
        features = json.loads(model_record["features_json"])
        medians = json.loads(model_record["medians_json"])
        bounds = json.loads(model_record["bounds_json"])
        model_matrix, _, _ = _matrix_and_medians(
            frame.loc[timestamps],
            features,
            medians=medians,
        )
        predictions = model.predict(model_matrix)
        scores = model.decision_function(model_matrix)
        results = []
        created_at = _utc_now()
        with closing(connect(self.db_path)) as connection, connection:
            for timestamp, prediction, score in zip(
                timestamps,
                predictions,
                scores,
            ):
                model_flagged = int(prediction) == -1
                payload = frame.loc[timestamp, "payload"]
                values = {
                    feature: frame.loc[timestamp, feature]
                    for feature in features
                }
                responsible = _responsible_metrics(payload, values, bounds)
                is_anomaly = model_flagged or bool(responsible)
                severity = _result_severity(score, payload, is_anomaly)
                if model_flagged:
                    explanation = (
                        "Isolation Forest identified an unusual multivariate reading"
                    )
                elif responsible:
                    explanation = (
                        "One or more metrics exceeded this application's "
                        "learned baseline."
                    )
                else:
                    explanation = (
                        "Reading is within the application-specific model's "
                        "normal range."
                    )
                if is_anomaly and responsible:
                    explanation += f" Supporting metrics: {', '.join(responsible)}."
                is_simulated = bool(
                    payload.get("is_simulated")
                    or frame.loc[timestamp, "is_simulated"]
                )
                result_data = {
                    **payload,
                    "application_id": application_id,
                    "timestamp": timestamp,
                    "is_simulated": is_simulated,
                    "prediction": "Anomaly" if is_anomaly else "Normal",
                    "anomaly_score": float(score),
                    "anomaly_strength": max(0.0, -float(score)),
                    "severity": severity,
                    "metrics_responsible": responsible,
                    "explanation": explanation,
                    "model": {
                        "algorithm": model_record["algorithm"],
                        "model_version": model_record["model_version"],
                        "training_sample_count":
                            model_record["training_sample_count"],
                        "trained_at": model_record["trained_at"],
                        "features": features,
                        "config": json.loads(model_record["config_json"]),
                    },
                }
                connection.execute(
                    """
                    INSERT OR IGNORE INTO anomaly_results (
                        application_id, timestamp, prediction, anomaly_score,
                        status, data_json, is_simulated, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        application_id,
                        timestamp,
                        result_data["prediction"],
                        float(score),
                        severity,
                        json.dumps(
                            result_data,
                            separators=(",", ":"),
                            allow_nan=False,
                        ),
                        1 if is_simulated else 0,
                        created_at,
                    ),
                )
                results.append(result_data)
        return results

    def analyze_application(self, application_id, include_simulated=False):
        if not isinstance(include_simulated, bool):
            raise ValueError("include_simulated must be a boolean.")
        with self._lock_for(application_id):
            telemetry, processed_timestamps = self._load_telemetry(
                application_id,
                include_simulated=include_simulated,
            )
            if not telemetry:
                return {
                    "application_id": application_id,
                    "status": "no_data",
                    "analyzed_count": 0,
                    "anomalies": [],
                }

            frame = _feature_frame(telemetry)
            features = frame.attrs.get("feature_columns", [])
            if frame.empty or not features:
                return {
                    "application_id": application_id,
                    "status": "insufficient_data",
                    "available_sample_count": 0,
                    "analyzable_sample_count": 0,
                    "minimum_sample_count": self.config.min_samples,
                    "analyzed_count": 0,
                    "anomalies": [],
                }
            training_frame = frame.loc[~frame["is_simulated"]].copy()
            training_frame.attrs["feature_columns"] = features
            if len(training_frame) < self.config.min_samples:
                return {
                    "application_id": application_id,
                    "status": "insufficient_data",
                    "available_sample_count": len(training_frame),
                    "analyzable_sample_count": len(frame),
                    "minimum_sample_count": self.config.min_samples,
                    "analyzed_count": 0,
                    "anomalies": [],
                }

            new_timestamps = [
                timestamp
                for timestamp in frame.index
                if timestamp not in processed_timestamps
            ]
            if not new_timestamps:
                model_record = self._load_model_record(application_id)
                return {
                    "application_id": application_id,
                    "status": "no_new_data",
                    "available_sample_count": len(training_frame),
                    "analyzable_sample_count": len(frame),
                    "analyzed_count": 0,
                    "model_version": (
                        model_record["model_version"] if model_record else None
                    ),
                    "anomalies": [],
                }

            model, model_record, trained = self._get_or_train_model(
                application_id,
                training_frame,
                features,
            )
            if model is None:
                return {
                    "application_id": application_id,
                    "status": "insufficient_data",
                    "available_sample_count": len(training_frame),
                    "analyzable_sample_count": len(frame),
                    "minimum_sample_count": self.config.min_samples,
                    "analyzed_count": 0,
                    "anomalies": [],
                }

            results = self._save_results(
                application_id,
                frame,
                new_timestamps,
                model,
                model_record,
            )
            anomalies = [
                result for result in results
                if result["prediction"] == "Anomaly"
            ]
            return {
                "application_id": application_id,
                "status": "analyzed",
                "available_sample_count": len(training_frame),
                "analyzable_sample_count": len(frame),
                "analyzed_count": len(results),
                "anomaly_count": len(anomalies),
                "model_version": model_record["model_version"],
                "model_trained": trained,
                "features": json.loads(model_record["features_json"]),
                "anomalies": anomalies,
                "results": results,
            }

    def model_info(self, application_id):
        record = self._load_model_record(application_id)
        if record is None:
            return None
        return {
            "application_id": application_id,
            "algorithm": record["algorithm"],
            "model_version": record["model_version"],
            "features": json.loads(record["features_json"]),
            "medians": json.loads(record["medians_json"]),
            "config": json.loads(record["config_json"]),
            "training_sample_count": record["training_sample_count"],
            "trained_through_timestamp": record["trained_through_timestamp"],
            "trained_at": record["trained_at"],
            "updated_at": record["updated_at"],
        }


def get_anomaly_history(application_id, limit=100, db_path=None):
    try:
        limit = int(limit)
    except (TypeError, ValueError) as error:
        raise ValueError("limit must be a positive integer.") from error
    if limit < 1:
        raise ValueError("limit must be a positive integer.")
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT application_id, timestamp, prediction, anomaly_score,
                   status, data_json, is_simulated, created_at
            FROM anomaly_results
            WHERE application_id = ?
            ORDER BY timestamp DESC, anomaly_id DESC
            LIMIT ?
            """,
            (application_id, limit),
        ).fetchall()
    history = []
    for row in rows:
        result = dict(row)
        result["details"] = json.loads(result.pop("data_json"))
        history.append(result)
    return history


_default_detector_lock = threading.Lock()
_default_detectors = {}


def get_default_detector(db_path=None, config=None):
    database_path = Path(db_path or DATABASE_FILE).resolve()
    config_object = (
        config
        if isinstance(config, AnomalyModelConfig)
        else AnomalyModelConfig(**(config or {}))
    )
    cache_key = (
        str(database_path),
        json.dumps(config_object.as_dict(), sort_keys=True),
    )
    with _default_detector_lock:
        if cache_key not in _default_detectors:
            _default_detectors[cache_key] = ApplicationAnomalyDetector(
                db_path=db_path,
                config=config_object,
            )
        return _default_detectors[cache_key]


def analyze_application(
    application_id,
    db_path=None,
    config=None,
    include_simulated=False,
):
    return get_default_detector(db_path=db_path, config=config).analyze_application(
        application_id,
        include_simulated=include_simulated,
    )


def analyze_registered_applications(db_path=None, config=None):
    results = []
    for application in get_applications(
        db_path=db_path,
        include_inactive=True,
    ):
        try:
            results.append(
                analyze_application(
                    application["application_id"],
                    db_path=db_path,
                    config=config,
                )
            )
        except Exception as error:
            LOGGER.exception(
                "Application anomaly detection failed for %s",
                application["application_id"],
            )
            results.append(
                {
                    "application_id": application["application_id"],
                    "status": "error",
                    "error": str(error),
                    "analyzed_count": 0,
                    "anomalies": [],
                }
            )
    return results


def run_legacy_csv_detection():
    data = pd.read_csv(DATA_FILE)
    if "timestamp" not in data.columns:
        raise ValueError("Metrics file must contain a timestamp column.")
    if len(data) < 100:
        raise ValueError("Collect at least 100 readings before training the model.")

    missing_features = [
        feature for feature in LEGACY_FEATURES if feature not in data.columns
    ]
    if missing_features:
        raise ValueError(
            "Metrics are missing multivariate features: "
            + ", ".join(missing_features)
            + ". Start the updated monitor and collect new readings."
        )

    data[LEGACY_FEATURES] = data[LEGACY_FEATURES].apply(
        pd.to_numeric,
        errors="coerce",
    )
    data = data.dropna(subset=LEGACY_FEATURES).copy()
    if len(data) < 100:
        raise ValueError(
            "Not enough complete multivariate readings. Collect at least 100 "
            "readings with all advanced monitoring metrics available."
        )

    existing_results = None
    if OUTPUT_FILE.exists():
        existing_results = pd.read_csv(OUTPUT_FILE)
        if (
            not existing_results.empty
            and "timestamp" not in existing_results.columns
        ):
            raise ValueError(
                "Existing anomaly results have no timestamp column; "
                "refusing to overwrite them."
            )

    if existing_results is None or existing_results.empty:
        new_data = data.copy()
    else:
        processed_timestamps = set(existing_results["timestamp"].astype(str))
        new_data = data[
            ~data["timestamp"].astype(str).isin(processed_timestamps)
        ].copy()

    if new_data.empty:
        print("No newly collected metric timestamps to analyze.")
        print("Existing anomaly results were preserved.")
        return {
            "analyzed_count": 0,
            "anomaly_count": 0,
            "results": new_data,
        }

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )
    model.fit(data[LEGACY_FEATURES])
    new_data["prediction"] = model.predict(new_data[LEGACY_FEATURES])
    new_data["anomaly_score"] = model.decision_function(
        new_data[LEGACY_FEATURES]
    )
    new_data["status"] = new_data["prediction"].map({
        1: "Normal",
        -1: "Anomaly",
    })

    for _, anomaly in new_data[new_data["status"] == "Anomaly"].iterrows():
        incident_management.record_anomaly_detection(anomaly.to_dict())

    if OUTPUT_FILE.exists():
        existing_columns = list(pd.read_csv(OUTPUT_FILE, nrows=0).columns)
        output_columns = existing_columns + [
            column
            for column in new_data.columns
            if column not in existing_columns
        ]
        if output_columns != existing_columns:
            history = existing_results.reindex(columns=output_columns)
            with tempfile.NamedTemporaryFile(
                "w",
                newline="",
                encoding="utf-8",
                dir=OUTPUT_FILE.parent,
                delete=False,
            ) as file:
                history.to_csv(file, index=False)
                temporary_file = file.name
            os.replace(temporary_file, OUTPUT_FILE)
        new_data = new_data.reindex(columns=output_columns)
        new_data.to_csv(OUTPUT_FILE, mode="a", header=False, index=False)
    else:
        new_data.to_csv(OUTPUT_FILE, index=False)

    return {
        "analyzed_count": len(new_data),
        "anomaly_count": int((new_data["status"] == "Anomaly").sum()),
        "results": new_data,
    }


def main():
    legacy_error = None
    try:
        legacy_result = run_legacy_csv_detection()
    except (FileNotFoundError, ValueError) as error:
        legacy_error = error
        legacy_result = {
            "analyzed_count": 0,
            "anomaly_count": 0,
        }
        LOGGER.warning("Legacy CSV anomaly detection was unavailable: %s", error)

    application_results = analyze_registered_applications()
    results = [
        result
        for result in application_results
        if result["status"] == "analyzed"
    ]
    if legacy_error is not None and not results:
        raise legacy_error
    print("\n========== SDP AI ANOMALY DETECTION ==========")
    print("Legacy CSV readings analyzed:", legacy_result["analyzed_count"])
    print("Legacy CSV anomalies detected:", legacy_result["anomaly_count"])
    for result in results:
        print(
            f"Application {result['application_id']}: "
            f"{result['analyzed_count']} readings, "
            f"{result['anomaly_count']} anomalies, "
            f"model v{result['model_version']}"
        )
    for result in application_results:
        if result["status"] == "error":
            print(
                f"Application {result['application_id']} detection failed: "
                f"{result['error']}"
            )
    print("Results saved to:", OUTPUT_FILE)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
