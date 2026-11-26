import json
import logging
import math
from contextlib import closing
from datetime import datetime, timedelta, timezone

from app.application_registry import get_application
from app.database import connect, initialize_database
from app.dependency_mapping import get_application_dependency_closure
from app.health_policy import RESOURCE_WARNING_THRESHOLD


LOGGER = logging.getLogger(__name__)
DEFAULT_LOOKBACK_MINUTES = 30
SLOW_RESPONSE_MS = 1000.0
HIGH_RESOURCE_PERCENT = RESOURCE_WARNING_THRESHOLD


def _utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _parse_timestamp(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _number(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _telemetry_records(rows):
    records = []
    for row in rows:
        try:
            payload = json.loads(row["data_json"])
        except (TypeError, json.JSONDecodeError):
            LOGGER.warning(
                "Ignoring invalid telemetry JSON for application %s at %s",
                row["application_id"],
                row["timestamp"],
            )
            continue
        if not isinstance(payload, dict):
            continue
        records.append(
            {
                "timestamp": row["timestamp"],
                "is_simulated": bool(row["is_simulated"]),
                "parsed_timestamp": _parse_timestamp(row["timestamp"]),
                "data": payload,
            }
        )
    return sorted(
        (record for record in records if record["parsed_timestamp"]),
        key=lambda record: record["parsed_timestamp"],
    )


def _load_application_evidence(
    application_id,
    source_timestamp,
    db_path,
    include_simulated=False,
):
    telemetry_filter = "AND (? = 1 OR is_simulated = 0)"
    with closing(connect(db_path)) as connection:
        if source_timestamp is None:
            telemetry_rows = connection.execute(
                f"""
                SELECT application_id, timestamp, data_json, is_simulated
                FROM application_telemetry
                WHERE application_id = ? {telemetry_filter}
                ORDER BY timestamp
                """,
                (application_id, 1 if include_simulated else 0),
            ).fetchall()
        else:
            telemetry_rows = connection.execute(
                f"""
                SELECT application_id, timestamp, data_json, is_simulated
                FROM application_telemetry
                WHERE application_id = ? {telemetry_filter}
                  AND timestamp <= ?
                ORDER BY timestamp
                """,
                (
                    application_id,
                    1 if include_simulated else 0,
                    source_timestamp,
                ),
            ).fetchall()
        if source_timestamp is None:
            latest_telemetry_timestamp = (
                telemetry_rows[-1]["timestamp"] if telemetry_rows else None
            )
            if latest_telemetry_timestamp is None:
                anomaly_row = None
                incident_row = None
            else:
                anomaly_row = connection.execute(
                    """
                    SELECT anomaly_id, timestamp, prediction, status, data_json,
                           is_simulated
                    FROM anomaly_results
                    WHERE application_id = ? AND timestamp = ?
                      AND (? = 1 OR is_simulated = 0)
                    ORDER BY anomaly_id DESC
                    LIMIT 1
                    """,
                    (
                        application_id,
                        latest_telemetry_timestamp,
                        1 if include_simulated else 0,
                    ),
                ).fetchone()
                incident_row = connection.execute(
                    """
                    SELECT incident_id
                    FROM incidents
                    WHERE application_id = ? AND source_timestamp = ?
                      AND is_simulated = ?
                    ORDER BY created_at DESC
                    LIMIT 1
                    """,
                    (
                        application_id,
                        latest_telemetry_timestamp,
                        1 if include_simulated else 0,
                    ),
                ).fetchone()
        else:
            anomaly_row = connection.execute(
                """
                SELECT anomaly_id, timestamp, prediction, status, data_json,
                       is_simulated
                FROM anomaly_results
                WHERE application_id = ? AND timestamp = ?
                  AND (? = 1 OR is_simulated = 0)
                ORDER BY anomaly_id DESC
                LIMIT 1
                """,
                (
                    application_id,
                    source_timestamp,
                    1 if include_simulated else 0,
                ),
            ).fetchone()
            incident_row = connection.execute(
                """
                SELECT incident_id
                FROM incidents
                WHERE application_id = ? AND source_timestamp = ?
                  AND is_simulated = ?
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (
                    application_id,
                    source_timestamp,
                    1 if include_simulated else 0,
                ),
            ).fetchone()
    return (
        _telemetry_records(telemetry_rows),
        dict(anomaly_row) if anomaly_row else None,
        dict(incident_row) if incident_row else None,
    )


def _anomaly_details(anomaly_row):
    if anomaly_row is None:
        return {}
    try:
        details = json.loads(anomaly_row["data_json"])
    except (TypeError, json.JSONDecodeError):
        return {}
    return details if isinstance(details, dict) else {}


def _window(records, latest_time, minutes):
    start = latest_time - timedelta(minutes=minutes)
    return [
        record for record in records
        if record["parsed_timestamp"] >= start
    ]


def _latest_dependency_health(dependency_id, source_time, lookback, db_path):
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT timestamp, data_json
            FROM application_telemetry
            WHERE application_id = ? AND is_simulated = 0 AND timestamp <= ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (dependency_id, source_time.isoformat()),
        ).fetchone()
        anomaly = connection.execute(
            """
            SELECT timestamp, prediction, status, data_json
            FROM anomaly_results
            WHERE application_id = ? AND is_simulated = 0
              AND timestamp <= ?
            ORDER BY timestamp DESC
            LIMIT 1
            """,
            (dependency_id, source_time.isoformat()),
        ).fetchone()

    if row is None:
        anomaly_time = _parse_timestamp(anomaly["timestamp"]) if anomaly else None
        anomaly_flagged = bool(
            anomaly
            and str(anomaly["prediction"]).casefold() == "anomaly"
            and anomaly_time
            and source_time - anomaly_time <= lookback
        )
        if anomaly_flagged:
            try:
                details = json.loads(anomaly["data_json"])
            except (TypeError, json.JSONDecodeError):
                details = {}
            details = details if isinstance(details, dict) else {}
            return {
                "health": "degraded",
                "timestamp": anomaly["timestamp"],
                "evidence": [
                    "A recent dependency anomaly result was recorded, but "
                    "dependency telemetry is unavailable to confirm a failure."
                ],
                "anomaly": True,
                "metrics_responsible": details.get("metrics_responsible", []),
            }
        return {
            "health": "unknown",
            "timestamp": None,
            "evidence": ["No real telemetry is available for this dependency."],
            "anomaly": False,
        }

    try:
        payload = json.loads(row["data_json"])
    except (TypeError, json.JSONDecodeError):
        payload = {}
    payload = payload if isinstance(payload, dict) else {}
    observed_time = _parse_timestamp(row["timestamp"])
    if observed_time is None or source_time - observed_time > lookback:
        return {
            "health": "unknown",
            "timestamp": row["timestamp"],
            "evidence": ["Dependency telemetry is stale for this analysis window."],
            "anomaly": False,
        }

    failed = (
        payload.get("availability") is False
        or payload.get("request_success") is False
        or payload.get("connection_error") is True
        or payload.get("timeout_error") is True
        or (_number(payload.get("http_status_code")) or 0) >= 500
    )
    healthy_signal = (
        payload.get("availability") is True
        or payload.get("request_success") is True
    )
    evidence = []
    if payload.get("availability") is False:
        evidence.append("Dependency availability was false.")
    if payload.get("request_success") is False:
        evidence.append("The dependency request failed.")
    if payload.get("connection_error") is True:
        evidence.append("The dependency probe reported a connection error.")
    if payload.get("timeout_error") is True:
        evidence.append("The dependency probe timed out.")
    status_code = _number(payload.get("http_status_code"))
    if status_code is not None and status_code >= 500:
        evidence.append(f"Dependency returned HTTP {int(status_code)}.")
    if healthy_signal and not failed:
        evidence.append("Latest dependency telemetry reports a successful response.")

    anomaly_details = {}
    if anomaly is not None:
        try:
            anomaly_details = json.loads(anomaly["data_json"])
        except (TypeError, json.JSONDecodeError):
            anomaly_details = {}
    anomaly_time = _parse_timestamp(anomaly["timestamp"]) if anomaly else None
    anomaly_flagged = bool(
        anomaly
        and str(anomaly["prediction"]).casefold() == "anomaly"
        and anomaly_time
        and source_time - anomaly_time <= lookback
    )
    if anomaly_flagged:
        evidence.append("A recent dependency anomaly result was recorded.")

    return {
        "health": "unhealthy" if failed else (
            "degraded" if anomaly_flagged else (
                "healthy" if healthy_signal else "unknown"
            )
        ),
        "timestamp": (
            anomaly["timestamp"]
            if anomaly_flagged
            else row["timestamp"]
        ),
        "evidence": evidence or ["Telemetry does not establish dependency health."],
        "anomaly": anomaly_flagged,
        "metrics_responsible": anomaly_details.get("metrics_responsible", []),
    }


def _candidate(cause, category, base, evidence, metrics, dependencies=None):
    evidence = list(dict.fromkeys(item for item in evidence if item))
    confidence = min(0.95, base + max(0, len(evidence) - 1) * 0.06)
    return {
        "cause": cause,
        "category": category,
        "confidence_score": round(confidence, 2),
        "supporting_evidence": evidence,
        "related_metrics": list(dict.fromkeys(metrics)),
        "related_dependencies": dependencies or [],
    }


def _evaluate(
    application,
    records,
    anomaly_row,
    incident_row,
    source_timestamp,
    lookback_minutes,
    db_path,
):
    anomaly = _anomaly_details(anomaly_row)
    anomaly_flagged = bool(
        anomaly_row
        and str(anomaly_row["prediction"]).casefold() == "anomaly"
    )
    if not records:
        return {
            "status": "insufficient_evidence",
            "observations": [],
            "supporting_evidence": [],
            "ranked_causes": [],
            "related_abnormal_metrics": [],
            "related_dependencies": [],
            "confidence_score": 0.0,
            "suspected_root_cause": "Insufficient evidence to identify a root cause.",
            "recommended_action": (
                "Collect application-specific telemetry and retry RCA when "
                "readings are available."
            ),
            "explanation": (
                "No real telemetry was available for this application at the "
                "requested detection time."
            ),
            "severity": "Unknown",
            "incident_id": incident_row["incident_id"] if incident_row else None,
            "anomaly_id": anomaly_row["anomaly_id"] if anomaly_row else None,
        }

    latest = records[-1]
    latest_time = _parse_timestamp(source_timestamp) or latest["parsed_timestamp"]
    telemetry_matches_detection = (
        _parse_timestamp(latest["timestamp"]) == _parse_timestamp(source_timestamp)
        if source_timestamp is not None
        else True
    )
    recent = _window(records, latest_time, lookback_minutes)
    latest_data = latest["data"]
    observations = []
    abnormal_metrics = []
    candidates = []
    if not telemetry_matches_detection:
        observations.append(
            "No telemetry was recorded at the detection timestamp; the latest "
            f"available reading was {latest['timestamp']}."
        )

    def metric(name):
        return _number(latest_data.get(name))

    available = latest_data.get("availability")
    success = latest_data.get("request_success")
    status_code = metric("http_status_code")
    response_time = metric("response_time_ms")
    failure_count = metric("consecutive_failure_count")
    failed_requests = [
        record for record in recent
        if record["data"].get("request_success") is False
        or record["data"].get("availability") is False
        or record["data"].get("connection_error") is True
        or record["data"].get("timeout_error") is True
        or (_number(record["data"].get("http_status_code")) or 0) >= 400
    ]

    if available is False:
        observations.append(
            f"Application availability was false at {latest['timestamp']}."
        )
        abnormal_metrics.append("availability")
    if success is False:
        observations.append(
            f"The application request failed at {latest['timestamp']}."
        )
        abnormal_metrics.append("request_success")
    if status_code is not None and status_code >= 400:
        observations.append(
            f"The application returned HTTP {int(status_code)}."
        )
        abnormal_metrics.append("http_status_code")
    if failure_count is not None and failure_count > 0:
        observations.append(
            f"Consecutive request failures: {int(failure_count)}."
        )
        abnormal_metrics.append("consecutive_failure_count")
    if latest_data.get("connection_error") is True:
        observations.append("The latest probe reported a connection error.")
        abnormal_metrics.append("connection_error")
    if latest_data.get("timeout_error") is True:
        observations.append("The latest probe timed out.")
        abnormal_metrics.append("timeout_error")
    if response_time is not None and response_time >= SLOW_RESPONSE_MS:
        observations.append(
            f"Response time was {response_time:.1f} ms, at or above "
            f"{SLOW_RESPONSE_MS:.0f} ms."
        )
        abnormal_metrics.append("response_time_ms")

    if available is False or success is False or latest_data.get(
        "connection_error"
    ) is True or latest_data.get("timeout_error") is True:
        evidence = [
            item for item in observations
            if any(
                term in item.casefold()
                for term in ("availability", "request failed", "connection", "timed out")
            )
        ]
        if len(failed_requests) > 1:
            evidence.append(
                f"{len(failed_requests)} failed readings occurred in the "
                f"{lookback_minutes}-minute evidence window."
            )
        if failure_count is not None and failure_count > 1:
            evidence.append(
                f"The monitor recorded {int(failure_count)} consecutive failures."
            )
        candidates.append(
            _candidate(
                "Application endpoint or network path is unavailable",
                "availability",
                0.58,
                evidence,
                ["availability", "request_success", "connection_error", "timeout_error"],
            )
        )

    http_errors = [
        record for record in recent
        if (_number(record["data"].get("http_status_code")) or 0) >= 400
    ]
    if status_code is not None and status_code >= 400:
        evidence = [f"Latest HTTP status was {int(status_code)}."]
        if len(http_errors) > 1:
            evidence.append(
                f"{len(http_errors)} HTTP error responses occurred in the "
                f"{lookback_minutes}-minute evidence window."
            )
        if status_code >= 500:
            evidence.append("The latest response was a server-side HTTP error.")
        candidates.append(
            _candidate(
                "Application is returning HTTP errors",
                "http_errors",
                0.48,
                evidence,
                ["http_status_code", "request_success"],
            )
        )

    response_values = [
        _number(record["data"].get("response_time_ms"))
        for record in recent
    ]
    response_values = [value for value in response_values if value is not None]
    previous_values = [
        _number(record["data"].get("response_time_ms"))
        for record in records[:-len(recent)] if len(recent) < len(records)
    ]
    previous_values = [value for value in previous_values if value is not None]
    response_increased = False
    if response_values and previous_values:
        recent_median = sorted(response_values)[len(response_values) // 2]
        previous_median = sorted(previous_values)[len(previous_values) // 2]
        response_increased = (
            recent_median >= previous_median * 1.5
            and recent_median - previous_median >= 100
        )
    if response_time is not None and (
        response_time >= SLOW_RESPONSE_MS or response_increased
    ):
        evidence = []
        if response_time >= SLOW_RESPONSE_MS:
            evidence.append(
                f"Latest response time was {response_time:.1f} ms."
            )
        if response_increased:
            evidence.append(
                "Recent median response time is at least 50% and 100 ms "
                "above the earlier application baseline."
            )
        if anomaly_flagged:
            evidence.append("Anomaly detection flagged this application reading.")
        candidates.append(
            _candidate(
                "Application response time is elevated or increasing",
                "response_time",
                0.46,
                evidence,
                ["response_time_ms"],
            )
        )
        if "response_time_ms" not in abnormal_metrics:
            abnormal_metrics.append("response_time_ms")

    owned_process_metrics = (
        bool(application.get("owned_by_platform"))
        and bool(application.get("process_monitoring_permitted"))
    )
    for field, label in (
        ("cpu_usage", "CPU"),
        ("process_cpu_percent", "process CPU"),
        ("memory_usage", "memory"),
    ):
        value = metric(field)
        is_percent = True
        if (
            value is None
            or value < HIGH_RESOURCE_PERCENT
            or not owned_process_metrics
        ):
            continue
        observations.append(f"{label} usage was {value:.1f}.")
        abnormal_metrics.append(field)
        candidates.append(
            _candidate(
                f"High {label} consumption may be contributing to application degradation",
                "resource",
                0.48,
                [
                    f"Latest {label} measurement was {value:.1f}"
                    + ("%" if is_percent else " MB")
                    + ".",
                    *(
                        ["Anomaly detection flagged this application reading."]
                        if anomaly_flagged
                        else []
                    ),
                ],
                [field],
            )
        )

    process_memory = metric("process_memory_mb")
    previous_process_memory = [
        _number(record["data"].get("process_memory_mb"))
        for record in records[:-1]
    ]
    previous_process_memory = [
        value for value in previous_process_memory if value is not None
    ][-10:]
    if process_memory is not None and previous_process_memory and owned_process_metrics:
        previous_median = sorted(previous_process_memory)[
            len(previous_process_memory) // 2
        ]
        memory_growth = process_memory - previous_median
        if memory_growth >= max(20.0, previous_median * 0.1):
            observations.append(
                f"Owned application process memory is {process_memory:.1f} MB, "
                f"{memory_growth:.1f} MB above its preceding-sample median."
            )
            abnormal_metrics.append("process_memory_mb")
            candidates.append(
                _candidate(
                    "Owned application process memory has increased above its recent baseline",
                    "resource",
                    0.48,
                    [
                        f"Process memory increased by {memory_growth:.1f} MB "
                        "compared with its preceding-sample median."
                    ],
                    ["process_memory_mb"],
                )
            )

    telemetry_errors = [
        str(record["data"].get("error_details")).strip()
        for record in recent
        if record["data"].get("error_details")
    ]
    if telemetry_errors:
        observations.append(
            "Application telemetry included error details: "
            + telemetry_errors[-1][:500]
        )

    db_fields = (
        ("database_available", "db_available"),
        ("database_response_time_ms", "db_response_time_ms"),
        ("database_error_rate", "db_error_rate"),
        ("database_error_count", "db_error_count"),
        ("database_connection_failures", "db_connection_failures"),
    )
    present_db_fields = [
        (field, metric(field))
        for field_group in db_fields
        for field in field_group
        if field in latest_data
    ]
    database_evidence = []
    database_metrics = []
    for field, value in present_db_fields:
        if field.endswith("_available") and latest_data.get(field) is False:
            database_evidence.append(f"{field} was false.")
            database_metrics.append(field)
        elif value is not None and (
            ("response_time" in field and value >= SLOW_RESPONSE_MS)
            or ("error_rate" in field and value > 5)
            or ("error_count" in field and value > 0)
            or ("connection_failures" in field and value > 0)
        ):
            database_evidence.append(f"{field} was {value:g}.")
            database_metrics.append(field)
    if database_evidence:
        observations.extend(database_evidence)
        abnormal_metrics.extend(database_metrics)
        candidates.append(
            _candidate(
                "Database telemetry indicates a possible database availability or performance issue",
                "database",
                0.55,
                database_evidence,
                database_metrics,
            )
        )

    dependency_reports = []
    dependencies = get_application_dependency_closure(
        application["application_id"],
        db_path=db_path,
    )
    source_time = _parse_timestamp(source_timestamp) or latest_time
    lookback = timedelta(minutes=lookback_minutes)
    for dependency in dependencies:
        health = _latest_dependency_health(
            dependency["depends_on_application_id"],
            source_time,
            lookback,
            db_path,
        )
        if not dependency["dependency_active"]:
            health = {
                "health": "unknown",
                "timestamp": health["timestamp"],
                "evidence": ["The registered dependency application is inactive."],
                "anomaly": False,
            }
        dependency_report = {
            "application_id": dependency["depends_on_application_id"],
            "name": dependency["dependency_name"],
            "dependency_type": dependency["dependency_type"],
            "depth": dependency["depth"],
            **health,
        }
        dependency_reports.append(dependency_report)
        if health["health"] not in {"unhealthy", "degraded"}:
            continue
        dependency_time = _parse_timestamp(health["timestamp"])
        correlated = bool(
            dependency_time
            and abs((source_time - dependency_time).total_seconds()) <= 300
        )
        evidence = [
            (
                f"Dependency {dependency['dependency_name']} is unhealthy "
                "based on its own telemetry."
                if health["health"] == "unhealthy"
                else f"Dependency {dependency['dependency_name']} has an "
                "anomaly signal, without confirmed failure."
            ),
            *health["evidence"],
        ]
        if correlated:
            evidence.append(
                "The dependency failure occurred within five minutes of the "
                "application detection."
            )
        candidates.append(
            _candidate(
                f"Dependency {dependency['dependency_name']} may be contributing to application symptoms",
                "dependency",
                (
                    0.5 if correlated else 0.34
                ) if health["health"] == "unhealthy" else (
                    0.38 if correlated else 0.28
                ),
                evidence,
                ["dependency_health"],
                [
                    {
                        "application_id": dependency["depends_on_application_id"],
                        "name": dependency["dependency_name"],
                        "health": health["health"],
                        "timestamp": health["timestamp"],
                    }
                ],
            )
        )

    related_failure_candidates = [
        candidate
        for candidate in candidates
        if candidate["category"] in {"availability", "http_errors"}
    ]
    if len(related_failure_candidates) > 1:
        candidates = [
            candidate
            for candidate in candidates
            if candidate["category"] not in {"availability", "http_errors"}
        ]
        failure_evidence = list(
            dict.fromkeys(
                evidence
                for candidate in related_failure_candidates
                for evidence in candidate["supporting_evidence"]
            )
        )
        failure_metrics = list(
            dict.fromkeys(
                metric_name
                for candidate in related_failure_candidates
                for metric_name in candidate["related_metrics"]
            )
        )
        candidates.append(
            _candidate(
                "Application requests are failing or returning HTTP errors",
                "application_failure",
                max(
                    candidate["confidence_score"]
                    for candidate in related_failure_candidates
                )
                + 0.04,
                failure_evidence,
                failure_metrics,
            )
        )

    resource_candidates = [
        candidate for candidate in candidates
        if candidate["category"] == "resource"
    ]
    if len(resource_candidates) > 1:
        candidates = [
            candidate
            for candidate in candidates
            if candidate["category"] != "resource"
        ]
        resource_evidence = list(
            dict.fromkeys(
                evidence
                for candidate in resource_candidates
                for evidence in candidate["supporting_evidence"]
            )
        )
        resource_metrics = list(
            dict.fromkeys(
                metric_name
                for candidate in resource_candidates
                for metric_name in candidate["related_metrics"]
            )
        )
        candidates.append(
            _candidate(
                "Elevated application resource consumption may be contributing to degradation",
                "resource",
                max(
                    candidate["confidence_score"]
                    for candidate in resource_candidates
                )
                + 0.04,
                resource_evidence,
                resource_metrics,
            )
        )

    if anomaly_flagged:
        anomaly_metrics = anomaly.get("metrics_responsible", [])
        if not isinstance(anomaly_metrics, (list, tuple)):
            anomaly_metrics = [str(anomaly_metrics)]
        abnormal_metrics.extend(anomaly_metrics)
        if not candidates:
            candidates.append(
                _candidate(
                    "Unclassified application anomaly",
                    "anomaly",
                    0.32,
                    [
                        "Application-specific anomaly detection flagged this reading.",
                        str(anomaly.get("explanation") or "No metric attribution was available."),
                    ],
                    anomaly_metrics,
                )
            )

    candidates.sort(
        key=lambda item: (
            item["confidence_score"],
            len(item["supporting_evidence"]),
        ),
        reverse=True,
    )
    for candidate in candidates:
        if not telemetry_matches_detection:
            candidate["confidence_score"] = min(
                candidate["confidence_score"],
                0.45,
            )
        candidate["classification"] = (
            "likely" if candidate["confidence_score"] >= 0.7 else "possible"
        )
    leading = candidates[0] if candidates else None
    if leading is None:
        root_cause = "No specific root cause established from current evidence."
        confidence = 0.0
        recommended_action = (
            "Continue collecting telemetry; investigate if symptoms appear or persist."
        )
        explanation = (
            "The available application-scoped evidence does not establish a "
            "specific cause."
        )
        status = "insufficient_evidence"
    else:
        root_cause = leading["cause"]
        confidence = leading["confidence_score"]
        status = "analyzed"
        if leading["category"] == "availability":
            recommended_action = (
                "Check the application's health endpoint, network path, and "
                "application logs; follow the configured recovery policy."
            )
        elif leading["category"] == "dependency":
            recommended_action = (
                "Verify the named dependency's service health and request path "
                "before attributing the application failure to it."
            )
        elif leading["category"] == "response_time":
            recommended_action = (
                "Inspect slow endpoints, request traces, and dependency timings "
                "for the affected application."
            )
        elif leading["category"] == "resource":
            recommended_action = (
                "Review resource use only for this owned, process-monitoring-"
                "permitted application and correlate it with its workload."
            )
        elif leading["category"] == "database":
            recommended_action = (
                "Validate the reported database telemetry and inspect the "
                "application's database request timings and error logs."
            )
        else:
            recommended_action = (
                "Inspect the application's HTTP errors and correlate them with "
                "request logs and downstream dependencies."
            )
        explanation = (
            f"The highest-ranked hypothesis is classified as "
            f"{leading['classification']}; confidence is an evidence score, "
            "not a calibrated probability. Confirmed observations are listed "
            "separately."
        )

    severity_rank = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
    severity = str(anomaly.get("severity") or "Low")
    if available is False or (status_code is not None and status_code >= 500):
        observed_severity = "High"
    elif (
        owned_process_metrics
        and any(
            (metric(field) or 0) >= 95.0
            for field in ("cpu_usage", "process_cpu_percent", "memory_usage")
        )
    ):
        observed_severity = "Critical"
    elif abnormal_metrics:
        observed_severity = "Medium"
    else:
        observed_severity = "Low"
    if severity not in severity_rank:
        severity = "Low"
    if severity_rank[observed_severity] > severity_rank[severity]:
        severity = observed_severity
    return {
        "status": status,
        "observations": observations,
        "ranked_causes": candidates,
        "related_abnormal_metrics": list(dict.fromkeys(abnormal_metrics)),
        "related_dependencies": dependency_reports,
        "confidence_score": confidence,
        "suspected_root_cause": root_cause,
        "recommended_action": recommended_action,
        "explanation": explanation,
        "severity": severity,
        "incident_id": incident_row["incident_id"] if incident_row else None,
        "anomaly_id": anomaly_row["anomaly_id"] if anomaly_row else None,
    }


def _report_from_row(row):
    result = dict(row)
    result["details"] = json.loads(result.pop("data_json"))
    details = result["details"]
    result["status"] = details.get("status", "analyzed")
    result["suspected_root_cause"] = details.get(
        "suspected_root_cause",
        result["root_cause"],
    )
    result["detection_timestamp"] = result["source_timestamp"]
    result["anomaly_id"] = details.get("anomaly_id")
    result["supporting_evidence"] = details.get("supporting_evidence", [])
    result["confirmed_observations"] = details.get(
        "confirmed_observations",
        [],
    )
    result["related_abnormal_metrics"] = details.get(
        "related_abnormal_metrics",
        [],
    )
    result["related_dependencies"] = details.get("related_dependencies", [])
    result["confidence_score"] = details.get("confidence_score", 0.0)
    result["explanation"] = details.get("explanation", "")
    return result


def generate_application_rca(
    application_id,
    source_timestamp=None,
    db_path=None,
    lookback_minutes=DEFAULT_LOOKBACK_MINUTES,
    include_simulated=False,
):
    if not isinstance(include_simulated, bool):
        raise ValueError("include_simulated must be a boolean.")
    try:
        lookback_minutes = int(lookback_minutes)
    except (TypeError, ValueError) as error:
        raise ValueError("lookback_minutes must be a positive integer.") from error
    if lookback_minutes < 1:
        raise ValueError("lookback_minutes must be a positive integer.")

    initialize_database(db_path)
    application = get_application(application_id, db_path=db_path)
    if application is None:
        raise KeyError(f"Unknown application ID: {application_id}")

    records, anomaly_row, incident_row = _load_application_evidence(
        application_id,
        source_timestamp,
        db_path,
        include_simulated=include_simulated,
    )
    if source_timestamp is None and records:
        source_timestamp = records[-1]["timestamp"]
    elif source_timestamp is None:
        result = _evaluate(
            application,
            records,
            anomaly_row,
            incident_row,
            None,
            lookback_minutes,
            db_path,
        )
        return {
            "report_id": None,
            "application_id": application_id,
            "source_timestamp": None,
            **result,
        }

    result = _evaluate(
        application,
        records,
        anomaly_row,
        incident_row,
        source_timestamp,
        lookback_minutes,
        db_path,
    )
    if not records and source_timestamp is None:
        return {
            "application_id": application_id,
            "source_timestamp": None,
            **result,
            "report_id": None,
        }

    source_record = next(
        (
            record
            for record in reversed(records)
            if record["timestamp"] == source_timestamp
        ),
        None,
    )
    is_simulated = bool(source_record and source_record["is_simulated"])
    report_details = {
        "application_id": application_id,
        "is_simulated": is_simulated,
        "simulation_id": (
            source_record["data"].get("simulation_id") if source_record else None
        ),
        "incident_id": result["incident_id"],
        "anomaly_id": result["anomaly_id"],
        "source_timestamp": source_timestamp,
        "suspected_root_cause": result["suspected_root_cause"],
        "supporting_evidence": list(dict.fromkeys(
            [
                *result["observations"],
                *(
                    result["ranked_causes"][0]["supporting_evidence"]
                    if result["ranked_causes"]
                    else []
                ),
            ]
        )),
        "confirmed_observations": result["observations"],
        "related_abnormal_metrics": result["related_abnormal_metrics"],
        "related_dependencies": result["related_dependencies"],
        "ranked_causes": result["ranked_causes"],
        "confidence_score": result["confidence_score"],
        "explanation": result["explanation"],
        "recommended_action": result["recommended_action"],
        "status": result["status"],
    }
    created_at = _utc_now()
    with closing(connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        existing = connection.execute(
            """
            SELECT * FROM root_cause_reports
            WHERE application_id = ? AND source_timestamp = ?
              AND is_simulated = ?
            ORDER BY report_id DESC
            LIMIT 1
            """,
            (application_id, source_timestamp, 1 if is_simulated else 0),
        ).fetchone()
        if existing:
            connection.rollback()
            return _report_from_row(existing)
        connection.execute(
            """
            INSERT INTO root_cause_reports (
                application_id, incident_id, source_timestamp, severity,
                root_cause, recommended_action, data_json, is_simulated,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                application_id,
                result["incident_id"],
                source_timestamp,
                result["severity"],
                result["suspected_root_cause"],
                result["recommended_action"],
                json.dumps(report_details, separators=(",", ":"), allow_nan=False),
                1 if is_simulated else 0,
                created_at,
            ),
        )
        report_id = connection.execute(
            "SELECT last_insert_rowid()"
        ).fetchone()[0]
        connection.commit()

    return {
        "report_id": report_id,
        "application_id": application_id,
        "incident_id": result["incident_id"],
        "anomaly_id": result["anomaly_id"],
        "source_timestamp": source_timestamp,
        "severity": result["severity"],
        "status": result["status"],
        "root_cause": result["suspected_root_cause"],
        "detection_timestamp": source_timestamp,
        "supporting_evidence": report_details["supporting_evidence"],
        "confirmed_observations": result["observations"],
        "related_abnormal_metrics": result["related_abnormal_metrics"],
        "related_dependencies": result["related_dependencies"],
        "confidence_score": result["confidence_score"],
        "explanation": result["explanation"],
        **result,
        "created_at": created_at,
        "details": report_details,
    }


def get_application_rca_history(application_id, limit=100, db_path=None):
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
            SELECT * FROM root_cause_reports
            WHERE application_id = ?
            ORDER BY source_timestamp DESC, report_id DESC
            LIMIT ?
            """,
            (application_id, limit),
        ).fetchall()
    return [_report_from_row(row) for row in rows]


def get_application_rca_report(report_id, db_path=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM root_cause_reports WHERE report_id = ?",
            (report_id,),
        ).fetchone()
    return _report_from_row(row) if row else None


def get_latest_application_rca(application_id, db_path=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT * FROM root_cause_reports
            WHERE application_id = ?
            ORDER BY source_timestamp DESC, report_id DESC
            LIMIT 1
            """,
            (application_id,),
        ).fetchone()
    return _report_from_row(row) if row else None

