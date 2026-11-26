import json
import math
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from app.health_policy import resource_severity
from app.database import (
    LEGACY_FLASK_APPLICATION_ID,
    connect,
    initialize_database,
)


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_FILE = BASE_DIR / "data" / "incidents.sqlite3"
INCIDENT_STATUSES = (
    "Open",
    "Acknowledged",
    "Investigating",
    "Monitoring",
    "Resolved",
    "Closed",
)
INCIDENT_SEVERITIES = ("Low", "Medium", "High", "Critical")
ACTIVE_INCIDENT_STATUSES = (
    "Open",
    "Acknowledged",
    "Investigating",
    "Monitoring",
)
INCIDENT_STATUS_TRANSITIONS = {
    "Open": {"Acknowledged", "Investigating", "Resolved"},
    "Acknowledged": {"Investigating", "Monitoring", "Resolved"},
    "Investigating": {"Monitoring", "Resolved"},
    "Monitoring": {"Investigating", "Resolved"},
    "Resolved": {"Open", "Closed"},
    "Closed": {"Open"},
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_timestamp(value=None):
    if value is None or not str(value).strip():
        return _now()
    try:
        timestamp = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise ValueError(f"Invalid incident timestamp: {value}") from error
    if timestamp.tzinfo is None:
        timestamp = timestamp.astimezone()
    return timestamp.astimezone(timezone.utc).isoformat(timespec="seconds")


def _connect(db_path=DATABASE_FILE):
    initialize_database(db_path)
    return connect(db_path)


def _add_event(
    connection,
    incident_id,
    event_type,
    summary,
    details="",
    occurred_at=None,
    source_key=None,
    application_id=None,
    anomaly_id=None,
    rca_report_id=None,
):
    connection.execute(
        """
        INSERT OR IGNORE INTO incident_events (
            incident_id, application_id, occurred_at, event_type,
            summary, details, source_key, anomaly_id, rca_report_id
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            application_id,
            _normalize_timestamp(occurred_at),
            event_type,
            summary,
            details,
            source_key,
            anomaly_id,
            rca_report_id,
        ),
    )


def _severity_value(value):
    normalized = str(value or "").strip().title()
    return normalized if normalized in INCIDENT_SEVERITIES else None


def _highest_severity(*values):
    rank = {severity: index for index, severity in enumerate(INCIDENT_SEVERITIES)}
    valid = []
    for value in values:
        severity = _severity_value(value)
        if severity:
            valid.append(severity)
    return max(valid, key=rank.get) if valid else "Medium"


def _new_incident_id():
    return f"INC-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"


def _decode_json_object(raw_value, label):
    try:
        value = json.loads(raw_value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} contains invalid JSON.") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must contain a JSON object.")
    return value


def _problem_key(anomaly, rca_details, anomaly_id):
    payload = anomaly
    leading = {}
    if rca_details:
        causes = rca_details.get("ranked_causes", [])
        if isinstance(causes, list) and causes and isinstance(causes[0], dict):
            leading = causes[0]
        category = str(leading.get("category") or "")
        if category == "dependency":
            dependencies = leading.get("related_dependencies") or []
            if dependencies and isinstance(dependencies[0], dict):
                return f"dependency:{dependencies[0].get('application_id', 'unknown')}"
            dependencies = rca_details.get("related_dependencies", [])
            for dependency in dependencies:
                if dependency.get("health") in {"unhealthy", "degraded"}:
                    return f"dependency:{dependency['application_id']}"
        if category == "database":
            return "database"

    status_code = _number_or_none(payload.get("http_status_code"))
    if (
        payload.get("availability") is False
        or payload.get("connection_error") is True
        or payload.get("timeout_error") is True
    ):
        return "availability"
    if status_code is not None and status_code >= 500:
        return "http_5xx"
    if status_code is not None and status_code >= 400:
        return "http_4xx"

    category = str(leading.get("category") or "")
    if category == "resource":
        resource_metrics = leading.get("related_metrics", [])
        if not isinstance(resource_metrics, (list, tuple)):
            resource_metrics = [str(resource_metrics)]
        resource_labels = " ".join(
            str(item).casefold() for item in resource_metrics
        )
        if "cpu" in resource_labels and "memory" in resource_labels:
            return "resource:cpu+memory"
        if "cpu" in resource_labels:
            return "cpu"
        if "memory" in resource_labels:
            return "memory"
        return "resource"
    if category in {
        "response_time",
        "http_errors",
        "application_failure",
        "database",
        "availability",
    }:
        return {
            "http_errors": "http_errors",
            "application_failure": "application_failure",
        }.get(category, category)

    response_time = _number_or_none(payload.get("response_time_ms"))
    if response_time is not None and response_time >= 1000:
        return "response_time"
    if category == "resource":
        return "resource"
    metrics = anomaly.get("metrics_responsible", [])
    if not isinstance(metrics, (list, tuple)):
        metrics = [str(metrics)]
    labels = " ".join(str(item).casefold() for item in metrics)
    if "cpu" in labels:
        return "cpu"
    if "memory" in labels:
        return "memory"
    if "response" in labels or "latency" in labels:
        return "response_time"
    if "http" in labels or "status" in labels:
        return "http_errors"
    if "database" in labels or "db " in labels:
        return "database"
    if labels.strip():
        return "metrics:" + "+".join(sorted(set(labels.split())))
    return f"anomaly:{anomaly_id}"


def _number_or_none(value):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return number if math.isfinite(number) else None


def create_incident_from_report(
    report,
    db_path=DATABASE_FILE,
    include_diagnosis=True,
    application_id=None,
):
    severity = str(report.get("severity", "")).strip()
    if not severity or severity.lower() == "normal":
        return None

    source_timestamp = str(report.get("source_timestamp", "")).strip()
    if not source_timestamp:
        raise ValueError("An incident report must include source_timestamp.")

    root_cause = str(report.get("root_cause", "")).strip()
    title = root_cause or "Anomaly detected"
    detected_at = _normalize_timestamp(source_timestamp)
    diagnosed_at = _normalize_timestamp(report.get("timestamp"))
    updated_at = _now()
    application_id = application_id or report.get("application_id")
    with closing(_connect(db_path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        if application_id:
            existing = connection.execute(
                """
                SELECT incident_id, severity FROM incidents
                WHERE source_timestamp = ? AND application_id = ?
                """,
                (source_timestamp, application_id),
            ).fetchone()
        else:
            existing = connection.execute(
                "SELECT incident_id, severity FROM incidents WHERE source_timestamp = ?",
                (source_timestamp,),
            ).fetchone()
        if existing:
            incident_id = existing["incident_id"]
            previous_severity = existing["severity"]
            connection.execute(
                """
                UPDATE incidents
                SET updated_at = ?, severity = ?, title = ?, root_cause = ?,
                    recommended_action = ?,
                    application_id = COALESCE(application_id, ?),
                    anomaly_id = COALESCE(?, anomaly_id),
                    rca_report_id = COALESCE(?, rca_report_id),
                    last_seen_at = ?
                WHERE incident_id = ?
                """,
                (
                    updated_at,
                    severity,
                    title,
                    root_cause,
                    str(report.get("recommended_action", "")),
                    application_id,
                    report.get("anomaly_id"),
                    report.get("rca_report_id"),
                    detected_at,
                    incident_id,
                ),
            )
            if previous_severity != severity:
                _add_event(
                    connection,
                    incident_id,
                    "severity_changed",
                    f"Severity changed: {previous_severity} -> {severity}",
                    application_id=application_id,
                    anomaly_id=report.get("anomaly_id"),
                    rca_report_id=report.get("rca_report_id"),
                    source_key=f"severity:{uuid.uuid4().hex}",
                )
        else:
            incident_id = (
                f"INC-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
            )
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, application_id, source_timestamp,
                    created_at, updated_at, severity, status,
                    title, root_cause, recommended_action, anomaly_id,
                    rca_report_id, last_seen_at
                ) VALUES (?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    application_id,
                    source_timestamp,
                    detected_at,
                    updated_at,
                    severity,
                    title,
                    root_cause,
                    str(report.get("recommended_action", "")),
                    report.get("anomaly_id"),
                    report.get("rca_report_id"),
                    detected_at,
                ),
            )

        _add_event(
            connection,
            incident_id,
            "detected",
            "Anomaly detected",
            f"Source metric timestamp: {source_timestamp}",
            occurred_at=detected_at,
            source_key=source_timestamp,
            application_id=application_id,
            anomaly_id=report.get("anomaly_id"),
            rca_report_id=report.get("rca_report_id"),
        )
        if include_diagnosis:
            diagnosis_details = root_cause
            dependency_correlation = str(
                report.get("dependency_correlation", "")
            ).strip()
            if dependency_correlation and dependency_correlation.lower() != "nan":
                diagnosis_details = (
                    f"{diagnosis_details}\n{dependency_correlation}"
                    if diagnosis_details
                    else dependency_correlation
                )
            _add_event(
                connection,
                incident_id,
                "diagnosed",
                "Root cause analysis completed",
                diagnosis_details,
                occurred_at=diagnosed_at,
                source_key=source_timestamp,
                application_id=application_id,
                anomaly_id=report.get("anomaly_id"),
                rca_report_id=report.get("rca_report_id"),
            )
    return incident_id


def sync_reports(reports, db_path=DATABASE_FILE):
    with closing(_connect(db_path)) as connection:
        existing_incidents = {
            (
                row["application_id"] or "",
                row["source_timestamp"],
            ): row["incident_id"]
            for row in connection.execute(
                "SELECT application_id, source_timestamp, incident_id FROM incidents"
            )
        }
        diagnosed_sources = {
            (
                row["application_id"] or "",
                row["source_key"],
            )
            for row in connection.execute(
                """
                SELECT application_id, source_key FROM incident_events
                WHERE event_type = 'diagnosed' AND source_key IS NOT NULL
                """
            )
        }

    incident_ids = []
    for report in reports:
        severity = str(report.get("severity", "")).strip()
        if not severity or severity.lower() == "normal":
            continue
        source_timestamp = str(report.get("source_timestamp", "")).strip()
        application_id = report.get("application_id") or ""
        incident_key = (application_id, source_timestamp)
        if (
            incident_key in existing_incidents
            and incident_key in diagnosed_sources
        ):
            incident_ids.append(existing_incidents[incident_key])
            continue

        incident_id = create_incident_from_report(
            report,
            db_path=db_path,
            application_id=application_id or None,
        )
        if incident_id is not None:
            incident_ids.append(incident_id)
            existing_incidents[incident_key] = incident_id
            diagnosed_sources.add(incident_key)
    return incident_ids


def process_application_anomaly(
    application_id,
    source_timestamp,
    db_path=DATABASE_FILE,
    minimum_severity="Medium",
    include_simulated=False,
):
    if not isinstance(include_simulated, bool):
        raise ValueError("include_simulated must be a boolean.")
    threshold = _severity_value(minimum_severity)
    if threshold is None:
        raise ValueError(
            "minimum_severity must be Low, Medium, High, or Critical."
        )
    if not application_id:
        raise ValueError("application_id is required.")
    if not str(source_timestamp or "").strip():
        raise ValueError("source_timestamp is required.")

    rank = {severity: index for index, severity in enumerate(INCIDENT_SEVERITIES)}
    with closing(_connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        anomaly_row = connection.execute(
            """
            SELECT anomaly_id, application_id, timestamp, prediction,
                   anomaly_score, status, data_json, is_simulated
            FROM anomaly_results
            WHERE application_id = ? AND timestamp = ? AND is_simulated = ?
            ORDER BY anomaly_id DESC
            LIMIT 1
            """,
            (
                application_id,
                str(source_timestamp),
                1 if include_simulated else 0,
            ),
        ).fetchone()
        if anomaly_row is None:
            connection.rollback()
            raise KeyError(
                f"No real anomaly result exists for {application_id} "
                f"at {source_timestamp}."
            )
        if str(anomaly_row["prediction"]).casefold() != "anomaly":
            connection.rollback()
            return None

        anomaly = _decode_json_object(
            anomaly_row["data_json"],
            "Anomaly result",
        )
        rca_row = connection.execute(
            """
            SELECT report_id, severity, root_cause, recommended_action, data_json
            FROM root_cause_reports
            WHERE application_id = ? AND source_timestamp = ?
              AND is_simulated = ?
            ORDER BY report_id DESC
            LIMIT 1
            """,
            (
                application_id,
                str(source_timestamp),
                1 if include_simulated else 0,
            ),
        ).fetchone()
        rca_details = (
            _decode_json_object(rca_row["data_json"], "RCA report")
            if rca_row
            else {}
        )
        application = connection.execute(
            """
            SELECT owned_by_platform, process_monitoring_permitted
            FROM applications
            WHERE application_id = ?
            """,
            (application_id,),
        ).fetchone()
        if application is None:
            connection.rollback()
            raise KeyError(f"Unknown application ID: {application_id}")

        severity_evidence = []
        status_code = _number_or_none(anomaly.get("http_status_code"))
        if (
            anomaly.get("availability") is False
            or anomaly.get("connection_error") is True
            or anomaly.get("timeout_error") is True
            or (status_code is not None and status_code >= 500)
            or (_number_or_none(anomaly.get("response_time_ms")) or 0) >= 2500
        ):
            severity_evidence.append("High")
        elif (
            anomaly.get("request_success") is False
            or (status_code is not None and status_code >= 400)
            or (_number_or_none(anomaly.get("response_time_ms")) or 0) >= 1000
        ):
            severity_evidence.append("Medium")
        if (
            application["owned_by_platform"]
            and application["process_monitoring_permitted"]
            and any(
                (_number_or_none(anomaly.get(field)) or 0) >= 95
                for field in (
                    "cpu_usage",
                    "memory_usage",
                    "process_cpu_percent",
                )
            )
        ):
            severity_evidence.append("Critical")
        severity = _highest_severity(
            anomaly.get("severity"),
            anomaly_row["status"],
            rca_row["severity"] if rca_row else None,
            *severity_evidence,
        )
        if rank[severity] < rank[threshold]:
            connection.rollback()
            return None

        problem_key = _problem_key(
            anomaly,
            rca_details,
            anomaly_row["anomaly_id"],
        )
        is_simulated = bool(anomaly_row["is_simulated"])
        simulation_id = anomaly.get("simulation_id")
        source_key = f"anomaly:{anomaly_row['anomaly_id']}"
        duplicate_event = connection.execute(
            """
            SELECT i.incident_id
            FROM incidents i
            JOIN incident_events e ON e.incident_id = i.incident_id
            WHERE i.application_id = ? AND e.anomaly_id = ?
              AND e.event_type = 'anomaly_detected'
            ORDER BY i.created_at DESC
            LIMIT 1
            """,
            (application_id, anomaly_row["anomaly_id"]),
        ).fetchone()
        if duplicate_event:
            incident_id = duplicate_event["incident_id"]
            if rca_row:
                _add_event(
                    connection,
                    incident_id,
                    "rca_generated",
                    "Root cause analysis report associated",
                    str(rca_row["root_cause"] or ""),
                    occurred_at=source_timestamp,
                    source_key=f"rca:{rca_row['report_id']}",
                    application_id=application_id,
                    anomaly_id=anomaly_row["anomaly_id"],
                    rca_report_id=rca_row["report_id"],
                )
                connection.execute(
                    """
                    UPDATE incidents
                    SET rca_report_id = COALESCE(rca_report_id, ?)
                    WHERE incident_id = ?
                    """,
                    (rca_row["report_id"], incident_id),
                )
                connection.execute(
                    """
                    UPDATE root_cause_reports
                    SET incident_id = COALESCE(incident_id, ?)
                    WHERE report_id = ? AND application_id = ?
                    """,
                    (incident_id, rca_row["report_id"], application_id),
                )
            connection.commit()
            return incident_id

        existing = connection.execute(
            """
            SELECT * FROM incidents
            WHERE application_id = ? AND problem_key = ?
              AND is_simulated = ?
              AND status IN ('Open', 'Acknowledged', 'Investigating', 'Monitoring')
            ORDER BY created_at DESC, incident_id DESC
            LIMIT 1
            """,
            (application_id, problem_key, 1 if is_simulated else 0),
        ).fetchone()
        timestamp = str(source_timestamp)
        detected_at = _normalize_timestamp(timestamp)
        now = _now()
        root_cause = (
            str(rca_row["root_cause"] or "").strip()
            if rca_row
            else str(anomaly.get("explanation") or "").strip()
        )
        if not root_cause:
            root_cause = "Significant application anomaly detected; RCA pending."
        recommended_action = (
            str(rca_row["recommended_action"] or "").strip()
            if rca_row
            else "Investigate the application-specific anomaly and its evidence."
        )
        explanation = str(anomaly.get("explanation") or "").strip()
        metrics = anomaly.get("metrics_responsible", [])
        if not isinstance(metrics, (list, tuple)):
            metrics = [str(metrics)]
        anomaly_details = (
            f"Anomaly ID: {anomaly_row['anomaly_id']}; "
            f"score: {anomaly_row['anomaly_score']}; "
            f"metrics: {', '.join(str(item) for item in metrics)}"
        )
        if explanation:
            anomaly_details += f"; explanation: {explanation}"

        if existing:
            incident_id = existing["incident_id"]
            new_severity = _highest_severity(existing["severity"], severity)
            connection.execute(
                """
                UPDATE incidents
                SET updated_at = ?, last_seen_at = ?, occurrence_count =
                        occurrence_count + 1,
                    severity = ?, anomaly_id = ?, rca_report_id =
                        COALESCE(?, rca_report_id),
                title = ?, root_cause = ?, recommended_action = ?,
                simulation_id = COALESCE(simulation_id, ?)
                WHERE incident_id = ?
                """,
                (
                    now,
                    detected_at,
                    new_severity,
                    anomaly_row["anomaly_id"],
                    rca_row["report_id"] if rca_row else None,
                    root_cause,
                    root_cause,
                    recommended_action,
                    simulation_id,
                    incident_id,
                ),
            )
            if new_severity != existing["severity"]:
                _add_event(
                    connection,
                    incident_id,
                    "severity_changed",
                    f"Severity changed: {existing['severity']} -> {new_severity}",
                    "Severity increased based on a later related anomaly.",
                    occurred_at=detected_at,
                    source_key=f"severity:{anomaly_row['anomaly_id']}",
                    application_id=application_id,
                    anomaly_id=anomaly_row["anomaly_id"],
                    rca_report_id=rca_row["report_id"] if rca_row else None,
                )
            _add_event(
                connection,
                incident_id,
                "anomaly_detected",
                "Additional related anomaly detected",
                anomaly_details,
                occurred_at=detected_at,
                source_key=source_key,
                application_id=application_id,
                anomaly_id=anomaly_row["anomaly_id"],
                rca_report_id=rca_row["report_id"] if rca_row else None,
            )
        else:
            incident_id = _new_incident_id()
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, application_id, source_timestamp,
                    created_at, updated_at, severity, status, title,
                    root_cause, recommended_action, anomaly_id, rca_report_id,
                    problem_key, last_seen_at, occurrence_count, is_simulated,
                    simulation_id
                ) VALUES (?, ?, ?, ?, ?, ?, 'Open', ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    incident_id,
                    application_id,
                    timestamp,
                    detected_at,
                    now,
                    severity,
                    root_cause,
                    root_cause,
                    recommended_action,
                    anomaly_row["anomaly_id"],
                    rca_row["report_id"] if rca_row else None,
                    problem_key,
                    detected_at,
                    1 if is_simulated else 0,
                    simulation_id,
                ),
            )
            _add_event(
                connection,
                incident_id,
                "created",
                "Incident created from a significant application anomaly",
                f"Problem context: {problem_key}; initial severity: {severity}",
                occurred_at=detected_at,
                source_key="created",
                application_id=application_id,
                anomaly_id=anomaly_row["anomaly_id"],
                rca_report_id=rca_row["report_id"] if rca_row else None,
            )
            _add_event(
                connection,
                incident_id,
                "anomaly_detected",
                "Significant application anomaly detected",
                anomaly_details,
                occurred_at=detected_at,
                source_key=source_key,
                application_id=application_id,
                anomaly_id=anomaly_row["anomaly_id"],
                rca_report_id=rca_row["report_id"] if rca_row else None,
            )

        if rca_row:
            _add_event(
                connection,
                incident_id,
                "rca_generated",
                "Application-specific root cause analysis completed",
                str(rca_row["root_cause"] or ""),
                occurred_at=source_timestamp,
                source_key=f"rca:{rca_row['report_id']}",
                application_id=application_id,
                anomaly_id=anomaly_row["anomaly_id"],
                rca_report_id=rca_row["report_id"],
            )
            connection.execute(
                """
                UPDATE root_cause_reports
                SET incident_id = COALESCE(incident_id, ?)
                WHERE report_id = ? AND application_id = ?
                """,
                (incident_id, rca_row["report_id"], application_id),
            )
        connection.commit()
    return incident_id


def record_anomaly_detection(metrics, db_path=DATABASE_FILE):
    source_timestamp = str(metrics.get("timestamp", "")).strip()
    if not source_timestamp:
        raise ValueError("An anomalous metric must include timestamp.")

    def metric_value(name):
        try:
            return float(metrics.get(name))
        except (TypeError, ValueError):
            return None

    application_status = str(metrics.get("application_status", "")).lower()
    cpu = metric_value("cpu_usage")
    memory = metric_value("memory_usage")
    disk = metric_value("disk_usage")
    response_time = metric_value("response_time_ms")
    error_rate = metric_value("api_error_rate")
    resource_levels = (
        resource_severity(cpu),
        resource_severity(memory),
        resource_severity(disk),
    )
    critical = (
        application_status == "unreachable"
        or "Critical" in resource_levels
        or (response_time is not None and response_time > 2500)
        or (error_rate is not None and error_rate > 20)
    )
    application_id = metrics.get("application_id")
    return create_incident_from_report(
        {
            "source_timestamp": source_timestamp,
            "application_id": application_id,
            "severity": "Critical" if critical else "Warning",
            "root_cause": (
                "Multivariate anomaly detected; root cause analysis pending."
            ),
            "recommended_action": "Run root-cause analysis.",
        },
        db_path=db_path,
        include_diagnosis=False,
        application_id=application_id,
    )


def record_recovery_attempt(
    source_timestamp,
    action,
    result,
    details="",
    db_path=DATABASE_FILE,
    application_id=None,
):
    with closing(_connect(db_path)) as connection, connection:
        if application_id:
            incident = connection.execute(
                "SELECT incident_id, status, created_at, application_id "
                "FROM incidents "
                "WHERE source_timestamp = ? AND application_id = ?",
                (source_timestamp, application_id),
            ).fetchone()
        else:
            candidates = connection.execute(
                "SELECT incident_id, status, created_at, application_id "
                "FROM incidents "
                "WHERE source_timestamp = ? "
                "ORDER BY created_at DESC, incident_id DESC",
                (source_timestamp,),
            ).fetchall()
            legacy_incident = next(
                (
                    row
                    for row in candidates
                    if row["application_id"] == LEGACY_FLASK_APPLICATION_ID
                ),
                None,
            )
            if legacy_incident is not None:
                incident = legacy_incident
            elif len(candidates) == 1:
                incident = candidates[0]
            else:
                return False
        if not incident:
            return False
        _add_event(
            connection,
            incident["incident_id"],
            "recovery_attempt",
            f"{action}: {result}",
            details,
            application_id=application_id or incident["application_id"],
        )
        if result.strip().casefold() in {"recovery successful", "retry verified"}:
            if incident["status"] not in {"Resolved", "Closed"}:
                now = _now()
                created_at = datetime.fromisoformat(incident["created_at"])
                resolution_time = max(
                    0.0, (datetime.fromisoformat(now) - created_at).total_seconds()
                )
                connection.execute(
                    """
                    UPDATE incidents
                    SET status = 'Resolved', updated_at = ?, resolved_at = ?,
                        resolution_time_seconds = ?
                    WHERE incident_id = ?
                    """,
                    (now, now, resolution_time, incident["incident_id"]),
                )
                _add_event(
                    connection,
                    incident["incident_id"],
                    "resolved",
                    "Automatically resolved after verified recovery "
                    f"({incident['status']} -> Resolved)",
                    details or "Status changed after verified recovery.",
                    application_id=application_id or incident["application_id"],
                )
    return True


def record_incident_event(
    incident_id,
    event_type,
    summary,
    details="",
    db_path=DATABASE_FILE,
    source_key=None,
):
    event_type = str(event_type or "").strip()
    summary = str(summary or "").strip()
    if not event_type or not summary:
        raise ValueError("Incident event type and summary are required.")
    now = _now()
    with closing(_connect(db_path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        incident = connection.execute(
            "SELECT application_id FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if incident is None:
            raise KeyError(f"Incident not found: {incident_id}")
        _add_event(
            connection,
            incident_id,
            event_type,
            summary,
            str(details or ""),
            occurred_at=now,
            source_key=source_key or f"{event_type}:{uuid.uuid4().hex}",
            application_id=incident["application_id"],
        )
        connection.execute(
            "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
            (now, incident_id),
        )
    return True


def complete_application_recovery_attempt(
    recovery_id,
    *,
    result,
    verification="",
    details="",
    decision_reason="",
    approval_status="Not required",
    error_details="",
    retry_count=0,
    verified=False,
    db_path=DATABASE_FILE,
):
    if isinstance(retry_count, bool) or not isinstance(retry_count, int):
        raise ValueError("retry_count must be a non-negative integer.")
    if retry_count < 0:
        raise ValueError("retry_count must be a non-negative integer.")
    now = _now()
    with closing(_connect(db_path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        attempt = connection.execute(
            """
            SELECT application_id, incident_id, action, completed_at
            FROM recovery_attempts
            WHERE recovery_id = ?
            """,
            (recovery_id,),
        ).fetchone()
        if attempt is None:
            raise KeyError(f"Recovery attempt not found: {recovery_id}")
        if attempt["completed_at"] is not None:
            return False

        connection.execute(
            """
            UPDATE recovery_attempts
            SET result = ?, verification = ?, details = ?,
                decision_reason = ?, approval_status = ?,
                error_details = ?, retry_count = ?, completed_at = ?
            WHERE recovery_id = ? AND completed_at IS NULL
            """,
            (
                str(result),
                str(verification or ""),
                str(details or ""),
                str(decision_reason or ""),
                str(approval_status or "Not required"),
                str(error_details or ""),
                retry_count,
                now,
                recovery_id,
            ),
        )

        incident_id = attempt["incident_id"]
        if incident_id:
            incident = connection.execute(
                """
                SELECT application_id, status, created_at
                FROM incidents WHERE incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
            if incident is not None:
                if incident["application_id"] != attempt["application_id"]:
                    raise ValueError(
                        "Recovery attempt application does not match its incident."
                    )
                event_details = "\n".join(
                    item
                    for item in (
                        str(decision_reason or "").strip(),
                        str(details or "").strip(),
                        (
                            "Verification: " + str(verification).strip()
                            if verification
                            else ""
                        ),
                        (
                            "Error: " + str(error_details).strip()
                            if error_details
                            else ""
                        ),
                        f"Approval: {approval_status}",
                        f"Health-check retries: {retry_count}",
                    )
                    if item
                )
                _add_event(
                    connection,
                    incident_id,
                    "recovery_attempt",
                    f"{attempt['action']}: {result}",
                    event_details,
                    occurred_at=now,
                    source_key=f"recovery:{recovery_id}",
                    application_id=incident["application_id"],
                )
                connection.execute(
                    "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
                    (now, incident_id),
                )
                if str(result).casefold() in {
                    "recovery failed",
                    "escalated",
                    "verification failed",
                }:
                    _add_event(
                        connection,
                        incident_id,
                        "recovery_escalated",
                        "Recovery did not verify; manual intervention may be required",
                        str(error_details or verification or details or result),
                        occurred_at=now,
                        source_key=f"recovery-escalation:{recovery_id}",
                        application_id=incident["application_id"],
                    )

                if (
                    verified
                    and str(result).casefold()
                    in {"recovery successful", "retry verified"}
                    and incident["status"] not in {"Resolved", "Closed"}
                ):
                    created_at = _normalize_timestamp(incident["created_at"])
                    resolution_seconds = max(
                        0.0,
                        (
                            datetime.fromisoformat(now)
                            - datetime.fromisoformat(created_at)
                        ).total_seconds(),
                    )
                    connection.execute(
                        """
                        UPDATE incidents
                        SET status = 'Resolved', updated_at = ?, resolved_at = ?,
                            resolution_time_seconds = ?
                        WHERE incident_id = ?
                        """,
                        (now, now, resolution_seconds, incident_id),
                    )
                    _add_event(
                        connection,
                        incident_id,
                        "resolved",
                        f"Incident resolved after verified recovery "
                        f"({incident['status']} -> Resolved)",
                        str(verification or "Independent health verification passed."),
                        occurred_at=now,
                        source_key=f"recovery-resolved:{recovery_id}",
                        application_id=incident["application_id"],
                    )
    return True


def acknowledge_incident(incident_id, db_path=DATABASE_FILE):
    with closing(_connect(db_path)) as connection:
        incident = connection.execute(
            "SELECT status FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
    if incident is None:
        raise KeyError(f"Incident not found: {incident_id}")
    if incident["status"] != "Open":
        return False
    return update_incident_status(incident_id, "Acknowledged", db_path)


def update_incident_status(incident_id, status, db_path=DATABASE_FILE):
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"Unsupported incident status: {status}")

    now = _now()
    with closing(_connect(db_path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        incident = connection.execute(
            """
            SELECT status, created_at, application_id, resolved_at,
                   resolution_time_seconds
            FROM incidents
            WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()
        if not incident:
            raise KeyError(f"Incident not found: {incident_id}")
        previous_status = incident["status"]
        if previous_status == status:
            return False
        if status not in INCIDENT_STATUS_TRANSITIONS.get(previous_status, set()):
            raise ValueError(
                f"Invalid incident status transition: "
                f"{previous_status} -> {status}"
            )

        resolved_at = now if status == "Resolved" else None
        closed_at = now if status == "Closed" else None
        resolution_time = None
        if resolved_at:
            created_at = _normalize_timestamp(incident["created_at"])
            resolution_time = max(
                0.0,
                (
                    datetime.fromisoformat(now)
                    - datetime.fromisoformat(created_at)
                ).total_seconds(),
            )
        elif status == "Closed":
            resolved_at = incident["resolved_at"]
            resolution_time = incident["resolution_time_seconds"]
        acknowledged_at = (
            now
            if status == "Acknowledged"
            or (status == "Investigating" and previous_status == "Open")
            else None
        )
        connection.execute(
            """
            UPDATE incidents
            SET status = ?, updated_at = ?,
                acknowledged_at = COALESCE(acknowledged_at, ?),
                resolved_at = ?, resolution_time_seconds = ?,
                closed_at = ?
            WHERE incident_id = ?
            """,
            (
                status,
                now,
                acknowledged_at,
                resolved_at,
                resolution_time,
                closed_at,
                incident_id,
            ),
        )
        if status == "Resolved":
            event_type = "resolved"
        elif status == "Closed":
            event_type = "closed"
        elif status == "Open" and previous_status in {"Resolved", "Closed"}:
            event_type = "reopened"
        elif status == "Acknowledged":
            event_type = "acknowledged"
        else:
            event_type = "status_changed"
        _add_event(
            connection,
            incident_id,
            event_type,
            f"Status changed: {previous_status} -> {status}",
            application_id=incident["application_id"],
            source_key=f"status:{uuid.uuid4().hex}",
        )
    return True


def start_investigation(incident_id, db_path=DATABASE_FILE):
    return update_incident_status(incident_id, "Investigating", db_path)


def resolve_incident(incident_id, db_path=DATABASE_FILE):
    return update_incident_status(incident_id, "Resolved", db_path)


def close_incident(incident_id, db_path=DATABASE_FILE):
    return update_incident_status(incident_id, "Closed", db_path)


def reopen_incident(incident_id, db_path=DATABASE_FILE):
    return update_incident_status(incident_id, "Open", db_path)


def add_investigation_note(incident_id, note, db_path=DATABASE_FILE):
    note = str(note or "").strip()
    if not note:
        raise ValueError("Investigation note cannot be empty.")
    now = _now()
    with closing(_connect(db_path)) as connection, connection:
        incident = connection.execute(
            "SELECT application_id FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if incident is None:
            raise KeyError(f"Incident not found: {incident_id}")
        connection.execute(
            "UPDATE incidents SET updated_at = ? WHERE incident_id = ?",
            (now, incident_id),
        )
        _add_event(
            connection,
            incident_id,
            "investigation_note",
            "Investigation note added",
            note,
            occurred_at=now,
            application_id=incident["application_id"],
        )
    return True


def change_incident_severity(incident_id, severity, db_path=DATABASE_FILE):
    severity = _severity_value(severity)
    if severity is None:
        raise ValueError("severity must be Low, Medium, High, or Critical.")
    now = _now()
    with closing(_connect(db_path)) as connection, connection:
        incident = connection.execute(
            "SELECT severity, application_id FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if incident is None:
            raise KeyError(f"Incident not found: {incident_id}")
        if incident["severity"] == severity:
            return False
        connection.execute(
            "UPDATE incidents SET severity = ?, updated_at = ? WHERE incident_id = ?",
            (severity, now, incident_id),
        )
        _add_event(
            connection,
            incident_id,
            "severity_changed",
            f"Severity changed: {incident['severity']} -> {severity}",
            occurred_at=now,
            source_key=f"severity-manual:{uuid.uuid4().hex}",
            application_id=incident["application_id"],
        )
    return True


def get_incident(incident_id, db_path=DATABASE_FILE):
    with closing(_connect(db_path)) as connection:
        incident = connection.execute(
            "SELECT * FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
    return dict(incident) if incident else None


def list_incidents(
    db_path=DATABASE_FILE,
    *,
    application_id=None,
    severity=None,
    status=None,
    include_simulated=False,
):
    if status is not None and status not in INCIDENT_STATUSES:
        raise ValueError(f"Unsupported incident status: {status}")
    query = """
        SELECT i.*,
            (SELECT COUNT(*) FROM incident_events e
             WHERE e.incident_id = i.incident_id
               AND e.event_type = 'recovery_attempt') AS recovery_attempts
        FROM incidents i
    """
    conditions = []
    parameters = []
    if not isinstance(include_simulated, bool):
        raise ValueError("include_simulated must be a boolean.")
    if not include_simulated:
        conditions.append("i.is_simulated = 0")
    if application_id is not None:
        conditions.append("i.application_id = ?")
        parameters.append(application_id)
    if severity is not None:
        conditions.append("i.severity = ?")
        parameters.append(str(severity))
    if status is not None:
        conditions.append("i.status = ?")
        parameters.append(status)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY i.created_at DESC, i.incident_id DESC"
    with closing(_connect(db_path)) as connection:
        incidents = connection.execute(query, parameters).fetchall()
    return [dict(incident) for incident in incidents]


def get_incident_timeline(incident_id, db_path=DATABASE_FILE):
    with closing(_connect(db_path)) as connection:
        events = connection.execute(
            """
            SELECT event_id, application_id, anomaly_id, rca_report_id,
                   occurred_at, event_type, summary, details, source_key
            FROM incident_events
            WHERE incident_id = ?
            ORDER BY julianday(occurred_at), event_id
            """,
            (incident_id,),
        ).fetchall()
    return [dict(event) for event in events]
