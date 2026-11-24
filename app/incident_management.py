import sqlite3
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_FILE = BASE_DIR / "data" / "incidents.sqlite3"
INCIDENT_STATUSES = ("Open", "Investigating", "Resolved")


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
    database_path = Path(db_path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            incident_id TEXT PRIMARY KEY,
            source_timestamp TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL CHECK (
                status IN ('Open', 'Investigating', 'Resolved')
            ),
            title TEXT NOT NULL,
            root_cause TEXT NOT NULL,
            recommended_action TEXT NOT NULL,
            acknowledged_at TEXT,
            resolved_at TEXT,
            resolution_time_seconds REAL
        );
        CREATE TABLE IF NOT EXISTS incident_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
            occurred_at TEXT NOT NULL,
            event_type TEXT NOT NULL,
            summary TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            source_key TEXT,
            UNIQUE (incident_id, event_type, source_key)
        );
        CREATE INDEX IF NOT EXISTS incident_events_timeline
            ON incident_events (incident_id, occurred_at, event_id);
        """
    )
    return connection


def _add_event(
    connection,
    incident_id,
    event_type,
    summary,
    details="",
    occurred_at=None,
    source_key=None,
):
    connection.execute(
        """
        INSERT OR IGNORE INTO incident_events (
            incident_id, occurred_at, event_type, summary, details, source_key
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            _normalize_timestamp(occurred_at),
            event_type,
            summary,
            details,
            source_key,
        ),
    )


def create_incident_from_report(
    report,
    db_path=DATABASE_FILE,
    include_diagnosis=True,
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
    with closing(_connect(db_path)) as connection, connection:
        existing = connection.execute(
            "SELECT incident_id FROM incidents WHERE source_timestamp = ?",
            (source_timestamp,),
        ).fetchone()
        if existing:
            incident_id = existing["incident_id"]
            connection.execute(
                """
                UPDATE incidents
                SET updated_at = ?, severity = ?, title = ?, root_cause = ?,
                    recommended_action = ?
                WHERE incident_id = ?
                """,
                (
                    updated_at,
                    severity,
                    title,
                    root_cause,
                    str(report.get("recommended_action", "")),
                    incident_id,
                ),
            )
        else:
            incident_id = (
                f"INC-{datetime.now():%Y%m%d}-{uuid.uuid4().hex[:8].upper()}"
            )
            connection.execute(
                """
                INSERT INTO incidents (
                    incident_id, source_timestamp, created_at, updated_at,
                    severity, status, title, root_cause, recommended_action
                ) VALUES (?, ?, ?, ?, ?, 'Open', ?, ?, ?)
                """,
                (
                    incident_id,
                    source_timestamp,
                    detected_at,
                    updated_at,
                    severity,
                    title,
                    root_cause,
                    str(report.get("recommended_action", "")),
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
            )
    return incident_id


def sync_reports(reports, db_path=DATABASE_FILE):
    with closing(_connect(db_path)) as connection:
        existing_incidents = {
            row["source_timestamp"]: row["incident_id"]
            for row in connection.execute(
                "SELECT source_timestamp, incident_id FROM incidents"
            )
        }
        diagnosed_sources = {
            row["source_key"]
            for row in connection.execute(
                """
                SELECT source_key FROM incident_events
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
        if (
            source_timestamp in existing_incidents
            and source_timestamp in diagnosed_sources
        ):
            incident_ids.append(existing_incidents[source_timestamp])
            continue

        incident_id = create_incident_from_report(report, db_path=db_path)
        if incident_id is not None:
            incident_ids.append(incident_id)
            existing_incidents[source_timestamp] = incident_id
            diagnosed_sources.add(source_timestamp)
    return incident_ids


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
    critical = (
        application_status == "unreachable"
        or (cpu is not None and cpu > 95)
        or (memory is not None and memory > 95)
        or (disk is not None and disk > 98)
        or (response_time is not None and response_time > 2500)
        or (error_rate is not None and error_rate > 20)
    )
    return create_incident_from_report(
        {
            "source_timestamp": source_timestamp,
            "severity": "Critical" if critical else "Warning",
            "root_cause": (
                "Multivariate anomaly detected; root cause analysis pending."
            ),
            "recommended_action": "Run root-cause analysis.",
        },
        db_path=db_path,
        include_diagnosis=False,
    )


def record_recovery_attempt(
    source_timestamp,
    action,
    result,
    details="",
    db_path=DATABASE_FILE,
):
    with closing(_connect(db_path)) as connection, connection:
        incident = connection.execute(
            "SELECT incident_id FROM incidents WHERE source_timestamp = ?",
            (source_timestamp,),
        ).fetchone()
        if not incident:
            return False
        _add_event(
            connection,
            incident["incident_id"],
            "recovery_attempt",
            f"{action}: {result}",
            details,
        )
    return True


def acknowledge_incident(incident_id, db_path=DATABASE_FILE):
    now = _now()
    with closing(_connect(db_path)) as connection, connection:
        incident = connection.execute(
            "SELECT status FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if not incident:
            raise KeyError(f"Incident not found: {incident_id}")
        if incident["status"] != "Open":
            return False
        connection.execute(
            """
            UPDATE incidents
            SET status = 'Investigating', acknowledged_at = ?, updated_at = ?
            WHERE incident_id = ?
            """,
            (now, now, incident_id),
        )
        _add_event(
            connection,
            incident_id,
            "acknowledged",
            "Incident acknowledged",
        )
    return True


def update_incident_status(incident_id, status, db_path=DATABASE_FILE):
    if status not in INCIDENT_STATUSES:
        raise ValueError(f"Unsupported incident status: {status}")

    now = _now()
    with closing(_connect(db_path)) as connection, connection:
        incident = connection.execute(
            "SELECT status, created_at FROM incidents WHERE incident_id = ?",
            (incident_id,),
        ).fetchone()
        if not incident:
            raise KeyError(f"Incident not found: {incident_id}")
        previous_status = incident["status"]
        if previous_status == status:
            return False

        resolved_at = now if status == "Resolved" else None
        resolution_time = None
        if resolved_at:
            created_at = datetime.fromisoformat(incident["created_at"])
            resolution_time = max(
                0.0, (datetime.fromisoformat(now) - created_at).total_seconds()
            )
        acknowledged_at = (
            now
            if status == "Investigating"
            and previous_status == "Open"
            else None
        )
        connection.execute(
            """
            UPDATE incidents
            SET status = ?, updated_at = ?,
                acknowledged_at = COALESCE(acknowledged_at, ?),
                resolved_at = ?, resolution_time_seconds = ?
            WHERE incident_id = ?
            """,
            (
                status,
                now,
                acknowledged_at,
                resolved_at,
                resolution_time,
                incident_id,
            ),
        )
        event_type = "resolved" if status == "Resolved" else "status_changed"
        _add_event(
            connection,
            incident_id,
            event_type,
            f"Status changed: {previous_status} -> {status}",
        )
    return True


def list_incidents(db_path=DATABASE_FILE):
    with closing(_connect(db_path)) as connection:
        incidents = connection.execute(
            """
            SELECT i.*,
                (SELECT COUNT(*) FROM incident_events e
                 WHERE e.incident_id = i.incident_id
                   AND e.event_type = 'recovery_attempt') AS recovery_attempts
            FROM incidents i
            ORDER BY i.created_at DESC, i.incident_id DESC
            """
        ).fetchall()
    return [dict(incident) for incident in incidents]


def get_incident_timeline(incident_id, db_path=DATABASE_FILE):
    with closing(_connect(db_path)) as connection:
        events = connection.execute(
            """
            SELECT occurred_at, event_type, summary, details
            FROM incident_events
            WHERE incident_id = ?
            ORDER BY julianday(occurred_at), event_id
            """,
            (incident_id,),
        ).fetchall()
    return [dict(event) for event in events]
