import json
import logging
import math
import sqlite3
import threading
import time
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone

import psutil

from app import incident_management
from app.application_registry import get_application
from app.database import connect, initialize_database
from app.process_control import (
    restart_registered_application,
    stop_registered_application,
    verify_registered_application_process,
)
from app.recovery_policy import (
    RECOVERY_ACTION_RESTART,
    RECOVERY_ACTION_RETRY,
    get_recovery_policy,
)


LOGGER = logging.getLogger(__name__)
DEFAULT_APPROVAL_TTL_SECONDS = 300
MAXIMUM_APPROVAL_TTL_SECONDS = 86400
HEALTHY_RESPONSE_TIME_MS = 2000.0
RECOVERY_POLL_INTERVAL_SECONDS = 0.25
STALE_RUNNING_ATTEMPT_SECONDS = 120
_application_locks = {}
_application_locks_guard = threading.Lock()


class RecoveryInProgressError(RuntimeError):
    pass


class RecoveryLimitError(RuntimeError):
    pass


def _utc_now():
    return datetime.now(timezone.utc)


def _timestamp(value=None):
    value = value or _utc_now()
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        value = value.astimezone(timezone.utc)
        return value.isoformat(timespec="microseconds")
    return str(value)


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


def _application_lock(application_id):
    with _application_locks_guard:
        return _application_locks.setdefault(application_id, threading.Lock())


def _timeline_event(connection, incident_id, application_id, event_type, summary,
                    details="", source_key=None, occurred_at=None):
    if not incident_id:
        return
    connection.execute(
        """
        INSERT OR IGNORE INTO incident_events (
            incident_id, application_id, occurred_at, event_type,
            summary, details, source_key
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            incident_id,
            application_id,
            _timestamp(occurred_at),
            event_type,
            summary,
            details,
            source_key,
        ),
    )


def _incident_evidence(incident, db_path):
    initialize_database(db_path)
    simulated = 1 if incident.get("is_simulated") else 0
    with closing(connect(db_path)) as connection:
        anomaly_row = None
        if incident.get("anomaly_id") is not None:
            anomaly_row = connection.execute(
                """
                SELECT data_json FROM anomaly_results
                WHERE anomaly_id = ? AND application_id = ?
                  AND is_simulated = ?
                """,
                (
                    incident["anomaly_id"],
                    incident["application_id"],
                    simulated,
                ),
            ).fetchone()
        if anomaly_row is None:
            anomaly_row = connection.execute(
                """
                SELECT data_json FROM anomaly_results
                WHERE application_id = ? AND timestamp = ? AND is_simulated = ?
                ORDER BY anomaly_id DESC LIMIT 1
                """,
                (
                    incident["application_id"],
                    incident["source_timestamp"],
                    simulated,
                ),
            ).fetchone()

        report_row = None
        if incident.get("rca_report_id") is not None:
            report_row = connection.execute(
                """
                SELECT data_json, root_cause, recommended_action
                FROM root_cause_reports
                WHERE report_id = ? AND application_id = ? AND is_simulated = ?
                """,
                (
                    incident["rca_report_id"],
                    incident["application_id"],
                    simulated,
                ),
            ).fetchone()
        if report_row is None:
            report_row = connection.execute(
                """
                SELECT data_json, root_cause, recommended_action
                FROM root_cause_reports
                WHERE application_id = ? AND source_timestamp = ?
                AND is_simulated = ?
                ORDER BY report_id DESC LIMIT 1
                """,
                (
                    incident["application_id"],
                    incident["source_timestamp"],
                    simulated,
                ),
            ).fetchone()
    anomaly = _decode_json(anomaly_row["data_json"], "anomaly result") if anomaly_row else {}
    rca = _decode_json(report_row["data_json"], "root-cause report") if report_row else {}
    if report_row:
        rca.setdefault("root_cause", report_row["root_cause"])
        rca.setdefault("recommended_action", report_row["recommended_action"])
    return anomaly, rca


def _decode_json(value, description):
    try:
        decoded = json.loads(value)
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"The stored {description} is invalid JSON.") from error
    if not isinstance(decoded, dict):
        raise RuntimeError(f"The stored {description} must be a JSON object.")
    return decoded


def _recent_telemetry(
    application_id,
    db_path,
    limit=3,
    include_simulated=False,
):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT timestamp, data_json FROM application_telemetry
            WHERE application_id = ?
              AND (? = 1 OR is_simulated = 0)
            ORDER BY timestamp DESC LIMIT ?
            """,
            (
                application_id,
                1 if include_simulated else 0,
                limit,
            ),
        ).fetchall()
    readings = []
    for row in rows:
        try:
            reading = json.loads(row["data_json"])
        except (TypeError, json.JSONDecodeError):
            LOGGER.warning(
                "Ignoring invalid recovery telemetry for application %s at %s",
                application_id,
                row["timestamp"],
            )
            continue
        if isinstance(reading, dict):
            readings.append(reading)
    return readings


def _health_state(reading, application):
    if not reading:
        return False, ["No current health reading is available."]
    reasons = []
    status_code = _number(reading.get("http_status_code"))
    response_time = _number(reading.get("response_time_ms"))
    if reading.get("availability") is not True:
        reasons.append("The application endpoint is unavailable.")
    if reading.get("request_success") is not True:
        reasons.append(
            str(reading.get("error_details") or "The health request failed.")
        )
    if status_code is None or not 200 <= status_code < 400:
        if status_code is not None:
            reasons.append(f"The health endpoint returned HTTP {status_code:g}.")
    if (
        response_time is not None
        and response_time >= HEALTHY_RESPONSE_TIME_MS
    ):
        reasons.append(
            f"Health response time was {response_time:.1f} ms, above "
            f"{HEALTHY_RESPONSE_TIME_MS:.0f} ms."
        )

    if _process_monitoring_applicable(application):
        process_id = reading.get("process_id")
        if (
            not isinstance(process_id, int)
            or isinstance(process_id, bool)
            or process_id <= 0
        ):
            reasons.append(
                "A unique owned-process PID could not be verified from telemetry."
            )
        for field in ("process_cpu_percent", "cpu_usage", "memory_usage"):
            value = _number(reading.get(field))
            if value is not None and value >= 95:
                reasons.append(f"Owned process {field} was {value:.1f}%.")
    return not reasons, reasons


def _process_monitoring_applicable(application):
    return bool(
        application.get("owned_by_platform")
        and application.get("process_monitoring_permitted")
    )


def _verify_process_telemetry(application, reading, process_provider):
    process_id = reading.get("process_id") if reading else None
    if (
        not isinstance(process_id, int)
        or isinstance(process_id, bool)
        or process_id <= 0
    ):
        return False, "No valid process ID was collected."
    if application.get("application_id") == "APP-SDP-FLASK-5000":
        from app.process_control import project_flask_processes

        processes = project_flask_processes()
        if len(processes) != 1 or processes[0].pid != process_id:
            return False, "The project Flask process did not match telemetry."
        return True, ""

    from app.multi_app_monitor import find_owned_process

    process, error = find_owned_process(application, process_provider)
    if process is None:
        return False, str(error or "The registered application process was not found.")
    if process.pid != process_id:
        return False, "The process PID did not match the latest telemetry."
    return True, ""


def _repeated_degradation(incident, application, current_reading, db_path):
    if int(incident.get("occurrence_count") or 1) >= 2:
        return True
    recent = _recent_telemetry(
        incident["application_id"],
        db_path,
        limit=2,
        include_simulated=bool(incident.get("is_simulated")),
    )
    if len(recent) < 2:
        return False
    if current_reading and recent[0].get("timestamp") != current_reading.get("timestamp"):
        recent.insert(0, current_reading)
        recent = recent[:2]
    return all(not _health_state(reading, application)[0] for reading in recent)


def _restart_supported_by_rca(rca):
    ranked_causes = rca.get("ranked_causes", [])
    if not isinstance(ranked_causes, list):
        return True
    categories = {
        str(cause.get("category") or "").casefold()
        for cause in ranked_causes
        if isinstance(cause, dict)
    }
    return not categories or not categories.issubset({"dependency", "database"})


def _restart_is_justified(incident, application, rca, repeated):
    if not (
        application.get("owned_by_platform")
        and application.get("process_monitoring_permitted")
        and application.get("automatic_recovery_permitted")
    ):
        return False
    if (
        application.get("application_type") != "CONTROLLED_LOCAL_APPLICATION"
        and application.get("application_id") != "APP-SDP-FLASK-5000"
    ):
        return False
    if incident.get("severity") not in {"High", "Critical"} or not repeated:
        return False
    return _restart_supported_by_rca(rca)


def _approval_required(action, policy):
    if not policy.automatic_recovery_enabled:
        return True
    if policy.required_approval_level == "all":
        return True
    return (
        policy.required_approval_level == "high_risk"
        and action == RECOVERY_ACTION_RESTART
    )


def _request_approval(
    application_id,
    incident_id,
    action,
    reason,
    db_path,
    requested_by,
    expires_in_seconds,
):
    if isinstance(expires_in_seconds, bool):
        raise ValueError("expires_in_seconds must be an integer.")
    try:
        expires_in_seconds = int(expires_in_seconds)
    except (TypeError, ValueError) as error:
        raise ValueError("expires_in_seconds must be an integer.") from error
    if not 1 <= expires_in_seconds <= MAXIMUM_APPROVAL_TTL_SECONDS:
        raise ValueError(
            "expires_in_seconds must be between 1 and "
            f"{MAXIMUM_APPROVAL_TTL_SECONDS}."
        )
    application = get_application(application_id, db_path=db_path)
    if application is None or not application["owned_by_platform"]:
        raise ValueError("Approval requests are limited to owned applications.")
    policy = get_recovery_policy(application_id, db_path=db_path)
    if (
        policy is None
        or not policy.policy_enabled
        or action not in policy.permitted_actions
    ):
        raise ValueError("The requested action is not permitted by policy.")
    if action == RECOVERY_ACTION_RESTART and not (
        application["automatic_recovery_permitted"]
        and application["process_monitoring_permitted"]
    ):
        raise ValueError("Local restart permissions are not enabled.")

    now = _utc_now()
    requested_at = _timestamp(now)
    expires_at = _timestamp(now + timedelta(seconds=expires_in_seconds))
    with closing(connect(db_path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        incident = connection.execute(
            """
            SELECT application_id, status FROM incidents WHERE incident_id = ?
            """,
            (incident_id,),
        ).fetchone()
        if incident is None or incident["application_id"] != application_id:
            raise ValueError(
                "The approval request incident does not belong to this application."
            )
        if incident["status"] in {"Resolved", "Closed"}:
            raise ValueError("Cannot request recovery approval for a closed incident.")

        expired = connection.execute(
            """
            SELECT approval_id FROM approval_requests
            WHERE application_id = ? AND incident_id = ? AND action = ?
              AND status = 'Pending' AND expires_at <= ?
            """,
            (application_id, incident_id, action, requested_at),
        ).fetchall()
        for row in expired:
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'Expired', decided_at = ?, decided_by = 'system',
                    decision_details = 'Approval request expired.'
                WHERE approval_id = ? AND status = 'Pending'
                """,
                (requested_at, row["approval_id"]),
            )
            _timeline_event(
                connection,
                incident_id,
                application_id,
                "approval_expired",
                f"Approval request {row['approval_id']} expired",
                "A later approval request replaced this expired request.",
                source_key=f"approval-expired:{row['approval_id']}",
                occurred_at=requested_at,
            )

        pending = connection.execute(
            """
            SELECT approval_id FROM approval_requests
            WHERE application_id = ? AND incident_id = ? AND action = ?
              AND status = 'Pending'
            ORDER BY approval_id DESC LIMIT 1
            """,
            (application_id, incident_id, action),
        ).fetchone()
        if pending:
            return pending["approval_id"]

        cursor = connection.execute(
            """
            INSERT INTO approval_requests (
                application_id, incident_id, action, status, requested_by,
                requested_at, expires_at, details
            ) VALUES (?, ?, ?, 'Pending', ?, ?, ?, ?)
            """,
            (
                application_id,
                incident_id,
                action,
                str(requested_by or "AIOps"),
                requested_at,
                expires_at,
                str(reason),
            ),
        )
        approval_id = cursor.lastrowid
        _timeline_event(
            connection,
            incident_id,
            application_id,
            "approval_requested",
            f"Approval requested for {action}",
            f"Approval ID: {approval_id}; expires: {expires_at}; reason: {reason}",
            source_key=f"approval-request:{approval_id}",
            occurred_at=requested_at,
        )
    return approval_id


def create_approval_request(
    application_id,
    incident_id,
    action,
    reason,
    *,
    requested_by="AIOps",
    expires_in_seconds=DEFAULT_APPROVAL_TTL_SECONDS,
    db_path=None,
):
    initialize_database(db_path)
    return _request_approval(
        application_id,
        incident_id,
        action,
        reason,
        db_path,
        requested_by,
        expires_in_seconds,
    )


def get_approval_request(approval_id, db_path=None):
    expire_pending_approvals(db_path=db_path)
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM approval_requests WHERE approval_id = ?",
            (approval_id,),
        ).fetchone()
    return dict(row) if row else None


def get_approval_history(
    *,
    application_id=None,
    incident_id=None,
    db_path=None,
):
    expire_pending_approvals(db_path=db_path)
    initialize_database(db_path)
    conditions = []
    parameters = []
    if application_id is not None:
        conditions.append("application_id = ?")
        parameters.append(application_id)
    if incident_id is not None:
        conditions.append("incident_id = ?")
        parameters.append(incident_id)
    query = "SELECT * FROM approval_requests"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY requested_at DESC, approval_id DESC"
    with closing(connect(db_path)) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


def expire_pending_approvals(db_path=None, now=None):
    initialize_database(db_path)
    current_time = _timestamp(now)
    expired_ids = []
    with closing(connect(db_path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute(
            """
            SELECT approval_id, application_id, incident_id
            FROM approval_requests
            WHERE status = 'Pending' AND expires_at <= ?
            """,
            (current_time,),
        ).fetchall()
        for row in rows:
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'Expired', decided_at = ?, decided_by = 'system',
                    decision_details = 'Approval request expired.'
                WHERE approval_id = ? AND status = 'Pending'
                """,
                (current_time, row["approval_id"]),
            )
            _timeline_event(
                connection,
                row["incident_id"],
                row["application_id"],
                "approval_expired",
                f"Approval request {row['approval_id']} expired",
                "No action was executed because approval was not received in time.",
                source_key=f"approval-expired:{row['approval_id']}",
                occurred_at=current_time,
            )
            expired_ids.append(row["approval_id"])
    return expired_ids


def _decide_approval(approval_id, approved, decided_by, details, db_path):
    decided_by = str(decided_by or "").strip()
    if not decided_by:
        raise ValueError("A non-empty decided_by value is required.")
    status = "Approved" if approved else "Rejected"
    current_time = _timestamp()
    initialize_database(db_path)
    with closing(connect(db_path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        request = connection.execute(
            """
            SELECT * FROM approval_requests WHERE approval_id = ?
            """,
            (approval_id,),
        ).fetchone()
        if request is None:
            raise KeyError(f"Approval request not found: {approval_id}")
        if request["status"] != "Pending":
            raise ValueError(
                f"Approval request {approval_id} is already {request['status']}."
            )
        expiry = _parse_timestamp(request["expires_at"])
        current = _parse_timestamp(current_time)
        if expiry is None or current is None or expiry <= current:
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'Expired', decided_at = ?, decided_by = 'system',
                    decision_details = 'Approval request expired.'
                WHERE approval_id = ? AND status = 'Pending'
                """,
                (current_time, approval_id),
            )
            _timeline_event(
                connection,
                request["incident_id"],
                request["application_id"],
                "approval_expired",
                f"Approval request {approval_id} expired",
                "The approval decision arrived after the request expired.",
                source_key=f"approval-expired:{approval_id}",
                occurred_at=current_time,
            )
            return dict(
                connection.execute(
                    "SELECT * FROM approval_requests WHERE approval_id = ?",
                    (approval_id,),
                ).fetchone()
            )

        connection.execute(
            """
            UPDATE approval_requests
            SET status = ?, decided_at = ?, decided_by = ?,
                decision_details = ?
            WHERE approval_id = ? AND status = 'Pending'
            """,
            (status, current_time, decided_by, str(details or ""), approval_id),
        )
        _timeline_event(
            connection,
            request["incident_id"],
            request["application_id"],
            "approval_approved" if approved else "approval_rejected",
            f"Recovery approval {status.casefold()} by {decided_by}",
            str(details or f"Approval request {approval_id} was {status.casefold()}."),
            source_key=f"approval-decision:{approval_id}",
            occurred_at=current_time,
        )
        return dict(
            connection.execute(
                "SELECT * FROM approval_requests WHERE approval_id = ?",
                (approval_id,),
            ).fetchone()
        )


def approve_recovery_request(
    approval_id,
    *,
    decided_by,
    details="",
    db_path=None,
):
    return _decide_approval(
        approval_id,
        True,
        decided_by,
        details,
        db_path,
    )


def reject_recovery_request(
    approval_id,
    *,
    decided_by,
    details="",
    db_path=None,
):
    return _decide_approval(
        approval_id,
        False,
        decided_by,
        details,
        db_path,
    )


def _attempt_counts(application_id, incident_id, db_path):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT action, result, retry_count
            FROM recovery_attempts
            WHERE application_id = ? AND incident_id = ?
            """,
            (application_id, incident_id),
        ).fetchall()
    retry_count = sum(
        int(row["retry_count"] or 0)
        for row in rows
        if row["action"] == RECOVERY_ACTION_RETRY
        and row["result"] != "Approval required"
    )
    restart_count = sum(
        1
        for row in rows
        if row["action"] == RECOVERY_ACTION_RESTART
        and row["result"] != "Approval required"
    )
    return retry_count, restart_count


def _attempt_counts_from_connection(connection, application_id, incident_id):
    rows = connection.execute(
        """
        SELECT action, result, retry_count
        FROM recovery_attempts
        WHERE application_id = ? AND incident_id = ?
        """,
        (application_id, incident_id),
    ).fetchall()
    retry_count = sum(
        int(row["retry_count"] or 0)
        for row in rows
        if row["action"] == RECOVERY_ACTION_RETRY
        and row["result"] != "Approval required"
    )
    restart_count = sum(
        1
        for row in rows
        if row["action"] == RECOVERY_ACTION_RESTART
        and row["result"] != "Approval required"
    )
    return retry_count, restart_count


def _last_attempt_from_connection(connection, application_id, incident_id):
    return connection.execute(
        """
        SELECT attempted_at FROM recovery_attempts
        WHERE application_id = ? AND incident_id = ?
          AND result NOT IN ('Approval required', 'In progress',
                             'No action required')
        ORDER BY attempted_at DESC LIMIT 1
        """,
        (application_id, incident_id),
    ).fetchone()


def _cooldown_is_active(last_attempt, policy, now=None):
    if policy.cooldown_seconds <= 0:
        return False
    if last_attempt is None:
        return False
    attempted_at = _parse_timestamp(last_attempt["attempted_at"])
    current = _parse_timestamp(_timestamp(now))
    if attempted_at is None or current is None:
        raise RuntimeError("Stored recovery attempt time is invalid.")
    elapsed = (current - attempted_at).total_seconds()
    return 0 <= elapsed < policy.cooldown_seconds


def _in_cooldown(application_id, incident_id, policy, db_path, now=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        last_attempt = _last_attempt_from_connection(
            connection,
            application_id,
            incident_id,
        )
    return _cooldown_is_active(last_attempt, policy, now)


def _reserve_attempt(
    application_id,
    incident_id,
    action,
    reason,
    policy,
    db_path,
    *,
    approval_id=None,
    approval_status="Not required",
    bypass_cooldown=False,
):
    attempted_at = _timestamp()
    initialize_database(db_path)
    with closing(connect(db_path)) as connection, connection:
        connection.execute("BEGIN IMMEDIATE")
        running = connection.execute(
            """
            SELECT recovery_id, incident_id, attempted_at FROM recovery_attempts
            WHERE application_id = ? AND completed_at IS NULL
            ORDER BY attempted_at DESC LIMIT 1
            """,
            (application_id,),
        ).fetchone()
        if running:
            started_at = _parse_timestamp(running["attempted_at"])
            current_at = _parse_timestamp(attempted_at)
            age = (
                (current_at - started_at).total_seconds()
                if started_at and current_at
                else 0
            )
            if age > STALE_RUNNING_ATTEMPT_SECONDS:
                connection.execute(
                    """
                    UPDATE recovery_attempts
                    SET result = 'Recovery failed', completed_at = ?,
                        error_details = 'Recovery worker stopped before finalizing.'
                    WHERE recovery_id = ? AND completed_at IS NULL
                    """,
                    (attempted_at, running["recovery_id"]),
                )
                _timeline_event(
                    connection,
                    running["incident_id"],
                    application_id,
                    "recovery_escalated",
                    "A stale recovery attempt was marked failed",
                    "The recovery worker did not finalize within the safety timeout.",
                    source_key=f"recovery-stale:{running['recovery_id']}",
                    occurred_at=attempted_at,
                )
            else:
                raise RecoveryInProgressError(
                    f"Recovery attempt {running['recovery_id']} is already running."
                )
        if not bypass_cooldown and _cooldown_is_active(
            _last_attempt_from_connection(
                connection,
                application_id,
                incident_id,
            ),
            policy,
        ):
            raise RecoveryLimitError(
                "Recovery cooldown is active for this incident."
            )

        retry_count, restart_count = _attempt_counts_from_connection(
            connection,
            application_id,
            incident_id,
        )
        if action == RECOVERY_ACTION_RETRY and retry_count >= policy.max_retry_attempts:
            raise RecoveryLimitError(
                "The maximum health-check retry count was reached."
            )
        if (
            action == RECOVERY_ACTION_RESTART
            and restart_count >= policy.max_retry_attempts
        ):
            raise RecoveryLimitError(
                "The maximum restart attempt count was reached."
            )
        cursor = connection.execute(
            """
            INSERT INTO recovery_attempts (
                application_id, incident_id, action, result, verification,
                details, attempted_at, completed_at, decision_reason,
                approval_status, error_details, retry_count, approval_id
            ) VALUES (?, ?, ?, 'In progress', '', '', ?, NULL, ?, ?, '', 0, ?)
            """,
            (
                application_id,
                incident_id,
                action,
                attempted_at,
                str(reason),
                approval_status,
                approval_id,
            ),
        )
        return cursor.lastrowid


def _complete_attempt(
    recovery_id,
    result,
    verification,
    *,
    details="",
    error_details="",
    decision_reason="",
    approval_status="Not required",
    retry_count=0,
    verified=False,
    db_path=None,
):
    return incident_management.complete_application_recovery_attempt(
        recovery_id,
        result=result,
        verification=verification,
        details=details,
        decision_reason=decision_reason,
        approval_status=approval_status,
        error_details=error_details,
        retry_count=retry_count,
        verified=verified,
        db_path=db_path,
    )


def _record_approval_required(
    application_id,
    incident_id,
    action,
    reason,
    policy,
    db_path,
    requested_by="AIOps",
):
    approval_id = _request_approval(
        application_id,
        incident_id,
        action,
        reason,
        db_path,
        requested_by,
        DEFAULT_APPROVAL_TTL_SECONDS,
    )
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        existing_attempt = connection.execute(
            """
            SELECT recovery_id FROM recovery_attempts
            WHERE approval_id = ? AND result = 'Approval required'
            ORDER BY recovery_id DESC LIMIT 1
            """,
            (approval_id,),
        ).fetchone()
    if existing_attempt:
        return {
            "decision": "REQUIRES_APPROVAL",
            "action": action,
            "approval_id": approval_id,
            "incident_id": incident_id,
            "reason": reason,
        }
    attempt_id = _reserve_attempt(
        application_id,
        incident_id,
        action,
        reason,
        policy,
        db_path,
        approval_id=approval_id,
        approval_status="Pending",
        bypass_cooldown=True,
    )
    _complete_attempt(
        attempt_id,
        "Approval required",
        "No recovery action was executed while approval is pending.",
        details=f"Approval request ID: {approval_id}",
        decision_reason=reason,
        approval_status="Pending",
        db_path=db_path,
    )
    return {
        "decision": "REQUIRES_APPROVAL",
        "action": action,
        "approval_id": approval_id,
        "incident_id": incident_id,
        "reason": reason,
    }


def _verification_summary(reading):
    if not reading:
        return "No health reading was available."
    status = reading.get("http_status_code")
    response_time = _number(reading.get("response_time_ms"))
    status_text = f"HTTP {status}" if status is not None else "HTTP status unavailable"
    timing_text = (
        f"{response_time:.1f} ms"
        if response_time is not None
        else "response time unavailable"
    )
    return (
        f"Availability={bool(reading.get('availability'))}; "
        f"request_success={bool(reading.get('request_success'))}; "
        f"{status_text}; response_time={timing_text}; "
        f"process_id={reading.get('process_id') or 'unavailable'}."
    )


def _collect_reading(
    application,
    policy,
    db_path,
    request_function,
    process_provider,
    incident=None,
):
    from app.multi_app_monitor import monitor_application_once

    return monitor_application_once(
        application["application_id"],
        db_path=db_path,
        request_timeout=policy.verification_timeout_seconds,
        request_function=request_function,
        process_provider=process_provider,
        is_simulated=bool(incident and incident.get("is_simulated")),
        simulation_id=incident.get("simulation_id") if incident else None,
        telemetry_source=(
            "controlled_simulation_recovery"
            if incident and incident.get("is_simulated")
            else "recovery_framework"
        ),
    )


def _execute_retry(
    incident,
    application,
    policy,
    reason,
    db_path,
    request_function,
    process_provider,
    *,
    approval_id=None,
    approved=False,
    bypass_cooldown=False,
):
    if RECOVERY_ACTION_RETRY not in policy.permitted_actions:
        raise ValueError("Health-check retry is not permitted by policy.")
    retry_so_far, _ = _attempt_counts(
        application["application_id"],
        incident["incident_id"],
        db_path,
    )
    remaining = max(0, policy.max_retry_attempts - retry_so_far)
    if remaining <= 0:
        raise RecoveryLimitError("The maximum health-check retry count was reached.")
    attempt_id = _reserve_attempt(
        application["application_id"],
        incident["incident_id"],
        RECOVERY_ACTION_RETRY,
        reason,
        policy,
        db_path,
        approval_id=approval_id,
        approval_status="Approved" if approved else "Not required",
        bypass_cooldown=bypass_cooldown,
    )
    readings = []
    last_error = ""
    verified = False
    attempts_used = 0
    try:
        for _ in range(remaining):
            attempts_used += 1
            reading = _collect_reading(
                application,
                policy,
                db_path,
                request_function,
                process_provider,
                incident=incident,
            )
            readings.append(reading)
            verified, health_reasons = _health_state(reading, application)
            if verified and _process_monitoring_applicable(application):
                try:
                    process_verified, process_error = _verify_process_telemetry(
                        application,
                        reading,
                        process_provider,
                    )
                except (OSError, RuntimeError, psutil.Error) as error:
                    verified = False
                    health_reasons.append(
                        f"Owned-process verification failed: {error}"
                    )
                else:
                    if not process_verified:
                        verified = False
                        health_reasons.append(process_error)
            if verified:
                break
            last_error = "; ".join(health_reasons)
        result = "Retry verified" if verified else "Recovery failed"
        summary = _verification_summary(readings[-1] if readings else None)
        if len(readings) > 1:
            summary += f" Health checks performed: {len(readings)}."
        _complete_attempt(
            attempt_id,
            result,
            summary,
            details="Bounded GET health-check retry; no application operation was replayed.",
            decision_reason=reason,
            approval_status="Approved" if approved else "Not required",
            error_details="" if verified else last_error,
            retry_count=attempts_used,
            verified=verified,
            db_path=db_path,
        )
        return {
            "decision": "RETRY_REQUEST" if verified else "ESCALATED",
            "action": RECOVERY_ACTION_RETRY,
            "incident_id": incident["incident_id"],
            "success": verified,
            "retry_count": attempts_used,
            "verification": summary,
            "reason": reason if verified else last_error or reason,
        }
    except (OSError, RuntimeError, ValueError, sqlite3.Error, psutil.Error) as error:
        _complete_attempt(
            attempt_id,
            "Recovery failed",
            "Health-check retry did not complete successfully.",
            decision_reason=reason,
            approval_status="Approved" if approved else "Not required",
            error_details=str(error),
            retry_count=attempts_used,
            db_path=db_path,
        )
        raise


def _execute_restart(
    incident,
    application,
    policy,
    reason,
    db_path,
    request_function,
    process_provider,
    *,
    approval_id=None,
    approved=False,
    expected_pid=None,
    bypass_cooldown=False,
):
    if RECOVERY_ACTION_RESTART not in policy.permitted_actions:
        raise ValueError("Local application restart is not permitted by policy.")
    if not (
        application.get("owned_by_platform")
        and application.get("process_monitoring_permitted")
        and application.get("automatic_recovery_permitted")
    ):
        raise ValueError(
            "Restart requires platform ownership and explicit process permissions."
        )
    _, restart_count = _attempt_counts(
        application["application_id"],
        incident["incident_id"],
        db_path,
    )
    if restart_count >= policy.max_retry_attempts:
        raise RecoveryLimitError("The maximum restart attempt count was reached.")
    attempt_id = _reserve_attempt(
        application["application_id"],
        incident["incident_id"],
        RECOVERY_ACTION_RESTART,
        reason,
        policy,
        db_path,
        approval_id=approval_id,
        approval_status="Approved" if approved else "Not required",
        bypass_cooldown=bypass_cooldown,
    )
    started_pid = None
    last_reading = None
    last_error = ""
    verified = False
    try:
        started_pid = restart_registered_application(
            application,
            expected_pid=expected_pid,
            process_provider=process_provider,
        )
        deadline = time.monotonic() + policy.verification_timeout_seconds
        while True:
            last_reading = _collect_reading(
                application,
                policy,
                db_path,
                request_function,
                process_provider,
                incident=incident,
            )
            health_ok, health_reasons = _health_state(last_reading, application)
            try:
                process = verify_registered_application_process(
                    application,
                    expected_pid=started_pid,
                    process_provider=process_provider,
                )
                process_ok = process is not None
            except (OSError, RuntimeError, psutil.Error) as error:
                process_ok = False
                last_error = str(error)
            verified = health_ok and process_ok
            if verified:
                break
            if health_reasons:
                last_error = "; ".join(health_reasons)
            if time.monotonic() >= deadline:
                break
            time.sleep(
                min(
                    RECOVERY_POLL_INTERVAL_SECONDS,
                    max(0.0, deadline - time.monotonic()),
                )
            )
        summary = _verification_summary(last_reading)
        summary += (
            " Process identity verified."
            if verified
            else " Process and health verification did not both pass."
        )
        result = "Recovery successful" if verified else "Verification failed"
        if not verified and started_pid is not None:
            try:
                stop_registered_application(
                    application,
                    expected_pid=started_pid,
                    process_provider=process_provider,
                )
            except (OSError, RuntimeError, psutil.Error) as rollback_error:
                last_error = (
                    f"{last_error}; safe cleanup failed: {rollback_error}"
                    if last_error
                    else f"Safe cleanup failed: {rollback_error}"
                )
        _complete_attempt(
            attempt_id,
            result,
            summary,
            details="Restart used the registered executable directly; no shell or user command was run.",
            decision_reason=reason,
            approval_status="Approved" if approved else "Not required",
            error_details="" if verified else last_error,
            verified=verified,
            db_path=db_path,
        )
        return {
            "decision": "RESTART_APPLICATION" if verified else "ESCALATED",
            "action": RECOVERY_ACTION_RESTART,
            "incident_id": incident["incident_id"],
            "success": verified,
            "process_id": started_pid,
            "verification": summary,
            "reason": reason if verified else last_error or summary,
        }
    except (OSError, RuntimeError, ValueError, sqlite3.Error, psutil.Error) as error:
        _complete_attempt(
            attempt_id,
            "Recovery failed",
            _verification_summary(last_reading),
            details="Registered-process restart did not complete successfully.",
            decision_reason=reason,
            approval_status="Approved" if approved else "Not required",
            error_details=str(error),
            verified=False,
            db_path=db_path,
        )
        return {
            "decision": "ESCALATED",
            "action": RECOVERY_ACTION_RESTART,
            "incident_id": incident["incident_id"],
            "success": False,
            "reason": str(error),
        }


def _escalate(incident, reason, db_path, escalation_behavior="manual_intervention"):
    details = str(reason)
    if escalation_behavior == "manual_intervention":
        details += " Manual intervention is required."
    incident_management.record_incident_event(
        incident["incident_id"],
        "recovery_escalated",
        "Recovery was withheld or unsuccessful",
        details,
        db_path=db_path,
        source_key=f"recovery-escalation:{uuid.uuid4().hex}",
    )
    return {
        "decision": "ESCALATED",
        "action": None,
        "incident_id": incident["incident_id"],
        "success": False,
        "reason": details,
    }


def process_incident(
    incident_id,
    *,
    db_path=None,
    request_function=None,
    process_provider=psutil,
):
    initialize_database(db_path)
    incident = incident_management.get_incident(incident_id, db_path=db_path)
    if incident is None:
        raise KeyError(f"Incident not found: {incident_id}")
    application_id = incident["application_id"]
    if not application_id:
        return {
            "decision": "NO_ACTION",
            "action": None,
            "incident_id": incident_id,
            "reason": "Legacy incident has no registered application identity.",
        }
    lock = _application_lock(application_id)
    if not lock.acquire(blocking=False):
        return {
            "decision": "RECOVERY_IN_PROGRESS",
            "action": None,
            "incident_id": incident_id,
            "reason": "Another recovery operation for this application is active.",
        }
    try:
        return _process_incident_locked(
            incident,
            db_path,
            request_function,
            process_provider,
        )
    finally:
        lock.release()


def _process_incident_locked(
    incident,
    db_path,
    request_function,
    process_provider,
):
    incident_id = incident["incident_id"]
    application_id = incident["application_id"]
    incident = incident_management.get_incident(incident_id, db_path=db_path)
    if incident is None:
        raise KeyError(f"Incident not found: {incident_id}")
    if incident["status"] in {"Resolved", "Closed"}:
        return {
            "decision": "NO_ACTION",
            "action": None,
            "incident_id": incident_id,
            "reason": "The incident is no longer active.",
        }
    application = get_application(application_id, db_path=db_path)
    if application is None:
        return _escalate(incident, "Registered application no longer exists.", db_path)
    policy = get_recovery_policy(application_id, db_path=db_path)
    if policy is None or not policy.policy_enabled:
        return {
            "decision": "NO_ACTION",
            "action": None,
            "incident_id": incident_id,
            "reason": "No enabled recovery policy is configured.",
        }
    if not application["owned_by_platform"]:
        return _escalate(
            incident,
            "Recovery is forbidden because the application is not platform-owned.",
            db_path,
        )
    if not application["active"]:
        return _escalate(
            incident,
            "Recovery is forbidden because the application is inactive.",
            db_path,
        )

    anomaly, rca = _incident_evidence(incident, db_path)
    try:
        current_reading = _collect_reading(
            application,
            policy,
            db_path,
            request_function,
            process_provider,
            incident=incident,
        )
    except (OSError, RuntimeError, ValueError, sqlite3.Error, psutil.Error) as error:
        return _escalate(
            incident,
            f"Could not obtain a fresh application health reading: {error}",
            db_path,
            policy.escalation_behavior,
        )
    healthy, health_reasons = _health_state(current_reading, application)
    if healthy:
        return {
            "decision": "NO_ACTION",
            "action": None,
            "incident_id": incident_id,
            "reason": "A fresh health check passed; no recovery action was needed.",
            "verification": _verification_summary(current_reading),
        }
    if _in_cooldown(application_id, incident_id, policy, db_path):
        return {
            "decision": "COOLDOWN",
            "action": None,
            "incident_id": incident_id,
            "reason": "Recovery cooldown is active; no action was repeated.",
        }

    issue = "; ".join(health_reasons) or "The current application health check failed."
    root_cause = str(
        rca.get("root_cause")
        or rca.get("suspected_root_cause")
        or incident.get("root_cause")
        or anomaly.get("explanation")
        or "No additional RCA evidence is available."
    )
    decision_reason = (
        f"Current health evidence: {issue} RCA/anomaly context: {root_cause}"
    )
    had_failed_action = False
    retry_count, restart_count = _attempt_counts(
        application_id,
        incident_id,
        db_path,
    )

    if RECOVERY_ACTION_RETRY in policy.permitted_actions:
        if retry_count < policy.max_retry_attempts:
            if _approval_required(RECOVERY_ACTION_RETRY, policy):
                return _record_approval_required(
                    application_id,
                    incident_id,
                    RECOVERY_ACTION_RETRY,
                    decision_reason,
                    policy,
                    db_path,
                )
            try:
                retry_result = _execute_retry(
                    incident,
                    application,
                    policy,
                    decision_reason,
                    db_path,
                    request_function,
                    process_provider,
                )
            except RecoveryLimitError as error:
                had_failed_action = True
                retry_reason = str(error)
            except RecoveryInProgressError:
                return {
                    "decision": "RECOVERY_IN_PROGRESS",
                    "action": RECOVERY_ACTION_RETRY,
                    "incident_id": incident_id,
                    "reason": "Another recovery operation is active.",
                }
            else:
                if retry_result["success"]:
                    return retry_result
                had_failed_action = True
                retry_reason = retry_result["reason"]
        else:
            had_failed_action = True
            retry_reason = "Health-check retries are exhausted."

    repeated = _repeated_degradation(
        incident,
        application,
        current_reading,
        db_path,
    )
    if (
        RECOVERY_ACTION_RESTART in policy.permitted_actions
        and restart_count < policy.max_retry_attempts
        and _restart_is_justified(incident, application, rca, repeated)
    ):
        restart_reason = (
            f"{decision_reason} Restart requires sustained high-severity "
            "evidence and a verified local process identity."
        )
        if _approval_required(RECOVERY_ACTION_RESTART, policy):
            return _record_approval_required(
                application_id,
                incident_id,
                RECOVERY_ACTION_RESTART,
                restart_reason,
                policy,
                db_path,
            )
        try:
            return _execute_restart(
                incident,
                application,
                policy,
                restart_reason,
                db_path,
                request_function,
                process_provider,
                expected_pid=current_reading.get("process_id"),
                bypass_cooldown=had_failed_action,
            )
        except RecoveryInProgressError:
            return {
                "decision": "RECOVERY_IN_PROGRESS",
                "action": RECOVERY_ACTION_RESTART,
                "incident_id": incident_id,
                "reason": "Another recovery operation is active.",
            }
        except RecoveryLimitError as error:
            return _escalate(incident, str(error), db_path, policy.escalation_behavior)

    if not had_failed_action and not policy.permitted_actions:
        issue = "No recovery actions are permitted by policy. " + decision_reason
    elif not had_failed_action and RECOVERY_ACTION_RESTART in policy.permitted_actions:
        issue = (
            "Restart was withheld because severity, repeated-failure, RCA, or "
            "local process-identity requirements were not met. "
            + decision_reason
        )
    elif had_failed_action:
        issue = f"{retry_reason} {decision_reason}"
    return _escalate(
        incident,
        issue,
        db_path,
        policy.escalation_behavior,
    )


def execute_approved_recovery(
    approval_id,
    *,
    db_path=None,
    request_function=None,
    process_provider=psutil,
):
    request = get_approval_request(approval_id, db_path=db_path)
    if request is None:
        raise KeyError(f"Approval request not found: {approval_id}")
    if request["status"] != "Approved":
        raise ValueError(
            "Only an approved, unexpired recovery request can be executed."
        )
    expiry = _parse_timestamp(request["expires_at"])
    if expiry is None or expiry <= _utc_now():
        current_time = _timestamp()
        with closing(connect(db_path)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                UPDATE approval_requests
                SET status = 'Expired', decided_at = ?, decided_by = 'system',
                    decision_details = 'Approved request expired before execution.'
                WHERE approval_id = ? AND status = 'Approved'
                """,
                (current_time, approval_id),
            )
            _timeline_event(
                connection,
                request["incident_id"],
                request["application_id"],
                "approval_expired",
                f"Approved request {approval_id} expired before execution",
                "No recovery action was executed after the approval expiry.",
                source_key=f"approval-expired:{approval_id}",
                occurred_at=current_time,
            )
        raise ValueError("The approved recovery request has expired.")
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        used = connection.execute(
            """
            SELECT recovery_id FROM recovery_attempts
            WHERE approval_id = ? AND result <> 'Approval required'
            """,
            (approval_id,),
        ).fetchone()
    if used:
        raise ValueError("This approval request has already been used.")

    application = get_application(request["application_id"], db_path=db_path)
    incident = incident_management.get_incident(request["incident_id"], db_path=db_path)
    policy = get_recovery_policy(request["application_id"], db_path=db_path)
    if (
        application is None
        or incident is None
        or policy is None
        or not policy.policy_enabled
        or request["action"] not in policy.permitted_actions
    ):
        raise ValueError(
            "Current application state or policy no longer permits this action."
        )
    if incident["status"] in {"Resolved", "Closed"}:
        raise ValueError("Cannot recover an incident that is already closed.")
    if not application["owned_by_platform"] or not application["active"]:
        raise ValueError("Recovery requires an active platform-owned application.")
    lock = _application_lock(request["application_id"])
    if not lock.acquire(blocking=False):
        return {
            "decision": "RECOVERY_IN_PROGRESS",
            "action": request["action"],
            "incident_id": request["incident_id"],
            "reason": "Another recovery operation for this application is active.",
        }
    try:
        current_reading = _collect_reading(
            application,
            policy,
            db_path,
            request_function,
            process_provider,
            incident=incident,
        )
        healthy, reasons = _health_state(current_reading, application)
        if healthy:
            return {
                "decision": "NO_ACTION",
                "action": request["action"],
                "incident_id": request["incident_id"],
                "reason": "A fresh health check passed; the approved action was withheld.",
                "verification": _verification_summary(current_reading),
            }
        if _in_cooldown(
            request["application_id"],
            request["incident_id"],
            policy,
            db_path,
        ):
            return {
                "decision": "COOLDOWN",
                "action": request["action"],
                "incident_id": request["incident_id"],
                "reason": "Recovery cooldown is active; the approved action was withheld.",
            }

        reason = (
            f"Operator {request['decided_by']} approved after revalidation. "
            f"Current health evidence: {'; '.join(reasons)}"
        )
        if request["action"] == RECOVERY_ACTION_RETRY:
            return _execute_retry(
                incident,
                application,
                policy,
                reason,
                db_path,
                request_function,
                process_provider,
                approval_id=approval_id,
                approved=True,
            )

        _, rca = _incident_evidence(incident, db_path)
        repeated = _repeated_degradation(
            incident,
            application,
            current_reading,
            db_path,
        )
        if not _restart_is_justified(incident, application, rca, repeated):
            return _escalate(
                incident,
                "Approved restart was withheld because current safety evidence "
                "does not justify a process restart.",
                db_path,
                policy.escalation_behavior,
            )
        return _execute_restart(
            incident,
            application,
            policy,
            reason,
            db_path,
            request_function,
            process_provider,
            approval_id=approval_id,
            approved=True,
            expected_pid=current_reading.get("process_id"),
        )
    finally:
        lock.release()


def get_recovery_history(
    *,
    application_id=None,
    incident_id=None,
    db_path=None,
):
    initialize_database(db_path)
    conditions = []
    parameters = []
    if application_id is not None:
        conditions.append("application_id = ?")
        parameters.append(application_id)
    if incident_id is not None:
        conditions.append("incident_id = ?")
        parameters.append(incident_id)
    query = "SELECT * FROM recovery_attempts"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY attempted_at DESC, recovery_id DESC"
    with closing(connect(db_path)) as connection:
        rows = connection.execute(query, parameters).fetchall()
    return [dict(row) for row in rows]


evaluate_incident_recovery = process_incident
