import math
from contextlib import closing
from datetime import datetime, timedelta, timezone

from app.browser_discovery import normalize_origin
from app.database import connect, initialize_database
from app.multi_app_monitor import store_application_telemetry


PAGE_METRICS_SOURCE = "browser_page_metrics"
MAX_FUTURE_TIMESTAMP_SKEW = timedelta(minutes=5)


def validate_page_metrics(payload, *, now=None):
    if not isinstance(payload, dict):
        raise ValueError("A JSON object is required.")

    try:
        origin, hostname = normalize_origin(payload.get("origin"))
    except ValueError as error:
        raise ValueError("A valid website origin is required.") from error

    if payload.get("hostname") != hostname:
        raise ValueError("Hostname does not match the website origin.")
    if payload.get("page_url") != origin:
        raise ValueError("Page URL must be the website origin only.")

    timestamp = payload.get("timestamp")
    if not isinstance(timestamp, str) or len(timestamp) > 40:
        raise ValueError("An ISO 8601 measurement timestamp is required.")
    try:
        measured_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("Measurement timestamp must be ISO 8601.") from error
    if measured_at.tzinfo is None or measured_at.utcoffset() is None:
        raise ValueError("Measurement timestamp must include a timezone.")
    current_time = now or datetime.now(timezone.utc)
    if measured_at > current_time + MAX_FUTURE_TIMESTAMP_SKEW:
        raise ValueError("Measurement timestamp is too far in the future.")

    interval = payload.get("measurement_interval_seconds")
    if (
        isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not 0 < interval <= 3600
        or isinstance(interval, float)
        and not math.isfinite(interval)
    ):
        raise ValueError("Measurement interval must be between 0 and 3600 seconds.")

    heap_available = payload.get("javascript_heap_available")
    long_tasks_available = payload.get("long_tasks_available")
    if not isinstance(heap_available, bool) or not isinstance(long_tasks_available, bool):
        raise ValueError("Metric availability flags must be booleans.")

    heap_bytes = payload.get("javascript_heap_used_bytes")
    long_task_count = payload.get("long_task_count")
    duration_ms = payload.get("total_long_task_duration_ms")

    def finite_nonnegative(value, label):
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or value < 0
            or value > 9_007_199_254_740_991
            or isinstance(value, float) and not math.isfinite(value)
        ):
            raise ValueError(f"{label} must be a finite nonnegative number.")
        return value

    if heap_available:
        heap_bytes = finite_nonnegative(heap_bytes, "JavaScript heap usage")
    elif heap_bytes is not None:
        raise ValueError("Unavailable JavaScript heap usage must be null.")

    if long_tasks_available:
        if (
            isinstance(long_task_count, bool)
            or not isinstance(long_task_count, int)
            or long_task_count < 0
        ):
            raise ValueError("Long-task count must be a nonnegative integer.")
        duration_ms = finite_nonnegative(duration_ms, "Long-task duration")
    elif long_task_count is not None or duration_ms is not None:
        raise ValueError("Unavailable long-task metrics must be null.")

    if heap_available and heap_bytes is None:
        raise ValueError("Available JavaScript heap usage is required.")
    if long_tasks_available and (long_task_count is None or duration_ms is None):
        raise ValueError("Available long-task metrics are required.")

    return {
        "origin": origin,
        "hostname": hostname,
        "timestamp": measured_at.astimezone(timezone.utc).isoformat(),
        "measurement_interval_seconds": interval,
        "javascript_heap_used_bytes": heap_bytes,
        "javascript_heap_available": heap_available,
        "long_task_count": long_task_count,
        "total_long_task_duration_ms": duration_ms,
        "long_tasks_available": long_tasks_available,
    }


def store_browser_page_metrics(payload, db_path=None, *, now=None):
    reading = validate_page_metrics(payload, now=now)
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT a.application_id
            FROM discovered_applications AS d
            JOIN applications AS a ON a.application_id = d.application_id
            LEFT JOIN discovery_exclusions AS e
              ON e.origin = d.origin AND e.restored_at IS NULL
            WHERE d.origin = ?
              AND d.registration_status IN ('registered', 'existing')
              AND d.monitoring_status = 'enabled'
              AND d.user_excluded = 0
              AND e.origin IS NULL
              AND a.active = 1
            """,
            (reading["origin"],),
        ).fetchone()
    if row is None:
        raise ValueError(
            "Website is not registered, monitored, and authorized for telemetry."
        )

    reading["application_id"] = row["application_id"]
    store_application_telemetry(
        reading,
        db_path=db_path,
        source=PAGE_METRICS_SOURCE,
    )
    return {
        "accepted": True,
        "application_id": row["application_id"],
        "origin": reading["origin"],
        "timestamp": reading["timestamp"],
    }
