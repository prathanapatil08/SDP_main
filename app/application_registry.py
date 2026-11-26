import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from app.database import (
    LEGACY_FLASK_APPLICATION_ID,
    connect,
    initialize_database,
)


SUPPORTED_APPLICATION_TYPES = (
    "HTTP_WEBSITE",
    "HTTPS_WEBSITE",
    "REST_API",
    "CONTROLLED_LOCAL_APPLICATION",
)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def generate_application_id():
    return f"APP-{uuid.uuid4().hex.upper()}"


def _validate_application(name, url, application_type, interval):
    if not str(name).strip():
        raise ValueError("Application name is required.")
    if not str(url).strip():
        raise ValueError("Application URL or health endpoint is required.")
    application_type = str(application_type).strip().upper()
    if application_type not in SUPPORTED_APPLICATION_TYPES:
        raise ValueError(
            f"Unsupported application type: {application_type}. "
            f"Supported types: {', '.join(SUPPORTED_APPLICATION_TYPES)}"
        )
    try:
        interval = int(interval)
    except (TypeError, ValueError) as error:
        raise ValueError("Monitoring interval must be a positive integer.") from error
    if interval <= 0:
        raise ValueError("Monitoring interval must be a positive integer.")

    if application_type in ("HTTP_WEBSITE", "HTTPS_WEBSITE", "REST_API"):
        parsed = urlparse(str(url).strip())
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError("HTTP/HTTPS applications require a valid absolute URL.")


def _validate_ownership(
    owned_by_platform,
    process_monitoring_permitted,
    automatic_recovery_permitted,
    process_name,
    process_executable_path,
):
    if (process_monitoring_permitted or automatic_recovery_permitted) and not owned_by_platform:
        raise ValueError(
            "Process monitoring and automatic recovery require platform ownership."
        )
    if process_monitoring_permitted and not (
        process_name or process_executable_path
    ):
        raise ValueError(
            "Process monitoring requires a process name or executable path."
        )


def register_application(
    name,
    url,
    application_type="REST_API",
    monitoring_interval_seconds=5,
    monitoring_enabled=True,
    owned_by_platform=False,
    process_monitoring_permitted=False,
    automatic_recovery_permitted=False,
    process_name=None,
    process_executable_path=None,
    process_working_directory=None,
    endpoint_path=None,
    application_id=None,
    db_path=None,
):
    application_type = str(application_type).strip().upper()
    _validate_application(
        name,
        url,
        application_type,
        monitoring_interval_seconds,
    )
    _validate_ownership(
        owned_by_platform,
        process_monitoring_permitted,
        automatic_recovery_permitted,
        process_name,
        process_executable_path,
    )

    initialize_database(db_path)
    application_id = application_id or generate_application_id()
    now = _now()
    with closing(connect(db_path)) as connection, connection:
        existing = connection.execute(
            "SELECT application_id FROM applications WHERE application_id = ?",
            (application_id,),
        ).fetchone()
        if existing:
            raise ValueError(f"Application ID already exists: {application_id}")

        connection.execute(
            """
            INSERT INTO applications (
                application_id, name, application_type, url,
                monitoring_interval_seconds, active, owned_by_platform,
                process_monitoring_permitted, automatic_recovery_permitted,
                process_name, process_executable_path,
                process_working_directory, endpoint_path,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                application_id,
                str(name).strip(),
                application_type,
                str(url).strip(),
                int(monitoring_interval_seconds),
                1 if monitoring_enabled else 0,
                1 if owned_by_platform else 0,
                1 if process_monitoring_permitted else 0,
                1 if automatic_recovery_permitted else 0,
                process_name,
                process_executable_path,
                process_working_directory,
                endpoint_path,
                now,
                now,
            ),
        )

        parsed = urlparse(str(url).strip())
        connection.execute(
            """
            INSERT INTO application_endpoints (
                application_id, name, url, protocol, health_path,
                timeout_seconds, active, created_at, updated_at
            ) VALUES (?, 'Primary endpoint', ?, ?, ?, 2, 1, ?, ?)
            """,
            (
                application_id,
                str(url).strip(),
                parsed.scheme or "local",
                endpoint_path,
                now,
                now,
            ),
        )
        if process_name or process_executable_path or process_working_directory:
            connection.execute(
                """
                INSERT INTO application_processes (
                    application_id, process_name, executable_path,
                    working_directory, active, created_at, updated_at
                ) VALUES (?, ?, ?, ?, 1, ?, ?)
                """,
                (
                    application_id,
                    process_name,
                    process_executable_path,
                    process_working_directory,
                    now,
                    now,
                ),
            )
    return get_application(application_id, db_path=db_path)


def get_application(application_id, db_path=None):
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM applications WHERE application_id = ?",
            (application_id,),
        ).fetchone()
    return dict(row) if row else None


def get_applications(db_path=None, include_inactive=True):
    with closing(connect(db_path)) as connection:
        query = "SELECT * FROM applications"
        if not include_inactive:
            query += " WHERE active = 1"
        query += " ORDER BY created_at, name"
        rows = connection.execute(query).fetchall()
    return [dict(row) for row in rows]


def list_applications(db_path=None, include_inactive=True):
    return get_applications(db_path, include_inactive)


def update_application(application_id, db_path=None, **changes):
    allowed = {
        "name",
        "url",
        "application_type",
        "monitoring_interval_seconds",
        "monitoring_enabled",
        "owned_by_platform",
        "process_monitoring_permitted",
        "automatic_recovery_permitted",
        "process_name",
        "process_executable_path",
        "process_working_directory",
        "endpoint_path",
        "active",
    }
    unknown = set(changes).difference(allowed)
    if unknown:
        raise ValueError(
            "Unsupported application fields: " + ", ".join(sorted(unknown))
        )

    current = get_application(application_id, db_path=db_path)
    if current is None:
        raise KeyError(f"Application not found: {application_id}")

    monitoring_enabled = changes.get(
        "monitoring_enabled",
        None,
    )
    if monitoring_enabled is None:
        active_value = changes.get("active", bool(current["active"]))
    else:
        active_value = monitoring_enabled
    merged = {
        "name": changes.get("name", current["name"]),
        "url": changes.get("url", current["url"]),
        "application_type": changes.get(
            "application_type", current["application_type"]
        ).strip().upper(),
        "monitoring_interval_seconds": changes.get(
            "monitoring_interval_seconds",
            current["monitoring_interval_seconds"],
        ),
        "owned_by_platform": changes.get(
            "owned_by_platform", bool(current["owned_by_platform"])
        ),
        "process_monitoring_permitted": changes.get(
            "process_monitoring_permitted",
            bool(current["process_monitoring_permitted"]),
        ),
        "automatic_recovery_permitted": changes.get(
            "automatic_recovery_permitted",
            bool(current["automatic_recovery_permitted"]),
        ),
        "process_name": changes.get("process_name", current["process_name"]),
        "process_executable_path": changes.get(
            "process_executable_path",
            current["process_executable_path"],
        ),
        "process_working_directory": changes.get(
            "process_working_directory",
            current["process_working_directory"],
        ),
        "endpoint_path": changes.get("endpoint_path", current["endpoint_path"]),
        "active": active_value,
    }

    _validate_application(
        merged["name"],
        merged["url"],
        merged["application_type"],
        merged["monitoring_interval_seconds"],
    )
    _validate_ownership(
        merged["owned_by_platform"],
        merged["process_monitoring_permitted"],
        merged["automatic_recovery_permitted"],
        merged["process_name"],
        merged["process_executable_path"],
    )

    now = _now()
    active = 1 if bool(merged["active"]) else 0
    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            """
            UPDATE applications
            SET name = ?, url = ?, application_type = ?,
                monitoring_interval_seconds = ?, active = ?,
                owned_by_platform = ?, process_monitoring_permitted = ?,
                automatic_recovery_permitted = ?, process_name = ?,
                process_executable_path = ?, process_working_directory = ?,
                endpoint_path = ?, updated_at = ?,
                deactivated_at = CASE WHEN ? = 1 THEN deactivated_at ELSE NULL END
            WHERE application_id = ?
            """,
            (
                merged["name"],
                merged["url"],
                merged["application_type"],
                int(merged["monitoring_interval_seconds"]),
                active,
                1 if merged["owned_by_platform"] else 0,
                1 if merged["process_monitoring_permitted"] else 0,
                1 if merged["automatic_recovery_permitted"] else 0,
                merged["process_name"],
                merged["process_executable_path"],
                merged["process_working_directory"],
                merged["endpoint_path"],
                now,
                active,
                application_id,
            ),
        )

        parsed = urlparse(str(merged["url"]).strip())
        connection.execute(
            """
            UPDATE application_endpoints
            SET url = ?, protocol = ?, health_path = ?, active = ?,
                updated_at = ?
            WHERE application_id = ? AND active = 1
            """,
            (
                str(merged["url"]).strip(),
                parsed.scheme or "local",
                merged["endpoint_path"],
                active,
                now,
                application_id,
            ),
        )
        connection.execute(
            "UPDATE application_processes SET active = ?, updated_at = ? "
            "WHERE application_id = ?",
            (active, now, application_id),
        )
    return get_application(application_id, db_path=db_path)


def deactivate_application(application_id, db_path=None):
    now = _now()
    with closing(connect(db_path)) as connection, connection:
        current = connection.execute(
            "SELECT active, deactivated_at FROM applications "
            "WHERE application_id = ?",
            (application_id,),
        ).fetchone()
        if current is None:
            raise KeyError(f"Application not found: {application_id}")
        if not current["active"] and current["deactivated_at"]:
            return False
        connection.execute(
            """
            UPDATE applications
            SET active = 0, updated_at = ?, deactivated_at = ?
            WHERE application_id = ?
            """,
            (now, now, application_id),
        )
        connection.execute(
            "UPDATE application_endpoints SET active = 0, updated_at = ? "
            "WHERE application_id = ?",
            (now, application_id),
        )
        connection.execute(
            "UPDATE application_processes SET active = 0, updated_at = ? "
            "WHERE application_id = ?",
            (now, application_id),
        )
    return True


def remove_application(application_id, db_path=None):
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT active FROM applications WHERE application_id = ?",
            (application_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Application not found: {application_id}")
        if row["active"]:
            raise ValueError("Deactivate the application before removing it.")

        referenced = {}
        for table, label in (
            ("incidents", "incidents"),
            ("application_telemetry", "telemetry"),
            ("anomaly_results", "anomaly results"),
            ("root_cause_reports", "root-cause reports"),
            ("recovery_attempts", "recovery attempts"),
        ):
            count = connection.execute(
                f"SELECT COUNT(*) FROM {table} WHERE application_id = ?",
                (application_id,),
            ).fetchone()[0]
            if count:
                referenced[label] = count
        if referenced:
            raise ValueError(
                "Cannot remove an application with retained records: "
                + ", ".join(
                    f"{label}={count}"
                    for label, count in referenced.items()
                )
            )

    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            "DELETE FROM applications WHERE application_id = ?",
            (application_id,),
        )
    return True


def migrate_existing_flask_application(db_path=None):
    initialize_database(db_path)
    existing = get_application(
        LEGACY_FLASK_APPLICATION_ID,
        db_path=db_path,
    )
    project_root = str(Path(__file__).resolve().parent.parent)
    values = {
        "name": "SDP Flask Application",
        "url": "http://127.0.0.1:5000",
        "application_type": "REST_API",
        "monitoring_interval_seconds": 5,
        "monitoring_enabled": True,
        "owned_by_platform": True,
        "process_monitoring_permitted": True,
        "automatic_recovery_permitted": True,
        "process_name": "python.exe",
        "process_working_directory": project_root,
        "endpoint_path": "/health",
    }
    if existing is None:
        existing = register_application(
            **values,
            application_id=LEGACY_FLASK_APPLICATION_ID,
            db_path=db_path,
        )
    else:
        existing = update_application(
            LEGACY_FLASK_APPLICATION_ID,
            db_path=db_path,
            **values,
        )

    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            """
            UPDATE incidents
            SET application_id = ?
            WHERE application_id IS NULL OR application_id = ''
            """,
            (LEGACY_FLASK_APPLICATION_ID,),
        )
        connection.execute(
            """
            UPDATE incident_events
            SET application_id = ?
            WHERE application_id IS NULL OR application_id = ''
            """,
            (LEGACY_FLASK_APPLICATION_ID,),
        )
    return existing
