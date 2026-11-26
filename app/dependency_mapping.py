import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from app.database import connect, initialize_database


SERVICE_LABELS = {
    "host_resources": "Host resources",
    "flask_api": "Flask API",
    "monitoring_pipeline": "Monitoring pipeline",
    "metrics_store": "Metrics CSV",
    "anomaly_detector": "Isolation Forest",
    "anomaly_results": "Anomaly results",
    "root_cause_analysis": "Root cause analysis",
    "rca_reports": "RCA reports",
    "incident_ledger": "Incident ledger (SQLite)",
    "recovery_policy": "Recovery policy",
    "dashboard": "Streamlit dashboard",
    "incident_management_ui": "Incident management controls",
}

# Each component lists the components it consumes or requires.
SERVICE_DEPENDENCIES = {
    "host_resources": (),
    "flask_api": ("host_resources",),
    "monitoring_pipeline": ("host_resources",),
    "metrics_store": ("monitoring_pipeline",),
    "anomaly_detector": ("metrics_store",),
    "anomaly_results": ("anomaly_detector",),
    "root_cause_analysis": ("metrics_store", "anomaly_results", "incident_ledger"),
    "rca_reports": ("root_cause_analysis",),
    "incident_ledger": (),
    "recovery_policy": ("flask_api", "metrics_store", "incident_ledger"),
    "dashboard": (
        "metrics_store",
        "anomaly_results",
        "rca_reports",
        "incident_ledger",
    ),
    "incident_management_ui": ("dashboard", "incident_ledger"),
}

CORRELATABLE_STATES = {
    "critical",
    "degraded",
    "down",
    "stale",
    "unavailable",
}


def dependency_rows(component_states):
    rows = []
    for component, dependencies in SERVICE_DEPENDENCIES.items():
        rows.append(
            {
                "Component": SERVICE_LABELS[component],
                "Depends on": (
                    ", ".join(SERVICE_LABELS[item] for item in dependencies)
                    or "None"
                ),
                "Current signal": component_states.get(component, "Unknown"),
            }
        )
    return rows


def _depends_on(component, target, visited=None):
    visited = set() if visited is None else visited
    if component in visited:
        return False
    visited.add(component)
    for dependency in SERVICE_DEPENDENCIES.get(component, ()):
        if dependency == target or _depends_on(dependency, target, visited):
            return True
    return False


def correlate_component_events(events):
    impaired = {
        event["component"]: event
        for event in events
        if event.get("status", "").lower() in CORRELATABLE_STATES
        and event.get("component") in SERVICE_DEPENDENCIES
    }

    correlations = []
    for root_component, root_event in impaired.items():
        affected = [
            component
            for component in impaired
            if component != root_component
            and _depends_on(component, root_component)
        ]
        if not affected:
            continue

        correlations.append(
            {
                "root_component": root_component,
                "root_label": SERVICE_LABELS[root_component],
                "root_status": root_event["status"],
                "root_evidence": root_event["summary"],
                "affected_components": affected,
                "affected_labels": [
                    SERVICE_LABELS[component] for component in affected
                ],
                "affected_evidence": [
                    impaired[component]["summary"] for component in affected
                ],
                "confidence": "possible",
            }
        )
    return correlations


def get_application_dependencies(application_id, db_path=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT d.application_id, d.depends_on_application_id,
                   d.dependency_type, a.name AS dependency_name,
                   a.application_type, a.active AS dependency_active
            FROM application_dependencies d
            JOIN applications a
              ON a.application_id = d.depends_on_application_id
            WHERE d.application_id = ? AND d.active = 1
            ORDER BY a.name, d.dependency_type
            """,
            (application_id,),
        ).fetchall()
    return [dict(row) for row in rows]


def _dependency_rows(connection, application_id):
    rows = connection.execute(
        """
        SELECT d.application_id, d.depends_on_application_id,
               d.dependency_type, a.name AS dependency_name,
               a.application_type, a.active AS dependency_active
        FROM application_dependencies d
        JOIN applications a
          ON a.application_id = d.depends_on_application_id
        WHERE d.application_id = ? AND d.active = 1
        ORDER BY a.name, d.dependency_type
        """,
        (application_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _dependency_closure(connection, application_id):
    dependencies = []
    visited = {application_id}

    def visit(parent_id, depth):
        for item in _dependency_rows(connection, parent_id):
            dependency_id = item["depends_on_application_id"]
            if dependency_id in visited:
                continue
            visited.add(dependency_id)
            dependency = {**item, "depth": depth}
            dependencies.append(dependency)
            visit(dependency_id, depth + 1)

    visit(application_id, 1)
    return dependencies


def get_application_dependency_closure(application_id, db_path=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        return _dependency_closure(connection, application_id)


def add_application_dependency(
    application_id,
    depends_on_application_id,
    dependency_type="service",
    db_path=None,
):
    if not application_id or not depends_on_application_id:
        raise ValueError("Both application IDs are required.")
    if application_id == depends_on_application_id:
        raise ValueError("An application cannot depend on itself.")

    initialize_database(db_path)
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with closing(connect(db_path)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        closure = _dependency_closure(
            connection,
            depends_on_application_id,
        )
        if any(
            dependency["depends_on_application_id"] == application_id
            for dependency in closure
        ):
            connection.rollback()
            raise ValueError(
                "The dependency would create a circular relationship."
            )
        try:
            connection.execute(
                """
                INSERT INTO application_dependencies (
                    application_id, depends_on_application_id,
                    dependency_type, active, created_at, updated_at
                ) VALUES (?, ?, ?, 1, ?, ?)
                """,
                (
                    application_id,
                    depends_on_application_id,
                    str(dependency_type).strip() or "service",
                    now,
                    now,
                ),
            )
            connection.commit()
        except sqlite3.IntegrityError as error:
            connection.rollback()
            if "FOREIGN KEY constraint failed" in str(error):
                raise KeyError("Both dependency applications must be registered.") from error
            if "UNIQUE constraint failed" in str(error):
                raise ValueError("This application dependency already exists.") from error
            raise
    return get_application_dependencies(application_id, db_path=db_path)
