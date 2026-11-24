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
