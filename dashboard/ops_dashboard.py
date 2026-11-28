import html
import json
import math
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh

from app.browser_discovery import (
    approve_discovery,
    configure_discovery,
    exclude_discovery,
    get_discovery_history,
    get_discovery_settings,
    ignore_discovery,
    list_discovered_applications,
    list_open_tabs,
    restore_discovery,
)
from app.browser_process_metrics import sample_chrome_process_metrics
from app.database import connect
from app.health_forecast import forecast_threshold_crossings
from testing_website.demo_app import DEMO_APPLICATIONS


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_FILE = BASE_DIR / "data" / "incidents.sqlite3"
SYSTEM_METRICS_FILE = BASE_DIR / "data" / "metrics.csv"
REFRESH_INTERVAL_MS = 15_000
ACTIVE_INCIDENT_STATUSES = {"Open", "Acknowledged", "Investigating", "Monitoring"}

PAGES = (
    "Overview Dashboard",
    "Application Registry",
    "Automatic Application Discovery",
    "Multi-Application Monitoring",
    "Performance Analytics",
    "AI Anomaly Detection",
    "Root Cause Analysis",
    "Incident Management",
    "Autonomous Self-Healing",
    "Fault Simulation Lab",
    "Application Dependency Map",
    "Reports and Analytics",
)

PAGE_ICONS = {
    "Overview Dashboard": "✦",
    "Application Registry": "◈",
    "Automatic Application Discovery": "⌕",
    "Multi-Application Monitoring": "◉",
    "Performance Analytics": "⌁",
    "AI Anomaly Detection": "✳",
    "Root Cause Analysis": "⌕",
    "Incident Management": "◷",
    "Autonomous Self-Healing": "⟳",
    "Fault Simulation Lab": "⚗",
    "Application Dependency Map": "⌘",
    "Reports and Analytics": "▤",
}

ACCENTS = (
    ("#eef2ff", "#6366f1", "✦"),
    ("#e9fbf7", "#0f9f8f", "◉"),
    ("#fff4e8", "#f28a32", "↗"),
    ("#f2edff", "#8b5cf6", "◈"),
)


@st.cache_data(ttl=5, show_spinner=False)
def load_snapshot():
    if not DATABASE_FILE.exists():
        raise FileNotFoundError(f"Project database not found: {DATABASE_FILE}")

    queries = {
        "applications": """
            SELECT * FROM applications ORDER BY name COLLATE NOCASE
        """,
        "telemetry": """
            SELECT telemetry_id, application_id, source, timestamp,
                   data_json, is_simulated
            FROM application_telemetry
            ORDER BY timestamp DESC, telemetry_id DESC LIMIT 5000
        """,
        "models": """
            SELECT application_id, algorithm, model_version,
                   training_sample_count, trained_through_timestamp,
                   trained_at, updated_at, features_json, config_json
            FROM application_models ORDER BY updated_at DESC
        """,
        "anomalies": """
            SELECT anomaly_id, application_id, timestamp, prediction,
                   anomaly_score, status, data_json, is_simulated, created_at
            FROM anomaly_results
            ORDER BY timestamp DESC, anomaly_id DESC LIMIT 1000
        """,
        "rca_reports": """
            SELECT report_id, application_id, incident_id, source_timestamp,
                   severity, root_cause, recommended_action, data_json,
                   is_simulated, created_at
            FROM root_cause_reports
            ORDER BY created_at DESC, report_id DESC LIMIT 500
        """,
        "incidents": """
            SELECT * FROM incidents
            ORDER BY updated_at DESC, created_at DESC LIMIT 1000
        """,
        "incident_events": """
            SELECT event_id, incident_id, application_id, occurred_at,
                   event_type, summary, details, anomaly_id, rca_report_id
            FROM incident_events
            ORDER BY occurred_at DESC, event_id DESC LIMIT 5000
        """,
        "recovery_attempts": """
            SELECT r.*, COALESCE(i.is_simulated, 0) AS is_simulated
            FROM recovery_attempts AS r
            LEFT JOIN incidents AS i ON i.incident_id = r.incident_id
            ORDER BY r.attempted_at DESC, r.recovery_id DESC LIMIT 1000
        """,
        "approvals": """
            SELECT a.*, COALESCE(i.is_simulated, 0) AS is_simulated
            FROM approval_requests AS a
            LEFT JOIN incidents AS i ON i.incident_id = a.incident_id
            ORDER BY a.requested_at DESC LIMIT 500
        """,
        "simulations": """
            SELECT simulation_id, application_id, simulation_type, status,
                   started_at, ended_at, data_json, is_simulated, created_at
            FROM simulation_events
            ORDER BY started_at DESC, simulation_id DESC LIMIT 500
        """,
        "dependencies": """
            SELECT dependency_id, application_id, depends_on_application_id,
                   dependency_type, active, created_at, updated_at
            FROM application_dependencies
            ORDER BY application_id, depends_on_application_id
        """,
    }

    with closing(connect(DATABASE_FILE)) as connection:
        results = {
            key: [dict(row) for row in connection.execute(query).fetchall()]
            for key, query in queries.items()
        }

    invalid_json = 0
    for collection, column in (
        ("telemetry", "data"),
        ("anomalies", "details"),
        ("rca_reports", "details"),
        ("simulations", "details"),
    ):
        for row in results[collection]:
            try:
                decoded = json.loads(row.pop("data_json"))
                if not isinstance(decoded, dict):
                    raise ValueError("JSON payload is not an object")
                row[column] = decoded
            except (TypeError, ValueError, json.JSONDecodeError):
                row[column] = {}
                invalid_json += 1

    for model in results["models"]:
        for field in ("features_json", "config_json"):
            try:
                model[field.removesuffix("_json")] = json.loads(model.pop(field))
            except (TypeError, ValueError, json.JSONDecodeError):
                model[field.removesuffix("_json")] = None
                invalid_json += 1

    return {**results, "invalid_json_count": invalid_json}


@st.cache_data(ttl=5, show_spinner=False)
def load_system_metrics():
    if not SYSTEM_METRICS_FILE.exists():
        return pd.DataFrame(), None
    try:
        frame = pd.read_csv(SYSTEM_METRICS_FILE, low_memory=False)
    except (OSError, UnicodeDecodeError, pd.errors.ParserError, ValueError) as error:
        return pd.DataFrame(), str(error)
    if "timestamp" in frame:
        frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
        frame = frame.dropna(subset=["timestamp"])
    for column in (
        "cpu_usage",
        "memory_usage",
        "disk_usage",
        "response_time_ms",
        "api_error_rate",
        "request_throughput_rps",
        "application_process_memory_mb",
    ):
        if column in frame:
            frame[column] = pd.to_numeric(frame[column], errors="coerce")
    return frame.tail(3000).reset_index(drop=True), None


def _escape(value):
    return html.escape(str(value if value is not None else ""))


def _decode_time(value):
    if not value:
        return None
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if result.tzinfo is None:
        return result.astimezone()
    return result.astimezone()


def _time_label(value):
    parsed = _decode_time(value)
    return parsed.strftime("%b %d, %H:%M:%S") if parsed else "—"


def _number(value):
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def _metric_text(value, unit="", precision=1):
    number = _number(value)
    if number is None:
        return "—"
    return f"{number:,.{precision}f}{unit}"


def _visible(rows, include_simulated):
    if include_simulated:
        return rows
    return [row for row in rows if not row.get("is_simulated")]


def _app_names(snapshot):
    return {
        row["application_id"]: row["name"]
        for row in snapshot["applications"]
    }


def _latest_readings(snapshot, include_simulated=True):
    latest = {}
    for row in snapshot["telemetry"]:
        if row.get("source") == "browser_page_metrics":
            continue
        if not include_simulated and row.get("is_simulated"):
            continue
        latest.setdefault(row["application_id"], row)
    return latest


def _application_state(application, reading):
    if not application.get("active"):
        return "Inactive"
    if reading is None:
        return "No telemetry"
    age = _decode_time(reading.get("timestamp"))
    if age and (datetime.now().astimezone() - age).total_seconds() > 60:
        return "Stale"
    payload = reading.get("data", {})
    if payload.get("request_success") is True:
        return "Operational"
    if payload.get("request_success") is False:
        return "Unavailable"
    return "Unknown"


def _badge(label, kind=None):
    value = str(label or "Unknown")
    normalized = (kind or value).casefold().replace(" ", "-")
    variants = {
        "operational": ("#e5f8ee", "#16834b"),
        "healthy": ("#e5f8ee", "#16834b"),
        "resolved": ("#e5f8ee", "#16834b"),
        "completed": ("#e5f8ee", "#16834b"),
        "verified": ("#e5f8ee", "#16834b"),
        "available": ("#e5f8ee", "#16834b"),
        "warning": ("#fff4df", "#ad6800"),
        "medium": ("#fff4df", "#ad6800"),
        "investigating": ("#fff4df", "#ad6800"),
        "monitoring": ("#eaf4ff", "#236bb5"),
        "acknowledged": ("#eaf4ff", "#236bb5"),
        "running": ("#eaf4ff", "#236bb5"),
        "simulated": ("#f1eaff", "#7546c8"),
        "critical": ("#ffebea", "#c23c35"),
        "high": ("#ffebea", "#c23c35"),
        "unavailable": ("#ffebea", "#c23c35"),
        "failed": ("#ffebea", "#c23c35"),
        "open": ("#fff0e8", "#bb5b22"),
        "inactive": ("#f0f2f6", "#667085"),
        "closed": ("#f0f2f6", "#667085"),
        "low": ("#edf4ff", "#4776b5"),
        "no-telemetry": ("#f0f2f6", "#667085"),
        "unknown": ("#f0f2f6", "#667085"),
        "stale": ("#fff4df", "#ad6800"),
    }
    background, foreground = variants.get(normalized, ("#edf1f8", "#526176"))
    st.markdown(
        f'<span class="status-badge" style="background:{background};color:{foreground}">'
        f"{_escape(value)}</span>",
        unsafe_allow_html=True,
    )


def _empty(title, detail):
    st.markdown(
        '<div class="empty-state"><div class="empty-icon">◌</div>'
        f"<strong>{_escape(title)}</strong><span>{_escape(detail)}</span></div>",
        unsafe_allow_html=True,
    )


def _kpi(label, value, detail, icon, accent):
    background, color, _ = accent
    st.markdown(
        '<div class="kpi-card">'
        f'<div class="kpi-top"><span class="kpi-label">{_escape(label)}</span>'
        f'<span class="kpi-icon" style="background:{background};color:{color}">'
        f"{_escape(icon)}</span></div>"
        f'<div class="kpi-value">{_escape(value)}</div>'
        f'<div class="kpi-detail">{_escape(detail)}</div></div>',
        unsafe_allow_html=True,
    )


def _section_heading(title, detail=None):
    st.markdown(
        '<div class="section-heading">'
        f"<h3>{_escape(title)}</h3>"
        f"<p>{_escape(detail or '')}</p></div>",
        unsafe_allow_html=True,
    )


def _table(frame, empty_title="No records", empty_detail="There is no matching saved data."):
    if frame.empty:
        _empty(empty_title, empty_detail)
        return
    st.dataframe(
        frame,
        hide_index=True,
        use_container_width=True,
        height=min(460, 42 + 36 * min(len(frame), 12)),
    )


def _time_series_chart(frame, columns, colors, *, height=300, y_title=None):
    available = [column for column in columns if column in frame.columns]
    if frame.empty or not available:
        _empty("No chartable readings", "The selected time window has no recorded values for these metrics.")
        return
    chart_frame = frame[["timestamp", *available]].copy()
    chart_frame["timestamp"] = pd.to_datetime(chart_frame["timestamp"], errors="coerce")
    chart_frame = chart_frame.dropna(subset=["timestamp"])
    for column in available:
        chart_frame[column] = pd.to_numeric(chart_frame[column], errors="coerce")
    chart_frame = chart_frame.melt(
        id_vars="timestamp",
        value_vars=available,
        var_name="metric",
        value_name="value",
    ).dropna(subset=["value"])
    if chart_frame.empty:
        _empty("Metrics unavailable", "No numeric values were recorded for the selected metrics.")
        return
    labels = {column: column.replace("_", " ").title() for column in available}
    chart_frame["metric"] = chart_frame["metric"].map(labels)
    domain = [labels[column] for column in available]
    range_values = [colors[column] for column in available]
    chart = (
        alt.Chart(chart_frame)
        .mark_line(point=alt.OverlayMarkDef(size=32), strokeWidth=2.5)
        .encode(
            x=alt.X("timestamp:T", title=None, axis=alt.Axis(format="%H:%M", labelColor="#718096")),
            y=alt.Y("value:Q", title=y_title, axis=alt.Axis(labelColor="#718096", gridColor="#edf1f6")),
            color=alt.Color(
                "metric:N",
                title=None,
                scale=alt.Scale(domain=domain, range=range_values),
                legend=alt.Legend(orient="top", labelColor="#526176"),
            ),
            tooltip=[
                alt.Tooltip("timestamp:T", title="Time"),
                alt.Tooltip("metric:N", title="Metric"),
                alt.Tooltip("value:Q", title="Value", format=",.2f"),
            ],
        )
        .properties(height=height)
        .configure_view(stroke=None)
        .configure(background="transparent")
    )
    st.altair_chart(chart, use_container_width=True)


def _application_telemetry(snapshot, application_id, include_simulated):
    rows = [
        row
        for row in snapshot["telemetry"]
        if row["application_id"] == application_id
        and row.get("source") != "browser_page_metrics"
        and (include_simulated or not row.get("is_simulated"))
    ]
    rows.reverse()
    result = []
    for row in rows:
        item = {
            "timestamp": row["timestamp"],
            "source": row["source"],
            "is_simulated": bool(row["is_simulated"]),
        }
        item.update(row["data"])
        result.append(item)
    return result


def _style():
    st.markdown(
        """
        <style>
        :root {
            color-scheme: light;
            --ink: #17243a;
            --muted: #718096;
            --line: #e8edf4;
            --paper: #ffffff;
            --canvas: #f5f7fb;
            --blue: #4778e8;
            --purple: #8158d8;
            --teal: #159b91;
            --green: #2e9b68;
            --orange: #e58b39;
        }
        html, body, [data-testid="stAppViewContainer"] {
            background: var(--canvas);
            color: var(--ink);
            font-family: Inter, ui-sans-serif, system-ui, -apple-system,
                         BlinkMacSystemFont, "Segoe UI", sans-serif;
        }
        [data-testid="stHeader"] { background: rgba(245,247,251,.9); }
        [data-testid="stSidebar"] {
            background: #fff;
            border-right: 1px solid var(--line);
        }
        [data-testid="stSidebar"] > div:first-child { padding-top: 1.1rem; }
        .block-container {
            max-width: 1540px;
            padding: 1.5rem 2.2rem 4rem;
        }
        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"] p {
            color: #64748b;
        }
        [data-testid="stRadio"] label { font-weight: 560; }
        .brand-lockup {
            display:flex; align-items:center; gap:12px; padding: 8px 8px 18px;
        }
        .brand-mark {
            width:42px;height:42px;border-radius:14px;display:grid;place-items:center;
            color:#fff;background:linear-gradient(140deg,#4778e8,#8c5ce8);
            font-size:21px;font-weight:800;box-shadow:0 8px 18px #6b70d633;
        }
        .brand-name {font-size:16px;font-weight:800;color:#17243a;letter-spacing:-.03em}
        .brand-caption {font-size:10px;font-weight:700;color:#8290a4;letter-spacing:.13em}
        .topline {
            display:flex;align-items:center;justify-content:space-between;
            margin:0 0 1.1rem;color:#718096;font-size:12px;
        }
        .eyebrow {
            color:#6176bb;font-size:10px;letter-spacing:.14em;font-weight:800;
            text-transform:uppercase;margin-bottom:7px;
        }
        .hero {
            background:linear-gradient(112deg,#eef4ff 0%,#f6f0ff 53%,#e9faf5 100%);
            border:1px solid #e3eaf7;border-radius:22px;padding:24px 28px;
            margin: 0 0 20px;box-shadow:0 10px 24px rgba(32,54,94,.035);
        }
        .hero-title {font-size:29px;font-weight:800;letter-spacing:-.045em;color:#182842;margin:0}
        .hero-copy {color:#687991;font-size:14px;margin:7px 0 0}
        .hero-chip {
            display:inline-flex;align-items:center;gap:7px;border-radius:999px;
            padding:7px 11px;background:#fff;color:#41635f;border:1px solid #dceee9;
            font-size:11px;font-weight:750;margin-top:14px;
        }
        .kpi-card {
            background:#fff;border:1px solid #e8edf4;border-radius:17px;
            padding:17px 18px 15px;min-height:132px;
            box-shadow:0 5px 16px rgba(30,49,82,.035);
        }
        .kpi-top {display:flex;align-items:center;justify-content:space-between}
        .kpi-label {font-size:12px;color:#718096;font-weight:700}
        .kpi-icon {width:34px;height:34px;border-radius:11px;display:grid;place-items:center;font-size:17px;font-weight:800}
        .kpi-value {font-size:29px;line-height:1.15;font-weight:800;color:#192941;letter-spacing:-.045em;margin-top:11px}
        .kpi-detail {color:#8a97a9;font-size:11px;margin-top:6px}
        .section-heading {margin:1.45rem 0 .75rem}
        .section-heading h3 {font-size:16px;margin:0;color:#1c2a40;letter-spacing:-.02em}
        .section-heading p {font-size:12px;margin:4px 0 0;color:#7a8799}
        .status-badge {
            display:inline-flex;align-items:center;border-radius:999px;
            font-size:10px;font-weight:800;letter-spacing:.01em;padding:5px 9px;
            white-space:nowrap;
        }
        .empty-state {
            min-height:130px;border:1px dashed #d6deea;border-radius:16px;
            background:#fbfcfe;display:flex;flex-direction:column;align-items:center;
            justify-content:center;text-align:center;padding:20px;color:#5e6f84;
        }
        .empty-state strong {font-size:13px;color:#32435b;margin:4px 0}
        .empty-state span {font-size:11px;max-width:500px;line-height:1.5}
        .empty-icon {font-size:23px;color:#8395b1}
        .app-card {
            background:#fff;border:1px solid #e7edf5;border-radius:17px;
            padding:18px 19px;box-shadow:0 5px 16px rgba(30,49,82,.035);
            height:100%;
        }
        .app-card-top {display:flex;justify-content:space-between;align-items:flex-start;gap:10px}
        .app-card-name {font-size:15px;font-weight:780;color:#1a2a42}
        .app-card-id {font-size:10px;color:#8a97a9;margin-top:4px;word-break:break-all}
        .app-card-url {font-size:11px;color:#6b7b91;margin-top:13px;word-break:break-all}
        .soft-note {
            border-left:3px solid #8a67e7;background:#f5f1ff;padding:11px 14px;
            color:#665b7e;border-radius:0 10px 10px 0;font-size:12px;margin:10px 0 16px;
        }
        .sim-note {
            border-left:3px solid #8158d8;background:#f5f0ff;padding:11px 14px;
            color:#61517e;border-radius:0 10px 10px 0;font-size:12px;margin:8px 0 16px;
        }
        [data-testid="stMetric"] {
            background:#fff;border:1px solid #e8edf4;border-radius:15px;
            padding:12px 15px;box-shadow:0 4px 14px rgba(30,49,82,.025);
        }
        [data-testid="stMetricLabel"] {color:#718096;font-size:11px;font-weight:700}
        [data-testid="stMetricValue"] {color:#1b2b43}
        .stButton > button, .stDownloadButton > button {
            border-radius:10px;border:1px solid #dce4ef;background:#fff;
            color:#385a9d;font-weight:700;
        }
        div[data-testid="stDataFrame"] {border:1px solid #e7edf5;border-radius:13px;overflow:hidden}
        hr {border-color:#e8edf4}
        @media (max-width: 850px) {
            .block-container {padding:1rem 1rem 3rem}
            .hero {padding:19px}
            .hero-title {font-size:24px}
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _application_rows(snapshot, include_simulated):
    latest = _latest_readings(snapshot, include_simulated=include_simulated)
    output = []
    for app in snapshot["applications"]:
        reading = latest.get(app["application_id"])
        payload = reading.get("data", {}) if reading else {}
        output.append(
            {
                **app,
                "latest": reading,
                "state": _application_state(app, reading),
                "payload": payload,
            }
        )
    return output


def _browser_page_metric_rows(snapshot, selected_origin="All websites"):
    latest = {}
    for row in snapshot["telemetry"]:
        if row.get("source") != "browser_page_metrics":
            continue
        data = row.get("data") or {}
        origin = data.get("origin")
        if not isinstance(origin, str) or not origin:
            continue
        if selected_origin != "All websites" and origin != selected_origin:
            continue
        latest.setdefault(origin, (row, data))

    output = []
    for origin, (row, data) in sorted(
        latest.items(),
        key=lambda item: (
            str(item[1][0].get("timestamp") or ""),
            str(item[1][1].get("hostname") or item[0]).casefold(),
        ),
        reverse=True,
    ):
        heap_value = _number(data.get("javascript_heap_used_bytes"))
        count_value = data.get("long_task_count")
        duration_value = _number(data.get("total_long_task_duration_ms"))
        heap_available = (
            data.get("javascript_heap_available") is True
            and heap_value is not None
            and heap_value >= 0
        )
        tasks_available = (
            data.get("long_tasks_available") is True
            and isinstance(count_value, int)
            and not isinstance(count_value, bool)
            and count_value >= 0
            and duration_value is not None
            and duration_value >= 0
        )
        output.append({
            "Website hostname": data.get("hostname") or origin,
            "JavaScript heap usage": (
                f"{_metric_text(heap_value / (1024 * 1024), ' MiB')}"
                if heap_available
                else "Unavailable"
            ),
            "Long-task count": (
                _metric_text(count_value, precision=0)
                if tasks_available
                else "Unavailable"
            ),
            "Total long-task duration": (
                _metric_text(duration_value, " ms")
                if tasks_available
                else "Unavailable"
            ),
            "Long-task measurement window": (
                f"{_metric_text(data.get('measurement_interval_seconds'), ' seconds')}"
                if tasks_available
                and _number(data.get("measurement_interval_seconds")) is not None
                else "Unavailable"
            ),
            "Last measurement time": _time_label(
                data.get("timestamp") or row.get("timestamp")
            ),
            "Measurement availability": (
                f"JavaScript heap: {'Available' if heap_available else 'Unavailable'}; "
                f"long tasks: {'Available' if tasks_available else 'Unavailable'}"
            ),
            "_origin": origin,
        })
    return output


def _render_hero(title, subtitle, right_label=None):
    label = (
        f'<span class="hero-chip">● {_escape(right_label)}</span>'
        if right_label
        else ""
    )
    st.markdown(
        f'<div class="hero"><div class="eyebrow">SDP · INTELLIGENT AIOPS</div>'
        f'<div class="hero-title">{_escape(title)}</div>'
        f'<div class="hero-copy">{_escape(subtitle)}</div>{label}</div>',
        unsafe_allow_html=True,
    )


def _render_app_card(app, reading, demo=False):
    if app is None:
        return
    payload = reading.get("data", {}) if reading else {}
    state = _application_state(app, reading)
    with st.container(border=True):
        left, right = st.columns([0.75, 0.25])
        with left:
            st.markdown(
                f'<div class="app-card-name">{_escape(app["name"])}</div>'
                f'<div class="app-card-id">{_escape(app["application_id"])}</div>',
                unsafe_allow_html=True,
            )
        with right:
            _badge(state)
        cols = st.columns(3)
        values = (
            ("Response", _metric_text(payload.get("response_time_ms"), " ms")),
            ("Memory", _metric_text(payload.get("memory_usage"), "%")),
            ("HTTP", _metric_text(payload.get("http_status_code"), precision=0)),
        )
        for column, (label, value) in zip(cols, values):
            with column:
                st.caption(label)
                st.markdown(f"**{value}**")
        st.markdown(
            f'<div class="app-card-url">{_escape(app.get("url") or "No endpoint registered")}</div>',
            unsafe_allow_html=True,
        )
        if demo and reading is None:
            st.caption("No telemetry yet · service has not been registered or monitored")
        elif reading:
            st.caption(f"Last signal · {_time_label(reading.get('timestamp'))}")


def render_overview(snapshot, system_metrics, include_simulated):
    apps = _application_rows(snapshot, include_simulated)
    visible_incidents = _visible(snapshot["incidents"], include_simulated)
    active_incidents = [
        item for item in visible_incidents
        if item["status"] in ACTIVE_INCIDENT_STATUSES
    ]
    anomalies = _visible(snapshot["anomalies"], include_simulated)
    healthy_count = sum(item["state"] == "Operational" for item in apps)
    latest_system = system_metrics.iloc[-1].to_dict() if not system_metrics.empty else {}

    _render_hero(
        "Operations overview",
        "A live view of service health, system performance, AI signals, and operational risk.",
        "LIVE TELEMETRY" if not system_metrics.empty else "WAITING FOR TELEMETRY",
    )
    columns = st.columns(4)
    cards = (
        ("Registered applications", str(len(snapshot["applications"])), f"{sum(bool(a['active']) for a in snapshot['applications'])} active in registry", "◈", ACCENTS[0]),
        ("Operational now", str(healthy_count), "Based on the latest saved health checks", "✓", ACCENTS[1]),
        ("Open incidents", str(len(active_incidents)), "Open · acknowledged · investigating · monitoring", "!", ACCENTS[2]),
        ("Anomaly records", str(len(anomalies)), "Stored detector results; no synthetic signals", "✳", ACCENTS[3]),
    )
    for column, card in zip(columns, cards):
        with column:
            _kpi(*card)

    st.markdown("")
    _section_heading("System pulse", "Host metrics collected by the existing local monitor.")
    metric_cols = st.columns(4)
    system_cards = (
        ("CPU utilization", _metric_text(latest_system.get("cpu_usage"), "%"), "Current host sample", "▦", ACCENTS[0]),
        ("Memory utilization", _metric_text(latest_system.get("memory_usage"), "%"), "Current host sample", "▤", ACCENTS[3]),
        ("Disk utilization", _metric_text(latest_system.get("disk_usage"), "%"), "Current host sample", "◫", ACCENTS[2]),
        ("API response time", _metric_text(latest_system.get("response_time_ms"), " ms"), "Latest measured request", "↗", ACCENTS[1]),
    )
    for column, card in zip(metric_cols, system_cards):
        with column:
            _kpi(*card)

    _section_heading(
        "Browser resource usage",
        "Current CPU and memory totals for this user's Chrome processes, across all tabs.",
    )
    browser_metrics = sample_chrome_process_metrics()
    if browser_metrics["error"]:
        st.info(browser_metrics["error"])
    browser_cols = st.columns(3)
    browser_memory = (
        f"{_metric_text(browser_metrics['memory_mib'], ' MiB')} "
        f"({_metric_text(browser_metrics['memory_percent'], '%')})"
        if browser_metrics["memory_mib"] is not None
        else "—"
    )
    browser_cards = (
        ("Chrome CPU", _metric_text(browser_metrics["cpu_percent"], "%"), "All tabs · percent of host CPU", "▦", ACCENTS[0]),
        ("Chrome memory", browser_memory, "All tabs · resident memory", "▤", ACCENTS[3]),
        ("Chrome processes", str(browser_metrics["process_count"]), "Current-user Chrome processes", "◈", ACCENTS[1]),
    )
    for column, card in zip(browser_cols, browser_cards):
        with column:
            _kpi(*card)
    if browser_metrics["warning"]:
        st.caption(browser_metrics["warning"])

    _section_heading(
        "Browser Page Metrics",
        "Latest periodic reading from an authorized tab per website; values are not combined across tabs. JavaScript heap is not total website RAM, and long-task duration is not CPU usage.",
    )
    page_metric_rows = _browser_page_metric_rows(snapshot)
    if page_metric_rows:
        origins = sorted(
            {row["_origin"] for row in page_metric_rows},
            key=lambda value: value.casefold(),
        )
        selected_origin = st.selectbox(
            "Filter browser page metrics by website",
            ["All websites", *origins],
            format_func=lambda value: (
                value
                if value == "All websites"
                else next(
                    (
                        row["Website hostname"]
                        for row in page_metric_rows
                        if row["_origin"] == value
                    ),
                    value,
                )
            ),
            key="browser_page_metrics_origin",
        )
        visible_page_metrics = _browser_page_metric_rows(
            snapshot,
            selected_origin,
        )
        _table(
            pd.DataFrame([
                {key: value for key, value in row.items() if not key.startswith("_")}
                for row in visible_page_metrics
            ]),
            "No browser page metrics",
            "No page measurements have been received for this website.",
        )
    else:
        _empty(
            "No browser page measurements",
            "Authorize monitored websites in the browser-extension popup to begin collecting page-level readings.",
        )

    left, right = st.columns([1.55, 1])
    with left:
        _section_heading("Host performance", "CPU, memory, and disk from actual monitor samples.")
        _time_series_chart(
            system_metrics.tail(180),
            ["cpu_usage", "memory_usage", "disk_usage"],
            {
                "cpu_usage": "#4778e8",
                "memory_usage": "#8158d8",
                "disk_usage": "#159b91",
            },
            height=285,
            y_title="Utilization (%)",
        )
    with right:
        _section_heading("Application health", "Latest saved signal per registered application.")
        if apps:
            for app in apps[:5]:
                _render_app_card(app, app["latest"])
                st.markdown("")
        else:
            _empty("No applications registered", "Register an application to begin displaying telemetry.")

    _section_heading("Local demo services", "Each service is shown separately; missing registrations stay visibly empty.")
    demo_cols = st.columns(2)
    registered = {row["application_id"]: row for row in apps}
    latest = _latest_readings(snapshot, include_simulated)
    for column, (app_id, definition) in zip(demo_cols, DEMO_APPLICATIONS.items()):
        with column:
            app = registered.get(app_id)
            if app:
                _render_app_card(app, latest.get(app_id), demo=True)
            else:
                st.markdown(
                    '<div class="app-card"><div class="app-card-top">'
                    f'<div><div class="app-card-name">{_escape(definition["name"])}</div>'
                    f'<div class="app-card-id">{_escape(app_id)}</div></div></div>'
                    '<div class="app-card-url">Not registered · no telemetry available</div>'
                    '<div class="soft-note">Local demo service is not running. '
                    'No metrics are inferred or displayed as zero.</div></div>',
                    unsafe_allow_html=True,
                )

    _section_heading("Incident watch", "Most recently updated active incidents.")
    if active_incidents:
        incident_frame = pd.DataFrame(
            [
                {
                    "Incident": row["incident_id"],
                    "Application": _app_names(snapshot).get(row["application_id"], row["application_id"] or "Legacy"),
                    "Title": row["title"],
                    "Severity": row["severity"],
                    "Status": row["status"],
                    "Updated": _time_label(row["updated_at"]),
                }
                for row in active_incidents[:8]
            ]
        )
        _table(incident_frame)
    else:
        _empty("No active incidents", "Resolved and closed incidents remain available in Incident Management.")


def render_registry(snapshot, include_simulated):
    _render_hero(
        "Application registry",
        "Ownership, monitoring configuration, endpoint identity, and current signal for each service.",
        f"{len(snapshot['applications'])} REGISTERED",
    )
    apps = _application_rows(snapshot, include_simulated)
    latest = _latest_readings(snapshot, include_simulated)
    registered = {row["application_id"]: row for row in apps}
    _section_heading("Registered services", "Registry facts come from SQLite; telemetry values come from saved readings.")
    if not apps:
        _empty("Registry is empty", "No application registrations exist in the database.")
    else:
        for row in apps:
            reading = row["latest"]
            payload = row["payload"]
            with st.container(border=True):
                cols = st.columns([1.4, 0.8, 0.8, 0.8])
                with cols[0]:
                    st.markdown(f"### {_escape(row['name'])}")
                    st.caption(f"{row['application_id']} · {row['application_type']}")
                with cols[1]:
                    st.caption("Current state")
                    _badge(row["state"])
                with cols[2]:
                    st.caption("Platform ownership")
                    _badge("Owned" if row["owned_by_platform"] else "External")
                with cols[3]:
                    st.caption("Monitoring interval")
                    st.markdown(f"**{row['monitoring_interval_seconds']} sec**")
                st.markdown(f"`{row['url']}`")
                values = st.columns(4)
                for col, (label, value) in zip(
                    values,
                    (
                        ("Availability", "Available" if payload.get("request_success") is True else "Unavailable" if payload.get("request_success") is False else "—"),
                        ("Response time", _metric_text(payload.get("response_time_ms"), " ms")),
                        ("HTTP status", _metric_text(payload.get("http_status_code"), precision=0)),
                        ("Last check", _time_label(reading.get("timestamp") if reading else None)),
                    ),
                ):
                    with col:
                        st.caption(label)
                        st.markdown(f"**{value}**")

    _section_heading("Demo application catalog", "Known local demos are not treated as registered until the registry confirms them.")
    demo_cols = st.columns(2)
    for column, (app_id, definition) in zip(demo_cols, DEMO_APPLICATIONS.items()):
        app = registered.get(app_id)
        with column:
            if app:
                _render_app_card(app, latest.get(app_id), demo=True)
            else:
                st.markdown(
                    '<div class="app-card"><div class="app-card-name">'
                    f'{_escape(definition["name"])}</div>'
                    f'<div class="app-card-id">{_escape(app_id)}</div>'
                    f'<div class="app-card-url">Fixed local port · 127.0.0.1:{definition["port"]}</div>'
                    '<div class="soft-note">Not registered or running; no health or performance data exists yet.</div>'
                    f'<div class="app-card-url">Routes: {_escape(", ".join(definition["paths"]))}</div></div>',
                    unsafe_allow_html=True,
                )


def render_browser_discovery():
    settings = get_discovery_settings(DATABASE_FILE)
    discoveries = list_discovered_applications(
        db_path=DATABASE_FILE,
        include_excluded=True,
    )
    open_tabs = list_open_tabs(db_path=DATABASE_FILE)
    history = get_discovery_history(200, db_path=DATABASE_FILE)
    with closing(connect(DATABASE_FILE)) as connection:
        paired = connection.execute(
            """
            SELECT 1 FROM discovery_credentials
            WHERE revoked_at IS NULL LIMIT 1
            """
        ).fetchone() is not None
    excluded = [row for row in discoveries if row["excluded_at"]]
    pending = [
        row
        for row in discoveries
        if row["registration_status"] == "pending_approval"
        and not row["excluded_at"]
    ]
    recent_cutoff = (
        datetime.now(timezone.utc) - timedelta(days=1)
    ).isoformat()
    newly_discovered = sum(
        row["first_discovered_at"] >= recent_cutoff for row in discoveries
    )
    monitored = sum(
        row["monitoring_status"] == "enabled" and not row["excluded_at"]
        for row in discoveries
    )

    _render_hero(
        "Automatic application discovery",
        "Discover website origins from opted-in top-level browser visits and reuse the existing application registry and monitors.",
        f"{len(discoveries)} DISCOVERED",
    )
    st.info(
        "Privacy: the paired extension submits only a normalized HTTP(S) origin "
        "and hostname. It does not collect page content, URL paths, search "
        "terms, cookies, passwords, form data, or authentication tokens. "
        "Private browsing is disabled."
    )
    if paired:
        st.success(
            "An extension pairing credential is stored. Check the extension "
            "popup to confirm its live backend connection."
        )
    else:
        st.error(
            "Browser extension is not paired. Generate a pairing code below "
            "and enter it in the extension popup."
        )
    status_columns = st.columns(5)
    for column, label, value in zip(
        status_columns,
        (
            "Discovery status",
            "Discovered websites",
            "New in the last 24 hours",
            "Monitored websites",
            "Awaiting registration",
        ),
        (
            settings["mode"].capitalize(),
            len(discoveries),
            newly_discovered,
            monitored,
            len(pending),
        ),
    ):
        with column:
            _kpi(label, value, "Saved discovery state", "◉", ACCENTS[0])

    _section_heading(
        "Discovery controls",
        "Discovery starts disabled. Enable it here and separately enable consent in the browser-extension popup.",
    )
    mode_columns = st.columns(3)
    for column, label, mode in zip(
        mode_columns,
        ("Enable discovery", "Pause discovery", "Disable discovery"),
        ("enabled", "paused", "disabled"),
    ):
        with column:
            if st.button(
                label,
                key=f"discovery_mode_{mode}",
                type="primary" if settings["mode"] == mode else "secondary",
                use_container_width=True,
            ):
                try:
                    configure_discovery(mode=mode, db_path=DATABASE_FILE)
                    st.cache_data.clear()
                    st.rerun()
                except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                    st.error(f"Could not update discovery mode: {error}")

    with st.form("browser_discovery_preferences"):
        automatic_registration = st.checkbox(
            "Automatically register eligible newly discovered websites",
            value=bool(settings["automatic_registration"]),
        )
        automatic_monitoring = st.checkbox(
            "Automatically monitor registered discovered websites",
            value=bool(settings["automatic_monitoring"]),
            help=(
                "Monitoring makes unauthenticated, rate-limited HTTP(S) "
                "requests to the origin. Private network targets and redirects "
                "are blocked for browser-discovered applications."
            ),
        )
        if st.form_submit_button("Save discovery preferences"):
            try:
                configure_discovery(
                    automatic_registration=automatic_registration,
                    automatic_monitoring=automatic_monitoring,
                    db_path=DATABASE_FILE,
                )
                st.cache_data.clear()
                st.rerun()
            except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                st.error(f"Could not save discovery preferences: {error}")

    with st.expander("Connect Chrome or Edge extension", expanded=False):
        st.markdown(
            "1. Start Flask from the sdpmain project on port 5001 "
            "(PowerShell: `$env:SDP_PORT=5001; python app/main.py`).\n"
            "2. From the sdpmain project root, run "
            "`python -m app.browser_discovery --pair` and enter the printed "
            "one-time code in the extension popup within five minutes.\n"
            "3. Load the `browser_extension` folder using the browser's "
            "**Load unpacked** extension option, then enable consent in its popup."
        )
        st.caption(
            "Pairing codes are single-use, short-lived, and stored only as "
            "hashes. The extension token is kept in browser extension storage."
        )
        st.markdown(
            "After pairing, enable discovery in both places. In the extension "
            "popup, choose **Scan tabs in this browser profile** and grant the optional tab "
            "access when Chrome asks. Only HTTP(S) origins and tab counts are "
            "saved; internal browser pages, local/private hosts, and page "
            "paths are skipped."
        )

    _section_heading(
        "Currently open websites",
        "Last on-demand scan of HTTP(S) tabs in the paired browser profile. This is not a live tab feed.",
    )
    if open_tabs:
        _table(
            pd.DataFrame([
                {
                    "Website": row["hostname"],
                    "Origin": row["origin"],
                    "Open tabs": row["tab_count"],
                    "Last scanned": _time_label(row["scanned_at"]),
                }
                for row in open_tabs
            ]),
            "No open websites",
            "The latest scan contained no HTTP(S) website tabs.",
        )
    else:
        _empty(
            "No open-tab scan yet",
            "Pair the extension, enable discovery, and choose Scan all open tabs in its popup.",
        )

    _section_heading(
        "Discovered websites",
        "A website is registered only when automatic registration is enabled or an operator approves it.",
    )
    if not discoveries:
        _empty(
            "No websites discovered",
            "No browser-origin events have been accepted. The initial setting is disabled.",
        )
    for row in discoveries:
        with st.container(border=True):
            columns = st.columns([1.5, 1, 1, 1, 1.4])
            with columns[0]:
                st.markdown(f"### {_escape(row['hostname'])}")
                st.caption(_escape(row["origin"]))
            with columns[1]:
                st.caption("Registration")
                st.markdown(f"**{_escape(row['registration_status'])}**")
            with columns[2]:
                st.caption("Monitoring")
                st.markdown(
                    f"**{'Excluded' if row['excluded_at'] else _escape(row['monitoring_status'])}**"
                )
            with columns[3]:
                st.caption("First discovered")
                st.markdown(f"**{_time_label(row['first_discovered_at'])}**")
            with columns[4]:
                st.caption("Last discovered")
                st.markdown(f"**{_time_label(row['last_discovered_at'])}**")

            action_columns = st.columns(3)
            if (
                row["registration_status"] == "pending_approval"
                and not row["excluded_at"]
            ):
                with action_columns[0]:
                    if st.button(
                        "Approve and register",
                        key=f"discovery_approve_{row['discovery_id']}",
                    ):
                        try:
                            approve_discovery(row["origin"], db_path=DATABASE_FILE)
                            st.cache_data.clear()
                            st.rerun()
                        except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                            st.error(f"Could not approve this website: {error}")
                with action_columns[1]:
                    if st.button(
                        "Ignore",
                        key=f"discovery_ignore_{row['discovery_id']}",
                    ):
                        try:
                            ignore_discovery(row["origin"], db_path=DATABASE_FILE)
                            st.cache_data.clear()
                            st.rerun()
                        except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                            st.error(f"Could not ignore this website: {error}")
            if row["excluded_at"]:
                with action_columns[2]:
                    if st.button(
                        "Restore website",
                        key=f"discovery_restore_{row['discovery_id']}",
                    ):
                        try:
                            restore_discovery(row["origin"], db_path=DATABASE_FILE)
                            st.cache_data.clear()
                            st.rerun()
                        except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                            st.error(f"Could not restore this website: {error}")
            elif row["registration_status"] in {"registered", "existing"}:
                with action_columns[2]:
                    if st.button(
                        "Exclude website",
                        key=f"discovery_exclude_{row['discovery_id']}",
                    ):
                        try:
                            exclude_discovery(row["origin"], db_path=DATABASE_FILE)
                            st.cache_data.clear()
                            st.rerun()
                        except (OSError, RuntimeError, ValueError, sqlite3.Error) as error:
                            st.error(f"Could not exclude this website: {error}")

    _section_heading("Discovery history", "Origin-level events only; full browsing URLs are never stored.")
    if history:
        st.dataframe(
            [
                {
                    "Time": _time_label(row["occurred_at"]),
                    "Website": row["hostname"],
                    "Origin": row["origin"],
                    "Event": row["event_type"],
                    "Source": row["discovery_source"],
                }
                for row in history
            ],
            hide_index=True,
            use_container_width=True,
        )
    else:
        _empty("No discovery events", "Accepted discovery events will appear here.")


def render_multi_monitoring(snapshot, include_simulated):
    _render_hero(
        "Multi-application monitoring",
        "Compare per-application health and recorded performance without conflating unknown values with zero.",
        "SIMULATED DATA INCLUDED" if include_simulated else "REAL TELEMETRY VIEW",
    )
    app_options = {row["application_id"]: row["name"] for row in snapshot["applications"]}
    for app_id, definition in DEMO_APPLICATIONS.items():
        app_options.setdefault(app_id, definition["name"])
    if not app_options:
        _empty("No application sources", "There are no registered applications or known demo services.")
        return
    selected_id = st.selectbox(
        "Application",
        list(app_options),
        format_func=lambda value: f"{app_options[value]} · {value}",
    )
    app_row = next(
        (row for row in snapshot["applications"] if row["application_id"] == selected_id),
        None,
    )
    readings = _application_telemetry(snapshot, selected_id, include_simulated)
    if app_row is None:
        st.info("This demo application is not registered. Metrics are unavailable, not zero.")
        return
    if not readings:
        st.info("No telemetry has been recorded for this application.")
        return
    latest = readings[-1]
    state = _application_state(app_row, {
        "timestamp": latest.get("timestamp"),
        "data": latest,
    })
    cols = st.columns(5)
    cards = (
        ("Health", state, "Latest application signal", "◉", ACCENTS[1]),
        ("CPU", _metric_text(latest.get("cpu_usage"), "%"), "Application process metric", "▦", ACCENTS[0]),
        ("Memory", _metric_text(latest.get("memory_usage"), "%"), "Application process metric", "▤", ACCENTS[3]),
        ("Response time", _metric_text(latest.get("response_time_ms"), " ms"), "Latest HTTP check", "↗", ACCENTS[2]),
        ("HTTP status", _metric_text(latest.get("http_status_code"), precision=0), "Latest response code", "⌁", ACCENTS[1]),
    )
    for col, card in zip(cols, cards):
        with col:
            _kpi(*card)
    if str(app_row.get("application_type") or "").upper() in {
        "HTTP_WEBSITE",
        "HTTPS_WEBSITE",
    }:
        browser_metrics = sample_chrome_process_metrics()
        st.markdown("")
        _section_heading(
            "Chrome process group (all tabs)",
            "Current sample across this user's Chrome processes (all tabs); not attributable to the selected website.",
        )
        if browser_metrics["error"]:
            st.info(browser_metrics["error"])
        chrome_cpu, chrome_memory = st.columns(2)
        memory_value = (
            f"{_metric_text(browser_metrics['memory_mib'], ' MiB')}"
            f" ({_metric_text(browser_metrics['memory_percent'], '%')})"
            if browser_metrics["memory_mib"] is not None
            else "—"
        )
        with chrome_cpu:
            _kpi(
                "Chrome CPU",
                _metric_text(browser_metrics["cpu_percent"], "%"),
                "All tabs · percent of total host CPU",
                "▦",
                ACCENTS[0],
            )
        with chrome_memory:
            _kpi(
                "Chrome memory",
                memory_value,
                f"{browser_metrics['process_count']} current-user Chrome process(es) · all tabs",
                "▤",
                ACCENTS[3],
            )
        if browser_metrics["warning"]:
            st.caption(browser_metrics["warning"])
    st.markdown("")
    frame = pd.DataFrame(readings)
    left, right = st.columns([1.4, 1])
    with left:
        _section_heading("Application signal history", "Null process metrics remain unavailable rather than being charted as zero.")
        _time_series_chart(
            frame.tail(240),
            ["response_time_ms", "cpu_usage", "memory_usage"],
            {
                "response_time_ms": "#4778e8",
                "cpu_usage": "#8158d8",
                "memory_usage": "#159b91",
            },
            height=300,
        )
    with right:
        _section_heading("Latest telemetry record", f"Source: {latest.get('source') or 'Unknown'}")
        detail = {
            "Timestamp": _time_label(latest.get("timestamp")),
            "Availability": "Available" if latest.get("request_success") is True else "Unavailable" if latest.get("request_success") is False else "—",
            "HTTP errors": str(latest.get("http_status_code")) if _number(latest.get("http_status_code")) is not None and _number(latest.get("http_status_code")) >= 400 else "None reported" if _number(latest.get("http_status_code")) is not None else "—",
            "Consecutive failures": _metric_text(latest.get("consecutive_failure_count"), precision=0),
            "Simulation marker": "Simulated" if latest.get("is_simulated") else "Normal telemetry",
            "Error details": latest.get("error_details") or "—",
        }
        _table(pd.DataFrame([{"Field": key, "Value": value} for key, value in detail.items()]))
    st.markdown("")
    history = frame.tail(100).copy()
    history["timestamp"] = history["timestamp"].map(_time_label)
    history["telemetry type"] = history["is_simulated"].map(
        lambda value: "Simulated" if value else "Normal"
    )
    cols = [
        key for key in
        ("timestamp", "source", "availability", "http_status_code", "response_time_ms", "cpu_usage", "memory_usage", "telemetry type")
        if key in history
    ]
    _table(history[cols].rename(columns={
        "timestamp": "Timestamp",
        "source": "Source",
        "availability": "Available",
        "http_status_code": "HTTP",
        "response_time_ms": "Response ms",
        "cpu_usage": "CPU %",
        "memory_usage": "Memory %",
        "telemetry type": "Telemetry",
    }))


def render_performance(snapshot, system_metrics, include_simulated):
    _render_hero(
        "Performance analytics",
        "Explore host trends, service latency, error signals, and the existing threshold forecast.",
        "SAVED METRICS",
    )
    latest = system_metrics.iloc[-1].to_dict() if not system_metrics.empty else {}
    columns = st.columns(4)
    for col, card in zip(
        columns,
        (
            ("CPU", _metric_text(latest.get("cpu_usage"), "%"), "Latest host sample", "▦", ACCENTS[0]),
            ("Memory", _metric_text(latest.get("memory_usage"), "%"), "Latest host sample", "▤", ACCENTS[3]),
            ("Disk", _metric_text(latest.get("disk_usage"), "%"), "Latest host sample", "◫", ACCENTS[2]),
            ("API response", _metric_text(latest.get("response_time_ms"), " ms"), "Latest monitor sample", "↗", ACCENTS[1]),
        ),
    ):
        with col:
            _kpi(*card)
    left, right = st.columns([1.35, 1])
    with left:
        _section_heading("Host utilization", "Actual measurements from data/metrics.csv.")
        _time_series_chart(
            system_metrics.tail(360),
            ["cpu_usage", "memory_usage", "disk_usage"],
            {"cpu_usage": "#4778e8", "memory_usage": "#8158d8", "disk_usage": "#159b91"},
            height=330,
            y_title="Percent",
        )
    with right:
        _section_heading("Threshold outlook", "Uses the project's existing trend-crossing policy; no prediction is fabricated.")
        records = system_metrics.tail(360).copy()
        if not records.empty and "timestamp" in records:
            records["timestamp"] = records["timestamp"].map(
                lambda value: value.isoformat() if pd.notna(value) else None
            )
        records = records.to_dict("records")
        forecast = forecast_threshold_crossings(records)
        if forecast["warnings"]:
            for warning in forecast["warnings"]:
                with st.container(border=True):
                    st.markdown(f"**{warning['label']}**")
                    _badge("Warning")
                    st.caption(
                        f"{warning['current_value']:.1f}{warning['unit']} now · "
                        f"trend reaches {warning['threshold']:.1f}{warning['unit']} "
                        f"in about {warning['minutes_to_threshold']:.1f} minutes"
                    )
        else:
            _empty(
                "No threshold crossing forecast",
                "The existing forecast found no eligible metric likely to cross a threshold within its horizon.",
            )
        if forecast["insufficient_metrics"]:
            st.caption("Insufficient trend history: " + ", ".join(forecast["insufficient_metrics"]))

    _section_heading("Application response times", "Per-service response times from recorded SQLite telemetry.")
    app_names = _app_names(snapshot)
    rows = _visible(snapshot["telemetry"], include_simulated)
    response_rows = []
    for row in rows:
        response = _number(row["data"].get("response_time_ms"))
        if response is not None:
            response_rows.append({
                "timestamp": row["timestamp"],
                "application": app_names.get(row["application_id"], row["application_id"]),
                "response_time_ms": response,
            })
    if response_rows:
        response_frame = pd.DataFrame(response_rows)
        app_filter = st.selectbox(
            "Application for latency chart",
            ["All applications", *sorted(response_frame["application"].unique())],
            key="performance_app_filter",
        )
        if app_filter != "All applications":
            response_frame = response_frame[response_frame["application"] == app_filter]
        chart = (
            alt.Chart(response_frame.tail(500))
            .mark_line(point=alt.OverlayMarkDef(size=22), color="#4778e8", strokeWidth=2.4)
            .encode(
                x=alt.X("timestamp:T", title=None),
                y=alt.Y("response_time_ms:Q", title="Response time (ms)", axis=alt.Axis(gridColor="#edf1f6")),
                tooltip=["timestamp:T", "application:N", alt.Tooltip("response_time_ms:Q", format=",.2f")],
            )
            .properties(height=290)
            .configure_view(stroke=None)
        )
        st.altair_chart(chart, use_container_width=True)
    else:
        _empty("No response-time samples", "The telemetry store has no numeric response-time measurements.")

    errors = []
    for row in rows:
        status = _number(row["data"].get("http_status_code"))
        if row["data"].get("request_success") is False or (status is not None and status >= 400):
            errors.append({
                "Application": app_names.get(row["application_id"], row["application_id"]),
                "Timestamp": _time_label(row["timestamp"]),
                "HTTP status": status if status is not None else "Unavailable",
                "Simulation": "Yes" if row.get("is_simulated") else "No",
                "Reason": row["data"].get("error_details") or row["data"].get("failure_type") or "Request failed",
            })
    _section_heading("HTTP error events", "Only failed or 4xx/5xx responses are listed.")
    _table(pd.DataFrame(errors[:100]), "No HTTP errors recorded", "No saved reading currently indicates an HTTP/request failure.")


def render_anomalies(snapshot, include_simulated):
    anomalies = _visible(snapshot["anomalies"], include_simulated)
    models = snapshot["models"]
    _render_hero(
        "AI anomaly detection",
        "Stored Isolation Forest results, evidence, and per-application model readiness.",
        "REAL + SIMULATED" if include_simulated else "REAL TELEMETRY VIEW",
    )
    model_cols = st.columns(min(4, max(1, len(models))))
    if models:
        for col, model in zip(model_cols, models[:4]):
            with col:
                _kpi(
                    model["application_id"],
                    f"v{model['model_version']}",
                    f"{model['training_sample_count']} training samples · {model['algorithm']}",
                    "✳",
                    ACCENTS[3],
                )
    else:
        st.info("No trained application models are stored yet. The detector requires its configured minimum of real telemetry.")

    anomaly_count = sum(str(row["prediction"]).casefold() == "anomaly" for row in anomalies)
    normal_count = sum(str(row["prediction"]).casefold() == "normal" for row in anomalies)
    kpis = st.columns(3)
    for col, card in zip(
        kpis,
        (
            ("Stored results", str(len(anomalies)), "Visible detector outputs", "▤", ACCENTS[0]),
            ("Anomalies", str(anomaly_count), "Classified by the saved model/evidence", "✳", ACCENTS[2]),
            ("Normal readings", str(normal_count), "Explicit normal classifications", "✓", ACCENTS[1]),
        ),
    ):
        with col:
            _kpi(*card)
    st.markdown("")
    _section_heading("Detection evidence", "Reasons and severity are taken directly from each saved result.")
    if not anomalies:
        _empty("No anomaly results stored", "No anomaly detections are available for the selected telemetry view.")
        return
    rows = []
    for item in anomalies:
        details = item.get("details", {})
        reasons = details.get("metrics_responsible") or details.get("supporting_evidence") or []
        if not isinstance(reasons, (list, tuple)):
            reasons = [reasons]
        rows.append({
            "Detected": _time_label(item["timestamp"]),
            "Application": _app_names(snapshot).get(item["application_id"], item["application_id"]),
            "Prediction": item["prediction"],
            "Severity": details.get("severity") or item["status"],
            "Score": _metric_text(item.get("anomaly_score"), precision=4),
            "Evidence": ", ".join(str(reason) for reason in reasons) or details.get("explanation") or "No explanation saved",
            "Telemetry": "Simulated" if item.get("is_simulated") else "Normal",
        })
    _table(pd.DataFrame(rows))
    with st.expander("Model configuration and feature sets"):
        model_frame = pd.DataFrame([
            {
                "Application": model["application_id"],
                "Algorithm": model["algorithm"],
                "Version": model["model_version"],
                "Training samples": model["training_sample_count"],
                "Trained through": _time_label(model["trained_through_timestamp"]),
                "Features": ", ".join(model.get("features") or []),
            }
            for model in models
        ])
        _table(model_frame, "No model metadata", "Model metadata appears after a model is trained.")


def render_rca(snapshot, include_simulated):
    reports = _visible(snapshot["rca_reports"], include_simulated)
    _render_hero(
        "Root cause analysis",
        "Evidence-backed explanations and recommended actions saved by the existing application RCA pipeline.",
        f"{len(reports)} REPORTS",
    )
    if not reports:
        _empty("No RCA reports available", "Reports will appear here after application-specific RCA has been generated.")
        return
    names = _app_names(snapshot)
    for report in reports:
        details = report.get("details", {})
        with st.container(border=True):
            first, second = st.columns([0.75, 0.25])
            with first:
                st.markdown(f"### {_escape(report.get('root_cause') or 'Root cause not recorded')}")
                st.caption(
                    f"{_escape(names.get(report['application_id'], report['application_id']))} · "
                    f"source {_time_label(report.get('source_timestamp'))}"
                )
            with second:
                _badge(report.get("severity") or "Unknown")
                if report.get("is_simulated"):
                    _badge("Simulated")
            explanation = (
                details.get("explanation")
                or details.get("summary")
                or details.get("diagnosis")
                or "No additional explanation was saved with this report."
            )
            st.write(explanation)
            st.markdown("**Recommended action**")
            st.write(report.get("recommended_action") or "No recommendation recorded.")
            evidence = details.get("supporting_evidence") or details.get("confirmed_observations") or []
            if evidence:
                st.markdown("**Supporting evidence**")
                for item in evidence[:8]:
                    st.markdown(f"- {_escape(item)}")
            if details.get("confidence_score") is not None:
                st.caption(f"Evidence score: {_metric_text(details['confidence_score'], precision=2)}")


def render_incidents(snapshot, include_simulated):
    incidents = _visible(snapshot["incidents"], include_simulated)
    _render_hero(
        "Incident management",
        "Application-scoped incident ledger, severity, lifecycle state, and audit timeline.",
        f"{len(incidents)} RECORDS",
    )
    if not incidents:
        _empty("No incidents stored", "Incident records will appear here when significant anomaly evidence creates them.")
        return
    names = _app_names(snapshot)
    filter_cols = st.columns(3)
    with filter_cols[0]:
        statuses = ["All statuses", *sorted({str(row["status"]) for row in incidents})]
        selected_status = st.selectbox("Status", statuses)
    with filter_cols[1]:
        severities = ["All severities", *sorted({str(row["severity"]) for row in incidents})]
        selected_severity = st.selectbox("Severity", severities)
    with filter_cols[2]:
        applications = ["All applications", *sorted({names.get(row["application_id"], row["application_id"] or "Legacy") for row in incidents})]
        selected_application = st.selectbox("Application", applications)
    filtered = [
        row for row in incidents
        if (selected_status == "All statuses" or row["status"] == selected_status)
        and (selected_severity == "All severities" or row["severity"] == selected_severity)
        and (selected_application == "All applications" or names.get(row["application_id"], row["application_id"] or "Legacy") == selected_application)
    ]
    frame = pd.DataFrame([
        {
            "Incident": row["incident_id"],
            "Application": names.get(row["application_id"], row["application_id"] or "Legacy"),
            "Title": row["title"],
            "Severity": row["severity"],
            "Status": row["status"],
            "Occurrences": row.get("occurrence_count"),
            "Created": _time_label(row["created_at"]),
            "Updated": _time_label(row["updated_at"]),
            "Type": "Simulated" if row.get("is_simulated") else "Normal",
        }
        for row in filtered
    ])
    _section_heading("Incident ledger", f"{len(filtered)} incidents match the selected filters.")
    _table(frame)
    if not filtered:
        return
    incident_titles = {row["incident_id"]: row["title"] for row in filtered}
    selected_id = st.selectbox(
        "Inspect incident timeline",
        [row["incident_id"] for row in filtered],
        format_func=lambda value: f"{value} · {incident_titles.get(value, '')}",
    )
    incident = next(row for row in filtered if row["incident_id"] == selected_id)
    left, right = st.columns([1.1, 1])
    with left:
        _section_heading("Incident context", "Saved evidence and lifecycle timestamps.")
        st.markdown(f"**{_escape(incident['title'])}**")
        st.write(incident.get("root_cause") or "No root cause recorded.")
        st.markdown("**Recommended action**")
        st.write(incident.get("recommended_action") or "No recommendation recorded.")
        st.caption(
            f"Detected {_time_label(incident.get('source_timestamp'))} · "
            f"last seen {_time_label(incident.get('last_seen_at'))}"
        )
        if incident.get("is_simulated"):
            _badge("Simulated")
    with right:
        _section_heading("Audit timeline", "Creation, detection, status, notes, recovery, and resolution events.")
        events = [
            row for row in snapshot["incident_events"]
            if row["incident_id"] == selected_id
        ]
        if not events:
            _empty("No timeline events", "No audit events have been saved for this incident.")
        else:
            for event in sorted(events, key=lambda row: row["occurred_at"]):
                st.markdown(
                    f"**{_time_label(event['occurred_at'])} · {_escape(event['event_type'].replace('_', ' ').title())}**"
                )
                st.caption(event.get("summary") or "")
                if event.get("details"):
                    st.write(event["details"])


def render_recovery(snapshot, include_simulated):
    attempts = _visible(snapshot["recovery_attempts"], include_simulated)
    approvals = _visible(snapshot["approvals"], include_simulated)
    names = _app_names(snapshot)
    pending = [row for row in approvals if row.get("status") == "Pending"]
    successful = sum(
        str(row.get("result") or "").casefold() in {"verified", "success", "recovery verified"}
        for row in attempts
    )
    failed = sum(
        str(row.get("result") or "").casefold() in {"failed", "recovery failed"}
        for row in attempts
    )
    _render_hero(
        "Autonomous self-healing",
        "Read-only view of recovery decisions, approvals, execution results, and independent verification.",
        "POLICY CONTROLLED",
    )
    cols = st.columns(4)
    for col, card in zip(
        cols,
        (
            ("Recovery attempts", str(len(attempts)), "Saved execution history", "⟳", ACCENTS[0]),
            ("Verified successes", str(successful), "Only results with a verified success label", "✓", ACCENTS[1]),
            ("Failed attempts", str(failed), "Failures remain visible for follow-up", "!", ACCENTS[2]),
            ("Pending approvals", str(len(pending)), "Approval requests awaiting a decision", "◷", ACCENTS[3]),
        ),
    ):
        with col:
            _kpi(*card)
    _section_heading("Recovery attempt history", "Verification and error details come from recovery_attempts.")
    if attempts:
        _table(pd.DataFrame([
            {
                "Attempted": _time_label(row.get("attempted_at")),
                "Application": names.get(row.get("application_id"), row.get("application_id")),
                "Incident": row.get("incident_id") or "—",
                "Action": row.get("action") or "—",
                "Result": row.get("result") or "—",
                "Verification": row.get("verification") or "—",
                "Retries": row.get("retry_count") if row.get("retry_count") is not None else "—",
                "Approval": row.get("approval_status") or "—",
                "Simulation": "Simulated" if row.get("is_simulated") else "Normal",
                "Error": row.get("error_details") or "—",
            }
            for row in attempts
        ]))
    else:
        _empty("No recovery attempts", "No recovery execution records exist in the selected operational view.")
    _section_heading("Approval queue", "The dashboard does not approve or execute recovery actions.")
    if approvals:
        _table(pd.DataFrame([
            {
                "Requested": _time_label(row.get("requested_at")),
                "Application": names.get(row.get("application_id"), row.get("application_id")),
                "Incident": row.get("incident_id"),
                "Action": row.get("action"),
                "Status": row.get("status"),
                "Expires": _time_label(row.get("expires_at")),
                "Requested by": row.get("requested_by"),
                "Decision": row.get("decision_details") or "—",
            }
            for row in approvals
        ]))
    else:
        _empty("No approval requests", "Approval history appears here when recovery policy requires operator review.")


def _pipeline_rows(details):
    summary = details.get("scenario_summary") or {}
    stages = summary.get("stage_results") or details.get("stage_results") or {}
    if not isinstance(stages, dict) or not stages:
        return []
    items = []
    for key, value in stages.items():
        if isinstance(value, bool):
            result = "Observed" if value else "Not observed"
        elif isinstance(value, (list, tuple)):
            result = f"{len(value)} recorded"
        elif value is None:
            result = "Unavailable"
        else:
            result = str(value)
        items.append({"Stage": key.replace("_", " ").title(), "Recorded result": result})
    return items


def render_simulation_lab(snapshot):
    events = snapshot["simulations"]
    _render_hero(
        "Fault simulation lab",
        "Read-only simulation history. This page never starts faults or workloads automatically.",
        "SIMULATION DATA ISOLATED",
    )
    st.markdown(
        '<div class="sim-note">Simulation records and telemetry are explicitly marked. '
        'Use the controlled simulator separately when authorized; nothing is injected from this dashboard.</div>',
        unsafe_allow_html=True,
    )
    if not events:
        _empty("No simulation history", "No controlled simulation events have been recorded in SQLite.")
        return
    names = _app_names(snapshot)
    _section_heading("Simulation events", f"{len(events)} saved event records.")
    _table(pd.DataFrame([
        {
            "ID": row["simulation_id"],
            "Application": names.get(row["application_id"], row["application_id"]),
            "Scenario": row["simulation_type"],
            "Status": row["status"],
            "Started": _time_label(row["started_at"]),
            "Ended": _time_label(row["ended_at"]),
            "Affected endpoint": row["details"].get("affected_endpoint") or "—",
        }
        for row in events
    ]))
    selected_id = st.selectbox("Inspect simulation report", [row["simulation_id"] for row in events])
    selected = next(row for row in events if row["simulation_id"] == selected_id)
    details = selected["details"]
    summary = details.get("scenario_summary") or {}
    if summary:
        cols = st.columns(4)
        for col, card in zip(
            cols,
            (
                ("Anomalies", str(len(summary.get("anomalies_detected") or [])), "Detector results recorded", "✳", ACCENTS[3]),
                ("RCA reports", str(len(summary.get("rca_results") or [])), "Reports linked to this run", "⌕", ACCENTS[0]),
                ("Incidents", str(len(summary.get("incidents_created") or [])), "Incident IDs recorded", "◷", ACCENTS[2]),
                ("Recovery attempted", "Yes" if summary.get("recovery_attempted") else "No", "From actual recovery decisions", "⟳", ACCENTS[1]),
            ),
        ):
            with col:
                _kpi(*card)
    st.markdown("")
    config = details.get("configuration") or {}
    if "configuration" in config:
        config = config["configuration"]
    _section_heading("Configuration and cleanup")
    _table(pd.DataFrame([
        {"Field": key.replace("_", " ").title(), "Value": value}
        for key, value in {
            **config,
            "Cleanup result": details.get("cleanup_result") or "—",
            "Error": details.get("error_details") or summary.get("error_details") or "—",
            "Expected outcome": details.get("expected_outcome") or summary.get("expected_outcome") or "—",
        }.items()
    ]))
    pipeline = _pipeline_rows(details)
    if pipeline:
        _section_heading("Observed pipeline stages", "A stage is reported only when its saved result exists.")
        _table(pd.DataFrame(pipeline))
    workload = details.get("workload_details")
    if workload:
        _section_heading("Workload result")
        _table(pd.DataFrame([{
            key.replace("_", " ").title(): value
            for key, value in workload.items()
        }]))


def render_dependency_map(snapshot, include_simulated):
    apps = snapshot["applications"]
    dependencies = [row for row in snapshot["dependencies"] if row.get("active")]
    _render_hero(
        "Application dependency map",
        "Registered application-to-application relationships from the dependency ledger.",
        f"{len(dependencies)} ACTIVE LINKS",
    )
    if not apps:
        _empty("No application nodes", "Register applications to build a dependency map.")
        return

    latest = _latest_readings(snapshot, include_simulated)
    nodes = []
    positions = {}
    count = len(apps)
    for index, app in enumerate(apps):
        angle = 2 * 3.141592653589793 * index / max(count, 1) - 1.5707963267948966
        x = 0.5 + 0.34 * math.cos(angle)
        y = 0.5 + 0.34 * math.sin(angle)
        positions[app["application_id"]] = (x, y)
        reading = latest.get(app["application_id"])
        nodes.append({
            "x": x,
            "y": y,
            "name": app["name"],
            "application_id": app["application_id"],
            "state": _application_state(app, reading),
            "type": app["application_type"],
        })

    edges = []
    names = _app_names(snapshot)
    for relation in dependencies:
        source = positions.get(relation["application_id"])
        target = positions.get(relation["depends_on_application_id"])
        if source and target:
            edges.append({
                "x": source[0],
                "y": source[1],
                "x2": target[0],
                "y2": target[1],
                "relationship": relation["dependency_type"],
            })
    node_frame = pd.DataFrame(nodes)
    node_chart = (
        alt.Chart(node_frame)
        .mark_circle(size=1250, stroke="#ffffff", strokeWidth=3)
        .encode(
            x=alt.X("x:Q", scale=alt.Scale(domain=[0, 1]), axis=None),
            y=alt.Y("y:Q", scale=alt.Scale(domain=[0, 1]), axis=None),
            color=alt.Color(
                "state:N",
                title="Current state",
                scale=alt.Scale(
                    domain=["Operational", "Unavailable", "Stale", "No telemetry", "Inactive", "Unknown"],
                    range=["#2e9b68", "#d34b45", "#e58b39", "#9aa6b8", "#9aa6b8", "#70809a"],
                ),
            ),
            tooltip=["name:N", "application_id:N", "state:N", "type:N"],
        )
    )
    if edges:
        edge_chart = (
            alt.Chart(pd.DataFrame(edges))
            .mark_rule(color="#9daec6", strokeWidth=2)
            .encode(
                x="x:Q",
                y="y:Q",
                x2="x2:Q",
                y2="y2:Q",
                tooltip=["relationship:N"],
            )
        )
        chart = edge_chart + node_chart
    else:
        chart = node_chart
    label_chart = (
        alt.Chart(node_frame)
        .mark_text(dy=30, fontSize=11, fontWeight=700, color="#34445c")
        .encode(x="x:Q", y="y:Q", text="name:N")
    )
    st.altair_chart(
        (chart + label_chart).properties(height=410).configure_view(stroke=None),
        use_container_width=True,
    )
    if not dependencies:
        st.info("No dependency relationships are registered. Nodes above represent applications only; no links are inferred.")
    _section_heading("Dependency records", "Direction: application depends on the listed upstream service.")
    if dependencies:
        _table(pd.DataFrame([
            {
                "Application": names.get(row["application_id"], row["application_id"]),
                "Depends on": names.get(row["depends_on_application_id"], row["depends_on_application_id"]),
                "Relationship": row["dependency_type"],
                "Updated": _time_label(row["updated_at"]),
            }
            for row in dependencies
        ]))
    else:
        _empty("No dependency records", "Relationships are displayed only when explicitly registered.")


def render_reports(snapshot, system_metrics, include_simulated):
    _render_hero(
        "Reports and analytics",
        "A shareable view of stored operational signals with CSV exports for analysis.",
        "SQLITE + MONITOR DATA",
    )
    period = st.selectbox(
        "Reporting window",
        ["All available history", "Last 24 hours", "Last 7 days", "Last 30 days"],
        key="reporting_window",
    )
    days = {"Last 24 hours": 1, "Last 7 days": 7, "Last 30 days": 30}.get(period)
    cutoff = datetime.now().astimezone() - timedelta(days=days) if days else None

    def in_window(row, field):
        if cutoff is None:
            return True
        parsed = _decode_time(row.get(field))
        return parsed is not None and parsed >= cutoff

    incidents = [
        row for row in _visible(snapshot["incidents"], include_simulated)
        if in_window(row, "created_at")
    ]
    anomalies = [
        row for row in _visible(snapshot["anomalies"], include_simulated)
        if in_window(row, "timestamp")
    ]
    telemetry = [
        row for row in snapshot["telemetry"]
        if (include_simulated or not row.get("is_simulated"))
        and in_window(row, "timestamp")
    ]
    rcas = [
        row for row in _visible(snapshot["rca_reports"], include_simulated)
        if in_window(row, "created_at")
    ]
    recoveries = [
        row for row in _visible(snapshot["recovery_attempts"], include_simulated)
        if in_window(row, "attempted_at")
    ]

    cols = st.columns(4)
    for col, card in zip(
        cols,
        (
            ("Telemetry samples", str(len(telemetry)), period, "▤", ACCENTS[0]),
            ("Anomaly results", str(len(anomalies)), "Saved detector outputs", "✳", ACCENTS[3]),
            ("Incidents created", str(len(incidents)), "Based on incident creation time", "◷", ACCENTS[2]),
            ("RCA reports", str(len(rcas)), "Saved analysis reports", "⌕", ACCENTS[1]),
        ),
    ):
        with col:
            _kpi(*card)

    status_counts = pd.DataFrame([
        {"Status": status, "Incidents": sum(row["status"] == status for row in incidents)}
        for status in sorted({row["status"] for row in incidents})
    ])
    left, right = st.columns(2)
    with left:
        _section_heading("Incident lifecycle", "Counts come from incidents created in the selected period.")
        if status_counts.empty:
            _empty("No incident counts", "No incident records fall within this reporting window.")
        else:
            chart = (
                alt.Chart(status_counts)
                .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6, color="#8158d8")
                .encode(
                    x=alt.X("Status:N", sort="-y", axis=alt.Axis(labelAngle=0)),
                    y=alt.Y("Incidents:Q", title="Incident count", axis=alt.Axis(gridColor="#edf1f6")),
                    tooltip=["Status:N", "Incidents:Q"],
                )
                .properties(height=280)
                .configure_view(stroke=None)
            )
            st.altair_chart(chart, use_container_width=True)
    with right:
        _section_heading("Host performance context", "Most recent saved samples from the system monitor.")
        _time_series_chart(
            system_metrics.tail(180),
            ["cpu_usage", "memory_usage", "disk_usage"],
            {"cpu_usage": "#4778e8", "memory_usage": "#8158d8", "disk_usage": "#159b91"},
            height=280,
        )

    st.markdown("---")
    _section_heading("Export saved records", "Downloads contain existing records only; no report rows are synthesized.")
    choices = st.columns(3)
    export_frames = {
        "Telemetry": pd.DataFrame([
            {
                "application_id": row["application_id"],
                "source": row["source"],
                "timestamp": row["timestamp"],
                "is_simulated": bool(row["is_simulated"]),
                **row["data"],
            }
            for row in telemetry
        ]),
        "Incidents": pd.DataFrame(incidents),
        "Anomalies": pd.DataFrame([
            {
                "anomaly_id": row["anomaly_id"],
                "application_id": row["application_id"],
                "timestamp": row["timestamp"],
                "prediction": row["prediction"],
                "score": row["anomaly_score"],
                "status": row["status"],
                "is_simulated": bool(row["is_simulated"]),
                **row["details"],
            }
            for row in anomalies
        ]),
        "RCA reports": pd.DataFrame(rcas),
        "Recovery attempts": pd.DataFrame(recoveries),
    }
    for index, (name, frame) in enumerate(export_frames.items()):
        with choices[index % len(choices)]:
            st.download_button(
                f"Download {name} CSV",
                data=frame.to_csv(index=False).encode("utf-8"),
                file_name=f"sdp_{name.casefold().replace(' ', '_')}.csv",
                mime="text/csv",
                key=f"export_{name}",
                disabled=frame.empty,
                use_container_width=True,
            )


def run_dashboard():
    st.set_page_config(
        page_title="SDP | AIOps Operations Center",
        page_icon="✦",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _style()

    st.sidebar.markdown(
        '<div class="brand-lockup"><div class="brand-mark">S</div>'
        '<div><div class="brand-name">SDP AIOps</div>'
        '<div class="brand-caption">OPERATIONS CENTER</div></div></div>',
        unsafe_allow_html=True,
    )
    selected_page = st.sidebar.radio(
        "Workspace",
        PAGES,
        format_func=lambda page: f"{PAGE_ICONS[page]}   {page}",
        label_visibility="collapsed",
        key="ops_dashboard_page",
    )
    st.sidebar.markdown("---")
    include_simulated = st.sidebar.checkbox(
        "Include simulated records",
        value=False,
        help="Operational pages exclude simulated records by default. The Simulation Lab always shows simulation history.",
    )
    st.sidebar.caption("Operations console · refreshes every 15 seconds")
    st.sidebar.caption("Source: project SQLite database and local monitor")

    st_autorefresh(interval=REFRESH_INTERVAL_MS, key="ops_dashboard_refresh")
    st.markdown(
        '<div class="topline"><span>SDP / Intelligent AIOps Platform</span>'
        f'<span>{_escape(datetime.now().astimezone().strftime("%a, %b %d · %H:%M:%S"))} · '
        "LOCAL ENVIRONMENT</span></div>",
        unsafe_allow_html=True,
    )
    st.title(selected_page)

    try:
        snapshot = load_snapshot()
    except (OSError, sqlite3.Error, RuntimeError) as error:
        st.error(f"Could not read the project database: {error}")
        st.stop()
    system_metrics, metrics_error = load_system_metrics()
    if metrics_error:
        st.warning(f"System metrics CSV could not be read: {metrics_error}")
    if snapshot["invalid_json_count"]:
        st.warning(
            f"{snapshot['invalid_json_count']} saved JSON record(s) could not be decoded; "
            "their unavailable details are shown as empty."
        )
    if include_simulated:
        st.info("Simulated telemetry and incidents are included and labeled in operational views.")

    page_renderers = {
        "Overview Dashboard": lambda: render_overview(snapshot, system_metrics, include_simulated),
        "Application Registry": lambda: render_registry(snapshot, include_simulated),
        "Automatic Application Discovery": render_browser_discovery,
        "Multi-Application Monitoring": lambda: render_multi_monitoring(snapshot, include_simulated),
        "Performance Analytics": lambda: render_performance(snapshot, system_metrics, include_simulated),
        "AI Anomaly Detection": lambda: render_anomalies(snapshot, include_simulated),
        "Root Cause Analysis": lambda: render_rca(snapshot, include_simulated),
        "Incident Management": lambda: render_incidents(snapshot, include_simulated),
        "Autonomous Self-Healing": lambda: render_recovery(snapshot, include_simulated),
        "Fault Simulation Lab": lambda: render_simulation_lab(snapshot),
        "Application Dependency Map": lambda: render_dependency_map(snapshot, include_simulated),
        "Reports and Analytics": lambda: render_reports(snapshot, system_metrics, include_simulated),
    }
    page_renderers[selected_page]()

    st.markdown("---")
    st.caption(
        f"SDP Operations Center · Last data refresh {_escape(datetime.now().astimezone().strftime('%H:%M:%S'))} · "
        "Unavailable values are shown as an em dash; simulations remain separately tagged."
    )
