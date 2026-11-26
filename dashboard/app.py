
from pathlib import Path as _Path
import sys as _sys

import streamlit as st

_PROJECT_ROOT = str(_Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)

from dashboard.ops_dashboard import run_dashboard

run_dashboard()
st.stop()

import importlib.util
import math
import sqlite3
import sys
import time
from pathlib import Path

import altair as alt
import pandas as pd
import psutil
import streamlit as st
from streamlit_autorefresh import st_autorefresh

BASE_DIR = Path(__file__).resolve().parent.parent
PROJECT_ROOT = str(BASE_DIR)
if PROJECT_ROOT in sys.path:
    sys.path.remove(PROJECT_ROOT)
sys.path.insert(0, PROJECT_ROOT)


def load_project_module(module_name):
    module_path = BASE_DIR / "app" / f"{module_name}.py"
    module_spec = importlib.util.spec_from_file_location(
        f"sdp_dashboard_{module_name}",
        module_path,
    )
    if module_spec is None or module_spec.loader is None:
        raise ImportError(f"Unable to load project module: {module_path}")
    module = importlib.util.module_from_spec(module_spec)
    sys.modules[module_spec.name] = module
    module_spec.loader.exec_module(module)
    return module


dependency_mapping = load_project_module("dependency_mapping")
health_forecast = load_project_module("health_forecast")
health_policy = load_project_module("health_policy")
incident_management = load_project_module("incident_management")

# --------------------------------------------------
# 1. PROJECT FILE PATHS
# --------------------------------------------------

METRICS_FILE = BASE_DIR / "data" / "metrics.csv"
ANOMALY_FILE = BASE_DIR / "data" / "anomaly_results.csv"
INCIDENT_FILE = BASE_DIR / "data" / "incident_reports.csv"

SELF_HEALING_LOG = BASE_DIR / "logs" / "self_healing_log.csv"
CPU_ALERT_THRESHOLD = health_policy.RESOURCE_NORMAL_MAX
MEMORY_ALERT_THRESHOLD = health_policy.RESOURCE_NORMAL_MAX
DISK_ALERT_THRESHOLD = health_policy.RESOURCE_NORMAL_MAX
RESOURCE_CRITICAL_THRESHOLD = health_policy.RESOURCE_CRITICAL_THRESHOLD
DASHBOARD_REFRESH_MS = 15_000
CHART_POINT_LIMIT = 60
STALE_READING_SECONDS = 30


def active_test_workloads():
    now = time.monotonic()
    previous_samples = st.session_state.get("test_workload_cpu_samples", {})
    current_samples = {}
    workloads = []

    for process in psutil.process_iter(["pid", "cmdline"]):
        try:
            command_line = " ".join(process.info["cmdline"] or [])
            if "AIOPS_CPU_SECONDS:" in command_line:
                kind = "CPU"
            elif "AIOPS_MEMORY_RSS_MIB:" in command_line:
                kind = "Memory"
            else:
                continue

            cpu_times = process.cpu_times()
            cpu_seconds = cpu_times.user + cpu_times.system
            previous = previous_samples.get(process.pid)
            cpu_percent = None
            if previous is not None and now > previous[1]:
                cpu_percent = max(
                    0.0,
                    (cpu_seconds - previous[0]) / (now - previous[1]) * 100,
                )
            current_samples[process.pid] = (cpu_seconds, now)
            workloads.append(
                {
                    "kind": kind,
                    "pid": process.pid,
                    "cpu_percent": cpu_percent,
                    "memory_mib": process.memory_info().rss / (1024 * 1024),
                }
            )
        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            OSError,
        ):
            continue

    st.session_state.test_workload_cpu_samples = current_samples
    return workloads


def build_time_series_chart(
    readings,
    series,
    thresholds=None,
    y_domain=None,
    height=245,
    y_format="~s",
):
    columns = [column for column, _, _ in series if column in readings.columns]
    if not columns:
        return None

    chart_data = readings[["timestamp", *columns]].copy()
    chart_data["timestamp"] = pd.to_datetime(
        chart_data["timestamp"], errors="coerce"
    )
    for column in columns:
        chart_data[column] = pd.to_numeric(chart_data[column], errors="coerce")
    chart_data = chart_data.dropna(subset=["timestamp"])
    chart_data = chart_data.melt(
        id_vars="timestamp",
        value_vars=columns,
        var_name="metric",
        value_name="value",
    ).dropna(subset=["value"])
    chart_data = chart_data[chart_data["value"].map(math.isfinite)]
    if chart_data.empty:
        return None

    label_by_column = {
        column: label for column, label, _ in series if column in columns
    }
    chart_data["metric"] = chart_data["metric"].map(label_by_column)
    labels = list(label_by_column.values())
    colors = [color for column, _, color in series if column in columns]
    if y_domain is not None:
        value_scale = alt.Scale(domain=list(y_domain))
    elif (
        chart_data["value"].min() == 0
        and chart_data["value"].max() == 0
    ):
        value_scale = alt.Scale(domain=[0, 1])
    else:
        value_scale = alt.Scale(zero=True)
    base = alt.Chart(chart_data).encode(
        x=alt.X(
            "timestamp:T",
            title=None,
            axis=alt.Axis(
                format="%H:%M",
                tickCount=5,
                labelColor="#91a3ba",
                labelOverlap="greedy",
                grid=False,
            ),
        ),
        y=alt.Y(
            "value:Q",
            title=None,
            scale=value_scale,
            axis=alt.Axis(
                gridColor="#24344a",
                gridOpacity=0.7,
                labelColor="#91a3ba",
                tickCount=5,
                format=y_format,
            ),
        ),
        color=alt.Color(
            "metric:N",
            title=None,
            scale=alt.Scale(domain=labels, range=colors),
            legend=(
                None
                if len(columns) == 1
                else alt.Legend(
                    orient="top",
                    direction="horizontal",
                    labelColor="#a9bad0",
                )
            ),
        ),
        tooltip=[
            alt.Tooltip("timestamp:T", title="Time", format="%H:%M:%S"),
            alt.Tooltip("metric:N", title="Metric"),
            alt.Tooltip("value:Q", title="Value", format=",.2f"),
        ],
    )
    layers = [
        base.mark_line(
            interpolate="monotone",
            point=alt.OverlayMarkDef(size=34, filled=True),
            strokeWidth=2.5,
        )
    ]
    for threshold, color in thresholds or ():
        threshold_data = pd.DataFrame({"threshold": [threshold]})
        layers.append(
            alt.Chart(threshold_data)
            .mark_rule(color=color, strokeDash=[6, 4], strokeWidth=1.5)
            .encode(y="threshold:Q")
        )

    return (
        alt.layer(*layers)
        .properties(height=height)
        .configure(background="transparent")
        .configure_view(stroke=None)
        .configure_axis(
            domain=False,
            tickColor="#34445a",
            labelFont="Inter",
            labelFontSize=11,
        )
    )


# --------------------------------------------------
# 2. PAGE CONFIGURATION
# --------------------------------------------------

st.set_page_config(
    page_title="SDP | AI Operations Center",
    page_icon="⚡",
    layout="wide",
)

st.markdown(
    """
    <style>
    [data-testid="stAppViewContainer"] {
        background:
            radial-gradient(ellipse at 12% 0%, rgba(32, 79, 120, 0.18), transparent 38%),
            #0b1220;
        color: #d7e2f1;
    }
    [data-testid="stHeader"] {
        background: rgba(11, 18, 32, 0.86);
    }
    [data-testid="stSidebar"] {
        background: #0e1728;
        border-right: 1px solid #1e2b40;
    }
    .block-container {
        max-width: 1600px;
        padding: 2rem 2.5rem 4rem;
    }
    h1, h2, h3 {
        color: #eef4ff;
        letter-spacing: -0.025em;
    }
    [data-testid="stMarkdownContainer"] p,
    [data-testid="stCaptionContainer"] {
        color: #a9bad0;
    }
    a {
        color: #65d8c3;
    }
    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #141f31, #101a2a);
        border: 1px solid #26364d;
        border-radius: 14px;
        padding: 0.8rem 0.95rem;
        min-height: 92px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
    }
    [data-testid="stMetricLabel"] {
        color: #9aacc4;
        font-size: 0.78rem;
        font-weight: 600;
    }
    [data-testid="stMetricValue"] {
        color: #f3f7ff;
        font-size: clamp(1.15rem, 1.8vw, 1.65rem);
        line-height: 1.2;
        white-space: normal;
        overflow-wrap: anywhere;
    }
    [data-testid="stMetricValue"] div,
    [data-testid="stMetricLabel"] div {
        overflow: visible;
        text-overflow: clip;
        white-space: normal;
        overflow-wrap: anywhere;
    }
    [data-testid="stVegaLiteChart"] {
        background: transparent;
    }
    [data-testid="stAlert"], [data-testid="stExpander"] {
        border-radius: 12px;
    }
    [data-testid="stDataFrame"] {
        border: 1px solid #26364d;
        border-radius: 12px;
        overflow: hidden;
    }
    .ops-hero {
        background: linear-gradient(115deg, #14263d, #101a2b 68%, #142d3b);
        border: 1px solid #29405a;
        border-radius: 20px;
        padding: 1.8rem 2rem;
        margin: 0.5rem 0 1.3rem;
    }
    .ops-eyebrow {
        color: #65d8c3;
        font-size: 0.75rem;
        font-weight: 700;
        letter-spacing: 0.15em;
        text-transform: uppercase;
    }
    .ops-hero h1 {
        margin: 0.45rem 0 0.3rem;
        font-size: 2.35rem;
    }
    .ops-hero p {
        color: #a9bad0;
        margin: 0;
    }
    .ops-live {
        color: #65d8c3;
        font-weight: 700;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------
# 3. AUTOMATIC REFRESH
# --------------------------------------------------

st_autorefresh(
    interval=DASHBOARD_REFRESH_MS,
    key="dashboard_refresh"
)

with st.sidebar:
    st.markdown("## SDP")
    st.caption("AI OPERATIONS CENTER")
    st.divider()
    st.markdown("**Navigate**")
    st.markdown(
        "[System overview](#system-overview)  \n"
        "[Anomaly & model health](#anomaly-monitoring)  \n"
        "[Root cause analysis](#root-cause-analysis)  \n"
        "[Incidents & dependencies](#incident-management)  \n"
        "[Recovery history](#self-healing-activity-history)  \n"
        "[Telemetry records](#recent-monitoring-records)"
    )
    st.divider()
    st.markdown("**Manual interventions**")
    st.markdown(
        '<a href="http://127.0.0.1:8502" target="_blank" '
        'rel="noopener noreferrer">Open Testing Control Panel ↗</a>',
        unsafe_allow_html=True,
    )
    st.caption(
        "When the monitor is running, it applies safe recovery automatically; "
        "Flask health failures are restarted immediately, and sustained high "
        "memory triggers a restart after 60 seconds. Outcomes appear below."
    )
    st.divider()
    st.caption("Live refresh · every 15 seconds")


# --------------------------------------------------
# 4. DASHBOARD TITLE
# --------------------------------------------------

st.markdown(
    """
    <div class="ops-hero">
        <div class="ops-eyebrow">SDP · LIVE OPERATIONS</div>
        <h1>AI Operations Center</h1>
        <p>System health, incident intelligence, dependency signals, and safe recovery.</p>
        <p class="ops-live">● AUTO-REFRESH ON · 15-second interval</p>
    </div>
    """,
    unsafe_allow_html=True,
)

st.divider()


# --------------------------------------------------
# 5. CHECK METRICS FILE
# --------------------------------------------------

if not METRICS_FILE.exists():

    st.error("Metrics file not found!")

    st.info(
        "Please start the monitoring program using: "
        "python app/monitor.py"
    )

    st.stop()


# --------------------------------------------------
# 6. LOAD EXISTING AI AND INCIDENT RESULTS
# --------------------------------------------------

st.caption(
    "Live telemetry and saved analysis results are combined here; model runs "
    "and recovery actions remain explicit operations."
)


# --------------------------------------------------
# 9. LOAD MONITORING DATA
# --------------------------------------------------

try:

    metrics = pd.read_csv(METRICS_FILE)

    if metrics.empty:
        st.warning("No monitoring data available.")
        st.stop()

except Exception as e:
    st.error(f"Unable to read metrics file: {e}")
    st.stop()


# --------------------------------------------------
# 10. LOAD AI RESULTS
# --------------------------------------------------

try:

    if ANOMALY_FILE.exists():
        anomalies = pd.read_csv(ANOMALY_FILE)
    else:
        anomalies = pd.DataFrame()

except Exception as e:
    st.error(f"Unable to read anomaly results: {e}")
    anomalies = pd.DataFrame()


# --------------------------------------------------
# 11. DATA PREPROCESSING
# --------------------------------------------------

required_columns = [
    "timestamp",
    "cpu_usage",
    "memory_usage",
    "application_status"
]

missing_columns = [
    column for column in required_columns
    if column not in metrics.columns
]

if missing_columns:
    st.error(
        "Missing columns in metrics.csv: "
        + ", ".join(missing_columns)
    )
    st.stop()


metrics["cpu_usage"] = pd.to_numeric(
    metrics["cpu_usage"],
    errors="coerce"
)

metrics["memory_usage"] = pd.to_numeric(
    metrics["memory_usage"],
    errors="coerce"
)

optional_metric_columns = [
    "available_memory_mb",
    "disk_usage",
    "network_sent_bytes_per_sec",
    "network_received_bytes_per_sec",
    "response_time_ms",
    "api_error_rate",
    "request_throughput_rps",
    "application_available",
    "application_process_pid",
    "application_process_memory_mb",
    "application_process_memory_percent",
]
for column in optional_metric_columns:
    if column in metrics.columns:
        metrics[column] = pd.to_numeric(metrics[column], errors="coerce")

metrics = metrics.dropna(
    subset=["cpu_usage", "memory_usage"]
)

if metrics.empty:
    st.warning("No valid monitoring readings found.")
    st.stop()


# --------------------------------------------------
# 12. LATEST SYSTEM READINGS
# --------------------------------------------------

latest = metrics.iloc[-1]

cpu = latest["cpu_usage"]
memory = latest["memory_usage"]
app_status = latest["application_status"]
latest_timestamp = str(latest["timestamp"])
current_ai_status = "Unavailable"
parsed_timestamp = pd.to_datetime(latest_timestamp, errors="coerce")
reading_age_seconds = None
if pd.isna(parsed_timestamp):
    st.warning("The timestamp on the latest monitoring reading is invalid.")
else:
    reading_age_seconds = max(
        0,
        (pd.Timestamp.now() - parsed_timestamp).total_seconds(),
    )
    if reading_age_seconds > STALE_READING_SECONDS:
        st.warning(
            f"Monitoring data is stale: latest reading is "
            f"{reading_age_seconds:.0f} seconds old."
        )
reading_is_fresh = (
    reading_age_seconds is not None
    and reading_age_seconds <= STALE_READING_SECONDS
)
if (
    reading_is_fresh
    and not anomalies.empty
    and {"timestamp", "status"}.issubset(anomalies.columns)
):
    matching_ai = anomalies[
        anomalies["timestamp"].astype(str).eq(latest_timestamp)
    ]
    if not matching_ai.empty:
        current_ai_status = str(matching_ai.iloc[-1]["status"])


# --------------------------------------------------
# 13. SYSTEM OVERVIEW
# --------------------------------------------------

st.markdown('<div id="system-overview"></div>', unsafe_allow_html=True)
st.subheader("System health overview")

disk = latest.get("disk_usage")
response_time = latest.get("response_time_ms")
api_error_rate = latest.get("api_error_rate")
resource_readings = [
    ("CPU", cpu),
    ("Memory", memory),
    ("Disk", disk),
]
resource_levels = [
    health_policy.resource_severity(value)
    for _, value in resource_readings
]
if not reading_is_fresh:
    overall_health = "Unavailable"
elif (
    str(app_status).lower() in {"unreachable", "unavailable"}
    or "Critical" in resource_levels
):
    overall_health = "Critical"
elif (
    "Warning" in resource_levels
    or (pd.notna(response_time) and response_time > 1000)
    or (pd.notna(api_error_rate) and api_error_rate > 5)
    or current_ai_status == "Anomaly"
    or (
        reading_age_seconds is not None
        and reading_age_seconds > STALE_READING_SECONDS
    )
):
    overall_health = "Degraded"
else:
    overall_health = "Healthy"

health_metrics = st.columns(5)
health_metrics[0].metric("Health", overall_health)
health_metrics[1].metric(
    "Flask API",
    str(app_status) if reading_is_fresh else "Stale",
)
health_metrics[2].metric("CPU", f"{cpu:.1f}%")
health_metrics[3].metric("Memory", f"{memory:.1f}%")
health_metrics[4].metric(
    "Disk",
    f"{disk:.1f}%" if pd.notna(disk) else "Unavailable",
)

secondary_metrics = st.columns(4)
for index, (column, label, unit) in enumerate(
    (
        ("response_time_ms", "API response", " ms"),
        ("api_error_rate", "Error rate", "%"),
        ("request_throughput_rps", "Requests/sec", " req/s"),
        ("available_memory_mb", "Free memory", " MB"),
    )
):
    value = latest.get(column)
    secondary_metrics[index].metric(
        label,
        f"{value:.1f}{unit}" if pd.notna(value) else "Unavailable",
    )
st.caption(f"{len(metrics):,} metric samples · latest reading {latest['timestamp']}")
network_columns = st.columns(2)
for index, (column, label) in enumerate(
    (
        ("network_sent_bytes_per_sec", "Network Sent"),
        ("network_received_bytes_per_sec", "Network Received"),
    )
):
    value = latest.get(column)
    network_columns[index].metric(
        label,
        f"{value:.1f} bytes/s" if pd.notna(value) else "Unavailable",
    )
process_columns = st.columns(2)
for index, (column, label, unit) in enumerate(
    (
        ("application_process_pid", "Flask Process PID", ""),
        ("application_process_memory_mb", "Flask Process RSS", " MB"),
    )
):
    value = latest.get(column)
    if pd.notna(value):
        display_value = f"{int(value)}" if not unit else f"{value:.1f}{unit}"
    else:
        display_value = "Unavailable"
    process_columns[index].metric(label, display_value)
st.caption(f"Latest monitoring reading: {latest_timestamp}")

st.markdown(
    "**Rule-based system/application alerts** (separate from multivariate "
    "Isolation Forest predictions)"
)
threshold_alerts = []
critical_alerts = []
if not reading_is_fresh:
    st.info("Current alerts are paused until fresh monitoring data is available.")
else:
    for (label, value), severity in zip(resource_readings, resource_levels):
        if severity == "Critical":
            critical_alerts.append(
                f"{label} is critical at {value:.1f}% "
                f"(critical threshold: {RESOURCE_CRITICAL_THRESHOLD:.0f}%)."
            )
        elif severity == "Warning":
            threshold_alerts.append(
                f"{label} is elevated at {value:.1f}% "
                f"(normal through {health_policy.RESOURCE_NORMAL_MAX:.0f}%; "
                f"critical at {RESOURCE_CRITICAL_THRESHOLD:.0f}%)."
            )
    if pd.notna(response_time) and response_time > 1000:
        threshold_alerts.append(
            f"API response time is elevated: {response_time:.1f} ms > 1000 ms."
        )
    if pd.notna(api_error_rate) and api_error_rate > 5:
        threshold_alerts.append(
            f"API error rate is elevated: {api_error_rate:.1f}% > 5%."
        )
    if critical_alerts or threshold_alerts:
        for alert in critical_alerts:
            st.error(alert)
        for alert in threshold_alerts:
            st.warning(alert)
    else:
        st.success(
            "No configured CPU, memory, disk, response-time, or API error "
            "threshold alert."
        )

st.markdown("**Predictive health trends** (separate from threshold and AI alerts)")
st.caption(
    "Heuristic linear projections use at least six readings spanning one minute "
    "and a 30-minute forecast horizon; they complement, not replace, anomaly detection."
)
if reading_is_fresh:
    trend_analysis = health_forecast.forecast_threshold_crossings(
        metrics.tail(360).to_dict(orient="records")
    )
    for forecast in trend_analysis["warnings"]:
        st.warning(
            f"{forecast['label']} is rising at an estimated "
            f"{forecast['slope_per_hour']:.1f}{forecast['unit']}/hour. "
            f"Current: {forecast['current_value']:.1f}{forecast['unit']}; "
            f"projected to reach {forecast['threshold']:.1f}{forecast['unit']} "
            f"in about {forecast['minutes_to_threshold']:.1f} minutes."
        )
    if not trend_analysis["warnings"]:
        if trend_analysis["insufficient_metrics"]:
            insufficient = ", ".join(trend_analysis["insufficient_metrics"])
            st.info(
                "No early-warning projection is available yet. More valid history "
                f"is needed for: {insufficient}."
            )
        else:
            st.success(
                "No increasing metric trend is projected to cross a configured "
                "threshold within 30 minutes."
            )
else:
    st.info("Predictive alerts are paused until fresh monitoring data is available.")

st.markdown("**Live workload detection** (actual worker processes; separate from threshold alerts)")
active_workloads = active_test_workloads()
if active_workloads:
    for workload in active_workloads:
        if workload["kind"] == "CPU":
            process_cpu = workload["cpu_percent"]
            cpu_detail = (
                f"{process_cpu:.1f}% of one CPU core"
                if process_cpu is not None
                else "sampling process CPU"
            )
            st.warning(
                f"CPU test process detected (PID {workload['pid']}): {cpu_detail}; "
                f"system CPU from metrics.csv is {cpu:.1f}%."
            )
        else:
            st.warning(
                f"Memory test process detected (PID {workload['pid']}): "
                f"{workload['memory_mib']:.1f} MiB resident memory; "
                f"system memory from metrics.csv is {memory:.1f}%."
            )
else:
    st.caption("No active CPU or memory test worker process detected.")


# --------------------------------------------------
# 14. PERFORMANCE CHARTS
# --------------------------------------------------

st.divider()
st.subheader("System performance")
st.caption(
    f"Recent telemetry · last {CHART_POINT_LIMIT} readings · refreshed every 15 seconds"
)

chart_metrics = metrics.tail(CHART_POINT_LIMIT).copy()
primary_charts = [
    (
        "CPU utilization",
        [("cpu_usage", "CPU", "#43d7bd")],
        [
            (CPU_ALERT_THRESHOLD, "#f7b955"),
            (RESOURCE_CRITICAL_THRESHOLD, "#fb7185"),
        ],
        "Warning above 91% · critical at 95%",
    ),
    (
        "Memory utilization",
        [("memory_usage", "Memory", "#9d8bff")],
        [
            (MEMORY_ALERT_THRESHOLD, "#f7b955"),
            (RESOURCE_CRITICAL_THRESHOLD, "#fb7185"),
        ],
        "Warning above 91% · critical at 95%",
    ),
]
primary_columns = st.columns(2)
for chart_column, (title, series, thresholds, caption) in zip(
    primary_columns, primary_charts
):
    with chart_column:
        with st.container(border=True):
            st.markdown(f"**{title}**")
            st.caption(caption)
            chart = build_time_series_chart(
                chart_metrics,
                series,
                thresholds=thresholds,
                y_domain=(0, 100),
            )
            if chart is not None:
                st.altair_chart(chart, width="stretch", theme=None)
            else:
                st.caption("No valid samples yet.")

extended_charts = [
    (
        "Disk utilization",
        [("disk_usage", "Disk", "#f7b955")],
        [
            (DISK_ALERT_THRESHOLD, "#f7b955"),
            (RESOURCE_CRITICAL_THRESHOLD, "#fb7185"),
        ],
        "Warning above 91% · critical at 95%",
        (0, 100),
    ),
    (
        "Network traffic",
        [
            ("network_sent_bytes_per_sec", "Sent", "#43d7bd"),
            ("network_received_bytes_per_sec", "Received", "#72a7ff"),
        ],
        [],
        "Bytes per second",
        None,
    ),
    (
        "API response time",
        [("response_time_ms", "Response time", "#72a7ff")],
        [(1000, "#f7b955")],
        "Alert threshold · 1,000 ms",
        None,
    ),
    (
        "API error rate",
        [("api_error_rate", "Error rate", "#fb7185")],
        [(5, "#f7b955")],
        "Alert threshold · 5%",
        (0, 100),
    ),
    (
        "Request throughput",
        [("request_throughput_rps", "Requests/sec", "#43d7bd")],
        [],
        "Requests per second",
        None,
    ),
]
available_extended_charts = [
    chart
    for chart in extended_charts
    if any(column in metrics.columns for column, _, _ in chart[1])
]
for start in range(0, len(available_extended_charts), 2):
    chart_columns = st.columns(2)
    for chart_column, (title, series, thresholds, caption, y_domain) in zip(
        chart_columns, available_extended_charts[start : start + 2]
    ):
        with chart_column:
            with st.container(border=True):
                st.markdown(f"**{title}**")
                st.caption(caption)
                chart = build_time_series_chart(
                    chart_metrics,
                    series,
                    thresholds=thresholds,
                    y_domain=y_domain,
                    height=220,
                )
                if chart is not None:
                    st.altair_chart(chart, width="stretch", theme=None)
                else:
                    st.caption("No valid samples yet.")


# --------------------------------------------------
# 15. AI ANOMALY SUMMARY
# --------------------------------------------------

st.divider()
st.markdown('<div id="anomaly-monitoring"></div>', unsafe_allow_html=True)
st.subheader("Anomaly timeline & model monitoring")
st.caption(
    "Operational model signals only: without labeled outcomes, anomaly rate "
    "and score drift are not accuracy or precision measurements."
)
st.caption(
    f"Live view is limited to predictions matching the latest "
    f"{CHART_POINT_LIMIT} telemetry readings."
)

has_recent_model_results = False
if not anomalies.empty and "status" in anomalies.columns:
    historical_model_history = anomalies.copy()
    if "timestamp" in historical_model_history.columns:
        historical_model_history["parsed_timestamp"] = pd.to_datetime(
            historical_model_history["timestamp"], errors="coerce"
        )
        historical_model_history = (
            historical_model_history.dropna(subset=["parsed_timestamp"])
            .sort_values("parsed_timestamp")
        )
    model_window_start = pd.to_datetime(
        chart_metrics["timestamp"].iloc[0], errors="coerce"
    )
    recent_model_history = (
        historical_model_history[
            historical_model_history["parsed_timestamp"].ge(model_window_start)
        ]
        if (
            "parsed_timestamp" in historical_model_history.columns
            and pd.notna(model_window_start)
        )
        else historical_model_history.iloc[0:0]
    )
    has_recent_model_results = not recent_model_history.empty

    if not has_recent_model_results:
        latest_model_time = (
            historical_model_history["parsed_timestamp"].max()
            if "parsed_timestamp" in historical_model_history.columns
            else pd.NaT
        )
        latest_model_label = (
            latest_model_time.strftime("%Y-%m-%d %H:%M:%S")
            if pd.notna(latest_model_time)
            else "unknown"
        )
        st.warning(
            "Saved anomaly predictions do not match the current telemetry. "
            f"The latest model output is from {latest_model_label}."
        )
        st.markdown(
            "[Open the Testing Control Panel to run anomaly detection](http://127.0.0.1:8502)"
        )
        with st.expander("Historical model predictions"):
            st.dataframe(
                historical_model_history.drop(
                    columns=["parsed_timestamp"],
                    errors="ignore",
                )
                .tail(20)
                .iloc[::-1],
                hide_index=True,
                width="stretch",
            )
    else:
        model_history = recent_model_history.copy()
        model_history["is_anomaly"] = (
            model_history["status"]
            .astype(str)
            .str.lower()
            .eq("anomaly")
            .astype(int)
        )
    if has_recent_model_results:
        anomaly_count = int(model_history["is_anomaly"].sum())
        normal_count = int(
            model_history["status"].astype(str).str.lower().eq("normal").sum()
        )
        total_analyzed = len(model_history)
        recent_history = model_history.tail(100)
        recent_anomaly_rate = (
            recent_history["is_anomaly"].mean() * 100
            if not recent_history.empty
            else 0
        )
        score_series = (
            pd.to_numeric(model_history["anomaly_score"], errors="coerce")
            if "anomaly_score" in model_history.columns
            else pd.Series(dtype=float)
        )
        recent_scores = score_series.tail(100).dropna()
        previous_scores = score_series.iloc[:-100].tail(100).dropna()
        score_median = recent_scores.median()
        score_delta = (
            score_median - previous_scores.median()
            if not recent_scores.empty and not previous_scores.empty
            else None
        )
        model_metrics = st.columns(5)
        model_metrics[0].metric("Scored", f"{total_analyzed:,}")
        model_metrics[1].metric("Normal", f"{normal_count:,}")
        model_metrics[2].metric("Anomalies", f"{anomaly_count:,}")
        model_metrics[3].metric(
            "Anomaly rate",
            f"{recent_anomaly_rate:.1f}%",
        )
        model_metrics[4].metric(
            "Median score",
            f"{score_median:.3f}" if pd.notna(score_median) else "Unavailable",
            delta=(
                f"{score_delta:+.3f} vs prior block"
                if score_delta is not None
                else None
            ),
        )
        st.caption(
            "For Isolation Forest, lower decision scores indicate more atypical "
            "readings; scores are not probabilities. "
            "These summaries cover the current telemetry window."
        )

    if has_recent_model_results and "parsed_timestamp" in model_history.columns:
        if not model_history.empty:
            timeline_columns = st.columns(2)
            anomaly_timeline = (
                model_history.tail(CHART_POINT_LIMIT)
                .copy()
            )
            with timeline_columns[0]:
                with st.container(border=True):
                    st.markdown(
                        f"**Anomaly timeline · latest {CHART_POINT_LIMIT} predictions**"
                    )
                    anomaly_chart = (
                        alt.Chart(anomaly_timeline)
                        .mark_circle(size=42, opacity=0.9)
                        .encode(
                            x=alt.X(
                                "parsed_timestamp:T",
                                title=None,
                                axis=alt.Axis(
                                    format="%H:%M",
                                    tickCount=5,
                                    labelColor="#91a3ba",
                                    grid=False,
                                ),
                            ),
                            y=alt.Y(
                                "status:N",
                                title=None,
                                sort=["Normal", "Anomaly"],
                                axis=alt.Axis(
                                    labelColor="#91a3ba",
                                    domain=False,
                                    ticks=False,
                                ),
                            ),
                            color=alt.condition(
                                alt.datum.is_anomaly == 1,
                                alt.value("#fb7185"),
                                alt.value("#43d7bd"),
                            ),
                            tooltip=[
                                alt.Tooltip(
                                    "parsed_timestamp:T",
                                    title="Time",
                                    format="%H:%M:%S",
                                ),
                                alt.Tooltip("status:N", title="Result"),
                                alt.Tooltip(
                                    "anomaly_score:Q",
                                    title="Score",
                                    format=",.3f",
                                ),
                            ],
                        )
                        .properties(height=245)
                        .configure(background="transparent")
                        .configure_view(stroke=None)
                        .configure_axis(domain=False, tickColor="#34445a")
                    )
                    st.altair_chart(
                        anomaly_chart,
                        width="stretch",
                        theme=None,
                    )

            if "anomaly_score" in model_history.columns:
                model_history["anomaly_score"] = pd.to_numeric(
                    model_history["anomaly_score"], errors="coerce"
                )
                with timeline_columns[1]:
                    with st.container(border=True):
                        st.markdown("**Isolation Forest score trend**")
                        score_chart = build_time_series_chart(
                            model_history.tail(CHART_POINT_LIMIT)[
                                ["parsed_timestamp", "anomaly_score"]
                            ].rename(columns={"parsed_timestamp": "timestamp"}),
                            [
                                (
                                    "anomaly_score",
                                    "Anomaly score",
                                    "#9d8bff",
                                )
                            ],
                            height=245,
                            y_format=".3f",
                        )
                        if score_chart is not None:
                            st.altair_chart(
                                score_chart,
                                width="stretch",
                                theme=None,
                            )
                        else:
                            st.caption("No valid anomaly scores yet.")

        with st.expander("Latest model evaluations"):
            st.dataframe(
                model_history.drop(
                    columns=["parsed_timestamp"],
                    errors="ignore",
                )
                .tail(20)
                .iloc[::-1],
                hide_index=True,
                width="stretch",
            )
        older_model_history = historical_model_history[
            historical_model_history["parsed_timestamp"].lt(model_window_start)
        ]
        if not older_model_history.empty:
            with st.expander("Older model predictions"):
                st.dataframe(
                    older_model_history.drop(
                        columns=["parsed_timestamp"],
                        errors="ignore",
                    )
                    .tail(20)
                    .iloc[::-1],
                    hide_index=True,
                    width="stretch",
                )
else:
    st.info(
        "No model prediction history is available. Run anomaly detection from "
        "the Testing Control Panel to populate this view."
    )


# --------------------------------------------------
# 16. ROOT CAUSE ANALYSIS
# --------------------------------------------------

st.divider()
st.subheader("🔍 Root Cause Analysis")

st.caption(
    "Live analysis uses the latest monitoring reading and active CPU/memory "
    "test workers; this section refreshes every 15 seconds."
)
st.caption(f"Incident source reading: {latest_timestamp}")

live_causes = []
live_recommendations = []
if reading_is_fresh:
    if str(app_status).lower() == "unreachable":
        live_causes.append("Flask application is unreachable")
        live_recommendations.append(
            "Check the Flask application and its recovery status."
        )
    for (label, value), severity in zip(resource_readings, resource_levels):
        if severity == "Unknown":
            continue
        if severity != "Normal":
            live_causes.append(
                f"{label} utilization is {value:.1f}% "
                f"({severity.lower()}; critical at "
                f"{RESOURCE_CRITICAL_THRESHOLD:.0f}%)."
            )
            live_recommendations.append(
                f"Review {label.lower()} usage and reduce sustained load if needed."
            )
    if pd.notna(response_time) and response_time > 1000:
        live_causes.append(
            f"Elevated API response time ({response_time:.1f} ms)"
        )
        live_recommendations.append(
            "Inspect slow endpoints and downstream dependencies."
        )
    if pd.notna(api_error_rate) and api_error_rate > 5:
        live_causes.append(f"Elevated API error rate ({api_error_rate:.1f}%)")
        live_recommendations.append(
            "Review application errors and recent request failures."
        )
    if current_ai_status == "Anomaly":
        live_causes.append(
            "Combined system and application metrics flagged by multivariate AI"
        )
        live_recommendations.append(
            "Review the correlated resource, network, latency, error-rate, "
            "throughput, and availability readings."
        )
for workload in active_workloads:
    if workload["kind"] == "CPU":
        process_cpu = workload["cpu_percent"]
        cpu_detail = (
            f"{process_cpu:.1f}% of one CPU core"
            if process_cpu is not None
            else "CPU usage is being sampled"
        )
        live_causes.append(
            f"Active CPU test load detected (PID {workload['pid']}; {cpu_detail})"
        )
        live_recommendations.append(
            "Stop the CPU test load when the demonstration is complete."
        )
    else:
        live_causes.append(
            "Active memory test load detected "
            f"(PID {workload['pid']}; {workload['memory_mib']:.1f} MiB resident)"
        )
        live_recommendations.append(
            "Stop the memory test load when the demonstration is complete."
        )

if reading_is_fresh and (
    str(app_status).lower() == "unreachable"
    or "Critical" in resource_levels
    or (pd.notna(response_time) and response_time > 2500)
    or (pd.notna(api_error_rate) and api_error_rate > 20)
):
    live_severity = "Critical"
elif live_causes:
    live_severity = "Warning"
elif not reading_is_fresh:
    live_severity = "Unavailable"
else:
    live_severity = "Normal"

if live_severity == "Critical":
    st.error("🚨 Critical Incident")
elif live_severity == "Warning":
    st.warning("⚠️ Warning Detected")
elif live_severity == "Unavailable":
    st.info("Monitoring data is stale; live incident analysis is paused.")
else:
    st.success("✅ System Normal")

r1, r2, r3 = st.columns(3)
r1.metric("CPU Usage", f"{cpu:.1f}%")
r2.metric("Memory Usage", f"{memory:.1f}%")
r3.metric("Severity", live_severity)

st.markdown("### Possible Root Cause")
if live_causes:
    for cause in live_causes:
        st.write(f"- {cause}")
else:
    st.write("No major issue identified")

st.markdown("### Recommended Action")
if live_recommendations:
    for recommendation in live_recommendations:
        st.info(recommendation)
else:
    st.info("Continue monitoring system performance.")

incident_reports = pd.DataFrame()
has_recent_rca_report = False
if INCIDENT_FILE.exists():
    try:
        incident_reports = pd.read_csv(INCIDENT_FILE)
        if not incident_reports.empty:
            latest_incident = incident_reports.iloc[-1]
            report_source = latest_incident.get(
                "source_timestamp",
                latest_incident.get("timestamp"),
            )
            report_time = pd.to_datetime(
                report_source, errors="coerce", utc=True
            )
            telemetry_time = pd.to_datetime(
                latest_timestamp, errors="coerce", utc=True
            )
            if pd.notna(report_time) and pd.notna(telemetry_time):
                report_age_seconds = (
                    telemetry_time - report_time
                ).total_seconds()
                has_recent_rca_report = 0 <= report_age_seconds <= 86400
            report_label = (
                report_time.strftime("%Y-%m-%d %H:%M:%S UTC")
                if pd.notna(report_time)
                else "date unavailable"
            )
            if not has_recent_rca_report:
                st.warning(
                    f"The latest saved root-cause report is from {report_label}; "
                    "it does not describe current telemetry."
                )
                st.markdown(
                    "[Open the Testing Control Panel to run current root-cause analysis]"
                    "(http://127.0.0.1:8502)"
                )
            with st.expander(f"Saved RCA explanation · {report_label}"):
                if "root_cause_confidence" in incident_reports.columns:
                    confidence = pd.to_numeric(
                        latest_incident["root_cause_confidence"],
                        errors="coerce",
                    )
                    if pd.notna(confidence):
                        st.metric("RCA evidence confidence", f"{confidence:.0f}%")
                        st.caption(
                            "Heuristic evidence score, not a calibrated probability."
                        )
                for column, heading in (
                    ("detected_symptoms", "Detected symptoms"),
                    ("incident_timeline", "Incident timeline"),
                    ("supporting_evidence", "Supporting evidence"),
                    ("dependency_correlation", "Dependency correlation"),
                    ("root_cause", "Probable cause"),
                    ("confidence_basis", "Confidence basis"),
                    ("recommended_action", "Recommended actions"),
                ):
                    if column not in incident_reports.columns:
                        continue
                    value = latest_incident[column]
                    if pd.isna(value) or not str(value).strip():
                        continue
                    st.markdown(f"**{heading}**")
                    for item in str(value).split("; "):
                        st.write(f"- {item}")
            with st.expander("Saved incident history"):
                st.dataframe(
                    incident_reports.tail(20).iloc[::-1],
                    width="stretch",
                )
    except (OSError, UnicodeError, pd.errors.ParserError) as error:
        st.error(f"Unable to load saved incident history: {error}")

st.divider()
st.subheader("🧭 Incident Management")
st.caption(
    "Non-normal saved RCA reports are imported into the incident ledger. "
    "Acknowledge to move an incident to Investigating; recovery actions and "
    "manual resolutions are recorded in its timeline."
)

try:
    incident_management.sync_reports(
        incident_reports.to_dict(orient="records")
    )
    managed_incidents = incident_management.list_incidents()
except (OSError, sqlite3.Error, ValueError) as error:
    st.error(f"Unable to load managed incidents: {error}")
    ledger_events = [
        {
            "component": "incident_ledger",
            "status": "unavailable",
            "summary": "The SQLite incident ledger could not be queried.",
        },
        {
            "component": "incident_management_ui",
            "status": "degraded",
            "summary": "Incident management controls are unavailable.",
        },
    ]
    with st.expander("🕸️ Service dependency map and event correlation"):
        st.caption(
            "Logical project dataflow; correlation indicates a possible shared "
            "dependency, not proof of causation."
        )
        st.dataframe(
            dependency_mapping.dependency_rows(
                {
                    "incident_ledger": "Unavailable",
                    "dashboard": "Available",
                    "incident_management_ui": "Degraded",
                }
            ),
            hide_index=True,
            width="stretch",
        )
        for correlation in dependency_mapping.correlate_component_events(
            ledger_events
        ):
            st.warning(
                f"Possible upstream dependency failure: "
                f"{correlation['root_label']}."
            )
            st.write(
                "Affected component(s): "
                + ", ".join(correlation["affected_labels"])
            )
else:
    resource_signals = []
    if reading_is_fresh:
        resource_signals = [
            f"{label} {value:.1f}%"
            for (label, value), severity in zip(
                resource_readings, resource_levels
            )
            if severity in {"Warning", "Critical"}
        ]
    if not reading_is_fresh:
        resource_state = "Unknown"
    elif "Critical" in resource_levels:
        resource_state = "Critical"
    elif resource_signals:
        resource_state = "Degraded"
    else:
        resource_state = "Healthy"

    api_unavailable = (
        reading_is_fresh
        and str(app_status).lower() in {"unreachable", "unavailable"}
    )
    api_degraded = reading_is_fresh and (
        (pd.notna(response_time) and response_time > 1000)
        or (pd.notna(api_error_rate) and api_error_rate > 5)
    )
    api_state = (
        "Unknown"
        if not reading_is_fresh
        else "Unavailable"
        if api_unavailable
        else "Degraded"
        if api_degraded
        else "Healthy"
    )

    component_states = {
        "host_resources": resource_state,
        "flask_api": api_state,
        "monitoring_pipeline": (
            "Unknown"
            if reading_age_seconds is None
            else "Stale"
            if reading_age_seconds > 15
            else "Fresh"
        ),
        "metrics_store": "Available",
        "anomaly_detector": (
            current_ai_status
            if current_ai_status in {"Anomaly", "Normal"}
            else "Not run"
        ),
        "anomaly_results": (
            "Available"
            if has_recent_model_results
            else "Stale"
            if not anomalies.empty
            else "Not run"
        ),
        "root_cause_analysis": (
            "Reports available"
            if has_recent_rca_report
            else "Stale"
            if not incident_reports.empty
            else "On demand"
        ),
        "rca_reports": (
            "Available"
            if has_recent_rca_report
            else "Stale"
            if not incident_reports.empty
            else "Not run"
        ),
        "incident_ledger": "Available",
        "recovery_policy": "Automatic with approval gates",
        "dashboard": "Available",
        "incident_management_ui": "Available",
    }

    component_events = []
    if resource_state in {"Critical", "Degraded"}:
        component_events.append(
            {
                "component": "host_resources",
                "status": resource_state.lower(),
                "summary": "Host resource pressure: "
                + ", ".join(resource_signals),
            }
        )
    if reading_is_fresh and api_state in {"Unavailable", "Degraded"}:
        component_events.append(
            {
                "component": "flask_api",
                "status": api_state.lower(),
                "summary": (
                    "Flask API is unreachable."
                    if api_unavailable
                    else "Flask API latency or error rate is elevated."
                ),
            }
        )
    if reading_is_fresh and reading_age_seconds > 15:
        component_events.append(
            {
                "component": "monitoring_pipeline",
                "status": "stale",
                "summary": (
                    f"Latest telemetry is {reading_age_seconds:.0f} seconds old."
                ),
            }
        )

    correlations = dependency_mapping.correlate_component_events(
        component_events
    )
    with st.expander(
        "🕸️ Service dependency map and event correlation",
        expanded=bool(correlations),
    ):
        st.caption(
            "Logical project dataflow for SDP1's actual components. Correlation is a "
            "possible shared cause, not proof of causation."
        )
        st.dataframe(
            dependency_mapping.dependency_rows(component_states),
            hide_index=True,
            width="stretch",
        )
        if correlations:
            for correlation in correlations:
                st.warning(
                    f"Possible shared upstream dependency: "
                    f"{correlation['root_label']} "
                    f"({correlation['root_status']})."
                )
                st.write(
                    "Related affected component(s): "
                    + ", ".join(correlation["affected_labels"])
                )
                st.caption(
                    "Evidence: "
                    + "; ".join(
                        [
                            correlation["root_evidence"],
                            *correlation["affected_evidence"],
                        ]
                    )
                )
        elif component_events:
            st.info(
                "Current symptoms do not share an observed impaired upstream "
                "dependency; they remain separate signals."
            )
        else:
            st.success("No impaired dependency signals are currently observed.")

    now_utc = pd.Timestamp.now(tz="UTC")
    recent_cutoff = now_utc - pd.Timedelta(hours=24)
    recent_incidents = []
    for item in managed_incidents:
        incident_time = pd.to_datetime(
            item.get("source_timestamp"),
            errors="coerce",
            utc=True,
        )
        if (
            pd.notna(incident_time)
            and recent_cutoff <= incident_time <= now_utc
        ):
            recent_incidents.append(item)

    st.caption(
        "Showing incidents detected in the last 24 hours by default. "
        "Older incidents remain available in the history view."
    )
    incident_view = st.radio(
        "Incident time range",
        ("Recent · 24 hours", "All history"),
        horizontal=True,
        key="incident_time_range",
    )
    display_incidents = (
        recent_incidents
        if incident_view == "Recent · 24 hours"
        else managed_incidents
    )

    open_count = sum(item["status"] == "Open" for item in recent_incidents)
    investigating_count = sum(
        item["status"] == "Investigating" for item in recent_incidents
    )
    resolved_count = sum(
        item["status"] == "Resolved" for item in recent_incidents
    )
    incident_metrics = st.columns(4)
    incident_metrics[0].metric("Incidents · 24h", len(recent_incidents))
    incident_metrics[1].metric("Open · 24h", open_count)
    incident_metrics[2].metric("Investigating · 24h", investigating_count)
    incident_metrics[3].metric("Resolved · 24h", resolved_count)

    if not display_incidents:
        if managed_incidents:
            st.info(
                "No incidents were detected in the last 24 hours. "
                "Select All history to browse older incidents."
            )
        else:
            st.info("No managed incidents have been created yet.")
    else:
        st.dataframe(
            [
                {
                    "Incident ID": item["incident_id"],
                    "Severity": item["severity"],
                    "Status": item["status"],
                    "Detected": item["source_timestamp"],
                    "Recovery attempts": item["recovery_attempts"],
                    "Resolution time (seconds)": item["resolution_time_seconds"],
                    "Summary": item["title"],
                }
                for item in display_incidents
            ],
            hide_index=True,
            width="stretch",
        )

        for incident in display_incidents:
            incident_id = incident["incident_id"]
            with st.expander(
                f"{incident_id} · {incident['severity']} · "
                f"{incident['status']} — {incident['title']}"
            ):
                st.markdown(f"**Root cause:** {incident['root_cause']}")
                st.markdown(
                    f"**Recommended action:** {incident['recommended_action']}"
                )
                if incident["resolution_time_seconds"] is not None:
                    st.caption(
                        "Resolution time: "
                        f"{incident['resolution_time_seconds']:.1f} seconds"
                    )

                status_key = f"incident_status_{incident_id}"
                if status_key not in st.session_state:
                    st.session_state[status_key] = incident["status"]

                if incident["status"] == "Open" and st.button(
                    "Acknowledge incident",
                    key=f"acknowledge_{incident_id}",
                ):
                    try:
                        incident_management.acknowledge_incident(incident_id)
                        st.session_state[status_key] = "Investigating"
                        st.rerun()
                    except (KeyError, OSError, sqlite3.Error) as error:
                        st.error(f"Unable to acknowledge incident: {error}")

                st.selectbox(
                    "Incident status",
                    incident_management.INCIDENT_STATUSES,
                    key=status_key,
                )
                if st.button(
                    "Save status",
                    key=f"save_status_{incident_id}",
                ):
                    try:
                        incident_management.update_incident_status(
                            incident_id, st.session_state[status_key]
                        )
                        st.rerun()
                    except (KeyError, OSError, sqlite3.Error, ValueError) as error:
                        st.error(f"Unable to update incident status: {error}")

                st.markdown("#### Incident timeline")
                try:
                    timeline = incident_management.get_incident_timeline(
                        incident_id
                    )
                    for event in timeline:
                        st.markdown(
                            f"- **{event['occurred_at']} · "
                            f"{event['event_type'].replace('_', ' ').title()}** — "
                            f"{event['summary']}"
                        )
                        if event["details"]:
                            st.caption(event["details"])
                except (OSError, sqlite3.Error) as error:
                    st.error(f"Unable to load incident timeline: {error}")

# --------------------------------------------------
# 17. SELF-HEALING ACTIVITY HISTORY
# --------------------------------------------------

st.divider()
st.subheader("🛠️ Self-Healing Activity History")

if SELF_HEALING_LOG.exists():

    try:

        healing_logs = pd.read_csv(SELF_HEALING_LOG)

        if not healing_logs.empty:

            total_attempts = len(
                healing_logs[
                    healing_logs["action"].str.contains(
                        "Start Flask application|Recovery attempted|Restart Flask",
                        case=False,
                        na=False
                    )
                ]
            )

            successful_recoveries = len(
                healing_logs[
                    healing_logs["result"].str.contains(
                        "Recovery successful",
                        case=False,
                        na=False
                    )
                ]
            )
            escalations = (
                healing_logs["escalation"].fillna("").str.strip().ne("").sum()
                if "escalation" in healing_logs.columns
                else 0
            )

            h1, h2, h3, h4 = st.columns(4)

            h1.metric(
                "Logged Recovery Attempts",
                total_attempts
            )

            h2.metric(
                "Successful Recoveries",
                successful_recoveries
            )

            h3.metric(
                "Total Activity Records",
                len(healing_logs)
            )
            h4.metric("Escalations", int(escalations))

            latest_activity = healing_logs.iloc[-1]
            latest_result_value = latest_activity.get("result", "")
            latest_result = (
                str(latest_result_value).strip()
                if pd.notna(latest_result_value)
                else ""
            )
            latest_action_value = latest_activity.get("action", "")
            latest_action = (
                str(latest_action_value).strip()
                if pd.notna(latest_action_value)
                else ""
            )
            latest_time_value = latest_activity.get("timestamp", "")
            latest_time = (
                str(latest_time_value).strip()
                if pd.notna(latest_time_value)
                else ""
            )
            latest_verification_value = latest_activity.get("verification", "")
            latest_verification = (
                str(latest_verification_value).strip()
                if pd.notna(latest_verification_value)
                else ""
            )
            latest_escalation_value = latest_activity.get("escalation", "")
            latest_escalation = (
                str(latest_escalation_value).strip()
                if pd.notna(latest_escalation_value)
                else ""
            )
            latest_summary = " · ".join(
                value for value in (latest_time, latest_action) if value
            )
            if latest_result.casefold() == "recovery successful":
                st.success(
                    f"Latest activity: Recovery successful"
                    f"{f' · {latest_summary}' if latest_summary else ''}"
                    f"{f' · {latest_verification}' if latest_verification else ''}"
                )
            elif (
                latest_result.casefold() in {"recovery failed", "policy failed"}
                or latest_escalation
            ):
                st.error(
                    f"Latest activity: Recovery failed or escalated"
                    f"{f' · {latest_summary}' if latest_summary else ''}"
                    f"{f' · {latest_escalation}' if latest_escalation else ''}"
                )
            elif latest_result.casefold() == "approval required":
                st.warning(
                    f"Latest activity: Recovery requires approval"
                    f"{f' · {latest_summary}' if latest_summary else ''}"
                    f"{f' · {latest_verification}' if latest_verification else ''}"
                )
            else:
                st.info(
                    f"Latest activity: {latest_result or 'Unknown'}"
                    f"{f' · {latest_summary}' if latest_summary else ''}"
                )

            st.markdown("### Recent Self-Healing Activities")

            st.dataframe(
                healing_logs.tail(20).iloc[::-1],
                width="stretch"
            )

        else:
            st.info("No self-healing activities recorded yet.")

    except Exception as e:
        st.error(f"Unable to load self-healing log: {e}")

else:
    st.info(
        "Self-healing log is not available yet. "
        "Run the self-healing script to create it."
    )


# --------------------------------------------------
# 18. RECENT MONITORING RECORDS
# --------------------------------------------------

st.divider()
st.subheader("📋 Recent Monitoring Records")

st.dataframe(
    metrics.tail(20).iloc[::-1],
    width="stretch"
)


# --------------------------------------------------
# 19. SYSTEM INFORMATION
# --------------------------------------------------

st.divider()
st.subheader("⚙️ Dashboard Information")

st.write("Monitoring interval: 5 seconds")
st.write("Dashboard refresh interval: 15 seconds")
st.write("AI algorithm: Isolation Forest")
st.write(
    "AI features: CPU, memory, disk, network rates, response time, API error "
    "rate, request throughput, and application availability"
)
st.write("Data source: metrics.csv")
st.write("AI output: anomaly_results.csv")
st.write("AI detection and Root Cause Analysis: Run from the Testing Control Panel")
st.write(
    "Self-healing: Runs from the monitor; Flask restarts after 60 seconds of "
    "sustained high memory. Latest outcome and verification appear above."
)

st.caption(
    "SDP | Intelligent AIOps Platform | Final Year Project"
)
