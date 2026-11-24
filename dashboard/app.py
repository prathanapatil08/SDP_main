
import importlib.util
import sqlite3
import sys
import streamlit as st
import pandas as pd
import psutil
import time
from pathlib import Path
from streamlit_autorefresh import st_autorefresh

BASE_DIR = Path(__file__).resolve().parent.parent


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
incident_management = load_project_module("incident_management")

# --------------------------------------------------
# 1. PROJECT FILE PATHS
# --------------------------------------------------

METRICS_FILE = BASE_DIR / "data" / "metrics.csv"
ANOMALY_FILE = BASE_DIR / "data" / "anomaly_results.csv"
INCIDENT_FILE = BASE_DIR / "data" / "incident_reports.csv"

SELF_HEALING_LOG = BASE_DIR / "logs" / "self_healing_log.csv"
CPU_ALERT_THRESHOLD = 85
MEMORY_ALERT_THRESHOLD = 90


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
        padding: 1rem 1.15rem;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.12);
    }
    [data-testid="stMetricLabel"] {
        color: #9aacc4;
    }
    [data-testid="stMetricValue"] {
        color: #f3f7ff;
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
    interval=5000,
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
        "high-memory restarts require approval."
    )
    st.divider()
    st.caption("Live refresh · every 5 seconds")


# --------------------------------------------------
# 4. DASHBOARD TITLE
# --------------------------------------------------

st.markdown(
    """
    <div class="ops-hero">
        <div class="ops-eyebrow">SDP · LIVE OPERATIONS</div>
        <h1>AI Operations Center</h1>
        <p>System health, incident intelligence, dependency signals, and safe recovery.</p>
        <p class="ops-live">● AUTO-REFRESH ON · 5-second interval</p>
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
if not anomalies.empty and {"timestamp", "status"}.issubset(anomalies.columns):
    matching_ai = anomalies[
        anomalies["timestamp"].astype(str).eq(latest_timestamp)
    ]
    if not matching_ai.empty:
        current_ai_status = str(matching_ai.iloc[-1]["status"])
parsed_timestamp = pd.to_datetime(latest_timestamp, errors="coerce")
reading_age_seconds = None
if pd.isna(parsed_timestamp):
    st.warning("The timestamp on the latest monitoring reading is invalid.")
else:
    reading_age_seconds = max(
        0,
        (pd.Timestamp.now() - parsed_timestamp).total_seconds(),
    )
    if reading_age_seconds > 15:
        st.warning(
            f"Monitoring data is stale: latest reading is "
            f"{reading_age_seconds:.0f} seconds old."
        )


# --------------------------------------------------
# 13. SYSTEM OVERVIEW
# --------------------------------------------------

st.markdown('<div id="system-overview"></div>', unsafe_allow_html=True)
st.subheader("System health overview")

disk = latest.get("disk_usage")
response_time = latest.get("response_time_ms")
api_error_rate = latest.get("api_error_rate")
if (
    str(app_status).lower() in {"unreachable", "unavailable"}
    or cpu > 95
    or memory > 95
    or (pd.notna(disk) and disk > 98)
):
    overall_health = "Critical"
elif (
    cpu > CPU_ALERT_THRESHOLD
    or memory > MEMORY_ALERT_THRESHOLD
    or (pd.notna(disk) and disk > 90)
    or (pd.notna(response_time) and response_time > 1000)
    or (pd.notna(api_error_rate) and api_error_rate > 5)
    or current_ai_status == "Anomaly"
    or (reading_age_seconds is not None and reading_age_seconds > 15)
):
    overall_health = "Degraded"
else:
    overall_health = "Healthy"

health_metrics = st.columns(5)
health_metrics[0].metric("Overall health", overall_health)
health_metrics[1].metric("Flask API", str(app_status))
health_metrics[2].metric("CPU utilization", f"{cpu:.1f}%")
health_metrics[3].metric("Memory utilization", f"{memory:.1f}%")
health_metrics[4].metric(
    "Disk utilization",
    f"{disk:.1f}%" if pd.notna(disk) else "Unavailable",
)

secondary_metrics = st.columns(4)
for index, (column, label, unit) in enumerate(
    (
        ("response_time_ms", "API Response Time", " ms"),
        ("api_error_rate", "API Error Rate", "%"),
        ("request_throughput_rps", "Request Throughput", " req/s"),
        ("available_memory_mb", "Available Memory", " MB"),
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
if cpu > CPU_ALERT_THRESHOLD:
    threshold_alerts.append(
        f"CPU threshold exceeded: {cpu:.1f}% > {CPU_ALERT_THRESHOLD}%."
    )
if memory > MEMORY_ALERT_THRESHOLD:
    threshold_alerts.append(
        f"Memory threshold exceeded: {memory:.1f}% > {MEMORY_ALERT_THRESHOLD}%."
    )
if pd.notna(disk) and disk > 90:
    threshold_alerts.append(f"Disk threshold exceeded: {disk:.1f}% > 90%.")
if pd.notna(response_time) and response_time > 1000:
    threshold_alerts.append(
        f"API response time is elevated: {response_time:.1f} ms > 1000 ms."
    )
if pd.notna(api_error_rate) and api_error_rate > 5:
    threshold_alerts.append(
        f"API error rate is elevated: {api_error_rate:.1f}% > 5%."
    )
if threshold_alerts:
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
st.subheader("📈 System Performance")

left, right = st.columns(2)
chart_metrics = metrics.tail(120).set_index("timestamp")

with left:
    st.write("CPU Usage Over Time")
    st.line_chart(
        chart_metrics["cpu_usage"]
    )

with right:
    st.write("Memory Usage Over Time")
    st.line_chart(
        chart_metrics["memory_usage"]
    )
extended_charts = [
    ("Disk utilization", ["disk_usage"]),
    (
        "Network traffic",
        ["network_sent_bytes_per_sec", "network_received_bytes_per_sec"],
    ),
    ("API response time", ["response_time_ms"]),
    ("API error rate", ["api_error_rate"]),
    ("Request throughput", ["request_throughput_rps"]),
]
available_extended_charts = [
    (title, columns)
    for title, columns in extended_charts
    if any(column in metrics.columns for column in columns)
]
for start in range(0, len(available_extended_charts), 2):
    chart_columns = st.columns(2)
    for chart_column, (title, columns) in zip(
        chart_columns, available_extended_charts[start : start + 2]
    ):
        visible_columns = [
            column for column in columns if column in metrics.columns
        ]
        with chart_column:
            st.write(title)
            st.line_chart(
                metrics.tail(120)
                .set_index("timestamp")[visible_columns]
            )


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

if not anomalies.empty and "status" in anomalies.columns:
    model_history = anomalies.copy()
    if "timestamp" in model_history.columns:
        model_history["parsed_timestamp"] = pd.to_datetime(
            model_history["timestamp"], errors="coerce"
        )
        model_history = (
            model_history.dropna(subset=["parsed_timestamp"])
            .sort_values("parsed_timestamp")
        )
    model_history["is_anomaly"] = (
        model_history["status"].astype(str).str.lower().eq("anomaly").astype(int)
    )
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
    model_metrics[0].metric("Readings scored", f"{total_analyzed:,}")
    model_metrics[1].metric("Normal readings", f"{normal_count:,}")
    model_metrics[2].metric("Anomalies flagged", f"{anomaly_count:,}")
    model_metrics[3].metric(
        "Anomaly rate · latest 100",
        f"{recent_anomaly_rate:.1f}%",
    )
    model_metrics[4].metric(
        "Median score · last 100",
        f"{score_median:.3f}" if pd.notna(score_median) else "Unavailable",
        delta=(
            f"{score_delta:+.3f} vs prior block"
            if score_delta is not None
            else None
        ),
    )
    st.caption(
        "For Isolation Forest, lower decision scores indicate more atypical "
        "readings; scores are not probabilities. A negative score change "
        "indicates recent readings are more atypical than the preceding block."
    )

    if "parsed_timestamp" in model_history.columns:
        if not model_history.empty:
            timeline_columns = st.columns(2)
            anomaly_timeline = (
                model_history.tail(120)
                .set_index("parsed_timestamp")[["is_anomaly"]]
            )
            with timeline_columns[0]:
                st.markdown("**Anomaly timeline · latest 120 predictions**")
                st.area_chart(anomaly_timeline)

            if "anomaly_score" in model_history.columns:
                model_history["anomaly_score"] = pd.to_numeric(
                    model_history["anomaly_score"], errors="coerce"
                )
                with timeline_columns[1]:
                    st.markdown("**Isolation Forest score trend**")
                    st.line_chart(
                        model_history.tail(120)
                        .set_index("parsed_timestamp")[["anomaly_score"]]
                    )

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
    "test workers; this section refreshes every 5 seconds."
)
st.caption(f"Incident source reading: {latest_timestamp}")

live_causes = []
live_recommendations = []
if str(app_status).lower() == "unreachable":
    live_causes.append("Flask application is unreachable")
    live_recommendations.append(
        "Check the Flask application and its recovery status."
    )
if cpu > CPU_ALERT_THRESHOLD:
    live_causes.append(
        f"High system CPU utilization ({cpu:.1f}% > {CPU_ALERT_THRESHOLD}%)"
    )
    live_recommendations.append(
        "Inspect active CPU processes and reduce load if needed."
    )
if memory > MEMORY_ALERT_THRESHOLD:
    live_causes.append(
        f"High system memory utilization ({memory:.1f}% > {MEMORY_ALERT_THRESHOLD}%)"
    )
    live_recommendations.append(
        "Inspect memory-consuming processes and available system memory."
    )
if pd.notna(disk) and disk > 90:
    live_causes.append(f"High disk utilization ({disk:.1f}% > 90%)")
    live_recommendations.append(
        "Check disk capacity and remove or archive unneeded data."
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

if (
    str(app_status).lower() == "unreachable"
    or cpu > 95
    or memory > 95
    or (pd.notna(disk) and disk > 98)
    or (pd.notna(response_time) and response_time > 2500)
    or (pd.notna(api_error_rate) and api_error_rate > 20)
):
    live_severity = "Critical"
elif live_causes:
    live_severity = "Warning"
else:
    live_severity = "Normal"

if live_severity == "Critical":
    st.error("🚨 Critical Incident")
elif live_severity == "Warning":
    st.warning("⚠️ Warning Detected")
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
if INCIDENT_FILE.exists():
    try:
        incident_reports = pd.read_csv(INCIDENT_FILE)
        if not incident_reports.empty:
            latest_incident = incident_reports.iloc[-1]
            with st.expander("Latest saved RCA explanation"):
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
    if cpu > 85:
        resource_signals.append(f"CPU {cpu:.1f}%")
    if memory > 90:
        resource_signals.append(f"memory {memory:.1f}%")
    if pd.notna(disk) and disk > 90:
        resource_signals.append(f"disk {disk:.1f}%")
    if cpu > 95 or memory > 95 or (pd.notna(disk) and disk > 98):
        resource_state = "Critical"
    elif resource_signals:
        resource_state = "Degraded"
    else:
        resource_state = "Healthy"

    api_unavailable = str(app_status).lower() in {"unreachable", "unavailable"}
    api_degraded = (
        pd.notna(response_time) and response_time > 1000
    ) or (
        pd.notna(api_error_rate) and api_error_rate > 5
    )
    api_state = (
        "Unavailable"
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
            "Available" if not anomalies.empty else "Not run"
        ),
        "root_cause_analysis": (
            "Reports available" if not incident_reports.empty else "On demand"
        ),
        "rca_reports": (
            "Available" if not incident_reports.empty else "Not run"
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
    if api_state in {"Unavailable", "Degraded"}:
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
    if reading_age_seconds is not None and reading_age_seconds > 15:
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

    open_count = sum(item["status"] == "Open" for item in managed_incidents)
    investigating_count = sum(
        item["status"] == "Investigating" for item in managed_incidents
    )
    resolved_count = sum(item["status"] == "Resolved" for item in managed_incidents)
    incident_metrics = st.columns(4)
    incident_metrics[0].metric("Total Incidents", len(managed_incidents))
    incident_metrics[1].metric("Open", open_count)
    incident_metrics[2].metric("Investigating", investigating_count)
    incident_metrics[3].metric("Resolved", resolved_count)

    if not managed_incidents:
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
                for item in managed_incidents
            ],
            hide_index=True,
            width="stretch",
        )

        for incident in managed_incidents:
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
st.write("Dashboard refresh interval: 5 seconds")
st.write("AI algorithm: Isolation Forest")
st.write(
    "AI features: CPU, memory, disk, network rates, response time, API error "
    "rate, request throughput, and application availability"
)
st.write("Data source: metrics.csv")
st.write("AI output: anomaly_results.csv")
st.write("AI detection and Root Cause Analysis: Run from the Testing Control Panel")
st.write(
    "Self-healing: Runs from the monitor; high-memory restarts require approval"
)

st.caption(
    "SDP | Intelligent AIOps Platform | Final Year Project"
)
