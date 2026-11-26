
import os
import sys
import tempfile
from datetime import datetime
from pathlib import Path

import pandas as pd
import psutil

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import dependency_mapping, incident_management
from app.health_policy import (
    RESOURCE_CRITICAL_THRESHOLD,
    RESOURCE_NORMAL_MAX,
    RESOURCE_WARNING_THRESHOLD,
)


def active_test_workloads():
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

            workloads.append(
                {
                    "kind": kind,
                    "pid": process.info["pid"],
                    "cpu_percent": process.cpu_percent(interval=0.1),
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

    return workloads


def top_memory_processes(limit=5):
    processes = []
    for process in psutil.process_iter(["pid", "name"]):
        try:
            processes.append(
                {
                    "pid": process.info["pid"],
                    "name": process.info["name"] or "unknown",
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
    return sorted(
        processes, key=lambda process: process["memory_mib"], reverse=True
    )[:limit]



def run_legacy_root_cause():
    # --------------------------------------------------
    # 1. PROJECT PATHS
    # --------------------------------------------------

    METRICS_FILE = BASE_DIR / "data" / "metrics.csv"
    ANOMALY_FILE = BASE_DIR / "data" / "anomaly_results.csv"
    INCIDENT_FILE = BASE_DIR / "data" / "incident_reports.csv"

    # --------------------------------------------------
    # 2. CHECK FILES
    # --------------------------------------------------

    if not METRICS_FILE.exists():
        raise FileNotFoundError("Metrics file not found.")

    # --------------------------------------------------
    # 3. LOAD DATA
    # --------------------------------------------------

    metrics = pd.read_csv(METRICS_FILE)
    anomalies = pd.read_csv(ANOMALY_FILE) if ANOMALY_FILE.exists() else pd.DataFrame()

    if metrics.empty:
        raise ValueError("No monitoring data available.")

    required_metric_columns = {
        "timestamp",
        "cpu_usage",
        "memory_usage",
        "available_memory_mb",
        "application_status",
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
    }
    missing_metric_columns = required_metric_columns.difference(metrics.columns)
    if missing_metric_columns:
        raise ValueError(
            "Metrics file is missing required columns: "
            + ", ".join(sorted(missing_metric_columns))
        )

    metrics["parsed_timestamp"] = pd.to_datetime(
        metrics["timestamp"], errors="coerce"
    )
    metrics = (
        metrics.dropna(subset=["parsed_timestamp"])
        .sort_values("parsed_timestamp")
        .copy()
    )
    if metrics.empty:
        raise ValueError("Monitoring data has no valid timestamps.")

    latest = metrics.iloc[-1]
    source_timestamp = str(latest["timestamp"])


    def metric_value(column):
        value = pd.to_numeric(latest[column], errors="coerce")
        return None if pd.isna(value) else float(value)


    ai_status = "Unavailable"
    if not anomalies.empty:
        if not {"timestamp", "status"}.issubset(anomalies.columns):
            raise ValueError(
                "Anomaly results must contain timestamp and status columns."
            )
        matching_ai = anomalies[
            anomalies["timestamp"].astype(str).eq(source_timestamp)
        ]
        if not matching_ai.empty:
            ai_status = str(matching_ai.iloc[-1]["status"])

    active_workloads = active_test_workloads()
    live_process_snapshot = top_memory_processes()
    process_snapshot_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # --------------------------------------------------
    # 4. AVOID DUPLICATE REPORTS
    # --------------------------------------------------

    if INCIDENT_FILE.exists():
        existing = pd.read_csv(INCIDENT_FILE)

        if not existing.empty and "source_timestamp" in existing.columns:
            same_source = existing["source_timestamp"].astype(str).eq(source_timestamp)
            already_reported_workloads = (
                not active_workloads
                or (
                    "root_cause" in existing.columns
                    and any(
                        all(
                            f"PID {workload['pid']}" in str(root_cause)
                            for workload in active_workloads
                        )
                        for root_cause in existing.loc[same_source, "root_cause"]
                    )
                )
            )
            if same_source.any() and already_reported_workloads:
                print("RCA already completed for this reading and active workload.")
                raise SystemExit(0)

    # --------------------------------------------------
    # 5. GET MATCHED METRICS AND AI RESULT
    # --------------------------------------------------

    cpu = float(latest["cpu_usage"])
    memory = float(latest["memory_usage"])
    app_status = str(latest["application_status"])
    disk = metric_value("disk_usage")
    network_sent = metric_value("network_sent_bytes_per_sec")
    network_received = metric_value("network_received_bytes_per_sec")
    response_time = metric_value("response_time_ms")
    api_error_rate = metric_value("api_error_rate")
    request_throughput = metric_value("request_throughput_rps")
    application_process_pid = metric_value("application_process_pid")
    application_process_memory = metric_value("application_process_memory_mb")
    application_process_memory_percent = metric_value(
        "application_process_memory_percent"
    )
    available_memory = metric_value("available_memory_mb")
    application_process_rank = next(
        (
            index
            for index, process in enumerate(live_process_snapshot, start=1)
            if application_process_pid is not None
            and process["pid"] == int(application_process_pid)
        ),
        None,
    )


    # --------------------------------------------------
    # 6. EVIDENCE AND TIMELINE ANALYSIS
    # --------------------------------------------------

    numeric_columns = [
        "cpu_usage",
        "memory_usage",
        "disk_usage",
        "response_time_ms",
        "api_error_rate",
        "application_process_memory_mb",
    ]
    for column in numeric_columns:
        metrics[column] = pd.to_numeric(metrics[column], errors="coerce")
    metrics["application_process_pid"] = pd.to_numeric(
        metrics["application_process_pid"], errors="coerce"
    )

    latest_time = metrics["parsed_timestamp"].max()
    window_start = latest_time - pd.Timedelta(minutes=10)
    window = (
        metrics.loc[metrics["parsed_timestamp"].ge(window_start)]
        .dropna(subset=["parsed_timestamp"])
        .sort_values("parsed_timestamp")
        .copy()
    )
    window_span_minutes = (
        (window["parsed_timestamp"].iloc[-1] - window["parsed_timestamp"].iloc[0])
        .total_seconds()
        / 60
        if len(window) > 1
        else 0.0
    )
    process_pid_values = window["application_process_pid"].dropna().unique()
    process_window = (
        window[
            window["application_process_pid"].eq(application_process_pid)
        ]
        if application_process_pid is not None
        else window.iloc[0:0]
    )
    process_window_span_minutes = (
        (
            process_window["parsed_timestamp"].iloc[-1]
            - process_window["parsed_timestamp"].iloc[0]
        ).total_seconds()
        / 60
        if len(process_window) > 1
        else 0.0
    )


    def series_change(column, frame=window):
        values = frame[["parsed_timestamp", column]].dropna()
        if len(values) < 2:
            return None

        start_value = float(values[column].iloc[0])
        end_value = float(values[column].iloc[-1])
        changes = values[column].diff().dropna()
        increasing_fraction = (
            float((changes > 0).mean()) if not changes.empty else 0.0
        )
        return {
            "start": start_value,
            "end": end_value,
            "delta": end_value - start_value,
            "increasing_fraction": increasing_fraction,
            "samples": len(values),
        }


    def correlation(left_column, right_column, frame=window):
        paired = frame[[left_column, right_column]].dropna()
        if len(paired) < 4:
            return None
        value = paired[left_column].corr(paired[right_column])
        return float(value) if pd.notna(value) else None


    def timeline_sort_key(event):
        timestamp = pd.to_datetime(event[:19], errors="coerce")
        return pd.Timestamp.max if pd.isna(timestamp) else timestamp


    process_memory_change = series_change(
        "application_process_memory_mb", process_window
    )
    system_memory_change = series_change("memory_usage")
    response_time_change = series_change("response_time_ms")
    process_memory_system_correlation = correlation(
        "application_process_memory_mb", "memory_usage", process_window
    )
    process_memory_latency_correlation = correlation(
        "application_process_memory_mb", "response_time_ms", process_window
    )
    system_memory_latency_correlation = correlation(
        "memory_usage", "response_time_ms"
    )

    process_memory_growing = bool(
        process_memory_change
        and process_memory_change["samples"] >= 4
        and process_window_span_minutes >= 1
        and process_memory_change["delta"]
        >= max(20.0, process_memory_change["start"] * 0.1)
        and process_memory_change["increasing_fraction"] >= 0.7
    )
    system_memory_rising = bool(
        system_memory_change and system_memory_change["delta"] >= 3
    )
    latency_degraded = bool(
        (response_time is not None and response_time >= 1000)
        or (
            response_time_change
            and response_time_change["delta"] >= 250
        )
    )
    errors_elevated = api_error_rate is not None and api_error_rate > 5

    detected_symptoms = []
    supporting_evidence = []
    incident_timeline = []

    if cpu > RESOURCE_NORMAL_MAX:
        detected_symptoms.append(f"CPU utilization is {cpu:.1f}%.")
    if memory > RESOURCE_NORMAL_MAX:
        detected_symptoms.append(f"System memory utilization is {memory:.1f}%.")
    if response_time is not None and response_time >= 1000:
        detected_symptoms.append(f"API response time is {response_time:.0f} ms.")
    if errors_elevated:
        detected_symptoms.append(f"API error rate is {api_error_rate:.1f}%.")
    if app_status.lower() == "unreachable":
        detected_symptoms.append("The application health endpoint is unreachable.")
    if disk is not None and disk > RESOURCE_NORMAL_MAX:
        detected_symptoms.append(f"Disk utilization is {disk:.1f}%.")

    window_start_label = (
        window["parsed_timestamp"].iloc[0].strftime("%Y-%m-%d %H:%M:%S")
        if not window.empty
        else source_timestamp
    )
    response_display = (
        f"{response_time:.0f} ms"
        if response_time is not None
        else "unavailable"
    )
    error_rate_display = (
        f"{api_error_rate:.1f}%"
        if api_error_rate is not None
        else "unavailable"
    )
    incident_timeline.append(
        f"{window_start_label}: beginning of available "
        f"{window_span_minutes:.1f}-minute analysis window "
        f"({len(window)} readings)."
    )
    incident_timeline.append(
        f"{source_timestamp}: latest CPU {cpu:.1f}%, memory {memory:.1f}%, "
        f"response {response_display}, API errors {error_rate_display}."
    )
    supporting_evidence.append(
        f"Analysis used {len(window)} timestamped readings spanning "
        f"{window_span_minutes:.1f} minutes; the requested look-back is 10 minutes."
    )

    if process_memory_change:
        supporting_evidence.append(
            f"Flask process RSS changed from "
            f"{process_memory_change['start']:.1f} MB to "
            f"{process_memory_change['end']:.1f} MB "
            f"({process_memory_change['delta']:+.1f} MB) over "
            f"{process_window_span_minutes:.1f} minutes and "
            f"{process_memory_change['samples']} readings; "
            f"{process_memory_change['increasing_fraction']:.0%} of sampled intervals increased."
        )
        if application_process_pid is not None and application_process_memory is not None:
            application_process_evidence = (
                f"Latest application process PID {int(application_process_pid)} "
                f"uses {application_process_memory:.1f} MB"
            )
            if application_process_memory_percent is not None:
                application_process_evidence += (
                    f" ({application_process_memory_percent:.2f}% of total system RAM)"
                )
            supporting_evidence.append(application_process_evidence + ".")
            if available_memory is not None:
                supporting_evidence.append(
                    f"Available system memory at the latest sample was "
                    f"{available_memory:.1f} MB."
                )
        if process_memory_growing:
            incident_timeline.append(
                f"{source_timestamp}: sustained Flask process RSS growth observed "
                f"({process_memory_change['delta']:+.1f} MB)."
            )
    else:
        supporting_evidence.append(
            "No usable Flask process-memory trend is available for this window."
        )

    if len(process_pid_values) > 1:
        supporting_evidence.append(
            "The application PID changed during the window; RSS trend and "
            "correlations use only readings from the latest PID."
        )
        incident_timeline.append(
            f"{source_timestamp}: application PID changed within the analysis window."
        )

    if system_memory_change:
        supporting_evidence.append(
            f"System memory changed from {system_memory_change['start']:.1f}% "
            f"to {system_memory_change['end']:.1f}% "
            f"({system_memory_change['delta']:+.1f} percentage points)."
        )
        if system_memory_rising:
            incident_timeline.append(
                f"{source_timestamp}: system memory rose "
                f"{system_memory_change['delta']:.1f} percentage points "
                "over the analysis window."
            )

    if response_time_change:
        supporting_evidence.append(
            f"API response time changed from {response_time_change['start']:.0f} ms "
            f"to {response_time_change['end']:.0f} ms "
            f"({response_time_change['delta']:+.0f} ms)."
        )
        if response_time_change["delta"] >= 250:
            incident_timeline.append(
                f"{source_timestamp}: API response time increased "
                f"{response_time_change['delta']:.0f} ms over the analysis window."
            )

    for label, value in (
        ("Flask RSS/system-memory", process_memory_system_correlation),
        ("Flask RSS/API-latency", process_memory_latency_correlation),
        ("System-memory/API-latency", system_memory_latency_correlation),
    ):
        if value is not None:
            supporting_evidence.append(
                f"{label} Pearson correlation over the window: {value:.2f}."
            )

    for workload in active_workloads:
        detected_symptoms.append(
            f"Active {workload['kind'].lower()} test process PID "
            f"{workload['pid']} uses {workload['memory_mib']:.1f} MiB RSS."
        )
        supporting_evidence.append(
            f"Live tagged test workload: {workload['kind']} PID {workload['pid']}, "
            f"{workload['cpu_percent']:.1f}% of one CPU core, "
            f"{workload['memory_mib']:.1f} MiB RSS."
        )

    if live_process_snapshot:
        top_process_summary = ", ".join(
            f"{process['name']} PID {process['pid']} "
            f"({process['memory_mib']:.1f} MiB)"
            for process in live_process_snapshot
        )
        supporting_evidence.append(
            f"Top current processes by RSS at {process_snapshot_timestamp}: "
            f"{top_process_summary}."
        )
        if application_process_rank is not None:
            supporting_evidence.append(
                f"The Flask process ranks #{application_process_rank} by current "
                "RSS among the top five visible processes."
            )

    if ai_status == "Anomaly":
        supporting_evidence.append(
            "Isolation Forest flagged the latest multivariate metric reading."
        )

    for column, threshold, label in (
        (
            "memory_usage",
            RESOURCE_WARNING_THRESHOLD,
            f"system memory entered warning band above {RESOURCE_NORMAL_MAX:.0f}%",
        ),
        (
            "cpu_usage",
            RESOURCE_WARNING_THRESHOLD,
            f"CPU entered warning band above {RESOURCE_NORMAL_MAX:.0f}%",
        ),
        ("response_time_ms", 1000, "API response time exceeded 1000 ms"),
        ("api_error_rate", 5, "API error rate exceeded 5%"),
    ):
        crossings = window.loc[window[column].ge(threshold)]
        if not crossings.empty:
            first_crossing = crossings.iloc[0]
            incident_timeline.append(
                f"{first_crossing['parsed_timestamp'].strftime('%Y-%m-%d %H:%M:%S')}: "
                f"{label} ({first_crossing[column]:.1f})."
            )

    probable_cause = None
    confidence = 0
    confidence_basis = []
    recommended_actions = []

    if process_memory_growing and (
        memory > RESOURCE_NORMAL_MAX or system_memory_rising
    ):
        probable_cause = (
            "Sustained Flask process memory growth is a probable contributor "
            "to system memory pressure."
        )
        confidence = 40
        confidence_basis.append("40: sustained application RSS growth")
        if memory > RESOURCE_NORMAL_MAX:
            confidence += 20
            confidence_basis.append(
                f"20: system memory is above {RESOURCE_NORMAL_MAX:.0f}%"
            )
        if latency_degraded or errors_elevated:
            confidence += 15
            confidence_basis.append("15: API latency or error rate is elevated")
        if system_memory_rising:
            confidence += 10
            confidence_basis.append("10: system memory increased across the window")
        if (
            process_memory_system_correlation is not None
            and process_memory_system_correlation >= 0.6
        ):
            confidence += 10
            confidence_basis.append("10: process RSS correlates with system memory")
        if (
            process_memory_latency_correlation is not None
            and process_memory_latency_correlation >= 0.6
        ):
            confidence += 10
            confidence_basis.append("10: process RSS correlates with API latency")
        if (
            system_memory_latency_correlation is not None
            and system_memory_latency_correlation >= 0.6
        ):
            confidence += 10
            confidence_basis.append("10: system memory correlates with API latency")
        if confidence > 95:
            confidence = 95
            confidence_basis.append("Score capped at 95")
        recommended_actions.append(
            f"Investigate allocations and retention in Flask PID "
            f"{int(application_process_pid) if application_process_pid is not None else 'unavailable'}, "
            "check active requests and the recovery policy before restarting."
        )
    elif app_status.lower() == "unreachable":
        probable_cause = "The Flask application is not responding to health checks."
        confidence = 80
        confidence_basis.append("80: the latest health probe failed")
        recommended_actions.append(
            "Inspect service logs and active requests, then follow the recovery policy."
        )
    elif active_workloads and any(
        workload["kind"] == "Memory" for workload in active_workloads
    ):
        probable_cause = "An active memory test workload is contributing to resource use."
        confidence = 75
        confidence_basis.append("75: a tagged memory-test process is currently active")
        recommended_actions.append(
            "Stop the test workload after the demonstration and confirm metrics recover."
        )
    elif memory > RESOURCE_NORMAL_MAX and application_process_rank == 1:
        probable_cause = (
            "System memory pressure is present and the Flask process is the "
            "largest visible process by RSS; a leak is not confirmed."
        )
        confidence = 70
        confidence_basis.append(
            f"70: system memory exceeds {RESOURCE_NORMAL_MAX:.0f}% "
            "and Flask ranks first by live RSS"
        )
        recommended_actions.append(
            "Inspect Flask allocations and active requests, then follow the recovery policy."
        )
    elif memory > RESOURCE_NORMAL_MAX:
        probable_cause = (
            "System memory pressure is confirmed, but the available evidence "
            "does not establish a specific process leak."
        )
        confidence = 60
        confidence_basis.append(
            f"60: system memory utilization exceeds {RESOURCE_NORMAL_MAX:.0f}%"
        )
        recommended_actions.append(
            "Inspect top memory-consuming processes and available RAM before recovery."
        )
    elif cpu > RESOURCE_NORMAL_MAX:
        probable_cause = (
            "High CPU utilization is confirmed; process-level evidence is "
            "listed below, but no specific CPU bottleneck is established."
        )
        confidence = 55
        confidence_basis.append(
            f"55: system CPU utilization exceeds {RESOURCE_NORMAL_MAX:.0f}%"
        )
        recommended_actions.append(
            "Review the top processes and active workloads for CPU consumption."
        )
    elif latency_degraded or errors_elevated:
        probable_cause = (
            "The API is degraded, but the available evidence does not establish "
            "a specific underlying dependency or code path."
        )
        confidence = 55
        confidence_basis.append("55: API latency or error threshold is elevated")
        recommended_actions.append(
            "Correlate affected requests with application logs and downstream dependencies."
        )
    elif disk is not None and disk > RESOURCE_NORMAL_MAX:
        probable_cause = "High disk utilization is limiting available storage capacity."
        confidence = 60
        confidence_basis.append(
            f"60: disk utilization exceeds {RESOURCE_NORMAL_MAX:.0f}%"
        )
        recommended_actions.append(
            "Identify large files and review retention or archival policies."
        )
    elif ai_status == "Anomaly":
        probable_cause = (
            "The combined metrics are anomalous, but current evidence does not "
            "isolate one cause."
        )
        confidence = 45
        confidence_basis.append("45: multivariate anomaly without a confirmed cause")

    if disk is not None and disk > RESOURCE_NORMAL_MAX:
        recommended_actions.append(
            "Check disk capacity and remove or archive unneeded data."
        )
    if latency_degraded or errors_elevated:
        recommended_actions.append(
            "Inspect slow endpoints, application errors, and downstream dependencies."
        )
    if not recommended_actions:
        recommended_actions.append(
            "Continue monitoring and investigate if symptoms persist or worsen."
        )

    if probable_cause is None:
        probable_cause = "No specific root cause established from current evidence."
        if detected_symptoms:
            confidence = 35
            confidence_basis.append(
                "35: symptoms are present without enough evidence to attribute a cause"
            )

    possible_causes = [probable_cause]
    dependency_events = []
    host_resource_signals = []
    if cpu > RESOURCE_NORMAL_MAX:
        host_resource_signals.append(f"CPU {cpu:.1f}%")
    if memory > RESOURCE_NORMAL_MAX:
        host_resource_signals.append(f"memory {memory:.1f}%")
    if disk is not None and disk > RESOURCE_NORMAL_MAX:
        host_resource_signals.append(f"disk {disk:.1f}%")
    if host_resource_signals:
        host_is_critical = (
            cpu >= RESOURCE_CRITICAL_THRESHOLD
            or memory >= RESOURCE_CRITICAL_THRESHOLD
            or (
                disk is not None
                and disk >= RESOURCE_CRITICAL_THRESHOLD
            )
        )
        dependency_events.append(
            {
                "component": "host_resources",
                "status": "critical" if host_is_critical else "degraded",
                "summary": "Host resource pressure: "
                + ", ".join(host_resource_signals),
            }
        )

    if app_status.lower() == "unreachable":
        dependency_events.append(
            {
                "component": "flask_api",
                "status": "unavailable",
                "summary": "Flask API health endpoint is unreachable.",
            }
        )
    elif latency_degraded or errors_elevated:
        dependency_events.append(
            {
                "component": "flask_api",
                "status": "degraded",
                "summary": (
                    f"Flask API latency is {response_display}; "
                    f"API error rate is {error_rate_display}."
                ),
            }
        )

    dependency_correlations = dependency_mapping.correlate_component_events(
        dependency_events
    )
    dependency_correlation = ""
    for correlation in dependency_correlations:
        affected = ", ".join(correlation["affected_labels"])
        evidence = "; ".join(
            [correlation["root_evidence"], *correlation["affected_evidence"]]
        )
        correlation_summary = (
            f"Possible shared upstream cause: {correlation['root_label']} may "
            f"contribute to symptoms in {affected}. Evidence: {evidence}. "
            "This is event correlation, not proof of causation."
        )
        dependency_correlation = (
            f"{dependency_correlation}; {correlation_summary}"
            if dependency_correlation
            else correlation_summary
        )
        possible_causes.append(
            f"Possible shared upstream contributor: {correlation['root_label']}."
        )
        confidence_basis.append(
            "Dependency correlation is a hypothesis; co-occurrence does not prove causation."
        )
        supporting_evidence.append(correlation_summary)
        incident_timeline.append(
            f"{source_timestamp}: correlated {correlation['root_label']} "
            f"with affected components: {affected}."
        )

    incident_timeline.sort(
        key=timeline_sort_key
    )

    # --------------------------------------------------
    # 7. INCIDENT SEVERITY
    # --------------------------------------------------

    if (
        app_status.lower() == "unreachable"
        or cpu >= RESOURCE_CRITICAL_THRESHOLD
        or memory >= RESOURCE_CRITICAL_THRESHOLD
        or (
            disk is not None
            and disk >= RESOURCE_CRITICAL_THRESHOLD
        )
        or (response_time is not None and response_time > 2500)
        or (api_error_rate is not None and api_error_rate > 20)
    ):
        severity = "Critical"

    elif (
        cpu > RESOURCE_NORMAL_MAX
        or memory > RESOURCE_NORMAL_MAX
        or (disk is not None and disk > RESOURCE_NORMAL_MAX)
        or (response_time is not None and response_time > 1000)
        or (api_error_rate is not None and api_error_rate > 5)
        or ai_status == "Anomaly"
        or active_workloads
    ):
        severity = "Warning"

    else:
        severity = "Normal"

    # --------------------------------------------------
    # 8. CREATE INCIDENT REPORT
    # --------------------------------------------------

    report = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source_timestamp": source_timestamp,
        "cpu_usage": cpu,
        "memory_usage": memory,
        "disk_usage": disk,
        "network_sent_bytes_per_sec": network_sent,
        "network_received_bytes_per_sec": network_received,
        "response_time_ms": response_time,
        "api_error_rate": api_error_rate,
        "request_throughput_rps": request_throughput,
        "available_memory_mb": available_memory,
        "application_available": metric_value("application_available"),
        "application_process_pid": (
            int(application_process_pid)
            if application_process_pid is not None
            else None
        ),
        "application_process_memory_mb": application_process_memory,
        "application_process_memory_percent": application_process_memory_percent,
        "application_status": app_status,
        "ai_status": ai_status,
        "severity": severity,
        "detected_symptoms": "; ".join(detected_symptoms)
        if detected_symptoms
        else "No configured threshold symptoms observed",
        "supporting_evidence": "; ".join(supporting_evidence),
        "incident_timeline": "; ".join(incident_timeline),
        "root_cause": "; ".join(possible_causes),
        "dependency_correlation": dependency_correlation,
        "root_cause_confidence": confidence,
        "confidence_basis": "; ".join(confidence_basis)
        if confidence_basis
        else "No incident evidence",
        "recommended_action": "; ".join(recommended_actions),
    }

    report_df = pd.DataFrame([report])

    # --------------------------------------------------
    # 9. SAVE REPORT
    # --------------------------------------------------

    if INCIDENT_FILE.exists():
        existing_reports = pd.read_csv(INCIDENT_FILE)
        report_columns = list(existing_reports.columns) + [
            column for column in report if column not in existing_reports.columns
        ]
        if report_columns != list(existing_reports.columns):
            existing_reports = existing_reports.reindex(columns=report_columns)
            with tempfile.NamedTemporaryFile(
                "w",
                newline="",
                encoding="utf-8",
                dir=INCIDENT_FILE.parent,
                delete=False,
            ) as file:
                existing_reports.to_csv(file, index=False)
                temporary_file = file.name
            os.replace(temporary_file, INCIDENT_FILE)
        report_df = report_df.reindex(columns=report_columns)
        report_df.to_csv(
            INCIDENT_FILE,
            mode="a",
            header=False,
            index=False
        )
    else:
        report_df.to_csv(INCIDENT_FILE, index=False)

    managed_incident_id = incident_management.create_incident_from_report(report)

    # --------------------------------------------------
    # 10. DISPLAY RESULTS
    # --------------------------------------------------

    print("\n========== SDP ROOT CAUSE ANALYSIS ==========")
    print("Source Timestamp:", source_timestamp)
    print("CPU Usage:", cpu, "%")
    print("Memory Usage:", memory, "%")
    print("Application Status:", app_status)
    print("Matched AI Detection:", ai_status)
    print("Incident Severity:", severity)

    print("\nIncident Timeline:")
    for event in incident_timeline:
        print("-", event)

    print("\nDetected Symptoms:")
    for symptom in detected_symptoms or ["No configured threshold symptoms observed"]:
        print("-", symptom)

    print("\nSupporting Evidence:")
    for evidence in supporting_evidence:
        print("-", evidence)

    print(
        "\nRoot Cause Confidence:",
        f"{confidence}% (heuristic evidence score, not a calibrated probability)",
    )
    print("Confidence Basis:")
    for item in confidence_basis or ["No incident evidence"]:
        print("-", item)

    print("\nPossible Root Cause:")
    for cause in possible_causes:
        print("-", cause)

    print("\nRecommended Actions:")
    for action in recommended_actions:
        print("-", action)

    print("\nIncident report saved to:")
    print(INCIDENT_FILE)
    if managed_incident_id:
        print("Managed incident ID:", managed_incident_id)


if __name__ == "__main__":
    run_legacy_root_cause()

import ml.application_root_cause as application_root_cause

generate_application_rca = application_root_cause.generate_application_rca
get_application_rca_history = application_root_cause.get_application_rca_history
get_application_rca_report = application_root_cause.get_application_rca_report
get_latest_application_rca = application_root_cause.get_latest_application_rca
