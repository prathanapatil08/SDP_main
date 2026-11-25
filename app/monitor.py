
import csv
import json
import os
import sys
import tempfile
import time
from datetime import datetime
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

import psutil

# Find the main SDP project folder
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import self_healing


# CSV file location
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

CSV_FILE = DATA_DIR / "metrics.csv"
METRIC_COLUMNS = [
    "timestamp",
    "cpu_usage",
    "memory_usage",
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
    "application_status",
]


def ensure_metrics_schema():
    if not CSV_FILE.exists():
        with CSV_FILE.open("w", newline="", encoding="utf-8") as file:
            csv.writer(file).writerow(METRIC_COLUMNS)
        return

    with CSV_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        existing_columns = reader.fieldnames or []
        columns = METRIC_COLUMNS + [
            column for column in existing_columns if column not in METRIC_COLUMNS
        ]
        if columns == existing_columns:
            return
        rows = list(reader)

    with tempfile.NamedTemporaryFile(
        "w",
        newline="",
        encoding="utf-8",
        dir=DATA_DIR,
        delete=False,
    ) as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
        temporary_file = file.name
    os.replace(temporary_file, CSV_FILE)

def check_application():
    started_at = time.perf_counter()

    try:
        with urlopen("http://127.0.0.1:5000/health", timeout=2) as response:
            if response.status == 200:
                return "Healthy", (time.perf_counter() - started_at) * 1000

    except (URLError, TimeoutError, OSError):
        return "Unreachable", (time.perf_counter() - started_at) * 1000

    return "Unreachable", (time.perf_counter() - started_at) * 1000


def read_application_metrics():
    try:
        with urlopen("http://127.0.0.1:5000/metrics", timeout=2) as response:
            metrics = json.loads(response.read().decode("utf-8"))
        required = {
            "request_count",
            "error_count",
            "total_response_time_ms",
            "last_response_time_ms",
            "application_process_pid",
            "application_process_memory_mb",
            "application_process_memory_percent",
        }
        if not required.issubset(metrics):
            missing = sorted(required.difference(metrics))
            print(
                "Application metrics response is missing fields: "
                + ", ".join(missing)
            )
            return None
        return metrics
    except (URLError, TimeoutError, OSError, json.JSONDecodeError):
        return None


ensure_metrics_schema()


print("SDP System Monitoring Started")
print("Collecting metrics every 5 seconds...")
print("Press CTRL + C to stop monitoring.\n")

previous_network = psutil.net_io_counters()
previous_sample_time = time.monotonic()
previous_api_metrics = None
psutil.cpu_percent(interval=None)

try:

    while True:
        cycle_started = time.monotonic()

        # Collect CPU usage
        cpu = psutil.cpu_percent(interval=None)

        # Collect memory information
        memory = psutil.virtual_memory()

        memory_usage = memory.percent
        available_memory = round(memory.available / (1024 * 1024), 2)

        disk_usage = psutil.disk_usage(str(BASE_DIR.anchor)).percent
        network = psutil.net_io_counters()
        sample_time = time.monotonic()
        elapsed = max(sample_time - previous_sample_time, 0.001)
        network_sent_rate = max(
            0, network.bytes_sent - previous_network.bytes_sent
        ) / elapsed
        network_received_rate = max(
            0, network.bytes_recv - previous_network.bytes_recv
        ) / elapsed
        previous_network = network
        previous_sample_time = sample_time

        # Check application health
        app_status, health_response_time = check_application()
        application_metrics = (
            read_application_metrics()
            if app_status == "Healthy"
            else None
        )
        response_time = (
            health_response_time
            if app_status == "Unreachable"
            else 0.0
        )
        api_error_rate = 100.0 if app_status == "Unreachable" else ""
        request_throughput = 0.0 if app_status == "Unreachable" else ""
        process_pid = ""
        process_memory_mb = 0.0 if app_status == "Unreachable" else ""
        process_memory_percent = 0.0 if app_status == "Unreachable" else ""
        if application_metrics is not None:
            first_api_sample = previous_api_metrics is None
            if first_api_sample:
                request_count = 0
                error_count = 0
                response_time_total = 0.0
            else:
                request_count = max(
                    0,
                    application_metrics["request_count"]
                    - previous_api_metrics["request_count"],
                )
                error_count = max(
                    0,
                    application_metrics["error_count"]
                    - previous_api_metrics["error_count"],
                )
                response_time_total = max(
                    0.0,
                    application_metrics["total_response_time_ms"]
                    - previous_api_metrics["total_response_time_ms"],
                )

            if request_count:
                response_time = response_time_total / request_count
            elif first_api_sample:
                response_time = application_metrics["last_response_time_ms"]
            else:
                response_time = 0.0
            api_error_rate = (
                error_count / request_count * 100
                if request_count
                else 0.0
            )
            request_throughput = request_count / elapsed
            previous_api_metrics = application_metrics
            process_pid = application_metrics["application_process_pid"]
            process_memory_mb = application_metrics["application_process_memory_mb"]
            process_memory_percent = application_metrics[
                "application_process_memory_percent"
            ]
        else:
            previous_api_metrics = None
            print("Application API metrics unavailable; recording blank API metrics.")

        # Current timestamp
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Save metrics in CSV
        with CSV_FILE.open("a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)

            writer.writerow([
                timestamp,
                cpu,
                memory_usage,
                available_memory,
                disk_usage,
                round(network_sent_rate, 2),
                round(network_received_rate, 2),
                round(response_time, 2) if response_time != "" else "",
                round(api_error_rate, 2) if api_error_rate != "" else "",
                round(request_throughput, 4)
                if request_throughput != ""
                else "",
                1 if app_status == "Healthy" else 0,
                process_pid,
                round(process_memory_mb, 2)
                if process_memory_mb != ""
                else "",
                round(process_memory_percent, 2)
                if process_memory_percent != ""
                else "",
                app_status,
            ])

        try:
            automatic_recovery_result = self_healing.run_automatic_policy_if_needed(
                app_status,
                {
                    "cpu_usage": cpu,
                    "memory_usage": memory_usage,
                    "disk_usage": disk_usage,
                    "response_time_ms": response_time,
                    "api_error_rate": api_error_rate,
                },
            )
        except (OSError, RuntimeError, csv.Error, psutil.Error, ValueError) as error:
            print(f"Automatic recovery coordinator failed: {error}")
        else:
            if automatic_recovery_result is False:
                print("Automatic recovery failed; check the self-healing log.")
            elif automatic_recovery_result is True:
                print("Automatic recovery policy evaluated; check the self-healing log.")

        # Display collected information
        print("--------------------------------")
        print("Time:", timestamp)
        print("CPU Usage:", cpu, "%")
        print("Memory Usage:", memory_usage, "%")
        print("Available Memory:", available_memory, "MB")
        print("Disk Usage:", disk_usage, "%")
        print("Network Sent:", round(network_sent_rate, 2), "bytes/s")
        print("Network Received:", round(network_received_rate, 2), "bytes/s")
        print("Response Time:", response_time, "ms")
        print("API Error Rate:", api_error_rate, "%")
        print("Request Throughput:", request_throughput, "requests/s")
        print("Flask PID:", process_pid)
        print("Flask Memory:", process_memory_mb, "MB")
        print("Application:", app_status)

        time.sleep(max(0, 5 - (time.monotonic() - cycle_started)))


except KeyboardInterrupt:

    print("\nMonitoring stopped.")
    print("Metrics saved at:", CSV_FILE)
