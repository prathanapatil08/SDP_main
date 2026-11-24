
import os
import sys
import tempfile
from pathlib import Path

import pandas as pd
from sklearn.ensemble import IsolationForest

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from app import incident_management

DATA_FILE = BASE_DIR / "data" / "metrics.csv"
OUTPUT_FILE = BASE_DIR / "data" / "anomaly_results.csv"

# Load monitoring data
data = pd.read_csv(DATA_FILE)
if "timestamp" not in data.columns:
    raise ValueError("Metrics file must contain a timestamp column.")

# Features used by the AI model
features = [
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
    "application_process_memory_percent",
]

# Check available data
if len(data) < 100:
    raise ValueError(
        "Collect at least 100 readings before training the model."
    )

missing_features = [feature for feature in features if feature not in data.columns]
if missing_features:
    raise ValueError(
        "Metrics are missing multivariate features: "
        + ", ".join(missing_features)
        + ". Start the updated monitor and collect new readings."
    )

# Convert features into numeric values
data[features] = data[features].apply(
    pd.to_numeric, errors="coerce"
)

# Remove incomplete records
data = data.dropna(subset=features).copy()

if len(data) < 100:
    raise ValueError(
        "Not enough complete multivariate readings. Collect at least 100 "
        "readings with all advanced monitoring metrics available."
    )

existing_results = None
if OUTPUT_FILE.exists():
    existing_results = pd.read_csv(OUTPUT_FILE)
    if not existing_results.empty and "timestamp" not in existing_results.columns:
        raise ValueError(
            "Existing anomaly results have no timestamp column; refusing to overwrite them."
        )

if existing_results is None or existing_results.empty:
    new_data = data.copy()
else:
    processed_timestamps = set(existing_results["timestamp"].astype(str))
    new_data = data[
        ~data["timestamp"].astype(str).isin(processed_timestamps)
    ].copy()

if new_data.empty:
    print("No newly collected metric timestamps to analyze.")
    print("Existing anomaly results were preserved.")
    raise SystemExit(0)

# Train across the complete feature vector so correlated resource and
# application signals contribute to each prediction.
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,
    random_state=42
)

model.fit(data[features])

# Predict newly collected readings. Isolation Forest is an outlier detector,
# so a higher resource reading is not automatically an anomaly.
# 1 = Normal
# -1 = Anomaly
new_data["prediction"] = model.predict(new_data[features])

# Calculate anomaly score
new_data["anomaly_score"] = model.decision_function(
    new_data[features]
)

# Convert prediction into readable labels
new_data["status"] = new_data["prediction"].map({
    1: "Normal",
    -1: "Anomaly"
})

for _, anomaly in new_data[new_data["status"] == "Anomaly"].iterrows():
    incident_management.record_anomaly_detection(anomaly.to_dict())

# Append only new timestamps so historical results remain intact.
if OUTPUT_FILE.exists():
    existing_columns = list(pd.read_csv(OUTPUT_FILE, nrows=0).columns)
    output_columns = existing_columns + [
        column for column in new_data.columns if column not in existing_columns
    ]
    if output_columns != existing_columns:
        history = existing_results.reindex(columns=output_columns)
        with tempfile.NamedTemporaryFile(
            "w",
            newline="",
            encoding="utf-8",
            dir=OUTPUT_FILE.parent,
            delete=False,
        ) as file:
            history.to_csv(file, index=False)
            temporary_file = file.name
        os.replace(temporary_file, OUTPUT_FILE)
    new_data = new_data.reindex(columns=output_columns)
    new_data.to_csv(OUTPUT_FILE, mode="a", header=False, index=False)
else:
    new_data.to_csv(OUTPUT_FILE, index=False)

# Display summary
normal_count = (new_data["status"] == "Normal").sum()
anomaly_count = (new_data["status"] == "Anomaly").sum()

print("\n========== SDP AI ANOMALY DETECTION ==========")

print("New readings analyzed:", len(new_data))
print("New readings classified normal:", normal_count)
print("New anomalies detected:", anomaly_count)

print("\nLatest readings:")

print(
    new_data[
        ["cpu_usage", "memory_usage", "status"]
    ].tail(10).to_string(index=False)
)

print("\nResults saved to:", OUTPUT_FILE)
