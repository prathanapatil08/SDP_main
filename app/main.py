
import threading
import time
from datetime import datetime

import psutil
from flask import Flask, g, jsonify, request

# Create Flask application
app = Flask(__name__)

_request_metrics_lock = threading.Lock()
_request_metrics = {
    "request_count": 0,
    "error_count": 0,
    "total_response_time_ms": 0.0,
    "last_response_time_ms": 0.0,
}


@app.before_request
def start_request_timer():
    g.request_start_time = time.perf_counter()


@app.after_request
def record_request_metrics(response):
    if request.path not in ("/health", "/metrics"):
        response_time_ms = (
            time.perf_counter() - g.request_start_time
        ) * 1000
        with _request_metrics_lock:
            _request_metrics["request_count"] += 1
            _request_metrics["total_response_time_ms"] += response_time_ms
            _request_metrics["last_response_time_ms"] = response_time_ms
            if response.status_code >= 400:
                _request_metrics["error_count"] += 1
    return response


# Home route
@app.route("/")
def home():
    return jsonify({
        "project": "Intelligent AIOps Platform",
        "status": "Running",
        "message": "Welcome to SDP"
    })


@app.route("/metrics")
def metrics():
    process = psutil.Process()
    process_memory = process.memory_info().rss
    process_memory_mb = process_memory / (1024 * 1024)
    process_memory_percent = (
        process_memory / psutil.virtual_memory().total * 100
    )
    with _request_metrics_lock:
        snapshot = _request_metrics.copy()
    snapshot.update(
        application_process_pid=process.pid,
        application_process_memory_mb=process_memory_mb,
        application_process_memory_percent=process_memory_percent,
    )
    return jsonify(snapshot)


# Health monitoring route
@app.route("/health")
def health():

    cpu = psutil.cpu_percent(interval=0.1)

    memory = psutil.virtual_memory().percent

    return jsonify({
        "application_status": "Healthy",
        "cpu_usage": cpu,
        "memory_usage": memory,
        "timestamp": datetime.now().isoformat()
    })


# Start application
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
