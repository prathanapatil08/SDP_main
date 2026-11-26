# SDP Intelligent AIOps Platform

An AI operations platform for system monitoring, multivariate anomaly detection,
root-cause analysis, incident management, predictive health trends, dependency
mapping, and safe recovery.

## Run locally

```powershell
python -m pip install -r requirements.txt
python app/main.py
python app/monitor.py
python -m streamlit run dashboard/app.py --server.address 127.0.0.1 --server.port 8501
python -m streamlit run testing_website/test_app.py --server.address 127.0.0.1 --server.port 8502
```

Run each long-lived command in its own terminal. `app/monitor.py` is required
for live dashboard telemetry; without it, the dashboard shows the latest saved
reading as stale and pauses live alerts. CPU, memory, and disk readings are
normal through 91%, warning above 91% through 94.9%, and critical at 95% or
higher.
The monitor also collects HTTP/HTTPS telemetry for registered, enabled
applications into the shared SQLite database. The legacy Flask monitor remains
the sole monitor for the built-in Flask application; other registered
applications use independent workers and their configured intervals. Process
metrics are collected only for platform-owned applications with process
monitoring explicitly permitted and a verifiable process identity.
After 100 usable readings are available, anomaly detection trains and stores a
separate Isolation Forest model per application in SQLite. Models are reused
and retrained after the configured number of additional samples; per-reading
results and explanations are stored in `anomaly_results`. The legacy
`metrics.csv` detector remains available when running `ml/detect_anomalies.py`.
The anomaly timeline shows predictions from the latest 60 telemetry readings;
older predictions and incidents remain available in their history views. Run
anomaly detection or root-cause analysis from the Testing Control Panel to
refresh saved model output. Incident Management defaults to the last 24 hours.
Each newly detected application anomaly also triggers application-scoped RCA.
Reports use up to 30 minutes of that application's real telemetry, matching
anomaly results, and explicitly registered dependencies; reports are persisted
in the shared SQLite `root_cause_reports` table and deduplicated by application
and source timestamp. Process resource causes are considered only for platform-
owned applications with process monitoring permitted. Database causes are
reported only when database telemetry is present, and application error details
come from collected telemetry (the platform does not search arbitrary log
files). RCA confidence is an evidence score, not a probability, and its
recommendations do not execute recovery actions.
Significant anomalies at Medium severity or higher create application-scoped
incidents by default; callers can change the threshold through
`process_application_anomaly`. Repeated anomalies with the same application
and problem category update the ongoing incident, while resolved or closed
incidents do not absorb later occurrences. Incident severity changes and
lifecycle transitions are retained in the SQLite event timeline.

Keep `app/monitor.py` running for legacy Flask monitoring and recovery. When no
per-application recovery policy is configured, its existing guarded recovery
continues to restart Flask after failed health checks and after memory stays at
or above the configured threshold for 60 seconds. A configured application
policy takes precedence over that legacy automatic coordinator.
Verified successful recovery automatically resolves its matching incident;
failed or unverified recovery leaves the incident open. Memory workload test
start/stop outcomes also appear there as diagnostic activities, not recoveries.
Flask stop/restart verifies the service PID from its local metrics endpoint, with
a project-script and port check fallback when the endpoint is unavailable.
The Testing Control Panel's Flask stop button is also a recovery test: it records
the verified stop, then launches recovery, so Flask may come back immediately.

## Controlled local simulations

The project includes isolated e-commerce and video-streaming demo services. They
bind only to `127.0.0.1` (ports 5101 and 5102) and are registered as platform
owned only after their managed process and health endpoint have been verified.
They provide product/video listing and detail routes, search/cart or streaming
routes, and `/health`. External applications cannot be used as simulation
targets.

Run a confirmed scenario from the repository root:

```powershell
python -m testing_website.test_scenarios `
  --scenario high_api_latency `
  --application-id APP-SDP-DEMO-ECOMMERCE `
  --confirm
```

Available scenarios include normal operation, API latency, HTTP 500 errors,
bounded CPU and memory pressure, application downtime, database delay, worker
failure, and recovery verification after fault removal. The scenario report
records which telemetry, anomaly, RCA, incident, recovery, and final-health
stages actually completed. Anomaly detection uses real telemetry for model
training and explicitly opted-in simulation telemetry only for scoring. If
there is not enough real history to train the model, the report marks ML and
downstream stages incomplete rather than claiming success.

Workloads and faults are available through `testing_website.workload_generator`
and `testing_website.failure_simulator`. Starting either requires explicit
confirmation. Workloads are capped at 60 seconds, 20 requests per second, and
8 concurrent requests (high-volume workloads at 30 seconds). Faults are capped
at 30 seconds, CPU load at 50% of one core, memory at 64 MB, and endpoint delay
at 5 seconds. Fault resources are stopped and released on cleanup; the
`FailureSimulator.emergency_stop()` method stops all active faults managed by
that simulator instance. Simulation records and tagged telemetry are stored in
the shared SQLite database and remain distinguishable from normal monitoring
history.

## Application recovery policies

Application-specific recovery is disabled until a policy is explicitly
configured. External websites and APIs cannot receive recovery policies.
Automatic policies require a platform-owned application with the registry's
automatic-recovery permission. Process restarts additionally require a
controlled local application, process-monitoring permission, and a uniquely
verified process identity. Restart starts only the registered executable
directly (no shell and no caller-supplied command arguments); applications that
need custom launch arguments must be started by an administrator.

For example, after registering an owned controlled local application with
verified process identity and recovery permissions:

```python
from app.recovery_policy import configure_recovery_policy

configure_recovery_policy(
    application_id="APP-ID",
    automatic_recovery_enabled=True,
    permitted_actions=("retry_request", "restart_local_application"),
    required_approval_level="high_risk",
    max_retry_attempts=3,
    cooldown_seconds=60,
    verification_timeout_seconds=10,
)
```

By default, health-check retries may run automatically, while local restarts
require an approval recorded in SQLite. An operator can approve or reject a
request with `approve_recovery_request` or `reject_recovery_request`; execution
then requires `execute_approved_recovery`, which rechecks policy, incident
state, application health, and process ownership. Recovery attempts, approval
decisions, verification results, and escalations are retained in the central
database and incident timeline.

## Deploy the dashboard on Streamlit Community Cloud

1. Open the repository in Streamlit Community Cloud.
2. Select `shreya-lang/seniorDesignProject`.
3. Set the main file to `dashboard/app.py`.
4. Use `main` as the deployment branch.
5. Deploy.

The dashboard is a read-only operations view in the cloud. Local Flask metrics,
system monitoring, workload tests, and service restarts require the application
to run on a local host or server where the Python processes are available.
