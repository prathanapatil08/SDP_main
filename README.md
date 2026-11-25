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

Keep `app/monitor.py` running for automatic recovery. It restarts Flask after
failed health checks and after memory stays at or above the configured threshold
for 60 seconds. Recovery outcomes, including failures and approval-required
actions, appear in the dashboard's Self-Healing Activity History.
Verified successful recovery automatically resolves its matching incident;
failed or unverified recovery leaves the incident open. Memory workload test
start/stop outcomes also appear there as diagnostic activities, not recoveries.
Flask stop/restart verifies the service PID from its local metrics endpoint, with
a project-script and port check fallback when the endpoint is unavailable.
The Testing Control Panel's Flask stop button is also a recovery test: it records
the verified stop, then launches recovery, so Flask may come back immediately.

## Deploy the dashboard on Streamlit Community Cloud

1. Open the repository in Streamlit Community Cloud.
2. Select `shreya-lang/seniorDesignProject`.
3. Set the main file to `dashboard/app.py`.
4. Use `main` as the deployment branch.
5. Deploy.

The dashboard is a read-only operations view in the cloud. Local Flask metrics,
system monitoring, workload tests, and service restarts require the application
to run on a local host or server where the Python processes are available.
