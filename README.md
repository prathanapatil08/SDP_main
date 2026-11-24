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

## Deploy the dashboard on Streamlit Community Cloud

1. Open the repository in Streamlit Community Cloud.
2. Select `shreya-lang/seniorDesignProject`.
3. Set the main file to `dashboard/app.py`.
4. Use `main` as the deployment branch.
5. Deploy.

The dashboard is a read-only operations view in the cloud. Local Flask metrics,
system monitoring, workload tests, and service restarts require the application
to run on a local host or server where the Python processes are available.
