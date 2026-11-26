import argparse
import json
import logging
import time
from contextlib import closing
from datetime import datetime, timezone

from app.database import connect, initialize_database
from app.incident_management import process_application_anomaly
from app.multi_app_monitor import monitor_application_once
from app.recovery_framework import process_incident
from ml.application_root_cause import generate_application_rca
from ml.detect_anomalies import analyze_application
from testing_website.demo_app import (
    DEMO_APPLICATIONS,
    get_demo_application_manager,
)
from testing_website.failure_simulator import FailureSimulator
from testing_website.simulation_store import (
    finish_simulation_event,
    start_simulation_event,
    update_simulation_event,
)


LOGGER = logging.getLogger(__name__)
SCENARIOS = {
    "normal_operation": {
        "fault": None,
        "configuration": {},
        "expected": "Health checks succeed without a fault injection.",
    },
    "high_api_latency": {
        "fault": "api_latency",
        "configuration": {
            "duration_seconds": 10,
            "delay_ms": 2500,
            "endpoint": "/health",
        },
        "expected": "The monitoring sample records delayed responses; health recovers after cleanup.",
    },
    "http_500_errors": {
        "fault": "http_errors",
        "configuration": {"duration_seconds": 10, "endpoint": "/health"},
        "expected": "The monitoring sample records controlled HTTP 500 responses.",
    },
    "cpu_overload": {
        "fault": "cpu_load",
        "configuration": {
            "duration_seconds": 10,
            "cpu_percent": 30,
        },
        "expected": "The controlled service reports bounded CPU load while active.",
    },
    "memory_pressure": {
        "fault": "memory_pressure",
        "configuration": {
            "duration_seconds": 10,
            "memory_mb": 16,
        },
        "expected": "The controlled service allocates bounded memory and releases it on cleanup.",
    },
    "application_downtime": {
        "fault": "application_downtime",
        "configuration": {"duration_seconds": 10},
        "expected": "The registered local process is unavailable during the fault and restarted during cleanup.",
    },
    "database_delay": {
        "fault": "database_delay",
        "configuration": {
            "duration_seconds": 10,
            "delay_ms": 1000,
            "endpoint": "/health",
        },
        "expected": "The controlled service reports an artificial database-operation delay.",
    },
    "worker_failure": {
        "fault": "worker_failure",
        "configuration": {
            "duration_seconds": 10,
            "endpoint": "/health",
        },
        "expected": "The selected controlled endpoint reports worker unavailability.",
    },
    "recovery_after_fault_removal": {
        "fault": "api_latency",
        "configuration": {
            "duration_seconds": 10,
            "delay_ms": 2500,
            "endpoint": "/health",
        },
        "expected": "The pipeline observes the injected fault, removes it, then verifies healthy service.",
    },
}


def _baseline_sample_count(application_id, db_path):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT COUNT(*) AS sample_count
            FROM application_telemetry
            WHERE application_id = ? AND is_simulated = 0
            """,
            (application_id,),
        ).fetchone()
    return int(row["sample_count"])


def _health_result(reading):
    if reading is None:
        return False
    status_code = reading.get("http_status_code")
    return bool(
        reading.get("request_success")
        and status_code is not None
        and 200 <= status_code < 400
    )


def run_scenario(
    scenario_name,
    application_id,
    *,
    db_path=None,
    confirm=False,
    recovery_processor=None,
):
    if scenario_name not in SCENARIOS:
        raise ValueError(f"Unknown scenario: {scenario_name}")
    if application_id not in DEMO_APPLICATIONS:
        raise ValueError("Scenarios are restricted to registered local demo applications.")
    if confirm is not True:
        raise ValueError("Explicit confirmation is required to run a scenario.")
    recovery_processor = recovery_processor or process_incident

    scenario = SCENARIOS[scenario_name]
    application = get_demo_application_manager(db_path).ensure_application(
        application_id
    )
    initial_health = monitor_application_once(
        application_id,
        db_path=db_path,
        request_timeout=3,
    )
    if not _health_result(initial_health):
        raise RuntimeError(
            "Scenario requires a healthy local demo application before it starts."
        )

    # The ML model is deliberately trained only from existing real telemetry.
    # A scenario reports incomplete ML stages when the real baseline is too small.
    real_baseline_count = _baseline_sample_count(application_id, db_path)
    simulation_id = None
    simulator = FailureSimulator(db_path=db_path)
    simulation_started_at = datetime.now(timezone.utc).isoformat()
    fault_error = None
    samples = []
    scored_results = []
    anomaly_results = []
    rca_reports = []
    incident_ids = []
    recovery_results = []
    final_reading = None
    fault_removed = scenario["fault"] is None
    event_owner = scenario["fault"] is None

    if event_owner:
        simulation_id = start_simulation_event(
            application_id,
            scenario_name,
            {
                "configuration": dict(scenario["configuration"]),
                "affected_endpoint": "/health",
                "expected_outcome": scenario["expected"],
                "scenario_name": scenario_name,
            },
            db_path=db_path,
        )

    try:
        if scenario["fault"]:
            simulation_id = simulator.start_simulation(
                application_id,
                scenario["fault"],
                scenario["configuration"],
                confirm=True,
            )
        sample_count = 2 if scenario["fault"] == "application_downtime" else 1
        for _ in range(sample_count):
            reading = monitor_application_once(
                application_id,
                db_path=db_path,
                request_timeout=3,
                is_simulated=True,
                simulation_id=simulation_id,
                telemetry_source="controlled_simulation",
            )
            samples.append(reading)
            if sample_count > 1:
                time.sleep(0.1)

        detection = analyze_application(
            application_id,
            db_path=db_path,
            include_simulated=True,
        )
        if detection.get("status") == "analyzed":
            scored_results = [
                result
                for result in detection.get("results", [])
                if result.get("is_simulated")
                and result.get("simulation_id") == simulation_id
            ]
            anomaly_results = [
                result
                for result in scored_results
                if result.get("prediction") == "Anomaly"
            ]

        for result in anomaly_results:
            report = generate_application_rca(
                application_id,
                source_timestamp=result["timestamp"],
                db_path=db_path,
                include_simulated=True,
            )
            rca_reports.append(report)
            if report.get("report_id") is None:
                continue
            incident_id = process_application_anomaly(
                application_id,
                result["timestamp"],
                db_path=db_path,
                minimum_severity="Medium",
                include_simulated=True,
            )
            if incident_id and incident_id not in incident_ids:
                incident_ids.append(incident_id)

        if (
            scenario_name == "recovery_after_fault_removal"
            and simulation_id is not None
        ):
            simulator.stop_simulation(
                simulation_id,
                "fault removed before recovery verification",
            )
            fault_removed = True

        for incident_id in incident_ids:
            recovery_results.append(
                recovery_processor(incident_id, db_path=db_path)
            )
    except Exception as error:
        fault_error = str(error)
        LOGGER.exception(
            "Simulation scenario %s failed for %s",
            scenario_name,
            application_id,
        )
    finally:
        if scenario["fault"] and simulation_id is not None and not fault_removed:
            try:
                simulator.stop_simulation(simulation_id, "scenario cleanup")
            except Exception as error:
                fault_error = fault_error or str(error)
                LOGGER.exception(
                    "Could not clean up scenario %s",
                    simulation_id,
                )
        elif event_owner and simulation_id is not None:
            finish_simulation_event(
                simulation_id,
                status="Failed" if fault_error else "Completed",
                updates={"cleanup_result": "No fault resources were allocated."},
                db_path=db_path,
            )
        try:
            final_reading = monitor_application_once(
                application_id,
                db_path=db_path,
                request_timeout=3,
                is_simulated=simulation_id is not None,
                simulation_id=simulation_id,
                telemetry_source="controlled_simulation",
            )
        except Exception as error:
            fault_error = fault_error or str(error)
            LOGGER.exception(
                "Final health verification failed for scenario %s",
                scenario_name,
            )

    stages = {
        "initial_health": _health_result(initial_health),
        "telemetry_collected": bool(samples),
        "real_training_baseline_samples": real_baseline_count,
        "anomaly_detection_status": detection.get("status")
        if "detection" in locals()
        else "not_run",
        "telemetry_scored": len(scored_results),
        "anomalies_detected": len(anomaly_results),
        "rca_reports": len(rca_reports),
        "incidents_created": list(incident_ids),
        "fault_removed_before_recovery": fault_removed,
        "recovery_decisions": recovery_results,
        "final_health": _health_result(final_reading),
    }
    summary = {
        "scenario_name": scenario_name,
        "application_id": application_id,
        "application_name": application["name"],
        "fault_configuration": {
            "fault": scenario["fault"],
            "configuration": dict(scenario["configuration"]),
        },
        "expected_outcome": scenario["expected"],
        "started_at": simulation_started_at,
        "ended_at": datetime.now(timezone.utc).isoformat(),
        "simulation_id": simulation_id,
        "anomalies_detected": anomaly_results,
        "rca_results": rca_reports,
        "incidents_created": incident_ids,
        "recovery_attempted": any(
            result.get("action") is not None
            and result.get("decision") not in {"REQUIRES_APPROVAL"}
            for result in recovery_results
        ),
        "recovery_results": recovery_results,
        "final_application_health": _health_result(final_reading),
        "stage_results": stages,
        "error_details": fault_error,
    }
    if simulation_id is not None:
        update_simulation_event(
            simulation_id,
            {"scenario_summary": summary, "stage_results": stages},
            db_path=db_path,
        )
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Run a confirmed AIOps scenario against a local SDP demo app."
    )
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), required=True)
    parser.add_argument(
        "--application-id",
        choices=sorted(DEMO_APPLICATIONS),
        required=True,
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirm that this controlled scenario may affect the selected demo app.",
    )
    arguments = parser.parse_args()
    summary = run_scenario(
        arguments.scenario,
        arguments.application_id,
        confirm=arguments.confirm,
    )
    print(json.dumps(summary, indent=2, allow_nan=False))
    return 0 if summary["error_details"] is None else 1


if __name__ == "__main__":
    raise SystemExit(main())
