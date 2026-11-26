import json
import logging
from contextlib import closing
from datetime import datetime, timezone

from app.database import connect, initialize_database


LOGGER = logging.getLogger(__name__)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def start_simulation_event(application_id, simulation_type, data, db_path=None):
    if not application_id:
        raise ValueError("application_id is required.")
    if not simulation_type:
        raise ValueError("simulation_type is required.")
    initialize_database(db_path)
    started_at = _now()
    payload = {
        **data,
        "application_id": application_id,
        "simulation_type": simulation_type,
        "started_at": started_at,
    }
    with closing(connect(db_path)) as connection, connection:
        cursor = connection.execute(
            """
            INSERT INTO simulation_events (
                application_id, simulation_type, status, started_at,
                ended_at, data_json, is_simulated, created_at
            ) VALUES (?, ?, 'Running', ?, NULL, ?, 1, ?)
            """,
            (
                application_id,
                simulation_type,
                started_at,
                json.dumps(payload, separators=(",", ":"), allow_nan=False),
                started_at,
            ),
        )
        return int(cursor.lastrowid)


def finish_simulation_event(
    simulation_id,
    *,
    status,
    updates=None,
    db_path=None,
):
    if status not in {"Completed", "Failed", "Stopped"}:
        raise ValueError("Unsupported simulation completion status.")
    initialize_database(db_path)
    ended_at = _now()
    with closing(connect(db_path)) as connection, connection:
        row = connection.execute(
            "SELECT data_json FROM simulation_events WHERE simulation_id = ?",
            (simulation_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Simulation event not found: {simulation_id}")
        try:
            data = json.loads(row["data_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"Simulation event {simulation_id} contains invalid JSON."
            ) from error
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Simulation event {simulation_id} must contain a JSON object."
            )
        data.update(updates or {})
        data["ended_at"] = ended_at
        connection.execute(
            """
            UPDATE simulation_events
            SET status = ?, ended_at = ?, data_json = ?
            WHERE simulation_id = ?
            """,
            (
                status,
                ended_at,
                json.dumps(data, separators=(",", ":"), allow_nan=False),
                simulation_id,
            ),
        )
    return ended_at


def update_simulation_event(simulation_id, updates, db_path=None):
    if not isinstance(updates, dict):
        raise ValueError("updates must be a mapping.")
    initialize_database(db_path)
    with closing(connect(db_path)) as connection, connection:
        row = connection.execute(
            "SELECT data_json FROM simulation_events WHERE simulation_id = ?",
            (simulation_id,),
        ).fetchone()
        if row is None:
            raise KeyError(f"Simulation event not found: {simulation_id}")
        try:
            data = json.loads(row["data_json"])
        except (TypeError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"Simulation event {simulation_id} contains invalid JSON."
            ) from error
        if not isinstance(data, dict):
            raise RuntimeError(
                f"Simulation event {simulation_id} must contain a JSON object."
            )
        data.update(updates)
        connection.execute(
            "UPDATE simulation_events SET data_json = ? WHERE simulation_id = ?",
            (
                json.dumps(data, separators=(",", ":"), allow_nan=False),
                simulation_id,
            ),
        )
    return get_simulation_event(simulation_id, db_path=db_path)


def get_simulation_event(simulation_id, db_path=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM simulation_events WHERE simulation_id = ?",
            (simulation_id,),
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    try:
        result["details"] = json.loads(result.pop("data_json"))
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Simulation event {simulation_id} contains invalid JSON."
        ) from error
    return result


def list_simulation_events(application_id=None, limit=100, db_path=None):
    if isinstance(limit, bool):
        raise ValueError("limit must be a positive integer.")
    try:
        limit = int(limit)
    except (TypeError, ValueError) as error:
        raise ValueError("limit must be a positive integer.") from error
    if limit < 1:
        raise ValueError("limit must be a positive integer.")
    initialize_database(db_path)
    query = "SELECT * FROM simulation_events"
    parameters = []
    if application_id:
        query += " WHERE application_id = ?"
        parameters.append(application_id)
    query += " ORDER BY started_at DESC, simulation_id DESC LIMIT ?"
    parameters.append(limit)
    with closing(connect(db_path)) as connection:
        rows = connection.execute(query, parameters).fetchall()
    events = []
    for row in rows:
        result = dict(row)
        try:
            result["details"] = json.loads(result.pop("data_json"))
        except (TypeError, json.JSONDecodeError) as error:
            raise RuntimeError(
                f"Simulation event {result['simulation_id']} contains invalid JSON."
            ) from error
        events.append(result)
    return events
