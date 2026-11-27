import sqlite3
from contextlib import closing
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_FILE = BASE_DIR / "data" / "incidents.sqlite3"
LEGACY_FLASK_APPLICATION_ID = "APP-SDP-FLASK-5000"


def get_database_path(db_path=None):
    return Path(db_path) if db_path is not None else DATABASE_FILE


def connect(db_path=None):
    database_path = get_database_path(db_path)
    database_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _ensure_incident_application_columns(connection):
    for table in ("incidents", "incident_events"):
        table_exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table,),
        ).fetchone()
        if table_exists is None:
            continue
        columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        if "application_id" not in columns:
            connection.execute(
                f"ALTER TABLE {table} ADD COLUMN application_id TEXT"
            )


def _migrate_legacy_incident_schema(connection):
    incidents_exists = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'incidents'"
    ).fetchone()
    if incidents_exists is None:
        return
    _ensure_incident_application_columns(connection)
    event_columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(incident_events)"
        ).fetchall()
    }
    if "anomaly_id" not in event_columns:
        connection.execute(
            "ALTER TABLE incident_events ADD COLUMN anomaly_id INTEGER"
        )
    if "rca_report_id" not in event_columns:
        connection.execute(
            "ALTER TABLE incident_events ADD COLUMN rca_report_id INTEGER"
        )

    incident_columns = {
        row["name"]
        for row in connection.execute("PRAGMA table_info(incidents)").fetchall()
    }
    if "is_simulated" not in incident_columns:
        connection.execute(
            "ALTER TABLE incidents ADD COLUMN is_simulated INTEGER "
            "NOT NULL DEFAULT 0 CHECK (is_simulated IN (0, 1))"
        )
        incident_columns.add("is_simulated")
    if "simulation_id" not in incident_columns:
        connection.execute(
            "ALTER TABLE incidents ADD COLUMN simulation_id INTEGER"
        )
        incident_columns.add("simulation_id")
    table_sql_row = connection.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'incidents'"
    ).fetchone()
    table_sql = str(table_sql_row["sql"] or "").casefold()
    required_columns = {
        "anomaly_id",
        "rca_report_id",
        "problem_key",
        "last_seen_at",
        "occurrence_count",
        "closed_at",
    }

    unique_indexes = []
    for index in connection.execute("PRAGMA index_list('incidents')").fetchall():
        if not index["unique"]:
            continue
        escaped_name = index["name"].replace("'", "''")
        columns = [
            row["name"]
            for row in connection.execute(
                f"PRAGMA index_info('{escaped_name}')"
            ).fetchall()
        ]
        unique_indexes.append(columns)

    has_new_statuses = all(
        f"'{status.casefold()}'" in table_sql
        for status in ("Acknowledged", "Monitoring", "Closed")
    )
    has_application_timestamp_key = [
        "application_id",
        "source_timestamp",
    ] in unique_indexes
    has_legacy_timestamp_key = ["source_timestamp"] in unique_indexes
    needs_rebuild = (
        not required_columns.issubset(incident_columns)
        or not has_new_statuses
        or not has_application_timestamp_key
        or has_legacy_timestamp_key
    )
    if not needs_rebuild:
        return

    defaults = {
        "application_id": "NULL",
        "anomaly_id": "NULL",
        "rca_report_id": "NULL",
        "problem_key": "NULL",
        "last_seen_at": "source_timestamp",
        "occurrence_count": "1",
        "closed_at": "NULL",
        "is_simulated": "0",
        "simulation_id": "NULL",
        "acknowledged_at": "NULL",
        "resolved_at": "NULL",
        "resolution_time_seconds": "NULL",
    }
    copy_columns = (
        "incident_id",
        "application_id",
        "source_timestamp",
        "created_at",
        "updated_at",
        "severity",
        "status",
        "title",
        "root_cause",
        "recommended_action",
        "acknowledged_at",
        "resolved_at",
        "resolution_time_seconds",
        "anomaly_id",
        "rca_report_id",
        "problem_key",
        "last_seen_at",
        "occurrence_count",
        "closed_at",
        "is_simulated",
        "simulation_id",
    )
    copy_expressions = []
    for column in copy_columns:
        if column in incident_columns:
            expression = column
            if column == "occurrence_count":
                expression = "COALESCE(occurrence_count, 1)"
        else:
            expression = defaults.get(column, "NULL")
        copy_expressions.append(expression)

    connection.execute("PRAGMA foreign_keys = OFF")
    try:
        connection.executescript(
            f"""
        BEGIN IMMEDIATE;
        CREATE TABLE incidents_migrated (
            incident_id TEXT PRIMARY KEY,
            application_id TEXT,
            source_timestamp TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL CHECK (
                status IN (
                    'Open', 'Acknowledged', 'Investigating', 'Monitoring',
                    'Resolved', 'Closed'
                )
            ),
            title TEXT NOT NULL,
            root_cause TEXT NOT NULL,
            recommended_action TEXT NOT NULL,
            acknowledged_at TEXT,
            resolved_at TEXT,
            resolution_time_seconds REAL,
            anomaly_id INTEGER,
            rca_report_id INTEGER,
            problem_key TEXT,
            last_seen_at TEXT,
            occurrence_count INTEGER NOT NULL DEFAULT 1,
            closed_at TEXT,
            is_simulated INTEGER NOT NULL DEFAULT 0
                CHECK (is_simulated IN (0, 1)),
            simulation_id INTEGER,
            UNIQUE (application_id, source_timestamp)
        );
        INSERT INTO incidents_migrated ({", ".join(copy_columns)})
        SELECT {", ".join(copy_expressions)} FROM incidents;
        DROP TABLE incidents;
        ALTER TABLE incidents_migrated RENAME TO incidents;
        COMMIT;
        """
        )
    except Exception:
        if connection.in_transaction:
            connection.rollback()
        connection.execute("PRAGMA foreign_keys = ON")
        raise
    connection.execute("PRAGMA foreign_keys = ON")


def _migrate_recovery_schema(connection):
    columns_to_add = {
        "recovery_attempts": {
            "decision_reason": "TEXT NOT NULL DEFAULT ''",
            "approval_status": "TEXT NOT NULL DEFAULT 'Not required'",
            "error_details": "TEXT NOT NULL DEFAULT ''",
            "retry_count": "INTEGER NOT NULL DEFAULT 0",
            "approval_id": "INTEGER",
        },
        "approval_requests": {
            "decided_by": "TEXT",
            "decision_details": "TEXT NOT NULL DEFAULT ''",
        },
    }
    for table, columns_to_add_for_table in columns_to_add.items():
        existing_columns = {
            row["name"]
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        for column, definition in columns_to_add_for_table.items():
            if column not in existing_columns:
                connection.execute(
                    f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
                )
    connection.executescript(
        """
        CREATE INDEX IF NOT EXISTS recovery_attempts_incident
            ON recovery_attempts(application_id, incident_id, attempted_at);
        CREATE UNIQUE INDEX IF NOT EXISTS recovery_attempts_approval_execution
            ON recovery_attempts(approval_id)
            WHERE approval_id IS NOT NULL AND result <> 'Approval required';
        CREATE INDEX IF NOT EXISTS approval_requests_incident_action
            ON approval_requests(application_id, incident_id, action, status);
        """
    )


def initialize_database(db_path=None):
    with closing(connect(db_path)) as connection, connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS applications (
                application_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                application_type TEXT NOT NULL,
                url TEXT,
                monitoring_interval_seconds INTEGER NOT NULL DEFAULT 5
                    CHECK (monitoring_interval_seconds > 0),
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                owned_by_platform INTEGER NOT NULL DEFAULT 0
                    CHECK (owned_by_platform IN (0, 1)),
                process_monitoring_permitted INTEGER NOT NULL DEFAULT 0
                    CHECK (process_monitoring_permitted IN (0, 1)),
                automatic_recovery_permitted INTEGER NOT NULL DEFAULT 0
                    CHECK (automatic_recovery_permitted IN (0, 1)),
                process_name TEXT,
                process_executable_path TEXT,
                process_working_directory TEXT,
                endpoint_path TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                deactivated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS application_endpoints (
                endpoint_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                protocol TEXT NOT NULL,
                health_path TEXT,
                timeout_seconds REAL NOT NULL DEFAULT 2 CHECK (timeout_seconds > 0),
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS application_endpoints_application
                ON application_endpoints(application_id, active);

            CREATE TABLE IF NOT EXISTS application_processes (
                process_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                pid INTEGER,
                process_name TEXT,
                executable_path TEXT,
                working_directory TEXT,
                port INTEGER,
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS application_processes_application
                ON application_processes(application_id, active);

            CREATE TABLE IF NOT EXISTS application_dependencies (
                dependency_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                depends_on_application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                dependency_type TEXT NOT NULL DEFAULT 'consumes',
                active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (
                    application_id,
                    depends_on_application_id,
                    dependency_type
                )
            );
            CREATE INDEX IF NOT EXISTS application_dependencies_upstream
                ON application_dependencies(depends_on_application_id, active);

            CREATE TABLE IF NOT EXISTS application_telemetry (
                telemetry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                source TEXT NOT NULL DEFAULT 'monitor',
                timestamp TEXT NOT NULL,
                data_json TEXT NOT NULL,
                is_simulated INTEGER NOT NULL DEFAULT 0
                    CHECK (is_simulated IN (0, 1)),
                created_at TEXT NOT NULL,
                UNIQUE (application_id, timestamp)
            );
            CREATE INDEX IF NOT EXISTS application_telemetry_timeline
                ON application_telemetry(application_id, timestamp);

            CREATE TABLE IF NOT EXISTS anomaly_results (
                anomaly_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                timestamp TEXT NOT NULL,
                prediction TEXT NOT NULL,
                anomaly_score REAL,
                status TEXT NOT NULL,
                data_json TEXT NOT NULL,
                is_simulated INTEGER NOT NULL DEFAULT 0
                    CHECK (is_simulated IN (0, 1)),
                created_at TEXT NOT NULL,
                UNIQUE (application_id, timestamp)
            );
            CREATE INDEX IF NOT EXISTS anomaly_results_timeline
                ON anomaly_results(application_id, timestamp);

            CREATE TABLE IF NOT EXISTS application_models (
                application_id TEXT PRIMARY KEY
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                algorithm TEXT NOT NULL,
                model_version INTEGER NOT NULL,
                model_blob BLOB NOT NULL,
                features_json TEXT NOT NULL,
                medians_json TEXT NOT NULL,
                bounds_json TEXT NOT NULL,
                config_json TEXT NOT NULL,
                training_sample_count INTEGER NOT NULL,
                trained_through_timestamp TEXT NOT NULL,
                trained_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS root_cause_reports (
                report_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                incident_id TEXT,
                source_timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                data_json TEXT NOT NULL,
                is_simulated INTEGER NOT NULL DEFAULT 0
                    CHECK (is_simulated IN (0, 1)),
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS root_cause_reports_application
                ON root_cause_reports(application_id, source_timestamp);

            CREATE TABLE IF NOT EXISTS recovery_policies (
                policy_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
                requires_approval INTEGER NOT NULL DEFAULT 1
                    CHECK (requires_approval IN (0, 1)),
                policy_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (application_id, name)
            );

            CREATE TABLE IF NOT EXISTS recovery_attempts (
                recovery_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                incident_id TEXT,
                action TEXT NOT NULL,
                result TEXT NOT NULL,
                verification TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                attempted_at TEXT NOT NULL,
                completed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS recovery_attempts_application
                ON recovery_attempts(application_id, attempted_at);

            CREATE TABLE IF NOT EXISTS approval_requests (
                approval_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                incident_id TEXT,
                action TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending'
                    CHECK (status IN ('Pending', 'Approved', 'Rejected', 'Expired')),
                requested_by TEXT,
                requested_at TEXT NOT NULL,
                decided_at TEXT,
                expires_at TEXT,
                details TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS approval_requests_application
                ON approval_requests(application_id, status);

            CREATE TABLE IF NOT EXISTS simulation_events (
                simulation_id INTEGER PRIMARY KEY AUTOINCREMENT,
                application_id TEXT NOT NULL
                    REFERENCES applications(application_id) ON DELETE CASCADE,
                simulation_type TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                data_json TEXT NOT NULL,
                is_simulated INTEGER NOT NULL DEFAULT 1
                    CHECK (is_simulated IN (1)),
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS simulation_events_application
                ON simulation_events(application_id, started_at);

            CREATE TABLE IF NOT EXISTS incidents (
                incident_id TEXT PRIMARY KEY,
                application_id TEXT,
                source_timestamp TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                severity TEXT NOT NULL,
                status TEXT NOT NULL CHECK (
                    status IN (
                        'Open', 'Acknowledged', 'Investigating', 'Monitoring',
                        'Resolved', 'Closed'
                    )
                ),
                title TEXT NOT NULL,
                root_cause TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                acknowledged_at TEXT,
                resolved_at TEXT,
                resolution_time_seconds REAL,
                anomaly_id INTEGER,
                rca_report_id INTEGER,
                problem_key TEXT,
                last_seen_at TEXT,
                occurrence_count INTEGER NOT NULL DEFAULT 1,
                closed_at TEXT,
                UNIQUE (application_id, source_timestamp)
            );

            CREATE TABLE IF NOT EXISTS incident_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_id TEXT NOT NULL
                    REFERENCES incidents(incident_id) ON DELETE CASCADE,
                application_id TEXT,
                occurred_at TEXT NOT NULL,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                details TEXT NOT NULL DEFAULT '',
                source_key TEXT,
                anomaly_id INTEGER,
                rca_report_id INTEGER,
                UNIQUE (incident_id, event_type, source_key)
            );
            CREATE INDEX IF NOT EXISTS incident_events_timeline
                ON incident_events (incident_id, occurred_at, event_id);
            """
        )
        _migrate_legacy_incident_schema(connection)
        _migrate_recovery_schema(connection)
        connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS incidents_application_status
                ON incidents(application_id, status, updated_at);
            CREATE INDEX IF NOT EXISTS incidents_problem_key
                ON incidents(application_id, problem_key, status);

            CREATE TABLE IF NOT EXISTS discovery_settings (
                settings_id INTEGER PRIMARY KEY CHECK (settings_id = 1),
                mode TEXT NOT NULL DEFAULT 'disabled'
                    CHECK (mode IN ('enabled', 'paused', 'disabled')),
                automatic_registration INTEGER NOT NULL DEFAULT 0
                    CHECK (automatic_registration IN (0, 1)),
                automatic_monitoring INTEGER NOT NULL DEFAULT 0
                    CHECK (automatic_monitoring IN (0, 1)),
                updated_at TEXT NOT NULL
            );
            INSERT OR IGNORE INTO discovery_settings (settings_id, updated_at)
                VALUES (1, CURRENT_TIMESTAMP);

            CREATE TABLE IF NOT EXISTS discovery_pairings (
                pairing_id INTEGER PRIMARY KEY AUTOINCREMENT,
                pairing_code_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                used_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS discovery_credentials (
                extension_id TEXT PRIMARY KEY,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                revoked_at TEXT
            );

            CREATE TABLE IF NOT EXISTS discovered_applications (
                discovery_id TEXT PRIMARY KEY,
                application_id TEXT REFERENCES applications(application_id)
                    ON DELETE SET NULL,
                origin TEXT NOT NULL UNIQUE,
                hostname TEXT NOT NULL,
                first_discovered_at TEXT NOT NULL,
                last_discovered_at TEXT NOT NULL,
                discovery_source TEXT NOT NULL,
                registration_status TEXT NOT NULL DEFAULT 'pending_approval'
                    CHECK (registration_status IN (
                        'pending_approval', 'registered', 'existing', 'ignored'
                    )),
                monitoring_status TEXT NOT NULL DEFAULT 'disabled'
                    CHECK (monitoring_status IN ('enabled', 'disabled')),
                user_excluded INTEGER NOT NULL DEFAULT 0
                    CHECK (user_excluded IN (0, 1))
            );
            CREATE INDEX IF NOT EXISTS discovered_applications_status
                ON discovered_applications(registration_status, last_discovered_at);

            CREATE TABLE IF NOT EXISTS discovery_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                discovery_id TEXT NOT NULL REFERENCES discovered_applications(
                    discovery_id
                ) ON DELETE CASCADE,
                event_type TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                discovery_source TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS discovery_events_timeline
                ON discovery_events(occurred_at DESC, event_id DESC);

            CREATE TABLE IF NOT EXISTS discovery_exclusions (
                origin TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                excluded_at TEXT NOT NULL,
                restored_at TEXT
            );
            """
        )


def table_names(db_path=None):
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT name FROM sqlite_master
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
    return [row["name"] for row in rows]
