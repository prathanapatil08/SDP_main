import hashlib
import hmac
import ipaddress
import re
import secrets
import socket
import threading
import time
import uuid
from collections import defaultdict, deque
from contextlib import closing
from datetime import datetime, timedelta, timezone
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlsplit
from urllib.request import (
    HTTPHandler,
    HTTPSHandler,
    HTTPRedirectHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from flask import Blueprint, current_app, jsonify, request

from app.application_registry import (
    get_application,
    get_applications,
    register_application,
    update_application,
)
from app.database import DATABASE_FILE, connect, initialize_database


DISCOVERY_INTERVAL_SECONDS = 300
DISCOVERY_EVENT_COOLDOWN_SECONDS = 60
PAIRING_CODE_TTL_SECONDS = 300
REQUEST_LIMIT = 60
REQUEST_WINDOW_SECONDS = 60
PAIRING_LIMIT = 5
PAIRING_WINDOW_SECONDS = 300
_EXTENSION_ORIGIN = re.compile(r"^chrome-extension://([a-p]{32})$")
_rate_lock = threading.Lock()
_rate_hits = defaultdict(deque)
_registration_lock = threading.Lock()

browser_discovery = Blueprint("browser_discovery", __name__)


class DiscoveryDisabledError(RuntimeError):
    pass


def _utc_now():
    return datetime.now(timezone.utc)


def _timestamp(value=None):
    return (value or _utc_now()).isoformat(timespec="microseconds")


def _hash_secret(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_origin(value):
    """Return a canonical HTTP(S) origin and hostname; reject URL details."""
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("A valid website origin is required.")
    if value != value.strip() or any(ord(char) < 32 for char in value):
        raise ValueError("Website origin contains invalid whitespace.")
    if "\\" in value:
        raise ValueError("Website origin contains an invalid path separator.")
    if "?" in value or "#" in value:
        raise ValueError("Website origins must not contain queries or fragments.")

    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.casefold()
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("Website origin is malformed.") from error

    if scheme not in {"http", "https"} or not parsed.netloc or not hostname:
        raise ValueError("Only absolute HTTP and HTTPS website origins are accepted.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Website origins must not contain credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Only a website origin may be submitted.")
    if "%" in hostname:
        raise ValueError("Encoded hostnames are not accepted.")

    hostname = hostname.rstrip(".").casefold()
    if not hostname:
        raise ValueError("Website hostname is empty.")
    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            hostname = hostname.encode("idna").decode("ascii").casefold()
        except UnicodeError as error:
            raise ValueError("Website hostname is invalid.") from error
        labels = hostname.split(".")
        if (
            len(labels) < 2
            or re.fullmatch(r"[0-9.]+", hostname)
            or any(
                not label
                or len(label) > 63
                or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
                for label in labels
            )
            or len(hostname) > 253
        ):
            raise ValueError("Website hostname is invalid.")
        if hostname == "localhost" or hostname.endswith(
            (".localhost", ".local", ".internal")
        ):
            raise ValueError("Local-only hostnames cannot be discovered.")
        host_for_origin = hostname
    else:
        if not address.is_global:
            raise ValueError("Private and non-public IP addresses cannot be discovered.")
        host_for_origin = f"[{address.compressed}]" if address.version == 6 else str(address)

    default_port = 80 if scheme == "http" else 443
    authority = host_for_origin
    if port is not None and port != default_port:
        authority = f"{authority}:{port}"
    return f"{scheme}://{authority}", hostname


def _extension_id(origin):
    if not isinstance(origin, str):
        return None
    match = _EXTENSION_ORIGIN.fullmatch(origin)
    return match.group(1) if match else None


def _local_request():
    remote = request.remote_addr
    try:
        is_loopback = ipaddress.ip_address(remote).is_loopback
    except (TypeError, ValueError):
        return False
    try:
        parsed_host = urlsplit(f"//{request.host}")
        host = (parsed_host.hostname or "").casefold()
        port = parsed_host.port
    except ValueError:
        return False
    return is_loopback and host in {"127.0.0.1", "localhost"} and port in {
        None,
        5000,
    }


def _paired_extension_id(db_path=None):
    origin_id = _extension_id(request.headers.get("Origin"))
    if origin_id is None:
        return None
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT extension_id FROM discovery_credentials
            WHERE extension_id = ? AND revoked_at IS NULL
            """,
            (origin_id,),
        ).fetchone()
    return origin_id if row else None


def _cors_allowed(origin, db_path=None, pairing=False):
    extension_id = _extension_id(origin)
    if extension_id is None:
        return False
    return pairing or extension_id == _paired_extension_id_for_origin(origin, db_path)


def _paired_extension_id_for_origin(origin, db_path=None):
    extension_id = _extension_id(origin)
    if extension_id is None:
        return None
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT extension_id FROM discovery_credentials
            WHERE extension_id = ? AND revoked_at IS NULL
            """,
            (extension_id,),
        ).fetchone()
    return extension_id if row else None


def _rate_limit(key, maximum, window):
    now = time.monotonic()
    with _rate_lock:
        hits = _rate_hits[key]
        while hits and now - hits[0] >= window:
            hits.popleft()
        if len(hits) >= maximum:
            return False
        hits.append(now)
        return True


def _settings(db_path=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM discovery_settings WHERE settings_id = 1"
        ).fetchone()
    return dict(row)


def _request_db_path():
    return current_app.config.get("SDP_DATABASE_PATH", DATABASE_FILE)


def get_discovery_settings(db_path=None):
    return _settings(db_path)


def _record_event(connection, discovery_id, event_type, source, now):
    previous = connection.execute(
        """
        SELECT occurred_at FROM discovery_events
        WHERE discovery_id = ? AND event_type IN ('discovered', 'rediscovered')
        ORDER BY event_id DESC LIMIT 1
        """,
        (discovery_id,),
    ).fetchone()
    if previous:
        try:
            last_event = datetime.fromisoformat(previous["occurred_at"])
            current = datetime.fromisoformat(now)
        except ValueError:
            last_event = current = None
        if (
            last_event is not None
            and current is not None
            and (current - last_event).total_seconds()
            < DISCOVERY_EVENT_COOLDOWN_SECONDS
        ):
            return
        event_type = "rediscovered"
    connection.execute(
        """
        INSERT INTO discovery_events (
            discovery_id, event_type, occurred_at, discovery_source
        ) VALUES (?, ?, ?, ?)
        """,
        (discovery_id, event_type, now, source),
    )


def _existing_application(origin, db_path=None):
    for application in get_applications(db_path=db_path, include_inactive=True):
        url = application.get("url")
        if not url:
            continue
        try:
            parsed = urlsplit(url)
            existing_origin, _ = normalize_origin(
                f"{parsed.scheme}://{parsed.netloc}"
            )
        except ValueError:
            continue
        if existing_origin == origin:
            return application
    return None


def _register_discovery(discovery, settings, db_path=None, event_source=None):
    application = register_application(
        name=discovery["hostname"],
        url=discovery["origin"],
        application_type=(
            "HTTPS_WEBSITE"
            if discovery["origin"].startswith("https://")
            else "HTTP_WEBSITE"
        ),
        monitoring_interval_seconds=DISCOVERY_INTERVAL_SECONDS,
        monitoring_enabled=bool(settings["automatic_monitoring"]),
        owned_by_platform=False,
        process_monitoring_permitted=False,
        automatic_recovery_permitted=False,
        db_path=db_path,
    )
    now = _timestamp()
    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            """
            UPDATE discovered_applications
            SET application_id = ?, registration_status = 'registered',
                monitoring_status = ?, user_excluded = 0
            WHERE discovery_id = ?
            """,
            (
                application["application_id"],
                "enabled" if application["active"] else "disabled",
                discovery["discovery_id"],
            ),
        )
        connection.execute(
            """
            INSERT INTO discovery_events (
                discovery_id, event_type, occurred_at, discovery_source
            ) VALUES (?, 'registered', ?, ?)
            """,
            (
                discovery["discovery_id"],
                now,
                event_source or discovery["discovery_source"],
            ),
        )
    return application


def discover_website(origin, discovery_source="browser_extension", db_path=None):
    origin, hostname = normalize_origin(origin)
    if (
        not isinstance(discovery_source, str)
        or not discovery_source.strip()
        or len(discovery_source) > 40
    ):
        raise ValueError("Discovery source is invalid.")
    initialize_database(db_path)
    settings = _settings(db_path)
    if settings["mode"] != "enabled":
        raise DiscoveryDisabledError("Browser discovery is not enabled.")

    now = _timestamp()
    with _registration_lock:
        with closing(connect(db_path)) as connection, connection:
            exclusion = connection.execute(
                """
                SELECT origin FROM discovery_exclusions
                WHERE origin = ? AND restored_at IS NULL
                """,
                (origin,),
            ).fetchone()
            if exclusion:
                return {
                    "accepted": True,
                    "excluded": True,
                    "origin": origin,
                    "registration_status": "excluded",
                    "monitoring_status": "disabled",
                }

            connection.execute(
                """
                INSERT OR IGNORE INTO discovered_applications (
                    discovery_id, origin, hostname, first_discovered_at,
                    last_discovered_at, discovery_source
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    origin,
                    hostname,
                    now,
                    now,
                    discovery_source,
                ),
            )
            discovery = connection.execute(
                "SELECT * FROM discovered_applications WHERE origin = ?",
                (origin,),
            ).fetchone()
            is_new = discovery["first_discovered_at"] == now
            connection.execute(
                """
                UPDATE discovered_applications
                SET last_discovered_at = ?, discovery_source = ?
                WHERE discovery_id = ?
                """,
                (now, discovery_source, discovery["discovery_id"]),
            )
            _record_event(
                connection,
                discovery["discovery_id"],
                "discovered" if is_new else "rediscovered",
                discovery_source,
                now,
            )
            discovery = dict(discovery)

        if discovery["registration_status"] == "ignored":
            return {
                "accepted": True,
                "excluded": False,
                "origin": origin,
                "application_id": discovery["application_id"],
                "registration_status": "ignored",
                "monitoring_status": discovery["monitoring_status"],
            }

        if not discovery["application_id"]:
            existing = _existing_application(origin, db_path)
            if existing is not None:
                with closing(connect(db_path)) as connection, connection:
                    connection.execute(
                        """
                        UPDATE discovered_applications
                        SET application_id = ?, registration_status = 'existing',
                            monitoring_status = ?
                        WHERE discovery_id = ?
                        """,
                        (
                            existing["application_id"],
                            "enabled" if existing["active"] else "disabled",
                            discovery["discovery_id"],
                        ),
                    )
                    connection.execute(
                        """
                        INSERT INTO discovery_events (
                            discovery_id, event_type, occurred_at,
                            discovery_source
                        ) VALUES (?, 'existing_application_matched', ?, ?)
                        """,
                        (discovery["discovery_id"], now, discovery_source),
                    )
                discovery["application_id"] = existing["application_id"]
                discovery["registration_status"] = "existing"
                discovery["monitoring_status"] = (
                    "enabled" if existing["active"] else "disabled"
                )

        if (
            discovery["registration_status"] == "pending_approval"
            and settings["automatic_registration"]
        ):
            application = _register_discovery(
                discovery,
                settings,
                db_path=db_path,
                event_source=discovery_source,
            )
            discovery["application_id"] = application["application_id"]
            discovery["registration_status"] = "registered"
            discovery["monitoring_status"] = (
                "enabled" if application["active"] else "disabled"
            )

        return {
            "accepted": True,
            "excluded": False,
            "origin": origin,
            "hostname": hostname,
            "application_id": discovery["application_id"],
            "registration_status": discovery["registration_status"],
            "monitoring_status": discovery["monitoring_status"],
        }


def list_discovered_applications(db_path=None, include_excluded=True):
    initialize_database(db_path)
    query = """
        SELECT d.*, e.excluded_at, e.restored_at
        FROM discovered_applications AS d
        LEFT JOIN discovery_exclusions AS e
          ON e.origin = d.origin AND e.restored_at IS NULL
    """
    if not include_excluded:
        query += " WHERE e.origin IS NULL"
    query += " ORDER BY d.last_discovered_at DESC, d.hostname COLLATE NOCASE"
    with closing(connect(db_path)) as connection:
        rows = connection.execute(query).fetchall()
    return [dict(row) for row in rows]


def get_discovery_history(limit=200, db_path=None):
    try:
        limit = int(limit)
    except (TypeError, ValueError) as error:
        raise ValueError("History limit must be an integer.") from error
    if not 1 <= limit <= 1000:
        raise ValueError("History limit must be between 1 and 1000.")
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        rows = connection.execute(
            """
            SELECT e.event_id, e.discovery_id, e.event_type, e.occurred_at,
                   e.discovery_source, d.origin, d.hostname, d.application_id
            FROM discovery_events AS e
            JOIN discovered_applications AS d
              ON d.discovery_id = e.discovery_id
            ORDER BY e.occurred_at DESC, e.event_id DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]


def _get_discovery(origin, db_path=None):
    origin, _ = normalize_origin(origin)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            "SELECT * FROM discovered_applications WHERE origin = ?",
            (origin,),
        ).fetchone()
    if row is None:
        raise KeyError("Discovered website was not found.")
    return dict(row)


def approve_discovery(origin, db_path=None):
    discovery = _get_discovery(origin, db_path)
    if discovery["user_excluded"]:
        raise ValueError("Excluded websites must be restored before approval.")
    if discovery["registration_status"] in {"registered", "existing"}:
        return discovery
    if discovery["registration_status"] == "ignored":
        raise ValueError("Ignored websites must be rediscovered before approval.")
    with _registration_lock:
        settings = _settings(db_path)
        application = _register_discovery(discovery, settings, db_path=db_path)
    return get_discovered_application(discovery["origin"], db_path)


def get_discovered_application(origin, db_path=None):
    origin, _ = normalize_origin(origin)
    for application in list_discovered_applications(db_path=db_path):
        if application["origin"] == origin:
            return application
    return None


def ignore_discovery(origin, db_path=None):
    discovery = _get_discovery(origin, db_path)
    if discovery["registration_status"] != "pending_approval":
        raise ValueError("Only pending discoveries can be ignored.")
    now = _timestamp()
    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            """
            UPDATE discovered_applications SET registration_status = 'ignored'
            WHERE discovery_id = ?
            """,
            (discovery["discovery_id"],),
        )
        connection.execute(
            """
            INSERT INTO discovery_events (
                discovery_id, event_type, occurred_at, discovery_source
            ) VALUES (?, 'ignored', ?, ?)
            """,
            (discovery["discovery_id"], now, discovery["discovery_source"]),
        )
    return get_discovered_application(discovery["origin"], db_path)


def exclude_discovery(origin, db_path=None):
    origin, hostname = normalize_origin(origin)
    initialize_database(db_path)
    now = _timestamp()
    with closing(connect(db_path)) as connection, connection:
        row = connection.execute(
            "SELECT * FROM discovered_applications WHERE origin = ?",
            (origin,),
        ).fetchone()
        if row is None:
            raise KeyError("Discovered website was not found.")
        connection.execute(
            """
            INSERT INTO discovery_exclusions (origin, hostname, excluded_at)
            VALUES (?, ?, ?)
            ON CONFLICT(origin) DO UPDATE SET
                hostname = excluded.hostname, excluded_at = excluded.excluded_at,
                restored_at = NULL
            """,
            (origin, hostname, now),
        )
        connection.execute(
            """
            UPDATE discovered_applications
            SET user_excluded = 1, monitoring_status = 'disabled'
            WHERE origin = ?
            """,
            (origin,),
        )
        connection.execute(
            """
            INSERT INTO discovery_events (
                discovery_id, event_type, occurred_at, discovery_source
            ) VALUES (?, 'excluded', ?, ?)
            """,
            (row["discovery_id"], now, row["discovery_source"]),
        )
        application_id = (
            row["application_id"]
            if row["registration_status"] == "registered"
            else None
        )
    if application_id:
        application = get_application(application_id, db_path)
        if (
            row["registration_status"] == "registered"
            and application
            and application["active"]
        ):
            update_application(
                application_id,
                db_path=db_path,
                monitoring_enabled=False,
            )
    return get_discovered_application(origin, db_path)


def restore_discovery(origin, db_path=None):
    origin, _ = normalize_origin(origin)
    now = _timestamp()
    with closing(connect(db_path)) as connection, connection:
        row = connection.execute(
            """
            SELECT d.*, s.automatic_monitoring
            FROM discovered_applications AS d
            CROSS JOIN discovery_settings AS s
            WHERE d.origin = ? AND s.settings_id = 1
            """,
            (origin,),
        ).fetchone()
        if row is None:
            raise KeyError("Discovered website was not found.")
        connection.execute(
            """
            UPDATE discovery_exclusions SET restored_at = ?
            WHERE origin = ? AND restored_at IS NULL
            """,
            (now, origin),
        )
        connection.execute(
            "UPDATE discovered_applications SET user_excluded = 0 WHERE origin = ?",
            (origin,),
        )
        connection.execute(
            """
            INSERT INTO discovery_events (
                discovery_id, event_type, occurred_at, discovery_source
            ) VALUES (?, 'exclusion_restored', ?, ?)
            """,
            (row["discovery_id"], now, row["discovery_source"]),
        )
        application_id = (
            row["application_id"]
            if row["registration_status"] == "registered"
            else None
        )
        enable_monitoring = bool(row["automatic_monitoring"])
    if application_id and enable_monitoring:
        update_application(
            application_id,
            db_path=db_path,
            monitoring_enabled=True,
        )
        with closing(connect(db_path)) as connection, connection:
            connection.execute(
                """
                UPDATE discovered_applications SET monitoring_status = 'enabled'
                WHERE origin = ?
                """,
                (origin,),
            )
    return get_discovered_application(origin, db_path)


def _register_pending(db_path=None):
    settings = _settings(db_path)
    if not settings["automatic_registration"]:
        return
    for discovery in list_discovered_applications(
        db_path=db_path,
        include_excluded=False,
    ):
        if discovery["registration_status"] == "pending_approval":
            with _registration_lock:
                _register_discovery(discovery, settings, db_path=db_path)


def configure_discovery(
    *,
    mode=None,
    automatic_registration=None,
    automatic_monitoring=None,
    db_path=None,
):
    current = _settings(db_path)
    if mode is not None and mode not in {"enabled", "paused", "disabled"}:
        raise ValueError("Discovery mode must be enabled, paused, or disabled.")
    for name, value in (
        ("automatic_registration", automatic_registration),
        ("automatic_monitoring", automatic_monitoring),
    ):
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"{name} must be a boolean.")

    updated = {
        "mode": mode if mode is not None else current["mode"],
        "automatic_registration": (
            automatic_registration
            if automatic_registration is not None
            else bool(current["automatic_registration"])
        ),
        "automatic_monitoring": (
            automatic_monitoring
            if automatic_monitoring is not None
            else bool(current["automatic_monitoring"])
        ),
    }
    now = _timestamp()
    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            """
            UPDATE discovery_settings
            SET mode = ?, automatic_registration = ?,
                automatic_monitoring = ?, updated_at = ?
            WHERE settings_id = 1
            """,
            (
                updated["mode"],
                int(updated["automatic_registration"]),
                int(updated["automatic_monitoring"]),
                now,
            ),
        )

    if automatic_monitoring is not None:
        for discovery in list_discovered_applications(db_path=db_path):
            if (
                discovery["registration_status"] != "registered"
                or not discovery["application_id"]
                or discovery["user_excluded"]
            ):
                continue
            update_application(
                discovery["application_id"],
                db_path=db_path,
                monitoring_enabled=automatic_monitoring,
            )
            with closing(connect(db_path)) as connection, connection:
                connection.execute(
                    """
                    UPDATE discovered_applications SET monitoring_status = ?
                    WHERE discovery_id = ?
                    """,
                    (
                        "enabled" if automatic_monitoring else "disabled",
                        discovery["discovery_id"],
                    ),
                )
    if automatic_registration is True:
        _register_pending(db_path)
    return _settings(db_path)


def generate_pairing_code(db_path=None, lifetime_seconds=PAIRING_CODE_TTL_SECONDS):
    if (
        isinstance(lifetime_seconds, bool)
        or not isinstance(lifetime_seconds, int)
        or not 30 <= lifetime_seconds <= 900
    ):
        raise ValueError("Pairing code lifetime must be between 30 and 900 seconds.")
    initialize_database(db_path)
    code = secrets.token_urlsafe(24)
    now = _utc_now()
    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            "UPDATE discovery_pairings SET used_at = ? WHERE used_at IS NULL",
            (_timestamp(now),),
        )
        connection.execute(
            """
            INSERT INTO discovery_pairings (
                pairing_code_hash, expires_at, created_at
            ) VALUES (?, ?, ?)
            """,
            (
                _hash_secret(code),
                _timestamp(now + timedelta(seconds=lifetime_seconds)),
                _timestamp(now),
            ),
        )
    return code


def pair_extension(code, origin, db_path=None):
    extension_id = _extension_id(origin)
    if extension_id is None:
        raise ValueError("Pairing is allowed only from a Chrome or Edge extension.")
    if not isinstance(code, str) or not 20 <= len(code) <= 128:
        raise ValueError("Pairing code is invalid or expired.")
    now = _timestamp()
    token = secrets.token_urlsafe(32)
    token_hash = _hash_secret(token)
    with closing(connect(db_path)) as connection, connection:
        rows = connection.execute(
            """
            SELECT pairing_id, pairing_code_hash FROM discovery_pairings
            WHERE used_at IS NULL AND expires_at > ?
            """,
            (now,),
        ).fetchall()
        pairing = next(
            (
                row
                for row in rows
                if hmac.compare_digest(
                    row["pairing_code_hash"],
                    _hash_secret(code),
                )
            ),
            None,
        )
        if pairing is None:
            raise ValueError("Pairing code is invalid or expired.")
        connection.execute(
            "UPDATE discovery_pairings SET used_at = ? WHERE pairing_id = ?",
            (now, pairing["pairing_id"]),
        )
        connection.execute(
            """
            INSERT INTO discovery_credentials (
                extension_id, token_hash, created_at, revoked_at
            ) VALUES (?, ?, ?, NULL)
            ON CONFLICT(extension_id) DO UPDATE SET
                token_hash = excluded.token_hash, created_at = excluded.created_at,
                revoked_at = NULL
            """,
            (extension_id, token_hash, now),
        )
    return token


def is_browser_discovered_application(application_id, db_path=None):
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT 1 FROM discovered_applications
            WHERE application_id = ? AND user_excluded = 0
            """,
            (application_id,),
        ).fetchone()
    return row is not None


def _resolve_public_target(url, resolver=None):
    resolver = resolver or socket.getaddrinfo
    try:
        parsed = urlsplit(url)
        origin, _ = normalize_origin(
            f"{parsed.scheme}://{parsed.netloc}"
        )
        hostname = urlsplit(origin).hostname
        port = urlsplit(origin).port or (
            443 if parsed.scheme.casefold() == "https" else 80
        )
        try:
            address = ipaddress.ip_address(hostname)
            return hostname, port, [address.compressed] if address.is_global else []
        except ValueError:
            results = resolver(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        addresses = []
        for result in results:
            address = ipaddress.ip_address(result[4][0])
            if not address.is_global:
                return hostname, port, []
            if address.compressed not in addresses:
                addresses.append(address.compressed)
        return hostname, port, addresses
    except (OSError, TypeError, ValueError):
        return None, None, []


def _safe_public_target(url, resolver=None):
    return bool(_resolve_public_target(url, resolver)[2])


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def safe_discovery_urlopen(request, timeout):
    hostname, _, addresses = _resolve_public_target(request.full_url)
    if not addresses:
        raise OSError("Discovered website resolves to a non-public network address.")

    address = addresses[0]

    class PinnedHTTPHandler(HTTPHandler):
        def http_open(self, req):
            class PinnedHTTPConnection(HTTPConnection):
                def connect(self):
                    self.sock = socket.create_connection(
                        (address, self.port),
                        self.timeout,
                        self.source_address,
                    )

            return self.do_open(PinnedHTTPConnection, req)

    class PinnedHTTPSHandler(HTTPSHandler):
        def https_open(self, req):
            class PinnedHTTPSConnection(HTTPSConnection):
                def connect(self):
                    raw_socket = socket.create_connection(
                        (address, self.port),
                        self.timeout,
                        self.source_address,
                    )
                    self.sock = self._context.wrap_socket(
                        raw_socket,
                        server_hostname=hostname,
                    )

            return self.do_open(PinnedHTTPSConnection, req)

    opener = build_opener(
        ProxyHandler({}),
        _NoRedirectHandler(),
        PinnedHTTPHandler(),
        PinnedHTTPSHandler(),
    )
    return opener.open(request, timeout=timeout)


def _json_body():
    value = request.get_json(silent=False)
    if not isinstance(value, dict):
        raise ValueError("A JSON object is required.")
    return value


@browser_discovery.before_request
def _authorize_discovery_request():
    db_path = _request_db_path()
    if not _local_request():
        return jsonify(error="Discovery API is available only on localhost."), 403

    origin = request.headers.get("Origin", "")
    initialize_database(db_path)
    is_pairing = request.endpoint == "browser_discovery.pair_route"
    if request.method == "OPTIONS":
        if not _cors_allowed(origin, db_path, pairing=is_pairing):
            return jsonify(error="Extension origin is not allowed."), 403
        return "", 204
    if is_pairing:
        if not _rate_limit(
            f"pair:{request.remote_addr}",
            PAIRING_LIMIT,
            PAIRING_WINDOW_SECONDS,
        ):
            return jsonify(error="Pairing rate limit exceeded."), 429
        return None

    extension_id = _extension_id(origin)
    if extension_id is None or extension_id != _paired_extension_id(db_path):
        return jsonify(error="Browser extension is not paired."), 401
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.casefold() != "bearer" or not token:
        return jsonify(error="Bearer authentication is required."), 401
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT token_hash FROM discovery_credentials
            WHERE extension_id = ? AND revoked_at IS NULL
            """,
            (extension_id,),
        ).fetchone()
    if row is None or not hmac.compare_digest(
        row["token_hash"],
        _hash_secret(token),
    ):
        return jsonify(error="Browser extension authentication failed."), 401
    if not _rate_limit(f"api:{row['token_hash']}", REQUEST_LIMIT, REQUEST_WINDOW_SECONDS):
        return jsonify(error="Discovery API rate limit exceeded."), 429
    return None


@browser_discovery.after_request
def _discovery_cors(response):
    origin = request.headers.get("Origin", "")
    pairing = request.endpoint == "browser_discovery.pair_route"
    if _cors_allowed(origin, _request_db_path(), pairing=pairing):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Max-Age"] = "300"
        response.headers["Vary"] = "Origin"
    return response


@browser_discovery.route("/api/discovery/pair", methods=["POST", "OPTIONS"])
def pair_route():
    try:
        body = _json_body()
        token = pair_extension(
            body.get("code"),
            request.headers.get("Origin"),
            db_path=_request_db_path(),
        )
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(token=token)


@browser_discovery.route("/api/discovery/register", methods=["POST", "OPTIONS"])
def register_route():
    try:
        body = _json_body()
        result = discover_website(
            body.get("origin"),
            discovery_source=body.get("source", "browser_extension"),
            db_path=_request_db_path(),
        )
    except DiscoveryDisabledError as error:
        return jsonify(error=str(error)), 409
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(result)


@browser_discovery.route("/api/discovery/status", methods=["GET", "OPTIONS"])
def status_route():
    settings = get_discovery_settings(_request_db_path())
    return jsonify(
        mode=settings["mode"],
        automatic_registration=bool(settings["automatic_registration"]),
        automatic_monitoring=bool(settings["automatic_monitoring"]),
        extension_connected=True,
    )


@browser_discovery.route("/api/discovery/applications", methods=["GET", "OPTIONS"])
def applications_route():
    return jsonify(
        applications=list_discovered_applications(
            db_path=_request_db_path(),
            include_excluded=True,
        )
    )


@browser_discovery.route("/api/discovery/history", methods=["GET", "OPTIONS"])
def history_route():
    try:
        limit = request.args.get("limit", default=200, type=int)
        history = get_discovery_history(limit, db_path=_request_db_path())
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(history=history)


@browser_discovery.route("/api/discovery/approve", methods=["POST", "OPTIONS"])
def approve_route():
    try:
        body = _json_body()
        result = approve_discovery(body.get("origin"), db_path=_request_db_path())
    except KeyError as error:
        return jsonify(error=str(error)), 404
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(application=result)


@browser_discovery.route("/api/discovery/ignore", methods=["POST", "OPTIONS"])
def ignore_route():
    try:
        body = _json_body()
        result = ignore_discovery(body.get("origin"), db_path=_request_db_path())
    except KeyError as error:
        return jsonify(error=str(error)), 404
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(application=result)


@browser_discovery.route("/api/discovery/exclude", methods=["POST", "OPTIONS"])
def exclude_route():
    try:
        body = _json_body()
        result = exclude_discovery(body.get("origin"), db_path=_request_db_path())
    except KeyError as error:
        return jsonify(error=str(error)), 404
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(application=result)


@browser_discovery.route("/api/discovery/restore", methods=["POST", "OPTIONS"])
def restore_route():
    try:
        body = _json_body()
        result = restore_discovery(body.get("origin"), db_path=_request_db_path())
    except KeyError as error:
        return jsonify(error=str(error)), 404
    except ValueError as error:
        return jsonify(error=str(error)), 400
    return jsonify(application=result)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a short-lived, single-use browser-extension pairing code."
    )
    parser.add_argument("--pair", action="store_true", required=True)
    args = parser.parse_args()
    if args.pair:
        print(generate_pairing_code(DATABASE_FILE))
