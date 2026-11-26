import json
import math
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone

from app.application_registry import get_application
from app.database import connect, initialize_database


RECOVERY_ACTION_RETRY = "retry_request"
RECOVERY_ACTION_RESTART = "restart_local_application"
SUPPORTED_RECOVERY_ACTIONS = (
    RECOVERY_ACTION_RETRY,
    RECOVERY_ACTION_RESTART,
)
APPROVAL_LEVELS = ("none", "high_risk", "all")
ESCALATION_BEHAVIORS = ("manual_intervention", "record_only")
MAXIMUM_ALLOWED_RETRIES = 5
MAXIMUM_COOLDOWN_SECONDS = 86400
MAXIMUM_VERIFICATION_TIMEOUT_SECONDS = 15.0


@dataclass(frozen=True)
class RecoveryPolicy:
    application_id: str
    automatic_recovery_enabled: bool
    permitted_actions: tuple[str, ...]
    required_approval_level: str
    max_retry_attempts: int
    cooldown_seconds: int
    verification_timeout_seconds: float
    escalation_behavior: str
    policy_enabled: bool = True


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _boolean(value, field):
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean.")
    return value


def _integer(value, field, minimum, maximum):
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer.")
    try:
        converted = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be an integer.") from error
    if isinstance(value, float) and not value.is_integer():
        raise ValueError(f"{field} must be an integer.")
    if isinstance(value, str) and str(converted) != value.strip():
        raise ValueError(f"{field} must be an integer.")
    if not minimum <= converted <= maximum:
        raise ValueError(
            f"{field} must be between {minimum} and {maximum}."
        )
    return converted


def _timeout(value):
    if isinstance(value, bool):
        raise ValueError("verification_timeout_seconds must be a number.")
    try:
        converted = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "verification_timeout_seconds must be a number."
        ) from error
    if (
        not math.isfinite(converted)
        or converted <= 0
        or converted > MAXIMUM_VERIFICATION_TIMEOUT_SECONDS
    ):
        raise ValueError(
            "verification_timeout_seconds must be greater than 0 and "
            f"at most {MAXIMUM_VERIFICATION_TIMEOUT_SECONDS:g}."
        )
    return converted


def _validated_policy(
    application_id,
    automatic_recovery_enabled,
    permitted_actions,
    required_approval_level,
    max_retry_attempts,
    cooldown_seconds,
    verification_timeout_seconds,
    escalation_behavior,
    policy_enabled,
):
    if not str(application_id or "").strip():
        raise ValueError("application_id is required.")
    if isinstance(permitted_actions, (str, bytes)):
        raise ValueError("permitted_actions must be a collection of action names.")
    try:
        actions = tuple(permitted_actions)
    except TypeError as error:
        raise ValueError(
            "permitted_actions must be a collection of action names."
        ) from error
    if any(not isinstance(action, str) for action in actions):
        raise ValueError("Recovery action names must be strings.")
    if len(set(actions)) != len(actions):
        raise ValueError("permitted_actions cannot contain duplicates.")
    unsupported = set(actions).difference(SUPPORTED_RECOVERY_ACTIONS)
    if unsupported:
        raise ValueError(
            "Unsupported recovery action(s): " + ", ".join(sorted(unsupported))
        )

    approval_level = str(required_approval_level or "").strip().casefold()
    if approval_level not in APPROVAL_LEVELS:
        raise ValueError(
            "required_approval_level must be none, high_risk, or all."
        )
    escalation = str(escalation_behavior or "").strip().casefold()
    if escalation not in ESCALATION_BEHAVIORS:
        raise ValueError(
            "escalation_behavior must be manual_intervention or record_only."
        )
    return RecoveryPolicy(
        application_id=str(application_id).strip(),
        automatic_recovery_enabled=_boolean(
            automatic_recovery_enabled,
            "automatic_recovery_enabled",
        ),
        permitted_actions=actions,
        required_approval_level=approval_level,
        max_retry_attempts=_integer(
            max_retry_attempts,
            "max_retry_attempts",
            1,
            MAXIMUM_ALLOWED_RETRIES,
        ),
        cooldown_seconds=_integer(
            cooldown_seconds,
            "cooldown_seconds",
            0,
            MAXIMUM_COOLDOWN_SECONDS,
        ),
        verification_timeout_seconds=_timeout(
            verification_timeout_seconds
        ),
        escalation_behavior=escalation,
        policy_enabled=_boolean(policy_enabled, "policy_enabled"),
    )


def _assert_application_permissions(application, policy):
    if application is None:
        raise KeyError(f"Application not found: {policy.application_id}")
    if not application["owned_by_platform"]:
        raise ValueError(
            "Recovery policies are permitted only for platform-owned applications."
        )
    if (
        policy.automatic_recovery_enabled
        and not application["automatic_recovery_permitted"]
    ):
        raise ValueError(
            "Automatic recovery is not permitted for this application."
        )
    if (
        RECOVERY_ACTION_RESTART in policy.permitted_actions
        and (
            not application["automatic_recovery_permitted"]
            or not application["process_monitoring_permitted"]
            or (
                application["application_type"] != "CONTROLLED_LOCAL_APPLICATION"
                and application["application_id"] != "APP-SDP-FLASK-5000"
            )
        )
    ):
        raise ValueError(
            "Local process restart requires a platform-owned controlled local "
            "application with automatic recovery and process monitoring permission."
        )


def configure_recovery_policy(
    application_id,
    *,
    automatic_recovery_enabled=False,
    permitted_actions=(),
    required_approval_level="high_risk",
    max_retry_attempts=3,
    cooldown_seconds=60,
    verification_timeout_seconds=10.0,
    escalation_behavior="manual_intervention",
    policy_enabled=True,
    db_path=None,
):
    policy = _validated_policy(
        application_id,
        automatic_recovery_enabled,
        permitted_actions,
        required_approval_level,
        max_retry_attempts,
        cooldown_seconds,
        verification_timeout_seconds,
        escalation_behavior,
        policy_enabled,
    )
    application = get_application(policy.application_id, db_path=db_path)
    _assert_application_permissions(application, policy)

    policy_json = json.dumps(
        {
            "automatic_recovery_enabled": policy.automatic_recovery_enabled,
            "permitted_actions": list(policy.permitted_actions),
            "required_approval_level": policy.required_approval_level,
            "max_retry_attempts": policy.max_retry_attempts,
            "cooldown_seconds": policy.cooldown_seconds,
            "verification_timeout_seconds": (
                policy.verification_timeout_seconds
            ),
            "escalation_behavior": policy.escalation_behavior,
        },
        separators=(",", ":"),
        allow_nan=False,
    )
    now = _now()
    initialize_database(db_path)
    with closing(connect(db_path)) as connection, connection:
        connection.execute(
            """
            INSERT INTO recovery_policies (
                application_id, name, enabled, requires_approval,
                policy_json, created_at, updated_at
            ) VALUES (?, 'application-default', ?, ?, ?, ?, ?)
            ON CONFLICT(application_id, name) DO UPDATE SET
                enabled = excluded.enabled,
                requires_approval = excluded.requires_approval,
                policy_json = excluded.policy_json,
                updated_at = excluded.updated_at
            """,
            (
                policy.application_id,
                1 if policy.policy_enabled else 0,
                (
                    1
                    if (
                        policy.required_approval_level != "none"
                        or not policy.automatic_recovery_enabled
                    )
                    else 0
                ),
                policy_json,
                now,
                now,
            ),
        )
    return policy


def get_recovery_policy(application_id, db_path=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        row = connection.execute(
            """
            SELECT enabled, policy_json
            FROM recovery_policies
            WHERE application_id = ? AND name = 'application-default'
            """,
            (application_id,),
        ).fetchone()
    if row is None:
        return None
    try:
        policy_data = json.loads(row["policy_json"])
    except (TypeError, json.JSONDecodeError) as error:
        raise RuntimeError(
            f"Recovery policy for {application_id} contains invalid JSON."
        ) from error
    if not isinstance(policy_data, dict):
        raise RuntimeError(
            f"Recovery policy for {application_id} must be a JSON object."
        )
    policy = _validated_policy(
        application_id,
        policy_data.get("automatic_recovery_enabled"),
        policy_data.get("permitted_actions", ()),
        policy_data.get("required_approval_level"),
        policy_data.get("max_retry_attempts"),
        policy_data.get("cooldown_seconds"),
        policy_data.get("verification_timeout_seconds"),
        policy_data.get("escalation_behavior"),
        bool(row["enabled"]),
    )
    _assert_application_permissions(
        get_application(application_id, db_path=db_path),
        policy,
    )
    return policy


def has_recovery_policy(application_id, db_path=None):
    initialize_database(db_path)
    with closing(connect(db_path)) as connection:
        return connection.execute(
            """
            SELECT 1 FROM recovery_policies
            WHERE application_id = ? AND name = 'application-default'
            """,
            (application_id,),
        ).fetchone() is not None
