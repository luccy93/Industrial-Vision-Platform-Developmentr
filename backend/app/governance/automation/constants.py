"""Stable V36 governance-automation vocabulary and bounded defaults.

Automation is opt-in. Every schedule is seeded disabled, every job has a hard
item/time bound, and every side effect is idempotent. The module contains no
destructive operation and no automatic approval, release, or export action.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import NAMESPACE_URL, uuid5

# ---------------------------------------------------------------------------
# Job vocabulary
# ---------------------------------------------------------------------------


class JobType(str, Enum):
    RETENTION_EVALUATION = "RETENTION_EVALUATION"
    RETENTION_REVIEW_REMINDERS = "RETENTION_REVIEW_REMINDERS"
    LEGAL_HOLD_REMINDERS = "LEGAL_HOLD_REMINDERS"
    DISPOSITION_REVIEW_REMINDERS = "DISPOSITION_REVIEW_REMINDERS"
    EXPORT_APPROVAL_REMINDERS = "EXPORT_APPROVAL_REMINDERS"
    COMPLIANCE_SNAPSHOT = "COMPLIANCE_SNAPSHOT"
    GOVERNANCE_HEALTH_CHECK = "GOVERNANCE_HEALTH_CHECK"


class JobStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    UNAVAILABLE = "UNAVAILABLE"


class JobTrigger(str, Enum):
    SCHEDULE = "SCHEDULE"
    MANUAL = "MANUAL"
    RETRY = "RETRY"
    RECOVERY = "RECOVERY"


class JobEventType(str, Enum):
    CREATED = "CREATED"
    CLAIMED = "CLAIMED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    CANCEL_REQUESTED = "CANCEL_REQUESTED"
    RETRY_SCHEDULED = "RETRY_SCHEDULED"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    RECOVERED = "RECOVERED"


TERMINAL_JOB_STATUSES: frozenset[str] = frozenset(
    {
        JobStatus.SUCCEEDED.value,
        JobStatus.FAILED.value,
        JobStatus.CANCELLED.value,
        JobStatus.UNAVAILABLE.value,
    }
)

RETRYABLE_JOB_STATUSES: frozenset[str] = frozenset(
    {
        JobStatus.FAILED.value,
        JobStatus.UNAVAILABLE.value,
        JobStatus.CANCELLED.value,
    }
)

JOB_TYPE_VALUES: frozenset[str] = frozenset(item.value for item in JobType)
JOB_STATUS_VALUES: frozenset[str] = frozenset(item.value for item in JobStatus)
JOB_TRIGGER_VALUES: frozenset[str] = frozenset(item.value for item in JobTrigger)
JOB_EVENT_VALUES: frozenset[str] = frozenset(item.value for item in JobEventType)

# ---------------------------------------------------------------------------
# Schedule defaults and bounds
# ---------------------------------------------------------------------------

DEFAULT_SCHEDULE_INTERVALS: dict[str, int] = {
    JobType.RETENTION_EVALUATION.value: 1440,
    JobType.RETENTION_REVIEW_REMINDERS.value: 1440,
    JobType.LEGAL_HOLD_REMINDERS.value: 1440,
    JobType.DISPOSITION_REVIEW_REMINDERS.value: 1440,
    JobType.EXPORT_APPROVAL_REMINDERS.value: 1440,
    JobType.COMPLIANCE_SNAPSHOT.value: 1440,
    JobType.GOVERNANCE_HEALTH_CHECK.value: 60,
}

DEFAULT_SCHEDULE_CONFIGS: dict[str, dict[str, Any]] = {
    JobType.RETENTION_EVALUATION.value: {"batch_limit": 100},
    JobType.RETENTION_REVIEW_REMINDERS.value: {"upcoming_days": 30, "max_items": 100},
    JobType.LEGAL_HOLD_REMINDERS.value: {
        "max_items": 100,
        "active_hold_age_days": 30,
        "include_pending_approval": True,
        "include_active_holds": True,
    },
    JobType.DISPOSITION_REVIEW_REMINDERS.value: {"max_items": 100, "min_age_days": 1},
    JobType.EXPORT_APPROVAL_REMINDERS.value: {"max_items": 100, "upcoming_days": 14},
    JobType.COMPLIANCE_SNAPSHOT.value: {},
    JobType.GOVERNANCE_HEALTH_CHECK.value: {},
}

MIN_INTERVAL_MINUTES = 5
MAX_INTERVAL_MINUTES = 10080
MAX_REMINDER_ITEMS = 500
MAX_RETENTION_BATCH = 500
MAX_RETRY_ATTEMPTS = 5
MIN_RETRY_ATTEMPTS = 1
MAX_ERROR_LENGTH = 512
MAX_DEDUP_KEY_LENGTH = 200
MAX_SCHEDULE_SLOT_LENGTH = 128
MAX_RESULT_BYTES = 65536
SNAPSHOT_SCHEMA_VERSION = 1
SNAPSHOT_TYPE_COMPLIANCE_SUMMARY = "COMPLIANCE_SUMMARY"

_SCHEDULE_ID_NAMESPACE = "urn:ivp:governance-automation:schedule"


def schedule_row_id(job_type: str) -> str:
    """Deterministic schedule identifier so seeds and runtime seeding agree."""
    return str(uuid5(NAMESPACE_URL, f"{_SCHEDULE_ID_NAMESPACE}:{str(job_type).upper()}"))


# ---------------------------------------------------------------------------
# Reminder vocabulary
# ---------------------------------------------------------------------------

RETENTION_REVIEW_DUE_EVENT = "GOVERNANCE_RETENTION_REVIEW_DUE"
LEGAL_HOLD_PENDING_APPROVAL_EVENT = "GOVERNANCE_LEGAL_HOLD_PENDING_APPROVAL"
LEGAL_HOLD_REVIEW_DUE_EVENT = "GOVERNANCE_LEGAL_HOLD_REVIEW_DUE"
DISPOSITION_REVIEW_DUE_EVENT = "GOVERNANCE_DISPOSITION_REVIEW_DUE"
EXPORT_APPROVAL_REVIEW_DUE_EVENT = "GOVERNANCE_EXPORT_APPROVAL_REVIEW_DUE"

REMINDER_EVENT_TYPES: frozenset[str] = frozenset(
    {
        RETENTION_REVIEW_DUE_EVENT,
        LEGAL_HOLD_PENDING_APPROVAL_EVENT,
        LEGAL_HOLD_REVIEW_DUE_EVENT,
        DISPOSITION_REVIEW_DUE_EVENT,
        EXPORT_APPROVAL_REVIEW_DUE_EVENT,
    }
)

REMINDER_JOB_EVENT_TYPES: dict[str, tuple[str, ...]] = {
    JobType.RETENTION_REVIEW_REMINDERS.value: (RETENTION_REVIEW_DUE_EVENT,),
    JobType.LEGAL_HOLD_REMINDERS.value: (
        LEGAL_HOLD_PENDING_APPROVAL_EVENT,
        LEGAL_HOLD_REVIEW_DUE_EVENT,
    ),
    JobType.DISPOSITION_REVIEW_REMINDERS.value: (DISPOSITION_REVIEW_DUE_EVENT,),
    JobType.EXPORT_APPROVAL_REMINDERS.value: (EXPORT_APPROVAL_REVIEW_DUE_EVENT,),
}

REMINDER_CATEGORY_BY_JOB_TYPE: dict[str, str] = {
    JobType.RETENTION_REVIEW_REMINDERS.value: "RETENTION",
    JobType.LEGAL_HOLD_REMINDERS.value: "LEGAL_HOLD",
    JobType.DISPOSITION_REVIEW_REMINDERS.value: "DISPOSITION",
    JobType.EXPORT_APPROVAL_REMINDERS.value: "EXPORT_APPROVAL",
}

# ---------------------------------------------------------------------------
# Honest non-claims
# ---------------------------------------------------------------------------

AUTOMATION_ASSURANCE = "LOCAL_SELF_DIGEST_ONLY"
AUTOMATION_NON_CLAIMS: tuple[str, ...] = (
    "Scheduled retention evaluation is non-destructive and never deletes evidence.",
    "Governance reminders are review prompts; they never approve or release a legal hold, "
    "approve or reject a disposition, or generate a forensic export.",
    "Compliance snapshots are local aggregate records with a self-digest; they are not "
    "regulatory certification and are not externally anchored.",
    "Automation jobs, events, and snapshots are retained; V36 performs no job or snapshot "
    "pruning or deletion.",
    "Reminder delivery is local queue state; it is not an external delivery guarantee.",
)
AUTOMATION_LIMITATIONS: tuple[str, ...] = (
    "V36 automation is disabled by default and requires both the global enable flag and "
    "per-schedule enablement.",
    "Reminder delivery depends on enabled V15 GOVERNANCE alert rules and channels; V15 has "
    "no per-user notification preference table.",
    "Scheduled retention evaluation is bounded by the configured batch limit; cases beyond "
    "the limit are reported as truncated, not silently skipped.",
    "Compliance snapshots are SUMMARY-only and local; no external immutable storage or trust "
    "anchor is claimed.",
    "No automatic hold release, disposition approval, or forensic export generation is implemented.",
)

# ---------------------------------------------------------------------------
# Deterministic UTC slot and backoff helpers
# ---------------------------------------------------------------------------

_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


def normalize_utc(value: datetime | None) -> datetime:
    """Return an aware UTC datetime; naive values are treated as UTC."""
    if value is None:
        return datetime.now(UTC)
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def slot_start(now: datetime, interval_minutes: int) -> datetime:
    """Epoch-aligned UTC bucket start for a bounded interval."""
    minutes = max(MIN_INTERVAL_MINUTES, min(MAX_INTERVAL_MINUTES, int(interval_minutes)))
    reference = normalize_utc(now)
    seconds = int((reference - _EPOCH).total_seconds())
    bucket_seconds = minutes * 60
    return _EPOCH + timedelta(seconds=seconds - (seconds % bucket_seconds))


def schedule_slot_id(job_type: str, interval_minutes: int, now: datetime) -> str:
    """Deterministic slot identifier stored on scheduled jobs."""
    start = slot_start(now, interval_minutes)
    stamp = start.strftime("%Y%m%dT%H%M%SZ")
    return f"{str(job_type)}:{int(interval_minutes)}:{stamp}"[:MAX_SCHEDULE_SLOT_LENGTH]


def next_slot_start(now: datetime, interval_minutes: int) -> datetime:
    """Next bucket boundary strictly after ``now``."""
    current = slot_start(now, interval_minutes)
    return current + timedelta(minutes=max(MIN_INTERVAL_MINUTES, int(interval_minutes)))


def retry_delay_seconds(
    job_id: str,
    attempt: int,
    *,
    base_seconds: float,
    max_seconds: float,
) -> float:
    """Deterministic exponential backoff with deterministic jitter (80-120%)."""
    base = max(1.0, float(base_seconds))
    maximum = max(base, float(max_seconds))
    exponent = max(0, int(attempt) - 1)
    nominal = min(maximum, base * (2.0**exponent))
    digest = hashlib.sha256(f"{job_id}:{int(attempt)}".encode()).hexdigest()
    fraction = int(digest[:8], 16) / 0xFFFFFFFF
    jittered = nominal * (0.8 + 0.4 * fraction)
    return max(1.0, min(maximum, jittered))


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


def _bounded_int(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{name} must be an integer") from None
    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return parsed


def _bounded_bool(value: Any, *, name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ValueError(f"{name} must be a boolean")


def validate_schedule_config(job_type: str, config: Mapping[str, Any] | None) -> dict[str, Any]:
    """Validate and normalize one job type's schedule configuration.

    Unknown keys are rejected so a typo cannot silently weaken a bound. Defaults
    are applied for omitted keys.
    """
    normalized_type = str(job_type or "").upper()
    if normalized_type not in JOB_TYPE_VALUES:
        raise ValueError(f"unknown governance job type: {job_type}")
    candidate = dict(config or {})
    allowed: dict[str, tuple[str, int, int]] = {
        JobType.RETENTION_EVALUATION.value: {
            "batch_limit": ("int", 1, MAX_RETENTION_BATCH),
        },
        JobType.RETENTION_REVIEW_REMINDERS.value: {
            "upcoming_days": ("int", 1, 365),
            "max_items": ("int", 1, MAX_REMINDER_ITEMS),
        },
        JobType.LEGAL_HOLD_REMINDERS.value: {
            "max_items": ("int", 1, MAX_REMINDER_ITEMS),
            "active_hold_age_days": ("int", 0, 3650),
            "include_pending_approval": ("bool", 0, 0),
            "include_active_holds": ("bool", 0, 0),
        },
        JobType.DISPOSITION_REVIEW_REMINDERS.value: {
            "max_items": ("int", 1, MAX_REMINDER_ITEMS),
            "min_age_days": ("int", 0, 3650),
        },
        JobType.EXPORT_APPROVAL_REMINDERS.value: {
            "max_items": ("int", 1, MAX_REMINDER_ITEMS),
            "upcoming_days": ("int", 1, 365),
        },
        JobType.COMPLIANCE_SNAPSHOT.value: {},
        JobType.GOVERNANCE_HEALTH_CHECK.value: {},
    }[normalized_type]
    unknown = sorted(set(candidate) - set(allowed))
    if unknown:
        raise ValueError(f"unsupported configuration keys for {normalized_type}: {', '.join(unknown)}")
    defaults = DEFAULT_SCHEDULE_CONFIGS[normalized_type]
    result: dict[str, Any] = {}
    for key, default in defaults.items():
        value = candidate.get(key, default)
        kind, minimum, maximum = allowed[key]
        if kind == "bool":
            result[key] = _bounded_bool(value, name=key)
        else:
            result[key] = _bounded_int(value, name=key, minimum=minimum, maximum=maximum)
    return result


def validate_interval_minutes(value: Any) -> int:
    return _bounded_int(
        value,
        name="interval_minutes",
        minimum=MIN_INTERVAL_MINUTES,
        maximum=MAX_INTERVAL_MINUTES,
    )


__all__ = [
    "AUTOMATION_ASSURANCE",
    "AUTOMATION_LIMITATIONS",
    "AUTOMATION_NON_CLAIMS",
    "DEFAULT_SCHEDULE_CONFIGS",
    "DEFAULT_SCHEDULE_INTERVALS",
    "DISPOSITION_REVIEW_DUE_EVENT",
    "EXPORT_APPROVAL_REVIEW_DUE_EVENT",
    "JOB_EVENT_VALUES",
    "JOB_STATUS_VALUES",
    "JOB_TRIGGER_VALUES",
    "JOB_TYPE_VALUES",
    "JobEventType",
    "JobStatus",
    "JobTrigger",
    "JobType",
    "LEGAL_HOLD_PENDING_APPROVAL_EVENT",
    "LEGAL_HOLD_REVIEW_DUE_EVENT",
    "MAX_DEDUP_KEY_LENGTH",
    "MAX_ERROR_LENGTH",
    "MAX_INTERVAL_MINUTES",
    "MAX_REMINDER_ITEMS",
    "MAX_RESULT_BYTES",
    "MAX_RETRY_ATTEMPTS",
    "MAX_SCHEDULE_SLOT_LENGTH",
    "MIN_INTERVAL_MINUTES",
    "MIN_RETRY_ATTEMPTS",
    "REMINDER_CATEGORY_BY_JOB_TYPE",
    "REMINDER_EVENT_TYPES",
    "REMINDER_JOB_EVENT_TYPES",
    "RETENTION_REVIEW_DUE_EVENT",
    "RETRYABLE_JOB_STATUSES",
    "SNAPSHOT_SCHEMA_VERSION",
    "SNAPSHOT_TYPE_COMPLIANCE_SUMMARY",
    "TERMINAL_JOB_STATUSES",
    "next_slot_start",
    "normalize_utc",
    "retry_delay_seconds",
    "schedule_row_id",
    "schedule_slot_id",
    "slot_start",
    "validate_interval_minutes",
    "validate_schedule_config",
]
