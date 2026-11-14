"""Stable V37 governance-intelligence vocabulary and bounded defaults.

All scoring is deterministic and rule-based. The module contains no model
inference, no statistical forecast, and no automatic governance decision. Risk
levels are prioritization bands, not calibrated probabilities or legal advice.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import NAMESPACE_URL, uuid5

# ---------------------------------------------------------------------------
# Honest non-claims
# ---------------------------------------------------------------------------
INTELLIGENCE_ASSURANCE = "DETERMINISTIC_LOCAL_RULES_ONLY"
INTELLIGENCE_NON_CLAIMS: tuple[str, ...] = (
    "Governance risk scores are deterministic rule-based prioritization aids, not "
    "calibrated probabilities, statistical forecasts, or legal advice.",
    "No LLM, machine-learning model, or external AI service makes a governance decision.",
    "Confirmed integrity failures are scored only when a forensic verification outcome is FAIL; "
    "unavailable, not-run, simulated, and incomplete checks are never described as confirmed "
    "failures or PASS.",
    "Operational SLA targets are organization-defined and distinct from legal or regulatory deadlines.",
    "Recommendations are advisory only and never approve or release a legal hold, approve or "
    "reject a disposition, modify evidence, or delete any record.",
    "Intelligence snapshots are local aggregate records with a self-digest; they are not "
    "regulatory certification and are not externally anchored or immutable.",
)
INTELLIGENCE_LIMITATIONS: tuple[str, ...] = (
    "Risk scoring is computed on demand from existing V35/V36 records; V37 adds no scheduler "
    "and makes no autonomous decision.",
    "Historical SLA calculations use the target version effective at each item's start time; "
    "later target versions never rewrite history.",
    "Backlog and trend analytics use explicit bounded windows and mark source coverage gaps; "
    "an unavailable source is never reported as zero.",
    "Recommendation dismissal suppresses re-raising while the same condition persists; a later "
    "recurrence reopens the deduplicated recommendation.",
    "Snapshot comparison verifies the local self-digest only; it cannot prove external "
    "immutability or regulatory compliance.",
)

# ---------------------------------------------------------------------------
# Risk model
# ---------------------------------------------------------------------------
DEFAULT_MODEL_ID = "RISK-DEFAULT"
DEFAULT_MODEL_VERSION = 1
DEFAULT_MODEL_NAME = "Default governance risk model"
MAX_FACTOR_POINTS = 50
MAX_TOTAL_SCORE = 100

RISK_LEVEL_ORDER: tuple[str, ...] = ("LOW", "MODERATE", "HIGH", "CRITICAL")

DEFAULT_RISK_THRESHOLDS: dict[str, dict[str, int]] = {
    "LOW": {"min": 0, "max": 24},
    "MODERATE": {"min": 25, "max": 49},
    "HIGH": {"min": 50, "max": 74},
    "CRITICAL": {"min": 75, "max": 100},
}


class RiskLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DataCompleteness(str, Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"


class FactorDataStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_RUN = "NOT_RUN"
    SIMULATED = "SIMULATED"


class RiskFactor(str, Enum):
    CONFIRMED_INTEGRITY_FAILURE = "CONFIRMED_INTEGRITY_FAILURE"
    INTEGRITY_VERIFICATION_PARTIAL = "INTEGRITY_VERIFICATION_PARTIAL"
    INTEGRITY_VERIFICATION_UNAVAILABLE = "INTEGRITY_VERIFICATION_UNAVAILABLE"
    INTEGRITY_VERIFICATION_NOT_RUN = "INTEGRITY_VERIFICATION_NOT_RUN"
    INTEGRITY_VERIFICATION_SIMULATED = "INTEGRITY_VERIFICATION_SIMULATED"
    RETENTION_REVIEW_OVERDUE = "RETENTION_REVIEW_OVERDUE"
    DISPOSITION_REVIEW_OVERDUE = "DISPOSITION_REVIEW_OVERDUE"
    DISPOSITION_BLOCKED = "DISPOSITION_BLOCKED"
    LEGAL_HOLD_REVIEW_OVERDUE = "LEGAL_HOLD_REVIEW_OVERDUE"
    EXPORT_APPROVAL_EXPIRED = "EXPORT_APPROVAL_EXPIRED"
    EXPORT_APPROVAL_EXPIRING = "EXPORT_APPROVAL_EXPIRING"
    POLICY_MISSING_OR_DISABLED = "POLICY_MISSING_OR_DISABLED"
    LINKED_OPEN_INCIDENT = "LINKED_OPEN_INCIDENT"
    CASE_SEVERITY_HIGH = "CASE_SEVERITY_HIGH"
    CASE_SEVERITY_CRITICAL = "CASE_SEVERITY_CRITICAL"


FACTOR_ORDER: tuple[str, ...] = tuple(item.value for item in RiskFactor)

DEFAULT_FACTOR_POINTS: dict[str, int] = {
    RiskFactor.CONFIRMED_INTEGRITY_FAILURE.value: 45,
    RiskFactor.INTEGRITY_VERIFICATION_PARTIAL.value: 12,
    RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value: 0,
    RiskFactor.INTEGRITY_VERIFICATION_NOT_RUN.value: 0,
    RiskFactor.INTEGRITY_VERIFICATION_SIMULATED.value: 0,
    RiskFactor.RETENTION_REVIEW_OVERDUE.value: 20,
    RiskFactor.DISPOSITION_REVIEW_OVERDUE.value: 15,
    RiskFactor.DISPOSITION_BLOCKED.value: 15,
    RiskFactor.LEGAL_HOLD_REVIEW_OVERDUE.value: 10,
    RiskFactor.EXPORT_APPROVAL_EXPIRED.value: 15,
    RiskFactor.EXPORT_APPROVAL_EXPIRING.value: 8,
    RiskFactor.POLICY_MISSING_OR_DISABLED.value: 10,
    RiskFactor.LINKED_OPEN_INCIDENT.value: 10,
    RiskFactor.CASE_SEVERITY_HIGH.value: 10,
    RiskFactor.CASE_SEVERITY_CRITICAL.value: 15,
}

FACTOR_LABELS: dict[str, str] = {
    RiskFactor.CONFIRMED_INTEGRITY_FAILURE.value: "Confirmed integrity verification failure",
    RiskFactor.INTEGRITY_VERIFICATION_PARTIAL.value: "Integrity verification incomplete",
    RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value: "Integrity verification unavailable",
    RiskFactor.INTEGRITY_VERIFICATION_NOT_RUN.value: "Integrity verification not run",
    RiskFactor.INTEGRITY_VERIFICATION_SIMULATED.value: "Integrity verification simulated",
    RiskFactor.RETENTION_REVIEW_OVERDUE.value: "Retention review overdue",
    RiskFactor.DISPOSITION_REVIEW_OVERDUE.value: "Disposition review overdue",
    RiskFactor.DISPOSITION_BLOCKED.value: "Disposition review blocked",
    RiskFactor.LEGAL_HOLD_REVIEW_OVERDUE.value: "Legal hold review overdue",
    RiskFactor.EXPORT_APPROVAL_EXPIRED.value: "Export approval expired",
    RiskFactor.EXPORT_APPROVAL_EXPIRING.value: "Export approval expiring",
    RiskFactor.POLICY_MISSING_OR_DISABLED.value: "Applicable policy missing or disabled",
    RiskFactor.LINKED_OPEN_INCIDENT.value: "Linked security incident open",
    RiskFactor.CASE_SEVERITY_HIGH.value: "Case severity high",
    RiskFactor.CASE_SEVERITY_CRITICAL.value: "Case severity critical",
}

#: Fixed correlation groups. Only the highest-points factor in a group
#: contributes to the score; every suppressed factor remains visible.
CORRELATION_GROUPS: dict[str, tuple[str, ...]] = {
    "integrity_verification": (
        RiskFactor.CONFIRMED_INTEGRITY_FAILURE.value,
        RiskFactor.INTEGRITY_VERIFICATION_PARTIAL.value,
        RiskFactor.INTEGRITY_VERIFICATION_UNAVAILABLE.value,
        RiskFactor.INTEGRITY_VERIFICATION_NOT_RUN.value,
        RiskFactor.INTEGRITY_VERIFICATION_SIMULATED.value,
    ),
    "export_approval": (
        RiskFactor.EXPORT_APPROVAL_EXPIRED.value,
        RiskFactor.EXPORT_APPROVAL_EXPIRING.value,
    ),
    "case_severity": (
        RiskFactor.CASE_SEVERITY_CRITICAL.value,
        RiskFactor.CASE_SEVERITY_HIGH.value,
    ),
}

FACTOR_CORRELATION_GROUP: dict[str, str] = {
    factor: group for group, factors in CORRELATION_GROUPS.items() for factor in factors
}

#: A blocked disposition caused by an integrity problem is already represented
#: by the integrity factor and must not be counted a second time.
DISPOSITION_BLOCKED_INTEGRITY_CODES: frozenset[str] = frozenset(
    {"INTEGRITY_NOT_PASS", "INTEGRITY_UNAVAILABLE"}
)


def validate_thresholds(value: Any) -> dict[str, dict[str, int]]:
    """Validate a contiguous 0-100 threshold partition and return a copy."""
    if not isinstance(value, Mapping):
        raise ValueError("thresholds must be an object keyed by risk level")
    normalized: dict[str, dict[str, int]] = {}
    for level in RISK_LEVEL_ORDER:
        raw = value.get(level)
        if not isinstance(raw, Mapping):
            raise ValueError(f"thresholds.{level} must define min and max")
        try:
            minimum = int(raw.get("min"))
            maximum = int(raw.get("max"))
        except (TypeError, ValueError):
            raise ValueError(f"thresholds.{level} min and max must be integers") from None
        if minimum < 0 or maximum > MAX_TOTAL_SCORE or minimum > maximum:
            raise ValueError(f"thresholds.{level} must be within 0..{MAX_TOTAL_SCORE}")
        normalized[level] = {"min": minimum, "max": maximum}
    if normalized["LOW"]["min"] != 0:
        raise ValueError("LOW threshold must start at 0")
    if normalized["CRITICAL"]["max"] != MAX_TOTAL_SCORE:
        raise ValueError(f"CRITICAL threshold must end at {MAX_TOTAL_SCORE}")
    for previous, current in zip(RISK_LEVEL_ORDER, RISK_LEVEL_ORDER[1:]):
        if normalized[current]["min"] != normalized[previous]["max"] + 1:
            raise ValueError("risk thresholds must be contiguous and ordered")
    return normalized


def validate_factor_points(value: Any) -> dict[str, int]:
    """Validate factor points, fill omitted defaults, and reject unknown keys."""
    if value is None:
        return dict(DEFAULT_FACTOR_POINTS)
    if not isinstance(value, Mapping):
        raise ValueError("factor_points must be an object")
    unknown = sorted(set(map(str, value)) - set(FACTOR_ORDER))
    if unknown:
        raise ValueError(f"unknown risk factors: {', '.join(unknown)}")
    normalized = dict(DEFAULT_FACTOR_POINTS)
    for factor in FACTOR_ORDER:
        if factor not in value:
            continue
        try:
            points = int(value[factor])
        except (TypeError, ValueError):
            raise ValueError(f"factor_points.{factor} must be an integer") from None
        if points < 0 or points > MAX_FACTOR_POINTS:
            raise ValueError(f"factor_points.{factor} must be between 0 and {MAX_FACTOR_POINTS}")
        normalized[factor] = points
    return normalized


def risk_level_for(score: int | float, thresholds: Mapping[str, Mapping[str, int]]) -> str:
    value = max(0, min(MAX_TOTAL_SCORE, int(score)))
    for level in RISK_LEVEL_ORDER:
        bounds = thresholds.get(level) or {}
        if int(bounds.get("min", 0)) <= value <= int(bounds.get("max", 0)):
            return level
    return RiskLevel.CRITICAL.value


def default_risk_model() -> dict[str, Any]:
    return {
        "model_id": DEFAULT_MODEL_ID,
        "version": DEFAULT_MODEL_VERSION,
        "name": DEFAULT_MODEL_NAME,
        "state": "ENABLED",
        "thresholds": {level: dict(bounds) for level, bounds in DEFAULT_RISK_THRESHOLDS.items()},
        "factor_points": dict(DEFAULT_FACTOR_POINTS),
    }


# ---------------------------------------------------------------------------
# Operational SLA targets
# ---------------------------------------------------------------------------
class SlaTargetKey(str, Enum):
    RETENTION_REVIEW = "RETENTION_REVIEW"
    DISPOSITION_REVIEW = "DISPOSITION_REVIEW"
    LEGAL_HOLD_REVIEW = "LEGAL_HOLD_REVIEW"
    EXPORT_APPROVAL = "EXPORT_APPROVAL"


SLA_TARGET_KEYS: tuple[str, ...] = tuple(item.value for item in SlaTargetKey)

#: v1 platform defaults. These are operational targets only; they are not
#: legal or regulatory deadlines. The effective date is the Unix epoch so the
#: default version also applies to pre-V37 historical records.
DEFAULT_SLA_EFFECTIVE_FROM = datetime(1970, 1, 1, tzinfo=UTC)
DEFAULT_SLA_TARGETS: dict[str, dict[str, int]] = {
    SlaTargetKey.RETENTION_REVIEW.value: {"target_hours": 720, "warning_hours": 168},
    SlaTargetKey.DISPOSITION_REVIEW.value: {"target_hours": 240, "warning_hours": 48},
    SlaTargetKey.LEGAL_HOLD_REVIEW.value: {"target_hours": 168, "warning_hours": 24},
    SlaTargetKey.EXPORT_APPROVAL.value: {"target_hours": 120, "warning_hours": 24},
}

SLA_KIND_OPERATIONAL = "OPERATIONAL"
SLA_NON_CLAIM = "This is an organization-configurable operational SLA, not a legal or regulatory deadline."
MIN_SLA_HOURS = 1
MAX_SLA_HOURS = 87600


class SlaState(str, Enum):
    WITHIN_TARGET = "WITHIN_TARGET"
    AT_RISK = "AT_RISK"
    BREACHED = "BREACHED"
    MET = "MET"
    MISSED = "MISSED"
    UNKNOWN = "UNKNOWN"
    NOT_APPLICABLE = "NOT_APPLICABLE"


SLA_STATE_VALUES: frozenset[str] = frozenset(item.value for item in SlaState)


def validate_sla_target(target_hours: Any, warning_hours: Any) -> tuple[int, int]:
    try:
        target = int(target_hours)
        warning = int(warning_hours)
    except (TypeError, ValueError):
        raise ValueError("target_hours and warning_hours must be integers") from None
    if target < MIN_SLA_HOURS or target > MAX_SLA_HOURS:
        raise ValueError(f"target_hours must be between {MIN_SLA_HOURS} and {MAX_SLA_HOURS}")
    if warning < MIN_SLA_HOURS or warning >= target:
        raise ValueError("warning_hours must be at least 1 and less than target_hours")
    return target, warning


# ---------------------------------------------------------------------------
# Recommendations
# ---------------------------------------------------------------------------
class RecommendationStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DISMISSED = "DISMISSED"
    RESOLVED = "RESOLVED"


class RecommendationSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RecommendationEventType(str, Enum):
    CREATED = "CREATED"
    REFRESHED = "REFRESHED"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    DISMISSED = "DISMISSED"
    RESOLVED = "RESOLVED"
    REOPENED = "REOPENED"
    AUTO_RESOLVED = "AUTO_RESOLVED"


RECOMMENDATION_STATUS_VALUES: frozenset[str] = frozenset(item.value for item in RecommendationStatus)
RECOMMENDATION_SEVERITY_VALUES: frozenset[str] = frozenset(item.value for item in RecommendationSeverity)
RECOMMENDATION_EVENT_VALUES: frozenset[str] = frozenset(item.value for item in RecommendationEventType)

RECOMMENDATION_TRANSITIONS: dict[str, frozenset[str]] = {
    RecommendationStatus.OPEN.value: frozenset(
        {
            RecommendationStatus.ACKNOWLEDGED.value,
            RecommendationStatus.DISMISSED.value,
            RecommendationStatus.RESOLVED.value,
        }
    ),
    RecommendationStatus.ACKNOWLEDGED.value: frozenset(
        {RecommendationStatus.DISMISSED.value, RecommendationStatus.RESOLVED.value}
    ),
    RecommendationStatus.DISMISSED.value: frozenset({RecommendationStatus.RESOLVED.value}),
    RecommendationStatus.RESOLVED.value: frozenset({RecommendationStatus.OPEN.value}),
}

MAX_DISMISS_REASON_LENGTH = 500
MIN_DISMISS_REASON_LENGTH = 3
MAX_RECOMMENDATION_REASON_LENGTH = 2048
MAX_RECOMMENDATION_KEY_LENGTH = 320
MAX_RECOMMENDATION_TITLE_LENGTH = 200
MAX_RECOMMENDATION_RATIONALE_LENGTH = 2048
MAX_RECOMMENDATION_EVENTS = 200
MAX_REFRESH_ITEMS = 500

RECOMMENDATION_ID_NAMESPACE = "urn:ivp:governance-intelligence:recommendation"


def risk_model_row_id(model_id: str, version: int) -> str:
    """Deterministic risk-model row identifier."""
    return str(
        uuid5(
            NAMESPACE_URL,
            f"urn:ivp:governance-intelligence:risk-model:{model_id}:{int(version)}",
        )
    )


def sla_target_row_id(target_key: str, version: int) -> str:
    """Deterministic SLA-target row identifier."""
    return str(
        uuid5(
            NAMESPACE_URL,
            f"urn:ivp:governance-intelligence:sla-target:{str(target_key).upper()}:{int(version)}",
        )
    )


def recommendation_key(rule_id: str, scope_type: str, scope_id: str) -> str:
    """Deterministic deduplication key for one rule and one scope."""
    return f"{str(rule_id).upper()}|{str(scope_type).upper()}|{str(scope_id)}"[:MAX_RECOMMENDATION_KEY_LENGTH]


def recommendation_id(rule_id: str, scope_type: str, scope_id: str) -> str:
    """Deterministic UUIDv5 recommendation identifier."""
    key = recommendation_key(rule_id, scope_type, scope_id)
    return str(uuid5(NAMESPACE_URL, f"{RECOMMENDATION_ID_NAMESPACE}:{key}"))


# rule_id -> (title, default severity)
RECOMMENDATION_RULES: dict[str, tuple[str, str]] = {
    "GOV-RISK-001": ("Review a critical governance risk case", RecommendationSeverity.CRITICAL.value),
    "GOV-RISK-002": ("Prioritize a high governance risk case", RecommendationSeverity.HIGH.value),
    "GOV-INT-001": (
        "Review a confirmed integrity verification failure",
        RecommendationSeverity.HIGH.value,
    ),
    "GOV-INT-002": (
        "Run or restore an unavailable integrity verification",
        RecommendationSeverity.MEDIUM.value,
    ),
    "GOV-RET-001": ("Complete an overdue retention review", RecommendationSeverity.HIGH.value),
    "GOV-DISP-001": ("Complete an overdue disposition review", RecommendationSeverity.HIGH.value),
    "GOV-HOLD-001": ("Complete an overdue legal-hold review", RecommendationSeverity.HIGH.value),
    "GOV-EXP-001": ("Review an expiring or expired export approval", RecommendationSeverity.MEDIUM.value),
    "GOV-SNAP-001": (
        "Investigate a governance snapshot digest mismatch",
        RecommendationSeverity.HIGH.value,
    ),
    "GOV-AUTO-001": (
        "Inspect repeated governance automation job failures",
        RecommendationSeverity.MEDIUM.value,
    ),
}

RULE_IDS: tuple[str, ...] = tuple(RECOMMENDATION_RULES)

# ---------------------------------------------------------------------------
# Snapshot comparison
# ---------------------------------------------------------------------------
SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY = "INTELLIGENCE_SUMMARY"
SNAPSHOT_TYPE_COMPLIANCE_SUMMARY = "COMPLIANCE_SUMMARY"
SNAPSHOT_COMPARABLE_TYPES: frozenset[str] = frozenset(
    {SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY, SNAPSHOT_TYPE_COMPLIANCE_SUMMARY}
)
MAX_SNAPSHOT_DIFF_ITEMS = 200

#: Fields that legitimately differ between two snapshots and therefore do not
#: belong in a metric diff.
SNAPSHOT_VOLATILE_KEYS: frozenset[str] = frozenset(
    {"generated_at", "as_of", "snapshot_type", "schema_version"}
)

# ---------------------------------------------------------------------------
# Trend sources and bounded categories
# ---------------------------------------------------------------------------
TREND_SOURCE_ORDER: tuple[str, ...] = (
    "governance_events",
    "retention_evaluations",
    "recommendations",
    "sla_inflow",
    "risk_scores",
)
TREND_AUDIT_GROUPS: tuple[str, ...] = (
    "ACCESS",
    "RETENTION",
    "LEGAL_HOLD",
    "DISPOSITION",
    "EXPORT",
    "REPORT",
    "AUTOMATION",
    "INTELLIGENCE",
    "OTHER",
)
RECOMMENDATION_SCOPE_CASE = "CASE"
RECOMMENDATION_SCOPE_DISPOSITION = "DISPOSITION"
RECOMMENDATION_SCOPE_LEGAL_HOLD = "LEGAL_HOLD"
RECOMMENDATION_SCOPE_EXPORT_APPROVAL = "EXPORT_APPROVAL"
RECOMMENDATION_SCOPE_SNAPSHOT = "SNAPSHOT"
RECOMMENDATION_SCOPE_AUTOMATION = "AUTOMATION"

#: Optional V15 event type for newly created CRITICAL recommendations.
INTELLIGENCE_ALERT_EVENT_TYPE = "GOVERNANCE_INTELLIGENCE_RECOMMENDATION_CRITICAL"


def audit_event_group(event_type: str) -> str:
    """Map a bounded governance audit event type to a stable trend group."""
    value = str(event_type or "").upper()
    if value.startswith("EXPORT_"):
        return "EXPORT"
    if value.startswith("LEGAL_HOLD_"):
        return "LEGAL_HOLD"
    if value.startswith("RETENTION_"):
        return "RETENTION"
    if value.startswith("DISPOSITION_"):
        return "DISPOSITION"
    if value.startswith("AUTOMATION_"):
        return "AUTOMATION"
    if value.startswith("INTELLIGENCE_"):
        return "INTELLIGENCE"
    if value.startswith("GOVERNANCE_REPORT_"):
        return "REPORT"
    if value in {
        "CASE_VIEWED",
        "EVIDENCE_METADATA_VIEWED",
        "CUSTODY_HISTORY_VIEWED",
        "EVIDENCE_VERIFICATION_REQUESTED",
        "GOVERNANCE_ACCESS_DENIED",
    }:
        return "ACCESS"
    return "OTHER"


# ---------------------------------------------------------------------------
# Bounds and page defaults
# ---------------------------------------------------------------------------
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20
MAX_RISK_CASES = 2000
DEFAULT_RISK_CASES = 500
DEFAULT_TREND_WINDOW_DAYS = 30
MAX_TREND_WINDOW_DAYS = 90
MAX_TREND_ROWS = 5000
MAX_SNAPSHOT_ROWS = 5000
DEFAULT_TREND_BUCKET = "day"
TREND_BUCKETS: tuple[str, ...] = ("hour", "day", "week")

CASE_SCOPE_TYPE = "CASE"
GLOBAL_SCOPE_TYPE = "GLOBAL"


def ordered_factor_points(points: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """Return factor points in stable display order."""
    normalized = validate_factor_points(points)
    return [
        {"factor_id": factor, "label": FACTOR_LABELS[factor], "points": normalized[factor]}
        for factor in FACTOR_ORDER
    ]


__all__ = [
    "CASE_SCOPE_TYPE",
    "CORRELATION_GROUPS",
    "DEFAULT_FACTOR_POINTS",
    "DEFAULT_MODEL_ID",
    "DEFAULT_MODEL_NAME",
    "DEFAULT_MODEL_VERSION",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_RISK_CASES",
    "DEFAULT_RISK_THRESHOLDS",
    "DEFAULT_SLA_EFFECTIVE_FROM",
    "DEFAULT_SLA_TARGETS",
    "DEFAULT_TREND_BUCKET",
    "DEFAULT_TREND_WINDOW_DAYS",
    "DISPOSITION_BLOCKED_INTEGRITY_CODES",
    "DataCompleteness",
    "FACTOR_CORRELATION_GROUP",
    "FACTOR_LABELS",
    "FACTOR_ORDER",
    "FactorDataStatus",
    "GLOBAL_SCOPE_TYPE",
    "INTELLIGENCE_ALERT_EVENT_TYPE",
    "INTELLIGENCE_ASSURANCE",
    "INTELLIGENCE_LIMITATIONS",
    "INTELLIGENCE_NON_CLAIMS",
    "MAX_DISMISS_REASON_LENGTH",
    "MAX_FACTOR_POINTS",
    "MAX_PAGE_SIZE",
    "MAX_RECOMMENDATION_EVENTS",
    "MAX_RECOMMENDATION_KEY_LENGTH",
    "MAX_RECOMMENDATION_RATIONALE_LENGTH",
    "MAX_RECOMMENDATION_REASON_LENGTH",
    "MAX_RECOMMENDATION_TITLE_LENGTH",
    "MAX_REFRESH_ITEMS",
    "MAX_RISK_CASES",
    "MAX_SLA_HOURS",
    "MAX_SNAPSHOT_DIFF_ITEMS",
    "MAX_SNAPSHOT_ROWS",
    "MAX_TOTAL_SCORE",
    "MAX_TREND_ROWS",
    "MAX_TREND_WINDOW_DAYS",
    "MIN_DISMISS_REASON_LENGTH",
    "MIN_SLA_HOURS",
    "RECOMMENDATION_EVENT_VALUES",
    "RECOMMENDATION_ID_NAMESPACE",
    "RECOMMENDATION_RULES",
    "RECOMMENDATION_SCOPE_AUTOMATION",
    "RECOMMENDATION_SCOPE_CASE",
    "RECOMMENDATION_SCOPE_DISPOSITION",
    "RECOMMENDATION_SCOPE_EXPORT_APPROVAL",
    "RECOMMENDATION_SCOPE_LEGAL_HOLD",
    "RECOMMENDATION_SCOPE_SNAPSHOT",
    "RECOMMENDATION_SEVERITY_VALUES",
    "RECOMMENDATION_STATUS_VALUES",
    "RECOMMENDATION_TRANSITIONS",
    "RISK_LEVEL_ORDER",
    "RULE_IDS",
    "RecommendationEventType",
    "RecommendationSeverity",
    "RecommendationStatus",
    "RiskFactor",
    "RiskLevel",
    "SLA_KIND_OPERATIONAL",
    "SLA_NON_CLAIM",
    "SLA_STATE_VALUES",
    "SLA_TARGET_KEYS",
    "SNAPSHOT_COMPARABLE_TYPES",
    "SNAPSHOT_TYPE_COMPLIANCE_SUMMARY",
    "SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY",
    "SNAPSHOT_VOLATILE_KEYS",
    "SlaState",
    "SlaTargetKey",
    "TREND_AUDIT_GROUPS",
    "TREND_BUCKETS",
    "TREND_SOURCE_ORDER",
    "audit_event_group",
    "default_risk_model",
    "ordered_factor_points",
    "recommendation_id",
    "recommendation_key",
    "risk_level_for",
    "risk_model_row_id",
    "sla_target_row_id",
    "validate_factor_points",
    "validate_sla_target",
    "validate_thresholds",
]
