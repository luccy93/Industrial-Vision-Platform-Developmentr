"""Stable V38 executive-governance vocabulary and bounded defaults.

Every executive KPI is derived from stored V10-V37 records. A missing source is
reported as ``UNAVAILABLE`` and is never converted to zero. The health model is
a deterministic, versioned aggregation of explicitly configured signals; it is
not a regulatory certification, a safety guarantee, or a statistical forecast.
"""

from __future__ import annotations

from datetime import timedelta
from enum import Enum
from typing import Any
from uuid import NAMESPACE_URL, uuid5

# ---------------------------------------------------------------------------
# Honest non-claims
# ---------------------------------------------------------------------------
EXECUTIVE_ASSURANCE = "DETERMINISTIC_LOCAL_EXECUTIVE_AGGREGATES_ONLY"
EXECUTIVE_NON_CLAIMS: tuple[str, ...] = (
    "Executive KPIs are derived from stored V10-V37 records; a missing or unreadable source "
    "is reported as unavailable, never as zero.",
    "Executive health is a deterministic local aggregate of explicitly configured signals. It "
    "is not a regulatory certification, safety guarantee, SLA warranty, or statistical forecast.",
    "Historical comparisons use stored snapshots only. V38 never recomputes or fabricates a past risk score.",
    "Strategic actions are internal governance tracking records. They never approve or release "
    "a legal hold, approve or reject a disposition, modify evidence, or execute a sensitive "
    "governance operation.",
    "Executive reports are local records with self-digests. They are not externally "
    "distributed, emailed, published, or anchored.",
    "An SLA ratio is a documented operational ratio of known items, not a blended governance "
    "compliance percentage.",
)
EXECUTIVE_LIMITATIONS: tuple[str, ...] = (
    "KPIs and health are computed on demand; V38 starts no executive scheduler and makes no "
    "autonomous decision.",
    "Health thresholds are fixed in EXEC_HEALTH_V1 so the same inputs always produce the same "
    "status and explanation.",
    "A partial source coverage lowers confidence explicitly; it is never silently averaged "
    "into a healthy score.",
    "Strategic actions are linked to V37 recommendations but do not resolve, dismiss, or "
    "acknowledge them automatically.",
    "Report generation is bounded and local; no email, PDF, external distribution, or "
    "third-party delivery path exists.",
)

# ---------------------------------------------------------------------------
# Health model
# ---------------------------------------------------------------------------
HEALTH_MODEL_VERSION = "EXEC_HEALTH_V1"

HEALTH_HEALTHY = "HEALTHY"
HEALTH_ATTENTION_REQUIRED = "ATTENTION_REQUIRED"
HEALTH_DEGRADED = "DEGRADED"
HEALTH_CRITICAL = "CRITICAL"
HEALTH_UNAVAILABLE = "UNAVAILABLE"

HEALTH_STATUS_VALUES: tuple[str, ...] = (
    HEALTH_HEALTHY,
    HEALTH_ATTENTION_REQUIRED,
    HEALTH_DEGRADED,
    HEALTH_CRITICAL,
    HEALTH_UNAVAILABLE,
)

#: Severity ordering only. ``UNAVAILABLE`` is a coverage outcome, not a
#: severity, and is handled separately.
HEALTH_STATUS_RANK: dict[str, int] = {
    HEALTH_HEALTHY: 0,
    HEALTH_ATTENTION_REQUIRED: 1,
    HEALTH_DEGRADED: 2,
    HEALTH_CRITICAL: 3,
}

COVERAGE_COMPLETE = "COMPLETE"
COVERAGE_PARTIAL = "PARTIAL"
COVERAGE_UNAVAILABLE = "UNAVAILABLE"
COVERAGE_STATUS_VALUES: tuple[str, ...] = (COVERAGE_COMPLETE, COVERAGE_PARTIAL, COVERAGE_UNAVAILABLE)

KPI_AVAILABLE = "AVAILABLE"
KPI_PARTIAL = "PARTIAL"
KPI_UNAVAILABLE = "UNAVAILABLE"
KPI_AVAILABILITY_VALUES: tuple[str, ...] = (KPI_AVAILABLE, KPI_PARTIAL, KPI_UNAVAILABLE)

COMPLETENESS_COMPLETE = "COMPLETE"
COMPLETENESS_PARTIAL = "PARTIAL"
COMPLETENESS_UNAVAILABLE = "UNAVAILABLE"
COMPLETENESS_VALUES: tuple[str, ...] = (
    COMPLETENESS_COMPLETE,
    COMPLETENESS_PARTIAL,
    COMPLETENESS_UNAVAILABLE,
)

#: Fixed, ordered health signals. Only the highest triggered severity contributes
#: to the overall status. A signal whose KPI is unavailable is not evaluated and
#: is reported as a coverage gap instead.
HEALTH_SIGNAL_RULES: tuple[dict[str, Any], ...] = (
    {
        "code": "CRITICAL_INTEGRITY_FINDINGS",
        "kpi_id": "INTEGRITY_CRITICAL_FINDINGS",
        "operator": "gte",
        "threshold": 1,
        "status": HEALTH_CRITICAL,
        "label": "Critical integrity findings in the latest audit run",
        "explanation": ("At least one CRITICAL finding is present in the latest V33 integrity audit run."),
    },
    {
        "code": "SLA_BREACHED_ITEMS",
        "kpi_id": "SLA_BREACHED_ITEMS",
        "operator": "gte",
        "threshold": 1,
        "status": HEALTH_DEGRADED,
        "label": "Operational SLA items breached or missed",
        "explanation": (
            "At least one known operational SLA item is BREACHED or MISSED. Operational SLAs "
            "are organization-defined and are not legal deadlines."
        ),
    },
    {
        "code": "CRITICAL_FORENSIC_CASES",
        "kpi_id": "FORENSIC_CRITICAL_CASES",
        "operator": "gte",
        "threshold": 1,
        "status": HEALTH_DEGRADED,
        "label": "Open critical forensic cases",
        "explanation": "At least one forensic case with CRITICAL severity is stored.",
    },
    {
        "code": "BLOCKING_LEGAL_HOLD_AGE",
        "kpi_id": "GOVERNANCE_OLDEST_BLOCKING_HOLD_AGE_HOURS",
        "operator": "gte",
        "threshold": 168,
        "status": HEALTH_DEGRADED,
        "label": "Oldest blocking legal hold",
        "explanation": ("A pending or active legal hold has remained blocking for at least 168 hours."),
    },
    {
        "code": "OVERDUE_GOVERNANCE_REVIEWS",
        "kpi_id": "GOVERNANCE_OVERDUE_REVIEWS",
        "operator": "gte",
        "threshold": 1,
        "status": HEALTH_ATTENTION_REQUIRED,
        "label": "Overdue retention reviews",
        "explanation": "At least one stored retention review is past its next-review time.",
    },
    {
        "code": "OPEN_CRITICAL_RECOMMENDATIONS",
        "kpi_id": "RECOMMENDATIONS_OPEN_CRITICAL",
        "operator": "gte",
        "threshold": 1,
        "status": HEALTH_ATTENTION_REQUIRED,
        "label": "Open critical recommendations",
        "explanation": "At least one OPEN or ACKNOWLEDGED CRITICAL recommendation is stored.",
    },
    {
        "code": "FAILED_AUTOMATION_JOBS",
        "kpi_id": "AUTOMATION_FAILED_JOBS",
        "operator": "gte",
        "threshold": 1,
        "status": HEALTH_ATTENTION_REQUIRED,
        "label": "Failed governance automation jobs",
        "explanation": "At least one governance automation job FAILED inside the KPI window.",
    },
    {
        "code": "STALE_AUTOMATION_JOBS",
        "kpi_id": "AUTOMATION_STALE_JOBS",
        "operator": "gte",
        "threshold": 1,
        "status": HEALTH_ATTENTION_REQUIRED,
        "label": "Stale governance automation jobs",
        "explanation": "At least one governance automation job is stale or lease-expired.",
    },
    {
        "code": "PENDING_EXPORT_APPROVALS",
        "kpi_id": "GOVERNANCE_PENDING_EXPORT_APPROVALS",
        "operator": "gte",
        "threshold": 1,
        "status": HEALTH_ATTENTION_REQUIRED,
        "label": "Pending export approvals",
        "explanation": "At least one governance export approval is PENDING_APPROVAL.",
    },
)

# ---------------------------------------------------------------------------
# KPI catalog
# ---------------------------------------------------------------------------
KPI_DEFINITIONS: dict[str, dict[str, Any]] = {
    "FORENSIC_OPEN_CASES": {
        "name": "Open forensic cases",
        "definition": ("Forensic cases whose stored status is neither RESOLVED nor CLOSED."),
        "source": "V34 forensic cases",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "FORENSIC_CRITICAL_CASES": {
        "name": "Critical forensic cases",
        "definition": "Forensic cases whose stored severity is CRITICAL.",
        "source": "V34 forensic cases",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "INTEGRITY_CRITICAL_FINDINGS": {
        "name": "Critical integrity findings",
        "definition": (
            "Findings with severity CRITICAL in the latest V33 integrity audit run. This is "
            "not a claim that every finding is a confirmed evidence failure."
        ),
        "source": "V33 integrity audit store",
        "unit": "count",
        "window_kind": "LATEST_AUDIT_RUN",
    },
    "GOVERNANCE_OVERDUE_REVIEWS": {
        "name": "Overdue retention reviews",
        "definition": (
            "Latest V35 retention evaluations whose stored next-review time is before the "
            "calculation time. Evaluations with an unknown next-review time are excluded from "
            "the numerator and reported as unknown."
        ),
        "source": "V35 retention evaluations",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "GOVERNANCE_RETENTION_DUE": {
        "name": "Retention deadlines reached",
        "definition": (
            "Latest V35 retention evaluations whose stored retention deadline is at or before "
            "the calculation time. Evaluations with an unknown deadline are reported as unknown."
        ),
        "source": "V35 retention evaluations",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "GOVERNANCE_BLOCKING_HOLDS": {
        "name": "Blocking legal holds",
        "definition": "V35 legal holds in PENDING_APPROVAL or ACTIVE state.",
        "source": "V35 legal holds",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "GOVERNANCE_OLDEST_BLOCKING_HOLD_AGE_HOURS": {
        "name": "Oldest blocking legal-hold age",
        "definition": (
            "Age in hours of the oldest PENDING_APPROVAL or ACTIVE legal hold. When no "
            "blocking hold exists the KPI is UNAVAILABLE, not zero."
        ),
        "source": "V35 legal holds",
        "unit": "hours",
        "window_kind": "CURRENT_STATE",
    },
    "GOVERNANCE_OPEN_DISPOSITIONS": {
        "name": "Open disposition reviews",
        "definition": "V35 disposition requests in REVIEW_REQUIRED or APPROVAL_PENDING state.",
        "source": "V35 disposition requests",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "GOVERNANCE_PENDING_EXPORT_APPROVALS": {
        "name": "Pending export approvals",
        "definition": "V35 export approvals in PENDING_APPROVAL state.",
        "source": "V35 export approvals",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "AUTOMATION_FAILED_JOBS": {
        "name": "Failed automation jobs",
        "definition": (
            "V36 governance automation jobs whose stored status is FAILED and whose finish "
            "time falls inside the KPI window."
        ),
        "source": "V36 governance automation jobs",
        "unit": "count",
        "window_kind": "ROLLING_WINDOW",
    },
    "AUTOMATION_STALE_JOBS": {
        "name": "Stale automation jobs",
        "definition": (
            "V36 governance automation jobs whose lease has expired or that have remained "
            "PENDING or RUNNING beyond the stale threshold."
        ),
        "source": "V36 governance automation jobs",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "RECOMMENDATIONS_OPEN": {
        "name": "Open recommendations",
        "definition": "V37 recommendations in OPEN or ACKNOWLEDGED state.",
        "source": "V37 governance recommendations",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "RECOMMENDATIONS_OPEN_CRITICAL": {
        "name": "Open critical recommendations",
        "definition": ("V37 recommendations in OPEN or ACKNOWLEDGED state whose severity is CRITICAL."),
        "source": "V37 governance recommendations",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "SLA_BREACHED_ITEMS": {
        "name": "Breached or missed SLA items",
        "definition": (
            "Known V37 operational SLA items in BREACHED or MISSED state. Items whose source "
            "is unavailable or whose state is UNKNOWN are excluded from the value and reported "
            "as coverage gaps."
        ),
        "source": "V37 operational SLA backlog",
        "unit": "count",
        "window_kind": "CURRENT_STATE",
    },
    "SLA_COMPLIANCE_RATIO": {
        "name": "Operational SLA compliance ratio",
        "definition": (
            "Documented operational ratio: (WITHIN_TARGET + AT_RISK) / (WITHIN_TARGET + "
            "AT_RISK + BREACHED + MISSED). UNKNOWN and NOT_APPLICABLE items are excluded. "
            "This is not a blended governance compliance percentage."
        ),
        "source": "V37 operational SLA backlog",
        "unit": "ratio",
        "window_kind": "CURRENT_STATE",
    },
}

KPI_ORDER: tuple[str, ...] = tuple(KPI_DEFINITIONS)
KPI_COUNT = len(KPI_ORDER)

# ---------------------------------------------------------------------------
# Windows and bounds
# ---------------------------------------------------------------------------
DEFAULT_WINDOW_DAYS = 30
MIN_WINDOW_DAYS = 1
MAX_WINDOW_DAYS = 90
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 20
MAX_ACTIONS = 2000
MAX_KPI_DETAIL_ITEMS = 100
MAX_SOURCE_ITEMS = 500

#: UTC rolling window used by windowed KPIs. Kept as a timedelta so callers can
#: derive explicit UTC boundaries without local-time arithmetic.
KPI_WINDOW = timedelta(days=DEFAULT_WINDOW_DAYS)


# ---------------------------------------------------------------------------
# Strategic actions
# ---------------------------------------------------------------------------
class ActionStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


ACTION_STATUS_VALUES: tuple[str, ...] = tuple(item.value for item in ActionStatus)

ACTION_TRANSITIONS: dict[str, frozenset[str]] = {
    ActionStatus.OPEN.value: frozenset(
        {
            ActionStatus.IN_PROGRESS.value,
            ActionStatus.BLOCKED.value,
            ActionStatus.COMPLETED.value,
            ActionStatus.CANCELLED.value,
        }
    ),
    ActionStatus.IN_PROGRESS.value: frozenset(
        {
            ActionStatus.BLOCKED.value,
            ActionStatus.COMPLETED.value,
            ActionStatus.CANCELLED.value,
        }
    ),
    ActionStatus.BLOCKED.value: frozenset(
        {
            ActionStatus.IN_PROGRESS.value,
            ActionStatus.CANCELLED.value,
        }
    ),
    ActionStatus.COMPLETED.value: frozenset(),
    ActionStatus.CANCELLED.value: frozenset(),
}

ACTION_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {ActionStatus.COMPLETED.value, ActionStatus.CANCELLED.value}
)
ACTION_OPEN_STATUSES: frozenset[str] = frozenset(
    {ActionStatus.OPEN.value, ActionStatus.IN_PROGRESS.value, ActionStatus.BLOCKED.value}
)

#: V37 recommendation statuses from which a strategic action may be created.
ACTIONABLE_RECOMMENDATION_STATUSES: frozenset[str] = frozenset({"OPEN", "ACKNOWLEDGED"})

#: Non-actionable recommendation statuses are rejected with a stable 409 code.
NON_ACTIONABLE_RECOMMENDATION_STATUSES: frozenset[str] = frozenset({"DISMISSED", "RESOLVED"})


class ActionEventType(str, Enum):
    CREATED = "CREATED"
    ASSIGNED = "ASSIGNED"
    TRANSITIONED = "TRANSITIONED"


ACTION_EVENT_VALUES: tuple[str, ...] = tuple(item.value for item in ActionEventType)

ACTION_ID_NAMESPACE = "urn:ivp:governance-executive:action"
MAX_ACTION_TITLE_LENGTH = 200
MAX_ACTION_DESCRIPTION_LENGTH = 4000
MAX_ACTION_REASON_LENGTH = 2048
MAX_ACTION_OUTCOME_LENGTH = 4000
MAX_ACTION_OWNER_LENGTH = 256
MAX_ACTION_EVENTS = 200
MAX_ACTION_DUE_DAYS = 3650
MIN_ACTION_REASON_LENGTH = 3
MIN_ACTION_OUTCOME_LENGTH = 3
MIN_ACTION_BLOCK_REASON_LENGTH = 3
MIN_ACTION_CANCEL_REASON_LENGTH = 3


# ---------------------------------------------------------------------------
# Executive reports
# ---------------------------------------------------------------------------
class ReportType(str, Enum):
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"
    EXECUTIVE_RISK = "EXECUTIVE_RISK"
    EXECUTIVE_SLA = "EXECUTIVE_SLA"
    EXECUTIVE_OPERATIONS = "EXECUTIVE_OPERATIONS"


REPORT_TYPE_VALUES: tuple[str, ...] = tuple(item.value for item in ReportType)


class ReportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"


REPORT_FORMAT_VALUES: tuple[str, ...] = tuple(item.value for item in ReportFormat)

REPORT_SCHEMA_VERSION = 1
EXECUTIVE_CONFIG_SCHEMA_VERSION = 1
EXECUTIVE_CONFIG_SNAPSHOT_TYPE = "EXECUTIVE_CONFIG"
REPORT_SNAPSHOT_TYPE_BY_REPORT: dict[str, str] = {
    ReportType.EXECUTIVE_SUMMARY.value: "EXECUTIVE_SUMMARY",
    ReportType.EXECUTIVE_RISK.value: "EXECUTIVE_RISK",
    ReportType.EXECUTIVE_SLA.value: "EXECUTIVE_SLA",
    ReportType.EXECUTIVE_OPERATIONS.value: "EXECUTIVE_OPERATIONS",
}
REPORT_SNAPSHOT_TYPES: frozenset[str] = frozenset(REPORT_SNAPSHOT_TYPE_BY_REPORT.values())
MAX_REPORT_ROWS = 5000
MAX_REPORT_PAYLOAD_BYTES = 512 * 1024
MAX_REPORT_CSV_BYTES = 1024 * 1024
MAX_REPORT_IDEMPOTENCY_KEY_LENGTH = 128
MAX_REPORT_REASON_LENGTH = 2048
MIN_REPORT_REASON_LENGTH = 3
MAX_REPORT_SECTIONS = 16

#: Report sections that are explicitly marked unavailable when their source
#: cannot be read. No section is silently omitted.
REPORT_SECTION_ORDER: tuple[str, ...] = (
    "executive_health",
    "kpis",
    "risk",
    "sla",
    "operations",
    "actions",
    "source_coverage",
    "assurance",
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
DEFAULT_EXECUTIVE_CONFIG: dict[str, Any] = {
    "default_window_days": DEFAULT_WINDOW_DAYS,
    "comparison_period_days": DEFAULT_WINDOW_DAYS,
    "action_due_soon_hours": 72,
    "report_max_rows": 500,
    "include_recommendations_in_summary": True,
    "health_thresholds_fixed": True,
}

EXECUTIVE_CONFIG_KEYS: frozenset[str] = frozenset(DEFAULT_EXECUTIVE_CONFIG)
MIN_ACTION_DUE_SOON_HOURS = 1
MAX_ACTION_DUE_SOON_HOURS = 720
MIN_REPORT_MAX_ROWS = 50
MAX_REPORT_MAX_ROWS = 5000
MIN_COMPARISON_PERIOD_DAYS = 1
MAX_COMPARISON_PERIOD_DAYS = 90

# ---------------------------------------------------------------------------
# Historical comparison
# ---------------------------------------------------------------------------
COMPARISON_COMPATIBILITY_VERSION = "EXEC_COMPARE_V1"
MAX_COMPARISON_DIFF_ITEMS = 200
COMPARISON_COMPARABLE = "COMPARABLE"
COMPARISON_INCOMPATIBLE = "INCOMPATIBLE"
COMPARISON_UNAVAILABLE = "UNAVAILABLE"
COMPARISON_STATUS_VALUES: tuple[str, ...] = (
    COMPARISON_COMPARABLE,
    COMPARISON_INCOMPATIBLE,
    COMPARISON_UNAVAILABLE,
)

# ---------------------------------------------------------------------------
# Bounded metric labels
# ---------------------------------------------------------------------------
EXECUTIVE_HEALTH_METRIC_STATUSES: frozenset[str] = frozenset(HEALTH_STATUS_VALUES)
EXECUTIVE_KPI_AVAILABILITY_METRIC_VALUES: frozenset[str] = frozenset(KPI_AVAILABILITY_VALUES)
EXECUTIVE_ACTION_STATUS_METRIC_VALUES: frozenset[str] = frozenset(ACTION_STATUS_VALUES)
EXECUTIVE_REPORT_TYPE_METRIC_VALUES: frozenset[str] = frozenset(REPORT_TYPE_VALUES)
EXECUTIVE_REPORT_FORMAT_METRIC_VALUES: frozenset[str] = frozenset(REPORT_FORMAT_VALUES)


def action_id_for(idempotency_key: str) -> str:
    """Deterministic action identifier derived from the idempotency key."""
    key = str(idempotency_key or "").strip()
    return str(uuid5(NAMESPACE_URL, f"{ACTION_ID_NAMESPACE}:{key}"))


def report_dedup_key(report_type: str, idempotency_key: str) -> str:
    """Bounded deterministic deduplication key for an executive report."""
    return f"executive:{str(report_type).upper()}:{str(idempotency_key).strip()}"[:200]


__all__ = [
    "ACTIONABLE_RECOMMENDATION_STATUSES",
    "ACTION_EVENT_VALUES",
    "ACTION_ID_NAMESPACE",
    "ACTION_OPEN_STATUSES",
    "ACTION_STATUS_VALUES",
    "ACTION_TERMINAL_STATUSES",
    "ACTION_TRANSITIONS",
    "ActionEventType",
    "ActionStatus",
    "COMPARISON_COMPARABLE",
    "COMPARISON_COMPATIBILITY_VERSION",
    "COMPARISON_INCOMPATIBLE",
    "COMPARISON_STATUS_VALUES",
    "COMPARISON_UNAVAILABLE",
    "COMPLETENESS_COMPLETE",
    "COMPLETENESS_PARTIAL",
    "COMPLETENESS_UNAVAILABLE",
    "COMPLETENESS_VALUES",
    "COVERAGE_COMPLETE",
    "COVERAGE_PARTIAL",
    "COVERAGE_STATUS_VALUES",
    "COVERAGE_UNAVAILABLE",
    "DEFAULT_EXECUTIVE_CONFIG",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_WINDOW_DAYS",
    "EXECUTIVE_ASSURANCE",
    "EXECUTIVE_CONFIG_KEYS",
    "EXECUTIVE_CONFIG_SCHEMA_VERSION",
    "EXECUTIVE_CONFIG_SNAPSHOT_TYPE",
    "EXECUTIVE_LIMITATIONS",
    "EXECUTIVE_NON_CLAIMS",
    "HEALTH_ATTENTION_REQUIRED",
    "HEALTH_CRITICAL",
    "HEALTH_DEGRADED",
    "HEALTH_HEALTHY",
    "HEALTH_MODEL_VERSION",
    "HEALTH_SIGNAL_RULES",
    "HEALTH_STATUS_RANK",
    "HEALTH_STATUS_VALUES",
    "HEALTH_UNAVAILABLE",
    "KPI_AVAILABLE",
    "KPI_AVAILABILITY_VALUES",
    "KPI_COUNT",
    "KPI_DEFINITIONS",
    "KPI_ORDER",
    "KPI_PARTIAL",
    "KPI_UNAVAILABLE",
    "KPI_WINDOW",
    "MAX_ACTION_DESCRIPTION_LENGTH",
    "MAX_ACTION_DUE_DAYS",
    "MAX_ACTION_EVENTS",
    "MAX_ACTION_OUTCOME_LENGTH",
    "MAX_ACTION_OWNER_LENGTH",
    "MAX_ACTION_REASON_LENGTH",
    "MAX_ACTION_TITLE_LENGTH",
    "MAX_ACTIONS",
    "MAX_COMPARISON_DIFF_ITEMS",
    "MAX_COMPARISON_PERIOD_DAYS",
    "MAX_KPI_DETAIL_ITEMS",
    "MAX_PAGE_SIZE",
    "MAX_REPORT_CSV_BYTES",
    "MAX_REPORT_IDEMPOTENCY_KEY_LENGTH",
    "MAX_REPORT_PAYLOAD_BYTES",
    "MAX_REPORT_REASON_LENGTH",
    "MAX_REPORT_ROWS",
    "MAX_REPORT_SECTIONS",
    "MAX_SOURCE_ITEMS",
    "MAX_WINDOW_DAYS",
    "MIN_ACTION_BLOCK_REASON_LENGTH",
    "MIN_ACTION_CANCEL_REASON_LENGTH",
    "MIN_ACTION_OUTCOME_LENGTH",
    "MIN_ACTION_REASON_LENGTH",
    "MIN_REPORT_REASON_LENGTH",
    "MIN_WINDOW_DAYS",
    "NON_ACTIONABLE_RECOMMENDATION_STATUSES",
    "REPORT_FORMAT_VALUES",
    "REPORT_SCHEMA_VERSION",
    "REPORT_SECTION_ORDER",
    "REPORT_SNAPSHOT_TYPES",
    "REPORT_SNAPSHOT_TYPE_BY_REPORT",
    "REPORT_TYPE_VALUES",
    "ReportFormat",
    "ReportType",
    "action_id_for",
    "report_dedup_key",
]
