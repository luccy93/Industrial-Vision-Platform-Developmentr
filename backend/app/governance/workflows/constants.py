"""Stable V39 enterprise workflow vocabulary and bounded defaults.

Workflows are deterministic local orchestration records over existing V34-V38
domains. They never approve or release a hold, approve or reject a disposition,
delete or modify evidence, generate an export, alter custody, resolve a
recommendation, or complete a V38 executive action. Human authorization remains
authoritative for every source-domain operation.
"""

from __future__ import annotations

from enum import Enum
from uuid import NAMESPACE_URL, uuid5

# ---------------------------------------------------------------------------
# Honest non-claims
# ---------------------------------------------------------------------------
WORKFLOW_ASSURANCE = "DETERMINISTIC_LOCAL_WORKFLOW_ORCHESTRATION_ONLY"
WORKFLOW_NON_CLAIMS: tuple[str, ...] = (
    "Workflow instances are internal orchestration records. They never approve or release a "
    "legal hold, approve or reject a disposition, delete or modify evidence, approve or generate "
    "an export, alter custody, resolve a recommendation, or complete an executive action.",
    "Cross-domain references are read-only pointers. V39 never copies source payloads, fabricates "
    "source data, or mutates a source record.",
    "An SLA state is a deterministic operational indicator, not a legal deadline, regulatory "
    "certification, or safety guarantee.",
    "Escalations are review prompts. Delivery is queued through the existing V15 pipeline and is "
    "never claimed delivered by V39.",
    "Workflow completion requires mandatory task completion and an outcome summary. It is not an "
    "approval of any source-domain decision.",
)
WORKFLOW_LIMITATIONS: tuple[str, ...] = (
    "Dependency evaluation is deterministic and bounded; no autonomous task completion or approval occurs.",
    "V39 starts no scheduler and creates no second worker. SLA and escalation state are computed "
    "on demand or on explicit user action.",
    "Missing due dates, missing owners, and unreadable source domains are reported explicitly and "
    "are never treated as zero time or as a healthy state.",
    "Terminal workflows and tasks are final. V39 exposes no reopen route.",
    "No live PostgreSQL, Redis, Docker, SMTP, webhook, or external-service validation is implied by "
    "local deterministic tests.",
)


# ---------------------------------------------------------------------------
# Workflow lifecycle
# ---------------------------------------------------------------------------
class WorkflowStatus(str, Enum):
    DRAFT = "DRAFT"
    READY = "READY"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    UNDER_REVIEW = "UNDER_REVIEW"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


WORKFLOW_STATUS_VALUES: tuple[str, ...] = tuple(item.value for item in WorkflowStatus)

WORKFLOW_TRANSITIONS: dict[str, frozenset[str]] = {
    WorkflowStatus.DRAFT.value: frozenset({WorkflowStatus.READY.value, WorkflowStatus.CANCELLED.value}),
    WorkflowStatus.READY.value: frozenset({WorkflowStatus.IN_PROGRESS.value, WorkflowStatus.CANCELLED.value}),
    WorkflowStatus.IN_PROGRESS.value: frozenset(
        {
            WorkflowStatus.BLOCKED.value,
            WorkflowStatus.UNDER_REVIEW.value,
            WorkflowStatus.CANCELLED.value,
        }
    ),
    WorkflowStatus.BLOCKED.value: frozenset(
        {WorkflowStatus.IN_PROGRESS.value, WorkflowStatus.CANCELLED.value}
    ),
    WorkflowStatus.UNDER_REVIEW.value: frozenset(
        {
            WorkflowStatus.COMPLETED.value,
            WorkflowStatus.IN_PROGRESS.value,
            WorkflowStatus.CANCELLED.value,
        }
    ),
    WorkflowStatus.COMPLETED.value: frozenset(),
    WorkflowStatus.CANCELLED.value: frozenset(),
}

WORKFLOW_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {WorkflowStatus.COMPLETED.value, WorkflowStatus.CANCELLED.value}
)
WORKFLOW_OPEN_STATUSES: frozenset[str] = frozenset(
    {
        WorkflowStatus.DRAFT.value,
        WorkflowStatus.READY.value,
        WorkflowStatus.IN_PROGRESS.value,
        WorkflowStatus.BLOCKED.value,
        WorkflowStatus.UNDER_REVIEW.value,
    }
)
WORKFLOW_ACTIVE_STATUSES: frozenset[str] = frozenset(
    {WorkflowStatus.READY.value, WorkflowStatus.IN_PROGRESS.value, WorkflowStatus.BLOCKED.value}
)


# ---------------------------------------------------------------------------
# Task lifecycle
# ---------------------------------------------------------------------------
class TaskStatus(str, Enum):
    PENDING = "PENDING"
    READY = "READY"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"


TASK_STATUS_VALUES: tuple[str, ...] = tuple(item.value for item in TaskStatus)

TASK_TRANSITIONS: dict[str, frozenset[str]] = {
    TaskStatus.PENDING.value: frozenset({TaskStatus.READY.value, TaskStatus.CANCELLED.value}),
    TaskStatus.READY.value: frozenset({TaskStatus.IN_PROGRESS.value, TaskStatus.CANCELLED.value}),
    TaskStatus.IN_PROGRESS.value: frozenset(
        {
            TaskStatus.BLOCKED.value,
            TaskStatus.COMPLETED.value,
            TaskStatus.CANCELLED.value,
        }
    ),
    TaskStatus.BLOCKED.value: frozenset({TaskStatus.IN_PROGRESS.value, TaskStatus.CANCELLED.value}),
    TaskStatus.COMPLETED.value: frozenset(),
    TaskStatus.CANCELLED.value: frozenset(),
}

TASK_TERMINAL_STATUSES: frozenset[str] = frozenset({TaskStatus.COMPLETED.value, TaskStatus.CANCELLED.value})
TASK_OPEN_STATUSES: frozenset[str] = frozenset(
    {
        TaskStatus.PENDING.value,
        TaskStatus.READY.value,
        TaskStatus.IN_PROGRESS.value,
        TaskStatus.BLOCKED.value,
    }
)


# ---------------------------------------------------------------------------
# Templates
# ---------------------------------------------------------------------------
class TemplateStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUPERSEDED = "SUPERSEDED"
    DISABLED = "DISABLED"


TEMPLATE_STATUS_VALUES: tuple[str, ...] = tuple(item.value for item in TemplateStatus)
TEMPLATE_ACTIVE_STATUSES: frozenset[str] = frozenset({TemplateStatus.ACTIVE.value})
TEMPLATE_TERMINAL_STATUSES: frozenset[str] = frozenset({TemplateStatus.DISABLED.value})


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------
class WorkflowEventType(str, Enum):
    WORKFLOW_CREATED = "WORKFLOW_CREATED"
    WORKFLOW_READY = "WORKFLOW_READY"
    WORKFLOW_STARTED = "WORKFLOW_STARTED"
    WORKFLOW_ASSIGNED = "WORKFLOW_ASSIGNED"
    WORKFLOW_REASSIGNED = "WORKFLOW_REASSIGNED"
    WORKFLOW_BLOCKED = "WORKFLOW_BLOCKED"
    WORKFLOW_UNBLOCKED = "WORKFLOW_UNBLOCKED"
    WORKFLOW_UNDER_REVIEW = "WORKFLOW_UNDER_REVIEW"
    WORKFLOW_COMPLETED = "WORKFLOW_COMPLETED"
    WORKFLOW_CANCELLED = "WORKFLOW_CANCELLED"
    WORKFLOW_REFERENCE_ADDED = "WORKFLOW_REFERENCE_ADDED"
    TASK_CREATED = "TASK_CREATED"
    TASK_ASSIGNED = "TASK_ASSIGNED"
    TASK_STARTED = "TASK_STARTED"
    TASK_BLOCKED = "TASK_BLOCKED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_CANCELLED = "TASK_CANCELLED"
    DEPENDENCY_SATISFIED = "DEPENDENCY_SATISFIED"
    ESCALATION_CREATED = "ESCALATION_CREATED"
    ESCALATION_ACKNOWLEDGED = "ESCALATION_ACKNOWLEDGED"
    ESCALATION_RESOLVED = "ESCALATION_RESOLVED"
    TEMPLATE_CREATED = "TEMPLATE_CREATED"
    TEMPLATE_UPDATED = "TEMPLATE_UPDATED"
    TEMPLATE_DISABLED = "TEMPLATE_DISABLED"


WORKFLOW_EVENT_VALUES: tuple[str, ...] = tuple(item.value for item in WorkflowEventType)

#: Required V39 event contract. Tests assert this exact minimum set is present.
REQUIRED_WORKFLOW_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "WORKFLOW_CREATED",
        "WORKFLOW_STARTED",
        "WORKFLOW_ASSIGNED",
        "WORKFLOW_REASSIGNED",
        "WORKFLOW_BLOCKED",
        "WORKFLOW_UNBLOCKED",
        "WORKFLOW_COMPLETED",
        "WORKFLOW_CANCELLED",
        "TASK_CREATED",
        "TASK_ASSIGNED",
        "TASK_STARTED",
        "TASK_BLOCKED",
        "TASK_COMPLETED",
        "TASK_CANCELLED",
        "DEPENDENCY_SATISFIED",
        "ESCALATION_CREATED",
        "ESCALATION_ACKNOWLEDGED",
        "ESCALATION_RESOLVED",
        "TEMPLATE_CREATED",
        "TEMPLATE_UPDATED",
        "TEMPLATE_DISABLED",
    }
)


# ---------------------------------------------------------------------------
# Cross-domain references
# ---------------------------------------------------------------------------
class ReferenceDomain(str, Enum):
    FORENSIC_CASE = "FORENSIC_CASE"
    FORENSIC_FINDING = "FORENSIC_FINDING"
    RETENTION_REVIEW = "RETENTION_REVIEW"
    LEGAL_HOLD = "LEGAL_HOLD"
    DISPOSITION = "DISPOSITION"
    EXPORT_APPROVAL = "EXPORT_APPROVAL"
    AUTOMATION_JOB = "AUTOMATION_JOB"
    RECOMMENDATION = "RECOMMENDATION"
    EXECUTIVE_ACTION = "EXECUTIVE_ACTION"


REFERENCE_DOMAIN_VALUES: tuple[str, ...] = tuple(item.value for item in ReferenceDomain)

#: Existing source-read capability required to attach or view a reference. V39
#: never elevates a caller beyond the source domain's own read policy.
REFERENCE_DOMAIN_CAPABILITY: dict[str, str] = {
    ReferenceDomain.FORENSIC_CASE.value: "read",
    ReferenceDomain.FORENSIC_FINDING.value: "read",
    ReferenceDomain.RETENTION_REVIEW.value: "governance_read",
    ReferenceDomain.LEGAL_HOLD.value: "governance_read",
    ReferenceDomain.DISPOSITION.value: "governance_read",
    ReferenceDomain.EXPORT_APPROVAL.value: "governance_read",
    ReferenceDomain.AUTOMATION_JOB.value: "governance_automation_read",
    ReferenceDomain.RECOMMENDATION.value: "governance_recommendations_read",
    ReferenceDomain.EXECUTIVE_ACTION.value: "governance_executive_action_read",
}

#: Domains whose records are always case-scoped.
CASE_SCOPED_REFERENCE_DOMAINS: frozenset[str] = frozenset(
    {
        ReferenceDomain.FORENSIC_CASE.value,
        ReferenceDomain.FORENSIC_FINDING.value,
        ReferenceDomain.RETENTION_REVIEW.value,
        ReferenceDomain.LEGAL_HOLD.value,
        ReferenceDomain.DISPOSITION.value,
        ReferenceDomain.EXPORT_APPROVAL.value,
    }
)


class ReferenceAvailability(str, Enum):
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    UNAVAILABLE = "UNAVAILABLE"
    UNAUTHORIZED = "UNAUTHORIZED"
    DELETED = "DELETED"


REFERENCE_AVAILABILITY_VALUES: tuple[str, ...] = tuple(item.value for item in ReferenceAvailability)


# ---------------------------------------------------------------------------
# SLA
# ---------------------------------------------------------------------------
class WorkflowSlaState(str, Enum):
    ON_TRACK = "ON_TRACK"
    AT_RISK = "AT_RISK"
    OVERDUE = "OVERDUE"
    PAUSED = "PAUSED"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"


WORKFLOW_SLA_STATE_VALUES: tuple[str, ...] = tuple(item.value for item in WorkflowSlaState)

#: Explicit mapping from the reusable V37 operational SLA states. V37 remains
#: the calculation engine; V39 only maps its vocabulary into workflow states.
V37_SLA_STATE_TO_WORKFLOW: dict[str, str] = {
    "WITHIN_TARGET": WorkflowSlaState.ON_TRACK.value,
    "AT_RISK": WorkflowSlaState.AT_RISK.value,
    "BREACHED": WorkflowSlaState.OVERDUE.value,
    "MET": WorkflowSlaState.ON_TRACK.value,
    "MISSED": WorkflowSlaState.OVERDUE.value,
    "UNKNOWN": WorkflowSlaState.UNAVAILABLE.value,
    "NOT_APPLICABLE": WorkflowSlaState.NOT_APPLICABLE.value,
}

SLA_TARGET_KEY_WORKFLOW = "WORKFLOW_ITEM"
SLA_NON_CLAIM = "This is an organization-configurable operational SLA, not a legal or regulatory deadline."


# ---------------------------------------------------------------------------
# Ownership
# ---------------------------------------------------------------------------
class OwnerType(str, Enum):
    USER = "USER"
    ROLE = "ROLE"


OWNER_TYPE_VALUES: tuple[str, ...] = tuple(item.value for item in OwnerType)


# ---------------------------------------------------------------------------
# Escalations
# ---------------------------------------------------------------------------
class EscalationType(str, Enum):
    SLA_OVERDUE = "SLA_OVERDUE"
    SLA_AT_RISK = "SLA_AT_RISK"
    BLOCKED = "BLOCKED"
    UNASSIGNED = "UNASSIGNED"
    MANUAL = "MANUAL"


ESCALATION_TYPE_VALUES: tuple[str, ...] = tuple(item.value for item in EscalationType)


class EscalationStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"


ESCALATION_STATUS_VALUES: tuple[str, ...] = tuple(item.value for item in EscalationStatus)

ESCALATION_TRANSITIONS: dict[str, frozenset[str]] = {
    EscalationStatus.OPEN.value: frozenset(
        {EscalationStatus.ACKNOWLEDGED.value, EscalationStatus.RESOLVED.value}
    ),
    EscalationStatus.ACKNOWLEDGED.value: frozenset({EscalationStatus.RESOLVED.value}),
    EscalationStatus.RESOLVED.value: frozenset(),
}

ESCALATION_OPEN_STATUSES: frozenset[str] = frozenset(
    {EscalationStatus.OPEN.value, EscalationStatus.ACKNOWLEDGED.value}
)
ESCALATION_SEVERITY_VALUES: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")


# ---------------------------------------------------------------------------
# Bounds
# ---------------------------------------------------------------------------
DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100
MAX_TEMPLATE_TASKS = 50
MAX_TEMPLATE_DEPENDENCIES = 200
MAX_TASKS_PER_WORKFLOW = 50
MAX_REFERENCES_PER_WORKFLOW = 100
MAX_ESCALATIONS_PER_WORKFLOW = 200
MAX_EVENTS_PER_READ = 500
MAX_WORKFLOWS_PER_STATUS_SAMPLE = 500
MAX_WORKFLOW_TITLE_LENGTH = 200
MAX_WORKFLOW_DESCRIPTION_LENGTH = 4000
MAX_WORKFLOW_REASON_LENGTH = 2048
MAX_WORKFLOW_OUTCOME_LENGTH = 4000
MAX_WORKFLOW_KEY_LENGTH = 64
MAX_WORKFLOW_OWNER_LENGTH = 256
MAX_WORKFLOW_IDEMPOTENCY_LENGTH = 128
MAX_REFERENCE_KEY_LENGTH = 160
MAX_REFERENCE_SOURCE_ID_LENGTH = 128
MAX_REFERENCE_LABEL_LENGTH = 200
MAX_TEMPLATE_DEFINITION_BYTES = 64 * 1024
MAX_DUE_DAYS = 3650
MIN_REASON_LENGTH = 3
MIN_TITLE_LENGTH = 3
MIN_OUTCOME_LENGTH = 3
DEFAULT_ESCALATION_SEVERITY = "MEDIUM"
DEFAULT_SLA_WARNING_HOURS = 24

WORKFLOW_PRIORITY_VALUES: tuple[str, ...] = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

WORKFLOW_ID_NAMESPACE = "urn:ivp:governance-workflow"
TEMPLATE_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"
TASK_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$"


# ---------------------------------------------------------------------------
# Bounded metric labels
# ---------------------------------------------------------------------------
WORKFLOW_STATUS_METRIC_VALUES: frozenset[str] = frozenset(WORKFLOW_STATUS_VALUES)
TASK_STATUS_METRIC_VALUES: frozenset[str] = frozenset(TASK_STATUS_VALUES)
WORKFLOW_SLA_METRIC_VALUES: frozenset[str] = frozenset(WORKFLOW_SLA_STATE_VALUES)
ESCALATION_TYPE_METRIC_VALUES: frozenset[str] = frozenset(ESCALATION_TYPE_VALUES)
ESCALATION_STATUS_METRIC_VALUES: frozenset[str] = frozenset(ESCALATION_STATUS_VALUES)
WORKFLOW_TRANSITION_OUTCOME_VALUES: frozenset[str] = frozenset({"APPLIED", "REJECTED", "CONFLICT"})
WORKFLOW_CREATION_OUTCOME_VALUES: frozenset[str] = frozenset({"CREATED", "REPLAYED", "REJECTED"})
WORKFLOW_DEPENDENCY_OUTCOME_VALUES: frozenset[str] = frozenset({"SATISFIED", "BLOCKED", "PENDING", "INVALID"})
WORKFLOW_OPERATION_VALUES: frozenset[str] = frozenset(
    {
        "status",
        "create_workflow",
        "transition_workflow",
        "assign_workflow",
        "transition_task",
        "assign_task",
        "add_reference",
        "create_escalation",
        "acknowledge_escalation",
        "resolve_escalation",
        "create_template",
        "disable_template",
    }
)


def workflow_id_for(idempotency_key: str) -> str:
    """Deterministic workflow identifier derived from the idempotency key."""
    key = str(idempotency_key or "").strip()
    return str(uuid5(NAMESPACE_URL, f"{WORKFLOW_ID_NAMESPACE}:workflow:{key}"))


def escalation_id_for(idempotency_key: str) -> str:
    """Deterministic escalation identifier derived from the idempotency key."""
    key = str(idempotency_key or "").strip()
    return str(uuid5(NAMESPACE_URL, f"{WORKFLOW_ID_NAMESPACE}:escalation:{key}"))


def template_id_for(template_key: str, version: int) -> str:
    """Deterministic template identifier derived from key and version."""
    key = str(template_key or "").strip().upper()
    return str(uuid5(NAMESPACE_URL, f"{WORKFLOW_ID_NAMESPACE}:template:{key}:{int(version)}"))


__all__ = [
    "CASE_SCOPED_REFERENCE_DOMAINS",
    "DEFAULT_ESCALATION_SEVERITY",
    "DEFAULT_PAGE_SIZE",
    "DEFAULT_SLA_WARNING_HOURS",
    "ESCALATION_OPEN_STATUSES",
    "ESCALATION_SEVERITY_VALUES",
    "ESCALATION_STATUS_VALUES",
    "ESCALATION_TRANSITIONS",
    "ESCALATION_TYPE_VALUES",
    "EscalationStatus",
    "EscalationType",
    "MAX_DUE_DAYS",
    "MAX_ESCALATIONS_PER_WORKFLOW",
    "MAX_EVENTS_PER_READ",
    "MAX_PAGE_SIZE",
    "MAX_REFERENCE_KEY_LENGTH",
    "MAX_REFERENCE_LABEL_LENGTH",
    "MAX_REFERENCE_SOURCE_ID_LENGTH",
    "MAX_REFERENCES_PER_WORKFLOW",
    "MAX_TASKS_PER_WORKFLOW",
    "MAX_TEMPLATE_DEFINITION_BYTES",
    "MAX_TEMPLATE_DEPENDENCIES",
    "MAX_TEMPLATE_TASKS",
    "MAX_WORKFLOWS_PER_STATUS_SAMPLE",
    "MAX_WORKFLOW_DESCRIPTION_LENGTH",
    "MAX_WORKFLOW_IDEMPOTENCY_LENGTH",
    "MAX_WORKFLOW_KEY_LENGTH",
    "MAX_WORKFLOW_OUTCOME_LENGTH",
    "MAX_WORKFLOW_OWNER_LENGTH",
    "MAX_WORKFLOW_REASON_LENGTH",
    "MAX_WORKFLOW_TITLE_LENGTH",
    "MIN_OUTCOME_LENGTH",
    "MIN_REASON_LENGTH",
    "MIN_TITLE_LENGTH",
    "OWNER_TYPE_VALUES",
    "OwnerType",
    "REFERENCE_AVAILABILITY_VALUES",
    "REFERENCE_DOMAIN_CAPABILITY",
    "REFERENCE_DOMAIN_VALUES",
    "REQUIRED_WORKFLOW_EVENT_TYPES",
    "ReferenceAvailability",
    "ReferenceDomain",
    "SLA_NON_CLAIM",
    "SLA_TARGET_KEY_WORKFLOW",
    "TASK_KEY_PATTERN",
    "TASK_OPEN_STATUSES",
    "TASK_STATUS_METRIC_VALUES",
    "TASK_STATUS_VALUES",
    "TASK_TERMINAL_STATUSES",
    "TASK_TRANSITIONS",
    "TEMPLATE_ACTIVE_STATUSES",
    "TEMPLATE_KEY_PATTERN",
    "TEMPLATE_STATUS_VALUES",
    "TEMPLATE_TERMINAL_STATUSES",
    "TaskStatus",
    "TemplateStatus",
    "V37_SLA_STATE_TO_WORKFLOW",
    "WORKFLOW_ACTIVE_STATUSES",
    "WORKFLOW_ASSURANCE",
    "WORKFLOW_CREATION_OUTCOME_VALUES",
    "WORKFLOW_DEPENDENCY_OUTCOME_VALUES",
    "WORKFLOW_EVENT_VALUES",
    "WORKFLOW_ID_NAMESPACE",
    "WORKFLOW_LIMITATIONS",
    "WORKFLOW_NON_CLAIMS",
    "WORKFLOW_OPEN_STATUSES",
    "WORKFLOW_OPERATION_VALUES",
    "WORKFLOW_PRIORITY_VALUES",
    "WORKFLOW_SLA_METRIC_VALUES",
    "WORKFLOW_SLA_STATE_VALUES",
    "WORKFLOW_STATUS_METRIC_VALUES",
    "WORKFLOW_STATUS_VALUES",
    "WORKFLOW_TERMINAL_STATUSES",
    "WORKFLOW_TRANSITION_OUTCOME_VALUES",
    "WORKFLOW_TRANSITIONS",
    "WorkflowEventType",
    "WorkflowSlaState",
    "WorkflowStatus",
    "escalation_id_for",
    "template_id_for",
    "workflow_id_for",
]
