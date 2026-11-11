"""Stable V35 forensic governance vocabulary.

V35 is a governance layer over V34 forensic records. It never deletes,
overwrites, repairs, re-hashes, moves, or cleans up evidence, cases, custody
records, checkpoints, or audit history. Every state is an authorization or
review state — never a deletion instruction.
"""

from __future__ import annotations

from enum import Enum

# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------
DEFAULT_POLICY_ID = "POL-DEFAULT"
DEFAULT_POLICY_NAME = "Default governance policy"
DEFAULT_POLICY_VERSION = 1


class PolicyState(str, Enum):
    DRAFT = "DRAFT"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    ARCHIVED = "ARCHIVED"


class ApprovalLevel(str, Enum):
    SINGLE_REVIEWER = "SINGLE_REVIEWER"
    DUAL_REVIEWER = "DUAL_REVIEWER"


POLICY_TRANSITIONS: dict[PolicyState, frozenset[PolicyState]] = {
    PolicyState.DRAFT: frozenset({PolicyState.ENABLED, PolicyState.DISABLED, PolicyState.ARCHIVED}),
    PolicyState.ENABLED: frozenset({PolicyState.DISABLED, PolicyState.ARCHIVED}),
    PolicyState.DISABLED: frozenset({PolicyState.ENABLED, PolicyState.ARCHIVED}),
    PolicyState.ARCHIVED: frozenset(),
}

#: Policies that are selectable for an evaluation. DRAFT/DISABLED/ARCHIVED
#: policies are retained as history but never applied.
SELECTABLE_POLICY_STATES: frozenset[str] = frozenset({PolicyState.ENABLED.value})


# ---------------------------------------------------------------------------
# Retention evaluation
# ---------------------------------------------------------------------------
class EvaluationKind(str, Enum):
    EVALUATION = "EVALUATION"
    REVIEW = "REVIEW"


class GovernanceState(str, Enum):
    ACTIVE = "ACTIVE"
    REVIEW_DUE = "REVIEW_DUE"
    LEGAL_HOLD = "LEGAL_HOLD"
    DISPOSITION_REVIEW_REQUIRED = "DISPOSITION_REVIEW_REQUIRED"
    DISPOSITION_APPROVED = "DISPOSITION_APPROVED"
    DISPOSITION_BLOCKED = "DISPOSITION_BLOCKED"


class DataStatus(str, Enum):
    OK = "OK"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"


#: Case statuses where a disposition review may be requested. A case that is
#: still being investigated is never eligible for disposition review.
DISPOSITION_ELIGIBLE_CASE_STATUSES: frozenset[str] = frozenset({"RESOLVED", "CLOSED"})


# ---------------------------------------------------------------------------
# Legal holds
# ---------------------------------------------------------------------------
class LegalHoldStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    ACTIVE = "ACTIVE"
    REJECTED = "REJECTED"
    RELEASED = "RELEASED"
    WITHDRAWN = "WITHDRAWN"


#: Both ACTIVE and PENDING_APPROVAL block disposition and export. Treating a
#: pending hold as blocking closes the race where approval could otherwise
#: complete while a hold request is still awaiting review.
BLOCKING_HOLD_STATUSES: frozenset[str] = frozenset(
    {LegalHoldStatus.PENDING_APPROVAL.value, LegalHoldStatus.ACTIVE.value}
)

HOLD_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {LegalHoldStatus.REJECTED.value, LegalHoldStatus.RELEASED.value, LegalHoldStatus.WITHDRAWN.value}
)

HOLD_TRANSITIONS: dict[str, frozenset[str]] = {
    LegalHoldStatus.PENDING_APPROVAL.value: frozenset(
        {
            LegalHoldStatus.ACTIVE.value,
            LegalHoldStatus.REJECTED.value,
            LegalHoldStatus.WITHDRAWN.value,
        }
    ),
    LegalHoldStatus.ACTIVE.value: frozenset({LegalHoldStatus.RELEASED.value}),
    LegalHoldStatus.REJECTED.value: frozenset(),
    LegalHoldStatus.RELEASED.value: frozenset(),
    LegalHoldStatus.WITHDRAWN.value: frozenset(),
}


class LegalHoldEventType(str, Enum):
    CREATED = "CREATED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    RELEASED = "RELEASED"
    WITHDRAWN = "WITHDRAWN"


# ---------------------------------------------------------------------------
# Disposition review
# ---------------------------------------------------------------------------
class DispositionStatus(str, Enum):
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVED = "APPROVED"
    BLOCKED = "BLOCKED"
    WITHDRAWN = "WITHDRAWN"


OPEN_DISPOSITION_STATUSES: frozenset[str] = frozenset(
    {DispositionStatus.REVIEW_REQUIRED.value, DispositionStatus.APPROVAL_PENDING.value}
)

DISPOSITION_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {DispositionStatus.APPROVED.value, DispositionStatus.BLOCKED.value, DispositionStatus.WITHDRAWN.value}
)

DISPOSITION_TRANSITIONS: dict[str, frozenset[str]] = {
    DispositionStatus.REVIEW_REQUIRED.value: frozenset(
        {
            DispositionStatus.APPROVAL_PENDING.value,
            DispositionStatus.APPROVED.value,
            DispositionStatus.BLOCKED.value,
            DispositionStatus.WITHDRAWN.value,
        }
    ),
    DispositionStatus.APPROVAL_PENDING.value: frozenset(
        {
            DispositionStatus.APPROVED.value,
            DispositionStatus.BLOCKED.value,
            DispositionStatus.WITHDRAWN.value,
        }
    ),
    DispositionStatus.APPROVED.value: frozenset(),
    DispositionStatus.BLOCKED.value: frozenset(),
    DispositionStatus.WITHDRAWN.value: frozenset(),
}


class DispositionDecision(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    BLOCK = "BLOCK"
    WITHDRAW = "WITHDRAW"


# ---------------------------------------------------------------------------
# Export approvals
# ---------------------------------------------------------------------------
class ExportApprovalStatus(str, Enum):
    PENDING_APPROVAL = "PENDING_APPROVAL"
    POLICY_AUTO_APPROVED = "POLICY_AUTO_APPROVED"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    GENERATED = "GENERATED"
    GENERATION_FAILED = "GENERATION_FAILED"
    VERIFIED = "VERIFIED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    EXPIRED = "EXPIRED"
    WITHDRAWN = "WITHDRAWN"


EXPORT_OPEN_STATUSES: frozenset[str] = frozenset(
    {
        ExportApprovalStatus.PENDING_APPROVAL.value,
        ExportApprovalStatus.POLICY_AUTO_APPROVED.value,
        ExportApprovalStatus.APPROVED.value,
        ExportApprovalStatus.GENERATED.value,
        ExportApprovalStatus.VERIFICATION_FAILED.value,
    }
)

EXPORT_GENERATION_READY_STATUSES: frozenset[str] = frozenset(
    {
        ExportApprovalStatus.POLICY_AUTO_APPROVED.value,
        ExportApprovalStatus.APPROVED.value,
        ExportApprovalStatus.GENERATION_FAILED.value,
    }
)

EXPORT_TERMINAL_STATUSES: frozenset[str] = frozenset(
    {
        ExportApprovalStatus.REJECTED.value,
        ExportApprovalStatus.VERIFIED.value,
        ExportApprovalStatus.EXPIRED.value,
        ExportApprovalStatus.WITHDRAWN.value,
    }
)

EXPORT_TRANSITIONS: dict[str, frozenset[str]] = {
    ExportApprovalStatus.PENDING_APPROVAL.value: frozenset(
        {
            ExportApprovalStatus.APPROVED.value,
            ExportApprovalStatus.REJECTED.value,
            ExportApprovalStatus.EXPIRED.value,
            ExportApprovalStatus.WITHDRAWN.value,
        }
    ),
    ExportApprovalStatus.POLICY_AUTO_APPROVED.value: frozenset(
        {
            ExportApprovalStatus.GENERATED.value,
            ExportApprovalStatus.GENERATION_FAILED.value,
            ExportApprovalStatus.EXPIRED.value,
            ExportApprovalStatus.WITHDRAWN.value,
        }
    ),
    ExportApprovalStatus.APPROVED.value: frozenset(
        {
            ExportApprovalStatus.GENERATED.value,
            ExportApprovalStatus.GENERATION_FAILED.value,
            ExportApprovalStatus.EXPIRED.value,
            ExportApprovalStatus.WITHDRAWN.value,
        }
    ),
    ExportApprovalStatus.GENERATION_FAILED.value: frozenset(
        {
            ExportApprovalStatus.GENERATED.value,
            ExportApprovalStatus.GENERATION_FAILED.value,
            ExportApprovalStatus.EXPIRED.value,
            ExportApprovalStatus.WITHDRAWN.value,
        }
    ),
    ExportApprovalStatus.GENERATED.value: frozenset(
        {
            ExportApprovalStatus.VERIFIED.value,
            ExportApprovalStatus.VERIFICATION_FAILED.value,
        }
    ),
    ExportApprovalStatus.VERIFICATION_FAILED.value: frozenset(
        {
            ExportApprovalStatus.VERIFIED.value,
            ExportApprovalStatus.VERIFICATION_FAILED.value,
        }
    ),
    ExportApprovalStatus.REJECTED.value: frozenset(),
    ExportApprovalStatus.VERIFIED.value: frozenset(),
    ExportApprovalStatus.EXPIRED.value: frozenset(),
    ExportApprovalStatus.WITHDRAWN.value: frozenset(),
}


# ---------------------------------------------------------------------------
# Governance access audit
# ---------------------------------------------------------------------------
class GovernanceAuditEventType(str, Enum):
    CASE_VIEWED = "CASE_VIEWED"
    EVIDENCE_METADATA_VIEWED = "EVIDENCE_METADATA_VIEWED"
    CUSTODY_HISTORY_VIEWED = "CUSTODY_HISTORY_VIEWED"
    EVIDENCE_VERIFICATION_REQUESTED = "EVIDENCE_VERIFICATION_REQUESTED"
    EXPORT_REQUESTED = "EXPORT_REQUESTED"
    EXPORT_APPROVED = "EXPORT_APPROVED"
    EXPORT_REJECTED = "EXPORT_REJECTED"
    EXPORT_GENERATED = "EXPORT_GENERATED"
    EXPORT_GENERATION_FAILED = "EXPORT_GENERATION_FAILED"
    EXPORT_VERIFIED = "EXPORT_VERIFIED"
    EXPORT_VERIFICATION_FAILED = "EXPORT_VERIFICATION_FAILED"
    EXPORT_DOWNLOAD_SERVED = "EXPORT_DOWNLOAD_SERVED"
    LEGAL_HOLD_CREATED = "LEGAL_HOLD_CREATED"
    LEGAL_HOLD_APPROVED = "LEGAL_HOLD_APPROVED"
    LEGAL_HOLD_REJECTED = "LEGAL_HOLD_REJECTED"
    LEGAL_HOLD_RELEASED = "LEGAL_HOLD_RELEASED"
    LEGAL_HOLD_WITHDRAWN = "LEGAL_HOLD_WITHDRAWN"
    RETENTION_POLICY_CREATED = "RETENTION_POLICY_CREATED"
    RETENTION_POLICY_VERSION_CREATED = "RETENTION_POLICY_VERSION_CREATED"
    RETENTION_EVALUATION_EXECUTED = "RETENTION_EVALUATION_EXECUTED"
    RETENTION_REVIEW_COMPLETED = "RETENTION_REVIEW_COMPLETED"
    DISPOSITION_REQUESTED = "DISPOSITION_REQUESTED"
    DISPOSITION_APPROVED = "DISPOSITION_APPROVED"
    DISPOSITION_REJECTED = "DISPOSITION_REJECTED"
    DISPOSITION_BLOCKED = "DISPOSITION_BLOCKED"
    DISPOSITION_WITHDRAWN = "DISPOSITION_WITHDRAWN"
    GOVERNANCE_REPORT_GENERATED = "GOVERNANCE_REPORT_GENERATED"
    GOVERNANCE_ACCESS_DENIED = "GOVERNANCE_ACCESS_DENIED"
    AUTOMATION_SCHEDULE_UPDATED = "AUTOMATION_SCHEDULE_UPDATED"
    AUTOMATION_JOB_ENQUEUED = "AUTOMATION_JOB_ENQUEUED"
    AUTOMATION_JOB_RETRIED = "AUTOMATION_JOB_RETRIED"
    AUTOMATION_JOB_CANCELLED = "AUTOMATION_JOB_CANCELLED"
    AUTOMATION_SNAPSHOT_GENERATED = "AUTOMATION_SNAPSHOT_GENERATED"


class GovernanceAuditOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    DENIED = "DENIED"
    FAILURE = "FAILURE"
    PARTIAL = "PARTIAL"


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
class ReportScope(str, Enum):
    SUMMARY = "SUMMARY"
    DETAIL = "DETAIL"


class ReportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"


class SectionStatus(str, Enum):
    OK = "OK"
    PARTIAL = "PARTIAL"
    INCOMPLETE = "INCOMPLETE"
    UNAVAILABLE = "UNAVAILABLE"


# ---------------------------------------------------------------------------
# Reason codes
# ---------------------------------------------------------------------------
RETENTION_START_UNAVAILABLE = "RETENTION_START_UNAVAILABLE"
RETENTION_POLICY_UNAVAILABLE = "RETENTION_POLICY_UNAVAILABLE"
RETENTION_EVALUATION_MISSING = "RETENTION_EVALUATION_MISSING"
RETENTION_DURATION_UNCONFIGURED = "RETENTION_DURATION_UNCONFIGURED"
REVIEW_INTERVAL_UNCONFIGURED = "REVIEW_INTERVAL_UNCONFIGURED"
RETENTION_DEADLINE_REACHED = "RETENTION_DEADLINE_REACHED"
RETENTION_REVIEW_DUE = "RETENTION_REVIEW_DUE"
LEGAL_HOLD_ACTIVE = "LEGAL_HOLD_ACTIVE"
LEGAL_HOLD_PENDING_APPROVAL = "LEGAL_HOLD_PENDING_APPROVAL"
DISPOSITION_APPROVED = "DISPOSITION_APPROVED"
DISPOSITION_BLOCKED = "DISPOSITION_BLOCKED"
DISPOSITION_OPEN = "DISPOSITION_OPEN"
DISPOSITION_REVIEW_REQUIRED = "DISPOSITION_REVIEW_REQUIRED"
CASE_STATUS_NOT_TERMINAL = "CASE_STATUS_NOT_TERMINAL"
INTEGRITY_NOT_PASS = "INTEGRITY_NOT_PASS"
INTEGRITY_UNAVAILABLE = "INTEGRITY_UNAVAILABLE"
POLICY_STALE = "POLICY_STALE"
EVALUATION_STALE = "EVALUATION_STALE"
HOLD_STATE_CHANGED = "HOLD_STATE_CHANGED"
VERIFICATION_STATE_CHANGED = "VERIFICATION_STATE_CHANGED"
EXPORT_POLICY_DISALLOWS = "EXPORT_POLICY_DISALLOWS"
EXPORT_EVIDENCE_BYTES_DISALLOWED = "EXPORT_EVIDENCE_BYTES_DISALLOWED"
EXPORT_ALREADY_GENERATED = "EXPORT_ALREADY_GENERATED"
EXPORT_EXPIRED = "EXPORT_EXPIRED"
EXPORT_NOT_APPROVED = "EXPORT_NOT_APPROVED"
EXPORT_VERIFICATION_NOT_PASS = "EXPORT_VERIFICATION_NOT_PASS"

# ---------------------------------------------------------------------------
# Honest non-claims
# ---------------------------------------------------------------------------
GOVERNANCE_ASSURANCE = "LOCAL_GOVERNANCE_AUDIT_ONLY"
GOVERNANCE_NON_CLAIMS: tuple[str, ...] = (
    "No automatic physical evidence deletion is performed.",
    "No automatic legal-hold release is performed.",
    "No automatic disposition approval is performed.",
    "No regulatory certification is claimed.",
    "No external immutable-storage claim is made.",
    "No external trust-anchor claim is made unless the existing V31/V32/V33 trust overview "
    "reports a configured and verified external anchor.",
    "Export approval does not prove external delivery or recipient validation.",
)
GOVERNANCE_LIMITATIONS: tuple[str, ...] = (
    "Retention evaluation is manual and bounded; V35 adds no background scheduler.",
    "Disposition approval authorizes only a future, separately scoped process; it never "
    "performs or schedules deletion.",
    "Legal holds never expire or release automatically; release requires an explicit ADMIN action.",
    "The governance audit is append-only in the database but is a local record, not an "
    "externally anchored or immutable log.",
    "Direct V34 forensic exports remain available to ADMIN and are policy/hold-guarded and "
    "audited, but do not require a governance approval record.",
)

#: Default policy reason text. Durations are organization-defined; V35 never
#: invents a regulatory retention period.
DEFAULT_POLICY_REASON = (
    "Safe fallback policy. Retention and review durations are organization-defined and remain "
    "unset until an administrator configures them; export approval is required and evidence "
    "bytes are disallowed by default."
)

MAX_REASON_LENGTH = 2048
MAX_JUSTIFICATION_LENGTH = 4096
MAX_PAGE_SIZE = 100
MAX_AUDIT_PAGE_SIZE = 200
MAX_BATCH_SIZE = 500
