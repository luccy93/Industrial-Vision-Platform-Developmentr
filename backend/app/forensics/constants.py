"""Stable V34 forensic vocabulary.

The enums and reason-code sets are part of the operational contract. They
deliberately reuse V33 severity and reason codes instead of inventing a second
integrity taxonomy, and they keep ``UNAVAILABLE`` / ``NOT_RUN`` / ``SIMULATED``
separate from confirmed failures.
"""

from __future__ import annotations

from enum import Enum

from backend.app.integrity import constants as v33

#: Reuse the V33 severity scale verbatim.
CaseSeverity = v33.Severity


class CaseType(str, Enum):
    EVIDENCE_TAMPERING = "EVIDENCE_TAMPERING"
    CHECKPOINT_COMPROMISE = "CHECKPOINT_COMPROMISE"
    SIGNATURE_FAILURE = "SIGNATURE_FAILURE"
    TRANSPARENCY_CONFLICT = "TRANSPARENCY_CONFLICT"
    TRUST_KEY_COMPROMISE = "TRUST_KEY_COMPROMISE"
    CHAIN_OF_CUSTODY_FAILURE = "CHAIN_OF_CUSTODY_FAILURE"
    FORENSIC_REVIEW = "FORENSIC_REVIEW"
    OTHER = "OTHER"


class CaseStatus(str, Enum):
    OPEN = "OPEN"
    TRIAGED = "TRIAGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
    AWAITING_REVIEW = "AWAITING_REVIEW"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CaseSource(str, Enum):
    MANUAL = "MANUAL"
    CORRELATION = "CORRELATION"
    SYSTEM = "SYSTEM"


class EvidenceArtifactType(str, Enum):
    V33_FINDING = "V33_FINDING"
    V33_AUDIT_RUN = "V33_AUDIT_RUN"
    EVIDENCE_FILE = "EVIDENCE_FILE"
    EVIDENCE_SIDECAR = "EVIDENCE_SIDECAR"
    EVIDENCE_AUDIT_CHAIN = "EVIDENCE_AUDIT_CHAIN"
    SIGNED_CHECKPOINT = "SIGNED_CHECKPOINT"
    TRUST_STATE = "TRUST_STATE"
    TRUST_STORE = "TRUST_STORE"
    TRANSPARENCY_LOG = "TRANSPARENCY_LOG"
    TREE_HEAD = "TREE_HEAD"
    INCLUSION_PROOF = "INCLUSION_PROOF"
    CONSISTENCY_PROOF = "CONSISTENCY_PROOF"
    RECEIPT = "RECEIPT"
    INCIDENT = "INCIDENT"
    OPERATIONAL_LOG = "OPERATIONAL_LOG"
    OTHER = "OTHER"


class VerificationOutcome(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_RUN = "NOT_RUN"


class FindingClassification(str, Enum):
    CONFIRMED_FAILURE = "CONFIRMED_FAILURE"
    SUSPICIOUS = "SUSPICIOUS"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_RUN = "NOT_RUN"
    SIMULATED = "SIMULATED"
    OPERATIONAL = "OPERATIONAL"


class CustodyEventType(str, Enum):
    CASE_CREATED = "CASE_CREATED"
    EVIDENCE_REFERENCED = "EVIDENCE_REFERENCED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_VERIFICATION_FAILED = "EVIDENCE_VERIFICATION_FAILED"
    EVIDENCE_ACCESS_RECORDED = "EVIDENCE_ACCESS_RECORDED"
    EVIDENCE_EXPORT_CREATED = "EVIDENCE_EXPORT_CREATED"
    EVIDENCE_EXPORT_VERIFIED = "EVIDENCE_EXPORT_VERIFIED"
    INVESTIGATOR_ASSIGNED = "INVESTIGATOR_ASSIGNED"
    INVESTIGATOR_REASSIGNED = "INVESTIGATOR_REASSIGNED"
    CASE_STATUS_CHANGED = "CASE_STATUS_CHANGED"
    INVESTIGATION_NOTE_ADDED = "INVESTIGATION_NOTE_ADDED"
    OPERATOR_ACTION_RECORDED = "OPERATOR_ACTION_RECORDED"
    FINDING_CORRELATED = "FINDING_CORRELATED"
    INCIDENT_LINKED = "INCIDENT_LINKED"
    CASE_RESOLVED = "CASE_RESOLVED"
    CASE_CLOSED = "CASE_CLOSED"
    CHAIN_VERIFICATION_FAILED = "CHAIN_VERIFICATION_FAILED"
    VERIFICATION_RECORDED = "VERIFICATION_RECORDED"


class NoteType(str, Enum):
    OBSERVATION = "OBSERVATION"
    ANALYSIS = "ANALYSIS"
    HYPOTHESIS = "HYPOTHESIS"
    ACTION = "ACTION"
    CONCLUSION = "CONCLUSION"
    HANDOVER = "HANDOVER"


class NoteVisibility(str, Enum):
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"


class ActionType(str, Enum):
    EVIDENCE_VERIFICATION_REQUESTED = "EVIDENCE_VERIFICATION_REQUESTED"
    EVIDENCE_REVIEWED = "EVIDENCE_REVIEWED"
    FINDING_LINKED = "FINDING_LINKED"
    INCIDENT_LINKED = "INCIDENT_LINKED"
    CONTAINMENT_RECOMMENDED = "CONTAINMENT_RECOMMENDED"
    REMEDIATION_RECORDED = "REMEDIATION_RECORDED"
    EXPORT_GENERATED = "EXPORT_GENERATED"
    HANDOVER = "HANDOVER"
    OTHER = "OTHER"


class ActionResult(str, Enum):
    RECORDED = "RECORDED"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PENDING = "PENDING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


# ---------------------------------------------------------------------------
# Finding classification
# ---------------------------------------------------------------------------
#: Findings that describe a concrete integrity violation. Only these may be
#: promoted to a confirmed security incident.
CONFIRMED_FAILURE_REASONS: frozenset[str] = frozenset(
    {
        v33.EVIDENCE_MODIFIED,
        v33.EVIDENCE_REPLACED,
        v33.MANIFEST_BINDING_MISMATCH,
        v33.REPORT_BINDING_MISMATCH,
        v33.AUDIT_CHAIN_INVALID,
        v33.CHECKPOINT_SIGNATURE_INVALID,
        v33.CHECKPOINT_REPLAY,
        v33.CHECKPOINT_BINDING_MISMATCH,
        v33.CHECKPOINT_SEQUENCE_INVALID,
        v33.CHECKPOINT_CONFLICT,
        v33.TRUST_KEY_UNKNOWN,
        v33.TRUST_KEY_REVOKED,
        v33.TRUST_KEY_EXPIRED,
        v33.TRUST_KEY_NOT_YET_VALID,
        v33.TRUST_KEY_PURPOSE_INVALID,
        v33.TRUST_KEY_UNTRUSTED,
        v33.TRUST_STORE_INVALID,
        v33.TRUST_STATE_INVALID,
        v33.TREE_HEAD_INVALID,
        v33.TREE_HEAD_REPLAY,
        v33.TREE_SIZE_ROLLBACK,
        v33.MERKLE_ROOT_CONFLICT,
        v33.TREE_HEAD_TIMESTAMP_REGRESSION,
        v33.TRANSPARENCY_LOG_INVALID,
        v33.INCLUSION_PROOF_INVALID,
        v33.CONSISTENCY_PROOF_INVALID,
        v33.RECEIPT_INVALID,
        v33.EXTERNAL_ANCHOR_MISMATCH,
        v33.CONCURRENT_EVIDENCE_CHANGE,
    }
)

#: Findings that merit investigation but are not, by themselves, proof of
#: tampering (for example missing evidence or an invalid path).
SUSPICIOUS_REASONS: frozenset[str] = frozenset(
    {
        v33.EVIDENCE_MISSING,
        v33.EVIDENCE_PATH_INVALID,
        v33.CHECKPOINT_MISSING,
        v33.INCLUSION_PROOF_MISSING,
        v33.CONSISTENCY_PROOF_MISSING,
        v33.VERIFICATION_FAILED,
    }
)

UNAVAILABLE_REASONS: frozenset[str] = frozenset(
    {
        v33.EVIDENCE_UNAVAILABLE,
        v33.EVIDENCE_NOT_CONFIGURED,
        v33.CHECKPOINT_NOT_CONFIGURED,
        v33.TRUST_STORE_UNAVAILABLE,
        v33.TRUST_STATE_UNAVAILABLE,
        v33.TRUST_STATE_NOT_CONFIGURED,
        v33.TREE_HEAD_TRUST_UNAVAILABLE,
        v33.TREE_HEAD_NOT_CONFIGURED,
        v33.TRANSPARENCY_LOG_UNAVAILABLE,
        v33.TRANSPARENCY_LOG_NOT_CONFIGURED,
        v33.INCLUSION_PROOFS_NOT_CONFIGURED,
        v33.CONSISTENCY_PROOFS_NOT_CONFIGURED,
        v33.RECEIPT_PROVIDER_UNAVAILABLE,
        v33.AUDIT_STORE_UNAVAILABLE,
        v33.VERIFICATION_UNAVAILABLE,
    }
)

NOT_RUN_REASONS: frozenset[str] = frozenset(
    {
        v33.AUDIT_TIMEOUT,
        v33.AUDIT_CANCELLED,
        v33.AUDIT_INTERRUPTED,
        v33.AUDIT_EXECUTION_ERROR,
        v33.AUDIT_RETRY_EXHAUSTED,
        v33.AUDIT_STALE,
        v33.SCHEDULER_FAILURE,
    }
)

OPERATIONAL_REASONS: frozenset[str] = frozenset(
    {
        v33.AUDIT_ALREADY_RUNNING,
        v33.BATCH_LIMIT_REACHED,
        v33.FINDINGS_TRUNCATED,
        v33.EXTERNAL_ANCHOR_UNCONFIGURED,
        v33.RECEIPT_STALE,
    }
)

SIMULATED_MARKERS: tuple[str, ...] = ("SIMULATED", "SIMULATION", "LOCAL_TEST")

#: Case type selection by reason code. Unknown confirmed reasons fall back to
#: FORENSIC_REVIEW; suspicious findings use FORENSIC_REVIEW as well.
CASE_TYPE_BY_REASON: dict[str, CaseType] = {
    v33.EVIDENCE_MODIFIED: CaseType.EVIDENCE_TAMPERING,
    v33.EVIDENCE_REPLACED: CaseType.EVIDENCE_TAMPERING,
    v33.EVIDENCE_MISSING: CaseType.EVIDENCE_TAMPERING,
    v33.EVIDENCE_PATH_INVALID: CaseType.EVIDENCE_TAMPERING,
    v33.MANIFEST_BINDING_MISMATCH: CaseType.EVIDENCE_TAMPERING,
    v33.REPORT_BINDING_MISMATCH: CaseType.EVIDENCE_TAMPERING,
    v33.AUDIT_CHAIN_INVALID: CaseType.EVIDENCE_TAMPERING,
    v33.CONCURRENT_EVIDENCE_CHANGE: CaseType.EVIDENCE_TAMPERING,
    v33.CHECKPOINT_SIGNATURE_INVALID: CaseType.SIGNATURE_FAILURE,
    v33.CHECKPOINT_MISSING: CaseType.CHECKPOINT_COMPROMISE,
    v33.CHECKPOINT_REPLAY: CaseType.CHECKPOINT_COMPROMISE,
    v33.CHECKPOINT_BINDING_MISMATCH: CaseType.CHECKPOINT_COMPROMISE,
    v33.CHECKPOINT_SEQUENCE_INVALID: CaseType.CHECKPOINT_COMPROMISE,
    v33.CHECKPOINT_CONFLICT: CaseType.CHECKPOINT_COMPROMISE,
    v33.TRUST_KEY_UNKNOWN: CaseType.TRUST_KEY_COMPROMISE,
    v33.TRUST_KEY_REVOKED: CaseType.TRUST_KEY_COMPROMISE,
    v33.TRUST_KEY_EXPIRED: CaseType.TRUST_KEY_COMPROMISE,
    v33.TRUST_KEY_NOT_YET_VALID: CaseType.TRUST_KEY_COMPROMISE,
    v33.TRUST_KEY_PURPOSE_INVALID: CaseType.TRUST_KEY_COMPROMISE,
    v33.TRUST_KEY_UNTRUSTED: CaseType.TRUST_KEY_COMPROMISE,
    v33.TRUST_STORE_INVALID: CaseType.TRUST_KEY_COMPROMISE,
    v33.TRUST_STATE_INVALID: CaseType.TRUST_KEY_COMPROMISE,
    v33.TREE_HEAD_INVALID: CaseType.TRANSPARENCY_CONFLICT,
    v33.TREE_HEAD_REPLAY: CaseType.TRANSPARENCY_CONFLICT,
    v33.TREE_SIZE_ROLLBACK: CaseType.TRANSPARENCY_CONFLICT,
    v33.MERKLE_ROOT_CONFLICT: CaseType.TRANSPARENCY_CONFLICT,
    v33.TREE_HEAD_TIMESTAMP_REGRESSION: CaseType.TRANSPARENCY_CONFLICT,
    v33.TRANSPARENCY_LOG_INVALID: CaseType.TRANSPARENCY_CONFLICT,
    v33.INCLUSION_PROOF_INVALID: CaseType.TRANSPARENCY_CONFLICT,
    v33.CONSISTENCY_PROOF_INVALID: CaseType.TRANSPARENCY_CONFLICT,
    v33.RECEIPT_INVALID: CaseType.TRANSPARENCY_CONFLICT,
    v33.EXTERNAL_ANCHOR_MISMATCH: CaseType.TRANSPARENCY_CONFLICT,
}

PRIORITY_BY_SEVERITY: dict[str, str] = {
    CaseSeverity.CRITICAL.value: "P1",
    CaseSeverity.HIGH.value: "P2",
    CaseSeverity.MEDIUM.value: "P3",
    CaseSeverity.LOW.value: "P4",
    CaseSeverity.INFO.value: "P4",
}

# ---------------------------------------------------------------------------
# Workflow
# ---------------------------------------------------------------------------
TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset({CaseStatus.TRIAGED}),
    CaseStatus.TRIAGED: frozenset({CaseStatus.INVESTIGATING}),
    CaseStatus.INVESTIGATING: frozenset({CaseStatus.CONTAINMENT_RECOMMENDED, CaseStatus.AWAITING_REVIEW}),
    CaseStatus.CONTAINMENT_RECOMMENDED: frozenset({CaseStatus.AWAITING_REVIEW}),
    CaseStatus.AWAITING_REVIEW: frozenset({CaseStatus.INVESTIGATING, CaseStatus.RESOLVED}),
    CaseStatus.RESOLVED: frozenset({CaseStatus.CLOSED}),
    CaseStatus.CLOSED: frozenset(),
}

#: Reopening is never an implicit side effect. It requires an explicit
#: authorized operation with a reason and is recorded as CLOSED/RESOLVED -> OPEN.
REOPEN_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.CLOSED: frozenset({CaseStatus.OPEN}),
    CaseStatus.RESOLVED: frozenset({CaseStatus.OPEN}),
}

ACTIVE_STATUSES: frozenset[CaseStatus] = frozenset(
    {
        CaseStatus.OPEN,
        CaseStatus.TRIAGED,
        CaseStatus.INVESTIGATING,
        CaseStatus.CONTAINMENT_RECOMMENDED,
        CaseStatus.AWAITING_REVIEW,
    }
)

TERMINAL_STATUSES: frozenset[CaseStatus] = frozenset({CaseStatus.RESOLVED, CaseStatus.CLOSED})

#: Statuses that require the dedicated close/reopen capability.
CLOSE_STATUSES: frozenset[CaseStatus] = frozenset({CaseStatus.RESOLVED, CaseStatus.CLOSED})

# ---------------------------------------------------------------------------
# Export package
# ---------------------------------------------------------------------------
EXPORT_SCHEMA_VERSION = "1.0"
EXPORT_POLICY_VERSION = "1"
EXPORT_FILENAME_PREFIX = "forensic-case-"
EXPORT_REQUIRED_MEMBERS: tuple[str, ...] = (
    "case.json",
    "incident-reference.json",
    "findings.json",
    "audit-runs.json",
    "evidence-references.json",
    "custody-ledger.json",
    "investigation-notes.json",
    "operator-actions.json",
    "verification-report.json",
    "assignments.json",
)
EXPORT_MANIFEST = "manifest.json"
EXPORT_MANIFEST_DIGEST = "manifest.sha256"
EXPORT_DEFAULT_MAX_FILES = 64
EXPORT_DEFAULT_MAX_BYTES = 50 * 1024 * 1024
EXPORT_MAX_JSON_BYTES = 8 * 1024 * 1024

#: Local custody chains are not independently anchored. This string is used
#: everywhere the API reports assurance so the limitation is never implied away.
CUSTODY_ASSURANCE = "LOCAL_HASH_CHAIN_ONLY"
EXTERNAL_ANCHORING_NOTE = (
    "No external transparency provider is configured or independently verified; "
    "the local custody chain is not externally anchored."
)

#: Actor role snapshots accepted in custody events.
VALID_ACTOR_ROLES: frozenset[str] = frozenset({"ADMIN", "OPERATOR", "VIEWER", "SYSTEM"})

#: Default correlation dimensions. The service never treats a bare reason code
#: as a unique case identity because repeated audit runs produce the same code.
CORRELATION_DIMENSIONS: tuple[str, ...] = (
    "finding_id",
    "audit_run_id",
    "evidence_identifier",
    "checkpoint_id",
    "transparency_log_id",
    "manifest_id",
    "reason_code",
    "incident_id",
)


def classify_reason(reason_code: str, *, verification_source: str | None = None) -> FindingClassification:
    """Deterministically classify one V33 finding.

    ``SIMULATED`` source markers always win; unavailable/not-run/operational
    reasons are never promoted to confirmed security incidents.
    """
    source = str(verification_source or "").upper()
    if any(marker in source for marker in SIMULATED_MARKERS):
        return FindingClassification.SIMULATED
    code = str(reason_code or "").upper()
    if code in CONFIRMED_FAILURE_REASONS:
        return FindingClassification.CONFIRMED_FAILURE
    if code in NOT_RUN_REASONS:
        return FindingClassification.NOT_RUN
    if code in UNAVAILABLE_REASONS:
        return FindingClassification.UNAVAILABLE
    if code in OPERATIONAL_REASONS:
        return FindingClassification.OPERATIONAL
    if code in SUSPICIOUS_REASONS:
        return FindingClassification.SUSPICIOUS
    return FindingClassification.SUSPICIOUS


def case_type_for_reason(reason_code: str) -> CaseType:
    code = str(reason_code or "").upper()
    return CASE_TYPE_BY_REASON.get(code, CaseType.FORENSIC_REVIEW)


def priority_for_severity(severity: str | CaseSeverity) -> str:
    value = severity.value if isinstance(severity, CaseSeverity) else str(severity).upper()
    return PRIORITY_BY_SEVERITY.get(value, "P4")


def is_transition_allowed(current: CaseStatus, target: CaseStatus) -> bool:
    return target in TRANSITIONS.get(current, frozenset())


def is_reopen_allowed(current: CaseStatus, target: CaseStatus) -> bool:
    return target in REOPEN_TRANSITIONS.get(current, frozenset())


__all__ = [
    "ACTIVE_STATUSES",
    "ActionResult",
    "ActionType",
    "CASE_TYPE_BY_REASON",
    "CLOSE_STATUSES",
    "CONFIRMED_FAILURE_REASONS",
    "CORRELATION_DIMENSIONS",
    "CUSTODY_ASSURANCE",
    "CaseSeverity",
    "CaseSource",
    "CaseStatus",
    "CaseType",
    "CustodyEventType",
    "EXPORT_DEFAULT_MAX_BYTES",
    "EXPORT_DEFAULT_MAX_FILES",
    "EXPORT_FILENAME_PREFIX",
    "EXPORT_MANIFEST",
    "EXPORT_MANIFEST_DIGEST",
    "EXPORT_MAX_JSON_BYTES",
    "EXPORT_POLICY_VERSION",
    "EXPORT_REQUIRED_MEMBERS",
    "EXPORT_SCHEMA_VERSION",
    "EXTERNAL_ANCHORING_NOTE",
    "EvidenceArtifactType",
    "FindingClassification",
    "NOT_RUN_REASONS",
    "NoteType",
    "NoteVisibility",
    "OPERATIONAL_REASONS",
    "PRIORITY_BY_SEVERITY",
    "REOPEN_TRANSITIONS",
    "SIMULATED_MARKERS",
    "SUSPICIOUS_REASONS",
    "TERMINAL_STATUSES",
    "TRANSITIONS",
    "UNAVAILABLE_REASONS",
    "VALID_ACTOR_ROLES",
    "VerificationOutcome",
    "case_type_for_reason",
    "classify_reason",
    "is_reopen_allowed",
    "is_transition_allowed",
    "priority_for_severity",
]
