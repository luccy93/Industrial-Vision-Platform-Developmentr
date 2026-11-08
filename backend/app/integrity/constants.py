"""Stable V33 audit vocabulary: scopes, outcomes, reason codes, severities.

Reason codes are part of the operational contract. The required codes from
the V33 mission are present verbatim; additional codes describe V30-V32
verifier results without inventing new cryptography.
"""

from __future__ import annotations

from enum import Enum


class IntegrityScope(str, Enum):
    """Explicit audit scopes. ``FULL`` expands to every concrete scope."""

    EVIDENCE = "EVIDENCE"
    SIGNED_CHECKPOINTS = "SIGNED_CHECKPOINTS"
    TRANSPARENCY_LOG = "TRANSPARENCY_LOG"
    TREE_HEADS = "TREE_HEADS"
    INCLUSION_PROOFS = "INCLUSION_PROOFS"
    CONSISTENCY_PROOFS = "CONSISTENCY_PROOFS"
    TRUST_STATE = "TRUST_STATE"
    FULL = "FULL"


CONCRETE_SCOPES: tuple[IntegrityScope, ...] = (
    IntegrityScope.EVIDENCE,
    IntegrityScope.SIGNED_CHECKPOINTS,
    IntegrityScope.TRANSPARENCY_LOG,
    IntegrityScope.TREE_HEADS,
    IntegrityScope.INCLUSION_PROOFS,
    IntegrityScope.CONSISTENCY_PROOFS,
    IntegrityScope.TRUST_STATE,
)
SCOPE_ORDER: dict[IntegrityScope, int] = {scope: index for index, scope in enumerate(CONCRETE_SCOPES)}


class AuditStatus(str, Enum):
    """Terminal audit outcomes, plus the internal ``RUNNING`` state."""

    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_RUN = "NOT_RUN"
    RUNNING = "RUNNING"


TERMINAL_STATUSES = frozenset(
    {AuditStatus.PASS, AuditStatus.FAIL, AuditStatus.PARTIAL, AuditStatus.UNAVAILABLE, AuditStatus.NOT_RUN}
)


class ScopeStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    NOT_RUN = "NOT_RUN"


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AuditTrigger(str, Enum):
    MANUAL = "MANUAL"
    SCHEDULED = "SCHEDULED"


class AssuranceLevel(str, Enum):
    """Honest assurance vocabulary; V33 never claims external anchoring."""

    NONE = "NONE"
    LOCAL_ONLY = "LOCAL_ONLY"
    LOCAL_VERIFIED = "LOCAL_VERIFIED"
    EXTERNAL_ANCHORED = "EXTERNAL_ANCHORED"


class AnchorStatus(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    SIMULATED = "SIMULATED"
    UNAVAILABLE = "UNAVAILABLE"
    EXTERNAL_VERIFIED = "EXTERNAL_VERIFIED"


# --- Required V33 reason codes -------------------------------------------
EVIDENCE_MISSING = "EVIDENCE_MISSING"
EVIDENCE_MODIFIED = "EVIDENCE_MODIFIED"
EVIDENCE_REPLACED = "EVIDENCE_REPLACED"
MANIFEST_BINDING_MISMATCH = "MANIFEST_BINDING_MISMATCH"
AUDIT_CHAIN_INVALID = "AUDIT_CHAIN_INVALID"
CHECKPOINT_SIGNATURE_INVALID = "CHECKPOINT_SIGNATURE_INVALID"
CHECKPOINT_REPLAY = "CHECKPOINT_REPLAY"
TRUST_KEY_UNKNOWN = "TRUST_KEY_UNKNOWN"
TRUST_KEY_REVOKED = "TRUST_KEY_REVOKED"
TRUST_KEY_EXPIRED = "TRUST_KEY_EXPIRED"
TREE_HEAD_INVALID = "TREE_HEAD_INVALID"
TREE_SIZE_ROLLBACK = "TREE_SIZE_ROLLBACK"
MERKLE_ROOT_CONFLICT = "MERKLE_ROOT_CONFLICT"
INCLUSION_PROOF_INVALID = "INCLUSION_PROOF_INVALID"
CONSISTENCY_PROOF_INVALID = "CONSISTENCY_PROOF_INVALID"
RECEIPT_INVALID = "RECEIPT_INVALID"
EXTERNAL_ANCHOR_UNCONFIGURED = "EXTERNAL_ANCHOR_UNCONFIGURED"
TRUST_STATE_UNAVAILABLE = "TRUST_STATE_UNAVAILABLE"
CONCURRENT_EVIDENCE_CHANGE = "CONCURRENT_EVIDENCE_CHANGE"
AUDIT_TIMEOUT = "AUDIT_TIMEOUT"
AUDIT_CANCELLED = "AUDIT_CANCELLED"

# --- Additional precise reason codes -------------------------------------
EVIDENCE_PATH_INVALID = "EVIDENCE_PATH_INVALID"
EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
EVIDENCE_NOT_CONFIGURED = "EVIDENCE_NOT_CONFIGURED"
REPORT_BINDING_MISMATCH = "REPORT_BINDING_MISMATCH"
CHECKPOINT_MISSING = "CHECKPOINT_MISSING"
CHECKPOINT_BINDING_MISMATCH = "CHECKPOINT_BINDING_MISMATCH"
CHECKPOINT_SEQUENCE_INVALID = "CHECKPOINT_SEQUENCE_INVALID"
CHECKPOINT_CONFLICT = "CHECKPOINT_CONFLICT"
CHECKPOINT_NOT_CONFIGURED = "CHECKPOINT_NOT_CONFIGURED"
TRUST_KEY_NOT_YET_VALID = "TRUST_KEY_NOT_YET_VALID"
TRUST_KEY_PURPOSE_INVALID = "TRUST_KEY_PURPOSE_INVALID"
TRUST_KEY_UNTRUSTED = "TRUST_KEY_UNTRUSTED"
TRUST_STORE_UNAVAILABLE = "TRUST_STORE_UNAVAILABLE"
TRUST_STORE_INVALID = "TRUST_STORE_INVALID"
TRUST_STATE_INVALID = "TRUST_STATE_INVALID"
TRUST_STATE_NOT_CONFIGURED = "TRUST_STATE_NOT_CONFIGURED"
TREE_HEAD_REPLAY = "TREE_HEAD_REPLAY"
TREE_HEAD_TIMESTAMP_REGRESSION = "TREE_HEAD_TIMESTAMP_REGRESSION"
TREE_HEAD_TRUST_UNAVAILABLE = "TREE_HEAD_TRUST_UNAVAILABLE"
TREE_HEAD_NOT_CONFIGURED = "TREE_HEAD_NOT_CONFIGURED"
TRANSPARENCY_LOG_INVALID = "TRANSPARENCY_LOG_INVALID"
TRANSPARENCY_LOG_UNAVAILABLE = "TRANSPARENCY_LOG_UNAVAILABLE"
TRANSPARENCY_LOG_NOT_CONFIGURED = "TRANSPARENCY_LOG_NOT_CONFIGURED"
INCLUSION_PROOF_MISSING = "INCLUSION_PROOF_MISSING"
INCLUSION_PROOFS_NOT_CONFIGURED = "INCLUSION_PROOFS_NOT_CONFIGURED"
CONSISTENCY_PROOF_MISSING = "CONSISTENCY_PROOF_MISSING"
CONSISTENCY_PROOFS_NOT_CONFIGURED = "CONSISTENCY_PROOFS_NOT_CONFIGURED"
RECEIPT_STALE = "RECEIPT_STALE"
RECEIPT_PROVIDER_UNAVAILABLE = "RECEIPT_PROVIDER_UNAVAILABLE"
EXTERNAL_ANCHOR_MISMATCH = "EXTERNAL_ANCHOR_MISMATCH"
AUDIT_INTERRUPTED = "AUDIT_INTERRUPTED"
AUDIT_EXECUTION_ERROR = "AUDIT_EXECUTION_ERROR"
AUDIT_STORE_UNAVAILABLE = "AUDIT_STORE_UNAVAILABLE"
AUDIT_ALREADY_RUNNING = "AUDIT_ALREADY_RUNNING"
AUDIT_RETRY_EXHAUSTED = "AUDIT_RETRY_EXHAUSTED"
BATCH_LIMIT_REACHED = "BATCH_LIMIT_REACHED"
FINDINGS_TRUNCATED = "FINDINGS_TRUNCATED"
SCHEDULER_FAILURE = "SCHEDULER_FAILURE"
AUDIT_STALE = "AUDIT_STALE"
VERIFICATION_UNAVAILABLE = "VERIFICATION_UNAVAILABLE"
VERIFICATION_FAILED = "VERIFICATION_FAILED"

REASON_CODES: frozenset[str] = frozenset(
    {
        EVIDENCE_MISSING,
        EVIDENCE_MODIFIED,
        EVIDENCE_REPLACED,
        MANIFEST_BINDING_MISMATCH,
        AUDIT_CHAIN_INVALID,
        CHECKPOINT_SIGNATURE_INVALID,
        CHECKPOINT_REPLAY,
        TRUST_KEY_UNKNOWN,
        TRUST_KEY_REVOKED,
        TRUST_KEY_EXPIRED,
        TREE_HEAD_INVALID,
        TREE_SIZE_ROLLBACK,
        MERKLE_ROOT_CONFLICT,
        INCLUSION_PROOF_INVALID,
        CONSISTENCY_PROOF_INVALID,
        RECEIPT_INVALID,
        EXTERNAL_ANCHOR_UNCONFIGURED,
        TRUST_STATE_UNAVAILABLE,
        CONCURRENT_EVIDENCE_CHANGE,
        AUDIT_TIMEOUT,
        AUDIT_CANCELLED,
        EVIDENCE_PATH_INVALID,
        EVIDENCE_UNAVAILABLE,
        EVIDENCE_NOT_CONFIGURED,
        REPORT_BINDING_MISMATCH,
        CHECKPOINT_MISSING,
        CHECKPOINT_BINDING_MISMATCH,
        CHECKPOINT_SEQUENCE_INVALID,
        CHECKPOINT_CONFLICT,
        CHECKPOINT_NOT_CONFIGURED,
        TRUST_KEY_NOT_YET_VALID,
        TRUST_KEY_PURPOSE_INVALID,
        TRUST_KEY_UNTRUSTED,
        TRUST_STORE_UNAVAILABLE,
        TRUST_STORE_INVALID,
        TRUST_STATE_INVALID,
        TRUST_STATE_NOT_CONFIGURED,
        TREE_HEAD_REPLAY,
        TREE_HEAD_TIMESTAMP_REGRESSION,
        TREE_HEAD_TRUST_UNAVAILABLE,
        TREE_HEAD_NOT_CONFIGURED,
        TRANSPARENCY_LOG_INVALID,
        TRANSPARENCY_LOG_UNAVAILABLE,
        TRANSPARENCY_LOG_NOT_CONFIGURED,
        INCLUSION_PROOF_MISSING,
        INCLUSION_PROOFS_NOT_CONFIGURED,
        CONSISTENCY_PROOF_MISSING,
        CONSISTENCY_PROOFS_NOT_CONFIGURED,
        RECEIPT_STALE,
        RECEIPT_PROVIDER_UNAVAILABLE,
        EXTERNAL_ANCHOR_MISMATCH,
        AUDIT_INTERRUPTED,
        AUDIT_EXECUTION_ERROR,
        AUDIT_STORE_UNAVAILABLE,
        AUDIT_ALREADY_RUNNING,
        AUDIT_RETRY_EXHAUSTED,
        BATCH_LIMIT_REACHED,
        FINDINGS_TRUNCATED,
        SCHEDULER_FAILURE,
        AUDIT_STALE,
        VERIFICATION_UNAVAILABLE,
        VERIFICATION_FAILED,
    }
)

#: Raw V30-V32 verifier codes mapped to V33 reason codes. Unmapped raw codes
#: fall back to ``VERIFICATION_FAILED``; a raw code that is already a V33
#: code is preserved verbatim.
_RAW_REASON_MAP: dict[str, str] = {
    # V30 evidence verification
    "EVIDENCE_REJECTED": EVIDENCE_PATH_INVALID,
    "EVIDENCE_MISSING": EVIDENCE_MISSING,
    "EVIDENCE_MODIFIED": EVIDENCE_MODIFIED,
    "EVIDENCE_REPLACED": EVIDENCE_REPLACED,
    "EVIDENCE_PATH_INVALID": EVIDENCE_PATH_INVALID,
    "MANIFEST_BINDING_MISMATCH": MANIFEST_BINDING_MISMATCH,
    "AUDIT_CHAIN_INVALID": AUDIT_CHAIN_INVALID,
    "SIGNED_CHECKPOINT_REQUIRES_REPORT": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_UNSIGNED": CHECKPOINT_SIGNATURE_INVALID,
    # V31 checkpoint and trust verification
    "CHECKPOINT_SCHEMA_INVALID": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_ID_MISMATCH": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_ID_REUSED": CHECKPOINT_CONFLICT,
    "CHECKPOINT_PAYLOAD_DIGEST_MISMATCH": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_SIGNATURE_MISMATCH": CHECKPOINT_SIGNATURE_INVALID,
    "CHECKPOINT_SIGNATURE_MALFORMED": CHECKPOINT_SIGNATURE_INVALID,
    "CHECKPOINT_ALGORITHM_UNKNOWN": CHECKPOINT_SIGNATURE_INVALID,
    "CHECKPOINT_MANIFEST_MISMATCH": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_MANIFEST_MISSING": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_REPORT_MISMATCH": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_AUDIT_MISMATCH": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_TIMESTAMP_INCONSISTENT": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_TIMESTAMP_INVALID": CHECKPOINT_BINDING_MISMATCH,
    "CHECKPOINT_REPLAY": CHECKPOINT_REPLAY,
    "CHECKPOINT_CONFLICT": CHECKPOINT_CONFLICT,
    "CHECKPOINT_SEQUENCE_INVALID": CHECKPOINT_SEQUENCE_INVALID,
    "CHECKPOINT_SEQUENCE_DECREASING": CHECKPOINT_REPLAY,
    "CHECKPOINT_SEQUENCE_DUPLICATE": CHECKPOINT_REPLAY,
    "CHECKPOINT_SEQUENCE_GAP": CHECKPOINT_SEQUENCE_INVALID,
    "AUDIT_HASH_ROLLBACK": AUDIT_CHAIN_INVALID,
    "CHAIN_TRUNCATION": AUDIT_CHAIN_INVALID,
    "MANIFEST_DIGEST_ROLLBACK": AUDIT_CHAIN_INVALID,
    "TRUST_STORE_MISSING": TRUST_STORE_UNAVAILABLE,
    "TRUST_STORE_INVALID": TRUST_STORE_INVALID,
    "TRUST_STATE_MISSING": TRUST_STATE_UNAVAILABLE,
    "TRUST_STATE_INVALID": TRUST_STATE_INVALID,
    "TRUST_FINGERPRINT_MISMATCH": TRUST_KEY_UNTRUSTED,
    "TRUST_KEY_UNKNOWN": TRUST_KEY_UNKNOWN,
    "TRUST_KEY_UNTRUSTED": TRUST_KEY_UNTRUSTED,
    "TRUST_KEY_REVOKED": TRUST_KEY_REVOKED,
    "TRUST_KEY_EXPIRED": TRUST_KEY_EXPIRED,
    "TRUST_KEY_NOT_YET_VALID": TRUST_KEY_NOT_YET_VALID,
    "TRUST_KEY_PURPOSE_INVALID": TRUST_KEY_PURPOSE_INVALID,
    "TRUST_KEY_ALGORITHM_DISALLOWED": TRUST_KEY_UNTRUSTED,
    "EXTERNAL_ANCHOR_UNCONFIGURED": EXTERNAL_ANCHOR_UNCONFIGURED,
    "EXTERNAL_ANCHOR_MISMATCH": EXTERNAL_ANCHOR_MISMATCH,
    "EXTERNAL_ANCHOR_REFERENCE_MISSING": EXTERNAL_ANCHOR_UNCONFIGURED,
    "INDEPENDENT_FRESHNESS_UNAVAILABLE": EXTERNAL_ANCHOR_UNCONFIGURED,
    # V32 transparency log, tree heads, receipts
    "TRANSPARENCY_LOG_UNAVAILABLE": TRANSPARENCY_LOG_UNAVAILABLE,
    "TRANSPARENCY_LOG_TOO_LARGE": BATCH_LIMIT_REACHED,
    "TRANSPARENCY_STATE_MISSING": TRUST_STATE_UNAVAILABLE,
    "TRANSPARENCY_STATE_INVALID": TRUST_STATE_INVALID,
    "TREE_HEAD_TRUST_STORE_MISSING": TRUST_STORE_UNAVAILABLE,
    "TREE_HEAD_KEY_UNKNOWN": TRUST_KEY_UNKNOWN,
    "TREE_HEAD_KEY_UNTRUSTED": TRUST_KEY_UNTRUSTED,
    "TREE_HEAD_KEY_REVOKED": TRUST_KEY_REVOKED,
    "TREE_HEAD_KEY_EXPIRED": TRUST_KEY_EXPIRED,
    "TREE_HEAD_KEY_NOT_YET_VALID": TRUST_KEY_NOT_YET_VALID,
    "TREE_HEAD_KEY_PURPOSE_INVALID": TRUST_KEY_PURPOSE_INVALID,
    "TREE_HEAD_KEY_ALGORITHM_DISALLOWED": TRUST_KEY_UNTRUSTED,
    "TREE_HEAD_SIGNATURE_MISMATCH": TREE_HEAD_INVALID,
    "TREE_HEAD_SIGNATURE_MALFORMED": TREE_HEAD_INVALID,
    "TREE_HEAD_PAYLOAD_DIGEST_MISMATCH": TREE_HEAD_INVALID,
    "TREE_HEAD_SCHEMA_INVALID": TREE_HEAD_INVALID,
    "TREE_HEAD_ALGORITHM_UNKNOWN": TREE_HEAD_INVALID,
    "TREE_HEAD_ID_MISMATCH": TREE_HEAD_INVALID,
    "TREE_HEAD_DUPLICATE": TREE_HEAD_INVALID,
    "TREE_HEAD_CONFLICT": TREE_HEAD_INVALID,
    "TREE_HEAD_REPLAY": TREE_HEAD_REPLAY,
    "TREE_SIZE_ROLLBACK": TREE_SIZE_ROLLBACK,
    "TREE_ROOT_CONFLICT": MERKLE_ROOT_CONFLICT,
    "TREE_HEAD_TIMESTAMP_REGRESSION": TREE_HEAD_TIMESTAMP_REGRESSION,
    "INCLUSION_PROOF_INVALID": INCLUSION_PROOF_INVALID,
    "INCLUSION_PROOF_MISSING": INCLUSION_PROOF_MISSING,
    "CONSISTENCY_PROOF_INVALID": CONSISTENCY_PROOF_INVALID,
    "CONSISTENCY_PROOF_MISSING": CONSISTENCY_PROOF_MISSING,
    "RECEIPT_SCHEMA_INVALID": RECEIPT_INVALID,
    "RECEIPT_ID_MISMATCH": RECEIPT_INVALID,
    "RECEIPT_LOG_MISMATCH": RECEIPT_INVALID,
    "RECEIPT_PAYLOAD_DIGEST_MISMATCH": RECEIPT_INVALID,
    "RECEIPT_PROVIDER_MISMATCH": RECEIPT_INVALID,
    "RECEIPT_ROOT_MISMATCH": RECEIPT_INVALID,
    "RECEIPT_SIGNATURE_MALFORMED": RECEIPT_INVALID,
    "RECEIPT_SIGNATURE_MISMATCH": RECEIPT_INVALID,
    "RECEIPT_STATUS_INVALID": RECEIPT_INVALID,
    "RECEIPT_TIMESTAMP_INVALID": RECEIPT_INVALID,
    "RECEIPT_TREE_HEAD_MISMATCH": RECEIPT_INVALID,
    "RECEIPT_TREE_SIZE_MISMATCH": RECEIPT_INVALID,
    "RECEIPT_UNSIGNED": RECEIPT_INVALID,
    "RECEIPT_STALE": RECEIPT_STALE,
    "ANCHOR_NOT_CONFIGURED": EXTERNAL_ANCHOR_UNCONFIGURED,
    "ANCHOR_SIMULATED": EXTERNAL_ANCHOR_UNCONFIGURED,
    "ANCHOR_UNAVAILABLE": RECEIPT_PROVIDER_UNAVAILABLE,
    "ANCHOR_EXTERNAL_VERIFIED": EXTERNAL_ANCHOR_UNCONFIGURED,
    "VERIFICATION_UNAVAILABLE": VERIFICATION_UNAVAILABLE,
    "UNAVAILABLE": VERIFICATION_UNAVAILABLE,
}

REASON_SEVERITY: dict[str, Severity] = {
    EVIDENCE_MISSING: Severity.HIGH,
    EVIDENCE_MODIFIED: Severity.CRITICAL,
    EVIDENCE_REPLACED: Severity.CRITICAL,
    EVIDENCE_PATH_INVALID: Severity.HIGH,
    EVIDENCE_UNAVAILABLE: Severity.MEDIUM,
    EVIDENCE_NOT_CONFIGURED: Severity.MEDIUM,
    MANIFEST_BINDING_MISMATCH: Severity.HIGH,
    REPORT_BINDING_MISMATCH: Severity.HIGH,
    AUDIT_CHAIN_INVALID: Severity.HIGH,
    CHECKPOINT_MISSING: Severity.HIGH,
    CHECKPOINT_SIGNATURE_INVALID: Severity.CRITICAL,
    CHECKPOINT_BINDING_MISMATCH: Severity.HIGH,
    CHECKPOINT_REPLAY: Severity.HIGH,
    CHECKPOINT_SEQUENCE_INVALID: Severity.HIGH,
    CHECKPOINT_CONFLICT: Severity.CRITICAL,
    CHECKPOINT_NOT_CONFIGURED: Severity.MEDIUM,
    TRUST_KEY_UNKNOWN: Severity.HIGH,
    TRUST_KEY_UNTRUSTED: Severity.HIGH,
    TRUST_KEY_REVOKED: Severity.CRITICAL,
    TRUST_KEY_EXPIRED: Severity.HIGH,
    TRUST_KEY_NOT_YET_VALID: Severity.MEDIUM,
    TRUST_KEY_PURPOSE_INVALID: Severity.HIGH,
    TRUST_STORE_UNAVAILABLE: Severity.MEDIUM,
    TRUST_STORE_INVALID: Severity.HIGH,
    TRUST_STATE_UNAVAILABLE: Severity.MEDIUM,
    TRUST_STATE_INVALID: Severity.HIGH,
    TRUST_STATE_NOT_CONFIGURED: Severity.MEDIUM,
    TREE_HEAD_INVALID: Severity.HIGH,
    TREE_HEAD_REPLAY: Severity.HIGH,
    TREE_HEAD_TIMESTAMP_REGRESSION: Severity.MEDIUM,
    TREE_HEAD_TRUST_UNAVAILABLE: Severity.MEDIUM,
    TREE_HEAD_NOT_CONFIGURED: Severity.MEDIUM,
    TREE_SIZE_ROLLBACK: Severity.CRITICAL,
    MERKLE_ROOT_CONFLICT: Severity.CRITICAL,
    TRANSPARENCY_LOG_INVALID: Severity.HIGH,
    TRANSPARENCY_LOG_UNAVAILABLE: Severity.MEDIUM,
    TRANSPARENCY_LOG_NOT_CONFIGURED: Severity.MEDIUM,
    INCLUSION_PROOF_INVALID: Severity.HIGH,
    INCLUSION_PROOF_MISSING: Severity.HIGH,
    INCLUSION_PROOFS_NOT_CONFIGURED: Severity.MEDIUM,
    CONSISTENCY_PROOF_INVALID: Severity.HIGH,
    CONSISTENCY_PROOF_MISSING: Severity.HIGH,
    CONSISTENCY_PROOFS_NOT_CONFIGURED: Severity.MEDIUM,
    RECEIPT_INVALID: Severity.HIGH,
    RECEIPT_STALE: Severity.MEDIUM,
    RECEIPT_PROVIDER_UNAVAILABLE: Severity.MEDIUM,
    EXTERNAL_ANCHOR_UNCONFIGURED: Severity.INFO,
    EXTERNAL_ANCHOR_MISMATCH: Severity.CRITICAL,
    CONCURRENT_EVIDENCE_CHANGE: Severity.HIGH,
    AUDIT_TIMEOUT: Severity.HIGH,
    AUDIT_CANCELLED: Severity.MEDIUM,
    AUDIT_INTERRUPTED: Severity.HIGH,
    AUDIT_EXECUTION_ERROR: Severity.HIGH,
    AUDIT_STORE_UNAVAILABLE: Severity.HIGH,
    AUDIT_ALREADY_RUNNING: Severity.INFO,
    AUDIT_RETRY_EXHAUSTED: Severity.HIGH,
    BATCH_LIMIT_REACHED: Severity.LOW,
    FINDINGS_TRUNCATED: Severity.MEDIUM,
    SCHEDULER_FAILURE: Severity.HIGH,
    AUDIT_STALE: Severity.HIGH,
    VERIFICATION_UNAVAILABLE: Severity.MEDIUM,
    VERIFICATION_FAILED: Severity.HIGH,
}

REASON_ACTIONS: dict[str, str] = {
    EVIDENCE_MISSING: (
        "Restore the missing evidence from the authoritative archive and re-run the audit; do not "
        "recreate it from memory."
    ),
    EVIDENCE_MODIFIED: (
        "Treat the evidence as compromised, isolate the affected artifact, and investigate the change "
        "before trusting the report."
    ),
    EVIDENCE_REPLACED: (
        "Treat the evidence as replaced, compare against the archived original, and investigate the producer."
    ),
    EVIDENCE_PATH_INVALID: (
        "Correct the evidence path so it resolves below the configured evidence root; never follow links "
        "outside it."
    ),
    EVIDENCE_UNAVAILABLE: "Check evidence-root readability and permissions, then re-run the audit.",
    EVIDENCE_NOT_CONFIGURED: "Configure the evidence report or manifest path to enable evidence auditing.",
    MANIFEST_BINDING_MISMATCH: (
        "Reconcile the report, integrity manifest, and evidence bindings; do not edit the manifest to fit "
        "the evidence."
    ),
    REPORT_BINDING_MISMATCH: (
        "Verify the report bytes against the sealed sidecar and restore the exact original report."
    ),
    AUDIT_CHAIN_INVALID: (
        "Treat the audit chain as tampered, preserve the bytes for investigation, and rebuild from "
        "trusted records only."
    ),
    CHECKPOINT_MISSING: (
        "Restore the signed checkpoint from trusted storage and re-run checkpoint verification."
    ),
    CHECKPOINT_SIGNATURE_INVALID: (
        "Treat the checkpoint as untrusted, preserve it for investigation, and verify the signing process."
    ),
    CHECKPOINT_BINDING_MISMATCH: (
        "Reconcile the checkpoint with its report, integrity sidecar, and audit chain; do not re-sign "
        "automatically."
    ),
    CHECKPOINT_REPLAY: "Investigate checkpoint sequence reuse and compare against the trusted prior state.",
    CHECKPOINT_SEQUENCE_INVALID: "Investigate sequence gaps or ordering; do not reset the sequence.",
    CHECKPOINT_CONFLICT: (
        "Investigate conflicting checkpoints for the same sequence; preserve both for analysis."
    ),
    CHECKPOINT_NOT_CONFIGURED: "Configure a signed checkpoint path to enable checkpoint auditing.",
    TRUST_KEY_UNKNOWN: (
        "Register the expected public key through the approved trust-store process or reject the artifact."
    ),
    TRUST_KEY_UNTRUSTED: (
        "Reconcile the key fingerprint with the independently supplied pin; do not trust the artifact."
    ),
    TRUST_KEY_REVOKED: "Reject artifacts signed by the revoked key and rotate to a trusted key.",
    TRUST_KEY_EXPIRED: "Reject artifacts signed after key expiry and rotate to a valid key.",
    TRUST_KEY_NOT_YET_VALID: "Check key activation time and clock assumptions before trusting the artifact.",
    TRUST_KEY_PURPOSE_INVALID: "Use a key registered for the required signing purpose.",
    TRUST_STORE_UNAVAILABLE: (
        "Restore the independently configured trust store; local verification is unavailable without it."
    ),
    TRUST_STORE_INVALID: (
        "Repair the trust store from the authoritative source; do not accept an invalid store."
    ),
    TRUST_STATE_UNAVAILABLE: "Restore the trusted prior state to enable replay and rollback protection.",
    TRUST_STATE_INVALID: (
        "Investigate the trust-state file; do not reset it or accept a new state automatically."
    ),
    TRUST_STATE_NOT_CONFIGURED: (
        "Configure evidence and transparency trust-state paths for replay protection."
    ),
    TREE_HEAD_INVALID: (
        "Treat the signed tree head as untrusted and investigate the signing and log processes."
    ),
    TREE_HEAD_REPLAY: "Investigate replayed tree heads and compare against the trusted prior state.",
    TREE_HEAD_TIMESTAMP_REGRESSION: (
        "Investigate timestamp ordering and clock integrity before trusting the head."
    ),
    TREE_HEAD_TRUST_UNAVAILABLE: "Restore tree-head trust material before relying on the head.",
    TREE_HEAD_NOT_CONFIGURED: "Configure tree-head paths to enable tree-head auditing.",
    TREE_SIZE_ROLLBACK: (
        "Treat the log as rolled back, preserve evidence, and investigate before accepting any head."
    ),
    MERKLE_ROOT_CONFLICT: (
        "Treat the log as split or conflicting, preserve both heads, and investigate the transparency log."
    ),
    TRANSPARENCY_LOG_INVALID: (
        "Treat the transparency log as tampered or malformed and preserve it for investigation."
    ),
    TRANSPARENCY_LOG_UNAVAILABLE: (
        "Check transparency-log readability and permissions, then re-run the audit."
    ),
    TRANSPARENCY_LOG_NOT_CONFIGURED: "Configure a transparency log path to enable log auditing.",
    INCLUSION_PROOF_INVALID: "Reject the inclusion claim and re-generate the proof from a trusted log view.",
    INCLUSION_PROOF_MISSING: "Provide the missing inclusion proof or treat the entry as unproven.",
    INCLUSION_PROOFS_NOT_CONFIGURED: "Configure an inclusion-proof directory to enable inclusion auditing.",
    CONSISTENCY_PROOF_INVALID: "Reject the consistency claim and investigate the log history.",
    CONSISTENCY_PROOF_MISSING: "Provide the missing consistency proof or treat the history as unproven.",
    CONSISTENCY_PROOFS_NOT_CONFIGURED: (
        "Configure a consistency-proof directory to enable consistency auditing."
    ),
    RECEIPT_INVALID: "Treat the anchor receipt as invalid and investigate the provider response.",
    RECEIPT_STALE: "Obtain a fresh receipt; do not present the stale receipt as current external anchoring.",
    RECEIPT_PROVIDER_UNAVAILABLE: (
        "Restore the configured provider or record the reduced-assurance state explicitly."
    ),
    EXTERNAL_ANCHOR_UNCONFIGURED: (
        "Configure an approved external transparency provider if external anchoring is required; V33 "
        "never claims it by default."
    ),
    EXTERNAL_ANCHOR_MISMATCH: (
        "Treat the external reference as conflicting and investigate before trusting the checkpoint."
    ),
    CONCURRENT_EVIDENCE_CHANGE: (
        "Stop concurrent writers, preserve the affected bytes, and re-run the audit from a quiescent state."
    ),
    AUDIT_TIMEOUT: "Reduce the batch size or increase the bounded timeout, then re-run the audit.",
    AUDIT_CANCELLED: "Re-run the audit when the operator or scheduler is ready.",
    AUDIT_INTERRUPTED: (
        "Investigate the worker restart, confirm the run did not partially persist findings, and re-run."
    ),
    AUDIT_EXECUTION_ERROR: (
        "Inspect sanitized audit diagnostics, correct the execution environment, and re-run."
    ),
    AUDIT_STORE_UNAVAILABLE: "Restore the monitoring store; audit results cannot be recorded without it.",
    AUDIT_ALREADY_RUNNING: "Wait for the active audit to finish; duplicate concurrent execution is refused.",
    AUDIT_RETRY_EXHAUSTED: (
        "Investigate the transient failure before retrying; retries never convert failures into passes."
    ),
    BATCH_LIMIT_REACHED: "Increase the bounded batch size or audit in smaller explicit scopes.",
    FINDINGS_TRUNCATED: (
        "Investigate the highest-severity findings first; additional findings were not persisted due to "
        "bounds."
    ),
    SCHEDULER_FAILURE: (
        "Inspect scheduler diagnostics and restore the worker; no audit frequency is silently changed."
    ),
    AUDIT_STALE: (
        "Check the scheduler and worker health; audit history has not advanced within the configured window."
    ),
    VERIFICATION_UNAVAILABLE: (
        "Restore the verifier's required input or dependency, then re-run; unavailable is not a pass."
    ),
    VERIFICATION_FAILED: (
        "Inspect the sanitized verification detail and re-run after correcting the underlying issue."
    ),
}

REASON_SOURCES: dict[str, str] = {
    EVIDENCE_MISSING: "V30 evidence verification",
    EVIDENCE_MODIFIED: "V30 evidence verification",
    EVIDENCE_REPLACED: "V30 evidence verification",
    EVIDENCE_PATH_INVALID: "V30 evidence path policy",
    EVIDENCE_UNAVAILABLE: "V30 evidence verification",
    EVIDENCE_NOT_CONFIGURED: "V33 audit configuration",
    MANIFEST_BINDING_MISMATCH: "V30 manifest binding verification",
    REPORT_BINDING_MISMATCH: "V30 report binding verification",
    AUDIT_CHAIN_INVALID: "V30 audit-chain verification",
    CHECKPOINT_MISSING: "V33 checkpoint discovery",
    CHECKPOINT_SIGNATURE_INVALID: "V31 signed-checkpoint verification",
    CHECKPOINT_BINDING_MISMATCH: "V31 signed-checkpoint binding verification",
    CHECKPOINT_REPLAY: "V31 checkpoint replay protection",
    CHECKPOINT_SEQUENCE_INVALID: "V31 checkpoint sequence verification",
    CHECKPOINT_CONFLICT: "V31 checkpoint conflict detection",
    CHECKPOINT_NOT_CONFIGURED: "V33 audit configuration",
    TRUST_KEY_UNKNOWN: "V31 trust-store verification",
    TRUST_KEY_UNTRUSTED: "V31 trust-store verification",
    TRUST_KEY_REVOKED: "V31 key lifecycle policy",
    TRUST_KEY_EXPIRED: "V31 key lifecycle policy",
    TRUST_KEY_NOT_YET_VALID: "V31 key lifecycle policy",
    TRUST_KEY_PURPOSE_INVALID: "V31 key purpose policy",
    TRUST_STORE_UNAVAILABLE: "V31 trust-store verification",
    TRUST_STORE_INVALID: "V31 trust-store verification",
    TRUST_STATE_UNAVAILABLE: "V31/V32 trust-state verification",
    TRUST_STATE_INVALID: "V31/V32 trust-state verification",
    TRUST_STATE_NOT_CONFIGURED: "V33 audit configuration",
    TREE_HEAD_INVALID: "V32 signed tree-head verification",
    TREE_HEAD_REPLAY: "V32 tree-head replay protection",
    TREE_HEAD_TIMESTAMP_REGRESSION: "V32 tree-head state comparison",
    TREE_HEAD_TRUST_UNAVAILABLE: "V32 tree-head trust verification",
    TREE_HEAD_NOT_CONFIGURED: "V33 audit configuration",
    TREE_SIZE_ROLLBACK: "V32 tree-head state comparison",
    MERKLE_ROOT_CONFLICT: "V32 Merkle root comparison",
    TRANSPARENCY_LOG_INVALID: "V32 transparency-log verification",
    TRANSPARENCY_LOG_UNAVAILABLE: "V32 transparency-log verification",
    TRANSPARENCY_LOG_NOT_CONFIGURED: "V33 audit configuration",
    INCLUSION_PROOF_INVALID: "V32 RFC 9162 inclusion verification",
    INCLUSION_PROOF_MISSING: "V32 RFC 9162 inclusion verification",
    INCLUSION_PROOFS_NOT_CONFIGURED: "V33 audit configuration",
    CONSISTENCY_PROOF_INVALID: "V32 RFC 9162 consistency verification",
    CONSISTENCY_PROOF_MISSING: "V32 RFC 9162 consistency verification",
    CONSISTENCY_PROOFS_NOT_CONFIGURED: "V33 audit configuration",
    RECEIPT_INVALID: "V32 anchor-receipt verification",
    RECEIPT_STALE: "V32 anchor-receipt verification",
    RECEIPT_PROVIDER_UNAVAILABLE: "V32 anchor provider status",
    EXTERNAL_ANCHOR_UNCONFIGURED: "V31/V32 external-anchor status",
    EXTERNAL_ANCHOR_MISMATCH: "V31 external-reference verification",
    CONCURRENT_EVIDENCE_CHANGE: "V33 read-only input snapshot",
    AUDIT_TIMEOUT: "V33 audit execution",
    AUDIT_CANCELLED: "V33 audit execution",
    AUDIT_INTERRUPTED: "V33 monitoring-store recovery",
    AUDIT_EXECUTION_ERROR: "V33 audit execution",
    AUDIT_STORE_UNAVAILABLE: "V33 monitoring store",
    AUDIT_ALREADY_RUNNING: "V33 duplicate-run prevention",
    AUDIT_RETRY_EXHAUSTED: "V33 retry policy",
    BATCH_LIMIT_REACHED: "V33 resource bounds",
    FINDINGS_TRUNCATED: "V33 finding bounds",
    SCHEDULER_FAILURE: "V33 audit scheduler",
    AUDIT_STALE: "V33 audit scheduler",
    VERIFICATION_UNAVAILABLE: "V30-V32 verification",
    VERIFICATION_FAILED: "V30-V32 verification",
}


def map_reason_code(raw: str | None, *, scope: IntegrityScope) -> str:
    """Map a V30-V32 verifier code to a stable V33 reason code."""
    if raw is None:
        return VERIFICATION_FAILED
    text = str(raw).strip().upper()
    if not text:
        return VERIFICATION_FAILED
    if text in REASON_CODES:
        return text
    mapped = _RAW_REASON_MAP.get(text)
    if mapped is not None:
        return mapped
    # An unmapped "unavailable" code means verification could not be performed;
    # it must never be reported as a confirmed verification failure.
    if text == "UNAVAILABLE" or text.endswith("_UNAVAILABLE"):
        return VERIFICATION_UNAVAILABLE
    if text.startswith("TRANSPARENCY_LOG_"):
        return TRANSPARENCY_LOG_INVALID
    if text.startswith("TREE_HEAD_"):
        return TREE_HEAD_INVALID
    if text.startswith("INCLUSION_"):
        return INCLUSION_PROOF_INVALID
    if text.startswith("CONSISTENCY_"):
        return CONSISTENCY_PROOF_INVALID
    if text.startswith("RECEIPT_"):
        return RECEIPT_INVALID
    if text.startswith("CHECKPOINT_"):
        return CHECKPOINT_BINDING_MISMATCH
    if text.startswith("TRUST_KEY_"):
        return TRUST_KEY_UNKNOWN
    if text.startswith("TRUST_"):
        return TRUST_STORE_INVALID
    return VERIFICATION_FAILED


def severity_for_reason(reason_code: str) -> Severity:
    return REASON_SEVERITY.get(reason_code, Severity.MEDIUM)


def recommended_action_for_reason(reason_code: str) -> str:
    return REASON_ACTIONS.get(
        reason_code,
        "Inspect the sanitized audit finding and re-run verification after correcting the underlying issue.",
    )


def verification_source_for_reason(reason_code: str) -> str:
    return REASON_SOURCES.get(reason_code, "V30-V32 verification")


def normalize_scope(value: object) -> IntegrityScope:
    if isinstance(value, IntegrityScope):
        return value
    text = str(value or "").strip().upper()
    try:
        return IntegrityScope(text)
    except ValueError:
        raise ValueError(f"unknown integrity audit scope: {text or '<empty>'}") from None


def expand_scopes(values: object, *, max_scopes: int = 8) -> tuple[IntegrityScope, ...]:
    """Validate and expand requested scopes; ``FULL`` must stand alone."""
    if isinstance(values, (str, IntegrityScope)):
        values = [values]
    if values is None:
        values = []
    scopes = [normalize_scope(value) for value in values]  # type: ignore[union-attr]
    if not scopes:
        raise ValueError("at least one audit scope is required")
    if len(scopes) > max_scopes:
        raise ValueError(f"at most {max_scopes} audit scopes are allowed")
    if len(set(scopes)) != len(scopes):
        raise ValueError("duplicate audit scopes are not allowed")
    if IntegrityScope.FULL in scopes:
        if len(scopes) != 1:
            raise ValueError("FULL must not be combined with explicit scopes")
        return CONCRETE_SCOPES
    return tuple(sorted(scopes, key=lambda scope: SCOPE_ORDER[scope]))


def aggregate_overall_status(
    scope_statuses: list[str],
    *,
    cancelled: bool,
    timed_out: bool,
    started: bool,
) -> AuditStatus:
    """Aggregate scope outcomes into the honest overall status.

    Confirmed failures always win. Unavailable/partial scopes produce
    ``PARTIAL`` (or ``UNAVAILABLE`` when nothing verified). Cancellation or
    timeout before any work is ``NOT_RUN``; after work it is ``PARTIAL``
    unless a confirmed failure exists.
    """
    statuses = [str(status).upper() for status in scope_statuses]
    if not started or not statuses:
        return AuditStatus.NOT_RUN
    if ScopeStatus.FAIL.value in statuses:
        return AuditStatus.FAIL
    if ScopeStatus.PARTIAL.value in statuses or ScopeStatus.UNAVAILABLE.value in statuses:
        if all(status == ScopeStatus.UNAVAILABLE.value for status in statuses):
            return AuditStatus.UNAVAILABLE
        return AuditStatus.PARTIAL
    if cancelled or timed_out:
        return AuditStatus.PARTIAL
    if all(status == ScopeStatus.PASS.value for status in statuses):
        return AuditStatus.PASS
    if all(status == ScopeStatus.NOT_RUN.value for status in statuses):
        return AuditStatus.NOT_RUN
    return AuditStatus.PARTIAL
