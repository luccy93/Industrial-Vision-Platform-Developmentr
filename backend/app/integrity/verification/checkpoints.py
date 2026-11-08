"""V33 SIGNED_CHECKPOINTS scope: read-only V31 checkpoint verification."""

from __future__ import annotations

from typing import Any

from backend.app.integrity.constants import (
    CHECKPOINT_BINDING_MISMATCH,
    CHECKPOINT_MISSING,
    CHECKPOINT_NOT_CONFIGURED,
    IntegrityScope,
    ScopeStatus,
)
from backend.app.integrity.errors import AuditCancelledError, AuditTimeoutError
from backend.app.integrity.models import safe_artifact_id
from backend.app.integrity.verification.base import (
    AuditContext,
    ScopeExecution,
    evaluate_checks,
    failed,
    missing_input,
    unavailable,
)
from tools.release.trust import (
    TrustConflict,
    TrustError,
    TrustInvalid,
    TrustUnavailable,
    load_signed_checkpoint,
    verify_signed_checkpoint,
)

_SAFE_TRUST_FIELDS = (
    "source",
    "trusted",
    "policy_version",
    "historical_revocation_policy",
    "key_id",
    "fingerprint",
    "algorithm",
    "purpose",
    "status",
    "historical",
)


def _safe_checkpoint_fields(checkpoint: dict[str, Any] | None) -> dict[str, Any]:
    if not checkpoint:
        return {}
    keys = (
        "checkpoint_id",
        "checkpoint_sequence",
        "created_at",
        "key_id",
        "public_key_fingerprint",
        "audit_record_count",
        "evidence_report_id",
    )
    return {key: checkpoint.get(key) for key in keys if key in checkpoint}


def _safe_trust_fields(trust: dict[str, Any] | None) -> dict[str, Any]:
    if not trust:
        return {}
    return {key: trust.get(key) for key in _SAFE_TRUST_FIELDS if key in trust}


def verify_signed_checkpoints(ctx: AuditContext) -> ScopeExecution:
    """Verify one configured signed checkpoint and its bindings."""
    targets = ctx.targets
    if targets.evidence_checkpoint is None:
        return unavailable(
            ctx,
            IntegrityScope.SIGNED_CHECKPOINTS,
            CHECKPOINT_NOT_CONFIGURED,
            "no signed checkpoint is configured; checkpoint signatures were not verified",
            details={"configured": False},
        )
    artifact = safe_artifact_id(targets.evidence_checkpoint, roots=targets.safe_roots)
    if not targets.evidence_checkpoint.exists():
        return missing_input(
            ctx,
            IntegrityScope.SIGNED_CHECKPOINTS,
            CHECKPOINT_MISSING,
            "the configured signed checkpoint is missing",
            artifact_id=artifact,
        )
    missing_bindings = [
        label
        for label, value in (
            ("report", targets.evidence_report),
            ("integrity sidecar", targets.evidence_integrity),
            ("audit chain", targets.evidence_audit),
        )
        if value is None
    ]
    if missing_bindings:
        return missing_input(
            ctx,
            IntegrityScope.SIGNED_CHECKPOINTS,
            CHECKPOINT_BINDING_MISMATCH,
            "checkpoint binding cannot be verified without: " + ", ".join(missing_bindings),
            artifact_id=artifact,
            details={"missing_bindings": missing_bindings},
        )
    ctx.check_budget()
    try:
        checkpoint = load_signed_checkpoint(targets.evidence_checkpoint)
    except (AuditCancelledError, AuditTimeoutError):
        raise
    except FileNotFoundError:
        return missing_input(
            ctx,
            IntegrityScope.SIGNED_CHECKPOINTS,
            CHECKPOINT_MISSING,
            "the configured signed checkpoint is missing",
            artifact_id=artifact,
        )
    except (TrustInvalid, TrustConflict, TrustError) as exc:
        return failed(
            ctx,
            IntegrityScope.SIGNED_CHECKPOINTS,
            CHECKPOINT_BINDING_MISMATCH,
            f"signed checkpoint is invalid ({type(exc).__name__})",
            artifact_id=artifact,
        )
    except Exception as exc:
        return failed(
            ctx,
            IntegrityScope.SIGNED_CHECKPOINTS,
            CHECKPOINT_BINDING_MISMATCH,
            f"signed checkpoint could not be loaded ({type(exc).__name__})",
            artifact_id=artifact,
        )

    try:
        result = verify_signed_checkpoint(
            checkpoint,
            report_path=targets.evidence_report,  # type: ignore[arg-type]
            integrity_path=targets.evidence_integrity,  # type: ignore[arg-type]
            audit_path=targets.evidence_audit,  # type: ignore[arg-type]
            trust_store_path=targets.evidence_trust_store,
            trusted_key_fingerprint=targets.evidence_trusted_fingerprint,
            trust_state_path=targets.evidence_trust_state,
            external_anchor=None,
            require_independent_freshness=False,
            generated_at=ctx.now(),
        )
    except (AuditCancelledError, AuditTimeoutError):
        raise
    except TrustUnavailable as exc:
        return unavailable(
            ctx,
            IntegrityScope.SIGNED_CHECKPOINTS,
            CHECKPOINT_BINDING_MISMATCH,
            f"checkpoint verification is unavailable ({type(exc).__name__})",
            artifact_id=artifact,
            finding=True,
        )
    except Exception as exc:
        return failed(
            ctx,
            IntegrityScope.SIGNED_CHECKPOINTS,
            CHECKPOINT_BINDING_MISMATCH,
            f"checkpoint verification failed ({type(exc).__name__})",
            artifact_id=artifact,
        )

    evaluation = evaluate_checks(
        ctx,
        IntegrityScope.SIGNED_CHECKPOINTS,
        result.checks,
        outcome=result.outcome,
        reason_codes=result.reason_codes,
        default_reason=CHECKPOINT_BINDING_MISMATCH,
        artifact_id=artifact,
    )
    details: dict[str, Any] = {
        "checkpoint": _safe_checkpoint_fields(result.checkpoint),
        "trust": _safe_trust_fields(result.trust),
        "assurance": result.assurance,
        "freshness": {
            key: value
            for key, value in dict(result.freshness or {}).items()
            if key in {"source", "independent", "configured", "fresh", "status"}
        },
        "external_anchor": {
            key: value
            for key, value in dict(result.external_anchor or {}).items()
            if key in {"configured", "status", "provider", "assurance", "detail"}
        },
        "limitations": [str(item)[:300] for item in result.limitations[:20]],
    }
    findings = list(evaluation.findings)
    if len(findings) > ctx.max_findings:
        findings = findings[: ctx.max_findings]
        details["findings_truncated"] = True
    status = evaluation.status
    if status is ScopeStatus.PASS and str(result.outcome).upper() == "UNAVAILABLE":
        status = ScopeStatus.UNAVAILABLE
    return ScopeExecution(
        status=status,
        checks_total=evaluation.checks_total,
        checks_failed=evaluation.checks_failed,
        artifacts_checked=1,
        findings=findings,
        reason_codes=evaluation.reason_codes,
        details=details,
    ).finalize()


__all__ = ["verify_signed_checkpoints"]
