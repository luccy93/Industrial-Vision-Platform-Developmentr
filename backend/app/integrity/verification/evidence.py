"""V33 EVIDENCE scope: read-only V30 evidence verification adapter."""

from __future__ import annotations

from typing import Any

from backend.app.integrity.constants import (
    EVIDENCE_MISSING,
    EVIDENCE_NOT_CONFIGURED,
    EVIDENCE_UNAVAILABLE,
    IntegrityScope,
    Severity,
)
from backend.app.integrity.errors import AuditCancelledError, AuditTimeoutError
from backend.app.integrity.models import Finding, safe_artifact_id
from backend.app.integrity.verification.base import (
    AuditContext,
    ScopeExecution,
    evaluate_checks,
    missing_input,
    unavailable,
)
from tools.release.evidence_verification import verify_report


def verify_evidence(ctx: AuditContext) -> ScopeExecution:
    """Verify the sealed report, evidence bytes, audit chain, and manifest."""
    targets = ctx.targets
    if targets.evidence_report is None:
        return unavailable(
            ctx,
            IntegrityScope.EVIDENCE,
            EVIDENCE_NOT_CONFIGURED,
            "no evidence report is configured; evidence integrity was not verified",
            details={"configured": False},
        )
    ctx.check_budget()
    try:
        result = verify_report(
            targets.evidence_report,
            manifest_path=targets.evidence_manifest,
            integrity_path=targets.evidence_integrity,
            evidence_root=targets.evidence_root,
            audit_path=targets.evidence_audit,
            generated_at=ctx.now(),
        )
    except (AuditCancelledError, AuditTimeoutError):
        raise
    except FileNotFoundError:
        return missing_input(
            ctx,
            IntegrityScope.EVIDENCE,
            EVIDENCE_MISSING,
            "the configured evidence report is missing",
            artifact_id=safe_artifact_id(targets.evidence_report, roots=targets.safe_roots),
        )
    except Exception as exc:
        return missing_input(
            ctx,
            IntegrityScope.EVIDENCE,
            EVIDENCE_UNAVAILABLE,
            f"evidence verification could not run ({type(exc).__name__})",
            artifact_id=safe_artifact_id(targets.evidence_report, roots=targets.safe_roots),
        )

    report_artifact = safe_artifact_id(targets.evidence_report, roots=targets.safe_roots)
    evaluation = evaluate_checks(
        ctx,
        IntegrityScope.EVIDENCE,
        result.checks,
        outcome=result.outcome,
        reason_codes=result.reason_codes,
        default_reason=EVIDENCE_MISSING,
        artifact_id=report_artifact,
    )
    evidence_count = len(result.evidence)
    details: dict[str, Any] = {
        "evidence_count": evidence_count,
        "report_artifact": report_artifact,
        "manifest_configured": targets.evidence_manifest is not None,
        "audit_chain_configured": targets.evidence_audit is not None,
        "assurance": result.assurance,
        "limitations": [str(item)[:300] for item in result.limitations[:20]],
        "findings_truncated": False,
    }
    status = evaluation.status
    findings = list(evaluation.findings)
    if len(findings) > ctx.max_findings:
        findings = findings[: ctx.max_findings]
        details["findings_truncated"] = True
    return ScopeExecution(
        status=status,
        checks_total=evaluation.checks_total,
        checks_failed=evaluation.checks_failed,
        artifacts_checked=evidence_count,
        findings=findings,
        reason_codes=evaluation.reason_codes,
        details=details,
    ).finalize()


def evidence_scope_finding(
    ctx: AuditContext,
    reason_code: str,
    explanation: str,
    *,
    artifact_id: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    """Helper for the runner's concurrent-change finding."""
    return Finding.create(
        audit_run_id=ctx.run_id,
        scope=IntegrityScope.EVIDENCE,
        reason_code=reason_code,
        artifact_id=artifact_id,
        explanation=explanation,
        severity=severity,
        detected_at=ctx.now(),
    )


__all__ = ["evidence_scope_finding", "verify_evidence"]
