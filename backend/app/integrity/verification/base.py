"""Shared execution context and result helpers for V33 scope verifiers.

Verifiers are thin, read-only adapters over the existing V30-V32 verification
tools. They never repair, rewrite, or re-sign anything; every failure is
reported with a stable V33 reason code and a sanitized finding.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

from backend.app.integrity.constants import (
    CHECKPOINT_BINDING_MISMATCH,
    CONCURRENT_EVIDENCE_CHANGE,
    EVIDENCE_MISSING,
    EVIDENCE_UNAVAILABLE,
    VERIFICATION_FAILED,
    IntegrityScope,
    ScopeStatus,
    map_reason_code,
    severity_for_reason,
)
from backend.app.integrity.errors import AuditCancelledError, AuditTimeoutError
from backend.app.integrity.models import Finding, utc_now_iso
from backend.app.integrity.targets import IntegrityTargets

#: NOT_RUN sub-checks that describe deliberately unconfigured optional
#: material. They are recorded as limitations, not as findings; the
#: dedicated TRUST_STATE / EXTERNAL_ANCHOR reporting covers them explicitly.
BENIGN_NOT_RUN_REASONS: frozenset[str] = frozenset(
    {
        "TRUST_STATE_MISSING",
        "EXTERNAL_ANCHOR_UNCONFIGURED",
        "EXTERNAL_ANCHOR_REFERENCE_MISSING",
        "INDEPENDENT_FRESHNESS_UNAVAILABLE",
        "TRANSPARENCY_STATE_MISSING",
        "TREE_HEAD_TRUST_STORE_MISSING",
        "ANCHOR_NOT_CONFIGURED",
    }
)

_FAIL_OUTCOMES = frozenset({"FAIL", "FAILED"})
_UNAVAILABLE_OUTCOMES = frozenset({"UNAVAILABLE"})
_NOT_RUN_OUTCOMES = frozenset({"NOT_RUN"})
_PARTIAL_OUTCOMES = frozenset({"PARTIAL", "SIMULATED"})


@dataclass
class AuditContext:
    """Bounded, cancellable execution context shared by all scopes."""

    run_id: str
    targets: IntegrityTargets
    deadline: float
    cancel_event: threading.Event
    batch_artifacts: int = 500
    max_findings: int = 1000
    clock: Callable[[], str] = utc_now_iso

    def now(self) -> str:
        return self.clock()

    def check_budget(self) -> None:
        if self.cancel_event.is_set():
            raise AuditCancelledError("audit was cancelled")
        if time.monotonic() >= self.deadline:
            raise AuditTimeoutError("audit execution deadline was exceeded")

    def remaining_seconds(self) -> float:
        return max(0.0, float(self.deadline - time.monotonic()))

    def bounded(self, items: Sequence[Any]) -> tuple[list[Any], bool]:
        limit = max(1, int(self.batch_artifacts))
        materialized = list(items)
        return materialized[:limit], len(materialized) > limit


@dataclass
class ScopeExecution:
    """One scope's execution result, ready for persistence."""

    status: ScopeStatus
    checks_total: int = 0
    checks_failed: int = 0
    artifacts_checked: int = 0
    findings: list[Finding] = field(default_factory=list)
    reason_codes: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    error_summary: str | None = None
    truncated: bool = False

    def finalize(self) -> ScopeExecution:
        unique: dict[str, Finding] = {}
        for finding in self.findings:
            unique.setdefault(finding.finding_id, finding)
        self.findings = list(unique.values())
        self.reason_codes = sorted({str(code) for code in self.reason_codes if code})
        return self


@dataclass
class CheckEvaluation:
    status: ScopeStatus
    checks_total: int
    checks_failed: int
    findings: list[Finding]
    reason_codes: list[str]
    limitations: list[str]


def _check_artifact_id(check: Any, fallback: str | None) -> str | None:
    evidence_id = getattr(check, "evidence_id", None)
    if evidence_id:
        text = str(evidence_id)
        parts = text.split(":", 2)
        if len(parts) == 3 and parts[0] == "evidence":
            return parts[2] or fallback
        return text
    name = str(getattr(check, "name", "") or "")
    if name.startswith("evidence:"):
        parts = name.split(":", 2)
        if len(parts) == 3 and parts[2]:
            return parts[2]
    return fallback


def evaluate_checks(
    ctx: AuditContext,
    scope: IntegrityScope,
    checks: Iterable[Any],
    *,
    outcome: str | None = None,
    reason_codes: Iterable[str | None] = (),
    default_reason: str = VERIFICATION_FAILED,
    artifact_id: str | None = None,
    artifact_id_for: Callable[[Any], str | None] | None = None,
    benign_not_run: frozenset[str] = BENIGN_NOT_RUN_REASONS,
) -> CheckEvaluation:
    """Classify verifier checks into one scope status plus sanitized findings.

    Confirmed FAIL checks always dominate. UNAVAILABLE checks produce an
    unavailable scope; required NOT_RUN checks produce a NOT_RUN scope.
    Optional NOT_RUN checks are informational limitations only.
    """
    materialized = list(checks)
    statuses: list[ScopeStatus] = []
    findings: list[Finding] = []
    codes: set[str] = set()
    limitations: list[str] = []
    failed = 0

    normalized_outcome = str(outcome or "").strip().upper()
    if normalized_outcome in _FAIL_OUTCOMES:
        statuses.append(ScopeStatus.FAIL)
    elif normalized_outcome in _UNAVAILABLE_OUTCOMES:
        statuses.append(ScopeStatus.UNAVAILABLE)
    elif normalized_outcome in _NOT_RUN_OUTCOMES:
        statuses.append(ScopeStatus.NOT_RUN)
    elif normalized_outcome in _PARTIAL_OUTCOMES:
        statuses.append(ScopeStatus.PARTIAL)

    for raw_code in reason_codes:
        if raw_code:
            codes.add(map_reason_code(str(raw_code), scope=scope))

    for check in materialized:
        ctx.check_budget()
        check_outcome = str(getattr(check, "outcome", "") or "").strip().upper()
        if check_outcome == "PASS":
            continue
        required = bool(getattr(check, "required", True))
        raw_reason = getattr(check, "reason_code", None) or getattr(check, "event_type", None)
        reason = map_reason_code(str(raw_reason) if raw_reason else None, scope=scope)
        if reason == VERIFICATION_FAILED and default_reason:
            reason = default_reason
        detail = str(getattr(check, "detail", "") or "")
        check_name = str(getattr(check, "name", "") or "")
        resolved_artifact = (
            artifact_id_for(check) if artifact_id_for is not None else _check_artifact_id(check, artifact_id)
        )
        if check_outcome in _NOT_RUN_OUTCOMES:
            raw_text = str(raw_reason or "").strip().upper()
            if not required or raw_text in benign_not_run or reason in benign_not_run:
                limitations.append(f"{check_name}: {detail}".strip(": "))
                continue
            statuses.append(ScopeStatus.NOT_RUN)
            failed += 1
            codes.add(reason)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=scope,
                    reason_code=reason,
                    artifact_id=resolved_artifact,
                    explanation=f"{check_name}: {detail}" if detail else check_name,
                    severity=severity_for_reason(reason),
                    detected_at=ctx.now(),
                )
            )
            continue
        if check_outcome in _FAIL_OUTCOMES:
            statuses.append(ScopeStatus.FAIL)
            failed += 1
            codes.add(reason)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=scope,
                    reason_code=reason,
                    artifact_id=resolved_artifact,
                    explanation=f"{check_name}: {detail}" if detail else check_name,
                    severity=severity_for_reason(reason),
                    detected_at=ctx.now(),
                )
            )
            continue
        if check_outcome in _UNAVAILABLE_OUTCOMES:
            statuses.append(ScopeStatus.UNAVAILABLE)
            failed += 1
            codes.add(reason)
            findings.append(
                Finding.create(
                    audit_run_id=ctx.run_id,
                    scope=scope,
                    reason_code=reason,
                    artifact_id=resolved_artifact,
                    explanation=f"{check_name}: {detail}" if detail else check_name,
                    severity=severity_for_reason(reason),
                    detected_at=ctx.now(),
                )
            )
            continue
        # Unknown/SIMULATED outcomes never count as a pass.
        statuses.append(ScopeStatus.PARTIAL)
        failed += 1
        codes.add(reason)
        findings.append(
            Finding.create(
                audit_run_id=ctx.run_id,
                scope=scope,
                reason_code=reason,
                artifact_id=resolved_artifact,
                explanation=f"{check_name}: {detail}" if detail else check_name,
                severity=severity_for_reason(reason),
                detected_at=ctx.now(),
            )
        )

    if ScopeStatus.FAIL in statuses:
        status = ScopeStatus.FAIL
    elif ScopeStatus.UNAVAILABLE in statuses:
        status = ScopeStatus.UNAVAILABLE
    elif ScopeStatus.PARTIAL in statuses:
        status = ScopeStatus.PARTIAL
    elif ScopeStatus.NOT_RUN in statuses:
        status = ScopeStatus.NOT_RUN
    else:
        status = ScopeStatus.PASS

    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.finding_id, finding)
    return CheckEvaluation(
        status=status,
        checks_total=len(materialized),
        checks_failed=failed,
        findings=list(unique.values()),
        reason_codes=sorted(codes),
        limitations=limitations,
    )


def combine_statuses(statuses: Sequence[ScopeStatus]) -> ScopeStatus:
    """Combine per-artifact outcomes without hiding partial coverage."""
    materialized = list(statuses)
    if not materialized:
        return ScopeStatus.NOT_RUN
    if ScopeStatus.FAIL in materialized:
        return ScopeStatus.FAIL
    if ScopeStatus.PASS in materialized and any(status is not ScopeStatus.PASS for status in materialized):
        return ScopeStatus.PARTIAL
    if all(status is ScopeStatus.PASS for status in materialized):
        return ScopeStatus.PASS
    if all(status is ScopeStatus.UNAVAILABLE for status in materialized):
        return ScopeStatus.UNAVAILABLE
    if all(status is ScopeStatus.NOT_RUN for status in materialized):
        return ScopeStatus.NOT_RUN
    return ScopeStatus.PARTIAL


def unavailable(
    ctx: AuditContext,
    scope: IntegrityScope,
    reason_code: str,
    explanation: str,
    *,
    artifact_id: str | None = None,
    details: dict[str, Any] | None = None,
    finding: bool = False,
) -> ScopeExecution:
    payload = dict(details or {})
    payload.setdefault("reason_code", reason_code)
    findings: list[Finding] = []
    if finding:
        findings.append(
            Finding.create(
                audit_run_id=ctx.run_id,
                scope=scope,
                reason_code=reason_code,
                artifact_id=artifact_id,
                explanation=explanation,
                severity=severity_for_reason(reason_code),
                detected_at=ctx.now(),
            )
        )
    return ScopeExecution(
        status=ScopeStatus.UNAVAILABLE,
        findings=findings,
        reason_codes=[reason_code],
        details=payload,
        error_summary=explanation[:500],
    ).finalize()


def not_run(
    ctx: AuditContext,
    scope: IntegrityScope,
    reason_code: str,
    explanation: str,
    *,
    artifact_id: str | None = None,
    details: dict[str, Any] | None = None,
    finding: bool = True,
) -> ScopeExecution:
    payload = dict(details or {})
    payload.setdefault("reason_code", reason_code)
    findings: list[Finding] = []
    if finding:
        findings.append(
            Finding.create(
                audit_run_id=ctx.run_id,
                scope=scope,
                reason_code=reason_code,
                artifact_id=artifact_id,
                explanation=explanation,
                severity=severity_for_reason(reason_code),
                detected_at=ctx.now(),
            )
        )
    return ScopeExecution(
        status=ScopeStatus.NOT_RUN,
        findings=findings,
        reason_codes=[reason_code],
        details=payload,
        error_summary=explanation[:500],
    ).finalize()


def failed(
    ctx: AuditContext,
    scope: IntegrityScope,
    reason_code: str,
    explanation: str,
    *,
    artifact_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> ScopeExecution:
    return ScopeExecution(
        status=ScopeStatus.FAIL,
        checks_total=1,
        checks_failed=1,
        findings=[
            Finding.create(
                audit_run_id=ctx.run_id,
                scope=scope,
                reason_code=reason_code,
                artifact_id=artifact_id,
                explanation=explanation,
                severity=severity_for_reason(reason_code),
                detected_at=ctx.now(),
            )
        ],
        reason_codes=[reason_code],
        details=dict(details or {}),
        error_summary=explanation[:500],
    ).finalize()


def missing_input(
    ctx: AuditContext,
    scope: IntegrityScope,
    reason_code: str,
    explanation: str,
    *,
    artifact_id: str | None = None,
    details: dict[str, Any] | None = None,
) -> ScopeExecution:
    """A configured input that is missing/unreadable is never a pass."""
    return unavailable(
        ctx,
        scope,
        reason_code,
        explanation,
        artifact_id=artifact_id,
        details=details,
        finding=True,
    )


def transient_reason(exc: BaseException) -> str:
    if isinstance(exc, FileNotFoundError):
        return EVIDENCE_MISSING
    if isinstance(exc, OSError):
        return EVIDENCE_UNAVAILABLE
    if isinstance(exc, (AuditCancelledError, AuditTimeoutError)):
        raise exc
    return VERIFICATION_FAILED


def concurrent_change_execution(
    ctx: AuditContext,
    *,
    scope: IntegrityScope,
    changed: Sequence[str],
) -> ScopeExecution:
    artifacts = ", ".join(sorted(changed)[:10])
    explanation = (
        "protected audit inputs changed while the audit was running; results are not "
        f"reliable until the inputs are quiescent ({artifacts})"
    )
    return ScopeExecution(
        status=ScopeStatus.PARTIAL,
        checks_total=1,
        checks_failed=1,
        findings=[
            Finding.create(
                audit_run_id=ctx.run_id,
                scope=scope,
                reason_code=CONCURRENT_EVIDENCE_CHANGE,
                artifact_id=None,
                explanation=explanation,
                severity=severity_for_reason(CONCURRENT_EVIDENCE_CHANGE),
                detected_at=ctx.now(),
            )
        ],
        reason_codes=[CONCURRENT_EVIDENCE_CHANGE],
        details={"changed_inputs": sorted(changed)[:50], "changed_count": len(changed)},
        error_summary=explanation[:500],
    ).finalize()


def checkpoint_binding_reason(exc: BaseException) -> str:
    return CHECKPOINT_BINDING_MISMATCH


__all__ = [
    "AuditContext",
    "BENIGN_NOT_RUN_REASONS",
    "CheckEvaluation",
    "ScopeExecution",
    "checkpoint_binding_reason",
    "combine_statuses",
    "concurrent_change_execution",
    "evaluate_checks",
    "failed",
    "missing_input",
    "not_run",
    "transient_reason",
    "unavailable",
]
