"""Bounded V33 continuous-audit runner.

The runner is the only component that writes audit records, and it writes
them exclusively to the isolated monitoring store. Every protected V30-V32
input is read-only. Scope verifiers are invoked behind cancellation, timeout,
batch, retry, and finding bounds; failures are never converted into passes.
"""

from __future__ import annotations

import hashlib
import threading
import time
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from backend.app.core.config import Settings
from backend.app.core.logging import get_logger
from backend.app.integrity.constants import (
    AUDIT_CANCELLED,
    AUDIT_EXECUTION_ERROR,
    AUDIT_RETRY_EXHAUSTED,
    AUDIT_TIMEOUT,
    CONCURRENT_EVIDENCE_CHANGE,
    FINDINGS_TRUNCATED,
    AuditStatus,
    AuditTrigger,
    IntegrityScope,
    ScopeStatus,
    aggregate_overall_status,
    expand_scopes,
    severity_for_reason,
)
from backend.app.integrity.errors import (
    AuditCancelledError,
    AuditTimeoutError,
    DuplicateAuditRunError,
    InvalidAuditScopeError,
    MonitoringStoreError,
    MonitoringStoreUnavailable,
)
from backend.app.integrity.models import (
    AuditRun,
    Finding,
    ScopeResult,
    count_findings,
    utc_now_iso,
)
from backend.app.integrity.store import MonitoringStore
from backend.app.integrity.targets import IntegrityTargets
from backend.app.integrity.verification import (
    build_trust_overview,
    capture_inputs,
    verify_consistency_proofs,
    verify_evidence,
    verify_inclusion_proofs,
    verify_signed_checkpoints,
    verify_transparency_log,
    verify_tree_heads,
    verify_trust_state,
)
from backend.app.integrity.verification.base import (
    AuditContext,
    ScopeExecution,
    concurrent_change_execution,
    not_run,
    unavailable,
)

logger = get_logger("industrial-vision.integrity")

SCOPE_VERIFIERS = {
    IntegrityScope.EVIDENCE: verify_evidence,
    IntegrityScope.SIGNED_CHECKPOINTS: verify_signed_checkpoints,
    IntegrityScope.TRANSPARENCY_LOG: verify_transparency_log,
    IntegrityScope.TREE_HEADS: verify_tree_heads,
    IntegrityScope.INCLUSION_PROOFS: verify_inclusion_proofs,
    IntegrityScope.CONSISTENCY_PROOFS: verify_consistency_proofs,
    IntegrityScope.TRUST_STATE: verify_trust_state,
}


def _run_id_for_key(idempotency_key: str) -> str:
    digest = hashlib.sha256(str(idempotency_key).encode("utf-8")).hexdigest()[:24]
    return f"audit-{digest}"


def _new_run_id() -> str:
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%f")
    return f"audit-{stamp}-{uuid.uuid4().hex[:8]}"


class AuditRunner:
    """Execute bounded, read-only integrity audits."""

    def __init__(
        self,
        *,
        settings: Settings,
        store: MonitoringStore,
        notifier: Any | None = None,
    ) -> None:
        self._settings = settings
        self._store = store
        self._notifier = notifier
        self._targets = IntegrityTargets.from_settings(settings)
        self._cancel_events: dict[str, threading.Event] = {}
        self._lock = threading.RLock()

    @property
    def targets(self) -> IntegrityTargets:
        return self._targets

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def execute(
        self,
        *,
        scopes: Sequence[str | IntegrityScope] | str | IntegrityScope | None = None,
        trigger: AuditTrigger | str = AuditTrigger.MANUAL,
        requested_by: str | None = None,
        schedule_slot: str | None = None,
        idempotency_key: str | None = None,
    ) -> AuditRun:
        if not self._settings.integrity_monitoring_enabled:
            raise MonitoringStoreUnavailable("integrity monitoring is disabled")
        try:
            expanded = expand_scopes(scopes, max_scopes=int(self._settings.integrity_max_scopes))
        except ValueError as exc:
            raise InvalidAuditScopeError(str(exc)) from None
        trigger_value = (
            trigger if isinstance(trigger, AuditTrigger) else AuditTrigger(str(trigger).strip().upper())
        )

        if schedule_slot is not None:
            existing = self._store.get_run_by_schedule_slot(str(schedule_slot))
            if existing is not None:
                return existing

        run_id = _run_id_for_key(idempotency_key) if idempotency_key else _new_run_id()
        if idempotency_key:
            existing = self._store.get_run(run_id)
            if existing is not None:
                return existing

        now = utc_now_iso()
        run = AuditRun(
            audit_run_id=run_id,
            trigger=trigger_value,
            requested_scopes=list(expanded),
            completed_scopes=[],
            status=AuditStatus.RUNNING,
            started_at=now,
            created_at=now,
            requested_by=str(requested_by)[:128] if requested_by else None,
            schedule_slot=str(schedule_slot)[:64] if schedule_slot else None,
        )
        owner = f"{run_id}:{uuid.uuid4().hex[:8]}"
        lease_ttl = max(60.0, float(self._settings.integrity_audit_timeout_seconds) * 2.0)
        lease = self._store.acquire_execution_lease(
            owner,
            slots=int(self._settings.integrity_max_concurrent_runs),
            ttl_seconds=lease_ttl,
        )
        if lease is None:
            active = self._store.find_active_run()
            raise DuplicateAuditRunError(active.audit_run_id if active is not None else None)
        created = False
        try:
            created = self._store.create_run(run)
            if not created:
                existing = self._store.get_run(run_id)
                if existing is None and schedule_slot is not None:
                    existing = self._store.get_run_by_schedule_slot(str(schedule_slot))
                if existing is not None:
                    return existing
                raise DuplicateAuditRunError(run_id)
            return self._execute_run(run, expanded, lease, owner)
        finally:
            try:
                self._store.release_execution_lease(lease, owner)
            except MonitoringStoreError:
                logger.warning("integrity lease release failed")

    def cancel(self, audit_run_id: str) -> bool:
        with self._lock:
            event = self._cancel_events.get(str(audit_run_id))
        if event is None:
            return False
        event.set()
        return True

    def is_running(self, audit_run_id: str) -> bool:
        with self._lock:
            return str(audit_run_id) in self._cancel_events

    # ------------------------------------------------------------------
    # Execution internals
    # ------------------------------------------------------------------
    def _execute_run(
        self,
        run: AuditRun,
        scopes: Sequence[IntegrityScope],
        lease: str,
        owner: str,
    ) -> AuditRun:
        started_monotonic = time.monotonic()
        cancel_event = threading.Event()
        with self._lock:
            self._cancel_events[run.audit_run_id] = cancel_event
            running_now = len(self._cancel_events)
        try:
            from backend.app.core.metrics import set_integrity_running_audits

            set_integrity_running_audits(running_now)
        except Exception:
            pass
        ctx = AuditContext(
            run_id=run.audit_run_id,
            targets=self._targets,
            deadline=started_monotonic + float(self._settings.integrity_audit_timeout_seconds),
            cancel_event=cancel_event,
            batch_artifacts=int(self._settings.integrity_batch_artifacts),
            max_findings=int(self._settings.integrity_max_findings),
        )
        before = capture_inputs(self._targets, batch_artifacts=int(self._settings.integrity_batch_artifacts))
        scope_results: list[ScopeResult] = []
        all_findings: dict[str, Finding] = {}
        cancelled = False
        timed_out = False
        retry_total = 0
        fatal_error: str | None = None

        try:
            for scope in scopes:
                if cancelled or timed_out:
                    execution = not_run(
                        ctx,
                        scope,
                        AUDIT_CANCELLED if cancelled else AUDIT_TIMEOUT,
                        "scope was not run because the audit was cancelled"
                        if cancelled
                        else "scope was not run because the audit deadline was exceeded",
                        finding=False,
                    )
                    scope_results.append(
                        self._persist_scope(run.audit_run_id, scope, execution, started_at=utc_now_iso())
                    )
                    continue
                scope_started = utc_now_iso()
                scope_monotonic = time.monotonic()
                retries = 0
                try:
                    execution, retries = self._execute_scope(scope, ctx)
                    retry_total += retries
                except AuditCancelledError:
                    cancelled = True
                    execution = not_run(
                        ctx,
                        scope,
                        AUDIT_CANCELLED,
                        "audit was cancelled during scope execution",
                    )
                except AuditTimeoutError:
                    timed_out = True
                    execution = not_run(
                        ctx,
                        scope,
                        AUDIT_TIMEOUT,
                        "audit deadline was exceeded during scope execution",
                    )
                if retries and execution.status is ScopeStatus.UNAVAILABLE:
                    execution.reason_codes = sorted(set(execution.reason_codes) | {AUDIT_RETRY_EXHAUSTED})
                duration_ms = int((time.monotonic() - scope_monotonic) * 1000)
                result = self._persist_scope(
                    run.audit_run_id,
                    scope,
                    execution,
                    started_at=scope_started,
                    duration_ms=duration_ms,
                )
                scope_results.append(result)
                for finding in execution.findings:
                    all_findings.setdefault(finding.finding_id, finding)
                self._heartbeat(run.audit_run_id, lease, owner)

            after = capture_inputs(
                self._targets, batch_artifacts=int(self._settings.integrity_batch_artifacts)
            )
            changed = before.changes_since(after)
            if changed:
                target_scope = IntegrityScope.EVIDENCE if IntegrityScope.EVIDENCE in scopes else scopes[0]
                execution = concurrent_change_execution(ctx, scope=target_scope, changed=changed)
                for finding in execution.findings:
                    all_findings.setdefault(finding.finding_id, finding)
                self._persist_findings(run.audit_run_id, execution.findings)
                self._downgrade_scope(run.audit_run_id, scope_results, target_scope, changed)

            status = aggregate_overall_status(
                [result.status.value for result in scope_results],
                cancelled=cancelled,
                timed_out=timed_out,
                started=bool(scope_results),
            )
            if changed and status is AuditStatus.PASS:
                status = AuditStatus.PARTIAL
            if cancelled:
                status = (
                    AuditStatus.PARTIAL
                    if any(result.status is not ScopeStatus.NOT_RUN for result in scope_results)
                    else AuditStatus.NOT_RUN
                )
            if timed_out and status is AuditStatus.PASS:
                status = AuditStatus.PARTIAL
            findings = list(all_findings.values())[: int(self._settings.integrity_max_findings)]
            finding_counts, reason_counts = count_findings(findings)
            run.completed_scopes = [
                result.scope for result in scope_results if result.status is not ScopeStatus.NOT_RUN
            ]
            run.status = status
            run.completed_at = utc_now_iso()
            run.duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            run.cancelled = cancelled
            run.timed_out = timed_out
            run.retry_count = retry_total
            run.artifacts_checked = sum(result.artifacts_checked for result in scope_results)
            run.finding_counts = finding_counts
            run.reason_code_counts = reason_counts
            run.error_summary = (
                "audit was cancelled"
                if cancelled
                else "audit deadline was exceeded"
                if timed_out
                else fatal_error
            )
            run.assurance = self._assurance(status)
            run.external_anchor_configured = False
            self._store.complete_run(run)
            self._record_metrics(run, scope_results)
            self._notify(run, findings)
            return run
        except MonitoringStoreUnavailable:
            raise
        except Exception as exc:  # never leak a partial RUNNING record silently
            fatal_error = f"audit execution failed ({type(exc).__name__})"
            logger.warning("integrity audit %s failed: %s", run.audit_run_id, type(exc).__name__)
            execution = unavailable(
                ctx,
                scopes[0] if scopes else IntegrityScope.EVIDENCE,
                AUDIT_EXECUTION_ERROR,
                fatal_error,
                finding=True,
            )
            for finding in execution.findings:
                all_findings.setdefault(finding.finding_id, finding)
            try:
                self._persist_findings(run.audit_run_id, execution.findings)
            except MonitoringStoreError:
                pass
            findings = list(all_findings.values())[: int(self._settings.integrity_max_findings)]
            finding_counts, reason_counts = count_findings(findings)
            run.status = AuditStatus.UNAVAILABLE
            run.completed_at = utc_now_iso()
            run.duration_ms = int((time.monotonic() - started_monotonic) * 1000)
            run.completed_scopes = [
                result.scope for result in scope_results if result.status is not ScopeStatus.NOT_RUN
            ]
            run.artifacts_checked = sum(result.artifacts_checked for result in scope_results)
            run.finding_counts = finding_counts
            run.reason_code_counts = reason_counts
            run.error_summary = fatal_error
            run.assurance = self._assurance(AuditStatus.UNAVAILABLE)
            self._store.complete_run(run)
            self._record_metrics(run, scope_results)
            return run
        finally:
            with self._lock:
                self._cancel_events.pop(run.audit_run_id, None)

    def _execute_scope(self, scope: IntegrityScope, ctx: AuditContext) -> tuple[ScopeExecution, int]:
        verifier = SCOPE_VERIFIERS[scope]
        attempts = 1 + int(self._settings.integrity_max_retries)
        retries = 0
        for attempt in range(attempts):
            ctx.check_budget()
            try:
                return verifier(ctx), attempt
            except (AuditCancelledError, AuditTimeoutError):
                raise
            except Exception as exc:
                retries = attempt
                logger.warning(
                    "integrity scope %s attempt %s failed: %s",
                    scope.value,
                    attempt + 1,
                    type(exc).__name__,
                )
                if attempt + 1 >= attempts:
                    execution = unavailable(
                        ctx,
                        scope,
                        AUDIT_EXECUTION_ERROR,
                        f"scope verification failed after retries ({type(exc).__name__})",
                        finding=True,
                    )
                    return execution, retries
        execution = unavailable(
            ctx,
            scope,
            AUDIT_EXECUTION_ERROR,
            "scope verification failed without a result",
            finding=True,
        )
        return execution, retries

    def _persist_scope(
        self,
        audit_run_id: str,
        scope: IntegrityScope,
        execution: ScopeExecution,
        *,
        started_at: str,
        duration_ms: int | None = None,
    ) -> ScopeResult:
        completed_at = utc_now_iso()
        result = ScopeResult(
            audit_run_id=audit_run_id,
            scope=scope,
            status=execution.status,
            started_at=started_at,
            completed_at=completed_at,
            duration_ms=int(duration_ms if duration_ms is not None else 0),
            artifacts_checked=int(execution.artifacts_checked),
            checks_total=int(execution.checks_total),
            checks_failed=int(execution.checks_failed),
            findings_count=len(execution.findings),
            reason_codes=list(execution.reason_codes),
            error_summary=(execution.error_summary or None),
            truncated=bool(execution.truncated),
            details=dict(execution.details),
        )
        self._store.upsert_scope_result(result)
        inserted, truncated = self._persist_findings(audit_run_id, execution.findings)
        if truncated:
            result.truncated = True
            result.details["findings_truncated"] = True
            truncated_finding = Finding.create(
                audit_run_id=audit_run_id,
                scope=scope,
                reason_code=FINDINGS_TRUNCATED,
                explanation="additional findings were not persisted because the finding bound was reached",
                severity=severity_for_reason(FINDINGS_TRUNCATED),
            )
            self._persist_findings(audit_run_id, [truncated_finding])
        return result

    def _persist_findings(self, audit_run_id: str, findings: Sequence[Finding]) -> tuple[int, bool]:
        if not findings:
            return 0, False
        try:
            return self._store.add_findings(findings, max_findings=int(self._settings.integrity_max_findings))
        except MonitoringStoreError:
            logger.warning("integrity finding persistence failed")
            return 0, True

    def _downgrade_scope(
        self,
        audit_run_id: str,
        scope_results: list[ScopeResult],
        scope: IntegrityScope,
        changed: Sequence[str],
    ) -> None:
        for result in scope_results:
            if result.scope is not scope:
                continue
            if result.status is ScopeStatus.PASS:
                result.status = ScopeStatus.PARTIAL
            result.reason_codes = sorted(set(result.reason_codes) | {CONCURRENT_EVIDENCE_CHANGE})
            result.details["concurrent_change"] = sorted(changed)[:20]
            self._store.upsert_scope_result(result)

    def _heartbeat(self, audit_run_id: str, lease: str, owner: str) -> None:
        try:
            self._store.update_run(audit_run_id, heartbeat_at=utc_now_iso())
            self._store.heartbeat_lease(
                lease,
                owner,
                ttl_seconds=max(60.0, float(self._settings.integrity_audit_timeout_seconds) * 2.0),
            )
        except MonitoringStoreError:
            logger.warning("integrity heartbeat failed")

    def _assurance(self, status: AuditStatus) -> Any:
        overview = build_trust_overview(self._targets)
        return overview.assurance

    def _record_metrics(self, run: AuditRun, scope_results: Sequence[ScopeResult]) -> None:
        artifacts_by_scope: dict[str, int] = {}
        failed_scopes: dict[str, int] = {}
        for result in scope_results:
            scope_name = result.scope.value
            artifacts_by_scope[scope_name] = artifacts_by_scope.get(scope_name, 0) + int(
                result.artifacts_checked
            )
            if result.status is not ScopeStatus.PASS:
                failed_scopes[scope_name] = failed_scopes.get(scope_name, 0) + 1
        try:
            from backend.app.core.metrics import (
                record_integrity_audit,
                set_integrity_external_anchor_configured,
                set_integrity_running_audits,
            )

            record_integrity_audit(
                trigger=run.trigger.value,
                status=run.status.value,
                duration_seconds=max(0.0, run.duration_ms / 1000.0),
                artifacts_by_scope=artifacts_by_scope,
                findings_by_severity=run.finding_counts,
                failed_scopes=failed_scopes,
                external_anchor_configured=False,
            )
            set_integrity_external_anchor_configured(False)
            set_integrity_running_audits(max(0, len(self._cancel_events) - 1))
        except Exception:
            pass

    def _notify(self, run: AuditRun, findings: Sequence[Finding]) -> None:
        if self._notifier is None:
            return
        try:
            self._notifier.notify(run, list(findings))
        except Exception as exc:
            logger.warning("integrity alerting failed: %s", type(exc).__name__)


__all__ = ["AuditRunner", "SCOPE_VERIFIERS"]
