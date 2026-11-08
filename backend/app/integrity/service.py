"""Read-oriented V33 integrity service for the authenticated API."""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

from backend.app.core.config import Settings
from backend.app.core.redaction import redact_structure, redact_text
from backend.app.integrity.constants import (
    AuditStatus,
    AuditTrigger,
    IntegrityScope,
    Severity,
    normalize_scope,
)
from backend.app.integrity.errors import (
    AuditRunNotCancellableError,
    AuditRunNotFoundError,
    DuplicateAuditRunError,
    InvalidAuditScopeError,
    MonitoringStoreError,
    MonitoringStoreUnavailable,
)
from backend.app.integrity.models import TrustOverview, utc_now_iso
from backend.app.integrity.runner import AuditRunner
from backend.app.integrity.scheduler import IntegrityScheduler
from backend.app.integrity.store import MonitoringStore, status_from_counts
from backend.app.integrity.verification import build_trust_overview


def _page_bounds(
    page: int, page_size: int | None, *, default: int = 20, maximum: int = 100
) -> tuple[int, int]:
    resolved = default if page_size is None else page_size
    return max(1, int(page)), min(maximum, max(1, int(resolved)))


def _validate_status(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    text = str(value).strip().upper()
    if text not in {status.value for status in AuditStatus}:
        raise ValueError(f"unknown audit status: {text}")
    return text


def _validate_trigger(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    text = str(value).strip().upper()
    if text not in {trigger.value for trigger in AuditTrigger}:
        raise ValueError(f"unknown audit trigger: {text}")
    return text


def _validate_scope(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    return normalize_scope(value).value


def _validate_severity(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    text = str(value).strip().upper()
    if text not in {severity.value for severity in Severity}:
        raise ValueError(f"unknown finding severity: {text}")
    return text


class IntegrityService:
    """Thin orchestration over the monitoring store, runner, and scheduler."""

    def __init__(
        self,
        *,
        settings: Settings,
        store: MonitoringStore,
        runner: AuditRunner,
        scheduler: IntegrityScheduler | None = None,
    ) -> None:
        self._settings = settings
        self._store = store
        self._runner = runner
        self._scheduler = scheduler

    @property
    def store(self) -> MonitoringStore:
        return self._store

    @property
    def runner(self) -> AuditRunner:
        return self._runner

    # ------------------------------------------------------------------
    # Status and summary
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        if not self._settings.integrity_monitoring_enabled:
            return self._disabled_status("integrity monitoring is disabled")
        try:
            summary = self._store.summary()
        except (MonitoringStoreUnavailable, MonitoringStoreError) as exc:
            return self._unavailable_status(f"monitoring store unavailable ({type(exc).__name__})")
        trust = self._trust_overview()
        verified = summary.get("verified", {}) or {}
        by_severity = self._severity_counts(summary.get("by_severity", {}) or {})
        scheduler_status = self._scheduler_status()
        return redact_structure(
            {
                "enabled": True,
                "store_status": "AVAILABLE",
                "store_error": None,
                "latest_audit": summary.get("latest_audit"),
                "last_success": summary.get("last_success"),
                "last_failure": summary.get("last_failure"),
                "running_audits": int(summary.get("running_audits", 0)),
                "total_audits": int(summary.get("total_runs", 0)),
                "total_audited_artifacts": int(summary.get("total_audited_artifacts", 0)),
                "verified_evidence_count": int(verified.get(IntegrityScope.EVIDENCE.value, 0)),
                "verified_checkpoint_count": int(verified.get(IntegrityScope.SIGNED_CHECKPOINTS.value, 0)),
                "verified_tree_head_count": int(verified.get(IntegrityScope.TREE_HEADS.value, 0)),
                "open_findings": int(summary.get("open_findings", 0)),
                "findings_by_severity": by_severity,
                "trust": trust.to_dict(),
                "scheduler": scheduler_status,
                "external_anchor_configured": False,
                "assurance": trust.assurance.value,
                "generated_at": utc_now_iso(),
            }
        )

    def summary(self) -> dict[str, Any]:
        try:
            summary = self._store.summary()
        except (MonitoringStoreUnavailable, MonitoringStoreError) as exc:
            raise MonitoringStoreUnavailable(str(exc)) from None
        payload = dict(summary)
        payload["by_status"] = status_from_counts(summary.get("by_status", {}) or {})
        payload["by_severity"] = self._severity_counts(summary.get("by_severity", {}) or {})
        payload["scheduler"] = self._scheduler_status()
        payload["retention_days"] = int(self._settings.integrity_retention_days)
        payload["page_size_default"] = int(self._settings.integrity_api_page_size)
        payload["page_size_max"] = 100
        payload["external_anchor_configured"] = False
        payload["assurance"] = self._trust_overview().assurance.value
        payload["generated_at"] = utc_now_iso()
        return redact_structure(payload)

    # ------------------------------------------------------------------
    # Audit history
    # ------------------------------------------------------------------
    def list_audits(
        self,
        *,
        status: str | None = None,
        scope: str | None = None,
        trigger: str | None = None,
        started_from: str | None = None,
        started_to: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        page, page_size = _page_bounds(
            page, page_size, default=int(self._settings.integrity_api_page_size), maximum=100
        )
        runs, total = self._store.list_runs(
            status=_validate_status(status),
            scope=_validate_scope(scope),
            trigger=_validate_trigger(trigger),
            started_from=started_from,
            started_to=started_to,
            page=page,
            page_size=page_size,
        )
        return {
            "items": [run.to_dict() for run in runs],
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, math.ceil(total / page_size)) if total else 0,
        }

    def history(self, *, page: int = 1, page_size: int | None = None) -> dict[str, Any]:
        return self.list_audits(page=page, page_size=page_size)

    def get_audit(self, audit_id: str) -> dict[str, Any]:
        detail = self._store.get_run_detail(str(audit_id))
        if detail is None:
            raise AuditRunNotFoundError(f"audit run {audit_id!r} was not found")
        return redact_structure(detail)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------
    def list_findings(
        self,
        *,
        severity: str | None = None,
        reason_code: str | None = None,
        scope: str | None = None,
        audit_run_id: str | None = None,
        artifact_id: str | None = None,
        detected_from: str | None = None,
        detected_to: str | None = None,
        page: int = 1,
        page_size: int | None = None,
    ) -> dict[str, Any]:
        page, page_size = _page_bounds(
            page, page_size, default=int(self._settings.integrity_api_page_size), maximum=100
        )
        items, total = self._store.list_findings(
            severity=_validate_severity(severity),
            reason_code=(str(reason_code).strip().upper() if reason_code else None),
            scope=_validate_scope(scope),
            audit_run_id=str(audit_run_id) if audit_run_id else None,
            artifact_id=str(artifact_id) if artifact_id else None,
            detected_from=detected_from,
            detected_to=detected_to,
            page=page,
            page_size=page_size,
        )
        return {
            "items": [finding.to_dict() for finding in items],
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": max(1, math.ceil(total / page_size)) if total else 0,
        }

    # ------------------------------------------------------------------
    # Execution control
    # ------------------------------------------------------------------
    def run_audit(
        self,
        *,
        scopes: Sequence[str] | str | None,
        requested_by: str | None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        try:
            run = self._runner.execute(
                scopes=scopes,
                trigger=AuditTrigger.MANUAL,
                requested_by=requested_by,
                idempotency_key=idempotency_key,
            )
        except InvalidAuditScopeError:
            raise
        except DuplicateAuditRunError:
            raise
        except (MonitoringStoreUnavailable, MonitoringStoreError) as exc:
            raise MonitoringStoreUnavailable(str(exc)) from None
        payload = run.to_dict(include_details=True)
        try:
            detail = self._store.get_run_detail(run.audit_run_id)
        except (MonitoringStoreUnavailable, MonitoringStoreError):
            detail = None
        if detail:
            payload["scope_results"] = detail.get("scope_results", [])
            payload["findings"] = detail.get("findings", [])
            payload["findings_total"] = detail.get("findings_total", 0)
        return payload

    def cancel_audit(self, audit_id: str) -> bool:
        run = self._store.get_run(str(audit_id))
        if run is None:
            raise AuditRunNotFoundError(f"audit run {audit_id!r} was not found")
        if run.status is not AuditStatus.RUNNING:
            raise AuditRunNotCancellableError("only a running audit can be cancelled")
        if not self._runner.cancel(str(audit_id)):
            raise AuditRunNotCancellableError(
                "the running audit is owned by another process and cannot be cancelled here"
            )
        return True

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _trust_overview(self) -> TrustOverview:
        try:
            return build_trust_overview(self._runner.targets)
        except Exception:
            return TrustOverview(
                external_anchor_detail="trust overview is unavailable",
                limitations=["trust overview could not be read"],
            )

    def _scheduler_status(self) -> dict[str, Any]:
        if self._scheduler is None:
            return {
                "enabled": bool(self._settings.integrity_scheduler_enabled),
                "state": "NOT_CONFIGURED",
                "interval_seconds": float(self._settings.integrity_scheduler_interval_seconds),
            }
        return self._scheduler.status()

    @staticmethod
    def _severity_counts(values: dict[str, Any]) -> dict[str, int]:
        return {severity.value: int(values.get(severity.value, 0) or 0) for severity in Severity}

    def _disabled_status(self, message: str) -> dict[str, Any]:
        trust = TrustOverview(
            external_anchor_detail="integrity monitoring is disabled",
            limitations=["integrity monitoring is disabled"],
        )
        return {
            "enabled": False,
            "store_status": "DISABLED",
            "store_error": redact_text(message),
            "latest_audit": None,
            "last_success": None,
            "last_failure": None,
            "running_audits": 0,
            "total_audits": 0,
            "total_audited_artifacts": 0,
            "verified_evidence_count": 0,
            "verified_checkpoint_count": 0,
            "verified_tree_head_count": 0,
            "open_findings": 0,
            "findings_by_severity": {severity.value: 0 for severity in Severity},
            "trust": trust.to_dict(),
            "scheduler": self._scheduler_status(),
            "external_anchor_configured": False,
            "assurance": trust.assurance.value,
            "generated_at": utc_now_iso(),
        }

    def _unavailable_status(self, message: str) -> dict[str, Any]:
        trust = TrustOverview(
            external_anchor_detail="monitoring store is unavailable",
            limitations=["audit history is unavailable"],
        )
        return {
            "enabled": bool(self._settings.integrity_monitoring_enabled),
            "store_status": "UNAVAILABLE",
            "store_error": redact_text(message),
            "latest_audit": None,
            "last_success": None,
            "last_failure": None,
            "running_audits": 0,
            "total_audits": 0,
            "total_audited_artifacts": 0,
            "verified_evidence_count": 0,
            "verified_checkpoint_count": 0,
            "verified_tree_head_count": 0,
            "open_findings": 0,
            "findings_by_severity": {severity.value: 0 for severity in Severity},
            "trust": trust.to_dict(),
            "scheduler": self._scheduler_status(),
            "external_anchor_configured": False,
            "assurance": trust.assurance.value,
            "generated_at": utc_now_iso(),
        }


__all__ = ["IntegrityService"]
