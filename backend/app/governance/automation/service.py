"""V36 governance automation application service.

Coordinates schedules, manual runs, retries, cancellation, and reporting on top
of the shared repository, executor, scheduler, and V35 governance service. The
service never approves or releases a hold, decides a disposition, generates a
forensic export, or deletes any record.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.core.metrics import (
    record_governance_automation_snapshot,
)
from backend.app.domain.common import utcnow
from backend.app.governance.automation.constants import (
    AUTOMATION_ASSURANCE,
    AUTOMATION_LIMITATIONS,
    AUTOMATION_NON_CLAIMS,
    JOB_TYPE_VALUES,
    RETRYABLE_JOB_STATUSES,
    SNAPSHOT_TYPE_COMPLIANCE_SUMMARY,
    JobTrigger,
    normalize_utc,
    validate_interval_minutes,
    validate_schedule_config,
)
from backend.app.governance.automation.errors import (
    AutomationDisabledError,
    AutomationValidationError,
    JobNotFoundError,
    JobStateError,
    RetryExhaustedError,
    ScheduleNotFoundError,
    UnsupportedJobTypeError,
)
from backend.app.governance.automation.executor import GovernanceJobExecutor
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.governance.automation.scheduler import GovernanceAutomationScheduler
from backend.app.governance.constants import GovernanceAuditEventType
from backend.app.governance.service import GovernanceService

logger = get_logger(__name__)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return normalize_utc(value).isoformat().replace("+00:00", "Z")


class GovernanceAutomationService:
    """Application-level API over schedules, jobs, and snapshots."""

    def __init__(
        self,
        *,
        settings: Any,
        repository: GovernanceAutomationRepository,
        executor: GovernanceJobExecutor,
        scheduler: GovernanceAutomationScheduler | None,
        governance_service: GovernanceService,
        integrity_service: Any | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._settings = settings
        self._repository = repository
        self._executor = executor
        self._scheduler = scheduler
        self._governance = governance_service
        self._integrity = integrity_service
        self._clock = clock or utcnow

    # ------------------------------------------------------------------
    # Status and health
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        schedules = self._repository.list_schedules()
        scheduler_status = (
            self._scheduler.status()
            if self._scheduler is not None
            else {
                "enabled": False,
                "state": "DISABLED",
                "running": False,
                "name": "governance-automation",
                "queue": self._repository.queue_counts(),
                "stale_jobs": self._repository.stale_job_count(now=self._clock()),
            }
        )
        return {
            "enabled": bool(self._settings.governance_automation_enabled),
            "assurance": AUTOMATION_ASSURANCE,
            "scheduler": scheduler_status,
            "schedule_count": len(schedules),
            "enabled_schedule_count": sum(1 for item in schedules if item["enabled"]),
            "schedules": schedules,
            "queue": self._repository.queue_counts(),
            "job_count": self._repository.count_jobs(),
            "snapshot_count": self._repository.count_snapshots(),
            "last_jobs": self._repository.latest_jobs_by_type(),
            "stale_jobs": self._repository.stale_job_count(now=self._clock()),
            "supported_job_types": sorted(self._executor.supported_job_types()),
            "non_claims": list(AUTOMATION_NON_CLAIMS),
            "limitations": list(AUTOMATION_LIMITATIONS),
        }

    def health(self) -> dict[str, Any]:
        governance_audit: dict[str, Any] = {
            "outcome": "UNAVAILABLE",
            "checked": 0,
            "verified": 0,
        }
        try:
            governance_audit = dict(self._governance.status().get("audit_integrity") or governance_audit)
        except Exception as exc:  # noqa: BLE001 - health must never raise
            governance_audit["error"] = type(exc).__name__
        integrity_status: dict[str, Any] = {"status": "DISABLED"}
        if self._integrity is not None:
            try:
                raw = self._integrity.status()
                latest = raw.get("latest_audit") or {}
                latest_status = str(
                    (latest.get("status") if isinstance(latest, Mapping) else None) or "NOT_RUN"
                ).upper()
                integrity_status = {
                    "status": "OK" if latest_status == "PASS" else "NOT_PASS",
                    "latest_audit_status": latest_status,
                    "store_status": str(raw.get("store_status") or "UNKNOWN"),
                    "open_findings": int(raw.get("open_findings", 0) or 0),
                }
            except Exception as exc:  # noqa: BLE001 - health must never raise
                integrity_status = {
                    "status": "UNAVAILABLE",
                    "error": type(exc).__name__,
                }
        scheduler = (
            self._scheduler.status()
            if self._scheduler is not None
            else {"enabled": False, "state": "DISABLED", "running": False}
        )
        audit_ok = str(governance_audit.get("outcome") or "").upper() == "OK"
        if not audit_ok:
            overall = "FAILED"
        elif bool(self._settings.governance_automation_enabled) and not bool(scheduler.get("running")):
            overall = "DEGRADED"
        elif integrity_status.get("status") != "OK":
            overall = "DEGRADED"
        else:
            overall = "OK"
        return {
            "enabled": bool(self._settings.governance_automation_enabled),
            "overall_status": overall,
            "scheduler": scheduler,
            "governance_audit": governance_audit,
            "integrity": integrity_status,
            "queue": self._repository.queue_counts(),
            "stale_jobs": self._repository.stale_job_count(now=self._clock()),
            "generated_at": _iso(self._clock()),
            "assurance": AUTOMATION_ASSURANCE,
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Schedules
    # ------------------------------------------------------------------
    def list_schedules(self) -> dict[str, Any]:
        return {
            "items": self._repository.list_schedules(),
            "automation_enabled": bool(self._settings.governance_automation_enabled),
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    def update_schedule(
        self,
        job_type: str,
        payload: Mapping[str, Any],
        *,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        normalized = str(job_type).upper()
        if normalized not in JOB_TYPE_VALUES:
            raise ScheduleNotFoundError(normalized)
        reason = str(payload.get("reason") or "").strip()
        if len(reason) < 3:
            raise AutomationValidationError("a reason of at least 3 characters is required")
        try:
            expected_version = int(payload.get("expected_version"))
        except (TypeError, ValueError):
            raise AutomationValidationError("expected_version is required") from None
        enabled = bool(payload.get("enabled", False))
        if enabled and not bool(self._settings.governance_automation_enabled):
            raise AutomationDisabledError(
                "schedules cannot be enabled while governance automation is disabled"
            )
        interval = validate_interval_minutes(payload.get("interval_minutes", 1440))
        config = validate_schedule_config(normalized, payload.get("config"))
        schedule = self._repository.update_schedule(
            normalized,
            enabled=enabled,
            interval_minutes=interval,
            config=config,
            expected_version=expected_version,
            actor_id=str(actor_id or "SYSTEM"),
            now=self._clock(),
        )
        self._audit(
            event_type=GovernanceAuditEventType.AUTOMATION_SCHEDULE_UPDATED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="AUTOMATION_SCHEDULE",
            target_id=normalized,
            reason=reason,
            request_id=request_id,
            event_key=f"automation:schedule:{normalized}:v{schedule['config_version']}",
            metadata={
                "enabled": schedule["enabled"],
                "interval_minutes": schedule["interval_minutes"],
                "config_version": schedule["config_version"],
            },
        )
        return {
            "schedule": schedule,
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------
    def list_jobs(
        self,
        *,
        job_type: str | None = None,
        status: str | None = None,
        trigger: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> dict[str, Any]:
        items, total = self._repository.list_jobs(
            job_type=job_type,
            status=status,
            trigger=trigger,
            page=page,
            page_size=page_size,
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": min(100, max(1, int(page_size))),
        }

    def job_detail(self, job_id: str) -> dict[str, Any]:
        job = self._repository.get_job(job_id)
        if job is None:
            raise JobNotFoundError(job_id)
        return {
            "job": job,
            "events": self._repository.job_events(job_id),
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    def run_now(
        self,
        *,
        job_type: str,
        idempotency_key: str,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        """Run a job synchronously with a required idempotency key."""
        normalized = str(job_type).upper()
        if normalized not in JOB_TYPE_VALUES:
            raise UnsupportedJobTypeError(f"unknown governance job type: {job_type}")
        if normalized not in self._executor.supported_job_types():
            raise UnsupportedJobTypeError(f"job type {normalized} is not implemented by this deployment")
        key = str(idempotency_key or "").strip()
        if not key:
            raise AutomationValidationError("idempotency_key is required")
        if len(key) > 128:
            raise AutomationValidationError("idempotency_key is limited to 128 characters")
        if len(str(reason or "").strip()) < 3:
            raise AutomationValidationError("a reason of at least 3 characters is required")
        schedule = self._repository.get_schedule(normalized)
        if schedule is None:
            raise ScheduleNotFoundError(normalized)
        dedup_key = f"manual:{normalized}:{key}"
        job, created = self._repository.create_job(
            job_type=normalized,
            trigger=JobTrigger.MANUAL.value,
            dedup_key=dedup_key,
            requested_by=str(actor_id or "SYSTEM"),
            requested_role=str(actor_role or "SYSTEM"),
            config_version=int(schedule["config_version"]),
            config_snapshot=dict(schedule["config"]),
            max_attempts=max(1, int(self._settings.governance_automation_max_attempts)),
            available_at=self._clock(),
            request_id=request_id,
            now=self._clock(),
        )
        if not created:
            return {
                "job": job,
                "replayed": True,
                "executed": False,
                "non_claims": list(AUTOMATION_NON_CLAIMS),
            }
        self._audit(
            event_type=GovernanceAuditEventType.AUTOMATION_JOB_ENQUEUED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="AUTOMATION_JOB",
            target_id=job["job_id"],
            reason=reason,
            request_id=request_id,
            event_key=f"automation:job:{job['job_id']}:enqueued",
            metadata={"job_type": normalized, "trigger": JobTrigger.MANUAL.value},
        )
        executed = self._execute_synchronously(job["job_id"], actor_id=actor_id)
        return {
            "job": self._repository.get_job(job["job_id"]) or job,
            "replayed": False,
            "executed": executed,
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    def retry_job(
        self,
        job_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        parent = self._repository.get_job(job_id)
        if parent is None:
            raise JobNotFoundError(job_id)
        if len(str(reason or "").strip()) < 3:
            raise AutomationValidationError("a reason of at least 3 characters is required")
        status = str(parent["status"])
        if status not in RETRYABLE_JOB_STATUSES:
            raise JobStateError(f"job {job_id} is not retryable from status {status}")
        next_attempt = int(parent["attempt"]) + 1
        if next_attempt > int(parent["max_attempts"]):
            raise RetryExhaustedError(f"job {job_id} reached its retry limit ({parent['max_attempts']})")
        dedup_key = f"retry:{job_id}:{next_attempt}"
        child, created = self._repository.create_job(
            job_type=str(parent["job_type"]),
            trigger=JobTrigger.RETRY.value,
            dedup_key=dedup_key,
            requested_by=str(actor_id or "SYSTEM"),
            requested_role=str(actor_role or "SYSTEM"),
            config_version=parent.get("config_version"),
            config_snapshot=dict(parent.get("config_snapshot") or {}),
            max_attempts=int(parent["max_attempts"]),
            retry_of_job_id=str(job_id),
            attempt=next_attempt,
            available_at=self._clock(),
            request_id=request_id,
            now=self._clock(),
        )
        self._audit(
            event_type=GovernanceAuditEventType.AUTOMATION_JOB_RETRIED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="AUTOMATION_JOB",
            target_id=job_id,
            reason=reason,
            request_id=request_id,
            event_key=f"automation:job:{job_id}:retry:{next_attempt}",
            metadata={"retry_job_id": child["job_id"], "attempt": next_attempt},
        )
        executed = False
        if created:
            executed = self._execute_synchronously(child["job_id"], actor_id=actor_id)
        return {
            "job": self._repository.get_job(child["job_id"]) or child,
            "parent_job_id": job_id,
            "replayed": not created,
            "executed": executed,
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    def cancel_job(
        self,
        job_id: str,
        *,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        if len(str(reason or "").strip()) < 3:
            raise AutomationValidationError("a reason of at least 3 characters is required")
        outcome = self._repository.request_cancel(
            job_id,
            actor_id=str(actor_id or "SYSTEM"),
            actor_role=str(actor_role or "SYSTEM"),
            now=self._clock(),
        )
        self._audit(
            event_type=GovernanceAuditEventType.AUTOMATION_JOB_CANCELLED.value,
            actor_id=actor_id,
            actor_role=actor_role,
            target_type="AUTOMATION_JOB",
            target_id=job_id,
            reason=reason,
            request_id=request_id,
            event_key=f"automation:job:{job_id}:cancelled",
            metadata={
                "cancelled": outcome["cancelled"],
                "cancel_requested": outcome["cancel_requested"],
            },
        )
        return {
            **outcome,
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    def _execute_synchronously(self, job_id: str, *, actor_id: str | None) -> bool:
        owner = f"manual-{job_id}"
        claimed = self._repository.claim_job(
            job_id,
            lease_owner=owner,
            lease_seconds=float(self._settings.governance_automation_lease_seconds),
            now=self._clock(),
        )
        if claimed is None:
            return False
        try:
            self._executor.execute(claimed, lease_owner=owner)
        except Exception as exc:  # noqa: BLE001 - terminal state is already recorded
            logger.warning("manual governance job failed job_id=%s error=%s", job_id, type(exc).__name__)
        return True

    def _audit(self, **kwargs: Any) -> None:
        try:
            self._governance.record_automation_audit(**kwargs)
        except Exception as exc:  # noqa: BLE001 - automation continues; audit is best-effort
            logger.warning("governance automation audit write failed error=%s", type(exc).__name__)

    # ------------------------------------------------------------------
    # Snapshots (implemented with the V36 reminder/snapshot commit)
    # ------------------------------------------------------------------
    def list_snapshots(
        self, *, snapshot_type: str | None = None, page: int = 1, page_size: int = 20
    ) -> dict[str, Any]:
        items, total = self._repository.list_snapshots(
            snapshot_type=snapshot_type, page=page, page_size=page_size
        )
        return {
            "items": items,
            "total": total,
            "page": max(1, int(page)),
            "page_size": min(100, max(1, int(page_size))),
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    def get_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        snapshot = self._repository.require_snapshot(snapshot_id)
        return {"snapshot": snapshot, "non_claims": list(AUTOMATION_NON_CLAIMS)}

    def generate_snapshot(
        self,
        *,
        idempotency_key: str,
        reason: str,
        actor_id: str | None,
        actor_role: str,
        request_id: str | None = None,
    ) -> dict[str, Any]:
        key = str(idempotency_key or "").strip()
        if not key:
            raise AutomationValidationError("idempotency_key is required")
        if len(str(reason or "").strip()) < 3:
            raise AutomationValidationError("a reason of at least 3 characters is required")
        dedup_key = f"snapshot:{SNAPSHOT_TYPE_COMPLIANCE_SUMMARY}:manual:{key}"
        existing = self._repository.find_snapshot_by_dedup_key(dedup_key)
        if existing is not None:
            return {
                "snapshot": existing,
                "replayed": True,
                "non_claims": list(AUTOMATION_NON_CLAIMS),
            }
        as_of = self._clock()
        report = self._governance.compliance_report(
            scope="SUMMARY",
            format="JSON",
            actor_id=actor_id,
            actor_role=actor_role,
            as_of=as_of,
            request_id=request_id,
        )
        payload = dict(report.get("report") or report)
        row_count = int(
            (payload.get("summary") or {}).get("evaluation_count", 0)
            if isinstance(payload.get("summary"), Mapping)
            else 0
        )
        snapshot, created = self._repository.create_snapshot(
            snapshot_type=SNAPSHOT_TYPE_COMPLIANCE_SUMMARY,
            as_of=as_of,
            generated_by=str(actor_id or "SYSTEM"),
            dedup_key=dedup_key,
            payload=payload,
            row_count=row_count,
            trigger=JobTrigger.MANUAL.value,
            now=self._clock(),
        )
        if created:
            record_governance_automation_snapshot(JobTrigger.MANUAL.value, "CREATED")
            self._audit(
                event_type=GovernanceAuditEventType.AUTOMATION_SNAPSHOT_GENERATED.value,
                actor_id=actor_id,
                actor_role=actor_role,
                target_type="AUTOMATION_SNAPSHOT",
                target_id=snapshot["snapshot_id"],
                reason=reason,
                request_id=request_id,
                event_key=f"automation:snapshot:{snapshot['snapshot_id']}:generated",
                metadata={
                    "snapshot_type": SNAPSHOT_TYPE_COMPLIANCE_SUMMARY,
                    "payload_digest": snapshot["payload_digest"],
                },
            )
        else:
            record_governance_automation_snapshot(JobTrigger.MANUAL.value, "REPLAYED")
        return {
            "snapshot": snapshot,
            "replayed": not created,
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    @staticmethod
    def snapshot_csv(snapshot: Mapping[str, Any]) -> str:
        """Render a stored snapshot payload as CSV (never regenerated live)."""
        return GovernanceService.report_csv(dict(snapshot.get("payload") or {}))


__all__ = ["GovernanceAutomationService"]
