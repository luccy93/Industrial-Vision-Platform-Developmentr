"""Bounded execution of V36 governance automation jobs.

The executor owns side effects. It reuses the V35 governance service for
retention evaluation and compliance reporting, the V33 integrity service for
read-only health, and the V15 notification system for reminders. It never
deletes evidence, approves or releases holds, decides dispositions, or
generates forensic exports.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.core.metrics import (
    record_governance_automation_job,
    record_governance_automation_recovery,
)
from backend.app.core.redaction import redact_text
from backend.app.domain.common import utcnow
from backend.app.governance.automation.constants import (
    AUTOMATION_NON_CLAIMS,
    MAX_ERROR_LENGTH,
    MAX_RESULT_BYTES,
    JobStatus,
    JobType,
    normalize_utc,
    validate_schedule_config,
)
from backend.app.governance.automation.errors import (
    AutomationExecutionError,
    JobCancelled,
    JobTimeout,
    LeaseLost,
    UnsupportedJobTypeError,
)
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.governance.service import GovernanceService

logger = get_logger(__name__)


def _slot_as_of(job: Mapping[str, Any], clock: Callable[[], datetime]) -> datetime:
    """Use the deterministic schedule slot timestamp when available."""
    slot = str(job.get("schedule_slot") or "")
    if slot:
        stamp = slot.rsplit(":", 1)[-1]
        try:
            return normalize_utc(datetime.strptime(stamp, "%Y%m%dT%H%M%SZ"))
        except ValueError:
            pass
    created = job.get("created_at")
    if isinstance(created, str) and created:
        try:
            return normalize_utc(datetime.fromisoformat(created.replace("Z", "+00:00")))
        except ValueError:
            pass
    return normalize_utc(clock())


@dataclass
class JobContext:
    """Per-job execution context with cooperative cancellation and leases."""

    job: dict[str, Any]
    lease_owner: str
    config: dict[str, Any]
    as_of: datetime
    executor: GovernanceJobExecutor
    started_monotonic: float = field(default_factory=time.monotonic)

    @property
    def job_id(self) -> str:
        return str(self.job["job_id"])

    @property
    def job_type(self) -> str:
        return str(self.job["job_type"])

    @property
    def trigger(self) -> str:
        return str(self.job.get("trigger") or "MANUAL")

    def checkpoint(self) -> None:
        """Heartbeat the lease and stop promptly if cancellation was requested."""
        if not self.executor.repository.heartbeat_job(
            self.job_id,
            lease_owner=self.lease_owner,
            lease_seconds=self.executor.lease_seconds,
            now=self.executor.clock(),
        ):
            raise LeaseLost(f"lease lost for job {self.job_id}")
        if self.executor.repository.is_cancel_requested(self.job_id):
            raise JobCancelled(f"job {self.job_id} was cancelled")
        if self.started_monotonic + self.executor.timeout_seconds < time.monotonic():
            raise JobTimeout(f"job {self.job_id} exceeded its execution deadline")


class GovernanceJobExecutor:
    """Execute one claimed governance job with bounded, idempotent side effects."""

    def __init__(
        self,
        *,
        repository: GovernanceAutomationRepository,
        governance_service: GovernanceService,
        forensic_repository: Any,
        integrity_service: Any | None = None,
        clock: Callable[[], datetime] | None = None,
        lease_seconds: float = 120.0,
        timeout_seconds: float = 300.0,
    ) -> None:
        self._repository = repository
        self._governance = governance_service
        self._forensics = forensic_repository
        self._integrity = integrity_service
        self._clock = clock or utcnow
        self._lease_seconds = max(1.0, float(lease_seconds))
        self._timeout_seconds = max(1.0, float(timeout_seconds))
        self._handlers: dict[str, Callable[[JobContext], dict[str, Any]]] = {
            JobType.RETENTION_EVALUATION.value: self._run_retention_evaluation,
            JobType.GOVERNANCE_HEALTH_CHECK.value: self._run_health_check,
        }

    @property
    def repository(self) -> GovernanceAutomationRepository:
        return self._repository

    @property
    def clock(self) -> Callable[[], datetime]:
        return self._clock

    @property
    def lease_seconds(self) -> float:
        return self._lease_seconds

    @property
    def timeout_seconds(self) -> float:
        return self._timeout_seconds

    def supported_job_types(self) -> frozenset[str]:
        return frozenset(self._handlers)

    def register_handler(self, job_type: str, handler: Callable[[JobContext], dict[str, Any]]) -> None:
        normalized = str(job_type).upper()
        if normalized not in {item.value for item in JobType}:
            raise ValueError(f"unknown governance job type: {job_type}")
        self._handlers[normalized] = handler

    def execute(self, job: Mapping[str, Any], *, lease_owner: str) -> dict[str, Any]:
        """Run a claimed job and persist exactly one terminal transition."""
        job_type = str(job.get("job_type") or "").upper()
        handler = self._handlers.get(job_type)
        started = time.monotonic()
        if handler is None:
            finished = self._repository.finish_job(
                str(job["job_id"]),
                lease_owner=lease_owner,
                status=JobStatus.FAILED.value,
                result={"job_type": job_type, "supported": False},
                error_code="UNSUPPORTED_JOB_TYPE",
                error_message=f"job type {job_type} is not implemented",
                now=self._clock(),
            )
            if finished:
                record_governance_automation_job(
                    job_type=job_type,
                    trigger=str(job.get("trigger") or "MANUAL"),
                    status=JobStatus.FAILED.value,
                    duration_seconds=time.monotonic() - started,
                )
            raise UnsupportedJobTypeError(f"job type {job_type} is not implemented")

        config = validate_schedule_config(job_type, dict(job.get("config_snapshot") or {}))
        context = JobContext(
            job=dict(job),
            lease_owner=lease_owner,
            config=config,
            as_of=_slot_as_of(job, self._clock),
            executor=self,
        )
        try:
            result = handler(context)
            bounded = _bounded_result(result)
            finished = self._repository.finish_job(
                context.job_id,
                lease_owner=lease_owner,
                status=JobStatus.SUCCEEDED.value,
                result=bounded,
                now=self._clock(),
            )
            if not finished:
                raise LeaseLost(f"lease lost before finish for job {context.job_id}")
            record_governance_automation_job(
                job_type=job_type,
                trigger=context.trigger,
                status=JobStatus.SUCCEEDED.value,
                duration_seconds=time.monotonic() - started,
            )
            logger.info(
                "governance automation job succeeded job_id=%s job_type=%s trigger=%s duration_ms=%.1f",
                context.job_id,
                job_type,
                context.trigger,
                (time.monotonic() - started) * 1000.0,
            )
            return self._repository.get_job(context.job_id) or dict(job)
        except JobCancelled:
            finished = self._repository.finish_job(
                context.job_id,
                lease_owner=lease_owner,
                status=JobStatus.CANCELLED.value,
                result={"cancelled": True, "as_of": context.as_of.isoformat()},
                error_code="CANCELLED",
                error_message="job observed cooperative cancellation",
                now=self._clock(),
            )
            if finished:
                record_governance_automation_job(
                    job_type=job_type,
                    trigger=context.trigger,
                    status=JobStatus.CANCELLED.value,
                    duration_seconds=time.monotonic() - started,
                )
            return self._repository.get_job(context.job_id) or dict(job)
        except LeaseLost:
            # A recovery owner may already have marked this job UNAVAILABLE.
            # Never overwrite another owner's terminal transition.
            logger.warning(
                "governance automation lease lost job_id=%s job_type=%s",
                context.job_id,
                job_type,
            )
            return self._repository.get_job(context.job_id) or dict(job)
        except JobTimeout:
            self._finish_failure(
                context,
                started=started,
                error_code="TIMEOUT",
                error_message=f"job exceeded {self._timeout_seconds:.0f}s deadline",
            )
            raise
        except Exception as exc:  # noqa: BLE001 - sanitized, bounded failure record
            self._finish_failure(
                context,
                started=started,
                error_code=_error_code(exc),
                error_message=_error_message(exc),
            )
            raise

    def _finish_failure(
        self,
        context: JobContext,
        *,
        started: float,
        error_code: str,
        error_message: str,
    ) -> None:
        finished = self._repository.finish_job(
            context.job_id,
            lease_owner=context.lease_owner,
            status=JobStatus.FAILED.value,
            result={"job_type": context.job_type, "as_of": context.as_of.isoformat()},
            error_code=error_code,
            error_message=error_message,
            now=self._clock(),
        )
        if finished:
            record_governance_automation_job(
                job_type=context.job_type,
                trigger=context.trigger,
                status=JobStatus.FAILED.value,
                duration_seconds=time.monotonic() - started,
            )
            logger.warning(
                "governance automation job failed job_id=%s job_type=%s error_code=%s",
                context.job_id,
                context.job_type,
                error_code,
            )

    # ------------------------------------------------------------------
    # Handlers
    # ------------------------------------------------------------------
    def _run_retention_evaluation(self, context: JobContext) -> dict[str, Any]:
        """Non-destructively evaluate retention for a bounded set of cases."""
        batch_limit = int(context.config.get("batch_limit", 100))
        page_size = min(100, max(1, batch_limit))
        cases: list[dict[str, Any]] = []
        page = 1
        total_cases = 0
        while len(cases) < batch_limit:
            rows, total = self._forensics.list_cases(page=page, page_size=page_size)
            total_cases = int(total)
            if not rows:
                break
            cases.extend(rows)
            if len(rows) < page_size:
                break
            page += 1
            if page > 1000:  # defensive bound; never unbounded pagination
                break
        truncated = len(cases) > batch_limit
        selected = cases[:batch_limit]
        evaluated = 0
        replayed = 0
        errors: list[dict[str, str]] = []
        states: dict[str, int] = {}
        integrity_states: dict[str, int] = {}
        for case in selected:
            context.checkpoint()
            case_id = str(case.get("case_id") or case.get("id") or "")
            if not case_id:
                continue
            try:
                outcome = self._governance.evaluate_case(
                    case_id,
                    actor_id="governance-automation",
                    actor_role="SYSTEM",
                    as_of=context.as_of,
                    request_id=f"job:{context.job_id}",
                )
            except Exception as exc:  # noqa: BLE001 - per-case isolation
                errors.append(
                    {
                        "case_id": case_id,
                        "error": _error_message(exc),
                    }
                )
                continue
            evaluation = outcome.get("evaluation") or {}
            if outcome.get("replayed"):
                replayed += 1
            else:
                evaluated += 1
            state = str(evaluation.get("governance_state") or "UNKNOWN")
            states[state] = states.get(state, 0) + 1
            integrity = str(evaluation.get("integrity_status") or "NOT_RUN")
            integrity_states[integrity] = integrity_states.get(integrity, 0) + 1
        if selected and not evaluated and not replayed and errors:
            raise AutomationExecutionError(
                f"retention evaluation completed no useful work ({len(errors)} errors)"
            )
        return {
            "job_type": JobType.RETENTION_EVALUATION.value,
            "as_of": context.as_of.isoformat(),
            "cases_considered": len(selected),
            "cases_available": total_cases,
            "evaluated": evaluated,
            "replayed": replayed,
            "errors": errors[:20],
            "error_count": len(errors),
            "truncated": truncated,
            "governance_states": states,
            "integrity_states": integrity_states,
            "destructive": False,
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    def _run_health_check(self, context: JobContext) -> dict[str, Any]:
        """Read-only governance, integrity, and queue health summary."""
        context.checkpoint()
        governance_health: dict[str, Any] = {
            "status": "UNAVAILABLE",
            "audit_outcome": "UNAVAILABLE",
        }
        try:
            status = self._governance.status()
            audit = dict(status.get("audit_integrity") or {})
            outcome = str(audit.get("outcome") or "UNAVAILABLE").upper()
            governance_health = {
                "status": "OK" if outcome == "OK" else "FAILED",
                "audit_outcome": outcome,
                "audit_checked": int(audit.get("checked", 0) or 0),
                "audit_verified": int(audit.get("verified", 0) or 0),
                "assurance": str(status.get("assurance") or "UNKNOWN"),
                "policy_count": int(status.get("policy_count", 0) or 0),
            }
        except Exception as exc:  # noqa: BLE001 - health must never crash on read
            governance_health["error"] = _error_message(exc)

        integrity_health: dict[str, Any] = {
            "status": "UNAVAILABLE",
            "latest_audit_status": "UNAVAILABLE",
        }
        if self._integrity is not None:
            try:
                integrity_status = self._integrity.status()
                latest = integrity_status.get("latest_audit") or {}
                latest_status = str(
                    (latest.get("status") if isinstance(latest, Mapping) else None) or "NOT_RUN"
                ).upper()
                # Only an explicit PASS may map to OK. FAIL, PARTIAL,
                # UNAVAILABLE, NOT_RUN, and RUNNING are never a pass.
                integrity_health = {
                    "status": "OK" if latest_status == "PASS" else "NOT_PASS",
                    "latest_audit_status": latest_status,
                    "store_status": str(integrity_status.get("store_status") or "UNKNOWN"),
                    "open_findings": int(integrity_status.get("open_findings", 0) or 0),
                    "assurance": str(integrity_status.get("assurance") or "UNKNOWN"),
                    "external_anchor_configured": bool(
                        integrity_status.get("external_anchor_configured", False)
                    ),
                }
            except Exception as exc:  # noqa: BLE001 - health must never crash on read
                integrity_health["error"] = _error_message(exc)
        else:
            integrity_health["status"] = "DISABLED"

        if governance_health["status"] != "OK":
            overall = "FAILED"
        elif integrity_health["status"] != "OK":
            overall = "DEGRADED"
        else:
            overall = "OK"
        return {
            "job_type": JobType.GOVERNANCE_HEALTH_CHECK.value,
            "checked_at": normalize_utc(self._clock()).isoformat(),
            "overall_status": overall,
            "governance": governance_health,
            "integrity": integrity_health,
            "queue": self._repository.queue_counts(),
            "stale_jobs": self._repository.stale_job_count(now=self._clock()),
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    # ------------------------------------------------------------------
    # Recovery helpers used by the scheduler
    # ------------------------------------------------------------------
    def recover_expired(self, *, now: datetime | None = None) -> list[dict[str, Any]]:
        recovered = self._repository.recover_expired_jobs(now=now or self._clock())
        for item in recovered:
            record_governance_automation_recovery(str(item.get("job_type") or ""))
        return recovered


def _bounded_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """Keep job results small and sanitized."""
    import json

    candidate = dict(result or {})
    encoded = json.dumps(candidate, sort_keys=True, default=str).encode("utf-8")
    if len(encoded) <= MAX_RESULT_BYTES:
        return candidate
    return {
        "truncated": True,
        "original_bytes": len(encoded),
        "non_claims": list(AUTOMATION_NON_CLAIMS),
    }


def _error_code(exc: Exception) -> str:
    name = type(exc).__name__
    if name.endswith("Error"):
        name = name[: -len("Error")]
    return (name or "ERROR").upper()[:64]


def _error_message(exc: Exception) -> str:
    return redact_text(str(exc) or type(exc).__name__)[:MAX_ERROR_LENGTH]


__all__ = ["GovernanceJobExecutor", "JobContext"]
