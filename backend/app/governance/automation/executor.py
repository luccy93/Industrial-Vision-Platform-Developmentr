"""Bounded execution of V36 governance automation jobs.

The executor owns side effects. It reuses the V35 governance service for
retention evaluation and compliance reporting, the V33 integrity service for
read-only health, and the V15 notification system for reminders. It never
deletes evidence, approves or releases holds, decides dispositions, or
generates forensic exports.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from backend.app.core.logging import get_logger
from backend.app.core.metrics import (
    record_governance_automation_job,
    record_governance_automation_recovery,
    record_governance_automation_reminder,
    record_governance_automation_snapshot,
)
from backend.app.core.redaction import redact_text
from backend.app.domain.common import utcnow
from backend.app.governance.automation.constants import (
    AUTOMATION_NON_CLAIMS,
    DISPOSITION_REVIEW_DUE_EVENT,
    EXPORT_APPROVAL_REVIEW_DUE_EVENT,
    LEGAL_HOLD_PENDING_APPROVAL_EVENT,
    LEGAL_HOLD_REVIEW_DUE_EVENT,
    MAX_ERROR_LENGTH,
    MAX_RESULT_BYTES,
    REMINDER_CATEGORY_BY_JOB_TYPE,
    RETENTION_REVIEW_DUE_EVENT,
    SNAPSHOT_TYPE_COMPLIANCE_SUMMARY,
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

_REMINDER_OUTCOMES = (
    "QUEUED",
    "DEDUPLICATED",
    "COOLDOWN",
    "NO_RULE",
    "DISABLED",
    "NOOP",
    "ERROR",
)


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


def _parse_moment(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return normalize_utc(value)
    if isinstance(value, str) and value.strip():
        try:
            return normalize_utc(datetime.fromisoformat(value.strip().replace("Z", "+00:00")))
        except ValueError:
            return None
    return None


def _reminder_window(context: JobContext) -> str:
    """Stable per-window reminder identity for dedup (slot or run timestamp)."""
    slot = str(context.job.get("schedule_slot") or "").strip()
    if slot:
        return slot
    return normalize_utc(context.as_of).strftime("%Y%m%dT%H%M%SZ")


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
        notifier: Any | None = None,
        clock: Callable[[], datetime] | None = None,
        lease_seconds: float = 120.0,
        timeout_seconds: float = 300.0,
    ) -> None:
        self._repository = repository
        self._governance = governance_service
        self._forensics = forensic_repository
        self._integrity = integrity_service
        self._notifier = notifier
        self._clock = clock or utcnow
        self._lease_seconds = max(1.0, float(lease_seconds))
        self._timeout_seconds = max(1.0, float(timeout_seconds))
        self._handlers: dict[str, Callable[[JobContext], dict[str, Any]]] = {
            JobType.RETENTION_EVALUATION.value: self._run_retention_evaluation,
            JobType.RETENTION_REVIEW_REMINDERS.value: self._run_retention_review_reminders,
            JobType.LEGAL_HOLD_REMINDERS.value: self._run_legal_hold_reminders,
            JobType.DISPOSITION_REVIEW_REMINDERS.value: self._run_disposition_review_reminders,
            JobType.EXPORT_APPROVAL_REMINDERS.value: self._run_export_approval_reminders,
            JobType.COMPLIANCE_SNAPSHOT.value: self._run_compliance_snapshot,
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

    @property
    def notifier_enabled(self) -> bool:
        return bool(self._notifier is not None and getattr(self._notifier, "enabled", False))

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

    # ------------------------------------------------------------------
    # Reminder handlers (V15 notification pipeline; reminder-only)
    # ------------------------------------------------------------------
    def _case_payload(self, case_id: str) -> dict[str, Any]:
        """Minimal case context for a notification (never evidence bytes)."""
        payload: dict[str, Any] = {"case_id": case_id}
        try:
            case = self._forensics.get_case(case_id)
        except Exception:  # noqa: BLE001 - reminders must not fail on enrichment
            case = None
        if isinstance(case, Mapping):
            payload.update(
                {
                    "case_number": case.get("case_number"),
                    "status": case.get("status"),
                    "priority": case.get("priority"),
                    "originating_incident_id": case.get("originating_incident_id"),
                    "version": case.get("version"),
                }
            )
        return payload

    def _reminder_once(
        self,
        context: JobContext,
        *,
        category: str,
        event_type: str,
        target_type: str,
        target_id: str,
        detail: str,
        case_id: str | None = None,
        reason_codes: Sequence[str] = (),
    ) -> dict[str, Any]:
        """Queue at most one deduplicated reminder for one target/window."""
        if not self.notifier_enabled:
            record_governance_automation_reminder(category, "DISABLED")
            return {
                "target_type": target_type,
                "target_id": target_id,
                "event_type": event_type,
                "outcome": "DISABLED",
                "queued": 0,
                "duplicate": 0,
                "suppressed": 0,
                "no_rule": 0,
                "failed": 0,
            }
        case = self._case_payload(case_id) if case_id else None
        try:
            stats = self._notifier.notify_event(
                event_type=event_type,
                case=case,
                target_type=target_type,
                target_id=target_id,
                severity="HIGH",
                detail=detail,
                reason_codes=reason_codes,
                dedup_version=_reminder_window(context),
            )
        except Exception as exc:  # noqa: BLE001 - one reminder never stops the job
            record_governance_automation_reminder(category, "ERROR")
            logger.warning(
                "governance reminder failed category=%s error=%s",
                category,
                type(exc).__name__,
            )
            return {
                "target_type": target_type,
                "target_id": target_id,
                "event_type": event_type,
                "outcome": "ERROR",
                "queued": 0,
                "duplicate": 0,
                "suppressed": 0,
                "no_rule": 0,
                "failed": 1,
            }
        if stats.get("failed", 0):
            outcome = "ERROR"
        elif stats.get("queued", 0):
            outcome = "QUEUED"
        elif stats.get("duplicate", 0):
            outcome = "DEDUPLICATED"
        elif stats.get("suppressed", 0):
            outcome = "COOLDOWN"
        elif stats.get("no_rule", 0):
            outcome = "NO_RULE"
        else:
            outcome = "NOOP"
        record_governance_automation_reminder(category, outcome)
        return {
            "target_type": target_type,
            "target_id": target_id,
            "event_type": event_type,
            "outcome": outcome,
            "queued": int(stats.get("queued", 0)),
            "duplicate": int(stats.get("duplicate", 0)),
            "suppressed": int(stats.get("suppressed", 0)),
            "no_rule": int(stats.get("no_rule", 0)),
            "failed": int(stats.get("failed", 0)),
        }

    def _reminder_summary(
        self,
        context: JobContext,
        *,
        category: str,
        candidates: int,
        results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        counts = {outcome: 0 for outcome in _REMINDER_OUTCOMES}
        queued = duplicate = suppressed = no_rule = failed = 0
        for item in results:
            outcome = str(item.get("outcome") or "NOOP")
            counts[outcome] = counts.get(outcome, 0) + 1
            queued += int(item.get("queued", 0))
            duplicate += int(item.get("duplicate", 0))
            suppressed += int(item.get("suppressed", 0))
            no_rule += int(item.get("no_rule", 0))
            failed += int(item.get("failed", 0))
        return {
            "job_type": context.job_type,
            "category": category,
            "as_of": context.as_of.isoformat(),
            "reminder_window": _reminder_window(context),
            "candidates": int(candidates),
            "evaluated": len(results),
            "queued": queued,
            "deduplicated": duplicate,
            "cooldown": suppressed,
            "no_rule": no_rule,
            "failed": failed,
            "notifier_enabled": self.notifier_enabled,
            "outcomes": counts,
            "items": results[:20],
            "truncated": len(results) > 20,
            "automatic_hold_release": False,
            "automatic_disposition_approval": False,
            "automatic_export_generation": False,
            "non_claims": list(AUTOMATION_NON_CLAIMS),
        }

    def _run_retention_review_reminders(self, context: JobContext) -> dict[str, Any]:
        """Remind reviewers about retention reviews that are due or upcoming."""
        category = REMINDER_CATEGORY_BY_JOB_TYPE[JobType.RETENTION_REVIEW_REMINDERS.value]
        max_items = int(context.config.get("max_items", 100))
        upcoming_days = int(context.config.get("upcoming_days", 30))
        horizon = context.as_of + timedelta(days=upcoming_days)
        queue = self._governance.retention_queue(page=1, page_size=max_items, as_of=context.as_of)
        candidates: list[tuple[datetime, dict[str, Any]]] = []
        for item in queue.get("items") or []:
            next_review = _parse_moment(item.get("next_review_at"))
            deadline = _parse_moment(item.get("retention_deadline"))
            state = str(item.get("governance_state") or "")
            due_at = next_review or deadline
            if (
                state == "REVIEW_DUE"
                or (next_review is not None and next_review <= horizon)
                or (deadline is not None and deadline <= context.as_of)
            ):
                candidates.append((due_at or context.as_of, item))
        candidates.sort(key=lambda pair: (pair[0], str(pair[1].get("evaluation_id") or "")))
        results: list[dict[str, Any]] = []
        for due_at, item in candidates[:max_items]:
            context.checkpoint()
            evaluation_id = str(item.get("evaluation_id") or "")
            case_id = str(item.get("case_id") or "")
            state = str(item.get("governance_state") or "UNKNOWN")
            results.append(
                self._reminder_once(
                    context,
                    category=category,
                    event_type=RETENTION_REVIEW_DUE_EVENT,
                    target_type="RETENTION_EVALUATION",
                    target_id=evaluation_id or case_id,
                    case_id=case_id or None,
                    detail=(
                        f"Retention review is due by {due_at.isoformat()}; "
                        f"governance state is {state}. Review the retention queue; "
                        "this reminder never deletes evidence."
                    ),
                    reason_codes=["RETENTION_REVIEW_DUE"],
                )
            )
        return self._reminder_summary(
            context,
            category=category,
            candidates=len(candidates),
            results=results,
        )

    def _run_legal_hold_reminders(self, context: JobContext) -> dict[str, Any]:
        """Remind reviewers about pending approvals and aging active holds."""
        category = REMINDER_CATEGORY_BY_JOB_TYPE[JobType.LEGAL_HOLD_REMINDERS.value]
        max_items = int(context.config.get("max_items", 100))
        age_days = int(context.config.get("active_hold_age_days", 30))
        include_pending = bool(context.config.get("include_pending_approval", True))
        include_active = bool(context.config.get("include_active_holds", True))
        candidates: list[tuple[datetime, str, dict[str, Any]]] = []
        if include_pending:
            pending = self._governance.list_legal_holds(
                statuses=["PENDING_APPROVAL"], page=1, page_size=max_items
            )
            for item in pending.get("items") or []:
                requested = _parse_moment(item.get("requested_at")) or context.as_of
                candidates.append((requested, LEGAL_HOLD_PENDING_APPROVAL_EVENT, item))
        if include_active:
            active = self._governance.list_legal_holds(statuses=["ACTIVE"], page=1, page_size=max_items)
            threshold = context.as_of - timedelta(days=age_days)
            for item in active.get("items") or []:
                approved = (
                    _parse_moment(item.get("approved_at"))
                    or _parse_moment(item.get("requested_at"))
                    or context.as_of
                )
                if age_days > 0 and approved > threshold:
                    continue
                candidates.append((approved, LEGAL_HOLD_REVIEW_DUE_EVENT, item))
        candidates.sort(key=lambda pair: (pair[0], str(pair[2].get("hold_id") or "")))
        results: list[dict[str, Any]] = []
        for since, event_type, item in candidates[:max_items]:
            context.checkpoint()
            hold_id = str(item.get("hold_id") or "")
            status = str(item.get("status") or "UNKNOWN")
            results.append(
                self._reminder_once(
                    context,
                    category=category,
                    event_type=event_type,
                    target_type="LEGAL_HOLD",
                    target_id=hold_id,
                    case_id=str(item.get("case_id") or "") or None,
                    detail=(
                        f"Legal hold {item.get('hold_number') or hold_id} is {status} "
                        f"since {since.isoformat()}. Review the hold workspace; "
                        "this reminder never approves, rejects, or releases a hold."
                    ),
                    reason_codes=[event_type],
                )
            )
        return self._reminder_summary(
            context,
            category=category,
            candidates=len(candidates),
            results=results,
        )

    def _run_disposition_review_reminders(self, context: JobContext) -> dict[str, Any]:
        """Remind reviewers about open disposition reviews."""
        category = REMINDER_CATEGORY_BY_JOB_TYPE[JobType.DISPOSITION_REVIEW_REMINDERS.value]
        max_items = int(context.config.get("max_items", 100))
        min_age_days = int(context.config.get("min_age_days", 1))
        threshold = context.as_of - timedelta(days=min_age_days)
        listing = self._governance.list_dispositions(
            statuses=["REVIEW_REQUIRED", "APPROVAL_PENDING"],
            page=1,
            page_size=max_items,
        )
        candidates: list[tuple[datetime, dict[str, Any]]] = []
        for item in listing.get("items") or []:
            requested = _parse_moment(item.get("requested_at")) or context.as_of
            if min_age_days > 0 and requested > threshold:
                continue
            candidates.append((requested, item))
        candidates.sort(key=lambda pair: (pair[0], str(pair[1].get("disposition_id") or "")))
        results: list[dict[str, Any]] = []
        for requested, item in candidates[:max_items]:
            context.checkpoint()
            disposition_id = str(item.get("disposition_id") or "")
            status = str(item.get("status") or "UNKNOWN")
            results.append(
                self._reminder_once(
                    context,
                    category=category,
                    event_type=DISPOSITION_REVIEW_DUE_EVENT,
                    target_type="DISPOSITION",
                    target_id=disposition_id,
                    case_id=str(item.get("case_id") or "") or None,
                    detail=(
                        f"Disposition {item.get('request_number') or disposition_id} "
                        f"is {status} since {requested.isoformat()}. Review the "
                        "disposition queue; this reminder never approves or rejects "
                        "a disposition and never deletes evidence."
                    ),
                    reason_codes=[DISPOSITION_REVIEW_DUE_EVENT],
                )
            )
        return self._reminder_summary(
            context,
            category=category,
            candidates=len(candidates),
            results=results,
        )

    def _run_export_approval_reminders(self, context: JobContext) -> dict[str, Any]:
        """Remind reviewers about export approvals that are still pending."""
        category = REMINDER_CATEGORY_BY_JOB_TYPE[JobType.EXPORT_APPROVAL_REMINDERS.value]
        max_items = int(context.config.get("max_items", 100))
        upcoming_days = int(context.config.get("upcoming_days", 14))
        horizon = context.as_of + timedelta(days=upcoming_days)
        listing = self._governance.list_export_approvals(
            statuses=["PENDING_APPROVAL"], page=1, page_size=max_items
        )
        candidates: list[tuple[datetime, dict[str, Any]]] = []
        for item in listing.get("items") or []:
            requested = _parse_moment(item.get("requested_at")) or context.as_of
            expires = _parse_moment(item.get("expires_at"))
            if expires is not None and expires > horizon:
                continue
            candidates.append((requested, item))
        candidates.sort(key=lambda pair: (pair[0], str(pair[1].get("approval_id") or "")))
        results: list[dict[str, Any]] = []
        for requested, item in candidates[:max_items]:
            context.checkpoint()
            approval_id = str(item.get("approval_id") or "")
            results.append(
                self._reminder_once(
                    context,
                    category=category,
                    event_type=EXPORT_APPROVAL_REVIEW_DUE_EVENT,
                    target_type="EXPORT_APPROVAL",
                    target_id=approval_id,
                    case_id=str(item.get("case_id") or "") or None,
                    detail=(
                        f"Export approval {item.get('request_number') or approval_id} "
                        f"has been pending since {requested.isoformat()}. Review the "
                        "approval queue; this reminder never generates an export, and "
                        "generation/download still require the forensic_export capability."
                    ),
                    reason_codes=[EXPORT_APPROVAL_REVIEW_DUE_EVENT],
                )
            )
        return self._reminder_summary(
            context,
            category=category,
            candidates=len(candidates),
            results=results,
        )

    # ------------------------------------------------------------------
    # Compliance snapshot handler
    # ------------------------------------------------------------------
    def _run_compliance_snapshot(self, context: JobContext) -> dict[str, Any]:
        """Persist a SUMMARY compliance snapshot with a local self-digest."""
        context.checkpoint()
        window = _reminder_window(context)
        dedup_key = (f"snapshot:{SNAPSHOT_TYPE_COMPLIANCE_SUMMARY}:{context.trigger.lower()}:{window}")[:200]
        existing = self._repository.find_snapshot_by_dedup_key(dedup_key)
        if existing is not None:
            record_governance_automation_snapshot(context.trigger, "REPLAYED")
            return {
                "job_type": JobType.COMPLIANCE_SNAPSHOT.value,
                "snapshot_id": existing["snapshot_id"],
                "snapshot_type": existing["snapshot_type"],
                "payload_digest": existing["payload_digest"],
                "digest_valid": existing["digest_valid"],
                "row_count": existing["row_count"],
                "as_of": existing["as_of"],
                "replayed": True,
                "non_claims": list(AUTOMATION_NON_CLAIMS),
            }
        report = self._governance.compliance_report(
            scope="SUMMARY",
            format="JSON",
            actor_id="governance-automation",
            actor_role="SYSTEM",
            as_of=context.as_of,
            request_id=f"job:{context.job_id}",
        )
        payload = dict(report or {})
        sections = payload.get("sections")
        retention = sections.get("retention") if isinstance(sections, Mapping) else None
        row_count = int(retention.get("evaluated_cases", 0) or 0) if isinstance(retention, Mapping) else 0
        snapshot, created = self._repository.create_snapshot(
            snapshot_type=SNAPSHOT_TYPE_COMPLIANCE_SUMMARY,
            as_of=context.as_of,
            generated_by="governance-automation",
            dedup_key=dedup_key,
            payload=payload,
            row_count=row_count,
            job_id=context.job_id,
            trigger=context.trigger,
            now=self._clock(),
        )
        record_governance_automation_snapshot(context.trigger, "CREATED" if created else "REPLAYED")
        return {
            "job_type": JobType.COMPLIANCE_SNAPSHOT.value,
            "snapshot_id": snapshot["snapshot_id"],
            "snapshot_type": snapshot["snapshot_type"],
            "payload_digest": snapshot["payload_digest"],
            "digest_valid": snapshot["digest_valid"],
            "row_count": snapshot["row_count"],
            "as_of": snapshot["as_of"],
            "overall_status": payload.get("overall_status"),
            "replayed": not created,
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
