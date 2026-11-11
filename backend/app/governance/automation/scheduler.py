"""V36 governance automation scheduler.

The scheduler is a ``ManagedWorker`` that owns no second database and no second
policy engine. Each cycle recovers expired leases, enqueues at most one job per
enabled schedule slot, and executes a bounded number of due jobs through the
shared executor. Missed slots are not replayed.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from backend.app.core.config import Settings
from backend.app.core.logging import get_logger
from backend.app.core.metrics import set_governance_automation_queue_depth
from backend.app.domain.common import utcnow
from backend.app.governance.automation.constants import (
    JobEventType,
    JobStatus,
    JobTrigger,
    normalize_utc,
    retry_delay_seconds,
    schedule_slot_id,
)
from backend.app.governance.automation.executor import GovernanceJobExecutor
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.workers.base import ManagedWorker, WorkerState

logger = get_logger(__name__)


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    return normalize_utc(value).isoformat().replace("+00:00", "Z")


class GovernanceAutomationScheduler(ManagedWorker):
    """Opt-in, bounded scheduler for governance automation jobs."""

    def __init__(
        self,
        *,
        settings: Settings,
        repository: GovernanceAutomationRepository,
        executor: GovernanceJobExecutor,
        name: str = "governance-automation",
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        super().__init__(name)
        self._settings = settings
        self._repository = repository
        self._executor = executor
        self._clock = clock or utcnow
        self._poll_seconds = max(1.0, float(settings.governance_automation_poll_seconds))
        self._lease_seconds = max(1.0, float(settings.governance_automation_lease_seconds))
        self._max_jobs_per_tick = max(1, int(settings.governance_automation_max_jobs_per_tick))
        self._max_pending_jobs = max(1, int(settings.governance_automation_max_pending_jobs))
        self._retry_base = max(1.0, float(settings.governance_automation_retry_base_seconds))
        self._retry_max = max(self._retry_base, float(settings.governance_automation_retry_max_seconds))
        self._max_attempts = max(1, int(settings.governance_automation_max_attempts))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._cycles = 0
        self._enqueued = 0
        self._executed = 0
        self._failed = 0
        self._recovered = 0
        self._last_cycle_at: datetime | None = None
        self._last_success_at: datetime | None = None
        self._last_error: str | None = None

    # ------------------------------------------------------------------
    # ManagedWorker contract
    # ------------------------------------------------------------------
    def start(self) -> bool:
        with self._state_lock:
            if self._worker_state is WorkerState.RUNNING:
                return True
            if self._worker_state is WorkerState.FAILED:
                return False
        try:
            self._transition(WorkerState.STARTING)
        except ValueError:
            return self.health().state is WorkerState.RUNNING
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop,
            name=f"governance-automation-{self.worker_name}",
            daemon=True,
        )
        self._thread.start()
        self._transition(WorkerState.RUNNING)
        self._report_heartbeat()
        return True

    def stop(self, timeout: float = 5.0) -> bool:
        with self._state_lock:
            if self._worker_state in (WorkerState.STOPPED, WorkerState.CREATED):
                return True
        try:
            self._transition(WorkerState.STOPPING)
        except ValueError:
            return self.health().state is WorkerState.STOPPED
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        try:
            self._transition(WorkerState.STOPPED)
        except ValueError:
            pass
        return True

    def _loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    self.run_once()
                except Exception as exc:  # noqa: BLE001 - scheduler must survive a cycle
                    self._record_failure(f"{type(exc).__name__}: {exc}")
                    self._last_error = f"{type(exc).__name__}: scheduler cycle failed"
                    logger.warning(
                        "governance automation scheduler cycle failed error=%s",
                        type(exc).__name__,
                    )
                self._stop_event.wait(self._poll_seconds)
        except Exception as exc:  # noqa: BLE001 - final guard
            self._record_failure(f"{type(exc).__name__}: {exc}")
            with self._state_lock:
                try:
                    self._transition(WorkerState.FAILED)
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # Cycle
    # ------------------------------------------------------------------
    def run_once(self, now: datetime | None = None) -> dict[str, Any]:
        reference = normalize_utc(now or self._clock())
        stats: dict[str, Any] = {
            "cycle": self._cycles + 1,
            "at": _iso(reference),
            "recovered": 0,
            "enqueued": 0,
            "executed": 0,
            "succeeded": 0,
            "failed": 0,
            "skipped_full": 0,
            "retries": 0,
        }
        self._cycles += 1
        self._last_cycle_at = reference
        if not bool(self._settings.governance_automation_enabled):
            stats["disabled"] = True
            return stats

        recovered = self._executor.recover_expired()
        stats["recovered"] = len(recovered)
        self._recovered += len(recovered)
        for item in recovered:
            job = self._repository.get_job(str(item.get("job_id")))
            if job is not None and self._maybe_retry(job, reference):
                stats["retries"] += 1

        schedules = self._repository.list_schedules()
        pending = int(self._repository.queue_counts().get(JobStatus.PENDING.value, 0))
        for schedule in schedules:
            if not bool(schedule.get("enabled")):
                continue
            if pending >= self._max_pending_jobs:
                stats["skipped_full"] += 1
                break
            job_type = str(schedule["job_type"])
            interval = int(schedule["interval_minutes"])
            slot = schedule_slot_id(job_type, interval, reference)
            if schedule.get("last_slot") == slot:
                continue
            dedup_key = f"schedule:{slot}"
            job, created = self._repository.create_job(
                job_type=job_type,
                trigger=JobTrigger.SCHEDULE.value,
                dedup_key=dedup_key,
                requested_by="governance-automation",
                requested_role="SYSTEM",
                config_version=int(schedule.get("config_version", 1)),
                config_snapshot=dict(schedule.get("config") or {}),
                max_attempts=self._max_attempts,
                schedule_slot=slot,
                available_at=reference,
                now=reference,
            )
            self._repository.mark_schedule_enqueued(job_type, slot=slot, dedup_key=dedup_key, now=reference)
            if created:
                self._enqueued += 1
                stats["enqueued"] += 1
                pending += 1

        for _ in range(self._max_jobs_per_tick):
            claimed = self._repository.claim_next_job(
                lease_owner=self.worker_name,
                lease_seconds=self._lease_seconds,
                now=self._clock(),
            )
            if claimed is None:
                break
            stats["executed"] += 1
            self._executed += 1
            try:
                finished = self._executor.execute(claimed, lease_owner=self.worker_name)
            except Exception:  # noqa: BLE001 - one failed job never stops the cycle
                stats["failed"] += 1
                self._failed += 1
                finished = self._repository.get_job(str(claimed["job_id"]))
            else:
                if str(finished.get("status")) == JobStatus.SUCCEEDED.value:
                    stats["succeeded"] += 1
                elif str(finished.get("status")) == JobStatus.FAILED.value:
                    stats["failed"] += 1
                    self._failed += 1
            if finished is not None and self._maybe_retry(finished, reference):
                stats["retries"] += 1

        counts = self._repository.queue_counts()
        try:
            set_governance_automation_queue_depth(counts)
        except Exception:  # noqa: BLE001 - metrics must never break the cycle
            pass
        self._last_success_at = reference
        self._last_error = None
        self._report_heartbeat()
        return stats

    def _maybe_retry(self, job: dict[str, Any], now: datetime) -> bool:
        """Create at most one retry child for a failed/unavailable job."""
        status = str(job.get("status") or "")
        if status not in {JobStatus.FAILED.value, JobStatus.UNAVAILABLE.value}:
            return False
        if str(job.get("error_code") or "") == "UNSUPPORTED_JOB_TYPE":
            return False
        attempt = int(job.get("attempt", 1))
        max_attempts = int(job.get("max_attempts", self._max_attempts))
        if attempt >= max_attempts:
            return False
        next_attempt = attempt + 1
        delay = retry_delay_seconds(
            str(job["job_id"]),
            next_attempt,
            base_seconds=self._retry_base,
            max_seconds=self._retry_max,
        )
        available_at = now + timedelta(seconds=delay)
        dedup_key = f"retry:{job['job_id']}:{next_attempt}"
        child, created = self._repository.create_job(
            job_type=str(job["job_type"]),
            trigger=JobTrigger.RETRY.value,
            dedup_key=dedup_key,
            requested_by="governance-automation",
            requested_role="SYSTEM",
            config_version=job.get("config_version"),
            config_snapshot=dict(job.get("config_snapshot") or {}),
            max_attempts=max_attempts,
            retry_of_job_id=str(job["job_id"]),
            attempt=next_attempt,
            available_at=available_at,
            now=now,
        )
        if not created:
            return False
        self._repository.append_event(
            str(job["job_id"]),
            JobEventType.RETRY_SCHEDULED.value,
            from_status=status,
            to_status=JobStatus.PENDING.value,
            actor_id="governance-automation",
            actor_role="SYSTEM",
            detail={
                "retry_job_id": child["job_id"],
                "attempt": next_attempt,
                "delay_seconds": round(delay, 3),
            },
            now=now,
        )
        return True

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        snapshot = self.health()
        enabled = bool(self._settings.governance_automation_enabled)
        state = snapshot.state.value if enabled else "DISABLED"
        return {
            "enabled": enabled,
            "state": state,
            "running": enabled and snapshot.state is WorkerState.RUNNING,
            "name": self.worker_name,
            "poll_seconds": self._poll_seconds,
            "lease_seconds": self._lease_seconds,
            "max_jobs_per_tick": self._max_jobs_per_tick,
            "max_pending_jobs": self._max_pending_jobs,
            "max_attempts": self._max_attempts,
            "last_heartbeat": _iso(snapshot.last_heartbeat),
            "last_cycle_at": _iso(self._last_cycle_at),
            "last_success_at": _iso(self._last_success_at),
            "last_error": self._last_error,
            "cycles": self._cycles,
            "enqueued": self._enqueued,
            "executed": self._executed,
            "failed": self._failed,
            "recovered": self._recovered,
            "queue": self._repository.queue_counts(),
            "stale_jobs": self._repository.stale_job_count(now=self._clock()),
        }


__all__ = ["GovernanceAutomationScheduler"]
