"""Bounded V33 audit scheduler.

The scheduler is a supervised worker with a bounded interval, durable slot
identifiers, stale-run recovery, and retention pruning. It never changes the
configured frequency silently and never retries a failed audit into a pass.
"""

from __future__ import annotations

import threading
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.core.config import Settings
from backend.app.core.logging import get_logger
from backend.app.integrity.constants import AuditTrigger, IntegrityScope
from backend.app.integrity.errors import DuplicateAuditRunError, MonitoringStoreError
from backend.app.integrity.runner import AuditRunner
from backend.app.integrity.store import MonitoringStore
from backend.app.workers.base import ManagedWorker, WorkerState

logger = get_logger("industrial-vision.integrity.scheduler")


class IntegrityScheduler(ManagedWorker):
    """Run FULL audits on a bounded interval and recover interrupted runs."""

    def __init__(
        self,
        *,
        settings: Settings,
        store: MonitoringStore,
        runner: AuditRunner,
        name: str = "integrity-scheduler",
    ) -> None:
        super().__init__(name)
        self._settings = settings
        self._store = store
        self._runner = runner
        self._interval = max(30.0, float(settings.integrity_scheduler_interval_seconds))
        self._stale_seconds = max(60.0, float(settings.integrity_stale_run_seconds))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_slot: str | None = None
        self._last_cycle_at: str | None = None
        self._last_success_at: str | None = None
        self._last_error: str | None = None
        self._last_prune_date: str | None = None
        self._cycles = 0
        self._runs_started = 0

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
        self._thread = threading.Thread(target=self._loop, name=f"integrity-{self.worker_name}", daemon=True)
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
                except Exception as exc:
                    self._record_failure(f"{type(exc).__name__}: {exc}")
                    logger.warning("integrity scheduler cycle failed: %s", type(exc).__name__)
                    self._record_metric("failed")
                self._stop_event.wait(self._interval)
        except Exception as exc:
            self._record_failure(f"{type(exc).__name__}: {exc}")
            with self._state_lock:
                try:
                    self._transition(WorkerState.FAILED)
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # Scheduler cycle
    # ------------------------------------------------------------------
    def run_once(self, now: datetime | None = None) -> dict[str, Any]:
        reference = (now or datetime.now(UTC)).astimezone(UTC)
        stats: dict[str, Any] = {
            "recovered": 0,
            "pruned": 0,
            "started": False,
            "skipped": False,
            "audit_run_id": None,
            "audit_status": None,
            "failed": False,
        }
        self._cycles += 1
        self._last_cycle_at = reference.isoformat().replace("+00:00", "Z")
        try:
            stale_before = (
                (reference - timedelta(seconds=self._stale_seconds)).isoformat().replace("+00:00", "Z")
            )
            stats["recovered"] = len(self._store.recover_stale_runs(stale_before=stale_before))
        except MonitoringStoreError:
            stats["failed"] = True
            self._record_failure("MonitoringStoreError: stale-run recovery failed")
            self._record_metric("failed")
            self._report_heartbeat()
            return stats
        if self._last_prune_date != reference.date().isoformat():
            try:
                stats["pruned"] = self._store.prune(
                    retention_days=int(self._settings.integrity_retention_days),
                    limit=1000,
                )
                self._last_prune_date = reference.date().isoformat()
            except MonitoringStoreError:
                logger.warning("integrity retention prune failed")
        if not self._settings.integrity_scheduler_enabled:
            stats["skipped"] = True
            self._record_metric("skipped")
            self._report_heartbeat()
            return stats
        bucket = int(reference.timestamp() // self._interval)
        slot = f"slot-{bucket}"
        if self._last_slot == slot:
            stats["skipped"] = True
            self._record_metric("skipped")
            self._report_heartbeat()
            return stats
        try:
            existing = self._store.get_run_by_schedule_slot(slot)
        except MonitoringStoreError:
            existing = None
        if existing is not None:
            self._last_slot = slot
            stats["skipped"] = True
            stats["audit_run_id"] = existing.audit_run_id
            stats["audit_status"] = existing.status.value
            self._record_metric("skipped")
            self._report_heartbeat()
            return stats
        try:
            run = self._runner.execute(
                scopes=[IntegrityScope.FULL],
                trigger=AuditTrigger.SCHEDULED,
                requested_by="scheduler",
                schedule_slot=slot,
            )
        except DuplicateAuditRunError:
            stats["skipped"] = True
            self._record_metric("skipped")
            self._report_heartbeat()
            return stats
        except Exception as exc:
            stats["failed"] = True
            self._last_error = f"{type(exc).__name__}: scheduler audit failed"
            self._record_failure(self._last_error)
            logger.warning("scheduled integrity audit failed: %s", type(exc).__name__)
            self._record_metric("failed")
            self._report_heartbeat()
            return stats
        self._last_slot = slot
        self._runs_started += 1
        self._last_success_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        stats["started"] = True
        stats["audit_run_id"] = run.audit_run_id
        stats["audit_status"] = run.status.value
        self._record_metric("completed")
        self._report_heartbeat()
        return stats

    # ------------------------------------------------------------------
    # Status snapshot
    # ------------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        snapshot = self.health()
        return {
            "enabled": bool(self._settings.integrity_scheduler_enabled),
            "state": snapshot.state.value,
            "interval_seconds": self._interval,
            "stale_run_seconds": self._stale_seconds,
            "last_heartbeat": (snapshot.last_heartbeat.isoformat() if snapshot.last_heartbeat else None),
            "last_cycle_at": self._last_cycle_at,
            "last_success_at": self._last_success_at,
            "last_error": self._last_error or snapshot.last_error,
            "cycles": self._cycles,
            "runs_started": self._runs_started,
        }

    def _record_metric(self, outcome: str) -> None:
        try:
            from backend.app.core.metrics import record_integrity_scheduler_run

            record_integrity_scheduler_run(outcome)
        except Exception:
            pass


__all__ = ["IntegrityScheduler"]
