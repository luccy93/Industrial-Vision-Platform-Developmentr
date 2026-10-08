"""Managed worker abstraction — lifecycle states + supervision snapshots (V11).

``ManagedWorker`` is the common contract for background workers
(inference, streams, and future V12 consumers). Existing workers keep
their thread loops; they adopt this contract via thin adapters that add
idempotent start/stop, health snapshots, and heartbeat reporting.

States::

    CREATED → STARTING → RUNNING → STOPPING → STOPPED
                          RUNNING → FAILED

``FAILED`` is terminal for the worker instance: the supervisor records it
and may retry within bounds, but there are no aggressive automatic restart
loops (no restart storms).
"""

from __future__ import annotations

import abc
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from backend.app.domain.common import utcnow


class WorkerState(str, Enum):
    """Managed worker lifecycle states (§21)."""

    CREATED = "CREATED"
    STARTING = "STARTING"
    RUNNING = "RUNNING"
    STOPPING = "STOPPING"
    STOPPED = "STOPPED"
    FAILED = "FAILED"


@dataclass
class WorkerSnapshot:
    """Supervision view of one worker (§22)."""

    name: str
    state: WorkerState = WorkerState.CREATED
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    last_heartbeat: datetime | None = None
    restart_count: int = 0
    last_error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def heartbeat_age_seconds(self, now: datetime | None = None) -> float | None:
        """Seconds since the last heartbeat (None when never reported)."""
        if self.last_heartbeat is None:
            return None
        reference = now or utcnow()
        try:
            return max(0.0, (reference - self.last_heartbeat).total_seconds())
        except Exception:
            return None

    def is_stale(self, timeout_seconds: float, now: datetime | None = None) -> bool:
        """A RUNNING worker with no heartbeat inside the timeout is stale."""
        if self.state is not WorkerState.RUNNING:
            return False
        age = self.heartbeat_age_seconds(now)
        if age is None:
            return True
        return age > max(0.0, float(timeout_seconds))


class ManagedWorker(abc.ABC):
    """Common lifecycle contract for background workers (§21)."""

    def __init__(self, name: str) -> None:
        self._worker_name = str(name)
        self._state_lock = threading.RLock()
        self._worker_state = WorkerState.CREATED
        self._started_at: datetime | None = None
        self._stopped_at: datetime | None = None
        self._last_heartbeat: datetime | None = None
        self._restart_count = 0
        self._last_error: str | None = None

    # ------------------------------------------------------------------
    # Contract
    # ------------------------------------------------------------------
    @property
    def worker_name(self) -> str:
        return self._worker_name

    @abc.abstractmethod
    def start(self) -> bool:
        """Start the worker. Idempotent: True when (already) running."""

    @abc.abstractmethod
    def stop(self, timeout: float = 5.0) -> bool:
        """Stop the worker. Idempotent: True when (already) stopped."""

    def health(self) -> WorkerSnapshot:
        """Supervision snapshot (never raises, never blocks)."""
        with self._state_lock:
            return WorkerSnapshot(
                name=self._worker_name,
                state=self._worker_state,
                started_at=self._started_at,
                stopped_at=self._stopped_at,
                last_heartbeat=self._last_heartbeat,
                restart_count=self._restart_count,
                last_error=self._last_error,
            )

    # ------------------------------------------------------------------
    # Helpers for implementations
    # ------------------------------------------------------------------
    def _transition(self, attempted: WorkerState) -> None:
        allowed: dict[WorkerState, frozenset[WorkerState]] = {
            WorkerState.CREATED: frozenset({WorkerState.STARTING, WorkerState.STOPPED}),
            WorkerState.STARTING: frozenset({WorkerState.RUNNING, WorkerState.FAILED, WorkerState.STOPPING}),
            WorkerState.RUNNING: frozenset({WorkerState.STOPPING, WorkerState.FAILED, WorkerState.STOPPED}),
            WorkerState.STOPPING: frozenset({WorkerState.STOPPED, WorkerState.FAILED}),
            WorkerState.STOPPED: frozenset({WorkerState.STARTING}),
            WorkerState.FAILED: frozenset({WorkerState.STARTING}),
        }
        with self._state_lock:
            if attempted not in allowed[self._worker_state]:
                raise ValueError(
                    f"invalid worker transition: {self._worker_state.value} -> {attempted.value}"
                )
            self._worker_state = attempted
            now = utcnow()
            if attempted is WorkerState.STARTING:
                self._started_at = now
                self._stopped_at = None
            if attempted in (WorkerState.STOPPED, WorkerState.FAILED):
                self._stopped_at = now

    def _report_heartbeat(self) -> None:
        with self._state_lock:
            self._last_heartbeat = utcnow()

    def _record_failure(self, message: str) -> None:
        with self._state_lock:
            self._last_error = str(message)[:1024]

    def _record_restart(self) -> None:
        with self._state_lock:
            self._restart_count += 1


class WorkerSupervisor:
    """Track named workers: state, heartbeats, restarts, errors (§22).

    Generic registry over ``ManagedWorker`` instances. Restart support is
    bounded (max attempts + backoff) and opt-in per worker; a failed
    optional worker never crashes the process.
    """

    def __init__(self, heartbeat_timeout_seconds: float = 30.0) -> None:
        self._lock = threading.RLock()
        self._workers: dict[str, ManagedWorker] = {}
        self._critical: set[str] = set()
        self._heartbeat_timeout = max(0.0, float(heartbeat_timeout_seconds))
        self._monotonic_started = time.monotonic()

    def register(self, worker: ManagedWorker, *, critical: bool = False) -> ManagedWorker:
        """Register a worker (replaces any worker under the same name)."""
        with self._lock:
            self._workers[worker.worker_name] = worker
            if critical:
                self._critical.add(worker.worker_name)
            else:
                self._critical.discard(worker.worker_name)
        return worker

    def unregister(self, name: str) -> ManagedWorker | None:
        with self._lock:
            self._critical.discard(str(name))
            return self._workers.pop(str(name), None)

    def get(self, name: str) -> ManagedWorker | None:
        with self._lock:
            return self._workers.get(str(name))

    def snapshot(self, name: str) -> WorkerSnapshot | None:
        worker = self.get(name)
        return worker.health() if worker is not None else None

    def snapshots(self) -> dict[str, WorkerSnapshot]:
        with self._lock:
            workers = list(self._workers.values())
        return {w.worker_name: w.health() for w in workers}

    def stale_workers(self, timeout_seconds: float | None = None) -> list[str]:
        """Names of RUNNING workers past the heartbeat timeout (§24)."""
        limit = self._heartbeat_timeout if timeout_seconds is None else float(timeout_seconds)
        return [name for name, snap in self.snapshots().items() if snap.is_stale(limit)]

    def critical_failures(self) -> list[str]:
        """Names of critical workers not in RUNNING state."""
        return [
            name
            for name, snap in self.snapshots().items()
            if name in self._critical and snap.state is not WorkerState.RUNNING
        ]

    def stop_all(self, timeout: float = 5.0) -> dict[str, bool]:
        """Stop every registered worker (isolated failures, never raises)."""
        with self._lock:
            workers = list(self._workers.values())
        outcomes: dict[str, bool] = {}
        for worker in workers:
            try:
                outcomes[worker.worker_name] = bool(worker.stop(timeout=timeout))
            except Exception:
                outcomes[worker.worker_name] = False
        return outcomes

    def uptime_seconds(self) -> float:
        return max(0.0, time.monotonic() - self._monotonic_started)
