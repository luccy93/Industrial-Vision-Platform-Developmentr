"""Managed worker base tests — lifecycle, snapshots, supervision."""

from __future__ import annotations

from datetime import UTC

import pytest

from backend.app.workers.base import ManagedWorker, WorkerSnapshot, WorkerState, WorkerSupervisor


class _ScriptWorker(ManagedWorker):
    def __init__(self, name: str = "script") -> None:
        super().__init__(name)
        self.starts = 0
        self.stops = 0
        self.fail_start = False

    def start(self) -> bool:
        with self._state_lock:
            if self._worker_state is WorkerState.RUNNING:
                return True
        if self.fail_start:
            self._transition(WorkerState.STARTING)
            self._record_failure("boom")
            self._transition(WorkerState.FAILED)
            return False
        self._transition(WorkerState.STARTING)
        self._transition(WorkerState.RUNNING)
        self._report_heartbeat()
        self.starts += 1
        return True

    def stop(self, timeout: float = 5.0) -> bool:
        with self._state_lock:
            if self._worker_state in (WorkerState.STOPPED, WorkerState.CREATED):
                return True
        self._transition(WorkerState.STOPPING)
        self._transition(WorkerState.STOPPED)
        self.stops += 1
        return True


def test_start_stop_lifecycle() -> None:
    worker = _ScriptWorker()
    assert worker.health().state is WorkerState.CREATED
    assert worker.start() is True
    snapshot = worker.health()
    assert snapshot.state is WorkerState.RUNNING
    assert snapshot.started_at is not None
    assert snapshot.last_heartbeat is not None
    assert worker.stop() is True
    assert worker.health().state is WorkerState.STOPPED
    assert worker.health().stopped_at is not None


def test_double_start_and_double_stop() -> None:
    worker = _ScriptWorker()
    assert worker.start() is True
    assert worker.start() is True
    assert worker.starts == 1
    assert worker.stop() is True
    assert worker.stop() is True
    assert worker.stops == 1


def test_failure_recorded() -> None:
    worker = _ScriptWorker()
    worker.fail_start = True
    assert worker.start() is False
    snapshot = worker.health()
    assert snapshot.state is WorkerState.FAILED
    assert snapshot.last_error == "boom"


def test_invalid_transition_rejected() -> None:
    worker = _ScriptWorker()
    with pytest.raises(ValueError):
        worker._transition(WorkerState.RUNNING)  # noqa: SLF001


def test_snapshot_staleness() -> None:
    from datetime import datetime, timedelta

    base = datetime(2026, 1, 1, tzinfo=UTC)
    fresh = WorkerSnapshot(name="w", state=WorkerState.RUNNING, last_heartbeat=base)
    assert fresh.is_stale(30.0, now=base) is False
    assert fresh.is_stale(30.0, now=base + timedelta(seconds=31)) is True
    assert fresh.is_stale(0.0, now=base + timedelta(seconds=1)) is True
    never = WorkerSnapshot(name="w", state=WorkerState.RUNNING)
    assert never.is_stale(30.0) is True
    stopped = WorkerSnapshot(name="w", state=WorkerState.STOPPED)
    assert stopped.is_stale(0.0) is False


def test_supervisor_tracks_workers() -> None:
    supervisor = WorkerSupervisor()
    worker = _ScriptWorker("a")
    supervisor.register(worker, critical=True)
    worker.start()
    assert supervisor.snapshot("a") is not None
    assert supervisor.snapshot("missing") is None
    assert supervisor.stale_workers(timeout_seconds=3600.0) == []
    assert supervisor.critical_failures() == []
    worker.stop()
    assert supervisor.critical_failures() == ["a"]


def test_supervisor_stop_all_isolated() -> None:
    class _Bad(ManagedWorker):
        def start(self) -> bool:
            return True

        def stop(self, timeout: float = 5.0) -> bool:
            raise RuntimeError("cannot stop")

    supervisor = WorkerSupervisor()
    supervisor.register(_ScriptWorker("good"))
    supervisor.register(_Bad("bad"))
    outcomes = supervisor.stop_all()
    assert outcomes["bad"] is False
    assert set(outcomes) == {"good", "bad"}


def test_unregister() -> None:
    supervisor = WorkerSupervisor()
    worker = _ScriptWorker("temp")
    supervisor.register(worker, critical=True)
    assert supervisor.unregister("temp") is worker
    assert supervisor.unregister("temp") is None
    assert supervisor.critical_failures() == []
