"""Application runtime lifecycle tests — states, phases, idempotent shutdown."""

from __future__ import annotations

from typing import Any

import pytest

from backend.app.runtime.manager import (
    SHUTDOWN_PHASES,
    STARTUP_PHASES,
    ApplicationRuntime,
    InvalidLifecycleTransition,
    RuntimeState,
)


def test_initial_state_is_created() -> None:
    runtime = ApplicationRuntime()
    assert runtime.state is RuntimeState.CREATED
    assert not runtime.is_ready
    assert not runtime.is_shutting_down


def test_initialize_runs_phases_in_order() -> None:
    runtime = ApplicationRuntime()
    seen: list[str] = []

    def _record(phase: str) -> str:
        seen.append(phase)
        return "ok"

    def _handler_for(phase: str) -> Any:
        def _run() -> str:
            return _record(phase)

        return _run

    for phase in STARTUP_PHASES:
        runtime.register_phase(phase, _handler_for(phase))
    results = runtime.initialize()
    assert [r.name for r in results] == list(STARTUP_PHASES)
    assert all(r.ok for r in results)
    assert seen == list(STARTUP_PHASES)
    assert runtime.state is RuntimeState.READY
    assert runtime.is_ready


def test_initialize_rejects_double_start() -> None:
    runtime = ApplicationRuntime()
    runtime.initialize()
    with pytest.raises(InvalidLifecycleTransition):
        runtime.initialize()


def test_invalid_transitions_rejected() -> None:
    runtime = ApplicationRuntime()
    # CREATED -> READY skips INITIALIZING.
    with pytest.raises(InvalidLifecycleTransition):
        runtime._move(RuntimeState.READY)  # noqa: SLF001
    # CREATED -> STOPPED via _move is invalid (shutdown() handles it).
    with pytest.raises(InvalidLifecycleTransition):
        runtime._move(RuntimeState.STOPPED)  # noqa: SLF001


def test_shutdown_from_ready_drains_then_stops() -> None:
    runtime = ApplicationRuntime()
    runtime.initialize()
    results = runtime.shutdown()
    assert [r.name for r in results] == list(SHUTDOWN_PHASES)
    assert runtime.state is RuntimeState.STOPPED
    assert runtime.is_shutting_down


def test_shutdown_is_idempotent() -> None:
    runtime = ApplicationRuntime()
    runtime.initialize()
    calls = 0

    def _handler() -> str:
        nonlocal calls
        calls += 1
        return "ok"

    runtime.register_phase("mark_draining", _handler, shutdown=True)
    first = runtime.shutdown()
    second = runtime.shutdown()
    assert calls == 1
    assert [r.name for r in second] == [r.name for r in first]
    assert runtime.state is RuntimeState.STOPPED


def test_shutdown_from_created_is_safe() -> None:
    runtime = ApplicationRuntime()
    assert runtime.shutdown() == []
    assert runtime.state is RuntimeState.STOPPED
    assert runtime.shutdown() == []


def test_failing_phase_does_not_block_shutdown() -> None:
    runtime = ApplicationRuntime()
    runtime.initialize()

    def _boom() -> str:
        raise RuntimeError("phase down")

    runtime.register_phase("stop_camera_streams", _boom, shutdown=True)
    results = runtime.shutdown()
    by_name = {r.name: r for r in results}
    assert by_name["stop_camera_streams"].ok is False
    assert runtime.state is RuntimeState.STOPPED


def test_unknown_phase_names_rejected() -> None:
    runtime = ApplicationRuntime()
    with pytest.raises(ValueError):
        runtime.register_phase("nope", lambda: "ok")
    with pytest.raises(ValueError):
        runtime.register_phase("nope", lambda: "ok", shutdown=True)


def test_health_snapshot() -> None:
    runtime = ApplicationRuntime()
    snapshot = runtime.health()
    assert snapshot["state"] == "CREATED"
    assert snapshot["ready"] is False
    runtime.initialize()
    assert runtime.health()["ready"] is True
