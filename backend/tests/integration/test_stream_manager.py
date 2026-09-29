"""Stream manager tests — lifecycle, metrics, reconnect, failure isolation."""

from __future__ import annotations

import time

from backend.app.domain.stream import StreamState
from backend.app.ingestion.manager import StreamManager, StreamSupervisor
from backend.tests.helpers import FakeVideoSource, make_camera


def _manager(**overrides) -> StreamManager:  # type: ignore[no-untyped-def]
    camera = make_camera()
    params = {
        "buffer_size": 8,
        "target_processing_fps": 1000.0,
        "backoff_initial": 0.01,
        "backoff_max": 0.05,
    }
    params.update(overrides)
    manager = StreamManager(camera, source_factory=lambda cam: FakeVideoSource(cam, total=40), **params)  # type: ignore[arg-type]
    return manager


def _wait_for(manager: StreamManager, states: set, timeout: float = 10.0) -> StreamState:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if manager.state in states:
            return manager.state
        time.sleep(0.02)
    return manager.state


def test_manager_reaches_running_and_collects_metrics() -> None:
    manager = _manager()
    try:
        manager.start()
        assert _wait_for(manager, {StreamState.RUNNING}) == StreamState.RUNNING
        time.sleep(0.3)
        metrics = manager.status()
        assert metrics.frames_received > 0
        assert metrics.frames_processed > 0
        assert metrics.width == 320 and metrics.height == 240
        assert metrics.uptime_seconds >= 0
    finally:
        manager.stop()
    assert manager.state == StreamState.STOPPED


def test_manager_stop_is_idempotent() -> None:
    manager = _manager()
    manager.start()
    _wait_for(manager, {StreamState.RUNNING})
    manager.stop()
    manager.stop()
    assert manager.state == StreamState.STOPPED


def test_failing_source_reconnects_with_backoff() -> None:
    camera = make_camera()
    manager = StreamManager(
        camera,
        source_factory=lambda cam: FakeVideoSource(cam, fail_open=True),
        backoff_initial=0.01,
        backoff_max=0.03,
    )
    try:
        manager.start()
        time.sleep(0.5)
        assert manager.status().reconnect_count >= 1
        assert manager.state in (
            StreamState.RECONNECTING,
            StreamState.CONNECTING,
            StreamState.ERROR,
        )
    finally:
        manager.stop()


def test_failed_camera_does_not_crash_supervisor() -> None:
    supervisor = StreamSupervisor()
    good = supervisor.register(
        make_camera(camera_id="good"),
        source_factory=lambda cam: FakeVideoSource(cam, total=1000),
        target_processing_fps=1000.0,
        backoff_initial=0.01,
        backoff_max=0.03,
    )
    bad = supervisor.register(
        make_camera(camera_id="bad"),
        source_factory=lambda cam: FakeVideoSource(cam, fail_open=True),
        backoff_initial=0.01,
        backoff_max=0.03,
    )
    try:
        good.start()
        bad.start()
        assert _wait_for(good, {StreamState.RUNNING}) == StreamState.RUNNING
        deadline = time.time() + 10
        while time.time() < deadline:
            if bad.status().reconnect_count >= 1 and bad.state != StreamState.RUNNING:
                break
            time.sleep(0.05)
        assert bad.status().reconnect_count >= 1
        assert bad.state != StreamState.RUNNING
        assert good.state == StreamState.RUNNING
        assert set(supervisor.statuses().keys()) == {"good", "bad"}
    finally:
        supervisor.stop_all()
    assert supervisor.remove("good") is True
    assert supervisor.remove("missing") is False
