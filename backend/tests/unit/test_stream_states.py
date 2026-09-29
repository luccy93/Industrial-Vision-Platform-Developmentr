"""Stream state + camera domain tests — deterministic transitions."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.domain.camera import Camera
from backend.app.domain.stream import SourceType, StreamMetrics, StreamState


def test_valid_transitions() -> None:
    assert StreamState.DISCONNECTED.can_transition_to(StreamState.CONNECTING)
    assert StreamState.CONNECTING.can_transition_to(StreamState.CONNECTED)
    assert StreamState.CONNECTED.can_transition_to(StreamState.RUNNING)
    assert StreamState.RUNNING.can_transition_to(StreamState.STOPPING)
    assert StreamState.STOPPING.can_transition_to(StreamState.STOPPED)
    assert StreamState.STOPPED.can_transition_to(StreamState.CONNECTING)
    assert StreamState.RUNNING.can_transition_to(StreamState.ERROR)
    assert StreamState.ERROR.can_transition_to(StreamState.RECONNECTING)
    assert StreamState.RECONNECTING.can_transition_to(StreamState.CONNECTED)


def test_invalid_transitions_rejected() -> None:
    assert not StreamState.DISCONNECTED.can_transition_to(StreamState.RUNNING)
    assert not StreamState.STOPPED.can_transition_to(StreamState.RUNNING)
    assert not StreamState.RUNNING.can_transition_to(StreamState.CONNECTING)
    assert not StreamState.STOPPED.can_transition_to(StreamState.ERROR)


def test_all_eight_states_defined() -> None:
    assert {state.value for state in StreamState} == {
        "DISCONNECTED",
        "CONNECTING",
        "CONNECTED",
        "RUNNING",
        "STOPPING",
        "STOPPED",
        "ERROR",
        "RECONNECTING",
    }


def test_camera_v02_fields() -> None:
    camera = Camera(
        name="Line 1",
        camera_id="cam-01",
        source_type=SourceType.rtsp,
        source="rtsp://10.0.0.5/live",
        enabled=True,
        width=1920,
        height=1080,
        target_fps=15.0,
        reconnect_enabled=True,
    )
    assert camera.source_type == SourceType.rtsp
    assert camera.created_at is not None and camera.updated_at is not None


def test_camera_source_types() -> None:
    for source_type in ("usb", "rtsp", "file"):
        camera = Camera(name="c", camera_id="c1", source_type=source_type, source="s")  # type: ignore[arg-type]
        assert camera.source_type.value == source_type
    with pytest.raises(ValidationError):
        Camera(name="c", camera_id="c1", source_type="ndi", source="s")  # type: ignore[arg-type]


def test_metrics_defaults() -> None:
    metrics = StreamMetrics(camera_id="cam-01")
    assert metrics.state == StreamState.DISCONNECTED
    assert metrics.frames_dropped == 0
    assert metrics.reconnect_count == 0
