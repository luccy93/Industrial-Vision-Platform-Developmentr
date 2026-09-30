"""Tracking manager integration — multi-camera, errors, metrics."""

from __future__ import annotations

from uuid import uuid4

from backend.app.core.config import Settings
from backend.app.tracking.manager import TrackingManager
from backend.tests.tracking_helpers import make_detection, utc


def _manager() -> TrackingManager:
    return TrackingManager(Settings(_env_file=None))  # type: ignore[call-arg]


def test_manager_isolates_cameras() -> None:
    manager = _manager()
    for i in range(4):
        manager.update("cam-01", [make_detection(x1=100 + i, camera_id="cam-01")], uuid4(), utc(i * 0.1))
        manager.update("cam-02", [make_detection(x1=100 + i, camera_id="cam-02")], uuid4(), utc(i * 0.1))
    first = manager.active_tracks("cam-01")
    second = manager.active_tracks("cam-02")
    assert len(first) == 1 and len(second) == 1
    assert first[0].camera_id == "cam-01" and second[0].camera_id == "cam-02"
    assert first[0].track_id == second[0].track_id == 1  # independent spaces
    assert manager.status()["active_cameras"] == 2


def test_manager_error_isolation() -> None:
    manager = _manager()
    # Garbage input type must not crash the manager.
    result = manager.update("cam-x", "not-detections", uuid4(), utc())  # type: ignore[arg-type]
    assert result == []
    status = manager.status()
    assert status["errors"] == 1
    assert status["last_error"] is not None
    # Manager still works afterwards.
    tracks = manager.update("cam-x", [make_detection()], uuid4(), utc())
    assert len(tracks) == 1


def test_reset_camera_policy() -> None:
    manager = _manager()
    manager.update("cam-r", [make_detection()], uuid4(), utc())
    manager.reset_camera("cam-r")
    assert manager.active_tracks("cam-r") == []
    fresh = manager.update("cam-r", [make_detection()], uuid4(), utc())
    assert fresh[0].track_id == 1  # IDs restart safely


def test_status_metrics_shape() -> None:
    manager = _manager()
    manager.update("cam-m", [make_detection(), make_detection(x1=400)], uuid4(), utc())
    status = manager.status()
    assert status["tracker"] == "bytetrack-native"
    assert status["active_cameras"] == 1
    assert status["active_tracks"] == 2
    assert status["detections_processed"] == 2
    assert status["tracking_updates"] == 1
    assert status["tracking_fps"] >= 0
