"""Tracking performance tests — latency, FPS, bounded memory, isolation."""

from __future__ import annotations

import time
from uuid import uuid4

from backend.app.core.config import Settings
from backend.app.tracking.bytetrack import ByteTrackConfig, ByteTrackTracker
from backend.app.tracking.manager import TrackingManager
from backend.tests.tracking_helpers import make_detection, utc


def test_tracking_latency_and_fps() -> None:
    tracker = ByteTrackTracker("perf", ByteTrackConfig(min_hits=1))
    detections = [make_detection(x1=100 + i * 60) for i in range(5)]
    started = time.time()
    for i in range(200):
        tracker.update(detections, uuid4(), utc(i * 0.1))
    elapsed = time.time() - started
    fps = 200 / elapsed
    assert fps > 50  # CPU tracking must clear 50 updates/sec easily
    assert elapsed < 10.0


def test_history_memory_bounded() -> None:
    tracker = ByteTrackTracker("mem", ByteTrackConfig(min_hits=1, history_size=10, max_age=1000))
    for i in range(100):
        tracks = tracker.update([make_detection(x1=100 + (i % 20))], uuid4(), utc(i * 0.1))
    assert len(tracks) == 1
    assert len(tracks[0].history) == 10


def test_eight_cameras_no_leakage() -> None:
    manager = TrackingManager(Settings(_env_file=None))  # type: ignore[call-arg]
    for frame in range(10):
        for cam in range(8):
            manager.update(
                f"cam-{cam}",
                [make_detection(x1=100 + frame, camera_id=f"cam-{cam}")],
                uuid4(),
                utc(frame * 0.1),
            )
    status = manager.status()
    assert status["active_cameras"] == 8
    assert status["active_tracks"] == 8
    for cam in range(8):
        tracks = manager.active_tracks(f"cam-{cam}")
        assert len(tracks) == 1
        assert tracks[0].camera_id == f"cam-{cam}"
        assert tracks[0].track_id == 1


def test_intermittent_detections_survive() -> None:
    """Every-other-frame detections keep the track (max_age tolerance)."""
    tracker = ByteTrackTracker("gap", ByteTrackConfig(min_hits=1, max_age=5))
    ids = set()
    for i in range(10):
        dets = [make_detection(x1=100 + i * 2)] if i % 2 == 0 else []
        for track in tracker.update(dets, uuid4(), utc(i * 0.1)):
            ids.add(track.track_id)
    assert ids == {1}
