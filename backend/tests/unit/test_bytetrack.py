"""Native ByteTrack tests — association, lifecycle cases, isolation."""

from __future__ import annotations

from uuid import uuid4

import numpy as np

from backend.app.tracking.base import Tracker
from backend.app.tracking.bytetrack import ByteTrackConfig, ByteTrackTracker, iou_matrix
from backend.app.tracking.schemas import TrackState
from backend.tests.tracking_helpers import make_detection, utc


def _tracker(**overrides) -> ByteTrackTracker:  # type: ignore[no-untyped-def]
    params = {"min_hits": 3, "max_age": 5, "iou_threshold": 0.3, "history_size": 10}
    params.update(overrides)
    return ByteTrackTracker("cam-t", ByteTrackConfig(**params))  # type: ignore[arg-type]


def test_interface_compliance() -> None:
    assert isinstance(_tracker(), Tracker)
    assert _tracker().name == "bytetrack-native"


def test_iou_matrix_values() -> None:
    tracks = np.array([[0.0, 0.0, 100.0, 100.0]])
    dets = np.array([[50.0, 50.0, 150.0, 150.0], [200.0, 200.0, 300.0, 300.0]])
    iou = iou_matrix(tracks, dets)
    assert iou.shape == (1, 2)
    assert abs(iou[0, 0] - 2500 / 17500) < 1e-9
    assert iou[0, 1] == 0.0
    assert iou_matrix(np.zeros((0, 4)), dets).shape == (0, 2)


def test_case1_repeated_detections_same_id() -> None:
    """Detection ×3 → one track, TENTATIVE → CONFIRMED, stable ID."""
    tracker = _tracker()
    ids = set()
    for i in range(3):
        tracks = tracker.update([make_detection(x1=100 + i * 5)], uuid4(), utc(i * 0.1))
        assert len(tracks) == 1
        ids.add(tracks[0].track_id)
    assert ids == {1}
    assert tracks[0].state == TrackState.CONFIRMED
    assert tracks[0].hits == 3


def test_single_detection_needs_confirmation() -> None:
    tracker = _tracker(min_hits=3)
    tracks = tracker.update([make_detection()], uuid4(), utc())
    assert tracks[0].state == TrackState.TENTATIVE
    fast = _tracker(min_hits=1)
    assert fast.update([make_detection()], uuid4(), utc())[0].state == TrackState.CONFIRMED


def test_case2_gap_within_max_age_survives() -> None:
    tracker = _tracker(max_age=5)
    tracker.update([make_detection()], uuid4(), utc(0.0))
    tracker.update([make_detection()], uuid4(), utc(0.1))
    missed = tracker.update([], uuid4(), utc(0.2))
    assert len(missed) == 1 and missed[0].state == TrackState.LOST
    found = tracker.update([make_detection(x1=102)], uuid4(), utc(0.3))
    assert len(found) == 1 and found[0].track_id == 1
    assert found[0].state == TrackState.CONFIRMED


def test_case3_long_gap_removes_track() -> None:
    tracker = _tracker(max_age=3)
    tracker.update([make_detection()], uuid4(), utc(0.0))
    tracker.update([make_detection()], uuid4(), utc(0.1))
    for i in range(2, 8):
        tracks = tracker.update([], uuid4(), utc(i * 0.1))
    assert tracks == []
    assert tracker.active_tracks() == []
    # A later detection starts a NEW track (IDs keep incrementing).
    fresh = tracker.update([make_detection()], uuid4(), utc(1.0))
    assert fresh[0].track_id == 2


def test_case4_camera_isolation() -> None:
    first = ByteTrackTracker("cam-01", ByteTrackConfig(min_hits=1))
    second = ByteTrackTracker("cam-02", ByteTrackConfig(min_hits=1))
    track_a = first.update([make_detection(camera_id="cam-01")], uuid4(), utc())[0]
    track_b = second.update([make_detection(camera_id="cam-02")], uuid4(), utc())[0]
    assert (track_a.camera_id, track_a.track_id) == ("cam-01", 1)
    assert (track_b.camera_id, track_b.track_id) == ("cam-02", 1)
    assert first.active_tracks()[0].camera_id != second.active_tracks()[0].camera_id


def test_multiple_objects_keep_identities() -> None:
    tracker = _tracker(min_hits=1)
    for i in range(4):
        tracks = tracker.update(
            [make_detection(x1=100 + i * 3), make_detection(x1=400 - i * 3)],
            uuid4(),
            utc(i * 0.1),
        )
        assert len(tracks) == 2
    assert {t.track_id for t in tracks} == {1, 2}
    left = next(t for t in tracks if t.track_id == 1)
    assert left.bounding_box.x1 < 200


def test_multiple_classes() -> None:
    tracker = _tracker(min_hits=1)
    tracks = tracker.update(
        [
            make_detection(x1=100, class_id=0, class_name="person"),
            make_detection(x1=400, class_id=2, class_name="car"),
        ],
        uuid4(),
        utc(),
    )
    assert {t.class_name for t in tracks} == {"person", "car"}


def test_low_confidence_continues_track() -> None:
    """ByteTrack stage-2: a weak detection keeps the track alive."""
    tracker = _tracker(min_hits=1, high_confidence=0.5)
    tracker.update([make_detection(conf=0.9)], uuid4(), utc(0.0))
    tracks = tracker.update([make_detection(conf=0.3, x1=102)], uuid4(), utc(0.1))
    assert len(tracks) == 1 and tracks[0].track_id == 1


def test_unmatched_low_confidence_starts_nothing() -> None:
    tracker = _tracker()
    assert tracker.update([make_detection(conf=0.2, x1=500)], uuid4(), utc()) == []


def test_history_is_bounded() -> None:
    tracker = _tracker(min_hits=1, history_size=5)
    for i in range(12):
        tracks = tracker.update([make_detection(x1=100 + i)], uuid4(), utc(i * 0.1))
    assert len(tracks[0].history) == 5


def test_velocity_pixels_per_second() -> None:
    tracker = _tracker(min_hits=1)
    tracker.update([make_detection(x1=100, timestamp=utc(0.0))], uuid4(), utc(0.0))
    tracks = tracker.update([make_detection(x1=120, timestamp=utc(0.5))], uuid4(), utc(0.5))
    velocity = tracks[0].velocity
    assert abs(velocity.x - 40.0) < 1e-6  # 20 px / 0.5 s
    assert abs(velocity.speed - 40.0) < 1e-6


def test_reset_restarts_ids() -> None:
    tracker = _tracker(min_hits=1)
    tracker.update([make_detection()], uuid4(), utc())
    tracker.reset()
    assert tracker.active_tracks() == []
    assert tracker.update([make_detection()], uuid4(), utc())[0].track_id == 1
