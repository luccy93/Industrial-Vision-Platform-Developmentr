"""Tracking schema tests — states, velocity, serialization."""

from __future__ import annotations

from uuid import uuid4

from backend.app.inference.schemas import InferenceBoundingBox
from backend.app.tracking.schemas import TrackedObject, TrackState, TrackVelocity


def _track(**overrides) -> TrackedObject:  # type: ignore[no-untyped-def]
    params = {
        "track_id": 17,
        "camera_id": "cam-001",
        "class_id": 0,
        "class_name": "person",
        "confidence": 0.93,
        "bounding_box": InferenceBoundingBox(x1=312, y1=180, x2=612, y2=910),
        "frame_id": uuid4(),
    }
    params.update(overrides)
    return TrackedObject(**params)  # type: ignore[arg-type]


def test_default_state_and_counters() -> None:
    track = _track()
    assert track.state == TrackState.TENTATIVE
    assert track.age == 0 and track.hits == 0 and track.time_since_update == 0
    assert track.history == [] and track.metadata == {}


def test_all_four_states_exist() -> None:
    assert {s.value for s in TrackState} == {"TENTATIVE", "CONFIRMED", "LOST", "REMOVED"}


def test_velocity_defaults_to_zero() -> None:
    assert _track().velocity.speed == 0.0


def test_websocket_payload_matches_contract() -> None:
    payload = _track(
        state=TrackState.CONFIRMED,
        age=42,
        hits=39,
        velocity=TrackVelocity(x=21.4, y=-3.1, speed=21.6),
    ).to_websocket()
    assert payload["track_id"] == 17
    assert payload["state"] == "CONFIRMED"
    assert payload["bounding_box"] == {"x1": 312, "y1": 180, "x2": 612, "y2": 910}
    assert payload["velocity"] == {"x": 21.4, "y": -3.1, "speed": 21.6}
    assert "safety" not in str(payload).lower()
