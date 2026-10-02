"""V06 proximity tests — relationships, strategies, canonical pair identity."""

from __future__ import annotations

from typing import Any

from backend.app.core.config import Settings
from backend.app.safety.base import SceneState
from backend.app.spatial.engine import (
    MAX_PAIRS_PER_RELATIONSHIP,
    SpatialEngine,
    _evaluate_pair,
)
from backend.app.spatial.rules import ProximityRule
from backend.app.spatial.schemas import ProximityStrategy
from backend.tests.safety_helpers import make_track, utc

_WIDTH, _HEIGHT = 1000.0, 1000.0
# Person and vehicle boxes whose centers are ~0.15 frame apart (overlapping-ish).
_PERSON_NEAR = (400.0, 300.0, 480.0, 600.0)
_VEHICLE_NEAR = (500.0, 350.0, 800.0, 650.0)
_PERSON_FAR = (100.0, 100.0, 160.0, 400.0)
_VEHICLE_FAR = (800.0, 500.0, 980.0, 800.0)


def _settings(**overrides: Any) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _person(track_id: int, box=_PERSON_NEAR):  # type: ignore[no-untyped-def]
    return make_track(track_id, "person", box)


def _vehicle(track_id: int, box=_VEHICLE_NEAR, camera_id: str = "cam-p"):  # type: ignore[no-untyped-def]
    return make_track(track_id, "forklift", box, camera_id=camera_id)


def _engine(**overrides: Any) -> SpatialEngine:
    return SpatialEngine(_settings(**overrides))


def test_person_vehicle_detected_and_far_pair_ignored() -> None:
    engine = _engine()
    tracks = [_person(1, _PERSON_NEAR), _vehicle(2, _VEHICLE_NEAR)]
    detections = engine.process_proximity("cam-p", tracks, _WIDTH, _HEIGHT, utc(0))
    assert len(detections) == 1
    detection = detections[0]
    assert detection.relationship.value == "PERSON_VEHICLE"
    assert (detection.track_a, detection.track_b) == (1, 2)
    assert detection.severity.value == "HIGH"
    assert detection.evidence["image_space"] is True

    far = engine.process_proximity(
        "cam-p", [_person(1, _PERSON_FAR), _vehicle(2, _VEHICLE_FAR)], _WIDTH, _HEIGHT, utc(0)
    )
    assert far == []


def test_pair_identity_is_order_independent() -> None:
    engine = _engine()
    forward = engine.process_proximity(
        "cam-p", [_vehicle(2, _VEHICLE_NEAR), _person(1, _PERSON_NEAR)], _WIDTH, _HEIGHT, utc(0)
    )
    assert forward[0].track_a == 1 and forward[0].track_b == 2
    assert forward[0].pair_key == "cam-p:1:2"


def test_person_person_and_vehicle_vehicle_disabled_by_default() -> None:
    engine = _engine()
    tracks = [_person(1), make_track(2, "person", _PERSON_NEAR)]
    assert engine.process_proximity("cam-p", tracks, _WIDTH, _HEIGHT, utc(0)) == []
    vehicles = [_vehicle(1), make_track(2, "truck", _VEHICLE_NEAR, camera_id="cam-p")]
    assert engine.process_proximity("cam-p", vehicles, _WIDTH, _HEIGHT, utc(0)) == []


def test_person_person_and_vehicle_vehicle_when_enabled() -> None:
    engine = _engine(spatial_person_person_enabled=True, spatial_vehicle_vehicle_enabled=True)
    people = engine.process_proximity(
        "cam-p", [_person(1), make_track(2, "person", _PERSON_NEAR)], _WIDTH, _HEIGHT, utc(0)
    )
    assert [d.relationship.value for d in people] == ["PERSON_PERSON"]
    assert people[0].severity.value == "MEDIUM"

    vehicles = engine.process_proximity(
        "cam-p",
        [_vehicle(1), make_track(2, "truck", _VEHICLE_NEAR, camera_id="cam-p")],
        _WIDTH,
        _HEIGHT,
        utc(0),
    )
    assert [d.relationship.value for d in vehicles] == ["VEHICLE_VEHICLE"]
    assert vehicles[0].severity.value == "LOW"


def test_tentative_tracks_excluded() -> None:
    from backend.app.tracking.schemas import TrackState

    engine = _engine()
    tentative = make_track(1, "person", _PERSON_NEAR, state=TrackState.TENTATIVE)
    assert engine.process_proximity("cam-p", [tentative, _vehicle(2)], _WIDTH, _HEIGHT, utc(0)) == []


def test_strategy_behaviour() -> None:
    # Far apart centers, zero overlap → only CENTER_DISTANCE can fire.
    a = (0.0, 0.0, 0.05, 0.05)
    b = (0.2, 0.2, 0.25, 0.25)
    ratio, iou, overlap = 0.3, 0.0, 0.0
    assert _evaluate_pair(ProximityStrategy.CENTER_DISTANCE, 0.5, 0.05, ratio, iou, overlap)[0] > 0
    assert _evaluate_pair(ProximityStrategy.IOU, 0.5, 0.05, ratio, iou, overlap)[0] == 0.0
    assert _evaluate_pair(ProximityStrategy.HYBRID, 0.5, 0.05, ratio, iou, overlap)[0] > 0

    # Overlapping boxes, far centers → IOU/HYBRID fire, CENTER_DISTANCE does not.
    assert _evaluate_pair(ProximityStrategy.CENTER_DISTANCE, 0.05, 0.05, ratio, 0.4, 0.8)[0] == 0.0
    assert _evaluate_pair(ProximityStrategy.IOU, 0.05, 0.05, ratio, 0.4, 0.8)[0] > 0
    assert _evaluate_pair(ProximityStrategy.HYBRID, 0.05, 0.05, ratio, 0.4, 0.8)[0] > 0
    del a, b


def test_strategy_selection_from_settings() -> None:
    engine = _engine(spatial_proximity_strategy="center_distance")
    assert engine._settings.spatial_proximity_strategy == "CENTER_DISTANCE"
    detections = engine.process_proximity("cam-p", [_person(1), _vehicle(2)], _WIDTH, _HEIGHT, utc(0))
    assert detections and detections[0].evidence["strategy"] == "CENTER_DISTANCE"


def test_pair_cap_bounds_scenarios() -> None:
    engine = _engine(spatial_person_person_enabled=True)
    people = [_person(i, (float(i % 100), 0.0, float(i % 100) + 10.0, 10.0)) for i in range(1, 90)]
    detections = engine.process_proximity("cam-p", people, _WIDTH, _HEIGHT, utc(0))
    # Bounded enumeration keeps a pathological scene from exploding: the
    # 4005 possible pairs are truncated at the documented cap.
    assert len(detections) == MAX_PAIRS_PER_RELATIONSHIP
    assert MAX_PAIRS_PER_RELATIONSHIP < 90 * 89 // 2
    # No self-pairs and no duplicates.
    pairs = {(d.track_a, d.track_b) for d in detections}
    assert len(pairs) == len(detections)
    assert all(a < b for a, b in pairs)


def test_proximity_rule_drafts() -> None:
    engine = _engine()
    rule = ProximityRule(engine)
    scene = SceneState(
        camera_id="cam-p",
        timestamp=utc(0),
        tracks=[_person(1), _vehicle(2)],
        frame_width=_WIDTH,
        frame_height=_HEIGHT,
    )
    drafts = rule.evaluate(scene)
    assert len(drafts) == 1
    draft = drafts[0]
    assert draft.event_type.value == "PERSON_VEHICLE_PROXIMITY"
    assert draft.dedupe_key == "proximity:cam-p:1:2:PERSON_VEHICLE"
    assert draft.track_ids == [1, 2]
    assert draft.evidence["image_space"] is True


def test_status_reports_relationships() -> None:
    status = _engine().status()
    assert status["coordinate_space"] == "normalized_image_space"
    assert status["membership_heuristic"] == "bounding_box_bottom_center"
    names = {r["relationship"]: r for r in status["relationships"]}
    assert set(names) == {"PERSON_VEHICLE", "PERSON_PERSON", "VEHICLE_VEHICLE"}
    assert names["PERSON_VEHICLE"]["enabled"] is True
    assert names["PERSON_PERSON"]["enabled"] is False
