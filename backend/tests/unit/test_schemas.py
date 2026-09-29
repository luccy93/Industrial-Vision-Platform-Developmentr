"""Domain schema tests — contracts reusable by future volumes."""

from __future__ import annotations

import pytest
from pydantic import ValidationError as PydanticValidationError

from backend.app.domain import (
    Alert,
    BoundingBox,
    Camera,
    Detection,
    Frame,
    Incident,
    PerceptionEvent,
    QualityEvent,
    RiskAssessment,
    SafetyEvent,
    TrackedObject,
    VideoStream,
)


def _box() -> BoundingBox:
    return BoundingBox(x=10, y=20, width=100, height=50)


def test_bounding_box_derived_coordinates() -> None:
    box = _box()
    assert box.x2 == 110
    assert box.y2 == 70


def test_detection_requires_spatial_info_and_confidence_bounds() -> None:
    det = Detection(camera_id="cam-01", class_name="helmet", confidence=0.91, bounding_box=_box())
    assert det.camera_id == "cam-01"
    assert det.confidence == pytest.approx(0.91)
    with pytest.raises(PydanticValidationError):
        Detection(camera_id="cam-01", class_name="helmet", confidence=1.7, bounding_box=_box())


def test_all_domain_models_accept_metadata_and_timestamps() -> None:
    models = [
        Camera(name="Line 1", camera_id="cam-01"),
        VideoStream(camera_id="cam-01", stream_id="s-01"),
        Frame(camera_id="cam-01", frame_number=7),
        Detection(camera_id="cam-01", class_name="person", confidence=0.5, bounding_box=_box()),
        TrackedObject(
            camera_id="cam-01", track_id="t-1", class_name="person", confidence=0.6, bounding_box=_box()
        ),
        SafetyEvent(camera_id="cam-01", class_name="no-helmet", confidence=0.8),
        QualityEvent(camera_id="cam-01", class_name="scratch", confidence=0.7),
        PerceptionEvent(camera_id="cam-01", class_name="forklift", confidence=0.66),
        RiskAssessment(risk_score=0.2),
        Incident(title="Zone intrusion"),
        Alert(message="Zone intrusion detected"),
    ]
    for model in models:
        assert model.id is not None
        assert model.timestamp is not None
        assert isinstance(model.metadata, dict)
