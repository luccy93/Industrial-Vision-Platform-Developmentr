"""Inference schema tests — boxes, detections, serializable results."""

from __future__ import annotations

from uuid import uuid4

import pytest
from pydantic import ValidationError

from backend.app.inference.schemas import (
    InferenceBoundingBox,
    InferenceDetection,
    InferenceResult,
)


def _detection(**overrides) -> InferenceDetection:  # type: ignore[no-untyped-def]
    params = {
        "camera_id": "cam-01",
        "frame_id": uuid4(),
        "class_id": 0,
        "class_name": "person",
        "confidence": 0.94,
        "bounding_box": InferenceBoundingBox(x1=312, y1=180, x2=612, y2=910),
        "model_name": "yolo",
        "inference_time_ms": 18.4,
    }
    params.update(overrides)
    return InferenceDetection(**params)  # type: ignore[arg-type]


def test_box_geometry() -> None:
    box = InferenceBoundingBox(x1=10, y1=20, x2=60, y2=120)
    assert box.width == 50 and box.height == 100


def test_box_rejects_inverted_corners() -> None:
    with pytest.raises(ValidationError):
        InferenceBoundingBox(x1=60, y1=20, x2=10, y2=120)
    with pytest.raises(ValidationError):
        InferenceBoundingBox(x1=10, y1=120, x2=60, y2=20)


def test_detection_contract() -> None:
    detection = _detection()
    assert detection.id is not None
    assert detection.timestamp is not None
    assert detection.metadata == {}
    with pytest.raises(ValidationError):
        _detection(confidence=1.5)


def test_result_websocket_serialization() -> None:
    result = InferenceResult(
        frame_id=uuid4(),
        camera_id="cam-001",
        detections=[_detection(camera_id="cam-001")],
        inference_time_ms=18.4,
        model_name="yolo",
        device="cpu",
    )
    payload = result.to_websocket()
    assert payload["type"] == "detection"
    assert payload["camera_id"] == "cam-001"
    assert payload["model_name"] == "yolo"
    assert payload["detections"][0]["bounding_box"] == {
        "x1": 312,
        "y1": 180,
        "x2": 612,
        "y2": 910,
    }
    assert "track_id" not in str(payload)  # V03 has no tracking


def test_empty_result_serializes() -> None:
    result = InferenceResult(
        frame_id=uuid4(),
        camera_id="c",
        detections=[],
        inference_time_ms=1.0,
        model_name="yolo",
        device="cpu",
    )
    assert result.to_websocket()["detections"] == []
