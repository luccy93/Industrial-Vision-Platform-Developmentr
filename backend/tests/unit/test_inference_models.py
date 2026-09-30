"""Model abstraction tests — mock inference, filtering, devices, lifecycle."""

from __future__ import annotations

from uuid import uuid4

import numpy as np
import pytest

from backend.app.core.config import AppEnv, Settings
from backend.app.inference.base import (
    InvalidFrameError,
    ModelNotFoundError,
    ModelUnavailableError,
    validate_image,
)
from backend.app.inference.manager import ModelManager
from backend.app.inference.mock_model import MockModel
from backend.app.inference.yolo_model import YOLOModel, resolve_device


def _image(width: int = 320, height: int = 240) -> np.ndarray:
    return np.zeros((height, width, 3), dtype=np.uint8)


def test_mock_predict_returns_detections() -> None:
    model = MockModel()
    model.load()
    assert model.is_ready
    detections, latency = model.predict(_image(), camera_id="c", frame_id=uuid4())
    assert len(detections) == 2
    assert detections[0].class_name == "person"
    assert latency >= 0


def test_confidence_filtering() -> None:
    model = MockModel()
    model.load()
    detections, _ = model.predict(_image(), camera_id="c", frame_id=uuid4(), confidence_threshold=0.95)
    assert detections == []


def test_class_allowlist_filtering() -> None:
    model = MockModel()
    model.load()
    detections, _ = model.predict(
        _image(), camera_id="c", frame_id=uuid4(), allowed_classes=frozenset({"forklift"})
    )
    assert [d.class_name for d in detections] == ["forklift"]


def test_boxes_clamped_to_frame() -> None:
    model = MockModel(detections_per_frame=3)
    model.load()
    detections, _ = model.predict(_image(320, 240), camera_id="c", frame_id=uuid4())
    for detection in detections:
        box = detection.bounding_box
        assert 0 <= box.x1 <= box.x2 <= 320
        assert 0 <= box.y1 <= box.y2 <= 240


def test_predict_requires_ready_model() -> None:
    with pytest.raises(ModelUnavailableError):
        MockModel().predict(_image(), camera_id="c", frame_id=uuid4())


def test_invalid_frames_rejected() -> None:
    with pytest.raises(InvalidFrameError):
        validate_image(np.zeros((0, 0, 3), dtype=np.uint8))
    with pytest.raises(InvalidFrameError):
        validate_image(np.zeros((10, 10, 3), dtype=np.float32))
    with pytest.raises(InvalidFrameError):
        validate_image("not-an-array")  # type: ignore[arg-type]


def test_cpu_device_selection_and_cuda_fallback() -> None:
    assert resolve_device("cpu") == "cpu"
    # CPU-only host: auto falls back without crashing.
    assert resolve_device("auto") == "cpu"


def test_yolo_missing_weights_structured_error(tmp_path) -> None:  # type: ignore[no-untyped-def]
    model = YOLOModel(model_path=str(tmp_path / "missing.pt"))
    with pytest.raises(ModelNotFoundError):
        model.load()
    assert not model.is_ready


def test_manager_loads_once_and_tracks_metrics() -> None:
    settings = Settings(app_env=AppEnv.testing, _env_file=None)  # type: ignore[call-arg]
    manager = ModelManager.from_settings(settings)
    first = manager.infer(_image(), camera_id="c", frame_id=uuid4())
    second = manager.infer(_image(), camera_id="c", frame_id=uuid4())
    assert manager.model.load_calls == 1  # type: ignore[attr-defined]
    assert first.model_name == second.model_name
    status = manager.status()
    assert status["loaded"] is True
    assert status["inference_count"] == 2
    assert status["frames_with_detections"] == 2
    assert status["detections_per_frame"] == 2.0
    assert status["average_latency_ms"] >= 0


def test_manager_status_before_load() -> None:
    settings = Settings(app_env=AppEnv.testing, _env_file=None)  # type: ignore[call-arg]
    manager = ModelManager.from_settings(settings)
    status = manager.status()
    assert status["loaded"] is False
    assert status["state"] == "NOT_READY"
    assert status["inference_count"] == 0
