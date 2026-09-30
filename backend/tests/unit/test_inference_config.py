"""Inference configuration tests — model settings, device, allowlist."""

from __future__ import annotations

import pytest

from backend.app.core.config import Settings


def test_model_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.model_name == "yolo11n"
    assert settings.model_path == "models/yolo11n.pt"
    assert settings.model_device == "cpu"
    assert settings.model_iou_threshold == 0.45
    assert settings.model_image_size == 640
    assert settings.model_max_detections == 300
    assert settings.model_classes == ""


def test_model_device_validation() -> None:
    for device in ("auto", "cpu", "cuda", "AUTO"):
        settings = Settings(model_device=device, _env_file=None)  # type: ignore[call-arg]
        assert settings.model_device in ("auto", "cpu", "cuda")
    with pytest.raises(ValueError):
        Settings(model_device="tpu", _env_file=None)  # type: ignore[call-arg]


def test_class_allowlist_parsing() -> None:
    settings = Settings(model_classes="person, car ,,TRUCK", _env_file=None)  # type: ignore[call-arg]
    assert settings.model_class_allowlist == frozenset({"person", "car", "truck"})
    empty = Settings(_env_file=None)  # type: ignore[call-arg]
    assert empty.model_class_allowlist == frozenset()


def test_threshold_bounds() -> None:
    with pytest.raises(ValueError):
        Settings(model_iou_threshold=2.0, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(model_image_size=100, _env_file=None)  # type: ignore[call-arg]
