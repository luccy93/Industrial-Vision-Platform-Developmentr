"""Real-model integration — runs ONLY when weights exist locally.

Skipped in CI/fresh clones (no weights, no internet). Validates the genuine
YOLO adapter end to end on CPU; never fails the standard suite.
"""

from __future__ import annotations

import os
from uuid import uuid4

import numpy as np
import pytest

from backend.app.inference.yolo_model import YOLOModel

WEIGHTS = "models/yolo11n.pt"

requires_weights = pytest.mark.skipif(
    not os.path.exists(WEIGHTS), reason="YOLO weights absent (see docs/INFERENCE.md)"
)


@requires_weights
def test_real_yolo_loads_and_infers_on_cpu() -> None:
    model = YOLOModel(name="yolo-test", model_path=WEIGHTS, device="cpu")
    model.load()
    try:
        assert model.is_ready
        assert model.device == "cpu"
        assert len(model.class_names) == 80
        image = np.zeros((480, 640, 3), dtype=np.uint8)
        detections, latency_ms = model.predict(image, camera_id="c", frame_id=uuid4())
        assert latency_ms >= 0
        assert isinstance(detections, list)
    finally:
        model.unload()
    assert not model.is_ready
