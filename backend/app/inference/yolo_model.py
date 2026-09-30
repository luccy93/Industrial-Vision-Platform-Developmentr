"""Ultralytics YOLO adapter — production inference backend.

``ultralytics`` is imported lazily inside ``load()`` so the application and
test suite work without the package. Weights are never auto-downloaded: a
missing ``MODEL_PATH`` raises ``ModelNotFoundError`` with setup instructions.
Coordinates come back in original-frame pixels (Ultralytics rescales its
internal letterboxed predictions automatically).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

import numpy as np

from backend.app.inference.base import (
    InferenceModel,
    ModelNotFoundError,
    ModelState,
    ModelUnavailableError,
    RawDetections,
    validate_image,
)

logger = logging.getLogger("industrial-vision.inference")


def resolve_device(requested: str) -> str:
    """Map ``auto|cpu|cuda`` to a concrete device without crashing on CPU hosts."""
    normalized = requested.lower()
    if normalized == "cpu":
        return "cpu"
    if normalized == "cuda":
        try:
            import torch

            if torch.cuda.is_available():
                return "cuda"
        except ImportError:
            pass
        raise ModelUnavailableError("MODEL_DEVICE=cuda requested but CUDA is unavailable")
    # auto
    try:
        import torch

        return "cuda" if torch.cuda.is_available() else "cpu"
    except ImportError:
        return "cpu"


class YOLOModel(InferenceModel):
    """YOLO adapter honoring conf/iou/imgsz/max-det + class allowlist."""

    def __init__(
        self,
        name: str = "yolo",
        model_path: str = "models/yolo11n.pt",
        device: str = "auto",
        confidence: float = 0.25,
        iou: float = 0.45,
        image_size: int = 640,
        max_detections: int = 300,
        allowed_classes: frozenset[str] | None = None,
    ) -> None:
        super().__init__(name)
        self.model_path = model_path
        self.requested_device = device
        self.confidence = confidence
        self.iou = iou
        self.image_size = image_size
        self.max_detections = max_detections
        self.allowed_classes = allowed_classes or frozenset()
        self._model: Any | None = None
        self._device = "cpu"
        self._names: dict[int, str] = {}
        self._lock = threading.Lock()

    @property
    def device(self) -> str:
        return self._device

    @property
    def class_names(self) -> dict[int, str]:
        return dict(self._names)

    def load(self) -> None:
        if self.is_ready:
            return
        self._state = ModelState.LOADING
        started = time.perf_counter()
        try:
            import ultralytics  # noqa: F401  (lazy: package is optional)
        except ImportError as exc:
            self._state = ModelState.NOT_READY
            raise ModelUnavailableError(
                "ultralytics is not installed; install backend/requirements.txt or use MockModel for tests"
            ) from exc
        if not os.path.exists(self.model_path):
            self._state = ModelState.NOT_READY
            raise ModelNotFoundError(
                f"YOLO weights not found at '{self.model_path}'. "
                "Run: python -m backend.app.inference.smoke_test --download "
                "(see docs/INFERENCE.md). Weights are never fetched silently."
            )
        from ultralytics import YOLO

        self._device = resolve_device(self.requested_device)
        try:
            with self._lock:
                self._model = YOLO(self.model_path)
                names = self._model.names or {}
                self._names = {int(k): str(v) for k, v in names.items()}
        except ModelUnavailableError:
            raise
        except Exception as exc:
            self._state = ModelState.NOT_READY
            raise ModelUnavailableError(f"failed to load '{self.model_path}': {exc}") from exc
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        logger.info(
            "loaded YOLO model=%s path=%s device=%s classes=%d in %.0fms",
            self.name,
            self.model_path,
            self._device,
            len(self._names),
            elapsed_ms,
        )
        self._mark_loaded(elapsed_ms)

    def unload(self) -> None:
        with self._lock:
            self._model = None
            self._names = {}
        self._state = ModelState.NOT_LOADED

    def predict_raw(self, image: np.ndarray) -> RawDetections:
        validate_image(image)
        if not self.is_ready or self._model is None:
            raise ModelUnavailableError(f"model '{self.name}' is not ready")
        started = time.perf_counter()
        with self._lock:
            results = self._model.predict(
                image,
                conf=self.confidence,
                iou=self.iou,
                imgsz=self.image_size,
                max_det=self.max_detections,
                verbose=False,
            )
        latency_ms = (time.perf_counter() - started) * 1000.0
        boxes: list[tuple[float, float, float, float]] = []
        class_ids: list[int] = []
        class_names: list[str] = []
        confidences: list[float] = []
        result = results[0]
        if result.boxes is not None and len(result.boxes) > 0:
            xyxy = result.boxes.xyxy.cpu().tolist()
            cls = result.boxes.cls.cpu().tolist()
            conf = result.boxes.conf.cpu().tolist()
            for coords, class_id, confidence in zip(xyxy, cls, conf):
                name = self._names.get(int(class_id), str(int(class_id)))
                if self.allowed_classes and name.lower() not in self.allowed_classes:
                    continue
                x1, y1, x2, y2 = (float(v) for v in coords)
                boxes.append((x1, y1, x2, y2))
                class_ids.append(int(class_id))
                class_names.append(name)
                confidences.append(float(confidence))
        return RawDetections(
            boxes=boxes,
            class_ids=class_ids,
            class_names=class_names,
            confidences=confidences,
            inference_time_ms=latency_ms,
        )
