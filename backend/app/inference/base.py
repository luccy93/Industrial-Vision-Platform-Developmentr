"""Model abstraction — the pipeline depends on this, never on Ultralytics."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID

import numpy as np

from backend.app.inference.schemas import InferenceBoundingBox, InferenceDetection


class ModelState(str, Enum):
    NOT_LOADED = "NOT_LOADED"
    LOADING = "LOADING"
    READY = "READY"
    NOT_READY = "NOT_READY"


@dataclass
class RawDetections:
    """Adapter output before validation: parallel arrays in frame pixels."""

    boxes: list[tuple[float, float, float, float]] = field(default_factory=list)
    class_ids: list[int] = field(default_factory=list)
    class_names: list[str] = field(default_factory=list)
    confidences: list[float] = field(default_factory=list)
    inference_time_ms: float = 0.0


class ModelError(Exception):
    """Base inference error — mapped to structured API errors, never leaked raw."""


class ModelNotFoundError(ModelError):
    """Weights file missing (not downloaded / bad MODEL_PATH)."""


class ModelUnavailableError(ModelError):
    """ultralytics/torch missing, CUDA requested but absent, load failure."""


class InvalidFrameError(ModelError):
    """Frame payload unsuitable for inference (empty, wrong dtype/shape)."""


def validate_image(image: np.ndarray) -> tuple[int, int]:
    """Return (width, height) or raise ``InvalidFrameError``."""
    if not isinstance(image, np.ndarray):
        raise InvalidFrameError("frame image must be a numpy array")
    if image.ndim not in (2, 3) or image.size == 0:
        raise InvalidFrameError(f"unsupported frame shape {image.shape}")
    if image.dtype != np.uint8:
        raise InvalidFrameError(f"unsupported frame dtype {image.dtype}")
    height, width = image.shape[0], image.shape[1]
    if width < 1 or height < 1:
        raise InvalidFrameError("frame dimensions must be positive")
    return width, height


class InferenceModel(ABC):
    """Interface every model backend implements (YOLO now, others in V04+)."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._state = ModelState.NOT_LOADED
        self._load_time_ms = 0.0

    @property
    def state(self) -> ModelState:
        return self._state

    @property
    def is_ready(self) -> bool:
        return self._state == ModelState.READY

    @property
    def load_time_ms(self) -> float:
        return self._load_time_ms

    @property
    @abstractmethod
    def device(self) -> str: ...

    @property
    @abstractmethod
    def class_names(self) -> dict[int, str]: ...

    @abstractmethod
    def load(self) -> None:
        """Load weights once. Raises ``ModelError`` with a clear reason."""

    @abstractmethod
    def unload(self) -> None: ...

    @abstractmethod
    def predict_raw(self, image: np.ndarray) -> RawDetections:
        """Run one forward pass. Callers use ``predict()`` for validation."""

    def predict(
        self,
        image: np.ndarray,
        *,
        camera_id: str,
        frame_id: UUID,
        confidence_threshold: float = 0.0,
        allowed_classes: frozenset[str] | None = None,
    ) -> tuple[list[InferenceDetection], float]:
        """Validated detections + pure inference latency (no load time)."""
        if not self.is_ready:
            raise ModelUnavailableError(f"model '{self.name}' is not ready")
        width, height = validate_image(image)
        started = time.perf_counter()
        raw = self.predict_raw(image)
        latency_ms = (time.perf_counter() - started) * 1000.0
        detections: list[InferenceDetection] = []
        for box, class_id, class_name, confidence in zip(
            raw.boxes, raw.class_ids, raw.class_names, raw.confidences
        ):
            if confidence < confidence_threshold:
                continue
            if allowed_classes and class_name.lower() not in allowed_classes:
                continue
            x1, y1, x2, y2 = (max(0.0, float(v)) for v in box)
            x1 = min(x1, float(width))
            y1 = min(y1, float(height))
            x2 = min(max(x2, x1), float(width))
            y2 = min(max(y2, y1), float(height))
            detections.append(
                InferenceDetection(
                    camera_id=camera_id,
                    frame_id=frame_id,
                    class_id=int(class_id),
                    class_name=str(class_name),
                    confidence=float(confidence),
                    bounding_box=InferenceBoundingBox(x1=x1, y1=y1, x2=x2, y2=y2),
                    model_name=self.name,
                    inference_time_ms=latency_ms,
                )
            )
        return detections, latency_ms

    def _mark_loaded(self, elapsed_ms: float) -> None:
        self._load_time_ms = elapsed_ms
        self._state = ModelState.READY
