"""Model manager — single reusable instance, load-once lifecycle, status."""

from __future__ import annotations

import logging
import threading
from uuid import UUID

import numpy as np

from backend.app.core.config import Settings
from backend.app.inference.base import InferenceModel, ModelError, ModelState
from backend.app.inference.mock_model import MockModel
from backend.app.inference.schemas import InferenceResult
from backend.app.inference.yolo_model import YOLOModel

logger = logging.getLogger("industrial-vision.inference")


class ModelManager:
    """Owns one shared model: loaded once, reused for every frame."""

    def __init__(self, model: InferenceModel, settings: Settings) -> None:
        self._model = model
        self._settings = settings
        self._lock = threading.Lock()
        self._inference_count = 0
        self._total_latency_ms = 0.0
        self._last_latency_ms = 0.0
        self._frames_with_detections = 0
        self._total_detections = 0

    @classmethod
    def from_settings(cls, settings: Settings, use_mock: bool = False) -> ModelManager:
        if use_mock or settings.app_env.value == "testing":
            return cls(MockModel(name=settings.model_name), settings)
        return cls(
            YOLOModel(
                name=settings.model_name,
                model_path=settings.model_path,
                device=settings.model_device,
                confidence=settings.model_confidence_threshold,
                iou=settings.model_iou_threshold,
                image_size=settings.model_image_size,
                max_detections=settings.model_max_detections,
                allowed_classes=settings.model_class_allowlist or None,
            ),
            settings,
        )

    @property
    def model(self) -> InferenceModel:
        return self._model

    def ensure_loaded(self) -> None:
        """Load once; concurrent callers share the single load."""
        with self._lock:
            if self._model.is_ready:
                return
            self._model.load()

    def infer(
        self,
        image: np.ndarray,
        *,
        camera_id: str,
        frame_id: UUID,
    ) -> InferenceResult:
        """Run inference; failures raise ``ModelError`` (never crash streams)."""
        self.ensure_loaded()
        detections, latency_ms = self._model.predict(
            image,
            camera_id=camera_id,
            frame_id=frame_id,
            confidence_threshold=self._settings.model_confidence_threshold,
            allowed_classes=self._settings.model_class_allowlist or None,
        )
        with self._lock:
            self._inference_count += 1
            self._total_latency_ms += latency_ms
            self._last_latency_ms = latency_ms
            self._total_detections += len(detections)
            if detections:
                self._frames_with_detections += 1
            average = self._total_latency_ms / self._inference_count
            fps = 1000.0 / average if average > 0 else 0.0
        from backend.app.domain.common import utcnow

        return InferenceResult(
            frame_id=frame_id,
            camera_id=camera_id,
            timestamp=utcnow(),
            detections=detections,
            inference_time_ms=latency_ms,
            processing_fps=fps,
            model_name=self._model.name,
            device=self._model.device,
        )

    def status(self) -> dict:
        with self._lock:
            count = self._inference_count
            average = self._total_latency_ms / count if count else 0.0
            fps = 1000.0 / average if average > 0 else 0.0
        classes: dict[int, str] = {}
        if self._model.is_ready:
            try:
                classes = self._model.class_names
            except Exception:
                logger.debug("class_names unavailable", exc_info=True)
        ready = self._model.is_ready
        return {
            "loaded": ready,
            "state": self._model.state.value if ready else ModelState.NOT_READY.value,
            "model_name": self._model.name,
            "model_path": getattr(self._model, "model_path", "mock"),
            "device": self._model.device,
            "classes": classes,
            "class_count": len(classes),
            "confidence_threshold": self._settings.model_confidence_threshold,
            "iou_threshold": self._settings.model_iou_threshold,
            "inference_count": count,
            "inference_fps": round(fps, 2),
            "average_latency_ms": round(average, 2),
            "last_inference_ms": round(self._last_latency_ms, 2),
            "frames_with_detections": self._frames_with_detections,
            "detections_per_frame": round(self._total_detections / count, 2) if count else 0.0,
            "model_load_time_ms": round(self._model.load_time_ms, 2),
        }


__all__ = ["ModelError", "ModelManager"]
