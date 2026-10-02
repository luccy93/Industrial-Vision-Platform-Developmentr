"""Inspection model boundary — the engine depends on this, never on a backend.

V07 ships the scripted fixture adapter (tests/dev) plus this boundary. Future
specialized models — a trained YOLO defect detector, a segmentation model, an
anomaly detector — implement :class:`InspectionModel` without any engine
change. No generic object detector is ever treated as a defect model here.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from uuid import UUID

import numpy as np


class InspectionModelState(str, Enum):
    NOT_LOADED = "NOT_LOADED"
    LOADING = "LOADING"
    READY = "READY"
    NOT_READY = "NOT_READY"


class InspectionErrorCode(str, Enum):
    """Stable, API-safe reasons an inspection could not complete."""

    INSPECTION_MODEL_NOT_CONFIGURED = "INSPECTION_MODEL_NOT_CONFIGURED"
    INSPECTION_MODEL_NOT_READY = "INSPECTION_MODEL_NOT_READY"
    INSPECTION_MODEL_ERROR = "INSPECTION_MODEL_ERROR"
    INSPECTION_CONFIG_INVALID = "INSPECTION_CONFIG_INVALID"
    FRAME_INVALID = "FRAME_INVALID"


class InspectionModelError(Exception):
    """Inspection failure carrying a stable, API-safe error code."""

    def __init__(self, code: InspectionErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class RawDefect:
    """One defect candidate from a model, in ROI pixel coordinates.

    ``confidence`` is the model's strength score for this candidate — not a
    calibrated probability unless the producing model documents calibration.
    """

    code: str
    box: tuple[float, float, float, float]
    confidence: float
    class_name: str | None = None
    metadata: dict = field(default_factory=dict)


class InspectionModel(ABC):
    """Interface every inspection backend implements."""

    def __init__(self, name: str, version: str = "0.0.0") -> None:
        self.name = name
        self.version = version
        self._state = InspectionModelState.NOT_LOADED

    @property
    def state(self) -> InspectionModelState:
        return self._state

    @property
    def is_ready(self) -> bool:
        return self._state is InspectionModelState.READY

    def load(self) -> None:
        """Load/initialize the model. Raises :class:`InspectionModelError`."""
        if self._state is InspectionModelState.READY:
            return
        self._state = InspectionModelState.LOADING
        try:
            self._load()
        except InspectionModelError:
            self._state = InspectionModelState.NOT_READY
            raise
        except Exception as exc:
            self._state = InspectionModelState.NOT_READY
            raise InspectionModelError(
                InspectionErrorCode.INSPECTION_MODEL_ERROR, f"{type(exc).__name__}: {exc}"
            ) from exc
        self._state = InspectionModelState.READY

    def unload(self) -> None:
        self._state = InspectionModelState.NOT_LOADED

    @abstractmethod
    def _load(self) -> None:
        """Backend-specific initialization."""

    @abstractmethod
    def predict(
        self,
        roi: np.ndarray,
        *,
        camera_id: str,
        frame_id: UUID | None,
        region_id: str,
    ) -> list[RawDefect]:
        """Inspect one ROI crop. Raises :class:`InspectionModelError`."""

    def supports(self, defect_codes: frozenset[str]) -> frozenset[str]:
        """Defect codes this model can produce (empty = unconstrained)."""
        return frozenset()
