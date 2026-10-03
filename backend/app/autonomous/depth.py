"""Depth estimation boundary — the engine depends on this, never on a backend.

V08 never requires a depth model, stereo camera, LiDAR, or external sensor.
Without a configured estimator, relative depth is explicitly unavailable
(``depth=None``, ``source=NOT_CONFIGURED``) and the rest of perception
continues. The fixture adapter returns explicit synthetic *relative* values
for tests — never meters, never a metric claim.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

import numpy as np

from backend.app.autonomous.schemas import DepthReading, DepthSource, ModelState


@dataclass
class DepthResult:
    """Per-object relative-depth readings keyed by object ID."""

    readings: dict[str, DepthReading] = field(default_factory=dict)
    source: DepthSource = DepthSource.NOT_CONFIGURED
    metadata: dict[str, Any] = field(default_factory=dict)


class DepthEstimator(ABC):
    """Interface every depth-estimation backend implements."""

    def __init__(self, name: str, version: str = "0.0.0") -> None:
        self.name = name
        self.version = version
        self._state = ModelState.NOT_LOADED

    @property
    def state(self) -> ModelState:
        return self._state

    @property
    def is_ready(self) -> bool:
        return self._state is ModelState.READY

    def load(self) -> None:
        if self._state is ModelState.READY:
            return
        self._state = ModelState.LOADING
        try:
            self._load()
        except Exception as exc:
            self._state = ModelState.NOT_READY
            raise RuntimeError(f"depth estimator failed to load: {exc}") from exc
        self._state = ModelState.READY

    def unload(self) -> None:
        self._state = ModelState.NOT_LOADED

    @abstractmethod
    def _load(self) -> None:
        """Backend-specific initialization."""

    @abstractmethod
    def estimate(
        self,
        image: np.ndarray,
        object_ids: list[str],
        *,
        camera_id: str,
        frame_id: UUID | None,
    ) -> DepthResult:
        """Estimate relative depth per object. Absent objects stay ``None``."""


class FixtureDepthEstimator(DepthEstimator):
    """Returns scripted relative-depth values for named objects.

    Unlisted objects get an explicit ``None`` reading (unavailable), never a
    fabricated value. Values are unitless relative orderings in (0, 1].
    """

    def __init__(
        self,
        depths: dict[str, float] | None = None,
        name: str = "fixture-depth",
    ) -> None:
        super().__init__(name=name, version="0.0.0-fixture")
        self._depths = dict(depths or {})

    def _load(self) -> None:
        return None

    def estimate(
        self,
        image: np.ndarray,
        object_ids: list[str],
        *,
        camera_id: str,
        frame_id: UUID | None,
    ) -> DepthResult:
        if not isinstance(image, np.ndarray) or image.ndim not in (2, 3) or image.size == 0:
            raise ValueError("fixture received an invalid frame")
        readings: dict[str, DepthReading] = {}
        for object_id in object_ids:
            value = self._depths.get(object_id)
            if value is None:
                readings[object_id] = DepthReading(source=DepthSource.FIXTURE_SYNTHETIC)
            else:
                readings[object_id] = DepthReading(
                    depth=value,
                    unit="relative",
                    confidence=1.0,
                    source=DepthSource.FIXTURE_SYNTHETIC,
                )
        return DepthResult(readings=readings, source=DepthSource.FIXTURE_SYNTHETIC)
