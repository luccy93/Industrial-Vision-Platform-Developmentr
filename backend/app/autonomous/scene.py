"""Scene classification boundary — the engine depends on this, never on a backend.

V08 ships a scripted fixture adapter (tests/dev) plus this boundary; the
deterministic heuristic baseline lands with the runtime in Commit 02. Future
learned scene classifiers implement :class:`SceneClassifier` without any
engine change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from backend.app.autonomous.schemas import ModelState, SceneHypothesis, SceneType


class SceneClassifier(ABC):
    """Interface every scene-classification backend implements."""

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
            raise RuntimeError(f"scene classifier failed to load: {exc}") from exc
        self._state = ModelState.READY

    def unload(self) -> None:
        self._state = ModelState.NOT_LOADED

    @abstractmethod
    def _load(self) -> None:
        """Backend-specific initialization."""

    @abstractmethod
    def classify(
        self,
        *,
        camera_id: str,
        object_classes: list[str],
        object_count: int,
        lane_count: int,
        metadata: dict[str, Any] | None = None,
    ) -> SceneHypothesis:
        """Classify a scene from lightweight summary features."""


class FixtureSceneClassifier(SceneClassifier):
    """Scripted scene classifier — returns an explicit hypothesis, never a guess."""

    def __init__(
        self,
        scene_type: SceneType = SceneType.UNKNOWN,
        confidence: float = 1.0,
        reason: str = "fixture hypothesis",
        name: str = "fixture-scene",
    ) -> None:
        super().__init__(name=name, version="0.0.0-fixture")
        self._hypothesis = SceneHypothesis(scene_type=scene_type, confidence=confidence, reason=reason)

    def _load(self) -> None:
        return None

    def classify(
        self,
        *,
        camera_id: str,
        object_classes: list[str],
        object_count: int,
        lane_count: int,
        metadata: dict[str, Any] | None = None,
    ) -> SceneHypothesis:
        return SceneHypothesis(
            scene_type=self._hypothesis.scene_type,
            confidence=self._hypothesis.confidence,
            reason=self._hypothesis.reason,
        )
