"""Safety rule abstraction — independent, testable, stateless-by-default rules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from backend.app.safety.schemas import SafetyEventType, SafetySeverity
from backend.app.tracking.schemas import TrackedObject


@dataclass
class SceneState:
    """One frame's tracking snapshot for a single camera."""

    camera_id: str
    timestamp: datetime
    tracks: list[TrackedObject] = field(default_factory=list)

    def persons(self) -> list[TrackedObject]:
        return [t for t in self.tracks if t.class_name.lower() == "person"]

    def vehicles(self) -> list[TrackedObject]:
        return [t for t in self.tracks if t.class_name.lower() in _VEHICLE_CLASSES]


_VEHICLE_CLASSES = frozenset({"car", "truck", "bus", "motorcycle", "bicycle", "forklift", "vehicle", "van"})


@dataclass
class EventDraft:
    """A rule's proposal; the engine assigns identity and lifecycle."""

    dedupe_key: str
    event_type: SafetyEventType
    severity: SafetySeverity
    track_ids: list[int]
    confidence: float
    message: str
    evidence: dict[str, Any] = field(default_factory=dict)


class SafetyRule(ABC):
    """Interface every safety rule implements."""

    def __init__(self, name: str, enabled: bool = True) -> None:
        self.name = name
        self.enabled = enabled

    @property
    @abstractmethod
    def event_type(self) -> SafetyEventType: ...

    @abstractmethod
    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        """Return zero or more event proposals for this scene."""
