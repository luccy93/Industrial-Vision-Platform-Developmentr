"""Tracker abstraction — the pipeline depends on this, not on ByteTrack."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from uuid import UUID

from backend.app.inference.schemas import InferenceDetection
from backend.app.tracking.schemas import TrackedObject


class Tracker(ABC):
    """Interface every tracking backend implements."""

    def __init__(self, name: str, camera_id: str) -> None:
        self.name = name
        self.camera_id = camera_id

    @abstractmethod
    def update(
        self,
        detections: list[InferenceDetection],
        frame_id: UUID,
        timestamp: datetime,
    ) -> list[TrackedObject]:
        """Associate detections to tracks; return live (non-REMOVED) tracks."""

    @abstractmethod
    def reset(self) -> None:
        """Drop all state (stream restart); track IDs restart at 1."""

    @abstractmethod
    def active_tracks(self) -> list[TrackedObject]: ...

    @property
    @abstractmethod
    def stats(self) -> dict:
        """Runtime counters for monitoring (active/confirmed/lost/...)."""
        ...
