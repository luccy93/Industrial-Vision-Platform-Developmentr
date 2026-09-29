"""Safety / quality / perception event contracts."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from backend.app.domain.common import EntityBase


class EventSeverity(str, Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


class SafetyEvent(EntityBase):
    camera_id: str = Field(min_length=1, max_length=128)
    class_name: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: EventSeverity = EventSeverity.info
    zone: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=1024)


class QualityEvent(EntityBase):
    camera_id: str = Field(min_length=1, max_length=128)
    class_name: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    severity: EventSeverity = EventSeverity.info
    station: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=1024)


class PerceptionEvent(EntityBase):
    camera_id: str = Field(min_length=1, max_length=128)
    class_name: str = Field(min_length=1, max_length=128)
    confidence: float = Field(ge=0.0, le=1.0)
    scene: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=1024)
