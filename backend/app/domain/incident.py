"""Incident + alert contracts."""

from __future__ import annotations

from enum import Enum

from pydantic import Field

from backend.app.domain.common import EntityBase


class IncidentStatus(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class AlertSeverity(str, Enum):
    info = "info"
    warning = "warning"
    critical = "critical"


class Incident(EntityBase):
    camera_id: str | None = Field(default=None, max_length=128)
    class_name: str | None = Field(default=None, max_length=128)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    title: str = Field(min_length=1, max_length=256)
    status: IncidentStatus = IncidentStatus.open
    description: str | None = Field(default=None, max_length=2048)


class Alert(EntityBase):
    camera_id: str | None = Field(default=None, max_length=128)
    class_name: str | None = Field(default=None, max_length=128)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    incident_id: str | None = Field(default=None, max_length=128)
    severity: AlertSeverity = AlertSeverity.info
    channel: str = Field(default="api", max_length=64)
    message: str = Field(min_length=1, max_length=2048)
    delivered: bool = False
