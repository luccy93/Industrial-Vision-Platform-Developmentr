"""Spatial schemas — zones, membership, transitions, relationships.

Polygons use normalized image coordinates (x, y ∈ [0, 1]) so zones are
resolution-independent. Membership tests use the bounding-box bottom-center
point as a ground-contact approximation — an image-space heuristic, NOT a
physical ground position.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from backend.app.domain.common import utcnow
from backend.app.safety.schemas import SafetySeverity


class ZoneType(str, Enum):
    RESTRICTED = "RESTRICTED"
    DANGER = "DANGER"
    WARNING = "WARNING"
    SAFE = "SAFE"
    CUSTOM = "CUSTOM"


class ZonePoint(BaseModel):
    x: float = Field(ge=0.0, le=1.0)
    y: float = Field(ge=0.0, le=1.0)


class ZoneTransition(str, Enum):
    ENTRY = "ENTRY"
    EXIT = "EXIT"
    STATIONARY_INSIDE = "STATIONARY_INSIDE"
    STATIONARY_OUTSIDE = "STATIONARY_OUTSIDE"


class ProximityStrategy(str, Enum):
    CENTER_DISTANCE = "CENTER_DISTANCE"
    IOU = "IOU"
    HYBRID = "HYBRID"


class ProximityRelationship(str, Enum):
    PERSON_VEHICLE = "PERSON_VEHICLE"
    PERSON_PERSON = "PERSON_PERSON"
    VEHICLE_VEHICLE = "VEHICLE_VEHICLE"


class SafetyZone(BaseModel):
    """Configured camera zone (mirrors the PostgreSQL `zones` table)."""

    zone_id: str = Field(min_length=1, max_length=128)
    camera_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    zone_type: ZoneType = ZoneType.RESTRICTED
    polygon: list[ZonePoint] = Field(min_length=3)
    enabled: bool = True
    severity: SafetySeverity = SafetySeverity.HIGH
    dwell_threshold_seconds: float | None = Field(default=None, ge=0.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator("polygon")
    @classmethod
    def _finite_points(cls, polygon: list[ZonePoint]) -> list[ZonePoint]:
        import math

        for point in polygon:
            if not (math.isfinite(point.x) and math.isfinite(point.y)):
                raise ValueError("polygon points must be finite numbers")
        return polygon

    @model_validator(mode="after")
    def _non_degenerate(self) -> SafetyZone:
        xs = {round(p.x, 6) for p in self.polygon}
        ys = {round(p.y, 6) for p in self.polygon}
        if len(xs) < 2 or len(ys) < 2:
            raise ValueError("polygon must span area in both axes")
        return self


class ZoneMembership(BaseModel):
    """Point-in-time membership of one track in one zone."""

    camera_id: str
    zone_id: str
    track_id: int
    inside: bool
    entered_at: datetime | None = None
    dwell_seconds: float = 0.0


class ZoneTrackState(BaseModel):
    """Runtime per (camera, zone, track) state (memory only)."""

    camera_id: str
    zone_id: str
    track_id: int
    inside: bool = False
    entered_at: datetime | None = None
    last_seen: datetime | None = None
    dwell_notified: bool = False
    previous_x: float | None = None
    previous_y: float | None = None
    movement_x: float = 0.0
    movement_y: float = 0.0
