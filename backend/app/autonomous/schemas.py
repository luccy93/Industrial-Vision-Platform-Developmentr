"""Autonomous perception domain model — relative scene understanding.

Honesty semantics: every quantity here is either image-space (normalized
[0, 1] coordinates, pixels/second) or an explicitly labeled *relative
estimate*. Metric distance, physical coordinates, and certified collision
prediction require calibration, sensors, models, and validation that V08
does not claim. Unavailable values are ``None`` with an explicit source
(``NOT_CONFIGURED``/``UNKNOWN``) — never zero, never fabricated.

Confidence and risk scores are uncalibrated heuristic strengths in [0, 1],
never probabilities.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator

from backend.app.domain.common import utcnow


class SceneType(str, Enum):
    ROAD = "ROAD"
    PARKING = "PARKING"
    WAREHOUSE = "WAREHOUSE"
    INDUSTRIAL_YARD = "INDUSTRIAL_YARD"
    INDOOR_MOBILE_ROBOT = "INDOOR_MOBILE_ROBOT"
    UNKNOWN = "UNKNOWN"


class PerceivedObjectState(str, Enum):
    MOVING = "MOVING"
    STATIONARY = "STATIONARY"
    APPROACHING = "APPROACHING"
    RECEDING = "RECEDING"
    CROSSING = "CROSSING"
    UNKNOWN = "UNKNOWN"


class LaneType(str, Enum):
    SOLID = "SOLID"
    DASHED = "DASHED"
    DOUBLE_SOLID = "DOUBLE_SOLID"
    UNKNOWN = "UNKNOWN"


class RiskLevel(str, Enum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class PerceptionEventType(str, Enum):
    COLLISION_RISK = "COLLISION_RISK"
    LANE_DEPARTURE_RISK = "LANE_DEPARTURE_RISK"
    OBJECT_APPROACH = "OBJECT_APPROACH"
    OBJECT_CROSSING = "OBJECT_CROSSING"
    SCENE_CHANGE = "SCENE_CHANGE"


class PerceptionEventStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"


class CoordinateFrame(str, Enum):
    """Reference frame of a geometric quantity."""

    UNKNOWN = "UNKNOWN"
    IMAGE_SPACE_RELATIVE = "IMAGE_SPACE_RELATIVE"
    RELATIVE_BEV = "RELATIVE_BEV"


class DepthSource(str, Enum):
    NOT_CONFIGURED = "NOT_CONFIGURED"
    FIXTURE_SYNTHETIC = "FIXTURE_SYNTHETIC"


class ModelState(str, Enum):
    NOT_LOADED = "NOT_LOADED"
    LOADING = "LOADING"
    READY = "READY"
    NOT_READY = "NOT_READY"


class NormalizedPoint(BaseModel):
    """One point in normalized image coordinates."""

    x: float = Field(ge=0.0, le=1.0)
    y: float = Field(ge=0.0, le=1.0)


class BevPoint(BaseModel):
    """One point in the relative bird's-eye plane.

    ``lateral`` in [-1, 1] (0 = image center), ``longitudinal`` in [0, 1]
    (1 = nearest the camera bottom edge). Unitless ordering proxy — NOT meters.
    """

    lateral: float = Field(ge=-1.0, le=1.0)
    longitudinal: float = Field(ge=0.0, le=1.0)


class EgoState(BaseModel):
    """Ego/camera state. All-``None`` with ``UNKNOWN`` frame means unavailable.

    V08 never fabricates vehicle speed: without a sensor or calibration
    source, velocity stays ``None`` and consumers must treat motion as unknown.
    """

    timestamp: datetime = Field(default_factory=utcnow)
    position: tuple[float, float, float] | None = None
    velocity: tuple[float, float, float] | None = None
    acceleration: tuple[float, float, float] | None = None
    heading: float | None = None
    yaw_rate: float | None = None
    coordinate_frame: CoordinateFrame = CoordinateFrame.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PerceivedObject(BaseModel):
    """One object in the autonomous scene, derived from V04 tracks.

    ``object_id`` is ``"track-{track_id}"`` when a V04 track backs the object.
    Velocities are normalized image units per second (resolution-independent,
    image-space — NOT m/s). Depth fields are ``None`` unless a configured
    estimator produced them.
    """

    object_id: str = Field(min_length=1, max_length=128)
    track_id: int | None = Field(default=None, ge=1)
    class_id: int = Field(default=0, ge=0)
    class_name: str = Field(default="object", min_length=1, max_length=128)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    bounding_box: tuple[float, float, float, float] | None = None
    center: tuple[float, float] | None = None
    bottom_center: tuple[float, float] | None = None
    velocity: tuple[float, float] | None = None
    acceleration: tuple[float, float] | None = None
    relative_position: tuple[float, float] | None = None
    relative_depth: float | None = Field(default=None, ge=0.0)
    depth_source: DepthSource = DepthSource.NOT_CONFIGURED
    heading: float | None = None
    object_state: PerceivedObjectState = PerceivedObjectState.UNKNOWN
    metadata: dict[str, Any] = Field(default_factory=dict)


class Lane(BaseModel):
    """One lane boundary in normalized image coordinates.

    Canonical representation: ``points`` (polyline, ordered). ``coefficients``
    holds an optional least-squares polynomial fit (x as a function of y,
    highest-degree first) derived from ``points`` — never the reverse.
    """

    lane_id: str = Field(min_length=1, max_length=128)
    points: list[NormalizedPoint] = Field(min_length=2)
    coefficients: list[float] | None = None
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    lane_type: LaneType = LaneType.UNKNOWN
    side: str | None = Field(default=None, max_length=16)
    metadata: dict[str, Any] = Field(default_factory=dict)


class Trajectory(BaseModel):
    """Short-horizon image-space prediction (constant-velocity baseline).

    Assumes the object keeps its EMA-smoothed image-space velocity over the
    horizon. Points are normalized coordinates, ordered oldest → newest from
    the current position outward. Confidence decays with horizon distance.
    """

    object_id: str = Field(min_length=1, max_length=128)
    points: list[NormalizedPoint] = Field(default_factory=list)
    horizon_seconds: float = Field(default=2.0, ge=0.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    coordinate_frame: CoordinateFrame = CoordinateFrame.IMAGE_SPACE_RELATIVE
    metadata: dict[str, Any] = Field(default_factory=dict)


class DepthReading(BaseModel):
    """One relative-depth estimate. ``depth=None`` means unavailable."""

    depth: float | None = Field(default=None, ge=0.0)
    unit: str | None = Field(default=None, max_length=32)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    source: DepthSource = DepthSource.NOT_CONFIGURED


class CollisionRisk(BaseModel):
    """One pairwise collision-risk assessment (relative-motion heuristic).

    ``risk_score`` is an uncalibrated heuristic strength in [0, 1], NOT a
    collision probability. ``time_to_collision`` is an *estimate* in seconds,
    present only when closing motion and depth support it — otherwise ``None``.
    ``risk_level=UNKNOWN`` means required inputs were unavailable, not safety.
    """

    object_ids: list[str] = Field(min_length=2, max_length=2)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    time_to_collision: float | None = Field(default=None, ge=0.0)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = Field(default="", max_length=1024)
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class BevObject(BaseModel):
    object_id: str = Field(min_length=1, max_length=128)
    lateral: float = Field(ge=-1.0, le=1.0)
    longitudinal: float = Field(ge=0.0, le=1.0)
    risk_level: RiskLevel = RiskLevel.UNKNOWN


class BirdsEyeView(BaseModel):
    """Relative bird's-eye representation (ordering proxy, never metric)."""

    coordinate_frame: CoordinateFrame = CoordinateFrame.RELATIVE_BEV
    objects: list[BevObject] = Field(default_factory=list)
    lanes: list[list[BevPoint]] = Field(default_factory=list)
    trajectories: dict[str, list[BevPoint]] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SceneHypothesis(BaseModel):
    """One scene-classification outcome."""

    scene_type: SceneType = SceneType.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    reason: str = Field(default="", max_length=1024)


class AutonomousScene(BaseModel):
    scene_id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    frame_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    scene_type: SceneType = SceneType.UNKNOWN
    scene_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    objects: list[PerceivedObject] = Field(default_factory=list)
    lanes: list[Lane] = Field(default_factory=list)
    ego_state: EgoState = Field(default_factory=EgoState)
    environment: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_websocket(self) -> dict[str, Any]:
        return {
            "scene_id": str(self.scene_id),
            "camera_id": self.camera_id,
            "frame_id": self.frame_id,
            "timestamp": self.timestamp.isoformat(),
            "scene_type": self.scene_type.value,
            "scene_confidence": self.scene_confidence,
            "objects": [
                {
                    "object_id": o.object_id,
                    "track_id": o.track_id,
                    "class_name": o.class_name,
                    "confidence": o.confidence,
                    "bounding_box": list(o.bounding_box) if o.bounding_box else None,
                    "velocity": list(o.velocity) if o.velocity else None,
                    "relative_depth": o.relative_depth,
                    "depth_source": o.depth_source.value,
                    "object_state": o.object_state.value,
                }
                for o in self.objects
            ],
            "lanes": [
                {
                    "lane_id": lane.lane_id,
                    "points": [{"x": p.x, "y": p.y} for p in lane.points],
                    "confidence": lane.confidence,
                    "lane_type": lane.lane_type.value,
                    "side": lane.side,
                }
                for lane in self.lanes
            ],
            "scene_type_confidence": self.scene_confidence,
        }


class AutonomousPerceptionEvent(BaseModel):
    """One continuing perception condition (not one per frame)."""

    event_id: UUID = Field(default_factory=uuid4)
    scene_id: UUID | None = None
    camera_id: str = Field(min_length=1, max_length=128)
    event_type: PerceptionEventType
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    object_ids: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    status: PerceptionEventStatus = PerceptionEventStatus.ACTIVE
    timestamp: datetime = Field(default_factory=utcnow)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    duration_ms: float = Field(default=0.0, ge=0.0)
    message: str = Field(default="", max_length=1024)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self, timestamp: datetime) -> None:
        self.last_seen = timestamp
        self.timestamp = timestamp
        self.duration_ms = max(0.0, (timestamp - self.first_seen).total_seconds() * 1000.0)

    def to_websocket(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "scene_id": str(self.scene_id) if self.scene_id else None,
            "event_type": self.event_type.value,
            "risk_level": self.risk_level.value,
            "object_ids": list(self.object_ids),
            "confidence": self.confidence,
            "status": self.status.value,
            "timestamp": self.timestamp.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_ms": self.duration_ms,
            "message": self.message,
        }


class AutonomousPerceptionResult(BaseModel):
    """Outcome of one perception pass (in memory only — never persisted)."""

    scene_id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    frame_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    scene: AutonomousScene | None = None
    objects: list[PerceivedObject] = Field(default_factory=list)
    lanes: list[Lane] = Field(default_factory=list)
    ego_state: EgoState = Field(default_factory=EgoState)
    trajectories: list[Trajectory] = Field(default_factory=list)
    collision_risks: list[CollisionRisk] = Field(default_factory=list)
    events: list[AutonomousPerceptionEvent] = Field(default_factory=list)
    bev: BirdsEyeView | None = None
    processing_time_ms: float = 0.0
    model_metadata: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_websocket(self) -> dict[str, Any]:
        scene = self.scene.to_websocket() if self.scene else None
        payload: dict[str, Any] = {
            "scene_id": str(self.scene_id),
            "camera_id": self.camera_id,
            "frame_id": self.frame_id,
            "timestamp": self.timestamp.isoformat(),
            "scene_type": self.scene.scene_type.value if self.scene else SceneType.UNKNOWN.value,
            "objects": scene["objects"] if scene else [],
            "lanes": scene["lanes"] if scene else [],
            "trajectories": [
                {
                    "object_id": t.object_id,
                    "points": [{"x": p.x, "y": p.y} for p in t.points],
                    "horizon_seconds": t.horizon_seconds,
                    "confidence": t.confidence,
                }
                for t in self.trajectories
            ],
            # Only actionable risks travel on the wire; NONE/UNKNOWN pairs
            # are noise. The full assessment lives in the engine state.
            "collision_risks": [
                {
                    "object_ids": list(r.object_ids),
                    "risk_level": r.risk_level.value,
                    "risk_score": r.risk_score,
                    "time_to_collision": r.time_to_collision,
                    "confidence": r.confidence,
                    "reason": r.reason,
                }
                for r in self.collision_risks
                if r.risk_level.value not in ("NONE", "UNKNOWN")
            ],
            "processing_time_ms": self.processing_time_ms,
        }
        return payload


class AutonomousProfile(BaseModel):
    """Per-camera perception configuration (mirrors the profiles table)."""

    profile_id: str = Field(min_length=1, max_length=128)
    camera_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    scene_type: SceneType = SceneType.UNKNOWN
    lane_detection_enabled: bool = True
    depth_enabled: bool = False
    trajectory_enabled: bool = True
    collision_risk_enabled: bool = True
    bev_enabled: bool = True
    trajectory_horizon_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    collision_risk_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    collision_grace_seconds: float = Field(default=0.5, ge=0.0, le=300.0)
    configuration: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _valid_thresholds(self) -> AutonomousProfile:
        if not 0.0 <= self.collision_risk_threshold <= 1.0:
            raise ValueError("collision_risk_threshold must be in [0, 1]")
        return self
