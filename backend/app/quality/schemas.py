"""Quality domain model — inspection profiles, regions, defects, decisions, events.

Confidence semantics: ``confidence`` is a model/rule *strength score* in
[0, 1]. It is NOT a statistically calibrated probability unless the producing
model documents calibration.

V07 is an inspection *framework*. Defect categories are configuration
definitions, not evidence that any model can detect them. The deterministic
fixture adapter (``backend.app.quality.fixture``) returns explicitly supplied
test observations and never represents them as real model predictions.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, model_validator

from backend.app.domain.common import utcnow
from backend.app.spatial.schemas import ZonePoint


class InspectionType(str, Enum):
    GENERAL = "GENERAL"
    SURFACE = "SURFACE"
    ASSEMBLY = "ASSEMBLY"
    COMPONENT = "COMPONENT"
    DIMENSION = "DIMENSION"
    CUSTOM = "CUSTOM"


class RegionType(str, Enum):
    RECTANGLE = "RECTANGLE"
    POLYGON = "POLYGON"


class DefectSeverity(str, Enum):
    """Quality severity — independent from V05 safety severity by design."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class QualityDecision(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    REVIEW = "REVIEW"
    ERROR = "ERROR"


class QualityEventType(str, Enum):
    QUALITY_FAIL = "QUALITY_FAIL"
    QUALITY_REVIEW = "QUALITY_REVIEW"
    QUALITY_ERROR = "QUALITY_ERROR"
    DEFECT_DETECTED = "DEFECT_DETECTED"


class QualityEventStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class MissingEvidenceBehavior(str, Enum):
    """What to decide when a required region produced no evidence."""

    REVIEW = "REVIEW"
    FAIL = "FAIL"
    IGNORE = "IGNORE"


class InspectionErrorBehavior(str, Enum):
    """What to do when an inspection cannot complete reliably."""

    RECORD_ERROR = "RECORD_ERROR"
    SKIP = "SKIP"


class ProductCorrelation(BaseModel):
    """Optional product/unit linkage — never fabricated, always operator-supplied."""

    product_id: str | None = Field(default=None, max_length=128)
    batch_id: str | None = Field(default=None, max_length=128)
    work_order_id: str | None = Field(default=None, max_length=128)
    unit_id: str | None = Field(default=None, max_length=128)


class DecisionPolicy(BaseModel):
    """How observations become a PASS/FAIL/REVIEW decision.

    Thresholds are ratios in [0, 1] and are always read from configuration —
    no production values are hard-coded here.
    """

    fail_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    fail_severities: list[DefectSeverity] = Field(
        default_factory=lambda: [DefectSeverity.HIGH, DefectSeverity.CRITICAL]
    )
    required_region_ids: list[str] = Field(default_factory=list)
    missing_evidence_behavior: MissingEvidenceBehavior = MissingEvidenceBehavior.REVIEW
    error_behavior: InspectionErrorBehavior = InspectionErrorBehavior.RECORD_ERROR

    @model_validator(mode="after")
    def _ordered_thresholds(self) -> DecisionPolicy:
        if self.review_threshold > self.fail_threshold:
            raise ValueError("review_threshold must not exceed fail_threshold")
        if not self.fail_severities:
            raise ValueError("fail_severities must not be empty")
        return self


class InspectionRegion(BaseModel):
    """One inspection region in normalized image coordinates (x, y in [0, 1]).

    Geometry validation reuses the V06 spatial primitives (``ZonePoint``) so
    polygon rules are defined exactly once. This is a separate domain model —
    V06 owns zones, V07 owns inspection regions.
    """

    region_id: str = Field(min_length=1, max_length=128)
    camera_id: str = Field(min_length=1, max_length=128)
    profile_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    region_type: RegionType = RegionType.RECTANGLE
    # RECTANGLE: {"x","y","width","height"}; POLYGON: list of ZonePoint.
    geometry: dict[str, Any]
    enabled: bool = True
    required: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _valid_geometry(self) -> InspectionRegion:
        if self.region_type is RegionType.RECTANGLE:
            rect = self.geometry
            for key in ("x", "y", "width", "height"):
                if key not in rect:
                    raise ValueError(f"rectangle geometry requires {key}")
            if not (0.0 <= float(rect["x"]) <= 1.0 and 0.0 <= float(rect["y"]) <= 1.0):
                raise ValueError("rectangle origin must be within normalized bounds")
            if not (0.0 < float(rect["width"]) <= 1.0 and 0.0 < float(rect["height"]) <= 1.0):
                raise ValueError("rectangle width/height must be in (0, 1]")
            if (
                float(rect["x"]) + float(rect["width"]) > 1.0
                or float(rect["y"]) + float(rect["height"]) > 1.0
            ):
                raise ValueError("rectangle must fit inside the normalized frame")
        else:
            points = self.geometry.get("points")
            if not isinstance(points, list) or len(points) < 3:
                raise ValueError("polygon geometry requires at least 3 points")
            # Re-validate every point through the shared V06 point contract.
            for point in points:
                ZonePoint(x=float(point["x"]), y=float(point["y"]))
            xs = {round(float(p["x"]), 6) for p in points}
            ys = {round(float(p["y"]), 6) for p in points}
            if len(xs) < 2 or len(ys) < 2:
                raise ValueError("polygon must span area in both axes")
        return self


class DefectCategory(BaseModel):
    """Reusable defect definition — a catalog entry, not a detection claim."""

    defect_id: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    description: str = Field(default="", max_length=1024)
    severity: DefectSeverity = DefectSeverity.MEDIUM
    enabled: bool = True
    confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _ordered_thresholds(self) -> DefectCategory:
        if self.review_threshold > self.confidence_threshold:
            raise ValueError("review_threshold must not exceed confidence_threshold")
        return self


class ProfileDefectCategory(BaseModel):
    """Association: which defect categories a profile inspects, with overrides."""

    profile_id: str = Field(min_length=1, max_length=128)
    defect_category_id: str = Field(min_length=1, max_length=128)
    defect_code: str = Field(min_length=1, max_length=64)
    enabled: bool = True
    override_confidence_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    override_review_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class InspectionProfile(BaseModel):
    """How one camera's inspection is performed (mirrors ``inspection_profiles``)."""

    profile_id: str = Field(min_length=1, max_length=128)
    camera_id: str = Field(min_length=1, max_length=128)
    name: str = Field(min_length=1, max_length=128)
    enabled: bool = True
    inspection_type: InspectionType = InspectionType.GENERAL
    confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    review_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    decision_policy: DecisionPolicy = Field(default_factory=DecisionPolicy)
    product_correlation: ProductCorrelation | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @model_validator(mode="after")
    def _ordered_thresholds(self) -> InspectionProfile:
        if self.review_threshold > self.confidence_threshold:
            raise ValueError("review_threshold must not exceed confidence_threshold")
        return self


class DefectObservation(BaseModel):
    """One defect observation produced by an inspection model for one region.

    ``confidence`` is the model/rule strength score for this observation — not
    a calibrated probability. ``bounding_box`` is in full-frame normalized
    coordinates regardless of the region it was found in.
    """

    observation_id: UUID = Field(default_factory=uuid4)
    inspection_id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    frame_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    defect_code: str = Field(min_length=1, max_length=64)
    defect_name: str = Field(min_length=1, max_length=128)
    severity: DefectSeverity = DefectSeverity.MEDIUM
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    bounding_box: tuple[float, float, float, float] | None = None
    region_id: str | None = None
    track_id: int | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class QualityEvidence(BaseModel):
    """Evidence attached to an observation or result — no image storage in V07."""

    frame_id: str | None = None
    region_id: str | None = None
    bounding_box: tuple[float, float, float, float] | None = None
    model_name: str | None = None
    model_version: str | None = None
    source: str | None = None


class InspectionResult(BaseModel):
    """Outcome of one inspection pass (in memory only — never persisted)."""

    inspection_id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    profile_id: str = Field(min_length=1, max_length=128)
    frame_id: str | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    decision: QualityDecision = QualityDecision.PASS
    decision_reason: str = ""
    severity: DefectSeverity = DefectSeverity.INFO
    observations: list[DefectObservation] = Field(default_factory=list)
    inspection_time_ms: float = 0.0
    model_name: str | None = None
    model_version: str | None = None
    regions_evaluated: list[str] = Field(default_factory=list)
    error_code: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_websocket(self) -> dict[str, Any]:
        return {
            "inspection_id": str(self.inspection_id),
            "camera_id": self.camera_id,
            "profile_id": self.profile_id,
            "frame_id": self.frame_id,
            "decision": self.decision.value,
            "decision_reason": self.decision_reason,
            "severity": self.severity.value,
            "observations": [
                {
                    "observation_id": str(o.observation_id),
                    "defect_code": o.defect_code,
                    "defect_name": o.defect_name,
                    "severity": o.severity.value,
                    "confidence": o.confidence,
                    "bounding_box": list(o.bounding_box) if o.bounding_box else None,
                    "region_id": o.region_id,
                    "track_id": o.track_id,
                }
                for o in self.observations
            ],
            "inspection_time_ms": self.inspection_time_ms,
            "model_name": self.model_name,
            "model_version": self.model_version,
            "regions_evaluated": list(self.regions_evaluated),
            "error_code": self.error_code,
            "timestamp": self.timestamp.isoformat(),
        }


class InspectionSession(BaseModel):
    """Runtime per (camera, profile) counters — bounded, in memory only."""

    session_id: UUID = Field(default_factory=uuid4)
    camera_id: str = Field(min_length=1, max_length=128)
    profile_id: str = Field(min_length=1, max_length=128)
    started_at: datetime = Field(default_factory=utcnow)
    last_inspection_at: datetime | None = None
    inspection_count: int = 0
    pass_count: int = 0
    fail_count: int = 0
    review_count: int = 0
    error_count: int = 0


class QualityEvent(BaseModel):
    """One continuing quality condition (not one per frame).

    Two event levels share this model:
    * inspection-level — QUALITY_FAIL / QUALITY_REVIEW / QUALITY_ERROR
    * defect-level   — DEFECT_DETECTED, the event representation of a specific
      DefectObservation's continuity (dedupe key: profile + defect code +
      region). Defect events never exist without an observation behind them.
    """

    event_id: UUID = Field(default_factory=uuid4)
    inspection_id: UUID | None = None
    camera_id: str = Field(min_length=1, max_length=128)
    event_type: QualityEventType
    decision: QualityDecision = QualityDecision.PASS
    severity: DefectSeverity = DefectSeverity.INFO
    status: QualityEventStatus = QualityEventStatus.ACTIVE
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    defect_code: str | None = None
    region_id: str | None = None
    track_id: int | None = None
    timestamp: datetime = Field(default_factory=utcnow)
    first_seen: datetime = Field(default_factory=utcnow)
    last_seen: datetime = Field(default_factory=utcnow)
    duration_ms: float = Field(default=0.0, ge=0.0)
    message: str = Field(default="", max_length=1024)
    observations: list[DefectObservation] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def touch(self, timestamp: datetime) -> None:
        self.last_seen = timestamp
        self.timestamp = timestamp
        self.duration_ms = max(0.0, (timestamp - self.first_seen).total_seconds() * 1000.0)

    def to_websocket(self) -> dict[str, Any]:
        return {
            "event_id": str(self.event_id),
            "inspection_id": str(self.inspection_id) if self.inspection_id else None,
            "event_type": self.event_type.value,
            "decision": self.decision.value,
            "severity": self.severity.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "defect_code": self.defect_code,
            "region_id": self.region_id,
            "track_id": self.track_id,
            "timestamp": self.timestamp.isoformat(),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "duration_ms": self.duration_ms,
            "message": self.message,
            "observations": len(self.observations),
        }
