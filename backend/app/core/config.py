"""Centralized application configuration.

Single source of truth for environment-driven settings. Supports
development / testing / production via ``APP_ENV``. No secrets are
hardcoded; everything sensitive comes from the environment.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppEnv(str, Enum):
    development = "development"
    testing = "testing"
    production = "production"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Application ---
    app_name: str = Field(default="industrial-vision-platform")
    app_env: AppEnv = Field(default=AppEnv.development)
    log_level: str = Field(default="INFO")

    # --- API ---
    api_host: str = Field(default="0.0.0.0")
    api_port: int = Field(default=8000)

    # --- Data layer (ready, not mandatory in V01) ---
    database_url: str = Field(
        default="postgresql+psycopg2://postgres:postgres@localhost:5432/industrial_vision"
    )
    redis_url: str = Field(default="redis://localhost:6379/0")

    # --- AI / model (V01 config; V03 live inference) ---
    gpu_enabled: bool = Field(default=False)
    model_device: str = Field(default="cpu")
    model_confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0)

    # --- V03 inference engine ---
    model_name: str = Field(default="yolo11n")
    model_path: str = Field(default="models/yolo11n.pt")
    model_iou_threshold: float = Field(default=0.45, ge=0.0, le=1.0)
    model_image_size: int = Field(default=640, ge=320, le=1280)
    model_max_detections: int = Field(default=300, ge=1, le=1000)
    # Comma-separated class allowlist, e.g. "person,car"; empty = all classes.
    model_classes: str = Field(default="")

    @field_validator("model_device")
    @classmethod
    def _normalize_device(cls, value: str) -> str:
        normalized = value.lower()
        if normalized not in ("auto", "cpu", "cuda"):
            raise ValueError("MODEL_DEVICE must be one of auto|cpu|cuda")
        return normalized

    @property
    def model_class_allowlist(self) -> frozenset[str]:
        return frozenset(part.strip().lower() for part in self.model_classes.split(",") if part.strip())

    # --- V04 tracking engine (native ByteTrack-compatible) ---
    track_min_hits: int = Field(default=3, ge=1, le=20)
    track_max_age: int = Field(default=30, ge=1, le=600)
    track_iou_threshold: float = Field(default=0.3, ge=0.0, le=1.0)
    track_history_size: int = Field(default=30, ge=1, le=300)
    # Detections at/above this confidence join stage-1 association; below it,
    # down to MODEL_CONFIDENCE_THRESHOLD, join stage-2 (track continuation).
    track_high_conf: float = Field(default=0.5, ge=0.0, le=1.0)

    # --- V05 safety intelligence (deterministic geometry rules) ---
    safety_enabled: bool = Field(default=True)
    safety_fall_aspect_ratio_threshold: float = Field(default=1.2, ge=0.1, le=10.0)
    safety_fall_persistence_frames: int = Field(default=5, ge=1, le=300)
    safety_crowd_warning_count: int = Field(default=5, ge=1, le=1000)
    safety_crowd_critical_count: int = Field(default=10, ge=1, le=1000)
    safety_proximity_iou_threshold: float = Field(default=0.05, ge=0.0, le=1.0)
    safety_proximity_center_distance_ratio: float = Field(default=0.3, ge=0.0, le=2.0)
    safety_stationary_speed_threshold: float = Field(default=15.0, ge=0.0)
    safety_stationary_duration_seconds: float = Field(default=10.0, ge=0.0)
    safety_event_resolution_grace_seconds: float = Field(default=3.0, ge=0.0, le=300.0)
    safety_max_events_per_camera: int = Field(default=100, ge=1, le=10000)

    # --- V06 spatial safety (image-space zones + proximity) ---
    spatial_enabled: bool = Field(default=True)
    spatial_default_dwell_seconds: float = Field(default=5.0, ge=0.0, le=3600.0)
    spatial_proximity_strategy: str = Field(default="HYBRID")
    spatial_proximity_iou_threshold: float = Field(default=0.05, ge=0.0, le=1.0)
    spatial_person_vehicle_enabled: bool = Field(default=True)
    spatial_person_vehicle_threshold: float = Field(default=0.3, ge=0.0, le=2.0)
    spatial_person_vehicle_severity: str = Field(default="HIGH")
    spatial_person_person_enabled: bool = Field(default=False)
    spatial_person_person_threshold: float = Field(default=0.25, ge=0.0, le=2.0)
    spatial_person_person_severity: str = Field(default="MEDIUM")
    spatial_vehicle_vehicle_enabled: bool = Field(default=False)
    spatial_vehicle_vehicle_threshold: float = Field(default=0.25, ge=0.0, le=2.0)
    spatial_vehicle_vehicle_severity: str = Field(default="LOW")
    spatial_max_zones_per_camera: int = Field(default=20, ge=1, le=200)
    spatial_state_grace_seconds: float = Field(default=5.0, ge=0.0, le=300.0)

    # --- V07 quality inspection (framework; no specialized defect weights) ---
    quality_enabled: bool = Field(default=True)
    # Named inspection model. Empty = INSPECTION_MODEL_NOT_CONFIGURED: an
    # inspection attempt then decides ERROR (never PASS). The scripted fixture
    # adapter resolves only outside production (see quality.registry).
    quality_inspection_model: str = Field(default="")
    quality_inspection_interval_frames: int = Field(default=5, ge=1, le=600)
    quality_max_profiles_per_camera: int = Field(default=10, ge=1, le=100)
    quality_max_regions_per_profile: int = Field(default=20, ge=1, le=200)
    quality_max_observations_per_inspection: int = Field(default=50, ge=1, le=1000)
    quality_max_results_per_camera: int = Field(default=30, ge=1, le=1000)
    quality_max_events_per_camera: int = Field(default=100, ge=1, le=10000)
    quality_event_resolution_grace_seconds: float = Field(default=3.0, ge=0.0, le=300.0)
    quality_default_confidence_threshold: float = Field(default=0.6, ge=0.0, le=1.0)
    quality_default_review_threshold: float = Field(default=0.35, ge=0.0, le=1.0)
    quality_default_fail_severities: str = Field(default="HIGH,CRITICAL")
    quality_missing_evidence_behavior: str = Field(default="REVIEW")
    quality_inspection_error_behavior: str = Field(default="RECORD_ERROR")

    @field_validator("quality_default_fail_severities")
    @classmethod
    def _normalize_fail_severities(cls, value: str) -> str:
        from backend.app.quality.schemas import DefectSeverity

        parts = [part.strip().upper() for part in value.split(",") if part.strip()]
        allowed = {s.value for s in DefectSeverity}
        unknown = [part for part in parts if part not in allowed]
        if unknown:
            raise ValueError(f"QUALITY_DEFAULT_FAIL_SEVERITIES unknown values: {unknown}")
        return ",".join(parts)

    @field_validator("quality_missing_evidence_behavior")
    @classmethod
    def _normalize_missing_evidence(cls, value: str) -> str:
        from backend.app.quality.schemas import MissingEvidenceBehavior

        normalized = value.upper()
        if normalized not in {b.value for b in MissingEvidenceBehavior}:
            raise ValueError(
                "QUALITY_MISSING_EVIDENCE_BEHAVIOR must be one of "
                f"{[b.value for b in MissingEvidenceBehavior]}"
            )
        return normalized

    @field_validator("quality_inspection_error_behavior")
    @classmethod
    def _normalize_error_behavior(cls, value: str) -> str:
        from backend.app.quality.schemas import InspectionErrorBehavior

        normalized = value.upper()
        if normalized not in {b.value for b in InspectionErrorBehavior}:
            raise ValueError(
                "QUALITY_INSPECTION_ERROR_BEHAVIOR must be one of "
                f"{[b.value for b in InspectionErrorBehavior]}"
            )
        return normalized

    @property
    def quality_fail_severities(self) -> frozenset[str]:
        return frozenset(
            part.strip() for part in self.quality_default_fail_severities.split(",") if part.strip()
        )

    # --- V08 autonomous perception (relative scene understanding; no metric claims) ---
    autonomous_enabled: bool = Field(default=True)
    # Named model adapters. Empty = NOT_CONFIGURED: that subsystem reports
    # unavailable and the rest of perception continues. "fixture" resolves the
    # scripted test adapters OUTSIDE production only (see autonomous.registry).
    autonomous_scene_classifier: str = Field(default="")
    autonomous_lane_detector: str = Field(default="")
    autonomous_depth_model: str = Field(default="")
    autonomous_lane_detection_enabled: bool = Field(default=True)
    autonomous_depth_enabled: bool = Field(default=False)
    autonomous_trajectory_enabled: bool = Field(default=True)
    autonomous_collision_risk_enabled: bool = Field(default=True)
    autonomous_bev_enabled: bool = Field(default=True)
    autonomous_perception_interval_frames: int = Field(default=10, ge=1, le=600)
    autonomous_trajectory_horizon_seconds: float = Field(default=2.0, ge=0.1, le=10.0)
    autonomous_trajectory_history_points: int = Field(default=8, ge=2, le=60)
    autonomous_collision_grace_seconds: float = Field(default=0.5, ge=0.0, le=300.0)
    autonomous_collision_risk_threshold: float = Field(default=0.5, ge=0.0, le=1.0)
    autonomous_max_objects_per_scene: int = Field(default=100, ge=1, le=1000)
    autonomous_max_results_per_camera: int = Field(default=30, ge=1, le=1000)
    autonomous_max_events_per_camera: int = Field(default=100, ge=1, le=10000)
    autonomous_max_profiles_per_camera: int = Field(default=10, ge=1, le=100)
    # Normalized-units-per-second below which an object counts as stationary.
    autonomous_motion_speed_threshold: float = Field(default=0.02, ge=0.0, le=2.0)
    # Fractional bbox-area growth per second that counts as approaching.
    autonomous_approach_area_ratio: float = Field(default=0.02, ge=0.0, le=2.0)

    @field_validator("spatial_proximity_strategy")
    @classmethod
    def _normalize_strategy(cls, value: str) -> str:
        normalized = value.upper()
        if normalized not in ("CENTER_DISTANCE", "IOU", "HYBRID"):
            raise ValueError("SPATIAL_PROXIMITY_STRATEGY must be CENTER_DISTANCE|IOU|HYBRID")
        return normalized

    @field_validator(
        "spatial_person_vehicle_severity",
        "spatial_person_person_severity",
        "spatial_vehicle_vehicle_severity",
    )
    @classmethod
    def _normalize_spatial_severity(cls, value: str) -> str:
        from backend.app.safety.schemas import SafetySeverity

        normalized = value.upper()
        if normalized not in {s.value for s in SafetySeverity}:
            raise ValueError(f"spatial severity must be one of {[s.value for s in SafetySeverity]}")
        return normalized

    # --- Realtime ---
    websocket_enabled: bool = Field(default=True)

    # --- V02 video ingestion ---
    target_processing_fps: float = Field(default=10.0, ge=0.0)
    frame_skip: int = Field(default=0, ge=0)
    buffer_size: int = Field(default=30, ge=1, le=1000)

    @field_validator("log_level")
    @classmethod
    def _normalize_log_level(cls, value: str) -> str:
        normalized = value.upper()
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if normalized not in allowed:
            raise ValueError(f"LOG_LEVEL must be one of {sorted(allowed)}")
        return normalized

    @property
    def is_testing(self) -> bool:
        return self.app_env == AppEnv.testing

    @property
    def is_production(self) -> bool:
        return self.app_env == AppEnv.production


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached settings instance (override in tests via dependency)."""
    return Settings()
