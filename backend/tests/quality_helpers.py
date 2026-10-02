"""Shared quality test builders — deterministic, hermetic, no model weights.

Mirrors ``backend/tests/safety_helpers.py``: a fixed synthetic epoch keeps
duration assertions stable, and every builder returns plain domain objects.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import numpy as np

from backend.app.quality.schemas import (
    DecisionPolicy,
    DefectCategory,
    DefectObservation,
    DefectSeverity,
    InspectionProfile,
    InspectionRegion,
    InspectionType,
    QualityDecision,
    RegionType,
)

_EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def utc(offset_seconds: float = 0.0) -> datetime:
    """Deterministic test clock: exact offsets from a fixed epoch."""
    return _EPOCH + timedelta(seconds=offset_seconds)


def make_profile(**overrides) -> InspectionProfile:  # type: ignore[no-untyped-def]
    params: dict = {
        "profile_id": "profile-01",
        "camera_id": "cam-01",
        "name": "Surface inspection",
        "enabled": True,
        "inspection_type": InspectionType.SURFACE,
        "confidence_threshold": 0.6,
        "review_threshold": 0.35,
    }
    params.update(overrides)
    return InspectionProfile(**params)  # type: ignore[arg-type]


def make_region(**overrides) -> InspectionRegion:  # type: ignore[no-untyped-def]
    params: dict = {
        "region_id": "region-01",
        "camera_id": "cam-01",
        "profile_id": "profile-01",
        "name": "Housing surface",
        "region_type": RegionType.RECTANGLE,
        "geometry": {"x": 0.1, "y": 0.1, "width": 0.8, "height": 0.8},
        "enabled": True,
        "required": False,
    }
    params.update(overrides)
    return InspectionRegion(**params)  # type: ignore[arg-type]


def make_category(**overrides) -> DefectCategory:  # type: ignore[no-untyped-def]
    params: dict = {
        "defect_id": "cat-crack",
        "code": "CRACK",
        "name": "Crack",
        "description": "Surface crack",
        "severity": DefectSeverity.HIGH,
        "enabled": True,
        "confidence_threshold": 0.6,
        "review_threshold": 0.35,
    }
    params.update(overrides)
    return DefectCategory(**params)  # type: ignore[arg-type]


def make_observation(**overrides) -> DefectObservation:  # type: ignore[no-untyped-def]
    params: dict = {
        "camera_id": "cam-01",
        "defect_code": "CRACK",
        "defect_name": "Crack",
        "severity": DefectSeverity.HIGH,
        "confidence": 0.97,
        "bounding_box": (0.4, 0.4, 0.6, 0.6),
        "region_id": "region-01",
    }
    params.update(overrides)
    return DefectObservation(**params)  # type: ignore[arg-type]


def make_policy(**overrides) -> DecisionPolicy:  # type: ignore[no-untyped-def]
    params: dict = {
        "fail_threshold": 0.6,
        "review_threshold": 0.35,
    }
    params.update(overrides)
    return DecisionPolicy(**params)  # type: ignore[arg-type]


def synthetic_frame(width: int = 640, height: int = 480, value: int = 128) -> np.ndarray:
    """Flat BGR uint8 frame — enough for ROI extraction and shape validation."""
    return np.full((height, width, 3), value, dtype=np.uint8)


def decision_rank(decision: QualityDecision) -> int:
    return {QualityDecision.PASS: 0, QualityDecision.REVIEW: 1, QualityDecision.FAIL: 2}[decision]


def new_id() -> str:
    return uuid4().hex[:12]
