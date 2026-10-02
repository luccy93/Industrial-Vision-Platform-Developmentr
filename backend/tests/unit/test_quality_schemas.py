"""Quality schema + config tests — enums, validation, serialization."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.core.config import Settings
from backend.app.quality.inspection import InspectionErrorCode, InspectionModelState
from backend.app.quality.schemas import (
    DefectSeverity,
    InspectionType,
    MissingEvidenceBehavior,
    ProductCorrelation,
    QualityDecision,
    QualityEvent,
    QualityEventStatus,
    QualityEventType,
    RegionType,
)
from backend.tests.quality_helpers import (
    make_category,
    make_observation,
    make_policy,
    make_profile,
    make_region,
)


def test_enum_values() -> None:
    assert {t.value for t in InspectionType} == {
        "GENERAL",
        "SURFACE",
        "ASSEMBLY",
        "COMPONENT",
        "DIMENSION",
        "CUSTOM",
    }
    assert {t.value for t in RegionType} == {"RECTANGLE", "POLYGON"}
    assert {s.value for s in DefectSeverity} == {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
    assert {d.value for d in QualityDecision} == {"PASS", "FAIL", "REVIEW", "ERROR"}
    assert {t.value for t in QualityEventType} == {
        "QUALITY_FAIL",
        "QUALITY_REVIEW",
        "QUALITY_ERROR",
        "DEFECT_DETECTED",
    }
    assert {s.value for s in QualityEventStatus} == {"ACTIVE", "RESOLVED", "SUPPRESSED"}
    assert {b.value for b in MissingEvidenceBehavior} == {"REVIEW", "FAIL", "IGNORE"}
    assert {c.value for c in InspectionErrorCode} == {
        "INSPECTION_MODEL_NOT_CONFIGURED",
        "INSPECTION_MODEL_NOT_READY",
        "INSPECTION_MODEL_ERROR",
        "INSPECTION_CONFIG_INVALID",
        "FRAME_INVALID",
    }
    assert {s.value for s in InspectionModelState} == {
        "NOT_LOADED",
        "LOADING",
        "READY",
        "NOT_READY",
    }


def test_profile_defaults_and_validation() -> None:
    profile = make_profile()
    assert profile.enabled is True
    assert profile.inspection_type is InspectionType.SURFACE
    assert profile.decision_policy.fail_threshold == 0.6
    assert profile.product_correlation is None
    with pytest.raises(ValidationError):
        make_profile(review_threshold=0.8, confidence_threshold=0.5)
    with pytest.raises(ValidationError):
        make_profile(confidence_threshold=1.5)


def test_decision_policy_validation() -> None:
    with pytest.raises(ValidationError):
        make_policy(review_threshold=0.8, fail_threshold=0.5)
    with pytest.raises(ValidationError):
        make_policy(fail_severities=[])
    policy = make_policy(fail_severities=[DefectSeverity.CRITICAL])
    assert policy.fail_severities == [DefectSeverity.CRITICAL]


def test_region_rectangle_validation() -> None:
    region = make_region()
    assert region.region_type is RegionType.RECTANGLE
    assert region.required is False
    with pytest.raises(ValidationError):
        make_region(geometry={"x": 0.1, "y": 0.1, "width": 0.5})
    with pytest.raises(ValidationError):
        make_region(geometry={"x": 0.8, "y": 0.1, "width": 0.5, "height": 0.5})
    with pytest.raises(ValidationError):
        make_region(geometry={"x": 0.1, "y": 0.1, "width": 0.0, "height": 0.5})


def test_region_polygon_validation() -> None:
    polygon = make_region(
        region_type=RegionType.POLYGON,
        geometry={
            "points": [
                {"x": 0.1, "y": 0.1},
                {"x": 0.9, "y": 0.1},
                {"x": 0.9, "y": 0.9},
            ]
        },
    )
    assert polygon.region_type is RegionType.POLYGON
    with pytest.raises(ValidationError):
        make_region(
            region_type=RegionType.POLYGON,
            geometry={"points": [{"x": 0.1, "y": 0.1}, {"x": 0.9, "y": 0.9}]},
        )
    with pytest.raises(ValidationError):
        make_region(
            region_type=RegionType.POLYGON,
            geometry={
                "points": [
                    {"x": 0.5, "y": 0.1},
                    {"x": 0.5, "y": 0.5},
                    {"x": 0.5, "y": 0.9},
                ]
            },
        )
    with pytest.raises(ValidationError):
        make_region(
            region_type=RegionType.POLYGON,
            geometry={"points": [{"x": 1.5, "y": 0.1}, {"x": 0.9, "y": 0.1}, {"x": 0.9, "y": 0.9}]},
        )


def test_category_validation() -> None:
    category = make_category()
    assert category.severity is DefectSeverity.HIGH
    with pytest.raises(ValidationError):
        make_category(review_threshold=0.8, confidence_threshold=0.5)
    with pytest.raises(ValidationError):
        make_category(confidence_threshold=-0.1)


def test_observation_confidence_bounds() -> None:
    observation = make_observation()
    assert observation.confidence == 0.97
    assert observation.bounding_box == (0.4, 0.4, 0.6, 0.6)
    with pytest.raises(ValidationError):
        make_observation(confidence=1.5)
    with pytest.raises(ValidationError):
        make_observation(confidence=-0.1)


def test_product_correlation_optional() -> None:
    correlation = ProductCorrelation(batch_id="B-100")
    assert correlation.batch_id == "B-100"
    assert correlation.product_id is None
    profile = make_profile(product_correlation=correlation)
    assert profile.product_correlation is not None


def test_quality_event_defaults_and_touch() -> None:
    from datetime import timedelta

    event = QualityEvent(
        camera_id="cam-01",
        event_type=QualityEventType.QUALITY_FAIL,
        decision=QualityDecision.FAIL,
        severity=DefectSeverity.HIGH,
        defect_code="CRACK",
    )
    assert event.status is QualityEventStatus.ACTIVE
    assert event.duration_ms == 0.0
    assert event.observations == []
    event.touch(event.first_seen + timedelta(seconds=2))
    assert event.duration_ms == pytest.approx(2000.0)
    assert event.to_websocket()["event_type"] == "QUALITY_FAIL"


def test_result_websocket_has_no_image_payload() -> None:
    from backend.app.quality.schemas import InspectionResult

    result = InspectionResult(camera_id="cam-01", profile_id="profile-01")
    payload = result.to_websocket()
    assert "image" not in payload and "base64" not in payload
    assert payload["decision"] == "PASS"


def test_quality_config_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.quality_enabled is True
    assert settings.quality_inspection_model == ""
    assert settings.quality_inspection_interval_frames == 5
    assert settings.quality_max_profiles_per_camera == 10
    assert settings.quality_max_regions_per_profile == 20
    assert settings.quality_max_observations_per_inspection == 50
    assert settings.quality_max_results_per_camera == 30
    assert settings.quality_max_events_per_camera == 100
    assert settings.quality_event_resolution_grace_seconds == 3.0
    assert settings.quality_default_confidence_threshold == 0.6
    assert settings.quality_default_review_threshold == 0.35
    assert settings.quality_fail_severities == frozenset({"HIGH", "CRITICAL"})
    assert settings.quality_missing_evidence_behavior == "REVIEW"
    assert settings.quality_inspection_error_behavior == "RECORD_ERROR"


def test_quality_config_validation() -> None:
    with pytest.raises(ValueError):
        Settings(quality_default_fail_severities="HIGH,EXTREME", _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(quality_missing_evidence_behavior="MAYBE", _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(quality_inspection_error_behavior="IGNORE", _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(quality_inspection_interval_frames=0, _env_file=None)  # type: ignore[call-arg]
