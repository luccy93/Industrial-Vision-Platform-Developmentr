"""Quality engine tests — decisions, events, sessions, isolation."""

from __future__ import annotations

import pytest

from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.quality.engine import QualityInspectionEngine
from backend.app.quality.fixture import FixtureInspectionModel
from backend.app.quality.inspection import InspectionErrorCode, RawDefect
from backend.app.quality.schemas import (
    DefectSeverity,
    ProfileDefectCategory,
    QualityDecision,
    QualityEventType,
    RegionType,
)
from backend.tests.quality_helpers import (
    make_category,
    make_policy,
    make_profile,
    make_region,
    synthetic_frame,
    utc,
)

_BOX = (10.0, 10.0, 100.0, 100.0)


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def _frame(width: int = 640, height: int = 480) -> IngestionFrame:
    return IngestionFrame(
        camera_id="cam-01",
        frame_number=1,
        width=width,
        height=height,
        image=synthetic_frame(width, height),
    )


def _engine(model=None, **overrides) -> QualityInspectionEngine:
    return QualityInspectionEngine(_settings(**overrides), model)


def _load(engine: QualityInspectionEngine, profile, regions=None, categories=None, associations=None) -> None:
    engine.set_profiles(
        "cam-01",
        [profile],
        regions or [],
        categories or [],
        associations or {},
    )


def test_pass_with_no_observations() -> None:
    model = FixtureInspectionModel(observations=[])
    engine = _engine(model)
    profile = make_profile()
    _load(engine, profile, categories=[make_category()])
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.PASS
    assert result.observations == []
    assert result.error_code is None
    assert result.regions_evaluated == ["full_frame"]


def test_fail_with_high_confidence_defect() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.97)])
    engine = _engine(model)
    profile = make_profile()
    category = make_category()
    _load(engine, profile, categories=[category])
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.FAIL
    assert len(result.observations) == 1
    assert result.observations[0].defect_code == "CRACK"
    assert result.observations[0].severity is DefectSeverity.HIGH
    assert result.severity is DefectSeverity.HIGH


def test_review_with_mid_confidence_defect() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="SCRATCH", box=_BOX, confidence=0.62)])
    engine = _engine(model)
    profile = make_profile()
    category = make_category(code="SCRATCH", name="Scratch", severity=DefectSeverity.MEDIUM)
    _load(engine, profile, categories=[category])
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.REVIEW


def test_error_when_no_model_configured() -> None:
    engine = _engine(None)
    profile = make_profile()
    _load(engine, profile)
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.ERROR
    assert result.error_code == "INSPECTION_MODEL_NOT_CONFIGURED"
    assert "INSPECTION_MODEL_NOT_CONFIGURED" in result.decision_reason
    assert result.model_name is None
    assert result.observations == []
    # An honest QUALITY_ERROR event exists — never a silent PASS.
    events = engine.active_events("cam-01")
    assert any(e.event_type is QualityEventType.QUALITY_ERROR for e in events)


def test_error_when_model_raises() -> None:
    model = FixtureInspectionModel(error_code=InspectionErrorCode.INSPECTION_MODEL_ERROR)
    engine = _engine(model)
    profile = make_profile()
    _load(engine, profile)
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.ERROR
    assert result.error_code == "INSPECTION_MODEL_ERROR"


def test_error_when_quality_disabled() -> None:
    model = FixtureInspectionModel(observations=[])
    engine = _engine(model, quality_enabled=False)
    profile = make_profile()
    _load(engine, profile)
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.ERROR
    assert result.error_code == "INSPECTION_CONFIG_INVALID"


def test_region_extraction_and_mapping() -> None:
    model = FixtureInspectionModel(
        observations=[RawDefect(code="CRACK", box=(0.0, 0.0, 320.0, 240.0), confidence=0.9)]
    )
    engine = _engine(model)
    profile = make_profile()
    region = make_region(geometry={"x": 0.25, "y": 0.25, "width": 0.5, "height": 0.5})
    _load(engine, profile, regions=[region], categories=[make_category()])
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.FAIL
    assert result.regions_evaluated == ["region-01"]
    box = result.observations[0].bounding_box
    assert box is not None
    # The ROI box maps back to the region bounds in full-frame normalized space.
    assert box[0] == pytest.approx(0.25)
    assert box[1] == pytest.approx(0.25)
    assert box[2] == pytest.approx(0.75)
    assert box[3] == pytest.approx(0.75)
    assert result.observations[0].region_id == "region-01"


def test_disabled_region_is_not_inspected() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.9)])
    engine = _engine(model)
    profile = make_profile()
    region = make_region(enabled=False)
    _load(engine, profile, regions=[region], categories=[make_category()])
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    # The disabled region is skipped; the full frame is inspected instead.
    assert result.regions_evaluated == ["full_frame"]


def test_multiple_observations_and_defect_events() -> None:
    model = FixtureInspectionModel(
        observations=[
            RawDefect(code="CRACK", box=_BOX, confidence=0.97),
            RawDefect(code="SCRATCH", box=_BOX, confidence=0.5, class_name="Scratch"),
        ]
    )
    engine = _engine(model)
    profile = make_profile()
    categories = [
        make_category(),
        make_category(
            defect_id="cat-scratch", code="SCRATCH", name="Scratch", severity=DefectSeverity.MEDIUM
        ),
    ]
    _load(engine, profile, categories=categories)
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.FAIL
    assert len(result.observations) == 2
    defect_events = [
        e for e in engine.active_events("cam-01") if e.event_type is QualityEventType.DEFECT_DETECTED
    ]
    assert len(defect_events) == 2
    codes = {e.defect_code for e in defect_events}
    assert codes == {"CRACK", "SCRATCH"}


def test_event_continuity_no_per_frame_spam() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.97)])
    engine = _engine(model)
    profile = make_profile()
    _load(engine, profile, categories=[make_category()])
    for i in range(10):
        result = engine.inspect("cam-01", profile, _frame(), utc(i * 0.5), None)
        assert result.decision is QualityDecision.FAIL
    fail_events = [e for e in engine.active_events("cam-01") if e.event_type is QualityEventType.QUALITY_FAIL]
    assert len(fail_events) == 1
    assert fail_events[0].duration_ms == pytest.approx(4500.0, abs=1.0)


def test_grace_resolution_after_pass() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.97)])
    engine = _engine(model, quality_event_resolution_grace_seconds=2.0)
    profile = make_profile()
    _load(engine, profile, categories=[make_category()])
    engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert len(engine.active_events("cam-01")) == 2  # FAIL + DEFECT_DETECTED
    # A PASS well past the grace period resolves both.
    model._observations = []
    engine.inspect("cam-01", profile, _frame(), utc(10), None)
    assert engine.active_events("cam-01") == []
    recent = engine.recent_events("cam-01", 10)
    assert all(e.status.value == "RESOLVED" for e in recent)


def test_per_camera_isolation() -> None:
    model = FixtureInspectionModel(observations=[])
    engine = _engine(model)
    profile_a = make_profile(profile_id="p-a", camera_id="cam-a")
    profile_b = make_profile(profile_id="p-b", camera_id="cam-b")
    engine.set_profiles("cam-a", [profile_a], [], [], {})
    engine.set_profiles("cam-b", [profile_b], [], [], {})
    engine.inspect("cam-a", profile_a, _frame(), utc(0), None)
    assert engine.session("cam-a", "p-a") is not None
    assert engine.session("cam-b", "p-b") is None
    assert engine.latest_result("cam-b") is None


def test_disabled_profile_is_not_inspected() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.97)])
    engine = _engine(model)
    profile = make_profile(enabled=False)
    _load(engine, profile, categories=[make_category()])
    results = engine.process("cam-01", _frame(), utc(0), None)
    assert results == []


def test_unknown_defect_code_maps_to_placeholder() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="MYSTERY", box=_BOX, confidence=0.9)])
    engine = _engine(model)
    profile = make_profile()
    _load(engine, profile, categories=[make_category()])
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.observations[0].defect_code == "MYSTERY"
    assert result.observations[0].defect_name == "Mystery (uncatalogued)"


def test_category_association_filters_observations() -> None:
    model = FixtureInspectionModel(
        observations=[
            RawDefect(code="CRACK", box=_BOX, confidence=0.9),
            RawDefect(code="SCRATCH", box=_BOX, confidence=0.9),
        ]
    )
    engine = _engine(model)
    profile = make_profile()
    categories = [make_category(), make_category(defect_id="cat-scratch", code="SCRATCH", name="Scratch")]
    # Profile associates only CRACK.
    associations = {
        "profile-01": {
            "CRACK": ProfileDefectCategory(
                profile_id="profile-01",
                defect_category_id="cat-crack",
                defect_code="CRACK",
                enabled=True,
            )
        }
    }
    _load(engine, profile, categories=categories, associations=associations)
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert [o.defect_code for o in result.observations] == ["CRACK"]


def test_observation_cap_is_bounded() -> None:
    observations = [RawDefect(code=f"D{i}", box=_BOX, confidence=0.9) for i in range(80)]
    model = FixtureInspectionModel(observations=observations)
    engine = _engine(model, quality_max_observations_per_inspection=10)
    profile = make_profile()
    _load(engine, profile)
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert len(result.observations) == 10


def test_session_counters_track_decisions() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.97)])
    engine = _engine(model)
    profile = make_profile()
    _load(engine, profile, categories=[make_category()])
    engine.inspect("cam-01", profile, _frame(), utc(0), None)
    model._observations = []
    engine.inspect("cam-01", profile, _frame(), utc(1), None)
    session = engine.session("cam-01", "profile-01")
    assert session is not None
    assert session.inspection_count == 2
    assert session.fail_count == 1
    assert session.pass_count == 1


def test_status_reports_model_and_counters() -> None:
    model = FixtureInspectionModel(observations=[])
    engine = _engine(model)
    profile = make_profile()
    _load(engine, profile)
    engine.inspect("cam-01", profile, _frame(), utc(0), None)
    status = engine.status()
    assert status["engine_status"] == "READY"
    assert status["model_status"] == "READY"
    assert status["model_name"] == "fixture-inspection"
    assert status["inspection_count"] == 1
    assert status["pass_count"] == 1
    assert status["cameras"]["cam-01"]["profiles"] == 1


def test_status_reports_not_configured_without_model() -> None:
    engine = _engine(None)
    status = engine.status()
    assert status["model_status"] == "NOT_CONFIGURED"
    assert status["model_name"] is None


def test_suppress_moves_event_to_recent() -> None:
    model = FixtureInspectionModel(observations=[RawDefect(code="CRACK", box=_BOX, confidence=0.97)])
    engine = _engine(model)
    profile = make_profile()
    _load(engine, profile, categories=[make_category()])
    engine.inspect("cam-01", profile, _frame(), utc(0), None)
    # One FAIL inspection produces a QUALITY_FAIL decision event plus a
    # DEFECT_DETECTED event for the CRACK observation.
    assert len(engine.active_events("cam-01")) == 2
    for event in list(engine.active_events("cam-01")):
        status = engine.suppress("cam-01", str(event.event_id))
        assert status.value == "SUPPRESSED"
    assert engine.active_events("cam-01") == []
    with pytest.raises(ValueError):
        engine.suppress("cam-01", str(event.event_id))


def test_reset_camera_clears_state() -> None:
    model = FixtureInspectionModel(observations=[])
    engine = _engine(model)
    profile = make_profile()
    _load(engine, profile)
    engine.inspect("cam-01", profile, _frame(), utc(0), None)
    engine.reset_camera("cam-01")
    assert engine.latest_result("cam-01") is None
    assert engine.status()["cameras"] == {}


def test_polygon_region_is_supported() -> None:
    model = FixtureInspectionModel(
        observations=[RawDefect(code="CRACK", box=(0.0, 0.0, 50.0, 50.0), confidence=0.9)]
    )
    engine = _engine(model)
    profile = make_profile()
    region = make_region(
        region_type=RegionType.POLYGON,
        geometry={
            "points": [
                {"x": 0.0, "y": 0.0},
                {"x": 0.5, "y": 0.0},
                {"x": 0.5, "y": 0.5},
                {"x": 0.0, "y": 0.5},
            ]
        },
    )
    _load(engine, profile, regions=[region], categories=[make_category()])
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.regions_evaluated == ["region-01"]
    assert result.observations[0].bounding_box is not None


def test_required_region_missing_evidence_reviews() -> None:
    model = FixtureInspectionModel(observations=[])
    engine = _engine(model)
    profile = make_profile(decision_policy=make_policy(required_region_ids=["region-01", "region-02"]))
    _load(engine, profile, regions=[make_region(region_id="region-01")])
    result = engine.inspect("cam-01", profile, _frame(), utc(0), None)
    assert result.decision is QualityDecision.REVIEW
    assert "region-02" in result.decision_reason
