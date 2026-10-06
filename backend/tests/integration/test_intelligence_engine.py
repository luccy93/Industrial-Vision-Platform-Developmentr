"""Intelligence engine tests — real domain engines, scenarios A–E, lifecycle."""

from __future__ import annotations

from typing import Any

from backend.app.autonomous.engine import AutonomousPerceptionEngine
from backend.app.core.config import Settings
from backend.app.domain.frame import IngestionFrame
from backend.app.intelligence.engine import IntelligenceEngine
from backend.app.intelligence.schemas import EventPriority, RiskLevel
from backend.app.quality.engine import QualityInspectionEngine
from backend.app.quality.fixture import FixtureInspectionModel
from backend.app.quality.inspection import RawDefect
from backend.app.safety.base import EventDraft, SafetyRule, SceneState
from backend.app.safety.engine import SafetyEngine
from backend.app.safety.schemas import SafetyEventType, SafetySeverity
from backend.tests.intelligence_helpers import utc
from backend.tests.quality_helpers import make_category, make_profile, make_region, synthetic_frame
from backend.tests.safety_helpers import make_track


class StubRule(SafetyRule):
    active: bool

    def __init__(self, name: str, event_type: SafetyEventType, severity: SafetySeverity) -> None:
        super().__init__(name, enabled=True)
        self._event_type = event_type
        self._severity = severity
        self.active = True

    @property
    def event_type(self) -> SafetyEventType:
        return self._event_type

    def evaluate(self, scene: SceneState) -> list[EventDraft]:
        if not self.active:
            return []
        return [
            EventDraft(
                dedupe_key=f"stub:{scene.camera_id}:{self.name}",
                event_type=self._event_type,
                severity=self._severity,
                track_ids=[t.track_id for t in scene.tracks],
                confidence=0.7,
                message="stub",
                evidence={},
            )
        ]


def _settings(**overrides: Any) -> Settings:
    params: dict[str, Any] = {
        "safety_event_resolution_grace_seconds": 30.0,
        "quality_event_resolution_grace_seconds": 30.0,
    }
    params.update(overrides)
    return Settings(_env_file=None, **params)  # type: ignore[call-arg]


def _safety(rule_name: str = "stub", severity: SafetySeverity = SafetySeverity.MEDIUM) -> SafetyEngine:
    engine = SafetyEngine(_settings(), [StubRule(rule_name, SafetyEventType.CROWD_WARNING, severity)])
    engine.process("cam-01", [], utc(0))
    return engine


def _frame() -> IngestionFrame:
    return IngestionFrame(camera_id="cam-01", frame_number=1, width=640, height=480, image=synthetic_frame())


def _quality(defect: bool = True) -> QualityInspectionEngine:
    observations = [RawDefect(code="CRACK", box=(10.0, 10.0, 100.0, 100.0), confidence=0.9)] if defect else []
    engine = QualityInspectionEngine(_settings(), FixtureInspectionModel(observations=observations))
    engine.set_profiles(
        "cam-01",
        [make_profile()],
        [make_region()],
        [make_category()],
        {"profile-01": {}},
    )
    engine.inspect("cam-01", make_profile(), _frame(), utc(0), None)
    return engine


def _approaching_tracks() -> list:
    near = [(300.0 + i * 6.0, 200.0 + i * 10.0, 340.0 + i * 6.0, 260.0 + i * 10.0) for i in range(5)]
    far = [(420.0 - i * 8.0, 180.0, 470.0 - i * 8.0, 260.0) for i in range(5)]
    return [
        make_track(3, "car", near[-1], history_boxes=near, history_span_seconds=2.0),
        make_track(5, "car", far[-1], history_boxes=far, history_span_seconds=2.0),
    ]


def _auto(tracks: list | None = None) -> AutonomousPerceptionEngine:
    engine = AutonomousPerceptionEngine(_settings())
    engine.process("cam-01", tracks if tracks is not None else _approaching_tracks(), _frame(), utc(0), None)
    return engine


def _intel(
    safety: SafetyEngine | None = None,
    quality: QualityInspectionEngine | None = None,
    autonomous: AutonomousPerceptionEngine | None = None,
    **overrides: Any,
) -> IntelligenceEngine:
    return IntelligenceEngine(
        _settings(**overrides),
        safety_engine=safety,
        quality_engine=quality,
        autonomous_engine=autonomous,
    )


def test_empty_result_no_domains() -> None:
    result = _intel().process("cam-01", utc(0))
    assert result.active_event_count == 0
    assert result.active_cluster_count == 0
    assert result.highest_priority is EventPriority.P4
    assert result.highest_risk.risk_level is RiskLevel.UNKNOWN
    assert result.metrics["events_processed"] == 0


def test_disabled_engine_processes_nothing() -> None:
    engine = _intel(intelligence_enabled=False)
    result = engine.process("cam-01", utc(0))
    assert result.active_event_count == 0
    assert engine.latest("cam-01") is None


def test_unknown_camera_empty() -> None:
    engine = _intel(safety=_safety())
    result = engine.process("cam-99", utc(0))
    assert result.active_event_count == 0
    assert engine.active_events("cam-99") == []


def test_safety_ingest_creates_solo_cluster() -> None:
    engine = _intel(safety=_safety())
    result = engine.process("cam-01", utc(0))
    assert result.active_event_count == 1
    assert result.active_cluster_count == 1
    event = result.events[0]
    assert event.source_domain.value == "SAFETY"
    assert event.event_type.value == "CROWD_WARNING"
    assert event.track_ids == []
    cluster = result.clusters[0]
    assert cluster.event_count == 1
    assert cluster.source_domains == [event.source_domain]
    assert cluster.risk_assessment.factors
    # MEDIUM severity solo: 0.10 + 0.35*0.5 + 0 + 0 + 0.15*0.7 = 0.38 → LOW → P3.
    assert event.risk_score == 0.38
    assert event.priority is EventPriority.P3


def test_dedupe_updates_without_duplicates() -> None:
    safety = _safety()
    engine = _intel(safety=safety)
    engine.process("cam-01", utc(0))
    engine.process("cam-01", utc(1))
    assert len(engine.active_events("cam-01")) == 1
    state = engine._cameras["cam-01"]
    assert state.events_deduplicated >= 1
    assert state.events_normalized >= 2


def test_spatial_routing() -> None:
    safety = SafetyEngine(
        _settings(),
        [StubRule("restricted_zone", SafetyEventType.RESTRICTED_ZONE_ENTRY, SafetySeverity.HIGH)],
    )
    safety.process("cam-01", [], utc(0))
    engine = _intel(safety=safety)
    result = engine.process("cam-01", utc(0))
    assert result.events[0].source_domain.value == "SPATIAL"
    assert result.events[0].event_type.value == "RESTRICTED_ZONE_ENTRY"


def test_quality_ingest() -> None:
    engine = _intel(quality=_quality())
    result = engine.process("cam-01", utc(0))
    # QUALITY_FAIL (no region) + DEFECT_DETECTED (region-01) share neither
    # identity nor location, so they correctly stay in solo clusters.
    assert result.active_event_count == 2
    by_type = {e.event_type.value: e for e in result.events}
    assert set(by_type) == {"QUALITY_FAIL", "DEFECT_DETECTED"}
    assert by_type["DEFECT_DETECTED"].location == "region-01"
    assert by_type["DEFECT_DETECTED"].metadata["defect_code"] == "CRACK"
    assert all(e.source_domain.value == "QUALITY" for e in result.events)


def test_autonomous_ingest() -> None:
    engine = _intel(autonomous=_auto())
    result = engine.process("cam-01", utc(0))
    domains = {e.source_domain.value for e in result.events}
    assert domains == {"AUTONOMOUS"}
    assert all(e.object_ids for e in result.events)


def test_scenario_a_zone_plus_proximity_one_cluster() -> None:
    safety = SafetyEngine(
        _settings(),
        [
            StubRule("restricted_zone", SafetyEventType.RESTRICTED_ZONE_ENTRY, SafetySeverity.HIGH),
            StubRule("person_vehicle", SafetyEventType.PERSON_VEHICLE_PROXIMITY, SafetySeverity.HIGH),
        ],
    )
    track = make_track(7, "person", (100.0, 100.0, 150.0, 300.0))
    safety.process("cam-01", [track], utc(0))
    # Both stubs emit for track 7: shared identity must correlate them.
    engine = _intel(safety=safety)
    result = engine.process("cam-01", utc(0))
    assert result.active_event_count == 2
    assert result.active_cluster_count == 1
    cluster = result.clusters[0]
    assert cluster.event_count == 2
    assert sorted(d.value for d in cluster.source_domains) == ["SAFETY", "SPATIAL"]
    assert sorted(cluster.track_ids) == [7]
    # Corroboration escalates above either solo score.
    assert cluster.risk_assessment.risk_score > 0.5


def test_scenario_b_quality_only() -> None:
    engine = _intel(quality=_quality())
    result = engine.process("cam-01", utc(0))
    assert result.active_cluster_count == 2
    assert all(c.source_domains == [c.source_domains[0]] for c in result.clusters)
    assert {d.value for c in result.clusters for d in c.source_domains} == {"QUALITY"}


def test_scenario_c_autonomous_cluster() -> None:
    engine = _intel(autonomous=_auto())
    result = engine.process("cam-01", utc(0))
    assert result.active_cluster_count >= 1
    assert all(c.source_domains[0].value == "AUTONOMOUS" for c in result.clusters)


def test_scenario_d_separate_tracks_separate_clusters() -> None:
    safety = SafetyEngine(
        _settings(),
        [StubRule("stub", SafetyEventType.CROWD_WARNING, SafetySeverity.MEDIUM)],
    )
    safety.process("cam-01", [make_track(1, "person", (10.0, 10.0, 50.0, 50.0))], utc(0))
    engine = _intel(safety=safety)
    first = engine.process("cam-01", utc(0))
    assert first.active_cluster_count == 1
    # A second, unrelated track on the same camera must not merge.
    other_rule_engine = SafetyEngine(
        _settings(),
        [StubRule("stub2", SafetyEventType.PERSON_VEHICLE_PROXIMITY, SafetySeverity.HIGH)],
    )
    other_rule_engine.process("cam-01", [make_track(9, "car", (400.0, 100.0, 500.0, 300.0))], utc(0))
    engine2 = _intel(safety=other_rule_engine)
    second = engine2.process("cam-01", utc(0))
    assert second.active_cluster_count == 1
    assert second.clusters[0].track_ids == [9]


def test_scenario_e_shared_object_correlates_domains() -> None:
    quality = _quality()
    auto_engine = AutonomousPerceptionEngine(_settings())
    auto_engine.process("cam-01", _approaching_tracks(), _frame(), utc(0), None)
    engine = _intel(quality=quality, autonomous=auto_engine)
    result = engine.process("cam-01", utc(0))
    # Quality event has no track/object identity; autonomous approach events
    # carry object ids — without shared identity or location they stay split.
    by_domain: dict[str, int] = {}
    for cluster in result.clusters:
        for domain in cluster.source_domains:
            by_domain[domain.value] = by_domain.get(domain.value, 0) + 1
    assert by_domain.get("QUALITY", 0) == 2
    assert by_domain.get("AUTONOMOUS", 0) >= 1
    assert result.active_cluster_count >= 3


def test_escalation_ladder() -> None:
    safety = SafetyEngine(_settings(), [StubRule("stub", SafetyEventType.CROWD_WARNING, SafetySeverity.LOW)])
    safety.process("cam-01", [], utc(0))
    engine = _intel(safety=safety)
    solo = engine.process("cam-01", utc(0))
    solo_level = solo.clusters[0].risk_assessment.risk_level
    assert solo_level is RiskLevel.LOW
    # Corroborating second event on the same track escalates the cluster.
    safety._rules.append(
        StubRule("restricted_zone", SafetyEventType.RESTRICTED_ZONE_ENTRY, SafetySeverity.HIGH)
    )
    track = make_track(4, "person", (100.0, 100.0, 150.0, 300.0))
    safety.process("cam-01", [track], utc(1))
    together = engine.process("cam-01", utc(1))
    assert len(together.clusters) >= 1
    assert together.highest_risk.risk_score >= solo.highest_risk.risk_score


def test_deescalation_and_resolve() -> None:
    stub = StubRule("stub", SafetyEventType.CROWD_WARNING, SafetySeverity.HIGH)
    rule_engine = SafetyEngine(
        _settings(safety_event_resolution_grace_seconds=0.5),
        [stub],
    )
    rule_engine.process("cam-01", [], utc(0))
    engine = _intel(safety=rule_engine)
    first = engine.process("cam-01", utc(0))
    assert first.active_event_count == 1
    stub.active = False
    rule_engine.process("cam-01", [], utc(10))
    second = engine.process("cam-01", utc(10))
    assert second.active_event_count == 0
    assert engine.recent_events("cam-01")


def test_suppressed_mirror() -> None:
    safety = _safety()
    event_id = safety.active_events("cam-01")[0].event_id
    safety.suppress("cam-01", str(event_id))
    engine = _intel(safety=safety)
    result = engine.process("cam-01", utc(0))
    # Terminal source states finalize into the recent ring, never the active set.
    assert result.active_event_count == 0
    recent = engine.recent_events("cam-01")
    assert len(recent) == 1
    assert recent[0].status.value == "SUPPRESSED"


def test_multi_camera_isolation() -> None:
    engine = _intel(safety=_safety())
    engine.process("cam-01", utc(0))
    other = engine.process("cam-02", utc(0))
    assert other.active_event_count == 0
    assert engine.active_clusters("cam-01")
    assert engine.active_clusters("cam-02") == []


def test_missing_domains_degrade() -> None:
    engine = _intel(safety=_safety())
    status = engine.status()
    assert status["engine_status"] == "READY"
    assert status["domains"]["SAFETY"]["available"] is True
    assert status["domains"]["QUALITY"]["available"] is False
    assert status["domains"]["AUTONOMOUS"]["available"] is False
    assert status["domains"]["SPATIAL"]["available"] is True


def test_status_shape() -> None:
    engine = _intel(safety=_safety(), quality=_quality(), autonomous=_auto())
    result = engine.process("cam-01", utc(0))
    status = engine.status()
    assert status["engine_status"] == "READY"
    assert status["active_events"] == result.active_event_count >= 3
    assert status["active_clusters"] >= 1
    assert status["highest_priority"] in ("P0", "P1", "P2", "P3", "P4")
    assert set(status["metrics"]) == {
        "events_processed",
        "events_normalized",
        "events_deduplicated",
        "clusters_created",
        "clusters_resolved",
        "risk_updates",
        "processing_latency_ms",
    }
    assert status["configuration"]["risk_high_threshold"] == 0.65
    assert status["cameras"]["cam-01"]["active_events"] == result.active_event_count


def test_event_caps_bounded() -> None:
    settings = _settings(intelligence_max_events_per_camera=2, intelligence_max_clusters_per_camera=1)
    safety = SafetyEngine(
        settings,
        [
            StubRule("a", SafetyEventType.CROWD_WARNING, SafetySeverity.LOW),
            StubRule("b", SafetyEventType.PERSON_VEHICLE_PROXIMITY, SafetySeverity.LOW),
            StubRule("c", SafetyEventType.PROLONGED_STATIONARY, SafetySeverity.LOW),
        ],
    )
    safety.process("cam-01", [], utc(0))
    engine = IntelligenceEngine(settings, safety_engine=safety)
    result = engine.process("cam-01", utc(0))
    assert result.active_event_count <= 2
    assert result.active_cluster_count <= 1


def test_reset_camera() -> None:
    engine = _intel(safety=_safety())
    engine.process("cam-01", utc(0))
    engine.reset_camera("cam-01")
    assert engine.active_events("cam-01") == []
    assert engine.latest("cam-01") is None
