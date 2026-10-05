"""Risk engine tests — determinism, clamping, factors, boundaries, priority."""

from __future__ import annotations

import pytest

from backend.app.intelligence.risk import RiskEngine, max_priority, max_risk_level, priority_for
from backend.app.intelligence.schemas import (
    EventPriority,
    RiskLevel,
    UnifiedSeverity,
)
from backend.tests.intelligence_helpers import make_unified_event, utc


def _engine(**overrides) -> RiskEngine:
    params = {
        "low_threshold": 0.20,
        "medium_threshold": 0.40,
        "high_threshold": 0.65,
        "critical_threshold": 0.85,
    }
    params.update(overrides)
    return RiskEngine(**params)


def test_threshold_validation() -> None:
    with pytest.raises(ValueError):
        RiskEngine(low_threshold=0.5, medium_threshold=0.4, high_threshold=0.65, critical_threshold=0.85)
    with pytest.raises(ValueError):
        RiskEngine(low_threshold=0.2, medium_threshold=0.2, high_threshold=0.65, critical_threshold=0.85)
    with pytest.raises(ValueError):
        RiskEngine(low_threshold=-0.1, medium_threshold=0.4, high_threshold=0.65, critical_threshold=0.85)
    with pytest.raises(ValueError):
        RiskEngine(
            low_threshold=0.2,
            medium_threshold=0.4,
            high_threshold=0.65,
            critical_threshold=0.85,
            severity_weight=1.5,
        )
    RiskEngine()  # defaults valid


def test_from_settings() -> None:
    from backend.app.core.config import Settings

    engine = RiskEngine.from_settings(Settings(_env_file=None))  # type: ignore[call-arg]
    assert engine.low_threshold == 0.20
    assert engine.critical_threshold == 0.85


def test_level_boundaries() -> None:
    engine = _engine()
    assert engine.level_for_score(0.0) is RiskLevel.NONE
    assert engine.level_for_score(0.199) is RiskLevel.NONE
    assert engine.level_for_score(0.20) is RiskLevel.LOW
    assert engine.level_for_score(0.399) is RiskLevel.LOW
    assert engine.level_for_score(0.40) is RiskLevel.MEDIUM
    assert engine.level_for_score(0.649) is RiskLevel.MEDIUM
    assert engine.level_for_score(0.65) is RiskLevel.HIGH
    assert engine.level_for_score(0.849) is RiskLevel.HIGH
    assert engine.level_for_score(0.85) is RiskLevel.CRITICAL
    assert engine.level_for_score(1.0) is RiskLevel.CRITICAL


def test_deterministic_scores() -> None:
    engine = _engine()
    event = make_unified_event()
    first = engine.assess_event(event, timestamp=utc(30))
    second = engine.assess_event(event, timestamp=utc(30))
    assert first.risk_score == second.risk_score
    assert first.risk_level == second.risk_level
    assert len(first.factors) == 5


def test_score_clamped() -> None:
    engine = _engine()
    event = make_unified_event(severity=UnifiedSeverity.CRITICAL, confidence=1.0)
    assessment = engine.assess_event(event, member_count=99, timestamp=utc(3600))
    assert 0.0 <= assessment.risk_score <= 1.0


def test_severity_contribution() -> None:
    engine = _engine()
    low = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.LOW, confidence=0.0), timestamp=utc(0)
    )
    critical = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.CRITICAL, confidence=0.0), timestamp=utc(0)
    )
    # base 0.10 + 0.35*rank (+0 persistence/correlation/confidence at age 0 solo)
    assert low.risk_score == pytest.approx(0.10 + 0.35 * 0.25)
    assert critical.risk_score == pytest.approx(0.10 + 0.35 * 1.0)
    assert critical.risk_score > low.risk_score


def test_persistence_contribution() -> None:
    engine = _engine()
    fresh = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.INFO, confidence=0.0), timestamp=utc(0)
    )
    aged = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.INFO, confidence=0.0), timestamp=utc(60)
    )
    assert aged.risk_score == pytest.approx(fresh.risk_score + 0.15)
    saturated = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.INFO, confidence=0.0), timestamp=utc(3600)
    )
    assert saturated.risk_score == pytest.approx(aged.risk_score)


def test_correlation_contribution() -> None:
    engine = _engine()
    solo = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.INFO, confidence=0.0),
        member_count=1,
        timestamp=utc(0),
    )
    assert solo.risk_score == pytest.approx(0.10)
    trio = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.INFO, confidence=0.0),
        member_count=3,
        timestamp=utc(0),
    )
    assert trio.risk_score == pytest.approx(0.10 + 0.25 * 0.5)


def test_confidence_contribution() -> None:
    engine = _engine()
    unsure = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.INFO, confidence=0.0), timestamp=utc(0)
    )
    sure = engine.assess_event(
        make_unified_event(severity=UnifiedSeverity.INFO, confidence=1.0), timestamp=utc(0)
    )
    assert sure.risk_score == pytest.approx(unsure.risk_score + 0.15)


def test_factors_explain_score() -> None:
    engine = _engine()
    assessment = engine.assess_event(make_unified_event(), timestamp=utc(0))
    names = [f.name for f in assessment.factors]
    assert names == ["base", "severity", "persistence", "correlation", "confidence"]
    total = assessment.factors[0].contribution + sum(f.contribution for f in assessment.factors[1:])
    assert assessment.risk_score == pytest.approx(min(1.0, total))
    assert all(f.reason for f in assessment.factors)
    assert assessment.reason


def test_cluster_scoring() -> None:
    engine = _engine()
    members = [
        make_unified_event(severity=UnifiedSeverity.MEDIUM, confidence=0.6),
        make_unified_event(severity=UnifiedSeverity.HIGH, confidence=0.8),
    ]
    assessment = engine.assess_cluster(members, utc(0), timestamp=utc(0))
    # Worst severity HIGH (0.75), mean confidence 0.7, 2 members → correlation 0.25*0.25
    assert assessment.risk_score == pytest.approx(0.10 + 0.35 * 0.75 + 0.25 * 0.25 + 0.15 * 0.7)
    assert assessment.risk_level is RiskLevel.MEDIUM


def test_empty_cluster_has_no_risk() -> None:
    assessment = _engine().assess_cluster([], utc(0), timestamp=utc(0))
    assert assessment.risk_score == 0.0
    assert assessment.risk_level is RiskLevel.NONE


def test_priority_mapping() -> None:
    assert priority_for(RiskLevel.NONE, UnifiedSeverity.INFO) is EventPriority.P4
    assert priority_for(RiskLevel.LOW, UnifiedSeverity.LOW) is EventPriority.P3
    assert priority_for(RiskLevel.MEDIUM, UnifiedSeverity.MEDIUM) is EventPriority.P2
    assert priority_for(RiskLevel.HIGH, UnifiedSeverity.HIGH) is EventPriority.P1
    assert priority_for(RiskLevel.CRITICAL, UnifiedSeverity.CRITICAL) is EventPriority.P0
    assert priority_for(RiskLevel.UNKNOWN, UnifiedSeverity.INFO) is EventPriority.P3


def test_severity_floor_bumps_priority() -> None:
    # Severe-but-uncertain signals are never buried at P4/P3.
    assert priority_for(RiskLevel.NONE, UnifiedSeverity.CRITICAL) is EventPriority.P3
    assert priority_for(RiskLevel.LOW, UnifiedSeverity.HIGH) is EventPriority.P2
    # Already-urgent priorities are untouched.
    assert priority_for(RiskLevel.HIGH, UnifiedSeverity.CRITICAL) is EventPriority.P1
    assert priority_for(RiskLevel.CRITICAL, UnifiedSeverity.HIGH) is EventPriority.P0


def test_max_helpers() -> None:
    assert max_priority(EventPriority.P4, EventPriority.P1) is EventPriority.P1
    assert max_priority(EventPriority.P0, EventPriority.P2) is EventPriority.P0
    assert max_risk_level(RiskLevel.LOW, RiskLevel.HIGH) is RiskLevel.HIGH
    assert max_risk_level(RiskLevel.UNKNOWN, RiskLevel.LOW) is RiskLevel.LOW
    assert max_risk_level(RiskLevel.UNKNOWN, RiskLevel.UNKNOWN) is RiskLevel.UNKNOWN
