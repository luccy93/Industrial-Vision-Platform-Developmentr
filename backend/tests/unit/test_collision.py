"""Collision-risk tests — pairs, TTC guards, thresholds, continuity identity."""

from __future__ import annotations

from backend.app.autonomous.collision import CollisionRiskEngine, canonical_pair
from backend.app.autonomous.schemas import RiskLevel
from backend.tests.autonomous_helpers import utc


def _engine(**overrides) -> CollisionRiskEngine:
    return CollisionRiskEngine(**overrides)


def test_canonical_pair_ordering() -> None:
    assert canonical_pair("track-2", "track-10") == ("track-10", "track-2")
    assert canonical_pair("track-1", "track-2") == ("track-1", "track-2")
    assert canonical_pair("b", "a") == ("a", "b")


def test_approaching_objects_produce_risk_and_ttc() -> None:
    engine = _engine()
    risk = engine.assess_pair(
        "track-1",
        "track-2",
        (0.3, 0.5),
        (0.7, 0.5),
        (0.2, 0.0),
        (-0.2, 0.0),
        0.6,
        0.5,
        True,
        True,
        utc(0),
    )
    assert risk.object_ids == ["track-1", "track-2"]
    assert risk.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
    assert risk.risk_score > 0.0
    # Separation 0.4, closing 0.4 units/s → TTC 1.0s.
    assert risk.time_to_collision == 1.0
    assert risk.confidence > 0.0
    assert "approach" in risk.reason


def test_separating_objects_are_none() -> None:
    engine = _engine()
    risk = engine.assess_pair(
        "track-1",
        "track-2",
        (0.3, 0.5),
        (0.7, 0.5),
        (-0.2, 0.0),
        (0.2, 0.0),
        None,
        None,
        True,
        True,
        utc(0),
    )
    assert risk.risk_level is RiskLevel.NONE
    assert risk.risk_score == 0.0
    assert risk.time_to_collision is None
    assert "separating" in risk.reason


def test_stationary_objects_are_none() -> None:
    engine = _engine()
    risk = engine.assess_pair(
        "track-1", "track-2", (0.3, 0.5), (0.7, 0.5), (0.0, 0.0), (0.0, 0.0),
        None, None, True, True, utc(0),
    )
    assert risk.risk_level is RiskLevel.NONE
    assert risk.time_to_collision is None


def test_missing_velocity_is_unknown() -> None:
    engine = _engine()
    risk = engine.assess_pair(
        "track-1", "track-2", (0.3, 0.5), (0.7, 0.5), None, (-0.2, 0.0),
        None, None, True, True, utc(0),
    )
    assert risk.risk_level is RiskLevel.UNKNOWN
    assert risk.time_to_collision is None


def test_missing_position_is_unknown() -> None:
    engine = _engine()
    risk = engine.assess_pair(
        "track-1", "track-2", None, (0.7, 0.5), (0.2, 0.0), (-0.2, 0.0),
        None, None, True, True, utc(0),
    )
    assert risk.risk_level is RiskLevel.UNKNOWN


def test_missing_depth_still_assesses() -> None:
    engine = _engine()
    risk = engine.assess_pair(
        "track-1", "track-2", (0.3, 0.5), (0.7, 0.5), (0.2, 0.0), (-0.2, 0.0),
        None, None, True, True, utc(0),
    )
    assert risk.risk_level is not RiskLevel.UNKNOWN
    assert risk.time_to_collision == 1.0
    assert risk.confidence < 0.7  # no depth evidence lowers confidence


def test_zero_relative_velocity_is_none_not_division_error() -> None:
    engine = _engine()
    risk = engine.assess_pair(
        "track-1", "track-2", (0.3, 0.5), (0.3, 0.5), (0.1, 0.0), (0.1, 0.0),
        None, None, True, True, utc(0),
    )
    assert risk.risk_level is RiskLevel.NONE
    assert risk.time_to_collision is None


def test_risk_bands_and_threshold() -> None:
    gentle = _engine()
    mild = gentle.assess_pair(
        "a", "b", (0.1, 0.5), (0.9, 0.5), (0.01, 0.0), (-0.01, 0.0),
        None, None, True, True, utc(0),
    )
    assert mild.risk_level is RiskLevel.LOW
    assert mild.risk_score < 0.5


def test_non_finite_inputs_are_unknown() -> None:
    import math

    engine = _engine()
    risk = engine.assess_pair(
        "a", "b", (math.nan, 0.5), (0.7, 0.5), (0.2, 0.0), (-0.2, 0.0),
        None, None, True, True, utc(0),
    )
    assert risk.risk_level is RiskLevel.UNKNOWN
