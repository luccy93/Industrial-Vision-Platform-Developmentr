"""Decision policy tests — PASS/FAIL/REVIEW precedence, boundaries, missing evidence."""

from __future__ import annotations

from backend.app.quality.policy import decide, effective_thresholds
from backend.app.quality.schemas import DefectSeverity, MissingEvidenceBehavior, QualityDecision
from backend.tests.quality_helpers import make_category, make_observation, make_policy


def test_no_observations_passes() -> None:
    decision, reason, severity, evidence = decide([], make_policy(), [])
    assert decision is QualityDecision.PASS
    assert "no qualifying defects" in reason
    assert severity is DefectSeverity.INFO
    assert evidence == {"observation_count": 0}


def test_high_confidence_fail_defect_fails() -> None:
    observation = make_observation(confidence=0.97, severity=DefectSeverity.HIGH)
    decision, reason, severity, _ = decide([observation], make_policy(), ["region-01"])
    assert decision is QualityDecision.FAIL
    assert "CRACK" in reason and "0.97" in reason
    assert severity is DefectSeverity.HIGH


def test_review_range_defect_reviews() -> None:
    observation = make_observation(
        defect_code="SCRATCH", defect_name="Scratch", confidence=0.62, severity=DefectSeverity.MEDIUM
    )
    decision, reason, severity, _ = decide([observation], make_policy(), ["region-01"])
    assert decision is QualityDecision.REVIEW
    assert "review threshold" in reason
    assert severity is DefectSeverity.MEDIUM


def test_boundary_values() -> None:
    # Exactly at the fail threshold -> FAIL (>=).
    at_fail = make_observation(confidence=0.6, severity=DefectSeverity.HIGH)
    assert decide([at_fail], make_policy(), ["region-01"])[0] is QualityDecision.FAIL
    # Just below the fail threshold, at/above review -> REVIEW.
    below_fail = make_observation(
        defect_code="SCRATCH", defect_name="Scratch", confidence=0.599, severity=DefectSeverity.MEDIUM
    )
    assert decide([below_fail], make_policy(), ["region-01"])[0] is QualityDecision.REVIEW
    # Exactly at the review threshold -> REVIEW (>=).
    at_review = make_observation(
        defect_code="SCRATCH", defect_name="Scratch", confidence=0.35, severity=DefectSeverity.MEDIUM
    )
    assert decide([at_review], make_policy(), ["region-01"])[0] is QualityDecision.REVIEW
    # Below the review threshold -> PASS (informational only).
    below_review = make_observation(
        defect_code="SCRATCH", defect_name="Scratch", confidence=0.34, severity=DefectSeverity.MEDIUM
    )
    decision, reason, _, _ = decide([below_review], make_policy(), ["region-01"])
    assert decision is QualityDecision.PASS
    assert "below review threshold" in reason


def test_severity_gating() -> None:
    # High confidence but a non-fail severity is REVIEW evidence, never PASS.
    low = make_observation(confidence=0.99, severity=DefectSeverity.LOW)
    decision, reason, severity, _ = decide([low], make_policy(), ["region-01"])
    assert decision is QualityDecision.REVIEW
    assert severity is DefectSeverity.LOW
    # Below the review threshold the same observation is informational only.
    quiet = make_observation(confidence=0.2, severity=DefectSeverity.LOW)
    assert decide([quiet], make_policy(), ["region-01"])[0] is QualityDecision.PASS


def test_fail_severity_list_is_configurable() -> None:
    policy = make_policy(fail_severities=[DefectSeverity.CRITICAL])
    # HIGH at 0.99 is not a fail severity here, but it is still REVIEW evidence.
    high = make_observation(confidence=0.99, severity=DefectSeverity.HIGH)
    assert decide([high], policy, ["region-01"])[0] is QualityDecision.REVIEW
    critical = make_observation(confidence=0.99, severity=DefectSeverity.CRITICAL)
    assert decide([critical], policy, ["region-01"])[0] is QualityDecision.FAIL


def test_missing_required_region_defaults_to_review() -> None:
    policy = make_policy(required_region_ids=["region-01", "region-02"])
    decision, reason, _, evidence = decide([], policy, ["region-01"])
    assert decision is QualityDecision.REVIEW
    assert "region-02" in reason
    assert evidence["missing_regions"] == ["region-02"]


def test_missing_required_region_can_fail_or_ignore() -> None:
    # No observations at all; only the missing required region decides.
    fail_policy = make_policy(
        required_region_ids=["region-01", "region-02"],
        missing_evidence_behavior=MissingEvidenceBehavior.FAIL,
    )
    assert decide([], fail_policy, ["region-01"])[0] is QualityDecision.FAIL
    ignore_policy = make_policy(
        required_region_ids=["region-01", "region-02"],
        missing_evidence_behavior=MissingEvidenceBehavior.IGNORE,
    )
    assert decide([], ignore_policy, ["region-01"])[0] is QualityDecision.PASS


def test_fail_outranks_missing_evidence_review() -> None:
    policy = make_policy(required_region_ids=["region-01", "region-02"])
    observation = make_observation(confidence=0.99, severity=DefectSeverity.CRITICAL, region_id="region-01")
    assert decide([observation], policy, ["region-01"])[0] is QualityDecision.FAIL


def test_strongest_observation_wins() -> None:
    weak = make_observation(
        defect_code="SCRATCH", defect_name="Scratch", confidence=0.5, severity=DefectSeverity.MEDIUM
    )
    strong = make_observation(confidence=0.95, severity=DefectSeverity.CRITICAL)
    decision, reason, severity, _ = decide([weak, strong], make_policy(), ["region-01"])
    assert decision is QualityDecision.FAIL
    assert severity is DefectSeverity.CRITICAL
    assert "CRACK" in reason


def test_effective_thresholds_with_overrides() -> None:
    category = make_category(confidence_threshold=0.7, review_threshold=0.4)
    assert effective_thresholds(category, None) == (0.7, 0.4)
    from backend.app.quality.schemas import ProfileDefectCategory

    association = ProfileDefectCategory(
        profile_id="profile-01",
        defect_category_id="cat-crack",
        defect_code="CRACK",
        override_confidence_threshold=0.9,
        override_review_threshold=0.5,
    )
    assert effective_thresholds(category, association) == (0.9, 0.5)
    # An override never lets review exceed confidence.
    clamped = ProfileDefectCategory(
        profile_id="profile-01",
        defect_category_id="cat-crack",
        defect_code="CRACK",
        override_confidence_threshold=0.5,
        override_review_threshold=0.9,
    )
    assert effective_thresholds(category, clamped) == (0.5, 0.5)
