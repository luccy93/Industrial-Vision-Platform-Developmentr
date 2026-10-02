"""Decision policy — pure functions turning observations into decisions.

The policy is deliberately free of engine, frame, and model concerns so the
PASS/FAIL/REVIEW logic can be unit-tested against exact boundary values.
"""

from __future__ import annotations

from backend.app.quality.schemas import (
    DecisionPolicy,
    DefectCategory,
    DefectObservation,
    DefectSeverity,
    MissingEvidenceBehavior,
    ProfileDefectCategory,
    QualityDecision,
)

_SEVERITY_RANK: dict[DefectSeverity, int] = {
    DefectSeverity.INFO: 0,
    DefectSeverity.LOW: 1,
    DefectSeverity.MEDIUM: 2,
    DefectSeverity.HIGH: 3,
    DefectSeverity.CRITICAL: 4,
}


def effective_thresholds(
    category: DefectCategory,
    association: ProfileDefectCategory | None,
) -> tuple[float, float]:
    """(confidence, review) thresholds for one category under one profile.

    Profile-level overrides win over the catalog defaults; an override is only
    applied when it keeps review <= confidence.
    """
    confidence = category.confidence_threshold
    review = category.review_threshold
    if association is not None:
        if association.override_confidence_threshold is not None:
            confidence = association.override_confidence_threshold
        if association.override_review_threshold is not None:
            review = association.override_review_threshold
    return confidence, min(review, confidence)


def decide(
    observations: list[DefectObservation],
    policy: DecisionPolicy,
    regions_evaluated: list[str],
) -> tuple[QualityDecision, str, DefectSeverity, dict]:
    """Return ``(decision, reason, severity, evidence)`` for one inspection.

    Required regions are read from the policy itself, so a policy object is
    the single source of truth for one inspection.

    Precedence: FAIL (defect or missing required evidence) > REVIEW (defect or
    missing required evidence) > PASS. A defect qualifies as FAIL at/above the
    fail threshold when its severity is in ``fail_severities``; any other
    observation at/above the review threshold is REVIEW evidence. Observations
    below the review threshold never qualify — they are reported in the PASS
    reason for transparency.
    """
    required = list(policy.required_region_ids)
    evaluated = set(regions_evaluated or [])
    missing = [region for region in required if region not in evaluated]

    fail_candidates = [
        o
        for o in observations
        if o.confidence >= policy.fail_threshold and o.severity in policy.fail_severities
    ]
    if fail_candidates:
        best = max(fail_candidates, key=lambda o: (o.confidence, _SEVERITY_RANK[o.severity]))
        return (
            QualityDecision.FAIL,
            f"FAIL: {best.severity.value} severity {best.defect_code} observation "
            f"(confidence {best.confidence:.2f}) exceeded fail threshold {policy.fail_threshold:.2f}",
            best.severity,
            {
                "defect_code": best.defect_code,
                "confidence": best.confidence,
                "region_id": best.region_id,
            },
        )

    if missing and policy.missing_evidence_behavior is MissingEvidenceBehavior.FAIL:
        return (
            QualityDecision.FAIL,
            f"FAIL: required region(s) {', '.join(missing)} produced no evidence",
            DefectSeverity.HIGH,
            {"missing_regions": missing},
        )

    review_candidates = [o for o in observations if o.confidence >= policy.review_threshold]
    if review_candidates:
        best = max(review_candidates, key=lambda o: (o.confidence, _SEVERITY_RANK[o.severity]))
        return (
            QualityDecision.REVIEW,
            f"REVIEW: {best.severity.value} severity {best.defect_code} observation "
            f"(confidence {best.confidence:.2f}) at/above review threshold "
            f"{policy.review_threshold:.2f} without meeting fail criteria",
            best.severity,
            {
                "defect_code": best.defect_code,
                "confidence": best.confidence,
                "region_id": best.region_id,
            },
        )

    if missing and policy.missing_evidence_behavior is MissingEvidenceBehavior.REVIEW:
        return (
            QualityDecision.REVIEW,
            f"REVIEW: required region(s) {', '.join(missing)} produced no evidence",
            DefectSeverity.MEDIUM,
            {"missing_regions": missing},
        )

    if observations:
        return (
            QualityDecision.PASS,
            f"PASS: configured inspection completed; {len(observations)} observation(s) "
            "below review threshold",
            DefectSeverity.INFO,
            {"observation_count": len(observations)},
        )

    return (
        QualityDecision.PASS,
        "PASS: configured inspection completed; no qualifying defects",
        DefectSeverity.INFO,
        {"observation_count": 0},
    )
