"""Deterministic risk scoring — pure functions, no I/O, no randomness.

Score formula (documented operational heuristic, not a probability)::

    score = clamp01(
        base
        + severity_weight      * severity_rank(severity)
        + persistence_weight   * min(1, age_seconds / 60)
        + correlation_weight   * min(1, (member_count - 1) / 4)
        + confidence_weight    * confidence
    )

With the default weights (0.10 + 0.35 + 0.15 + 0.25 + 0.15) the maximum is
exactly 1.0. Every assessment carries its named factors, so no score is ever
unexplained.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from backend.app.domain.common import utcnow
from backend.app.intelligence.schemas import (
    SEVERITY_RANK,
    EventPriority,
    RiskAssessment,
    RiskFactor,
    RiskLevel,
    UnifiedEvent,
    UnifiedSeverity,
)

_PRIORITY_BY_LEVEL: dict[RiskLevel, EventPriority] = {
    RiskLevel.NONE: EventPriority.P4,
    RiskLevel.LOW: EventPriority.P3,
    RiskLevel.MEDIUM: EventPriority.P2,
    RiskLevel.HIGH: EventPriority.P1,
    RiskLevel.CRITICAL: EventPriority.P0,
    RiskLevel.UNKNOWN: EventPriority.P3,
}

_PRIORITY_ORDER: list[EventPriority] = [
    EventPriority.P4,
    EventPriority.P3,
    EventPriority.P2,
    EventPriority.P1,
    EventPriority.P0,
]

_LEVEL_ORDER: list[RiskLevel] = [
    RiskLevel.NONE,
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
]


def _bump_priority(priority: EventPriority) -> EventPriority:
    index = _PRIORITY_ORDER.index(priority)
    return _PRIORITY_ORDER[min(len(_PRIORITY_ORDER) - 1, index + 1)]


def priority_for(risk_level: RiskLevel, severity: UnifiedSeverity) -> EventPriority:
    """Deterministic priority from risk level with a severity floor.

    Base priority comes from the risk level; HIGH/CRITICAL severity bumps an
    otherwise low priority one step toward P0 so severe-but-uncertain signals
    are never buried at P4.
    """
    priority = _PRIORITY_BY_LEVEL.get(risk_level, EventPriority.P3)
    if severity in (UnifiedSeverity.HIGH, UnifiedSeverity.CRITICAL) and priority in (
        EventPriority.P4,
        EventPriority.P3,
    ):
        priority = _bump_priority(priority)
    return priority


def max_priority(first: EventPriority, second: EventPriority) -> EventPriority:
    """The more urgent of two priorities (P0 is most urgent)."""
    if _PRIORITY_ORDER.index(first) >= _PRIORITY_ORDER.index(second):
        return first
    return second


def max_risk_level(first: RiskLevel, second: RiskLevel) -> RiskLevel:
    """The more severe of two risk levels (UNKNOWN never wins ties)."""
    if first is RiskLevel.UNKNOWN:
        return second
    if second is RiskLevel.UNKNOWN:
        return first
    if _LEVEL_ORDER.index(first) >= _LEVEL_ORDER.index(second):
        return first
    return second


class RiskEngine:
    """Pure deterministic scorer; thresholds and weights come from settings."""

    def __init__(
        self,
        *,
        low_threshold: float = 0.20,
        medium_threshold: float = 0.40,
        high_threshold: float = 0.65,
        critical_threshold: float = 0.85,
        base_score: float = 0.10,
        severity_weight: float = 0.35,
        persistence_weight: float = 0.15,
        correlation_weight: float = 0.25,
        confidence_weight: float = 0.15,
    ) -> None:
        thresholds = [low_threshold, medium_threshold, high_threshold, critical_threshold]
        if not all(0.0 <= t <= 1.0 for t in thresholds):
            raise ValueError("risk thresholds must be within [0, 1]")
        if not (low_threshold < medium_threshold < high_threshold < critical_threshold):
            raise ValueError("risk thresholds must be strictly ordered: low < medium < high < critical")
        for name, weight in {
            "base_score": base_score,
            "severity_weight": severity_weight,
            "persistence_weight": persistence_weight,
            "correlation_weight": correlation_weight,
            "confidence_weight": confidence_weight,
        }.items():
            if not 0.0 <= weight <= 1.0:
                raise ValueError(f"{name} must be within [0, 1]")
        self.low_threshold = low_threshold
        self.medium_threshold = medium_threshold
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold
        self.base_score = base_score
        self.severity_weight = severity_weight
        self.persistence_weight = persistence_weight
        self.correlation_weight = correlation_weight
        self.confidence_weight = confidence_weight

    @classmethod
    def from_settings(cls, settings: Any) -> RiskEngine:
        return cls(
            low_threshold=settings.risk_low_threshold,
            medium_threshold=settings.risk_medium_threshold,
            high_threshold=settings.risk_high_threshold,
            critical_threshold=settings.risk_critical_threshold,
            base_score=settings.risk_base_score,
            severity_weight=settings.risk_severity_weight,
            persistence_weight=settings.risk_persistence_weight,
            correlation_weight=settings.risk_correlation_weight,
            confidence_weight=settings.risk_confidence_weight,
        )

    def level_for_score(self, score: float) -> RiskLevel:
        if score >= self.critical_threshold:
            return RiskLevel.CRITICAL
        if score >= self.high_threshold:
            return RiskLevel.HIGH
        if score >= self.medium_threshold:
            return RiskLevel.MEDIUM
        if score >= self.low_threshold:
            return RiskLevel.LOW
        return RiskLevel.NONE

    def _factors(
        self,
        severity: UnifiedSeverity,
        confidence: float,
        age_seconds: float,
        member_count: int,
    ) -> tuple[float, list[RiskFactor]]:
        age = max(0.0, age_seconds)
        members = max(1, member_count)
        severity_value = SEVERITY_RANK.get(severity, 0.25)
        persistence_value = min(1.0, age / 60.0)
        correlation_value = min(1.0, (members - 1) / 4.0)
        confidence = min(1.0, max(0.0, confidence))
        factors = [
            RiskFactor(
                name="base",
                value=1.0,
                weight=self.base_score,
                contribution=round(self.base_score, 4),
                reason="baseline operational attention for any active signal",
            ),
            RiskFactor(
                name="severity",
                value=round(severity_value, 4),
                weight=self.severity_weight,
                contribution=round(self.severity_weight * severity_value, 4),
                reason=f"source severity {severity.value}",
            ),
            RiskFactor(
                name="persistence",
                value=round(persistence_value, 4),
                weight=self.persistence_weight,
                contribution=round(self.persistence_weight * persistence_value, 4),
                reason=f"signal age {age:.1f}s (saturates at 60s)",
            ),
            RiskFactor(
                name="correlation",
                value=round(correlation_value, 4),
                weight=self.correlation_weight,
                contribution=round(self.correlation_weight * correlation_value, 4),
                reason=f"{members} correlated member(s) corroborate the signal",
            ),
            RiskFactor(
                name="confidence",
                value=round(confidence, 4),
                weight=self.confidence_weight,
                contribution=round(self.confidence_weight * confidence, 4),
                reason="source-reported signal confidence",
            ),
        ]
        total = self.base_score + sum(f.contribution for f in factors[1:])
        return min(1.0, max(0.0, total)), factors

    def assess_event(
        self,
        event: UnifiedEvent,
        *,
        member_count: int = 1,
        timestamp: datetime | None = None,
    ) -> RiskAssessment:
        """Score one unified event with full factor explanation."""
        now = timestamp or utcnow()
        age = max(0.0, (now - event.first_seen).total_seconds())
        score, factors = self._factors(event.severity, event.confidence, age, member_count)
        level = self.level_for_score(score)
        return RiskAssessment(
            risk_score=round(score, 4),
            risk_level=level,
            confidence=event.confidence,
            factors=factors,
            reason=(
                f"{event.event_type.value} from {event.source_domain.value} "
                f"scored {score:.3f} → {level.value}"
            ),
            timestamp=now,
            metadata={"event_id": str(event.event_id)},
        )

    def assess_cluster(
        self,
        members: list[UnifiedEvent],
        first_seen: datetime,
        *,
        timestamp: datetime | None = None,
    ) -> RiskAssessment:
        """Score a cluster from its members: worst severity, mean confidence."""
        now = timestamp or utcnow()
        if not members:
            return RiskAssessment(
                risk_score=0.0,
                risk_level=RiskLevel.NONE,
                confidence=0.0,
                factors=[],
                reason="empty cluster carries no risk",
                timestamp=now,
            )
        worst_severity = UnifiedSeverity.INFO
        for member in members:
            if SEVERITY_RANK.get(member.severity, 0.0) > SEVERITY_RANK.get(worst_severity, 0.0):
                worst_severity = member.severity
        mean_confidence = sum(m.confidence for m in members) / len(members)
        age = max(0.0, (now - first_seen).total_seconds())
        score, factors = self._factors(worst_severity, mean_confidence, age, len(members))
        level = self.level_for_score(score)
        return RiskAssessment(
            risk_score=round(score, 4),
            risk_level=level,
            confidence=round(mean_confidence, 4),
            factors=factors,
            reason=(
                f"cluster of {len(members)} event(s), worst severity "
                f"{worst_severity.value}, scored {score:.3f} → {level.value}"
            ),
            timestamp=now,
        )
