"""Collision-risk foundation — relative-motion heuristic over track pairs.

The engine identifies potentially hazardous relative motion from closing
image-space velocity, image proximity, and relative depth when available.
Outputs are heuristic assessments (uncalibrated score, estimated TTC or
``None``), never certified predictions. Missing required inputs yield
``risk_level=UNKNOWN``, never a fabricated probability.

Pair identity is canonical ``(min, max)`` object-ID ordering per camera, so
a pair maps to exactly one ongoing risk/event.
"""

from __future__ import annotations

import math
from datetime import datetime

from backend.app.autonomous.schemas import CollisionRisk, RiskLevel

MAX_COLLISION_PAIRS = 200
_SMALL_SPEED = 1e-9


def canonical_pair(first: str, second: str) -> tuple[str, str]:
    """Deterministic pair identity independent of argument order."""
    return (first, second) if first <= second else (second, first)


class CollisionRiskEngine:
    """Pairwise relative-motion risk heuristic (image-space, uncalibrated)."""

    def __init__(
        self,
        risk_threshold: float = 0.5,
        max_closing_speed: float = 1.0,
        proximity_range: float = 0.5,
    ) -> None:
        self.risk_threshold = min(1.0, max(0.0, risk_threshold))
        # Normalized units/second that counts as a "full-scale" closing rate.
        self.max_closing_speed = max(_SMALL_SPEED, float(max_closing_speed))
        # Normalized center distance below which proximity contributes fully.
        self.proximity_range = max(_SMALL_SPEED, float(proximity_range))

    def assess_pair(
        self,
        object_a: str,
        object_b: str,
        center_a: tuple[float, float] | None,
        center_b: tuple[float, float] | None,
        velocity_a: tuple[float, float] | None,
        velocity_b: tuple[float, float] | None,
        depth_a: float | None,
        depth_b: float | None,
        confirmed_a: bool,
        confirmed_b: bool,
        timestamp: datetime,
    ) -> CollisionRisk:
        """Assess one canonical pair. Never raises; degrades to UNKNOWN/NONE."""
        first, second = canonical_pair(object_a, object_b)

        def unknown(reason: str) -> CollisionRisk:
            return CollisionRisk(
                object_ids=[first, second],
                risk_level=RiskLevel.UNKNOWN,
                risk_score=0.0,
                time_to_collision=None,
                confidence=0.0,
                reason=reason,
                timestamp=timestamp,
            )

        if center_a is None or center_b is None:
            return unknown("missing position evidence")
        if not all(math.isfinite(v) for v in (*center_a, *center_b)):
            return unknown("non-finite position evidence")
        rel_x = center_b[0] - center_a[0]
        rel_y = center_b[1] - center_a[1]
        distance = math.hypot(rel_x, rel_y)
        if not math.isfinite(distance):
            return unknown("non-finite separation")
        if velocity_a is None or velocity_b is None:
            return unknown("missing velocity evidence")

        rel_vx = velocity_b[0] - velocity_a[0]
        rel_vy = velocity_b[1] - velocity_a[1]
        if not all(math.isfinite(v) for v in (rel_vx, rel_vy)):
            return unknown("non-finite velocity evidence")

        if distance <= 0.0:
            closing = math.hypot(rel_vx, rel_vy)
        else:
            closing = -(rel_x * rel_vx + rel_y * rel_vy) / distance
        if not math.isfinite(closing):
            return unknown("non-finite closing rate")

        if closing <= _SMALL_SPEED:
            detail = "objects separating" if closing < -_SMALL_SPEED else "no relative motion"
            return CollisionRisk(
                object_ids=[first, second],
                risk_level=RiskLevel.NONE,
                risk_score=0.0,
                time_to_collision=None,
                confidence=0.6 if confirmed_a and confirmed_b else 0.3,
                reason=detail,
                timestamp=timestamp,
            )

        closing_norm = min(1.0, closing / self.max_closing_speed)
        proximity = 1.0 - min(1.0, distance / self.proximity_range)
        risk_score = round(min(1.0, max(0.0, 0.5 * closing_norm + 0.5 * proximity)), 3)

        depth_known = (
            depth_a is not None and depth_b is not None and math.isfinite(depth_a) and math.isfinite(depth_b)
        )
        time_to_collision: float | None = round(distance / closing, 3)

        if risk_score < 0.25:
            level = RiskLevel.LOW
        elif risk_score < 0.5:
            level = RiskLevel.MEDIUM
        elif risk_score < 0.75:
            level = RiskLevel.HIGH
        else:
            level = RiskLevel.CRITICAL
        confidence = round(
            min(0.95, 0.4 + (0.3 if depth_known else 0.0) + (0.1 if confirmed_a and confirmed_b else 0.0)), 3
        )
        reason = f"relative approach trajectory (closing {closing:.3f} units/s, separation {distance:.3f})"
        return CollisionRisk(
            object_ids=[first, second],
            risk_level=level,
            risk_score=risk_score,
            time_to_collision=time_to_collision,
            confidence=confidence,
            reason=reason,
            timestamp=timestamp,
        )
