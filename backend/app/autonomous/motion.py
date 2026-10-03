"""Motion estimation primitives — pure functions over track history.

All functions operate on 2D positions in a *consistent unit* (pixels in V04
history; callers normalize) paired with real timestamps — never frame counts.
Undefined results (zero/negative time delta, missing points, non-finite
values) return ``None`` instead of raising or producing NaN/Inf.
"""

from __future__ import annotations

import math
from datetime import datetime

Point = tuple[float, float]
Velocity = tuple[float, float]


def _finite_point(point: Point | None) -> bool:
    return point is not None and len(point) == 2 and math.isfinite(point[0]) and math.isfinite(point[1])


def _delta_seconds(earlier: datetime | None, later: datetime | None) -> float | None:
    if earlier is None or later is None:
        return None
    delta = (later - earlier).total_seconds()
    if not math.isfinite(delta) or delta <= 0.0:
        return None
    return delta


def center_velocity(
    earlier: Point | None,
    earlier_at: datetime | None,
    later: Point | None,
    later_at: datetime | None,
) -> Velocity | None:
    """Displacement rate between two timestamped centers, or ``None``."""
    if not _finite_point(earlier) or not _finite_point(later):
        return None
    assert earlier is not None and later is not None
    delta = _delta_seconds(earlier_at, later_at)
    if delta is None:
        return None
    vx = (later[0] - earlier[0]) / delta
    vy = (later[1] - earlier[1]) / delta
    if not math.isfinite(vx) or not math.isfinite(vy):
        return None
    return (vx, vy)


def speed(velocity: Velocity | None) -> float:
    if velocity is None or not _finite_point(velocity):
        return 0.0
    return math.hypot(velocity[0], velocity[1])


def acceleration(
    earlier_velocity: Velocity | None,
    earlier_at: datetime | None,
    later_velocity: Velocity | None,
    later_at: datetime | None,
) -> Velocity | None:
    """Rate of velocity change, or ``None`` when undefined."""
    if earlier_velocity is None or later_velocity is None:
        return None
    if not _finite_point(earlier_velocity) or not _finite_point(later_velocity):
        return None
    delta = _delta_seconds(earlier_at, later_at)
    if delta is None:
        return None
    ax = (later_velocity[0] - earlier_velocity[0]) / delta
    ay = (later_velocity[1] - earlier_velocity[1]) / delta
    if not math.isfinite(ax) or not math.isfinite(ay):
        return None
    return (ax, ay)


def movement_direction(velocity: Velocity | None, dead_zone: float = 1e-9) -> float | None:
    """Heading angle in radians (atan2, image y-down), or ``None`` near rest."""
    if velocity is None or not _finite_point(velocity):
        return None
    if math.hypot(velocity[0], velocity[1]) <= dead_zone:
        return None
    return math.atan2(velocity[1], velocity[0])


def ema_velocity(previous: Velocity | None, sample: Velocity | None, alpha: float = 0.35) -> Velocity | None:
    """Exponentially smoothed velocity; a missing sample keeps the previous."""
    if sample is None:
        return previous
    if previous is None:
        return sample
    weight = min(1.0, max(0.0, alpha))
    return (
        previous[0] + weight * (sample[0] - previous[0]),
        previous[1] + weight * (sample[1] - previous[1]),
    )


def approach_state(
    earlier_area: float | None,
    later_area: float | None,
    earlier_distance: float | None,
    later_distance: float | None,
    object_speed: float,
    speed_threshold: float,
    area_growth_ratio: float = 0.02,
) -> str:
    """Classify approach/recede from area growth + reference-distance change.

    Returns one of ``"APPROACHING"``, ``"RECEDING"``, ``"MOVING"``,
    ``"STATIONARY"``. Below ``speed_threshold`` the object is stationary
    regardless of area noise; without usable area/distance evidence the
    verdict is ``"MOVING"`` (it moves, direction unknown) rather than a guess.
    """
    if not math.isfinite(object_speed) or object_speed < 0.0:
        return "UNKNOWN"
    if object_speed <= speed_threshold:
        return "STATIONARY"
    growing = (
        earlier_area is not None
        and later_area is not None
        and math.isfinite(earlier_area)
        and math.isfinite(later_area)
        and earlier_area > 0.0
        and (later_area - earlier_area) / earlier_area >= area_growth_ratio
    )
    closing = (
        earlier_distance is not None
        and later_distance is not None
        and math.isfinite(earlier_distance)
        and math.isfinite(later_distance)
        and later_distance < earlier_distance
    )
    shrinking = (
        earlier_area is not None
        and later_area is not None
        and math.isfinite(earlier_area)
        and math.isfinite(later_area)
        and earlier_area > 0.0
        and (earlier_area - later_area) / earlier_area >= area_growth_ratio
    )
    opening = (
        earlier_distance is not None
        and later_distance is not None
        and math.isfinite(earlier_distance)
        and math.isfinite(later_distance)
        and later_distance > earlier_distance
    )
    if growing or closing:
        return "APPROACHING"
    if shrinking or opening:
        return "RECEDING"
    return "MOVING"
