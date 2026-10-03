"""Relative bird's-eye view — unitless ordering proxy, never metric.

Normalized image ``(x, y)`` maps to ``(lateral=(x−0.5)×2, longitudinal=1−y)``:
lateral in [-1, 1] with 0 at the image center, longitudinal in [0, 1] with 1
nearest the bottom edge. This preserves *ordering* (who is left/right,
nearer/farther in the image) while claiming no physical layout. No 3D
reconstruction, no homography, no calibration.
"""

from __future__ import annotations

from datetime import datetime

from backend.app.autonomous.schemas import (
    BevObject,
    BevPoint,
    BirdsEyeView,
    CollisionRisk,
    CoordinateFrame,
    Lane,
    PerceivedObject,
    RiskLevel,
    Trajectory,
)


def to_bev(x: float, y: float) -> BevPoint:
    """Map a normalized image point into the relative BEV plane (clamped)."""
    return BevPoint(
        lateral=min(1.0, max(-1.0, (x - 0.5) * 2.0)),
        longitudinal=min(1.0, max(0.0, 1.0 - y)),
    )


def build_bev(
    objects: list[PerceivedObject],
    lanes: list[Lane],
    trajectories: list[Trajectory],
    risks: list[CollisionRisk],
    timestamp: datetime,
) -> BirdsEyeView:
    """Assemble a ``RELATIVE_BEV`` view from one perception pass."""
    risk_by_object: dict[str, RiskLevel] = {}
    order = [RiskLevel.NONE, RiskLevel.LOW, RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
    for risk in risks:
        for object_id in risk.object_ids:
            current = risk_by_object.get(object_id, RiskLevel.NONE)
            if order.index(risk.risk_level) > order.index(current):
                risk_by_object[object_id] = risk.risk_level

    bev_objects: list[BevObject] = []
    for obj in objects:
        if obj.center is None:
            continue
        point = to_bev(*obj.center)
        bev_objects.append(
            BevObject(
                object_id=obj.object_id,
                lateral=point.lateral,
                longitudinal=point.longitudinal,
                risk_level=risk_by_object.get(obj.object_id, RiskLevel.UNKNOWN),
            )
        )

    bev_lanes = [[to_bev(p.x, p.y) for p in lane.points] for lane in lanes]
    bev_trajectories = {
        trajectory.object_id: [to_bev(p.x, p.y) for p in trajectory.points] for trajectory in trajectories
    }
    return BirdsEyeView(
        coordinate_frame=CoordinateFrame.RELATIVE_BEV,
        objects=bev_objects,
        lanes=bev_lanes,
        trajectories=bev_trajectories,
        timestamp=timestamp,
    )
