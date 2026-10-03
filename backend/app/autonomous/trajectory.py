"""Trajectory estimation — constant-velocity baseline over image history.

The estimator extrapolates EMA-smoothed image-space velocity over the last
history points. Assumptions (documented, not hidden): objects keep their
smoothed velocity over the horizon; predictions are clipped to the visible
frame; confidence decays with horizon distance. No Kalman filtering, no
learned prediction — a transparent short-horizon baseline.
"""

from __future__ import annotations

from datetime import datetime

from backend.app.autonomous import motion
from backend.app.autonomous.schemas import CoordinateFrame, NormalizedPoint, Trajectory

_DEFAULT_STEPS = 10


class TrajectoryEstimator:
    """Constant-velocity trajectory baseline in normalized coordinates."""

    def __init__(
        self,
        horizon_seconds: float = 2.0,
        history_points: int = 8,
        steps: int = _DEFAULT_STEPS,
    ) -> None:
        self.horizon_seconds = max(0.1, float(horizon_seconds))
        self.history_points = max(2, int(history_points))
        self.steps = max(1, int(steps))

    def estimate(
        self,
        object_id: str,
        centers: list[tuple[float, float]],
        timestamps: list[datetime],
        frame_width: float,
        frame_height: float,
    ) -> Trajectory | None:
        """Predict normalized points oldest→newest from the current position.

        Returns ``None`` when no usable velocity can be established (fewer
        than two timestamped centers, zero time deltas, non-finite values).
        """
        pairs = [(c, t) for c, t in zip(centers, timestamps) if c is not None and t is not None]
        pairs = pairs[-self.history_points :]
        if len(pairs) < 2:
            return None
        if frame_width <= 0 or frame_height <= 0:
            return None

        velocity: motion.Velocity | None = None
        for (earlier_c, earlier_t), (later_c, later_t) in zip(pairs, pairs[1:]):
            sample = motion.center_velocity(earlier_c, earlier_t, later_c, later_t)
            velocity = motion.ema_velocity(velocity, sample)
        if velocity is None:
            return None

        current = pairs[-1][0]
        current_norm = (current[0] / frame_width, current[1] / frame_height)
        norm_velocity = (velocity[0] / frame_width, velocity[1] / frame_height)
        norm_speed = motion.speed(norm_velocity)
        points = [
            NormalizedPoint(
                x=min(1.0, max(0.0, current_norm[0] + norm_velocity[0] * self.horizon_seconds * i / self.steps)),
                y=min(1.0, max(0.0, current_norm[1] + norm_velocity[1] * self.horizon_seconds * i / self.steps)),
            )
            for i in range(1, self.steps + 1)
        ]
        if norm_speed <= 1e-9:
            confidence = 0.9
        else:
            confidence = max(0.1, min(0.9, 0.9 - 0.15 * self.horizon_seconds))
        return Trajectory(
            object_id=object_id,
            points=points,
            horizon_seconds=self.horizon_seconds,
            confidence=round(confidence, 3),
            coordinate_frame=CoordinateFrame.IMAGE_SPACE_RELATIVE,
            metadata={"model": "constant-velocity"},
        )
