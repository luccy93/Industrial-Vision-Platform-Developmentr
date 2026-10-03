"""Motion primitive tests — timestamps, guards, approach classification."""

from __future__ import annotations

import math

from backend.app.autonomous.motion import (
    acceleration,
    approach_state,
    center_velocity,
    ema_velocity,
    movement_direction,
    speed,
)
from backend.tests.autonomous_helpers import utc


def test_velocity_from_two_positions() -> None:
    velocity = center_velocity((0.0, 0.0), utc(0), (10.0, 0.0), utc(2))
    assert velocity is not None
    assert velocity[0] == 5.0
    assert velocity[1] == 0.0
    assert speed(velocity) == 5.0


def test_velocity_none_on_zero_time_delta() -> None:
    assert center_velocity((0.0, 0.0), utc(0), (10.0, 0.0), utc(0)) is None


def test_velocity_none_on_negative_time_delta() -> None:
    assert center_velocity((0.0, 0.0), utc(5), (10.0, 0.0), utc(0)) is None


def test_velocity_none_on_missing_inputs() -> None:
    assert center_velocity(None, utc(0), (10.0, 0.0), utc(1)) is None
    assert center_velocity((0.0, 0.0), None, (10.0, 0.0), utc(1)) is None
    assert center_velocity((0.0, 0.0), utc(0), None, utc(1)) is None
    assert center_velocity((0.0, 0.0), utc(0), (10.0, 0.0), None) is None


def test_velocity_none_on_non_finite() -> None:
    assert center_velocity((math.nan, 0.0), utc(0), (10.0, 0.0), utc(1)) is None
    assert center_velocity((0.0, 0.0), utc(0), (math.inf, 0.0), utc(1)) is None
    assert speed(None) == 0.0
    assert speed((math.nan, 0.0)) == 0.0


def test_acceleration() -> None:
    accel = acceleration((0.0, 0.0), utc(0), (4.0, 0.0), utc(2))
    assert accel is not None
    assert accel[0] == 2.0
    assert acceleration((0.0, 0.0), utc(0), (4.0, 0.0), utc(0)) is None
    assert acceleration(None, utc(0), (4.0, 0.0), utc(2)) is None


def test_movement_direction() -> None:
    assert movement_direction((1.0, 0.0)) == 0.0
    assert movement_direction((0.0, 0.0)) is None
    assert movement_direction(None) is None
    assert movement_direction((math.nan, 0.0)) is None


def test_ema_velocity() -> None:
    assert ema_velocity(None, (4.0, 0.0)) == (4.0, 0.0)
    assert ema_velocity((4.0, 0.0), None) == (4.0, 0.0)
    smoothed = ema_velocity((0.0, 0.0), (10.0, 0.0), alpha=0.5)
    assert smoothed is not None
    assert smoothed[0] == 5.0
    clamped = ema_velocity((0.0, 0.0), (10.0, 0.0), alpha=5.0)
    assert clamped == (10.0, 0.0)


def test_approach_state_stationary_below_threshold() -> None:
    assert approach_state(100.0, 200.0, 0.9, 0.5, 0.0, 0.02) == "STATIONARY"
    assert approach_state(100.0, 200.0, 0.9, 0.5, 0.01, 0.02) == "STATIONARY"


def test_approach_state_approaching() -> None:
    # Growing bbox area → approaching even without distance evidence.
    assert approach_state(100.0, 130.0, None, None, 1.0, 0.02) == "APPROACHING"
    # Closing reference distance → approaching even without area evidence.
    assert approach_state(None, None, 0.9, 0.7, 1.0, 0.02) == "APPROACHING"


def test_approach_state_receding() -> None:
    assert approach_state(130.0, 100.0, None, None, 1.0, 0.02) == "RECEDING"
    assert approach_state(None, None, 0.7, 0.9, 1.0, 0.02) == "RECEDING"


def test_approach_state_moving_without_direction_evidence() -> None:
    assert approach_state(100.0, 100.5, 0.8, 0.8, 1.0, 0.02) == "MOVING"
    assert approach_state(None, None, None, None, 1.0, 0.02) == "MOVING"


def test_approach_state_unknown_on_invalid_speed() -> None:
    assert approach_state(100.0, 130.0, 0.9, 0.7, math.nan, 0.02) == "UNKNOWN"
    assert approach_state(100.0, 130.0, 0.9, 0.7, -1.0, 0.02) == "UNKNOWN"
