"""Safety configuration tests."""

from __future__ import annotations

import pytest

from backend.app.core.config import Settings


def test_safety_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.safety_enabled is True
    assert settings.safety_fall_aspect_ratio_threshold == 1.2
    assert settings.safety_fall_persistence_frames == 5
    assert settings.safety_crowd_warning_count == 5
    assert settings.safety_crowd_critical_count == 10
    assert settings.safety_proximity_iou_threshold == 0.05
    assert settings.safety_proximity_center_distance_ratio == 0.3
    assert settings.safety_stationary_speed_threshold == 15.0
    assert settings.safety_stationary_duration_seconds == 10.0
    assert settings.safety_event_resolution_grace_seconds == 3.0
    assert settings.safety_max_events_per_camera == 100


def test_safety_bounds() -> None:
    with pytest.raises(ValueError):
        Settings(safety_fall_persistence_frames=0, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(safety_crowd_warning_count=0, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(safety_proximity_iou_threshold=2.0, _env_file=None)  # type: ignore[call-arg]
