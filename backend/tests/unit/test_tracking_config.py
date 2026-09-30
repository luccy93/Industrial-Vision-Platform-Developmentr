"""Tracking configuration tests."""

from __future__ import annotations

import pytest

from backend.app.core.config import Settings


def test_tracking_defaults() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.track_min_hits == 3
    assert settings.track_max_age == 30
    assert settings.track_iou_threshold == 0.3
    assert settings.track_history_size == 30
    assert settings.track_high_conf == 0.5


def test_tracking_bounds() -> None:
    with pytest.raises(ValueError):
        Settings(track_min_hits=0, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(track_max_age=0, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(track_iou_threshold=1.5, _env_file=None)  # type: ignore[call-arg]
    with pytest.raises(ValueError):
        Settings(track_history_size=0, _env_file=None)  # type: ignore[call-arg]
