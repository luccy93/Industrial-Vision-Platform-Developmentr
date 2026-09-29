"""Configuration tests — env-driven, deterministic."""

from __future__ import annotations

import pytest

from backend.app.core.config import AppEnv, Settings


def test_defaults_support_development_without_secrets() -> None:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    assert settings.app_name == "industrial-vision-platform"
    assert settings.api_port == 8000
    assert settings.model_confidence_threshold == 0.5
    assert settings.websocket_enabled is True


def test_testing_env_flag() -> None:
    settings = Settings(app_env=AppEnv.testing, _env_file=None)  # type: ignore[call-arg]
    assert settings.is_testing is True
    assert settings.is_production is False


def test_production_env_flag() -> None:
    settings = Settings(app_env=AppEnv.production, _env_file=None)  # type: ignore[call-arg]
    assert settings.is_production is True


def test_required_env_keys_documented() -> None:
    fields = set(Settings.model_fields.keys())
    for key in [
        "app_name",
        "app_env",
        "log_level",
        "api_host",
        "api_port",
        "database_url",
        "redis_url",
        "gpu_enabled",
        "model_device",
        "model_confidence_threshold",
        "websocket_enabled",
    ]:
        assert key in fields


def test_invalid_log_level_rejected() -> None:
    with pytest.raises(ValueError):
        Settings(log_level="NOPE", _env_file=None)  # type: ignore[call-arg]


def test_confidence_threshold_bounds_enforced() -> None:
    with pytest.raises(ValueError):
        Settings(model_confidence_threshold=1.5, _env_file=None)  # type: ignore[call-arg]
