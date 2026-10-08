"""Hardening configuration tests — CORS table, startup validation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.core.config import AppEnv, Settings
from backend.app.core.exceptions import ConfigurationError


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_defaults_pass_validation() -> None:
    settings = _settings()
    assert settings.validate_startup() != []


def test_wildcard_plus_credentials_rejected_everywhere() -> None:
    for env in (AppEnv.development, AppEnv.testing, AppEnv.production):
        with pytest.raises(ConfigurationError):
            _settings(
                app_env=env,
                cors_allowed_origins=["*"],
                cors_allow_credentials=True,
            )


def test_production_rejects_wildcard_regardless() -> None:
    with pytest.raises(ConfigurationError):
        _settings(
            app_env=AppEnv.production,
            cors_allowed_origins=["*"],
            cors_allow_credentials=False,
        )


def test_production_requires_explicit_origin() -> None:
    with pytest.raises(ConfigurationError):
        _settings(app_env=AppEnv.production, cors_allowed_origins=[])
    settings = _settings(
        app_env=AppEnv.production,
        cors_allowed_origins=["https://vision.example.com"],
        cors_allow_credentials=True,
    )
    assert settings.validate_startup() != []


def test_development_explicit_localhost_ok() -> None:
    settings = _settings(
        app_env=AppEnv.development,
        cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        cors_allow_credentials=True,
    )
    assert settings.validate_startup() != []


def test_empty_database_url_rejected() -> None:
    with pytest.raises(ConfigurationError):
        _settings(database_url="  ").validate_startup()


def test_invalid_worker_and_queue_bounds_rejected() -> None:
    with pytest.raises(ValidationError):
        _settings(worker_heartbeat_timeout_seconds=0.0)
    with pytest.raises(ValidationError):
        _settings(websocket_queue_max_size=0)
    with pytest.raises(ValidationError):
        _settings(max_request_body_bytes=100)


def test_new_settings_have_sane_defaults() -> None:
    settings = _settings()
    assert settings.worker_heartbeat_timeout_seconds == 30.0
    assert settings.websocket_queue_max_size == 100
    assert settings.websocket_heartbeat_timeout_seconds == 60.0
    assert settings.websocket_shutdown_timeout_seconds == 5.0
    assert settings.max_request_body_bytes == 1048576
    assert settings.cors_allow_credentials is False
