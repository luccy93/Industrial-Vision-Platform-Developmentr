"""V12 configuration tests — pools, Redis, bus, retention, validation."""

from __future__ import annotations

import pytest

from backend.app.core.config import Settings
from backend.app.core.exceptions import ConfigurationError


def _settings(**overrides) -> Settings:
    return Settings(_env_file=None, **overrides)  # type: ignore[call-arg]


def test_v12_pool_defaults() -> None:
    settings = _settings()
    assert settings.db_pool_size == 5
    assert settings.db_max_overflow == 10
    assert settings.db_pool_timeout_seconds == 30.0
    assert settings.db_pool_recycle_seconds == 1800.0
    assert settings.db_connect_timeout_seconds == 10.0


def test_v12_redis_and_bus_defaults_are_local() -> None:
    settings = _settings()
    assert settings.redis_enabled is False
    assert settings.redis_required is False
    assert settings.event_bus_mode == "local"
    assert settings.is_distributed is False
    assert settings.event_bus_channel == "ivp:events/v1"
    assert settings.event_max_payload_bytes == 65536
    assert settings.event_queue_max == 1000
    assert settings.outbox_batch_size == 50
    assert settings.outbox_max_attempts == 10
    assert settings.outbox_retry_base_seconds == 5.0
    assert settings.operational_event_retention_days == 90


def test_distributed_requires_redis_enabled() -> None:
    settings = _settings(event_bus_mode="distributed", redis_enabled=True)
    assert settings.is_distributed is True
    with pytest.raises(ConfigurationError):
        _settings(event_bus_mode="distributed", redis_enabled=False).validate_startup()


def test_required_implies_enabled() -> None:
    with pytest.raises(ConfigurationError):
        _settings(redis_required=True, redis_enabled=False).validate_startup()


def test_enabled_requires_url() -> None:
    with pytest.raises(ConfigurationError):
        _settings(redis_enabled=True, redis_url="  ").validate_startup()


def test_invalid_bus_mode_rejected() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        _settings(event_bus_mode="broadcast")


def test_bus_mode_normalized() -> None:
    assert _settings(event_bus_mode="Distributed").event_bus_mode == "distributed"


def test_pool_bounds_rejected() -> None:
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        _settings(db_pool_size=0)
    with pytest.raises(ValidationError):
        _settings(db_pool_timeout_seconds=0.0)
    with pytest.raises(ValidationError):
        _settings(operational_event_retention_days=0)


def test_distributed_startup_passes_with_redis() -> None:
    settings = _settings(
        event_bus_mode="distributed",
        redis_enabled=True,
        redis_url="redis://localhost:6379/0",
    )
    assert settings.validate_startup() != []
    assert settings.is_distributed is True
