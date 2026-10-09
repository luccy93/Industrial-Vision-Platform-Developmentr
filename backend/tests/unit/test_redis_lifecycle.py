"""Redis lifecycle tests — offline via deterministic fake transport."""

from __future__ import annotations

import pytest

from backend.app.infrastructure.redis_client import (
    RedisConnectionError,
    RedisLifecycleManager,
    redact_redis_url,
)
from backend.tests.redis_helpers import (
    FakeRedisError,
    FakeRedisTimeout,
    FakeRedisTransport,
    fake_client_factory,
)


def _manager(transport: FakeRedisTransport, **overrides) -> RedisLifecycleManager:  # type: ignore[no-untyped-def]
    params: dict = {
        "enabled": True,
        "required": False,
        "url": "redis://localhost:6379/0",
        "client_factory": fake_client_factory(transport),
    }
    params.update(overrides)
    return RedisLifecycleManager(**params)


def test_disabled_manager_never_connects() -> None:
    transport = FakeRedisTransport()
    manager = RedisLifecycleManager(enabled=False, client_factory=fake_client_factory(transport))
    assert manager.start() is False
    assert manager.connected is False
    assert transport.ping_calls == 0
    manager.close()


def test_start_ping_publish_close() -> None:
    transport = FakeRedisTransport()
    manager = _manager(transport)
    assert manager.start() is True
    assert manager.connected is True
    assert manager.ping() is True
    assert manager.publish("ivp:events/v1", b"{}") == 0
    assert transport.publish_calls == [("ivp:events/v1", b"{}")]
    status = manager.status()
    assert status.connected is True
    assert status.publishes == 1
    manager.close()
    manager.close()
    assert manager.connected is False
    assert transport.closed is True


def test_start_idempotent() -> None:
    transport = FakeRedisTransport()
    manager = _manager(transport)
    assert manager.start() is True
    assert manager.start() is True
    assert transport.ping_calls == 1


def test_unreachable_optional_records_and_returns_false() -> None:
    transport = FakeRedisTransport()
    transport.fail_ping = FakeRedisError("refused")
    manager = _manager(transport)
    assert manager.start() is False
    assert manager.connected is False
    assert manager.status().last_error == "FakeRedisError"


def test_unreachable_required_raises() -> None:
    transport = FakeRedisTransport()
    transport.fail_ping = FakeRedisError("refused")
    manager = _manager(transport, required=True)
    with pytest.raises(RedisConnectionError):
        manager.start()


def test_publish_failure_observed_never_silent() -> None:
    transport = FakeRedisTransport()
    manager = _manager(transport)
    assert manager.start() is True
    transport.fail_publish = FakeRedisTimeout("timed out")
    with pytest.raises(RedisConnectionError):
        manager.publish("ivp:events/v1", b"{}")
    assert manager.status().publish_failures == 1
    assert manager.connected is False


def test_publish_without_connection_raises() -> None:
    transport = FakeRedisTransport()
    manager = _manager(transport)
    with pytest.raises(RedisConnectionError):
        manager.publish("ivp:events/v1", b"{}")


def test_redact_redis_url_strips_credentials() -> None:
    assert redact_redis_url("redis://:s3cret@db.internal:6379/0") == "redis://db.internal:6379/0"
    assert redact_redis_url("rediss://user:pw@h:6380/2") == "rediss://h:6380/2"
    assert "s3cret" not in redact_redis_url("redis://:s3cret@db.internal:6379/0")
    assert redact_redis_url("") == "redis://unknown"


def test_status_has_no_secrets() -> None:
    transport = FakeRedisTransport()
    manager = RedisLifecycleManager(
        enabled=True,
        url="redis://:s3cret@db.internal:6379/0",
        client_factory=fake_client_factory(transport),
    )
    manager.start()
    blob = str(manager.status())
    assert "s3cret" not in blob
    manager.close()
