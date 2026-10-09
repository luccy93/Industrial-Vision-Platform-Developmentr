"""Redis subscriber tests — offline roundtrip via fake transport."""

from __future__ import annotations

from backend.app.domain.common import utcnow
from backend.app.events.bus import EventBus
from backend.app.events.envelope import EventEnvelope
from backend.app.events.publisher import RedisEventSubscriber
from backend.app.infrastructure.redis_client import RedisLifecycleManager
from backend.tests.redis_helpers import FakeRedisTransport, fake_client_factory


def _subscriber(transport: FakeRedisTransport) -> tuple[RedisEventSubscriber, EventBus]:
    manager = RedisLifecycleManager(
        enabled=True, url="redis://localhost:6379/0", client_factory=fake_client_factory(transport)
    )
    assert manager.start() is True
    bus = EventBus(mode="distributed", redis_manager=manager)
    bus.start()
    subscriber = RedisEventSubscriber(redis_manager=manager, bus=bus, channel="ivp:events/v1")
    return subscriber, bus


def _envelope(event_id: str) -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id,
        event_type="incident_created",
        domain="INCIDENT",
        camera_id="cam-01",
        timestamp=utcnow(),
        origin="proc-other",
        payload={"incident_id": "x"},
    )


def test_subscriber_roundtrip() -> None:
    transport = FakeRedisTransport()
    subscriber, bus = _subscriber(transport)
    received: list[str] = []
    bus.subscribe(lambda e: received.append(e.event_id))
    assert subscriber.poll_once() == {"received": 0, "dropped": 0}
    transport.publish("ivp:events/v1", _envelope("r-1").to_bytes())
    stats = subscriber.poll_once()
    assert stats["received"] == 1
    assert received == ["r-1"]
    assert subscriber.subscriber_stats() == {"received": 1, "dropped": 0}
    subscriber.stop()


def test_subscriber_drops_malformed_safely() -> None:
    transport = FakeRedisTransport()
    subscriber, bus = _subscriber(transport)
    received: list[str] = []
    bus.subscribe(lambda e: received.append(e.event_id))
    assert subscriber.poll_once() == {"received": 0, "dropped": 0}
    transport.publish("ivp:events/v1", b"not-json")
    transport.publish("ivp:events/v1", b"[1,2]")
    stats = subscriber.poll_once()
    assert received == []
    assert stats["dropped"] == 2
    # Subscriber stays healthy after malformed input.
    transport.publish("ivp:events/v1", _envelope("r-2").to_bytes())
    stats = subscriber.poll_once()
    assert stats["received"] == 1
    assert received == ["r-2"]
    subscriber.stop()


def test_subscriber_ignores_own_origin_echo() -> None:
    transport = FakeRedisTransport()
    subscriber, bus = _subscriber(transport)
    received: list[str] = []
    bus.subscribe(lambda e: received.append(e.event_id))
    assert subscriber.poll_once() == {"received": 0, "dropped": 0}
    own = EventEnvelope(
        event_id="own-1",
        event_type="incident_created",
        domain="INCIDENT",
        origin=bus.origin,
        payload={},
    )
    transport.publish("ivp:events/v1", own.to_bytes())
    stats = subscriber.poll_once()
    assert stats["received"] == 0
    assert received == []
    subscriber.stop()


def test_subscriber_start_stop_lifecycle() -> None:
    from backend.app.workers.base import WorkerState

    transport = FakeRedisTransport()
    subscriber, _ = _subscriber(transport)
    assert subscriber.health().state is WorkerState.CREATED
    assert subscriber.start() is True
    assert subscriber.start() is True
    assert subscriber.health().state is WorkerState.RUNNING
    assert subscriber.stop() is True
    assert subscriber.stop() is True
    assert subscriber.health().state is WorkerState.STOPPED
