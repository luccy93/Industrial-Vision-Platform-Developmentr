"""Event bus tests — local fan-out, dedup, isolation, distributed policy."""

from __future__ import annotations

import pytest

from backend.app.events.bus import EventBus
from backend.app.events.envelope import EventEnvelope


def _envelope(event_id: str = "evt-1", event_type: str = "safety_event") -> EventEnvelope:
    return EventEnvelope(
        event_id=event_id,
        event_type=event_type,
        domain="SAFETY",
        camera_id="cam-01",
        origin="proc-test",
        payload={"tag": event_id},
    )


def test_local_fan_out_with_type_filter() -> None:
    bus = EventBus(mode="local")
    bus.start()
    seen: list[str] = []
    all_seen: list[str] = []
    bus.subscribe(lambda e: seen.append(e.event_id), event_type="safety_event")
    bus.subscribe(lambda e: all_seen.append(e.event_id))
    bus.publish(_envelope("a", "safety_event"))
    bus.publish(_envelope("b", "risk_cluster"))
    assert seen == ["a"]
    assert all_seen == ["a", "b"]


def test_duplicate_event_ids_dropped() -> None:
    bus = EventBus(mode="local")
    bus.start()
    seen: list[str] = []
    bus.subscribe(lambda e: seen.append(e.event_id))
    first = bus.publish(_envelope("dup"))
    second = bus.publish(_envelope("dup"))
    assert first.duplicate_dropped is False
    assert second.duplicate_dropped is True
    assert seen == ["dup"]


def test_subscriber_failure_isolated() -> None:
    bus = EventBus(mode="local")
    bus.start()

    def _boom(envelope: EventEnvelope) -> None:
        raise RuntimeError("subscriber down")

    seen: list[str] = []
    bus.subscribe(_boom)
    bus.subscribe(lambda e: seen.append(e.event_id))
    report = bus.publish(_envelope("x"))
    assert report.subscriber_errors == 1
    assert report.delivered_local == 1
    assert seen == ["x"]


def test_oversize_publish_dropped() -> None:
    bus = EventBus(mode="local", max_payload_bytes=128)
    bus.start()
    big = EventEnvelope(
        event_id="big",
        event_type="safety_event",
        domain="SAFETY",
        origin="proc-test",
        payload={"blob": "y" * 4096},
    )
    report = bus.publish(big)
    assert report.oversize_dropped is True
    assert report.delivered_local == 0


def test_distributed_without_transport_raises() -> None:
    bus = EventBus(mode="distributed", redis_manager=None)
    bus.start()
    with pytest.raises(ConnectionError):
        bus.publish(_envelope("x"))


def test_invalid_mode_rejected() -> None:
    with pytest.raises(ValueError):
        EventBus(mode="broadcast")


def test_receive_remote_paths() -> None:
    bus = EventBus(mode="local", origin="proc-a")
    bus.start()
    seen: list[str] = []
    bus.subscribe(lambda e: seen.append(e.event_id))
    # Malformed → None, bus stays healthy.
    assert bus.receive_remote(b"nope") is None
    assert bus.receive_remote(b"[1]") is None
    # Own origin echo → None (not an error, not delivered).
    own = EventEnvelope(event_id="own-1", event_type="safety_event", domain="SAFETY", origin="proc-a")
    assert bus.receive_remote(own.to_bytes()) is None
    assert seen == []
    # Foreign event → delivered once; repeat → duplicate drop.
    foreign = EventEnvelope(event_id="ext-1", event_type="safety_event", domain="SAFETY", origin="proc-b")
    assert bus.receive_remote(foreign.to_bytes()) is not None
    assert seen == ["ext-1"]
    assert bus.receive_remote(foreign.to_bytes()) is None
    assert seen == ["ext-1"]


def test_subscribe_unsubscribe_and_shutdown() -> None:
    bus = EventBus(mode="local")
    bus.start()
    seen: list[str] = []
    subscription_id = bus.subscribe(lambda e: seen.append(e.event_id))
    assert bus.subscription_count() == 1
    assert bus.unsubscribe(subscription_id) is True
    assert bus.unsubscribe(subscription_id) is False
    assert bus.subscription_count() == 0
    bus.publish(_envelope("z"))
    assert seen == []
    bus.shutdown()
    bus.shutdown()
    assert bus.stats()["running"] is False
