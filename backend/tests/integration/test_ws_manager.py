"""WebSocket manager foundation tests — lifecycle, subscriptions, backpressure."""

from __future__ import annotations

import pytest

from backend.app.websocket.manager import (
    Connection,
    MessagePriority,
    Subscription,
    WebSocketManager,
    classify_message,
)


def _manager(**overrides) -> WebSocketManager:
    return WebSocketManager(queue_max_size=4, **overrides)


def test_connect_disconnect() -> None:
    manager = _manager()
    connection = manager.connect("c1", camera_id="cam-1")
    assert isinstance(connection, Connection)
    assert manager.get("c1") is connection
    assert manager.metrics()["active_connections"] == 1
    assert manager.metrics()["connections_total"] == 1
    assert manager.disconnect("c1") is connection
    assert manager.get("c1") is None
    assert manager.metrics()["disconnects_total"] == 1
    assert manager.disconnect("c1") is None


def test_connect_refused_while_draining() -> None:
    import asyncio

    manager = _manager()
    asyncio.run(manager.shutdown("test"))
    with pytest.raises(ConnectionRefusedError):
        manager.connect("late", camera_id="cam-1")


def test_subscribe_unsubscribe() -> None:
    manager = _manager()
    manager.connect("c1", camera_id="cam-1")
    assert manager.subscribe("c1", Subscription(event_types=frozenset({"safety_event"})))
    connection = manager.get("c1")
    assert connection is not None
    assert connection.subscription.event_types == frozenset({"safety_event"})
    assert manager.unsubscribe("c1") is True
    connection = manager.get("c1")
    assert connection is not None
    assert connection.subscription.event_types == frozenset()
    assert manager.subscribe("ghost", Subscription()) is False
    assert manager.unsubscribe("ghost") is False


def test_subscription_matching() -> None:
    open_feed = Subscription()
    assert open_feed.matches("safety_event", "cam-1", "SAFETY")
    filtered = Subscription(camera_id="cam-1", event_types=frozenset({"safety_event"}))
    assert filtered.matches("safety_event", "cam-1", "SAFETY")
    assert not filtered.matches("tracking", "cam-1")
    assert not filtered.matches("safety_event", "cam-2")
    domain = Subscription(domains=frozenset({"SAFETY"}))
    assert domain.matches("safety_event", "cam-9", "SAFETY")
    assert not domain.matches("safety_event", "cam-9", "QUALITY")


def test_message_priority_classes() -> None:
    for message_type in (
        "incident_created",
        "incident_status_changed",
        "incident_resolved",
        "incident_closed",
        "risk_cluster",
        "safety_event",
    ):
        assert classify_message(message_type) is MessagePriority.HIGH
    for message_type in ("tracking", "detection", "autonomous_perception", "quality_result"):
        assert classify_message(message_type) is MessagePriority.NORMAL
    assert classify_message("frame") is MessagePriority.LOW
    assert classify_message("unknown_future_type") is MessagePriority.LOW


def test_bounded_queue_drops_low_first() -> None:
    manager = _manager()
    manager.connect("c1")
    for index in range(4):
        assert manager.enqueue("c1", f'{{"type": "frame", "n": {index}}}', "frame") is True
    # Queue full: another low message is dropped, never blocking.
    assert manager.enqueue("c1", '{"type": "frame"}', "frame") is False
    assert manager.metrics()["messages_dropped"] == 1
    # High priority evicts a low message to make room — never silently lost.
    assert manager.enqueue("c1", '{"type": "incident_closed"}', "incident_closed") is True
    drained = manager.drain("c1", limit=10)
    assert len(drained) == 4
    assert '{"type": "incident_closed"}' in drained


def test_high_priority_never_dropped_when_possible() -> None:
    manager = _manager()
    manager.connect("c1")
    for index in range(4):
        assert (
            manager.enqueue("c1", f'{{"type": "incident_closed", "n": {index}}}', "incident_closed") is True
        )
    # Queue holds only HIGH payloads: even HIGH cannot evict — counted drop.
    assert manager.enqueue("c1", '{"type": "safety_event"}', "safety_event") is False
    assert manager.metrics()["messages_dropped"] == 1


def test_enqueue_unknown_connection() -> None:
    manager = _manager()
    assert manager.enqueue("ghost", "{}", "frame") is False
    assert manager.drain("ghost") == []


def test_heartbeat_and_stale() -> None:
    from datetime import timedelta

    from backend.app.domain.common import utcnow

    manager = _manager()
    manager.connect("c1")
    assert manager.heartbeat("c1", received=True) is True
    assert manager.heartbeat("ghost") is False
    assert manager.stale_connections(timeout_seconds=3600.0) == []
    connection = manager.get("c1")
    assert connection is not None
    connection.connected_at = utcnow() - timedelta(minutes=5)
    connection.last_received = None
    connection.last_ping = None
    assert manager.stale_connections(timeout_seconds=60.0) == ["c1"]


def test_metrics_shape() -> None:
    manager = _manager()
    manager.connect("c1")
    manager.enqueue("c1", '{"type": "frame"}', "frame")
    manager.record_sent("c1")
    manager.record_failed("c1")
    metrics = manager.metrics()
    for key in (
        "active_connections",
        "connections_total",
        "disconnects_total",
        "messages_sent",
        "messages_dropped",
        "messages_failed",
        "queue_depth",
    ):
        assert key in metrics
    assert metrics["active_connections"] == 1
    assert metrics["queue_depth"] == 1


def test_shutdown_closes_sockets_with_reason() -> None:
    import asyncio

    manager = _manager()

    class _Socket:
        def __init__(self) -> None:
            self.closed_with: tuple[int, str] | None = None

        async def close(self, code: int = 1000, reason: str = "") -> None:
            self.closed_with = (code, reason)

    socket = _Socket()
    manager.connect("c1", websocket=socket)
    result = asyncio.run(manager.shutdown("draining"))
    assert result["closed"] == 1
    assert socket.closed_with == (1012, "draining")
    assert manager.get("c1") is None
    assert manager.draining is True
