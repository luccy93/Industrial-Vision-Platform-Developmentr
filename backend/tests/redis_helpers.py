"""Deterministic fake Redis transport for offline tests (V12).

Implements exactly the narrow protocol the application uses (ping,
publish, pubsub listen, close) with scripted failure injection. This
fake proves application behavior, never Redis server behavior — real
protocol validation is an explicitly optional smoke gate.
"""

from __future__ import annotations

import queue
import threading
from typing import Any


class FakeRedisError(ConnectionError):
    """Scripted connection failure."""


class FakeRedisTimeout(TimeoutError):
    """Scripted operation timeout."""


class FakePubSub:
    """In-process pub/sub handle fed by FakeRedis.publish."""

    def __init__(self, transport: FakeRedisTransport) -> None:
        self._transport = transport
        self._subscribed: set[str] = set()
        self._closed = False

    def subscribe(self, *channels: str) -> None:
        for channel in channels:
            self._subscribed.add(str(channel))
            self._transport._register(self, str(channel))

    def unsubscribe(self, *channels: str) -> None:
        targets = set(map(str, channels)) if channels else set(self._subscribed)
        for channel in targets:
            self._subscribed.discard(channel)
            self._transport._unregister(self, channel)

    def get_message(self, timeout: float = 0.0) -> dict[str, Any] | None:
        """Next message for a subscribed channel, or None on timeout."""
        if self._closed:
            return None
        try:
            item = self._transport._inbox(self).get(timeout=max(0.0, timeout))
        except queue.Empty:
            return None
        channel, payload = item
        if channel not in self._subscribed:
            return self.get_message(timeout=0.0)
        return {"type": "message", "channel": channel, "data": payload}

    def close(self) -> None:
        self._closed = True
        self._transport._drop(self)


class FakeRedisTransport:
    """Deterministic stand-in for the redis client surface we use."""

    def __init__(self) -> None:
        self.ping_calls = 0
        self.publish_calls: list[tuple[str, bytes]] = []
        self.closed = False
        self.fail_ping: Exception | None = None
        self.fail_publish: Exception | None = None
        self.fail_subscribe: Exception | None = None
        self._lock = threading.RLock()
        self._inboxes: dict[int, queue.Queue] = {}
        self._registrations: dict[str, set[int]] = {}

    # -- client surface -------------------------------------------------
    def ping(self) -> bool:
        self.ping_calls += 1
        if self.fail_ping is not None:
            raise self.fail_ping
        return True

    def publish(self, channel: str, payload: bytes) -> int:
        with self._lock:
            self.publish_calls.append((str(channel), bytes(payload)))
            if self.fail_publish is not None:
                raise self.fail_publish
            targets = set(self._registrations.get(str(channel), ()))
        for key in targets:
            inbox = self._inboxes.get(key)
            if inbox is not None:
                inbox.put((str(channel), bytes(payload)))
        return len(targets)

    def pubsub(self) -> FakePubSub:
        if self.fail_subscribe is not None:
            raise self.fail_subscribe
        return FakePubSub(self)

    def close(self) -> None:
        self.closed = True

    # -- subscription plumbing ------------------------------------------
    def _register(self, sub: FakePubSub, channel: str) -> None:
        with self._lock:
            self._inboxes.setdefault(id(sub), queue.Queue())
            self._registrations.setdefault(channel, set()).add(id(sub))

    def _unregister(self, sub: FakePubSub, channel: str) -> None:
        with self._lock:
            members = self._registrations.get(channel)
            if members is not None:
                members.discard(id(sub))

    def _inbox(self, sub: FakePubSub) -> queue.Queue:
        with self._lock:
            return self._inboxes.setdefault(id(sub), queue.Queue())

    def _drop(self, sub: FakePubSub) -> None:
        with self._lock:
            self._inboxes.pop(id(sub), None)
            for members in self._registrations.values():
                members.discard(id(sub))


def fake_client_factory(transport: FakeRedisTransport):  # type: ignore[no-untyped-def]
    """Adapt a FakeRedisTransport to the manager's client_factory protocol."""

    def _factory(url: str, **kwargs: Any) -> FakeRedisTransport:
        assert url, "redis URL must be passed through"
        return transport

    return _factory
