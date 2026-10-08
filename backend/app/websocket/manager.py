"""WebSocket connection manager — lifecycle boundary, not a hot loop (V11).

Design ruling (locked): ``WebSocketManager`` surrounds the existing
``streams_ws`` per-connection delta loop; it does not own or rewrite it.
The manager owns connection registration, metadata, heartbeat/idle
tracking, subscription metadata, connection-level metrics, graceful
shutdown, safe disconnect, and bounded send/backpressure primitives.
Delta computation, message ordering, payload construction, and scheduling
stay in ``streams_ws``.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from backend.app.domain.common import utcnow

logger = logging.getLogger("industrial-vision.websocket")


class MessagePriority(str, Enum):
    """WebSocket message priority classes (§29)."""

    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


# High-priority lifecycle messages are never silently dropped. Normal
# messages queue behind them. Low messages (frames, high-frequency
# metrics) are droppable under backpressure.
HIGH_PRIORITY_TYPES = frozenset(
    {
        "incident_created",
        "incident_status_changed",
        "incident_resolved",
        "incident_closed",
        "risk_cluster",
        "safety_event",
    }
)

NORMAL_PRIORITY_TYPES = frozenset(
    {
        "tracking",
        "detection",
        "autonomous_perception",
        "quality_result",
    }
)


def classify_message(message_type: str) -> MessagePriority:
    """Classify a wire message type into its priority class (§29)."""
    if message_type in HIGH_PRIORITY_TYPES:
        return MessagePriority.HIGH
    if message_type in NORMAL_PRIORITY_TYPES:
        return MessagePriority.NORMAL
    return MessagePriority.LOW


@dataclass
class Subscription:
    """Client subscription filters (§27).

    Empty sets mean "no filter" — the client receives the same compatible
    feed as today (default behavior preserved).
    """

    camera_id: str = ""
    event_types: frozenset[str] = frozenset()
    domains: frozenset[str] = frozenset()

    def matches(self, message_type: str, camera_id: str, domain: str = "") -> bool:
        """True when a message passes this subscription's filters."""
        if self.camera_id and self.camera_id != camera_id:
            return False
        if self.event_types and message_type not in self.event_types:
            return False
        if self.domains and domain and domain not in self.domains:
            return False
        return True


@dataclass
class Connection:
    """One tracked WebSocket connection (§30)."""

    connection_id: str
    camera_id: str = ""
    connected_at: datetime = field(default_factory=utcnow)
    last_received: datetime | None = None
    last_sent: datetime | None = None
    last_ping: datetime | None = None
    subscription: Subscription = field(default_factory=Subscription)
    queue: deque[str] = field(default_factory=deque)
    dropped: int = 0
    sent: int = 0
    failed: int = 0

    def mark_received(self) -> None:
        self.last_received = utcnow()

    def mark_sent(self) -> None:
        self.last_sent = utcnow()
        self.sent += 1

    def idle_seconds(self, now: datetime | None = None) -> float:
        """Seconds since the last activity on this connection.

        Considers receives, pings, *and* successful sends: on the
        send-only camera feed a flowing socket is alive even though the
        client never transmits application frames.
        """
        reference = now or utcnow()
        candidates = [self.connected_at]
        for stamp in (self.last_received, self.last_ping, self.last_sent):
            if stamp is not None:
                candidates.append(stamp)
        try:
            return max(0.0, (reference - max(candidates)).total_seconds())
        except Exception:
            return 0.0


@dataclass
class WebSocketMetrics:
    """Connection-level metrics (§33). In memory only — never PostgreSQL."""

    active_connections: int = 0
    connections_total: int = 0
    disconnects_total: int = 0
    messages_sent: int = 0
    messages_dropped: int = 0
    messages_failed: int = 0
    slow_clients: int = 0

    def queue_depth(self, connections: dict[str, Connection]) -> int:
        return sum(len(c.queue) for c in connections.values())

    def to_dict(self, connections: dict[str, Connection] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "active_connections": self.active_connections,
            "connections_total": self.connections_total,
            "disconnects_total": self.disconnects_total,
            "messages_sent": self.messages_sent,
            "messages_dropped": self.messages_dropped,
            "messages_failed": self.messages_failed,
            "slow_clients": self.slow_clients,
        }
        if connections is not None:
            payload["queue_depth"] = self.queue_depth(connections)
        return payload


class WebSocketManager:
    """Lifecycle boundary for WebSocket connections (§25, §31–§33)."""

    def __init__(
        self,
        *,
        queue_max_size: int = 100,
        heartbeat_timeout_seconds: float = 60.0,
        shutdown_timeout_seconds: float = 5.0,
    ) -> None:
        self._lock = threading.RLock()
        self._connections: dict[str, Connection] = {}
        self._metrics = WebSocketMetrics()
        self._queue_max = max(1, int(queue_max_size))
        self._heartbeat_timeout = max(0.0, float(heartbeat_timeout_seconds))
        self._shutdown_timeout = max(0.0, float(shutdown_timeout_seconds))
        self._draining = False
        self._sockets: dict[str, Any] = {}

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    @property
    def draining(self) -> bool:
        with self._lock:
            return self._draining

    def connect(
        self,
        connection_id: str,
        camera_id: str = "",
        subscription: Subscription | None = None,
        websocket: Any | None = None,
    ) -> Connection:
        """Register a connection. Refused while draining (shutdown, §31)."""
        with self._lock:
            if self._draining:
                raise ConnectionRefusedError("server is draining; no new connections")
            connection = Connection(
                connection_id=str(connection_id),
                camera_id=str(camera_id or ""),
                subscription=subscription or Subscription(),
            )
            self._connections[connection.connection_id] = connection
            if websocket is not None:
                self._sockets[connection.connection_id] = websocket
            self._metrics.active_connections = len(self._connections)
            self._metrics.connections_total += 1
            return connection

    def disconnect(self, connection_id: str) -> Connection | None:
        """Unregister a connection (safe to call for unknown ids)."""
        with self._lock:
            connection = self._connections.pop(str(connection_id), None)
            self._sockets.pop(str(connection_id), None)
            if connection is not None:
                self._metrics.active_connections = len(self._connections)
                self._metrics.disconnects_total += 1
            return connection

    def get(self, connection_id: str) -> Connection | None:
        with self._lock:
            return self._connections.get(str(connection_id))

    def subscribe(self, connection_id: str, subscription: Subscription) -> bool:
        """Replace a connection's subscription filters (§27)."""
        with self._lock:
            connection = self._connections.get(str(connection_id))
            if connection is None:
                return False
            connection.subscription = subscription
            return True

    def unsubscribe(self, connection_id: str) -> bool:
        """Reset a connection to the unfiltered (compatible) feed (§27)."""
        return self.subscribe(connection_id, Subscription())

    # ------------------------------------------------------------------
    # Send path (bounded, prioritized, §28–§29)
    # ------------------------------------------------------------------
    def enqueue(self, connection_id: str, payload: str, message_type: str = "") -> bool:
        """Queue a payload for a connection.

        Returns True when queued. HIGH-priority messages make room by
        evicting LOW payloads first and are never silently dropped unless
        the queue holds only HIGH payloads; LOW payloads are dropped when
        the queue is full (counted in metrics). Never blocks.
        """
        with self._lock:
            connection = self._connections.get(str(connection_id))
            if connection is None:
                return False
            priority = classify_message(message_type)
            if len(connection.queue) >= self._queue_max:
                if priority is MessagePriority.LOW:
                    connection.dropped += 1
                    self._metrics.messages_dropped += 1
                    return False
                # Make room for important messages: evict oldest LOW first.
                evicted = False
                for _ in range(len(connection.queue)):
                    oldest = connection.queue[0]
                    if classify_message(_peek_type(oldest)) is MessagePriority.LOW:
                        connection.queue.popleft()
                        connection.dropped += 1
                        self._metrics.messages_dropped += 1
                        evicted = True
                        break
                    connection.queue.rotate(-1)
                if not evicted:
                    connection.dropped += 1
                    self._metrics.messages_dropped += 1
                    return False
            connection.queue.append(payload)
            return True

    def drain(self, connection_id: str, limit: int = 20) -> list[str]:
        """Pop up to ``limit`` queued payloads (oldest first)."""
        with self._lock:
            connection = self._connections.get(str(connection_id))
            if connection is None:
                return []
            items: list[str] = []
            while connection.queue and len(items) < max(1, limit):
                items.append(connection.queue.popleft())
            return items

    def record_sent(self, connection_id: str, count: int = 1) -> None:
        with self._lock:
            connection = self._connections.get(str(connection_id))
            if connection is not None:
                connection.mark_sent()
            self._metrics.messages_sent += max(0, count)

    def record_failed(self, connection_id: str) -> None:
        with self._lock:
            connection = self._connections.get(str(connection_id))
            if connection is not None:
                connection.failed += 1
            self._metrics.messages_failed += 1

    # ------------------------------------------------------------------
    # Heartbeat (§30)
    # ------------------------------------------------------------------
    def heartbeat(self, connection_id: str, *, received: bool = False) -> bool:
        """Record client activity (receive) or a ping."""
        with self._lock:
            connection = self._connections.get(str(connection_id))
            if connection is None:
                return False
            if received:
                connection.mark_received()
            else:
                connection.last_ping = utcnow()
            return True

    def stale_connections(
        self, timeout_seconds: float | None = None, now: datetime | None = None
    ) -> list[str]:
        """Connection ids idle past the heartbeat timeout."""
        limit = self._heartbeat_timeout if timeout_seconds is None else float(timeout_seconds)
        reference = now or utcnow()
        with self._lock:
            return [
                cid
                for cid, connection in self._connections.items()
                if connection.idle_seconds(reference) > max(0.0, limit)
            ]

    # ------------------------------------------------------------------
    # Shutdown (§31)
    # ------------------------------------------------------------------
    async def shutdown(self, reason: str = "server shutdown") -> dict[str, Any]:
        """Drain: refuse new connections, close all with a reason (bounded)."""
        with self._lock:
            self._draining = True
            sockets = list(self._sockets.items())
        closed = 0
        failed = 0
        deadline = time.monotonic() + self._shutdown_timeout
        for connection_id, socket in sockets:
            if time.monotonic() > deadline:
                break
            try:
                await asyncio.wait_for(socket.close(code=1012, reason=reason), timeout=2.0)
                closed += 1
            except Exception:
                failed += 1
            finally:
                self.disconnect(connection_id)
        return {"closed": closed, "failed": failed, "reason": reason}

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            return self._metrics.to_dict(dict(self._connections))

    def reset_for_tests(self) -> None:
        """Clear all state (tests only — never call in production)."""
        with self._lock:
            self._connections.clear()
            self._sockets.clear()
            self._metrics = WebSocketMetrics()
            self._draining = False


def _peek_type(payload: str) -> str:
    """Best-effort message-type extraction for eviction decisions."""
    try:
        import json as _json

        value = _json.loads(payload)
        if isinstance(value, dict):
            return str(value.get("type", ""))
    except Exception:
        pass
    return ""
