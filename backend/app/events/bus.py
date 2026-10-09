"""Event bus — local fan-out with optional Redis distribution (V12, §5.2).

Semantics:

- Local mode (default): synchronous in-process fan-out to matching
  subscribers. Existing direct-call flows are untouched; the bus is an
  additive notification path.
- Distributed mode: local fan-out PLUS Redis pub/sub publication for
  cross-process delivery (best-effort; Pub/Sub is not durable storage).
  Never silently falls back to local-only when distributed is configured:
  publication failures are observed (raised or reported).
- Subscribers never republish: subscriber callbacks must not call
  ``publish`` for received events (loops are prevented by contract, and
  by the origin/seen-set guard below).
- Delivery is at-most-once per subscriber with duplicate suppression on
  ``event_id`` (bounded seen-set). Crash-recovery redelivery goes through
  the PostgreSQL outbox (Commit 02), whose subscribers must be idempotent.
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from backend.app.events.envelope import EventEnvelope

logger = logging.getLogger("industrial-vision.events")

_SEEN_MAX = 5000


@dataclass
class DeliveryReport:
    """Outcome of one publish call (never silently converts failure)."""

    event_id: str
    delivered_local: int = 0
    subscriber_errors: int = 0
    published_remote: bool = False
    remote_error: str | None = None
    duplicate_dropped: bool = False
    oversize_dropped: bool = False


SubscriberCallback = Callable[[EventEnvelope], None]


@dataclass
class _Subscription:
    subscription_id: str
    event_type: str | None
    callback: SubscriberCallback


class EventBus:
    """Small fan-out bus with pluggable remote transport."""

    def __init__(
        self,
        *,
        mode: str = "local",
        channel: str = "ivp:events/v1",
        max_payload_bytes: int = 65536,
        origin: str | None = None,
        redis_manager: Any | None = None,
    ) -> None:
        normalized = str(mode or "local").strip().lower()
        if normalized not in ("local", "distributed"):
            raise ValueError("event bus mode must be local|distributed")
        self._mode = normalized
        self._channel = str(channel or "ivp:events/v1")
        self._max_payload = max(1024, int(max_payload_bytes))
        self._origin = str(origin or f"proc-{uuid.uuid4().hex[:12]}")
        self._redis_manager = redis_manager
        self._lock = threading.RLock()
        self._subscriptions: dict[str, _Subscription] = {}
        self._seen: deque[str] = deque(maxlen=_SEEN_MAX)
        self._seen_set: set[str] = set()
        self._running = False
        self._delivered = 0
        self._dropped_duplicates = 0

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------
    @property
    def mode(self) -> str:
        return self._mode

    @property
    def origin(self) -> str:
        return self._origin

    @property
    def channel(self) -> str:
        return self._channel

    @property
    def is_distributed(self) -> bool:
        return self._mode == "distributed"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Mark the bus running (idempotent). No threads in local mode."""
        with self._lock:
            self._running = True

    def shutdown(self) -> None:
        """Stop delivery and clear subscriptions (idempotent)."""
        with self._lock:
            self._running = False
            self._subscriptions.clear()

    # ------------------------------------------------------------------
    # Subscriptions
    # ------------------------------------------------------------------
    def subscribe(self, callback: SubscriberCallback, event_type: str | None = None) -> str:
        """Subscribe to one event type (None = all). Returns subscription id."""
        subscription_id = f"sub-{uuid.uuid4().hex[:12]}"
        with self._lock:
            self._subscriptions[subscription_id] = _Subscription(
                subscription_id=subscription_id,
                event_type=str(event_type) if event_type else None,
                callback=callback,
            )
        return subscription_id

    def unsubscribe(self, subscription_id: str) -> bool:
        with self._lock:
            return self._subscriptions.pop(str(subscription_id), None) is not None

    def subscription_count(self) -> int:
        with self._lock:
            return len(self._subscriptions)

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------
    def _is_duplicate(self, event_id: str) -> bool:
        with self._lock:
            if event_id in self._seen_set:
                return True
            if len(self._seen) >= _SEEN_MAX:
                oldest = self._seen.popleft()
                self._seen_set.discard(oldest)
            self._seen.append(event_id)
            self._seen_set.add(event_id)
            return False

    def publish(self, envelope: EventEnvelope) -> DeliveryReport:
        """Deliver locally; also publish remotely when distributed.

        Local subscriber failures are isolated (counted, logged) and never
        crash the publisher. Remote failures raise in distributed mode
        (observed, never silent) and are skipped in local mode.
        """
        report = DeliveryReport(event_id=envelope.event_id)
        try:
            raw = envelope.to_bytes(self._max_payload)
        except ValueError:
            report.oversize_dropped = True
            logger.warning(
                "event oversize dropped type=%s event_id=%s",
                envelope.event_type,
                envelope.event_id,
            )
            return report
        if self._is_duplicate(envelope.event_id):
            report.duplicate_dropped = True
            self._dropped_duplicates += 1
            return report
        with self._lock:
            running = self._running
            subscriptions = list(self._subscriptions.values())
        if running:
            for subscription in subscriptions:
                if subscription.event_type is not None and (subscription.event_type != envelope.event_type):
                    continue
                try:
                    subscription.callback(envelope)
                    report.delivered_local += 1
                except Exception as exc:
                    report.subscriber_errors += 1
                    logger.warning(
                        "event subscriber failed type=%s error=%s",
                        envelope.event_type,
                        type(exc).__name__,
                    )
        self._delivered += 1
        if self.is_distributed:
            manager = self._redis_manager
            if manager is None:
                # Misconfiguration: distributed without transport is a loud
                # error, never a silent local-only fallback.
                raise ConnectionError("distributed event bus has no Redis transport configured")
            try:
                manager.publish(self._channel, raw)
                report.published_remote = True
            except Exception as exc:
                report.remote_error = f"{type(exc).__name__}"
                raise
        return report

    def receive_remote(self, raw: bytes | bytearray) -> EventEnvelope | None:
        """Handle one remotely-received payload: validate + local fan-out.

        Returns the envelope, or None when safely dropped (malformed,
        unknown version, oversize, duplicate, or own-origin echo).
        """
        try:
            envelope = EventEnvelope.from_bytes(raw)
        except ValueError:
            logger.warning("remote event dropped: malformed envelope")
            return None
        try:
            envelope.to_bytes(self._max_payload)
        except ValueError:
            logger.warning("remote event dropped: oversize event_id=%s", envelope.event_id)
            return None
        if envelope.origin == self._origin:
            return None  # own echo; not an error
        if self._is_duplicate(envelope.event_id):
            self._dropped_duplicates += 1
            return None
        with self._lock:
            running = self._running
            subscriptions = list(self._subscriptions.values())
        if running:
            for subscription in subscriptions:
                if subscription.event_type is not None and (subscription.event_type != envelope.event_type):
                    continue
                try:
                    subscription.callback(envelope)
                except Exception as exc:
                    logger.warning(
                        "remote event subscriber failed type=%s error=%s",
                        envelope.event_type,
                        type(exc).__name__,
                    )
        return envelope

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "mode": self._mode,
                "channel": self._channel,
                "origin": self._origin,
                "running": self._running,
                "subscriptions": len(self._subscriptions),
                "delivered": self._delivered,
                "dropped_duplicates": self._dropped_duplicates,
            }
