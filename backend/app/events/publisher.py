"""Outbox publisher — durable drain with bounded retries (V12, §4.4).

A :class:`ManagedWorker` that polls pending outbox rows and delivers each
through the event bus (local fan-out always; Redis publication when the
bus is distributed). Rows are marked sent only after successful delivery;
failures schedule bounded exponential-backoff retries, and intents that
exhaust attempts become observably ``failed`` (never silently dropped,
never retried without bound).

Crash semantics: commit precedes delivery, so a crash between them leaves
a pending row that redelivers on recovery. Subscribers MUST be idempotent
(duplicate delivery is possible and expected).
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from typing import Any

from backend.app.domain.common import utcnow
from backend.app.events.bus import EventBus
from backend.app.events.envelope import EventEnvelope
from backend.app.events.store import OutboxRepository
from backend.app.workers.base import ManagedWorker, WorkerState

logger = logging.getLogger("industrial-vision.outbox")


class OutboxPublisher(ManagedWorker):
    """Poll-based outbox drain (deterministic via :meth:`drain_once`)."""

    def __init__(
        self,
        *,
        name: str = "outbox-publisher",
        outbox: OutboxRepository,
        bus: EventBus,
        batch_size: int = 50,
        max_attempts: int = 10,
        retry_base_seconds: float = 5.0,
        poll_interval_seconds: float = 1.0,
    ) -> None:
        super().__init__(name)
        self._outbox = outbox
        self._bus = bus
        self._batch_size = max(1, int(batch_size))
        self._max_attempts = max(1, int(max_attempts))
        self._retry_base = max(0.1, float(retry_base_seconds))
        self._poll_interval = max(0.1, float(poll_interval_seconds))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._delivered = 0
        self._failed = 0

    # ------------------------------------------------------------------
    # ManagedWorker contract
    # ------------------------------------------------------------------
    def start(self) -> bool:
        with self._state_lock:
            if self._worker_state is WorkerState.RUNNING:
                return True
            if self._worker_state is WorkerState.FAILED:
                return False
        try:
            self._transition(WorkerState.STARTING)
        except ValueError:
            return self.health().state is WorkerState.RUNNING
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name=f"outbox-{self.worker_name}", daemon=True)
        self._thread.start()
        self._transition(WorkerState.RUNNING)
        self._report_heartbeat()
        return True

    def stop(self, timeout: float = 5.0) -> bool:
        with self._state_lock:
            if self._worker_state in (WorkerState.STOPPED, WorkerState.CREATED):
                return True
        try:
            self._transition(WorkerState.STOPPING)
        except ValueError:
            return self.health().state is WorkerState.STOPPED
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        try:
            self._transition(WorkerState.STOPPED)
        except ValueError:
            pass
        return True

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------
    def drain_once(self, now: datetime | None = None) -> dict[str, int]:
        """Claim due rows and deliver one batch. Sync; used by tests too."""
        reference = now or utcnow()
        stats = {"claimed": 0, "delivered": 0, "retried": 0, "dead": 0, "invalid": 0}
        try:
            due = self._outbox.claim_due(limit=self._batch_size, now=reference)
        except Exception as exc:
            logger.warning("outbox claim failed: %s", type(exc).__name__)
            return stats
        stats["claimed"] = len(due)
        for row in due:
            self._deliver_row(row, reference, stats)
        self._report_heartbeat()
        return stats

    def _deliver_row(self, row: dict[str, Any], now: datetime, stats: dict[str, int]) -> None:
        row_id = str(row["id"])
        try:
            envelope = EventEnvelope.model_validate(dict(row.get("envelope") or {}))
            if envelope.event_id != row.get("event_id"):
                raise ValueError("outbox envelope identity mismatch")
        except Exception as exc:
            # Programming error in stored data: never retried blindly.
            self._outbox.mark_failed(row_id, f"invalid envelope: {exc}")
            stats["invalid"] += 1
            self._failed += 1
            return
        try:
            self._bus.deliver_durable(envelope)
        except Exception as exc:
            attempts = int(row.get("attempts") or 0) + 1
            if attempts >= self._max_attempts:
                self._outbox.mark_failed(row_id, f"attempts exhausted: {type(exc).__name__}")
                stats["dead"] += 1
                self._failed += 1
                logger.warning(
                    "outbox intent dead event_id=%s attempts=%d",
                    row.get("event_id"),
                    attempts,
                )
            else:
                backoff = self._retry_base * (2.0 ** min(attempts, 6))
                self._outbox.mark_failed(row_id, f"{type(exc).__name__}")
                self._outbox.requeue_failed(row_id, now + timedelta(seconds=backoff))
                stats["retried"] += 1
            return
        self._outbox.mark_sent(row_id)
        stats["delivered"] += 1
        self._delivered += 1

    def delivery_stats(self) -> dict[str, int]:
        with self._state_lock:
            return {"delivered": self._delivered, "failed": self._failed}

    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------
    def _loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    self.drain_once()
                except Exception as exc:
                    self._record_failure(f"{type(exc).__name__}: {exc}")
                    logger.warning("outbox drain failed: %s", type(exc).__name__)
                self._stop_event.wait(self._poll_interval)
        except Exception as exc:
            self._record_failure(f"{type(exc).__name__}: {exc}")
            with self._state_lock:
                try:
                    self._transition(WorkerState.FAILED)
                except ValueError:
                    pass
            logger.warning("outbox publisher crashed", exc_info=True)


class RedisEventSubscriber(ManagedWorker):
    """Redis pub/sub listener routing into local fan-out (distributed mode).

    Owns one pub/sub handle and a daemon listen loop. Malformed payloads
    are dropped safely via ``bus.receive_remote``; a dead subscription
    marks FAILED (observable) without touching publishers. Never
    republishes received events.
    """

    def __init__(
        self,
        *,
        name: str = "redis-subscriber",
        redis_manager: Any,
        bus: EventBus,
        channel: str = "ivp:events/v1",
        poll_timeout_seconds: float = 0.5,
    ) -> None:
        super().__init__(name)
        self._redis_manager = redis_manager
        self._bus = bus
        self._channel = str(channel)
        self._poll_timeout = max(0.05, float(poll_timeout_seconds))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._handle: Any | None = None
        self._received = 0
        self._dropped = 0

    def start(self) -> bool:
        with self._state_lock:
            if self._worker_state is WorkerState.RUNNING:
                return True
            if self._worker_state is WorkerState.FAILED:
                return False
        try:
            self._transition(WorkerState.STARTING)
        except ValueError:
            return self.health().state is WorkerState.RUNNING
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name=f"sub-{self.worker_name}", daemon=True)
        self._thread.start()
        self._transition(WorkerState.RUNNING)
        self._report_heartbeat()
        return True

    def stop(self, timeout: float = 5.0) -> bool:
        with self._state_lock:
            if self._worker_state in (WorkerState.STOPPED, WorkerState.CREATED):
                return True
        try:
            self._transition(WorkerState.STOPPING)
        except ValueError:
            return self.health().state is WorkerState.STOPPED
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        self._close_handle()
        try:
            self._transition(WorkerState.STOPPED)
        except ValueError:
            pass
        return True

    def _ensure_handle(self) -> Any | None:
        """Persistent subscription: one handle for the worker lifetime."""
        if self._handle is not None:
            return self._handle
        try:
            handle = self._redis_manager.pubsub()
            handle.subscribe(self._channel)
        except Exception as exc:
            self._record_failure(f"{type(exc).__name__}: {exc}")
            return None
        self._handle = handle
        return handle

    def _close_handle(self) -> None:
        handle, self._handle = self._handle, None
        if handle is None:
            return
        try:
            handle.unsubscribe(self._channel)
        except Exception:
            pass
        try:
            close = getattr(handle, "close", None)
            if callable(close):
                close()
        except Exception:
            pass

    def poll_once(self, max_messages: int = 100) -> dict[str, int]:
        """Drain currently-available messages once (sync; tests use this)."""
        stats = {"received": 0, "dropped": 0}
        handle = self._ensure_handle()
        if handle is None:
            return stats
        try:
            for _ in range(max(1, max_messages)):
                if self._stop_event.is_set():
                    break
                try:
                    message = handle.get_message(timeout=self._poll_timeout)
                except Exception as exc:
                    self._record_failure(f"{type(exc).__name__}: {exc}")
                    break
                if message is None:
                    break
                if not isinstance(message, dict) or message.get("type") != "message":
                    continue
                data = message.get("data")
                if isinstance(data, str):
                    data = data.encode("utf-8")
                if not isinstance(data, (bytes, bytearray)):
                    stats["dropped"] += 1
                    continue
                delivered = self._bus.receive_remote(bytes(data))
                if delivered is None:
                    stats["dropped"] += 1
                    self._dropped += 1
                else:
                    stats["received"] += 1
                    self._received += 1
            self._report_heartbeat()
        except Exception as exc:
            self._record_failure(f"{type(exc).__name__}: {exc}")
        return stats

    def subscriber_stats(self) -> dict[str, int]:
        with self._state_lock:
            return {"received": self._received, "dropped": self._dropped}

    def _loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    self.poll_once()
                except Exception as exc:
                    self._record_failure(f"{type(exc).__name__}: {exc}")
                    logger.warning("redis subscriber poll failed: %s", type(exc).__name__)
                self._stop_event.wait(self._poll_timeout)
        except Exception as exc:
            self._record_failure(f"{type(exc).__name__}: {exc}")
            with self._state_lock:
                try:
                    self._transition(WorkerState.FAILED)
                except ValueError:
                    pass
            logger.warning("redis subscriber crashed", exc_info=True)


__all__ = ["OutboxPublisher", "RedisEventSubscriber"]
