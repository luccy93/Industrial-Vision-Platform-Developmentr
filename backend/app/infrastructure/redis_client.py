"""Centralized Redis lifecycle — one client, bounded timeouts (V12, §5.1).

Single-process local delivery is the default; this manager only activates
when ``REDIS_ENABLED`` is set. No client is created per request, frame,
or event. URLs (which may carry passwords) never appear in logs or
errors — only the host/port/db index.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from backend.app.domain.common import utcnow

logger = logging.getLogger("industrial-vision.redis")


def redact_redis_url(url: str) -> str:
    """Render host:port/db without credentials for logs and health."""
    try:
        parsed = urlparse(str(url or ""))
        host = parsed.hostname or "unknown"
        port = f":{parsed.port}" if parsed.port else ""
        path = parsed.path or ""
        return f"{parsed.scheme or 'redis'}://{host}{port}{path}"
    except Exception:
        return "redis://unknown"


@dataclass
class RedisStatus:
    """Observable Redis state (no secrets)."""

    enabled: bool = False
    required: bool = False
    connected: bool = False
    endpoint: str = "redis://unknown"
    last_error: str | None = None
    last_ping_at: datetime | None = None
    publishes: int = 0
    publish_failures: int = 0
    started_at: datetime = field(default_factory=utcnow)


class RedisConnectionError(ConnectionError):
    """Redis is unreachable or misconfigured (maps to 503 when required)."""


class RedisLifecycleManager:
    """Own the single Redis client: start → ping → publish → close (§5.1).

    Thread-safe. ``start()`` is idempotent; ``close()`` is idempotent and
    never raises. When disabled, every operation is a documented no-op and
    no socket is ever opened.
    """

    def __init__(
        self,
        *,
        enabled: bool = False,
        required: bool = False,
        url: str = "redis://localhost:6379/0",
        connect_timeout_seconds: float = 5.0,
        socket_timeout_seconds: float = 5.0,
        client_factory: Any | None = None,
    ) -> None:
        self._lock = threading.RLock()
        self._enabled = bool(enabled)
        self._required = bool(required)
        self._url = str(url or "")
        self._connect_timeout = max(0.1, float(connect_timeout_seconds))
        self._socket_timeout = max(0.1, float(socket_timeout_seconds))
        self._client_factory = client_factory
        self._client: Any | None = None
        self._status = RedisStatus(
            enabled=self._enabled,
            required=self._required,
            endpoint=redact_redis_url(self._url),
        )

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def required(self) -> bool:
        return self._required

    @property
    def connected(self) -> bool:
        with self._lock:
            return self._client is not None and self._status.connected

    def status(self) -> RedisStatus:
        with self._lock:
            return RedisStatus(
                enabled=self._status.enabled,
                required=self._status.required,
                connected=self._status.connected,
                endpoint=self._status.endpoint,
                last_error=self._status.last_error,
                last_ping_at=self._status.last_ping_at,
                publishes=self._status.publishes,
                publish_failures=self._status.publish_failures,
                started_at=self._status.started_at,
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> bool:
        """Connect + verify with a bounded ping. Idempotent.

        Raises :class:`RedisConnectionError` when required and unreachable;
        when merely enabled, records the failure and returns False (the
        caller reports degraded state honestly).
        """
        with self._lock:
            if not self._enabled:
                return False
            if self._client is not None and self._status.connected:
                return True
            try:
                client = self._build_client()
                client.ping()
            except Exception as exc:
                self._client = None
                self._status.connected = False
                self._status.last_error = f"{type(exc).__name__}"
                logger.warning(
                    "redis unavailable endpoint=%s error=%s",
                    self._status.endpoint,
                    type(exc).__name__,
                )
                if self._required:
                    raise RedisConnectionError(
                        f"required Redis unreachable at {self._status.endpoint}"
                    ) from exc
                return False
            self._client = client
            self._status.connected = True
            self._status.last_error = None
            self._status.last_ping_at = utcnow()
            logger.info("redis connected endpoint=%s", self._status.endpoint)
            return True

    def ping(self) -> bool:
        """Bounded connectivity probe (health/readiness path)."""
        with self._lock:
            client = self._client
            if client is None:
                return False
            try:
                client.ping()
            except Exception as exc:
                self._status.connected = False
                self._status.last_error = f"{type(exc).__name__}"
                return False
            self._status.connected = True
            self._status.last_ping_at = utcnow()
            return True

    def publish(self, channel: str, payload: bytes) -> int:
        """Publish bytes; returns receiver count.

        Raises :class:`RedisConnectionError` on failure so callers (outbox
        publisher, health) observe it; optional paths catch and degrade.
        Failures are never silently converted into success.
        """
        with self._lock:
            client = self._client
            if client is None or not self._status.connected:
                raise RedisConnectionError("redis client not connected")
            try:
                receivers = int(client.publish(str(channel), bytes(payload)))
            except Exception as exc:
                self._status.connected = False
                self._status.last_error = f"{type(exc).__name__}"
                self._status.publish_failures += 1
                raise RedisConnectionError(f"redis publish failed: {type(exc).__name__}") from exc
            self._status.publishes += 1
            return receivers

    def pubsub(self) -> Any:
        """Return a namespaced pub/sub handle bound to this client."""
        with self._lock:
            if self._client is None:
                raise RedisConnectionError("redis client not connected")
            return self._client.pubsub()

    def close(self) -> None:
        """Release the client. Idempotent, never raises."""
        with self._lock:
            client, self._client = self._client, None
            self._status.connected = False
        if client is not None:
            try:
                close = getattr(client, "close", None)
                if callable(close):
                    close()
            except Exception:
                logger.debug("redis close failed", exc_info=True)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _build_client(self) -> Any:
        if self._client_factory is not None:
            return self._client_factory(
                self._url,
                connect_timeout=self._connect_timeout,
                socket_timeout=self._socket_timeout,
            )
        try:
            import redis as _redis
        except ImportError as exc:
            raise RedisConnectionError("redis package not installed; add redis to requirements") from exc
        return _redis.Redis.from_url(
            self._url,
            socket_connect_timeout=self._connect_timeout,
            socket_timeout=self._socket_timeout,
            health_check_interval=30,
        )
