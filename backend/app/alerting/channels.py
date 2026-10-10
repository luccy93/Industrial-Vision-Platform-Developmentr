"""Channel adapter contracts — in-app, SMTP, webhook (V15).

Adapters never see credentials: SMTP/webhook secrets are injected at
construction from environment configuration, never stored in rule rows,
payloads, or logs. Failures surface as sanitized error *categories*;
raw provider exceptions never leave the adapter boundary.
"""

from __future__ import annotations

import abc
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# Sanitized, operator-safe error categories. Adapters map every failure
# onto exactly one of these; raw messages stay in server logs only.
ERROR_TIMEOUT = "timeout"
ERROR_CONNECTION = "connection_failed"
ERROR_AUTH = "auth_failed"
ERROR_RATE_LIMITED = "rate_limited"
ERROR_SERVER = "provider_error"
ERROR_CLIENT = "invalid_request"
ERROR_NOT_CONFIGURED = "not_configured"
ERROR_UNKNOWN = "unknown_error"


@dataclass
class ChannelResult:
    """Outcome of one adapter send attempt."""

    delivered: bool
    retryable: bool = False
    error_category: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


class ChannelAdapter(abc.ABC):
    """Delivery contract every channel implements (real or fake)."""

    name: str = "channel"

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """True when the channel can actually deliver (else unavailable)."""

    @abc.abstractmethod
    def send(self, notification: dict[str, Any], context: dict[str, Any] | None = None) -> ChannelResult:
        """Attempt one delivery. Never raises for expected failures."""

    def close(self) -> None:
        """Release clients/sockets. Idempotent; default no-op."""


def build_webhook_payload(notification: dict[str, Any]) -> dict[str, Any]:
    """Documented generic webhook body (stable keys, minimal safe context)."""
    return {
        "notification_id": str(notification.get("id", "")),
        "rule_id": str(notification.get("rule_id", "")),
        "source_event_id": str(notification.get("source_event_id", "")),
        "event_type": str(notification.get("event_type", "")),
        "severity": str(notification.get("severity", "UNKNOWN")),
        "priority": str(notification.get("priority", "P4")),
        "camera_id": notification.get("camera_id"),
        "incident_id": notification.get("incident_id"),
        "title": str(notification.get("title", "")),
        "message": str(notification.get("message", "")),
        "occurred_at": _iso(notification.get("created_at")),
    }


def _iso(value: Any) -> str | None:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str) and value:
        return value
    return None


def sign_webhook_payload(secret: str, body: bytes) -> str:
    """HMAC-SHA256 signature for X-IVP-Signature (empty secret → empty)."""
    if not secret:
        return ""
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def categorize_smtp_error(exc: BaseException) -> tuple[str, bool]:
    """Map smtplib failures to (category, retryable) without leaking details."""
    name = type(exc).__name__
    message = str(exc)
    if "Timeout" in name or "timeout" in message.lower():
        return ERROR_TIMEOUT, True
    if "Authentication" in name or "auth" in message.lower():
        return ERROR_AUTH, False
    if "Recipient" in name or "recipient" in message.lower() or "Sender" in name:
        return ERROR_CLIENT, False
    if "Connect" in name or "Connection" in name or "refused" in message.lower():
        return ERROR_CONNECTION, True
    if "ServerDisconnected" in name or "response" in message.lower():
        return ERROR_SERVER, True
    return ERROR_UNKNOWN, True


def categorize_http_error(
    *, status: int | None, timeout: bool = False, connection: bool = False
) -> tuple[str, bool]:
    """Map HTTP failures to (category, retryable). 429/5xx retry; 4xx terminal."""
    if timeout or connection:
        return (ERROR_TIMEOUT if timeout else ERROR_CONNECTION), True
    if status is None:
        return ERROR_UNKNOWN, True
    if status == 429:
        return ERROR_RATE_LIMITED, True
    if 500 <= status <= 599:
        return ERROR_SERVER, True
    if 400 <= status <= 499:
        return ERROR_CLIENT, False
    if 200 <= status <= 299:
        return "", False
    return ERROR_UNKNOWN, True


class FakeChannelAdapter(ChannelAdapter):
    """Deterministic test double: scripted outcomes, recorded calls."""

    def __init__(
        self,
        name: str = "fake",
        configured: bool = True,
        results: list[ChannelResult] | None = None,
    ) -> None:
        self.name = name
        self._configured = configured
        self._results = list(results or [])
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def is_configured(self) -> bool:
        return self._configured

    def send(self, notification: dict[str, Any], context: dict[str, Any] | None = None) -> ChannelResult:
        self.calls.append(dict(notification))
        if self._results:
            return self._results.pop(0)
        return ChannelResult(delivered=True)

    def close(self) -> None:
        self.closed = True


def payload_bytes(payload: dict[str, Any], max_bytes: int = 65536) -> bytes:
    """Serialize a webhook payload with an explicit size bound."""
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if len(raw) > max_bytes:
        raise ValueError(f"webhook payload too large ({len(raw)} > {max_bytes})")
    return raw


__all__ = [
    "ERROR_AUTH",
    "ERROR_CLIENT",
    "ERROR_CONNECTION",
    "ERROR_NOT_CONFIGURED",
    "ERROR_RATE_LIMITED",
    "ERROR_SERVER",
    "ERROR_TIMEOUT",
    "ERROR_UNKNOWN",
    "ChannelAdapter",
    "ChannelResult",
    "FakeChannelAdapter",
    "build_webhook_payload",
    "categorize_http_error",
    "categorize_smtp_error",
    "payload_bytes",
    "sign_webhook_payload",
]
