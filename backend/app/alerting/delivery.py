"""Channel delivery — worker, SMTP, webhook, in-app adapters (V15).

The :class:`DeliveryWorker` claims due delivery rows, invokes exactly
one adapter per row *outside* any database transaction, then persists
the outcome. Provider calls never run on inference, request, or event
hot paths — only on this worker's thread (or synchronously in tests via
:meth:`drain_once`).

Delivery semantics are at-least-once per channel: a crash after the
provider accepts but before success persists redelivers. SMTP and
generic webhooks may therefore receive duplicates; exactly-once across
external systems is never claimed.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta
from typing import Any

from backend.app.alerting.channels import (
    ERROR_NOT_CONFIGURED,
    ChannelAdapter,
    ChannelResult,
    build_webhook_payload,
    categorize_http_error,
    categorize_smtp_error,
    payload_bytes,
    sign_webhook_payload,
)
from backend.app.alerting.repository import AlertRepository
from backend.app.domain.common import utcnow
from backend.app.workers.base import ManagedWorker, WorkerState

logger = logging.getLogger("industrial-vision.alerting")


class InAppChannelAdapter(ChannelAdapter):
    """In-app delivery: the notification row itself is the delivery."""

    name = "in_app"

    def is_configured(self) -> bool:
        return True

    def send(self, notification: dict[str, Any], context: dict[str, Any] | None = None) -> ChannelResult:
        return ChannelResult(delivered=True)


class SmtpChannelAdapter(ChannelAdapter):
    """SMTP email delivery over stdlib smtplib (optional channel)."""

    name = "email"

    def __init__(
        self,
        *,
        host: str = "",
        port: int = 587,
        tls_mode: str = "starttls",
        username: str = "",
        password: str = "",
        sender: str = "",
        recipients: list[str] | None = None,
        timeout_seconds: float = 10.0,
    ) -> None:
        self._host = str(host or "").strip()
        self._port = int(port)
        self._tls_mode = str(tls_mode or "starttls").strip().lower()
        self._username = str(username or "")
        self._password = str(password or "")
        self._sender = str(sender or "").strip()
        self._recipients = [str(r).strip() for r in (recipients or []) if str(r).strip()]
        self._timeout = max(1.0, float(timeout_seconds))

    def is_configured(self) -> bool:
        return bool(self._host and self._sender and self._recipients)

    def send(self, notification: dict[str, Any], context: dict[str, Any] | None = None) -> ChannelResult:
        if not self.is_configured():
            return ChannelResult(delivered=False, retryable=False, error_category=ERROR_NOT_CONFIGURED)
        import smtplib
        from email.message import EmailMessage

        base_url = ""
        if context:
            base_url = str(context.get("app_base_url", "") or "").rstrip("/")
        lines = [
            f"[{notification.get('severity', 'UNKNOWN')}] {notification.get('title', '')}",
            "",
            str(notification.get("message", "")),
            "",
            f"Rule: {notification.get('rule_id', '')}",
            f"Event: {notification.get('source_event_id', '')}",
        ]
        incident_id = notification.get("incident_id")
        if base_url and incident_id:
            lines.append(f"Incident: {base_url}/incidents/{incident_id}")
        message = EmailMessage()
        message["Subject"] = f"[Industrial Vision] {notification.get('title', 'alert')}"[:256]
        message["From"] = self._sender
        message["To"] = ", ".join(self._recipients)
        message.set_content("\n".join(lines)[:8000])
        server = None
        try:
            server = smtplib.SMTP(self._host, self._port, timeout=self._timeout)
            server.ehlo()
            if self._tls_mode == "starttls":
                import ssl as _ssl

                server.starttls(context=_ssl.create_default_context())
                server.ehlo()
            elif self._tls_mode not in ("ssl", "none"):
                return ChannelResult(delivered=False, retryable=False, error_category=ERROR_NOT_CONFIGURED)
            if self._tls_mode == "ssl":
                # Reconnect under SSL when STARTTLS was not the mode.
                try:
                    server.quit()
                except Exception:
                    pass
                import ssl as _ssl

                server = smtplib.SMTP_SSL(
                    self._host, self._port, timeout=self._timeout, context=_ssl.create_default_context()
                )
                server.ehlo()
            if self._username:
                server.login(self._username, self._password)
            server.send_message(message)
            return ChannelResult(delivered=True)
        except Exception as exc:
            category, retryable = categorize_smtp_error(exc)
            return ChannelResult(delivered=False, retryable=retryable, error_category=category)
        finally:
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    pass


class WebhookChannelAdapter(ChannelAdapter):
    """Generic HTTPS webhook delivery over httpx (optional channel)."""

    name = "webhook"

    def __init__(
        self,
        *,
        allowlist: list[str] | None = None,
        secret: str = "",
        timeout_seconds: float = 10.0,
        max_payload_bytes: int = 65536,
        transport: Any = None,
    ) -> None:
        self._allowlist = [str(u).strip() for u in (allowlist or []) if str(u).strip()]
        self._secret = str(secret or "")
        self._timeout = max(1.0, float(timeout_seconds))
        self._max_payload = max(1024, int(max_payload_bytes))
        self._transport = transport
        self._client: Any = None
        self._lock = threading.RLock()

    def is_configured(self) -> bool:
        return len(self._allowlist) > 0

    def destinations(self) -> list[str]:
        return list(self._allowlist[:5])

    def send(self, notification: dict[str, Any], context: dict[str, Any] | None = None) -> ChannelResult:
        destination = str((context or {}).get("destination", "") or "")
        if not self.is_configured():
            return ChannelResult(delivered=False, retryable=False, error_category=ERROR_NOT_CONFIGURED)
        if destination not in self._allowlist:
            # A destination outside the allowlist is a configuration error,
            # never an implicit fetch of an arbitrary URL (SSRF guard).
            return ChannelResult(delivered=False, retryable=False, error_category=ERROR_NOT_CONFIGURED)
        try:
            payload = build_webhook_payload(notification)
            raw = payload_bytes(payload, self._max_payload)
        except ValueError:
            return ChannelResult(delivered=False, retryable=False, error_category="oversize")
        import httpx

        with self._lock:
            if self._client is None:
                self._client = httpx.Client(
                    timeout=httpx.Timeout(self._timeout),
                    follow_redirects=False,
                    transport=self._transport,
                )
            client = self._client
        headers = {"Content-Type": "application/json"}
        signature = sign_webhook_payload(self._secret, raw)
        if signature:
            headers["X-IVP-Signature"] = signature
        try:
            response = client.post(destination, content=raw, headers=headers)
        except Exception as exc:
            name = type(exc).__name__
            if "Timeout" in name:
                category, retryable = categorize_http_error(status=None, timeout=True)
            elif "Connect" in name or "Network" in name or "DNS" in name or "Resolve" in name:
                category, retryable = categorize_http_error(status=None, connection=True)
            else:
                category, retryable = categorize_http_error(status=None)
            return ChannelResult(delivered=False, retryable=retryable, error_category=category)
        try:
            # Bounded response drain; body content is never stored or logged.
            _ = response.read() if hasattr(response, "read") else response.content
        except Exception:
            pass
        category, retryable = categorize_http_error(status=response.status_code)
        if 200 <= response.status_code <= 299:
            return ChannelResult(delivered=True)
        return ChannelResult(delivered=False, retryable=retryable, error_category=category)

    def close(self) -> None:
        with self._lock:
            client, self._client = self._client, None
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


class DeliveryWorker(ManagedWorker):
    """Supervised per-channel delivery with bounded retries (V15 §9)."""

    def __init__(
        self,
        *,
        name: str = "alerting-delivery",
        alert_repository: AlertRepository,
        adapters: dict[str, ChannelAdapter] | None = None,
        batch_size: int = 50,
        max_attempts: int = 8,
        retry_base_seconds: float = 30.0,
        poll_interval_seconds: float = 5.0,
        app_base_url: str = "",
    ) -> None:
        super().__init__(name)
        self._alerts = alert_repository
        self._adapters: dict[str, ChannelAdapter] = dict(adapters or {})
        self._adapters.setdefault("in_app", InAppChannelAdapter())
        self._batch_size = max(1, int(batch_size))
        self._max_attempts = max(1, int(max_attempts))
        self._retry_base = max(1.0, float(retry_base_seconds))
        self._poll_interval = max(0.5, float(poll_interval_seconds))
        self._app_base_url = str(app_base_url or "").rstrip("/")
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
        self._thread = threading.Thread(target=self._loop, name=f"alert-{self.worker_name}", daemon=True)
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
        for adapter in list(self._adapters.values()):
            try:
                adapter.close()
            except Exception:
                pass
        try:
            self._transition(WorkerState.STOPPED)
        except ValueError:
            pass
        return True

    def _loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    self.drain_once()
                except Exception as exc:
                    self._record_failure(f"{type(exc).__name__}: {exc}")
                    logger.warning("alert delivery cycle failed: %s", type(exc).__name__)
                self._stop_event.wait(self._poll_interval)
        except Exception as exc:
            self._record_failure(f"{type(exc).__name__}: {exc}")
            with self._state_lock:
                try:
                    self._transition(WorkerState.FAILED)
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------
    def drain_once(self, now: datetime | None = None) -> dict[str, int]:
        """Claim due rows and deliver one batch. Sync; tests drive this."""
        reference = now or utcnow()
        stats = {"claimed": 0, "delivered": 0, "retried": 0, "terminal": 0, "skipped": 0}
        try:
            due = self._alerts.claim_due_deliveries(limit=self._batch_size, now=reference)
        except Exception as exc:
            logger.warning("delivery claim failed: %s", type(exc).__name__)
            return stats
        stats["claimed"] = len(due)
        for row in due:
            self._deliver_row(row, reference, stats)
        self._report_heartbeat()
        return stats

    def _deliver_row(self, row: Any, now: datetime, stats: dict[str, int]) -> None:
        channel = row.channel.value if hasattr(row.channel, "value") else str(row.channel)
        adapter = self._adapters.get(channel)
        if adapter is None or not adapter.is_configured():
            # Unconfigured channel: terminal, visible, never silent success.
            self._alerts.mark_delivery(str(row.id), status="failed", error=ERROR_NOT_CONFIGURED)
            stats["terminal"] += 1
            self._failed += 1
            return
        notification = self._notification_payload(row.notification_id)
        if notification is None:
            self._alerts.mark_delivery(str(row.id), status="failed", error="notification_missing")
            stats["terminal"] += 1
            self._failed += 1
            return
        if self._is_muted(notification, now):
            # V16 operator mute: leave pending, no attempt consumed.
            stats["skipped"] += 1
            return
        try:
            result = adapter.send(
                notification,
                {"destination": row.destination, "app_base_url": self._app_base_url},
            )
        except Exception as exc:
            logger.warning("adapter raised unexpectedly: %s", type(exc).__name__)
            result = ChannelResult(delivered=False, retryable=True, error_category="unknown_error")
        if result.delivered:
            self._alerts.mark_delivery(str(row.id), status="sent", delivered=True)
            stats["delivered"] += 1
            self._delivered += 1
            return
        attempts = int(row.attempts or 0) + 1
        if not result.retryable or attempts >= self._max_attempts:
            self._alerts.mark_delivery(
                str(row.id), status="failed", error=result.error_category or "unknown_error"
            )
            stats["terminal"] += 1
            self._failed += 1
            logger.warning("delivery terminal channel=%s error=%s", row.channel, result.error_category)
        else:
            backoff = self._retry_base * (2.0 ** min(attempts, 6))
            # Bounded jitter keeps stampedes down without breaking determinism badly.
            backoff = backoff * (0.8 + 0.4 * ((attempts * 2654435761) % 100) / 100.0)
            self._alerts.mark_delivery(
                str(row.id),
                status="pending",
                error=result.error_category,
                next_retry_at=now + timedelta(seconds=backoff),
            )
            stats["retried"] += 1

    def _is_muted(self, notification: dict[str, Any], now: datetime) -> bool:
        """True while a V16 operator mute window is in effect."""
        muted_until = notification.get("muted_until")
        if muted_until is None:
            return False
        if isinstance(muted_until, str):
            try:
                muted_until = datetime.fromisoformat(muted_until)
            except ValueError:
                return False
        if muted_until.tzinfo is None:
            muted_until = muted_until.replace(tzinfo=now.tzinfo)
        try:
            return bool(muted_until > now)
        except TypeError:
            return False

    def _notification_payload(self, notification_id: str) -> dict[str, Any] | None:
        notification = self._alerts.get_notification(str(notification_id))
        if notification is None:
            return None
        muted = notification.muted_until
        return {
            "id": str(notification.id),
            "rule_id": str(notification.rule_id),
            "source_event_id": notification.source_event_id,
            "event_type": notification.event_type,
            "severity": notification.severity,
            "priority": notification.priority,
            "camera_id": notification.camera_id,
            "incident_id": notification.incident_id,
            "title": notification.title,
            "message": notification.message,
            "created_at": notification.created_at.isoformat() if notification.created_at else None,
            "muted_until": muted.isoformat() if muted else None,
        }

    def delivery_stats(self) -> dict[str, int]:
        with self._state_lock:
            return {"delivered": self._delivered, "failed": self._failed}


__all__ = [
    "DeliveryWorker",
    "InAppChannelAdapter",
    "SmtpChannelAdapter",
    "WebhookChannelAdapter",
]
