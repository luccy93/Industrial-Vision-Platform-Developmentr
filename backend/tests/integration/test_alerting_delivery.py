"""Delivery worker tests — adapters, retries, crash recovery (V15)."""

from __future__ import annotations

from typing import Any

import httpx

from backend.app.alerting.channels import (
    FakeChannelAdapter,
)
from backend.app.alerting.delivery import (
    DeliveryWorker,
    SmtpChannelAdapter,
    WebhookChannelAdapter,
)
from backend.app.alerting.repository import AlertRepository
from backend.app.infrastructure.db import get_session_factory, init_db


def _repo(url: str) -> AlertRepository:
    return AlertRepository(get_session_factory(url))


def _notification(repo: AlertRepository, rule_id: str, source: str = "evt-1") -> str:
    created = repo.create_notification(
        rule_id=rule_id,
        source_event_id=source,
        source_domain="SAFETY",
        event_type="CROWD_WARNING",
        title="t",
        severity="HIGH",
    )
    assert created is not None
    return str(created.id)


def _rule(repo: AlertRepository, **overrides: Any) -> str:
    params: dict[str, Any] = {"name": "R", "channels": ["in_app"]}
    params.update(overrides)
    return str(repo.create_rule(**params).id)


def _worker(url: str, adapters: dict[str, Any] | None = None, **overrides: Any) -> DeliveryWorker:
    params: dict[str, Any] = {
        "alert_repository": _repo(url),
        "adapters": adapters,
        "poll_interval_seconds": 3600.0,
    }
    params.update(overrides)
    return DeliveryWorker(**params)


def test_in_app_delivery_completes(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/delivery.db"
    init_db(url)
    repo = _repo(url)
    rule_id = _rule(repo)
    notification_id = _notification(repo, rule_id)
    repo.ensure_delivery(notification_id=notification_id, channel="in_app")
    worker = _worker(url)
    stats = worker.drain_once()
    assert stats == {"claimed": 1, "delivered": 1, "retried": 0, "terminal": 0, "skipped": 0}
    assert repo.delivery_counts() == {"sent": 1}
    assert worker.delivery_stats() == {"delivered": 1, "failed": 0}


def test_unconfigured_channel_terminal_never_silent(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/delivery.db"
    init_db(url)
    repo = _repo(url)
    rule_id = _rule(repo, channels=["email"])
    notification_id = _notification(repo, rule_id)
    repo.ensure_delivery(notification_id=notification_id, channel="email")
    worker = _worker(url, adapters={"email": FakeChannelAdapter(configured=False)})
    stats = worker.drain_once()
    assert stats["terminal"] == 1
    items, _ = repo.list_deliveries(notification_id=notification_id)
    assert items[0].status.value == "failed"
    assert items[0].last_error == "not_configured"


def test_retryable_then_terminal(tmp_path) -> None:
    from backend.app.alerting.channels import ChannelResult

    url = f"sqlite:///{tmp_path}/delivery.db"
    init_db(url)
    repo = _repo(url)
    rule_id = _rule(repo, channels=["webhook"])
    notification_id = _notification(repo, rule_id)
    repo.ensure_delivery(
        notification_id=notification_id, channel="webhook", destination="https://ops.example.com/hook"
    )
    fake = FakeChannelAdapter(
        name="webhook",
        results=[
            ChannelResult(delivered=False, retryable=True, error_category="timeout"),
            ChannelResult(delivered=False, retryable=True, error_category="timeout"),
            ChannelResult(delivered=True),
        ],
    )
    worker = _worker(url, adapters={"webhook": fake}, max_attempts=5, retry_base_seconds=0.1)
    assert worker.drain_once()["retried"] == 1
    # Immediate redrain is throttled by backoff; force due with explicit now.
    from datetime import timedelta

    from backend.app.domain.common import utcnow

    future = utcnow() + timedelta(hours=1)
    assert worker.drain_once(now=future)["retried"] == 1
    assert worker.drain_once(now=future + timedelta(hours=1))["delivered"] == 1
    assert repo.delivery_counts() == {"sent": 1}


def test_max_attempts_terminal(tmp_path) -> None:
    from datetime import timedelta

    from backend.app.alerting.channels import ChannelResult
    from backend.app.domain.common import utcnow

    url = f"sqlite:///{tmp_path}/delivery.db"
    init_db(url)
    repo = _repo(url)
    rule_id = _rule(repo, channels=["webhook"])
    notification_id = _notification(repo, rule_id)
    repo.ensure_delivery(
        notification_id=notification_id, channel="webhook", destination="https://ops.example.com/hook"
    )
    fake = FakeChannelAdapter(
        name="webhook",
        results=[ChannelResult(delivered=False, retryable=True, error_category="timeout")] * 10,
    )
    worker = _worker(url, adapters={"webhook": fake}, max_attempts=2, retry_base_seconds=0.1)
    assert worker.drain_once()["retried"] == 1
    stats = worker.drain_once(now=utcnow() + timedelta(hours=1))
    assert stats["terminal"] == 1
    assert repo.delivery_counts() == {"failed": 1}
    assert worker.delivery_stats()["failed"] == 1


def test_permanent_failure_no_retry(tmp_path) -> None:
    from backend.app.alerting.channels import ChannelResult

    url = f"sqlite:///{tmp_path}/delivery.db"
    init_db(url)
    repo = _repo(url)
    rule_id = _rule(repo, channels=["webhook"])
    notification_id = _notification(repo, rule_id)
    repo.ensure_delivery(
        notification_id=notification_id, channel="webhook", destination="https://ops.example.com/hook"
    )
    fake = FakeChannelAdapter(
        name="webhook",
        results=[ChannelResult(delivered=False, retryable=False, error_category="invalid_request")],
    )
    worker = _worker(url, adapters={"webhook": fake})
    stats = worker.drain_once()
    assert stats["terminal"] == 1
    assert stats["retried"] == 0


def test_crash_after_accept_redelivers_safely(tmp_path) -> None:
    """Adapter accepted but outcome never persisted → redelivery works."""
    url = f"sqlite:///{tmp_path}/delivery.db"
    init_db(url)
    repo = _repo(url)
    rule_id = _rule(repo)
    notification_id = _notification(repo, rule_id)
    delivery = repo.ensure_delivery(notification_id=notification_id, channel="in_app")
    # Crash window: the row stays pending; the next drain completes it.
    worker = _worker(url)
    assert worker.drain_once()["delivered"] == 1
    assert repo.get_delivery(str(delivery.id)) is not None


def test_webhook_adapter_roundtrip_via_mock_transport(tmp_path) -> None:
    seen: list[dict[str, Any]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        seen.append(dict(request.headers))
        assert request.headers["content-type"] == "application/json"
        assert request.headers["X-IVP-Signature"] != ""
        return httpx.Response(200, json={"ok": True})

    transport = httpx.MockTransport(_handler)
    adapter = WebhookChannelAdapter(
        allowlist=["https://ops.example.com/hook"], secret="s3cret", transport=transport
    )
    assert adapter.is_configured() is True
    assert adapter.destinations() == ["https://ops.example.com/hook"]
    result = adapter.send(
        {"id": "n1", "title": "t", "message": "m"},
        {"destination": "https://ops.example.com/hook"},
    )
    assert result.delivered is True
    assert len(seen) == 1
    adapter.close()


def test_webhook_rejects_non_allowlisted_destination() -> None:
    adapter = WebhookChannelAdapter(allowlist=["https://ops.example.com/hook"])
    result = adapter.send({"id": "n1"}, {"destination": "https://evil.example.com/hook"})
    assert result.delivered is False
    assert result.retryable is False


def test_webhook_retryable_vs_terminal_statuses() -> None:
    def _adapter_for(status: int) -> WebhookChannelAdapter:
        def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, json={})

        return WebhookChannelAdapter(
            allowlist=["https://ops.example.com/hook"],
            transport=httpx.MockTransport(_handler),
        )

    retryable = _adapter_for(503).send({"id": "n"}, {"destination": "https://ops.example.com/hook"})
    assert retryable.delivered is False and retryable.retryable is True
    assert retryable.error_category == "provider_error"
    terminal = _adapter_for(404).send({"id": "n"}, {"destination": "https://ops.example.com/hook"})
    assert terminal.delivered is False and terminal.retryable is False
    limited = _adapter_for(429).send({"id": "n"}, {"destination": "https://ops.example.com/hook"})
    assert limited.retryable is True and limited.error_category == "rate_limited"


def test_smtp_adapter_with_fake_server(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    sent: list[Any] = []
    logins: list[Any] = []

    class _FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float = 10.0) -> None:
            assert host == "smtp.example.com" and port == 587
            self.host = host

        def ehlo(self) -> None:
            return None

        def starttls(self, context: Any = None) -> None:
            return None

        def login(self, username: str, password: str) -> None:
            logins.append((username, password))

        def send_message(self, message: Any) -> None:
            sent.append(message)

        def quit(self) -> None:
            return None

    import smtplib

    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    adapter = SmtpChannelAdapter(
        host="smtp.example.com",
        port=587,
        tls_mode="starttls",
        username="bot",
        password="s3cret",
        sender="ivp@example.com",
        recipients=["ops@example.com"],
    )
    assert adapter.is_configured() is True
    result = adapter.send({"id": "n1", "title": "Alert", "message": "body"})
    assert result.delivered is True
    assert logins == [("bot", "s3cret")]
    assert len(sent) == 1
    assert sent[0]["To"] == "ops@example.com"


def test_smtp_failure_categorized_no_secrets(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import smtplib
    import ssl

    class _BoomSMTP:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            raise ssl.SSLError("certificate verify hunter2")

    monkeypatch.setattr(smtplib, "SMTP", _BoomSMTP)
    adapter = SmtpChannelAdapter(host="smtp.example.com", sender="a@b.c", recipients=["c@d.e"])
    result = adapter.send({"id": "n1"})
    assert result.delivered is False
    assert "hunter2" not in (result.error_category or "")
    assert result.error_category in ("connection_failed", "unknown_error", "timeout")


def test_worker_lifecycle_and_shutdown(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/delivery.db"
    init_db(url)
    worker = _worker(url, poll_interval_seconds=3600.0)
    assert worker.health().state.value == "CREATED"
    assert worker.start() is True
    assert worker.start() is True
    assert worker.health().state.value == "RUNNING"
    assert worker.stop() is True
    assert worker.stop() is True
    assert worker.health().state.value == "STOPPED"


def test_failed_email_does_not_hide_in_app(tmp_path) -> None:
    """Channel failures are independent: in-app stays visible."""
    url = f"sqlite:///{tmp_path}/delivery.db"
    init_db(url)
    repo = _repo(url)
    rule_id = _rule(repo, channels=["in_app", "email"])
    notification_id = _notification(repo, rule_id)
    repo.ensure_delivery(notification_id=notification_id, channel="in_app")
    repo.ensure_delivery(notification_id=notification_id, channel="email")
    worker = _worker(
        url, adapters={"email": FakeChannelAdapter(name="email", configured=False)}
    )
    stats = worker.drain_once()
    assert stats["delivered"] == 1  # in-app
    assert stats["terminal"] == 1  # email unconfigured
    assert repo.get_notification(notification_id) is not None
