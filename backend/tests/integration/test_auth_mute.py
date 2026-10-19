"""Operator notification mute — endpoint, worker skip, expiry (V16)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.alerting.channels import FakeChannelAdapter
from backend.app.alerting.delivery import DeliveryWorker
from backend.app.alerting.repository import AlertRepository
from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user


def _setup(tmp_path: Any) -> tuple[AlertRepository, str]:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/mute.db"
    init_db(url)
    repo = AlertRepository(get_session_factory(url))
    rule_id = str(repo.create_rule(name="R", channels=["in_app"]).id)
    created = repo.create_notification(
        rule_id=rule_id,
        source_event_id="evt-mute",
        source_domain="SAFETY",
        event_type="CROWD_WARNING",
        title="t",
        severity="HIGH",
    )
    assert created is not None
    repo.ensure_delivery(notification_id=str(created.id), channel="in_app")
    return repo, str(created.id)


def test_mute_skips_delivery_then_auto_restores(tmp_path: Any) -> None:  # type: ignore[no-untyped-def]
    repo, notification_id = _setup(tmp_path)
    now = datetime.now(UTC)
    muted = repo.mute_notification(notification_id, now + timedelta(minutes=30))
    assert muted is not None and muted.muted_until is not None
    worker = DeliveryWorker(alert_repository=repo, poll_interval_seconds=3600.0)
    stats = worker.drain_once(now=now)
    assert stats["claimed"] == 1
    assert stats["skipped"] == 1
    assert stats["delivered"] == 0
    pending, _ = repo.list_deliveries()
    assert pending[0].status.value == "pending"
    # After expiry the same row delivers normally.
    stats = worker.drain_once(now=now + timedelta(hours=1))
    assert stats["delivered"] == 1
    assert FakeChannelAdapter is not None


def test_mute_endpoint_roundtrip(client: Any) -> None:
    from fastapi.testclient import TestClient

    url = str(client.app.state.settings.database_url)
    auth_repo = AuthRepository(get_session_factory(url))
    create_test_user(auth_repo, "op2@example.com", role=Role.OPERATOR)
    logged = TestClient(client.app)
    login = logged.post("/api/v1/auth/login", json={"email": "op2@example.com", "password": TEST_PASSWORD})
    assert login.status_code == 200, login.text
    logged.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    alerts = AlertRepository(get_session_factory(url))
    rule_id = str(alerts.create_rule(name="R", channels=["in_app"]).id)
    created = alerts.create_notification(rule_id=rule_id, source_event_id="evt-ep", title="t", message="m")
    assert created is not None
    res = logged.post(f"/api/v1/alerting/notifications/{created.id}/mute", json={"minutes": 60})
    assert res.status_code == 200, res.text
    assert res.json()["muted_until"] is not None
    assert (
        logged.post(f"/api/v1/alerting/notifications/{created.id}/mute", json={"minutes": 0}).status_code
        == 422
    )
    assert logged.post("/api/v1/alerting/notifications/missing/mute", json={"minutes": 10}).status_code == 404
