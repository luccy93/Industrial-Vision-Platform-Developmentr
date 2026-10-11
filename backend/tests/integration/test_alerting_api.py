"""Alerting API tests — rules, notifications, deliveries, envelopes (V15)."""

from __future__ import annotations

from fastapi.testclient import TestClient


def _rule(client: TestClient, **overrides) -> dict:  # type: ignore[no-untyped-def]
    payload = {"name": "Critical safety", "domains": ["SAFETY"], "channels": ["in_app"]}
    payload.update(overrides)
    res = client.post("/api/v1/alerting/rules", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def test_rule_crud_and_envelopes(client: TestClient) -> None:
    created = _rule(client)
    assert created["enabled"] is True
    assert created["trigger_count"] == 0
    rule_id = created["id"]
    res = client.get(f"/api/v1/alerting/rules/{rule_id}")
    assert res.status_code == 200
    assert res.json()["name"] == "Critical safety"
    assert client.get("/api/v1/alerting/rules/missing").status_code == 404
    res = client.patch(f"/api/v1/alerting/rules/{rule_id}", json={"enabled": False})
    assert res.status_code == 200
    assert res.json()["enabled"] is False
    assert client.patch("/api/v1/alerting/rules/missing", json={"enabled": True}).status_code == 404
    body = client.get("/api/v1/alerting/rules").json()
    assert body["total"] == 1
    assert set(body) == {"rules", "total", "page", "page_size"}


def test_rule_validation_rejects_unknowns(client: TestClient) -> None:
    res = client.post(
        "/api/v1/alerting/rules",
        json={"name": "Bad", "domains": ["TRACKING"], "channels": ["in_app"]},
    )
    assert res.status_code == 422
    assert res.json()["error"]["code"] == "validation_error"
    res = client.post(
        "/api/v1/alerting/rules",
        json={"name": "Bad", "event_types": ["FRAME_PROCESSED"], "channels": ["in_app"]},
    )
    assert res.status_code == 422
    res = client.post("/api/v1/alerting/rules", json={"name": "Bad", "channels": ["pagerduty"]})
    assert res.status_code == 422
    res = client.post("/api/v1/alerting/rules", json={"name": "Bad", "channels": []})
    assert res.status_code == 422
    created = _rule(client)
    res = client.patch(f"/api/v1/alerting/rules/{created['id']}", json={"channels": ["sms"]})
    assert res.status_code == 422


def test_notification_list_filters_and_pagination(client: TestClient) -> None:
    body = client.get("/api/v1/alerting/notifications").json()
    assert body == {"notifications": [], "total": 0, "page": 1, "page_size": 20}
    assert client.get("/api/v1/alerting/notifications/missing").status_code == 404
    body = client.get("/api/v1/alerting/deliveries").json()
    assert set(body) == {"deliveries", "total", "page", "page_size"}
    assert client.get("/api/v1/alerting/deliveries?channel=sms").status_code == 422
    assert client.get("/api/v1/alerting/deliveries?status=bogus").status_code == 422


def test_status_reports_honest_channels(client: TestClient) -> None:
    body = client.get("/api/v1/alerting/status").json()
    assert body["enabled"] is False
    assert body["channels"]["in_app"] == {"available": True}
    assert body["channels"]["email"] == {"available": False}
    assert body["channels"]["webhook"]["available"] is False
    assert "V16" in body["security_note"]
    for key in ("evaluator", "delivery_worker", "channels", "deliveries"):
        assert key in body


def test_manual_retry_idempotent(client: TestClient) -> None:
    assert client.post("/api/v1/alerting/deliveries/missing/retry").status_code == 404


def test_manual_retry_requeues_failed(client: TestClient) -> None:
    from typing import Any, cast

    from fastapi import FastAPI

    rule = _rule(client, channels=["email"])
    state = cast(FastAPI, cast(Any, client).app).state
    from backend.app.alerting.repository import AlertRepository

    repo = AlertRepository(state.session_factory)
    notification = repo.create_notification(rule_id=rule["id"], source_event_id="e1")
    assert notification is not None
    delivery = repo.ensure_delivery(notification_id=str(notification.id), channel="email")
    repo.mark_delivery(str(delivery.id), status="failed", error="timeout")
    res = client.post(f"/api/v1/alerting/deliveries/{delivery.id}/retry")
    assert res.status_code == 200
    body = res.json()
    assert body["retried"] is True
    assert body["status"] == "pending"
    # Retrying a pending record is a no-op, never a duplicate row.
    res = client.post(f"/api/v1/alerting/deliveries/{delivery.id}/retry")
    assert res.json()["retried"] is False
    _, total = repo.list_deliveries(notification_id=str(notification.id))
    assert total == 1


def test_api_responses_contain_no_secrets(client: TestClient) -> None:
    body = client.get("/api/v1/alerting/status").json()
    blob = str(body).lower()
    for token in ("password", "passwd"):
        assert token not in blob, token
