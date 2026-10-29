"""Alert evaluation tests — matching, cooldown, watermarks, recovery (V15)."""

from __future__ import annotations

from datetime import timedelta
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.alerting.evaluator import AlertingEvaluator
from backend.app.alerting.repository import AlertRepository
from backend.app.domain.common import utcnow
from backend.app.events.store import OperationalEventRepository


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def _repos(client: TestClient) -> tuple[AlertRepository, OperationalEventRepository]:
    state = _state(client)
    return (
        AlertRepository(state.session_factory),
        OperationalEventRepository(state.session_factory),
    )


def _rule(client: TestClient, **overrides: Any) -> dict[str, Any]:
    payload = {"name": "R", "channels": ["in_app"]}
    payload.update(overrides)
    res = client.post("/api/v1/alerting/rules", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def _seed_event(
    client: TestClient,
    event_id: str = "evt-1",
    event_type: str = "CROWD_WARNING",
    severity: str = "HIGH",
    camera_id: str = "cam-01",
    domain: str = "SAFETY",
    day_offset: int = 0,
) -> None:
    _, events = _repos(client)
    timestamp = utcnow() + timedelta(days=day_offset)
    events.upsert_event(
        event_id=event_id,
        camera_id=camera_id,
        source_domain=domain,
        source_event_id=f"src-{event_id}",
        event_type=event_type,
        severity=severity,
        status="ACTIVE",
        first_seen=timestamp,
        last_seen=timestamp,
    )


def _evaluator(client: TestClient, **overrides: Any) -> AlertingEvaluator:
    alerts, events = _repos(client)
    params: dict[str, Any] = {
        "alert_repository": alerts,
        "operational_repository": events,
        "poll_interval_seconds": 3600.0,
    }
    params.update(overrides)
    return AlertingEvaluator(**params)


def test_event_match_creates_notification_and_delivery(client: TestClient) -> None:
    rule = _rule(client, domains=["SAFETY"], min_severity="HIGH")
    _seed_event(client)
    evaluator = _evaluator(client)
    stats = evaluator.drain_once()
    assert stats["notified"] == 1
    assert stats["suppressed"] == 0
    body = client.get("/api/v1/alerting/notifications").json()
    assert body["total"] == 1
    item = body["notifications"][0]
    assert item["rule_id"] == rule["id"]
    assert item["severity"] == "HIGH"
    assert item["camera_id"] == "cam-01"
    detail = client.get(f"/api/v1/alerting/notifications/{item['id']}").json()
    assert len(detail["deliveries"]) == 1
    assert detail["deliveries"][0]["channel"] == "in_app"


def test_disabled_and_nonmatching_rules_silent(client: TestClient) -> None:
    _rule(client, domains=["SAFETY"], min_severity="CRITICAL")
    _seed_event(client, severity="HIGH")
    evaluator = _evaluator(client)
    stats = evaluator.drain_once()
    assert stats["notified"] == 0
    assert client.get("/api/v1/alerting/notifications").json()["total"] == 0
    state = _state(client)
    from backend.app.alerting.repository import AlertRepository as _Repo

    repo = _Repo(state.session_factory)
    rules, _ = repo.list_rules()
    repo.update_rule(str(rules[0].id), enabled=False)
    _seed_event(client, event_id="evt-2", severity="CRITICAL")
    stats = evaluator.drain_once()
    assert stats["notified"] == 0


def test_duplicate_delivery_is_noop(client: TestClient) -> None:
    from backend.app.alerting.evaluator import EVENTS_CONSUMER

    _rule(client)
    _seed_event(client)
    evaluator = _evaluator(client)
    first = evaluator.drain_once()
    assert first["notified"] == 1
    second = evaluator.drain_once()
    assert second["notified"] == 0
    assert client.get("/api/v1/alerting/notifications").json()["total"] == 1
    # Simulate redelivery (cursor rewind, e.g. restart before advance):
    # the same pair collapses on the evaluation UNIQUE constraint.
    state = _state(client)
    from backend.app.alerting.repository import AlertRepository as _Repo

    _Repo(state.session_factory).advance_cursor(EVENTS_CONSUMER, None, None)
    third = evaluator.drain_once()
    assert third["notified"] == 0
    assert third["duplicates"] >= 1
    assert client.get("/api/v1/alerting/notifications").json()["total"] == 1


def test_incident_transition_match(client: TestClient) -> None:
    rule = _rule(client, incident_statuses=["RESOLVED"])
    res = client.post("/api/v1/incidents", json={"title": "t", "priority": "P2"})
    incident_id = res.json()["incident"]["id"]
    res = client.post(f"/api/v1/incidents/{incident_id}/resolve", json={"reason": "OPERATOR_ACTION"})
    assert res.status_code == 200
    evaluator = _evaluator(client)
    stats = evaluator.drain_once()
    assert stats["notified"] == 1
    assert stats["transitions_scanned"] >= 1
    body = client.get("/api/v1/alerting/notifications").json()
    assert body["total"] == 1
    assert body["notifications"][0]["incident_id"] == incident_id
    assert body["notifications"][0]["rule_id"] == rule["id"]


def test_cooldown_rule_scope_suppresses_with_record(client: TestClient) -> None:
    _rule(client, cooldown_seconds=3600)
    _seed_event(client, event_id="evt-1")
    _seed_event(client, event_id="evt-2")
    evaluator = _evaluator(client)
    stats = evaluator.drain_once()
    assert stats["notified"] == 1
    assert stats["suppressed"] == 1
    state = _state(client)
    from backend.app.alerting.repository import AlertRepository as _Repo

    repo = _Repo(state.session_factory)
    assert len(repo.recent_suppressions()) == 1
    rules, _ = repo.list_rules()
    assert rules[0].suppressed_count == 1
    assert rules[0].trigger_count == 1
    assert client.get("/api/v1/alerting/notifications").json()["total"] == 1


def test_cooldown_rule_camera_scope_independent(client: TestClient) -> None:
    from backend.app.alerting.repository import AlertRepository as _Repo

    rule = _rule(client, cooldown_seconds=3600)
    state = _state(client)
    repo = _Repo(state.session_factory)
    updated = repo.update_rule(str(rule["id"]), suppression_scope="RULE_CAMERA")
    assert updated is not None
    _seed_event(client, event_id="evt-1", camera_id="cam-01")
    _seed_event(client, event_id="evt-2", camera_id="cam-02")
    evaluator = _evaluator(client)
    stats = evaluator.drain_once()
    assert stats["notified"] == 2
    assert stats["suppressed"] == 0
    _seed_event(client, event_id="evt-3", camera_id="cam-01")
    stats = evaluator.drain_once()
    assert stats["notified"] == 0
    assert stats["suppressed"] == 1


def test_watermark_restart_recovery(client: TestClient) -> None:
    _rule(client)
    _seed_event(client, event_id="evt-1")
    first = _evaluator(client)
    assert first.drain_once()["notified"] == 1
    # A fresh worker over the same database resumes past the watermark.
    second = _evaluator(client)
    stats = second.drain_once()
    assert stats["notified"] == 0
    assert client.get("/api/v1/alerting/notifications").json()["total"] == 1


def test_watermark_window_includes_event_at_reference_time(client: TestClient) -> None:
    _rule(client)
    _, events = _repos(client)
    timestamp = utcnow()
    events.upsert_event(
        event_id="evt-boundary",
        camera_id="cam-01",
        source_domain="SAFETY",
        source_event_id="src-evt-boundary",
        event_type="CROWD_WARNING",
        severity="HIGH",
        status="ACTIVE",
        first_seen=timestamp,
        last_seen=timestamp,
    )
    evaluator = _evaluator(client)
    stats = evaluator.drain_once(now=timestamp)
    assert stats["events_scanned"] == 1
    assert stats["notified"] == 1
    assert client.get("/api/v1/alerting/notifications").json()["total"] == 1


def test_bounded_batches_and_storm_cap(client: TestClient) -> None:
    _rule(client)
    for index in range(5):
        _seed_event(client, event_id=f"evt-{index}")
    evaluator = _evaluator(client, batch_size=2, max_notifications_per_cycle=10)
    first = evaluator.drain_once()
    assert first["events_scanned"] == 2
    second = evaluator.drain_once()
    assert second["events_scanned"] == 2
    third = evaluator.drain_once()
    assert third["events_scanned"] == 1
    assert client.get("/api/v1/alerting/notifications").json()["total"] == 5


def test_storm_cap_defers_without_loss(client: TestClient) -> None:
    _rule(client)
    for index in range(3):
        _seed_event(client, event_id=f"evt-{index}")
    evaluator = _evaluator(client, batch_size=10, max_notifications_per_cycle=1)
    first = evaluator.drain_once()
    assert first["notified"] == 1
    assert first["capped"] == 1
    second = evaluator.drain_once()
    assert second["notified"] == 1
    assert second["capped"] == 1
    third = evaluator.drain_once()
    assert third["notified"] == 1
    assert third["capped"] == 0
    assert client.get("/api/v1/alerting/notifications").json()["total"] == 3


def test_manager_mutations_record_transitions(client: TestClient) -> None:
    from backend.app.alerting.repository import AlertRepository as _Repo

    state = _state(client)
    repo = _Repo(state.session_factory)
    res = client.post("/api/v1/incidents", json={"title": "t"})
    incident_id = res.json()["incident"]["id"]
    assert len(repo.list_transitions_since(None, None)) == 1  # CREATED
    client.post(f"/api/v1/incidents/{incident_id}/acknowledge", json={})
    types = [t.transition_type for t in repo.list_transitions_since(None, None)]
    assert types == ["CREATED", "ACKNOWLEDGED"]
    # Rejected transitions record nothing.
    res = client.post(f"/api/v1/incidents/{incident_id}/acknowledge", json={})
    assert res.status_code == 409
    assert len(repo.list_transitions_since(None, None)) == 2


def test_evaluator_lifecycle(client: TestClient) -> None:
    from backend.app.workers.base import WorkerState

    state = _state(client)
    evaluator = state.alerting_evaluator
    assert evaluator.health().state is WorkerState.CREATED
    assert evaluator.start() is True
    assert evaluator.start() is True
    assert evaluator.health().state is WorkerState.RUNNING
    assert evaluator.stop() is True
    assert evaluator.stop() is True
    assert evaluator.health().state is WorkerState.STOPPED
    assert state.alerting_delivery.health().state is WorkerState.CREATED


def test_health_reports_alerting_component(client: TestClient) -> None:
    body = client.get("/api/v1/health").json()
    components = {c["component"]: c for c in body["components"]}
    assert "alerting" in components
    assert components["alerting"]["status"] == "DISABLED"
    assert "password" not in str(body).lower()


def test_readiness_ignores_alerting(client: TestClient) -> None:
    body = client.get("/ready").json()
    assert body["ready"] is True
    assert "alerting" not in body.get("readiness", {}).get("checks", {})
