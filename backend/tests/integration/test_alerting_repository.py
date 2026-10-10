"""Alerting repository foundation tests — CRUD, uniqueness, cursors (V15)."""

from __future__ import annotations

from backend.app.alerting.repository import (
    AlertRepository,
    AlertRuleNotFoundError,
    DeliveryNotFoundError,
    NotificationNotFoundError,
)
from backend.app.alerting.schemas import AlertChannel
from backend.app.infrastructure.db import get_session_factory, init_db


def _repo(url: str) -> AlertRepository:
    return AlertRepository(get_session_factory(url))


def test_rule_crud(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/alerting.db"
    init_db(url)
    repo = _repo(url)
    rule = repo.create_rule(name="Critical safety", domains=["SAFETY"], channels=["in_app"])
    assert rule.enabled is True
    assert rule.domains == ["SAFETY"]
    assert repo.get_rule(str(rule.id)) is not None
    assert repo.get_rule("missing") is None
    updated = repo.update_rule(str(rule.id), enabled=False, cooldown_seconds=60)
    assert updated is not None and updated.enabled is False
    assert updated.cooldown_seconds == 60
    assert repo.update_rule("missing", enabled=True) is None
    rules, total = repo.list_rules()
    assert total == 1 and len(rules) == 1
    assert AlertRuleNotFoundError("x").rule_id == "x"
    assert NotificationNotFoundError("y").notification_id == "y"
    assert DeliveryNotFoundError("z").delivery_id == "z"


def test_notification_idempotent(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/alerting.db"
    init_db(url)
    repo = _repo(url)
    rule = repo.create_rule(name="R", channels=[AlertChannel.IN_APP])
    first = repo.create_notification(
        rule_id=str(rule.id), source_event_id="evt-1", title="t", severity="HIGH"
    )
    assert first is not None
    assert repo.create_notification(rule_id=str(rule.id), source_event_id="evt-1") is None
    assert repo.get_notification(str(first.id)) is not None
    items, total = repo.list_notifications()
    assert total == 1 and len(items) == 1


def test_delivery_lifecycle(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/alerting.db"
    init_db(url)
    repo = _repo(url)
    rule = repo.create_rule(name="R", channels=["email"])
    notification = repo.create_notification(rule_id=str(rule.id), source_event_id="e1")
    assert notification is not None
    first = repo.ensure_delivery(
        notification_id=str(notification.id), channel="email", destination="ops@example.com"
    )
    second = repo.ensure_delivery(
        notification_id=str(notification.id), channel="email", destination="ops@example.com"
    )
    assert first.id == second.id
    assert repo.get_delivery(str(first.id)) is not None
    assert repo.get_delivery("missing") is None
    due = repo.claim_due_deliveries(limit=10)
    assert len(due) == 1
    marked = repo.mark_delivery(str(first.id), status="sent", delivered=True)
    assert marked is not None and marked.status.value == "sent"
    assert repo.claim_due_deliveries(limit=10) == []
    assert repo.delivery_counts() == {"sent": 1}
    items, total = repo.list_deliveries(notification_id=str(notification.id))
    assert total == 1 and len(items) == 1


def test_transitions_evaluations_cursors(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/alerting.db"
    init_db(url)
    repo = _repo(url)
    rule = repo.create_rule(name="R", channels=["in_app"])
    transition = repo.record_transition(
        incident_id="i1", transition_type="RESOLVED", previous_state="OPEN", new_state="RESOLVED"
    )
    assert transition.incident_id == "i1"
    assert repo.get_cursor("evaluator") == (None, None)
    repo.advance_cursor("evaluator", transition.timestamp, str(transition.id))
    assert repo.get_cursor("evaluator")[1] == str(transition.id)
    rows = repo.list_transitions_since(None, None)
    assert len(rows) == 1
    evaluation = repo.record_evaluation(
        rule_id=str(rule.id), source_event_id=str(transition.id), outcome="NOTIFIED"
    )
    assert evaluation is not None
    assert (
        repo.record_evaluation(rule_id=str(rule.id), source_event_id=str(transition.id), outcome="NOTIFIED")
        is None
    )
    assert repo.get_evaluation(str(rule.id), str(transition.id)) is not None
    suppressed = repo.record_evaluation(
        rule_id=str(rule.id),
        source_event_id="evt-9",
        outcome="SUPPRESSED_COOLDOWN",
        suppression_reason="cooldown",
        suppression_scope="RULE",
    )
    assert suppressed is not None
    assert len(repo.recent_suppressions()) == 1
    assert repo.notification_counts() == {"total": 0}
    assert repo.delete_old_evaluations(transition.timestamp) == 0
