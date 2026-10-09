"""Operational event store tests — upsert, idempotency, outbox, retention."""

from __future__ import annotations

from datetime import timedelta

import pytest

from backend.app.domain.common import utcnow
from backend.app.events.store import OperationalEventRepository, OutboxRepository
from backend.app.infrastructure.db import get_session_factory, init_db


def _factories(url: str) -> tuple[OperationalEventRepository, OutboxRepository]:
    factory = get_session_factory(url)
    return OperationalEventRepository(factory), OutboxRepository(factory)


def _event(**overrides):  # type: ignore[no-untyped-def]
    fields: dict = {
        "event_id": "evt-1",
        "camera_id": "cam-01",
        "source_domain": "SAFETY",
        "source_event_id": "src-1",
        "event_type": "CROWD_WARNING",
        "severity": "HIGH",
        "risk_level": "MEDIUM",
        "risk_score": 0.5,
        "status": "ACTIVE",
        "metadata": {"note": "x"},
    }
    fields.update(overrides)
    return fields


def test_upsert_creates_then_updates(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/ops.db"
    init_db(url)
    events, _ = _factories(url)
    row, created = events.upsert_event(**_event())
    assert created is True
    assert row["severity"] == "HIGH"
    row, created = events.upsert_event(**_event(status="RESOLVED", risk_score=0.1))
    assert created is False
    assert row["status"] == "RESOLVED"
    assert row["risk_score"] == 0.1
    assert events.get_event("evt-1") is not None
    assert events.get_event("missing") is None


def test_same_source_identity_updates_in_place(tmp_path) -> None:
    """A re-issued event_id for a known source triple updates, not duplicates."""
    url = f"sqlite:///{tmp_path}/ops.db"
    init_db(url)
    events, _ = _factories(url)
    row, created = events.upsert_event(**_event(event_id="e-1", source_event_id="s-1"))
    assert created is True
    row, created = events.upsert_event(**_event(event_id="e-2", source_event_id="s-1", status="RESOLVED"))
    assert created is False
    assert row["status"] == "RESOLVED"
    # Still exactly one durable row: the first-seen identity is canonical.
    first = events.get_event("e-1")
    assert first is not None
    assert first["status"] == "RESOLVED"
    assert events.get_event("e-2") is None


def test_upsert_rejects_oversize_metadata(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/ops.db"
    init_db(url)
    events, _ = _factories(url)
    with pytest.raises(ValueError):
        events.upsert_event(**_event(metadata={"blob": "z" * 40000}))


def test_record_event_with_outbox_is_atomic(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/ops.db"
    init_db(url)
    events, outbox = _factories(url)
    envelope = {"v": 1, "event_id": "evt-9", "kind": "safety_event"}
    row, created, queued = outbox.record_event_with_outbox(
        events, kind="safety_event", envelope=envelope, **_event(event_id="evt-9")
    )
    assert created is True and queued is True
    assert row["event_id"] == "evt-9"
    assert outbox.count_by_status() == {"pending": 1}
    # Duplicate intent rolls back cleanly: existing intent already covers it.
    row, created, queued = outbox.record_event_with_outbox(
        events, kind="safety_event", envelope=envelope, **_event(event_id="evt-9")
    )
    assert created is False and queued is False
    assert outbox.count_by_status() == {"pending": 1}


def test_outbox_claim_mark_cycle(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/ops.db"
    init_db(url)
    _, outbox = _factories(url)
    assert outbox.enqueue("a", "safety_event", {"v": 1}) is True
    assert outbox.enqueue("a", "safety_event", {"v": 1}) is False
    assert outbox.enqueue("b", "risk_cluster", {"v": 1}) is True
    due = outbox.claim_due(limit=10)
    assert [d["event_id"] for d in due] == ["a", "b"]
    assert outbox.mark_sent(due[0]["id"]) is True
    assert outbox.mark_sent("missing") is False
    assert outbox.count_by_status() == {"pending": 1, "sent": 1}
    assert outbox.mark_failed(due[1]["id"], "boom") is True
    assert outbox.count_by_status()["failed"] == 1
    assert outbox.claim_due(limit=10) == []
    assert outbox.requeue_failed(due[1]["id"]) is True
    assert len(outbox.claim_due(limit=10)) == 1


def test_retention_cleanup_is_bounded(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/ops.db"
    init_db(url)
    events, outbox = _factories(url)
    old = utcnow() - timedelta(days=120)
    for index in range(5):
        events.upsert_event(
            **_event(event_id=f"old-{index}", source_event_id=f"src-old-{index}", last_seen=old)
        )
    events.upsert_event(**_event(event_id="fresh"))
    assert events.delete_older_than(utcnow() - timedelta(days=90), limit=2) == 2
    assert events.delete_older_than(utcnow() - timedelta(days=90), limit=100) == 3
    assert events.get_event("fresh") is not None
    outbox.enqueue("s1", "safety_event", {})
    due = outbox.claim_due(limit=10)
    outbox.mark_sent(due[0]["id"])
    assert outbox.delete_sent_older_than(utcnow() + timedelta(seconds=1)) == 1


def test_orphan_link_report(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/ops.db"
    init_db(url)
    events, _ = _factories(url)
    assert events.count_orphan_links() == 0
    import uuid as _uuid

    from backend.app.models.incident_orm import IncidentEventORM

    factory = get_session_factory(url)
    with factory() as session:
        session.add(
            IncidentEventORM(
                id=str(_uuid.uuid4()),
                incident_id=str(_uuid.uuid4()),
                event_id="ghost-event",
                event_type="CROWD_WARNING",
                source_domain="SAFETY",
                is_primary=True,
            )
        )
        session.commit()
    assert events.count_orphan_links() == 1
    events.upsert_event(**_event(event_id="ghost-event"))
    assert events.count_orphan_links() == 0
