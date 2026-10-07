"""Incident repository tests — persistence, numbering, constraints, ordering."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from backend.app.incidents.repository import (
    DuplicateIncidentError,
    IncidentNotFoundError,
    IncidentRepository,
    next_incident_number,
)
from backend.app.incidents.schemas import (
    EvidenceType,
    Incident,
    IncidentStatus,
    TimelineEventType,
)
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.models.incident_orm import (
    IncidentAssignmentORM,
    IncidentCounterORM,
    IncidentEventORM,
    IncidentEvidenceORM,
    IncidentORM,
    IncidentTimelineORM,
)
from backend.tests.incident_helpers import utc


@pytest.fixture()
def db_url(tmp_path):
    url = f"sqlite:///{tmp_path}/incident_repo.db"
    init_db(url)
    return url


@pytest.fixture()
def session_factory(db_url):
    return get_session_factory(db_url)


@pytest.fixture()
def repository(session_factory) -> IncidentRepository:
    return IncidentRepository(session_factory)


def _create(repository: IncidentRepository, **overrides: Any) -> Incident:
    params: dict[str, Any] = {
        "camera_id": "cam-01",
        "title": "Person in restricted zone",
        "priority": "P1",
    }
    params.update(overrides)
    return repository.create_manual(**params)


def test_create_manual_round_trip(repository: IncidentRepository) -> None:
    incident = _create(repository)
    assert incident.incident_number == "INC-2026-000001"
    assert incident.status is IncidentStatus.OPEN
    assert incident.source == "MANUAL"
    assert incident.priority.value == "P1"
    fetched = repository.get_incident(str(incident.id))
    assert fetched is not None
    assert fetched.incident_number == incident.incident_number
    assert fetched.title == "Person in restricted zone"
    assert repository.get_incident("00000000-0000-0000-0000-000000000000") is None


def test_numbering_increments_and_year_scoped(db_url: str) -> None:
    factory = get_session_factory(db_url)
    with factory() as session:
        assert next_incident_number(session, 2026) == "INC-2026-000001"
        assert next_incident_number(session, 2026) == "INC-2026-000002"
        assert next_incident_number(session, 2027) == "INC-2027-000001"
        row = session.get(IncidentCounterORM, 2026)
        assert row is not None and row.last_number == 2


def test_numbering_concurrent_allocations_unique(session_factory) -> None:
    import threading

    results: list[str] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def allocate() -> None:
        try:
            with session_factory() as session:
                number = next_incident_number(session, 2026)
                session.commit()
            with lock:
                results.append(number)
        except Exception as exc:  # pragma: no cover - documents contention behavior
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=allocate) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert not errors
    assert len(set(results)) == 8
    assert all(number.startswith("INC-2026-") for number in results)


def test_create_requires_title(repository: IncidentRepository) -> None:
    with pytest.raises(Exception):
        _create(repository, title="")


def test_duplicate_open_cluster_rejected(repository: IncidentRepository) -> None:
    _create(repository, source_cluster_id="cluster-9")
    with pytest.raises(DuplicateIncidentError):
        _create(repository, title="Second", source_cluster_id="cluster-9")


def test_find_open_for_cluster_skips_closed(repository: IncidentRepository) -> None:
    incident = _create(repository, source_cluster_id="cluster-7")
    found = repository.find_open_for_cluster("cam-01", "cluster-7")
    assert found is not None and found.id == incident.id
    assert repository.find_open_for_cluster("cam-01", "nope") is None
    assert repository.find_open_for_cluster("cam-99", "cluster-7") is None


def test_list_ordering_priority_then_newest(repository: IncidentRepository) -> None:
    first = _create(repository, title="older P1")
    _create(repository, title="P4 info", priority="P4")
    second = _create(repository, title="newer P1")
    incidents, total = repository.list_incidents()
    assert total == 3
    assert [i.title for i in incidents] == ["newer P1", "older P1", "P4 info"]
    assert first.id != second.id


def test_list_filters_and_pagination(repository: IncidentRepository) -> None:
    _create(repository, title="open one", camera_id="cam-a")
    _create(repository, title="open two", camera_id="cam-b", priority="P3")
    page, total = repository.list_incidents(camera_id="cam-a")
    assert total == 1 and page[0].camera_id == "cam-a"
    page, total = repository.list_incidents(priority=["P3"])
    assert total == 1 and page[0].priority.value == "P3"
    page, total = repository.list_incidents(page=2, page_size=1)
    assert total == 2 and len(page) == 1
    page, _ = repository.list_incidents(status=["CLOSED"])
    assert page == []
    with pytest.raises(ValueError):
        repository.list_incidents(status=["BOGUS"])


def test_list_created_range_filters(repository: IncidentRepository) -> None:
    now = datetime.now(UTC)
    _create(repository, title="timed")
    page, total = repository.list_incidents(created_from=now - timedelta(hours=1))
    assert total == 1
    page, total = repository.list_incidents(created_to=now + timedelta(hours=1))
    assert total == 1
    page, total = repository.list_incidents(created_from=now + timedelta(hours=1))
    assert total == 0


def test_update_incident_whitelist(repository: IncidentRepository) -> None:
    incident = _create(repository)
    updated = repository.update_incident(str(incident.id), title="Retitled", priority="P0")
    assert updated is not None
    assert updated.title == "Retitled"
    assert updated.priority.value == "P0"
    # Status and unknown fields are not settable here — lifecycle moves use
    # transitions, and unknown fields are ignored, never applied.
    updated = repository.update_incident(str(incident.id), status="CLOSED", bogus_field="x")
    assert updated is not None
    assert updated.status is IncidentStatus.OPEN
    assert repository.update_incident("00000000-0000-0000-0000-000000000000", title="x") is None


def test_transition_sets_lifecycle_timestamps(repository: IncidentRepository) -> None:
    incident = _create(repository)
    moved = repository.transition(str(incident.id), IncidentStatus.ACKNOWLEDGED)
    assert moved is not None
    assert moved.status is IncidentStatus.ACKNOWLEDGED
    assert moved.acknowledged_at is not None
    assert moved.resolved_at is None
    moved = repository.transition(str(incident.id), IncidentStatus.RESOLVED)
    assert moved is not None
    assert moved.resolved_at is not None
    assert moved.closed_at is None
    # Invalid moves surface without mutating.
    with pytest.raises(Exception):
        repository.transition(str(incident.id), IncidentStatus.OPEN)


def test_timeline_append_only_ordering(repository: IncidentRepository) -> None:
    incident = _create(repository)
    repository.add_timeline_entry(
        str(incident.id), TimelineEventType.CREATED, message="born", timestamp=utc(0)
    )
    repository.add_timeline_entry(
        str(incident.id),
        TimelineEventType.NOTE_ADDED,
        message="second",
        actor_id="op-1",
        timestamp=utc(60),
    )
    entries = repository.list_timeline(str(incident.id))
    assert [e.message for e in entries] == ["born", "second"]
    assert entries[1].actor.actor_id == "op-1"
    latest = repository.latest_timeline_entry(str(incident.id))
    assert latest is not None and latest.message == "second"
    assert repository.list_timeline("00000000-0000-0000-0000-000000000000") == []


def test_link_event_idempotent(repository: IncidentRepository) -> None:
    incident = _create(repository)
    assert repository.link_event(str(incident.id), "evt-1", "CROWD_WARNING", "SAFETY", True) is True
    assert repository.link_event(str(incident.id), "evt-1", "CROWD_WARNING", "SAFETY", True) is False
    assert repository.link_event(str(incident.id), "evt-2", "CROWD_WARNING", "SAFETY") is True
    linked = repository.list_linked_events(str(incident.id))
    assert [e["event_id"] for e in linked] == ["evt-1", "evt-2"]
    assert linked[0]["is_primary"] is True
    with pytest.raises(IncidentNotFoundError):
        repository.link_event("00000000-0000-0000-0000-000000000000", "evt-9", "X", "SAFETY")


def test_evidence_crud(repository: IncidentRepository) -> None:
    incident = _create(repository)
    created = repository.add_evidence(
        str(incident.id), "cam-01", EvidenceType.SNAPSHOT, "s3://bucket/frame.jpg"
    )
    assert created.uri == "s3://bucket/frame.jpg"
    assert len(repository.list_evidence(str(incident.id))) == 1
    assert repository.delete_evidence(str(incident.id), str(created.id)) is True
    assert repository.list_evidence(str(incident.id)) == []
    assert repository.delete_evidence(str(incident.id), str(created.id)) is False
    with pytest.raises(IncidentNotFoundError):
        repository.add_evidence(
            "00000000-0000-0000-0000-000000000000", "cam-01", EvidenceType.LINK, "https://x"
        )


def test_assignment_audit_and_current(repository: IncidentRepository) -> None:
    incident = _create(repository)
    first = repository.record_assignment(str(incident.id), "op-1", None, actor_id="lead-2")
    assert first.assignee == "op-1"
    assert first.previous_assignee is None
    second = repository.record_assignment(str(incident.id), "op-9", "op-1")
    assert second.previous_assignee == "op-1"
    history = repository.list_assignments(str(incident.id))
    assert [a.assignee for a in history] == ["op-1", "op-9"]
    current = repository.get_incident(str(incident.id))
    assert current is not None and current.assigned_to == "op-9"
    with pytest.raises(IncidentNotFoundError):
        repository.record_assignment("00000000-0000-0000-0000-000000000000", "op-1", None)


def test_delete_for_camera_cascades(repository: IncidentRepository) -> None:
    incident = _create(repository, camera_id="cam-gone")
    _create(repository, camera_id="cam-stays")
    repository.add_timeline_entry(str(incident.id), TimelineEventType.CREATED)
    repository.link_event(str(incident.id), "evt-1", "X", "SAFETY")
    repository.add_evidence(str(incident.id), "cam-gone", EvidenceType.SNAPSHOT, "s3://x")
    repository.record_assignment(str(incident.id), "op-1", None)
    assert repository.delete_for_camera("cam-gone") == 1
    assert repository.get_incident(str(incident.id)) is None
    assert repository.list_timeline(str(incident.id)) == []
    assert repository.list_linked_events(str(incident.id)) == []
    assert repository.list_evidence(str(incident.id)) == []
    assert repository.list_assignments(str(incident.id)) == []
    assert repository.delete_for_camera("cam-gone") == 0


def test_orm_tables_match_migration() -> None:
    from backend.app.models.incident_orm import (
        IncidentCounterORM,
    )

    assert {c.name for c in IncidentORM.__table__.columns} == {
        "id",
        "incident_number",
        "camera_id",
        "title",
        "description",
        "source_cluster_id",
        "primary_event_id",
        "severity",
        "risk_level",
        "risk_score",
        "priority",
        "status",
        "category",
        "source",
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
        "acknowledged_at",
        "resolved_at",
        "closed_at",
        "assigned_to",
        "metadata",
    }
    assert {c.name for c in IncidentEventORM.__table__.columns} == {
        "id",
        "incident_id",
        "event_id",
        "event_type",
        "source_domain",
        "is_primary",
        "created_at",
        "metadata",
    }
    assert {c.name for c in IncidentTimelineORM.__table__.columns} == {
        "id",
        "incident_id",
        "event_type",
        "actor_id",
        "actor_type",
        "message",
        "previous_state",
        "new_state",
        "timestamp",
        "metadata",
    }
    assert {c.name for c in IncidentEvidenceORM.__table__.columns} == {
        "id",
        "incident_id",
        "camera_id",
        "evidence_type",
        "uri",
        "timestamp",
        "frame_id",
        "description",
        "checksum",
        "metadata",
        "created_at",
    }
    assert {c.name for c in IncidentAssignmentORM.__table__.columns} == {
        "id",
        "incident_id",
        "assignee",
        "previous_assignee",
        "actor_id",
        "actor_type",
        "created_at",
        "metadata",
    }
    assert {c.name for c in IncidentCounterORM.__table__.columns} == {"year", "last_number"}


def test_incident_helpers_utc_deterministic() -> None:
    assert utc(0) < utc(90)
    assert (utc(90) - utc(0)).total_seconds() == 90.0
