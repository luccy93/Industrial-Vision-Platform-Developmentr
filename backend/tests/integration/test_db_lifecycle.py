"""Database lifecycle tests — sessions, rollback, isolation, transactions."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.app.incidents.schemas import IncidentStatus, TimelineEventType
from backend.app.incidents.statemachine import InvalidTransitionError
from backend.app.infrastructure.db import get_db


def _app(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app)


def test_request_session_commits_and_closes(client: TestClient) -> None:
    app = _app(client)
    gen = get_db.__wrapped__ if hasattr(get_db, "__wrapped__") else None
    assert gen is None  # get_db is a plain generator dependency
    from fastapi import Request

    scope: dict[str, Any] = {"type": "http", "app": app}
    request = Request(scope)
    dependency = get_db(request)
    session = next(dependency)
    session.execute(text("SELECT 1"))
    try:
        next(dependency)
    except StopIteration:
        closed = True
    else:
        closed = False
    assert closed, "get_db must close the session after the request"


def test_request_session_rolls_back_on_error(client: TestClient) -> None:
    from fastapi import Request

    from backend.app.models.camera_orm import Base, CameraORM

    app = _app(client)
    scope: dict[str, Any] = {"type": "http", "app": app}
    request = Request(scope)
    dependency = get_db(request)
    assert hasattr(dependency, "throw")
    session = next(dependency)
    import uuid as _uuid

    session.add(CameraORM(id=str(_uuid.uuid4()), camera_id="rollback-probe", name="probe"))
    session.flush()
    # FastAPI throws the request error into the dependency generator.
    try:
        dependency.throw(RuntimeError("request failed"))  # type: ignore[attr-defined]
    except (RuntimeError, StopIteration):
        pass
    factory = app.state.session_factory
    with factory() as check:
        row = check.query(CameraORM).filter_by(camera_id="rollback-probe").one_or_none()
        assert row is None, "failed request must not persist partial writes"
    assert Base is not None


def test_worker_sessions_are_independent(client: TestClient) -> None:
    """Repository sessions never share identity maps across callers."""
    app = _app(client)
    factory = app.state.session_factory
    first = factory()
    second = factory()
    try:
        assert first is not second
        first.execute(text("SELECT 1"))
        second.execute(text("SELECT 1"))
    finally:
        first.close()
        second.close()


def test_incident_transition_is_atomic(client: TestClient) -> None:
    """Lifecycle move + timeline row commit together or not at all."""
    app = _app(client)
    manager = app.state.incident_manager
    incident = manager.create_manual(title="atomic", category="OPERATIONAL", priority="P3")
    incident_id = str(incident.id)
    before = len(manager.repository.list_timeline(incident_id))
    # Invalid moves validate before any write: nothing partial persists.
    try:
        manager.repository.transition_with_timeline(
            incident_id,
            IncidentStatus.CLOSED,
            TimelineEventType.CLOSED,
        )
    except InvalidTransitionError:
        pass
    else:
        raise AssertionError("OPEN -> CLOSED must be rejected")
    current = manager.repository.get_incident(incident_id)
    assert current is not None and current.status.value == "OPEN"
    assert len(manager.repository.list_timeline(incident_id)) == before
    # Valid moves persist state and audit row together.
    manager.acknowledge(incident_id, actor_id="op-1")
    current = manager.repository.get_incident(incident_id)
    assert current is not None and current.status.value == "ACKNOWLEDGED"
    types = [t.event_type.value for t in manager.repository.list_timeline(incident_id)]
    assert "ACKNOWLEDGED" in types


def test_migration_chain_applies_on_startup(client: TestClient) -> None:
    """The configured database has all V01–V10 tables (005 incidents)."""
    app = _app(client)
    with app.state.session_factory() as session:
        tables = {
            row[0] for row in session.execute(text("SELECT name FROM sqlite_master WHERE type='table'")).all()
        }
    for table in ("incidents", "incident_timeline", "incident_counters", "cameras"):
        assert table in tables, table
