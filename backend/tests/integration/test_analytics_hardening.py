"""Analytics hardening — N+1 guards, orphans, dedup, limits, sessions."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import event as sa_event

from backend.app.domain.common import utcnow
from backend.app.infrastructure.db import get_session_factory, init_db


def _window(days: int = 30) -> str:
    from urllib.parse import urlencode

    end = utcnow()
    start = end - timedelta(days=days)
    return urlencode({"start_at": start.isoformat(), "end_at": end.isoformat()})


def _seed_incident(client: TestClient, title: str = "x", priority: str = "P2") -> str:
    res = client.post("/api/v1/incidents", json={"title": title, "priority": priority})
    assert res.status_code == 201, res.text
    return str(res.json()["incident"]["id"])


def test_summary_query_count_bounded(client: TestClient) -> None:
    """One summary call issues a bounded number of SQL statements (no N+1)."""
    from typing import Any, cast

    from fastapi import FastAPI

    _seed_incident(client, "a", "P1")
    _seed_incident(client, "b", "P2")
    app = cast(FastAPI, cast(Any, client).app)
    factory = app.state.session_factory
    bind = factory.kw.get("bind")
    statements: list[str] = []

    def _count(
        conn: Any, cursor: Any, statement: str, parameters: Any, context: Any, executemany: Any
    ) -> None:
        statements.append(statement.split()[0])

    sa_event.listen(bind, "before_cursor_execute", _count)
    try:
        res = client.get(f"/api/v1/analytics/summary?{_window()}")
        assert res.status_code == 200, res.text
    finally:
        sa_event.remove(bind, "before_cursor_execute", _count)
    # 1 (cameras) + 1 (counts) + 1 (terminal x2? no: resolved+closed) +
    # timestamps + events + cameras-events + cameras-stamps ≈ under 12.
    selects = [s for s in statements if s.upper() == "SELECT"]
    assert len(selects) <= 12, f"{len(selects)} SELECTs: {selects}"


def test_orphan_links_preserved_and_excluded(client: TestClient) -> None:
    """Ghost incident_events rows survive analytics and stay uncounted."""
    import uuid as _uuid
    from typing import Any, cast

    from fastapi import FastAPI

    _seed_incident(client, "real", "P1")
    app = cast(FastAPI, cast(Any, client).app)
    factory = app.state.session_factory
    from backend.app.models.incident_orm import IncidentEventORM

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
    body = client.get(f"/api/v1/analytics/summary?{_window()}").json()
    assert body["events"]["total"] == 0
    trends = client.get(f"/api/v1/analytics/trends?{_window(2)}&bucket=day&metric=events").json()
    assert sum(b["count"] for b in trends["buckets"]) == 0
    exported = client.get(f"/api/v1/analytics/export?{_window()}&report=events")
    assert exported.status_code == 200
    assert "ghost-event" not in exported.text
    # The legacy relationship itself is untouched.
    with factory() as session:
        remaining = session.query(IncidentEventORM).filter_by(event_id="ghost-event").count()
    assert remaining == 1


def test_event_dedup_by_canonical_identity(client: TestClient) -> None:
    """Re-ingesting the same canonical event never inflates history counts."""
    from typing import Any, cast

    from fastapi import FastAPI

    from backend.app.events.store import OperationalEventRepository

    app = cast(FastAPI, cast(Any, client).app)
    repo = OperationalEventRepository(app.state.session_factory)
    fields: dict[str, Any] = {
        "event_id": "dup-1",
        "camera_id": "cam-01",
        "source_domain": "SAFETY",
        "source_event_id": "src-dup",
        "event_type": "CROWD_WARNING",
        "severity": "HIGH",
    }
    first, created_first = repo.upsert_event(**fields)
    assert created_first is True
    second, created_second = repo.upsert_event(**fields)
    assert created_second is False
    assert first["event_id"] == second["event_id"]
    body = client.get(f"/api/v1/analytics/summary?{_window()}").json()
    assert body["events"]["total"] == 1
    assert body["events"]["by_severity"] == {"HIGH": 1}


def test_join_fanout_cannot_inflate_counts(client: TestClient) -> None:
    """One incident linked to N events counts N events, not N×M rows."""
    from typing import Any, cast

    from fastapi import FastAPI

    from backend.app.events.store import OperationalEventRepository

    incident_id = _seed_incident(client, "linked", "P2")
    app = cast(FastAPI, cast(Any, client).app)
    factory = app.state.session_factory
    history = OperationalEventRepository(factory)
    for index in range(3):
        history.upsert_event(
            event_id=f"fan-{index}",
            camera_id="cam-01",
            source_domain="SAFETY",
            source_event_id=f"fan-src-{index}",
            event_type="CROWD_WARNING",
        )
    manager = app.state.incident_manager
    for index in range(3):
        assert manager.repository.link_event(incident_id, f"fan-{index}", "CROWD_WARNING", "SAFETY") is True
    body = client.get(f"/api/v1/analytics/summary?{_window()}").json()
    assert body["events"]["total"] == 3
    assert body["events"]["by_domain"] == {"SAFETY": 3}


def test_empty_window_is_genuine_zero(client: TestClient) -> None:
    from urllib.parse import urlencode

    far = urlencode({"start_at": "2020-01-01T00:00:00Z", "end_at": "2020-01-08T00:00:00Z"})
    body = client.get(f"/api/v1/analytics/summary?{far}").json()
    assert body["events"]["status"] == "ok"
    assert body["events"]["total"] == 0
    assert body["incidents"]["created_total"] == 0
    trends = client.get(f"/api/v1/analytics/trends?{far}&bucket=day&metric=events").json()
    assert all(b["count"] == 0 for b in trends["buckets"])
    assert len(trends["buckets"]) == 7


def test_export_over_limit_fails_explicitly(client: TestClient, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import backend.app.api.v1.analytics as analytics

    _seed_incident(client, "a", "P1")
    _seed_incident(client, "b", "P2")
    monkeypatch.setattr(analytics, "MAX_EXPORT_ROWS", 1)
    res = client.get(f"/api/v1/analytics/export?{_window()}&report=incidents")
    assert res.status_code == 422
    assert "narrow" in res.json()["error"]["message"]


def test_hour_bucket_window_cap(client: TestClient) -> None:
    from urllib.parse import urlencode

    wide = urlencode({"start_at": "2026-01-01T00:00:00Z", "end_at": "2026-03-01T00:00:00Z"})
    res = client.get(f"/api/v1/analytics/trends?{wide}&bucket=hour&metric=events")
    assert res.status_code == 422
    res = client.get(f"/api/v1/analytics/trends?{wide}&bucket=day&metric=events")
    assert res.status_code == 200


def test_tmp_db_uses_fresh_chain(tmp_path) -> None:
    """Analytics repositories work on isolated databases (no global state)."""
    url = f"sqlite:///{tmp_path}/iso.db"
    init_db(url)
    factory = get_session_factory(url)
    from backend.app.events.store import OperationalEventRepository

    repo = OperationalEventRepository(factory)
    row, created = repo.upsert_event(
        event_id="iso-1",
        camera_id="cam-iso",
        source_domain="SAFETY",
        source_event_id="iso-src",
        event_type="CROWD_WARNING",
    )
    assert created is True
    assert row["camera_id"] == "cam-iso"
