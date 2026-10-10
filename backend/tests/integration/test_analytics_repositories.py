"""Analytics repository tests — seeded deterministic fixtures (V14)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from backend.app.events.store import OperationalEventRepository
from backend.app.incidents.repository import IncidentRepository
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.models.incident_orm import IncidentORM

EPOCH = datetime(2026, 1, 1, tzinfo=UTC)


def _repos(url: str) -> tuple[IncidentRepository, OperationalEventRepository]:
    factory = get_session_factory(url)
    return IncidentRepository(factory), OperationalEventRepository(factory)


def _seed_incidents(url: str) -> IncidentRepository:
    incidents, _ = _repos(url)
    # (title, priority, created_day_offset, resolved_day_offset|None, closed_day_offset|None, camera)
    plan = [
        ("a", "P1", 1, 2, 3, "cam-01"),
        ("b", "P2", 2, None, None, "cam-01"),
        ("c", "P1", 5, 6, None, "cam-02"),
        ("d", "P3", 10, None, None, "cam-02"),
    ]
    created = []
    for title, priority, cday, _, _, camera in plan:
        created.append(
            incidents.create_manual(title=title, camera_id=camera, priority=priority)  # type: ignore[arg-type]
        )
    factory = get_session_factory(url)
    with factory() as session:
        for incident, (_, _, cday, rday, clday, _) in zip(created, plan):
            row = session.query(IncidentORM).filter_by(id=str(incident.id)).one()
            row.created_at = EPOCH + timedelta(days=cday)
            row.first_seen = EPOCH + timedelta(days=cday)
            row.last_seen = EPOCH + timedelta(days=cday)
            if rday is not None:
                row.status = "RESOLVED"
                row.resolved_at = EPOCH + timedelta(days=rday)
            if clday is not None:
                row.status = "CLOSED"
                row.closed_at = EPOCH + timedelta(days=clday)
            session.add(row)
        session.commit()
    return incidents


def _seed_events(url: str) -> OperationalEventRepository:
    _, events = _repos(url)
    for index in range(6):
        # Alternate domains/severities across two cameras and three days.
        events.upsert_event(
            event_id=f"evt-{index}",
            camera_id="cam-01" if index % 2 == 0 else "cam-02",
            source_domain="SAFETY" if index < 4 else "QUALITY",
            source_event_id=f"src-{index}",
            event_type="CROWD_WARNING" if index < 4 else "QUALITY_FAIL",
            severity="HIGH" if index % 3 == 0 else "LOW",
            status="ACTIVE",
            first_seen=EPOCH + timedelta(days=index % 3, hours=index),
            last_seen=EPOCH + timedelta(days=index % 3, hours=index),
        )
    return events


def test_created_range_counts(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/analytics.db"
    init_db(url)
    incidents = _seed_incidents(url)
    start, end = EPOCH, EPOCH + timedelta(days=7)
    grouped = incidents.count_created_in_range(start, end)
    assert grouped["RESOLVED"]["P1"] == 1  # a (created day 1)
    assert grouped["OPEN"]["P2"] == 1  # b
    assert incidents.count_created_in_range(end, end + timedelta(days=30)) == {
        "OPEN": {"P3": 1}
    }  # d created day 10


def test_terminal_counts_use_authoritative_timestamps(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/analytics.db"
    init_db(url)
    incidents = _seed_incidents(url)
    start, end = EPOCH, EPOCH + timedelta(days=7)
    assert incidents.count_terminal_in_range("resolved_at", start, end) == 2  # a day 2, c day 6
    assert incidents.count_terminal_in_range("closed_at", start, end) == 1  # a day 3
    assert incidents.count_terminal_in_range("closed_at", end, end + timedelta(days=30)) == 0


def test_timestamp_rows_bounded_and_ordered(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/analytics.db"
    init_db(url)
    incidents = _seed_incidents(url)
    rows, truncated = incidents.incident_timestamps_in_range(EPOCH, EPOCH + timedelta(days=30))
    assert truncated is False
    created_days = [r["created_at"].day for r in rows]
    assert created_days == [2, 3, 6, 11]  # ascending created_at order
    rows, truncated = incidents.incident_timestamps_in_range(EPOCH, EPOCH + timedelta(days=30), limit=2)
    assert truncated is True
    assert len(rows) == 2


def test_export_incidents_bounded_columns(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/analytics.db"
    init_db(url)
    incidents = _seed_incidents(url)
    rows, truncated = incidents.export_incidents(EPOCH, EPOCH + timedelta(days=30))
    assert truncated is False
    assert len(rows) == 4
    assert set(rows[0]) == {
        "incident_number",
        "title",
        "status",
        "priority",
        "severity",
        "category",
        "camera_id",
        "created_at",
        "acknowledged_at",
        "resolved_at",
        "closed_at",
        "assigned_to",
    }
    cam_rows, _ = incidents.export_incidents(EPOCH, EPOCH + timedelta(days=30), camera_id="cam-02")
    assert {r["camera_id"] for r in cam_rows} == {"cam-02"}


def test_history_window_filters_and_truncation(tmp_path) -> None:
    url = f"sqlite:///{tmp_path}/analytics.db"
    init_db(url)
    events = _seed_events(url)
    rows, truncated = events.list_in_window(EPOCH, EPOCH + timedelta(days=2))
    assert truncated is False
    assert len(rows) == 4  # days 0 and 1 (2 per day)
    safety, _ = events.list_in_window(EPOCH, EPOCH + timedelta(days=30), domain="safety")
    assert len(safety) == 4
    assert {r["source_domain"] for r in safety} == {"SAFETY"}
    cam, _ = events.list_in_window(EPOCH, EPOCH + timedelta(days=30), camera_id="cam-02")
    assert len(cam) == 3
    high, _ = events.list_in_window(EPOCH, EPOCH + timedelta(days=30), severity="HIGH")
    assert len(high) == 2  # indexes 0 and 3
    rows, truncated = events.list_in_window(EPOCH, EPOCH + timedelta(days=30), limit=2)
    assert truncated is True
    assert len(rows) == 2
    ordered = [r["first_seen"] for r in events.list_in_window(EPOCH, EPOCH + timedelta(days=30))[0]]
    assert ordered == sorted(ordered)
