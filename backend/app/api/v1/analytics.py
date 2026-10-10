"""Historical analytics + CSV reporting (V14).

Read-only aggregations over durable PostgreSQL records (V12 canonical
event history, V10 incidents). No domain logic is duplicated here: the
endpoints count, group, and bucket what repositories return.

Honesty rules enforced throughout:

- Missing sources are ``unavailable``, never zero.
- Quality inspection outcomes are always ``unavailable`` (no persisted
  results exist); recorded quality *events* are reported separately.
- Incident pagination stays exactly ``{incidents,total,page,page_size}``.
- CSV exports carry a UTF-8 BOM, correct quoting, and formula-injection
  mitigation; over-limit exports fail explicitly (422), never truncate
  silently.
"""

from __future__ import annotations

import csv
import io
import statistics
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.analytics.contracts import (
    MAX_EXPORT_ROWS,
    MAX_WINDOW_ROWS,
    SectionAvailability,
    TimeRange,
    as_utc,
    bucket_start,
    validate_bucket,
)
from backend.app.domain.common import utcnow
from backend.app.infrastructure.db import get_db, get_session_factory

router = APIRouter(prefix="/analytics", tags=["analytics"])

TREND_METRICS = ("events", "incidents_created", "incidents_resolved", "incidents_closed")
BREAKDOWN_DATASETS = ("events", "incidents")
EVENT_GROUP_BYS = ("domain", "severity", "camera", "event_type")
INCIDENT_GROUP_BYS = ("status", "priority", "camera", "category")
EXPORT_REPORTS = ("events", "incidents", "safety", "camera_activity", "quality_events")
SAFETY_DOMAINS = ("SAFETY", "SPATIAL")


class Section(BaseModel):
    status: SectionAvailability = SectionAvailability.OK
    message: str = ""


class EventsSummary(Section):
    total: int = 0
    by_domain: dict[str, int] = Field(default_factory=dict)
    by_severity: dict[str, int] = Field(default_factory=dict)
    truncated: bool = False


class ResolutionSummary(BaseModel):
    count: int = 0
    average_seconds: float | None = None
    median_seconds: float | None = None
    min_seconds: float | None = None
    max_seconds: float | None = None


class IncidentsSummary(Section):
    created_total: int = 0
    open_total: int = 0
    resolved_total: int = 0
    closed_total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    resolution: ResolutionSummary = Field(default_factory=ResolutionSummary)


class QualityAvailability(Section):
    reason: str = ""


class CamerasSummary(Section):
    by_camera: dict[str, int] = Field(default_factory=dict)


class SummaryResponse(BaseModel):
    start_at: datetime
    end_at: datetime
    generated_at: datetime = Field(default_factory=utcnow)
    events: EventsSummary = Field(default_factory=EventsSummary)
    incidents: IncidentsSummary = Field(default_factory=IncidentsSummary)
    quality: QualityAvailability = Field(
        default_factory=lambda: QualityAvailability(
            status=SectionAvailability.UNAVAILABLE,
            message="Historical inspection outcomes unavailable",
            reason=(
                "Inspection results are not persisted, so historical inspection "
                "totals and outcome rates cannot be calculated. See Recorded "
                "Quality Events for durably recorded quality-domain events."
            ),
        )
    )
    cameras: CamerasSummary = Field(default_factory=CamerasSummary)


class TrendResponse(BaseModel):
    metric: str
    bucket: str
    start_at: datetime
    end_at: datetime
    buckets: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False


class BreakdownResponse(BaseModel):
    dataset: str
    group_by: str
    start_at: datetime
    end_at: datetime
    groups: list[dict[str, Any]] = Field(default_factory=list)
    truncated: bool = False


def _parse_range(start_at: str | None, end_at: str | None) -> TimeRange:
    try:
        return TimeRange(start_at=start_at, end_at=end_at)  # type: ignore[arg-type]
    except Exception as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "validation_error", "message": f"invalid time range: {exc}"},
        ) from exc


def _parse_list(values: list[str]) -> list[str]:
    items: list[str] = []
    for value in values:
        items.extend(part.strip() for part in str(value).split(",") if part.strip())
    return [item for item in items if item]


def _repositories(request: Request) -> tuple[Any, Any]:
    from backend.app.events.store import OperationalEventRepository
    from backend.app.incidents.repository import IncidentRepository

    factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory(str(request.state.session.get_bind().url))  # type: ignore[union-attr]
    return IncidentRepository(factory), OperationalEventRepository(factory)


def _bucket_series(
    moments: list[datetime | None], start: datetime, end: datetime, bucket: str
) -> list[dict[str, Any]]:
    """Bucket UTC moments with inclusive-start/exclusive-end boundaries."""
    from datetime import timedelta

    step = {"hour": timedelta(hours=1), "day": timedelta(days=1), "week": timedelta(weeks=1)}[bucket]
    boundaries: list[datetime] = []
    cursor = bucket_start(start, bucket)
    while cursor < end:
        boundaries.append(cursor)
        cursor = cursor + step
    counts = [0] * len(boundaries)
    index = {boundary: position for position, boundary in enumerate(boundaries)}
    for moment in moments:
        normalized = as_utc(moment)
        if normalized is None or normalized < start or normalized >= end:
            continue
        key = bucket_start(normalized, bucket)
        position = index.get(key)
        if position is not None:
            counts[position] += 1
    return [
        {"bucket_start": boundary.isoformat(), "count": counts[position]}
        for position, boundary in enumerate(boundaries)
    ]


def _resolution_stats(rows: list[dict[str, Any]]) -> ResolutionSummary:
    """Durations for records with valid created + terminal timestamps.

    Terminal = closed_at else resolved_at. Pairs with terminal before
    creation are excluded (clock anomalies, counted nowhere silently —
    the denominator only covers valid pairs).
    """
    durations: list[float] = []
    for row in rows:
        created = as_utc(row.get("created_at"))
        terminal = as_utc(row.get("closed_at")) or as_utc(row.get("resolved_at"))
        if created is None or terminal is None:
            continue
        delta = (terminal - created).total_seconds()
        if delta < 0:
            continue
        durations.append(delta)
    if not durations:
        return ResolutionSummary(count=0)
    return ResolutionSummary(
        count=len(durations),
        average_seconds=round(sum(durations) / len(durations), 2),
        median_seconds=round(statistics.median(durations), 2),
        min_seconds=round(min(durations), 2),
        max_seconds=round(max(durations), 2),
    )


@router.get("/summary", summary="Historical analytics summary")
def analytics_summary(
    request: Request,
    start_at: str | None = Query(default=None),
    end_at: str | None = Query(default=None),
    camera_id: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    session: Session = Depends(get_db),
) -> SummaryResponse:
    """Historical summary over durable records (replaces the V01 stub).

    Bare ``GET`` (no params) keeps HTTP 200 with default 7-day window.
    """
    window = _parse_range(start_at, end_at)
    assert window.start_at is not None and window.end_at is not None
    start, end = window.start_at, window.end_at
    incident_repository, event_repository = _repositories(request)
    response = SummaryResponse(start_at=start, end_at=end)

    try:
        rows, truncated = event_repository.list_in_window(
            start,
            end,
            camera_id=camera_id,
            domain=domain,
            severity=severity,
            limit=MAX_WINDOW_ROWS,
        )
        by_domain: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for row in rows:
            by_domain[str(row["source_domain"])] = by_domain.get(str(row["source_domain"]), 0) + 1
            by_severity[str(row["severity"])] = by_severity.get(str(row["severity"]), 0) + 1
        response.events = EventsSummary(
            total=len(rows), by_domain=by_domain, by_severity=by_severity, truncated=truncated
        )
    except Exception as exc:
        response.events = EventsSummary(
            status=SectionAvailability.UNAVAILABLE, message=f"event history failed: {type(exc).__name__}"
        )

    try:
        created = incident_repository.count_created_in_range(start, end, camera_id=camera_id)
        created_total = sum(sum(priorities.values()) for priorities in created.values())
        by_status: dict[str, int] = {
            status: sum(priorities.values()) for status, priorities in created.items()
        }
        by_priority: dict[str, int] = {}
        for priorities in created.values():
            for priority, count in priorities.items():
                by_priority[priority] = by_priority.get(priority, 0) + count
        current = incident_repository.count_by_status_priority()
        open_total = sum(
            sum(priorities.values()) for status, priorities in current.items() if status != "CLOSED"
        )
        resolved_total = incident_repository.count_terminal_in_range("resolved_at", start, end)
        closed_total = incident_repository.count_terminal_in_range("closed_at", start, end)
        stamp_rows, _ = incident_repository.incident_timestamps_in_range(start, end, camera_id=camera_id)
        response.incidents = IncidentsSummary(
            created_total=created_total,
            open_total=open_total,
            resolved_total=resolved_total,
            closed_total=closed_total,
            by_status=by_status,
            by_priority=by_priority,
            resolution=_resolution_stats(stamp_rows),
        )
    except Exception as exc:
        response.incidents = IncidentsSummary(
            status=SectionAvailability.UNAVAILABLE,
            message=f"incident query failed: {type(exc).__name__}",
        )

    try:
        event_rows = response.events
        by_camera: dict[str, int] = {}
        if event_rows.status == SectionAvailability.OK:
            rows, _ = event_repository.list_in_window(
                start,
                end,
                camera_id=camera_id,
                domain=domain,
                severity=severity,
                limit=MAX_WINDOW_ROWS,
            )
            for row in rows:
                by_camera[str(row["camera_id"])] = by_camera.get(str(row["camera_id"]), 0) + 1
        created_rows, _ = incident_repository.incident_timestamps_in_range(start, end, camera_id=camera_id)
        for row in created_rows:
            key = f"{row['camera_id']}:incidents"
            by_camera[key] = by_camera.get(key, 0) + 1
        response.cameras = CamerasSummary(by_camera=by_camera)
    except Exception as exc:
        response.cameras = CamerasSummary(
            status=SectionAvailability.UNAVAILABLE, message=f"camera query failed: {type(exc).__name__}"
        )
    return response


@router.get("/trends", summary="Historical trend buckets")
def analytics_trends(
    request: Request,
    start_at: str | None = Query(default=None),
    end_at: str | None = Query(default=None),
    bucket: str = Query(default="day"),
    metric: str = Query(default="events"),
    camera_id: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    session: Session = Depends(get_db),
) -> TrendResponse:
    window = _parse_range(start_at, end_at)
    assert window.start_at is not None and window.end_at is not None
    start, end = window.start_at, window.end_at
    try:
        grain = validate_bucket(bucket, start, end)
    except ValueError as exc:
        raise HTTPException(
            status_code=422, detail={"code": "validation_error", "message": str(exc)}
        ) from exc
    normalized_metric = str(metric or "events").strip().lower()
    if normalized_metric not in TREND_METRICS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "validation_error",
                "message": f"metric must be one of {list(TREND_METRICS)}",
            },
        )
    incident_repository, event_repository = _repositories(request)
    truncated = False
    if normalized_metric == "events":
        rows, truncated = event_repository.list_in_window(
            start,
            end,
            camera_id=camera_id,
            domain=domain,
            severity=severity,
            limit=MAX_WINDOW_ROWS,
        )
        moments = [row.get("first_seen") for row in rows]
    elif normalized_metric == "incidents_created":
        rows, truncated = incident_repository.incident_timestamps_in_range(
            start, end, camera_id=camera_id, limit=MAX_WINDOW_ROWS
        )
        moments = [row.get("created_at") for row in rows]
    else:
        field = "resolved_at" if normalized_metric == "incidents_resolved" else "closed_at"
        rows, truncated = incident_repository.terminal_timestamps_in_range(
            field, start, end, camera_id=camera_id, limit=MAX_WINDOW_ROWS
        )
        moments = [row.get("terminal_at") for row in rows]
    return TrendResponse(
        metric=normalized_metric,
        bucket=grain,
        start_at=start,
        end_at=end,
        buckets=_bucket_series(moments, start, end, grain),
        truncated=truncated,
    )


@router.get("/breakdowns", summary="Historical group breakdowns")
def analytics_breakdowns(
    request: Request,
    start_at: str | None = Query(default=None),
    end_at: str | None = Query(default=None),
    dataset: str = Query(default="events"),
    group_by: str = Query(default="domain"),
    camera_id: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    session: Session = Depends(get_db),
) -> BreakdownResponse:
    window = _parse_range(start_at, end_at)
    assert window.start_at is not None and window.end_at is not None
    start, end = window.start_at, window.end_at
    normalized_dataset = str(dataset or "events").strip().lower()
    if normalized_dataset not in BREAKDOWN_DATASETS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "validation_error",
                "message": f"dataset must be one of {list(BREAKDOWN_DATASETS)}",
            },
        )
    normalized_group = str(group_by or "").strip().lower()
    if normalized_dataset == "events" and normalized_group not in EVENT_GROUP_BYS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "validation_error",
                "message": f"events group_by must be one of {list(EVENT_GROUP_BYS)}",
            },
        )
    if normalized_dataset == "incidents" and normalized_group not in INCIDENT_GROUP_BYS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "validation_error",
                "message": f"incidents group_by must be one of {list(INCIDENT_GROUP_BYS)}",
            },
        )
    incident_repository, event_repository = _repositories(request)
    groups: dict[str, int] = {}
    truncated = False
    if normalized_dataset == "events":
        key_map = {
            "domain": "source_domain",
            "severity": "severity",
            "camera": "camera_id",
            "event_type": "event_type",
        }
        rows, truncated = event_repository.list_in_window(
            start,
            end,
            camera_id=camera_id,
            domain=domain,
            severity=severity,
            limit=MAX_WINDOW_ROWS,
        )
        for row in rows:
            key = str(row.get(key_map[normalized_group], "UNKNOWN"))
            groups[key] = groups.get(key, 0) + 1
    else:
        rows, truncated = incident_repository.incident_timestamps_in_range(
            start, end, camera_id=camera_id, limit=MAX_WINDOW_ROWS
        )
        for row in rows:
            key = str(row.get(normalized_group, "UNKNOWN"))
            groups[key] = groups.get(key, 0) + 1
    ordered = [
        {"key": key, "label": key, "count": count}
        for key, count in sorted(groups.items(), key=lambda item: (-item[1], item[0]))
    ]
    return BreakdownResponse(
        dataset=normalized_dataset,
        group_by=normalized_group,
        start_at=start,
        end_at=end,
        groups=ordered,
        truncated=truncated,
    )


def _csv_cell(value: Any) -> str:
    """Stringify a cell with spreadsheet-formula-injection mitigation."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        normalized = as_utc(value)
        text = (normalized or value).isoformat()
    elif isinstance(value, bool):
        text = "true" if value else "false"
    else:
        text = str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def _csv_chunk(header: list[str], rows: list[dict[str, Any]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)
    for row in rows:
        writer.writerow([_csv_cell(row.get(column)) for column in header])
    return buffer.getvalue()


EVENT_COLUMNS = [
    "event_id",
    "camera_id",
    "source_domain",
    "event_type",
    "severity",
    "status",
    "first_seen",
    "last_seen",
]
INCIDENT_COLUMNS = [
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
]
CAMERA_ACTIVITY_COLUMNS = ["camera_id", "events", "incidents"]


def _report_filename(report: str, start: datetime, end: datetime) -> str:
    return f"analytics-{report}-{start.strftime('%Y%m%d')}-{end.strftime('%Y%m%d')}.csv"


@router.get("/export", summary="Export analytics CSV")
def analytics_export(
    request: Request,
    start_at: str | None = Query(default=None),
    end_at: str | None = Query(default=None),
    report: str = Query(default="events"),
    camera_id: str | None = Query(default=None),
    domain: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    status: list[str] = Query(default=[]),
    priority: list[str] = Query(default=[]),
    session: Session = Depends(get_db),
) -> StreamingResponse:
    """Download a bounded CSV report (UTF-8 with BOM for Excel)."""
    window = _parse_range(start_at, end_at)
    assert window.start_at is not None and window.end_at is not None
    start, end = window.start_at, window.end_at
    normalized = str(report or "events").strip().lower()
    if normalized not in EXPORT_REPORTS:
        raise HTTPException(
            status_code=422,
            detail={
                "code": "validation_error",
                "message": (
                    f"report must be one of {list(EXPORT_REPORTS)} "
                    "(historical quality outcomes are unavailable: inspection "
                    "results are not persisted)"
                ),
            },
        )
    incident_repository, event_repository = _repositories(request)
    header: list[str]
    rows: list[dict[str, Any]]
    if normalized in ("events", "safety", "quality_events"):
        domains: str | list[str] | None = domain
        if normalized == "safety":
            domains = ["SAFETY", "SPATIAL"]
        elif normalized == "quality_events":
            domains = "QUALITY"
        header = EVENT_COLUMNS
        rows, truncated = event_repository.list_in_window(
            start,
            end,
            camera_id=camera_id,
            domain=domains,
            severity=severity,
            limit=MAX_EXPORT_ROWS,
        )
    elif normalized == "incidents":
        header = INCIDENT_COLUMNS
        rows, truncated = incident_repository.export_incidents(
            start,
            end,
            status=_parse_list(status) or None,
            priority=_parse_list(priority) or None,
            camera_id=camera_id,
            limit=MAX_EXPORT_ROWS,
        )
    else:  # camera_activity
        header = CAMERA_ACTIVITY_COLUMNS
        event_rows, events_truncated = event_repository.list_in_window(
            start,
            end,
            camera_id=camera_id,
            domain=domain,
            severity=severity,
            limit=MAX_EXPORT_ROWS,
        )
        stamp_rows, stamps_truncated = incident_repository.incident_timestamps_in_range(
            start, end, camera_id=camera_id, limit=MAX_EXPORT_ROWS
        )
        truncated = events_truncated or stamps_truncated
        counts: dict[str, dict[str, Any]] = {}
        for row in event_rows:
            entry = counts.setdefault(
                str(row["camera_id"]),
                {"camera_id": str(row["camera_id"]), "events": 0, "incidents": 0},
            )
            entry["events"] = int(entry["events"]) + 1
        for row in stamp_rows:
            entry = counts.setdefault(
                str(row["camera_id"]),
                {"camera_id": str(row["camera_id"]), "events": 0, "incidents": 0},
            )
            entry["incidents"] = int(entry["incidents"]) + 1
        rows = [counts[key] for key in sorted(counts)]
    if truncated:
        # Explicit failure beats silent truncation: the file would lie.
        raise HTTPException(
            status_code=422,
            detail={
                "code": "validation_error",
                "message": (
                    f"report exceeds {MAX_EXPORT_ROWS} rows; narrow the time window or filters and retry"
                ),
            },
        )

    def _csv_rows_only(chunk_rows: list[dict[str, Any]]) -> str:
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        for row in chunk_rows:
            writer.writerow([_csv_cell(row.get(column)) for column in header])
        return buffer.getvalue()

    CSV_BOM = "﻿"

    def _generate() -> Any:
        yield CSV_BOM
        yield _csv_chunk(header, [])
        for offset in range(0, len(rows), 500):
            yield _csv_rows_only(rows[offset : offset + 500])

    return StreamingResponse(
        _generate(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{_report_filename(normalized, start, end)}"'},
    )
