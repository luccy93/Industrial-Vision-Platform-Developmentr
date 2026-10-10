"""Incident persistence — operational records in PostgreSQL.

All multi-row operations (creation with timeline + links, transitions with
timeline, evidence with timeline) commit atomically in one session. Reads
never mutate. Numbering uses an atomic counter increment, never count()+1.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from enum import Enum
from typing import Any, cast
from uuid import UUID

from sqlalchemy import case, select
from sqlalchemy import update as sa_update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.domain.common import utcnow
from backend.app.incidents.schemas import (
    Actor,
    ActorType,
    EvidenceType,
    Incident,
    IncidentAssignment,
    IncidentCategory,
    IncidentEvidence,
    IncidentStatus,
    IncidentTimelineEntry,
    TimelineEventType,
)
from backend.app.incidents.statemachine import validate_transition
from backend.app.intelligence.schemas import EventPriority, RiskLevel, UnifiedSeverity
from backend.app.models.incident_orm import (
    IncidentAssignmentORM,
    IncidentCounterORM,
    IncidentEventORM,
    IncidentEvidenceORM,
    IncidentORM,
    IncidentTimelineORM,
)

_NONTerminal = ("OPEN", "ACKNOWLEDGED", "INVESTIGATING", "MITIGATED")


class DuplicateIncidentError(ValueError):
    """An open incident already exists for the same source cluster."""


class IncidentNotFoundError(ValueError):
    """No incident with the given id exists."""

    def __init__(self, incident_id: str) -> None:
        super().__init__(f"incident not found: {incident_id}")
        self.incident_id = incident_id


def _coerce_enum(value: Any, enum_cls: Any, name: str) -> Any:
    if isinstance(value, enum_cls):
        return value
    try:
        return enum_cls(str(value).strip().upper())
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"unknown {name}: {value!r}") from exc


def _parse_enum_list(values: Sequence[str] | None, enum_cls: Any, name: str) -> list[str] | None:
    if not values:
        return None
    return [_coerce_enum(value, enum_cls, name).value for value in values]


def next_incident_number(session: Session, year: int, retries: int = 5) -> str:
    """Allocate ``INC-YYYY-XXXXXX`` concurrency-safely.

    A single atomic ``UPDATE ... SET last_number = last_number + 1`` means
    concurrent transactions can never observe the same value; the UNIQUE
    constraint on ``incidents.incident_number`` backstops the allocation with
    a bounded retry that also tolerates transient lock contention.
    """
    from sqlalchemy.exc import IntegrityError, OperationalError

    last_error: Exception | None = None
    for _ in range(max(1, retries)):
        try:
            # Atomic single-statement increment: concurrent transactions can
            # never observe the same value, on PostgreSQL and SQLite alike.
            incremented = cast(
                CursorResult,
                session.execute(
                    sa_update(IncidentCounterORM)
                    .where(IncidentCounterORM.year == year)
                    .values(last_number=IncidentCounterORM.last_number + 1)
                ),
            ).rowcount
            if incremented == 0:
                session.add(IncidentCounterORM(year=year, last_number=0))
                session.flush()
                continue
            session.flush()
            last_number = session.execute(
                select(IncidentCounterORM.last_number).where(IncidentCounterORM.year == year)
            ).scalar_one()
            number = f"INC-{year}-{last_number:06d}"
            exists = session.query(IncidentORM).filter_by(incident_number=number).one_or_none()
            if exists is None:
                return number
            last_error = DuplicateIncidentError(f"incident number collision: {number}")
            session.rollback()
        except (IntegrityError, OperationalError) as exc:
            # Counter-row insert races and transient lock contention both
            # resolve by retrying the whole allocation.
            last_error = exc
            session.rollback()
    raise last_error if last_error is not None else DuplicateIncidentError("numbering exhausted")


def _uuid(value: str) -> UUID:
    """Boundary conversion: database strings are canonical uuid4 hex."""
    return UUID(str(value))


def incident_to_domain(row: IncidentORM) -> Incident:
    return Incident(
        id=_uuid(row.id),
        incident_number=row.incident_number,
        camera_id=row.camera_id,
        title=row.title,
        description=row.description,
        source_cluster_id=row.source_cluster_id,
        primary_event_id=row.primary_event_id,
        severity=UnifiedSeverity(row.severity),
        risk_level=RiskLevel(row.risk_level),
        risk_score=row.risk_score,
        priority=EventPriority(row.priority),
        status=IncidentStatus(row.status),
        category=IncidentCategory(row.category),
        source=row.source,
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        created_at=row.created_at,
        updated_at=row.updated_at,
        acknowledged_at=row.acknowledged_at,
        resolved_at=row.resolved_at,
        closed_at=row.closed_at,
        assigned_to=row.assigned_to,
        metadata=dict(row.meta or {}),
    )


def timeline_to_domain(row: IncidentTimelineORM) -> IncidentTimelineEntry:
    return IncidentTimelineEntry(
        id=_uuid(row.id),
        incident_id=_uuid(row.incident_id),
        event_type=TimelineEventType(row.event_type),
        actor=Actor(actor_id=row.actor_id, actor_type=ActorType(row.actor_type)),
        message=row.message,
        previous_state=row.previous_state,
        new_state=row.new_state,
        timestamp=row.timestamp,
        metadata=dict(row.meta or {}),
    )


def evidence_to_domain(row: IncidentEvidenceORM) -> IncidentEvidence:
    return IncidentEvidence(
        id=_uuid(row.id),
        incident_id=_uuid(row.incident_id),
        camera_id=row.camera_id,
        evidence_type=EvidenceType(row.evidence_type),
        uri=row.uri,
        timestamp=row.timestamp,
        frame_id=row.frame_id,
        description=row.description,
        checksum=row.checksum,
        metadata=dict(row.meta or {}),
        created_at=row.created_at,
    )


def assignment_to_domain(row: IncidentAssignmentORM) -> IncidentAssignment:
    return IncidentAssignment(
        id=_uuid(row.id),
        incident_id=_uuid(row.incident_id),
        assignee=row.assignee,
        previous_assignee=row.previous_assignee,
        actor=Actor(actor_id=row.actor_id, actor_type=ActorType(row.actor_type)),
        timestamp=row.created_at,
        metadata=dict(row.meta or {}),
    )


def _priority_rank() -> Any:
    return case(
        {f"P{i}": i for i in range(5)},
        value=IncidentORM.priority,
        else_=5,
    )


class IncidentRepository:
    """PostgreSQL-backed incident store. Sessions are short-lived per call."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def create_manual(
        self,
        *,
        camera_id: str | None,
        title: str,
        description: str = "",
        category: IncidentCategory | str = IncidentCategory.UNKNOWN,
        priority: EventPriority | str = EventPriority.P4,
        metadata: dict[str, Any] | None = None,
        source_cluster_id: str | None = None,
        source_event_id: str | None = None,
        source: str = "MANUAL",
    ) -> Incident:
        """Create an incident row. Manual incidents use ``source = MANUAL``;
        the manager passes ``AUTOMATIC`` for V09-derived incidents."""
        incident = Incident(
            incident_number="TEMPORARY",
            camera_id=camera_id or "manual",
            title=title,
            description=description,
            category=_coerce_enum(category, IncidentCategory, "category"),
            priority=_coerce_enum(priority, EventPriority, "priority"),
            source_cluster_id=source_cluster_id,
            primary_event_id=source_event_id,
            source=source,
            metadata=dict(metadata or {}),
        )
        now = utcnow()
        with self._session_factory() as session:
            number = next_incident_number(session, now.year)
            row = IncidentORM(
                id=str(incident.id),
                incident_number=number,
                camera_id=incident.camera_id,
                title=incident.title,
                description=incident.description,
                source_cluster_id=incident.source_cluster_id,
                primary_event_id=incident.primary_event_id,
                severity=incident.severity.value,
                risk_level=incident.risk_level.value,
                risk_score=incident.risk_score,
                priority=incident.priority.value,
                status=IncidentStatus.OPEN.value,
                category=incident.category.value,
                source=source,
                first_seen=now,
                last_seen=now,
                created_at=now,
                updated_at=now,
                meta=dict(metadata or {}),
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise DuplicateIncidentError(
                    f"open incident already exists for cluster {source_cluster_id} "
                    f"on camera {incident.camera_id}"
                ) from exc
            session.refresh(row)
            return incident_to_domain(row)

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._session_factory() as session:
            row = session.query(IncidentORM).filter_by(id=incident_id).one_or_none()
            return incident_to_domain(row) if row else None

    def find_open_for_cluster(self, camera_id: str, source_cluster_id: str) -> Incident | None:
        """Active (non-closed, non-resolved-awaiting-new?) incident for a cluster.

        Matches incidents in non-terminal states plus RESOLVED (updated in
        place, never reopened); CLOSED incidents never match, so a new cluster
        after closure creates a new incident.
        """
        with self._session_factory() as session:
            row = (
                session.query(IncidentORM)
                .filter_by(camera_id=camera_id, source_cluster_id=source_cluster_id)
                .filter(IncidentORM.status.in_(list(_NONTerminal) + ["RESOLVED"]))
                .order_by(IncidentORM.created_at.desc())
                .first()
            )
            return incident_to_domain(row) if row else None

    def count_by_status_priority(self) -> dict[str, dict[str, int]]:
        """Grouped incident counts for dashboards (single indexed query).

        Returns ``{status: {priority: count}}`` covering only states and
        priorities actually present. Read-only; no pagination.
        """
        from sqlalchemy import func as _func

        with self._session_factory() as session:
            rows = (
                session.query(IncidentORM.status, IncidentORM.priority, _func.count(IncidentORM.id))
                .group_by(IncidentORM.status, IncidentORM.priority)
                .all()
            )
            grouped: dict[str, dict[str, int]] = {}
            for status, priority, count in rows:
                grouped.setdefault(str(status), {})[str(priority)] = int(count)
            return grouped

    def count_created_in_range(
        self,
        start: datetime,
        end: datetime,
        *,
        status: Sequence[str] | None = None,
        priority: Sequence[str] | None = None,
        camera_id: str | None = None,
    ) -> dict[str, dict[str, int]]:
        """Incidents created in [start, end), grouped by status/priority."""
        from sqlalchemy import func as _func

        with self._session_factory() as session:
            query = session.query(
                IncidentORM.status, IncidentORM.priority, _func.count(IncidentORM.id)
            ).filter(IncidentORM.created_at >= start, IncidentORM.created_at < end)
            if status:
                query = query.filter(IncidentORM.status.in_(list(status)))
            if priority:
                query = query.filter(IncidentORM.priority.in_(list(priority)))
            if camera_id:
                query = query.filter(IncidentORM.camera_id == camera_id)
            grouped: dict[str, dict[str, int]] = {}
            for row_status, row_priority, count in query.group_by(
                IncidentORM.status, IncidentORM.priority
            ).all():
                grouped.setdefault(str(row_status), {})[str(row_priority)] = int(count)
            return grouped

    def count_terminal_in_range(self, field: str, start: datetime, end: datetime) -> int:
        """Incidents whose resolved_at/closed_at falls in [start, end)."""
        column = {
            "resolved_at": IncidentORM.resolved_at,
            "closed_at": IncidentORM.closed_at,
        }.get(field)
        if column is None:
            raise ValueError("field must be resolved_at|closed_at")
        from sqlalchemy import func as _func

        with self._session_factory() as session:
            return int(
                session.query(_func.count(IncidentORM.id))
                .filter(column.is_not(None), column >= start, column < end)
                .scalar()
                or 0
            )

    def incident_timestamps_in_range(
        self,
        start: datetime,
        end: datetime,
        *,
        camera_id: str | None = None,
        limit: int = 5000,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Bounded timestamp rows ordered by created_at. Returns (rows, truncated).

        Serves trends, durations, and breakdowns from one indexed query.
        """
        from backend.app.analytics.contracts import as_utc as _as_utc

        cap = max(1, min(int(limit), 5000))
        with self._session_factory() as session:
            query = (
                session.query(IncidentORM)
                .filter(IncidentORM.created_at >= start, IncidentORM.created_at < end)
                .order_by(IncidentORM.created_at.asc())
            )
            if camera_id:
                query = query.filter(IncidentORM.camera_id == camera_id)
            rows = query.limit(cap + 1).all()
            truncated = len(rows) > cap
            return [
                {
                    "id": str(row.id),
                    "created_at": _as_utc(row.created_at),
                    "resolved_at": _as_utc(row.resolved_at),
                    "closed_at": _as_utc(row.closed_at),
                    "status": str(row.status),
                    "priority": str(row.priority),
                    "camera_id": str(row.camera_id),
                    "category": str(row.category),
                }
                for row in rows[:cap]
            ], truncated

    def terminal_timestamps_in_range(
        self,
        field: str,
        start: datetime,
        end: datetime,
        *,
        camera_id: str | None = None,
        limit: int = 5000,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Bounded (terminal_ts, status, priority) rows for trend bucketing.

        ``field`` is resolved_at|closed_at; rows ordered by terminal time.
        """
        from backend.app.analytics.contracts import as_utc as _as_utc

        column = {
            "resolved_at": IncidentORM.resolved_at,
            "closed_at": IncidentORM.closed_at,
        }.get(field)
        if column is None:
            raise ValueError("field must be resolved_at|closed_at")
        cap = max(1, min(int(limit), 5000))
        with self._session_factory() as session:
            query = (
                session.query(IncidentORM)
                .filter(column.is_not(None), column >= start, column < end)
                .order_by(column.asc())
            )
            if camera_id:
                query = query.filter(IncidentORM.camera_id == camera_id)
            rows = query.limit(cap + 1).all()
            truncated = len(rows) > cap
            return [
                {
                    "terminal_at": _as_utc(getattr(row, field)),
                    "status": str(row.status),
                    "priority": str(row.priority),
                    "camera_id": str(row.camera_id),
                }
                for row in rows[:cap]
            ], truncated

    def export_incidents(
        self,
        start: datetime,
        end: datetime,
        *,
        status: Sequence[str] | None = None,
        priority: Sequence[str] | None = None,
        camera_id: str | None = None,
        limit: int = 5000,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Bounded incident export rows (capped columns, created_at order)."""
        from backend.app.analytics.contracts import as_utc as _as_utc

        cap = max(1, min(int(limit), 5000))
        with self._session_factory() as session:
            query = (
                session.query(IncidentORM)
                .filter(IncidentORM.created_at >= start, IncidentORM.created_at < end)
                .order_by(IncidentORM.created_at.asc())
            )
            if status:
                query = query.filter(IncidentORM.status.in_(list(status)))
            if priority:
                query = query.filter(IncidentORM.priority.in_(list(priority)))
            if camera_id:
                query = query.filter(IncidentORM.camera_id == camera_id)
            rows = query.limit(cap + 1).all()
            truncated = len(rows) > cap
            return [
                {
                    "incident_number": str(row.incident_number),
                    "title": str(row.title),
                    "status": str(row.status),
                    "priority": str(row.priority),
                    "severity": str(row.severity),
                    "category": str(row.category),
                    "camera_id": str(row.camera_id),
                    "created_at": _as_utc(row.created_at),
                    "acknowledged_at": _as_utc(row.acknowledged_at),
                    "resolved_at": _as_utc(row.resolved_at),
                    "closed_at": _as_utc(row.closed_at),
                    "assigned_to": row.assigned_to,
                }
                for row in rows[:cap]
            ], truncated

    def list_incidents(
        self,
        *,
        status: Sequence[str] | None = None,
        priority: Sequence[str] | None = None,
        severity: Sequence[str] | None = None,
        category: Sequence[str] | None = None,
        camera_id: str | None = None,
        assigned_to: str | None = None,
        risk_level: Sequence[str] | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Incident], int]:
        """Filtered, paginated incidents in deterministic priority order.

        Ordering is urgency-first: ``P0 → P4``, then newest, then id. Page is
        1-based; page_size is clamped to [1, 100]. Unknown filter values raise
        ``ValueError`` (surfaced as HTTP 422, never silent).
        """
        from backend.app.incidents.schemas import IncidentCategory as Category

        page = max(1, page)
        page_size = min(100, max(1, page_size))
        with self._session_factory() as session:
            query = session.query(IncidentORM)
            if status:
                query = query.filter(
                    IncidentORM.status.in_(_parse_enum_list(status, IncidentStatus, "status") or [])
                )
            if priority:
                query = query.filter(
                    IncidentORM.priority.in_(_parse_enum_list(priority, EventPriority, "priority") or [])
                )
            if severity:
                query = query.filter(
                    IncidentORM.severity.in_(_parse_enum_list(severity, UnifiedSeverity, "severity") or [])
                )
            if category:
                query = query.filter(
                    IncidentORM.category.in_(_parse_enum_list(category, Category, "category") or [])
                )
            if camera_id:
                query = query.filter_by(camera_id=camera_id)
            if assigned_to is not None:
                query = query.filter_by(assigned_to=assigned_to)
            if risk_level:
                query = query.filter(
                    IncidentORM.risk_level.in_(_parse_enum_list(risk_level, RiskLevel, "risk_level") or [])
                )
            if created_from is not None:
                query = query.filter(IncidentORM.created_at >= created_from)
            if created_to is not None:
                query = query.filter(IncidentORM.created_at <= created_to)
            total = query.count()
            rows = (
                query.order_by(_priority_rank(), IncidentORM.created_at.desc(), IncidentORM.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [incident_to_domain(row) for row in rows], total

    def update_incident(self, incident_id: str, **fields: Any) -> Incident | None:
        """Update whitelisted row fields (no lifecycle moves — use transitions)."""
        allowed = {
            "title",
            "description",
            "severity",
            "risk_level",
            "risk_score",
            "priority",
            "category",
            "last_seen",
            "assigned_to",
            "metadata",
        }
        with self._session_factory() as session:
            row = session.query(IncidentORM).filter_by(id=incident_id).one_or_none()
            if row is None:
                return None
            for key, value in fields.items():
                if key not in allowed or value is None:
                    continue
                if key == "metadata" and isinstance(value, dict):
                    row.meta = dict(value)
                elif hasattr(row, key):
                    setattr(row, key, value.value if isinstance(value, Enum) else value)
            row.updated_at = utcnow()
            session.commit()
            session.refresh(row)
            return incident_to_domain(row)

    def transition(
        self, incident_id: str, new_status: IncidentStatus, timestamp: datetime | None = None
    ) -> Incident | None:
        """Move lifecycle state (validated by the caller via the state machine)."""

        with self._session_factory() as session:
            row = session.query(IncidentORM).filter_by(id=incident_id).one_or_none()
            if row is None:
                return None
            validate_transition(IncidentStatus(row.status), new_status)
            now = timestamp or utcnow()
            row.status = new_status.value
            row.updated_at = now
            if new_status is IncidentStatus.ACKNOWLEDGED and row.acknowledged_at is None:
                row.acknowledged_at = now
            if new_status is IncidentStatus.RESOLVED:
                row.resolved_at = now
            if new_status is IncidentStatus.CLOSED:
                row.closed_at = now
            session.commit()
            session.refresh(row)
            return incident_to_domain(row)

    def transition_with_timeline(
        self,
        incident_id: str,
        new_status: IncidentStatus,
        timeline_type: TimelineEventType,
        message: str = "",
        actor_id: str | None = None,
        actor_type: ActorType = ActorType.SYSTEM,
        previous_state: str | None = None,
        new_state: str | None = None,
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> Incident | None:
        """Move lifecycle state and append the timeline row atomically (§20).

        A single session/transaction covers both writes: a crash between
        them can no longer leave a moved incident without its audit row.
        Returns None for unknown incidents (matches ``transition``).
        """
        with self._session_factory() as session:
            row = session.query(IncidentORM).filter_by(id=incident_id).one_or_none()
            if row is None:
                return None
            validate_transition(IncidentStatus(row.status), new_status)
            now = timestamp or utcnow()
            row.status = new_status.value
            row.updated_at = now
            if new_status is IncidentStatus.ACKNOWLEDGED and row.acknowledged_at is None:
                row.acknowledged_at = now
            if new_status is IncidentStatus.RESOLVED:
                row.resolved_at = now
            if new_status is IncidentStatus.CLOSED:
                row.closed_at = now
            session.add(
                IncidentTimelineORM(
                    id=str(uuid.uuid4()),
                    incident_id=incident_id,
                    event_type=timeline_type.value
                    if isinstance(timeline_type, TimelineEventType)
                    else str(timeline_type),
                    actor_id=actor_id,
                    actor_type=actor_type.value if isinstance(actor_type, ActorType) else str(actor_type),
                    message=message,
                    previous_state=previous_state,
                    new_state=new_state,
                    timestamp=now,
                    meta=dict(metadata or {}),
                )
            )
            session.commit()
            session.refresh(row)
            return incident_to_domain(row)

    def add_timeline_entry(
        self,
        incident_id: str,
        event_type: TimelineEventType,
        message: str = "",
        actor_id: str | None = None,
        actor_type: ActorType = ActorType.SYSTEM,
        previous_state: str | None = None,
        new_state: str | None = None,
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentTimelineEntry:
        with self._session_factory() as session:
            row = IncidentTimelineORM(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                event_type=event_type.value if isinstance(event_type, TimelineEventType) else str(event_type),
                actor_id=actor_id,
                actor_type=actor_type.value if isinstance(actor_type, ActorType) else str(actor_type),
                message=message,
                previous_state=previous_state,
                new_state=new_state,
                timestamp=timestamp or utcnow(),
                meta=dict(metadata or {}),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return timeline_to_domain(row)

    def list_timeline(self, incident_id: str, limit: int = 200) -> list[IncidentTimelineEntry]:
        with self._session_factory() as session:
            rows = (
                session.query(IncidentTimelineORM)
                .filter_by(incident_id=incident_id)
                .order_by(IncidentTimelineORM.timestamp.asc(), IncidentTimelineORM.id.asc())
                .limit(max(1, min(limit, 1000)))
                .all()
            )
            return [timeline_to_domain(row) for row in rows]

    def latest_timeline_entry(
        self, incident_id: str, event_type: TimelineEventType | None = None
    ) -> IncidentTimelineEntry | None:
        with self._session_factory() as session:
            query = session.query(IncidentTimelineORM).filter_by(incident_id=incident_id)
            if event_type is not None:
                query = query.filter_by(event_type=event_type.value)
            row = query.order_by(IncidentTimelineORM.timestamp.desc(), IncidentTimelineORM.id.desc()).first()
            return timeline_to_domain(row) if row else None

    def link_event(
        self,
        incident_id: str,
        event_id: str,
        event_type: str = "UNKNOWN",
        source_domain: str = "UNKNOWN",
        is_primary: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """Link a V09 event; returns False if already linked (no duplicates)."""
        with self._session_factory() as session:
            if session.query(IncidentORM).filter_by(id=incident_id).one_or_none() is None:
                raise IncidentNotFoundError(incident_id)
            exists = (
                session.query(IncidentEventORM)
                .filter_by(incident_id=incident_id, event_id=event_id)
                .one_or_none()
            )
            if exists is not None:
                return False
            session.add(
                IncidentEventORM(
                    id=str(uuid.uuid4()),
                    incident_id=incident_id,
                    event_id=event_id,
                    event_type=event_type,
                    source_domain=source_domain,
                    is_primary=is_primary,
                    created_at=utcnow(),
                    meta=dict(metadata or {}),
                )
            )
            session.commit()
            return True

    def list_linked_events(self, incident_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(IncidentEventORM)
                .filter_by(incident_id=incident_id)
                .order_by(IncidentEventORM.created_at.asc())
                .all()
            )
            return [
                {
                    "event_id": row.event_id,
                    "event_type": row.event_type,
                    "source_domain": row.source_domain,
                    "is_primary": bool(row.is_primary),
                    "created_at": row.created_at,
                }
                for row in rows
            ]

    def add_evidence(
        self,
        incident_id: str,
        camera_id: str,
        evidence_type: EvidenceType,
        uri: str,
        timestamp: datetime | None = None,
        frame_id: str | None = None,
        description: str = "",
        checksum: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentEvidence:
        with self._session_factory() as session:
            if session.query(IncidentORM).filter_by(id=incident_id).one_or_none() is None:
                raise IncidentNotFoundError(incident_id)
            row = IncidentEvidenceORM(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                camera_id=camera_id,
                evidence_type=evidence_type.value,
                uri=uri,
                timestamp=timestamp or utcnow(),
                frame_id=frame_id,
                description=description,
                checksum=checksum,
                meta=dict(metadata or {}),
                created_at=utcnow(),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return evidence_to_domain(row)

    def list_evidence(self, incident_id: str) -> list[IncidentEvidence]:
        with self._session_factory() as session:
            rows = (
                session.query(IncidentEvidenceORM)
                .filter_by(incident_id=incident_id)
                .order_by(IncidentEvidenceORM.created_at.asc())
                .all()
            )
            return [evidence_to_domain(row) for row in rows]

    def delete_evidence(self, incident_id: str, evidence_id: str) -> bool:
        with self._session_factory() as session:
            row = (
                session.query(IncidentEvidenceORM)
                .filter_by(id=evidence_id, incident_id=incident_id)
                .one_or_none()
            )
            if row is None:
                return False
            session.delete(row)
            session.commit()
            return True

    def record_assignment(
        self,
        incident_id: str,
        assignee: str | None,
        previous_assignee: str | None,
        actor_id: str | None = None,
        actor_type: ActorType = ActorType.SYSTEM,
        metadata: dict[str, Any] | None = None,
    ) -> IncidentAssignment:
        with self._session_factory() as session:
            if session.query(IncidentORM).filter_by(id=incident_id).one_or_none() is None:
                raise IncidentNotFoundError(incident_id)
            row = IncidentAssignmentORM(
                id=str(uuid.uuid4()),
                incident_id=incident_id,
                assignee=assignee,
                previous_assignee=previous_assignee,
                actor_id=actor_id,
                actor_type=actor_type.value,
                created_at=utcnow(),
                meta=dict(metadata or {}),
            )
            session.add(row)
            incident = session.query(IncidentORM).filter_by(id=incident_id).one_or_none()
            if incident is not None:
                incident.assigned_to = assignee
                incident.updated_at = utcnow()
            session.commit()
            session.refresh(row)
            return assignment_to_domain(row)

    def list_assignments(self, incident_id: str) -> list[IncidentAssignment]:
        with self._session_factory() as session:
            rows = (
                session.query(IncidentAssignmentORM)
                .filter_by(incident_id=incident_id)
                .order_by(IncidentAssignmentORM.created_at.asc())
                .all()
            )
            return [assignment_to_domain(row) for row in rows]

    def delete_for_camera(self, camera_id: str) -> int:
        """Remove all incident data for a camera (camera deletion path)."""
        with self._session_factory() as session:
            ids = [row.id for row in session.query(IncidentORM.id).filter_by(camera_id=camera_id).all()]
            for table in (
                IncidentEventORM,
                IncidentTimelineORM,
                IncidentEvidenceORM,
                IncidentAssignmentORM,
            ):
                session.query(table).filter(table.incident_id.in_(ids)).delete(synchronize_session=False)
            count = (
                session.query(IncidentORM).filter_by(camera_id=camera_id).delete(synchronize_session=False)
            )
            session.commit()
            return count
