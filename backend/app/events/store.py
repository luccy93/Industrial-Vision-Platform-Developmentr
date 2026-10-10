"""Operational event history + outbox repositories (V12, §4.3–§4.4).

``OperationalEventRepository`` persists canonical V09 unified events that
gain operational significance (incident linkage). One row per stable event
identity — retries and re-ingests update, never duplicate.

``OutboxRepository`` holds delivery intents. Event row + outbox row commit
in one transaction (via ``record_event_with_outbox``); a managed publisher
drains pending rows. Redis is never part of the transaction.
"""

from __future__ import annotations

import json
import logging
import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.domain.common import utcnow
from backend.app.models.operational_orm import EventOutboxORM, OperationalEventORM

logger = logging.getLogger("industrial-vision.events")

METADATA_MAX_BYTES = 32768


def _check_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    meta = dict(metadata or {})
    try:
        size = len(json.dumps(meta).encode("utf-8"))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"event metadata not JSON-serializable: {exc}") from exc
    if size > METADATA_MAX_BYTES:
        raise ValueError(f"event metadata too large ({size} bytes > {METADATA_MAX_BYTES})")
    return meta


def _event_to_dict(row: OperationalEventORM) -> dict[str, Any]:
    return {
        "event_id": row.event_id,
        "camera_id": row.camera_id,
        "source_domain": row.source_domain,
        "source_event_id": row.source_event_id,
        "event_type": row.event_type,
        "severity": row.severity,
        "risk_level": row.risk_level,
        "risk_score": row.risk_score,
        "status": row.status,
        "first_seen": row.first_seen,
        "last_seen": row.last_seen,
        "created_at": row.created_at,
        "metadata": dict(row.meta or {}),
    }


def _outbox_to_dict(row: EventOutboxORM) -> dict[str, Any]:
    return {
        "id": row.id,
        "event_id": row.event_id,
        "kind": row.kind,
        "status": row.status,
        "attempts": row.attempts,
        "next_retry_at": row.next_retry_at,
        "envelope": dict(row.envelope or {}),
        "last_error": row.last_error,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


class OperationalEventRepository:
    """Durable canonical event history (idempotent upsert)."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def upsert_event(
        self,
        *,
        event_id: str,
        camera_id: str,
        source_domain: str,
        source_event_id: str,
        event_type: str,
        severity: str = "UNKNOWN",
        risk_level: str = "UNKNOWN",
        risk_score: float = 0.0,
        status: str = "ACTIVE",
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Insert or refresh one canonical event. Returns (row, created).

        Idempotent on both the primary key and the source-identity unique
        key. Integrity conflicts trigger exactly one recovery read (no
        unbounded retries); a conflict with no matching row re-raises —
        integrity violations are never hidden.
        """
        now = utcnow()
        meta = _check_metadata(metadata)
        first = first_seen or now
        last = last_seen or now
        identity = {
            "event_id": str(event_id),
            "camera_id": str(camera_id),
            "source_domain": str(source_domain).upper(),
            "source_event_id": str(source_event_id),
        }
        with self._session_factory() as session:
            row = (
                session.query(OperationalEventORM).filter_by(event_id=identity["event_id"]).one_or_none()
                or session.query(OperationalEventORM)
                .filter_by(
                    camera_id=identity["camera_id"],
                    source_domain=identity["source_domain"],
                    source_event_id=identity["source_event_id"],
                )
                .one_or_none()
            )
            created = False
            if row is None:
                row = OperationalEventORM(
                    **identity,
                    event_type=str(event_type),
                    severity=str(severity),
                    risk_level=str(risk_level),
                    risk_score=float(risk_score),
                    status=str(status),
                    first_seen=first,
                    last_seen=last,
                    created_at=now,
                    meta=meta,
                )
                session.add(row)
                try:
                    session.commit()
                    created = True
                except IntegrityError:
                    # Lost a create race: exactly one recovery read, then
                    # update-in-place. No match → re-raise, never retry blind.
                    session.rollback()
                    row = (
                        session.query(OperationalEventORM)
                        .filter_by(event_id=identity["event_id"])
                        .one_or_none()
                        or session.query(OperationalEventORM)
                        .filter_by(
                            camera_id=identity["camera_id"],
                            source_domain=identity["source_domain"],
                            source_event_id=identity["source_event_id"],
                        )
                        .one_or_none()
                    )
                    if row is None:
                        raise
            if not created:
                row.severity = str(severity)
                row.risk_level = str(risk_level)
                row.risk_score = float(risk_score)
                row.status = str(status)
                row.last_seen = last
                if meta:
                    merged = dict(row.meta or {})
                    merged.update(meta)
                    row.meta = merged
                session.commit()
            session.refresh(row)
            return _event_to_dict(row), created

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.query(OperationalEventORM).filter_by(event_id=str(event_id)).one_or_none()
            return _event_to_dict(row) if row is not None else None

    def list_in_window(
        self,
        start: datetime,
        end: datetime,
        *,
        camera_id: str | None = None,
        domain: str | Sequence[str] | None = None,
        severity: str | None = None,
        limit: int = 5000,
    ) -> tuple[list[dict[str, Any]], bool]:
        """Bounded canonical events by occurrence window. Returns (rows, truncated).

        Filters hit indexed columns (first_seen/camera/domain/severity);
        occurrence semantics use first_seen. Python-side grouping/bucketing
        keeps SQLite and PostgreSQL behavior identical at dashboard volumes.
        """
        from backend.app.analytics.contracts import as_utc as _as_utc

        cap = max(1, min(int(limit), 5000))
        with self._session_factory() as session:
            query = session.query(OperationalEventORM).filter(
                OperationalEventORM.first_seen >= start,
                OperationalEventORM.first_seen < end,
            )
            if camera_id:
                query = query.filter(OperationalEventORM.camera_id == camera_id)
            if domain:
                domains = [domain] if isinstance(domain, str) else list(domain)
                query = query.filter(OperationalEventORM.source_domain.in_([d.upper() for d in domains]))
            if severity:
                query = query.filter(OperationalEventORM.severity == severity.upper())
            query = query.order_by(OperationalEventORM.first_seen.asc())
            rows = query.limit(cap + 1).all()
            truncated = len(rows) > cap
            result = []
            for row in rows[:cap]:
                item = _event_to_dict(row)
                item["first_seen"] = _as_utc(row.first_seen)
                item["last_seen"] = _as_utc(row.last_seen)
                item["created_at"] = _as_utc(row.created_at)
                result.append(item)
            return result, truncated

    def count_orphan_links(self) -> int:
        """Incident links whose event_id has no durable history row.

        Pre-V12 links predate durability, so orphans are expected, never
        fabricated or deleted — this count is the explicit report.
        """
        from backend.app.models.incident_orm import IncidentEventORM

        with self._session_factory() as session:
            return (
                session.query(IncidentEventORM)
                .outerjoin(
                    OperationalEventORM,
                    OperationalEventORM.event_id == IncidentEventORM.event_id,
                )
                .filter(OperationalEventORM.event_id.is_(None))
                .count()
            )

    def delete_older_than(self, cutoff: datetime, limit: int = 500) -> int:
        """Bounded retention delete by last_seen. Returns rows removed."""
        with self._session_factory() as session:
            rows = (
                session.query(OperationalEventORM)
                .filter(OperationalEventORM.last_seen < cutoff)
                .order_by(OperationalEventORM.last_seen.asc())
                .limit(max(1, min(int(limit), 5000)))
                .all()
            )
            count = len(rows)
            for row in rows:
                session.delete(row)
            session.commit()
            return count


class OutboxRepository:
    """Durable delivery intents (drained by the outbox publisher)."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    def enqueue(self, event_id: str, kind: str, envelope: dict[str, Any]) -> bool:
        """Queue one delivery intent. False when already queued (idempotent)."""
        now = utcnow()
        with self._session_factory() as session:
            row = EventOutboxORM(
                id=str(uuid.uuid4()),
                event_id=str(event_id),
                kind=str(kind),
                status="pending",
                attempts=0,
                next_retry_at=None,
                envelope=dict(envelope or {}),
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return False
            return True

    def record_event_with_outbox(
        self,
        event: OperationalEventRepository,
        *,
        kind: str,
        envelope: dict[str, Any],
        **event_fields: Any,
    ) -> tuple[dict[str, Any], bool, bool]:
        """Persist the event row + outbox intent in ONE transaction.

        ``event_fields`` must include ``event_id``. Returns (event_row,
        event_created, outbox_queued). A crash before commit leaves
        neither; a crash after commit leaves both, and the publisher's
        redelivery is duplicate-safe.
        """
        event_id = str(event_fields.get("event_id") or "")
        if not event_id:
            raise ValueError("record_event_with_outbox requires event_fields['event_id']")
        now = utcnow()
        meta = _check_metadata(event_fields.get("metadata"))
        first = event_fields.get("first_seen") or now
        last = event_fields.get("last_seen") or now
        with self._session_factory() as session:
            row = session.query(OperationalEventORM).filter_by(event_id=event_id).one_or_none()
            created = False
            if row is None:
                row = OperationalEventORM(
                    event_id=str(event_id),
                    camera_id=str(event_fields.get("camera_id", "")),
                    source_domain=str(event_fields.get("source_domain", "")).upper(),
                    source_event_id=str(event_fields.get("source_event_id", "")),
                    event_type=str(event_fields.get("event_type", "UNKNOWN")),
                    severity=str(event_fields.get("severity", "UNKNOWN")),
                    risk_level=str(event_fields.get("risk_level", "UNKNOWN")),
                    risk_score=float(event_fields.get("risk_score", 0.0)),
                    status=str(event_fields.get("status", "ACTIVE")),
                    first_seen=first,
                    last_seen=last,
                    created_at=now,
                    meta=meta,
                )
                session.add(row)
                created = True
            else:
                row.severity = str(event_fields.get("severity", row.severity))
                row.risk_level = str(event_fields.get("risk_level", row.risk_level))
                row.risk_score = float(event_fields.get("risk_score", row.risk_score))
                row.status = str(event_fields.get("status", row.status))
                row.last_seen = last
            outbox = EventOutboxORM(
                id=str(uuid.uuid4()),
                event_id=str(event_id),
                kind=str(kind),
                status="pending",
                attempts=0,
                next_retry_at=None,
                envelope=dict(envelope or {}),
                created_at=now,
                updated_at=now,
            )
            session.add(outbox)
            try:
                session.commit()
            except IntegrityError:
                # Duplicate outbox intent (redelivery of the same event):
                # roll everything back — the existing intent already covers it.
                session.rollback()
                existing = event.get_event(event_id)
                assert existing is not None
                return existing, False, False
            session.refresh(row)
            return _event_to_dict(row), created, True

    def claim_due(self, limit: int = 50, now: datetime | None = None) -> list[dict[str, Any]]:
        """Fetch pending rows due for delivery (ordered oldest-first)."""
        reference = now or utcnow()
        with self._session_factory() as session:
            rows = (
                session.query(EventOutboxORM)
                .filter(EventOutboxORM.status == "pending")
                .filter(
                    (EventOutboxORM.next_retry_at.is_(None)) | (EventOutboxORM.next_retry_at <= reference)
                )
                .order_by(EventOutboxORM.created_at.asc())
                .limit(max(1, min(int(limit), 1000)))
                .all()
            )
            return [_outbox_to_dict(row) for row in rows]

    def mark_sent(self, row_id: str) -> bool:
        with self._session_factory() as session:
            row = session.query(EventOutboxORM).filter_by(id=row_id).one_or_none()
            if row is None:
                return False
            row.status = "sent"
            row.updated_at = utcnow()
            session.commit()
            return True

    def mark_failed(self, row_id: str, error: str, next_retry_at: datetime | None = None) -> bool:
        with self._session_factory() as session:
            row = session.query(EventOutboxORM).filter_by(id=row_id).one_or_none()
            if row is None:
                return False
            row.attempts = int(row.attempts or 0) + 1
            row.status = "failed"
            row.last_error = str(error)[:512]
            row.next_retry_at = next_retry_at
            row.updated_at = utcnow()
            session.commit()
            return True

    def requeue_failed(self, row_id: str, next_retry_at: datetime | None = None) -> bool:
        """Return a failed row to pending (bounded retry scheduling)."""
        with self._session_factory() as session:
            row = session.query(EventOutboxORM).filter_by(id=row_id).one_or_none()
            if row is None:
                return False
            row.status = "pending"
            row.next_retry_at = next_retry_at
            row.updated_at = utcnow()
            session.commit()
            return True

    def count_by_status(self) -> dict[str, int]:
        from sqlalchemy import func

        with self._session_factory() as session:
            rows = (
                session.query(EventOutboxORM.status, func.count(EventOutboxORM.id))
                .group_by(EventOutboxORM.status)
                .all()
            )
            return {str(status): int(count) for status, count in rows}

    def delete_sent_older_than(self, cutoff: datetime, limit: int = 500) -> int:
        with self._session_factory() as session:
            rows = (
                session.query(EventOutboxORM)
                .filter(EventOutboxORM.status == "sent")
                .filter(EventOutboxORM.updated_at < cutoff)
                .order_by(EventOutboxORM.updated_at.asc())
                .limit(max(1, min(int(limit), 5000)))
                .all()
            )
            count = len(rows)
            for row in rows:
                session.delete(row)
            session.commit()
            return count
