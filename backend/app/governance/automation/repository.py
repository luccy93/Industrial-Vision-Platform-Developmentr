"""Persistence for V36 governance automation.

All writes are additive and transactional. Jobs move through explicit
conditional transitions (claim, heartbeat, finish, cancel, recover). Job events
and snapshots are append-only. No method deletes a row or touches V30-V35
evidence, cases, custody, governance workflow, or audit records.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.redaction import redact_structure, redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.custody import canonical_json_bytes, datetime_to_iso, sha256_hex
from backend.app.governance.automation.constants import (
    DEFAULT_SCHEDULE_CONFIGS,
    DEFAULT_SCHEDULE_INTERVALS,
    JOB_STATUS_VALUES,
    JOB_TYPE_VALUES,
    MAX_DEDUP_KEY_LENGTH,
    MAX_ERROR_LENGTH,
    SNAPSHOT_SCHEMA_VERSION,
    JobEventType,
    JobStatus,
    JobType,
    normalize_utc,
    schedule_row_id,
)
from backend.app.governance.automation.errors import (
    JobNotFoundError,
    JobStateError,
    ScheduleNotFoundError,
    ScheduleVersionConflictError,
    SnapshotNotFoundError,
)
from backend.app.models.governance_automation_orm import (
    GovernanceJobEventORM,
    GovernanceJobORM,
    GovernanceJobScheduleORM,
    GovernanceSnapshotORM,
)


def _new_id() -> str:
    return str(uuid.uuid4())


def _iso(value: datetime | None) -> str | None:
    return datetime_to_iso(value) if value is not None else None


def _safe_text(value: Any, limit: int) -> str:
    return redact_text(str(value or "")).strip()[:limit]


def _safe_dict(value: Any) -> dict[str, Any]:
    redacted = redact_structure(value if isinstance(value, Mapping) else {})
    return dict(redacted) if isinstance(redacted, Mapping) else {}


def _schedule_to_dict(row: GovernanceJobScheduleORM) -> dict[str, Any]:
    return {
        "schedule_id": row.id,
        "job_type": row.job_type,
        "enabled": bool(row.enabled),
        "interval_minutes": int(row.interval_minutes),
        "config": _safe_dict(row.config),
        "config_version": int(row.config_version),
        "last_slot": row.last_slot,
        "last_idempotency_key": row.last_idempotency_key,
        "updated_by": row.updated_by,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


def _job_to_dict(row: GovernanceJobORM) -> dict[str, Any]:
    return {
        "job_id": row.id,
        "job_type": row.job_type,
        "status": row.status,
        "trigger": row.trigger,
        "schedule_slot": row.schedule_slot,
        "dedup_key": row.dedup_key,
        "retry_of_job_id": row.retry_of_job_id,
        "attempt": int(row.attempt),
        "max_attempts": int(row.max_attempts),
        "config_version": row.config_version,
        "config_snapshot": _safe_dict(row.config_snapshot),
        "requested_by": row.requested_by,
        "requested_role": row.requested_role,
        "request_id": row.request_id,
        "created_at": _iso(row.created_at),
        "available_at": _iso(row.available_at),
        "started_at": _iso(row.started_at),
        "finished_at": _iso(row.finished_at),
        "lease_owner": row.lease_owner,
        "lease_expires_at": _iso(row.lease_expires_at),
        "heartbeat_at": _iso(row.heartbeat_at),
        "cancel_requested_at": _iso(row.cancel_requested_at),
        "cancel_requested_by": row.cancel_requested_by,
        "cancel_requested": row.cancel_requested_at is not None,
        "result": _safe_dict(row.result),
        "error_code": row.error_code,
        "error_message": row.error_message,
    }


def _event_to_dict(row: GovernanceJobEventORM) -> dict[str, Any]:
    return {
        "event_id": row.id,
        "job_id": row.job_id,
        "event_type": row.event_type,
        "from_status": row.from_status,
        "to_status": row.to_status,
        "actor_id": row.actor_id,
        "actor_role": row.actor_role,
        "detail": _safe_dict(row.detail),
        "created_at": _iso(row.created_at),
    }


def _snapshot_to_dict(row: GovernanceSnapshotORM) -> dict[str, Any]:
    payload = _safe_dict(row.payload)
    digest_valid = sha256_hex(canonical_json_bytes(payload)) == row.payload_digest
    return {
        "snapshot_id": row.id,
        "snapshot_type": row.snapshot_type,
        "as_of": _iso(row.as_of),
        "generated_at": _iso(row.generated_at),
        "generated_by": row.generated_by,
        "job_id": row.job_id,
        "trigger": row.trigger,
        "dedup_key": row.dedup_key,
        "payload_digest": row.payload_digest,
        "digest_valid": digest_valid,
        "row_count": int(row.row_count),
        "schema_version": int(row.schema_version),
        "payload": payload,
    }


class GovernanceAutomationRepository:
    """Governance-owned schedule, job, event, and snapshot persistence."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Schedules
    # ------------------------------------------------------------------
    def ensure_schedules(self, *, actor_id: str = "SYSTEM") -> int:
        """Insert any missing seeded schedules. Returns the insert count."""
        created = 0
        now = utcnow()
        with self._session_factory() as session:
            existing = {str(row.job_type) for row in session.query(GovernanceJobScheduleORM).all()}
            for job_type in JobType:
                if job_type.value in existing:
                    continue
                session.add(
                    GovernanceJobScheduleORM(
                        id=schedule_row_id(job_type.value),
                        job_type=job_type.value,
                        enabled=False,
                        interval_minutes=DEFAULT_SCHEDULE_INTERVALS[job_type.value],
                        config=dict(DEFAULT_SCHEDULE_CONFIGS[job_type.value]),
                        config_version=1,
                        updated_by=_safe_text(actor_id, 256) or "SYSTEM",
                        created_at=now,
                        updated_at=now,
                    )
                )
                created += 1
            session.commit()
        return created

    def list_schedules(self) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceJobScheduleORM)
                .order_by(GovernanceJobScheduleORM.job_type.asc())
                .all()
            )
            return [_schedule_to_dict(row) for row in rows]

    def get_schedule(self, job_type: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceJobScheduleORM)
                .filter_by(job_type=str(job_type).upper())
                .one_or_none()
            )
            return _schedule_to_dict(row) if row is not None else None

    def update_schedule(
        self,
        job_type: str,
        *,
        enabled: bool,
        interval_minutes: int,
        config: Mapping[str, Any],
        expected_version: int,
        actor_id: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        normalized = str(job_type).upper()
        moment = normalize_utc(now or utcnow())
        with self._session_factory() as session:
            row = session.query(GovernanceJobScheduleORM).filter_by(job_type=normalized).one_or_none()
            if row is None:
                raise ScheduleNotFoundError(normalized)
            if int(row.config_version) != int(expected_version):
                raise ScheduleVersionConflictError(normalized, int(expected_version), int(row.config_version))
            row.enabled = bool(enabled)
            row.interval_minutes = int(interval_minutes)
            row.config = dict(config)
            row.config_version = int(row.config_version) + 1
            row.updated_by = _safe_text(actor_id, 256) or "SYSTEM"
            row.updated_at = moment
            session.commit()
            session.refresh(row)
            return _schedule_to_dict(row)

    def mark_schedule_enqueued(
        self,
        job_type: str,
        *,
        slot: str,
        dedup_key: str,
        now: datetime | None = None,
    ) -> None:
        moment = normalize_utc(now or utcnow())
        with self._session_factory() as session:
            session.query(GovernanceJobScheduleORM).filter_by(job_type=str(job_type).upper()).update(
                {
                    GovernanceJobScheduleORM.last_slot: str(slot)[:128],
                    GovernanceJobScheduleORM.last_idempotency_key: str(dedup_key)[:MAX_DEDUP_KEY_LENGTH],
                    GovernanceJobScheduleORM.updated_at: moment,
                },
                synchronize_session=False,
            )
            session.commit()

    # ------------------------------------------------------------------
    # Jobs
    # ------------------------------------------------------------------
    def create_job(
        self,
        *,
        job_type: str,
        trigger: str,
        dedup_key: str,
        requested_by: str,
        requested_role: str,
        config_version: int | None = None,
        config_snapshot: Mapping[str, Any] | None = None,
        max_attempts: int = 3,
        schedule_slot: str | None = None,
        retry_of_job_id: str | None = None,
        attempt: int = 1,
        available_at: datetime | None = None,
        request_id: str | None = None,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """Insert a job unless its dedup key already exists.

        Returns ``(job, created)``. A duplicate returns the existing row so
        callers can report replay without creating a second side effect.
        """
        normalized_type = str(job_type).upper()
        if normalized_type not in JOB_TYPE_VALUES:
            raise ValueError(f"unknown governance job type: {job_type}")
        key = _safe_text(dedup_key, MAX_DEDUP_KEY_LENGTH)
        if not key:
            raise ValueError("dedup_key is required")
        moment = normalize_utc(now or utcnow())
        with self._session_factory() as session:
            existing = session.query(GovernanceJobORM).filter_by(dedup_key=key).one_or_none()
            if existing is not None:
                return _job_to_dict(existing), False
            row = GovernanceJobORM(
                id=_new_id(),
                job_type=normalized_type,
                status=JobStatus.PENDING.value,
                trigger=str(trigger).upper(),
                schedule_slot=str(schedule_slot)[:128] if schedule_slot else None,
                dedup_key=key,
                retry_of_job_id=retry_of_job_id,
                attempt=max(1, int(attempt)),
                max_attempts=max(1, int(max_attempts)),
                config_version=config_version,
                config_snapshot=dict(config_snapshot or {}),
                requested_by=_safe_text(requested_by, 256) or "SYSTEM",
                requested_role=_safe_text(requested_role, 16) or "SYSTEM",
                request_id=_safe_text(request_id, 128) or None,
                created_at=moment,
                available_at=normalize_utc(available_at or moment),
                result={},
            )
            session.add(row)
            session.add(
                GovernanceJobEventORM(
                    id=_new_id(),
                    job_id=row.id,
                    event_type=JobEventType.CREATED.value,
                    from_status=None,
                    to_status=JobStatus.PENDING.value,
                    actor_id=row.requested_by,
                    actor_role=row.requested_role,
                    detail={
                        "trigger": row.trigger,
                        "attempt": row.attempt,
                        "max_attempts": row.max_attempts,
                    },
                    created_at=moment,
                )
            )
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = session.query(GovernanceJobORM).filter_by(dedup_key=key).one_or_none()
                if existing is None:
                    raise
                return _job_to_dict(existing), False
            session.refresh(row)
            return _job_to_dict(row), True

    def get_job(self, job_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(GovernanceJobORM, str(job_id))
            return _job_to_dict(row) if row is not None else None

    def get_job_row(self, job_id: str) -> GovernanceJobORM | None:
        """Return the ORM row for executor-internal use (never serialized)."""
        with self._session_factory() as session:
            return session.get(GovernanceJobORM, str(job_id))

    def list_jobs(
        self,
        *,
        job_type: str | None = None,
        status: str | None = None,
        trigger: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceJobORM)
            if job_type:
                query = query.filter_by(job_type=str(job_type).upper())
            if status:
                query = query.filter_by(status=str(status).upper())
            if trigger:
                query = query.filter_by(trigger=str(trigger).upper())
            total = int(query.count())
            rows = (
                query.order_by(GovernanceJobORM.created_at.desc(), GovernanceJobORM.id.desc())
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_job_to_dict(row) for row in rows], total

    def claim_next_job(
        self,
        *,
        lease_owner: str,
        lease_seconds: float,
        now: datetime | None = None,
        job_types: Sequence[str] | None = None,
    ) -> dict[str, Any] | None:
        """Conditionally claim one due PENDING job (atomic status transition)."""
        moment = normalize_utc(now or utcnow())
        owner = _safe_text(lease_owner, 128)
        expiry = datetime.fromtimestamp(moment.timestamp() + max(1.0, float(lease_seconds)), tz=moment.tzinfo)
        with self._session_factory() as session:
            query = session.query(GovernanceJobORM).filter(
                GovernanceJobORM.status == JobStatus.PENDING.value,
                GovernanceJobORM.available_at <= moment,
            )
            if job_types:
                query = query.filter(GovernanceJobORM.job_type.in_([str(item).upper() for item in job_types]))
            candidate = query.order_by(
                GovernanceJobORM.available_at.asc(), GovernanceJobORM.created_at.asc()
            ).first()
            if candidate is None:
                return None
            job_id = candidate.id
            updated = (
                session.query(GovernanceJobORM)
                .filter(
                    GovernanceJobORM.id == job_id,
                    GovernanceJobORM.status == JobStatus.PENDING.value,
                )
                .update(
                    {
                        GovernanceJobORM.status: JobStatus.RUNNING.value,
                        GovernanceJobORM.started_at: moment,
                        GovernanceJobORM.heartbeat_at: moment,
                        GovernanceJobORM.lease_owner: owner,
                        GovernanceJobORM.lease_expires_at: expiry,
                    },
                    synchronize_session=False,
                )
            )
            if not updated:
                session.rollback()
                return None
            session.add(
                GovernanceJobEventORM(
                    id=_new_id(),
                    job_id=job_id,
                    event_type=JobEventType.CLAIMED.value,
                    from_status=JobStatus.PENDING.value,
                    to_status=JobStatus.RUNNING.value,
                    actor_id=owner,
                    actor_role="SYSTEM",
                    detail={"lease_seconds": float(lease_seconds)},
                    created_at=moment,
                )
            )
            session.commit()
            row = session.get(GovernanceJobORM, job_id)
            if row is not None:
                session.refresh(row)
            return _job_to_dict(row) if row is not None else None

    def claim_job(
        self,
        job_id: str,
        *,
        lease_owner: str,
        lease_seconds: float,
        now: datetime | None = None,
    ) -> dict[str, Any] | None:
        """Claim one specific PENDING job for synchronous manual execution."""
        moment = normalize_utc(now or utcnow())
        owner = _safe_text(lease_owner, 128)
        expiry = datetime.fromtimestamp(moment.timestamp() + max(1.0, float(lease_seconds)), tz=moment.tzinfo)
        with self._session_factory() as session:
            updated = (
                session.query(GovernanceJobORM)
                .filter(
                    GovernanceJobORM.id == str(job_id),
                    GovernanceJobORM.status == JobStatus.PENDING.value,
                )
                .update(
                    {
                        GovernanceJobORM.status: JobStatus.RUNNING.value,
                        GovernanceJobORM.started_at: moment,
                        GovernanceJobORM.heartbeat_at: moment,
                        GovernanceJobORM.lease_owner: owner,
                        GovernanceJobORM.lease_expires_at: expiry,
                    },
                    synchronize_session=False,
                )
            )
            if not updated:
                session.rollback()
                return None
            session.add(
                GovernanceJobEventORM(
                    id=_new_id(),
                    job_id=str(job_id),
                    event_type=JobEventType.CLAIMED.value,
                    from_status=JobStatus.PENDING.value,
                    to_status=JobStatus.RUNNING.value,
                    actor_id=owner,
                    actor_role="SYSTEM",
                    detail={"lease_seconds": float(lease_seconds), "manual": True},
                    created_at=moment,
                )
            )
            session.commit()
            row = session.get(GovernanceJobORM, str(job_id))
            if row is not None:
                session.refresh(row)
            return _job_to_dict(row) if row is not None else None

    def heartbeat_job(
        self,
        job_id: str,
        *,
        lease_owner: str,
        lease_seconds: float,
        now: datetime | None = None,
    ) -> bool:
        moment = normalize_utc(now or utcnow())
        expiry = datetime.fromtimestamp(moment.timestamp() + max(1.0, float(lease_seconds)), tz=moment.tzinfo)
        with self._session_factory() as session:
            updated = (
                session.query(GovernanceJobORM)
                .filter(
                    GovernanceJobORM.id == str(job_id),
                    GovernanceJobORM.status == JobStatus.RUNNING.value,
                    GovernanceJobORM.lease_owner == _safe_text(lease_owner, 128),
                )
                .update(
                    {
                        GovernanceJobORM.heartbeat_at: moment,
                        GovernanceJobORM.lease_expires_at: expiry,
                    },
                    synchronize_session=False,
                )
            )
            session.commit()
            return bool(updated)

    def finish_job(
        self,
        job_id: str,
        *,
        lease_owner: str,
        status: str,
        result: Mapping[str, Any] | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
        now: datetime | None = None,
    ) -> bool:
        terminal = str(status).upper()
        if terminal not in JOB_STATUS_VALUES:
            raise ValueError(f"unknown governance job status: {status}")
        moment = normalize_utc(now or utcnow())
        with self._session_factory() as session:
            row = session.get(GovernanceJobORM, str(job_id))
            if row is None:
                return False
            updated = (
                session.query(GovernanceJobORM)
                .filter(
                    GovernanceJobORM.id == str(job_id),
                    GovernanceJobORM.status == JobStatus.RUNNING.value,
                    GovernanceJobORM.lease_owner == _safe_text(lease_owner, 128),
                )
                .update(
                    {
                        GovernanceJobORM.status: terminal,
                        GovernanceJobORM.finished_at: moment,
                        GovernanceJobORM.result: dict(result or {}),
                        GovernanceJobORM.error_code: (_safe_text(error_code, 64) or None),
                        GovernanceJobORM.error_message: (_safe_text(error_message, MAX_ERROR_LENGTH) or None),
                    },
                    synchronize_session=False,
                )
            )
            if not updated:
                session.rollback()
                return False
            event_type = {
                JobStatus.SUCCEEDED.value: JobEventType.SUCCEEDED.value,
                JobStatus.FAILED.value: JobEventType.FAILED.value,
                JobStatus.CANCELLED.value: JobEventType.CANCELLED.value,
                JobStatus.UNAVAILABLE.value: JobEventType.RECOVERED.value,
            }.get(terminal, terminal)
            session.add(
                GovernanceJobEventORM(
                    id=_new_id(),
                    job_id=str(job_id),
                    event_type=event_type,
                    from_status=JobStatus.RUNNING.value,
                    to_status=terminal,
                    actor_id=_safe_text(lease_owner, 128),
                    actor_role="SYSTEM",
                    detail={
                        "error_code": _safe_text(error_code, 64) or None,
                        "cancel_requested": bool(row.cancel_requested_at),
                    },
                    created_at=moment,
                )
            )
            session.commit()
            return True

    def request_cancel(
        self,
        job_id: str,
        *,
        actor_id: str,
        actor_role: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        """Cancel a PENDING job or request cooperative cancellation of a RUNNING one."""
        moment = normalize_utc(now or utcnow())
        with self._session_factory() as session:
            row = session.get(GovernanceJobORM, str(job_id))
            if row is None:
                raise JobNotFoundError(str(job_id))
            status = str(row.status)
            if status in {
                JobStatus.SUCCEEDED.value,
                JobStatus.FAILED.value,
                JobStatus.CANCELLED.value,
                JobStatus.UNAVAILABLE.value,
            }:
                raise JobStateError(f"job {job_id} is already terminal ({status})")
            actor = _safe_text(actor_id, 256) or "SYSTEM"
            role = _safe_text(actor_role, 16) or "SYSTEM"
            if status == JobStatus.PENDING.value:
                updated = (
                    session.query(GovernanceJobORM)
                    .filter(
                        GovernanceJobORM.id == str(job_id),
                        GovernanceJobORM.status == JobStatus.PENDING.value,
                    )
                    .update(
                        {
                            GovernanceJobORM.status: JobStatus.CANCELLED.value,
                            GovernanceJobORM.finished_at: moment,
                            GovernanceJobORM.cancel_requested_at: moment,
                            GovernanceJobORM.cancel_requested_by: actor,
                            GovernanceJobORM.error_code: "CANCELLED",
                            GovernanceJobORM.error_message: ("cancelled before execution"),
                        },
                        synchronize_session=False,
                    )
                )
                if not updated:
                    session.rollback()
                    raise JobStateError(f"job {job_id} changed state during cancellation")
                session.add(
                    GovernanceJobEventORM(
                        id=_new_id(),
                        job_id=str(job_id),
                        event_type=JobEventType.CANCELLED.value,
                        from_status=JobStatus.PENDING.value,
                        to_status=JobStatus.CANCELLED.value,
                        actor_id=actor,
                        actor_role=role,
                        detail={"immediate": True},
                        created_at=moment,
                    )
                )
                session.commit()
                refreshed = session.get(GovernanceJobORM, str(job_id))
                if refreshed is not None:
                    session.refresh(refreshed)
                payload = _job_to_dict(refreshed) if refreshed is not None else {}
                return {
                    "job": payload,
                    "cancelled": True,
                    "cancel_requested": True,
                }
            # RUNNING: cooperative cancellation only.
            if row.cancel_requested_at is None:
                row.cancel_requested_at = moment
                row.cancel_requested_by = actor
                session.add(
                    GovernanceJobEventORM(
                        id=_new_id(),
                        job_id=str(job_id),
                        event_type=JobEventType.CANCEL_REQUESTED.value,
                        from_status=JobStatus.RUNNING.value,
                        to_status=JobStatus.RUNNING.value,
                        actor_id=actor,
                        actor_role=role,
                        detail={"cooperative": True},
                        created_at=moment,
                    )
                )
                session.commit()
                session.refresh(row)
            return {
                "job": _job_to_dict(row),
                "cancelled": False,
                "cancel_requested": True,
            }

    def recover_expired_jobs(
        self,
        *,
        now: datetime | None = None,
        actor_id: str = "SYSTEM",
    ) -> list[dict[str, Any]]:
        """Mark RUNNING jobs with expired leases UNAVAILABLE (no side effects)."""
        moment = normalize_utc(now or utcnow())
        recovered: list[dict[str, Any]] = []
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceJobORM)
                .filter(
                    GovernanceJobORM.status == JobStatus.RUNNING.value,
                    GovernanceJobORM.lease_expires_at.is_not(None),
                    GovernanceJobORM.lease_expires_at <= moment,
                )
                .order_by(GovernanceJobORM.created_at.asc())
                .all()
            )
            for row in rows:
                job_id = row.id
                previous_owner = row.lease_owner
                updated = (
                    session.query(GovernanceJobORM)
                    .filter(
                        GovernanceJobORM.id == job_id,
                        GovernanceJobORM.status == JobStatus.RUNNING.value,
                        GovernanceJobORM.lease_expires_at.is_not(None),
                        GovernanceJobORM.lease_expires_at <= moment,
                    )
                    .update(
                        {
                            GovernanceJobORM.status: JobStatus.UNAVAILABLE.value,
                            GovernanceJobORM.finished_at: moment,
                            GovernanceJobORM.error_code: "LEASE_EXPIRED",
                            GovernanceJobORM.error_message: ("job lease expired before completion"),
                        },
                        synchronize_session=False,
                    )
                )
                if not updated:
                    continue
                session.add(
                    GovernanceJobEventORM(
                        id=_new_id(),
                        job_id=job_id,
                        event_type=JobEventType.LEASE_EXPIRED.value,
                        from_status=JobStatus.RUNNING.value,
                        to_status=JobStatus.UNAVAILABLE.value,
                        actor_id=_safe_text(actor_id, 256) or "SYSTEM",
                        actor_role="SYSTEM",
                        detail={"previous_lease_owner": previous_owner},
                        created_at=moment,
                    )
                )
                recovered.append({"job_id": job_id, "job_type": row.job_type})
            session.commit()
            return recovered

    def append_event(
        self,
        job_id: str,
        event_type: str,
        *,
        from_status: str | None = None,
        to_status: str | None = None,
        actor_id: str | None = None,
        actor_role: str | None = None,
        detail: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> None:
        moment = normalize_utc(now or utcnow())
        with self._session_factory() as session:
            session.add(
                GovernanceJobEventORM(
                    id=_new_id(),
                    job_id=str(job_id),
                    event_type=str(event_type).upper()[:32],
                    from_status=from_status,
                    to_status=to_status,
                    actor_id=_safe_text(actor_id, 256) or None,
                    actor_role=_safe_text(actor_role, 16) or None,
                    detail=dict(detail or {}),
                    created_at=moment,
                )
            )
            session.commit()

    def is_cancel_requested(self, job_id: str) -> bool:
        with self._session_factory() as session:
            row = session.get(GovernanceJobORM, str(job_id))
            return bool(row is not None and row.cancel_requested_at is not None)

    def job_events(self, job_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceJobEventORM)
                .filter_by(job_id=str(job_id))
                .order_by(
                    GovernanceJobEventORM.created_at.asc(),
                    GovernanceJobEventORM.id.asc(),
                )
                .all()
            )
            return [_event_to_dict(row) for row in rows]

    def queue_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in JobStatus}
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceJobORM.status, func.count(GovernanceJobORM.id))
                .group_by(GovernanceJobORM.status)
                .all()
            )
            for status, count in rows:
                counts[str(status)] = int(count)
        return counts

    def stale_job_count(self, *, now: datetime | None = None) -> int:
        moment = normalize_utc(now or utcnow())
        with self._session_factory() as session:
            return int(
                session.query(GovernanceJobORM)
                .filter(
                    GovernanceJobORM.status == JobStatus.RUNNING.value,
                    GovernanceJobORM.lease_expires_at.is_not(None),
                    GovernanceJobORM.lease_expires_at <= moment,
                )
                .count()
            )

    def latest_jobs_by_type(self) -> dict[str, dict[str, Any]]:
        result: dict[str, dict[str, Any]] = {}
        with self._session_factory() as session:
            for job_type in JobType:
                row = (
                    session.query(GovernanceJobORM)
                    .filter_by(job_type=job_type.value)
                    .order_by(GovernanceJobORM.created_at.desc(), GovernanceJobORM.id.desc())
                    .first()
                )
                if row is not None:
                    result[job_type.value] = _job_to_dict(row)
        return result

    def count_jobs(self) -> int:
        with self._session_factory() as session:
            return int(session.query(GovernanceJobORM).count())

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------
    def create_snapshot(
        self,
        *,
        snapshot_type: str,
        as_of: datetime,
        generated_by: str,
        dedup_key: str,
        payload: Mapping[str, Any],
        row_count: int = 0,
        job_id: str | None = None,
        trigger: str = "MANUAL",
        schema_version: int = SNAPSHOT_SCHEMA_VERSION,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        moment = normalize_utc(now or utcnow())
        key = _safe_text(dedup_key, MAX_DEDUP_KEY_LENGTH)
        if not key:
            raise ValueError("dedup_key is required")
        stored_payload = _safe_dict(payload)
        digest = sha256_hex(canonical_json_bytes(stored_payload))
        with self._session_factory() as session:
            existing = session.query(GovernanceSnapshotORM).filter_by(dedup_key=key).one_or_none()
            if existing is not None:
                return _snapshot_to_dict(existing), False
            row = GovernanceSnapshotORM(
                id=_new_id(),
                snapshot_type=str(snapshot_type).upper()[:32],
                as_of=normalize_utc(as_of),
                generated_at=moment,
                generated_by=_safe_text(generated_by, 256) or "SYSTEM",
                job_id=job_id,
                trigger=str(trigger).upper()[:16],
                dedup_key=key,
                payload=stored_payload,
                payload_digest=digest,
                row_count=max(0, int(row_count)),
                schema_version=max(1, int(schema_version)),
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = session.query(GovernanceSnapshotORM).filter_by(dedup_key=key).one_or_none()
                if existing is None:
                    raise
                return _snapshot_to_dict(existing), False
            session.refresh(row)
            return _snapshot_to_dict(row), True

    def get_snapshot(self, snapshot_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(GovernanceSnapshotORM, str(snapshot_id))
            return _snapshot_to_dict(row) if row is not None else None

    def require_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        snapshot = self.get_snapshot(snapshot_id)
        if snapshot is None:
            raise SnapshotNotFoundError(str(snapshot_id))
        return snapshot

    def find_snapshot_by_dedup_key(self, dedup_key: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceSnapshotORM)
                .filter_by(dedup_key=_safe_text(dedup_key, MAX_DEDUP_KEY_LENGTH))
                .one_or_none()
            )
            return _snapshot_to_dict(row) if row is not None else None

    def list_snapshots(
        self,
        *,
        snapshot_type: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceSnapshotORM)
            if snapshot_type:
                query = query.filter_by(snapshot_type=str(snapshot_type).upper())
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceSnapshotORM.generated_at.desc(),
                    GovernanceSnapshotORM.id.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_snapshot_to_dict(row) for row in rows], total

    def count_snapshots(self) -> int:
        with self._session_factory() as session:
            return int(session.query(GovernanceSnapshotORM).count())
