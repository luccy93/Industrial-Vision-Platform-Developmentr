"""Persistence for V38 executive governance.

Only the three V38 tables are written here. Report payloads are stored through
the V36 ``GovernanceAutomationRepository`` snapshot methods. No method deletes a
row, cascades a delete, or mutates evidence, cases, custody records, governance
workflow, automation jobs, intelligence recommendations, snapshots, or audit
history.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.redaction import redact_structure, redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.custody import canonical_json_bytes, datetime_to_iso, sha256_hex
from backend.app.governance.executive.constants import (
    ACTION_STATUS_VALUES,
    ACTION_TERMINAL_STATUSES,
    ACTION_TRANSITIONS,
    MAX_ACTION_DESCRIPTION_LENGTH,
    MAX_ACTION_EVENTS,
    MAX_ACTION_OUTCOME_LENGTH,
    MAX_ACTION_OWNER_LENGTH,
    MAX_ACTION_REASON_LENGTH,
    MAX_ACTION_TITLE_LENGTH,
)
from backend.app.governance.executive.errors import (
    ActionNotFoundError,
    ActionStateError,
    ActionVersionConflictError,
)
from backend.app.models.governance_executive_orm import (
    GovernanceExecutiveActionEventORM,
    GovernanceExecutiveActionORM,
    GovernanceExecutiveReportORM,
)


def _iso(value: datetime | None) -> str | None:
    return datetime_to_iso(value) if value is not None else None


def _normalize_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _safe_text(value: Any, limit: int) -> str:
    return redact_text(str(value or "").strip())[:limit]


def _safe_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        return {}
    redacted = redact_structure(dict(value))
    return dict(redacted) if isinstance(redacted, Mapping) else {}


def _new_id() -> str:
    return str(uuid.uuid4())


def _action_to_dict(row: GovernanceExecutiveActionORM) -> dict[str, Any]:
    return {
        "action_id": row.id,
        "recommendation_id": row.recommendation_id,
        "recommendation_rule_id": row.recommendation_rule_id,
        "recommendation_severity": row.recommendation_severity,
        "case_id": row.case_id,
        "title": row.title,
        "description": row.description,
        "owner_id": row.owner_id,
        "due_at": _iso(row.due_at),
        "priority": row.priority,
        "status": row.status,
        "version": int(row.version),
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "started_at": _iso(row.started_at),
        "blocked_at": _iso(row.blocked_at),
        "completed_at": _iso(row.completed_at),
        "cancelled_at": _iso(row.cancelled_at),
        "outcome_summary": row.outcome_summary,
        "block_reason": row.block_reason,
        "cancel_reason": row.cancel_reason,
        "idempotency_key": row.idempotency_key,
        "terminal": row.status in ACTION_TERMINAL_STATUSES,
        "overdue": (row.status not in ACTION_TERMINAL_STATUSES and _normalize_utc(row.due_at) < utcnow()),
    }


def _event_to_dict(row: GovernanceExecutiveActionEventORM) -> dict[str, Any]:
    return {
        "event_id": row.id,
        "action_id": row.action_id,
        "event_type": row.event_type,
        "from_status": row.from_status,
        "to_status": row.to_status,
        "actor_id": row.actor_id,
        "actor_role": row.actor_role,
        "reason": row.reason,
        "detail": _safe_dict(row.detail),
        "created_at": _iso(row.created_at),
    }


def _report_to_dict(row: GovernanceExecutiveReportORM) -> dict[str, Any]:
    return {
        "report_id": row.id,
        "report_type": row.report_type,
        "format": row.report_format,
        "status": row.status,
        "window_start": _iso(row.window_start),
        "window_end": _iso(row.window_end),
        "generated_at": _iso(row.generated_at),
        "generated_by": row.generated_by,
        "snapshot_id": row.snapshot_id,
        "snapshot_type": row.snapshot_type,
        "schema_version": int(row.schema_version),
        "source_coverage": _safe_dict(row.source_coverage),
        "sections_available": list(row.sections_available or []),
        "sections_unavailable": list(row.sections_unavailable or []),
        "payload_digest": row.payload_digest,
        "report_digest": row.report_digest,
        "row_count": int(row.row_count),
        "redaction_applied": bool(row.redaction_applied),
        "idempotency_key": row.idempotency_key,
        "reason": row.reason,
        "created_at": _iso(row.created_at),
    }


def report_digest_for(metadata: Mapping[str, Any]) -> str:
    """Deterministic self-digest over the report metadata contract."""
    canonical = {
        key: metadata.get(key)
        for key in (
            "report_id",
            "report_type",
            "format",
            "status",
            "window_start",
            "window_end",
            "generated_at",
            "generated_by",
            "snapshot_id",
            "snapshot_type",
            "schema_version",
            "payload_digest",
            "row_count",
            "redaction_applied",
            "idempotency_key",
        )
    }
    return sha256_hex(canonical_json_bytes(canonical))


class GovernanceExecutiveRepository:
    """Executive action, action-event, and report-metadata persistence."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Counts
    # ------------------------------------------------------------------
    def count_actions(self) -> int:
        with self._session_factory() as session:
            return int(session.query(GovernanceExecutiveActionORM).count())

    def action_status_counts(self) -> dict[str, int]:
        counts = {status: 0 for status in ACTION_STATUS_VALUES}
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceExecutiveActionORM.status,
                    func.count(GovernanceExecutiveActionORM.id),
                )
                .group_by(GovernanceExecutiveActionORM.status)
                .all()
            )
            for status, count in rows:
                counts[str(status)] = int(count)
        return counts

    def count_reports(self) -> int:
        with self._session_factory() as session:
            return int(session.query(GovernanceExecutiveReportORM).count())

    def report_type_counts(self) -> dict[str, int]:
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceExecutiveReportORM.report_type,
                    func.count(GovernanceExecutiveReportORM.id),
                )
                .group_by(GovernanceExecutiveReportORM.report_type)
                .all()
            )
            return {str(report_type): int(count) for report_type, count in rows}

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def get_action(self, action_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(GovernanceExecutiveActionORM, str(action_id))
            return _action_to_dict(row) if row is not None else None

    def find_action_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceExecutiveActionORM)
                .filter_by(idempotency_key=_safe_text(key, 128))
                .one_or_none()
            )
            return _action_to_dict(row) if row is not None else None

    def create_action(
        self,
        *,
        recommendation_id: str,
        recommendation_rule_id: str,
        recommendation_severity: str,
        case_id: str | None,
        title: str,
        description: str,
        owner_id: str,
        due_at: datetime,
        priority: str,
        created_by: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        moment = _normalize_utc(now or utcnow())
        key = _safe_text(idempotency_key, 128)
        if not key:
            raise ValueError("idempotency_key is required")
        existing = self.find_action_by_idempotency_key(key)
        if existing is not None:
            return existing, False
        row = GovernanceExecutiveActionORM(
            id=_new_id(),
            recommendation_id=str(recommendation_id),
            recommendation_rule_id=_safe_text(recommendation_rule_id, 64),
            recommendation_severity=_safe_text(recommendation_severity, 16),
            case_id=str(case_id) if case_id else None,
            title=_safe_text(title, MAX_ACTION_TITLE_LENGTH),
            description=_safe_text(description, MAX_ACTION_DESCRIPTION_LENGTH),
            owner_id=_safe_text(owner_id, MAX_ACTION_OWNER_LENGTH),
            due_at=_normalize_utc(due_at),
            priority=_safe_text(priority, 16).upper() or "MEDIUM",
            status="OPEN",
            version=1,
            created_by=_safe_text(created_by, 256) or "SYSTEM",
            created_at=moment,
            updated_at=moment,
            idempotency_key=key,
        )
        with self._session_factory() as session:
            session.add(row)
            session.flush()
            session.add(
                GovernanceExecutiveActionEventORM(
                    id=_new_id(),
                    action_id=row.id,
                    event_type="CREATED",
                    from_status=None,
                    to_status="OPEN",
                    actor_id=_safe_text(created_by, 256) or "SYSTEM",
                    actor_role="SYSTEM",
                    reason="Strategic action created.",
                    detail={
                        "recommendation_id": row.recommendation_id,
                        "owner_id": row.owner_id,
                        "due_at": _iso(row.due_at),
                    },
                    created_at=moment,
                )
            )
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = self.find_action_by_idempotency_key(key)
                if existing is None:
                    raise
                return existing, False
            session.refresh(row)
            return _action_to_dict(row), True

    def list_actions(
        self,
        *,
        status: str | None = None,
        owner_id: str | None = None,
        recommendation_id: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceExecutiveActionORM)
            if status:
                query = query.filter_by(status=str(status).upper())
            if owner_id:
                query = query.filter_by(owner_id=str(owner_id))
            if recommendation_id:
                query = query.filter_by(recommendation_id=str(recommendation_id))
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceExecutiveActionORM.due_at.asc(),
                    GovernanceExecutiveActionORM.created_at.asc(),
                    GovernanceExecutiveActionORM.id.asc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_action_to_dict(row) for row in rows], total

    def action_events(self, action_id: str, *, limit: int = MAX_ACTION_EVENTS) -> list[dict[str, Any]]:
        bounded = max(1, min(MAX_ACTION_EVENTS, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceExecutiveActionEventORM)
                .filter_by(action_id=str(action_id))
                .order_by(
                    GovernanceExecutiveActionEventORM.created_at.asc(),
                    GovernanceExecutiveActionEventORM.id.asc(),
                )
                .limit(bounded)
                .all()
            )
            return [_event_to_dict(row) for row in rows]

    def transition_action(
        self,
        action_id: str,
        *,
        target_status: str,
        expected_version: int,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        outcome_summary: str | None = None,
        block_reason: str | None = None,
        cancel_reason: str | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_utc(now or utcnow())
        target = str(target_status).upper()
        if target not in ACTION_STATUS_VALUES:
            raise ActionStateError(f"unsupported executive action status: {target_status}")
        with self._session_factory() as session:
            row = session.get(GovernanceExecutiveActionORM, str(action_id))
            if row is None:
                raise ActionNotFoundError(str(action_id))
            current = str(row.status)
            if int(expected_version) != int(row.version):
                raise ActionVersionConflictError(str(action_id), int(expected_version), int(row.version))
            allowed = ACTION_TRANSITIONS.get(current, frozenset())
            if target not in allowed:
                raise ActionStateError(f"executive action transition not allowed: {current} -> {target}")
            updates: dict[str, Any] = {
                "status": target,
                "version": int(row.version) + 1,
                "updated_at": moment,
            }
            if target == "IN_PROGRESS":
                if row.started_at is None:
                    updates["started_at"] = moment
                updates["block_reason"] = None
            elif target == "BLOCKED":
                updates["blocked_at"] = moment
                updates["block_reason"] = _safe_text(block_reason or reason, 2048)
            elif target == "COMPLETED":
                updates["completed_at"] = moment
                updates["outcome_summary"] = _safe_text(outcome_summary or "", MAX_ACTION_OUTCOME_LENGTH)
            elif target == "CANCELLED":
                updates["cancelled_at"] = moment
                updates["cancel_reason"] = _safe_text(cancel_reason or reason, 2048)
            updated = (
                session.query(GovernanceExecutiveActionORM)
                .filter_by(id=str(action_id), version=int(expected_version))
                .update(updates, synchronize_session=False)
            )
            if int(updated or 0) != 1:
                session.rollback()
                latest = session.get(GovernanceExecutiveActionORM, str(action_id))
                if latest is None:
                    raise ActionNotFoundError(str(action_id))
                raise ActionVersionConflictError(str(action_id), int(expected_version), int(latest.version))
            session.add(
                GovernanceExecutiveActionEventORM(
                    id=_new_id(),
                    action_id=str(action_id),
                    event_type="TRANSITIONED",
                    from_status=current,
                    to_status=target,
                    actor_id=_safe_text(actor_id, 256) or None,
                    actor_role=_safe_text(actor_role, 16).upper() or None,
                    reason=_safe_text(reason, MAX_ACTION_REASON_LENGTH),
                    detail={
                        "outcome_summary": _safe_text(outcome_summary or "", MAX_ACTION_OUTCOME_LENGTH)
                        or None,
                        "block_reason": _safe_text(block_reason or "", 2048) or None,
                        "cancel_reason": _safe_text(cancel_reason or "", 2048) or None,
                        "expected_version": int(expected_version),
                    },
                    created_at=moment,
                )
            )
            session.commit()
            session.refresh(row)
            return _action_to_dict(row)

    def assign_action(
        self,
        action_id: str,
        *,
        owner_id: str,
        expected_version: int,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_utc(now or utcnow())
        with self._session_factory() as session:
            row = session.get(GovernanceExecutiveActionORM, str(action_id))
            if row is None:
                raise ActionNotFoundError(str(action_id))
            current = str(row.status)
            if current in ACTION_TERMINAL_STATUSES:
                raise ActionStateError(f"executive action is terminal and cannot be reassigned: {current}")
            if int(expected_version) != int(row.version):
                raise ActionVersionConflictError(str(action_id), int(expected_version), int(row.version))
            updated = (
                session.query(GovernanceExecutiveActionORM)
                .filter_by(id=str(action_id), version=int(expected_version))
                .update(
                    {
                        "owner_id": _safe_text(owner_id, MAX_ACTION_OWNER_LENGTH),
                        "version": int(row.version) + 1,
                        "updated_at": moment,
                    },
                    synchronize_session=False,
                )
            )
            if int(updated or 0) != 1:
                session.rollback()
                latest = session.get(GovernanceExecutiveActionORM, str(action_id))
                if latest is None:
                    raise ActionNotFoundError(str(action_id))
                raise ActionVersionConflictError(str(action_id), int(expected_version), int(latest.version))
            session.add(
                GovernanceExecutiveActionEventORM(
                    id=_new_id(),
                    action_id=str(action_id),
                    event_type="ASSIGNED",
                    from_status=current,
                    to_status=current,
                    actor_id=_safe_text(actor_id, 256) or None,
                    actor_role=_safe_text(actor_role, 16).upper() or None,
                    reason=_safe_text(reason, MAX_ACTION_REASON_LENGTH),
                    detail={"owner_id": _safe_text(owner_id, MAX_ACTION_OWNER_LENGTH)},
                    created_at=moment,
                )
            )
            session.commit()
            session.refresh(row)
            return _action_to_dict(row)

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------
    def get_report(self, report_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(GovernanceExecutiveReportORM, str(report_id))
            return _report_to_dict(row) if row is not None else None

    def find_report_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceExecutiveReportORM)
                .filter_by(idempotency_key=_safe_text(key, 128))
                .one_or_none()
            )
            return _report_to_dict(row) if row is not None else None

    def create_report(
        self,
        *,
        report_type: str,
        report_format: str,
        window_start: datetime | None,
        window_end: datetime | None,
        generated_by: str,
        snapshot_id: str,
        snapshot_type: str,
        schema_version: int,
        source_coverage: Mapping[str, Any],
        sections_available: list[str],
        sections_unavailable: list[str],
        payload_digest: str,
        row_count: int,
        idempotency_key: str,
        reason: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        moment = _normalize_utc(now or utcnow())
        key = _safe_text(idempotency_key, 128)
        if not key:
            raise ValueError("idempotency_key is required")
        existing = self.find_report_by_idempotency_key(key)
        if existing is not None:
            return existing, False
        report_id = _new_id()
        metadata = {
            "report_id": report_id,
            "report_type": str(report_type).upper(),
            "format": str(report_format).lower(),
            "status": "GENERATED",
            "window_start": _iso(window_start),
            "window_end": _iso(window_end),
            "generated_at": _iso(moment),
            "generated_by": _safe_text(generated_by, 256) or "SYSTEM",
            "snapshot_id": str(snapshot_id),
            "snapshot_type": str(snapshot_type).upper(),
            "schema_version": max(1, int(schema_version)),
            "payload_digest": str(payload_digest),
            "row_count": max(0, int(row_count)),
            "redaction_applied": True,
            "idempotency_key": key,
        }
        row = GovernanceExecutiveReportORM(
            id=report_id,
            report_type=metadata["report_type"],
            report_format=metadata["format"],
            status="GENERATED",
            window_start=_normalize_utc(window_start) if window_start else None,
            window_end=_normalize_utc(window_end) if window_end else None,
            generated_at=moment,
            generated_by=metadata["generated_by"],
            snapshot_id=str(snapshot_id),
            snapshot_type=metadata["snapshot_type"],
            schema_version=metadata["schema_version"],
            source_coverage=_safe_dict(source_coverage),
            sections_available=[_safe_text(item, 64) for item in sections_available],
            sections_unavailable=[_safe_text(item, 64) for item in sections_unavailable],
            payload_digest=metadata["payload_digest"],
            report_digest=report_digest_for(metadata),
            row_count=metadata["row_count"],
            redaction_applied=True,
            idempotency_key=key,
            reason=_safe_text(reason, 2048),
            created_at=moment,
        )
        with self._session_factory() as session:
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = self.find_report_by_idempotency_key(key)
                if existing is None:
                    raise
                return existing, False
            session.refresh(row)
            return _report_to_dict(row), True

    def list_reports(
        self,
        *,
        report_type: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceExecutiveReportORM)
            if report_type:
                query = query.filter_by(report_type=str(report_type).upper())
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceExecutiveReportORM.generated_at.desc(),
                    GovernanceExecutiveReportORM.id.desc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_report_to_dict(row) for row in rows], total


__all__ = [
    "GovernanceExecutiveRepository",
    "report_digest_for",
]
