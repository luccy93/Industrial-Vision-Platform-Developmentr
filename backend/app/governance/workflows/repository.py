"""Persistence for V39 enterprise workflow orchestration.

Only the seven V39 tables are written here. Every state change and its event are
written in one transaction. Task dependencies, references, and events are
append-only. No method deletes a row, cascades a delete, or mutates evidence,
cases, custody records, governance records, automation jobs, intelligence
recommendations, executive actions, snapshots, or audit history.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import case, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.core.redaction import redact_structure, redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.custody import datetime_to_iso
from backend.app.governance.workflows.constants import (
    ESCALATION_STATUS_VALUES,
    ESCALATION_TRANSITIONS,
    MAX_EVENTS_PER_READ,
    MAX_REFERENCE_KEY_LENGTH,
    MAX_REFERENCE_LABEL_LENGTH,
    MAX_REFERENCE_SOURCE_ID_LENGTH,
    MAX_WORKFLOW_DESCRIPTION_LENGTH,
    MAX_WORKFLOW_OUTCOME_LENGTH,
    MAX_WORKFLOW_OWNER_LENGTH,
    MAX_WORKFLOW_REASON_LENGTH,
    MAX_WORKFLOW_TITLE_LENGTH,
    TASK_OPEN_STATUSES,
    TASK_STATUS_VALUES,
    TASK_TERMINAL_STATUSES,
    TASK_TRANSITIONS,
    WORKFLOW_OPEN_STATUSES,
    WORKFLOW_STATUS_VALUES,
    WORKFLOW_TERMINAL_STATUSES,
    WORKFLOW_TRANSITIONS,
    TaskStatus,
    TemplateStatus,
    WorkflowEventType,
    WorkflowStatus,
)
from backend.app.governance.workflows.dependencies import (
    DEPENDENCY_BLOCKED,
    DEPENDENCY_READY,
    dependency_verdict,
)
from backend.app.governance.workflows.errors import (
    EscalationNotFoundError,
    EscalationStateError,
    EscalationVersionConflictError,
    TaskNotFoundError,
    TaskStateError,
    TaskVersionConflictError,
    TemplateNotFoundError,
    WorkflowNotFoundError,
    WorkflowStateError,
    WorkflowVersionConflictError,
)
from backend.app.models.governance_workflow_orm import (
    GovernanceWorkflowEscalationORM,
    GovernanceWorkflowEventORM,
    GovernanceWorkflowORM,
    GovernanceWorkflowReferenceORM,
    GovernanceWorkflowTaskDependencyORM,
    GovernanceWorkflowTaskORM,
    GovernanceWorkflowTemplateORM,
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


def _template_to_dict(row: GovernanceWorkflowTemplateORM) -> dict[str, Any]:
    return {
        "template_id": row.id,
        "template_key": row.template_key,
        "version": int(row.version),
        "name": row.name,
        "description": row.description,
        "status": row.status,
        "definition": _safe_dict(row.definition),
        "definition_digest": row.definition_digest,
        "task_count": int(row.task_count),
        "dependency_count": int(row.dependency_count),
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "idempotency_key": row.idempotency_key,
        "disabled": row.status == TemplateStatus.DISABLED.value,
    }


def _workflow_to_dict(row: GovernanceWorkflowORM) -> dict[str, Any]:
    return {
        "workflow_id": row.id,
        "template_id": row.template_id,
        "template_key": row.template_key,
        "template_version": int(row.template_version),
        "template_digest": row.template_digest,
        "template_snapshot": _safe_dict(row.template_snapshot),
        "case_id": row.case_id,
        "title": row.title,
        "description": row.description,
        "status": row.status,
        "version": int(row.version),
        "owner_type": row.owner_type,
        "owner_id": row.owner_id,
        "priority": row.priority,
        "due_at": _iso(row.due_at),
        "created_by": row.created_by,
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "ready_at": _iso(row.ready_at),
        "started_at": _iso(row.started_at),
        "blocked_at": _iso(row.blocked_at),
        "review_at": _iso(row.review_at),
        "completed_at": _iso(row.completed_at),
        "cancelled_at": _iso(row.cancelled_at),
        "outcome_summary": row.outcome_summary,
        "block_reason": row.block_reason,
        "cancel_reason": row.cancel_reason,
        "idempotency_key": row.idempotency_key,
        "terminal": row.status in WORKFLOW_TERMINAL_STATUSES,
        "unassigned": row.owner_id is None,
    }


def _task_to_dict(row: GovernanceWorkflowTaskORM) -> dict[str, Any]:
    return {
        "task_id": row.id,
        "workflow_id": row.workflow_id,
        "task_key": row.task_key,
        "title": row.title,
        "description": row.description,
        "status": row.status,
        "version": int(row.version),
        "owner_type": row.owner_type,
        "owner_id": row.owner_id,
        "required": bool(row.required),
        "order_index": int(row.order_index),
        "due_at": _iso(row.due_at),
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
        "started_at": _iso(row.started_at),
        "blocked_at": _iso(row.blocked_at),
        "completed_at": _iso(row.completed_at),
        "cancelled_at": _iso(row.cancelled_at),
        "outcome_summary": row.outcome_summary,
        "block_reason": row.block_reason,
        "cancel_reason": row.cancel_reason,
        "terminal": row.status in TASK_TERMINAL_STATUSES,
        "unassigned": row.owner_id is None,
    }


def _dependency_to_dict(row: GovernanceWorkflowTaskDependencyORM) -> dict[str, Any]:
    return {
        "dependency_id": row.id,
        "workflow_id": row.workflow_id,
        "task_id": row.task_id,
        "depends_on_task_id": row.depends_on_task_id,
        "created_at": _iso(row.created_at),
    }


def _reference_to_dict(row: GovernanceWorkflowReferenceORM) -> dict[str, Any]:
    return {
        "reference_id": row.id,
        "workflow_id": row.workflow_id,
        "task_id": row.task_id,
        "domain": row.domain,
        "source_id": row.source_id,
        "reference_key": row.reference_key,
        "source_label": row.source_label,
        "source_case_id": row.source_case_id,
        "availability": row.availability,
        "source_status": row.source_status,
        "source_version": int(row.source_version) if row.source_version is not None else None,
        "added_by": row.added_by,
        "added_at": _iso(row.added_at),
        "last_checked_at": _iso(row.last_checked_at),
        "reason": row.reason,
    }


def _escalation_to_dict(row: GovernanceWorkflowEscalationORM) -> dict[str, Any]:
    return {
        "escalation_id": row.id,
        "workflow_id": row.workflow_id,
        "task_id": row.task_id,
        "escalation_type": row.escalation_type,
        "severity": row.severity,
        "status": row.status,
        "reason": row.reason,
        "resolution": row.resolution,
        "requested_by": row.requested_by,
        "requested_at": _iso(row.requested_at),
        "acknowledged_by": row.acknowledged_by,
        "acknowledged_at": _iso(row.acknowledged_at),
        "resolved_by": row.resolved_by,
        "resolved_at": _iso(row.resolved_at),
        "version": int(row.version),
        "idempotency_key": row.idempotency_key,
        "terminal": row.status == "RESOLVED",
    }


def _event_to_dict(row: GovernanceWorkflowEventORM) -> dict[str, Any]:
    return {
        "event_id": row.id,
        "workflow_id": row.workflow_id,
        "task_id": row.task_id,
        "template_id": row.template_id,
        "event_type": row.event_type,
        "from_status": row.from_status,
        "to_status": row.to_status,
        "actor_id": row.actor_id,
        "actor_role": row.actor_role,
        "reason": row.reason,
        "detail": _safe_dict(row.detail),
        "sequence": int(row.sequence),
        "created_at": _iso(row.created_at),
    }


class GovernanceWorkflowRepository:
    """Workflow template, instance, task, reference, escalation, and event storage."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Shared helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _event(
        session: Session,
        *,
        moment: datetime,
        event_type: str,
        workflow_id: str | None = None,
        task_id: str | None = None,
        template_id: str | None = None,
        from_status: str | None = None,
        to_status: str | None = None,
        actor_id: str | None = None,
        actor_role: str | None = None,
        reason: str = "",
        detail: Mapping[str, Any] | None = None,
    ) -> None:
        # Flush pending rows first so the per-parent monotonic sequence is
        # computed from everything already written in this transaction.
        session.flush()
        sequence_query = session.query(func.max(GovernanceWorkflowEventORM.sequence))
        if workflow_id is not None:
            sequence_query = sequence_query.filter_by(workflow_id=str(workflow_id))
        elif template_id is not None:
            sequence_query = sequence_query.filter_by(template_id=str(template_id))
        sequence = int(sequence_query.scalar() or 0) + 1
        session.add(
            GovernanceWorkflowEventORM(
                id=_new_id(),
                workflow_id=workflow_id,
                task_id=task_id,
                template_id=template_id,
                event_type=str(event_type),
                from_status=from_status,
                to_status=to_status,
                actor_id=_safe_text(actor_id, 256) or None,
                actor_role=_safe_text(actor_role, 16).upper() or None,
                reason=_safe_text(reason, MAX_WORKFLOW_REASON_LENGTH),
                detail=_safe_dict(detail or {}),
                sequence=sequence,
                created_at=moment,
            )
        )

    @staticmethod
    def _await_conflicting_write(
        reader: Callable[[], dict[str, Any] | None],
    ) -> dict[str, Any] | None:
        """Wait briefly for a concurrent unique-key winner to become visible."""
        for attempt in range(5):
            existing = reader()
            if existing is not None:
                return existing
            if attempt < 4:
                time.sleep(0.01 * (attempt + 1))
        return None

    # ------------------------------------------------------------------
    # Templates
    # ------------------------------------------------------------------
    def get_template(self, template_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(GovernanceWorkflowTemplateORM, str(template_id))
            return _template_to_dict(row) if row is not None else None

    def find_template_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceWorkflowTemplateORM)
                .filter_by(idempotency_key=_safe_text(key, 128))
                .one_or_none()
            )
            return _template_to_dict(row) if row is not None else None

    def template_by_key_version(self, template_key: str, version: int) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceWorkflowTemplateORM)
                .filter_by(template_key=str(template_key).strip().upper(), version=int(version))
                .one_or_none()
            )
            return _template_to_dict(row) if row is not None else None

    def latest_template(
        self, template_key: str, *, statuses: Sequence[str] = ("ACTIVE",)
    ) -> dict[str, Any] | None:
        with self._session_factory() as session:
            query = session.query(GovernanceWorkflowTemplateORM).filter_by(
                template_key=str(template_key).strip().upper()
            )
            normalized = tuple(str(item).upper() for item in statuses)
            if normalized:
                query = query.filter(GovernanceWorkflowTemplateORM.status.in_(normalized))
            row = query.order_by(GovernanceWorkflowTemplateORM.version.desc()).first()
            return _template_to_dict(row) if row is not None else None

    def next_template_version(self, template_key: str) -> int:
        with self._session_factory() as session:
            latest = (
                session.query(func.max(GovernanceWorkflowTemplateORM.version))
                .filter_by(template_key=str(template_key).strip().upper())
                .scalar()
            )
            return int(latest or 0) + 1

    def list_templates(
        self,
        *,
        template_key: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceWorkflowTemplateORM)
            if template_key:
                query = query.filter_by(template_key=str(template_key).strip().upper())
            if status:
                query = query.filter_by(status=str(status).strip().upper())
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceWorkflowTemplateORM.template_key.asc(),
                    GovernanceWorkflowTemplateORM.version.desc(),
                    GovernanceWorkflowTemplateORM.id.asc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_template_to_dict(row) for row in rows], total

    def create_template(
        self,
        *,
        template_key: str,
        version: int,
        name: str,
        description: str,
        definition: Mapping[str, Any],
        definition_digest: str,
        task_count: int,
        dependency_count: int,
        created_by: str,
        idempotency_key: str,
        actor_role: str,
        reason: str,
        event_type: str = WorkflowEventType.TEMPLATE_CREATED.value,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        moment = _normalize_utc(now or utcnow())
        key = _safe_text(idempotency_key, 128)
        if not key:
            raise ValueError("idempotency_key is required")
        existing = self.find_template_by_idempotency_key(key)
        if existing is not None:
            return existing, False
        normalized_key = str(template_key).strip().upper()
        row = GovernanceWorkflowTemplateORM(
            id=_new_id(),
            template_key=normalized_key,
            version=max(1, int(version)),
            name=_safe_text(name, MAX_WORKFLOW_TITLE_LENGTH),
            description=_safe_text(description, MAX_WORKFLOW_DESCRIPTION_LENGTH),
            status=TemplateStatus.ACTIVE.value,
            definition=_safe_dict(definition),
            definition_digest=str(definition_digest),
            task_count=max(0, int(task_count)),
            dependency_count=max(0, int(dependency_count)),
            created_by=_safe_text(created_by, 256) or "SYSTEM",
            created_at=moment,
            updated_at=moment,
            idempotency_key=key,
        )
        with self._session_factory() as session:
            # Exactly one active version per template key. Superseding is an
            # internal status update; the new version carries the audit event.
            session.query(GovernanceWorkflowTemplateORM).filter(
                GovernanceWorkflowTemplateORM.template_key == normalized_key,
                GovernanceWorkflowTemplateORM.status == TemplateStatus.ACTIVE.value,
            ).update({"status": TemplateStatus.SUPERSEDED.value, "updated_at": moment})
            session.add(row)
            try:
                session.flush()
                self._event(
                    session,
                    moment=moment,
                    event_type=event_type,
                    template_id=row.id,
                    actor_id=created_by,
                    actor_role=actor_role,
                    reason=reason,
                    detail={
                        "template_key": normalized_key,
                        "version": int(row.version),
                        "definition_digest": str(definition_digest),
                        "task_count": int(task_count),
                        "dependency_count": int(dependency_count),
                    },
                )
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = self._await_conflicting_write(lambda: self.find_template_by_idempotency_key(key))
                if existing is not None:
                    return existing, False
                raise
            session.refresh(row)
            return _template_to_dict(row), True

    def disable_template(
        self,
        template_id: str,
        *,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        moment = _normalize_utc(now or utcnow())
        with self._session_factory() as session:
            row = session.get(GovernanceWorkflowTemplateORM, str(template_id))
            if row is None:
                raise TemplateNotFoundError(str(template_id))
            if row.status == TemplateStatus.DISABLED.value:
                return _template_to_dict(row), False
            row.status = TemplateStatus.DISABLED.value
            row.updated_at = moment
            self._event(
                session,
                moment=moment,
                event_type=WorkflowEventType.TEMPLATE_DISABLED.value,
                template_id=row.id,
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                detail={"template_key": row.template_key, "version": int(row.version)},
            )
            session.commit()
            session.refresh(row)
            return _template_to_dict(row), True

    # ------------------------------------------------------------------
    # Counts
    # ------------------------------------------------------------------
    def count_workflows(self) -> int:
        with self._session_factory() as session:
            return int(session.query(GovernanceWorkflowORM).count())

    def workflow_status_counts(self) -> dict[str, int]:
        counts = {status: 0 for status in WORKFLOW_STATUS_VALUES}
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceWorkflowORM.status,
                    func.count(GovernanceWorkflowORM.id),
                )
                .group_by(GovernanceWorkflowORM.status)
                .all()
            )
            for status, count in rows:
                counts[str(status)] = int(count)
        return counts

    def task_status_counts(self) -> dict[str, int]:
        counts = {status: 0 for status in TASK_STATUS_VALUES}
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceWorkflowTaskORM.status,
                    func.count(GovernanceWorkflowTaskORM.id),
                )
                .group_by(GovernanceWorkflowTaskORM.status)
                .all()
            )
            for status, count in rows:
                counts[str(status)] = int(count)
        return counts

    def escalation_status_counts(self) -> dict[str, int]:
        counts = {status: 0 for status in ESCALATION_STATUS_VALUES}
        with self._session_factory() as session:
            rows = (
                session.query(
                    GovernanceWorkflowEscalationORM.status,
                    func.count(GovernanceWorkflowEscalationORM.id),
                )
                .group_by(GovernanceWorkflowEscalationORM.status)
                .all()
            )
            for status, count in rows:
                counts[str(status)] = int(count)
        return counts

    def unassigned_counts(self) -> dict[str, int]:
        open_workflows = tuple(sorted(WORKFLOW_OPEN_STATUSES))
        open_tasks = tuple(status for status in TASK_STATUS_VALUES if status not in TASK_TERMINAL_STATUSES)
        with self._session_factory() as session:
            workflows = int(
                session.query(GovernanceWorkflowORM)
                .filter(
                    GovernanceWorkflowORM.owner_id.is_(None),
                    GovernanceWorkflowORM.status.in_(open_workflows),
                )
                .count()
            )
            tasks = int(
                session.query(GovernanceWorkflowTaskORM)
                .filter(
                    GovernanceWorkflowTaskORM.owner_id.is_(None),
                    GovernanceWorkflowTaskORM.status.in_(open_tasks),
                )
                .count()
            )
        return {"workflows": workflows, "tasks": tasks}

    def overdue_counts(self, *, now: datetime) -> dict[str, int]:
        moment = _normalize_utc(now)
        open_workflows = tuple(sorted(WORKFLOW_OPEN_STATUSES))
        open_tasks = tuple(status for status in TASK_STATUS_VALUES if status not in TASK_TERMINAL_STATUSES)
        with self._session_factory() as session:
            workflows = int(
                session.query(GovernanceWorkflowORM)
                .filter(
                    GovernanceWorkflowORM.status.in_(open_workflows),
                    GovernanceWorkflowORM.due_at.is_not(None),
                    GovernanceWorkflowORM.due_at < moment,
                )
                .count()
            )
            tasks = int(
                session.query(GovernanceWorkflowTaskORM)
                .filter(
                    GovernanceWorkflowTaskORM.status.in_(open_tasks),
                    GovernanceWorkflowTaskORM.due_at.is_not(None),
                    GovernanceWorkflowTaskORM.due_at < moment,
                )
                .count()
            )
        return {"workflows": workflows, "tasks": tasks}

    # ------------------------------------------------------------------
    # Workflows
    # ------------------------------------------------------------------
    def get_workflow(self, workflow_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(GovernanceWorkflowORM, str(workflow_id))
            return _workflow_to_dict(row) if row is not None else None

    def find_workflow_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceWorkflowORM)
                .filter_by(idempotency_key=_safe_text(key, 128))
                .one_or_none()
            )
            return _workflow_to_dict(row) if row is not None else None

    def list_workflows(
        self,
        *,
        status: str | None = None,
        owner_id: str | None = None,
        case_id: str | None = None,
        unassigned: bool = False,
        overdue: bool = False,
        page: int = 1,
        page_size: int = 20,
        now: datetime | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        moment = _normalize_utc(now or utcnow())
        open_workflows = tuple(sorted(WORKFLOW_OPEN_STATUSES))
        with self._session_factory() as session:
            query = session.query(GovernanceWorkflowORM)
            if status:
                query = query.filter_by(status=str(status).strip().upper())
            if owner_id:
                query = query.filter_by(owner_id=str(owner_id))
            if case_id:
                query = query.filter_by(case_id=str(case_id))
            if unassigned:
                query = query.filter(GovernanceWorkflowORM.owner_id.is_(None))
            if overdue:
                query = query.filter(
                    GovernanceWorkflowORM.status.in_(open_workflows),
                    GovernanceWorkflowORM.due_at.is_not(None),
                    GovernanceWorkflowORM.due_at < moment,
                )
            total = int(query.count())
            rows = (
                query.order_by(
                    case((GovernanceWorkflowORM.due_at.is_(None), 1), else_=0),
                    GovernanceWorkflowORM.due_at.asc(),
                    GovernanceWorkflowORM.created_at.desc(),
                    GovernanceWorkflowORM.id.asc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_workflow_to_dict(row) for row in rows], total

    def active_workflows(self, *, limit: int = 500) -> list[dict[str, Any]]:
        bounded = min(500, max(1, int(limit)))
        open_workflows = tuple(sorted(WORKFLOW_OPEN_STATUSES))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowORM)
                .filter(GovernanceWorkflowORM.status.in_(open_workflows))
                .order_by(
                    GovernanceWorkflowORM.created_at.asc(),
                    GovernanceWorkflowORM.id.asc(),
                )
                .limit(bounded)
                .all()
            )
            return [_workflow_to_dict(row) for row in rows]

    def active_tasks(self, *, limit: int = 500) -> list[dict[str, Any]]:
        bounded = min(500, max(1, int(limit)))
        open_tasks = tuple(sorted(TASK_OPEN_STATUSES))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowTaskORM)
                .filter(GovernanceWorkflowTaskORM.status.in_(open_tasks))
                .order_by(
                    GovernanceWorkflowTaskORM.created_at.asc(),
                    GovernanceWorkflowTaskORM.id.asc(),
                )
                .limit(bounded)
                .all()
            )
            return [_task_to_dict(row) for row in rows]

    def create_workflow(
        self,
        *,
        template: Mapping[str, Any],
        case_id: str | None,
        title: str,
        description: str,
        priority: str,
        due_at: datetime | None,
        owner_type: str | None,
        owner_id: str | None,
        created_by: str,
        actor_role: str,
        idempotency_key: str,
        reason: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        moment = _normalize_utc(now or utcnow())
        key = _safe_text(idempotency_key, 128)
        if not key:
            raise ValueError("idempotency_key is required")
        existing = self.find_workflow_by_idempotency_key(key)
        if existing is not None:
            return existing, False
        definition = template.get("definition")
        if not isinstance(definition, Mapping):
            raise ValueError("template definition is unavailable")
        task_specs = list(definition.get("tasks") or [])
        snapshot = {
            "template_id": template.get("template_id"),
            "template_key": template.get("template_key"),
            "template_version": template.get("version"),
            "name": template.get("name"),
            "description": template.get("description"),
            "definition": dict(definition),
            "definition_digest": template.get("definition_digest"),
            "pinned_at": _iso(moment),
        }
        workflow_id = _new_id()
        workflow_row = GovernanceWorkflowORM(
            id=workflow_id,
            template_id=str(template.get("template_id")),
            template_key=_safe_text(template.get("template_key"), 64).upper(),
            template_version=int(template.get("version") or 1),
            template_digest=str(template.get("definition_digest") or ""),
            template_snapshot=_safe_dict(snapshot),
            case_id=str(case_id) if case_id else None,
            title=_safe_text(title, MAX_WORKFLOW_TITLE_LENGTH),
            description=_safe_text(description, MAX_WORKFLOW_DESCRIPTION_LENGTH),
            status=WorkflowStatus.DRAFT.value,
            version=1,
            owner_type=str(owner_type).upper() if owner_type else None,
            owner_id=_safe_text(owner_id, MAX_WORKFLOW_OWNER_LENGTH) or None,
            priority=_safe_text(priority, 16).upper() or "MEDIUM",
            due_at=_normalize_utc(due_at) if due_at else None,
            created_by=_safe_text(created_by, 256) or "SYSTEM",
            created_at=moment,
            updated_at=moment,
            idempotency_key=key,
        )
        task_rows: list[GovernanceWorkflowTaskORM] = []
        task_id_by_key: dict[str, str] = {}
        for spec in task_specs:
            task_key = str(spec.get("task_key") or "")
            task_id = _new_id()
            task_id_by_key[task_key] = task_id
            due_in_hours = spec.get("due_in_hours")
            task_due = moment + timedelta(hours=int(due_in_hours)) if due_in_hours is not None else None
            task_rows.append(
                GovernanceWorkflowTaskORM(
                    id=task_id,
                    workflow_id=workflow_id,
                    task_key=task_key,
                    title=_safe_text(spec.get("title"), MAX_WORKFLOW_TITLE_LENGTH),
                    description=_safe_text(spec.get("description"), MAX_WORKFLOW_DESCRIPTION_LENGTH),
                    status=TaskStatus.PENDING.value,
                    version=1,
                    required=bool(spec.get("required", True)),
                    order_index=int(spec.get("order_index", 0)),
                    due_at=task_due,
                    created_at=moment,
                    updated_at=moment,
                )
            )
        with self._session_factory() as session:
            session.add(workflow_row)
            session.add_all(task_rows)
            try:
                session.flush()
                for spec in task_specs:
                    task_key = str(spec.get("task_key") or "")
                    for dependency_key in spec.get("depends_on") or []:
                        session.add(
                            GovernanceWorkflowTaskDependencyORM(
                                id=_new_id(),
                                workflow_id=workflow_id,
                                task_id=task_id_by_key[task_key],
                                depends_on_task_id=task_id_by_key[str(dependency_key)],
                                created_at=moment,
                            )
                        )
                self._event(
                    session,
                    moment=moment,
                    event_type=WorkflowEventType.WORKFLOW_CREATED.value,
                    workflow_id=workflow_id,
                    actor_id=created_by,
                    actor_role=actor_role,
                    reason=reason,
                    detail={
                        "template_id": workflow_row.template_id,
                        "template_key": workflow_row.template_key,
                        "template_version": workflow_row.template_version,
                        "task_count": len(task_rows),
                        "case_id": workflow_row.case_id,
                    },
                )
                for spec in task_specs:
                    task_key = str(spec.get("task_key") or "")
                    self._event(
                        session,
                        moment=moment,
                        event_type=WorkflowEventType.TASK_CREATED.value,
                        workflow_id=workflow_id,
                        task_id=task_id_by_key[task_key],
                        actor_id=created_by,
                        actor_role=actor_role,
                        reason="Task instantiated from the pinned template version.",
                        detail={
                            "task_key": task_key,
                            "required": bool(spec.get("required", True)),
                            "order_index": int(spec.get("order_index", 0)),
                            "depends_on": list(spec.get("depends_on") or []),
                        },
                    )
                if workflow_row.owner_id:
                    self._event(
                        session,
                        moment=moment,
                        event_type=WorkflowEventType.WORKFLOW_ASSIGNED.value,
                        workflow_id=workflow_id,
                        actor_id=created_by,
                        actor_role=actor_role,
                        reason=reason,
                        detail={
                            "owner_type": workflow_row.owner_type,
                            "owner_id": workflow_row.owner_id,
                            "reassigned": False,
                        },
                    )
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = self._await_conflicting_write(lambda: self.find_workflow_by_idempotency_key(key))
                if existing is not None:
                    return existing, False
                raise
            session.refresh(workflow_row)
            return _workflow_to_dict(workflow_row), True

    def workflow_tasks(self, workflow_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowTaskORM)
                .filter_by(workflow_id=str(workflow_id))
                .order_by(
                    GovernanceWorkflowTaskORM.order_index.asc(),
                    GovernanceWorkflowTaskORM.task_key.asc(),
                    GovernanceWorkflowTaskORM.id.asc(),
                )
                .all()
            )
            return [_task_to_dict(row) for row in rows]

    def get_task(self, workflow_id: str, task_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceWorkflowTaskORM)
                .filter_by(id=str(task_id), workflow_id=str(workflow_id))
                .one_or_none()
            )
            return _task_to_dict(row) if row is not None else None

    def workflow_dependencies(self, workflow_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowTaskDependencyORM)
                .filter_by(workflow_id=str(workflow_id))
                .order_by(
                    GovernanceWorkflowTaskDependencyORM.task_id.asc(),
                    GovernanceWorkflowTaskDependencyORM.depends_on_task_id.asc(),
                )
                .all()
            )
            task_keys = {
                str(row.id): str(row.task_key)
                for row in session.query(GovernanceWorkflowTaskORM)
                .filter_by(workflow_id=str(workflow_id))
                .all()
            }
            items = []
            for row in rows:
                item = _dependency_to_dict(row)
                item["task_key"] = task_keys.get(str(row.task_id))
                item["depends_on_task_key"] = task_keys.get(str(row.depends_on_task_id))
                items.append(item)
            return items

    def task_dependency_ids(self, task_id: str) -> list[str]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowTaskDependencyORM.depends_on_task_id)
                .filter_by(task_id=str(task_id))
                .all()
            )
            return [str(row[0]) for row in rows]

    def list_tasks(
        self,
        *,
        workflow_id: str | None = None,
        status: str | None = None,
        owner_id: str | None = None,
        unassigned: bool = False,
        overdue: bool = False,
        page: int = 1,
        page_size: int = 20,
        now: datetime | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        moment = _normalize_utc(now or utcnow())
        open_tasks = tuple(status for status in TASK_STATUS_VALUES if status not in TASK_TERMINAL_STATUSES)
        with self._session_factory() as session:
            query = session.query(GovernanceWorkflowTaskORM)
            if workflow_id:
                query = query.filter_by(workflow_id=str(workflow_id))
            if status:
                query = query.filter_by(status=str(status).strip().upper())
            if owner_id:
                query = query.filter_by(owner_id=str(owner_id))
            if unassigned:
                query = query.filter(GovernanceWorkflowTaskORM.owner_id.is_(None))
            if overdue:
                query = query.filter(
                    GovernanceWorkflowTaskORM.status.in_(open_tasks),
                    GovernanceWorkflowTaskORM.due_at.is_not(None),
                    GovernanceWorkflowTaskORM.due_at < moment,
                )
            total = int(query.count())
            rows = (
                query.order_by(
                    case((GovernanceWorkflowTaskORM.due_at.is_(None), 1), else_=0),
                    GovernanceWorkflowTaskORM.due_at.asc(),
                    GovernanceWorkflowTaskORM.created_at.asc(),
                    GovernanceWorkflowTaskORM.id.asc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_task_to_dict(row) for row in rows], total

    def _evaluate_dependencies(
        self,
        session: Session,
        *,
        workflow_id: str,
        moment: datetime,
        actor_id: str | None,
        actor_role: str,
        reason: str,
    ) -> dict[str, int]:
        """Advance PENDING tasks deterministically after a state change."""
        session.expire_all()
        tasks = (
            session.query(GovernanceWorkflowTaskORM)
            .filter_by(workflow_id=str(workflow_id))
            .order_by(
                GovernanceWorkflowTaskORM.order_index.asc(),
                GovernanceWorkflowTaskORM.task_key.asc(),
                GovernanceWorkflowTaskORM.id.asc(),
            )
            .all()
        )
        status_by_id = {str(task.id): str(task.status) for task in tasks}
        dependency_ids: dict[str, list[str]] = {str(task.id): [] for task in tasks}
        dependency_rows = (
            session.query(GovernanceWorkflowTaskDependencyORM)
            .filter_by(workflow_id=str(workflow_id))
            .order_by(GovernanceWorkflowTaskDependencyORM.id.asc())
            .all()
        )
        for row in dependency_rows:
            dependency_ids.setdefault(str(row.task_id), []).append(str(row.depends_on_task_id))
        counts = {"SATISFIED": 0, "BLOCKED": 0, "PENDING": 0}
        for task in tasks:
            if str(task.status) != TaskStatus.PENDING.value:
                continue
            verdict = dependency_verdict(
                dependency_ids=dependency_ids.get(str(task.id), []),
                status_by_id=status_by_id,
            )
            if verdict == DEPENDENCY_READY:
                task.status = TaskStatus.READY.value
                task.version = int(task.version) + 1
                task.updated_at = moment
                counts["SATISFIED"] += 1
                self._event(
                    session,
                    moment=moment,
                    event_type=WorkflowEventType.DEPENDENCY_SATISFIED.value,
                    workflow_id=str(workflow_id),
                    task_id=str(task.id),
                    from_status=TaskStatus.PENDING.value,
                    to_status=TaskStatus.READY.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason=reason or "All task dependencies are satisfied.",
                    detail={"task_key": task.task_key},
                )
            elif verdict == DEPENDENCY_BLOCKED:
                task.status = TaskStatus.BLOCKED.value
                task.version = int(task.version) + 1
                task.blocked_at = moment
                task.updated_at = moment
                task.block_reason = "A dependency was cancelled."
                counts["BLOCKED"] += 1
                self._event(
                    session,
                    moment=moment,
                    event_type=WorkflowEventType.TASK_BLOCKED.value,
                    workflow_id=str(workflow_id),
                    task_id=str(task.id),
                    from_status=TaskStatus.PENDING.value,
                    to_status=TaskStatus.BLOCKED.value,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason="A dependency was cancelled.",
                    detail={"task_key": task.task_key},
                )
            else:
                counts["PENDING"] += 1
        return counts

    def transition_workflow(
        self,
        workflow_id: str,
        *,
        target_status: str,
        expected_version: int,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        outcome_summary: str | None = None,
        block_reason: str | None = None,
        cancel_reason: str | None = None,
        dependency_observer: Callable[[dict[str, int]], None] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_utc(now or utcnow())
        target = str(target_status).upper()
        if target not in WORKFLOW_STATUS_VALUES:
            raise WorkflowStateError(f"unsupported workflow status: {target_status}")
        with self._session_factory() as session:
            row = session.get(GovernanceWorkflowORM, str(workflow_id))
            if row is None:
                raise WorkflowNotFoundError(str(workflow_id))
            current = str(row.status)
            if int(expected_version) != int(row.version):
                raise WorkflowVersionConflictError(str(workflow_id), int(expected_version), int(row.version))
            allowed = WORKFLOW_TRANSITIONS.get(current, frozenset())
            if target not in allowed:
                raise WorkflowStateError(f"workflow transition not allowed: {current} -> {target}")
            tasks = session.query(GovernanceWorkflowTaskORM).filter_by(workflow_id=str(workflow_id)).all()
            required_tasks = [task for task in tasks if bool(task.required)]
            if target == WorkflowStatus.UNDER_REVIEW.value:
                incomplete = [
                    task.task_key for task in required_tasks if str(task.status) != TaskStatus.COMPLETED.value
                ]
                if incomplete:
                    raise WorkflowStateError(
                        "all mandatory tasks must be completed before review: "
                        + ", ".join(sorted(incomplete))
                    )
            if target == WorkflowStatus.COMPLETED.value:
                incomplete = [
                    task.task_key for task in required_tasks if str(task.status) != TaskStatus.COMPLETED.value
                ]
                if incomplete:
                    raise WorkflowStateError(
                        "all mandatory tasks must be completed before completion: "
                        + ", ".join(sorted(incomplete))
                    )
                if len(str(outcome_summary or "").strip()) < 3:
                    raise WorkflowStateError("completion requires an outcome summary")
            updates: dict[str, Any] = {
                "status": target,
                "version": int(row.version) + 1,
                "updated_at": moment,
            }
            event_type = WorkflowEventType.WORKFLOW_STARTED.value
            if target == WorkflowStatus.READY.value:
                updates["ready_at"] = moment
                event_type = WorkflowEventType.WORKFLOW_READY.value
            elif target == WorkflowStatus.IN_PROGRESS.value:
                if current == WorkflowStatus.READY.value:
                    updates["started_at"] = moment
                    event_type = WorkflowEventType.WORKFLOW_STARTED.value
                elif current == WorkflowStatus.BLOCKED.value:
                    updates["block_reason"] = None
                    event_type = WorkflowEventType.WORKFLOW_UNBLOCKED.value
                else:
                    event_type = WorkflowEventType.WORKFLOW_STARTED.value
            elif target == WorkflowStatus.BLOCKED.value:
                updates["blocked_at"] = moment
                updates["block_reason"] = _safe_text(block_reason or reason, 2048)
                event_type = WorkflowEventType.WORKFLOW_BLOCKED.value
            elif target == WorkflowStatus.UNDER_REVIEW.value:
                updates["review_at"] = moment
                event_type = WorkflowEventType.WORKFLOW_UNDER_REVIEW.value
            elif target == WorkflowStatus.COMPLETED.value:
                updates["completed_at"] = moment
                updates["outcome_summary"] = _safe_text(outcome_summary, MAX_WORKFLOW_OUTCOME_LENGTH)
                event_type = WorkflowEventType.WORKFLOW_COMPLETED.value
            elif target == WorkflowStatus.CANCELLED.value:
                updates["cancelled_at"] = moment
                updates["cancel_reason"] = _safe_text(cancel_reason or reason, 2048)
                event_type = WorkflowEventType.WORKFLOW_CANCELLED.value
            updated = (
                session.query(GovernanceWorkflowORM)
                .filter_by(id=str(workflow_id), version=int(expected_version))
                .update(updates, synchronize_session=False)
            )
            if int(updated or 0) != 1:
                session.rollback()
                latest = session.get(GovernanceWorkflowORM, str(workflow_id))
                if latest is None:
                    raise WorkflowNotFoundError(str(workflow_id))
                raise WorkflowVersionConflictError(
                    str(workflow_id), int(expected_version), int(latest.version)
                )
            self._event(
                session,
                moment=moment,
                event_type=event_type,
                workflow_id=str(workflow_id),
                from_status=current,
                to_status=target,
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                detail={
                    "expected_version": int(expected_version),
                    "outcome_summary": _safe_text(outcome_summary or "", MAX_WORKFLOW_OUTCOME_LENGTH) or None,
                    "block_reason": _safe_text(block_reason or "", 2048) or None,
                    "cancel_reason": _safe_text(cancel_reason or "", 2048) or None,
                },
            )
            if target == WorkflowStatus.IN_PROGRESS.value:
                counts = self._evaluate_dependencies(
                    session,
                    workflow_id=str(workflow_id),
                    moment=moment,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason="Workflow started; dependency evaluation advanced ready tasks.",
                )
                if dependency_observer is not None:
                    dependency_observer(counts)
            if target == WorkflowStatus.CANCELLED.value:
                session.expire_all()
                open_tasks = (
                    session.query(GovernanceWorkflowTaskORM)
                    .filter(
                        GovernanceWorkflowTaskORM.workflow_id == str(workflow_id),
                        GovernanceWorkflowTaskORM.status.notin_(tuple(sorted(TASK_TERMINAL_STATUSES))),
                    )
                    .order_by(
                        GovernanceWorkflowTaskORM.order_index.asc(),
                        GovernanceWorkflowTaskORM.task_key.asc(),
                        GovernanceWorkflowTaskORM.id.asc(),
                    )
                    .all()
                )
                for task in open_tasks:
                    previous = str(task.status)
                    task.status = TaskStatus.CANCELLED.value
                    task.version = int(task.version) + 1
                    task.cancelled_at = moment
                    task.updated_at = moment
                    task.cancel_reason = _safe_text(cancel_reason or reason, 2048)
                    self._event(
                        session,
                        moment=moment,
                        event_type=WorkflowEventType.TASK_CANCELLED.value,
                        workflow_id=str(workflow_id),
                        task_id=str(task.id),
                        from_status=previous,
                        to_status=TaskStatus.CANCELLED.value,
                        actor_id=actor_id,
                        actor_role=actor_role,
                        reason="Workflow cancelled; the task was cancelled explicitly.",
                        detail={"task_key": task.task_key, "workflow_cancelled": True},
                    )
            session.commit()
            session.refresh(row)
            return _workflow_to_dict(row)

    def assign_workflow(
        self,
        workflow_id: str,
        *,
        owner_type: str,
        owner_id: str,
        expected_version: int,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_utc(now or utcnow())
        with self._session_factory() as session:
            row = session.get(GovernanceWorkflowORM, str(workflow_id))
            if row is None:
                raise WorkflowNotFoundError(str(workflow_id))
            if str(row.status) in WORKFLOW_TERMINAL_STATUSES:
                raise WorkflowStateError(f"workflow is terminal and cannot be reassigned: {row.status}")
            if int(expected_version) != int(row.version):
                raise WorkflowVersionConflictError(str(workflow_id), int(expected_version), int(row.version))
            previous_owner = row.owner_id
            reassigned = previous_owner is not None and previous_owner != owner_id
            updated = (
                session.query(GovernanceWorkflowORM)
                .filter_by(id=str(workflow_id), version=int(expected_version))
                .update(
                    {
                        "owner_type": str(owner_type).upper(),
                        "owner_id": _safe_text(owner_id, MAX_WORKFLOW_OWNER_LENGTH),
                        "version": int(row.version) + 1,
                        "updated_at": moment,
                    },
                    synchronize_session=False,
                )
            )
            if int(updated or 0) != 1:
                session.rollback()
                latest = session.get(GovernanceWorkflowORM, str(workflow_id))
                if latest is None:
                    raise WorkflowNotFoundError(str(workflow_id))
                raise WorkflowVersionConflictError(
                    str(workflow_id), int(expected_version), int(latest.version)
                )
            self._event(
                session,
                moment=moment,
                event_type=(
                    WorkflowEventType.WORKFLOW_REASSIGNED.value
                    if reassigned
                    else WorkflowEventType.WORKFLOW_ASSIGNED.value
                ),
                workflow_id=str(workflow_id),
                from_status=str(row.status),
                to_status=str(row.status),
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                detail={
                    "owner_type": str(owner_type).upper(),
                    "owner_id": _safe_text(owner_id, MAX_WORKFLOW_OWNER_LENGTH),
                    "previous_owner_id": previous_owner,
                    "reassigned": reassigned,
                },
            )
            session.commit()
            session.refresh(row)
            return _workflow_to_dict(row)

    # ------------------------------------------------------------------
    # Tasks
    # ------------------------------------------------------------------
    def transition_task(
        self,
        workflow_id: str,
        task_id: str,
        *,
        target_status: str,
        expected_version: int,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        outcome_summary: str | None = None,
        block_reason: str | None = None,
        cancel_reason: str | None = None,
        dependency_observer: Callable[[dict[str, int]], None] | None = None,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_utc(now or utcnow())
        target = str(target_status).upper()
        if target not in TASK_STATUS_VALUES:
            raise TaskStateError(f"unsupported task status: {target_status}")
        with self._session_factory() as session:
            workflow = session.get(GovernanceWorkflowORM, str(workflow_id))
            if workflow is None:
                raise WorkflowNotFoundError(str(workflow_id))
            task = (
                session.query(GovernanceWorkflowTaskORM)
                .filter_by(id=str(task_id), workflow_id=str(workflow_id))
                .one_or_none()
            )
            if task is None:
                raise TaskNotFoundError(str(task_id))
            workflow_status = str(workflow.status)
            if workflow_status in WORKFLOW_TERMINAL_STATUSES:
                raise TaskStateError(f"workflow is terminal: {workflow_status}")
            if workflow_status == WorkflowStatus.BLOCKED.value:
                raise TaskStateError("task writes are not allowed while the workflow is blocked")
            current = str(task.status)
            if int(expected_version) != int(task.version):
                raise TaskVersionConflictError(str(task_id), int(expected_version), int(task.version))
            allowed = TASK_TRANSITIONS.get(current, frozenset())
            if target not in allowed:
                raise TaskStateError(f"task transition not allowed: {current} -> {target}")
            dependency_ids = [
                str(row[0])
                for row in session.query(GovernanceWorkflowTaskDependencyORM.depends_on_task_id)
                .filter_by(task_id=str(task_id))
                .all()
            ]
            if target in {TaskStatus.READY.value, TaskStatus.IN_PROGRESS.value} and dependency_ids:
                statuses = {
                    str(row.id): str(row.status)
                    for row in session.query(GovernanceWorkflowTaskORM)
                    .filter(GovernanceWorkflowTaskORM.id.in_(dependency_ids))
                    .all()
                }
                verdict = dependency_verdict(dependency_ids=dependency_ids, status_by_id=statuses)
                if verdict != DEPENDENCY_READY:
                    raise TaskStateError("task dependencies are not satisfied; the task cannot start")
            if target == TaskStatus.IN_PROGRESS.value:
                if workflow_status != WorkflowStatus.IN_PROGRESS.value:
                    raise TaskStateError("tasks can start only while the workflow is in progress")
                if not task.owner_id:
                    raise TaskStateError("task must be assigned before it can start")
            updates: dict[str, Any] = {
                "status": target,
                "version": int(task.version) + 1,
                "updated_at": moment,
            }
            event_type = WorkflowEventType.TASK_STARTED.value
            if target == TaskStatus.READY.value:
                event_type = WorkflowEventType.DEPENDENCY_SATISFIED.value
            elif target == TaskStatus.IN_PROGRESS.value:
                if task.started_at is None:
                    updates["started_at"] = moment
                updates["block_reason"] = None
                event_type = WorkflowEventType.TASK_STARTED.value
            elif target == TaskStatus.BLOCKED.value:
                updates["blocked_at"] = moment
                updates["block_reason"] = _safe_text(block_reason or reason, 2048)
                event_type = WorkflowEventType.TASK_BLOCKED.value
            elif target == TaskStatus.COMPLETED.value:
                if len(str(outcome_summary or "").strip()) < 3:
                    raise TaskStateError("task completion requires an outcome summary")
                updates["completed_at"] = moment
                updates["outcome_summary"] = _safe_text(outcome_summary, MAX_WORKFLOW_OUTCOME_LENGTH)
                event_type = WorkflowEventType.TASK_COMPLETED.value
            elif target == TaskStatus.CANCELLED.value:
                updates["cancelled_at"] = moment
                updates["cancel_reason"] = _safe_text(cancel_reason or reason, 2048)
                event_type = WorkflowEventType.TASK_CANCELLED.value
            updated = (
                session.query(GovernanceWorkflowTaskORM)
                .filter_by(id=str(task_id), version=int(expected_version))
                .update(updates, synchronize_session=False)
            )
            if int(updated or 0) != 1:
                session.rollback()
                latest = (
                    session.query(GovernanceWorkflowTaskORM)
                    .filter_by(id=str(task_id), workflow_id=str(workflow_id))
                    .one_or_none()
                )
                if latest is None:
                    raise TaskNotFoundError(str(task_id))
                raise TaskVersionConflictError(str(task_id), int(expected_version), int(latest.version))
            self._event(
                session,
                moment=moment,
                event_type=event_type,
                workflow_id=str(workflow_id),
                task_id=str(task_id),
                from_status=current,
                to_status=target,
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                detail={
                    "task_key": task.task_key,
                    "expected_version": int(expected_version),
                    "outcome_summary": _safe_text(outcome_summary or "", MAX_WORKFLOW_OUTCOME_LENGTH) or None,
                    "block_reason": _safe_text(block_reason or "", 2048) or None,
                    "cancel_reason": _safe_text(cancel_reason or "", 2048) or None,
                },
            )
            if target in {TaskStatus.COMPLETED.value, TaskStatus.CANCELLED.value}:
                counts = self._evaluate_dependencies(
                    session,
                    workflow_id=str(workflow_id),
                    moment=moment,
                    actor_id=actor_id,
                    actor_role=actor_role,
                    reason="Task state changed; dependency evaluation advanced ready tasks.",
                )
                if dependency_observer is not None:
                    dependency_observer(counts)
            session.commit()
            session.refresh(task)
            return _task_to_dict(task)

    def assign_task(
        self,
        workflow_id: str,
        task_id: str,
        *,
        owner_type: str,
        owner_id: str,
        expected_version: int,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_utc(now or utcnow())
        with self._session_factory() as session:
            workflow = session.get(GovernanceWorkflowORM, str(workflow_id))
            if workflow is None:
                raise WorkflowNotFoundError(str(workflow_id))
            if str(workflow.status) in WORKFLOW_TERMINAL_STATUSES:
                raise TaskStateError("workflow is terminal")
            if str(workflow.status) == WorkflowStatus.BLOCKED.value:
                raise TaskStateError("task writes are not allowed while the workflow is blocked")
            task = (
                session.query(GovernanceWorkflowTaskORM)
                .filter_by(id=str(task_id), workflow_id=str(workflow_id))
                .one_or_none()
            )
            if task is None:
                raise TaskNotFoundError(str(task_id))
            if str(task.status) in TASK_TERMINAL_STATUSES:
                raise TaskStateError(f"task is terminal and cannot be reassigned: {task.status}")
            if int(expected_version) != int(task.version):
                raise TaskVersionConflictError(str(task_id), int(expected_version), int(task.version))
            previous_owner = task.owner_id
            reassigned = previous_owner is not None and previous_owner != owner_id
            updated = (
                session.query(GovernanceWorkflowTaskORM)
                .filter_by(id=str(task_id), version=int(expected_version))
                .update(
                    {
                        "owner_type": str(owner_type).upper(),
                        "owner_id": _safe_text(owner_id, MAX_WORKFLOW_OWNER_LENGTH),
                        "version": int(task.version) + 1,
                        "updated_at": moment,
                    },
                    synchronize_session=False,
                )
            )
            if int(updated or 0) != 1:
                session.rollback()
                latest = (
                    session.query(GovernanceWorkflowTaskORM)
                    .filter_by(id=str(task_id), workflow_id=str(workflow_id))
                    .one_or_none()
                )
                if latest is None:
                    raise TaskNotFoundError(str(task_id))
                raise TaskVersionConflictError(str(task_id), int(expected_version), int(latest.version))
            self._event(
                session,
                moment=moment,
                event_type=WorkflowEventType.TASK_ASSIGNED.value,
                workflow_id=str(workflow_id),
                task_id=str(task_id),
                from_status=str(task.status),
                to_status=str(task.status),
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                detail={
                    "owner_type": str(owner_type).upper(),
                    "owner_id": _safe_text(owner_id, MAX_WORKFLOW_OWNER_LENGTH),
                    "previous_owner_id": previous_owner,
                    "reassigned": reassigned,
                },
            )
            session.commit()
            session.refresh(task)
            return _task_to_dict(task)

    # ------------------------------------------------------------------
    # References
    # ------------------------------------------------------------------
    def count_references(self, workflow_id: str) -> int:
        with self._session_factory() as session:
            return int(
                session.query(GovernanceWorkflowReferenceORM).filter_by(workflow_id=str(workflow_id)).count()
            )

    def find_reference_by_key(self, workflow_id: str, reference_key: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceWorkflowReferenceORM)
                .filter_by(
                    workflow_id=str(workflow_id),
                    reference_key=_safe_text(reference_key, MAX_REFERENCE_KEY_LENGTH),
                )
                .one_or_none()
            )
            return _reference_to_dict(row) if row is not None else None

    def add_reference(
        self,
        *,
        workflow_id: str,
        task_id: str | None,
        domain: str,
        source_id: str,
        reference_key: str,
        source_label: str,
        source_case_id: str | None,
        availability: str,
        source_status: str,
        source_version: int | None,
        added_by: str,
        reason: str,
        actor_role: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        moment = _normalize_utc(now or utcnow())
        key = _safe_text(reference_key, MAX_REFERENCE_KEY_LENGTH)
        existing = self.find_reference_by_key(workflow_id, key)
        if existing is not None:
            return existing, False
        row = GovernanceWorkflowReferenceORM(
            id=_new_id(),
            workflow_id=str(workflow_id),
            task_id=str(task_id) if task_id else None,
            domain=_safe_text(domain, 32).upper(),
            source_id=_safe_text(source_id, MAX_REFERENCE_SOURCE_ID_LENGTH),
            reference_key=key,
            source_label=_safe_text(source_label, MAX_REFERENCE_LABEL_LENGTH),
            source_case_id=_safe_text(source_case_id, 36) or None,
            availability=_safe_text(availability, 16).upper(),
            source_status=_safe_text(source_status, 32).upper(),
            source_version=int(source_version) if source_version is not None else None,
            added_by=_safe_text(added_by, 256) or "SYSTEM",
            added_at=moment,
            last_checked_at=moment,
            reason=_safe_text(reason, MAX_WORKFLOW_REASON_LENGTH),
        )
        with self._session_factory() as session:
            session.add(row)
            try:
                session.flush()
                self._event(
                    session,
                    moment=moment,
                    event_type=WorkflowEventType.WORKFLOW_REFERENCE_ADDED.value,
                    workflow_id=str(workflow_id),
                    task_id=str(task_id) if task_id else None,
                    actor_id=added_by,
                    actor_role=actor_role,
                    reason=reason,
                    detail={
                        "reference_id": row.id,
                        "domain": row.domain,
                        "source_id": row.source_id,
                        "reference_key": row.reference_key,
                    },
                )
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = self._await_conflicting_write(lambda: self.find_reference_by_key(workflow_id, key))
                if existing is not None:
                    return existing, False
                raise
            session.refresh(row)
            return _reference_to_dict(row), True

    def list_references(self, workflow_id: str) -> list[dict[str, Any]]:
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowReferenceORM)
                .filter_by(workflow_id=str(workflow_id))
                .order_by(
                    GovernanceWorkflowReferenceORM.domain.asc(),
                    GovernanceWorkflowReferenceORM.source_id.asc(),
                    GovernanceWorkflowReferenceORM.id.asc(),
                )
                .all()
            )
            return [_reference_to_dict(row) for row in rows]

    # ------------------------------------------------------------------
    # Escalations
    # ------------------------------------------------------------------
    def get_escalation(self, escalation_id: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = session.get(GovernanceWorkflowEscalationORM, str(escalation_id))
            return _escalation_to_dict(row) if row is not None else None

    def find_escalation_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        with self._session_factory() as session:
            row = (
                session.query(GovernanceWorkflowEscalationORM)
                .filter_by(idempotency_key=_safe_text(key, 128))
                .one_or_none()
            )
            return _escalation_to_dict(row) if row is not None else None

    def count_escalations(self, workflow_id: str) -> int:
        with self._session_factory() as session:
            return int(
                session.query(GovernanceWorkflowEscalationORM).filter_by(workflow_id=str(workflow_id)).count()
            )

    def list_escalations(
        self,
        *,
        workflow_id: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[dict[str, Any]], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(GovernanceWorkflowEscalationORM)
            if workflow_id:
                query = query.filter_by(workflow_id=str(workflow_id))
            if status:
                query = query.filter_by(status=str(status).strip().upper())
            total = int(query.count())
            rows = (
                query.order_by(
                    GovernanceWorkflowEscalationORM.requested_at.desc(),
                    GovernanceWorkflowEscalationORM.id.asc(),
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
                .all()
            )
            return [_escalation_to_dict(row) for row in rows], total

    def create_escalation(
        self,
        *,
        workflow_id: str,
        task_id: str | None,
        escalation_type: str,
        severity: str,
        reason: str,
        requested_by: str,
        actor_role: str,
        idempotency_key: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], bool]:
        moment = _normalize_utc(now or utcnow())
        key = _safe_text(idempotency_key, 128)
        if not key:
            raise ValueError("idempotency_key is required")
        existing = self.find_escalation_by_idempotency_key(key)
        if existing is not None:
            return existing, False
        row = GovernanceWorkflowEscalationORM(
            id=_new_id(),
            workflow_id=str(workflow_id),
            task_id=str(task_id) if task_id else None,
            escalation_type=_safe_text(escalation_type, 32).upper(),
            severity=_safe_text(severity, 16).upper() or "MEDIUM",
            status="OPEN",
            reason=_safe_text(reason, MAX_WORKFLOW_REASON_LENGTH),
            requested_by=_safe_text(requested_by, 256) or "SYSTEM",
            requested_at=moment,
            version=1,
            idempotency_key=key,
        )
        with self._session_factory() as session:
            session.add(row)
            try:
                session.flush()
                self._event(
                    session,
                    moment=moment,
                    event_type=WorkflowEventType.ESCALATION_CREATED.value,
                    workflow_id=str(workflow_id),
                    task_id=str(task_id) if task_id else None,
                    from_status=None,
                    to_status="OPEN",
                    actor_id=requested_by,
                    actor_role=actor_role,
                    reason=reason,
                    detail={
                        "escalation_id": row.id,
                        "escalation_type": row.escalation_type,
                        "severity": row.severity,
                    },
                )
                session.commit()
            except IntegrityError:
                session.rollback()
                existing = self._await_conflicting_write(lambda: self.find_escalation_by_idempotency_key(key))
                if existing is not None:
                    return existing, False
                raise
            session.refresh(row)
            return _escalation_to_dict(row), True

    def acknowledge_escalation(
        self,
        escalation_id: str,
        *,
        expected_version: int,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_utc(now or utcnow())
        with self._session_factory() as session:
            row = session.get(GovernanceWorkflowEscalationORM, str(escalation_id))
            if row is None:
                raise EscalationNotFoundError(str(escalation_id))
            current = str(row.status)
            if int(expected_version) != int(row.version):
                raise EscalationVersionConflictError(
                    str(escalation_id), int(expected_version), int(row.version)
                )
            if "ACKNOWLEDGED" not in ESCALATION_TRANSITIONS.get(current, frozenset()):
                raise EscalationStateError(f"escalation transition not allowed: {current} -> ACKNOWLEDGED")
            updated = (
                session.query(GovernanceWorkflowEscalationORM)
                .filter_by(id=str(escalation_id), version=int(expected_version))
                .update(
                    {
                        "status": "ACKNOWLEDGED",
                        "acknowledged_by": _safe_text(actor_id, 256) or None,
                        "acknowledged_at": moment,
                        "version": int(row.version) + 1,
                    },
                    synchronize_session=False,
                )
            )
            if int(updated or 0) != 1:
                session.rollback()
                latest = session.get(GovernanceWorkflowEscalationORM, str(escalation_id))
                if latest is None:
                    raise EscalationNotFoundError(str(escalation_id))
                raise EscalationVersionConflictError(
                    str(escalation_id), int(expected_version), int(latest.version)
                )
            self._event(
                session,
                moment=moment,
                event_type=WorkflowEventType.ESCALATION_ACKNOWLEDGED.value,
                workflow_id=str(row.workflow_id),
                task_id=str(row.task_id) if row.task_id else None,
                from_status=current,
                to_status="ACKNOWLEDGED",
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                detail={"escalation_id": str(escalation_id)},
            )
            session.commit()
            session.refresh(row)
            return _escalation_to_dict(row)

    def resolve_escalation(
        self,
        escalation_id: str,
        *,
        expected_version: int,
        actor_id: str | None,
        actor_role: str,
        reason: str,
        resolution: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        moment = _normalize_utc(now or utcnow())
        with self._session_factory() as session:
            row = session.get(GovernanceWorkflowEscalationORM, str(escalation_id))
            if row is None:
                raise EscalationNotFoundError(str(escalation_id))
            current = str(row.status)
            if int(expected_version) != int(row.version):
                raise EscalationVersionConflictError(
                    str(escalation_id), int(expected_version), int(row.version)
                )
            if "RESOLVED" not in ESCALATION_TRANSITIONS.get(current, frozenset()):
                raise EscalationStateError(f"escalation transition not allowed: {current} -> RESOLVED")
            updated = (
                session.query(GovernanceWorkflowEscalationORM)
                .filter_by(id=str(escalation_id), version=int(expected_version))
                .update(
                    {
                        "status": "RESOLVED",
                        "resolved_by": _safe_text(actor_id, 256) or None,
                        "resolved_at": moment,
                        "resolution": _safe_text(resolution, MAX_WORKFLOW_REASON_LENGTH),
                        "version": int(row.version) + 1,
                    },
                    synchronize_session=False,
                )
            )
            if int(updated or 0) != 1:
                session.rollback()
                latest = session.get(GovernanceWorkflowEscalationORM, str(escalation_id))
                if latest is None:
                    raise EscalationNotFoundError(str(escalation_id))
                raise EscalationVersionConflictError(
                    str(escalation_id), int(expected_version), int(latest.version)
                )
            self._event(
                session,
                moment=moment,
                event_type=WorkflowEventType.ESCALATION_RESOLVED.value,
                workflow_id=str(row.workflow_id),
                task_id=str(row.task_id) if row.task_id else None,
                from_status=current,
                to_status="RESOLVED",
                actor_id=actor_id,
                actor_role=actor_role,
                reason=reason,
                detail={
                    "escalation_id": str(escalation_id),
                    "resolution": _safe_text(resolution, MAX_WORKFLOW_REASON_LENGTH),
                },
            )
            session.commit()
            session.refresh(row)
            return _escalation_to_dict(row)

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------
    def workflow_events(self, workflow_id: str, *, limit: int = MAX_EVENTS_PER_READ) -> list[dict[str, Any]]:
        bounded = max(1, min(MAX_EVENTS_PER_READ, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowEventORM)
                .filter_by(workflow_id=str(workflow_id))
                .order_by(
                    GovernanceWorkflowEventORM.sequence.asc(),
                    GovernanceWorkflowEventORM.created_at.asc(),
                    GovernanceWorkflowEventORM.id.asc(),
                )
                .limit(bounded)
                .all()
            )
            return [_event_to_dict(row) for row in rows]

    def task_events(self, task_id: str, *, limit: int = MAX_EVENTS_PER_READ) -> list[dict[str, Any]]:
        bounded = max(1, min(MAX_EVENTS_PER_READ, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowEventORM)
                .filter_by(task_id=str(task_id))
                .order_by(
                    GovernanceWorkflowEventORM.sequence.asc(),
                    GovernanceWorkflowEventORM.created_at.asc(),
                    GovernanceWorkflowEventORM.id.asc(),
                )
                .limit(bounded)
                .all()
            )
            return [_event_to_dict(row) for row in rows]

    def template_events(self, template_id: str, *, limit: int = MAX_EVENTS_PER_READ) -> list[dict[str, Any]]:
        bounded = max(1, min(MAX_EVENTS_PER_READ, int(limit)))
        with self._session_factory() as session:
            rows = (
                session.query(GovernanceWorkflowEventORM)
                .filter_by(template_id=str(template_id))
                .order_by(
                    GovernanceWorkflowEventORM.sequence.asc(),
                    GovernanceWorkflowEventORM.created_at.asc(),
                    GovernanceWorkflowEventORM.id.asc(),
                )
                .limit(bounded)
                .all()
            )
            return [_event_to_dict(row) for row in rows]


__all__ = ["GovernanceWorkflowRepository"]
