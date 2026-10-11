"""Alerting persistence — rules, notifications, deliveries, transitions (V15).

All multi-row operations commit atomically in one session. Reads never
mutate. Unique constraints make notification creation, evaluation
outcomes, and delivery rows idempotent under concurrency and redelivery.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from datetime import datetime
from typing import Any

from sqlalchemy import and_, or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.alerting.schemas import (
    AlertChannel,
    AlertRule,
    DeliveryAttempt,
    DeliveryStatus,
    EvaluationOutcome,
    EvaluationRecord,
    Notification,
    SuppressionScope,
    TransitionRecord,
    validate_rule_filters,
)
from backend.app.domain.common import utcnow
from backend.app.models.alerting_orm import (
    AlertEvaluationORM,
    AlertingCursorORM,
    AlertRuleORM,
    DeliveryAttemptORM,
    IncidentTransitionORM,
    NotificationORM,
)


class AlertRuleNotFoundError(ValueError):
    """No alert rule with the given id exists."""

    def __init__(self, rule_id: str) -> None:
        super().__init__(f"alert rule not found: {rule_id}")
        self.rule_id = rule_id


class NotificationNotFoundError(ValueError):
    """No notification with the given id exists."""

    def __init__(self, notification_id: str) -> None:
        super().__init__(f"notification not found: {notification_id}")
        self.notification_id = notification_id


class DeliveryNotFoundError(ValueError):
    """No delivery attempt with the given id exists."""

    def __init__(self, delivery_id: str) -> None:
        super().__init__(f"delivery not found: {delivery_id}")
        self.delivery_id = delivery_id


def _rule_to_domain(row: AlertRuleORM) -> AlertRule:
    return AlertRule(
        id=uuid.UUID(row.id),
        name=row.name,
        description=row.description or "",
        enabled=bool(row.enabled),
        domains=list(row.domains or []),
        event_types=list(row.event_types or []),
        min_severity=row.min_severity,
        min_priority=row.min_priority,
        camera_ids=list(row.camera_ids or []),
        incident_statuses=list(row.incident_statuses or []),
        channels=[AlertChannel(c) for c in (row.channels or [])],
        cooldown_seconds=int(row.cooldown_seconds or 0),
        suppression_scope=SuppressionScope(row.suppression_scope or "RULE"),
        trigger_count=int(row.trigger_count or 0),
        suppressed_count=int(row.suppressed_count or 0),
        last_triggered_at=row.last_triggered_at,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _notification_to_domain(row: NotificationORM) -> Notification:
    return Notification(
        id=uuid.UUID(row.id),
        rule_id=uuid.UUID(row.rule_id),
        source_event_id=row.source_event_id,
        source_domain=row.source_domain or "",
        event_type=row.event_type or "",
        camera_id=row.camera_id,
        incident_id=row.incident_id,
        title=row.title or "",
        message=row.message or "",
        severity=row.severity or "UNKNOWN",
        priority=row.priority or "P4",
        context=dict(row.context or {}),
        muted_until=row.muted_until,
        created_at=row.created_at,
    )


def _delivery_to_domain(row: DeliveryAttemptORM) -> DeliveryAttempt:
    return DeliveryAttempt(
        id=uuid.UUID(row.id),
        notification_id=uuid.UUID(row.notification_id),
        channel=AlertChannel(row.channel),
        destination=row.destination or "",
        status=DeliveryStatus(row.status),
        attempts=int(row.attempts or 0),
        next_retry_at=row.next_retry_at,
        last_attempt_at=row.last_attempt_at,
        delivered_at=row.delivered_at,
        last_error=row.last_error,
        created_at=row.created_at,
    )


def _transition_to_domain(row: IncidentTransitionORM) -> TransitionRecord:
    return TransitionRecord(
        id=uuid.UUID(row.id),
        incident_id=row.incident_id,
        transition_type=row.transition_type,
        previous_state=row.previous_state,
        new_state=row.new_state,
        actor_id=row.actor_id,
        timestamp=row.timestamp,
        metadata=dict(row.meta or {}),
    )


def _evaluation_to_domain(row: AlertEvaluationORM) -> EvaluationRecord:
    return EvaluationRecord(
        id=uuid.UUID(row.id),
        rule_id=uuid.UUID(row.rule_id),
        source_event_id=row.source_event_id,
        outcome=EvaluationOutcome(row.outcome),
        suppression_reason=row.suppression_reason,
        suppression_scope=SuppressionScope(row.suppression_scope) if row.suppression_scope else None,
        next_eligible_at=row.next_eligible_at,
        evaluated_at=row.evaluated_at,
        metadata=dict(row.meta or {}),
    )


class AlertRepository:
    """Durable alerting state behind one session factory."""

    def __init__(self, session_factory: Callable[[], Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------
    def create_rule(
        self,
        *,
        name: str,
        description: str = "",
        enabled: bool = True,
        domains: Sequence[str] | None = None,
        event_types: Sequence[str] | None = None,
        min_severity: str | None = None,
        min_priority: str | None = None,
        camera_ids: Sequence[str] | None = None,
        incident_statuses: Sequence[str] | None = None,
        channels: Sequence[str | AlertChannel],
        cooldown_seconds: int = 0,
        suppression_scope: str | SuppressionScope = SuppressionScope.RULE,
    ) -> AlertRule:
        normalized_domains = [str(d).strip().upper() for d in (domains or [])]
        normalized_types = [str(t).strip().upper() for t in (event_types or [])]
        normalized_statuses = [str(s).strip().upper() for s in (incident_statuses or [])]
        validate_rule_filters(
            domains=normalized_domains,
            event_types=normalized_types,
            incident_statuses=normalized_statuses,
        )
        channel_values = [
            c.value if isinstance(c, AlertChannel) else str(c).strip().lower() for c in channels
        ]
        for value in channel_values:
            if value not in ("in_app", "email", "webhook"):
                raise ValueError(f"unknown alert channel: {value!r}")
        if not channel_values:
            raise ValueError("at least one channel is required")
        scope = (
            suppression_scope.value
            if isinstance(suppression_scope, SuppressionScope)
            else str(suppression_scope).strip().upper()
        )
        if scope not in ("RULE", "RULE_CAMERA"):
            raise ValueError(f"unknown suppression scope: {suppression_scope!r}")
        now = utcnow()
        with self._session_factory() as session:
            row = AlertRuleORM(
                id=str(uuid.uuid4()),
                name=str(name).strip(),
                description=str(description or ""),
                enabled=bool(enabled),
                domains=normalized_domains,
                event_types=normalized_types,
                min_severity=str(min_severity).strip().upper() if min_severity else None,
                min_priority=str(min_priority).strip().upper() if min_priority else None,
                camera_ids=[str(c).strip() for c in (camera_ids or []) if str(c).strip()],
                incident_statuses=normalized_statuses,
                channels=channel_values,
                cooldown_seconds=max(0, min(int(cooldown_seconds), 86400)),
                suppression_scope=scope,
                trigger_count=0,
                suppressed_count=0,
                created_at=now,
                updated_at=now,
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _rule_to_domain(row)

    def get_rule(self, rule_id: str) -> AlertRule | None:
        with self._session_factory() as session:
            row = session.query(AlertRuleORM).filter_by(id=str(rule_id)).one_or_none()
            return _rule_to_domain(row) if row is not None else None

    def list_rules(
        self, *, enabled: bool | None = None, page: int = 1, page_size: int = 20
    ) -> tuple[list[AlertRule], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(AlertRuleORM).order_by(AlertRuleORM.created_at.asc())
            if enabled is not None:
                query = query.filter(AlertRuleORM.enabled.is_(bool(enabled)))
            total = query.count()
            rows = query.offset((page - 1) * page_size).limit(page_size).all()
            return [_rule_to_domain(row) for row in rows], int(total)

    def update_rule(self, rule_id: str, **fields: Any) -> AlertRule | None:
        """Partial update; unknown filter values rejected, never stored."""
        allowed = {
            "name",
            "description",
            "enabled",
            "domains",
            "event_types",
            "min_severity",
            "min_priority",
            "camera_ids",
            "incident_statuses",
            "channels",
            "cooldown_seconds",
            "suppression_scope",
        }
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"unknown rule fields: {sorted(unknown)}")
        with self._session_factory() as session:
            row = session.query(AlertRuleORM).filter_by(id=str(rule_id)).one_or_none()
            if row is None:
                return None
            domains = list(row.domains or [])
            event_types = list(row.event_types or [])
            statuses = list(row.incident_statuses or [])
            if "domains" in fields and fields["domains"] is not None:
                domains = [str(d).strip().upper() for d in fields["domains"]]
            if "event_types" in fields and fields["event_types"] is not None:
                event_types = [str(t).strip().upper() for t in fields["event_types"]]
            if "incident_statuses" in fields and fields["incident_statuses"] is not None:
                statuses = [str(s).strip().upper() for s in fields["incident_statuses"]]
            validate_rule_filters(domains=domains, event_types=event_types, incident_statuses=statuses)
            row.domains = domains
            row.event_types = event_types
            row.incident_statuses = statuses
            if "name" in fields and fields["name"] is not None:
                row.name = str(fields["name"]).strip()
            if "description" in fields and fields["description"] is not None:
                row.description = str(fields["description"] or "")
            if "enabled" in fields and fields["enabled"] is not None:
                row.enabled = bool(fields["enabled"])
            if "min_severity" in fields:
                row.min_severity = (
                    str(fields["min_severity"]).strip().upper() if fields["min_severity"] else None
                )
            if "min_priority" in fields:
                row.min_priority = (
                    str(fields["min_priority"]).strip().upper() if fields["min_priority"] else None
                )
            if "camera_ids" in fields and fields["camera_ids"] is not None:
                row.camera_ids = [str(c).strip() for c in fields["camera_ids"] if str(c).strip()]
            if "channels" in fields and fields["channels"] is not None:
                channel_values = [
                    c.value if isinstance(c, AlertChannel) else str(c).strip().lower()
                    for c in fields["channels"]
                ]
                for value in channel_values:
                    if value not in ("in_app", "email", "webhook"):
                        raise ValueError(f"unknown alert channel: {value!r}")
                if not channel_values:
                    raise ValueError("at least one channel is required")
                row.channels = channel_values
            if "cooldown_seconds" in fields and fields["cooldown_seconds"] is not None:
                row.cooldown_seconds = max(0, min(int(fields["cooldown_seconds"]), 86400))
            if "suppression_scope" in fields and fields["suppression_scope"] is not None:
                scope = fields["suppression_scope"]
                scope = scope.value if isinstance(scope, SuppressionScope) else str(scope).strip().upper()
                if scope not in ("RULE", "RULE_CAMERA"):
                    raise ValueError(f"unknown suppression scope: {fields['suppression_scope']!r}")
                row.suppression_scope = scope
            row.updated_at = utcnow()
            session.commit()
            session.refresh(row)
            return _rule_to_domain(row)

    def bump_rule_counters(
        self, rule_id: str, *, triggered: bool, suppressed: bool, timestamp: datetime | None = None
    ) -> None:
        with self._session_factory() as session:
            row = session.query(AlertRuleORM).filter_by(id=str(rule_id)).one_or_none()
            if row is None:
                return
            if triggered:
                row.trigger_count = int(row.trigger_count or 0) + 1
                row.last_triggered_at = timestamp or utcnow()
            if suppressed:
                row.suppressed_count = int(row.suppressed_count or 0) + 1
            row.updated_at = utcnow()
            session.commit()

    # ------------------------------------------------------------------
    # Notifications (idempotent on rule + source identity)
    # ------------------------------------------------------------------
    def create_notification(
        self,
        *,
        rule_id: str,
        source_event_id: str,
        source_domain: str = "",
        event_type: str = "",
        camera_id: str | None = None,
        incident_id: str | None = None,
        title: str = "",
        message: str = "",
        severity: str = "UNKNOWN",
        priority: str = "P4",
        context: dict[str, Any] | None = None,
    ) -> Notification | None:
        """Insert unless the (rule, source) pair already notified. None on dup."""
        now = utcnow()
        with self._session_factory() as session:
            row = NotificationORM(
                id=str(uuid.uuid4()),
                rule_id=str(rule_id),
                source_event_id=str(source_event_id),
                source_domain=str(source_domain or ""),
                event_type=str(event_type or ""),
                camera_id=camera_id,
                incident_id=incident_id,
                title=str(title or "")[:256],
                message=str(message or "")[:4096],
                severity=str(severity or "UNKNOWN"),
                priority=str(priority or "P4"),
                context=dict(context or {}),
                created_at=now,
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return None
            session.refresh(row)
            return _notification_to_domain(row)

    def get_notification(self, notification_id: str) -> Notification | None:
        with self._session_factory() as session:
            row = session.query(NotificationORM).filter_by(id=str(notification_id)).one_or_none()
            return _notification_to_domain(row) if row is not None else None

    def mute_notification(self, notification_id: str, muted_until: datetime) -> Notification | None:
        """Pause channel delivery until ``muted_until`` (V16 operator mute).

        Detection, history, and analytics are unaffected; the delivery
        worker skips muted notifications and retries after expiry.
        """
        with self._session_factory() as session:
            row = session.query(NotificationORM).filter_by(id=str(notification_id)).one_or_none()
            if row is None:
                return None
            row.muted_until = muted_until
            session.commit()
            session.refresh(row)
            return _notification_to_domain(row)

    def list_notifications(
        self,
        *,
        rule_id: str | None = None,
        severity: str | None = None,
        domain: str | None = None,
        camera_id: str | None = None,
        incident_id: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[Notification], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(NotificationORM).order_by(NotificationORM.created_at.desc())
            if rule_id:
                query = query.filter(NotificationORM.rule_id == str(rule_id))
            if severity:
                query = query.filter(NotificationORM.severity == str(severity).upper())
            if domain:
                query = query.filter(NotificationORM.source_domain == str(domain).upper())
            if camera_id:
                query = query.filter(NotificationORM.camera_id == camera_id)
            if incident_id:
                query = query.filter(NotificationORM.incident_id == str(incident_id))
            if created_from is not None:
                query = query.filter(NotificationORM.created_at >= created_from)
            if created_to is not None:
                query = query.filter(NotificationORM.created_at < created_to)
            total = query.count()
            rows = query.offset((page - 1) * page_size).limit(page_size).all()
            return [_notification_to_domain(row) for row in rows], int(total)

    # ------------------------------------------------------------------
    # Deliveries (one row per notification × channel × destination)
    # ------------------------------------------------------------------
    def ensure_delivery(
        self, *, notification_id: str, channel: str, destination: str = ""
    ) -> DeliveryAttempt:
        """Get-or-create the delivery row (idempotent under races)."""
        now = utcnow()
        with self._session_factory() as session:
            row = (
                session.query(DeliveryAttemptORM)
                .filter_by(
                    notification_id=str(notification_id),
                    channel=str(channel),
                    destination=str(destination or ""),
                )
                .one_or_none()
            )
            if row is None:
                row = DeliveryAttemptORM(
                    id=str(uuid.uuid4()),
                    notification_id=str(notification_id),
                    channel=str(channel),
                    destination=str(destination or ""),
                    status="pending",
                    attempts=0,
                    created_at=now,
                )
                session.add(row)
                try:
                    session.commit()
                except IntegrityError:
                    session.rollback()
                    row = (
                        session.query(DeliveryAttemptORM)
                        .filter_by(
                            notification_id=str(notification_id),
                            channel=str(channel),
                            destination=str(destination or ""),
                        )
                        .one()
                    )
            session.refresh(row)
            return _delivery_to_domain(row)

    def get_delivery(self, delivery_id: str) -> DeliveryAttempt | None:
        with self._session_factory() as session:
            row = session.query(DeliveryAttemptORM).filter_by(id=str(delivery_id)).one_or_none()
            return _delivery_to_domain(row) if row is not None else None

    def list_deliveries(
        self,
        *,
        notification_id: str | None = None,
        channel: str | None = None,
        status: str | None = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[DeliveryAttempt], int]:
        page = max(1, int(page))
        page_size = min(100, max(1, int(page_size)))
        with self._session_factory() as session:
            query = session.query(DeliveryAttemptORM).order_by(DeliveryAttemptORM.created_at.desc())
            if notification_id:
                query = query.filter(DeliveryAttemptORM.notification_id == str(notification_id))
            if channel:
                query = query.filter(DeliveryAttemptORM.channel == str(channel))
            if status:
                query = query.filter(DeliveryAttemptORM.status == str(status))
            total = query.count()
            rows = query.offset((page - 1) * page_size).limit(page_size).all()
            return [_delivery_to_domain(row) for row in rows], int(total)

    def claim_due_deliveries(self, limit: int = 50, now: datetime | None = None) -> list[DeliveryAttempt]:
        reference = now or utcnow()
        with self._session_factory() as session:
            rows = (
                session.query(DeliveryAttemptORM)
                .filter(DeliveryAttemptORM.status == "pending")
                .filter(
                    (DeliveryAttemptORM.next_retry_at.is_(None))
                    | (DeliveryAttemptORM.next_retry_at <= reference)
                )
                .order_by(DeliveryAttemptORM.created_at.asc())
                .limit(max(1, min(int(limit), 1000)))
                .all()
            )
            return [_delivery_to_domain(row) for row in rows]

    def mark_delivery(
        self,
        delivery_id: str,
        *,
        status: str,
        error: str | None = None,
        next_retry_at: datetime | None = None,
        delivered: bool = False,
    ) -> DeliveryAttempt | None:
        now = utcnow()
        with self._session_factory() as session:
            row = session.query(DeliveryAttemptORM).filter_by(id=str(delivery_id)).one_or_none()
            if row is None:
                return None
            row.status = str(status)
            row.last_attempt_at = now
            if error is not None:
                row.last_error = str(error)[:512]
            if next_retry_at is not None:
                row.next_retry_at = next_retry_at
            if delivered:
                row.delivered_at = now
            else:
                row.attempts = int(row.attempts or 0) + 1
            session.commit()
            session.refresh(row)
            return _delivery_to_domain(row)

    def delivery_counts(self) -> dict[str, int]:
        from sqlalchemy import func as _func

        with self._session_factory() as session:
            rows = (
                session.query(DeliveryAttemptORM.status, _func.count(DeliveryAttemptORM.id))
                .group_by(DeliveryAttemptORM.status)
                .all()
            )
            return {str(status): int(count) for status, count in rows}

    # ------------------------------------------------------------------
    # Transitions (durable incident-mutation records)
    # ------------------------------------------------------------------
    def record_transition(
        self,
        *,
        incident_id: str,
        transition_type: str,
        previous_state: str | None = None,
        new_state: str | None = None,
        actor_id: str | None = None,
        timestamp: datetime | None = None,
        metadata: dict[str, Any] | None = None,
        transition_id: str | None = None,
    ) -> TransitionRecord:
        now = timestamp or utcnow()
        with self._session_factory() as session:
            row = IncidentTransitionORM(
                id=transition_id or str(uuid.uuid4()),
                incident_id=str(incident_id),
                transition_type=str(transition_type),
                previous_state=previous_state,
                new_state=new_state,
                actor_id=actor_id,
                timestamp=now,
                meta=dict(metadata or {}),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return _transition_to_domain(row)

    def list_transitions_since(
        self,
        timestamp: datetime | None,
        last_id: str | None,
        limit: int = 200,
    ) -> list[TransitionRecord]:
        """Transitions strictly after the (timestamp, id) watermark, ordered."""
        with self._session_factory() as session:
            query = session.query(IncidentTransitionORM).order_by(
                IncidentTransitionORM.timestamp.asc(), IncidentTransitionORM.id.asc()
            )
            if timestamp is not None:
                if last_id:
                    query = query.filter(
                        or_(
                            IncidentTransitionORM.timestamp > timestamp,
                            and_(
                                IncidentTransitionORM.timestamp == timestamp,
                                IncidentTransitionORM.id > str(last_id),
                            ),
                        )
                    )
                else:
                    query = query.filter(IncidentTransitionORM.timestamp > timestamp)
            rows = query.limit(max(1, min(int(limit), 5000))).all()
            return [_transition_to_domain(row) for row in rows]

    # ------------------------------------------------------------------
    # Evaluations (notified + suppressed outcomes, idempotent)
    # ------------------------------------------------------------------
    def record_evaluation(
        self,
        *,
        rule_id: str,
        source_event_id: str,
        outcome: str,
        suppression_reason: str | None = None,
        suppression_scope: str | None = None,
        next_eligible_at: datetime | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvaluationRecord | None:
        """Insert unless this rule/source pair was already evaluated. None on dup."""
        now = utcnow()
        with self._session_factory() as session:
            row = AlertEvaluationORM(
                id=str(uuid.uuid4()),
                rule_id=str(rule_id),
                source_event_id=str(source_event_id),
                outcome=str(outcome),
                suppression_reason=suppression_reason,
                suppression_scope=suppression_scope,
                next_eligible_at=next_eligible_at,
                evaluated_at=now,
                meta=dict(metadata or {}),
            )
            session.add(row)
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return None
            session.refresh(row)
            return _evaluation_to_domain(row)

    def get_evaluation(self, rule_id: str, source_event_id: str) -> EvaluationRecord | None:
        with self._session_factory() as session:
            row = (
                session.query(AlertEvaluationORM)
                .filter_by(rule_id=str(rule_id), source_event_id=str(source_event_id))
                .one_or_none()
            )
            return _evaluation_to_domain(row) if row is not None else None

    def recent_suppressions(self, limit: int = 50) -> list[EvaluationRecord]:
        with self._session_factory() as session:
            rows = (
                session.query(AlertEvaluationORM)
                .filter(AlertEvaluationORM.outcome == "SUPPRESSED_COOLDOWN")
                .order_by(AlertEvaluationORM.evaluated_at.desc())
                .limit(max(1, min(int(limit), 500)))
                .all()
            )
            return [_evaluation_to_domain(row) for row in rows]

    # ------------------------------------------------------------------
    # Cursors, counters, retention
    # ------------------------------------------------------------------
    def get_cursor(self, consumer: str) -> tuple[datetime | None, str | None]:
        with self._session_factory() as session:
            row = session.query(AlertingCursorORM).filter_by(consumer=str(consumer)).one_or_none()
            if row is None:
                return None, None
            return row.last_timestamp, row.last_id

    def advance_cursor(self, consumer: str, timestamp: datetime | None, last_id: str | None) -> None:
        now = utcnow()
        with self._session_factory() as session:
            row = session.query(AlertingCursorORM).filter_by(consumer=str(consumer)).one_or_none()
            if row is None:
                row = AlertingCursorORM(
                    consumer=str(consumer),
                    last_timestamp=timestamp,
                    last_id=last_id,
                    updated_at=now,
                )
                session.add(row)
            else:
                row.last_timestamp = timestamp
                row.last_id = last_id
                row.updated_at = now
            session.commit()

    def notification_counts(self) -> dict[str, int]:
        from sqlalchemy import func as _func

        with self._session_factory() as session:
            total = int(session.query(_func.count(NotificationORM.id)).scalar() or 0)
            return {"total": total}

    def delete_old_evaluations(self, cutoff: datetime, limit: int = 500) -> int:
        with self._session_factory() as session:
            rows = (
                session.query(AlertEvaluationORM)
                .filter(AlertEvaluationORM.evaluated_at < cutoff)
                .order_by(AlertEvaluationORM.evaluated_at.asc())
                .limit(max(1, min(int(limit), 5000)))
                .all()
            )
            count = len(rows)
            for row in rows:
                session.delete(row)
            session.commit()
            return count

    def delete_old_terminal_deliveries(self, cutoff: datetime, limit: int = 500) -> int:
        """Bounded cleanup of sent/failed deliveries (pending never touched)."""
        with self._session_factory() as session:
            rows = (
                session.query(DeliveryAttemptORM)
                .filter(DeliveryAttemptORM.status.in_(["sent", "failed"]))
                .filter(DeliveryAttemptORM.created_at < cutoff)
                .order_by(DeliveryAttemptORM.created_at.asc())
                .limit(max(1, min(int(limit), 5000)))
                .all()
            )
            count = len(rows)
            for row in rows:
                session.delete(row)
            session.commit()
            return count
