"""V34 forensic notifications through the existing V15 alerting pipeline.

Notifications are durable and sanitized. Delivery rows start as ``pending`` for
the existing delivery worker; this module never claims a channel delivered a
message. Deduplication is per rule + case event + case version, and cooldown is
per rule + case + event type. Only confirmed or explicitly escalated case
events are notified; unavailable/not-run/simulated findings never produce a
confirmed security notification.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from backend.app.alerting.matcher import rule_matches, severity_rank
from backend.app.alerting.repository import AlertRepository
from backend.app.alerting.schemas import AlertRule
from backend.app.core.logging import get_logger
from backend.app.core.redaction import redact_structure, redact_text
from backend.app.domain.common import utcnow
from backend.app.forensics.constants import (
    EXTERNAL_ANCHORING_NOTE,
    CaseSeverity,
    priority_for_severity,
)
from backend.app.models.forensic_orm import ForensicNotificationStateORM

logger = get_logger("industrial-vision.forensics.alerting")


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class ForensicNotifier:
    """Bounded, deduplicated forensic case notifications."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], Session],
        alert_repository: AlertRepository,
        enabled: bool = False,
        min_severity: str = "HIGH",
        cooldown_seconds: int = 3600,
        webhook_urls: Sequence[str] = (),
    ) -> None:
        self._session_factory = session_factory
        self._repository = alert_repository
        self._enabled = bool(enabled)
        self._min_severity = str(min_severity or "HIGH").upper()
        self._cooldown_seconds = max(0, int(cooldown_seconds))
        self._webhook_urls = [str(url) for url in webhook_urls if str(url).strip()][:5]

    def notify_case_event(
        self,
        case: Mapping[str, Any],
        event_type: str,
        *,
        detail: str = "",
        finding_id: str | None = None,
        audit_run_id: str | None = None,
        reason_codes: Sequence[str] = (),
    ) -> dict[str, int]:
        stats = {
            "considered": 0,
            "queued": 0,
            "duplicate": 0,
            "suppressed": 0,
            "no_rule": 0,
            "failed": 0,
        }
        if not self._enabled:
            return stats
        severity = str(case.get("severity") or CaseSeverity.MEDIUM.value).upper()
        if severity_rank(severity) < severity_rank(self._min_severity):
            return stats
        try:
            rules, _ = self._repository.list_rules(enabled=True, page=1, page_size=100)
        except Exception as exc:
            logger.warning("forensic alert rule lookup failed: %s", type(exc).__name__)
            stats["failed"] += 1
            return stats
        forensic_rules = [
            rule for rule in rules if any(str(domain).upper() == "FORENSIC" for domain in rule.domains)
        ]
        if not forensic_rules:
            stats["no_rule"] += 1
            return stats
        priority = str(case.get("priority") or priority_for_severity(severity))
        candidate = {
            "domain": "FORENSIC",
            "event_type": str(event_type).upper(),
            "severity": severity,
            "priority": priority,
            "camera_id": None,
            "new_state": str(case.get("status") or ""),
        }
        for rule in forensic_rules:
            if not rule_matches(rule, candidate):
                continue
            stats["considered"] += 1
            try:
                self._notify_one(
                    rule,
                    case,
                    candidate,
                    stats,
                    detail=detail,
                    finding_id=finding_id,
                    audit_run_id=audit_run_id,
                    reason_codes=reason_codes,
                )
            except Exception as exc:
                logger.warning("forensic notification failed: %s", type(exc).__name__)
                stats["failed"] += 1
        return stats

    def _notify_one(
        self,
        rule: AlertRule,
        case: Mapping[str, Any],
        candidate: Mapping[str, Any],
        stats: dict[str, int],
        *,
        detail: str,
        finding_id: str | None,
        audit_run_id: str | None,
        reason_codes: Sequence[str],
    ) -> None:
        now = utcnow()
        event_type = str(candidate["event_type"])
        case_id = str(case.get("case_id") or "")
        case_number = str(case.get("case_number") or "")
        version = int(case.get("version") or 1)
        dedup_key = f"forensic:{rule.id}:{event_type}:{case_id}:{version}"[:256]
        cooldown_key = f"{case_id}:{event_type}"[:128]
        with self._session_factory() as session:
            if (
                session.query(ForensicNotificationStateORM).filter_by(dedup_key=dedup_key).one_or_none()
                is not None
            ):
                stats["duplicate"] += 1
                return
            if self._cooldown_seconds > 0:
                threshold = now - timedelta(seconds=self._cooldown_seconds)
                recent = (
                    session.query(ForensicNotificationStateORM)
                    .filter(
                        ForensicNotificationStateORM.rule_id == str(rule.id),
                        ForensicNotificationStateORM.cooldown_key == cooldown_key,
                    )
                    .order_by(ForensicNotificationStateORM.last_sent_at.desc())
                    .first()
                )
                last_sent = _as_utc(recent.last_sent_at) if recent is not None else None
                if last_sent is not None and last_sent >= threshold:
                    stats["suppressed"] += 1
                    return
        title = f"[{case.get('severity')}] forensic {event_type.replace('_', ' ').lower()}"
        message = redact_text(
            f"Case {case_number} ({case.get('case_type')}) is {case.get('status')}. "
            f"{detail or 'Review the forensic workspace for details.'}"
        )[:4096]
        context = {
            "case_id": case_id,
            "case_number": case_number,
            "case_type": case.get("case_type"),
            "status": case.get("status"),
            "severity": case.get("severity"),
            "priority": case.get("priority"),
            "originating_incident_id": case.get("originating_incident_id"),
            "originating_audit_run_id": case.get("originating_audit_run_id"),
            "incident_ids": list(case.get("incident_ids") or []),
            "finding_id": finding_id,
            "audit_run_id": audit_run_id,
            "reason_codes": list(reason_codes)[:20],
            "case_version": version,
            "delivery_status": "pending",
            "external_anchor_claimed": False,
            "external_anchor_note": EXTERNAL_ANCHORING_NOTE,
        }
        notification = self._repository.create_notification(
            rule_id=str(rule.id),
            source_event_id=dedup_key,
            source_domain="FORENSIC",
            event_type=event_type,
            title=title[:256],
            message=message,
            severity=str(candidate["severity"]),
            priority=str(candidate["priority"]),
            incident_id=str(case.get("originating_incident_id") or "") or None,
            context=dict(redact_structure(context)),
        )
        if notification is None:
            stats["duplicate"] += 1
            return
        with self._session_factory() as session:
            session.add(
                ForensicNotificationStateORM(
                    id=str(uuid.uuid4()),
                    rule_id=str(rule.id),
                    dedup_key=dedup_key,
                    cooldown_key=cooldown_key,
                    last_sent_at=now,
                    notification_id=str(notification.id),
                    meta={},
                )
            )
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                stats["duplicate"] += 1
                return
        for channel, destination in self._destinations(rule):
            try:
                self._repository.ensure_delivery(
                    notification_id=str(notification.id),
                    channel=channel,
                    destination=destination,
                )
            except Exception as exc:
                logger.warning("forensic delivery row failed: %s", type(exc).__name__)
        try:
            self._repository.bump_rule_counters(str(rule.id), triggered=True, suppressed=False)
        except Exception:
            pass
        stats["queued"] += 1

    def _destinations(self, rule: AlertRule) -> list[tuple[str, str]]:
        channels = [channel.value if hasattr(channel, "value") else str(channel) for channel in rule.channels]
        destinations: list[tuple[str, str]] = []
        if "in_app" in channels:
            destinations.append(("in_app", ""))
        if "email" in channels:
            destinations.append(("email", ""))
        if "webhook" in channels:
            destinations.extend(("webhook", url) for url in self._webhook_urls)
        return destinations


__all__ = ["ForensicNotifier"]
