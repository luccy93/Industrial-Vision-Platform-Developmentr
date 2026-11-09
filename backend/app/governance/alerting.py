"""V35 governance notifications through the existing V15 alerting pipeline.

Notifications are durable and sanitized. Delivery rows start as ``pending`` for
the existing delivery worker; this module never claims a channel delivered a
message. Deduplication is deterministic per rule + event type + target + case
version and cooldown is per rule + target + event type. Governance alerts are
review prompts, not evidence-deletion or hold-release instructions.
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
from backend.app.forensics.constants import CaseSeverity, priority_for_severity
from backend.app.models.forensic_orm import ForensicNotificationStateORM

logger = get_logger("industrial-vision.governance.alerting")

GOVERNANCE_NON_CLAIMS: tuple[str, ...] = (
    "Governance notifications are review prompts, not approvals.",
    "Notification delivery is queued locally and is not an external delivery claim.",
    "No notification authorizes physical evidence deletion or legal-hold release.",
)


def _as_utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class GovernanceNotifier:
    """Bounded, deduplicated governance review notifications."""

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

    def notify_event(
        self,
        *,
        event_type: str,
        case: Mapping[str, Any] | None,
        target_type: str,
        target_id: str,
        severity: str = "MEDIUM",
        detail: str = "",
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
        payload = dict(case or {})
        level = str(severity or CaseSeverity.MEDIUM.value).upper()
        if severity_rank(level) < severity_rank(self._min_severity):
            return stats
        try:
            rules, _ = self._repository.list_rules(enabled=True, page=1, page_size=100)
        except Exception as exc:
            logger.warning("governance alert rule lookup failed: %s", type(exc).__name__)
            stats["failed"] += 1
            return stats
        governance_rules = [
            rule for rule in rules if any(str(domain).upper() == "GOVERNANCE" for domain in rule.domains)
        ]
        if not governance_rules:
            stats["no_rule"] += 1
            return stats
        priority = str(payload.get("priority") or priority_for_severity(level))
        candidate = {
            "domain": "GOVERNANCE",
            "event_type": str(event_type).upper(),
            "severity": level,
            "priority": priority,
            "camera_id": None,
            "new_state": str(payload.get("status") or ""),
        }
        for rule in governance_rules:
            if not rule_matches(rule, candidate):
                continue
            stats["considered"] += 1
            try:
                self._notify_one(
                    rule,
                    payload,
                    candidate,
                    stats,
                    target_type=target_type,
                    target_id=target_id,
                    detail=detail,
                    reason_codes=reason_codes,
                )
            except Exception as exc:
                logger.warning("governance notification failed: %s", type(exc).__name__)
                stats["failed"] += 1
        return stats

    def _notify_one(
        self,
        rule: AlertRule,
        case: Mapping[str, Any],
        candidate: Mapping[str, Any],
        stats: dict[str, int],
        *,
        target_type: str,
        target_id: str,
        detail: str,
        reason_codes: Sequence[str],
    ) -> None:
        now = utcnow()
        event_type = str(candidate["event_type"])
        case_id = str(case.get("case_id") or "")
        case_number = str(case.get("case_number") or "")
        version = int(case.get("version") or 1)
        safe_target = redact_text(str(target_id or ""))[:128]
        dedup_key = (f"governance:{rule.id}:{event_type}:{target_type}:{safe_target}:{version}")[:256]
        cooldown_key = f"governance:{target_type}:{safe_target}:{event_type}"[:128]
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
        title = f"[{candidate['severity']}] governance {event_type.replace('_', ' ').lower()}"
        message = redact_text(
            f"Case {case_number or 'n/a'} governance event {event_type}. "
            f"{detail or 'Review the governance workspace for details.'}"
        )[:4096]
        context = {
            "case_id": case_id,
            "case_number": case_number,
            "target_type": str(target_type)[:32],
            "target_id": safe_target,
            "severity": candidate["severity"],
            "priority": candidate["priority"],
            "reason_codes": [str(code)[:64] for code in list(reason_codes)[:20]],
            "case_version": version,
            "delivery_status": "pending",
            "delivery_claimed": False,
            "automatic_deletion": False,
            "automatic_hold_release": False,
            "automatic_disposition_approval": False,
            "external_anchor_claimed": False,
            "non_claims": list(GOVERNANCE_NON_CLAIMS),
        }
        notification = self._repository.create_notification(
            rule_id=str(rule.id),
            source_event_id=dedup_key,
            source_domain="GOVERNANCE",
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
                    meta={"domain": "GOVERNANCE"},
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
                logger.warning("governance delivery row failed: %s", type(exc).__name__)
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


__all__ = ["GOVERNANCE_NON_CLAIMS", "GovernanceNotifier"]
