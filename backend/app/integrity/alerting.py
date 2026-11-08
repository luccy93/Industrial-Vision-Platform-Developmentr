"""V33 integrity-finding alerting integration.

Notifications are durable and sanitized. Delivery rows are created as
``pending`` for the existing delivery worker; this module never claims that a
channel actually delivered anything. Deduplication is per finding identity and
cooldown is per correlated scope/reason/artifact key.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from backend.app.alerting.matcher import rule_matches, severity_rank
from backend.app.alerting.repository import AlertRepository
from backend.app.alerting.schemas import AlertRule
from backend.app.core.logging import get_logger
from backend.app.core.redaction import redact_text
from backend.app.integrity.constants import Severity
from backend.app.integrity.models import AuditRun, Finding
from backend.app.integrity.store import MonitoringStore

logger = get_logger("industrial-vision.integrity.alerting")

_PRIORITY_BY_SEVERITY = {
    Severity.CRITICAL.value: "P1",
    Severity.HIGH.value: "P2",
    Severity.MEDIUM.value: "P3",
    Severity.LOW.value: "P4",
    Severity.INFO.value: "P4",
}


def correlation_key(finding: Finding) -> str:
    payload = "|".join(
        [
            finding.scope.value,
            finding.reason_code,
            finding.artifact_id or "",
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


class IntegrityNotifier:
    """Create sanitized alert notifications for integrity findings."""

    def __init__(
        self,
        *,
        session_factory: Any,
        store: MonitoringStore,
        enabled: bool,
        min_severity: str = "HIGH",
        cooldown_seconds: int = 3600,
        webhook_urls: Sequence[str] = (),
    ) -> None:
        self._repository = AlertRepository(session_factory)
        self._store = store
        self._enabled = bool(enabled)
        self._min_severity = str(min_severity or "HIGH").upper()
        self._cooldown_seconds = max(0, int(cooldown_seconds))
        self._webhook_urls = [str(url) for url in webhook_urls if str(url).strip()][:5]

    def notify(self, run: AuditRun, findings: Sequence[Finding]) -> dict[str, int]:
        stats = {
            "considered": 0,
            "queued": 0,
            "duplicate": 0,
            "suppressed": 0,
            "no_rule": 0,
            "failed": 0,
        }
        if not self._enabled or not findings:
            return stats
        try:
            rules, _ = self._repository.list_rules(enabled=True, page=1, page_size=100)
        except Exception as exc:
            logger.warning("integrity alert rule lookup failed: %s", type(exc).__name__)
            stats["failed"] += 1
            return stats
        integrity_rules = [
            rule for rule in rules if any(str(domain).upper() == "INTEGRITY" for domain in rule.domains)
        ]
        if not integrity_rules:
            stats["no_rule"] += 1
            return stats
        minimum = severity_rank(self._min_severity)
        for finding in findings:
            if severity_rank(finding.severity.value) < minimum:
                continue
            candidate = {
                "domain": "INTEGRITY",
                "event_type": "INTEGRITY_FINDING",
                "severity": finding.severity.value,
                "priority": _PRIORITY_BY_SEVERITY.get(finding.severity.value, "P4"),
                "camera_id": None,
                "new_state": None,
            }
            for rule in integrity_rules:
                if not rule_matches(rule, candidate):
                    continue
                stats["considered"] += 1
                try:
                    self._notify_one(run, finding, rule, candidate, stats)
                except Exception as exc:
                    logger.warning("integrity notification failed: %s", type(exc).__name__)
                    stats["failed"] += 1
        return stats

    def _notify_one(
        self,
        run: AuditRun,
        finding: Finding,
        rule: AlertRule,
        candidate: dict[str, Any],
        stats: dict[str, int],
    ) -> None:
        dedup_key = finding.finding_id
        key = correlation_key(finding)
        allowed, _existing, reason = self._store.alert_is_allowed(
            rule_id=str(rule.id),
            dedup_key=dedup_key,
            cooldown_key=key,
            cooldown_seconds=self._cooldown_seconds,
        )
        if not allowed:
            if reason == "COOLDOWN":
                stats["suppressed"] += 1
            else:
                stats["duplicate"] += 1
            return
        title = f"[{finding.severity.value}] integrity {finding.reason_code}"
        message = (
            f"{finding.scope.value} finding {finding.finding_id} during audit "
            f"{run.audit_run_id}: {redact_text(finding.explanation)[:1000]}"
        )
        context = {
            "audit_run_id": run.audit_run_id,
            "finding_id": finding.finding_id,
            "scope": finding.scope.value,
            "reason_code": finding.reason_code,
            "artifact_id": finding.artifact_id,
            "correlation_key": key,
            "verification_source": finding.verification_source,
            "recommended_action": finding.recommended_action,
            "delivery_status": "pending",
        }
        notification = self._repository.create_notification(
            rule_id=str(rule.id),
            source_event_id=f"{run.audit_run_id}:{finding.finding_id}",
            source_domain="INTEGRITY",
            event_type="INTEGRITY_FINDING",
            title=title[:256],
            message=message[:4096],
            severity=finding.severity.value,
            priority=str(candidate["priority"]),
            context=context,
        )
        if notification is None:
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
                logger.warning("integrity delivery row failed: %s", type(exc).__name__)
        self._store.record_alert_sent(
            rule_id=str(rule.id),
            dedup_key=dedup_key,
            reason_code=finding.reason_code,
            scope=finding.scope.value,
            cooldown_key=key,
            notification_id=str(notification.id),
        )
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


__all__ = ["IntegrityNotifier", "correlation_key"]
