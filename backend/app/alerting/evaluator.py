"""Alert rule evaluation — durable, bounded, restart-recoverable (V15).

The evaluator polls two durable sources with (timestamp, id) watermarks
stored in ``alerting_cursor``:

- ``operational_events`` ordered by (first_seen, event_id) — genuine
  normalized domain events only (never frames/detections/tracks, which
  are not persisted and therefore never evaluated).
- ``incident_transitions`` ordered by (timestamp, id) — committed
  incident mutations only (rejected/no-op actions create no rows).

For each source item × each enabled rule, a match produces exactly one
of two durable outcomes in a single transaction: a notification (+
delivery rows) or a cooldown suppression. Duplicate deliveries and
restarts collapse on UNIQUE(rule_id, source_event_id). The watermark
advances only past fully processed items, so a crash rescans safely.

Cooldown starts when the notification commits (never on external
delivery success). Storm protection: bounded batches + a per-cycle
notification ceiling; unprocessed items stay behind the watermark.
"""

from __future__ import annotations

import logging
import threading
from datetime import UTC, datetime
from typing import Any

from backend.app.alerting.matcher import rule_matches
from backend.app.alerting.repository import AlertRepository
from backend.app.alerting.schemas import AlertRule, EvaluationOutcome
from backend.app.domain.common import utcnow
from backend.app.events.store import OperationalEventRepository
from backend.app.workers.base import ManagedWorker, WorkerState

logger = logging.getLogger("industrial-vision.alerting")

EVENTS_CONSUMER = "alert-evaluator-events"
TRANSITIONS_CONSUMER = "alert-evaluator-transitions"


def _naive_utc(moment: datetime | None) -> datetime | None:
    """Normalize for watermark comparison (storage is UTC; SQLite reads naive)."""
    if moment is None:
        return None
    try:
        if moment.tzinfo is not None:
            return moment.astimezone(UTC).replace(tzinfo=None)
        return moment
    except Exception:
        return None


def _after_watermark(
    timestamp: datetime | str | None,
    row_id: str,
    watermark_ts: datetime | None,
    watermark_id: str | None,
) -> bool:
    """Strictly-past-watermark test on (timestamp, id) — never UUID order."""
    ts = _naive_utc(timestamp) if not isinstance(timestamp, str) else None
    if isinstance(timestamp, str):
        try:
            from datetime import datetime as _dt

            ts = _naive_utc(_dt.fromisoformat(timestamp))
        except ValueError:
            return False
    if ts is None:
        return False
    if watermark_ts is None:
        return True
    mark = _naive_utc(watermark_ts)
    if mark is None:
        return True
    if ts > mark:
        return True
    if ts == mark and watermark_id is not None:
        return str(row_id) > str(watermark_id)
    return False


class AlertingEvaluator(ManagedWorker):
    """Poll-based rule evaluation with deterministic drain_once()."""

    def __init__(
        self,
        *,
        name: str = "alerting-evaluator",
        alert_repository: AlertRepository,
        operational_repository: OperationalEventRepository,
        settings: Any = None,
        event_bus: Any = None,
        poll_interval_seconds: float = 10.0,
        batch_size: int = 200,
        max_notifications_per_cycle: int = 500,
    ) -> None:
        super().__init__(name)
        self._alerts = alert_repository
        self._operational = operational_repository
        self._settings = settings
        self._event_bus = event_bus
        self._poll_interval = max(0.5, float(poll_interval_seconds))
        self._batch_size = max(1, int(batch_size))
        self._cycle_cap = max(1, int(max_notifications_per_cycle))
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {
            "cycles": 0,
            "evaluated": 0,
            "notified": 0,
            "suppressed": 0,
            "duplicates": 0,
            "errors": 0,
        }

    # ------------------------------------------------------------------
    # ManagedWorker contract
    # ------------------------------------------------------------------
    def start(self) -> bool:
        with self._state_lock:
            if self._worker_state is WorkerState.RUNNING:
                return True
            if self._worker_state is WorkerState.FAILED:
                return False
        try:
            self._transition(WorkerState.STARTING)
        except ValueError:
            return self.health().state is WorkerState.RUNNING
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, name=f"alert-{self.worker_name}", daemon=True)
        self._thread.start()
        self._transition(WorkerState.RUNNING)
        self._report_heartbeat()
        return True

    def stop(self, timeout: float = 5.0) -> bool:
        with self._state_lock:
            if self._worker_state in (WorkerState.STOPPED, WorkerState.CREATED):
                return True
        try:
            self._transition(WorkerState.STOPPING)
        except ValueError:
            return self.health().state is WorkerState.STOPPED
        self._stop_event.set()
        thread, self._thread = self._thread, None
        if thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=max(0.0, float(timeout)))
        try:
            self._transition(WorkerState.STOPPED)
        except ValueError:
            pass
        return True

    def _loop(self) -> None:
        try:
            while not self._stop_event.is_set():
                try:
                    self.drain_once()
                except Exception as exc:
                    self._record_failure(f"{type(exc).__name__}: {exc}")
                    logger.warning("alert evaluation cycle failed: %s", type(exc).__name__)
                self._stop_event.wait(self._poll_interval)
        except Exception as exc:
            self._record_failure(f"{type(exc).__name__}: {exc}")
            with self._state_lock:
                try:
                    self._transition(WorkerState.FAILED)
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------
    def drain_once(self, now: datetime | None = None) -> dict[str, int]:
        """Run one bounded evaluation cycle. Sync; tests drive this directly."""
        reference = now or utcnow()
        stats = {
            "events_scanned": 0,
            "transitions_scanned": 0,
            "evaluated": 0,
            "notified": 0,
            "suppressed": 0,
            "duplicates": 0,
            "capped": 0,
        }
        try:
            rules = self._enabled_rules()
        except Exception as exc:
            logger.warning("alert rule load failed: %s", type(exc).__name__)
            stats["errors"] = 1
            return stats
        if not rules:
            return stats
        try:
            # One trigger map per cycle: cooldown sees same-cycle notifies.
            recent_triggers: dict[str, datetime] = {}
            self._drain_events(rules, reference, stats, recent_triggers=recent_triggers)
            self._drain_transitions(rules, reference, stats, recent_triggers=recent_triggers)
        except Exception as exc:
            logger.warning("alert evaluation failed: %s", type(exc).__name__)
            stats["errors"] = 1
        with self._lock_stats():
            for key in ("evaluated", "notified", "suppressed", "duplicates"):
                self._stats[key] += stats[key]
            self._stats["cycles"] += 1
        self._report_heartbeat()
        return stats

    def _lock_stats(self) -> threading.RLock:
        return self._state_lock

    def evaluation_stats(self) -> dict[str, int]:
        with self._state_lock:
            return dict(self._stats)

    def _enabled_rules(self) -> list[AlertRule]:
        rules, _ = self._alerts.list_rules(page=1, page_size=1000)
        return [rule for rule in rules if rule.enabled]

    def _drain_events(
        self,
        rules: list[AlertRule],
        now: datetime,
        stats: dict[str, int],
        recent_triggers: dict[str, datetime] | None = None,
    ) -> None:
        timestamp, last_id = self._alerts.get_cursor(EVENTS_CONSUMER)
        # Watermark poll: operational history has no since-API, so read the
        # recent window and filter strictly past the watermark in Python.
        # Window is bounded (yesterday → now covers any realistic lag).
        from datetime import timedelta

        window_start = now - timedelta(days=1)
        rows, _ = self._operational.list_in_window(
            window_start,
            now,
            limit=5000,
            end_inclusive=True,
        )
        pending = [
            row
            for row in rows
            if _after_watermark(row.get("first_seen"), str(row.get("event_id", "")), timestamp, last_id)
        ]
        pending.sort(key=lambda row: (str(row.get("first_seen") or ""), str(row.get("event_id", ""))))
        for row in pending[: self._batch_size]:
            if stats["notified"] >= self._cycle_cap:
                stats["capped"] += 1
                break
            stats["events_scanned"] += 1
            candidate = {
                "domain": str(row.get("source_domain", "")),
                "event_type": str(row.get("event_type", "")),
                "severity": str(row.get("severity", "UNKNOWN")),
                "priority": "P4",
                "camera_id": row.get("camera_id"),
                "new_state": None,
            }
            self._evaluate_candidate(
                rules, str(row["event_id"]), candidate, now, stats, recent_triggers=recent_triggers
            )
            self._alerts.advance_cursor(EVENTS_CONSUMER, row.get("first_seen"), str(row.get("event_id", "")))

    def _drain_transitions(
        self,
        rules: list[AlertRule],
        now: datetime,
        stats: dict[str, int],
        recent_triggers: dict[str, datetime] | None = None,
    ) -> None:
        timestamp, last_id = self._alerts.get_cursor(TRANSITIONS_CONSUMER)
        rows = self._alerts.list_transitions_since(timestamp, last_id, limit=self._batch_size)
        for row in rows:
            if stats["notified"] >= self._cycle_cap:
                stats["capped"] += 1
                break
            stats["transitions_scanned"] += 1
            meta = row.metadata if isinstance(row.metadata, dict) else {}
            candidate = {
                "domain": "INCIDENT",
                "event_type": row.transition_type,
                "severity": str(meta.get("severity", "UNKNOWN")),
                "priority": str(meta.get("priority", "P4")),
                "camera_id": meta.get("camera_id"),
                "new_state": row.new_state,
            }
            source_id = f"transition:{row.id}"
            self._evaluate_candidate(
                rules,
                source_id,
                candidate,
                now,
                stats,
                incident_id=row.incident_id,
                transition=row,
                recent_triggers=recent_triggers,
            )
            self._alerts.advance_cursor(TRANSITIONS_CONSUMER, row.timestamp, str(row.id))

    def _evaluate_candidate(
        self,
        rules: list[AlertRule],
        source_id: str,
        candidate: dict[str, Any],
        now: datetime,
        stats: dict[str, int],
        incident_id: str | None = None,
        transition: Any = None,
        recent_triggers: dict[str, datetime] | None = None,
    ) -> None:
        recent = recent_triggers if recent_triggers is not None else {}
        for rule in rules:
            if not rule_matches(rule, candidate):
                continue
            stats["evaluated"] += 1
            if self._alerts.get_evaluation(str(rule.id), source_id) is not None:
                stats["duplicates"] += 1
                continue
            scope_key = self._cooldown_scope_key(rule, candidate)
            if self._in_cooldown(rule, scope_key, now, recent):
                recorded = self._alerts.record_evaluation(
                    rule_id=str(rule.id),
                    source_event_id=source_id,
                    outcome=EvaluationOutcome.SUPPRESSED_COOLDOWN.value,
                    suppression_reason="cooldown",
                    suppression_scope=rule.suppression_scope.value,
                    next_eligible_at=self._cooldown_ends_at(rule, scope_key, now, recent),
                    metadata={"scope_key": scope_key},
                )
                if recorded is None:
                    stats["duplicates"] += 1
                else:
                    stats["suppressed"] += 1
                    self._alerts.bump_rule_counters(str(rule.id), triggered=False, suppressed=True)
                continue
            self._notify(rule, source_id, candidate, now, stats, incident_id=incident_id, scope_key=scope_key)
            recent[scope_key] = now

    def _cooldown_scope_key(self, rule: AlertRule, candidate: dict[str, Any]) -> str:
        if rule.suppression_scope.value == "RULE_CAMERA":
            camera = candidate.get("camera_id") or ""
            return f"{rule.id}:{camera}"
        return str(rule.id)

    def _cooldown_ends_at(
        self,
        rule: AlertRule,
        scope_key: str,
        now: datetime,
        recent: dict[str, datetime] | None = None,
    ) -> datetime | None:
        if rule.cooldown_seconds <= 0:
            return None
        from datetime import timedelta

        last = (recent or {}).get(scope_key) or self._last_trigger_at(rule, scope_key)
        if last is None:
            return None
        return last + timedelta(seconds=rule.cooldown_seconds)

    def _last_trigger_at(self, rule: AlertRule, scope_key: str) -> datetime | None:
        if rule.suppression_scope.value == "RULE_CAMERA" and ":" in scope_key:
            _, _, camera_part = scope_key.partition(":")
            scoped_camera: str | None = camera_part or None
            return self._latest_notification_at(str(rule.id), scoped_camera)
        return rule.last_triggered_at

    def _latest_notification_at(self, rule_id: str, camera_id: str | None) -> datetime | None:
        items, _ = self._alerts.list_notifications(rule_id=rule_id, camera_id=camera_id, page=1, page_size=1)
        if not items:
            return None
        return items[0].created_at

    def _in_cooldown(
        self,
        rule: AlertRule,
        scope_key: str,
        now: datetime,
        recent: dict[str, datetime] | None = None,
    ) -> bool:
        if rule.cooldown_seconds <= 0:
            return False
        last = (recent or {}).get(scope_key) or self._last_trigger_at(rule, scope_key)
        if last is None:
            return False
        try:
            if last.tzinfo is None:
                # SQLite reads back naive datetimes; storage is UTC.
                last = last.replace(tzinfo=now.tzinfo)
            elapsed = (now - last).total_seconds()
        except (TypeError, OverflowError, ValueError):
            return False
        return elapsed < rule.cooldown_seconds

    def _notify(
        self,
        rule: AlertRule,
        source_id: str,
        candidate: dict[str, Any],
        now: datetime,
        stats: dict[str, int],
        incident_id: str | None = None,
        scope_key: str = "",
    ) -> None:

        title, message = _notification_text(rule, candidate)
        notification = self._alerts.create_notification(
            rule_id=str(rule.id),
            source_event_id=source_id,
            source_domain=str(candidate.get("domain", "")),
            event_type=str(candidate.get("event_type", "")),
            camera_id=candidate.get("camera_id"),
            incident_id=incident_id,
            title=title,
            message=message,
            severity=str(candidate.get("severity", "UNKNOWN")),
            priority=str(candidate.get("priority", "P4")),
            context={"scope_key": scope_key},
        )
        if notification is None:
            stats["duplicates"] += 1
            return
        destinations = self._destinations_for_rule(rule)
        for channel, destination in destinations:
            try:
                self._alerts.ensure_delivery(
                    notification_id=str(notification.id),
                    channel=channel,
                    destination=destination,
                )
            except Exception as exc:
                logger.warning("delivery row create failed: %s", type(exc).__name__)
        recorded = self._alerts.record_evaluation(
            rule_id=str(rule.id),
            source_event_id=source_id,
            outcome=EvaluationOutcome.NOTIFIED.value,
            metadata={"scope_key": scope_key, "notification_id": str(notification.id)},
        )
        if recorded is None:
            # Lost a race after creating the notification: the notification
            # row stands (UNIQUE collapsed the evaluation, not the notify).
            # Extremely rare; counted, never retried blindly.
            stats["duplicates"] += 1
            return
        self._alerts.bump_rule_counters(str(rule.id), triggered=True, suppressed=False, timestamp=now)
        stats["notified"] += 1
        self._push_created(notification, now)

    def _push_created(self, notification: Any, now: datetime) -> None:
        """Best-effort notification_created push (persisted first, REST rules).

        Failures are logged only; REST reconciliation recovers anything
        missed. Never raises.
        """
        bus = self._event_bus
        if bus is None:
            return
        try:
            from backend.app.events.envelope import EventEnvelope

            envelope = EventEnvelope(
                event_id=f"notification:{notification.id}",
                event_type="notification_created",
                domain=str(notification.source_domain or "INCIDENT"),
                camera_id=str(notification.camera_id or ""),
                timestamp=now,
                origin=f"alerting:{id(self):x}",
                payload={
                    "notification_id": str(notification.id),
                    "rule_id": str(notification.rule_id),
                    "title": notification.title,
                    "severity": notification.severity,
                    "event_type": notification.event_type,
                    "incident_id": notification.incident_id,
                },
            )
            bus.publish(envelope)
        except Exception as exc:
            logger.debug("notification push failed: %s", type(exc).__name__)

    def _destinations_for_rule(self, rule: AlertRule) -> list[tuple[str, str]]:
        destinations: list[tuple[str, str]] = []
        channels = [c.value if hasattr(c, "value") else str(c) for c in rule.channels]
        if "in_app" in channels:
            destinations.append(("in_app", ""))
        if "email" in channels:
            destinations.append(("email", ""))
        if "webhook" in channels:
            urls = self._webhook_urls()
            for url in urls[:5]:
                destinations.append(("webhook", url))
        return destinations

    def _webhook_urls(self) -> list[str]:
        settings = self._settings
        if settings is None:
            return []
        try:
            return list(settings.alerting_webhook_allowlist)
        except Exception:
            return []


def _notification_text(rule: AlertRule, candidate: dict[str, Any]) -> tuple[str, str]:
    event_type = str(candidate.get("event_type", "event"))
    camera = candidate.get("camera_id")
    where = f" on {camera}" if camera else ""
    severity = str(candidate.get("severity", "UNKNOWN"))
    title = f"[{severity}] {event_type}{where} (rule: {rule.name})"
    message = (
        f"Rule {rule.name!r} matched {event_type} from {candidate.get('domain', '?')}{where} "
        f"at severity {severity}."
    )
    return title[:256], message[:4096]


__all__ = ["AlertingEvaluator", "EVENTS_CONSUMER", "TRANSITIONS_CONSUMER"]
