"""V33 integrity alerting: dedup, cooldown, sanitization, honest delivery."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from backend.app.alerting.repository import AlertRepository
from backend.app.core.config import AppEnv, Settings
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.integrity.alerting import IntegrityNotifier, correlation_key
from backend.app.integrity.constants import (
    AuditStatus,
    AuditTrigger,
    IntegrityScope,
    Severity,
)
from backend.app.integrity.models import AuditRun, Finding
from backend.app.integrity.store import MonitoringStore


def _settings(tmp_path: Path) -> Settings:
    tmp_path.mkdir(parents=True, exist_ok=True)
    return Settings(
        app_name="industrial-vision-platform",
        app_env=AppEnv.testing,
        log_level="WARNING",
        database_url=f"sqlite:///{tmp_path}/test.db",
        integrity_monitoring_db_url=f"sqlite:///{tmp_path}/monitor.db",
        _env_file=None,
    )


def _run(run_id: str) -> AuditRun:
    return AuditRun(
        audit_run_id=run_id,
        trigger=AuditTrigger.MANUAL,
        requested_scopes=[IntegrityScope.TRANSPARENCY_LOG],
        completed_scopes=[IntegrityScope.TRANSPARENCY_LOG],
        status=AuditStatus.FAIL,
        started_at="2026-01-01T00:00:00.000Z",
        created_at="2026-01-01T00:00:00.000Z",
        completed_at="2026-01-01T00:00:01.000Z",
    )


def _finding(run_id: str, *, severity: Severity = Severity.HIGH) -> Finding:
    return Finding.create(
        audit_run_id=run_id,
        scope=IntegrityScope.TRANSPARENCY_LOG,
        reason_code="TREE_HEAD_INVALID",
        artifact_id="head-2",
        explanation="signature mismatch; token=super-secret-value password=hunter2",
        severity=severity,
    )


def _notifier(tmp_path: Path, *, enabled: bool = True) -> tuple[IntegrityNotifier, Any, MonitoringStore]:
    settings = _settings(tmp_path)
    init_db(settings.database_url)
    factory = get_session_factory(settings.database_url)
    store = MonitoringStore(settings.integrity_store_url)
    store.initialize()
    repository = AlertRepository(factory)
    repository.create_rule(
        name="Integrity failures",
        domains=["INTEGRITY"],
        event_types=["INTEGRITY_FINDING"],
        channels=["in_app", "webhook"],
        cooldown_seconds=3600,
    )
    notifier = IntegrityNotifier(
        session_factory=factory,
        store=store,
        enabled=enabled,
        min_severity="HIGH",
        cooldown_seconds=3600,
        webhook_urls=["https://ops.example.invalid/hook"],
    )
    return notifier, repository, store


def test_finding_is_queued_once_with_sanitized_pending_delivery(tmp_path: Path) -> None:
    notifier, repository, _store = _notifier(tmp_path)
    finding = _finding("run-1")

    stats = notifier.notify(_run("run-1"), [finding])

    assert stats == {
        "considered": 1,
        "queued": 1,
        "duplicate": 0,
        "suppressed": 0,
        "no_rule": 0,
        "failed": 0,
    }
    notifications, total = repository.list_notifications(domain="INTEGRITY")
    assert total == 1
    notification = notifications[0]
    assert notification.severity == "HIGH"
    assert notification.priority == "P2"
    assert "super-secret-value" not in notification.message
    assert "hunter2" not in notification.message
    assert "[REDACTED]" in notification.message
    assert notification.context["delivery_status"] == "pending"
    assert notification.context["audit_run_id"] == "run-1"
    assert notification.context["reason_code"] == "TREE_HEAD_INVALID"
    assert notification.context["correlation_key"] == correlation_key(finding)

    deliveries, delivery_total = repository.list_deliveries(notification_id=str(notification.id))
    assert delivery_total == 2
    assert {item.channel for item in deliveries} == {"in_app", "webhook"}
    assert {item.status for item in deliveries} == {"pending"}


def test_duplicate_and_correlated_cooldown_are_suppressed(tmp_path: Path) -> None:
    notifier, repository, _store = _notifier(tmp_path)
    first = _finding("run-1")
    assert notifier.notify(_run("run-1"), [first])["queued"] == 1

    duplicate = notifier.notify(_run("run-1"), [first])
    assert duplicate["queued"] == 0
    assert duplicate["duplicate"] == 1

    # A different run yields a new finding id but the same scope/reason/artifact
    # correlation key, so the cooldown suppresses a second notification.
    correlated = _finding("run-2")
    assert correlated.finding_id != first.finding_id
    assert correlation_key(correlated) == correlation_key(first)
    cooled = notifier.notify(_run("run-2"), [correlated])
    assert cooled["queued"] == 0
    assert cooled["suppressed"] == 1

    _notifications, total = repository.list_notifications(domain="INTEGRITY")
    assert total == 1


def test_below_threshold_findings_and_disabled_alerting_are_not_queued(tmp_path: Path) -> None:
    notifier, repository, _store = _notifier(tmp_path)
    low = _finding("run-low", severity=Severity.LOW)
    stats = notifier.notify(_run("run-low"), [low])
    assert stats["queued"] == 0
    assert stats["considered"] == 0
    assert repository.list_notifications(domain="INTEGRITY")[1] == 0

    disabled, disabled_repo, _store = _notifier(tmp_path / "disabled", enabled=False)
    assert disabled.notify(_run("run-1"), [_finding("run-1")])["queued"] == 0
    assert disabled_repo.list_notifications(domain="INTEGRITY")[1] == 0
