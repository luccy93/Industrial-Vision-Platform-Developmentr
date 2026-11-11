"""V36 reminder and compliance-snapshot execution tests.

Every fixture is synthetic and local. Reminders flow through the real V15
notification repository with a deterministic in-app rule; no external channel
is contacted and no delivery is claimed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from backend.app.alerting.repository import AlertRepository
from backend.app.core.config import AppEnv, Settings
from backend.app.governance.alerting import GovernanceNotifier
from backend.app.governance.automation.constants import (
    DISPOSITION_REVIEW_DUE_EVENT,
    EXPORT_APPROVAL_REVIEW_DUE_EVENT,
    LEGAL_HOLD_PENDING_APPROVAL_EVENT,
    LEGAL_HOLD_REVIEW_DUE_EVENT,
    RETENTION_REVIEW_DUE_EVENT,
    JobStatus,
)
from backend.app.governance.automation.executor import GovernanceJobExecutor
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.governance.automation.service import GovernanceAutomationService
from backend.app.infrastructure.db import get_session_factory, init_db

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class FakeGovernanceService:
    """Deterministic governance read model for reminder handlers."""

    def __init__(
        self,
        *,
        retention: list[dict[str, Any]] | None = None,
        holds: list[dict[str, Any]] | None = None,
        dispositions: list[dict[str, Any]] | None = None,
        exports: list[dict[str, Any]] | None = None,
        report: dict[str, Any] | None = None,
    ) -> None:
        self.retention = retention or []
        self.holds = holds or []
        self.dispositions = dispositions or []
        self.exports = exports or []
        self.report = report or {}

    def retention_queue(self, *, page: int = 1, page_size: int = 20, as_of: Any = None) -> dict[str, Any]:
        return {"items": list(self.retention), "total": len(self.retention)}

    def list_legal_holds(
        self, *, statuses: list[str] | None = None, page: int = 1, page_size: int = 20
    ) -> dict[str, Any]:
        wanted = set(statuses or [])
        return {
            "items": [item for item in self.holds if not wanted or item["status"] in wanted],
            "total": len(self.holds),
        }

    def list_dispositions(
        self, *, statuses: list[str] | None = None, page: int = 1, page_size: int = 20
    ) -> dict[str, Any]:
        wanted = set(statuses or [])
        return {
            "items": [item for item in self.dispositions if not wanted or item["status"] in wanted],
            "total": len(self.dispositions),
        }

    def list_export_approvals(
        self, *, statuses: list[str] | None = None, page: int = 1, page_size: int = 20
    ) -> dict[str, Any]:
        wanted = set(statuses or [])
        return {
            "items": [item for item in self.exports if not wanted or item["status"] in wanted],
            "total": len(self.exports),
        }

    def compliance_report(self, **kwargs: Any) -> dict[str, Any]:
        return dict(self.report)

    def status(self) -> dict[str, Any]:
        return {
            "assurance": "LOCAL_SELF_DIGEST_ONLY",
            "policy_count": 1,
            "audit_integrity": {"outcome": "OK", "checked": 1, "verified": 1},
        }


class FakeForensicRepository:
    def list_cases(self, *, page: int = 1, page_size: int = 20) -> tuple[list[dict[str, Any]], int]:
        return [], 0

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        return {
            "case_id": case_id,
            "case_number": "CASE-SYNTHETIC",
            "status": "OPEN",
            "priority": "P3",
            "version": 1,
        }


def _retention_item(
    evaluation_id: str,
    *,
    state: str = "REVIEW_DUE",
    next_review: datetime | None = None,
    deadline: datetime | None = None,
) -> dict[str, Any]:
    return {
        "evaluation_id": evaluation_id,
        "case_id": f"case-{evaluation_id}",
        "governance_state": state,
        "next_review_at": _iso(next_review) if next_review else None,
        "retention_deadline": _iso(deadline) if deadline else None,
    }


def _hold_item(
    hold_id: str,
    status: str,
    *,
    requested_at: datetime,
    approved_at: datetime | None = None,
) -> dict[str, Any]:
    return {
        "hold_id": hold_id,
        "hold_number": f"HOLD-{hold_id}",
        "case_id": f"case-{hold_id}",
        "status": status,
        "requested_at": _iso(requested_at),
        "approved_at": _iso(approved_at) if approved_at else None,
    }


def _disposition_item(disposition_id: str, status: str, *, requested_at: datetime) -> dict[str, Any]:
    return {
        "disposition_id": disposition_id,
        "request_number": f"DIS-{disposition_id}",
        "case_id": f"case-{disposition_id}",
        "status": status,
        "requested_at": _iso(requested_at),
    }


def _export_item(approval_id: str, *, requested_at: datetime, expires_at: datetime | None) -> dict[str, Any]:
    return {
        "approval_id": approval_id,
        "request_number": f"EXP-{approval_id}",
        "case_id": f"case-{approval_id}",
        "status": "PENDING_APPROVAL",
        "requested_at": _iso(requested_at),
        "expires_at": _iso(expires_at) if expires_at else None,
    }


def _setup(
    tmp_path: Any,
    *,
    notifier_enabled: bool = True,
    with_rule: bool = True,
    cooldown_seconds: int = 0,
    governance: FakeGovernanceService | None = None,
) -> tuple[GovernanceJobExecutor, GovernanceAutomationRepository, AlertRepository, dict[str, Any]]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        app_name="v36-reminders",
        app_env=AppEnv.testing,
        database_url=f"sqlite:///{tmp_path}/reminders.db",
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    session_factory = get_session_factory(settings.database_url)
    repository = GovernanceAutomationRepository(session_factory)
    repository.ensure_schedules()
    alert_repository = AlertRepository(session_factory)
    if with_rule:
        alert_repository.create_rule(
            name="Synthetic governance reminders",
            domains=["GOVERNANCE"],
            channels=["in_app"],
            cooldown_seconds=0,
        )
    notifier = GovernanceNotifier(
        session_factory=session_factory,
        alert_repository=alert_repository,
        enabled=notifier_enabled,
        min_severity="HIGH",
        cooldown_seconds=cooldown_seconds,
    )
    clock = {"now": NOW}

    def _clock() -> datetime:
        return clock["now"]

    executor = GovernanceJobExecutor(
        repository=repository,
        governance_service=governance or FakeGovernanceService(),
        forensic_repository=FakeForensicRepository(),
        notifier=notifier,
        clock=_clock,
        lease_seconds=60,
        timeout_seconds=60,
    )
    return executor, repository, alert_repository, clock


def _run(
    executor: GovernanceJobExecutor,
    repository: GovernanceAutomationRepository,
    job_type: str,
    config: dict[str, Any],
    *,
    dedup_key: str,
) -> dict[str, Any]:
    job, created = repository.create_job(
        job_type=job_type,
        trigger="MANUAL",
        dedup_key=dedup_key,
        requested_by="tester",
        requested_role="ADMIN",
        config_snapshot=config,
        now=executor.clock(),
    )
    assert created is True
    claimed = repository.claim_job(
        job["job_id"], lease_owner="tester", lease_seconds=60, now=executor.clock()
    )
    assert claimed is not None
    return executor.execute(claimed, lease_owner="tester")


def test_all_reminder_categories_queue_through_v15(tmp_path: Any) -> None:
    governance = FakeGovernanceService(
        retention=[
            _retention_item("eval-due", next_review=NOW - timedelta(days=1)),
            _retention_item(
                "eval-future",
                state="ACTIVE",
                next_review=NOW + timedelta(days=90),
            ),
        ],
        holds=[
            _hold_item(
                "hold-pending",
                "PENDING_APPROVAL",
                requested_at=NOW - timedelta(days=2),
            ),
            _hold_item(
                "hold-active-old",
                "ACTIVE",
                requested_at=NOW - timedelta(days=90),
                approved_at=NOW - timedelta(days=60),
            ),
            _hold_item(
                "hold-active-young",
                "ACTIVE",
                requested_at=NOW - timedelta(days=2),
                approved_at=NOW - timedelta(days=1),
            ),
        ],
        dispositions=[
            _disposition_item("disp-old", "REVIEW_REQUIRED", requested_at=NOW - timedelta(days=2)),
            _disposition_item("disp-new", "REVIEW_REQUIRED", requested_at=NOW - timedelta(hours=1)),
        ],
        exports=[
            _export_item(
                "exp-soon",
                requested_at=NOW - timedelta(days=2),
                expires_at=NOW + timedelta(days=7),
            ),
            _export_item(
                "exp-later",
                requested_at=NOW - timedelta(days=2),
                expires_at=NOW + timedelta(days=60),
            ),
        ],
    )
    executor, repository, alert_repository, _ = _setup(tmp_path, governance=governance)

    retention = _run(
        executor,
        repository,
        "RETENTION_REVIEW_REMINDERS",
        {"upcoming_days": 30, "max_items": 100},
        dedup_key="reminders:retention:1",
    )
    assert retention["status"] == JobStatus.SUCCEEDED.value
    assert retention["result"]["candidates"] == 1
    assert retention["result"]["outcomes"]["QUEUED"] == 1

    holds = _run(
        executor,
        repository,
        "LEGAL_HOLD_REMINDERS",
        {
            "max_items": 100,
            "active_hold_age_days": 30,
            "include_pending_approval": True,
            "include_active_holds": True,
        },
        dedup_key="reminders:holds:1",
    )
    assert holds["result"]["candidates"] == 2
    assert holds["result"]["outcomes"]["QUEUED"] == 2

    dispositions = _run(
        executor,
        repository,
        "DISPOSITION_REVIEW_REMINDERS",
        {"max_items": 100, "min_age_days": 1},
        dedup_key="reminders:dispositions:1",
    )
    assert dispositions["result"]["candidates"] == 1
    assert dispositions["result"]["outcomes"]["QUEUED"] == 1

    exports = _run(
        executor,
        repository,
        "EXPORT_APPROVAL_REMINDERS",
        {"max_items": 100, "upcoming_days": 14},
        dedup_key="reminders:exports:1",
    )
    assert exports["result"]["candidates"] == 1
    assert exports["result"]["outcomes"]["QUEUED"] == 1

    notifications, total = alert_repository.list_notifications(domain="GOVERNANCE", page=1, page_size=100)
    assert total == 5
    assert {item.event_type for item in notifications} == {
        RETENTION_REVIEW_DUE_EVENT,
        LEGAL_HOLD_PENDING_APPROVAL_EVENT,
        LEGAL_HOLD_REVIEW_DUE_EVENT,
        DISPOSITION_REVIEW_DUE_EVENT,
        EXPORT_APPROVAL_REVIEW_DUE_EVENT,
    }
    # Queued locally, never claimed as delivered.
    deliveries, delivery_total = alert_repository.list_deliveries(status="pending", page=1, page_size=100)
    assert delivery_total == 5
    assert all(item.delivered_at is None for item in deliveries)
    for notification in notifications:
        assert notification.context["delivery_status"] == "pending"
        assert notification.context["reminder_window"] == "20261111T120000Z"
        assert notification.context["automatic_hold_release"] is False
        assert notification.context["automatic_disposition_approval"] is False


def test_reminder_dedup_is_per_window_and_target(tmp_path: Any) -> None:
    governance = FakeGovernanceService(
        retention=[_retention_item("eval-dedup", next_review=NOW - timedelta(days=1))]
    )
    executor, repository, alert_repository, _ = _setup(tmp_path, governance=governance)
    config = {"upcoming_days": 30, "max_items": 100}
    first = _run(
        executor,
        repository,
        "RETENTION_REVIEW_REMINDERS",
        config,
        dedup_key="reminders:dedup:1",
    )
    assert first["result"]["outcomes"]["QUEUED"] == 1
    second = _run(
        executor,
        repository,
        "RETENTION_REVIEW_REMINDERS",
        config,
        dedup_key="reminders:dedup:2",
    )
    assert second["result"]["outcomes"]["DEDUPLICATED"] == 1
    _, total = alert_repository.list_notifications(domain="GOVERNANCE", page=1, page_size=100)
    assert total == 1


def test_reminder_cooldown_suppresses_a_new_window(tmp_path: Any) -> None:
    governance = FakeGovernanceService(
        retention=[_retention_item("eval-cooldown", next_review=NOW - timedelta(days=1))]
    )
    executor, repository, alert_repository, clock = _setup(
        tmp_path, governance=governance, cooldown_seconds=3600
    )
    config = {"upcoming_days": 30, "max_items": 100}
    first = _run(
        executor,
        repository,
        "RETENTION_REVIEW_REMINDERS",
        config,
        dedup_key="reminders:cooldown:1",
    )
    assert first["result"]["outcomes"]["QUEUED"] == 1
    clock["now"] = NOW + timedelta(minutes=1)
    second = _run(
        executor,
        repository,
        "RETENTION_REVIEW_REMINDERS",
        config,
        dedup_key="reminders:cooldown:2",
    )
    assert second["result"]["outcomes"]["COOLDOWN"] == 1
    assert second["result"]["reminder_window"] == "20261111T120100Z"
    _, total = alert_repository.list_notifications(domain="GOVERNANCE", page=1, page_size=100)
    assert total == 1


def test_disabled_notifier_and_missing_rule_are_reported_honestly(tmp_path: Any) -> None:
    governance = FakeGovernanceService(
        retention=[_retention_item("eval-disabled", next_review=NOW - timedelta(days=1))]
    )
    config = {"upcoming_days": 30, "max_items": 100}

    disabled_executor, disabled_repo, disabled_alerts, _ = _setup(
        tmp_path / "disabled", notifier_enabled=False, governance=governance
    )
    disabled = _run(
        disabled_executor,
        disabled_repo,
        "RETENTION_REVIEW_REMINDERS",
        config,
        dedup_key="reminders:disabled:1",
    )
    assert disabled["result"]["outcomes"]["DISABLED"] == 1
    assert disabled["result"]["notifier_enabled"] is False
    _, disabled_total = disabled_alerts.list_notifications(domain="GOVERNANCE", page=1, page_size=100)
    assert disabled_total == 0

    no_rule_executor, no_rule_repo, no_rule_alerts, _ = _setup(
        tmp_path / "no-rule", with_rule=False, governance=governance
    )
    no_rule = _run(
        no_rule_executor,
        no_rule_repo,
        "RETENTION_REVIEW_REMINDERS",
        config,
        dedup_key="reminders:no-rule:1",
    )
    assert no_rule["result"]["outcomes"]["NO_RULE"] == 1
    _, no_rule_total = no_rule_alerts.list_notifications(domain="GOVERNANCE", page=1, page_size=100)
    assert no_rule_total == 0


def test_compliance_snapshot_is_digested_idempotent_and_csv_exportable(tmp_path: Any) -> None:
    report = {
        "generated_at": _iso(NOW),
        "scope": "SUMMARY",
        "as_of": NOW.date().isoformat(),
        "overall_status": "NO_KNOWN_GAPS",
        "sections": {
            "policy": {"status": "OK", "count": 1},
            "retention": {"status": "OK", "evaluated_cases": 7},
            "audit": {"status": "OK", "events": 3},
        },
        "regulatory_certification_claimed": False,
        "external_immutable_storage_claimed": False,
        "automatic_deletion": False,
    }
    executor, repository, _, _ = _setup(tmp_path, governance=FakeGovernanceService(report=report))
    first = _run(
        executor,
        repository,
        "COMPLIANCE_SNAPSHOT",
        {},
        dedup_key="snapshot:first",
    )
    assert first["status"] == JobStatus.SUCCEEDED.value
    result = first["result"]
    assert result["replayed"] is False
    assert result["row_count"] == 7
    assert result["overall_status"] == "NO_KNOWN_GAPS"
    assert len(result["payload_digest"]) == 64
    assert result["digest_valid"] is True

    second = _run(
        executor,
        repository,
        "COMPLIANCE_SNAPSHOT",
        {},
        dedup_key="snapshot:second",
    )
    assert second["result"]["replayed"] is True
    assert second["result"]["snapshot_id"] == result["snapshot_id"]

    snapshots, total = repository.list_snapshots(page=1, page_size=10)
    assert total == 1
    snapshot = snapshots[0]
    assert snapshot["digest_valid"] is True
    assert snapshot["row_count"] == 7
    assert snapshot["payload"]["sections"]["retention"]["evaluated_cases"] == 7

    csv_body = GovernanceAutomationService.snapshot_csv(snapshot)
    assert csv_body.startswith("section,metric,value")
    assert "retention,evaluated_cases,7" in csv_body
    assert "report,regulatory_certification_claimed,false" in csv_body


def test_reminder_activity_reports_pending_then_delivered(tmp_path: Any) -> None:
    governance = FakeGovernanceService(
        retention=[_retention_item("eval-activity", next_review=NOW - timedelta(days=1))]
    )
    executor, repository, alert_repository, _ = _setup(tmp_path, governance=governance)
    _run(
        executor,
        repository,
        "RETENTION_REVIEW_REMINDERS",
        {"upcoming_days": 30, "max_items": 100},
        dedup_key="reminders:activity:1",
    )
    activity = repository.reminder_activity(now=NOW)
    assert activity["total"] == 1
    assert activity["delivery_states"]["PENDING"] == 1
    assert activity["delivery_claimed"] is False
    assert activity["items"][0]["delivery_state"] == "PENDING"
    assert activity["items"][0]["target_type"] == "RETENTION_EVALUATION"

    deliveries, _ = alert_repository.list_deliveries(status="pending", page=1, page_size=10)
    assert len(deliveries) == 1
    alert_repository.mark_delivery(deliveries[0].id, status="sent", delivered=True)
    delivered = repository.reminder_activity(now=NOW)
    assert delivered["delivery_states"]["DELIVERED"] == 1
    assert delivered["items"][0]["delivery_state"] == "DELIVERED"
    assert delivered["items"][0]["delivery_claimed"] is False


@pytest.mark.parametrize(
    ("job_type", "config"),
    [
        ("RETENTION_REVIEW_REMINDERS", {"upcoming_days": 30, "max_items": 100}),
        ("LEGAL_HOLD_REMINDERS", {"max_items": 100, "active_hold_age_days": 30}),
        ("DISPOSITION_REVIEW_REMINDERS", {"max_items": 100, "min_age_days": 1}),
        ("EXPORT_APPROVAL_REMINDERS", {"max_items": 100, "upcoming_days": 14}),
    ],
)
def test_reminders_never_mutate_governance_state(
    tmp_path: Any, job_type: str, config: dict[str, Any]
) -> None:
    governance = FakeGovernanceService(
        retention=[_retention_item("eval-mutate", next_review=NOW - timedelta(days=1))],
        holds=[
            _hold_item(
                "hold-mutate",
                "PENDING_APPROVAL",
                requested_at=NOW - timedelta(days=2),
            )
        ],
        dispositions=[
            _disposition_item("disp-mutate", "REVIEW_REQUIRED", requested_at=NOW - timedelta(days=2))
        ],
        exports=[
            _export_item(
                "exp-mutate",
                requested_at=NOW - timedelta(days=2),
                expires_at=NOW + timedelta(days=7),
            )
        ],
    )
    executor, repository, _, _ = _setup(tmp_path, governance=governance)
    result = _run(executor, repository, job_type, config, dedup_key=f"reminders:{job_type}:1")
    payload = result["result"]
    assert payload["automatic_hold_release"] is False
    assert payload["automatic_disposition_approval"] is False
    assert payload["automatic_export_generation"] is False
    assert payload["non_claims"]
