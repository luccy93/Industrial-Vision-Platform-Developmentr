"""V36 governance automation hardening and recovery tests.

Synthetic local fixtures only. These tests target adversarial edges: lease
heartbeat races, concurrent claims and manual runs, cooperative cancellation,
timeouts, retry exhaustion, crash recovery, snapshot digest tamper detection,
bounded metric labels, redaction, muted reminder state, and honest health.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from prometheus_client import REGISTRY

from backend.app.alerting.repository import AlertRepository
from backend.app.core.config import AppEnv, Settings
from backend.app.core.metrics import (
    metrics_payload,
    record_governance_automation_job,
    record_governance_automation_recovery,
    record_governance_automation_reminder,
    record_governance_automation_snapshot,
    set_governance_automation_queue_depth,
)
from backend.app.governance.alerting import GovernanceNotifier
from backend.app.governance.automation.constants import (
    RETENTION_REVIEW_DUE_EVENT,
    JobStatus,
    JobType,
)
from backend.app.governance.automation.errors import (
    AutomationValidationError,
    JobStateError,
    JobTimeout,
    UnsupportedJobTypeError,
)
from backend.app.governance.automation.executor import GovernanceJobExecutor
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.governance.automation.scheduler import GovernanceAutomationScheduler
from backend.app.governance.automation.service import GovernanceAutomationService
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.models.governance_automation_orm import GovernanceSnapshotORM

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


class FakeGovernanceService:
    def __init__(
        self,
        *,
        status: dict[str, Any] | None = None,
        report: dict[str, Any] | None = None,
        report_error: Exception | None = None,
    ) -> None:
        self._status = status or {"audit_integrity": {"outcome": "OK", "checked": 1, "verified": 1}}
        self._report = report or {}
        self._report_error = report_error

    def status(self) -> dict[str, Any]:
        return dict(self._status)

    def compliance_report(self, **_kwargs: Any) -> dict[str, Any]:
        if self._report_error is not None:
            raise self._report_error
        return dict(self._report)


class FakeForensicRepository:
    def list_cases(self, *, page: int = 1, page_size: int = 20) -> tuple[list[dict[str, Any]], int]:
        return [], 0

    def get_case(self, case_id: str) -> dict[str, Any] | None:
        return {"case_id": case_id, "case_number": "CASE-SYNTHETIC", "status": "OPEN"}


class FakeIntegrityService:
    def __init__(self, latest_status: str) -> None:
        self._latest_status = latest_status

    def status(self) -> dict[str, Any]:
        return {
            "latest_audit": {"status": self._latest_status},
            "store_status": "OK",
            "open_findings": 0,
        }


class StubExecutor:
    """Minimal executor surface used by status/health/validation tests."""

    notifier_enabled = False

    def supported_job_types(self) -> frozenset[str]:
        return frozenset(item.value for item in JobType)


def _settings(tmp_path: Any, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "app_name": "v36-hardening",
        "app_env": AppEnv.testing,
        "database_url": f"sqlite:///{tmp_path}/hardening.db",
        "governance_automation_enabled": True,
        "governance_automation_lease_seconds": 30,
        "governance_automation_max_attempts": 3,
        "governance_automation_retry_base_seconds": 1,
        "governance_automation_retry_max_seconds": 1,
        "governance_automation_max_jobs_per_tick": 5,
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def _repository(tmp_path: Any, **overrides: Any) -> tuple[Settings, GovernanceAutomationRepository]:
    settings = _settings(tmp_path, **overrides)
    init_db(settings.database_url)
    repository = GovernanceAutomationRepository(get_session_factory(settings.database_url))
    repository.ensure_schedules()
    return settings, repository


def _executor(
    repository: GovernanceAutomationRepository,
    *,
    governance: FakeGovernanceService | None = None,
    clock: Any | None = None,
    timeout_seconds: float = 300.0,
) -> GovernanceJobExecutor:
    return GovernanceJobExecutor(
        repository=repository,
        governance_service=governance or FakeGovernanceService(),  # type: ignore[arg-type]
        forensic_repository=FakeForensicRepository(),
        integrity_service=None,
        clock=clock or (lambda: NOW),
        lease_seconds=60,
        timeout_seconds=timeout_seconds,
    )


def _service(
    settings: Settings,
    repository: GovernanceAutomationRepository,
    *,
    executor: Any | None = None,
    governance: FakeGovernanceService | None = None,
    integrity: Any | None = None,
    clock: Any | None = None,
) -> GovernanceAutomationService:
    return GovernanceAutomationService(
        settings=settings,
        repository=repository,
        executor=executor or StubExecutor(),  # type: ignore[arg-type]
        scheduler=None,
        governance_service=governance or FakeGovernanceService(),  # type: ignore[arg-type]
        integrity_service=integrity,
        clock=clock or (lambda: NOW),
    )


def _new_job(
    repository: GovernanceAutomationRepository,
    *,
    job_type: str = "GOVERNANCE_HEALTH_CHECK",
    dedup_key: str,
    now: datetime = NOW,
    config: dict[str, Any] | None = None,
    max_attempts: int = 3,
) -> dict[str, Any]:
    job, created = repository.create_job(
        job_type=job_type,
        trigger="MANUAL",
        dedup_key=dedup_key,
        requested_by="tester",
        requested_role="ADMIN",
        config_snapshot=config or {},
        max_attempts=max_attempts,
        now=now,
    )
    assert created is True
    return job


# ---------------------------------------------------------------------------
# Leases, heartbeats, concurrency
# ---------------------------------------------------------------------------
def test_heartbeat_extension_prevents_recovery_and_owner_is_enforced(tmp_path: Any) -> None:
    _, repository = _repository(tmp_path)
    job = _new_job(repository, dedup_key="hardening:heartbeat")
    claimed = repository.claim_job(job["job_id"], lease_owner="worker-a", lease_seconds=10, now=NOW)
    assert claimed is not None
    assert repository.heartbeat_job(
        job["job_id"], lease_owner="worker-a", lease_seconds=60, now=NOW + timedelta(seconds=5)
    )
    assert not repository.heartbeat_job(
        job["job_id"], lease_owner="worker-b", lease_seconds=60, now=NOW + timedelta(seconds=5)
    )
    # The extended lease is not expired at +20s.
    assert repository.recover_expired_jobs(now=NOW + timedelta(seconds=20)) == []
    # It is expired after the extended deadline.
    recovered = repository.recover_expired_jobs(now=NOW + timedelta(seconds=70))
    assert [item["job_id"] for item in recovered] == [job["job_id"]]
    stored = repository.get_job(job["job_id"])
    assert stored is not None and stored["status"] == JobStatus.UNAVAILABLE.value
    # A late owner cannot finish a recovered job.
    assert not repository.finish_job(
        job["job_id"], lease_owner="worker-a", status="SUCCEEDED", now=NOW + timedelta(seconds=71)
    )


def test_concurrent_claims_never_claim_the_same_job_twice(tmp_path: Any) -> None:
    _, repository = _repository(tmp_path)
    jobs = [_new_job(repository, dedup_key=f"hardening:concurrent-claim:{index}") for index in range(5)]
    barrier = threading.Barrier(5)

    def claim(index: int) -> str | None:
        barrier.wait(timeout=10)
        claimed = repository.claim_next_job(lease_owner=f"worker-{index}", lease_seconds=60, now=NOW)
        return str(claimed["job_id"]) if claimed is not None else None

    with ThreadPoolExecutor(max_workers=5) as pool:
        claimed_ids = [future.result(timeout=30) for future in [pool.submit(claim, i) for i in range(5)]]
    non_null = [item for item in claimed_ids if item is not None]
    assert len(non_null) == len(set(non_null))
    for job in jobs:
        events = repository.job_events(job["job_id"])
        assert sum(1 for event in events if event["event_type"] == "CLAIMED") <= 1


def test_concurrent_manual_runs_create_one_job_and_one_execution(tmp_path: Any) -> None:
    settings, repository = _repository(tmp_path)
    executor = _executor(repository)
    service = _service(settings, repository, executor=executor)
    barrier = threading.Barrier(4)

    def run() -> dict[str, Any]:
        barrier.wait(timeout=10)
        return service.run_now(
            job_type="GOVERNANCE_HEALTH_CHECK",
            idempotency_key="hardening-concurrent-run",
            reason="synthetic concurrent manual run",
            actor_id="operator@example.com",
            actor_role="OPERATOR",
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = [future.result(timeout=60) for future in [pool.submit(run) for _ in range(4)]]

    assert repository.count_jobs() == 1
    job = repository.list_jobs(job_type="GOVERNANCE_HEALTH_CHECK")[0][0]
    assert job["status"] == JobStatus.SUCCEEDED.value
    assert sum(1 for item in results if item["replayed"] is False) == 1
    events = repository.job_events(job["job_id"])
    assert sum(1 for event in events if event["event_type"] == "CLAIMED") == 1
    assert sum(1 for event in events if event["event_type"] == "SUCCEEDED") == 1


# ---------------------------------------------------------------------------
# Cancellation, timeout, unsupported types, crash recovery
# ---------------------------------------------------------------------------
def test_running_cancellation_is_cooperative_and_terminal_cancel_conflicts(tmp_path: Any) -> None:
    settings, repository = _repository(tmp_path)
    service = _service(settings, repository)
    job = _new_job(repository, dedup_key="hardening:cancel-running")
    claimed = repository.claim_job(job["job_id"], lease_owner="worker-a", lease_seconds=60, now=NOW)
    assert claimed is not None

    outcome = service.cancel_job(
        job["job_id"],
        reason="synthetic cooperative cancellation",
        actor_id="operator@example.com",
        actor_role="OPERATOR",
    )
    assert outcome["cancelled"] is False
    assert outcome["cancel_requested"] is True
    assert outcome["job"]["status"] == JobStatus.RUNNING.value
    assert repository.is_cancel_requested(job["job_id"]) is True

    assert repository.finish_job(
        job["job_id"],
        lease_owner="worker-a",
        status=JobStatus.CANCELLED.value,
        now=NOW + timedelta(seconds=1),
    )
    stored = repository.get_job(job["job_id"])
    assert stored is not None and stored["status"] == JobStatus.CANCELLED.value
    with pytest.raises(JobStateError):
        service.cancel_job(
            job["job_id"],
            reason="already terminal cancellation",
            actor_id="operator@example.com",
            actor_role="OPERATOR",
        )
    with pytest.raises(AutomationValidationError):
        service.cancel_job(
            job["job_id"],
            reason="x",
            actor_id="operator@example.com",
            actor_role="OPERATOR",
        )


def test_checkpoint_timeout_marks_failed_with_bounded_error(tmp_path: Any) -> None:
    _, repository = _repository(tmp_path)
    executor = _executor(repository)

    def timeout_handler(context: Any) -> dict[str, Any]:
        # Move the start far enough into the past to beat the coarse Windows
        # monotonic clock resolution without relying on private mutation.
        context.started_monotonic -= 3600.0
        context.checkpoint()
        return {}

    executor.register_handler("GOVERNANCE_HEALTH_CHECK", timeout_handler)
    job = _new_job(repository, dedup_key="hardening:timeout")
    claimed = repository.claim_job(job["job_id"], lease_owner="tester", lease_seconds=60, now=NOW)
    assert claimed is not None
    with pytest.raises(JobTimeout):
        executor.execute(claimed, lease_owner="tester")
    stored = repository.get_job(job["job_id"])
    assert stored is not None
    assert stored["status"] == JobStatus.FAILED.value
    assert stored["error_code"] == "TIMEOUT"
    assert len(stored["error_message"]) <= 512


def test_checkpoint_observes_cancellation_and_records_cancelled(tmp_path: Any) -> None:
    _, repository = _repository(tmp_path)
    executor = _executor(repository)
    job = _new_job(repository, dedup_key="hardening:checkpoint-cancel")
    claimed = repository.claim_job(job["job_id"], lease_owner="tester", lease_seconds=60, now=NOW)
    assert claimed is not None
    repository.request_cancel(
        job["job_id"],
        actor_id="operator@example.com",
        actor_role="OPERATOR",
        now=NOW,
    )
    finished = executor.execute(claimed, lease_owner="tester")
    assert finished["status"] == JobStatus.CANCELLED.value
    events = repository.job_events(job["job_id"])
    assert any(event["event_type"] == "CANCELLED" for event in events)


def test_unsupported_job_type_fails_without_retry_and_is_sanitized(tmp_path: Any) -> None:
    _, repository = _repository(tmp_path)
    executor = _executor(repository)
    executor._handlers.pop("GOVERNANCE_HEALTH_CHECK")
    job = _new_job(repository, dedup_key="hardening:unsupported")
    claimed = repository.claim_job(job["job_id"], lease_owner="tester", lease_seconds=60, now=NOW)
    assert claimed is not None
    with pytest.raises(UnsupportedJobTypeError):
        executor.execute(claimed, lease_owner="tester")
    stored = repository.get_job(job["job_id"])
    assert stored is not None
    assert stored["status"] == JobStatus.FAILED.value
    assert stored["error_code"] == "UNSUPPORTED_JOB_TYPE"
    assert "not implemented" in stored["error_message"]


class CrashingExecutor:
    """Executor that crashes before recording a terminal state."""

    def __init__(self, repository: GovernanceAutomationRepository, clock: Any) -> None:
        self.repository = repository
        self.clock = clock
        self.calls: list[str] = []

    def recover_expired(self) -> list[dict[str, Any]]:
        return self.repository.recover_expired_jobs(now=self.clock())

    def execute(self, job: dict[str, Any], *, lease_owner: str) -> dict[str, Any]:
        self.calls.append(str(job["job_id"]))
        raise RuntimeError("synthetic executor crash")


def test_crashed_executor_job_is_recovered_and_retried_once(tmp_path: Any) -> None:
    settings, repository = _repository(
        tmp_path,
        governance_automation_lease_seconds=5,
        governance_automation_max_attempts=2,
    )
    clock = {"now": NOW}

    def _clock() -> datetime:
        return clock["now"]

    executor = CrashingExecutor(repository, _clock)
    scheduler = GovernanceAutomationScheduler(
        settings=settings,
        repository=repository,
        executor=executor,  # type: ignore[arg-type]
        clock=_clock,
    )
    repository.update_schedule(
        "GOVERNANCE_HEALTH_CHECK",
        enabled=True,
        interval_minutes=60,
        config={},
        expected_version=1,
        actor_id="tester",
        now=NOW,
    )
    first = scheduler.run_once(NOW)
    assert first["executed"] == 1
    assert first["failed"] == 1
    jobs, total = repository.list_jobs(job_type="GOVERNANCE_HEALTH_CHECK")
    assert total == 1
    parent = jobs[0]
    assert parent["status"] == JobStatus.RUNNING.value

    clock["now"] = NOW + timedelta(seconds=10)
    second = scheduler.run_once(clock["now"])
    assert second["recovered"] == 1
    assert second["retries"] == 1
    recovered = repository.get_job(parent["job_id"])
    assert recovered is not None and recovered["status"] == JobStatus.UNAVAILABLE.value
    jobs, total = repository.list_jobs(job_type="GOVERNANCE_HEALTH_CHECK")
    assert total == 2
    child = next(item for item in jobs if item["attempt"] == 2)
    assert child["retry_of_job_id"] == parent["job_id"]
    assert child["status"] == JobStatus.PENDING.value


def test_retry_chain_stops_at_max_attempts(tmp_path: Any) -> None:
    settings, repository = _repository(
        tmp_path,
        governance_automation_max_attempts=2,
        governance_automation_retry_base_seconds=1,
        governance_automation_retry_max_seconds=1,
    )
    clock = {"now": NOW}

    def _clock() -> datetime:
        return clock["now"]

    class FailingExecutor(CrashingExecutor):
        def execute(self, job: dict[str, Any], *, lease_owner: str) -> dict[str, Any]:
            self.calls.append(str(job["job_id"]))
            self.repository.finish_job(
                job["job_id"],
                lease_owner=lease_owner,
                status=JobStatus.FAILED.value,
                error_code="SYNTHETIC",
                error_message="synthetic retry exhaustion failure",
                now=self.clock(),
            )
            raise RuntimeError("synthetic retry exhaustion failure")

    executor = FailingExecutor(repository, _clock)
    scheduler = GovernanceAutomationScheduler(
        settings=settings,
        repository=repository,
        executor=executor,  # type: ignore[arg-type]
        clock=_clock,
    )
    repository.update_schedule(
        "GOVERNANCE_HEALTH_CHECK",
        enabled=True,
        interval_minutes=60,
        config={},
        expected_version=1,
        actor_id="tester",
        now=NOW,
    )
    scheduler.run_once(NOW)
    jobs, total = repository.list_jobs(job_type="GOVERNANCE_HEALTH_CHECK")
    assert total == 2
    child = next(item for item in jobs if item["attempt"] == 2)

    clock["now"] = NOW + timedelta(seconds=5)
    scheduler.run_once(clock["now"])
    jobs, total = repository.list_jobs(job_type="GOVERNANCE_HEALTH_CHECK")
    assert total == 2
    assert all(item["status"] == JobStatus.FAILED.value for item in jobs)
    assert child["retry_of_job_id"] is not None


# ---------------------------------------------------------------------------
# Snapshot integrity, redaction, reminder state
# ---------------------------------------------------------------------------
def test_snapshot_digest_tamper_is_detected_on_read(tmp_path: Any) -> None:
    _, repository = _repository(tmp_path)
    snapshot, created = repository.create_snapshot(
        snapshot_type="COMPLIANCE_SUMMARY",
        as_of=NOW,
        generated_by="tester",
        dedup_key="hardening:snapshot-digest",
        payload={"status": "OK"},
        row_count=1,
        now=NOW,
    )
    assert created is True
    assert snapshot["digest_valid"] is True

    # Insert-time corruption is detectable; the append-only trigger blocks
    # updates, so simulate a damaged import rather than an in-place edit.
    with repository._session_factory() as session:  # noqa: SLF001 - deliberate tamper fixture
        session.add(
            GovernanceSnapshotORM(
                id="snapshot-tampered",
                snapshot_type="COMPLIANCE_SUMMARY",
                as_of=NOW,
                generated_at=NOW,
                generated_by="tester",
                job_id=None,
                trigger="MANUAL",
                dedup_key="hardening:snapshot-tampered",
                payload={"status": "TAMPERED"},
                payload_digest="0" * 64,
                row_count=1,
                schema_version=1,
            )
        )
        session.commit()
    tampered = repository.get_snapshot("snapshot-tampered")
    assert tampered is not None
    assert tampered["digest_valid"] is False
    # The append-only UPDATE/DELETE triggers are installed by the Alembic
    # migration, not by metadata create_all, and are asserted in
    # test_v36_migration.py. Here we only prove read-time tamper detection.


def test_snapshot_failure_is_terminal_and_redacted(tmp_path: Any) -> None:
    _, repository = _repository(tmp_path)
    governance = FakeGovernanceService(
        report_error=RuntimeError("snapshot failed api_key=super-secret-value")
    )
    executor = _executor(repository, governance=governance)
    job = _new_job(repository, job_type="COMPLIANCE_SNAPSHOT", dedup_key="hardening:snapshot-fail")
    claimed = repository.claim_job(job["job_id"], lease_owner="tester", lease_seconds=60, now=NOW)
    assert claimed is not None
    with pytest.raises(RuntimeError):
        executor.execute(claimed, lease_owner="tester")
    stored = repository.get_job(job["job_id"])
    assert stored is not None
    assert stored["status"] == JobStatus.FAILED.value
    assert "super-secret-value" not in (stored["error_message"] or "")
    assert "[REDACTED]" in (stored["error_message"] or "")
    assert repository.count_snapshots() == 0


def test_snapshot_payload_and_csv_are_redacted(tmp_path: Any) -> None:
    _, repository = _repository(tmp_path)
    report = {
        "generated_at": NOW.isoformat().replace("+00:00", "Z"),
        "scope": "SUMMARY",
        "as_of": NOW.date().isoformat(),
        "overall_status": "NO_KNOWN_GAPS",
        "sections": {
            "retention": {"status": "OK", "evaluated_cases": 3},
            "audit": {"status": "OK", "events": 1},
        },
        "api_key": "super-secret-value",
        "nested": {"password": "hunter2"},
        "regulatory_certification_claimed": False,
        "external_immutable_storage_claimed": False,
    }
    executor = _executor(repository, governance=FakeGovernanceService(report=report))
    job = _new_job(repository, job_type="COMPLIANCE_SNAPSHOT", dedup_key="hardening:snapshot-redact")
    claimed = repository.claim_job(job["job_id"], lease_owner="tester", lease_seconds=60, now=NOW)
    assert claimed is not None
    executor.execute(claimed, lease_owner="tester")
    snapshots, total = repository.list_snapshots()
    assert total == 1
    snapshot = snapshots[0]
    serialized = str(snapshot["payload"])
    assert "super-secret-value" not in serialized
    assert "hunter2" not in serialized
    assert snapshot["payload"]["api_key"] == "[REDACTED]"
    assert snapshot["payload"]["nested"]["password"] == "[REDACTED]"
    assert snapshot["digest_valid"] is True
    csv_body = GovernanceAutomationService.snapshot_csv(snapshot)
    assert "super-secret-value" not in csv_body
    assert "hunter2" not in csv_body


def test_reminder_activity_reports_muted_and_filters_by_event_type(tmp_path: Any) -> None:
    settings, repository = _repository(tmp_path)
    alert_repository = AlertRepository(get_session_factory(settings.database_url))
    alert_repository.create_rule(
        name="Synthetic hardening reminder rule",
        domains=["GOVERNANCE"],
        channels=["in_app"],
        cooldown_seconds=0,
    )
    notifier = GovernanceNotifier(
        session_factory=get_session_factory(settings.database_url),
        alert_repository=alert_repository,
        enabled=True,
        min_severity="HIGH",
        cooldown_seconds=0,
    )
    stats = notifier.notify_event(
        event_type=RETENTION_REVIEW_DUE_EVENT,
        case={"case_id": "case-muted", "case_number": "CASE-M", "version": 1},
        target_type="RETENTION_EVALUATION",
        target_id="eval-muted",
        severity="HIGH",
        detail="Synthetic muted reminder.",
        dedup_version="20261111T120000Z",
    )
    assert stats["queued"] == 1
    notifications, total = alert_repository.list_notifications(domain="GOVERNANCE", page=1, page_size=10)
    assert total == 1
    notification = notifications[0]
    alert_repository.mute_notification(notification.id, muted_until=NOW + timedelta(hours=1))

    activity = repository.reminder_activity(now=NOW)
    assert activity["total"] == 1
    assert activity["muted"] == 1
    assert activity["items"][0]["muted"] is True
    assert activity["items"][0]["delivery_state"] == "PENDING"
    assert activity["items"][0]["delivery_claimed"] is False

    filtered = repository.reminder_activity(event_type=RETENTION_REVIEW_DUE_EVENT, now=NOW)
    assert filtered["total"] == 1
    unknown = repository.reminder_activity(event_type="NOT_A_REMINDER", now=NOW)
    assert unknown["total"] == 0
    assert unknown["items"] == []


# ---------------------------------------------------------------------------
# Metrics cardinality and honest health
# ---------------------------------------------------------------------------
def test_metrics_labels_are_bounded_and_do_not_leak_values() -> None:
    service = "v36-hardening-metrics"
    record_governance_automation_job(
        job_type="SECRET_JOB_TYPE",
        trigger="<script>",
        status="DROP TABLE",
        duration_seconds=0.5,
        service=service,
    )
    unknown_job = {
        "service": service,
        "job_type": "UNKNOWN",
        "trigger": "UNKNOWN",
        "status": "UNKNOWN",
    }
    assert (REGISTRY.get_sample_value("ivp_governance_automation_jobs_total", unknown_job) or 0) >= 1
    assert (
        REGISTRY.get_sample_value(
            "ivp_governance_automation_job_duration_seconds_count",
            {"service": service, "job_type": "UNKNOWN"},
        )
        or 0
    ) >= 1

    record_governance_automation_reminder("SECRET_CATEGORY", "SECRET_OUTCOME", service=service)
    reminder_labels = {"service": service, "category": "UNKNOWN", "outcome": "UNKNOWN"}
    assert (REGISTRY.get_sample_value("ivp_governance_automation_reminders_total", reminder_labels) or 0) >= 1

    record_governance_automation_snapshot("SECRET_TRIGGER", "SECRET_STATUS", service=service)
    snapshot_labels = {"service": service, "trigger": "UNKNOWN", "status": "UNKNOWN"}
    assert (REGISTRY.get_sample_value("ivp_governance_automation_snapshots_total", snapshot_labels) or 0) >= 1

    record_governance_automation_recovery("SECRET_JOB", service=service)
    recovery_labels = {"service": service, "job_type": "UNKNOWN"}
    assert (
        REGISTRY.get_sample_value("ivp_governance_automation_recoveries_total", recovery_labels) or 0
    ) >= 1

    set_governance_automation_queue_depth({"SECRET_STATUS": 3}, service=service)
    queue_labels = {"service": service, "status": "UNKNOWN"}
    assert (REGISTRY.get_sample_value("ivp_governance_automation_queue_depth", queue_labels) or 0) == 3

    payload = metrics_payload().decode("utf-8")
    assert "SECRET_JOB_TYPE" not in payload
    assert "DROP TABLE" not in payload
    assert "SECRET_CATEGORY" not in payload
    assert "SECRET_OUTCOME" not in payload
    assert "SECRET_TRIGGER" not in payload
    assert "SECRET_STATUS" not in payload


@pytest.mark.parametrize(
    "latest_status",
    ["FAIL", "PARTIAL", "UNAVAILABLE", "NOT_RUN", "RUNNING"],
)
def test_health_never_treats_non_pass_integrity_as_ok(tmp_path: Any, latest_status: str) -> None:
    settings, repository = _repository(tmp_path, governance_automation_enabled=False)
    service = _service(
        settings,
        repository,
        integrity=FakeIntegrityService(latest_status),
        governance=FakeGovernanceService(
            status={"audit_integrity": {"outcome": "OK", "checked": 1, "verified": 1}}
        ),
    )
    health = service.health()
    assert health["integrity"]["status"] == "NOT_PASS"
    assert health["integrity"]["latest_audit_status"] == latest_status
    assert health["overall_status"] != "OK"


def test_health_reports_pass_only_for_pass_and_fails_on_audit(tmp_path: Any) -> None:
    settings, repository = _repository(tmp_path, governance_automation_enabled=False)
    passing = _service(
        settings,
        repository,
        integrity=FakeIntegrityService("PASS"),
        governance=FakeGovernanceService(
            status={"audit_integrity": {"outcome": "OK", "checked": 1, "verified": 1}}
        ),
    )
    assert passing.health()["overall_status"] == "OK"

    failing_audit = _service(
        settings,
        repository,
        integrity=FakeIntegrityService("PASS"),
        governance=FakeGovernanceService(
            status={"audit_integrity": {"outcome": "FAILED", "checked": 1, "verified": 0}}
        ),
    )
    health = failing_audit.health()
    assert health["overall_status"] == "FAILED"
    assert health["governance_audit"]["outcome"] == "FAILED"


# ---------------------------------------------------------------------------
# Validation and retry replay
# ---------------------------------------------------------------------------
def test_schedule_and_manual_run_validation_is_bounded(tmp_path: Any) -> None:
    settings, repository = _repository(tmp_path)
    service = _service(settings, repository)
    base = {
        "enabled": False,
        "interval_minutes": 60,
        "config": {},
        "expected_version": 1,
        "reason": "synthetic validation",
    }
    with pytest.raises(ValueError):
        service.update_schedule(
            "RETENTION_EVALUATION",
            {**base, "interval_minutes": 4},
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(ValueError):
        service.update_schedule(
            "RETENTION_EVALUATION",
            {**base, "config": {"batch_limit": 501}},
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(ValueError):
        service.update_schedule(
            "RETENTION_EVALUATION",
            {**base, "config": {"unknown": 1}},
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(UnsupportedJobTypeError):
        service.run_now(
            job_type="NOT_A_JOB",
            idempotency_key="hardening-validation-1",
            reason="synthetic validation",
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(AutomationValidationError):
        service.run_now(
            job_type="GOVERNANCE_HEALTH_CHECK",
            idempotency_key="hardening-validation-2",
            reason="x",
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(AutomationValidationError):
        service.run_now(
            job_type="GOVERNANCE_HEALTH_CHECK",
            idempotency_key="k" * 129,
            reason="synthetic validation",
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_retry_replay_does_not_execute_a_second_child(tmp_path: Any) -> None:
    settings, repository = _repository(tmp_path)
    executor = _executor(repository)
    service = _service(settings, repository, executor=executor)
    job = _new_job(repository, dedup_key="hardening:retry-replay")
    claimed = repository.claim_job(job["job_id"], lease_owner="tester", lease_seconds=60, now=NOW)
    assert claimed is not None
    repository.finish_job(
        job["job_id"],
        lease_owner="tester",
        status=JobStatus.FAILED.value,
        error_code="SYNTHETIC",
        error_message="synthetic failure",
        now=NOW,
    )
    first = service.retry_job(
        job["job_id"],
        reason="synthetic retry replay",
        actor_id="operator@example.com",
        actor_role="OPERATOR",
    )
    second = service.retry_job(
        job["job_id"],
        reason="synthetic retry replay",
        actor_id="operator@example.com",
        actor_role="OPERATOR",
    )
    assert first["replayed"] is False
    assert second["replayed"] is True
    assert second["executed"] is False
    assert second["job"]["job_id"] == first["job"]["job_id"]
    assert repository.count_jobs() == 2
