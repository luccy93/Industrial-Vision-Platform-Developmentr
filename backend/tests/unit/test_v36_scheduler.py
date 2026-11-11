"""V36 governance automation scheduler tests (deterministic, injected clock)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.core.config import AppEnv, Settings
from backend.app.governance.automation.constants import JobStatus
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.governance.automation.scheduler import GovernanceAutomationScheduler
from backend.app.infrastructure.db import get_session_factory, init_db

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


class FakeExecutor:
    """Bounded executor double that records calls and persists terminal states."""

    def __init__(self, repository: GovernanceAutomationRepository, clock: Any) -> None:
        self.repository = repository
        self.clock = clock
        self.calls: list[dict[str, Any]] = []
        self.fail_types: set[str] = set()

    def recover_expired(self) -> list[dict[str, Any]]:
        return self.repository.recover_expired_jobs(now=self.clock())

    def execute(self, job: dict[str, Any], *, lease_owner: str) -> dict[str, Any]:
        self.calls.append(dict(job))
        if job["job_type"] in self.fail_types:
            self.repository.finish_job(
                job["job_id"],
                lease_owner=lease_owner,
                status=JobStatus.FAILED.value,
                error_code="SYNTHETIC",
                error_message="synthetic scheduler failure",
                now=self.clock(),
            )
            raise RuntimeError("synthetic scheduler failure")
        self.repository.finish_job(
            job["job_id"],
            lease_owner=lease_owner,
            status=JobStatus.SUCCEEDED.value,
            result={"synthetic": True},
            now=self.clock(),
        )
        stored = self.repository.get_job(job["job_id"])
        assert stored is not None
        return stored


def _setup(
    tmp_path: Any,
    *,
    enabled: bool = True,
    max_pending: int = 100,
    max_per_tick: int = 5,
) -> tuple[GovernanceAutomationScheduler, GovernanceAutomationRepository, FakeExecutor, Any]:
    settings = Settings(
        app_name="v36-scheduler",
        app_env=AppEnv.testing,
        database_url=f"sqlite:///{tmp_path}/scheduler.db",
        governance_automation_enabled=enabled,
        governance_automation_max_pending_jobs=max_pending,
        governance_automation_max_jobs_per_tick=max_per_tick,
        governance_automation_poll_seconds=5,
        governance_automation_lease_seconds=30,
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    repository = GovernanceAutomationRepository(get_session_factory(settings.database_url))
    repository.ensure_schedules()
    clock = {"now": NOW}

    def _clock() -> datetime:
        return clock["now"]

    executor = FakeExecutor(repository, _clock)
    scheduler = GovernanceAutomationScheduler(
        settings=settings,
        repository=repository,
        executor=executor,  # type: ignore[arg-type]
        clock=_clock,
    )
    return scheduler, repository, executor, clock


def _enable(
    repository: GovernanceAutomationRepository,
    job_type: str,
    config: dict[str, Any],
    *,
    now: datetime = NOW,
) -> None:
    repository.update_schedule(
        job_type,
        enabled=True,
        interval_minutes=60,
        config=config,
        expected_version=1,
        actor_id="tester",
        now=now,
    )


def test_scheduler_is_disabled_by_default(tmp_path: Any) -> None:
    scheduler, repository, executor, _ = _setup(tmp_path, enabled=False)
    _enable(repository, "GOVERNANCE_HEALTH_CHECK", {})
    stats = scheduler.run_once(NOW)
    assert stats["disabled"] is True
    assert executor.calls == []
    assert repository.queue_counts()[JobStatus.PENDING.value] == 0


def test_slot_idempotency_enqueues_once_and_executes_once(tmp_path: Any) -> None:
    scheduler, repository, executor, clock = _setup(tmp_path)
    _enable(repository, "GOVERNANCE_HEALTH_CHECK", {})
    first = scheduler.run_once(NOW)
    assert first["enqueued"] == 1
    assert first["executed"] == 1
    assert first["succeeded"] == 1
    assert len(executor.calls) == 1
    second = scheduler.run_once(NOW + timedelta(minutes=1))
    assert second["enqueued"] == 0
    assert second["executed"] == 0
    assert len(executor.calls) == 1
    # A later bucket enqueues exactly one more job.
    clock["now"] = NOW + timedelta(minutes=60)
    third = scheduler.run_once(clock["now"])
    assert third["enqueued"] == 1
    assert len(executor.calls) == 2


def test_queue_bound_skips_instead_of_growing(tmp_path: Any) -> None:
    scheduler, repository, _, _ = _setup(tmp_path, max_pending=1, max_per_tick=1)
    _enable(repository, "GOVERNANCE_HEALTH_CHECK", {})
    _enable(repository, "RETENTION_EVALUATION", {"batch_limit": 5})
    stats = scheduler.run_once(NOW)
    assert stats["enqueued"] == 1
    assert stats["skipped_full"] >= 1
    assert repository.count_jobs() == 1


def test_failed_job_schedules_deterministic_retry_child(tmp_path: Any) -> None:
    scheduler, repository, executor, _ = _setup(tmp_path)
    _enable(repository, "GOVERNANCE_HEALTH_CHECK", {})
    executor.fail_types.add("GOVERNANCE_HEALTH_CHECK")
    stats = scheduler.run_once(NOW)
    assert stats["failed"] == 1
    assert stats["retries"] == 1
    jobs, total = repository.list_jobs(job_type="GOVERNANCE_HEALTH_CHECK")
    assert total == 2
    parent = next(item for item in jobs if item["attempt"] == 1)
    child = next(item for item in jobs if item["attempt"] == 2)
    assert parent["status"] == JobStatus.FAILED.value
    assert child["status"] == JobStatus.PENDING.value
    assert child["retry_of_job_id"] == parent["job_id"]
    assert child["trigger"] == "RETRY"
    assert child["available_at"] > NOW.isoformat().replace("+00:00", "Z")


def test_expired_lease_is_recovered_and_retried(tmp_path: Any) -> None:
    scheduler, repository, executor, clock = _setup(tmp_path)
    job, created = repository.create_job(
        job_type="GOVERNANCE_HEALTH_CHECK",
        trigger="MANUAL",
        dedup_key="scheduler:lease-parent",
        requested_by="tester",
        requested_role="ADMIN",
        config_snapshot={},
        max_attempts=2,
        now=NOW,
    )
    assert created is True
    claimed = repository.claim_job(job["job_id"], lease_owner="dead-worker", lease_seconds=5, now=NOW)
    assert claimed is not None
    clock["now"] = NOW + timedelta(seconds=30)
    stats = scheduler.run_once(clock["now"])
    assert stats["recovered"] == 1
    assert stats["retries"] == 1
    recovered = repository.get_job(job["job_id"])
    assert recovered is not None and recovered["status"] == JobStatus.UNAVAILABLE.value
    jobs, total = repository.list_jobs(job_type="GOVERNANCE_HEALTH_CHECK")
    assert total == 2
    child = next(item for item in jobs if item["attempt"] == 2)
    assert child["retry_of_job_id"] == job["job_id"]
    assert executor.calls == []


def test_scheduler_status_reports_queue_and_heartbeat(tmp_path: Any) -> None:
    scheduler, repository, _, _ = _setup(tmp_path)
    _enable(repository, "GOVERNANCE_HEALTH_CHECK", {})
    scheduler.run_once(NOW)
    status = scheduler.status()
    assert status["enabled"] is True
    assert status["cycles"] == 1
    assert status["executed"] == 1
    assert status["queue"][JobStatus.SUCCEEDED.value] == 1
    assert status["last_cycle_at"] is not None
    assert status["last_success_at"] is not None
