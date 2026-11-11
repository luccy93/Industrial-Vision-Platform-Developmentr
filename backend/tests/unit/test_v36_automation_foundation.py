"""V36 governance automation foundation tests.

Every fixture is synthetic and local. These tests exercise schedules, job
dedup, leases, retry children, manual runs, and health reporting without any
external service or protected evidence file.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from backend.app.governance.automation.constants import (
    JobStatus,
    JobType,
    retry_delay_seconds,
    schedule_slot_id,
    slot_start,
    validate_schedule_config,
)
from backend.app.governance.automation.errors import (
    AutomationDisabledError,
    AutomationValidationError,
    JobStateError,
    RetryExhaustedError,
    ScheduleVersionConflictError,
)
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.infrastructure.db import get_session_factory, init_db


def _create_case(client: Any, title: str = "Synthetic V36 automation case") -> str:
    response = client.post(
        "/api/v1/forensics/cases",
        json={
            "title": title,
            "description": "Synthetic V36 fixture; no real evidence.",
            "case_type": "FORENSIC_REVIEW",
            "severity": "HIGH",
            "evidence_references": [],
        },
    )
    assert response.status_code == 201, response.text
    return str(response.json()["case_id"])


def test_schedules_are_seeded_disabled_and_status_stays_disabled(client: Any) -> None:
    service = client.app.state.governance_automation_service
    assert service is not None
    status = service.status()
    assert status["enabled"] is False
    assert status["schedule_count"] == len(JobType)
    assert status["enabled_schedule_count"] == 0
    assert all(item["enabled"] is False for item in status["schedules"])
    assert status["scheduler"]["state"] == "DISABLED"
    assert status["scheduler"]["running"] is False
    # The V35 workspace contract is preserved by default.
    governance_status = client.app.state.governance_service.status()
    assert governance_status["retention_scheduler"] == "DISABLED"
    assert governance_status["automation"]["enabled"] is False


def test_schedule_update_is_versioned_and_requires_global_enablement(client: Any) -> None:
    service = client.app.state.governance_automation_service
    with pytest.raises(AutomationDisabledError):
        service.update_schedule(
            "RETENTION_EVALUATION",
            {
                "enabled": True,
                "interval_minutes": 60,
                "config": {"batch_limit": 10},
                "expected_version": 1,
                "reason": "attempt to enable while disabled",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    updated = service.update_schedule(
        "RETENTION_EVALUATION",
        {
            "enabled": False,
            "interval_minutes": 60,
            "config": {"batch_limit": 10},
            "expected_version": 1,
            "reason": "synthetic schedule configuration",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )["schedule"]
    assert updated["interval_minutes"] == 60
    assert updated["config"] == {"batch_limit": 10}
    assert updated["config_version"] == 2
    with pytest.raises(ScheduleVersionConflictError):
        service.update_schedule(
            "RETENTION_EVALUATION",
            {
                "enabled": False,
                "interval_minutes": 60,
                "config": {"batch_limit": 10},
                "expected_version": 1,
                "reason": "stale version",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(AutomationValidationError):
        service.update_schedule(
            "RETENTION_EVALUATION",
            {
                "enabled": False,
                "interval_minutes": 60,
                "config": {"batch_limit": 10},
                "expected_version": 2,
                "reason": "x",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_manual_retention_run_is_idempotent_and_non_destructive(client: Any) -> None:
    case_id = _create_case(client)
    service = client.app.state.governance_automation_service
    first = service.run_now(
        job_type="RETENTION_EVALUATION",
        idempotency_key="manual-retention-1",
        reason="synthetic manual retention run",
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert first["replayed"] is False
    assert first["executed"] is True
    assert first["job"]["status"] == JobStatus.SUCCEEDED.value
    assert first["job"]["result"]["destructive"] is False
    assert first["job"]["result"]["evaluated"] >= 1
    second = service.run_now(
        job_type="RETENTION_EVALUATION",
        idempotency_key="manual-retention-1",
        reason="synthetic manual retention run",
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert second["replayed"] is True
    assert second["executed"] is False
    assert second["job"]["job_id"] == first["job"]["job_id"]
    # The case still exists and no evidence path was removed.
    detail = client.get(f"/api/v1/forensics/cases/{case_id}")
    assert detail.status_code == 200, detail.text


def test_repository_lease_claim_finish_and_stale_recovery(tmp_path: Any) -> None:
    from backend.app.core.config import AppEnv, Settings

    settings = Settings(
        app_name="v36-foundation",
        app_env=AppEnv.testing,
        database_url=f"sqlite:///{tmp_path}/foundation.db",
        _env_file=None,  # type: ignore[call-arg]
    )
    init_db(settings.database_url)
    repository = GovernanceAutomationRepository(get_session_factory(settings.database_url))
    repository.ensure_schedules()
    now = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
    job, created = repository.create_job(
        job_type="RETENTION_EVALUATION",
        trigger="MANUAL",
        dedup_key="foundation:lease:1",
        requested_by="tester",
        requested_role="ADMIN",
        config_snapshot={"batch_limit": 1},
        now=now,
    )
    assert created is True
    claimed = repository.claim_next_job(lease_owner="worker-a", lease_seconds=10, now=now)
    assert claimed is not None and claimed["job_id"] == job["job_id"]
    assert repository.claim_next_job(lease_owner="worker-b", lease_seconds=10, now=now) is None
    assert repository.heartbeat_job(job["job_id"], lease_owner="worker-a", lease_seconds=30, now=now)
    assert not repository.heartbeat_job(job["job_id"], lease_owner="worker-b", lease_seconds=30, now=now)
    assert not repository.finish_job(
        job["job_id"],
        lease_owner="worker-b",
        status="SUCCEEDED",
        now=now,
    )
    recovered = repository.recover_expired_jobs(now=now + timedelta(seconds=60))
    assert [item["job_id"] for item in recovered] == [job["job_id"]]
    stored = repository.get_job(job["job_id"])
    assert stored is not None
    assert stored["status"] == JobStatus.UNAVAILABLE.value
    assert stored["error_code"] == "LEASE_EXPIRED"
    # A late executor cannot overwrite the recovered terminal state.
    assert not repository.finish_job(
        job["job_id"],
        lease_owner="worker-a",
        status="SUCCEEDED",
        now=now + timedelta(seconds=61),
    )


def test_retry_child_is_unique_and_bounded(client: Any) -> None:
    service = client.app.state.governance_automation_service
    repository: GovernanceAutomationRepository = client.app.state.governance_automation_repository
    job, created = repository.create_job(
        job_type="RETENTION_EVALUATION",
        trigger="MANUAL",
        dedup_key="foundation:retry-parent",
        requested_by="tester",
        requested_role="ADMIN",
        config_snapshot={"batch_limit": 1},
        max_attempts=2,
        now=datetime(2026, 11, 11, 12, 0, tzinfo=UTC),
    )
    assert created is True
    claimed = repository.claim_job(
        job["job_id"],
        lease_owner="tester",
        lease_seconds=60,
        now=datetime(2026, 11, 11, 12, 0, tzinfo=UTC),
    )
    assert claimed is not None
    assert repository.finish_job(
        job["job_id"],
        lease_owner="tester",
        status=JobStatus.FAILED.value,
        error_code="SYNTHETIC",
        error_message="synthetic failure",
        now=datetime(2026, 11, 11, 12, 0, tzinfo=UTC),
    )
    first = service.retry_job(
        job["job_id"],
        reason="synthetic manual retry",
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert first["replayed"] is False
    assert first["job"]["attempt"] == 2
    assert first["job"]["retry_of_job_id"] == job["job_id"]
    second = service.retry_job(
        job["job_id"],
        reason="synthetic manual retry",
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert second["replayed"] is True
    assert second["job"]["job_id"] == first["job"]["job_id"]
    assert first["job"]["status"] == JobStatus.SUCCEEDED.value
    # A successful job is not retryable at all.
    with pytest.raises(JobStateError):
        service.retry_job(
            first["job"]["job_id"],
            reason="synthetic successful retry",
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    # A failed job already at max_attempts is exhausted.
    exhausted, _ = repository.create_job(
        job_type="RETENTION_EVALUATION",
        trigger="MANUAL",
        dedup_key="foundation:retry-exhausted",
        requested_by="tester",
        requested_role="ADMIN",
        config_snapshot={"batch_limit": 1},
        max_attempts=1,
        now=datetime(2026, 11, 11, 12, 5, tzinfo=UTC),
    )
    repository.claim_job(
        exhausted["job_id"],
        lease_owner="tester",
        lease_seconds=60,
        now=datetime(2026, 11, 11, 12, 5, tzinfo=UTC),
    )
    repository.finish_job(
        exhausted["job_id"],
        lease_owner="tester",
        status=JobStatus.FAILED.value,
        error_code="SYNTHETIC",
        error_message="synthetic failure",
        now=datetime(2026, 11, 11, 12, 5, tzinfo=UTC),
    )
    with pytest.raises(RetryExhaustedError):
        service.retry_job(
            exhausted["job_id"],
            reason="synthetic exhausted retry",
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_cancel_pending_and_terminal_states(client: Any) -> None:
    service = client.app.state.governance_automation_service
    repository: GovernanceAutomationRepository = client.app.state.governance_automation_repository
    now = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
    job, _ = repository.create_job(
        job_type="RETENTION_EVALUATION",
        trigger="MANUAL",
        dedup_key="foundation:cancel-pending",
        requested_by="tester",
        requested_role="ADMIN",
        config_snapshot={"batch_limit": 1},
        now=now,
    )
    outcome = service.cancel_job(
        job["job_id"],
        reason="synthetic cancellation",
        actor_id="operator@example.com",
        actor_role="OPERATOR",
    )
    assert outcome["cancelled"] is True
    assert outcome["cancel_requested"] is True
    assert outcome["job"]["status"] == JobStatus.CANCELLED.value
    with pytest.raises(JobStateError):
        service.cancel_job(
            job["job_id"],
            reason="already cancelled",
            actor_id="operator@example.com",
            actor_role="OPERATOR",
        )


def test_health_check_is_honest_about_missing_integrity(client: Any) -> None:
    service = client.app.state.governance_automation_service
    result = service.run_now(
        job_type="GOVERNANCE_HEALTH_CHECK",
        idempotency_key="manual-health-1",
        reason="synthetic health check",
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert result["job"]["status"] == JobStatus.SUCCEEDED.value
    payload = result["job"]["result"]
    assert payload["integrity"]["status"] in {"OK", "NOT_PASS", "DISABLED", "UNAVAILABLE"}
    if payload["integrity"]["status"] != "OK":
        assert payload["overall_status"] != "OK"
    assert payload["governance"]["status"] in {"OK", "FAILED", "UNAVAILABLE"}


def test_slot_and_backoff_helpers_are_deterministic() -> None:
    moment = datetime(2026, 11, 11, 12, 34, 56, tzinfo=UTC)
    assert slot_start(moment, 60) == datetime(2026, 11, 11, 12, 0, tzinfo=UTC)
    first = schedule_slot_id("RETENTION_EVALUATION", 60, moment)
    second = schedule_slot_id("RETENTION_EVALUATION", 60, moment + timedelta(seconds=30))
    assert first == second
    assert re.fullmatch(r"RETENTION_EVALUATION:60:\d{8}T\d{6}Z", first)
    assert retry_delay_seconds("job-1", 2, base_seconds=10, max_seconds=900) == (
        retry_delay_seconds("job-1", 2, base_seconds=10, max_seconds=900)
    )
    assert retry_delay_seconds("job-1", 1, base_seconds=10, max_seconds=900) <= 12.0
    with pytest.raises(ValueError):
        validate_schedule_config("RETENTION_EVALUATION", {"unknown": 1})
