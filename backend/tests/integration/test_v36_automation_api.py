"""V36 governance automation API tests.

Synthetic local database only. These tests exercise RBAC, pagination, manual
run/retry/cancel, snapshot reads, reminder delivery-state reporting, and the
absence of destructive routes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient

from backend.app.alerting.repository import AlertRepository
from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.governance.automation.constants import (
    RETENTION_REVIEW_DUE_EVENT,
    JobStatus,
)
from backend.app.infrastructure.db import get_session_factory
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

NOW = datetime(2026, 11, 11, 12, 0, tzinfo=UTC)


def _clients(client: Any) -> dict[str, TestClient]:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, "operator-automation@example.com", role=Role.OPERATOR)
    create_test_user(repo, "viewer-automation@example.com", role=Role.VIEWER)
    out: dict[str, TestClient] = {"anon": TestClient(client.app)}
    for name, email in [
        ("admin", "admin@example.com"),
        ("operator", "operator-automation@example.com"),
        ("viewer", "viewer-automation@example.com"),
    ]:
        logged = TestClient(client.app)
        res = logged.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
        assert res.status_code == 200, (name, res.text)
        logged.headers["X-CSRF-Token"] = res.json()["csrf_token"]
        out[name] = logged
    return out


def _repository(client: Any) -> Any:
    return client.app.state.governance_automation_repository


def _create_job(client: Any, *, job_type: str, dedup_key: str) -> dict[str, Any]:
    job, created = _repository(client).create_job(
        job_type=job_type,
        trigger="MANUAL",
        dedup_key=dedup_key,
        requested_by="tester",
        requested_role="ADMIN",
        config_snapshot={},
        now=NOW,
    )
    assert created is True
    return job


def test_automation_read_endpoints_allow_all_roles(client: Any) -> None:
    parties = _clients(client)
    assert parties["anon"].get("/api/v1/governance/automation/status").status_code in {401, 403}
    for name in ("admin", "operator", "viewer"):
        for path in (
            "/api/v1/governance/automation/status",
            "/api/v1/governance/automation/health",
            "/api/v1/governance/automation/schedules",
            "/api/v1/governance/automation/jobs",
            "/api/v1/governance/automation/snapshots",
            "/api/v1/governance/automation/reminders",
        ):
            response = parties[name].get(path)
            assert response.status_code == 200, (name, path, response.text)
    status = parties["viewer"].get("/api/v1/governance/automation/status").json()
    assert status["enabled"] is False
    assert status["schedule_count"] == 7
    assert status["enabled_schedule_count"] == 0
    assert status["scheduler"]["state"] == "DISABLED"
    assert status["non_claims"]


def test_schedule_configuration_is_admin_only_and_versioned(client: Any) -> None:
    parties = _clients(client)
    payload = {
        "enabled": False,
        "interval_minutes": 60,
        "config": {"batch_limit": 10},
        "expected_version": 1,
        "reason": "synthetic API schedule update",
    }
    assert (
        parties["viewer"]
        .put("/api/v1/governance/automation/schedules/RETENTION_EVALUATION", json=payload)
        .status_code
        == 403
    )
    assert (
        parties["operator"]
        .put("/api/v1/governance/automation/schedules/RETENTION_EVALUATION", json=payload)
        .status_code
        == 403
    )
    updated = parties["admin"].put(
        "/api/v1/governance/automation/schedules/RETENTION_EVALUATION", json=payload
    )
    assert updated.status_code == 200, updated.text
    schedule = updated.json()["schedule"]
    assert schedule["config_version"] == 2
    assert schedule["interval_minutes"] == 60
    assert schedule["config"] == {"batch_limit": 10}
    stale = parties["admin"].put("/api/v1/governance/automation/schedules/RETENTION_EVALUATION", json=payload)
    assert stale.status_code == 409
    unknown = parties["admin"].put("/api/v1/governance/automation/schedules/NOT_A_JOB", json=payload)
    assert unknown.status_code == 404


def test_manual_run_is_operator_allowed_and_idempotent(client: Any) -> None:
    parties = _clients(client)
    payload = {
        "job_type": "RETENTION_EVALUATION",
        "idempotency_key": "api-retention-run-1",
        "reason": "synthetic API manual retention run",
    }
    assert parties["viewer"].post("/api/v1/governance/automation/jobs/run", json=payload).status_code == 403
    first = parties["operator"].post("/api/v1/governance/automation/jobs/run", json=payload)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["replayed"] is False
    assert body["executed"] is True
    assert body["job"]["status"] == JobStatus.SUCCEEDED.value
    second = parties["operator"].post("/api/v1/governance/automation/jobs/run", json=payload)
    assert second.status_code == 200
    assert second.json()["replayed"] is True
    assert second.json()["job"]["job_id"] == body["job"]["job_id"]
    unknown = parties["operator"].post(
        "/api/v1/governance/automation/jobs/run",
        json={**payload, "job_type": "NOT_A_JOB", "idempotency_key": "unknown-1"},
    )
    assert unknown.status_code == 422


def test_retry_and_cancel_rbac_and_lifecycle(client: Any) -> None:
    parties = _clients(client)
    repository = _repository(client)

    failed = _create_job(client, job_type="RETENTION_EVALUATION", dedup_key="api:failed:1")
    repository.claim_job(failed["job_id"], lease_owner="tester", lease_seconds=60, now=NOW)
    repository.finish_job(
        failed["job_id"],
        lease_owner="tester",
        status=JobStatus.FAILED.value,
        error_code="SYNTHETIC",
        error_message="synthetic failure",
        now=NOW,
    )
    retry_payload = {"reason": "synthetic API retry"}
    assert (
        parties["viewer"]
        .post(
            f"/api/v1/governance/automation/jobs/{failed['job_id']}/retry",
            json=retry_payload,
        )
        .status_code
        == 403
    )
    retried = parties["operator"].post(
        f"/api/v1/governance/automation/jobs/{failed['job_id']}/retry",
        json=retry_payload,
    )
    assert retried.status_code == 200, retried.text
    assert retried.json()["job"]["attempt"] == 2
    assert retried.json()["job"]["retry_of_job_id"] == failed["job_id"]

    pending = _create_job(client, job_type="GOVERNANCE_HEALTH_CHECK", dedup_key="api:pending:1")
    assert (
        parties["viewer"]
        .post(
            f"/api/v1/governance/automation/jobs/{pending['job_id']}/cancel",
            json={"reason": "synthetic cancellation"},
        )
        .status_code
        == 403
    )
    cancelled = parties["operator"].post(
        f"/api/v1/governance/automation/jobs/{pending['job_id']}/cancel",
        json={"reason": "synthetic cancellation"},
    )
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["cancelled"] is True
    assert cancelled.json()["job"]["status"] == JobStatus.CANCELLED.value
    again = parties["operator"].post(
        f"/api/v1/governance/automation/jobs/{pending['job_id']}/cancel",
        json={"reason": "already cancelled"},
    )
    assert again.status_code == 409


def test_job_pagination_and_no_delete_routes(client: Any) -> None:
    parties = _clients(client)
    for index in range(3):
        _create_job(
            client,
            job_type="GOVERNANCE_HEALTH_CHECK",
            dedup_key=f"api:pagination:{index}",
        )
    page = parties["viewer"].get("/api/v1/governance/automation/jobs", params={"page": 1, "page_size": 2})
    assert page.status_code == 200
    body = page.json()
    assert len(body["items"]) == 2
    assert body["total"] >= 3
    assert body["page"] == 1
    assert body["page_size"] == 2
    second = parties["viewer"].get("/api/v1/governance/automation/jobs", params={"page": 2, "page_size": 2})
    assert second.status_code == 200
    assert len(second.json()["items"]) >= 1
    filtered = parties["viewer"].get(
        "/api/v1/governance/automation/jobs",
        params={"job_type": "GOVERNANCE_HEALTH_CHECK", "status": "PENDING"},
    )
    assert filtered.status_code == 200
    assert all(
        item["job_type"] == "GOVERNANCE_HEALTH_CHECK" and item["status"] == "PENDING"
        for item in filtered.json()["items"]
    )
    job_id = body["items"][0]["job_id"]
    assert parties["admin"].delete(f"/api/v1/governance/automation/jobs/{job_id}").status_code == 405
    assert (
        parties["admin"].delete("/api/v1/governance/automation/schedules/GOVERNANCE_HEALTH_CHECK").status_code
        == 405
    )
    assert parties["admin"].delete("/api/v1/governance/automation/snapshots/any").status_code == 405


def test_snapshot_generation_read_and_csv(client: Any) -> None:
    parties = _clients(client)
    payload = {
        "idempotency_key": "api-snapshot-1",
        "reason": "synthetic API snapshot generation",
    }
    assert parties["viewer"].post("/api/v1/governance/automation/snapshots", json=payload).status_code == 403
    generated = parties["operator"].post("/api/v1/governance/automation/snapshots", json=payload)
    assert generated.status_code == 200, generated.text
    body = generated.json()
    assert body["replayed"] is False
    snapshot = body["snapshot"]
    assert len(snapshot["payload_digest"]) == 64
    assert snapshot["digest_valid"] is True
    assert snapshot["snapshot_type"] == "COMPLIANCE_SUMMARY"

    replay = parties["operator"].post("/api/v1/governance/automation/snapshots", json=payload)
    assert replay.status_code == 200
    assert replay.json()["replayed"] is True
    assert replay.json()["snapshot"]["snapshot_id"] == snapshot["snapshot_id"]

    listing = parties["viewer"].get("/api/v1/governance/automation/snapshots")
    assert listing.status_code == 200
    assert listing.json()["total"] == 1
    detail = parties["viewer"].get(f"/api/v1/governance/automation/snapshots/{snapshot['snapshot_id']}")
    assert detail.status_code == 200
    assert detail.json()["snapshot"]["digest_valid"] is True
    csv_response = parties["viewer"].get(
        f"/api/v1/governance/automation/snapshots/{snapshot['snapshot_id']}/csv"
    )
    assert csv_response.status_code == 200
    assert csv_response.headers["content-type"].startswith("text/csv")
    assert csv_response.text.startswith("section,metric,value")
    assert "regulatory_certification_claimed,false" in csv_response.text
    assert (
        parties["viewer"].get("/api/v1/governance/automation/snapshots/missing-snapshot").status_code == 404
    )


def test_reminder_activity_reports_pending_and_delivered_states(client: Any) -> None:
    parties = _clients(client)
    notifier = client.app.state.governance_notifier
    assert notifier is not None
    notifier._enabled = True
    notifier._cooldown_seconds = 0
    rule = parties["admin"].post(
        "/api/v1/alerting/rules",
        json={
            "name": "Synthetic V36 reminder rule",
            "domains": ["GOVERNANCE"],
            "event_types": [RETENTION_REVIEW_DUE_EVENT],
            "channels": ["in_app"],
            "cooldown_seconds": 0,
        },
    )
    assert rule.status_code == 201, rule.text
    stats = notifier.notify_event(
        event_type=RETENTION_REVIEW_DUE_EVENT,
        case={"case_id": "case-reminder", "case_number": "CASE-R", "version": 1},
        target_type="RETENTION_EVALUATION",
        target_id="eval-reminder",
        severity="HIGH",
        detail="Synthetic reminder for API state testing.",
        dedup_version="20261111T120000Z",
    )
    assert stats["queued"] == 1
    pending = parties["viewer"].get("/api/v1/governance/automation/reminders")
    assert pending.status_code == 200
    pending_body = pending.json()
    assert pending_body["total"] == 1
    assert pending_body["delivery_claimed"] is False
    assert pending_body["delivery_states"]["PENDING"] == 1
    assert pending_body["items"][0]["delivery_state"] == "PENDING"
    assert pending_body["items"][0]["reminder_window"] == "20261111T120000Z"

    alert_repository = AlertRepository(get_session_factory(str(client.app.state.settings.database_url)))
    deliveries, _ = alert_repository.list_deliveries(status="pending", page=1, page_size=10)
    assert len(deliveries) == 1
    alert_repository.mark_delivery(deliveries[0].id, status="sent", delivered=True)
    delivered = parties["viewer"].get("/api/v1/governance/automation/reminders")
    assert delivered.status_code == 200
    assert delivered.json()["delivery_states"]["DELIVERED"] == 1
    assert delivered.json()["items"][0]["delivery_state"] == "DELIVERED"
    assert delivered.json()["items"][0]["delivery_claimed"] is False
    filtered = parties["viewer"].get(
        "/api/v1/governance/automation/reminders",
        params={"event_type": RETENTION_REVIEW_DUE_EVENT},
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1
