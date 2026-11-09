"""V35 governance API integration tests.

All fixtures are synthetic. These tests never touch protected V29-V34 evidence
files; they only create local forensic cases and governance records in the
temporary application database.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import update

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.infrastructure.db import get_session_factory
from backend.app.integrity.constants import (
    AuditStatus,
    AuditTrigger,
    IntegrityScope,
    Severity,
)
from backend.app.integrity.models import AuditRun, Finding, utc_now_iso
from backend.app.models.forensic_orm import ForensicCaseORM
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user


def _clients(client: Any) -> dict[str, TestClient]:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, "operator-governance@example.com", role=Role.OPERATOR)
    create_test_user(repo, "viewer-governance@example.com", role=Role.VIEWER)
    out: dict[str, TestClient] = {"anon": TestClient(client.app)}
    for name, email in [
        ("admin", "admin@example.com"),
        ("operator", "operator-governance@example.com"),
        ("viewer", "viewer-governance@example.com"),
    ]:
        logged = TestClient(client.app)
        res = logged.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
        assert res.status_code == 200, (name, res.text)
        logged.headers["X-CSRF-Token"] = res.json()["csrf_token"]
        out[name] = logged
    return out


def _seed_finding(client: Any, *, finding_id: str = "finding-v35-1") -> Finding:
    store = client.app.state.integrity_store
    assert store is not None
    now = utc_now_iso()
    run_id = f"run-{finding_id}"
    run = AuditRun(
        audit_run_id=run_id,
        trigger=AuditTrigger.MANUAL,
        requested_scopes=[IntegrityScope.EVIDENCE],
        completed_scopes=[IntegrityScope.EVIDENCE],
        status=AuditStatus.FAIL,
        started_at=now,
        created_at=now,
        completed_at=now,
    )
    assert store.create_run(run)
    finding = Finding.create(
        audit_run_id=run_id,
        scope=IntegrityScope.EVIDENCE,
        reason_code="EVIDENCE_HASH_MISMATCH",
        artifact_id=finding_id,
        explanation="synthetic V35 governance fixture",
        severity=Severity.HIGH,
    )
    inserted, truncated = store.add_findings([finding])
    assert inserted == 1 and truncated is False
    return finding


def _create_case(client: TestClient, *, finding: Finding | None = None) -> dict[str, Any]:
    references = []
    if finding is not None:
        references.append(
            {
                "artifact_type": "V33_FINDING",
                "artifact_id": finding.finding_id,
            }
        )
    response = client.post(
        "/api/v1/forensics/cases",
        json={
            "title": "Synthetic governance review",
            "description": "Synthetic V35 fixture; no real evidence.",
            "case_type": "FORENSIC_REVIEW",
            "severity": "HIGH",
            "evidence_references": references,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _mark_case_closed(client: Any, case_id: str) -> None:
    session_factory = get_session_factory(str(client.app.state.settings.database_url))
    with session_factory() as session:
        session.execute(
            update(ForensicCaseORM)
            .where(ForensicCaseORM.id == case_id)
            .values(status="CLOSED", resolution_summary="Synthetic test closure.")
        )
        session.commit()


def _configure_default_policy(admin: TestClient) -> None:
    response = admin.patch(
        "/api/v1/governance/policies/POL-DEFAULT",
        json={
            "name": "Default governance policy",
            "retention_days": 30,
            "review_interval_days": 10,
            "reason": "Synthetic test configuration.",
        },
    )
    assert response.status_code == 200, response.text


def _future_clock(client: Any, days: int = 60) -> None:
    service = client.app.state.governance_service
    assert service is not None
    service._clock = lambda: datetime.now(UTC) + timedelta(days=days)


def test_governance_status_and_policy_rbac(client: Any) -> None:
    parties = _clients(client)
    for path in ("/api/v1/governance/status", "/api/v1/governance/policies"):
        assert parties["anon"].get(path).status_code == 401, path
        for name in ("admin", "operator", "viewer"):
            response = parties[name].get(path)
            assert response.status_code == 200, (name, path, response.text)

    status = parties["viewer"].get("/api/v1/governance/status").json()
    assert status["enabled"] is True
    assert status["retention_scheduler"] == "DISABLED"
    assert status["automatic_deletion"] is False
    assert status["automatic_hold_release"] is False
    assert status["automatic_disposition_approval"] is False
    assert status["regulatory_certification_claimed"] is False
    assert status["external_immutable_storage_claimed"] is False
    assert status["external_anchor_claimed"] is False
    assert status["audit_integrity"]["assurance"] == "LOCAL_SELF_DIGEST_ONLY"

    policies = parties["viewer"].get("/api/v1/governance/policies").json()
    default = next(item for item in policies["items"] if item["policy_id"] == "POL-DEFAULT")
    assert default["state"] == "ENABLED"
    assert default["retention_days"] is None
    assert default["review_interval_days"] is None
    assert default["export_requires_approval"] is True
    assert default["allow_evidence_bytes"] is False

    payload = {
        "name": "Synthetic retention policy",
        "state": "ENABLED",
        "case_type": "FORENSIC_REVIEW",
        "retention_days": 30,
        "review_interval_days": 10,
        "reason": "Synthetic policy creation.",
    }
    assert parties["viewer"].post("/api/v1/governance/policies", json=payload).status_code == 403
    assert parties["operator"].post("/api/v1/governance/policies", json=payload).status_code == 403
    created = parties["admin"].post("/api/v1/governance/policies", json=payload)
    assert created.status_code == 201, created.text
    policy_id = created.json()["policy"]["policy_id"]
    assert created.json()["policy"]["version"] == 1

    updated = parties["admin"].patch(
        f"/api/v1/governance/policies/{policy_id}",
        json={"retention_days": 45, "reason": "Synthetic policy update."},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["policy"]["version"] == 2
    assert updated.json()["policy"]["retention_days"] == 45

    versions = parties["viewer"].get(f"/api/v1/governance/policies/{policy_id}/versions").json()
    assert [item["version"] for item in versions["items"]] == [2, 1]

    disabled = parties["admin"].post(
        "/api/v1/governance/policies/POL-DEFAULT/state",
        json={"state": "DISABLED", "reason": "must be rejected"},
    )
    assert disabled.status_code == 422, disabled.text


def test_retention_evaluation_is_idempotent_and_non_destructive(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    finding = _seed_finding(client)
    case = _create_case(operator, finding=finding)
    case_id = case["case_id"]
    _configure_default_policy(admin)
    _future_clock(client)

    first = operator.post("/api/v1/governance/retention/evaluate", json={"case_id": case_id})
    assert first.status_code == 200, first.text
    evaluation = first.json()["evaluation"]
    assert evaluation["policy_id"] == "POL-DEFAULT"
    assert evaluation["policy_version"] == 2
    assert evaluation["retention_deadline"] is not None
    assert evaluation["deletion_authorized"] is False
    assert first.json()["replayed"] is False

    second = operator.post("/api/v1/governance/retention/evaluate", json={"case_id": case_id})
    assert second.status_code == 200, second.text
    assert second.json()["replayed"] is True
    assert second.json()["evaluation"]["evaluation_id"] == evaluation["evaluation_id"]

    queue = parties["viewer"].get("/api/v1/governance/retention/queue").json()
    assert queue["total"] >= 1
    row = next(item for item in queue["items"] if item["case_id"] == case_id)
    assert row["deletion_authorized"] is False
    assert row["governance_state"] in {
        "ACTIVE",
        "REVIEW_DUE",
        "LEGAL_HOLD",
        "DISPOSITION_REVIEW_REQUIRED",
        "DISPOSITION_APPROVED",
        "DISPOSITION_BLOCKED",
    }

    case_state = parties["viewer"].get(f"/api/v1/governance/retention/cases/{case_id}").json()
    assert case_state["evaluation"]["evaluation_id"] == evaluation["evaluation_id"]

    assert (
        operator.post(
            "/api/v1/governance/retention/evaluate",
            json={"case_ids": [case_id] * 1},
        ).status_code
        == 200
    )
    assert operator.post("/api/v1/governance/retention/evaluate", json={}).status_code == 422


def test_legal_hold_lifecycle_separation_and_overlap(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    viewer = parties["viewer"]
    case = _create_case(operator)
    case_id = case["case_id"]

    assert (
        viewer.post(
            "/api/v1/governance/holds",
            json={"case_id": case_id, "reason": "viewer cannot request"},
        ).status_code
        == 403
    )
    first = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_id, "scope": "case", "reason": "Synthetic hold one."},
    )
    assert first.status_code == 201, first.text
    hold_one = first.json()["hold"]
    assert hold_one["status"] == "PENDING_APPROVAL"

    replay = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_id, "scope": "case", "reason": "Synthetic hold one."},
    )
    assert replay.status_code == 201
    assert replay.json()["hold"]["hold_id"] != hold_one["hold_id"]

    own = operator.post(
        f"/api/v1/governance/holds/{hold_one['hold_id']}/approve",
        json={"reason": "operator self approval"},
    )
    assert own.status_code == 403, own.text

    approved = admin.post(
        f"/api/v1/governance/holds/{hold_one['hold_id']}/approve",
        json={"reason": "Synthetic approval."},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["hold"]["status"] == "ACTIVE"
    assert approved.json()["hold"]["approved_by"] == "admin@example.com"

    second = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_id, "scope": "evidence", "reason": "Synthetic hold two."},
    )
    assert second.status_code == 201, second.text
    hold_two = second.json()["hold"]
    assert hold_two["status"] == "PENDING_APPROVAL"

    export = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": "hold must block export"},
    )
    assert export.status_code == 409, export.text
    assert "LEGAL_HOLD" in export.text

    released = admin.post(
        f"/api/v1/governance/holds/{hold_one['hold_id']}/release",
        json={"reason": "Synthetic release one."},
    )
    assert released.status_code == 200, released.text
    assert released.json()["hold"]["status"] == "RELEASED"

    still_blocked = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": "second hold must still block"},
    )
    assert still_blocked.status_code == 409, still_blocked.text

    holds = viewer.get(f"/api/v1/governance/holds?case_id={case_id}").json()
    assert holds["total"] == 3
    statuses = {item["hold_id"]: item["status"] for item in holds["items"]}
    assert statuses[hold_one["hold_id"]] == "RELEASED"
    assert statuses[replay.json()["hold"]["hold_id"]] == "PENDING_APPROVAL"
    assert statuses[hold_two["hold_id"]] == "PENDING_APPROVAL"

    rejected = admin.post(
        f"/api/v1/governance/holds/{hold_two['hold_id']}/reject",
        json={"reason": "Synthetic rejection."},
    )
    assert rejected.status_code == 200, rejected.text
    assert rejected.json()["hold"]["status"] == "REJECTED"

    history = viewer.get(f"/api/v1/governance/holds/{hold_one['hold_id']}").json()
    assert [event["event_type"] for event in history["events"]] == [
        "CREATED",
        "LEGAL_HOLD_APPROVED",
        "LEGAL_HOLD_RELEASED",
    ]


def test_disposition_requires_review_and_separation_of_duties(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    viewer = parties["viewer"]
    finding = _seed_finding(client, finding_id="finding-v35-disposition")
    case = _create_case(operator, finding=finding)
    case_id = case["case_id"]
    _configure_default_policy(admin)
    _future_clock(client)

    verify = operator.post(f"/api/v1/forensics/cases/{case_id}/verify")
    assert verify.status_code == 200, verify.text
    assert verify.json()["custody"]["outcome"] == "PASS", verify.text
    _mark_case_closed(client, case_id)

    blocked_hold = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_id, "reason": "Synthetic pending hold."},
    )
    assert blocked_hold.status_code == 201, blocked_hold.text
    blocked = operator.post(
        "/api/v1/governance/dispositions",
        json={"case_id": case_id, "justification": "Hold must block this."},
    )
    assert blocked.status_code == 409, blocked.text
    assert "LEGAL_HOLD_PENDING_APPROVAL" in blocked.text

    hold_id = blocked_hold.json()["hold"]["hold_id"]
    assert (
        admin.post(
            f"/api/v1/governance/holds/{hold_id}/reject",
            json={"reason": "Synthetic rejection."},
        ).status_code
        == 200
    )

    request = operator.post(
        "/api/v1/governance/dispositions",
        json={"case_id": case_id, "justification": "Synthetic disposition review."},
    )
    assert request.status_code == 201, request.text
    disposition_id = request.json()["disposition"]["disposition_id"]
    assert request.json()["disposition"]["status"] == "REVIEW_REQUIRED"
    assert request.json()["disposition_approval_note"].startswith("Approval authorizes only")

    assert (
        viewer.post(
            f"/api/v1/governance/dispositions/{disposition_id}/decide",
            json={"decision": "APPROVE", "reason": "viewer attempt"},
        ).status_code
        == 403
    )
    own = operator.post(
        f"/api/v1/governance/dispositions/{disposition_id}/decide",
        json={"decision": "APPROVE", "reason": "operator attempt"},
    )
    assert own.status_code == 403, own.text

    approved = admin.post(
        f"/api/v1/governance/dispositions/{disposition_id}/decide",
        json={"decision": "APPROVE", "reason": "Synthetic approval."},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["disposition"]["status"] == "APPROVED"
    assert approved.json()["physical_deletion_performed"] is False

    duplicate = admin.post(
        f"/api/v1/governance/dispositions/{disposition_id}/decide",
        json={"decision": "APPROVE", "reason": "duplicate approval"},
    )
    assert duplicate.status_code == 409, duplicate.text

    listing = viewer.get(f"/api/v1/governance/dispositions?case_id={case_id}").json()
    assert listing["total"] == 1
    assert listing["items"][0]["status"] == "APPROVED"


def test_export_approval_generation_verification_and_audit(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    viewer = parties["viewer"]
    finding = _seed_finding(client, finding_id="finding-v35-export")
    case = _create_case(operator, finding=finding)
    case_id = case["case_id"]
    verify = operator.post(f"/api/v1/forensics/cases/{case_id}/verify")
    assert verify.status_code == 200, verify.text

    assert (
        viewer.post(
            "/api/v1/governance/exports",
            json={"case_id": case_id, "reason": "viewer cannot request"},
        ).status_code
        == 403
    )
    requested = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": "Synthetic export request."},
    )
    assert requested.status_code == 201, requested.text
    approval_id = requested.json()["approval"]["approval_id"]
    assert requested.json()["approval"]["status"] == "PENDING_APPROVAL"
    assert requested.json()["delivery_claimed"] is False

    own = operator.post(
        f"/api/v1/governance/exports/{approval_id}/approve",
        json={"reason": "operator self approval"},
    )
    assert own.status_code == 403, own.text

    approved = admin.post(
        f"/api/v1/governance/exports/{approval_id}/approve",
        json={"reason": "Synthetic export approval."},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["approval"]["status"] == "APPROVED"

    generated = admin.post(f"/api/v1/governance/exports/{approval_id}/generate")
    assert generated.status_code == 200, generated.text
    assert generated.json()["approval"]["status"] == "GENERATED"
    assert generated.json()["delivery_claimed"] is False
    export_id = generated.json()["approval"]["export_id"]
    assert export_id

    verified = admin.post(f"/api/v1/governance/exports/{approval_id}/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["approval"]["status"] == "VERIFIED"
    assert verified.json()["verification"]["outcome"] == "PASS"

    download = admin.get(f"/api/v1/governance/exports/{approval_id}/download")
    assert download.status_code == 200
    assert download.headers["cache-control"] == "no-store"

    withdraw = admin.post(
        f"/api/v1/governance/exports/{approval_id}/withdraw",
        json={"reason": "generated exports cannot be withdrawn"},
    )
    assert withdraw.status_code == 409, withdraw.text

    audit = admin.get("/api/v1/governance/audit?event_type=EXPORT_GENERATED").json()
    assert audit["total"] >= 1
    assert audit["assurance"] == "LOCAL_SELF_DIGEST_ONLY"
    assert all(item["event_hash"] for item in audit["items"])
    event = admin.get(f"/api/v1/governance/audit/{audit['items'][0]['event_id']}").json()
    assert event["digest_valid"] is True

    assert viewer.get("/api/v1/governance/audit").status_code == 403
    assert operator.get("/api/v1/governance/audit").status_code == 403

    report = viewer.get("/api/v1/governance/reports/compliance").json()
    assert report["scope"] == "SUMMARY"
    assert report["regulatory_certification_claimed"] is False
    assert report["external_immutable_storage_claimed"] is False
    assert report["automatic_deletion"] is False
    assert report["sections"]["exports"]["delivery_claimed"] is False
    assert report["overall_status"] in {"NO_KNOWN_GAPS", "REVIEW_REQUIRED"}

    assert (
        viewer.get(
            "/api/v1/governance/reports/compliance",
            params={"scope": "DETAIL", "case_id": case_id},
        ).status_code
        == 403
    )
    detail = admin.get(
        "/api/v1/governance/reports/compliance",
        params={"scope": "DETAIL", "case_id": case_id},
    )
    assert detail.status_code == 200, detail.text
    assert detail.json()["detail"][0]["deletion_authorized"] is False

    csv = admin.get("/api/v1/governance/reports/compliance.csv")
    assert csv.status_code == 200
    assert csv.headers["content-type"].startswith("text/csv")
    assert "regulatory_certification_claimed,false" in csv.text
