"""V35 governance security, idempotency, and retention hardening tests.

All fixtures are synthetic. These tests never touch protected V29-V34 evidence
files; they create local forensic cases and governance records in the temporary
application database and never request evidence-byte export.
"""

from __future__ import annotations

import hashlib
import json
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
from backend.app.models.forensic_orm import ForensicCaseORM, ForensicCustodyEventORM
from backend.app.models.governance_orm import GovernanceAccessAuditORM
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

_SECRET = "ghp_" + "A" * 36


def _clients(client: Any) -> dict[str, TestClient]:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, "operator-governance-hardening@example.com", role=Role.OPERATOR)
    create_test_user(repo, "viewer-governance-hardening@example.com", role=Role.VIEWER)
    out: dict[str, TestClient] = {"anon": TestClient(client.app)}
    for name, email in [
        ("admin", "admin@example.com"),
        ("operator", "operator-governance-hardening@example.com"),
        ("viewer", "viewer-governance-hardening@example.com"),
    ]:
        logged = TestClient(client.app)
        res = logged.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
        assert res.status_code == 200, (name, res.text)
        logged.headers["X-CSRF-Token"] = res.json()["csrf_token"]
        out[name] = logged
    return out


def _call(party: TestClient, method: str, path: str, payload: dict[str, Any] | None) -> Any:
    if payload is None:
        return getattr(party, method)(path)
    return getattr(party, method)(path, json=payload)


def _seed_finding(client: Any, *, finding_id: str) -> Finding:
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
        explanation="synthetic V35 hardening fixture",
        severity=Severity.HIGH,
    )
    inserted, truncated = store.add_findings([finding])
    assert inserted == 1 and truncated is False
    return finding


def _create_case(client: TestClient, *, finding: Finding | None = None) -> dict[str, Any]:
    references = []
    if finding is not None:
        references.append({"artifact_type": "V33_FINDING", "artifact_id": finding.finding_id})
    response = client.post(
        "/api/v1/forensics/cases",
        json={
            "title": "Synthetic governance hardening",
            "description": "Synthetic V35 hardening fixture; no real evidence.",
            "case_type": "FORENSIC_REVIEW",
            "severity": "HIGH",
            "evidence_references": references,
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _mark_case_closed(client: Any, case_id: str) -> None:
    factory = get_session_factory(str(client.app.state.settings.database_url))
    with factory() as session:
        session.execute(
            update(ForensicCaseORM)
            .where(ForensicCaseORM.id == case_id)
            .values(status="CLOSED", resolution_summary="Synthetic hardening closure.")
        )
        session.commit()


def _configure_default_policy(admin: TestClient, **overrides: Any) -> None:
    payload: dict[str, Any] = {
        "name": "Default governance policy",
        "retention_days": 30,
        "review_interval_days": 10,
        "reason": "Synthetic hardening configuration.",
    }
    payload.update(overrides)
    response = admin.patch("/api/v1/governance/policies/POL-DEFAULT", json=payload)
    assert response.status_code == 200, response.text


def _future_clock(client: Any, days: int = 60) -> None:
    service = client.app.state.governance_service
    assert service is not None
    service._clock = lambda: datetime.now(UTC) + timedelta(days=days)


def _eligible_case(client: Any, admin: TestClient, operator: TestClient, *, finding_id: str) -> str:
    finding = _seed_finding(client, finding_id=finding_id)
    case = _create_case(operator, finding=finding)
    case_id = case["case_id"]
    verify = operator.post(f"/api/v1/forensics/cases/{case_id}/verify")
    assert verify.status_code == 200, verify.text
    assert verify.json()["custody"]["outcome"] == "PASS", verify.text
    _mark_case_closed(client, case_id)
    _configure_default_policy(admin)
    _future_clock(client)
    return case_id


def _request_disposition(operator: TestClient, case_id: str, **extra: Any) -> dict[str, Any]:
    payload = {
        "case_id": case_id,
        "justification": "Synthetic hardening disposition review.",
        **extra,
    }
    response = operator.post("/api/v1/governance/dispositions", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


# ---------------------------------------------------------------------------
# Route surface and RBAC
# ---------------------------------------------------------------------------
def test_governance_route_surface_has_no_delete_and_rbac_is_least_privilege(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    viewer = parties["viewer"]
    anon = parties["anon"]

    # No governance route accepts DELETE, and the OpenAPI document agrees.
    for route in client.app.routes:
        path = str(getattr(route, "path", ""))
        methods = set(getattr(route, "methods", set()) or set())
        if path.startswith("/api/v1/governance"):
            assert "DELETE" not in methods, (path, methods)
    schema = admin.get("/openapi.json").json()
    governance_paths = {
        path: ops for path, ops in schema["paths"].items() if path.startswith("/api/v1/governance")
    }
    assert governance_paths
    for path, operations in governance_paths.items():
        assert "delete" not in operations, path

    for path in (
        "/api/v1/governance/status",
        "/api/v1/governance/policies",
        "/api/v1/governance/holds",
        "/api/v1/governance/dispositions",
        "/api/v1/governance/exports",
        "/api/v1/governance/audit",
        "/api/v1/governance/reports/compliance",
    ):
        assert anon.get(path).status_code == 401, path

    case_id = _eligible_case(client, admin, operator, finding_id="finding-hardening-rbac")

    viewer_forbidden = [
        ("post", "/api/v1/governance/policies", {"name": "x", "reason": "x"}),
        ("patch", "/api/v1/governance/policies/POL-DEFAULT", {"reason": "x"}),
        ("post", "/api/v1/governance/retention/evaluate", {"case_id": case_id}),
        ("post", "/api/v1/governance/holds", {"case_id": case_id, "reason": "x"}),
        ("post", "/api/v1/governance/holds/unknown/approve", {"reason": "x"}),
        ("post", "/api/v1/governance/dispositions", {"case_id": case_id, "justification": "x"}),
        ("post", "/api/v1/governance/dispositions/unknown/decide", {"decision": "APPROVE", "reason": "x"}),
        ("post", "/api/v1/governance/exports", {"case_id": case_id, "reason": "x"}),
        ("post", "/api/v1/governance/exports/unknown/approve", {"reason": "x"}),
        ("post", "/api/v1/governance/exports/unknown/generate", {}),
        ("get", "/api/v1/governance/audit", None),
        ("get", f"/api/v1/governance/reports/compliance?scope=DETAIL&case_id={case_id}", None),
        ("get", f"/api/v1/governance/reports/compliance.csv?scope=DETAIL&case_id={case_id}", None),
    ]
    for method, path, payload in viewer_forbidden:
        response = _call(viewer, method, path, payload)
        assert response.status_code == 403, (method, path, response.status_code, response.text)

    operator_forbidden = [
        ("post", "/api/v1/governance/policies", {"name": "x", "reason": "x"}),
        ("patch", "/api/v1/governance/policies/POL-DEFAULT", {"reason": "x"}),
        ("post", "/api/v1/governance/holds/unknown/approve", {"reason": "x"}),
        ("post", "/api/v1/governance/holds/unknown/release", {"reason": "x"}),
        ("post", "/api/v1/governance/dispositions/unknown/decide", {"decision": "APPROVE", "reason": "x"}),
        ("post", "/api/v1/governance/exports/unknown/approve", {"reason": "x"}),
        ("post", "/api/v1/governance/exports/unknown/generate", {}),
        ("get", "/api/v1/governance/audit", None),
        ("get", f"/api/v1/governance/reports/compliance?scope=DETAIL&case_id={case_id}", None),
    ]
    for method, path, payload in operator_forbidden:
        response = _call(operator, method, path, payload)
        assert response.status_code == 403, (method, path, response.status_code, response.text)

    # Operator holds the request/evaluate capabilities but not approval/review.
    assert (
        operator.post("/api/v1/governance/retention/evaluate", json={"case_id": case_id}).status_code == 200
    )
    hold = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_id, "reason": "Synthetic hardening hold."},
    )
    assert hold.status_code == 201, hold.text
    hold_id = hold.json()["hold"]["hold_id"]
    assert (
        admin.post(
            f"/api/v1/governance/holds/{hold_id}/reject",
            json={"reason": "Synthetic hardening rejection."},
        ).status_code
        == 200
    )
    disposition = _request_disposition(operator, case_id)
    assert disposition["disposition"]["status"] == "REVIEW_REQUIRED"
    assert (
        operator.post(
            "/api/v1/governance/exports",
            json={"case_id": case_id, "reason": "Synthetic hardening export request."},
        ).status_code
        == 201
    )

    # ADMIN-only read surfaces remain available to ADMIN.
    assert admin.get("/api/v1/governance/audit").status_code == 200
    detail = admin.get(
        "/api/v1/governance/reports/compliance",
        params={"scope": "DETAIL", "case_id": case_id},
    )
    assert detail.status_code == 200, detail.text
    csv = admin.get("/api/v1/governance/reports/compliance.csv")
    assert csv.status_code == 200
    assert "regulatory_certification_claimed,false" in csv.text

    # No DELETE route: the method is rejected before any service is reached.
    assert admin.delete("/api/v1/governance/status").status_code == 405


def test_governance_validation_not_found_and_cross_case_isolation(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_a = _eligible_case(client, admin, operator, finding_id="finding-hardening-case-a")
    case_b = _create_case(operator)["case_id"]

    # Evidence references cannot be borrowed from another case.
    reference = operator.post(
        f"/api/v1/forensics/cases/{case_a}/evidence",
        json={
            "artifact_type": "EVIDENCE_FILE",
            "artifact_id": "artifact.bin",
            "original_relative_path": "evidence/artifact.bin",
            "expected_sha256": "a" * 64,
        },
    )
    assert reference.status_code == 201, reference.text
    reference_id = reference.json()["reference_id"]
    borrowed = operator.post(
        "/api/v1/governance/holds",
        json={
            "case_id": case_b,
            "evidence_reference_id": reference_id,
            "reason": "cross-case evidence reference",
        },
    )
    assert borrowed.status_code == 422, borrowed.text

    # Unknown identifiers map to 404 rather than 422/500.
    assert admin.get("/api/v1/governance/policies/POL-NOPE").status_code == 404
    assert admin.patch("/api/v1/governance/policies/POL-NOPE", json={"reason": "missing"}).status_code == 404
    assert admin.get("/api/v1/governance/holds/HOLD-NOPE").status_code == 404
    assert (
        admin.post("/api/v1/governance/holds/HOLD-NOPE/approve", json={"reason": "missing"}).status_code
        == 404
    )
    assert admin.get("/api/v1/governance/dispositions/DISP-NOPE").status_code == 404
    assert (
        admin.post(
            "/api/v1/governance/dispositions/DISP-NOPE/decide",
            json={"decision": "APPROVE", "reason": "missing"},
        ).status_code
        == 404
    )
    assert admin.get("/api/v1/governance/exports/EXP-NOPE").status_code == 404
    assert (
        admin.post("/api/v1/governance/exports/EXP-NOPE/approve", json={"reason": "missing"}).status_code
        == 404
    )
    assert admin.get("/api/v1/governance/audit/AUD-NOPE").status_code == 404
    assert admin.get("/api/v1/governance/retention/cases/CASE-NOPE").status_code == 404
    assert (
        operator.post("/api/v1/governance/retention/evaluate", json={"case_id": "CASE-NOPE"}).status_code
        == 404
    )
    assert (
        operator.post(
            "/api/v1/governance/dispositions",
            json={"case_id": "CASE-NOPE", "justification": "missing"},
        ).status_code
        == 404
    )
    assert (
        operator.post(
            "/api/v1/governance/exports",
            json={"case_id": "CASE-NOPE", "reason": "missing"},
        ).status_code
        == 404
    )
    assert (
        admin.get(
            "/api/v1/governance/reports/compliance",
            params={"scope": "DETAIL", "case_id": "CASE-NOPE"},
        ).status_code
        == 404
    )

    # Pagination and payload validation.
    assert admin.get("/api/v1/governance/policies", params={"page_size": 101}).status_code == 422
    assert admin.get("/api/v1/governance/holds", params={"page_size": 0}).status_code == 422
    assert admin.get("/api/v1/governance/audit", params={"page_size": 201}).status_code == 422
    assert (
        admin.post(
            "/api/v1/governance/policies", json={"name": "x", "state": "BOGUS", "reason": "x"}
        ).status_code
        == 422
    )
    assert admin.post("/api/v1/governance/policies", json={"name": "x"}).status_code == 422
    assert operator.post("/api/v1/governance/retention/evaluate", json={}).status_code == 422
    assert operator.post("/api/v1/governance/holds", json={"case_id": case_a}).status_code == 422
    assert operator.post("/api/v1/governance/dispositions", json={"case_id": case_a}).status_code == 422
    assert operator.post("/api/v1/governance/exports", json={"case_id": case_a}).status_code == 422

    disposition = _request_disposition(operator, case_a)
    disposition_id = disposition["disposition"]["disposition_id"]
    assert (
        admin.post(
            f"/api/v1/governance/dispositions/{disposition_id}/decide",
            json={"decision": "BOGUS", "reason": "invalid decision"},
        ).status_code
        == 422
    )

    # Case-scoped listings do not leak rows from other cases.
    other = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_b, "reason": "Synthetic other-case hold."},
    )
    assert other.status_code == 201, other.text
    listed = admin.get("/api/v1/governance/holds", params={"case_id": case_b}).json()
    assert listed["total"] == 1
    assert all(item["case_id"] == case_b for item in listed["items"])
    assert admin.get("/api/v1/governance/holds", params={"case_id": case_a}).json()["total"] == 0


# ---------------------------------------------------------------------------
# Idempotency and stale-state protection
# ---------------------------------------------------------------------------
def test_legal_hold_idempotency_replay_and_cross_case_conflict(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_a = _create_case(operator)["case_id"]
    case_b = _create_case(operator)["case_id"]

    first = operator.post(
        "/api/v1/governance/holds",
        json={
            "case_id": case_a,
            "reason": "Synthetic idempotent hold.",
            "idempotency_key": "hold-key-1",
        },
    )
    assert first.status_code == 201, first.text
    assert first.json()["replayed"] is False
    hold_id = first.json()["hold"]["hold_id"]

    replay = operator.post(
        "/api/v1/governance/holds",
        json={
            "case_id": case_a,
            "reason": "Synthetic idempotent hold.",
            "idempotency_key": "hold-key-1",
        },
    )
    assert replay.status_code == 201, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["hold"]["hold_id"] == hold_id
    assert admin.get("/api/v1/governance/holds", params={"case_id": case_a}).json()["total"] == 1

    cross_case = operator.post(
        "/api/v1/governance/holds",
        json={
            "case_id": case_b,
            "reason": "Synthetic idempotent hold.",
            "idempotency_key": "hold-key-1",
        },
    )
    assert cross_case.status_code == 409, cross_case.text
    assert "different legal hold" in cross_case.text

    approved = admin.post(
        f"/api/v1/governance/holds/{hold_id}/approve",
        json={"reason": "Synthetic idempotent approval.", "idempotency_key": "hold-approve-1"},
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["hold"]["status"] == "ACTIVE"

    approve_replay = admin.post(
        f"/api/v1/governance/holds/{hold_id}/approve",
        json={"reason": "Synthetic idempotent approval.", "idempotency_key": "hold-approve-1"},
    )
    assert approve_replay.status_code == 200, approve_replay.text
    assert approve_replay.json()["replayed"] is True
    assert approve_replay.json()["hold"]["status"] == "ACTIVE"

    stale = admin.post(
        f"/api/v1/governance/holds/{hold_id}/release",
        json={"reason": "stale release", "expected_version": 1},
    )
    assert stale.status_code == 409, stale.text

    released = admin.post(
        f"/api/v1/governance/holds/{hold_id}/release",
        json={"reason": "Synthetic release.", "expected_version": 2},
    )
    assert released.status_code == 200, released.text
    assert released.json()["hold"]["status"] == "RELEASED"

    release_replay = admin.post(
        f"/api/v1/governance/holds/{hold_id}/release",
        json={
            "reason": "Synthetic release.",
            "idempotency_key": "hold-release-1",
        },
    )
    assert release_replay.status_code == 409, release_replay.text

    # A second release with the original action key is a true replay only when
    # the key was stored; this release used no key, so it remains a state error.
    keyed_release = admin.post(
        f"/api/v1/governance/holds/{hold_id}/release",
        json={"reason": "already released", "idempotency_key": "hold-release-2"},
    )
    assert keyed_release.status_code == 409, keyed_release.text


def test_disposition_decision_replay_after_terminal_status(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_a = _eligible_case(client, admin, operator, finding_id="finding-hardening-disp-a")
    case_b = _eligible_case(client, admin, operator, finding_id="finding-hardening-disp-b")

    first = _request_disposition(operator, case_a)
    disposition_a = first["disposition"]["disposition_id"]
    approved = admin.post(
        f"/api/v1/governance/dispositions/{disposition_a}/decide",
        json={
            "decision": "APPROVE",
            "reason": "Synthetic hardening approval.",
            "idempotency_key": "disp-approve-1",
        },
    )
    assert approved.status_code == 200, approved.text
    assert approved.json()["disposition"]["status"] == "APPROVED"
    assert approved.json()["replayed"] is False
    assert len(approved.json()["decisions"]) == 1

    replay = admin.post(
        f"/api/v1/governance/dispositions/{disposition_a}/decide",
        json={
            "decision": "APPROVE",
            "reason": "Synthetic hardening approval.",
            "idempotency_key": "disp-approve-1",
        },
    )
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["disposition"]["status"] == "APPROVED"
    assert replay.json()["physical_deletion_performed"] is False
    assert len(replay.json()["decisions"]) == 1

    duplicate = admin.post(
        f"/api/v1/governance/dispositions/{disposition_a}/decide",
        json={
            "decision": "APPROVE",
            "reason": "different key",
            "idempotency_key": "disp-approve-2",
        },
    )
    assert duplicate.status_code == 409, duplicate.text

    second = _request_disposition(operator, case_b)
    disposition_b = second["disposition"]["disposition_id"]
    cross_target = admin.post(
        f"/api/v1/governance/dispositions/{disposition_b}/decide",
        json={
            "decision": "APPROVE",
            "reason": "cross-target replay",
            "idempotency_key": "disp-approve-1",
        },
    )
    assert cross_target.status_code == 409, cross_target.text
    assert "different disposition" in cross_target.text

    withdrawn = admin.post(
        f"/api/v1/governance/dispositions/{disposition_b}/withdraw",
        json={
            "reason": "Synthetic hardening withdrawal.",
            "idempotency_key": "disp-withdraw-1",
        },
    )
    assert withdrawn.status_code == 200, withdrawn.text
    assert withdrawn.json()["disposition"]["status"] == "WITHDRAWN"

    withdraw_replay = admin.post(
        f"/api/v1/governance/dispositions/{disposition_b}/withdraw",
        json={
            "reason": "Synthetic hardening withdrawal.",
            "idempotency_key": "disp-withdraw-1",
        },
    )
    assert withdraw_replay.status_code == 200, withdraw_replay.text
    assert withdraw_replay.json()["replayed"] is True
    assert withdraw_replay.json()["disposition"]["status"] == "WITHDRAWN"


def test_export_generation_replay_after_success_and_verification(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_id = _eligible_case(client, admin, operator, finding_id="finding-hardening-export-replay")

    requested = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": "Synthetic hardening export."},
    )
    assert requested.status_code == 201, requested.text
    approval_id = requested.json()["approval"]["approval_id"]

    approved = admin.post(
        f"/api/v1/governance/exports/{approval_id}/approve",
        json={"reason": "Synthetic hardening approval."},
    )
    assert approved.status_code == 200, approved.text

    generated = admin.post(f"/api/v1/governance/exports/{approval_id}/generate")
    assert generated.status_code == 200, generated.text
    assert generated.json()["replayed"] is False
    export = generated.json()["export"]
    assert generated.json()["delivery_claimed"] is False
    assert generated.json()["external_recipient_validated"] is False

    replay = admin.post(f"/api/v1/governance/exports/{approval_id}/generate")
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["approval"]["status"] == "GENERATED"
    assert replay.json()["export"]["export_id"] == export["export_id"]
    assert replay.json()["export"]["sha256"] == export["sha256"]
    assert replay.json()["delivery_claimed"] is False

    verified = admin.post(f"/api/v1/governance/exports/{approval_id}/verify")
    assert verified.status_code == 200, verified.text
    assert verified.json()["approval"]["status"] == "VERIFIED"
    assert verified.json()["verification"]["outcome"] == "PASS"

    replay_after_verify = admin.post(f"/api/v1/governance/exports/{approval_id}/generate")
    assert replay_after_verify.status_code == 200, replay_after_verify.text
    assert replay_after_verify.json()["replayed"] is True
    assert replay_after_verify.json()["approval"]["status"] == "VERIFIED"
    assert replay_after_verify.json()["export"]["sha256"] == export["sha256"]

    download = admin.get(f"/api/v1/governance/exports/{approval_id}/download")
    assert download.status_code == 200
    assert download.content.startswith(b"PK")
    assert hashlib.sha256(download.content).hexdigest() == export["sha256"]

    # A terminal non-generated state must not replay an export.
    rejected_request = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": "Synthetic rejected export."},
    )
    rejected_id = rejected_request.json()["approval"]["approval_id"]
    assert (
        admin.post(
            f"/api/v1/governance/exports/{rejected_id}/reject",
            json={"reason": "Synthetic rejection."},
        ).status_code
        == 200
    )
    assert admin.post(f"/api/v1/governance/exports/{rejected_id}/generate").status_code == 409


def test_hold_blocks_new_export_but_allows_existing_generation_replay(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_id = _eligible_case(client, admin, operator, finding_id="finding-hardening-export-hold")

    requested = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": "Synthetic export before hold."},
    )
    approval_id = requested.json()["approval"]["approval_id"]
    assert (
        admin.post(
            f"/api/v1/governance/exports/{approval_id}/approve",
            json={"reason": "Synthetic approval before hold."},
        ).status_code
        == 200
    )
    generated = admin.post(f"/api/v1/governance/exports/{approval_id}/generate")
    assert generated.status_code == 200, generated.text

    hold = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_id, "reason": "Synthetic blocking hold."},
    )
    assert hold.status_code == 201, hold.text
    hold_id = hold.json()["hold"]["hold_id"]

    blocked = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": "hold must block a new export"},
    )
    assert blocked.status_code == 409, blocked.text
    assert "LEGAL_HOLD_PENDING_APPROVAL" in blocked.text

    replay = admin.post(f"/api/v1/governance/exports/{approval_id}/generate")
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["export"]["export_id"] == generated.json()["export"]["export_id"]

    direct = admin.post(f"/api/v1/forensics/cases/{case_id}/exports", json={})
    assert direct.status_code == 422, direct.text
    assert "legal hold" in direct.text

    assert (
        admin.post(
            f"/api/v1/governance/holds/{hold_id}/reject",
            json={"reason": "Synthetic rejection."},
        ).status_code
        == 200
    )
    after = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": "export allowed after rejection"},
    )
    assert after.status_code == 201, after.text


def test_integrity_failure_blocks_disposition_review(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    finding = _seed_finding(client, finding_id="finding-hardening-integrity")
    case = _create_case(operator, finding=finding)
    case_id = case["case_id"]
    verify = operator.post(f"/api/v1/forensics/cases/{case_id}/verify")
    assert verify.status_code == 200, verify.text
    _mark_case_closed(client, case_id)

    factory = get_session_factory(str(client.app.state.settings.database_url))
    with factory() as session:
        row = session.query(ForensicCustodyEventORM).filter_by(case_id=case_id, sequence=1).one()
        row.event_hash = "0" * 64
        session.commit()

    failed = operator.post(f"/api/v1/forensics/cases/{case_id}/verify")
    assert failed.status_code == 200, failed.text
    assert failed.json()["outcome"] == "FAIL"
    assert failed.json()["external_anchor_claimed"] is False

    blocked = operator.post(
        "/api/v1/governance/dispositions",
        json={"case_id": case_id, "justification": "integrity failure must block review"},
    )
    assert blocked.status_code == 409, blocked.text
    assert "INTEGRITY_NOT_PASS" in blocked.text

    evaluation = operator.post("/api/v1/governance/retention/evaluate", json={"case_id": case_id})
    assert evaluation.status_code == 200, evaluation.text
    assert evaluation.json()["evaluation"]["integrity_status"] == "FAIL"
    assert evaluation.json()["evaluation"]["disposition_eligible"] is False


def test_policy_version_idempotency_transitions_and_default_protection(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]

    payload = {
        "policy_id": "POL-CUSTOM-1",
        "name": "Synthetic custom policy",
        "state": "DRAFT",
        "case_type": "FORENSIC_REVIEW",
        "retention_days": 20,
        "review_interval_days": 5,
        "reason": "Synthetic policy creation.",
        "idempotency_key": "policy-key-1",
    }
    first = admin.post("/api/v1/governance/policies", json=payload)
    assert first.status_code == 201, first.text
    assert first.json()["replayed"] is False
    assert first.json()["policy"]["version"] == 1

    replay = admin.post("/api/v1/governance/policies", json=payload)
    assert replay.status_code == 201, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["policy"]["version"] == 1

    conflict = admin.post(
        "/api/v1/governance/policies",
        json={**payload, "policy_id": "POL-CUSTOM-2"},
    )
    assert conflict.status_code == 409, conflict.text

    updated = admin.patch(
        "/api/v1/governance/policies/POL-CUSTOM-1",
        json={"retention_days": 25, "reason": "Synthetic update.", "expected_version": 1},
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["policy"]["version"] == 2

    stale = admin.patch(
        "/api/v1/governance/policies/POL-CUSTOM-1",
        json={"retention_days": 30, "reason": "Synthetic stale update.", "expected_version": 1},
    )
    assert stale.status_code == 409, stale.text

    enabled = admin.post(
        "/api/v1/governance/policies/POL-CUSTOM-1/state",
        json={"state": "ENABLED", "reason": "Synthetic enable.", "expected_version": 2},
    )
    assert enabled.status_code == 200, enabled.text
    assert enabled.json()["policy"]["state"] == "ENABLED"

    disabled = admin.post(
        "/api/v1/governance/policies/POL-CUSTOM-1/state",
        json={"state": "DISABLED", "reason": "Synthetic disable.", "expected_version": 3},
    )
    assert disabled.status_code == 200, disabled.text
    assert disabled.json()["policy"]["state"] == "DISABLED"

    archived = admin.post(
        "/api/v1/governance/policies/POL-CUSTOM-1/state",
        json={"state": "ARCHIVED", "reason": "Synthetic archive.", "expected_version": 4},
    )
    assert archived.status_code == 200, archived.text
    assert archived.json()["policy"]["state"] == "ARCHIVED"

    immutable = admin.patch(
        "/api/v1/governance/policies/POL-CUSTOM-1",
        json={"retention_days": 40, "reason": "archived must reject", "expected_version": 5},
    )
    assert immutable.status_code == 422, immutable.text

    assert (
        admin.post(
            "/api/v1/governance/policies/POL-DEFAULT/state",
            json={"state": "DISABLED", "reason": "default must stay enabled"},
        ).status_code
        == 422
    )
    assert (
        admin.post(
            "/api/v1/governance/policies/POL-DEFAULT/state",
            json={"state": "ARCHIVED", "reason": "default must stay enabled"},
        ).status_code
        == 422
    )

    versions = admin.get("/api/v1/governance/policies/POL-CUSTOM-1/versions").json()
    assert [item["version"] for item in versions["items"]] == [5, 4, 3, 2, 1]


def test_retention_review_requires_evaluation_and_batch_is_bounded(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_a = _create_case(operator)["case_id"]
    case_b = _create_case(operator)["case_id"]
    _configure_default_policy(admin)
    _future_clock(client)

    missing = operator.post(
        f"/api/v1/governance/retention/cases/{case_a}/review",
        json={"reason": "no evaluation yet"},
    )
    assert missing.status_code == 404, missing.text

    assert operator.post("/api/v1/governance/retention/evaluate", json={"case_id": case_a}).status_code == 200
    reviewed = operator.post(
        f"/api/v1/governance/retention/cases/{case_a}/review",
        json={"reason": "Synthetic retention review."},
    )
    assert reviewed.status_code == 200, reviewed.text
    assert reviewed.json()["evaluation"]["evaluation_kind"] == "REVIEW"

    review_replay = operator.post(
        f"/api/v1/governance/retention/cases/{case_a}/review",
        json={"reason": "Synthetic retention review."},
    )
    assert review_replay.status_code == 200, review_replay.text
    assert review_replay.json()["replayed"] is True

    batch = operator.post(
        "/api/v1/governance/retention/evaluate",
        json={"case_ids": [case_a, case_b, "CASE-MISSING"]},
    )
    assert batch.status_code == 200, batch.text
    body = batch.json()
    assert len(body["items"]) == 2
    assert body["errors"][0]["case_id"] == "CASE-MISSING"

    too_many = operator.post(
        "/api/v1/governance/retention/evaluate",
        json={"case_ids": [f"CASE-{index}" for index in range(101)]},
    )
    assert too_many.status_code == 422, too_many.text


# ---------------------------------------------------------------------------
# Audit, redaction, and non-destructive behavior
# ---------------------------------------------------------------------------
def test_audit_tampering_is_detected_and_reports_degrade(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_id = _create_case(operator)["case_id"]

    hold = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_id, "reason": "Synthetic audit tamper hold."},
    )
    assert hold.status_code == 201, hold.text

    events = admin.get("/api/v1/governance/audit", params={"event_type": "LEGAL_HOLD_CREATED"}).json()
    assert events["total"] >= 1
    event_id = events["items"][0]["event_id"]
    assert admin.get(f"/api/v1/governance/audit/{event_id}").json()["digest_valid"] is True

    factory = get_session_factory(str(client.app.state.settings.database_url))
    with factory() as session:
        row = session.query(GovernanceAccessAuditORM).filter_by(id=event_id).one()
        row.reason = "tampered reason"
        session.commit()

    tampered = admin.get(f"/api/v1/governance/audit/{event_id}")
    assert tampered.status_code == 200
    assert tampered.json()["digest_valid"] is False
    assert tampered.json()["assurance"] == "LOCAL_SELF_DIGEST_ONLY"

    summary = admin.get("/api/v1/governance/audit/summary").json()
    assert summary["integrity"]["outcome"] == "FAILED"
    assert summary["integrity"]["verified"] < summary["integrity"]["checked"]

    report = admin.get("/api/v1/governance/reports/compliance").json()
    assert report["sections"]["audit"]["status"] == "PARTIAL"
    assert report["overall_status"] == "REVIEW_REQUIRED"
    assert report["regulatory_certification_claimed"] is False

    # The tampered row is evidence of an integrity problem, not a reason to
    # delete or rewrite history: it remains readable and append-only in intent.
    still_there = admin.get(f"/api/v1/governance/audit/{event_id}")
    assert still_there.status_code == 200
    assert still_there.json()["event"]["reason"] == "tampered reason"


def test_secrets_are_redacted_across_governance_surfaces(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_id = _eligible_case(client, admin, operator, finding_id="finding-hardening-redaction")

    hold = operator.post(
        "/api/v1/governance/holds",
        json={
            "case_id": case_id,
            "reason": f"hold reason contains {_SECRET}",
            "scope": f"scope {_SECRET}",
        },
    )
    assert hold.status_code == 201, hold.text
    hold_id = hold.json()["hold"]["hold_id"]
    assert _SECRET not in hold.text
    assert "[REDACTED]" in hold.text

    # Reject the pending hold so it does not block the disposition workflow.
    rejected = admin.post(
        f"/api/v1/governance/holds/{hold_id}/reject",
        json={"reason": "Synthetic redaction cleanup."},
    )
    assert rejected.status_code == 200, rejected.text

    disposition = operator.post(
        "/api/v1/governance/dispositions",
        json={
            "case_id": case_id,
            "justification": f"justification contains {_SECRET}",
        },
    )
    assert disposition.status_code == 201, disposition.text
    assert _SECRET not in disposition.text
    assert "[REDACTED]" in disposition.text

    export = operator.post(
        "/api/v1/governance/exports",
        json={"case_id": case_id, "reason": f"export reason contains {_SECRET}"},
    )
    assert export.status_code == 201, export.text
    assert _SECRET not in export.text
    assert "[REDACTED]" in export.text

    hold_detail = admin.get(f"/api/v1/governance/holds/{hold_id}")
    assert hold_detail.status_code == 200
    assert _SECRET not in hold_detail.text
    assert "[REDACTED]" in hold_detail.text

    audit = admin.get("/api/v1/governance/audit", params={"case_id": case_id})
    assert audit.status_code == 200
    assert _SECRET not in audit.text

    report = admin.get("/api/v1/governance/reports/compliance")
    assert report.status_code == 200
    assert _SECRET not in json.dumps(report.json())

    csv = admin.get("/api/v1/governance/reports/compliance.csv")
    assert csv.status_code == 200
    assert _SECRET not in csv.text


def test_governance_disabled_and_not_initialized_return_503(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_id = _create_case(operator)["case_id"]

    original = client.app.state.governance_service
    assert original is not None
    try:
        client.app.state.governance_service = None
        assert admin.get("/api/v1/governance/status").status_code == 503
        assert (
            operator.post("/api/v1/governance/retention/evaluate", json={"case_id": case_id}).status_code
            == 503
        )
    finally:
        client.app.state.governance_service = original

    original._settings.governance_enabled = False
    try:
        # Status remains readable so operators can see governance is disabled.
        status = admin.get("/api/v1/governance/status")
        assert status.status_code == 200
        assert status.json()["enabled"] is False
        assert (
            operator.post("/api/v1/governance/retention/evaluate", json={"case_id": case_id}).status_code
            == 503
        )
        assert (
            operator.post(
                "/api/v1/governance/holds",
                json={"case_id": case_id, "reason": "disabled"},
            ).status_code
            == 503
        )
        assert admin.get("/api/v1/governance/reports/compliance").status_code == 503

        # Direct V34 exports remain backward-compatible when governance is off.
        direct = admin.post(f"/api/v1/forensics/cases/{case_id}/exports", json={})
        assert direct.status_code == 201, direct.text
    finally:
        original._settings.governance_enabled = True


def test_v34_reads_and_direct_exports_append_governance_audit(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_id = _create_case(operator)["case_id"]

    assert operator.get(f"/api/v1/forensics/cases/{case_id}").status_code == 200
    assert operator.get(f"/api/v1/forensics/cases/{case_id}/custody").status_code == 200
    assert operator.get(f"/api/v1/forensics/cases/{case_id}/exports").status_code == 200

    audit = admin.get("/api/v1/governance/audit", params={"case_id": case_id}).json()
    event_types = {item["event_type"] for item in audit["items"]}
    assert {"CASE_VIEWED", "CUSTODY_HISTORY_VIEWED", "EVIDENCE_METADATA_VIEWED"} <= event_types

    direct = admin.post(f"/api/v1/forensics/cases/{case_id}/exports", json={})
    assert direct.status_code == 201, direct.text
    export_id = direct.json()["export_id"]
    direct_events = admin.get("/api/v1/governance/audit", params={"event_type": "EXPORT_GENERATED"}).json()
    assert direct_events["total"] >= 1
    generated = next(item for item in direct_events["items"] if item["target_id"] == export_id)
    assert generated["metadata"]["approval_id"] is None
    assert generated["metadata"]["direct_export"] is True

    refused = admin.post(
        f"/api/v1/forensics/cases/{case_id}/exports",
        json={"include_evidence_bytes": True},
    )
    assert refused.status_code == 422, refused.text
    assert "evidence-byte export is disabled" in refused.text

    download = admin.get(f"/api/v1/forensics/exports/{export_id}")
    assert download.status_code == 200
    download_events = admin.get(
        "/api/v1/governance/audit", params={"event_type": "EXPORT_DOWNLOAD_SERVED"}
    ).json()
    assert download_events["total"] >= 1
    served = download_events["items"][0]
    assert served["metadata"]["delivery_claimed"] is False
    assert served["metadata"]["approval_id"] is None


def test_hold_release_never_deletes_case_or_evidence_records(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    case_id = _eligible_case(client, admin, operator, finding_id="finding-hardening-nodelete")

    before = admin.get(f"/api/v1/forensics/cases/{case_id}").json()
    hold = operator.post(
        "/api/v1/governance/holds",
        json={"case_id": case_id, "reason": "Synthetic no-delete hold."},
    )
    hold_id = hold.json()["hold"]["hold_id"]
    assert (
        admin.post(
            f"/api/v1/governance/holds/{hold_id}/approve",
            json={"reason": "Synthetic no-delete approval."},
        ).status_code
        == 200
    )
    assert (
        admin.post(
            f"/api/v1/governance/holds/{hold_id}/release",
            json={"reason": "Synthetic no-delete release."},
        ).status_code
        == 200
    )

    after = admin.get(f"/api/v1/forensics/cases/{case_id}").json()
    assert after["case"]["case_id"] == before["case"]["case_id"]
    assert after["case"]["case_number"] == before["case"]["case_number"]
    assert after["case"]["status"] == before["case"]["status"]
    assert after["evidence_references"] == before["evidence_references"]
    assert after["custody"]["events"] == before["custody"]["events"]

    # The hold remains as append-only history in RELEASED state.
    history = admin.get(f"/api/v1/governance/holds/{hold_id}").json()
    assert history["hold"]["status"] == "RELEASED"
    assert [event["event_type"] for event in history["events"]] == [
        "CREATED",
        "LEGAL_HOLD_APPROVED",
        "LEGAL_HOLD_RELEASED",
    ]
