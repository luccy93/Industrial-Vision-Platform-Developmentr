"""V34 forensic API integration tests: RBAC, correlation, custody, closure, exports.

Every test uses synthetic V33 findings in the isolated monitoring store and the
temporary application database created by the shared fixtures. Protected
artifacts are never repaired or rewritten; tamper tests mutate only the local
custody row and assert that verification reports the failure.
"""

from __future__ import annotations

import hashlib
from typing import Any

from fastapi.testclient import TestClient

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.incidents.repository import IncidentRepository
from backend.app.infrastructure.db import get_session_factory
from backend.app.integrity.constants import (
    AuditStatus,
    AuditTrigger,
    IntegrityScope,
    Severity,
)
from backend.app.integrity.models import AuditRun, Finding, utc_now_iso
from backend.app.models.forensic_orm import ForensicCustodyEventORM
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

TERMINAL = {"PASS", "FAIL", "PARTIAL", "UNAVAILABLE", "NOT_RUN"}


def _clients(client: Any) -> dict[str, TestClient]:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, "operator-forensic@example.com", role=Role.OPERATOR)
    create_test_user(repo, "viewer-forensic@example.com", role=Role.VIEWER)
    out: dict[str, TestClient] = {"anon": TestClient(client.app)}
    for name, email in [
        ("admin", "admin@example.com"),
        ("operator", "operator-forensic@example.com"),
        ("viewer", "viewer-forensic@example.com"),
    ]:
        logged = TestClient(client.app)
        res = logged.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
        assert res.status_code == 200, (name, res.text)
        logged.headers["X-CSRF-Token"] = res.json()["csrf_token"]
        out[name] = logged
    return out


def _seed_findings(
    client: Any,
    *,
    run_id: str,
    findings: list[Finding],
) -> None:
    store = client.app.state.integrity_store
    assert store is not None
    now = utc_now_iso()
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
    inserted, truncated = store.add_findings(findings)
    assert inserted == len(findings)
    assert truncated is False


def _finding(
    *,
    run_id: str,
    reason_code: str,
    artifact_id: str,
    severity: Severity | None = None,
    verification_source: str | None = None,
) -> Finding:
    return Finding.create(
        audit_run_id=run_id,
        scope=IntegrityScope.EVIDENCE,
        reason_code=reason_code,
        artifact_id=artifact_id,
        explanation="synthetic V34 API fixture",
        verification_source=verification_source,
        severity=severity,
    )


def _create_case(client: TestClient, **payload: Any) -> dict[str, Any]:
    body = {
        "title": "Synthetic forensic review",
        "description": "Synthetic API fixture; no real evidence.",
        "case_type": "FORENSIC_REVIEW",
        "severity": "MEDIUM",
        **payload,
    }
    response = client.post("/api/v1/forensics/cases", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def _advance_to_review(client: TestClient, case_id: str) -> None:
    for target in ("TRIAGED", "INVESTIGATING", "AWAITING_REVIEW"):
        response = client.post(
            f"/api/v1/forensics/cases/{case_id}/transition",
            json={"target_status": target, "reason": f"advance to {target}"},
        )
        assert response.status_code == 200, (target, response.text)


# ---------------------------------------------------------------------------
# Reads and case lifecycle
# ---------------------------------------------------------------------------
def test_reads_require_authentication_and_allow_every_role(client: Any) -> None:
    parties = _clients(client)
    paths = [
        "/api/v1/forensics/status",
        "/api/v1/forensics/summary",
        "/api/v1/forensics/cases",
        "/api/v1/forensics/findings",
    ]
    for path in paths:
        assert parties["anon"].get(path).status_code == 401, path
        for name in ("admin", "operator", "viewer"):
            response = parties[name].get(path)
            assert response.status_code == 200, (name, path, response.text)

    status = parties["viewer"].get("/api/v1/forensics/status").json()
    assert status["enabled"] is True
    assert status["external_anchor_claimed"] is False
    assert status["assurance"] == "LOCAL_HASH_CHAIN_ONLY"
    assert "not externally anchored" in status["external_anchor_note"]
    assert status["v33_source"] in {"AVAILABLE", "UNAVAILABLE", "DISABLED"}

    summary = parties["viewer"].get("/api/v1/forensics/summary").json()
    assert summary["total"] == 0
    assert summary["by_status"] == {}


def test_case_lifecycle_notes_revisions_and_version_conflicts(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    viewer = parties["viewer"]

    assert parties["anon"].post("/api/v1/forensics/cases", json={"title": "anonymous"}).status_code == 401
    assert viewer.post("/api/v1/forensics/cases", json={"title": "viewer"}).status_code == 403

    case = _create_case(operator, severity="HIGH", case_type="EVIDENCE_TAMPERING")
    case_id = case["case_id"]
    assert case["status"] == "OPEN"
    assert case["source"] == "MANUAL"
    assert case["case_number"].startswith("CASE-")
    assert case["priority"] == "P2"

    # Reads are available to every role; writes are not.
    assert viewer.get(f"/api/v1/forensics/cases/{case_id}").status_code == 200
    assert (
        viewer.post(
            f"/api/v1/forensics/cases/{case_id}/transition",
            json={"target_status": "TRIAGED", "reason": "viewer attempt"},
        ).status_code
        == 403
    )
    assert (
        viewer.post(
            f"/api/v1/forensics/cases/{case_id}/notes",
            json={"note_type": "OBSERVATION", "content": "viewer attempt"},
        ).status_code
        == 403
    )

    invalid = operator.post(
        f"/api/v1/forensics/cases/{case_id}/transition",
        json={"target_status": "INVESTIGATING", "reason": "skip triage"},
    )
    assert invalid.status_code == 409, invalid.text

    triaged = operator.post(
        f"/api/v1/forensics/cases/{case_id}/transition",
        json={"target_status": "TRIAGED", "reason": "initial triage"},
    )
    assert triaged.status_code == 200
    assert triaged.json()["status"] == "TRIAGED"

    note = operator.post(
        f"/api/v1/forensics/cases/{case_id}/notes",
        json={
            "note_type": "OBSERVATION",
            "content": "Synthetic observation from the API test.",
            "visibility": "INTERNAL",
        },
    )
    assert note.status_code == 201, note.text
    note_id = note.json()["note_id"]
    assert note.json()["version"] == 1

    edited = operator.patch(
        f"/api/v1/forensics/cases/{case_id}/notes/{note_id}",
        json={"content": "Synthetic observation, edited.", "expected_version": 1},
    )
    assert edited.status_code == 200, edited.text
    assert edited.json()["version"] == 2
    assert edited.json()["edited_by"] == "operator-forensic@example.com"

    stale = operator.patch(
        f"/api/v1/forensics/cases/{case_id}/notes/{note_id}",
        json={"content": "stale edit", "expected_version": 1},
    )
    assert stale.status_code == 409, stale.text

    revisions = viewer.get(f"/api/v1/forensics/cases/{case_id}/notes/{note_id}/revisions")
    assert revisions.status_code == 200, revisions.text
    items = revisions.json()["items"]
    assert [item["revision"] for item in items] == [1, 2]
    assert items[0]["content"] == "Synthetic observation from the API test."
    assert items[1]["content"] == "Synthetic observation, edited."

    credential_note = operator.post(
        f"/api/v1/forensics/cases/{case_id}/notes",
        json={
            "note_type": "OBSERVATION",
            "content": "-----BEGIN PRIVATE KEY-----\nsynthetic-not-a-real-key\n-----END PRIVATE KEY-----",
        },
    )
    assert credential_note.status_code == 409, credential_note.text

    action = operator.post(
        f"/api/v1/forensics/cases/{case_id}/actions",
        json={
            "action_type": "EVIDENCE_REVIEWED",
            "description": "Reviewed the synthetic reference.",
            "result": "SUCCESS",
        },
    )
    assert action.status_code == 201, action.text

    assigned = operator.post(
        f"/api/v1/forensics/cases/{case_id}/assign",
        json={"assignee": "operator-forensic@example.com", "expected_version": 2},
    )
    assert assigned.status_code == 200, assigned.text
    conflict = operator.post(
        f"/api/v1/forensics/cases/{case_id}/assign",
        json={"assignee": "someone-else@example.com", "expected_version": 2},
    )
    assert conflict.status_code == 409, conflict.text

    detail = viewer.get(f"/api/v1/forensics/cases/{case_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["assurance"] == "LOCAL_HASH_CHAIN_ONLY"
    assert body["external_anchor_claimed"] is False
    assert body["custody"]["verification"]["outcome"] == "PASS"
    assert body["notes"][0]["note_id"] == note_id
    assert body["actions"][0]["result"] == "SUCCESS"
    assert body["assignments"][-1]["assignee"] == "operator-forensic@example.com"
    assert str(client.app.state.settings.database_url) not in detail.text
    assert str(client.app.state.settings.integrity_store_url) not in detail.text


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------
def test_correlation_promotes_only_confirmed_failures_and_is_idempotent(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    run_id = "run-v34-confirmed"
    confirmed = _finding(
        run_id=run_id,
        reason_code="EVIDENCE_MODIFIED",
        artifact_id="evidence/synthetic-a.bin",
        severity=Severity.CRITICAL,
    )
    unavailable = _finding(
        run_id=run_id,
        reason_code="EVIDENCE_UNAVAILABLE",
        artifact_id="evidence/synthetic-b.bin",
    )
    not_run = _finding(
        run_id=run_id,
        reason_code="AUDIT_TIMEOUT",
        artifact_id="evidence/synthetic-c.bin",
    )
    simulated = _finding(
        run_id=run_id,
        reason_code="EVIDENCE_MODIFIED",
        artifact_id="evidence/synthetic-d.bin",
        verification_source="SIMULATED_LOCAL_TEST",
    )
    _seed_findings(
        client,
        run_id=run_id,
        findings=[confirmed, unavailable, not_run, simulated],
    )

    assert (
        parties["viewer"]
        .post(
            "/api/v1/forensics/correlate",
            json={"finding_ids": [confirmed.finding_id]},
        )
        .status_code
        == 403
    )

    response = operator.post(
        "/api/v1/forensics/correlate",
        json={
            "finding_ids": [
                confirmed.finding_id,
                unavailable.finding_id,
                not_run.finding_id,
                simulated.finding_id,
            ]
        },
    )
    assert response.status_code == 200, response.text
    stats = response.json()["stats"]
    assert stats["examined"] == 4
    assert stats["confirmed"] == 1
    assert stats["skipped_unavailable"] == 1
    assert stats["skipped_not_run"] == 1
    assert stats["skipped_simulated"] == 1
    assert stats["cases_created"] == 1
    assert stats["incidents_created"] == 1
    assert stats["failed"] == 0

    cases = operator.get("/api/v1/forensics/cases").json()
    assert cases["total"] == 1
    case = cases["items"][0]
    assert case["case_type"] == "EVIDENCE_TAMPERING"
    assert case["severity"] == "CRITICAL"
    assert case["priority"] == "P1"
    assert case["source"] == "CORRELATION"
    assert case["originating_audit_run_id"] == run_id

    detail = operator.get(f"/api/v1/forensics/cases/{case['case_id']}").json()
    assert len(detail["correlations"]) == 1
    assert detail["correlations"][0]["finding_id"] == confirmed.finding_id
    assert len(detail["incident_links"]) == 1
    incident_id = detail["incident_links"][0]["incident_id"]

    incidents = IncidentRepository(get_session_factory(str(client.app.state.settings.database_url)))
    incident = incidents.get_incident(incident_id)
    assert incident is not None
    assert incident.category.value == "SECURITY"
    assert incident.source == "FORENSIC"
    assert incident.metadata["forensic_case_id"] == case["case_id"]
    assert incident.metadata["finding_id"] == confirmed.finding_id

    replay = operator.post(
        "/api/v1/forensics/correlate",
        json={"finding_ids": [confirmed.finding_id]},
    )
    assert replay.status_code == 200
    replay_stats = replay.json()["stats"]
    assert replay_stats["duplicates"] == 1
    assert replay_stats["cases_created"] == 0
    assert operator.get("/api/v1/forensics/cases").json()["total"] == 1

    # A later audit run with the same artifact/reason updates the same case.
    later = _finding(
        run_id="run-v34-confirmed-later",
        reason_code="EVIDENCE_MODIFIED",
        artifact_id="evidence/synthetic-a.bin",
        severity=Severity.CRITICAL,
    )
    _seed_findings(client, run_id="run-v34-confirmed-later", findings=[later])
    updated = operator.post(
        "/api/v1/forensics/correlate",
        json={"finding_ids": [later.finding_id]},
    )
    assert updated.status_code == 200
    updated_stats = updated.json()["stats"]
    assert updated_stats["cases_created"] == 0
    assert updated_stats["cases_updated"] == 1
    assert updated_stats["incidents_linked"] == 1
    assert operator.get("/api/v1/forensics/cases").json()["total"] == 1
    detail = operator.get(f"/api/v1/forensics/cases/{case['case_id']}").json()
    assert len(detail["correlations"]) == 2
    assert len(detail["incident_links"]) == 1


def test_unresolved_critical_finding_blocks_silent_closure(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    admin = parties["admin"]
    run_id = "run-v34-closure"
    confirmed = _finding(
        run_id=run_id,
        reason_code="EVIDENCE_MODIFIED",
        artifact_id="evidence/closure.bin",
        severity=Severity.CRITICAL,
    )
    _seed_findings(client, run_id=run_id, findings=[confirmed])
    assert (
        operator.post(
            "/api/v1/forensics/correlate",
            json={"finding_ids": [confirmed.finding_id]},
        ).status_code
        == 200
    )
    case_id = operator.get("/api/v1/forensics/cases").json()["items"][0]["case_id"]

    _advance_to_review(operator, case_id)
    conclusion = operator.post(
        f"/api/v1/forensics/cases/{case_id}/notes",
        json={
            "note_type": "CONCLUSION",
            "content": "Synthetic conclusion for closure testing.",
        },
    )
    assert conclusion.status_code == 201, conclusion.text

    missing_ack = admin.post(
        f"/api/v1/forensics/cases/{case_id}/transition",
        json={
            "target_status": "RESOLVED",
            "reason": "attempted silent resolution",
            "resolution_summary": "Synthetic resolution summary.",
            "allow_unverified_evidence": True,
        },
    )
    assert missing_ack.status_code == 409, missing_ack.text
    assert "unresolved critical" in missing_ack.json()["error"]["message"]

    # The dedicated close capability is ADMIN-only, even for RESOLVED.
    assert (
        operator.post(
            f"/api/v1/forensics/cases/{case_id}/transition",
            json={
                "target_status": "RESOLVED",
                "reason": "operator close attempt",
                "resolution_summary": "Synthetic resolution summary.",
                "allow_unverified_evidence": True,
                "acknowledge_critical_findings": True,
            },
        ).status_code
        == 403
    )

    resolved = admin.post(
        f"/api/v1/forensics/cases/{case_id}/transition",
        json={
            "target_status": "RESOLVED",
            "reason": "explicit acknowledgement",
            "resolution_summary": "Synthetic resolution summary.",
            "allow_unverified_evidence": True,
            "acknowledge_critical_findings": True,
        },
    )
    assert resolved.status_code == 200, resolved.text
    assert resolved.json()["status"] == "RESOLVED"
    assert resolved.json()["resolution_summary"] == "Synthetic resolution summary."

    closed = admin.post(
        f"/api/v1/forensics/cases/{case_id}/transition",
        json={
            "target_status": "CLOSED",
            "reason": "explicit closure",
            "allow_unverified_evidence": True,
            "acknowledge_critical_findings": True,
        },
    )
    assert closed.status_code == 200, closed.text
    assert closed.json()["status"] == "CLOSED"

    reopened = admin.post(
        f"/api/v1/forensics/cases/{case_id}/transition",
        json={
            "target_status": "OPEN",
            "reason": "reopen after new synthetic finding",
            "reopening": True,
        },
    )
    assert reopened.status_code == 200, reopened.text
    assert reopened.json()["status"] == "OPEN"


# ---------------------------------------------------------------------------
# Custody and verification
# ---------------------------------------------------------------------------
def test_custody_tampering_is_detected_and_source_finding_is_untouched(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    run_id = "run-v34-custody"
    finding = _finding(
        run_id=run_id,
        reason_code="EVIDENCE_MODIFIED",
        artifact_id="evidence/custody.bin",
        severity=Severity.HIGH,
    )
    _seed_findings(client, run_id=run_id, findings=[finding])
    assert (
        operator.post(
            "/api/v1/forensics/correlate",
            json={"finding_ids": [finding.finding_id]},
        ).status_code
        == 200
    )
    case_id = operator.get("/api/v1/forensics/cases").json()["items"][0]["case_id"]

    store = client.app.state.integrity_store
    before = store.get_finding(finding.finding_id).to_dict()
    assert before is not None

    factory = get_session_factory(str(client.app.state.settings.database_url))
    with factory() as session:
        row = session.query(ForensicCustodyEventORM).filter_by(case_id=case_id, sequence=1).one()
        row.event_hash = "0" * 64
        session.commit()

    custody = operator.get(f"/api/v1/forensics/cases/{case_id}/custody")
    assert custody.status_code == 200
    verification = custody.json()["verification"]
    assert verification["outcome"] == "FAIL"
    assert "CUSTODY_EVENT_HASH_INVALID" in verification["reason_codes"]
    assert verification["external_anchor_claimed"] is False

    report = operator.post(f"/api/v1/forensics/cases/{case_id}/verify")
    assert report.status_code == 200, report.text
    body = report.json()
    assert body["outcome"] == "FAIL"
    assert body["custody"]["outcome"] == "FAIL"
    assert "FORENSIC_CUSTODY_CHAIN_INVALID" in body["reason_codes"]
    assert body["external_anchor_claimed"] is False
    assert body["assurance"] == "LOCAL_HASH_CHAIN_ONLY"
    assert body["counts"]["failed"] >= 1

    after = store.get_finding(finding.finding_id).to_dict()
    assert after == before

    # Verification is read-only for the source but appends its own observations.
    detail = operator.get(f"/api/v1/forensics/cases/{case_id}").json()
    assert detail["custody"]["verification"]["outcome"] == "FAIL"
    assert detail["latest_verification"]["outcome"] == "FAIL"


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------
def test_export_requires_dedicated_capability_and_verifies(client: Any) -> None:
    parties = _clients(client)
    admin = parties["admin"]
    operator = parties["operator"]
    viewer = parties["viewer"]

    case = _create_case(admin, title="Synthetic export case")
    case_id = case["case_id"]

    for party in (operator, viewer):
        assert (
            party.post(
                f"/api/v1/forensics/cases/{case_id}/exports",
                json={"include_evidence_bytes": False},
            ).status_code
            == 403
        )

    created = admin.post(
        f"/api/v1/forensics/cases/{case_id}/exports",
        json={"include_evidence_bytes": False},
    )
    assert created.status_code == 201, created.text
    export = created.json()
    export_id = export["export_id"]
    assert export["evidence_bytes_included"] is False
    assert export["file_count"] == 12
    assert len(export["sha256"]) == 64
    assert len(export["manifest_digest"]) == 64
    assert len(export["root_digest"]) == 64
    assert export["verification_outcome"] == "NOT_RUN"

    denied_download = operator.get(f"/api/v1/forensics/exports/{export_id}")
    assert denied_download.status_code == 403
    assert viewer.get(f"/api/v1/forensics/exports/{export_id}").status_code == 403
    assert operator.post(f"/api/v1/forensics/exports/{export_id}/verify").status_code == 403

    download = admin.get(f"/api/v1/forensics/exports/{export_id}")
    assert download.status_code == 200, download.text
    assert download.headers["content-type"] == "application/zip"
    payload = download.content
    assert payload.startswith(b"PK")
    assert len(payload) == export["size_bytes"]
    assert hashlib.sha256(payload).hexdigest() == export["sha256"]

    verified = admin.post(f"/api/v1/forensics/exports/{export_id}/verify")
    assert verified.status_code == 200, verified.text
    verification = verified.json()["verification"]
    assert verification["outcome"] == "PASS", verification
    assert verification["reason_codes"] == []
    assert verification["external_anchor_claimed"] is False
    assert verified.json()["export"]["verification_outcome"] == "PASS"

    # Evidence-byte inclusion is policy-gated and refused by default.
    refused = admin.post(
        f"/api/v1/forensics/cases/{case_id}/exports",
        json={"include_evidence_bytes": True},
    )
    assert refused.status_code == 422, refused.text
    assert "evidence-byte export is disabled" in refused.json()["error"]["message"]

    listing = admin.get(f"/api/v1/forensics/cases/{case_id}/exports")
    assert listing.status_code == 200
    assert listing.json()["items"][0]["export_id"] == export_id


def test_manual_evidence_reference_validation_and_bounded_inputs(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    case = _create_case(operator)
    case_id = case["case_id"]

    unsafe = operator.post(
        f"/api/v1/forensics/cases/{case_id}/evidence",
        json={
            "artifact_type": "EVIDENCE_FILE",
            "artifact_id": "artifact.bin",
            "original_relative_path": "../escape.bin",
            "expected_sha256": "a" * 64,
        },
    )
    assert unsafe.status_code == 422, unsafe.text

    absolute = operator.post(
        f"/api/v1/forensics/cases/{case_id}/evidence",
        json={
            "artifact_type": "EVIDENCE_FILE",
            "artifact_id": "artifact.bin",
            "original_relative_path": "C:/Windows/system.ini",
            "expected_sha256": "a" * 64,
        },
    )
    assert absolute.status_code == 422, absolute.text

    missing_digest = operator.post(
        f"/api/v1/forensics/cases/{case_id}/evidence",
        json={
            "artifact_type": "SIGNED_CHECKPOINT",
            "artifact_id": "checkpoint.json",
            "original_relative_path": "checkpoint.json",
        },
    )
    assert missing_digest.status_code == 422, missing_digest.text

    unknown_type = operator.post(
        f"/api/v1/forensics/cases/{case_id}/evidence",
        json={"artifact_type": "NOT_A_REAL_TYPE", "artifact_id": "x"},
    )
    assert unknown_type.status_code == 422, unknown_type.text

    assert operator.get("/api/v1/forensics/cases?page_size=101").status_code == 422
    assert operator.get("/api/v1/forensics/cases?page=0").status_code == 422
    assert operator.post("/api/v1/forensics/cases", json={"title": ""}).status_code == 422
    assert (
        operator.post(
            "/api/v1/forensics/cases",
            json={"title": "x", "case_type": "NOT_A_CASE_TYPE"},
        ).status_code
        == 422
    )
