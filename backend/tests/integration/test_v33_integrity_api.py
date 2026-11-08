"""V33 integrity API: authentication, RBAC, bounded inputs, honest outcomes."""

from __future__ import annotations

from typing import Any

from fastapi.testclient import TestClient

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.infrastructure.db import get_session_factory
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

TERMINAL = {"PASS", "FAIL", "PARTIAL", "UNAVAILABLE", "NOT_RUN"}


def _clients(client: Any) -> dict[str, TestClient]:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, "operator-integrity@example.com", role=Role.OPERATOR)
    create_test_user(repo, "viewer-integrity@example.com", role=Role.VIEWER)
    out: dict[str, TestClient] = {"anon": TestClient(client.app)}
    for name, email in [
        ("admin", "admin@example.com"),
        ("operator", "operator-integrity@example.com"),
        ("viewer", "viewer-integrity@example.com"),
    ]:
        logged = TestClient(client.app)
        res = logged.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
        assert res.status_code == 200, (name, res.text)
        logged.headers["X-CSRF-Token"] = res.json()["csrf_token"]
        out[name] = logged
    return out


def test_reads_require_authentication_and_allow_every_role(client: Any) -> None:
    parties = _clients(client)
    paths = [
        "/api/v1/integrity/status",
        "/api/v1/integrity/summary",
        "/api/v1/integrity/audits",
        "/api/v1/integrity/history",
        "/api/v1/integrity/findings",
    ]
    for path in paths:
        assert parties["anon"].get(path).status_code == 401, path
        for name in ("admin", "operator", "viewer"):
            res = parties[name].get(path)
            assert res.status_code == 200, (name, path, res.text)

    status = parties["viewer"].get("/api/v1/integrity/status").json()
    assert status["enabled"] is True
    assert status["external_anchor_configured"] is False
    assert status["assurance"] in {"NONE", "LOCAL_ONLY", "LOCAL_VERIFIED"}
    assert status["trust"]["external_anchor_status"] in {
        "NOT_CONFIGURED",
        "UNAVAILABLE",
        "SIMULATED",
    }
    summary = parties["viewer"].get("/api/v1/integrity/summary").json()
    assert summary["page_size_max"] == 100
    assert summary["external_anchor_configured"] is False


def test_start_audit_requires_operator_capability(client: Any) -> None:
    parties = _clients(client)
    payload = {"scopes": ["TRUST_STATE", "TRANSPARENCY_LOG"]}
    assert parties["anon"].post("/api/v1/integrity/audits", json=payload).status_code == 401
    denied = parties["viewer"].post("/api/v1/integrity/audits", json=payload)
    assert denied.status_code == 403, denied.text

    for name in ("operator", "admin"):
        res = parties[name].post("/api/v1/integrity/audits", json=payload)
        assert res.status_code == 201, (name, res.text)
        body = res.json()
        assert body["status"] in TERMINAL
        assert body["status"] != "PASS"  # no trust inputs are configured
        assert body["requested_scopes"] == ["TRANSPARENCY_LOG", "TRUST_STATE"]
        assert body["external_anchor_configured"] is False
        assert body["requested_by"] in {
            "operator-integrity@example.com",
            "admin@example.com",
        }
        assert isinstance(body["scope_results"], list) and body["scope_results"]
        assert all(item["status"] in TERMINAL for item in body["scope_results"])


def test_scope_validation_page_bounds_and_idempotent_replay(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    assert operator.post("/api/v1/integrity/audits", json={"scopes": ["BOGUS"]}).status_code == 422
    assert (
        operator.post("/api/v1/integrity/audits", json={"scopes": ["FULL", "TREE_HEADS"]}).status_code == 422
    )
    assert operator.get("/api/v1/integrity/findings?page_size=101").status_code == 422
    assert operator.get("/api/v1/integrity/findings?page_size=0").status_code == 422
    assert operator.get("/api/v1/integrity/audits?page=0").status_code == 422

    payload = {"scopes": ["TRUST_STATE"], "idempotency_key": "api-replay-key"}
    first = operator.post("/api/v1/integrity/audits", json=payload)
    second = operator.post("/api/v1/integrity/audits", json=payload)
    assert first.status_code == second.status_code == 201
    assert first.json()["audit_run_id"] == second.json()["audit_run_id"]


def test_detail_missing_run_and_terminal_cancel(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    assert operator.get("/api/v1/integrity/audits/does-not-exist").status_code == 404

    created = operator.post("/api/v1/integrity/audits", json={"scopes": ["TRUST_STATE"]})
    assert created.status_code == 201
    audit_id = created.json()["audit_run_id"]

    detail = operator.get(f"/api/v1/integrity/audits/{audit_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert set(body) == {"audit", "scope_results", "findings", "findings_total"}
    assert body["audit"]["audit_run_id"] == audit_id

    cancelled = operator.post(f"/api/v1/integrity/audits/{audit_id}/cancel")
    assert cancelled.status_code == 409
    assert parties["viewer"].post(f"/api/v1/integrity/audits/{audit_id}/cancel").status_code == 403


def test_history_findings_and_no_absolute_paths(client: Any) -> None:
    parties = _clients(client)
    operator = parties["operator"]
    created = operator.post("/api/v1/integrity/audits", json={"scopes": ["FULL"]})
    assert created.status_code == 201
    body = created.json()

    audits = operator.get("/api/v1/integrity/audits?page=1&page_size=1")
    assert audits.status_code == 200
    listed = audits.json()
    assert listed["total"] >= 1
    assert listed["page_size"] == 1
    assert len(listed["items"]) == 1
    assert listed["items"][0]["audit_run_id"] == body["audit_run_id"]

    history = operator.get("/api/v1/integrity/history?page_size=5")
    assert history.status_code == 200
    assert history.json()["total"] >= 1

    findings = operator.get("/api/v1/integrity/findings?page_size=5")
    assert findings.status_code == 200
    payload_text = findings.text
    assert str(client.app.state.settings.database_url) not in payload_text
    assert str(client.app.state.settings.integrity_store_url) not in payload_text
    for finding in findings.json()["items"]:
        assert not str(finding.get("artifact_id") or "").startswith(("/", "C:", "\\\\"))
        assert set(finding) == {
            "finding_id",
            "audit_run_id",
            "scope",
            "severity",
            "reason_code",
            "artifact_id",
            "detected_at",
            "explanation",
            "verification_source",
            "recommended_action",
        }
