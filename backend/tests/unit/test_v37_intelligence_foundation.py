"""V37 governance intelligence foundation tests.

Synthetic, deterministic, local-only. These tests exercise the risk model,
explainable scoring, versioned operational SLAs, backlog reads, and RBAC. No
external service, evidence file, or live infrastructure is involved.
"""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.governance.intelligence.constants import (
    DEFAULT_FACTOR_POINTS,
    DEFAULT_RISK_THRESHOLDS,
    DEFAULT_SLA_TARGETS,
    RISK_LEVEL_ORDER,
    risk_level_for,
)
from backend.app.governance.intelligence.errors import (
    RiskModelVersionConflictError,
    SlaTargetVersionConflictError,
)
from backend.app.governance.intelligence.scoring import score_case
from backend.app.governance.intelligence.service import GovernanceIntelligenceService
from backend.app.governance.intelligence.sla import calculate_sla, resolve_target_version
from backend.app.infrastructure.db import get_session_factory
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


def _model() -> dict[str, Any]:
    return {
        "model_id": "RISK-DEFAULT",
        "version": 1,
        "thresholds": {key: dict(value) for key, value in DEFAULT_RISK_THRESHOLDS.items()},
        "factor_points": dict(DEFAULT_FACTOR_POINTS),
    }


def _case(severity: str = "CRITICAL") -> dict[str, Any]:
    return {
        "case_id": "case-1",
        "case_number": "CASE-2026-000001",
        "case_type": "FORENSIC_REVIEW",
        "severity": severity,
        "status": "OPEN",
    }


def _policy() -> dict[str, Any]:
    return {
        "policy_id": "POL-DEFAULT",
        "version": 1,
        "state": "ENABLED",
        "case_type": None,
        "evidence_category": None,
    }


def _score(**overrides: Any) -> dict[str, Any]:
    params: dict[str, Any] = {
        "case_id": "case-1",
        "case": _case(),
        "evaluation": {
            "evaluation_id": "eval-1",
            "case_id": "case-1",
            "governance_state": "REVIEW_DUE",
            "next_review_at": "2026-11-01T00:00:00Z",
            "evaluated_at": "2026-10-01T00:00:00Z",
            "reviewed_at": None,
            "policy_snapshot": _policy(),
        },
        "verification": {
            "verification_id": "ver-1",
            "outcome": "FAIL",
            "report": {},
            "metadata": {},
        },
        "verification_error": None,
        "holds": [],
        "disposition": None,
        "export_approvals": [],
        "policy": _policy(),
        "incident": None,
        "incident_error": None,
        "sla_context": {},
        "model": _model(),
        "now": NOW,
    }
    params.update(overrides)
    return score_case(**params)


def test_risk_threshold_boundaries_are_contiguous_and_bounded() -> None:
    thresholds = DEFAULT_RISK_THRESHOLDS
    expected = {
        0: "LOW",
        24: "LOW",
        25: "MODERATE",
        49: "MODERATE",
        50: "HIGH",
        74: "HIGH",
        75: "CRITICAL",
        100: "CRITICAL",
        -5: "LOW",
        150: "CRITICAL",
    }
    for score, level in expected.items():
        assert risk_level_for(score, thresholds) == level
    assert tuple(thresholds) == RISK_LEVEL_ORDER


def test_scoring_is_deterministic_explainable_and_versioned() -> None:
    first = _score()
    second = _score()
    assert first["score"] == second["score"] == 80
    assert first["risk_level"] == second["risk_level"] == "CRITICAL"
    assert first["model_version"] == 1
    assert first["calculated_at"] == "2026-11-14T12:00:00Z"
    assert first["data_completeness"] == "COMPLETE"
    assert first["missing_data"] == []
    assert first["policy_context"]["policy_id"] == "POL-DEFAULT"
    factor_ids = [factor["factor_id"] for factor in first["factors"]]
    assert factor_ids == [
        "CONFIRMED_INTEGRITY_FAILURE",
        "RETENTION_REVIEW_OVERDUE",
        "CASE_SEVERITY_CRITICAL",
    ]
    for factor in first["factors"]:
        assert factor["reason"]
        assert factor["source_refs"]
        assert factor["data_status"] == "CONFIRMED"
        assert factor["suppressed"] is False


def test_scoring_does_not_double_count_blocked_disposition_from_integrity() -> None:
    result = _score(
        disposition={
            "disposition_id": "disp-1",
            "status": "BLOCKED",
            "requested_at": "2026-10-01T00:00:00Z",
            "blocked_reason_codes": ["INTEGRITY_NOT_PASS"],
        },
        sla_context={
            "DISPOSITION_REVIEW": {
                "state": "BREACHED",
                "target_version": 1,
            }
        },
    )
    blocked = next(factor for factor in result["factors"] if factor["factor_id"] == "DISPOSITION_BLOCKED")
    assert blocked["suppressed"] is True
    assert blocked["suppressed_by"] == "CONFIRMED_INTEGRITY_FAILURE"
    assert "not counted twice" in str(blocked["suppression_reason"]).lower()
    assert result["score"] == 80


def test_integrity_states_never_become_confirmed_failures_or_pass() -> None:
    cases = {
        "PARTIAL": ("INTEGRITY_VERIFICATION_PARTIAL", "INCOMPLETE", 12),
        "UNAVAILABLE": ("INTEGRITY_VERIFICATION_UNAVAILABLE", "UNAVAILABLE", 0),
        "NOT_RUN": ("INTEGRITY_VERIFICATION_NOT_RUN", "NOT_RUN", 0),
    }
    for outcome, (factor_id, status, expected_points) in cases.items():
        result = _score(
            verification={
                "verification_id": f"ver-{outcome}",
                "outcome": outcome,
                "report": {},
                "metadata": {},
            },
            evaluation=None,
            policy=None,
            case=_case("LOW"),
            sla_context={},
        )
        factor = next(item for item in result["factors"] if item["factor_id"] == factor_id)
        assert factor["data_status"] == status
        assert factor["points"] == expected_points
        assert (
            "not a confirmed failure" in factor["reason"].lower() or "no failure" in factor["reason"].lower()
        )
        assert not any(item["factor_id"] == "CONFIRMED_INTEGRITY_FAILURE" for item in result["factors"])
        assert any(entry["source"] == "forensic_verification" for entry in result["missing_data"])
        assert "PASS" not in str(result["risk_level"]).upper()

    simulated = _score(
        verification={
            "verification_id": "ver-simulated",
            "outcome": "FAIL",
            "report": {"simulated": True},
            "metadata": {"source": "SIMULATED"},
        },
        evaluation=None,
        policy=None,
        case=_case("LOW"),
    )
    simulated_factor = next(
        item for item in simulated["factors"] if item["factor_id"] == "INTEGRITY_VERIFICATION_SIMULATED"
    )
    assert simulated_factor["data_status"] == "SIMULATED"
    assert simulated_factor["points"] == 0
    assert not any(item["factor_id"] == "CONFIRMED_INTEGRITY_FAILURE" for item in simulated["factors"])


def test_missing_verification_is_reported_honestly() -> None:
    result = _score(verification=None, evaluation=None, policy=None, case=_case("LOW"))
    factor = next(item for item in result["factors"] if item["factor_id"] == "INTEGRITY_VERIFICATION_NOT_RUN")
    assert factor["data_status"] == "NOT_RUN"
    assert "PASS" in factor["reason"]
    assert "not run" in factor["reason"].lower()
    assert result["data_completeness"] == "UNAVAILABLE"


def test_sla_versions_resolve_at_item_start_and_preserve_history() -> None:
    versions = [
        {
            "version": 1,
            "target_hours": 720,
            "warning_hours": 168,
            "effective_from": "1970-01-01T00:00:00Z",
        },
        {
            "version": 2,
            "target_hours": 240,
            "warning_hours": 48,
            "effective_from": "2026-06-01T00:00:00Z",
        },
    ]
    old_item = calculate_sla(
        target_key="RETENTION_REVIEW",
        versions=versions,
        item_start="2026-01-01T00:00:00Z",
        now=datetime(2026, 1, 20, 0, 0, tzinfo=UTC),
    )
    new_item = calculate_sla(
        target_key="RETENTION_REVIEW",
        versions=versions,
        item_start="2026-07-01T00:00:00Z",
        now=datetime(2026, 7, 2, 0, 0, tzinfo=UTC),
    )
    assert old_item["target_version"] == 1
    assert old_item["target_hours"] == 720
    assert old_item["state"] == "WITHIN_TARGET"
    assert new_item["target_version"] == 2
    assert new_item["target_hours"] == 240
    assert old_item["sla_kind"] == "OPERATIONAL"
    assert "not a legal or regulatory deadline" in old_item["non_claim"]
    assert resolve_target_version(versions, datetime(2026, 5, 31, tzinfo=UTC))["version"] == 1
    assert resolve_target_version(versions, datetime(2026, 6, 1, tzinfo=UTC))["version"] == 2


def test_sla_unresolved_items_have_open_age_but_no_duration() -> None:
    versions = [
        {
            "version": 1,
            "target_hours": 24,
            "warning_hours": 6,
            "effective_from": "1970-01-01T00:00:00Z",
        }
    ]
    at_risk = calculate_sla(
        target_key="DISPOSITION_REVIEW",
        versions=versions,
        item_start="2026-11-14T00:00:00Z",
        now=datetime(2026, 11, 14, 20, 0, tzinfo=UTC),
    )
    assert at_risk["state"] == "AT_RISK"
    assert at_risk["open_age_hours"] == 20.0
    assert at_risk["duration_hours"] is None
    assert at_risk["resolved"] is False
    breached = calculate_sla(
        target_key="DISPOSITION_REVIEW",
        versions=versions,
        item_start="2026-11-12T00:00:00Z",
        now=NOW,
    )
    assert breached["state"] == "BREACHED"
    resolved = calculate_sla(
        target_key="DISPOSITION_REVIEW",
        versions=versions,
        item_start="2026-11-12T00:00:00Z",
        resolved_at="2026-11-12T12:00:00Z",
        now=NOW,
    )
    assert resolved["state"] == "MET"
    assert resolved["duration_hours"] == 12.0
    unknown = calculate_sla(
        target_key="DISPOSITION_REVIEW",
        versions=versions,
        item_start=None,
        now=NOW,
    )
    assert unknown["state"] == "UNKNOWN"
    assert unknown["duration_hours"] is None
    assert "no SLA duration is invented" in unknown["reason"]


def test_defaults_are_seeded_idempotently(client: Any) -> None:
    repository = client.app.state.governance_intelligence_repository
    first = repository.ensure_defaults(now=NOW)
    second = repository.ensure_defaults(now=NOW)
    assert first == {"risk_models": 0, "sla_targets": 0}
    assert second == {"risk_models": 0, "sla_targets": 0}
    model = repository.latest_risk_model()
    assert model["model_id"] == "RISK-DEFAULT"
    assert model["version"] == 1
    targets = repository.latest_sla_targets()
    assert set(targets) == set(DEFAULT_SLA_TARGETS)
    assert all(item["version"] == 1 for item in targets.values())


def test_risk_model_update_appends_version_and_rejects_stale_write(client: Any) -> None:
    service: GovernanceIntelligenceService = client.app.state.governance_intelligence_service
    created = service.update_risk_model(
        {
            "name": "Synthetic tuned model",
            "thresholds": DEFAULT_RISK_THRESHOLDS,
            "factor_points": {"CONFIRMED_INTEGRITY_FAILURE": 50},
            "expected_version": 1,
            "reason": "synthetic model tuning",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert created["created"] is True
    assert created["model"]["version"] == 2
    assert created["model"]["factor_points"]["CONFIRMED_INTEGRITY_FAILURE"] == 50
    assert service.risk_model()["model"]["version"] == 2
    with pytest.raises(RiskModelVersionConflictError):
        service.update_risk_model(
            {
                "name": "Stale model",
                "thresholds": DEFAULT_RISK_THRESHOLDS,
                "expected_version": 1,
                "reason": "stale write",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_sla_target_update_appends_version_and_rejects_stale_write(client: Any) -> None:
    service: GovernanceIntelligenceService = client.app.state.governance_intelligence_service
    created = service.update_sla_target(
        "RETENTION_REVIEW",
        {
            "target_hours": 480,
            "warning_hours": 96,
            "expected_version": 1,
            "reason": "synthetic SLA tuning",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert created["created"] is True
    assert created["target"]["version"] == 2
    with pytest.raises(SlaTargetVersionConflictError):
        service.update_sla_target(
            "RETENTION_REVIEW",
            {
                "target_hours": 360,
                "warning_hours": 72,
                "expected_version": 1,
                "reason": "stale SLA write",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def _create_case(client: Any, severity: str = "HIGH") -> str:
    response = client.post(
        "/api/v1/forensics/cases",
        json={
            "title": "Synthetic V37 risk case",
            "description": "Synthetic V37 fixture; no real evidence.",
            "case_type": "FORENSIC_REVIEW",
            "severity": severity,
            "evidence_references": [],
        },
    )
    assert response.status_code == 201, response.text
    return str(response.json()["case_id"])


def test_intelligence_api_status_model_and_risk_cases(client: Any) -> None:
    case_id = _create_case(client)
    status = client.get("/api/v1/governance/intelligence/status")
    assert status.status_code == 200, status.text
    body = status.json()
    assert body["enabled"] is True
    assert body["model"]["version"] == 1
    assert body["scheduled_intelligence"] is False
    assert len(body["sla_targets"]) == 4

    model = client.get("/api/v1/governance/intelligence/risk/model")
    assert model.status_code == 200
    assert model.json()["model"]["version"] == 1

    listing = client.get("/api/v1/governance/intelligence/risk/cases", params={"page_size": 10})
    assert listing.status_code == 200, listing.text
    payload = listing.json()
    assert payload["total"] >= 1
    assert payload["model"]["version"] == 1
    item = next(entry for entry in payload["items"] if entry["case_id"] == case_id)
    assert item["score"] >= 0
    assert item["risk_level"] in RISK_LEVEL_ORDER
    assert item["calculated_at"]

    detail = client.get(f"/api/v1/governance/intelligence/risk/cases/{case_id}")
    assert detail.status_code == 200, detail.text
    risk = detail.json()["risk"]
    assert risk["case_id"] == case_id
    assert risk["model_version"] == 1
    assert risk["calculated_at"]
    assert isinstance(risk["factors"], list)
    assert isinstance(risk["missing_data"], list)
    assert detail.json()["non_claims"]

    missing = client.get("/api/v1/governance/intelligence/risk/cases/does-not-exist")
    assert missing.status_code == 404


def test_intelligence_sla_backlog_reports_availability(client: Any) -> None:
    response = client.get("/api/v1/governance/intelligence/sla/backlog")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["sla_kind"] == "OPERATIONAL"
    assert "not a legal or regulatory deadline" in payload["non_claim"]
    assert set(payload["availability"]) == {
        "retention",
        "disposition",
        "legal_hold",
        "export_approval",
    }
    assert payload["partial"] is False
    assert payload["unavailable_sources"] == []


def test_intelligence_api_rejects_malicious_pagination(client: Any) -> None:
    assert (
        client.get("/api/v1/governance/intelligence/risk/cases", params={"page_size": 101}).status_code == 422
    )
    assert client.get("/api/v1/governance/intelligence/risk/cases", params={"page": 0}).status_code == 422
    assert (
        client.get(
            "/api/v1/governance/intelligence/risk/cases",
            params={"risk_level": "DROP TABLE"},
        ).status_code
        == 422
    )
    assert (
        client.get(
            "/api/v1/governance/intelligence/sla/backlog",
            params={"state": "not-a-state"},
        ).status_code
        == 422
    )


def _role_client(client: Any, email: str, role: Role) -> TestClient:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, email, role=role)
    plain = TestClient(client.app)
    login = plain.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert login.status_code == 200, login.text
    plain.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    return plain


def test_intelligence_rbac_is_enforced_server_side(client: Any) -> None:
    viewer = _role_client(client, "v37-viewer@example.com", Role.VIEWER)
    operator = _role_client(client, "v37-operator@example.com", Role.OPERATOR)

    assert viewer.get("/api/v1/governance/intelligence/status").status_code == 200
    assert viewer.get("/api/v1/governance/intelligence/risk/model").status_code == 200
    assert (
        viewer.put(
            "/api/v1/governance/intelligence/risk/model",
            json={
                "name": "viewer attempt",
                "thresholds": DEFAULT_RISK_THRESHOLDS,
                "reason": "viewer must be denied",
            },
        ).status_code
        == 403
    )
    assert (
        operator.put(
            "/api/v1/governance/intelligence/risk/model",
            json={
                "name": "operator attempt",
                "thresholds": DEFAULT_RISK_THRESHOLDS,
                "reason": "operator must be denied",
            },
        ).status_code
        == 403
    )
    admin_update = client.put(
        "/api/v1/governance/intelligence/risk/model",
        json={
            "name": "admin model",
            "thresholds": DEFAULT_RISK_THRESHOLDS,
            "expected_version": 1,
            "reason": "admin configuration",
        },
    )
    assert admin_update.status_code == 200, admin_update.text
    assert admin_update.json()["model"]["version"] == 2


def test_intelligence_has_no_delete_routes(client: Any) -> None:
    paths = {
        path: methods
        for path, methods in client.app.openapi()["paths"].items()
        if path.startswith("/api/v1/governance/intelligence")
    }
    assert paths
    delete_routes = [path for path, methods in paths.items() if "delete" in methods]
    assert delete_routes == []


def _service_for_sla(
    governance_repository: Any, forensic_repository: Any | None = None
) -> GovernanceIntelligenceService:
    class _Repository:
        def sla_target_versions(self, target_key: str) -> list[dict[str, Any]]:
            return [
                {
                    "version": 1,
                    "target_hours": 720,
                    "warning_hours": 168,
                    "effective_from": "1970-01-01T00:00:00Z",
                }
            ]

    return GovernanceIntelligenceService(
        settings=SimpleNamespace(governance_intelligence_enabled=True, governance_enabled=True),
        repository=_Repository(),
        governance_service=SimpleNamespace(),
        governance_repository=governance_repository,
        forensic_repository=forensic_repository or SimpleNamespace(),
    )


def test_retention_sla_uses_due_time_and_resolves_from_review_history() -> None:
    due = {
        "evaluation_id": "eval-1",
        "case_id": "case-1",
        "evaluation_kind": "EVALUATION",
        "governance_state": "REVIEW_DUE",
        "next_review_at": "2026-01-01T00:00:00Z",
        "evaluated_at": "2025-12-01T00:00:00Z",
    }
    review = {
        "evaluation_id": "eval-2",
        "case_id": "case-1",
        "evaluation_kind": "REVIEW",
        "governance_state": "ACTIVE",
        "next_review_at": "2027-01-01T00:00:00Z",
        "evaluated_at": "2026-01-10T00:00:00Z",
    }

    class _GovernanceRepository:
        def list_evaluations(self, case_id: str, *, page: int = 1, page_size: int = 20):
            assert case_id == "case-1"
            return [review, due], 2

    service = _service_for_sla(_GovernanceRepository())
    context = service._sla_context(  # noqa: SLF001 - deterministic unit seam
        case_id="case-1",
        evaluation=review,
        disposition=None,
        holds=[],
        approvals=[],
        now=datetime(2026, 2, 1, tzinfo=UTC),
    )
    resolved = context["RETENTION_REVIEW"]
    assert resolved["state"] == "MET"
    assert resolved["start_at"] == "2026-01-01T00:00:00Z"
    assert resolved["resolution_at"] == "2026-01-10T00:00:00Z"
    assert resolved["duration_hours"] == 216.0
    assert resolved["open_age_hours"] is None

    unresolved = service._sla_context(  # noqa: SLF001 - deterministic unit seam
        case_id="case-1",
        evaluation=due,
        disposition=None,
        holds=[],
        approvals=[],
        now=datetime(2026, 2, 1, tzinfo=UTC),
    )["RETENTION_REVIEW"]
    assert unresolved["state"] == "BREACHED"
    assert unresolved["open_age_hours"] == 744.0
    assert unresolved["duration_hours"] is None


def test_bounded_cases_reports_truncation_honestly() -> None:
    class _Forensics:
        def list_cases(self, *, page: int, page_size: int):
            total = 250
            start = (page - 1) * page_size
            items = [{"case_id": f"case-{index}"} for index in range(start, min(start + page_size, total))]
            return items, total

    service = _service_for_sla(SimpleNamespace(), _Forensics())
    cases, truncated = service._bounded_cases(100)  # noqa: SLF001 - deterministic unit seam
    assert len(cases) == 100
    assert truncated is True
