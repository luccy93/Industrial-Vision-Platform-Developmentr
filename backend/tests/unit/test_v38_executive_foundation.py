"""V38 executive governance foundation tests.

Synthetic, deterministic, local-only. These tests exercise KPI source
preservation (missing data is never zero), health determinism, configuration
reads, RBAC, and stable error envelopes. No external service, evidence file, or
live infrastructure is involved.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.governance.executive.constants import (
    DEFAULT_EXECUTIVE_CONFIG,
    HEALTH_MODEL_VERSION,
    KPI_ORDER,
)
from backend.app.governance.executive.health import evaluate_health
from backend.app.governance.executive.repository import GovernanceExecutiveRepository
from backend.app.governance.executive.service import GovernanceExecutiveService
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)


def _factory(tmp_path: Any) -> Any:
    url = f"sqlite:///{tmp_path}/v38-foundation.db"
    init_db(url)
    return get_session_factory(url)


def _forensic_summary(
    *,
    total: int = 0,
    critical: int = 0,
    latest_audit_id: str | None = "audit-1",
    by_severity: dict[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "total": total,
        "critical": critical,
        "by_status": {"OPEN": total} if total else {},
        "by_severity": by_severity or ({"CRITICAL": critical} if critical else {}),
        "integrity_findings": {
            "availability": "AVAILABLE",
            "message": "",
            "latest_audit_id": latest_audit_id,
            "latest_audit_status": "COMPLETED" if latest_audit_id else None,
            "latest_findings": 0,
            "latest_findings_by_severity": {},
        },
    }


def _readiness(
    *,
    evaluations: list[dict[str, Any]] | None = None,
    blocking_holds: int = 0,
    oldest: str | None = None,
) -> dict[str, Any]:
    evaluations = evaluations or []
    next_review_known = sum(1 for item in evaluations if item.get("next_review_at"))
    deadline_known = sum(1 for item in evaluations if item.get("retention_deadline"))
    return {
        "availability": "OK",
        "evaluations": evaluations,
        "evaluation_count": len(evaluations),
        "evaluations_truncated": False,
        "evaluation_state_counts": {},
        "next_review_known": next_review_known,
        "next_review_unknown": len(evaluations) - next_review_known,
        "retention_deadline_known": deadline_known,
        "retention_deadline_unknown": len(evaluations) - deadline_known,
        "hold_states": {"ACTIVE": blocking_holds} if blocking_holds else {},
        "blocking_holds": [],
        "blocking_hold_count": blocking_holds,
        "oldest_blocking_requested_at": oldest,
        "disposition_states": {},
        "open_dispositions": [],
        "open_disposition_count": 0,
        "export_states": {"PENDING_APPROVAL": 0},
        "pending_export_approvals": 0,
    }


def _automation(repository: GovernanceAutomationRepository | None = None) -> Any:
    if repository is not None:
        return repository
    return SimpleNamespace(
        queue_counts=lambda: {"PENDING": 0, "RUNNING": 0, "FAILED": 0},
        stale_job_count=lambda now=None: 0,
        count_jobs_in_range=lambda **kwargs: 0,
        count_jobs=lambda: 0,
        list_snapshots=lambda **kwargs: ([], 0),
        get_snapshot=lambda snapshot_id: None,
    )


def _service(
    tmp_path: Any,
    *,
    forensic_summary: dict[str, Any] | None = None,
    forensic_error: Exception | None = None,
    readiness: dict[str, Any] | None = None,
    readiness_error: Exception | None = None,
    automation: Any | None = None,
    recommendations: dict[str, Any] | None = None,
    risk_model: dict[str, Any] | None = None,
    sla_backlog: dict[str, Any] | None = None,
) -> GovernanceExecutiveService:
    factory = _factory(tmp_path)
    repository = GovernanceExecutiveRepository(factory)

    def _summary() -> dict[str, Any]:
        if forensic_error is not None:
            raise forensic_error
        return forensic_summary or _forensic_summary()

    def _readiness_metrics() -> dict[str, Any]:
        if readiness_error is not None:
            raise readiness_error
        return readiness or _readiness()

    forensic_service = SimpleNamespace(summary=_summary)
    governance_service = SimpleNamespace(readiness_metrics=_readiness_metrics)
    governance_repository = SimpleNamespace(
        get_policy=lambda policy_id: {"policy_id": policy_id, "version": 3}
    )
    intelligence_service = SimpleNamespace(
        sla_backlog=lambda **kwargs: (
            sla_backlog
            or {
                "state_counts": {},
                "availability": {},
                "unavailable_sources": [],
                "truncated": False,
            }
        )
    )
    intelligence_repository = SimpleNamespace(
        recommendation_counts=lambda: (
            recommendations or {"total": 0, "by_status": {}, "by_severity": {}, "by_status_severity": {}}
        ),
        latest_risk_model=lambda: risk_model or {"model_id": "RISK-DEFAULT", "version": 1},
    )
    settings = SimpleNamespace(
        governance_enabled=True,
        governance_executive_enabled=True,
        governance_executive_default_window_days=30,
        governance_executive_page_size=20,
        governance_executive_max_report_rows=500,
    )
    return GovernanceExecutiveService(
        settings=settings,
        repository=repository,
        governance_service=governance_service,
        governance_repository=governance_repository,
        forensic_repository=forensic_service,
        forensic_service=forensic_service,
        automation_repository=automation if automation is not None else _automation(),
        intelligence_service=intelligence_service,
        intelligence_repository=intelligence_repository,
        clock=lambda: NOW,
    )


def _role_client(client: Any, email: str, role: Role) -> TestClient:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, email, role=role)
    plain = TestClient(client.app)
    login = plain.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert login.status_code == 200, login.text
    plain.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    return plain


# ---------------------------------------------------------------------------
# KPI source preservation
# ---------------------------------------------------------------------------
def test_all_kpis_expose_definition_source_window_and_versions(tmp_path: Any) -> None:
    service = _service(tmp_path)
    payload = service.kpis(now=NOW)

    assert [item["kpi_id"] for item in payload["items"]] == list(KPI_ORDER)
    assert payload["total"] == len(KPI_ORDER) == 15
    for kpi in payload["items"]:
        assert kpi["name"]
        assert kpi["definition"]
        assert kpi["source"]
        assert kpi["calculated_at"] == "2026-11-15T12:00:00Z"
        assert kpi["window"]
        assert kpi["availability"] in {"AVAILABLE", "PARTIAL", "UNAVAILABLE"}
        assert set(kpi["completeness"]) >= {"status", "known", "unknown", "total", "message"}
        assert "model_version" in kpi
        assert "policy_version" in kpi
        if kpi["kpi_id"].startswith("GOVERNANCE_"):
            assert kpi["policy_version"] == 3
        else:
            assert kpi["policy_version"] is None
    by_id = {item["kpi_id"]: item for item in payload["items"]}
    assert by_id["RECOMMENDATIONS_OPEN"]["model_version"] == 1


def test_missing_source_is_unavailable_never_zero(tmp_path: Any) -> None:
    service = _service(tmp_path, forensic_error=RuntimeError("synthetic outage"))
    payload = service.kpis(now=NOW)
    by_id = {item["kpi_id"]: item for item in payload["items"]}

    open_cases = by_id["FORENSIC_OPEN_CASES"]
    assert open_cases["value"] is None
    assert open_cases["availability"] == "UNAVAILABLE"
    assert open_cases["unavailable_reason"] == "SOURCE_UNAVAILABLE"
    assert open_cases["completeness"]["status"] == "UNAVAILABLE"
    assert payload["source_coverage"]["status"] == "PARTIAL"
    assert "FORENSIC_OPEN_CASES" in payload["source_coverage"]["unavailable_kpi_ids"]

    health = service.health(now=NOW)
    assert health["health"]["overall_status"] != "HEALTHY"
    forensic_signal = next(
        signal for signal in health["health"]["signals"] if signal["code"] == "CRITICAL_INTEGRITY_FINDINGS"
    )
    assert forensic_signal["evaluated"] is False
    assert forensic_signal["triggered"] is False


def test_genuine_zero_is_available_and_healthy(tmp_path: Any) -> None:
    service = _service(tmp_path, forensic_summary=_forensic_summary(total=0, critical=0))
    payload = service.kpis(now=NOW)
    by_id = {item["kpi_id"]: item for item in payload["items"]}

    assert by_id["FORENSIC_OPEN_CASES"]["value"] == 0
    assert by_id["FORENSIC_OPEN_CASES"]["availability"] == "AVAILABLE"
    assert by_id["INTEGRITY_CRITICAL_FINDINGS"]["value"] == 0
    assert by_id["INTEGRITY_CRITICAL_FINDINGS"]["availability"] == "AVAILABLE"

    health = service.health(now=NOW)
    assert health["health"]["model_version"] == HEALTH_MODEL_VERSION
    assert health["health"]["averaged_score_used"] is False


def test_no_integrity_audit_history_is_unavailable_not_zero(tmp_path: Any) -> None:
    summary = _forensic_summary()
    summary["integrity_findings"]["latest_audit_id"] = None
    service = _service(tmp_path, forensic_summary=summary)
    payload = service.kpis(now=NOW)
    kpi = next(item for item in payload["items"] if item["kpi_id"] == "INTEGRITY_CRITICAL_FINDINGS")
    assert kpi["value"] is None
    assert kpi["availability"] == "UNAVAILABLE"
    assert kpi["applicable"] is False
    assert kpi["unavailable_reason"] == "NO_INTEGRITY_AUDIT_HISTORY"


def test_sla_ratio_uses_known_items_and_reports_unknown(tmp_path: Any) -> None:
    service = _service(
        tmp_path,
        sla_backlog={
            "state_counts": {
                "DISPOSITION_REVIEW": {
                    "WITHIN_TARGET": 3,
                    "AT_RISK": 1,
                    "BREACHED": 1,
                    "MISSED": 1,
                    "UNKNOWN": 4,
                }
            },
            "availability": {"DISPOSITION_REVIEW": {"availability": "AVAILABLE"}},
            "unavailable_sources": [],
            "truncated": False,
        },
    )
    payload = service.kpis(now=NOW)
    ratio = next(item for item in payload["items"] if item["kpi_id"] == "SLA_COMPLIANCE_RATIO")
    breached = next(item for item in payload["items"] if item["kpi_id"] == "SLA_BREACHED_ITEMS")
    assert ratio["numerator"] == 4
    assert ratio["denominator"] == 6
    assert ratio["value"] == 0.6667
    assert ratio["completeness"]["unknown"] == 4
    assert breached["value"] == 2
    assert "not a blended governance compliance percentage" in ratio["definition"]


def test_no_known_sla_items_is_unavailable_not_zero_percent(tmp_path: Any) -> None:
    service = _service(
        tmp_path,
        sla_backlog={
            "state_counts": {"DISPOSITION_REVIEW": {"UNKNOWN": 2}},
            "availability": {"DISPOSITION_REVIEW": {"availability": "UNAVAILABLE"}},
            "unavailable_sources": ["DISPOSITION_REVIEW"],
            "truncated": False,
        },
    )
    payload = service.kpis(now=NOW)
    ratio = next(item for item in payload["items"] if item["kpi_id"] == "SLA_COMPLIANCE_RATIO")
    assert ratio["value"] is None
    assert ratio["availability"] == "UNAVAILABLE"
    assert ratio["applicable"] is False
    assert ratio["unavailable_reason"] == "NO_KNOWN_SLA_ITEMS"


# ---------------------------------------------------------------------------
# Health determinism
# ---------------------------------------------------------------------------
def test_health_is_deterministic_and_explainable(tmp_path: Any) -> None:
    service = _service(
        tmp_path,
        forensic_summary=_forensic_summary(total=2, critical=1),
    )
    first = service.health(now=NOW)
    second = service.health(now=NOW)
    assert first == second
    health = first["health"]
    assert health["overall_status"] == "DEGRADED"
    assert health["thresholds"]["fixed"] is True
    assert health["thresholds"]["model_version"] == HEALTH_MODEL_VERSION
    assert "CRITICAL_FORENSIC_CASES" in health["triggered_signals"]
    assert health["coverage"]["status"] in {"COMPLETE", "PARTIAL"}


def test_health_status_precedence_and_coverage_outcomes() -> None:
    def kpi(kpi_id: str, value: Any, availability: str = "AVAILABLE", applicable: bool = True):
        return {
            "kpi_id": kpi_id,
            "value": value,
            "availability": availability,
            "applicable": applicable,
            "completeness": {"status": availability if availability != "AVAILABLE" else "COMPLETE"},
        }

    critical = evaluate_health(
        [
            kpi("INTEGRITY_CRITICAL_FINDINGS", 1),
            kpi("SLA_BREACHED_ITEMS", 3),
            kpi("FORENSIC_CRITICAL_CASES", 0),
            kpi("GOVERNANCE_OVERDUE_REVIEWS", 0),
        ],
        calculated_at=NOW,
    )
    assert critical["overall_status"] == "CRITICAL"

    degraded = evaluate_health(
        [
            kpi("INTEGRITY_CRITICAL_FINDINGS", 0),
            kpi("SLA_BREACHED_ITEMS", 1),
            kpi("FORENSIC_CRITICAL_CASES", 0),
        ],
        calculated_at=NOW,
    )
    assert degraded["overall_status"] == "DEGRADED"

    attention = evaluate_health(
        [
            kpi("INTEGRITY_CRITICAL_FINDINGS", 0),
            kpi("SLA_BREACHED_ITEMS", 0),
            kpi("FORENSIC_CRITICAL_CASES", 0),
            kpi("GOVERNANCE_OVERDUE_REVIEWS", 0),
            kpi("SLA_COMPLIANCE_RATIO", 0.9, "PARTIAL"),
        ],
        calculated_at=NOW,
    )
    assert attention["overall_status"] == "ATTENTION_REQUIRED"
    assert attention["coverage"]["status"] == "PARTIAL"

    unavailable = evaluate_health(
        [kpi("INTEGRITY_CRITICAL_FINDINGS", None, "UNAVAILABLE")],
        calculated_at=NOW,
    )
    assert unavailable["overall_status"] == "UNAVAILABLE"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
def test_config_defaults_when_no_snapshot_exists(tmp_path: Any) -> None:
    service = _service(tmp_path)
    payload = service.config()
    assert payload["availability"] == "DEFAULT"
    assert payload["config"] == DEFAULT_EXECUTIVE_CONFIG
    assert payload["health_thresholds_fixed"] is True
    assert payload["fixed_health_model_version"] == HEALTH_MODEL_VERSION


def test_config_reads_valid_snapshot_and_rejects_tampering(tmp_path: Any) -> None:
    factory = _factory(tmp_path)
    automation = GovernanceAutomationRepository(factory)
    stored = {**DEFAULT_EXECUTIVE_CONFIG, "default_window_days": 14, "report_max_rows": 250}
    snapshot, created = automation.create_snapshot(
        snapshot_type="EXECUTIVE_CONFIG",
        as_of=NOW,
        generated_by="admin@example.com",
        dedup_key="v38-foundation-config",
        payload={"config": stored, "schema_version": 1},
        now=NOW,
    )
    assert created is True

    service = _service(tmp_path, automation=automation)
    payload = service.config()
    assert payload["availability"] == "OK"
    assert payload["config"]["default_window_days"] == 14
    assert payload["config"]["report_max_rows"] == 250
    assert payload["source"]["digest_valid"] is True
    assert payload["source"]["snapshot_id"] == snapshot["snapshot_id"]

    # Tamper with the stored payload without updating the self-digest.
    with factory() as session:
        session.execute(
            text("UPDATE governance_snapshots SET payload = :payload WHERE id = :id"),
            {
                "payload": json.dumps({"config": {**stored, "default_window_days": 90}, "schema_version": 1}),
                "id": snapshot["snapshot_id"],
            },
        )
        session.commit()

    tampered = service.config()
    assert tampered["availability"] == "INTEGRITY_FAILED"
    assert tampered["config"] == DEFAULT_EXECUTIVE_CONFIG
    assert tampered["source"]["digest_valid"] is False


# ---------------------------------------------------------------------------
# API and RBAC
# ---------------------------------------------------------------------------
def test_executive_api_reads_and_role_boundaries(client: Any) -> None:
    admin = client
    assert admin.get("/api/v1/governance/executive/status").status_code == 200
    health = admin.get("/api/v1/governance/executive/health?window_days=7")
    assert health.status_code == 200
    assert health.json()["health"]["model_version"] == HEALTH_MODEL_VERSION
    kpis = admin.get("/api/v1/governance/executive/kpis")
    assert kpis.status_code == 200
    assert kpis.json()["total"] == 15
    assert admin.get("/api/v1/governance/executive/config").status_code == 200

    viewer = _role_client(admin, "viewer-v38@example.com", Role.VIEWER)
    assert viewer.get("/api/v1/governance/executive/status").status_code == 200
    assert viewer.get("/api/v1/governance/executive/health").status_code == 200
    assert viewer.get("/api/v1/governance/executive/kpis").status_code == 200
    forbidden = viewer.get("/api/v1/governance/executive/config")
    assert forbidden.status_code == 403
    assert forbidden.json()["error"]["code"]

    operator = _role_client(admin, "operator-v38@example.com", Role.OPERATOR)
    assert operator.get("/api/v1/governance/executive/config").status_code == 200

    anonymous = TestClient(admin.app)
    assert anonymous.get("/api/v1/governance/executive/status").status_code == 401


def test_executive_api_rejects_invalid_window_with_stable_envelope(client: Any) -> None:
    response = client.get("/api/v1/governance/executive/kpis?window_days=0")
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "validation_error"
    assert body["error"]["message"]


def test_disabled_executive_service_returns_stable_503(client: Any) -> None:
    client.app.state.governance_executive_service = None
    response = client.get("/api/v1/governance/executive/status")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "executive_not_ready"
