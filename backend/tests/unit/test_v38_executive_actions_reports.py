"""V38 executive governance actions, reports, comparisons, and configuration.

Synthetic, deterministic, local-only. Missing sources remain explicitly
unavailable; no historical value is interpolated or fabricated; reports are
bounded local JSON/CSV documents and are never distributed externally.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.governance.automation.repository import GovernanceAutomationRepository
from backend.app.governance.executive.constants import (
    DEFAULT_EXECUTIVE_CONFIG,
    HEALTH_MODEL_VERSION,
    KPI_ORDER,
    REPORT_SECTION_ORDER,
)
from backend.app.governance.executive.errors import (
    ActionNotFoundError,
    ActionStateError,
    ActionVersionConflictError,
    ExecutiveValidationError,
    RecommendationNotActionableError,
    RecommendationNotFoundForActionError,
    ReportIntegrityError,
    ReportNotFoundError,
    ReportUnavailableError,
)
from backend.app.governance.executive.repository import GovernanceExecutiveRepository
from backend.app.governance.executive.service import GovernanceExecutiveService
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.models.governance_intelligence_orm import GovernanceRecommendationORM
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

NOW = datetime(2026, 11, 15, 12, 0, tzinfo=UTC)
FUTURE = datetime(2099, 12, 1, 12, 0, tzinfo=UTC)


class _FakeGovernance:
    def __init__(self) -> None:
        self.audit_events: list[dict[str, Any]] = []

    def readiness_metrics(self) -> dict[str, Any]:
        return {
            "availability": "OK",
            "evaluations": [],
            "evaluation_count": 0,
            "evaluations_truncated": False,
            "evaluation_state_counts": {},
            "next_review_known": 0,
            "next_review_unknown": 0,
            "retention_deadline_known": 0,
            "retention_deadline_unknown": 0,
            "hold_states": {},
            "blocking_holds": [],
            "blocking_hold_count": 0,
            "oldest_blocking_requested_at": None,
            "disposition_states": {},
            "open_dispositions": [],
            "open_disposition_count": 0,
            "export_states": {"PENDING_APPROVAL": 0},
            "pending_export_approvals": 0,
        }

    def record_access(self, **kwargs: Any) -> dict[str, Any]:
        self.audit_events.append(dict(kwargs))
        return {"recorded": True}


class _FakeIntelligenceRepository:
    def __init__(self, recommendation: dict[str, Any] | None = None) -> None:
        self.recommendation = recommendation
        self.risk_model: dict[str, Any] = {
            "model_id": "RISK-DEFAULT",
            "version": 1,
            "name": "Default risk model",
        }
        self.counts: dict[str, Any] = {
            "total": 1,
            "by_status": {"OPEN": 1},
            "by_severity": {"CRITICAL": 1},
            "by_status_severity": {"OPEN": {"CRITICAL": 1}},
        }

    def get_recommendation(self, recommendation_id: str) -> dict[str, Any] | None:
        if self.recommendation is None:
            return None
        if self.recommendation.get("recommendation_id") != recommendation_id:
            return None
        return dict(self.recommendation)

    def recommendation_counts(self) -> dict[str, Any]:
        return dict(self.counts)

    def latest_risk_model(self) -> dict[str, Any]:
        return dict(self.risk_model)


class _FakeIntelligenceService:
    def __init__(self) -> None:
        self.risk: dict[str, Any] = {
            "risk_level_counts": {"CRITICAL": 1, "HIGH": 2},
            "truncated": False,
            "unavailable_case_count": 0,
            "partial": False,
        }
        self.sla: dict[str, Any] = {
            "state_counts": {
                "DISPOSITION_REVIEW": {
                    "WITHIN_TARGET": 3,
                    "AT_RISK": 1,
                    "BREACHED": 1,
                    "MISSED": 0,
                    "UNKNOWN": 0,
                }
            },
            "availability": {"DISPOSITION_REVIEW": {"availability": "AVAILABLE"}},
            "unavailable_sources": [],
            "truncated": False,
        }

    def risk_cases(self, **kwargs: Any) -> dict[str, Any]:
        return dict(self.risk)

    def sla_backlog(self, **kwargs: Any) -> dict[str, Any]:
        return dict(self.sla)


def _recommendation(
    *,
    recommendation_id: str = "rec-v38",
    status: str = "OPEN",
    severity: str = "CRITICAL",
) -> dict[str, Any]:
    return {
        "recommendation_id": recommendation_id,
        "recommendation_key": f"GOV-RISK-001|CASE|{recommendation_id}",
        "rule_id": "GOV-RISK-001",
        "scope_type": "CASE",
        "scope_id": "case-v38",
        "case_id": "case-v38",
        "severity": severity,
        "risk_level": "CRITICAL",
        "title": "Review critical forensic finding",
        "status": status,
        "version": 1,
    }


def _forensic_summary() -> dict[str, Any]:
    return {
        "total": 0,
        "critical": 0,
        "by_status": {},
        "by_severity": {},
        "integrity_findings": {
            "availability": "AVAILABLE",
            "message": "",
            "latest_audit_id": "audit-v38",
            "latest_audit_status": "COMPLETED",
            "latest_findings": 0,
            "latest_findings_by_severity": {},
        },
    }


def _settings(*, max_report_bytes: int = 1024 * 1024) -> Any:
    return SimpleNamespace(
        governance_enabled=True,
        governance_executive_enabled=True,
        governance_executive_default_window_days=30,
        governance_executive_page_size=20,
        governance_executive_max_report_rows=500,
        governance_executive_report_max_bytes=max_report_bytes,
    )


def _build_service(
    tmp_path: Any,
    *,
    recommendation: dict[str, Any] | None = None,
    max_report_bytes: int = 1024 * 1024,
) -> tuple[
    GovernanceExecutiveService, _FakeGovernance, _FakeIntelligenceRepository, _FakeIntelligenceService
]:
    url = f"sqlite:///{tmp_path}/v38-actions.db"
    init_db(url)
    factory = get_session_factory(url)
    repository = GovernanceExecutiveRepository(factory)
    automation = GovernanceAutomationRepository(factory)
    governance = _FakeGovernance()
    intelligence_repository = _FakeIntelligenceRepository(recommendation)
    intelligence_service = _FakeIntelligenceService()
    service = GovernanceExecutiveService(
        settings=_settings(max_report_bytes=max_report_bytes),
        repository=repository,
        governance_service=governance,
        governance_repository=SimpleNamespace(
            get_policy=lambda policy_id: {"policy_id": policy_id, "version": 3}
        ),
        forensic_repository=SimpleNamespace(summary=_forensic_summary),
        forensic_service=SimpleNamespace(summary=_forensic_summary),
        automation_repository=automation,
        intelligence_service=intelligence_service,
        intelligence_repository=intelligence_repository,
        clock=lambda: NOW,
    )
    return service, governance, intelligence_repository, intelligence_service


def _create_action(
    service: GovernanceExecutiveService,
    *,
    recommendation_id: str = "rec-v38",
    key: str = "action-key-1",
    title: str = "Mitigate critical forensic finding",
) -> dict[str, Any]:
    return service.create_action(
        {
            "recommendation_id": recommendation_id,
            "title": title,
            "description": "Strategic follow-up from a V37 recommendation.",
            "owner_id": "operator@example.com",
            "due_at": FUTURE,
            "priority": "HIGH",
            "idempotency_key": key,
            "reason": "Executive review requested this strategic action.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )


def _role_client(client: Any, email: str, role: Role) -> TestClient:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, email, role=role)
    plain = TestClient(client.app)
    login = plain.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert login.status_code == 200, login.text
    plain.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    return plain


def _seed_api_recommendation(client: Any) -> None:
    factory = get_session_factory(str(client.app.state.settings.database_url))
    with factory() as session:
        session.add(
            GovernanceRecommendationORM(
                id="rec-v38-api",
                recommendation_key="GOV-RISK-001|CASE|case-v38-api",
                rule_id="GOV-RISK-001",
                scope_type="CASE",
                scope_id="case-v38-api",
                case_id="case-v38-api",
                severity="CRITICAL",
                risk_level="CRITICAL",
                title="Review critical API recommendation",
                rationale="Synthetic V38 API fixture.",
                source_refs=[],
                status="OPEN",
                version=1,
                first_seen_at=NOW,
                last_evaluated_at=NOW,
                created_at=NOW,
                updated_at=NOW,
            )
        )
        session.commit()


# ---------------------------------------------------------------------------
# Strategic action lifecycle
# ---------------------------------------------------------------------------
def test_action_creation_is_idempotent_and_links_v37_recommendation(tmp_path: Any) -> None:
    service, governance, _, _ = _build_service(tmp_path, recommendation=_recommendation())

    first = _create_action(service)
    action = first["action"]
    assert action["status"] == "OPEN"
    assert action["version"] == 1
    assert action["recommendation_id"] == "rec-v38"
    assert action["recommendation_rule_id"] == "GOV-RISK-001"
    assert action["recommendation_severity"] == "CRITICAL"
    assert action["case_id"] == "case-v38"
    assert first["replayed"] is False
    assert first["recommendation_status"] == "OPEN"
    assert [event["event_type"] for event in first["events"]] == ["CREATED"]

    replay = _create_action(service)
    assert replay["replayed"] is True
    assert replay["action"]["action_id"] == action["action_id"]
    assert len(replay["events"]) == 1

    event_types = [event["event_type"] for event in governance.audit_events]
    assert event_types.count("EXECUTIVE_ACTION_CREATED") == 1
    assert governance.audit_events[0]["actor_role"] == "ADMIN"


def test_action_creation_rejects_non_actionable_recommendations(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation(status="DISMISSED"))
    with pytest.raises(RecommendationNotActionableError):
        _create_action(service)

    service, _, _, _ = _build_service(tmp_path, recommendation=None)
    with pytest.raises(RecommendationNotFoundForActionError):
        _create_action(service)


def test_action_lifecycle_transitions_are_validated_and_audited(tmp_path: Any) -> None:
    service, governance, intelligence_repository, _ = _build_service(
        tmp_path, recommendation=_recommendation()
    )
    created = _create_action(service)
    action_id = created["action"]["action_id"]

    started = service.transition_action(
        action_id,
        {
            "target_status": "IN_PROGRESS",
            "expected_version": 1,
            "reason": "Work started.",
        },
        actor_id="operator@example.com",
        actor_role="OPERATOR",
    )
    assert started["action"]["status"] == "IN_PROGRESS"
    assert started["action"]["version"] == 2
    assert started["from_status"] == "OPEN"
    assert started["to_status"] == "IN_PROGRESS"
    assert started["recommendation_resolved"] is False

    blocked = service.transition_action(
        action_id,
        {
            "target_status": "BLOCKED",
            "expected_version": 2,
            "block_reason": "Awaiting evidence review.",
        },
        actor_id="operator@example.com",
        actor_role="OPERATOR",
    )
    assert blocked["action"]["status"] == "BLOCKED"
    assert blocked["action"]["block_reason"] == "Awaiting evidence review."
    assert blocked["action"]["version"] == 3

    resumed = service.transition_action(
        action_id,
        {
            "target_status": "IN_PROGRESS",
            "expected_version": 3,
            "reason": "Evidence review completed.",
        },
        actor_id="operator@example.com",
        actor_role="OPERATOR",
    )
    assert resumed["action"]["version"] == 4

    completed = service.transition_action(
        action_id,
        {
            "target_status": "COMPLETED",
            "expected_version": 4,
            "outcome_summary": "Finding mitigated and verified.",
        },
        actor_id="operator@example.com",
        actor_role="OPERATOR",
    )
    assert completed["action"]["status"] == "COMPLETED"
    assert completed["action"]["outcome_summary"] == "Finding mitigated and verified."
    assert completed["action"]["version"] == 5
    event_types = [event["event_type"] for event in completed["events"]]
    assert sorted(event_types) == ["CREATED"] + ["TRANSITIONED"] * 4
    assert event_types.count("TRANSITIONED") == 4

    with pytest.raises(ActionStateError):
        service.transition_action(
            action_id,
            {
                "target_status": "CANCELLED",
                "expected_version": 5,
                "cancel_reason": "No longer needed.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )

    # The linked V37 recommendation is never resolved automatically.
    linked = service.action_detail(action_id)["linked_recommendation"]
    assert linked is not None
    assert linked["status"] == "OPEN"
    assert intelligence_repository.recommendation is not None

    event_types = [event["event_type"] for event in governance.audit_events]
    assert event_types.count("EXECUTIVE_ACTION_TRANSITIONED") == 4


def test_action_transition_requires_reason_and_expected_version(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    action_id = _create_action(service)["action"]["action_id"]

    with pytest.raises(ExecutiveValidationError):
        service.transition_action(
            action_id,
            {
                "target_status": "COMPLETED",
                "expected_version": 1,
                "outcome_summary": "",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(ExecutiveValidationError):
        service.transition_action(
            action_id,
            {
                "target_status": "BLOCKED",
                "expected_version": 1,
                "block_reason": "",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(ActionVersionConflictError):
        service.transition_action(
            action_id,
            {
                "target_status": "IN_PROGRESS",
                "expected_version": 99,
                "reason": "Stale write.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(ActionNotFoundError):
        service.transition_action(
            "missing-action",
            {
                "target_status": "IN_PROGRESS",
                "expected_version": 1,
                "reason": "Missing action.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_action_assignment_requires_reason_and_bumps_version(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    action_id = _create_action(service)["action"]["action_id"]

    assigned = service.assign_action(
        action_id,
        {
            "owner_id": "new-owner@example.com",
            "expected_version": 1,
            "reason": "Ownership transferred for executive review.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert assigned["action"]["owner_id"] == "new-owner@example.com"
    assert assigned["action"]["version"] == 2
    assert sorted(event["event_type"] for event in assigned["events"]) == [
        "ASSIGNED",
        "CREATED",
    ]

    with pytest.raises(ExecutiveValidationError):
        service.assign_action(
            action_id,
            {"owner_id": "x@example.com", "expected_version": 2, "reason": "no"},
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


# ---------------------------------------------------------------------------
# Executive reports
# ---------------------------------------------------------------------------
def test_report_generation_is_bounded_deterministic_and_idempotent(tmp_path: Any) -> None:
    service, governance, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    first = service.generate_report(
        {
            "report_type": "EXECUTIVE_SUMMARY",
            "format": "json",
            "window_days": 30,
            "idempotency_key": "report-key-1",
            "reason": "Monthly executive governance review.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )

    report = first["report"]
    payload = first["payload"]
    assert first["replayed"] is False
    assert report["report_type"] == "EXECUTIVE_SUMMARY"
    assert report["format"] == "json"
    assert report["schema_version"] == 1
    assert report["redaction_applied"] is True
    assert payload["report_type"] == "EXECUTIVE_SUMMARY"
    assert payload["schema_version"] == 1
    assert payload["window_days"] == 30
    assert payload["health_model_version"] == HEALTH_MODEL_VERSION
    assert payload["redaction_applied"] is True
    assert payload["sections"]["assurance"]["external_distribution"] is False
    assert payload["sections"]["assurance"]["pdf_supported"] is False
    assert payload["sections"]["assurance"]["email_supported"] is False
    assert list(payload["sections"]) == list(REPORT_SECTION_ORDER)
    assert [item["kpi_id"] for item in payload["sections"]["kpis"]["items"]] == list(KPI_ORDER)
    assert json.loads(first["content"])["report_type"] == "EXECUTIVE_SUMMARY"

    stored = service.get_report(report["report_id"])
    assert stored["integrity"]["report_digest_valid"] is True
    assert stored["integrity"]["snapshot_digest_valid"] is True
    assert stored["payload"] == payload

    replay = service.generate_report(
        {
            "report_type": "EXECUTIVE_SUMMARY",
            "format": "json",
            "window_days": 30,
            "idempotency_key": "report-key-1",
            "reason": "Monthly executive governance review.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert replay["replayed"] is True
    assert replay["report"]["report_id"] == report["report_id"]

    event_types = [event["event_type"] for event in governance.audit_events]
    assert event_types.count("EXECUTIVE_REPORT_GENERATED") == 1
    assert event_types.count("EXECUTIVE_REPORT_VIEWED") == 1


def test_report_csv_is_a_deterministic_flat_export(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    generated = service.generate_report(
        {
            "report_type": "EXECUTIVE_SLA",
            "format": "csv",
            "window_days": 30,
            "idempotency_key": "report-csv-1",
            "reason": "Executive SLA review export.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert generated["media_type"] == "text/csv"
    assert generated["content"].startswith("path,value\n")
    assert "sections.sla.availability" in generated["content"]
    assert "report_type,EXECUTIVE_SLA" in generated["content"]

    content = service.get_report_content(generated["report"]["report_id"])
    assert content["media_type"] == "text/csv"
    assert content["content"] == generated["content"]


def test_report_detects_snapshot_and_metadata_tampering(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    generated = service.generate_report(
        {
            "report_type": "EXECUTIVE_SUMMARY",
            "format": "json",
            "window_days": 30,
            "idempotency_key": "report-tamper-1",
            "reason": "Integrity validation review.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    report_id = generated["report"]["report_id"]
    factory = get_session_factory(f"sqlite:///{tmp_path / 'v38-actions.db'}")

    with factory() as session:
        session.execute(
            text("UPDATE governance_snapshots SET payload = :payload WHERE id = :snapshot_id"),
            {
                "payload": json.dumps({"report_type": "EXECUTIVE_SUMMARY", "schema_version": 1}),
                "snapshot_id": generated["report"]["snapshot_id"],
            },
        )
        session.commit()
    with pytest.raises(ReportIntegrityError):
        service.get_report(report_id)

    with factory() as session:
        session.execute(
            text("UPDATE governance_executive_reports SET report_digest = :digest WHERE id = :report_id"),
            {"digest": "f" * 64, "report_id": report_id},
        )
        session.commit()
    with pytest.raises(ReportIntegrityError):
        service.get_report(report_id)


def test_report_missing_and_oversized_payloads_are_explicit(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    with pytest.raises(ReportNotFoundError):
        service.get_report("missing-report")

    (tmp_path / "tiny").mkdir()
    tiny_service, _, _, _ = _build_service(
        tmp_path / "tiny", recommendation=_recommendation(), max_report_bytes=100
    )
    with pytest.raises(ReportUnavailableError):
        tiny_service.generate_report(
            {
                "report_type": "EXECUTIVE_SUMMARY",
                "format": "json",
                "window_days": 30,
                "idempotency_key": "report-too-large",
                "reason": "Bounded report size validation.",
            },
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


def test_report_redacts_credential_bearing_fields(tmp_path: Any) -> None:
    service, _, _, intelligence_service = _build_service(tmp_path, recommendation=_recommendation())
    intelligence_service.risk = {
        "risk_level_counts": {
            "CRITICAL": 1,
            "api_key": "sk_live_51H8xQ2eZvKYlo2C",
        },
        "truncated": False,
        "unavailable_case_count": 0,
        "partial": False,
    }
    generated = service.generate_report(
        {
            "report_type": "EXECUTIVE_RISK",
            "format": "json",
            "window_days": 30,
            "idempotency_key": "report-redaction-1",
            "reason": "Redaction validation review.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    content = generated["content"]
    assert "[REDACTED]" in content
    assert "sk_live_51H8xQ2eZvKYlo2C" not in content
    assert generated["payload"]["redaction_applied"] is True


# ---------------------------------------------------------------------------
# Compatible historical comparisons
# ---------------------------------------------------------------------------
def test_comparison_rejects_incompatible_periods_without_interpolation(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    baseline = service.generate_report(
        {
            "report_type": "EXECUTIVE_SUMMARY",
            "format": "json",
            "window_days": 30,
            "idempotency_key": "compare-baseline",
            "reason": "Baseline executive report.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    current = service.generate_report(
        {
            "report_type": "EXECUTIVE_SUMMARY",
            "format": "json",
            "window_days": 7,
            "idempotency_key": "compare-current",
            "reason": "Current executive report.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    result = service.compare_reports(
        baseline["report"]["report_id"],
        other_report_id=current["report"]["report_id"],
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert result["status"] == "INCOMPATIBLE"
    assert result["comparable"] is False
    assert result["interpolated"] is False
    assert result["fabricated_history"] is False
    assert any(item["code"] == "PERIOD_LENGTH_MISMATCH" for item in result["incompatibilities"])


def test_comparison_explains_model_versions_and_unavailable_sources(tmp_path: Any) -> None:
    service, _, intelligence_repository, intelligence_service = _build_service(
        tmp_path, recommendation=_recommendation()
    )
    baseline = service.generate_report(
        {
            "report_type": "EXECUTIVE_SLA",
            "format": "json",
            "window_days": 30,
            "idempotency_key": "compare-model-baseline",
            "reason": "Baseline model comparison report.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )

    intelligence_repository.risk_model = {
        "model_id": "RISK-DEFAULT",
        "version": 2,
        "name": "Updated risk model",
    }
    intelligence_service.sla = {
        "state_counts": {"DISPOSITION_REVIEW": {"UNKNOWN": 2}},
        "availability": {"DISPOSITION_REVIEW": {"availability": "UNAVAILABLE"}},
        "unavailable_sources": ["DISPOSITION_REVIEW"],
        "truncated": False,
    }
    current = service.generate_report(
        {
            "report_type": "EXECUTIVE_SLA",
            "format": "json",
            "window_days": 30,
            "idempotency_key": "compare-model-current",
            "reason": "Current model comparison report.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    result = service.compare_reports(
        baseline["report"]["report_id"],
        other_report_id=current["report"]["report_id"],
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert result["status"] == "INCOMPATIBLE"
    codes = {item["code"] for item in result["incompatibilities"]}
    assert "RISK_MODEL_VERSION_MISMATCH" in codes
    gap_codes = {item["code"] for item in result["gaps"]}
    assert "SOURCE_UNAVAILABLE" in gap_codes
    for gap in result["gaps"]:
        assert "delta" not in gap
    assert result["model_versions"]["baseline_risk_model"] == "1"
    assert result["model_versions"]["current_risk_model"] == "2"


def test_comparison_current_period_is_read_only_and_explicit(tmp_path: Any) -> None:
    service, governance, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    baseline = service.generate_report(
        {
            "report_type": "EXECUTIVE_SUMMARY",
            "format": "json",
            "window_days": 30,
            "idempotency_key": "compare-current-period",
            "reason": "Current-period comparison baseline.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    result = service.compare_reports(
        baseline["report"]["report_id"],
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert result["current"]["label"] == "CURRENT"
    assert result["baseline"]["report_id"] == baseline["report"]["report_id"]
    assert result["interpolated"] is False
    assert result["source_preserved"] is True
    assert "EXECUTIVE_COMPARISON_VIEWED" in [event["event_type"] for event in governance.audit_events]


# ---------------------------------------------------------------------------
# Configuration writes
# ---------------------------------------------------------------------------
def test_config_write_appends_snapshot_and_replays_idempotently(tmp_path: Any) -> None:
    service, governance, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    updated = service.update_config(
        {
            **DEFAULT_EXECUTIVE_CONFIG,
            "default_window_days": 14,
            "action_due_soon_hours": 48,
        },
        reason="Executive operating cadence changed.",
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert updated["config"]["default_window_days"] == 14
    assert updated["config"]["action_due_soon_hours"] == 48
    assert updated["replayed"] is False
    assert updated["snapshot_id"]
    assert updated["health_thresholds_fixed"] is True

    read = service.config()
    assert read["availability"] == "OK"
    assert read["config"]["default_window_days"] == 14
    assert read["source"]["digest_valid"] is True

    replay = service.update_config(
        {
            **DEFAULT_EXECUTIVE_CONFIG,
            "default_window_days": 14,
            "action_due_soon_hours": 48,
        },
        reason="Executive operating cadence changed.",
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert replay["replayed"] is True
    assert replay["snapshot_id"] == updated["snapshot_id"]

    event_types = [event["event_type"] for event in governance.audit_events]
    assert event_types.count("EXECUTIVE_CONFIG_UPDATED") == 1

    with pytest.raises(ExecutiveValidationError):
        service.update_config(
            {"default_window_days": 90, "unknown_key": True},
            reason="Invalid configuration test.",
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )
    with pytest.raises(ExecutiveValidationError):
        service.update_config(
            {"health_thresholds_fixed": False},
            reason="Attempt to change fixed thresholds.",
            actor_id="admin@example.com",
            actor_role="ADMIN",
        )


# ---------------------------------------------------------------------------
# API, RBAC, and stable envelopes
# ---------------------------------------------------------------------------
def test_executive_action_and_report_api_rbac(client: Any) -> None:
    _seed_api_recommendation(client)
    admin = client
    payload = {
        "recommendation_id": "rec-v38-api",
        "title": "Mitigate critical API finding",
        "description": "Strategic follow-up from a V37 recommendation.",
        "owner_id": "operator-v38@example.com",
        "due_at": "2099-12-01T12:00:00Z",
        "priority": "HIGH",
        "idempotency_key": "api-action-1",
        "reason": "Executive review requested this strategic action.",
    }
    created = admin.post("/api/v1/governance/executive/actions", json=payload)
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["action"]["status"] == "OPEN"
    action_id = body["action"]["action_id"]

    replay = admin.post("/api/v1/governance/executive/actions", json=payload)
    assert replay.status_code == 200, replay.text
    assert replay.json()["replayed"] is True
    assert replay.json()["action"]["action_id"] == action_id

    viewer = _role_client(admin, "viewer-v38-actions@example.com", Role.VIEWER)
    forbidden = viewer.post("/api/v1/governance/executive/actions", json=payload)
    assert forbidden.status_code == 403
    assert forbidden.json()["error"]["code"]

    operator = _role_client(admin, "operator-v38-actions@example.com", Role.OPERATOR)
    operator_payload = {**payload, "idempotency_key": "api-action-operator"}
    operator_created = operator.post("/api/v1/governance/executive/actions", json=operator_payload)
    assert operator_created.status_code == 200, operator_created.text
    operator_action_id = operator_created.json()["action"]["action_id"]

    transitioned = operator.post(
        f"/api/v1/governance/executive/actions/{operator_action_id}/transition",
        json={
            "target_status": "IN_PROGRESS",
            "expected_version": 1,
            "reason": "Operator started the work.",
        },
    )
    assert transitioned.status_code == 200, transitioned.text
    assert transitioned.json()["action"]["status"] == "IN_PROGRESS"

    detail = viewer.get(f"/api/v1/governance/executive/actions/{operator_action_id}")
    assert detail.status_code == 403

    report_payload = {
        "report_type": "EXECUTIVE_SUMMARY",
        "format": "json",
        "window_days": 30,
        "idempotency_key": "api-report-1",
        "reason": "Executive summary API report.",
    }
    generated = admin.post("/api/v1/governance/executive/reports", json=report_payload)
    assert generated.status_code == 200, generated.text
    report_id = generated.json()["report"]["report_id"]

    assert viewer.post("/api/v1/governance/executive/reports", json=report_payload).status_code == 403
    assert operator.post("/api/v1/governance/executive/reports", json=report_payload).status_code == 403
    assert viewer.get(f"/api/v1/governance/executive/reports/{report_id}").status_code == 403
    assert operator.get(f"/api/v1/governance/executive/reports/{report_id}").status_code == 200

    content = operator.get(f"/api/v1/governance/executive/reports/{report_id}/content")
    assert content.status_code == 200
    assert content.headers["content-type"].startswith("application/json")
    assert json.loads(content.text)["report_type"] == "EXECUTIVE_SUMMARY"

    comparison = operator.get(f"/api/v1/governance/executive/comparisons/{report_id}")
    assert comparison.status_code == 200, comparison.text
    assert comparison.json()["interpolated"] is False

    config_payload = {
        "config": {**DEFAULT_EXECUTIVE_CONFIG, "default_window_days": 21},
        "reason": "API configuration update.",
    }
    assert operator.put("/api/v1/governance/executive/config", json=config_payload).status_code == 403
    updated = admin.put("/api/v1/governance/executive/config", json=config_payload)
    assert updated.status_code == 200, updated.text
    assert updated.json()["config"]["default_window_days"] == 21

    anonymous = TestClient(admin.app)
    assert anonymous.get("/api/v1/governance/executive/actions").status_code == 401


def test_executive_action_and_report_api_stable_errors(client: Any) -> None:
    missing = client.get("/api/v1/governance/executive/actions/missing-action")
    assert missing.status_code == 404
    assert missing.json()["error"]["code"] == "not_found"

    invalid = client.post(
        "/api/v1/governance/executive/actions",
        json={
            "recommendation_id": "missing",
            "title": "x",
            "owner_id": "",
            "due_at": "2099-12-01T12:00:00Z",
            "idempotency_key": "bad-action",
            "reason": "short",
        },
    )
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"

    missing_report = client.get("/api/v1/governance/executive/reports/missing-report")
    assert missing_report.status_code == 404
    assert missing_report.json()["error"]["code"] == "not_found"

    disabled = client.app.state.governance_executive_service
    client.app.state.governance_executive_service = None
    try:
        unavailable = client.get("/api/v1/governance/executive/actions")
        assert unavailable.status_code == 503
        assert unavailable.json()["error"]["code"] == "executive_not_ready"
    finally:
        client.app.state.governance_executive_service = disabled
