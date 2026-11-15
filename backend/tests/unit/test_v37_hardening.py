"""V37 governance intelligence hardening tests.

Synthetic, deterministic, local-only. These tests target the seams that are
easy to get wrong in production: optimistic-concurrency lost updates, metric
label cardinality, cross-case leakage, SQL-like identifiers, bounded trend
windows, version changes, and regression compatibility with V10/V14/V15/V16 and
V29-V36. No external service, evidence file, or live infrastructure is used.
"""

from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.core.metrics import (
    metrics_payload,
    record_governance_intelligence_refresh,
    record_governance_intelligence_score,
    record_governance_intelligence_snapshot_comparison,
    set_governance_intelligence_sla_counts,
)
from backend.app.core.redaction import redact_text
from backend.app.governance.intelligence.constants import (
    DEFAULT_FACTOR_POINTS,
    DEFAULT_RISK_THRESHOLDS,
    MAX_TREND_WINDOW_DAYS,
    TREND_SOURCE_ORDER,
    recommendation_key,
)
from backend.app.governance.intelligence.errors import (
    RecommendationStateError,
    RecommendationVersionConflictError,
)
from backend.app.governance.intelligence.repository import GovernanceIntelligenceRepository
from backend.app.governance.intelligence.scoring import score_case
from backend.app.governance.intelligence.service import GovernanceIntelligenceService
from backend.app.infrastructure.db import get_session_factory, init_db
from backend.app.models.governance_intelligence_orm import GovernanceRecommendationORM
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _real_repository(tmp_path: Any) -> tuple[GovernanceIntelligenceRepository, Any]:
    url = f"sqlite:///{tmp_path}/v37-hardening.db"
    init_db(url)
    factory = get_session_factory(url)
    repository = GovernanceIntelligenceRepository(factory)
    repository.ensure_defaults(now=NOW)
    return repository, factory


def _candidate(
    scope_id: str = "case-a",
    *,
    rule_id: str = "GOV-RISK-001",
    case_id: str | None = None,
    severity: str = "CRITICAL",
) -> dict[str, Any]:
    resolved_case = case_id if case_id is not None else scope_id
    return {
        "rule_id": rule_id,
        "scope_type": "CASE",
        "scope_id": scope_id,
        "case_id": resolved_case,
        "severity": severity,
        "risk_level": "CRITICAL" if severity == "CRITICAL" else "HIGH",
        "title": "Synthetic deterministic recommendation.",
        "rationale": f"Synthetic deterministic rationale for {resolved_case}.",
        "source_refs": [f"risk_case:{resolved_case}"],
    }


def _role_client(client: Any, email: str, role: Role) -> TestClient:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, email, role=role)
    plain = TestClient(client.app)
    login = plain.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert login.status_code == 200, login.text
    plain.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    return plain


def _all_keys(value: Any) -> set[str]:
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(str(key).lower())
            keys.update(_all_keys(child))
    elif isinstance(value, list):
        for child in value:
            keys.update(_all_keys(child))
    return keys


# ---------------------------------------------------------------------------
# Concurrency and optimistic locking
# ---------------------------------------------------------------------------
def test_transition_compare_and_set_prevents_lost_update(tmp_path: Any, monkeypatch: Any) -> None:
    """A competing writer that commits after our read must not be overwritten."""
    repository, factory = _real_repository(tmp_path)
    created = repository.sync_recommendations([_candidate()], now=NOW)
    recommendation_id = created["created_ids"][0]

    # Simulate a competing writer that committed version 2 after our stale read.
    with factory() as session:
        row = session.get(GovernanceRecommendationORM, recommendation_id)
        assert row is not None
        row.status = "ACKNOWLEDGED"
        row.version = 2
        row.updated_at = NOW
        session.commit()

    stale = SimpleNamespace(
        id=recommendation_id,
        version=1,
        status="OPEN",
        rule_id="GOV-RISK-001",
    )
    original_get = Session.get
    stale_used = False

    def stale_then_real_get(self: Session, entity: Any, ident: Any, *args: Any, **kwargs: Any):
        nonlocal stale_used
        if entity is GovernanceRecommendationORM and not stale_used:
            stale_used = True
            return stale
        return original_get(self, entity, ident, *args, **kwargs)

    monkeypatch.setattr(Session, "get", stale_then_real_get)

    with pytest.raises(RecommendationVersionConflictError) as excinfo:
        repository.transition_recommendation(
            recommendation_id,
            target_status="ACKNOWLEDGED",
            expected_version=1,
            actor_id="operator@example.com",
            actor_role="OPERATOR",
            reason="Concurrent stale write must fail.",
            now=NOW + timedelta(minutes=1),
        )
    assert excinfo.value.expected == 1
    assert excinfo.value.actual == 2

    events = repository.recommendation_events(recommendation_id)
    assert [event["event_type"] for event in events] == ["CREATED"]
    current = repository.get_recommendation(recommendation_id)
    assert current is not None
    assert current["version"] == 2
    assert current["status"] == "ACKNOWLEDGED"


def test_concurrent_transitions_record_exactly_one_event(tmp_path: Any) -> None:
    repository, _ = _real_repository(tmp_path)
    created = repository.sync_recommendations([_candidate()], now=NOW)
    recommendation_id = created["created_ids"][0]
    barrier = threading.Barrier(2)

    def attempt(actor: str) -> str:
        barrier.wait(timeout=10)
        try:
            repository.transition_recommendation(
                recommendation_id,
                target_status="ACKNOWLEDGED",
                expected_version=1,
                actor_id=actor,
                actor_role="ADMIN",
                reason="Concurrent acknowledgement.",
                now=NOW + timedelta(minutes=1),
            )
            return "ok"
        except (RecommendationVersionConflictError, RecommendationStateError):
            return "conflict"
        except Exception as exc:  # noqa: BLE001 - surfaced as a failed assertion
            return f"error:{type(exc).__name__}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ["admin-a@example.com", "admin-b@example.com"]))

    assert results.count("ok") == 1, results
    assert all(result in {"ok", "conflict"} for result in results), results
    events = repository.recommendation_events(recommendation_id)
    assert [event["event_type"] for event in events].count("ACKNOWLEDGED") == 1
    current = repository.get_recommendation(recommendation_id)
    assert current is not None
    assert current["version"] == 2


def test_duplicate_candidates_in_one_refresh_create_one_row(tmp_path: Any) -> None:
    repository, _ = _real_repository(tmp_path)
    candidate = _candidate()
    summary = repository.sync_recommendations([candidate, dict(candidate)], now=NOW)
    assert summary["created"] == 1
    assert summary["truncated"] is False
    items, total = repository.list_recommendations(page=1, page_size=10)
    assert total == 1
    assert items[0]["recommendation_key"] == recommendation_key("GOV-RISK-001", "CASE", "case-a")


def test_concurrent_refreshes_do_not_duplicate_or_crash(tmp_path: Any) -> None:
    repository, _ = _real_repository(tmp_path)
    barrier = threading.Barrier(2)

    def refresh() -> str:
        barrier.wait(timeout=10)
        try:
            repository.sync_recommendations([_candidate()], now=NOW)
            return "ok"
        except Exception as exc:  # noqa: BLE001 - surfaced as a failed assertion
            return f"error:{type(exc).__name__}"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: refresh(), range(2)))

    assert results == ["ok", "ok"], results
    items, total = repository.list_recommendations(page=1, page_size=10)
    assert total == 1
    assert items[0]["recommendation_key"] == recommendation_key("GOV-RISK-001", "CASE", "case-a")


def test_stale_recommendations_auto_resolve_once_and_stay_resolved(tmp_path: Any) -> None:
    repository, _ = _real_repository(tmp_path)
    created = repository.sync_recommendations([_candidate()], now=NOW)
    recommendation_id = created["created_ids"][0]

    first = repository.sync_recommendations([], now=NOW + timedelta(hours=1))
    assert first["auto_resolved"] == 1
    resolved = repository.get_recommendation(recommendation_id)
    assert resolved is not None
    assert resolved["status"] == "RESOLVED"
    assert resolved["version"] == 2

    second = repository.sync_recommendations([], now=NOW + timedelta(hours=2))
    assert second["auto_resolved"] == 0
    unchanged = repository.get_recommendation(recommendation_id)
    assert unchanged is not None
    assert unchanged["version"] == 2


# ---------------------------------------------------------------------------
# Cross-case isolation and sensitive payload boundaries
# ---------------------------------------------------------------------------
def test_recommendations_and_snapshots_never_mix_cases(client: Any) -> None:
    repository = client.app.state.governance_intelligence_repository
    repository.sync_recommendations(
        [
            _candidate("case-a"),
            _candidate("case-b", rule_id="GOV-RISK-002", severity="HIGH"),
        ],
        now=datetime.now(UTC),
    )

    listing = client.get(
        "/api/v1/governance/intelligence/recommendations",
        params={"page_size": 100},
    )
    assert listing.status_code == 200, listing.text
    by_case = {
        item["case_id"]: item for item in listing.json()["items"] if item["case_id"] in {"case-a", "case-b"}
    }
    assert set(by_case) == {"case-a", "case-b"}
    for case_id, item in by_case.items():
        foreign = "case-b" if case_id == "case-a" else "case-a"
        assert foreign not in json.dumps(item)
        assert all(foreign not in ref for ref in item["source_refs"])
        detail = client.get(f"/api/v1/governance/intelligence/recommendations/{item['recommendation_id']}")
        assert detail.status_code == 200, detail.text
        assert foreign not in json.dumps(detail.json())

    generated = client.post(
        "/api/v1/governance/intelligence/snapshots",
        json={
            "idempotency_key": "v37-hardening-cross-case",
            "reason": "Synthetic cross-case isolation snapshot.",
        },
    )
    assert generated.status_code == 200, generated.text
    snapshot_id = generated.json()["snapshot"]["snapshot_id"]
    detail = client.get(f"/api/v1/governance/intelligence/snapshots/{snapshot_id}")
    assert detail.status_code == 200, detail.text
    payload = detail.json()["snapshot"]["payload"]
    serialized = json.dumps(payload)
    assert "case-a" not in serialized
    assert "case-b" not in serialized


def test_snapshot_payload_has_no_case_or_evidence_identifiers(client: Any) -> None:
    generated = client.post(
        "/api/v1/governance/intelligence/snapshots",
        json={
            "idempotency_key": "v37-hardening-payload-boundary",
            "reason": "Synthetic payload boundary snapshot.",
        },
    )
    assert generated.status_code == 200, generated.text
    snapshot_id = generated.json()["snapshot"]["snapshot_id"]
    detail = client.get(f"/api/v1/governance/intelligence/snapshots/{snapshot_id}")
    assert detail.status_code == 200, detail.text
    payload = detail.json()["snapshot"]["payload"]
    keys = _all_keys(payload)
    forbidden = {
        "case_id",
        "evidence_id",
        "evidence_reference_id",
        "storage_path",
        "file_path",
        "path",
        "sha256",
        "payload_digest",
    }
    assert keys.isdisjoint(forbidden), keys & forbidden
    serialized = json.dumps(payload).lower()
    assert "case-a" not in serialized
    assert "evidence_id" not in serialized


# ---------------------------------------------------------------------------
# Bounded inputs and identifier handling
# ---------------------------------------------------------------------------
def test_api_identifiers_and_filters_are_not_sql_and_never_500(client: Any) -> None:
    injection = "' OR 1=1 --"
    for path in (
        f"/api/v1/governance/intelligence/risk/cases/{injection}",
        f"/api/v1/governance/intelligence/recommendations/{injection}",
        f"/api/v1/governance/intelligence/snapshots/{injection}",
        f"/api/v1/governance/intelligence/snapshots/{injection}/compare/{injection}",
    ):
        response = client.get(path)
        assert response.status_code == 404, (path, response.status_code, response.text)

    for path, params in (
        ("/api/v1/governance/intelligence/recommendations", {"status": injection}),
        ("/api/v1/governance/intelligence/recommendations", {"severity": injection}),
        ("/api/v1/governance/intelligence/recommendations", {"rule_id": injection}),
        ("/api/v1/governance/intelligence/risk/cases", {"risk_level": injection}),
        ("/api/v1/governance/intelligence/trends", {"bucket": injection}),
        ("/api/v1/governance/intelligence/sla/backlog", {"state": injection}),
    ):
        response = client.get(path, params=params)
        assert response.status_code == 422, (path, params, response.status_code, response.text)

    oversized = "a" * 500
    response = client.get(
        "/api/v1/governance/intelligence/trends",
        params={"start_at": oversized, "end_at": oversized},
    )
    assert response.status_code == 422


def test_trends_default_window_is_capped_at_ninety_days() -> None:
    class _GovernanceRepository:
        def historical_coverage(self) -> dict[str, str | None]:
            return {
                "governance_audit": None,
                "retention_evaluations": None,
                "legal_holds": None,
                "dispositions": None,
                "export_approvals": None,
            }

        def audit_timestamps_in_range(self, *args: Any, **kwargs: Any) -> list[Any]:
            return []

        def retention_timestamps_in_range(self, *args: Any, **kwargs: Any) -> list[Any]:
            return []

        def legal_hold_timestamps_in_range(self, *args: Any, **kwargs: Any) -> list[Any]:
            return []

        def disposition_timestamps_in_range(self, *args: Any, **kwargs: Any) -> list[Any]:
            return []

        def export_approval_timestamps_in_range(self, *args: Any, **kwargs: Any) -> list[Any]:
            return []

    class _IntelligenceRepository:
        def recommendation_timestamps_in_range(self, *args: Any, **kwargs: Any) -> list[Any]:
            return []

        def recommendation_coverage_start(self) -> None:
            return None

    service = GovernanceIntelligenceService(
        settings=SimpleNamespace(
            governance_intelligence_enabled=True,
            governance_enabled=True,
            governance_intelligence_default_window_days=365,
        ),
        repository=_IntelligenceRepository(),
        governance_service=SimpleNamespace(),
        governance_repository=_GovernanceRepository(),
        forensic_repository=SimpleNamespace(),
        clock=lambda: NOW,
    )
    payload = service.trends()
    assert payload["start_at"] == (NOW - timedelta(days=MAX_TREND_WINDOW_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert payload["end_at"] == NOW.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert payload["source_order"] == list(TREND_SOURCE_ORDER)
    # A 90-day UTC window can touch 91 day-bucket starts because both ends are
    # inclusive of the day containing the boundary.
    assert len(payload["sources"]["governance_events"]["buckets"]) <= MAX_TREND_WINDOW_DAYS + 1


# ---------------------------------------------------------------------------
# Metric cardinality
# ---------------------------------------------------------------------------
def test_metric_labels_are_bounded_for_user_controlled_values() -> None:
    token = "v37-user-controlled-case-123456"
    record_governance_intelligence_score(
        risk_level=token,
        data_completeness=token,
        service="v37-hardening",
    )
    record_governance_intelligence_refresh(token, service="v37-hardening")
    record_governance_intelligence_snapshot_comparison(token, service="v37-hardening")
    set_governance_intelligence_sla_counts(token, {token: 1}, service="v37-hardening")

    payload = metrics_payload().decode("utf-8")
    assert token not in payload
    assert 'risk_level="UNKNOWN"' in payload
    assert 'data_completeness="UNKNOWN"' in payload
    assert 'outcome="UNKNOWN"' in payload
    assert 'status="UNKNOWN"' in payload
    assert 'target_key="UNKNOWN"' in payload
    assert 'state="UNKNOWN"' in payload


# ---------------------------------------------------------------------------
# Version changes preserve history
# ---------------------------------------------------------------------------
def test_model_and_sla_version_changes_preserve_snapshot_history(client: Any) -> None:
    before = client.post(
        "/api/v1/governance/intelligence/snapshots",
        json={
            "idempotency_key": "v37-hardening-version-before",
            "reason": "Synthetic snapshot before a model version change.",
        },
    )
    assert before.status_code == 200, before.text
    before_snapshot = before.json()["snapshot"]
    assert before_snapshot["payload"]["model"]["version"] == 1

    updated = client.put(
        "/api/v1/governance/intelligence/risk/model",
        json={
            "name": "Hardening model v2",
            "thresholds": {key: dict(value) for key, value in DEFAULT_RISK_THRESHOLDS.items()},
            "factor_points": dict(DEFAULT_FACTOR_POINTS),
            "expected_version": 1,
            "reason": "Synthetic model version for hardening tests.",
        },
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["model"]["version"] == 2

    after = client.post(
        "/api/v1/governance/intelligence/snapshots",
        json={
            "idempotency_key": "v37-hardening-version-after",
            "reason": "Synthetic snapshot after a model version change.",
        },
    )
    assert after.status_code == 200, after.text
    after_snapshot = after.json()["snapshot"]
    assert after_snapshot["payload"]["model"]["version"] == 2

    old_detail = client.get(f"/api/v1/governance/intelligence/snapshots/{before_snapshot['snapshot_id']}")
    assert old_detail.status_code == 200, old_detail.text
    assert old_detail.json()["snapshot"]["payload"]["model"]["version"] == 1

    compared = client.get(
        "/api/v1/governance/intelligence/snapshots/"
        f"{before_snapshot['snapshot_id']}/compare/{after_snapshot['snapshot_id']}"
    )
    assert compared.status_code == 200, compared.text
    assert compared.json()["status"] == "COMPARED"
    assert any(change["path"] == "model.version" for change in compared.json()["changes"])

    sla_update = client.put(
        "/api/v1/governance/intelligence/sla/targets/RETENTION_REVIEW",
        json={
            "target_hours": 480,
            "warning_hours": 120,
            "effective_from": (NOW + timedelta(days=30)).isoformat(),
            "expected_version": 1,
            "reason": "Synthetic SLA version for hardening tests.",
        },
    )
    assert sla_update.status_code == 200, sla_update.text
    assert sla_update.json()["target"]["version"] == 2

    versions = client.get(
        "/api/v1/governance/intelligence/sla/targets",
        params={"target_key": "RETENTION_REVIEW", "page_size": 100},
    )
    assert versions.status_code == 200, versions.text
    assert {item["version"] for item in versions.json()["items"]} == {1, 2}
    assert all(item["target_hours"] == 720 for item in versions.json()["items"] if item["version"] == 1)


def test_scoring_policy_context_is_versioned_from_evaluation_snapshot() -> None:
    model = {
        "model_id": "RISK-DEFAULT",
        "version": 1,
        "thresholds": {key: dict(value) for key, value in DEFAULT_RISK_THRESHOLDS.items()},
        "factor_points": dict(DEFAULT_FACTOR_POINTS),
    }
    result = score_case(
        case_id="case-policy",
        case={"case_id": "case-policy", "case_type": "FORENSIC_REVIEW", "severity": "LOW"},
        evaluation={
            "evaluation_id": "eval-policy",
            "governance_state": "ACTIVE",
            "policy_snapshot": {
                "policy_id": "policy-1",
                "version": 1,
                "state": "ENABLED",
                "case_type": "FORENSIC_REVIEW",
            },
        },
        verification=None,
        verification_error=None,
        holds=[],
        disposition=None,
        export_approvals=[],
        policy={"policy_id": "policy-1", "version": 1, "state": "ENABLED"},
        incident=None,
        incident_error=None,
        sla_context={},
        model=model,
        now=NOW,
    )
    assert result["policy_context"]["policy_id"] == "policy-1"
    assert result["policy_context"]["policy_version"] == 1
    assert result["model_version"] == 1


# ---------------------------------------------------------------------------
# RBAC and platform regressions
# ---------------------------------------------------------------------------
def test_unauthenticated_intelligence_access_is_denied(client: Any) -> None:
    anonymous = TestClient(client.app)
    for path in (
        "/api/v1/governance/intelligence/status",
        "/api/v1/governance/intelligence/risk/model",
        "/api/v1/governance/intelligence/sla/targets",
        "/api/v1/governance/intelligence/trends",
        "/api/v1/governance/intelligence/recommendations",
        "/api/v1/governance/intelligence/snapshots",
    ):
        assert anonymous.get(path).status_code == 401, path
    assert (
        anonymous.post(
            "/api/v1/governance/intelligence/snapshots",
            json={"idempotency_key": "anonymous", "reason": "anonymous must fail"},
        ).status_code
        == 401
    )


def test_platform_regression_smoke(client: Any) -> None:
    """V10/V14/V15/V16/V29-V36 surfaces remain reachable and unchanged."""
    for path in (
        "/api/v1/incidents",
        "/api/v1/analytics/summary",
        "/api/v1/alerts",
        "/api/v1/forensics/status",
        "/api/v1/integrity/status",
        "/api/v1/governance/status",
        "/api/v1/governance/automation/status",
    ):
        response = client.get(path)
        assert response.status_code == 200, (path, response.status_code, response.text)

    redacted = redact_text("Authorization: Bearer v37-hardening-secret-token")
    assert "v37-hardening-secret-token" not in redacted
    assert "Bearer" in redacted

    viewer = _role_client(client, "v37-hardening-viewer@example.com", Role.VIEWER)
    assert viewer.get("/api/v1/governance/intelligence/status").status_code == 200
    assert (
        viewer.put(
            "/api/v1/governance/intelligence/sla/targets/RETENTION_REVIEW",
            json={
                "target_hours": 12,
                "warning_hours": 6,
                "reason": "viewer must be denied",
            },
        ).status_code
        == 403
    )
