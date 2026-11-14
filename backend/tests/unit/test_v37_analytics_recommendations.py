"""V37 governance intelligence analytics, recommendations, and snapshots.

Synthetic, deterministic, local-only tests. They exercise bounded trend reads,
the advisory recommendation lifecycle, local snapshot generation and comparison,
and server-side RBAC. No external service, evidence file, or live infrastructure
is involved, and no test approves a disposition, releases a hold, modifies
evidence, or deletes a record.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from fastapi.testclient import TestClient

from backend.app.auth.repository import AuthRepository
from backend.app.auth.roles import Role
from backend.app.governance.intelligence.constants import (
    INTELLIGENCE_ASSURANCE,
    RECOMMENDATION_RULES,
    SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY,
    TREND_SOURCE_ORDER,
    recommendation_key,
)
from backend.app.governance.intelligence.service import GovernanceIntelligenceService
from backend.app.infrastructure.db import get_session_factory
from backend.app.models.governance_automation_orm import GovernanceSnapshotORM
from backend.tests.auth_helpers import TEST_PASSWORD, create_test_user

NOW = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Bounded trend analytics
# ---------------------------------------------------------------------------
class _TrendGovernanceRepository:
    def __init__(
        self,
        *,
        audit: list[dict[str, Any]] | None = None,
        retention: list[dict[str, Any]] | None = None,
        holds: list[dict[str, Any]] | None = None,
        dispositions: list[dict[str, Any]] | None = None,
        approvals: list[dict[str, Any]] | None = None,
        coverage: dict[str, str | None] | None = None,
        fail: str | None = None,
    ) -> None:
        self.audit = audit or []
        self.retention = retention or []
        self.holds = holds or []
        self.dispositions = dispositions or []
        self.approvals = approvals or []
        self.coverage = coverage or {
            "governance_audit": None,
            "retention_evaluations": None,
            "legal_holds": None,
            "dispositions": None,
            "export_approvals": None,
        }
        self.fail = fail

    def _check(self, name: str) -> None:
        if self.fail == name:
            raise RuntimeError(f"synthetic {name} failure")

    def historical_coverage(self) -> dict[str, str | None]:
        self._check("coverage")
        return self.coverage

    def audit_timestamps_in_range(self, start: Any, end: Any, *, limit: int = 5000):
        self._check("audit")
        return self.audit

    def retention_timestamps_in_range(self, start: Any, end: Any, *, limit: int = 5000):
        self._check("retention")
        return self.retention

    def legal_hold_timestamps_in_range(self, start: Any, end: Any, *, limit: int = 5000):
        self._check("holds")
        return self.holds

    def disposition_timestamps_in_range(self, start: Any, end: Any, *, limit: int = 5000):
        self._check("dispositions")
        return self.dispositions

    def export_approval_timestamps_in_range(self, start: Any, end: Any, *, limit: int = 5000):
        self._check("approvals")
        return self.approvals


class _TrendIntelligenceRepository:
    def __init__(
        self,
        *,
        events: list[dict[str, Any]] | None = None,
        coverage_start: str | None = None,
        fail: bool = False,
    ) -> None:
        self.events = events or []
        self.coverage_start = coverage_start
        self.fail = fail

    def recommendation_timestamps_in_range(self, start: Any, end: Any, *, limit: int = 5000):
        if self.fail:
            raise RuntimeError("synthetic recommendation failure")
        return self.events

    def recommendation_coverage_start(self) -> str | None:
        if self.fail:
            raise RuntimeError("synthetic recommendation coverage failure")
        return self.coverage_start


def _trend_service(
    governance_repository: Any, repository: Any | None = None
) -> GovernanceIntelligenceService:
    return GovernanceIntelligenceService(
        settings=SimpleNamespace(
            governance_intelligence_enabled=True,
            governance_enabled=True,
            governance_intelligence_default_window_days=30,
        ),
        repository=repository or _TrendIntelligenceRepository(),
        governance_service=SimpleNamespace(),
        governance_repository=governance_repository,
        forensic_repository=SimpleNamespace(),
        clock=lambda: NOW,
    )


def test_trends_are_bounded_and_risk_history_is_unavailable_not_zero() -> None:
    service = _trend_service(_TrendGovernanceRepository())
    payload = service.trends(
        start_at="2026-11-01T00:00:00Z",
        end_at="2026-11-05T00:00:00Z",
        bucket="day",
    )
    assert payload["start_at"] == "2026-11-01T00:00:00Z"
    assert payload["end_at"] == "2026-11-05T00:00:00Z"
    assert payload["bucket"] == "day"
    assert payload["timezone"] == "UTC"
    assert payload["source_order"] == list(TREND_SOURCE_ORDER)
    assert set(payload["sources"]) == set(TREND_SOURCE_ORDER)
    assert len(payload["sources"]["governance_events"]["buckets"]) == 4

    risk = payload["sources"]["risk_scores"]
    assert risk["availability"] == "UNAVAILABLE"
    assert risk["total"] == 0
    assert risk["category_totals"] == {}
    assert all(bucket["count"] is None for bucket in risk["buckets"])
    assert "not persisted" in risk["message"]

    audit = payload["sources"]["governance_events"]
    assert audit["availability"] == "OK"
    assert audit["no_history"] is True
    assert audit["coverage_start"] is None
    assert all(bucket["coverage"] == "NO_HISTORY" for bucket in audit["buckets"])
    assert all(bucket["count"] is None for bucket in audit["buckets"])
    assert payload["partial"] is True
    assert "risk_scores" in payload["unavailable_sources"]
    assert payload["assurance"] == INTELLIGENCE_ASSURANCE


def test_trends_mark_gaps_before_coverage_and_keep_actual_counts() -> None:
    # Earliest stored audit event is 2026-11-02T10:00Z. The bucket starting
    # 2026-11-02 straddles the coverage boundary and must be marked partial.
    repository = _TrendGovernanceRepository(
        audit=[
            {"event_type": "CASE_VIEWED", "created_at": "2026-11-02T10:00:00Z"},
            {"event_type": "RETENTION_EVALUATION_CREATED", "created_at": "2026-11-03T10:00:00Z"},
        ],
        coverage={
            "governance_audit": "2026-11-02T10:00:00Z",
            "retention_evaluations": None,
            "legal_holds": None,
            "dispositions": None,
            "export_approvals": None,
        },
    )
    service = _trend_service(repository)
    payload = service.trends(
        start_at="2026-11-01T00:00:00Z",
        end_at="2026-11-04T00:00:00Z",
        bucket="day",
    )
    buckets = payload["sources"]["governance_events"]["buckets"]
    assert [bucket["coverage"] for bucket in buckets] == [
        "BEFORE_COVERAGE",
        "IN_COVERAGE",
        "IN_COVERAGE",
    ]
    assert [bucket["count"] for bucket in buckets] == [None, 1, 1]
    assert buckets[0]["in_coverage"] is False
    assert buckets[1]["partial_coverage"] is True
    assert buckets[2]["partial_coverage"] is False
    assert payload["sources"]["governance_events"]["total"] == 2
    assert payload["sources"]["governance_events"]["category_totals"]["ACCESS"] == 1
    assert payload["sources"]["governance_events"]["category_totals"]["RETENTION"] == 1


def test_trends_report_unavailable_sources_without_inventing_zero() -> None:
    repository = _TrendGovernanceRepository(fail="audit")
    service = _trend_service(repository)
    payload = service.trends(
        start_at="2026-11-01T00:00:00Z",
        end_at="2026-11-02T00:00:00Z",
        bucket="hour",
    )
    audit = payload["sources"]["governance_events"]
    assert audit["availability"] == "UNAVAILABLE"
    assert audit["coverage_available"] is False
    assert all(bucket["count"] is None for bucket in audit["buckets"])
    assert all(bucket["coverage"] == "UNKNOWN" for bucket in audit["buckets"])
    assert "governance_events" in payload["unavailable_sources"]
    assert payload["partial"] is True


def test_trends_report_unknown_coverage_honestly() -> None:
    repository = _TrendGovernanceRepository(fail="coverage")
    service = _trend_service(repository)
    payload = service.trends(
        start_at="2026-11-01T00:00:00Z",
        end_at="2026-11-02T00:00:00Z",
        bucket="day",
    )
    assert payload["coverage"]["available"] is False
    assert "could not be read" in payload["coverage"]["message"]
    for source in payload["sources"].values():
        if source["availability"] == "UNAVAILABLE" or source["no_history"]:
            continue
        assert all(bucket["in_coverage"] is None for bucket in source["buckets"])
        assert all(bucket["coverage"] == "UNKNOWN" for bucket in source["buckets"])
    # A source with its own readable coverage (recommendation events) may
    # legitimately report NO_HISTORY while the global coverage read failed.
    recommendations = payload["sources"]["recommendations"]
    assert recommendations["coverage_available"] is True
    assert recommendations["no_history"] is True
    assert payload["partial"] is True


def test_trends_reject_malicious_or_unbounded_ranges() -> None:
    service = _trend_service(_TrendGovernanceRepository())
    for start, end, bucket in (
        ("2026-11-05T00:00:00Z", "2026-11-01T00:00:00Z", "day"),
        ("2025-01-01T00:00:00Z", "2026-11-01T00:00:00Z", "day"),
        ("2026-11-01T00:00:00Z", "2026-11-02T00:00:00Z", "minute"),
        ("not-a-timestamp", "2026-11-02T00:00:00Z", "day"),
    ):
        try:
            service.trends(start_at=start, end_at=end, bucket=bucket)
        except Exception as exc:  # noqa: BLE001 - asserting sanitized validation
            assert "invalid trend window" in str(exc)
        else:  # pragma: no cover - defensive
            raise AssertionError(f"range should be rejected: {start}..{end} {bucket}")


def test_trends_api_defaults_and_malicious_queries(client: Any) -> None:
    default = client.get("/api/v1/governance/intelligence/trends")
    assert default.status_code == 200, default.text
    payload = default.json()
    assert payload["bucket"] == "day"
    assert payload["source_order"] == list(TREND_SOURCE_ORDER)
    assert payload["sources"]["risk_scores"]["availability"] == "UNAVAILABLE"
    assert payload["assurance"] == INTELLIGENCE_ASSURANCE

    end = datetime.now(UTC)
    start = end - timedelta(days=2)
    explicit = client.get(
        "/api/v1/governance/intelligence/trends",
        params={
            "start_at": start.isoformat(),
            "end_at": end.isoformat(),
            "bucket": "hour",
        },
    )
    assert explicit.status_code == 200, explicit.text
    assert explicit.json()["bucket"] == "hour"

    assert (
        client.get(
            "/api/v1/governance/intelligence/trends",
            params={"start_at": "2026-11-05T00:00:00Z", "end_at": "2026-11-01T00:00:00Z"},
        ).status_code
        == 422
    )
    assert (
        client.get(
            "/api/v1/governance/intelligence/trends",
            params={"start_at": "2025-01-01T00:00:00Z", "end_at": "2026-11-01T00:00:00Z"},
        ).status_code
        == 422
    )
    assert (
        client.get(
            "/api/v1/governance/intelligence/trends",
            params={"bucket": "DROP TABLE"},
        ).status_code
        == 422
    )


# ---------------------------------------------------------------------------
# Advisory recommendation lifecycle
# ---------------------------------------------------------------------------
def _candidate(
    rule_id: str = "GOV-RISK-001",
    *,
    scope_type: str = "CASE",
    scope_id: str = "case-1",
    case_id: str | None = "case-1",
    severity: str = "CRITICAL",
    rationale: str = "Synthetic deterministic recommendation.",
) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "scope_type": scope_type,
        "scope_id": scope_id,
        "case_id": case_id,
        "severity": severity,
        "risk_level": "CRITICAL" if severity == "CRITICAL" else "HIGH",
        "title": RECOMMENDATION_RULES[rule_id][0],
        "rationale": rationale,
        "source_refs": [f"risk_case:{case_id or scope_id}"],
    }


def _role_client(client: Any, email: str, role: Role) -> TestClient:
    repo = AuthRepository(get_session_factory(str(client.app.state.settings.database_url)))
    create_test_user(repo, email, role=role)
    plain = TestClient(client.app)
    login = plain.post("/api/v1/auth/login", json={"email": email, "password": TEST_PASSWORD})
    assert login.status_code == 200, login.text
    plain.headers["X-CSRF-Token"] = login.json()["csrf_token"]
    return plain


def test_recommendation_sync_is_deduplicated_and_lifecycle_managed(client: Any) -> None:
    repository = client.app.state.governance_intelligence_repository
    first = repository.sync_recommendations([_candidate()], now=NOW)
    assert first["created"] == 1
    assert first["refreshed"] == 0
    assert len(first["created_ids"]) == 1

    second = repository.sync_recommendations([_candidate()], now=NOW + timedelta(minutes=5))
    assert second["created"] == 0
    assert second["refreshed"] == 1

    key = recommendation_key("GOV-RISK-001", "CASE", "case-1")
    items, total = repository.list_recommendations(page=1, page_size=10)
    assert total == 1
    recommendation = items[0]
    assert recommendation["recommendation_key"] == key
    assert recommendation["status"] == "OPEN"

    acknowledged = repository.transition_recommendation(
        recommendation["recommendation_id"],
        target_status="ACKNOWLEDGED",
        expected_version=1,
        actor_id="operator@example.com",
        actor_role="OPERATOR",
        reason="Operator reviewed the case.",
        now=NOW + timedelta(minutes=10),
    )
    assert acknowledged["status"] == "ACKNOWLEDGED"
    assert acknowledged["version"] == 2
    assert acknowledged["acknowledged_by"] == "operator@example.com"

    dismissed = repository.transition_recommendation(
        recommendation["recommendation_id"],
        target_status="DISMISSED",
        expected_version=2,
        actor_id="admin@example.com",
        actor_role="ADMIN",
        reason="Duplicate of an existing review task.",
        now=NOW + timedelta(minutes=20),
    )
    assert dismissed["status"] == "DISMISSED"
    assert dismissed["version"] == 3
    assert dismissed["dismissal_reason"] == "Duplicate of an existing review task."

    events = repository.recommendation_events(recommendation["recommendation_id"])
    assert [event["event_type"] for event in events] == [
        "CREATED",
        "ACKNOWLEDGED",
        "DISMISSED",
    ]
    assert events[-1]["actor_role"] == "ADMIN"

    suppressed = repository.sync_recommendations([_candidate()], now=NOW + timedelta(minutes=30))
    assert suppressed["suppressed"] == 1
    assert suppressed["created"] == 0
    assert repository.get_recommendation(recommendation["recommendation_id"])["status"] == "DISMISSED"


def test_recommendation_sync_auto_resolves_and_reopens(tmp_path: Any) -> None:
    # Use the real repository with a temporary database instead of duplicating
    # the application's SQLAlchemy setup here.
    from backend.app.governance.intelligence.repository import (
        GovernanceIntelligenceRepository,
    )
    from backend.app.infrastructure.db import get_session_factory, init_db

    url = f"sqlite:///{tmp_path}/recommendations.db"
    init_db(url)
    repository = GovernanceIntelligenceRepository(get_session_factory(url))
    repository.ensure_defaults(now=NOW)

    created = repository.sync_recommendations([_candidate()], now=NOW)
    assert created["created"] == 1
    identifier = created["created_ids"][0]

    cleared = repository.sync_recommendations([], now=NOW + timedelta(minutes=5))
    assert cleared["auto_resolved"] == 1
    resolved = repository.get_recommendation(identifier)
    assert resolved["status"] == "RESOLVED"
    assert resolved["resolved_by"] == "SYSTEM"

    reopened = repository.sync_recommendations([_candidate()], now=NOW + timedelta(minutes=10))
    assert reopened["reopened"] == 1
    assert reopened["created"] == 0
    assert reopened["reopened_ids"] == [identifier]
    current = repository.get_recommendation(identifier)
    assert current["status"] == "OPEN"
    assert current["version"] == 3

    bounded = repository.sync_recommendations(
        [
            _candidate("GOV-RISK-001", scope_id="case-1"),
            _candidate("GOV-RISK-002", scope_id="case-2", case_id="case-2", severity="HIGH"),
        ],
        now=NOW + timedelta(minutes=15),
        max_items=1,
    )
    assert bounded["truncated"] is True


def test_recommendation_api_refresh_and_rbac(client: Any) -> None:
    viewer = _role_client(client, "v37-analytics-viewer@example.com", Role.VIEWER)
    operator = _role_client(client, "v37-analytics-operator@example.com", Role.OPERATOR)

    repository = client.app.state.governance_intelligence_repository
    repository.sync_recommendations([_candidate()], now=datetime.now(UTC))
    items, _ = repository.list_recommendations(page=1, page_size=10)
    recommendation_id = items[0]["recommendation_id"]

    listing = client.get("/api/v1/governance/intelligence/recommendations")
    assert listing.status_code == 200, listing.text
    assert listing.json()["total"] >= 1
    assert listing.json()["items"][0]["recommendation_id"]
    assert viewer.get("/api/v1/governance/intelligence/recommendations").status_code == 200
    assert operator.get("/api/v1/governance/intelligence/recommendations").status_code == 200

    detail = client.get(f"/api/v1/governance/intelligence/recommendations/{recommendation_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["recommendation"]["recommendation_id"] == recommendation_id
    assert detail.json()["events"][0]["event_type"] == "CREATED"
    assert detail.json()["non_claims"]

    acknowledged = operator.post(
        f"/api/v1/governance/intelligence/recommendations/{recommendation_id}/acknowledge",
        json={"reason": "Operator triage.", "expected_version": 1},
    )
    assert acknowledged.status_code == 200, acknowledged.text
    assert acknowledged.json()["recommendation"]["status"] == "ACKNOWLEDGED"

    stale = client.post(
        f"/api/v1/governance/intelligence/recommendations/{recommendation_id}/dismiss",
        json={"reason": "Stale write must fail.", "expected_version": 1},
    )
    assert stale.status_code == 409

    assert (
        operator.post(
            f"/api/v1/governance/intelligence/recommendations/{recommendation_id}/dismiss",
            json={"reason": "Operator must not dismiss."},
        ).status_code
        == 403
    )
    assert (
        viewer.post(
            f"/api/v1/governance/intelligence/recommendations/{recommendation_id}/dismiss",
            json={"reason": "Viewer must not dismiss."},
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/v1/governance/intelligence/recommendations/{recommendation_id}/dismiss",
            json={"reason": "x"},
        ).status_code
        == 422
    )
    dismissed = client.post(
        f"/api/v1/governance/intelligence/recommendations/{recommendation_id}/dismiss",
        json={"reason": "Administrator confirmed duplicate.", "expected_version": 2},
    )
    assert dismissed.status_code == 200, dismissed.text
    assert dismissed.json()["recommendation"]["status"] == "DISMISSED"
    assert dismissed.json()["recommendation"]["dismissal_reason"] == ("Administrator confirmed duplicate.")

    again = client.post(
        f"/api/v1/governance/intelligence/recommendations/{recommendation_id}/dismiss",
        json={"reason": "Second dismissal must fail."},
    )
    assert again.status_code == 409

    refresh = operator.post(
        "/api/v1/governance/intelligence/recommendations/refresh",
        json={"reason": "Synthetic operator refresh."},
    )
    assert refresh.status_code == 200, refresh.text
    summary = refresh.json()["summary"]
    assert summary["created"] == 0
    # The synthetic recommendation has no matching live condition, so the
    # refresh resolves it rather than inventing a new advisory item.
    assert summary["auto_resolved"] >= 1
    assert "snapshots" in refresh.json()["sources"]
    assert viewer.post("/api/v1/governance/intelligence/recommendations/refresh").status_code == 403
    missing = client.get("/api/v1/governance/intelligence/recommendations/does-not-exist")
    assert missing.status_code == 404


def test_recommendation_candidates_never_mix_cases() -> None:
    class _Forensics:
        def list_cases(self, *, page: int, page_size: int):
            return [
                {
                    "case_id": "case-a",
                    "case_number": "CASE-A",
                    "case_type": "FORENSIC_REVIEW",
                    "severity": "CRITICAL",
                    "status": "OPEN",
                },
                {
                    "case_id": "case-b",
                    "case_number": "CASE-B",
                    "case_type": "FORENSIC_REVIEW",
                    "severity": "HIGH",
                    "status": "OPEN",
                },
            ], 2

        def latest_verification(self, case_id: str):
            if case_id == "case-a":
                return {
                    "verification_id": "ver-a",
                    "outcome": "FAIL",
                    "report": {},
                    "metadata": {},
                }
            return None

        def list_evidence_references(self, case_id: str):
            return []

        def get_case(self, case_id: str):
            return None

    class _GovernanceRepository:
        def latest_evaluations(self, *, limit: int):
            return []

        def latest_evaluation(self, case_id: str):
            return None

        def list_holds(self, case_id: str, *, page: int = 1, page_size: int = 100):
            return [], 0

        def latest_disposition(self, case_id: str):
            return None

        def list_export_approvals(self, *, case_id: str, page_size: int = 100):
            return [], 0

        def latest_enabled_policies(self):
            return []

        def sla_target_versions(self, target_key: str):
            return [
                {
                    "version": 1,
                    "target_hours": 720,
                    "warning_hours": 168,
                    "effective_from": "1970-01-01T00:00:00Z",
                }
            ]

    class _IntelligenceRepository:
        def latest_risk_model(self):
            return {
                "model_id": "RISK-DEFAULT",
                "version": 1,
                "thresholds": {
                    "LOW": {"min": 0, "max": 24},
                    "MODERATE": {"min": 25, "max": 49},
                    "HIGH": {"min": 50, "max": 74},
                    "CRITICAL": {"min": 75, "max": 100},
                },
                "factor_points": {
                    "CONFIRMED_INTEGRITY_FAILURE": 50,
                    "CASE_SEVERITY_CRITICAL": 50,
                    "CASE_SEVERITY_HIGH": 50,
                },
            }

        def recommendation_timestamps_in_range(self, *args: Any, **kwargs: Any):
            return []

        def recommendation_coverage_start(self):
            return None

        def sla_target_versions(self, target_key: str):
            return [
                {
                    "version": 1,
                    "target_hours": 720,
                    "warning_hours": 168,
                    "effective_from": "1970-01-01T00:00:00Z",
                }
            ]

    service = GovernanceIntelligenceService(
        settings=SimpleNamespace(
            governance_intelligence_enabled=True,
            governance_enabled=True,
            governance_intelligence_max_cases=10,
            governance_intelligence_max_recommendations=10,
        ),
        repository=_IntelligenceRepository(),
        governance_service=SimpleNamespace(),
        governance_repository=_GovernanceRepository(),
        forensic_repository=_Forensics(),
        clock=lambda: NOW,
    )
    candidates, sources = service._recommendation_candidates(  # noqa: SLF001 - deterministic seam
        now=NOW, model=_IntelligenceRepository().latest_risk_model()
    )
    assert sources["cases"]["availability"] == "OK"
    risk_candidates = [item for item in candidates if item["rule_id"].startswith("GOV-RISK")]
    assert {item["case_id"] for item in risk_candidates} == {"case-a", "case-b"}
    for item in candidates:
        assert item["case_id"] in {"case-a", "case-b"}
        foreign = "case-b" if item["case_id"] == "case-a" else "case-a"
        assert not any(foreign in ref for ref in item["source_refs"])
        assert foreign not in item["rationale"]


# ---------------------------------------------------------------------------
# Local intelligence snapshots and comparison
# ---------------------------------------------------------------------------
def _generate(client: Any, key: str) -> dict[str, Any]:
    response = client.post(
        "/api/v1/governance/intelligence/snapshots",
        json={"idempotency_key": key, "reason": "Synthetic snapshot for local testing."},
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_intelligence_snapshot_generation_is_idempotent_and_listed_without_payload(
    client: Any,
) -> None:
    first = _generate(client, "v37-snapshot-1")
    assert first["replayed"] is False
    snapshot = first["snapshot"]
    assert snapshot["snapshot_type"] == SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY
    assert snapshot["digest_valid"] is True
    assert snapshot["payload"]["assurance"] == INTELLIGENCE_ASSURANCE
    assert snapshot["payload"]["model"]["version"] == 1

    replay = _generate(client, "v37-snapshot-1")
    assert replay["replayed"] is True
    assert replay["snapshot"]["snapshot_id"] == snapshot["snapshot_id"]

    listing = client.get("/api/v1/governance/intelligence/snapshots")
    assert listing.status_code == 200, listing.text
    body = listing.json()
    assert body["availability"] == "OK"
    assert body["total"] >= 1
    assert all("payload" not in item for item in body["items"])
    assert all(item["snapshot_type"] == SNAPSHOT_TYPE_INTELLIGENCE_SUMMARY for item in body["items"])

    detail = client.get(f"/api/v1/governance/intelligence/snapshots/{snapshot['snapshot_id']}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["integrity"]["state"] == "VALID"
    assert detail.json()["snapshot"]["payload"]

    missing = client.get("/api/v1/governance/intelligence/snapshots/does-not-exist")
    assert missing.status_code == 404


def test_snapshot_comparison_reports_compatible_and_incompatible(client: Any) -> None:
    left = _generate(client, "v37-snapshot-compare-a")["snapshot"]
    right = _generate(client, "v37-snapshot-compare-b")["snapshot"]
    compared = client.get(
        f"/api/v1/governance/intelligence/snapshots/{left['snapshot_id']}/compare/{right['snapshot_id']}"
    )
    assert compared.status_code == 200, compared.text
    body = compared.json()
    assert body["status"] == "COMPARED"
    assert body["comparable"] is True
    assert body["tampered_snapshot_ids"] == []
    assert isinstance(body["changes"], list)
    assert "not regulatory certification" in body["message"]
    assert "not externally anchored" in body["message"]

    compliance = client.post(
        "/api/v1/governance/automation/snapshots",
        json={
            "idempotency_key": "v37-compliance-incompatible",
            "reason": "Synthetic compliance snapshot for compatibility testing.",
        },
    )
    assert compliance.status_code == 200, compliance.text
    compliance_id = compliance.json()["snapshot"]["snapshot_id"]
    incompatible = client.get(
        f"/api/v1/governance/intelligence/snapshots/{left['snapshot_id']}/compare/{compliance_id}"
    )
    assert incompatible.status_code == 200, incompatible.text
    assert incompatible.json()["status"] == "INCOMPATIBLE"
    assert incompatible.json()["comparable"] is False
    assert incompatible.json()["diff"] is None


def test_snapshot_tampering_is_detected_and_never_diffed(client: Any) -> None:
    snapshot = _generate(client, "v37-snapshot-tamper")["snapshot"]
    snapshot_id = snapshot["snapshot_id"]
    other = _generate(client, "v37-snapshot-tamper-other")["snapshot"]

    session_factory = get_session_factory(str(client.app.state.settings.database_url))
    with session_factory() as session:
        row = session.get(GovernanceSnapshotORM, snapshot_id)
        assert row is not None
        payload = dict(row.payload)
        risk = dict(payload["risk"])
        counts = dict(risk["risk_level_counts"])
        counts["CRITICAL"] = int(counts.get("CRITICAL", 0)) + 1
        risk["risk_level_counts"] = counts
        payload["risk"] = risk
        row.payload = payload
        session.commit()

    detail = client.get(f"/api/v1/governance/intelligence/snapshots/{snapshot_id}")
    assert detail.status_code == 200, detail.text
    assert detail.json()["integrity"]["state"] == "INTEGRITY_FAILED"
    assert detail.json()["integrity"]["digest_valid"] is False

    compared = client.get(
        f"/api/v1/governance/intelligence/snapshots/{snapshot_id}/compare/{other['snapshot_id']}"
    )
    assert compared.status_code == 200, compared.text
    body = compared.json()
    assert body["status"] == "INTEGRITY_FAILED"
    assert body["comparable"] is False
    assert body["diff"] is None
    assert snapshot_id in body["tampered_snapshot_ids"]
    assert "preserved for investigation" in body["message"]


def test_intelligence_snapshot_rbac(client: Any) -> None:
    viewer = _role_client(client, "v37-snapshot-viewer@example.com", Role.VIEWER)
    operator = _role_client(client, "v37-snapshot-operator@example.com", Role.OPERATOR)

    assert viewer.get("/api/v1/governance/intelligence/snapshots").status_code == 200
    assert (
        viewer.post(
            "/api/v1/governance/intelligence/snapshots",
            json={"idempotency_key": "viewer-snapshot", "reason": "viewer denied"},
        ).status_code
        == 403
    )
    generated = operator.post(
        "/api/v1/governance/intelligence/snapshots",
        json={"idempotency_key": "operator-snapshot", "reason": "operator snapshot"},
    )
    assert generated.status_code == 200, generated.text
    snapshot_id = generated.json()["snapshot"]["snapshot_id"]
    assert viewer.get(f"/api/v1/governance/intelligence/snapshots/{snapshot_id}").status_code == 200
