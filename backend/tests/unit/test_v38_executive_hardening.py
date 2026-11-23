"""V38 executive governance hardening: concurrency, bounds, and isolation.

Synthetic, deterministic, local-only. These tests exercise the adversarial
edges of the executive layer: concurrent idempotent writes, bounded metric
labels, append-only history, cross-case isolation, redaction, and API route
surface. No live infrastructure is contacted.
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import pytest
from pydantic import ValidationError

from backend.app.api.v1.governance_executive import router as executive_router
from backend.app.auth.roles import Role
from backend.app.core.metrics import (
    metrics_payload,
    record_governance_executive_action_transition,
    record_governance_executive_comparison,
    record_governance_executive_report,
    set_governance_executive_action_counts,
    set_governance_executive_health,
    set_governance_executive_kpi_availability,
)
from backend.app.governance.executive.errors import ActionVersionConflictError
from backend.app.governance.executive.schemas import ExecutiveConfigUpdateRequest
from backend.tests.unit.test_v38_executive_actions_reports import (
    FUTURE,
    _build_service,
    _create_action,
    _recommendation,
    _role_client,
    _seed_api_recommendation,
)

_SECRET_TOKEN = "ghp_" + "A" * 36


class _TwoCaseRecommendations:
    """Recommendation repository exposing two distinct synthetic cases."""

    def __init__(self) -> None:
        self.recommendations = {
            "rec-case-a": _recommendation(recommendation_id="rec-case-a"),
            "rec-case-b": _recommendation(recommendation_id="rec-case-b"),
        }
        self.recommendations["rec-case-a"]["case_id"] = "case-a"
        self.recommendations["rec-case-b"]["case_id"] = "case-b"

    def get_recommendation(self, recommendation_id: str) -> dict[str, Any] | None:
        value = self.recommendations.get(recommendation_id)
        return dict(value) if value is not None else None

    def recommendation_counts(self) -> dict[str, Any]:
        return {
            "total": 2,
            "by_status": {"OPEN": 2},
            "by_severity": {"CRITICAL": 2},
            "by_status_severity": {"OPEN": {"CRITICAL": 2}},
        }

    def latest_risk_model(self) -> dict[str, Any]:
        return {"model_id": "RISK-DEFAULT", "version": 1, "name": "Default risk model"}


def _action_payload(*, key: str, description: str = "Strategic follow-up.") -> dict[str, Any]:
    return {
        "recommendation_id": "rec-v38",
        "title": "Mitigate critical forensic finding",
        "description": description,
        "owner_id": "operator@example.com",
        "due_at": FUTURE,
        "priority": "HIGH",
        "idempotency_key": key,
        "reason": "Executive review requested this strategic action.",
    }


def _report_payload(*, key: str, report_format: str = "json") -> dict[str, Any]:
    return {
        "report_type": "EXECUTIVE_SUMMARY",
        "format": report_format,
        "window_days": 30,
        "idempotency_key": key,
        "reason": "Hardening test report.",
    }


# ---------------------------------------------------------------------------
# Concurrency and optimistic concurrency
# ---------------------------------------------------------------------------
def test_concurrent_action_creation_is_idempotent_and_audited_once(tmp_path: Any) -> None:
    service, governance, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    payload = _action_payload(key="concurrent-action")

    def create() -> dict[str, Any]:
        return service.create_action(payload, actor_id="admin@example.com", actor_role="ADMIN")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: create(), range(2)))

    assert sorted(bool(result["replayed"]) for result in results) == [False, True]
    assert len({result["action"]["action_id"] for result in results}) == 1
    action_id = str(results[0]["action"]["action_id"])
    assert service._repository.count_actions() == 1
    created_events = [
        event for event in service._repository.action_events(action_id) if event["event_type"] == "CREATED"
    ]
    assert len(created_events) == 1
    audit_types = [event["event_type"] for event in governance.audit_events]
    assert audit_types.count("EXECUTIVE_ACTION_CREATED") == 1


def test_concurrent_transitions_apply_once_and_conflict_once(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    action = _create_action(service)
    action_id = str(action["action"]["action_id"])

    def transition() -> dict[str, Any]:
        return service.transition_action(
            action_id,
            {
                "target_status": "IN_PROGRESS",
                "expected_version": 1,
                "reason": "Operator started the work.",
            },
            actor_id="operator@example.com",
            actor_role="OPERATOR",
        )

    outcomes: list[str] = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(transition) for _ in range(2)]
        for future in as_completed(futures):
            try:
                future.result()
                outcomes.append("applied")
            except ActionVersionConflictError:
                outcomes.append("conflict")

    assert sorted(outcomes) == ["applied", "conflict"]
    stored = service._repository.get_action(action_id)
    assert stored is not None
    assert stored["status"] == "IN_PROGRESS"
    assert stored["version"] == 2
    transitions = [
        event
        for event in service._repository.action_events(action_id)
        if event["event_type"] == "TRANSITIONED"
    ]
    assert len(transitions) == 1


def test_concurrent_report_generation_reuses_stored_snapshot_without_duplicate_audit(
    tmp_path: Any,
) -> None:
    service, governance, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    payload = _report_payload(key="concurrent-report")

    def generate() -> dict[str, Any]:
        return service.generate_report(payload, actor_id="admin@example.com", actor_role="ADMIN")

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: generate(), range(2)))

    assert sorted(bool(result["replayed"]) for result in results) == [False, True]
    assert len({result["report"]["report_id"] for result in results}) == 1
    assert results[0]["content"] == results[1]["content"]
    assert service._repository.count_reports() == 1
    snapshots, total = service._automation.list_snapshots(snapshot_type="EXECUTIVE_SUMMARY")
    assert total == 1
    assert len(snapshots) == 1
    audit_types = [event["event_type"] for event in governance.audit_events]
    assert audit_types.count("EXECUTIVE_REPORT_GENERATED") == 1


# ---------------------------------------------------------------------------
# Bounded metrics
# ---------------------------------------------------------------------------
def test_executive_metrics_labels_are_bounded() -> None:
    hostile = "V38/SENTINEL/UNBOUNDED"
    set_governance_executive_health(hostile, service=hostile)
    set_governance_executive_kpi_availability(
        {"FORENSIC_OPEN_CASES": hostile, hostile: "AVAILABLE"}, service=hostile
    )
    set_governance_executive_action_counts({"OPEN": 1, hostile: 999}, service=hostile)
    record_governance_executive_report(hostile, hostile, hostile, service=hostile)
    record_governance_executive_comparison(hostile, service=hostile)
    record_governance_executive_action_transition(hostile, hostile, hostile, service=hostile)
    record_governance_executive_report("EXECUTIVE_SUMMARY", "json", "GENERATED")

    payload = metrics_payload().decode("utf-8")
    assert "SENTINEL" not in payload
    assert 'service="unknown"' in payload
    assert 'status="UNKNOWN"' in payload
    assert 'format="unknown"' in payload
    assert 'format="json"' in payload

    report_series = [
        line for line in payload.splitlines() if line.startswith("ivp_governance_executive_reports_total{")
    ]
    # Four report types x three bounded formats x four outcomes x at most two services.
    assert len(report_series) <= 96


def test_executive_kpi_metric_reports_unavailable_without_zero() -> None:
    service_label = "v38-hardening"
    set_governance_executive_kpi_availability({"FORENSIC_OPEN_CASES": "UNAVAILABLE"}, service=service_label)
    payload = metrics_payload().decode("utf-8")
    matching = [
        line
        for line in payload.splitlines()
        if line.startswith("ivp_governance_executive_kpi_availability{")
        and 'kpi_id="FORENSIC_OPEN_CASES"' in line
        and f'service="{service_label}"' in line
    ]
    assert len(matching) == 3
    unavailable = [line for line in matching if 'availability="UNAVAILABLE"' in line]
    assert len(unavailable) == 1
    assert unavailable[0].endswith("} 1.0")


# ---------------------------------------------------------------------------
# Route surface and bounded request bodies
# ---------------------------------------------------------------------------
def test_executive_api_has_no_delete_route_for_protected_history(client: Any) -> None:
    routes = list(executive_router.routes)
    assert routes
    assert not [route for route in routes if "DELETE" in set(getattr(route, "methods", set()))]
    assert client.delete("/api/v1/governance/executive/reports/any").status_code == 405
    assert client.patch("/api/v1/governance/executive/actions/any").status_code == 405


def test_config_update_schema_bounds_keys_and_values() -> None:
    with pytest.raises(ValidationError):
        ExecutiveConfigUpdateRequest(
            config={f"key-{index}": 1 for index in range(40)},
            reason="Oversized configuration request.",
        )
    with pytest.raises(ValidationError):
        ExecutiveConfigUpdateRequest(
            config={"default_window_days": "x" * 300},
            reason="Oversized configuration value.",
        )
    with pytest.raises(ValidationError):
        ExecutiveConfigUpdateRequest(
            config={"default_window_days": {"nested": True}},
            reason="Nested configuration value.",
        )


# ---------------------------------------------------------------------------
# Cross-case isolation and redaction
# ---------------------------------------------------------------------------
def test_cross_case_actions_keep_separate_recommendation_and_case_links(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    service._intelligence_repository = _TwoCaseRecommendations()

    first = service.create_action(
        {**_action_payload(key="case-a-action"), "recommendation_id": "rec-case-a"},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    second = service.create_action(
        {**_action_payload(key="case-b-action"), "recommendation_id": "rec-case-b"},
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert first["action"]["case_id"] == "case-a"
    assert second["action"]["case_id"] == "case-b"

    first_detail = service.action_detail(str(first["action"]["action_id"]))
    second_detail = service.action_detail(str(second["action"]["action_id"]))
    assert first_detail["linked_recommendation"]["case_id"] == "case-a"
    assert second_detail["linked_recommendation"]["case_id"] == "case-b"
    assert "case-b" not in json.dumps(first_detail, sort_keys=True)
    assert "case-a" not in json.dumps(second_detail, sort_keys=True)

    filtered, total = service._repository.list_actions(recommendation_id="rec-case-a")
    assert total == 1
    assert filtered[0]["case_id"] == "case-a"


def test_action_text_and_event_history_redact_credentials(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    created = service.create_action(
        _action_payload(
            key="redacted-action",
            description=f"Do not share {_SECRET_TOKEN} with anyone.",
        ),
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    action_id = str(created["action"]["action_id"])
    detail = service.action_detail(action_id)
    serialized = json.dumps(detail, sort_keys=True)
    assert _SECRET_TOKEN not in serialized
    assert "REDACTED" in serialized

    transitioned = service.transition_action(
        action_id,
        {
            "target_status": "COMPLETED",
            "expected_version": 1,
            "reason": "Finished the review.",
            "outcome_summary": f"Token {_SECRET_TOKEN} was handled.",
        },
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    assert _SECRET_TOKEN not in json.dumps(transitioned, sort_keys=True)


def test_api_audit_records_are_redacted_for_executive_writes(client: Any) -> None:
    _seed_api_recommendation(client)
    admin = _role_client(client, "admin-v38-redaction@example.com", Role.ADMIN)
    response = admin.post(
        "/api/v1/governance/executive/actions",
        json={
            **_action_payload(key="api-redacted-action", description=f"Secret {_SECRET_TOKEN}"),
            "recommendation_id": "rec-v38-api",
            "due_at": "2099-12-01T12:00:00Z",
        },
    )
    assert response.status_code == 200, response.text
    audit = admin.get(
        "/api/v1/governance/audit",
        params={"event_type": "EXECUTIVE_ACTION_CREATED", "page_size": 50},
    )
    assert audit.status_code == 200, audit.text
    assert _SECRET_TOKEN not in audit.text


def test_report_generation_does_not_duplicate_v37_intelligence_snapshot(tmp_path: Any) -> None:
    service, _, _, _ = _build_service(tmp_path, recommendation=_recommendation())
    service.generate_report(
        _report_payload(key="no-v37-snapshot"),
        actor_id="admin@example.com",
        actor_role="ADMIN",
    )
    snapshots, total = service._automation.list_snapshots()
    assert total == 1
    assert {snapshot["snapshot_type"] for snapshot in snapshots} == {"EXECUTIVE_SUMMARY"}
