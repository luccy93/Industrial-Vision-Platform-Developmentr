"""Focused V35 deterministic retention-evaluation tests."""

from __future__ import annotations

from datetime import UTC, datetime

from backend.app.governance.policies import default_policy_definition
from backend.app.governance.retention import (
    build_evaluation_key,
    evaluate_retention,
    evaluation_key_payload,
    normalize_as_of,
)


def _case(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "case_id": "case-1",
        "case_number": "CASE-2026-000001",
        "case_type": "EVIDENCE_TAMPERING",
        "status": "CLOSED",
        "created_at": datetime(2026, 1, 1, tzinfo=UTC),
    }
    values.update(overrides)
    return values


def _policy(**overrides: object):
    policy = default_policy_definition()
    values = {
        "policy_id": "POL-RET",
        "version": 1,
        "name": "Retention policy",
        "state": "ENABLED",
        "retention_days": 30,
        "review_interval_days": 10,
        "reason": "synthetic retention policy",
    }
    values.update(overrides)
    return type(policy)(**{**policy.__dict__, **values})


def test_missing_durations_report_incomplete_without_guessing() -> None:
    result = evaluate_retention(
        case=_case(), policy=default_policy_definition(), as_of=datetime(2026, 1, 5, tzinfo=UTC)
    )
    payload = result.to_dict()
    assert payload["data_status"] == "INCOMPLETE"
    assert payload["retention_deadline"] is None
    assert payload["next_review_at"] is None
    assert "RETENTION_DURATION_UNCONFIGURED" in payload["reasons"]
    assert "REVIEW_INTERVAL_UNCONFIGURED" in payload["reasons"]
    assert payload["deletion_authorized"] is False


def test_missing_case_start_or_policy_is_unavailable() -> None:
    missing_start = evaluate_retention(
        case=_case(created_at=None),
        policy=_policy(),
        as_of=datetime(2026, 1, 5, tzinfo=UTC),
    )
    assert missing_start.data_status == "UNAVAILABLE"
    assert "RETENTION_START_UNAVAILABLE" in missing_start.reasons

    missing_policy = evaluate_retention(case=_case(), policy=None, as_of=datetime(2026, 1, 5, tzinfo=UTC))
    assert missing_policy.data_status == "UNAVAILABLE"
    assert "RETENTION_POLICY_UNAVAILABLE" in missing_policy.reasons


def test_active_review_due_and_disposition_states_are_deterministic() -> None:
    policy = _policy()
    active = evaluate_retention(case=_case(), policy=policy, as_of=datetime(2026, 1, 5, tzinfo=UTC))
    assert active.governance_state == "ACTIVE"

    review_due = evaluate_retention(case=_case(), policy=policy, as_of=datetime(2026, 1, 11, tzinfo=UTC))
    assert review_due.governance_state == "REVIEW_DUE"
    assert "RETENTION_REVIEW_DUE" in review_due.reasons

    disposition_due = evaluate_retention(case=_case(), policy=policy, as_of=datetime(2026, 1, 31, tzinfo=UTC))
    assert disposition_due.governance_state == "DISPOSITION_REVIEW_REQUIRED"
    assert disposition_due.disposition_eligible is True
    assert "RETENTION_DEADLINE_REACHED" in disposition_due.reasons


def test_blocking_holds_outrank_every_other_state() -> None:
    policy = _policy()
    pending = evaluate_retention(
        case=_case(),
        policy=policy,
        as_of=datetime(2026, 2, 5, tzinfo=UTC),
        holds=[{"hold_id": "hold-1", "status": "PENDING_APPROVAL"}],
        latest_disposition={"status": "APPROVED", "disposition_id": "disp-1", "version": 2},
    )
    assert pending.governance_state == "LEGAL_HOLD"
    assert pending.legal_hold_ids == ["hold-1"]
    assert "LEGAL_HOLD_PENDING_APPROVAL" in pending.reasons
    assert pending.disposition_eligible is False

    active = evaluate_retention(
        case=_case(),
        policy=policy,
        as_of=datetime(2026, 2, 5, tzinfo=UTC),
        holds=[{"hold_id": "hold-2", "status": "ACTIVE"}],
    )
    assert active.governance_state == "LEGAL_HOLD"
    assert "LEGAL_HOLD_ACTIVE" in active.reasons

    released = evaluate_retention(
        case=_case(),
        policy=policy,
        as_of=datetime(2026, 2, 5, tzinfo=UTC),
        holds=[{"hold_id": "hold-3", "status": "RELEASED"}],
    )
    assert released.governance_state == "DISPOSITION_REVIEW_REQUIRED"
    assert released.legal_hold_ids == []


def test_disposition_approved_and_blocked_states_are_reported() -> None:
    policy = _policy()
    approved = evaluate_retention(
        case=_case(),
        policy=policy,
        as_of=datetime(2026, 2, 5, tzinfo=UTC),
        latest_disposition={"status": "APPROVED", "disposition_id": "disp-1", "version": 2},
    )
    assert approved.governance_state == "DISPOSITION_APPROVED"
    assert approved.disposition_eligible is False
    assert approved.deletion_authorized is False

    blocked = evaluate_retention(
        case=_case(),
        policy=policy,
        as_of=datetime(2026, 2, 5, tzinfo=UTC),
        latest_disposition={"status": "BLOCKED", "disposition_id": "disp-2", "version": 2},
    )
    assert blocked.governance_state == "DISPOSITION_BLOCKED"
    assert "DISPOSITION_BLOCKED" in blocked.reasons


def test_review_completion_schedules_next_interval_without_moving_deadline() -> None:
    policy = _policy()
    result = evaluate_retention(
        case=_case(),
        policy=policy,
        as_of=datetime(2026, 1, 20, tzinfo=UTC),
        review_completed_at=datetime(2026, 1, 20, tzinfo=UTC),
    )
    assert result.retention_deadline == datetime(2026, 1, 31, tzinfo=UTC)
    assert result.next_review_at == datetime(2026, 1, 30, tzinfo=UTC)


def test_non_terminal_cases_are_not_disposition_eligible() -> None:
    result = evaluate_retention(
        case=_case(status="INVESTIGATING"),
        policy=_policy(),
        as_of=datetime(2026, 2, 5, tzinfo=UTC),
    )
    assert result.disposition_eligible is False
    assert "CASE_STATUS_NOT_TERMINAL" in result.reasons


def test_evaluation_key_is_stable_and_input_sensitive() -> None:
    payload = evaluation_key_payload(
        case_id="case-1",
        policy_id="POL-RET",
        policy_version=1,
        evaluation_kind="EVALUATION",
        as_of=datetime(2026, 1, 5, 18, 30, tzinfo=UTC),
        hold_ids=["hold-1"],
        latest_disposition=None,
        latest_verification={"verification_id": "verify-1", "outcome": "PASS"},
    )
    first = build_evaluation_key(payload)
    second = build_evaluation_key(
        evaluation_key_payload(
            case_id="case-1",
            policy_id="POL-RET",
            policy_version=1,
            evaluation_kind="EVALUATION",
            as_of=datetime(2026, 1, 5, 1, 0, tzinfo=UTC),
            hold_ids=["hold-1"],
            latest_disposition=None,
            latest_verification={"verification_id": "verify-1", "outcome": "PASS"},
        )
    )
    assert first == second
    changed = build_evaluation_key(
        evaluation_key_payload(
            case_id="case-1",
            policy_id="POL-RET",
            policy_version=1,
            evaluation_kind="EVALUATION",
            as_of=datetime(2026, 1, 6, tzinfo=UTC),
            hold_ids=["hold-1"],
            latest_disposition=None,
            latest_verification={"verification_id": "verify-1", "outcome": "PASS"},
        )
    )
    assert first != changed


def test_as_of_normalization_uses_utc_midnight() -> None:
    assert normalize_as_of(datetime(2026, 1, 5, 23, 59, tzinfo=UTC)).isoformat() == (
        "2026-01-05T00:00:00+00:00"
    )
