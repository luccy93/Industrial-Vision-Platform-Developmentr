"""Focused V35 governance policy and repository unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from backend.app.core.config import AppEnv, Settings
from backend.app.governance.errors import (
    PolicyValidationError,
    PolicyVersionConflictError,
)
from backend.app.governance.policies import (
    PolicyDefinition,
    default_policy_definition,
    select_policy,
    validate_policy,
    validate_state_transition,
)
from backend.app.governance.repository import GovernanceRepository
from backend.app.infrastructure.db import get_session_factory, init_db


def _settings(tmp_path: Path, **overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "app_name": "industrial-vision-platform",
        "app_env": AppEnv.testing,
        "log_level": "WARNING",
        "database_url": f"sqlite:///{tmp_path}/governance.db",
        "_env_file": None,
    }
    values.update(overrides)
    return Settings(**values)


def _policy(**overrides: Any) -> PolicyDefinition:
    values: dict[str, Any] = {
        "policy_id": "POL-TEST",
        "version": 1,
        "name": "Synthetic policy",
        "state": "DRAFT",
        "reason": "synthetic test policy",
        "actor_id": "admin@example.com",
        "actor_role": "ADMIN",
    }
    values.update(overrides)
    return PolicyDefinition(**values)


@pytest.fixture()
def repository(tmp_path: Path) -> GovernanceRepository:
    settings = _settings(tmp_path)
    init_db(settings.database_url)
    return GovernanceRepository(get_session_factory(settings.database_url))


def test_default_policy_is_safe_and_has_no_invented_durations() -> None:
    policy = default_policy_definition()
    validate_policy(policy)
    assert policy.state == "ENABLED"
    assert policy.retention_days is None
    assert policy.review_interval_days is None
    assert policy.export_requires_approval is True
    assert policy.allow_evidence_bytes is False
    assert policy.legal_hold_eligible is True
    assert policy.disposition_review_required is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"retention_days": 0},
        {"review_interval_days": -1},
        {"retention_days": 10, "review_interval_days": 20},
        {"allow_evidence_bytes": True, "export_allowed": False},
        {"required_approval_level": "DUAL_REVIEWER", "disposition_review_required": False},
        {"policy_id": "POL-DEFAULT", "state": "DISABLED"},
        {"case_type": "NOT_A_CASE_TYPE"},
        {"evidence_category": "NOT_AN_ARTIFACT"},
        {"name": ""},
        {"reason": ""},
    ],
)
def test_policy_validation_rejects_unsafe_definitions(overrides: dict[str, Any]) -> None:
    with pytest.raises(PolicyValidationError):
        validate_policy(_policy(**overrides))


def test_policy_state_transitions_are_bounded() -> None:
    validate_state_transition("DRAFT", "ENABLED")
    validate_state_transition("ENABLED", "DISABLED")
    validate_state_transition("DISABLED", "ENABLED")
    validate_state_transition("ENABLED", "ARCHIVED")
    with pytest.raises(PolicyValidationError):
        validate_state_transition("ARCHIVED", "ENABLED")
    with pytest.raises(PolicyValidationError):
        validate_state_transition("DRAFT", "DRAFT")


def test_policy_selection_prefers_case_type_then_evidence_and_tiebreaks() -> None:
    default = default_policy_definition()
    case_specific = _policy(policy_id="POL-CASE", state="ENABLED", case_type="EVIDENCE_TAMPERING")
    evidence_specific = _policy(policy_id="POL-EVIDENCE", state="ENABLED", evidence_category="EVIDENCE_FILE")
    tie_a = _policy(policy_id="POL-A", state="ENABLED", case_type="EVIDENCE_TAMPERING")
    disabled = _policy(policy_id="POL-DISABLED", state="DISABLED", case_type="EVIDENCE_TAMPERING")
    selected = select_policy(
        [default, case_specific, evidence_specific, tie_a, disabled],
        case_type="EVIDENCE_TAMPERING",
        evidence_categories=["EVIDENCE_FILE"],
    )
    assert selected is not None
    assert selected.policy_id == "POL-A"

    evidence_only = select_policy(
        [default, evidence_specific],
        case_type="OTHER",
        evidence_categories=["EVIDENCE_FILE"],
    )
    assert evidence_only is not None
    assert evidence_only.policy_id == "POL-EVIDENCE"

    fallback = select_policy([default], case_type="OTHER", evidence_categories=[])
    assert fallback is not None
    assert fallback.policy_id == "POL-DEFAULT"


def test_repository_seeds_default_policy_idempotently(repository: GovernanceRepository) -> None:
    first, replayed = repository.ensure_default_policy()
    second, replayed_again = repository.ensure_default_policy()
    assert replayed is False
    assert replayed_again is True
    assert first["policy_id"] == "POL-DEFAULT"
    assert second["policy_id"] == "POL-DEFAULT"
    assert repository.count_policies() == 1


def test_policy_versions_are_append_only_and_version_checked(repository: GovernanceRepository) -> None:
    created, replayed = repository.create_policy_version(_policy())
    assert replayed is False
    assert created["version"] == 1
    assert created["state"] == "DRAFT"

    enabled, _ = repository.create_policy_version(
        _policy(state="ENABLED", reason="enable for production"), expected_version=1
    )
    assert enabled["version"] == 2
    assert enabled["state"] == "ENABLED"
    assert repository.get_policy("POL-TEST")["version"] == 2

    with pytest.raises(PolicyVersionConflictError):
        repository.create_policy_version(_policy(state="DISABLED", reason="stale update"), expected_version=1)

    archived, _ = repository.create_policy_version(
        _policy(state="ARCHIVED", reason="retire"), expected_version=2
    )
    assert archived["version"] == 3
    with pytest.raises(PolicyValidationError):
        repository.create_policy_version(
            _policy(state="ENABLED", reason="cannot resurrect"), expected_version=3
        )

    versions, total = repository.list_policy_versions("POL-TEST")
    assert total == 3
    assert [item["version"] for item in versions] == [3, 2, 1]


def test_policy_idempotency_key_returns_existing_version(repository: GovernanceRepository) -> None:
    first, _ = repository.create_policy_version(_policy(idempotency_key="idem-policy-1"))
    second, replayed = repository.create_policy_version(_policy(idempotency_key="idem-policy-1"))
    assert replayed is True
    assert second["version"] == first["version"]
    assert second["policy_id"] == first["policy_id"]


def test_evaluation_insert_is_immutable_and_idempotent(repository: GovernanceRepository) -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    created, replayed = repository.create_evaluation(
        case_id="case-1",
        evaluation_kind="EVALUATION",
        policy_id="POL-DEFAULT",
        policy_version=1,
        policy_snapshot={"policy_id": "POL-DEFAULT", "version": 1},
        as_of=now.date(),
        evaluated_at=now,
        retention_start=now,
        retention_deadline=None,
        next_review_at=None,
        governance_state="ACTIVE",
        data_status="INCOMPLETE",
        disposition_eligible=False,
        integrity_status="NOT_RUN",
        verification_id=None,
        legal_hold_ids=[],
        reasons=["RETENTION_DURATION_UNCONFIGURED"],
        created_by="admin@example.com",
        request_id="req-1",
        idempotency_key="idem-eval-1",
    )
    assert replayed is False
    assert created["evaluation_version"] == 1
    assert created["deletion_authorized"] is False
    replay, replayed_again = repository.create_evaluation(
        case_id="case-1",
        evaluation_kind="EVALUATION",
        policy_id="POL-DEFAULT",
        policy_version=1,
        policy_snapshot={"policy_id": "POL-DEFAULT", "version": 1},
        as_of=now.date(),
        evaluated_at=now,
        retention_start=now,
        retention_deadline=None,
        next_review_at=None,
        governance_state="ACTIVE",
        data_status="INCOMPLETE",
        disposition_eligible=False,
        integrity_status="NOT_RUN",
        verification_id=None,
        legal_hold_ids=[],
        reasons=["RETENTION_DURATION_UNCONFIGURED"],
        created_by="admin@example.com",
        request_id="req-1",
        idempotency_key="idem-eval-1",
    )
    assert replayed_again is True
    assert replay["evaluation_id"] == created["evaluation_id"]
    assert repository.latest_evaluation("case-1")["evaluation_id"] == created["evaluation_id"]
