"""Alerting schema tests — rule validation, no-wildcard unknowns (V15)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.app.alerting.schemas import (
    ALERTABLE_DOMAINS,
    AlertChannel,
    RuleCreate,
    SuppressionScope,
    validate_rule_filters,
)


def test_valid_rule_accepted() -> None:
    rule = RuleCreate(
        name="Critical safety",
        domains=["safety"],
        event_types=["CROWD_CRITICAL"],
        min_severity="HIGH",
        camera_ids=["cam-01"],
        channels=[AlertChannel.IN_APP, AlertChannel.EMAIL],
        cooldown_seconds=300,
    )
    assert rule.domains == ["SAFETY"]
    assert rule.event_types == ["CROWD_CRITICAL"]
    assert rule.cooldown_seconds == 300
    assert rule.suppression_scope is SuppressionScope.RULE


def test_empty_filters_match_all_by_design() -> None:
    rule = RuleCreate(name="Everything", channels=[AlertChannel.IN_APP])
    assert rule.domains == []
    assert rule.event_types == []
    assert rule.camera_ids == []


def test_unknown_domain_rejected_never_wildcard() -> None:
    with pytest.raises(ValidationError):
        RuleCreate(name="Bad", domains=["TRACKING"], channels=[AlertChannel.IN_APP])
    with pytest.raises(ValidationError):
        RuleCreate(name="Bad", domains=["NOPE"], channels=[AlertChannel.IN_APP])


def test_unknown_event_type_rejected() -> None:
    with pytest.raises(ValidationError):
        RuleCreate(name="Bad", event_types=["FRAME_PROCESSED"], channels=[AlertChannel.IN_APP])


def test_unknown_incident_status_rejected() -> None:
    with pytest.raises(ValidationError):
        RuleCreate(name="Bad", incident_statuses=["REOPENED"], channels=[AlertChannel.IN_APP])
    rule = RuleCreate(name="Ok", incident_statuses=["resolved"], channels=[AlertChannel.IN_APP])
    assert rule.incident_statuses == ["RESOLVED"]


def test_channels_required_and_cooldown_bounded() -> None:
    with pytest.raises(ValidationError):
        RuleCreate(name="No channels", channels=[])
    with pytest.raises(ValidationError):
        RuleCreate(name="Bad cooldown", channels=[AlertChannel.IN_APP], cooldown_seconds=-1)
    with pytest.raises(ValidationError):
        RuleCreate(name="Bad cooldown", channels=[AlertChannel.IN_APP], cooldown_seconds=86401)


def test_reserved_domains_excluded() -> None:
    assert "TRACKING" not in ALERTABLE_DOMAINS
    assert "PERCEPTION" not in ALERTABLE_DOMAINS
    assert "SYSTEM" not in ALERTABLE_DOMAINS
    with pytest.raises(ValueError):
        validate_rule_filters(domains=["SYSTEM"], event_types=None, incident_statuses=None)
