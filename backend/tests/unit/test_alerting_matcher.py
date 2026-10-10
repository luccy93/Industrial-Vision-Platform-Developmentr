"""Rule matcher tests — deterministic, pure, no I/O (V15)."""

from __future__ import annotations

from backend.app.alerting.matcher import priority_rank, rule_matches, severity_rank
from backend.app.alerting.schemas import AlertChannel, AlertRule


def _rule(**overrides) -> AlertRule:
    params: dict = {"name": "R", "channels": [AlertChannel.IN_APP]}
    params.update(overrides)
    return AlertRule(**params)


def test_empty_filters_match_all() -> None:
    candidate = {"domain": "SAFETY", "event_type": "CROWD_WARNING", "severity": "LOW"}
    assert rule_matches(_rule(), candidate) is True


def test_disabled_never_matches() -> None:
    assert rule_matches(_rule(enabled=False), {"domain": "SAFETY"}) is False


def test_domain_and_type_filters() -> None:
    rule = _rule(domains=["SAFETY"], event_types=["CROWD_WARNING"])
    assert rule_matches(rule, {"domain": "SAFETY", "event_type": "CROWD_WARNING"}) is True
    assert rule_matches(rule, {"domain": "QUALITY", "event_type": "CROWD_WARNING"}) is False
    assert rule_matches(rule, {"domain": "SAFETY", "event_type": "QUALITY_FAIL"}) is False


def test_severity_minimum() -> None:
    rule = _rule(min_severity="HIGH")
    assert rule_matches(rule, {"severity": "CRITICAL"}) is True
    assert rule_matches(rule, {"severity": "HIGH"}) is True
    assert rule_matches(rule, {"severity": "MEDIUM"}) is False
    assert rule_matches(rule, {"severity": "UNKNOWN"}) is False
    assert rule_matches(rule, {}) is False


def test_priority_minimum() -> None:
    rule = _rule(min_priority="P2")
    assert rule_matches(rule, {"priority": "P0"}) is True
    assert rule_matches(rule, {"priority": "P2"}) is True
    assert rule_matches(rule, {"priority": "P3"}) is False
    assert rule_matches(rule, {"priority": "BOGUS"}) is False


def test_camera_filter() -> None:
    rule = _rule(camera_ids=["cam-01"])
    assert rule_matches(rule, {"camera_id": "cam-01"}) is True
    assert rule_matches(rule, {"camera_id": "cam-02"}) is False
    assert rule_matches(rule, {}) is False


def test_incident_status_filter() -> None:
    rule = _rule(incident_statuses=["RESOLVED", "CLOSED"])
    assert rule_matches(rule, {"new_state": "RESOLVED"}) is True
    assert rule_matches(rule, {"new_state": "OPEN"}) is False
    # Domain events carry no status: a status-filtered rule ignores them.
    assert rule_matches(rule, {"domain": "SAFETY", "event_type": "CROWD_WARNING"}) is False


def test_ranks() -> None:
    assert severity_rank("CRITICAL") > severity_rank("HIGH") > severity_rank("LOW")
    assert severity_rank("UNKNOWN") == -1.0
    assert severity_rank("BOGUS") == -1.0
    assert priority_rank("P0") < priority_rank("P4")
    assert priority_rank("BOGUS") == 5
