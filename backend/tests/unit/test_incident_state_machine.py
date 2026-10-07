"""State machine tests — every valid transition, every invalid transition."""

from __future__ import annotations

import pytest

from backend.app.incidents.schemas import IncidentCategory, IncidentStatus
from backend.app.incidents.statemachine import (
    TRANSITIONS,
    InvalidTransitionError,
    allowed_actions,
    category_for_domains,
    validate_transition,
)
from backend.app.intelligence.schemas import EventSourceDomain


def test_transition_table_matches_spec() -> None:
    assert TRANSITIONS == {
        IncidentStatus.OPEN: frozenset(
            {IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED}
        ),
        IncidentStatus.ACKNOWLEDGED: frozenset(
            {IncidentStatus.INVESTIGATING, IncidentStatus.MITIGATED, IncidentStatus.RESOLVED}
        ),
        IncidentStatus.INVESTIGATING: frozenset({IncidentStatus.MITIGATED, IncidentStatus.RESOLVED}),
        IncidentStatus.MITIGATED: frozenset({IncidentStatus.RESOLVED}),
        IncidentStatus.RESOLVED: frozenset({IncidentStatus.CLOSED}),
        IncidentStatus.CLOSED: frozenset(),
    }


@pytest.mark.parametrize(
    ("current", "attempted"),
    [
        (IncidentStatus.OPEN, IncidentStatus.ACKNOWLEDGED),
        (IncidentStatus.OPEN, IncidentStatus.INVESTIGATING),
        (IncidentStatus.OPEN, IncidentStatus.RESOLVED),
        (IncidentStatus.ACKNOWLEDGED, IncidentStatus.INVESTIGATING),
        (IncidentStatus.ACKNOWLEDGED, IncidentStatus.MITIGATED),
        (IncidentStatus.ACKNOWLEDGED, IncidentStatus.RESOLVED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.MITIGATED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.RESOLVED),
        (IncidentStatus.MITIGATED, IncidentStatus.RESOLVED),
        (IncidentStatus.RESOLVED, IncidentStatus.CLOSED),
    ],
)
def test_valid_transitions_pass(current: IncidentStatus, attempted: IncidentStatus) -> None:
    validate_transition(current, attempted)


@pytest.mark.parametrize(
    ("current", "attempted"),
    [
        (IncidentStatus.OPEN, IncidentStatus.MITIGATED),
        (IncidentStatus.OPEN, IncidentStatus.CLOSED),
        (IncidentStatus.OPEN, IncidentStatus.OPEN),
        (IncidentStatus.ACKNOWLEDGED, IncidentStatus.ACKNOWLEDGED),
        (IncidentStatus.ACKNOWLEDGED, IncidentStatus.CLOSED),
        (IncidentStatus.ACKNOWLEDGED, IncidentStatus.OPEN),
        (IncidentStatus.INVESTIGATING, IncidentStatus.ACKNOWLEDGED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED),
        (IncidentStatus.INVESTIGATING, IncidentStatus.OPEN),
        (IncidentStatus.MITIGATED, IncidentStatus.INVESTIGATING),
        (IncidentStatus.MITIGATED, IncidentStatus.ACKNOWLEDGED),
        (IncidentStatus.MITIGATED, IncidentStatus.CLOSED),
        (IncidentStatus.MITIGATED, IncidentStatus.OPEN),
        (IncidentStatus.RESOLVED, IncidentStatus.OPEN),
        (IncidentStatus.RESOLVED, IncidentStatus.MITIGATED),
        (IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING),
        (IncidentStatus.RESOLVED, IncidentStatus.RESOLVED),
        (IncidentStatus.CLOSED, IncidentStatus.OPEN),
        (IncidentStatus.CLOSED, IncidentStatus.ACKNOWLEDGED),
        (IncidentStatus.CLOSED, IncidentStatus.RESOLVED),
        (IncidentStatus.CLOSED, IncidentStatus.CLOSED),
    ],
)
def test_invalid_transitions_raise(current: IncidentStatus, attempted: IncidentStatus) -> None:
    with pytest.raises(InvalidTransitionError) as exc_info:
        validate_transition(current, attempted)
    assert exc_info.value.current is current
    assert exc_info.value.attempted is attempted
    assert current.value in str(exc_info.value)
    assert attempted.value in str(exc_info.value)


def test_allowed_actions_never_bypass_lifecycle() -> None:
    by_status = {
        IncidentStatus.OPEN: {"acknowledge", "investigate", "resolve"},
        IncidentStatus.ACKNOWLEDGED: {"investigate", "mitigate", "resolve"},
        IncidentStatus.INVESTIGATING: {"mitigate", "resolve"},
        IncidentStatus.MITIGATED: {"resolve"},
        IncidentStatus.RESOLVED: {"close"},
        IncidentStatus.CLOSED: set(),
    }
    for status, lifecycle_actions in by_status.items():
        actions = set(allowed_actions(status))
        assert lifecycle_actions <= actions
    # CLOSED exposes nothing at all.
    assert allowed_actions(IncidentStatus.CLOSED) == ()


def test_allowed_actions_cover_operations() -> None:
    for status in (
        IncidentStatus.OPEN,
        IncidentStatus.ACKNOWLEDGED,
        IncidentStatus.INVESTIGATING,
        IncidentStatus.MITIGATED,
        IncidentStatus.RESOLVED,
    ):
        actions = set(allowed_actions(status))
        assert "note" in actions
        assert "evidence" in actions


def test_category_mapping_precedence() -> None:
    assert (
        category_for_domains([EventSourceDomain.AUTONOMOUS, EventSourceDomain.SAFETY])
        is IncidentCategory.COLLISION
    )
    assert category_for_domains([EventSourceDomain.QUALITY]) is IncidentCategory.QUALITY
    assert category_for_domains([EventSourceDomain.SPATIAL]) is IncidentCategory.SPATIAL
    assert category_for_domains([EventSourceDomain.SAFETY]) is IncidentCategory.SAFETY
    assert category_for_domains([]) is IncidentCategory.OPERATIONAL
    # Reserved domains never drive inference.
    assert category_for_domains([EventSourceDomain.SYSTEM]) is IncidentCategory.OPERATIONAL
    assert category_for_domains([EventSourceDomain.TRACKING]) is IncidentCategory.OPERATIONAL
