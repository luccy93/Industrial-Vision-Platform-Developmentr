"""Correlation predicate tests — gates, affinity, windows, determinism."""

from __future__ import annotations

from backend.app.intelligence.correlate import (
    cluster_match_score,
    link_events,
    same_affinity,
    shared_identity,
    within_window,
)
from backend.app.intelligence.schemas import UnifiedEventType
from backend.tests.intelligence_helpers import make_unified_event, utc


def test_shared_identity_tracks() -> None:
    first = make_unified_event(track_ids=[7])
    second = make_unified_event(track_ids=[7, 9])
    assert shared_identity(first, second) is True
    assert shared_identity(first, make_unified_event(track_ids=[9])) is False


def test_shared_identity_objects() -> None:
    first = make_unified_event(track_ids=[], object_ids=["track-3"])
    second = make_unified_event(track_ids=[], object_ids=["track-3"])
    assert shared_identity(first, second) is True
    assert shared_identity(first, make_unified_event(track_ids=[], object_ids=[""])) is False


def test_affinity_groups() -> None:
    assert same_affinity(UnifiedEventType.RESTRICTED_ZONE_ENTRY, UnifiedEventType.COLLISION_RISK) is True
    assert same_affinity(UnifiedEventType.QUALITY_FAIL, UnifiedEventType.DEFECT_DETECTED) is True
    assert same_affinity(UnifiedEventType.QUALITY_FAIL, UnifiedEventType.COLLISION_RISK) is False
    assert same_affinity(UnifiedEventType.SCENE_CHANGE, UnifiedEventType.SCENE_CHANGE) is True
    assert same_affinity(UnifiedEventType.SCENE_CHANGE, UnifiedEventType.COLLISION_RISK) is False


def test_window_boundaries() -> None:
    assert within_window(utc(0), utc(5), 5.0) is True
    assert within_window(utc(0), utc(5.001), 5.0) is False
    assert within_window(utc(10), utc(0), 5.0) is False
    assert within_window(utc(0), utc(0), 0.0) is True


def test_link_requires_same_camera() -> None:
    first = make_unified_event(camera_id="cam-01", track_ids=[7])
    second = make_unified_event(camera_id="cam-02", track_ids=[7])
    linked, reasons = link_events(first, second, 5.0)
    assert linked is False
    assert reasons == ["different cameras never correlate"]


def test_link_shared_identity_ignores_window() -> None:
    first = make_unified_event(track_ids=[7], last_seen=utc(0))
    second = make_unified_event(track_ids=[7], last_seen=utc(3600))
    linked, reasons = link_events(first, second, 5.0)
    assert linked is True
    assert reasons == ["shared track/object identity"]


def test_link_location_affinity_inside_window() -> None:
    first = make_unified_event(
        track_ids=[],
        location="zone-1",
        event_type=UnifiedEventType.RESTRICTED_ZONE_ENTRY,
        last_seen=utc(0),
    )
    second = make_unified_event(
        track_ids=[],
        location="zone-1",
        event_type=UnifiedEventType.COLLISION_RISK,
        last_seen=utc(3),
    )
    linked, _ = link_events(first, second, 5.0)
    assert linked is True


def test_link_location_affinity_outside_window() -> None:
    first = make_unified_event(
        track_ids=[],
        location="zone-1",
        event_type=UnifiedEventType.RESTRICTED_ZONE_ENTRY,
        last_seen=utc(0),
    )
    second = make_unified_event(
        track_ids=[],
        location="zone-1",
        event_type=UnifiedEventType.COLLISION_RISK,
        last_seen=utc(30),
    )
    linked, reasons = link_events(first, second, 5.0)
    assert linked is False
    assert reasons == ["no shared identity or co-located affinity inside window"]


def test_link_location_without_affinity_rejected() -> None:
    first = make_unified_event(
        track_ids=[],
        location="zone-1",
        event_type=UnifiedEventType.QUALITY_FAIL,
        last_seen=utc(0),
    )
    second = make_unified_event(
        track_ids=[],
        location="zone-1",
        event_type=UnifiedEventType.COLLISION_RISK,
        last_seen=utc(1),
    )
    linked, _ = link_events(first, second, 5.0)
    assert linked is False


def test_link_same_camera_alone_never_links() -> None:
    first = make_unified_event(track_ids=[1], location=None, last_seen=utc(0))
    second = make_unified_event(track_ids=[2], location=None, last_seen=utc(0))
    linked, _ = link_events(first, second, 3600.0)
    assert linked is False


def test_match_score() -> None:
    candidate = make_unified_event(track_ids=[7])
    members = [make_unified_event(track_ids=[7]), make_unified_event(track_ids=[8])]
    fraction, count = cluster_match_score(candidate, members, 5.0)
    assert fraction == 0.5
    assert count == 1
    assert cluster_match_score(candidate, [], 5.0) == (0.0, 0)
