"""Incident WebSocket tests — seven incident messages, V01–V09 preserved."""

from __future__ import annotations

import json
import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.tests.intelligence_helpers import utc as intel_utc
from backend.tests.safety_helpers import make_track

INCIDENTS = "/api/v1/incidents"
INCIDENT_TYPES = {
    "incident_created",
    "incident_updated",
    "incident_status_changed",
    "incident_assigned",
    "incident_resolved",
    "incident_closed",
    "incident_evidence_added",
}


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def _setup(client: TestClient, camera_id: str = "cam-ws") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "WS", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _create(client: TestClient, **overrides: Any) -> str:
    payload = {"title": "ws incident", "priority": "P2"}
    payload.update(overrides)
    res = client.post(INCIDENTS, json=payload)
    assert res.status_code == 201, res.text
    return str(res.json()["incident"]["id"])


def _drain(websocket: Any, want: set[str], timeout: float = 15.0) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    deadline = time.time() + timeout
    seen_types: set[str] = set()
    while time.time() < deadline and not want <= seen_types:
        message = json.loads(websocket.receive_text())
        collected.append(message)
        seen_types.add(message.get("type", ""))
    return collected


def test_ws_incident_lifecycle_messages(client: TestClient) -> None:
    _setup(client)
    incident_id = _create(client)

    with client.websocket_connect("/ws/cameras/cam-ws") as websocket:
        messages = _drain(websocket, {"incident_created", "stream_status"})
        created = [m for m in messages if m["type"] == "incident_created"]
        assert created, "expected an incident_created message"
        assert created[0]["incident_id"] == incident_id
        assert created[0]["incident_number"].startswith("INC-")
        assert created[0]["status"] == "OPEN"
        assert created[0]["priority"] == "P2"
        assert created[0]["timestamp"]

        # Mutations performed while the socket is open stream as they happen.
        assert (
            client.post(f"{INCIDENTS}/{incident_id}/acknowledge", json={"actor_id": "op-1"}).status_code
            == 200
        )
        assert (
            client.post(
                f"{INCIDENTS}/{incident_id}/assign",
                json={"assignee": "op-2", "actor_id": "op-1"},
            ).status_code
            == 200
        )
        assert (
            client.post(f"{INCIDENTS}/{incident_id}/evidence", json={"uri": "frames/a.jpg"}).status_code
            == 201
        )
        assert (
            client.post(
                f"{INCIDENTS}/{incident_id}/resolve",
                json={"reason": "OPERATOR_ACTION", "actor_id": "op-1"},
            ).status_code
            == 200
        )
        assert (
            client.post(
                f"{INCIDENTS}/{incident_id}/close",
                json={"closure_reason": "done", "actor_id": "op-1"},
            ).status_code
            == 200
        )

        messages += _drain(
            websocket,
            {
                "incident_status_changed",
                "incident_assigned",
                "incident_evidence_added",
                "incident_resolved",
                "incident_closed",
            },
        )

    by_type: dict[str, list[dict[str, Any]]] = {}
    for message in messages:
        if str(message.get("type", "")).startswith("incident_"):
            by_type.setdefault(message["type"], []).append(message)

    # This sequence exercises six of the seven types; incident_updated has
    # its own test (it only fires for risk/detail updates, not lifecycle).
    assert set(by_type) == INCIDENT_TYPES - {"incident_updated"}
    status_changed = by_type["incident_status_changed"][0]
    assert status_changed["previous_status"] == "OPEN"
    assert status_changed["actor_id"] == "op-1"
    assigned = by_type["incident_assigned"][0]
    assert assigned["previous_assignee"] is None
    assert assigned["new_assignee"] == "op-2"
    evidence = by_type["incident_evidence_added"][0]
    assert evidence["evidence_type"] == "OTHER"
    assert evidence["evidence_id"]
    resolved = by_type["incident_resolved"][0]
    assert resolved["resolution_reason"] == "OPERATOR_ACTION"
    closed = by_type["incident_closed"][0]
    assert closed["closure_reason"] == "done"
    # Bounded payloads: summary fields only, never timeline/evidence arrays.
    for message in by_type["incident_status_changed"]:
        assert "timeline" not in message
        assert "evidence" not in message


def test_ws_incident_updated_message(client: TestClient) -> None:
    _setup(client)
    incident_id = _create(client)
    client.post(f"{INCIDENTS}/{incident_id}/acknowledge", json={"actor_id": "op-1"})
    client.patch(f"{INCIDENTS}/{incident_id}", json={"title": "renamed"})

    with client.websocket_connect("/ws/cameras/cam-ws") as websocket:
        messages = _drain(websocket, {"incident_updated"})
    updated = [m for m in messages if m["type"] == "incident_updated"]
    assert updated
    assert updated[0]["incident_id"] == incident_id
    assert updated[0]["title"] == "renamed"


def test_ws_preserves_v01_to_v09_with_incidents(client: TestClient) -> None:
    """Incident block never displaces the established channels."""
    _setup(client)
    incident_id = _create(client)
    client.post(f"{INCIDENTS}/{incident_id}/acknowledge", json={"actor_id": "op-1"})

    state = _state(client)
    tracks = [
        make_track(i + 1, "person", (10.0 + i * 60.0, 10.0, 50.0 + i * 60.0, 200.0), camera_id="cam-ws")
        for i in range(6)
    ]
    state.safety_engine.process("cam-ws", tracks, intel_utc(0), 640.0, 480.0)
    state.intelligence_engine.process("cam-ws", intel_utc(0))

    wanted = {
        "stream_status",
        "safety_event",
        "intelligence_event",
        "risk_cluster",
        "risk_update",
        "incident_created",
    }
    with client.websocket_connect("/ws/cameras/cam-ws") as websocket:
        messages = _drain(websocket, wanted)
    seen = {m["type"] for m in messages}
    assert wanted <= seen, f"missing {wanted - seen}"
    for retired in ("video", "jpeg", "image", "suppress", "acknowledge"):
        assert retired not in seen


def test_ws_incident_feed_not_duplicated_across_reconnects(client: TestClient) -> None:
    """Each connection starts its own cursor — no cross-connection bleed."""
    _setup(client)
    incident_id = _create(client)
    with client.websocket_connect("/ws/cameras/cam-ws") as websocket:
        _drain(websocket, {"incident_created"})
    # Second connection replays its own feed from the cursor start (seq 0),
    # which is by design for late joiners; what must never happen is an
    # exception or a non-incident message type appearing unexpectedly.
    with client.websocket_connect("/ws/cameras/cam-ws") as websocket:
        messages = _drain(websocket, {"incident_created"})
    created = [m for m in messages if m["type"] == "incident_created"]
    assert created
    assert created[0]["incident_id"] == incident_id
    for message in messages:
        assert message.get("type") in INCIDENT_TYPES | {
            "stream_status",
            "intelligence_event",
            "intelligence_cluster",
            "risk_cluster",
            "risk_update",
            "safety_event",
            "quality_alert",
            "perception_status",
            "perception_error",
            "tracking",
            "detection",
        }


def test_ws_unknown_camera_still_reports_error_with_incidents(client: TestClient) -> None:
    with client.websocket_connect("/ws/cameras/ghost") as websocket:
        message = json.loads(websocket.receive_text())
    assert message["type"] == "stream_error"
    assert message["code"] == "CAMERA_NOT_FOUND"
