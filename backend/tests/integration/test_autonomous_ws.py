"""Autonomous WebSocket tests — new messages alongside V02–V07."""

from __future__ import annotations

import json
import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.domain.frame import IngestionFrame
from backend.tests.autonomous_helpers import synthetic_frame, utc
from backend.tests.safety_helpers import make_track


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


def _setup(client: TestClient, camera_id: str = "cam-aws") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Auto WS", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201
    res = client.post(
        f"/api/v1/cameras/{camera_id}/autonomous-profiles",
        json={"name": "Road", "profile_id": "profile-01"},
    )
    assert res.status_code == 201, res.text


def _perceive(client: TestClient, camera_id: str) -> None:
    """Drive the app's autonomous engine directly (no stream)."""
    state = _app(client)
    engine = state.autonomous_engine
    boxes = [(100.0 + i * 10.0, 100.0, 150.0 + i * 10.0, 300.0) for i in range(5)]
    track = make_track(1, "car", boxes[-1], history_boxes=boxes, history_span_seconds=2.0)
    frame = IngestionFrame(
        camera_id=camera_id, frame_number=1, width=640, height=480, image=synthetic_frame()
    )
    engine.process(camera_id, [track], frame, utc(0), None)


def test_ws_autonomous_perception_message(client: TestClient) -> None:
    _setup(client)
    _perceive(client, "cam-aws")

    seen: set[str] = set()
    perception = None
    with client.websocket_connect("/ws/cameras/cam-aws") as websocket:
        deadline = time.time() + 15
        while time.time() < deadline and perception is None:
            message = json.loads(websocket.receive_text())
            seen.add(message["type"])
            if message["type"] == "autonomous_perception":
                perception = message

    assert perception is not None
    assert perception["camera_id"] == "cam-aws"
    assert perception["scene_type"] == "UNKNOWN"
    assert len(perception["objects"]) == 1
    assert perception["objects"][0]["object_id"] == "track-1"
    assert perception["objects"][0]["track_id"] == 1
    assert "stream_status" in seen
    # No production video protocol on this channel.
    assert not {"video", "jpeg", "image"} & seen


def test_ws_previous_messages_still_compatible(client: TestClient) -> None:
    """V02–V07 channels are unaffected by the autonomous wiring."""
    _setup(client)
    _perceive(client, "cam-aws")
    with client.websocket_connect("/ws/cameras/cam-aws") as websocket:
        deadline = time.time() + 15
        seen: set[str] = set()
        while time.time() < deadline and "autonomous_perception" not in seen:
            seen.add(json.loads(websocket.receive_text())["type"])
    assert "stream_status" in seen
    assert "autonomous_perception" in seen


def test_ws_perception_with_two_tracks(client: TestClient) -> None:
    _setup(client)
    state = _app(client)
    engine = state.autonomous_engine
    boxes_a = [(100.0 + i * 10.0, 100.0, 150.0 + i * 10.0, 300.0) for i in range(5)]
    boxes_b = [(500.0 - i * 10.0, 100.0, 550.0 - i * 10.0, 300.0) for i in range(5)]
    track_a = make_track(1, "car", boxes_a[-1], history_boxes=boxes_a, history_span_seconds=2.0)
    track_b = make_track(2, "car", boxes_b[-1], history_boxes=boxes_b, history_span_seconds=2.0)
    frame = IngestionFrame(
        camera_id="cam-aws", frame_number=1, width=640, height=480, image=synthetic_frame()
    )
    result = engine.process("cam-aws", [track_a, track_b], frame, utc(0), None)
    assert len(result.objects) == 2

    seen: set[str] = set()
    perception = None
    with client.websocket_connect("/ws/cameras/cam-aws") as websocket:
        deadline = time.time() + 15
        while time.time() < deadline and perception is None:
            message = json.loads(websocket.receive_text())
            seen.add(message["type"])
            if message["type"] == "autonomous_perception":
                perception = message
    assert perception is not None
    assert len(perception["objects"]) == 2
    assert {o["object_id"] for o in perception["objects"]} == {"track-1", "track-2"}


def test_ws_collision_risk_event_delivery(client: TestClient) -> None:
    _setup(client, "cam-wrisk")
    res = client.post(
        "/api/v1/cameras/cam-wrisk/autonomous-profiles",
        json={"name": "Sensitive", "profile_id": "p-sensitive", "collision_risk_threshold": 0.3},
    )
    assert res.status_code == 201, res.text
    state = _app(client)
    engine = state.autonomous_engine
    boxes_a = [(160.0 + i * 24.0, 100.0, 210.0 + i * 24.0, 300.0) for i in range(5)]
    boxes_b = [(384.0 - i * 24.0, 100.0, 434.0 - i * 24.0, 300.0) for i in range(5)]
    track_a = make_track(1, "car", boxes_a[-1], history_boxes=boxes_a, history_span_seconds=2.0)
    track_b = make_track(2, "car", boxes_b[-1], history_boxes=boxes_b, history_span_seconds=2.0)
    frame = IngestionFrame(
        camera_id="cam-wrisk", frame_number=1, width=640, height=480, image=synthetic_frame()
    )
    engine.process("cam-wrisk", [track_a, track_b], frame, utc(0), None)
    assert any(e.event_type.value == "COLLISION_RISK" for e in engine.active_events("cam-wrisk")), (
        "expected a live collision-risk event for the closing pair"
    )

    risk_message = None
    with client.websocket_connect("/ws/cameras/cam-wrisk") as websocket:
        deadline = time.time() + 15
        while time.time() < deadline and risk_message is None:
            message = json.loads(websocket.receive_text())
            if message["type"] == "collision_risk":
                risk_message = message
    assert risk_message is not None
    assert risk_message["camera_id"] == "cam-wrisk"
    assert risk_message["event"]["event_type"] == "COLLISION_RISK"
    assert set(risk_message["event"]["object_ids"]) == {"track-1", "track-2"}


def test_ws_unknown_camera_still_reports_error(client: TestClient) -> None:
    with client.websocket_connect("/ws/cameras/ghost") as websocket:
        message = json.loads(websocket.receive_text())
    assert message["type"] == "stream_error"
    assert message["code"] == "CAMERA_NOT_FOUND"
