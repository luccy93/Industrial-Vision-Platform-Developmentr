"""Spatial WebSocket tests — zone_event/proximity_event alongside V02–V05."""

from __future__ import annotations

import json
import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.spatial.schemas import ZonePoint
from backend.tests.safety_helpers import make_track, utc


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


_POLYGON = [
    {"x": 0.2, "y": 0.4},
    {"x": 0.8, "y": 0.4},
    {"x": 0.8, "y": 0.9},
    {"x": 0.2, "y": 0.9},
]


def _setup(client: TestClient, camera_id: str = "cam-spatial") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Spatial", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201
    created = client.post(
        f"/api/v1/cameras/{camera_id}/zones",
        json={"name": "Furnace", "zone_id": "restricted-01", "polygon": _POLYGON},
    )
    assert created.status_code == 201


def _feed_zone_event(client: TestClient, camera_id: str) -> None:
    """Drive the spatial rules through the app's safety engine (no stream)."""
    state = _app(client)
    engine = state.safety_engine
    spatial = state.spatial_engine
    assert any(z.zone_id == "restricted-01" for z in spatial.zones_for(camera_id))
    track = make_track(1, "person", (400.0, 300.0, 450.0, 500.0), camera_id=camera_id)
    engine.process(camera_id, [track], utc(0), 1000.0, 1000.0)


def test_ws_zone_event_message(client: TestClient) -> None:
    _setup(client)
    _feed_zone_event(client, "cam-spatial")

    seen: set[str] = set()
    zone_message = None
    with client.websocket_connect("/ws/cameras/cam-spatial") as websocket:
        deadline = time.time() + 15
        while time.time() < deadline and zone_message is None:
            message = json.loads(websocket.receive_text())
            seen.add(message["type"])
            if message["type"] == "zone_event":
                zone_message = message

    assert zone_message is not None
    assert zone_message["camera_id"] == "cam-spatial"
    event = zone_message["event"]
    assert event["event_type"] == "RESTRICTED_ZONE_ENTRY"
    assert event["spatial"] is True
    assert event["track_ids"] == [1]
    assert zone_message["spatial"]["zone_id"] == "restricted-01"
    assert "stream_status" in seen
    # No production video protocol on this channel.
    assert not {"video", "jpeg", "image"} & seen


def test_ws_proximity_event_message(client: TestClient) -> None:
    _setup(client)
    engine = _app(client).safety_engine
    person = make_track(1, "person", (400.0, 300.0, 480.0, 600.0), camera_id="cam-spatial")
    vehicle = make_track(2, "forklift", (500.0, 350.0, 800.0, 650.0), camera_id="cam-spatial")
    engine.process("cam-spatial", [person, vehicle], utc(0), 1000.0, 1000.0)

    proximity = None
    with client.websocket_connect("/ws/cameras/cam-spatial") as websocket:
        deadline = time.time() + 15
        while time.time() < deadline and proximity is None:
            message = json.loads(websocket.receive_text())
            if message["type"] == "proximity_event":
                proximity = message

    assert proximity is not None
    event = proximity["event"]
    assert event["event_type"] == "PERSON_VEHICLE_PROXIMITY"
    assert event["track_ids"] == [1, 2]
    assert event["spatial"] is True
    assert proximity["spatial"]["strategy"] == "HYBRID"


def test_ws_unknown_camera_still_reports_error(client: TestClient) -> None:
    with client.websocket_connect("/ws/cameras/ghost") as websocket:
        message = json.loads(websocket.receive_text())
    assert message["type"] == "stream_error"
    assert message["code"] == "CAMERA_NOT_FOUND"


def test_zone_polygon_requires_three_points(client: TestClient) -> None:
    _setup(client, "cam-spatial-2")
    res = client.post(
        "/api/v1/cameras/cam-spatial-2/zones",
        json={"name": "bad", "polygon": [{"x": 0.1, "y": 0.1}, {"x": 0.2, "y": 0.2}]},
    )
    assert res.status_code == 422
    assert ZonePoint(x=0.5, y=0.5).x == 0.5
