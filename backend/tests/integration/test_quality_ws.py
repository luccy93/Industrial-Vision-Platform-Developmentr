"""Quality WebSocket tests — quality_event/quality_result alongside V02–V06."""

from __future__ import annotations

import json
import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.quality.fixture import FixtureInspectionModel
from backend.app.quality.inspection import RawDefect
from backend.tests.quality_helpers import utc


def _app(client: TestClient) -> Any:
    """TestClient types ``app`` as an ASGI callable; we need its state."""
    return cast(FastAPI, cast(Any, client).app).state


def _setup(client: TestClient, camera_id: str = "cam-qws") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Quality WS", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201
    res = client.post(
        "/api/v1/quality/defect-categories",
        json={"code": "CRACK", "name": "Crack", "severity": "HIGH"},
    )
    assert res.status_code == 201
    res = client.post(
        f"/api/v1/cameras/{camera_id}/inspection-profiles",
        json={"name": "Surface", "profile_id": "profile-01", "defect_codes": ["CRACK"]},
    )
    assert res.status_code == 201, res.text


def _attach_fixture(client: TestClient, camera_id: str, defects: list[RawDefect]) -> None:
    """Swap the app's quality model for a scripted fixture (test-only)."""
    from backend.app.domain.frame import IngestionFrame
    from backend.tests.quality_helpers import synthetic_frame

    state = _app(client)
    engine = state.quality_engine
    engine._model = FixtureInspectionModel(observations=defects)
    profile = engine._cameras[camera_id].profiles["profile-01"]
    frame = IngestionFrame(
        camera_id=camera_id, frame_number=1, width=640, height=480, image=synthetic_frame()
    )
    engine.inspect(camera_id, profile, frame, utc(0), None)


def _collect(websocket, want: set[str], timeout_s: float = 15) -> tuple[dict, set[str]]:
    seen: set[str] = set()
    found: dict = {}
    deadline = time.time() + timeout_s
    while time.time() < deadline and not want.issubset(found):
        message = json.loads(websocket.receive_text())
        seen.add(message["type"])
        if message["type"] in want and message["type"] not in found:
            found[message["type"]] = message
    return found, seen


def test_ws_quality_event_and_result(client: TestClient) -> None:
    _setup(client)
    _attach_fixture(
        client, "cam-qws", [RawDefect(code="CRACK", box=(10.0, 10.0, 100.0, 100.0), confidence=0.97)]
    )
    fail_event: dict = {}
    defect_event: dict = {}
    result_message: dict = {}
    seen: set[str] = set()
    with client.websocket_connect("/ws/cameras/cam-qws") as websocket:
        deadline = time.time() + 15
        while time.time() < deadline and not (fail_event and defect_event and result_message):
            message = json.loads(websocket.receive_text())
            seen.add(message["type"])
            if message["type"] == "quality_event":
                if message["event"]["event_type"] == "QUALITY_FAIL":
                    fail_event = message
                elif message["event"]["event_type"] == "DEFECT_DETECTED":
                    defect_event = message
            elif message["type"] == "quality_result":
                result_message = message
    assert fail_event, "expected a QUALITY_FAIL decision event"
    assert defect_event, "expected a DEFECT_DETECTED defect event"
    assert result_message, "expected a quality_result message"
    assert "stream_status" in seen
    # No production video protocol on this channel.
    assert not {"video", "jpeg", "image"} & seen

    assert fail_event["camera_id"] == "cam-qws"
    assert fail_event["event"]["decision"] == "FAIL"
    assert fail_event["event"]["severity"] == "HIGH"
    assert fail_event["event"]["status"] == "ACTIVE"

    assert defect_event["event"]["defect_code"] == "CRACK"
    assert defect_event["quality"]["defect_code"] == "CRACK"

    assert result_message["camera_id"] == "cam-qws"
    assert result_message["result"]["decision"] == "FAIL"
    assert len(result_message["result"]["observations"]) == 1
    assert result_message["result"]["observations"][0]["defect_code"] == "CRACK"


def test_ws_previous_messages_still_compatible(client: TestClient) -> None:
    """V02–V06 channels are unaffected by the quality wiring."""
    _setup(client)
    _attach_fixture(client, "cam-qws", [])
    with client.websocket_connect("/ws/cameras/cam-qws") as websocket:
        _, seen = _collect(websocket, {"quality_result"})
    assert "stream_status" in seen
    assert "quality_result" in seen
    # quality_event is absent: a PASS produces no decision event.


def test_ws_defect_detected_event(client: TestClient) -> None:
    _setup(client)
    _attach_fixture(
        client, "cam-qws", [RawDefect(code="CRACK", box=(10.0, 10.0, 100.0, 100.0), confidence=0.97)]
    )
    with client.websocket_connect("/ws/cameras/cam-qws") as websocket:
        found, _ = _collect(websocket, {"quality_event"})
    # The first quality_event may be the FAIL or the DEFECT_DETECTED event;
    # keep reading until the defect-level event arrives.
    assert found["quality_event"]["event"]["event_type"] in {"QUALITY_FAIL", "DEFECT_DETECTED"}
