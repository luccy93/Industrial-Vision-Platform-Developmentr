"""Operations socket tests — shared feed, filters, isolation, cleanup.

Contract note: the shared feed forwards V12 event envelopes as-is
(``event_type``/``camera_id``/``timestamp``/``payload``) alongside
``stream_status`` lifecycle messages. Reusing the envelope verbatim —
instead of translating payloads into per-camera wire shapes — keeps one
contract for local, Redis, and socket delivery with no information loss.
"""

from __future__ import annotations

import json
import time
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.events.envelope import EventEnvelope
from backend.tests.helpers import FakeVideoSource, make_camera


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def _kinds(messages: list[dict[str, Any]]) -> set[str]:
    """Message identity across both shapes (wire `type`, envelope `event_type`)."""
    return {str(m.get("type") or m.get("event_type") or "") for m in messages}


def _collect_until(websocket: Any, want: set[str], timeout: float = 15.0) -> list[dict[str, Any]]:
    """Collect until all wanted kinds arrive (bounded by timeout)."""
    collected: list[dict[str, Any]] = []
    deadline = time.time() + timeout
    while time.time() < deadline and not want <= _kinds(collected):
        try:
            collected.append(json.loads(websocket.receive_text()))
        except Exception:
            break
    return collected


def _start_stream(client: TestClient, camera_id: str = "cam-ops") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Ops", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201
    state = _state(client)
    supervisor = state.supervisor
    camera = make_camera(camera_id=camera_id)
    manager = supervisor.register(camera, source_factory=lambda cam: FakeVideoSource(cam, total=500))
    manager.start()


def test_operations_socket_lifecycle_and_cleanup(client: TestClient) -> None:
    _start_stream(client)
    manager = _state(client).ws_manager
    before = manager.metrics()["connections_total"]
    with client.websocket_connect("/ws/operations") as websocket:
        messages = _collect_until(websocket, {"stream_status"})
    assert "stream_status" in _kinds(messages)
    assert manager.metrics()["connections_total"] == before + 1
    assert manager.metrics()["active_connections"] == 0
    assert manager.metrics()["disconnects_total"] >= 1


def test_operations_socket_receives_bus_events(client: TestClient) -> None:
    _start_stream(client)
    state = _state(client)
    with client.websocket_connect("/ws/operations") as websocket:
        _collect_until(websocket, {"stream_status"})
        envelope = EventEnvelope(
            event_id="ops-evt-1",
            event_type="safety_event",
            domain="SAFETY",
            camera_id="cam-ops",
            origin="proc-test",
            payload={"event_id": "x"},
        )
        state.event_bus.publish(envelope)
        messages = _collect_until(websocket, {"safety_event"})
    assert "safety_event" in _kinds(messages)


def test_operations_socket_filtering(client: TestClient) -> None:
    _start_stream(client)
    state = _state(client)
    with client.websocket_connect("/ws/operations?event_types=incident_created") as websocket:
        first = _collect_until(websocket, {"stream_status"})
        state.event_bus.publish(
            EventEnvelope(
                event_id="ops-evt-2",
                event_type="safety_event",
                domain="SAFETY",
                camera_id="cam-ops",
                origin="proc-test",
                payload={},
            )
        )
        state.event_bus.publish(
            EventEnvelope(
                event_id="ops-evt-3",
                event_type="incident_created",
                domain="INCIDENT",
                camera_id="cam-ops",
                origin="proc-test",
                payload={"incident_id": "x"},
            )
        )
        rest = _collect_until(websocket, {"incident_created"})
    types = _kinds(first + rest)
    assert "safety_event" not in types
    assert "incident_created" in types


def test_operations_socket_never_carries_frames(client: TestClient) -> None:
    _start_stream(client)
    with client.websocket_connect("/ws/operations") as websocket:
        messages = _collect_until(websocket, {"stream_status"})
    assert not (_kinds(messages) & {"frame", "detection", "tracking"})


def test_camera_socket_untouched(client: TestClient) -> None:
    _start_stream(client)
    with client.websocket_connect("/ws/cameras/cam-ops") as websocket:
        messages = _collect_until(websocket, {"stream_status", "frame"})
    assert _kinds(messages) >= {"stream_status"}
