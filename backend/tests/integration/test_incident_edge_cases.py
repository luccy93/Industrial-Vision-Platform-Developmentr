"""Incident edge-case tests — closed-state rejection, validation, idempotency."""

from __future__ import annotations

import json
import time
from datetime import UTC
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

INCIDENTS = "/api/v1/incidents"


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def _create(client: TestClient, **overrides: Any) -> str:
    payload = {"title": "edge", "priority": "P2"}
    payload.update(overrides)
    res = client.post(INCIDENTS, json=payload)
    assert res.status_code == 201, res.text
    return str(res.json()["incident"]["id"])


def _close(client: TestClient, incident_id: str) -> None:
    assert (
        client.post(
            f"{INCIDENTS}/{incident_id}/resolve",
            json={"reason": "FALSE_ALARM", "actor_id": "op-1"},
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


def test_closed_rejects_every_mutation(client: TestClient) -> None:
    incident_id = _create(client)
    _close(client, incident_id)
    bodies: dict[str, Any] = {
        "acknowledge": {"actor_id": "op-1"},
        "investigate": {"actor_id": "op-1"},
        "mitigate": {"actor_id": "op-1", "reason": "r"},
        "resolve": {"reason": "FALSE_ALARM", "actor_id": "op-1"},
        "close": {"closure_reason": "again", "actor_id": "op-1"},
        "assign": {"assignee": "op-2", "actor_id": "op-1"},
        "unassign": {"actor_id": "op-1"},
        "escalate": {"priority": "P1", "reason": "r", "actor_id": "op-1"},
        "notes": {"message": "m", "actor_id": "op-1"},
        "evidence": {"uri": "frames/x.jpg"},
    }
    for action, payload in bodies.items():
        res = client.post(f"{INCIDENTS}/{incident_id}/{action}", json=payload)
        assert res.status_code == 409, f"{action}: {res.status_code}"
        assert res.json()["error"]["code"] == "invalid_state"
    assert client.patch(f"{INCIDENTS}/{incident_id}", json={"title": "x"}).status_code == 409
    # Reads still work on closed incidents.
    assert client.get(f"{INCIDENTS}/{incident_id}").status_code == 200
    assert client.get(f"{INCIDENTS}/{incident_id}/evidence").status_code == 200


def test_double_terminal_moves_conflict(client: TestClient) -> None:
    incident_id = _create(client)
    assert (
        client.post(
            f"{INCIDENTS}/{incident_id}/resolve",
            json={"reason": "FALSE_ALARM", "actor_id": "op-1"},
        ).status_code
        == 200
    )
    again = client.post(
        f"{INCIDENTS}/{incident_id}/resolve",
        json={"reason": "FALSE_ALARM", "actor_id": "op-1"},
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "invalid_transition"


def test_resolve_from_every_allowed_state(client: TestClient) -> None:
    paths: dict[str, list[str]] = {
        "OPEN": [],
        "ACKNOWLEDGED": ["acknowledge"],
        "INVESTIGATING": ["acknowledge", "investigate"],
        "MITIGATED": ["acknowledge", "investigate", "mitigate"],
    }
    reasons = {"acknowledge": {}, "investigate": {}, "mitigate": {"reason": "guard reset"}}
    for start, steps in paths.items():
        incident_id = _create(client, title=f"from-{start}")
        for step in steps:
            res = client.post(
                f"{INCIDENTS}/{incident_id}/{step}",
                json={"actor_id": "op-1", **reasons[step]},
            )
            assert res.status_code == 200, f"{start}/{step}: {res.text}"
        res = client.post(
            f"{INCIDENTS}/{incident_id}/resolve",
            json={"reason": "OPERATOR_ACTION", "actor_id": "op-1"},
        )
        assert res.status_code == 200, f"resolve from {start}: {res.text}"
        assert res.json()["incident"]["status"] == "RESOLVED"


def test_validation_failures_are_422(client: TestClient) -> None:
    assert client.post(INCIDENTS, json={"title": " "}).status_code == 422
    assert client.post(INCIDENTS, json={"title": "x", "priority": "P9"}).status_code == 422
    incident_id = _create(client)
    assert client.patch(f"{INCIDENTS}/{incident_id}", json={"title": ""}).status_code == 422
    assert (
        client.post(
            f"{INCIDENTS}/{incident_id}/escalate",
            json={"priority": "P9", "reason": "r"},
        ).status_code
        == 422
    )
    assert client.post(f"{INCIDENTS}/{incident_id}/evidence", json={"uri": "  "}).status_code == 422
    assert client.post(f"{INCIDENTS}/{incident_id}/notes", json={"message": ""}).status_code == 422
    assert client.post(f"{INCIDENTS}/{incident_id}/resolve", json={"reason": "BOGUS"}).status_code == 422


def test_delete_unknown_evidence_is_404(client: TestClient) -> None:
    incident_id = _create(client)
    res = client.delete(f"{INCIDENTS}/{incident_id}/evidence/nope")
    assert res.status_code == 404


def test_unassign_never_assigned_is_ok(client: TestClient) -> None:
    incident_id = _create(client)
    res = client.post(f"{INCIDENTS}/{incident_id}/unassign", json={"actor_id": "op-1"})
    assert res.status_code == 200
    assert res.json()["incident"]["assigned_to"] is None


def test_assign_same_assignee_twice_is_ok(client: TestClient) -> None:
    incident_id = _create(client)
    for _ in range(2):
        res = client.post(
            f"{INCIDENTS}/{incident_id}/assign",
            json={"assignee": "op-2", "actor_id": "op-1"},
        )
        assert res.status_code == 200
    assert res.json()["incident"]["assigned_to"] == "op-2"


def test_incident_numbers_sequence(client: TestClient) -> None:
    first = _create(client, title="seq-1")
    second = _create(client, title="seq-2")
    n1 = client.get(f"{INCIDENTS}/{first}").json()["incident"]["incident_number"]
    n2 = client.get(f"{INCIDENTS}/{second}").json()["incident"]["incident_number"]
    assert n1[:4] == "INC-" and n1[4:8].isdigit() and n1[8] == "-"
    assert n2[:9] == n1[:9]  # same year batch
    assert int(n2[9:]) == int(n1[9:]) + 1


def test_disabled_manager_keeps_operator_api(client: TestClient) -> None:
    """incidents_enabled=false gates the automatic pipeline, not operators."""
    from datetime import datetime

    manager = _state(client).incident_manager
    saved = manager._settings.model_copy()
    manager._settings = manager._settings.model_copy(update={"incidents_enabled": False})
    try:
        summary = manager.sync_camera("cam-x", datetime.now(UTC))
        assert summary == {
            "created": 0,
            "updated": 0,
            "resolved": 0,
            "linked": 0,
            "checked": 0,
        }
        incident_id = _create(client, title="manual-while-disabled")
        assert (
            client.post(f"{INCIDENTS}/{incident_id}/acknowledge", json={"actor_id": "op-1"}).status_code
            == 200
        )
    finally:
        manager._settings = saved


def test_ws_skips_unknown_change_kinds(client: TestClient) -> None:
    """A corrupt/foreign feed entry never breaks the socket loop."""
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Edge", "camera_id": "cam-edge", "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201
    incident_id = _create(client, title="edge-ws")
    manager = _state(client).incident_manager
    manager._changes.append(
        {
            "seq": 10**9,
            "kind": "not_a_real_kind",
            "incident_id": incident_id,
            "camera_id": "cam-edge",
        }
    )
    with client.websocket_connect("/ws/cameras/cam-edge") as websocket:
        deadline = time.time() + 15
        seen: set[str] = set()
        while time.time() < deadline and "incident_created" not in seen:
            seen.add(json.loads(websocket.receive_text()).get("type", ""))
    assert "incident_created" in seen
    assert "not_a_real_kind" not in seen
