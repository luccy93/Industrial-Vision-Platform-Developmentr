"""Incident API tests — list/create/detail/patch, lifecycle actions, evidence."""

from __future__ import annotations

import re
from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient

INCIDENTS = "/api/v1/incidents"


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def _camera(client: TestClient, camera_id: str = "cam-i") -> None:
    res = client.post(
        "/api/v1/cameras",
        json={"name": "Inc", "camera_id": camera_id, "source_type": "file", "source": "v.mp4"},
    )
    assert res.status_code == 201


def _create(client: TestClient, **overrides: Any) -> dict[str, Any]:
    payload = {"title": "Line blocked", "priority": "P2", "category": "QUALITY"}
    payload.update(overrides)
    res = client.post(INCIDENTS, json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def _id(detail: dict[str, Any]) -> str:
    return str(detail["incident"]["id"])


def test_list_empty(client: TestClient) -> None:
    res = client.get(INCIDENTS)
    assert res.status_code == 200
    body = res.json()
    assert body == {"incidents": [], "total": 0, "page": 1, "page_size": 20}


def test_create_manual_incident(client: TestClient) -> None:
    detail = _create(client, description="Conveyor jam at station 3")
    incident = detail["incident"]
    assert re.fullmatch(r"INC-\d{4}-\d{6}", incident["incident_number"])
    assert incident["source"] == "MANUAL"
    assert incident["status"] == "OPEN"
    assert incident["priority"] == "P2"
    assert incident["category"] == "QUALITY"
    assert detail["timeline"][0]["event_type"] == "CREATED"
    assert detail["allowed_actions"] == [
        "acknowledge",
        "investigate",
        "assign",
        "note",
        "resolve",
        "evidence",
    ]


def test_create_rejects_invalid_priority(client: TestClient) -> None:
    res = client.post(INCIDENTS, json={"title": "x", "priority": "P9"})
    assert res.status_code == 422


def test_create_rejects_unknown_camera(client: TestClient) -> None:
    res = client.post(INCIDENTS, json={"title": "x", "camera_id": "cam-missing"})
    assert res.status_code == 404


def test_create_with_known_camera(client: TestClient) -> None:
    _camera(client)
    detail = _create(client, camera_id="cam-i")
    assert detail["incident"]["camera_id"] == "cam-i"


def test_get_detail_and_404(client: TestClient) -> None:
    incident_id = _id(_create(client))
    res = client.get(f"{INCIDENTS}/{incident_id}")
    assert res.status_code == 200
    body = res.json()
    assert body["incident"]["id"] == incident_id
    assert "risk_summary" in body
    assert body["assignment"]["assigned_to"] is None
    assert client.get(f"{INCIDENTS}/does-not-exist").status_code == 404


def test_patch_updates_fields_but_not_priority(client: TestClient) -> None:
    incident_id = _id(_create(client, priority="P2"))
    res = client.patch(
        f"{INCIDENTS}/{incident_id}",
        json={"title": "Renamed", "metadata": {"shift": "night"}},
    )
    assert res.status_code == 200
    incident = res.json()["incident"]
    assert incident["title"] == "Renamed"
    assert incident["metadata"] == {"shift": "night"}
    assert incident["priority"] == "P2"
    # priority/category are intentionally not patchable (escalate only).
    res = client.patch(f"{INCIDENTS}/{incident_id}", json={"priority": "P0", "category": "SAFETY"})
    assert res.status_code == 200
    incident = res.json()["incident"]
    assert incident["priority"] == "P2"
    assert incident["category"] == "QUALITY"


def test_acknowledge_then_conflict(client: TestClient) -> None:
    incident_id = _id(_create(client))
    res = client.post(f"{INCIDENTS}/{incident_id}/acknowledge", json={"actor_id": "op-1"})
    assert res.status_code == 200
    body = res.json()
    assert body["incident"]["status"] == "ACKNOWLEDGED"
    assert body["incident"]["acknowledged_at"] is not None
    again = client.post(f"{INCIDENTS}/{incident_id}/acknowledge", json={"actor_id": "op-1"})
    assert again.status_code == 409
    error = again.json()["error"]
    assert error["code"] == "invalid_transition"
    assert error["details"]["current_status"] == "ACKNOWLEDGED"
    assert error["details"]["attempted_status"] == "ACKNOWLEDGED"


def test_full_lifecycle_happy_path(client: TestClient) -> None:
    incident_id = _id(_create(client))
    steps = [
        ("acknowledge", {"actor_id": "op-1", "reason": "On it"}),
        ("investigate", {"actor_id": "op-1", "reason": "Checking"}),
        ("mitigate", {"actor_id": "op-1", "reason": "Guard reset"}),
        ("resolve", {"reason": "OPERATOR_ACTION", "actor_id": "op-1", "detail": "Fixed"}),
        ("close", {"closure_reason": "Reviewed with shift lead", "actor_id": "op-1"}),
    ]
    for path, payload in steps:
        res = client.post(f"{INCIDENTS}/{incident_id}/{path}", json=payload)
        assert res.status_code == 200, f"{path}: {res.text}"
    detail = client.get(f"{INCIDENTS}/{incident_id}").json()
    assert detail["incident"]["status"] == "CLOSED"
    assert detail["incident"]["closed_at"] is not None
    assert detail["allowed_actions"] == []  # tuple serializes to JSON list
    types = [t["event_type"] for t in detail["timeline"]]
    assert types == [
        "CREATED",
        "ACKNOWLEDGED",
        "INVESTIGATION_STARTED",
        "MITIGATED",
        "RESOLVED",
        "CLOSED",
    ]


def test_close_from_open_is_409(client: TestClient) -> None:
    incident_id = _id(_create(client))
    res = client.post(f"{INCIDENTS}/{incident_id}/close", json={"closure_reason": "skipping"})
    assert res.status_code == 409
    assert res.json()["error"]["details"]["attempted_status"] == "CLOSED"


def test_resolve_without_reason_is_422(client: TestClient) -> None:
    incident_id = _id(_create(client))
    res = client.post(f"{INCIDENTS}/{incident_id}/resolve", json={"reason": "NOT_A_REASON"})
    assert res.status_code == 422


def test_mitigate_requires_reason(client: TestClient) -> None:
    incident_id = _id(_create(client))
    client.post(f"{INCIDENTS}/{incident_id}/acknowledge", json={"actor_id": "op-1"})
    res = client.post(f"{INCIDENTS}/{incident_id}/mitigate", json={"actor_id": "op-1"})
    assert res.status_code == 422


def test_escalate_up_and_down_with_reason(client: TestClient) -> None:
    incident_id = _id(_create(client, priority="P3"))
    client.post(f"{INCIDENTS}/{incident_id}/acknowledge", json={"actor_id": "op-1"})
    up = client.post(
        f"{INCIDENTS}/{incident_id}/escalate",
        json={"priority": "P1", "reason": "Safety impact", "actor_id": "op-1"},
    )
    assert up.status_code == 200
    assert up.json()["incident"]["priority"] == "P1"
    down = client.post(
        f"{INCIDENTS}/{incident_id}/escalate",
        json={"priority": "P4", "reason": "Confirmed benign", "actor_id": "op-1"},
    )
    assert down.status_code == 200
    assert down.json()["incident"]["priority"] == "P4"
    no_reason = client.post(f"{INCIDENTS}/{incident_id}/escalate", json={"priority": "P2", "reason": "  "})
    assert no_reason.status_code == 422


def test_assign_unassign_and_history(client: TestClient) -> None:
    incident_id = _id(_create(client))
    res = client.post(f"{INCIDENTS}/{incident_id}/assign", json={"assignee": "op-2", "actor_id": "op-1"})
    assert res.status_code == 200
    body = res.json()
    assert body["incident"]["assigned_to"] == "op-2"
    assert body["assignment"]["history"][-1]["assignee"] == "op-2"
    res = client.post(f"{INCIDENTS}/{incident_id}/unassign", json={"actor_id": "op-1"})
    assert res.status_code == 200
    assert res.json()["incident"]["assigned_to"] is None
    res = client.post(f"{INCIDENTS}/{incident_id}/assign", json={"assignee": " "})
    assert res.status_code == 422


def test_assign_filter_on_list(client: TestClient) -> None:
    a = _id(_create(client, title="A"))
    _id(_create(client, title="B"))
    client.post(f"{INCIDENTS}/{a}/assign", json={"assignee": "op-2", "actor_id": "op-1"})
    res = client.get(f"{INCIDENTS}?assigned_to=op-2")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["incidents"][0]["id"] == a


def test_notes_add_timeline_entry(client: TestClient) -> None:
    incident_id = _id(_create(client))
    res = client.post(
        f"{INCIDENTS}/{incident_id}/notes",
        json={"message": "Checked with operator", "kind": "FINDING", "actor_id": "op-1"},
    )
    assert res.status_code == 200
    types = [t["event_type"] for t in res.json()["timeline"]]
    assert types[-1] == "NOTE_ADDED"


def test_evidence_crud(client: TestClient) -> None:
    incident_id = _id(_create(client))
    res = client.post(
        f"{INCIDENTS}/{incident_id}/evidence",
        json={"evidence_type": "FRAME", "uri": "frames/0001.jpg", "frame_id": "f-1"},
    )
    assert res.status_code == 201, res.text
    evidence_id = res.json()["id"]
    listing = client.get(f"{INCIDENTS}/{incident_id}/evidence")
    assert listing.status_code == 200
    assert listing.json()["count"] == 1
    detail = client.get(f"{INCIDENTS}/{incident_id}").json()
    types = [t["event_type"] for t in detail["timeline"]]
    assert "EVIDENCE_ADDED" in types
    res = client.delete(f"{INCIDENTS}/{incident_id}/evidence/{evidence_id}")
    assert res.status_code == 200
    assert res.json()["deleted"] is True
    detail = client.get(f"{INCIDENTS}/{incident_id}").json()
    types = [t["event_type"] for t in detail["timeline"]]
    assert types[-1] == "NOTE_ADDED"  # deletion is recorded, never silent
    assert detail["evidence"] == []


def test_evidence_on_closed_incident_conflicts(client: TestClient) -> None:
    incident_id = _id(_create(client))
    client.post(f"{INCIDENTS}/{incident_id}/resolve", json={"reason": "FALSE_ALARM", "actor_id": "op-1"})
    client.post(
        f"{INCIDENTS}/{incident_id}/close",
        json={"closure_reason": "done", "actor_id": "op-1"},
    )
    res = client.post(f"{INCIDENTS}/{incident_id}/evidence", json={"uri": "frames/x.jpg"})
    assert res.status_code == 409
    # Closed incidents remain readable: listing is historical, not a mutation.
    assert client.get(f"{INCIDENTS}/{incident_id}").status_code == 200
    listing = client.get(f"{INCIDENTS}/{incident_id}/evidence")
    assert listing.status_code == 200
    assert listing.json()["count"] == 0


def test_unknown_ids_are_404(client: TestClient) -> None:
    for path in ("acknowledge", "investigate", "mitigate", "notes", "assign", "resolve"):
        payload = {"actor_id": "op-1", "assignee": "op-2", "reason": "r", "message": "m"}
        if path == "resolve":
            payload["reason"] = "FALSE_ALARM"
        if path == "mitigate":
            payload["reason"] = "reset"
        res = client.post(f"{INCIDENTS}/ghost/{path}", json=payload)
        assert res.status_code == 404, f"{path}: {res.status_code}"
    assert client.patch(f"{INCIDENTS}/ghost", json={"title": "x"}).status_code == 404


def test_list_filters_and_pagination(client: TestClient) -> None:
    _create(client, title="one", priority="P3")
    _create(client, title="two", priority="P1")
    res = client.get(f"{INCIDENTS}?priority=P1")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] == 1
    assert body["incidents"][0]["title"] == "two"
    # urgency-first ordering: P1 before P3
    res = client.get(f"{INCIDENTS}?page=1&page_size=1")
    body = res.json()
    assert body["total"] == 2
    assert len(body["incidents"]) == 1
    assert body["incidents"][0]["priority"] == "P1"
    res = client.get(f"{INCIDENTS}?page=2&page_size=1")
    assert res.json()["incidents"][0]["priority"] == "P3"
    # comma-separated values are accepted too
    res = client.get(f"{INCIDENTS}?priority=P1,P4")
    assert res.json()["total"] == 1


def test_list_unknown_filter_value_is_422(client: TestClient) -> None:
    res = client.get(f"{INCIDENTS}?status=NOT_A_STATUS")
    assert res.status_code == 422


def test_manager_unavailable_is_503(client: TestClient) -> None:
    state = _state(client)
    saved = state.incident_manager
    state.incident_manager = None
    try:
        res = client.get(INCIDENTS)
        assert res.status_code == 503
        assert res.json()["error"]["message"] == "incident manager unavailable"
    finally:
        state.incident_manager = saved


def test_list_filters_by_status_and_camera(client: TestClient) -> None:
    a = _id(_create(client, title="a", camera_id=None))
    client.post(f"{INCIDENTS}/{a}/acknowledge", json={"actor_id": "op-1"})
    _create(client, title="b")
    res = client.get(f"{INCIDENTS}?status=OPEN")
    assert res.json()["total"] == 1
    assert res.json()["incidents"][0]["title"] == "b"
    res = client.get(f"{INCIDENTS}?status=ACKNOWLEDGED")
    assert res.json()["total"] == 1
    assert res.json()["incidents"][0]["title"] == "a"
    res = client.get(f"{INCIDENTS}?camera_id=cam-none")
    assert res.json()["total"] == 0
