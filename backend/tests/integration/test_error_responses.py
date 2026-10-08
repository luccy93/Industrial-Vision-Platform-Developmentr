"""Error response tests — stable envelope across validation/404/409/503/500."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_validation_error_envelope(client: TestClient) -> None:
    res = client.post("/api/v1/incidents", json={"title": "x", "priority": "P9"})
    assert res.status_code == 422
    body = res.json()
    assert body["error"]["code"] == "validation_error"
    assert "request_id" in body["error"]
    assert "errors" in body["error"]["details"]


def test_404_envelope(client: TestClient) -> None:
    res = client.get("/api/v1/incidents/does-not-exist")
    assert res.status_code == 404
    body = res.json()
    assert body["error"]["code"] == "not_found"
    assert body["error"]["message"] == "incident not found"
    assert "details" not in body["error"]


def test_409_transition_code_preserved(client: TestClient) -> None:
    created = client.post("/api/v1/incidents", json={"title": "edge"}).json()
    incident_id = created["incident"]["id"]
    res = client.post(f"/api/v1/incidents/{incident_id}/acknowledge", json={"actor_id": "op-1"})
    assert res.status_code == 200
    again = client.post(f"/api/v1/incidents/{incident_id}/acknowledge", json={"actor_id": "op-1"})
    assert again.status_code == 409
    error = again.json()["error"]
    assert error["code"] == "invalid_transition"
    assert error["details"]["current_status"] == "ACKNOWLEDGED"
    assert error["details"]["attempted_status"] == "ACKNOWLEDGED"


def test_409_invalid_state_code_preserved(client: TestClient) -> None:
    created = client.post("/api/v1/incidents", json={"title": "edge"}).json()
    incident_id = created["incident"]["id"]
    client.post(
        f"/api/v1/incidents/{incident_id}/resolve",
        json={"reason": "FALSE_ALARM", "actor_id": "op-1"},
    )
    client.post(
        f"/api/v1/incidents/{incident_id}/close",
        json={"closure_reason": "done", "actor_id": "op-1"},
    )
    res = client.post(f"/api/v1/incidents/{incident_id}/acknowledge", json={"actor_id": "op-1"})
    assert res.status_code == 409
    assert res.json()["error"]["code"] == "invalid_state"


def test_503_dependency_unavailable(client: TestClient) -> None:
    from typing import Any, cast

    from fastapi import FastAPI

    state = cast(FastAPI, cast(Any, client).app).state
    saved = state.incident_manager
    state.incident_manager = None
    try:
        res = client.get("/api/v1/incidents")
        assert res.status_code == 503
        assert res.json()["error"]["message"] == "incident manager unavailable"
    finally:
        state.incident_manager = saved


def test_unexpected_exception_is_stable_500(client: TestClient) -> None:
    from typing import Any, cast

    from fastapi import FastAPI
    from fastapi.testclient import TestClient as _TestClient

    app = cast(FastAPI, cast(Any, client).app)

    @app.get("/api/v1/_boom")
    def _boom() -> dict:
        raise RuntimeError("kaboom with secret=password123")

    # The shared fixture re-raises server exceptions; a portal client
    # observes the real wire response instead.
    probe = _TestClient(app, raise_server_exceptions=False)
    res = probe.get("/api/v1/_boom")
    assert res.status_code == 500
    body = res.json()
    assert body["error"]["code"] == "internal_error"
    assert "kaboom" not in body["error"]["message"]
    assert "password123" not in res.text


def test_payload_too_large_is_413(client: TestClient) -> None:
    big = "x" * (1024 * 1024 + 1)
    res = client.post("/api/v1/incidents", json={"title": big})
    assert res.status_code == 413
    body = res.json()
    assert body["error"]["code"] == "PAYLOAD_TOO_LARGE"


def test_normal_payloads_unaffected_by_body_cap(client: TestClient) -> None:
    res = client.post("/api/v1/incidents", json={"title": "fine"})
    assert res.status_code == 201
