"""Error-handling tests — consistent envelope, no stack-trace leaks."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from backend.app.core.exceptions import (
    CameraError,
    ServiceUnavailableError,
    register_exception_handlers,
)


def _app_with_boom() -> TestClient:
    app = FastAPI()

    @app.get("/boom-camera")
    def boom_camera() -> None:
        raise CameraError("Camera offline.")

    @app.get("/boom-downstream")
    def boom_downstream() -> None:
        raise ServiceUnavailableError("Redis unavailable.")

    @app.get("/boom-unexpected")
    def boom_unexpected() -> None:
        raise RuntimeError("kaboom")

    register_exception_handlers(app)
    return TestClient(app, raise_server_exceptions=False)


def test_typed_errors_map_to_stable_envelope() -> None:
    client = _app_with_boom()
    res = client.get("/boom-camera")
    assert res.status_code == 502
    body = res.json()["error"]
    assert body["code"] == "camera_error"
    assert body["message"] == "Camera offline."
    assert "request_id" in body


def test_unexpected_errors_do_not_leak_internals() -> None:
    client = _app_with_boom()
    res = client.get("/boom-unexpected")
    assert res.status_code == 500
    body = res.json()["error"]
    assert body["code"] == "internal_error"
    assert "kaboom" not in body["message"]
    assert "traceback" not in res.text.lower()
