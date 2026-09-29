"""API startup tests — factory, versioning, request-id behavior."""

from __future__ import annotations

from fastapi.testclient import TestClient

from backend.app.core.config import Settings
from backend.app.main import create_app


def test_app_starts_with_testing_settings(test_settings: Settings) -> None:
    app = create_app(test_settings)
    assert app.title.startswith("Industrial AI Vision")
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/health" in paths
    assert "/ready" in paths


def test_api_versioning_prefix_present(test_settings: Settings) -> None:
    client = TestClient(create_app(test_settings))
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    assert res.json()["version"] == "v01"


def test_request_id_header_propagated(client: TestClient) -> None:
    res = client.get("/health")
    assert "X-Request-ID" in res.headers
    assert len(res.headers["X-Request-ID"]) > 0
