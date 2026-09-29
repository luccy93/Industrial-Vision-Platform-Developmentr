"""Health endpoint tests — liveness + readiness contract."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_health_endpoints_return_ok(client: TestClient) -> None:
    for path in ["/health", "/ready", "/api/v1/health"]:
        res = client.get(path)
        assert res.status_code == 200, path
        body = res.json()
        assert body["status"] == "ok"
        assert body["service"] == "industrial-vision-platform"


def test_ready_reports_honest_downstream_states(client: TestClient) -> None:
    body = client.get("/ready").json()
    assert body["ready"] is True
    checks = body["checks"]
    # V01 must not fake downstream health.
    assert checks["database"]["status"] == "not_checked_in_v01"
    assert checks["redis"]["status"] == "not_checked_in_v01"
    assert checks["models"]["status"] == "not_loaded_in_v01"


def test_v1_stubs_are_structured_placeholders(client: TestClient) -> None:
    assert client.get("/api/v1/cameras").status_code == 200
    assert client.get("/api/v1/detections").status_code == 200
    assert client.get("/api/v1/incidents").status_code == 200
    assert client.get("/api/v1/alerts").status_code == 200
    assert client.get("/api/v1/analytics/summary").status_code == 200
