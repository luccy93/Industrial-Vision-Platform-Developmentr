"""Health endpoint tests — /live, /ready, /health (+ versioned)."""

from __future__ import annotations

from typing import Any, cast

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _state(client: TestClient) -> Any:
    return cast(FastAPI, cast(Any, client).app).state


def test_live_is_trivial(client: TestClient) -> None:
    res = client.get("/live")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["service"] == "industrial-vision-platform"
    assert body["runtime_state"] == "READY"


def test_ready_reports_real_verdict(client: TestClient) -> None:
    res = client.get("/ready")
    assert res.status_code == 200
    body = res.json()
    # Legacy shape preserved for existing consumers.
    assert body["status"] == "ok"
    assert body["ready"] is True
    assert body["checks"]["database"]["status"] == "not_checked_in_v01"
    # New centralized verdict is additive.
    verdict = body["readiness"]
    assert verdict["ready"] is True
    assert verdict["status"] == "ready"
    assert verdict["checks"]["application"] == "READY"
    assert verdict["checks"]["database"] == "READY"
    assert verdict["checks"]["workers"] == "READY"


def test_ready_503_when_database_down(client: TestClient) -> None:
    state = _state(client)
    saved = state.session_factory

    def _broken() -> Any:
        raise ConnectionError("db gone")

    state.session_factory = _broken
    try:
        res = client.get("/ready")
        assert res.status_code == 503
        body = res.json()
        assert body["ready"] is False
        assert body["readiness"]["checks"]["database"] == "NOT_READY"
        # Legacy keys still present even on 503.
        assert body["status"] == "ok"
        assert "checks" in body
    finally:
        state.session_factory = saved
    assert client.get("/ready").status_code == 200


def test_ready_503_when_shutting_down(client: TestClient) -> None:
    state = _state(client)
    state.runtime.shutdown()
    res = client.get("/ready")
    assert res.status_code == 503
    assert res.json()["ready"] is False


def test_health_has_runtime_snapshot(client: TestClient) -> None:
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["runtime"]["state"] == "READY"
    assert body["runtime"]["ready"] is True


def test_v1_health_components_and_summary(client: TestClient) -> None:
    res = client.get("/api/v1/health")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "ok"
    assert body["checks"]["database"]["status"] == "not_checked_in_v01"
    components = {c["component"]: c for c in body["components"]}
    for name in (
        "application",
        "database",
        "camera_manager",
        "inference",
        "tracking",
        "safety",
        "spatial",
        "quality",
        "autonomous",
        "intelligence",
        "incidents",
        "websocket",
        "workers",
    ):
        assert name in components, name
        component = components[name]
        assert set(component) == {
            "component",
            "status",
            "message",
            "latency_ms",
            "timestamp",
            "metadata",
        }
        assert component["latency_ms"] >= 0.0
    assert body["summary"] in ("READY", "DEGRADED", "NOT_READY")
    # Testing env ships no loaded model: inference honestly reports it.
    assert components["inference"]["status"] == "NOT_READY"


def test_health_payloads_have_no_secrets(client: TestClient) -> None:
    blobs: list[str] = []
    for path in ("/health", "/live", "/ready", "/api/v1/health"):
        blobs.append(client.get(path).text.lower())
    blob = "\n".join(blobs)
    for secret in ("password", "passwd", "secret", "postgres://", "api_key", "apikey", "token"):
        assert secret not in blob, secret
