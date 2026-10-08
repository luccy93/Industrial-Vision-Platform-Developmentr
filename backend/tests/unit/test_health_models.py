"""Health model tests — states, aggregation, secret-free payloads."""

from __future__ import annotations

from backend.app.runtime.health import (
    HEALTH_COMPONENTS,
    ComponentHealth,
    HealthStatus,
    component_health,
    summarize,
)


def _make(component: str, status: HealthStatus) -> ComponentHealth:
    return component_health(component, status, message=f"{component} {status.value}")


def test_worst_state_aggregation() -> None:
    assert summarize([_make("a", HealthStatus.READY)]) is HealthStatus.READY
    assert (
        summarize([_make("a", HealthStatus.READY), _make("b", HealthStatus.DEGRADED)])
        is HealthStatus.DEGRADED
    )
    assert (
        summarize([_make("a", HealthStatus.DEGRADED), _make("b", HealthStatus.NOT_READY)])
        is HealthStatus.NOT_READY
    )
    assert (
        summarize([_make("a", HealthStatus.NOT_READY), _make("b", HealthStatus.FAILED)])
        is HealthStatus.FAILED
    )


def test_disabled_components_ignored() -> None:
    assert (
        summarize([_make("depth", HealthStatus.DISABLED), _make("api", HealthStatus.READY)])
        is HealthStatus.READY
    )
    assert summarize([_make("depth", HealthStatus.DISABLED)]) is HealthStatus.DISABLED


def test_unknown_propagates() -> None:
    assert (
        summarize([_make("a", HealthStatus.READY), _make("b", HealthStatus.UNKNOWN)]) is HealthStatus.UNKNOWN
    )


def test_component_payload_has_no_secrets() -> None:
    health = component_health(
        "database",
        HealthStatus.READY,
        metadata={"driver": "postgresql", "reachable": True},
    )
    payload = health.model_dump(mode="json")
    assert set(payload) == {
        "component",
        "status",
        "message",
        "latency_ms",
        "timestamp",
        "metadata",
    }
    blob = str(payload).lower()
    for secret in ("password", "passwd", "secret", "token", "api_key", "apikey"):
        assert secret not in blob


def test_expected_components_listed() -> None:
    for name in (
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
        assert name in HEALTH_COMPONENTS


def test_latency_never_negative() -> None:
    assert component_health("x", HealthStatus.READY, latency_ms=-5.0).latency_ms == 0.0
