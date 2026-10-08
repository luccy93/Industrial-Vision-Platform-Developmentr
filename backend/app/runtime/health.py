"""Structured health models — component states without secrets (V11).

Health checks are lightweight by contract: no inference runs, no camera
connection tests, no credentials or model paths in any payload.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from backend.app.domain.common import utcnow


class HealthStatus(str, Enum):
    """Component health states (single vocabulary for every check)."""

    READY = "READY"
    DEGRADED = "DEGRADED"
    NOT_READY = "NOT_READY"
    FAILED = "FAILED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


class ComponentHealth(BaseModel):
    """Health of one backend component."""

    component: str = Field(min_length=1, max_length=128)
    status: HealthStatus = HealthStatus.UNKNOWN
    message: str = Field(default="", max_length=1024)
    latency_ms: float = Field(default=0.0, ge=0.0)
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ReadinessStatus(BaseModel):
    """Aggregate readiness verdict for traffic serving."""

    ready: bool
    status: str = Field(min_length=1, max_length=64)
    checks: dict[str, str] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)


# Components with first-class health checks (§9). Optional subsystems report
# DISABLED / NOT_CONFIGURED / DEGRADED here without failing readiness.
HEALTH_COMPONENTS: tuple[str, ...] = (
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
)


def component_health(
    component: str,
    status: HealthStatus,
    message: str = "",
    latency_ms: float = 0.0,
    metadata: dict[str, Any] | None = None,
) -> ComponentHealth:
    """Build a ComponentHealth with a fresh timestamp."""
    return ComponentHealth(
        component=component,
        status=status,
        message=message,
        latency_ms=max(0.0, float(latency_ms)),
        timestamp=utcnow(),
        metadata=dict(metadata or {}),
    )


def summarize(components: list[ComponentHealth]) -> HealthStatus:
    """Worst-state aggregation: FAILED > NOT_READY > DEGRADED > UNKNOWN > READY.

    DISABLED components are ignored (optional subsystems that are simply
    off never degrade the aggregate).
    """
    considered = [c.status for c in components if c.status is not HealthStatus.DISABLED]
    if not considered:
        return HealthStatus.DISABLED
    for state in (
        HealthStatus.FAILED,
        HealthStatus.NOT_READY,
        HealthStatus.DEGRADED,
        HealthStatus.UNKNOWN,
        HealthStatus.READY,
    ):
        if state in considered:
            return state
    return HealthStatus.UNKNOWN  # pragma: no cover - unreachable
