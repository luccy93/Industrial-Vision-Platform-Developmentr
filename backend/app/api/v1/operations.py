"""Operations summary — thin read-only dashboard aggregation (V13).

Assembles cross-camera aggregates exclusively from existing domain
services and repositories. No domain logic lives here: engines and
repositories stay authoritative; this module counts, groups, and bounds.

Every section reports its own availability: a failed domain never
zeroes — or breaks — unrelated sections. No cache (V12 decision stands):
PostgreSQL and live engine state are read directly on each call.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Protocol, TypeVar

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

from backend.app.domain.common import utcnow

router = APIRouter(tags=["operations"])

MAX_EVENT_SCAN = 200
MAX_CAMERAS_SCAN = 50


class SectionState(str, Enum):
    OK = "ok"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class CamerasSection(BaseModel):
    status: SectionState = SectionState.OK
    message: str = ""
    configured: int = 0
    enabled: int = 0
    by_state: dict[str, int] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utcnow)


class SafetySection(BaseModel):
    status: SectionState = SectionState.OK
    message: str = ""
    total_active: int = 0
    by_severity: dict[str, int] = Field(default_factory=dict)
    cameras_with_events: int = 0
    truncated: bool = False
    updated_at: datetime = Field(default_factory=utcnow)


class IncidentsSection(BaseModel):
    status: SectionState = SectionState.OK
    message: str = ""
    total: int = 0
    open_total: int = 0
    by_status: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utcnow)


class QualitySection(BaseModel):
    status: SectionState = SectionState.OK
    message: str = ""
    model_status: str = "UNKNOWN"
    outcomes: dict[str, int] = Field(default_factory=dict)
    active_profiles: int = 0
    updated_at: datetime = Field(default_factory=utcnow)


class RiskSection(BaseModel):
    status: SectionState = SectionState.OK
    message: str = ""
    risk_level: str = "UNKNOWN"
    risk_score: float = 0.0
    priority: str = "P4"
    active_events: int = 0
    active_clusters: int = 0
    updated_at: datetime = Field(default_factory=utcnow)


class HealthSection(BaseModel):
    status: SectionState = SectionState.OK
    message: str = ""
    ready: bool = False
    readiness: str = "unknown"
    checks: dict[str, str] = Field(default_factory=dict)
    updated_at: datetime = Field(default_factory=utcnow)


class OperationsSummary(BaseModel):
    timestamp: datetime = Field(default_factory=utcnow)
    cameras: CamerasSection = Field(default_factory=CamerasSection)
    safety: SafetySection = Field(default_factory=SafetySection)
    incidents: IncidentsSection = Field(default_factory=IncidentsSection)
    quality: QualitySection = Field(default_factory=QualitySection)
    risk: RiskSection = Field(default_factory=RiskSection)
    health: HealthSection = Field(default_factory=HealthSection)


class _Section(Protocol):
    status: SectionState
    message: str


_S = TypeVar("_S", bound=_Section)


def _unavailable(section: _S, message: str) -> _S:
    section.status = SectionState.UNAVAILABLE
    section.message = str(message)[:256]
    return section


def _cameras_section(state: Any) -> CamerasSection:
    from backend.app.ingestion.repository import CameraRepository

    section = CamerasSection()
    try:
        factory = getattr(state, "session_factory", None)
        configured = CameraRepository(factory).list() if factory is not None else []
    except Exception as exc:
        return _unavailable(section, f"camera registry unreadable: {type(exc).__name__}")
    try:
        supervisor = getattr(state, "supervisor", None)
        statuses = supervisor.statuses() if supervisor is not None else {}
    except Exception:
        statuses = {}
    by_state: dict[str, int] = {}
    enabled = 0
    for camera in configured:
        if bool(getattr(camera, "enabled", True)):
            enabled += 1
        metrics = statuses.get(getattr(camera, "camera_id", ""))
        name = str(getattr(getattr(metrics, "state", None), "value", "NOT_STARTED"))
        by_state[name] = by_state.get(name, 0) + 1
    section.configured = len(configured)
    section.enabled = enabled
    section.by_state = by_state
    return section


def _safety_section(state: Any) -> SafetySection:
    section = SafetySection()
    engine = getattr(state, "safety_engine", None)
    if engine is None:
        return _unavailable(section, "safety engine not registered")
    try:
        if not bool(getattr(engine, "enabled", True)):
            return _unavailable(section, "safety engine disabled")
        status = engine.status()
        camera_ids = list((status.get("cameras") or {}).keys())[:MAX_CAMERAS_SCAN]
    except Exception as exc:
        return _unavailable(section, f"safety status failed: {type(exc).__name__}")
    by_severity: dict[str, int] = {}
    total = 0
    with_events = 0
    truncated = False
    for camera_id in camera_ids:
        try:
            events = engine.active_events(camera_id, 50)
        except Exception:
            continue
        if events:
            with_events += 1
        for event in events:
            if total >= MAX_EVENT_SCAN:
                truncated = True
                break
            severity = str(getattr(getattr(event, "severity", None), "value", "UNKNOWN"))
            by_severity[severity] = by_severity.get(severity, 0) + 1
            total += 1
        if truncated:
            break
    section.total_active = total
    section.by_severity = by_severity
    section.cameras_with_events = with_events
    section.truncated = truncated
    return section


def _incidents_section(state: Any) -> IncidentsSection:
    section = IncidentsSection()
    manager = getattr(state, "incident_manager", None)
    if manager is None:
        return _unavailable(section, "incident manager not registered")
    try:
        grouped = manager.repository.count_by_status_priority()
    except Exception as exc:
        return _unavailable(section, f"incident query failed: {type(exc).__name__}")
    by_status: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    total = 0
    for status, priorities in grouped.items():
        subtotal = sum(int(v) for v in priorities.values())
        by_status[str(status)] = subtotal
        total += subtotal
        for priority, count in priorities.items():
            by_priority[str(priority)] = by_priority.get(str(priority), 0) + int(count)
    section.total = total
    section.open_total = total - by_status.get("CLOSED", 0)
    section.by_status = by_status
    section.by_priority = by_priority
    return section


def _quality_section(state: Any) -> QualitySection:
    section = QualitySection()
    engine = getattr(state, "quality_engine", None)
    if engine is None:
        return _unavailable(section, "quality engine not registered")
    try:
        status = engine.status()
    except Exception as exc:
        return _unavailable(section, f"quality status failed: {type(exc).__name__}")
    model_status = str(status.get("model_status", "UNKNOWN"))
    section.model_status = model_status
    if model_status == "NOT_CONFIGURED":
        # Missing inference is not a PASS: report unavailable, never zeros-as-ok.
        return _unavailable(section, "inspection model not configured")
    section.outcomes = {
        "PASS": int(status.get("pass_count", 0) or 0),
        "FAIL": int(status.get("fail_count", 0) or 0),
        "REVIEW": int(status.get("review_count", 0) or 0),
        "ERROR": int(status.get("error_count", 0) or 0),
    }
    section.active_profiles = int(status.get("active_profiles", 0) or 0)
    return section


def _risk_section(state: Any) -> RiskSection:
    section = RiskSection()
    engine = getattr(state, "intelligence_engine", None)
    if engine is None:
        return _unavailable(section, "intelligence engine not registered")
    try:
        if not bool(getattr(engine, "enabled", True)):
            return _unavailable(section, "intelligence engine disabled")
        status = engine.status()
    except Exception as exc:
        return _unavailable(section, f"risk status failed: {type(exc).__name__}")
    highest = status.get("highest_risk") or {}
    # UNKNOWN/0.0/P4 with no latest is the established risk contract:
    # genuine absence of risk signal, not a failure.
    section.risk_level = str(highest.get("risk_level", "UNKNOWN"))
    try:
        section.risk_score = float(highest.get("risk_score", 0.0) or 0.0)
    except (TypeError, ValueError):
        section.risk_score = 0.0
    section.priority = str(status.get("highest_priority", "P4"))
    section.active_events = int(status.get("active_events", 0) or 0)
    section.active_clusters = int(status.get("active_clusters", 0) or 0)
    return section


def _health_section(state: Any) -> HealthSection:
    section = HealthSection()
    readiness = getattr(state, "readiness", None)
    if readiness is None:
        return _unavailable(section, "readiness service not registered")
    try:
        verdict = readiness.evaluate()
    except Exception as exc:
        return _unavailable(section, f"readiness failed: {type(exc).__name__}")
    section.ready = bool(verdict.get("ready", False))
    section.readiness = str(verdict.get("status", "unknown"))
    checks = verdict.get("checks") or {}
    section.checks = {str(k): str(v) for k, v in checks.items()}
    return section


@router.get("/api/v1/operations/summary", summary="Operations summary")
def operations_summary(request: Request) -> OperationsSummary:
    """Cross-camera dashboard snapshot assembled from live services."""
    state = request.app.state
    return OperationsSummary(
        timestamp=utcnow(),
        cameras=_cameras_section(state),
        safety=_safety_section(state),
        incidents=_incidents_section(state),
        quality=_quality_section(state),
        risk=_risk_section(state),
        health=_health_section(state),
    )
