"""Shared incident test builders — deterministic, hermetic, no services.

Fixed synthetic epoch mirrors the other helper modules so duration
assertions never depend on wall-clock speed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from backend.app.incidents.schemas import (
    Incident,
    IncidentCategory,
    IncidentEvidence,
    IncidentStatus,
)
from backend.app.intelligence.schemas import EventPriority, RiskLevel, UnifiedSeverity


def utc(offset_seconds: float = 0.0) -> datetime:
    """Deterministic test clock: exact offsets from a fixed epoch."""
    return datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=offset_seconds)


def make_incident(**overrides: Any) -> Incident:
    params: dict[str, Any] = {
        "incident_number": "INC-2026-000001",
        "camera_id": "cam-01",
        "title": "Person in restricted zone",
        "description": "Operator review requested",
        "source_cluster_id": "cluster-01",
        "primary_event_id": "SAFETY:evt-01",
        "severity": UnifiedSeverity.HIGH,
        "risk_level": RiskLevel.HIGH,
        "risk_score": 0.78,
        "priority": EventPriority.P1,
        "status": IncidentStatus.OPEN,
        "category": IncidentCategory.SPATIAL,
    }
    params.update(overrides)
    return Incident(**params)


def make_evidence(**overrides: Any) -> IncidentEvidence:
    from uuid import uuid4

    params: dict[str, Any] = {
        "incident_id": uuid4(),
        "camera_id": "cam-01",
        "uri": "s3://evidence-bucket/cam-01/frame-123.jpg",
        "description": "Frame showing the zone entry",
    }
    params.update(overrides)
    return IncidentEvidence(**params)
