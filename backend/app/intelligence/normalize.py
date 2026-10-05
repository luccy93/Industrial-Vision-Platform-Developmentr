"""Source-domain adapters: domain events → canonical ``UnifiedEvent``.

Each adapter preserves source identity (IDs, camera, timestamps, tracks,
severity, metadata) and maps the source type into the unified taxonomy. The
original source type is always kept in ``metadata["source_event_type"]`` so
no domain semantics are destroyed.

Adapters duck-type their inputs (attribute access with safe defaults) so the
intelligence layer does not import domain engine internals. Missing optional
fields degrade to defaults; missing identity (camera, timestamps) raises
``ValueError`` rather than inventing values.

Reserved domains (TRACKING, PERCEPTION, SYSTEM) have no registered adapter
in V09 — V09 never synthesizes events for them.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import UUID

from backend.app.domain.common import utcnow
from backend.app.intelligence.schemas import (
    EventSourceDomain,
    UnifiedEvent,
    UnifiedEventStatus,
    UnifiedEventType,
    UnifiedSeverity,
)

# SafetyEvent rules owned by the V06 spatial package (mirrors the WS router).
SPATIAL_RULES: frozenset[str] = frozenset({"restricted_zone", "proximity_relationships"})

_SAFETY_TYPE_MAP: dict[str, UnifiedEventType] = {
    "POSSIBLE_FALL": UnifiedEventType.FALL_RISK,
    "CROWD_WARNING": UnifiedEventType.CROWD_WARNING,
    "CROWD_CRITICAL": UnifiedEventType.CROWD_CRITICAL,
    "PERSON_VEHICLE_PROXIMITY": UnifiedEventType.PERSON_VEHICLE_PROXIMITY,
    "PROLONGED_STATIONARY": UnifiedEventType.STATIONARY_OBJECT,
    "RESTRICTED_ZONE_ENTRY": UnifiedEventType.RESTRICTED_ZONE_ENTRY,
    "RESTRICTED_ZONE_EXIT": UnifiedEventType.RESTRICTED_ZONE_EXIT,
    "ZONE_DWELL": UnifiedEventType.RESTRICTED_ZONE_DWELL,
}

_QUALITY_TYPE_MAP: dict[str, UnifiedEventType] = {
    "QUALITY_FAIL": UnifiedEventType.QUALITY_FAIL,
    "QUALITY_REVIEW": UnifiedEventType.QUALITY_REVIEW,
    "QUALITY_ERROR": UnifiedEventType.QUALITY_ERROR,
    "DEFECT_DETECTED": UnifiedEventType.DEFECT_DETECTED,
}

_AUTONOMOUS_TYPE_MAP: dict[str, UnifiedEventType] = {
    "COLLISION_RISK": UnifiedEventType.COLLISION_RISK,
    "LANE_DEPARTURE_RISK": UnifiedEventType.LANE_DEPARTURE_RISK,
    "OBJECT_APPROACH": UnifiedEventType.OBJECT_APPROACH,
    "OBJECT_CROSSING": UnifiedEventType.OBJECT_CROSSING,
    "SCENE_CHANGE": UnifiedEventType.SCENE_CHANGE,
}

# V08 risk levels share severity names except NONE (→INFO).
_RISK_SEVERITY_MAP: dict[str, UnifiedSeverity] = {
    "NONE": UnifiedSeverity.INFO,
    "LOW": UnifiedSeverity.LOW,
    "MEDIUM": UnifiedSeverity.MEDIUM,
    "HIGH": UnifiedSeverity.HIGH,
    "CRITICAL": UnifiedSeverity.CRITICAL,
    "UNKNOWN": UnifiedSeverity.UNKNOWN,
}

_STATUS_MAP: dict[str, UnifiedEventStatus] = {
    "ACTIVE": UnifiedEventStatus.ACTIVE,
    "RESOLVED": UnifiedEventStatus.RESOLVED,
    "SUPPRESSED": UnifiedEventStatus.SUPPRESSED,
}


def _name(value: Any, default: str = "UNKNOWN") -> str:
    if value is None:
        return default
    if isinstance(value, Enum):
        return str(value.value)
    text = str(value).strip()
    return text if text else default


def _severity(value: Any) -> UnifiedSeverity:
    try:
        return UnifiedSeverity(_name(value))
    except ValueError:
        return UnifiedSeverity.UNKNOWN


def _status(value: Any) -> UnifiedEventStatus:
    return _STATUS_MAP.get(_name(value, "ACTIVE"), UnifiedEventStatus.ACTIVE)


def _confidence(value: Any) -> float:
    try:
        return min(1.0, max(0.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def _text(value: Any) -> str:
    return str(value) if value is not None else ""


def _timestamps(event: Any) -> tuple[datetime, datetime, datetime]:
    timestamp = getattr(event, "timestamp", None)
    first_seen = getattr(event, "first_seen", None)
    last_seen = getattr(event, "last_seen", None)
    if not isinstance(timestamp, datetime):
        timestamp = first_seen if isinstance(first_seen, datetime) else last_seen
    if not isinstance(timestamp, datetime):
        raise ValueError("source event carries no usable timestamp")
    if not isinstance(first_seen, datetime):
        first_seen = timestamp
    if not isinstance(last_seen, datetime):
        last_seen = timestamp
    return timestamp, first_seen, last_seen


def _camera_id(event: Any) -> str:
    camera_id = getattr(event, "camera_id", None)
    text = str(camera_id).strip() if camera_id is not None else ""
    if not text:
        raise ValueError("source event carries no camera_id")
    return text


def _track_ids(event: Any) -> list[int]:
    raw = getattr(event, "track_ids", None) or []
    ids: list[int] = []
    for item in raw:
        try:
            ids.append(int(item))
        except (TypeError, ValueError):
            continue
    single = getattr(event, "track_id", None)
    if single is not None:
        try:
            value = int(single)
            if value not in ids:
                ids.append(value)
        except (TypeError, ValueError):
            pass
    return ids


def _object_ids(event: Any) -> list[str]:
    raw = getattr(event, "object_ids", None) or []
    return [str(item) for item in raw if str(item).strip()]


def _evidence(event: Any) -> dict[str, Any]:
    evidence = getattr(event, "evidence", None)
    return dict(evidence) if isinstance(evidence, dict) else {}


def _metadata(event: Any) -> dict[str, Any]:
    metadata = getattr(event, "metadata", None)
    return dict(metadata) if isinstance(metadata, dict) else {}


def _source_id(event: Any) -> str:
    for attr in ("event_id", "inspection_id", "scene_id"):
        value = getattr(event, attr, None)
        if value is None:
            continue
        if isinstance(value, UUID):
            return str(value)
        text = str(value).strip()
        if text:
            return text
    raise ValueError("source event carries no usable identity")


def _base(
    event: Any,
    domain: EventSourceDomain,
    event_type: UnifiedEventType,
    severity: UnifiedSeverity,
    location: str | None,
    reason: str,
    extra_metadata: dict[str, Any] | None = None,
) -> UnifiedEvent:
    timestamp, first_seen, last_seen = _timestamps(event)
    metadata = _metadata(event)
    if extra_metadata:
        metadata.update(extra_metadata)
    return UnifiedEvent(
        source_event_id=_source_id(event),
        camera_id=_camera_id(event),
        source_domain=domain,
        event_type=event_type,
        severity=severity,
        status=_status(getattr(event, "status", None)),
        confidence=_confidence(getattr(event, "confidence", None)),
        timestamp=timestamp,
        first_seen=first_seen,
        last_seen=last_seen,
        track_ids=_track_ids(event),
        object_ids=_object_ids(event),
        location=location,
        message=_text(getattr(event, "message", "")),
        reason=reason,
        evidence=_evidence(event),
        metadata=metadata,
    )


def is_spatial_safety_event(event: Any) -> bool:
    """True when a SafetyEvent was produced by a V06 spatial rule."""
    metadata = _metadata(event)
    return str(metadata.get("rule", "")) in SPATIAL_RULES


class SafetyEventAdapter:
    """Normalizes V05 safety events (non-spatial rules)."""

    domain = EventSourceDomain.SAFETY

    def normalize(self, event: Any) -> UnifiedEvent:
        if event is None:
            raise ValueError("cannot normalize a missing safety event")
        source_type = _name(getattr(event, "event_type", None))
        event_type = _SAFETY_TYPE_MAP.get(source_type, UnifiedEventType.UNKNOWN)
        reason = f"normalized V05 safety event {source_type}"
        if event_type is UnifiedEventType.UNKNOWN:
            reason += " (no taxonomy counterpart; source type preserved in metadata)"
        return _base(
            event,
            self.domain,
            event_type,
            _severity(getattr(event, "severity", None)),
            None,
            reason,
            {"source_event_type": source_type},
        )


class SpatialEventAdapter:
    """Normalizes V06 spatial safety events (zone/proximity rules)."""

    domain = EventSourceDomain.SPATIAL

    def normalize(self, event: Any) -> UnifiedEvent:
        if event is None:
            raise ValueError("cannot normalize a missing spatial event")
        source_type = _name(getattr(event, "event_type", None))
        event_type = _SAFETY_TYPE_MAP.get(source_type, UnifiedEventType.UNKNOWN)
        evidence = _evidence(event)
        zone_id = evidence.get("zone_id")
        location = str(zone_id) if zone_id else None
        reason = f"normalized V06 spatial event {source_type}"
        if event_type is UnifiedEventType.UNKNOWN:
            reason += " (no taxonomy counterpart; source type preserved in metadata)"
        return _base(
            event,
            self.domain,
            event_type,
            _severity(getattr(event, "severity", None)),
            location,
            reason,
            {"source_event_type": source_type},
        )


class QualityEventAdapter:
    """Normalizes V07 quality events and (non-PASS) quality results."""

    domain = EventSourceDomain.QUALITY

    def normalize(self, event: Any) -> UnifiedEvent:
        if event is None:
            raise ValueError("cannot normalize a missing quality event")
        source_type = _name(getattr(event, "event_type", None))
        event_type = _QUALITY_TYPE_MAP.get(source_type, UnifiedEventType.UNKNOWN)
        region = getattr(event, "region_id", None)
        location = str(region) if region else None
        reason = f"normalized V07 quality event {source_type}"
        return _base(
            event,
            self.domain,
            event_type,
            _severity(getattr(event, "severity", None)),
            location,
            reason,
            {
                "source_event_type": source_type,
                "decision": _name(getattr(event, "decision", None), ""),
                "defect_code": getattr(event, "defect_code", None),
            },
        )

    def normalize_result(self, result: Any) -> UnifiedEvent | None:
        """Normalizes a V07 InspectionResult. PASS results yield None.

        A PASS result reports the absence of qualifying defects — turning it
        into a unified event would manufacture signal from silence.
        """
        if result is None:
            raise ValueError("cannot normalize a missing quality result")
        decision = _name(getattr(result, "decision", None))
        if decision == "PASS":
            return None
        mapped = {"FAIL": "QUALITY_FAIL", "REVIEW": "QUALITY_REVIEW", "ERROR": "QUALITY_ERROR"}
        source_type = mapped.get(decision, decision)
        event_type = _QUALITY_TYPE_MAP.get(source_type, UnifiedEventType.UNKNOWN)
        timestamp, first_seen, last_seen = _timestamps(result)
        regions = getattr(result, "regions_evaluated", None) or []
        location = str(regions[0]) if regions else None
        metadata = _metadata(result)
        metadata.update(
            {
                "source_event_type": f"RESULT_{decision}",
                "decision_reason": _text(getattr(result, "decision_reason", "")),
                "error_code": getattr(result, "error_code", None),
            }
        )
        return UnifiedEvent(
            source_event_id=_source_id(result),
            camera_id=_camera_id(result),
            source_domain=self.domain,
            event_type=event_type,
            severity=_severity(getattr(result, "severity", None)),
            status=UnifiedEventStatus.ACTIVE,
            confidence=_confidence(getattr(result, "confidence", 0.0)),
            timestamp=timestamp,
            first_seen=first_seen,
            last_seen=last_seen,
            location=location,
            message=_text(getattr(result, "decision_reason", "")),
            reason=f"normalized V07 quality result {decision}",
            evidence={"regions_evaluated": list(regions)},
            metadata=metadata,
        )


class AutonomousEventAdapter:
    """Normalizes V08 autonomous perception events and collision risks."""

    domain = EventSourceDomain.AUTONOMOUS

    def normalize(self, event: Any) -> UnifiedEvent:
        if event is None:
            raise ValueError("cannot normalize a missing autonomous event")
        source_type = _name(getattr(event, "event_type", None))
        event_type = _AUTONOMOUS_TYPE_MAP.get(source_type, UnifiedEventType.UNKNOWN)
        reason = f"normalized V08 autonomous event {source_type}"
        return _base(
            event,
            self.domain,
            event_type,
            _severity(_risk_to_severity_name(getattr(event, "risk_level", None))),
            None,
            reason,
            {"source_event_type": source_type},
        )

    def normalize_risk(self, risk: Any, camera_id: str) -> UnifiedEvent:
        """Normalizes a V08 CollisionRisk assessment (interface completeness).

        The engine path consumes risk *events*; this adapter exists for
        external feeders. The pair key stands in as the source identity.
        """
        if risk is None:
            raise ValueError("cannot normalize a missing collision risk")
        object_ids = [str(item) for item in (getattr(risk, "object_ids", None) or [])]
        if not str(camera_id).strip():
            raise ValueError("collision risk carries no camera_id")
        timestamp = getattr(risk, "timestamp", None)
        if not isinstance(timestamp, datetime):
            timestamp = utcnow()
        pair = ":".join(sorted(object_ids)) if object_ids else "unknown-pair"
        return UnifiedEvent(
            source_event_id=f"collision-risk:{pair}",
            camera_id=str(camera_id).strip(),
            source_domain=self.domain,
            event_type=UnifiedEventType.COLLISION_RISK,
            severity=_severity(_risk_to_severity_name(getattr(risk, "risk_level", None))),
            status=UnifiedEventStatus.ACTIVE,
            confidence=_confidence(getattr(risk, "confidence", None)),
            timestamp=timestamp,
            first_seen=timestamp,
            last_seen=timestamp,
            object_ids=object_ids,
            message=_text(getattr(risk, "reason", "")),
            reason="normalized V08 collision risk assessment",
            evidence={
                "risk_score": getattr(risk, "risk_score", None),
                "time_to_collision": getattr(risk, "time_to_collision", None),
            },
            metadata={"source_event_type": "COLLISION_RISK_ASSESSMENT"},
        )


def _risk_to_severity_name(risk_level: Any) -> str:
    name = _name(risk_level)
    return _RISK_SEVERITY_MAP.get(name, UnifiedSeverity.UNKNOWN).value


ADAPTERS: dict[EventSourceDomain, Any] = {
    EventSourceDomain.SAFETY: SafetyEventAdapter(),
    EventSourceDomain.SPATIAL: SpatialEventAdapter(),
    EventSourceDomain.QUALITY: QualityEventAdapter(),
    EventSourceDomain.AUTONOMOUS: AutonomousEventAdapter(),
}
