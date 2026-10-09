"""Versioned event envelopes — bus contracts (V12, §5.2).

Event types reuse existing domain contracts (V05–V10 wire/builder names);
the envelope adds identity, versioning, origin, and size bounds. No new
event types are invented here, and reserved V09 domains stay reserved.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from backend.app.domain.common import utcnow

EVENT_ENVELOPE_VERSION = 1

# Event types carried on the bus (locked scope): genuine V05–V08 domain
# events, V09 unified/cluster updates, V10 incident lifecycle. Never raw
# frames, detections, tracks, telemetry, or heartbeats.
BUS_EVENT_TYPES = frozenset(
    {
        # V05/V06 safety + spatial (wire names from streams_ws).
        "safety_event",
        "zone_event",
        "proximity_event",
        # V07 quality.
        "quality_event",
        "quality_result",
        # V08 autonomous perception.
        "autonomous_perception",
        "collision_risk",
        "lane_event",
        # V09 intelligence.
        "intelligence_event",
        "risk_cluster",
        "risk_update",
        # V10 incident lifecycle.
        "incident_created",
        "incident_updated",
        "incident_status_changed",
        "incident_assigned",
        "incident_resolved",
        "incident_closed",
        "incident_evidence_added",
    }
)


class EventEnvelope(BaseModel):
    """Validated bus envelope (v1)."""

    v: int = Field(default=EVENT_ENVELOPE_VERSION, ge=1, le=16)
    event_id: str = Field(min_length=1, max_length=256)
    event_type: str = Field(min_length=1, max_length=64)
    domain: str = Field(min_length=1, max_length=32)
    camera_id: str = Field(default="", max_length=128)
    timestamp: datetime = Field(default_factory=utcnow)
    origin: str = Field(min_length=1, max_length=128)
    payload: dict[str, Any] = Field(default_factory=dict)

    _normalize_type = field_validator("event_type", mode="before")(
        lambda value: value.strip() if isinstance(value, str) else value
    )
    _normalize_domain = field_validator("domain", mode="before")(
        lambda value: value.strip().upper() if isinstance(value, str) else value
    )

    def to_bytes(self, max_payload_bytes: int = 65536) -> bytes:
        """Serialize with an explicit size bound (oversize → ValueError)."""
        raw = self.model_dump_json().encode("utf-8")
        if len(raw) > max(1024, int(max_payload_bytes)):
            raise ValueError(f"event envelope too large ({len(raw)} bytes > {max_payload_bytes} bytes)")
        return raw

    @classmethod
    def from_bytes(cls, raw: bytes | bytearray) -> EventEnvelope:
        """Parse + validate; malformed input raises ValueError (never None)."""
        try:
            data = json.loads(bytes(raw).decode("utf-8"))
        except Exception as exc:
            raise ValueError(f"malformed event envelope: {type(exc).__name__}") from exc
        if not isinstance(data, dict):
            raise ValueError("malformed event envelope: not an object")
        try:
            envelope = cls.model_validate(data)
        except Exception as exc:
            raise ValueError(f"invalid event envelope: {exc}") from exc
        if envelope.v != EVENT_ENVELOPE_VERSION:
            raise ValueError(f"unsupported envelope version: {envelope.v}")
        return envelope

    @staticmethod
    def new_id(prefix: str = "evt") -> str:
        clean = "".join(c for c in str(prefix or "evt") if c.isalnum() or c in ("-", "_"))[:32]
        return f"{clean or 'evt'}-{uuid.uuid4().hex[:12]}"
