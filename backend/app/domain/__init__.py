"""Domain contracts — strongly typed, reusable Pydantic v2 models.

V01 established the shared vocabulary; V02 adds ingestion contracts
(source types, stream states, frames). No business logic lives here.
"""

from backend.app.domain.camera import Camera, CameraStatus
from backend.app.domain.detection import BoundingBox, Detection, TrackedObject
from backend.app.domain.events import PerceptionEvent, QualityEvent, SafetyEvent
from backend.app.domain.frame import IngestionFrame
from backend.app.domain.incident import Alert, AlertSeverity, Incident, IncidentStatus
from backend.app.domain.risk import RiskAssessment, RiskLevel
from backend.app.domain.stream import SourceType, StreamMetrics, StreamState, redact_source
from backend.app.domain.video import Frame, StreamStatus, VideoStream

__all__ = [
    "Alert",
    "AlertSeverity",
    "BoundingBox",
    "Camera",
    "CameraStatus",
    "Detection",
    "Frame",
    "Incident",
    "IncidentStatus",
    "IngestionFrame",
    "PerceptionEvent",
    "QualityEvent",
    "RiskAssessment",
    "RiskLevel",
    "SafetyEvent",
    "SourceType",
    "StreamMetrics",
    "StreamState",
    "StreamStatus",
    "TrackedObject",
    "VideoStream",
    "redact_source",
]
