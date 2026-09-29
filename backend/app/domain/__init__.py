"""Domain contracts — strongly typed, reusable Pydantic v2 models.

V01 establishes the shared vocabulary for all future volumes
(ingestion → inference → tracking → safety/quality/perception →
risk → incident → API/dashboard). No business logic lives here.
"""

from backend.app.domain.camera import Camera, CameraStatus
from backend.app.domain.detection import BoundingBox, Detection, TrackedObject
from backend.app.domain.events import PerceptionEvent, QualityEvent, SafetyEvent
from backend.app.domain.incident import Alert, AlertSeverity, Incident, IncidentStatus
from backend.app.domain.risk import RiskAssessment, RiskLevel
from backend.app.domain.video import Frame, VideoStream, StreamStatus

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
    "PerceptionEvent",
    "QualityEvent",
    "RiskAssessment",
    "RiskLevel",
    "SafetyEvent",
    "StreamStatus",
    "TrackedObject",
    "VideoStream",
]
