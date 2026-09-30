"""Inference API — model status + recent per-camera detections (runtime state).

High-frequency results stay in memory; PostgreSQL persistence of selected
events arrives in later volumes.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from backend.app.api.v1.cameras import get_repository
from backend.app.inference.manager import ModelManager
from backend.app.inference.worker import InferenceSupervisor
from backend.app.ingestion.repository import CameraRepository

router = APIRouter(tags=["inference"])


def get_model_manager(request: Request) -> ModelManager:
    manager = getattr(request.app.state, "model_manager", None)
    if manager is None:
        from backend.app.core.config import get_settings

        manager = ModelManager.from_settings(get_settings(), use_mock=True)
    return manager


def get_inference_supervisor(request: Request) -> InferenceSupervisor:
    supervisor = getattr(request.app.state, "inference_supervisor", None)
    if supervisor is None:
        supervisor = InferenceSupervisor()
    return supervisor


@router.get("/api/v1/inference/status")
def inference_status(
    manager: ModelManager = Depends(get_model_manager),
    supervisor: InferenceSupervisor = Depends(get_inference_supervisor),
) -> dict[str, Any]:
    body = manager.status()
    body["active_workers"] = supervisor.worker_count()
    return body


@router.get("/api/v1/cameras/{camera_id}/detections")
def camera_detections(
    camera_id: str,
    limit: int = 10,
    repository: CameraRepository = Depends(get_repository),
    supervisor: InferenceSupervisor = Depends(get_inference_supervisor),
) -> dict[str, Any]:
    if repository.get(camera_id) is None:
        raise HTTPException(status_code=404, detail="camera not found")
    worker = supervisor.get(camera_id)
    results = worker.recent(max(1, min(limit, 30))) if worker else []
    return {
        "camera_id": camera_id,
        "inference_running": worker.running if worker else False,
        "count": len(results),
        "results": [
            {
                "frame_id": str(result.frame_id),
                "timestamp": result.timestamp.isoformat(),
                "inference_time_ms": result.inference_time_ms,
                "model_name": result.model_name,
                "device": result.device,
                "detections": [
                    {
                        "class_id": detection.class_id,
                        "class_name": detection.class_name,
                        "confidence": detection.confidence,
                        "bounding_box": {
                            "x1": detection.bounding_box.x1,
                            "y1": detection.bounding_box.y1,
                            "x2": detection.bounding_box.x2,
                            "y2": detection.bounding_box.y2,
                        },
                    }
                    for detection in result.detections
                ],
            }
            for result in results
        ],
    }
