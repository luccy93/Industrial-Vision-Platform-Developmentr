"""Detections resource — V01 stub. Inference/tracking land in V03+."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.auth.dependencies import require_read

router = APIRouter(prefix="/detections", tags=["detections"], dependencies=[require_read])


@router.get("")
def list_detections() -> dict:
    return {"items": [], "message": "Detection queries planned in V03 (AI inference)."}
