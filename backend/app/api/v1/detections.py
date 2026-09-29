"""Detections resource — V01 stub. Inference/tracking land in V03+."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/detections", tags=["detections"])


@router.get("")
def list_detections() -> dict:
    return {"items": [], "message": "Detection queries planned in V03 (AI inference)."}
