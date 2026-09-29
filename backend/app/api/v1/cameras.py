"""Cameras resource — V01 stub. Full CRUD/streaming lands in V02+."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/cameras", tags=["cameras"])


@router.get("")
def list_cameras() -> dict:
    return {"items": [], "message": "Camera management planned in V02 (video ingestion)."}


@router.get("/{camera_id}")
def get_camera(camera_id: str) -> dict:
    return {"camera_id": camera_id, "message": "Camera detail planned in V02."}
