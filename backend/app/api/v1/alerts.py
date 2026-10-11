"""Alerts resource — V01 stub. Alert delivery lands in later volumes."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.auth.dependencies import require_read

router = APIRouter(prefix="/alerts", tags=["alerts"], dependencies=[require_read])


@router.get("")
def list_alerts() -> dict:
    return {"items": [], "message": "Alert delivery planned in a later volume."}
