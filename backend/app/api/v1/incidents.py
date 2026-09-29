"""Incidents resource — V01 stub. Incident engine lands in later volumes."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_incidents() -> dict:
    return {"items": [], "message": "Incident engine planned in a later volume."}
