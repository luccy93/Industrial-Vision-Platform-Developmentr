"""Analytics resource — V01 stub. Aggregations land in later volumes."""

from __future__ import annotations

from fastapi import APIRouter

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/summary")
def analytics_summary() -> dict:
    return {"message": "Analytics planned in a later volume.", "summary": {}}
