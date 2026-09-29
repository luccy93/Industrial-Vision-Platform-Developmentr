"""Assemble the versioned /api/v1 router."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1 import alerts, analytics, cameras, detections, health, incidents

v1_router = APIRouter(prefix="/api/v1")
v1_router.include_router(health.router)
v1_router.include_router(cameras.router)
v1_router.include_router(detections.router)
v1_router.include_router(incidents.router)
v1_router.include_router(alerts.router)
v1_router.include_router(analytics.router)
