"""V01 health endpoints — honest, non-faked service state."""

from __future__ import annotations

import socket
from typing import Any

from fastapi import APIRouter, Depends

from backend.app.api.deps import get_app_settings
from backend.app.core.config import Settings

router = APIRouter(tags=["health"])


def _checks(settings: Settings) -> dict[str, Any]:
    """Future volumes extend this with real PG/Redis/GPU/model/camera probes."""
    return {
        "api": {"status": "up"},
        "config": {"status": "ok", "app_env": settings.app_env.value},
        "database": {"status": "not_checked_in_v01", "configured": bool(settings.database_url)},
        "redis": {"status": "not_checked_in_v01", "configured": bool(settings.redis_url)},
        "gpu": {
            "status": "disabled" if not settings.gpu_enabled else "enabled",
            "device": settings.model_device,
        },
        "models": {"status": "not_loaded_in_v01"},
        "camera_streams": {"status": "not_connected_in_v01"},
    }


@router.get("/health")
def v1_health(settings: Settings = Depends(get_app_settings)) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": "v01",
        "env": settings.app_env.value,
        "checks": _checks(settings),
    }


def _base_payload(settings: Settings) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": "v01",
        "env": settings.app_env.value,
        "hostname": socket.gethostname(),
    }
