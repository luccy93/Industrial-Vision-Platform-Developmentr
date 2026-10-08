"""V01 health endpoints — honest, non-faked service state."""

from __future__ import annotations

import socket
from typing import Any

from fastapi import APIRouter, Depends, Request

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


@router.get("/health", summary="Versioned health diagnostics")
def v1_health(request: Request, settings: Settings = Depends(get_app_settings)) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": "ok",
        "service": settings.app_name,
        "version": "v01",
        "env": settings.app_env.value,
        "checks": _checks(settings),
    }
    # Component diagnostics are additive: legacy `status`/`checks` shape
    # is preserved byte-for-byte for existing consumers.
    try:
        from backend.app.runtime.components import evaluate_components
        from backend.app.runtime.health import summarize

        components = evaluate_components(request.app.state, settings)
        payload["components"] = [c.model_dump(mode="json") for c in components]
        payload["summary"] = summarize(components).value
    except Exception:
        payload["components"] = []
        payload["summary"] = "UNKNOWN"
    return payload


def _base_payload(settings: Settings) -> dict[str, Any]:
    return {
        "status": "ok",
        "service": settings.app_name,
        "version": "v01",
        "env": settings.app_env.value,
        "hostname": socket.gethostname(),
    }
