"""FastAPI application factory — V01 foundation.

Exposes:
  GET /health          lightweight liveness probe
  GET /ready           readiness probe (honest about V01 scope)
  GET /api/v1/health   versioned health with checks skeleton
  /api/v1/*            modular resource stubs for future volumes
"""

from __future__ import annotations

import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.v1.health import _base_payload, _checks
from backend.app.api.v1.router import v1_router
from backend.app.api.v1.streams_ws import router as streams_ws_router
from backend.app.core.config import Settings, get_settings
from backend.app.core.exceptions import register_exception_handlers
from backend.app.core.logging import configure_logging, get_logger

_started_at = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    logger = get_logger("industrial-vision")
    logger.info("startup service=%s env=%s", settings.app_name, settings.app_env.value)
    # Best-effort schema init (Alembic owns prod; never block startup).
    try:
        from backend.app.infrastructure.db import init_db

        init_db(settings.database_url)
    except Exception:
        logger.warning("database init skipped (unreachable?)", exc_info=True)
    yield
    for key in ("inference_supervisor", "supervisor"):
        try:
            supervisor = getattr(app.state, key, None)
            if supervisor is not None:
                supervisor.stop_all()
        except Exception:
            logger.debug("%s shutdown failed", key, exc_info=True)
    logger.info("shutdown service=%s", settings.app_name)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="Industrial AI Vision & Safety Intelligence Platform",
        version="0.1.0",
        description="V01 foundation: modular API skeleton, health, config, logging, errors.",
        lifespan=lifespan,
    )
    app.state.settings = settings
    from backend.app.api.v1.cameras import _app_supervisor
    from backend.app.infrastructure.db import get_session_factory

    app.state.session_factory = get_session_factory(settings.database_url)
    app.state.supervisor = _app_supervisor()
    from backend.app.inference.manager import ModelManager
    from backend.app.inference.worker import InferenceSupervisor

    app.state.model_manager = ModelManager.from_settings(settings)
    app.state.inference_supervisor = InferenceSupervisor()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.middleware("http")
    async def _request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        request.state.request_id = uuid.uuid4().hex[:12]
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        return response

    register_exception_handlers(app)
    app.include_router(v1_router)
    app.include_router(streams_ws_router)
    from backend.app.api.v1.inference import router as inference_router

    app.include_router(inference_router)

    @app.get("/health", tags=["health"])
    def health() -> dict:
        return _base_payload(settings)

    @app.get("/ready", tags=["health"])
    def ready() -> JSONResponse:
        # V01: API itself is ready; downstream systems report explicit not-checked
        # states rather than faked healthy states.
        payload = _base_payload(settings)
        payload["checks"] = _checks(settings)
        payload["ready"] = True
        return JSONResponse(content=payload)

    @app.get("/", tags=["health"])
    def root() -> dict:
        return {"service": settings.app_name, "version": "0.1.0", "docs": "/docs"}

    return app


app = create_app()
