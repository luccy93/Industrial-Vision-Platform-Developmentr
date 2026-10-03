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
from typing import Any

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


def _load_spatial_configuration(app: FastAPI, logger: Any) -> None:
    """Warm the V06 zone runtime from stored configuration (best-effort).

    Zone configuration lives in PostgreSQL; the runtime holds a snapshot so the
    worker thread never touches the database. A database that is unreachable at
    startup must not block the API — spatial simply starts empty.
    """
    try:
        from backend.app.api.v1.spatial import sync_camera_zones
        from backend.app.ingestion.repository import CameraRepository
        from backend.app.spatial.engine import SpatialEngine
        from backend.app.spatial.repository import ZoneRepository

        spatial = getattr(app.state, "spatial_engine", None)
        factory = getattr(app.state, "session_factory", None)
        if not isinstance(spatial, SpatialEngine) or factory is None:
            return
        cameras = CameraRepository(factory).list()
        zones = ZoneRepository(factory)
        for camera in cameras:
            loaded = sync_camera_zones(spatial, zones, camera.camera_id)
            if loaded:
                logger.info("loaded %s zone(s) for camera %s", len(loaded), camera.camera_id)
    except Exception:
        logger.warning("zone configuration load skipped", exc_info=True)


def _load_quality_configuration(app: FastAPI, logger: Any) -> None:
    """Warm the V07 quality runtime from stored configuration (best-effort).

    Profile/region/category configuration lives in PostgreSQL; the runtime
    holds a snapshot so the worker thread never touches the database.
    """
    try:
        from backend.app.api.v1.quality import sync_camera_quality
        from backend.app.ingestion.repository import CameraRepository
        from backend.app.quality.engine import QualityInspectionEngine
        from backend.app.quality.repository import (
            DefectCategoryRepository,
            InspectionProfileRepository,
        )

        quality = getattr(app.state, "quality_engine", None)
        factory = getattr(app.state, "session_factory", None)
        if not isinstance(quality, QualityInspectionEngine) or factory is None:
            return
        cameras = CameraRepository(factory).list()
        profiles = InspectionProfileRepository(factory)
        categories = DefectCategoryRepository(factory)
        catalog = categories.list_all()
        for camera in cameras:
            loaded = sync_camera_quality(quality, profiles, categories, camera.camera_id, catalog)
            if loaded:
                logger.info("loaded %s inspection profile(s) for camera %s", len(loaded), camera.camera_id)
    except Exception:
        logger.warning("quality configuration load skipped", exc_info=True)


def _load_autonomous_configuration(app: FastAPI, logger: Any) -> None:
    """Warm the V08 perception runtime from stored profiles (best-effort).

    Perception profiles live in PostgreSQL; the runtime holds a snapshot so
    the worker thread never touches the database. An unreachable database
    must not block startup — perception simply starts on global defaults.
    """
    try:
        from backend.app.api.v1.autonomous import sync_camera_perception
        from backend.app.autonomous.engine import AutonomousPerceptionEngine
        from backend.app.autonomous.repository import AutonomousProfileRepository
        from backend.app.ingestion.repository import CameraRepository

        autonomous = getattr(app.state, "autonomous_engine", None)
        factory = getattr(app.state, "session_factory", None)
        if not isinstance(autonomous, AutonomousPerceptionEngine) or factory is None:
            return
        cameras = CameraRepository(factory).list()
        profiles = AutonomousProfileRepository(factory)
        for camera in cameras:
            loaded = sync_camera_perception(autonomous, profiles, camera.camera_id)
            if loaded:
                logger.info(
                    "loaded %s perception profile(s) for camera %s", len(loaded), camera.camera_id
                )
    except Exception:
        logger.warning("autonomous configuration load skipped", exc_info=True)


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
    _load_spatial_configuration(app, logger)
    _load_quality_configuration(app, logger)
    _load_autonomous_configuration(app, logger)
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
    from backend.app.tracking.manager import TrackingManager

    app.state.tracking_manager = TrackingManager(settings)
    from backend.app.safety.engine import SafetyEngine
    from backend.app.safety.rules import default_rules
    from backend.app.spatial.engine import SpatialEngine
    from backend.app.spatial.rules import spatial_rules

    # V06: one spatial runtime shared by the zone/proximity rules so they
    # participate in the V05 event lifecycle (dedup, grace, suppression).
    app.state.spatial_engine = SpatialEngine(settings)
    app.state.safety_engine = SafetyEngine(
        settings, default_rules(settings) + spatial_rules(app.state.spatial_engine)
    )

    # V07: quality inspection runtime (configuration snapshot + events +
    # sessions). The model resolves honestly from QUALITY_INSPECTION_MODEL.
    from backend.app.quality.engine import QualityInspectionEngine
    from backend.app.quality.registry import resolve_inspection_model

    app.state.quality_engine = QualityInspectionEngine(settings, resolve_inspection_model(settings))

    # V08: autonomous perception runtime (profile snapshots + relative scene
    # understanding). Model adapters resolve honestly from AUTONOMOUS_* names;
    # empty names degrade that subsystem to unavailable, never to fake output.
    from backend.app.autonomous.engine import AutonomousPerceptionEngine
    from backend.app.autonomous.registry import (
        resolve_depth_estimator,
        resolve_lane_detector,
        resolve_scene_classifier,
    )

    app.state.autonomous_engine = AutonomousPerceptionEngine(
        settings,
        scene_classifier=resolve_scene_classifier(settings),
        lane_detector=resolve_lane_detector(settings),
        depth_estimator=resolve_depth_estimator(settings),
    )

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
    from backend.app.api.v1.tracking import router as tracking_router

    app.include_router(tracking_router)
    from backend.app.api.v1.safety import router as safety_router

    app.include_router(safety_router)
    from backend.app.api.v1.spatial import router as spatial_router

    app.include_router(spatial_router)
    from backend.app.api.v1.quality import router as quality_router

    app.include_router(quality_router)
    from backend.app.api.v1.autonomous import router as autonomous_router

    app.include_router(autonomous_router)

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
