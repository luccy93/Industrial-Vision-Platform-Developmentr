"""FastAPI application factory — V01 foundation.

Exposes:
  GET /health          lightweight liveness probe
  GET /ready           readiness probe (honest about V01 scope)
  GET /api/v1/health   versioned health with checks skeleton
  /api/v1/*            modular resource stubs for future volumes
"""

from __future__ import annotations

import time
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


def _register_runtime_phases(app: FastAPI, settings: Settings) -> None:
    """Report create_app construction as runtime startup phases (§5).

    Reporters are cheap and side-effect-free: construction already
    happened inline above; the runtime records and orders it. Live probes
    (SELECT 1, worker states) stay in readiness/health, not here.
    """
    from backend.app.runtime.manager import STARTUP_PHASES

    runtime = app.state.runtime
    state = app.state

    def _reporters() -> dict[str, str]:
        notes: dict[str, str] = {}
        try:
            notes["configuration"] = "; ".join(settings.validate_startup())
        except Exception as exc:
            notes["configuration"] = f"invalid: {exc}"
            raise
        notes["logging"] = f"level={settings.log_level}"
        notes["database"] = "session factory ready (live probe in readiness)"
        redis_manager = getattr(state, "redis_manager", None)
        if redis_manager is None or not bool(getattr(redis_manager, "enabled", False)):
            notes["redis"] = "disabled (local mode)"
        elif bool(getattr(redis_manager, "connected", False)):
            notes["redis"] = "connected"
        else:
            notes["redis"] = "enabled but unreachable (degraded unless required)"
        notes["repositories"] = "schema warm-up deferred to lifespan"
        notes["camera_manager"] = "stream supervisor constructed"
        notes["inference"] = "model manager + inference supervisor constructed"
        notes["tracking"] = "tracking manager constructed"
        notes["safety_spatial"] = "safety + spatial engines constructed"
        notes["quality"] = "quality engine constructed"
        notes["autonomous"] = "autonomous engine constructed"
        notes["intelligence"] = "intelligence engine constructed"
        notes["incidents"] = "incident manager constructed"
        notes["workers"] = "worker supervision registry ready"
        notes["websocket"] = "socket route mounted; manager registered"
        notes["ready"] = "application READY"
        return notes

    reports = _reporters()
    for phase in STARTUP_PHASES:
        runtime.register_phase(phase, lambda p=phase: reports.get(p, "ok"))

    # Shutdown phases (§6): best-effort, isolated, idempotent.
    def _stop_all(supervisor: Any, label: str) -> str:
        try:
            supervisor.stop_all()
        except Exception as exc:
            return f"{label}: stop failed ({type(exc).__name__})"
        return f"{label}: stopped"

    runtime.register_phase(
        "mark_draining", lambda: "draining: new background work refused", shutdown=True
    )
    runtime.register_phase(
        "stop_background_work", lambda: "no standalone background pool", shutdown=True
    )
    runtime.register_phase(
        "stop_camera_streams",
        lambda: _stop_all(state.supervisor, "stream supervisor"),
        shutdown=True,
    )
    runtime.register_phase(
        "stop_inference_workers",
        lambda: _stop_all(state.inference_supervisor, "inference supervisor"),
        shutdown=True,
    )
    def _stop_event_bus() -> str:
        # Consumers stop before the resources they need (§6): publisher +
        # subscriber first, Redis client after (close_redis phase).
        stopped: list[str] = []
        for key in ("outbox_publisher", "redis_subscriber"):
            worker = getattr(state, key, None)
            if worker is None:
                continue
            try:
                worker.stop(timeout=5.0)
                stopped.append(key)
            except Exception as exc:
                return f"event bus stop failed ({type(exc).__name__})"
        return f"event bus stopped ({','.join(stopped) or 'nothing running'})"

    def _close_redis() -> str:
        manager = getattr(state, "redis_manager", None)
        if manager is None:
            return "no redis manager"
        try:
            manager.close()
            return "redis client closed"
        except Exception as exc:
            return f"redis close skipped ({type(exc).__name__})"

    for _phase, _message in (
        ("stop_perception_workers", "perception runs inline on inference workers"),
        ("stop_intelligence_worker", "intelligence runs inline on inference workers"),
        ("stop_incident_sync", "incident sync is an inference worker stage"),
        ("flush_pending_work", "no unbounded pending queues"),
        ("close_websockets", "websocket drain managed by lifespan (bounded)"),
    ):
        runtime.register_phase(_phase, lambda m=_message: m, shutdown=True)
    runtime.register_phase("stop_event_bus", _stop_event_bus, shutdown=True)
    runtime.register_phase("close_redis", _close_redis, shutdown=True)
    runtime.register_phase(
        "close_database", lambda: _dispose_engine(state), shutdown=True
    )
    runtime.register_phase("mark_stopped", lambda: "runtime STOPPED", shutdown=True)


def _redis_readiness(app: FastAPI) -> tuple[Any, str]:
    """Redis readiness: required → real ping; optional → honest state."""
    from backend.app.runtime.health import HealthStatus

    manager = getattr(app.state, "redis_manager", None)
    if manager is None or not bool(getattr(manager, "enabled", False)):
        return HealthStatus.DISABLED, "redis disabled (local mode)"
    try:
        reachable = bool(manager.ping())
    except Exception:
        return HealthStatus.NOT_READY, "redis probe failed"
    if reachable:
        return HealthStatus.READY, "redis reachable"
    return HealthStatus.NOT_READY, "redis unreachable"


def _dispose_engine(state: Any) -> str:
    """Best-effort engine dispose (pooled connections released)."""
    from backend.app.infrastructure.db import dispose_engine

    try:
        if dispose_engine(state.session_factory):
            return "engine disposed"
        return "no engine to dispose"
    except Exception as exc:
        return f"dispose skipped ({type(exc).__name__})"

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    runtime = app.state.runtime
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
    # V12: start durable-distribution threads (lifespan only, so tests that
    # build apps without a lifespan context never leak threads). The
    # publisher drains in both modes; the subscriber only exists when
    # distributed delivery is configured.
    publisher = getattr(app.state, "outbox_publisher", None)
    if publisher is not None:
        try:
            publisher.start()
        except Exception:
            logger.warning("outbox publisher start failed", exc_info=True)
    subscriber = getattr(app.state, "redis_subscriber", None)
    if subscriber is not None:
        try:
            subscriber.start()
        except Exception:
            logger.warning("redis subscriber start failed", exc_info=True)
    yield
    # Graceful shutdown (§6, §31): refuse new sockets, drain with a bound,
    # then run the ordered idempotent runtime shutdown.
    ws_manager = getattr(app.state, "ws_manager", None)
    if ws_manager is not None:
        try:
            report = await ws_manager.shutdown("server shutdown")
            logger.info("websockets drained: %s", report)
        except Exception:
            logger.warning("websocket drain failed", exc_info=True)
    try:
        runtime.shutdown()
    except Exception:
        logger.warning("runtime shutdown failed", exc_info=True)
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

    # V09: event & risk intelligence orchestration over the V05/V06 safety,
    # V07 quality, and V08 autonomous engines. Reads their event outputs;
    # owns no detectors, trackers, or models.
    from backend.app.intelligence.engine import IntelligenceEngine

    app.state.intelligence_engine = IntelligenceEngine(
        settings,
        safety_engine=app.state.safety_engine,
        quality_engine=app.state.quality_engine,
        autonomous_engine=app.state.autonomous_engine,
    )

    # V10: incident operations over V09 intelligence. Owns PostgreSQL-backed
    # operational records; reads V09 public contracts, never private state.
    from backend.app.incidents.manager import IncidentManager

    app.state.incident_manager = IncidentManager(
        settings,
        app.state.session_factory,
        intelligence_engine=app.state.intelligence_engine,
    )

    # V11: central lifecycle owner. Construction stays here (the test suite
    # builds apps without a lifespan context); the lifespan and endpoints
    # drive its phases. Starts in CREATED; initialized below.
    from backend.app.runtime.manager import ApplicationRuntime

    app.state.runtime = ApplicationRuntime()

    # V11: WebSocket lifecycle boundary + worker supervision registry.
    # Both are additive: the streams_ws loop and worker threads keep
    # their current behavior; these objects observe and bound it.
    from backend.app.websocket.manager import WebSocketManager
    from backend.app.workers.base import WorkerSupervisor

    app.state.ws_manager = WebSocketManager(
        queue_max_size=settings.websocket_queue_max_size,
        heartbeat_timeout_seconds=settings.websocket_heartbeat_timeout_seconds,
        shutdown_timeout_seconds=settings.websocket_shutdown_timeout_seconds,
    )
    app.state.worker_supervisor = WorkerSupervisor(
        heartbeat_timeout_seconds=settings.worker_heartbeat_timeout_seconds
    )

    # V11: centralized readiness (route handlers stay thin).
    from backend.app.runtime.health import HealthStatus
    from backend.app.runtime.readiness import ReadinessManager, database_check_factory

    readiness = ReadinessManager(app.state.runtime)
    readiness.register_check(
        "database", lambda: database_check_factory(app.state.session_factory)()
    )

    def _workers_check() -> tuple[HealthStatus, str]:
        # Only FAILED supervision fails readiness; DEGRADED/stale optional
        # workers keep the platform servable (§10, §23).
        try:
            snapshots: dict[str, Any] = {}
            snapshots.update(app.state.inference_supervisor.health_snapshots())
            snapshots.update(app.state.supervisor.health_snapshots())
        except Exception as exc:
            return HealthStatus.UNKNOWN, f"supervisors unreachable: {type(exc).__name__}"
        failed = [k for k, v in snapshots.items() if v.get("state") == "FAILED"]
        if failed:
            return HealthStatus.NOT_READY, f"failed workers: {','.join(sorted(failed)[:5])}"
        return (
            HealthStatus.READY,
            f"{len(snapshots)} worker(s) supervised",
        )

    readiness.register_check("workers", _workers_check)
    app.state.readiness = readiness

    # V12: durable distribution layer (local mode by default).
    from backend.app.events.bus import EventBus
    from backend.app.events.publisher import OutboxPublisher, RedisEventSubscriber
    from backend.app.events.store import OperationalEventRepository, OutboxRepository
    from backend.app.infrastructure.redis_client import RedisLifecycleManager

    operational_repository = OperationalEventRepository(app.state.session_factory)
    outbox_repository = OutboxRepository(app.state.session_factory)
    redis_manager = RedisLifecycleManager(
        enabled=settings.redis_enabled,
        required=settings.redis_required,
        url=settings.redis_url,
        connect_timeout_seconds=settings.redis_connect_timeout_seconds,
        socket_timeout_seconds=settings.redis_socket_timeout_seconds,
    )
    # Required Redis unreachable fails startup here (fail fast); optional
    # Redis degrades honestly inside start().
    redis_manager.start()
    app.state.redis_manager = redis_manager
    event_bus = EventBus(
        mode=settings.event_bus_mode,
        channel=settings.event_bus_channel,
        max_payload_bytes=settings.event_max_payload_bytes,
        redis_manager=redis_manager if settings.is_distributed else None,
    )
    event_bus.start()
    app.state.event_bus = event_bus
    outbox_publisher = OutboxPublisher(
        outbox=outbox_repository,
        bus=event_bus,
        batch_size=settings.outbox_batch_size,
        max_attempts=settings.outbox_max_attempts,
        retry_base_seconds=settings.outbox_retry_base_seconds,
    )
    app.state.outbox_publisher = outbox_publisher
    redis_subscriber: RedisEventSubscriber | None = None
    if settings.is_distributed:
        redis_subscriber = RedisEventSubscriber(
            redis_manager=redis_manager, bus=event_bus, channel=settings.event_bus_channel
        )
    app.state.redis_subscriber = redis_subscriber
    app.state.incident_manager.configure_distribution(
        event_bus=event_bus,
        operational_repository=operational_repository,
        outbox_repository=outbox_repository,
    )

    # Cross-process incident changes ingest idempotently into the WS
    # feed (own-bus echoes skipped; no hot-loop changes).
    from backend.app.events.wiring import register_remote_incident_ingest

    register_remote_incident_ingest(event_bus, app.state.incident_manager)
    app.state.readiness.register_check(
        "redis", lambda: _redis_readiness(app), required=settings.redis_required
    )

    _register_runtime_phases(app, settings)
    app.state.runtime.initialize()

    app.add_middleware(
        CORSMiddleware,
        allow_origins=list(settings.cors_allowed_origins),
        allow_credentials=bool(settings.cors_allow_credentials),
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID"],
    )

    @app.middleware("http")
    async def _body_limit(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Bounded JSON payloads (§38). Content-Length is checked before any
        # domain service sees the body; chunked bodies without a length fall
        # through to the per-field Field(max_length=...) validators.
        # The 413 is returned directly: exceptions raised in middleware
        # bypass the route exception handlers.
        from fastapi.responses import JSONResponse

        from backend.app.core.exceptions import error_envelope
        from backend.app.core.request_context import (
            REQUEST_ID_HEADER as _RID_HEADER,
        )
        from backend.app.core.request_context import sanitize_request_id as _sanitize

        limit = int(settings.max_request_body_bytes)
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                size = int(content_length)
            except ValueError:
                size = 0
            if size > limit:
                request_id = _sanitize(request.headers.get(_RID_HEADER))
                return JSONResponse(
                    status_code=413,
                    content=error_envelope(
                        "PAYLOAD_TOO_LARGE",
                        f"request body too large ({size} bytes > {limit} bytes)",
                        request_id,
                    ),
                    headers={_RID_HEADER: request_id},
                )
        return await call_next(request)

    @app.middleware("http")
    async def _request_id(request: Request, call_next):  # type: ignore[no-untyped-def]
        from backend.app.core.request_context import (
            REQUEST_ID_HEADER,
            RequestContext,
            reset_request_context,
            sanitize_request_id,
            set_request_context,
        )

        request_id = sanitize_request_id(request.headers.get(REQUEST_ID_HEADER))
        request.state.request_id = request_id
        request.state.started_monotonic = time.monotonic()
        token = set_request_context(
            RequestContext(
                request_id=request_id, method=request.method, path=request.url.path
            )
        )
        try:
            response = await call_next(request)
        except BaseException:
            reset_request_context(token)
            raise
        reset_request_context(token)
        response.headers[REQUEST_ID_HEADER] = request_id
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
    from backend.app.api.v1.intelligence import router as intelligence_router

    app.include_router(intelligence_router)
    from backend.app.api.v1.incidents import router as incidents_router

    app.include_router(incidents_router)

    @app.get("/health", tags=["health"], summary="Service health diagnostics")
    def health() -> dict:
        payload = _base_payload(settings)
        try:
            payload["runtime"] = app.state.runtime.health()
        except Exception:
            payload["runtime"] = {"state": "UNKNOWN", "ready": False}
        return payload

    @app.get("/live", tags=["health"], summary="Liveness probe")
    def live() -> dict:
        # Liveness only: the process is running. Never expensive.
        payload = _base_payload(settings)
        try:
            payload["runtime_state"] = app.state.runtime.state.value
        except Exception:
            payload["runtime_state"] = "UNKNOWN"
        return payload

    @app.get("/ready", tags=["health"], summary="Readiness probe")
    def ready() -> JSONResponse:
        # Legacy shape preserved (status/checks/ready); the real verdict
        # comes from the centralized ReadinessManager (additive).
        payload = _base_payload(settings)
        payload["checks"] = _checks(settings)
        try:
            verdict = app.state.readiness.evaluate()
        except Exception:
            verdict = {"ready": False, "status": "not_ready", "checks": {}, "failing": ["readiness"]}
        payload["ready"] = bool(verdict["ready"])
        payload["readiness"] = verdict
        return JSONResponse(
            status_code=200 if verdict["ready"] else 503, content=payload
        )

    @app.get("/", tags=["health"], summary="Service root")
    def root() -> dict:
        return {"service": settings.app_name, "version": "0.1.0", "docs": "/docs"}

    return app


app = create_app()
