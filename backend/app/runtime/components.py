"""Lightweight component health checks — no I/O beyond SELECT 1 (V11, §9).

Every check is cheap, exception-isolated (a failing probe yields UNKNOWN,
never a 500), and secret-free (no URLs, credentials, or model paths).
No inference runs; no camera connections are opened.
"""

from __future__ import annotations

import time
from typing import Any

from backend.app.runtime.health import ComponentHealth, HealthStatus, component_health


def _timed(name: str, probe: Any) -> ComponentHealth:
    started = time.perf_counter()
    try:
        status, message, metadata = probe()
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        return component_health(
            name,
            HealthStatus.UNKNOWN,
            message=f"probe failed: {type(exc).__name__}",
            latency_ms=elapsed,
        )
    elapsed = (time.perf_counter() - started) * 1000.0
    if not isinstance(status, HealthStatus):
        status = HealthStatus.UNKNOWN
    return component_health(
        name, status, message=str(message or ""), latency_ms=elapsed, metadata=dict(metadata or {})
    )


def _presence(state: Any, attr: str) -> Any | None:
    return getattr(state, attr, None)


def evaluate_components(state: Any, settings: Any) -> list[ComponentHealth]:
    """Evaluate the 12 health components against live app state."""
    results: list[ComponentHealth] = []

    def _application() -> tuple[HealthStatus, str, dict[str, Any]]:
        runtime = _presence(state, "runtime")
        if runtime is None:
            return HealthStatus.UNKNOWN, "no runtime registered", {}
        current = runtime.state.value if hasattr(runtime, "state") else "?"
        if getattr(runtime, "is_ready", False):
            return HealthStatus.READY, f"state={current}", {}
        return HealthStatus.NOT_READY, f"state={current}", {}

    results.append(_timed("application", _application))

    def _database() -> tuple[HealthStatus, str, dict[str, Any]]:
        from sqlalchemy import text

        factory = _presence(state, "session_factory")
        if factory is None:
            return HealthStatus.UNKNOWN, "no session factory", {}
        session = factory()
        try:
            session.execute(text("SELECT 1"))
            return HealthStatus.READY, "connectivity ok", {}
        except Exception as exc:
            return HealthStatus.NOT_READY, f"unreachable: {type(exc).__name__}", {}
        finally:
            try:
                session.close()
            except Exception:
                pass

    results.append(_timed("database", _database))

    def _redis() -> tuple[HealthStatus, str, dict[str, Any]]:
        manager = _presence(state, "redis_manager")
        if manager is None:
            return HealthStatus.DISABLED, "redis not configured (local mode)", {"required": False}
        try:
            status = manager.status()
        except Exception:
            return HealthStatus.UNKNOWN, "redis status unavailable", {}
        metadata = {"required": bool(status.required), "connected": bool(status.connected)}
        if not bool(status.enabled):
            return HealthStatus.DISABLED, "redis disabled (local mode)", metadata
        if bool(status.connected):
            return HealthStatus.READY, "redis reachable", metadata
        # Enabled but unreachable: required → NOT_READY (gates readiness),
        # optional → DEGRADED (honest, platform stays servable).
        if bool(status.required):
            return HealthStatus.NOT_READY, "required redis unreachable", metadata
        return HealthStatus.DEGRADED, "optional redis unreachable", metadata

    results.append(_timed("redis", _redis))

    def _eventbus() -> tuple[HealthStatus, str, dict[str, Any]]:
        bus = _presence(state, "event_bus")
        if bus is None:
            return HealthStatus.DISABLED, "event bus not configured", {}
        try:
            stats = bus.stats()
        except Exception:
            return HealthStatus.UNKNOWN, "event bus status unavailable", {}
        mode = str(stats.get("mode", "local"))
        metadata = {
            "mode": mode,
            "subscriptions": int(stats.get("subscriptions", 0)),
            "delivered": int(stats.get("delivered", 0)),
            "dropped_duplicates": int(stats.get("dropped_duplicates", 0)),
        }
        return HealthStatus.READY, f"event bus running ({mode})", metadata

    results.append(_timed("eventbus", _eventbus))

    def _camera_manager() -> tuple[HealthStatus, str, dict[str, Any]]:
        supervisor = _presence(state, "supervisor")
        if supervisor is None:
            return HealthStatus.UNKNOWN, "no stream supervisor", {}
        try:
            count = len(supervisor.statuses())
        except Exception:
            count = -1
        return HealthStatus.READY, f"{count} stream(s) registered", {"streams": count}

    results.append(_timed("camera_manager", _camera_manager))

    def _inference() -> tuple[HealthStatus, str, dict[str, Any]]:
        supervisor = _presence(state, "inference_supervisor")
        manager = _presence(state, "model_manager")
        if supervisor is None:
            return HealthStatus.UNKNOWN, "no inference supervisor", {}
        try:
            workers = supervisor.worker_count()
        except Exception:
            workers = -1
        ready = False
        try:
            ready = bool(manager.status().get("ready", False)) if manager else False
        except Exception:
            ready = False
        if ready:
            return HealthStatus.READY, f"model ready, {workers} worker(s)", {"workers": workers}
        return HealthStatus.NOT_READY, f"model not loaded, {workers} worker(s)", {"workers": workers}

    results.append(_timed("inference", _inference))

    def _tracking() -> tuple[HealthStatus, str, dict[str, Any]]:
        manager = _presence(state, "tracking_manager")
        if manager is None:
            return HealthStatus.UNKNOWN, "no tracking manager", {}
        return HealthStatus.READY, "tracker registry available", {}

    results.append(_timed("tracking", _tracking))

    for attr, label in (
        ("safety_engine", "safety"),
        ("spatial_engine", "spatial"),
        ("quality_engine", "quality"),
        ("autonomous_engine", "autonomous"),
        ("intelligence_engine", "intelligence"),
    ):

        def _engine(attribute: str = attr, name: str = label) -> tuple[HealthStatus, str, dict[str, Any]]:
            engine = _presence(state, attribute)
            if engine is None:
                return HealthStatus.UNKNOWN, f"no {name} engine", {}
            if not bool(getattr(engine, "enabled", True)):
                return HealthStatus.DISABLED, f"{name} disabled by configuration", {}
            return HealthStatus.READY, f"{name} engine available", {}

        results.append(_timed(label, _engine))

    def _incidents() -> tuple[HealthStatus, str, dict[str, Any]]:
        manager = _presence(state, "incident_manager")
        if manager is None:
            return HealthStatus.DISABLED, "incident manager not registered", {}
        if not bool(getattr(manager, "enabled", True)):
            return HealthStatus.DISABLED, "incidents disabled by configuration", {}
        return HealthStatus.READY, "incident manager available", {}

    results.append(_timed("incidents", _incidents))

    def _websocket() -> tuple[HealthStatus, str, dict[str, Any]]:
        if not bool(getattr(settings, "websocket_enabled", True)):
            return HealthStatus.DISABLED, "websocket disabled by configuration", {}
        manager = _presence(state, "ws_manager")
        active = -1
        if manager is not None:
            try:
                active = int(manager.metrics().get("active_connections", -1))
            except Exception:
                active = -1
        return HealthStatus.READY, "socket route mounted", {"active_connections": active}

    results.append(_timed("websocket", _websocket))

    def _workers() -> tuple[HealthStatus, str, dict[str, Any]]:
        supervisor = _presence(state, "worker_supervisor")
        inference_supervisor = _presence(state, "inference_supervisor")
        stream_supervisor = _presence(state, "supervisor")
        snapshots: dict[str, dict[str, Any]] = {}
        sources: list[tuple[Any, str]] = [
            (inference_supervisor, "inference"),
            (stream_supervisor, "stream"),
        ]
        for source, key in sources:
            if source is None:
                continue
            try:
                for camera_id, snap in source.health_snapshots().items():
                    snapshots[f"{key}:{camera_id}"] = dict(snap)
            except Exception:
                continue
        timeout = float(getattr(settings, "worker_heartbeat_timeout_seconds", 30.0) or 30.0)
        stale: list[str] = []
        failed: list[str] = []
        degraded: list[str] = []
        for name, snap in snapshots.items():
            worker_state = str(snap.get("state", "UNKNOWN"))
            if worker_state == "FAILED":
                failed.append(name)
                continue
            if worker_state in ("ERROR",):
                degraded.append(name)
                continue
            if snap.get("running") and not snap.get("last_heartbeat"):
                stale.append(name)
                continue
            if snap.get("running") and snap.get("last_error"):
                degraded.append(name)
        metadata: dict[str, Any] = {
            "inference_workers": sum(1 for n in snapshots if n.startswith("inference:")),
            "stream_workers": sum(1 for n in snapshots if n.startswith("stream:")),
            "heartbeat_timeout_seconds": timeout,
        }
        if failed:
            return HealthStatus.FAILED, f"failed: {','.join(failed[:5])}", metadata
        if stale:
            return HealthStatus.DEGRADED, f"stale: {','.join(stale[:5])}", metadata
        if degraded:
            return HealthStatus.DEGRADED, f"degraded: {','.join(degraded[:5])}", metadata
        if supervisor is not None:
            try:
                managed_stale = supervisor.stale_workers(timeout)
                managed_failed = [n for n, s in supervisor.snapshots().items() if s.state.value == "FAILED"]
            except Exception:
                managed_stale, managed_failed = [], []
            if managed_failed:
                return HealthStatus.FAILED, f"failed: {','.join(managed_failed[:5])}", metadata
            if managed_stale:
                return HealthStatus.DEGRADED, f"stale: {','.join(managed_stale[:5])}", metadata
        return HealthStatus.READY, "supervision nominal", metadata

    results.append(_timed("workers", _workers))

    return results
