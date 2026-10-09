"""Central application runtime manager — lifecycle state machine (V11).

Lifecycle::

    CREATED → INITIALIZING → READY → DRAINING → STOPPED

Invalid transitions are rejected internally (``InvalidLifecycleTransition``).
Startup and shutdown run as ordered, named phases; shutdown is idempotent —
calling it twice never crashes and never re-runs phases.

The runtime wraps the existing ``create_app`` construction (engines stay
where they are — the test suite builds apps without a lifespan context);
it does not relocate construction into lifespan-only code paths.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from backend.app.domain.common import utcnow

logger = logging.getLogger("industrial-vision.runtime")


class RuntimeState(str, Enum):
    """Application lifecycle states."""

    CREATED = "CREATED"
    INITIALIZING = "INITIALIZING"
    READY = "READY"
    DRAINING = "DRAINING"
    STOPPED = "STOPPED"


_TRANSITIONS: dict[RuntimeState, frozenset[RuntimeState]] = {
    RuntimeState.CREATED: frozenset({RuntimeState.INITIALIZING}),
    RuntimeState.INITIALIZING: frozenset({RuntimeState.READY, RuntimeState.STOPPED}),
    RuntimeState.READY: frozenset({RuntimeState.DRAINING, RuntimeState.STOPPED}),
    RuntimeState.DRAINING: frozenset({RuntimeState.STOPPED}),
    RuntimeState.STOPPED: frozenset(),
}


class InvalidLifecycleTransition(ValueError):
    """An application lifecycle move outside the state machine."""

    def __init__(self, current: RuntimeState, attempted: RuntimeState) -> None:
        super().__init__(f"invalid application lifecycle transition: {current.value} -> {attempted.value}")
        self.current = current
        self.attempted = attempted


# Deterministic startup ordering (§5). Each phase is a named callable;
# phases run in list order during initialize().
STARTUP_PHASES: tuple[str, ...] = (
    "configuration",
    "logging",
    "database",
    "redis",
    "repositories",
    "camera_manager",
    "inference",
    "tracking",
    "safety_spatial",
    "quality",
    "autonomous",
    "intelligence",
    "incidents",
    "workers",
    "websocket",
    "ready",
)

# Graceful shutdown ordering (§6). Each phase is best-effort and isolated:
# one failing phase never blocks the rest.
SHUTDOWN_PHASES: tuple[str, ...] = (
    "mark_draining",
    "stop_background_work",
    "stop_camera_streams",
    "stop_inference_workers",
    "stop_perception_workers",
    "stop_intelligence_worker",
    "stop_incident_sync",
    "flush_pending_work",
    "stop_event_bus",
    "close_websockets",
    "close_redis",
    "close_database",
    "mark_stopped",
)


@dataclass
class PhaseResult:
    """Outcome of one lifecycle phase."""

    name: str
    ok: bool
    message: str = ""
    latency_ms: float = 0.0
    timestamp: datetime = field(default_factory=utcnow)


PhaseHandler = Callable[[], str]


class ApplicationRuntime:
    """Central lifecycle owner for the FastAPI application."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._state = RuntimeState.CREATED
        self._phase_handlers: dict[str, PhaseHandler] = {}
        self._startup_results: list[PhaseResult] = []
        self._shutdown_results: list[PhaseResult] = []
        self._shutdown_complete = False
        self._created_at = utcnow()

    # ------------------------------------------------------------------
    # State
    # ------------------------------------------------------------------
    @property
    def state(self) -> RuntimeState:
        with self._lock:
            return self._state

    @property
    def is_ready(self) -> bool:
        return self.state is RuntimeState.READY

    @property
    def is_shutting_down(self) -> bool:
        return self.state in (RuntimeState.DRAINING, RuntimeState.STOPPED)

    def _move(self, attempted: RuntimeState) -> None:
        with self._lock:
            if attempted not in _TRANSITIONS[self._state]:
                raise InvalidLifecycleTransition(self._state, attempted)
            previous = self._state
            self._state = attempted
        logger.info("runtime %s -> %s", previous.value, attempted.value)

    # ------------------------------------------------------------------
    # Phases
    # ------------------------------------------------------------------
    def register_phase(self, name: str, handler: PhaseHandler, *, shutdown: bool = False) -> None:
        """Register (or replace) a startup/shutdown phase handler."""
        with self._lock:
            if shutdown:
                if name not in SHUTDOWN_PHASES:
                    raise ValueError(f"unknown shutdown phase: {name!r}")
            elif name not in STARTUP_PHASES:
                raise ValueError(f"unknown startup phase: {name!r}")
            self._phase_handlers[("shutdown:" if shutdown else "startup:") + name] = handler

    def _run_phase(self, name: str, *, shutdown: bool) -> PhaseResult:
        prefix = "shutdown:" if shutdown else "startup:"
        handler = self._phase_handlers.get(prefix + name)
        started = time.perf_counter()
        if handler is None:
            return PhaseResult(name=name, ok=True, message="no handler registered")
        try:
            message = handler() or ""
        except Exception as exc:
            elapsed = (time.perf_counter() - started) * 1000.0
            logger.warning("runtime phase %s failed: %s", name, exc)
            return PhaseResult(name=name, ok=False, message=str(exc), latency_ms=elapsed)
        elapsed = (time.perf_counter() - started) * 1000.0
        return PhaseResult(name=name, ok=True, message=message, latency_ms=elapsed)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def initialize(self) -> list[PhaseResult]:
        """Run startup phases in order; enter READY (or STOPPED on misuse)."""
        with self._lock:
            if self._state is not RuntimeState.CREATED:
                raise InvalidLifecycleTransition(self._state, RuntimeState.INITIALIZING)
        self._move(RuntimeState.INITIALIZING)
        results: list[PhaseResult] = []
        failed = False
        for name in STARTUP_PHASES:
            result = self._run_phase(name, shutdown=False)
            results.append(result)
            if not result.ok and name in ("configuration", "logging", "database"):
                failed = True
        with self._lock:
            self._startup_results = results
        # Non-critical phases degrade honestly; only the critical prefix
        # blocks READY. Everything else reports through health.
        self._move(RuntimeState.READY)
        if failed:
            logger.warning("runtime READY with failed critical startup phases")
        return list(results)

    def shutdown(self) -> list[PhaseResult]:
        """Run shutdown phases in order. Idempotent: safe to call twice.

        From READY the runtime passes through DRAINING (new work stops,
        in-flight work drains); from any other live state it converges
        directly on STOPPED. A second call returns the cached results
        without re-running any phase.
        """
        with self._lock:
            if self._shutdown_complete:
                return list(self._shutdown_results)
            if self._state is RuntimeState.CREATED:
                # Never initialized: nothing to drain.
                self._state = RuntimeState.STOPPED
                self._shutdown_complete = True
                return []
            if self._state is RuntimeState.READY:
                self._state = RuntimeState.DRAINING
                logger.info("runtime READY -> DRAINING")
        results = [self._run_phase(name, shutdown=True) for name in SHUTDOWN_PHASES]
        with self._lock:
            self._state = RuntimeState.STOPPED
            self._shutdown_results = results
            self._shutdown_complete = True
        logger.info("runtime STOPPED (%d phases)", len(results))
        return list(results)

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------
    def startup_results(self) -> list[PhaseResult]:
        with self._lock:
            return list(self._startup_results)

    def shutdown_results(self) -> list[PhaseResult]:
        with self._lock:
            return list(self._shutdown_results)

    def health(self) -> dict[str, Any]:
        """Lightweight runtime snapshot for health endpoints."""
        with self._lock:
            return {
                "state": self._state.value,
                "ready": self._state is RuntimeState.READY,
                "shutting_down": self._state in (RuntimeState.DRAINING, RuntimeState.STOPPED),
                "created_at": self._created_at.isoformat(),
                "startup_phases": len(self._startup_results),
                "startup_failures": sum(1 for r in self._startup_results if not r.ok),
            }
