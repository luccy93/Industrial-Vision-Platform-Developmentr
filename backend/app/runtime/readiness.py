"""Centralized readiness evaluation — fast, side-effect-free (V11).

``/ready`` answers one question: can this instance safely serve traffic?
The route handler stays thin; all policy lives here. Required checks are
the application runtime, the database (lightweight connectivity only), and
the critical workers. Optional subsystems may be DISABLED / NOT_CONFIGURED /
DEGRADED without failing readiness.

Not-ready is reported with HTTP 503, never 500. Invalid *configuration*
fails startup instead — readiness is for *runtime* state.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

from backend.app.runtime.health import HealthStatus
from backend.app.runtime.manager import ApplicationRuntime

# Check name → required-for-ready flag is supplied by the caller; these are
# the well-known check names the runtime wires in Commit 02.
REQUIRED_CHECKS: tuple[str, ...] = ("application", "database", "workers")


CheckHandler = Callable[[], tuple[HealthStatus, str]]


class ReadinessManager:
    """Evaluate readiness from registered lightweight checks."""

    def __init__(self, runtime: ApplicationRuntime | None = None) -> None:
        self._runtime = runtime
        self._checks: dict[str, CheckHandler] = {}
        self._required: set[str] = set(REQUIRED_CHECKS)

    def register_check(self, name: str, handler: CheckHandler, *, required: bool = True) -> None:
        """Register (or replace) a named readiness check."""
        self._checks[str(name)] = handler
        if required:
            self._required.add(str(name))
        else:
            self._required.discard(str(name))

    def set_required(self, names: list[str]) -> None:
        """Replace the explicit set of components required for readiness."""
        self._required = {str(n) for n in names}

    def evaluate(self) -> dict[str, Any]:
        """Run checks and return a readiness verdict (fast, no side effects)."""
        checks: dict[str, str] = {}
        failures: list[str] = []
        for name, handler in self._checks.items():
            started = time.perf_counter()
            try:
                status, _message = handler()
                value = status.value if isinstance(status, HealthStatus) else str(status)
            except Exception as exc:
                value = HealthStatus.FAILED.value
                failures.append(f"{name}: {exc}")
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if elapsed_ms > 1000.0:
                # A readiness check must never be expensive; flag it.
                value = HealthStatus.DEGRADED.value
            checks[name] = value
            if name in self._required and value not in (
                HealthStatus.READY.value,
                HealthStatus.DISABLED.value,
            ):
                failures.append(name)
        # The runtime itself is always required when present.
        if self._runtime is not None:
            checks["application"] = (
                HealthStatus.READY.value if self._runtime.is_ready else HealthStatus.NOT_READY.value
            )
            if not self._runtime.is_ready:
                failures.append("application")
        ready = not failures
        return {
            "ready": ready,
            "status": "ready" if ready else "not_ready",
            "checks": checks,
            "failing": sorted(set(failures)),
        }

    def is_ready(self) -> bool:
        """Boolean verdict (for middleware / guards)."""
        try:
            return bool(self.evaluate()["ready"])
        except Exception:
            return False


def database_check_factory(session_factory: Any) -> CheckHandler:
    """Build a lightweight DB connectivity check (acquire + SELECT 1)."""

    def _check() -> tuple[HealthStatus, str]:
        from sqlalchemy import text

        try:
            session = session_factory()
        except Exception as exc:
            return HealthStatus.NOT_READY, f"session acquisition failed: {exc}"
        try:
            session.execute(text("SELECT 1"))
            return HealthStatus.READY, "connectivity ok"
        except Exception as exc:
            return HealthStatus.NOT_READY, f"connectivity failed: {exc}"
        finally:
            try:
                session.close()
            except Exception:
                pass

    return _check


def mapping_checks(components: Mapping[str, HealthStatus]) -> dict[str, CheckHandler]:
    """Adapt a static component→status mapping into check handlers (tests)."""
    handlers: dict[str, CheckHandler] = {}
    for name, status in components.items():

        def _static(current: HealthStatus = status) -> tuple[HealthStatus, str]:
            return current, current.value

        handlers[str(name)] = _static
    return handlers
