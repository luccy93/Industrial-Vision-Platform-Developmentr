"""Readiness manager tests — fast verdicts, required vs optional."""

from __future__ import annotations

from backend.app.runtime.health import HealthStatus
from backend.app.runtime.manager import ApplicationRuntime
from backend.app.runtime.readiness import ReadinessManager, mapping_checks


def _ready_manager() -> ReadinessManager:
    runtime = ApplicationRuntime()
    runtime.initialize()
    manager = ReadinessManager(runtime)
    manager.register_check("database", lambda: (HealthStatus.READY, "ok"))
    manager.register_check("workers", lambda: (HealthStatus.READY, "ok"))
    return manager


def test_all_ready_state() -> None:
    verdict = _ready_manager().evaluate()
    assert verdict["ready"] is True
    assert verdict["status"] == "ready"
    assert verdict["checks"]["application"] == "READY"
    assert verdict["failing"] == []


def test_critical_dependency_failure() -> None:
    manager = _ready_manager()
    manager.register_check("database", lambda: (HealthStatus.NOT_READY, "down"))
    verdict = manager.evaluate()
    assert verdict["ready"] is False
    assert verdict["status"] == "not_ready"
    assert "database" in verdict["failing"]


def test_optional_subsystem_does_not_fail_readiness() -> None:
    manager = _ready_manager()
    manager.register_check("depth", lambda: (HealthStatus.DISABLED, "not configured"), required=False)
    verdict = manager.evaluate()
    assert verdict["ready"] is True
    assert verdict["checks"]["depth"] == "DISABLED"


def test_optional_degraded_does_not_fail_readiness() -> None:
    manager = _ready_manager()
    manager.register_check("quality", lambda: (HealthStatus.DEGRADED, "slow"), required=False)
    assert manager.evaluate()["ready"] is True


def test_required_degraded_fails_readiness() -> None:
    manager = _ready_manager()
    manager.register_check("workers", lambda: (HealthStatus.DEGRADED, "stale"))
    assert manager.evaluate()["ready"] is False


def test_check_exception_maps_to_failed() -> None:
    manager = _ready_manager()

    def _boom() -> tuple[HealthStatus, str]:
        raise RuntimeError("probe exploded")

    manager.register_check("database", _boom)
    verdict = manager.evaluate()
    assert verdict["ready"] is False
    assert verdict["checks"]["database"] == "FAILED"


def test_malformed_component_state() -> None:
    manager = ReadinessManager()
    for name, handler in mapping_checks({"database": HealthStatus.NOT_READY}).items():
        manager.register_check(name, handler)
    verdict = manager.evaluate()
    assert verdict["ready"] is False


def test_runtime_not_ready_blocks() -> None:
    runtime = ApplicationRuntime()  # never initialized
    manager = ReadinessManager(runtime)
    verdict = manager.evaluate()
    assert verdict["ready"] is False
    assert verdict["checks"]["application"] == "NOT_READY"


def test_empty_manager_is_vacuously_ready() -> None:
    manager = ReadinessManager()
    assert manager.is_ready() is True


def test_custom_required_set() -> None:
    manager = _ready_manager()
    manager.set_required(["application"])
    manager.register_check("database", lambda: (HealthStatus.FAILED, "x"), required=False)
    assert manager.evaluate()["ready"] is True
