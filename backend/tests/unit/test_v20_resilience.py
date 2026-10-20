"""V20 resilience — engine disposal and lifespan teardown guarantees."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from backend.app.core.config import Settings
from backend.app.infrastructure import db as dbmod
from backend.app.main import create_app, lifespan


def test_dispose_engine_clears_factory_cache(tmp_path) -> None:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/dispose.db"
    factory = dbmod.get_session_factory(url)
    assert dbmod._session_factory.cache_info().currsize >= 1

    assert dbmod.dispose_engine(factory) is True
    # The disposed engine is never handed back out: the cache is cleared.
    assert dbmod._session_factory.cache_info().currsize == 0

    rebuilt = dbmod.get_session_factory(url)
    assert rebuilt is not factory


def test_dispose_engine_is_idempotent(tmp_path) -> None:  # type: ignore[no-untyped-def]
    factory = dbmod.get_session_factory(f"sqlite:///{tmp_path}/idem.db")
    assert dbmod.dispose_engine(factory) is True
    assert dbmod.dispose_engine(factory) is True


def test_lifespan_tears_down_after_partial_startup_failure(
    test_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A startup failure still runs the ordered shutdown (no orphan threads)."""
    app = create_app(test_settings)
    assert app.state.runtime.state.value == "READY"

    def _boom(_app: Any, _logger: Any) -> None:
        raise RuntimeError("spatial configuration exploded")

    monkeypatch.setattr("backend.app.main._load_spatial_configuration", _boom)

    async def drive() -> None:
        with pytest.raises(RuntimeError):
            async with lifespan(app):
                pass  # pragma: no cover - startup fails before the body

    asyncio.run(drive())
    # The finally block ran the runtime shutdown despite the failed startup.
    assert app.state.runtime.state.value == "STOPPED"
