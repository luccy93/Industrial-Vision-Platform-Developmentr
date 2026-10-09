"""Database engine + session helpers (V02: cameras persistence).

PostgreSQL in production (``DATABASE_URL``); SQLite works for local dev and
Alembic offline validation. Sessions are request-scoped via ``get_db``.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache
from typing import Any

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import get_settings
from backend.app.models import (
    autonomous_orm,  # noqa: F401 (registers the autonomous profiles table)
    incident_orm,  # noqa: F401 (registers the incident tables)
    operational_orm,  # noqa: F401 (registers operational history + outbox)
    quality_orm,  # noqa: F401 (registers the quality tables)
    zone_orm,  # noqa: F401 (registers the zones table)
)
from backend.app.models.camera_orm import Base


@lru_cache(maxsize=8)
def _session_factory(
    database_url: str,
    pool_size: int = 5,
    max_overflow: int = 10,
    pool_timeout: float = 30.0,
    pool_recycle: float = 1800.0,
    connect_timeout: float = 10.0,
) -> sessionmaker[Session]:
    if database_url.startswith("sqlite"):
        # Local dev/test path: unchanged behavior (no pooling knobs).
        connect_args: dict[str, object] = {"check_same_thread": False}
        engine = create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)
    else:
        engine = create_engine(
            database_url,
            pool_size=pool_size,
            max_overflow=max_overflow,
            pool_timeout=pool_timeout,
            pool_recycle=pool_recycle,
            pool_pre_ping=True,
            connect_args={"connect_timeout": int(connect_timeout)},
        )
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session_factory(
    database_url: str | None = None, settings: Any | None = None
) -> sessionmaker[Session]:
    """Resolve a cached factory; pool knobs come from settings (V12).

    SQLite URLs ignore pool settings (identical behavior to V01–V11).
    The cache key includes pool values, so distinct configurations never
    share an engine.
    """
    from backend.app.core.config import Settings

    url = database_url or get_settings().database_url
    if url.startswith("sqlite"):
        return _session_factory(url)
    cfg = settings if isinstance(settings, Settings) else get_settings()
    return _session_factory(
        url,
        int(cfg.db_pool_size),
        int(cfg.db_max_overflow),
        float(cfg.db_pool_timeout_seconds),
        float(cfg.db_pool_recycle_seconds),
        float(cfg.db_connect_timeout_seconds),
    )


def dispose_engine(factory: sessionmaker[Session]) -> bool:
    """Dispose the engine behind a factory (shutdown path). Idempotent."""
    try:
        engine = factory.kw.get("bind")  # type: ignore[union-attr]
        if engine is None:
            return False
        engine.dispose()
        return True
    except Exception:
        return False


def pool_status(factory: sessionmaker[Session]) -> dict[str, Any]:
    """Cheap pool telemetry for health metadata (no secrets, no I/O)."""
    status: dict[str, Any] = {"driver": "unknown", "pooled": False}
    try:
        engine = factory.kw.get("bind")  # type: ignore[union-attr]
        if engine is None:
            return status
        status["driver"] = str(getattr(engine, "driver", "unknown"))
        pool = getattr(engine, "pool", None)
        if pool is None or type(pool).__name__ in (
            "SingletonThreadPool",
            "NullPool",
            "StaticPool",
            "AssertionPool",
        ):
            return status
        status["pooled"] = True
        if hasattr(pool, "checkedout"):
            status["checked_out"] = pool.checkedout()
        if hasattr(pool, "size"):
            status["pool_size"] = pool.size()
        if hasattr(pool, "overflow"):
            status["overflow"] = pool.overflow()
    except Exception:
        pass
    return status


def get_db(request: Request) -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session.

    Prefers the factory bound to the application
    (``app.state.session_factory``) so each app — including tests — controls
    its database; falls back to global settings otherwise.
    """
    factory: sessionmaker[Session] | None = None
    if request is not None:
        factory = getattr(request.app.state, "session_factory", None)
    if factory is None:
        factory = get_session_factory()
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(database_url: str | None = None) -> None:
    """Create tables directly (dev/test convenience; Alembic owns prod schema)."""
    url = database_url or get_settings().database_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    engine = create_engine(url, connect_args=connect_args)
    Base.metadata.create_all(engine)
