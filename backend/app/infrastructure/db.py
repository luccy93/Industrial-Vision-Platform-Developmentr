"""Database engine + session helpers (V02: cameras persistence).

PostgreSQL in production (``DATABASE_URL``); SQLite works for local dev and
Alembic offline validation. Sessions are request-scoped via ``get_db``.
"""

from __future__ import annotations

from collections.abc import Iterator
from functools import lru_cache

from fastapi import Request
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import get_settings
from backend.app.models import (
    autonomous_orm,  # noqa: F401 (registers the autonomous profiles table)
    incident_orm,  # noqa: F401 (registers the incident tables)
    quality_orm,  # noqa: F401 (registers the quality tables)
    zone_orm,  # noqa: F401 (registers the zones table)
)
from backend.app.models.camera_orm import Base


@lru_cache(maxsize=8)
def _session_factory(database_url: str) -> sessionmaker[Session]:
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, pool_pre_ping=True, connect_args=connect_args)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_session_factory(database_url: str | None = None) -> sessionmaker[Session]:
    url = database_url or get_settings().database_url
    return _session_factory(url)


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
