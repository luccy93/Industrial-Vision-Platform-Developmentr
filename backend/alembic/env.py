"""Alembic environment — V02 cameras migration chain."""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure `backend.*` imports resolve when alembic runs from the repo root.
sys.path.insert(0, os.path.abspath("."))

from backend.app.core.config import get_settings  # noqa: E402
from backend.app.models import (
    autonomous_orm,  # noqa: E402,F401 (register autonomous metadata)
    incident_orm,  # noqa: E402,F401 (register incident metadata)
    quality_orm,  # noqa: E402,F401 (register quality metadata)
    zone_orm,  # noqa: E402,F401 (register zones metadata)
)
from backend.app.models.camera_orm import Base  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _database_url() -> str:
    return os.environ.get("DATABASE_URL") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(
        url=_database_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    from sqlalchemy import text

    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = _database_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        # V17: alembic's default version table is VARCHAR(32), but this
        # project's revision ids are longer (e.g.
        # 004_create_autonomous_perception_profiles). Pre-create the table
        # with a wide column on fresh databases; IF NOT EXISTS leaves
        # existing databases — and SQLite, which ignores lengths —
        # untouched. Historical migrations are never rewritten for this.
        connection.execute(
            text("CREATE TABLE IF NOT EXISTS alembic_version (version_num VARCHAR(128) NOT NULL PRIMARY KEY)")
        )
        connection.commit()
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
