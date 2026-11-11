"""V36 governance automation migration — additive, reversible, no cascade."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

_REPO_ROOT = Path(__file__).resolve().parents[3]

_V36_TABLES = {
    "governance_job_schedules",
    "governance_jobs",
    "governance_job_events",
    "governance_snapshots",
}

_V35_TABLES = {
    "governance_policy_versions",
    "governance_retention_evaluations",
    "governance_legal_holds",
    "governance_legal_hold_events",
    "governance_disposition_requests",
    "governance_disposition_decisions",
    "governance_export_approvals",
    "governance_access_audit",
}


def _tables(url: str) -> set[str]:
    return set(inspect(create_engine(url)).get_table_names())


def _config(tmp_path: Path, monkeypatch) -> Config:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/migrate.db"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))
    return config


def _seed_counts(url: str) -> tuple[int, int]:
    engine = create_engine(url)
    with engine.begin() as connection:
        total = int(connection.execute(text("SELECT COUNT(*) FROM governance_job_schedules")).scalar_one())
        disabled = int(
            connection.execute(
                text("SELECT COUNT(*) FROM governance_job_schedules WHERE enabled = 0")
            ).scalar_one()
        )
    return total, disabled


def test_governance_automation_migration_cycle(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = _config(tmp_path, monkeypatch)
    url = f"sqlite:///{tmp_path}/migrate.db"

    command.upgrade(config, "head")
    tables = _tables(url)
    assert _V36_TABLES <= tables
    assert _V35_TABLES <= tables
    assert _seed_counts(url) == (7, 7)

    engine = create_engine(url)
    with engine.begin() as connection:
        triggers = {
            str(row[0])
            for row in connection.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND (name LIKE 'trg_governance_job%' OR name LIKE 'trg_governance_snapshot%')"
                )
            ).all()
        }
    assert {
        "trg_governance_job_schedules_no_delete",
        "trg_governance_jobs_no_delete",
        "trg_governance_job_events_no_delete",
        "trg_governance_job_events_no_update",
        "trg_governance_snapshots_no_delete",
        "trg_governance_snapshots_no_update",
    } <= triggers

    # Schedules are mutable for configuration but cannot be deleted.
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE governance_job_schedules SET interval_minutes = 120 "
                "WHERE job_type = 'RETENTION_EVALUATION'"
            )
        )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM governance_job_schedules WHERE job_type = 'RETENTION_EVALUATION'")
            )

    # Snapshots are append-only.
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO governance_snapshots (
                    id, snapshot_type, as_of, generated_at, generated_by, job_id,
                    trigger, dedup_key, payload, payload_digest, row_count, schema_version
                ) VALUES (
                    'snap-1', 'COMPLIANCE_SUMMARY', '2026-11-11 12:00:00',
                    '2026-11-11 12:00:00', 'tester', NULL, 'MANUAL', 'dedup-1',
                    '{}', 'digest', 0, 1
                )
                """
            )
        )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(text("UPDATE governance_snapshots SET payload = '{}' WHERE id = 'snap-1'"))
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM governance_snapshots WHERE id = 'snap-1'"))

    # V36 reverses alone: only automation tables disappear.
    command.downgrade(config, "-1")
    remaining = _tables(url)
    assert _V36_TABLES.isdisjoint(remaining)
    assert _V35_TABLES <= remaining
    with engine.begin() as connection:
        leftover = connection.execute(
            text(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                "AND (name LIKE 'trg_governance_job%' OR name LIKE 'trg_governance_snapshot%')"
            )
        ).all()
        assert leftover == []

    command.upgrade(config, "head")
    assert _V36_TABLES <= _tables(url)
    assert _seed_counts(url) == (7, 7)


def test_governance_automation_postgresql_sql_is_additive_and_triggered(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))
    buffer = io.StringIO()
    config.output_buffer = buffer

    command.upgrade(config, "012_create_governance:013_create_governance_automation", sql=True)
    sql = buffer.getvalue()

    for table in _V36_TABLES:
        assert f"CREATE TABLE {table}" in sql
    assert sql.count("INSERT INTO governance_job_schedules") == 7
    assert "CREATE OR REPLACE FUNCTION governance_automation_block_mutation()" in sql
    assert sql.count("CREATE TRIGGER") == 4
    assert "trg_governance_job_events_append_only" in sql
    assert "trg_governance_snapshots_append_only" in sql
    assert "trg_governance_job_schedules_no_delete" in sql
    assert "trg_governance_jobs_no_delete" in sql
    assert "ON DELETE CASCADE" not in sql.upper()
    assert "ON DELETE SET NULL" not in sql.upper()
    assert "DROP TABLE" not in sql.upper()
    assert "BEFORE UPDATE OR DELETE" in sql
    assert "BEFORE DELETE" in sql
