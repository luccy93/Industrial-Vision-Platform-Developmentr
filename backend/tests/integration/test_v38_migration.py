"""V38 executive governance migration — additive, reversible, no cascade."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

_REPO_ROOT = Path(__file__).resolve().parents[3]

_V38_TABLES = {
    "governance_executive_actions",
    "governance_executive_action_events",
    "governance_executive_reports",
}

_V37_TABLES = {
    "governance_risk_models",
    "governance_sla_targets",
    "governance_recommendations",
    "governance_recommendation_events",
}

_V36_TABLES = {
    "governance_job_schedules",
    "governance_jobs",
    "governance_job_events",
    "governance_snapshots",
}

_V38_TRIGGERS = {
    "trg_governance_executive_actions_no_delete",
    "trg_governance_executive_action_events_no_update",
    "trg_governance_executive_action_events_no_delete",
    "trg_governance_executive_reports_no_update",
    "trg_governance_executive_reports_no_delete",
}


def _tables(url: str) -> set[str]:
    return set(inspect(create_engine(url)).get_table_names())


def _config(tmp_path: Path, monkeypatch) -> Config:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/migrate.db"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))
    return config


def _insert_recommendation(engine) -> None:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO governance_recommendations (
                    id, recommendation_key, rule_id, scope_type, scope_id, case_id,
                    severity, risk_level, title, rationale, source_refs, status,
                    version, first_seen_at, last_evaluated_at, created_at, updated_at
                ) VALUES (
                    'rec-v38', 'GOV-RISK-001|CASE|case-v38', 'GOV-RISK-001', 'CASE',
                    'case-v38', 'case-v38', 'CRITICAL', 'CRITICAL', 'Review case',
                    'Synthetic V38 migration fixture.', '[]', 'OPEN', 1,
                    '2026-11-15 12:00:00', '2026-11-15 12:00:00',
                    '2026-11-15 12:00:00', '2026-11-15 12:00:00'
                )
                """
            )
        )


def _insert_snapshot(engine) -> None:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO governance_snapshots (
                    id, snapshot_type, as_of, generated_at, generated_by, job_id,
                    trigger, dedup_key, payload, payload_digest, row_count,
                    schema_version
                ) VALUES (
                    'snap-v38', 'EXECUTIVE_SUMMARY', '2026-11-15 12:00:00',
                    '2026-11-15 12:00:00', 'admin@example.com', NULL, 'MANUAL',
                    'v38-migration-fixture-snapshot', '{}', :digest, 0, 1
                )
                """
            ),
            {"digest": "a" * 64},
        )


def _insert_action(engine) -> None:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO governance_executive_actions (
                    id, recommendation_id, recommendation_rule_id,
                    recommendation_severity, case_id, title, description, owner_id,
                    due_at, priority, status, version, created_by, created_at,
                    updated_at, idempotency_key
                ) VALUES (
                    'act-v38', 'rec-v38', 'GOV-RISK-001', 'CRITICAL', 'case-v38',
                    'Synthetic strategic action', 'Synthetic migration fixture.',
                    'operator@example.com', '2026-12-01 12:00:00', 'HIGH', 'OPEN', 1,
                    'admin@example.com', '2026-11-15 12:00:00',
                    '2026-11-15 12:00:00', 'v38-migration-action'
                )
                """
            )
        )


def test_governance_executive_migration_cycle(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = _config(tmp_path, monkeypatch)
    url = f"sqlite:///{tmp_path}/migrate.db"

    command.upgrade(config, "head")
    tables = _tables(url)
    assert _V38_TABLES <= tables
    assert _V37_TABLES <= tables
    assert _V36_TABLES <= tables

    engine = create_engine(url)
    with engine.begin() as connection:
        triggers = {
            str(row[0])
            for row in connection.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND name LIKE 'trg_governance_executive%'"
                )
            ).all()
        }
    assert _V38_TRIGGERS <= triggers

    _insert_recommendation(engine)
    _insert_snapshot(engine)
    _insert_action(engine)

    # Actions stay mutable for lifecycle updates but cannot be deleted.
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE governance_executive_actions "
                "SET status = 'IN_PROGRESS', version = 2 WHERE id = 'act-v38'"
            )
        )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM governance_executive_actions WHERE id = 'act-v38'"))

    # Action events are append-only.
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO governance_executive_action_events (
                    id, action_id, event_type, from_status, to_status, actor_id,
                    actor_role, reason, detail, created_at
                ) VALUES (
                    'evt-v38', 'act-v38', 'CREATED', NULL, 'OPEN',
                    'admin@example.com', 'ADMIN', 'synthetic migration fixture',
                    '{}', '2026-11-15 12:00:00'
                )
                """
            )
        )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE governance_executive_action_events SET reason = 'tampered' WHERE id = 'evt-v38'")
            )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM governance_executive_action_events WHERE id = 'evt-v38'"))

    # Report metadata is append-only.
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO governance_executive_reports (
                    id, report_type, report_format, status, window_start,
                    window_end, generated_at, generated_by, snapshot_id,
                    snapshot_type, schema_version, source_coverage,
                    sections_available, sections_unavailable, payload_digest,
                    report_digest, row_count, redaction_applied,
                    idempotency_key, reason, created_at
                ) VALUES (
                    'rep-v38', 'EXECUTIVE_SUMMARY', 'json', 'GENERATED',
                    '2026-10-16 12:00:00', '2026-11-15 12:00:00',
                    '2026-11-15 12:00:00', 'admin@example.com', 'snap-v38',
                    'EXECUTIVE_SUMMARY', 1, '{}', '[]', '[]', :payload_digest,
                    :report_digest, 0, 1, 'v38-migration-report',
                    'synthetic migration fixture', '2026-11-15 12:00:00'
                )
                """
            ),
            {"payload_digest": "b" * 64, "report_digest": "c" * 64},
        )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE governance_executive_reports SET reason = 'tampered' WHERE id = 'rep-v38'")
            )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM governance_executive_reports WHERE id = 'rep-v38'"))

    # V38 reverses alone: only executive tables disappear.
    command.downgrade(config, "014_create_governance_intelligence")
    remaining = _tables(url)
    assert _V38_TABLES.isdisjoint(remaining)
    assert _V37_TABLES <= remaining
    assert _V36_TABLES <= remaining
    with engine.begin() as connection:
        leftover = connection.execute(
            text(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                "AND name LIKE 'trg_governance_executive%'"
            )
        ).all()
        assert leftover == []

    command.upgrade(config, "head")
    assert _V38_TABLES <= _tables(url)


def test_v38_downgrade_preserves_v36_snapshots_and_v37_history(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = _config(tmp_path, monkeypatch)
    url = f"sqlite:///{tmp_path}/migrate.db"
    command.upgrade(config, "head")
    engine = create_engine(url)
    _insert_recommendation(engine)
    _insert_snapshot(engine)

    command.downgrade(config, "014_create_governance_intelligence")
    with engine.begin() as connection:
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM governance_snapshots WHERE id = 'snap-v38'")
            ).scalar_one()
            == 1
        )
        assert (
            connection.execute(
                text("SELECT COUNT(*) FROM governance_recommendations WHERE id = 'rec-v38'")
            ).scalar_one()
            == 1
        )

    command.upgrade(config, "head")
    with engine.begin() as connection:
        snapshot = connection.execute(
            text("SELECT snapshot_type, payload_digest FROM governance_snapshots WHERE id = 'snap-v38'")
        ).one()
        assert snapshot[0] == "EXECUTIVE_SUMMARY"
        assert snapshot[1] == "a" * 64


def test_governance_executive_postgresql_sql_is_additive_and_triggered(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))
    buffer = io.StringIO()
    config.output_buffer = buffer

    command.upgrade(
        config,
        "014_create_governance_intelligence:015_create_governance_executive",
        sql=True,
    )
    sql = buffer.getvalue()

    for table in _V38_TABLES:
        assert f"CREATE TABLE {table}" in sql
    assert "CREATE OR REPLACE FUNCTION governance_executive_block_mutation()" in sql
    assert "trg_governance_executive_actions_no_delete" in sql
    assert "trg_governance_executive_action_events_append_only" in sql
    assert "trg_governance_executive_reports_append_only" in sql
    assert sql.count("CREATE TRIGGER") == 3
    assert "ON DELETE CASCADE" not in sql.upper()
    assert "ON DELETE SET NULL" not in sql.upper()
    assert "DROP TABLE" not in sql.upper()
    assert "BEFORE UPDATE OR DELETE" in sql
    assert "BEFORE DELETE" in sql
