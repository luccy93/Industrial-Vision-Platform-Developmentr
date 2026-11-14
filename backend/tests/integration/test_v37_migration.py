"""V37 governance intelligence migration — additive, reversible, no cascade."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

_REPO_ROOT = Path(__file__).resolve().parents[3]

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

_V37_TRIGGERS = {
    "trg_governance_risk_models_no_update",
    "trg_governance_risk_models_no_delete",
    "trg_governance_sla_targets_no_update",
    "trg_governance_sla_targets_no_delete",
    "trg_governance_recommendation_events_no_update",
    "trg_governance_recommendation_events_no_delete",
    "trg_governance_recommendations_no_delete",
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
        models = int(connection.execute(text("SELECT COUNT(*) FROM governance_risk_models")).scalar_one())
        targets = int(connection.execute(text("SELECT COUNT(*) FROM governance_sla_targets")).scalar_one())
    return models, targets


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
                    'rec-1', 'GOV-RISK-001|CASE|case-1', 'GOV-RISK-001', 'CASE',
                    'case-1', 'case-1', 'CRITICAL', 'CRITICAL', 'Review case',
                    'Synthetic migration fixture.', '[]', 'OPEN', 1,
                    '2026-11-11 12:00:00', '2026-11-11 12:00:00',
                    '2026-11-11 12:00:00', '2026-11-11 12:00:00'
                )
                """
            )
        )


def test_governance_intelligence_migration_cycle(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = _config(tmp_path, monkeypatch)
    url = f"sqlite:///{tmp_path}/migrate.db"

    command.upgrade(config, "head")
    tables = _tables(url)
    assert _V37_TABLES <= tables
    assert _V36_TABLES <= tables
    assert _V35_TABLES <= tables
    assert _seed_counts(url) == (1, 4)

    engine = create_engine(url)
    with engine.begin() as connection:
        triggers = {
            str(row[0])
            for row in connection.execute(
                text(
                    "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                    "AND (name LIKE 'trg_governance_risk%' "
                    "OR name LIKE 'trg_governance_sla%' "
                    "OR name LIKE 'trg_governance_recommendation%')"
                )
            ).all()
        }
    assert _V37_TRIGGERS <= triggers

    # Risk models and SLA targets are append-only.
    for table in ("governance_risk_models", "governance_sla_targets"):
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(text(f"UPDATE {table} SET reason = 'tampered'"))
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(text(f"DELETE FROM {table}"))

    # Recommendations are mutable for lifecycle updates but cannot be deleted.
    _insert_recommendation(engine)
    with engine.begin() as connection:
        connection.execute(
            text(
                "UPDATE governance_recommendations "
                "SET status = 'ACKNOWLEDGED', version = 2 WHERE id = 'rec-1'"
            )
        )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM governance_recommendations WHERE id = 'rec-1'"))

    # Recommendation events are append-only.
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO governance_recommendation_events (
                    id, recommendation_id, event_type, from_status, to_status,
                    actor_id, actor_role, reason, detail, created_at
                ) VALUES (
                    'event-1', 'rec-1', 'ACKNOWLEDGED', 'OPEN', 'ACKNOWLEDGED',
                    'tester', 'ADMIN', 'synthetic migration fixture', '{}',
                    '2026-11-11 12:00:00'
                )
                """
            )
        )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(
                text("UPDATE governance_recommendation_events SET reason = 'tampered' WHERE id = 'event-1'")
            )
    with pytest.raises(IntegrityError):
        with engine.begin() as connection:
            connection.execute(text("DELETE FROM governance_recommendation_events WHERE id = 'event-1'"))

    # V37 reverses alone: only intelligence tables disappear.
    command.downgrade(config, "013_create_governance_automation")
    remaining = _tables(url)
    assert _V37_TABLES.isdisjoint(remaining)
    assert _V36_TABLES <= remaining
    assert _V35_TABLES <= remaining
    with engine.begin() as connection:
        leftover = connection.execute(
            text(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' "
                "AND (name LIKE 'trg_governance_risk%' "
                "OR name LIKE 'trg_governance_sla%' "
                "OR name LIKE 'trg_governance_recommendation%')"
            )
        ).all()
        assert leftover == []

    command.upgrade(config, "head")
    assert _V37_TABLES <= _tables(url)
    assert _seed_counts(url) == (1, 4)


def test_governance_intelligence_postgresql_sql_is_additive_and_triggered(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))
    buffer = io.StringIO()
    config.output_buffer = buffer

    command.upgrade(
        config,
        "013_create_governance_automation:014_create_governance_intelligence",
        sql=True,
    )
    sql = buffer.getvalue()

    for table in _V37_TABLES:
        assert f"CREATE TABLE {table}" in sql
    assert sql.count("INSERT INTO governance_risk_models") == 1
    assert sql.count("INSERT INTO governance_sla_targets") == 4
    assert "CREATE OR REPLACE FUNCTION governance_intelligence_block_mutation()" in sql
    assert sql.count("CREATE TRIGGER") == 4
    assert "trg_governance_risk_models_append_only" in sql
    assert "trg_governance_sla_targets_append_only" in sql
    assert "trg_governance_recommendation_events_append_only" in sql
    assert "trg_governance_recommendations_no_delete" in sql
    assert "ON DELETE CASCADE" not in sql.upper()
    assert "ON DELETE SET NULL" not in sql.upper()
    assert "DROP TABLE" not in sql.upper()
    assert "BEFORE UPDATE OR DELETE" in sql
    assert "BEFORE DELETE" in sql
