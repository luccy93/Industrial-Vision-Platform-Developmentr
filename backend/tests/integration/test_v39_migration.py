"""V39 governance workflow migration — additive, reversible, no cascade."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

_REPO_ROOT = Path(__file__).resolve().parents[3]

_V39_TABLES = {
    "governance_workflow_templates",
    "governance_workflows",
    "governance_workflow_tasks",
    "governance_workflow_task_dependencies",
    "governance_workflow_references",
    "governance_workflow_escalations",
    "governance_workflow_events",
}

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

_APPEND_ONLY_TABLES = {
    "governance_workflow_task_dependencies",
    "governance_workflow_references",
    "governance_workflow_events",
}

_V39_TRIGGERS = {f"trg_{table}_no_delete" for table in _V39_TABLES} | {
    f"trg_{table}_no_update" for table in _APPEND_ONLY_TABLES
}


def _tables(url: str) -> set[str]:
    return set(inspect(create_engine(url)).get_table_names())


def _config(tmp_path: Path, monkeypatch) -> Config:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/migrate.db"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))
    return config


def _seed(engine) -> None:  # type: ignore[no-untyped-def]
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO governance_workflow_templates (
                    id, template_key, version, name, description, status,
                    definition, definition_digest, task_count, dependency_count,
                    created_by, created_at, updated_at, idempotency_key
                ) VALUES (
                    'tpl-v39', 'CASE_REVIEW', 1, 'Synthetic V39 template',
                    'Synthetic migration fixture.', 'ACTIVE', '{}', :digest, 2, 1,
                    'admin@example.com', '2026-11-15 12:00:00',
                    '2026-11-15 12:00:00', 'v39-migration-template'
                )
                """
            ),
            {"digest": "a" * 64},
        )
        connection.execute(
            text(
                """
                INSERT INTO governance_workflows (
                    id, template_id, template_key, template_version,
                    template_digest, template_snapshot, case_id, title,
                    description, status, version, owner_type, owner_id, priority,
                    created_by, created_at, updated_at, idempotency_key
                ) VALUES (
                    'wf-v39', 'tpl-v39', 'CASE_REVIEW', 1, :digest, '{}', NULL,
                    'Synthetic V39 workflow', 'Synthetic migration fixture.',
                    'DRAFT', 1, 'ROLE', 'OPERATOR', 'MEDIUM',
                    'admin@example.com', '2026-11-15 12:00:00',
                    '2026-11-15 12:00:00', 'v39-migration-workflow'
                )
                """
            ),
            {"digest": "a" * 64},
        )
        connection.execute(
            text(
                """
                INSERT INTO governance_workflow_tasks (
                    id, workflow_id, task_key, title, description, status,
                    version, required, order_index, created_at, updated_at
                ) VALUES (
                    'task-v39-a', 'wf-v39', 'intake', 'Intake',
                    'Synthetic task fixture.', 'PENDING', 1, 1, 0,
                    '2026-11-15 12:00:00', '2026-11-15 12:00:00'
                ), (
                    'task-v39-b', 'wf-v39', 'review', 'Review',
                    'Synthetic task fixture.', 'PENDING', 1, 1, 1,
                    '2026-11-15 12:00:00', '2026-11-15 12:00:00'
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO governance_workflow_task_dependencies (
                    id, workflow_id, task_id, depends_on_task_id, created_at
                ) VALUES (
                    'dep-v39', 'wf-v39', 'task-v39-b', 'task-v39-a',
                    '2026-11-15 12:00:00'
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO governance_workflow_references (
                    id, workflow_id, task_id, domain, source_id, reference_key,
                    source_label, source_case_id, availability, source_status,
                    source_version, added_by, added_at, last_checked_at, reason
                ) VALUES (
                    'ref-v39', 'wf-v39', 'task-v39-a', 'FORENSIC_CASE',
                    'case-v39', 'FORENSIC_CASE:case-v39', 'Synthetic case', NULL,
                    'AVAILABLE', 'OPEN', 1, 'admin@example.com',
                    '2026-11-15 12:00:00', '2026-11-15 12:00:00',
                    'Synthetic migration fixture.'
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO governance_workflow_escalations (
                    id, workflow_id, task_id, escalation_type, severity, status,
                    reason, resolution, requested_by, requested_at,
                    acknowledged_by, acknowledged_at, resolved_by, resolved_at,
                    version, idempotency_key
                ) VALUES (
                    'esc-v39', 'wf-v39', NULL, 'MANUAL', 'HIGH', 'OPEN',
                    'Synthetic escalation fixture.', NULL, 'admin@example.com',
                    '2026-11-15 12:00:00', NULL, NULL, NULL, NULL, 1,
                    'v39-migration-escalation'
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO governance_workflow_events (
                    id, workflow_id, task_id, template_id, event_type,
                    from_status, to_status, actor_id, actor_role, reason, detail,
                    sequence, created_at
                ) VALUES (
                    'evt-v39', 'wf-v39', NULL, NULL, 'WORKFLOW_CREATED',
                    NULL, 'DRAFT', 'admin@example.com', 'ADMIN',
                    'Synthetic migration fixture.', '{}', 1,
                    '2026-11-15 12:00:00'
                )
                """
            )
        )


def test_governance_workflow_migration_cycle(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = _config(tmp_path, monkeypatch)
    url = f"sqlite:///{tmp_path}/migrate.db"

    command.upgrade(config, "head")
    tables = _tables(url)
    assert _V39_TABLES <= tables
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
                    "AND name LIKE 'trg_governance_workflow%'"
                )
            ).all()
        }
    assert _V39_TRIGGERS <= triggers

    # No workflow foreign key may cascade or null a parent row.
    inspector = inspect(engine)
    for table in _V39_TABLES:
        for foreign_key in inspector.get_foreign_keys(table):
            ondelete = str(foreign_key.get("options", {}).get("ondelete", "") or "").upper()
            assert ondelete not in {"CASCADE", "SET NULL"}, (table, foreign_key)

    _seed(engine)

    # Workflow and task rows stay mutable for validated lifecycle updates.
    with engine.begin() as connection:
        connection.execute(
            text("UPDATE governance_workflows SET status = 'READY', version = 2 WHERE id = 'wf-v39'")
        )
        connection.execute(
            text("UPDATE governance_workflow_tasks SET status = 'READY', version = 2 WHERE id = 'task-v39-a'")
        )

    for table, row_id in (
        ("governance_workflow_templates", "tpl-v39"),
        ("governance_workflows", "wf-v39"),
        ("governance_workflow_tasks", "task-v39-a"),
        ("governance_workflow_escalations", "esc-v39"),
    ):
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(text(f"DELETE FROM {table} WHERE id = '{row_id}'"))

    # Dependencies, references, and events are append-only and undeletable.
    for table, row_id, update_column in (
        ("governance_workflow_task_dependencies", "dep-v39", "created_at"),
        ("governance_workflow_references", "ref-v39", "reason"),
        ("governance_workflow_events", "evt-v39", "reason"),
    ):
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(f"UPDATE {table} SET {update_column} = 'tampered' WHERE id = '{row_id}'")
                )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(text(f"DELETE FROM {table} WHERE id = '{row_id}'"))

    # V39 reverses alone: only workflow tables disappear.
    command.downgrade(config, "015_create_governance_executive")
    remaining = _tables(url)
    assert _V39_TABLES.isdisjoint(remaining)
    assert _V38_TABLES <= remaining
    assert _V37_TABLES <= remaining
    assert _V36_TABLES <= remaining

    command.upgrade(config, "head")
    assert _V39_TABLES <= _tables(url)
