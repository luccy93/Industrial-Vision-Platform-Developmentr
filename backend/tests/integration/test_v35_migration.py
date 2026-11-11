"""V35 governance migration — additive upgrade/downgrade and trigger cycle."""

from __future__ import annotations

import io
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError

_REPO_ROOT = Path(__file__).resolve().parents[3]

_GOVERNANCE_TABLES = {
    "governance_policy_versions",
    "governance_retention_evaluations",
    "governance_legal_holds",
    "governance_legal_hold_events",
    "governance_disposition_requests",
    "governance_disposition_decisions",
    "governance_export_approvals",
    "governance_access_audit",
}

#: V34 tables that V35 must leave untouched.
_PRIOR_TABLES = {
    "forensic_cases",
    "forensic_custody_events",
    "forensic_exports",
    "incidents",
    "alert_rules",
    "notifications",
    "users",
    "cameras",
}

_APPEND_ONLY_TABLES = {
    "governance_policy_versions",
    "governance_retention_evaluations",
    "governance_legal_hold_events",
    "governance_disposition_decisions",
    "governance_access_audit",
}

_MUTABLE_TABLES = _GOVERNANCE_TABLES - _APPEND_ONLY_TABLES

#: Minimal rows used to exercise row-level triggers. SQLite triggers fire per
#: affected row, so the enforcement test must operate on real rows.
_APPEND_ONLY_ROWS: dict[str, dict[str, object]] = {
    "governance_policy_versions": {
        "id": "trigger-policy",
        "policy_id": "POL-TRIGGER",
        "version": 99,
        "name": "Trigger probe",
        "created_at": "2026-01-01 00:00:00",
    },
    "governance_retention_evaluations": {
        "id": "trigger-evaluation",
        "case_id": "CASE-TRIGGER",
        "policy_snapshot": "{}",
        "as_of": "2026-01-01",
        "evaluated_at": "2026-01-01 00:00:00",
        "governance_state": "ACTIVE",
        "legal_hold_ids": "[]",
        "reasons": "[]",
        "created_at": "2026-01-01 00:00:00",
    },
    "governance_legal_hold_events": {
        "id": "trigger-hold-event",
        "hold_id": "HOLD-TRIGGER",
        "event_type": "CREATED",
        "actor_id": "SYSTEM",
        "actor_role": "SYSTEM",
        "to_status": "PENDING_APPROVAL",
        "occurred_at": "2026-01-01 00:00:00",
        "metadata": "{}",
        "created_at": "2026-01-01 00:00:00",
    },
    "governance_disposition_decisions": {
        "id": "trigger-decision",
        "disposition_id": "DISP-TRIGGER",
        "decision": "APPROVE",
        "actor_id": "SYSTEM",
        "actor_role": "SYSTEM",
        "from_status": "REVIEW_REQUIRED",
        "to_status": "APPROVED",
        "occurred_at": "2026-01-01 00:00:00",
        "metadata": "{}",
        "created_at": "2026-01-01 00:00:00",
    },
    "governance_access_audit": {
        "id": "trigger-audit",
        "event_type": "CASE_VIEWED",
        "actor_id": "SYSTEM",
        "actor_role": "SYSTEM",
        "target_type": "FORENSIC_CASE",
        "target_id": "CASE-TRIGGER",
        "outcome": "SUCCESS",
        "occurred_at": "2026-01-01T00:00:00+00:00",
        "event_hash": "0" * 64,
        "metadata": "{}",
        "created_at": "2026-01-01 00:00:00",
    },
}

_MUTABLE_ROWS: dict[str, dict[str, object]] = {
    "governance_legal_holds": {
        "id": "trigger-hold",
        "hold_number": "HOLD-TRIGGER-1",
        "case_id": "CASE-TRIGGER",
        "reason": "Trigger probe",
        "requested_by": "SYSTEM",
        "requested_role": "SYSTEM",
        "requested_at": "2026-01-01 00:00:00",
        "created_at": "2026-01-01 00:00:00",
        "updated_at": "2026-01-01 00:00:00",
        "metadata": "{}",
    },
    "governance_disposition_requests": {
        "id": "trigger-disposition",
        "request_number": "DISP-TRIGGER-1",
        "case_id": "CASE-TRIGGER",
        "status": "REVIEW_REQUIRED",
        "justification": "Trigger probe",
        "requested_by": "SYSTEM",
        "requested_role": "SYSTEM",
        "requested_at": "2026-01-01 00:00:00",
        "blocked_reason_codes": "[]",
        "created_at": "2026-01-01 00:00:00",
        "updated_at": "2026-01-01 00:00:00",
        "metadata": "{}",
    },
    "governance_export_approvals": {
        "id": "trigger-export",
        "request_number": "EXP-TRIGGER-1",
        "case_id": "CASE-TRIGGER",
        "status": "PENDING_APPROVAL",
        "reason": "Trigger probe",
        "requested_by": "SYSTEM",
        "requested_role": "SYSTEM",
        "requested_at": "2026-01-01 00:00:00",
        "created_at": "2026-01-01 00:00:00",
        "updated_at": "2026-01-01 00:00:00",
        "metadata": "{}",
    },
}


def _insert_row(engine, table: str, values: dict[str, object]) -> None:  # type: ignore[no-untyped-def]
    columns = ", ".join(values)
    params = ", ".join(f":{name}" for name in values)
    with engine.begin() as connection:
        connection.execute(
            text(f"INSERT INTO {table} ({columns}) VALUES ({params})"),
            values,
        )


def _tables(url: str) -> set[str]:
    return set(inspect(create_engine(url)).get_table_names())


def _columns(url: str, table: str) -> set[str]:
    return {str(c["name"]) for c in inspect(create_engine(url)).get_columns(table)}


def _indexes(url: str, table: str) -> dict[str, dict[str, object]]:
    return {str(item["name"]): item for item in inspect(create_engine(url)).get_indexes(table)}


def _config(tmp_path: Path, monkeypatch) -> Config:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/migrate.db"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))
    return config


def test_governance_migration_upgrade_downgrade_reupgrade(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    config = _config(tmp_path, monkeypatch)
    url = f"sqlite:///{tmp_path}/migrate.db"

    command.upgrade(config, "012_create_governance")
    tables = _tables(url)
    assert _GOVERNANCE_TABLES <= tables
    assert _PRIOR_TABLES <= tables

    assert {
        "policy_id",
        "version",
        "state",
        "retention_days",
        "review_interval_days",
        "required_approval_level",
        "export_allowed",
        "export_requires_approval",
        "allow_evidence_bytes",
        "legal_hold_eligible",
        "disposition_review_required",
        "idempotency_key",
    } <= _columns(url, "governance_policy_versions")
    assert {
        "case_id",
        "evaluation_kind",
        "governance_state",
        "data_status",
        "disposition_eligible",
        "integrity_status",
        "legal_hold_ids",
        "reasons",
        "idempotency_key",
    } <= _columns(url, "governance_retention_evaluations")
    assert {
        "hold_number",
        "case_id",
        "evidence_reference_id",
        "status",
        "requested_by",
        "approved_by",
        "released_by",
        "version",
    } <= _columns(url, "governance_legal_holds")
    assert {
        "hold_id",
        "event_type",
        "actor_id",
        "from_status",
        "to_status",
        "idempotency_key",
    } <= _columns(url, "governance_legal_hold_events")
    assert {
        "case_id",
        "evaluation_id",
        "status",
        "justification",
        "approval_count",
        "blocked_reason_codes",
        "open_key",
    } <= _columns(url, "governance_disposition_requests")
    assert {
        "disposition_id",
        "decision",
        "actor_id",
        "from_status",
        "to_status",
        "idempotency_key",
    } <= _columns(url, "governance_disposition_decisions")
    assert {
        "case_id",
        "status",
        "include_evidence_bytes",
        "export_id",
        "export_sha256",
        "verification_outcome",
        "version",
    } <= _columns(url, "governance_export_approvals")
    assert {
        "event_type",
        "actor_id",
        "target_type",
        "target_id",
        "case_id",
        "event_hash",
        "event_key",
    } <= _columns(url, "governance_access_audit")

    inspector = inspect(create_engine(url))
    policy_uniques = {str(c["name"]) for c in inspector.get_unique_constraints("governance_policy_versions")}
    assert "uq_governance_policy_version" in policy_uniques
    decision_uniques = {
        str(c["name"]) for c in inspector.get_unique_constraints("governance_disposition_decisions")
    }
    assert "uq_governance_disposition_actor_decision" in decision_uniques

    unique_indexes = {
        "governance_policy_versions": "ix_governance_policy_versions_idempotency_key",
        "governance_retention_evaluations": "ix_governance_retention_evaluations_idempotency_key",
        "governance_legal_holds": "ix_governance_legal_holds_hold_number",
        "governance_legal_hold_events": "ix_governance_legal_hold_events_idempotency_key",
        "governance_disposition_requests": "ix_governance_disposition_requests_open_key",
        "governance_disposition_decisions": "ix_governance_disposition_decisions_idempotency_key",
        "governance_export_approvals": "ix_governance_export_approvals_export_id",
        "governance_access_audit": "ix_governance_access_audit_event_key",
    }
    for table, index_name in unique_indexes.items():
        assert _indexes(url, table)[index_name].get("unique"), (table, index_name)

    engine = create_engine(url)
    with engine.begin() as connection:
        seeded = connection.execute(
            text(
                "SELECT policy_id, version, state, retention_days, review_interval_days, "
                "export_requires_approval, allow_evidence_bytes, legal_hold_eligible, "
                "disposition_review_required FROM governance_policy_versions "
                "WHERE policy_id = 'POL-DEFAULT'"
            )
        ).all()
        assert len(seeded) == 1
        row = seeded[0]
        assert row[1] == 1
        assert row[2] == "ENABLED"
        assert row[3] is None and row[4] is None
        assert bool(row[5]) is True
        assert bool(row[6]) is False
        assert bool(row[7]) is True
        assert bool(row[8]) is True

        triggers = {
            str(item[0])
            for item in connection.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'trg_governance_%'")
            ).all()
        }
        expected = {f"trg_{table}_no_delete" for table in _GOVERNANCE_TABLES}
        expected |= {f"trg_{table}_no_update" for table in _APPEND_ONLY_TABLES}
        assert triggers == expected
        assert len(triggers) == 13

    # Row-level triggers require real rows: insert probes, then prove that
    # append-only history rejects UPDATE/DELETE while mutable workflow rows
    # reject DELETE but remain updatable.
    for table, values in _APPEND_ONLY_ROWS.items():
        _insert_row(engine, table, values)
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(f"UPDATE {table} SET id = id WHERE id = :id"),
                    {"id": values["id"]},
                )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(f"DELETE FROM {table} WHERE id = :id"),
                    {"id": values["id"]},
                )
    for table, values in _MUTABLE_ROWS.items():
        _insert_row(engine, table, values)
        with engine.begin() as connection:
            connection.execute(
                text(f"UPDATE {table} SET id = id WHERE id = :id"),
                {"id": values["id"]},
            )
        with pytest.raises(IntegrityError):
            with engine.begin() as connection:
                connection.execute(
                    text(f"DELETE FROM {table} WHERE id = :id"),
                    {"id": values["id"]},
                )

    # V35 reverses alone: only governance tables disappear.
    command.downgrade(config, "-1")
    remaining = _tables(url)
    assert _GOVERNANCE_TABLES.isdisjoint(remaining)
    assert _PRIOR_TABLES <= remaining
    with engine.begin() as connection:
        leftover_triggers = connection.execute(
            text("SELECT name FROM sqlite_master WHERE type = 'trigger' AND name LIKE 'trg_governance_%'")
        ).all()
        assert leftover_triggers == []

    command.upgrade(config, "012_create_governance")
    assert _GOVERNANCE_TABLES <= _tables(url)
    with engine.begin() as connection:
        reseeded = connection.execute(
            text("SELECT COUNT(*) FROM governance_policy_versions WHERE policy_id = 'POL-DEFAULT'")
        ).scalar_one()
        assert int(reseeded) == 1


def test_governance_migration_postgresql_sql_is_additive_and_triggered(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@localhost/db")
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))
    buffer = io.StringIO()
    config.output_buffer = buffer

    command.upgrade(config, "011_create_forensics:012_create_governance", sql=True)
    sql = buffer.getvalue()

    for table in _GOVERNANCE_TABLES:
        assert f"CREATE TABLE {table}" in sql
    assert "INSERT INTO governance_policy_versions" in sql
    assert "POL-DEFAULT" in sql
    assert "CREATE OR REPLACE FUNCTION governance_block_mutation()" in sql
    assert sql.count("CREATE TRIGGER") == 8
    for table in _APPEND_ONLY_TABLES:
        assert f"trg_{table}_append_only" in sql
    for table in _MUTABLE_TABLES:
        assert f"trg_{table}_no_delete" in sql
    assert "ON DELETE CASCADE" not in sql.upper()
    assert "ON DELETE SET NULL" not in sql.upper()
    assert "DROP TABLE" not in sql.upper()

    # PostgreSQL-specific trigger behavior is not executed locally; the offline
    # SQL above is the reviewable proof that the migration installs it.
    assert "BEFORE UPDATE OR DELETE" in sql
    assert "BEFORE DELETE" in sql
