"""V34 forensic migration — upgrade/downgrade cycle from the V33 head."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

_REPO_ROOT = Path(__file__).resolve().parents[3]

_FORENSIC_TABLES = {
    "forensic_cases",
    "forensic_case_counters",
    "forensic_correlations",
    "forensic_incident_links",
    "forensic_evidence_references",
    "forensic_evidence_observations",
    "forensic_custody_events",
    "forensic_notes",
    "forensic_note_revisions",
    "forensic_actions",
    "forensic_assignments",
    "forensic_exports",
    "forensic_verification_runs",
    "forensic_notification_state",
}

#: Tables owned by earlier versions that V34 must never disturb.
_PRIOR_TABLES = {
    "incidents",
    "alert_rules",
    "notifications",
    "users",
    "cameras",
}


def _tables(url: str) -> set[str]:
    return set(inspect(create_engine(url)).get_table_names())


def _columns(url: str, table: str) -> set[str]:
    return {str(c["name"]) for c in inspect(create_engine(url)).get_columns(table)}


def _indexes(url: str, table: str) -> dict[str, dict[str, object]]:
    return {str(item["name"]): item for item in inspect(create_engine(url)).get_indexes(table)}


def test_forensic_migration_upgrade_and_downgrade_cycle(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/migrate.db"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))

    command.upgrade(config, "head")
    tables = _tables(url)
    assert _FORENSIC_TABLES <= tables
    assert _PRIOR_TABLES <= tables  # V10/V15/V16 tables still present

    assert {
        "id",
        "case_number",
        "case_type",
        "severity",
        "status",
        "priority",
        "source",
        "originating_incident_id",
        "originating_audit_run_id",
        "custody_event_count",
        "custody_head_hash",
        "correlation_key",
        "idempotency_key",
        "version",
        "created_at",
        "updated_at",
        "closed_at",
    } <= _columns(url, "forensic_cases")
    assert {
        "sequence",
        "event_type",
        "previous_hash",
        "event_hash",
        "actor_id",
        "actor_role",
    } <= _columns(url, "forensic_custody_events")
    assert {"sha256", "manifest_digest", "root_digest", "evidence_bytes_included"} <= _columns(
        url, "forensic_exports"
    )

    inspector = inspect(create_engine(url))
    case_indexes = _indexes(url, "forensic_cases")
    assert case_indexes["ix_forensic_cases_case_number"].get("unique")
    correlation_uniques = {str(c["name"]) for c in inspector.get_unique_constraints("forensic_correlations")}
    assert "uq_forensic_correlation_case_finding" in correlation_uniques
    correlation_indexes = _indexes(url, "forensic_correlations")
    # A correlation key groups repeated findings in one case, so the index
    # must stay non-unique; individual findings remain unique.
    assert not correlation_indexes["ix_forensic_correlations_correlation_key"].get("unique")
    assert correlation_indexes["ix_forensic_correlations_finding_id"].get("unique")
    export_indexes = _indexes(url, "forensic_exports")
    assert export_indexes["ix_forensic_exports_storage_relative_path"].get("unique")

    # V34 reverses alone: only forensic tables disappear.
    command.downgrade(config, "-1")
    remaining = _tables(url)
    assert _FORENSIC_TABLES.isdisjoint(remaining)
    assert _PRIOR_TABLES <= remaining

    command.upgrade(config, "head")
    assert _FORENSIC_TABLES <= _tables(url)
