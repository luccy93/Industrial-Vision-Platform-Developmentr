"""V16 auth migrations — upgrade/downgrade cycle from the V15 head."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

_REPO_ROOT = Path(__file__).resolve().parents[3]

_AUTH_TABLES = {"users", "user_sessions", "ws_tickets", "login_attempts", "auth_audit"}


def _tables(url: str) -> set[str]:
    return set(inspect(create_engine(url)).get_table_names())


def _columns(url: str, table: str) -> set[str]:
    return {str(c["name"]) for c in inspect(create_engine(url)).get_columns(table)}


def test_auth_migration_upgrade_and_downgrade_cycle(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    url = f"sqlite:///{tmp_path}/migrate.db"
    monkeypatch.setenv("DATABASE_URL", url)
    config = Config(str(_REPO_ROOT / "backend" / "alembic.ini"))
    config.set_main_option("script_location", str(_REPO_ROOT / "backend" / "alembic"))

    command.upgrade(config, "head")
    tables = _tables(url)
    assert _AUTH_TABLES <= tables
    assert "alert_rules" in tables  # V15 tables still present

    assert {
        "id",
        "email",
        "password_hash",
        "role",
        "is_active",
        "must_change_password",
    } <= _columns(url, "users")
    inspector = inspect(create_engine(url))
    uniques = {str(c["name"]) for c in inspector.get_unique_constraints("users")}
    assert "uq_users_email" in uniques
    session_uniques = {str(c["name"]) for c in inspector.get_unique_constraints("user_sessions")}
    assert "uq_session_token_digest" in session_uniques
    ticket_uniques = {str(c["name"]) for c in inspector.get_unique_constraints("ws_tickets")}
    assert "uq_ws_ticket_digest" in ticket_uniques
    assert "muted_until" in _columns(url, "notifications")  # 010

    # V16 (010) reverses first: mute column goes, 009 tables stay.
    command.downgrade(config, "-1")
    assert "muted_until" not in _columns(url, "notifications")
    assert _AUTH_TABLES <= _tables(url)

    # V16 (009) reverses next: auth tables go, alerting stays.
    command.downgrade(config, "-1")
    remaining = _tables(url)
    assert _AUTH_TABLES.isdisjoint(remaining)
    assert "alert_rules" in remaining
    assert "notifications" in remaining

    command.upgrade(config, "head")
    assert _AUTH_TABLES <= _tables(url)
    assert "muted_until" in _columns(url, "notifications")
