"""Create authentication and RBAC tables (V16).

Users, server-side sessions (digest-only), single-use WebSocket
tickets, bounded login-attempt throttle records, and sanitized auth
audit. Additive only; no existing tables touched.

Secrets live in digests only: password hashes, session-token digests,
CSRF digests, ticket digests. Raw tokens and plaintext passwords are
never persisted.

Revision ID: 009_create_auth
Revises: 008_create_alerting
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "009_create_auth"
down_revision = "008_create_alerting"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("password_hash", sa.String(512), nullable=False),
        sa.Column("role", sa.String(16), nullable=False, server_default="VIEWER"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("must_change_password", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_role", "users", ["role"])
    op.create_index("ix_users_is_active", "users", ["is_active"])

    op.create_table(
        "user_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_digest", sa.String(64), nullable=False),
        sa.Column("csrf_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("token_digest", name="uq_session_token_digest"),
    )
    op.create_index("ix_user_sessions_user_id", "user_sessions", ["user_id"])
    op.create_index("ix_user_sessions_expires_at", "user_sessions", ["expires_at"])

    op.create_table(
        "ws_tickets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "session_id",
            sa.String(36),
            sa.ForeignKey("user_sessions.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("scope", sa.String(128), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("digest", name="uq_ws_ticket_digest"),
    )
    op.create_index("ix_ws_tickets_user_id", "ws_tickets", ["user_id"])
    op.create_index("ix_ws_tickets_session_id", "ws_tickets", ["session_id"])
    op.create_index("ix_ws_tickets_scope", "ws_tickets", ["scope"])
    op.create_index("ix_ws_tickets_expires_at", "ws_tickets", ["expires_at"])

    op.create_table(
        "login_attempts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("email_normalized", sa.String(320), nullable=False),
        sa.Column("ip_hash", sa.String(64), nullable=False),
        sa.Column("succeeded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("attempted_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_login_attempts_email", "login_attempts", ["email_normalized"])
    op.create_index("ix_login_attempts_ip", "login_attempts", ["ip_hash"])
    op.create_index("ix_login_attempts_at", "login_attempts", ["attempted_at"])

    op.create_table(
        "auth_audit",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor_user_id", sa.String(36), nullable=True),
        sa.Column("target_user_id", sa.String(36), nullable=True),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("detail", sa.String(1024), nullable=False, server_default=""),
        sa.Column("metadata", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_auth_audit_actor", "auth_audit", ["actor_user_id"])
    op.create_index("ix_auth_audit_target", "auth_audit", ["target_user_id"])
    op.create_index("ix_auth_audit_action", "auth_audit", ["action"])
    op.create_index("ix_auth_audit_created_at", "auth_audit", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_auth_audit_created_at", table_name="auth_audit")
    op.drop_index("ix_auth_audit_action", table_name="auth_audit")
    op.drop_index("ix_auth_audit_target", table_name="auth_audit")
    op.drop_index("ix_auth_audit_actor", table_name="auth_audit")
    op.drop_table("auth_audit")

    op.drop_index("ix_login_attempts_at", table_name="login_attempts")
    op.drop_index("ix_login_attempts_ip", table_name="login_attempts")
    op.drop_index("ix_login_attempts_email", table_name="login_attempts")
    op.drop_table("login_attempts")

    op.drop_index("ix_ws_tickets_expires_at", table_name="ws_tickets")
    op.drop_index("ix_ws_tickets_scope", table_name="ws_tickets")
    op.drop_index("ix_ws_tickets_session_id", table_name="ws_tickets")
    op.drop_index("ix_ws_tickets_user_id", table_name="ws_tickets")
    op.drop_table("ws_tickets")

    op.drop_index("ix_user_sessions_expires_at", table_name="user_sessions")
    op.drop_index("ix_user_sessions_user_id", table_name="user_sessions")
    op.drop_table("user_sessions")

    op.drop_index("ix_users_is_active", table_name="users")
    op.drop_index("ix_users_role", table_name="users")
    op.drop_table("users")
