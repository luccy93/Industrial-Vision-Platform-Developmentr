"""Add operator notification mute window (V16).

Time-limited per-notification delivery mute for operators. Detection,
history, and analytics are untouched — only channel delivery pauses
until ``muted_until`` passes. Additive single column.

Revision ID: 010_add_notification_mute
Revises: 009_create_auth
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "010_add_notification_mute"
down_revision = "009_create_auth"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "notifications",
        sa.Column("muted_until", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("notifications", "muted_until")
