"""add deep_scan job kind and monthly_deep_scan_quota

Revision ID: 0002_deep_scan
Revises: 0001_initial
Create Date: 2026-05-24 00:02:00
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002_deep_scan"
down_revision: Union[str, None] = "0001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add 'deep_scan' value to the jobkind enum type
    op.execute("ALTER TYPE jobkind ADD VALUE IF NOT EXISTS 'deep_scan'")

    # Add monthly_deep_scan_quota column to subscriptions table
    op.add_column(
        "subscriptions",
        sa.Column("monthly_deep_scan_quota", sa.Integer(), nullable=False, server_default="0"),
    )


def downgrade() -> None:
    op.drop_column("subscriptions", "monthly_deep_scan_quota")

    # Note: PostgreSQL does not support removing values from enum types directly.
    # The 'deep_scan' value will remain in the jobkind enum on downgrade.
