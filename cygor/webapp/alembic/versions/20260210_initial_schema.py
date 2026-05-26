"""Baseline: stamp existing schema

Revision ID: 0001_baseline
Revises: None
Create Date: 2026-02-10

This is a baseline migration. All tables already exist via
SQLModel.metadata.create_all() and the manual _migrate_*() helpers
in db.py. Running `alembic stamp head` marks the DB as up-to-date
without executing any DDL.
"""
from typing import Sequence, Union


# revision identifiers, used by Alembic.
revision: str = "0001_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Baseline — tables already exist.
    pass


def downgrade() -> None:
    # Cannot downgrade past baseline.
    pass
