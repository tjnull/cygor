"""Add note table

User-authored markdown notes. A note is global by default; setting host_id
attaches it to a host (e.g. notes created from a host detail page). Content is
stored as raw markdown and rendered (sanitized) at display time.

Revision ID: 0011_notes_table
Revises: 0010_drop_vulnscan_cve_tables
Create Date: 2026-06-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0011_notes_table"
down_revision: Union[str, None] = "0010_drop_vulnscan_cve_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "note" in set(insp.get_table_names()):
        return

    op.create_table(
        "note",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("host.id"), nullable=True),
        sa.Column("title", sa.String(length=200), nullable=False, server_default="Untitled"),
        sa.Column("content", sa.Text(), nullable=False, server_default=""),
        sa.Column("tags", sa.String(), nullable=True),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_note_host_id", "note", ["host_id"])
    op.create_index("ix_note_title", "note", ["title"])
    op.create_index("ix_note_created_by", "note", ["created_by"])
    op.create_index("ix_note_created_at", "note", ["created_at"])
    op.create_index("ix_note_updated_at", "note", ["updated_at"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "note" not in set(insp.get_table_names()):
        return
    for ix in ("ix_note_updated_at", "ix_note_created_at", "ix_note_created_by",
               "ix_note_title", "ix_note_host_id"):
        op.drop_index(ix, table_name="note")
    op.drop_table("note")
