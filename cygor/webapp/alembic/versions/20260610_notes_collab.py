"""Notes collaboration: many-to-many host links + author/pin/archive columns

Adds the note_host_link association table (a note can reference many hosts and a
host can be referenced by many notes) and collaboration/discoverability columns
on note (author, last_edited_by, pinned, archived). Existing note.host_id values
are backfilled into note_host_link at startup by db._migrate_note_table().

Revision ID: 0012_notes_collab
Revises: 0011_notes_table
Create Date: 2026-06-10
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0012_notes_collab"
down_revision: Union[str, None] = "0011_notes_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if "note" in set(insp.get_table_names()):
        existing = {c["name"] for c in insp.get_columns("note")}
        if "author" not in existing:
            op.add_column("note", sa.Column("author", sa.String(length=100), nullable=True))
            op.create_index("ix_note_author", "note", ["author"])
        if "last_edited_by" not in existing:
            op.add_column("note", sa.Column("last_edited_by", sa.String(length=100), nullable=True))
        if "pinned" not in existing:
            op.add_column("note", sa.Column("pinned", sa.Boolean(), nullable=False, server_default=sa.false()))
            op.create_index("ix_note_pinned", "note", ["pinned"])
        if "archived" not in existing:
            op.add_column("note", sa.Column("archived", sa.Boolean(), nullable=False, server_default=sa.false()))
            op.create_index("ix_note_archived", "note", ["archived"])

    if "note_host_link" not in set(insp.get_table_names()):
        op.create_table(
            "note_host_link",
            sa.Column("note_id", sa.Integer(), sa.ForeignKey("note.id"), primary_key=True),
            sa.Column("host_id", sa.Integer(), sa.ForeignKey("host.id"), primary_key=True),
        )
        op.create_index("ix_note_host_link_host_id", "note_host_link", ["host_id"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if "note_host_link" in set(insp.get_table_names()):
        op.drop_index("ix_note_host_link_host_id", table_name="note_host_link")
        op.drop_table("note_host_link")

    if "note" in set(insp.get_table_names()):
        existing = {c["name"] for c in insp.get_columns("note")}
        if "archived" in existing:
            op.drop_index("ix_note_archived", table_name="note")
            op.drop_column("note", "archived")
        if "pinned" in existing:
            op.drop_index("ix_note_pinned", table_name="note")
            op.drop_column("note", "pinned")
        if "last_edited_by" in existing:
            op.drop_column("note", "last_edited_by")
        if "author" in existing:
            op.drop_index("ix_note_author", table_name="note")
            op.drop_column("note", "author")
