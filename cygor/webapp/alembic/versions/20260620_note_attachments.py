"""Add note_attachment table

Binary attachments (pasted / dropped / uploaded images) for notes. The bytes
are stored in the DB as the durable source of truth; a copy is also written to
static/uploads/notes/ for fast serving. `note_id` is nullable because images are
typically uploaded before a new note is first saved.

Revision ID: 0013_note_attachments
Revises: 0012_notes_collab
Create Date: 2026-06-20
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0013_note_attachments"
down_revision: Union[str, None] = "0012_notes_collab"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "note_attachment" in set(insp.get_table_names()):
        return

    op.create_table(
        "note_attachment",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("token", sa.String(length=64), nullable=False),
        sa.Column("note_id", sa.Integer(), sa.ForeignKey("note.id"), nullable=True),
        sa.Column("filename", sa.String(length=255), nullable=True),
        sa.Column("content_type", sa.String(length=100), nullable=False,
                  server_default="application/octet-stream"),
        sa.Column("ext", sa.String(length=12), nullable=False, server_default="bin"),
        sa.Column("size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("created_by", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_note_attachment_token", "note_attachment", ["token"], unique=True)
    op.create_index("ix_note_attachment_note_id", "note_attachment", ["note_id"])
    op.create_index("ix_note_attachment_created_by", "note_attachment", ["created_by"])
    op.create_index("ix_note_attachment_created_at", "note_attachment", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_note_attachment_created_at", table_name="note_attachment")
    op.drop_index("ix_note_attachment_created_by", table_name="note_attachment")
    op.drop_index("ix_note_attachment_note_id", table_name="note_attachment")
    op.drop_index("ix_note_attachment_token", table_name="note_attachment")
    op.drop_table("note_attachment")
