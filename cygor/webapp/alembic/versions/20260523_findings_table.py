"""Add finding table

Queryable index of high-signal observations the Next-Steps engine derives from
enumeration module output (unauthenticated database, anonymous SMB share, DNS
AXFR, ...). The per-module cygor-result.json files remain the source of truth;
this table powers per-host next steps and cross-host triage.

Revision ID: 0009_findings_table
Revises: 0008_enrichment_tables
Create Date: 2026-05-23
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0009_findings_table"
down_revision: Union[str, None] = "0008_enrichment_tables"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "finding" in set(insp.get_table_names()):
        return

    op.create_table(
        "finding",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("host.id"), nullable=True),
        sa.Column("target_host", sa.String(), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("service", sa.String(), nullable=True),
        sa.Column("module", sa.String(), nullable=True),
        sa.Column("finding_type", sa.String(), nullable=False),
        sa.Column("severity", sa.String(), nullable=False, server_default="info"),
        sa.Column("title", sa.String(), nullable=False, server_default=""),
        sa.Column("evidence", sa.Text(), nullable=True),
        sa.Column("command", sa.Text(), nullable=True),
        sa.Column("detected_at", sa.DateTime(), nullable=False),
    )
    op.create_index("ix_finding_host_id", "finding", ["host_id"])
    op.create_index("ix_finding_target_host", "finding", ["target_host"])
    op.create_index("ix_finding_port", "finding", ["port"])
    op.create_index("ix_finding_service", "finding", ["service"])
    op.create_index("ix_finding_module", "finding", ["module"])
    op.create_index("ix_finding_finding_type", "finding", ["finding_type"])
    op.create_index("ix_finding_severity", "finding", ["severity"])
    op.create_index("ix_finding_detected_at", "finding", ["detected_at"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    if "finding" not in set(insp.get_table_names()):
        return
    for ix in ("ix_finding_detected_at", "ix_finding_severity", "ix_finding_finding_type",
               "ix_finding_module", "ix_finding_service", "ix_finding_port",
               "ix_finding_target_host", "ix_finding_host_id"):
        op.drop_index(ix, table_name="finding")
    op.drop_table("finding")
