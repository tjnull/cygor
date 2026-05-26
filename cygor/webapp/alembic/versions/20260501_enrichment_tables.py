"""Add enrichment_run and enrichment_finding tables

Substrate for the External Visibility / enrichment dashboard. The two
tables index what cygor enrich has gathered from external sources for
the assets in scope; the JSON output file on disk remains the source
of truth.

Revision ID: 0008_enrichment_tables
Revises: 0004_vulnerability_intelligence
Create Date: 2026-05-01
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0008_enrichment_tables"
down_revision: Union[str, None] = "0004_vulnerability_intelligence"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = set(insp.get_table_names())

    if "enrichment_run" not in existing:
        op.create_table(
            "enrichment_run",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("task_id", sa.String(length=100), nullable=True),
            sa.Column("started_at", sa.DateTime(), nullable=False),
            sa.Column("completed_at", sa.DateTime(), nullable=True),
            sa.Column("output_path", sa.String(length=500), nullable=False),
            sa.Column("sources", sa.JSON(), nullable=True),
            sa.Column("ioc_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("finding_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("notes", sa.Text(), nullable=True),
        )
        op.create_index("ix_enrichment_run_task_id", "enrichment_run", ["task_id"])
        op.create_index("ix_enrichment_run_started_at", "enrichment_run", ["started_at"])
        op.create_index("ix_enrichment_run_completed_at", "enrichment_run", ["completed_at"])

    if "enrichment_finding" not in existing:
        op.create_table(
            "enrichment_finding",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("run_id", sa.Integer(), sa.ForeignKey("enrichment_run.id"), nullable=False),
            sa.Column("ioc_value", sa.String(length=500), nullable=False),
            sa.Column("ioc_type", sa.String(length=20), nullable=False),
            sa.Column("source", sa.String(length=40), nullable=False),
            sa.Column("finding_kind", sa.String(length=40), nullable=False, server_default="observation"),
            sa.Column("summary", sa.Text(), nullable=True),
            sa.Column("signals", sa.JSON(), nullable=True),
            sa.Column("raw", sa.JSON(), nullable=True),
            sa.Column("host_id", sa.Integer(), sa.ForeignKey("host.id"), nullable=True),
            sa.Column("enriched_at", sa.DateTime(), nullable=False),
        )
        op.create_index("ix_enrichment_finding_run_id", "enrichment_finding", ["run_id"])
        op.create_index("ix_enrichment_finding_ioc_value", "enrichment_finding", ["ioc_value"])
        op.create_index("ix_enrichment_finding_ioc_type", "enrichment_finding", ["ioc_type"])
        op.create_index("ix_enrichment_finding_source", "enrichment_finding", ["source"])
        op.create_index("ix_enrichment_finding_finding_kind", "enrichment_finding", ["finding_kind"])
        op.create_index("ix_enrichment_finding_host_id", "enrichment_finding", ["host_id"])
        op.create_index("ix_enrichment_finding_enriched_at", "enrichment_finding", ["enriched_at"])
        op.create_index("ix_enrichment_finding_ioc_source", "enrichment_finding", ["ioc_value", "source"])
        op.create_index("ix_enrichment_finding_run_source", "enrichment_finding", ["run_id", "source"])


def downgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = set(insp.get_table_names())

    if "enrichment_finding" in existing:
        op.drop_index("ix_enrichment_finding_run_source", table_name="enrichment_finding")
        op.drop_index("ix_enrichment_finding_ioc_source", table_name="enrichment_finding")
        op.drop_index("ix_enrichment_finding_enriched_at", table_name="enrichment_finding")
        op.drop_index("ix_enrichment_finding_host_id", table_name="enrichment_finding")
        op.drop_index("ix_enrichment_finding_finding_kind", table_name="enrichment_finding")
        op.drop_index("ix_enrichment_finding_source", table_name="enrichment_finding")
        op.drop_index("ix_enrichment_finding_ioc_type", table_name="enrichment_finding")
        op.drop_index("ix_enrichment_finding_ioc_value", table_name="enrichment_finding")
        op.drop_index("ix_enrichment_finding_run_id", table_name="enrichment_finding")
        op.drop_table("enrichment_finding")

    if "enrichment_run" in existing:
        op.drop_index("ix_enrichment_run_completed_at", table_name="enrichment_run")
        op.drop_index("ix_enrichment_run_started_at", table_name="enrichment_run")
        op.drop_index("ix_enrichment_run_task_id", table_name="enrichment_run")
        op.drop_table("enrichment_run")
