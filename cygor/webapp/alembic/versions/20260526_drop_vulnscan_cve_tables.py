"""Drop vulnerability-scanning and CVE-intelligence tables

The vulnerability-scanning feature and the CVE database / threat-intelligence
feature are no longer part of the OSS build. This migration drops the tables
they owned if they exist, so existing databases are cleaned up. It is guarded
with table-existence checks so it is safe on both SQLite and PostgreSQL.

Tables dropped (in FK-safe order):
- remediation_history (FK -> vulnerability)
- vulnerability
- vuln_scan
- scour_scan_result
- cpe_match (FK -> cve)
- exploit_metadata (FK -> cve)
- validation_rule (FK -> cve)
- epss_score
- cisa_kev
- cve_sync_status
- cve

Revision ID: 0010_drop_vulnscan_cve_tables
Revises: 0009_findings_table
Create Date: 2026-05-26
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0010_drop_vulnscan_cve_tables"
down_revision: Union[str, None] = "0009_findings_table"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Ordered so child/FK-owning tables are dropped before their parents.
_TABLES_TO_DROP = [
    "remediation_history",
    "vulnerability",
    "vuln_scan",
    "scour_scan_result",
    "cpe_match",
    "exploit_metadata",
    "validation_rule",
    "epss_score",
    "cisa_kev",
    "cve_sync_status",
    "cve",
]


def upgrade() -> None:
    bind = op.get_bind()
    insp = sa.inspect(bind)
    existing = set(insp.get_table_names())
    for table in _TABLES_TO_DROP:
        if table in existing:
            op.drop_table(table)


def downgrade() -> None:
    # These tables belong to features that were removed from the OSS build.
    # There is no schema to recreate here; downgrade is intentionally a no-op.
    pass
