"""Add scheduler resilience fields: retry, misfire, watchdog

Revision ID: 0003_scheduler_resilience
Revises: 0001_baseline
Create Date: 2026-03-23

Adds columns for:
- Retry configuration on ScheduledTask
- Retry tracking on ScheduledTaskHistory
- Watchdog support on RunningTaskRecord
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "0003_scheduler_resilience"
down_revision: Union[str, None] = "0001_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ScheduledTask: retry config
    op.add_column("scheduled_task", sa.Column("max_retries", sa.Integer, nullable=False, server_default="3"))
    op.add_column("scheduled_task", sa.Column("retry_delay_seconds", sa.Integer, nullable=False, server_default="300"))
    op.add_column("scheduled_task", sa.Column("retry_backoff", sa.Boolean, nullable=False, server_default="1"))
    op.add_column("scheduled_task", sa.Column("misfire_grace_time", sa.Integer, nullable=True))
    op.add_column("scheduled_task", sa.Column("stall_timeout_seconds", sa.Integer, nullable=True))

    # ScheduledTaskHistory: retry tracking
    op.add_column("scheduled_task_history", sa.Column("retry_attempt", sa.Integer, nullable=False, server_default="0"))
    op.add_column("scheduled_task_history", sa.Column("retry_of_history_id", sa.Integer, nullable=True))

    # RunningTaskRecord: watchdog
    op.add_column("running_task_record", sa.Column("last_output_at", sa.DateTime, nullable=True))


def downgrade() -> None:
    op.drop_column("running_task_record", "last_output_at")
    op.drop_column("scheduled_task_history", "retry_of_history_id")
    op.drop_column("scheduled_task_history", "retry_attempt")
    op.drop_column("scheduled_task", "stall_timeout_seconds")
    op.drop_column("scheduled_task", "misfire_grace_time")
    op.drop_column("scheduled_task", "retry_backoff")
    op.drop_column("scheduled_task", "retry_delay_seconds")
    op.drop_column("scheduled_task", "max_retries")
