"""link Talos audit jobs to normal agent tasks

Revision ID: 20260723_01
Revises: 20260722_01
Create Date: 2026-07-23 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260723_01"
down_revision = "20260722_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("talos_audit_jobs", sa.Column("agent_task_id", sa.String(length=36), nullable=True))
    op.create_foreign_key(
        "fk_talos_audit_jobs_agent_task_id",
        "talos_audit_jobs",
        "agent_tasks",
        ["agent_task_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_talos_audit_jobs_agent_task_id", "talos_audit_jobs", ["agent_task_id"])


def downgrade() -> None:
    op.drop_index("ix_talos_audit_jobs_agent_task_id", table_name="talos_audit_jobs")
    op.drop_constraint("fk_talos_audit_jobs_agent_task_id", "talos_audit_jobs", type_="foreignkey")
    op.drop_column("talos_audit_jobs", "agent_task_id")
