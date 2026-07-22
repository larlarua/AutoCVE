"""add persisted Talos audit jobs

Revision ID: 20260722_01
Revises: 20260711_01
Create Date: 2026-07-22 00:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260722_01"
down_revision = "20260711_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "talos_audit_jobs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("request_id", sa.String(length=255), nullable=False),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("service_user_id", sa.String(length=36), nullable=False),
        sa.Column("audit_session_id", sa.String(length=36), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="queued"),
        sa.Column("finalize_finding", sa.JSON(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["audit_session_id"], ["audit_sessions.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["service_user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("request_id"),
    )
    op.create_index("ix_talos_audit_jobs_audit_session_id", "talos_audit_jobs", ["audit_session_id"])
    op.create_index("ix_talos_audit_jobs_project_id", "talos_audit_jobs", ["project_id"])
    op.create_index("ix_talos_audit_jobs_service_user_id", "talos_audit_jobs", ["service_user_id"])
    op.create_index("ix_talos_audit_jobs_status", "talos_audit_jobs", ["status"])


def downgrade() -> None:
    op.drop_index("ix_talos_audit_jobs_status", table_name="talos_audit_jobs")
    op.drop_index("ix_talos_audit_jobs_service_user_id", table_name="talos_audit_jobs")
    op.drop_index("ix_talos_audit_jobs_project_id", table_name="talos_audit_jobs")
    op.drop_index("ix_talos_audit_jobs_audit_session_id", table_name="talos_audit_jobs")
    op.drop_table("talos_audit_jobs")
