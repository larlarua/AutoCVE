from __future__ import annotations

import uuid

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.sql import func

from app.db.base import Base


class TalosAuditJobStatus:
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TalosAuditJob(Base):
    __tablename__ = "talos_audit_jobs"

    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    request_id = Column(String(255), nullable=False, unique=True, index=True)
    project_id = Column(String(36), ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True)
    service_user_id = Column(String(36), ForeignKey("users.id"), nullable=False, index=True)
    audit_session_id = Column(String(36), ForeignKey("audit_sessions.id", ondelete="SET NULL"), nullable=True, index=True)
    status = Column(String(32), nullable=False, default=TalosAuditJobStatus.QUEUED, index=True)
    finalize_finding = Column(JSON, nullable=True)
    error_message = Column(Text, nullable=True)
    attempts = Column(Integer, nullable=False, default=0)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), nullable=True)
