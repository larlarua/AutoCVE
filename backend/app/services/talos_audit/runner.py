from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.api.v1.endpoints.agent_direct_audit import (
    _extract_direct_audit_final_payload,
    _load_direct_audit_messages,
    start_direct_audit_session,
)
from app.db.session import AsyncSessionLocal
from app.models.project import Project
from app.models.talos_audit import TalosAuditJob, TalosAuditJobStatus
from app.models.user import User

logger = logging.getLogger(__name__)


async def run_talos_audit_job(job_id: str) -> None:
    """Execute a persisted Talos job through the shared agent worker.

    ``generate_reports=False`` is intentional: Talos consumes only the
    FinalizeFinding payload and never starts the report-generation ReAct loop.
    """
    async with AsyncSessionLocal() as db:
        job = await db.get(TalosAuditJob, job_id)
        if job is None:
            logger.warning("Talos audit job %s no longer exists", job_id)
            return
        if job.status == TalosAuditJobStatus.COMPLETED:
            return

        project = await db.get(Project, job.project_id)
        service_user = await db.get(User, job.service_user_id)
        if project is None or service_user is None or not service_user.is_active or not service_user.is_superuser:
            job.status = TalosAuditJobStatus.FAILED
            job.error_message = "Talos project or service user is unavailable"
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return

        job.status = TalosAuditJobStatus.RUNNING
        job.error_message = None
        job.attempts = int(job.attempts or 0) + 1
        job.started_at = job.started_at or datetime.now(timezone.utc)
        project.workspace_mode = "audit_running"
        await db.commit()

        try:
            session = await start_direct_audit_session(
                project=project,
                content=(
                    "Perform the requested source-code security audit. Start from the supplied recon context, "
                    "then complete the Finding phase and call FinalizeFinding with the structured final result. "
                    "Do not generate vulnerability reports."
                ),
                guardrails_enabled=False,
                db=db,
                current_user=service_user,
                generate_reports=False,
            )
            final_payload = _extract_direct_audit_final_payload(
                await _load_direct_audit_messages(session_id=session.id, db=db)
            )
            if final_payload is None:
                raise RuntimeError("Audit completed without a FinalizeFinding payload")
        except Exception as exc:
            await db.rollback()
            failed_job = await db.get(TalosAuditJob, job_id)
            failed_project = await db.get(Project, project.id)
            if failed_job is not None:
                failed_job.status = TalosAuditJobStatus.FAILED
                failed_job.error_message = str(exc)
                failed_job.completed_at = datetime.now(timezone.utc)
            if failed_project is not None:
                failed_project.workspace_mode = "audit_failed"
            await db.commit()
            logger.exception("Talos audit job %s failed", job_id)
            raise

        completed_job = await db.get(TalosAuditJob, job_id)
        completed_project = await db.get(Project, project.id)
        if completed_job is None:
            logger.warning("Talos audit job %s disappeared before completion", job_id)
            return
        completed_job.status = TalosAuditJobStatus.COMPLETED
        completed_job.audit_session_id = session.id
        completed_job.finalize_finding = final_payload
        completed_job.error_message = None
        completed_job.completed_at = datetime.now(timezone.utc)
        if completed_project is not None:
            completed_project.workspace_mode = "audit_completed"
        await db.commit()
