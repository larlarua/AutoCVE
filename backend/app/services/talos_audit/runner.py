from __future__ import annotations

import asyncio
import contextlib
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


async def _watch_talos_audit_cancellation(job_id: str, audit_task: asyncio.Task[object]) -> None:
    """Cancel local audit execution after the API persists a cancellation request."""
    while not audit_task.done():
        await asyncio.sleep(1)
        async with AsyncSessionLocal() as cancellation_db:
            job = await cancellation_db.get(TalosAuditJob, job_id)
            if job is not None and job.status == TalosAuditJobStatus.CANCELLED:
                audit_task.cancel()
                return


async def _mark_talos_audit_cancelled(*, db, job_id: str, project_id: str) -> None:
    job = await db.get(TalosAuditJob, job_id)
    project = await db.get(Project, project_id)
    if job is not None:
        job.status = TalosAuditJobStatus.CANCELLED
        job.error_message = "Talos audit cancelled by request"
        job.completed_at = datetime.now(timezone.utc)
    if project is not None:
        project.workspace_mode = "audit_cancelled"
    await db.commit()


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
        if job.status in {TalosAuditJobStatus.COMPLETED, TalosAuditJobStatus.CANCELLED}:
            return

        project = await db.get(Project, job.project_id)
        service_user = await db.get(User, job.service_user_id)
        if project is None or service_user is None or not service_user.is_active or not service_user.is_superuser:
            job.status = TalosAuditJobStatus.FAILED
            job.error_message = "Talos project or service user is unavailable"
            job.completed_at = datetime.now(timezone.utc)
            await db.commit()
            return

        project_id = str(project.id)

        job.status = TalosAuditJobStatus.RUNNING
        job.error_message = None
        job.attempts = int(job.attempts or 0) + 1
        job.started_at = job.started_at or datetime.now(timezone.utc)
        project.workspace_mode = "audit_running"
        await db.commit()

        audit_task = asyncio.create_task(
            start_direct_audit_session(
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
        )
        cancel_watch_task = asyncio.create_task(_watch_talos_audit_cancellation(job_id, audit_task))
        try:
            session = await audit_task
            final_payload = _extract_direct_audit_final_payload(
                await _load_direct_audit_messages(session_id=session.id, db=db)
            )
            if final_payload is None:
                raise RuntimeError("Audit completed without a FinalizeFinding payload")
        except asyncio.CancelledError:
            await db.rollback()
            await _mark_talos_audit_cancelled(db=db, job_id=job_id, project_id=project_id)
            logger.info("Talos audit job %s cancelled", job_id)
            return
        except Exception as exc:
            await db.rollback()
            failed_job = await db.get(TalosAuditJob, job_id)
            failed_project = await db.get(Project, project_id)
            if failed_job is not None:
                failed_job.status = TalosAuditJobStatus.FAILED
                failed_job.error_message = str(exc)
                failed_job.completed_at = datetime.now(timezone.utc)
            if failed_project is not None:
                failed_project.workspace_mode = "audit_failed"
            await db.commit()
            logger.exception("Talos audit job %s failed", job_id)
            raise
        finally:
            cancel_watch_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cancel_watch_task

        completed_job = await db.get(TalosAuditJob, job_id)
        completed_project = await db.get(Project, project_id)
        if completed_job is None:
            logger.warning("Talos audit job %s disappeared before completion", job_id)
            return
        await db.refresh(completed_job)
        if completed_job.status == TalosAuditJobStatus.CANCELLED:
            return
        completed_job.status = TalosAuditJobStatus.COMPLETED
        completed_job.audit_session_id = session.id
        completed_job.finalize_finding = final_payload
        completed_job.error_message = None
        completed_job.completed_at = datetime.now(timezone.utc)
        if completed_project is not None:
            completed_project.workspace_mode = "audit_completed"
        await db.commit()
