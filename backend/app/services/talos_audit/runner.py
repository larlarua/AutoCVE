from __future__ import annotations

import asyncio
import contextlib
import logging
from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.agent_task import AgentTask, AgentTaskPhase, AgentTaskStatus
from app.models.audit_session import AuditSession, AuditToolCall
from app.models.project import Project
from app.models.talos_audit import TalosAuditJob, TalosAuditJobStatus
from app.models.user import User
from app.services.agent.task_executor import execute_agent_task, request_agent_task_cancellation
from app.services.finding_runtime.config import FindingRuntimeStack

logger = logging.getLogger(__name__)


def _build_talos_agent_task(*, job: TalosAuditJob, project: Project, service_user: User) -> AgentTask:
    """Create the same persisted task used by the normal intelligent-audit flow."""
    return AgentTask(
        id=str(uuid4()),
        project_id=project.id,
        name=f"Talos audit - {job.request_id}",
        description="Internal Talos source archive audit.",
        status=AgentTaskStatus.PENDING,
        current_phase=AgentTaskPhase.PLANNING,
        task_type="agent_audit",
        version_label=project.default_branch or "source-archive",
        branch_name=project.default_branch,
        repository_url_snapshot=project.repository_url,
        verification_level="sandbox",
        exclude_patterns=["node_modules", "__pycache__", ".git", "*.min.js", "dist", "build", "vendor"],
        max_iterations=settings.AGENT_MAX_ITERATIONS,
        timeout_seconds=1800,
        agent_config={
            "finding_runtime_stack": FindingRuntimeStack.RUNTIME.value,
            "skip_report_generation": True,
            "talos_audit_job_id": job.id,
        },
        audit_scope={"talos": {"request_id": job.request_id}},
        created_by=service_user.id,
    )


async def _watch_talos_audit_cancellation(
    job_id: str,
    agent_task_id: str,
    audit_task: asyncio.Task[object],
) -> None:
    """Cancel the normal agent task after Talos persists a cancellation request."""
    while not audit_task.done():
        await asyncio.sleep(1)
        async with AsyncSessionLocal() as cancellation_db:
            job = await cancellation_db.get(TalosAuditJob, job_id)
            if job is not None and job.status == TalosAuditJobStatus.CANCELLED:
                request_agent_task_cancellation(agent_task_id)
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


async def _load_talos_finalize_finding(*, db, task_id: str) -> tuple[AuditSession | None, dict | None]:
    session_result = await db.execute(
        select(AuditSession)
        .where(AuditSession.task_id == task_id)
        .order_by(AuditSession.created_at.desc())
        .limit(1)
    )
    session = session_result.scalars().first()
    if session is None:
        return None, None
    tool_result = await db.execute(
        select(AuditToolCall)
        .where(
            AuditToolCall.session_id == session.id,
            AuditToolCall.tool_name == "FinalizeFinding",
            AuditToolCall.status == "completed",
        )
        .order_by(AuditToolCall.sequence.desc())
        .limit(1)
    )
    tool_call = tool_result.scalars().first()
    payload = dict(tool_call.output_payload or {}).get("final_payload") if tool_call is not None else None
    return session, payload if isinstance(payload, dict) else None


async def run_talos_audit_job(job_id: str) -> None:
    """Run Talos through the normal intelligent-audit task pipeline.

    The task uses the production Finding ReAct workflow.  Its report-generation
    post-processing is explicitly disabled, so a successful FinalizeFinding ends
    the Talos audit without starting the FinalReport loop.
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

        task = await db.get(AgentTask, job.agent_task_id) if job.agent_task_id else None
        if task is None:
            task = _build_talos_agent_task(job=job, project=project, service_user=service_user)
            db.add(task)
            await db.flush()
            job.agent_task_id = task.id

        project_id = str(project.id)
        job.status = TalosAuditJobStatus.RUNNING
        job.error_message = None
        job.attempts = int(job.attempts or 0) + 1
        job.started_at = job.started_at or datetime.now(timezone.utc)
        project.workspace_mode = "audit_running"
        await db.commit()

        audit_task = asyncio.create_task(execute_agent_task(str(task.id)))
        cancel_watch_task = asyncio.create_task(
            _watch_talos_audit_cancellation(job_id, str(task.id), audit_task)
        )
        try:
            await audit_task
            await db.refresh(task)
            session, final_payload = await _load_talos_finalize_finding(db=db, task_id=str(task.id))
            if session is not None:
                job.audit_session_id = session.id
            if task.status != AgentTaskStatus.COMPLETED:
                raise RuntimeError(task.error_message or "Normal intelligent audit did not complete")
            if final_payload is None:
                raise RuntimeError("Normal intelligent audit completed without a FinalizeFinding payload")
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
        if completed_job is None or completed_job.status == TalosAuditJobStatus.CANCELLED:
            return
        completed_job.status = TalosAuditJobStatus.COMPLETED
        completed_job.audit_session_id = session.id
        completed_job.finalize_finding = final_payload
        completed_job.error_message = None
        completed_job.completed_at = datetime.now(timezone.utc)
        if completed_project is not None:
            completed_project.workspace_mode = "audit_completed"
        await db.commit()
