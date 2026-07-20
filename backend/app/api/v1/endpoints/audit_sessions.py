from __future__ import annotations

import asyncio
import copy
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api import deps
from app.core.config import settings
from app.core.encryption import decrypt_sensitive_data
from app.db.session import get_db
from app.models.agent_task import AgentFinding, AgentTask, FindingStatus
from app.models.audit_session import (
    AuditHandoff,
    AuditCheckpoint,
    AuditCheckpointType,
    AuditMemory,
    AuditModelStreamAttempt,
    AuditSession,
    AuditSessionMessage,
    AuditSessionTurn,
    AuditSkill,
    AuditSkillInvocation,
    AuditToolCall,
)
from app.models.managed_vulnerability import ManagedVulnerability
from app.models.one_click_cve import (
    OneClickCveBatch,
    OneClickCveBatchProject,
    OneClickCveBatchStatus,
    OneClickCveProjectStatus,
)
from app.models.project import Project
from app.schemas.managed_vulnerability import ManagedVulnerabilityDetailResponse
from app.models.user import User
from app.services.agent.tools.sandbox_tool import SandboxManager
from app.services.audit_chat_runtime.bridge import AuditChatRuntimeBridge
from app.services.finding_runtime.bridge import FindingRuntimeBridge
from app.services.finding_runtime.models import RuntimeStopReason
from app.services.llm.service import LLMService
from app.services.runtime_core.runtime_guardrails import is_guardrails_enabled
from app.services.finding_runtime.resume_queue import enqueue_audit_session_resume

router = APIRouter()


class AuditSessionResponse(BaseModel):
    id: str
    project_id: str
    task_id: Optional[str] = None
    runtime_stack: str
    state: str
    system_prompt: Optional[str] = None
    recon_payload: Optional[dict[str, Any]] = None
    guardrails_enabled: bool = False
    created_at: datetime
    updated_at: datetime
    can_resume: bool = False
    last_error_kind: Optional[str] = None
    resume_status: Optional[str] = None

    model_config = {"from_attributes": True}


class AuditSessionMessageResponse(BaseModel):
    id: str
    session_id: str
    sequence: int
    role: str
    content: str
    name: Optional[str] = None
    metadata: dict[str, Any]
    payload: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditSessionMessageMutationResponse(AuditSessionMessageResponse):
    mode: str = "chat"
    synced_managed_vulnerability: ManagedVulnerabilityDetailResponse | None = None


class AuditSessionToolCallResponse(BaseModel):
    id: str
    session_id: str
    turn_id: str
    sequence: int
    tool_use_id: str
    tool_name: str
    status: str
    is_concurrency_safe: bool
    input_payload: dict[str, Any]
    output_payload: dict[str, Any]
    error_message: Optional[str] = None
    duration_ms: Optional[int] = None
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AuditModelStreamAttemptResponse(BaseModel):
    id: str
    session_id: str
    turn_id: str
    attempt_number: int
    status: str
    error_kind: Optional[str] = None
    error_message: Optional[str] = None
    provider_request_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class AuditSessionSkillResponse(BaseModel):
    id: str
    session_id: str
    skill_ref: str
    name: str
    description: Optional[str] = None
    source_type: Optional[str] = None
    enabled: bool
    matched: bool
    skill_metadata: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditSessionSkillInvocationResponse(BaseModel):
    id: str
    session_id: str
    turn_id: str
    sequence: int
    skill_ref: str
    status: str
    input_payload: dict[str, Any]
    output_payload: dict[str, Any]
    error_message: Optional[str] = None
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditSessionMemoryResponse(BaseModel):
    id: str
    session_id: str
    sequence: int
    memory_kind: str
    title: str
    source_type: str
    source_ref: str
    content: str
    relevance_score: Optional[int] = None
    metadata_json: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditSessionHandoffResponse(BaseModel):
    id: str
    session_id: str
    target: str
    status: str
    payload: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class AuditSessionMessageCreate(BaseModel):
    content: str
    mode: str = "chat"
    selected_skill_refs: list[str] = []


class AuditSessionResumeResponse(BaseModel):
    session_id: str
    status: str
    message: str


def _format_sse_event(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


_AUDIT_CHAT_SUCCESS_STOP_REASONS = {
    RuntimeStopReason.COMPLETED.value,
    RuntimeStopReason.HOOK_STOPPED.value,
}

_AUDIT_CHAT_ERROR_MESSAGES = {
    RuntimeStopReason.BLOCKING_LIMIT.value: "当前上下文超过可处理范围，已停止本次继续对话。可以在压缩上下文后恢复。",
    RuntimeStopReason.MAX_TURNS.value: "本次继续对话达到最大执行轮数，已停止。可以从当前检查点恢复。",
    RuntimeStopReason.TOOL_TIMEOUT.value: "工具执行超时，已停止本次继续对话。可以重试或恢复。",
    RuntimeStopReason.ABORTED_STREAMING.value: "继续对话已取消，已保存可恢复检查点。",
    RuntimeStopReason.ABORTED_TOOLS.value: "工具执行已取消，已保存可恢复检查点。",
}


def _runtime_stop_reason_value(runner_result: Any) -> str | None:
    stop_reason = getattr(runner_result, "stop_reason", None)
    if stop_reason is None:
        return None
    return str(getattr(stop_reason, "value", stop_reason))


async def _load_audit_chat_assistant_message(
    *,
    db: AsyncSession,
    session_id: str,
    runner_result: Any,
) -> AuditSessionMessage | None:
    message_id = getattr(runner_result, "assistant_message_id", None)
    if not message_id:
        return None
    message = await db.get(AuditSessionMessage, message_id)
    if message is None or message.session_id != session_id or message.role != "assistant":
        return None
    return message if (message.content or "").strip() else None


async def _load_latest_audit_checkpoint_payload(
    *,
    db: AsyncSession,
    session_id: str,
    turn_id: str | None,
) -> dict[str, Any]:
    statement = select(AuditCheckpoint).where(AuditCheckpoint.session_id == session_id)
    if turn_id:
        statement = statement.where(AuditCheckpoint.turn_id == turn_id)
    checkpoint = (await db.execute(statement.order_by(desc(AuditCheckpoint.created_at), desc(AuditCheckpoint.id)).limit(1))).scalars().first()
    return dict(checkpoint.state_payload or {}) if checkpoint is not None else {}


async def _build_audit_chat_failure(
    *,
    db: AsyncSession,
    session_id: str,
    runner_result: Any | None = None,
    exception: BaseException | None = None,
    missing_presentation: bool = False,
) -> dict[str, Any]:
    turn_id = str(getattr(runner_result, "turn_id", "") or "") or None
    stop_reason = _runtime_stop_reason_value(runner_result)
    source_checkpoint = await _load_latest_audit_checkpoint_payload(
        db=db,
        session_id=session_id,
        turn_id=turn_id,
    )
    phase = str(source_checkpoint.get("phase") or "")

    if missing_presentation:
        error_kind = "empty_assistant_response"
        message = "继续对话未生成可展示的助手回复，已保存可恢复检查点。"
    elif isinstance(exception, asyncio.CancelledError):
        error_kind = "cancelled"
        stop_reason = RuntimeStopReason.ABORTED_STREAMING.value
        message = _AUDIT_CHAT_ERROR_MESSAGES[stop_reason]
    elif stop_reason == RuntimeStopReason.BLOCKING_LIMIT.value:
        error_kind = "blocking_limit"
        message = _AUDIT_CHAT_ERROR_MESSAGES[stop_reason]
    elif stop_reason == RuntimeStopReason.MAX_TURNS.value:
        error_kind = "max_turns"
        message = _AUDIT_CHAT_ERROR_MESSAGES[stop_reason]
    elif stop_reason == RuntimeStopReason.TOOL_TIMEOUT.value:
        error_kind = "tool_timeout"
        message = _AUDIT_CHAT_ERROR_MESSAGES[stop_reason]
    elif stop_reason in {RuntimeStopReason.ABORTED_STREAMING.value, RuntimeStopReason.ABORTED_TOOLS.value}:
        error_kind = "cancelled"
        message = _AUDIT_CHAT_ERROR_MESSAGES[stop_reason]
    elif phase == "tool_execution":
        error_kind = "tool_execution_failed"
        message = str(source_checkpoint.get("error") or "工具执行失败，已停止本次继续对话。可以从当前检查点恢复。")
    elif stop_reason:
        error_kind = stop_reason
        message = str(source_checkpoint.get("error") or _AUDIT_CHAT_ERROR_MESSAGES.get(stop_reason) or "继续对话未能完成，已保存可恢复检查点。")
    elif exception is not None:
        error_kind = "runtime_exception"
        message = str(exception) or "继续对话运行异常，已保存可恢复检查点。"
    else:
        error_kind = "missing_runner_result"
        message = "继续对话未返回可确认的运行结果，已保存可恢复检查点。"

    return {
        "checkpoint_kind": "resumable_failed",
        "resumable": True,
        "phase": "audit_chat_follow_up",
        "error_kind": error_kind,
        "stop_reason": stop_reason,
        "message": message,
        "message_text": message,
        "turn_id": turn_id,
        "source_phase": phase or None,
        "source_checkpoint": source_checkpoint or None,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }


async def _persist_audit_chat_failure(
    *,
    db: AsyncSession,
    session_id: str,
    failure: dict[str, Any],
) -> dict[str, Any]:
    """Persist a resumable terminal failure without hiding the original SSE error."""
    try:
        session = await db.get(AuditSession, session_id)
        if session is None:
            return failure
        await db.refresh(session)
        runtime_state = dict(session.runtime_state_json or {})
        runtime_state["resume_job"] = {
            **dict(runtime_state.get("resume_job") or {}),
            "status": "resumable_failed",
            "error_kind": failure["error_kind"],
            "error": failure["message"],
            "can_resume": True,
            "updated_at": failure["occurred_at"],
        }
        runtime_state["audit_chat_follow_up_failure"] = dict(failure)
        session.runtime_state_json = runtime_state
        session.state = "failed"

        turn_id = failure.get("turn_id")
        if turn_id:
            turn = await db.get(AuditSessionTurn, turn_id)
            if turn is None or turn.session_id != session_id:
                turn_id = None
        db.add(AuditCheckpoint(
            session_id=session_id,
            turn_id=turn_id,
            checkpoint_type=AuditCheckpointType.AUTO.value,
            state_payload=dict(failure),
        ))
        await db.commit()
    except Exception:
        await db.rollback()
        failure = {**failure, "resumable": False, "persistence_error": True}
    return failure


def _chunk_text(content: str, chunk_size: int = 4) -> list[str]:
    text = content or ""
    return [text[index : index + chunk_size] for index in range(0, len(text), chunk_size)] or [""]


def _to_message_response(message: AuditSessionMessage) -> AuditSessionMessageResponse:
    return AuditSessionMessageResponse(
        id=message.id,
        session_id=message.session_id,
        sequence=message.sequence,
        role=message.role,
        content=message.content,
        name=message.name,
        metadata=dict(message.message_metadata or {}),
        payload=dict(message.payload or {}),
        created_at=message.created_at,
    )


def _to_message_mutation_response(
    message: AuditSessionMessage,
    *,
    mode: str,
    synced_managed_vulnerability: ManagedVulnerability | None = None,
) -> AuditSessionMessageMutationResponse:
    payload = _to_message_response(message).model_dump(mode="python")
    payload["mode"] = mode
    payload["synced_managed_vulnerability"] = synced_managed_vulnerability
    return AuditSessionMessageMutationResponse.model_validate(payload)


def _to_session_response(session: AuditSession) -> AuditSessionResponse:
    metadata = dict((session.runtime_state_json or {}).get("metadata") or {})
    runtime_state = type("RuntimeStateRef", (), {"metadata": metadata})()
    return AuditSessionResponse.model_validate(
        {
            "id": session.id,
            "project_id": session.project_id,
            "task_id": session.task_id,
            "runtime_stack": session.runtime_stack,
            "state": session.state,
            "system_prompt": session.system_prompt,
            "recon_payload": session.recon_payload,
            "guardrails_enabled": is_guardrails_enabled(runtime_state),
            "created_at": session.created_at,
            "updated_at": session.updated_at,
        }
    )


def _build_agent_user_config(user_config: dict[str, Any] | None, agent_name: str | None) -> dict[str, Any]:
    merged = copy.deepcopy(user_config or {})
    llm_payload = copy.deepcopy((merged or {}).get("llmConfig", {}) or {})
    agent_configs = llm_payload.get("agentConfigs") or {}
    override = agent_configs.get(agent_name or "") if agent_name else None
    if isinstance(override, dict) and override.get("enabled"):
        for key in (
            "llmProvider",
            "llmApiKey",
            "llmModel",
            "llmBaseUrl",
            "llmTimeout",
            "llmTemperature",
            "llmTopP",
            "llmMaxTokens",
            "alwaysThinkingEnabled",
            "llmCustomHeaders",
            "llmFirstTokenTimeout",
            "llmStreamTimeout",
            "agentTimeout",
            "subAgentTimeout",
            "toolTimeout",
        ):
            value = override.get(key)
            if value not in (None, ""):
                llm_payload[key] = value
        override_env = override.get("env")
        if isinstance(override_env, dict) and override_env:
            base_env = llm_payload.get("env") if isinstance(llm_payload.get("env"), dict) else {}
            llm_payload["env"] = {**base_env, **override_env}
    merged["llmConfig"] = llm_payload
    return merged


def _resolve_runtime_turn_limit(user_config: dict[str, Any] | None, agent_name: str) -> int | None:
    llm_payload = copy.deepcopy((user_config or {}).get("llmConfig", {}) or {})
    agent_configs = llm_payload.get("agentConfigs") or {}
    override = agent_configs.get(agent_name) or {}
    raw_value = override.get("maxIterations") if isinstance(override, dict) else None
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


async def _build_runtime_follow_up_context(
    *,
    session: AuditSession,
    db: AsyncSession,
) -> tuple[FindingRuntimeBridge, SandboxManager, str, int | None]:
    from app.api.v1.endpoints.agent_tasks import _get_project_root, _get_user_config, _initialize_tools

    task = await db.get(AgentTask, session.task_id) if session.task_id else None
    project = await db.get(Project, session.project_id)
    if task is None or project is None:
        raise HTTPException(status_code=409, detail="Audit session is missing task or project context")

    user_config = await _get_user_config(db, task.created_by)
    other_config = (user_config or {}).get("otherConfig", {})
    github_token = other_config.get("githubToken") or settings.GITHUB_TOKEN
    gitlab_token = other_config.get("gitlabToken") or settings.GITLAB_TOKEN
    gitea_token = other_config.get("giteaToken") or settings.GITEA_TOKEN
    ssh_private_key = None
    if other_config.get("sshPrivateKey"):
        try:
            ssh_private_key = decrypt_sensitive_data(other_config["sshPrivateKey"])
        except Exception:
            ssh_private_key = None

    sandbox_manager = SandboxManager()
    await sandbox_manager.initialize()

    project_root = await _get_project_root(
        project,
        task.id,
        task.branch_name,
        github_token=github_token,
        gitlab_token=gitlab_token,
        gitea_token=gitea_token,
        ssh_private_key=ssh_private_key,
        event_emitter=None,
    )

    target_files = task.target_files
    if target_files:
        valid_target_files = [file_path for file_path in target_files if os.path.exists(os.path.join(project_root, file_path))]
        target_files = valid_target_files or None

    llm_service = LLMService(user_config=_build_agent_user_config(user_config, "finding"))
    tools = await _initialize_tools(
        project_root,
        llm_service,
        user_config,
        sandbox_manager=sandbox_manager,
        exclude_patterns=task.exclude_patterns,
        target_files=target_files,
        project_id=str(project.id),
        event_emitter=None,
        task_id=task.id,
        user_id=task.created_by,
    )
    bridge = FindingRuntimeBridge(
        llm_service=llm_service,
        tools=tools.get("finding", {}),
        user_id=task.created_by,
    )
    model_name = None
    latest_turn_model = await db.scalar(
        select(AuditSessionTurn.model_name)
        .where(AuditSessionTurn.session_id == session.id)
        .order_by(AuditSessionTurn.sequence.desc())
        .limit(1)
    )
    model_name = str(latest_turn_model or "finding")
    max_turns = _resolve_runtime_turn_limit(user_config, "finding")
    return bridge, sandbox_manager, model_name, max_turns


async def _build_audit_chat_follow_up_context(
    *,
    session: AuditSession,
    db: AsyncSession,
) -> tuple[AuditChatRuntimeBridge, SandboxManager, str, int | None]:
    from app.api.v1.endpoints.agent_tasks import _get_project_root, _get_user_config, _initialize_tools

    task = await db.get(AgentTask, session.task_id) if session.task_id else None
    project = await db.get(Project, session.project_id)
    if task is None or project is None:
        raise HTTPException(status_code=409, detail="Audit session is missing task or project context")

    user_config = await _get_user_config(db, task.created_by)
    other_config = (user_config or {}).get("otherConfig", {})
    github_token = other_config.get("githubToken") or settings.GITHUB_TOKEN
    gitlab_token = other_config.get("gitlabToken") or settings.GITLAB_TOKEN
    gitea_token = other_config.get("giteaToken") or settings.GITEA_TOKEN
    ssh_private_key = None
    if other_config.get("sshPrivateKey"):
        try:
            ssh_private_key = decrypt_sensitive_data(other_config["sshPrivateKey"])
        except Exception:
            ssh_private_key = None

    sandbox_manager = SandboxManager()
    await sandbox_manager.initialize()

    project_root = await _get_project_root(
        project,
        task.id,
        task.branch_name,
        github_token=github_token,
        gitlab_token=gitlab_token,
        gitea_token=gitea_token,
        ssh_private_key=ssh_private_key,
        event_emitter=None,
    )

    target_files = task.target_files
    if target_files:
        valid_target_files = [file_path for file_path in target_files if os.path.exists(os.path.join(project_root, file_path))]
        target_files = valid_target_files or None

    llm_service = LLMService(user_config=_build_agent_user_config(user_config, "audit_chat"))
    tools = await _initialize_tools(
        project_root,
        llm_service,
        user_config,
        sandbox_manager=sandbox_manager,
        exclude_patterns=task.exclude_patterns,
        target_files=target_files,
        project_id=str(project.id),
        event_emitter=None,
        task_id=task.id,
        user_id=task.created_by,
    )
    bridge = AuditChatRuntimeBridge(
        llm_service=llm_service,
        tools=tools.get("finding", {}),
        user_id=task.created_by,
    )
    latest_turn_model = await db.scalar(
        select(AuditSessionTurn.model_name)
        .where(AuditSessionTurn.session_id == session.id)
        .order_by(AuditSessionTurn.sequence.desc())
        .limit(1)
    )
    model_name = str(latest_turn_model or "audit_chat")
    max_turns = _resolve_runtime_turn_limit(user_config, "audit_chat")
    return bridge, sandbox_manager, model_name, max_turns


async def continue_runtime_session(*, session_id: str, content: str, db: AsyncSession) -> dict[str, Any] | None:
    del content
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    try:
        bridge, sandbox_manager, model_name, max_turns = await _build_runtime_follow_up_context(session=session, db=db)
    except HTTPException as exc:
        if exc.status_code == 409:
            return None
        raise
    try:
        return await bridge.continue_dialogue_session(session_id=session_id, model_name=model_name, max_turns=max_turns)
    finally:
        try:
            await sandbox_manager.cleanup()
        except Exception:
            pass


async def queue_runtime_session_resume(
    *,
    session_id: str,
    current_user_id: str,
    db: AsyncSession,
) -> tuple[AuditSession, bool]:
    """Atomically claim a failed session and enqueue one durable resume job."""
    session = await db.scalar(
        select(AuditSession).where(AuditSession.id == session_id).with_for_update()
    )
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    task = await db.get(AgentTask, session.task_id) if session.task_id else None
    if task is not None and task.created_by != current_user_id:
        raise HTTPException(status_code=403, detail="No permission to resume this audit session")
    if session.runtime_stack != "runtime":
        raise HTTPException(status_code=400, detail="Only runtime audit sessions can be resumed")
    if session.state == "running":
        return session, False
    if session.state == "completed":
        raise HTTPException(status_code=400, detail="Completed audit sessions cannot be resumed")

    resume_token = str(uuid.uuid4())
    runtime_state = dict(session.runtime_state_json or {})
    metadata = dict(runtime_state.get("metadata") or {})
    metadata["resume_job"] = {
        "token": resume_token,
        "status": "queued",
        "queued_at": datetime.now(timezone.utc).isoformat(),
        "can_resume": False,
        "error_kind": None,
    }
    runtime_state["metadata"] = metadata
    session.runtime_state_json = runtime_state
    session.state = "running"
    if task is not None:
        task.status = "running"
        task.error_message = None
        task.completed_at = None
    batch_project = await db.scalar(
        select(OneClickCveBatchProject)
        .where(OneClickCveBatchProject.agent_task_id == session.task_id)
        .order_by(OneClickCveBatchProject.created_at.desc())
        .limit(1)
    ) if session.task_id else None
    if batch_project is not None:
        batch_project.status = OneClickCveProjectStatus.AUDITING
        batch_project.error_message = None
        batch_project.updated_at_local = datetime.now(timezone.utc)
    await db.commit()

    try:
        await enqueue_audit_session_resume(session.id, resume_token)
    except Exception as exc:
        await db.refresh(session)
        session.state = "failed"
        runtime_state = dict(session.runtime_state_json or {})
        metadata = dict(runtime_state.get("metadata") or {})
        metadata["resume_job"] = {
            **dict(metadata.get("resume_job") or {}),
            "status": "enqueue_failed",
            "can_resume": True,
            "error_kind": "queue_unavailable",
            "error": str(exc),
        }
        runtime_state["metadata"] = metadata
        session.runtime_state_json = runtime_state
        if task is not None:
            task.status = "failed"
            task.error_message = f"继续审计任务入队失败：{exc}"
        if batch_project is not None:
            message = "继续审计队列不可用，已停止整个一键 CVE"
            batch_project.status = OneClickCveProjectStatus.FAILED
            batch_project.error_message = message
            batch_project.updated_at_local = datetime.now(timezone.utc)
            batch = await db.get(OneClickCveBatch, batch_project.batch_id)
            if batch is not None:
                batch.status = OneClickCveBatchStatus.FAILED
                batch.error_message = message
                batch.current_step = message
                batch.completed_at = datetime.now(timezone.utc)
        await db.commit()
        raise HTTPException(status_code=503, detail="Resume queue is temporarily unavailable") from exc
    return session, True


async def continue_audit_chat_session(
    *,
    session_id: str,
    content: str,
    db: AsyncSession,
    event_sink=None,
) -> dict[str, Any]:
    del content
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    try:
        bridge, sandbox_manager, model_name, max_turns = await _build_audit_chat_follow_up_context(session=session, db=db)
    except HTTPException as exc:
        # Preserve the legacy non-streaming mutation contract while allowing the
        # streaming endpoint to turn the missing result into a structured error.
        if exc.status_code == 409:
            return {"session_id": session_id, "runner_result": None, "runtime_error": str(exc.detail)}
        raise
    try:
        return await bridge.continue_chat_session(
            session_id=session_id,
            model_name=model_name,
            max_turns=max_turns,
            event_sink=event_sink,
        )
    finally:
        try:
            await sandbox_manager.cleanup()
        except Exception:
            pass


async def _generate_and_sync_follow_up_managed_vulnerability(
    *,
    session: AuditSession,
    db: AsyncSession,
) -> ManagedVulnerability:
    if not session.task_id:
        raise ValueError("This audit session is not attached to an agent task.")

    task = await db.get(AgentTask, session.task_id)
    if task is None:
        raise ValueError("Unable to load the task for this audit session.")

    finding_result = await db.execute(
        select(AgentFinding)
        .where(
            AgentFinding.task_id == task.id,
            AgentFinding.status != FindingStatus.FALSE_POSITIVE,
        )
        .order_by(
            desc(AgentFinding.is_verified),
            desc(AgentFinding.verified_at),
            desc(AgentFinding.created_at),
            desc(AgentFinding.id),
        )
        .limit(1)
    )
    finding = finding_result.scalars().first()
    if finding is None:
        raise ValueError("No non-false-positive findings are available for report sync yet.")

    from app.api.v1.endpoints.agent_tasks import (
        _append_internal_audit_session_message,
        _generate_managed_report_bundle_from_session,
        _managed_reports_completed,
    )
    from app.services.managed_vulnerability_service import ManagedVulnerabilityService
    from app.services.vulnerability_report_generation import VulnerabilityReportGenerationService

    managed_service = ManagedVulnerabilityService(db)
    report_service = VulnerabilityReportGenerationService()
    managed = await managed_service.create_from_finding(task=task, finding=finding)

    if not _managed_reports_completed(managed):
        prompt = report_service.build_generation_prompt(vulnerability=managed)
        await _append_internal_audit_session_message(
            db,
            session_id=session.id,
            role="user",
            content=prompt,
            name="managed_report_generator",
            metadata={
                "kind": "internal_managed_report_request",
                "finding_id": finding.id,
                "managed_vulnerability_id": managed.id,
            },
        )
        generated_bundle = await _generate_managed_report_bundle_from_session(
            db,
            session=session,
            task=task,
            finding=finding,
            managed_vulnerability=managed,
            report_service=report_service,
        )
        report_service.apply_generated_reports(vulnerability=managed, result=generated_bundle)

    await db.commit()
    result = await db.execute(
        select(ManagedVulnerability)
        .options(selectinload(ManagedVulnerability.reports))
        .where(ManagedVulnerability.id == managed.id)
    )
    refreshed = result.scalar_one()
    return refreshed


async def _build_follow_up_llm_service(*, session: AuditSession, db: AsyncSession) -> tuple[LLMService, AgentTask]:
    from app.api.v1.endpoints.agent_tasks import _get_user_config

    task = await db.get(AgentTask, session.task_id) if session.task_id else None
    project = await db.get(Project, session.project_id)
    if task is None or project is None:
        raise HTTPException(status_code=409, detail="Audit session is missing task or project context")

    user_config = await _get_user_config(db, task.created_by)
    llm_service = LLMService(user_config=_build_agent_user_config(user_config, "finding"))
    return llm_service, task


def _render_follow_up_context(messages: list[AuditSessionMessage]) -> str:
    if not messages:
        return "No prior transcript is available."

    selected_messages = messages
    if len(messages) > 80:
        selected_messages = [messages[0], *messages[-79:]]

    lines: list[str] = []
    for message in selected_messages:
        role = (message.role or "unknown").upper()
        name = f" {message.name}" if message.name else ""
        lines.append(f"[{role}{name} #{message.sequence}]")
        lines.append((message.content or "").strip() or "(empty)")
        lines.append("")
    return "\n".join(lines).strip()


def _build_follow_up_messages(
    *,
    session: AuditSession,
    transcript_context: str,
    latest_user_prompt: str,
) -> list[dict[str, str]]:
    system_prompt = (session.system_prompt or "").strip()
    follow_up_system = (
        system_prompt
        + "\n\n"
        + "You are continuing an existing code-audit session. "
        + "Answer as the same audit agent, rely on the stored transcript context, "
        + "format the response as Markdown, and do not claim tools were executed unless the transcript already shows them."
    ).strip()
    return [
        {"role": "system", "content": follow_up_system},
        {"role": "user", "content": "Existing audit-session context:\n\n" + transcript_context},
        {"role": "user", "content": latest_user_prompt},
    ]


@router.get("/{session_id}", response_model=AuditSessionResponse)
async def get_audit_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> AuditSessionResponse:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    if session.task_id:
        task = await db.get(AgentTask, session.task_id)
        if task is not None and task.created_by != current_user.id:
            raise HTTPException(status_code=403, detail="No permission to access this audit session")
    checkpoint = await db.scalar(
        select(AuditCheckpoint)
        .where(AuditCheckpoint.session_id == session_id)
        .order_by(AuditCheckpoint.created_at.desc())
        .limit(1)
    )
    response = _to_session_response(session)
    checkpoint_payload = dict(checkpoint.state_payload or {}) if checkpoint is not None else {}
    runtime_metadata = dict((session.runtime_state_json or {}).get("metadata") or {})
    resume_job = dict(runtime_metadata.get("resume_job") or {})
    response.can_resume = session.runtime_stack == "runtime" and session.state == "failed" and bool(
        resume_job.get("can_resume")
        or checkpoint_payload.get("resumable")
        or checkpoint_payload.get("checkpoint_kind") == "resumable_failed"
    )
    response.last_error_kind = str(resume_job.get("error_kind") or checkpoint_payload.get("error_kind") or "") or None
    response.resume_status = str(resume_job.get("status") or "") or None
    return response


@router.post("/{session_id}/resume", response_model=AuditSessionResumeResponse, status_code=202)
async def resume_audit_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> AuditSessionResumeResponse:
    session, queued = await queue_runtime_session_resume(
        session_id=session_id,
        current_user_id=current_user.id,
        db=db,
    )
    if not queued:
        return AuditSessionResumeResponse(session_id=session_id, status="running", message="Audit session is already running")
    return AuditSessionResumeResponse(session_id=session_id, status="running", message="Audit session resume job queued")


@router.get("/{session_id}/messages", response_model=list[AuditSessionMessageResponse])
async def list_audit_session_messages(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> list[AuditSessionMessageResponse]:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")

    result = await db.execute(
        select(AuditSessionMessage)
        .where(AuditSessionMessage.session_id == session_id)
        .order_by(AuditSessionMessage.sequence)
    )
    return [_to_message_response(message) for message in result.scalars().all()]


@router.get("/{session_id}/tool-calls", response_model=list[AuditSessionToolCallResponse])
async def list_audit_session_tool_calls(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> list[AuditSessionToolCallResponse]:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")

    result = await db.execute(
        select(AuditToolCall)
        .where(AuditToolCall.session_id == session_id)
        .order_by(AuditToolCall.sequence)
    )
    return [AuditSessionToolCallResponse.model_validate(tool_call) for tool_call in result.scalars().all()]


@router.get("/{session_id}/model-attempts", response_model=list[AuditModelStreamAttemptResponse])
async def list_audit_session_model_attempts(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> list[AuditModelStreamAttemptResponse]:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    result = await db.execute(
        select(AuditModelStreamAttempt)
        .where(AuditModelStreamAttempt.session_id == session_id)
        .order_by(AuditModelStreamAttempt.started_at)
    )
    return [AuditModelStreamAttemptResponse.model_validate(item) for item in result.scalars().all()]


@router.get("/{session_id}/skills", response_model=list[AuditSessionSkillResponse])
async def list_audit_session_skills(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> list[AuditSessionSkillResponse]:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")

    result = await db.execute(
        select(AuditSkill)
        .where(AuditSkill.session_id == session_id)
        .order_by(AuditSkill.created_at)
    )
    return [AuditSessionSkillResponse.model_validate(skill) for skill in result.scalars().all()]


@router.get("/{session_id}/skill-invocations", response_model=list[AuditSessionSkillInvocationResponse])
async def list_audit_session_skill_invocations(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> list[AuditSessionSkillInvocationResponse]:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")

    result = await db.execute(
        select(AuditSkillInvocation)
        .where(AuditSkillInvocation.session_id == session_id)
        .order_by(AuditSkillInvocation.sequence)
    )
    return [AuditSessionSkillInvocationResponse.model_validate(invocation) for invocation in result.scalars().all()]


@router.get("/{session_id}/memories", response_model=list[AuditSessionMemoryResponse])
async def list_audit_session_memories(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> list[AuditSessionMemoryResponse]:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")

    result = await db.execute(
        select(AuditMemory)
        .where(AuditMemory.session_id == session_id)
        .order_by(AuditMemory.sequence)
    )
    return [AuditSessionMemoryResponse.model_validate(memory) for memory in result.scalars().all()]


@router.get("/{session_id}/handoffs", response_model=list[AuditSessionHandoffResponse])
async def list_audit_session_handoffs(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> list[AuditSessionHandoffResponse]:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")

    result = await db.execute(
        select(AuditHandoff)
        .where(AuditHandoff.session_id == session_id)
        .order_by(AuditHandoff.created_at)
    )
    return [AuditSessionHandoffResponse.model_validate(handoff) for handoff in result.scalars().all()]


@router.post("/{session_id}/messages", response_model=AuditSessionMessageMutationResponse)
async def create_audit_session_message(
    session_id: str,
    payload: AuditSessionMessageCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> AuditSessionMessageMutationResponse:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    mode = str(payload.mode or "chat").strip() or "chat"
    if mode not in {"chat", "generate_report_and_sync"}:
        raise HTTPException(status_code=400, detail="Unsupported audit session message mode")
    if mode == "generate_report_and_sync" and session.runtime_stack != "runtime":
        raise HTTPException(status_code=400, detail="Report generation and sync is only supported for runtime audit sessions")

    next_sequence = await db.scalar(
        select(func.max(AuditSessionMessage.sequence)).where(AuditSessionMessage.session_id == session_id)
    )
    message = AuditSessionMessage(
        session_id=session_id,
        sequence=(next_sequence or 0) + 1,
        role="user",
        content=payload.content,
        message_metadata=(
            {"kind": "follow_up_user_message", "mode": mode, "selected_skill_refs": list(payload.selected_skill_refs or [])}
            if session.runtime_stack == "runtime"
            else {"mode": mode, "selected_skill_refs": list(payload.selected_skill_refs or [])}
        ),
        payload=(
            {"continued": session.runtime_stack == "runtime", "mode": mode, "selected_skill_refs": list(payload.selected_skill_refs or [])}
            if session.runtime_stack == "runtime"
            else {"mode": mode, "selected_skill_refs": list(payload.selected_skill_refs or [])}
        ),
    )
    db.add(message)
    await db.commit()
    await db.refresh(message)

    synced_managed_vulnerability: ManagedVulnerability | None = None
    if session.runtime_stack == "runtime":
        if mode == "generate_report_and_sync":
            try:
                synced_managed_vulnerability = await _generate_and_sync_follow_up_managed_vulnerability(session=session, db=db)
            except ValueError as exc:
                await db.rollback()
                raise HTTPException(status_code=400, detail=str(exc)) from exc
        else:
            await continue_audit_chat_session(session_id=session_id, content=payload.content, db=db)

    return _to_message_mutation_response(
        message,
        mode=mode,
        synced_managed_vulnerability=synced_managed_vulnerability,
    )


@router.post("/{session_id}/messages/stream")
async def stream_audit_session_message(
    session_id: str,
    payload: AuditSessionMessageCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> StreamingResponse:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    mode = str(payload.mode or "chat").strip() or "chat"
    if mode not in {"chat", "generate_report_and_sync"}:
        raise HTTPException(status_code=400, detail="Unsupported audit session message mode")
    if mode == "generate_report_and_sync" and session.runtime_stack != "runtime":
        raise HTTPException(status_code=400, detail="Report generation and sync is only supported for runtime audit sessions")

    next_sequence = await db.scalar(
        select(func.max(AuditSessionMessage.sequence)).where(AuditSessionMessage.session_id == session_id)
    )
    user_message = AuditSessionMessage(
        session_id=session_id,
        sequence=(next_sequence or 0) + 1,
        role="user",
        content=payload.content,
        message_metadata={
            "kind": "follow_up_user_message",
            "streaming": True,
            "mode": mode,
            "selected_skill_refs": list(payload.selected_skill_refs or []),
        },
        payload={
            "continued": True,
            "streaming": True,
            "mode": mode,
            "selected_skill_refs": list(payload.selected_skill_refs or []),
        },
    )
    db.add(user_message)
    await db.commit()
    await db.refresh(user_message)

    if session.runtime_stack == "runtime":
        async def runtime_event_generator():
            yield _format_sse_event({
                "type": "user_message",
                "message": _to_message_response(user_message).model_dump(mode="json"),
            })
            try:
                synced_managed_vulnerability = None
                if mode == "generate_report_and_sync":
                    synced_managed_vulnerability = await _generate_and_sync_follow_up_managed_vulnerability(session=session, db=db)
                else:
                    queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()
                    runner_result: Any | None = None
                    terminal_failure: dict[str, Any] | None = None
                    terminal_message: AuditSessionMessage | None = None

                    async def collect_event(event: dict[str, Any]):
                        # QueryLoop emits model-level done/error events before the complete ReAct
                        # run has reached a terminal state. This endpoint owns the SSE terminal event.
                        if event.get("type") in {"done", "error"}:
                            return
                        await queue.put(event)

                    async def worker():
                        nonlocal runner_result, terminal_failure, terminal_message
                        try:
                            result = await continue_audit_chat_session(
                                session_id=session_id,
                                content=payload.content,
                                db=db,
                                event_sink=collect_event,
                            )
                            runner_result = result.get("runner_result") if isinstance(result, dict) else None
                            runtime_error = str(result.get("runtime_error") or "") if isinstance(result, dict) else ""
                            stop_reason = _runtime_stop_reason_value(runner_result)
                            terminal_message = await _load_audit_chat_assistant_message(
                                db=db,
                                session_id=session_id,
                                runner_result=runner_result,
                            ) if runner_result is not None else None
                            if stop_reason not in _AUDIT_CHAT_SUCCESS_STOP_REASONS or terminal_message is None:
                                terminal_failure = await _build_audit_chat_failure(
                                    db=db,
                                    session_id=session_id,
                                    runner_result=runner_result,
                                    exception=RuntimeError(runtime_error) if runtime_error else None,
                                    missing_presentation=(
                                        stop_reason in _AUDIT_CHAT_SUCCESS_STOP_REASONS and terminal_message is None
                                    ),
                                )
                                terminal_failure = await _persist_audit_chat_failure(
                                    db=db,
                                    session_id=session_id,
                                    failure=terminal_failure,
                                )
                        except asyncio.CancelledError as exc:
                            terminal_failure = await _persist_audit_chat_failure(
                                db=db,
                                session_id=session_id,
                                failure=await _build_audit_chat_failure(
                                    db=db,
                                    session_id=session_id,
                                    runner_result=runner_result,
                                    exception=exc,
                                ),
                            )
                            raise
                        except Exception as exc:
                            terminal_failure = await _persist_audit_chat_failure(
                                db=db,
                                session_id=session_id,
                                failure=await _build_audit_chat_failure(
                                    db=db,
                                    session_id=session_id,
                                    runner_result=runner_result,
                                    exception=exc,
                                ),
                            )
                        finally:
                            await queue.put(None)

                    worker_task = asyncio.create_task(worker())
                    try:
                        while True:
                            try:
                                event = await asyncio.wait_for(queue.get(), timeout=15.0)
                            except asyncio.TimeoutError:
                                yield _format_sse_event({"type": "heartbeat"})
                                continue
                            if event is None:
                                break
                            yield _format_sse_event(event)
                        await worker_task
                    finally:
                        if not worker_task.done():
                            worker_task.cancel()
                if mode == "generate_report_and_sync":
                    yield _format_sse_event({
                        "type": "done",
                        "usage": {},
                        "mode": mode,
                        "synced_managed_vulnerability": ManagedVulnerabilityDetailResponse.model_validate(
                            synced_managed_vulnerability
                        ).model_dump(mode="json"),
                    })
                elif terminal_failure is not None:
                    yield _format_sse_event({"type": "error", **terminal_failure})
                elif terminal_message is not None:
                    yield _format_sse_event({
                        "type": "done",
                        "message": _to_message_response(terminal_message).model_dump(mode="json"),
                        "usage": {},
                        "mode": mode,
                        "synced_managed_vulnerability": None,
                    })
                else:
                    # Defensive fallback: do not claim a completed response without a persisted assistant message.
                    failure = await _persist_audit_chat_failure(
                        db=db,
                        session_id=session_id,
                        failure=await _build_audit_chat_failure(
                            db=db,
                            session_id=session_id,
                            runner_result=runner_result,
                            missing_presentation=True,
                        ),
                    )
                    yield _format_sse_event({"type": "error", **failure})
            except Exception as exc:
                await db.rollback()
                failure = await _persist_audit_chat_failure(
                    db=db,
                    session_id=session_id,
                    failure=await _build_audit_chat_failure(
                        db=db,
                        session_id=session_id,
                        exception=exc,
                    ),
                )
                yield _format_sse_event({"type": "error", **failure})

        return StreamingResponse(
            runtime_event_generator(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
        )

    llm_service, _task = await _build_follow_up_llm_service(session=session, db=db)

    transcript_result = await db.execute(
        select(AuditSessionMessage)
        .where(AuditSessionMessage.session_id == session_id, AuditSessionMessage.sequence < user_message.sequence)
        .order_by(AuditSessionMessage.sequence)
    )
    transcript_context = _render_follow_up_context(list(transcript_result.scalars().all()))
    llm_messages = _build_follow_up_messages(
        session=session,
        transcript_context=transcript_context,
        latest_user_prompt=payload.content,
    )

    async def event_generator():
        yield _format_sse_event({
            "type": "user_message",
            "message": _to_message_response(user_message).model_dump(mode="json"),
        })
        yield _format_sse_event({
            "type": "assistant_start",
            "message": {
                "id": f"streaming-{session_id}",
                "session_id": session_id,
                "sequence": user_message.sequence + 1,
                "role": "assistant",
                "content": "",
                "metadata": {"kind": "follow_up_assistant_message", "streaming": True},
                "payload": {},
                "created_at": datetime.utcnow().isoformat(),
            },
        })

        accumulated = ""
        try:
            async for event in llm_service.chat_completion_stream(
                messages=llm_messages,
                agent_type="finding",
            ):
                event_type = event.get("type")
                if event_type == "token":
                    token_text = str(event.get("content") or "")
                    for chunk in _chunk_text(token_text):
                        accumulated += chunk
                        yield _format_sse_event({
                            "type": "token",
                            "content": chunk,
                            "accumulated": accumulated,
                        })
                        await asyncio.sleep(0.01)
                    continue

                if event_type != "done":
                    continue

                final_content = str(event.get("content") or accumulated)
                if final_content and final_content != accumulated:
                    suffix = final_content[len(accumulated):]
                    for chunk in _chunk_text(suffix):
                        accumulated += chunk
                        yield _format_sse_event({
                            "type": "token",
                            "content": chunk,
                            "accumulated": accumulated,
                        })
                        await asyncio.sleep(0.01)
                else:
                    final_content = accumulated

                assistant_message = AuditSessionMessage(
                    session_id=session_id,
                    sequence=user_message.sequence + 1,
                    role="assistant",
                    content=final_content,
                    message_metadata={"kind": "follow_up_assistant_message", "streaming": True},
                    payload={"usage": event.get("usage") or {}},
                )
                db.add(assistant_message)
                await db.commit()
                await db.refresh(assistant_message)

                yield _format_sse_event({
                    "type": "done",
                    "message": _to_message_response(assistant_message).model_dump(mode="json"),
                    "usage": event.get("usage") or {},
                })
                return

            assistant_message = AuditSessionMessage(
                session_id=session_id,
                sequence=user_message.sequence + 1,
                role="assistant",
                content=accumulated,
                message_metadata={"kind": "follow_up_assistant_message", "streaming": True},
                payload={},
            )
            db.add(assistant_message)
            await db.commit()
            await db.refresh(assistant_message)
            yield _format_sse_event({
                "type": "done",
                "message": _to_message_response(assistant_message).model_dump(mode="json"),
                "usage": {},
            })
        except Exception as exc:
            await db.rollback()
            yield _format_sse_event({"type": "error", "message": str(exc)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )
