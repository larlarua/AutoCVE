from __future__ import annotations

import asyncio
import copy
import json
import os
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.core.config import settings
from app.core.encryption import decrypt_sensitive_data
from app.db.session import get_db
from app.models.agent_task import AgentTask
from app.models.audit_session import (
    AuditHandoff,
    AuditMemory,
    AuditSession,
    AuditSessionMessage,
    AuditSessionTurn,
    AuditSkill,
    AuditSkillInvocation,
    AuditToolCall,
)
from app.models.project import Project
from app.models.user import User
from app.services.agent.tools.sandbox_tool import SandboxManager
from app.services.finding_runtime.bridge import FindingRuntimeBridge
from app.services.llm.service import LLMService

router = APIRouter()


class AuditSessionResponse(BaseModel):
    id: str
    project_id: str
    task_id: Optional[str] = None
    runtime_stack: str
    state: str
    system_prompt: Optional[str] = None
    recon_payload: Optional[dict[str, Any]] = None
    created_at: datetime
    updated_at: datetime

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


def _format_sse_event(payload: dict[str, Any]) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


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


async def continue_runtime_session(*, session_id: str, content: str, db: AsyncSession) -> None:
    del content
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    try:
        bridge, sandbox_manager, model_name, max_turns = await _build_runtime_follow_up_context(session=session, db=db)
    except HTTPException as exc:
        if exc.status_code == 409:
            return
        raise
    try:
        await bridge.continue_session(session_id=session_id, model_name=model_name, max_turns=max_turns)
    finally:
        try:
            await sandbox_manager.cleanup()
        except Exception:
            pass


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
    _: User = Depends(deps.get_current_user),
) -> AuditSessionResponse:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    return AuditSessionResponse.model_validate(session)


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


@router.post("/{session_id}/messages", response_model=AuditSessionMessageResponse)
async def create_audit_session_message(
    session_id: str,
    payload: AuditSessionMessageCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(deps.get_current_user),
) -> AuditSessionMessageResponse:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")

    next_sequence = await db.scalar(
        select(func.max(AuditSessionMessage.sequence)).where(AuditSessionMessage.session_id == session_id)
    )
    message = AuditSessionMessage(
        session_id=session_id,
        sequence=(next_sequence or 0) + 1,
        role="user",
        content=payload.content,
        message_metadata={"kind": "follow_up_user_message"} if session.runtime_stack == "runtime" else {},
        payload={"continued": session.runtime_stack == "runtime"} if session.runtime_stack == "runtime" else {},
    )
    db.add(message)
    await db.commit()
    await db.refresh(message)

    if session.runtime_stack == "runtime":
        await continue_runtime_session(session_id=session_id, content=payload.content, db=db)

    return _to_message_response(message)


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

    next_sequence = await db.scalar(
        select(func.max(AuditSessionMessage.sequence)).where(AuditSessionMessage.session_id == session_id)
    )
    user_message = AuditSessionMessage(
        session_id=session_id,
        sequence=(next_sequence or 0) + 1,
        role="user",
        content=payload.content,
        message_metadata={"kind": "follow_up_user_message", "streaming": True},
        payload={"continued": True, "streaming": True},
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
                await continue_runtime_session(session_id=session_id, content=payload.content, db=db)
                yield _format_sse_event({
                    "type": "done",
                    "usage": {},
                })
            except Exception as exc:
                await db.rollback()
                yield _format_sse_event({"type": "error", "message": str(exc)})

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
