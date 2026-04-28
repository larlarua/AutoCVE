from __future__ import annotations

from typing import Any, Dict

from pydantic import BaseModel, Field

from app.services.runtime_core.interaction_runtime import InteractionRuntime
from app.services.runtime_core.session_state import (
    SessionRuntimeState,
    build_legacy_agent_runtime_state,
    sync_legacy_agent_metadata_from_runtime_state,
)

from .base import AgentTool, ToolResult


class TodoWriteInput(BaseModel):
    title: str = Field(..., min_length=1)
    details: str | None = None


class AskUserInput(BaseModel):
    question: str = Field(..., min_length=1)
    context: Dict[str, str] = Field(default_factory=dict)


class PlanModeInput(BaseModel):
    reason: str | None = None


_INTERACTION_RUNTIME = InteractionRuntime()


def _require_agent(kwargs: Dict[str, Any]):
    agent = kwargs.pop("_agent", None)
    if agent is None:
        raise ValueError("Interaction tools require agent context")
    return agent


def _interaction_state(agent) -> Dict[str, Any]:
    metadata = agent.state.metadata
    state = metadata.setdefault("interaction_runtime", {})
    state.setdefault("pending_todos", [])
    state.setdefault("pending_questions", [])
    state.setdefault("plan_mode", {"active": False})
    state.setdefault("todos", {})
    state.setdefault("questions", {})
    state.setdefault("permission_mode", "default")
    return state


def _build_runtime_state(agent) -> SessionRuntimeState:
    return build_legacy_agent_runtime_state(
        session_id=agent.agent_id,
        agent_type=agent.agent_type.value,
        interaction_state=_interaction_state(agent),
        tool_runtime=agent.state.metadata.get("tool_runtime") or {},
        memory_runtime=agent.state.metadata.get("memory_runtime") or {},
    )


def _sync_runtime_state(agent, runtime_state: SessionRuntimeState) -> Dict[str, Any]:
    stored, tool_runtime = sync_legacy_agent_metadata_from_runtime_state(
        runtime_state,
        agent_type=agent.agent_type.value,
        interaction_state=_interaction_state(agent),
        tool_runtime=agent.state.metadata.setdefault("tool_runtime", {}),
        memory_runtime=agent.state.metadata.setdefault("memory_runtime", {}),
    )
    agent.state.metadata["tool_runtime"] = tool_runtime
    return stored


def _write_back_record(runtime_state: SessionRuntimeState, *, agent, bucket: str, record: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(record)
    enriched["agent_id"] = agent.agent_id
    enriched["agent_type"] = agent.agent_type.value
    agent_state = runtime_state.ensure_agent_state(agent.agent_type.value)
    if bucket == "todos":
        if agent_state.pending_todos:
            agent_state.pending_todos[-1] = dict(enriched)
        runtime_state.metadata.setdefault("todos", {})[enriched["id"]] = dict(enriched)
    elif bucket == "questions":
        if agent_state.pending_questions:
            agent_state.pending_questions[-1] = dict(enriched)
        if runtime_state.pending_questions:
            runtime_state.pending_questions[-1] = dict(enriched)
        runtime_state.metadata.setdefault("questions", {})[enriched["id"]] = dict(enriched)
    return enriched


class TodoWriteTool(AgentTool):
    requires_agent_context = True

    @property
    def name(self) -> str:
        return "TodoWrite"

    @property
    def description(self) -> str:
        return "为当前 Agent 会话创建共享待办项"

    @property
    def args_schema(self):
        return TodoWriteInput

    async def _execute(self, title: str, details: str | None = None, **kwargs) -> ToolResult:
        agent = _require_agent(kwargs)
        runtime_state = _build_runtime_state(agent)
        todo = _INTERACTION_RUNTIME.create_todo(
            runtime_state,
            agent_type=agent.agent_type.value,
            title=title,
            details=details,
            todo_id=f"todo-{len(runtime_state.ensure_agent_state(agent.agent_type.value).pending_todos) + 1}",
        )
        todo = _write_back_record(runtime_state, agent=agent, bucket="todos", record=todo)
        _sync_runtime_state(agent, runtime_state)
        return ToolResult(success=True, data=f"Todo recorded: {todo['title']}", metadata={"todo": todo, "interaction": "todo"})


class AskUserTool(AgentTool):
    requires_agent_context = True

    @property
    def name(self) -> str:
        return "AskUser"

    @property
    def description(self) -> str:
        return "为人工操作员记录一个阻塞问题"

    @property
    def args_schema(self):
        return AskUserInput

    async def _execute(self, question: str, context: Dict[str, str] | None = None, **kwargs) -> ToolResult:
        agent = _require_agent(kwargs)
        runtime_state = _build_runtime_state(agent)
        entry = _INTERACTION_RUNTIME.ask_user(
            runtime_state,
            agent_type=agent.agent_type.value,
            question=question,
            context=context,
            question_id=f"question-{len(runtime_state.ensure_agent_state(agent.agent_type.value).pending_questions) + 1}",
        )
        entry = _write_back_record(runtime_state, agent=agent, bucket="questions", record=entry)
        _sync_runtime_state(agent, runtime_state)
        agent.state.enter_waiting_state(reason=f"Waiting for user input: {entry['question']}")
        return ToolResult(success=True, data=f"Question recorded: {entry['question']}", metadata={"question": entry, "interaction": "ask_user"})


class EnterPlanModeTool(AgentTool):
    requires_agent_context = True

    @property
    def name(self) -> str:
        return "EnterPlanMode"

    @property
    def description(self) -> str:
        return "让当前 Agent 进入共享计划模式"

    @property
    def args_schema(self):
        return PlanModeInput

    async def _execute(self, reason: str | None = None, **kwargs) -> ToolResult:
        agent = _require_agent(kwargs)
        runtime_state = _build_runtime_state(agent)
        plan_state = _INTERACTION_RUNTIME.enter_plan_mode(
            runtime_state,
            agent_type=agent.agent_type.value,
            reason=reason,
        )
        plan_state.update({
            "entered_by": agent.agent_id,
            "entered_agent_type": agent.agent_type.value,
        })
        runtime_state.metadata["plan_mode"] = dict(plan_state)
        _sync_runtime_state(agent, runtime_state)
        return ToolResult(success=True, data="计划模式已启用", metadata={"plan_mode": dict(plan_state), "interaction": "plan_mode_enter"})


class ExitPlanModeTool(AgentTool):
    requires_agent_context = True

    @property
    def name(self) -> str:
        return "ExitPlanMode"

    @property
    def description(self) -> str:
        return "让当前 Agent 退出共享计划模式"

    @property
    def args_schema(self):
        return PlanModeInput

    async def _execute(self, reason: str | None = None, **kwargs) -> ToolResult:
        agent = _require_agent(kwargs)
        runtime_state = _build_runtime_state(agent)
        plan_state = _INTERACTION_RUNTIME.exit_plan_mode(
            runtime_state,
            agent_type=agent.agent_type.value,
            reason=reason,
        )
        plan_state.update({
            "last_exited_by": agent.agent_id,
        })
        runtime_state.metadata["plan_mode"] = dict(plan_state)
        _sync_runtime_state(agent, runtime_state)
        return ToolResult(success=True, data="计划模式已关闭", metadata={"plan_mode": dict(plan_state), "interaction": "plan_mode_exit"})
