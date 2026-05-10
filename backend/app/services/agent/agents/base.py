from __future__ import annotations

import asyncio
import json
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from ..core.message import AgentMessage, MessageType, message_bus
from ..core.registry import agent_registry
from ..core.state import AgentState
from app.models.audit_session import AuditCheckpointType
from app.services.runtime_core.permission_runtime import ToolPermissionDecision, resolve_permission_rule_decision
from app.services.runtime_core.session_registry import runtime_session_registry
from app.services.runtime_core.session_state import (
    SessionRuntimeState,
    build_legacy_agent_runtime_state,
)
from app.services.runtime_core.tool_runtime import match_runtime_event_hooks

logger = logging.getLogger(__name__)


class AgentType(Enum):
    ORCHESTRATOR = "orchestrator"
    RECON = "recon"
    ANALYSIS = "analysis"
    SCAN = "scan"
    TRIAGE = "triage"
    FINDING = "finding"
    VERIFICATION = "verification"


class AgentPattern(Enum):
    REACT = "react"
    PLAN_AND_EXECUTE = "plan_execute"


@dataclass
class AgentConfig:
    name: str
    agent_type: AgentType
    pattern: AgentPattern = AgentPattern.REACT
    model: Optional[str] = None
    temperature: float = 0.1
    max_tokens: int = 8192
    max_iterations: int = 20
    timeout_seconds: int = 600
    tools: List[str] = field(default_factory=list)
    system_prompt: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskHandoff:
    from_agent: str
    to_agent: str
    summary: str
    work_completed: List[str] = field(default_factory=list)
    key_findings: List[Dict[str, Any]] = field(default_factory=list)
    insights: List[str] = field(default_factory=list)
    suggested_actions: List[Dict[str, Any]] = field(default_factory=list)
    attention_points: List[str] = field(default_factory=list)
    priority_areas: List[str] = field(default_factory=list)
    context_data: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.8
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_agent": self.from_agent,
            "to_agent": self.to_agent,
            "summary": self.summary,
            "work_completed": self.work_completed,
            "key_findings": self.key_findings,
            "insights": self.insights,
            "suggested_actions": self.suggested_actions,
            "attention_points": self.attention_points,
            "priority_areas": self.priority_areas,
            "context_data": self.context_data,
            "confidence": self.confidence,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskHandoff":
        return cls(
            from_agent=data.get("from_agent", ""),
            to_agent=data.get("to_agent", ""),
            summary=data.get("summary", ""),
            work_completed=data.get("work_completed", []),
            key_findings=data.get("key_findings", []),
            insights=data.get("insights", []),
            suggested_actions=data.get("suggested_actions", []),
            attention_points=data.get("attention_points", []),
            priority_areas=data.get("priority_areas", []),
            context_data=data.get("context_data", {}),
            confidence=data.get("confidence", 0.8),
        )

    def to_prompt_context(self) -> str:
        lines = [
            f"## Handoff From {self.from_agent} Agent",
            "",
            "### Summary",
            self.summary,
            "",
        ]
        if self.work_completed:
            lines.append("### Completed Work")
            lines.extend(f"- {work}" for work in self.work_completed)
            lines.append("")
        if self.key_findings:
            lines.append("### Key Findings")
            for index, finding in enumerate(self.key_findings[:15], 1):
                severity = finding.get("severity", "medium")
                title = finding.get("title", "Unknown")
                file_path = finding.get("file_path", "")
                lines.append(f"{index}. [{severity.upper()}] {title}")
                if file_path:
                    lines.append(f"   Location: {file_path}:{finding.get('line_start', '')}")
                if finding.get("description"):
                    lines.append(f"   Description: {finding['description'][:100]}")
            lines.append("")
        if self.insights:
            lines.append("### Insights")
            lines.extend(f"- {item}" for item in self.insights)
            lines.append("")
        if self.suggested_actions:
            lines.append("### Suggested Actions")
            for action in self.suggested_actions:
                action_type = action.get("type", action.get("action", "general"))
                description = action.get("description", action.get("reason", ""))
                priority = action.get("priority", "medium")
                lines.append(f"- [{priority.upper()}] {action_type}: {description}")
            lines.append("")
        if self.attention_points:
            lines.append("### Attention Points")
            lines.extend(f"- {item}" for item in self.attention_points)
            lines.append("")
        if self.priority_areas:
            lines.append("### Priority Areas")
            lines.extend(f"- {item}" for item in self.priority_areas)
        return "\n".join(lines)


@dataclass
class AgentResult:
    success: bool
    data: Any = None
    error: Optional[str] = None
    iterations: int = 0
    tool_calls: int = 0
    tokens_used: int = 0
    duration_ms: int = 0
    intermediate_steps: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    handoff: Optional[TaskHandoff] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "iterations": self.iterations,
            "tool_calls": self.tool_calls,
            "tokens_used": self.tokens_used,
            "duration_ms": self.duration_ms,
            "metadata": self.metadata,
            "handoff": self.handoff.to_dict() if self.handoff else None,
        }


class BaseAgent(ABC):
    def __init__(
        self,
        config: AgentConfig,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
        parent_id: Optional[str] = None,
        knowledge_modules: Optional[List[str]] = None,
    ):
        self.config = config
        self.llm_service = llm_service
        self.tools = tools
        self.event_emitter = event_emitter
        self.parent_id = parent_id
        self.knowledge_modules = knowledge_modules or []
        self._agent_id = f"agent_{uuid.uuid4().hex[:8]}"
        self._state = AgentState(
            agent_id=self._agent_id,
            agent_name=config.name,
            agent_type=config.agent_type.value,
            parent_id=parent_id,
            max_iterations=config.max_iterations,
            knowledge_modules=self.knowledge_modules,
        )
        self._iteration = 0
        self._total_tokens = 0
        self._tool_calls = 0
        self._cancelled = False
        self._cancel_callback = None
        self._registered = False
        self._runtime_session_checkpoint_store = None
        self._incoming_handoff: Optional[TaskHandoff] = None
        self._insights: List[str] = []
        self._work_completed: List[str] = []
        self._timeout_config = self._get_timeout_config()

    @property
    def name(self) -> str:
        return self.config.name

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def state(self) -> AgentState:
        return self._state

    @property
    def agent_type(self) -> AgentType:
        return self.config.agent_type

    def _get_timeout_config(self) -> Dict[str, int]:
        from app.core.config import settings
        timeout_getter = getattr(self.llm_service, "get_agent_timeout_config", None)
        if callable(timeout_getter):
            resolved = timeout_getter()
            if isinstance(resolved, dict):
                return resolved
        return {
            "llm_first_token_timeout": getattr(settings, "LLM_FIRST_TOKEN_TIMEOUT", 30),
            "llm_stream_timeout": getattr(settings, "LLM_STREAM_TIMEOUT", 60),
            "agent_timeout": getattr(settings, "AGENT_TIMEOUT_SECONDS", 1800),
            "sub_agent_timeout": getattr(settings, "SUB_AGENT_TIMEOUT_SECONDS", 600),
            "tool_timeout": getattr(settings, "TOOL_TIMEOUT_SECONDS", 60),
        }

    def _register_to_registry(self, task: Optional[str] = None) -> None:
        if self._registered:
            return
        agent_registry.register_agent(
            agent_id=self._agent_id,
            agent_name=self.config.name,
            agent_type=self.config.agent_type.value,
            task=task or self._state.task or "Initializing",
            parent_id=self.parent_id,
            agent_instance=self,
            state=self._state,
            knowledge_modules=self.knowledge_modules,
        )
        try:
            message_bus.create_queue(self._agent_id)
        except Exception:
            pass
        self._registered = True

    def configure_runtime_session_persistence(self, *, task_id: str, checkpoint_store: Any) -> None:
        self._state.metadata["task_id"] = str(task_id)
        self._state.task_context["task_id"] = str(task_id)
        self._runtime_session_checkpoint_store = checkpoint_store

    async def restore_runtime_session_from_checkpoint(self) -> dict[str, Any] | None:
        if self._runtime_session_checkpoint_store is None:
            return None
        task_id = str(self._state.metadata.get("task_id") or self._state.task_context.get("task_id") or "").strip()
        if not task_id:
            return None
        restored = await self._runtime_session_checkpoint_store.restore_agent_runtime_session_checkpoint(
            task_id=task_id,
            agent_state=self._state,
        )
        if restored is not None and self._state.metadata.get("runtime_session_state"):
            runtime_session_state = self._state.metadata.get("runtime_session_state") or {}
            self._state.metadata["runtime_session_state"] = dict(runtime_session_state)
            self._apply_runtime_memory_prompt_overlay()
        return restored

    async def _persist_runtime_session_checkpoint_if_needed(self) -> None:
        if self._runtime_session_checkpoint_store is None:
            return
        task_id = str(self._state.metadata.get("task_id") or self._state.task_context.get("task_id") or "").strip()
        if not task_id:
            return
        await self._runtime_session_checkpoint_store.persist_agent_runtime_session_checkpoint(
            task_id=task_id,
            agent_state=self._state,
        )

    def set_parent_id(self, parent_id: str) -> None:
        self.parent_id = parent_id
        self._state.parent_id = parent_id

    def check_messages(self) -> List[AgentMessage]:
        try:
            return message_bus.get_messages(self._agent_id, unread_only=True, mark_as_read=True)
        except Exception:
            return []

    def set_cancel_callback(self, callback) -> None:
        self._cancel_callback = callback

    def cancel(self) -> None:
        self._cancelled = True
        logger.info("[%s] Cancel requested", self.name)

    @property
    def is_cancelled(self) -> bool:
        if self._cancelled:
            return True
        if self._cancel_callback and self._cancel_callback():
            self._cancelled = True
            return True
        return False

    def receive_handoff(self, handoff: TaskHandoff) -> None:
        self._incoming_handoff = handoff

    def get_handoff_context(self) -> str:
        return self._incoming_handoff.to_prompt_context() if self._incoming_handoff else ""

    def create_handoff(
        self,
        *,
        to_agent: str,
        summary: str,
        work_completed: Optional[List[str]] = None,
        key_findings: Optional[List[Dict[str, Any]]] = None,
        insights: Optional[List[str]] = None,
        suggested_actions: Optional[List[Dict[str, Any]]] = None,
        attention_points: Optional[List[str]] = None,
        priority_areas: Optional[List[str]] = None,
        context_data: Optional[Dict[str, Any]] = None,
        confidence: float = 0.8,
    ) -> TaskHandoff:
        return TaskHandoff(
            from_agent=self.config.agent_type.value,
            to_agent=to_agent,
            summary=summary,
            work_completed=work_completed or self._work_completed.copy(),
            key_findings=key_findings or [],
            insights=insights or self._insights.copy(),
            suggested_actions=suggested_actions or [],
            attention_points=attention_points or [],
            priority_areas=priority_areas or [],
            context_data=context_data or {},
            confidence=confidence,
        )

    def record_work(self, item: str) -> None:
        self._work_completed.append(item)

    def add_insight(self, insight: str) -> None:
        self._insights.append(insight)

    def _agent_log_label(self) -> str:
        return f"{self.config.name} Agent"

    def _decorate_message(self, message: str) -> str:
        clean = (message or "").strip()
        prefix = f"[{self._agent_log_label()}]"
        if clean.startswith(prefix):
            return clean
        return f"{prefix} {clean}" if clean else prefix

    def _decorate_metadata(self, metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        merged = dict(metadata or {})
        merged.setdefault("agent_name", self.config.name)
        merged.setdefault("agent_type", self.config.agent_type.value)
        merged.setdefault("agent_label", self._agent_log_label())
        return merged

    async def emit_debug_payload(
        self,
        event_type: str,
        payload: Dict[str, Any],
        *,
        message: Optional[str] = None,
        phase: Optional[str] = None,
        tool_name: Optional[str] = None,
    ) -> None:
        if not self.event_emitter:
            return
        try:
            from app.services.agent.event_manager import AgentEventData

            metadata = self._decorate_metadata({"payload": payload})
            await self.event_emitter.emit(
                AgentEventData(
                    event_type=event_type,
                    phase=phase,
                    message=self._decorate_message(message or event_type.replace("_", " ")),
                    tool_name=tool_name,
                    metadata=metadata,
                )
            )
        except Exception:
            logger.debug("Debug payload emission failed for %s", event_type, exc_info=True)

    async def emit_agent_start_debug(self, input_data: Dict[str, Any]) -> None:
        await self.emit_debug_payload(
            "agent_start",
            {
                "agent_name": self.config.name,
                "agent_type": self.config.agent_type.value,
                "input_data": input_data,
            },
            message=f"{self.config.name} agent started",
        )

    async def emit_prompt_debug(self, role: str, content: str, *, iteration: int = 0) -> None:
        await self.emit_debug_payload(
            f"prompt_{role}",
            {"role": role, "content": content, "iteration": iteration},
            message=f"{role} prompt captured",
        )

    async def emit_model_response_debug(self, content: str, *, iteration: int = 0) -> None:
        await self.emit_debug_payload(
            "model_response_raw",
            {"content": content, "iteration": iteration},
            message="raw model response captured",
        )

    async def emit_handoff_debug(self, direction: str, handoff: TaskHandoff) -> None:
        await self.emit_debug_payload(
            f"handoff_{direction}",
            handoff.to_dict(),
            message=f"handoff {direction}: {handoff.from_agent} -> {handoff.to_agent}",
        )

    async def emit_event(
        self,
        event_type: str,
        message: str,
        *,
        metadata: Optional[Dict[str, Any]] = None,
        tool_name: Optional[str] = None,
        tool_input: Optional[Dict[str, Any]] = None,
        tool_output: Optional[Dict[str, Any]] = None,
        tool_duration_ms: Optional[int] = None,
    ) -> None:
        if not self.event_emitter:
            return
        try:
            from app.services.agent.event_manager import AgentEventData
            await self.event_emitter.emit(
                AgentEventData(
                    event_type=event_type,
                    message=self._decorate_message(message),
                    tool_name=tool_name,
                    tool_input=tool_input,
                    tool_output=tool_output,
                    tool_duration_ms=tool_duration_ms,
                    metadata=self._decorate_metadata(metadata),
                )
            )
        except Exception:
            logger.debug("Event emission failed for %s", event_type, exc_info=True)

    async def emit_thinking(self, message: str) -> None:
        await self.emit_event("thinking", message)

    async def emit_thinking_start(self) -> None:
        await self.emit_event("thinking_start", "Thinking...")

    async def emit_thinking_token(self, token: str, accumulated: str) -> None:
        await self.emit_event("thinking_token", "", metadata={"token": token, "accumulated": accumulated})

    async def emit_thinking_end(self, full_response: str) -> None:
        await self.emit_event("thinking_end", "Thinking complete", metadata={"accumulated": full_response})

    async def emit_llm_thought(self, thought: str, iteration: int) -> None:
        await self.emit_event("llm_thought", thought, metadata={"iteration": iteration, "thought": thought})
        await self.emit_debug_payload(
            "react_thought",
            {"thought": thought, "iteration": iteration},
            message=f"react thought #{iteration}",
        )

    async def emit_llm_decision(self, decision: str, reason: str = "") -> None:
        await self.emit_event("llm_decision", decision, metadata={"reason": reason})

    async def emit_llm_complete(self, result_summary: str, tokens_used: int) -> None:
        await self.emit_event("llm_complete", result_summary, metadata={"tokens_used": tokens_used})

    async def emit_llm_action(self, action: str, action_input: Dict[str, Any]) -> None:
        await self.emit_event("llm_action", action, metadata={"action_input": action_input})
        await self.emit_debug_payload(
            "react_action",
            {"action": action, "action_input": action_input, "iteration": self._iteration},
            message=f"react action: {action}",
        )

    async def emit_llm_observation(self, observation: str) -> None:
        await self.emit_event("llm_observation", observation[:300], metadata={"observation": observation[:2000]})
        await self.emit_debug_payload(
            "react_observation",
            {"observation": observation[:2000], "iteration": self._iteration},
            message="react observation captured",
        )

    async def emit_tool_call(self, tool_name: str, tool_input: Dict[str, Any]) -> None:
        await self.emit_event("tool_call", f"Calling tool: {tool_name}", tool_name=tool_name, tool_input=tool_input)

    async def emit_tool_result(self, tool_name: str, result: str, duration_ms: int) -> None:
        await self.emit_event(
            "tool_result",
            f"Tool {tool_name} completed ({duration_ms}ms)",
            tool_name=tool_name,
            tool_output={"result": (result or "")[:2000]},
            tool_duration_ms=duration_ms,
        )

    async def emit_finding(self, title: str, severity: str, vuln_type: str, file_path: str = "", is_verified: bool = False) -> None:
        event_type = "finding_verified" if is_verified else "finding_new"
        await self.emit_event(
            event_type,
            f"[{severity.upper()}] {title}",
            metadata={"vulnerability_type": vuln_type, "file_path": file_path, "is_verified": is_verified},
        )

    def compress_messages_if_needed(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        max_messages = 40
        if len(messages) <= max_messages:
            return messages
        return [messages[0]] + messages[-(max_messages - 1):]

    async def stream_llm_call(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        auto_compress: bool = True,
    ) -> Tuple[str, int]:
        if auto_compress:
            messages = self.compress_messages_if_needed(messages)
        if self.is_cancelled:
            return "", 0

        accumulated = ""
        total_tokens = 0
        await self.emit_thinking_start()
        try:
            stream = self.llm_service.chat_completion_stream(
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
            )
            iterator = stream.__aiter__()
            first_timeout = float(self._timeout_config.get("llm_first_token_timeout", 30))
            stream_timeout = float(self._timeout_config.get("llm_stream_timeout", 60))
            first_token = False
            while True:
                if self.is_cancelled:
                    break
                try:
                    timeout = first_timeout if not first_token else stream_timeout
                    chunk = await asyncio.wait_for(iterator.__anext__(), timeout=timeout)
                except StopAsyncIteration:
                    break
                except asyncio.TimeoutError:
                    accumulated = accumulated or "[LLM timeout]"
                    break

                if chunk.get("type") == "token":
                    first_token = True
                    token = chunk.get("content", "")
                    accumulated = chunk.get("accumulated", accumulated + token)
                    await self.emit_thinking_token(token, accumulated)
                    await asyncio.sleep(0)
                elif chunk.get("type") == "done":
                    accumulated = chunk.get("content", accumulated)
                    usage = chunk.get("usage") or {}
                    total_tokens = usage.get("total_tokens", 0)
                    break
                elif chunk.get("type") == "error":
                    accumulated = chunk.get("accumulated", accumulated)
                    error_message = chunk.get("user_message") or chunk.get("error") or "Unknown error"
                    accumulated = accumulated or f"[API_ERROR:{chunk.get('error_type', 'unknown')}] {error_message}"
                    usage = chunk.get("usage") or {}
                    total_tokens = usage.get("total_tokens", 0)
                    break
        except Exception as exc:
            logger.error("[%s] Unexpected error in stream_llm_call: %s", self.name, exc, exc_info=True)
            await self.emit_event("error", f"LLM call error: {exc}")
            accumulated = f"[LLM调用错误: {str(exc)}] 请重试。"
        finally:
            await self.emit_thinking_end(accumulated)
        return accumulated, total_tokens

    def _memory_runtime_metadata(self) -> Dict[str, Any]:
        metadata = self._state.metadata.setdefault("memory_runtime", {})
        metadata.setdefault("instructions", [])
        metadata.setdefault("recalls", [])
        metadata.setdefault("source", None)
        return metadata

    def _compose_runtime_memory_prompt(self) -> str:
        from app.services.finding_runtime.models import RuntimeMemoryRecord
        from app.services.runtime_core.memory_runtime import build_runtime_memory_prompt

        memory_runtime = self._memory_runtime_metadata()
        base_prompt = str(memory_runtime.get("base_system_prompt") or self.config.system_prompt or "").strip()
        rendered: List[str] = []
        for bucket in ("instructions", "recalls"):
            for item in memory_runtime.get(bucket) or []:
                if not isinstance(item, dict):
                    continue
                try:
                    record = RuntimeMemoryRecord(**item)
                except TypeError:
                    continue
                rendered.append(record)
        return build_runtime_memory_prompt(base_prompt, rendered)

    def _apply_runtime_memory_prompt_overlay(self) -> None:
        memory_runtime = self._state.metadata.get("memory_runtime") or {}
        if not memory_runtime:
            return
        if memory_runtime.get("base_system_prompt") is None:
            memory_runtime["base_system_prompt"] = self.config.system_prompt or ""
        composed = self._compose_runtime_memory_prompt()
        if composed:
            self.config.system_prompt = composed
            self._state.system_prompt = composed

    def load_runtime_memory_bundle(self, bundle: Any, *, source: str = "preload") -> None:
        memory_runtime = self._memory_runtime_metadata()
        if memory_runtime.get("base_system_prompt") is None:
            memory_runtime["base_system_prompt"] = self.config.system_prompt or ""
        memory_runtime["instructions"] = [
            {
                "memory_kind": item.memory_kind,
                "title": item.title,
                "source_type": item.source_type,
                "source_ref": item.source_ref,
                "content": item.content,
                "relevance_score": item.relevance_score,
                "metadata": dict(item.metadata or {}),
            }
            for item in getattr(bundle, "instructions", []) or []
        ]
        memory_runtime["recalls"] = [
            {
                "memory_kind": item.memory_kind,
                "title": item.title,
                "source_type": item.source_type,
                "source_ref": item.source_ref,
                "content": item.content,
                "relevance_score": item.relevance_score,
                "metadata": dict(item.metadata or {}),
            }
            for item in getattr(bundle, "recalls", []) or []
        ]
        memory_runtime["source"] = str(source or "preload")
        memory_runtime["loaded_at"] = datetime.now(timezone.utc).isoformat()
        self._apply_runtime_memory_prompt_overlay()
        self._sync_runtime_session_state_view()

    def _tool_runtime_metadata(self) -> Dict[str, Any]:
        metadata = self._state.metadata.setdefault("tool_runtime", {})
        metadata.setdefault("records", [])
        metadata.setdefault("events", [])
        metadata.setdefault("hook_records", [])
        metadata.setdefault("checkpoints", [])
        return metadata

    def _sync_runtime_session_state_view(self) -> None:
        metadata = self._state.metadata
        task_id = str(metadata.get("task_id") or self._state.task_context.get("task_id") or "").strip() or None
        runtime_state = build_legacy_agent_runtime_state(
            session_id=self.agent_id,
            agent_type=self.agent_type.value,
            interaction_state=metadata.get("interaction_runtime") or {},
            tool_runtime=metadata.get("tool_runtime") or {},
            memory_runtime=metadata.get("memory_runtime") or {},
        )
        metadata["runtime_session_state"] = runtime_state.model_dump()
        session_key = f"legacy:{task_id}:{self.agent_id}" if task_id else f"legacy:{self.agent_id}"
        entry = runtime_session_registry.upsert(
            session_key=session_key,
            runtime_state=runtime_state,
            agent_id=self.agent_id,
            agent_type=self.agent_type.value,
            task_id=task_id,
            source="legacy",
        )
        metadata["runtime_session_ref"] = {
            "session_key": entry["session_key"],
            "session_id": entry["session_id"],
            "task_id": entry["task_id"],
            "agent_id": entry["agent_id"],
            "agent_type": entry["agent_type"],
            "source": entry["source"],
            "updated_at": entry["updated_at"],
        }

    def _record_tool_runtime_lifecycle(
        self,
        *,
        event_name: str,
        tool_name: str,
        permission: ToolPermissionDecision | None = None,
        error_message: str | None = None,
    ) -> None:
        runtime_metadata = self._tool_runtime_metadata()
        event = {
            "event": event_name,
            "tool_name": tool_name,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "permission_source": permission.source if permission else None,
            "permission_mode": permission.mode if permission else None,
            "error_message": error_message,
        }
        events = runtime_metadata.setdefault("events", [])
        events.append(event)
        if len(events) > 200:
            del events[:-200]
        runtime_metadata["last_event"] = dict(event)
        self._record_tool_runtime_hook_matches(
            event_name=event_name,
            tool_name=tool_name,
            permission=permission,
            error_message=error_message,
        )

    def _record_tool_runtime_checkpoint(
        self,
        *,
        event_name: str,
        tool_name: str,
        skill_ref: str | None,
        matched_hooks: list[dict[str, Any]],
        permission: ToolPermissionDecision | None = None,
        error_message: str | None = None,
    ) -> None:
        runtime_metadata = self._tool_runtime_metadata()
        checkpoint = {
            "checkpoint_type": AuditCheckpointType.AUTO.value,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "state_payload": {
                "kind": "runtime_hook",
                "event": event_name,
                "tool_name": tool_name,
                "agent_type": self.agent_type.value,
                "skill_ref": skill_ref,
                "matched_hooks": [dict(item) for item in matched_hooks],
                "reason": error_message,
                "source": permission.source if permission else None,
                "mode": permission.mode if permission else None,
            },
        }
        checkpoints = runtime_metadata.setdefault("checkpoints", [])
        checkpoints.append(checkpoint)
        if len(checkpoints) > 200:
            del checkpoints[:-200]
        runtime_metadata["last_checkpoint"] = dict(checkpoint)

    def _record_tool_runtime_hook_matches(
        self,
        *,
        event_name: str,
        tool_name: str,
        permission: ToolPermissionDecision | None = None,
        error_message: str | None = None,
    ) -> None:
        runtime_metadata = self._tool_runtime_metadata()
        session_hooks = runtime_metadata.get("session_hooks") or {}
        hook_records = runtime_metadata.setdefault("hook_records", [])
        wrote_hook_record = False
        for skill_ref, hook_config in session_hooks.items():
            matched_hooks = match_runtime_event_hooks(hook_config, event_name=event_name, tool_name=tool_name)
            if not matched_hooks:
                continue
            record = {
                "event": event_name,
                "tool_name": tool_name,
                "skill_ref": skill_ref,
                "matched_hooks": matched_hooks,
                "recorded_at": datetime.now(timezone.utc).isoformat(),
                "permission_source": permission.source if permission else None,
                "permission_mode": permission.mode if permission else None,
                "error_message": error_message,
            }
            hook_records.append(record)
            self._record_tool_runtime_checkpoint(
                event_name=event_name,
                tool_name=tool_name,
                skill_ref=skill_ref,
                matched_hooks=matched_hooks,
                permission=permission,
                error_message=error_message,
            )
            wrote_hook_record = True
        persist_without_hook = (
            event_name == "PermissionDenied"
            and permission is not None
            and permission.source == "permission_rule"
        )
        if persist_without_hook and not wrote_hook_record:
            self._record_tool_runtime_checkpoint(
                event_name=event_name,
                tool_name=tool_name,
                skill_ref=None,
                matched_hooks=[],
                permission=permission,
                error_message=error_message,
            )
        if len(hook_records) > 200:
            del hook_records[:-200]
        if hook_records:
            runtime_metadata["last_hook_record"] = dict(hook_records[-1])

    def _record_tool_runtime_event(
        self,
        *,
        tool_name: str,
        status: str,
        duration_ms: int,
        permission: ToolPermissionDecision | None = None,
        error_message: str | None = None,
    ) -> None:
        runtime_metadata = self._tool_runtime_metadata()
        record = {
            "tool_name": tool_name,
            "status": status,
            "duration_ms": max(0, int(duration_ms)),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "permission_source": permission.source if permission else None,
            "permission_mode": permission.mode if permission else None,
            "error_message": error_message,
        }
        records = runtime_metadata.setdefault("records", [])
        records.append(record)
        if len(records) > 100:
            del records[:-100]
        runtime_metadata["last_record"] = dict(record)

    def _evaluate_tool_permission(self, tool_name: str, tool: Any, tool_input: Dict[str, Any]) -> ToolPermissionDecision:
        interaction_state = self._state.metadata.get("interaction_runtime") or {}
        explicit = resolve_permission_rule_decision(
            interaction_state.get("permission_rules"),
            agent_type=self.agent_type.value,
            tool_name=tool_name,
        )
        if explicit is not None:
            return explicit

        permission_mode = str(interaction_state.get("permission_mode") or "default").strip().lower()
        if permission_mode != "plan":
            return ToolPermissionDecision(allowed=True, source="runtime", mode="allow")
        if tool_name in {"TodoWrite", "AskUser", "EnterPlanMode", "ExitPlanMode"}:
            return ToolPermissionDecision(allowed=True, source="runtime", mode="allow")
        try:
            is_read_only = bool(tool.is_read_only(**tool_input))
        except Exception:
            is_read_only = False
        if is_read_only:
            return ToolPermissionDecision(allowed=True, source="runtime", mode="allow")
        return ToolPermissionDecision(
            allowed=False,
            reason=f"Tool '{tool_name}' is blocked in plan mode until the user approves execution.",
            source="permission_mode",
            mode="deny",
        )

    async def execute_tool(self, tool_name: str, tool_input: Dict[str, Any]) -> str:
        if self.is_cancelled:
            return "Task cancelled."
        tool = self.tools.get(tool_name)
        if not tool:
            return f"Error: tool '{tool_name}' not found. Available: {list(self.tools.keys())}"

        self._tool_calls += 1
        await self.emit_tool_call(tool_name, tool_input)
        start = time.time()
        timeout = self._timeout_config.get("tool_timeout", 60)
        execution_input = dict(tool_input or {})
        if getattr(tool, "requires_agent_context", False):
            execution_input.setdefault("_agent", self)
        permission = self._evaluate_tool_permission(tool_name, tool, dict(tool_input or {}))
        if permission.allowed:
            self._record_tool_runtime_lifecycle(
                event_name="PreToolUse",
                tool_name=tool_name,
                permission=permission,
                error_message=None,
            )
        if not permission.allowed:
            denial_message = permission.reason or "Tool permission denied"
            self._record_tool_runtime_lifecycle(
                event_name="PermissionDenied",
                tool_name=tool_name,
                permission=permission,
                error_message=denial_message,
            )
            self._record_tool_runtime_event(
                tool_name=tool_name,
                status="denied",
                duration_ms=0,
                permission=permission,
                error_message=denial_message,
            )
            self._sync_runtime_session_state_view()
            await self._persist_runtime_session_checkpoint_if_needed()
            await self.emit_tool_result(tool_name, denial_message, 0)
            return denial_message
        try:
            result = await asyncio.wait_for(tool.execute(**execution_input), timeout=timeout)
            duration_ms = int((time.time() - start) * 1000)
            if getattr(result, "success", False):
                output = str(getattr(result, "data", ""))
                if getattr(result, "metadata", None):
                    metadata = result.metadata
                    if isinstance(metadata, dict):
                        if "issues" in metadata:
                            output += "\n\nIssues:\n" + json.dumps(metadata["issues"], ensure_ascii=False, indent=2)
                        if "findings" in metadata:
                            output += "\n\nFindings:\n" + json.dumps(metadata["findings"][:10], ensure_ascii=False, indent=2)
                self._record_tool_runtime_lifecycle(
                    event_name="PostToolUse",
                    tool_name=tool_name,
                    permission=permission,
                    error_message=None,
                )
                self._record_tool_runtime_event(
                    tool_name=tool_name,
                    status="completed",
                    duration_ms=duration_ms,
                    permission=permission,
                    error_message=None,
                )
                self._sync_runtime_session_state_view()
                await self._persist_runtime_session_checkpoint_if_needed()
                await self.emit_tool_result(tool_name, output, duration_ms)
                return output[:6000] if len(output) > 6000 else output
            error = str(getattr(result, "error", "Unknown tool error"))
            self._record_tool_runtime_lifecycle(
                event_name="PostToolUseFailure",
                tool_name=tool_name,
                permission=permission,
                error_message=error,
            )
            self._record_tool_runtime_event(
                tool_name=tool_name,
                status="failed",
                duration_ms=duration_ms,
                permission=permission,
                error_message=error,
            )
            self._sync_runtime_session_state_view()
            await self._persist_runtime_session_checkpoint_if_needed()
            await self.emit_tool_result(tool_name, error, duration_ms)
            return f"Tool execution failed: {error}"
        except asyncio.TimeoutError:
            duration_ms = int((time.time() - start) * 1000)
            self._record_tool_runtime_lifecycle(
                event_name="PostToolUseFailure",
                tool_name=tool_name,
                permission=permission,
                error_message=f"Timeout ({timeout}s)",
            )
            self._record_tool_runtime_event(
                tool_name=tool_name,
                status="timeout",
                duration_ms=duration_ms,
                permission=permission,
                error_message=f"Timeout ({timeout}s)",
            )
            self._sync_runtime_session_state_view()
            await self._persist_runtime_session_checkpoint_if_needed()
            await self.emit_tool_result(tool_name, f"Timeout ({timeout}s)", duration_ms)
            return f"Tool '{tool_name}' timed out after {timeout}s"
        except asyncio.CancelledError:
            self._record_tool_runtime_lifecycle(
                event_name="PostToolUseFailure",
                tool_name=tool_name,
                permission=permission,
                error_message="Task cancelled.",
            )
            self._record_tool_runtime_event(
                tool_name=tool_name,
                status="cancelled",
                duration_ms=int((time.time() - start) * 1000),
                permission=permission,
                error_message="Task cancelled.",
            )
            self._sync_runtime_session_state_view()
            await self._persist_runtime_session_checkpoint_if_needed()
            return "Task cancelled."
        except Exception as exc:
            logger.error("Tool execution error for %s: %s", tool_name, exc, exc_info=True)
            self._record_tool_runtime_lifecycle(
                event_name="PostToolUseFailure",
                tool_name=tool_name,
                permission=permission,
                error_message=str(exc),
            )
            self._record_tool_runtime_event(
                tool_name=tool_name,
                status="error",
                duration_ms=int((time.time() - start) * 1000),
                permission=permission,
                error_message=str(exc),
            )
            self._sync_runtime_session_state_view()
            await self._persist_runtime_session_checkpoint_if_needed()
            return f"Tool execution error ({tool_name}): {exc}"

    async def call_tool(self, tool_name: str, **kwargs) -> Any:
        tool = self.tools.get(tool_name)
        if not tool:
            raise ValueError(f"Tool not found: {tool_name}")
        return await tool.execute(**kwargs)

    def get_tools_description(self) -> str:
        tools_info = []
        for name, tool in self.tools.items():
            if name.startswith("_"):
                continue
            tools_info.append(f"- {name}: {getattr(tool, 'description', 'No description')}")
        return "\n".join(tools_info)

    @abstractmethod
    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        raise NotImplementedError
