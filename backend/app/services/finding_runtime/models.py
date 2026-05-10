from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class RuntimeSessionState(StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class RuntimeMessageRole(StrEnum):
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    HANDOFF = "handoff"


class RuntimeContinueReason(StrEnum):
    NEXT_TURN = "next_turn"
    TERMINAL_ACTION_NUDGE = "terminal_action_nudge"
    LEGACY_TOOL_SYNTAX_NUDGE = "legacy_tool_syntax_nudge"
    MAX_OUTPUT_TOKENS_ESCALATE = "max_output_tokens_escalate"
    MAX_OUTPUT_TOKENS_RECOVERY = "max_output_tokens_recovery"
    REACTIVE_COMPACT_RETRY = "reactive_compact_retry"
    COLLAPSE_DRAIN_RETRY = "collapse_drain_retry"
    STOP_HOOK_BLOCKING = "stop_hook_blocking"
    TOKEN_BUDGET_CONTINUATION = "token_budget_continuation"


class RuntimeStopReason(StrEnum):
    COMPLETED = "completed"
    BLOCKING_LIMIT = "blocking_limit"
    PROMPT_TOO_LONG = "prompt_too_long"
    IMAGE_ERROR = "image_error"
    MODEL_ERROR = "model_error"
    ABORTED_STREAMING = "aborted_streaming"
    ABORTED_TOOLS = "aborted_tools"
    STOP_HOOK_PREVENTED = "stop_hook_prevented"
    HOOK_STOPPED = "hook_stopped"
    MAX_TURNS = "max_turns"


class RuntimeTerminalAction(StrEnum):
    FINALIZE_FINDING = "finalize_finding"
    FINALIZE_TRIAGE_BATCH = "finalize_triage_batch"
    FINALIZE_TRIAGE = "finalize_triage"
    NATURAL_END_WITHOUT_TERMINAL_ACTION = "natural_end_without_terminal_action"
    HOOK_STOP = "hook_stop"
    MAX_TURNS = "max_turns"


class RuntimeCompletionMode(StrEnum):
    FINALIZE_TOOL = "finalize_tool"
    LEGACY_FINAL_JSON = "legacy_final_json"
    FALLBACK_RECOVERED = "fallback_recovered"
    INCOMPLETE = "incomplete"


@dataclass(slots=True)
class TranscriptItem:
    role: RuntimeMessageRole
    content: str
    name: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ToolCallRequest:
    id: str
    name: str
    input: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ToolExecutionPayload:
    content: str
    output_payload: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    is_error: bool = False
    context_modifier: dict[str, Any] | None = None


@dataclass(slots=True)
class ToolExecutionRecord:
    tool_call_id: str
    request: ToolCallRequest
    status: str
    is_concurrency_safe: bool
    result: ToolExecutionPayload
    error_message: str | None = None
    duration_ms: int | None = None
    lifecycle: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuntimeModelResponse:
    content: str = ""
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    stop_reason: str | None = None
    recoverable_error_kind: str | None = None
    recoverable_error_message: str | None = None
    usage: dict[str, Any] = field(default_factory=dict)
    native_tool_call_count: int = 0
    has_terminal_tool_call: bool = False


@dataclass(slots=True)
class RuntimeSkillCatalogSnapshot:
    available_skills: list[dict[str, Any]] = field(default_factory=list)
    matched_skills: list[dict[str, Any]] = field(default_factory=list)
    prompt: str = ""
    route_message: str = ""
    route_plan: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuntimeMemoryRecord:
    memory_kind: str
    title: str
    source_type: str
    source_ref: str
    content: str
    relevance_score: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RuntimeMemoryBundle:
    instructions: list[RuntimeMemoryRecord] = field(default_factory=list)
    recalls: list[RuntimeMemoryRecord] = field(default_factory=list)

    @property
    def all_memories(self) -> list[RuntimeMemoryRecord]:
        return [*self.instructions, *self.recalls]


@dataclass(slots=True)
class RuntimeSessionSnapshot:
    session: Any
    messages: list[Any] = field(default_factory=list)
    turns: list[Any] = field(default_factory=list)
    checkpoints: list[Any] = field(default_factory=list)
    tool_calls: list[Any] = field(default_factory=list)
    skills: list[Any] = field(default_factory=list)
    skill_invocations: list[Any] = field(default_factory=list)
    memories: list[Any] = field(default_factory=list)
    handoffs: list[Any] = field(default_factory=list)


@dataclass(slots=True)
class TurnExecutionResult:
    turn_id: str
    stop_reason: RuntimeStopReason | None
    assistant_message_id: str | None = None
    tool_call_ids: list[str] = field(default_factory=list)
    tool_result_message_ids: list[str] = field(default_factory=list)
    transition: RuntimeContinueReason | None = None
    terminal_action: RuntimeTerminalAction | None = None
    completion_mode: RuntimeCompletionMode | None = None
    final_payload: dict[str, Any] | None = None
