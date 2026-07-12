from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


PayloadExtractor = Callable[[Any], Any | None]
PayloadBuilder = Callable[[Any], Any]
PromptBuilder = Callable[[], list[str]]
ToolFactory = Callable[[], Any]
ToolRegistryBuilder = Callable[..., Any]


@dataclass(slots=True)
class AgentRuntimeSpec:
    agent_type: str
    default_model_name: str
    default_user_message: str
    require_terminal_action: bool = False
    terminal_action_nudge_limit: int = 1
    payload_extractor: PayloadExtractor | None = None
    finalizer_prompts: PromptBuilder | None = None
    fallback_payload_builder: PayloadBuilder | None = None
    finalizer_tool_factory: ToolFactory | None = None
    tool_registry_builder: ToolRegistryBuilder | None = None

    def build_finalizer_tool(self) -> Any | None:
        if self.finalizer_tool_factory is None:
            return None
        return self.finalizer_tool_factory()

    def build_finalizer_prompts(self) -> list[str]:
        if self.finalizer_prompts is None:
            return []
        return list(self.finalizer_prompts() or [])


def build_finding_runtime_spec() -> AgentRuntimeSpec:
    from app.services.finding_runtime.bridge import FindingRuntimeBridge
    from app.services.finding_runtime.tools.finalize_finding import FinalizeFindingTool
    from app.services.runtime_core import build_runtime_tool_registry

    return AgentRuntimeSpec(
        agent_type="finding",
        default_model_name="finding-runtime",
        default_user_message="Continue auditing the current Finding target.",
        require_terminal_action=True,
        terminal_action_nudge_limit=2,
        payload_extractor=FindingRuntimeBridge.extract_final_payload,
        finalizer_prompts=FindingRuntimeBridge._default_finalizer_prompts,
        fallback_payload_builder=FindingRuntimeBridge._default_fallback_payload,
        finalizer_tool_factory=FinalizeFindingTool,
        tool_registry_builder=build_runtime_tool_registry,
    )


def _triage_fallback_payload(_snapshot: Any) -> dict[str, Any]:
    from app.services.finding_runtime.models import RuntimeCompletionMode

    return {
        "findings": [],
        "summary": "Triage batch did not complete - FinalizeTriageBatch was not called.",
        "runtime_completion_mode": RuntimeCompletionMode.INCOMPLETE.value,
        "is_partial": True,
        "requires_retry": True,
    }


def _extract_tool_final_payload(snapshot: Any) -> dict[str, Any] | None:
    for message in reversed(getattr(snapshot, "messages", []) or []):
        payload = getattr(message, "payload", {}) or {}
        output = payload.get("output") if isinstance(payload, dict) else None
        if isinstance(output, dict) and isinstance(output.get("final_payload"), dict):
            return dict(output["final_payload"])
        if isinstance(payload, dict) and isinstance(payload.get("final_payload"), dict):
            return dict(payload["final_payload"])
    return None


def build_triage_runtime_spec() -> AgentRuntimeSpec:
    from app.services.runtime_core import build_runtime_tool_registry

    return AgentRuntimeSpec(
        agent_type="triage",
        default_model_name="triage-runtime",
        default_user_message=(
            "Claim the next scan finding batch, load every raw finding and required source context, "
            "then call FinalizeTriageBatch with a decision for every finding_id in the batch."
        ),
        require_terminal_action=True,
        terminal_action_nudge_limit=2,
        payload_extractor=_extract_tool_final_payload,
        finalizer_prompts=None,
        fallback_payload_builder=_triage_fallback_payload,
        finalizer_tool_factory=None,
        tool_registry_builder=build_runtime_tool_registry,
    )
