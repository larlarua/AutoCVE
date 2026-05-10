from __future__ import annotations

from typing import Any, Callable

from app.db.session import get_sync_session_factory
from app.services.agent_runtime.adapter import AgentRuntimeAdapter
from app.services.agent_runtime.specs import AgentRuntimeSpec
from app.services.finding_runtime.bridge import RuntimeLLMModelClient
from app.services.finding_runtime.memory import RuntimeMemoryManager
from app.services.finding_runtime.models import (
    RuntimeCompletionMode,
    RuntimeMessageRole,
    RuntimeStopReason,
    RuntimeTerminalAction,
    TranscriptItem,
    TurnExecutionResult,
)
from app.services.finding_runtime.runner import FindingRuntimeRunner
from app.services.finding_runtime.session_store import AuditSessionStore
from app.services.finding_runtime.skills import RuntimeSkillCatalog
from app.services.finding_runtime.tooling import ToolOrchestrator, ToolRegistry

FINALIZER_ELIGIBLE_STOP_REASONS = {
    RuntimeStopReason.COMPLETED,
    RuntimeStopReason.MAX_TURNS,
    RuntimeStopReason.HOOK_STOPPED,
}


class AgentRuntimeBridge:
    def __init__(
        self,
        *,
        llm_service,
        tools: dict[str, Any],
        spec: AgentRuntimeSpec,
        user_id: str | None = None,
        session_factory=None,
    ):
        self._llm_service = llm_service
        self._tools = tools
        self._spec = spec
        self._user_id = user_id
        self._session_store = AuditSessionStore(session_factory=session_factory or get_sync_session_factory())

    @property
    def agent_type(self) -> str:
        return self._spec.agent_type

    async def run(
        self,
        *,
        project_id: str,
        task_id: str | None,
        system_prompt: str,
        recon_payload: dict[str, Any],
        user_message: str | None = None,
        model_name: str | None = None,
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        model_name = model_name or self._spec.default_model_name
        model_client = self._build_model_client()
        tool_registry = self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(
            session_store=self._session_store,
            tool_registry=tool_registry,
            agent_type=self._spec.agent_type,
        )
        runner = FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
            require_terminal_action=self._spec.require_terminal_action,
            terminal_action_nudge_limit=self._spec.terminal_action_nudge_limit,
        )
        adapter = self._build_adapter(runner)
        result = await adapter.run(
            project_id=project_id,
            task_id=task_id,
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            user_message=user_message,
            model_name=model_name,
        )
        snapshot, final_payload = await self._ensure_payload(
            session_id=result["session_id"],
            model_name=model_name,
            max_turns=max_turns,
            model_client=model_client,
            runner_result=result.get("runner_result"),
            payload_extractor=self._payload_extractor,
            finalizer_prompts=self._spec.build_finalizer_prompts(),
            fallback_payload_builder=self._spec.fallback_payload_builder,
        )
        return {
            **result,
            "final_payload": final_payload,
            "turn_count": len(snapshot.turns),
            "tool_call_count": len(snapshot.tool_calls),
        }

    async def run_chat_session(
        self,
        *,
        project_id: str,
        task_id: str | None,
        system_prompt: str,
        recon_payload: dict[str, Any],
        user_message: str,
        model_name: str | None = None,
        max_turns: int = 8,
        on_session_created: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        model_client = self._build_model_client()
        runner = self._build_runner(
            model_client=model_client,
            max_turns=max_turns,
            require_terminal_action=self._spec.require_terminal_action,
            terminal_action_nudge_limit=self._spec.terminal_action_nudge_limit,
        )
        adapter = self._build_adapter(runner)
        return await adapter.run(
            project_id=project_id,
            task_id=task_id,
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            user_message=user_message,
            model_name=model_name or self._spec.default_model_name,
            on_session_created=on_session_created,
        )

    async def run_chat_session_stream(
        self,
        *,
        project_id: str,
        task_id: str | None,
        system_prompt: str,
        recon_payload: dict[str, Any],
        user_message: str,
        model_name: str | None = None,
        max_turns: int = 8,
        event_sink: Callable[[dict[str, Any]], Any] | None = None,
        on_session_created: Callable[[str], Any] | None = None,
        on_user_message_created: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        model_client = self._build_model_client()
        runner = self._build_runner(
            model_client=model_client,
            max_turns=max_turns,
            event_sink=event_sink,
        )
        adapter = self._build_adapter(runner)
        return await adapter.run(
            project_id=project_id,
            task_id=task_id,
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            user_message=user_message,
            model_name=model_name or self._spec.default_model_name,
            on_session_created=on_session_created,
            on_user_message_created=on_user_message_created,
        )

    async def continue_session(
        self,
        *,
        session_id: str,
        model_name: str | None = None,
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        return await self.continue_session_until_payload(
            session_id=session_id,
            model_name=model_name or self._spec.default_model_name,
            max_turns=max_turns,
            payload_extractor=self._payload_extractor,
            finalizer_prompts=self._spec.build_finalizer_prompts(),
            fallback_payload_builder=self._spec.fallback_payload_builder,
        )

    async def continue_dialogue_session(
        self,
        *,
        session_id: str,
        model_name: str | None = None,
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        runner = self._build_runner(
            model_client=self._build_model_client(),
            max_turns=max_turns,
        )
        adapter = self._build_adapter(runner)
        await adapter.refresh_session_context(session_id=session_id)
        runner_result = await runner.run_once(
            session_id=session_id,
            model_name=model_name or self._spec.default_model_name,
        )
        snapshot = self._session_store.load_session_snapshot(session_id)
        return {
            "session_id": session_id,
            "runner_result": runner_result,
            "turn_count": len(snapshot.turns),
            "tool_call_count": len(snapshot.tool_calls),
        }

    async def continue_chat_session(
        self,
        *,
        session_id: str,
        model_name: str | None = None,
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        return await self.continue_dialogue_session(
            session_id=session_id,
            model_name=model_name or self._spec.default_model_name,
            max_turns=max_turns,
        )

    async def continue_chat_session_stream(
        self,
        *,
        session_id: str,
        model_name: str | None = None,
        max_turns: int | None = None,
        event_sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        runner = self._build_runner(
            model_client=self._build_model_client(),
            max_turns=max_turns,
            event_sink=event_sink,
        )
        adapter = self._build_adapter(runner)
        await adapter.refresh_session_context(session_id=session_id)
        runner_result = await runner.run_once(
            session_id=session_id,
            model_name=model_name or self._spec.default_model_name,
        )
        snapshot = self._session_store.load_session_snapshot(session_id)
        return {
            "session_id": session_id,
            "runner_result": runner_result,
            "turn_count": len(snapshot.turns),
            "tool_call_count": len(snapshot.tool_calls),
        }

    async def continue_session_until_payload(
        self,
        *,
        session_id: str,
        payload_extractor: Callable[[Any], Any | None],
        finalizer_prompts: list[str],
        model_name: str | None = None,
        max_turns: int | None = None,
        fallback_payload_builder: Callable[[Any], Any] | None = None,
    ) -> dict[str, Any]:
        model_name = model_name or self._spec.default_model_name
        model_client = self._build_model_client()
        runner = self._build_runner(
            model_client=model_client,
            max_turns=max_turns,
            require_terminal_action=True,
            terminal_action_nudge_limit=self._spec.terminal_action_nudge_limit,
        )
        adapter = self._build_adapter(runner)
        await adapter.refresh_session_context(session_id=session_id)
        runner_result = await runner.run_once(session_id=session_id, model_name=model_name)
        snapshot, final_payload = await self._ensure_payload(
            session_id=session_id,
            model_name=model_name,
            max_turns=max_turns,
            model_client=model_client,
            runner_result=runner_result,
            payload_extractor=payload_extractor,
            finalizer_prompts=finalizer_prompts,
            fallback_payload_builder=fallback_payload_builder,
        )
        return {
            "session_id": session_id,
            "runner_result": runner_result,
            "final_payload": final_payload,
            "turn_count": len(snapshot.turns),
            "tool_call_count": len(snapshot.tool_calls),
        }

    def record_handoff(self, session_id: str, handoff_payload: dict[str, Any], *, status: str = "pending") -> str:
        return self._session_store.create_handoff(
            session_id=session_id,
            target=str(handoff_payload.get("to_agent") or "verification"),
            status=status,
            payload=handoff_payload,
        )

    async def _ensure_payload(
        self,
        *,
        session_id: str,
        model_name: str,
        max_turns: int | None,
        model_client: RuntimeLLMModelClient,
        runner_result: TurnExecutionResult | dict[str, Any] | None,
        payload_extractor: Callable[[Any], Any | None],
        finalizer_prompts: list[str],
        fallback_payload_builder: Callable[[Any], Any] | None = None,
    ) -> tuple[Any, Any]:
        snapshot = self._session_store.load_session_snapshot(session_id)
        runner_payload = getattr(runner_result, "final_payload", None)
        if isinstance(runner_payload, dict):
            return snapshot, runner_payload
        payload = payload_extractor(snapshot)
        if payload is not None:
            return snapshot, payload

        if not finalizer_prompts:
            if fallback_payload_builder is not None:
                return snapshot, fallback_payload_builder(snapshot)
            raise ValueError("Runtime session ended without a machine-parseable payload for the requested continuation.")

        if not self._should_attempt_finalizer(runner_result):
            if fallback_payload_builder is not None:
                return snapshot, fallback_payload_builder(snapshot)
            raise ValueError("Runtime session ended without a machine-parseable payload for the requested continuation.")

        finalizer_tool = self._spec.build_finalizer_tool()
        if finalizer_tool is None:
            if fallback_payload_builder is not None:
                return snapshot, fallback_payload_builder(snapshot)
            raise ValueError("Runtime session ended without a configured finalizer tool.")

        finalizer_registry = ToolRegistry([finalizer_tool])
        finalizer_orchestrator = ToolOrchestrator(
            session_store=self._session_store,
            tool_registry=finalizer_registry,
            agent_type=self._spec.agent_type,
        )
        for index, prompt in enumerate(finalizer_prompts, start=1):
            self._session_store.append_message(
                session_id,
                TranscriptItem(
                    role=RuntimeMessageRole.USER,
                    name="runtime_finalizer" if index == 1 else f"runtime_finalizer_retry_{index}",
                    content=prompt,
                    metadata={"kind": "finalization_prompt", "attempt": index},
                ),
            )
            runner = FindingRuntimeRunner(
                session_store=self._session_store,
                model_client=model_client,
                tool_registry=finalizer_registry,
                tool_orchestrator=finalizer_orchestrator,
                max_turns=2 if max_turns is None else max(1, min(2, max_turns)),
                require_terminal_action=True,
                terminal_action_nudge_limit=1,
            )
            await runner.run_once(session_id=session_id, model_name=model_name)
            snapshot = self._session_store.load_session_snapshot(session_id)
            payload = payload_extractor(snapshot)
            if payload is not None:
                return snapshot, payload

        if fallback_payload_builder is not None:
            return snapshot, fallback_payload_builder(snapshot)
        raise ValueError("Runtime session ended without a machine-parseable payload for the requested continuation.")

    def _build_model_client(self) -> RuntimeLLMModelClient:
        return RuntimeLLMModelClient(llm_service=self._llm_service, agent_type=self._spec.agent_type)

    def _build_runner(
        self,
        *,
        model_client,
        max_turns: int | None = None,
        event_sink: Callable[[dict[str, Any]], Any] | None = None,
        require_terminal_action: bool | None = None,
        terminal_action_nudge_limit: int | None = None,
    ) -> FindingRuntimeRunner:
        tool_registry = self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(
            session_store=self._session_store,
            tool_registry=tool_registry,
            agent_type=self._spec.agent_type,
        )
        return FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
            event_sink=event_sink,
            require_terminal_action=self._spec.require_terminal_action if require_terminal_action is None else require_terminal_action,
            terminal_action_nudge_limit=(
                self._spec.terminal_action_nudge_limit
                if terminal_action_nudge_limit is None
                else terminal_action_nudge_limit
            ),
        )

    def _build_adapter(self, runner) -> AgentRuntimeAdapter:
        return AgentRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            agent_type=self._spec.agent_type,
            default_user_message=self._spec.default_user_message,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )

    def _build_tool_registry(self) -> ToolRegistry:
        if self._spec.tool_registry_builder is None:
            return ToolRegistry()
        return self._spec.tool_registry_builder(
            session_store=self._session_store,
            agent_tools=self._tools,
            agent_type=self._spec.agent_type,
            user_id=self._user_id,
        )

    def _payload_extractor(self, snapshot: Any) -> Any | None:
        if self._spec.payload_extractor is None:
            return None
        return self._spec.payload_extractor(snapshot)

    @staticmethod
    def _should_attempt_finalizer(runner_result: TurnExecutionResult | dict[str, Any] | None) -> bool:
        if runner_result is None:
            return True
        completion_mode = getattr(runner_result, "completion_mode", None)
        if completion_mode is None and isinstance(runner_result, dict):
            completion_mode = runner_result.get("completion_mode")
        if completion_mode is not None:
            try:
                completion_mode = (
                    completion_mode
                    if isinstance(completion_mode, RuntimeCompletionMode)
                    else RuntimeCompletionMode(str(completion_mode))
                )
            except ValueError:
                completion_mode = None
        if completion_mode in {RuntimeCompletionMode.FINALIZE_TOOL, RuntimeCompletionMode.INCOMPLETE}:
            return False

        terminal_action = getattr(runner_result, "terminal_action", None)
        if terminal_action is None and isinstance(runner_result, dict):
            terminal_action = runner_result.get("terminal_action")
        if terminal_action is not None:
            try:
                terminal_action = (
                    terminal_action
                    if isinstance(terminal_action, RuntimeTerminalAction)
                    else RuntimeTerminalAction(str(terminal_action))
                )
            except ValueError:
                terminal_action = None
        if terminal_action is RuntimeTerminalAction.NATURAL_END_WITHOUT_TERMINAL_ACTION:
            return False

        stop_reason = getattr(runner_result, "stop_reason", None)
        if stop_reason is None and isinstance(runner_result, dict):
            stop_reason = runner_result.get("stop_reason")
        if stop_reason is None:
            return True
        if not isinstance(stop_reason, RuntimeStopReason):
            try:
                stop_reason = RuntimeStopReason(str(stop_reason))
            except ValueError:
                return False
        return stop_reason in FINALIZER_ELIGIBLE_STOP_REASONS
