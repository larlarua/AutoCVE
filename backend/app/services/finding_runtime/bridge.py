from __future__ import annotations

import json
import inspect
import re
from typing import Any, AsyncGenerator, Callable

from app.db.session import get_sync_session_factory
from app.services.agent.json_parser import AgentJsonParser
from app.services.finding_runtime.adapters.finding import FindingRuntimeAdapter
from app.services.finding_runtime.models import (
    RuntimeMessageRole,
    RuntimeModelResponse,
    RuntimeStopReason,
    TranscriptItem,
    TurnExecutionResult,
)
from app.services.finding_runtime.memory import RuntimeMemoryManager
from app.services.finding_runtime.runner import FindingRuntimeRunner
from app.services.finding_runtime.session_store import AuditSessionStore
from app.services.finding_runtime.skills import RuntimeSkillCatalog
from app.services.finding_runtime.tooling import ToolOrchestrator, ToolRegistry
from app.services.runtime_core import build_runtime_tool_registry

READ_SAFE_RUNTIME_TOOLS = {"Read", "Glob", "Grep", "Skill"}
INTERNAL_TOOL_NAMES = {"think", "reflect", "load_skill_body", "skill_resource_lookup"}
RUNTIME_FINALIZATION_PROMPT = (
    "Stop auditing now and return the final report as JSON only. "
    "Do not call more tools unless absolutely required for the final answer. "
    "Return an object with keys: findings (array) and summary (string). "
    "If no CVE-grade issue is supported, return findings=[] and explain the reviewed attack surfaces in summary."
)
FINALIZER_ELIGIBLE_STOP_REASONS = {
    RuntimeStopReason.COMPLETED,
    RuntimeStopReason.MAX_TURNS,
    RuntimeStopReason.HOOK_STOPPED,
}


class RuntimeLLMModelClient:
    def __init__(self, *, llm_service, agent_type: str = "finding"):
        self._llm_service = llm_service
        self._agent_type = agent_type

    async def complete(
        self,
        *,
        system_prompt: str | None,
        recon_payload: dict[str, Any],
        transcript: list[Any],
        model_name: str,
        tool_definitions: list[dict[str, Any]],
        max_output_tokens_override: int | None = None,
    ) -> RuntimeModelResponse:
        del model_name
        messages = self._build_messages(system_prompt=system_prompt, recon_payload=recon_payload, transcript=transcript)
        response = await self._llm_service.chat_completion(
            messages=messages,
            agent_type=self._agent_type,
            tools=[self._to_llm_tool_schema(item) for item in tool_definitions],
            parallel_tool_calls=True,
            max_tokens=max_output_tokens_override,
        )
        return RuntimeModelResponse(
            content=response.get("content", "") or "",
            tool_calls=[self._normalize_tool_call(item) for item in response.get("tool_calls") or []],
            stop_reason=response.get("finish_reason") or "stop",
            recoverable_error_kind=self._classify_recoverable_error_kind(response),
            recoverable_error_message=str(response.get("error_message") or "").strip() or None,
            usage=dict(response.get("usage") or {}),
        )

    async def complete_stream(
        self,
        *,
        system_prompt: str | None,
        recon_payload: dict[str, Any],
        transcript: list[Any],
        model_name: str,
        tool_definitions: list[dict[str, Any]],
        on_event: Callable[[dict[str, Any]], Any] | None = None,
        max_output_tokens_override: int | None = None,
    ) -> RuntimeModelResponse:
        del model_name
        messages: list[dict[str, str]] = []
        effective_system_prompt = (system_prompt or "").strip()
        if recon_payload:
            recon_text = "Runtime recon payload:\n" + json.dumps(recon_payload, ensure_ascii=False, indent=2)
            effective_system_prompt = f"{effective_system_prompt}\n\n{recon_text}".strip() if effective_system_prompt else recon_text
        if effective_system_prompt:
            messages.append({"role": "system", "content": effective_system_prompt})
        messages.extend(mapped for item in transcript if (mapped := self._map_transcript_item(item)) is not None)

        final_event: dict[str, Any] | None = None
        async for event in self._llm_service.chat_completion_stream(
            messages=messages,
            agent_type=self._agent_type,
            tools=[self._to_llm_tool_schema(item) for item in tool_definitions],
            parallel_tool_calls=True,
            max_tokens=max_output_tokens_override,
        ):
            if on_event is not None:
                maybe_awaitable = on_event(event)
                if inspect.isawaitable(maybe_awaitable):
                    await maybe_awaitable
            if event.get("type") == "done":
                final_event = event
            if event.get("type") == "error":
                return RuntimeModelResponse(
                    content=str(event.get("accumulated") or ""),
                    tool_calls=[],
                    stop_reason="error",
                    recoverable_error_kind=str(event.get("error_type") or "").strip() or None,
                    recoverable_error_message=str(event.get("error") or event.get("user_message") or "").strip() or None,
                )

        final_event = final_event or {}
        return RuntimeModelResponse(
            content=str(final_event.get("content") or ""),
            tool_calls=[self._normalize_tool_call(item) for item in final_event.get("tool_calls") or []],
            stop_reason=str(final_event.get("finish_reason") or "stop"),
            recoverable_error_kind=self._classify_recoverable_error_kind(final_event),
            recoverable_error_message=str(final_event.get("error") or final_event.get("user_message") or "").strip() or None,
            usage=dict(final_event.get("usage") or {}),
        )

    async def stream_complete(
        self,
        *,
        system_prompt: str | None,
        recon_payload: dict[str, Any],
        transcript: list[Any],
        model_name: str,
        tool_definitions: list[dict[str, Any]],
        max_output_tokens_override: int | None = None,
    ) -> AsyncGenerator[dict[str, Any], None]:
        del model_name
        messages = self._build_messages(system_prompt=system_prompt, recon_payload=recon_payload, transcript=transcript)
        stream_fn = getattr(self._llm_service, "chat_completion_stream", None)
        if callable(stream_fn):
            accumulated = ""
            async for event in stream_fn(
                messages=messages,
                agent_type=self._agent_type,
                tools=[self._to_llm_tool_schema(item) for item in tool_definitions],
                parallel_tool_calls=True,
                max_tokens=max_output_tokens_override,
            ):
                normalized = self._normalize_stream_event(event, accumulated=accumulated)
                if normalized is None:
                    continue
                if normalized.get("type") == "content_delta":
                    accumulated = normalized.get("accumulated") or accumulated
                if normalized.get("type") == "done":
                    for tool_call in list(normalized.get("tool_calls") or []):
                        yield {"type": "tool_call", "tool_call": tool_call}
                yield normalized
                if normalized.get("type") == "done":
                    return

        response = await self.complete(
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            transcript=transcript,
            model_name="finding",
            tool_definitions=tool_definitions,
            max_output_tokens_override=max_output_tokens_override,
        )
        if response.content:
            yield {"type": "content_delta", "content": response.content, "accumulated": response.content}
        for tool_call in response.tool_calls:
            yield {"type": "tool_call", "tool_call": tool_call}
        yield {
            "type": "done",
            "content": response.content,
            "stop_reason": response.stop_reason,
            "recoverable_error_kind": response.recoverable_error_kind,
            "recoverable_error_message": response.recoverable_error_message,
            "tool_calls": [],
        }

    @staticmethod
    def _build_messages(*, system_prompt: str | None, recon_payload: dict[str, Any], transcript: list[Any]) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        effective_system_prompt = (system_prompt or "").strip()
        if recon_payload:
            recon_text = "Runtime recon payload:\n" + json.dumps(recon_payload, ensure_ascii=False, indent=2)
            effective_system_prompt = f"{effective_system_prompt}\n\n{recon_text}".strip() if effective_system_prompt else recon_text
        if effective_system_prompt:
            messages.append({"role": "system", "content": effective_system_prompt})
        messages.extend(mapped for item in transcript if (mapped := RuntimeLLMModelClient._map_transcript_item(item)) is not None)
        return messages

    @staticmethod
    def _classify_recoverable_error_kind(response: dict[str, Any]) -> str | None:
        finish_reason = str(response.get("finish_reason") or "").strip().lower()
        if finish_reason in {"length", "max_tokens", "max_output_tokens"}:
            return "max_output_tokens"
        error_type = str(response.get("error_type") or "").strip().lower()
        if error_type in {"prompt_too_long", "image_error", "media_size", "max_output_tokens"}:
            return error_type
        return None

    @staticmethod
    def _normalize_stream_event(event: dict[str, Any], *, accumulated: str) -> dict[str, Any] | None:
        payload = dict(event or {})
        event_type = str(payload.get("type") or "").strip().lower()
        if event_type == "token":
            content = str(payload.get("content") or "")
            next_accumulated = str(payload.get("accumulated") or (accumulated + content))
            if not content:
                return None
            return {"type": "content_delta", "content": content, "accumulated": next_accumulated}
        if event_type == "tool_call":
            raw_tool_call = payload.get("tool_call") or payload
            return {"type": "tool_call", "tool_call": RuntimeLLMModelClient._normalize_tool_call(raw_tool_call)}
        if event_type == "done":
            tool_calls = [RuntimeLLMModelClient._normalize_tool_call(item) for item in payload.get("tool_calls") or []]
            response_payload = {
                "finish_reason": payload.get("stop_reason") or payload.get("finish_reason") or "stop",
                "error_type": payload.get("recoverable_error_kind"),
                "error_message": payload.get("recoverable_error_message") or payload.get("error_message"),
            }
            return {
                "type": "done",
                "content": str(payload.get("content") or payload.get("accumulated") or accumulated),
                "stop_reason": payload.get("stop_reason") or payload.get("finish_reason") or "stop",
                "recoverable_error_kind": RuntimeLLMModelClient._classify_recoverable_error_kind(response_payload),
                "recoverable_error_message": str(payload.get("recoverable_error_message") or payload.get("error_message") or "").strip() or None,
                "tool_calls": tool_calls,
            }
        return None

    @staticmethod
    def _to_llm_tool_schema(definition: dict[str, Any]) -> dict[str, Any]:
        return {
            "type": "function",
            "function": {
                "name": definition.get("name", ""),
                "description": definition.get("description", ""),
                "parameters": definition.get("input_schema", {"type": "object"}),
            },
        }

    @staticmethod
    def _map_transcript_item(item: Any) -> dict[str, str] | None:
        role = str(getattr(item, "role", "user"))
        content = str(getattr(item, "content", "") or "")
        payload = getattr(item, "payload", {}) or {}
        if role == "system":
            return None
        if role == "assistant":
            return {"role": "assistant", "content": content}
        if role == "tool_use":
            tool_name = payload.get("tool_name") or getattr(item, "name", "tool")
            return {"role": "assistant", "content": f"Tool Call: {tool_name}\n{json.dumps(payload, ensure_ascii=False)}"}
        if role == "tool_result":
            return {"role": "user", "content": f"Tool Result:\n{content}"}
        if role == "handoff":
            target = payload.get("target") or "verification"
            return {"role": "user", "content": f"Handoff ({target}):\n{content}"}
        return {"role": "user", "content": content}

    @staticmethod
    def _normalize_tool_call(raw_tool_call: dict[str, Any]) -> dict[str, Any]:
        function_payload = raw_tool_call.get("function") if isinstance(raw_tool_call, dict) else None
        if not isinstance(function_payload, dict):
            function_payload = raw_tool_call
        raw_arguments = function_payload.get("arguments") if isinstance(function_payload, dict) else None
        parsed_arguments = AgentJsonParser.parse_any(raw_arguments, default={}) if isinstance(raw_arguments, str) else raw_arguments
        if not isinstance(parsed_arguments, dict):
            parsed_arguments = {"raw_input": parsed_arguments}
        return {
            "id": raw_tool_call.get("id") or function_payload.get("id") or "tool-call",
            "name": function_payload.get("name") or raw_tool_call.get("name") or "",
            "input": parsed_arguments,
        }


class FindingRuntimeBridge:
    def __init__(
        self,
        *,
        llm_service,
        tools: dict[str, Any],
        user_id: str | None = None,
        session_factory=None,
    ):
        self._llm_service = llm_service
        self._tools = tools
        self._user_id = user_id
        self._session_store = AuditSessionStore(session_factory=session_factory or get_sync_session_factory())

    async def run(
        self,
        *,
        project_id: str,
        task_id: str | None,
        system_prompt: str,
        recon_payload: dict[str, Any],
        user_message: str,
        model_name: str = "finding-runtime",
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        model_client = RuntimeLLMModelClient(llm_service=self._llm_service, agent_type="finding")
        tool_registry = self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(session_store=self._session_store, tool_registry=tool_registry)
        runner = FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
        )
        adapter = FindingRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )
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
            payload_extractor=self.extract_final_payload,
            finalizer_prompts=self._default_finalizer_prompts(),
            fallback_payload_builder=self._default_fallback_payload,
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
        model_name: str = "finding-runtime",
        max_turns: int = 8,
        on_session_created: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        model_client = RuntimeLLMModelClient(llm_service=self._llm_service, agent_type="finding")
        tool_registry = self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(session_store=self._session_store, tool_registry=tool_registry)
        runner = FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
        )
        adapter = FindingRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )
        return await adapter.run(
            project_id=project_id,
            task_id=task_id,
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            user_message=user_message,
            model_name=model_name,
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
        model_name: str = "finding-runtime",
        max_turns: int = 8,
        event_sink: Callable[[dict[str, Any]], Any] | None = None,
        on_session_created: Callable[[str], Any] | None = None,
        on_user_message_created: Callable[[str], Any] | None = None,
    ) -> dict[str, Any]:
        model_client = RuntimeLLMModelClient(llm_service=self._llm_service, agent_type="finding")
        tool_registry = self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(session_store=self._session_store, tool_registry=tool_registry)
        runner = FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
            event_sink=event_sink,
        )
        adapter = FindingRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )
        return await adapter.run(
            project_id=project_id,
            task_id=task_id,
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            user_message=user_message,
            model_name=model_name,
            on_session_created=on_session_created,
            on_user_message_created=on_user_message_created,
        )

    async def continue_session(
        self,
        *,
        session_id: str,
        model_name: str = "finding-runtime",
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        return await self.continue_session_until_payload(
            session_id=session_id,
            model_name=model_name,
            max_turns=max_turns,
            payload_extractor=self.extract_final_payload,
            finalizer_prompts=self._default_finalizer_prompts(),
            fallback_payload_builder=self._default_fallback_payload,
        )

    async def continue_dialogue_session(
        self,
        *,
        session_id: str,
        model_name: str = "finding-runtime",
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        model_client = RuntimeLLMModelClient(llm_service=self._llm_service, agent_type="finding")
        tool_registry = self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(session_store=self._session_store, tool_registry=tool_registry)
        runner = FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
        )
        adapter = FindingRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )
        await adapter.refresh_session_context(session_id=session_id)
        runner_result = await runner.run_once(session_id=session_id, model_name=model_name)
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
        model_name: str = "finding-runtime",
        max_turns: int | None = None,
    ) -> dict[str, Any]:
        return await self.continue_dialogue_session(
            session_id=session_id,
            model_name=model_name,
            max_turns=max_turns,
        )

    async def continue_chat_session_stream(
        self,
        *,
        session_id: str,
        model_name: str = "finding-runtime",
        max_turns: int | None = None,
        event_sink: Callable[[dict[str, Any]], Any] | None = None,
    ) -> dict[str, Any]:
        model_client = RuntimeLLMModelClient(llm_service=self._llm_service, agent_type="finding")
        tool_registry = self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(session_store=self._session_store, tool_registry=tool_registry)
        runner = FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
            event_sink=event_sink,
        )
        adapter = FindingRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )
        await adapter.refresh_session_context(session_id=session_id)
        runner_result = await runner.run_once(session_id=session_id, model_name=model_name)
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
        model_name: str = "finding-runtime",
        max_turns: int | None = None,
        fallback_payload_builder: Callable[[Any], Any] | None = None,
    ) -> dict[str, Any]:
        model_client = RuntimeLLMModelClient(llm_service=self._llm_service, agent_type="finding")
        tool_registry = self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(session_store=self._session_store, tool_registry=tool_registry)
        runner = FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
        )
        adapter = FindingRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )
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
        payload = payload_extractor(snapshot)
        if payload is not None:
            return snapshot, payload

        if not self._should_attempt_finalizer(runner_result):
            if fallback_payload_builder is not None:
                return snapshot, fallback_payload_builder(snapshot)
            raise ValueError('Runtime session ended without a machine-parseable payload for the requested continuation.')

        finalizer_registry = ToolRegistry([])
        for index, prompt in enumerate(finalizer_prompts, start=1):
            self._session_store.append_message(
                session_id,
                TranscriptItem(
                    role=RuntimeMessageRole.USER,
                    name='runtime_finalizer' if index == 1 else f'runtime_finalizer_retry_{index}',
                    content=prompt,
                    metadata={'kind': 'finalization_prompt', 'attempt': index},
                ),
            )
            runner = FindingRuntimeRunner(
                session_store=self._session_store,
                model_client=model_client,
                tool_registry=finalizer_registry,
                tool_orchestrator=None,
                max_turns=2 if max_turns is None else max(1, min(2, max_turns)),
            )
            await runner.run_once(session_id=session_id, model_name=model_name)
            snapshot = self._session_store.load_session_snapshot(session_id)
            payload = payload_extractor(snapshot)
            if payload is not None:
                return snapshot, payload

        if fallback_payload_builder is not None:
            return snapshot, fallback_payload_builder(snapshot)
        raise ValueError('Runtime session ended without a machine-parseable payload for the requested continuation.')

    def _build_tool_registry(self) -> ToolRegistry:
        return build_runtime_tool_registry(
            session_store=self._session_store,
            agent_tools=self._tools,
            agent_type="finding",
            user_id=self._user_id,
        )

    @staticmethod
    def _default_finalizer_prompts() -> list[str]:
        return [
            RUNTIME_FINALIZATION_PROMPT,
            (
                'Return the final report now as strict JSON only. '
                'Do not request any more tools. '
                'The response must be a single JSON object with keys findings and summary.'
            ),
        ]

    @classmethod
    def _default_fallback_payload(cls, snapshot: Any) -> dict[str, Any]:
        return {
            'findings': [],
            'summary': cls._fallback_summary(snapshot),
        }

    @staticmethod
    def _should_attempt_finalizer(runner_result: TurnExecutionResult | dict[str, Any] | None) -> bool:
        if runner_result is None:
            return True
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

    @staticmethod
    def extract_final_payload(snapshot: Any) -> dict[str, Any] | None:
        for message in reversed(getattr(snapshot, 'messages', []) or []):
            if getattr(message, 'role', '') != 'assistant':
                continue
            payload = FindingRuntimeBridge._parse_payload(getattr(message, 'content', '') or '')
            if payload is not None:
                return payload
        return None

    @staticmethod
    def _parse_payload(text: str) -> dict[str, Any] | None:
        direct = AgentJsonParser.parse_any(text, default=None)
        if isinstance(direct, dict) and isinstance(direct.get('findings'), list) and isinstance(direct.get('summary'), str):
            return direct
        match = re.search(r'(\{.*\})', text, re.DOTALL)
        if not match:
            return None
        parsed = AgentJsonParser.parse_any(match.group(1), default=None)
        if isinstance(parsed, dict) and isinstance(parsed.get('findings'), list) and isinstance(parsed.get('summary'), str):
            return parsed
        return None

    @staticmethod
    def _fallback_summary(snapshot: Any) -> str:
        last_assistant = ''
        for message in reversed(getattr(snapshot, 'messages', []) or []):
            if getattr(message, 'role', '') == 'assistant':
                last_assistant = str(getattr(message, 'content', '') or '').strip()
                if last_assistant:
                    break
        if last_assistant:
            return (
                'Runtime session ended without a machine-parseable final JSON payload. '
                f'Last assistant reply: {last_assistant[:1200]}'
            )
        return 'Runtime session ended without a machine-parseable final JSON payload.'

