from __future__ import annotations

import json
import inspect
import re
from typing import Any, AsyncGenerator, Callable

from app.db.session import get_sync_session_factory
from app.services.agent.json_parser import AgentJsonParser
from app.services.finding_runtime.adapters.finding import FindingRuntimeAdapter
from app.services.finding_runtime.models import (
    RuntimeCompletionMode,
    RuntimeMessageRole,
    RuntimeModelResponse,
    RuntimeStopReason,
    RuntimeTerminalAction,
    TranscriptItem,
    TurnExecutionResult,
)
from app.services.finding_runtime.memory import RuntimeMemoryManager
from app.services.finding_runtime.runner import FindingRuntimeRunner
from app.services.finding_runtime.session_store import AuditSessionStore
from app.services.finding_runtime.skills import RuntimeSkillCatalog
from app.services.finding_runtime.tools.finalize_finding import FinalizeFindingTool
from app.services.finding_runtime.tooling import ToolOrchestrator, ToolRegistry
from app.services.runtime_core import build_runtime_tool_registry

READ_SAFE_RUNTIME_TOOLS = {"Read", "Glob", "Grep", "Skill"}
INTERNAL_TOOL_NAMES = {"think", "reflect", "load_skill_body", "skill_resource_lookup"}
AUTO_FINALIZER_PROMPTS_ENABLED = True
RUNTIME_FINALIZATION_PROMPT = (
    "立即停止继续审计，并仅以 JSON 返回最终报告。"
    "除非最终答案绝对需要，否则不要再调用任何工具。"
    "返回一个对象，顶层只包含 findings（数组）和 summary（字符串）。"
    "如果当前证据不足以支持 CVE 级问题，请返回 findings=[]，并在 summary 中说明已审查的攻击面。"

)
RUNTIME_FINALIZATION_PROMPT = (
    "你正在补交 Finding 阶段最终结果。你只能做一件事：\n\n"
    "如果已有足够证据形成漏洞结论，请调用 FinalizeFinding，提交 findings 和 summary。\n"
    "如果没有足够证据确认漏洞，请调用 FinalizeFinding，提交 findings=[]，并在 summary 中说明未确认到可报告漏洞。\n\n"
    "不要继续普通文字分析，不要输出 Markdown，不要声称还需要查看文件。"
)
RUNTIME_FINALIZATION_PROMPT = (
    "你正在补交 Finding 阶段最终结果。你只能做一件事：\n\n"
    "如果已有足够证据形成漏洞结论，请调用 FinalizeFinding，提交 findings 和 summary。\n"
    "只有在审计已经完成、且可以明确确认没有可报告漏洞时，才允许调用 FinalizeFinding 提交 findings=[]。\n"
    "如果仍需继续查看文件、验证调用链、补齐 source/sink/PoC/影响面，请不要调用 FinalizeFinding，"
    "应继续调用 Read/Grep/Glob/PowerShell 等工具收集证据。\n\n"
    "不要继续普通文字分析，不要输出 Markdown，不要把未完成审计包装成空 findings。"
)
FINALIZER_ELIGIBLE_STOP_REASONS = {
    RuntimeStopReason.COMPLETED,
    RuntimeStopReason.MAX_TURNS,
    RuntimeStopReason.HOOK_STOPPED,
}
NATIVE_TOOL_CALLING_REMINDER = (
    "当存在可用工具时，只能使用模型提供方原生的结构化工具调用接口。"
    "不要输出纯文本工具语法，例如 'Tool Call:'、'Action:' 或“我接下来要调用某个工具”。"
    "如果还需要继续收集证据，请直接调用下一次工具。"
    "如果已经完成审计，请调用 FinalizeFinding 提交最终结构化结果。"
    "不要只描述下一步计划而不执行。"
)


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
        messages = self._build_messages(
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            transcript=transcript,
            tool_definitions=tool_definitions,
        )
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
        messages = self._build_messages(
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            transcript=transcript,
            tool_definitions=tool_definitions,
        )

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
        messages = self._build_messages(
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            transcript=transcript,
            tool_definitions=tool_definitions,
        )
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
    def _build_messages(
        *,
        system_prompt: str | None,
        recon_payload: dict[str, Any],
        transcript: list[Any],
        tool_definitions: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, str]]:
        messages: list[dict[str, str]] = []
        effective_system_prompt = (system_prompt or "").strip()
        if tool_definitions:
            effective_system_prompt = (
                f"{effective_system_prompt}\n\n{NATIVE_TOOL_CALLING_REMINDER}".strip()
                if effective_system_prompt
                else NATIVE_TOOL_CALLING_REMINDER
            )
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
        if event_type == "llm_retry":
            return {
                "type": "llm_retry",
                "attempt": int(payload.get("attempt") or 0),
                "max_attempts": int(payload.get("max_attempts") or 0),
                "message_text": str(payload.get("message_text") or "").strip(),
                "error_type": str(payload.get("error_type") or "").strip() or None,
                "error": str(payload.get("error") or "").strip() or None,
            }
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
        if event_type == "error":
            return {
                "type": "error",
                "error": str(payload.get("error") or "").strip() or None,
                "user_message": str(payload.get("user_message") or "").strip() or None,
                "error_type": str(payload.get("error_type") or "").strip() or None,
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
        metadata = getattr(item, "metadata", None)
        if not isinstance(metadata, dict):
            metadata = getattr(item, "message_metadata", {}) or {}
        if role == "system":
            return None
        if role == "assistant":
            legacy_tool_summary = RuntimeLLMModelClient._summarize_legacy_tool_call_content(content)
            if legacy_tool_summary is not None:
                return {"role": "user", "content": legacy_tool_summary}
            return {"role": "assistant", "content": content}
        if role == "tool_use":
            tool_name = payload.get("tool_name") or getattr(item, "name", "tool")
            return {
                "role": "user",
                "content": RuntimeLLMModelClient._format_tool_history(
                    tool_name=tool_name,
                    tool_input=RuntimeLLMModelClient._extract_tool_input_payload(payload),
                ),
            }
        if role == "tool_result":
            return {
                "role": "user",
                "content": RuntimeLLMModelClient._format_tool_result_feedback(
                    tool_name=str(payload.get("tool_name") or getattr(item, "name", "tool")),
                    content=content,
                    status=str(metadata.get("status") or ""),
                    is_error=bool(metadata.get("is_error")),
                    payload=payload,
                ),
            }
        if role == "handoff":
            target = payload.get("target") or "verification"
            return {"role": "user", "content": f"Handoff ({target}):\n{content}"}
        return {"role": "user", "content": content}

    @staticmethod
    def _format_tool_history(*, tool_name: str, tool_input: dict[str, Any]) -> str:
        serialized_input = json.dumps(tool_input, ensure_ascii=False)
        return (
            f"先前工具请求历史（{tool_name}）：\n"
            f"{serialized_input}\n"
            "这是更早轮次的上下文，不要把它当作当前 assistant 回复。"
        )

    @staticmethod
    def _format_tool_result_feedback(
        *,
        tool_name: str,
        content: str,
        status: str,
        is_error: bool,
        payload: dict[str, Any],
    ) -> str:
        summary: dict[str, Any] = {
            "tool_name": str(tool_name or "tool"),
            "tool_use_id": payload.get("tool_use_id"),
            "tool_call_id": payload.get("tool_call_id"),
            "status": str(status or ""),
            "is_error": bool(is_error),
            "content": str(content or ""),
        }
        input_payload = payload.get("input")
        if isinstance(input_payload, dict) and input_payload:
            summary["input"] = dict(input_payload)
        output_payload = payload.get("output")
        if isinstance(output_payload, dict):
            summary["output"] = dict(output_payload)
        error_message = str(payload.get("error_message") or "").strip()
        if error_message:
            summary["error_message"] = error_message

        prefix = "工具执行失败" if is_error else "工具执行结果"
        guidance = (
            "\n请根据上面的错误信息修正这次工具调用；如果还需要继续审计，请直接发起下一次原生工具调用。"
            if is_error
            else ""
        )
        return f"{prefix}:\n{json.dumps(summary, ensure_ascii=False, indent=2)}{guidance}"

    @staticmethod
    def _extract_tool_input_payload(payload: Any) -> dict[str, Any]:
        if isinstance(payload, dict):
            input_payload = payload.get("input")
            if isinstance(input_payload, dict):
                return dict(input_payload)
            return dict(payload)
        if isinstance(payload, list):
            for item in payload:
                extracted = RuntimeLLMModelClient._extract_tool_input_payload(item)
                if extracted:
                    return extracted
        return {}

    @staticmethod
    def _summarize_legacy_tool_call_content(content: str) -> str | None:
        text = (content or "").strip()
        if not text:
            return None

        tool_call_match = re.match(r"Tool Call:\s*([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$", text, re.DOTALL)
        if tool_call_match:
            return RuntimeLLMModelClient._format_tool_history(
                tool_name=tool_call_match.group(1).strip(),
                tool_input=RuntimeLLMModelClient._extract_tool_input_payload(
                    AgentJsonParser.parse_any(tool_call_match.group(2).strip(), default={})
                ),
            )

        action_match = re.match(
            r"Action:\s*([A-Za-z_][A-Za-z0-9_]*)\s*Action Input:\s*(.*)$",
            text,
            re.DOTALL,
        )
        if action_match:
            return RuntimeLLMModelClient._format_tool_history(
                tool_name=action_match.group(1).strip(),
                tool_input=RuntimeLLMModelClient._extract_tool_input_payload(
                    AgentJsonParser.parse_any(action_match.group(2).strip(), default={})
                ),
            )

        return None

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
    _RECOVERY_KEYWORDS: dict[str, tuple[str, ...]] = {
        "ssrf": ("ssrf", "server-side request forgery"),
        "path_traversal": ("path traversal", "directory traversal", "zip slip", "lfi", "rfi"),
        "sql_injection": ("sql injection", "sqli"),
        "xss": ("xss", "cross-site scripting"),
        "auth_bypass": ("auth bypass", "authentication bypass", "authorization bypass", "未认证", "绕过", "鉴权"),
        "idor": ("idor", "insecure direct object reference", "越权"),
        "command_injection": ("command injection", "rce", "remote code execution"),
        "deserialization": ("deserialization", "unsafe deserialization", "反序列化"),
        "file_upload": ("file upload", "arbitrary file upload"),
        "business_logic": ("business logic", "logic flaw", "race condition"),
    }
    _RECOVERY_SEVERITY: dict[str, str] = {
        "ssrf": "high",
        "path_traversal": "high",
        "sql_injection": "critical",
        "xss": "high",
        "auth_bypass": "high",
        "idor": "high",
        "command_injection": "critical",
        "deserialization": "critical",
        "file_upload": "high",
        "business_logic": "medium",
    }

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
            require_terminal_action=True,
            terminal_action_nudge_limit=2,
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
            require_terminal_action=True,
            terminal_action_nudge_limit=2,
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
            require_terminal_action=True,
            terminal_action_nudge_limit=2,
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
        runner_payload = getattr(runner_result, "final_payload", None)
        if isinstance(runner_payload, dict):
            return snapshot, runner_payload
        payload = payload_extractor(snapshot)
        if payload is not None:
            return snapshot, payload

        if not finalizer_prompts:
            if fallback_payload_builder is not None:
                return snapshot, fallback_payload_builder(snapshot)
            raise ValueError('Runtime session ended without a machine-parseable payload for the requested continuation.')

        if not self._should_attempt_finalizer(runner_result):
            if fallback_payload_builder is not None:
                return snapshot, fallback_payload_builder(snapshot)
            raise ValueError('Runtime session ended without a machine-parseable payload for the requested continuation.')

        finalizer_registry = ToolRegistry([FinalizeFindingTool()])
        finalizer_orchestrator = ToolOrchestrator(session_store=self._session_store, tool_registry=finalizer_registry)
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
        if not AUTO_FINALIZER_PROMPTS_ENABLED:
            return []
        return [RUNTIME_FINALIZATION_PROMPT]
        return [
            RUNTIME_FINALIZATION_PROMPT,
            (
                "现在请立即仅以严格 JSON 返回最终报告。"
                "不要再请求任何工具。"
                "响应必须是一个单独的 JSON 对象，顶层键只能是 findings 和 summary。"

            ),
        ]

    @classmethod
    def _default_fallback_payload(cls, snapshot: Any) -> dict[str, Any]:
        recovered_findings = cls._recover_findings_from_assistant_transcript(snapshot)
        return {
            'findings': [],
            'recovered_candidates': recovered_findings,
            'summary': cls._fallback_summary(snapshot, recovered_findings),
            'runtime_completion_mode': RuntimeCompletionMode.INCOMPLETE.value,
            'is_final': False,
            'requires_retry': True,
        }

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

    @classmethod
    def _recover_findings_from_assistant_transcript(cls, snapshot: Any) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        seen_titles: set[str] = set()

        for message in getattr(snapshot, "messages", []) or []:
            if getattr(message, "role", "") != "assistant":
                continue
            content = str(getattr(message, "content", "") or "")
            for raw_line in content.splitlines():
                line = cls._normalize_recovery_line(raw_line)
                if not line:
                    continue
                vuln_type = cls._infer_recovered_vulnerability_type(line)
                if not vuln_type:
                    continue
                title = cls._normalize_recovered_title(line)
                if not title or title in seen_titles:
                    continue
                seen_titles.add(title)
                findings.append(
                    {
                        "vulnerability_type": vuln_type,
                        "severity": cls._RECOVERY_SEVERITY.get(vuln_type, "high"),
                        "title": title,
                        "description": (
                            "Recovered from the runtime assistant transcript after final JSON finalization failed. "
                            f"Evidence line: {line}"
                        ),
                        "confidence": 0.84,
                        "needs_verification": True,
                        "verdict": "candidate",
                        "verification_notes": (
                            "Recovered from high-signal runtime transcript after finalizer failure. "
                            "Please verify the code path before disclosure."
                        ),
                        "origin": "transcript_recovery",
                        "report_status": "recovered_candidate",
                        "evidence_type": "transcript_recovery",
                        "not_finalized": True,
                        "evidence_gaps": ["recovered_after_finalizer_failure"],
                        "entry_point_refs": [],
                        "priority_path_refs": [],
                        "business_flow_notes": [line],
                    }
                )
        return findings

    @classmethod
    def _normalize_recovery_line(cls, raw_line: str) -> str:
        line = re.sub(r"^\s*(?:[-*]|\d+[.)])\s*", "", str(raw_line or "").strip())
        if not line:
            return ""
        lowered = line.lower()
        if lowered.startswith("thought:") or lowered.startswith("tool call:"):
            return ""
        if len(line) < 6:
            return ""
        return line.strip().strip("`").strip()

    @classmethod
    def _infer_recovered_vulnerability_type(cls, line: str) -> str | None:
        lowered = line.lower()
        for vuln_type, keywords in cls._RECOVERY_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                return vuln_type
        return None

    @staticmethod
    def _normalize_recovered_title(line: str) -> str:
        cleaned = re.sub(r"\s*[-:：]\s*(?:明确确认|待确认|confirmed|candidate).*$", "", line, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*[（(].*?(?:策略|确认|confirmed|candidate).*?[）)]\s*$", "", cleaned, flags=re.IGNORECASE)
        return cleaned.replace("`", "").strip()

    @staticmethod
    def _fallback_summary(snapshot: Any, recovered_findings: list[dict[str, Any]] | None = None) -> str:
        recovered_findings = list(recovered_findings or [])
        last_assistant = ''
        for message in reversed(getattr(snapshot, 'messages', []) or []):
            if getattr(message, 'role', '') == 'assistant':
                last_assistant = str(getattr(message, 'content', '') or '').strip()
                if last_assistant:
                    break
        prefix = ""
        if recovered_findings:
            prefix = (
                f"Finding runtime 未产出结构化最终结果。以下 {len(recovered_findings)} 条内容只是从 transcript 恢复的候选线索，不是最终漏洞结论。"
            )
        if last_assistant:
            return (
                prefix
                + "最后一条 assistant 回复："
                + last_assistant[:1200]
            )
        return prefix or "Finding runtime 未产出结构化最终结果。"

