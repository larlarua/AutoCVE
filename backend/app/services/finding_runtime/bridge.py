from __future__ import annotations

import inspect
import json
import re
from collections.abc import AsyncGenerator, Callable
from typing import Any

from app.db.session import get_sync_session_factory
from app.services.agent.json_parser import AgentJsonParser
from app.services.finding_runtime.adapters.finding import FindingRuntimeAdapter
from app.services.finding_runtime.memory import RuntimeMemoryManager
from app.services.finding_runtime.models import (
    RuntimeCompletionMode,
    RuntimeMessageRole,
    RuntimeModelResponse,
    RuntimeStopReason,
    TranscriptItem,
    TurnExecutionResult,
)
from app.services.finding_runtime.runner import FindingRuntimeRunner
from app.services.finding_runtime.session_store import AuditSessionStore
from app.services.finding_runtime.skills import RuntimeSkillCatalog
from app.services.finding_runtime.tooling import ToolOrchestrator, ToolRegistry
from app.services.finding_runtime.tools.finalize_finding import FinalizeFindingTool
from app.services.finding_runtime.tools.finalize_vulnerability_reports import (
    FinalizeVulnerabilityReportsTool,
)
from app.services.runtime_core import build_runtime_tool_registry
from app.services.runtime_core.tool_message_codec import (
    ToolMessageFormat,
    build_runtime_model_messages,
)
from app.services.llm.protocols.registry import resolve_tool_message_format

READ_SAFE_RUNTIME_TOOLS = {"Read", "Glob", "Grep", "Skill"}
REPORT_GENERATION_RUNTIME_TOOLS = {"Read", "Glob", "Grep"}
INTERNAL_TOOL_NAMES = {"think", "reflect", "load_skill_body", "skill_resource_lookup"}
AUTO_FINALIZER_PROMPTS_ENABLED = True
RESUME_TERMINAL_ACTION_NUDGE_LIMIT = 5
RUNTIME_FINALIZATION_PROMPT = (
    "你正在处理 Finding 阶段的最终提交恢复流程。\n\n"
    "不要因为当前已经存在一个完整漏洞就直接结束。FinalizeFinding 是终点工具，调用成功后审计会立即停止。\n\n"
    "如果审计尚未充分覆盖主要攻击面，或者仍存在需要继续验证的高价值候选，请不要调用 FinalizeFinding；"
    "应继续调用 Read/Grep/Glob/PowerShell/Skill 等工具补齐证据。\n\n"
    "只有在审计已经完成且以下条件满足时才调用 FinalizeFinding：\n"
    "1. 已经完成主要攻击面覆盖；\n"
    "2. 所有放入 findings 的漏洞都具备完整 source→sink 利用链、PoC、impact、cve_justification 和 verification_notes；\n"
    "3. 如果 findings 数量较少，summary 明确说明已覆盖范围、被排除候选和没有更多可报告漏洞的原因。\n\n"
    "不要输出 Markdown，不要自然语言宣布完成。继续审计就调用工具；确实完成才调用 FinalizeFinding。"
)
FINALIZER_ELIGIBLE_STOP_REASONS = {
    RuntimeStopReason.COMPLETED,
    RuntimeStopReason.MAX_TURNS,
    RuntimeStopReason.HOOK_STOPPED,
}
NATIVE_TOOL_CALLING_REMINDER = (
    "工具调用协议：\n"
    "当存在可用工具时，继续审计不能只用自然语言表达计划。凡是你说“继续、检查、查看、读取、搜索、追踪、"
    "验证、确认、补齐证据、分析调用链”等意思，必须在同一条 assistant 响应中实际发起原生结构化工具调用。\n\n"
    "如果还需要证据：直接调用 Read/Grep/Glob/Skill/PowerShell 等合适工具继续审计。如果还没有充分覆盖主要攻击面，也必须继续调用工具。\n"
    "如果审计已经充分完成：调用 FinalizeFinding 提交结构化结果；或输出可解析的 {\"findings\": [...], \"summary\": \"...\"} JSON。\n"
    "注意：发现第一个完整漏洞不等于审计完成。FinalizeFinding 调用成功后会终止 Finding 阶段，因此不要把它当作阶段性保存工具。\n"
    "禁止只回复“我将继续/让我继续/下一步我会...”而不调用工具。这样的响应会被视为未完成。\n"
    "不要输出伪工具语法，例如 Tool Call:、Action:、JSON 形式的伪调用；只能使用模型提供方原生 tool_call。"
)


class RuntimeLLMModelClient:
    def __init__(self, *, llm_service, agent_type: str = "finding"):
        self._llm_service = llm_service
        self._agent_type = agent_type

    @staticmethod
    def _finding_stream_retry_override(stream_fn: Callable[..., Any]) -> dict[str, Any]:
        """Disable LLMService retries when QueryLoop owns the retry budget."""
        try:
            parameters = inspect.signature(stream_fn).parameters.values()
        except (TypeError, ValueError):
            return {}
        if any(parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters):
            return {"retry_enabled": False}
        if any(parameter.name == "retry_enabled" for parameter in parameters):
            return {"retry_enabled": False}
        return {}

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
            tool_message_format=self._resolve_tool_message_format(),
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
            reasoning_content=str(response.get("reasoning_content") or ""),
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
            tool_message_format=self._resolve_tool_message_format(),
        )

        final_event: dict[str, Any] | None = None
        async for event in self._llm_service.chat_completion_stream(
            messages=messages,
            agent_type=self._agent_type,
            tools=[self._to_llm_tool_schema(item) for item in tool_definitions],
            parallel_tool_calls=True,
            max_tokens=max_output_tokens_override,
            **self._finding_stream_retry_override(self._llm_service.chat_completion_stream),
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
            reasoning_content=str(final_event.get("reasoning_content") or ""),
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
            tool_message_format=self._resolve_tool_message_format(),
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
                **self._finding_stream_retry_override(stream_fn),
            ):
                normalized = self._normalize_stream_event(event, accumulated=accumulated)
                if normalized is None:
                    continue
                if normalized.get("type") == "content_delta":
                    accumulated = normalized.get("accumulated") or accumulated
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
        tool_message_format: ToolMessageFormat | str = ToolMessageFormat.OPENAI_TOOLS,
    ) -> list[dict[str, Any]]:
        effective_system_prompt = (system_prompt or "").strip()
        if tool_definitions:
            effective_system_prompt = (
                f"{effective_system_prompt}\n\n{NATIVE_TOOL_CALLING_REMINDER}".strip()
                if effective_system_prompt
                else NATIVE_TOOL_CALLING_REMINDER
            )
        return build_runtime_model_messages(
            system_prompt=effective_system_prompt,
            recon_payload=recon_payload,
            transcript=transcript,
            tool_definitions=tool_definitions,
            tool_message_format=tool_message_format,
        )

    def _resolve_tool_message_format(self) -> ToolMessageFormat:
        config = getattr(self._llm_service, "config", None)
        raw = getattr(config, "tool_message_format", None)
        if not raw or str(raw).strip().lower() == "auto":
            endpoint_protocol = str(getattr(config, "endpoint_protocol", "") or "").strip().lower()
            provider = str(getattr(getattr(config, "provider", None), "value", None) or getattr(config, "provider", "") or "").strip().lower()
            resolved = resolve_tool_message_format(endpoint_protocol, provider=provider, requested="auto")
            return ToolMessageFormat(resolved)
        try:
            resolved = resolve_tool_message_format(getattr(config, "endpoint_protocol", None), provider=None, requested=str(raw))
            return ToolMessageFormat(resolved)
        except ValueError:
            return ToolMessageFormat.OPENAI_TOOLS

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
        if event_type == "reasoning_delta":
            content = str(payload.get("reasoning_content") or payload.get("content") or "")
            next_accumulated = str(payload.get("accumulated") or content)
            if not content:
                return None
            return {"type": "reasoning_delta", "content": content, "accumulated": next_accumulated}
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
                "reasoning_content": str(payload.get("reasoning_content") or "").strip(),
                "usage": dict(payload.get("usage") or {}),
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
            require_terminal_action=True,
            terminal_action_nudge_limit=RESUME_TERMINAL_ACTION_NUDGE_LIMIT,
        )
        adapter = FindingRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )
        self._session_store.append_message(
            session_id,
            TranscriptItem(
                role=RuntimeMessageRole.USER,
                name="runtime_resume",
                content=(
                    "这是一次从上一个完整审计边界恢复的任务。请基于已有审计记录继续检查尚未完成的高价值候选，"
                    "不要把之前的中断或自然语言总结当作完成。只有确实完成审计后，才调用 FinalizeFinding 提交结构化结果；"
                    "若仍需证据，请继续调用工具。"
                ),
                metadata={"kind": "runtime_resume_instruction"},
            ),
        )
        # Refresh after appending the instruction: QueryLoop reads its persisted
        # transcript state first, so refreshing before this append would make the
        # resume instruction visible in the database but invisible to the model.
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
        tool_registry: ToolRegistry | None = None,
        finalizer_tools: list[Any] | None = None,
        terminal_action_nudge_message: str | None = None,
    ) -> dict[str, Any]:
        model_client = RuntimeLLMModelClient(llm_service=self._llm_service, agent_type="finding")
        tool_registry = tool_registry or self._build_tool_registry()
        tool_orchestrator = ToolOrchestrator(session_store=self._session_store, tool_registry=tool_registry)
        runner = FindingRuntimeRunner(
            session_store=self._session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            max_turns=max_turns,
            require_terminal_action=True,
            terminal_action_nudge_limit=2,
            terminal_action_nudge_message=terminal_action_nudge_message,
        )
        adapter = FindingRuntimeAdapter(
            session_store=self._session_store,
            runner=runner,
            skill_catalog=RuntimeSkillCatalog(),
            memory_manager=RuntimeMemoryManager(session_factory=self._session_store._session_factory),
        )
        await adapter.refresh_session_context(session_id=session_id)
        runner_result = await runner.run_once(session_id=session_id, model_name=model_name)
        ensure_kwargs = {
            "session_id": session_id,
            "model_name": model_name,
            "max_turns": max_turns,
            "model_client": model_client,
            "runner_result": runner_result,
            "payload_extractor": payload_extractor,
            "finalizer_prompts": finalizer_prompts,
            "fallback_payload_builder": fallback_payload_builder,
        }
        if finalizer_tools is not None:
            ensure_kwargs["finalizer_tools"] = finalizer_tools
        if terminal_action_nudge_message is not None:
            ensure_kwargs["terminal_action_nudge_message"] = terminal_action_nudge_message
        snapshot, final_payload = await self._ensure_payload(**ensure_kwargs)
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
        finalizer_tools: list[Any] | None = None,
        terminal_action_nudge_message: str | None = None,
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

        finalizer_registry = ToolRegistry(finalizer_tools or [FinalizeFindingTool()])
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
                terminal_action_nudge_message=terminal_action_nudge_message,
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

    def _build_report_generation_tool_registry(self) -> ToolRegistry:
        full_registry = build_runtime_tool_registry(
            session_store=self._session_store,
            agent_tools=self._tools,
            agent_type="finding",
            user_id=self._user_id,
            include_finding_finalizer=False,
            include_report_finalizer=True,
        )
        allowed_names = {*REPORT_GENERATION_RUNTIME_TOOLS, FinalizeVulnerabilityReportsTool.name}
        return ToolRegistry([tool for tool in full_registry.all_tools() if tool.name in allowed_names])

    def prepare_report_generation_continuation(
        self,
        *,
        session_id: str,
        system_prompt: str,
        context_message: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        prompt = str(system_prompt or "").strip()
        if not prompt:
            raise ValueError("Report generation system prompt must not be empty.")
        runtime_state = self._session_store.load_runtime_state(session_id)
        runtime_state.metadata["base_system_prompt"] = prompt
        runtime_state.metadata["last_user_message"] = str(context_message or "")
        runtime_state.metadata["report_generation_mode"] = True
        self._session_store.update_system_prompt(session_id, prompt)
        self._session_store.replace_runtime_state(session_id, runtime_state)
        return self._session_store.append_message(
            session_id,
            TranscriptItem(
                role=RuntimeMessageRole.USER,
                name="managed_report_generator",
                content=str(context_message or ""),
                metadata={
                    "kind": "internal_managed_report_request",
                    **dict(metadata or {}),
                },
            ),
        )

    async def continue_session_until_report_payload(
        self,
        *,
        session_id: str,
        payload_extractor: Callable[[Any], Any | None],
        finalizer_prompts: list[str],
        terminal_action_nudge_message: str | None = None,
        model_name: str = "finding-runtime",
        max_turns: int | None = None,
        fallback_payload_builder: Callable[[Any], Any] | None = None,
    ) -> dict[str, Any]:
        return await self.continue_session_until_payload(
            session_id=session_id,
            payload_extractor=payload_extractor,
            finalizer_prompts=finalizer_prompts,
            model_name=model_name,
            max_turns=max_turns,
            fallback_payload_builder=fallback_payload_builder,
            tool_registry=self._build_report_generation_tool_registry(),
            finalizer_tools=[FinalizeVulnerabilityReportsTool()],
            terminal_action_nudge_message=terminal_action_nudge_message,
        )

    @staticmethod
    def _default_finalizer_prompts() -> list[str]:
        if not AUTO_FINALIZER_PROMPTS_ENABLED:
            return []
        return [
            RUNTIME_FINALIZATION_PROMPT
            + "\n如果仍需继续查看文件、验证调用链、补齐 source/sink/PoC/影响面，请继续调用工具，不要结束。"
        ]

    @classmethod
    def _default_fallback_payload(cls, snapshot: Any) -> dict[str, Any]:
        recovered_findings = cls._recover_findings_from_assistant_transcript(snapshot)
        payload = {
            'findings': [],
            'recovered_candidates': recovered_findings,
            'summary': cls._fallback_summary(snapshot, recovered_findings),
            'runtime_completion_mode': RuntimeCompletionMode.INCOMPLETE.value,
            'is_final': False,
            'requires_retry': True,
        }
        runtime_error = cls._latest_runtime_error(snapshot)
        if runtime_error:
            payload['runtime_error'] = runtime_error
        return payload

    @staticmethod
    def _latest_runtime_error(snapshot: Any) -> dict[str, Any] | None:
        for checkpoint in reversed(getattr(snapshot, 'checkpoints', []) or []):
            state_payload = getattr(checkpoint, 'state_payload', None)
            if not isinstance(state_payload, dict):
                continue
            stop_reason = str(state_payload.get('stop_reason') or '').strip()
            error_message = str(state_payload.get('error') or '').strip()
            if stop_reason != RuntimeStopReason.MODEL_ERROR.value and not error_message:
                continue
            return {
                'stop_reason': stop_reason or None,
                'message': error_message or None,
                'error_class': state_payload.get('error_class'),
                'phase': state_payload.get('phase'),
                'checkpoint_id': getattr(checkpoint, 'id', None),
            }
        return None

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
        if completion_mode == RuntimeCompletionMode.FINALIZE_TOOL:
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

