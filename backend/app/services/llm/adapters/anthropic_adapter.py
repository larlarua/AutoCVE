"""
Anthropic Messages API adapter.

Used when a model endpoint is configured as Anthropic-native. This path keeps
assistant tool_use blocks paired with user tool_result blocks instead of sending
them through LiteLLM's OpenAI chat-completion validator.
"""

from __future__ import annotations

import json
import logging
from collections.abc import AsyncGenerator
from typing import Any

import httpx

from ..base_adapter import BaseLLMAdapter
from ..types import (
    DEFAULT_BASE_URLS,
    LLMConfig,
    LLMError,
    LLMProvider,
    LLMRequest,
    LLMResponse,
    LLMUsage,
)

logger = logging.getLogger(__name__)


def _is_thinking_model(model: str) -> bool:
    """Return True for models that use extended thinking and do not accept temperature or prefill."""
    m = (model or "").lower()
    return "opus-4-8" in m or "claude-3-7-sonnet" in m


class AnthropicAdapter(BaseLLMAdapter):
    """Adapter for Anthropic-native /v1/messages endpoints."""

    ANTHROPIC_VERSION = "2023-06-01"

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._base_url = (config.base_url or DEFAULT_BASE_URLS[LLMProvider.CLAUDE]).rstrip("/")

    async def complete(self, request: LLMRequest) -> LLMResponse:
        try:
            await self.validate_config()
            return await self.retry(lambda: self._send_request(request))
        except Exception as error:
            api_response = getattr(error, "api_response", None)
            self.handle_error(error, "Anthropic API call failed", api_response=api_response)

    async def _send_request(self, request: LLMRequest) -> LLMResponse:
        response = await self.client.post(
            self._messages_url(),
            headers=self._headers(),
            json=self._build_payload(request, stream=False),
        )
        if response.status_code >= 400:
            raise self._to_llm_error(response)
        data = response.json()
        content, tool_calls = self._parse_message_content(data.get("content") or [])
        usage = self._usage_from_payload(data.get("usage") or {})
        return LLMResponse(
            content=content,
            model=data.get("model") or self.config.model,
            usage=usage,
            finish_reason=data.get("stop_reason"),
            tool_calls=tool_calls or None,
        )

    async def stream_complete(self, request: LLMRequest) -> AsyncGenerator[dict[str, Any], None]:
        await self.validate_config()
        payload = self._build_payload(request, stream=True)

        accumulated_content = ""
        accumulated_reasoning = ""
        prompt_tokens = 0
        completion_tokens = 0
        stop_reason = "stop"
        block_states: dict[int, dict[str, Any]] = {}
        collected_tool_calls: list[dict[str, Any]] = []
        done_emitted = False

        try:
            async with self.client.stream(
                "POST",
                self._messages_url(),
                headers=self._headers(),
                json=payload,
            ) as response:
                if response.status_code >= 400:
                    body = await response.aread()
                    raise self._to_llm_error(response, body.decode("utf-8", errors="replace"))

                async for line in response.aiter_lines():
                    event = self._parse_sse_data_line(line)
                    if event is None:
                        continue

                    event_type = str(event.get("type") or "")
                    if event_type == "message_start":
                        usage = ((event.get("message") or {}).get("usage") or {})
                        prompt_tokens = int(usage.get("input_tokens") or prompt_tokens or 0)
                    elif event_type == "content_block_start":
                        index = int(event.get("index") or 0)
                        content_block = dict(event.get("content_block") or {})
                        block_states[index] = {
                            "type": content_block.get("type"),
                            "text": str(content_block.get("text") or ""),
                            "thinking": str(content_block.get("thinking") or ""),
                            "id": content_block.get("id"),
                            "name": content_block.get("name"),
                            "input": content_block.get("input") if isinstance(content_block.get("input"), dict) else {},
                            "partial_json": "",
                        }
                    elif event_type == "content_block_delta":
                        index = int(event.get("index") or 0)
                        delta = dict(event.get("delta") or {})
                        state = block_states.setdefault(index, {"type": None})
                        delta_type = str(delta.get("type") or "")
                        if delta_type == "text_delta":
                            text = str(delta.get("text") or "")
                            if text:
                                accumulated_content += text
                                yield {"type": "token", "content": text, "accumulated": accumulated_content}
                        elif delta_type == "thinking_delta":
                            thinking = str(delta.get("thinking") or "")
                            if thinking:
                                accumulated_reasoning += thinking
                                yield {
                                    "type": "reasoning_delta",
                                    "content": thinking,
                                    "reasoning_content": thinking,
                                    "accumulated": accumulated_reasoning,
                                }
                        elif delta_type == "input_json_delta":
                            state["partial_json"] = f"{state.get('partial_json') or ''}{delta.get('partial_json') or ''}"
                    elif event_type == "content_block_stop":
                        index = int(event.get("index") or 0)
                        state = block_states.get(index) or {}
                        if state.get("type") == "tool_use":
                            tool_call = self._tool_call_from_state(state, index=index)
                            collected_tool_calls.append(tool_call)
                            yield {"type": "tool_call", "tool_call": tool_call}
                    elif event_type == "message_delta":
                        delta = dict(event.get("delta") or {})
                        stop_reason = str(delta.get("stop_reason") or stop_reason or "stop")
                        usage = dict(event.get("usage") or {})
                        completion_tokens = int(usage.get("output_tokens") or completion_tokens or 0)
                    elif event_type == "message_stop":
                        done_emitted = True
                        yield self._done_event(
                            content=accumulated_content,
                            reasoning_content=accumulated_reasoning,
                            tool_calls=collected_tool_calls,
                            stop_reason=stop_reason,
                            prompt_tokens=prompt_tokens,
                            completion_tokens=completion_tokens,
                        )
        except LLMError as error:
            done_emitted = True
            yield self._error_event(error)
        except httpx.HTTPError as error:
            done_emitted = True
            yield self._error_event(LLMError(str(error), self.config.provider, original_error=error))
        except Exception as error:
            logger.exception("Anthropic stream failed")
            done_emitted = True
            yield self._error_event(LLMError(str(error), self.config.provider, original_error=error))

        if not done_emitted:
            yield self._done_event(
                content=accumulated_content,
                reasoning_content=accumulated_reasoning,
                tool_calls=collected_tool_calls,
                stop_reason=stop_reason,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )

    def _messages_url(self) -> str:
        if self._base_url.endswith("/messages"):
            return self._base_url
        if self._base_url.endswith("/v1"):
            return f"{self._base_url}/messages"
        return f"{self._base_url}/v1/messages"

    def _headers(self) -> dict[str, str]:
        headers = self.build_headers(
            {
                "anthropic-version": self.ANTHROPIC_VERSION,
                "accept": "application/json",
            }
        )
        api_key = (self.config.api_key or "").strip()
        if api_key.lower().startswith("bearer "):
            headers["Authorization"] = api_key
        elif api_key:
            headers["x-api-key"] = api_key
        return headers

    def _build_payload(self, request: LLMRequest, *, stream: bool) -> dict[str, Any]:
        messages, system = self._normalize_messages([msg.to_dict() for msg in request.messages])
        # Extended thinking models do not support assistant prefill (trailing assistant message)
        if messages and messages[-1]["role"] == "assistant" and _is_thinking_model(self.config.model):
            messages = messages[:-1]
        payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": request.max_tokens if request.max_tokens is not None else self.config.max_tokens,
            "stream": stream,
        }
        temperature = request.temperature if request.temperature is not None else self.config.temperature
        # Extended thinking models do not accept the temperature parameter
        if temperature is not None and not _is_thinking_model(self.config.model):
            payload["temperature"] = temperature
        if system:
            payload["system"] = system
        tools = self._normalize_tools(request.tools or [])
        if tools:
            payload["tools"] = tools
        return payload

    def _normalize_messages(self, messages: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], str]:
        normalized: list[dict[str, Any]] = []
        system_parts: list[str] = []
        for message in messages:
            role = str(message.get("role") or "user")
            content = message.get("content")
            if role == "system":
                system_parts.append(self._content_to_text(content))
                continue
            if role == "tool":
                normalized.append(
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "tool_result",
                                "tool_use_id": str(message.get("tool_call_id") or ""),
                                "content": self._content_to_text(content),
                            }
                        ],
                    }
                )
                continue
            if role not in {"user", "assistant"}:
                role = "user"
            if content is None:
                content = ""
            if content == "" and role == "assistant" and not message.get("tool_calls"):
                continue
            normalized.append({"role": role, "content": content})
        return normalized, "\n\n".join(part for part in system_parts if part)

    @staticmethod
    def _content_to_text(content: Any) -> str:
        if isinstance(content, str):
            return content
        if content is None:
            return ""
        if isinstance(content, list):
            parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "text":
                        parts.append(str(block.get("text") or ""))
                    elif block.get("type") == "tool_result":
                        parts.append(str(block.get("content") or ""))
                    else:
                        parts.append(json.dumps(block, ensure_ascii=False))
                else:
                    parts.append(str(block))
            return "\n".join(part for part in parts if part)
        return json.dumps(content, ensure_ascii=False)

    @staticmethod
    def _normalize_tools(tools: list[dict[str, Any]]) -> list[dict[str, Any]]:
        normalized: list[dict[str, Any]] = []
        for tool in tools:
            if "function" in tool:
                function = dict(tool.get("function") or {})
                normalized.append(
                    {
                        "name": str(function.get("name") or ""),
                        "description": str(function.get("description") or ""),
                        "input_schema": function.get("parameters") or {"type": "object", "properties": {}},
                    }
                )
                continue
            if "name" in tool:
                normalized.append(
                    {
                        "name": str(tool.get("name") or ""),
                        "description": str(tool.get("description") or ""),
                        "input_schema": tool.get("input_schema") or tool.get("parameters") or {"type": "object", "properties": {}},
                    }
                )
        return [tool for tool in normalized if tool.get("name")]

    @staticmethod
    def _parse_sse_data_line(line: str) -> dict[str, Any] | None:
        line = (line or "").strip()
        if not line.startswith("data:"):
            return None
        data = line[len("data:") :].strip()
        if not data or data == "[DONE]":
            return None
        return json.loads(data)

    @staticmethod
    def _tool_call_from_state(state: dict[str, Any], *, index: int) -> dict[str, Any]:
        arguments_obj = state.get("input") if isinstance(state.get("input"), dict) else {}
        partial_json = str(state.get("partial_json") or "").strip()
        if partial_json:
            try:
                parsed = json.loads(partial_json)
                if isinstance(parsed, dict):
                    arguments_obj = parsed
            except json.JSONDecodeError:
                arguments_obj = {}
        return {
            "id": str(state.get("id") or f"toolu_{index}"),
            "type": "function",
            "name": str(state.get("name") or ""),
            "arguments": json.dumps(arguments_obj, ensure_ascii=False),
        }

    def _parse_message_content(self, blocks: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
        text_parts: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        for index, block in enumerate(blocks):
            block_type = block.get("type")
            if block_type == "text":
                text_parts.append(str(block.get("text") or ""))
            elif block_type == "tool_use":
                tool_calls.append(
                    self._tool_call_from_state(
                        {
                            "id": block.get("id"),
                            "name": block.get("name"),
                            "input": block.get("input") if isinstance(block.get("input"), dict) else {},
                        },
                        index=index,
                    )
                )
        return "".join(text_parts), tool_calls

    @staticmethod
    def _usage_from_payload(usage: dict[str, Any]) -> LLMUsage | None:
        if not usage:
            return None
        prompt_tokens = int(usage.get("input_tokens") or 0)
        completion_tokens = int(usage.get("output_tokens") or 0)
        return LLMUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        )

    @staticmethod
    def _done_event(
        *,
        content: str,
        reasoning_content: str,
        tool_calls: list[dict[str, Any]],
        stop_reason: str,
        prompt_tokens: int,
        completion_tokens: int,
    ) -> dict[str, Any]:
        return {
            "type": "done",
            "content": content,
            "reasoning_content": reasoning_content,
            "finish_reason": stop_reason,
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
            "tool_calls": list(tool_calls),
        }

    def _to_llm_error(self, response: httpx.Response, body: str | None = None) -> LLMError:
        raw = body if body is not None else response.text
        message = raw or f"HTTP {response.status_code}"
        try:
            payload = json.loads(raw) if raw else {}
            error = payload.get("error") if isinstance(payload, dict) else None
            if isinstance(error, dict):
                message = str(error.get("message") or message)
        except Exception:
            pass
        return LLMError(message, self.config.provider, response.status_code, api_response=raw)

    def _error_event(self, error: LLMError) -> dict[str, Any]:
        status_code = getattr(error, "status_code", None)
        error_type = "connection"
        if status_code == 429:
            error_type = "rate_limit"
        elif status_code in {401, 403}:
            error_type = "authentication"
        elif status_code and 400 <= status_code < 500:
            error_type = "api_error"
        return {
            "type": "error",
            "error_type": error_type,
            "error_class": error.__class__.__name__,
            "error": str(error),
            "user_message": str(error) or "Anthropic streaming request failed. Please retry.",
            "accumulated": "",
        }
