from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
from copy import deepcopy
from typing import Any, AsyncGenerator, Dict, List, Optional

from app.core.config import settings
from app.services.agent.core.errors import LLMConnectionError, LLMRateLimitError, LLMTimeoutError
from app.services.agent.core.retry import LLM_RETRY_CONFIG, RetryConfig, retry_with_backoff

from .factory import LLMFactory
from .types import DEFAULT_MODELS, LLMConfig, LLMMessage, LLMProvider, LLMRequest

try:
    from json_repair import repair_json
    JSON_REPAIR_AVAILABLE = True
except ImportError:
    JSON_REPAIR_AVAILABLE = False

logger = logging.getLogger(__name__)


class LLMService:
    """LLM service with per-agent model override, chat completion, and code analysis helpers."""

    _provider_semaphores: Dict[str, asyncio.Semaphore] = {}
    _provider_semaphore_limits: Dict[str, int] = {}
    _provider_gap_locks: Dict[str, asyncio.Lock] = {}
    _provider_last_request_at: Dict[str, float] = {}

    def __init__(self, user_config: Optional[Dict[str, Any]] = None):
        self._config: Optional[LLMConfig] = None
        self._user_config = user_config or {}

    def _resolve_llm_payload(self, agent_type: Optional[str] = None) -> Dict[str, Any]:
        user_llm_config = deepcopy(self._user_config.get("llmConfig", {}) or {})
        if agent_type:
            agent_configs = user_llm_config.get("agentConfigs") or {}
            override = agent_configs.get(agent_type)
            if isinstance(override, dict) and override.get("enabled"):
                for key in (
                    "llmProvider",
                    "llmApiKey",
                    "llmModel",
                    "llmBaseUrl",
                    "llmTimeout",
                    "llmTemperature",
                    "llmMaxTokens",
                    "llmCustomHeaders",
                    "llmFirstTokenTimeout",
                    "llmStreamTimeout",
                    "agentTimeout",
                    "subAgentTimeout",
                    "toolTimeout",
                    "alwaysThinkingEnabled",
                ):
                    value = override.get(key)
                    if value not in (None, ""):
                        user_llm_config[key] = value
                override_env = override.get("env")
                if isinstance(override_env, dict):
                    base_env = user_llm_config.get("env") if isinstance(user_llm_config.get("env"), dict) else {}
                    user_llm_config["env"] = {**base_env, **override_env}
        return user_llm_config

    def _get_runtime_env(self, llm_payload: Dict[str, Any]) -> Dict[str, str]:
        env_payload = llm_payload.get("env")
        if not isinstance(env_payload, dict):
            return {}
        return {
            str(key): str(value)
            for key, value in env_payload.items()
            if value not in (None, "")
        }

    def _provider_env_candidates(self, provider: LLMProvider) -> Dict[str, List[str]]:
        prefix_map = {
            LLMProvider.CLAUDE: "ANTHROPIC",
            LLMProvider.OPENAI: "OPENAI",
            LLMProvider.GEMINI: "GEMINI",
            LLMProvider.QWEN: "QWEN",
            LLMProvider.DEEPSEEK: "DEEPSEEK",
            LLMProvider.ZHIPU: "ZHIPU",
            LLMProvider.MOONSHOT: "MOONSHOT",
            LLMProvider.BAIDU: "BAIDU",
            LLMProvider.MINIMAX: "MINIMAX",
            LLMProvider.DOUBAO: "DOUBAO",
            LLMProvider.OLLAMA: "OLLAMA",
        }
        prefix = prefix_map.get(provider, "LLM")
        return {
            "api_key": [f"{prefix}_AUTH_TOKEN", f"{prefix}_API_KEY", "LLM_API_KEY"],
            "base_url": [f"{prefix}_BASE_URL", "LLM_BASE_URL"],
            "model": [f"{prefix}_MODEL", "LLM_MODEL"],
            "timeout_ms": ["API_TIMEOUT_MS", "LLM_TIMEOUT_MS"],
        }

    def _first_env_value(self, env_payload: Dict[str, str], keys: List[str]) -> Optional[str]:
        for key in keys:
            value = env_payload.get(key)
            if value not in (None, ""):
                return value
        return None

    def get_agent_timeout_config(self, agent_type: Optional[str] = None) -> Dict[str, int]:
        user_llm_config = self._resolve_llm_payload(agent_type)
        return {
            "llm_first_token_timeout": int(user_llm_config.get("llmFirstTokenTimeout") or getattr(settings, "LLM_FIRST_TOKEN_TIMEOUT", 30)),
            "llm_stream_timeout": int(user_llm_config.get("llmStreamTimeout") or getattr(settings, "LLM_STREAM_TIMEOUT", 60)),
            "agent_timeout": int(user_llm_config.get("agentTimeout") or getattr(settings, "AGENT_TIMEOUT_SECONDS", 1800)),
            "sub_agent_timeout": int(user_llm_config.get("subAgentTimeout") or getattr(settings, "SUB_AGENT_TIMEOUT_SECONDS", 600)),
            "tool_timeout": int(user_llm_config.get("toolTimeout") or getattr(settings, "TOOL_TIMEOUT_SECONDS", 60)),
        }

    def _parse_provider(self, provider_str: str) -> LLMProvider:
        provider_map = {
            "gemini": LLMProvider.GEMINI,
            "openai": LLMProvider.OPENAI,
            "claude": LLMProvider.CLAUDE,
            "qwen": LLMProvider.QWEN,
            "deepseek": LLMProvider.DEEPSEEK,
            "zhipu": LLMProvider.ZHIPU,
            "moonshot": LLMProvider.MOONSHOT,
            "baidu": LLMProvider.BAIDU,
            "minimax": LLMProvider.MINIMAX,
            "doubao": LLMProvider.DOUBAO,
            "ollama": LLMProvider.OLLAMA,
        }
        return provider_map.get((provider_str or "").lower(), LLMProvider.OPENAI)

    def _get_provider_api_key_from_user_config(self, provider: LLMProvider, user_llm_config: Dict[str, Any]) -> Optional[str]:
        provider_key_map = {
            LLMProvider.OPENAI: "openaiApiKey",
            LLMProvider.GEMINI: "geminiApiKey",
            LLMProvider.CLAUDE: "claudeApiKey",
            LLMProvider.QWEN: "qwenApiKey",
            LLMProvider.DEEPSEEK: "deepseekApiKey",
            LLMProvider.ZHIPU: "zhipuApiKey",
            LLMProvider.MOONSHOT: "moonshotApiKey",
            LLMProvider.BAIDU: "baiduApiKey",
            LLMProvider.MINIMAX: "minimaxApiKey",
            LLMProvider.DOUBAO: "doubaoApiKey",
        }
        key_name = provider_key_map.get(provider)
        return user_llm_config.get(key_name) if key_name else None

    def _get_provider_api_key(self, provider: LLMProvider) -> str:
        provider_key_map = {
            LLMProvider.OPENAI: "OPENAI_API_KEY",
            LLMProvider.GEMINI: "GEMINI_API_KEY",
            LLMProvider.CLAUDE: "CLAUDE_API_KEY",
            LLMProvider.QWEN: "QWEN_API_KEY",
            LLMProvider.DEEPSEEK: "DEEPSEEK_API_KEY",
            LLMProvider.ZHIPU: "ZHIPU_API_KEY",
            LLMProvider.MOONSHOT: "MOONSHOT_API_KEY",
            LLMProvider.BAIDU: "BAIDU_API_KEY",
            LLMProvider.MINIMAX: "MINIMAX_API_KEY",
            LLMProvider.DOUBAO: "DOUBAO_API_KEY",
        }
        key_name = provider_key_map.get(provider)
        if key_name:
            return getattr(settings, key_name, "") or ""
        return "ollama"

    def _get_provider_base_url(self, provider: LLMProvider) -> Optional[str]:
        if provider == LLMProvider.OPENAI:
            return getattr(settings, "OPENAI_BASE_URL", None)
        if provider == LLMProvider.OLLAMA:
            return getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434/v1")
        return None

    def get_agent_config(self, agent_type: Optional[str] = None) -> LLMConfig:
        user_llm_config = self._resolve_llm_payload(agent_type)
        provider = self._parse_provider(user_llm_config.get("llmProvider") or getattr(settings, "LLM_PROVIDER", "openai"))
        runtime_env = self._get_runtime_env(user_llm_config)
        env_candidates = self._provider_env_candidates(provider)
        api_key = (
            user_llm_config.get("llmApiKey")
            or self._get_provider_api_key_from_user_config(provider, user_llm_config)
            or self._first_env_value(runtime_env, env_candidates["api_key"])
            or getattr(settings, "LLM_API_KEY", "")
            or self._get_provider_api_key(provider)
        )
        model = (
            user_llm_config.get("llmModel")
            or self._first_env_value(runtime_env, env_candidates["model"])
            or getattr(settings, "LLM_MODEL", "")
            or DEFAULT_MODELS.get(provider, "gpt-4o-mini")
        )
        base_url = (
            user_llm_config.get("llmBaseUrl")
            or self._first_env_value(runtime_env, env_candidates["base_url"])
            or getattr(settings, "LLM_BASE_URL", None)
            or self._get_provider_base_url(provider)
        )
        timeout_ms = user_llm_config.get("llmTimeout")
        if timeout_ms in (None, ""):
            timeout_ms = self._first_env_value(runtime_env, env_candidates["timeout_ms"])
            try:
                timeout_ms = int(timeout_ms) if timeout_ms not in (None, "") else None
            except (TypeError, ValueError):
                timeout_ms = None
        timeout = int(timeout_ms / 1000) if timeout_ms and timeout_ms > 1000 else int(timeout_ms or getattr(settings, "LLM_TIMEOUT", 300))
        temperature = user_llm_config.get("llmTemperature") if user_llm_config.get("llmTemperature") is not None else float(getattr(settings, "LLM_TEMPERATURE", 0.1))
        max_tokens = int(user_llm_config.get("llmMaxTokens") or getattr(settings, "LLM_MAX_TOKENS", 4096))
        return LLMConfig(
            provider=provider,
            api_key=api_key,
            model=model,
            base_url=base_url,
            timeout=timeout,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    @property
    def config(self) -> LLMConfig:
        if self._config is None:
            self._config = self.get_agent_config()
        return self._config

    def _get_output_language(self) -> str:
        user_other_config = self._user_config.get("otherConfig", {}) or {}
        return user_other_config.get("outputLanguage") or getattr(settings, "OUTPUT_LANGUAGE", "zh-CN")

    def _get_runtime_llm_limits(self) -> Dict[str, int]:
        other_config = self._user_config.get("otherConfig", {}) or {}
        raw_concurrency = other_config.get("llmConcurrency")
        raw_gap_ms = other_config.get("llmGapMs")

        try:
            concurrency = int(raw_concurrency) if raw_concurrency is not None else int(getattr(settings, "LLM_CONCURRENCY", 3))
        except (TypeError, ValueError):
            concurrency = int(getattr(settings, "LLM_CONCURRENCY", 3))

        try:
            gap_ms = int(raw_gap_ms) if raw_gap_ms is not None else int(getattr(settings, "LLM_GAP_MS", 0))
        except (TypeError, ValueError):
            gap_ms = int(getattr(settings, "LLM_GAP_MS", 0))

        return {
            "concurrency": max(1, concurrency),
            "gap_ms": max(0, gap_ms),
        }

    def _build_provider_limit_key(self, config: LLMConfig) -> str:
        return "|".join(
            [
                config.provider.value,
                config.base_url or "",
                hashlib.sha1((config.api_key or "").encode("utf-8")).hexdigest()[:12],
            ]
        )

    def _get_provider_semaphore(self, config: LLMConfig) -> asyncio.Semaphore:
        key = self._build_provider_limit_key(config)
        desired_limit = self._get_runtime_llm_limits()["concurrency"]
        semaphore = self._provider_semaphores.get(key)
        if semaphore is None or self._provider_semaphore_limits.get(key) != desired_limit:
            semaphore = asyncio.Semaphore(desired_limit)
            self._provider_semaphores[key] = semaphore
            self._provider_semaphore_limits[key] = desired_limit
        return semaphore

    def _get_provider_gap_lock(self, config: LLMConfig) -> asyncio.Lock:
        key = self._build_provider_limit_key(config)
        lock = self._provider_gap_locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._provider_gap_locks[key] = lock
        return lock

    async def _await_provider_gap(self, config: LLMConfig) -> None:
        gap_ms = self._get_runtime_llm_limits()["gap_ms"]
        if gap_ms <= 0:
            return

        key = self._build_provider_limit_key(config)
        lock = self._get_provider_gap_lock(config)
        async with lock:
            now = asyncio.get_running_loop().time()
            last_started = self._provider_last_request_at.get(key)
            if last_started is not None:
                wait_seconds = (gap_ms / 1000.0) - (now - last_started)
                if wait_seconds > 0:
                    await asyncio.sleep(wait_seconds)
                    now = asyncio.get_running_loop().time()
            self._provider_last_request_at[key] = now

    def _normalize_retryable_llm_error(self, error: Exception) -> Exception:
        if isinstance(error, (LLMRateLimitError, LLMTimeoutError, LLMConnectionError)):
            return error

        status_code = getattr(error, "status_code", None)
        message = str(error or "")
        lowered = message.lower()

        if status_code == 429 or any(token in lowered for token in ("rate limit", "too many requests", "频率超限", "限流")):
            return LLMRateLimitError(message, retry_after=15, cause=error)
        if "timeout" in lowered or "timed out" in lowered:
            return LLMTimeoutError(message, cause=error)
        if status_code == 503 or any(
            token in lowered
            for token in (
                "connection",
                "connect",
                "network",
                "dns",
                "temporarily unavailable",
                "service unavailable",
                "server disconnected",
                "no available accounts",
                "unavailable account",
            )
        ):
            return LLMConnectionError(message, cause=error)
        return error

    async def _execute_chat_completion(self, adapter: Any, request: LLMRequest, config: LLMConfig) -> Any:
        semaphore = self._get_provider_semaphore(config)
        retry_config = RetryConfig(
            max_attempts=LLM_RETRY_CONFIG.max_attempts,
            base_delay=LLM_RETRY_CONFIG.base_delay,
            max_delay=LLM_RETRY_CONFIG.max_delay,
            exponential_base=LLM_RETRY_CONFIG.exponential_base,
            jitter=LLM_RETRY_CONFIG.jitter,
            jitter_factor=LLM_RETRY_CONFIG.jitter_factor,
            backoff_strategy=LLM_RETRY_CONFIG.backoff_strategy,
            retryable_exceptions=LLM_RETRY_CONFIG.retryable_exceptions,
        )

        async def attempt() -> Any:
            async with semaphore:
                await self._await_provider_gap(config)
                try:
                    return await adapter.complete(request)
                except Exception as exc:  # noqa: BLE001
                    raise self._normalize_retryable_llm_error(exc) from exc

        return await retry_with_backoff(
            attempt,
            config=retry_config,
            operation_name=f"{config.provider.value} chat completion",
        )


    async def _execute_chat_completion_stream(self, adapter: Any, request: LLMRequest, config: LLMConfig):
        semaphore = self._get_provider_semaphore(config)
        retry_config = RetryConfig(
            max_attempts=LLM_RETRY_CONFIG.max_attempts,
            base_delay=LLM_RETRY_CONFIG.base_delay,
            max_delay=LLM_RETRY_CONFIG.max_delay,
            exponential_base=LLM_RETRY_CONFIG.exponential_base,
            jitter=LLM_RETRY_CONFIG.jitter,
            jitter_factor=LLM_RETRY_CONFIG.jitter_factor,
            backoff_strategy=LLM_RETRY_CONFIG.backoff_strategy,
            retryable_exceptions=LLM_RETRY_CONFIG.retryable_exceptions,
        )

        attempt = 0
        while True:
            emitted_any_output = False
            retry_decision: tuple[Exception, float] | None = None

            async with semaphore:
                await self._await_provider_gap(config)
                try:
                    async for event in adapter.stream_complete(request):
                        event_type = str((event or {}).get("type") or "").strip().lower()
                        if event_type in {"token", "tool_call", "done"}:
                            emitted_any_output = True

                        if event_type == "error":
                            normalized_error = self._normalize_stream_error_event(event)
                            if (
                                not emitted_any_output
                                and attempt < retry_config.max_attempts - 1
                                and retry_config.should_retry(normalized_error)
                            ):
                                retry_decision = (
                                    normalized_error,
                                    retry_config.calculate_delay(attempt, normalized_error),
                                )
                                break
                            yield self._build_terminal_stream_error_event(
                                normalized_error,
                                base_event=event,
                                max_attempts=retry_config.max_attempts,
                                attempts_used=attempt + 1,
                            )
                            return

                        yield event
                        if event_type == "done":
                            return
                except Exception as exc:  # noqa: BLE001
                    normalized_error = self._normalize_retryable_llm_error(exc)
                    if (
                        not emitted_any_output
                        and attempt < retry_config.max_attempts - 1
                        and retry_config.should_retry(normalized_error)
                    ):
                        retry_decision = (
                            normalized_error,
                            retry_config.calculate_delay(attempt, normalized_error),
                        )
                    else:
                        yield self._build_terminal_stream_error_event(
                            normalized_error,
                            base_event=None,
                            max_attempts=retry_config.max_attempts,
                            attempts_used=attempt + 1,
                        )
                        return

            if retry_decision is None:
                return

            attempt += 1
            error, delay = retry_decision
            yield self._build_llm_retry_event(
                error=error,
                attempt=attempt,
                max_attempts=retry_config.max_attempts,
            )
            await asyncio.sleep(delay)

    def _normalize_stream_error_event(self, event: Dict[str, Any]) -> Exception:
        error_type = str(event.get("error_type") or "").strip().lower()
        error_message = str(event.get("error") or event.get("user_message") or "LLM streaming request failed").strip()

        if error_type == "rate_limit":
            return LLMRateLimitError(error_message, retry_after=15)
        if error_type == "connection":
            return LLMConnectionError(error_message)
        if error_type == "quota_exceeded":
            return Exception(error_message)
        return self._normalize_retryable_llm_error(Exception(error_message))

    @staticmethod
    def _describe_stream_error(error: Exception) -> tuple[str, str]:
        if isinstance(error, LLMRateLimitError):
            return "rate_limit", "模型服务当前请求过多，"
        if isinstance(error, LLMTimeoutError):
            return "timeout", "模型响应超时，"
        if isinstance(error, LLMConnectionError):
            return "connection", "上游模型账号或连接暂时不可用，"
        return "unknown", "模型服务暂时不可用，"

    @classmethod
    def _build_llm_retry_event(cls, *, error: Exception, attempt: int, max_attempts: int) -> Dict[str, Any]:
        error_type, prefix = cls._describe_stream_error(error)
        return {
            "type": "llm_retry",
            "attempt": attempt,
            "max_attempts": max_attempts,
            "error_type": error_type,
            "message_text": f"{prefix}正在进行第 {attempt}/{max_attempts} 次自动重试……",
            "error": str(error),
        }

    @classmethod
    def _build_terminal_stream_error_event(
        cls,
        error: Exception,
        *,
        base_event: Dict[str, Any] | None,
        max_attempts: int,
        attempts_used: int,
    ) -> Dict[str, Any]:
        payload = dict(base_event or {})
        error_type, _ = cls._describe_stream_error(error)
        if isinstance(error, (LLMConnectionError, LLMTimeoutError, LLMRateLimitError)) and attempts_used >= max_attempts:
            user_message = f"模型服务连接失败，已自动重试 {max_attempts} 次仍未恢复。请稍后重试或切换可用账号。"
        else:
            user_message = str(payload.get("user_message") or str(error) or "LLM streaming request failed").strip()
        return {
            **payload,
            "type": "error",
            "error_type": str(payload.get("error_type") or error_type or "unknown"),
            "error": str(payload.get("error") or str(error)),
            "user_message": user_message,
        }

    def _build_analysis_schema(self) -> str:
        return json.dumps(
            {
                "issues": [
                    {
                        "type": "security|bug|performance|style|maintainability",
                        "severity": "critical|high|medium|low",
                        "title": "string",
                        "description": "string",
                        "suggestion": "string",
                        "line": 1,
                        "column": 1,
                        "code_snippet": "string",
                        "ai_explanation": "string",
                        "xai": {
                            "what": "string",
                            "why": "string",
                            "how": "string",
                            "learn_more": "string(optional)",
                        },
                    }
                ],
                "quality_score": 0,
                "summary": {
                    "total_issues": 0,
                    "critical_issues": 0,
                    "high_issues": 0,
                    "medium_issues": 0,
                    "low_issues": 0,
                },
                "metrics": {
                    "complexity": 0,
                    "maintainability": 0,
                    "security": 0,
                    "performance": 0,
                },
            },
            ensure_ascii=False,
            indent=2,
        )

    def _analysis_system_prompt(self, output_language: Optional[str] = None) -> str:
        is_chinese = (output_language or self._get_output_language()).lower().startswith("zh")
        schema = self._build_analysis_schema()
        if is_chinese:
            return (
                "你是专业代码审计助手。请只输出 JSON，不要输出 Markdown，不要输出解释性前后缀。\n"
                "返回结果必须符合给定 Schema，并尽量发现安全、逻辑、性能和可维护性问题。\n"
                "line 和 column 必须是数字，code_snippet 使用字符串。\n"
                f"JSON Schema:\n{schema}"
            )
        return (
            "You are a professional code auditing assistant. Output JSON only. No markdown, no prose outside JSON.\n"
            "Return issues for security, bugs, performance, style, and maintainability.\n"
            f"JSON Schema:\n{schema}"
        )

    def _build_system_prompt(self, is_chinese: bool) -> str:
        return self._analysis_system_prompt("zh-CN" if is_chinese else "en-US")

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        agent_type: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        parallel_tool_calls: Optional[bool] = None,
    ) -> Dict[str, Any]:
        config = self.get_agent_config(agent_type)
        adapter = LLMFactory.create_adapter(config)
        request = LLMRequest(
            messages=[LLMMessage(role=item["role"], content=item["content"]) for item in messages],
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            parallel_tool_calls=parallel_tool_calls,
            stream=False,
        )
        response = await self._execute_chat_completion(adapter, request, config)
        usage = None
        if response.usage:
            usage = {
                "prompt_tokens": response.usage.prompt_tokens,
                "completion_tokens": response.usage.completion_tokens,
                "total_tokens": response.usage.total_tokens,
            }
        return {
            "content": response.content,
            "model": response.model or config.model,
            "usage": usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "finish_reason": response.finish_reason,
            "tool_calls": getattr(response, "tool_calls", None) or [],
            "tools_ignored": False,
        }

    async def chat_completion_raw(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        agent_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await self.chat_completion(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            agent_type=agent_type,
        )

    async def chat_completion_stream(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        agent_type: Optional[str] = None,
        tools: Optional[List[Dict[str, Any]]] = None,
        parallel_tool_calls: Optional[bool] = None,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        config = self.get_agent_config(agent_type)
        adapter = LLMFactory.create_adapter(config)
        request = LLMRequest(
            messages=[LLMMessage(role=item["role"], content=item["content"]) for item in messages],
            temperature=temperature,
            max_tokens=max_tokens,
            tools=tools,
            parallel_tool_calls=parallel_tool_calls,
            stream=True,
        )
        stream_complete = getattr(adapter, "stream_complete", None)
        if callable(stream_complete):
            async for event in self._execute_chat_completion_stream(adapter, request, config):
                yield event
            return

        result = await self.chat_completion(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            agent_type=agent_type,
            tools=tools,
            parallel_tool_calls=parallel_tool_calls,
        )
        content = result.get("content", "") or ""
        accumulated = ""
        chunk_size = 24
        for index in range(0, len(content), chunk_size):
            token = content[index:index + chunk_size]
            accumulated += token
            yield {"type": "token", "content": token, "accumulated": accumulated}
        for tool_call in result.get("tool_calls") or []:
            yield {"type": "tool_call", "tool_call": tool_call}
        yield {
            "type": "done",
            "content": content,
            "usage": result.get("usage") or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            "tool_calls": result.get("tool_calls") or [],
            "finish_reason": result.get("finish_reason") or "stop",
        }

    def _clean_text(self, text: str) -> str:
        clean = (text or "").replace("\ufeff", "").replace("\u200b", "").replace("\u200c", "").replace("\u200d", "")
        clean = clean.strip()
        clean = re.sub(r"^```json\s*", "", clean, flags=re.IGNORECASE)
        clean = re.sub(r"^```\s*", "", clean)
        clean = re.sub(r"```$", "", clean).strip()
        return clean

    def clean_text(self, text: str) -> str:
        return self._clean_text(text)

    def fix_json_format(self, text: str) -> str:
        text = self._clean_text(text)
        text = re.sub(r",(\s*[}\]])", r"\1", text)
        text = re.sub(r':\s*"([^"]*)\n([^"]*)"', r': "\1\\n\2"', text)
        return text

    def aggressive_fix_json(self, text: str) -> str:
        text = self.fix_json_format(text)
        text = re.sub(r"\n+", "\\n", text)
        text = re.sub(r"\t+", " ", text)
        return text

    def _extract_from_markdown(self, text: str) -> Dict[str, Any]:
        match = re.search(r"```json\s*(\{.*?\})\s*```", text or "", flags=re.IGNORECASE | re.DOTALL)
        if not match:
            match = re.search(r"```\s*(\{.*?\})\s*```", text or "", flags=re.DOTALL)
        if not match:
            raise ValueError("No JSON block found in markdown")
        return json.loads(match.group(1))

    def _extract_json_object(self, text: str) -> Dict[str, Any]:
        clean = self._clean_text(text)
        try:
            return json.loads(clean)
        except Exception:
            pass
        match = re.search(r"\{.*\}", clean, flags=re.DOTALL)
        if match:
            candidate = match.group(0)
            try:
                return json.loads(candidate)
            except Exception:
                if JSON_REPAIR_AVAILABLE:
                    repaired = repair_json(candidate)
                    return json.loads(repaired) if isinstance(repaired, str) else repaired
        if JSON_REPAIR_AVAILABLE:
            repaired = repair_json(clean)
            return json.loads(repaired) if isinstance(repaired, str) else repaired
        raise ValueError("LLM did not return valid JSON")

    def _fix_truncated_json(self, text: str) -> Dict[str, Any]:
        start_idx = text.find("{")
        if start_idx == -1:
            raise ValueError("Cannot fix truncated JSON")
        json_str = text[start_idx:]
        json_str += "]" * max(0, json_str.count("[") - json_str.count("]"))
        json_str += "}" * max(0, json_str.count("{") - json_str.count("}"))
        json_str = re.sub(r",(\s*[}\]])", r"\1", json_str)
        return json.loads(json_str)

    def _repair_json_with_library(self, text: str) -> Dict[str, Any]:
        if not JSON_REPAIR_AVAILABLE:
            raise ValueError("json-repair library not available")
        start_idx = text.find("{")
        if start_idx == -1:
            raise ValueError("No JSON object found for repair")
        end_idx = text.rfind("}")
        json_str = text[start_idx:end_idx + 1] if end_idx > start_idx else text[start_idx:]
        repaired = repair_json(json_str, return_objects=True)
        if isinstance(repaired, dict):
            return repaired
        if isinstance(repaired, str):
            return json.loads(repaired)
        raise ValueError(f"json-repair returned unexpected type: {type(repaired)}")

    def _get_default_response(self) -> Dict[str, Any]:
        return {
            "issues": [],
            "quality_score": 80,
            "summary": {
                "total_issues": 0,
                "critical_issues": 0,
                "high_issues": 0,
                "medium_issues": 0,
                "low_issues": 0,
            },
            "metrics": {
                "complexity": 80,
                "maintainability": 80,
                "security": 80,
                "performance": 80,
            },
        }

    def _parse_json(self, text: str) -> Dict[str, Any]:
        if not text or not text.strip():
            raise ValueError("LLM response content is empty")
        clean = self._clean_text(text)
        attempts = [
            lambda: json.loads(clean),
            lambda: json.loads(self.fix_json_format(clean)),
            lambda: self._extract_from_markdown(text),
            lambda: self._extract_json_object(clean),
            lambda: self._fix_truncated_json(clean),
            lambda: json.loads(self.aggressive_fix_json(clean)),
            lambda: self._repair_json_with_library(clean),
        ]
        last_error: Optional[Exception] = None
        for attempt in attempts:
            try:
                result = attempt()
                if isinstance(result, dict):
                    return result
            except Exception as exc:
                last_error = exc
        raise ValueError(f"Failed to parse JSON from LLM response: {last_error}")

    def _normalize_analysis(self, payload: Dict[str, Any], code: str = "") -> Dict[str, Any]:
        issues = payload.get("issues") if isinstance(payload.get("issues"), list) else []
        normalized_issues = []
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            try:
                line = int(issue.get("line") or 1)
            except Exception:
                line = 1
            try:
                column = int(issue.get("column") or 1)
            except Exception:
                column = 1
            normalized_issues.append(
                {
                    "type": str(issue.get("type") or "maintainability"),
                    "severity": str(issue.get("severity") or "low"),
                    "title": str(issue.get("title") or "Issue"),
                    "description": str(issue.get("description") or ""),
                    "suggestion": str(issue.get("suggestion") or ""),
                    "line": line,
                    "column": column,
                    "code_snippet": str(issue.get("code_snippet") or ""),
                    "ai_explanation": str(issue.get("ai_explanation") or ""),
                    "xai": issue.get("xai") if isinstance(issue.get("xai"), dict) else {},
                }
            )
        summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
        metrics = payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {}
        return {
            "issues": normalized_issues,
            "quality_score": float(payload.get("quality_score") or max(0, 100 - len(normalized_issues) * 5)),
            "summary": {
                "total_issues": len(normalized_issues),
                "critical_issues": sum(1 for issue in normalized_issues if issue["severity"] == "critical"),
                "high_issues": sum(1 for issue in normalized_issues if issue["severity"] == "high"),
                "medium_issues": sum(1 for issue in normalized_issues if issue["severity"] == "medium"),
                "low_issues": sum(1 for issue in normalized_issues if issue["severity"] == "low"),
                **summary,
            },
            "metrics": {
                "complexity": int(metrics.get("complexity") or 70),
                "maintainability": int(metrics.get("maintainability") or 70),
                "security": int(metrics.get("security") or 70),
                "performance": int(metrics.get("performance") or 70),
            },
        }

    async def analyze_code(self, code: str, language: str, output_language: Optional[str] = None) -> Dict[str, Any]:
        actual_language = output_language or self._get_output_language()
        is_chinese = actual_language.lower().startswith("zh")
        code_with_lines = "\n".join(f"{i + 1}| {line}" for i, line in enumerate(code.split("\n")))
        if is_chinese:
            user_prompt = (
                f"编程语言: {language}\n\n"
                "⚠️ 代码已标注行号（格式：行号| 代码内容），请根据行号准确填写 line 字段。\n\n"
                f"请分析以下代码：\n\n{code_with_lines}"
            )
        else:
            user_prompt = (
                f"Programming Language: {language}\n\n"
                "⚠️ Code is annotated with line numbers (format: lineNumber| code), please fill the line field accurately.\n\n"
                f"Please analyze the following code:\n\n{code_with_lines}"
            )
        result = await self.chat_completion(
            messages=[
                {"role": "system", "content": self._analysis_system_prompt(actual_language)},
                {"role": "user", "content": user_prompt},
            ]
        )
        payload = self._parse_json(result.get("content", ""))
        return self._normalize_analysis(payload, code)

    async def analyze_code_with_custom_prompt(
        self,
        code: str,
        language: str,
        custom_prompt: str,
        output_language: Optional[str] = None,
        rules: Optional[list] = None,
    ) -> Dict[str, Any]:
        actual_language = output_language or self._get_output_language()
        code_with_lines = "\n".join(f"{i + 1}| {line}" for i, line in enumerate(code.split("\n")))
        rules_prompt = ""
        if rules:
            rules_prompt = "\n\nRules:\n" + "\n".join(
                f"- [{rule.get('rule_code', '')}] {rule.get('name', '')}: {rule.get('description', '')}"
                for rule in rules
                if isinstance(rule, dict) and rule.get("enabled", True)
            )
        result = await self.chat_completion(
            messages=[
                {"role": "system", "content": self._analysis_system_prompt(actual_language)},
                {"role": "user", "content": f"{custom_prompt}{rules_prompt}\n\n```{language}\n{code_with_lines}\n```"},
            ]
        )
        payload = self._parse_json(result.get("content", ""))
        return self._normalize_analysis(payload, code)

    async def analyze_code_with_rules(
        self,
        code: str,
        language: str,
        rule_set_id: Optional[str] = None,
        prompt_template_id: Optional[str] = None,
        db_session: Any = None,
        use_default_template: bool = True,
        output_language: Optional[str] = None,
    ) -> Dict[str, Any]:
        custom_prompt = None
        rules = None

        if db_session is not None:
            try:
                from sqlalchemy import select
                from sqlalchemy.orm import selectinload
                from app.models.prompt_template import PromptTemplate
                from app.models.audit_rule import AuditRuleSet

                actual_language = output_language or self._get_output_language()
                is_chinese = actual_language.lower().startswith("zh")

                if prompt_template_id:
                    result = await db_session.execute(select(PromptTemplate).where(PromptTemplate.id == prompt_template_id))
                    template = result.scalar_one_or_none()
                    if template:
                        custom_prompt = template.content_zh if is_chinese else template.content_en
                elif use_default_template:
                    result = await db_session.execute(
                        select(PromptTemplate).where(
                            PromptTemplate.is_default == True,
                            PromptTemplate.is_active == True,
                            PromptTemplate.template_type == "system",
                        )
                    )
                    template = result.scalar_one_or_none()
                    if template:
                        custom_prompt = template.content_zh if is_chinese else template.content_en

                if rule_set_id:
                    result = await db_session.execute(
                        select(AuditRuleSet).options(selectinload(AuditRuleSet.rules)).where(AuditRuleSet.id == rule_set_id)
                    )
                    rule_set = result.scalar_one_or_none()
                    if rule_set and getattr(rule_set, "rules", None):
                        rules = [
                            {
                                "rule_code": r.rule_code,
                                "name": r.name,
                                "description": r.description,
                                "category": r.category,
                                "severity": r.severity,
                                "custom_prompt": r.custom_prompt,
                                "enabled": r.enabled,
                            }
                            for r in rule_set.rules
                            if getattr(r, "enabled", True)
                        ]
            except Exception:
                logger.exception("Failed to load prompt template or rule set for analyze_code_with_rules")

        if custom_prompt:
            return await self.analyze_code_with_custom_prompt(
                code=code,
                language=language,
                custom_prompt=custom_prompt,
                output_language=output_language,
                rules=rules,
            )

        extra_lines = []
        if rule_set_id:
            extra_lines.append(f"Rule set id: {rule_set_id}")
        if prompt_template_id:
            extra_lines.append(f"Prompt template id: {prompt_template_id}")
        if rules:
            extra_lines.append("Rules:")
            extra_lines.extend(
                f"- [{rule.get('rule_code', '')}] {rule.get('name', '')}: {rule.get('description', '')}"
                for rule in rules
            )
        extra_text = "\n".join(extra_lines)
        prompt = (
            "Analyze the code according to the configured security rules and prompt template.\n"
            f"{extra_text}\n\n"
            f"```{language}\n{code}\n```"
        )
        result = await self.chat_completion(
            messages=[
                {"role": "system", "content": self._analysis_system_prompt(output_language)},
                {"role": "user", "content": prompt},
            ]
        )
        payload = self._parse_json(result.get("content", ""))
        return self._normalize_analysis(payload, code)


llm_service = LLMService()
