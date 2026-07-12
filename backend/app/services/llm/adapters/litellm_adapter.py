"""
LiteLLM 统一适配器
支持通过 LiteLLM 调用多个 LLM 提供商，使用统一的 OpenAI 兼容格式

增强功能:
- Prompt Caching: 为支持的 LLM（如 Claude）添加缓存标记
- 智能重试: 指数退避重试策略
- 流式输出: 支持逐 token 返回
"""

import json
import logging
from typing import Dict, Any, Optional, List
from ..base_adapter import BaseLLMAdapter
from ..types import (
    LLMConfig,
    LLMRequest,
    LLMResponse,
    LLMUsage,
    LLMProvider,
    LLMError,
    DEFAULT_BASE_URLS,
)
from ..prompt_cache import prompt_cache_manager, estimate_tokens
from ..protocols.registry import get_model_capabilities

logger = logging.getLogger(__name__)


def _token_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return ""
    return json.dumps(value, ensure_ascii=False)


class LiteLLMAdapter(BaseLLMAdapter):
    """
    LiteLLM 统一适配器
    
    支持的提供商:
    - OpenAI (openai/gpt-4o-mini)
    - Claude (anthropic/claude-3-5-sonnet-20241022)
    - Gemini (gemini/gemini-1.5-flash)
    - DeepSeek (deepseek/deepseek-chat)
    - Qwen (qwen/qwen-turbo) - 通过 OpenAI 兼容模式
    - Zhipu (zhipu/glm-4-flash) - 通过 OpenAI 兼容模式
    - Moonshot (moonshot/moonshot-v1-8k) - 通过 OpenAI 兼容模式
    - Ollama (ollama/llama3)
    """

    # LiteLLM 模型前缀映射
    PROVIDER_PREFIX_MAP = {
        LLMProvider.OPENAI: "openai",
        LLMProvider.CLAUDE: "anthropic",
        LLMProvider.GEMINI: "gemini",
        LLMProvider.DEEPSEEK: "deepseek",
        LLMProvider.QWEN: "openai",  # 使用 OpenAI 兼容模式
        LLMProvider.ZHIPU: "openai",  # 使用 OpenAI 兼容模式
        LLMProvider.MOONSHOT: "openai",  # 使用 OpenAI 兼容模式
        LLMProvider.MINIMAX: "openai",
        LLMProvider.DOUBAO: "openai",
        LLMProvider.MIMO: "openai",
        LLMProvider.OLLAMA: "ollama",
    }

    # 需要自定义 base_url 的提供商
    CUSTOM_BASE_URL_PROVIDERS = {
        LLMProvider.QWEN,
        LLMProvider.ZHIPU,
        LLMProvider.MOONSHOT,
        LLMProvider.DEEPSEEK,
        LLMProvider.MINIMAX,
        LLMProvider.DOUBAO,
        LLMProvider.MIMO,
    }

    def __init__(self, config: LLMConfig):
        super().__init__(config)
        self._litellm_model = self._get_litellm_model()
        self._api_base = self._get_api_base()

    def _get_litellm_model(self) -> str:
        """获取 LiteLLM 格式的模型名称
        
        对于使用第三方 OpenAI 兼容 API（如 SiliconFlow）的情况：
        - 如果用户设置了自定义 base_url，且模型名包含 / (如 Qwen/Qwen3-8B)
        - 需要将其转换为 openai/Qwen/Qwen3-8B 格式
        - 因为 LiteLLM 只认识 openai 作为有效前缀
        """
        provider = self.config.provider
        model = self.config.model

        # 检查模型名是否已经包含前缀
        if "/" in model:
            # 提取第一部分作为可能的 provider 前缀
            prefix_part = model.split("/")[0].lower()
            
            # LiteLLM 认识的有效 provider 前缀列表
            valid_litellm_prefixes = [
                "openai", "anthropic", "gemini", "deepseek", "ollama",
                "azure", "huggingface", "together", "groq", "mistral",
                "anyscale", "replicate", "bedrock", "vertex_ai", "cohere",
                "sagemaker", "palm", "ai21", "nlp_cloud", "aleph_alpha",
                "petals", "baseten", "vllm", "cloudflare", "xinference"
            ]
            
            # 如果前缀是 LiteLLM 认识的，直接返回
            if prefix_part in valid_litellm_prefixes:
                return model
            
            # 如果用户设置了自定义 base_url，将其视为 OpenAI 兼容 API
            # 例如 SiliconFlow 使用模型名 "Qwen/Qwen3-8B"
            if self.config.base_url:
                logger.debug(f"使用自定义 base_url，将模型 {model} 视为 OpenAI 兼容格式")
                return f"openai/{model}"
            
            # 对于没有自定义 base_url 的情况，尝试使用 provider 的前缀
            prefix = self.PROVIDER_PREFIX_MAP.get(provider, "openai")
            return f"{prefix}/{model}"

        # 获取 provider 前缀
        prefix = self.PROVIDER_PREFIX_MAP.get(provider, "openai")
        
        return f"{prefix}/{model}"

    def _extract_api_response(self, error: Exception) -> Optional[str]:
        """从异常中提取 API 服务器返回的原始响应信息"""
        error_str = str(error)

        # 尝试提取 JSON 格式的错误信息
        import re
        import json

        # 匹配 {'error': {...}} 或 {"error": {...}} 格式
        json_pattern = r"\{['\"]error['\"]:\s*\{[^}]+\}\}"
        match = re.search(json_pattern, error_str)
        if match:
            try:
                # 将单引号替换为双引号以便 JSON 解析
                json_str = match.group().replace("'", '"')
                error_obj = json.loads(json_str)
                if 'error' in error_obj:
                    err = error_obj['error']
                    code = err.get('code', '')
                    message = err.get('message', '')
                    return f"[{code}] {message}" if code else message
            except:
                pass

        # 尝试提取 message 字段
        message_pattern = r"['\"]message['\"]:\s*['\"]([^'\"]+)['\"]"
        match = re.search(message_pattern, error_str)
        if match:
            return match.group(1)

        # 尝试从 litellm 异常中获取原始消息
        if hasattr(error, 'message'):
            return error.message
        if hasattr(error, 'llm_provider'):
            # litellm 异常通常包含原始错误信息
            return error_str.split(' - ')[-1] if ' - ' in error_str else None

        return None

    def _get_api_base(self) -> Optional[str]:
        """获取 API 基础 URL"""
        # 优先使用用户配置的 base_url
        if self.config.base_url:
            return self.config.base_url

        # 对于需要自定义 base_url 的提供商，使用默认值
        if self.config.provider in self.CUSTOM_BASE_URL_PROVIDERS:
            return DEFAULT_BASE_URLS.get(self.config.provider)

        # Ollama 使用本地地址
        if self.config.provider == LLMProvider.OLLAMA:
            return DEFAULT_BASE_URLS.get(LLMProvider.OLLAMA, "http://localhost:11434")

        return None

    def _sampling_kwargs(self, request: LLMRequest) -> Dict[str, float]:
        """Return only sampling parameters explicitly configured for this request."""
        sampling: Dict[str, float] = {}
        temperature = request.temperature if request.temperature is not None else self.config.temperature
        capabilities = get_model_capabilities(self.config.provider, self.config.model)
        if temperature is not None and capabilities.get("supports_temperature", True):
            sampling["temperature"] = temperature
        top_p = request.top_p if request.top_p is not None else self.config.top_p
        if self.config.provider != LLMProvider.CLAUDE and top_p is not None:
            sampling["top_p"] = top_p
        return sampling

    async def complete(self, request: LLMRequest) -> LLMResponse:
        """使用 LiteLLM 发送请求"""
        try:
            await self.validate_config()
            return await self.retry(lambda: self._send_request(request))
        except Exception as error:
            self.handle_error(error, f"LiteLLM ({self.config.provider.value}) API调用失败")

    async def _send_request(self, request: LLMRequest) -> LLMResponse:
        """发送请求到 LiteLLM"""
        import litellm
        
        # 启用 LiteLLM 调试模式以获取更详细的错误信息
        # 注释掉下一行可关闭调试模式
        # litellm._turn_on_debug()
        
        # 禁用 LiteLLM 的缓存，确保每次都实际调用 API
        litellm.cache = None
        
        # 禁用 LiteLLM 自动添加的 reasoning_effort 参数
        # 这可以防止模型名称被错误解析为 effort 参数
        litellm.drop_params = True
        
        # 构建消息
        messages = [msg.to_dict() for msg in request.messages]
        
        # 🔥 Prompt Caching: 为支持的 LLM 添加缓存标记
        cache_enabled = False
        if self.config.provider == LLMProvider.CLAUDE:
            # 估算系统提示词 token 数
            system_tokens = 0
            for msg in messages:
                if msg.get("role") == "system":
                    system_tokens += estimate_tokens(_token_text(msg.get("content", "")))
            
            messages, cache_enabled = prompt_cache_manager.process_messages(
                messages=messages,
                model=self.config.model,
                provider=self.config.provider.value,
                system_prompt_tokens=system_tokens,
            )
            
            if cache_enabled:
                logger.debug(f"🔥 Prompt Caching enabled for {self.config.model}")

        # 构建请求参数
        kwargs: Dict[str, Any] = {
            "model": self._litellm_model,
            "messages": messages,
            "max_tokens": request.max_tokens if request.max_tokens is not None else self.config.max_tokens,
        }

        kwargs.update(self._sampling_kwargs(request))
        if request.tools:
            kwargs["tools"] = request.tools
        if request.parallel_tool_calls is not None:
            kwargs["parallel_tool_calls"] = request.parallel_tool_calls
        if request.tools:
            kwargs["tools"] = request.tools
        if request.parallel_tool_calls is not None:
            kwargs["parallel_tool_calls"] = request.parallel_tool_calls
        if request.tools:
            kwargs["tools"] = request.tools
        if request.parallel_tool_calls is not None:
            kwargs["parallel_tool_calls"] = request.parallel_tool_calls

        # 设置 API Key
        if self.config.api_key and self.config.api_key != "ollama":
            kwargs["api_key"] = self.config.api_key

        # 设置 API Base URL
        if self._api_base:
            kwargs["api_base"] = self._api_base
            logger.debug(f"🔗 使用自定义 API Base: {self._api_base}")

        # 设置超时
        kwargs["timeout"] = self.config.timeout

        # 对于 OpenAI 提供商，添加额外参数
        if self.config.provider == LLMProvider.OPENAI:
            kwargs["frequency_penalty"] = self.config.frequency_penalty
            kwargs["presence_penalty"] = self.config.presence_penalty

        try:
            # 调用 LiteLLM
            response = await litellm.acompletion(**kwargs)
        except litellm.exceptions.AuthenticationError as e:
            api_response = self._extract_api_response(e)
            raise LLMError(f"API Key 无效或已过期", self.config.provider, 401, api_response=api_response)
        except litellm.exceptions.RateLimitError as e:
            error_msg = str(e)
            api_response = self._extract_api_response(e)
            # 区分"余额不足"和"频率超限"
            if any(keyword in error_msg for keyword in ["余额不足", "资源包", "充值", "quota", "insufficient", "balance"]):
                raise LLMError(f"账户余额不足或配额已用尽，请充值后重试", self.config.provider, 402, api_response=api_response)
            raise LLMError(f"API 调用频率超限，请稍后重试", self.config.provider, 429, api_response=api_response)
        except litellm.exceptions.APIConnectionError as e:
            api_response = self._extract_api_response(e)
            raise LLMError(f"无法连接到 API 服务", self.config.provider, api_response=api_response)
        except litellm.exceptions.APIError as e:
            api_response = self._extract_api_response(e)
            raise LLMError(f"API 错误", self.config.provider, getattr(e, 'status_code', None), api_response=api_response)
        except Exception as e:
            # 捕获其他异常并重新抛出
            error_msg = str(e)
            api_response = self._extract_api_response(e)
            if "invalid_api_key" in error_msg.lower() or "incorrect api key" in error_msg.lower():
                raise LLMError(f"API Key 无效", self.config.provider, 401, api_response=api_response)
            elif "authentication" in error_msg.lower():
                raise LLMError(f"认证失败", self.config.provider, 401, api_response=api_response)
            elif any(keyword in error_msg for keyword in ["余额不足", "资源包", "充值", "quota", "insufficient", "balance"]):
                raise LLMError(f"账户余额不足或配额已用尽", self.config.provider, 402, api_response=api_response)
            raise

        # 解析响应
        if not response:
            raise LLMError("API 返回空响应", self.config.provider)
            
        choice = response.choices[0] if response.choices else None
        if not choice:
            raise LLMError("API响应格式异常: 缺少choices字段", self.config.provider)

        usage = None
        if hasattr(response, "usage") and response.usage:
            usage = LLMUsage(
                prompt_tokens=response.usage.prompt_tokens or 0,
                completion_tokens=response.usage.completion_tokens or 0,
                total_tokens=response.usage.total_tokens or 0,
            )
            
            # 🔥 更新 Prompt Cache 统计
            if cache_enabled and hasattr(response.usage, "cache_creation_input_tokens"):
                prompt_cache_manager.update_stats(
                    cache_creation_input_tokens=getattr(response.usage, "cache_creation_input_tokens", 0),
                    cache_read_input_tokens=getattr(response.usage, "cache_read_input_tokens", 0),
                    total_input_tokens=response.usage.prompt_tokens or 0,
                )

        tool_calls = []
        raw_tool_calls = getattr(choice.message, "tool_calls", None) or []
        for tool_call in raw_tool_calls:
            function = getattr(tool_call, "function", None)
            tool_calls.append(
                {
                    "id": getattr(tool_call, "id", "") or "",
                    "type": getattr(tool_call, "type", "function") or "function",
                    "name": getattr(function, "name", "") if function else "",
                    "arguments": getattr(function, "arguments", "") if function else "",
                }
            )

        return LLMResponse(
            content=choice.message.content or "",
            model=response.model,
            usage=usage,
            finish_reason=choice.finish_reason,
            tool_calls=tool_calls or None,
            reasoning_content=str(getattr(choice.message, "reasoning_content", None) or ""),
        )

    async def stream_complete(self, request: LLMRequest):
        """
        Stream model output and surface provider-native tool call events.
        """
        import json
        import litellm

        await self.validate_config()

        litellm.cache = None
        litellm.drop_params = True

        messages = [msg.to_dict() for msg in request.messages]
        input_tokens_estimate = sum(
            estimate_tokens(_token_text(msg["content"]), self.config.model) for msg in messages
        )

        kwargs = {
            "model": self._litellm_model,
            "messages": messages,
            "max_tokens": request.max_tokens if request.max_tokens is not None else self.config.max_tokens,
            "stream": True,
        }

        kwargs.update(self._sampling_kwargs(request))
        if request.tools:
            kwargs["tools"] = request.tools
        if request.parallel_tool_calls is not None:
            kwargs["parallel_tool_calls"] = request.parallel_tool_calls
        if self.config.provider in [LLMProvider.OPENAI, LLMProvider.DEEPSEEK]:
            kwargs["stream_options"] = {"include_usage": True}
        if self.config.api_key and self.config.api_key != "ollama":
            kwargs["api_key"] = self.config.api_key
        if self._api_base:
            kwargs["api_base"] = self._api_base
        kwargs["timeout"] = self.config.timeout

        accumulated_content = ""
        accumulated_reasoning_content = ""
        final_usage = None
        chunk_count = 0
        partial_tool_calls: Dict[int, Dict[str, Any]] = {}
        emitted_tool_calls: set[int] = set()
        collected_tool_calls: List[Dict[str, Any]] = []

        def _as_dictish(value, field=None, default=None):
            if isinstance(value, dict):
                if field is None:
                    return value
                return value.get(field, default)
            if field is None:
                return value
            direct = getattr(value, field, default)
            if direct is not default and direct is not None:
                return direct
            for extra_name in ("model_extra", "additional_kwargs", "provider_specific_fields"):
                extra = getattr(value, extra_name, None)
                if isinstance(extra, dict) and extra.get(field) is not None:
                    return extra.get(field)
            model_dump = getattr(value, "model_dump", None)
            if callable(model_dump):
                try:
                    dumped = model_dump()
                except Exception:
                    dumped = None
                if isinstance(dumped, dict) and dumped.get(field) is not None:
                    return dumped.get(field)
            legacy_dict = getattr(value, "dict", None)
            if callable(legacy_dict):
                try:
                    dumped = legacy_dict()
                except Exception:
                    dumped = None
                if isinstance(dumped, dict) and dumped.get(field) is not None:
                    return dumped.get(field)
            return default

        def _iter_delta_tool_calls(delta):
            for raw in _as_dictish(delta, "tool_calls", []) or []:
                function = _as_dictish(raw, "function", {}) or {}
                yield {
                    "index": _as_dictish(raw, "index", 0) or 0,
                    "id": _as_dictish(raw, "id", "") or "",
                    "type": _as_dictish(raw, "type", "function") or "function",
                    "name": _as_dictish(function, "name", "") or "",
                    "arguments": _as_dictish(function, "arguments", "") or "",
                }

        def _delta_reasoning_content(delta) -> str:
            value = _as_dictish(delta, "reasoning_content", None)
            if value is None:
                value = _as_dictish(delta, "reasoning", None)
            if value is None:
                return ""
            return str(value)

        def _is_complete_json(arguments: str) -> bool:
            if not arguments or not arguments.strip():
                return False
            try:
                json.loads(arguments)
            except Exception:
                return False
            return True

        def _normalize_stream_tool_call(index: int, state: Dict[str, Any]) -> Dict[str, Any]:
            return {
                "id": state.get("id") or f"tool_call_{index}",
                "type": state.get("type") or "function",
                "name": state.get("name") or "",
                "arguments": state.get("arguments") or "{}",
            }

        def _collect_ready_tool_calls(delta, *, force_flush: bool = False) -> List[Dict[str, Any]]:
            ready: List[Dict[str, Any]] = []
            for tool_delta in _iter_delta_tool_calls(delta):
                index = int(tool_delta.get("index") or 0)
                state = partial_tool_calls.setdefault(
                    index,
                    {"id": "", "type": "function", "name": "", "arguments": ""},
                )
                if tool_delta.get("id"):
                    state["id"] = tool_delta["id"]
                if tool_delta.get("type"):
                    state["type"] = tool_delta["type"]
                if tool_delta.get("name"):
                    state["name"] = f"{state['name']}{tool_delta['name']}"
                if tool_delta.get("arguments"):
                    state["arguments"] = f"{state['arguments']}{tool_delta['arguments']}"
                if index in emitted_tool_calls:
                    continue
                if state.get("name") and _is_complete_json(state.get("arguments") or ""):
                    emitted_tool_calls.add(index)
                    ready.append(_normalize_stream_tool_call(index, state))

            if force_flush:
                for index, state in sorted(partial_tool_calls.items()):
                    if index in emitted_tool_calls:
                        continue
                    if not state.get("name"):
                        continue
                    emitted_tool_calls.add(index)
                    ready.append(_normalize_stream_tool_call(index, state))
            return ready

        try:
            response = await litellm.acompletion(**kwargs)

            async for chunk in response:
                chunk_count += 1

                if hasattr(chunk, "usage") and chunk.usage:
                    final_usage = {
                        "prompt_tokens": chunk.usage.prompt_tokens or 0,
                        "completion_tokens": chunk.usage.completion_tokens or 0,
                        "total_tokens": chunk.usage.total_tokens or 0,
                    }
                    logger.debug(f"Got usage from chunk: {final_usage}")

                if not getattr(chunk, "choices", None):
                    continue

                choice = chunk.choices[0]
                delta = getattr(choice, "delta", None) or {}
                content = _as_dictish(delta, "content", "") or ""
                reasoning_content = _delta_reasoning_content(delta)
                finish_reason = getattr(choice, "finish_reason", None)

                if reasoning_content:
                    accumulated_reasoning_content += reasoning_content
                    yield {
                        "type": "reasoning_delta",
                        "content": reasoning_content,
                        "reasoning_content": reasoning_content,
                        "accumulated": accumulated_reasoning_content,
                    }

                if content:
                    accumulated_content += content
                    yield {
                        "type": "token",
                        "content": content,
                        "accumulated": accumulated_content,
                    }

                for tool_call in _collect_ready_tool_calls(delta):
                    collected_tool_calls.append(tool_call)
                    yield {"type": "tool_call", "tool_call": tool_call}

                if finish_reason:
                    for tool_call in _collect_ready_tool_calls(delta, force_flush=True):
                        collected_tool_calls.append(tool_call)
                        yield {"type": "tool_call", "tool_call": tool_call}
                    if not final_usage:
                        output_tokens_estimate = estimate_tokens(accumulated_content, self.config.model)
                        final_usage = {
                            "prompt_tokens": input_tokens_estimate,
                            "completion_tokens": output_tokens_estimate,
                            "total_tokens": input_tokens_estimate + output_tokens_estimate,
                        }
                    if not accumulated_content and not partial_tool_calls:
                        logger.warning(
                            f"Stream completed with no content after {chunk_count} chunks, finish_reason={finish_reason}"
                        )
                    yield {
                        "type": "done",
                        "content": accumulated_content,
                        "reasoning_content": accumulated_reasoning_content,
                        "usage": final_usage,
                        "finish_reason": finish_reason,
                        "tool_calls": list(collected_tool_calls),
                    }
                    break
            else:
                if accumulated_content or partial_tool_calls:
                    for tool_call in _collect_ready_tool_calls({}, force_flush=True):
                        collected_tool_calls.append(tool_call)
                        yield {"type": "tool_call", "tool_call": tool_call}
                    if not final_usage:
                        output_tokens_estimate = estimate_tokens(accumulated_content, self.config.model)
                        final_usage = {
                            "prompt_tokens": input_tokens_estimate,
                            "completion_tokens": output_tokens_estimate,
                            "total_tokens": input_tokens_estimate + output_tokens_estimate,
                        }
                    yield {
                        "type": "done",
                        "content": accumulated_content,
                        "reasoning_content": accumulated_reasoning_content,
                        "usage": final_usage,
                        "finish_reason": "complete",
                        "tool_calls": list(collected_tool_calls),
                    }

        except litellm.exceptions.RateLimitError as e:
            logger.error(f"Stream rate limit error: {e}")
            error_msg = str(e)
            if any(keyword in error_msg.lower() for keyword in ["quota", "insufficient", "balance", "billing"]):
                error_type = "quota_exceeded"
                user_message = "API quota exceeded or account balance is insufficient."
            else:
                error_type = "rate_limit"
                import re as _re
                retry_match = _re.search(r"retry\s*(?:in|after)\s*(\d+(?:\.\d+)?)\s*s", error_msg, _re.IGNORECASE)
                retry_seconds = float(retry_match.group(1)) if retry_match else 60
                user_message = f"API rate limit reached. Retry after about {int(retry_seconds)} seconds."

            output_tokens_estimate = estimate_tokens(accumulated_content, self.config.model) if accumulated_content else 0
            yield {
                "type": "error",
                "error_type": error_type,
                "error": error_msg,
                "user_message": user_message,
                "accumulated": accumulated_content,
                "usage": {
                    "prompt_tokens": input_tokens_estimate,
                    "completion_tokens": output_tokens_estimate,
                    "total_tokens": input_tokens_estimate + output_tokens_estimate,
                } if accumulated_content else None,
            }

        except litellm.exceptions.AuthenticationError as e:
            logger.error(f"Stream authentication error: {e}")
            yield {
                "type": "error",
                "error_type": "authentication",
                "error": str(e),
                "user_message": "API Key ???????????????????",
                "accumulated": accumulated_content,
                "usage": None,
            }

        except litellm.exceptions.APIConnectionError as e:
            logger.error(f"Stream connection error: {e}")
            yield {
                "type": "error",
                "error_type": "connection",
                "error": str(e),
                "user_message": "????????API ????????????????",
                "accumulated": accumulated_content,
                "usage": None,
            }

        except Exception as e:
            error_msg = str(e).strip() or repr(e)
            logger.exception("Stream error: %r", e)
            is_rate_limit = any(keyword in error_msg.lower() for keyword in [
                "ratelimiterror", "rate limit", "429", "resource_exhausted",
                "quota exceeded", "too many requests"
            ])

            if is_rate_limit:
                import re as _re
                if any(keyword in error_msg.lower() for keyword in ["quota", "exceeded", "billing"]):
                    error_type = "quota_exceeded"
                    user_message = "API quota exceeded or account balance is insufficient."
                else:
                    error_type = "rate_limit"
                    retry_match = _re.search(r"retry\s*(?:in|after)\s*(\d+(?:\.\d+)?)\s*s", error_msg, _re.IGNORECASE)
                    retry_seconds = float(retry_match.group(1)) if retry_match else 60
                    user_message = f"API rate limit reached. Retry after about {int(retry_seconds)} seconds."
            else:
                error_type = "unknown"
                user_message = "LLM streaming request failed. Please retry."

            output_tokens_estimate = estimate_tokens(accumulated_content, self.config.model) if accumulated_content else 0
            yield {
                "type": "error",
                "error_type": error_type,
                "error": error_msg,
                "error_class": e.__class__.__name__,
                "user_message": user_message,
                "accumulated": accumulated_content,
                "usage": {
                    "prompt_tokens": input_tokens_estimate,
                    "completion_tokens": output_tokens_estimate,
                    "total_tokens": input_tokens_estimate + output_tokens_estimate,
                } if accumulated_content else None,
            }

    async def validate_config(self) -> bool:
        """验证配置"""
        # Ollama 不需要 API Key
        if self.config.provider == LLMProvider.OLLAMA:
            if not self.config.model:
                raise LLMError("未指定 Ollama 模型", LLMProvider.OLLAMA)
            return True

        # 其他提供商需要 API Key
        if not self.config.api_key:
            raise LLMError(
                f"API Key未配置 ({self.config.provider.value})",
                self.config.provider,
            )

        # check for placeholder keys
        if "sk-your-" in self.config.api_key or "***" in self.config.api_key:
             raise LLMError(
                f"无效的 API Key (使用了占位符): {self.config.api_key[:10]}...",
                self.config.provider,
                401
            )

        if not self.config.model:
            raise LLMError(
                f"未指定模型 ({self.config.provider.value})",
                self.config.provider,
            )

        return True

    @classmethod
    def supports_provider(cls, provider: LLMProvider) -> bool:
        """检查是否支持指定的提供商"""
        return provider in cls.PROVIDER_PREFIX_MAP
