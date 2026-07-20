from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from app.services.finding_runtime.models import TranscriptItem
from app.services.llm.tokenizer import TokenEstimator


DEFAULT_CONTEXT_WINDOW_TOKENS = 272_000
AUTO_COMPACT_THRESHOLD_PERCENT = 90
_MESSAGE_OVERHEAD_TOKENS = 4
_REQUEST_OVERHEAD_TOKENS = 3


@dataclass(frozen=True, slots=True)
class ContextTokenBudget:
    input_tokens: int
    context_window_tokens: int
    auto_compact_threshold_tokens: int
    source: str


def resolve_context_window_tokens(controller: dict[str, Any] | None = None) -> tuple[int, str]:
    configured = int(dict(controller or {}).get("context_window") or 0)
    if configured > 0:
        return configured, "configured"
    return DEFAULT_CONTEXT_WINDOW_TOKENS, "default_272000"


def get_auto_compact_threshold_tokens(context_window_tokens: int) -> int:
    return max(1, (max(0, context_window_tokens) * AUTO_COMPACT_THRESHOLD_PERCENT) // 100)


def estimate_transcript_tokens(*, transcript: list[TranscriptItem], model: str) -> int:
    total = _REQUEST_OVERHEAD_TOKENS
    for item in transcript:
        total += _MESSAGE_OVERHEAD_TOKENS
        total += TokenEstimator.count_tokens(item.content or "", model)
        if item.name:
            total += TokenEstimator.count_tokens(item.name, model)
    return total


def estimate_request_token_budget(
    *,
    model: str,
    system_prompt: str | None,
    transcript: list[TranscriptItem],
    tool_definitions: list[dict[str, Any]] | None,
    controller: dict[str, Any] | None = None,
) -> ContextTokenBudget:
    """Estimate the actual model input, including prompt and tool schema overhead.

    The provider's post-request usage remains authoritative, but it cannot be
    used to decide whether the *next* request needs compaction. This estimator
    deliberately uses the same model-aware tokenizer as the LLM subsystem.
    """
    context_window_tokens, source = resolve_context_window_tokens(controller)
    input_tokens = estimate_transcript_tokens(transcript=transcript, model=model)
    if system_prompt:
        input_tokens += _MESSAGE_OVERHEAD_TOKENS + TokenEstimator.count_tokens(system_prompt, model)
    if tool_definitions:
        serialized_tools = json.dumps(tool_definitions, ensure_ascii=False, separators=(",", ":"), default=str)
        input_tokens += TokenEstimator.count_tokens(serialized_tools, model)
    return ContextTokenBudget(
        input_tokens=input_tokens,
        context_window_tokens=context_window_tokens,
        auto_compact_threshold_tokens=get_auto_compact_threshold_tokens(context_window_tokens),
        source=source,
    )
