from __future__ import annotations

import asyncio
import inspect
from dataclasses import dataclass
from typing import Any, Callable

from app.services.finding_runtime.compaction.compact import compact_conversation
from app.services.finding_runtime.compaction.models import AutoCompactTrackingState
from app.services.finding_runtime.compaction.token_budget import (
    AUTO_COMPACT_THRESHOLD_PERCENT,
    estimate_request_token_budget,
    resolve_context_window_tokens,
)
from app.services.finding_runtime.models import TranscriptItem
from app.services.finding_runtime.query_state import QueryLoopState

MAX_OUTPUT_TOKENS_FOR_SUMMARY = 20_000
AUTOCOMPACT_BUFFER_TOKENS = 13_000
WARNING_THRESHOLD_BUFFER_TOKENS = 20_000
ERROR_THRESHOLD_BUFFER_TOKENS = 20_000
MANUAL_COMPACT_BUFFER_TOKENS = 3_000
MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES = 3
BLOCKING_LIMIT_PERCENT = 97


@dataclass(slots=True)
class AutoCompactDecision:
    was_compacted: bool
    compaction_result: Any | None = None
    consecutive_failures: int | None = None


def get_effective_context_window_size(*, model: str, context_window: int, max_output_tokens: int) -> int:
    del model, max_output_tokens
    resolved, _source = resolve_context_window_tokens({"context_window": context_window})
    return resolved


def get_auto_compact_threshold(*, model: str, context_window: int, max_output_tokens: int) -> int:
    del model, max_output_tokens
    resolved, _source = resolve_context_window_tokens({"context_window": context_window})
    return (resolved * AUTO_COMPACT_THRESHOLD_PERCENT) // 100


def calculate_token_warning_state(*, token_usage: int, model: str, context_window: int, max_output_tokens: int) -> dict[str, Any]:
    auto_compact_threshold = get_auto_compact_threshold(
        model=model,
        context_window=context_window,
        max_output_tokens=max_output_tokens,
    )
    effective_window = get_effective_context_window_size(
        model=model,
        context_window=context_window,
        max_output_tokens=max_output_tokens,
    )
    threshold = auto_compact_threshold
    percent_left = max(0, round(((threshold - token_usage) / threshold) * 100)) if threshold > 0 else 0
    warning_threshold = threshold - WARNING_THRESHOLD_BUFFER_TOKENS
    error_threshold = threshold - ERROR_THRESHOLD_BUFFER_TOKENS
    # Keep a proportional hard stop so explicitly configured small test/model
    # windows remain valid.  The 90% auto-compact threshold leaves the normal
    # recovery headroom; this is only the final guard when compaction cannot
    # make enough room.
    blocking_limit = max(1, (effective_window * BLOCKING_LIMIT_PERCENT) // 100)
    return {
        "percent_left": percent_left,
        "is_above_warning_threshold": token_usage >= warning_threshold,
        "is_above_error_threshold": token_usage >= error_threshold,
        "is_above_auto_compact_threshold": token_usage >= auto_compact_threshold,
        "is_at_blocking_limit": token_usage >= blocking_limit,
        "blocking_limit": blocking_limit,
    }


def auto_compact_if_needed(
    messages: list[TranscriptItem],
    state: QueryLoopState,
    *,
    tracking: AutoCompactTrackingState | None,
    compactor: Callable[..., Any] | None = None,
    model: str = "claude-sonnet-4-5",
    system_prompt: str | None = None,
    tool_definitions: list[dict[str, Any]] | None = None,
    on_compaction_start: Callable[[dict[str, Any]], Any] | None = None,
    on_compaction_error: Callable[[dict[str, Any]], Any] | None = None,
) -> AutoCompactDecision:
    if tracking is not None and (tracking.consecutive_failures or 0) >= MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES:
        return AutoCompactDecision(
            was_compacted=False,
            consecutive_failures=tracking.consecutive_failures,
        )

    pipeline = dict(state.tool_use_context.get("query_context_pipeline") or {})
    controller = dict(
        pipeline.get("autocompact_controller")
        or state.tool_use_context.get("autocompact_controller")
        or {}
    )
    budget = estimate_request_token_budget(
        model=model,
        system_prompt=system_prompt,
        transcript=messages,
        tool_definitions=tool_definitions,
        controller=controller,
    )
    token_usage = budget.input_tokens
    threshold = budget.auto_compact_threshold_tokens
    if token_usage < threshold:
        return AutoCompactDecision(
            was_compacted=False,
            consecutive_failures=(tracking.consecutive_failures if tracking is not None else None),
        )

    chosen_compactor = compactor or compact_conversation

    async def _run_async() -> AutoCompactDecision:
        event_payload = {
            "token_usage": token_usage,
            "threshold_tokens": threshold,
            "context_window_tokens": budget.context_window_tokens,
            "token_budget_source": budget.source,
        }
        await _notify_lifecycle_callback(on_compaction_start, event_payload)
        try:
            result = chosen_compactor(
                messages,
                state,
                tracking=tracking,
                model=model,
                token_usage=token_usage,
                auto_compact_threshold=threshold,
                context_window_tokens=budget.context_window_tokens,
                token_budget_source=budget.source,
            )
            if inspect.isawaitable(result):
                result = await result
        except Exception as exc:
            await _notify_lifecycle_callback(
                on_compaction_error,
                {
                    **event_payload,
                    "error_type": exc.__class__.__name__,
                    "error": str(exc).strip() or repr(exc),
                },
            )
            previous = tracking.consecutive_failures if tracking is not None and tracking.consecutive_failures is not None else 0
            return AutoCompactDecision(
                was_compacted=False,
                consecutive_failures=previous + 1,
            )

        return AutoCompactDecision(
            was_compacted=True,
            compaction_result=result,
            consecutive_failures=0,
        )

    coroutine = _run_async()
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coroutine)
    return coroutine


async def _notify_lifecycle_callback(callback: Callable[[dict[str, Any]], Any] | None, payload: dict[str, Any]) -> None:
    """Lifecycle telemetry must never make compaction fail or change its result."""
    if callback is None:
        return
    try:
        result = callback(payload)
        if inspect.isawaitable(result):
            await result
    except Exception:
        # UI/log delivery is best-effort. The compactor is the source of truth.
        return
