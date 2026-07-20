from __future__ import annotations

from app.services.finding_runtime.compaction.auto_compact import (
    AUTO_COMPACT_THRESHOLD_PERCENT,
    MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES,
    MAX_OUTPUT_TOKENS_FOR_SUMMARY,
    auto_compact_if_needed,
    calculate_token_warning_state,
    get_auto_compact_threshold,
    get_effective_context_window_size,
)
from app.services.finding_runtime.compaction.models import AutoCompactTrackingState
from app.services.finding_runtime.compaction.token_budget import DEFAULT_CONTEXT_WINDOW_TOKENS
from app.services.finding_runtime.models import RuntimeMessageRole, TranscriptItem
from app.services.finding_runtime.query_state import QueryLoopState


class _DummyCompactor:
    def __init__(self, *, should_compact: bool = True, result=None, error: Exception | None = None):
        self.should_compact = should_compact
        self.result = result
        self.error = error
        self.calls = 0

    def __call__(self, messages, state, *, tracking, model, token_usage, auto_compact_threshold, **kwargs):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.result


def test_get_effective_context_window_size_uses_configured_input_window():
    window = get_effective_context_window_size(model="claude-sonnet-4-5", context_window=200_000, max_output_tokens=64_000)

    assert window == 200_000
    assert MAX_OUTPUT_TOKENS_FOR_SUMMARY == 20_000


def test_get_auto_compact_threshold_uses_codex_ninety_percent():
    threshold = get_auto_compact_threshold(model="claude-sonnet-4-5", context_window=200_000, max_output_tokens=64_000)

    assert threshold == 180_000
    assert AUTO_COMPACT_THRESHOLD_PERCENT == 90


def test_calculate_token_warning_state_uses_ninety_percent_threshold_and_blocking_limit():
    state = calculate_token_warning_state(token_usage=197_000, model="claude-sonnet-4-5", context_window=200_000, max_output_tokens=64_000)

    assert state["is_above_warning_threshold"] is True
    assert state["is_above_error_threshold"] is True
    assert state["is_above_auto_compact_threshold"] is True
    assert state["is_at_blocking_limit"] is True
    assert state["percent_left"] == 0


def test_auto_compact_defaults_to_272k_context_window_when_not_configured():
    assert get_effective_context_window_size(model="unknown", context_window=0, max_output_tokens=0) == DEFAULT_CONTEXT_WINDOW_TOKENS
    assert get_auto_compact_threshold(model="unknown", context_window=0, max_output_tokens=0) == 244_800


def test_auto_compact_if_needed_skips_when_breaker_tripped():
    messages = [TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 500)]
    tracking = AutoCompactTrackingState(compacted=False, turn_counter=3, turn_id="turn-3", consecutive_failures=MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES)
    state = QueryLoopState(tool_use_context={"autocompact_controller": {"context_window": 1_000, "max_output_tokens": 64_000}})
    compactor = _DummyCompactor(result={"summary": "unused"})

    decision = auto_compact_if_needed(messages, state, tracking=tracking, compactor=compactor)

    assert decision.was_compacted is False
    assert decision.consecutive_failures == MAX_CONSECUTIVE_AUTOCOMPACT_FAILURES
    assert compactor.calls == 0


def test_auto_compact_if_needed_resets_failure_counter_on_success():
    messages = [TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 10_000)]
    tracking = AutoCompactTrackingState(compacted=True, turn_counter=7, turn_id="turn-7", consecutive_failures=2)
    state = QueryLoopState(tool_use_context={"autocompact_controller": {"context_window": 1_000, "max_output_tokens": 64_000}})
    compactor = _DummyCompactor(result={"summary": "compacted"})

    decision = auto_compact_if_needed(messages, state, tracking=tracking, compactor=compactor)

    assert decision.was_compacted is True
    assert decision.compaction_result == {"summary": "compacted"}
    assert decision.consecutive_failures == 0
    assert compactor.calls == 1


def test_auto_compact_emits_lifecycle_events_only_after_threshold_is_crossed():
    messages = [TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 10_000)]
    state = QueryLoopState(tool_use_context={"autocompact_controller": {"context_window": 1_000}})
    emitted: list[tuple[str, dict]] = []

    decision = auto_compact_if_needed(
        messages,
        state,
        tracking=None,
        compactor=_DummyCompactor(result={"summary": "compacted"}),
        on_compaction_start=lambda details: emitted.append(("started", details)),
        on_compaction_error=lambda details: emitted.append(("failed", details)),
    )

    assert decision.was_compacted is True
    assert [kind for kind, _details in emitted] == ["started"]
    assert emitted[0][1]["token_usage"] >= emitted[0][1]["threshold_tokens"]


def test_auto_compact_emits_failure_lifecycle_event_when_summary_fails():
    messages = [TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 10_000)]
    state = QueryLoopState(tool_use_context={"autocompact_controller": {"context_window": 1_000}})
    emitted: list[tuple[str, dict]] = []

    decision = auto_compact_if_needed(
        messages,
        state,
        tracking=None,
        compactor=_DummyCompactor(error=RuntimeError("summary provider unavailable")),
        on_compaction_start=lambda details: emitted.append(("started", details)),
        on_compaction_error=lambda details: emitted.append(("failed", details)),
    )

    assert decision.was_compacted is False
    assert [kind for kind, _details in emitted] == ["started", "failed"]
    assert emitted[-1][1]["error"] == "summary provider unavailable"


def test_auto_compact_reads_context_window_from_runtime_query_context_pipeline():
    messages = [TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 10_000)]
    state = QueryLoopState(
        tool_use_context={
            "query_context_pipeline": {
                "autocompact_controller": {"context_window": 1_000},
            },
        },
    )
    compactor = _DummyCompactor(result={"summary": "compacted"})

    decision = auto_compact_if_needed(messages, state, tracking=None, compactor=compactor)

    assert decision.was_compacted is True
    assert compactor.calls == 1


def test_auto_compact_if_needed_increments_failure_counter_on_compactor_error():
    messages = [TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 10_000)]
    tracking = AutoCompactTrackingState(compacted=False, turn_counter=4, turn_id="turn-4", consecutive_failures=1)
    state = QueryLoopState(tool_use_context={"autocompact_controller": {"context_window": 1_000, "max_output_tokens": 64_000}})
    compactor = _DummyCompactor(error=RuntimeError("prompt too long"))

    decision = auto_compact_if_needed(messages, state, tracking=tracking, compactor=compactor)

    assert decision.was_compacted is False
    assert decision.consecutive_failures == 2
    assert compactor.calls == 1
