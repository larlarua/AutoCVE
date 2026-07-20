from __future__ import annotations

from app.services.finding_runtime.models import RuntimeMessageRole, TranscriptItem
import app.services.finding_runtime.query_context as query_context
from app.services.finding_runtime.query_context import (
    apply_context_collapse_if_needed,
    apply_history_snip,
    apply_microcompact,
    apply_tool_result_budget,
    evaluate_blocking_limit,
    get_messages_after_compact_boundary,
)
from app.services.finding_runtime.query_state import QueryLoopState


def test_get_messages_after_compact_boundary_returns_tail_after_last_boundary():
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="old-1"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="old-2"),
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="boundary",
            name="auto_compact_boundary",
            metadata={"kind": "compact_boundary"},
        ),
        TranscriptItem(role=RuntimeMessageRole.USER, content="recent-1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="recent-2"),
    ]

    result = get_messages_after_compact_boundary(messages, QueryLoopState())

    assert [item.content for item in result] == ["recent-1", "recent-2"]


def test_get_messages_after_compact_boundary_keeps_compact_summary_for_next_model_turn():
    messages = [
        TranscriptItem(role=RuntimeMessageRole.SYSTEM, content="boundary", name="auto_compact_boundary", metadata={"kind": "compact_boundary"}),
        TranscriptItem(role=RuntimeMessageRole.USER, content="durable summary", name="auto_compact_summary", metadata={"kind": "auto_compact_summary"}),
        TranscriptItem(role=RuntimeMessageRole.USER, content="latest follow-up"),
    ]

    result = get_messages_after_compact_boundary(messages, QueryLoopState())

    assert [item.content for item in result] == ["durable summary", "latest follow-up"]


def test_apply_tool_result_budget_truncates_old_tool_results_when_over_budget():
    state = QueryLoopState(
        tool_use_context={
            "tool_result_budget": {"max_total_chars": 35, "trim_to_chars": 10},
        }
    )
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"),
        TranscriptItem(role=RuntimeMessageRole.TOOL_RESULT, content="A" * 20, name="read_file"),
        TranscriptItem(role=RuntimeMessageRole.TOOL_RESULT, content="B" * 20, name="grep"),
    ]

    result = apply_tool_result_budget(messages, state)

    assert result[1].content.endswith("...[truncated]")
    assert result[1].metadata["content_replaced"] is True
    assert result[2].content == "B" * 20


def test_apply_history_snip_keeps_recent_messages_and_inserts_marker():
    state = QueryLoopState(tool_use_context={"history_snip": {"keep_last_messages": 2}})
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="m1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="m2"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="m3"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="m4"),
    ]

    result = apply_history_snip(messages, state)

    assert result[0].name == "history_snip_boundary"
    assert result[1].content == "m3"
    assert result[2].content == "m4"


def test_apply_microcompact_truncates_large_tool_result_payloads():
    state = QueryLoopState(tool_use_context={"microcompact": {"tool_result_max_chars": 8}})
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"),
        TranscriptItem(role=RuntimeMessageRole.TOOL_RESULT, content="1234567890abcdef", name="grep"),
    ]

    result = apply_microcompact(messages, state)

    assert result[1].content == "12345678...[microcompact]"
    assert result[1].metadata["microcompacted"] is True




def test_query_context_no_longer_exports_legacy_inline_compaction_helpers():
    assert not hasattr(query_context, "project_context_collapse")
    assert not hasattr(query_context, "run_proactive_autocompact")
    assert not hasattr(query_context, "run_reactive_compact")

def test_apply_context_collapse_if_needed_stages_and_projects_summary_view():
    state = QueryLoopState(
        tool_use_context={
            "context_collapse": {"max_chars": 30, "preserve_tail_messages": 1},
        }
    )
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 20),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="B" * 20),
        TranscriptItem(role=RuntimeMessageRole.USER, content="tail"),
    ]

    projected_messages, next_state = apply_context_collapse_if_needed(messages, state)

    assert projected_messages[0].name == "context_collapse_summary"
    assert projected_messages[-1].content == "tail"
    assert next_state.auto_compact_tracking["pending_collapse"] is True
    assert len(next_state.context_collapse_state["snapshot"]["staged"]) == 1
    assert next_state.context_collapse_state["commits"] == []


def test_apply_context_collapse_if_needed_replays_persisted_commit_view():
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="m1", metadata={"collapse_uuid": "u1"}),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="m2", metadata={"collapse_uuid": "u2"}),
        TranscriptItem(role=RuntimeMessageRole.USER, content="tail", metadata={"collapse_uuid": "u3"}),
    ]
    state = QueryLoopState(
        tool_use_context={"context_collapse": {"max_chars": 999, "preserve_tail_messages": 1}},
        context_collapse_state={
            "commits": [
                {
                    "collapse_id": "0000000000000001",
                    "summary_uuid": "summary-1",
                    "summary_content": "Collapsed earlier context.",
                    "summary": "Collapsed earlier context.",
                    "first_archived_uuid": "u1",
                    "last_archived_uuid": "u2",
                }
            ],
            "snapshot": {"staged": [], "armed": False, "last_spawn_tokens": 0},
        },
    )

    projected_messages, next_state = apply_context_collapse_if_needed(messages, state)

    assert projected_messages[0].name == "context_collapse_summary"
    assert projected_messages[0].metadata["collapse_id"] == "0000000000000001"
    assert projected_messages[-1].content == "tail"
    assert next_state.context_collapse_state["commits"][0]["summary_uuid"] == "summary-1"


def test_evaluate_blocking_limit_uses_restored_style_controller_when_present():
    state = QueryLoopState(
        tool_use_context={
            "autocompact_controller": {"context_window": 1000, "max_output_tokens": 40}
        }
    )
    messages = [TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 8000)]

    result = evaluate_blocking_limit(messages, state)

    assert result["blocked"] is True
    assert result["blocking_limit"] == 970
    assert result["token_usage"] >= 970



