from __future__ import annotations

import asyncio

from app.services.finding_runtime.compaction.compact import PTL_RETRY_MARKER, compact_conversation, truncate_head_for_ptl_retry
from app.services.finding_runtime.compaction.models import AutoCompactTrackingState, CompactionResult
from app.services.finding_runtime.compaction.post_compact import build_post_compact_messages
from app.services.finding_runtime.models import RuntimeMessageRole, RuntimeModelResponse, TranscriptItem
from app.services.finding_runtime.query_state import QueryLoopState


def test_build_post_compact_messages_uses_restored_ordering():
    boundary = TranscriptItem(role=RuntimeMessageRole.SYSTEM, content="boundary", name="auto_compact_boundary")
    summary = TranscriptItem(role=RuntimeMessageRole.USER, content="summary", name="auto_compact_summary")
    kept = TranscriptItem(role=RuntimeMessageRole.USER, content="kept tail")
    attachment = TranscriptItem(role=RuntimeMessageRole.SYSTEM, content="attachment", name="post_compact_attachment")
    hook_result = TranscriptItem(role=RuntimeMessageRole.SYSTEM, content="hook", name="post_compact_hook")
    result = CompactionResult(
        boundary_marker=boundary,
        summary_messages=[summary],
        attachments=[attachment],
        hook_results=[hook_result],
        messages_to_keep=[kept],
    )

    messages = build_post_compact_messages(result)

    assert messages == [boundary, summary, kept, attachment, hook_result]


def test_compact_conversation_returns_restored_style_compaction_result_with_preserved_tail():
    state = QueryLoopState(tool_use_context={"autocompact": {"preserve_tail_messages": 1}, "transcript_path": "transcripts/session.md"})
    tracking = AutoCompactTrackingState(compacted=True, turn_counter=4, turn_id="turn-4", consecutive_failures=1)
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="controller routing"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="sink reasoning"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="tail work"),
    ]

    result = asyncio.run(compact_conversation(
        messages,
        state,
        tracking=tracking,
        model="claude-sonnet-4-5",
        token_usage=12345,
        auto_compact_threshold=11000,
    ))

    assert isinstance(result, CompactionResult)
    assert result.boundary_marker.name == "auto_compact_boundary"
    assert result.summary_messages[0].name == "auto_compact_summary"
    assert result.messages_to_keep == [messages[-1]]
    assert result.boundary_marker.metadata["preserved_segment"]["tail_name"] is None
    assert result.summary_messages[0].metadata["is_compact_summary"] is True
    assert result.summary_messages[0].payload["transcript_path"] == "transcripts/session.md"


def test_build_post_compact_messages_uses_compact_conversation_output_order():
    state = QueryLoopState(tool_use_context={"autocompact": {"preserve_tail_messages": 1}})
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="earlier"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="tail"),
    ]

    result = asyncio.run(compact_conversation(
        messages,
        state,
        tracking=None,
        model="claude-sonnet-4-5",
        token_usage=9000,
        auto_compact_threshold=8000,
    ))

    assembled = build_post_compact_messages(result)

    assert [item.name for item in assembled[:2]] == ["auto_compact_boundary", "auto_compact_summary"]
    assert assembled[-1].content == "tail"


class _FakeCompactModelClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    async def complete(self, **kwargs):
        self.calls.append(kwargs)
        return self.responses.pop(0)


def test_compact_conversation_uses_model_driven_summary_request_prompt():
    client = _FakeCompactModelClient([
        {"content": "<analysis>scratch</analysis><summary>Compacted summary</summary>"}
    ])
    state = QueryLoopState(tool_use_context={"autocompact": {"preserve_tail_messages": 1}, "compact_instructions": "Focus on tests."})
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="earlier"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="tail"),
    ]

    result = asyncio.run(
        compact_conversation(
            messages,
            state,
            tracking=None,
            model="claude-sonnet-4-5",
            token_usage=9000,
            auto_compact_threshold=8000,
            model_client=client,
        )
    )

    assert client.calls[0]["system_prompt"] == "你是一个负责总结对话的 AI 助手。请使用简体中文总结。"
    assert client.calls[0]["tool_definitions"] == []
    assert client.calls[0]["transcript"][-1].name == "compact_summary_request"
    assert "禁止调用任何工具" in client.calls[0]["transcript"][-1].content
    assert "Focus on tests." in client.calls[0]["transcript"][-1].content
    assert "Compacted summary" in result.summary_messages[0].content


def test_truncate_head_for_ptl_retry_prepends_retry_marker_when_slice_becomes_assistant_first():
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="u1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="a1"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="u2"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="a2"),
    ]

    truncated = truncate_head_for_ptl_retry(
        messages,
        RuntimeModelResponse(recoverable_error_kind="prompt_too_long", recoverable_error_message="Need 10 more tokens"),
    )

    assert truncated is not None
    assert truncated[0].content == PTL_RETRY_MARKER
    assert truncated[1].role is RuntimeMessageRole.ASSISTANT





def test_partial_compact_conversation_from_preserves_prefix_and_anchors_boundary():
    from app.services.finding_runtime.compaction.compact import partial_compact_conversation

    client = _FakeCompactModelClient([
        {"content": "<summary>Partial from summary</summary>"}
    ])
    state = QueryLoopState(tool_use_context={"compact_instructions": "Keep exploit chain evidence."})
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="prefix-1", name="prefix-1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="prefix-2", name="prefix-2"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="summarize-me", name="pivot-user"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="tail", name="tail-assistant"),
    ]

    result = asyncio.run(
        partial_compact_conversation(
            messages,
            pivot_index=2,
            state=state,
            model="claude-sonnet-4-5",
            model_client=client,
            direction="from",
        )
    )

    assert [item.name for item in result.messages_to_keep] == ["prefix-1", "prefix-2"]
    assert result.boundary_marker.metadata["preserved_segment"]["anchor_name"] == "reactive_compact_boundary"
    assert result.summary_messages[0].metadata["summarize_metadata"]["direction"] == "from"
    prompt_text = client.calls[0]["transcript"][-1].content
    assert "关键要求：只能用文本回复，禁止调用任何工具。" in prompt_text
    assert "不要调用任何工具。只返回纯文本" in prompt_text



def test_partial_compact_conversation_up_to_preserves_suffix_and_anchors_summary():
    from app.services.finding_runtime.compaction.compact import partial_compact_conversation

    client = _FakeCompactModelClient([
        {"content": "<summary>Partial up_to summary</summary>"}
    ])
    state = QueryLoopState(tool_use_context={})
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="old-1", name="old-1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="old-2", name="old-2"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="keep-1", name="keep-1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="keep-2", name="keep-2"),
    ]

    result = asyncio.run(
        partial_compact_conversation(
            messages,
            pivot_index=2,
            state=state,
            model="claude-sonnet-4-5",
            model_client=client,
            direction="up_to",
        )
    )

    assert [item.name for item in result.messages_to_keep] == ["keep-1", "keep-2"]
    assert result.boundary_marker.metadata["preserved_segment"]["anchor_name"] == "reactive_compact_summary"
    assert result.summary_messages[0].metadata["summarize_metadata"]["direction"] == "up_to"
    api_transcript = client.calls[0]["transcript"]
    assert [item.name for item in api_transcript[:-1]] == ["old-1", "old-2"]




def test_compact_conversation_rebuilds_post_compact_attachments_and_hook_results():
    state = QueryLoopState(
        tool_use_context={
            "autocompact": {"preserve_tail_messages": 1},
            "post_compact": {
                "read_files": [
                    {"path": "src/finding.py", "content": "def finding(): pass"},
                ],
                "active_skills": [
                    {"ref": "skills.finding", "title": "Finding skill"},
                ],
                "plan_mode": {"active": True, "steps": ["collect sinks", "trace sources"]},
                "deferred_tools": ["Read", "Bash"],
                "agent_listing": ["finding", "verification"],
                "mcp_servers": ["filesystem", "github"],
                "session_start_hooks": [
                    {"event": "compact", "message": "Session hooks reattached after compact."},
                ],
                "post_compact_hooks": {
                    "user_display_message": "Compaction hooks completed.",
                },
            },
        }
    )
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="earlier"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="tail", name="tail"),
    ]

    result = asyncio.run(
        compact_conversation(
            messages,
            state,
            tracking=None,
            model="claude-sonnet-4-5",
            token_usage=9000,
            auto_compact_threshold=8000,
        )
    )

    assert [item.name for item in result.attachments] == [
        "post_compact_file_attachment",
        "post_compact_skill_attachment",
        "post_compact_plan_attachment",
        "post_compact_tools_attachment",
        "post_compact_agents_attachment",
        "post_compact_mcp_attachment",
    ]
    assert [item.name for item in result.hook_results] == ["post_compact_hook_result"]
    assembled = build_post_compact_messages(result)
    assert [item.name for item in assembled[-2:]] == ["post_compact_mcp_attachment", "post_compact_hook_result"]
    assert result.user_display_message == "Compaction hooks completed."



def test_partial_compact_rebuild_skips_preserved_tail_duplicates():
    from app.services.finding_runtime.compaction.compact import partial_compact_conversation

    state = QueryLoopState(
        tool_use_context={
            "post_compact": {
                "read_files": [
                    {"path": "src/old.py", "content": "old"},
                    {"path": "src/kept.py", "content": "kept"},
                ],
                "deferred_tools": ["Read", "Bash"],
                "session_start_hooks": [
                    {"event": "compact", "message": "restarted"},
                ],
            }
        }
    )
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="old-1", name="old-1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="old-2", name="old-2"),
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="kept file context",
            name="kept-file",
            metadata={"attachment_kind": "file", "path": "src/kept.py"},
        ),
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="kept tools context",
            name="kept-tools",
            metadata={"attachment_kind": "tools_delta", "tools": ["Read", "Bash"]},
        ),
    ]

    result = asyncio.run(
        partial_compact_conversation(
            messages,
            pivot_index=2,
            state=state,
            model="claude-sonnet-4-5",
            direction="up_to",
        )
    )

    assert [item.name for item in result.attachments] == ["post_compact_file_attachment"]
    assert result.attachments[0].metadata["path"] == "src/old.py"
    assert [item.name for item in result.hook_results] == ["post_compact_hook_result"]




def test_post_compact_rebuild_skips_duplicate_skill_agent_mcp_and_tool_context_from_preserved_tail():
    from app.services.finding_runtime.compaction.compact import partial_compact_conversation

    state = QueryLoopState(
        tool_use_context={
            "post_compact": {
                "active_skills": [
                    {"ref": "skills.finding", "title": "Finding skill", "path": "skills/finding.md", "content": "A" * 200},
                ],
                "deferred_tools": ["Read", "Bash"],
                "agent_listing": ["finding", "verification"],
                "mcp_servers": ["filesystem", "github"],
            }
        }
    )
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="old-1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="old-2"),
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="kept skills",
            metadata={"attachment_kind": "invoked_skills", "skills": ["skills.finding"]},
        ),
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="kept tools",
            metadata={"attachment_kind": "tools_delta", "tools": ["Read", "Bash"]},
        ),
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="kept agents",
            metadata={"attachment_kind": "agent_listing", "agents": ["finding", "verification"]},
        ),
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="kept mcp",
            metadata={"attachment_kind": "mcp_instructions", "mcp_servers": ["filesystem", "github"]},
        ),
    ]

    result = asyncio.run(
        partial_compact_conversation(
            messages,
            pivot_index=2,
            state=state,
            model="claude-sonnet-4-5",
            direction="up_to",
        )
    )

    assert result.attachments == []



def test_post_compact_skill_attachment_preserves_content_with_truncation_marker():
    state = QueryLoopState(
        tool_use_context={
            "post_compact": {
                "active_skills": [
                    {
                        "ref": "skills.finding",
                        "title": "Finding skill",
                        "path": "skills/finding.md",
                        "content": "B" * 30000,
                    },
                ],
            }
        }
    )

    result = asyncio.run(
        compact_conversation(
            [TranscriptItem(role=RuntimeMessageRole.USER, content="earlier")],
            state,
            tracking=None,
            model="claude-sonnet-4-5",
            token_usage=9000,
            auto_compact_threshold=8000,
        )
    )

    skill_attachment = next(item for item in result.attachments if item.name == "post_compact_skill_attachment")
    assert skill_attachment.metadata["skills"] == ["skills.finding"]
    assert "skills/finding.md" in skill_attachment.content
    assert "truncated for compaction" in skill_attachment.content




def test_compaction_request_strips_reinjected_attachments_from_summary_input():
    client = _FakeCompactModelClient([
        {"content": "<summary>Compacted summary</summary>"}
    ])
    state = QueryLoopState(tool_use_context={"autocompact": {"preserve_tail_messages": 0}})
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="real work", name="work"),
        TranscriptItem(
            role=RuntimeMessageRole.SYSTEM,
            content="skill listing to be re-injected later",
            name="post_compact_skill_attachment",
            metadata={"kind": "post_compact_skill_attachment"},
        ),
        TranscriptItem(
            role=RuntimeMessageRole.SYSTEM,
            content="tools delta to be re-injected later",
            name="post_compact_tools_attachment",
            metadata={"kind": "post_compact_tools_attachment"},
        ),
    ]

    asyncio.run(
        compact_conversation(
            messages,
            state,
            tracking=None,
            model="claude-sonnet-4-5",
            token_usage=9000,
            auto_compact_threshold=8000,
            model_client=client,
        )
    )

    transcript_names = [item.name for item in client.calls[0]["transcript"][:-1]]
    assert transcript_names == ["work"]

def test_compact_conversation_retries_on_prompt_too_long_before_succeeding():
    client = _FakeCompactModelClient([
        {"content": "", "recoverable_error_kind": "prompt_too_long", "recoverable_error_message": "Need 10 more tokens"},
        {"content": "<summary>Recovered compact summary</summary>"},
    ])
    state = QueryLoopState(tool_use_context={"autocompact": {"preserve_tail_messages": 0}})
    messages = [
        TranscriptItem(role=RuntimeMessageRole.USER, content="u1"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="a1"),
        TranscriptItem(role=RuntimeMessageRole.USER, content="u2"),
        TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="a2"),
    ]

    result = asyncio.run(
        compact_conversation(
            messages,
            state,
            tracking=None,
            model="claude-sonnet-4-5",
            token_usage=9000,
            auto_compact_threshold=8000,
            model_client=client,
        )
    )

    assert len(client.calls) == 2
    assert client.calls[1]["transcript"][0].content == PTL_RETRY_MARKER
    assert "Recovered compact summary" in result.summary_messages[0].content
