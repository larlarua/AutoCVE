from __future__ import annotations

from app.services.finding_runtime.compaction.prompts import (
    BASE_COMPACT_PROMPT,
    NO_TOOLS_PREAMBLE,
    NO_TOOLS_TRAILER,
    PARTIAL_COMPACT_PROMPT,
    PARTIAL_COMPACT_UP_TO_PROMPT,
    build_compaction_prompt,
)


def test_compaction_prompt_constants_include_restored_no_tools_contract():
    assert "禁止调用任何工具" in NO_TOOLS_PREAMBLE
    assert "<analysis>" in NO_TOOLS_PREAMBLE
    assert "<summary>" in NO_TOOLS_PREAMBLE
    assert "不要调用任何工具" in NO_TOOLS_TRAILER


def test_compaction_prompt_variants_match_restored_scopes():
    assert "目前为止的对话" in BASE_COMPACT_PROMPT
    assert "对话的最近部分" in PARTIAL_COMPACT_PROMPT
    assert "放在后续会话的开头" in PARTIAL_COMPACT_UP_TO_PROMPT


def test_build_compaction_prompt_wraps_prompt_with_no_tools_markers_and_custom_instructions():
    prompt = build_compaction_prompt(
        mode="partial",
        custom_instructions="Focus on code changes and test output.",
    )

    assert prompt.startswith(NO_TOOLS_PREAMBLE)
    assert "对话的最近部分" in prompt
    assert "Focus on code changes and test output." in prompt
    assert prompt.endswith(NO_TOOLS_TRAILER)
