from __future__ import annotations

from app.services.finding_runtime.compaction.token_budget import (
    DEFAULT_CONTEXT_WINDOW_TOKENS,
    estimate_request_token_budget,
)
from app.services.finding_runtime.models import RuntimeMessageRole, TranscriptItem


def test_request_token_budget_defaults_to_272k_and_uses_ninety_percent_threshold():
    budget = estimate_request_token_budget(
        model="gpt-4",
        system_prompt="Audit code carefully.",
        transcript=[TranscriptItem(role=RuntimeMessageRole.USER, content="Inspect the webhook handler.")],
        tool_definitions=[],
    )

    assert budget.context_window_tokens == DEFAULT_CONTEXT_WINDOW_TOKENS
    assert budget.auto_compact_threshold_tokens == 244_800
    assert budget.source == "default_272000"


def test_request_token_budget_includes_system_prompt_and_tool_schema():
    transcript = [TranscriptItem(role=RuntimeMessageRole.USER, content="Inspect the code.")]
    base = estimate_request_token_budget(
        model="gpt-4",
        system_prompt="",
        transcript=transcript,
        tool_definitions=[],
        controller={"context_window": 4096},
    )
    expanded = estimate_request_token_budget(
        model="gpt-4",
        system_prompt="System audit constraints: preserve evidence and do not invent findings.",
        transcript=transcript,
        tool_definitions=[
            {
                "name": "Read",
                "description": "Read a source file.",
                "parameters": {"type": "object", "properties": {"path": {"type": "string"}}},
            }
        ],
        controller={"context_window": 4096},
    )

    assert expanded.input_tokens > base.input_tokens
    assert expanded.context_window_tokens == 4096
    assert expanded.auto_compact_threshold_tokens == 3686
