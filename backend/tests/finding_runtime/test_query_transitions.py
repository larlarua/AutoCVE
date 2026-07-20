from __future__ import annotations

import json
from pathlib import Path

from app.services.finding_runtime.models import RuntimeContinueReason, RuntimeMessageRole, RuntimeStopReason, TranscriptItem
from app.services.finding_runtime.query_state import QueryLoopState
from app.services.finding_runtime.query_transitions import (
    PERSISTED_MESSAGE_ID_KEY,
    PERSISTED_MESSAGE_SEQUENCE_KEY,
    PERSISTED_SYNC_SEQUENCE_KEY,
    build_continue_state,
    refresh_query_loop_state_from_persisted_messages,
    restore_compacted_query_loop_state_from_checkpoints,
)

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "query_parity" / "reason_matrix.json"
REASON_MATRIX = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


def test_restored_inspired_continue_reason_matrix_matches_runtime_enum():
    assert [reason.value for reason in RuntimeContinueReason] == REASON_MATRIX["continue_reasons"]


def test_restored_inspired_terminal_reason_matrix_matches_runtime_enum():
    assert [reason.value for reason in RuntimeStopReason] == REASON_MATRIX["terminal_reasons"]


def test_refresh_preserves_compacted_transcript_and_only_merges_new_user_messages():
    state = QueryLoopState(
        messages=[
            TranscriptItem(role=RuntimeMessageRole.SYSTEM, content="boundary", name="auto_compact_boundary", metadata={"kind": "compact_boundary"}),
            TranscriptItem(role=RuntimeMessageRole.USER, content="durable summary", name="auto_compact_summary", metadata={"kind": "auto_compact_summary"}),
            TranscriptItem(role=RuntimeMessageRole.USER, content="ephemeral context", name="runtime_user_context", metadata={"kind": "user_context"}),
        ],
        tool_use_context={PERSISTED_SYNC_SEQUENCE_KEY: 10},
        auto_compact_tracking={"compacted": True},
    )
    persisted_messages = [
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="old user message",
            metadata={PERSISTED_MESSAGE_ID_KEY: "m-10", PERSISTED_MESSAGE_SEQUENCE_KEY: 10},
        ),
        TranscriptItem(
            role=RuntimeMessageRole.USER,
            content="new follow-up",
            metadata={PERSISTED_MESSAGE_ID_KEY: "m-11", PERSISTED_MESSAGE_SEQUENCE_KEY: 11},
        ),
        TranscriptItem(
            role=RuntimeMessageRole.ASSISTANT,
            content="already represented by query state",
            metadata={PERSISTED_MESSAGE_ID_KEY: "m-12", PERSISTED_MESSAGE_SEQUENCE_KEY: 12},
        ),
    ]

    refreshed = refresh_query_loop_state_from_persisted_messages(state, persisted_messages=persisted_messages)

    assert [item.name for item in refreshed.messages[:2]] == ["auto_compact_boundary", "auto_compact_summary"]
    assert [item.content for item in refreshed.messages] == ["boundary", "durable summary", "new follow-up"]
    assert refreshed.tool_use_context[PERSISTED_SYNC_SEQUENCE_KEY] == 12


def test_continue_state_does_not_persist_runtime_user_context():
    state = QueryLoopState()

    next_state = build_continue_state(
        state,
        messages=[
            TranscriptItem(role=RuntimeMessageRole.USER, content="runtime context", name="runtime_user_context", metadata={"kind": "user_context"}),
            TranscriptItem(role=RuntimeMessageRole.USER, content="real user message"),
        ],
        transition=RuntimeContinueReason.NEXT_TURN,
    )

    assert [item.content for item in next_state.messages] == ["real user message"]


def test_refresh_restores_compacted_state_from_checkpoint_after_legacy_overwrite():
    compacted_state = QueryLoopState(
        messages=[
            TranscriptItem(role=RuntimeMessageRole.SYSTEM, content="boundary", name="auto_compact_boundary", metadata={"kind": "compact_boundary"}),
            TranscriptItem(role=RuntimeMessageRole.USER, content="durable summary", name="auto_compact_summary", metadata={"kind": "auto_compact_summary"}),
        ],
        auto_compact_tracking={"compacted": True},
    )
    overwritten_state = QueryLoopState(
        messages=[TranscriptItem(role=RuntimeMessageRole.USER, content="raw history")],
        auto_compact_tracking={"compacted": True},
    )
    checkpoint = type(
        "Checkpoint",
        (),
        {
            "state_payload": {
                "checkpoint_kind": "context_compaction",
                "compacted_query_loop_state": compacted_state.to_payload(),
            },
        },
    )()

    restored = restore_compacted_query_loop_state_from_checkpoints(
        overwritten_state,
        checkpoints=[checkpoint],
    )

    assert [item.name for item in restored.messages] == ["auto_compact_boundary", "auto_compact_summary"]
