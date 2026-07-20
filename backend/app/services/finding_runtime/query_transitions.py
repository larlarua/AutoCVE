from __future__ import annotations

from copy import deepcopy
from typing import Any

from app.services.finding_runtime.models import RuntimeContinueReason, TranscriptItem
from app.services.finding_runtime.query_state import QueryLoopState

PERSISTED_MESSAGE_ID_KEY = "persisted_session_message_id"
PERSISTED_MESSAGE_SEQUENCE_KEY = "persisted_session_message_sequence"
PERSISTED_SYNC_SEQUENCE_KEY = "persisted_session_sync_sequence"
_COMPACTION_MESSAGE_NAMES = {
    "auto_compact_boundary",
    "auto_compact_summary",
    "reactive_compact_boundary",
    "reactive_compact_summary",
    "microcompact_boundary",
    "microcompact_summary",
}
_EPHEMERAL_RUNTIME_MESSAGE_NAMES = {"runtime_user_context"}


def strip_ephemeral_runtime_messages(messages: list[TranscriptItem]) -> list[TranscriptItem]:
    """Do not persist per-turn prompt injections into the durable transcript."""
    return [
        item
        for item in messages
        if item.name not in _EPHEMERAL_RUNTIME_MESSAGE_NAMES
        and str(item.metadata.get("kind") or "") != "user_context"
    ]


def refresh_query_loop_state_from_persisted_messages(
    state: QueryLoopState,
    *,
    persisted_messages: list[TranscriptItem],
) -> QueryLoopState:
    """Refresh from DB without replacing a durable compacted transcript.

    Once a compact boundary exists, the query-loop state is the source of truth:
    the database retains the full audit log for display, while the compact state
    retains the model-ready summary.  Only externally appended user messages
    newer than the last refresh are merged into that compact state.
    """
    clean_state_messages = strip_ephemeral_runtime_messages(state.messages)
    clean_persisted_messages = strip_ephemeral_runtime_messages(persisted_messages)
    tool_use_context = deepcopy(state.tool_use_context)
    latest_sequence = max(
        (
            int(item.metadata.get(PERSISTED_MESSAGE_SEQUENCE_KEY) or 0)
            for item in clean_persisted_messages
        ),
        default=0,
    )

    if not _contains_compaction_state(state, clean_state_messages):
        refreshed = hydrate_query_loop_state(state, messages=clean_persisted_messages)
        refreshed.tool_use_context[PERSISTED_SYNC_SEQUENCE_KEY] = latest_sequence
        return refreshed

    synced_sequence = int(tool_use_context.get(PERSISTED_SYNC_SEQUENCE_KEY) or 0)
    known_ids = {
        str(item.metadata.get(PERSISTED_MESSAGE_ID_KEY) or "")
        for item in clean_state_messages
        if str(item.metadata.get(PERSISTED_MESSAGE_ID_KEY) or "")
    }
    new_user_messages = [
        item
        for item in clean_persisted_messages
        if item.role.value == "user"
        and int(item.metadata.get(PERSISTED_MESSAGE_SEQUENCE_KEY) or 0) > synced_sequence
        and str(item.metadata.get(PERSISTED_MESSAGE_ID_KEY) or "") not in known_ids
    ]
    refreshed = hydrate_query_loop_state(
        state,
        messages=[*clean_state_messages, *new_user_messages],
    )
    refreshed.tool_use_context[PERSISTED_SYNC_SEQUENCE_KEY] = latest_sequence
    return refreshed


def restore_compacted_query_loop_state_from_checkpoints(
    state: QueryLoopState,
    *,
    checkpoints: list[Any],
) -> QueryLoopState:
    """Recover a compacted transcript if an older refresh already overwrote it."""
    clean_messages = strip_ephemeral_runtime_messages(state.messages)
    if _contains_compaction_state(state, clean_messages):
        return state
    if not bool((state.auto_compact_tracking or {}).get("compacted")):
        return state
    for checkpoint in reversed(checkpoints):
        payload = dict(getattr(checkpoint, "state_payload", {}) or {})
        if payload.get("checkpoint_kind") != "context_compaction":
            continue
        compacted_payload = payload.get("compacted_query_loop_state")
        if not isinstance(compacted_payload, dict):
            continue
        restored = QueryLoopState.from_payload(compacted_payload)
        if _contains_compaction_state(restored, restored.messages):
            return restored
    return state


def _contains_compaction_state(state: QueryLoopState, messages: list[TranscriptItem]) -> bool:
    if not bool((state.auto_compact_tracking or {}).get("compacted")):
        return False
    return any(
        item.name in _COMPACTION_MESSAGE_NAMES
        or str(item.metadata.get("kind") or "") in {"compact_boundary", "auto_compact_summary", "reactive_compact_summary"}
        for item in messages
    )


def hydrate_query_loop_state(state: QueryLoopState, *, messages: list[TranscriptItem]) -> QueryLoopState:
    return QueryLoopState(
        messages=strip_ephemeral_runtime_messages(messages),
        tool_use_context=deepcopy(state.tool_use_context),
        auto_compact_tracking=deepcopy(state.auto_compact_tracking),
        context_collapse_state=deepcopy(state.context_collapse_state),
        max_output_tokens_recovery_count=state.max_output_tokens_recovery_count,
        has_attempted_reactive_compact=state.has_attempted_reactive_compact,
        max_output_tokens_override=state.max_output_tokens_override,
        pending_tool_use_summary=deepcopy(state.pending_tool_use_summary),
        stop_hook_active=state.stop_hook_active,
        turn_count=max(1, state.turn_count),
        transition=state.transition,
    )


def build_continue_state(
    state: QueryLoopState,
    *,
    messages: list[TranscriptItem],
    transition: RuntimeContinueReason,
) -> QueryLoopState:
    return QueryLoopState(
        messages=strip_ephemeral_runtime_messages(messages),
        tool_use_context=deepcopy(state.tool_use_context),
        auto_compact_tracking=deepcopy(state.auto_compact_tracking),
        context_collapse_state=deepcopy(state.context_collapse_state),
        max_output_tokens_recovery_count=state.max_output_tokens_recovery_count,
        has_attempted_reactive_compact=state.has_attempted_reactive_compact,
        max_output_tokens_override=state.max_output_tokens_override,
        pending_tool_use_summary=deepcopy(state.pending_tool_use_summary),
        stop_hook_active=state.stop_hook_active,
        turn_count=max(1, state.turn_count) + 1,
        transition=transition,
    )


def build_terminal_state(state: QueryLoopState, *, messages: list[TranscriptItem]) -> QueryLoopState:
    return QueryLoopState(
        messages=strip_ephemeral_runtime_messages(messages),
        tool_use_context=deepcopy(state.tool_use_context),
        auto_compact_tracking=deepcopy(state.auto_compact_tracking),
        context_collapse_state=deepcopy(state.context_collapse_state),
        max_output_tokens_recovery_count=state.max_output_tokens_recovery_count,
        has_attempted_reactive_compact=state.has_attempted_reactive_compact,
        max_output_tokens_override=state.max_output_tokens_override,
        pending_tool_use_summary=deepcopy(state.pending_tool_use_summary),
        stop_hook_active=state.stop_hook_active,
        turn_count=max(1, state.turn_count),
        transition=None,
    )
