from __future__ import annotations

import inspect
import re
from copy import deepcopy
from typing import Any, Iterable, Literal

from app.services.finding_runtime.compaction.models import AutoCompactTrackingState, CompactionResult
from app.services.finding_runtime.compaction.post_compact import rebuild_post_compact_artifacts
from app.services.finding_runtime.compaction.prompts import build_compaction_prompt, get_compact_user_summary_message
from app.services.finding_runtime.models import RuntimeMessageRole, RuntimeModelResponse, TranscriptItem
from app.services.finding_runtime.query_state import QueryLoopState

MAX_PTL_RETRIES = 3
PTL_RETRY_MARKER = "[earlier conversation truncated for compaction retry]"
ERROR_MESSAGE_PROMPT_TOO_LONG = "Conversation too long. Compaction could not recover."
_PARTIAL_DIRECTION = Literal["from", "up_to"]
_COMPACT_BOUNDARY_NAMES = {"auto_compact_boundary", "reactive_compact_boundary", "microcompact_boundary"}
_COMPACT_SUMMARY_NAMES = {"auto_compact_summary", "reactive_compact_summary", "microcompact_summary"}


async def compact_conversation(
    messages: list[TranscriptItem],
    state: QueryLoopState,
    *,
    tracking: AutoCompactTrackingState | None,
    model: str,
    token_usage: int,
    auto_compact_threshold: int,
    model_client=None,
) -> CompactionResult:
    config = dict(state.tool_use_context.get("autocompact") or {})
    preserve_tail_messages = max(0, int(config.get("preserve_tail_messages") or 0))
    custom_instructions = str(state.tool_use_context.get("compact_instructions") or "").strip() or None
    transcript_path = str(state.tool_use_context.get("transcript_path") or "").strip() or None
    messages_to_summarize = list(messages[:-preserve_tail_messages]) if preserve_tail_messages else list(messages)
    messages_to_keep = [deepcopy(item) for item in messages[-preserve_tail_messages:]] if preserve_tail_messages else []
    if not messages_to_summarize:
        messages_to_summarize = list(messages)
        messages_to_keep = []

    summary_input_messages = _strip_reinjected_attachments(messages_to_summarize)
    summary, compaction_usage = await _summarize_messages(
        api_messages=summary_input_messages,
        prompt_mode="base",
        custom_instructions=custom_instructions,
        model=model,
        model_client=model_client,
        fallback_summary=_build_summary_from_messages(messages_to_summarize),
    )

    pre_compact_token_count = token_usage
    boundary_marker = TranscriptItem(
        role=RuntimeMessageRole.SYSTEM,
        content="Auto compact boundary.",
        name="auto_compact_boundary",
        metadata={
            "synthetic": True,
            "kind": "compact_boundary",
            "strategy": "auto_compact",
            "pre_compact_token_count": pre_compact_token_count,
            "auto_compact_threshold": auto_compact_threshold,
            "turn_id": tracking.turn_id if tracking is not None else None,
            "recompaction_in_chain": bool(tracking.compacted) if tracking is not None else False,
        },
    )
    summary_message = TranscriptItem(
        role=RuntimeMessageRole.USER,
        content=get_compact_user_summary_message(summary, True, transcript_path),
        name="auto_compact_summary",
        metadata={
            "synthetic": True,
            "kind": "auto_compact_summary",
            "is_compact_summary": True,
            "is_visible_in_transcript_only": len(messages_to_keep) == 0,
            "messages_summarized": len(messages_to_summarize),
        },
        payload={"transcript_path": transcript_path},
    )
    annotated_boundary = annotate_boundary_with_preserved_segment(
        boundary_marker,
        anchor_name=summary_message.name,
        messages_to_keep=messages_to_keep,
    )
    attachments, hook_results, user_display_message = rebuild_post_compact_artifacts(
        state=state,
        messages_to_keep=messages_to_keep,
    )
    true_post_compact_token_count = sum(
        len(item.content or "")
        for item in [annotated_boundary, summary_message, *messages_to_keep, *attachments, *hook_results]
    )
    return CompactionResult(
        boundary_marker=annotated_boundary,
        summary_messages=[summary_message],
        messages_to_keep=messages_to_keep,
        attachments=attachments,
        hook_results=hook_results,
        user_display_message=user_display_message,
        pre_compact_token_count=pre_compact_token_count,
        post_compact_token_count=true_post_compact_token_count,
        true_post_compact_token_count=true_post_compact_token_count,
        compaction_usage=compaction_usage or {"input_tokens": pre_compact_token_count, "output_tokens": len(summary_message.content or "")},
    )


async def partial_compact_conversation(
    all_messages: list[TranscriptItem],
    pivot_index: int,
    state: QueryLoopState,
    *,
    model: str,
    model_client=None,
    user_feedback: str | None = None,
    direction: _PARTIAL_DIRECTION = "from",
    strategy: str = "reactive_compact",
    boundary_name: str = "reactive_compact_boundary",
    summary_name: str = "reactive_compact_summary",
    recoverable_error_kind: str | None = None,
) -> CompactionResult:
    custom_instructions = str(state.tool_use_context.get("compact_instructions") or "").strip() or None
    transcript_path = str(state.tool_use_context.get("transcript_path") or "").strip() or None
    prepared_messages, media_stats = _strip_media_from_messages(
        all_messages,
        enabled=(recoverable_error_kind in {"media_size", "image_error"}),
    )

    if direction == "up_to":
        messages_to_summarize = list(prepared_messages[:pivot_index])
        messages_to_keep = _filter_partial_messages_to_keep(prepared_messages[pivot_index:], direction=direction)
        prompt_mode = "partial_up_to"
        api_messages = list(messages_to_summarize)
    else:
        messages_to_summarize = list(prepared_messages[pivot_index:])
        messages_to_keep = _filter_partial_messages_to_keep(prepared_messages[:pivot_index], direction=direction)
        prompt_mode = "partial"
        api_messages = list(prepared_messages)

    if not messages_to_summarize:
        raise ValueError("Nothing to summarize for partial compaction.")

    summary_input_messages = _strip_reinjected_attachments(api_messages)
    summary, compaction_usage = await _summarize_messages(
        api_messages=summary_input_messages,
        prompt_mode=prompt_mode,
        custom_instructions=custom_instructions,
        model=model,
        model_client=model_client,
        fallback_summary=_build_summary_from_messages(messages_to_summarize),
    )

    pre_compact_token_count = sum(len(item.content or "") for item in all_messages)
    boundary_marker = TranscriptItem(
        role=RuntimeMessageRole.SYSTEM,
        content="Reactive compact boundary." if strategy == "reactive_compact" else "Partial compact boundary.",
        name=boundary_name,
        metadata={
            "synthetic": True,
            "kind": "compact_boundary",
            "strategy": strategy,
            "direction": direction,
            "recoverable_error_kind": recoverable_error_kind,
            "messages_summarized": len(messages_to_summarize),
            "media_stripped_count": media_stats["media_stripped_count"],
            "user_feedback": user_feedback,
        },
    )
    summary_metadata = {
        "synthetic": True,
        "kind": summary_name,
        "strategy": strategy,
        "is_compact_summary": True,
        "media_stripped_count": media_stats["media_stripped_count"],
    }
    if messages_to_keep:
        summary_metadata["summarize_metadata"] = {
            "messages_summarized": len(messages_to_summarize),
            "user_context": user_feedback,
            "direction": direction,
        }
    else:
        summary_metadata["is_visible_in_transcript_only"] = True
    summary_message = TranscriptItem(
        role=RuntimeMessageRole.USER,
        content=get_compact_user_summary_message(summary, False, transcript_path),
        name=summary_name,
        metadata=summary_metadata,
        payload={"transcript_path": transcript_path},
    )
    anchor_name = summary_message.name if direction == "up_to" else boundary_marker.name
    annotated_boundary = annotate_boundary_with_preserved_segment(
        boundary_marker,
        anchor_name=anchor_name,
        messages_to_keep=messages_to_keep,
    )
    attachments, hook_results, user_display_message = rebuild_post_compact_artifacts(
        state=state,
        messages_to_keep=messages_to_keep,
    )
    post_messages = [annotated_boundary, summary_message, *messages_to_keep, *attachments, *hook_results]
    true_post_compact_token_count = sum(len(item.content or "") for item in post_messages)
    return CompactionResult(
        boundary_marker=annotated_boundary,
        summary_messages=[summary_message],
        messages_to_keep=messages_to_keep,
        attachments=attachments,
        hook_results=hook_results,
        user_display_message=user_display_message,
        pre_compact_token_count=pre_compact_token_count,
        post_compact_token_count=true_post_compact_token_count,
        true_post_compact_token_count=true_post_compact_token_count,
        compaction_usage={
            **(compaction_usage or {}),
            "media_stripped_count": media_stats["media_stripped_count"],
            "direction": direction,
            "messages_summarized": len(messages_to_summarize),
            "messages_kept": len(messages_to_keep),
        },
    )


def truncate_head_for_ptl_retry(messages: list[TranscriptItem], model_response: RuntimeModelResponse) -> list[TranscriptItem] | None:
    input_messages = list(messages)
    if input_messages and input_messages[0].role is RuntimeMessageRole.USER and input_messages[0].content == PTL_RETRY_MARKER:
        input_messages = input_messages[1:]
    groups = group_messages_by_api_round(input_messages)
    if len(groups) < 2:
        return None
    token_gap = _parse_prompt_too_long_token_gap(model_response)
    if token_gap is not None:
        accumulated = 0
        drop_count = 0
        for group in groups:
            accumulated += sum(len(item.content or "") for item in group)
            drop_count += 1
            if accumulated >= token_gap:
                break
    else:
        drop_count = max(1, len(groups) // 5)
    drop_count = min(drop_count, len(groups) - 1)
    if drop_count < 1:
        return None
    sliced = [deepcopy(item) for group in groups[drop_count:] for item in group]
    if not sliced:
        return None
    if sliced[0].role is RuntimeMessageRole.ASSISTANT:
        return [
            TranscriptItem(
                role=RuntimeMessageRole.USER,
                content=PTL_RETRY_MARKER,
                name="ptl_retry_marker",
                metadata={"synthetic": True, "is_meta": True},
            ),
            *sliced,
        ]
    return sliced


def group_messages_by_api_round(messages: list[TranscriptItem]) -> list[list[TranscriptItem]]:
    groups: list[list[TranscriptItem]] = []
    current: list[TranscriptItem] = []
    seen_assistant = False
    for item in messages:
        if item.role is RuntimeMessageRole.ASSISTANT:
            if current and seen_assistant:
                groups.append(current)
                current = [item]
                continue
            if current and not seen_assistant:
                groups.append(current)
                current = [item]
                seen_assistant = True
                continue
            seen_assistant = True
            current.append(item)
            continue
        current.append(item)
    if current:
        groups.append(current)
    return [group for group in groups if group]


def annotate_boundary_with_preserved_segment(
    boundary: TranscriptItem,
    *,
    anchor_name: str | None,
    messages_to_keep: list[TranscriptItem] | None,
) -> TranscriptItem:
    keep = messages_to_keep or []
    if not keep:
        return boundary
    annotated = deepcopy(boundary)
    annotated.metadata["preserved_segment"] = {
        "head_name": keep[0].name,
        "anchor_name": anchor_name,
        "tail_name": keep[-1].name,
    }
    return annotated


async def _summarize_messages(
    *,
    api_messages: list[TranscriptItem],
    prompt_mode: str,
    custom_instructions: str | None,
    model: str,
    model_client,
    fallback_summary: str,
) -> tuple[str, dict[str, Any] | None]:
    summary = fallback_summary
    compaction_usage: dict[str, Any] | None = None
    if model_client is None:
        return summary, compaction_usage

    prompt = build_compaction_prompt(mode=prompt_mode, custom_instructions=custom_instructions)
    summary_request = TranscriptItem(
        role=RuntimeMessageRole.USER,
        content=prompt,
        name="compact_summary_request",
        metadata={"synthetic": True, "kind": "compact_summary_request"},
    )
    ptl_attempts = 0
    request_messages = list(api_messages)
    while True:
        response = await _await_maybe(
            model_client.complete(
                system_prompt="你是一个负责总结对话的 AI 助手。请使用简体中文总结。",
                recon_payload={},
                transcript=[*request_messages, summary_request],
                model_name=model,
                tool_definitions=[],
                max_output_tokens_override=None,
            )
        )
        model_response = _normalize_model_response(response)
        compaction_usage = {"output_tokens": len(model_response.content or ""), "ptl_attempts": ptl_attempts}
        if model_response.recoverable_error_kind != "prompt_too_long":
            summary = model_response.content or summary
            break
        ptl_attempts += 1
        truncated = truncate_head_for_ptl_retry(request_messages, model_response) if ptl_attempts <= MAX_PTL_RETRIES else None
        if not truncated:
            raise RuntimeError(ERROR_MESSAGE_PROMPT_TOO_LONG)
        request_messages = truncated
    return summary, compaction_usage


def _strip_reinjected_attachments(messages: list[TranscriptItem]) -> list[TranscriptItem]:
    stripped: list[TranscriptItem] = []
    for item in messages:
        name = str(item.name or "")
        kind = str(item.metadata.get("kind") or "")
        attachment_kind = str(item.metadata.get("attachment_kind") or "")
        if name.startswith("post_compact_"):
            continue
        if kind in {
            "post_compact_file_attachment",
            "post_compact_skill_attachment",
            "post_compact_plan_attachment",
            "post_compact_tools_attachment",
            "post_compact_agents_attachment",
            "post_compact_mcp_attachment",
            "skill_listing",
            "skill_discovery",
        }:
            continue
        if attachment_kind in {"skill_listing", "skill_discovery", "invoked_skills", "tools_delta", "agent_listing", "mcp_instructions"}:
            continue
        stripped.append(deepcopy(item))
    return stripped


def _filter_partial_messages_to_keep(messages: list[TranscriptItem], *, direction: _PARTIAL_DIRECTION) -> list[TranscriptItem]:
    keep: list[TranscriptItem] = []
    for item in messages:
        if item.name == "progress":
            continue
        if direction == "up_to" and _is_compact_boundary_or_summary(item):
            continue
        keep.append(deepcopy(item))
    return keep


def _is_compact_boundary_or_summary(item: TranscriptItem) -> bool:
    name = str(item.name or "")
    kind = str(item.metadata.get("kind") or "")
    return (
        name in _COMPACT_BOUNDARY_NAMES
        or name in _COMPACT_SUMMARY_NAMES
        or kind == "compact_boundary"
        or kind.endswith("_compact_summary")
    )


def _build_summary_from_messages(messages: Iterable[TranscriptItem]) -> str:
    parts: list[str] = []
    for item in list(messages)[:6]:
        excerpt = (item.content or "").strip().replace("\n", " ")[:120]
        if excerpt:
            parts.append(f"[{item.role.value}] {excerpt}")
    joined = " | ".join(parts)
    if not joined:
        return "Conversation summary unavailable."
    return f"Summary of earlier conversation: {joined}"


def _parse_prompt_too_long_token_gap(model_response: RuntimeModelResponse) -> int | None:
    text = str(model_response.recoverable_error_message or "")
    match = re.search(r"(\d+)", text)
    return int(match.group(1)) if match else None


async def _await_maybe(value):
    if inspect.isawaitable(value):
        return await value
    return value


def _normalize_model_response(response) -> RuntimeModelResponse:
    if isinstance(response, RuntimeModelResponse):
        return response
    payload = dict(response or {})
    return RuntimeModelResponse(
        content=str(payload.get("content") or ""),
        tool_calls=list(payload.get("tool_calls") or []),
        stop_reason=payload.get("stop_reason"),
        recoverable_error_kind=payload.get("recoverable_error_kind"),
        recoverable_error_message=payload.get("recoverable_error_message"),
    )


def _strip_media_from_messages(
    messages: list[TranscriptItem],
    *,
    enabled: bool,
) -> tuple[list[TranscriptItem], dict[str, int]]:
    if not enabled:
        return [deepcopy(item) for item in messages], {"media_stripped_count": 0}

    total_stripped = 0
    result: list[TranscriptItem] = []
    for item in messages:
        clone = deepcopy(item)
        markers: list[str] = []
        payload = dict(clone.payload or {})
        content_blocks = payload.get("content_blocks")
        if isinstance(content_blocks, list):
            new_blocks = []
            for block in content_blocks:
                if not isinstance(block, dict):
                    new_blocks.append(block)
                    continue
                block_type = str(block.get("type") or "").lower()
                if block_type == "image":
                    total_stripped += 1
                    markers.append("[image]")
                    new_blocks.append({"type": "text", "text": "[image]"})
                    continue
                if block_type == "document":
                    total_stripped += 1
                    markers.append("[document]")
                    new_blocks.append({"type": "text", "text": "[document]"})
                    continue
                if block_type == "tool_result" and isinstance(block.get("content"), list):
                    nested_content = []
                    nested_changed = False
                    for nested in block.get("content") or []:
                        if not isinstance(nested, dict):
                            nested_content.append(nested)
                            continue
                        nested_type = str(nested.get("type") or "").lower()
                        if nested_type == "image":
                            total_stripped += 1
                            markers.append("[image]")
                            nested_content.append({"type": "text", "text": "[image]"})
                            nested_changed = True
                            continue
                        if nested_type == "document":
                            total_stripped += 1
                            markers.append("[document]")
                            nested_content.append({"type": "text", "text": "[document]"})
                            nested_changed = True
                            continue
                        nested_content.append(nested)
                    if nested_changed:
                        new_blocks.append({**block, "content": nested_content})
                        continue
                new_blocks.append(block)
            payload["content_blocks"] = new_blocks
        media_entries = payload.get("media")
        if isinstance(media_entries, list) and media_entries:
            for entry in media_entries:
                marker = "[document]" if isinstance(entry, dict) and str(entry.get("type") or "").lower() == "document" else "[image]"
                markers.append(marker)
                total_stripped += 1
            payload["media"] = []
        if markers:
            clone.payload = payload
            clone.metadata["media_stripped"] = True
            marker_prefix = " ".join(dict.fromkeys(markers))
            content = str(clone.content or "").strip()
            clone.content = f"{marker_prefix} {content}".strip() if content else marker_prefix
        result.append(clone)
    return result, {"media_stripped_count": total_stripped}
