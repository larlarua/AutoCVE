from __future__ import annotations

import asyncio
import inspect
import re
from datetime import datetime, timezone

from app.models.audit_session import AuditCheckpointType
from app.services.agent.json_parser import AgentJsonParser
from app.services.finding_runtime.models import (
    RuntimeCompletionMode,
    RuntimeContinueReason,
    RuntimeMessageRole,
    RuntimeModelResponse,
    RuntimeStopReason,
    RuntimeTerminalAction,
    ToolCallRequest,
    TranscriptItem,
    TurnExecutionResult,
)
from app.services.finding_runtime.query_attachments import (
    build_between_turn_attachments,
    materialize_pending_tool_use_summary,
    start_pending_tool_use_summary,
)
from app.services.finding_runtime.compaction.auto_compact import auto_compact_if_needed
from app.services.finding_runtime.compaction.compact import compact_conversation
from app.services.finding_runtime.compaction.models import AutoCompactTrackingState
from app.services.finding_runtime.compaction.post_compact import build_post_compact_messages
from app.services.finding_runtime.query_context import (
    append_system_context,
    apply_history_snip,
    apply_microcompact,
    apply_tool_result_budget,
    evaluate_blocking_limit,
    get_messages_after_compact_boundary,
    prepend_user_context,
    apply_context_collapse_if_needed,
)
from app.services.finding_runtime.query_degradation import handle_recoverable_response
from app.services.finding_runtime.query_messages import normalize_messages_for_model
from app.services.finding_runtime.query_state import QueryLoopState
from app.services.runtime_core.tool_search_runtime import TOOL_SEARCH_TOOL_NAME
from app.services.finding_runtime.query_stop_hooks import (
    build_stop_hook_artifact_messages,
    build_stop_hook_messages,
    evaluate_post_tool_hooks,
    evaluate_stop_hooks,
)
from app.services.runtime_core.hook_policy import collect_turn_hook_events
from app.services.finding_runtime.query_token_budget import evaluate_token_budget_continuation
from app.services.finding_runtime.query_transitions import (
    build_continue_state,
    build_terminal_state,
    hydrate_query_loop_state,
)


class QueryLoop:
    ALLOW_LEGACY_TEXT_TOOL_CALLS = False
    _CONTINUE_INTENT_PATTERNS = (
        re.compile(r"继续审查"),
        re.compile(r"继续检查"),
        re.compile(r"继续查看"),
        re.compile(r"继续搜索"),
        re.compile(r"让我继续"),
        re.compile(r"让我再看"),
        re.compile(r"我再看"),
        re.compile(r"let me continue", re.IGNORECASE),
        re.compile(r"i(?:'| wi)ll continue", re.IGNORECASE),
        re.compile(r"let me inspect", re.IGNORECASE),
        re.compile(r"let me check", re.IGNORECASE),
        re.compile(r"i(?:'| wi)ll inspect", re.IGNORECASE),
        re.compile(r"我需要(查看|检查|读取|确认|分析)"),
        re.compile(r"需要(继续)?(查看|检查|读取|确认|分析)"),
        re.compile(r"还需要(查看|检查|读取|确认|分析)"),
        re.compile(r"接下来(查看|检查|读取|确认|分析)"),
        re.compile(r"让我(查看|检查|读取|确认|分析)"),
        re.compile(r"我将(查看|检查|读取|确认|分析)"),
        re.compile(r"继续(查看|检查|读取|确认|分析)"),
        re.compile(r"\b(let me|i need to|i should|i will|i'll)\s+(read|inspect|check|review|examine|look at)\b", re.IGNORECASE),
        re.compile(r"\bneed to\s+(read|inspect|check|review|examine|look at)\b", re.IGNORECASE),
    )

    def __init__(
        self,
        *,
        session_store,
        model_client,
        tool_registry=None,
        tool_orchestrator=None,
        event_sink=None,
        require_terminal_action: bool = False,
        terminal_action_nudge_limit: int = 1,
    ):
        self._session_store = session_store
        self._model_client = model_client
        self._tool_registry = tool_registry
        self._tool_orchestrator = tool_orchestrator
        self._event_sink = event_sink
        self._require_terminal_action = bool(require_terminal_action)
        self._terminal_action_nudge_limit = max(0, int(terminal_action_nudge_limit or 0))

    async def run_turn(self, *, session_id: str, model_name: str) -> TurnExecutionResult:
        snapshot = self._session_store.load_session_snapshot(session_id)
        runtime_state = self._session_store.load_runtime_state(session_id)
        state = self._load_query_loop_state(session_id=session_id, snapshot=snapshot)
        state = self._merge_runtime_query_context_pipeline(state, runtime_state)
        state = materialize_pending_tool_use_summary(state)
        turn_id = self._session_store.open_turn(session_id, model_name=model_name)
        tool_definitions = self._tool_registry.describe_tools(active_tool_names=self._state_active_tool_names(state)) if self._tool_registry is not None else []
        transcript = list(state.messages)
        prepared_messages = get_messages_after_compact_boundary(transcript, state)
        prepared_messages = apply_tool_result_budget(prepared_messages, state)
        prepared_messages = apply_history_snip(prepared_messages, state)
        prepared_messages = apply_microcompact(prepared_messages, state)
        prepared_messages, state = apply_context_collapse_if_needed(prepared_messages, state)
        auto_compact_decision = auto_compact_if_needed(
            prepared_messages,
            state,
            tracking=self._extract_auto_compact_tracking(state),
            compactor=lambda messages, state, **kwargs: compact_conversation(
                messages,
                state,
                model_client=self._model_client,
                **kwargs,
            ),
        )
        if inspect.isawaitable(auto_compact_decision):
            auto_compact_decision = await auto_compact_decision
        prepared_messages, state = self._apply_auto_compact_decision(
            state=state,
            prepared_messages=prepared_messages,
            decision=auto_compact_decision,
        )
        effective_system_prompt = append_system_context(snapshot.session.system_prompt, runtime_state)
        prepared_messages = prepend_user_context(prepared_messages, runtime_state)
        prepared_messages = normalize_messages_for_model(prepared_messages)
        blocking_limit = evaluate_blocking_limit(prepared_messages, state)
        if blocking_limit.get("blocked"):
            return self._finalize_terminal_result(
                session_id=session_id,
                turn_id=turn_id,
                state=state,
                messages=state.messages,
                stop_reason=RuntimeStopReason.BLOCKING_LIMIT,
                status="blocking_limit",
                checkpoint_extra={
                    "phase": "blocking_limit_preflight",
                    "blocking_limit": {
                        "current_chars": int(blocking_limit.get("current_chars") or 0),
                        "max_chars": int(blocking_limit.get("max_chars") or 0),
                    },
                },
            )
        assistant_stream_started = False
        assistant_stream_sequence = (snapshot.messages[-1].sequence if snapshot.messages else 0) + 1
        assistant_stream_placeholder_id = f"streaming-{session_id}-{turn_id}"

        try:
            collected = await self._collect_model_turn(
                session_id=session_id,
                turn_id=turn_id,
                state=state,
                snapshot=snapshot,
                effective_system_prompt=effective_system_prompt,
                prepared_messages=prepared_messages,
                model_name=model_name,
                tool_definitions=tool_definitions,
                assistant_stream_placeholder_id=assistant_stream_placeholder_id,
                assistant_stream_sequence=assistant_stream_sequence,
            )
        except asyncio.CancelledError:
            return self._finalize_terminal_result(
                session_id=session_id,
                turn_id=turn_id,
                state=state,
                messages=state.messages,
                stop_reason=RuntimeStopReason.ABORTED_STREAMING,
                status="aborted_streaming",
            )
        except Exception as exc:
            return self._finalize_terminal_result(
                session_id=session_id,
                turn_id=turn_id,
                state=state,
                messages=state.messages,
                stop_reason=RuntimeStopReason.MODEL_ERROR,
                status="model_error",
                checkpoint_extra={"phase": "model", "error": str(exc)},
            )

        model_response = collected["model_response"]
        assistant_message_id = collected["assistant_message_id"]
        working_messages = collected["working_messages"]
        tool_requests = collected["tool_requests"]
        tool_result_message_ids = collected["tool_result_message_ids"]
        tool_call_ids = collected["tool_call_ids"]
        streamed_records = collected["records"]
        tool_use_context = collected["tool_use_context"]
        streamed_tool_uses = bool(collected.get("tool_uses_appended"))
        legacy_text_tool_calls = list(collected.get("legacy_text_tool_calls") or [])
        stop_reason: RuntimeStopReason | None = None
        transition: RuntimeContinueReason | None = None
        checkpoint_extra: dict[str, object] | None = None
        terminal_action: RuntimeTerminalAction | None = None
        completion_mode: RuntimeCompletionMode | None = None
        final_payload: dict[str, Any] | None = None
        continue_intent_without_action = False

        if not tool_requests and legacy_text_tool_calls and tool_definitions and self._tool_orchestrator is not None:
            legacy_tool_names = [str(item.get("name") or "").strip() for item in legacy_text_tool_calls if str(item.get("name") or "").strip()]
            if self._should_issue_legacy_tool_syntax_nudge(state=state):
                transition = RuntimeContinueReason.LEGACY_TOOL_SYNTAX_NUDGE
                nudge_message = TranscriptItem(
                    role=RuntimeMessageRole.USER,
                    content=(
                        "你刚刚使用了纯文本工具调用语法（例如 Tool Call:/Action:），这类内容不会被执行。"
                        "如果还需要继续审计，请改用模型提供方原生的结构化工具调用重新发起同一动作。"
                        "如果已经完成审计，请直接调用 FinalizeFinding 提交最终结构化结果。"
                    ),
                    name="legacy_tool_syntax_nudge",
                    metadata={"synthetic": True, "kind": "legacy_tool_syntax_nudge"},
                )
                next_state = build_continue_state(state, messages=[*working_messages, nudge_message], transition=transition)
                next_state.tool_use_context["legacy_text_tool_call_nudge_count"] = int(
                    (state.tool_use_context or {}).get("legacy_text_tool_call_nudge_count") or 0
                ) + 1
                self._session_store.save_query_loop_state(session_id, next_state)
                self._session_store.close_turn(turn_id, status="legacy_tool_syntax_nudge")
                self._write_checkpoint(
                    session_id=session_id,
                    turn_id=turn_id,
                    stop_reason=None,
                    transition=transition,
                    assistant_message_id=assistant_message_id,
                    tool_call_ids=[],
                    extra_state_payload={
                        "phase": "legacy_tool_syntax",
                        "legacy_text_tool_call_names": legacy_tool_names,
                    },
                )
                return TurnExecutionResult(
                    turn_id=turn_id,
                    stop_reason=None,
                    assistant_message_id=assistant_message_id,
                    tool_call_ids=[],
                    tool_result_message_ids=[],
                    transition=transition,
                )

            return self._finalize_terminal_result(
                session_id=session_id,
                turn_id=turn_id,
                state=state,
                messages=working_messages,
                stop_reason=RuntimeStopReason.COMPLETED,
                status="legacy_tool_syntax_incomplete",
                assistant_message_id=assistant_message_id,
                terminal_action=RuntimeTerminalAction.NATURAL_END_WITHOUT_TERMINAL_ACTION,
                completion_mode=RuntimeCompletionMode.INCOMPLETE,
                checkpoint_extra={
                    "phase": "legacy_tool_syntax",
                    "legacy_text_tool_call_names": legacy_tool_names,
                },
            )

        if tool_requests:
            if not streamed_tool_uses:
                for request in tool_requests:
                    tool_use_item = TranscriptItem(
                        role=RuntimeMessageRole.TOOL_USE,
                        content=request.name,
                        name=request.name,
                        payload={
                            "tool_use_id": request.id,
                            "tool_name": request.name,
                            "input": request.input,
                        },
                    )
                    self._session_store.append_message(session_id, tool_use_item)
                    working_messages.append(tool_use_item)

            if self._tool_orchestrator is None:
                if tool_definitions:
                    raise RuntimeError("Tool calls were returned but no tool orchestrator is configured")
                return self._finalize_terminal_result(
                    session_id=session_id,
                    turn_id=turn_id,
                    state=state,
                    messages=working_messages,
                    stop_reason=RuntimeStopReason.COMPLETED,
                    status="tool_calls_ignored",
                    assistant_message_id=assistant_message_id,
                    ignored_tool_calls=[request.name for request in tool_requests],
                )

            records = list(streamed_records)
            if not records:
                executor_builder = getattr(self._tool_orchestrator, "build_streaming_executor", None)
                try:
                    if callable(executor_builder):
                        executor = executor_builder(
                            session_id=session_id,
                            turn_id=turn_id,
                            tool_calls=tool_requests,
                            session=snapshot.session,
                            recon_payload=snapshot.session.recon_payload or {},
                            initial_context=tool_use_context,
                        )
                        async for update in executor.get_remaining_updates():
                            tool_use_context = self._consume_executor_update(
                                session_id=session_id,
                                update=update,
                                working_messages=working_messages,
                                records=records,
                                tool_call_ids=tool_call_ids,
                                tool_result_message_ids=tool_result_message_ids,
                                tool_use_context=tool_use_context,
                            )
                        tool_use_context = executor.get_updated_context()
                    else:
                        fallback_records = await self._tool_orchestrator.execute_tool_calls(
                            session_id=session_id,
                            turn_id=turn_id,
                            tool_calls=tool_requests,
                            session=snapshot.session,
                            recon_payload=snapshot.session.recon_payload or {},
                        )
                        for record in fallback_records:
                            tool_use_context = self._consume_executor_update(
                                session_id=session_id,
                                update=type("Update", (), {"kind": "record", "record": record, "progress_payload": None, "new_context": None})(),
                                working_messages=working_messages,
                                records=records,
                                tool_call_ids=tool_call_ids,
                                tool_result_message_ids=tool_result_message_ids,
                                tool_use_context=tool_use_context,
                            )
                except asyncio.CancelledError:
                    return self._finalize_terminal_result(
                        session_id=session_id,
                        turn_id=turn_id,
                        state=state,
                        messages=working_messages,
                        stop_reason=RuntimeStopReason.ABORTED_TOOLS,
                        status="aborted_tools",
                        assistant_message_id=assistant_message_id,
                        checkpoint_extra={"phase": "tool_execution"},
                    )
                except Exception as exc:
                    return self._finalize_terminal_result(
                        session_id=session_id,
                        turn_id=turn_id,
                        state=state,
                        messages=working_messages,
                        stop_reason=RuntimeStopReason.MODEL_ERROR,
                        status="tool_execution_failed",
                        assistant_message_id=assistant_message_id,
                        checkpoint_extra={"phase": "tool_execution", "error": str(exc)},
                    )

            post_tool_snapshot = self._session_store.load_session_snapshot(session_id)
            turn_hook_events = collect_turn_hook_events(checkpoints=post_tool_snapshot.checkpoints, turn_id=turn_id)
            post_tool_hook = evaluate_post_tool_hooks(
                runtime_state=runtime_state,
                records=records,
                hook_events=turn_hook_events,
            )
            if inspect.isawaitable(post_tool_hook):
                post_tool_hook = await post_tool_hook
            post_tool_emitted_events = list(post_tool_hook.get("emitted_hook_events") or [])
            if post_tool_emitted_events:
                self._persist_runtime_hook_events(
                    session_id=session_id,
                    turn_id=turn_id,
                    hook_events=post_tool_emitted_events,
                )
                post_tool_artifacts = build_stop_hook_artifact_messages(post_tool_hook)
                if post_tool_artifacts:
                    self._append_transcript_items(session_id=session_id, items=post_tool_artifacts)
                    working_messages.extend(post_tool_artifacts)
            if post_tool_hook.get("hook_stopped"):
                return self._finalize_terminal_result(
                    session_id=session_id,
                    turn_id=turn_id,
                    state=state,
                    messages=working_messages,
                    stop_reason=RuntimeStopReason.HOOK_STOPPED,
                    status="hook_stopped",
                    assistant_message_id=assistant_message_id,
                    tool_call_ids=tool_call_ids,
                    tool_result_message_ids=tool_result_message_ids,
                    terminal_action=RuntimeTerminalAction.HOOK_STOP,
                    checkpoint_extra={"hook_stop_reason": post_tool_hook.get("stop_reason")},
                )

            finalize_payload = self._extract_finalize_payload(records)
            if finalize_payload is not None:
                finalize_terminal_action = self._extract_finalize_terminal_action(records)
                return self._finalize_terminal_result(
                    session_id=session_id,
                    turn_id=turn_id,
                    state=state,
                    messages=working_messages,
                    stop_reason=RuntimeStopReason.COMPLETED,
                    status="completed",
                    assistant_message_id=assistant_message_id,
                    tool_call_ids=tool_call_ids,
                    tool_result_message_ids=tool_result_message_ids,
                    terminal_action=finalize_terminal_action,
                    completion_mode=RuntimeCompletionMode.FINALIZE_TOOL,
                    final_payload=finalize_payload,
                )

            attachment_messages = build_between_turn_attachments(
                state=state,
                records=records,
                session_snapshot=post_tool_snapshot,
            )
            pending_tool_use_summary = start_pending_tool_use_summary(
                state=state,
                records=records,
                session_snapshot=post_tool_snapshot,
            )
            transition = RuntimeContinueReason.NEXT_TURN
            next_messages = [*working_messages, *list(attachment_messages or [])]
            next_state = build_continue_state(state, messages=next_messages, transition=transition)
            streaming_state = QueryLoopState(tool_use_context=tool_use_context)
            next_tool_use_context = self._apply_tool_search_activations(state=streaming_state, records=records)
            next_tool_use_context.pop("missing_terminal_action_nudge_count", None)
            next_state.tool_use_context = next_tool_use_context
            next_state.pending_tool_use_summary = pending_tool_use_summary
            self._session_store.save_query_loop_state(session_id, next_state)
            self._session_store.close_turn(turn_id, status="tool_results_ready")
        else:
            degradation = await handle_recoverable_response(
                state=state,
                working_messages=working_messages,
                model_response=model_response,
                model=str(getattr(snapshot.session, "model_name", "") or state.tool_use_context.get("main_loop_model") or ""),
                model_client=self._model_client,
            )
            if degradation is not None and degradation.next_state is not None:
                transition = degradation.next_state.transition
                checkpoint_extra = dict(degradation.checkpoint_payload or {})
                self._session_store.save_query_loop_state(session_id, degradation.next_state)
                self._session_store.close_turn(turn_id, status="recovery_pending")
                self._write_checkpoint(
                    session_id=session_id,
                    turn_id=turn_id,
                    stop_reason=None,
                    transition=transition,
                    assistant_message_id=assistant_message_id,
                    tool_call_ids=[],
                    extra_state_payload=checkpoint_extra,
                )
                return TurnExecutionResult(
                    turn_id=turn_id,
                    stop_reason=None,
                    assistant_message_id=assistant_message_id,
                    tool_call_ids=[],
                    tool_result_message_ids=[],
                    transition=transition,
                )
            if degradation is not None and degradation.stop_reason is not None:
                stop_reason = degradation.stop_reason
            else:
                stop_hook_result = evaluate_stop_hooks(
                    runtime_state=runtime_state,
                    messages=working_messages,
                    model_response=model_response,
                    hook_events=collect_turn_hook_events(checkpoints=self._session_store.load_session_snapshot(session_id).checkpoints, turn_id=turn_id),
                )
                if inspect.isawaitable(stop_hook_result):
                    stop_hook_result = await stop_hook_result
                emitted_hook_events = list(stop_hook_result.get("emitted_hook_events") or [])
                if emitted_hook_events:
                    self._persist_runtime_hook_events(
                        session_id=session_id,
                        turn_id=turn_id,
                        hook_events=emitted_hook_events,
                    )
                artifact_messages = build_stop_hook_artifact_messages(stop_hook_result)
                if artifact_messages:
                    self._append_transcript_items(session_id=session_id, items=artifact_messages)
                    working_messages.extend(artifact_messages)
                blocking_errors = list(stop_hook_result.get("blocking_errors") or [])
                if blocking_errors:
                    transition = RuntimeContinueReason.STOP_HOOK_BLOCKING
                    next_messages = [*working_messages, *build_stop_hook_messages(blocking_errors)]
                    next_state = build_continue_state(state, messages=next_messages, transition=transition)
                    next_state.stop_hook_active = True
                    self._session_store.save_query_loop_state(session_id, next_state)
                    self._session_store.close_turn(turn_id, status="stop_hook_blocking")
                    self._write_checkpoint(
                        session_id=session_id,
                        turn_id=turn_id,
                        stop_reason=None,
                        transition=transition,
                        assistant_message_id=assistant_message_id,
                        tool_call_ids=[],
                    )
                    return TurnExecutionResult(
                        turn_id=turn_id,
                        stop_reason=None,
                        assistant_message_id=assistant_message_id,
                        tool_call_ids=[],
                        tool_result_message_ids=[],
                        transition=transition,
                    )
                if stop_hook_result.get("prevent_continuation"):
                    stop_reason = RuntimeStopReason.STOP_HOOK_PREVENTED
                else:
                    token_budget_result = evaluate_token_budget_continuation(
                        runtime_state=runtime_state,
                        state=state,
                        model_response=model_response,
                    )
                    if token_budget_result.get("should_continue"):
                        transition = RuntimeContinueReason.TOKEN_BUDGET_CONTINUATION
                        nudge_message = TranscriptItem(
                            role=RuntimeMessageRole.USER,
                            content=str(token_budget_result.get("message") or "").strip(),
                            name="token_budget_nudge",
                            metadata={"synthetic": True, "kind": "token_budget_continuation"},
                        )
                        next_state = build_continue_state(state, messages=[*working_messages, nudge_message], transition=transition)
                        self._session_store.save_query_loop_state(session_id, next_state)
                        self._session_store.close_turn(turn_id, status="token_budget_continuation")
                        self._write_checkpoint(
                            session_id=session_id,
                            turn_id=turn_id,
                            stop_reason=None,
                            transition=transition,
                            assistant_message_id=assistant_message_id,
                            tool_call_ids=[],
                        )
                        return TurnExecutionResult(
                            turn_id=turn_id,
                            stop_reason=None,
                            assistant_message_id=assistant_message_id,
                            tool_call_ids=[],
                            tool_result_message_ids=[],
                            transition=transition,
                        )
                    stop_reason = self._coerce_stop_reason(model_response.stop_reason)
                    continue_intent_without_action = self._has_continue_intent_without_action(
                        model_response=model_response,
                        tool_definitions=tool_definitions,
                    )
            if (
                stop_reason is RuntimeStopReason.COMPLETED
                and self._should_issue_terminal_action_nudge(
                    state=state,
                    model_response=model_response,
                    tool_definitions=tool_definitions,
                    continue_intent_without_action=continue_intent_without_action,
                )
            ):
                transition = RuntimeContinueReason.TERMINAL_ACTION_NUDGE
                nudge_message = TranscriptItem(
                    role=RuntimeMessageRole.USER,
                    content=(
                        "你刚刚表达了还要继续审查的意图，但没有真正执行动作。"
                        "如果还需要继续收集证据，请直接调用下一次工具；"
                        "如果已经完成审计，请立即调用 FinalizeFinding 提交最终结构化结果。"
                        "不要只描述下一步计划而不执行。"
                    ),
                    name="terminal_action_nudge",
                    metadata={"synthetic": True, "kind": "terminal_action_nudge"},
                )
                nudge_message.content = (
                    "你刚才没有发起工具调用，也没有调用 FinalizeFinding。Finding 阶段不能用普通文字结束。\n\n"
                    "如果仍需验证，请立即调用 Read/Grep/Glob/PowerShell 等工具继续查看证据。\n"
                    "如果审计已经完成，请立即调用 FinalizeFinding，提交 findings 和 summary。\n"
                    "不要只回复说明文字。"
                )
                next_state = build_continue_state(state, messages=[*working_messages, nudge_message], transition=transition)
                next_state.tool_use_context["missing_terminal_action_nudge_count"] = int(
                    (state.tool_use_context or {}).get("missing_terminal_action_nudge_count") or 0
                ) + 1
                self._session_store.save_query_loop_state(session_id, next_state)
                self._session_store.close_turn(turn_id, status="terminal_action_nudge")
                self._write_checkpoint(
                    session_id=session_id,
                    turn_id=turn_id,
                    stop_reason=None,
                    transition=transition,
                    assistant_message_id=assistant_message_id,
                    tool_call_ids=[],
                )
                return TurnExecutionResult(
                    turn_id=turn_id,
                    stop_reason=None,
                    assistant_message_id=assistant_message_id,
                    tool_call_ids=[],
                    tool_result_message_ids=[],
                    transition=transition,
                )
            if (
                stop_reason is RuntimeStopReason.COMPLETED
                and (continue_intent_without_action or self._require_terminal_action)
            ):
                terminal_action = RuntimeTerminalAction.NATURAL_END_WITHOUT_TERMINAL_ACTION
                completion_mode = RuntimeCompletionMode.INCOMPLETE
            return self._finalize_terminal_result(
                session_id=session_id,
                turn_id=turn_id,
                state=state,
                messages=working_messages,
                stop_reason=stop_reason,
                status="completed",
                assistant_message_id=assistant_message_id,
                terminal_action=terminal_action,
                completion_mode=completion_mode,
                final_payload=final_payload,
                checkpoint_extra=checkpoint_extra,
            )

        self._write_checkpoint(
            session_id=session_id,
            turn_id=turn_id,
            stop_reason=stop_reason,
            transition=transition,
            assistant_message_id=assistant_message_id,
            tool_call_ids=tool_call_ids,
            extra_state_payload=checkpoint_extra,
        )
        return TurnExecutionResult(
            turn_id=turn_id,
            stop_reason=stop_reason,
            assistant_message_id=assistant_message_id,
            tool_call_ids=tool_call_ids,
            tool_result_message_ids=tool_result_message_ids,
            transition=transition,
            terminal_action=terminal_action,
            completion_mode=completion_mode,
            final_payload=final_payload,
        )

    @staticmethod
    def _extract_auto_compact_tracking(state: QueryLoopState) -> AutoCompactTrackingState | None:
        tracking = dict(state.auto_compact_tracking or {})
        if not tracking:
            return None
        return AutoCompactTrackingState(
            compacted=bool(tracking.get("compacted") or False),
            turn_counter=int(tracking.get("turn_counter") or state.turn_count),
            turn_id=str(tracking.get("turn_id") or f"turn-{state.turn_count}"),
            consecutive_failures=(
                int(tracking.get("consecutive_failures"))
                if tracking.get("consecutive_failures") is not None
                else None
            ),
        )

    @staticmethod
    def _apply_auto_compact_decision(
        *,
        state: QueryLoopState,
        prepared_messages: list[TranscriptItem],
        decision,
    ) -> tuple[list[TranscriptItem], QueryLoopState]:
        tracking = dict(state.auto_compact_tracking or {})
        if getattr(decision, "consecutive_failures", None) is not None:
            tracking["consecutive_failures"] = decision.consecutive_failures
        next_messages = list(prepared_messages)
        if getattr(decision, "was_compacted", False) and getattr(decision, "compaction_result", None) is not None:
            result = decision.compaction_result
            next_messages = build_post_compact_messages(result)
            tracking.update({
                "compacted": True,
                "turn_counter": int(state.turn_count),
                "turn_id": f"turn-{state.turn_count}",
                "consecutive_failures": 0,
                "boundary_name": result.boundary_marker.name,
                "summary_message_name": result.summary_messages[-1].name if result.summary_messages else None,
            })
            for key in ("auto_compact_threshold", "effective_context_window"):
                if result.boundary_marker.metadata.get(key) is not None:
                    tracking[key] = result.boundary_marker.metadata.get(key)
        return next_messages, QueryLoopState(
            messages=list(next_messages),
            tool_use_context=dict(state.tool_use_context),
            auto_compact_tracking=tracking or None,
            context_collapse_state=dict(state.context_collapse_state or {}) if state.context_collapse_state is not None else None,
            max_output_tokens_recovery_count=state.max_output_tokens_recovery_count,
            has_attempted_reactive_compact=state.has_attempted_reactive_compact,
            max_output_tokens_override=state.max_output_tokens_override,
            pending_tool_use_summary=dict(state.pending_tool_use_summary or {}) if state.pending_tool_use_summary is not None else None,
            stop_hook_active=state.stop_hook_active,
            turn_count=state.turn_count,
            transition=state.transition,
        )

    def _load_query_loop_state(self, *, session_id: str, snapshot) -> QueryLoopState:
        state = self._session_store.load_query_loop_state(session_id)
        if state.messages:
            return state
        transcript = [
            TranscriptItem(
                role=RuntimeMessageRole(message.role),
                content=message.content,
                name=message.name,
                metadata=dict(message.message_metadata or {}),
                payload=dict(message.payload or {}),
            )
            for message in snapshot.messages
        ]
        if snapshot.turns:
            state.turn_count = len(snapshot.turns) + 1
        return hydrate_query_loop_state(state, messages=transcript)


    def _state_active_tool_names(self, state: QueryLoopState) -> list[str] | None:
        active = (state.tool_use_context or {}).get("active_tool_names")
        if not isinstance(active, list):
            return None
        return [str(name) for name in active if str(name or "").strip()]

    def _apply_tool_search_activations(self, *, state: QueryLoopState, records) -> dict[str, object]:
        tool_use_context = dict(state.tool_use_context or {})
        if self._tool_registry is None:
            return tool_use_context
        active_names = self._tool_registry.resolve_active_tool_names(self._state_active_tool_names(state))
        activated: list[str] = []
        for record in records:
            if record.request.name != TOOL_SEARCH_TOOL_NAME or record.result.is_error:
                continue
            matches = record.result.output_payload.get("matches") if isinstance(record.result.output_payload, dict) else None
            for match in matches or []:
                tool = self._tool_registry.get(str(match))
                if tool is None:
                    continue
                if tool.name not in active_names:
                    active_names.append(tool.name)
                if tool.name not in activated:
                    activated.append(tool.name)
        if active_names:
            tool_use_context["active_tool_names"] = active_names
        if activated:
            tool_use_context["last_tool_search"] = {"selected_tools": activated}
        return tool_use_context


    @staticmethod
    def _merge_runtime_query_context_pipeline(state: QueryLoopState, runtime_state) -> QueryLoopState:
        query_context = dict(getattr(runtime_state, "metadata", {}).get("query_context") or {})
        pipeline = dict(query_context.get("pipeline") or {})
        if not pipeline:
            return state
        merged_tool_use_context = dict(state.tool_use_context or {})
        existing_pipeline = dict(merged_tool_use_context.get("query_context_pipeline") or {})
        for key, value in pipeline.items():
            if isinstance(value, dict) and isinstance(existing_pipeline.get(key), dict):
                merged_value = dict(value)
                merged_value.update(existing_pipeline.get(key) or {})
                existing_pipeline[key] = merged_value
            else:
                existing_pipeline.setdefault(key, value)
        merged_tool_use_context["query_context_pipeline"] = existing_pipeline
        state.tool_use_context = merged_tool_use_context
        return state
    @staticmethod
    def _normalize_model_response(response) -> RuntimeModelResponse:
        if isinstance(response, RuntimeModelResponse):
            return response
        payload = dict(response or {})
        return RuntimeModelResponse(
            content=str(payload.get("content") or ""),
            tool_calls=list(payload.get("tool_calls") or []),
            stop_reason=str(payload.get("stop_reason")) if payload.get("stop_reason") is not None else None,
            recoverable_error_kind=str(payload.get("recoverable_error_kind")) if payload.get("recoverable_error_kind") else None,
            recoverable_error_message=str(payload.get("recoverable_error_message")) if payload.get("recoverable_error_message") else None,
            usage=dict(payload.get("usage") or {}),
            native_tool_call_count=len(list(payload.get("tool_calls") or [])),
            has_terminal_tool_call=any(
                str((item or {}).get("name") or "").strip() == "FinalizeFinding"
                for item in list(payload.get("tool_calls") or [])
                if isinstance(item, dict)
            ),
        )

    def _finalize_terminal_result(
        self,
        *,
        session_id: str,
        turn_id: str,
        state: QueryLoopState,
        messages: list[TranscriptItem],
        stop_reason: RuntimeStopReason,
        status: str,
        assistant_message_id: str | None = None,
        tool_call_ids: list[str] | None = None,
        tool_result_message_ids: list[str] | None = None,
        ignored_tool_calls: list[str] | None = None,
        terminal_action: RuntimeTerminalAction | None = None,
        completion_mode: RuntimeCompletionMode | None = None,
        final_payload: dict[str, Any] | None = None,
        checkpoint_extra: dict[str, object] | None = None,
    ) -> TurnExecutionResult:
        terminal_state = build_terminal_state(state, messages=messages)
        terminal_state.pending_tool_use_summary = state.pending_tool_use_summary
        self._session_store.save_query_loop_state(session_id, terminal_state)
        self._session_store.close_turn(turn_id, status=status)
        self._write_checkpoint(
            session_id=session_id,
            turn_id=turn_id,
            stop_reason=stop_reason,
            transition=None,
            assistant_message_id=assistant_message_id,
            tool_call_ids=list(tool_call_ids or []),
            ignored_tool_calls=ignored_tool_calls,
            extra_state_payload={
                **dict(checkpoint_extra or {}),
                **({"terminal_action": terminal_action.value} if terminal_action is not None else {}),
                **({"completion_mode": completion_mode.value} if completion_mode is not None else {}),
                **({"final_payload": dict(final_payload)} if final_payload is not None else {}),
            } or None,
        )
        return TurnExecutionResult(
            turn_id=turn_id,
            stop_reason=stop_reason,
            assistant_message_id=assistant_message_id,
            tool_call_ids=list(tool_call_ids or []),
            tool_result_message_ids=list(tool_result_message_ids or []),
            transition=None,
            terminal_action=terminal_action,
            completion_mode=completion_mode,
            final_payload=dict(final_payload) if final_payload is not None else None,
        )

    def _append_transcript_items(
        self,
        *,
        session_id: str,
        items: list[TranscriptItem],
    ) -> None:
        for item in items:
            self._session_store.append_message(session_id, item)

    async def _emit_event(self, event: dict[str, object]) -> None:
        if self._event_sink is None:
            return
        maybe_awaitable = self._event_sink(event)
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable

    async def _collect_model_turn(
        self,
        *,
        session_id: str,
        turn_id: str,
        state: QueryLoopState,
        snapshot,
        effective_system_prompt: str,
        prepared_messages: list[TranscriptItem],
        model_name: str,
        tool_definitions: list[dict[str, Any]],
        assistant_stream_placeholder_id: str,
        assistant_stream_sequence: int,
    ) -> dict[str, Any]:
        stream_fn = getattr(self._model_client, "stream_complete", None)
        if not callable(stream_fn):
            model_response = self._normalize_model_response(
                await self._model_client.complete(
                    system_prompt=effective_system_prompt,
                    recon_payload=snapshot.session.recon_payload or {},
                    transcript=prepared_messages,
                    model_name=model_name,
                    tool_definitions=tool_definitions,
                    max_output_tokens_override=state.max_output_tokens_override,
                )
            )
            assistant_message_id = None
            working_messages = list(state.messages)
            if model_response.content:
                assistant_item = TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content=model_response.content)
                assistant_message_id = self._session_store.append_message(session_id, assistant_item)
                working_messages.append(assistant_item)
                if self._event_sink is not None:
                    assistant_message = self._session_store.get_message(assistant_message_id)
                    if assistant_message is not None:
                        await self._emit_event(
                            {
                                "type": "assistant_start",
                                "message": {
                                    "id": assistant_stream_placeholder_id,
                                    "session_id": session_id,
                                    "sequence": assistant_message.sequence,
                                    "role": "assistant",
                                    "content": "",
                                    "metadata": {"kind": "direct_audit_assistant_message", "streaming": True},
                                    "payload": {},
                                    "created_at": assistant_message.created_at.isoformat(),
                                },
                            }
                        )
                        await self._emit_event(
                            {
                                "type": "token",
                                "content": assistant_message.content,
                                "accumulated": assistant_message.content,
                            }
                        )
                        await self._emit_event(
                            {
                                "type": "done",
                                "message": {
                                    "id": assistant_message.id,
                                    "session_id": assistant_message.session_id,
                                    "sequence": assistant_message.sequence,
                                    "role": assistant_message.role,
                                    "content": assistant_message.content,
                                    "metadata": dict(assistant_message.message_metadata or {}),
                                    "payload": dict(assistant_message.payload or {}),
                                    "created_at": assistant_message.created_at.isoformat(),
                                },
                                "usage": dict(model_response.usage or {}),
                            }
                        )
            raw_tool_calls = list(model_response.tool_calls or [])
            legacy_text_tool_calls: list[dict[str, object]] = []
            if not raw_tool_calls and model_response.content and tool_definitions and self._tool_orchestrator is not None:
                extracted_tool_calls = self._extract_text_tool_calls(model_response.content)
                if self.ALLOW_LEGACY_TEXT_TOOL_CALLS:
                    raw_tool_calls = extracted_tool_calls
                else:
                    legacy_text_tool_calls = list(extracted_tool_calls)
            return {
                "model_response": model_response,
                "assistant_message_id": assistant_message_id,
                "working_messages": working_messages,
                "tool_requests": [
                    ToolCallRequest(
                        id=item.get("id") or f"tool-use-{index + 1}",
                        name=item["name"],
                        input=dict(item.get("input") or {}),
                    )
                    for index, item in enumerate(raw_tool_calls)
                ],
                "tool_result_message_ids": [],
                "tool_call_ids": [],
                "records": [],
                "tool_use_context": dict(state.tool_use_context or {}),
                "tool_uses_appended": False,
                "legacy_text_tool_calls": legacy_text_tool_calls,
            }

        working_messages = list(state.messages)
        tool_requests: list[ToolCallRequest] = []
        tool_result_message_ids: list[str] = []
        tool_call_ids: list[str] = []
        records = []
        tool_use_context = dict(state.tool_use_context or {})
        assistant_message_id: str | None = None
        assistant_content = ""
        stream_done: dict[str, Any] | None = None
        assistant_stream_started = False
        executor = None
        if self._tool_orchestrator is not None:
            executor = self._tool_orchestrator.build_streaming_executor(
                session_id=session_id,
                turn_id=turn_id,
                tool_calls=[],
                session=snapshot.session,
                recon_payload=snapshot.session.recon_payload or {},
                initial_context=tool_use_context,
            )
        async for event in stream_fn(
            system_prompt=effective_system_prompt,
            recon_payload=snapshot.session.recon_payload or {},
            transcript=prepared_messages,
            model_name=model_name,
            tool_definitions=tool_definitions,
            max_output_tokens_override=state.max_output_tokens_override,
        ):
            event_type = str((event or {}).get("type") or "").strip().lower()
            if event_type == "content_delta":
                assistant_content = str((event or {}).get("accumulated") or (assistant_content + str((event or {}).get("content") or "")))
                if not assistant_stream_started:
                    assistant_stream_started = True
                    await self._emit_event(
                        {
                            "type": "assistant_start",
                            "message": {
                                "id": assistant_stream_placeholder_id,
                                "session_id": session_id,
                                "sequence": assistant_stream_sequence,
                                "role": "assistant",
                                "content": "",
                                "metadata": {"kind": "direct_audit_assistant_message", "streaming": True},
                                "payload": {},
                                "created_at": datetime.now(timezone.utc).isoformat(),
                            },
                        }
                    )
                await self._emit_event(
                    {
                        "type": "token",
                        "content": str((event or {}).get("content") or ""),
                        "accumulated": assistant_content,
                    }
                )
                if assistant_message_id is not None:
                    self._session_store.update_message_content(assistant_message_id, content=assistant_content)
                    self._update_working_message_content(working_messages, assistant_message_id, assistant_content)
            elif event_type == "tool_call":
                request = self._tool_request_from_event(event, fallback_index=len(tool_requests) + 1)
                if request is None:
                    continue
                if self._event_sink is not None and not assistant_stream_started:
                    assistant_stream_started = True
                    await self._emit_event(
                        {
                            "type": "assistant_start",
                            "message": {
                                "id": assistant_stream_placeholder_id,
                                "session_id": session_id,
                                "sequence": assistant_stream_sequence,
                                "role": "assistant",
                                "content": "",
                                "metadata": {"kind": "direct_audit_assistant_message", "streaming": True},
                                "payload": {},
                                "created_at": datetime.now(timezone.utc).isoformat(),
                            },
                        }
                    )
                if assistant_message_id is None:
                    assistant_message_id = self._append_streaming_assistant_message(
                        session_id=session_id,
                        working_messages=working_messages,
                        content=assistant_content,
                    )
                self._append_tool_use_message(session_id=session_id, working_messages=working_messages, request=request)
                tool_requests.append(request)
                if executor is not None:
                    executor.add_tool_call_request(request)
                    await executor.process_queue()
                    for update in executor.get_completed_updates():
                        tool_use_context = self._consume_executor_update(
                            session_id=session_id,
                            update=update,
                            working_messages=working_messages,
                            records=records,
                            tool_call_ids=tool_call_ids,
                            tool_result_message_ids=tool_result_message_ids,
                            tool_use_context=tool_use_context,
                        )
            elif event_type == "done":
                stream_done = dict(event or {})
                assistant_content = str(stream_done.get("content") or assistant_content)
                if assistant_message_id is None and assistant_content:
                    assistant_message_id = self._append_streaming_assistant_message(
                        session_id=session_id,
                        working_messages=working_messages,
                        content=assistant_content,
                    )
                elif assistant_message_id is not None:
                    self._session_store.update_message_content(assistant_message_id, content=assistant_content)
                    self._update_working_message_content(working_messages, assistant_message_id, assistant_content)
                for item in stream_done.get("tool_calls") or []:
                    request = ToolCallRequest(
                        id=item.get("id") or f"tool-use-{len(tool_requests) + 1}",
                        name=item["name"],
                        input=dict(item.get("input") or {}),
                    )
                    if any(existing.id == request.id for existing in tool_requests):
                        continue
                    self._append_tool_use_message(session_id=session_id, working_messages=working_messages, request=request)
                    tool_requests.append(request)
                    if executor is not None:
                        executor.add_tool_call_request(request)
                        await executor.process_queue()
                        for update in executor.get_completed_updates():
                            tool_use_context = self._consume_executor_update(
                                session_id=session_id,
                                update=update,
                                working_messages=working_messages,
                                records=records,
                                tool_call_ids=tool_call_ids,
                                tool_result_message_ids=tool_result_message_ids,
                                tool_use_context=tool_use_context,
                            )
            elif event_type == "llm_retry":
                await self._emit_event(
                    {
                        "type": "llm_retry",
                        "attempt": int(event.get("attempt") or 0),
                        "max_attempts": int(event.get("max_attempts") or 0),
                        "message_text": str(event.get("message_text") or "模型服务暂时不可用，正在自动重试。"),
                        "error_type": str(event.get("error_type") or "").strip() or None,
                    }
                )
            elif event_type == "error":
                raise RuntimeError(str(event.get("user_message") or event.get("error") or "Streaming failed"))
        if executor is not None:
            async for update in executor.get_remaining_updates():
                tool_use_context = self._consume_executor_update(
                    session_id=session_id,
                    update=update,
                    working_messages=working_messages,
                    records=records,
                    tool_call_ids=tool_call_ids,
                    tool_result_message_ids=tool_result_message_ids,
                    tool_use_context=tool_use_context,
                )
            tool_use_context = executor.get_updated_context()
        model_response = self._normalize_model_response(
            {
                "content": assistant_content,
                "tool_calls": [{"id": request.id, "name": request.name, "input": request.input} for request in tool_requests],
                "stop_reason": (stream_done or {}).get("stop_reason") or RuntimeStopReason.COMPLETED.value,
                "recoverable_error_kind": (stream_done or {}).get("recoverable_error_kind"),
                "recoverable_error_message": (stream_done or {}).get("recoverable_error_message"),
                "usage": dict((stream_done or {}).get("usage") or {}),
            }
        )
        if assistant_message_id is not None:
            assistant_message = self._session_store.get_message(assistant_message_id)
            if assistant_message is not None:
                if not assistant_stream_started:
                    await self._emit_event(
                        {
                            "type": "assistant_start",
                            "message": {
                                "id": assistant_stream_placeholder_id,
                                "session_id": session_id,
                                "sequence": assistant_message.sequence,
                                "role": "assistant",
                                "content": "",
                                "metadata": {"kind": "direct_audit_assistant_message", "streaming": True},
                                "payload": {},
                                "created_at": assistant_message.created_at.isoformat(),
                            },
                        }
                    )
                    if assistant_message.content:
                        await self._emit_event(
                            {
                                "type": "token",
                                "content": assistant_message.content,
                                "accumulated": assistant_message.content,
                            }
                        )
                await self._emit_event(
                    {
                        "type": "done",
                        "message": {
                            "id": assistant_message.id,
                            "session_id": assistant_message.session_id,
                            "sequence": assistant_message.sequence,
                            "role": assistant_message.role,
                            "content": assistant_message.content,
                            "metadata": dict(assistant_message.message_metadata or {}),
                            "payload": dict(assistant_message.payload or {}),
                            "created_at": assistant_message.created_at.isoformat(),
                        },
                        "usage": dict(model_response.usage or {}),
                    }
                )
        legacy_text_tool_calls: list[dict[str, object]] = []
        if not tool_requests and model_response.content and tool_definitions and self._tool_orchestrator is not None:
            raw_tool_calls = self._extract_text_tool_calls(model_response.content)
            if self.ALLOW_LEGACY_TEXT_TOOL_CALLS:
                for index, item in enumerate(raw_tool_calls, start=1):
                    tool_requests.append(
                        ToolCallRequest(
                            id=item.get("id") or f"tool-use-{index}",
                            name=item["name"],
                            input=dict(item.get("input") or {}),
                        )
                    )
            else:
                legacy_text_tool_calls = list(raw_tool_calls)
        return {
            "model_response": model_response,
            "assistant_message_id": assistant_message_id,
            "working_messages": working_messages,
            "tool_requests": tool_requests,
            "tool_result_message_ids": tool_result_message_ids,
            "tool_call_ids": tool_call_ids,
            "records": records,
            "tool_use_context": tool_use_context,
            "tool_uses_appended": bool(tool_requests and assistant_message_id is not None),
            "legacy_text_tool_calls": legacy_text_tool_calls,
        }

    def _consume_executor_update(
        self,
        *,
        session_id: str,
        update,
        working_messages: list[TranscriptItem],
        records: list,
        tool_call_ids: list[str],
        tool_result_message_ids: list[str],
        tool_use_context: dict[str, Any],
    ) -> dict[str, Any]:
        if update.kind == "progress" and update.progress_payload is not None:
            progress_item = self._build_tool_progress_item(update)
            self._session_store.append_message(session_id, progress_item)
            working_messages.append(progress_item)
            return tool_use_context
        if update.kind == "context" and update.new_context is not None:
            return dict(update.new_context)
        if update.kind != "record" or update.record is None:
            return tool_use_context
        record = update.record
        records.append(record)
        tool_call_ids.append(record.tool_call_id)
        tool_result_item = TranscriptItem(
            role=RuntimeMessageRole.TOOL_RESULT,
            content=record.result.content,
            name=record.request.name,
            metadata={
                "status": record.status,
                "is_error": record.result.is_error,
                "duration_ms": record.duration_ms,
            },
            payload={
                "tool_use_id": record.request.id,
                "tool_call_id": record.tool_call_id,
                "tool_name": record.request.name,
                "input": record.request.input,
                "output": record.result.output_payload,
                "error_message": record.error_message,
            },
        )
        tool_result_message_ids.append(self._session_store.append_message(session_id, tool_result_item))
        working_messages.append(tool_result_item)
        return tool_use_context

    @staticmethod
    def _extract_finalize_payload(records) -> dict[str, Any] | None:
        for record in records or []:
            result = getattr(record, "result", None)
            if result is None or getattr(result, "is_error", False):
                continue
            payload = dict(getattr(result, "output_payload", {}) or {})
            final_payload = payload.get("final_payload")
            if isinstance(final_payload, dict):
                return dict(final_payload)
        return None

    @staticmethod
    def _extract_finalize_terminal_action(records) -> RuntimeTerminalAction:
        for record in records or []:
            result = getattr(record, "result", None)
            if result is None or getattr(result, "is_error", False):
                continue
            payload = dict(getattr(result, "output_payload", {}) or {})
            if not isinstance(payload.get("final_payload"), dict):
                continue
            raw_action = str(payload.get("terminal_action") or "").strip()
            if raw_action:
                try:
                    return RuntimeTerminalAction(raw_action)
                except ValueError:
                    pass
            tool_name = str(getattr(getattr(record, "request", None), "name", "") or "")
            if tool_name == "FinalizeTriageBatch":
                return RuntimeTerminalAction.FINALIZE_TRIAGE_BATCH
            if tool_name == "FinalizeTriage":
                return RuntimeTerminalAction.FINALIZE_TRIAGE
        return RuntimeTerminalAction.FINALIZE_FINDING

    def _should_issue_terminal_action_nudge(
        self,
        *,
        state: QueryLoopState,
        model_response: RuntimeModelResponse,
        tool_definitions: list[dict[str, Any]],
        continue_intent_without_action: bool,
    ) -> bool:
        if not tool_definitions:
            return False
        if model_response.native_tool_call_count or model_response.has_terminal_tool_call:
            return False
        nudge_count = int((state.tool_use_context or {}).get("missing_terminal_action_nudge_count") or 0)
        if nudge_count >= self._terminal_action_nudge_limit:
            return False
        return self._require_terminal_action or continue_intent_without_action

    @classmethod
    def _should_issue_legacy_tool_syntax_nudge(
        cls,
        *,
        state: QueryLoopState,
    ) -> bool:
        nudge_count = int((state.tool_use_context or {}).get("legacy_text_tool_call_nudge_count") or 0)
        return nudge_count < 1

    @classmethod
    def _has_continue_intent_without_action(
        cls,
        *,
        model_response: RuntimeModelResponse,
        tool_definitions: list[dict[str, Any]],
    ) -> bool:
        if not tool_definitions:
            return False
        if model_response.native_tool_call_count or model_response.has_terminal_tool_call:
            return False
        text = str(model_response.content or "").strip()
        if not text:
            return False
        return any(pattern.search(text) for pattern in cls._CONTINUE_INTENT_PATTERNS)

    def _append_streaming_assistant_message(self, *, session_id: str, working_messages: list[TranscriptItem], content: str) -> str:
        assistant_item = TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content=content)
        message_id = self._session_store.append_message(session_id, assistant_item)
        assistant_item.payload = {"message_id": message_id}
        working_messages.append(assistant_item)
        return message_id

    @staticmethod
    def _update_working_message_content(working_messages: list[TranscriptItem], message_id: str, content: str) -> None:
        for item in reversed(working_messages):
            if item.role is RuntimeMessageRole.ASSISTANT and item.payload.get("message_id") == message_id:
                item.content = content
                return

    def _append_tool_use_message(self, *, session_id: str, working_messages: list[TranscriptItem], request: ToolCallRequest) -> None:
        tool_use_item = TranscriptItem(
            role=RuntimeMessageRole.TOOL_USE,
            content=request.name,
            name=request.name,
            payload={"tool_use_id": request.id, "tool_name": request.name, "input": request.input},
        )
        self._session_store.append_message(session_id, tool_use_item)
        working_messages.append(tool_use_item)

    @staticmethod
    def _tool_request_from_event(event: dict[str, Any], *, fallback_index: int) -> ToolCallRequest | None:
        tool_call = dict((event or {}).get("tool_call") or {})
        name = str(tool_call.get("name") or "").strip()
        if not name:
            return None
        return ToolCallRequest(
            id=str(tool_call.get("id") or f"tool-use-{fallback_index}"),
            name=name,
            input=dict(tool_call.get("input") or {}),
        )

    @staticmethod
    def _build_tool_progress_item(update) -> TranscriptItem:
        payload = dict(update.progress_payload or {})
        message = str(payload.get("message") or payload.get("event") or "Tool progress")
        return TranscriptItem(
            role=RuntimeMessageRole.SYSTEM,
            content=message,
            name="tool_progress",
            metadata={"synthetic": True, "kind": "tool_progress", "hidden_from_model": True},
            payload=payload,
        )

    def _persist_runtime_hook_events(
        self,
        *,
        session_id: str,
        turn_id: str,
        hook_events: list[dict[str, object]],
    ) -> None:
        for event in hook_events:
            payload = {"kind": "runtime_hook", **dict(event or {})}
            self._session_store.create_checkpoint(
                session_id=session_id,
                turn_id=turn_id,
                checkpoint_type=AuditCheckpointType.AUTO,
                state_payload=payload,
            )

    def _write_checkpoint(
        self,
        *,
        session_id: str,
        turn_id: str,
        stop_reason: RuntimeStopReason | None,
        transition: RuntimeContinueReason | None,
        assistant_message_id: str | None,
        tool_call_ids: list[str],
        ignored_tool_calls: list[str] | None = None,
        extra_state_payload: dict[str, object] | None = None,
    ) -> None:
        payload = {
            "stop_reason": stop_reason.value if stop_reason is not None else None,
            "transition": transition.value if transition is not None else None,
            "assistant_message_id": assistant_message_id,
            "tool_call_ids": list(tool_call_ids),
        }
        if ignored_tool_calls is not None:
            payload["ignored_tool_calls"] = list(ignored_tool_calls)
        if extra_state_payload:
            payload.update(dict(extra_state_payload))
        self._session_store.create_checkpoint(
            session_id=session_id,
            turn_id=turn_id,
            checkpoint_type=AuditCheckpointType.AUTO,
            state_payload=payload,
        )

    @staticmethod
    def _coerce_stop_reason(value: str | None) -> RuntimeStopReason:
        if not value:
            return RuntimeStopReason.COMPLETED
        normalized = str(value).strip()
        aliases = {
            "assistant_turn_complete": RuntimeStopReason.COMPLETED,
            "user_follow_up_required": RuntimeStopReason.COMPLETED,
            "model_stop": RuntimeStopReason.COMPLETED,
            "tool_execution_continue": RuntimeStopReason.COMPLETED,
            "max_turns_exceeded": RuntimeStopReason.MAX_TURNS,
            "stop": RuntimeStopReason.COMPLETED,
        }
        if normalized in aliases:
            return aliases[normalized]
        try:
            return RuntimeStopReason(normalized)
        except ValueError:
            return RuntimeStopReason.COMPLETED

    @staticmethod
    def _extract_text_tool_calls(content: str) -> list[dict[str, object]]:
        text = (content or '').strip()
        if not text:
            return []

        tool_call_match = re.search(r'Tool Call:\s*([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$', text, re.DOTALL)
        if tool_call_match:
            tool_name = tool_call_match.group(1).strip()
            payload_text = tool_call_match.group(2).strip()
            parsed_payload = AgentJsonParser.parse_any(payload_text, default={})
            tool_input = QueryLoop._extract_tool_input_from_payload(parsed_payload)
            return [{'id': 'text-tool-call-1', 'name': tool_name, 'input': tool_input}]

        action_match = re.search(r'Action:\s*([A-Za-z_][A-Za-z0-9_]*)\s*Action Input:\s*(.*)$', text, re.DOTALL)
        if action_match:
            tool_name = action_match.group(1).strip()
            parsed_payload = AgentJsonParser.parse_any(action_match.group(2).strip(), default={})
            tool_input = QueryLoop._extract_tool_input_from_payload(parsed_payload)
            if tool_input:
                return [{'id': 'text-tool-call-1', 'name': tool_name, 'input': tool_input}]
        return []

    @staticmethod
    def _extract_tool_input_from_payload(parsed_payload: object) -> dict[str, object]:
        if isinstance(parsed_payload, dict) and isinstance(parsed_payload.get('input'), dict):
            return dict(parsed_payload.get('input') or {})
        if isinstance(parsed_payload, dict):
            return dict(parsed_payload)
        if isinstance(parsed_payload, list):
            for item in parsed_payload:
                tool_input = QueryLoop._extract_tool_input_from_payload(item)
                if tool_input:
                    return tool_input
        return {}











