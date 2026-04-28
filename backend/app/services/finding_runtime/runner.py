from __future__ import annotations

from app.services.finding_runtime.models import (
    RuntimeCompletionMode,
    RuntimeSessionState,
    RuntimeStopReason,
    RuntimeTerminalAction,
    TurnExecutionResult,
)
from app.services.finding_runtime.query_loop import QueryLoop

COMPLETED_SESSION_STOP_REASONS = {
    RuntimeStopReason.COMPLETED,
    RuntimeStopReason.HOOK_STOPPED,
}


class FindingRuntimeRunner:
    def __init__(
        self,
        *,
        session_store,
        model_client,
        tool_registry=None,
        tool_orchestrator=None,
        max_turns: int | None = None,
        event_sink=None,
        require_terminal_action: bool = False,
        terminal_action_nudge_limit: int = 1,
    ):
        self._session_store = session_store
        self._max_turns = max_turns
        self._query_loop = QueryLoop(
            session_store=session_store,
            model_client=model_client,
            tool_registry=tool_registry,
            tool_orchestrator=tool_orchestrator,
            event_sink=event_sink,
            require_terminal_action=require_terminal_action,
            terminal_action_nudge_limit=terminal_action_nudge_limit,
        )

    async def run_once(self, *, session_id: str, model_name: str) -> TurnExecutionResult:
        self._session_store.update_session_state(session_id, RuntimeSessionState.RUNNING)
        last_result: TurnExecutionResult | None = None
        turns_executed = 0
        try:
            while self._max_turns is None or turns_executed < self._max_turns:
                last_result = await self._query_loop.run_turn(session_id=session_id, model_name=model_name)
                turns_executed += 1
                if last_result.transition is None:
                    if last_result.stop_reason is None:
                        last_result.stop_reason = RuntimeStopReason.COMPLETED
                    session_state = (
                        RuntimeSessionState.COMPLETED
                        if (
                            last_result.stop_reason in COMPLETED_SESSION_STOP_REASONS
                            and last_result.completion_mode is not RuntimeCompletionMode.INCOMPLETE
                        )
                        else RuntimeSessionState.FAILED
                    )
                    self._session_store.update_session_state(session_id, session_state)
                    return last_result
            self._session_store.update_session_state(session_id, RuntimeSessionState.FAILED)
            return TurnExecutionResult(
                turn_id=last_result.turn_id if last_result is not None else "",
                stop_reason=RuntimeStopReason.MAX_TURNS,
                assistant_message_id=last_result.assistant_message_id if last_result is not None else None,
                tool_call_ids=list(last_result.tool_call_ids) if last_result is not None else [],
                tool_result_message_ids=list(last_result.tool_result_message_ids) if last_result is not None else [],
                transition=None,
                terminal_action=RuntimeTerminalAction.MAX_TURNS,
                completion_mode=RuntimeCompletionMode.INCOMPLETE,
            )
        except Exception:
            self._session_store.update_session_state(session_id, RuntimeSessionState.FAILED)
            raise
