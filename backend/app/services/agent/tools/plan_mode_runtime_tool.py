from __future__ import annotations

from pydantic import BaseModel

from app.services.finding_runtime.models import ToolExecutionPayload
from app.services.runtime_core.interaction_runtime import InteractionRuntime
from app.services.runtime_core.tool_runtime import RuntimeTool, ToolExecutionContext


class PlanModeInput(BaseModel):
    reason: str | None = None


class EnterPlanModeRuntimeTool(RuntimeTool):
    name = "EnterPlanMode"
    description = "让当前会话进入共享计划模式"
    input_model = PlanModeInput
    should_defer = True
    always_load = True
    search_hint = "进入计划模式"

    def __init__(self, session_store):
        super().__init__()
        self._session_store = session_store
        self._interaction_runtime = InteractionRuntime()

    async def execute(self, parsed_input: PlanModeInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        runtime_state = self._session_store.load_runtime_state(context.session_id)
        plan_state = self._interaction_runtime.enter_plan_mode(
            runtime_state,
            agent_type=context.agent_type,
            reason=parsed_input.reason,
        )
        self._session_store.replace_runtime_state(context.session_id, runtime_state)
        return ToolExecutionPayload(
            content="计划模式已启用",
            output_payload={"plan_mode": plan_state},
            metadata={"interaction": "plan_mode_enter"},
        )


class ExitPlanModeRuntimeTool(RuntimeTool):
    name = "ExitPlanMode"
    description = "让当前会话退出共享计划模式"
    input_model = PlanModeInput
    should_defer = True
    always_load = True
    search_hint = "退出计划模式"

    def __init__(self, session_store):
        super().__init__()
        self._session_store = session_store
        self._interaction_runtime = InteractionRuntime()

    async def execute(self, parsed_input: PlanModeInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        runtime_state = self._session_store.load_runtime_state(context.session_id)
        plan_state = self._interaction_runtime.exit_plan_mode(
            runtime_state,
            agent_type=context.agent_type,
            reason=parsed_input.reason,
        )
        self._session_store.replace_runtime_state(context.session_id, runtime_state)
        return ToolExecutionPayload(
            content="计划模式已关闭",
            output_payload={"plan_mode": plan_state},
            metadata={"interaction": "plan_mode_exit"},
        )
