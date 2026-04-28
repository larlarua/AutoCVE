import asyncio

import pytest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from app.services.agent.agents.analysis import AnalysisAgent
from app.services.agent.agents.analysis_workflow import AnalysisWorkflowAgent
from app.services.agent.agents.base import AgentConfig, AgentPattern, AgentResult, AgentType
from app.services.agent.agents.recon import RECON_OUTPUT_CONTRACT, RECON_SYSTEM_PROMPT, ReconAgent
from app.services.agent.tools.base import AgentTool, ToolResult
from app.services.agent.tools.interaction_agent_tools import AskUserTool, EnterPlanModeTool, ExitPlanModeTool, TodoWriteTool
from app.services.finding_runtime.models import RuntimeMemoryBundle, RuntimeMemoryRecord
from app.services.runtime_core.session_registry import runtime_session_registry


class DummyWorkflowAgent(AnalysisWorkflowAgent):
    def __init__(self, tools=None):
        llm_service = MagicMock()
        llm_service.chat_completion_stream = MagicMock()
        super().__init__(
            name="Dummy",
            agent_type=AgentType.ANALYSIS,
            llm_service=llm_service,
            tools=tools or {},
            event_emitter=MagicMock(),
            system_prompt="dummy",
            max_iterations=1,
        )

    def _build_initial_message(self, context):
        return "dummy"


class ConcurrencyProbeTool(AgentTool):
    def __init__(
        self,
        tool_name: str,
        tracker: dict[str, int],
        *,
        concurrency_safe: bool = True,
        concurrency_key: str | None = None,
        delay: float = 0.05,
    ):
        super().__init__()
        self._tool_name = tool_name
        self._tracker = tracker
        self._concurrency_safe = concurrency_safe
        self._concurrency_key = concurrency_key
        self._delay = delay

    @property
    def name(self) -> str:
        return self._tool_name

    @property
    def description(self) -> str:
        return f"Probe tool {self._tool_name}"

    def is_concurrency_safe(self, **kwargs) -> bool:
        del kwargs
        return self._concurrency_safe

    def concurrency_key(self, **kwargs) -> str | None:
        del kwargs
        return self._concurrency_key

    async def _execute(self, value: str = "", **kwargs) -> ToolResult:
        del kwargs
        self._tracker["active"] = self._tracker.get("active", 0) + 1
        self._tracker["max_active"] = max(self._tracker.get("max_active", 0), self._tracker["active"])
        try:
            await asyncio.sleep(self._delay)
        finally:
            self._tracker["active"] -= 1
        return ToolResult(success=True, data=f"{self._tool_name}:{value}")


class ReadOnlyProbeTool(AgentTool):
    @property
    def name(self) -> str:
        return "read_only_probe"

    @property
    def description(self) -> str:
        return "Read-only probe tool"

    def is_read_only(self, **kwargs) -> bool:
        del kwargs
        return True

    async def _execute(self, value: str = "", **kwargs) -> ToolResult:
        del kwargs
        return ToolResult(success=True, data=f"read-only:{value}")


def setup_function():
    runtime_session_registry.clear()


class TestReconAgent:
    @pytest.fixture
    def recon_agent(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        return ReconAgent(
            llm_service=mock_llm_service,
            tools={},
            event_emitter=mock_event_emitter,
        )

    def test_recon_agent_normalizes_navigation_contract(self, recon_agent):
        result = recon_agent._normalize_recon_result(
            {
                "tech_stack": {"languages": ["Python"], "frameworks": ["Flask"]},
                "high_risk_areas": ["src/api.py"],
                "recommended_tools": {"must_use": ["semgrep_scan"], "recommended": ["bandit_scan"]},
            },
            config={"target_files": ["src/api.py"]},
        )

        assert result["project_profile"]["languages"] == ["Python"]
        assert result["priority_paths"] == ["src/api.py"]
        assert result["recommended_scanners"]["must_use"] == ["semgrep_scan"]
        assert result["audit_targets"]["target_files"] == ["src/api.py"]

    def test_recon_agent_summary_fallback_returns_new_schema(self, recon_agent):
        recon_agent._steps = [
            SimpleNamespace(
                thought="found flask routes",
                observation="requirements.txt\nsrc/api.py\nflask\nsqlite\n",
            )
        ]

        result = recon_agent._summarize_from_steps(config={"target_files": ["src/api.py"]})

        assert "project_profile" in result
        assert "priority_paths" in result
        assert "audit_targets" in result
        assert "recommended_scanners" in result
        assert "tech_stack" not in result

    def test_recon_prompt_and_contract_only_advertise_canonical_schema(self):
        joined = f"{RECON_SYSTEM_PROMPT}\n{RECON_OUTPUT_CONTRACT}"

        assert "project_profile" in joined
        assert "priority_paths" in joined
        assert "audit_targets" in joined
        assert "recommended_scanners" in joined
        assert "tech_stack" not in joined
        assert "recommended_tools" not in joined
        assert "high_risk_areas" not in joined
        assert "initial_findings" not in joined


class TestAnalysisAgent:
    @pytest.fixture
    def analysis_agent(self, temp_project_dir, mock_llm_service, mock_event_emitter):
        from app.services.agent.tools import FileReadTool, FileSearchTool, PatternMatchTool

        tools = {
            "read_file": FileReadTool(temp_project_dir),
            "search_code": FileSearchTool(temp_project_dir),
            "pattern_match": PatternMatchTool(temp_project_dir),
        }

        return AnalysisAgent(
            llm_service=mock_llm_service,
            tools=tools,
            event_emitter=mock_event_emitter,
        )

    def test_analysis_agent_instantiates(self, analysis_agent):
        assert analysis_agent.name == "Analysis"

    def test_analysis_agent_preserves_tooling(self, analysis_agent):
        assert set(analysis_agent.tools.keys()) == {"read_file", "search_code", "pattern_match"}

    def test_analysis_agent_read_only_tools_advertise_concurrency_safety(self, analysis_agent):
        assert analysis_agent.tools["read_file"].is_concurrency_safe(file_path="src/api.py") is True
        assert analysis_agent.tools["search_code"].is_concurrency_safe(keyword="auth") is True
        assert analysis_agent.tools["pattern_match"].is_concurrency_safe(scan_file="src/api.py") is True


class TestAgentResult:
    def test_agent_result_success(self):
        result = AgentResult(
            success=True,
            data={"findings": []},
            iterations=5,
            tool_calls=10,
        )

        assert result.success is True
        assert result.iterations == 5
        assert result.tool_calls == 10

    def test_agent_result_failure(self):
        result = AgentResult(
            success=False,
            error="Test error",
        )

        assert result.success is False
        assert result.error == "Test error"

    def test_agent_result_to_dict(self):
        result = AgentResult(
            success=True,
            data={"key": "value"},
            iterations=3,
        )

        data = result.to_dict()

        assert data["success"] is True
        assert data["iterations"] == 3


class TestAgentConfig:
    def test_agent_config_defaults(self):
        config = AgentConfig(
            name="Test",
            agent_type=AgentType.RECON,
        )

        assert config.pattern == AgentPattern.REACT
        assert config.max_iterations == 20
        assert config.temperature == 0.1

    def test_agent_config_custom(self):
        config = AgentConfig(
            name="Custom",
            agent_type=AgentType.ANALYSIS,
            pattern=AgentPattern.PLAN_AND_EXECUTE,
            max_iterations=50,
            temperature=0.5,
        )

        assert config.pattern == AgentPattern.PLAN_AND_EXECUTE
        assert config.max_iterations == 50
        assert config.temperature == 0.5


class TestLegacyAnalysisWorkflowConcurrency:
    @pytest.mark.asyncio
    async def test_executes_concurrency_safe_batch_actions_in_parallel(self):
        tracker = {"active": 0, "max_active": 0}
        agent = DummyWorkflowAgent(
            tools={
                "read_a": ConcurrencyProbeTool("read_a", tracker),
                "read_b": ConcurrencyProbeTool("read_b", tracker),
            }
        )
        agent.emit_llm_action = AsyncMock()
        step = type("Step", (), {})()
        step.actions = [
            type("Invocation", (), {"action": "read_a", "action_input": {"value": "alpha"}})(),
            type("Invocation", (), {"action": "read_b", "action_input": {"value": "beta"}})(),
        ]

        observation = await agent._execute_step_actions(step, failed_tool_calls={})

        assert tracker["max_active"] == 2
        assert "read_a:alpha" in observation
        assert "read_b:beta" in observation

    @pytest.mark.asyncio
    async def test_serializes_conflicting_concurrency_safe_actions(self):
        tracker = {"active": 0, "max_active": 0}
        agent = DummyWorkflowAgent(
            tools={
                "read_a": ConcurrencyProbeTool("read_a", tracker, concurrency_key="src/api.py"),
                "read_b": ConcurrencyProbeTool("read_b", tracker, concurrency_key="src/api.py"),
            }
        )
        agent.emit_llm_action = AsyncMock()
        step = type("Step", (), {})()
        step.actions = [
            type("Invocation", (), {"action": "read_a", "action_input": {"value": "alpha"}})(),
            type("Invocation", (), {"action": "read_b", "action_input": {"value": "beta"}})(),
        ]

        observation = await agent._execute_step_actions(step, failed_tool_calls={})

        assert tracker["max_active"] == 1
        assert "read_a:alpha" in observation
        assert "read_b:beta" in observation


class TestLegacyInteractionAgentTools:
    @pytest.fixture
    def recon_agent_with_interactions(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        return ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "TodoWrite": TodoWriteTool(),
                "AskUser": AskUserTool(),
                "EnterPlanMode": EnterPlanModeTool(),
                "ExitPlanMode": ExitPlanModeTool(),
            },
            event_emitter=mock_event_emitter,
        )

    @pytest.mark.asyncio
    async def test_legacy_todo_tool_records_agent_scoped_todos(self, recon_agent_with_interactions):
        result = await recon_agent_with_interactions.execute_tool(
            "TodoWrite",
            {"title": "Review auth middleware", "details": "Trace admin bypass guards"},
        )

        interaction_state = recon_agent_with_interactions.state.metadata["interaction_runtime"]

        assert "Review auth middleware" in result
        assert interaction_state["pending_todos"][0]["title"] == "Review auth middleware"
        assert interaction_state["pending_todos"][0]["details"] == "Trace admin bypass guards"

    @pytest.mark.asyncio
    async def test_legacy_ask_user_tool_puts_agent_into_waiting_state(self, recon_agent_with_interactions):
        result = await recon_agent_with_interactions.execute_tool(
            "AskUser",
            {"question": "Can we use staging credentials?", "context": {"reason": "verification"}},
        )

        interaction_state = recon_agent_with_interactions.state.metadata["interaction_runtime"]

        assert "Can we use staging credentials?" in result
        assert recon_agent_with_interactions.state.waiting_for_input is True
        assert recon_agent_with_interactions.state.status == "waiting"
        assert interaction_state["pending_questions"][0]["question"] == "Can we use staging credentials?"
        assert interaction_state["pending_questions"][0]["context"] == {"reason": "verification"}
        assert interaction_state["questions"][interaction_state["pending_questions"][0]["id"]]["status"] == "pending"

    @pytest.mark.asyncio
    async def test_legacy_plan_mode_tools_toggle_agent_plan_state(self, recon_agent_with_interactions):
        await recon_agent_with_interactions.execute_tool(
            "EnterPlanMode",
            {"reason": "Need user approval before mutation"},
        )
        enter_state = recon_agent_with_interactions.state.metadata["interaction_runtime"]["plan_mode"].copy()
        enter_permission_mode = recon_agent_with_interactions.state.metadata["interaction_runtime"]["permission_mode"]

        result = await recon_agent_with_interactions.execute_tool(
            "ExitPlanMode",
            {"reason": "Approval captured"},
        )
        exit_state = recon_agent_with_interactions.state.metadata["interaction_runtime"]["plan_mode"]
        exit_permission_mode = recon_agent_with_interactions.state.metadata["interaction_runtime"]["permission_mode"]

        assert enter_state["active"] is True
        assert enter_state["entered_by"] == recon_agent_with_interactions.agent_id
        assert enter_state["reason"] == "Need user approval before mutation"
        assert enter_permission_mode == "plan"
        assert "计划模式已关闭" in result
        assert exit_state["active"] is False
        assert exit_state["last_exit_reason"] == "Approval captured"
        assert exit_permission_mode == "default"


    @pytest.mark.asyncio
    async def test_legacy_plan_mode_blocks_non_read_only_tools_but_allows_read_only_ones(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "EnterPlanMode": EnterPlanModeTool(),
                "ExitPlanMode": ExitPlanModeTool(),
                "read_only_probe": ReadOnlyProbeTool(),
                "mutating_probe": ConcurrencyProbeTool("mutating_probe", {"active": 0, "max_active": 0}, concurrency_safe=False),
            },
            event_emitter=mock_event_emitter,
        )

        await agent.execute_tool("EnterPlanMode", {"reason": "Need approval"})
        denied = await agent.execute_tool("mutating_probe", {"value": "secret"})
        allowed = await agent.execute_tool("read_only_probe", {"value": "scan"})

        assert "blocked in plan mode" in denied.lower()
        assert allowed == "read-only:scan"


    @pytest.mark.asyncio
    async def test_legacy_permission_rules_can_require_ask_for_mutating_tools(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "mutating_probe": ConcurrencyProbeTool("mutating_probe", {"active": 0, "max_active": 0}, concurrency_safe=False),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["interaction_runtime"] = {
            "permission_mode": "default",
            "permission_rules": {
                "mutating_probe": {"mode": "ask", "reason": "Need human approval before mutation."}
            },
        }

        denied = await agent.execute_tool("mutating_probe", {"value": "secret"})

        assert "need human approval" in denied.lower()

    @pytest.mark.asyncio
    async def test_legacy_permission_rules_can_allow_specific_tool_even_in_plan_mode(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "mutating_probe": ConcurrencyProbeTool("mutating_probe", {"active": 0, "max_active": 0}, concurrency_safe=False),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["interaction_runtime"] = {
            "permission_mode": "plan",
            "permission_rules": {
                "mutating_probe": {"mode": "allow", "reason": "Pre-approved during this planning checkpoint."}
            },
        }

        allowed = await agent.execute_tool("mutating_probe", {"value": "secret"})

        assert allowed == "mutating_probe:secret"


    @pytest.mark.asyncio
    async def test_legacy_execute_tool_records_permission_denials_in_runtime_metadata(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "mutating_probe": ConcurrencyProbeTool("mutating_probe", {"active": 0, "max_active": 0}, concurrency_safe=False),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["interaction_runtime"] = {
            "permission_mode": "default",
            "permission_rules": {
                "mutating_probe": {"mode": "ask", "reason": "Need human approval before mutation."}
            },
        }

        await agent.execute_tool("mutating_probe", {"value": "secret"})

        runtime_records = agent.state.metadata["tool_runtime"]["records"]
        assert runtime_records[-1]["tool_name"] == "mutating_probe"
        assert runtime_records[-1]["status"] == "denied"
        assert runtime_records[-1]["permission_source"] == "permission_rule"
        assert runtime_records[-1]["permission_mode"] == "ask"

    @pytest.mark.asyncio
    async def test_legacy_execute_tool_records_completed_calls_in_runtime_metadata(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "read_only_probe": ReadOnlyProbeTool(),
            },
            event_emitter=mock_event_emitter,
        )

        result = await agent.execute_tool("read_only_probe", {"value": "scan"})

        runtime_records = agent.state.metadata["tool_runtime"]["records"]
        assert result == "read-only:scan"
        assert runtime_records[-1]["tool_name"] == "read_only_probe"
        assert runtime_records[-1]["status"] == "completed"
        assert runtime_records[-1]["duration_ms"] >= 0


    @pytest.mark.asyncio
    async def test_legacy_execute_tool_records_runtime_lifecycle_events_for_success(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "read_only_probe": ReadOnlyProbeTool(),
            },
            event_emitter=mock_event_emitter,
        )

        await agent.execute_tool("read_only_probe", {"value": "scan"})

        runtime_events = agent.state.metadata["tool_runtime"]["events"]
        assert [event["event"] for event in runtime_events[-2:]] == ["PreToolUse", "PostToolUse"]
        assert runtime_events[-2]["tool_name"] == "read_only_probe"
        assert runtime_events[-1]["tool_name"] == "read_only_probe"

    @pytest.mark.asyncio
    async def test_legacy_execute_tool_records_runtime_lifecycle_events_for_permission_denial(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "mutating_probe": ConcurrencyProbeTool("mutating_probe", {"active": 0, "max_active": 0}, concurrency_safe=False),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["interaction_runtime"] = {
            "permission_mode": "default",
            "permission_rules": {
                "mutating_probe": {"mode": "ask", "reason": "Need human approval before mutation."}
            },
        }

        await agent.execute_tool("mutating_probe", {"value": "secret"})

        runtime_events = agent.state.metadata["tool_runtime"]["events"]
        assert runtime_events[-1]["event"] == "PermissionDenied"
        assert runtime_events[-1]["tool_name"] == "mutating_probe"
        assert runtime_events[-1]["permission_source"] == "permission_rule"


    @pytest.mark.asyncio
    async def test_legacy_execute_tool_records_hook_matches_for_success_events(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "read_only_probe": ReadOnlyProbeTool(),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["tool_runtime"] = {
            "session_hooks": {
                "code-audit-finding": {
                    "PreToolUse": [{"matcher": "*", "hooks": ["log-pre"]}],
                    "PostToolUse": [{"matcher": "read_only_probe", "hooks": ["log-post"]}],
                }
            }
        }

        await agent.execute_tool("read_only_probe", {"value": "scan"})

        hook_records = agent.state.metadata["tool_runtime"]["hook_records"]
        assert [item["event"] for item in hook_records[-2:]] == ["PreToolUse", "PostToolUse"]
        assert hook_records[-1]["matched_hooks"][0]["hooks"] == ["log-post"]
        assert hook_records[-1]["skill_ref"] == "code-audit-finding"

    @pytest.mark.asyncio
    async def test_legacy_execute_tool_records_hook_matches_for_permission_denials(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "mutating_probe": ConcurrencyProbeTool("mutating_probe", {"active": 0, "max_active": 0}, concurrency_safe=False),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["tool_runtime"] = {
            "session_hooks": {
                "code-audit-finding": {
                    "PermissionDenied": [{"matcher": "*", "hooks": ["deny-log"]}],
                }
            }
        }
        agent.state.metadata["interaction_runtime"] = {
            "permission_mode": "default",
            "permission_rules": {
                "mutating_probe": {"mode": "ask", "reason": "Need human approval before mutation."}
            },
        }

        await agent.execute_tool("mutating_probe", {"value": "secret"})

        hook_records = agent.state.metadata["tool_runtime"]["hook_records"]
        assert hook_records[-1]["event"] == "PermissionDenied"
        assert hook_records[-1]["matched_hooks"][0]["hooks"] == ["deny-log"]
        assert hook_records[-1]["tool_name"] == "mutating_probe"


    @pytest.mark.asyncio
    async def test_legacy_execute_tool_records_checkpoint_style_view_for_hook_matches(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "read_only_probe": ReadOnlyProbeTool(),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["tool_runtime"] = {
            "session_hooks": {
                "code-audit-finding": {
                    "PostToolUse": [{"matcher": "read_only_probe", "hooks": ["log-post"]}],
                }
            }
        }

        await agent.execute_tool("read_only_probe", {"value": "scan"})

        checkpoints = agent.state.metadata["tool_runtime"]["checkpoints"]
        assert checkpoints[-1]["checkpoint_type"] == "auto"
        assert checkpoints[-1]["state_payload"]["event"] == "PostToolUse"
        assert checkpoints[-1]["state_payload"]["skill_ref"] == "code-audit-finding"
        assert checkpoints[-1]["state_payload"]["matched_hooks"][0]["hooks"] == ["log-post"]

    @pytest.mark.asyncio
    async def test_legacy_execute_tool_records_checkpoint_style_view_for_permission_rule_denial_without_hooks(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "mutating_probe": ConcurrencyProbeTool("mutating_probe", {"active": 0, "max_active": 0}, concurrency_safe=False),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["interaction_runtime"] = {
            "permission_mode": "default",
            "permission_rules": {
                "mutating_probe": {"mode": "ask", "reason": "Need human approval before mutation."}
            },
        }

        await agent.execute_tool("mutating_probe", {"value": "secret"})

        checkpoints = agent.state.metadata["tool_runtime"]["checkpoints"]
        assert checkpoints[-1]["checkpoint_type"] == "auto"
        assert checkpoints[-1]["state_payload"]["event"] == "PermissionDenied"
        assert checkpoints[-1]["state_payload"]["source"] == "permission_rule"
        assert checkpoints[-1]["state_payload"]["matched_hooks"] == []


    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_legacy_agent_can_restore_runtime_session_checkpoint_when_configured(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "TodoWrite": TodoWriteTool(),
            },
            event_emitter=mock_event_emitter,
        )
        checkpoint_store = AsyncMock()
        checkpoint_store.restore_agent_runtime_session_checkpoint = AsyncMock(return_value={"checkpoint_id": "cp-1"})
        agent.configure_runtime_session_persistence(task_id="task-1", checkpoint_store=checkpoint_store)

        restored = await agent.restore_runtime_session_from_checkpoint()

        assert restored == {"checkpoint_id": "cp-1"}
        checkpoint_store.restore_agent_runtime_session_checkpoint.assert_awaited_once()
        kwargs = checkpoint_store.restore_agent_runtime_session_checkpoint.await_args.kwargs
        assert kwargs["task_id"] == "task-1"
        assert kwargs["agent_state"] is agent.state

    @pytest.mark.asyncio
    async def test_legacy_execute_tool_persists_runtime_session_checkpoint_when_configured(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "TodoWrite": TodoWriteTool(),
            },
            event_emitter=mock_event_emitter,
        )
        checkpoint_store = AsyncMock()
        checkpoint_store.persist_agent_runtime_session_checkpoint = AsyncMock(return_value=SimpleNamespace(id="cp-1"))
        agent.configure_runtime_session_persistence(task_id="task-1", checkpoint_store=checkpoint_store)

        await agent.execute_tool("TodoWrite", {"title": "Review auth flow", "details": "Check tenant guard"})

        checkpoint_store.persist_agent_runtime_session_checkpoint.assert_awaited_once()
        kwargs = checkpoint_store.persist_agent_runtime_session_checkpoint.await_args.kwargs
        assert kwargs["task_id"] == "task-1"
        assert kwargs["agent_state"] is agent.state
        assert agent.state.metadata["runtime_session_ref"]["task_id"] == "task-1"

    async def test_legacy_execute_tool_syncs_session_runtime_state_view(self, mock_llm_service, mock_event_emitter):
        mock_llm_service.chat_completion_stream = MagicMock()
        agent = ReconAgent(
            llm_service=mock_llm_service,
            tools={
                "EnterPlanMode": EnterPlanModeTool(),
                "TodoWrite": TodoWriteTool(),
            },
            event_emitter=mock_event_emitter,
        )
        agent.state.metadata["interaction_runtime"] = {
            "permission_mode": "default",
            "permission_rules": {
                "mutating_probe": {"mode": "ask", "reason": "Need human approval before mutation."}
            },
        }
        agent.state.metadata["tool_runtime"] = {
            "session_hooks": {
                "code-audit-finding": {
                    "PostToolUse": [{"matcher": "TodoWrite", "hooks": ["log-post"]}]
                }
            }
        }

        await agent.execute_tool("EnterPlanMode", {"reason": "Need review before mutating state"})
        await agent.execute_tool("TodoWrite", {"title": "Review auth flow", "details": "Check tenant guard"})

        runtime_state = agent.state.metadata["runtime_session_state"]
        assert runtime_state["session_id"] == agent.agent_id
        assert runtime_state["permission_mode"] == "plan"
        assert runtime_state["agent_states"][agent.agent_type.value]["pending_todos"][0]["title"] == "Review auth flow"
        assert runtime_state["metadata"]["plan_mode"]["active"] is True
        assert runtime_state["metadata"]["permission_rules"]["mutating_probe"]["mode"] == "ask"
        assert runtime_state["metadata"]["session_hooks"]["code-audit-finding"]["PostToolUse"][0]["hooks"] == ["log-post"]
        assert runtime_state["metadata"]["tool_runtime"]["records"][-1]["tool_name"] == "TodoWrite"
        session_ref = agent.state.metadata["runtime_session_ref"]
        assert session_ref["source"] == "legacy"
        assert session_ref["agent_id"] == agent.agent_id
        assert runtime_session_registry.get(session_ref["session_key"])["runtime_state"]["permission_mode"] == "plan"


    async def test_legacy_agent_load_runtime_memory_bundle_updates_prompt_and_session_state(self, mock_llm_service, mock_event_emitter):
        agent = DummyWorkflowAgent()
        original_prompt = agent.config.system_prompt

        bundle = RuntimeMemoryBundle(
            instructions=[
                RuntimeMemoryRecord(
                    memory_kind="instruction",
                    title="Project rule",
                    source_type="project_memory",
                    source_ref="CLAUDE.md",
                    content="Focus authorization invariants.",
                    metadata={"scope": "project"},
                )
            ],
            recalls=[
                RuntimeMemoryRecord(
                    memory_kind="recall",
                    title="Checklist",
                    source_type="skill_reference",
                    source_ref="references/checklist.md",
                    content="Verify object ownership before updates.",
                    relevance_score=9,
                    metadata={"category": "reference"},
                )
            ],
        )

        agent.load_runtime_memory_bundle(bundle, source="task-bootstrap")

        memory_runtime = agent.state.metadata["memory_runtime"]
        assert memory_runtime["base_system_prompt"] == original_prompt
        assert memory_runtime["instructions"][0]["source_ref"] == "CLAUDE.md"
        assert memory_runtime["recalls"][0]["source_ref"] == "references/checklist.md"
        assert "## Runtime Memory OS" in agent.config.system_prompt
        assert "Focus authorization invariants." in agent.config.system_prompt
        assert agent.state.metadata["runtime_session_state"]["metadata"]["memory_runtime"]["source"] == "task-bootstrap"
