import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from app.services.agent.agents.analysis_workflow import AnalysisWorkflowAgent
from app.services.agent.agents.base import AgentType
from app.services.agent.agents.finding import FindingAgent
from app.services.agent.agents.finding_skill_preloader import PreloadedSkillContext
from app.services.agent.agents.analysis_workflow import ToolInvocation
from app.services.agent.tools.base import AgentTool, ToolResult
from app.services.agent.tools.thinking_tool import ReflectTool, ThinkTool
from app.services.finding_runtime.models import RuntimeCompletionMode, RuntimeStopReason, TurnExecutionResult


class DummyWorkflowAgent(AnalysisWorkflowAgent):
    def __init__(self, tools=None):
        llm_service = MagicMock()
        llm_service.chat_completion_stream = MagicMock()
        super().__init__(
            name="Dummy",
            agent_type=AgentType.FINDING,
            llm_service=llm_service,
            tools=tools or {},
            event_emitter=MagicMock(),
            system_prompt="dummy",
            max_iterations=2,
        )

    def _build_initial_message(self, context):
        return "dummy"


class EchoTool(AgentTool):
    def __init__(self, tool_name: str):
        super().__init__()
        self._tool_name = tool_name

    @property
    def name(self) -> str:
        return self._tool_name

    @property
    def description(self) -> str:
        return f"Echo tool {self._tool_name}"

    async def _execute(self, value: str = "", **kwargs) -> ToolResult:
        return ToolResult(success=True, data=f"{self._tool_name}:{value}")


class PathEchoTool(AgentTool):
    def __init__(self, tool_name: str):
        super().__init__()
        self._tool_name = tool_name

    @property
    def name(self) -> str:
        return self._tool_name

    @property
    def description(self) -> str:
        return f"Path echo tool {self._tool_name}"

    async def _execute(self, file_path: str = "", file_paths=None, **kwargs) -> ToolResult:
        if file_paths:
            rendered = ",".join(file_paths)
        else:
            rendered = file_path
        return ToolResult(success=True, data=f"{self._tool_name}:{rendered}")


def test_analysis_workflow_parses_action_batch_payload():
    agent = DummyWorkflowAgent()

    step = agent._parse_llm_response(
        """Thought: inspect multiple directories first
Action Batch:
[
  {"action": "list_files", "action_input": {"directory": "src", "max_depth": 2}},
  {"action": "list_files", "action_input": {"directory": "config", "max_depth": 1}}
]"""
    )

    assert step.thought == "inspect multiple directories first"
    assert [item.action for item in step.actions] == ["list_files", "list_files"]
    assert step.actions[0].action_input == {"directory": "src", "max_depth": 2}
    assert step.actions[1].action_input == {"directory": "config", "max_depth": 1}


def test_analysis_workflow_parses_textual_structured_tool_calls():
    agent = DummyWorkflowAgent()

    step = agent._build_step_from_structured_response(
        'Tool Calls:\n- think({"category":"evaluation","thought":"Need one more pass"})',
        [],
    )

    assert [item.action for item in step.actions] == ["think"]
    assert step.actions[0].action_input == {
        "category": "evaluation",
        "thought": "Need one more pass",
    }


def test_analysis_workflow_synthesizes_thought_for_action_only_structured_response():
    agent = DummyWorkflowAgent()

    step = agent._build_step_from_structured_response(
        'Action: search_code\nAction Input: {"keyword":"glueSource","max_results":10}',
        [],
    )

    assert step.action == "search_code"
    assert step.thought == "Searching the codebase for 'glueSource'."


@pytest.mark.asyncio
async def test_analysis_workflow_emits_completion_events_for_fallback_results():
    agent = DummyWorkflowAgent()
    event_emitter = MagicMock()
    event_emitter.emit = AsyncMock()
    agent.event_emitter = event_emitter

    agent._build_fallback_result = MagicMock(
        return_value={
            "findings": [{"title": "fallback finding"}],
            "summary": "fallback summary",
        }
    )
    agent.stream_llm_call = AsyncMock(
        side_effect=[("", 0), ("", 0), ("", 0), ("", 0), ("", 0)]
    )

    result = await agent.run(
        {
            "project_info": {"name": "demo", "root": "."},
            "config": {},
            "task": "audit",
            "previous_results": {},
        }
    )

    assert result.success is True
    emitted_types = [
        call.args[0].event_type
        for call in event_emitter.emit.await_args_list
    ]
    assert "llm_complete" in emitted_types
    assert "info" in emitted_types


@pytest.mark.asyncio
async def test_analysis_workflow_run_executes_action_batch_and_aggregates_observation():
    agent = DummyWorkflowAgent(
        tools={
            "tool_a": EchoTool("tool_a"),
            "tool_b": EchoTool("tool_b"),
        }
    )

    responses = [
        (
            """Thought: gather two quick signals
Action Batch:
[
  {"action": "tool_a", "action_input": {"value": "alpha"}},
  {"action": "tool_b", "action_input": {"value": "beta"}}
]""",
            0,
        ),
        ('Final Answer: {"findings": [], "summary": "done"}', 0),
    ]

    agent.stream_llm_call = AsyncMock(side_effect=responses)

    result = await agent.run(
        {
            "project_info": {"name": "demo", "root": "."},
            "config": {},
            "task": "audit",
            "previous_results": {},
        }
    )

    assert result.success is True
    assert result.data["summary"] == "done"
    assert "tool_a:alpha" in result.data["steps"][0]["observation"]
    assert "tool_b:beta" in result.data["steps"][0]["observation"]


@pytest.mark.asyncio
async def test_finding_agent_prefers_structured_tool_calling_run(monkeypatch):
    llm_service = MagicMock()
    llm_service.chat_completion = AsyncMock(
        side_effect=[
            {
                "content": "Read the primary skill file first.",
                "usage": {"total_tokens": 11},
                "finish_reason": "tool_calls",
                "tool_calls": [
                    {
                        "id": "call_bootstrap",
                        "type": "function",
                        "function": {
                            "name": "read_file",
                            "arguments": '{"file_path":"skill_library/code-audit-finding/SKILL.md"}',
                        },
                    }
                ],
            },
            {
                "content": "Compare the controller and mapper next.",
                "usage": {"total_tokens": 13},
                "finish_reason": "tool_calls",
                "tool_calls": [
                    {
                        "id": "call_batch",
                        "type": "function",
                        "function": {
                            "name": "read_many_files",
                            "arguments": '{"file_paths":["src/controller.java","src/mapper.xml"]}',
                        },
                    }
                ],
            },
            {
                "content": '{"findings": [], "summary": "done"}',
                "usage": {"total_tokens": 7},
                "finish_reason": "stop",
                "tool_calls": [],
            },
        ]
    )
    llm_service.chat_completion_stream = AsyncMock(side_effect=AssertionError("legacy stream path should not be used"))

    agent = FindingAgent(
        llm_service=llm_service,
        tools={
            "read_file": PathEchoTool("read_file"),
            "read_many_files": PathEchoTool("read_many_files"),
        },
        event_emitter=MagicMock(),
    )

    monkeypatch.setattr(
        "app.services.agent.skill_service.SkillService.resolve_agent_skills",
        AsyncMock(
            return_value={
                "metadata": [
                    {
                        "slug": "code-audit-finding",
                        "paths": {"skill_file_path": "skill_library/code-audit-finding/SKILL.md"},
                    }
                ],
                "matched": [
                    {
                        "slug": "code-audit-finding",
                        "paths": {"skill_file_path": "skill_library/code-audit-finding/SKILL.md"},
                    }
                ],
                "route_plan": {"primary_skill": "code-audit-finding"},
            }
        ),
    )

    async def fake_preload(user_id, context):
        del user_id, context
        return PreloadedSkillContext(primary_skill_name="code-audit-finding")

    monkeypatch.setattr(agent._skill_preloader, "preload", fake_preload)

    result = await agent.run(
        {
            "project_info": {"name": "demo", "root": "."},
            "config": {},
            "task": "audit",
            "task_context": "focus on controller to mapper flows",
            "previous_results": {
                "recon": {
                    "data": {
                        "entry_points": [{"type": "http", "file": "src/controller.java", "line": 10}],
                        "priority_paths": ["src/controller.java", "src/mapper.xml"],
                        "project_profile": {"languages": ["Java"], "frameworks": ["Spring"]},
                    }
                }
            },
        }
    )

    assert result.success is True
    assert result.data["summary"] == "done"
    assert llm_service.chat_completion.await_count == 3
    llm_service.chat_completion_stream.assert_not_called()
    assert result.data["steps"][0]["actions"][0]["action"] == "read_file"
    assert result.data["steps"][1]["actions"][0]["action"] == "read_many_files"
    assert "skill_library/code-audit-finding/SKILL.md" in (result.data["steps"][0]["observation"] or "")
    assert "src/controller.java,src/mapper.xml" in (result.data["steps"][1]["observation"] or "")


def test_finding_agent_structured_tool_schemas_exclude_internal_reasoning_tools():
    agent = FindingAgent(
        llm_service=MagicMock(),
        tools={
            "read_file": PathEchoTool("read_file"),
            "read_many_files": PathEchoTool("read_many_files"),
            "think": ThinkTool(),
            "reflect": ReflectTool(),
        },
        event_emitter=MagicMock(),
    )

    schemas = agent._build_structured_tool_schemas()
    schema_names = [
        schema.get("function", {}).get("name", "")
        for schema in schemas
        if isinstance(schema, dict)
    ]

    assert "read_file" in schema_names
    assert "read_many_files" in schema_names
    assert "think" not in schema_names
    assert "reflect" not in schema_names
    assert "load_skill_body" not in schema_names
    assert "skill_resource_lookup" not in schema_names


@pytest.mark.asyncio
async def test_finding_agent_rejects_compatibility_skill_tools():
    llm_service = MagicMock()
    llm_service.chat_completion_stream = MagicMock()
    agent = FindingAgent(
        llm_service=llm_service,
        tools={},
        event_emitter=MagicMock(),
    )

    class Step:
        actions = [
            ToolInvocation(
                action="skill_resource_lookup",
                action_input={"skill_ref": "code-audit-finding", "resource_name": "references", "mode": "list"},
            )
        ]

    observation = await agent._execute_step_actions(Step(), {})

    assert "不要使用 skill_resource_lookup 加载 Finding runtime 技能。" in observation


def test_finding_agent_fallback_result_does_not_use_heuristic_findings():
    llm_service = MagicMock()
    llm_service.chat_completion_stream = MagicMock()
    agent = FindingAgent(
        llm_service=llm_service,
        tools={},
        event_emitter=MagicMock(),
    )
    agent._runtime_state = None
    agent._steps = [
        SimpleNamespace(
            thought='Tool Calls:\\n- search_code({"keyword":"glueSource"})',
            action="search_code",
            observation="闂佺懓鍚嬬划搴ㄥ磼閵娧呯＜闁规儳顕禍? glueSource",
        )
    ]

    fallback = agent._build_fallback_result()

    assert fallback["findings"] == []
    assert "最终化" in fallback["summary"]


@pytest.mark.asyncio
async def test_finding_skill_preloader_returns_route_metadata_without_preloading_resources(monkeypatch):
    from app.services.agent.agents.finding_skill_preloader import FindingSkillPreloader

    monkeypatch.setattr(
        "app.services.agent.skill_service.SkillService.get_skill_body",
        AsyncMock(side_effect=AssertionError("skill body should not be preloaded")),
    )
    monkeypatch.setattr(
        "app.services.agent.skill_service.SkillService.get_skill_resource",
        AsyncMock(side_effect=AssertionError("skill resources should not be preloaded")),
    )

    preloader = FindingSkillPreloader()
    loaded = await preloader.preload(
        user_id=None,
        context={
            "skill_context": {
                "route_plan": {
                    "primary_skill": "code-audit-finding",
                    "mandatory_reads": [
                        "references/checklists/python.md",
                        "references/frameworks/fastapi.md",
                    ],
                    "recommended_reads": ["references/security/llm_security.md"],
                    "case_candidates": ["references/wooyun/INDEX.md"],
                }
            }
        },
    )

    assert loaded.primary_skill_name == "code-audit-finding"
    assert loaded.primary_skill_body == {}
    assert loaded.mandatory_resources == []
    assert loaded.recommended_resources == []
    assert loaded.case_hints == ["references/wooyun/INDEX.md"]
    assert loaded.to_prompt_block() == ""


def test_candidate_queue_manager_deduplicates_candidates():
    from app.services.agent.agents.finding_candidates import CandidateCase, CandidateQueueManager

    manager = CandidateQueueManager()
    queue = manager.build_queue(
        [
            CandidateCase(
                id="c1",
                vuln_family="idor",
                priority=90,
                entry_point_refs=["src/api.py:10"],
                source_refs=["src/api.py:10"],
                sink_refs=["src/service.py:33"],
                control_refs=[],
                business_flow_notes=[],
            ),
            CandidateCase(
                id="c2",
                vuln_family="idor",
                priority=70,
                entry_point_refs=["src/api.py:10"],
                source_refs=["src/api.py:10"],
                sink_refs=["src/service.py:33"],
                control_refs=[],
                business_flow_notes=[],
            ),
        ]
    )

    assert [candidate.id for candidate in queue] == ["c1"]


def test_evidence_bundle_store_upserts_and_summarizes_bundles():
    from app.services.agent.agents.finding_evidence import EvidenceBundle, EvidenceBundleStore

    store = EvidenceBundleStore()
    bundle_id = store.upsert(
        EvidenceBundle(
            id="ev-1",
            file_path="src/api.py",
            line_start=10,
            line_end=18,
            snippet="dangerous_call(user_input)",
            source_desc="request parameter",
            sink_desc="dangerous_call",
            control_analysis="missing ownership validation",
            business_flow_analysis="tenant update path",
            entry_point_refs=["src/api.py:10"],
            priority_path_refs=["src/api.py"],
            evidence_gaps=["missing_verification"],
            confidence=0.82,
        )
    )

    summary = store.build_candidate_summary(["ev-1"])

    assert bundle_id == "ev-1"
    assert summary["file_paths"] == ["src/api.py"]
    assert summary["entry_point_refs"] == ["src/api.py:10"]
    assert summary["evidence_gaps"] == ["missing_verification"]


def test_finding_controller_caps_initial_queue_with_family_diversity_and_tracks_suppressed_candidates():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "config": {"max_active_candidates": 3},
            "target_files": ["app/api/uploads.py", "app/api/admin.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass", "sql_injection", "xss"],
            "recon_data": {
                "entry_points": [
                    {"type": "http", "file": "app/api/uploads.py", "line": 11},
                    {"type": "http", "file": "app/api/admin.py", "line": 5},
                ],
                "priority_paths": ["app/api/uploads.py", "app/api/admin.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    assert runtime_state.plan.max_active_candidates == 3
    assert len(runtime_state.queue) == 3
    assert len({candidate.vuln_family for candidate in runtime_state.queue}) == 3
    assert runtime_state.discarded_candidates
    assert runtime_state.discarded_candidates[0]["discard_reason"] == "initial_queue_cap"
    assert runtime_state.metrics["queue.initial_candidates_raw"] > runtime_state.metrics["queue.initial_candidates"]


def test_finding_controller_builds_coverage_first_runtime_state():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass"],
            "recon_data": {
                "entry_points": [
                    {"type": "http", "file": "app/api/uploads.py", "line": 11},
                    {"type": "http", "file": "app/api/admin.py", "line": 5},
                ],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    assert runtime_state.plan.strategy == "coverage_first"
    assert runtime_state.coverage.uncovered_priority_paths == [
        "app/api/uploads.py",
        "app/services/authz.py",
    ]
    assert runtime_state.queue
    assert runtime_state.queue[0].vuln_family in {"idor", "auth_bypass"}


@pytest.mark.asyncio
async def test_finding_agent_prepare_runtime_context_injects_runtime_state(monkeypatch):
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())

    async def fake_preload(user_id, context):
        del user_id, context
        return PreloadedSkillContext(primary_skill_name="code-audit-finding")

    monkeypatch.setattr(agent._skill_preloader, "preload", fake_preload)

    prepared = await agent._prepare_runtime_context(
        {
            "config": {},
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor"],
            "skill_context": {
                "route_plan": {"primary_skill": "code-audit-finding"},
                "metadata": [
                    {
                        "slug": "code-audit-finding",
                        "paths": {"skill_file_path": "skill_library/code-audit-finding/SKILL.md"},
                    }
                ],
            },
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    assert prepared["preloaded_skill_context"].primary_skill_name == "code-audit-finding"
    assert prepared["finding_runtime_state"].plan.strategy == "coverage_first"
    assert prepared["finding_runtime_state"].queue
    assert prepared["skill_bootstrap_state"]["primary_skill"] == "code-audit-finding"
    assert prepared["skill_bootstrap_state"]["skill_file_path"] == "skill_library/code-audit-finding/SKILL.md"
    assert prepared["skill_bootstrap_state"]["loaded"] is False


@pytest.mark.asyncio
async def test_finding_requires_primary_skill_bootstrap_before_general_reads():
    agent = FindingAgent(
        llm_service=MagicMock(),
        tools={
            "read_file": EchoTool("read_file"),
            "read_many_files": EchoTool("read_many_files"),
            "load_skill_body": EchoTool("load_skill_body"),
        },
        event_emitter=MagicMock(),
    )
    agent.emit_llm_action = AsyncMock()
    agent.execute_tool = AsyncMock(return_value="should not run")
    agent._skill_bootstrap_state = {
        "primary_skill": "code-audit-finding",
        "skill_file_path": "skill_library/code-audit-finding/SKILL.md",
        "loaded": False,
    }

    step = SimpleNamespace(
        actions=[ToolInvocation(action="read_file", action_input={"file_path": "src/api.py"})],
    )

    observation = await agent._execute_step_actions(step, failed_tool_calls={})

    assert "Read" in observation
    assert "skill_library/code-audit-finding/SKILL.md" in observation
    agent.execute_tool.assert_not_awaited()


@pytest.mark.asyncio
async def test_finding_allows_batch_actions_after_primary_skill_bootstrap():
    agent = FindingAgent(
        llm_service=MagicMock(),
        tools={
            "read_many_files": EchoTool("read_many_files"),
            "read_file": EchoTool("read_file"),
        },
        event_emitter=MagicMock(),
    )
    agent.emit_llm_action = AsyncMock()
    agent.execute_tool = AsyncMock(side_effect=["skill bootstrap ok", "batch read ok"])
    agent._skill_bootstrap_state = {
        "primary_skill": "code-audit-finding",
        "skill_file_path": "skill_library/code-audit-finding/SKILL.md",
        "loaded": False,
    }

    step = SimpleNamespace(
        actions=[
            ToolInvocation(
                action="read_file",
                action_input={"file_path": "skill_library/code-audit-finding/SKILL.md"},
            ),
            ToolInvocation(
                action="read_many_files",
                action_input={"file_paths": ["src/api.py", "src/service.py"]},
            ),
        ],
    )

    observation = await agent._execute_step_actions(step, failed_tool_calls={})

    assert "skill bootstrap ok" in observation
    assert "batch read ok" in observation
    assert agent._skill_bootstrap_state["loaded"] is True
    assert agent.execute_tool.await_count == 2


@pytest.mark.asyncio
async def test_finding_allows_read_many_files_to_bootstrap_primary_skill():
    agent = FindingAgent(
        llm_service=MagicMock(),
        tools={
            "read_many_files": EchoTool("read_many_files"),
        },
        event_emitter=MagicMock(),
    )
    agent.emit_llm_action = AsyncMock()
    agent.execute_tool = AsyncMock(return_value="batch bootstrap ok")
    agent._skill_bootstrap_state = {
        "primary_skill": "code-audit-finding",
        "skill_file_path": "skill_library/code-audit-finding/SKILL.md",
        "loaded": False,
    }

    step = SimpleNamespace(
        actions=[
            ToolInvocation(
                action="read_many_files",
                action_input={
                    "file_paths": [
                        "skill_library/code-audit-finding/SKILL.md",
                        "src/api.py",
                    ]
                },
            ),
        ],
    )

    observation = await agent._execute_step_actions(step, failed_tool_calls={})

    assert "batch bootstrap ok" in observation
    assert agent._skill_bootstrap_state["loaded"] is True


def test_finding_loop_detector_blocks_repeated_no_progress_calls():
    from app.services.agent.agents.finding_loop_detector import FindingLoopDetector

    detector = FindingLoopDetector(warn_threshold=2, block_threshold=3)

    first = detector.register("read_file", {"file_path": "app/api.py"}, evidence_delta=0)
    second = detector.register("read_file", {"file_path": "app/api.py"}, evidence_delta=0)
    third = detector.register("read_file", {"file_path": "app/api.py"}, evidence_delta=0)

    assert first.status == "allow"
    assert second.status == "warn"
    assert third.status == "block"


def test_candidate_worker_records_evidence_for_candidate():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_evidence import EvidenceBundleStore
    from app.services.agent.agents.finding_worker import CandidateWorker

    store = EvidenceBundleStore()
    worker = CandidateWorker(evidence_store=store)
    candidate = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=95,
        entry_point_refs=["app/api/uploads.py:11"],
        source_refs=["app/api/uploads.py:11"],
        sink_refs=["app/services/authz.py:44"],
        control_refs=["app/services/authz.py:44"],
        business_flow_notes=["upload approval flow"],
    )

    result = worker.record_tool_result(
        candidate,
        "read_file",
        {"file_path": "app/api/uploads.py", "start_line": 11, "end_line": 19},
        "闂佸搫鍊稿ú锝呪枎? app/api/uploads.py\n闁荤偞绋戦張顒勫汲? 11-19\n```python\nowner_id = request.user_id\nservice.approve(upload_id)\n```",
    )

    assert result.evidence_bundle_ids
    summary = store.build_candidate_summary(result.evidence_bundle_ids)
    assert summary["file_paths"] == ["app/api/uploads.py"]
    assert candidate.evidence_bundle_ids == result.evidence_bundle_ids


def test_finding_synthesizer_builds_candidate_findings_from_evidence():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle, EvidenceBundleStore
    from app.services.agent.agents.finding_synthesizer import FindingSynthesizer

    store = EvidenceBundleStore()
    store.upsert(
        EvidenceBundle(
            id="ev-1",
            file_path="app/api/uploads.py",
            line_start=11,
            line_end=19,
            snippet="service.approve(upload_id)",
            source_desc="request path upload_id",
            sink_desc="approval state change",
            control_analysis="ownership check is missing in the reviewed path",
            business_flow_analysis="upload approval flow",
            entry_point_refs=["app/api/uploads.py:11"],
            priority_path_refs=["app/api/uploads.py"],
            evidence_gaps=["dynamic_verification_pending"],
            confidence=0.83,
        )
    )

    candidate = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=95,
        entry_point_refs=["app/api/uploads.py:11"],
        source_refs=["app/api/uploads.py:11"],
        sink_refs=["app/services/authz.py:44"],
        control_refs=["app/services/authz.py:44"],
        business_flow_notes=["upload approval flow"],
        evidence_bundle_ids=["ev-1"],
    )
    runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        queue=[candidate],
    )

    runtime_state.unresolved_candidates = [{"candidate_id": "cand-1", "unresolved_reason": "followup exhausted"}]
    runtime_state.discarded_candidates = [{"candidate_id": "cand-x", "discard_reason": "worker budget exhausted"}]

    synthesized = FindingSynthesizer().synthesize(runtime_state, store)

    assert synthesized["findings"]
    assert synthesized["findings"][0]["vulnerability_type"] == "idor"
    assert synthesized["findings"][0]["file_path"] == "app/api/uploads.py"
    assert synthesized["findings"][0]["verdict"] == "candidate"
    assert "1 unresolved candidates remain" in synthesized["summary"]
    assert "1 low-value candidates were discarded" in synthesized["summary"]


@pytest.mark.asyncio
async def test_finding_agent_recover_final_result_prefers_synthesized_evidence(monkeypatch):
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        queue=[
            CandidateCase(
                id="cand-1",
                vuln_family="idor",
                priority=95,
                entry_point_refs=["app/api/uploads.py:11"],
                source_refs=["app/api/uploads.py:11"],
                sink_refs=["app/services/authz.py:44"],
                control_refs=["app/services/authz.py:44"],
                business_flow_notes=["upload approval flow"],
                evidence_bundle_ids=["ev-1"],
            )
        ],
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-1",
            file_path="app/api/uploads.py",
            line_start=11,
            line_end=19,
            snippet="service.approve(upload_id)",
            source_desc="request path upload_id",
            sink_desc="approval state change",
            control_analysis="ownership check is missing in the reviewed path",
            business_flow_analysis="upload approval flow",
            entry_point_refs=["app/api/uploads.py:11"],
            priority_path_refs=["app/api/uploads.py"],
            evidence_gaps=["dynamic_verification_pending"],
            confidence=0.83,
        )
    )

    async def unexpected_stream(messages):
        raise AssertionError(f"LLM fallback should not run when synthesized evidence exists: {messages}")

    monkeypatch.setattr(agent, "stream_llm_call", unexpected_stream)

    recovered = await agent._recover_final_result()

    assert recovered["findings"]
    assert recovered["findings"][0]["vulnerability_type"] == "idor"


def test_finding_controller_creates_worker_sessions_with_independent_budgets():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass"],
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    assert runtime_state.active_candidate_id
    first_candidate = runtime_state.queue[0]
    session = runtime_state.worker_sessions[first_candidate.id]
    assert session.candidate_id == first_candidate.id
    assert session.remaining_budget == runtime_state.plan.worker_budget
    assert session.followup_rounds_left == runtime_state.plan.max_followup_rounds_per_candidate
    assert session.message_history
    assert first_candidate.vuln_family in session.brief
    assert first_candidate.sink_refs[0] in session.brief


def test_finding_controller_rotates_candidates_explicitly_and_marks_reason():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass"],
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    first_id = runtime_state.active_candidate_id
    next_candidate = controller.rotate_candidate(runtime_state, "budget exhausted")

    assert next_candidate is not None
    assert next_candidate.id != first_id
    assert runtime_state.worker_sessions[first_id].status == "rotated"
    assert runtime_state.worker_sessions[first_id].rotation_reason == "budget exhausted"
    assert runtime_state.active_candidate_id == next_candidate.id


def test_finding_controller_updates_worker_budget_and_rotates_when_exhausted():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass"],
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    first_id = runtime_state.active_candidate_id
    session = runtime_state.worker_sessions[first_id]
    session.remaining_budget = 1

    controller.consume_worker_budget(runtime_state, first_id, spent=1, reason="worker budget exhausted")

    assert runtime_state.worker_sessions[first_id].status == "budget_exhausted"
    assert runtime_state.active_candidate_id != first_id


def test_finding_controller_schedules_followup_round_before_full_exhaustion():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass"],
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    first_id = runtime_state.active_candidate_id
    first_candidate = runtime_state.queue[0]
    first_candidate.evidence_bundle_ids.append("ev-1")
    session = runtime_state.worker_sessions[first_id]
    session.remaining_budget = 1
    session.followup_rounds_left = 1

    controller.consume_worker_budget(runtime_state, first_id, spent=1, reason="worker budget exhausted")

    assert runtime_state.worker_sessions[first_id].status == "needs_followup"
    assert runtime_state.worker_sessions[first_id].followup_rounds_left == 0
    assert runtime_state.active_candidate_id != first_id


@pytest.mark.asyncio
async def test_finding_agent_builds_iteration_messages_from_active_candidate_local_context(monkeypatch):
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())

    async def fake_preload(user_id, context):
        del user_id, context
        return PreloadedSkillContext(primary_skill_name="code-audit-finding")

    monkeypatch.setattr(agent._skill_preloader, "preload", fake_preload)

    context = await agent._prepare_runtime_context(
        {
            "project_info": {"name": "demo", "root": "."},
            "config": {},
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor"],
            "skill_context": {"route_plan": {"primary_skill": "code-audit-finding"}},
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )
    agent._conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": agent._build_initial_message(context)},
        {"role": "assistant", "content": "global unrelated reasoning"},
    ]
    active_id = agent._runtime_state.active_candidate_id
    session = agent._runtime_state.worker_sessions[active_id]
    session.message_history.extend(
        [
            {"role": "assistant", "content": "candidate specific thought"},
            {"role": "user", "content": "Observation:\nread app/api/uploads.py"},
        ]
    )

    messages = agent._build_iteration_messages()

    assert messages[0]["role"] == "system"
    assert messages[1]["role"] == "user"
    assert "global unrelated reasoning" not in "\n".join(item["content"] for item in messages if item["role"] != "system")
    assert any("candidate specific thought" in item["content"] for item in messages)
    assert any(active_id in item["content"] for item in messages if item["role"] == "user")


def test_finding_agent_iteration_messages_include_backlog_summaries():
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_candidates import CandidateCase

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    active_candidate = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=90,
        entry_point_refs=["app/api/uploads.py:11"],
        source_refs=["app/api/uploads.py:11"],
        sink_refs=["app/services/authz.py:44"],
        control_refs=[],
    )
    unresolved_candidate = CandidateCase(
        id="cand-2",
        vuln_family="sql_injection",
        priority=95,
        entry_point_refs=["app/api/search.py:10"],
        source_refs=["app/api/search.py:10"],
        sink_refs=["app/services/search.py:44"],
        control_refs=[],
        evidence_bundle_ids=["ev-2"],
    )
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor", "sql_injection"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11", "app/api/search.py:10"]),
        queue=[active_candidate, unresolved_candidate],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief",
                max_budget=4,
                remaining_budget=2,
                status="active",
                message_history=[{"role": "user", "content": "brief"}],
                followup_rounds_left=0,
            ),
            "cand-2": WorkerSession(
                candidate_id="cand-2",
                brief="brief-2",
                max_budget=4,
                remaining_budget=0,
                status="budget_exhausted",
                rotation_reason="followup exhausted",
                message_history=[{"role": "user", "content": "brief-2"}],
                followup_rounds_left=0,
            ),
        },
        active_candidate_id="cand-1",
        discarded_candidates=[{"candidate_id": "cand-x", "discard_reason": "worker budget exhausted"}],
        metrics={"convergence": {"selected_candidate_id": "cand-1"}},
    )
    agent._evidence_store.upsert(
        type("Bundle", (), {
            "id": "ev-2",
            "file_path": "app/api/search.py",
            "line_start": 10,
            "line_end": 18,
            "snippet": "db.execute(query)",
            "source_desc": "request parameter",
            "sink_desc": "SQL execution",
            "control_analysis": "query is concatenated without parameterization",
            "business_flow_analysis": "search flow",
            "entry_point_refs": ["app/api/search.py:10"],
            "priority_path_refs": ["app/api/search.py"],
            "evidence_gaps": ["dynamic_verification_pending"],
            "confidence": 0.84,
        })()
    )
    agent._conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": "initial"},
    ]
    agent._iteration = 5

    messages = agent._build_iteration_messages()
    context_message = next(item["content"] for item in messages if item["role"] == "user" and "当前候选本地上下文" in item["content"])

    assert '"discarded_candidates"' in context_message
    assert '"candidate_id": "cand-x"' in context_message
    assert '"unresolved_candidates"' in context_message
    assert '"candidate_id": "cand-2"' in context_message
    assert '"unresolved_reason": "followup exhausted"' in context_message


def test_finding_agent_records_local_candidate_history():
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_candidates import CandidateCase

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    candidate = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=90,
        entry_point_refs=["app/api/uploads.py:11"],
        source_refs=["app/api/uploads.py:11"],
        sink_refs=["app/services/authz.py:44"],
        control_refs=[],
        business_flow_notes=[],
    )
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        queue=[candidate],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief",
                max_budget=4,
                remaining_budget=4,
                status="active",
                message_history=[{"role": "user", "content": "brief"}],
                followup_rounds_left=1,
            )
        },
        active_candidate_id="cand-1",
    )

    agent._record_active_candidate_message("assistant", "candidate thought")
    agent._record_active_candidate_message("user", "Observation:\nchunk")

    history = agent._runtime_state.worker_sessions["cand-1"].message_history

    assert history[-2]["content"] == "candidate thought"
    assert history[-1]["content"] == "Observation:\nchunk"


@pytest.mark.asyncio
async def test_finding_agent_initial_message_reports_queue_suppression_summary(monkeypatch):
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())

    async def fake_preload(user_id, context):
        del user_id, context
        return PreloadedSkillContext(primary_skill_name="code-audit-finding")

    monkeypatch.setattr(agent._skill_preloader, "preload", fake_preload)

    context = await agent._prepare_runtime_context(
        {
            "project_info": {"name": "demo", "root": "."},
            "config": {"max_active_candidates": 2},
            "target_files": ["app/api/uploads.py", "app/api/admin.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass", "sql_injection", "xss"],
            "skill_context": {"route_plan": {"primary_skill": "code-audit-finding"}},
            "recon_data": {
                "entry_points": [
                    {"type": "http", "file": "app/api/uploads.py", "line": 11},
                    {"type": "http", "file": "app/api/admin.py", "line": 5},
                ],
                "priority_paths": ["app/api/uploads.py", "app/api/admin.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    message = agent._build_initial_message(context)

    assert '"max_active_candidates": 2' in message
    assert '"initial_queue_suppressed":' in message
    assert '"初始队列生成规则"' in message


@pytest.mark.asyncio
async def test_finding_agent_iteration_messages_include_global_budget_and_report_phase_guidance(monkeypatch):
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent.config.max_iterations = 32
    agent._iteration = 26

    async def fake_preload(user_id, context):
        del user_id, context
        return PreloadedSkillContext(primary_skill_name="code-audit-finding")

    monkeypatch.setattr(agent._skill_preloader, "preload", fake_preload)

    context = await agent._prepare_runtime_context(
        {
            "project_info": {"name": "demo", "root": "."},
            "config": {},
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor"],
            "skill_context": {"route_plan": {"primary_skill": "code-audit-finding"}},
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )
    agent._conversation_history = [
        {"role": "system", "content": "system"},
        {"role": "user", "content": agent._build_initial_message(context)},
    ]

    messages = agent._build_iteration_messages()
    context_message = next(item["content"] for item in messages if item["role"] == "user" and "当前候选本地上下文" in item["content"])

    assert '"current_iteration": 26' in context_message
    assert '"max_iterations": 32' in context_message
    assert '"rounds_left": 6' in context_message
    assert '"phase": "evidence_collection"' in context_message
    assert "保持证据收集模式" in context_message


def test_finding_agent_preemptive_finalization_prompt_is_disabled_by_default():
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())

    assert agent._build_preemptive_finalization_prompt(7) == ""
    assert agent._build_preemptive_finalization_prompt(6) == ""
    assert agent._build_preemptive_finalization_prompt(3) == ""
    assert agent._build_preemptive_finalization_prompt(1) == ""


def test_finding_agent_aborts_llm_failures_immediately_in_final_only_mode():
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState
    from app.services.agent.agents.finding_coverage import CoverageMap

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        phase="report_finalization",
        phase_reason="closed_exploit_chain_candidate",
    )

    assert agent._should_abort_after_llm_failure("[LLM error: timeout] retry", 1) is False

    agent._runtime_state.phase = "evidence_collection"
    assert agent._should_abort_after_llm_failure("[LLM error: timeout] retry", 1) is False


def test_finding_agent_enters_report_phase_when_closed_chain_candidate_exists():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    candidate = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=95,
        entry_point_refs=["app/api/uploads.py:11"],
        source_refs=["app/api/uploads.py:11"],
        sink_refs=["app/services/authz.py:44"],
        control_refs=["app/services/authz.py:44"],
        business_flow_notes=["upload approval flow"],
        evidence_bundle_ids=["ev-1", "ev-2"],
    )
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        queue=[candidate],
        active_candidate_id="cand-1",
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-1",
            file_path="app/api/uploads.py",
            line_start=11,
            line_end=19,
            snippet="load target account",
            source_desc="request path upload_id",
            sink_desc="approval state change",
            control_analysis="ownership check is missing in the reviewed path",
            business_flow_analysis="upload approval flow",
            entry_point_refs=["app/api/uploads.py:11"],
            priority_path_refs=["app/api/uploads.py"],
            evidence_gaps=[],
            confidence=0.92,
        )
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-2",
            file_path="app/services/authz.py",
            line_start=44,
            line_end=51,
            snippet="service.approve(upload_id)",
            source_desc="request path upload_id",
            sink_desc="approval state change",
            control_analysis="approval executes without caller ownership validation",
            business_flow_analysis="upload approval flow",
            entry_point_refs=["app/api/uploads.py:11"],
            priority_path_refs=["app/services/authz.py"],
            evidence_gaps=[],
            confidence=0.94,
        )
    )

    agent._update_runtime_phase(current_iteration=5)

    assert agent._runtime_state.phase == "report_finalization"
    assert agent._runtime_state.phase_reason == "closed_exploit_chain_candidate"


def test_finding_agent_report_phase_freezes_candidate_rotation():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass"],
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = runtime_state
    current_id = runtime_state.active_candidate_id

    agent._enter_report_finalization_phase("tail_budget")
    agent._advance_candidate("should not rotate while finalizing")

    assert runtime_state.phase == "report_finalization"
    assert runtime_state.phase_reason == "tail_budget"
    assert runtime_state.active_candidate_id == current_id
    assert runtime_state.rotation_history == []




def test_finding_agent_does_not_force_report_phase_when_viable_candidates_remain():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor", "auth_bypass"],
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = runtime_state
    agent.config.max_iterations = 32
    agent._iteration = 26

    agent._update_runtime_phase(current_iteration=26)

    assert runtime_state.phase == "evidence_collection"
    assert runtime_state.phase_reason == ""


def test_finding_agent_enters_report_phase_when_queue_is_exhausted_with_report_ready_evidence():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle

    candidate = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=95,
        entry_point_refs=["app/api/uploads.py:11"],
        source_refs=["app/api/uploads.py:11"],
        sink_refs=["app/services/authz.py:44"],
        control_refs=["app/services/authz.py:44"],
        business_flow_notes=["upload approval flow"],
        evidence_bundle_ids=["ev-1"],
    )
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        queue=[candidate],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief",
                max_budget=4,
                remaining_budget=0,
                status="budget_exhausted",
                message_history=[{"role": "user", "content": "brief"}],
                followup_rounds_left=0,
            )
        },
        active_candidate_id="cand-1",
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-1",
            file_path="app/api/uploads.py",
            line_start=11,
            line_end=19,
            snippet="service.approve(upload_id)",
            source_desc="request path upload_id",
            sink_desc="approval state change",
            control_analysis="ownership check is missing in the reviewed path",
            business_flow_analysis="upload approval flow",
            entry_point_refs=["app/api/uploads.py:11"],
            priority_path_refs=["app/api/uploads.py"],
            evidence_gaps=["dynamic_verification_pending"],
            confidence=0.9,
        )
    )

    agent._update_runtime_phase(current_iteration=12)

    assert agent._runtime_state.phase == "report_finalization"
    assert agent._runtime_state.phase_reason == "coverage_saturated"
    assert agent._runtime_state.active_candidate_id == "cand-1"

def test_finding_agent_promotes_highest_value_runnable_candidate_after_budget_rotation():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle

    cand_1 = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=120,
        entry_point_refs=["app/api/one.py:10"],
        source_refs=["app/api/one.py:10"],
        sink_refs=["app/services/one.py:30"],
        control_refs=[],
    )
    cand_2 = CandidateCase(
        id="cand-2",
        vuln_family="auth_bypass",
        priority=80,
        entry_point_refs=["app/api/two.py:10"],
        source_refs=["app/api/two.py:10"],
        sink_refs=["app/services/two.py:30"],
        control_refs=[],
    )
    cand_3 = CandidateCase(
        id="cand-3",
        vuln_family="sql_injection",
        priority=90,
        entry_point_refs=["app/api/three.py:10"],
        source_refs=["app/api/three.py:10"],
        sink_refs=["app/services/three.py:30"],
        control_refs=[],
        evidence_bundle_ids=["ev-3"],
    )
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor", "auth_bypass", "sql_injection"]),
        coverage=CoverageMap(entry_points=["app/api/one.py:10", "app/api/two.py:10", "app/api/three.py:10"]),
        queue=[cand_1, cand_2, cand_3],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief-1",
                max_budget=4,
                remaining_budget=1,
                status="active",
                message_history=[{"role": "user", "content": "brief-1"}],
                followup_rounds_left=0,
            ),
            "cand-2": WorkerSession(
                candidate_id="cand-2",
                brief="brief-2",
                max_budget=4,
                remaining_budget=3,
                status="pending",
                message_history=[{"role": "user", "content": "brief-2"}],
                followup_rounds_left=0,
            ),
            "cand-3": WorkerSession(
                candidate_id="cand-3",
                brief="brief-3",
                max_budget=4,
                remaining_budget=2,
                status="needs_followup",
                message_history=[{"role": "user", "content": "brief-3"}],
                followup_rounds_left=1,
            ),
        },
        active_candidate_id="cand-1",
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-3",
            file_path="app/api/three.py",
            line_start=10,
            line_end=16,
            snippet="execute(query)",
            source_desc="request parameter",
            sink_desc="SQL execution",
            control_analysis="parameterization is missing",
            business_flow_analysis="search flow",
            entry_point_refs=["app/api/three.py:10"],
            priority_path_refs=["app/api/three.py"],
            evidence_gaps=["dynamic_verification_pending"],
            confidence=0.92,
        )
    )

    agent._controller.consume_worker_budget(agent._runtime_state, "cand-1", spent=1, reason="worker budget exhausted")
    promoted = agent._promote_best_runnable_candidate()

    assert promoted is not None
    assert promoted.id == "cand-3"
    assert agent._runtime_state.active_candidate_id == "cand-3"
    assert agent._runtime_state.worker_sessions["cand-3"].status == "active"


def test_finding_agent_advance_candidate_prefers_highest_value_runnable_candidate():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle

    cand_1 = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=120,
        entry_point_refs=["app/api/one.py:10"],
        source_refs=["app/api/one.py:10"],
        sink_refs=["app/services/one.py:30"],
        control_refs=[],
    )
    cand_2 = CandidateCase(
        id="cand-2",
        vuln_family="auth_bypass",
        priority=80,
        entry_point_refs=["app/api/two.py:10"],
        source_refs=["app/api/two.py:10"],
        sink_refs=["app/services/two.py:30"],
        control_refs=[],
    )
    cand_3 = CandidateCase(
        id="cand-3",
        vuln_family="sql_injection",
        priority=90,
        entry_point_refs=["app/api/three.py:10"],
        source_refs=["app/api/three.py:10"],
        sink_refs=["app/services/three.py:30"],
        control_refs=[],
        evidence_bundle_ids=["ev-3"],
    )
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor", "auth_bypass", "sql_injection"]),
        coverage=CoverageMap(entry_points=["app/api/one.py:10", "app/api/two.py:10", "app/api/three.py:10"]),
        queue=[cand_1, cand_2, cand_3],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief-1",
                max_budget=4,
                remaining_budget=3,
                status="active",
                message_history=[{"role": "user", "content": "brief-1"}],
                followup_rounds_left=0,
            ),
            "cand-2": WorkerSession(
                candidate_id="cand-2",
                brief="brief-2",
                max_budget=4,
                remaining_budget=3,
                status="pending",
                message_history=[{"role": "user", "content": "brief-2"}],
                followup_rounds_left=0,
            ),
            "cand-3": WorkerSession(
                candidate_id="cand-3",
                brief="brief-3",
                max_budget=4,
                remaining_budget=2,
                status="pending",
                message_history=[{"role": "user", "content": "brief-3"}],
                followup_rounds_left=1,
            ),
        },
        active_candidate_id="cand-1",
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-3",
            file_path="app/api/three.py",
            line_start=10,
            line_end=16,
            snippet="execute(query)",
            source_desc="request parameter",
            sink_desc="SQL execution",
            control_analysis="parameterization is missing",
            business_flow_analysis="search flow",
            entry_point_refs=["app/api/three.py:10"],
            priority_path_refs=["app/api/three.py"],
            evidence_gaps=["dynamic_verification_pending"],
            confidence=0.92,
        )
    )

    agent._advance_candidate("loop block")

    assert agent._runtime_state.active_candidate_id == "cand-3"
    assert agent._runtime_state.worker_sessions["cand-1"].status == "rotated"
    assert agent._runtime_state.worker_sessions["cand-3"].status == "active"


def test_finding_agent_prunes_budget_exhausted_no_evidence_candidates_into_discarded_backlog():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap

    cand_1 = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=120,
        entry_point_refs=["app/api/one.py:10"],
        source_refs=["app/api/one.py:10"],
        sink_refs=["app/services/one.py:30"],
        control_refs=[],
    )
    cand_2 = CandidateCase(
        id="cand-2",
        vuln_family="auth_bypass",
        priority=100,
        entry_point_refs=["app/api/two.py:10"],
        source_refs=["app/api/two.py:10"],
        sink_refs=["app/services/two.py:30"],
        control_refs=[],
    )
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor", "auth_bypass"]),
        coverage=CoverageMap(entry_points=["app/api/one.py:10", "app/api/two.py:10"]),
        queue=[cand_1, cand_2],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief-1",
                max_budget=4,
                remaining_budget=0,
                status="budget_exhausted",
                rotation_reason="worker budget exhausted",
                message_history=[{"role": "user", "content": "brief-1"}],
                followup_rounds_left=0,
            ),
            "cand-2": WorkerSession(
                candidate_id="cand-2",
                brief="brief-2",
                max_budget=4,
                remaining_budget=3,
                status="pending",
                message_history=[{"role": "user", "content": "brief-2"}],
                followup_rounds_left=0,
            ),
        },
        active_candidate_id="cand-1",
    )

    agent._refresh_candidate_backlog()

    assert [candidate.id for candidate in agent._runtime_state.queue] == ["cand-2"]
    assert agent._runtime_state.active_candidate_id == "cand-2"
    assert agent._runtime_state.discarded_candidates
    assert agent._runtime_state.discarded_candidates[0]["candidate_id"] == "cand-1"
    assert agent._runtime_state.discarded_candidates[0]["discard_reason"] == "worker budget exhausted"


def test_finding_agent_tracks_evidence_backed_exhausted_candidates_as_unresolved():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle

    cand_1 = CandidateCase(
        id="cand-1",
        vuln_family="sql_injection",
        priority=110,
        entry_point_refs=["app/api/search.py:10"],
        source_refs=["app/api/search.py:10"],
        sink_refs=["app/services/search.py:30"],
        control_refs=[],
        evidence_bundle_ids=["ev-1"],
    )
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["sql_injection"]),
        coverage=CoverageMap(entry_points=["app/api/search.py:10"]),
        queue=[cand_1],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief-1",
                max_budget=4,
                remaining_budget=0,
                status="budget_exhausted",
                rotation_reason="followup exhausted",
                message_history=[{"role": "user", "content": "brief-1"}],
                followup_rounds_left=0,
            )
        },
        active_candidate_id="cand-1",
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-1",
            file_path="app/api/search.py",
            line_start=10,
            line_end=18,
            snippet="db.execute(query)",
            source_desc="request parameter",
            sink_desc="SQL execution",
            control_analysis="query is concatenated without parameterization",
            business_flow_analysis="search flow",
            entry_point_refs=["app/api/search.py:10"],
            priority_path_refs=["app/api/search.py"],
            evidence_gaps=["dynamic_verification_pending"],
            confidence=0.84,
        )
    )

    agent._refresh_candidate_backlog()

    assert [candidate.id for candidate in agent._runtime_state.queue] == ["cand-1"]
    assert agent._runtime_state.unresolved_candidates
    assert agent._runtime_state.unresolved_candidates[0]["candidate_id"] == "cand-1"
    assert agent._runtime_state.unresolved_candidates[0]["unresolved_reason"] == "followup exhausted"


def test_finding_controller_runtime_plan_exposes_convergence_stop_conditions():
    from app.services.agent.agents.finding_controller import FindingController

    controller = FindingController()
    runtime_state = controller.build_runtime_state(
        {
            "target_files": ["app/api/uploads.py"],
            "focus_vulnerabilities": ["idor"],
            "recon_data": {
                "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
                "priority_paths": ["app/api/uploads.py"],
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            },
        }
    )

    assert runtime_state.plan.stop_conditions == [
        "closed_exploit_chain_found",
        "coverage_saturated_with_reportable_evidence",
        "queue_exhausted_without_reportable_evidence",
        "controller_budget_exhausted",
    ]


def test_finding_agent_convergence_decision_surfaces_best_report_candidate():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle

    candidate_a = CandidateCase(
        id="cand-a",
        vuln_family="idor",
        priority=90,
        entry_point_refs=["app/api/a.py:10"],
        source_refs=["app/api/a.py:10"],
        sink_refs=["app/services/a.py:30"],
        control_refs=[],
        evidence_bundle_ids=["ev-a"],
    )
    candidate_b = CandidateCase(
        id="cand-b",
        vuln_family="auth_bypass",
        priority=110,
        entry_point_refs=["app/api/b.py:10"],
        source_refs=["app/api/b.py:10"],
        sink_refs=["app/services/b.py:30"],
        control_refs=[],
        evidence_bundle_ids=["ev-b1", "ev-b2"],
    )
    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor", "auth_bypass"]),
        coverage=CoverageMap(entry_points=["app/api/a.py:10", "app/api/b.py:10"]),
        queue=[candidate_a, candidate_b],
        worker_sessions={
            "cand-a": WorkerSession(
                candidate_id="cand-a",
                brief="brief-a",
                max_budget=4,
                remaining_budget=0,
                status="budget_exhausted",
                message_history=[{"role": "user", "content": "brief-a"}],
                followup_rounds_left=0,
            ),
            "cand-b": WorkerSession(
                candidate_id="cand-b",
                brief="brief-b",
                max_budget=4,
                remaining_budget=0,
                status="completed",
                message_history=[{"role": "user", "content": "brief-b"}],
                followup_rounds_left=0,
            ),
        },
        active_candidate_id="cand-a",
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-a",
            file_path="app/api/a.py",
            line_start=10,
            line_end=16,
            snippet="update_record(target_id)",
            source_desc="request path id",
            sink_desc="record update",
            control_analysis="ownership validation is missing",
            business_flow_analysis="tenant update path",
            entry_point_refs=["app/api/a.py:10"],
            priority_path_refs=["app/api/a.py"],
            evidence_gaps=["dynamic_verification_pending"],
            confidence=0.87,
        )
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-b1",
            file_path="app/api/b.py",
            line_start=10,
            line_end=16,
            snippet="if token: allow_admin()",
            source_desc="Authorization header",
            sink_desc="admin gate",
            control_analysis="missing role check",
            business_flow_analysis="admin workflow",
            entry_point_refs=["app/api/b.py:10"],
            priority_path_refs=["app/api/b.py"],
            evidence_gaps=[],
            confidence=0.93,
        )
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-b2",
            file_path="app/services/b.py",
            line_start=30,
            line_end=37,
            snippet="return do_admin_action()",
            source_desc="Authorization header",
            sink_desc="privileged action",
            control_analysis="admin action executes without role enforcement",
            business_flow_analysis="admin workflow",
            entry_point_refs=["app/api/b.py:10"],
            priority_path_refs=["app/services/b.py"],
            evidence_gaps=[],
            confidence=0.95,
        )
    )

    decision = agent._build_convergence_decision(current_iteration=14)

    assert decision["phase"] == "report_finalization"
    assert decision["reason"] == "closed_exploit_chain_candidate"
    assert decision["selected_candidate_id"] == "cand-b"
    assert decision["stop_condition"] == "closed_exploit_chain_found"


def test_finding_agent_final_only_mode_is_disabled_by_default():
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState
    from app.services.agent.agents.finding_coverage import CoverageMap

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        phase="report_finalization",
        phase_reason="coverage_saturated",
    )

    assert agent._final_only_mode_active(current_iteration=12) is False


def test_analysis_workflow_can_ignore_structured_tool_calls_when_tools_disabled():
    agent = DummyWorkflowAgent()

    step = agent._build_step_from_structured_response(
        'Tool Calls:\n- read_file({"file_path":"demo.py"})',
        [],
        allow_tool_calls=False,
    )

    assert step.action in {"", None}
    assert step.actions == []


@pytest.mark.asyncio
async def test_finding_agent_request_structured_step_keeps_tools_available_when_guided_finalization_is_disabled():
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState
    from app.services.agent.agents.finding_coverage import CoverageMap

    llm_service = MagicMock()
    llm_service.chat_completion = AsyncMock(
        return_value={
            "content": 'Final Answer: {"findings": [], "summary": "done"}',
            "tool_calls": [],
            "usage": {"total_tokens": 9},
            "finish_reason": "stop",
        }
    )
    agent = FindingAgent(llm_service=llm_service, tools={"read_file": PathEchoTool("read_file")}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        phase="report_finalization",
        phase_reason="closed_exploit_chain_candidate",
    )
    agent._iteration = 10

    await agent._request_structured_step(
        [
            {"role": "system", "content": "system"},
            {"role": "user", "content": "return final"},
        ]
    )

    call_kwargs = llm_service.chat_completion.await_args.kwargs
    assert call_kwargs["tools"]


@pytest.mark.asyncio
async def test_finding_agent_report_finalization_phase_still_allows_tool_execution_when_guided_finalization_is_disabled():
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        queue=[
            CandidateCase(
                id="cand-1",
                vuln_family="idor",
                priority=95,
                entry_point_refs=["app/api/uploads.py:11"],
                source_refs=["app/api/uploads.py:11"],
                sink_refs=["app/services/authz.py:44"],
                control_refs=["app/services/authz.py:44"],
                business_flow_notes=[],
            )
        ],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief",
                max_budget=4,
                remaining_budget=4,
                status="finalizing",
                message_history=[{"role": "user", "content": "brief"}],
                followup_rounds_left=1,
            )
        },
        active_candidate_id="cand-1",
        phase="report_finalization",
        phase_reason="closed_exploit_chain_candidate",
    )
    agent.execute_tool = AsyncMock(return_value="read ok")

    step = SimpleNamespace(
        action="read_file",
        action_input={"file_path": "app/api/uploads.py"},
        actions=[ToolInvocation(action="read_file", action_input={"file_path": "app/api/uploads.py"})],
    )

    observation = await agent._execute_step_actions(step, {})

    assert "read ok" in observation
    agent.execute_tool.assert_awaited_once()


def test_finding_agent_checkpoint_persists_closed_candidate_findings(tmp_path):
    from app.services.agent.agents.finding_candidates import CandidateCase
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState, WorkerSession
    from app.services.agent.agents.finding_coverage import CoverageMap
    from app.services.agent.agents.finding_evidence import EvidenceBundle

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._task_id = "task-1"
    agent._current_project_root = str(tmp_path)
    candidate = CandidateCase(
        id="cand-1",
        vuln_family="idor",
        priority=95,
        entry_point_refs=["app/api/uploads.py:11"],
        source_refs=["app/api/uploads.py:11"],
        sink_refs=["app/services/authz.py:44"],
        control_refs=["app/services/authz.py:44"],
        business_flow_notes=["upload approval flow"],
        evidence_bundle_ids=["ev-1", "ev-2"],
    )
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        queue=[candidate],
        worker_sessions={
            "cand-1": WorkerSession(
                candidate_id="cand-1",
                brief="brief",
                max_budget=4,
                remaining_budget=2,
                status="active",
                message_history=[{"role": "user", "content": "brief"}],
                followup_rounds_left=1,
            )
        },
        active_candidate_id="cand-1",
        phase="report_finalization",
        phase_reason="closed_exploit_chain_candidate",
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-1",
            file_path="app/api/uploads.py",
            line_start=11,
            line_end=19,
            snippet="load target account",
            source_desc="request path upload_id",
            sink_desc="approval state change",
            control_analysis="ownership check is missing in the reviewed path",
            business_flow_analysis="upload approval flow",
            entry_point_refs=["app/api/uploads.py:11"],
            priority_path_refs=["app/api/uploads.py"],
            evidence_gaps=[],
            confidence=0.92,
        )
    )
    agent._evidence_store.upsert(
        EvidenceBundle(
            id="ev-2",
            file_path="app/services/authz.py",
            line_start=44,
            line_end=51,
            snippet="service.approve(upload_id)",
            source_desc="request path upload_id",
            sink_desc="approval state change",
            control_analysis="approval executes without caller ownership validation",
            business_flow_analysis="upload approval flow",
            entry_point_refs=["app/api/uploads.py:11"],
            priority_path_refs=["app/services/authz.py"],
            evidence_gaps=[],
            confidence=0.94,
        )
    )

    checkpoint_path = agent._persist_candidate_checkpoint(candidate, trigger="closed_exploit_chain_candidate")
    payload = json.loads(Path(checkpoint_path).read_text(encoding="utf-8"))

    assert payload["trigger"] == "closed_exploit_chain_candidate"
    assert payload["findings"]
    assert payload["findings"][0]["vulnerability_type"] == "idor"


@pytest.mark.asyncio
async def test_finding_agent_recover_final_result_prefers_checkpoint_findings(tmp_path, monkeypatch):
    from app.services.agent.agents.finding_controller import AuditPlan, FindingRuntimeState
    from app.services.agent.agents.finding_coverage import CoverageMap

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    agent._task_id = "task-1"
    agent._current_project_root = str(tmp_path)
    agent._runtime_state = FindingRuntimeState(
        plan=AuditPlan(focus_vulnerabilities=["idor"]),
        coverage=CoverageMap(entry_points=["app/api/uploads.py:11"]),
        phase="report_finalization",
        phase_reason="closed_exploit_chain_candidate",
    )
    checkpoint_file = Path(agent._checkpoint_file_path())
    checkpoint_file.parent.mkdir(parents=True, exist_ok=True)
    checkpoint_file.write_text(
        json.dumps(
            {
                "task_id": "task-1",
                "phase": "report_finalization",
                "trigger": "closed_exploit_chain_candidate",
                "findings": [
                    {
                        "vulnerability_type": "idor",
                        "severity": "high",
                        "title": "Recovered finding",
                        "description": "Recovered from checkpoint",
                        "file_path": "app/api/uploads.py",
                        "line_start": 11,
                        "line_end": 19,
                        "source": "request path upload_id",
                        "sink": "approval state change",
                        "suggestion": "Validate ownership",
                        "confidence": 0.93,
                        "verdict": "candidate",
                        "impact": "Unauthorized approval",
                        "cve_justification": "Closed source-to-sink path",
                        "verification_notes": "Recovered from checkpoint",
                        "exploit_chain": [],
                        "poc": {},
                        "entry_point_refs": ["app/api/uploads.py:11"],
                        "priority_path_refs": ["app/api/uploads.py"],
                        "business_flow_notes": ["upload approval flow"],
                        "evidence_gaps": [],
                    }
                ],
                "summary": "Recovered from checkpoint",
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    async def unexpected_stream(messages):
        raise AssertionError(f"LLM recovery should not run when checkpoint findings exist: {messages}")

    monkeypatch.setattr(agent, "stream_llm_call", unexpected_stream)

    recovered = await agent._recover_final_result()

    assert recovered["findings"]
    assert recovered["findings"][0]["title"] == "Recovered finding"


@pytest.mark.asyncio
async def test_finding_runtime_stack_defaults_to_unbounded_max_turns(monkeypatch):
    captured = {}

    class FakeBridge:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return {
                "session_id": "session-1",
                "final_payload": {"findings": [], "summary": "done"},
                "skill_route": {},
                "memory_counts": {},
            }

        def record_handoff(self, session_id, payload):
            del session_id, payload

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    monkeypatch.setattr(agent, "_build_runtime_bridge", lambda user_id: FakeBridge())
    monkeypatch.setattr(
        "app.services.agent.skill_service.SkillService.resolve_agent_skills",
        AsyncMock(return_value={"route_plan": {}, "matched": [], "metadata": []}),
    )

    result = await agent.run(
        {
            "project_id": "project-1",
            "project_info": {"name": "demo", "project_id": "project-1", "root": "."},
            "config": {"finding_runtime_stack": "runtime"},
            "task": "audit",
            "previous_results": {},
        }
    )

    assert result.success is True
    assert captured["max_turns"] is None


@pytest.mark.asyncio
async def test_finding_runtime_stack_uses_explicit_runtime_turn_limit(monkeypatch):
    captured = {}

    class FakeBridge:
        async def run(self, **kwargs):
            captured.update(kwargs)
            return {
                "session_id": "session-1",
                "final_payload": {"findings": [], "summary": "done"},
                "skill_route": {},
                "memory_counts": {},
            }

        def record_handoff(self, session_id, payload):
            del session_id, payload

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    monkeypatch.setattr(agent, "_build_runtime_bridge", lambda user_id: FakeBridge())
    monkeypatch.setattr(
        "app.services.agent.skill_service.SkillService.resolve_agent_skills",
        AsyncMock(return_value={"route_plan": {}, "matched": [], "metadata": []}),
    )

    await agent.run(
        {
            "project_id": "project-1",
            "project_info": {"name": "demo", "project_id": "project-1", "root": "."},
            "config": {"finding_runtime_stack": "runtime", "finding_runtime_max_iterations": 7},
            "task": "audit",
            "previous_results": {},
        }
    )

    assert captured["max_turns"] == 7


@pytest.mark.asyncio
async def test_finding_runtime_stack_skips_handoff_for_fallback_recovered_result(monkeypatch):
    captured_handoffs = []

    class FakeBridge:
        async def run(self, **kwargs):
            del kwargs
            return {
                "session_id": "session-1",
                "final_payload": {
                    "findings": [],
                    "recovered_candidates": [
                        {
                            "title": "Recovered SSRF candidate",
                            "severity": "high",
                            "vulnerability_type": "ssrf",
                            "file_path": "app/api/fetch.py",
                            "line_start": 11,
                            "line_end": 19,
                            "description": "Recovered from transcript fallback",
                            "source": "request.url",
                            "sink": "requests.get",
                            "suggestion": "Validate outbound destinations",
                            "confidence": 0.74,
                            "needs_verification": True,
                            "verdict": "candidate",
                            "impact": "Potential internal access",
                            "cve_justification": "Recovered candidate only",
                            "verification_notes": "Needs explicit verification",
                            "exploit_chain": [],
                            "poc": {},
                            "entry_point_refs": ["app/api/fetch.py:11"],
                            "priority_path_refs": ["app/api/fetch.py"],
                            "business_flow_notes": ["Recovered from transcript"],
                            "evidence_gaps": ["recovered_after_finalizer_failure"],
                        }
                    ],
                    "summary": "Recovered from transcript fallback",
                },
                "runner_result": TurnExecutionResult(
                    turn_id="turn-1",
                    stop_reason=RuntimeStopReason.COMPLETED,
                    completion_mode=RuntimeCompletionMode.FALLBACK_RECOVERED,
                ),
                "skill_route": {},
                "memory_counts": {},
            }

        def record_handoff(self, session_id, payload):
            captured_handoffs.append((session_id, payload))

    agent = FindingAgent(llm_service=MagicMock(), tools={}, event_emitter=MagicMock())
    monkeypatch.setattr(agent, "_build_runtime_bridge", lambda user_id: FakeBridge())
    monkeypatch.setattr(
        "app.services.agent.skill_service.SkillService.resolve_agent_skills",
        AsyncMock(return_value={"route_plan": {}, "matched": [], "metadata": []}),
    )

    result = await agent.run(
        {
            "project_id": "project-1",
            "project_info": {"name": "demo", "project_id": "project-1", "root": "."},
            "config": {"finding_runtime_stack": "runtime"},
            "task": "audit",
            "previous_results": {},
        }
    )

    assert result.success is False
    assert result.handoff is None
    assert captured_handoffs == []
    assert result.data["findings"] == []
    assert len(result.data["recovered_candidates"]) == 1
    assert result.data["recovered_candidates"][0]["title"] == "Recovered SSRF candidate"
    assert result.data["runtime_completion_mode"] == RuntimeCompletionMode.FALLBACK_RECOVERED.value
    assert "Finding 未完成" in result.error

