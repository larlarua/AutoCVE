from __future__ import annotations

import asyncio

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.services.finding_runtime.bridge import (
    FindingRuntimeBridge,
    NATIVE_TOOL_CALLING_REMINDER,
    RuntimeLLMModelClient,
)
from app.services.finding_runtime.models import (
    RuntimeCompletionMode,
    RuntimeMemoryBundle,
    RuntimeMessageRole,
    RuntimeStopReason,
    RuntimeTerminalAction,
    TranscriptItem,
    TurnExecutionResult,
)
from app.services.agent.tools.base import AgentTool, ToolResult


class FakeAgentTool(AgentTool):
    def __init__(self, name: str):
        super().__init__()
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def description(self) -> str:
        return f"Tool {self._name}"

    async def _execute(self, **kwargs):
        return ToolResult(success=True, data=kwargs)


class FakeLLMService:
    def __init__(self, responses: list[dict]):
        self.responses = list(responses)
        self.calls = []

    async def chat_completion(self, *, messages, agent_type, tools, parallel_tool_calls, max_tokens=None):
        assert agent_type == "finding"
        assert parallel_tool_calls is True
        assert tools is not None
        self.calls.append({"messages": messages, "tools": tools, "max_tokens": max_tokens})
        if not self.responses:
            return {"content": "{}", "finish_reason": "stop"}
        return self.responses.pop(0)

    async def chat_completion_stream(self, *, messages, agent_type, tools, parallel_tool_calls, max_tokens=None, retry_enabled=True):
        assert agent_type == "finding"
        self.calls.append({"messages": messages, "tools": tools, "max_tokens": max_tokens, "stream": True, "retry_enabled": retry_enabled})
        if not self.responses:
            yield {"type": "done", "content": "{}", "usage": {}, "tool_calls": []}
            return
        for event in self.responses.pop(0):
            yield event


class FakeLLMServiceWithConfig(FakeLLMService):
    def __init__(self, *, provider: str, endpoint_protocol: str, tool_message_format: str = "auto"):
        super().__init__(responses=[])
        self.config = type(
            "Config",
            (),
            {
                "provider": type("Provider", (), {"value": provider})(),
                "endpoint_protocol": endpoint_protocol,
                "tool_message_format": tool_message_format,
            },
        )()


def build_session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_report_generation_tool_registry_excludes_skill_tool():
    bridge = FindingRuntimeBridge(
        llm_service=FakeLLMService([]),
        tools={
            "read_file": FakeAgentTool("read_file"),
            "list_files": FakeAgentTool("list_files"),
            "search_code": FakeAgentTool("search_code"),
            "Skill": FakeAgentTool("Skill"),
        },
    )

    tool_names = {tool.name for tool in bridge._build_report_generation_tool_registry().all_tools()}

    assert "FinalizeVulnerabilityReports" in tool_names
    assert {"Read", "Glob", "Grep"}.issubset(tool_names)
    assert "Skill" not in tool_names


def test_runtime_model_client_uses_openai_tool_messages_for_claude_openai_compatible():
    llm = FakeLLMServiceWithConfig(provider="claude", endpoint_protocol="openai_compatible")
    client = RuntimeLLMModelClient(llm_service=llm, agent_type="finding")

    assert client._resolve_tool_message_format().value == "openai_tools"


def test_runtime_model_client_uses_anthropic_blocks_for_anthropic_endpoint():
    llm = FakeLLMServiceWithConfig(provider="claude", endpoint_protocol="anthropic")
    client = RuntimeLLMModelClient(llm_service=llm, agent_type="finding")

    assert client._resolve_tool_message_format().value == "anthropic_blocks"


def test_bridge_finalizes_non_json_assistant_reply(monkeypatch):
    async def fake_adapter_run(self, *, project_id, task_id, system_prompt, recon_payload, user_message, model_name):
        session_id = self._session_store.create_session(
            project_id=project_id,
            task_id=task_id,
            runtime_stack="runtime",
            system_prompt=system_prompt,
            recon_payload=recon_payload,
        )
        self._session_store.append_message(
            session_id, TranscriptItem(role=RuntimeMessageRole.USER, content=user_message)
        )
        self._session_store.append_message(
            session_id, TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="??????????")
        )
        return {
            "session_id": session_id,
            "runner_result": None,
            "skill_route": {},
            "memory_counts": {"instruction": 0, "recall": 0},
        }

    async def fake_skill_preload(self, *, user_id, agent_type, context):
        class Snapshot:
            available_skills = []
            matched_skills = []
            prompt = ""
            route_message = ""
            route_plan = {}

        return Snapshot()

    async def fake_memory_preload(self, *, agent_type, system_prompt, recon_payload, user_message, skill_context=None):
        return RuntimeMemoryBundle()

    monkeypatch.setattr(
        "app.services.finding_runtime.adapters.finding.FindingRuntimeAdapter.run",
        fake_adapter_run,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.skills.RuntimeSkillCatalog.preload",
        fake_skill_preload,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.memory.RuntimeMemoryManager.preload",
        fake_memory_preload,
    )

    llm = FakeLLMService(
        responses=[
            [
                {
                    "type": "done",
                    "content": '{"findings": [], "summary": "???????"}',
                    "finish_reason": "stop",
                    "tool_calls": [],
                    "usage": {},
                }
            ]
        ]
    )
    bridge = FindingRuntimeBridge(
        llm_service=llm,
        tools={},
        session_factory=build_session_factory(),
    )

    result = asyncio.run(
        bridge.run(
            project_id="project-1",
            task_id="task-1",
            system_prompt="system",
            recon_payload={"repo": "demo"},
            user_message="inspect",
        )
    )

    assert result["final_payload"]["findings"] == []
    assert result["final_payload"]["summary"] == "???????"
    assert result["turn_count"] >= 0


def test_bridge_run_requires_terminal_action_for_main_audit_runner(monkeypatch):
    captured_runner_kwargs: list[dict] = []

    def fake_runner_init(self, **kwargs):
        captured_runner_kwargs.append(kwargs)

    async def fake_adapter_run(self, *, project_id, task_id, system_prompt, recon_payload, user_message, model_name):
        session_id = self._session_store.create_session(
            project_id=project_id,
            task_id=task_id,
            runtime_stack="runtime",
            system_prompt=system_prompt,
            recon_payload=recon_payload,
        )
        self._session_store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content=user_message))
        return {
            "session_id": session_id,
            "runner_result": TurnExecutionResult(
                turn_id="turn-1",
                stop_reason=RuntimeStopReason.COMPLETED,
            ),
            "skill_route": {},
            "memory_counts": {"instruction": 0, "recall": 0},
        }

    async def fake_ensure_payload(self, *, session_id, model_name, max_turns, model_client, runner_result, payload_extractor, finalizer_prompts, fallback_payload_builder=None):
        del model_name, max_turns, model_client, runner_result, payload_extractor, finalizer_prompts, fallback_payload_builder
        return self._session_store.load_session_snapshot(session_id), {"findings": [], "summary": "stub"}

    monkeypatch.setattr(
        "app.services.finding_runtime.bridge.FindingRuntimeRunner.__init__",
        fake_runner_init,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.adapters.finding.FindingRuntimeAdapter.run",
        fake_adapter_run,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.bridge.FindingRuntimeBridge._ensure_payload",
        fake_ensure_payload,
    )

    bridge = FindingRuntimeBridge(
        llm_service=FakeLLMService([]),
        tools={},
        session_factory=build_session_factory(),
    )

    asyncio.run(
        bridge.run(
            project_id="project-1",
            task_id="task-1",
            system_prompt="system",
            recon_payload={"repo": "demo"},
            user_message="inspect",
        )
    )

    assert captured_runner_kwargs[0]["require_terminal_action"] is True
    assert captured_runner_kwargs[0]["terminal_action_nudge_limit"] == 2


def test_continue_dialogue_session_syncs_resume_instruction_and_nudges_empty_response():
    session_factory = build_session_factory()
    llm = FakeLLMService(
        responses=[
            [
                {
                    "type": "done",
                    "content": "",
                    "reasoning_content": "",
                    "finish_reason": "stop",
                    "tool_calls": [],
                    "usage": {},
                }
            ]
        ]
    )
    bridge = FindingRuntimeBridge(llm_service=llm, tools={}, session_factory=session_factory)
    session_id = bridge._session_store.create_session(project_id="project-1", system_prompt="system")
    bridge._session_store.append_message(
        session_id,
        TranscriptItem(role=RuntimeMessageRole.USER, content="continue the audit"),
    )

    asyncio.run(
        bridge.continue_dialogue_session(
            session_id=session_id,
            model_name="finding-runtime",
            max_turns=1,
        )
    )

    snapshot = bridge._session_store.load_session_snapshot(session_id)
    state = bridge._session_store.load_query_loop_state(session_id)
    assert snapshot.messages[-1].name == "runtime_resume"
    assert any(message.name == "runtime_resume" for message in state.messages)
    assert state.messages[-1].name == "empty_model_response_nudge"
    assert snapshot.checkpoints[-1].state_payload["error_kind"] == "empty_model_response"


def test_agent_runtime_bridge_uses_finding_spec_without_changing_runner_contract(monkeypatch):
    from app.services.agent_runtime.bridge import AgentRuntimeBridge
    from app.services.agent_runtime.specs import build_finding_runtime_spec

    captured_runner_kwargs: list[dict] = []

    def fake_runner_init(self, **kwargs):
        captured_runner_kwargs.append(kwargs)

    async def fake_adapter_run(self, *, project_id, task_id, system_prompt, recon_payload, user_message, model_name):
        session_id = self._session_store.create_session(
            project_id=project_id,
            task_id=task_id,
            runtime_stack="runtime",
            system_prompt=system_prompt,
            recon_payload=recon_payload,
        )
        self._session_store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content=user_message))
        return {
            "session_id": session_id,
            "runner_result": TurnExecutionResult(
                turn_id="turn-1",
                stop_reason=RuntimeStopReason.COMPLETED,
            ),
            "skill_route": {},
            "memory_counts": {"instruction": 0, "recall": 0},
        }

    async def fake_ensure_payload(self, *, session_id, model_name, max_turns, model_client, runner_result, payload_extractor, finalizer_prompts, fallback_payload_builder=None):
        del model_name, max_turns, model_client, runner_result, payload_extractor, finalizer_prompts, fallback_payload_builder
        return self._session_store.load_session_snapshot(session_id), {"findings": [], "summary": "stub"}

    monkeypatch.setattr(
        "app.services.agent_runtime.bridge.FindingRuntimeRunner.__init__",
        fake_runner_init,
    )
    monkeypatch.setattr(
        "app.services.agent_runtime.bridge.AgentRuntimeAdapter.run",
        fake_adapter_run,
    )
    monkeypatch.setattr(
        "app.services.agent_runtime.bridge.AgentRuntimeBridge._ensure_payload",
        fake_ensure_payload,
    )

    bridge = AgentRuntimeBridge(
        llm_service=FakeLLMService([]),
        tools={},
        spec=build_finding_runtime_spec(),
        session_factory=build_session_factory(),
    )

    result = asyncio.run(
        bridge.run(
            project_id="project-1",
            task_id="task-1",
            system_prompt="system",
            recon_payload={"repo": "demo"},
            user_message="inspect",
        )
    )

    assert result["final_payload"] == {"findings": [], "summary": "stub"}
    assert captured_runner_kwargs[0]["require_terminal_action"] is True
    assert captured_runner_kwargs[0]["terminal_action_nudge_limit"] == 2
    assert "FinalizeFinding" in [tool["name"] for tool in bridge._build_tool_registry().describe_tools()]


def test_bridge_attempts_finalizer_after_incomplete_terminal_action():
    result = TurnExecutionResult(
        turn_id="turn-1",
        stop_reason=RuntimeStopReason.COMPLETED,
        terminal_action=RuntimeTerminalAction.NATURAL_END_WITHOUT_TERMINAL_ACTION,
        completion_mode=RuntimeCompletionMode.INCOMPLETE,
    )

    assert FindingRuntimeBridge._should_attempt_finalizer(result) is True


def test_bridge_finalizer_prompt_does_not_force_empty_findings_for_incomplete_audit():
    bridge = FindingRuntimeBridge(llm_service=FakeLLMService([]), tools={}, session_factory=build_session_factory())

    prompt = bridge._default_finalizer_prompts()[0]

    assert "只有在审计已经完成" in prompt
    assert "如果仍需继续查看文件、验证调用链、补齐 source/sink/PoC/影响面" in prompt
    assert "证据不足" not in prompt


def test_bridge_fallback_summary_uses_last_assistant_message():
    session_factory = build_session_factory()
    bridge = FindingRuntimeBridge(llm_service=FakeLLMService([]), tools={}, session_factory=session_factory)
    store = bridge._session_store
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"))
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="???? OpenApiController ? GLUE ?????"))
    snapshot = store.load_session_snapshot(session_id)

    summary = bridge._fallback_summary(snapshot)

    assert "最后一条 assistant 回复" in summary
    assert "OpenApiController" in summary


def test_bridge_fallback_payload_recovers_findings_from_assistant_transcript():
    session_factory = build_session_factory()
    bridge = FindingRuntimeBridge(llm_service=FakeLLMService([]), tools={}, session_factory=session_factory)
    store = bridge._session_store
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"))
    store.append_message(
        session_id,
        TranscriptItem(
            role=RuntimeMessageRole.ASSISTANT,
            content=(
                "Thought: 鐜板湪璁╂垜娣卞叆纭鍑犱釜鍏抽敭鍙戠幇骞堕獙璇佸畬鏁村埄鐢ㄩ摼銆俓n"
                "1. `/user/invited` 娉ㄥ唽闄愬埗缁曡繃 - 鏄庣‘纭\n"
                "2. `unpinDashboard` IDOR - 鏄庣‘纭\n"
                "3. 鏁版嵁搴撹繛鎺ユ祴璇?SSRF锛圡ySQL/MongoDB 鏃?outbound 绛栫暐锛塡n"
                "4. `/chart/:chart_id/query` 鏈璇佺鐐筡n"
            ),
        ),
    )
    snapshot = store.load_session_snapshot(session_id)

    payload = bridge._default_fallback_payload(snapshot)
    assert payload["findings"] == []
    assert len(payload["recovered_candidates"]) >= 2
    assert {finding["vulnerability_type"] for finding in payload["recovered_candidates"]} >= {"idor", "ssrf"}
    assert all(candidate["needs_verification"] is True for candidate in payload["recovered_candidates"])
    assert "候选线索" in payload["summary"]
    assert "不是最终漏洞结论" in payload["summary"]


def test_bridge_fallback_payload_marks_recovered_candidates_as_incomplete():
    session_factory = build_session_factory()
    bridge = FindingRuntimeBridge(llm_service=FakeLLMService([]), tools={}, session_factory=session_factory)
    store = bridge._session_store
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"))
    store.append_message(
        session_id,
        TranscriptItem(
            role=RuntimeMessageRole.ASSISTANT,
            content="关键发现：`convertUrlRoute` 可能存在 SSRF。我需要查看 tasks.go 的请求拦截逻辑。",
        ),
    )
    snapshot = store.load_session_snapshot(session_id)

    payload = bridge._default_fallback_payload(snapshot)

    assert payload["findings"] == []
    assert payload["runtime_completion_mode"] == "incomplete"
    assert payload["is_final"] is False
    assert payload["requires_retry"] is True
    assert "不是最终漏洞结论" in payload["summary"]


def test_bridge_exposes_restored_style_runtime_tools():
    bridge = FindingRuntimeBridge(
        llm_service=FakeLLMService([]),
        tools={
            "read_file": FakeAgentTool("read_file"),
            "read_many_files": FakeAgentTool("read_many_files"),
            "list_files": FakeAgentTool("list_files"),
            "search_code": FakeAgentTool("search_code"),
            "think": FakeAgentTool("think"),
        },
        session_factory=build_session_factory(),
    )

    tool_names = [item["name"] for item in bridge._build_tool_registry().describe_tools()]

    assert "Read" in tool_names
    assert "Glob" in tool_names
    assert "Grep" in tool_names
    assert "Write" in tool_names
    assert "Skill" in tool_names
    assert "TodoWrite" in tool_names
    assert "AskUser" in tool_names
    assert "EnterPlanMode" in tool_names
    assert "ExitPlanMode" in tool_names
    assert "read_many_files" not in tool_names


def test_bridge_exposes_shell_runtime_tools_when_shell_backend_is_available(monkeypatch):
    read_tool = FakeAgentTool("read_file")
    read_tool.project_root = "D:/repo"
    list_tool = FakeAgentTool("list_files")
    list_tool.project_root = "D:/repo"
    search_tool = FakeAgentTool("search_code")
    search_tool.project_root = "D:/repo"

    monkeypatch.setattr("app.services.runtime_core.runtime_tool_registry.detect_bash_executable", lambda: None)
    monkeypatch.setattr("app.services.runtime_core.runtime_tool_registry.detect_powershell_executable", lambda: "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
    monkeypatch.setattr("app.services.runtime_core.runtime_tool_registry.is_powershell_runtime_tool_enabled", lambda: True)

    bridge = FindingRuntimeBridge(
        llm_service=FakeLLMService([]),
        tools={
            "read_file": read_tool,
            "list_files": list_tool,
            "search_code": search_tool,
            "sandbox_exec": FakeAgentTool("sandbox_exec"),
        },
        session_factory=build_session_factory(),
    )

    tool_names = [item["name"] for item in bridge._build_tool_registry().describe_tools()]

    assert "Bash" in tool_names
    assert "PowerShell" in tool_names


def test_bridge_skips_system_transcript_messages_when_building_model_payload():
    llm = FakeLLMService([{"content": "{}", "finish_reason": "stop", "tool_calls": []}])
    client = FindingRuntimeBridge(llm_service=llm, tools={}, session_factory=build_session_factory())
    model_client = client._llm_service
    del model_client
    runtime_client = client.__class__.__dict__  # keep bridge imported
    del runtime_client

    llm_client = __import__("app.services.finding_runtime.bridge", fromlist=["RuntimeLLMModelClient"]).RuntimeLLMModelClient(
        llm_service=llm,
        agent_type="finding",
    )
    asyncio.run(
        llm_client.complete(
            system_prompt="base prompt",
            recon_payload={"repo": "demo"},
            transcript=[
                TranscriptItem(role=RuntimeMessageRole.SYSTEM, content="should be skipped"),
                TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"),
            ],
            model_name="finding",
            tool_definitions=[],
        )
    )

    assert len(llm.calls[-1]["messages"]) == 2
    assert llm.calls[-1]["messages"][0]["role"] == "system"
    assert "Runtime recon payload" in llm.calls[-1]["messages"][0]["content"]
    assert llm.calls[-1]["messages"][1] == {"role": "user", "content": "inspect"}


def test_native_tool_calling_reminder_requires_actual_tool_call_or_terminal_json():
    assert "工具调用协议" in NATIVE_TOOL_CALLING_REMINDER
    assert "必须在同一条 assistant 响应中实际发起原生结构化工具调用" in NATIVE_TOOL_CALLING_REMINDER
    assert "如果还需要证据：直接调用 Read/Grep/Glob/Skill/PowerShell" in NATIVE_TOOL_CALLING_REMINDER
    assert '输出可解析的 {"findings": [...], "summary": "..."} JSON' in NATIVE_TOOL_CALLING_REMINDER
    assert "禁止只回复“我将继续/让我继续/下一步我会...”" in NATIVE_TOOL_CALLING_REMINDER
    assert "不要输出伪工具语法" in NATIVE_TOOL_CALLING_REMINDER


def test_bridge_extracts_json_from_mixed_final_answer():
    payload = FindingRuntimeBridge._parse_payload(
        "Thought: enough evidence collected.\nFinal Answer: {\"findings\": [{\"title\": \"auth bypass\"}], \"summary\": \"done\"}"
    )

    assert payload == {"findings": [{"title": "auth bypass"}], "summary": "done"}


def test_runtime_model_client_formats_tool_error_result_as_structured_feedback():
    mapped = RuntimeLLMModelClient._map_transcript_item(
        TranscriptItem(
            role=RuntimeMessageRole.TOOL_RESULT,
            content="Invalid input for tool 'FinalizeFinding': summary: Field required",
            name="FinalizeFinding",
            metadata={"status": "invalid", "is_error": True, "duration_ms": 7},
            payload={
                "tool_use_id": "tool-1",
                "tool_call_id": "call-1",
                "tool_name": "FinalizeFinding",
                "input": {"findings": [{"title": "SSRF"}]},
                "output": {},
                "error_message": "Invalid input for tool 'FinalizeFinding': summary: Field required",
            },
        )
    )

    assert mapped is not None
    assert mapped["role"] == "user"
    assert "工具执行失败" in mapped["content"]
    assert '"tool_name": "FinalizeFinding"' in mapped["content"]
    assert '"is_error": true' in mapped["content"]
    assert '"status": "invalid"' in mapped["content"]


def test_runtime_model_client_complete_stream_emits_tokens_and_returns_tool_calls():
    llm = FakeLLMService(
        responses=[
            [
                {"type": "token", "content": "Need ", "accumulated": "Need "},
                {"type": "token", "content": "tool", "accumulated": "Need tool"},
                {
                    "type": "done",
                    "content": "Need tool",
                    "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "name": "Read",
                            "arguments": "{\"file_path\":\"main.py\"}",
                        }
                    ],
                    "finish_reason": "stop",
                },
            ]
        ]
    )
    client = RuntimeLLMModelClient(llm_service=llm, agent_type="finding")

    streamed_events = []

    async def run():
        return await client.complete_stream(
            system_prompt="system",
            recon_payload={"repo": "demo"},
            transcript=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect")],
            model_name="finding",
            tool_definitions=[
                {
                    "name": "Read",
                    "description": "Read a file",
                    "input_schema": {"type": "object", "properties": {}},
                }
            ],
            on_event=streamed_events.append,
        )

    response = asyncio.run(run())

    assert [event["type"] for event in streamed_events] == ["token", "token", "done"]
    assert response.content == "Need tool"
    assert response.tool_calls == [{"id": "call-1", "name": "Read", "input": {"file_path": "main.py"}}]


def test_bridge_run_chat_session_stream_emits_runtime_events():
    llm = FakeLLMService(
        responses=[
            [
                {"type": "token", "content": "run ", "accumulated": "run "},
                {"type": "token", "content": "chat", "accumulated": "run chat"},
                {
                    "type": "done",
                    "content": "run chat",
                    "usage": {"prompt_tokens": 4, "completion_tokens": 4, "total_tokens": 8},
                    "tool_calls": [],
                    "finish_reason": "stop",
                },
            ]
        ]
    )
    bridge = FindingRuntimeBridge(
        llm_service=llm,
        tools={},
        session_factory=build_session_factory(),
    )

    streamed_events = []

    async def run():
        return await bridge.run_chat_session_stream(
            project_id="project-1",
            task_id=None,
            system_prompt="system",
            recon_payload={"repo": "demo"},
            user_message="inspect",
            event_sink=streamed_events.append,
        )

    result = asyncio.run(run())

    assert result["session_id"]
    assert [event["type"] for event in streamed_events] == ["assistant_start", "token", "token", "done"]
    assert streamed_events[-1]["message"]["content"] == "run chat"


def test_bridge_continue_session_refreshes_skill_catalog(monkeypatch):
    async def fake_skill_preload(self, *, user_id, agent_type, context):
        class Snapshot:
            available_skills = [
                {
                    "id": "new-skill",
                    "slug": "new-skill",
                    "name": "New Skill",
                    "description": "Added after session start",
                    "source_type": "manual",
                }
            ]
            matched_skills = list(available_skills)
            prompt = "fresh skill prompt"
            route_message = "use new skill if it helps"
            route_plan = {"primary_skill": "new-skill", "secondary_skills": []}

        assert context["task"] == "continue audit"
        return Snapshot()

    async def fake_run_once(self, *, session_id, model_name):
        return {"status": "continued", "session_id": session_id, "model_name": model_name}

    async def fake_ensure_payload(self, *, session_id, model_name, max_turns, model_client, runner_result, payload_extractor, finalizer_prompts, fallback_payload_builder=None):
        del model_name, max_turns, model_client, runner_result, payload_extractor, finalizer_prompts, fallback_payload_builder
        return self._session_store.load_session_snapshot(session_id), {"findings": [], "summary": "continued"}

    monkeypatch.setattr(
        "app.services.finding_runtime.skills.RuntimeSkillCatalog.preload",
        fake_skill_preload,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.bridge.FindingRuntimeRunner.run_once",
        fake_run_once,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.bridge.FindingRuntimeBridge._ensure_payload",
        fake_ensure_payload,
    )

    bridge = FindingRuntimeBridge(
        llm_service=FakeLLMService([]),
        tools={},
        session_factory=build_session_factory(),
    )
    store = bridge._session_store
    session_id = store.create_session(
        project_id="project-1",
        system_prompt="base system prompt",
        recon_payload={"project_info": {"name": "demo"}},
        runtime_stack="runtime",
    )
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="continue audit"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["base_system_prompt"] = "base system prompt"
    runtime_state.metadata["last_user_message"] = "continue audit"
    store.replace_runtime_state(session_id, runtime_state)

    result = asyncio.run(bridge.continue_session(session_id=session_id, model_name="finding-runtime"))

    snapshot = store.load_session_snapshot(session_id)
    refreshed_runtime_state = store.load_runtime_state(session_id)

    assert result["final_payload"] == {"findings": [], "summary": "continued"}
    assert [skill.skill_ref for skill in snapshot.skills] == ["new-skill"]
    assert "fresh skill prompt" in (snapshot.session.system_prompt or "")
    assert "use new skill if it helps" in (snapshot.session.system_prompt or "")
    assert refreshed_runtime_state.metadata["skill_catalog"]["finding"]["available_skills"] == ["new-skill"]
    assert refreshed_runtime_state.metadata["last_user_message"] == "continue audit"
def test_bridge_continue_session_uses_discovery_selected_skill(monkeypatch):
    async def fake_skill_preload(self, *, user_id, agent_type, context):
        class Snapshot:
            available_skills = [
                {
                    "id": "code-audit",
                    "slug": "code-audit",
                    "name": "Code Audit",
                    "description": "General audit skill",
                    "tags": ["audit", "security"],
                    "match_keywords": ["audit"],
                    "always_include": False,
                    "skill_metadata": {"frontmatter": {"when_to_use": "Audit source code."}},
                    "paths": {"skill_file_path": "skill_library/code-audit/SKILL.md"},
                },
                {
                    "id": "cve-report-writer",
                    "slug": "cve-report-writer",
                    "name": "CVE Report Writer",
                    "description": "Write vulnerability reports",
                    "tags": ["report", "cve"],
                    "match_keywords": ["report", "cve"],
                    "always_include": False,
                    "skill_metadata": {"frontmatter": {"when_to_use": "Write vulnerability reports."}},
                    "paths": {"skill_file_path": "skill_library/cve-report-writer/SKILL.md"},
                },
            ]
            matched_skills = list(available_skills)
            prompt = "static prompt"
            route_message = "static route message"
            route_plan = {"primary_skill": "code-audit", "secondary_skills": ["cve-report-writer"]}

        return Snapshot()

    async def fake_run_once(self, *, session_id, model_name):
        return {"status": "continued", "session_id": session_id, "model_name": model_name}

    async def fake_ensure_payload(self, *, session_id, model_name, max_turns, model_client, runner_result, payload_extractor, finalizer_prompts, fallback_payload_builder=None):
        del model_name, max_turns, model_client, runner_result, payload_extractor, finalizer_prompts, fallback_payload_builder
        return self._session_store.load_session_snapshot(session_id), {"findings": [], "summary": "continued"}

    async def fake_get_skill_body(user_id, skill_ref, agent_type=None):
        del user_id, agent_type
        raise AssertionError(f"discovery must not auto-load skill body for {skill_ref}")

    monkeypatch.setattr(
        "app.services.finding_runtime.skills.RuntimeSkillCatalog.preload",
        fake_skill_preload,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.bridge.FindingRuntimeRunner.run_once",
        fake_run_once,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.bridge.FindingRuntimeBridge._ensure_payload",
        fake_ensure_payload,
    )
    monkeypatch.setattr(
        "app.services.agent.skill_service.SkillService.get_skill_body",
        fake_get_skill_body,
    )

    bridge = FindingRuntimeBridge(
        llm_service=FakeLLMService([]),
        tools={},
        session_factory=build_session_factory(),
    )
    store = bridge._session_store
    session_id = store.create_session(
        project_id="project-1",
        system_prompt="base system prompt",
        recon_payload={"project_info": {"name": "demo"}},
        runtime_stack="runtime",
    )
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="use the report writer skill to draft the CVE report"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["base_system_prompt"] = "base system prompt"
    runtime_state.metadata["last_user_message"] = "use the report writer skill to draft the CVE report"
    store.replace_runtime_state(session_id, runtime_state)

    asyncio.run(bridge.continue_session(session_id=session_id, model_name="finding-runtime"))

    snapshot = store.load_session_snapshot(session_id)
    refreshed_runtime_state = store.load_runtime_state(session_id)

    assert "Discovery scheduler selected: cve-report-writer" in (snapshot.session.system_prompt or "")
    assert "bootstrap for cve-report-writer" not in (snapshot.session.system_prompt or "")
    assert store.list_skill_invocations(session_id) == []
    assert refreshed_runtime_state.metadata["skill_discovery"]["finding"]["selected_skill"] == "cve-report-writer"

def test_runtime_model_client_classifies_max_output_tokens_responses():
    llm = FakeLLMService([
        {
            "content": "partial answer",
            "finish_reason": "length",
            "tool_calls": [],
        }
    ])
    llm_client = __import__("app.services.finding_runtime.bridge", fromlist=["RuntimeLLMModelClient"]).RuntimeLLMModelClient(
        llm_service=llm,
        agent_type="finding",
    )

    response = asyncio.run(
        llm_client.complete(
            system_prompt="system",
            recon_payload={},
            transcript=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect")],
            model_name="finding",
            tool_definitions=[],
        )
    )

    assert response.recoverable_error_kind == "max_output_tokens"
    assert response.content == "partial answer"


def test_runtime_model_client_classifies_prompt_too_long_errors():
    llm = FakeLLMService([
        {
            "content": "",
            "finish_reason": "stop",
            "tool_calls": [],
            "error_type": "prompt_too_long",
            "error_message": "context too large",
        }
    ])
    llm_client = __import__("app.services.finding_runtime.bridge", fromlist=["RuntimeLLMModelClient"]).RuntimeLLMModelClient(
        llm_service=llm,
        agent_type="finding",
    )

    response = asyncio.run(
        llm_client.complete(
            system_prompt="system",
            recon_payload={},
            transcript=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect")],
            model_name="finding",
            tool_definitions=[],
        )
    )

    assert response.recoverable_error_kind == "prompt_too_long"
    assert response.recoverable_error_message == "context too large"


def test_bridge_skips_finalizer_for_non_finalizable_terminal_reason(monkeypatch):
    async def fake_refresh_session_context(self, *, session_id):
        del self, session_id
        return None

    async def fake_run_once(self, *, session_id, model_name):
        del self, session_id, model_name
        return TurnExecutionResult(turn_id="turn-1", stop_reason=RuntimeStopReason.PROMPT_TOO_LONG)

    monkeypatch.setattr(
        "app.services.finding_runtime.adapters.finding.FindingRuntimeAdapter.refresh_session_context",
        fake_refresh_session_context,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.bridge.FindingRuntimeRunner.run_once",
        fake_run_once,
    )

    llm = FakeLLMService([
        {
            "content": '{"findings": [], "summary": "should not be used"}',
            "finish_reason": "stop",
            "tool_calls": [],
        }
    ])
    bridge = FindingRuntimeBridge(
        llm_service=llm,
        tools={},
        session_factory=build_session_factory(),
    )
    store = bridge._session_store
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"))
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="context window exhausted"))

    result = asyncio.run(
        bridge.continue_session_until_payload(
            session_id=session_id,
            model_name="finding-runtime",
            payload_extractor=bridge.extract_final_payload,
            finalizer_prompts=bridge._default_finalizer_prompts(),
            fallback_payload_builder=bridge._default_fallback_payload,
        )
    )

    assert result["final_payload"]["findings"] == []
    assert "context window exhausted" in result["final_payload"]["summary"]
    assert llm.calls == []




def test_runtime_model_client_passes_max_output_tokens_override_to_llm_service():
    llm = FakeLLMService([
        {
            "content": "partial answer",
            "finish_reason": "stop",
            "tool_calls": [],
        }
    ])
    llm_client = __import__("app.services.finding_runtime.bridge", fromlist=["RuntimeLLMModelClient"]).RuntimeLLMModelClient(
        llm_service=llm,
        agent_type="finding",
    )

    asyncio.run(
        llm_client.complete(
            system_prompt="system",
            recon_payload={},
            transcript=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect")],
            model_name="finding",
            tool_definitions=[],
            max_output_tokens_override=64000,
        )
    )

    assert llm.calls[-1]["max_tokens"] == 64000


def test_continue_session_until_payload_adds_auto_finalizer_prompt(monkeypatch):
    async def fake_refresh_session_context(self, session_id: str):
        return None

    async def fake_run_once(self, *, session_id: str, model_name: str):
        return TurnExecutionResult(turn_id="turn-1", stop_reason=RuntimeStopReason.COMPLETED)

    monkeypatch.setattr(
        "app.services.finding_runtime.adapters.finding.FindingRuntimeAdapter.refresh_session_context",
        fake_refresh_session_context,
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.bridge.FindingRuntimeRunner.run_once",
        fake_run_once,
    )

    bridge = FindingRuntimeBridge(
        llm_service=FakeLLMService([]),
        tools={},
        session_factory=build_session_factory(),
    )
    store = bridge._session_store
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"))
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="natural stop"))

    result = asyncio.run(
        bridge.continue_session_until_payload(
            session_id=session_id,
            model_name="finding-runtime",
            payload_extractor=bridge.extract_final_payload,
            finalizer_prompts=bridge._default_finalizer_prompts(),
            fallback_payload_builder=bridge._default_fallback_payload,
        )
    )

    snapshot = store.load_session_snapshot(session_id)
    finalization_prompts = [
        item
        for item in snapshot.messages
        if (
            isinstance(getattr(item, "metadata", None), dict)
            and item.metadata.get("kind") == "finalization_prompt"
        )
        or (
            isinstance(getattr(item, "message_metadata", None), dict)
            and item.message_metadata.get("kind") == "finalization_prompt"
        )
    ]

    assert result["final_payload"]["findings"] == []
    assert len(finalization_prompts) == 1
    assert "FinalizeFinding" in finalization_prompts[0].content



def test_runtime_model_client_stream_complete_emits_tool_call_events_before_done():
    class StreamingLLMService(FakeLLMService):
        async def chat_completion_stream(self, *, messages, agent_type, tools, parallel_tool_calls, max_tokens=None, retry_enabled=True):
            self.calls.append({"messages": messages, "tools": tools, "max_tokens": max_tokens, "streaming": True, "retry_enabled": retry_enabled})
            yield {"type": "token", "content": "Need ", "accumulated": "Need "}
            yield {"type": "tool_call", "tool_call": {"id": "tool-1", "name": "Read", "input": {"file_path": "README.md"}}}
            yield {"type": "done", "content": "Need tool", "finish_reason": "stop"}

    llm = StreamingLLMService([])
    llm_client = __import__("app.services.finding_runtime.bridge", fromlist=["RuntimeLLMModelClient"]).RuntimeLLMModelClient(
        llm_service=llm,
        agent_type="finding",
    )

    async def collect_events():
        events = []
        async for event in llm_client.stream_complete(
            system_prompt="system",
            recon_payload={},
            transcript=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect")],
            model_name="finding",
            tool_definitions=[{"name": "Read", "description": "read", "input_schema": {"type": "object"}}],
        ):
            events.append(event)
        return events

    events = asyncio.run(collect_events())

    assert [event["type"] for event in events] == ["content_delta", "tool_call", "done"]
    assert events[1]["tool_call"]["name"] == "Read"
    assert events[2]["content"] == "Need tool"
    assert llm.calls[0]["retry_enabled"] is False


def test_runtime_model_client_stream_complete_does_not_reemit_done_tool_calls():
    class StreamingLLMService(FakeLLMService):
        async def chat_completion_stream(self, *, messages, agent_type, tools, parallel_tool_calls, max_tokens=None):
            self.calls.append({"messages": messages, "tools": tools, "max_tokens": max_tokens, "streaming": True})
            yield {"type": "token", "content": "Need ", "accumulated": "Need "}
            yield {"type": "tool_call", "tool_call": {"id": "tool-1", "name": "Read", "input": {"file_path": "README.md"}}}
            yield {
                "type": "done",
                "content": "Need tool",
                "finish_reason": "tool_calls",
                "tool_calls": [
                    {"id": "tool-1", "name": "Read", "input": {"file_path": "README.md"}},
                ],
            }

    llm = StreamingLLMService([])
    llm_client = __import__("app.services.finding_runtime.bridge", fromlist=["RuntimeLLMModelClient"]).RuntimeLLMModelClient(
        llm_service=llm,
        agent_type="finding",
    )

    async def collect_events():
        events = []
        async for event in llm_client.stream_complete(
            system_prompt="system",
            recon_payload={},
            transcript=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect")],
            model_name="finding",
            tool_definitions=[{"name": "Read", "description": "read", "input_schema": {"type": "object"}}],
        ):
            events.append(event)
        return events

    events = asyncio.run(collect_events())

    assert [event["type"] for event in events] == ["content_delta", "tool_call", "done"]
    assert [event["tool_call"]["id"] for event in events if event["type"] == "tool_call"] == ["tool-1"]
    assert events[-1]["tool_calls"][0]["id"] == "tool-1"


def test_runtime_model_client_stream_complete_passthroughs_llm_retry_events():
    class StreamingLLMService(FakeLLMService):
        async def chat_completion_stream(self, *, messages, agent_type, tools, parallel_tool_calls, max_tokens=None):
            self.calls.append({"messages": messages, "tools": tools, "max_tokens": max_tokens, "streaming": True})
            yield {
                "type": "llm_retry",
                "attempt": 1,
                "max_attempts": 3,
                "message_text": "模型服务暂时不可用，正在进行第 1/3 次自动重试……",
                "error_type": "connection",
            }
            yield {"type": "done", "content": "恢复完成", "finish_reason": "stop"}

    llm = StreamingLLMService([])
    llm_client = __import__("app.services.finding_runtime.bridge", fromlist=["RuntimeLLMModelClient"]).RuntimeLLMModelClient(
        llm_service=llm,
        agent_type="finding",
    )

    async def collect_events():
        events = []
        async for event in llm_client.stream_complete(
            system_prompt="system",
            recon_payload={},
            transcript=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect")],
            model_name="finding",
            tool_definitions=[{"name": "Read", "description": "read", "input_schema": {"type": "object"}}],
        ):
            events.append(event)
        return events

    events = asyncio.run(collect_events())

    assert [event["type"] for event in events] == ["llm_retry", "done"]
    assert events[0]["attempt"] == 1
    assert "自动重试" in events[0]["message_text"]
    assert events[1]["content"] == "恢复完成"


def test_runtime_model_client_tool_use_history_is_mapped_as_user_context_note():
    mapped = RuntimeLLMModelClient._map_transcript_item(
        TranscriptItem(
            role=RuntimeMessageRole.TOOL_USE,
            content="Write",
            name="Write",
            payload={
                "tool_use_id": "tool-1",
                "tool_name": "Write",
                "input": {"path": ".auditai/findings.json", "content": "{}"},
            },
        )
    )

    assert mapped is not None
    assert mapped["role"] == "user"
    assert "Tool Call:" not in mapped["content"]
    assert "先前工具请求历史" in mapped["content"]


def test_runtime_model_client_build_messages_uses_native_openai_tool_history():
    messages = RuntimeLLMModelClient._build_messages(
        system_prompt="system",
        recon_payload={},
        tool_definitions=[{"name": "Read"}],
        transcript=[
            TranscriptItem(role=RuntimeMessageRole.USER, content="inspect"),
            TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="Reading."),
            TranscriptItem(
                role=RuntimeMessageRole.TOOL_USE,
                content="",
                name="Read",
                payload={
                    "tool_use_id": "tool-use-1",
                    "tool_name": "Read",
                    "input": {"path": "src/auth.py"},
                },
            ),
            TranscriptItem(
                role=RuntimeMessageRole.TOOL_RESULT,
                content="source",
                name="Read",
                payload={"tool_use_id": "tool-use-1", "tool_name": "Read"},
            ),
        ],
    )

    assert messages[2]["role"] == "assistant"
    assert messages[2]["tool_calls"][0]["id"] == "tool-use-1"
    assert messages[3] == {
        "role": "tool",
        "tool_call_id": "tool-use-1",
        "name": "Read",
        "content": "source",
    }

def test_runtime_model_client_assistant_history_sanitizes_legacy_text_tool_calls_into_user_context_note():
    mapped = RuntimeLLMModelClient._map_transcript_item(
        TranscriptItem(
            role=RuntimeMessageRole.ASSISTANT,
            content='Tool Call: Write\n{"input":{"path":".auditai/findings.json","content":"{}"}}',
        )
    )

    assert mapped is not None
    assert mapped["role"] == "user"
    assert "Tool Call:" not in mapped["content"]
    assert "先前工具请求历史" in mapped["content"]
