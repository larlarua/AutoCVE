from __future__ import annotations

import asyncio
import json

from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.audit_session import AuditSkillInvocationStatus, AuditToolCallStatus
from app.services.finding_runtime.models import (
    RuntimeCompletionMode,
    RuntimeContinueReason,
    RuntimeMessageRole,
    RuntimeStopReason,
    RuntimeTerminalAction,
    ToolExecutionPayload,
    TranscriptItem,
)
from app.services.finding_runtime.query_loop import QueryLoop
from app.services.runtime_core.tool_search_runtime import ToolSearchRuntimeTool
from app.services.finding_runtime.query_state import QueryLoopState
from app.services.finding_runtime.runner import FindingRuntimeRunner
from app.services.finding_runtime.session_store import AuditSessionPersistenceError, AuditSessionStore
from app.services.finding_runtime.skills import RuntimeSkillTool
from app.services.finding_runtime.tools.finalize_finding import FinalizeFindingTool
from app.services.finding_runtime.tooling import RuntimeTool, ToolExecutionContext, ToolOrchestrator, ToolRegistry


class FakeModelClient:
    def __init__(self, responses: list[dict] | None = None, content: str = "assistant reply"):
        self._responses = list(responses or [])
        self.content = content
        self.calls = []

    async def complete(self, *, system_prompt, recon_payload, transcript, model_name, tool_definitions, max_output_tokens_override=None):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "recon_payload": recon_payload,
                "transcript": transcript,
                "model_name": model_name,
                "tool_definitions": tool_definitions,
                "max_output_tokens_override": max_output_tokens_override,
            }
        )
        if self._responses:
            return self._responses.pop(0)
        return {
            "content": self.content,
            "stop_reason": RuntimeStopReason.COMPLETED.value,
        }


class StreamingFakeModelClient(FakeModelClient):
    def __init__(self, stream_events: list[dict[str, object]]):
        super().__init__(responses=[])
        self._stream_events = list(stream_events)

    async def stream_complete(self, *, system_prompt, recon_payload, transcript, model_name, tool_definitions, max_output_tokens_override=None):
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "recon_payload": recon_payload,
                "transcript": transcript,
                "model_name": model_name,
                "tool_definitions": tool_definitions,
                "max_output_tokens_override": max_output_tokens_override,
                "streaming": True,
            }
        )
        for event in self._stream_events:
            yield dict(event)


class EchoInput(BaseModel):
    text: str


class EchoTool(RuntimeTool):
    name = "echo"
    description = "Echo text"
    input_model = EchoInput

    def is_concurrency_safe(self, parsed_input: EchoInput) -> bool:
        return True

    async def execute(self, parsed_input: EchoInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        return ToolExecutionPayload(
            content=f"echo:{parsed_input.text}",
            output_payload={"echo": parsed_input.text},
        )


class FakeSkillService:
    @staticmethod
    async def get_skill_body(user_id, skill_ref, agent_type=None):
        return {"skill": skill_ref, "content": "body"}

    @staticmethod
    async def list_skill_resources(user_id, skill_ref, resource_name="", agent_type=None):
        return {"skill": skill_ref, "mode": "list", "resource_name": resource_name, "items": []}

    @staticmethod
    async def get_skill_resource(user_id, skill_ref, resource_name, agent_type=None):
        return {"skill": skill_ref, "resource": resource_name, "content": "resource body"}


def build_store() -> AuditSessionStore:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    return AuditSessionStore(session_factory=session_factory)


def _messages_without_system(snapshot):
    return [message for message in snapshot.messages if message.role != RuntimeMessageRole.SYSTEM.value]


def _valid_finalize_input() -> dict:
    return {
        "findings": [
            {
                "vulnerability_type": "ssrf",
                "severity": "high",
                "title": "SSRF in webhook fetcher",
                "description": "The webhook fetcher accepts a user-controlled URL and fetches it without an SSRF allowlist.",
                "file_path": "pkg/modules/webhook/webhook.go",
                "line_start": 99,
                "line_end": 131,
                "code_snippet": "target := r.Header.Get(\"Gotenberg-Webhook-Url\")",
                "source": "HTTP header Gotenberg-Webhook-Url",
                "sink": "retryablehttp client request to the supplied webhook URL",
                "suggestion": "Validate webhook URLs with a strict allowlist and block loopback/link-local/private ranges.",
                "confidence": 0.95,
                "needs_verification": True,
                "verdict": "candidate",
                "exploit_chain": [
                    {
                        "step": 1,
                        "location": "pkg/modules/webhook/webhook.go:99-131",
                        "description": "User-controlled webhook URL is accepted from the request header.",
                        "data_state": "The URL remains attacker controlled.",
                        "bypass_reason": "No SSRF allowlist is applied before the outbound request.",
                    }
                ],
                "poc": {
                    "description": "Submit a webhook URL pointing at a loopback service and observe the server initiating the request.",
                    "preconditions": ["Webhook feature is enabled."],
                    "steps": [
                        {
                            "step": 1,
                            "action": "Send a conversion request with Gotenberg-Webhook-Url set to http://127.0.0.1:8080/admin.",
                            "request": "POST /forms/chromium/convert/url",
                            "expected_response": "The server attempts to contact the supplied internal URL.",
                        }
                    ],
                    "payload": "Gotenberg-Webhook-Url: http://127.0.0.1:8080/admin",
                    "impact": "An authenticated attacker can pivot the server into internal HTTP services.",
                    "cve_justification": "The issue exposes SSRF reachability through a network-facing endpoint.",
                },
                "impact": "An attacker can reach internal network services from the server.",
                "cve_justification": "Network-reachable SSRF with internal service impact is CVE-relevant.",
                "verification_notes": "Source, sink, and propagation path were verified in code.",
            }
        ],
        "summary": "Completed audit with one structured SSRF candidate.",
        "completion_note": "Evidence chain is closed.",
        "needs_handoff": True,
    }


def test_query_loop_run_turn_persists_assistant_reply_and_turn():
    store = build_store()
    session_id = store.create_session(
        project_id="project-1",
        runtime_stack="runtime",
        system_prompt="system prompt",
        recon_payload={"repo": "demo"},
    )
    store.append_message(
        session_id,
        TranscriptItem(role=RuntimeMessageRole.USER, content="inspect the repo"),
    )
    client = FakeModelClient()
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.transition is None
    assert len(snapshot.turns) == 1
    assert snapshot.turns[0].model_name == "gpt-test"
    assert snapshot.turns[0].status == "completed"
    assert snapshot.messages[-1].role == RuntimeMessageRole.ASSISTANT.value
    assert snapshot.messages[-1].content == "assistant reply"
    assert snapshot.checkpoints[-1].state_payload["stop_reason"] == RuntimeStopReason.COMPLETED.value
    assert snapshot.checkpoints[-1].state_payload["transition"] is None

    assert client.calls[0]["system_prompt"] == "system prompt"
    assert client.calls[0]["recon_payload"] == {"repo": "demo"}
    assert [item.content for item in client.calls[0]["transcript"]] == ["inspect the repo"]


def test_runner_executes_tool_calls_and_loops_until_final_answer():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Need a tool",
                "tool_calls": [{"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}],
            },
            {
                "content": "Final answer",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.transition is None
    assert snapshot.session.state == "completed"
    visible_messages = _messages_without_system(snapshot)
    assert [message.role for message in visible_messages] == [
        RuntimeMessageRole.USER.value,
        RuntimeMessageRole.ASSISTANT.value,
        RuntimeMessageRole.TOOL_USE.value,
        RuntimeMessageRole.TOOL_RESULT.value,
        RuntimeMessageRole.ASSISTANT.value,
    ]
    assert visible_messages[2].payload["tool_name"] == "echo"
    assert visible_messages[3].payload["output"] == {"echo": "repo summary"}
    assert len(snapshot.tool_calls) == 1
    assert snapshot.tool_calls[0].status == AuditToolCallStatus.COMPLETED.value
    assert client.calls[0]["tool_definitions"][0]["name"] == "echo"


def test_runner_continues_when_transition_requests_next_turn():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Need a tool",
                "tool_calls": [{"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}],
            },
            {
                "content": "Final answer",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    transition_checkpoints = [checkpoint.state_payload for checkpoint in snapshot.checkpoints if checkpoint.state_payload.get("transition") is not None or "transition" in checkpoint.state_payload]
    assert transition_checkpoints[0]["transition"] == RuntimeContinueReason.NEXT_TURN.value
    assert transition_checkpoints[1]["transition"] is None


def test_runner_executes_skill_tool_and_persists_skill_invocation():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.replace_skills(
        session_id,
        [{"slug": "code-audit-finding", "name": "Code Audit Finding", "description": "primary skill", "source_type": "bundled"}],
        matched_skill_refs={"code-audit-finding"},
    )
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="bootstrap skill"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Load the audit skill",
                "tool_calls": [{"id": "tool-1", "name": "Skill", "input": {"skill_ref": "code-audit-finding", "action": "body"}}],
            },
            {
                "content": "Final answer",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    registry = ToolRegistry([RuntimeSkillTool(session_store=store, skill_service=FakeSkillService())])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert len(snapshot.skill_invocations) == 1
    assert snapshot.skill_invocations[0].skill_ref == "code-audit-finding"
    assert snapshot.skill_invocations[0].status == AuditSkillInvocationStatus.COMPLETED.value
    visible_messages = _messages_without_system(snapshot)
    assert visible_messages[2].payload["tool_name"] == "Skill"
    assert visible_messages[3].payload["output"] == {"skill": "code-audit-finding", "content": "body"}


def test_query_loop_defaults_stop_reason_when_model_omits_it():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    loop = QueryLoop(session_store=store, model_client=FakeModelClient(responses=[{"content": "done"}]), tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.transition is None


def test_query_loop_rejects_textual_tool_call_fallback_and_requests_native_tool_call():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Thought: inspect a file first.\nTool Call: echo\n{\"text\": \"repo summary\"}",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
                "tool_calls": [],
            },
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=registry, tool_orchestrator=orchestrator)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.LEGACY_TOOL_SYNTAX_NUDGE
    assert len(snapshot.tool_calls) == 0
    visible_messages = _messages_without_system(snapshot)
    assert [message.role for message in visible_messages] == [
        RuntimeMessageRole.USER.value,
        RuntimeMessageRole.ASSISTANT.value,
    ]
    assert state.messages[-1].name == "legacy_tool_syntax_nudge"
    assert state.messages[-1].content
    assert state.tool_use_context["legacy_text_tool_call_nudge_count"] == 1
    assert snapshot.checkpoints[-1].state_payload["transition"] == RuntimeContinueReason.LEGACY_TOOL_SYNTAX_NUDGE.value


def test_runner_finalize_finding_tool_marks_terminal_completion():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Ready to submit final findings",
                "tool_calls": [
                    {
                        "id": "tool-1",
                        "name": "FinalizeFinding",
                        "input": _valid_finalize_input(),
                    }
                ],
            }
        ]
    )
    registry = ToolRegistry([FinalizeFindingTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.terminal_action is RuntimeTerminalAction.FINALIZE_FINDING
    assert result.completion_mode is RuntimeCompletionMode.FINALIZE_TOOL
    assert result.final_payload == _valid_finalize_input()


def test_finalize_finding_description_explains_terminal_contract_and_required_fields():
    description = FinalizeFindingTool.description

    assert "提交 Finding 阶段的最终结构化审计结论" in description
    assert "这是终点工具" in description
    assert "审计完成且没有确认可报告漏洞时" in description
    assert "不要调用 FinalizeFinding" in description
    assert "vulnerability_type、severity、title、description" in description
    assert "不要只用自然语言宣布“审计完成”" in description


def test_runner_rejects_reason_only_finalize_finding_payload_without_terminal_completion():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Submit final result",
                "tool_calls": [
                    {
                        "id": "tool-1",
                        "name": "FinalizeFinding",
                        "input": {
                            "findings": [
                                {
                                    "reason": "SSRF vulnerability with the exploit chain and PoC hidden in free-form prose.",
                                }
                            ],
                            "summary": "Found SSRF.",
                        },
                    }
                ],
            },
            {
                "content": "Continue collecting structured evidence",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    registry = ToolRegistry([FinalizeFindingTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.terminal_action is None
    assert result.completion_mode is None
    assert len(client.calls) == 2
    assert snapshot.tool_calls[0].status == AuditToolCallStatus.COMPLETED.value
    assert snapshot.tool_calls[0].output_payload["finalization_rejected"] is True
    assert "reason" in snapshot.tool_calls[0].output_payload["validation_errors"][0]["message"]


def test_runner_invalid_finalize_finding_continues_with_tool_error_feedback():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="继续审查"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Ready to submit final result",
                "tool_calls": [
                    {
                        "id": "tool-1",
                        "name": "FinalizeFinding",
                        "input": {
                            "findings": [
                                {
                                    "title": "SSRF in webhook fetcher",
                                    "severity": "high",
                                    "vulnerability_type": "ssrf",
                                }
                            ]
                        },
                    }
                ],
            },
            {
                "content": "Final natural language reply",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    registry = ToolRegistry([FinalizeFindingTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.terminal_action is None
    assert result.completion_mode is None
    assert len(client.calls) == 2
    assert snapshot.tool_calls[0].status == AuditToolCallStatus.COMPLETED.value
    assert snapshot.tool_calls[0].output_payload["finalization_rejected"] is True
    assert snapshot.messages[-2].role == RuntimeMessageRole.TOOL_RESULT.value
    assert snapshot.messages[-2].message_metadata["is_error"] is False
    transition_checkpoints = [
        checkpoint.state_payload
        for checkpoint in snapshot.checkpoints
        if checkpoint.state_payload.get("transition") is not None or "transition" in checkpoint.state_payload
    ]
    assert transition_checkpoints[0]["transition"] == RuntimeContinueReason.NEXT_TURN.value


def test_query_loop_marks_natural_end_without_terminal_action():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="continue audit"))
    state = store.load_query_loop_state(session_id)
    state.tool_use_context["missing_terminal_action_nudge_count"] = 1
    store.save_query_loop_state(session_id, state)
    loop = QueryLoop(
        session_store=store,
        model_client=FakeModelClient(responses=[{"content": "让我继续审查媒体上传和内部 API。"}]),
        tool_registry=ToolRegistry([EchoTool()]),
        tool_orchestrator=None,
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.terminal_action is RuntimeTerminalAction.NATURAL_END_WITHOUT_TERMINAL_ACTION
    assert result.completion_mode is RuntimeCompletionMode.INCOMPLETE
    assert result.final_payload is None


def test_query_loop_injects_terminal_action_nudge_once_for_continue_intent():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="继续审查"))
    loop = QueryLoop(
        session_store=store,
        model_client=FakeModelClient(responses=[{"content": "让我继续审查状态创建、媒体上传和内部 API。"}]),
        tool_registry=ToolRegistry([EchoTool()]),
        tool_orchestrator=None,
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.TERMINAL_ACTION_NUDGE
    assert state.messages[-1].name == "terminal_action_nudge"
    assert state.messages[-1].content
    assert state.tool_use_context["missing_terminal_action_nudge_count"] == 1
    assert snapshot.checkpoints[-1].state_payload["transition"] == RuntimeContinueReason.TERMINAL_ACTION_NUDGE.value


def test_runner_marks_incomplete_natural_end_as_failed_session_state():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="继续审查"))
    state = store.load_query_loop_state(session_id)
    state.tool_use_context["missing_terminal_action_nudge_count"] = 1
    store.save_query_loop_state(session_id, state)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=FakeModelClient(responses=[{"content": "让我继续审查媒体上传和内部 API。"}]),
        tool_registry=ToolRegistry([EchoTool()]),
        tool_orchestrator=None,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.terminal_action is RuntimeTerminalAction.NATURAL_END_WITHOUT_TERMINAL_ACTION
    assert result.completion_mode is RuntimeCompletionMode.INCOMPLETE
    assert snapshot.session.state == "failed"


def test_query_loop_requires_terminal_action_and_nudges_plain_summary_without_tool_call():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="audit code"))
    loop = QueryLoop(
        session_store=store,
        model_client=FakeModelClient(
            responses=[
                {
                    "content": "Key finding: convertUrlRoute may have SSRF. I need to inspect tasks.go request blocking logic.",
                    "stop_reason": RuntimeStopReason.COMPLETED.value,
                }
            ]
        ),
        tool_registry=ToolRegistry([EchoTool()]),
        tool_orchestrator=None,
        require_terminal_action=True,
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.TERMINAL_ACTION_NUDGE
    assert result.completion_mode is None
    assert state.messages[-1].name == "terminal_action_nudge"
    assert state.messages[-1].content
    assert "下一条 assistant 响应必须满足以下二选一" in state.messages[-1].content
    assert "必须立即调用 Read/Grep/Glob/Skill/PowerShell" in state.messages[-1].content
    assert '输出严格可解析的 {"findings": [...], "summary": "..."} JSON' in state.messages[-1].content
    assert "继续就必须实际调用工具" in state.messages[-1].content
    assert state.tool_use_context["missing_terminal_action_nudge_count"] == 1
    assert snapshot.turns[-1].status == "terminal_action_nudge"


def test_query_loop_nudges_empty_model_response_when_terminal_action_is_required():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="continue audit"))
    loop = QueryLoop(
        session_store=store,
        model_client=FakeModelClient(
            responses=[
                {
                    "content": "",
                    "reasoning_content": "",
                    "tool_calls": [],
                    "stop_reason": RuntimeStopReason.COMPLETED.value,
                }
            ]
        ),
        tool_registry=ToolRegistry([EchoTool()]),
        tool_orchestrator=None,
        require_terminal_action=True,
        terminal_action_nudge_limit=5,
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.transition is RuntimeContinueReason.TERMINAL_ACTION_NUDGE
    assert state.messages[-1].name == "empty_model_response_nudge"
    assert snapshot.checkpoints[-1].state_payload["error_kind"] == "empty_model_response"


def test_runner_marks_required_terminal_action_exhaustion_as_failed_session_state():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="audit code"))
    state = store.load_query_loop_state(session_id)
    state.tool_use_context["missing_terminal_action_nudge_count"] = 2
    store.save_query_loop_state(session_id, state)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=FakeModelClient(
            responses=[
                {
                    "content": "Key finding: convertUrlRoute may have SSRF. I need to inspect tasks.go request blocking logic.",
                    "stop_reason": RuntimeStopReason.COMPLETED.value,
                }
            ]
        ),
        tool_registry=ToolRegistry([EchoTool()]),
        tool_orchestrator=None,
        require_terminal_action=True,
        terminal_action_nudge_limit=2,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.terminal_action is RuntimeTerminalAction.NATURAL_END_WITHOUT_TERMINAL_ACTION
    assert result.completion_mode is RuntimeCompletionMode.INCOMPLETE
    assert snapshot.session.state == "failed"


def test_query_loop_resets_terminal_action_nudge_count_after_tool_call():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="audit code"))
    state = store.load_query_loop_state(session_id)
    state.tool_use_context["missing_terminal_action_nudge_count"] = 2
    store.save_query_loop_state(session_id, state)
    loop = QueryLoop(
        session_store=store,
        model_client=FakeModelClient(
            responses=[
                {
                    "content": "I will inspect the next file.",
                    "tool_calls": [{"id": "tool-1", "name": "echo", "input": {"text": "continue"}}],
                    "stop_reason": RuntimeStopReason.COMPLETED.value,
                }
            ]
        ),
        tool_registry=ToolRegistry([EchoTool()]),
        tool_orchestrator=ToolOrchestrator(session_store=store, tool_registry=ToolRegistry([EchoTool()])),
        require_terminal_action=True,
        terminal_action_nudge_limit=2,
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    next_state = store.load_query_loop_state(session_id)

    assert result.transition is RuntimeContinueReason.NEXT_TURN
    assert "missing_terminal_action_nudge_count" not in next_state.tool_use_context


def test_query_loop_ignores_textual_tool_calls_without_orchestrator_when_no_tools_are_exposed():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="finalize"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Tool Call: Read\n{\"file_path\": \"README.md\"}",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
                "tool_calls": [],
            }
        ]
    )
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry([]), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert result.transition is None
    assert snapshot.turns[-1].status == "completed"
    assert [message.role for message in snapshot.messages] == [
        RuntimeMessageRole.USER.value,
        RuntimeMessageRole.ASSISTANT.value,
    ]
    assert snapshot.checkpoints[-1].state_payload["tool_call_ids"] == []
    assert snapshot.checkpoints[-1].state_payload["transition"] is None


def test_extract_text_tool_calls_preserves_nested_write_payload():
    nested_content = json.dumps(
        {
            "findings": [
                {
                    "title": "Server-side request forgery in fetcher",
                    "references": ["CWE-918", "https://example.test/advisory"],
                }
            ],
            "summary": "in progress",
        },
        ensure_ascii=False,
    )
    tool_payload = {
        "tool_use_id": "call_123",
        "tool_name": "Write",
        "input": {
            "path": ".auditai/findings.json",
            "content": nested_content,
        },
    }

    parsed = QueryLoop._extract_text_tool_calls(
        "Tool Call: Write\n"
        + json.dumps(tool_payload, ensure_ascii=False)
        + "\nObservation: [done]"
    )

    assert parsed == [
        {
            "id": "text-tool-call-1",
            "name": "Write",
            "input": {
                "path": ".auditai/findings.json",
                "content": nested_content,
            },
        }
    ]

def test_query_loop_runs_pre_model_pipeline_in_restored_order(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect repo"))
    client = FakeModelClient()
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)
    events: list[str] = []

    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.get_messages_after_compact_boundary",
        lambda messages, state: (events.append("compact_boundary"), list(messages))[1],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.apply_tool_result_budget",
        lambda messages, state: (events.append("tool_result_budget"), list(messages))[1],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.apply_history_snip",
        lambda messages, state: (events.append("history_snip"), list(messages))[1],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.apply_microcompact",
        lambda messages, state: (events.append("microcompact"), list(messages))[1],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.apply_context_collapse_if_needed",
        lambda messages, state: (events.append("context_collapse"), (list(messages), state))[1],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.auto_compact_if_needed",
        lambda messages, state, **kwargs: (events.append("autocompact"), type("Decision", (), {"was_compacted": False, "consecutive_failures": None, "compaction_result": None})())[1],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.append_system_context",
        lambda system_prompt, runtime_state: (events.append("append_system_context"), system_prompt)[1],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.prepend_user_context",
        lambda messages, runtime_state: (events.append("prepend_user_context"), list(messages))[1],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.normalize_messages_for_model",
        lambda messages: (events.append("normalize_messages"), list(messages))[1],
    )

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    assert events == [
        "compact_boundary",
        "tool_result_budget",
        "history_snip",
        "microcompact",
        "context_collapse",
        "append_system_context",
        "prepend_user_context",
        "normalize_messages",
        "autocompact",
        "normalize_messages",
    ]


def test_query_loop_applies_runtime_query_context_to_system_prompt_and_transcript():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="base system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect repo"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["query_context"] = {
        "system_sections": ["skills prompt", "route prompt"],
        "user_context_prefix": "Focus on auth boundary.",
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient()
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    assert client.calls[0]["system_prompt"] == "base system\n\nskills prompt\n\nroute prompt"
    assert [item.content for item in client.calls[0]["transcript"]] == [
        "Focus on auth boundary.",
        "inspect repo",
    ]

def test_query_loop_saves_between_turn_attachments_and_pending_summary(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Need a tool",
                "tool_calls": [{"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}],
            }
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=registry, tool_orchestrator=orchestrator)

    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.build_between_turn_attachments",
        lambda **kwargs: [TranscriptItem(role=RuntimeMessageRole.USER, content="memory attachment", name="memory_attachment")],
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.start_pending_tool_use_summary",
        lambda **kwargs: {"status": "pending", "tool_names": ["echo"]},
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)

    assert result.transition is RuntimeContinueReason.NEXT_TURN
    assert state.transition is RuntimeContinueReason.NEXT_TURN
    assert state.pending_tool_use_summary == {"status": "pending", "tool_names": ["echo"]}
    assert state.messages[-1].content == "memory attachment"


def test_query_loop_uses_state_messages_for_next_turn_when_attachments_exist():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    store.save_query_loop_state(
        session_id,
        QueryLoopState(
            messages=[
                TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"),
                TranscriptItem(role=RuntimeMessageRole.USER, content="memory attachment", name="memory_attachment"),
            ],
            turn_count=2,
            transition=RuntimeContinueReason.NEXT_TURN,
        ),
    )
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    assert [item.content for item in client.calls[0]["transcript"]] == ["inspect code", "memory attachment"]




def test_query_loop_escalates_max_output_tokens_once():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "partial answer",
                "recoverable_error_kind": "max_output_tokens",
                "recoverable_error_message": "output truncated",
            }
        ]
    )
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.MAX_OUTPUT_TOKENS_ESCALATE
    assert state.max_output_tokens_override == 64000
    assert state.max_output_tokens_recovery_count == 0
    assert snapshot.checkpoints[-1].state_payload["transition"] == RuntimeContinueReason.MAX_OUTPUT_TOKENS_ESCALATE.value
    assert client.calls[0]["max_output_tokens_override"] is None


def test_query_loop_recovers_after_max_output_tokens_escalation_is_already_used():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    store.save_query_loop_state(
        session_id,
        QueryLoopState(
            messages=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code")],
            max_output_tokens_override=64000,
            turn_count=1,
        ),
    )
    client = FakeModelClient(
        responses=[
            {
                "content": "partial answer",
                "recoverable_error_kind": "max_output_tokens",
                "recoverable_error_message": "still truncated",
            }
        ]
    )
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.MAX_OUTPUT_TOKENS_RECOVERY
    assert state.max_output_tokens_override == 64000
    assert state.max_output_tokens_recovery_count == 1
    assert state.messages[-1].content.startswith("Continue from where you left off")
    assert client.calls[0]["max_output_tokens_override"] == 64000


def test_query_loop_uses_collapse_drain_retry_placeholder_for_prompt_too_long_with_pending_collapse():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    store.save_query_loop_state(
        session_id,
        QueryLoopState(
            messages=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code")],
            auto_compact_tracking={"pending_collapse": True},
            context_collapse_state={
                "commits": [],
                "snapshot": {
                    "staged": [{"start_uuid": "u1", "end_uuid": "u1", "summary": "Collapsed earlier context.", "risk": 5, "staged_at": 1}],
                    "armed": True,
                    "last_spawn_tokens": 10,
                },
            },
            turn_count=1,
        ),
    )
    client = FakeModelClient(
        responses=[
            {
                "content": "",
                "recoverable_error_kind": "prompt_too_long",
                "recoverable_error_message": "context too large",
            }
        ]
    )
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.COLLAPSE_DRAIN_RETRY
    assert snapshot.checkpoints[-1].state_payload["transition"] == RuntimeContinueReason.COLLAPSE_DRAIN_RETRY.value
    assert snapshot.checkpoints[-1].state_payload["recovery"] == {"strategy": "collapse_drain", "status": "deferred", "committed": 1}
    assert state.auto_compact_tracking["pending_collapse"] is False
    assert len(state.context_collapse_state["commits"]) == 1


def test_query_loop_uses_reactive_compact_retry_with_restored_style_compact_messages():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "",
                "recoverable_error_kind": "prompt_too_long",
                "recoverable_error_message": "context too large",
            }
        ]
    )
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.REACTIVE_COMPACT_RETRY
    assert state.has_attempted_reactive_compact is True
    assert state.auto_compact_tracking["last_recovery_strategy"] == "reactive_compact"
    assert state.messages[0].name == "reactive_compact_boundary"
    assert state.messages[1].name == "reactive_compact_summary"
    recovery = dict(snapshot.checkpoints[-1].state_payload["recovery"])
    assert recovery["strategy"] == "reactive_compact"
    assert recovery["status"] == "deferred"



def test_query_loop_uses_stop_hook_blocking_when_runtime_requests_correction(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.evaluate_stop_hooks",
        lambda **kwargs: {
            "blocking_errors": ["Need to justify the auth bypass conclusion with concrete sink evidence."],
            "prevent_continuation": False,
        },
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.STOP_HOOK_BLOCKING
    assert state.messages[-1].content == "Need to justify the auth bypass conclusion with concrete sink evidence."
    assert snapshot.checkpoints[-1].state_payload["transition"] == RuntimeContinueReason.STOP_HOOK_BLOCKING.value


def test_query_loop_respects_stop_hook_prevented_terminal_reason(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.evaluate_stop_hooks",
        lambda **kwargs: {
            "blocking_errors": [],
            "prevent_continuation": True,
        },
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.STOP_HOOK_PREVENTED
    assert result.transition is None
    assert snapshot.checkpoints[-1].state_payload["stop_reason"] == RuntimeStopReason.STOP_HOOK_PREVENTED.value


def test_query_loop_uses_token_budget_continuation_when_budget_allows_more_work(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.evaluate_stop_hooks",
        lambda **kwargs: {
            "blocking_errors": [],
            "prevent_continuation": False,
        },
    )
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.evaluate_token_budget_continuation",
        lambda **kwargs: {
            "should_continue": True,
            "message": "Keep investigating until you either exhaust plausible paths or produce stronger evidence.",
        },
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is None
    assert result.transition is RuntimeContinueReason.TOKEN_BUDGET_CONTINUATION
    assert state.messages[-1].content.startswith("Keep investigating")
    assert snapshot.checkpoints[-1].state_payload["transition"] == RuntimeContinueReason.TOKEN_BUDGET_CONTINUATION.value


def test_query_loop_can_stop_after_tool_execution_when_hook_requests_stop(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Need a tool",
                "tool_calls": [{"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}],
            }
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=registry, tool_orchestrator=orchestrator)

    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.evaluate_post_tool_hooks",
        lambda **kwargs: {"hook_stopped": True},
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.HOOK_STOPPED
    assert result.transition is None
    assert snapshot.checkpoints[-1].state_payload["stop_reason"] == RuntimeStopReason.HOOK_STOPPED.value


def test_query_loop_returns_model_error_when_model_client_raises():
    class BrokenModelClient:
        async def complete(self, **kwargs):
            raise RuntimeError("provider unavailable")

    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    loop = QueryLoop(session_store=store, model_client=BrokenModelClient(), tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.MODEL_ERROR
    assert snapshot.turns[-1].status == "resumable_failed"
    assert snapshot.checkpoints[-1].state_payload["phase"] == "model"


def test_query_loop_classifies_message_persistence_failures_separately(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))

    def fail_append_message(*args, **kwargs):
        raise AuditSessionPersistenceError("database rejected audit message")

    monkeypatch.setattr(store, "append_message", fail_append_message)
    loop = QueryLoop(
        session_store=store,
        model_client=FakeModelClient(),
        tool_registry=ToolRegistry(),
        tool_orchestrator=None,
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.PERSISTENCE_ERROR
    assert snapshot.turns[-1].status == "persistence_error"
    assert snapshot.checkpoints[-1].state_payload["phase"] == "message_persistence"
    assert "database rejected audit message" in snapshot.checkpoints[-1].state_payload["error"]


def test_query_loop_returns_aborted_streaming_when_model_client_is_cancelled():
    class CancelledModelClient:
        async def complete(self, **kwargs):
            raise asyncio.CancelledError()

    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    loop = QueryLoop(session_store=store, model_client=CancelledModelClient(), tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.ABORTED_STREAMING
    assert snapshot.turns[-1].status == "manual_cancelled"
    assert snapshot.checkpoints[-1].state_payload["stop_reason"] == RuntimeStopReason.ABORTED_STREAMING.value
    assert snapshot.checkpoints[-1].state_payload["checkpoint_kind"] == "manual_cancelled"
    assert snapshot.checkpoints[-1].state_payload["resumable"] is True
    assert snapshot.checkpoints[-1].state_payload["error_kind"] == "manual_cancelled"


def test_query_loop_returns_aborted_tools_when_tool_execution_is_cancelled():
    class CancelledToolOrchestrator:
        async def execute_tool_calls(self, **kwargs):
            raise asyncio.CancelledError()

    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Need a tool",
                "tool_calls": [{"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}],
            }
        ]
    )
    registry = ToolRegistry([EchoTool()])
    loop = QueryLoop(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=CancelledToolOrchestrator(),
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.ABORTED_TOOLS
    assert snapshot.turns[-1].status == "manual_cancelled"
    assert snapshot.checkpoints[-1].state_payload["phase"] == "tool_execution"
    assert snapshot.checkpoints[-1].state_payload["checkpoint_kind"] == "manual_cancelled"
    assert snapshot.checkpoints[-1].state_payload["resumable"] is True


def test_runner_marks_prompt_too_long_as_failed_session_state():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "",
                "recoverable_error_kind": "prompt_too_long",
                "recoverable_error_message": "context too large",
            },
            {
                "content": "",
                "recoverable_error_kind": "prompt_too_long",
                "recoverable_error_message": "context too large",
            },
        ]
    )
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=ToolRegistry(),
        tool_orchestrator=None,
        max_turns=3,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.PROMPT_TOO_LONG
    assert snapshot.session.state == "failed"



def test_query_loop_uses_runtime_query_context_pipeline_settings_when_state_has_no_pipeline_config():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="m1"))
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.ASSISTANT, content="m2"))
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="m3"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["query_context"] = {
        "pipeline": {
            "history_snip": {"keep_last_messages": 2}
        }
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient()
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    assert client.calls[0]["transcript"][0].name == "history_snip_boundary"
    assert [item.content for item in client.calls[0]["transcript"][1:]] == ["m2", "m3"]


def test_query_loop_injects_pending_tool_use_summary_once_on_next_turn():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    store.save_query_loop_state(
        session_id,
        QueryLoopState(
            messages=[TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code")],
            pending_tool_use_summary={
                "status": "ready",
                "tool_names": ["echo"],
                "summary_message": "Tool-use summary:\n- echo: completed -> repo summary",
            },
            turn_count=2,
            transition=RuntimeContinueReason.NEXT_TURN,
        ),
    )
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)

    assert [item.content for item in client.calls[0]["transcript"]] == [
        "inspect code",
        "Tool-use summary:\n- echo: completed -> repo summary",
    ]
    assert state.pending_tool_use_summary is None


def test_query_loop_returns_blocking_limit_before_model_call_when_preflight_budget_exceeded():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 80))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["query_context"] = {
        "pipeline": {
            "blocking_limit": {"max_chars": 40}
        }
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient(responses=[{"content": "should not run", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.BLOCKING_LIMIT
    assert client.calls == []
    assert snapshot.turns[-1].status == "blocking_limit"
    assert snapshot.checkpoints[-1].state_payload["stop_reason"] == RuntimeStopReason.BLOCKING_LIMIT.value


def test_query_loop_uses_stop_hook_policy_without_monkeypatch_when_claim_has_no_evidence():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["stop_hooks"] = {
        "require_tool_result_evidence": True,
        "claim_phrases": ["reportable finding", "definitely exploitable"],
        "missing_evidence_message": "Need concrete tool-backed evidence before claiming a reportable finding.",
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient(responses=[{"content": "This is definitely exploitable and looks like a reportable finding.", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)

    assert result.transition is RuntimeContinueReason.STOP_HOOK_BLOCKING
    assert state.messages[-1].content == "Need concrete tool-backed evidence before claiming a reportable finding."


def test_query_loop_uses_computed_token_budget_policy_without_monkeypatch():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["token_budget"] = {
        "budget_chars": 200,
        "minimum_remaining_chars": 40,
        "max_turns": 4,
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient(responses=[{"content": "Short summary with more work remaining.", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)

    assert result.transition is RuntimeContinueReason.TOKEN_BUDGET_CONTINUATION
    assert "remaining budget" in state.messages[-1].content






def test_runner_stops_when_runtime_hook_checkpoint_requests_post_tool_stop():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["session_hooks"] = {
        "code-audit-finding": {
            "PostToolUse": [
                {
                    "matcher": "echo",
                    "prevent_continuation": True,
                    "stop_reason": "Skill requested stop after successful tool execution.",
                }
            ]
        }
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient(
        responses=[
            {
                "content": "Need a tool",
                "tool_calls": [{"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}],
            },
            {
                "content": "Final answer that should never be requested",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.HOOK_STOPPED
    assert len(client.calls) == 1
    assert snapshot.checkpoints[-1].state_payload["stop_reason"] == RuntimeStopReason.HOOK_STOPPED.value
    assert any(
        checkpoint.state_payload.get("kind") == "runtime_hook"
        and checkpoint.state_payload.get("event") == "PostToolUse"
        for checkpoint in snapshot.checkpoints
    )

def test_query_loop_persists_task_completed_hook_checkpoint_when_teammate_blocks():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["teammate"] = {
        "enabled": True,
        "agent_name": "alice",
        "team_name": "red",
        "tasks": [
            {
                "id": "task-1",
                "subject": "Trace auth sink",
                "description": "Need proof for privilege escalation sink",
                "owner": "alice",
                "status": "in_progress",
            }
        ],
    }
    runtime_state.metadata["session_hooks"] = {
        "code-audit-finding": {
            "TaskCompleted": [
                {
                    "matcher": "*",
                    "blocking_error": "Confirm whether the auth sink is actually reachable before concluding the task is done.",
                }
            ]
        }
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)
    state = store.load_query_loop_state(session_id)

    assert result.transition is RuntimeContinueReason.STOP_HOOK_BLOCKING
    assert state.messages[-1].content == "Confirm whether the auth sink is actually reachable before concluding the task is done."
    assert any(
        checkpoint.state_payload.get("kind") == "runtime_hook"
        and checkpoint.state_payload.get("event") == "TaskCompleted"
        and checkpoint.state_payload.get("task_id") == "task-1"
        for checkpoint in snapshot.checkpoints
    )


def test_query_loop_persists_teammate_idle_hook_checkpoint_when_it_prevents_continuation():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["teammate"] = {
        "enabled": True,
        "agent_name": "alice",
        "team_name": "red",
    }
    runtime_state.metadata["session_hooks"] = {
        "code-audit-finding": {
            "TeammateIdle": [
                {
                    "matcher": "*",
                    "prevent_continuation": True,
                    "stop_reason": "Teammate idle hook requested a handoff before continuing.",
                }
            ]
        }
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.STOP_HOOK_PREVENTED
    assert any(
        checkpoint.state_payload.get("kind") == "runtime_hook"
        and checkpoint.state_payload.get("event") == "TeammateIdle"
        and checkpoint.state_payload.get("agent_name") == "alice"
        for checkpoint in snapshot.checkpoints
    )

def test_query_loop_persists_hook_execution_artifacts_for_teammate_idle_stop():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["teammate"] = {
        "enabled": True,
        "agent_name": "alice",
        "team_name": "red",
    }
    runtime_state.metadata["session_hooks"] = {
        "code-audit-finding": {
            "TeammateIdle": [
                {
                    "matcher": "*",
                    "prevent_continuation": True,
                    "stop_reason": "Teammate idle hook requested a handoff before continuing.",
                }
            ]
        }
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.STOP_HOOK_PREVENTED
    artifact_names = [message.name for message in snapshot.messages if message.role == RuntimeMessageRole.SYSTEM.value]
    assert artifact_names == ["hook_progress", "hook_stopped_continuation", "stop_hook_summary"]
    assert snapshot.messages[-1].payload["hook_event"] == "TeammateIdle"

def test_query_loop_persists_hook_execution_artifacts_for_teammate_idle_stop():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["teammate"] = {
        "enabled": True,
        "agent_name": "alice",
        "team_name": "red",
    }
    runtime_state.metadata["session_hooks"] = {
        "code-audit-finding": {
            "TeammateIdle": [
                {
                    "matcher": "*",
                    "prevent_continuation": True,
                    "stop_reason": "Teammate idle hook requested a handoff before continuing.",
                    "command": "python hooks/idle.py",
                    "prompt_text": "Decide whether alice should hand off.",
                    "stdout": "handoff requested",
                    "stderr": "",
                    "exit_code": 0,
                    "duration_ms": 42,
                }
            ]
        }
    }
    store.replace_runtime_state(session_id, runtime_state)
    client = FakeModelClient(responses=[{"content": "done", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.STOP_HOOK_PREVENTED
    artifact_messages = [message for message in snapshot.messages if message.role == RuntimeMessageRole.SYSTEM.value]
    assert [message.name for message in artifact_messages] == [
        "hook_progress",
        "hook_progress",
        "hook_attachment",
        "hook_stopped_continuation",
        "stop_hook_summary",
    ]
    assert artifact_messages[0].payload["data"]["command"] == "python hooks/idle.py"
    assert artifact_messages[2].payload["attachment_type"] == "hook_success"
    assert artifact_messages[4].payload["hook_infos"][0]["durationMs"] == 42


def test_query_loop_returns_blocking_limit_before_model_call_when_compaction_is_unavailable(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="A" * 8000))
    runtime_state = store.load_runtime_state(session_id)
    runtime_state.metadata["query_context"] = {
        "pipeline": {
            "autocompact": {"preserve_tail_messages": 999},
            "autocompact_controller": {"context_window": 1000, "max_output_tokens": 40}
        }
    }
    store.replace_runtime_state(session_id, runtime_state)
    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.auto_compact_if_needed",
        lambda messages, state, **kwargs: type(
            "Decision",
            (),
            {"was_compacted": False, "consecutive_failures": 3, "compaction_result": None},
        )(),
    )
    client = FakeModelClient(responses=[{"content": "should not run", "stop_reason": RuntimeStopReason.COMPLETED.value}])
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    assert result.stop_reason is RuntimeStopReason.BLOCKING_LIMIT
    assert client.calls == []




def test_query_loop_uses_auto_compact_orchestrator_output_as_model_transcript(monkeypatch):
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system prompt")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="earlier context"))
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="tail"))
    client = FakeModelClient()
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    class _Decision:
        was_compacted = True
        consecutive_failures = 0
        compaction_result = type("Result", (), {
            "boundary_marker": TranscriptItem(role=RuntimeMessageRole.SYSTEM, content="boundary", name="auto_compact_boundary"),
            "summary_messages": [TranscriptItem(role=RuntimeMessageRole.USER, content="summary", name="auto_compact_summary")],
            "messages_to_keep": [TranscriptItem(role=RuntimeMessageRole.USER, content="tail")],
            "attachments": [],
            "hook_results": [],
        })()

    monkeypatch.setattr(
        "app.services.finding_runtime.query_loop.auto_compact_if_needed",
        lambda messages, state, **kwargs: _Decision(),
    )

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    saved_state = store.load_query_loop_state(session_id)

    assert client.calls[0]["transcript"][0].name == "auto_compact_summary"
    assert client.calls[0]["transcript"][-1].content == "tail"
    assert saved_state.messages[0].name == "auto_compact_boundary"
    assert saved_state.messages[1].name == "auto_compact_summary"
    checkpoint_payload = next(
        checkpoint.state_payload
        for checkpoint in store.load_session_snapshot(session_id).checkpoints
        if checkpoint.state_payload.get("checkpoint_kind") == "context_compaction"
    )
    assert checkpoint_payload["checkpoint_kind"] == "context_compaction"
    assert checkpoint_payload["resumable"] is True
    assert checkpoint_payload["compacted_query_loop_state"]["messages"][1]["name"] == "auto_compact_summary"


def test_runner_with_unbounded_max_turns_runs_until_terminal_result():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = FakeModelClient(
        responses=[
            {
                "content": "Need tool 1",
                "tool_calls": [{"id": "tool-1", "name": "echo", "input": {"text": "first"}}],
            },
            {
                "content": "Need tool 2",
                "tool_calls": [{"id": "tool-2", "name": "echo", "input": {"text": "second"}}],
            },
            {
                "content": "Final answer",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
        max_turns=None,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert snapshot.session.state == "completed"
    assert len(snapshot.turns) == 3



class DeferredEchoTool(RuntimeTool):
    name = "DeferredEcho"
    description = "Echo text after ToolSearch loads the schema"
    input_model = EchoInput
    should_defer = True
    search_hint = "echo deferred text"

    def is_concurrency_safe(self, parsed_input: EchoInput) -> bool:
        return True

    async def execute(self, parsed_input: EchoInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        del context
        return ToolExecutionPayload(
            content=f"deferred:{parsed_input.text}",
            output_payload={"echo": parsed_input.text},
        )


def test_runner_activates_deferred_tools_after_tool_search_selection():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    registry = ToolRegistry()
    deferred_echo = DeferredEchoTool()
    registry.register(deferred_echo)
    registry.register(ToolSearchRuntimeTool(session_store=store, registry_getter=lambda: registry))
    client = FakeModelClient(
        responses=[
            {
                "content": "Search for the deferred tool",
                "tool_calls": [{"id": "tool-1", "name": "ToolSearch", "input": {"query": "select:DeferredEcho"}}],
            },
            {
                "content": "Use the deferred tool",
                "tool_calls": [{"id": "tool-2", "name": "DeferredEcho", "input": {"text": "repo summary"}}],
            },
            {
                "content": "Final answer",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    runner = FindingRuntimeRunner(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
        max_turns=None,
    )

    result = asyncio.run(runner.run_once(session_id=session_id, model_name="gpt-test"))
    state = store.load_query_loop_state(session_id)

    assert result.stop_reason is RuntimeStopReason.COMPLETED
    assert [tool["name"] for tool in client.calls[0]["tool_definitions"]] == ["ToolSearch"]
    assert [tool["name"] for tool in client.calls[1]["tool_definitions"]] == ["DeferredEcho", "ToolSearch"]
    assert state.tool_use_context["active_tool_names"] == ["DeferredEcho", "ToolSearch"]


def test_query_loop_executes_streamed_tool_calls_only_after_done():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    client = StreamingFakeModelClient(
        stream_events=[
            {"type": "content_delta", "content": "Need ", "accumulated": "Need "},
            {"type": "content_delta", "content": "tool", "accumulated": "Need tool"},
            {"type": "tool_call", "tool_call": {"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}},
            {"type": "done", "content": "Need tool", "stop_reason": RuntimeStopReason.COMPLETED.value},
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=registry, tool_orchestrator=orchestrator)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)
    visible_messages = _messages_without_system(snapshot)
    system_messages = [message for message in snapshot.messages if message.role == RuntimeMessageRole.SYSTEM.value]

    assert result.transition is RuntimeContinueReason.NEXT_TURN
    assert [message.role for message in visible_messages] == [
        RuntimeMessageRole.USER.value,
        RuntimeMessageRole.ASSISTANT.value,
        RuntimeMessageRole.TOOL_USE.value,
        RuntimeMessageRole.TOOL_RESULT.value,
    ]
    assert visible_messages[1].content == "Need tool"
    assert visible_messages[3].payload["output"] == {"echo": "repo summary"}
    assert [message.name for message in system_messages] == ["tool_progress", "tool_progress"]
    assert client.calls[0]["streaming"] is True


def test_query_loop_never_executes_tool_before_stream_generator_finishes():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    lifecycle = {"stream_finished": False, "tool_saw_finished": False}

    class BoundaryClient(FakeModelClient):
        async def stream_complete(self, **kwargs):
            del kwargs
            yield {"type": "tool_call", "tool_call": {"id": "tool-1", "name": "boundary_echo", "input": {"text": "ok"}}}
            yield {"type": "done", "content": "", "stop_reason": RuntimeStopReason.COMPLETED.value}
            lifecycle["stream_finished"] = True

    class BoundaryEchoTool(EchoTool):
        name = "boundary_echo"

        async def execute(self, parsed_input: EchoInput, context: ToolExecutionContext) -> ToolExecutionPayload:
            lifecycle["tool_saw_finished"] = lifecycle["stream_finished"]
            return await super().execute(parsed_input, context)

    registry = ToolRegistry([BoundaryEchoTool()])
    loop = QueryLoop(
        session_store=store,
        model_client=BoundaryClient(),
        tool_registry=registry,
        tool_orchestrator=ToolOrchestrator(session_store=store, tool_registry=registry),
    )

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    assert lifecycle == {"stream_finished": True, "tool_saw_finished": True}


def test_query_loop_ignores_duplicate_streaming_tool_call_ids():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect code"))
    duplicate_tool_call = {"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}
    client = StreamingFakeModelClient(
        stream_events=[
            {"type": "tool_call", "tool_call": duplicate_tool_call},
            {"type": "tool_call", "tool_call": duplicate_tool_call},
            {
                "type": "done",
                "content": "",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
                "tool_calls": [duplicate_tool_call],
            },
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=registry, tool_orchestrator=orchestrator)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)
    visible_messages = _messages_without_system(snapshot)

    assert result.transition is RuntimeContinueReason.NEXT_TURN
    assert [message.role for message in visible_messages] == [
        RuntimeMessageRole.USER.value,
        RuntimeMessageRole.ASSISTANT.value,
        RuntimeMessageRole.TOOL_USE.value,
        RuntimeMessageRole.TOOL_RESULT.value,
    ]
    assert [message.payload["tool_use_id"] for message in visible_messages if message.role == RuntimeMessageRole.TOOL_USE.value] == ["tool-1"]
    assert [message.payload["tool_use_id"] for message in visible_messages if message.role == RuntimeMessageRole.TOOL_RESULT.value] == ["tool-1"]
    assert len(snapshot.tool_calls) == 1


def test_query_loop_persists_streaming_reasoning_content_for_tool_call_replay():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="load skill"))
    client = StreamingFakeModelClient(
        stream_events=[
            {"type": "reasoning_delta", "content": "Need the skill first.", "accumulated": "Need the skill first."},
            {"type": "tool_call", "tool_call": {"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}},
            {
                "type": "done",
                "content": "",
                "reasoning_content": "Need the skill first.",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=registry, tool_orchestrator=orchestrator)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)
    visible_messages = _messages_without_system(snapshot)

    assert result.transition is RuntimeContinueReason.NEXT_TURN
    assert visible_messages[1].role == RuntimeMessageRole.ASSISTANT.value
    assert visible_messages[1].content == ""
    assert visible_messages[1].payload["reasoning_content"] == "Need the skill first."
    assert visible_messages[2].role == RuntimeMessageRole.TOOL_USE.value


def test_query_loop_forwards_streaming_reasoning_to_event_sink():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect auth"))
    client = StreamingFakeModelClient(
        stream_events=[
            {"type": "reasoning_delta", "content": "Need to inspect auth middleware.", "accumulated": "Need to inspect auth middleware."},
            {
                "type": "done",
                "content": "",
                "reasoning_content": "Need to inspect auth middleware.",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    events = []
    loop = QueryLoop(
        session_store=store,
        model_client=client,
        tool_registry=ToolRegistry(),
        tool_orchestrator=None,
        event_sink=events.append,
    )

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    reasoning_events = [event for event in events if event.get("type") == "reasoning_delta"]
    assert reasoning_events
    assert reasoning_events[-1]["accumulated"] == "Need to inspect auth middleware."


def test_query_loop_forwards_streaming_tool_messages_to_event_sink():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect repo"))
    client = StreamingFakeModelClient(
        stream_events=[
            {"type": "tool_call", "tool_call": {"id": "tool-1", "name": "echo", "input": {"text": "repo summary"}}},
            {
                "type": "done",
                "content": "",
                "stop_reason": RuntimeStopReason.COMPLETED.value,
            },
        ]
    )
    events = []
    registry = ToolRegistry([EchoTool()])
    orchestrator = ToolOrchestrator(session_store=store, tool_registry=registry)
    loop = QueryLoop(
        session_store=store,
        model_client=client,
        tool_registry=registry,
        tool_orchestrator=orchestrator,
        event_sink=events.append,
    )

    asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))

    message_events = [
        event
        for event in events
        if event.get("type") == "message" and event.get("message", {}).get("role") in {"tool_use", "tool_result"}
    ]
    assert [event["message"]["role"] for event in message_events] == ["tool_use", "tool_result"]
    assert message_events[0]["message"]["content"] == "echo"
    assert message_events[1]["message"]["content"] == "echo:repo summary"


def test_query_loop_preserves_raw_stream_error_in_event_sink_and_checkpoint():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect auth"))
    client = StreamingFakeModelClient(
        stream_events=[
            {
                "type": "error",
                "error_type": "connection",
                "error": "upstream 502 from relay: provider trace id abc123",
                "user_message": "LLM streaming request failed. Please retry.",
            },
        ]
    )
    events = []
    loop = QueryLoop(
        session_store=store,
        model_client=client,
        tool_registry=ToolRegistry(),
        tool_orchestrator=None,
        event_sink=events.append,
    )

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.MODEL_ERROR
    error_events = [event for event in events if event.get("type") == "error"]
    assert len(error_events) == 1
    assert "upstream 502 from relay: provider trace id abc123" in error_events[-1]["error"]
    assert error_events[-1]["error_type"] == "model_stream_error"
    assert "upstream 502 from relay" in snapshot.checkpoints[-1].state_payload["error"]
    assert len(client.calls) == QueryLoop.MODEL_STREAM_MAX_RETRIES + 1
    attempt_checkpoints = [
        checkpoint
        for checkpoint in snapshot.checkpoints
        if checkpoint.state_payload.get("kind") == "model_stream_attempt"
    ]
    assert len(attempt_checkpoints) == QueryLoop.MODEL_STREAM_MAX_RETRIES + 1
    assert attempt_checkpoints[0].state_payload["status"] == "superseded"
    assert attempt_checkpoints[-1].state_payload["status"] == "tombstone"
    assert snapshot.checkpoints[-1].state_payload["checkpoint_kind"] == "resumable_failed"
    assert snapshot.checkpoints[-1].state_payload["resumable"] is True
    assert len(snapshot.model_stream_attempts) == QueryLoop.MODEL_STREAM_MAX_RETRIES + 1
    assert snapshot.model_stream_attempts[0].status == "superseded"
    assert snapshot.model_stream_attempts[-1].status == "tombstone"
    assert all(item.provider_request_count == 1 for item in snapshot.model_stream_attempts)


def test_query_loop_treats_provider_tpd_rate_limit_as_non_retryable_quota_exhaustion():
    store = build_store()
    session_id = store.create_session(project_id="project-1", system_prompt="system")
    store.append_message(session_id, TranscriptItem(role=RuntimeMessageRole.USER, content="inspect auth"))
    client = StreamingFakeModelClient(
        stream_events=[
            {
                "type": "error",
                "error_type": "rate_limit",
                "error": "request reached organization TPD rate limit, current: 1500001, limit: 1500000",
                "user_message": "Model rate limited",
            },
        ]
    )
    loop = QueryLoop(session_store=store, model_client=client, tool_registry=ToolRegistry(), tool_orchestrator=None)

    result = asyncio.run(loop.run_turn(session_id=session_id, model_name="gpt-test"))
    snapshot = store.load_session_snapshot(session_id)

    assert result.stop_reason is RuntimeStopReason.QUOTA_EXHAUSTED
    assert len(client.calls) == 1
    assert snapshot.model_stream_attempts[-1].status == "tombstone"
    assert snapshot.model_stream_attempts[-1].error_kind == "quota_exhausted"
    assert snapshot.checkpoints[-1].state_payload["error_kind"] == "quota_exhausted"
