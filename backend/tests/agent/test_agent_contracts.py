from unittest.mock import AsyncMock, MagicMock

import pytest

from app.api.v1.endpoints.agent_tasks import _save_findings
from app.models.agent_task import AgentTaskStatus
from app.models.agent_task import FindingStatus
from app.services.agent import prompts as prompt_exports
from app.services.agent.agents.analysis_workflow import AnalysisWorkflowAgent
from app.services.agent.agents.base import AgentResult, AgentType, TaskHandoff
from app.services.agent.agents.finding import FindingAgent
from app.services.agent.agents.finding_skill_router import resolve_finding_skill_routes
from app.services.agent.agents.orchestrator import OrchestratorAgent
from app.services.agent.prompts import system_prompts
from app.services.agent.tools.skill_tool import SkillBodyTool, SkillResourceTool
from app.services.agent.agents.recon import ReconAgent, ReconStep
from app.services.agent.skill_service import SkillService
from app.services.finding_runtime.models import RuntimeCompletionMode, RuntimeStopReason, TurnExecutionResult
from app.services.skill_file_service import SkillFileService
from app.services.task_report_service import build_report_payload

CODE_AUDIT_SKILL_REF = "code-audit-finding"


class DummyWorkflowAgent(AnalysisWorkflowAgent):
    def __init__(self):
        llm_service = MagicMock()
        llm_service.chat_completion_stream = MagicMock()
        super().__init__(
            name="Dummy",
            agent_type=AgentType.FINDING,
            llm_service=llm_service,
            tools={},
            event_emitter=MagicMock(),
            system_prompt="dummy",
            max_iterations=1,
        )

    def _build_initial_message(self, context):
        return "dummy"


class StubSubAgent:
    def __init__(self, result):
        self.result = result
        self.calls = []

    async def run(self, payload):
        self.calls.append(payload)
        return self.result

    def set_cancel_callback(self, callback):
        return None


@pytest.fixture
def stub_llm_service():
    service = MagicMock()
    service.chat_completion_stream = MagicMock()
    return service


@pytest.fixture
def recon_agent(stub_llm_service, mock_event_emitter):
    return ReconAgent(
        llm_service=stub_llm_service,
        tools={},
        event_emitter=mock_event_emitter,
    )


@pytest.fixture
def finding_agent(stub_llm_service, mock_event_emitter):
    return FindingAgent(
        llm_service=stub_llm_service,
        tools={},
        event_emitter=mock_event_emitter,
    )


def test_recon_normalizes_legacy_fields_into_navigation_contract(recon_agent):
    raw = {
        "project_structure": {"directories": ["src"]},
        "tech_stack": {
            "languages": ["Python"],
            "frameworks": ["FastAPI"],
            "databases": ["PostgreSQL"],
        },
        "recommended_tools": {
            "must_use": ["semgrep_scan"],
            "recommended": ["bandit_scan"],
            "reason": "python web app",
        },
        "entry_points": [{"type": "http", "file": "src/api.py", "line": 12}],
        "high_risk_areas": ["src/api.py", "src/auth.py"],
        "initial_findings": [{"title": "legacy"}],
        "summary": "legacy output",
    }

    normalized = recon_agent._normalize_recon_result(raw, config={"target_files": ["src/api.py"]})

    assert normalized["project_profile"]["languages"] == ["Python"]
    assert normalized["project_profile"]["frameworks"] == ["FastAPI"]
    assert normalized["project_profile"]["databases"] == ["PostgreSQL"]
    assert normalized["priority_paths"] == ["src/api.py", "src/auth.py"]
    assert normalized["recommended_scanners"]["must_use"] == ["semgrep_scan"]
    assert normalized["recommended_scanners"]["optional"] == ["bandit_scan"]
    assert normalized["audit_targets"]["target_files"] == ["src/api.py"]
    assert "initial_findings" not in normalized
    assert "tech_stack" not in normalized
    assert "high_risk_areas" not in normalized
    assert "recommended_tools" not in normalized


def test_recon_summary_fallback_uses_navigation_schema(recon_agent):
    recon_agent._steps = [
        ReconStep(
            thought="Found FastAPI routes and auth middleware",
            observation="src/api.py\nsrc/auth.py\nrequirements.txt\nFastAPI\nPostgreSQL\n",
        )
    ]

    summarized = recon_agent._summarize_from_steps(config={"target_files": ["src/api.py"]})

    assert "project_profile" in summarized
    assert "priority_paths" in summarized
    assert "audit_targets" in summarized
    assert "initial_findings" not in summarized
    assert "high_risk_areas" not in summarized
    assert "tech_stack" not in summarized


def test_finding_initial_message_includes_recon_navigation_and_user_scope(finding_agent):
    context = {
        "project_info": {"name": "demo", "root": "/tmp/demo"},
        "config": {
            "target_files": ["src/api.py"],
            "exclude_patterns": ["tests/**"],
            "target_vulnerabilities": ["idor", "auth_bypass"],
        },
        "task": "",
        "task_context": "audit payment ownership flow",
        "recon_data": {
            "project_profile": {
                "languages": ["Python"],
                "frameworks": ["FastAPI"],
                "databases": ["PostgreSQL"],
            },
            "entry_points": [{"type": "http", "file": "src/api.py", "line": 12}],
            "priority_paths": ["src/api.py", "src/auth.py"],
            "audit_targets": {"target_files": ["src/api.py"], "exclude_patterns": ["tests/**"]},
            "recommended_scanners": {
                "must_use": ["semgrep_scan"],
                "optional": ["bandit_scan"],
                "reason": "Python web service",
            },
            "summary": "FastAPI service with auth middleware",
        },
        "handoff_context": "",
        "focus_vulnerabilities": ["idor", "auth_bypass"],
        "target_files": ["src/api.py"],
        "exclude_patterns": ["tests/**"],
        "skill_context": {},
    }

    message = finding_agent._build_initial_message(context)

    assert "src/api.py" in message
    assert "tests/**" in message
    assert "idor" in message
    assert "auth_bypass" in message
    assert "FastAPI" in message
    assert "PostgreSQL" in message
    assert "semgrep_scan" in message
    assert "bandit_scan" in message
    assert "audit payment ownership flow" in message
    assert "请直接审计代码仓库" in message
    assert "项目信息" in message
    assert "审计优先级" in message
    assert "Review the repository directly" not in message
    assert "Project information:" not in message


def test_finding_initial_message_ignores_legacy_recon_keys_when_canonical_data_missing(finding_agent):
    context = {
        "project_info": {"name": "demo", "root": "/tmp/demo"},
        "config": {},
        "task": "",
        "task_context": "audit API ownership flow",
        "recon_data": {
            "tech_stack": {"languages": ["Python"], "frameworks": ["FastAPI"]},
            "high_risk_areas": ["legacy/path.py"],
            "recommended_tools": {"must_use": ["semgrep_scan"]},
        },
        "handoff_context": "",
        "focus_vulnerabilities": [],
        "target_files": [],
        "exclude_patterns": [],
        "skill_context": {},
    }

    message = finding_agent._build_initial_message(context)

    assert "legacy/path.py" not in message
    assert "semgrep_scan" not in message
    assert "FastAPI" not in message


def test_finding_system_prompt_includes_code_audit_skill_overlay(finding_agent):
    prompt = finding_agent.config.system_prompt

    assert "先启动当前主审计技能" in prompt
    assert "不要把扫描器式工具作为主要证据来源" in prompt
    assert "Read" in prompt
    assert "不要反复停留在技能材料上" in prompt
    assert "skill_file_path" in prompt
    assert "references_root" in prompt
    assert "load_skill_body" not in prompt
    assert "skill_resource_lookup" not in prompt
    assert "code-audit-finding" not in prompt
    assert "每次分析必用" not in prompt


def test_resolve_runtime_skill_reads_routes_language_framework_and_security_modules():
    context = {
        "project_info": {"name": "demo", "root": "/tmp/demo"},
        "config": {
            "target_vulnerabilities": ["auth_bypass", "idor", "race_condition"],
        },
        "task": "Audit GraphQL file upload approval flow for tenant isolation and duplicate payment race issues",
        "task_context": "FastAPI service with OAuth login and upload endpoints",
        "recon_data": {
            "project_profile": {
                "languages": ["Python"],
                "frameworks": ["FastAPI", "GraphQL"],
            },
            "priority_paths": ["app/api/uploads.py", "app/api/payments.py"],
            "entry_points": [
                {"type": "http", "file": "app/api/uploads.py", "line": 10},
                {"type": "graphql", "file": "app/graphql/schema.py", "line": 4},
            ],
            "summary": "OAuth-backed FastAPI GraphQL service handling uploads and payment approval flows",
        },
        "focus_vulnerabilities": ["auth_bypass", "idor", "race_condition"],
        "skill_context": {"route_plan": {"primary_skill": "code-audit-finding", "secondary_skills": []}},
    }

    routed = resolve_finding_skill_routes(context, context["skill_context"])

    assert "references/checklists/python.md" in routed["mandatory_reads"]
    assert "references/languages/python.md" in routed["mandatory_reads"]
    assert "references/frameworks/fastapi.md" in routed["mandatory_reads"]
    assert "references/security/authentication_authorization.md" in routed["mandatory_reads"]
    assert "references/security/business_logic.md" in routed["mandatory_reads"]
    assert "references/security/file_operations.md" in routed["mandatory_reads"]
    assert "references/security/api_security.md" in routed["mandatory_reads"]
    assert "references/security/graphql.md" in routed["mandatory_reads"]
    assert "references/security/race_conditions.md" in routed["mandatory_reads"]
    assert "references/adapters/python.yaml" in routed["mandatory_reads"]
    assert routed["progressive_disclosure"][0] == "references/wooyun/INDEX.md"
    assert "references/wooyun/unauthorized-access.md" in routed["case_candidates"]
    assert routed["primary_skill"] == "code-audit-finding"


def test_finding_initial_message_requires_loading_skill_and_project_specific_references(finding_agent):
    context = {
        "project_info": {"name": "demo", "root": "/tmp/demo"},
        "config": {
            "target_files": ["app/api/uploads.py"],
            "exclude_patterns": ["tests/**"],
            "target_vulnerabilities": ["auth_bypass", "idor"],
        },
        "task": "Audit upload authorization flow",
        "task_context": "Focus on tenant isolation for upload review APIs",
        "recon_data": {
            "project_profile": {
                "languages": ["Python"],
                "frameworks": ["FastAPI"],
                "databases": ["PostgreSQL"],
            },
            "entry_points": [{"type": "http", "file": "app/api/uploads.py", "line": 11}],
            "priority_paths": ["app/api/uploads.py", "app/services/authz.py"],
            "summary": "FastAPI upload service with role-based approval flow",
        },
        "focus_vulnerabilities": ["auth_bypass", "idor"],
        "target_files": ["app/api/uploads.py"],
        "exclude_patterns": ["tests/**"],
        "skill_context": {
            "prompt": "<available_skills><skill><name>Code Audit</name></skill></available_skills>",
            "route_plan": {
                "primary_skill": "code-audit-finding",
                "secondary_skills": [],
                "mandatory_reads": [],
                "recommended_reads": [],
                "selection_reason": ["default finding audit skill"],
            },
        },
    }

    message = finding_agent._build_initial_message(context)

    assert "code-audit-finding" in message
    assert message.count("<available_skills>") == 1
    assert "Read" in message
    assert "skill_file_path" in message
    assert "references_root" in message
    assert "references/checklists/python.md" in message
    assert "references/frameworks/fastapi.md" in message
    assert "references/security/authentication_authorization.md" in message
    assert "references/security/file_operations.md" in message
    assert "references/adapters/python.yaml" in message
    assert "references/wooyun/INDEX.md" in message
    assert "Fixed-first reads" not in message
    assert "Current routing inputs" not in message


def test_removed_shared_prompt_constants_are_no_longer_exported():
    assert not hasattr(system_prompts, "CORE_SECURITY_PRINCIPLES")
    assert not hasattr(system_prompts, "VULNERABILITY_PRIORITIES")
    assert not hasattr(prompt_exports, "CORE_SECURITY_PRINCIPLES")
    assert not hasattr(prompt_exports, "VULNERABILITY_PRIORITIES")


@pytest.mark.asyncio
async def test_finding_run_injects_skill_catalog_only_once(monkeypatch, finding_agent, temp_project_dir):
    async def fake_resolve_agent_skills(cls, user_id, agent_type, context):
        return {
            "metadata": [{"slug": "code-audit-finding", "name": "Code Audit", "description": "Main"}],
            "matched": [{"slug": "code-audit-finding"}],
            "prompt": "<available_skills><skill><name>Code Audit</name></skill></available_skills>",
            "route_plan": {
                "primary_skill": "code-audit-finding",
                "secondary_skills": ["ai-security-audit"],
                "mandatory_reads": ["references/checklists/python.md"],
                "recommended_reads": ["references/security/llm_security.md"],
                "selection_reason": ["default code audit", "ai signals matched"],
            },
        }

    async def fake_stream_llm_call(history):
        return 'Final Answer: {"findings": [], "summary": "none"}', 0

    monkeypatch.setattr(SkillService, "resolve_agent_skills", classmethod(fake_resolve_agent_skills))
    monkeypatch.setattr(finding_agent, "stream_llm_call", fake_stream_llm_call)

    await finding_agent.run(
        {
            "project_info": {"name": "demo", "root": temp_project_dir},
            "config": {"target_vulnerabilities": ["idor"]},
            "task": "audit",
            "task_context": "ai service",
            "previous_results": {
                "recon": {
                    "data": {
                        "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
                        "priority_paths": ["app/rag.py"],
                        "entry_points": [{"type": "http", "file": "app/api.py", "line": 1}],
                        "summary": "ai rag service",
                    }
                }
            },
        }
    )

    user_prompt = finding_agent.get_conversation_history()[1]["content"]
    assert user_prompt.count("<available_skills>") == 1
    assert "ai-security-audit" in user_prompt


def test_analysis_workflow_context_exposes_scope_and_vulnerability_focus(temp_project_dir):
    agent = DummyWorkflowAgent()

    context = agent._get_project_context(
        {
            "project_info": {"name": "demo", "root": temp_project_dir},
            "config": {
                "target_files": ["src/sql_vuln.py"],
                "exclude_patterns": ["tests/**"],
                "target_vulnerabilities": ["sql_injection"],
            },
            "task_context": "focus on SQLi",
            "previous_results": {"recon": {"data": {"priority_paths": ["src/sql_vuln.py"]}}},
        }
    )

    assert context["target_files"] == ["src/sql_vuln.py"]
    assert context["exclude_patterns"] == ["tests/**"]
    assert context["focus_vulnerabilities"] == ["sql_injection"]
    assert context["recon_data"]["priority_paths"] == ["src/sql_vuln.py"]


def test_analysis_workflow_postprocess_marks_incomplete_findings_for_verification():
    agent = DummyWorkflowAgent()

    processed = agent._postprocess_result(
        {
            "findings": [
                {
                    "title": "Missing ownership validation",
                    "vulnerability_type": "idor",
                    "severity": "high",
                    "file_path": "src/sql_vuln.py",
                    "line_start": 0,
                    "line_end": -1,
                    "confidence": 0.95,
                }
            ],
            "summary": "one finding",
        }
    )

    finding = processed["findings"][0]
    assert finding["line_start"] == 1
    assert finding["line_end"] == 1
    assert finding["needs_verification"] is True
    assert finding["confidence"] < 0.95
    assert "missing_source" in finding["evidence_gaps"]
    assert "missing_sink" in finding["evidence_gaps"]


def test_analysis_workflow_preserves_rich_vulnerability_fields():
    agent = DummyWorkflowAgent()

    processed = agent._postprocess_result(
        {
            "findings": [
                {
                    "title": "SSRF through webhook fetcher",
                    "vulnerability_type": "ssrf",
                    "severity": "high",
                    "file_path": "src/sql_vuln.py",
                    "line_start": 7,
                    "line_end": 10,
                    "source": "POST body url",
                    "sink": "requests.get(url)",
                    "confidence": 0.91,
                    "exploit_chain": [
                        {
                            "step": 1,
                            "location": "src/sql_vuln.py:7",
                            "description": "user input accepted",
                            "data_state": "attacker-controlled URL",
                        }
                    ],
                    "poc": {
                        "preconditions": ["attacker can call webhook endpoint"],
                        "steps": [
                            {
                                "step": 1,
                                "action": "POST webhook target",
                                "request": "POST /webhook",
                                "expected_response": "callback succeeds",
                            }
                        ],
                        "payload": "http://169.254.169.254/latest/meta-data/",
                        "impact": "Cloud metadata disclosure",
                        "cve_justification": "Remote SSRF to cloud metadata",
                    },
                    "impact": "Cloud metadata disclosure",
                    "cve_justification": "Remote SSRF with credential theft potential",
                    "verification_notes": "Needs outbound egress confirmation",
                    "verdict": "candidate",
                    "references": ["CWE-918"],
                }
            ],
            "summary": "one rich finding",
        }
    )

    finding = processed["findings"][0]
    assert finding["exploit_chain"][0]["location"] == "src/sql_vuln.py:7"
    assert finding["poc"]["payload"] == "http://169.254.169.254/latest/meta-data/"
    assert finding["impact"] == "Cloud metadata disclosure"
    assert finding["cve_justification"] == "Remote SSRF with credential theft potential"
    assert finding["verification_notes"] == "Needs outbound egress confirmation"
    assert finding["verdict"] == "candidate"
    assert finding["references"] == ["CWE-918"]


def test_finding_handoff_includes_navigation_context(finding_agent):
    processed = {
        "findings": [
            {
                "title": "Tenant takeover through IDOR",
                "vulnerability_type": "idor",
                "severity": "high",
                "file_path": "src/sql_vuln.py",
                "line_start": 10,
                "line_end": 12,
                "confidence": 0.82,
                "needs_verification": True,
                "entry_point_refs": ["src/api.py:12"],
                "priority_path_refs": ["src/sql_vuln.py"],
                "evidence_gaps": ["missing_sink"],
                "business_flow_notes": ["payment ownership update path"],
            }
        ],
        "summary": "one direct finding",
    }

    handoff = finding_agent._build_handoff(processed)

    assert handoff is not None
    assert handoff.to_agent == "verification"
    assert "evidence_gaps" in handoff.context_data
    assert handoff.context_data["entry_point_refs"] == ["src/api.py:12"]
    assert handoff.context_data["priority_path_refs"] == ["src/sql_vuln.py"]


def test_finding_fallback_result_does_not_recover_candidate_from_high_signal_steps(finding_agent):
    finding_agent._steps = [
        type(
            "Step",
            (),
            {
                "thought": "读取 uploadImgByHttp 相关实现，确认 fileUrl 如何传入下游请求。",
                "action": "read_file",
                "observation": """📄 文件: jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/controller/CommonController.java
行数: 315-346 / 346

```java
@PostMapping(value = "/uploadImgByHttp")
public Result<String> uploadImgByHttp(@RequestBody JSONObject jsonObject) {
    String fileUrl = jsonObject.getString("fileUrl");
    HttpFileToMultipartFileUtil httpFile = new HttpFileToMultipartFileUtil(fileUrl,"image");
}
```""",
            },
        )(),
        type(
            "Step",
            (),
            {
                "thought": "发现 /sys/common/uploadImgByHttp 接口存在 SSRF 漏洞。它接受用户提供的 fileUrl 并直接发起 HTTP 请求，没有任何内网地址限制。",
                "action": "read_file",
                "observation": """📄 文件: jeecg-boot/jeecg-module-system/jeecg-system-biz/src/main/java/org/jeecg/modules/system/util/HttpFileToMultipartFileUtil.java
行数: 36-38 / 120

```java
URL url = new URL(fileUrl);
URLConnection httpUrl = url.openConnection();
httpUrl.connect();
```""",
            },
        )(),
    ]

    recovered = finding_agent._build_fallback_result()

    assert recovered["findings"] == []
    assert "没有产出符合要求的 Final Answer" in recovered["summary"]


def test_orchestrator_merges_finding_and_triage_handoffs():
    orchestrator = OrchestratorAgent(
        llm_service=MagicMock(),
        tools={},
        event_emitter=MagicMock(),
        sub_agents={},
    )
    triage_handoff = TaskHandoff(
        from_agent="triage",
        to_agent="verification",
        summary="triage summary",
        key_findings=[{"title": "Scanner SSRF", "file_path": "src/a.py", "line_start": 5}],
        insights=["triage insight"],
        attention_points=["src/a.py"],
        priority_areas=["src/a.py"],
        context_data={"severity_distribution": {"high": 1}, "evidence_gaps": ["missing_sink"]},
    )
    finding_handoff = TaskHandoff(
        from_agent="finding",
        to_agent="verification",
        summary="finding summary",
        key_findings=[{"title": "Direct IDOR", "file_path": "src/b.py", "line_start": 9}],
        insights=["finding insight"],
        attention_points=["src/b.py"],
        priority_areas=["src/b.py"],
        context_data={"entry_point_refs": ["src/b.py:9"], "business_flow_notes": ["tenant update flow"]},
    )

    merged = orchestrator._merge_handoffs([triage_handoff, finding_handoff])

    assert merged is not None
    assert merged.from_agent == "orchestrator"
    assert merged.to_agent == "verification"
    assert len(merged.key_findings) == 2
    assert "triage insight" in merged.insights
    assert "finding insight" in merged.insights
    assert "src/a.py" in merged.priority_areas
    assert "src/b.py" in merged.priority_areas
    assert merged.context_data["entry_point_refs"] == ["src/b.py:9"]
    assert merged.context_data["evidence_gaps"] == ["missing_sink"]


def test_orchestrator_falls_back_to_merged_findings_when_verification_returns_empty():
    orchestrator = OrchestratorAgent(
        llm_service=MagicMock(),
        tools={},
        event_emitter=MagicMock(),
        sub_agents={},
    )
    merged = [
        {
            "title": "Direct SSRF",
            "vulnerability_type": "ssrf",
            "severity": "high",
            "file_path": "src/a.py",
            "line_start": 5,
            "confidence": 0.9,
            "verdict": "candidate",
        }
    ]

    verification_result = AgentResult(success=True, data={"findings": []})

    final_findings = orchestrator._finalize_findings(merged, verification_result)

    assert len(final_findings) == 1
    assert final_findings[0]["title"] == "Direct SSRF"
    assert final_findings[0]["verdict"] == "candidate"
    assert final_findings[0]["report_status"] == "candidate"


def test_orchestrator_resolves_effective_workflow_when_scan_branch_is_disabled():
    orchestrator = OrchestratorAgent(
        llm_service=MagicMock(),
        tools={},
        event_emitter=MagicMock(),
        sub_agents={},
    )

    workflow = orchestrator._resolve_workflow_state(
        {
            "workflow": {
                "agentStates": {
                    "scan": {"enabled": False},
                    "triage": {"enabled": False},
                    "finding": {"enabled": True},
                    "verification": {"enabled": True},
                }
            }
        }
    )

    assert workflow["effective_agents"]["orchestrator"] is True
    assert workflow["effective_agents"]["recon"] is True
    assert workflow["effective_agents"]["scan"] is False
    assert workflow["effective_agents"]["triage"] is False
    assert workflow["effective_agents"]["finding"] is True
    assert workflow["effective_agents"]["verification"] is True
    assert workflow["active_edges"] == [
        ("orchestrator", "recon"),
        ("recon", "finding"),
        ("finding", "verification"),
    ]


def test_orchestrator_disables_verification_without_any_enabled_analysis_branch():
    orchestrator = OrchestratorAgent(
        llm_service=MagicMock(),
        tools={},
        event_emitter=MagicMock(),
        sub_agents={},
    )

    workflow = orchestrator._resolve_workflow_state(
        {
            "workflow": {
                "agentStates": {
                    "scan": {"enabled": False},
                    "triage": {"enabled": False},
                    "finding": {"enabled": False},
                    "verification": {"enabled": True},
                }
            }
        }
    )

    assert workflow["effective_agents"]["scan"] is False
    assert workflow["effective_agents"]["triage"] is False
    assert workflow["effective_agents"]["finding"] is False
    assert workflow["effective_agents"]["verification"] is False
    assert workflow["active_edges"] == [
        ("orchestrator", "recon"),
    ]


@pytest.mark.asyncio
async def test_orchestrator_run_skips_disabled_scan_branch(mock_event_emitter):
    finding_result = AgentResult(
        success=True,
        data={
            "findings": [
                {
                    "title": "Direct IDOR",
                    "vulnerability_type": "idor",
                    "severity": "high",
                    "file_path": "src/a.py",
                    "line_start": 8,
                    "confidence": 0.92,
                    "verdict": "candidate",
                }
            ],
            "summary": "finding branch",
        },
        handoff=TaskHandoff(from_agent="finding", to_agent="verification", summary="finding handoff"),
    )
    verification_result = AgentResult(
        success=True,
        data={"findings": [], "summary": "verified"},
    )

    recon_agent = StubSubAgent(AgentResult(success=True, data={"summary": "recon"}))
    scan_agent = StubSubAgent(AgentResult(success=True, data={"raw_findings": [], "summary": "scan"}))
    triage_agent = StubSubAgent(AgentResult(success=True, data={"findings": [], "summary": "triage"}))
    finding_agent = StubSubAgent(finding_result)
    verification_agent = StubSubAgent(verification_result)

    orchestrator = OrchestratorAgent(
        llm_service=MagicMock(),
        tools={},
        event_emitter=mock_event_emitter,
        sub_agents={
            "recon": recon_agent,
            "scan": scan_agent,
            "triage": triage_agent,
            "finding": finding_agent,
            "verification": verification_agent,
        },
    )

    result = await orchestrator.run(
        {
            "task_id": "task-1",
            "project_info": {"name": "demo", "root": "/tmp/demo", "file_count": 12},
            "project_root": "/tmp/demo",
            "config": {
                "workflow": {
                    "agentStates": {
                        "scan": {"enabled": False},
                        "triage": {"enabled": False},
                        "finding": {"enabled": True},
                        "verification": {"enabled": True},
                    }
                }
            },
        }
    )

    assert result.success is True
    assert len(recon_agent.calls) == 1
    assert len(scan_agent.calls) == 0
    assert len(triage_agent.calls) == 0
    assert len(finding_agent.calls) == 1
    assert len(verification_agent.calls) == 1
    assert set(result.data["phases"].keys()) == {"recon", "finding", "verification"}
    assert result.data["workflow"]["effective_agents"]["scan"] is False
    assert result.data["workflow"]["effective_agents"]["triage"] is False
    assert result.data["workflow"]["effective_agents"]["verification"] is True


@pytest.mark.asyncio
async def test_orchestrator_stops_when_finding_runtime_is_incomplete(mock_event_emitter):
    finding_result = AgentResult(
        success=False,
        data={
            "findings": [],
            "runtime_completion_mode": "incomplete",
            "recovered_candidates": [{"title": "Recovered SSRF candidate"}],
            "summary": "Finding runtime incomplete",
        },
        error="Finding 未完成：运行时没有调用 FinalizeFinding，也没有产出结构化最终结果。",
    )

    recon_agent = StubSubAgent(AgentResult(success=True, data={"summary": "recon"}))
    scan_agent = StubSubAgent(AgentResult(success=True, data={"raw_findings": [], "summary": "scan"}))
    triage_agent = StubSubAgent(AgentResult(success=True, data={"findings": [], "summary": "triage"}))
    finding_agent = StubSubAgent(finding_result)
    verification_agent = StubSubAgent(AgentResult(success=True, data={"findings": [], "summary": "verified"}))

    orchestrator = OrchestratorAgent(
        llm_service=MagicMock(),
        tools={},
        event_emitter=mock_event_emitter,
        sub_agents={
            "recon": recon_agent,
            "scan": scan_agent,
            "triage": triage_agent,
            "finding": finding_agent,
            "verification": verification_agent,
        },
    )

    result = await orchestrator.run(
        {
            "task_id": "task-1",
            "project_info": {"name": "demo", "root": "/tmp/demo", "file_count": 12},
            "project_root": "/tmp/demo",
            "config": {
                "workflow": {
                    "agentStates": {
                        "scan": {"enabled": False},
                        "triage": {"enabled": False},
                        "finding": {"enabled": True},
                        "verification": {"enabled": True},
                    }
                }
            },
        }
    )

    assert result.success is False
    assert "Finding 未完成" in result.error
    assert len(recon_agent.calls) == 1
    assert len(finding_agent.calls) == 1
    assert len(scan_agent.calls) == 0
    assert len(triage_agent.calls) == 0
    assert len(verification_agent.calls) == 0
    assert result.data["phases"]["finding"]["success"] is False


@pytest.mark.asyncio
async def test_build_report_payload_includes_rich_vulnerability_story():
    task = MagicMock()
    task.id = "task-1"
    task.status = AgentTaskStatus.COMPLETED
    task.current_phase = "reporting"
    task.name = "demo"
    task.security_score = 55.0
    task.analyzed_files = 8
    task.false_positive_count = 1
    task.total_iterations = 12
    task.tool_calls_count = 34
    task.tokens_used = 2048
    task.duration_ms = 4567

    project = MagicMock()
    project.id = "proj-1"
    project.name = "demo-project"
    project.source_type = "upload"

    payload = await build_report_payload(
        None,
        task,
        project,
        [
            {
                "title": "Webhook SSRF",
                "severity": "high",
                "vulnerability_type": "ssrf",
                "description": "attacker controls webhook target",
                "file_path": "src/webhook.py",
                "line_start": 22,
                "line_end": 28,
                "source": "POST body url",
                "sink": "requests.get(url)",
                "exploit_chain": [{"step": 1, "location": "src/webhook.py:22"}],
                "poc": {"payload": "http://169.254.169.254/latest/meta-data/"},
                "impact": "metadata exposure",
                "cve_justification": "Remote credential theft path",
                "verdict": "confirmed",
                "origin": "direct_finding",
                "report_status": "confirmed",
                "is_verified": True,
            }
        ],
    )

    finding = payload["findings"][0]
    assert finding["exploit_chain"][0]["location"] == "src/webhook.py:22"
    assert finding["poc"]["payload"] == "http://169.254.169.254/latest/meta-data/"
    assert finding["impact"] == "metadata exposure"
    assert finding["cve_justification"] == "Remote credential theft path"
    assert finding["report_status"] == "confirmed"
    assert payload["summary"]["confirmed_findings"] == 1
    assert payload["summary"]["candidate_findings"] == 0
    assert payload["summary"]["origin_distribution"]["direct_finding"] == 1


@pytest.mark.asyncio
async def test_skill_service_exposes_code_audit_skill_for_finding_agent():
    skill_context = await SkillService.resolve_agent_skills(
        None,
        "finding",
        {
            "task": "audit auth and idor issues",
            "task_context": "focus on tenant access control",
            "config": {"target_vulnerabilities": ["auth_bypass", "idor"]},
            "recon_data": {
                "project_profile": {"languages": ["Python"], "frameworks": ["FastAPI"]},
                "priority_paths": ["app/api.py"],
                "summary": "python api",
            },
        },
    )

    slugs = {item["slug"] for item in skill_context["metadata"]}
    matched = {item["slug"] for item in skill_context["matched"]}

    assert CODE_AUDIT_SKILL_REF in slugs
    assert CODE_AUDIT_SKILL_REF in matched


def test_skill_file_service_prefers_repo_root_for_shared_assets():
    root = SkillFileService.project_root()

    assert (root / "docker-compose.yml").exists()
    assert (root / "skill_library").exists()


@pytest.mark.asyncio
async def test_skill_body_tool_defaults_missing_skill_ref(monkeypatch):
    called = {}

    async def fake_get_skill_body(user_id, skill_ref):
        called["user_id"] = user_id
        called["skill_ref"] = skill_ref
        return "skill body"

    monkeypatch.setattr(SkillService, "get_skill_body", fake_get_skill_body)

    result = await SkillBodyTool().execute()

    assert result.success is True
    assert result.data == "skill body"
    assert called["skill_ref"] == CODE_AUDIT_SKILL_REF


@pytest.mark.asyncio
async def test_skill_resource_tool_defaults_missing_skill_ref(monkeypatch):
    called = {}

    async def fake_list_skill_resources(user_id, skill_ref, resource_name):
        called["user_id"] = user_id
        called["skill_ref"] = skill_ref
        called["resource_name"] = resource_name
        return {"items": ["references/core/anti_hallucination.md"]}

    monkeypatch.setattr(SkillService, "list_skill_resources", fake_list_skill_resources)

    result = await SkillResourceTool().execute(mode="list")

    assert result.success is True
    assert result.data["items"] == ["references/core/anti_hallucination.md"]
    assert result.data["next_step"] == "Choose one file path from items and call skill_resource_lookup again with mode='read'."
    assert "references/core/anti_hallucination.md" in result.data["example_read_paths"]
    assert called["skill_ref"] == CODE_AUDIT_SKILL_REF
    assert called["resource_name"] == ""


@pytest.mark.asyncio
async def test_skill_resource_tool_read_without_resource_name_falls_back_to_listing(monkeypatch):
    called = {}

    async def fake_list_skill_resources(user_id, skill_ref, resource_name):
        called["user_id"] = user_id
        called["skill_ref"] = skill_ref
        called["resource_name"] = resource_name
        return {"items": [{"path": "references", "type": "directory"}]}

    monkeypatch.setattr(SkillService, "list_skill_resources", fake_list_skill_resources)

    result = await SkillResourceTool().execute(mode="read")

    assert result.success is True
    assert result.metadata["mode"] == "list"
    assert result.metadata["auto_fallback"] == "missing_resource_name"
    assert result.data["items"] == [{"path": "references", "type": "directory"}]
    assert result.data["next_step"] == "Choose one file path from items and call skill_resource_lookup again with mode='read'."
    assert "references/core/anti_hallucination.md" in result.data["example_read_paths"]
    assert called["skill_ref"] == CODE_AUDIT_SKILL_REF
    assert called["resource_name"] == ""


@pytest.mark.asyncio
async def test_skill_resource_tool_supports_batch_read(monkeypatch):
    calls = []

    async def fake_get_skill_resource(user_id, skill_ref, resource_name):
        calls.append((user_id, skill_ref, resource_name))
        return {"resource": resource_name, "content": f"body:{resource_name}"}

    monkeypatch.setattr(SkillService, "get_skill_resource", fake_get_skill_resource)

    result = await SkillResourceTool().execute(
        mode="read",
        resource_name=[
            "references/core/anti_hallucination.md",
            "references/core/false_positive_filter.md",
        ],
    )

    assert result.success is True
    assert result.metadata["mode"] == "batch_read"
    assert len(result.data["resources"]) == 2
    assert calls[0][1] == CODE_AUDIT_SKILL_REF
    assert calls[0][2] == "references/core/anti_hallucination.md"


@pytest.mark.asyncio
async def test_save_findings_uses_supported_status_and_model_fields(mock_db_session, temp_project_dir):
    findings = [
        {
            "title": "Confirmed traversal in uploadLocal",
            "description": "Confirmed path traversal chain.",
            "vulnerability_type": "path_traversal",
            "severity": "high",
            "file_path": "src/path_vuln.py",
            "line_start": 4,
            "line_end": 8,
            "code_snippet": "with open(filepath, 'r') as f:",
            "suggestion": "Normalize and validate the path.",
            "confidence": 0.95,
            "verdict": "confirmed",
            "references": ["CWE-22", "OWASP A01"],
            "verification_result": {"verdict": "confirmed"},
        }
    ]

    saved = await _save_findings(
        mock_db_session,
        task_id="test-task-id",
        findings=findings,
        project_root=temp_project_dir,
    )

    assert saved == 1
    mock_db_session.commit.assert_awaited_once()
    record = mock_db_session.add.call_args[0][0]
    assert record.status == FindingStatus.VERIFIED
    assert record.is_verified is True
    assert record.references == ["CWE-22", "OWASP A01"]
    assert record.finding_metadata["raw_finding"]["title"] == "Confirmed traversal in uploadLocal"


@pytest.mark.asyncio
async def test_save_findings_normalizes_model_line_range(mock_db_session, temp_project_dir):
    saved = await _save_findings(
        mock_db_session,
        task_id="test-task-id",
        findings=[
            {
                "title": "Mass assignment in user update",
                "description": "The update accepts a privileged field.",
                "vulnerability_type": "auth_bypass",
                "severity": "critical",
                "file_path": "src/path_vuln.py",
                "line_start": "407-415",
                "line_end": "407-415",
                "code_snippet": "User.update(req.body)",
                "suggestion": "Use an allowlist.",
                "confidence": 0.9,
                "verdict": "confirmed",
            }
        ],
        project_root=temp_project_dir,
    )

    assert saved == 1
    record = mock_db_session.add.call_args[0][0]
    assert record.line_start == 407
    assert record.line_end == 415



@pytest.mark.asyncio
async def test_save_findings_does_not_mark_empty_normalized_poc_as_present(mock_db_session, temp_project_dir):
    findings = [
        {
            "title": "Confirmed traversal in uploadLocal",
            "description": "Confirmed path traversal chain.",
            "vulnerability_type": "path_traversal",
            "severity": "high",
            "file_path": "src/path_vuln.py",
            "line_start": 4,
            "line_end": 8,
            "code_snippet": "with open(filepath, 'r') as f:",
            "source": "HTTP filename parameter",
            "sink": "open(filepath)",
            "suggestion": "Normalize and validate the path.",
            "confidence": 0.95,
            "verdict": "confirmed",
            "poc": {
                "preconditions": [],
                "steps": [],
                "payload": "",
                "impact": "",
                "cve_justification": "",
                "description": "",
            },
        }
    ]

    saved = await _save_findings(
        mock_db_session,
        task_id="test-task-id",
        findings=findings,
        project_root=temp_project_dir,
    )

    assert saved == 1
    record = mock_db_session.add.call_args[0][0]
    assert record.has_poc is False
    assert record.poc_description is None
    assert record.poc_steps is None


@pytest.mark.asyncio
async def test_finding_runtime_stack_preserves_verification_handoff_contract(finding_agent, mock_event_emitter, monkeypatch):
    class FakeBridge:
        def __init__(self):
            self.run_calls = []
            self.recorded_handoffs = []

        async def run(self, **kwargs):
            self.run_calls.append(kwargs)
            return {
                "session_id": "runtime-session-1",
                "final_payload": {
                    "findings": [
                        {
                            "vulnerability_type": "auth_bypass",
                            "severity": "high",
                            "title": "Tenant approval endpoint leaks cross-tenant actions",
                            "description": "Authorization is bypassed on the approval flow.",
                            "file_path": "app/api/uploads.py",
                            "line_start": 18,
                            "line_end": 34,
                            "code_snippet": "approve_upload(upload_id)",
                            "source": "POST /api/uploads/{id}/approve",
                            "sink": "approve_upload without tenant guard",
                            "suggestion": "Re-check tenant ownership before approval.",
                            "confidence": 0.91,
                            "needs_verification": True,
                            "verdict": "candidate",
                            "entry_point_refs": ["POST /api/uploads/{id}/approve"],
                            "priority_path_refs": ["app/api/uploads.py"],
                            "business_flow_notes": ["Approval requires tenant scoping."],
                            "evidence_gaps": ["Need sandbox proof for cross-tenant approval."],
                        }
                    ],
                    "summary": "Found one high-confidence authorization bypass candidate.",
                },
                "turn_count": 2,
                "tool_call_count": 3,
                "runner_result": TurnExecutionResult(
                    turn_id="turn-1",
                    stop_reason=RuntimeStopReason.COMPLETED,
                    completion_mode=RuntimeCompletionMode.FINALIZE_TOOL,
                ),
                "skill_route": {"primary_skill": "code-audit-finding"},
                "memory_counts": {"instruction": 1, "recall": 1},
            }

        def record_handoff(self, session_id, handoff_payload, *, status="pending"):
            self.recorded_handoffs.append(
                {"session_id": session_id, "handoff_payload": handoff_payload, "status": status}
            )
            return "handoff-1"

    bridge = FakeBridge()
    finding_agent._runtime_bridge_factory = lambda user_id: bridge
    finding_agent._build_initial_message = lambda context: "audit this repo"
    monkeypatch.setattr(
        SkillService,
        "resolve_agent_skills",
        AsyncMock(return_value={"route_plan": {"primary_skill": "code-audit-finding"}}),
    )

    result = await finding_agent.run(
        {
            "project_id": "project-1",
            "project_info": {"name": "demo", "root": "/tmp/demo"},
            "task_id": "task-1",
            "task": "Audit upload approval flow",
            "task_context": "Focus on tenant isolation.",
            "recon_data": {"summary": "FastAPI upload service"},
            "config": {
                "user_id": "user-1",
                "finding_runtime_stack": "runtime",
                "workflow": {"finding_runtime_stack": "runtime"},
            },
        }
    )

    assert result.success is True
    assert result.metadata["runtime_stack"] == "runtime"
    assert result.metadata["runtime_session_id"] == "runtime-session-1"
    assert result.iterations == 2
    assert result.tool_calls == 3
    assert result.data["runtime_session_id"] == "runtime-session-1"
    assert result.data["skill_route"] == {"primary_skill": "code-audit-finding"}
    assert result.data["memory_counts"] == {"instruction": 1, "recall": 1}
    assert result.handoff is not None
    assert result.handoff.to_agent == "verification"
    assert result.handoff.context_data["entry_point_refs"] == ["POST /api/uploads/{id}/approve"]
    assert result.handoff.context_data["priority_path_refs"] == ["app/api/uploads.py"]
    assert result.handoff.context_data["business_flow_notes"] == ["Approval requires tenant scoping."]
    assert "Need sandbox proof for cross-tenant approval." in result.handoff.context_data["evidence_gaps"]
    assert bridge.run_calls[0]["project_id"] == "project-1"
    assert bridge.run_calls[0]["task_id"] == "task-1"
    assert bridge.recorded_handoffs[0]["session_id"] == "runtime-session-1"
    assert bridge.recorded_handoffs[0]["handoff_payload"]["to_agent"] == "verification"


@pytest.mark.asyncio
async def test_finding_runtime_stack_emits_assistant_responses_to_activity_log(
    finding_agent,
    mock_event_emitter,
    monkeypatch,
):
    class FakeBridge:
        def __init__(self):
            self.run_calls = []

        async def run(self, **kwargs):
            self.run_calls.append(kwargs)
            event_sink = kwargs.get("event_sink")
            assert callable(event_sink)
            await event_sink(
                {
                    "type": "done",
                    "message": {
                        "id": "assistant-1",
                        "content": "",
                        "payload": {"reasoning_content": "Need to inspect auth middleware before finalizing."},
                    },
                }
            )
            return {
                "session_id": "runtime-session-1",
                "final_payload": {"findings": [], "summary": "No findings."},
                "turn_count": 1,
                "tool_call_count": 0,
                "runner_result": TurnExecutionResult(
                    turn_id="turn-1",
                    stop_reason=RuntimeStopReason.COMPLETED,
                    completion_mode=RuntimeCompletionMode.FINALIZE_TOOL,
                ),
                "skill_route": {},
                "memory_counts": {},
            }

        def record_handoff(self, session_id, handoff_payload, *, status="pending"):
            return "handoff-1"

    bridge = FakeBridge()
    finding_agent._runtime_bridge_factory = lambda user_id: bridge
    finding_agent._build_initial_message = lambda context: "audit this repo"
    monkeypatch.setattr(
        SkillService,
        "resolve_agent_skills",
        AsyncMock(return_value={}),
    )

    result = await finding_agent.run(
        {
            "project_id": "project-1",
            "project_info": {"name": "demo", "root": "/tmp/demo"},
            "task_id": "task-1",
            "task": "Audit auth middleware",
            "task_context": "Focus on auth.",
            "recon_data": {"summary": "FastAPI service"},
            "config": {
                "user_id": "user-1",
                "finding_runtime_stack": "runtime",
                "workflow": {"finding_runtime_stack": "runtime"},
            },
        }
    )

    assert result.success is True
    emitted_events = [call.args[0] for call in mock_event_emitter.emit.await_args_list]
    assert any(
        getattr(event, "event_type", "") == "thinking"
        and "Need to inspect auth middleware" in (getattr(event, "message", "") or "")
        for event in emitted_events
    )


@pytest.mark.asyncio
async def test_finding_runtime_activity_sink_flushes_reasoning_before_stream_error(
    finding_agent,
    mock_event_emitter,
):
    sink = finding_agent._build_runtime_activity_event_sink()

    await sink(
        {
            "type": "reasoning_delta",
            "content": "Need to inspect auth middleware.",
            "accumulated": "Need to inspect auth middleware.",
        }
    )
    await sink(
        {
            "type": "error",
            "error_type": "connection",
            "error": "upstream 502 from relay: provider trace id abc123",
            "user_message": "LLM streaming request failed. Please retry.",
        }
    )

    emitted_events = [call.args[0] for call in mock_event_emitter.emit.await_args_list]
    assert any(
        getattr(event, "event_type", "") == "thinking"
        and "Need to inspect auth middleware" in (getattr(event, "message", "") or "")
        for event in emitted_events
    )
    error_events = [event for event in emitted_events if getattr(event, "event_type", "") == "error"]
    assert error_events
    assert "upstream 502 from relay" in (getattr(error_events[-1], "message", "") or "")
    assert error_events[-1].metadata["raw_error"] == "upstream 502 from relay: provider trace id abc123"

