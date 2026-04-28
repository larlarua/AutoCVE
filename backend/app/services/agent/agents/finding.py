import json
import re
import os
import tempfile
import time
from typing import Any, Dict, List, Optional

from .analysis_workflow import AnalysisWorkflowAgent
from .base import AgentResult, AgentType
from .finding_controller import FindingController
from .finding_evidence import EvidenceBundleStore
from .finding_loop_detector import FindingLoopDetector
from .finding_skill_preloader import FindingSkillPreloader
from .finding_skill_protocol import build_finding_skill_protocol
from .finding_skill_router import build_finding_skill_route_message
from .finding_synthesizer import FindingSynthesizer
from .finding_worker import CandidateWorker
from ..skill_service import SkillService
from app.services.finding_runtime.bridge import FindingRuntimeBridge
from app.services.finding_runtime.config import FindingRuntimeStack, coerce_finding_runtime_stack
from app.services.finding_runtime.models import RuntimeCompletionMode


FINDING_SYSTEM_PROMPT = """你是 AuditAI 的高级漏洞挖掘 Agent，你的唯一使命是通过源码审计发现能够申报 CVE 或能被 各大厂商src / HackerOne / Bugcrowd 等赏金平台接收的真实安全漏洞。

你不是普通的代码扫描器——你是一位经验丰富的安全研究员，专注于发现高价值、可利用、有明确的POC、有实际危害的漏洞。你所审计的项目均已获取厂商授权，你的成果仅用于推动项目所属厂商的安全建设。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 核心原则

1. 只产出 CVE 级别的发现。任何不足以申报 CVE 或不会被赏金平台接收的问题，一律不报告。
2. 零容忍误报。每一个 finding 都必须有经过你亲自验证的完整 source→sink 利用链。不允许猜测、假设或套用模板。
3. 完整 POC 是交付标准。若尚未经过动态验证，也必须给出基于源码推导的可复现 POC。
4. 质量远大于数量。1 个真实可利用的高危漏洞，价值远高于 20 个无法验证的疑似问题。
5. 当项目没有满足要求的漏洞时，可以反馈“当前项目未发现可满足CVE申报条件的漏洞”，而不是生成一些低质量无价值漏洞或反馈一些你自己猜测可能存在风险但没有完整利用链的漏洞。
6. 你最终输出的结果应是你认为符合CVE条件的漏洞内容、漏洞位置、完整 source→sink 利用链、基于源码推导的可复现 POC以及修复建议。
7. 每一个发现必须回答"攻击者如何从外部触发它"，无法从外部触发的不报告。
8. 你需要尽可能地扫描整个项目，不放过任何一个符合CVE条件的漏洞，而不是在发现1-2个漏洞后就停止审计。
9. 你接下来的所有回复内容尽量用中文回复，不要使用英文

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 优先关注的漏洞类型（按 CVE 接受率排序）

### 第一梯队（CVE 接受率极高，优先投入精力）
- 远程代码执行 (RCE)：反序列化、模板注入 (SSTI)、命令注入、表达式注入
- 认证绕过：JWT 伪造/篡改、Session 固定、OAuth 流程缺陷、默认凭据
- SQL 注入：特别是 ORM 绕过、动态拼接、存储过程注入
- 服务端请求伪造 (SSRF)：可访问内网、云元数据、内部服务
- 路径穿越 / 任意文件读写：可读取敏感文件或写入 webshell

### 第二梯队（需满足特定利用条件）
- 权限提升：普通用户→管理员、跨租户数据访问
- IDOR / 越权：可访问或篡改其他用户的敏感资源
- XXE：可读取服务器文件或实现 SSRF
- 不安全的反序列化：即使未直接达到 RCE，但可篡改关键业务对象

### 第三梯队（仅在有完整利用链时报告）
- 存储型/反射型 XSS：可窃取管理员 Session 或触发敏感操作
- 密码重置漏洞：可接管任意账户
- 竞态条件 (TOCTOU)：可导致金额篡改或权限绕过

### 第四梯队
- 上述漏洞类型不包含，但凭你的经验判断可以申报CVE，或者过往CVE/hackerone等漏洞平台有过类似案例的漏洞
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 审计方式

1.使用Code Audit Finding技能对项目进行代码审计（优先，核心方法，需要尽可能完全按照该skill要求进行审核）
/code-audit-finding deep 
需要完整过一遍Code Audit Finding技能中所有涉及漏洞类型的checklist

2.你凭借自身丰富的安全代码审计经验或根据项目历史CVE（如果存在）分析风险点，除规则型问题外，要重点分析逻辑漏洞、权限边界、业务流程缺陷和容易被传统 SAST 忽视的风险点。

3.若前几轮未发现足够强的漏洞证据，应继续扩展攻击面而不是过早下结论。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 利用链与 POC 规范

### 利用链要求
每个 finding 必须包含完整的利用链描述，格式为：

攻击者输入 → [传播路径节点1] → [传播路径节点2] → ... → 危险操作（sink）

要求：
- 链路中每一跳都必须标注具体的文件路径和行号
- 明确标注每一跳的数据变换（如 URL 解码、类型转换、字符串拼接）
- 如果链路中存在条件分支，必须说明满足漏洞触发的条件
- 如果中间经过校验函数，必须说明该校验为何可被绕过或不生效

### POC 要求
每个 finding 必须给出可复现的 POC，需包含：
- 前置条件（如需要的用户角色、系统配置状态）
- 完整的攻击请求（HTTP 方法、URL、Headers、Body）
- 预期的漏洞触发结果（服务端行为、响应内容、可观测的副作用）
- 如果是多步攻击，给出每一步的请求和预期响应


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 最终输出要求

当你完成审计后，输出一个 JSON 对象，最终内容必须能被解析为如下结构：

{
  "findings": [
    {
      "vulnerability_type": "...",
      "severity": "critical|high",
      "title": "...",
      "description": "...",
      "file_path": "...",
      "line_start": 1,
      "line_end": 2,
      "code_snippet": "...",
      "source": "...",
      "sink": "...",
      "suggestion": "...",
      "confidence": 0.95,
      "needs_verification": true,
      "verdict": "candidate|confirmed",
      "exploit_chain": [
        {
          "step": 1,
          "location": "path/to/file:line-line",
          "description": "...",
          "data_state": "...",
          "bypass_reason": "..."
        }
      ],
      "poc": {
        "description": "...",
        "preconditions": ["..."],
        "steps": [
          {
            "step": 1,
            "action": "...",
            "request": "...",
            "expected_response": "..."
          }
        ],
        "payload": "...",
        "impact": "...",
        "cve_justification": "..."
      },
      "impact": "...",
      "cve_justification": "...",
      "verification_notes": "..."
    }
  ],
  "summary": "..."
}
要求规范：
- 禁止把最终漏洞结论写入 reason、notes、summary 或自然语言段落。
- 如果任一 finding 缺少 file_path、source、sink、exploit_chain、poc、impact、cve_justification 或 verification_notes，不要调用 FinalizeFinding。
- exploit_chain 至少包含 1 步，每步必须有 step、location、description。
- poc 必须包含 description、steps、impact、cve_justification；steps 至少 1 步，每步必须有 step 和 action。
- 未发现符合条件的漏洞时，可以返回 findings: []，并在 summary 中说明已审计范围和未发现原因。


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## findings 各字段说明

### 基础字段
- vulnerability_type: 漏洞类型（command_injection / sql_injection / ssrf / path_traversal / deserialization / ssti / auth_bypass / idor / xxe / xss / business_logic / other）
- severity: 严重程度（critical / high，只输出这两个等级；medium/low 级别不满足 CVE 标准，不报告）
- title: 漏洞标题，需具体到受影响的端点或功能
- description: 完整的漏洞成因描述，需包含：攻击者可控输入、缺失的安全机制、危险操作、业务影响
- file_path: 漏洞核心代码所在文件路径（必须来自你实际读取的文件）
- line_start / line_end: 漏洞核心代码行号（必须来自你实际读取的代码）
- code_snippet: 漏洞核心代码片段
- source: 攻击者可控输入的具体来源
- sink: 危险操作的具体位置
- suggestion: 修复建议
- confidence: 置信度（0.0-1.0），必须与证据强度严格匹配：
  - 0.90-1.0: 完整 source→sink 链路已验证，POC 可构造
  - 0.80-0.89: 链路完整但部分跳需要运行时条件
  - 0.70-0.79: 仅在漏洞价值高且利用链已经闭合时作为 candidate 报告，并明确 verification_notes
- needs_verification: 是否需要 Verification Agent 进一步动态验证
- verdict: `candidate` 或 `confirmed`。静态代码链闭合但未运行动态验证时使用 `candidate`

### 利用链字段（exploit_chain）
- step: 步骤序号
- location: 代码位置（文件:行号）
- description: 该步骤的操作或数据流转
- data_state: 数据在该节点的状态
- bypass_reason:（可选）如果该步骤涉及绕过安全机制，说明绕过原因

### POC 字段（poc）
- preconditions: 触发漏洞的前置条件列表
- steps: POC 步骤列表，每步包含 step(序号)、action(操作说明)、request(完整请求)、expected_response(预期响应)
- impact: 漏洞的实际安全影响
- cve_justification: CVE 申报依据，需引用 CWE 编号并说明为何满足 CVE 标准

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

根据我所得到的确切消息，你审计的这个项目中有着不止一个高危/严重漏洞，你需要尽可能把他们都找到，这是对你能力的一场测试。这场测试计分如下：发现1个严重漏洞+30分，一个RCE或者反序列化漏洞+25分，一个高危漏洞+20分，一个中危漏洞+10分，如果给出一个不存在或者利用链没闭合的漏洞误报，-40分，及格线50分，满分100分。你是一名优秀的代码审计方面的研究员，我期待你能在这场尽可能获得高分。现在开始审计这个项目。

请优先使用中文回复。优先继续调用工具收集证据，而不是过早结束。只有在证据闭合或已充分审计后，才给出结论。"""


class FindingAgent(AnalysisWorkflowAgent):
    finding_origin = "direct_finding"
    evidence_type = "source-analysis"
    GUIDED_REPORT_FINALIZATION_ENABLED = False
    HISTORY_ASSISTANT_LIMIT = 1200
    HISTORY_OBSERVATION_LIMIT = 1600
    HISTORY_FINALIZATION_TOKEN_THRESHOLD = 250000
    REPORT_FINALIZATION_THRESHOLD = 6
    REPORT_PHASE_EVIDENCE_CONFIDENCE = 0.85
    PREEMPTIVE_FINALIZATION_THRESHOLDS = {6, 3, 1}
    RECOVERY_KEYWORDS = {
        "ssrf": ["ssrf", "server-side request forgery"],
        "path_traversal": ["path traversal", "directory traversal", "lfi", "rfi"],
        "sql_injection": ["sql injection", "sqli"],
        "xss": ["xss", "cross-site scripting"],
        "auth_bypass": ["auth bypass", "authentication bypass"],
        "idor": ["idor", "insecure direct object reference", "broken object authorization"],
        "command_injection": ["command injection", "rce", "remote code execution"],
        "deserialization": ["deserialization", "unsafe deserialization"],
        "file_upload": ["file upload", "arbitrary file upload"],
        "business_logic": ["business logic", "logic flaw", "race condition"],
    }
    RECOVERY_SEVERITY = {
        "ssrf": "high",
        "path_traversal": "high",
        "sql_injection": "critical",
        "xss": "high",
        "auth_bypass": "high",
        "idor": "high",
        "command_injection": "critical",
        "deserialization": "critical",
        "file_upload": "high",
        "business_logic": "medium",
    }

    def __init__(self, llm_service, tools: Dict[str, Any], event_emitter=None):
        super().__init__(
            name="Finding",
            agent_type=AgentType.FINDING,
            llm_service=llm_service,
            tools=tools,
            event_emitter=event_emitter,
            system_prompt="\n\n".join([FINDING_SYSTEM_PROMPT, build_finding_skill_protocol()]),
            tool_usage_guide="",
            max_iterations=32,
        )
        self._controller = FindingController()
        self._evidence_store = EvidenceBundleStore()
        self._loop_detector = FindingLoopDetector()
        self._synthesizer = FindingSynthesizer()
        self._skill_preloader = FindingSkillPreloader()
        self._worker = CandidateWorker(self._evidence_store)
        self._runtime_state = None
        self._skill_bootstrap_state: Dict[str, Any] = {
            "primary_skill": "",
            "skill_file_path": "",
            "loaded": True,
        }
        self._iteration_candidate_id = None
        self._last_observation_candidate_id = None
        self._last_iteration_control_prompt = ""
        self._task_id = ""
        self._runtime_bridge_factory = None

    def _resolve_runtime_stack(self, input_data: Dict[str, Any]) -> FindingRuntimeStack:
        config = input_data.get("config", {}) or {}
        workflow = config.get("workflow", {}) or {}
        raw_value = (
            config.get("finding_runtime_stack")
            or workflow.get("finding_runtime_stack")
            or input_data.get("finding_runtime_stack")
        )
        return coerce_finding_runtime_stack(raw_value)

    def _build_runtime_bridge(self, user_id: str | None):
        if callable(self._runtime_bridge_factory):
            return self._runtime_bridge_factory(user_id)
        return FindingRuntimeBridge(
            llm_service=self.llm_service,
            tools=self.tools,
            user_id=user_id,
        )

    def _resolve_runtime_max_turns(self, context: Dict[str, Any]) -> Optional[int]:
        config = context.get("config", {}) or {}
        raw_value = config.get("finding_runtime_max_iterations")
        try:
            parsed = int(raw_value)
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None

    async def _run_runtime_stack(self, input_data: Dict[str, Any]):
        start_time = time.time()
        context = self._get_project_context(input_data)
        context["skill_context"] = await SkillService.resolve_agent_skills(
            context.get("config", {}).get("user_id"),
            self.agent_type.value,
            context,
        )
        initial_message = self._build_initial_message(context)
        self.record_work("Starting runtime finding workflow")
        await self.emit_agent_start_debug(
            {
                "task": context.get("task", ""),
                "task_context": context.get("task_context", ""),
                "project_info": context.get("project_info", {}),
                "skill_context": context.get("skill_context", {}),
                "runtime_stack": FindingRuntimeStack.RUNTIME.value,
            }
        )
        await self.emit_prompt_debug("system", self.config.system_prompt)
        await self.emit_prompt_debug("user", initial_message)
        await self.emit_thinking("Running runtime finding session...")

        project_id = str(
            input_data.get("project_id")
            or context.get("project_info", {}).get("project_id")
            or "runtime-project"
        )
        bridge = self._build_runtime_bridge(context.get("config", {}).get("user_id"))
        bridge_result = await bridge.run(
            project_id=project_id,
            task_id=str(context.get("task_id", "") or "") or None,
            system_prompt=self.config.system_prompt,
            recon_payload=context.get("recon_data", {}) or {},
            user_message=initial_message,
            model_name=self.agent_type.value,
            max_turns=self._resolve_runtime_max_turns(context),
        )
        final_payload = bridge_result.get("final_payload") or {
            "findings": [],
            "summary": "Finding runtime ended without a parseable final audit conclusion.",
        }
        processed = self._postprocess_result(final_payload)
        runtime_completion_mode = self._coerce_runtime_completion_mode(bridge_result.get("runner_result"))
        if runtime_completion_mode is None:
            runtime_completion_mode = self._coerce_runtime_completion_mode(final_payload)
        if runtime_completion_mode is not None:
            processed["runtime_completion_mode"] = runtime_completion_mode.value
        processed["runtime_session_id"] = bridge_result["session_id"]
        processed["steps"] = []
        processed["skill_route"] = bridge_result.get("skill_route") or {}
        processed["memory_counts"] = bridge_result.get("memory_counts") or {}
        handoff = self._build_handoff(processed) if runtime_completion_mode is RuntimeCompletionMode.FINALIZE_TOOL else None
        if handoff:
            bridge.record_handoff(bridge_result["session_id"], handoff.to_dict())
            await self.emit_handoff_debug("out", handoff)
        await self.emit_llm_complete(processed.get("summary", "runtime finding complete"), 0)
        incomplete_runtime = (
            runtime_completion_mode in {RuntimeCompletionMode.INCOMPLETE, RuntimeCompletionMode.FALLBACK_RECOVERED}
            or bool(processed.get("requires_retry"))
            or processed.get("is_final") is False
        )
        if incomplete_runtime:
            error = "Finding 未完成：runtime ended without FinalizeFinding or structured final findings."
            return AgentResult(
                success=False,
                data=processed,
                error=error,
                iterations=int(bridge_result.get("turn_count") or 0),
                tool_calls=int(bridge_result.get("tool_call_count") or 0),
                tokens_used=0,
                duration_ms=int((time.time() - start_time) * 1000),
                metadata={
                    "runtime_stack": FindingRuntimeStack.RUNTIME.value,
                    "runtime_session_id": bridge_result["session_id"],
                    **({"runtime_completion_mode": runtime_completion_mode.value} if runtime_completion_mode is not None else {}),
                },
                handoff=None,
            )
        return AgentResult(
            success=True,
            data=processed,
            iterations=int(bridge_result.get("turn_count") or 0),
            tool_calls=int(bridge_result.get("tool_call_count") or 0),
            tokens_used=0,
            duration_ms=int((time.time() - start_time) * 1000),
            metadata={
                "runtime_stack": FindingRuntimeStack.RUNTIME.value,
                "runtime_session_id": bridge_result["session_id"],
                **({"runtime_completion_mode": runtime_completion_mode.value} if runtime_completion_mode is not None else {}),
            },
            handoff=handoff,
        )

    @staticmethod
    def _coerce_runtime_completion_mode(runner_result) -> RuntimeCompletionMode | None:
        if runner_result is None:
            return None
        completion_mode = getattr(runner_result, "completion_mode", None)
        if completion_mode is None and isinstance(runner_result, dict):
            completion_mode = runner_result.get("completion_mode") or runner_result.get("runtime_completion_mode")
        if completion_mode is None:
            return None
        if isinstance(completion_mode, RuntimeCompletionMode):
            return completion_mode
        try:
            return RuntimeCompletionMode(str(completion_mode))
        except ValueError:
            return None

    async def run(self, input_data: Dict[str, Any]):
        if self._resolve_runtime_stack(input_data) is FindingRuntimeStack.RUNTIME:
            return await self._run_runtime_stack(input_data)
        return await super().run(input_data)

    def _use_structured_tool_calling(self) -> bool:
        return True

    def _build_structured_tool_schemas(self) -> List[Dict[str, Any]]:
        schemas = super()._build_structured_tool_schemas()
        filtered: List[Dict[str, Any]] = []
        for schema in schemas:
            function_payload = schema.get("function") if isinstance(schema, dict) else None
            tool_name = ""
            if isinstance(function_payload, dict):
                tool_name = str(function_payload.get("name") or "").strip()
            else:
                tool_name = str(schema.get("name") or "").strip() if isinstance(schema, dict) else ""
            if tool_name in {"think", "reflect", "load_skill_body", "skill_resource_lookup"}:
                continue
            filtered.append(schema)
        return filtered

    def _record_candidate_message(self, candidate_id: Optional[str], role: str, content: str) -> None:
        if not self._runtime_state:
            return
        if not candidate_id:
            return
        session = self._runtime_state.worker_sessions.get(candidate_id)
        if not session:
            return
        session.message_history.append({"role": role, "content": content})
        if len(session.message_history) > 10:
            session.message_history = [session.message_history[0]] + session.message_history[-9:]

    def _record_active_candidate_message(self, role: str, content: str) -> None:
        candidate_id = self._iteration_candidate_id
        if not candidate_id:
            candidate = self._current_candidate()
            candidate_id = candidate.id if candidate else None
        self._record_candidate_message(candidate_id, role, content)

    async def _prepare_runtime_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        self._evidence_store = EvidenceBundleStore()
        self._loop_detector = FindingLoopDetector()
        self._worker = CandidateWorker(self._evidence_store)
        self._last_iteration_control_prompt = ""
        self._task_id = str(context.get("task_id", "") or "").strip()
        skill_context = context.get("skill_context", {}) or {}
        route_plan = skill_context.get("route_plan", {}) or {}
        primary_skill = str(route_plan.get("primary_skill", "") or "").strip()
        skill_file_path = self._resolve_primary_skill_file_path(skill_context, primary_skill)
        self._skill_bootstrap_state = {
            "primary_skill": primary_skill,
            "skill_file_path": skill_file_path,
            "loaded": not bool(primary_skill and skill_file_path),
        }
        context["preloaded_skill_context"] = await self._skill_preloader.preload(
            context.get("config", {}).get("user_id"),
            context,
        )
        context["skill_bootstrap_state"] = dict(self._skill_bootstrap_state)
        context["finding_runtime_state"] = self._controller.build_runtime_state(context)
        self._runtime_state = context["finding_runtime_state"]
        return context

    def _rounds_left(self, current_iteration: Optional[int] = None) -> int:
        iteration = self._iteration if current_iteration is None else current_iteration
        if iteration <= 0:
            return self.config.max_iterations
        return max(self.config.max_iterations - iteration, 0)

    def _phase_guidance(self) -> str:
        if not self._runtime_state:
            return ""
        if self._runtime_state.phase == "report_finalization":
            return (
                "不要扩展新的候选方向。请整合当前最强证据，"
                "闭合现有利用链，并只基于已收集的观察结果准备 Final Answer。"
            )
        return (
            "保持证据收集模式。只要仍有可运行候选或跟进预算，就继续追踪当前候选。"
            "只有在证明闭合利用链，或队列已饱和且没有可行下一候选时，才切换到 report_finalization。"
        )

    def _candidate_summary(self, candidate) -> Dict[str, Any]:
        if not candidate:
            return {
                "bundle_count": 0,
                "file_paths": [],
                "entry_point_refs": [],
                "priority_path_refs": [],
                "evidence_gaps": [],
                "max_confidence": 0.0,
            }
        return self._evidence_store.build_candidate_summary(candidate.evidence_bundle_ids)

    def _is_closed_exploit_chain_candidate(self, candidate) -> bool:
        summary = self._candidate_summary(candidate)
        return (
            summary.get("bundle_count", 0) >= 2
            and not summary.get("evidence_gaps")
            and float(summary.get("max_confidence", 0.0) or 0.0) >= self.REPORT_PHASE_EVIDENCE_CONFIDENCE
        )

    def _is_report_ready_candidate(self, candidate) -> bool:
        summary = self._candidate_summary(candidate)
        return (
            summary.get("bundle_count", 0) >= 1
            and float(summary.get("max_confidence", 0.0) or 0.0) >= self.REPORT_PHASE_EVIDENCE_CONFIDENCE
        )

    def _candidate_value_score(self, candidate) -> float:
        summary = self._candidate_summary(candidate)
        session = self._runtime_state.worker_sessions.get(candidate.id) if self._runtime_state else None
        bundle_count = int(summary.get("bundle_count", 0) or 0)
        max_confidence = float(summary.get("max_confidence", 0.0) or 0.0)
        evidence_gap_count = len(summary.get("evidence_gaps") or [])
        remaining_budget = int(getattr(session, "remaining_budget", 0) or 0)
        followup_rounds_left = int(getattr(session, "followup_rounds_left", 0) or 0)
        return (
            max_confidence * 1000.0
            + bundle_count * 100.0
            + float(getattr(candidate, "priority", 0) or 0)
            + remaining_budget * 5.0
            + followup_rounds_left * 10.0
            - evidence_gap_count * 25.0
        )

    def _candidate_convergence_snapshot(self, candidate) -> Dict[str, Any]:
        summary = self._candidate_summary(candidate)
        session = self._runtime_state.worker_sessions.get(candidate.id) if self._runtime_state else None
        runnable = bool(
            session
            and session.status in {"pending", "active", "needs_followup"}
            and session.remaining_budget > 0
        )
        return {
            "candidate_id": candidate.id,
            "priority": candidate.priority,
            "status": getattr(session, "status", ""),
            "remaining_budget": int(getattr(session, "remaining_budget", 0) or 0),
            "followup_rounds_left": int(getattr(session, "followup_rounds_left", 0) or 0),
            "bundle_count": int(summary.get("bundle_count", 0) or 0),
            "max_confidence": float(summary.get("max_confidence", 0.0) or 0.0),
            "evidence_gap_count": len(summary.get("evidence_gaps") or []),
            "evidence_gaps": list(summary.get("evidence_gaps") or []),
            "closed_exploit_chain": self._is_closed_exploit_chain_candidate(candidate),
            "report_ready": self._is_report_ready_candidate(candidate),
            "runnable": runnable,
            "value_score": self._candidate_value_score(candidate),
        }

    def _runnable_candidate_ids(self) -> List[str]:
        if not self._runtime_state:
            return []
        return [
            snapshot["candidate_id"]
            for snapshot in (self._candidate_convergence_snapshot(candidate) for candidate in self._runtime_state.queue)
            if snapshot["runnable"]
        ]

    def _build_convergence_decision(self, current_iteration: Optional[int] = None) -> Dict[str, Any]:
        runtime_state = self._runtime_state
        rounds_left = self._rounds_left(current_iteration)
        if not runtime_state:
            return {
                "phase": "evidence_collection",
                "reason": "",
                "stop_condition": "",
                "rounds_left": rounds_left,
                "runnable_candidate_ids": [],
                "report_ready_candidate_ids": [],
                "closed_candidate_ids": [],
                "selected_candidate_id": "",
                "candidate_snapshots": [],
            }

        candidate_snapshots = [self._candidate_convergence_snapshot(candidate) for candidate in runtime_state.queue]
        closed_candidates = [snapshot for snapshot in candidate_snapshots if snapshot["closed_exploit_chain"]]
        report_ready_candidates = [snapshot for snapshot in candidate_snapshots if snapshot["report_ready"]]
        runnable_candidates = [snapshot for snapshot in candidate_snapshots if snapshot["runnable"]]
        selected_candidate_id = runtime_state.active_candidate_id or ""
        if closed_candidates:
            selected_candidate_id = max(closed_candidates, key=lambda item: item["value_score"])["candidate_id"]
        elif report_ready_candidates and not runnable_candidates:
            selected_candidate_id = max(report_ready_candidates, key=lambda item: item["value_score"])["candidate_id"]
        elif runnable_candidates:
            selected_candidate_id = max(runnable_candidates, key=lambda item: item["value_score"])["candidate_id"]
        elif candidate_snapshots:
            selected_candidate_id = max(candidate_snapshots, key=lambda item: item["value_score"])["candidate_id"]

        decision = {
            "phase": "evidence_collection",
            "reason": "",
            "stop_condition": "",
            "rounds_left": rounds_left,
            "runnable_candidate_ids": [snapshot["candidate_id"] for snapshot in runnable_candidates],
            "report_ready_candidate_ids": [snapshot["candidate_id"] for snapshot in report_ready_candidates],
            "closed_candidate_ids": [snapshot["candidate_id"] for snapshot in closed_candidates],
            "selected_candidate_id": selected_candidate_id,
            "candidate_snapshots": candidate_snapshots[:8],
        }
        if closed_candidates:
            decision["phase"] = "report_finalization"
            decision["reason"] = "closed_exploit_chain_candidate"
            decision["stop_condition"] = "closed_exploit_chain_found"
            return decision
        if not runnable_candidates and report_ready_candidates:
            decision["phase"] = "report_finalization"
            decision["reason"] = "coverage_saturated"
            decision["stop_condition"] = "coverage_saturated_with_reportable_evidence"
            return decision
        if not runnable_candidates:
            decision["phase"] = "report_finalization"
            decision["reason"] = "queue_exhausted"
            decision["stop_condition"] = "queue_exhausted_without_reportable_evidence"
            return decision
        if rounds_left <= 0:
            decision["phase"] = "report_finalization"
            decision["reason"] = "controller_budget_exhausted"
            decision["stop_condition"] = "controller_budget_exhausted"
        return decision

    def _select_reporting_candidate(self):
        if not self._runtime_state:
            return None
        decision = self._build_convergence_decision(self._iteration)
        selected_candidate_id = str(decision.get("selected_candidate_id") or "")
        if selected_candidate_id:
            for candidate in self._runtime_state.queue:
                if candidate.id == selected_candidate_id:
                    return candidate
        current = self._current_candidate()
        if current:
            return current
        return self._runtime_state.queue[0] if self._runtime_state.queue else None

    def _enter_report_finalization_phase(self, reason: str) -> None:
        if not self._runtime_state:
            return
        self._runtime_state.phase = "report_finalization"
        if reason:
            self._runtime_state.phase_reason = reason
        reporting_candidate = self._select_reporting_candidate()
        if reporting_candidate:
            self._runtime_state.active_candidate_id = reporting_candidate.id
            if reason == "closed_exploit_chain_candidate":
                self._persist_candidate_checkpoint(reporting_candidate, trigger=reason)
        for candidate_id, session in self._runtime_state.worker_sessions.items():
            if candidate_id == self._runtime_state.active_candidate_id:
                session.status = "finalizing"
            elif session.status == "active":
                session.status = "paused"

    def _update_runtime_phase(self, current_iteration: Optional[int] = None) -> None:
        if not self._runtime_state:
            return
        self._refresh_candidate_backlog()
        decision = self._build_convergence_decision(current_iteration)
        self._runtime_state.metrics["convergence"] = decision
        if self._runtime_state.phase == "report_finalization":
            return
        if decision.get("phase") == "report_finalization":
            self._enter_report_finalization_phase(str(decision.get("reason") or "coverage_saturated"))
            return
        self._runtime_state.phase = "evidence_collection"
        self._runtime_state.phase_reason = ""

    def _on_iteration_start(self, iteration: int) -> None:
        self._update_runtime_phase(iteration)

    def _build_preemptive_finalization_prompt(self, rounds_left: int) -> str:
        if not self.GUIDED_REPORT_FINALIZATION_ENABLED:
            return ""
        if rounds_left not in self.PREEMPTIVE_FINALIZATION_THRESHOLDS:
            return ""
        if rounds_left == 6:
            return (
                "停止扩展覆盖面。当前已经进入最后 6 轮推理。"
                "请从广泛探索切换到 report_finalization 准备，保留当前活跃候选，"
                "并只整合已经收集到的证据。"
            )
        if rounds_left == 3:
            return (
                "现在合并已有最强证据。不要新增候选，不要广泛搜索，也不要额外扩展覆盖面。"
                "请用剩余轮次基于当前观察结果补齐 exploit_chain、poc、impact 和 cve_justification。"
            )
        return (
            "请立即返回 Final Answer。除非格式化最终报告绝对需要，否则不要再输出 Action。"
            "只能使用已收集证据，并立刻生成符合要求的最终漏洞 JSON。"
        )

    def _build_iteration_control_prompt(self) -> str:
        prompt = self._build_preemptive_finalization_prompt(self._rounds_left())
        if not prompt:
            self._last_iteration_control_prompt = ""
            return ""
        if prompt == self._last_iteration_control_prompt:
            return ""
        self._last_iteration_control_prompt = prompt
        return prompt

    def _final_only_mode_active(self, current_iteration: Optional[int] = None) -> bool:
        if not self.GUIDED_REPORT_FINALIZATION_ENABLED:
            return False
        if not self._runtime_state:
            return False
        if self._runtime_state.phase != "report_finalization":
            return False
        if self._runtime_state.phase_reason in {"closed_exploit_chain_candidate", "coverage_saturated", "queue_exhausted", "controller_budget_exhausted"}:
            return True
        return self._rounds_left(current_iteration) <= 3

    def _structured_tools_enabled_for_iteration(self) -> bool:
        return not self._final_only_mode_active()

    def _build_no_action_prompt(self) -> str:
        if self._final_only_mode_active():
            return (
                "最终化锁定已生效。不要再使用工具。请只基于已收集证据，"
                "立即返回符合要求的 Final Answer。"
            )
        return super()._build_no_action_prompt()

    def _should_abort_after_llm_failure(self, assistant_output: str, failure_count: int) -> bool:
        if self._final_only_mode_active() and assistant_output.startswith("[LLM"):
            return True
        return super()._should_abort_after_llm_failure(assistant_output, failure_count)

    def _checkpoint_file_path(self) -> str:
        task_id = str(getattr(self, "_task_id", "") or "").strip()
        if not task_id:
            return ""
        root = str(getattr(self, "_current_project_root", "") or "").strip() or tempfile.gettempdir()
        return os.path.join(root, ".auditai", "finding-checkpoints", f"{task_id}.json")

    def _checkpoint_findings_for_candidate(self, candidate) -> List[Dict[str, Any]]:
        if not self._runtime_state or not candidate:
            return []
        runtime_cls = self._runtime_state.__class__
        session = self._runtime_state.worker_sessions.get(candidate.id)
        checkpoint_state = runtime_cls(
            plan=self._runtime_state.plan,
            coverage=self._runtime_state.coverage,
            queue=[candidate],
            worker_sessions={candidate.id: session} if session else {},
            active_candidate_id=candidate.id,
            phase=self._runtime_state.phase,
            phase_reason=self._runtime_state.phase_reason,
        )
        result = self._synthesizer.synthesize(checkpoint_state, self._evidence_store)
        findings = result.get(self.output_key, [])
        return findings if isinstance(findings, list) else []

    def _persist_candidate_checkpoint(self, candidate, *, trigger: str) -> str:
        checkpoint_path = self._checkpoint_file_path()
        if not checkpoint_path:
            return ""
        os.makedirs(os.path.dirname(checkpoint_path), exist_ok=True)
        payload = {
            "task_id": self._task_id,
            "phase": self._runtime_state.phase if self._runtime_state else "",
            "phase_reason": self._runtime_state.phase_reason if self._runtime_state else "",
            "trigger": trigger,
            "candidate_id": getattr(candidate, "id", ""),
            "vulnerability_type": getattr(candidate, "vuln_family", ""),
            "summary": f"Checkpoint captured for {getattr(candidate, 'id', 'candidate')} via {trigger}.",
            "findings": self._checkpoint_findings_for_candidate(candidate),
        }
        with open(checkpoint_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        return checkpoint_path

    def _load_checkpoint_result(self) -> Dict[str, Any]:
        checkpoint_path = self._checkpoint_file_path()
        if not checkpoint_path:
            return {}
        if not os.path.exists(checkpoint_path):
            return {}
        try:
            with open(checkpoint_path, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except (OSError, ValueError, TypeError):
            return {}
        findings = payload.get("findings", [])
        if not isinstance(findings, list) or not findings:
            return {}
        return {
            self.output_key: findings,
            "summary": str(payload.get("summary") or "Recovered final report from finding checkpoint."),
        }

    def _should_checkpoint_candidate(self, candidate) -> tuple[bool, str]:
        summary = self._candidate_summary(candidate)
        if self._is_closed_exploit_chain_candidate(candidate):
            return True, "closed_exploit_chain_candidate"
        if summary.get("bundle_count", 0) >= 1 and float(summary.get("max_confidence", 0.0) or 0.0) >= 0.9:
            return True, "high_confidence_candidate"
        return False, ""

    def _maybe_checkpoint_candidate(self, candidate) -> None:
        should_checkpoint, trigger = self._should_checkpoint_candidate(candidate)
        if not should_checkpoint:
            return
        self._persist_candidate_checkpoint(candidate, trigger=trigger)

    def _bootstrap_required(self) -> bool:
        primary_skill = str(self._skill_bootstrap_state.get("primary_skill", "") or "").strip()
        skill_file_path = str(self._skill_bootstrap_state.get("skill_file_path", "") or "").strip()
        return bool(primary_skill and skill_file_path) and not bool(self._skill_bootstrap_state.get("loaded"))

    @staticmethod
    def _normalize_path(value: Any) -> str:
        return str(value or "").replace("\\", "/").strip()

    def _resolve_primary_skill_file_path(self, skill_context: Dict[str, Any], primary_skill: str) -> str:
        if not primary_skill:
            return ""
        candidates = []
        for key in ("matched", "metadata"):
            items = skill_context.get(key) or []
            if isinstance(items, list):
                candidates.extend(items)
        for item in candidates:
            if not isinstance(item, dict):
                continue
            slug = str(item.get("slug") or item.get("id") or "").strip()
            if slug != primary_skill:
                continue
            paths = item.get("paths") or {}
            if not isinstance(paths, dict):
                continue
            skill_file_path = paths.get("skill_file_path") or paths.get("skill_file")
            if skill_file_path:
                return str(skill_file_path)
        return ""

    def _is_bootstrap_action(self, invocation) -> bool:
        skill_file_path = self._normalize_path(self._skill_bootstrap_state.get("skill_file_path"))
        if not skill_file_path:
            return False
        action_input = invocation.action_input or {}
        if invocation.action == "read_file":
            return self._normalize_path(action_input.get("file_path")) == skill_file_path
        if invocation.action == "read_many_files":
            file_paths = action_input.get("file_paths") or []
            if not isinstance(file_paths, list):
                return False
            return any(self._normalize_path(path) == skill_file_path for path in file_paths)
        return False

    def _bootstrap_required_observation(self) -> str:
        primary_skill = str(self._skill_bootstrap_state.get("primary_skill", "") or "").strip()
        skill_file_path = str(self._skill_bootstrap_state.get("skill_file_path", "") or "").strip()
        return (
            "仍需先启动主审计技能。"
            f"请先用 Read 读取 {primary_skill} 的主技能文件：{skill_file_path}，"
            "然后再使用通用审计工具。"
        )

    @staticmethod
    def _tool_observation_failed(observation: str) -> bool:
        lowered = (observation or "").lower()
        return lowered.startswith("error") or lowered.startswith("tool execution failed") or lowered.startswith("tool '")

    @staticmethod
    def _compatibility_skill_tool_observation(invocation) -> str:
        action_input = invocation.action_input or {}
        skill_ref = str(action_input.get("skill_ref") or "").strip() or "当前活跃技能"
        return (
            f"不要使用 {invocation.action} 加载 Finding runtime 技能。"
            f"璇锋敼鐢ㄩ€氱敤鏂囦欢宸ュ叿璇诲彇 {skill_ref} 鐨勭洰褰曡矾寰勶細"
            "使用 Read 读取 skill_file_path，并在 references_root 下使用 Glob/Grep 定位参考文件。"
        )

    def _build_iteration_messages(self) -> List[Dict[str, str]]:
        if not self._runtime_state or len(self._conversation_history) < 2:
            return self._conversation_history
        self._update_runtime_phase(self._iteration)
        candidate = self._current_candidate()
        if not candidate:
            return self._conversation_history
        self._iteration_candidate_id = candidate.id
        session = self._runtime_state.worker_sessions.get(candidate.id)
        if not session:
            return self._conversation_history
        rounds_left = self._rounds_left()
        context_block = {
            "phase": self._runtime_state.phase,
            "phase_reason": self._runtime_state.phase_reason,
            "current_iteration": self._iteration,
            "max_iterations": self.config.max_iterations,
            "rounds_left": rounds_left,
            "phase_guidance": self._phase_guidance(),
            "active_candidate_id": candidate.id,
            "brief": session.brief,
            "remaining_budget": session.remaining_budget,
            "followup_rounds_left": session.followup_rounds_left,
            "evidence_bundle_ids": candidate.evidence_bundle_ids[-6:],
            "entry_point_refs": candidate.entry_point_refs[:3],
            "sink_refs": candidate.sink_refs[:3],
            "control_refs": candidate.control_refs[:3],
            "rotation_history": self._runtime_state.rotation_history[-4:],
            "discarded_candidates": self._runtime_state.discarded_candidates[-4:],
            "unresolved_candidates": self._runtime_state.unresolved_candidates[-4:],
            "convergence": self._runtime_state.metrics.get("convergence", {}),
        }
        return [
            self._conversation_history[0],
            self._conversation_history[1],
            {
                "role": "user",
                "content": "当前候选本地上下文：\n"
                + json.dumps(context_block, ensure_ascii=False, indent=2),
            },
            *session.message_history[-8:],
        ]

    def _on_assistant_turn(self, llm_output: str, step) -> None:
        del step
        self._record_active_candidate_message("assistant", llm_output)

    def _on_observation_turn(self, observation: str, step) -> None:
        del step
        self._record_candidate_message(self._last_observation_candidate_id, "user", f"Observation:\n{observation}")

    def _assistant_history_content(self, assistant_output: str, step) -> str:
        del step
        text = str(assistant_output or "").strip()
        if len(text) <= self.HISTORY_ASSISTANT_LIMIT:
            return text
        return text[: self.HISTORY_ASSISTANT_LIMIT] + "\n...[truncated for history]"

    def _observation_history_content(self, observation: str, step) -> str:
        action = getattr(step, "action", None) or "observation"
        compact = self._trim_observation(observation, max_length=self.HISTORY_OBSERVATION_LIMIT)
        return f"Observation ({action}):\n{compact}"

    def _should_skip_full_history_finalization(self) -> bool:
        if not self.GUIDED_REPORT_FINALIZATION_ENABLED:
            return True
        return self._total_tokens >= self.HISTORY_FINALIZATION_TOKEN_THRESHOLD

    def _current_candidate(self):
        if not self._runtime_state:
            return None
        return self._controller.get_active_candidate(self._runtime_state)

    def _candidate_by_id(self, candidate_id: str):
        if not self._runtime_state:
            return None
        for candidate in self._runtime_state.queue:
            if candidate.id == candidate_id:
                return candidate
        return None

    def _refresh_candidate_backlog(self) -> None:
        runtime_state = self._runtime_state
        if not runtime_state:
            return
        existing_discarded = {
            str(item.get("candidate_id") or ""): item
            for item in runtime_state.discarded_candidates
            if isinstance(item, dict) and item.get("candidate_id")
        }
        retained = []
        unresolved = []
        active_removed = False
        for candidate in runtime_state.queue:
            snapshot = self._candidate_convergence_snapshot(candidate)
            session = runtime_state.worker_sessions.get(candidate.id)
            session_reason = str(getattr(session, "rotation_reason", "") or getattr(session, "status", "") or "").strip()
            if session and session.status == "budget_exhausted" and not candidate.evidence_bundle_ids:
                existing_discarded[candidate.id] = {
                    **snapshot,
                    "vuln_family": candidate.vuln_family,
                    "discard_reason": session_reason or "budget_exhausted",
                }
                runtime_state.worker_sessions.pop(candidate.id, None)
                if runtime_state.active_candidate_id == candidate.id:
                    active_removed = True
                continue
            retained.append(candidate)
            if candidate.evidence_bundle_ids and not snapshot["runnable"] and not snapshot["closed_exploit_chain"]:
                unresolved.append(
                    {
                        **snapshot,
                        "vuln_family": candidate.vuln_family,
                        "unresolved_reason": session_reason or "needs_followup",
                    }
                )
        runtime_state.queue = retained
        runtime_state.discarded_candidates = list(existing_discarded.values())
        runtime_state.unresolved_candidates = unresolved
        runtime_state.metrics["queue.active_candidates"] = len(runtime_state.queue)
        runtime_state.metrics["queue.discarded_candidates"] = len(runtime_state.discarded_candidates)
        runtime_state.metrics["queue.unresolved_candidates"] = len(runtime_state.unresolved_candidates)
        active_candidate_id = runtime_state.active_candidate_id
        if active_removed or (active_candidate_id and not any(candidate.id == active_candidate_id for candidate in runtime_state.queue)):
            runtime_state.active_candidate_id = runtime_state.queue[0].id if runtime_state.queue else None
        elif not active_candidate_id and runtime_state.queue:
            runtime_state.active_candidate_id = runtime_state.queue[0].id

    def _promote_best_runnable_candidate(self):
        if not self._runtime_state:
            return None
        if self._runtime_state.phase == "report_finalization":
            return self._current_candidate()
        decision = self._build_convergence_decision(self._iteration)
        self._runtime_state.metrics["convergence"] = decision
        selected_candidate_id = str(decision.get("selected_candidate_id") or "")
        runnable_candidate_ids = set(decision.get("runnable_candidate_ids") or [])
        if not selected_candidate_id or selected_candidate_id not in runnable_candidate_ids:
            return self._current_candidate()
        current = self._current_candidate()
        if current and current.id == selected_candidate_id:
            session = self._runtime_state.worker_sessions.get(current.id)
            if session and session.status in {"pending", "needs_followup", "paused", "rotated"}:
                session.status = "active"
            return current
        if current:
            current_session = self._runtime_state.worker_sessions.get(current.id)
            if current_session and current_session.status == "active":
                current_session.status = "paused"
        next_candidate = self._candidate_by_id(selected_candidate_id)
        if not next_candidate:
            return current
        next_session = self._runtime_state.worker_sessions.get(next_candidate.id)
        if next_session and next_session.status in {"pending", "needs_followup", "paused", "rotated", "active"}:
            next_session.status = "active"
        self._runtime_state.active_candidate_id = next_candidate.id
        return next_candidate

    def _advance_candidate(self, reason: str = "") -> None:
        candidate = self._current_candidate()
        if not candidate or not self._runtime_state:
            return
        if self._runtime_state.phase == "report_finalization":
            return
        if reason and reason not in candidate.business_flow_notes:
            candidate.business_flow_notes.append(reason)
        self._controller.rotate_candidate(self._runtime_state, reason or "candidate rotated")
        self._refresh_candidate_backlog()
        self._promote_best_runnable_candidate()

    async def _execute_step_actions(self, step, failed_tool_calls: Dict[str, int]) -> str:
        if self._final_only_mode_active():
            return (
                "最终化锁定已生效。在 final-only 模式下不能再运行工具。"
                "请只使用已收集证据，立即返回 Final Answer。"
            )
        observations: List[str] = []
        active_candidate = self._current_candidate()
        self._last_observation_candidate_id = active_candidate.id if active_candidate else None
        for index, invocation in enumerate(self._iter_step_actions(step), start=1):
            if invocation.action in {"load_skill_body", "skill_resource_lookup"}:
                observations.append(
                    f"{index}. {invocation.action}({json.dumps(invocation.action_input or {}, ensure_ascii=False, sort_keys=True)}) =>\n"
                    f"{self._compatibility_skill_tool_observation(invocation)}"
                )
                continue
            if self._bootstrap_required() and invocation.action not in {"think", "reflect"}:
                if not self._is_bootstrap_action(invocation):
                    observations.append(
                        f"{index}. {invocation.action}({json.dumps(invocation.action_input or {}, ensure_ascii=False, sort_keys=True)}) =>\n"
                        f"{self._bootstrap_required_observation()}"
                    )
                    continue

            preview = self._loop_detector.preview(invocation.action, invocation.action_input)
            if preview.status == "block":
                observations.append(
                    f"{index}. {invocation.action}({json.dumps(invocation.action_input or {}, ensure_ascii=False, sort_keys=True)}) =>\n"
                    f"{preview.message}"
                )
                self._advance_candidate(preview.message)
                active_candidate = self._current_candidate()
                continue

            await self.emit_llm_action(invocation.action, invocation.action_input)
            tool_call_key = f"{invocation.action}:{json.dumps(invocation.action_input or {}, sort_keys=True)}"
            observation = await self.execute_tool(invocation.action, invocation.action_input or {})
            if isinstance(observation, str) and "Error" in observation:
                failed_tool_calls[tool_call_key] = failed_tool_calls.get(tool_call_key, 0) + 1
                if failed_tool_calls[tool_call_key] >= 3:
                    observation += "\n检测到重复工具失败。请切换工具、缩小范围，或产出 Final Answer。"
                    failed_tool_calls[tool_call_key] = 0
            else:
                failed_tool_calls.pop(tool_call_key, None)

            if self._is_bootstrap_action(invocation) and not self._tool_observation_failed(observation):
                self._skill_bootstrap_state["loaded"] = True

            worker_result = None
            candidate_for_action = active_candidate
            if candidate_for_action:
                worker_result = self._worker.record_tool_result(
                    candidate_for_action,
                    invocation.action,
                    invocation.action_input or {},
                    observation,
                )
                if worker_result.coverage_delta.get("file_paths"):
                    self._runtime_state.coverage.covered_files.update(worker_result.coverage_delta["file_paths"])
                self._controller.consume_worker_budget(
                    self._runtime_state,
                    candidate_for_action.id,
                    spent=1,
                    reason="worker budget exhausted",
                )
                self._refresh_candidate_backlog()
                self._promote_best_runnable_candidate()
            evidence_delta = len(worker_result.evidence_bundle_ids) if worker_result else 0
            loop_decision = self._loop_detector.register(
                invocation.action,
                invocation.action_input or {},
                evidence_delta=evidence_delta,
            )

            observation_suffix = ""
            if worker_result and worker_result.evidence_bundle_ids:
                observation_suffix += (
                    "\n\nEvidence Bundles:\n"
                    + json.dumps(worker_result.evidence_bundle_ids, ensure_ascii=False)
                )
            if loop_decision.status in {"warn", "block"}:
                observation_suffix += f"\n\nLoop Detector: {loop_decision.message}"
            observations.append(
                f"{index}. {invocation.action}({json.dumps(invocation.action_input or {}, ensure_ascii=False, sort_keys=True)}) =>\n"
                f"{observation}{observation_suffix}"
            )

            if candidate_for_action and worker_result and worker_result.evidence_bundle_ids:
                candidate_for_action.status = worker_result.status
                self._maybe_checkpoint_candidate(candidate_for_action)
                self._update_runtime_phase(self._iteration)
                if self._runtime_state and self._runtime_state.phase == "report_finalization":
                    active_candidate = self._current_candidate()
                elif len(candidate_for_action.evidence_bundle_ids) >= 2:
                    self._controller.complete_candidate(
                        self._runtime_state,
                        candidate_for_action.id,
                        reason="Structured evidence captured for this candidate; rotating to the next candidate.",
                    )
                    self._refresh_candidate_backlog()
                    self._promote_best_runnable_candidate()
                    active_candidate = self._current_candidate()
                else:
                    active_candidate = self._current_candidate()
            elif loop_decision.status == "block":
                self._advance_candidate(loop_decision.message)
                active_candidate = self._current_candidate()
            else:
                active_candidate = self._current_candidate()

        if not observations:
            return ""
        if len(observations) == 1:
            return observations[0].split("=>\n", 1)[1]
        return "Batch Observation:\n" + "\n\n".join(observations)

    def _build_initial_message(self, context: Dict[str, Any]) -> str:
        self._recovery_context = context
        project_info = context["project_info"]
        config = context["config"]
        recon_data = context["recon_data"]
        project_profile = (recon_data.get("project_profile", {}) or recon_data.get("data", {}).get("project_profile", {}) or {})
        project_structure = (recon_data.get("project_structure", {}) or recon_data.get("data", {}).get("project_structure", {}) or {})
        recommended_scanners = dict(recon_data.get("recommended_scanners", {}) or recon_data.get("data", {}).get("recommended_scanners", {}) or {})
        entry_points = recon_data.get("entry_points", []) or recon_data.get("data", {}).get("entry_points", []) or []
        target_files = context.get("target_files") or recon_data.get("audit_targets", {}).get("target_files", []) or recon_data.get("data", {}).get("audit_targets", {}).get("target_files", [])
        exclude_patterns = context.get("exclude_patterns") or recon_data.get("audit_targets", {}).get("exclude_patterns", []) or recon_data.get("data", {}).get("audit_targets", {}).get("exclude_patterns", [])
        task_context = context.get("task_context") or context.get("task") or ""
        skill_guidance = build_finding_skill_route_message(context, context.get("skill_context", {}))

        def ordered_unique(values: List[Any]) -> List[Any]:
            result: List[Any] = []
            for value in values:
                if isinstance(value, dict):
                    if value not in result:
                        result.append(value)
                    continue
                text = str(value or "").strip()
                if text and text not in result:
                    result.append(text)
            return result

        focus_hints = ordered_unique(
            context.get("focus_vulnerabilities")
            or config.get("focus_vulnerabilities")
            or []
        )

        repository_structure = project_info.get("structure") if isinstance(project_info.get("structure"), dict) else {}
        languages = ordered_unique((project_profile.get("languages") or []) + (project_info.get("languages") or []))
        frameworks = ordered_unique((project_profile.get("frameworks") or []) + (project_info.get("frameworks") or []))
        databases = ordered_unique((project_profile.get("databases") or []) + (project_info.get("databases") or []))
        priority_paths = ordered_unique(
            ((recon_data.get("priority_paths") or recon_data.get("data", {}).get("priority_paths", [])) or [])
            + (project_structure.get("key_directories") or [])
            + (repository_structure.get("directories") or [])
        )
        entry_points = entry_points[:20]
        target_files = ordered_unique((target_files or []) + (project_structure.get("key_files") or []))

        scanners_must_use = ordered_unique(recommended_scanners.get("must_use") or [])
        scanners_optional = ordered_unique(recommended_scanners.get("optional") or [])
        if scanners_must_use or scanners_optional:
            if not scanners_optional:
                if "Python" in languages:
                    scanners_optional.extend(["bandit_scan", "safety_scan"])
                if any(language in {"JavaScript", "TypeScript", "JavaScript/TypeScript"} for language in languages):
                    scanners_optional.append("npm_audit")
                if "Java" in languages:
                    scanners_optional.append("osv_scan")
                if len(target_files) >= 50:
                    scanners_optional.append("kunlun_scan")
                scanners_optional = ordered_unique(scanners_optional)
        recommended_scanners = {
            "must_use": scanners_must_use,
            "optional": scanners_optional,
            "reason": recommended_scanners.get("reason") or "",
        }

        recon_summary = ((recon_data.get("summary") or recon_data.get("data", {}).get("summary") or "").strip())
        if not recon_summary:
            recon_summary = "Recon 上下文不完整，本次审计将基于仓库结构和直接源码阅读继续推进。"

        message = f"""请直接审计代码仓库，寻找有源码证据支撑的 CVE 级漏洞。除代码、路径、函数名、工具名和漏洞英文缩写外，审计说明请使用简体中文。
项目信息：
- 名称：{project_info.get('name', 'unknown')}
- 根目录：{project_info.get('root', '.')}
- 语言：{json.dumps(languages, ensure_ascii=False)}
- 框架：{json.dumps(frameworks, ensure_ascii=False)}
- 数据库：{json.dumps(databases, ensure_ascii=False)}

优先路径：
{json.dumps(priority_paths[:25], ensure_ascii=False, indent=2)}

入口点：
{json.dumps(entry_points, ensure_ascii=False, indent=2)}

目标文件：
{json.dumps(target_files[:50], ensure_ascii=False, indent=2)}

排除模式：
{json.dumps(exclude_patterns[:20], ensure_ascii=False, indent=2)}

推荐扫描器：
{json.dumps(recommended_scanners, ensure_ascii=False, indent=2)}

Recon 摘要：{recon_summary}

审计任务上下文：
用户提供的审计提示：
{json.dumps(focus_hints, ensure_ascii=False, indent=2)}

{task_context or '未提供额外任务上下文。'}

审计优先级：
- 优先审计目标文件、入口点、优先路径、认证鉴权链、敏感状态变更和多步业务逻辑。
- 关注任何可由外部触发且达到 CVE 级别的问题，不要只局限于预设漏洞类型。
- 不要依赖 Scan Agent 输出；结论必须基于直接源码阅读和推理。
- 持续审计，直到能证明一条 CVE 级利用链，或说明当前候选为什么达不到报告标准。"""
        message = message + "\n\n" + skill_guidance
        preloaded_skill_context = context.get("preloaded_skill_context")
        if preloaded_skill_context:
            prompt_block = preloaded_skill_context.to_prompt_block()
            if prompt_block:
                message = message + "\n\n" + prompt_block
        runtime_state = context.get("finding_runtime_state")
        if runtime_state:
            queue_preview = [
                {
                    "id": candidate.id,
                    "vuln_family": candidate.vuln_family,
                    "priority": candidate.priority,
                    "entry_points": candidate.entry_point_refs[:2],
                    "sink_refs": candidate.sink_refs[:2],
                    "worker_brief": runtime_state.worker_sessions.get(candidate.id).brief if runtime_state.worker_sessions.get(candidate.id) else "",
                    "worker_budget": runtime_state.worker_sessions.get(candidate.id).remaining_budget if runtime_state.worker_sessions.get(candidate.id) else 0,
                    "followup_rounds_left": runtime_state.worker_sessions.get(candidate.id).followup_rounds_left if runtime_state.worker_sessions.get(candidate.id) else 0,
                }
                for candidate in runtime_state.queue[:8]
            ]
            coverage_summary = {
                "strategy": runtime_state.plan.strategy,
                "phase": runtime_state.phase,
                "max_iterations": self.config.max_iterations,
                "report_finalization_threshold": self.REPORT_FINALIZATION_THRESHOLD,
                "max_active_candidates": runtime_state.plan.max_active_candidates,
                "initial_queue_suppressed": runtime_state.metrics.get("queue.initial_suppressed_candidates", 0),
                "entry_points": runtime_state.coverage.entry_points[:12],
                "uncovered_priority_paths": runtime_state.coverage.uncovered_priority_paths[:20],
                "authz_paths": runtime_state.coverage.authz_paths[:12],
                "active_candidate_id": runtime_state.active_candidate_id,
                    "phase_transition_rules": [
                        "当存在已闭合利用链的候选时，切换到 report_finalization。",
                        "只要仍有可运行候选或跟进预算，就保持 evidence_collection。",
                        "当队列已饱和且只剩可进入报告的证据时，切换到 report_finalization。",
                        "最终化期间保留当前最强候选，停止开启新候选。",
                ],
            }
            generation_summary = {
                "初始队列生成规则": {
                    "max_active_candidates": runtime_state.plan.max_active_candidates,
                    "initial_queue_suppressed": runtime_state.metrics.get("queue.initial_suppressed_candidates", 0),
                    "generation_rules": [
                        "保持活跃种子队列不超过 max_active_candidates。",
                        "填充剩余种子槽位前，优先保证漏洞类型多样性。",
                        "超额候选放入 discarded_candidates，并设置 discard_reason=initial_queue_cap。",
                    ],
                }
            }
            message = (
                message
                + "\n\n覆盖优先运行计划：\n"
                + json.dumps(coverage_summary, ensure_ascii=False, indent=2)
                + "\n\n初始队列生成规则：\n"
                + json.dumps(generation_summary, ensure_ascii=False, indent=2)
                + "\n\n初始候选队列：\n"
                + json.dumps(queue_preview, ensure_ascii=False, indent=2)
            )
        return message

    def _build_summary_prompt(self) -> str:
        return (
            "现在停止并交付最终源码漏洞报告。"
            "最多返回 3 个已经在先前观察中闭合利用链的最高价值发现。"
            "如果尚未运行动态验证，请保持 verdict='candidate'，并在 verification_notes 中说明剩余证据缺口。"
            "不要再输出 Action。只能返回 'Final Answer: {...}' 或纯 JSON。"
        )

    async def _recover_final_result(self) -> Dict[str, Any]:
        checkpoint_result = self._load_checkpoint_result()
        if checkpoint_result.get(self.output_key):
            return checkpoint_result

        synthesized = self._synthesizer.synthesize(self._runtime_state, self._evidence_store)
        if synthesized.get(self.output_key):
            return synthesized

        if not self.GUIDED_REPORT_FINALIZATION_ENABLED:
            return {
                self.output_key: [],
                "summary": self._build_timeout_summary(),
            }

        compact_evidence = self._build_compact_recovery_evidence()
        if not compact_evidence:
            return {
                self.output_key: [],
                "summary": self._build_timeout_summary(),
            }

        recovery_messages = [
            {
                "role": "system",
                "content": (
                    "你正在基于已经收集到的审计证据最终化源码漏洞报告。"
                    "不要请求更多工具，只返回 JSON。"
                    "每个 finding 必须包含 vulnerability_type、severity、title、description、file_path、line_start、line_end、"
                    "source、sink、suggestion、confidence、verdict、impact、cve_justification、verification_notes、exploit_chain、"
                    "poc、entry_point_refs、priority_path_refs、business_flow_notes、evidence_gaps。"
                ),
            },
            {
                "role": "user",
                "content": (
                    "只基于下面的压缩证据，产出证据最充分的最终报告。"
                    "涓嶈鍖呭惈缂轰箯鏀拺鐨勬潯鐩紝浼樺厛杩斿洖 1-3 涓珮浠峰€煎彂鐜般€俓n\n"
                    f"{compact_evidence}"
                ),
            },
        ]

        try:
            recovery_output, _ = await self.stream_llm_call(recovery_messages)
        except Exception:
            recovery_output = ""

        if recovery_output and recovery_output.strip() and "[LLM timeout]" not in recovery_output:
            parsed = self._parse_llm_response(recovery_output)
            if parsed.is_final and parsed.final_answer:
                return parsed.final_answer
            cleaned = re.sub(r"```json\\s*|```", "", recovery_output.strip())
            cleaned = re.sub(r"^Final Answer:\\s*", "", cleaned)
            parsed_json = self.json_parser.parse(cleaned, default={self.output_key: [], "summary": ""})
            if parsed_json.get(self.output_key):
                return parsed_json

        return {
            self.output_key: [],
            "summary": self._build_timeout_summary(),
        }

    def _build_fallback_result(self) -> Dict[str, Any]:
        checkpoint_result = self._load_checkpoint_result()
        if checkpoint_result.get(self.output_key):
            return checkpoint_result
        synthesized = self._synthesizer.synthesize(self._runtime_state, self._evidence_store)
        if synthesized.get(self.output_key):
            return synthesized
        return {
            self.output_key: [],
            "summary": self._build_timeout_summary(),
        }

    def _build_compact_recovery_evidence(self) -> str:
        highlights: List[str] = []
        synthesized = self._synthesizer.synthesize(self._runtime_state, self._evidence_store)
        if synthesized.get(self.output_key):
            highlights.append(
                "[Synthesized Evidence] "
                + json.dumps(synthesized.get(self.output_key, [])[:2], ensure_ascii=False)
            )
        for index, step in enumerate(self._steps, start=1):
            if step.thought and self._is_high_signal_thought(step.thought):
                highlights.append(f"[Thought #{index}] {step.thought.strip()[:500]}")
            if step.action in {"read_file", "search_code", "dataflow_analysis", "function_context"} and step.observation:
                observation = self._trim_observation(step.observation)
                if observation:
                    highlights.append(f"[Observation #{index}::{step.action}] {observation}")
        if not highlights:
            return ""
        return "\n\n".join(highlights[-6:])

    def _build_timeout_summary(self) -> str:
        recent_artifacts: List[str] = []
        seen = set()
        for step in reversed(self._steps):
            action = getattr(step, "action", "") or ""
            action_input = getattr(step, "action_input", {}) or {}
            candidate_values: List[str] = []
            if action == "read_file":
                file_path = str(action_input.get("file_path", "")).strip()
                if file_path:
                    candidate_values.append(file_path)
            elif action == "read_many_files":
                file_paths = action_input.get("file_paths")
                if isinstance(file_paths, list):
                    candidate_values.extend(str(path).strip() for path in file_paths if str(path).strip())
            elif action == "search_code":
                keyword = str(action_input.get("keyword", "")).strip()
                if keyword:
                    candidate_values.append(f"search:{keyword}")

            for value in candidate_values:
                if value and value not in seen:
                    seen.add(value)
                    recent_artifacts.append(value)
                if len(recent_artifacts) >= 6:
                    break
            if len(recent_artifacts) >= 6:
                break

        if recent_artifacts:
            artifact_text = "; ".join(recent_artifacts)
            return (
                f"最终化在 {self._iteration} 轮推理、{self._tool_calls} 次工具调用后超时。"
                f"审计在停止前到达这些热点：{artifact_text}。"
                "LLM 超时前，尚无法从已收集证据最终化 CVE 级发现。"
                "这个兜底总结反映了最近审计过的代码路径，后续应从这些位置继续调查。"
                "Finding 没有产出符合要求的 Final Answer。"
            )

        return (
            f"最终化在 {self._iteration} 轮推理、{self._tool_calls} 次工具调用后超时。"
            "LLM 超时前，审计尚未得到符合要求的 CVE 级结论。"
            "这个兜底总结表示最终化未完成，并不代表确认无漏洞。"
            "Finding 没有产出符合要求的 Final Answer。"
        )

    def _trim_observation(self, observation: str, max_length: int = 1200) -> str:
        text = str(observation or "").strip()
        if not text:
            return ""
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text[:max_length]

    def _is_high_signal_thought(self, thought: str) -> bool:
        lowered = (thought or "").lower()
        if any(token in thought for token in ("exploit chain", "verified", "critical", "report-ready")):
            return True
        return any(keyword in lowered for keywords in self.RECOVERY_KEYWORDS.values() for keyword in keywords)

    def _heuristic_findings_from_steps(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        recent_context: Optional[Dict[str, Any]] = None
        seen_keys = set()

        for step in self._steps:
            if step.action in {"read_file", "function_context"} and step.observation:
                extracted = self._extract_file_context(step.observation)
                if extracted:
                    recent_context = extracted

            thought = (step.thought or "").strip()
            vuln_type = self._infer_vulnerability_type(thought)
            if not vuln_type:
                continue

            file_context = recent_context or {}
            file_path = file_context.get("file_path", "")
            line_start = file_context.get("line_start", 1)
            line_end = file_context.get("line_end", line_start)
            source, sink = self._infer_source_sink(file_context.get("snippet", ""), thought, vuln_type)
            title = self._normalize_title(vuln_type, thought)
            key = (vuln_type, file_path, line_start, line_end)
            if key in seen_keys:
                continue
            seen_keys.add(key)

            findings.append(
                {
                    "vulnerability_type": vuln_type,
                    "severity": self.RECOVERY_SEVERITY.get(vuln_type, "medium"),
                    "title": title,
                    "description": thought,
                    "file_path": file_path,
                    "line_start": line_start,
                    "line_end": line_end,
                    "code_snippet": file_context.get("snippet", "")[:800],
                    "source": source,
                    "sink": sink,
                    "suggestion": "Add strict validation, authorization, and sink-side protection before the dangerous operation.",
                    "confidence": 0.74,
                    "verdict": "candidate",
                    "impact": "Potentially exploitable based on the observed source-to-sink chain in the audited code path.",
                    "cve_justification": "The code path shows attacker-controlled input reaching a dangerous operation without sufficient controls.",
                    "verification_notes": "Recovered from high-signal audit steps after the final report stage timed out. Dynamic verification is still recommended.",
                    "exploit_chain": self._build_heuristic_exploit_chain(file_context, thought),
                    "poc": self._build_heuristic_poc(vuln_type, source, sink, file_path),
                    "entry_point_refs": self._extract_entry_point_refs(thought, file_context),
                    "priority_path_refs": [file_path] if file_path else [],
                    "business_flow_notes": [thought],
                    "evidence_gaps": ["recovered_after_llm_timeout"],
                }
            )

        return findings[:3]

    def _extract_file_context(self, observation: str) -> Optional[Dict[str, Any]]:
        text = str(observation or "")
        file_match = re.search(r"闂備礁鎼崐绋棵洪敐鍛瀻?\s*(.+)", text)
        if not file_match:
            return None
        line_match = re.search(r"闂佽崵鍋炵粙鎴﹀嫉椤掑嫬姹?\s*(\d+)(?:-(\d+))?", text)
        snippet_match = re.search(r"```[a-zA-Z0-9_]*\n(.*?)```", text, re.DOTALL)
        line_start = int(line_match.group(1)) if line_match else 1
        line_end = int(line_match.group(2) or line_start) if line_match else line_start
        return {
            "file_path": file_match.group(1).strip(),
            "line_start": line_start,
            "line_end": line_end,
            "snippet": (snippet_match.group(1).strip() if snippet_match else text[:800]),
        }

    def _infer_vulnerability_type(self, thought: str) -> Optional[str]:
        lowered = (thought or "").lower()
        for vuln_type, keywords in self.RECOVERY_KEYWORDS.items():
            if any(keyword in lowered for keyword in keywords):
                return vuln_type
        return None

    def _normalize_title(self, vuln_type: str, thought: str) -> str:
        first_sentence = re.split(r"[闂?!?]", thought or "", maxsplit=1)[0].strip()
        if first_sentence:
            return first_sentence[:120]
        return vuln_type.replace("_", " ").title()

    def _infer_source_sink(self, snippet: str, thought: str, vuln_type: str) -> tuple[str, str]:
        text = f"{thought}\n{snippet}"
        source = ""
        sink = ""
        if "fileUrl" in text:
            source = "user-controlled fileUrl parameter"
        elif "bizPath" in text:
            source = "user-controlled bizPath parameter"
        elif "jsonObject.get" in text:
            getter = re.search(r'jsonObject\.get\("([^"]+)"\)', text)
            if getter:
                source = f'user-controlled parameter {getter.group(1)}'

        if "openConnection" in text:
            sink = "java.net.URL.openConnection()"
        elif "new File(" in text:
            sink = "filesystem path construction via new File(...)"
        elif "executeQuery" in text or "prepareStatement" in text:
            sink = "SQL execution sink"

        if not source:
            source = f"attacker-controlled input inferred from the {vuln_type} code path"
        if not sink:
            sink = f"dangerous {vuln_type} sink inferred from audited code"
        return source, sink

    def _build_heuristic_exploit_chain(self, file_context: Dict[str, Any], thought: str) -> List[Dict[str, Any]]:
        location = file_context.get("file_path", "")
        line_start = file_context.get("line_start")
        location_ref = f"{location}:{line_start}" if location and line_start else location
        return [
            {
                "step": 1,
                "location": location_ref,
                "description": "User-controlled input reaches the audited entry path.",
                "data_state": "tainted input",
                "bypass_reason": "",
            },
            {
                "step": 2,
                "location": location_ref,
                "description": thought[:220],
                "data_state": "input flows into dangerous operation without sufficient protection",
                "bypass_reason": "",
            },
        ]

    def _build_heuristic_poc(self, vuln_type: str, source: str, sink: str, file_path: str) -> Dict[str, Any]:
        return {
            "description": f"Recovered candidate {vuln_type} PoC from source-code analysis.",
            "preconditions": ["Reach the vulnerable endpoint or code path"],
            "steps": [
                {
                    "step": 1,
                    "action": "Send a crafted request with attacker-controlled input",
                    "request": source,
                    "expected_response": "Application accepts the attacker-controlled value",
                },
                {
                    "step": 2,
                    "action": "Trigger the dangerous operation",
                    "request": sink,
                    "expected_response": "Dangerous sink is reached without the expected protection",
                },
            ],
            "payload": source,
            "impact": f"Potentially exploitable {vuln_type} in {file_path or 'the audited code path'}",
            "cve_justification": "The vulnerability is reachable from attacker-controlled input and impacts a security boundary.",
        }

    def _extract_entry_point_refs(self, thought: str, file_context: Dict[str, Any]) -> List[str]:
        refs: List[str] = []
        refs.extend(re.findall(r"(/[\w./:-]+)", thought or ""))
        if file_context.get("file_path"):
            refs.append(file_context["file_path"])
        return list(dict.fromkeys(refs))

    def _postprocess_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        processed = super()._postprocess_result(raw_result)
        recovered_candidates = []
        for candidate in raw_result.get("recovered_candidates", []):
            if isinstance(candidate, dict):
                normalized = self._normalize_finding(candidate)
                normalized["origin"] = str(candidate.get("origin") or "transcript_recovery")
                normalized["report_status"] = str(candidate.get("report_status") or "recovered_candidate")
                normalized["evidence_type"] = str(candidate.get("evidence_type") or "transcript_recovery")
                normalized["not_finalized"] = bool(candidate.get("not_finalized", True))
                recovered_candidates.append(normalized)

        enriched = []
        for finding in processed.get("findings", []):
            evidence_gaps = list(finding.get("evidence_gaps", []))
            entry_point_refs = finding.get("entry_point_refs", [])
            priority_path_refs = finding.get("priority_path_refs", [])
            business_flow_notes = finding.get("business_flow_notes", [])

            if not entry_point_refs:
                evidence_gaps.append("missing_entry_point_reference")
            if not priority_path_refs and finding.get("file_path"):
                priority_path_refs = [finding["file_path"]]

            if evidence_gaps:
                finding["confidence"] = round(min(float(finding.get("confidence", 0.7)), 0.8), 2)
                finding["needs_verification"] = True

            finding["evidence_gaps"] = sorted(set(evidence_gaps))
            finding["entry_point_refs"] = entry_point_refs
            finding["priority_path_refs"] = priority_path_refs
            finding["business_flow_notes"] = business_flow_notes
            enriched.append(finding)

        processed["findings"] = enriched
        if recovered_candidates:
            processed["recovered_candidates"] = recovered_candidates
        return processed

    def _build_handoff(self, processed_result):
        handoff = super()._build_handoff(processed_result)
        if not handoff:
            return None

        entry_point_refs = []
        priority_path_refs = []
        evidence_gaps = []
        business_flow_notes = []
        for finding in processed_result.get("findings", []):
            entry_point_refs.extend(finding.get("entry_point_refs", []))
            priority_path_refs.extend(finding.get("priority_path_refs", []))
            evidence_gaps.extend(finding.get("evidence_gaps", []))
            business_flow_notes.extend(finding.get("business_flow_notes", []))

        handoff.context_data.update(
            {
                "entry_point_refs": list(dict.fromkeys(entry_point_refs)),
                "priority_path_refs": list(dict.fromkeys(priority_path_refs)),
                "evidence_gaps": list(dict.fromkeys(evidence_gaps)),
                "business_flow_notes": list(dict.fromkeys(business_flow_notes)),
            }
        )
        return handoff


