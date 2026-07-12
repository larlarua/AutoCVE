import asyncio
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .base import AgentConfig, AgentPattern, AgentResult, AgentType, BaseAgent, TaskHandoff
from ..prompts import MULTI_AGENT_RULES

logger = logging.getLogger(__name__)


ORCHESTRATOR_SYSTEM_PROMPT = """你是 AutoCVE 的确定性编排 Agent。
你不能让 LLM 自行决定主要阶段。
你必须执行固定流程：
1. 规划
2. Recon 信息收集
3. 并行分析：
   - scan -> triage
   - finding
4. 合并
5. verification 验证
6. finalize 收尾
"""


TRIAGE_RUNTIME_SYSTEM_PROMPT = """You are AutoCVE's runtime triage agent.

Your job is to process scan findings from the deterministic triage queue.
For batch work, call GetTriageBatch with batch_size=5, then call GetScanFinding for every finding_id in the batch.
Read the relevant source context with Read/Grep/Glob as needed before deciding.
You must finish each batch by calling FinalizeTriageBatch with exactly one decision for every finding_id in the claimed batch.
For final aggregation, call FinalizeTriage and return the tool result. Do not end with ordinary prose.
Keep only high-quality critical/high findings that have concrete source evidence.
"""


@dataclass
class ExecutionPlan:
    recon_mode: str
    verification_confidence_threshold: float
    verification_limit: int


class OrchestratorAgent(BaseAgent):
    def __init__(
        self,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
        sub_agents: Optional[Dict[str, BaseAgent]] = None,
        tracer=None,
    ):
        config = AgentConfig(
            name="Orchestrator",
            agent_type=AgentType.ORCHESTRATOR,
            pattern=AgentPattern.PLAN_AND_EXECUTE,
            max_iterations=8,
            system_prompt=f"{ORCHESTRATOR_SYSTEM_PROMPT}\n\n{MULTI_AGENT_RULES}",
        )
        super().__init__(config, llm_service, tools, event_emitter)
        self.sub_agents = sub_agents or {}
        self.tracer = tracer
        self._agent_results: Dict[str, Dict[str, Any]] = {}
        self._agent_handoffs: Dict[str, TaskHandoff] = {}
        self._all_findings: List[Dict[str, Any]] = []
        self._runtime_context: Dict[str, Any] = {}

    def _resolve_workflow_state(self, config: Dict[str, Any]) -> Dict[str, Any]:
        configured_agents = {
            "orchestrator": True,
            "recon": True,
            "scan": True,
            "triage": True,
            "finding": True,
            "verification": True,
        }

        workflow_config = config.get("workflow") or config.get("workflow_config") or {}
        incoming_states = workflow_config.get("agentStates", {}) if isinstance(workflow_config, dict) else {}
        if isinstance(incoming_states, dict):
            for agent in configured_agents:
                raw_state = incoming_states.get(agent)
                if isinstance(raw_state, dict):
                    configured_agents[agent] = bool(raw_state.get("enabled", True))
                elif isinstance(raw_state, bool):
                    configured_agents[agent] = raw_state

        configured_agents["orchestrator"] = True
        configured_agents["recon"] = True

        effective_agents = dict(configured_agents)
        effective_agents["triage"] = configured_agents["triage"] and effective_agents["scan"]
        effective_agents["verification"] = configured_agents["verification"] and (
            effective_agents["triage"] or effective_agents["finding"]
        )

        active_edges: List[tuple[str, str]] = [("orchestrator", "recon")]
        if effective_agents["scan"]:
            active_edges.append(("recon", "scan"))
        if effective_agents["triage"]:
            active_edges.append(("scan", "triage"))
        if effective_agents["finding"]:
            active_edges.append(("recon", "finding"))
        if effective_agents["verification"] and effective_agents["triage"]:
            active_edges.append(("triage", "verification"))
        if effective_agents["verification"] and effective_agents["finding"]:
            active_edges.append(("finding", "verification"))

        return {
            "configured_agents": configured_agents,
            "effective_agents": effective_agents,
            "active_edges": active_edges,
        }

    def _build_skipped_result(self, agent_name: str, reason: str, *, output_key: str = "findings") -> AgentResult:
        data: Dict[str, Any] = {"summary": reason}
        data[output_key] = []
        if output_key != "findings":
            data["findings"] = []
        return AgentResult(success=True, data=data, metadata={"skipped": True, "reason": reason, "agent": agent_name})

    @staticmethod
    def _result_tokens_used(result: Optional[AgentResult]) -> int:
        if result is None:
            return 0
        try:
            return int(result.tokens_used or 0)
        except (TypeError, ValueError):
            return 0

    def _sum_result_tokens(self, *results: Optional[AgentResult]) -> int:
        return sum(self._result_tokens_used(result) for result in results)

    def register_sub_agent(self, name: str, agent: BaseAgent):
        self.sub_agents[name] = agent

    def cancel(self):
        self._cancelled = True
        for agent in self.sub_agents.values():
            if hasattr(agent, "cancel"):
                agent.cancel()

    def _build_execution_plan(self, project_info: Dict[str, Any], config: Dict[str, Any]) -> ExecutionPlan:
        file_count = project_info.get("file_count", 0)
        target_files = config.get("target_files") or []
        if target_files and len(target_files) <= 20:
            recon_mode = "light"
        elif file_count <= 40:
            recon_mode = "light"
        elif file_count >= 400:
            recon_mode = "full"
        else:
            recon_mode = "light"

        return ExecutionPlan(
            recon_mode=recon_mode,
            verification_confidence_threshold=0.8,
            verification_limit=20,
        )

    async def _run_sub_agent(self, name: str, payload: Dict[str, Any]) -> AgentResult:
        agent = self.sub_agents[name]
        await self.emit_debug_payload(
            "handoff_out",
            {
                "from_agent": self.agent_type.value,
                "to_agent": name,
                "payload": payload,
            },
            message=f"orchestrator dispatched payload to {name}",
        )
        await self.emit_event("dispatch", f"Dispatching {name}", metadata={"agent": name})
        result = await agent.run(payload)
        self._agent_results[name] = result.to_dict()
        if result.handoff:
            self._agent_handoffs[name] = result.handoff
            await self.emit_debug_payload(
                "handoff_in",
                {
                    "from_agent": name,
                    "to_agent": self.agent_type.value,
                    "payload": result.handoff.to_dict(),
                },
                message=f"{name} returned handoff to orchestrator",
            )
        await self.emit_event("dispatch_complete", f"{name} completed", metadata={"agent": name, "success": result.success})
        return result

    def _resolve_sandbox_manager(self) -> Any:
        for toolset in (
            self.tools,
            getattr(self.sub_agents.get("scan"), "tools", {}),
            getattr(self.sub_agents.get("triage"), "tools", {}),
            getattr(self.sub_agents.get("finding"), "tools", {}),
            getattr(self.sub_agents.get("verification"), "tools", {}),
        ):
            if not isinstance(toolset, dict):
                continue
            for tool_name in ("semgrep_scan", "sandbox_exec"):
                tool = toolset.get(tool_name)
                sandbox_manager = getattr(tool, "sandbox_manager", None)
                if sandbox_manager is not None:
                    return sandbox_manager
        from app.services.agent.tools.sandbox_tool import SandboxManager

        return SandboxManager()

    def _build_scan_handoff(self, scan_data: Dict[str, Any]) -> TaskHandoff:
        summary = scan_data.get("summary") if isinstance(scan_data.get("summary"), dict) else {}
        total_candidates = int(summary.get("total_candidates") or 0) if isinstance(summary, dict) else 0
        return TaskHandoff(
            from_agent="scan",
            to_agent="triage",
            summary=f"Deterministic scan completed with {total_candidates} indexed candidates.",
            work_completed=["Ran deterministic ScanPipeline with SemgrepScan."],
            context_data={
                "scan_run_id": scan_data.get("scan_run_id"),
                "index_ref": scan_data.get("index_ref"),
                "summary_ref": scan_data.get("summary_ref"),
                "artifact_refs": scan_data.get("artifact_refs", {}),
                "scanner_runs": scan_data.get("scanner_runs", []),
            },
            confidence=0.95,
        )

    async def _run_scan_pipeline(
        self,
        *,
        input_data: Dict[str, Any],
        recon_result: AgentResult,
        config: Dict[str, Any],
    ) -> AgentResult:
        from app.services.scan_runtime import ScanPipeline

        project_root = self._runtime_context.get("project_root")
        recon_data = recon_result.data if isinstance(recon_result.data, dict) else {}
        scan_plan = recon_data.get("scan_plan") if isinstance(recon_data.get("scan_plan"), dict) else {}
        scan_plan = {
            **scan_plan,
            "target_paths": scan_plan.get("target_paths") or ["."],
            "exclude_patterns": scan_plan.get("exclude_patterns") or config.get("exclude_patterns") or [],
        }
        await self.emit_event(
            "phase_start",
            "deterministic scan pipeline",
            metadata={"phase": "scan", "scanner": "SemgrepScan"},
        )

        async def emit_scan_activity(event: Dict[str, Any]) -> None:
            metadata = dict(event.get("metadata") or {})
            metadata.setdefault("phase", "scan")
            metadata.setdefault("agent", "scan")
            event_name = str(event.get("event") or "scan_event")
            message = str(event.get("message") or event_name)
            if event_name == "scanner_started":
                message = f"SemgrepScan command: {metadata.get('command_summary', '')}".strip()
            elif event_name == "scanner_completed":
                message = (
                    "SemgrepScan completed "
                    f"(exit_code={metadata.get('exit_code')}, "
                    f"targets_scanned={metadata.get('targets_scanned')}, "
                    f"raw={metadata.get('raw_count')}, indexed={metadata.get('indexed_count')})"
                )
            elif event_name == "scan_completed":
                message = (
                    "Scan pipeline indexed "
                    f"{metadata.get('indexed_count')} candidates from {metadata.get('raw_count')} raw scanner findings."
                )
            await self.emit_event("info", message, metadata={**metadata, "scan_event": event_name})

        pipeline_result = await ScanPipeline(
            project_root=project_root,
            sandbox_manager=self._resolve_sandbox_manager(),
            event_sink=emit_scan_activity,
        ).run(
            project_id=input_data.get("project_id"),
            task_id=input_data.get("task_id"),
            project_profile=recon_data,
            scan_plan=scan_plan,
        )
        scan_data = {
            **pipeline_result,
            "raw_findings": [],
        }
        handoff = self._build_scan_handoff(scan_data)
        result = AgentResult(success=True, data=scan_data, metadata={"runtime_stack": "deterministic"}, handoff=handoff)
        self._agent_results["scan"] = result.to_dict()
        self._agent_handoffs["scan"] = handoff
        await self.emit_debug_payload(
            "handoff_in",
            {
                "from_agent": "scan",
                "to_agent": self.agent_type.value,
                "payload": handoff.to_dict(),
            },
            message="deterministic scan returned handoff to orchestrator",
        )
        await self.emit_event(
            "phase_complete",
            "scan pipeline completed",
            metadata={"phase": "scan", "scan_run_id": scan_data.get("scan_run_id"), "index_ref": scan_data.get("index_ref")},
        )
        return result

    def _triage_runtime_turn_limit(self, config: Dict[str, Any]) -> int:
        for key in ("triage_runtime_max_iterations", "triage_runtime_max_turns"):
            try:
                parsed = int(config.get(key))
            except (TypeError, ValueError):
                continue
            if parsed > 0:
                return parsed
        triage_agent = self.sub_agents.get("triage")
        configured = getattr(getattr(triage_agent, "config", None), "max_iterations", None)
        try:
            parsed = int(configured)
        except (TypeError, ValueError):
            return 12
        return max(4, min(parsed, 20))

    def _build_triage_runtime_payload(
        self,
        *,
        input_data: Dict[str, Any],
        recon_result: AgentResult,
        scan_result: AgentResult,
    ) -> Dict[str, Any]:
        scan_data = scan_result.data if isinstance(scan_result.data, dict) else {}
        scan_handoff = scan_result.handoff.to_dict() if scan_result.handoff else None
        return {
            **input_data,
            "recon_result": recon_result.to_dict(),
            "recon_data": recon_result.data if isinstance(recon_result.data, dict) else {},
            "scan_result": scan_data,
            "index_ref": scan_data.get("index_ref"),
            "handoff": scan_handoff,
        }

    def _build_triage_handoff(self, triage_data: Dict[str, Any]) -> TaskHandoff | None:
        findings = triage_data.get("findings", []) if isinstance(triage_data, dict) else []
        if not isinstance(findings, list) or not findings:
            return None
        return TaskHandoff(
            from_agent="triage",
            to_agent="verification",
            summary=triage_data.get("summary", f"{len(findings)} scanner findings kept after triage."),
            key_findings=findings[:20],
            priority_areas=[finding.get("file_path", "") for finding in findings[:15] if isinstance(finding, dict) and finding.get("file_path")],
            context_data={"triage_findings_count": len(findings), "coverage": triage_data.get("coverage", {})},
            confidence=0.85,
        )

    async def _run_runtime_triage(
        self,
        *,
        input_data: Dict[str, Any],
        recon_result: AgentResult,
        scan_result: AgentResult,
        config: Dict[str, Any],
    ) -> AgentResult:
        from app.services.agent_runtime import AgentRuntimeBridge, build_triage_runtime_spec
        from app.services.triage_runtime.queue import TriageQueue

        scan_data = scan_result.data if isinstance(scan_result.data, dict) else {}
        index_ref = str(scan_data.get("index_ref") or "").strip()
        if not index_ref:
            return AgentResult(success=False, error="ScanPipeline did not produce an index_ref for runtime triage.")

        project_root = self._runtime_context.get("project_root")
        queue = TriageQueue(project_root=project_root, index_ref=index_ref)
        initial_coverage = queue.coverage_summary()
        triage_agent = self.sub_agents.get("triage")
        bridge = AgentRuntimeBridge(
            llm_service=getattr(triage_agent, "llm_service", None) or self.llm_service,
            tools=getattr(triage_agent, "tools", {}) or self.tools,
            spec=build_triage_runtime_spec(),
            user_id=config.get("user_id"),
        )
        runtime_payload = self._build_triage_runtime_payload(
            input_data=input_data,
            recon_result=recon_result,
            scan_result=scan_result,
        )
        project_id = str(input_data.get("project_id") or input_data.get("project_info", {}).get("id") or "unknown")
        task_id = input_data.get("task_id")
        max_turns = self._triage_runtime_turn_limit(config)
        total_count = int(initial_coverage.get("total_count") or 0)
        max_batches = max(1, (total_count + 4) // 5 + 5)
        batch_runs: List[Dict[str, Any]] = []

        await self.emit_event(
            "phase_start",
            "runtime triage",
            metadata={"phase": "triage", "coverage": initial_coverage},
        )
        for batch_number in range(1, max_batches + 1):
            if self.is_cancelled:
                raise asyncio.CancelledError("Task cancelled during runtime triage.")
            coverage = queue.coverage_summary()
            if coverage.get("is_complete"):
                break
            await self.emit_event(
                "thinking",
                f"Runtime triage batch {batch_number} starting.",
                metadata={"agent": "triage", "batch_number": batch_number, "coverage": coverage},
            )
            batch_result = await bridge.run(
                project_id=project_id,
                task_id=task_id,
                system_prompt=TRIAGE_RUNTIME_SYSTEM_PROMPT,
                recon_payload=runtime_payload,
                user_message=(
                    "Process exactly one triage batch now. Call GetTriageBatch with batch_size=5, "
                    "call GetScanFinding for every returned finding_id, inspect source context with Read/Grep/Glob, "
                    "then call FinalizeTriageBatch covering every finding_id in that batch."
                ),
                max_turns=max_turns,
            )
            batch_runs.append(
                {
                    "batch_number": batch_number,
                    "session_id": batch_result.get("session_id"),
                    "final_payload": batch_result.get("final_payload"),
                    "turn_count": batch_result.get("turn_count"),
                    "tool_call_count": batch_result.get("tool_call_count"),
                }
            )
        else:
            coverage = queue.coverage_summary()
            if not coverage.get("is_complete"):
                return AgentResult(
                    success=False,
                    error="Runtime triage did not complete all scan findings within the batch limit.",
                    data={"findings": [], "coverage": coverage, "batch_runs": batch_runs},
                    metadata={"runtime_stack": "runtime"},
                )

        final_result = await bridge.run(
            project_id=project_id,
            task_id=task_id,
            system_prompt=TRIAGE_RUNTIME_SYSTEM_PROMPT,
            recon_payload=runtime_payload,
            user_message=(
                "All queued scan findings have been processed. Call FinalizeTriage now to return the final "
                "triage findings and summary. Do not claim another batch."
            ),
            max_turns=max(3, min(max_turns, 6)),
        )
        final_payload = final_result.get("final_payload") if isinstance(final_result, dict) else {}
        triage_data = dict(final_payload or {})
        triage_data.setdefault("findings", [])
        triage_data.setdefault("summary", "Runtime triage completed.")
        triage_data["batch_runs"] = batch_runs
        triage_data["final_session_id"] = final_result.get("session_id")
        triage_data["coverage"] = triage_data.get("coverage") or queue.coverage_summary()
        if triage_data.get("requires_retry"):
            return AgentResult(
                success=False,
                error="Runtime triage did not return a finalized payload.",
                data=triage_data,
                metadata={"runtime_stack": "runtime", "batch_count": len(batch_runs)},
            )
        handoff = self._build_triage_handoff(triage_data)
        result = AgentResult(
            success=True,
            data=triage_data,
            metadata={"runtime_stack": "runtime", "batch_count": len(batch_runs)},
            handoff=handoff,
        )
        self._agent_results["triage"] = result.to_dict()
        if handoff:
            self._agent_handoffs["triage"] = handoff
        await self.emit_event(
            "phase_complete",
            "runtime triage completed",
            metadata={"phase": "triage", "coverage": triage_data.get("coverage"), "findings": len(triage_data.get("findings", []))},
        )
        return result

    def _normalize_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not isinstance(finding, dict):
            return None
        normalized = dict(finding)
        if "file" in normalized and "file_path" not in normalized:
            normalized["file_path"] = normalized["file"]
        if "line" in normalized and "line_start" not in normalized:
            normalized["line_start"] = normalized["line"]
        if "severity" not in normalized:
            normalized["severity"] = "medium"
        normalized["severity"] = str(normalized.get("severity", "medium")).lower()
        if "vulnerability_type" not in normalized:
            normalized["vulnerability_type"] = normalized.get("type", "other")
        normalized.setdefault("title", f"{normalized['vulnerability_type']} finding")
        normalized.setdefault("description", "")
        normalized.setdefault("code_snippet", "")
        normalized.setdefault("confidence", 0.7)
        normalized.setdefault("needs_verification", True)
        normalized.setdefault("origins", [normalized.get("origin")] if normalized.get("origin") else [])
        normalized.setdefault("verdict", "candidate")
        normalized.setdefault("report_status", self._derive_report_status(normalized))

        file_path = normalized.get("file_path", "")
        if file_path and not self._validate_file_path(file_path):
            logger.warning("Skipping finding with invalid file path: %s", file_path)
            return None
        return normalized

    def _validate_file_path(self, file_path: str) -> bool:
        if not file_path:
            return True
        project_root = self._runtime_context.get("project_root", ".")
        try:
            abs_path = os.path.abspath(os.path.join(project_root, file_path))
            project_root_abs = os.path.abspath(project_root)
            return abs_path.startswith(project_root_abs) and os.path.exists(abs_path)
        except Exception:
            return False

    def _merge_findings(self, findings_groups: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict[str, Any]] = {}
        for group in findings_groups:
            for finding in group:
                normalized = self._normalize_finding(finding)
                if not normalized:
                    continue
                key = "|".join([
                    normalized.get("file_path", ""),
                    str(normalized.get("line_start", 0)),
                    normalized.get("vulnerability_type", "other"),
                ])
                current = merged.get(key)
                if not current:
                    merged[key] = normalized
                    continue

                current["confidence"] = max(current.get("confidence", 0.0), normalized.get("confidence", 0.0))
                severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
                if severity_rank.get(normalized.get("severity", "low"), 1) > severity_rank.get(current.get("severity", "low"), 1):
                    current["severity"] = normalized["severity"]
                if len(normalized.get("description", "")) > len(current.get("description", "")):
                    current["description"] = normalized["description"]
                if len(normalized.get("code_snippet", "")) > len(current.get("code_snippet", "")):
                    current["code_snippet"] = normalized["code_snippet"]
                if normalized.get("source") and not current.get("source"):
                    current["source"] = normalized["source"]
                if normalized.get("sink") and not current.get("sink"):
                    current["sink"] = normalized["sink"]
                if normalized.get("suggestion") and not current.get("suggestion"):
                    current["suggestion"] = normalized["suggestion"]
                if normalized.get("impact") and not current.get("impact"):
                    current["impact"] = normalized["impact"]
                if normalized.get("cve_justification") and not current.get("cve_justification"):
                    current["cve_justification"] = normalized["cve_justification"]
                if normalized.get("verification_notes") and not current.get("verification_notes"):
                    current["verification_notes"] = normalized["verification_notes"]
                if normalized.get("exploit_chain") and not current.get("exploit_chain"):
                    current["exploit_chain"] = normalized["exploit_chain"]
                if normalized.get("poc") and not current.get("poc"):
                    current["poc"] = normalized["poc"]
                if normalized.get("references") and not current.get("references"):
                    current["references"] = normalized["references"]
                if normalized.get("verdict") and current.get("verdict") in {None, "", "candidate"}:
                    current["verdict"] = normalized["verdict"]
                current["needs_verification"] = current.get("needs_verification", True) or normalized.get("needs_verification", True)
                origin = normalized.get("origin")
                if origin and origin not in current["origins"]:
                    current["origins"].append(origin)
                current["origin"] = current["origins"][0] if len(current["origins"]) == 1 else "multiple"
                current["report_status"] = self._derive_report_status(current)
        return list(merged.values())

    def _merge_context_data(self, base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(base)
        for key, value in (incoming or {}).items():
            existing = merged.get(key)
            if isinstance(existing, dict) and isinstance(value, dict):
                merged[key] = self._merge_context_data(existing, value)
            elif isinstance(existing, list) and isinstance(value, list):
                merged[key] = list(dict.fromkeys([*existing, *value]))
            elif existing in (None, "", [], {}):
                merged[key] = value
            else:
                merged[key] = value
        return merged

    def _merge_handoffs(self, handoffs: List[Optional[TaskHandoff]]) -> Optional[TaskHandoff]:
        valid_handoffs = [handoff for handoff in handoffs if handoff]
        if not valid_handoffs:
            return None
        if len(valid_handoffs) == 1:
            return valid_handoffs[0]

        merged_context: Dict[str, Any] = {}
        key_findings: List[Dict[str, Any]] = []
        work_completed: List[str] = []
        insights: List[str] = []
        suggested_actions: List[Dict[str, Any]] = []
        attention_points: List[str] = []
        priority_areas: List[str] = []
        summaries: List[str] = []

        for handoff in valid_handoffs:
            if handoff.summary:
                summaries.append(f"{handoff.from_agent}: {handoff.summary}")
            for finding in handoff.key_findings:
                if finding not in key_findings:
                    key_findings.append(finding)
            work_completed.extend(item for item in handoff.work_completed if item not in work_completed)
            insights.extend(item for item in handoff.insights if item not in insights)
            for action in handoff.suggested_actions:
                if action not in suggested_actions:
                    suggested_actions.append(action)
            attention_points.extend(item for item in handoff.attention_points if item not in attention_points)
            priority_areas.extend(item for item in handoff.priority_areas if item not in priority_areas)
            merged_context = self._merge_context_data(merged_context, handoff.context_data or {})

        return TaskHandoff(
            from_agent=self.agent_type.value,
            to_agent="verification",
            summary="\n".join(summaries),
            work_completed=work_completed,
            key_findings=key_findings[:20],
            insights=insights,
            suggested_actions=suggested_actions[:20],
            attention_points=attention_points[:20],
            priority_areas=priority_areas[:20],
            context_data=merged_context,
            confidence=max(handoff.confidence for handoff in valid_handoffs),
        )

    def _finding_key(self, finding: Dict[str, Any]) -> str:
        return "|".join(
            [
                str(finding.get("file_path", "")),
                str(finding.get("line_start", 0)),
                str(finding.get("vulnerability_type", "other")),
            ]
        )

    def _derive_report_status(self, finding: Dict[str, Any]) -> str:
        verdict = str(finding.get("verdict", "") or "").lower()
        if verdict in {"confirmed", "false_positive", "candidate", "likely", "uncertain"}:
            return "candidate" if verdict == "likely" else verdict
        if finding.get("is_verified"):
            return "confirmed"
        if str(finding.get("status", "")).lower() == "false_positive":
            return "false_positive"
        return "candidate"

    def _finalize_findings(self, merged_findings: List[Dict[str, Any]], verification_result: Optional[AgentResult]) -> List[Dict[str, Any]]:
        baseline = [dict(item, report_status=self._derive_report_status(item)) for item in merged_findings]
        if not verification_result or not verification_result.success or not isinstance(verification_result.data, dict):
            return baseline

        verification_findings = verification_result.data.get("findings", [])
        if not isinstance(verification_findings, list) or not verification_findings:
            return baseline

        final_map = {self._finding_key(finding): dict(finding) for finding in baseline}
        for verified in verification_findings:
            normalized = self._normalize_finding(verified)
            if not normalized:
                continue
            key = self._finding_key(normalized)
            current = final_map.get(key, {})
            merged = {**current, **normalized}
            merged["report_status"] = self._derive_report_status(merged)
            final_map[key] = merged
        return list(final_map.values())

    def _select_findings_for_verification(self, findings: List[Dict[str, Any]], plan: ExecutionPlan) -> List[Dict[str, Any]]:
        selected = []
        for finding in findings:
            severity = finding.get("severity", "low")
            confidence = finding.get("confidence", 0.0)
            if severity in {"critical", "high"}:
                selected.append(finding)
            elif finding.get("needs_verification") and confidence >= plan.verification_confidence_threshold:
                selected.append(finding)
        return selected[: plan.verification_limit]

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        import time

        start_time = time.time()
        project_info = input_data.get("project_info", {})
        config = input_data.get("config", {})
        self._runtime_context = {
            "project_info": project_info,
            "config": config,
            "project_root": input_data.get("project_root", project_info.get("root", ".")),
            "task_id": input_data.get("task_id"),
        }
        self._agent_results = {}
        self._agent_handoffs = {}
        self._all_findings = []

        try:
            plan = self._build_execution_plan(project_info, config)
            workflow_state = self._resolve_workflow_state(config)
            await self.emit_agent_start_debug(
                {
                    "project_info": project_info,
                    "config": config,
                    "project_root": self._runtime_context.get("project_root"),
                }
            )
            await self.emit_prompt_debug("system", self.config.system_prompt)
            await self.emit_prompt_debug(
                "user",
                f"Execute deterministic orchestration for task {input_data.get('task_id')} with project {project_info.get('name', 'unknown')}",
            )
            await self.emit_event(
                "phase_start",
                "planning",
                metadata={"phase": "planning", "plan": plan.__dict__, "workflow": workflow_state},
            )

            recon_payload = {
                **input_data,
                "task": "light recon for project profiling",
                "task_context": f"Run {plan.recon_mode} recon and output project profile, entry points, priority paths and recommended scanners.",
            }
            await self.emit_event("phase_complete", "planning completed", metadata={"phase": "planning"})

            recon_result = await self._run_sub_agent("recon", recon_payload)
            previous_results = {"recon": recon_result.to_dict()}

            scan_payload = {
                **input_data,
                "previous_results": previous_results,
                "task": "mandatory scanner execution",
                "task_context": "Run scanner tools only and produce raw findings.",
            }
            finding_payload = {
                **input_data,
                "previous_results": previous_results,
                "task": "direct source finding",
                "task_context": "Review source code directly for logic and auth risks.",
            }

            await self.emit_event(
                "phase_start",
                "analysis",
                metadata={
                    "phase": "analysis",
                    "execution_mode": "finding_first_sequential",
                    "workflow": workflow_state,
                },
            )

            if workflow_state["effective_agents"]["finding"]:
                finding_result = await self._run_sub_agent("finding", finding_payload)
                if not finding_result.success:
                    error = finding_result.error or "Finding agent failed before producing finalized findings."
                    await self.emit_event(
                        "phase_failed",
                        "analysis failed",
                        metadata={"phase": "analysis", "agent": "finding", "error": error},
                    )
                    return AgentResult(
                        success=False,
                        error=error,
                        data={
                            "phases": {
                                "recon": recon_result.to_dict(),
                                "finding": finding_result.to_dict(),
                            },
                            "workflow": workflow_state,
                            "findings": [],
                            "summary": {"error": error},
                        },
                    )
            else:
                finding_result = self._build_skipped_result("finding", "Finding agent disabled in workflow config.")
                await self.emit_event("thinking", "Skipping finding: disabled in workflow config.", metadata={"agent": "finding", "skipped": True})

            if workflow_state["effective_agents"]["scan"]:
                scan_result = await self._run_scan_pipeline(
                    input_data=input_data,
                    recon_result=recon_result,
                    config=config,
                )
            else:
                scan_result = self._build_skipped_result("scan", "Scan agent disabled in workflow config.", output_key="raw_findings")
                await self.emit_event("thinking", "Skipping scan: disabled in workflow config.", metadata={"agent": "scan", "skipped": True})

            if workflow_state["effective_agents"]["triage"]:
                triage_result = await self._run_runtime_triage(
                    input_data=input_data,
                    recon_result=recon_result,
                    scan_result=scan_result,
                    config=config,
                )
                if not triage_result.success:
                    error = triage_result.error or "Runtime triage failed before producing finalized findings."
                    await self.emit_event(
                        "phase_failed",
                        "analysis failed",
                        metadata={"phase": "analysis", "agent": "triage", "error": error},
                    )
                    return AgentResult(
                        success=False,
                        error=error,
                        data={
                            "phases": {
                                "recon": recon_result.to_dict(),
                                "scan": scan_result.to_dict(),
                                "triage": triage_result.to_dict(),
                            },
                            "workflow": workflow_state,
                            "findings": [],
                            "summary": {"error": error},
                        },
                    )
            else:
                triage_reason = (
                    "Triage agent disabled in workflow config."
                    if workflow_state["configured_agents"]["triage"] is False
                    else "Triage skipped because scan is disabled."
                )
                triage_result = self._build_skipped_result("triage", triage_reason)
                await self.emit_event("thinking", f"Skipping triage: {triage_reason}", metadata={"agent": "triage", "skipped": True})
            await self.emit_event("phase_complete", "analysis completed", metadata={"phase": "analysis"})

            triage_findings = triage_result.data.get("findings", []) if triage_result.success and isinstance(triage_result.data, dict) else []
            direct_findings = finding_result.data.get("findings", []) if finding_result.success and isinstance(finding_result.data, dict) else []
            merged_findings = self._merge_findings([triage_findings, direct_findings])
            self._all_findings = merged_findings

            verification_candidates: List[Dict[str, Any]] = []
            verification_result: Optional[AgentResult] = None
            if workflow_state["effective_agents"]["verification"]:
                verification_candidates = self._select_findings_for_verification(merged_findings, plan)
                candidate_handoff = self._merge_handoffs([triage_result.handoff, finding_result.handoff])
                verification_payload = {
                    **input_data,
                    "previous_results": {"findings": verification_candidates},
                    "task": "verify high-confidence findings",
                    "handoff": candidate_handoff.to_dict() if candidate_handoff else None,
                }
                await self.emit_event(
                    "phase_start",
                    "verification",
                    metadata={"phase": "verification", "candidates": len(verification_candidates)},
                )
                verification_result = await self._run_sub_agent("verification", verification_payload)
                await self.emit_event("phase_complete", "verification completed", metadata={"phase": "verification"})
            else:
                verification_reason = (
                    "Verification agent disabled in workflow config."
                    if workflow_state["configured_agents"]["verification"] is False
                    else "Verification skipped because no analysis branch is enabled."
                )
                await self.emit_event(
                    "thinking",
                    f"Skipping verification: {verification_reason}",
                    metadata={"agent": "verification", "skipped": True},
                )

            final_findings = self._finalize_findings(merged_findings, verification_result)
            duration_ms = int((time.time() - start_time) * 1000)
            report_distribution = {
                "confirmed": sum(1 for finding in final_findings if finding.get("report_status") == "confirmed"),
                "candidate": sum(1 for finding in final_findings if finding.get("report_status") == "candidate"),
                "false_positive": sum(1 for finding in final_findings if finding.get("report_status") == "false_positive"),
            }
            summary = {
                "recon_mode": plan.recon_mode,
                "scan_candidates": (
                    int((scan_result.data.get("summary") or {}).get("total_candidates") or 0)
                    if scan_result.success and isinstance(scan_result.data, dict) and isinstance(scan_result.data.get("summary"), dict)
                    else len(scan_result.data.get("raw_findings", [])) if scan_result.success and isinstance(scan_result.data, dict) else 0
                ),
                "triaged_findings": len(triage_findings),
                "direct_findings": len(direct_findings),
                "merged_findings": len(merged_findings),
                "verified_findings": report_distribution["confirmed"],
                "candidate_findings": report_distribution["candidate"],
                "false_positive_findings": report_distribution["false_positive"],
                "workflow": workflow_state,
            }
            phases = {
                "recon": recon_result.to_dict(),
            }
            if workflow_state["effective_agents"]["scan"]:
                phases["scan"] = scan_result.to_dict()
            if workflow_state["effective_agents"]["triage"]:
                phases["triage"] = triage_result.to_dict()
            if workflow_state["effective_agents"]["finding"]:
                phases["finding"] = finding_result.to_dict()
            if workflow_state["effective_agents"]["verification"] and verification_result:
                phases["verification"] = verification_result.to_dict()
            total_tokens_used = self._sum_result_tokens(
                recon_result,
                scan_result,
                triage_result,
                finding_result,
                verification_result,
            )
            return AgentResult(
                success=True,
                data={
                    "findings": final_findings,
                    "verification_candidates": verification_candidates,
                    "raw_findings": scan_result.data.get("raw_findings", []) if scan_result.success and isinstance(scan_result.data, dict) else [],
                    "summary": summary,
                    "plan": plan.__dict__,
                    "workflow": workflow_state,
                    "phases": phases,
                },
                iterations=1,
                tool_calls=self._tool_calls,
                tokens_used=total_tokens_used,
                duration_ms=duration_ms,
                handoff=verification_result.handoff if verification_result else None,
            )
        except Exception as exc:
            logger.error("Orchestrator failed: %s", exc, exc_info=True)
            return AgentResult(success=False, error=str(exc))
