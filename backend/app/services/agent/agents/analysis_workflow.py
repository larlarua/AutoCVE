import asyncio
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .base import AgentConfig, AgentPattern, AgentResult, AgentType, BaseAgent, TaskHandoff
from ..json_parser import AgentJsonParser
from ..skill_service import SkillService
from ..prompts import FILE_VALIDATION_RULES, TOOL_USAGE_GUIDE

logger = logging.getLogger(__name__)

FINDING_OUTPUT_SCHEMA = """```json
{
  "findings": [
    {
      "vulnerability_type": "sql_injection|xss|command_injection|path_traversal|ssrf|hardcoded_secret|auth_bypass|idor|business_logic|other",
      "severity": "critical|high|medium|low",
      "title": "Finding title",
      "description": "Why this is risky",
      "file_path": "path/to/file",
      "line_start": 1,
      "line_end": 1,
      "code_snippet": "relevant code",
      "source": "attacker controlled input",
      "sink": "dangerous operation",
      "suggestion": "fix guidance",
      "confidence": 0.85,
      "needs_verification": true,
      "verdict": "candidate|confirmed|likely|uncertain|false_positive",
      "impact": "security impact",
      "cve_justification": "why this is CVE or bounty-worthy",
      "verification_notes": "what still needs confirmation",
      "references": ["CWE-79"],
      "exploit_chain": [
        {
          "step": 1,
          "location": "path/to/file:line",
          "description": "how attacker-controlled data moves",
          "data_state": "attacker-controlled string"
        }
      ],
      "poc": {
        "preconditions": ["attacker can access endpoint"],
        "steps": [
          {
            "step": 1,
            "action": "send request",
            "request": "GET /path?q=test",
            "expected_response": "vulnerable behavior"
          }
        ],
        "payload": "payload string",
        "impact": "what attacker gets",
        "cve_justification": "why it meets CVE/bounty acceptance"
      }
    }
  ],
  "summary": "short summary"
}
```"""

SCAN_OUTPUT_SCHEMA = """```json
{
  "scanner_runs": [
    {
      "tool": "semgrep_scan",
      "status": "success",
      "summary": "what was scanned"
    }
  ],
  "raw_findings": [
    {
      "source_tool": "semgrep_scan",
      "rule_id": "rule-or-pattern",
      "vulnerability_type": "sql_injection|xss|command_injection|path_traversal|ssrf|hardcoded_secret|other",
      "severity": "critical|high|medium|low",
      "title": "scanner candidate title",
      "description": "scanner description",
      "file_path": "path/to/file",
      "line_start": 1,
      "line_end": 1,
      "code_snippet": "matched code",
      "confidence": 0.6,
      "needs_verification": true
    }
  ],
  "summary": "short scan summary"
}
```"""


@dataclass
class ToolInvocation:
    action: str
    action_input: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowStep:
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict[str, Any]] = None
    actions: List[ToolInvocation] = field(default_factory=list)
    observation: Optional[str] = None
    is_final: bool = False
    final_answer: Optional[Dict[str, Any]] = None


@dataclass
class PreparedToolInvocation:
    invocation: ToolInvocation
    is_concurrency_safe: bool = False
    concurrency_key: Optional[str] = None


class AnalysisWorkflowAgent(BaseAgent):
    finding_origin = "analysis"
    evidence_type = "source-analysis"
    output_key = "findings"
    handoff_target = "verification"

    def __init__(
        self,
        *,
        name: str,
        agent_type: AgentType,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
        system_prompt: str,
        tool_usage_guide: Optional[str] = None,
        max_iterations: int = 20,
    ):
        tools_description = "\n".join(
            f"- {tool_name}: {getattr(tool, 'description', 'No description')}"
            for tool_name, tool in tools.items()
            if not tool_name.startswith("_")
        )
        full_prompt = "\n\n".join(
            part for part in [
                system_prompt,
                FILE_VALIDATION_RULES,
                TOOL_USAGE_GUIDE if tool_usage_guide is None else tool_usage_guide,
                "## Available Tools\n" + tools_description if tools_description else "",
            ] if part
        )
        config = AgentConfig(
            name=name,
            agent_type=agent_type,
            pattern=AgentPattern.REACT,
            max_iterations=max_iterations,
            system_prompt=full_prompt,
        )
        super().__init__(config, llm_service, tools, event_emitter)
        self._conversation_history: List[Dict[str, str]] = []
        self._steps: List[WorkflowStep] = []

    def _parse_llm_response(self, response: str) -> WorkflowStep:
        step = WorkflowStep(thought="")
        cleaned = response or ""
        cleaned = re.sub(r"\*\*Thought:\*\*", "Thought:", cleaned)
        cleaned = re.sub(r"\*\*Action:\*\*", "Action:", cleaned)
        cleaned = re.sub(r"\*\*Action Batch:\*\*", "Action Batch:", cleaned)
        cleaned = re.sub(r"\*\*Action Input:\*\*", "Action Input:", cleaned)
        cleaned = re.sub(r"\*\*Final Answer:\*\*", "Final Answer:", cleaned)

        thought_match = re.search(r"Thought:\s*(.*?)(?=Action Batch:|Action:|Final Answer:|$)", cleaned, re.DOTALL)
        if thought_match:
            step.thought = thought_match.group(1).strip()

        final_match = re.search(r"Final Answer:\s*(.*?)$", cleaned, re.DOTALL)
        if final_match:
            step.is_final = True
            answer_text = re.sub(r"```json\s*|```", "", final_match.group(1).strip())
            step.final_answer = AgentJsonParser.parse(answer_text, default={self.output_key: [], "summary": ""})
            if not step.thought:
                before_final = cleaned[:cleaned.find("Final Answer:")].strip()
                step.thought = re.sub(r"^Thought:\s*", "", before_final)[:500]
            return step

        batch_match = re.search(
            r"Action Batch:\s*(\[.*?\])(?=\s*(?:Thought:|Action:|Final Answer:|Observation:|$))",
            cleaned,
            re.DOTALL,
        )
        if batch_match:
            batch_text = re.sub(r"```json\s*|```", "", batch_match.group(1).strip())
            raw_actions = AgentJsonParser.parse_any(batch_text, default=[])
            if isinstance(raw_actions, list):
                step.actions = self._normalize_action_batch(raw_actions)
            if step.actions:
                step.action = step.actions[0].action
                step.action_input = step.actions[0].action_input
            if not step.thought:
                before_batch = cleaned[:cleaned.find("Action Batch:")].strip()
                step.thought = re.sub(r"^Thought:\s*", "", before_batch)[:500]
            return step

        action_match = re.search(r"Action:\s*([A-Za-z0-9_]+)", cleaned)
        if action_match:
            step.action = action_match.group(1).strip()
            step.actions = [ToolInvocation(action=step.action, action_input={})]
            if not step.thought:
                before_action = cleaned[:cleaned.find("Action:")].strip()
                step.thought = re.sub(r"^Thought:\s*", "", before_action)[:500]

        input_match = re.search(r"Action Input:\s*(.*?)(?=Thought:|Action:|Observation:|$)", cleaned, re.DOTALL)
        if input_match:
            input_text = re.sub(r"```json\s*|```", "", input_match.group(1).strip())
            step.action_input = AgentJsonParser.parse(input_text, default={"raw_input": input_text})
            if step.actions:
                step.actions[0].action_input = step.action_input or {}

        if not step.thought and not step.action and cleaned.strip():
            step.thought = cleaned.strip()[:500]
        return step

    def _normalize_action_batch(self, raw_actions: List[Any]) -> List[ToolInvocation]:
        normalized: List[ToolInvocation] = []
        for item in raw_actions:
            if not isinstance(item, dict):
                continue
            action = str(item.get("action", "")).strip()
            if not action:
                continue
            action_input = item.get("action_input", {})
            if not isinstance(action_input, dict):
                action_input = {"raw_input": action_input}
            normalized.append(ToolInvocation(action=action, action_input=action_input))
        return normalized

    def _iter_step_actions(self, step: WorkflowStep) -> List[ToolInvocation]:
        if step.actions:
            return step.actions
        if step.action:
            return [ToolInvocation(action=step.action, action_input=step.action_input or {})]
        return []

    def _prepare_step_actions(self, step: WorkflowStep) -> List[PreparedToolInvocation]:
        prepared: List[PreparedToolInvocation] = []
        for invocation in self._iter_step_actions(step):
            tool = self.tools.get(invocation.action)
            is_concurrency_safe = False
            concurrency_key: Optional[str] = None
            if tool is not None:
                action_input = invocation.action_input or {}
                try:
                    is_concurrency_safe = bool(tool.is_concurrency_safe(**action_input))
                except Exception:
                    is_concurrency_safe = False
                if is_concurrency_safe:
                    try:
                        raw_key = tool.concurrency_key(**action_input)
                        concurrency_key = str(raw_key).strip() or None if raw_key is not None else None
                    except Exception:
                        concurrency_key = None
            prepared.append(
                PreparedToolInvocation(
                    invocation=invocation,
                    is_concurrency_safe=is_concurrency_safe,
                    concurrency_key=concurrency_key,
                )
            )
        return prepared

    @staticmethod
    def _partition_prepared_actions(prepared_actions: List[PreparedToolInvocation]) -> List[tuple[bool, List[PreparedToolInvocation]]]:
        batches: List[tuple[bool, List[PreparedToolInvocation]]] = []
        active_keys: set[str] = set()
        for prepared in prepared_actions:
            if prepared.is_concurrency_safe:
                key = prepared.concurrency_key
                can_join_batch = bool(batches and batches[-1][0] and (not key or key not in active_keys))
                if can_join_batch:
                    batches[-1][1].append(prepared)
                    if key:
                        active_keys.add(key)
                    continue
                batches.append((True, [prepared]))
                active_keys = {key} if key else set()
                continue
            batches.append((False, [prepared]))
            active_keys = set()
        return batches

    @staticmethod
    def _render_action_observation(
        *,
        index: int,
        invocation: ToolInvocation,
        observation: str,
        failed_tool_calls: Dict[str, int],
    ) -> str:
        tool_call_key = f"{invocation.action}:{json.dumps(invocation.action_input or {}, sort_keys=True)}"
        rendered_observation = observation
        if isinstance(rendered_observation, str) and "Error" in rendered_observation:
            failed_tool_calls[tool_call_key] = failed_tool_calls.get(tool_call_key, 0) + 1
            if failed_tool_calls[tool_call_key] >= 3:
                rendered_observation += "\nRepeated tool failure detected. Switch tools, narrow the scope, or produce Final Answer."
                failed_tool_calls[tool_call_key] = 0
        else:
            failed_tool_calls.pop(tool_call_key, None)
        return (
            f"{index}. {invocation.action}({json.dumps(invocation.action_input or {}, ensure_ascii=False, sort_keys=True)}) =>\n"
            f"{rendered_observation}"
        )

    async def _execute_step_actions(self, step: WorkflowStep, failed_tool_calls: Dict[str, int]) -> str:
        prepared_actions = self._prepare_step_actions(step)
        observations: List[str] = []

        for is_concurrency_safe, batch in self._partition_prepared_actions(prepared_actions):
            for prepared in batch:
                await self.emit_llm_action(prepared.invocation.action, prepared.invocation.action_input)

            if is_concurrency_safe:
                raw_observations = await asyncio.gather(
                    *[
                        self.execute_tool(prepared.invocation.action, prepared.invocation.action_input or {})
                        for prepared in batch
                    ]
                )
            else:
                raw_observations = [
                    await self.execute_tool(prepared.invocation.action, prepared.invocation.action_input or {})
                    for prepared in batch
                ]

            for prepared, observation in zip(batch, raw_observations):
                observations.append(
                    self._render_action_observation(
                        index=len(observations) + 1,
                        invocation=prepared.invocation,
                        observation=observation,
                        failed_tool_calls=failed_tool_calls,
                    )
                )

        if not observations:
            return ""
        if len(observations) == 1:
            return observations[0].split("=>\n", 1)[1]
        return "Batch Observation:\n" + "\n\n".join(observations)

    async def _prepare_runtime_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        return context

    def _build_iteration_messages(self) -> List[Dict[str, str]]:
        return self._conversation_history

    def _on_iteration_start(self, iteration: int) -> None:
        del iteration

    def _build_iteration_control_prompt(self) -> str:
        return ""

    def _inject_iteration_control_prompt(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        prompt = self._build_iteration_control_prompt().strip()
        if not prompt:
            return messages
        return [*messages, {"role": "user", "content": prompt}]

    def _structured_tools_enabled_for_iteration(self) -> bool:
        return True

    def _build_no_action_prompt(self) -> str:
        return "Choose one action or produce Final Answer."

    def _should_abort_after_llm_failure(self, assistant_output: str, failure_count: int) -> bool:
        del assistant_output
        return failure_count >= 3

    def _use_structured_tool_calling(self) -> bool:
        return False

    def _structured_tool_calling_parallel(self) -> bool:
        return True

    def _build_structured_tool_schemas(self) -> List[Dict[str, Any]]:
        schemas: List[Dict[str, Any]] = []
        for tool_name, tool in self.tools.items():
            if tool_name.startswith("_"):
                continue
            to_tool_schema = getattr(tool, "to_tool_schema", None)
            if not callable(to_tool_schema):
                continue
            try:
                schemas.append(to_tool_schema())
            except Exception as exc:  # noqa: BLE001
                logger.debug("Failed to build structured schema for tool %s: %s", tool_name, exc)
        return schemas

    def _normalize_structured_action_input(self, raw_input: Any) -> Dict[str, Any]:
        if raw_input is None:
            return {}
        if isinstance(raw_input, dict):
            return raw_input
        if isinstance(raw_input, str):
            parsed = AgentJsonParser.parse_any(raw_input, default={"raw_input": raw_input})
            if isinstance(parsed, dict):
                return parsed
            return {"raw_input": parsed}
        return {"raw_input": raw_input}

    def _parse_structured_tool_calls(self, tool_calls: List[Dict[str, Any]]) -> List[ToolInvocation]:
        invocations: List[ToolInvocation] = []
        for tool_call in tool_calls or []:
            if not isinstance(tool_call, dict):
                continue
            function_payload = tool_call.get("function")
            if not isinstance(function_payload, dict):
                function_payload = tool_call
            action = str(function_payload.get("name") or tool_call.get("name") or "").strip()
            if not action:
                continue
            raw_input = function_payload.get("arguments")
            if raw_input is None:
                raw_input = tool_call.get("arguments")
            action_input = self._normalize_structured_action_input(raw_input)
            invocations.append(ToolInvocation(action=action, action_input=action_input))
        return invocations

    def _parse_textual_structured_tool_calls(self, content: str) -> List[ToolInvocation]:
        invocations: List[ToolInvocation] = []
        if not content or "Tool Calls:" not in content:
            return invocations

        for action, raw_input in re.findall(r"^\s*-\s*([A-Za-z0-9_]+)\((.*)\)\s*$", content, re.MULTILINE):
            normalized_action = str(action or "").strip()
            if not normalized_action:
                continue
            invocations.append(
                ToolInvocation(
                    action=normalized_action,
                    action_input=self._normalize_structured_action_input(raw_input.strip()),
                )
            )
        return invocations

    def _build_structured_assistant_content(self, content: str, tool_calls: List[Dict[str, Any]]) -> str:
        parts: List[str] = []
        if content and content.strip():
            parts.append(content.strip())
        invocations = self._parse_structured_tool_calls(tool_calls)
        if invocations:
            rendered_calls = "\n".join(
                f"- {invocation.action}({json.dumps(invocation.action_input or {}, ensure_ascii=False, sort_keys=True)})"
                for invocation in invocations
            )
            parts.append("Tool Calls:\n" + rendered_calls)
        return "\n\n".join(part for part in parts if part).strip()

    def _build_structured_debug_output(
        self,
        content: str,
        tool_calls: List[Dict[str, Any]],
        finish_reason: Optional[str] = None,
    ) -> str:
        invocations = self._parse_structured_tool_calls(tool_calls)
        if not invocations:
            invocations = self._parse_textual_structured_tool_calls(content)
        payload = {
            "mode": "structured_tool_calling",
            "assistant_content": content or "",
            "tool_calls": [
                {
                    "action": invocation.action,
                    "action_input": invocation.action_input,
                }
                for invocation in invocations
            ],
            "finish_reason": finish_reason,
        }
        return json.dumps(payload, ensure_ascii=False, indent=2)

    def _maybe_parse_structured_final_answer(self, content: str) -> Optional[Dict[str, Any]]:
        stripped = re.sub(r"```json\s*|```", "", (content or "").strip())
        if not stripped:
            return None
        parsed = AgentJsonParser.parse_any(stripped, default=None)
        if isinstance(parsed, dict) and (self.output_key in parsed or "summary" in parsed):
            return parsed
        return None

    def _synthesize_action_thought(self, step: WorkflowStep) -> Optional[str]:
        action = (step.action or "").strip()
        action_input = step.action_input or {}
        if not action:
            return None

        if action == "read_file":
            file_path = str(action_input.get("file_path", "")).strip()
            if file_path:
                return f"Inspecting code in {file_path}."
        if action == "read_many_files":
            file_paths = action_input.get("file_paths")
            if isinstance(file_paths, list) and file_paths:
                preview = ", ".join(str(path) for path in file_paths[:3])
                if len(file_paths) > 3:
                    preview += ", ..."
                return f"Comparing related files: {preview}."
        if action == "search_code":
            keyword = str(action_input.get("keyword", "")).strip()
            if keyword:
                return f"Searching the codebase for '{keyword}'."
        if action == "list_files":
            directory = str(action_input.get("directory", "")).strip()
            if directory:
                return f"Listing files under {directory}."

        return f"Preparing to use {action}."

    def _build_step_from_structured_response(
        self,
        content: str,
        tool_calls: List[Dict[str, Any]],
        *,
        allow_tool_calls: bool = True,
    ) -> WorkflowStep:
        invocations: List[ToolInvocation] = []
        if allow_tool_calls:
            invocations = self._parse_structured_tool_calls(tool_calls)
            if not invocations:
                invocations = self._parse_textual_structured_tool_calls(content)
        if invocations:
            thought = (content or "").strip()
            step = WorkflowStep(
                thought=thought,
                action=invocations[0].action,
                action_input=invocations[0].action_input,
                actions=invocations,
            )
            if not step.thought:
                step.thought = "Using structured tool calls."
            return step

        step = self._parse_llm_response(content or "")
        if not step.is_final and not self._iter_step_actions(step):
            final_answer = self._maybe_parse_structured_final_answer(content or "")
            if final_answer is not None:
                step.is_final = True
                step.final_answer = final_answer
                if not step.thought:
                    step.thought = "Returning final answer."
        if step.action and not step.thought:
            step.thought = self._synthesize_action_thought(step) or step.thought
        return step

    async def _request_structured_step(
        self,
        messages: List[Dict[str, str]],
    ) -> tuple[WorkflowStep, str, str, int]:
        messages = self.compress_messages_if_needed(messages)
        if self.is_cancelled:
            return WorkflowStep(thought=""), "", "", 0

        debug_output = ""
        assistant_output = ""
        total_tokens = 0
        await self.emit_thinking_start()
        try:
            allow_tool_calls = self._structured_tools_enabled_for_iteration()
            response = await self.llm_service.chat_completion(
                messages=messages,
                agent_type=self.agent_type.value,
                tools=self._build_structured_tool_schemas() if allow_tool_calls else [],
                parallel_tool_calls=self._structured_tool_calling_parallel() if allow_tool_calls else False,
            )
            usage = response.get("usage") or {}
            total_tokens = int(usage.get("total_tokens", 0) or 0)
            content = response.get("content", "") or ""
            tool_calls = response.get("tool_calls") or []
            step = self._build_step_from_structured_response(
                content,
                tool_calls,
                allow_tool_calls=allow_tool_calls,
            )
            assistant_output = self._build_structured_assistant_content(content, tool_calls)
            debug_output = self._build_structured_debug_output(
                content,
                tool_calls,
                finish_reason=response.get("finish_reason"),
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("[%s] Unexpected error in structured tool calling: %s", self.name, exc, exc_info=True)
            await self.emit_event("error", f"LLM call error: {exc}")
            assistant_output = f"[LLM调用错误: {str(exc)}] 请重试。"
            debug_output = assistant_output
            step = self._parse_llm_response(assistant_output)
        finally:
            await self.emit_thinking_end(debug_output or assistant_output)

        return step, assistant_output, debug_output or assistant_output, total_tokens

    async def _request_iteration_step(
        self,
        messages: List[Dict[str, str]],
    ) -> tuple[WorkflowStep, str, str, int]:
        if self._use_structured_tool_calling():
            return await self._request_structured_step(messages)

        llm_output, total_tokens = await self.stream_llm_call(messages)
        step = self._parse_llm_response(llm_output)
        return step, llm_output, llm_output, total_tokens

    def _on_assistant_turn(self, llm_output: str, step: WorkflowStep) -> None:
        del llm_output, step

    def _on_observation_turn(self, observation: str, step: WorkflowStep) -> None:
        del observation, step

    def _assistant_history_content(self, assistant_output: str, step: WorkflowStep) -> str:
        del step
        return assistant_output

    def _observation_history_content(self, observation: str, step: WorkflowStep) -> str:
        del step
        return f"Observation:\n{observation}"

    def _should_skip_full_history_finalization(self) -> bool:
        return False

    def _get_project_context(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        project_info = input_data.get("project_info", {})
        config = input_data.get("config", {})
        previous_results = input_data.get("previous_results", {}) or {}
        plan = input_data.get("plan", {}) or {}
        task = input_data.get("task", "")
        task_context = input_data.get("task_context", "")
        handoff = input_data.get("handoff")
        if handoff:
            if isinstance(handoff, dict):
                handoff = TaskHandoff.from_dict(handoff)
            self.receive_handoff(handoff)

        recon_data = previous_results.get("recon", {})
        if isinstance(recon_data, dict) and "data" in recon_data:
            recon_data = recon_data["data"]
        recon_payload = recon_data if isinstance(recon_data, dict) else {}
        target_files = config.get("target_files", []) or []
        exclude_patterns = config.get("exclude_patterns", []) or []
        focus_vulnerabilities = (
            config.get("focus_vulnerabilities")
            or config.get("target_vulnerabilities")
            or []
        )
        self._current_project_root = project_info.get("root", "")

        return {
            "task_id": input_data.get("task_id", ""),
            "project_info": project_info,
            "config": config,
            "previous_results": previous_results,
            "plan": plan,
            "task": task,
            "task_context": task_context,
            "recon_data": recon_payload,
            "handoff_context": self.get_handoff_context(),
            "target_files": target_files,
            "exclude_patterns": exclude_patterns,
            "focus_vulnerabilities": focus_vulnerabilities,
            "skill_context": {},
        }

    def _build_initial_message(self, context: Dict[str, Any]) -> str:
        raise NotImplementedError

    def _build_summary_prompt(self) -> str:
        schema = SCAN_OUTPUT_SCHEMA if self.output_key == "raw_findings" else FINDING_OUTPUT_SCHEMA
        return (
            "现在停止使用工具。只基于已经收集到的代码和观察结果，"
            "立即返回符合要求的 Final Answer，不要再输出 Action。\n"
            f"使用这个 schema：\n{schema}\n"
            "只能返回 'Final Answer: {...}' 或匹配 schema 的纯 JSON。"
        )

    def _build_fallback_result(self) -> Dict[str, Any]:
        return {
            self.output_key: [],
            "summary": f"{self.name} 已完成 {len(self._steps)} 轮推理，但没有产出符合要求的 Final Answer。",
        }

    async def _recover_final_result(self) -> Dict[str, Any]:
        return {}

    def _normalize_finding(self, finding: Dict[str, Any], *, origin: Optional[str] = None, evidence_type: Optional[str] = None) -> Dict[str, Any]:
        line_start = finding.get("line_start") or finding.get("line", 0) or 0
        line_end = finding.get("line_end") or finding.get("line_start") or finding.get("line", 0) or 0
        try:
            line_start = max(int(line_start), 1)
        except (TypeError, ValueError):
            line_start = 1
        try:
            line_end = max(int(line_end), line_start)
        except (TypeError, ValueError):
            line_end = line_start

        file_path = str(finding.get("file_path", "") or "").strip()
        confidence = float(finding.get("confidence", 0.7) or 0.7)
        needs_verification = bool(finding.get("needs_verification", True))
        evidence_gaps = [
            item for item in finding.get("evidence_gaps", [])
            if isinstance(item, str) and item.strip()
        ]

        if not finding.get("source"):
            evidence_gaps.append("missing_source")
            confidence = min(confidence, 0.8)
            needs_verification = True

        if not finding.get("sink"):
            evidence_gaps.append("missing_sink")
            confidence = min(confidence, 0.8)
            needs_verification = True

        if not finding.get("description"):
            evidence_gaps.append("missing_description")
            needs_verification = True

        if not finding.get("suggestion"):
            evidence_gaps.append("missing_suggestion")
            needs_verification = True

        if file_path and getattr(self, "_current_project_root", ""):
            candidate = os.path.join(self._current_project_root, file_path)
            if not os.path.exists(candidate):
                evidence_gaps.append("unverified_file_path")
                confidence = min(confidence, 0.75)
                needs_verification = True

        normalized = {
            "vulnerability_type": finding.get("vulnerability_type", "other"),
            "severity": str(finding.get("severity", "medium")).lower(),
            "title": finding.get("title", "Unknown Finding"),
            "description": finding.get("description", ""),
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "code_snippet": finding.get("code_snippet", ""),
            "source": finding.get("source", ""),
            "sink": finding.get("sink", ""),
            "suggestion": finding.get("suggestion", ""),
            "confidence": round(max(min(confidence, 1.0), 0.0), 2),
            "needs_verification": needs_verification,
            "origin": origin or self.finding_origin,
            "evidence_type": evidence_type or self.evidence_type,
            "evidence_gaps": sorted(set(evidence_gaps)),
            "verdict": str(finding.get("verdict", "candidate")).lower(),
            "impact": finding.get("impact", ""),
            "cve_justification": finding.get("cve_justification", ""),
            "verification_notes": finding.get("verification_notes", ""),
            "false_positive_reason": finding.get("false_positive_reason", ""),
            "references": self._normalize_references(finding.get("references", [])),
            "exploit_chain": self._normalize_exploit_chain(finding.get("exploit_chain", [])),
            "poc": self._normalize_poc(finding.get("poc", {})),
        }
        for key in ("entry_point_refs", "priority_path_refs", "business_flow_notes"):
            values = finding.get(key, [])
            if isinstance(values, list):
                normalized[key] = [item for item in values if isinstance(item, str) and item.strip()]
        return normalized

    def _normalize_references(self, references: Any) -> List[str]:
        if not references:
            return []
        if isinstance(references, str):
            return [references.strip()] if references.strip() else []
        if isinstance(references, list):
            return [str(item).strip() for item in references if str(item).strip()]
        return [str(references).strip()]

    def _normalize_exploit_chain(self, exploit_chain: Any) -> List[Dict[str, Any]]:
        if not isinstance(exploit_chain, list):
            return []
        normalized_chain: List[Dict[str, Any]] = []
        for idx, step in enumerate(exploit_chain, start=1):
            if not isinstance(step, dict):
                continue
            location = str(step.get("location", "")).strip()
            description = str(step.get("description", "")).strip()
            if not location and not description:
                continue
            normalized_chain.append(
                {
                    "step": int(step.get("step") or idx),
                    "location": location,
                    "description": description,
                    "data_state": str(step.get("data_state", "")).strip(),
                    "bypass_reason": str(step.get("bypass_reason", "")).strip(),
                }
            )
        return normalized_chain

    def _normalize_poc(self, poc: Any) -> Dict[str, Any]:
        if not isinstance(poc, dict):
            return {}
        preconditions = poc.get("preconditions", [])
        steps = poc.get("steps", [])
        normalized_steps: List[Dict[str, Any]] = []
        if isinstance(steps, list):
            for idx, step in enumerate(steps, start=1):
                if not isinstance(step, dict):
                    continue
                normalized_steps.append(
                    {
                        "step": int(step.get("step") or idx),
                        "action": str(step.get("action", "")).strip(),
                        "request": str(step.get("request", "")).strip(),
                        "expected_response": str(step.get("expected_response", "")).strip(),
                    }
                )
        return {
            "preconditions": [str(item).strip() for item in preconditions if str(item).strip()] if isinstance(preconditions, list) else [],
            "steps": normalized_steps,
            "payload": str(poc.get("payload", "")).strip(),
            "impact": str(poc.get("impact", "")).strip(),
            "cve_justification": str(poc.get("cve_justification", "")).strip(),
            "description": str(poc.get("description", "")).strip(),
        }

    def _postprocess_result(self, raw_result: Dict[str, Any]) -> Dict[str, Any]:
        findings = raw_result.get(self.output_key, [])
        standardized = []
        for finding in findings:
            if isinstance(finding, dict):
                standardized.append(self._normalize_finding(finding))
        return {
            self.output_key: standardized,
            "summary": raw_result.get("summary", ""),
        }

    def _build_handoff(self, processed_result: Dict[str, Any]) -> Optional[TaskHandoff]:
        findings = processed_result.get("findings", [])
        if not findings:
            return None

        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        sorted_findings = sorted(findings, key=lambda item: severity_order.get(item.get("severity", "low"), 3))
        severity_counts: Dict[str, int] = {}
        type_counts: Dict[str, int] = {}
        files_with_findings: Dict[str, int] = {}

        for finding in findings:
            severity = finding.get("severity", "medium")
            vuln_type = finding.get("vulnerability_type", "other")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            type_counts[vuln_type] = type_counts.get(vuln_type, 0) + 1
            file_path = finding.get("file_path")
            if file_path:
                files_with_findings[file_path] = files_with_findings.get(file_path, 0) + 1

        insights = [
            f"Collected {len(findings)} findings.",
            f"Severity distribution: critical={severity_counts.get('critical', 0)}, high={severity_counts.get('high', 0)}, medium={severity_counts.get('medium', 0)}, low={severity_counts.get('low', 0)}",
        ]
        if type_counts:
            top_types = sorted(type_counts.items(), key=lambda item: item[1], reverse=True)[:3]
            insights.append("Top vulnerability types: " + ", ".join(f"{name}({count})" for name, count in top_types))

        suggested_actions = []
        for finding in sorted_findings[:10]:
            suggested_actions.append(
                {
                    "action": "verify_vulnerability",
                    "target": finding.get("file_path", ""),
                    "line": finding.get("line_start", 0),
                    "vulnerability_type": finding.get("vulnerability_type", "other"),
                    "severity": finding.get("severity", "medium"),
                    "priority": "high" if finding.get("severity") in {"critical", "high"} else "normal",
                    "reason": finding.get("title", "Security finding"),
                }
            )

        return self.create_handoff(
            to_agent=self.handoff_target,
            summary=processed_result.get("summary", f"{len(findings)} findings produced by {self.name}"),
            key_findings=sorted_findings[:15],
            insights=insights,
            suggested_actions=suggested_actions,
            attention_points=[f"{file_path} ({count})" for file_path, count in sorted(files_with_findings.items(), key=lambda item: item[1], reverse=True)[:10]],
            priority_areas=[item.get("file_path", "") for item in sorted_findings[:10] if item.get("severity") in {"critical", "high"} and item.get("file_path")],
            context_data={
                "severity_distribution": severity_counts,
                "vulnerability_types": type_counts,
                "files_with_findings": files_with_findings,
            },
        )

    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        start_time = time.time()
        context = self._get_project_context(input_data)
        context["skill_context"] = await SkillService.resolve_agent_skills(
            context.get("config", {}).get("user_id"),
            self.agent_type.value,
            context,
        )
        context = await self._prepare_runtime_context(context)
        initial_message = self._build_initial_message(context)
        self.record_work(f"Starting {self.name.lower()} workflow")
        self._conversation_history = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": initial_message},
        ]
        self._steps = []
        final_result: Dict[str, Any] = {self.output_key: [], "summary": ""}
        completion_source = "not_completed"
        empty_response_count = 0
        llm_failure_count = 0
        failed_tool_calls: Dict[str, int] = {}
        await self.emit_agent_start_debug(
            {
                "task": context.get("task", ""),
                "task_context": context.get("task_context", ""),
                "project_info": context.get("project_info", {}),
                "skill_context": context.get("skill_context", {}),
            }
        )
        await self.emit_prompt_debug("system", self.config.system_prompt)
        await self.emit_prompt_debug("user", initial_message)
        if self._incoming_handoff:
            await self.emit_handoff_debug("in", self._incoming_handoff)
        await self.emit_thinking(f"Starting {self.name}...")

        try:
            for iteration in range(self.config.max_iterations):
                if self.is_cancelled:
                    break

                self._iteration = iteration + 1
                self._on_iteration_start(self._iteration)
                iteration_messages = self._inject_iteration_control_prompt(self._build_iteration_messages())
                step, assistant_output, debug_output, tokens_this_round = await self._request_iteration_step(
                    iteration_messages
                )
                self._total_tokens += tokens_this_round

                if not assistant_output or not assistant_output.strip():
                    empty_response_count += 1
                    if empty_response_count >= 3:
                        final_result = self._build_fallback_result()
                        break
                    self._conversation_history.append({"role": "user", "content": "请返回有效的 Thought/Action 或 Final Answer。"})
                    continue
                empty_response_count = 0

                if "[LLM timeout]" in assistant_output or "[LLM调用错误:" in assistant_output:
                    llm_failure_count += 1
                    if self._should_abort_after_llm_failure(assistant_output, llm_failure_count):
                        break
                else:
                    llm_failure_count = 0

                self._steps.append(step)
                if step.thought:
                    await self.emit_llm_thought(step.thought, self._iteration)
                self._conversation_history.append(
                    {
                        "role": "assistant",
                        "content": self._assistant_history_content(assistant_output, step),
                    }
                )
                self._on_assistant_turn(assistant_output, step)
                await self.emit_model_response_debug(debug_output, iteration=self._iteration)

                if step.is_final:
                    final_result = step.final_answer or final_result
                    completion_source = "explicit_final_answer"
                    break

                if self._iter_step_actions(step):
                    observation = await self._execute_step_actions(step, failed_tool_calls)
                    step.observation = observation
                    await self.emit_llm_observation(observation)
                    self._conversation_history.append(
                        {
                            "role": "user",
                            "content": self._observation_history_content(observation, step),
                        }
                    )
                    self._on_observation_turn(observation, step)
                else:
                    await self.emit_llm_decision("continue", "需要具体 Action 或 Final Answer")
                    self._conversation_history.append({"role": "user", "content": self._build_no_action_prompt()})

            if not final_result.get(self.output_key) and not final_result.get("summary") and not self.is_cancelled:
                if not self._should_skip_full_history_finalization():
                    self._conversation_history.append({"role": "user", "content": self._build_summary_prompt()})
                    summary_output, _ = await self.stream_llm_call(self._conversation_history)
                    if summary_output and summary_output.strip():
                        await self.emit_model_response_debug(summary_output, iteration=self._iteration + 1)
                        parsed_summary = self._parse_llm_response(summary_output)
                        if parsed_summary.is_final and parsed_summary.final_answer:
                            final_result = parsed_summary.final_answer
                            completion_source = "summary_prompt_final_answer"
                        else:
                            summary_text = re.sub(r"```json\s*|```", "", summary_output.strip())
                            summary_text = re.sub(r"^Final Answer:\\s*", "", summary_text)
                            final_result = AgentJsonParser.parse(summary_text, default=final_result)
                            if final_result.get(self.output_key) or final_result.get("summary"):
                                completion_source = "summary_prompt_json"
                    if not final_result.get(self.output_key):
                        self._conversation_history.append({
                            "role": "user",
                            "content": "最后一次机会。不要再使用工具。只返回 JSON，并包含先前观察中证据最充分的发现。"
                                       "如果证据不完整但仍可行动，请保持 verdict='candidate'，并在 verification_notes 中说明缺口。",
                        })
                        strict_output, _ = await self.stream_llm_call(self._conversation_history)
                        if strict_output and strict_output.strip():
                            await self.emit_model_response_debug(strict_output, iteration=self._iteration + 2)
                            parsed_strict = self._parse_llm_response(strict_output)
                            if parsed_strict.is_final and parsed_strict.final_answer:
                                final_result = parsed_strict.final_answer
                                completion_source = "strict_summary_final_answer"
                            else:
                                strict_text = re.sub(r"```json\s*|```", "", strict_output.strip())
                                strict_text = re.sub(r"^Final Answer:\\s*", "", strict_text)
                                final_result = AgentJsonParser.parse(strict_text, default=final_result)
                                if final_result.get(self.output_key) or final_result.get("summary"):
                                    completion_source = "strict_summary_json"
                if not final_result.get(self.output_key):
                    recovered_result = await self._recover_final_result()
                    if recovered_result and recovered_result.get(self.output_key):
                        final_result = recovered_result
                        completion_source = "recovered_result"
                    else:
                        final_result = self._build_fallback_result()
                        completion_source = "fallback_result"

            duration_ms = int((time.time() - start_time) * 1000)
            if self.is_cancelled:
                return AgentResult(
                    success=False,
                    error="cancelled",
                    data=final_result,
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )

            processed = self._postprocess_result(final_result)
            if completion_source in {"recovered_result", "fallback_result"}:
                await self.emit_debug_payload(
                    "model_response_raw",
                    {
                        "content": json.dumps(processed, ensure_ascii=False, indent=2),
                        "iteration": self._iteration + 1,
                        "completion_source": completion_source,
                        "synthetic": True,
                    },
                    message="synthesized final result captured",
                )
            completion_reason = f"completed via {completion_source.replace('_', ' ')}"
            await self.emit_event(
                "final_answer",
                processed.get("summary") or f"{self.name} final answer ready.",
                metadata={
                    "completion_source": completion_source,
                    "result": processed,
                },
            )
            await self.emit_llm_decision("complete", completion_reason)
            await self.emit_llm_complete(
                processed.get("summary")
                or f"{self.name} completed via {completion_source.replace('_', ' ')}.",
                self._total_tokens,
            )
            await self.emit_event(
                "info",
                f"{self.name} finished ({completion_source}).",
                metadata={"completion_source": completion_source},
            )
            handoff = self._build_handoff(processed)
            if handoff:
                await self.emit_handoff_debug("out", handoff)
            return AgentResult(
                success=True,
                data={
                    **processed,
                    "steps": [
                        {
                            "thought": step.thought,
                            "action": step.action,
                            "action_input": step.action_input,
                            "actions": [
                                {
                                    "action": invocation.action,
                                    "action_input": invocation.action_input,
                                }
                                for invocation in step.actions
                            ],
                            "observation": step.observation[:500] if step.observation else None,
                        }
                        for step in self._steps
                    ],
                },
                iterations=self._iteration,
                tool_calls=self._tool_calls,
                tokens_used=self._total_tokens,
                duration_ms=duration_ms,
                handoff=handoff,
            )
        except Exception as exc:
            logger.error("%s failed: %s", self.name, exc, exc_info=True)
            return AgentResult(success=False, error=str(exc))

    def get_conversation_history(self) -> List[Dict[str, str]]:
        return self._conversation_history

    def get_steps(self) -> List[WorkflowStep]:
        return self._steps
