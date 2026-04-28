"""
Recon Agent - repository reconnaissance and navigation planning.
"""

import asyncio
import json
import logging
import os
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from .base import BaseAgent, AgentConfig, AgentResult, AgentType, AgentPattern, TaskHandoff
from .schemas import normalize_recon_payload
from ..json_parser import AgentJsonParser
from ..skill_service import SkillService
from ..prompts import TOOL_USAGE_GUIDE

logger = logging.getLogger(__name__)

LIVE_RECON_OUTPUT_CONTRACT = """## Recon 输出规范
- Recon 仅产出项目导航数据（攻击面测绘与审计路径规划），不要输出漏洞结论。
- Final Answer 必须是 JSON，并且顶层字段必须且只能包含以下这些：
  - project_profile
  - project_structure
  - entry_points
  - priority_paths
  - audit_targets
  - recommended_scanners
  - summary
- priority_paths 的含义是“建议优先审计这些路径”，不是“这些路径存在漏洞”。
- 如果可以确定具体文件，audit_targets.target_files 应包含值得直接审查的具体文件。
"""

LIVE_RECON_SYSTEM_PROMPT = """你是 AuditAI 的 Recon 信息收集 Agent。

你的任务是为下游的 Finding Agent 收集项目导航数据（攻击面测绘与审计路径规划）。

目标：
1. 识别语言、框架、数据库、包管理器以及运行时特征。
2. 识别具体入口点，例如 HTTP 路由、控制器、处理器、调度任务、队列消费者和管理后台暴露面。
3. 识别应当优先审计的路径。
4. 根据识别出的技术栈推荐外部扫描器。
5. 简要总结 finding agent 应优先审查的内容。

规则：
- 你不是 finding agent。不要输出漏洞结论。
- 不要输出初步发现。
- 回答前必须先使用工具。
- 优先引用工具输出中实际存在的具体文件和目录。
- 如果你不确定，应以仓库中已观察到的证据为准，并保持结果保守。

工作格式：
Thought: 说明你下一步需要什么
Action: tool_name
Action Input: {"json": "object"}

完成后，请返回：
Final Answer: {JSON}
"""


RECON_OUTPUT_CONTRACT = LIVE_RECON_OUTPUT_CONTRACT
RECON_SYSTEM_PROMPT = LIVE_RECON_SYSTEM_PROMPT

@dataclass
class ReconStep:
    """Single recon reasoning step."""
    thought: str
    action: Optional[str] = None
    action_input: Optional[Dict] = None
    observation: Optional[str] = None
    is_final: bool = False
    final_answer: Optional[Dict] = None


class ReconAgent(BaseAgent):
    """LLM-driven reconnaissance agent for repository navigation and stack discovery."""
    
    def __init__(
        self,
        llm_service,
        tools: Dict[str, Any],
        event_emitter=None,
    ):
        # Cleaned legacy mojibake comment.
        full_system_prompt = f"{LIVE_RECON_SYSTEM_PROMPT}\n\n{LIVE_RECON_OUTPUT_CONTRACT}\n\n{TOOL_USAGE_GUIDE}"
        
        config = AgentConfig(
            name="Recon",
            agent_type=AgentType.RECON,
            pattern=AgentPattern.REACT,
            max_iterations=15,
            system_prompt=full_system_prompt,
        )
        super().__init__(config, llm_service, tools, event_emitter)
        
        self._conversation_history: List[Dict[str, str]] = []
        self._steps: List[ReconStep] = []

    def _normalize_recon_result(self, raw_result: Dict[str, Any], config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return normalize_recon_payload(raw_result, config=config or {})

    def _recon_result_has_signal(self, result: Dict[str, Any]) -> bool:
        normalized = self._normalize_recon_result(result)
        project_profile = normalized.get("project_profile", {}) or {}
        project_structure = normalized.get("project_structure", {}) or {}
        recommended_scanners = normalized.get("recommended_scanners", {}) or {}
        return any([
            project_profile.get("languages"),
            project_profile.get("frameworks"),
            project_profile.get("databases"),
            project_structure.get("key_directories"),
            project_structure.get("key_files"),
            normalized.get("entry_points"),
            normalized.get("priority_paths"),
            normalized.get("audit_targets", {}).get("target_files"),
            recommended_scanners.get("must_use"),
            recommended_scanners.get("optional"),
            normalized.get("summary"),
        ])

    def _build_recommended_scanners(self, languages: List[str]) -> Dict[str, Any]:
        must_use: List[str] = ["semgrep_scan", "gitleaks_scan"]
        optional: List[str] = []
        normalized_languages = {str(language).strip().lower() for language in languages}
        if "python" in normalized_languages:
            optional.extend(["bandit_scan", "safety_scan"])
        if normalized_languages.intersection({"javascript", "typescript", "javascript/typescript"}):
            optional.append("npm_audit")
        if "java" in normalized_languages:
            optional.append("osv_scan")
        deduped: List[str] = []
        for item in must_use + optional:
            if item not in deduped:
                deduped.append(item)
        return {
            "must_use": [item for item in deduped if item in must_use],
            "optional": [item for item in deduped if item not in must_use],
            "reason": "优先直接阅读源码，并将技术栈匹配的扫描器作为佐证。",
        }

    def _merge_recon_with_project_info(
        self,
        final_result: Dict[str, Any],
        project_info: Optional[Dict[str, Any]],
        config: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        normalized = self._normalize_recon_result(final_result, config=config or {})
        project_info = project_info or {}
        repository_structure = project_info.get("structure") if isinstance(project_info.get("structure"), dict) else {}

        def ordered_strings(*groups: Any) -> List[str]:
            items: List[str] = []
            for group in groups:
                if not isinstance(group, list):
                    continue
                for item in group:
                    text = str(item or "").strip()
                    if text and text not in items:
                        items.append(text)
            return items

        project_profile = normalized.get("project_profile", {}) or {}
        project_structure = normalized.get("project_structure", {}) or {}
        merged_languages = ordered_strings(project_profile.get("languages"), project_info.get("languages"))
        merged_frameworks = ordered_strings(project_profile.get("frameworks"), project_info.get("frameworks"))
        merged_databases = ordered_strings(project_profile.get("databases"), project_info.get("databases"))
        merged_directories = ordered_strings(project_structure.get("key_directories"), repository_structure.get("directories"))
        merged_files = ordered_strings(project_structure.get("key_files"), repository_structure.get("key_files"), repository_structure.get("files"))

        normalized["project_profile"] = {
            **project_profile,
            "languages": merged_languages,
            "frameworks": merged_frameworks,
            "databases": merged_databases,
        }
        normalized["project_structure"] = {
            **project_structure,
            "key_directories": merged_directories,
            "key_files": merged_files,
            "monorepo_layout": project_structure.get("monorepo_layout") or repository_structure.get("monorepo_layout") or "",
        }
        normalized["priority_paths"] = ordered_strings(normalized.get("priority_paths"), merged_directories, merged_files[:20])
        cfg = config or {}
        audit_targets = normalized.get("audit_targets", {}) or {}
        normalized["audit_targets"] = {
            "target_files": ordered_strings(audit_targets.get("target_files"), cfg.get("target_files"), merged_files[:50]),
            "exclude_patterns": ordered_strings(audit_targets.get("exclude_patterns"), cfg.get("exclude_patterns")),
        }
        recommended_scanners = normalized.get("recommended_scanners", {}) or {}
        if not recommended_scanners.get("must_use") and not recommended_scanners.get("optional"):
            recommended_scanners = self._build_recommended_scanners(merged_languages)
        normalized["recommended_scanners"] = recommended_scanners
        if not (normalized.get("summary") or "").strip():
            summary_bits = []
            if merged_languages:
                summary_bits.append(f"languages={', '.join(merged_languages[:4])}")
            if merged_frameworks:
                summary_bits.append(f"frameworks={', '.join(merged_frameworks[:4])}")
            summary_bits.append(f"priority_paths={len(normalized['priority_paths'])}")
            summary_bits.append(f"entry_points={len(normalized.get('entry_points', []))}")
            normalized["summary"] = "Recon fallback summary: " + "; ".join(summary_bits)
        return normalized
    
    def _parse_llm_response(self, response: str) -> ReconStep:
        """Parse the LLM response into a ReconStep."""
        step = ReconStep(thought="")

        # Cleaned legacy mojibake comment.
        cleaned_response = response
        cleaned_response = re.sub(r'\*\*Action:\*\*', 'Action:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Action Input:\*\*', 'Action Input:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Thought:\*\*', 'Thought:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Final Answer:\*\*', 'Final Answer:', cleaned_response)
        cleaned_response = re.sub(r'\*\*Observation:\*\*', 'Observation:', cleaned_response)

        # Cleaned legacy mojibake comment.
        thought_match = re.search(r'Thought:\s*(.*?)(?=Action:|Final Answer:|$)', cleaned_response, re.DOTALL)
        if thought_match:
            step.thought = thought_match.group(1).strip()

        # Cleaned legacy mojibake comment.
        final_match = re.search(r'Final Answer:\s*(.*?)$', cleaned_response, re.DOTALL)
        if final_match:
            step.is_final = True
            answer_text = final_match.group(1).strip()
            answer_text = re.sub(r'```json\s*', '', answer_text)
            answer_text = re.sub(r'```\s*', '', answer_text)
            # Cleaned legacy mojibake comment.
            step.final_answer = AgentJsonParser.parse(
                answer_text,
                default={"raw_answer": answer_text}
            )
            # Cleaned legacy mojibake comment.
            if "initial_findings" in step.final_answer:
                step.final_answer["initial_findings"] = [
                    f for f in step.final_answer["initial_findings"]
                    if isinstance(f, dict)
                ]

            # Cleaned legacy mojibake comment.
            step.final_answer = self._normalize_recon_result(step.final_answer)
            if not step.thought:
                before_final = cleaned_response[:cleaned_response.find('Final Answer:')].strip()
                if before_final:
                    # Cleaned legacy mojibake comment.
                    before_final = re.sub(r'^Thought:\s*', '', before_final)
                    step.thought = before_final[:500] if len(before_final) > 500 else before_final

            return step

        # Cleaned legacy mojibake comment.
        action_match = re.search(r'Action:\s*(\w+)', cleaned_response)
        if action_match:
            step.action = action_match.group(1).strip()

            # Cleaned legacy mojibake comment.
            if not step.thought:
                action_pos = cleaned_response.find('Action:')
                if action_pos > 0:
                    before_action = cleaned_response[:action_pos].strip()
                    # Cleaned legacy mojibake comment.
                    before_action = re.sub(r'^Thought:\s*', '', before_action)
                    if before_action:
                        step.thought = before_action[:500] if len(before_action) > 500 else before_action

        # Cleaned legacy mojibake comment.
        input_match = re.search(r'Action Input:\s*(.*?)(?=Thought:|Action:|Observation:|$)', cleaned_response, re.DOTALL)
        if input_match:
            input_text = input_match.group(1).strip()
            input_text = re.sub(r'```json\s*', '', input_text)
            input_text = re.sub(r'```\s*', '', input_text)
            # Cleaned legacy mojibake comment.
            step.action_input = AgentJsonParser.parse(
                input_text,
                default={"raw_input": input_text}
            )

        # Cleaned legacy mojibake comment.
        if not step.thought and not step.action and not step.is_final:
            if response.strip():
                step.thought = response.strip()[:500]

        return step
    

    
    async def run(self, input_data: Dict[str, Any]) -> AgentResult:
        """Run repository reconnaissance and return canonical navigation data."""
        import time
        start_time = time.time()
        
        project_info = input_data.get("project_info", {})
        config = input_data.get("config", {})
        skill_context = await SkillService.resolve_agent_skills(config.get("user_id"), self.agent_type.value, {"project_info": project_info, "config": config, "task": input_data.get("task", ""), "task_context": input_data.get("task_context", "")})
        task = input_data.get("task", "")
        task_context = input_data.get("task_context", "")
        
        # Cleaned legacy mojibake comment.
        target_files = config.get("target_files", [])
        exclude_patterns = config.get("exclude_patterns", [])
        
        # Cleaned legacy mojibake comment.
        initial_message = f"""请梳理代码仓库，并为 Finding Agent 收集项目导航上下文。

## 项目信息
- 名称：{project_info.get('name', 'unknown')}
- 根目录：{project_info.get('root', '.')}
- 文件数量：{project_info.get('file_count', 'unknown')}

## 可用目标文件
"""
        if target_files:
            initial_message += f"已提供目标文件数量：{len(target_files)}\n"
            for tf in target_files[:10]:
                initial_message += f"- {tf}\n"
            if len(target_files) > 10:
                initial_message += f"- ... 另有 {len(target_files) - 10} 个文件\n"
            initial_message += "请先关注这些文件，再扩展到周边入口点和高信号目录。\n"
        else:
            initial_message += "未提供明确目标文件。请从仓库自身识别技术栈、入口点和优先审计路径。\n"

        if exclude_patterns:
            initial_message += f"\n排除模式：{', '.join(exclude_patterns[:5])}\n"

        initial_message += f"""
## 任务上下文
{task_context or task or '未提供额外任务上下文。'}

## 可用工具
{self.get_tools_description()}

返回 Final Answer 前必须先使用工具。结果要保守，并以已观察到的仓库证据为依据。
"""

        # Conversation history
        self._conversation_history = [
            {"role": "system", "content": self.config.system_prompt},
            {"role": "user", "content": initial_message},
        ]
        await self.emit_agent_start_debug(
            {
                "task": task,
                "task_context": task_context,
                "project_info": project_info,
                "skill_context": skill_context,
            }
        )
        await self.emit_prompt_debug("system", self.config.system_prompt)
        await self.emit_prompt_debug("user", initial_message)
        self._steps = []
        final_result = None
        error_message = None  # Runtime error captured during recon execution
        
        await self.emit_thinking("Recon Agent 开始收集仓库导航信息。")
        
        try:
            for iteration in range(self.config.max_iterations):
                if self.is_cancelled:
                    break
                
                self._iteration = iteration + 1
                
                # Cleaned legacy mojibake comment.
                if self.is_cancelled:
                    await self.emit_thinking("Recon run cancelled before the next model call.")
                    break
                
                # Cleaned legacy mojibake comment.
                try:
                    llm_output, tokens_this_round = await self.stream_llm_call(
                        self._conversation_history,
                        # Cleaned legacy mojibake comment.
                    )
                except asyncio.CancelledError:
                    logger.info(f"[{self.name}] LLM call cancelled")
                    break
                
                self._total_tokens += tokens_this_round
                
                # Cleaned legacy mojibake comment.
                if not llm_output or not llm_output.strip():
                    empty_retry_count = getattr(self, '_empty_retry_count', 0) + 1
                    self._empty_retry_count = empty_retry_count
                    
                    # Cleaned legacy mojibake comment.
                    logger.warning(
                        f"[{self.name}] Empty LLM response in iteration {self._iteration} "
                        f"(retry {empty_retry_count}/3, tokens_this_round={tokens_this_round})"
                    )
                    
                    if empty_retry_count >= 3:
                        logger.error(f"[{self.name}] Too many empty responses, generating fallback result")
                        error_message = "Recon stopped after repeated empty model responses."
                        await self.emit_event("warning", error_message)
                        # Cleaned legacy mojibake comment.
                        break
                    
                    # Cleaned legacy mojibake comment.
                    retry_prompt = f"""你上一条回复为空或不可用。

请严格使用以下格式之一回复：

Thought: [简要推理]
Action: [允许工具列表中的一个工具]
Action Input: {{"key": "value"}}

允许工具：{', '.join(self.tools.keys())}

如果 Recon 已完成：
Thought: [简要总结]
Final Answer: [规范 Recon JSON]
"""
                    
                    self._conversation_history.append({
                        "role": "user",
                        "content": retry_prompt,
                    })
                    continue
                
                # Cleaned legacy mojibake comment.
                self._empty_retry_count = 0

                # Cleaned legacy mojibake comment.
                step = self._parse_llm_response(llm_output)
                self._steps.append(step)
                
                # Cleaned legacy mojibake comment.
                if step.thought:
                    await self.emit_llm_thought(step.thought, iteration + 1)
                
                # Cleaned legacy mojibake comment.
                self._conversation_history.append({
                    "role": "assistant",
                    "content": llm_output,
                })
                await self.emit_model_response_debug(llm_output, iteration=self._iteration)
                
                # Cleaned legacy mojibake comment.
                if step.is_final:
                    await self.emit_llm_decision("Final answer detected", "LLM returned a final recon payload.")
                    await self.emit_llm_complete(
                        f"Recon completed in {self._iteration} iterations",
                        self._total_tokens
                    )
                    final_result = step.final_answer
                    break
                
                # Cleaned legacy mojibake comment.
                if step.action:
                    # Cleaned legacy mojibake comment.
                    await self.emit_llm_action(step.action, step.action_input or {})
                    
                    # Cleaned legacy mojibake comment.
                    tool_call_key = f"{step.action}:{json.dumps(step.action_input or {}, sort_keys=True)}"
                    if not hasattr(self, '_failed_tool_calls'):
                        self._failed_tool_calls = {}
                    
                    observation = await self.execute_tool(
                        step.action,
                        step.action_input or {}
                    )
                    
                    # Cleaned legacy mojibake comment.
                    is_tool_error = (
                        "error" in observation.lower() or 
                        "failed" in observation.lower() or 
                        "Exception" in observation or
                        "not found" in observation.lower() or
                        "Error" in observation
                    )
                    
                    if is_tool_error:
                        self._failed_tool_calls[tool_call_key] = self._failed_tool_calls.get(tool_call_key, 0) + 1
                        fail_count = self._failed_tool_calls[tool_call_key]
                        
                        # Cleaned legacy mojibake comment.
                        if fail_count >= 3:
                            logger.warning(f"[{self.name}] Tool call failed {fail_count} times: {tool_call_key}")
                            observation += f"\n\n重复工具失败提示：这个完全相同的工具调用已经失败 {fail_count} 次。\n"
                            observation += "1. 请改变策略，不要盲目重试相同输入。\n"
                            observation += "2. 优先使用 search_code 或 list_files 重新获取上下文。\n"
                            observation += "3. 如果已经收集到足够仓库证据，请保守总结。\n"
                            observation += "4. 如果 Recon 已完成，请立即返回 Final Answer。"
                            
                            # Cleaned legacy mojibake comment.
                            self._failed_tool_calls[tool_call_key] = 0
                    else:
                        # Cleaned legacy mojibake comment.
                        if tool_call_key in self._failed_tool_calls:
                            del self._failed_tool_calls[tool_call_key]
                    
                    # Cleaned legacy mojibake comment.
                    if self.is_cancelled:
                        logger.info(f"[{self.name}] Cancelled after tool execution")
                        break
                    
                    step.observation = observation
                    
                    # Cleaned legacy mojibake comment.
                    await self.emit_llm_observation(observation)
                    
                    # Cleaned legacy mojibake comment.
                    self._conversation_history.append({
                        "role": "user",
                        "content": f"Observation:\n{observation}",
                    })
                else:
                    # Cleaned legacy mojibake comment.
                    await self.emit_llm_decision("Missing action", "LLM response did not include a valid tool action.")
                    self._conversation_history.append({
                        "role": "user",
                        "content": "你上一条回复没有包含有效 Action。请只用 Thought/Action/Action Input 或 Final Answer 回复。",
                    })
            
            # Cleaned legacy mojibake comment.
            if not final_result and not self.is_cancelled and not error_message:
                await self.emit_thinking("Recon is forcing a final canonical summary.")
                
                # Cleaned legacy mojibake comment.
                self._conversation_history.append({
                    "role": "user",
                    "content": """现在返回最终 Recon 结果。

使用下面的规范 JSON schema，不要添加额外说明。
```json
{
    "project_profile": {"languages": [], "frameworks": [], "databases": [], "package_managers": [], "runtime_indicators": []},
    "project_structure": {"key_directories": [], "key_files": [], "monorepo_layout": ""},
    "entry_points": [{"type": "", "file": "", "line": 0, "method": "", "symbol": "", "notes": ""}],
    "priority_paths": [],
    "audit_targets": {"target_files": [], "exclude_patterns": []},
    "recommended_scanners": {"must_use": [], "optional": [], "reason": ""},
    "summary": ""
}
```

Final Answer:""",
                })
                
                try:
                    summary_output, _ = await self.stream_llm_call(
                        self._conversation_history,
                        # Cleaned legacy mojibake comment.
                    )
                    
                    if summary_output and summary_output.strip():
                        summary_text = summary_output.strip()
                        summary_text = re.sub(r'```json\s*', '', summary_text)
                        summary_text = re.sub(r'```\s*', '', summary_text)
                        fallback_result = self._summarize_from_steps(config=config)
                        if summary_text.strip() == "[LLM timeout]" or "{" not in summary_text:
                            final_result = fallback_result
                        else:
                            parsed_result = AgentJsonParser.parse(
                                summary_text,
                                default=fallback_result,
                            )
                            final_result = parsed_result if self._recon_result_has_signal(parsed_result) else fallback_result
                except Exception as e:
                    logger.warning(f"[{self.name}] Failed to generate summary: {e}")
            
            # Cleaned legacy mojibake comment.
            # Finalize result state
            duration_ms = int((time.time() - start_time) * 1000)

            if self.is_cancelled:
                await self.emit_event("info", f"Recon Agent cancelled after {self._iteration} iterations")
                return AgentResult(
                    success=False,
                    error="Task cancelled",
                    data=self._summarize_from_steps(config=config),
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )

            if error_message:
                await self.emit_event("error", f"Recon Agent failed: {error_message}")
                return AgentResult(
                    success=False,
                    error=error_message,
                    data=self._summarize_from_steps(config=config),
                    iterations=self._iteration,
                    tool_calls=self._tool_calls,
                    tokens_used=self._total_tokens,
                    duration_ms=duration_ms,
                )

            fallback_result = self._summarize_from_steps(config=config)
            if not final_result:
                final_result = fallback_result

            final_result = self._normalize_recon_result(final_result, config=config)
            if not self._recon_result_has_signal(final_result) and self._recon_result_has_signal(fallback_result):
                final_result = fallback_result
            final_result = self._merge_recon_with_project_info(final_result, project_info, config=config)

            self.record_work(f"Completed recon collection; entry_points={len(final_result.get('entry_points', []))}")
            self.record_work(f"Derived project profile: {final_result.get('project_profile', {})}")
            self.record_work(f"Derived priority paths: {len(final_result.get('priority_paths', []))}")

            if final_result.get("priority_paths"):
                self.add_insight(f"Generated {len(final_result['priority_paths'])} priority paths for downstream review")
            if final_result.get("recommended_scanners", {}).get("must_use") or final_result.get("recommended_scanners", {}).get("optional"):
                scanner_count = len(final_result.get("recommended_scanners", {}).get("must_use", [])) + len(final_result.get("recommended_scanners", {}).get("optional", []))
                self.add_insight(f"Suggested {scanner_count} external scanners")

            await self.emit_event(
                "info",
                f"Recon Agent completed: {self._iteration} iterations, {self._tool_calls} tool calls",
            )

            handoff = self._create_recon_handoff(final_result)
            await self.emit_handoff_debug("out", handoff)
            return AgentResult(
                success=True,
                data=final_result,
                iterations=self._iteration,
                tool_calls=self._tool_calls,
                tokens_used=self._total_tokens,
                duration_ms=duration_ms,
                handoff=handoff,
            )
        except Exception as e:
            logger.error(f"Recon Agent failed: {e}", exc_info=True)
            return AgentResult(success=False, error=str(e))
    
    def _summarize_from_steps(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Derive a conservative canonical recon payload from observed steps."""
        config = config or {}
        observations = [step.observation for step in self._steps if step.observation]
        thoughts = [step.thought.strip() for step in self._steps if step.thought]

        languages: List[str] = []
        frameworks: List[str] = []
        databases: List[str] = []
        key_files: List[str] = []
        key_directories: List[str] = []
        priority_paths: List[str] = []
        entry_points: List[Dict[str, Any]] = []

        def push_text(bucket: List[str], value: str) -> None:
            text = str(value or "").strip()
            if text and text not in bucket:
                bucket.append(text)

        def push_entry(entry: Dict[str, Any]) -> None:
            if entry not in entry_points:
                entry_points.append(entry)

        file_pattern = re.compile(r'[\w./-]+\.(?:py|js|ts|tsx|java|kt|go|php|rb|rs|cs|xml|yml|yaml|properties|gradle|sql)')
        for observation in observations:
            lowered = observation.lower()
            for keyword, language in {
                '.py': 'Python',
                'requirements.txt': 'Python',
                'setup.py': 'Python',
                '.java': 'Java',
                'pom.xml': 'Java',
                'build.gradle': 'Java',
                '.js': 'JavaScript',
                '.ts': 'TypeScript',
                'package.json': 'JavaScript',
                '.go': 'Go',
                'go.mod': 'Go',
                '.php': 'PHP',
                '.rb': 'Ruby',
                'cargo.toml': 'Rust',
                '.rs': 'Rust',
            }.items():
                if keyword in lowered:
                    push_text(languages, language)
            for keyword, framework in {
                'spring': 'Spring',
                'springboot': 'Spring Boot',
                'django': 'Django',
                'flask': 'Flask',
                'fastapi': 'FastAPI',
                'express': 'Express',
                'nestjs': 'NestJS',
                'react': 'React',
                'vue': 'Vue',
                'angular': 'Angular',
            }.items():
                if keyword in lowered:
                    push_text(frameworks, framework)
            for keyword, database in {
                'mysql': 'MySQL',
                'postgres': 'PostgreSQL',
                'redis': 'Redis',
                'mongodb': 'MongoDB',
                'sqlite': 'SQLite',
                'oracle': 'Oracle',
            }.items():
                if keyword in lowered:
                    push_text(databases, database)

            files = file_pattern.findall(observation)
            for file_path in files[:20]:
                push_text(key_files, file_path)
                directory = os.path.dirname(file_path).replace('\\', '/')
                if directory:
                    push_text(key_directories, directory)
                lowered_path = file_path.lower()
                if any(token in lowered_path for token in ['controller', 'route', 'router', 'api', 'handler', 'admin', 'web', 'service', 'executor', 'job']):
                    push_text(priority_paths, file_path)
                if any(token in lowered_path for token in ['controller', 'route', 'router', 'api', 'handler', 'admin']):
                    push_entry({
                        'type': 'candidate_entry_point',
                        'file': file_path,
                        'line': 1,
                        'method': '',
                        'symbol': '',
                        'notes': 'Derived from observed file path during recon.',
                    })

        for directory in key_directories[:20]:
            if any(token in directory.lower() for token in ['controller', 'route', 'router', 'api', 'admin', 'auth', 'service', 'executor', 'job']):
                push_text(priority_paths, directory)

        recommended_scanners = self._build_recommended_scanners(languages)
        summary = ' '.join(thoughts[-3:]).strip()
        if not summary:
            summary = (
                f"Recon fallback summary: languages={languages[:4]}; "
                f"entry_points={len(entry_points)}; priority_paths={len(priority_paths)}"
            )

        result = {
            'project_profile': {
                'languages': languages,
                'frameworks': frameworks,
                'databases': databases,
                'package_managers': [],
                'runtime_indicators': [],
            },
            'project_structure': {
                'key_directories': key_directories[:40],
                'key_files': key_files[:60],
                'monorepo_layout': '',
            },
            'entry_points': entry_points[:20],
            'priority_paths': priority_paths[:30],
            'audit_targets': {
                'target_files': list(dict.fromkeys((config.get('target_files') or []) + key_files[:50])),
                'exclude_patterns': config.get('exclude_patterns', []),
            },
            'recommended_scanners': recommended_scanners,
            'summary': summary,
        }
        return self._normalize_recon_result(result, config=config)
    def get_conversation_history(self) -> List[Dict[str, str]]:
        """Return the recorded conversation history for debugging."""
        return self._conversation_history

    def get_steps(self) -> List[ReconStep]:
        """Return the collected recon steps."""
        return self._steps

    def _create_recon_handoff(self, final_result: Dict[str, Any]) -> TaskHandoff:
        normalized = self._normalize_recon_result(final_result)
        project_profile = normalized.get("project_profile", {}) or {}
        languages = project_profile.get("languages", [])
        frameworks = project_profile.get("frameworks", [])
        priority_paths = normalized.get("priority_paths", []) or []
        entry_points = normalized.get("entry_points", []) or []

        summary_parts = ["Recon completed"]
        if languages:
            summary_parts.append(f"languages={', '.join(languages[:3])}")
        if frameworks:
            summary_parts.append(f"frameworks={', '.join(frameworks[:3])}")
        summary_parts.append(f"entry_points={len(entry_points)}")
        summary_parts.append(f"priority_paths={len(priority_paths)}")

        attention_points = []
        for entry_point in entry_points[:15]:
            if isinstance(entry_point, dict):
                attention_points.append(
                    f"[{entry_point.get('type', 'unknown')}] {entry_point.get('file', '')}:{entry_point.get('line', '')}"
                )

        return self.create_handoff(
            to_agent="orchestrator",
            summary='; '.join(summary_parts),
            key_findings=[],
            suggested_actions=[
                {
                    'action': 'audit_priority_path',
                    'target': path,
                    'reason': 'Recon marked this as a priority audit path.',
                }
                for path in priority_paths[:10]
            ],
            attention_points=attention_points,
            priority_areas=priority_paths[:15],
            context_data=normalized,
        )



