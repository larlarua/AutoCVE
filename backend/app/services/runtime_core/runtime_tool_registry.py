from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from app.services.agent.tools.ask_user_runtime_tool import AskUserRuntimeTool
from app.services.agent.tools.base import AgentTool
from app.services.agent.tools.plan_mode_runtime_tool import EnterPlanModeRuntimeTool, ExitPlanModeRuntimeTool
from app.services.agent.tools.todo_runtime_tool import TodoWriteRuntimeTool
from app.services.finding_runtime.models import ToolExecutionPayload
from app.services.finding_runtime.skills import RuntimeSkillTool
from app.services.finding_runtime.tools.finalize_finding import FinalizeFindingTool
from app.services.triage_runtime.tools import (
    FinalizeTriageBatchTool,
    FinalizeTriageTool,
    GetScanFindingTool,
    GetTriageBatchTool,
)
from app.services.runtime_core.permission_runtime import ToolPermissionDecision
from app.services.runtime_core.runtime_guardrails import (
    APPROVAL_SCOPE_SINGLE_USE,
    consume_write_approval,
    has_write_approval,
    is_guardrails_enabled,
    register_write_approval,
)
from app.services.runtime_core.shell_runtime_tools import (
    BashRuntimeTool,
    PowerShellRuntimeTool,
    detect_bash_executable,
    detect_powershell_executable,
    is_powershell_runtime_tool_enabled,
)
from app.services.runtime_core.tool_runtime import RuntimeTool, ToolExecutionContext, ToolRegistry
from app.services.runtime_core.tool_search_runtime import ToolSearchRuntimeTool


class ReadToolInput(BaseModel):
    file_path: str | None = Field(default=None, description="Path to a file relative to the project root.")
    file_paths: list[str] = Field(default_factory=list, description="Optional batch of related files to read together.")
    start_line: int | None = Field(default=None, description="Optional 1-based start line.")
    end_line: int | None = Field(default=None, description="Optional inclusive end line.")
    max_lines: int = Field(default=400, description="Maximum lines to return per file.")
    max_files: int = Field(default=6, description="Maximum files when batch reading.")


class GlobToolInput(BaseModel):
    path: str = Field(default=".", description="Directory relative to the project root.")
    pattern: str | None = Field(default=None, description="Optional glob pattern, for example **/*.java or *.xml.")
    recursive: bool = Field(default=True, description="Whether to walk child directories.")
    max_results: int = Field(default=120, description="Maximum files to return.")


class GrepToolInput(BaseModel):
    pattern: str = Field(description="Keyword or regular expression to search for.")
    path: str | None = Field(default=None, description="Optional directory relative to the project root.")
    glob: str | None = Field(default=None, description="Optional glob such as *.py or **/*.java.")
    case_sensitive: bool = Field(default=False, description="Whether the search is case sensitive.")
    max_results: int = Field(default=80, description="Maximum number of matches to return.")
    is_regex: bool = Field(default=False, description="Whether pattern should be treated as regex.")


class WriteToolInput(BaseModel):
    path: str = Field(description="Target path relative to the project root. Managed outputs should go under .auditai/.")
    content: str = Field(description="Text content to write.")
    overwrite: bool = Field(default=False, description="Whether to overwrite an existing file.")


def _result_to_payload(result: Any) -> ToolExecutionPayload:
    output_payload = result.to_dict()
    return ToolExecutionPayload(
        content=result.to_string(),
        output_payload=output_payload,
        metadata={"success": result.success, **(result.metadata or {})},
        is_error=not result.success,
    )


def _infer_project_root(agent_tools: dict[str, AgentTool]) -> str | None:
    for key in ("read_file", "list_files", "search_code"):
        tool = agent_tools.get(key)
        project_root = getattr(tool, "project_root", None)
        if isinstance(project_root, str) and project_root.strip():
            return project_root
    return None


class CanonicalReadTool(RuntimeTool):
    name = "Read"
    description = (
        "读取项目中的单个文件，或读取少量密切相关的文件。"
        "适合控制器、服务、配置、SQL、XML 和技能参考文件。"
    )
    input_model = ReadToolInput

    def __init__(self, *, read_tool: AgentTool | None, read_many_tool: AgentTool | None = None):
        self._read_tool = read_tool
        self._read_many_tool = read_many_tool

    def validate_input(self, raw_input: dict[str, Any]) -> ReadToolInput:
        payload = dict(raw_input or {})
        normalized = {
            "file_path": payload.get("file_path") or payload.get("path") or payload.get("file"),
            "file_paths": list(payload.get("file_paths") or payload.get("paths") or []),
            "start_line": payload.get("start_line") or payload.get("from_line"),
            "end_line": payload.get("end_line") or payload.get("to_line"),
            "max_lines": payload.get("max_lines") or payload.get("limit") or 400,
            "max_files": payload.get("max_files") or 6,
        }
        if not normalized["file_path"] and normalized["file_paths"]:
            normalized["file_path"] = normalized["file_paths"][0]
        return ReadToolInput.model_validate(normalized)

    def is_concurrency_safe(self, parsed_input: Any) -> bool:
        return True

    async def execute(self, parsed_input: ReadToolInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        del context
        file_paths = [item for item in parsed_input.file_paths if str(item or "").strip()]
        if len(file_paths) > 1:
            if self._read_many_tool is None:
                raise ValueError("Batch file reading is not available in this runtime.")
            result = await self._read_many_tool.execute(
                file_paths=file_paths,
                start_line=parsed_input.start_line,
                end_line=parsed_input.end_line,
                max_lines=parsed_input.max_lines,
                max_files=parsed_input.max_files,
            )
            return _result_to_payload(result)

        if self._read_tool is None or not parsed_input.file_path:
            raise ValueError("Read requires file_path or file_paths.")
        result = await self._read_tool.execute(
            file_path=parsed_input.file_path,
            start_line=parsed_input.start_line,
            end_line=parsed_input.end_line,
            max_lines=parsed_input.max_lines,
        )
        return _result_to_payload(result)


class CanonicalGlobTool(RuntimeTool):
    name = "Glob"
    description = "按 glob 模式列出项目目录下的文件。"
    input_model = GlobToolInput

    def __init__(self, *, list_tool: AgentTool):
        self._list_tool = list_tool

    def validate_input(self, raw_input: dict[str, Any]) -> GlobToolInput:
        payload = dict(raw_input or {})
        normalized = {
            "path": payload.get("path") or payload.get("directory") or ".",
            "pattern": payload.get("pattern") or payload.get("glob"),
            "recursive": payload.get("recursive", True),
            "max_results": payload.get("max_results") or payload.get("max_files") or 120,
        }
        return GlobToolInput.model_validate(normalized)

    def is_concurrency_safe(self, parsed_input: Any) -> bool:
        return True

    async def execute(self, parsed_input: GlobToolInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        del context
        result = await self._list_tool.execute(
            directory=parsed_input.path,
            pattern=parsed_input.pattern,
            recursive=parsed_input.recursive,
            max_files=parsed_input.max_results,
        )
        return _result_to_payload(result)


class CanonicalGrepTool(RuntimeTool):
    name = "Grep"
    description = "使用正则或关键字在代码和配置文本中搜索。"
    input_model = GrepToolInput

    def __init__(self, *, search_tool: AgentTool):
        self._search_tool = search_tool

    def validate_input(self, raw_input: dict[str, Any]) -> GrepToolInput:
        payload = dict(raw_input or {})
        normalized = {
            "pattern": payload.get("pattern") or payload.get("query") or payload.get("keyword"),
            "path": payload.get("path") or payload.get("directory"),
            "glob": payload.get("glob") or payload.get("file_pattern"),
            "case_sensitive": payload.get("case_sensitive", False),
            "max_results": payload.get("max_results") or payload.get("limit") or 80,
            "is_regex": payload.get("is_regex", False),
        }
        return GrepToolInput.model_validate(normalized)

    def is_concurrency_safe(self, parsed_input: Any) -> bool:
        return True

    async def execute(self, parsed_input: GrepToolInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        del context
        result = await self._search_tool.execute(
            keyword=parsed_input.pattern,
            file_pattern=parsed_input.glob,
            directory=parsed_input.path,
            case_sensitive=parsed_input.case_sensitive,
            max_results=parsed_input.max_results,
            is_regex=parsed_input.is_regex,
        )
        return _result_to_payload(result)


class CanonicalWriteTool(RuntimeTool):
    name = "Write"
    description = (
        "为当前审计会话写入文本产物。"
        "托管输出允许写入 .auditai/ 目录。"
        "启用护栏时，写入源码文件或项目根目录外的位置需要用户明确批准。"
    )
    input_model = WriteToolInput

    def __init__(self, *, session_store=None):
        self._session_store = session_store

    @staticmethod
    def _resolve_project_root(context: ToolExecutionContext) -> Path:
        payload = dict(context.recon_payload or {})
        if not payload and getattr(context.session, "recon_payload", None):
            payload = dict(context.session.recon_payload or {})
        project_info = payload.get("project_info") if isinstance(payload, dict) else {}
        workspace_root = str((project_info or {}).get("workspace_root") or "").strip()
        if not workspace_root:
            raise ValueError("Missing workspace root for write tool")
        return Path(workspace_root).resolve()

    def _guardrails_enabled(self, *, context: ToolExecutionContext) -> bool:
        if self._session_store is None:
            return False
        runtime_state = self._session_store.load_runtime_state(context.session_id)
        return is_guardrails_enabled(runtime_state)

    def _has_matching_approval(
        self,
        *,
        context: ToolExecutionContext,
        project_root: Path,
        resolved_path: Path,
        guardrail_code: str,
    ) -> bool:
        if self._session_store is None:
            return False
        runtime_state = self._session_store.load_runtime_state(context.session_id)
        return has_write_approval(
            runtime_state,
            project_root=project_root,
            resolved_path=resolved_path,
            guardrail_code=guardrail_code,
        )

    def _consume_matching_approval(
        self,
        *,
        context: ToolExecutionContext,
        project_root: Path,
        resolved_path: Path,
        guardrail_code: str,
    ) -> None:
        if self._session_store is None:
            return
        runtime_state = self._session_store.load_runtime_state(context.session_id)
        approval = consume_write_approval(
            runtime_state,
            project_root=project_root,
            resolved_path=resolved_path,
            guardrail_code=guardrail_code,
        )
        if approval and str(approval.get("scope") or "") == APPROVAL_SCOPE_SINGLE_USE:
            self._session_store.replace_runtime_state(context.session_id, runtime_state)

    @staticmethod
    def register_approval(
        runtime_state,
        *,
        path: str,
        guardrail_code: str,
        tool_call_id: str | None = None,
        scope: str | None = None,
    ) -> dict[str, Any]:
        return register_write_approval(
            runtime_state,
            path=path,
            guardrail_code=guardrail_code,
            tool_call_id=tool_call_id,
            scope=scope,
        )

    async def check_permission(
        self,
        parsed_input: WriteToolInput,
        context: ToolExecutionContext,
    ) -> ToolPermissionDecision:
        project_root = self._resolve_project_root(context)
        requested_path = str(parsed_input.path or "").strip()
        candidate = Path(requested_path)
        guardrails_enabled = self._guardrails_enabled(context=context)

        if candidate.is_absolute():
            if guardrails_enabled and self._has_matching_approval(
                context=context,
                project_root=project_root,
                resolved_path=candidate.resolve(),
                guardrail_code="absolute_path_requires_approval",
            ):
                return ToolPermissionDecision(allowed=True, source="tool_guardrail", mode="allow")
            if guardrails_enabled:
                return ToolPermissionDecision(
                    allowed=False,
                    source="tool_guardrail",
                    mode="ask",
                    reason="Writing to an absolute path requires explicit approval.",
                    guardrail_code="absolute_path_requires_approval",
                )
            return ToolPermissionDecision(allowed=True, source="tool_guardrail", mode="allow")

        resolved_path = (project_root / candidate).resolve()
        try:
            resolved_path.relative_to(project_root)
        except ValueError:
            if guardrails_enabled and self._has_matching_approval(
                context=context,
                project_root=project_root,
                resolved_path=resolved_path,
                guardrail_code="outside_project_root_requires_approval",
            ):
                return ToolPermissionDecision(allowed=True, source="tool_guardrail", mode="allow")
            if guardrails_enabled:
                return ToolPermissionDecision(
                    allowed=False,
                    source="tool_guardrail",
                    mode="ask",
                    reason="Writing outside the project root requires explicit approval.",
                    guardrail_code="outside_project_root_requires_approval",
                )
            return ToolPermissionDecision(allowed=True, source="tool_guardrail", mode="allow")

        artifact_root = (project_root / ".auditai").resolve()
        try:
            resolved_path.relative_to(artifact_root)
        except ValueError:
            if guardrails_enabled and self._has_matching_approval(
                context=context,
                project_root=project_root,
                resolved_path=resolved_path,
                guardrail_code="source_write_requires_approval",
            ):
                return ToolPermissionDecision(allowed=True, source="tool_guardrail", mode="allow")
            if guardrails_enabled:
                return ToolPermissionDecision(
                    allowed=False,
                    source="tool_guardrail",
                    mode="ask",
                    reason="写入源码文件需要明确批准。生成的审计产物请写入 .auditai/。",
                    guardrail_code="source_write_requires_approval",
                )

        if resolved_path.exists() and parsed_input.overwrite and guardrails_enabled and self._has_matching_approval(
            context=context,
            project_root=project_root,
            resolved_path=resolved_path,
            guardrail_code="overwrite_existing_requires_approval",
        ):
            return ToolPermissionDecision(allowed=True, source="tool_guardrail", mode="allow")

        if resolved_path.exists() and not parsed_input.overwrite:
            return ToolPermissionDecision(
                allowed=False,
                source="tool_guardrail",
                mode="deny",
                reason="Target file already exists. Re-run with overwrite=true to replace an existing artifact.",
                guardrail_code="artifact_exists_requires_overwrite",
            )

        if resolved_path.exists() and parsed_input.overwrite and guardrails_enabled:
            return ToolPermissionDecision(
                allowed=False,
                source="tool_guardrail",
                mode="ask",
                reason="Overwriting an existing file requires explicit approval while guardrails are enabled.",
                guardrail_code="overwrite_existing_requires_approval",
            )

        return ToolPermissionDecision(allowed=True, source="tool_guardrail", mode="allow")

    async def execute(self, parsed_input: WriteToolInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        project_root = self._resolve_project_root(context)
        requested_path = Path(str(parsed_input.path or "").strip())
        resolved_path = requested_path.resolve() if requested_path.is_absolute() else (project_root / requested_path).resolve()
        guardrails_enabled = self._guardrails_enabled(context=context)
        if guardrails_enabled:
            if requested_path.is_absolute():
                self._consume_matching_approval(
                    context=context,
                    project_root=project_root,
                    resolved_path=resolved_path,
                    guardrail_code="absolute_path_requires_approval",
                )
            else:
                try:
                    resolved_path.relative_to(project_root)
                except ValueError:
                    self._consume_matching_approval(
                        context=context,
                        project_root=project_root,
                        resolved_path=resolved_path,
                        guardrail_code="outside_project_root_requires_approval",
                    )
                else:
                    artifact_root = (project_root / ".auditai").resolve()
                    try:
                        resolved_path.relative_to(artifact_root)
                    except ValueError:
                        self._consume_matching_approval(
                            context=context,
                            project_root=project_root,
                            resolved_path=resolved_path,
                            guardrail_code="source_write_requires_approval",
                        )
                    if resolved_path.exists() and parsed_input.overwrite:
                        self._consume_matching_approval(
                            context=context,
                            project_root=project_root,
                            resolved_path=resolved_path,
                            guardrail_code="overwrite_existing_requires_approval",
                        )
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_path.write_text(parsed_input.content, encoding="utf-8")
        artifact_root = (project_root / ".auditai").resolve()
        is_managed_output = False
        try:
            resolved_path.relative_to(artifact_root)
            is_managed_output = True
        except ValueError:
            is_managed_output = False
        return ToolExecutionPayload(
            content=f"Wrote audit artifact to {resolved_path}",
            output_payload={
                "path": parsed_input.path,
                "resolved_path": str(resolved_path),
                "bytes_written": len(parsed_input.content.encode("utf-8")),
                "artifact_type": "managed_output" if is_managed_output else "project_write",
                "overwrite": parsed_input.overwrite,
            },
            metadata={"managed_output": is_managed_output},
        )


def build_runtime_tool_registry(*, session_store, agent_tools: dict[str, AgentTool], agent_type: str, user_id: str | None = None) -> ToolRegistry:
    tools: list[RuntimeTool] = []

    read_tool = agent_tools.get("read_file")
    if isinstance(read_tool, AgentTool):
        read_many_tool = agent_tools.get("read_many_files")
        tools.append(
            CanonicalReadTool(
                read_tool=read_tool,
                read_many_tool=read_many_tool if isinstance(read_many_tool, AgentTool) else None,
            )
        )

    list_tool = agent_tools.get("list_files")
    if isinstance(list_tool, AgentTool):
        tools.append(CanonicalGlobTool(list_tool=list_tool))

    search_tool = agent_tools.get("search_code")
    if isinstance(search_tool, AgentTool):
        tools.append(CanonicalGrepTool(search_tool=search_tool))

    tools.append(CanonicalWriteTool(session_store=session_store))

    project_root = _infer_project_root(agent_tools)
    shell_backend = agent_tools.get("sandbox_exec") if isinstance(agent_tools.get("sandbox_exec"), AgentTool) else None
    if project_root:
        bash_executable = detect_bash_executable()
        if bash_executable or shell_backend is not None:
            tools.append(
                BashRuntimeTool(
                    project_root=project_root,
                    backend_tool=shell_backend,
                    executable=bash_executable,
                    session_store=session_store,
                )
            )
        if is_powershell_runtime_tool_enabled():
            powershell_executable = detect_powershell_executable()
            if powershell_executable or shell_backend is not None:
                tools.append(
                    PowerShellRuntimeTool(
                        project_root=project_root,
                        backend_tool=shell_backend,
                        executable=powershell_executable,
                        session_store=session_store,
                    )
                )

    tools.append(
        RuntimeSkillTool(
            session_store=session_store,
            agent_type=agent_type,
            user_id=user_id,
        )
    )
    if str(agent_type or "").strip() == "finding":
        tools.append(FinalizeFindingTool())
    if str(agent_type or "").strip() == "triage":
        tools.extend(
            [
                GetTriageBatchTool(project_root=project_root),
                GetScanFindingTool(project_root=project_root),
                FinalizeTriageBatchTool(project_root=project_root),
                FinalizeTriageTool(project_root=project_root),
            ]
        )
    tools.extend(
        [
            TodoWriteRuntimeTool(session_store),
            AskUserRuntimeTool(session_store),
            EnterPlanModeRuntimeTool(session_store),
            ExitPlanModeRuntimeTool(session_store),
        ]
    )

    registry = ToolRegistry(tools)
    if registry.has_deferred_tools():
        registry.register(ToolSearchRuntimeTool(session_store=session_store, registry_getter=lambda: registry))
    return registry
