"""
File and code navigation tools used by agents.
"""

from __future__ import annotations

import asyncio
import fnmatch
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .base import AgentTool, ToolResult


def _build_allowed_roots(project_root: str, additional_roots: Optional[List[str]] = None) -> List[str]:
    roots: List[str] = []
    for raw_root in [project_root, *(additional_roots or [])]:
        normalized = os.path.realpath(str(raw_root or "").strip())
        if normalized and normalized not in roots:
            roots.append(normalized)
    return roots


def _resolve_allowed_path(path_value: str, allowed_roots: List[str]) -> Optional[str]:
    raw_path = str(path_value or "").strip()
    if not raw_path:
        return None

    if os.path.isabs(raw_path):
        candidate = os.path.realpath(raw_path)
        if any(candidate.startswith(root) for root in allowed_roots):
            return candidate
        return None

    fallback_candidate: Optional[str] = None
    for root in allowed_roots:
        candidate = os.path.realpath(os.path.join(root, raw_path))
        if not candidate.startswith(root):
            continue
        if os.path.exists(candidate):
            return candidate
        if fallback_candidate is None:
            fallback_candidate = candidate
    return fallback_candidate


def _best_display_path(full_path: str, project_root: str, allowed_roots: List[str], requested_path: str) -> str:
    if not full_path:
        return requested_path

    normalized_full = os.path.realpath(full_path)
    normalized_project = os.path.realpath(project_root)
    if normalized_full.startswith(normalized_project):
        return os.path.relpath(normalized_full, normalized_project).replace("\\", "/")

    for root in allowed_roots[1:]:
        normalized_root = os.path.realpath(root)
        if normalized_full.startswith(normalized_root):
            root_name = os.path.basename(normalized_root.rstrip("/\\"))
            relative = os.path.relpath(normalized_full, normalized_root).replace("\\", "/")
            return f"{root_name}/{relative}" if relative != "." else root_name

    return requested_path.replace("\\", "/")


def _detect_language(file_path: str) -> str:
    return {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rs": "rust",
        ".cpp": "cpp",
        ".c": "c",
        ".cs": "csharp",
        ".php": "php",
        ".rb": "ruby",
        ".swift": "swift",
        ".md": "markdown",
        ".xml": "xml",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
    }.get(Path(file_path).suffix.lower(), "text")


class FileReadInput(BaseModel):
    file_path: str = Field(description="File path relative to the audit project root or an approved shared root")
    start_line: Optional[int] = Field(default=None, description="Optional 1-based start line")
    end_line: Optional[int] = Field(default=None, description="Optional inclusive end line")
    max_lines: int = Field(default=500, description="Maximum number of lines to return")


class ReadManyFilesInput(BaseModel):
    file_paths: List[str] = Field(description="Multiple file paths to read in one audit turn")
    start_line: Optional[int] = Field(default=None, description="Optional shared start line")
    end_line: Optional[int] = Field(default=None, description="Optional shared end line")
    max_lines: int = Field(default=220, description="Maximum lines per file")
    max_files: int = Field(default=6, description="Maximum number of files to read in one batch")


class FileSearchInput(BaseModel):
    keyword: str = Field(description="Keyword or regex to search for")
    file_pattern: Optional[str] = Field(default=None, description="Optional glob such as *.py")
    directory: Optional[str] = Field(default=None, description="Optional directory relative to project root or shared root")
    case_sensitive: bool = Field(default=False, description="Whether the search is case sensitive")
    max_results: int = Field(default=50, description="Maximum number of matches to return")
    is_regex: bool = Field(default=False, description="Whether keyword should be treated as regex")


class ListFilesInput(BaseModel):
    directory: str = Field(default=".", description="Directory relative to project root or shared root")
    pattern: Optional[str] = Field(default=None, description="Optional glob such as *.py")
    recursive: bool = Field(default=False, description="Whether to walk child directories")
    max_files: int = Field(default=100, description="Maximum number of files to return")


class FileReadTool(AgentTool):
    def __init__(
        self,
        project_root: str,
        exclude_patterns: Optional[List[str]] = None,
        target_files: Optional[List[str]] = None,
        additional_roots: Optional[List[str]] = None,
    ):
        super().__init__()
        self.project_root = os.path.realpath(project_root)
        self.exclude_patterns = exclude_patterns or []
        self.target_files = set(target_files) if target_files else None
        self.additional_roots = [str(root) for root in (additional_roots or []) if str(root or "").strip()]
        self.allowed_roots = _build_allowed_roots(self.project_root, self.additional_roots)

    @property
    def name(self) -> str:
        return "read_file"

    @property
    def description(self) -> str:
        return (
            "读取审计项目中的文件。"
            "也支持本地技能库等已批准的共享根目录。"
        )

    @property
    def args_schema(self):
        return FileReadInput

    def is_concurrency_safe(self, **kwargs) -> bool:
        del kwargs
        return True

    def is_read_only(self, **kwargs) -> bool:
        del kwargs
        return True

    @staticmethod
    def _read_file_lines_sync(file_path: str, start_idx: int, end_idx: int) -> tuple[list[str], int]:
        selected_lines: List[str] = []
        total_lines = 0
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            for index, line in enumerate(handle):
                total_lines = index + 1
                if start_idx <= index < end_idx:
                    selected_lines.append(line)
                elif index >= end_idx:
                    break
        return selected_lines, total_lines

    @staticmethod
    def _read_all_lines_sync(file_path: str) -> List[str]:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.readlines()

    def _is_target_allowed(self, requested_path: str, resolved_path: str) -> bool:
        if not self.target_files:
            return True
        normalized_project = os.path.realpath(self.project_root)
        if not os.path.realpath(resolved_path).startswith(normalized_project):
            return True
        relative_path = os.path.relpath(resolved_path, normalized_project).replace("\\", "/")
        requested_relative = str(requested_path or "").replace("\\", "/").strip()
        return relative_path in self.target_files or requested_relative in self.target_files

    def _should_exclude(self, display_path: str) -> bool:
        basename = os.path.basename(display_path)
        for pattern in self.exclude_patterns:
            if fnmatch.fnmatch(display_path, pattern) or fnmatch.fnmatch(basename, pattern):
                return True
        return False

    async def _read_resolved_file(
        self,
        *,
        requested_path: str,
        full_path: str,
        start_line: Optional[int],
        end_line: Optional[int],
        max_lines: int,
    ) -> ToolResult:
        if not os.path.exists(full_path):
            return ToolResult(success=False, error=f"文件不存在: {requested_path}")
        if not os.path.isfile(full_path):
            return ToolResult(success=False, error=f"不是文件: {requested_path}")

        file_size = os.path.getsize(full_path)
        is_large_file = file_size > 1024 * 1024
        if is_large_file and start_line is None and end_line is None:
            return ToolResult(
                success=False,
                error=f"文件过大 ({file_size / 1024:.1f}KB)，请指定 start_line 和 end_line 读取部分内容",
            )

        if is_large_file and (start_line is not None or end_line is not None):
            start_idx = max(0, (start_line or 1) - 1)
            end_idx = end_line if end_line else start_idx + max_lines
            selected_lines, total_lines = await asyncio.to_thread(
                self._read_file_lines_sync, full_path, start_idx, end_idx
            )
            end_idx = min(end_idx, start_idx + len(selected_lines))
        else:
            lines = await asyncio.to_thread(self._read_all_lines_sync, full_path)
            total_lines = len(lines)
            start_idx = max(0, (start_line or 1) - 1)
            end_idx = min(total_lines, end_line) if end_line is not None else min(total_lines, start_idx + max_lines)
            selected_lines = lines[start_idx:end_idx]

        numbered_lines = [f"{index:4d}| {line.rstrip()}" for index, line in enumerate(selected_lines, start=start_idx + 1)]
        display_path = _best_display_path(full_path, self.project_root, self.allowed_roots, requested_path)
        language = _detect_language(full_path)
        output = f"文件: {display_path}\n"
        output += f"行数: {start_idx + 1}-{end_idx} / {total_lines}\n\n"
        output += f"```{language}\n" + "\n".join(numbered_lines) + "\n```"
        if end_idx < total_lines:
            output += f"\n\n... 还有 {total_lines - end_idx} 行未显示"

        return ToolResult(
            success=True,
            data=output,
            metadata={
                "file_path": display_path,
                "resolved_path": full_path,
                "total_lines": total_lines,
                "start_line": start_idx + 1,
                "end_line": end_idx,
                "language": language,
            },
        )

    async def _execute(
        self,
        file_path: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        max_lines: int = 500,
        **kwargs,
    ) -> ToolResult:
        del kwargs
        full_path = _resolve_allowed_path(file_path, self.allowed_roots)
        if not full_path:
            return ToolResult(success=False, error="安全错误：不允许访问项目目录外的文件")
        if not self._is_target_allowed(file_path, full_path):
            return ToolResult(success=False, error=f"文件被排除或不在目标文件列表中: {file_path}")

        display_path = _best_display_path(full_path, self.project_root, self.allowed_roots, file_path)
        if self._should_exclude(display_path):
            return ToolResult(success=False, error=f"文件被排除或不在目标文件列表中: {display_path}")

        try:
            return await self._read_resolved_file(
                requested_path=file_path,
                full_path=full_path,
                start_line=start_line,
                end_line=end_line,
                max_lines=max_lines,
            )
        except Exception as exc:  # noqa: BLE001
            return ToolResult(success=False, error=f"读取文件失败: {str(exc)}")


class ReadManyFilesTool(FileReadTool):
    @property
    def name(self) -> str:
        return "read_many_files"

    @property
    def description(self) -> str:
        return (
            "在一次调用中读取多个相关源码文件。"
            "适合同时对比 source、sink、controller、service、mapper、xml 文件。"
        )

    @property
    def args_schema(self):
        return ReadManyFilesInput

    async def _execute(
        self,
        file_paths: List[str],
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
        max_lines: int = 220,
        max_files: int = 6,
        **kwargs,
    ) -> ToolResult:
        del kwargs
        normalized_paths: List[str] = []
        seen = set()
        for raw_path in file_paths or []:
            file_path = str(raw_path or "").strip()
            if not file_path or file_path in seen:
                continue
            seen.add(file_path)
            normalized_paths.append(file_path)

        if not normalized_paths:
            return ToolResult(success=False, error="At least one file_path is required.")
        if len(normalized_paths) > max_files:
            return ToolResult(
                success=False,
                error=f"Too many files requested ({len(normalized_paths)}). Limit is {max_files}.",
            )

        rendered_results: List[str] = []
        failures: List[str] = []
        for index, file_path in enumerate(normalized_paths, start=1):
            result = await super()._execute(
                file_path=file_path,
                start_line=start_line,
                end_line=end_line,
                max_lines=max_lines,
            )
            if not result.success:
                failures.append(f"{file_path}: {result.error}")
                continue
            rendered_results.append(f"[{index}/{len(normalized_paths)}]\n{result.data}")

        if failures:
            return ToolResult(
                success=False,
                error="Failed to read one or more files: " + " | ".join(failures),
                metadata={"files_requested": normalized_paths, "failures": failures},
            )

        return ToolResult(
            success=True,
            data="Batch file reads:\n\n" + "\n\n".join(rendered_results),
            metadata={
                "files_read": normalized_paths,
                "files_requested": normalized_paths,
                "total_files": len(normalized_paths),
            },
        )


class FileSearchTool(AgentTool):
    DEFAULT_EXCLUDE_DIRS = {
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".git",
        "__pycache__",
        ".pytest_cache",
        "coverage",
        ".nyc_output",
        ".vscode",
        ".idea",
        ".vs",
        "target",
        "venv",
        "env",
    }

    def __init__(
        self,
        project_root: str,
        exclude_patterns: Optional[List[str]] = None,
        target_files: Optional[List[str]] = None,
        additional_roots: Optional[List[str]] = None,
    ):
        super().__init__()
        self.project_root = os.path.realpath(project_root)
        self.exclude_patterns = exclude_patterns or []
        self.target_files = set(target_files) if target_files else None
        self.additional_roots = [str(root) for root in (additional_roots or []) if str(root or "").strip()]
        self.allowed_roots = _build_allowed_roots(self.project_root, self.additional_roots)
        self.exclude_dirs = set(self.DEFAULT_EXCLUDE_DIRS)
        for pattern in self.exclude_patterns:
            if pattern.endswith("/**"):
                self.exclude_dirs.add(pattern[:-3])
            elif "/" not in pattern and "*" not in pattern:
                self.exclude_dirs.add(pattern)

    @property
    def name(self) -> str:
        return "search_code"

    @property
    def description(self) -> str:
        return "使用关键字或正则搜索代码，并返回局部上下文。"

    @property
    def args_schema(self):
        return FileSearchInput

    def is_concurrency_safe(self, **kwargs) -> bool:
        del kwargs
        return True

    def is_read_only(self, **kwargs) -> bool:
        del kwargs
        return True

    @staticmethod
    def _read_file_lines_sync(file_path: str) -> List[str]:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as handle:
            return handle.readlines()

    @staticmethod
    def _normalize_keyword_input(
        keyword: Optional[str] = None,
        **kwargs,
    ) -> Optional[str]:
        if isinstance(keyword, str) and keyword.strip():
            return keyword.strip()

        for alias in ("query", "pattern", "term", "text", "needle", "raw_input"):
            candidate = kwargs.get(alias)
            if isinstance(candidate, str) and candidate.strip():
                return candidate.strip()
        return None

    async def _execute(
        self,
        keyword: Optional[str] = None,
        file_pattern: Optional[str] = None,
        directory: Optional[str] = None,
        case_sensitive: bool = False,
        max_results: int = 50,
        is_regex: bool = False,
        **kwargs,
    ) -> ToolResult:
        normalized_keyword = self._normalize_keyword_input(keyword, **kwargs)
        if not normalized_keyword:
            return ToolResult(
                success=False,
                error="Missing required search keyword. Provide keyword, query, pattern, term, or text.",
            )

        search_dir = self.project_root if not directory else _resolve_allowed_path(directory, self.allowed_roots)
        if not search_dir:
            return ToolResult(
                success=False,
                error="Security error: search is limited to the audit project and approved shared roots.",
            )

        flags = 0 if case_sensitive else re.IGNORECASE
        try:
            pattern = re.compile(normalized_keyword if is_regex else re.escape(normalized_keyword), flags)
        except re.error as exc:
            return ToolResult(success=False, error=f"Invalid search pattern: {exc}")

        results: List[Dict[str, Any]] = []
        files_searched = 0
        for root, dirs, files in os.walk(search_dir):
            dirs[:] = [directory_name for directory_name in dirs if directory_name not in self.exclude_dirs]
            for filename in files:
                if file_pattern and not fnmatch.fnmatch(filename, file_pattern):
                    continue
                full_path = os.path.join(root, filename)
                display_path = _best_display_path(full_path, self.project_root, self.allowed_roots, full_path)
                if self.target_files and display_path not in self.target_files and display_path.startswith("skill_library/") is False:
                    continue
                if any(
                    fnmatch.fnmatch(display_path, pattern_text) or fnmatch.fnmatch(filename, pattern_text)
                    for pattern_text in self.exclude_patterns
                ):
                    continue

                try:
                    lines = await asyncio.to_thread(self._read_file_lines_sync, full_path)
                except Exception:
                    continue
                files_searched += 1

                for index, line in enumerate(lines):
                    if not pattern.search(line):
                        continue
                    start = max(0, index - 1)
                    end = min(len(lines), index + 2)
                    context_lines = []
                    for inner_index in range(start, end):
                        prefix = ">" if inner_index == index else " "
                        context_lines.append(f"{prefix} {inner_index + 1:4d}| {lines[inner_index].rstrip()}")
                    results.append(
                        {
                            "file": display_path,
                            "line": index + 1,
                            "match": line.strip()[:200],
                            "context": "\n".join(context_lines),
                        }
                    )
                    if len(results) >= max_results:
                        break
                if len(results) >= max_results:
                    break
            if len(results) >= max_results:
                break

        if not results:
            return ToolResult(
                success=True,
                data=f"未找到 '{normalized_keyword}' 的匹配结果。\n已搜索 {files_searched} 个文件。",
                metadata={"files_searched": files_searched, "matches": 0, "keyword": normalized_keyword},
            )

        output_parts = [
            f"'{normalized_keyword}' 的搜索结果\n",
            f"在 {files_searched} 个文件中找到 {len(results)} 处匹配。\n",
        ]
        for result in results:
            output_parts.append(f"\nFile {result['file']}:{result['line']}")
            output_parts.append(f"```\n{result['context']}\n```")
        if len(results) >= max_results:
            output_parts.append(f"\n... results truncated (max {max_results})")

        return ToolResult(
            success=True,
            data="\\n".join(output_parts),
            metadata={
                "keyword": normalized_keyword,
                "files_searched": files_searched,
                "matches": len(results),
                "results": results[:10],
            },
        )

class ListFilesTool(AgentTool):
    DEFAULT_EXCLUDE_DIRS = {
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".git",
        "__pycache__",
        ".pytest_cache",
        "coverage",
    }

    def __init__(
        self,
        project_root: str,
        exclude_patterns: Optional[List[str]] = None,
        target_files: Optional[List[str]] = None,
        additional_roots: Optional[List[str]] = None,
    ):
        super().__init__()
        self.project_root = os.path.realpath(project_root)
        self.exclude_patterns = exclude_patterns or []
        self.target_files = set(target_files) if target_files else None
        self.additional_roots = [str(root) for root in (additional_roots or []) if str(root or "").strip()]
        self.allowed_roots = _build_allowed_roots(self.project_root, self.additional_roots)
        self.exclude_dirs = set(self.DEFAULT_EXCLUDE_DIRS)
        for pattern in self.exclude_patterns:
            if pattern.endswith("/**"):
                self.exclude_dirs.add(pattern[:-3])
            elif "/" not in pattern and "*" not in pattern:
                self.exclude_dirs.add(pattern)

    @property
    def name(self) -> str:
        return "list_files"

    @property
    def description(self) -> str:
        return "列出审计项目或技能库等已批准共享根目录下的文件。"

    @property
    def args_schema(self):
        return ListFilesInput

    def is_concurrency_safe(self, **kwargs) -> bool:
        del kwargs
        return True

    def is_read_only(self, **kwargs) -> bool:
        del kwargs
        return True

    async def _execute(
        self,
        directory: str = ".",
        pattern: Optional[str] = None,
        recursive: bool = False,
        max_files: int = 100,
        **kwargs,
    ) -> ToolResult:
        if "path" in kwargs and kwargs["path"]:
            directory = kwargs["path"]

        target_dir = _resolve_allowed_path(directory, self.allowed_roots)
        if not target_dir:
            return ToolResult(success=False, error="安全错误：不允许访问项目目录外的目录")
        if not os.path.exists(target_dir):
            return ToolResult(success=False, error=f"目录不存在: {directory}")
        if not os.path.isdir(target_dir):
            return ToolResult(success=False, error=f"不是目录: {directory}")

        files: List[str] = []
        dirs: List[str] = []

        def include_file(display_path: str, file_name: str) -> bool:
            if pattern and not fnmatch.fnmatch(file_name, pattern):
                return False
            if self.target_files and display_path not in self.target_files and not display_path.startswith("skill_library/"):
                return False
            if any(fnmatch.fnmatch(display_path, item) or fnmatch.fnmatch(file_name, item) for item in self.exclude_patterns):
                return False
            return True

        if recursive:
            for root, dirnames, filenames in os.walk(target_dir):
                dirnames[:] = [name for name in dirnames if name not in self.exclude_dirs]
                for filename in filenames:
                    full_path = os.path.join(root, filename)
                    display_path = _best_display_path(full_path, self.project_root, self.allowed_roots, full_path)
                    if not include_file(display_path, filename):
                        continue
                    files.append(display_path)
                    if len(files) >= max_files:
                        break
                if len(files) >= max_files:
                    break
        else:
            for item in os.listdir(target_dir):
                if item in self.exclude_dirs:
                    continue
                full_path = os.path.join(target_dir, item)
                display_path = _best_display_path(full_path, self.project_root, self.allowed_roots, full_path)
                if os.path.isdir(full_path):
                    dirs.append(display_path.rstrip("/") + "/")
                    continue
                if include_file(display_path, item):
                    files.append(display_path)
                if len(files) >= max_files:
                    break

        output_parts = [f"目录: {directory}\n"]
        if dirs:
            output_parts.append("目录:")
            for item in sorted(dirs)[:20]:
                output_parts.append(f"  {item}")
            if len(dirs) > 20:
                output_parts.append(f"  ... 还有 {len(dirs) - 20} 个目录")

        if files:
            output_parts.append(f"\n文件 ({len(files)}):")
            for item in sorted(files):
                output_parts.append(f"  {item}")
        elif self.target_files:
            output_parts.append(f"\n指定的目标文件 ({len(self.target_files)}):")
            for item in sorted(self.target_files)[:20]:
                output_parts.append(f"  {item}")
            if len(self.target_files) > 20:
                output_parts.append(f"  ... 还有 {len(self.target_files) - 20} 个文件")

        if len(files) >= max_files:
            output_parts.append(f"\n... 结果已截断（最大 {max_files} 个文件）")

        return ToolResult(
            success=True,
            data="\n".join(output_parts),
            metadata={
                "directory": directory,
                "file_count": len(files),
                "dir_count": len(dirs),
            },
        )
