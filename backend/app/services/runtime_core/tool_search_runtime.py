from __future__ import annotations

import re
from typing import Any, Callable

from pydantic import BaseModel, Field

from app.services.finding_runtime.models import ToolExecutionPayload
from app.services.runtime_core.tool_runtime import RuntimeTool, ToolExecutionContext, ToolRegistry


TOOL_SEARCH_TOOL_NAME = "ToolSearch"


class ToolSearchInput(BaseModel):
    query: str = Field(..., min_length=1, description="Query to search deferred tools or select by name with select:<tool_name>.")
    max_results: int = Field(default=5, ge=1, le=25)


def _parse_tool_name(name: str) -> tuple[list[str], str]:
    spaced = re.sub(r"([a-z])([A-Z])", r"\1 \2", str(name or ""))
    normalized = spaced.replace("_", " ").strip().lower()
    parts = [part for part in normalized.split() if part]
    return parts, normalized


def _score_tool_match(query: str, *, tool: RuntimeTool) -> int:
    query_terms = [term for term in str(query or "").strip().lower().split() if term]
    if not query_terms:
        return 0

    name_parts, full_name = _parse_tool_name(tool.name)
    description = str(tool.description or "").strip().lower()
    search_hint = str(tool.search_hint or "").strip().lower()
    score = 0
    for term in query_terms:
        if term in name_parts:
            score += 10
        elif any(term in part for part in name_parts):
            score += 5
        elif term in full_name:
            score += 3
        if search_hint and re.search(rf"\b{re.escape(term)}\b", search_hint):
            score += 4
        if description and re.search(rf"\b{re.escape(term)}\b", description):
            score += 2
    return score


class ToolSearchRuntimeTool(RuntimeTool):
    name = TOOL_SEARCH_TOOL_NAME
    description = "按名称或能力搜索延迟加载的工具，并在下一轮让匹配工具可用。"
    input_model = ToolSearchInput
    search_hint = "按名称或能力搜索延迟加载的工具"
    always_load = True

    def __init__(self, *, session_store, registry_getter: Callable[[], ToolRegistry]):
        super().__init__()
        self._session_store = session_store
        self._registry_getter = registry_getter

    def is_enabled(self) -> bool:
        registry = self._registry_getter()
        for tool in registry.all_tools():
            if tool is self:
                continue
            if tool.always_load or not tool.should_defer:
                continue
            try:
                if tool.is_enabled():
                    return True
            except Exception:
                continue
        return False

    def is_concurrency_safe(self, parsed_input: Any = None) -> bool:
        del parsed_input
        return True

    def is_read_only(self, parsed_input: Any = None) -> bool:
        del parsed_input
        return True

    async def execute(self, parsed_input: ToolSearchInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        registry = self._registry_getter()
        query_state = self._session_store.load_query_loop_state(context.session_id)
        explicit_active_names = query_state.tool_use_context.get("active_tool_names")
        deferred_tools = registry.deferred_tools(active_tool_names=explicit_active_names)
        matches = self._resolve_matches(
            registry=registry,
            deferred_tools=deferred_tools,
            query=parsed_input.query,
            max_results=parsed_input.max_results,
        )
        if matches:
            content = f"Deferred tools ready: {', '.join(matches)}"
        else:
            content = f"No matching deferred tools found for query: {parsed_input.query}"
        return ToolExecutionPayload(
            content=content,
            output_payload={
                "matches": matches,
                "query": parsed_input.query,
                "total_deferred_tools": len(deferred_tools),
            },
            metadata={"tool_search": True},
            is_error=False,
        )

    @staticmethod
    def _resolve_matches(
        *,
        registry: ToolRegistry,
        deferred_tools: list[RuntimeTool],
        query: str,
        max_results: int,
    ) -> list[str]:
        normalized_query = str(query or "").strip()
        if not normalized_query:
            return []

        select_match = re.match(r"^select:(.+)$", normalized_query, flags=re.IGNORECASE)
        if select_match:
            found: list[str] = []
            for raw_name in select_match.group(1).split(","):
                candidate = str(raw_name or "").strip()
                if not candidate:
                    continue
                tool = registry.get(candidate)
                if tool is None:
                    continue
                if tool.name not in found:
                    found.append(tool.name)
            return found[:max_results]

        exact_match = None
        for tool in deferred_tools:
            if tool.name.lower() == normalized_query.lower():
                exact_match = tool.name
                break
        if exact_match is not None:
            return [exact_match]

        scored = []
        for tool in deferred_tools:
            score = _score_tool_match(normalized_query, tool=tool)
            if score <= 0:
                continue
            scored.append((score, tool.name))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [name for _, name in scored[:max_results]]
