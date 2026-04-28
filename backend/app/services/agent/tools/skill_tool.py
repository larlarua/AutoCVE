from typing import List, Literal, Optional

from pydantic import BaseModel, Field

from app.services.agent.skill_service import SkillService

from .base import AgentTool, ToolResult

DEFAULT_SKILL_REF = "code-audit-finding"
DEFAULT_READ_EXAMPLES = [
    "references/core/anti_hallucination.md",
    "references/core/false_positive_filter.md",
    "references/checklists/coverage_matrix.md",
]


class SkillBodyInput(BaseModel):
    skill_ref: Optional[str] = Field(
        default=DEFAULT_SKILL_REF,
        description="Skill id, slug, or display name. Defaults to the bundled code-audit-finding skill.",
    )


class SkillResourceInput(BaseModel):
    skill_ref: Optional[str] = Field(
        default=DEFAULT_SKILL_REF,
        description="Skill id, slug, or display name. Defaults to the bundled code-audit-finding skill.",
    )
    resource_name: Optional[str | List[str]] = Field(
        default=None,
        description="Relative path under references/examples/scripts. May be a single path or a small list of concrete file paths.",
    )
    mode: Literal["read", "list"] = Field(
        default="read",
        description="Use 'list' to inspect available files/directories before reading a specific file.",
    )


class SkillBodyTool(AgentTool):
    def __init__(self, user_id: str | None = None, agent_type: str | None = None):
        super().__init__()
        self.user_id = user_id
        self.agent_type = agent_type

    @property
    def name(self) -> str:
        return "load_skill_body"

    @property
    def description(self) -> str:
        return (
            "从本地 skill_library 文件夹加载某个技能的完整 SKILL.md 正文。"
            "在查看技能元数据并确认需要完整说明后使用。"
        )

    @property
    def args_schema(self):
        return SkillBodyInput

    def is_read_only(self, **kwargs) -> bool:
        del kwargs
        return True

    async def _execute(self, skill_ref: Optional[str] = None, **kwargs) -> ToolResult:
        try:
            resolved_skill_ref = skill_ref or DEFAULT_SKILL_REF
            if self.agent_type is None:
                body = await SkillService.get_skill_body(self.user_id, resolved_skill_ref)
            else:
                body = await SkillService.get_skill_body(
                    self.user_id,
                    resolved_skill_ref,
                    agent_type=self.agent_type,
                )
            return ToolResult(success=True, data=body, metadata={"layer": "body"})
        except Exception as exc:  # noqa: BLE001
            return ToolResult(success=False, error=str(exc))


class SkillResourceTool(AgentTool):
    def __init__(self, user_id: str | None = None, agent_type: str | None = None):
        super().__init__()
        self.user_id = user_id
        self.agent_type = agent_type

    @property
    def name(self) -> str:
        return "skill_resource_lookup"

    @property
    def description(self) -> str:
        return (
            "查看或读取 skill_library 中某个技能 references/examples/scripts 目录下的文件。"
            "先用 mode='list' 查看可用目录或文件，再用 mode='read' 打开具体文件。"
        )

    @property
    def args_schema(self):
        return SkillResourceInput

    def is_read_only(self, **kwargs) -> bool:
        del kwargs
        return True

    async def _execute(
        self,
        skill_ref: Optional[str] = None,
        resource_name: Optional[str | List[str]] = None,
        mode: str = "read",
        **kwargs,
    ) -> ToolResult:
        try:
            resolved_skill_ref = skill_ref or DEFAULT_SKILL_REF
            normalized_list = self._normalize_resource_names(resource_name)
            normalized_resource = normalized_list[0] if normalized_list else ""
            if mode == "list":
                if self.agent_type is None:
                    resource = await SkillService.list_skill_resources(self.user_id, resolved_skill_ref, normalized_resource)
                else:
                    resource = await SkillService.list_skill_resources(
                        self.user_id,
                        resolved_skill_ref,
                        normalized_resource,
                        agent_type=self.agent_type,
                    )
                resource = self._augment_listing(resource)
                return ToolResult(success=True, data=resource, metadata={"layer": "extension", "mode": "list"})

            if not normalized_resource:
                if self.agent_type is None:
                    resource = await SkillService.list_skill_resources(self.user_id, resolved_skill_ref, "")
                else:
                    resource = await SkillService.list_skill_resources(
                        self.user_id,
                        resolved_skill_ref,
                        "",
                        agent_type=self.agent_type,
                    )
                resource = self._augment_listing(resource)
                return ToolResult(
                    success=True,
                    data=resource,
                    metadata={
                        "layer": "extension",
                        "mode": "list",
                        "auto_fallback": "missing_resource_name",
                    },
                )

            if len(normalized_list) > 1:
                resources = []
                for item in normalized_list[:8]:
                    if self.agent_type is None:
                        resources.append(await SkillService.get_skill_resource(self.user_id, resolved_skill_ref, item))
                    else:
                        resources.append(
                            await SkillService.get_skill_resource(
                                self.user_id,
                                resolved_skill_ref,
                                item,
                                agent_type=self.agent_type,
                            )
                        )
                return ToolResult(
                    success=True,
                    data={
                        "skill": resolved_skill_ref,
                        "mode": "batch_read",
                        "resources": resources,
                    },
                    metadata={"layer": "extension", "mode": "batch_read", "resource_count": len(resources)},
                )

            if self.agent_type is None:
                resource = await SkillService.get_skill_resource(self.user_id, resolved_skill_ref, normalized_resource)
            else:
                resource = await SkillService.get_skill_resource(
                    self.user_id,
                    resolved_skill_ref,
                    normalized_resource,
                    agent_type=self.agent_type,
                )
            return ToolResult(success=True, data=resource, metadata={"layer": "extension", "mode": "read"})
        except Exception as exc:  # noqa: BLE001
            return ToolResult(success=False, error=str(exc))

    @staticmethod
    def _normalize_resource_names(resource_name: Optional[str | List[str]]) -> List[str]:
        if resource_name is None:
            return []
        if isinstance(resource_name, list):
            values = resource_name
        else:
            values = [part for part in str(resource_name).split(",")]
        normalized = []
        for value in values:
            item = str(value or "").replace("\\", "/").strip().strip("/")
            if item:
                normalized.append(item)
        return normalized

    @staticmethod
    def _augment_listing(resource: dict) -> dict:
        items = resource.get("items", []) if isinstance(resource, dict) else []
        example_read_paths = [
            item.get("path")
            for item in items
            if isinstance(item, dict) and item.get("type") == "file" and item.get("path")
        ][:3]
        if not example_read_paths:
            example_read_paths = DEFAULT_READ_EXAMPLES

        enriched = dict(resource)
        enriched.setdefault(
            "next_step",
            "Choose one file path from items and call skill_resource_lookup again with mode='read'.",
        )
        enriched.setdefault("example_read_paths", example_read_paths)
        return enriched
