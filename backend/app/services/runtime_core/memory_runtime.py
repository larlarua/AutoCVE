from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from sqlalchemy import select

from app.models.audit_rule import AuditRule, AuditRuleSet
from app.models.audit_session import AuditMemoryKind
from app.services.agent.agents.finding_skill_router import resolve_finding_skill_routes
from app.services.finding_runtime.models import RuntimeMemoryBundle, RuntimeMemoryRecord
from app.services.skill_file_service import SkillFileService

MAX_RECALLS = 5
MAX_CONTENT_CHARS = 3200
PROJECT_MEMORY_LIMIT = 8
RUNTIME_MEMORY_HEADER = "## Runtime Memory OS"
RUNTIME_RULE_SET_ALLOWLIST = {"owasp top 10"}
PROJECT_MEMORY_FILES = ("CLAUDE.md", "CLAW.md", "CLAUDE.local.md", "CLAW.local.md")
PROJECT_MEMORY_DIRS = ((".claude", "CLAUDE.md"), (".claw", "CLAW.md"))
PROJECT_RULE_DIRS = ((".claude", "rules"), (".claw", "rules"))
STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "in", "is", "it", "of", "on",
    "or", "that", "the", "to", "with", "this", "these", "those", "into", "out", "api", "code", "repo", "project",
}


@dataclass(slots=True)
class MemoryCandidate:
    path: Path
    relative_ref: str
    category: str
    bonus: int


class RuntimeMemoryManager:
    def __init__(self, *, session_factory=None, skill_file_service: type[SkillFileService] = SkillFileService):
        self._session_factory = session_factory
        self._skill_file_service = skill_file_service

    async def preload(
        self,
        *,
        agent_type: str,
        system_prompt: str,
        recon_payload: dict[str, Any],
        user_message: str,
        skill_context: dict[str, Any] | None = None,
    ) -> RuntimeMemoryBundle:
        instructions = self._load_instruction_memories(system_prompt=system_prompt)
        instructions.extend(self._load_project_instruction_memories(recon_payload=recon_payload, system_prompt=system_prompt))

        recalls: list[RuntimeMemoryRecord] = []
        if agent_type == "finding":
            context = {
                "recon_data": recon_payload,
                "project_info": recon_payload.get("project_info", {}),
                "task": user_message,
                "config": {},
            }
            route = resolve_finding_skill_routes(context, skill_context)
            recalls = self._load_recalled_memories(
                recon_payload=recon_payload,
                user_message=user_message,
                route=route,
            )
        return RuntimeMemoryBundle(instructions=instructions, recalls=recalls)

    def _load_instruction_memories(self, *, system_prompt: str) -> list[RuntimeMemoryRecord]:
        memories: list[RuntimeMemoryRecord] = []
        if not self._session_factory:
            return memories

        with self._session_factory() as db:
            rule_sets = list(
                db.scalars(
                    select(AuditRuleSet)
                    .where(AuditRuleSet.is_active.is_(True))
                    .where((AuditRuleSet.is_system.is_(True)) | (AuditRuleSet.is_default.is_(True)))
                    .order_by(AuditRuleSet.sort_order, AuditRuleSet.created_at)
                )
            )
            for rule_set in rule_sets:
                if not _is_runtime_rule_set_allowed(rule_set):
                    continue
                rules = list(
                    db.scalars(
                        select(AuditRule)
                        .where(AuditRule.rule_set_id == rule_set.id)
                        .where(AuditRule.enabled.is_(True))
                        .order_by(AuditRule.sort_order, AuditRule.rule_code)
                    )
                )
                if not rules:
                    continue
                lines = []
                if rule_set.description:
                    lines.append(str(rule_set.description).strip())
                for rule in rules[:10]:
                    parts = [f"[{rule.rule_code}] {rule.name}"]
                    if rule.category:
                        parts.append(f"category={rule.category}")
                    if rule.severity:
                        parts.append(f"severity={rule.severity}")
                    lines.append(" | ".join(parts))
                    if rule.description:
                        lines.append(f"Detection: {str(rule.description).strip()}")
                    if rule.custom_prompt:
                        lines.append(f"Guidance: {str(rule.custom_prompt).strip()}")
                    if rule.fix_suggestion:
                        lines.append(f"Remediation focus: {str(rule.fix_suggestion).strip()}")
                    if rule.reference_url:
                        lines.append(f"Reference: {str(rule.reference_url).strip()}")
                    lines.append("")
                content = "\n".join(line for line in lines if line is not None).strip()
                if not content:
                    continue
                memories.append(
                    RuntimeMemoryRecord(
                        memory_kind=AuditMemoryKind.INSTRUCTION.value,
                        title=f"Rule set: {rule_set.name}",
                        source_type="audit_rule_set",
                        source_ref=rule_set.id,
                        content=content[:MAX_CONTENT_CHARS],
                        metadata={
                            "rule_set_name": rule_set.name,
                            "language": rule_set.language,
                            "rule_type": rule_set.rule_type,
                            "rule_count": len(rules),
                            "prompt_digest": len(system_prompt or ""),
                        },
                    )
                )
        return memories

    def _load_project_instruction_memories(self, *, recon_payload: dict[str, Any], system_prompt: str) -> list[RuntimeMemoryRecord]:
        project_root = self._resolve_project_root(recon_payload)
        if project_root is None or not project_root.exists():
            return []

        discovered: list[Path] = []
        seen: set[Path] = set()
        for file_name in PROJECT_MEMORY_FILES:
            candidate = project_root / file_name
            if candidate.exists() and candidate.is_file() and candidate not in seen:
                seen.add(candidate)
                discovered.append(candidate)

        for folder_name, file_name in PROJECT_MEMORY_DIRS:
            candidate = project_root / folder_name / file_name
            if candidate.exists() and candidate.is_file() and candidate not in seen:
                seen.add(candidate)
                discovered.append(candidate)

        for folder_name, rules_dir in PROJECT_RULE_DIRS:
            base = project_root / folder_name / rules_dir
            if not base.exists() or not base.is_dir():
                continue
            for candidate in sorted(base.rglob('*.md')):
                if candidate.is_file() and candidate not in seen:
                    seen.add(candidate)
                    discovered.append(candidate)

        memories: list[RuntimeMemoryRecord] = []
        for candidate in discovered[:PROJECT_MEMORY_LIMIT]:
            content = self._read_project_memory(candidate, project_root, seen_files=set())
            if not content:
                continue
            relative_ref = candidate.relative_to(project_root).as_posix()
            memories.append(
                RuntimeMemoryRecord(
                    memory_kind=AuditMemoryKind.INSTRUCTION.value,
                    title=f"Project memory: {relative_ref}",
                    source_type="project_memory",
                    source_ref=relative_ref,
                    content=content[:MAX_CONTENT_CHARS],
                    metadata={
                        "project_root": str(project_root),
                        "prompt_digest": len(system_prompt or ""),
                    },
                )
            )
        return memories

    def _load_recalled_memories(
        self,
        *,
        recon_payload: dict[str, Any],
        user_message: str,
        route: dict[str, Any],
    ) -> list[RuntimeMemoryRecord]:
        root = self._skill_file_service.library_root() / "code-audit-finding"
        if not root.exists():
            return []

        candidates = self._build_candidates(root=root, route=route)
        query_tokens = self._tokenize(
            user_message,
            recon_payload.get("summary"),
            recon_payload.get("entry_points", []),

            recon_payload.get("priority_paths", []),
            recon_payload.get("project_info", {}),
            recon_payload.get("project_profile", {}),
        )
        ranked: list[tuple[int, str, MemoryCandidate, str]] = []
        for candidate in candidates:
            text = self._read_text(candidate.path)
            if not text:
                continue
            score = self._score_candidate(query_tokens=query_tokens, relative_ref=candidate.relative_ref, text=text, bonus=candidate.bonus)
            ranked.append((score, candidate.relative_ref, candidate, text))

        ranked.sort(key=lambda item: (-item[0], item[1]))
        memories: list[RuntimeMemoryRecord] = []
        for score, _, candidate, text in ranked[:MAX_RECALLS]:
            title = candidate.relative_ref.split("/")[-1]
            memories.append(
                RuntimeMemoryRecord(
                    memory_kind=AuditMemoryKind.RECALL.value,
                    title=title,
                    source_type="skill_reference",
                    source_ref=candidate.relative_ref,
                    content=text[:MAX_CONTENT_CHARS],
                    relevance_score=score,
                    metadata={
                        "category": candidate.category,
                        "path": candidate.relative_ref,
                    },
                )
            )
        return memories

    def _build_candidates(self, *, root: Path, route: dict[str, Any]) -> list[MemoryCandidate]:
        ordered_paths: list[tuple[str, str, int]] = []
        for item in route.get("mandatory_reads", []):
            ordered_paths.append((item, "mandatory", 40))
        for item in route.get("recommended_reads", []):
            ordered_paths.append((item, "recommended", 20))
        for item in route.get("case_candidates", []):
            ordered_paths.append((item, "case", 10))
        for item in route.get("progressive_disclosure", []):
            ordered_paths.append((item, "progressive", 5))

        seen: set[str] = set()
        candidates: list[MemoryCandidate] = []
        for relative_ref, category, bonus in ordered_paths:
            normalized = relative_ref.replace('\\', '/').lstrip('/')
            if normalized in seen:
                continue
            seen.add(normalized)
            path = root / normalized.replace('/', '\\')
            if path.exists() and path.is_file():
                candidates.append(MemoryCandidate(path=path, relative_ref=normalized, category=category, bonus=bonus))
        return candidates

    @staticmethod
    def _resolve_project_root(recon_payload: dict[str, Any]) -> Path | None:
        project_info = recon_payload.get("project_info", {}) or {}
        for key in ("root", "project_root", "workspace_root", "repo_root", "path"):
            value = project_info.get(key) or recon_payload.get(key)
            if not value:
                continue
            try:
                candidate = Path(str(value)).expanduser().resolve(strict=False)
            except OSError:
                continue
            return candidate
        return None

    def _read_project_memory(self, path: Path, project_root: Path, seen_files: set[Path]) -> str:
        resolved = path.resolve(strict=False)
        if resolved in seen_files or not resolved.exists() or not resolved.is_file():
            return ""
        seen_files.add(resolved)
        try:
            raw = resolved.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return ""

        parts: list[str] = []
        in_code_block = False
        for line in raw.splitlines():
            stripped = line.strip()
            if stripped.startswith("```"):
                in_code_block = not in_code_block
                parts.append(line)
                continue
            if not in_code_block and stripped.startswith("@"):
                include_text = stripped[1:].strip()
                include_target = self._resolve_include(project_root, resolved.parent, include_text)
                if include_target is not None:
                    included = self._read_project_memory(include_target, project_root, seen_files)
                    if included:
                        parts.append(f"\n[Included from {include_target.relative_to(project_root).as_posix()}]\n{included}\n")
                continue
            parts.append(line)
        return "\n".join(parts).strip()

    @staticmethod
    def _resolve_include(project_root: Path, base_dir: Path, include_text: str) -> Path | None:
        normalized = str(include_text or "").strip()
        if not normalized or normalized.startswith("~/"):
            return None
        if normalized.startswith("/"):
            candidate = Path(normalized).resolve(strict=False)
        else:
            include_rel = normalized[2:] if normalized.startswith("./") else normalized
            if ".." in PurePosixPath(include_rel.replace('\\', '/')).parts:
                return None
            candidate = (base_dir / include_rel).resolve(strict=False)
        try:
            candidate.relative_to(project_root.resolve(strict=False))
        except ValueError:
            return None
        return candidate

    @staticmethod
    def _read_text(path: Path) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            return ""

    @staticmethod
    def _tokenize(*values: Any) -> set[str]:
        tokens: set[str] = set()
        stack = list(values)
        while stack:
            value = stack.pop()
            if value is None:
                continue
            if isinstance(value, dict):
                stack.extend(value.values())
                continue
            if isinstance(value, (list, tuple, set)):
                stack.extend(value)
                continue
            lowered = str(value).lower()
            for piece in lowered.replace("/", " ").replace("\\", " ").replace("-", " ").replace("_", " ").split():
                token = piece.strip(".,:;()[]{}'\"")
                if token and token not in STOPWORDS:
                    tokens.add(token)
        return tokens

    @classmethod
    def _score_candidate(cls, *, query_tokens: set[str], relative_ref: str, text: str, bonus: int) -> int:
        path_tokens = cls._tokenize(relative_ref)
        sample_tokens = cls._tokenize(text[:4000])
        overlap = len(query_tokens.intersection(path_tokens)) * 8 + len(query_tokens.intersection(sample_tokens))
        return bonus + overlap


def build_memory_message(record: RuntimeMemoryRecord) -> str:
    heading = "指令记忆" if record.memory_kind == AuditMemoryKind.INSTRUCTION.value else "相关召回记忆"
    return "\n".join(
        [
            f"{heading}: {record.title}",
            f"来源：{record.source_type} :: {record.source_ref}",
            "将其作为范围化指南和证据辅助，不要替代项目自身证据。",
            "",
            record.content,
        ]
    ).strip()


def build_runtime_memory_prompt(base_prompt: str, memories: list[RuntimeMemoryRecord] | None) -> str:
    base = strip_runtime_memory_section(base_prompt)
    rendered: list[str] = []
    seen: set[tuple[str, str, str, str]] = set()
    for memory in memories or []:
        key = (
            str(memory.memory_kind or ""),
            str(memory.source_type or ""),
            str(memory.source_ref or ""),
            str(memory.title or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        message = build_memory_message(memory).strip()
        if message:
            rendered.append(message)
    if not rendered:
        return base
    return "\n\n".join(section for section in [base, RUNTIME_MEMORY_HEADER, *rendered] if section)


def strip_runtime_memory_section(prompt: str) -> str:
    text = str(prompt or "").strip()
    marker_index = text.find(RUNTIME_MEMORY_HEADER)
    if marker_index < 0:
        return text
    return text[:marker_index].rstrip()


def _is_runtime_rule_set_allowed(rule_set: AuditRuleSet) -> bool:
    return str(getattr(rule_set, "name", "") or "").strip().lower() in RUNTIME_RULE_SET_ALLOWLIST
