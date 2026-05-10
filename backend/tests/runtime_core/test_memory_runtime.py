from __future__ import annotations

from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.models.audit_rule import AuditRule, AuditRuleSet
from app.models.audit_session import AuditMemoryKind
from app.services.finding_runtime.models import RuntimeMemoryRecord
from app.services.runtime_core.memory_runtime import (
    RUNTIME_MEMORY_HEADER,
    RuntimeMemoryManager,
    build_memory_message,
    build_runtime_memory_prompt,
)


WORKTREE_ROOT = Path(__file__).resolve().parents[3]


def build_session_factory():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_shared_memory_runtime_loads_instruction_and_recalled_memories(monkeypatch):
    monkeypatch.setenv("AUDITAI_ASSET_ROOT", str(WORKTREE_ROOT))
    session_factory = build_session_factory()
    with session_factory() as db:
        rule_set = AuditRuleSet(
            name="OWASP Top 10",
            description="OWASP security rules for finding agent.",
            language="python",
            rule_type="security",
            is_default=True,
            is_system=True,
            is_active=True,
        )
        db.add(rule_set)
        db.flush()
        db.add(
            AuditRule(
                rule_set_id=rule_set.id,
                rule_code="SEC001",
                name="Authorization bypass checks",
                description="Inspect ownership and tenant isolation.",
                category="security",
                severity="high",
                custom_prompt="Trace authz from controller to data access.",
                fix_suggestion="Bind resources to current principal.",
                enabled=True,
            )
        )
        quality_rule_set = AuditRuleSet(
            name="General Quality",
            description="Generic code quality checks.",
            language="python",
            rule_type="quality",
            is_default=True,
            is_system=True,
            is_active=True,
        )
        db.add(quality_rule_set)
        db.flush()
        db.add(
            AuditRule(
                rule_set_id=quality_rule_set.id,
                rule_code="QUAL001",
                name="Style check",
                description="Check generic maintainability issues.",
                category="quality",
                severity="medium",
                enabled=True,
            )
        )
        db.commit()

    manager = RuntimeMemoryManager(session_factory=session_factory)
    bundle = __import__("asyncio").run(
        manager.preload(
            agent_type="finding",
            system_prompt="Keep this prompt stable.",
            recon_payload={
                "summary": "FastAPI auth endpoints with tenant logic.",
                "project_info": {"languages": ["python"], "frameworks": ["fastapi"]},
                "project_profile": {"languages": ["python"], "frameworks": ["fastapi"]},
                "target_vulnerabilities": ["idor", "authorization"],
                "entry_points": ["/api/admin/users"],
            },
            user_message="Audit the FastAPI authorization flow for IDOR and auth bypass.",
            skill_context={"route_plan": {"primary_skill": "code-audit-finding"}},
        )
    )

    assert len(bundle.instructions) == 1
    assert bundle.instructions[0].memory_kind == AuditMemoryKind.INSTRUCTION.value
    assert bundle.instructions[0].title == "Rule set: OWASP Top 10"
    assert "SEC001" in bundle.instructions[0].content
    assert "QUAL001" not in bundle.instructions[0].content
    assert bundle.recalls
    assert any(item.source_ref.endswith("references/languages/python.md") for item in bundle.recalls)
    rendered = build_memory_message(bundle.recalls[0])
    assert bundle.recalls[0].title in rendered
    assert bundle.recalls[0].source_ref in rendered


def test_shared_memory_runtime_loads_project_memories(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITAI_ASSET_ROOT", str(WORKTREE_ROOT))
    (tmp_path / "CLAUDE.md").write_text("Project rule: focus auth flows.\n@include.md", encoding="utf-8")
    (tmp_path / "include.md").write_text("Included guidance for exploit proof.", encoding="utf-8")
    (tmp_path / ".claw").mkdir()
    (tmp_path / ".claw" / "CLAW.md").write_text("Claw memory: use canonical tools.", encoding="utf-8")

    manager = RuntimeMemoryManager(session_factory=build_session_factory())
    bundle = __import__("asyncio").run(
        manager.preload(
            agent_type="finding",
            system_prompt="Stay aligned.",
            recon_payload={
                "project_info": {"root": str(tmp_path), "languages": ["java"]},
                "summary": "Spring Boot controllers and serializers.",
                "target_vulnerabilities": ["deserialization"],
            },
            user_message="Audit this project for deserialization issues.",
            skill_context={"route_plan": {"primary_skill": "code-audit-finding"}},
        )
    )

    project_memories = [item for item in bundle.instructions if item.source_type == "project_memory"]

    assert project_memories
    assert any(item.source_ref == "CLAUDE.md" for item in project_memories)
    assert any(item.source_ref == ".claw/CLAW.md" for item in project_memories)
    assert any("Included guidance" in item.content for item in project_memories if item.source_ref == "CLAUDE.md")


def test_shared_memory_runtime_only_loads_owasp_instruction_memories_for_non_finding_agents(monkeypatch):
    monkeypatch.setenv("AUDITAI_ASSET_ROOT", str(WORKTREE_ROOT))
    session_factory = build_session_factory()
    with session_factory() as db:
        rule_set = AuditRuleSet(
            name="OWASP Top 10",
            description="Shared security rules for all agents.",
            language="python",
            rule_type="security",
            is_default=True,
            is_system=True,
            is_active=True,
        )
        db.add(rule_set)
        db.flush()
        db.add(
            AuditRule(
                rule_set_id=rule_set.id,
                rule_code="GEN001",
                name="Trace trust boundaries",
                description="Map external input to sensitive operations.",
                category="security",
                severity="medium",
                enabled=True,
            )
        )
        db.commit()

    manager = RuntimeMemoryManager(session_factory=session_factory)
    bundle = __import__("asyncio").run(
        manager.preload(
            agent_type="analysis",
            system_prompt="Analyze the codebase carefully.",
            recon_payload={
                "project_info": {"languages": ["python"], "frameworks": ["fastapi"]},
                "summary": "FastAPI API with auth decorators.",
            },
            user_message="Analyze request handling boundaries.",
            skill_context=None,
        )
    )

    assert bundle.instructions
    assert bundle.instructions[0].memory_kind == AuditMemoryKind.INSTRUCTION.value
    assert "GEN001" in bundle.instructions[0].content
    assert bundle.recalls == []


def test_shared_memory_runtime_ignores_quality_and_performance_rule_sets(monkeypatch):
    monkeypatch.setenv("AUDITAI_ASSET_ROOT", str(WORKTREE_ROOT))
    session_factory = build_session_factory()
    with session_factory() as db:
        for name, rule_type, rule_code in [
            ("General Quality", "quality", "QUAL001"),
            ("Performance Checks", "performance", "PERF005"),
        ]:
            rule_set = AuditRuleSet(
                name=name,
                description=f"{name} rules.",
                language="python",
                rule_type=rule_type,
                is_default=True,
                is_system=True,
                is_active=True,
            )
            db.add(rule_set)
            db.flush()
            db.add(
                AuditRule(
                    rule_set_id=rule_set.id,
                    rule_code=rule_code,
                    name="Ignored rule",
                    description="This rule should not enter Runtime Memory OS.",
                    category=rule_type,
                    severity="medium",
                    enabled=True,
                )
            )
        db.commit()

    manager = RuntimeMemoryManager(session_factory=session_factory)
    bundle = __import__("asyncio").run(
        manager.preload(
            agent_type="finding",
            system_prompt="Find CVE-grade security issues.",
            recon_payload={"project_info": {"languages": ["python"]}},
            user_message="Audit the project.",
            skill_context={"route_plan": {"primary_skill": "code-audit-finding"}},
        )
    )

    assert bundle.instructions == []


def test_build_runtime_memory_prompt_strips_existing_memory_section():
    memory = RuntimeMemoryRecord(
        memory_kind=AuditMemoryKind.INSTRUCTION.value,
        title="Rule set: OWASP Top 10",
        source_type="audit_rule_set",
        source_ref="owasp-id",
        content="[SEC001] Authorization bypass checks",
    )
    base_prompt = "\n\n".join(
        [
            "Base prompt.",
            RUNTIME_MEMORY_HEADER,
            "stale duplicated memory",
        ]
    )

    rendered = build_runtime_memory_prompt(base_prompt, [memory, memory])

    assert rendered.count(RUNTIME_MEMORY_HEADER) == 1
    assert "stale duplicated memory" not in rendered
    assert rendered.count("[SEC001]") == 1
