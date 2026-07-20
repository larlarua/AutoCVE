from __future__ import annotations

from typing import Any

from app.services.agent.skill_service import SkillService
from app.services.audit_chat_runtime.context import (
    render_audit_record_context,
    selected_skill_refs_from_message,
    transcript_from_db_messages,
)
from app.services.audit_chat_runtime.prompts import AUDIT_CHAT_SYSTEM_PROMPT
from app.services.finding_runtime.query_transitions import (
    refresh_query_loop_state_from_persisted_messages,
    restore_compacted_query_loop_state_from_checkpoints,
)
from app.services.finding_runtime.skills import RuntimeSkillCatalog
from app.services.runtime_core.explicit_skill_loader import load_explicit_skill_injections
from app.services.runtime_core.memory_runtime import RuntimeMemoryManager, build_runtime_memory_prompt
from app.services.runtime_core.skill_discovery import SkillDiscoveryScheduler
from app.services.runtime_core.skill_mentions import collect_explicit_skill_mentions


class AuditChatRuntimeAdapter:
    def __init__(
        self,
        *,
        session_store,
        runner,
        skill_catalog: RuntimeSkillCatalog | None = None,
        memory_manager: RuntimeMemoryManager | None = None,
        discovery_scheduler: SkillDiscoveryScheduler | None = None,
        skill_service: Any = SkillService,
    ):
        self._session_store = session_store
        self._runner = runner
        self._skill_catalog = skill_catalog or RuntimeSkillCatalog()
        self._memory_manager = memory_manager or RuntimeMemoryManager(
            session_factory=getattr(session_store, "_session_factory", None)
        )
        self._discovery_scheduler = discovery_scheduler or SkillDiscoveryScheduler()
        self._skill_service = skill_service

    async def refresh_session_context(self, *, session_id: str) -> dict[str, Any]:
        snapshot = self._session_store.load_session_snapshot(session_id)
        runtime_state = self._session_store.load_runtime_state(session_id)
        query_loop_state = self._session_store.load_query_loop_state(session_id)
        query_loop_state = restore_compacted_query_loop_state_from_checkpoints(
            query_loop_state,
            checkpoints=list(snapshot.checkpoints or []),
        )
        latest_user_message = self._latest_user_message(snapshot.messages)
        latest_user_text = str(getattr(latest_user_message, "content", "") or "").strip()

        skill_context = await self._skill_catalog.preload(
            user_id=None,
            agent_type="audit_chat",
            context={
                "task": latest_user_text,
                "config": {},
            },
        )
        discovery_snapshot = self._discovery_scheduler.discover(
            agent_type="audit_chat",
            runtime_state=runtime_state,
            available_skills=skill_context.available_skills,
            matched_skills=skill_context.matched_skills,
            task=latest_user_text,
            latest_user_message=latest_user_text,
            recon_payload={},
        )
        self._session_store.replace_skills(
            session_id,
            skill_context.available_skills,
            matched_skill_refs=self._skill_refs(skill_context.matched_skills),
        )

        explicit_mentions = collect_explicit_skill_mentions(
            mention_sources=[
                ("user", latest_user_text),
                ("ui", self._selected_skill_mention_text(latest_user_message)),
            ],
            available_skills=skill_context.available_skills,
        )
        explicit_skill_injection_text = await load_explicit_skill_injections(
            session_store=self._session_store,
            agent_type="audit_chat",
            session_id=session_id,
            mentions=explicit_mentions,
            skill_service=self._skill_service,
        )

        memories = self._session_store.list_memories(session_id)
        audit_record_context = render_audit_record_context(snapshot.messages)
        system_prompt = self._compose_system_prompt(
            skill_prompt=skill_context.prompt,
            explicit_skill_injection_text=explicit_skill_injection_text,
            memories=memories,
        )
        self._session_store.update_system_prompt(session_id, system_prompt)

        runtime_state.metadata["conversation_mode"] = "audit_chat"
        runtime_state.metadata["base_system_prompt"] = AUDIT_CHAT_SYSTEM_PROMPT
        runtime_state.metadata["last_user_message"] = latest_user_text
        runtime_state.metadata["query_context"] = {
            **dict(runtime_state.metadata.get("query_context") or {}),
            "user_context_prefix": audit_record_context,
        }
        runtime_state.record_skill_catalog_snapshot(
            agent_type="audit_chat",
            available_skills=list(self._skill_refs(skill_context.available_skills)),
            matched_skills=list(self._skill_refs(skill_context.matched_skills)),
            primary_skill=self._selected_skill(discovery_snapshot),
        )
        runtime_state.record_skill_discovery_snapshot(
            agent_type="audit_chat",
            selected_skill=self._selected_skill(discovery_snapshot),
            ranked_candidates=list(discovery_snapshot.get("ranked_candidates") or []),
            latest_user_message=latest_user_text,
        )
        self._session_store.replace_runtime_state(session_id, runtime_state)

        refreshed_transcript = transcript_from_db_messages(snapshot.messages)
        self._session_store.save_query_loop_state(
            session_id,
            refresh_query_loop_state_from_persisted_messages(
                query_loop_state,
                persisted_messages=refreshed_transcript,
            ),
        )
        return {
            "prompt": skill_context.prompt,
            "route_plan": skill_context.route_plan,
            "explicit_skills": [mention.skill_ref for mention in explicit_mentions],
        }

    async def run_once(self, *, session_id: str, model_name: str):
        await self.refresh_session_context(session_id=session_id)
        return await self._runner.run_once(session_id=session_id, model_name=model_name)

    def _compose_system_prompt(
        self,
        *,
        skill_prompt: str,
        explicit_skill_injection_text: str,
        memories: list,
    ) -> str:
        sections = [AUDIT_CHAT_SYSTEM_PROMPT]
        if str(skill_prompt or "").strip():
            sections.append(str(skill_prompt).strip())
        if str(explicit_skill_injection_text or "").strip():
            sections.append(str(explicit_skill_injection_text).strip())
        return build_runtime_memory_prompt("\n\n".join(sections), memories)

    @staticmethod
    def _latest_user_message(messages: list) -> Any | None:
        for message in reversed(messages or []):
            if str(getattr(message, "role", "") or "") == "user":
                return message
        return None

    @staticmethod
    def _selected_skill_mention_text(message: Any | None) -> str:
        return " ".join(f"${ref}" for ref in selected_skill_refs_from_message(message))

    @staticmethod
    def _skill_refs(items: list[dict]) -> set[str]:
        refs: set[str] = set()
        for item in items or []:
            ref = str(item.get("slug") or item.get("id") or item.get("name") or "").strip()
            if ref:
                refs.add(ref)
        return refs

    @staticmethod
    def _selected_skill(discovery_snapshot: dict[str, Any]) -> str | None:
        selected = str(discovery_snapshot.get("selected_skill") or "").strip()
        return selected or None
