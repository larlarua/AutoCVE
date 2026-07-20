from __future__ import annotations

from app.models.audit_session import AuditSessionMessage
from app.services.finding_runtime.models import RuntimeMessageRole, TranscriptItem
from app.services.finding_runtime.query_transitions import (
    PERSISTED_MESSAGE_ID_KEY,
    PERSISTED_MESSAGE_SEQUENCE_KEY,
)


def render_audit_record_context(messages: list[AuditSessionMessage], *, max_messages: int = 120) -> str:
    if not messages:
        return "当前审计会话没有可用的历史审计记录。"

    selected = list(messages)
    if len(selected) > max_messages:
        selected = [selected[0], *selected[-(max_messages - 1) :]]

    lines: list[str] = [
        "Audit record context:",
        "以下内容是此前审计过程的记录摘要/摘录。它们是本轮会话的上文和证据基础，不是固定流程继续执行指令。",
        "",
    ]
    omitted = len(messages) - len(selected)
    if omitted > 0:
        lines.append(f"已省略 {omitted} 条更早的审计记录，仅保留首条和最近 {len(selected) - 1} 条。")
        lines.append("")

    for message in selected:
        role = str(getattr(message, "role", "") or "unknown").upper()
        name = str(getattr(message, "name", "") or "").strip()
        sequence = getattr(message, "sequence", None)
        header = f"[{role}{' ' + name if name else ''}{' #' + str(sequence) if sequence is not None else ''}]"
        content = str(getattr(message, "content", "") or "").strip() or "(empty)"
        lines.append(header)
        lines.append(content[:6000])
        lines.append("")

    return "\n".join(lines).strip()


def transcript_from_db_messages(messages: list[AuditSessionMessage]) -> list[TranscriptItem]:
    transcript: list[TranscriptItem] = []
    for message in messages:
        role = _coerce_runtime_role(str(message.role or "user"))
        transcript.append(
            TranscriptItem(
                role=role,
                content=message.content or "",
                name=message.name,
                metadata={
                    **dict(message.message_metadata or {}),
                    PERSISTED_MESSAGE_ID_KEY: str(message.id),
                    PERSISTED_MESSAGE_SEQUENCE_KEY: int(message.sequence),
                },
                payload=dict(message.payload or {}),
            )
        )
    return transcript


def selected_skill_refs_from_message(message: AuditSessionMessage | None) -> list[str]:
    if message is None:
        return []
    refs: list[str] = []
    for container in (getattr(message, "message_metadata", None), getattr(message, "payload", None)):
        if not isinstance(container, dict):
            continue
        raw = container.get("selected_skill_refs")
        if isinstance(raw, list):
            for item in raw:
                ref = str(item or "").strip()
                if ref and ref not in refs:
                    refs.append(ref)
    return refs


def _coerce_runtime_role(role: str) -> RuntimeMessageRole:
    try:
        return RuntimeMessageRole(role)
    except ValueError:
        return RuntimeMessageRole.USER
