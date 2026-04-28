from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import deps
from app.api.v1.endpoints import audit_sessions as audit_sessions_endpoint
from app.api.v1.endpoints.audit_sessions import router as audit_sessions_router
from app.db.base import Base
from app.models.audit_session import AuditHandoff, AuditMemory, AuditSession, AuditSessionMessage, AuditSkill, AuditSkillInvocation, AuditToolCall


def build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(audit_sessions_router, prefix="/api/v1/audit-sessions")
    return app


@pytest.mark.asyncio
async def test_get_audit_session_detail_messages_tool_calls_skills_and_memories():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        session = AuditSession(
            project_id="project-1",
            task_id="task-1",
            runtime_stack="runtime",
            state="pending",
            system_prompt="prompt",
            recon_payload={"repo": "demo"},
        )
        db.add(session)
        await db.flush()
        db.add(
            AuditSessionMessage(
                session_id=session.id,
                sequence=1,
                role="user",
                content="inspect the repo",
                message_metadata={},
                payload={},
            )
        )
        db.add(
            AuditToolCall(
                session_id=session.id,
                turn_id="turn-1",
                sequence=1,
                tool_use_id="tool-1",
                tool_name="echo",
                status="completed",
                is_concurrency_safe=True,
                input_payload={"text": "demo"},
                output_payload={"echo": "demo"},
                duration_ms=7,
                started_at=datetime.now(timezone.utc),
                completed_at=datetime.now(timezone.utc),
            )
        )
        db.add(
            AuditSkill(
                session_id=session.id,
                skill_ref="code-audit-finding",
                name="Code Audit Finding",
                description="primary skill",
                source_type="bundled",
                enabled=True,
                matched=True,
                skill_metadata={"slug": "code-audit-finding"},
            )
        )
        db.add(
            AuditSkillInvocation(
                session_id=session.id,
                turn_id="turn-1",
                sequence=1,
                skill_ref="code-audit-finding",
                status="completed",
                input_payload={"action": "body"},
                output_payload={"content": "body"},
            )
        )
        db.add(
            AuditMemory(
                session_id=session.id,
                sequence=1,
                memory_kind="instruction",
                title="Rule set: baseline",
                source_type="audit_rule_set",
                source_ref="ruleset-1",
                content="Always verify authz.",
                metadata_json={"rule_count": 1},
            )
        )
        await db.commit()
        session_id = session.id

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        detail = await client.get(f"/api/v1/audit-sessions/{session_id}")
        messages = await client.get(f"/api/v1/audit-sessions/{session_id}/messages")
        tool_calls = await client.get(f"/api/v1/audit-sessions/{session_id}/tool-calls")
        skills = await client.get(f"/api/v1/audit-sessions/{session_id}/skills")
        skill_invocations = await client.get(f"/api/v1/audit-sessions/{session_id}/skill-invocations")
        memories = await client.get(f"/api/v1/audit-sessions/{session_id}/memories")

    await engine.dispose()

    assert detail.status_code == 200
    assert detail.json()["id"] == session_id
    assert detail.json()["runtime_stack"] == "runtime"
    assert len(messages.json()) == 1
    assert len(tool_calls.json()) == 1
    assert tool_calls.json()[0]["tool_name"] == "echo"
    assert len(skills.json()) == 1
    assert skills.json()[0]["skill_ref"] == "code-audit-finding"
    assert len(skill_invocations.json()) == 1
    assert skill_invocations.json()[0]["skill_ref"] == "code-audit-finding"
    assert len(memories.json()) == 1
    assert memories.json()[0]["memory_kind"] == "instruction"


@pytest.mark.asyncio
async def test_post_follow_up_message_appends_to_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        session = AuditSession(
            project_id="project-1",
            task_id="task-1",
            runtime_stack="runtime",
            state="completed",
        )
        db.add(session)
        await db.commit()
        session_id = session.id

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            f"/api/v1/audit-sessions/{session_id}/messages",
            json={"content": "show me the exploit details"},
        )
        messages = await client.get(f"/api/v1/audit-sessions/{session_id}/messages")

    await engine.dispose()

    assert response.status_code == 200
    assert response.json()["role"] == "user"
    assert response.json()["content"] == "show me the exploit details"
    assert len(messages.json()) == 1
    assert messages.json()[0]["sequence"] == 1


@pytest.mark.asyncio
async def test_get_audit_session_handoffs():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        session = AuditSession(
            project_id="project-1",
            task_id="task-1",
            runtime_stack="runtime",
            state="completed",
        )
        db.add(session)
        await db.flush()
        db.add(
            AuditHandoff(
                session_id=session.id,
                target="verification",
                status="pending",
                payload={"from_agent": "finding", "to_agent": "verification", "summary": "verify exploit"},
            )
        )
        await db.commit()
        session_id = session.id

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        handoffs = await client.get(f"/api/v1/audit-sessions/{session_id}/handoffs")

    await engine.dispose()

    assert handoffs.status_code == 200
    assert len(handoffs.json()) == 1
    assert handoffs.json()[0]["target"] == "verification"


@pytest.mark.asyncio
async def test_post_follow_up_message_continues_runtime_session(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        session = AuditSession(
            project_id="project-1",
            task_id="task-1",
            runtime_stack="runtime",
            state="completed",
        )
        db.add(session)
        await db.commit()
        session_id = session.id

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    async def fake_continue_runtime_session(*, session_id: str, content: str, db):
        db.add(
            AuditSessionMessage(
                session_id=session_id,
                sequence=2,
                role="assistant",
                content="Exploit chain continues here.",
                message_metadata={"kind": "follow_up_response"},
                payload={"continued": True},
            )
        )
        await db.commit()

    monkeypatch.setattr(audit_sessions_endpoint, "continue_runtime_session", fake_continue_runtime_session, raising=False)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            f"/api/v1/audit-sessions/{session_id}/messages",
            json={"content": "show me the exploit details"},
        )
        messages = await client.get(f"/api/v1/audit-sessions/{session_id}/messages")

    await engine.dispose()

    assert response.status_code == 200
    assert response.json()["mode"] == "chat"
    assert len(messages.json()) == 2
    assert messages.json()[0]["role"] == "user"
    assert messages.json()[1]["role"] == "assistant"
    assert messages.json()[1]["payload"]["continued"] is True


@pytest.mark.asyncio
async def test_post_follow_up_message_can_generate_report_and_sync(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        session = AuditSession(
            project_id="project-1",
            task_id="task-1",
            runtime_stack="runtime",
            state="completed",
        )
        db.add(session)
        await db.commit()
        session_id = session.id

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    continue_called = False

    async def fake_continue_runtime_session(*, session_id: str, content: str, db):
        nonlocal continue_called
        continue_called = True

    async def fake_generate_and_sync(*, session, db):
        return {
            "id": "managed-1",
            "project_id": session.project_id,
            "task_id": session.task_id,
            "finding_id": "finding-1",
            "project_name": "Demo Project",
            "version_label": "main",
            "version_tag": None,
            "branch_name": "main",
            "commit_sha": None,
            "repository_url_snapshot": None,
            "vulnerability_name": "SSRF in report generator",
            "vulnerability_type": "ssrf",
            "severity": "high",
            "file_path": "app/services/report.py",
            "line_start": 42,
            "line_end": 57,
            "human_review_result": "pending",
            "cve_request_status": "not_requested",
            "cve_failure_reason": None,
            "cve_id": None,
            "report_generation_status": "completed",
            "source_finding_fingerprint": None,
            "source_metadata": {},
            "reports": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": None,
        }

    monkeypatch.setattr(audit_sessions_endpoint, "continue_runtime_session", fake_continue_runtime_session, raising=False)
    monkeypatch.setattr(
        audit_sessions_endpoint,
        "_generate_and_sync_follow_up_managed_vulnerability",
        fake_generate_and_sync,
        raising=False,
    )

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            f"/api/v1/audit-sessions/{session_id}/messages",
            json={"content": "please turn the latest finding into a managed report", "mode": "generate_report_and_sync"},
        )

    await engine.dispose()

    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "generate_report_and_sync"
    assert body["synced_managed_vulnerability"]["id"] == "managed-1"
    assert body["synced_managed_vulnerability"]["report_generation_status"] == "completed"
    assert continue_called is False


@pytest.mark.asyncio
async def test_stream_follow_up_message_for_runtime_session_uses_runtime_continuation(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        session = AuditSession(
            project_id="project-1",
            task_id="task-1",
            runtime_stack="runtime",
            state="completed",
        )
        db.add(session)
        await db.commit()
        session_id = session.id

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    continuation_calls: list[tuple[str, str]] = []

    async def fake_continue_runtime_session(*, session_id: str, content: str, db):
        continuation_calls.append((session_id, content))
        db.add(
            AuditSessionMessage(
                session_id=session_id,
                sequence=2,
                role="assistant",
                content="Runtime loop persisted the real follow-up response.",
                message_metadata={"kind": "runtime_follow_up_response"},
                payload={"continued": True},
            )
        )
        await db.commit()

    async def fail_build_follow_up_llm_service(*, session, db):
        raise AssertionError("streaming follow-up path should not build a direct LLM follow-up service for runtime sessions")

    monkeypatch.setattr(audit_sessions_endpoint, "continue_runtime_session", fake_continue_runtime_session, raising=False)
    monkeypatch.setattr(audit_sessions_endpoint, "_build_follow_up_llm_service", fail_build_follow_up_llm_service, raising=False)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            f"/api/v1/audit-sessions/{session_id}/messages/stream",
            json={"content": "please continue the audit"},
            headers={"Accept": "text/event-stream"},
        )
        messages = await client.get(f"/api/v1/audit-sessions/{session_id}/messages")

    await engine.dispose()

    assert response.status_code == 200
    assert continuation_calls == [(session_id, "please continue the audit")]
    assert '"type": "user_message"' in response.text
    assert '"type": "done"' in response.text
    assert len(messages.json()) == 2
    assert messages.json()[0]["metadata"]["kind"] == "follow_up_user_message"
    assert messages.json()[1]["metadata"]["kind"] == "runtime_follow_up_response"


@pytest.mark.asyncio
async def test_stream_follow_up_message_can_generate_report_and_sync(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        session = AuditSession(
            project_id="project-1",
            task_id="task-1",
            runtime_stack="runtime",
            state="completed",
        )
        db.add(session)
        await db.commit()
        session_id = session.id

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    continue_called = False

    async def fake_continue_runtime_session(*, session_id: str, content: str, db):
        nonlocal continue_called
        continue_called = True

    async def fake_generate_and_sync(*, session, db):
        return {
            "id": "managed-2",
            "project_id": session.project_id,
            "task_id": session.task_id,
            "finding_id": "finding-2",
            "project_name": "Demo Project",
            "version_label": "main",
            "version_tag": None,
            "branch_name": "main",
            "commit_sha": None,
            "repository_url_snapshot": None,
            "vulnerability_name": "SQL injection",
            "vulnerability_type": "sql_injection",
            "severity": "critical",
            "file_path": "app/api/users.py",
            "line_start": 88,
            "line_end": 102,
            "human_review_result": "pending",
            "cve_request_status": "not_requested",
            "cve_failure_reason": None,
            "cve_id": None,
            "report_generation_status": "completed",
            "source_finding_fingerprint": None,
            "source_metadata": {},
            "reports": [],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": None,
        }

    monkeypatch.setattr(audit_sessions_endpoint, "continue_runtime_session", fake_continue_runtime_session, raising=False)
    monkeypatch.setattr(
        audit_sessions_endpoint,
        "_generate_and_sync_follow_up_managed_vulnerability",
        fake_generate_and_sync,
        raising=False,
    )

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            f"/api/v1/audit-sessions/{session_id}/messages/stream",
            json={"content": "sync the latest finding into vulnerability management", "mode": "generate_report_and_sync"},
            headers={"Accept": "text/event-stream"},
        )

    await engine.dispose()

    assert response.status_code == 200
    assert '"type": "done"' in response.text
    assert '"synced_managed_vulnerability"' in response.text
    assert '"id": "managed-2"' in response.text
    assert continue_called is False


@pytest.mark.asyncio
async def test_stream_follow_up_message_surfaces_generate_report_error(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        session = AuditSession(
            project_id="project-1",
            task_id="task-1",
            runtime_stack="runtime",
            state="completed",
        )
        db.add(session)
        await db.commit()
        session_id = session.id

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    async def fake_generate_and_sync(*, session, db):
        del session, db
        raise ValueError("No non-false-positive findings are available for report sync yet.")

    monkeypatch.setattr(
        audit_sessions_endpoint,
        "_generate_and_sync_follow_up_managed_vulnerability",
        fake_generate_and_sync,
        raising=False,
    )

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.post(
            f"/api/v1/audit-sessions/{session_id}/messages/stream",
            json={"content": "regenerate report", "mode": "generate_report_and_sync"},
            headers={"Accept": "text/event-stream"},
        )

    await engine.dispose()

    assert response.status_code == 200
    assert '"type": "error"' in response.text
    assert '"message_text": "No non-false-positive findings are available for report sync yet."' in response.text


@pytest.mark.asyncio
async def test_continue_runtime_session_uses_dialogue_continuation(monkeypatch):
    session = AuditSession(
        project_id="project-1",
        task_id="task-1",
        runtime_stack="runtime",
        state="completed",
    )

    class DummySandbox:
        def __init__(self):
            self.cleaned = False

        async def cleanup(self):
            self.cleaned = True

    class DummyBridge:
        def __init__(self):
            self.dialogue_calls: list[tuple[str, str, int | None]] = []
            self.report_calls: list[tuple[str, str, int | None]] = []

        async def continue_dialogue_session(self, *, session_id: str, model_name: str, max_turns: int | None):
            self.dialogue_calls.append((session_id, model_name, max_turns))

        async def continue_session(self, *, session_id: str, model_name: str, max_turns: int | None):
            self.report_calls.append((session_id, model_name, max_turns))
            raise AssertionError('audit session follow-up should not use final-report continuation')

    bridge = DummyBridge()
    sandbox = DummySandbox()

    class DummyDb:
        async def get(self, model, session_id):
            return session

    async def fake_build_runtime_follow_up_context(*, session, db):
        return bridge, sandbox, 'finding-runtime', None

    monkeypatch.setattr(audit_sessions_endpoint, '_build_runtime_follow_up_context', fake_build_runtime_follow_up_context, raising=False)

    await audit_sessions_endpoint.continue_runtime_session(
        session_id='session-1',
        content='please keep auditing',
        db=DummyDb(),
    )

    assert bridge.dialogue_calls == [('session-1', 'finding-runtime', None)]
    assert bridge.report_calls == []
    assert sandbox.cleaned is True
