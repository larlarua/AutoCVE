from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
import json

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import selectinload

from app.api import deps
import app.api.v1.endpoints.agent_tasks as agent_tasks_endpoint
from app.api.v1.endpoints.agent_tasks import router as agent_tasks_router
from app.db.base import Base
from app.models.agent_task import AgentEvent, AgentEventType, AgentFinding, AgentTask, AgentTaskStatus
from app.models.audit_session import AuditSession, AuditSessionMessage
from app.models.managed_vulnerability import ManagedVulnerability
from app.models.project import Project
from app.models.user import User
from app.services.vulnerability_report_generation import GeneratedReportBundle
import app.services.agent.tools as agent_tools_module
import app.services.rag as rag_module


def build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(agent_tasks_router, prefix='/api/v1/agent-tasks')
    return app


@pytest.mark.asyncio
async def test_create_agent_task_requires_version_label(monkeypatch):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
            repository_url='https://example.com/demo.git',
        )
        db.add_all([user, project])
        await db.commit()

    async def fake_execute_agent_task(task_id: str):
        return None

    monkeypatch.setattr(agent_tasks_endpoint, '_execute_agent_task', fake_execute_agent_task)

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id='user-1', is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://testserver') as client:
        response = await client.post(
            '/api/v1/agent-tasks/',
            json={
                'project_id': 'project-1',
                'name': 'Runtime audit',
            },
        )

    await engine.dispose()

    assert response.status_code == 422
    assert 'version_label' in response.text


@pytest.mark.asyncio
async def test_create_agent_task_persists_version_snapshot(monkeypatch):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
            repository_url='https://example.com/demo.git',
        )
        db.add_all([user, project])
        await db.commit()

    async def fake_execute_agent_task(task_id: str):
        return None

    monkeypatch.setattr(agent_tasks_endpoint, '_execute_agent_task', fake_execute_agent_task)

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id='user-1', is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://testserver') as client:
        response = await client.post(
            '/api/v1/agent-tasks/',
            json={
                'project_id': 'project-1',
                'name': 'Runtime audit',
                'branch_name': 'release/v1',
                'version_label': 'v1.2.3',
            },
        )

    async with session_factory() as db:
        task = await db.get(AgentTask, response.json()['id'])

    await engine.dispose()

    assert response.status_code == 200
    assert task is not None
    assert task.version_label == 'v1.2.3'
    assert task.branch_name == 'release/v1'
    assert task.repository_url_snapshot == 'https://example.com/demo.git'
    assert response.json()['version_label'] == 'v1.2.3'
    assert response.json()['repository_url_snapshot'] == 'https://example.com/demo.git'


@pytest.mark.asyncio
async def test_agent_task_routes_include_runtime_session_id():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
        )
        task = AgentTask(
            id='task-1',
            project_id='project-1',
            created_by='user-1',
            name='Audit demo',
            version_label='runtime-test',
            status=AgentTaskStatus.RUNNING,
            current_phase='analysis',
            created_at=datetime.now(timezone.utc),
        )
        session = AuditSession(
            id='session-1',
            project_id='project-1',
            task_id='task-1',
            runtime_stack='runtime',
            state='running',
        )
        db.add_all([user, project, task, session])
        await db.commit()

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id='user-1', is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://testserver') as client:
        list_response = await client.get('/api/v1/agent-tasks/')
        detail_response = await client.get('/api/v1/agent-tasks/task-1')

    await engine.dispose()

    assert list_response.status_code == 200
    assert list_response.json()[0]['runtime_session_id'] == 'session-1'

    assert detail_response.status_code == 200
    assert detail_response.json()['runtime_session_id'] == 'session-1'


@pytest.mark.asyncio
async def test_create_agent_task_persists_runtime_stack_in_agent_config(monkeypatch):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
        )
        db.add_all([user, project])
        await db.commit()

    async def fake_execute_agent_task(task_id: str):
        return None

    monkeypatch.setattr(agent_tasks_endpoint, '_execute_agent_task', fake_execute_agent_task)

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id='user-1', is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://testserver') as client:
        response = await client.post(
            '/api/v1/agent-tasks/',
            json={
                'project_id': 'project-1',
                'name': 'Runtime audit',
                'version_label': 'runtime-v1',
                'finding_runtime_stack': 'runtime',
            },
        )

    async with session_factory() as db:
        task = await db.get(AgentTask, response.json()['id'])

    await engine.dispose()

    assert response.status_code == 200
    assert task is not None
    assert task.agent_config == {'finding_runtime_stack': 'runtime'}


@pytest.mark.asyncio
async def test_agent_task_routes_include_resolved_runtime_stack():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
        )
        task = AgentTask(
            id='task-1',
            project_id='project-1',
            created_by='user-1',
            name='Audit demo',
            version_label='runtime-test',
            status=AgentTaskStatus.RUNNING,
            current_phase='analysis',
            created_at=datetime.now(timezone.utc),
            agent_config={'finding_runtime_stack': 'runtime'},
        )
        db.add_all([user, project, task])
        await db.commit()

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id='user-1', is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://testserver') as client:
        list_response = await client.get('/api/v1/agent-tasks/')
        detail_response = await client.get('/api/v1/agent-tasks/task-1')

    await engine.dispose()

    assert list_response.status_code == 200
    assert list_response.json()[0]['finding_runtime_stack'] == 'runtime'
    assert detail_response.status_code == 200
    assert detail_response.json()['finding_runtime_stack'] == 'runtime'


@pytest.mark.asyncio
async def test_create_agent_task_uses_default_runtime_stack_from_settings(monkeypatch):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
        )
        db.add_all([user, project])
        await db.commit()

    async def fake_execute_agent_task(task_id: str):
        return None

    monkeypatch.setattr(agent_tasks_endpoint, '_execute_agent_task', fake_execute_agent_task)
    monkeypatch.setattr(agent_tasks_endpoint.settings, 'FINDING_RUNTIME_STACK_DEFAULT', 'runtime', raising=False)

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id='user-1', is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://testserver') as client:
        response = await client.post(
            '/api/v1/agent-tasks/',
            json={
                'project_id': 'project-1',
                'name': 'Default runtime audit',
                'version_label': 'runtime-default',
            },
        )

    async with session_factory() as db:
        task = await db.get(AgentTask, response.json()['id'])

    await engine.dispose()

    assert response.status_code == 200
    assert task is not None
    assert task.agent_config == {'finding_runtime_stack': 'runtime'}


@pytest.mark.asyncio
async def test_agent_task_events_list_returns_history_for_activity_log():
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
        )
        task = AgentTask(
            id='task-1',
            project_id='project-1',
            created_by='user-1',
            name='Audit demo',
            version_label='runtime-test',
            status=AgentTaskStatus.RUNNING,
            current_phase='analysis',
            created_at=datetime.now(timezone.utc),
        )
        event = AgentEvent(
            id='event-1',
            task_id='task-1',
            event_type=AgentEventType.THINKING,
            sequence=1,
            phase='analysis',
            message='thinking...',
            created_at=datetime.now(timezone.utc),
        )
        db.add_all([user, project, task, event])
        await db.commit()

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id='user-1', is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://testserver') as client:
        response = await client.get('/api/v1/agent-tasks/task-1/events/list')

    await engine.dispose()

    assert response.status_code == 200
    payload = response.json()
    assert payload[0]['task_id'] == 'task-1'
    assert payload[0]['event_type'] == AgentEventType.THINKING
    assert payload[0]['timestamp']
    assert payload[0]['created_at']


@pytest.mark.asyncio
async def test_auto_generate_managed_reports_when_verification_disabled(monkeypatch):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
            repository_url='https://example.com/demo.git',
        )
        task = AgentTask(
            id='task-1',
            project_id='project-1',
            created_by='user-1',
            name='Audit demo',
            version_label='v1.2.3',
            branch_name='release/v1',
            repository_url_snapshot='https://example.com/demo.git',
            status=AgentTaskStatus.COMPLETED,
            current_phase='reporting',
        )
        session = AuditSession(
            id='session-1',
            project_id='project-1',
            task_id='task-1',
            runtime_stack='runtime',
            state='completed',
        )
        finding = AgentFinding(
            id='finding-1',
            task_id='task-1',
            vulnerability_type='ssrf',
            severity='high',
            title='SSRF in fetch endpoint',
            description='User controlled target reaches outbound HTTP client.',
            file_path='app/api.py',
            line_start=21,
            line_end=22,
            code_snippet='response = httpx.get(target, timeout=5)',
            finding_metadata={
                'raw_finding': {
                    'title': 'SSRF in fetch endpoint',
                    'description': 'User controlled target reaches outbound HTTP client.',
                    'impact': 'Internal service exposure',
                    'references': ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'],
                }
            },
        )
        db.add_all([user, project, task, session, finding])
        await db.commit()

        async def fake_get_user_config(db_session, user_id):
            return {}

        captured = {}

        async def fake_generate_managed_report_bundle_from_session(
            db_session,
            *,
            session,
            task,
            finding,
            managed_vulnerability,
            report_service,
        ):
            del db_session, task, finding
            captured['session_id'] = session.id
            captured['managed_vulnerability_id'] = managed_vulnerability.id
            prompt = report_service.build_generation_prompt(vulnerability=managed_vulnerability)
            assert 'Use the cve-report-writer skill' in prompt
            return GeneratedReportBundle(
                report_en='# EN\n\n## Summary\n\n## Vulnerability Description\n\n## Exploitation\n\n## Impact\n\n## Remediation\n\n## Disclosure Notes\n\n## Supplemental Information\n\n### Affected products\n- Ecosystem: self-hosted\n- Package name: demo-app\n- Affected versions: to be confirmed\n- Patched versions: none confirmed\n\n### Severity\n- Scoring method: CVSS v3.1\n- Score: 8.6\n- Vector string: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N\n\n### Weaknesses\n- CWE: CWE-918 Server-Side Request Forgery (SSRF)',
                report_zh='# ZH\n\n## Summary\n\n## Vulnerability Description\n\n## Exploitation\n\n## Impact\n\n## Remediation\n\n## Disclosure Notes\n\n## 补充信息\n\n### Affected products\n- Ecosystem: self-hosted\n- Package name: demo-app\n- Affected versions: to be confirmed\n- Patched versions: none confirmed\n\n### Severity\n- Scoring method: CVSS v3.1\n- Score: 8.6\n- Vector string: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N\n\n### Weaknesses\n- CWE: CWE-918 Server-Side Request Forgery (SSRF)',
                report_cve='# demo_cve.md\n\n## CVE Submission Helper\n\n## Vulnerability type\n- [x] SSRF\n\n## CWE\nCWE-918 Server-Side Request Forgery (SSRF)\n\n## Vendor of the product(s)\nDemo Vendor\n\n## Affected product(s)/code base\n### Product\ndemo-app\n\n### Version\nto be confirmed\n\n## Attack type\n- [x] Remote\n\n## Impact\n- [x] Information disclosure\n\n## Affected component(s)\n/api/fetch endpoint\n\n## Core vulnerable code path\n`python\nresponse = httpx.get(target, timeout=5)\n`\n\n## Attack vector(s)\nPOST /api/fetch\n\n## Suggested description of the vulnerability for use in the CVE\nSSRF in fetch endpoint.\n\n## Discoverer(s)/Credits\ncil\n\n## Reference(s)\n- [ ] TBD\n\n## Additional information\nNone.',
            )

        async def fail_chat_completion(self, *args, **kwargs):
            raise AssertionError('chat_completion should not be called for managed report generation')

        monkeypatch.setattr(agent_tasks_endpoint, '_get_user_config', fake_get_user_config)
        monkeypatch.setattr(agent_tasks_endpoint, '_generate_managed_report_bundle_from_session', fake_generate_managed_report_bundle_from_session)
        monkeypatch.setattr('app.services.llm.service.LLMService.chat_completion', fail_chat_completion)

        stats = await agent_tasks_endpoint._auto_generate_managed_vulnerability_reports(
            db=db,
            task=task,
            workflow_config={'agentStates': {'verification': {'enabled': False}}},
            findings=[finding],
        )
        await db.commit()

        managed_result = await db.execute(
            select(ManagedVulnerability)
            .options(selectinload(ManagedVulnerability.reports))
            .where(ManagedVulnerability.task_id == 'task-1')
        )
        managed = managed_result.scalar_one()
        message_result = await db.execute(
            select(AuditSessionMessage)
            .where(AuditSessionMessage.session_id == 'session-1')
            .order_by(AuditSessionMessage.sequence)
        )
        messages = list(message_result.scalars().all())

    await engine.dispose()

    assert stats == {'generated': 1, 'failed': 0, 'skipped': 0}
    assert managed.report_generation_status == 'completed'
    assert {report.report_kind for report in managed.reports} == {'en', 'zh', 'cve'}
    assert captured == {'session_id': 'session-1', 'managed_vulnerability_id': managed.id}
    assert len(messages) == 1
    assert messages[0].role == 'user'
    assert messages[0].message_metadata['kind'] == 'internal_managed_report_request'
    assert 'Use the cve-report-writer skill' in messages[0].content


@pytest.mark.asyncio
async def test_auto_generate_managed_reports_skips_when_verification_enabled(monkeypatch):
    engine = create_async_engine('sqlite+aiosqlite:///:memory:')
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        user = User(
            id='user-1',
            email='owner@example.com',
            hashed_password='not-a-real-hash',
            full_name='Owner',
            is_active=True,
        )
        project = Project(
            id='project-1',
            name='Demo Project',
            owner_id='user-1',
            source_type='repository',
        )
        task = AgentTask(
            id='task-1',
            project_id='project-1',
            created_by='user-1',
            name='Audit demo',
            version_label='v1.2.3',
            status=AgentTaskStatus.COMPLETED,
        )
        finding = AgentFinding(
            id='finding-1',
            task_id='task-1',
            vulnerability_type='ssrf',
            severity='high',
            title='SSRF in fetch endpoint',
            description='User controlled target reaches outbound HTTP client.',
            file_path='app/api.py',
            line_start=21,
            line_end=22,
            finding_metadata={'raw_finding': {'impact': 'Internal service exposure'}},
        )
        db.add_all([user, project, task, finding])
        await db.commit()

        async def fail_chat_completion(self, *args, **kwargs):
            raise AssertionError('chat_completion should not be called when verification is enabled')

        monkeypatch.setattr('app.services.llm.service.LLMService.chat_completion', fail_chat_completion)

        stats = await agent_tasks_endpoint._auto_generate_managed_vulnerability_reports(
            db=db,
            task=task,
            workflow_config={'agentStates': {'verification': {'enabled': True}}},
            findings=[finding],
        )

        managed_result = await db.execute(select(ManagedVulnerability).where(ManagedVulnerability.task_id == 'task-1'))
        message_result = await db.execute(select(AuditSessionMessage).where(AuditSessionMessage.session_id == 'task-1'))

    await engine.dispose()

    assert stats == {'generated': 0, 'failed': 0, 'skipped': 1}
    assert managed_result.scalars().all() == []
    assert message_result.scalars().all() == []




@pytest.mark.asyncio
async def test_initialize_tools_builds_sandbox_tools_without_local_scope_error(monkeypatch):
    class FakeSimpleTool:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class FakeSandboxTool(FakeSimpleTool):
        pass

    class FakeEmbeddingService:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self.batch_size = None

    class FakeCodeIndexer:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

        async def smart_index_directory(self, **kwargs):
            if False:
                yield None
            return

    class FakeCodeRetriever:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    simple_tool_names = [
        'FileReadTool',
        'ReadManyFilesTool',
        'FileSearchTool',
        'ListFilesTool',
        'PatternMatchTool',
        'DataFlowAnalysisTool',
        'SemgrepTool',
        'BanditTool',
        'GitleaksTool',
        'NpmAuditTool',
        'SafetyTool',
        'TruffleHogTool',
        'OSVScannerTool',
        'ThinkTool',
        'ReflectTool',
        'CreateVulnerabilityReportTool',
        'SkillBodyTool',
        'SkillResourceTool',
        'RAGQueryTool',
        'SecurityCodeSearchTool',
        'FunctionContextTool',
        'SmartScanTool',
        'QuickAuditTool',
        'SandboxTool',
        'SandboxHttpTool',
        'VulnerabilityVerifyTool',
        'PhpTestTool',
        'PythonTestTool',
        'JavaScriptTestTool',
        'JavaTestTool',
        'GoTestTool',
        'RubyTestTool',
        'ShellTestTool',
        'UniversalCodeTestTool',
        'CommandInjectionTestTool',
        'SqlInjectionTestTool',
        'XssTestTool',
        'PathTraversalTestTool',
        'SstiTestTool',
        'DeserializationTestTool',
        'UniversalVulnTestTool',
        'RunCodeTool',
        'ExtractFunctionTool',
    ]

    for name in simple_tool_names:
        monkeypatch.setattr(
            agent_tools_module,
            name,
            FakeSandboxTool if name == 'SandboxTool' else type(name, (FakeSimpleTool,), {}),
            raising=False,
        )

    monkeypatch.setattr(agent_tools_module, 'build_shared_agent_tool_catalog', lambda **kwargs: {'read_file': FakeSimpleTool()}, raising=False)
    monkeypatch.setattr(agent_tools_module, 'build_agent_skill_tools', lambda **kwargs: {}, raising=False)
    monkeypatch.setattr(agent_tools_module, 'build_agent_tool_catalog', lambda **kwargs: {}, raising=False)
    monkeypatch.setattr(agent_tasks_endpoint, 'SecurityKnowledgeQueryTool', type('SecurityKnowledgeQueryTool', (FakeSimpleTool,), {}), raising=False)
    monkeypatch.setattr(agent_tasks_endpoint, 'GetVulnerabilityKnowledgeTool', type('GetVulnerabilityKnowledgeTool', (FakeSimpleTool,), {}), raising=False)

    monkeypatch.setattr(rag_module, 'EmbeddingService', FakeEmbeddingService, raising=False)
    monkeypatch.setattr(rag_module, 'CodeIndexer', FakeCodeIndexer, raising=False)
    monkeypatch.setattr(rag_module, 'CodeRetriever', FakeCodeRetriever, raising=False)
    monkeypatch.setattr(rag_module, 'IndexUpdateMode', SimpleNamespace(SMART='smart'), raising=False)

    tools = await agent_tasks_endpoint._initialize_tools(
        project_root='D:/repo',
        llm_service=SimpleNamespace(),
        user_config={},
        sandbox_manager=SimpleNamespace(),
        user_id='user-1',
    )

    assert 'sandbox_exec' in tools['finding']
    assert isinstance(tools['finding']['sandbox_exec'], FakeSandboxTool)
    assert 'sandbox_exec' in tools['verification']
    assert isinstance(tools['verification']['sandbox_exec'], FakeSandboxTool)
