from __future__ import annotations

import asyncio
import hashlib
import io
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

import app.api.v1.endpoints.talos_audit as talos_audit_endpoint
import app.services.talos_audit.runner as talos_audit_runner
from app.api.v1.endpoints.talos_audit import router as talos_audit_router
from app.db.base import Base
from app.models.agent_task import AgentTask, AgentTaskStatus
from app.models.audit_session import AuditSession, AuditSessionTurn, AuditToolCall
from app.models.project import Project
from app.models.talos_audit import TalosAuditJob, TalosAuditJobStatus
from app.models.user import User


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo/app.py", "print('hello')\n")
    return buffer.getvalue()


def _write_portal_archive(source_root: Path, request_id: str, *, project_name: str = "Portal Demo") -> Path:
    archive_bytes = _zip_bytes()
    file_id = talos_audit_endpoint._portal_archive_file_id(request_id)
    archive_dir = source_root / file_id
    archive_dir.mkdir(parents=True)
    (archive_dir / "source.zip").write_bytes(archive_bytes)
    (archive_dir / "metadata.json").write_text(
        json.dumps(
            {
                "file_id": file_id,
                "request_id": request_id,
                "project_name": project_name,
                "original_filename": "portal-demo.zip",
                "size_bytes": len(archive_bytes),
                "sha256": hashlib.sha256(archive_bytes).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    return archive_dir


def _build_app(session_factory) -> FastAPI:
    app = FastAPI()
    app.include_router(talos_audit_router, prefix="/api/v1/integrations/talos")

    async def get_test_db():
        async with session_factory() as db:
            yield db

    app.dependency_overrides[talos_audit_endpoint.get_db] = get_test_db
    return app


@pytest.mark.asyncio
async def test_talos_route_is_hidden_when_not_configured(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    app = _build_app(session_factory)
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_TOKEN", None)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/integrations/talos/audits",
            headers={"X-Talos-Token": "ignored"},
            json={"request_id": "portal-1"},
        )

    assert response.status_code == 404
    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_queues_zip_project_and_exposes_finalize_result(monkeypatch, tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="talos-service-user",
                email="talos@example.internal",
                hashed_password="not-used",
                is_active=True,
                is_superuser=True,
            )
        )
        await db.commit()

    source_root = tmp_path / "portal-archives"
    source_root.mkdir()
    _write_portal_archive(source_root, "portal-1")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_TOKEN", "test-secret")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_ENABLED", True)
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_SERVICE_USER_EMAIL", "talos@example.internal")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_SOURCE_ARCHIVE_DIR", str(source_root))
    monkeypatch.setattr(talos_audit_endpoint.settings, "ZIP_STORAGE_PATH", str(tmp_path / "stored-zips"))
    monkeypatch.setattr(talos_audit_endpoint.settings, "PROJECT_SOURCE_STORAGE_PATH", str(tmp_path / "project-sources"))
    final_payload = {"findings": [], "summary": "No verified findings."}
    called: dict[str, object] = {}

    async def fake_enqueue_talos_audit_job(job_id: str):
        called["job_id"] = job_id

    monkeypatch.setattr(talos_audit_endpoint, "enqueue_talos_audit_job", fake_enqueue_talos_audit_job)

    app = _build_app(session_factory)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/integrations/talos/audits",
            headers={"X-Talos-Token": "test-secret"},
            json={"request_id": "portal-1"},
        )

    assert response.status_code == 200, response.text
    acknowledgement = response.json()
    assert set(acknowledgement) == {"request_id", "project_id", "status", "reused"}
    assert acknowledgement["request_id"] == "portal-1"
    assert acknowledgement["status"] == "queued"
    assert acknowledgement["reused"] is False

    async with session_factory() as db:
        project = (await db.execute(select(Project))).scalar_one()
        job = (await db.execute(select(TalosAuditJob))).scalar_one()
        assert job.id == called["job_id"]
        assert job.project_id == project.id
        assert job.status == TalosAuditJobStatus.QUEUED
        assert project.source_type == "zip"
        assert project.name == "Portal Demo"
        assert project.repository_url == "talos:portal-1"
        assert project.workspace_mode == "audit_queued"
        assert project.local_path is not None
        assert (Path(project.local_path) / "app.py").read_text(encoding="utf-8") == "print('hello')\n"
        job.status = TalosAuditJobStatus.COMPLETED
        db.add(
            AuditSession(
                id="session-finalized",
                project_id=project.id,
                task_id=None,
                runtime_stack="runtime",
                state="completed",
                runtime_state_json={},
            )
        )
        job.audit_session_id = "session-finalized"
        job.finalize_finding = final_payload
        await db.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        result_response = await client.get(
            "/api/v1/integrations/talos/audits/portal-1",
            headers={"X-Talos-Token": "test-secret"},
        )

    assert result_response.status_code == 200, result_response.text
    assert result_response.json()["status"] == "completed"
    assert result_response.json()["finalize_finding"] == final_payload
    assert result_response.json()["error_message"] is None

    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_rejects_client_supplied_archive_path(monkeypatch, tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    app = _build_app(session_factory)
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_TOKEN", "test-secret")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_ENABLED", True)
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_SOURCE_ARCHIVE_DIR", str(tmp_path))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/integrations/talos/audits",
            headers={"X-Talos-Token": "test-secret"},
            json={"request_id": "portal-1", "archive_path": "../secret.zip"},
        )

    assert response.status_code == 422
    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_resolves_request_id_from_portal_metadata(monkeypatch, tmp_path):
    source_root = tmp_path / "portal-archives"
    source_root.mkdir()
    archive_dir = _write_portal_archive(source_root, "portal-1", project_name="Receiver Project")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_SOURCE_ARCHIVE_DIR", str(source_root))

    source_archive = talos_audit_endpoint._resolve_portal_source_archive("portal-1")

    assert source_archive.archive_path == archive_dir / "source.zip"
    assert source_archive.project_name == "Receiver Project"
    assert source_archive.original_filename == "portal-demo.zip"


@pytest.mark.asyncio
async def test_talos_rejects_portal_metadata_for_another_request(monkeypatch, tmp_path):
    source_root = tmp_path / "portal-archives"
    source_root.mkdir()
    archive_dir = _write_portal_archive(source_root, "portal-1")
    metadata_path = archive_dir / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["request_id"] = "portal-other"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_SOURCE_ARCHIVE_DIR", str(source_root))

    with pytest.raises(talos_audit_endpoint.HTTPException) as exc_info:
        talos_audit_endpoint._resolve_portal_source_archive("portal-1")

    assert exc_info.value.status_code == 422


@pytest.mark.asyncio
async def test_talos_cancel_marks_queued_job_cancelled(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="talos-service-user",
                email="talos@example.internal",
                hashed_password="not-used",
                is_active=True,
                is_superuser=True,
            )
        )
        db.add(Project(id="talos-project", name="Talos Project", owner_id="talos-service-user", source_type="zip"))
        db.add(
            TalosAuditJob(
                id="talos-job",
                request_id="portal-1",
                project_id="talos-project",
                service_user_id="talos-service-user",
                status=TalosAuditJobStatus.QUEUED,
            )
        )
        await db.commit()

    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_TOKEN", "test-secret")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_ENABLED", True)
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_SERVICE_USER_EMAIL", "talos@example.internal")
    app = _build_app(session_factory)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/integrations/talos/audits/portal-1/cancel",
            headers={"X-Talos-Token": "test-secret"},
        )

    assert response.status_code == 200, response.text
    assert response.json()["status"] == TalosAuditJobStatus.CANCELLED
    assert response.json()["error_message"] == "Talos audit cancelled by request"
    async with session_factory() as db:
        job = await db.get(TalosAuditJob, "talos-job")
        project = await db.get(Project, "talos-project")
    assert job is not None and job.status == TalosAuditJobStatus.CANCELLED
    assert project is not None and project.workspace_mode == "audit_cancelled"
    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_worker_stops_after_finalize_finding(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="talos-service-user",
                email="talos@example.internal",
                hashed_password="not-used",
                is_active=True,
                is_superuser=True,
            )
        )
        db.add(Project(id="talos-project", name="Talos Project", owner_id="talos-service-user", source_type="zip"))
        db.add(
            TalosAuditJob(
                id="talos-job",
                request_id="portal-1",
                project_id="talos-project",
                service_user_id="talos-service-user",
                status=TalosAuditJobStatus.QUEUED,
            )
        )
        await db.commit()

    called: dict[str, object] = {}
    final_payload = {"findings": [], "summary": "No verified findings."}

    async def fake_execute_agent_task(task_id: str):
        called["task_id"] = task_id
        async with session_factory() as worker_db:
            task = await worker_db.get(AgentTask, task_id)
            assert task is not None
            called["agent_config"] = dict(task.agent_config or {})
            called["audit_scope"] = dict(task.audit_scope or {})
            task.status = AgentTaskStatus.COMPLETED
            worker_db.add(
                AuditSession(
                    id="session-finalized",
                    project_id=task.project_id,
                    task_id=task.id,
                    runtime_stack="runtime",
                    state="completed",
                    runtime_state_json={},
                )
            )
            worker_db.add(AuditSessionTurn(id="turn-finalized", session_id="session-finalized", sequence=1))
            worker_db.add(
                AuditToolCall(
                    id="tool-finalized",
                    session_id="session-finalized",
                    turn_id="turn-finalized",
                    sequence=1,
                    tool_use_id="tool-use-finalized",
                    tool_name="FinalizeFinding",
                    status="completed",
                    output_payload={"final_payload": final_payload},
                )
            )
            await worker_db.commit()

    monkeypatch.setattr(talos_audit_runner, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(talos_audit_runner, "execute_agent_task", fake_execute_agent_task)

    await talos_audit_runner.run_talos_audit_job("talos-job")

    async with session_factory() as db:
        job = await db.get(TalosAuditJob, "talos-job")
        project = await db.get(Project, "talos-project")

    assert called["agent_config"]["finding_runtime_stack"] == "runtime"
    assert called["agent_config"]["skip_report_generation"] is True
    assert called["audit_scope"]["workflow"]["agentStates"] == {
        "scan": {"enabled": False},
        "triage": {"enabled": False},
        "finding": {"enabled": True},
        "verification": {"enabled": False},
    }
    assert job is not None and job.status == TalosAuditJobStatus.COMPLETED
    assert job.finalize_finding == final_payload
    assert project is not None and project.workspace_mode == "audit_completed"
    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_worker_persists_failure_after_runtime_error(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="talos-service-user",
                email="talos@example.internal",
                hashed_password="not-used",
                is_active=True,
                is_superuser=True,
            )
        )
        db.add(Project(id="talos-project", name="Talos Project", owner_id="talos-service-user", source_type="zip"))
        db.add(
            TalosAuditJob(
                id="talos-job",
                request_id="portal-1",
                project_id="talos-project",
                service_user_id="talos-service-user",
                status=TalosAuditJobStatus.QUEUED,
            )
        )
        await db.commit()

    async def fake_execute_agent_task(_task_id: str):
        raise RuntimeError("model token quota is exhausted")

    monkeypatch.setattr(talos_audit_runner, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(talos_audit_runner, "execute_agent_task", fake_execute_agent_task)

    with pytest.raises(RuntimeError, match="token quota"):
        await talos_audit_runner.run_talos_audit_job("talos-job")

    async with session_factory() as db:
        job = await db.get(TalosAuditJob, "talos-job")
        project = await db.get(Project, "talos-project")

    assert job is not None and job.status == TalosAuditJobStatus.FAILED
    assert job.error_message == "model token quota is exhausted"
    assert project is not None and project.workspace_mode == "audit_failed"
    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_worker_marks_running_job_cancelled(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="talos-service-user",
                email="talos@example.internal",
                hashed_password="not-used",
                is_active=True,
                is_superuser=True,
            )
        )
        db.add(Project(id="talos-project", name="Talos Project", owner_id="talos-service-user", source_type="zip"))
        db.add(
            TalosAuditJob(
                id="talos-job",
                request_id="portal-1",
                project_id="talos-project",
                service_user_id="talos-service-user",
                status=TalosAuditJobStatus.QUEUED,
            )
        )
        await db.commit()

    async def fake_execute_agent_task(_task_id: str):
        await asyncio.sleep(60)

    async def fake_cancel_watch(_job_id, _agent_task_id, audit_task):
        audit_task.cancel()

    monkeypatch.setattr(talos_audit_runner, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(talos_audit_runner, "execute_agent_task", fake_execute_agent_task)
    monkeypatch.setattr(talos_audit_runner, "_watch_talos_audit_cancellation", fake_cancel_watch)

    await talos_audit_runner.run_talos_audit_job("talos-job")

    async with session_factory() as db:
        job = await db.get(TalosAuditJob, "talos-job")
        project = await db.get(Project, "talos-project")

    assert job is not None and job.status == TalosAuditJobStatus.CANCELLED
    assert project is not None and project.workspace_mode == "audit_cancelled"
    await engine.dispose()
