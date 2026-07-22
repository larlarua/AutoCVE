from __future__ import annotations

import asyncio
import io
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
from app.models.audit_session import AuditSession
from app.models.project import Project
from app.models.talos_audit import TalosAuditJob, TalosAuditJobStatus
from app.models.user import User


def _zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("demo/app.py", "print('hello')\n")
    return buffer.getvalue()


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
            json={"request_id": "portal-1", "archive_path": "portal-1.zip"},
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
    (source_root / "portal-1.zip").write_bytes(_zip_bytes())
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
            json={
                "request_id": "portal-1",
                "project_name": "Portal Demo",
                "archive_path": "portal-1.zip",
            },
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

    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_rejects_path_outside_configured_archive_directory(monkeypatch, tmp_path):
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

    async def fake_start_direct_audit_session(*, generate_reports, db, project, **kwargs):
        called["generate_reports"] = generate_reports
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
        await db.commit()
        return SimpleNamespace(id="session-finalized")

    async def fake_load_messages(**kwargs):
        return []

    monkeypatch.setattr(talos_audit_runner, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(talos_audit_runner, "start_direct_audit_session", fake_start_direct_audit_session)
    monkeypatch.setattr(talos_audit_runner, "_load_direct_audit_messages", fake_load_messages)
    monkeypatch.setattr(talos_audit_runner, "_extract_direct_audit_final_payload", lambda _messages: final_payload)

    await talos_audit_runner.run_talos_audit_job("talos-job")

    async with session_factory() as db:
        job = await db.get(TalosAuditJob, "talos-job")
        project = await db.get(Project, "talos-project")

    assert called["generate_reports"] is False
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

    async def fake_start_direct_audit_session(**_kwargs):
        raise RuntimeError("model token quota is exhausted")

    monkeypatch.setattr(talos_audit_runner, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(talos_audit_runner, "start_direct_audit_session", fake_start_direct_audit_session)

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

    async def fake_start_direct_audit_session(**_kwargs):
        await asyncio.sleep(60)

    async def fake_cancel_watch(_job_id, audit_task):
        audit_task.cancel()

    monkeypatch.setattr(talos_audit_runner, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(talos_audit_runner, "start_direct_audit_session", fake_start_direct_audit_session)
    monkeypatch.setattr(talos_audit_runner, "_watch_talos_audit_cancellation", fake_cancel_watch)

    await talos_audit_runner.run_talos_audit_job("talos-job")

    async with session_factory() as db:
        job = await db.get(TalosAuditJob, "talos-job")
        project = await db.get(Project, "talos-project")

    assert job is not None and job.status == TalosAuditJobStatus.CANCELLED
    assert project is not None and project.workspace_mode == "audit_cancelled"
    await engine.dispose()
