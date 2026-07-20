from __future__ import annotations

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
from app.api.v1.endpoints.talos_audit import router as talos_audit_router
from app.db.base import Base
from app.models.project import Project
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
            headers={"X-AutoCVE-Talos-Token": "ignored"},
            json={"request_id": "portal-1", "archive_path": "portal-1.zip"},
        )

    assert response.status_code == 404
    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_creates_zip_project_and_stops_after_finalize(monkeypatch, tmp_path):
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
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_SERVICE_USER_EMAIL", "talos@example.internal")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_SOURCE_ARCHIVE_DIR", str(source_root))
    monkeypatch.setattr(talos_audit_endpoint.settings, "ZIP_STORAGE_PATH", str(tmp_path / "stored-zips"))
    monkeypatch.setattr(talos_audit_endpoint.settings, "PROJECT_SOURCE_STORAGE_PATH", str(tmp_path / "project-sources"))

    final_payload = {"findings": [], "summary": "No verified findings."}
    called: dict[str, object] = {}

    async def fake_start_direct_audit_session(*, project, content, guardrails_enabled, db, current_user, generate_reports):
        del content, guardrails_enabled, db, current_user
        called["project_id"] = project.id
        called["generate_reports"] = generate_reports
        return SimpleNamespace(id="session-finalized")

    monkeypatch.setattr(talos_audit_endpoint, "start_direct_audit_session", fake_start_direct_audit_session)
    monkeypatch.setattr(talos_audit_endpoint, "_extract_direct_audit_final_payload", lambda _messages: final_payload)

    app = _build_app(session_factory)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/integrations/talos/audits",
            headers={"X-AutoCVE-Talos-Token": "test-secret"},
            json={
                "request_id": "portal-1",
                "project_name": "Portal Demo",
                "archive_path": "portal-1.zip",
            },
        )

    assert response.status_code == 200, response.text
    assert response.json()["finalize_finding"] == final_payload
    assert response.json()["reused"] is False
    assert called["generate_reports"] is False

    async with session_factory() as db:
        project = (await db.execute(select(Project))).scalar_one()
        assert project.id == called["project_id"]
        assert project.source_type == "zip"
        assert project.repository_url == "talos:portal-1"
        assert project.workspace_mode == "persistent_source"
        assert project.local_path is not None
        assert (Path(project.local_path) / "app.py").read_text(encoding="utf-8") == "print('hello')\n"

    await engine.dispose()


@pytest.mark.asyncio
async def test_talos_rejects_path_outside_configured_archive_directory(monkeypatch, tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    app = _build_app(session_factory)
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_AUDIT_TOKEN", "test-secret")
    monkeypatch.setattr(talos_audit_endpoint.settings, "TALOS_SOURCE_ARCHIVE_DIR", str(tmp_path))

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/integrations/talos/audits",
            headers={"X-AutoCVE-Talos-Token": "test-secret"},
            json={"request_id": "portal-1", "archive_path": "../secret.zip"},
        )

    assert response.status_code == 422
    await engine.dispose()
