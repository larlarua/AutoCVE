from __future__ import annotations

import asyncio
import io
from pathlib import Path
import shutil
import tempfile
import time
from types import SimpleNamespace
import uuid
import zipfile

import pytest
from fastapi import FastAPI
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import deps
from app.api.v1.endpoints.projects import router as projects_router
from app.db.base import Base
from app.models.user import User
import app.api.v1.endpoints.projects as projects_endpoint
from app.models.project import Project
from app.services.zip_storage import save_project_zip

WORKSPACE_ROOT = Path(__file__).resolve().parents[3]


def build_test_app() -> FastAPI:
    app = FastAPI()
    app.include_router(projects_router, prefix="/api/v1/projects")
    return app


def make_managed_root() -> Path:
    managed_root = WORKSPACE_ROOT / ".pytest-managed-projects" / str(uuid.uuid4())
    managed_root.mkdir(parents=True, exist_ok=True)
    return managed_root


@pytest.mark.asyncio
async def test_list_managed_local_directories_creates_missing_root():
    managed_root = WORKSPACE_ROOT / ".pytest-managed-projects" / str(uuid.uuid4()) / "projects"
    original_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root)

    try:
        payload = await projects_endpoint.list_managed_local_directories(
            current_user=SimpleNamespace(id="user-1", is_active=True),
        )
        assert managed_root.exists() is True
        assert managed_root.is_dir() is True
        assert payload == []
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_root
        shutil.rmtree(managed_root.parent, ignore_errors=True)


@pytest.mark.asyncio
async def test_create_local_directory_project_requires_local_path():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        await db.commit()

    async with session_factory() as db:
        with pytest.raises(HTTPException) as exc_info:
            await projects_endpoint.create_project(
                db=db,
                project_in=projects_endpoint.ProjectCreate(
                    name="Managed Demo",
                    source_type="local_directory",
                    programming_languages=["Python"],
                ),
                current_user=SimpleNamespace(id="user-1", is_active=True),
            )

    await engine.dispose()

    assert exc_info.value.status_code == 422
    assert "local_path" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_create_local_directory_project_rejects_duplicate_registration():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        await db.commit()

    managed_root_path = make_managed_root()
    project_path = managed_root_path / "managed-demo"
    project_path.mkdir()
    original_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root_path)

    payload = {
        "name": "Managed Demo",
        "source_type": "local_directory",
        "local_path": str(project_path),
        "programming_languages": ["Python"],
    }

    try:
        async with session_factory() as db:
            first = await projects_endpoint.create_project(
                db=db,
                project_in=projects_endpoint.ProjectCreate(**payload),
                current_user=SimpleNamespace(id="user-1", is_active=True),
            )

            with pytest.raises(HTTPException) as exc_info:
                await projects_endpoint.create_project(
                    db=db,
                    project_in=projects_endpoint.ProjectCreate(**payload),
                    current_user=SimpleNamespace(id="user-1", is_active=True),
                )

            result = await db.execute(
                projects_endpoint.select(Project).where(Project.owner_id == "user-1")
            )
            projects = result.scalars().all()
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_root
        shutil.rmtree(managed_root_path, ignore_errors=True)

    await engine.dispose()

    assert first.name == "Managed Demo"
    assert len(projects) == 1
    assert exc_info.value.status_code == 400
    assert "already registered" in str(exc_info.value.detail)


@pytest.mark.asyncio
async def test_list_managed_local_directories_returns_first_level_directories(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        await db.commit()

    managed_root_path = make_managed_root()
    (managed_root_path / "alpha").mkdir()
    (managed_root_path / "beta").mkdir()
    (managed_root_path / "README.md").write_text("ignore me", encoding="utf-8")
    original_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root_path)

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get("/api/v1/projects/managed-local-directories")
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_root
        shutil.rmtree(managed_root_path, ignore_errors=True)

    await engine.dispose()

    assert response.status_code == 200
    payload = response.json()
    assert [item["name"] for item in payload] == ["alpha", "beta"]
    assert payload[0]["path"] == str((managed_root_path / "alpha").resolve())


@pytest.mark.asyncio
async def test_get_local_directory_project_file_content_returns_text():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        await db.commit()

    managed_root_path = make_managed_root()
    project_path = managed_root_path / "preview-demo"
    src_dir = project_path / "src"
    src_dir.mkdir(parents=True)
    target_file = src_dir / "app.py"
    target_file.write_text("print('hello from direct audit')\n", encoding="utf-8")
    original_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root_path)

    async with session_factory() as db:
        created = await projects_endpoint.create_project(
            db=db,
            project_in=projects_endpoint.ProjectCreate(
                name="Preview Demo",
                source_type="local_directory",
                local_path=str(project_path),
                programming_languages=["Python"],
            ),
            current_user=SimpleNamespace(id="user-1", is_active=True),
        )

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                f"/api/v1/projects/{created.id}/file-content",
                params={"path": "src/app.py"},
            )
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_root
        shutil.rmtree(managed_root_path, ignore_errors=True)

    await engine.dispose()

    assert response.status_code == 200
    payload = response.json()
    assert payload["path"] == "src/app.py"
    assert "hello from direct audit" in payload["content"]
    assert payload["truncated"] is False


@pytest.mark.asyncio
async def test_get_local_directory_project_files_skips_virtualenv_directories():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        await db.commit()

    managed_root_path = make_managed_root()
    project_path = managed_root_path / "files-demo"
    src_dir = project_path / "src"
    venv_dir = project_path / ".venv" / "lib" / "site-packages"
    src_dir.mkdir(parents=True)
    venv_dir.mkdir(parents=True)
    (src_dir / "app.py").write_text("print('keep me')\n", encoding="utf-8")
    (venv_dir / "dependency.py").write_text("print('exclude me')\n", encoding="utf-8")
    original_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root_path)

    async with session_factory() as db:
        created = await projects_endpoint.create_project(
            db=db,
            project_in=projects_endpoint.ProjectCreate(
                name="Files Demo",
                source_type="local_directory",
                local_path=str(project_path),
                programming_languages=["Python"],
            ),
            current_user=SimpleNamespace(id="user-1", is_active=True),
        )

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(f"/api/v1/projects/{created.id}/files")
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_root
        shutil.rmtree(managed_root_path, ignore_errors=True)

    await engine.dispose()

    assert response.status_code == 200
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["path"] == "src/app.py"
    assert payload[0]["size"] > 0


def test_list_local_project_files_skips_virtualenv_directories():
    managed_root_path = make_managed_root()
    project_path = managed_root_path / "exclude-demo"
    src_dir = project_path / "src"
    venv_dir = project_path / ".venv" / "lib" / "site-packages"
    src_dir.mkdir(parents=True)
    venv_dir.mkdir(parents=True)

    (src_dir / "app.py").write_text("print('keep me')\n", encoding="utf-8")
    (venv_dir / "dependency.py").write_text("print('exclude me')\n", encoding="utf-8")

    try:
        files = projects_endpoint._list_local_project_files(project_path)
    finally:
        shutil.rmtree(managed_root_path, ignore_errors=True)

    assert [entry["path"] for entry in files] == ["src/app.py"]


@pytest.mark.asyncio
async def test_get_local_directory_project_files_does_not_block_event_loop(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        await db.commit()

    managed_root_path = make_managed_root()
    project_path = managed_root_path / "non-blocking-demo"
    project_path.mkdir(parents=True)
    (project_path / "app.py").write_text("print('hello')\n", encoding="utf-8")
    original_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root_path)

    async with session_factory() as db:
        created = await projects_endpoint.create_project(
            db=db,
            project_in=projects_endpoint.ProjectCreate(
                name="Non Blocking Demo",
                source_type="local_directory",
                local_path=str(project_path),
                programming_languages=["Python"],
            ),
            current_user=SimpleNamespace(id="user-1", is_active=True),
        )

    events: list[str] = []

    def slow_list_local_project_files(project_root: Path, exclude_patterns: list[str] | None = None):
        del project_root, exclude_patterns
        time.sleep(0.1)
        events.append("list_done")
        return [{"path": "app.py", "size": 15}]

    monkeypatch.setattr(projects_endpoint, "_list_local_project_files", slow_list_local_project_files)

    async with session_factory() as db:
        listing_task = asyncio.create_task(
            projects_endpoint.get_project_files(
                id=created.id,
                db=db,
                current_user=SimpleNamespace(id="user-1", is_active=True),
            )
        )

        async def observer():
            await asyncio.sleep(0.01)
            events.append("tick")

        observer_task = asyncio.create_task(observer())
        await asyncio.sleep(0.02)
        interim_events = list(events)
        files = await listing_task
        await observer_task

    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_root
    shutil.rmtree(managed_root_path, ignore_errors=True)
    await engine.dispose()

    assert interim_events == ["tick"]
    assert files == [{"path": "app.py", "size": 15}]
    assert events == ["tick", "list_done"]


@pytest.mark.asyncio
async def test_get_local_directory_project_file_content_rejects_path_escape():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        await db.commit()

    managed_root_path = make_managed_root()
    project_path = managed_root_path / "escape-demo"
    project_path.mkdir(parents=True)
    (project_path / "safe.txt").write_text("safe", encoding="utf-8")
    original_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root_path)

    async with session_factory() as db:
        created = await projects_endpoint.create_project(
            db=db,
            project_in=projects_endpoint.ProjectCreate(
                name="Escape Demo",
                source_type="local_directory",
                local_path=str(project_path),
                programming_languages=["Text"],
            ),
            current_user=SimpleNamespace(id="user-1", is_active=True),
        )

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.get(
                f"/api/v1/projects/{created.id}/file-content",
                params={"path": "../outside.txt"},
            )
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_root
        shutil.rmtree(managed_root_path, ignore_errors=True)

    await engine.dispose()

    assert response.status_code == 400
    assert "project root" in response.json()["detail"]


def build_zip_bytes(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zip_buffer:
        for path, content in files.items():
            zip_buffer.writestr(path, content)
    return buffer.getvalue()


@pytest.mark.asyncio
async def test_upload_project_zip_extracts_persistent_source_and_can_skip_archive_retention():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        db.add(
            Project(
                id="project-zip-1",
                name="Zip Demo",
                owner_id="user-1",
                source_type="zip",
                repository_type="other",
                default_branch="main",
            )
        )
        await db.commit()

    managed_root = make_managed_root()
    zip_root = managed_root / "zip-storage"
    original_managed_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    original_zip_root = projects_endpoint.settings.ZIP_STORAGE_PATH
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root)
    projects_endpoint.settings.ZIP_STORAGE_PATH = str(zip_root)

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)
    zip_bytes = build_zip_bytes({"demo/src/app.py": "print('zip source')\n"})

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            upload_response = await client.post(
                "/api/v1/projects/project-zip-1/zip",
                data={"keep_archive": "false"},
                files={"file": ("demo.zip", zip_bytes, "application/zip")},
            )
            info_response = await client.get("/api/v1/projects/project-zip-1/zip")
            preview_response = await client.get(
                "/api/v1/projects/project-zip-1/file-content",
                params={"path": "src/app.py"},
            )
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_managed_root
        projects_endpoint.settings.ZIP_STORAGE_PATH = original_zip_root

    async with session_factory() as db:
        project = await db.get(Project, "project-zip-1")

    await engine.dispose()

    assert upload_response.status_code == 200
    assert info_response.status_code == 200
    assert preview_response.status_code == 200
    assert project.local_path
    assert Path(project.local_path).is_dir() is True
    assert Path(project.local_path, "src", "app.py").read_text(encoding="utf-8") == "print('zip source')\n"
    assert preview_response.json()["content"] == "print('zip source')\n"
    assert info_response.json()["has_file"] is False
    assert info_response.json()["has_persistent_source"] is True
    assert info_response.json()["persistent_source_path"] == str(Path(project.local_path).resolve())


@pytest.mark.asyncio
async def test_zip_project_file_content_uses_existing_legacy_local_path_when_archive_is_missing():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        db.add(
            Project(
                id="project-zip-legacy-1",
                name="Legacy Zip Demo",
                owner_id="user-1",
                source_type="zip",
                repository_type="other",
                default_branch="main",
            )
        )
        await db.commit()

    managed_root = make_managed_root()
    legacy_root = Path(tempfile.mkdtemp(prefix="auditai-legacy-zip-")).resolve()
    original_managed_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    original_zip_root = projects_endpoint.settings.ZIP_STORAGE_PATH
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root)
    projects_endpoint.settings.ZIP_STORAGE_PATH = str(managed_root / "zip-storage")

    try:
        (legacy_root / "src").mkdir(parents=True, exist_ok=True)
        (legacy_root / "src" / "Kernel.php").write_text("<?php\nreturn 'legacy zip';\n", encoding="utf-8")

        async with session_factory() as db:
            project = await db.get(Project, "project-zip-legacy-1")
            project.local_path = str(legacy_root)
            await db.commit()

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
            files_response = await client.get("/api/v1/projects/project-zip-legacy-1/files")
            preview_response = await client.get(
                "/api/v1/projects/project-zip-legacy-1/file-content",
                params={"path": "src/Kernel.php"},
            )
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_managed_root
        projects_endpoint.settings.ZIP_STORAGE_PATH = original_zip_root
        shutil.rmtree(legacy_root, ignore_errors=True)

    await engine.dispose()

    assert files_response.status_code == 200
    assert preview_response.status_code == 200
    assert preview_response.json()["content"] == "<?php\nreturn 'legacy zip';\n"


@pytest.mark.asyncio
async def test_delete_project_source_artifacts_supports_source_only_and_both():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    session_factory = async_sessionmaker(engine, expire_on_commit=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    async with session_factory() as db:
        db.add(
            User(
                id="user-1",
                email="owner@example.com",
                hashed_password="not-a-real-hash",
                full_name="Owner",
                is_active=True,
            )
        )
        project = Project(
            id="project-zip-delete-1",
            name="Zip Delete Demo",
            owner_id="user-1",
            source_type="zip",
            repository_type="other",
            default_branch="main",
        )
        db.add(project)
        await db.commit()

    managed_root = make_managed_root()
    zip_root = managed_root / "zip-storage"
    original_managed_root = projects_endpoint.settings.MANAGED_PROJECTS_ROOT
    original_zip_root = projects_endpoint.settings.ZIP_STORAGE_PATH
    projects_endpoint.settings.MANAGED_PROJECTS_ROOT = str(managed_root)
    projects_endpoint.settings.ZIP_STORAGE_PATH = str(zip_root)

    persistent_source = managed_root / "project-zip-delete-1"
    persistent_source.mkdir(parents=True, exist_ok=True)
    (persistent_source / "README.md").write_text("persisted source", encoding="utf-8")

    temp_archive = managed_root / "archive.zip"
    temp_archive.write_bytes(build_zip_bytes({"README.md": "archive"}))
    await save_project_zip("project-zip-delete-1", str(temp_archive), "archive.zip")

    async with session_factory() as db:
        project = await db.get(Project, "project-zip-delete-1")
        project.local_path = str(persistent_source.resolve())
        await db.commit()

    app = build_test_app()

    async def override_get_db():
        async with session_factory() as db:
            yield db

    async def override_get_current_user():
        return SimpleNamespace(id="user-1", is_active=True)

    app.dependency_overrides[deps.get_db] = override_get_db
    app.dependency_overrides[deps.get_current_user] = override_get_current_user

    transport = ASGITransport(app=app)

    try:
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            delete_source_response = await client.post(
                "/api/v1/projects/project-zip-delete-1/source-artifacts/delete",
                json={"delete_persistent_source": True},
            )
            info_after_source_delete = await client.get("/api/v1/projects/project-zip-delete-1/zip")

            persistent_source.mkdir(parents=True, exist_ok=True)
            (persistent_source / "README.md").write_text("persisted source again", encoding="utf-8")
            async with session_factory() as db:
                project = await db.get(Project, "project-zip-delete-1")
                project.local_path = str(persistent_source.resolve())
                await db.commit()

            delete_both_response = await client.post(
                "/api/v1/projects/project-zip-delete-1/source-artifacts/delete",
                json={"delete_zip": True, "delete_persistent_source": True},
            )
            final_info_response = await client.get("/api/v1/projects/project-zip-delete-1/zip")
    finally:
        projects_endpoint.settings.MANAGED_PROJECTS_ROOT = original_managed_root
        projects_endpoint.settings.ZIP_STORAGE_PATH = original_zip_root
        shutil.rmtree(managed_root, ignore_errors=True)

    async with session_factory() as db:
        project = await db.get(Project, "project-zip-delete-1")

    await engine.dispose()

    assert delete_source_response.status_code == 200
    assert delete_source_response.json()["deleted_persistent_source"] is True
    assert delete_source_response.json()["deleted_zip"] is False
    assert info_after_source_delete.json()["has_file"] is True
    assert info_after_source_delete.json()["has_persistent_source"] is False

    assert delete_both_response.status_code == 200
    assert delete_both_response.json()["deleted_zip"] is True
    assert delete_both_response.json()["deleted_persistent_source"] is True
    assert final_info_response.json()["has_file"] is False
    assert final_info_response.json()["has_persistent_source"] is False
    assert project.local_path is None
