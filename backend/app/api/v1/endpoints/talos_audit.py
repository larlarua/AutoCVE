"""Private Talos integration for auditing an already received source archive.

The endpoint is deliberately disabled unless an operator configures a token and
an existing AutoCVE superuser.  Talos supplies only a *relative* archive path;
the resolved file must remain below ``TALOS_SOURCE_ARCHIVE_DIR``.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import zipfile
from pathlib import Path
from typing import Any, Annotated, Literal

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.project import Project
from app.models.talos_audit import TalosAuditJob, TalosAuditJobStatus
from app.models.user import User
from app.services.talos_audit.task_queue import enqueue_talos_audit_job
from app.services.zip_storage import (
    delete_project_persistent_source,
    delete_project_zip,
    materialize_project_source_from_zip,
    save_project_zip,
    update_project_zip_meta,
)

router = APIRouter()

_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")


class TalosAuditRequest(BaseModel):
    request_id: str = Field(..., min_length=1, max_length=255, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    archive_path: str = Field(..., min_length=1, max_length=1024)
    project_name: str | None = Field(default=None, max_length=255)
    file_sha256: str | None = Field(default=None, max_length=64)


class TalosAuditAcceptedResponse(BaseModel):
    request_id: str
    project_id: str
    status: Literal["queued", "running", "completed", "failed"]
    reused: bool = False


class TalosAuditStatusResponse(TalosAuditAcceptedResponse):
    session_id: str | None = None
    finalize_finding: dict[str, Any] | None = None


async def _require_talos_token(
    x_autocve_talos_token: Annotated[str | None, Header(alias="X-AutoCVE-Talos-Token")] = None,
) -> None:
    """Authenticate Talos without exposing this private route by default."""
    configured_token = str(settings.TALOS_AUDIT_TOKEN or "").strip()
    if not settings.TALOS_AUDIT_ENABLED or not configured_token:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Not found")
    if not x_autocve_talos_token or not secrets.compare_digest(x_autocve_talos_token, configured_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid Talos integration token")


def _resolve_archive_path(relative_archive_path: str) -> Path:
    configured_root = str(settings.TALOS_SOURCE_ARCHIVE_DIR or "").strip()
    if not configured_root:
        raise HTTPException(status_code=503, detail="Talos source archive directory is not configured")

    relative_path = Path(relative_archive_path)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise HTTPException(status_code=422, detail="archive_path must be relative to TALOS_SOURCE_ARCHIVE_DIR")

    source_root = Path(configured_root).resolve()
    archive_path = (source_root / relative_path).resolve()
    try:
        archive_path.relative_to(source_root)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="archive_path must stay inside TALOS_SOURCE_ARCHIVE_DIR") from exc

    if archive_path.suffix.lower() != ".zip":
        raise HTTPException(status_code=422, detail="archive_path must reference a ZIP file")
    if not archive_path.is_file():
        raise HTTPException(status_code=404, detail="Source archive was not found")
    return archive_path


def _validate_source_archive(archive_path: Path, expected_sha256: str | None) -> None:
    try:
        file_size = archive_path.stat().st_size
    except OSError as exc:
        raise HTTPException(status_code=404, detail="Source archive was not found") from exc
    if file_size > settings.TALOS_AUDIT_MAX_ARCHIVE_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="Source archive exceeds the configured size limit")

    if expected_sha256:
        if not _SHA256_RE.fullmatch(expected_sha256):
            raise HTTPException(status_code=422, detail="file_sha256 must be a SHA-256 hex digest")
        digest_builder = hashlib.sha256()
        with archive_path.open("rb") as source_file:
            for chunk in iter(lambda: source_file.read(1024 * 1024), b""):
                digest_builder.update(chunk)
        digest = digest_builder.hexdigest()
        if not secrets.compare_digest(digest, expected_sha256.lower()):
            raise HTTPException(status_code=422, detail="Source archive SHA-256 does not match")

    try:
        with zipfile.ZipFile(archive_path, "r") as archive:
            entries = archive.infolist()
            if len(entries) > settings.TALOS_AUDIT_MAX_ARCHIVE_FILES:
                raise HTTPException(status_code=422, detail="Source archive has too many entries")
            if sum(entry.file_size for entry in entries) > settings.TALOS_AUDIT_MAX_UNCOMPRESSED_SIZE_BYTES:
                raise HTTPException(status_code=422, detail="Source archive expands beyond the configured size limit")
            if any(entry.flag_bits & 0x1 for entry in entries):
                raise HTTPException(status_code=422, detail="Encrypted ZIP archives are not supported")
            bad_member = next(
                (
                    entry.filename
                    for entry in entries
                    if Path(entry.filename).is_absolute() or ".." in Path(entry.filename).parts
                ),
                None,
            )
            if bad_member:
                raise HTTPException(status_code=422, detail="Source archive contains an unsafe path")
            bad_archive = archive.testzip()
            if bad_archive:
                raise HTTPException(status_code=422, detail="Source archive is corrupt")
    except HTTPException:
        raise
    except (OSError, zipfile.BadZipFile) as exc:
        raise HTTPException(status_code=422, detail="Source archive is not a valid ZIP file") from exc


def _talos_project_ref(request_id: str) -> str:
    return f"talos:{request_id}"


async def _get_service_user(db: AsyncSession) -> User:
    email = str(settings.TALOS_AUDIT_SERVICE_USER_EMAIL or "").strip()
    if not email:
        raise HTTPException(status_code=503, detail="Talos service user is not configured")
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if user is None or not user.is_active or not user.is_superuser:
        raise HTTPException(status_code=503, detail="Talos service user must be an active superuser")
    return user


def _to_talos_audit_status(job: TalosAuditJob, *, reused: bool = False) -> TalosAuditStatusResponse:
    return TalosAuditStatusResponse(
        request_id=job.request_id,
        project_id=job.project_id,
        status=job.status,
        session_id=job.audit_session_id,
        finalize_finding=job.finalize_finding,
        reused=reused,
    )


async def _create_project_from_archive(
    *,
    request: TalosAuditRequest,
    archive_path: Path,
    service_user: User,
    db: AsyncSession,
) -> Project:
    project = Project(
        name=(request.project_name or f"Talos {request.request_id}").strip() or f"Talos {request.request_id}",
        description=f"Created by Talos integration for request_id={request.request_id}",
        source_type="zip",
        repository_url=_talos_project_ref(request.request_id),
        repository_type="talos",
        default_branch="main",
        owner_id=service_user.id,
        workspace_mode="importing",
    )
    db.add(project)
    await db.flush()

    try:
        await save_project_zip(
            project.id,
            str(archive_path),
            archive_path.name,
            import_status="processing",
            keep_archive=True,
        )
        source_meta = await materialize_project_source_from_zip(project.id, str(archive_path))
        project.local_path = str(source_meta["path"])
        project.workspace_mode = "audit_queued"
        await update_project_zip_meta(
            project.id,
            import_status="ready",
            import_error=None,
            persistent_source_path=source_meta["path"],
            persistent_source_updated_at=source_meta["updated_at"],
        )
        await db.commit()
        await db.refresh(project)
        return project
    except Exception:
        await db.rollback()
        await delete_project_persistent_source(project.id)
        await delete_project_zip(project.id)
        raise


async def _find_talos_audit_job(*, request_id: str, db: AsyncSession) -> TalosAuditJob | None:
    result = await db.execute(
        select(TalosAuditJob).where(TalosAuditJob.request_id == request_id)
    )
    return result.scalar_one_or_none()


@router.post("/audits", response_model=TalosAuditAcceptedResponse)
async def start_talos_audit(
    payload: TalosAuditRequest,
    _: None = Depends(_require_talos_token),
    db: AsyncSession = Depends(get_db),
) -> TalosAuditAcceptedResponse:
    """Accept a Talos audit request and schedule the Finding runtime in the background."""
    archive_path = _resolve_archive_path(payload.archive_path)
    _validate_source_archive(archive_path, payload.file_sha256)
    service_user = await _get_service_user(db)

    existing_job = await _find_talos_audit_job(
        request_id=payload.request_id,
        db=db,
    )
    if existing_job is not None:
        current = _to_talos_audit_status(existing_job, reused=True)
        return TalosAuditAcceptedResponse(**current.model_dump(exclude={"session_id", "finalize_finding"}))

    project = await _create_project_from_archive(
        request=payload,
        archive_path=archive_path,
        service_user=service_user,
        db=db,
    )
    job = TalosAuditJob(
        request_id=payload.request_id,
        project_id=project.id,
        service_user_id=service_user.id,
        status=TalosAuditJobStatus.QUEUED,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    try:
        await enqueue_talos_audit_job(job.id)
    except Exception as exc:
        job.status = TalosAuditJobStatus.FAILED
        job.error_message = f"Unable to enqueue Talos audit: {exc}"
        await db.commit()
        raise HTTPException(status_code=503, detail="Talos audit queue is unavailable") from exc
    return TalosAuditAcceptedResponse(
        request_id=job.request_id,
        project_id=job.project_id,
        status=job.status,
    )


@router.get("/audits/{request_id}", response_model=TalosAuditStatusResponse)
async def get_talos_audit_result(
    request_id: str,
    _: None = Depends(_require_talos_token),
    db: AsyncSession = Depends(get_db),
) -> TalosAuditStatusResponse:
    """Temporary local result endpoint until Talos provides a callback contract."""
    await _get_service_user(db)
    job = await _find_talos_audit_job(
        request_id=request_id,
        db=db,
    )
    if job is None:
        raise HTTPException(status_code=404, detail="Talos audit request was not found")
    return _to_talos_audit_status(job)
