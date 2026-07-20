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
from typing import Any, Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.endpoints.agent_direct_audit import (
    _extract_direct_audit_final_payload,
    _load_direct_audit_messages,
    start_direct_audit_session,
)
from app.core.config import settings
from app.db.session import get_db
from app.models.audit_session import AuditSession
from app.models.project import Project
from app.models.user import User
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


class TalosAuditResponse(BaseModel):
    request_id: str
    project_id: str
    session_id: str
    finalize_finding: dict[str, Any]
    reused: bool = False


async def _require_talos_token(
    x_autocve_talos_token: Annotated[str | None, Header(alias="X-AutoCVE-Talos-Token")] = None,
) -> None:
    """Authenticate Talos without exposing this private route by default."""
    configured_token = str(settings.TALOS_AUDIT_TOKEN or "").strip()
    if not configured_token:
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


async def _get_reusable_result(
    *, project: Project, request_id: str, db: AsyncSession
) -> TalosAuditResponse | None:
    result = await db.execute(
        select(AuditSession)
        .where(AuditSession.project_id == project.id)
        .order_by(AuditSession.updated_at.desc(), AuditSession.created_at.desc())
    )
    for session in result.scalars().all():
        payload = _extract_direct_audit_final_payload(await _load_direct_audit_messages(session_id=session.id, db=db))
        if payload is not None:
            return TalosAuditResponse(
                request_id=request_id,
                project_id=project.id,
                session_id=session.id,
                finalize_finding=payload,
                reused=True,
            )
    return None


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
        project.workspace_mode = "persistent_source"
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


@router.post("/audits", response_model=TalosAuditResponse)
async def start_talos_audit(
    payload: TalosAuditRequest,
    _: None = Depends(_require_talos_token),
    db: AsyncSession = Depends(get_db),
) -> TalosAuditResponse:
    """Create a ZIP project and return the first Finding runtime finalization.

    This request intentionally blocks until ``FinalizeFinding`` is received.
    It never invokes the follow-up report-generation loop.
    """
    archive_path = _resolve_archive_path(payload.archive_path)
    _validate_source_archive(archive_path, payload.file_sha256)
    service_user = await _get_service_user(db)

    existing_result = await db.execute(
        select(Project).where(
            Project.owner_id == service_user.id,
            Project.source_type == "zip",
            Project.repository_url == _talos_project_ref(payload.request_id),
        )
    )
    existing_project = existing_result.scalar_one_or_none()
    if existing_project is not None:
        reusable = await _get_reusable_result(project=existing_project, request_id=payload.request_id, db=db)
        if reusable is not None:
            return reusable
        raise HTTPException(status_code=409, detail="A Talos audit for this request_id already exists")

    project = await _create_project_from_archive(
        request=payload,
        archive_path=archive_path,
        service_user=service_user,
        db=db,
    )
    session = await start_direct_audit_session(
        project=project,
        content=(
            "Perform the requested source-code security audit. Start from the supplied recon context, "
            "then complete the Finding phase and call FinalizeFinding with the structured final result. "
            "Do not generate vulnerability reports."
        ),
        guardrails_enabled=False,
        db=db,
        current_user=service_user,
        generate_reports=False,
    )
    final_payload = _extract_direct_audit_final_payload(
        await _load_direct_audit_messages(session_id=session.id, db=db)
    )
    if final_payload is None:
        raise HTTPException(status_code=502, detail="Audit completed without a FinalizeFinding payload")
    return TalosAuditResponse(
        request_id=payload.request_id,
        project_id=project.id,
        session_id=session.id,
        finalize_finding=final_payload,
    )
