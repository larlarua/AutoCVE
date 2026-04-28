from typing import Any, List, Optional
import asyncio
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Form
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel
from datetime import datetime, timezone
from pathlib import Path
import shutil
import os
import uuid
import json
import tempfile

from app.api import deps
from app.core.config import settings
from app.db.session import get_db, AsyncSessionLocal
from app.models.project import Project
from app.models.user import User
from app.models.audit import AuditTask, AuditIssue
from app.models.agent_task import AgentTask, AgentTaskStatus, AgentFinding
from app.models.user_config import UserConfig
import zipfile
from app.services.scanner import (
    scan_repo_task,
    get_github_files,
    get_gitlab_files,
    get_gitea_files,
    get_github_branches,
    get_gitlab_branches,
    get_gitea_branches,
    fetch_file_content,
    should_exclude,
    is_text_file,
)
from app.services.zip_storage import (
    delete_project_persistent_source,
    delete_project_zip,
    get_project_persistent_source_meta,
    get_project_zip_meta,
    has_project_persistent_source,
    has_project_zip,
    load_project_zip,
    materialize_project_source_from_zip,
    save_project_zip,
)

router = APIRouter()

# Schemas
class ProjectCreate(BaseModel):
    name: str
    source_type: Optional[str] = "repository"  # 'repository' 或 'zip'
    repository_url: Optional[str] = None
    repository_type: Optional[str] = "other"  # github, gitlab, other
    local_path: Optional[str] = None
    workspace_mode: Optional[str] = None
    description: Optional[str] = None
    default_branch: Optional[str] = "main"
    programming_languages: Optional[List[str]] = None

class ProjectUpdate(BaseModel):
    name: Optional[str] = None
    source_type: Optional[str] = None
    repository_url: Optional[str] = None
    repository_type: Optional[str] = None
    local_path: Optional[str] = None
    workspace_mode: Optional[str] = None
    description: Optional[str] = None
    default_branch: Optional[str] = None
    programming_languages: Optional[List[str]] = None

class OwnerSchema(BaseModel):
    id: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    role: Optional[str] = None

    class Config:
        from_attributes = True

class ProjectResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    source_type: Optional[str] = "repository"  # 'repository' 或 'zip'
    repository_url: Optional[str] = None
    repository_type: Optional[str] = None  # github, gitlab, other
    local_path: Optional[str] = None
    workspace_mode: Optional[str] = None
    default_branch: Optional[str] = None
    programming_languages: Optional[str] = None
    owner_id: str
    is_active: bool
    created_at: datetime
    updated_at: Optional[datetime] = None
    owner: Optional[OwnerSchema] = None

    class Config:
        from_attributes = True

class StatsResponse(BaseModel):
    total_projects: int
    active_projects: int
    total_tasks: int
    completed_tasks: int
    total_issues: int
    resolved_issues: int
    avg_quality_score: float = 0.0


class ManagedLocalDirectoryResponse(BaseModel):
    name: str
    path: str


class ProjectFileContentResponse(BaseModel):
    path: str
    content: str
    size: int
    truncated: bool = False


def _get_managed_projects_root() -> Path:
    managed_root = Path(settings.MANAGED_PROJECTS_ROOT).resolve()
    managed_root.mkdir(parents=True, exist_ok=True)
    return managed_root


def _normalize_managed_local_path(local_path: str) -> str:
    managed_root = _get_managed_projects_root()
    candidate = Path(local_path).resolve()

    try:
        candidate.relative_to(managed_root)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="local_path must stay within the managed projects directory",
        ) from exc

    if not candidate.exists() or not candidate.is_dir():
        raise HTTPException(status_code=400, detail="local_path does not exist or is not a directory")

    return str(candidate)


def _ensure_project_relative_path(relative_path: str) -> str:
    candidate = Path(relative_path)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise HTTPException(status_code=400, detail="path must stay inside the project root")
    normalized = candidate.as_posix().lstrip("/")
    if not normalized:
        raise HTTPException(status_code=400, detail="path is required")
    return normalized


def _build_file_content_response(*, relative_path: str, content: str) -> ProjectFileContentResponse:
    encoded = content.encode("utf-8", errors="ignore")
    size = len(encoded)
    max_size = settings.MAX_FILE_SIZE_BYTES
    truncated = size > max_size
    if truncated:
        content = encoded[:max_size].decode("utf-8", errors="ignore")
    return ProjectFileContentResponse(
        path=relative_path,
        content=content,
        size=size,
        truncated=truncated,
    )


def _normalize_zip_local_path(local_path: str | None) -> Optional[str]:
    if not local_path:
        return None
    candidate = Path(local_path)
    if not candidate.exists() or not candidate.is_dir():
        return None
    try:
        return _normalize_managed_local_path(str(candidate))
    except HTTPException:
        # Legacy ZIP projects may already point at a persisted extracted source
        # directory outside the current managed root. Preview and file listing
        # should still work as long as the stored path exists and later
        # path-resolution stays inside that project root.
        return str(candidate.resolve())


def _resolve_persistent_project_root(project: Project) -> Optional[Path]:
    normalized = _normalize_zip_local_path(project.local_path)
    if not normalized:
        return None
    return Path(normalized).resolve()


LOCAL_PROJECT_EXCLUDE_DIR_NAMES = {
    ".cache",
    ".git",
    ".idea",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    ".vs",
    ".vscode",
    "__pycache__",
    "build",
    "coverage",
    "dist",
    "env",
    "node_modules",
    "out",
    "target",
    "tmp",
    "venv",
    "vendor",
}


def _should_skip_local_directory(
    *,
    project_root: Path,
    current_root: Path,
    directory_name: str,
    exclude_patterns: list[str],
) -> bool:
    if directory_name in LOCAL_PROJECT_EXCLUDE_DIR_NAMES:
        return True

    relative_directory = (current_root / directory_name).relative_to(project_root).as_posix()
    return should_exclude(f"{relative_directory}/", exclude_patterns)


def _list_local_project_files(project_root: Path, exclude_patterns: Optional[list[str]] = None) -> list[dict[str, Any]]:
    exclude_patterns = list(exclude_patterns or [])
    files: list[dict[str, Any]] = []

    for root, dir_names, file_names in os.walk(project_root, topdown=True):
        current_root = Path(root)
        dir_names[:] = sorted(
            directory_name
            for directory_name in dir_names
            if not _should_skip_local_directory(
                project_root=project_root,
                current_root=current_root,
                directory_name=directory_name,
                exclude_patterns=exclude_patterns,
            )
        )

        for file_name in sorted(file_names):
            file_path = current_root / file_name
            relative_path = file_path.relative_to(project_root).as_posix()
            if should_exclude(relative_path, exclude_patterns):
                continue
            try:
                file_size = file_path.stat().st_size
            except OSError:
                continue
            files.append({"path": relative_path, "size": file_size})
    return files


def _read_local_text_file(file_path: Path) -> str:
    return file_path.read_text(encoding="utf-8")


def _read_zip_file_bytes(zip_path: str, relative_path: str) -> bytes:
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        with zip_ref.open(relative_path, "r") as file_handle:
            return file_handle.read()


@router.get("/managed-local-directories", response_model=List[ManagedLocalDirectoryResponse])
async def list_managed_local_directories(
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    List first-level managed project directories available for local import.
    """
    managed_root = _get_managed_projects_root()

    directories = [
        ManagedLocalDirectoryResponse(name=entry.name, path=str(entry.resolve()))
        for entry in sorted(managed_root.iterdir(), key=lambda item: item.name.lower())
        if entry.is_dir()
    ]
    return directories

@router.post("/", response_model=ProjectResponse)
async def create_project(
    *,
    db: AsyncSession = Depends(get_db),
    project_in: ProjectCreate,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Create new project.
    """
    import json
    # 根据 source_type 设置默认值
    source_type = project_in.source_type or "repository"
    normalized_local_path: Optional[str] = None

    if source_type == "local_directory":
        if not project_in.local_path:
            raise HTTPException(status_code=422, detail="local_path is required for local_directory projects")
        normalized_local_path = _normalize_managed_local_path(project_in.local_path)
        existing_result = await db.execute(
            select(Project).where(
                Project.owner_id == current_user.id,
                Project.source_type == "local_directory",
                Project.local_path == normalized_local_path,
                Project.is_active == True,
            )
        )
        if existing_result.scalars().first():
            raise HTTPException(status_code=400, detail="local directory is already registered")
    elif source_type == "zip":
        normalized_local_path = _normalize_zip_local_path(project_in.local_path)
    
    project = Project(
        name=project_in.name,
        source_type=source_type,
        repository_url=project_in.repository_url if source_type == "repository" else None,
        repository_type=project_in.repository_type or "other" if source_type == "repository" else "other",
        local_path=normalized_local_path if source_type in {"local_directory", "zip"} else None,
        workspace_mode=project_in.workspace_mode or (
            "in_place" if source_type == "local_directory" else "persistent_source" if source_type == "zip" else None
        ),
        description=project_in.description,
        default_branch=project_in.default_branch or "main",
        programming_languages=json.dumps(project_in.programming_languages or []),
        owner_id=current_user.id
    )
    db.add(project)
    await db.commit()
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.owner))
        .where(Project.id == project.id)
    )
    return result.scalars().first()

@router.get("/", response_model=List[ProjectResponse])
async def read_projects(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    include_deleted: bool = False,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Retrieve projects for current user.
    """
    query = select(Project).options(selectinload(Project.owner))
    # 只返回当前用户的项目
    query = query.where(Project.owner_id == current_user.id)
    if not include_deleted:
        query = query.where(Project.is_active == True)
    query = query.order_by(Project.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()

@router.get("/deleted", response_model=List[ProjectResponse])
async def read_deleted_projects(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Retrieve deleted (soft-deleted) projects for current user.
    """
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.owner))
        .where(Project.owner_id == current_user.id)
        .where(Project.is_active == False)
        .order_by(Project.updated_at.desc())
    )
    return result.scalars().all()

@router.get("/stats", response_model=StatsResponse)
async def get_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Get statistics for current user.
    """
    # 只统计当前用户的项目
    projects_result = await db.execute(
        select(Project).where(Project.owner_id == current_user.id)
    )
    projects = projects_result.scalars().all()
    project_ids = [p.id for p in projects]

    # 统计旧的 AuditTask
    tasks_result = await db.execute(
        select(AuditTask).where(AuditTask.project_id.in_(project_ids)) if project_ids else select(AuditTask).where(False)
    )
    tasks = tasks_result.scalars().all()
    task_ids = [t.id for t in tasks]

    # 统计旧的 AuditIssue
    issues_result = await db.execute(
        select(AuditIssue).where(AuditIssue.task_id.in_(task_ids)) if task_ids else select(AuditIssue).where(False)
    )
    issues = issues_result.scalars().all()

    # 🔥 同时统计新的 AgentTask
    agent_tasks_result = await db.execute(
        select(AgentTask).where(AgentTask.project_id.in_(project_ids)) if project_ids else select(AgentTask).where(False)
    )
    agent_tasks = agent_tasks_result.scalars().all()
    agent_task_ids = [t.id for t in agent_tasks]

    # 🔥 统计 AgentFinding
    agent_findings_result = await db.execute(
        select(AgentFinding).where(AgentFinding.task_id.in_(agent_task_ids)) if agent_task_ids else select(AgentFinding).where(False)
    )
    agent_findings = agent_findings_result.scalars().all()

    # 合并统计（旧任务 + 新 Agent 任务）
    total_tasks = len(tasks) + len(agent_tasks)
    completed_tasks = (
        len([t for t in tasks if t.status == "completed"]) +
        len([t for t in agent_tasks if t.status == AgentTaskStatus.COMPLETED])
    )
    total_issues = len(issues) + len(agent_findings)
    resolved_issues = (
        len([i for i in issues if i.status == "resolved"]) +
        len([f for f in agent_findings if f.status in ("fixed", "wont_fix", "false_positive")])
    )

    # 计算平均质量分（只统计已完成且有质量分的任务）
    quality_scores = (
        [t.quality_score for t in tasks if t.status == "completed" and t.quality_score and t.quality_score > 0] +
        [t.quality_score for t in agent_tasks if t.status == AgentTaskStatus.COMPLETED and t.quality_score and t.quality_score > 0]
    )
    avg_quality_score = sum(quality_scores) / len(quality_scores) if quality_scores else 0.0

    return {
        "total_projects": len(projects),
        "active_projects": len([p for p in projects if p.is_active]),
        "total_tasks": total_tasks,
        "completed_tasks": completed_tasks,
        "total_issues": total_issues,
        "resolved_issues": resolved_issues,
        "avg_quality_score": avg_quality_score,
    }

@router.get("/{id}", response_model=ProjectResponse)
async def read_project(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Get project by ID.
    """
    result = await db.execute(
        select(Project)
        .options(selectinload(Project.owner))
        .where(Project.id == id)
    )
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    
    # 检查权限：只有项目所有者可以查看
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权查看此项目")
    
    return project

@router.put("/{id}", response_model=ProjectResponse)
async def update_project(
    id: str,
    *,
    db: AsyncSession = Depends(get_db),
    project_in: ProjectUpdate,
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Update project.
    """
    import json
    result = await db.execute(select(Project).where(Project.id == id))
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    
    # 检查权限：只有项目所有者可以更新
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权更新此项目")
    
    update_data = project_in.model_dump(exclude_unset=True)
    target_source_type = update_data.get("source_type", project.source_type)

    if "programming_languages" in update_data and update_data["programming_languages"] is not None:
        update_data["programming_languages"] = json.dumps(update_data["programming_languages"])

    if target_source_type == "local_directory":
        local_path = update_data.get("local_path", project.local_path)
        if not local_path:
            raise HTTPException(status_code=422, detail="local_path is required for local_directory projects")

        normalized_local_path = _normalize_managed_local_path(local_path)
        existing_result = await db.execute(
            select(Project).where(
                Project.owner_id == current_user.id,
                Project.source_type == "local_directory",
                Project.local_path == normalized_local_path,
                Project.id != project.id,
                Project.is_active == True,
            )
        )
        if existing_result.scalars().first():
            raise HTTPException(status_code=400, detail="local directory is already registered")

        update_data["local_path"] = normalized_local_path
        update_data["workspace_mode"] = update_data.get("workspace_mode") or project.workspace_mode or "in_place"
    elif target_source_type == "zip":
        normalized_local_path = _normalize_zip_local_path(update_data.get("local_path", project.local_path))
        update_data["local_path"] = normalized_local_path
        update_data["workspace_mode"] = update_data.get("workspace_mode") or project.workspace_mode or "persistent_source"
    elif "source_type" in update_data and update_data["source_type"] not in {"local_directory", "zip"}:
        update_data["local_path"] = None
        update_data["workspace_mode"] = None
    
    for field, value in update_data.items():
        setattr(project, field, value)
    
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(project)
    return project

@router.delete("/{id}")
async def delete_project(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Soft delete project.
    """
    result = await db.execute(select(Project).where(Project.id == id))
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    
    # 检查权限：只有项目所有者可以删除
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权删除此项目")
    
    project.is_active = False
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "项目已删除"}

@router.post("/{id}/restore")
async def restore_project(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Restore soft-deleted project.
    """
    result = await db.execute(select(Project).where(Project.id == id))
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    
    # 检查权限：只有项目所有者可以恢复
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权恢复此项目")
    
    project.is_active = True
    project.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"message": "项目已恢复"}

@router.delete("/{id}/permanent")
async def permanently_delete_project(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Permanently delete project.
    """
    result = await db.execute(select(Project).where(Project.id == id))
    project = result.scalars().first()
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    
    # 检查权限：只有项目所有者可以永久删除
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权永久删除此项目")
    
    await db.delete(project)
    await db.commit()
    return {"message": "项目已永久删除"}


@router.get("/{id}/files")
async def get_project_files(
    id: str,
    branch: Optional[str] = None,
    exclude_patterns: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Get list of files in the project.
    可选参数:
    - branch: 指定仓库分支（仅对仓库类型项目有效）
    - exclude_patterns: JSON 格式的排除模式数组，如 ["node_modules/**", "*.log"]
    """
    project = await db.get(Project, id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    
    # Check permissions
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权查看此项目")
    
    # 解析排除模式
    parsed_exclude_patterns = []
    if exclude_patterns:
        try:
            parsed_exclude_patterns = json.loads(exclude_patterns)
        except json.JSONDecodeError:
            pass
    
    files = []
    
    if project.source_type == "zip":
        project_root = _resolve_persistent_project_root(project)
        if project_root is not None:
            local_entries = await asyncio.to_thread(
                _list_local_project_files,
                project_root,
                parsed_exclude_patterns,
            )
            return [
                entry
                for entry in local_entries
                if is_text_file(str(entry["path"]))
            ]

        zip_path = await load_project_zip(id)
        print(f"📦 ZIP项目 {id} 文件路径: {zip_path}")
        if not zip_path or not os.path.exists(zip_path):
            print(f"⚠️ ZIP文件不存在: {zip_path}")
            return []
            
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for file_info in zip_ref.infolist():
                    if not file_info.is_dir():
                        name = file_info.filename
                        # 使用统一的排除逻辑，支持用户自定义排除模式
                        if should_exclude(name, parsed_exclude_patterns):
                            continue
                        # 只显示支持的代码文件
                        if not is_text_file(name):
                            continue
                        files.append({"path": name, "size": file_info.file_size})
        except Exception as e:
            print(f"Error reading zip file: {e}")
            raise HTTPException(status_code=500, detail="无法读取项目文件")
            
    elif project.source_type == "local_directory":
        if not project.local_path:
            raise HTTPException(status_code=400, detail="local directory project is missing local_path")

        project_root = Path(project.local_path).resolve()
        if not project_root.exists() or not project_root.is_dir():
            raise HTTPException(status_code=400, detail="local project directory is unavailable")

        local_entries = await asyncio.to_thread(
            _list_local_project_files,
            project_root,
            parsed_exclude_patterns,
        )
        files.extend(entry for entry in local_entries if is_text_file(str(entry["path"])))

    elif project.source_type == "repository":
        # Handle Repository project
        if not project.repository_url:
            return []

        # Get tokens from user config
        from sqlalchemy.future import select
        from app.core.encryption import decrypt_sensitive_data
        from app.core.config import settings
        from app.services.git_ssh_service import GitSSHOperations

        SENSITIVE_OTHER_FIELDS = ['githubToken', 'gitlabToken', 'sshPrivateKey']

        result = await db.execute(
            select(UserConfig).where(UserConfig.user_id == current_user.id)
        )
        config = result.scalar_one_or_none()

        github_token = settings.GITHUB_TOKEN
        gitlab_token = settings.GITLAB_TOKEN
        ssh_private_key = None

        if config and config.other_config:
            other_config = json.loads(config.other_config)
            for field in SENSITIVE_OTHER_FIELDS:
                if field in other_config and other_config[field]:
                    decrypted_val = decrypt_sensitive_data(other_config[field])
                    if field == 'githubToken':
                        github_token = decrypted_val
                    elif field == 'gitlabToken':
                        gitlab_token = decrypted_val
                    elif field == 'sshPrivateKey':
                        ssh_private_key = decrypted_val

        # 检查是否为SSH URL
        is_ssh_url = GitSSHOperations.is_ssh_url(project.repository_url)
        target_branch = branch or project.default_branch or "main"

        try:
            if is_ssh_url:
                # 使用SSH方式获取文件列表
                if not ssh_private_key:
                    raise HTTPException(
                        status_code=400,
                        detail="仓库使用SSH URL，但未配置SSH密钥。请先在设置中生成SSH密钥。"
                    )

                print(f"🔐 使用SSH方式获取文件列表: {project.repository_url}")
                files_with_content = GitSSHOperations.get_repo_files_via_ssh(
                    project.repository_url,
                    ssh_private_key,
                    target_branch,
                    parsed_exclude_patterns
                )
                files = [{"path": f["path"], "size": len(f.get("content", ""))} for f in files_with_content]
            else:
                # 使用API方式获取文件列表
                repo_type = project.repository_type or "other"

                if repo_type == "github":
                    # 传入用户自定义排除模式
                    repo_files = await get_github_files(project.repository_url, target_branch, github_token, parsed_exclude_patterns)
                    files = [{"path": f["path"], "size": 0} for f in repo_files]
                elif repo_type == "gitlab":
                    # 传入用户自定义排除模式
                    repo_files = await get_gitlab_files(project.repository_url, target_branch, gitlab_token, parsed_exclude_patterns)
                    files = [{"path": f["path"], "size": 0} for f in repo_files]
                else:
                    raise HTTPException(status_code=400, detail="不支持的仓库类型")
        except HTTPException:
            raise
        except Exception as e:
             print(f"Error fetching repo files: {e}")
             raise HTTPException(status_code=500, detail=f"无法获取仓库文件: {str(e)}")

    return files


@router.get("/{id}/file-content", response_model=ProjectFileContentResponse)
async def get_project_file_content(
    id: str,
    path: str,
    branch: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Read a single text file from the selected project for workspace preview.
    """
    project = await db.get(Project, id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="无权查看此项目")

    relative_path = _ensure_project_relative_path(path)

    if project.source_type == "local_directory":
        if not project.local_path:
            raise HTTPException(status_code=400, detail="local directory project is missing local_path")

        project_root = Path(project.local_path).resolve()
        file_path = (project_root / relative_path).resolve()
        try:
            file_path.relative_to(project_root)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="path must stay inside the project root") from exc

        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="project file not found")
        if not is_text_file(relative_path):
            raise HTTPException(status_code=400, detail="only text files can be previewed")

        try:
            content = await asyncio.to_thread(_read_local_text_file, file_path)
        except UnicodeDecodeError:
            raise HTTPException(status_code=400, detail="file is not valid UTF-8 text")

        return _build_file_content_response(relative_path=relative_path, content=content)

    if project.source_type == "zip":
        project_root = _resolve_persistent_project_root(project)
        if project_root is not None:
            file_path = (project_root / relative_path).resolve()
            try:
                file_path.relative_to(project_root)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="path must stay inside the project root") from exc

            if not file_path.exists() or not file_path.is_file():
                raise HTTPException(status_code=404, detail="project file not found")
            if not is_text_file(relative_path):
                raise HTTPException(status_code=400, detail="only text files can be previewed")

            try:
                content = await asyncio.to_thread(_read_local_text_file, file_path)
            except UnicodeDecodeError as exc:
                raise HTTPException(status_code=400, detail="file is not valid UTF-8 text") from exc

            return _build_file_content_response(relative_path=relative_path, content=content)

        zip_path = await load_project_zip(id)
        if not zip_path or not os.path.exists(zip_path):
            raise HTTPException(status_code=404, detail="project zip not found")

        try:
            raw_content = await asyncio.to_thread(_read_zip_file_bytes, zip_path, relative_path)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail="project file not found") from exc
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=500, detail="无法读取项目文件") from exc

        try:
            content = raw_content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HTTPException(status_code=400, detail="file is not valid UTF-8 text") from exc

        return _build_file_content_response(relative_path=relative_path, content=content)

    if project.source_type == "repository":
        if not project.repository_url:
            raise HTTPException(status_code=400, detail="repository_url is required for repository projects")

        from app.core.encryption import decrypt_sensitive_data
        from app.services.git_ssh_service import GitSSHOperations

        sensitive_fields = ["githubToken", "gitlabToken", "giteaToken", "sshPrivateKey"]
        result = await db.execute(select(UserConfig).where(UserConfig.user_id == current_user.id))
        config = result.scalar_one_or_none()

        github_token = settings.GITHUB_TOKEN
        gitlab_token = settings.GITLAB_TOKEN
        gitea_token = settings.GITEA_TOKEN
        ssh_private_key = None

        if config and config.other_config:
            other_config = json.loads(config.other_config)
            for field in sensitive_fields:
                if field in other_config and other_config[field]:
                    decrypted_val = decrypt_sensitive_data(other_config[field])
                    if field == "githubToken":
                        github_token = decrypted_val
                    elif field == "gitlabToken":
                        gitlab_token = decrypted_val
                    elif field == "giteaToken":
                        gitea_token = decrypted_val
                    elif field == "sshPrivateKey":
                        ssh_private_key = decrypted_val

        target_branch = branch or project.default_branch or "main"

        if GitSSHOperations.is_ssh_url(project.repository_url):
            if not ssh_private_key:
                raise HTTPException(status_code=400, detail="repository uses SSH but ssh private key is not configured")

            files_with_content = GitSSHOperations.get_repo_files_via_ssh(
                project.repository_url,
                ssh_private_key,
                target_branch,
                [],
            )
            matched_file = next((item for item in files_with_content if item.get("path") == relative_path), None)
            if not matched_file:
                raise HTTPException(status_code=404, detail="project file not found")
            content = matched_file.get("content", "")
            return _build_file_content_response(relative_path=relative_path, content=content)

        repo_type = project.repository_type or "other"
        if repo_type == "github":
            repo_files = await get_github_files(project.repository_url, target_branch, github_token, [])
        elif repo_type == "gitlab":
            repo_files = await get_gitlab_files(project.repository_url, target_branch, gitlab_token, [])
        elif repo_type == "gitea":
            repo_files = await get_gitea_files(project.repository_url, target_branch, gitea_token, [])
        else:
            raise HTTPException(status_code=400, detail="不支持的仓库类型")

        matched_file = next((item for item in repo_files if item.get("path") == relative_path), None)
        if not matched_file:
            raise HTTPException(status_code=404, detail="project file not found")

        headers = {}
        if repo_type == "github" and github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        elif repo_type == "gitlab" and matched_file.get("token"):
            headers["PRIVATE-TOKEN"] = matched_file["token"]
        elif repo_type == "gitea" and matched_file.get("token"):
            headers["Authorization"] = f"token {matched_file['token']}"

        content = await fetch_file_content(matched_file["url"], headers)
        if content is None:
            raise HTTPException(status_code=404, detail="project file not found")

        return _build_file_content_response(relative_path=relative_path, content=content)

    raise HTTPException(status_code=400, detail="unsupported project source type")

class ScanRequest(BaseModel):
    file_paths: Optional[List[str]] = None
    full_scan: bool = True
    exclude_patterns: Optional[List[str]] = None
    branch_name: Optional[str] = None


@router.post("/{id}/scan")
async def scan_project(
    id: str,
    background_tasks: BackgroundTasks,
    scan_request: Optional[ScanRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    Start a scan task.
    """
    project = await db.get(Project, id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")

    # 获取分支和排除模式
    branch_name = scan_request.branch_name if scan_request else None
    exclude_patterns = scan_request.exclude_patterns if scan_request else None

    # Create Task Record
    task = AuditTask(
        project_id=project.id,
        created_by=current_user.id,
        task_type="repository",
        status="pending",
        branch_name=branch_name or project.default_branch or "main",
        exclude_patterns=json.dumps(exclude_patterns or []),
        scan_config=json.dumps(scan_request.dict()) if scan_request else "{}"
    )
    db.add(task)
    await db.commit()
    await db.refresh(task)

    # 获取用户配置（包含解密敏感字段）
    from app.core.encryption import decrypt_sensitive_data

    # 需要解密的敏感字段列表
    SENSITIVE_LLM_FIELDS = [
        'llmApiKey', 'geminiApiKey', 'openaiApiKey', 'claudeApiKey',
        'qwenApiKey', 'deepseekApiKey', 'zhipuApiKey', 'moonshotApiKey',
        'baiduApiKey', 'minimaxApiKey', 'doubaoApiKey'
    ]
    SENSITIVE_OTHER_FIELDS = ['githubToken', 'gitlabToken']

    def decrypt_config(config_dict: dict, sensitive_fields: list) -> dict:
        """解密配置中的敏感字段"""
        decrypted = config_dict.copy()
        for field in sensitive_fields:
            if field in decrypted and decrypted[field]:
                decrypted[field] = decrypt_sensitive_data(decrypted[field])
        return decrypted

    result = await db.execute(
        select(UserConfig).where(UserConfig.user_id == current_user.id)
    )
    config = result.scalar_one_or_none()
    user_config = {}
    if config:
        llm_config = json.loads(config.llm_config) if config.llm_config else {}
        other_config = json.loads(config.other_config) if config.other_config else {}
        # 解密敏感字段
        llm_config = decrypt_config(llm_config, SENSITIVE_LLM_FIELDS)
        other_config = decrypt_config(other_config, SENSITIVE_OTHER_FIELDS)
        user_config = {
            'llmConfig': llm_config,
            'otherConfig': other_config,
        }

    # 将扫描配置注入到 user_config 中，以便 scan_repo_task 使用
    if scan_request and scan_request.file_paths:
        user_config['scan_config'] = {'file_paths': scan_request.file_paths}

    # Trigger Background Task
    background_tasks.add_task(scan_repo_task, task.id, AsyncSessionLocal, user_config)

    return {"task_id": task.id, "status": "started"}


# ============ ZIP文件管理端点 ============

class ZipFileMetaResponse(BaseModel):
    has_file: bool
    original_filename: Optional[str] = None
    file_size: Optional[int] = None
    uploaded_at: Optional[str] = None
    has_persistent_source: bool = False
    persistent_source_path: Optional[str] = None
    persistent_source_updated_at: Optional[str] = None


class ProjectSourceArtifactDeleteRequest(BaseModel):
    delete_zip: bool = False
    delete_persistent_source: bool = False


@router.get("/{id}/zip", response_model=ZipFileMetaResponse)
async def get_project_zip_info(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get ZIP archive and persistent source metadata for a project."""
    project = await db.get(Project, id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied")

    has_file = await has_project_zip(id)
    source_meta = await get_project_persistent_source_meta(id)
    meta = await get_project_zip_meta(id)
    payload: dict[str, Any] = {
        "has_file": has_file,
        "has_persistent_source": source_meta is not None,
        "persistent_source_path": source_meta.get("path") if source_meta else None,
        "persistent_source_updated_at": source_meta.get("updated_at") if source_meta else None,
    }
    if meta:
        payload.update(
            {
                "original_filename": meta.get("original_filename"),
                "file_size": meta.get("file_size"),
                "uploaded_at": meta.get("uploaded_at"),
            }
        )
    return payload


@router.post("/{id}/zip")
async def upload_project_zip(
    id: str,
    file: UploadFile = File(...),
    keep_archive: bool = Form(True),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Upload a ZIP archive, materialize persistent source, and optionally keep the archive."""
    project = await db.get(Project, id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied")
    if project.source_type != "zip":
        raise HTTPException(status_code=400, detail="Only ZIP projects can upload ZIP archives")
    if not str(file.filename or "").lower().endswith('.zip'):
        raise HTTPException(status_code=400, detail="Please upload a ZIP file")

    temp_file_handle = tempfile.NamedTemporaryFile(delete=False, suffix='.zip')
    temp_file_path = temp_file_handle.name
    temp_file_handle.close()

    try:
        with open(temp_file_path, 'wb') as buffer:
            shutil.copyfileobj(file.file, buffer)

        file_size = os.path.getsize(temp_file_path)
        if file_size > 500 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="ZIP file size cannot exceed 500MB")

        source_meta = await materialize_project_source_from_zip(id, temp_file_path)
        archive_meta = None
        if keep_archive:
            archive_meta = await save_project_zip(id, temp_file_path, str(file.filename or 'upload.zip'))
        else:
            await delete_project_zip(id)

        project.local_path = str(source_meta.get('path') or '')
        project.workspace_mode = 'persistent_source'
        project.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(project)

        payload = {
            'message': 'ZIP archive uploaded successfully',
            'has_file': archive_meta is not None,
            'has_persistent_source': True,
            'persistent_source_path': source_meta.get('path'),
            'persistent_source_updated_at': source_meta.get('updated_at'),
            'original_filename': str(file.filename or 'upload.zip'),
            'file_size': file_size,
        }
        if archive_meta:
            payload['uploaded_at'] = archive_meta.get('uploaded_at')
        return payload
    finally:
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)


@router.delete("/{id}/zip")
async def delete_project_zip_file(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Delete only the stored ZIP archive and keep the persistent source directory."""
    project = await db.get(Project, id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied")

    deleted = await delete_project_zip(id)
    if deleted:
        return {"message": "ZIP archive deleted"}
    return {"message": "No ZIP archive found"}


@router.post("/{id}/source-artifacts/delete")
async def delete_project_source_artifacts(
    id: str,
    payload: ProjectSourceArtifactDeleteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    project = await db.get(Project, id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Permission denied")
    if not payload.delete_zip and not payload.delete_persistent_source:
        raise HTTPException(status_code=400, detail="Select at least one source artifact to delete")

    deleted_zip = False
    deleted_persistent_source = False
    if payload.delete_zip:
        deleted_zip = await delete_project_zip(id)
    if payload.delete_persistent_source:
        deleted_persistent_source = await delete_project_persistent_source(id)
        if deleted_persistent_source:
            project.local_path = None
            project.updated_at = datetime.now(timezone.utc)
    await db.commit()

    return {
        'deleted_zip': deleted_zip,
        'deleted_persistent_source': deleted_persistent_source,
    }


@router.get("/{id}/branches")
async def get_project_branches(
    id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """
    获取项目仓库的分支列表
    """
    project = await db.get(Project, id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    
    # 检查是否为仓库类型项目
    if project.source_type != "repository":
        raise HTTPException(status_code=400, detail="仅仓库类型项目支持获取分支")
    
    if not project.repository_url:
        raise HTTPException(status_code=400, detail="项目未配置仓库地址")
    
    # 获取用户配置的 Token
    from app.core.config import settings
    from app.core.encryption import decrypt_sensitive_data
    
    config = await db.execute(
        select(UserConfig).where(UserConfig.user_id == current_user.id)
    )
    config = config.scalar_one_or_none()
    
    github_token = settings.GITHUB_TOKEN
    gitea_token = settings.GITEA_TOKEN
    gitlab_token = settings.GITLAB_TOKEN

    SENSITIVE_OTHER_FIELDS = ['githubToken', 'gitlabToken', 'giteaToken']
    
    if config and config.other_config:
        import json
        other_config = json.loads(config.other_config)
        for field in SENSITIVE_OTHER_FIELDS:
            if field in other_config and other_config[field]:
                decrypted_val = decrypt_sensitive_data(other_config[field])
                if field == 'githubToken':
                    github_token = decrypted_val
                elif field == 'gitlabToken':
                    gitlab_token = decrypted_val
                elif field == 'giteaToken':
                    gitea_token = decrypted_val
    
    repo_type = project.repository_type or "other"
    
    # 详细日志
    print(f"[Branch] 项目: {project.name}, 类型: {repo_type}, URL: {project.repository_url}")
    
    try:
        if repo_type == "github":
            if not github_token:
                print("[Branch] 警告: GitHub Token 未配置，可能会遇到 API 限制")
            branches = await get_github_branches(project.repository_url, github_token)
        elif repo_type == "gitlab":
            if not gitlab_token:
                print("[Branch] 警告: GitLab Token 未配置，可能无法访问私有仓库")
            branches = await get_gitlab_branches(project.repository_url, gitlab_token)
        elif repo_type == "gitea":
            if not gitea_token:
                print("[Branch] 警告: Gitea Token 未配置，可能无法访问私有仓库")
            branches = await get_gitea_branches(project.repository_url, gitea_token)
        else:
            # 对于其他类型，返回默认分支
            print(f"[Branch] 仓库类型 '{repo_type}' 不支持获取分支，返回默认分支")
            branches = [project.default_branch or "main"]
        
        print(f"[Branch] 成功获取 {len(branches)} 个分支")
        
        # 将默认分支放在第一位
        default_branch = project.default_branch or "main"
        if default_branch in branches:
            branches.remove(default_branch)
            branches.insert(0, default_branch)
        
        return {"branches": branches, "default_branch": default_branch}
    
    except Exception as e:
        error_msg = str(e)
        print(f"[Branch] 获取分支列表失败: {error_msg}")
        # 返回默认分支作为后备
        return {
            "branches": [project.default_branch or "main"],
            "default_branch": project.default_branch or "main",
            "error": str(e)
        }
