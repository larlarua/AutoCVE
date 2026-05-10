from __future__ import annotations

from app.core.config import settings
from app.services.agent.tools.sandbox_tool import SandboxManager


def test_sandbox_manager_maps_managed_workspace_to_host_root(monkeypatch):
    original_managed_root = settings.MANAGED_PROJECTS_ROOT
    settings.MANAGED_PROJECTS_ROOT = "/workspace/projects"
    monkeypatch.setenv("HOST_PROJECT_ROOT", r"D:\Projects\AuditAI\projects")

    try:
        resolved = SandboxManager._resolve_docker_host_workdir(
            "/workspace/projects/.auditai_workspaces/task-1/chartbrew-4.9.0"
        )
    finally:
        settings.MANAGED_PROJECTS_ROOT = original_managed_root

    assert resolved == r"D:\Projects\AuditAI\projects\.auditai_workspaces\task-1\chartbrew-4.9.0"
