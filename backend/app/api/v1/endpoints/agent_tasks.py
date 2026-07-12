"""AutoCVE Agent task API."""

import asyncio
import contextlib
import inspect
import json
import logging
import copy
import os
import re
import zipfile
import shutil
import hashlib
from typing import Any, Callable, List, Optional, Dict, Set
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import case, func
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from pydantic import BaseModel, Field

from app.api import deps
from app.api.v1.endpoints.config import _normalize_workflow_config, WORKFLOW_AGENT_TYPES, WORKFLOW_LOCKED_AGENTS
from app.db.session import get_db, async_session_factory
from app.models.agent_task import (
    AgentTask, AgentEvent, AgentFinding, AgentTreeNode,
    AgentTaskStatus, AgentTaskPhase, AgentEventType,
    VulnerabilitySeverity, FindingStatus,
)
from app.models.audit_session import AuditCheckpoint, AuditSession, AuditSessionMessage, AuditSessionTurn, AuditToolCall
from app.services.finding_runtime.config import FindingRuntimeStack, coerce_finding_runtime_stack
from app.services.finding_runtime.final_finding_contract import has_meaningful_poc, is_placeholder_finding
from app.models.project import Project
from app.models.user import User
from app.models.user_config import UserConfig
from app.services.agent.event_manager import EventManager
from app.services.agent.event_stream import create_agent_event_stream, event_stream_enabled
from app.services.agent.task_queue import enqueue_agent_task, should_use_worker_queue
from app.services.agent.task_executor import (
    _cancelled_tasks,
    _running_asyncio_tasks,
    _running_tasks,
    _watch_task_cancellation,
    clear_task_cancellation,
    execute_agent_task,
    is_task_cancelled,
    request_agent_task_cancellation,
)
from app.services.agent.streaming import StreamHandler, StreamEvent, StreamEventType
from app.services.git_ssh_service import GitSSHOperations
from app.services.skill_file_service import SkillFileService
from app.services.runtime_core.runtime_session_checkpoint_store import RuntimeSessionCheckpointStore
from app.core.config import settings
from app.core.encryption import decrypt_sensitive_data

logger = logging.getLogger(__name__)
router = APIRouter()

# Automatically generate managed-vulnerability reports after finalized findings are imported.
AUTO_MANAGED_REPORT_POSTPROCESSING_ENABLED = True


async def _mark_latest_runtime_session_manual_cancelled(db: AsyncSession, task_id: str) -> None:
    """Close a fully stopped runtime task at a durable resumable boundary."""
    from app.models.one_click_cve import OneClickCveBatchProject, OneClickCveProjectStatus

    batch_project = await db.scalar(
        select(OneClickCveBatchProject)
        .where(OneClickCveBatchProject.agent_task_id == task_id)
        .order_by(OneClickCveBatchProject.created_at.desc())
        .limit(1)
    )
    if batch_project is not None:
        batch_project.status = OneClickCveProjectStatus.CANCELLED
        batch_project.error_message = "用户已手动终止，可继续审计"
        batch_project.updated_at_local = datetime.now(timezone.utc)

    session = await db.scalar(
        select(AuditSession)
        .where(AuditSession.task_id == task_id, AuditSession.runtime_stack == "runtime")
        .order_by(AuditSession.created_at.desc())
        .limit(1)
    )
    if session is None or session.state == "completed":
        return
    session.state = "failed"
    runtime_state = dict(session.runtime_state_json or {})
    metadata = dict(runtime_state.get("metadata") or {})
    metadata["manual_cancel"] = {
        "status": "stopped",
        "can_resume": True,
        "stopped_at": datetime.now(timezone.utc).isoformat(),
    }
    runtime_state["metadata"] = metadata
    session.runtime_state_json = runtime_state

    latest_checkpoint = await db.scalar(
        select(AuditCheckpoint)
        .where(AuditCheckpoint.session_id == session.id)
        .order_by(AuditCheckpoint.created_at.desc())
        .limit(1)
    )
    latest_payload = dict(latest_checkpoint.state_payload or {}) if latest_checkpoint is not None else {}
    if latest_payload.get("checkpoint_kind") == "manual_cancelled":
        return
    turn_id = await db.scalar(
        select(AuditSessionTurn.id)
        .where(AuditSessionTurn.session_id == session.id)
        .order_by(AuditSessionTurn.sequence.desc())
        .limit(1)
    )
    db.add(
        AuditCheckpoint(
            session_id=session.id,
            turn_id=turn_id,
            checkpoint_type="auto",
            state_payload={
                "checkpoint_kind": "manual_cancelled",
                "resumable": True,
                "error_kind": "manual_cancelled",
                "error": "Audit manually cancelled by user",
                "phase": "task_shutdown",
            },
        )
    )

# Running task registry kept for cancellation and legacy task lookups.



# ============ Schemas ============

class AgentTaskCreate(BaseModel):
    """Schema for creating an agent audit task."""

    project_id: str = Field(..., description="Project ID")
    name: Optional[str] = Field(None, description="Task name")
    description: Optional[str] = Field(None, description="Task description")

    audit_scope: Optional[dict] = Field(None, description="Audit scope configuration")
    target_vulnerabilities: Optional[List[str]] = Field(
        default=None,
        description="Optional explicit vulnerability classes to emphasize",
    )
    verification_level: str = Field(
        "sandbox",
        description="Verification mode: analysis_only, sandbox, or generate_poc",
    )

    version_label: str = Field(..., description="Human-entered version label")
    version_tag: Optional[str] = Field(None, description="Optional repository tag")
    branch_name: Optional[str] = Field(None, description="Repository branch name")
    exclude_patterns: Optional[List[str]] = Field(
        default=["node_modules", "__pycache__", ".git", "*.min.js"],
        description="Glob patterns to exclude from the audit",
    )
    target_files: Optional[List[str]] = Field(None, description="Explicit file targets for the audit")

    max_iterations: int = Field(50, ge=1, le=200, description="Maximum agent iterations")
    timeout_seconds: int = Field(1800, ge=60, le=7200, description="Task timeout in seconds")
    finding_runtime_stack: Optional[str] = Field(None, description="Finding runtime stack: legacy or runtime")


class AgentTaskResponse(BaseModel):
    """Agent task response schema."""
    id: str
    project_id: str
    name: Optional[str]
    description: Optional[str]
    task_type: str = "agent_audit"
    status: str
    current_phase: Optional[str]
    current_step: Optional[str] = None
    version_label: Optional[str] = None
    version_tag: Optional[str] = None
    branch_name: Optional[str] = None
    commit_sha: Optional[str] = None
    repository_url_snapshot: Optional[str] = None
    
    total_files: int = 0
    indexed_files: int = 0
    analyzed_files: int = 0
    files_with_findings: int = 0
    total_chunks: int = 0
    
    total_iterations: int = 0
    tool_calls_count: int = 0
    tokens_used: int = 0
    
    findings_count: int = 0
    total_findings: int = 0
    verified_count: int = 0
    verified_findings: int = 0
    false_positive_count: int = 0
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    quality_score: float = 0.0
    security_score: Optional[float] = None
    
    # Progress metrics
    progress_percentage: float = 0.0
    
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    audit_scope: Optional[dict] = None
    target_vulnerabilities: Optional[List[str]] = None
    verification_level: Optional[str] = None
    exclude_patterns: Optional[List[str]] = None
    target_files: Optional[List[str]] = None
    
    error_message: Optional[str] = None
    runtime_session_id: Optional[str] = None
    finding_runtime_stack: str = FindingRuntimeStack.RUNTIME.value
    finding_outcome: str = "none"
    runtime_completion_mode: Optional[str] = None
    finalized_findings_count: int = 0
    recovered_candidates_count: int = 0
    handoff_ready: bool = False
    recovered_candidates: List[Dict[str, Any]] = Field(default_factory=list)
    
    class Config:
        from_attributes = True



class AgentEventResponse(BaseModel):
    """Agent event response schema."""
    id: str
    task_id: Optional[str] = None
    event_type: str
    phase: Optional[str] = None
    message: Optional[str] = None
    sequence: int
    timestamp: Optional[str] = None
    created_at: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_output: Optional[Dict[str, Any]] = None
    tool_duration_ms: Optional[int] = None
    progress_percent: Optional[float] = None
    finding_id: Optional[str] = None
    tokens_used: Optional[int] = None
    metadata: Optional[Dict[str, Any]] = None

    model_config = {
        "from_attributes": True,
        "populate_by_name": True,
    }


class AgentFindingResponse(BaseModel):
    """Agent finding response schema."""
    id: str
    task_id: str
    vulnerability_type: str
    severity: str
    title: str
    description: Optional[str] = None
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    code_snippet: Optional[str] = None
    is_verified: bool
    confidence: Optional[float] = Field(default=0.5, validation_alias="ai_confidence")
    ai_confidence: Optional[float] = None
    status: str
    report_status: Optional[str] = None
    verdict: Optional[str] = None
    suggestion: Optional[str] = None
    has_poc: Optional[bool] = None
    poc_code: Optional[str] = None
    fix_code: Optional[str] = None
    ai_explanation: Optional[str] = None
    poc: Optional[dict] = None
    source: Optional[str] = None
    sink: Optional[str] = None
    exploit_chain: List[Dict[str, Any]] = Field(default_factory=list)
    impact: Optional[str] = None
    cve_justification: Optional[str] = None
    verification_notes: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    origin: Optional[str] = None
    evidence_type: Optional[str] = None
    entry_point_refs: List[str] = Field(default_factory=list)
    priority_path_refs: List[str] = Field(default_factory=list)
    business_flow_notes: List[str] = Field(default_factory=list)
    evidence_gaps: List[str] = Field(default_factory=list)
    created_at: datetime

    model_config = {
        "from_attributes": True,
        "populate_by_name": True,
    }


class TaskSummaryResponse(BaseModel):
    """Task summary response schema."""
    task_id: str
    status: str
    security_score: Optional[int] = None
    total_findings: int
    verified_findings: int
    severity_distribution: Dict[str, int]
    vulnerability_types: Dict[str, int]
    duration_seconds: Optional[int] = None
    phases_completed: List[str]


class DebugTaskListItem(BaseModel):
    id: str
    project_id: str
    name: Optional[str]
    status: str
    created_at: datetime
    latest_event_at: Optional[str] = None
    event_count: int = 0
    agent_count: int = 0
    tool_call_count: int = 0


class DebugTraceResponse(BaseModel):
    task: Dict[str, Any]
    summary: Dict[str, Any]
    timeline: List[Dict[str, Any]]
    handoffs: List[Dict[str, Any]]



_running_orchestrators: Dict[str, Any] = {}
_running_event_managers: Dict[str, EventManager] = {}
ONE_CLICK_CVE_DEFAULT_DISABLED_AGENTS = {"scan", "triage", "verification"}
ONE_CLICK_CVE_DEFAULT_ENABLED_AGENTS = {"finding"}


async def _schedule_agent_task(background_tasks: BackgroundTasks, task_id: str) -> None:
    if should_use_worker_queue():
        await enqueue_agent_task(task_id)
        return
    background_tasks.add_task(_execute_agent_task, task_id)


def _is_one_click_cve_scope(audit_scope: Optional[Dict[str, Any]]) -> bool:
    return isinstance(audit_scope, dict) and isinstance(audit_scope.get("one_click_cve"), dict)


def _apply_workflow_agent_states(target: Dict[str, Any], states: Any, *, missing_enabled_value: bool = True) -> None:
    if isinstance(states, dict):
        for agent in WORKFLOW_AGENT_TYPES:
            raw_state = states.get(agent)
            if isinstance(raw_state, dict):
                target["agentStates"][agent]["enabled"] = bool(raw_state.get("enabled", missing_enabled_value))
            elif isinstance(raw_state, bool):
                target["agentStates"][agent]["enabled"] = raw_state


def _enforce_one_click_cve_workflow(target: Dict[str, Any]) -> None:
    for agent in ONE_CLICK_CVE_DEFAULT_DISABLED_AGENTS:
        target["agentStates"][agent]["enabled"] = False
    for agent in ONE_CLICK_CVE_DEFAULT_ENABLED_AGENTS:
        target["agentStates"][agent]["enabled"] = True


def _merge_task_workflow_config(global_workflow: Optional[Dict[str, Any]], audit_scope: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    one_click_cve_scope = _is_one_click_cve_scope(audit_scope)
    if one_click_cve_scope:
        merged = _normalize_workflow_config({})
    else:
        merged = _normalize_workflow_config(global_workflow)

    task_workflow = audit_scope.get("workflow") if isinstance(audit_scope, dict) else None
    task_states = task_workflow.get("agentStates", {}) if isinstance(task_workflow, dict) else {}
    _apply_workflow_agent_states(merged, task_states)

    if one_click_cve_scope:
        _enforce_one_click_cve_workflow(merged)

    for agent in WORKFLOW_LOCKED_AGENTS:
        merged["agentStates"][agent]["enabled"] = True
        merged["agentStates"][agent]["locked"] = True

    return merged


def _resolve_task_runtime_stack(agent_config: Any) -> str:
    if isinstance(agent_config, dict):
        raw_value = agent_config.get("finding_runtime_stack")
    else:
        raw_value = None
    if raw_value in (None, ""):
        raw_value = getattr(settings, "FINDING_RUNTIME_STACK_DEFAULT", FindingRuntimeStack.LEGACY.value)
    return coerce_finding_runtime_stack(raw_value).value


def _extract_finding_runtime_payload(result_data: Any) -> Dict[str, Any]:
    if not isinstance(result_data, dict):
        return {}
    if any(key in result_data for key in ("runtime_completion_mode", "recovered_candidates", "findings")):
        return result_data
    phases = result_data.get("phases")
    if not isinstance(phases, dict):
        return {}
    finding_phase = phases.get("finding")
    if not isinstance(finding_phase, dict):
        return {}
    data = finding_phase.get("data")
    return data if isinstance(data, dict) else {}


def _normalize_recovered_candidate(candidate: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(candidate, dict):
        return None
    normalized = {
        "title": str(candidate.get("title") or candidate.get("vulnerability_type") or "Recovered candidate"),
        "severity": str(candidate.get("severity") or "medium"),
        "vulnerability_type": str(candidate.get("vulnerability_type") or "other"),
        "description": candidate.get("description"),
        "file_path": candidate.get("file_path"),
        "line_start": candidate.get("line_start"),
        "line_end": candidate.get("line_end"),
        "report_status": candidate.get("report_status") or "recovered_candidate",
        "verdict": candidate.get("verdict"),
        "origin": candidate.get("origin") or "transcript_recovery",
        "evidence_type": candidate.get("evidence_type") or "transcript_recovery",
        "not_finalized": bool(candidate.get("not_finalized", True)),
        "source": candidate.get("source"),
        "sink": candidate.get("sink"),
        "impact": candidate.get("impact"),
        "cve_justification": candidate.get("cve_justification"),
        "verification_notes": candidate.get("verification_notes"),
        "exploit_chain": candidate.get("exploit_chain") or [],
        "references": candidate.get("references") or [],
        "evidence_gaps": candidate.get("evidence_gaps") or [],
    }
    return normalized


def _build_finding_runtime_result_snapshot(
    *,
    persisted_findings_count: int,
    finding_payload: Dict[str, Any],
    handoff: Any = None,
) -> Dict[str, Any]:
    runtime_completion_mode = finding_payload.get("runtime_completion_mode")
    recovered_candidates = [
        normalized
        for normalized in (
            _normalize_recovered_candidate(candidate)
            for candidate in (finding_payload.get("recovered_candidates") or [])
        )
        if normalized is not None
    ]
    finalized_findings_count = int(persisted_findings_count or 0)
    recovered_candidates_count = len(recovered_candidates)
    handoff_ready = bool(handoff) and runtime_completion_mode == "finalize_tool"

    if finalized_findings_count > 0:
        finding_outcome = "finalized"
    elif recovered_candidates_count > 0:
        finding_outcome = "recovered_only"
    elif runtime_completion_mode == "incomplete":
        finding_outcome = "incomplete"
    else:
        finding_outcome = "none"

    return {
        "finding_outcome": finding_outcome,
        "runtime_completion_mode": runtime_completion_mode,
        "finalized_findings_count": finalized_findings_count,
        "recovered_candidates_count": recovered_candidates_count,
        "handoff_ready": handoff_ready,
        "recovered_candidates": recovered_candidates,
    }


def _get_task_finding_runtime_result(task: AgentTask) -> Dict[str, Any]:
    agent_config = dict(task.agent_config or {})
    stored = agent_config.get("finding_runtime_result")
    if isinstance(stored, dict):
        snapshot = {
            "finding_outcome": str(stored.get("finding_outcome") or "none"),
            "runtime_completion_mode": stored.get("runtime_completion_mode"),
            "finalized_findings_count": int(stored.get("finalized_findings_count") or 0),
            "recovered_candidates_count": int(stored.get("recovered_candidates_count") or 0),
            "handoff_ready": bool(stored.get("handoff_ready", False)),
            "recovered_candidates": [
                normalized
                for normalized in (
                    _normalize_recovered_candidate(candidate)
                    for candidate in (stored.get("recovered_candidates") or [])
                )
                if normalized is not None
            ],
        }
        snapshot["recovered_candidates_count"] = len(snapshot["recovered_candidates"]) or snapshot["recovered_candidates_count"]
        return snapshot

    findings_count = int(task.findings_count or 0)
    return {
        "finding_outcome": "finalized" if findings_count > 0 else "none",
        "runtime_completion_mode": None,
        "finalized_findings_count": findings_count,
        "recovered_candidates_count": 0,
        "handoff_ready": False,
        "recovered_candidates": [],
    }


async def _restore_agents_from_checkpoints(agents: List[Any]) -> List[Dict[str, Any]]:
    restored: List[Dict[str, Any]] = []
    for agent in agents:
        restore_fn = getattr(agent, "restore_runtime_session_from_checkpoint", None)
        if not callable(restore_fn):
            continue
        payload = await restore_fn()
        if not payload:
            continue
        restored.append({
            "agent_id": getattr(agent, "agent_id", None),
            "agent_name": getattr(agent, "name", getattr(agent, "config", None).name if getattr(agent, "config", None) else None),
            "checkpoint_id": payload.get("checkpoint_id"),
        })
    return restored


async def _bootstrap_legacy_agent_memories(
    *,
    agents: List[Any],
    project_root: str,
    project_info: Dict[str, Any],
    task: AgentTask,
) -> List[Dict[str, Any]]:
    from app.db.session import get_sync_session_factory
    from app.services.runtime_core.memory_runtime import RuntimeMemoryManager

    manager = RuntimeMemoryManager(session_factory=get_sync_session_factory())
    loaded: List[Dict[str, Any]] = []
    user_message = " ".join(
        part.strip()
        for part in [
            str(task.name or "").strip(),
            str(task.description or "").strip(),
            " ".join(str(item) for item in (task.target_vulnerabilities or [])),
        ]
        if part and str(part).strip()
    ).strip() or "Audit the project for security vulnerabilities."
    recon_payload = {
        "project_info": {**dict(project_info or {}), "root": project_root},
        "project_profile": {
            "languages": list((project_info or {}).get("languages") or []),
            "frameworks": list((project_info or {}).get("frameworks") or []),
        },
        "summary": str(task.description or task.name or (project_info or {}).get("name") or "").strip(),
        "target_vulnerabilities": list(task.target_vulnerabilities or []),
        "entry_points": list(task.target_files or []),
        "priority_paths": list(task.target_files or []),
    }

    for agent in agents:
        if not callable(getattr(agent, "load_runtime_memory_bundle", None)):
            continue
        existing_memory = dict((getattr(agent.state, "metadata", {}) or {}).get("memory_runtime") or {})
        if existing_memory.get("instructions") or existing_memory.get("recalls"):
            continue
        bundle = await manager.preload(
            agent_type=getattr(agent, "agent_type").value,
            system_prompt=getattr(getattr(agent, "config", None), "system_prompt", "") or "",
            recon_payload=recon_payload,
            user_message=user_message,
            skill_context=None,
        )
        if not bundle.instructions and not bundle.recalls:
            continue
        agent.load_runtime_memory_bundle(bundle, source="task-bootstrap")
        loaded.append({
            "agent_id": getattr(agent, "agent_id", None),
            "agent_type": getattr(agent, "agent_type").value,
            "instruction_count": len(bundle.instructions),
            "recall_count": len(bundle.recalls),
        })
    return loaded


def _prepare_task_for_resume(task: AgentTask) -> AgentTask:
    previous_status = str(task.status or "").strip() or None
    task.status = AgentTaskStatus.PENDING
    task.current_phase = AgentTaskPhase.PLANNING
    task.current_step = "Resuming from latest checkpoint"
    task.error_message = None
    task.started_at = None
    task.completed_at = None
    agent_config = dict(task.agent_config or {})
    agent_config["resume_from_checkpoint"] = True
    agent_config["resume_requested_at"] = datetime.now(timezone.utc).isoformat()
    agent_config["resume_count"] = int(agent_config.get("resume_count") or 0) + 1
    if previous_status:
        agent_config["last_resume_from_status"] = previous_status
    task.agent_config = agent_config
    return task


def _mark_task_resume_restore(task: AgentTask, restored_agents: List[Dict[str, Any]] | None) -> bool:
    agent_config = dict(task.agent_config or {})
    if not agent_config.get("resume_from_checkpoint"):
        return False

    normalized_agents: List[Dict[str, Any]] = []
    for item in restored_agents or []:
        if not isinstance(item, dict):
            continue
        normalized_agents.append({
            "agent_id": str(item.get("agent_id") or "").strip() or None,
            "agent_name": str(item.get("agent_name") or "").strip() or None,
            "checkpoint_id": str(item.get("checkpoint_id") or "").strip() or None,
        })

    agent_config["resume_from_checkpoint"] = False
    agent_config["last_resume_restored_at"] = datetime.now(timezone.utc).isoformat()
    agent_config["last_resume_restore_count"] = len(normalized_agents)
    agent_config["last_resume_restored_agents"] = normalized_agents
    task.agent_config = agent_config
    if normalized_agents:
        task.current_step = f"Resumed from {len(normalized_agents)} runtime checkpoints"
    else:
        task.current_step = "Resume requested; no runtime checkpoints were found"
    return True


def _resolve_completed_task_tokens_used(*, current_tokens: int, result: Any, orchestrator: Any) -> int:
    candidates = [
        getattr(result, "tokens_used", None),
        getattr(orchestrator, "total_tokens_used", None),
        current_tokens,
    ]
    for candidate in candidates:
        try:
            value = int(candidate or 0)
        except (TypeError, ValueError):
            value = 0
        if value > 0:
            return value
    return 0


def _merge_live_agent_tree_stats(
    nodes: Dict[str, Dict[str, Any]],
    *,
    get_agent: Callable[[str], Any],
) -> Dict[str, Dict[str, Any]]:
    enriched_nodes: Dict[str, Dict[str, Any]] = {}
    for agent_id, node in nodes.items():
        enriched = dict(node)
        agent_instance = get_agent(agent_id)
        if agent_instance and hasattr(agent_instance, "get_stats"):
            try:
                stats = agent_instance.get_stats()
            except Exception:
                stats = {}
            for node_key, stats_key in (
                ("iterations", "iterations"),
                ("tool_calls", "tool_calls"),
                ("tokens_used", "tokens_used"),
            ):
                try:
                    current_value = int(enriched.get(node_key, 0) or 0)
                    stats_value = int(stats.get(stats_key, 0) or 0)
                except (TypeError, ValueError):
                    continue
                enriched[node_key] = max(current_value, stats_value)
        enriched_nodes[agent_id] = enriched
    return enriched_nodes


async def _load_runtime_session_ids(db: AsyncSession, task_ids: List[str]) -> Dict[str, str]:
    if not task_ids:
        return {}

    result = await db.execute(
        select(AuditSession.task_id, AuditSession.id)
        .where(AuditSession.task_id.in_(task_ids))
        .order_by(AuditSession.created_at.desc())
    )
    mapping: Dict[str, str] = {}
    for task_id, session_id in result.all():
        if task_id and task_id not in mapping:
            mapping[str(task_id)] = str(session_id)
    return mapping


async def _load_runtime_task_stats(db: AsyncSession, task_ids: List[str]) -> Dict[str, Dict[str, int]]:
    if not task_ids:
        return {}

    stats: Dict[str, Dict[str, int]] = {
        str(task_id): {"total_iterations": 0, "tool_calls_count": 0, "tokens_used": 0}
        for task_id in task_ids
        if task_id
    }
    turn_rows = await db.execute(
        select(AuditSession.task_id, func.count(AuditSessionTurn.id))
        .join(AuditSessionTurn, AuditSessionTurn.session_id == AuditSession.id)
        .where(AuditSession.task_id.in_(task_ids))
        .group_by(AuditSession.task_id)
    )
    for task_id, count in turn_rows.all():
        if task_id:
            stats.setdefault(str(task_id), {"total_iterations": 0, "tool_calls_count": 0, "tokens_used": 0})["total_iterations"] = int(count or 0)

    tool_rows = await db.execute(
        select(AuditSession.task_id, func.count(AuditToolCall.id))
        .join(AuditToolCall, AuditToolCall.session_id == AuditSession.id)
        .where(AuditSession.task_id.in_(task_ids))
        .group_by(AuditSession.task_id)
    )
    for task_id, count in tool_rows.all():
        if task_id:
            stats.setdefault(str(task_id), {"total_iterations": 0, "tool_calls_count": 0, "tokens_used": 0})["tool_calls_count"] = int(count or 0)

    event_rows = await db.execute(
        select(
            AgentEvent.task_id,
            func.sum(case((AgentEvent.event_type == "llm_action", 1), else_=0)),
            func.sum(case((AgentEvent.event_type == "tool_call", 1), else_=0)),
            func.sum(case((AgentEvent.event_type == "llm_usage", AgentEvent.tokens_used), else_=0)),
            func.max(AgentEvent.tokens_used),
        )
        .where(AgentEvent.task_id.in_(task_ids))
        .group_by(AgentEvent.task_id)
    )
    for task_id, llm_actions, tool_calls, usage_tokens, max_tokens in event_rows.all():
        if not task_id:
            continue
        task_stats = stats.setdefault(str(task_id), {"total_iterations": 0, "tool_calls_count": 0, "tokens_used": 0})
        task_stats["total_iterations"] = max(int(task_stats["total_iterations"] or 0), int(llm_actions or 0))
        task_stats["tool_calls_count"] = max(int(task_stats["tool_calls_count"] or 0), int(tool_calls or 0))
        task_stats["tokens_used"] = max(
            int(task_stats["tokens_used"] or 0),
            int(usage_tokens or 0),
            int(max_tokens or 0),
        )
    return stats


def _is_verification_enabled(workflow_config: Optional[Dict[str, Any]]) -> bool:
    if not isinstance(workflow_config, dict):
        return False
    agent_states = workflow_config.get('agentStates')
    if not isinstance(agent_states, dict):
        return False
    verification_state = agent_states.get('verification')
    if isinstance(verification_state, dict):
        return bool(verification_state.get('enabled', False))
    if isinstance(verification_state, bool):
        return verification_state
    return False


async def _load_latest_task_audit_session(db: AsyncSession, task_id: str) -> Optional[AuditSession]:
    result = await db.execute(
        select(AuditSession)
        .where(AuditSession.task_id == task_id)
        .order_by(AuditSession.created_at.desc())
        .limit(1)
    )
    return result.scalars().first()


async def _append_internal_audit_session_message(
    db: AsyncSession,
    *,
    session_id: str,
    role: str,
    content: str,
    name: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditSessionMessage:
    latest_sequence = await db.scalar(
        select(AuditSessionMessage.sequence)
        .where(AuditSessionMessage.session_id == session_id)
        .order_by(AuditSessionMessage.sequence.desc())
        .limit(1)
    )
    message = AuditSessionMessage(
        session_id=session_id,
        sequence=int(latest_sequence or 0) + 1,
        role=role,
        content=content,
        name=name,
        message_metadata=metadata or {},
        payload={},
    )
    db.add(message)
    await db.flush()
    return message


def _managed_reports_completed(managed_vulnerability: Any) -> bool:
    reports = list(getattr(managed_vulnerability, 'reports', []) or [])
    if getattr(managed_vulnerability, 'report_generation_status', '') != 'completed':
        return False
    if len(reports) != 3:
        return False
    reports_by_kind = {getattr(report, 'report_kind', ''): report for report in reports}
    for report_kind in ('en', 'zh', 'cve'):
        report = reports_by_kind.get(report_kind)
        if report is None:
            return False
        if getattr(report, 'generation_status', '') != 'completed':
            return False
        if not str(getattr(report, 'markdown_content', '') or '').strip():
            return False
    return True


def _managed_report_slug(managed_vulnerability: Any) -> str:
    raw = str(getattr(managed_vulnerability, "vulnerability_name", "") or getattr(managed_vulnerability, "id", "") or "vulnerability")
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw.strip().lower()).strip("._-")
    return slug or "vulnerability"


def _activity_preview(value: Any, *, limit: int = 4000) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return f"{text[:limit]}\n... (truncated, {len(text)} chars total)"


async def _latest_audit_session_message_sequence(db: AsyncSession, session_id: str) -> int:
    result = await db.execute(
        select(func.max(AuditSessionMessage.sequence))
        .where(AuditSessionMessage.session_id == session_id)
    )
    value = result.scalar_one_or_none()
    return int(value or 0)


async def _emit_managed_report_transcript_activity(
    db: AsyncSession,
    *,
    session_id: str,
    after_sequence: int,
    event_emitter: Any | None,
) -> None:
    if event_emitter is None:
        return

    result = await db.execute(
        select(AuditSessionMessage)
        .where(AuditSessionMessage.session_id == session_id)
        .where(AuditSessionMessage.sequence > after_sequence)
        .order_by(AuditSessionMessage.sequence)
    )
    messages = list(result.scalars().all())
    for message in messages:
        metadata = dict(message.message_metadata or {})
        payload = dict(message.payload or {})
        role = str(message.role or "")
        name = str(message.name or "")
        event_metadata = {
            "audit_session_id": session_id,
            "audit_message_id": message.id,
            "audit_message_sequence": message.sequence,
            "kind": metadata.get("kind") or "managed_report_transcript",
        }
        if role == "user" and name == "managed_report_generator":
            await event_emitter.emit_info(
                "Managed report generation prompt:\n" + _activity_preview(message.content),
                metadata=event_metadata,
            )
            continue
        if role == "assistant":
            content = _activity_preview(message.content)
            if not content:
                content = "Model response contained no text; it proceeded via tool call or runtime control message."
            await event_emitter.emit_info(
                "Managed report model response:\n" + content,
                metadata=event_metadata,
            )
            continue
        if role == "tool_use":
            tool_name = name or str(payload.get("tool_name") or "unknown")
            tool_input = payload.get("input") if isinstance(payload.get("input"), dict) else {}
            await event_emitter.emit_tool_call(
                tool_name,
                tool_input,
                message=f"Managed report tool call: {tool_name}",
            )
            continue
        if role == "tool_result":
            tool_name = name or str(payload.get("tool_name") or "unknown")
            tool_output = payload.get("output")
            if not isinstance(tool_output, dict):
                tool_output = {"result": _activity_preview(message.content)}
            duration_ms = int((message.message_metadata or {}).get("duration_ms") or 0)
            await event_emitter.emit_tool_result(
                tool_name,
                tool_output,
                duration_ms,
                message=f"Managed report tool result: {_activity_preview(message.content, limit=500)}",
            )


async def _generate_managed_report_bundle_from_session(
    db: AsyncSession,
    *,
    session: AuditSession,
    task: AgentTask,
    finding: AgentFinding,
    managed_vulnerability: Any,
    report_service: Any,
):
    if session.runtime_stack == FindingRuntimeStack.RUNTIME.value:
        from app.api.v1.endpoints.audit_sessions import _build_runtime_follow_up_context

        bridge, sandbox_manager, model_name, _max_turns = await _build_runtime_follow_up_context(session=session, db=db)
        finding_id = str(getattr(finding, "id", "") or getattr(managed_vulnerability, "finding_id", "") or "").strip()
        report_slug = _managed_report_slug(managed_vulnerability)
        bridge.prepare_report_generation_continuation(
            session_id=session.id,
            system_prompt=report_service.build_generation_system_prompt(),
            context_message=report_service.build_generation_context_message(
                vulnerability=managed_vulnerability,
                finding_id=finding_id,
                report_slug=report_slug,
            ),
            metadata={
                "kind": "internal_managed_report_request",
                "finding_id": finding_id,
                "managed_vulnerability_id": getattr(managed_vulnerability, "id", None),
                "report_slug": report_slug,
            },
        )
        try:
            continuation = await bridge.continue_session_until_report_payload(
                session_id=session.id,
                model_name=model_name,
                max_turns=None,
                payload_extractor=report_service.extract_generation_payload_from_snapshot,
                finalizer_prompts=[],
                terminal_action_nudge_message=report_service.build_generation_terminal_nudge(),
                fallback_payload_builder=lambda _: None,
            )
            bundle = continuation.get("final_payload")
            if bundle is None:
                raise ValueError("Runtime report continuation did not return a report bundle")
            return report_service.coerce_generation_result(bundle)
        finally:
            try:
                await sandbox_manager.cleanup()
            except Exception:
                logger.debug("Managed-report runtime sandbox cleanup skipped", exc_info=True)

    prompt = report_service.build_generation_prompt(vulnerability=managed_vulnerability)
    from app.services.llm.service import LLMService

    user_config = await _get_user_config(db, task.created_by)
    llm_service = LLMService(user_config=user_config)
    response = await llm_service.chat_completion(
        messages=[{"role": "user", "content": prompt}],
        agent_type="finding",
    )
    raw_content = str((response or {}).get("content") or "").strip()
    return report_service.parse_generation_payload(raw_content)


async def _auto_generate_managed_vulnerability_reports(
    db: AsyncSession,
    *,
    task: AgentTask,
    workflow_config: Optional[Dict[str, Any]],
    findings: Optional[List[AgentFinding]] = None,
    event_emitter: Any | None = None,
) -> Dict[str, int]:
    del workflow_config

    persisted_findings = list(findings or await _load_task_findings(db, task.id))
    if not persisted_findings:
        return {'generated': 0, 'failed': 0, 'skipped': 0}

    from app.services.managed_vulnerability_service import ManagedVulnerabilityService
    from app.services.vulnerability_report_generation import VulnerabilityReportGenerationService

    managed_service = ManagedVulnerabilityService(db)
    report_service = VulnerabilityReportGenerationService()
    session = await _load_latest_task_audit_session(db, task.id)

    stats = {'generated': 0, 'failed': 0, 'skipped': 0}
    for finding in persisted_findings:
        managed = await managed_service.create_from_finding(task=task, finding=finding)
        if _managed_reports_completed(managed):
            stats['skipped'] += 1
            continue

        prompt = report_service.build_generation_prompt(vulnerability=managed)
        if event_emitter is not None:
            await event_emitter.emit_info(
                f"Starting managed vulnerability report generation for {managed.vulnerability_name}"
            )
        activity_after_sequence = 0
        if session is not None and event_emitter is not None:
            activity_after_sequence = await _latest_audit_session_message_sequence(db, session.id)

        try:
            if session is not None and session.runtime_stack == FindingRuntimeStack.RUNTIME.value:
                # Runtime report generation writes its own committed transcript message
                # through AuditSessionStore before the continuation starts.
                pass
            elif session is not None:
                await _append_internal_audit_session_message(
                    db,
                    session_id=session.id,
                    role='user',
                    content=prompt,
                    name='managed_report_generator',
                    metadata={
                        'kind': 'internal_managed_report_request',
                        'finding_id': finding.id,
                        'managed_vulnerability_id': managed.id,
                        'report_slug': _managed_report_slug(managed),
                    },
                )
            if session is not None:
                generated_bundle = await _generate_managed_report_bundle_from_session(
                    db,
                    session=session,
                    task=task,
                    finding=finding,
                    managed_vulnerability=managed,
                    report_service=report_service,
                )
            else:
                from app.services.llm.service import LLMService

                user_config = await _get_user_config(db, task.created_by)
                llm_service = LLMService(user_config=user_config)
                response = await llm_service.chat_completion(
                    messages=[{"role": "user", "content": prompt}],
                    agent_type="finding",
                )
                raw_content = str((response or {}).get("content") or "").strip()
                generated_bundle = report_service.parse_generation_payload(raw_content)
            generated_bundle = report_service.coerce_generation_result(generated_bundle)
            report_service.apply_generated_reports(vulnerability=managed, result=generated_bundle)
            if session is not None:
                await _append_internal_audit_session_message(
                    db,
                    session_id=session.id,
                    role='assistant',
                    content='Managed vulnerability reports finalized: English, Chinese, and CVE helper Markdown were generated.',
                    name='managed_report_generator',
                    metadata={
                        'kind': 'internal_managed_report_complete',
                        'finding_id': finding.id,
                        'managed_vulnerability_id': managed.id,
                        'report_slug': _managed_report_slug(managed),
                    },
                )
                await _emit_managed_report_transcript_activity(
                    db,
                    session_id=session.id,
                    after_sequence=activity_after_sequence,
                    event_emitter=event_emitter,
                )
            if event_emitter is not None:
                await event_emitter.emit_info(
                    f"Generated EN/ZH/CVE managed vulnerability reports for {managed.vulnerability_name}"
                )
            stats['generated'] += 1
        except Exception as exc:
            managed.report_generation_status = 'failed'
            for report in list(getattr(managed, 'reports', []) or []):
                report.generation_status = 'failed'
            if session is not None:
                await _append_internal_audit_session_message(
                    db,
                    session_id=session.id,
                    role='assistant',
                    content=f"Managed report generation failed: {exc}",
                    name='managed_report_generator',
                    metadata={
                        'kind': 'internal_managed_report_error',
                        'finding_id': finding.id,
                        'managed_vulnerability_id': managed.id,
                    },
                )
                await _emit_managed_report_transcript_activity(
                    db,
                    session_id=session.id,
                    after_sequence=activity_after_sequence,
                    event_emitter=event_emitter,
                )
            stats['failed'] += 1
            logger.exception('Managed vulnerability report generation failed for finding %s', finding.id)
            if event_emitter is not None:
                await event_emitter.emit_info(
                    f"Managed vulnerability report generation failed for {managed.vulnerability_name}: {exc}"
                )
        await db.flush()
    return stats


async def _sync_managed_vulnerability_records(
    db: AsyncSession,
    *,
    task: AgentTask,
    findings: Optional[List[AgentFinding]] = None,
) -> Dict[str, int]:
    persisted_findings = list(findings or await _load_task_findings(db, task.id))
    if not persisted_findings:
        return {'created': 0, 'existing': 0, 'failed': 0}

    from app.models.managed_vulnerability import ManagedVulnerability
    from app.services.managed_vulnerability_service import ManagedVulnerabilityService

    finding_ids = [
        str(getattr(finding, 'id', '') or '').strip()
        for finding in persisted_findings
        if str(getattr(finding, 'id', '') or '').strip()
    ]
    existing_ids: set[str] = set()
    if finding_ids:
        existing_result = await db.execute(
            select(ManagedVulnerability.finding_id).where(ManagedVulnerability.finding_id.in_(finding_ids))
        )
        existing_ids = {str(item) for item in existing_result.scalars().all()}

    managed_service = ManagedVulnerabilityService(db)
    stats = {'created': 0, 'existing': 0, 'failed': 0}
    for finding in persisted_findings:
        finding_id = str(getattr(finding, 'id', '') or '').strip()
        try:
            await managed_service.create_from_finding(task=task, finding=finding)
            if finding_id in existing_ids:
                stats['existing'] += 1
            else:
                stats['created'] += 1
                if finding_id:
                    existing_ids.add(finding_id)
        except Exception:
            stats['failed'] += 1
            logger.exception('Managed vulnerability record sync failed for finding %s', finding_id or '<unknown>')
    await db.flush()
    return stats


def _disabled_managed_report_stats(findings: Optional[List[AgentFinding]] = None) -> Dict[str, int]:
    return {'generated': 0, 'failed': 0, 'skipped': len(findings or [])}



async def _execute_agent_task_impl(task_id: str):
    """Execute an agent audit task in the background."""
    import time
    from app.core.config import settings
    from app.services.agent.agents import (
        OrchestratorAgent,
        ReconAgent,
        AnalysisAgent,
        ScanAgent,
        TriageAgent,
        FindingAgent,
        VerificationAgent,
    )
    from app.services.agent.core import agent_registry
    from app.services.agent.event_manager import EventManager, AgentEventEmitter
    from app.services.agent.tools import SandboxManager
    from app.services.llm.service import LLMService

    logger.info(f"Starting execution for task {task_id}")
    sandbox_manager = SandboxManager()
    await sandbox_manager.initialize()

    event_stream = create_agent_event_stream() if event_stream_enabled() else None
    event_manager = EventManager(
        db_session_factory=async_session_factory,
        event_stream=event_stream,
    )
    event_manager.create_queue(task_id)
    event_emitter = AgentEventEmitter(task_id, event_manager)
    _running_event_managers[task_id] = event_manager

    async with async_session_factory() as db:
        orchestrator = None
        project_root = None
        start_time = time.time()
        try:
            task = await db.get(AgentTask, task_id, options=[selectinload(AgentTask.project)])
            if not task:
                logger.error(f"Task {task_id} not found")
                return
            project = task.project
            if not project:
                logger.error(f"Project not found for task {task_id}")
                return

            if task.status == AgentTaskStatus.CANCELLED or is_task_cancelled(task_id):
                raise asyncio.CancelledError("Task cancelled before execution")

            task.status = AgentTaskStatus.RUNNING
            task.started_at = datetime.now(timezone.utc)
            task.current_phase = AgentTaskPhase.PLANNING
            await db.commit()
            await event_emitter.emit_phase_start("preparation", f"Starting audit for {project.name}")

            user_config = await _get_user_config(db, task.created_by)
            other_config = (user_config or {}).get("otherConfig", {})
            github_token = other_config.get("githubToken") or settings.GITHUB_TOKEN
            gitlab_token = other_config.get("gitlabToken") or settings.GITLAB_TOKEN
            gitea_token = other_config.get("giteaToken") or settings.GITEA_TOKEN
            ssh_private_key = None
            if other_config.get("sshPrivateKey"):
                try:
                    ssh_private_key = decrypt_sensitive_data(other_config["sshPrivateKey"])
                except Exception as exc:
                    logger.warning(f"Failed to decrypt SSH private key: {exc}")

            project_root = await _get_project_root(
                project,
                task_id,
                task.branch_name,
                github_token=github_token,
                gitlab_token=gitlab_token,
                gitea_token=gitea_token,
                ssh_private_key=ssh_private_key,
                event_emitter=event_emitter,
            )

            if task.target_files:
                valid_target_files = [
                    file_path for file_path in task.target_files
                    if os.path.exists(os.path.join(project_root, file_path))
                ]
                if valid_target_files:
                    task.target_files = valid_target_files
                else:
                    task.target_files = None
                    await event_emitter.emit_warning("No valid target files remained after project preparation; scanning full project.")
                await db.commit()

            if is_task_cancelled(task_id):
                raise asyncio.CancelledError("Task cancelled during preparation")

            def build_agent_user_config(agent_name: str | None) -> dict:
                merged = copy.deepcopy(user_config or {})
                llm_payload = copy.deepcopy((merged or {}).get("llmConfig", {}) or {})
                agent_configs = llm_payload.get("agentConfigs") or {}
                override = agent_configs.get(agent_name or "") if agent_name else None
                if isinstance(override, dict) and override.get("enabled"):
                    for key in (
                        "llmProvider",
                        "llmApiKey",
                        "llmModel",
                        "llmBaseUrl",
                        "llmTimeout",
                        "llmTemperature",
                        "llmTopP",
                        "llmMaxTokens",
                        "alwaysThinkingEnabled",
                    ):
                        value = override.get(key)
                        if value not in (None, ""):
                            llm_payload[key] = value
                    override_env = override.get("env")
                    if isinstance(override_env, dict) and override_env:
                        base_env = llm_payload.get("env") if isinstance(llm_payload.get("env"), dict) else {}
                        llm_payload["env"] = {**base_env, **override_env}
                merged["llmConfig"] = llm_payload
                return merged

            def resolve_agent_max_iterations(agent_name: str, default_value: int) -> int:
                llm_payload = (user_config or {}).get("llmConfig", {}) or {}
                agent_configs = llm_payload.get("agentConfigs") or {}
                override = agent_configs.get(agent_name) or {}
                raw_value = override.get("maxIterations") if isinstance(override, dict) else None
                try:
                    parsed = int(raw_value)
                except (TypeError, ValueError):
                    return default_value
                return parsed if parsed > 0 else default_value

            def resolve_runtime_turn_limit(agent_name: str) -> int | None:
                llm_payload = (user_config or {}).get("llmConfig", {}) or {}
                agent_configs = llm_payload.get("agentConfigs") or {}
                override = agent_configs.get(agent_name) or {}
                raw_value = override.get("maxIterations") if isinstance(override, dict) else None
                try:
                    parsed = int(raw_value)
                except (TypeError, ValueError):
                    return None
                return parsed if parsed > 0 else None

            orchestrator_llm_service = LLMService(user_config=build_agent_user_config("orchestrator"))
            recon_llm_service = LLMService(user_config=build_agent_user_config("recon"))
            analysis_llm_service = LLMService(user_config=build_agent_user_config("analysis"))
            scan_llm_service = LLMService(user_config=build_agent_user_config("scan"))
            triage_llm_service = LLMService(user_config=build_agent_user_config("triage"))
            finding_llm_service = LLMService(user_config=build_agent_user_config("finding"))
            verification_llm_service = LLMService(user_config=build_agent_user_config("verification"))
            runtime_session_checkpoint_store = RuntimeSessionCheckpointStore(session_factory=async_session_factory)
            tools = await _initialize_tools(
                project_root,
                orchestrator_llm_service,
                user_config,
                sandbox_manager=sandbox_manager,
                exclude_patterns=task.exclude_patterns,
                target_files=task.target_files,
                project_id=str(project.id),
                event_emitter=event_emitter,
                task_id=task_id,
                user_id=task.created_by,
            )

            recon_agent = ReconAgent(llm_service=recon_llm_service, tools=tools.get("recon", {}), event_emitter=event_emitter)
            analysis_agent = AnalysisAgent(llm_service=analysis_llm_service, tools=tools.get("analysis", {}), event_emitter=event_emitter)
            scan_agent = ScanAgent(llm_service=scan_llm_service, tools=tools.get("scan", {}), event_emitter=event_emitter)
            triage_agent = TriageAgent(llm_service=triage_llm_service, tools=tools.get("triage", {}), event_emitter=event_emitter)
            finding_agent = FindingAgent(llm_service=finding_llm_service, tools=tools.get("finding", {}), event_emitter=event_emitter)
            verification_agent = VerificationAgent(llm_service=verification_llm_service, tools=tools.get("verification", {}), event_emitter=event_emitter)

            orchestrator = OrchestratorAgent(
                llm_service=orchestrator_llm_service,
                tools=tools.get("orchestrator", {}),
                event_emitter=event_emitter,
                sub_agents={
                    "recon": recon_agent,
                    "scan": scan_agent,
                    "triage": triage_agent,
                    "finding": finding_agent,
                    "analysis": analysis_agent,
                    "verification": verification_agent,
                },
            )

            orchestrator.config.max_iterations = resolve_agent_max_iterations("orchestrator", orchestrator.config.max_iterations)
            recon_agent.config.max_iterations = resolve_agent_max_iterations("recon", recon_agent.config.max_iterations)
            scan_agent.config.max_iterations = resolve_agent_max_iterations("scan", scan_agent.config.max_iterations)
            triage_agent.config.max_iterations = resolve_agent_max_iterations("triage", triage_agent.config.max_iterations)
            finding_agent.config.max_iterations = resolve_agent_max_iterations("finding", finding_agent.config.max_iterations)
            verification_agent.config.max_iterations = resolve_agent_max_iterations("verification", verification_agent.config.max_iterations)

            def check_global_cancel() -> bool:
                return is_task_cancelled(task_id)

            legacy_agents = [orchestrator, recon_agent, analysis_agent, scan_agent, triage_agent, finding_agent, verification_agent]
            for agent in legacy_agents:
                agent.set_cancel_callback(check_global_cancel)
                agent.configure_runtime_session_persistence(task_id=task_id, checkpoint_store=runtime_session_checkpoint_store)
            restored_agents = await _restore_agents_from_checkpoints(legacy_agents)
            if _mark_task_resume_restore(task, restored_agents):
                await db.commit()

            _running_orchestrators[task_id] = orchestrator
            _running_tasks[task_id] = orchestrator
            _running_event_managers[task_id] = event_manager
            agent_registry.clear()
            orchestrator._register_to_registry(task="Root orchestrator for security audit")
            if restored_agents:
                await event_emitter.emit_info(
                    f"Restored runtime session checkpoints for {len(restored_agents)} agents",
                    metadata={"restored_agents": restored_agents},
                )

            project_info = await _collect_project_info(
                project_root,
                project.name,
                exclude_patterns=task.exclude_patterns,
                target_files=task.target_files,
            )
            task.total_files = project_info.get("file_count", 0)
            await db.commit()

            preloaded_memories = await _bootstrap_legacy_agent_memories(
                agents=legacy_agents,
                project_root=project_root,
                project_info=project_info,
                task=task,
            )
            if preloaded_memories:
                await event_emitter.emit_info(
                    f"Preloaded runtime memories for {len(preloaded_memories)} agents",
                    metadata={"preloaded_memories": preloaded_memories},
                )

            runtime_agent_config = dict(task.agent_config or {})
            finding_runtime_stack = runtime_agent_config.get("finding_runtime_stack") or "legacy"
            global_workflow_config = (other_config or {}).get("workflowConfig", {})
            if _is_one_click_cve_scope(task.audit_scope):
                global_workflow_config = await _get_raw_user_workflow_config(db, task.created_by)
            workflow_config = _merge_task_workflow_config(global_workflow_config, task.audit_scope)
            workflow_config["finding_runtime_stack"] = finding_runtime_stack
            input_data = {
                "project_id": str(project.id),
                "project_info": project_info,
                "config": {
                    "target_vulnerabilities": task.target_vulnerabilities or [],
                    "verification_level": task.verification_level or "sandbox",
                    "exclude_patterns": task.exclude_patterns or [],
                    "target_files": task.target_files or [],
                    "max_iterations": task.max_iterations or 50,
                    "finding_runtime_max_iterations": resolve_runtime_turn_limit("finding"),
                    "user_id": task.created_by,
                    "finding_runtime_stack": finding_runtime_stack,
                    "workflow": workflow_config,
                },
                "project_root": project_root,
                "task_id": task_id,
                "finding_runtime_stack": finding_runtime_stack,
            }

            task.current_phase = AgentTaskPhase.ANALYSIS
            await db.commit()
            await event_emitter.emit_phase_start("orchestration", "Starting orchestrated security audit")

            run_task = asyncio.create_task(orchestrator.run(input_data))
            _running_asyncio_tasks[task_id] = run_task
            cancel_watch_task = asyncio.create_task(
                _watch_task_cancellation(
                    task_id=task_id,
                    run_task=run_task,
                    session_factory=async_session_factory,
                )
            )
            try:
                result = await run_task
            finally:
                cancel_watch_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await cancel_watch_task
                _running_asyncio_tasks.pop(task_id, None)

            await db.refresh(task)
            duration_ms = int((time.time() - start_time) * 1000)
            task.completed_at = datetime.now(timezone.utc)

            if result.success:
                findings = (result.data or {}).get("findings", []) if isinstance(result.data, dict) else []
                saved_count = await _save_findings(db, task_id, findings, project_root=project_root)
                task.status = AgentTaskStatus.CANCELLED if is_task_cancelled(task_id) else AgentTaskStatus.COMPLETED
                task.current_phase = AgentTaskPhase.REPORTING
                task.security_score = _calculate_security_score(findings)
                task.total_iterations = getattr(orchestrator, "iteration_count", task.total_iterations or 0)
                task.tool_calls_count = getattr(orchestrator, "tool_call_count", task.tool_calls_count or 0)
                task.tokens_used = _resolve_completed_task_tokens_used(
                    current_tokens=task.tokens_used or 0,
                    result=result,
                    orchestrator=orchestrator,
                )
                runtime_stats = (await _load_runtime_task_stats(db, [task_id])).get(str(task_id), {})
                if runtime_stats.get("total_iterations"):
                    task.total_iterations = max(int(task.total_iterations or 0), int(runtime_stats["total_iterations"]))
                if runtime_stats.get("tool_calls_count"):
                    task.tool_calls_count = max(int(task.tool_calls_count or 0), int(runtime_stats["tool_calls_count"]))
                if runtime_stats.get("tokens_used"):
                    task.tokens_used = max(int(task.tokens_used or 0), int(runtime_stats["tokens_used"]))
                task.analyzed_files = task.total_files
                task.duration_ms = duration_ms
                saved_findings = await _load_task_findings(db, task_id)
                _apply_task_finding_metrics(task, saved_findings)
                runtime_agent_config = dict(task.agent_config or {})
                runtime_agent_config["finding_runtime_result"] = _build_finding_runtime_result_snapshot(
                    persisted_findings_count=len(saved_findings),
                    finding_payload=_extract_finding_runtime_payload(result.data),
                    handoff=getattr(result, "handoff", None),
                )
                task.agent_config = runtime_agent_config
                managed_record_stats = await _sync_managed_vulnerability_records(
                    db,
                    task=task,
                    findings=saved_findings,
                )
                if AUTO_MANAGED_REPORT_POSTPROCESSING_ENABLED:
                    managed_report_stats = await _auto_generate_managed_vulnerability_reports(
                        db,
                        task=task,
                        workflow_config=workflow_config,
                        findings=saved_findings,
                        event_emitter=event_emitter,
                    )
                else:
                    managed_report_stats = _disabled_managed_report_stats(saved_findings)
                project_ref = await db.get(Project, task.project_id)
                if project_ref:
                    from app.services.task_report_service import generate_task_report
                    await generate_task_report(db, task, project_ref, saved_findings)
                await db.commit()
                if managed_report_stats.get("generated"):
                    await event_emitter.emit_info(
                        f"Generated managed vulnerability reports for {managed_report_stats['generated']} findings"
                    )
                elif managed_report_stats.get("failed"):
                    await event_emitter.emit_info(
                        f"Managed vulnerability report generation failed for {managed_report_stats['failed']} findings"
                    )
                if managed_record_stats.get("created"):
                    await event_emitter.emit_info(
                        f"Imported {managed_record_stats['created']} findings into vulnerability management"
                    )
                elif managed_record_stats.get("failed"):
                    await event_emitter.emit_info(
                        f"Managed vulnerability import failed for {managed_record_stats['failed']} findings"
                    )
                await event_emitter.emit_info("Final vulnerability report generated")
                await event_emitter.emit_phase_complete("reporting", f"Audit completed with {saved_count} findings")
            else:
                task_was_cancelled = is_task_cancelled(task_id)
                task.status = AgentTaskStatus.CANCELLED if task_was_cancelled else AgentTaskStatus.FAILED
                task.completed_at = datetime.now(timezone.utc)
                task.error_message = result.error if hasattr(result, "error") else "Unknown execution error"
                task.duration_ms = duration_ms
                runtime_stats = (await _load_runtime_task_stats(db, [task_id])).get(str(task_id), {})
                if runtime_stats.get("total_iterations"):
                    task.total_iterations = max(int(task.total_iterations or 0), int(runtime_stats["total_iterations"]))
                if runtime_stats.get("tool_calls_count"):
                    task.tool_calls_count = max(int(task.tool_calls_count or 0), int(runtime_stats["tool_calls_count"]))
                if runtime_stats.get("tokens_used"):
                    task.tokens_used = max(int(task.tokens_used or 0), int(runtime_stats["tokens_used"]))
                if task_was_cancelled:
                    await _mark_latest_runtime_session_manual_cancelled(db, task_id)
                await db.commit()
                await event_emitter.emit_error(task.error_message or "Task failed")

        except asyncio.CancelledError:
            logger.info(f"Task {task_id} cancelled")
            task = await db.get(AgentTask, task_id)
            if task:
                existing_error_message = task.error_message
                task.status = AgentTaskStatus.CANCELLED
                task.completed_at = datetime.now(timezone.utc)
                task.error_message = existing_error_message or "Task cancelled"
                task.duration_ms = int((time.time() - start_time) * 1000)
                runtime_stats = (await _load_runtime_task_stats(db, [task_id])).get(str(task_id), {})
                if runtime_stats.get("total_iterations"):
                    task.total_iterations = max(int(task.total_iterations or 0), int(runtime_stats["total_iterations"]))
                if runtime_stats.get("tool_calls_count"):
                    task.tool_calls_count = max(int(task.tool_calls_count or 0), int(runtime_stats["tool_calls_count"]))
                if runtime_stats.get("tokens_used"):
                    task.tokens_used = max(int(task.tokens_used or 0), int(runtime_stats["tokens_used"]))
                await _mark_latest_runtime_session_manual_cancelled(db, task_id)
                await db.commit()
            await event_emitter.emit_warning("Task cancelled")
        except Exception as exc:
            logger.exception(f"Task {task_id} failed: {exc}")
            task = await db.get(AgentTask, task_id)
            if task:
                task.status = AgentTaskStatus.FAILED
                task.completed_at = datetime.now(timezone.utc)
                task.error_message = str(exc)
                await db.commit()
            await event_emitter.emit_error(str(exc))
        finally:
            try:
                async with async_session_factory() as save_db:
                    await _save_agent_tree(save_db, task_id)
            except Exception as save_error:
                logger.error(f"Failed to save agent tree: {save_error}")

            _running_orchestrators.pop(task_id, None)
            _running_tasks.pop(task_id, None)
            _running_event_managers.pop(task_id, None)
            _running_asyncio_tasks.pop(task_id, None)
            _cancelled_tasks.discard(task_id)
            agent_registry.clear()

            try:
                await sandbox_manager.cleanup()
            except Exception:
                logger.debug("Sandbox cleanup skipped", exc_info=True)
            try:
                await event_manager.close()
            except Exception:
                logger.debug("Event manager cleanup skipped", exc_info=True)


_execute_agent_task = execute_agent_task


async def _get_user_config(db: AsyncSession, user_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Load merged user config for task execution."""
    if not user_id:
        return None

    try:
        from app.api.v1.endpoints.config import _get_user_config_record, _merge_user_config

        record = await _get_user_config_record(db, user_id)
        return _merge_user_config(record)
    except Exception as e:
        logger.warning(f"Failed to get user config: {e}")

    return None


async def _get_raw_user_workflow_config(db: AsyncSession, user_id: Optional[str]) -> Dict[str, Any]:
    """Load only workflow settings explicitly persisted by the user."""
    if not user_id:
        return {}

    try:
        from app.api.v1.endpoints.config import _get_user_config_record

        record = await _get_user_config_record(db, user_id)
        if record is None or not record.other_config:
            return {}
        other_config = json.loads(record.other_config)
        workflow_config = other_config.get("workflowConfig")
        return workflow_config if isinstance(workflow_config, dict) else {}
    except Exception as exc:
        logger.warning(f"Failed to get raw user workflow config: {exc}")
        return {}


async def _initialize_tools(
    project_root: str,
    llm_service,
    user_config: Optional[Dict[str, Any]],
    sandbox_manager: Any,
    exclude_patterns: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
    project_id: Optional[str] = None,
    event_emitter: Optional[Any] = None,
    task_id: Optional[str] = None,
    user_id: Optional[str] = None,
) -> Dict[str, Dict[str, Any]]:
    """Initialize toolsets for each agent stage."""
    from app.services.agent.tools import (
        FileReadTool,
        ReadManyFilesTool,
        FileSearchTool,
        ListFilesTool,
        PatternMatchTool,
        DataFlowAnalysisTool,
        SemgrepTool,
        BanditTool,
        GitleaksTool,
        NpmAuditTool,
        SafetyTool,
        TruffleHogTool,
        OSVScannerTool,
        ThinkTool,
        ReflectTool,
        CreateVulnerabilityReportTool,
        SkillBodyTool,
        SkillResourceTool,
        SandboxTool,
        build_shared_agent_tool_catalog,
        build_agent_skill_tools,
        build_agent_tool_catalog,
    )
    async def emit(message: str, level: str = "info") -> None:
        if not event_emitter:
            return
        try:
            if level == "warning":
                await event_emitter.emit_warning(message)
            elif level == "error":
                await event_emitter.emit_error(message)
            else:
                await event_emitter.emit_info(message)
        except Exception as exc:
            logger.warning(f"Failed to emit tool event: {exc}")

    base_tools = build_shared_agent_tool_catalog(
        project_root=project_root,
        exclude_patterns=exclude_patterns,
        target_files=target_files,
    )

    shared_scanners = {
        "semgrep_scan": SemgrepTool(project_root, sandbox_manager),
        "bandit_scan": BanditTool(project_root, sandbox_manager),
        "gitleaks_scan": GitleaksTool(project_root, sandbox_manager),
        "npm_audit": NpmAuditTool(project_root, sandbox_manager),
        "safety_scan": SafetyTool(project_root, sandbox_manager),
        "trufflehog_scan": TruffleHogTool(project_root, sandbox_manager),
        "osv_scan": OSVScannerTool(project_root, sandbox_manager),
    }

    recon_tools = {
        **base_tools,
        **build_agent_skill_tools(user_id=user_id, agent_type="recon"),
        **shared_scanners,
    }

    from app.services.agent.tools import SmartScanTool, QuickAuditTool

    analysis_tools = {
        **base_tools,
        **build_agent_skill_tools(user_id=user_id, agent_type="analysis"),
        "smart_scan": SmartScanTool(project_root),
        "quick_audit": QuickAuditTool(project_root),
        "pattern_match": PatternMatchTool(project_root),
        "dataflow_analysis": DataFlowAnalysisTool(llm_service),
        **shared_scanners,
    }

    scan_tools = {
        **analysis_tools,
        **build_agent_skill_tools(user_id=user_id, agent_type="scan"),
    }

    triage_tools = {
        **analysis_tools,
        **build_agent_skill_tools(user_id=user_id, agent_type="triage"),
    }

    finding_tools = {
        **base_tools,
        **build_agent_skill_tools(user_id=user_id, agent_type="finding"),
        "dataflow_analysis": DataFlowAnalysisTool(llm_service),
        "sandbox_exec": SandboxTool(sandbox_manager),
    }

    from app.services.agent.tools import (
        SandboxHttpTool,
        VulnerabilityVerifyTool,
        PhpTestTool,
        PythonTestTool,
        JavaScriptTestTool,
        JavaTestTool,
        GoTestTool,
        RubyTestTool,
        ShellTestTool,
        UniversalCodeTestTool,
        CommandInjectionTestTool,
        SqlInjectionTestTool,
        XssTestTool,
        PathTraversalTestTool,
        SstiTestTool,
        DeserializationTestTool,
        UniversalVulnTestTool,
        RunCodeTool,
        ExtractFunctionTool,
    )

    verification_tools = {
        **base_tools,
        **build_agent_skill_tools(user_id=user_id, agent_type="verification"),
        "sandbox_exec": SandboxTool(sandbox_manager),
        "sandbox_http": SandboxHttpTool(sandbox_manager),
        "verify_vulnerability": VulnerabilityVerifyTool(sandbox_manager),
        "php_test": PhpTestTool(sandbox_manager, project_root),
        "python_test": PythonTestTool(sandbox_manager, project_root),
        "javascript_test": JavaScriptTestTool(sandbox_manager, project_root),
        "java_test": JavaTestTool(sandbox_manager, project_root),
        "go_test": GoTestTool(sandbox_manager, project_root),
        "ruby_test": RubyTestTool(sandbox_manager, project_root),
        "shell_test": ShellTestTool(sandbox_manager, project_root),
        "universal_code_test": UniversalCodeTestTool(sandbox_manager, project_root),
        "test_command_injection": CommandInjectionTestTool(sandbox_manager, project_root),
        "test_sql_injection": SqlInjectionTestTool(sandbox_manager, project_root),
        "test_xss": XssTestTool(sandbox_manager, project_root),
        "test_path_traversal": PathTraversalTestTool(sandbox_manager, project_root),
        "test_ssti": SstiTestTool(sandbox_manager, project_root),
        "test_deserialization": DeserializationTestTool(sandbox_manager, project_root),
        "universal_vuln_test": UniversalVulnTestTool(sandbox_manager, project_root),
        "run_code": RunCodeTool(sandbox_manager, project_root),
        "extract_function": ExtractFunctionTool(project_root),
        "create_vulnerability_report": CreateVulnerabilityReportTool(project_root),
    }

    orchestrator_tools = build_agent_tool_catalog(
        project_root=None,
        user_id=user_id,
        agent_type="orchestrator",
    )

    return {
        "recon": recon_tools,
        "analysis": analysis_tools,
        "scan": scan_tools,
        "triage": triage_tools,
        "finding": finding_tools,
        "verification": verification_tools,
        "orchestrator": orchestrator_tools,
    }



async def _collect_project_info(
    project_root: str,
    project_name: str,
    exclude_patterns: Optional[List[str]] = None,
    target_files: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Collect a lightweight project summary for agent orchestration."""
    import fnmatch

    info: Dict[str, Any] = {
        "name": project_name,
        "root": project_root,
        "languages": [],
        "file_count": 0,
        "structure": {},
    }

    try:
        exclude_dirs = {
            "node_modules",
            "__pycache__",
            ".git",
            "venv",
            ".venv",
            "build",
            "dist",
            "target",
            ".idea",
            ".vscode",
        }
        if exclude_patterns:
            for pattern in exclude_patterns:
                if pattern.endswith('/**'):
                    exclude_dirs.add(pattern[:-3])
                elif '/' not in pattern and '*' not in pattern:
                    exclude_dirs.add(pattern)

        target_files_set = set(target_files) if target_files else None
        lang_map = {
            '.py': 'Python',
            '.js': 'JavaScript',
            '.ts': 'TypeScript',
            '.java': 'Java',
            '.go': 'Go',
            '.php': 'PHP',
            '.rb': 'Ruby',
            '.rs': 'Rust',
            '.c': 'C',
            '.cpp': 'C++',
        }

        filtered_files: List[str] = []
        filtered_dirs: Set[str] = set()

        for root, dirs, files in os.walk(project_root):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for filename in files:
                relative_path = os.path.relpath(os.path.join(root, filename), project_root)
                if target_files_set and relative_path not in target_files_set:
                    continue

                should_skip = False
                for pattern in exclude_patterns or []:
                    if fnmatch.fnmatch(relative_path, pattern) or fnmatch.fnmatch(filename, pattern):
                        should_skip = True
                        break
                if should_skip:
                    continue

                info["file_count"] += 1
                filtered_files.append(relative_path)

                dir_path = os.path.dirname(relative_path)
                if dir_path:
                    parts = dir_path.split(os.sep)
                    for i in range(len(parts)):
                        filtered_dirs.add(os.sep.join(parts[: i + 1]))

                ext = os.path.splitext(filename)[1].lower()
                language = lang_map.get(ext)
                if language and language not in info["languages"]:
                    info["languages"].append(language)

        if target_files_set:
            info["structure"] = {
                "directories": sorted(filtered_dirs)[:20],
                "files": filtered_files[:30],
                "scope_limited": True,
                "scope_message": f"Audit scope limited to {len(filtered_files)} target files.",
            }
        else:
            top_items = os.listdir(project_root)
            info["structure"] = {
                "directories": [
                    item for item in top_items
                    if os.path.isdir(os.path.join(project_root, item)) and item not in exclude_dirs
                ],
                "files": [
                    item for item in top_items
                    if os.path.isfile(os.path.join(project_root, item))
                ][:20],
                "scope_limited": False,
            }
    except Exception as exc:
        logger.warning(f"Failed to collect project info: {exc}")

    return info



def _severity_rank(value: str | None) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(str(value or "").lower(), -1)


def _finding_status_rank(value: str | None) -> int:
    return {
        FindingStatus.NEW: 0,
        FindingStatus.ANALYZING: 1,
        FindingStatus.NEEDS_REVIEW: 1,
        FindingStatus.FALSE_POSITIVE: 2,
        FindingStatus.VERIFIED: 3,
        FindingStatus.FIXED: 4,
    }.get(str(value or "").lower(), -1)


def _merge_string_list(existing_values: Any, new_values: Any) -> list[str] | None:
    merged: list[str] = []
    for value in list(existing_values or []) + list(new_values or []):
        normalized = str(value or "").strip()
        if normalized and normalized not in merged:
            merged.append(normalized)
    return merged or None


def _merge_existing_finding_record(existing: AgentFinding, incoming: AgentFinding, raw_finding: Dict[str, Any]) -> bool:
    changed = False

    if _severity_rank(incoming.severity) > _severity_rank(existing.severity):
        existing.severity = incoming.severity
        changed = True
    if (incoming.ai_confidence or 0) > (existing.ai_confidence or 0):
        existing.ai_confidence = incoming.ai_confidence
        changed = True
    if incoming.is_verified and not existing.is_verified:
        existing.is_verified = True
        existing.status = incoming.status
        changed = True
    elif _finding_status_rank(incoming.status) > _finding_status_rank(existing.status):
        existing.status = incoming.status
        changed = True

    for field_name in (
        "description",
        "suggestion",
        "ai_explanation",
        "verification_method",
        "poc_code",
        "poc_description",
        "source",
        "sink",
    ):
        incoming_value = getattr(incoming, field_name, None)
        existing_value = getattr(existing, field_name, None)
        if incoming_value and (not existing_value or incoming.is_verified):
            if existing_value != incoming_value:
                setattr(existing, field_name, incoming_value)
                changed = True

    if incoming.has_poc and not existing.has_poc:
        existing.has_poc = True
        changed = True
    if incoming.poc_steps and not existing.poc_steps:
        existing.poc_steps = incoming.poc_steps
        changed = True
    if incoming.verification_result and incoming.verification_result != existing.verification_result:
        existing.verification_result = incoming.verification_result
        changed = True
    if incoming.line_end and (existing.line_end or 0) < incoming.line_end:
        existing.line_end = incoming.line_end
        changed = True

    merged_references = _merge_string_list(existing.references, incoming.references)
    if merged_references != (existing.references or None):
        existing.references = merged_references
        changed = True

    metadata = dict(existing.finding_metadata or {})
    latest_report_status = raw_finding.get("report_status") or raw_finding.get("verdict")
    if latest_report_status and metadata.get("report_status") != latest_report_status:
        metadata["report_status"] = latest_report_status
        changed = True
    if raw_finding.get("origin") and metadata.get("origin") != raw_finding.get("origin"):
        metadata["origin"] = raw_finding.get("origin")
        changed = True
    if raw_finding.get("evidence_type") and metadata.get("evidence_type") != raw_finding.get("evidence_type"):
        metadata["evidence_type"] = raw_finding.get("evidence_type")
        changed = True
    if changed:
        metadata["raw_finding"] = raw_finding
        metadata["merge_count"] = int(metadata.get("merge_count") or 0) + 1
        metadata["last_merged_at"] = datetime.now(timezone.utc).isoformat()
        existing.finding_metadata = metadata
    return changed


def _build_finding_fingerprint(record: AgentFinding) -> str:
    record.fingerprint = record.fingerprint or record.generate_fingerprint()
    normalized = str(record.fingerprint or "").strip()
    if normalized:
        return normalized
    components = [
        str(record.vulnerability_type or ""),
        str(record.file_path or ""),
        str(record.line_start or 0),
        str(record.line_end or 0),
        str(record.title or ""),
    ]
    fingerprint = hashlib.sha256("|".join(components).encode("utf-8")).hexdigest()[:16]
    record.fingerprint = fingerprint
    return fingerprint


async def _save_findings(
    db: AsyncSession,
    task_id: str,
    findings: List[Dict],
    project_root: Optional[str] = None,
) -> int:
    """Persist normalized findings for an audit task."""
    from app.models.agent_task import VulnerabilityType

    logger.info(f"[SaveFindings] Starting to save {len(findings)} findings for task {task_id}")
    if not findings:
        logger.warning(f"[SaveFindings] No findings to save for task {task_id}")
        return 0

    existing_result = await db.execute(select(AgentFinding).where(AgentFinding.task_id == task_id))
    existing_scalars = existing_result.scalars()
    if inspect.isawaitable(existing_scalars):
        existing_scalars = await existing_scalars
    existing_findings_result = existing_scalars.all()
    if inspect.isawaitable(existing_findings_result):
        existing_findings_result = await existing_findings_result
    existing_findings = list(existing_findings_result or [])
    existing_by_fingerprint: Dict[str, AgentFinding] = {}
    for existing in existing_findings:
        existing_by_fingerprint[_build_finding_fingerprint(existing)] = existing

    severity_map = {
        "critical": VulnerabilitySeverity.CRITICAL,
        "high": VulnerabilitySeverity.HIGH,
        "medium": VulnerabilitySeverity.MEDIUM,
        "low": VulnerabilitySeverity.LOW,
        "info": VulnerabilitySeverity.INFO,
    }
    type_map = {
        "sql_injection": VulnerabilityType.SQL_INJECTION,
        "nosql_injection": VulnerabilityType.NOSQL_INJECTION,
        "xss": VulnerabilityType.XSS,
        "command_injection": VulnerabilityType.COMMAND_INJECTION,
        "code_injection": VulnerabilityType.CODE_INJECTION,
        "path_traversal": VulnerabilityType.PATH_TRAVERSAL,
        "ssrf": VulnerabilityType.SSRF,
        "xxe": VulnerabilityType.XXE,
        "auth_bypass": VulnerabilityType.AUTH_BYPASS,
        "idor": VulnerabilityType.IDOR,
        "sensitive_data_exposure": VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        "hardcoded_secret": VulnerabilityType.HARDCODED_SECRET,
        "deserialization": VulnerabilityType.DESERIALIZATION,
        "weak_crypto": VulnerabilityType.WEAK_CRYPTO,
        "file_inclusion": VulnerabilityType.FILE_INCLUSION,
        "race_condition": VulnerabilityType.RACE_CONDITION,
        "business_logic": VulnerabilityType.BUSINESS_LOGIC,
        "memory_corruption": VulnerabilityType.MEMORY_CORRUPTION,
    }

    def normalize_type(raw_type: str):
        mapped = type_map.get(raw_type, VulnerabilityType.OTHER)
        if "sqli" in raw_type or raw_type == "sql" or "sql_" in raw_type:
            return VulnerabilityType.SQL_INJECTION
        if "xss" in raw_type:
            return VulnerabilityType.XSS
        if "rce" in raw_type or "command" in raw_type or "cmd" in raw_type:
            return VulnerabilityType.COMMAND_INJECTION
        if "traversal" in raw_type or "lfi" in raw_type or "rfi" in raw_type:
            return VulnerabilityType.PATH_TRAVERSAL
        if "ssrf" in raw_type:
            return VulnerabilityType.SSRF
        if "xxe" in raw_type:
            return VulnerabilityType.XXE
        if "auth" in raw_type:
            return VulnerabilityType.AUTH_BYPASS
        if "secret" in raw_type or "credential" in raw_type or "password" in raw_type:
            return VulnerabilityType.HARDCODED_SECRET
        if "deserial" in raw_type:
            return VulnerabilityType.DESERIALIZATION
        return mapped

    def normalize_references(raw_references):
        if not raw_references:
            return None
        if isinstance(raw_references, str):
            try:
                parsed = json.loads(raw_references)
                if isinstance(parsed, list):
                    return parsed
            except json.JSONDecodeError:
                return [raw_references]
            return [raw_references]
        if isinstance(raw_references, list):
            return raw_references
        return [str(raw_references)]

    inserted_count = 0
    merged_count = 0
    for finding in findings:
        if not isinstance(finding, dict):
            logger.debug(f"[SaveFindings] Skipping non-dict finding: {type(finding)}")
            continue
        if is_placeholder_finding(finding):
            logger.warning(
                "[SaveFindings] Skipping placeholder or free-form finding payload: %s",
                sorted(finding.keys()),
            )
            continue

        try:
            raw_severity = str(finding.get("severity") or finding.get("risk") or "medium").lower().strip()
            severity_enum = severity_map.get(raw_severity, VulnerabilitySeverity.MEDIUM)

            raw_type = str(
                finding.get("vulnerability_type")
                or finding.get("type")
                or finding.get("vuln_type")
                or "other"
            ).lower().strip().replace(" ", "_").replace("-", "_")
            type_enum = normalize_type(raw_type)

            location = finding.get("location", "") or ""
            file_path = finding.get("file_path") or finding.get("file")
            if not file_path:
                file_path = location.split(":")[0] if ":" in location else location

            if project_root and file_path:
                clean_path = file_path.split(":")[0].strip()
                full_path = os.path.join(project_root, clean_path)
                if not os.path.isfile(full_path) and not (os.path.isabs(clean_path) and os.path.isfile(clean_path)):
                    logger.warning(
                        f"[SaveFindings] Skipping finding with missing file path '{file_path}' "
                        f"(title: {str(finding.get('title', 'N/A'))[:50]})"
                    )
                    continue

            line_start = finding.get("line_start") or finding.get("line")
            if not line_start and ":" in location:
                try:
                    line_start = int(location.split(":")[1])
                except (ValueError, IndexError):
                    line_start = None
            line_end = finding.get("line_end") or line_start

            code_snippet = finding.get("code_snippet") or finding.get("code") or finding.get("vulnerable_code")
            title = finding.get("title")
            if not title:
                type_display = raw_type.replace("_", " ").title()
                title = f"{type_display} in {os.path.basename(file_path)}" if file_path else f"{type_display} Vulnerability"

            description = (
                finding.get("description")
                or finding.get("details")
                or finding.get("explanation")
                or finding.get("impact")
                or ""
            )
            suggestion = (
                finding.get("suggestion")
                or finding.get("recommendation")
                or finding.get("remediation")
                or finding.get("fix")
            )

            confidence = finding.get("confidence") or finding.get("ai_confidence") or 0.5
            if isinstance(confidence, str):
                try:
                    confidence = float(confidence)
                except ValueError:
                    confidence = 0.5

            verdict = str(finding.get("verdict") or finding.get("report_status") or "candidate").lower()
            is_verified = bool(finding.get("is_verified", False) or verdict == "confirmed")
            poc_data = finding.get("poc") or {}
            has_poc = has_meaningful_poc(poc_data)
            poc_code = poc_data.get("code") if has_poc and isinstance(poc_data, dict) else None
            poc_description = poc_data.get("description") if has_poc and isinstance(poc_data, dict) else None
            poc_steps = poc_data.get("steps") if has_poc and isinstance(poc_data, dict) else None

            verification_method = finding.get("verification_method")
            verification_result = finding.get("verification_result") or {"verdict": verdict}
            references = normalize_references(finding.get("references") or finding.get("reference_links"))
            if verdict == "false_positive":
                status = FindingStatus.FALSE_POSITIVE
            elif is_verified:
                status = FindingStatus.VERIFIED
            else:
                status = FindingStatus.NEW

            record = AgentFinding(
                id=str(uuid4()),
                task_id=task_id,
                title=title,
                description=description,
                vulnerability_type=type_enum,
                severity=severity_enum,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                code_snippet=code_snippet,
                suggestion=suggestion,
                ai_explanation=finding.get("verification_notes") or finding.get("impact"),
                ai_confidence=confidence,
                status=status,
                is_verified=is_verified,
                has_poc=has_poc,
                poc_code=poc_code,
                poc_description=poc_description,
                poc_steps=poc_steps,
                verification_method=verification_method,
                verification_result=verification_result,
                source=finding.get("source"),
                sink=finding.get("sink"),
                references=references,
                finding_metadata={
                    "raw_finding": finding,
                    "report_status": finding.get("report_status") or verdict,
                    "origin": finding.get("origin"),
                    "evidence_type": finding.get("evidence_type"),
                },
            )
            fingerprint = _build_finding_fingerprint(record)
            existing = existing_by_fingerprint.get(fingerprint)
            if existing is not None:
                if _merge_existing_finding_record(existing, record, finding):
                    merged_count += 1
                continue

            db.add(record)
            existing_by_fingerprint[fingerprint] = record
            inserted_count += 1
        except Exception as exc:
            logger.exception(f"[SaveFindings] Failed to save finding: {exc}")

    persisted_count = inserted_count + merged_count
    if persisted_count:
        await db.commit()
        logger.info(
            f"[SaveFindings] Persisted {persisted_count} findings for task {task_id} "
            f"({inserted_count} inserted, {merged_count} merged)"
        )
    else:
        logger.warning(f"[SaveFindings] No findings were saved for task {task_id}")
    return persisted_count


def _serialize_agent_finding_record(finding: AgentFinding) -> Dict[str, Any]:
    from app.services.task_report_service import serialize_finding

    item = serialize_finding(finding)
    item["confidence"] = item.pop("confidence", None)
    return item


async def _load_task_findings(db: AsyncSession, task_id: str) -> List[AgentFinding]:
    result = await db.execute(
        select(AgentFinding)
        .where(AgentFinding.task_id == task_id)
        .order_by(
            case(
                (AgentFinding.is_verified.is_(True), 0),
                (AgentFinding.status == FindingStatus.VERIFIED, 1),
                (AgentFinding.severity == "critical", 2),
                (AgentFinding.severity == "high", 3),
                (AgentFinding.severity == "medium", 4),
                (AgentFinding.severity == "low", 5),
                else_=6,
            ),
            AgentFinding.created_at.desc(),
        )
    )
    return list(result.scalars().all())


def _apply_task_finding_metrics(task: AgentTask, findings: List[AgentFinding | Dict[str, Any]]) -> None:
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    files_with_findings: Set[str] = set()
    verified_count = 0
    false_positive_count = 0

    for item in findings:
        finding = item if isinstance(item, dict) else _serialize_agent_finding_record(item)
        severity = str(finding.get("severity", "")).lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
        if finding.get("file_path"):
            files_with_findings.add(str(finding["file_path"]))
        if finding.get("is_verified") or str(finding.get("report_status", "")).lower() == "confirmed":
            verified_count += 1
        if str(finding.get("report_status") or finding.get("status") or "").lower() == "false_positive":
            false_positive_count += 1

    task.findings_count = len(findings)
    task.verified_count = verified_count
    task.false_positive_count = false_positive_count
    task.files_with_findings = len(files_with_findings)
    task.critical_count = severity_counts["critical"]
    task.high_count = severity_counts["high"]
    task.medium_count = severity_counts["medium"]
    task.low_count = severity_counts["low"]



def _calculate_security_score(findings: List[Dict]) -> float:
    """Calculate a simple security score from finding severities."""
    if not findings:
        return 100.0

    deductions = {
        "critical": 25,
        "high": 15,
        "medium": 8,
        "low": 3,
        "info": 1,
    }
    total_deduction = 0
    for finding in findings:
        if isinstance(finding, dict):
            severity = str(finding.get("severity", "low")).lower()
            total_deduction += deductions.get(severity, 3)
    return float(max(0, 100 - total_deduction))


def _debug_event_value(event: Any, key: str, default: Any = None) -> Any:
    if hasattr(event, key):
        value = getattr(event, key)
        if value is not None:
            return value
    if isinstance(event, dict):
        return event.get(key, default)
    return default


def _normalize_debug_event(event: Any) -> Dict[str, Any]:
    metadata = _debug_event_value(event, "event_metadata", {}) or {}
    created_at = _debug_event_value(event, "created_at")
    timestamp = created_at.isoformat() if hasattr(created_at, "isoformat") else str(created_at) if created_at else None
    payload = metadata.get("payload") if isinstance(metadata, dict) else None
    return {
        "id": _debug_event_value(event, "id"),
        "task_id": _debug_event_value(event, "task_id"),
        "event_type": _debug_event_value(event, "event_type"),
        "sequence": _debug_event_value(event, "sequence", 0),
        "phase": _debug_event_value(event, "phase"),
        "message": _debug_event_value(event, "message"),
        "tool_name": _debug_event_value(event, "tool_name"),
        "tool_input": _debug_event_value(event, "tool_input"),
        "tool_output": _debug_event_value(event, "tool_output"),
        "tool_duration_ms": _debug_event_value(event, "tool_duration_ms"),
        "progress_percent": _event_progress_percent(event),
        "timestamp": timestamp,
        "created_at": timestamp,
        "agent_name": metadata.get("agent_name"),
        "agent_type": metadata.get("agent_type"),
        "provider": metadata.get("provider"),
        "model": metadata.get("model"),
        "iteration": metadata.get("iteration"),
        "payload": payload if payload is not None else metadata,
        "metadata": metadata,
    }


def _event_progress_percent(event: Any) -> Optional[float]:
    direct_value = _debug_event_value(event, "progress_percent")
    if direct_value is not None:
        try:
            return float(direct_value)
        except (TypeError, ValueError):
            return None

    metadata = _debug_event_value(event, "event_metadata", {}) or {}
    candidates: list[Any] = []
    if isinstance(metadata, dict):
        candidates.append(metadata.get("progress_percent"))
        payload = metadata.get("payload")
        if isinstance(payload, dict):
            candidates.append(payload.get("progress_percent"))

    for value in candidates:
        if value is None:
            continue
        try:
            return float(value)
        except (TypeError, ValueError):
            continue
    return None


def build_debug_task_item(
    *,
    task_id: str,
    task_name: Optional[str],
    project_id: str,
    status: str,
    created_at: datetime,
    events: List[Any],
) -> Dict[str, Any]:
    normalized = [_normalize_debug_event(event) for event in events]
    agent_types = sorted({event["agent_type"] for event in normalized if event.get("agent_type")})
    latest_event_at = normalized[-1]["timestamp"] if normalized else None
    tool_call_count = sum(1 for event in normalized if event["event_type"] == "tool_call")
    return {
        "id": task_id,
        "project_id": project_id,
        "name": task_name,
        "status": status,
        "created_at": created_at,
        "latest_event_at": latest_event_at,
        "event_count": len(normalized),
        "agent_count": len(agent_types),
        "tool_call_count": tool_call_count,
    }


def build_debug_trace_payload(
    *,
    task_id: str,
    task_name: Optional[str],
    task_status: str,
    events: List[Any],
) -> Dict[str, Any]:
    normalized = [_normalize_debug_event(event) for event in events]
    normalized.sort(key=lambda item: item["sequence"])
    handoffs: List[Dict[str, Any]] = []
    phases = sorted({event["phase"] for event in normalized if event.get("phase")})
    agents = sorted({event["agent_type"] for event in normalized if event.get("agent_type")})
    tool_calls = sum(1 for event in normalized if event["event_type"] == "tool_call")
    for event in normalized:
        if event["event_type"] in {"handoff_out", "handoff_in"}:
            payload = event.get("payload") or {}
            if isinstance(payload, dict):
                handoffs.append(
                    {
                        "event_id": event["id"],
                        "event_type": event["event_type"],
                        "sequence": event["sequence"],
                        "timestamp": event["timestamp"],
                        "from_agent": payload.get("from_agent"),
                        "to_agent": payload.get("to_agent"),
                        "summary": payload.get("summary") or payload.get("payload", {}).get("summary"),
                        "payload": payload,
                    }
                )
    return {
        "task": {
            "id": task_id,
            "name": task_name,
            "status": task_status,
        },
        "summary": {
            "event_count": len(normalized),
            "agents": agents,
            "phases": phases,
            "tool_calls": tool_calls,
            "handoff_count": len(handoffs),
        },
        "timeline": normalized,
        "handoffs": handoffs,
    }


async def _save_agent_tree(db: AsyncSession, task_id: str) -> None:
    """Persist the in-memory agent tree to the database."""
    from app.models.agent_task import AgentTreeNode
    from app.services.agent.core import agent_registry

    def get_depth(nodes: Dict[str, Dict[str, Any]], agent_id: str, visited: Optional[Set[str]] = None) -> int:
        if visited is None:
            visited = set()
        if agent_id in visited:
            return 0
        visited.add(agent_id)
        node = nodes.get(agent_id)
        if not node:
            return 0
        parent_id = node.get("parent_id")
        if not parent_id:
            return 0
        return 1 + get_depth(nodes, parent_id, visited)

    try:
        tree = agent_registry.get_agent_tree()
        nodes = tree.get("nodes", {})
        if not nodes:
            logger.warning(f"[SaveAgentTree] No agent nodes to save for task {task_id}")
            return

        logger.info(f"[SaveAgentTree] Saving {len(nodes)} agent nodes for task {task_id}")
        saved_count = 0
        for agent_id, node_data in nodes.items():
            agent_instance = agent_registry.get_agent(agent_id)
            iterations = 0
            tool_calls = 0
            tokens_used = 0
            if agent_instance and hasattr(agent_instance, "get_stats"):
                stats = agent_instance.get_stats()
                iterations = stats.get("iterations", 0)
                tool_calls = stats.get("tool_calls", 0)
                tokens_used = stats.get("tokens_used", 0)

            findings_count = 0
            result_summary = None
            result = node_data.get("result") or {}
            if isinstance(result, dict):
                findings_count = len(result.get("findings", []))
                if result.get("summary"):
                    result_summary = str(result.get("summary"))[:2000]

            tree_node = AgentTreeNode(
                id=str(uuid4()),
                task_id=task_id,
                agent_id=agent_id,
                agent_name=node_data.get("name", "Unknown"),
                agent_type=node_data.get("type", "unknown"),
                parent_agent_id=node_data.get("parent_id"),
                depth=get_depth(nodes, agent_id),
                task_description=node_data.get("task"),
                knowledge_modules=node_data.get("knowledge_modules"),
                status=node_data.get("status", "unknown"),
                result_summary=result_summary,
                findings_count=findings_count,
                iterations=iterations,
                tool_calls=tool_calls,
                tokens_used=tokens_used,
            )
            db.add(tree_node)
            saved_count += 1

        await db.commit()
        logger.info(f"[SaveAgentTree] Successfully saved {saved_count} agent nodes to database")
    except Exception as exc:
        logger.error(f"[SaveAgentTree] Failed to save agent tree: {exc}", exc_info=True)
        await db.rollback()


# ============ API Endpoints ============


@router.post("/", response_model=AgentTaskResponse)
async def create_agent_task(
    request: AgentTaskCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Create a new audit task and schedule background execution."""
    project = await db.get(Project, request.project_id)
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    task = AgentTask(
        id=str(uuid4()),
        project_id=project.id,
        name=request.name or f"Agent Audit - {datetime.now().strftime('%Y%m%d_%H%M%S')}",
        description=request.description,
        status=AgentTaskStatus.PENDING,
        current_phase=AgentTaskPhase.PLANNING,
        target_vulnerabilities=request.target_vulnerabilities,
        version_label=request.version_label,
        version_tag=request.version_tag,
        verification_level=request.verification_level or "sandbox",
        branch_name=request.branch_name,
        repository_url_snapshot=project.repository_url,
        exclude_patterns=request.exclude_patterns,
        target_files=request.target_files,
        max_iterations=request.max_iterations or 50,
        timeout_seconds=request.timeout_seconds or 1800,
        agent_config={"finding_runtime_stack": coerce_finding_runtime_stack(request.finding_runtime_stack or getattr(settings, "FINDING_RUNTIME_STACK_DEFAULT", FindingRuntimeStack.LEGACY.value)).value},
        created_by=current_user.id,
        audit_scope=request.audit_scope,
    )

    db.add(task)
    await db.commit()
    await db.refresh(task)
    await _schedule_agent_task(background_tasks, task.id)
    logger.info(f"Created agent task {task.id} for project {project.name}")
    return task


@router.get("/", response_model=List[AgentTaskResponse])
async def list_agent_tasks(
    project_id: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """List audit tasks visible to the current user."""
    projects_result = await db.execute(select(Project.id).where(Project.owner_id == current_user.id))
    user_project_ids = [row[0] for row in projects_result.fetchall()]
    if not user_project_ids:
        return []

    query = select(AgentTask).where(AgentTask.project_id.in_(user_project_ids))
    if project_id:
        query = query.where(AgentTask.project_id == project_id)
    if status:
        try:
            query = query.where(AgentTask.status == AgentTaskStatus(status))
        except ValueError:
            pass

    result = await db.execute(query.order_by(AgentTask.created_at.desc()).offset(skip).limit(limit))
    tasks = result.scalars().all()
    runtime_session_ids = await _load_runtime_session_ids(db, [task.id for task in tasks])
    runtime_stats = await _load_runtime_task_stats(db, [task.id for task in tasks])
    for task in tasks:
        runtime_result = _get_task_finding_runtime_result(task)
        task_runtime_stats = runtime_stats.get(str(task.id), {})
        if task_runtime_stats.get("total_iterations"):
            setattr(task, "total_iterations", max(int(task.total_iterations or 0), int(task_runtime_stats["total_iterations"])))
        if task_runtime_stats.get("tool_calls_count"):
            setattr(task, "tool_calls_count", max(int(task.tool_calls_count or 0), int(task_runtime_stats["tool_calls_count"])))
        if task_runtime_stats.get("tokens_used"):
            setattr(task, "tokens_used", max(int(task.tokens_used or 0), int(task_runtime_stats["tokens_used"])))
        setattr(task, "runtime_session_id", runtime_session_ids.get(task.id))
        setattr(task, "finding_runtime_stack", _resolve_task_runtime_stack(task.agent_config))
        setattr(task, "finding_outcome", runtime_result["finding_outcome"])
        setattr(task, "runtime_completion_mode", runtime_result["runtime_completion_mode"])
        setattr(task, "finalized_findings_count", runtime_result["finalized_findings_count"])
        setattr(task, "recovered_candidates_count", runtime_result["recovered_candidates_count"])
        setattr(task, "handoff_ready", runtime_result["handoff_ready"])
        setattr(task, "recovered_candidates", runtime_result["recovered_candidates"])
    return tasks


@router.get("/debug-tasks", response_model=List[DebugTaskListItem])
async def list_debug_tasks(
    project_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    logger.info(
        "debug-tasks:start user=%s project_id=%s status=%s limit=%s",
        getattr(current_user, "id", ""),
        project_id,
        status,
        limit,
    )
    projects_result = await db.execute(select(Project.id).where(Project.owner_id == current_user.id))
    user_project_ids = [row[0] for row in projects_result.fetchall()]
    logger.info("debug-tasks:projects count=%s", len(user_project_ids))
    if not user_project_ids:
        logger.info("debug-tasks:return empty-no-projects")
        return []

    query = select(
        AgentTask.id,
        AgentTask.project_id,
        AgentTask.name,
        AgentTask.status,
        AgentTask.created_at,
        AgentTask.started_at,
        AgentTask.completed_at,
        AgentTask.tool_calls_count,
    ).where(AgentTask.project_id.in_(user_project_ids))
    if project_id:
        query = query.where(AgentTask.project_id == project_id)
    if status:
        query = query.where(AgentTask.status == status)
    logger.info("debug-tasks:before-task-query")
    tasks_result = await db.execute(query.order_by(AgentTask.created_at.desc()).limit(limit))
    tasks = tasks_result.mappings().all()
    logger.info("debug-tasks:tasks count=%s", len(tasks))

    payload = [
        {
            "id": task["id"],
            "project_id": task["project_id"],
            "name": task["name"],
            "status": str(task["status"]),
            "created_at": task["created_at"].isoformat() if task["created_at"] else None,
            "latest_event_at": (
                (task["completed_at"] or task["started_at"] or task["created_at"]).isoformat()
                if (task["completed_at"] or task["started_at"] or task["created_at"])
                else None
            ),
            "event_count": 0,
            "agent_count": 0,
            "tool_call_count": int(task["tool_calls_count"] or 0),
        }
        for task in tasks
    ]
    logger.info("debug-tasks:return count=%s", len(payload))
    return payload


@router.get("/{task_id}", response_model=AgentTaskResponse)
async def get_agent_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Fetch a single audit task with live stats when available."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    progress = 0.0
    if hasattr(task, "progress_percentage") and task.progress_percentage is not None:
        progress = task.progress_percentage
    elif task.status == AgentTaskStatus.COMPLETED:
        progress = 100.0

    total_iterations = task.total_iterations or 0
    tool_calls_count = task.tool_calls_count or 0
    tokens_used = task.tokens_used or 0

    orchestrator = _running_orchestrators.get(task_id)
    if orchestrator and task.status == AgentTaskStatus.RUNNING and hasattr(orchestrator, "get_stats"):
        stats = orchestrator.get_stats()
        total_iterations = stats.get("iterations", total_iterations)
        tool_calls_count = stats.get("tool_calls", tool_calls_count)
        tokens_used = stats.get("tokens_used", tokens_used)
        for agent in getattr(orchestrator, "sub_agents", {}).values():
            if hasattr(agent, "get_stats"):
                sub_stats = agent.get_stats()
                total_iterations += sub_stats.get("iterations", 0)
                tool_calls_count += sub_stats.get("tool_calls", 0)
                tokens_used += sub_stats.get("tokens_used", 0)

    runtime_session_ids = await _load_runtime_session_ids(db, [task.id])
    runtime_stats = await _load_runtime_task_stats(db, [task.id])
    task_runtime_stats = runtime_stats.get(str(task.id), {})
    if task_runtime_stats.get("total_iterations"):
        total_iterations = max(total_iterations, int(task_runtime_stats["total_iterations"]))
    if task_runtime_stats.get("tool_calls_count"):
        tool_calls_count = max(tool_calls_count, int(task_runtime_stats["tool_calls_count"]))
    if task_runtime_stats.get("tokens_used"):
        tokens_used = max(tokens_used, int(task_runtime_stats["tokens_used"]))
    runtime_result = _get_task_finding_runtime_result(task)

    response_data = {
        "id": task.id,
        "project_id": task.project_id,
        "name": task.name,
        "description": task.description,
        "task_type": task.task_type or "agent_audit",
        "status": task.status,
        "current_phase": task.current_phase,
        "current_step": task.current_step,
        "total_files": task.total_files or 0,
        "indexed_files": task.indexed_files or 0,
        "analyzed_files": task.analyzed_files or 0,
        "total_chunks": task.total_chunks or 0,
        "total_iterations": total_iterations,
        "tool_calls_count": tool_calls_count,
        "tokens_used": tokens_used,
        "findings_count": task.findings_count or 0,
        "total_findings": task.findings_count or 0,
        "verified_count": task.verified_count or 0,
        "verified_findings": task.verified_count or 0,
        "false_positive_count": task.false_positive_count or 0,
        "critical_count": task.critical_count or 0,
        "high_count": task.high_count or 0,
        "medium_count": task.medium_count or 0,
        "low_count": task.low_count or 0,
        "quality_score": float(task.quality_score or 0.0),
        "security_score": float(task.security_score) if task.security_score is not None else None,
        "progress_percentage": progress,
        "created_at": task.created_at,
        "started_at": task.started_at,
        "completed_at": task.completed_at,
        "error_message": task.error_message,
        "runtime_session_id": runtime_session_ids.get(task.id),
        "finding_runtime_stack": _resolve_task_runtime_stack(task.agent_config),
        "finding_outcome": runtime_result["finding_outcome"],
        "runtime_completion_mode": runtime_result["runtime_completion_mode"],
        "finalized_findings_count": runtime_result["finalized_findings_count"],
        "recovered_candidates_count": runtime_result["recovered_candidates_count"],
        "handoff_ready": runtime_result["handoff_ready"],
        "recovered_candidates": runtime_result["recovered_candidates"],
        "audit_scope": task.audit_scope,
        "target_vulnerabilities": task.target_vulnerabilities,
        "verification_level": task.verification_level,
        "exclude_patterns": task.exclude_patterns,
        "target_files": task.target_files,
    }
    try:
        return AgentTaskResponse(**response_data)
    except Exception as exc:
        logger.error(f"Error serializing task {task_id}: {exc}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to serialize task data: {exc}")


@router.get("/{task_id}/debug-trace", response_model=DebugTraceResponse)
async def get_debug_trace(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    events_result = await db.execute(
        select(AgentEvent)
        .where(AgentEvent.task_id == task_id)
        .order_by(AgentEvent.sequence)
    )
    events = events_result.scalars().all()
    return build_debug_trace_payload(
        task_id=task.id,
        task_name=task.name,
        task_status=str(task.status),
        events=events,
    )


@router.post("/{task_id}/resume")
async def resume_agent_task(
    task_id: str,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Resume a cancelled, failed, or paused audit task from the latest checkpoint."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    if task.status == AgentTaskStatus.RUNNING:
        raise HTTPException(status_code=400, detail="Task is already running")
    if task.status == AgentTaskStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Completed tasks cannot be resumed")
    if task.status not in [AgentTaskStatus.CANCELLED, AgentTaskStatus.FAILED, AgentTaskStatus.PAUSED]:
        raise HTTPException(status_code=400, detail="Task is not resumable")

    _cancelled_tasks.discard(task_id)
    _prepare_task_for_resume(task)
    await db.commit()
    await _schedule_agent_task(background_tasks, task.id)
    logger.info(f"Resumed agent task {task.id}")
    return {
        "message": "Task resumed",
        "task_id": task.id,
        "status": task.status,
        "current_phase": task.current_phase,
    }


@router.post("/{task_id}/cancel")
async def cancel_agent_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Cancel a running audit task."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    if task.status in [AgentTaskStatus.COMPLETED, AgentTaskStatus.FAILED, AgentTaskStatus.CANCELLED]:
        raise HTTPException(status_code=400, detail="Task is already finished")

    request_agent_task_cancellation(task_id)
    task.status = AgentTaskStatus.CANCELLED
    task.completed_at = datetime.now(timezone.utc)
    await db.commit()
    logger.info(f"[Cancel] Task {task_id} cancelled successfully")
    return {"message": "Task cancelled", "task_id": task_id}


@router.get("/{task_id}/events")
async def stream_agent_events(
    task_id: str,
    after_sequence: int = Query(0, ge=0, description="Return events after this sequence number."),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    """Stream persisted agent events via SSE."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    async def event_generator():
        last_sequence = after_sequence
        poll_interval = 0.5
        max_idle = 300
        idle_time = 0.0

        while True:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(AgentEvent)
                    .where(AgentEvent.task_id == task_id)
                    .where(AgentEvent.sequence > last_sequence)
                    .order_by(AgentEvent.sequence)
                    .limit(50)
                )
                events = result.scalars().all()
                current_task = await session.get(AgentTask, task_id)
                task_status = current_task.status if current_task else None

            if events:
                idle_time = 0.0
                for event in events:
                    last_sequence = event.sequence
                    payload = {
                        "id": event.id,
                        "type": str(event.event_type),
                        "phase": str(event.phase) if event.phase else None,
                        "message": event.message,
                        "sequence": event.sequence,
                        "timestamp": event.created_at.isoformat() if event.created_at else None,
                        "progress_percent": _event_progress_percent(event),
                        "tool_name": event.tool_name,
                    }
                    yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"
            else:
                idle_time += poll_interval

            status_str = str(task_status) if task_status is not None else None
            if status_str in ["completed", "failed", "cancelled"]:
                yield f"data: {json.dumps({'type': 'task_end', 'status': status_str})}\n\n"
                break
            if idle_time >= max_idle:
                yield f"data: {json.dumps({'type': 'timeout'})}\n\n"
                break
            await asyncio.sleep(poll_interval)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/{task_id}/stream")
async def stream_agent_with_thinking(
    task_id: str,
    include_thinking: bool = Query(True, description="Include live LLM thinking events."),
    include_tool_calls: bool = Query(True, description="Include detailed tool call events."),
    after_sequence: int = Query(0, ge=0, description="Return events after this sequence number."),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    """Enhanced SSE stream that prefers in-memory events while a task is running."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")

    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    def format_sse_event(event_data: Dict[str, Any]) -> str:
        event_type = event_data.get("event_type") or event_data.get("type") or "message"
        if "type" not in event_data:
            event_data["type"] = event_type
        return f"event: {event_type}\ndata: {json.dumps(event_data, ensure_ascii=False)}\n\n"

    async def enhanced_event_generator():
        event_manager = _running_event_managers.get(task_id)
        skip_types = set()
        if not include_thinking:
            skip_types.update({"thinking_start", "thinking_token", "thinking_end"})
        if not include_tool_calls:
            skip_types.update({"tool_call_start", "tool_call_input", "tool_call_output", "tool_call_end"})

        if event_stream_enabled():
            event_stream = create_agent_event_stream()
            try:
                async for event in event_stream.stream_events(task_id, after_sequence=after_sequence):
                    event_type = event.get("event_type") or event.get("type")
                    if event_type in skip_types:
                        continue
                    yield format_sse_event(event)
                    if event_type == "thinking_token":
                        await asyncio.sleep(0.01)
                return
            except Exception as exc:
                logger.error(f"Redis event stream error: {exc}", exc_info=True)
            finally:
                await event_stream.close()

        if event_manager:
            logger.debug(f"Stream {task_id}: Using in-memory event manager")
            try:
                async for event in event_manager.stream_events(task_id, after_sequence=after_sequence):
                    event_type = event.get("event_type") or event.get("type")
                    if event_type in skip_types:
                        continue
                    yield format_sse_event(event)
                    if event_type == "thinking_token":
                        await asyncio.sleep(0.01)
                return
            except Exception as exc:
                logger.error(f"In-memory stream error: {exc}")
                yield format_sse_event({"type": "error", "message": str(exc)})
                return

        logger.debug(f"Stream {task_id}: Falling back to DB polling")
        last_sequence = after_sequence
        poll_interval = 2.0
        heartbeat_interval = 15.0
        max_idle = 60.0
        idle_time = 0.0
        last_heartbeat = 0.0

        while True:
            try:
                async with async_session_factory() as session:
                    result = await session.execute(
                        select(AgentEvent)
                        .where(AgentEvent.task_id == task_id)
                        .where(AgentEvent.sequence > last_sequence)
                        .order_by(AgentEvent.sequence)
                        .limit(100)
                    )
                    events = result.scalars().all()
                    current_task = await session.get(AgentTask, task_id)
                    task_status = current_task.status if current_task else None

                if events:
                    idle_time = 0.0
                    for event in events:
                        last_sequence = event.sequence
                        event_type = str(event.event_type)
                        if event_type in skip_types:
                            continue
                        payload = {
                            "id": event.id,
                            "type": event_type,
                            "phase": str(event.phase) if event.phase else None,
                            "message": event.message,
                            "sequence": event.sequence,
                            "timestamp": event.created_at.isoformat() if event.created_at else None,
                            "progress_percent": _event_progress_percent(event),
                            "tool_name": event.tool_name,
                        }
                        yield format_sse_event(payload)
                else:
                    idle_time += poll_interval
                    last_heartbeat += poll_interval

                status_str = str(task_status) if task_status is not None else None
                if status_str in ["completed", "failed", "cancelled"]:
                    yield format_sse_event({"type": "task_end", "status": status_str})
                    break
                if last_heartbeat >= heartbeat_interval:
                    last_heartbeat = 0.0
                    yield format_sse_event({"type": "heartbeat"})
                if idle_time >= max_idle:
                    yield format_sse_event({"type": "timeout"})
                    break
            except Exception as exc:
                logger.error(f"DB stream error: {exc}", exc_info=True)
                yield format_sse_event({"type": "error", "message": str(exc)})
                break

            await asyncio.sleep(poll_interval)

    return StreamingResponse(
        enhanced_event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )



@router.get("/{task_id}/events/list", response_model=List[AgentEventResponse])
async def list_agent_events(
    task_id: str,
    after_sequence: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Return persisted events for a task."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(
        select(AgentEvent)
        .where(AgentEvent.task_id == task_id)
        .where(AgentEvent.sequence > after_sequence)
        .order_by(AgentEvent.sequence)
        .limit(limit)
    )
    return [_normalize_debug_event(event) for event in result.scalars().all()]


@router.get("/{task_id}/findings")
async def list_agent_findings(
    task_id: str,
    severity: Optional[str] = None,
    verified_only: bool = False,
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """List findings for a task."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    query = select(AgentFinding).where(AgentFinding.task_id == task_id)
    if severity:
        try:
            query = query.where(AgentFinding.severity == VulnerabilitySeverity(severity))
        except ValueError:
            pass
    if verified_only:
        query = query.where(AgentFinding.is_verified.is_(True))

    result = await db.execute(query.order_by(AgentFinding.created_at.desc()).offset(skip).limit(limit))
    return [_serialize_agent_finding_record(item) for item in result.scalars().all()]


@router.get("/{task_id}/findings/{finding_id}")
async def get_agent_finding_detail(
    task_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Get a single finding with the rich vulnerability report fields."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    finding = await db.get(AgentFinding, finding_id)
    if not finding or finding.task_id != task_id:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _serialize_agent_finding_record(finding)


@router.get("/{task_id}/summary", response_model=TaskSummaryResponse)
async def get_task_summary(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Return a summary view for a task."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(select(AgentFinding).where(AgentFinding.task_id == task_id))
    findings = result.scalars().all()
    severity_distribution: Dict[str, int] = {}
    vulnerability_types: Dict[str, int] = {}
    verified_count = 0
    for finding in findings:
        severity_key = str(finding.severity)
        type_key = str(finding.vulnerability_type)
        severity_distribution[severity_key] = severity_distribution.get(severity_key, 0) + 1
        vulnerability_types[type_key] = vulnerability_types.get(type_key, 0) + 1
        if finding.is_verified:
            verified_count += 1

    duration = None
    if task.started_at and task.completed_at:
        duration = int((task.completed_at - task.started_at).total_seconds())

    phases_result = await db.execute(
        select(AgentEvent.phase)
        .where(AgentEvent.task_id == task_id)
        .where(AgentEvent.event_type == AgentEventType.PHASE_COMPLETE)
        .distinct()
    )
    phases = [str(row[0]) for row in phases_result.fetchall() if row[0]]

    return TaskSummaryResponse(
        task_id=task_id,
        status=str(task.status),
        security_score=task.security_score,
        total_findings=len(findings),
        verified_findings=verified_count,
        severity_distribution=severity_distribution,
        vulnerability_types=vulnerability_types,
        duration_seconds=duration,
        phases_completed=phases,
    )


@router.patch("/{task_id}/findings/{finding_id}")
async def update_finding_status(
    task_id: str,
    finding_id: str,
    body: dict,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Update finding status."""
    status = body.get("status")
    if not status:
        raise HTTPException(status_code=400, detail="Missing status field")

    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    finding = await db.get(AgentFinding, finding_id)
    if not finding or finding.task_id != task_id:
        raise HTTPException(status_code=404, detail="Finding not found")

    finding.status = status
    await db.commit()
    return {"message": "Finding status updated", "finding_id": finding_id, "status": status}


# ============ Helper Functions ============


def validate_git_url(url: str) -> bool:
    """Validate a git URL and reject obvious command-injection patterns."""
    if not url:
        return False
    from urllib.parse import urlparse

    parsed = urlparse(url)
    allowed_schemes = {"http", "https", "git", "ssh"}
    if parsed.scheme and parsed.scheme not in allowed_schemes:
        return False

    dangerous_patterns = [";", "|", "&", "$(", "`", "\n", "\r", "\t"]
    return not any(pattern in url for pattern in dangerous_patterns)



def validate_branch_name(branch: str) -> bool:
    """Validate a git branch name."""
    if not branch:
        return False
    if not re.match(r"^[a-zA-Z0-9_\-./]+$", branch):
        return False
    if ".." in branch or branch.startswith("/") or branch.endswith("/"):
        return False
    return len(branch) <= 256


def is_path_safe(base_path: str, target_path: str) -> bool:
    """Ensure a target path stays within a base directory."""
    abs_base = os.path.abspath(base_path)
    abs_target = os.path.abspath(os.path.join(base_path, target_path))
    return abs_target == abs_base or abs_target.startswith(abs_base + os.sep)


def safe_extract_zip(zip_ref: zipfile.ZipFile, extract_dir: str, task_id: str) -> None:
    """Safely extract a ZIP archive while preventing Zip Slip."""
    for index, member in enumerate(zip_ref.infolist()):
        if index % 50 == 0 and is_task_cancelled(task_id):
            raise asyncio.CancelledError("Task cancelled")
        filename = member.filename
        if not filename or filename.endswith("/"):
            continue
        if not is_path_safe(extract_dir, filename):
            logger.warning(f"Skipping unsafe ZIP member: {filename}")
            continue
        target_path = os.path.join(extract_dir, filename)
        os.makedirs(os.path.dirname(target_path), exist_ok=True)
        with zip_ref.open(member) as src, open(target_path, "wb") as dst:
            shutil.copyfileobj(src, dst)


def _find_managed_project_root_fallback(project: Project) -> Optional[str]:
    managed_root = os.path.abspath(settings.MANAGED_PROJECTS_ROOT)
    if not os.path.isdir(managed_root):
        return None

    entries: list[tuple[str, str]] = []
    for name in os.listdir(managed_root):
        if name == ".auditai_workspaces":
            continue
        path = os.path.join(managed_root, name)
        if os.path.isdir(path):
            entries.append((name, path))

    if not entries:
        return None

    project_name = str(project.name or "").strip().lower()
    if not project_name:
        return None

    exact_matches = [path for name, path in entries if name.lower() == project_name]
    if len(exact_matches) == 1:
        return exact_matches[0]

    normalized_project_name = re.sub(r"[^a-z0-9]+", "", project_name)
    prefix_matches = [
        path
        for name, path in entries
        if re.sub(r"[^a-z0-9]+", "", name.lower()).startswith(normalized_project_name)
    ]
    if len(prefix_matches) == 1:
        return prefix_matches[0]

    return None


async def _get_project_root(
    project: Project,
    task_id: str,
    branch_name: Optional[str] = None,
    github_token: Optional[str] = None,
    gitlab_token: Optional[str] = None,
    gitea_token: Optional[str] = None,
    ssh_private_key: Optional[str] = None,
    event_emitter: Optional[Any] = None,
    workspace_scope: str = "project",
    refresh: bool = False,
) -> str:
    """Prepare a local working copy for the project."""
    import subprocess
    from urllib.parse import urlparse, urlunparse
    from app.services.zip_storage import load_project_zip

    async def emit(message: str, level: str = "info") -> None:
        if not event_emitter:
            return
        if level == "warning":
            await event_emitter.emit_warning(message)
        elif level == "error":
            await event_emitter.emit_error(message)
        else:
            await event_emitter.emit_info(message)

    def check_cancelled() -> None:
        if is_task_cancelled(task_id):
            raise asyncio.CancelledError("Task cancelled")

    safe_task_id = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(task_id or "task")).strip(".-") or "task"
    safe_project_id = re.sub(r"[^a-zA-Z0-9_.-]+", "-", str(project.id or project.name or "project")).strip(".-") or "project"
    workspace_root = os.path.join(settings.MANAGED_PROJECTS_ROOT, ".auditai_workspaces")
    if workspace_scope == "project":
        base_path = os.path.join(workspace_root, "projects", safe_project_id)
    else:
        base_path = os.path.join(workspace_root, safe_task_id)

    def select_effective_root(root_path: str) -> str:
        items = [item for item in os.listdir(root_path) if not item.startswith("__") and not item.startswith(".")]
        if len(items) == 1:
            single_item_path = os.path.join(root_path, items[0])
            if os.path.isdir(single_item_path):
                return single_item_path
        return root_path

    if project.source_type == "zip":
        persistent_source = str(getattr(project, "local_path", "") or "").strip()
        if persistent_source and os.path.isdir(persistent_source):
            check_cancelled()
            await emit("Using persistent project source directory directly...")
            return select_effective_root(persistent_source)

    if refresh and os.path.exists(base_path):
        shutil.rmtree(base_path, ignore_errors=True)
    if os.path.isdir(base_path) and os.listdir(base_path):
        await emit(f"Reusing project workspace at: {base_path}")
        return select_effective_root(base_path)

    os.makedirs(base_path, exist_ok=True)
    check_cancelled()

    if project.source_type in {"zip", "local_directory"}:
        persistent_source = str(getattr(project, "local_path", "") or "").strip()
        if persistent_source and os.path.isdir(persistent_source):
            await emit("Copying persistent project source directory into the project workspace...")
            shutil.copytree(persistent_source, base_path, dirs_exist_ok=True)
        else:
            if project.source_type == "local_directory":
                raise RuntimeError("Local directory project is missing local_path")
            await emit("Extracting uploaded ZIP project...")
            zip_path = await load_project_zip(project.id)
            if not zip_path or not os.path.exists(zip_path):
                fallback_root = _find_managed_project_root_fallback(project)
                if fallback_root:
                    await emit(f"ZIP source missing; falling back to managed project directory: {fallback_root}", level="warning")
                    target_dir = os.path.join(base_path, os.path.basename(fallback_root))
                    shutil.copytree(fallback_root, target_dir, dirs_exist_ok=True)
                    base_path = target_dir
                else:
                    raise RuntimeError(f"Project ZIP not found: {project.id}")
            else:
                with zipfile.ZipFile(zip_path, "r") as zip_ref:
                    safe_extract_zip(zip_ref, base_path, task_id)
    elif project.source_type == "repository" and project.repository_url:
        repo_url = project.repository_url
        if not validate_git_url(repo_url):
            raise RuntimeError(f"Invalid repository URL: {repo_url}")
        branch = branch_name or project.default_branch or "main"
        if branch and not validate_branch_name(branch):
            raise RuntimeError(f"Invalid branch name: {branch}")

        await emit(f"Cloning repository: {repo_url}")
        target_dir = os.path.join(base_path, "repo")
        os.makedirs(target_dir, exist_ok=True)

        if GitSSHOperations.is_ssh_url(repo_url) and ssh_private_key:
            result = GitSSHOperations.clone_repo_with_ssh(repo_url, ssh_private_key, target_dir, branch)
            if not result.get("success"):
                raise RuntimeError(result.get("error") or result.get("message") or "SSH clone failed")
        else:
            auth_url = repo_url
            parsed = urlparse(repo_url)
            token = github_token or gitlab_token or gitea_token
            if token and parsed.scheme in {"http", "https"} and parsed.hostname:
                auth_url = urlunparse((parsed.scheme, f"oauth2:{token}@{parsed.netloc}", parsed.path, parsed.params, parsed.query, parsed.fragment))
            cmd = ["git", "clone", "--depth", "1"]
            if branch:
                cmd.extend(["--branch", branch])
            cmd.extend([auth_url, target_dir])
            completed = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if completed.returncode != 0:
                raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "git clone failed")
        base_path = target_dir
    else:
        raise RuntimeError("Unsupported project source type")

    base_path = select_effective_root(base_path)

    await emit(f"Project prepared at: {base_path}")
    return base_path


class AgentTreeResponse(BaseModel):
    task_id: str
    total_agents: int
    total_findings: int
    total_iterations: int
    total_tool_calls: int
    total_tokens: int
    root_agent_id: Optional[str] = None
    nodes: Dict[str, Any]
    edges: List[Dict[str, Any]]


class CheckpointResponse(BaseModel):
    id: str
    agent_id: Optional[str] = None
    agent_name: Optional[str] = None
    agent_type: Optional[str] = None
    iteration: int = 0
    status: Optional[str] = None
    total_tokens: int = 0
    tool_calls: int = 0
    findings_count: int = 0
    checkpoint_type: Optional[str] = None
    checkpoint_name: Optional[str] = None
    created_at: Optional[str] = None


@router.get("/{task_id}/tree", response_model=AgentTreeResponse)
async def get_agent_tree(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Return the live or persisted agent tree for a task."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.services.agent.core import agent_registry
    tree = agent_registry.get_agent_tree()
    nodes = tree.get("nodes", {}) if tree else {}
    if nodes:
        nodes = _merge_live_agent_tree_stats(nodes, get_agent=agent_registry.get_agent)
    else:
        from app.models.agent_task import AgentTreeNode
        result = await db.execute(select(AgentTreeNode).where(AgentTreeNode.task_id == task_id))
        db_nodes = result.scalars().all()
        nodes = {
            node.agent_id: {
                "id": node.agent_id,
                "name": node.agent_name,
                "type": node.agent_type,
                "parent_id": node.parent_agent_id,
                "status": node.status,
                "task": node.task_description,
                "result": {"summary": node.result_summary, "findings": [None] * (node.findings_count or 0)},
                "tool_calls": node.tool_calls,
                "iterations": node.iterations,
                "tokens_used": node.tokens_used,
            }
            for node in db_nodes
        }
    edges = []
    root_agent_id = None
    total_iterations = 0
    total_tool_calls = 0
    total_tokens = 0
    total_findings = 0
    for agent_id, node in nodes.items():
        parent_id = node.get("parent_id")
        if parent_id:
            edges.append({"source": parent_id, "target": agent_id})
        else:
            root_agent_id = root_agent_id or agent_id
        total_iterations += int(node.get("iterations", 0) or 0)
        total_tool_calls += int(node.get("tool_calls", 0) or 0)
        total_tokens += int(node.get("tokens_used", 0) or 0)
        result = node.get("result") or {}
        if isinstance(result, dict):
            total_findings += len(result.get("findings", []) or [])

    if total_findings == 0:
        total_findings = int(task.findings_count or 0)

    return AgentTreeResponse(
        task_id=task_id,
        total_agents=len(nodes),
        total_findings=total_findings,
        total_iterations=total_iterations,
        total_tool_calls=total_tool_calls,
        total_tokens=total_tokens,
        root_agent_id=root_agent_id,
        nodes=nodes,
        edges=edges,
    )


@router.get("/{task_id}/checkpoints", response_model=List[CheckpointResponse])
async def list_checkpoints(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """List task checkpoints."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.models.agent_task import AgentCheckpoint
    result = await db.execute(
        select(AgentCheckpoint)
        .where(AgentCheckpoint.task_id == task_id)
        .order_by(AgentCheckpoint.created_at.desc())
    )
    checkpoints = result.scalars().all()
    return [
        CheckpointResponse(
            id=cp.id,
            agent_id=cp.agent_id,
            agent_name=cp.agent_name,
            agent_type=cp.agent_type,
            iteration=cp.iteration or 0,
            status=cp.status,
            total_tokens=cp.total_tokens or 0,
            tool_calls=cp.tool_calls or 0,
            findings_count=cp.findings_count or 0,
            checkpoint_type=cp.checkpoint_type,
            checkpoint_name=cp.checkpoint_name,
            created_at=cp.created_at.isoformat() if cp.created_at else None,
        )
        for cp in checkpoints
    ]


@router.get("/{task_id}/checkpoints/{checkpoint_id}")
async def get_checkpoint_detail(
    task_id: str,
    checkpoint_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    """Return a checkpoint detail payload."""
    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    from app.models.agent_task import AgentCheckpoint
    checkpoint = await db.get(AgentCheckpoint, checkpoint_id)
    if not checkpoint or checkpoint.task_id != task_id:
        raise HTTPException(status_code=404, detail="Checkpoint not found")

    state_data = {}
    if checkpoint.state_data:
        try:
            state_data = json.loads(checkpoint.state_data)
        except json.JSONDecodeError:
            state_data = {}

    return {
        "id": checkpoint.id,
        "task_id": checkpoint.task_id,
        "agent_id": checkpoint.agent_id,
        "agent_name": checkpoint.agent_name,
        "agent_type": checkpoint.agent_type,
        "parent_agent_id": checkpoint.parent_agent_id,
        "iteration": checkpoint.iteration,
        "status": checkpoint.status,
        "total_tokens": checkpoint.total_tokens,
        "tool_calls": checkpoint.tool_calls,
        "findings_count": checkpoint.findings_count,
        "checkpoint_type": checkpoint.checkpoint_type,
        "checkpoint_name": checkpoint.checkpoint_name,
        "state_data": state_data,
        "metadata": checkpoint.checkpoint_metadata,
        "created_at": checkpoint.created_at.isoformat() if checkpoint.created_at else None,
    }


@router.get("/{task_id}/report")
async def generate_audit_report(
    task_id: str,
    format: str = Query("markdown", pattern="^(markdown|json|html)$"),
    template_id: Optional[str] = Query(None, description="闂佺厧顨庢禍婊堟偩閻愵剛鈻曞璺侯儏琚氶梺鍛婄☉閿曘儴鍟梺?ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
):
    """Generate a final vulnerability report for the task."""
    from fastapi.responses import Response
    from app.models.report_template import AgentTaskReport
    from app.services.task_report_service import generate_task_report

    task = await db.get(AgentTask, task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    project = await db.get(Project, task.project_id)
    if not project or project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")

    result = await db.execute(
        select(AgentFinding)
        .where(AgentFinding.task_id == task_id)
        .order_by(
            case(
                (AgentFinding.severity == 'critical', 1),
                (AgentFinding.severity == 'high', 2),
                (AgentFinding.severity == 'medium', 3),
                (AgentFinding.severity == 'low', 4),
                else_=5,
            ),
            AgentFinding.created_at.desc(),
        )
    )
    findings = result.scalars().all()
    report = await generate_task_report(db, task, project, findings, template_id=template_id, output_format=format)
    await db.commit()

    if format == "json":
        return report.report_json

    media_type = "text/markdown"
    extension = "md"
    if format == "html":
        media_type = "text/html"
        extension = "html"
    filename = f"audit_report_{task.id[:8]}_{datetime.now().strftime('%Y%m%d')}.{extension}"
    return Response(report.content, media_type=media_type, headers={"Content-Disposition": f"attachment; filename={filename}"})






