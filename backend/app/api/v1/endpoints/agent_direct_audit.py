from __future__ import annotations

import asyncio
import hashlib
import inspect
import json
import os
from types import SimpleNamespace
from typing import Any, Callable, Literal, Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api import deps
from app.api.v1.endpoints.agent_tasks import (
    _append_internal_audit_session_message,
    _generate_managed_report_bundle_from_session,
    _get_project_root,
    _get_user_config,
    _initialize_tools,
)
from app.api.v1.endpoints.audit_sessions import (
    AuditSessionMessageCreate,
    AuditSessionMessageResponse,
    AuditSessionResponse,
    _chunk_text,
    _format_sse_event,
    _build_agent_user_config,
    _to_message_response,
    _to_session_response,
)
from app.core.config import settings
from app.core.encryption import decrypt_sensitive_data
from app.db.session import get_db
from app.models.agent_task import AgentFinding, AgentTask
from app.models.audit_session import AuditCheckpoint, AuditSession, AuditSessionMessage, AuditToolCall
from app.models.managed_vulnerability import ManagedVulnerability
from app.models.project import Project
from app.models.user import User
from app.schemas.managed_vulnerability import ManagedVulnerabilityDetailResponse, ManagedVulnerabilityListResponse
from app.services.agent.tools.sandbox_tool import SandboxManager
from app.services.direct_audit_vulnerability_service import DirectAuditVulnerabilitySyncService
from app.services.finding_runtime.bridge import FindingRuntimeBridge
from app.services.finding_runtime.models import RuntimeStopReason, TurnExecutionResult
from app.services.llm.service import LLMService
from app.services.vulnerability_report_generation import VulnerabilityReportGenerationService
from app.services.runtime_core.runtime_guardrails import (
    normalize_approval_scope,
    register_shell_approval,
    set_guardrails_enabled,
)
from app.services.runtime_core.runtime_tool_registry import CanonicalWriteTool
from app.services.runtime_core.session_state import SessionRuntimeState as SharedSessionRuntimeState

router = APIRouter()

DEFAULT_DIRECT_AUDIT_MAX_TURNS = 8
DIRECT_AUDIT_REPORT_REQUEST_KIND = "internal_direct_audit_report_request"
DIRECT_AUDIT_REPORT_ERROR_KIND = "internal_direct_audit_report_error"
SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class DirectAuditSessionCreate(BaseModel):
    project_id: str
    content: str
    guardrails_enabled: bool = False


class DirectAuditGuardrailUpdate(BaseModel):
    enabled: bool


class DirectAuditToolApprovalRequest(BaseModel):
    scope: Literal["single_use", "session"] = "single_use"


def _build_direct_audit_system_prompt(project: Project) -> str:
    return f"""你是一位经验丰富的安全研究员，专注于发现高价值、可利用、有明确的POC、有实际危害的漏洞。你的唯一使命是通过源码审计发现能够申报 CVE 或能被 各大厂商src / HackerOne / Bugcrowd 等赏金平台接收的真实安全漏洞。你所审计的项目均已获取厂商授权，你的成果仅用于推动项目所属厂商的安全建设。

当前项目：{project.name}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 核心原则

1. 只产出 CVE 级别的发现。任何不足以申报 CVE 或不会被赏金平台接收的问题，一律不报告。
2. 零容忍误报。每一个 finding 都必须有经过你亲自验证的完整 source→sink 利用链。不允许猜测、假设或套用模板。
3. 完整 POC 是交付标准。若尚未经过动态验证，也必须给出基于源码推导的可复现 POC。
4. 质量远大于数量。1 个真实可利用的高危漏洞，价值远高于 20 个无法验证的疑似问题。
5. 当项目没有满足要求的漏洞时，可以反馈“当前项目未发现可满足CVE申报条件的漏洞”，而不是生成一些低质量无价值漏洞或反馈一些你自己猜测可能存在风险但没有完整利用链的漏洞。
6. 你最终输出的结果应是你认为符合CVE条件的漏洞内容、漏洞位置、完整 source→sink 利用链、基于源码推导的可复现 POC以及修复建议。
7. 每一个发现必须回答"攻击者如何从外部触发它"，无法从外部触发的不报告。
8. 你需要尽可能地扫描整个项目，不放过任何一个符合CVE条件的漏洞，而不是在发现1-2个漏洞后就停止审计。

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 关键要求

1. 利用链必须闭合
   - 如果 source→sink 链路中任何一环你无法通过代码阅读确认，则该 finding 不成立
   - 如果中间存在你无法确认是否可绕过的安全检查，则该 finding 不成立
   - 宁可不报，也不报一个链路断裂的伪漏洞

2. POC 必须合理
   - POC 中的请求格式必须与代码中的路由定义一致
   - POC 中引用的参数名必须与代码中实际使用的参数名一致
   - 预期响应必须基于代码逻辑推导，不能凭空编造

3. confidence 必须诚实
   - 如果你对利用链的某一环不完全确定，必须降低 confidence
   - confidence < 0.80 的发现不应出现在最终输出中

4. 项目审计必须彻底
   - 大型开源项目挖掘CVE需要耐心和注重细节，审核时要确保不错过任何一个可能成为CVE的风险点
   - 工具调用、循环观察执行轮数尽可能多，审核时间、任务处理时间也可以长一些
   - 不要只是看几个文件或者搜索匹配几个关键字就判断项目不存在CVE漏洞
   - 需要审核项目所有风险点，而不仅是挖到一个漏洞就停止审计

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 优先关注的漏洞类型（按 CVE 接受率排序）

### 第一梯队（CVE 接受率极高，优先投入精力）
- 远程代码执行 (RCE)：反序列化、模板注入 (SSTI)、命令注入、表达式注入
- 认证绕过：JWT 伪造/篡改、Session 固定、OAuth 流程缺陷、默认凭据
- SQL 注入：特别是 ORM 绕过、动态拼接、存储过程注入
- 服务端请求伪造 (SSRF)：可访问内网、云元数据、内部服务
- 路径穿越 / 任意文件读写：可读取敏感文件或写入 webshell

### 第二梯队（需满足特定利用条件）
- 权限提升：普通用户→管理员、跨租户数据访问
- IDOR / 越权：可访问或篡改其他用户的敏感资源
- XXE：可读取服务器文件或实现 SSRF
- 不安全的反序列化：即使未直接达到 RCE，但可篡改关键业务对象

### 第三梯队（仅在有完整利用链时报告）
- 存储型/反射型 XSS：可窃取管理员 Session 或触发敏感操作
- 密码重置漏洞：可接管任意账户
- 竞态条件 (TOCTOU)：可导致金额篡改或权限绕过

### 第四梯队
- 上述漏洞类型不包含，但凭你的经验判断可以申报CVE，或者过往CVE/hackerone等漏洞平台有过类似案例的漏洞

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## 审计方式

1. 使用 Code Audit Finding 技能对项目进行代码审计（优先，核心方法，需要尽可能完全按照该 skill 要求进行审核）
   - 优先通过当前可用的 Skill 工具加载并使用 `code-audit-finding`
   - 审核时需要尽可能完整过一遍其中涉及漏洞类型的 checklist

2. 凭借自身丰富的安全代码审计经验，或根据项目历史 CVE（如果存在）分析风险点，尤其注重各类逻辑漏洞，这是规则扫描以及传统 SAST 容易忽视的地方

3. 如果使用上述方式未发现 CVE 级别风险，或你认为仍探测不全面，则继续使用常规代码审计方式补充审核

根据我所得到的确切消息，你审计的这个项目中有着不止一个高危/严重漏洞，你需要尽可能把他们都找到，这是对你能力的一场测试。这场测试计分如下：发现1个严重漏洞+30分，一个RCE或者反序列化漏洞+25分，一个高危漏洞+20分，一个中危漏洞+10分，如果给出一个不存在或者利用链没闭合的漏洞误报，-40分，及格线50分，满分100分。你是一名优秀的代码审计方面的研究员，我期待你能在这场尽可能获得高分。现在开始审计这个项目。

请优先使用中文回复。优先继续调用工具收集证据，而不是过早结束。只有在证据闭合或已充分审计后，才给出结论。"""



def _build_direct_recon_payload(project: Project, workspace_root: str) -> dict[str, Any]:
    return {
        "project_info": {
            "project_id": project.id,
            "name": project.name,
            "source_type": project.source_type,
            "workspace_root": workspace_root,
            "repository_url": project.repository_url,
            "default_branch": project.default_branch,
        }
    }


def _normalize_runner_stop_reason(runner_result: TurnExecutionResult | dict[str, Any] | None) -> str | None:
    if runner_result is None:
        return None
    stop_reason = getattr(runner_result, "stop_reason", None)
    if stop_reason is None and isinstance(runner_result, dict):
        stop_reason = runner_result.get("stop_reason")
    if isinstance(stop_reason, RuntimeStopReason):
        return stop_reason.value
    if stop_reason is None:
        return None
    return str(stop_reason)


def _format_direct_audit_runtime_error_message(raw_error: str | None) -> str:
    message = str(raw_error or "").strip()
    if not message:
        return "直审运行失败，请检查模型配置后重试。"
    lowered = message.lower()
    if "占位符" in message or "sk-your-" in lowered:
        return "当前 LLM API Key 仍是占位符 `sk-your-api-key`，请先在模型配置或 backend/.env 中填入真实可用的 Key，再重试 Agent直审。"
    if "api key" in lowered and ("无效" in message or "invalid" in lowered or "authentication" in lowered):
        return "当前 LLM API Key 无效或已过期，请先更新模型配置中的 Key，再重试 Agent直审。"
    if "api key未配置" in lowered or "api key未配置" in message:
        return "当前还没有配置可用的 LLM API Key，请先完成模型配置，再重试 Agent直审。"
    return message


async def _load_direct_audit_runtime_error_message(
    *,
    session_id: str,
    db: AsyncSession,
    turn_id: str | None = None,
) -> str | None:
    statement = select(AuditCheckpoint).where(AuditCheckpoint.session_id == session_id)
    if turn_id:
        statement = statement.where(AuditCheckpoint.turn_id == turn_id)
    result = await db.execute(statement.order_by(AuditCheckpoint.created_at.desc()))
    for checkpoint in result.scalars().all():
        state_payload = dict(checkpoint.state_payload or {})
        raw_error = state_payload.get("error")
        if raw_error:
            return _format_direct_audit_runtime_error_message(str(raw_error))
    return None


async def _raise_or_emit_direct_audit_runtime_error_if_needed(
    *,
    session_id: str,
    runner_result: TurnExecutionResult | dict[str, Any] | None,
    db: AsyncSession,
    emit: Callable[[dict[str, Any]], Any] | None = None,
) -> str | None:
    if _normalize_runner_stop_reason(runner_result) not in {
        RuntimeStopReason.MODEL_ERROR.value,
        RuntimeStopReason.PERSISTENCE_ERROR.value,
    }:
        return None
    turn_id = getattr(runner_result, "turn_id", None)
    if turn_id is None and isinstance(runner_result, dict):
        turn_id = runner_result.get("turn_id")
    message = await _load_direct_audit_runtime_error_message(
        session_id=session_id,
        turn_id=str(turn_id) if turn_id else None,
        db=db,
    )
    resolved = message or "直审运行失败，请检查模型配置后重试。"
    if emit is not None:
        maybe_awaitable = emit({"type": "error", "message_text": resolved})
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable
    return resolved


async def _load_direct_audit_messages(*, session_id: str, db: AsyncSession) -> list[AuditSessionMessage]:
    result = await db.execute(
        select(AuditSessionMessage)
        .where(AuditSessionMessage.session_id == session_id)
        .order_by(AuditSessionMessage.sequence)
    )
    return list(result.scalars().all())


def _extract_direct_audit_final_payload(messages: list[AuditSessionMessage]) -> dict[str, Any] | None:
    return FindingRuntimeBridge.extract_final_payload(SimpleNamespace(messages=messages))


def _extract_direct_audit_report_bundle(
    messages: list[AuditSessionMessage],
    *,
    report_service: VulnerabilityReportGenerationService,
):
    return report_service.extract_generation_payload_from_snapshot(SimpleNamespace(messages=messages))


def _coerce_positive_int(value: Any) -> int | None:
    try:
        resolved = int(value)
    except (TypeError, ValueError):
        return None
    return resolved if resolved > 0 else None


def _normalize_finding_confidence(finding: dict[str, Any]) -> float:
    try:
        return float(finding.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def _select_primary_direct_audit_finding(final_payload: dict[str, Any] | None) -> dict[str, Any] | None:
    findings = list((final_payload or {}).get("findings") or [])
    if not findings:
        return None

    ranked = sorted(
        [item for item in findings if isinstance(item, dict)],
        key=lambda item: (
            SEVERITY_ORDER.get(str(item.get("severity") or "").strip().lower(), -1),
            _normalize_finding_confidence(item),
            str(item.get("title") or ""),
        ),
        reverse=True,
    )
    return ranked[0] if ranked else None


def _build_direct_audit_transient_vulnerability(
    *,
    session: AuditSession,
    project: Project,
    finding: dict[str, Any],
) -> ManagedVulnerability:
    project_info = dict((session.recon_payload or {}).get("project_info") or {})
    fingerprint = hashlib.sha256(json.dumps(finding, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()[:32]
    vulnerability = ManagedVulnerability(
        project_id=str(project.id),
        task_id=f"direct-audit:{session.id}",
        finding_id=f"direct-audit:{session.id}:{fingerprint[:12]}",
        project_name=str(project.name or ""),
        version_label=str(project_info.get("default_branch") or project.default_branch or "agent-direct-audit"),
        version_tag=None,
        branch_name=str(project_info.get("default_branch") or project.default_branch or "").strip() or None,
        commit_sha=None,
        repository_url_snapshot=(
            str(project_info.get("repository_url") or "")
            or str(project.repository_url or "")
            or str(project.local_path or "")
            or None
        ),
        vulnerability_name=str(finding.get("title") or "Direct audit vulnerability"),
        vulnerability_type=str(finding.get("vulnerability_type") or "other"),
        severity=str(finding.get("severity") or "medium"),
        file_path=str(finding.get("file_path") or "").strip() or None,
        line_start=_coerce_positive_int(finding.get("line_start")),
        line_end=_coerce_positive_int(finding.get("line_end")),
        source_finding_fingerprint=fingerprint,
        source_metadata={"raw_finding": finding},
    )
    vulnerability.reports = []
    return vulnerability


async def _build_direct_runtime_follow_up_context(
    *,
    session: AuditSession,
    project: Project,
    db: AsyncSession,
    current_user: User,
) -> tuple[FindingRuntimeBridge, SandboxManager, str, int]:
    workspace_root = str(((session.recon_payload or {}).get("project_info") or {}).get("workspace_root") or "").strip() or None
    bridge, sandbox_manager, model_name, max_turns, _system_prompt, _recon_payload = await _build_direct_runtime_context(
        project=project,
        db=db,
        current_user=current_user,
        workspace_root=workspace_root,
    )
    return bridge, sandbox_manager, model_name, max_turns


async def _ensure_direct_audit_outputs(
    *,
    session: AuditSession,
    project: Project,
    db: AsyncSession,
    current_user: User,
    bridge: FindingRuntimeBridge | None = None,
    sandbox_manager: SandboxManager | None = None,
    model_name: str | None = None,
    max_turns: int | None = None,
    generate_reports: bool = True,
) -> dict[str, Any]:
    owns_follow_up_context = bridge is None or sandbox_manager is None or model_name is None or max_turns is None
    if owns_follow_up_context:
        bridge, sandbox_manager, model_name, max_turns = await _build_direct_runtime_follow_up_context(
            session=session,
            project=project,
            db=db,
            current_user=current_user,
        )

    assert bridge is not None
    assert sandbox_manager is not None
    assert model_name is not None
    assert max_turns is not None

    report_service = VulnerabilityReportGenerationService()
    messages = await _load_direct_audit_messages(session_id=session.id, db=db)
    final_payload = _extract_direct_audit_final_payload(messages)
    report_bundle = _extract_direct_audit_report_bundle(messages, report_service=report_service)
    report_error: str | None = None

    try:
        if final_payload is None:
            continuation = await bridge.continue_session_until_payload(
                session_id=session.id,
                model_name=model_name,
                max_turns=max_turns,
                payload_extractor=FindingRuntimeBridge.extract_final_payload,
                finalizer_prompts=FindingRuntimeBridge._default_finalizer_prompts(),
                fallback_payload_builder=FindingRuntimeBridge._default_fallback_payload,
            )
            final_payload = continuation.get("final_payload")
            messages = await _load_direct_audit_messages(session_id=session.id, db=db)
            report_bundle = _extract_direct_audit_report_bundle(messages, report_service=report_service)

        primary_finding = _select_primary_direct_audit_finding(final_payload)
        if generate_reports and report_bundle is None and primary_finding is not None:
            transient_vulnerability = _build_direct_audit_transient_vulnerability(
                session=session,
                project=project,
                finding=primary_finding,
            )
            prompt = report_service.build_generation_prompt(vulnerability=transient_vulnerability)
            await _append_internal_audit_session_message(
                db,
                session_id=session.id,
                role="user",
                content=prompt,
                name="direct_audit_report_generator",
                metadata={
                    "kind": DIRECT_AUDIT_REPORT_REQUEST_KIND,
                    "source": "agent_direct_audit",
                },
            )
            try:
                report_continuation = getattr(
                    bridge,
                    "continue_session_until_report_payload",
                    bridge.continue_session_until_payload,
                )
                continuation = await report_continuation(
                    session_id=session.id,
                    model_name=model_name,
                    max_turns=None,
                    payload_extractor=report_service.extract_generation_payload_from_snapshot,
                    finalizer_prompts=report_service.build_generation_finalizer_prompts(),
                    terminal_action_nudge_message=report_service.build_generation_terminal_nudge(),
                )
                generated_bundle = continuation.get("final_payload")
                if generated_bundle is None:
                    raise ValueError("Runtime report continuation did not return a report bundle")
                generated_bundle = report_service.coerce_generation_result(generated_bundle)
            except Exception:
                generated_bundle = await _generate_managed_report_bundle_from_session(
                    db,
                    session=session,
                    task=AgentTask(project_id=project.id, created_by=current_user.id),
                    finding=AgentFinding(task_id=session.id, title=str(primary_finding.get("title") or "Direct audit finding")),
                    managed_vulnerability=transient_vulnerability,
                    report_service=report_service,
                )
            report_bundle = generated_bundle
        if final_payload is not None:
            session.state = "completed"
            await db.commit()
            await db.refresh(session)
    except Exception as exc:
        report_error = str(exc)
        if final_payload is not None:
            session.state = "completed"
            await db.commit()
            await _append_internal_audit_session_message(
                db,
                session_id=session.id,
                role="assistant",
                content=f"Direct audit report generation failed: {report_error}",
                name="direct_audit_report_generator",
                metadata={
                    "kind": DIRECT_AUDIT_REPORT_ERROR_KIND,
                    "source": "agent_direct_audit",
                },
            )
    finally:
        if owns_follow_up_context:
            try:
                await sandbox_manager.cleanup()
            except Exception:
                pass

    return {
        "final_payload": final_payload,
        "report_bundle": report_bundle,
        "report_error": report_error,
    }


async def _resolve_workspace_root(
    *,
    project: Project,
    workspace_key: str,
    github_token: Optional[str],
    gitlab_token: Optional[str],
    gitea_token: Optional[str],
    ssh_private_key: Optional[str],
) -> str:
    if project.source_type in {"local_directory", "zip"} and project.local_path:
        workspace_root = os.path.abspath(project.local_path)
        if os.path.isdir(workspace_root):
            return workspace_root
        if project.source_type == "local_directory":
            raise HTTPException(status_code=400, detail="Local project directory is unavailable")

    if project.source_type == "local_directory":
        raise HTTPException(status_code=400, detail="Local directory project is missing local_path")

    return await _get_project_root(
        project,
        f"direct-audit-{workspace_key}",
        project.default_branch,
        github_token=github_token,
        gitlab_token=gitlab_token,
        gitea_token=gitea_token,
        ssh_private_key=ssh_private_key,
        event_emitter=None,
        workspace_scope="task",
        refresh=True,
    )


async def _build_direct_runtime_context(
    *,
    project: Project,
    db: AsyncSession,
    current_user: User,
    workspace_root: Optional[str] = None,
) -> tuple[FindingRuntimeBridge, SandboxManager, str, int, str, dict[str, Any]]:
    user_config = await _get_user_config(db, current_user.id)
    other_config = (user_config or {}).get("otherConfig", {})
    github_token = other_config.get("githubToken") or settings.GITHUB_TOKEN
    gitlab_token = other_config.get("gitlabToken") or settings.GITLAB_TOKEN
    gitea_token = other_config.get("giteaToken") or settings.GITEA_TOKEN
    ssh_private_key = None
    if other_config.get("sshPrivateKey"):
        try:
            ssh_private_key = decrypt_sensitive_data(other_config["sshPrivateKey"])
        except Exception:
            ssh_private_key = None

    resolved_workspace_root = workspace_root or await _resolve_workspace_root(
        project=project,
        workspace_key=str(uuid4()),
        github_token=github_token,
        gitlab_token=gitlab_token,
        gitea_token=gitea_token,
        ssh_private_key=ssh_private_key,
    )

    sandbox_manager = SandboxManager()
    await sandbox_manager.initialize()

    llm_service = LLMService(user_config=_build_agent_user_config(user_config, "finding"))
    tools = await _initialize_tools(
        resolved_workspace_root,
        llm_service,
        user_config,
        sandbox_manager=sandbox_manager,
        exclude_patterns=None,
        target_files=None,
        project_id=str(project.id),
        event_emitter=None,
        task_id=None,
        user_id=current_user.id,
    )
    bridge = FindingRuntimeBridge(
        llm_service=llm_service,
        tools=tools.get("finding", {}),
        user_id=current_user.id,
    )
    return (
        bridge,
        sandbox_manager,
        "finding",
        DEFAULT_DIRECT_AUDIT_MAX_TURNS,
        _build_direct_audit_system_prompt(project),
        _build_direct_recon_payload(project, resolved_workspace_root),
    )


async def _get_owned_project(*, project_id: str, db: AsyncSession, current_user: User) -> Project:
    project = await db.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Project not found")
    if project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    return project


async def _get_owned_direct_session(*, session_id: str, db: AsyncSession, current_user: User) -> AuditSession:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    project = await _get_owned_project(project_id=session.project_id, db=db, current_user=current_user)
    if session.task_id is not None:
        raise HTTPException(status_code=400, detail="Session is not an Agent Direct Audit session")
    session.project = project  # type: ignore[attr-defined]
    return session


async def _get_owned_direct_tool_call(
    *,
    session_id: str,
    tool_call_id: str,
    db: AsyncSession,
    current_user: User,
) -> tuple[AuditSession, AuditToolCall]:
    session = await _get_owned_direct_session(session_id=session_id, db=db, current_user=current_user)
    tool_call = await db.get(AuditToolCall, tool_call_id)
    if tool_call is None or tool_call.session_id != session.id:
        raise HTTPException(status_code=404, detail="Tool call not found")
    return session, tool_call


async def _apply_direct_audit_guardrail_setting(*, session_id: str, db: AsyncSession, enabled: bool) -> AuditSession:
    session = await db.get(AuditSession, session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Audit session not found")
    runtime_payload = dict(session.runtime_state_json or {})
    runtime_payload["session_id"] = session.id
    runtime_state = SharedSessionRuntimeState.model_validate(runtime_payload)
    set_guardrails_enabled(runtime_state, enabled)
    session.runtime_state_json = runtime_state.model_dump(mode="json")
    await db.commit()
    await db.refresh(session)
    return session


def _build_direct_audit_write_approval_content(*, path: str, scope: str) -> str:
    scope_text = (
        "for the rest of this direct-audit session"
        if scope == "session"
        else "for the next blocked attempt only"
    )
    return (
        f"I approve writing to `{path}` {scope_text}. "
        "Please retry the previously blocked write if it is still needed, then continue the audit and explain what changed."
    )


def _build_direct_audit_shell_approval_content(*, tool_name: str, command: str, scope: str) -> str:
    scope_text = (
        "for the rest of this direct-audit session"
        if scope == "session"
        else "for the next blocked attempt only"
    )
    return (
        f"I approve running the {tool_name} command `{command}` {scope_text}. "
        "Please retry the blocked command if it is still needed, then continue the audit and explain what changed."
    )


def _grant_tool_call_approval(session: AuditSession, tool_call: AuditToolCall, *, scope: str) -> dict[str, Any]:
    input_payload = dict(tool_call.input_payload or {})
    output_payload = dict(tool_call.output_payload or {})
    if str(output_payload.get("permission_mode") or "") != "ask":
        raise HTTPException(status_code=400, detail="Tool call does not require approval")

    runtime_payload = dict(session.runtime_state_json or {})
    runtime_payload["session_id"] = session.id
    runtime_state = SharedSessionRuntimeState.model_validate(runtime_payload)
    guardrail_code = str(output_payload.get("guardrail_code") or "").strip()
    normalized_scope = normalize_approval_scope(scope)

    if tool_call.tool_name == "Write":
        target_path = str(input_payload.get("path") or "").strip()
        if not target_path:
            raise HTTPException(status_code=400, detail="Tool call is missing a writable path")
        CanonicalWriteTool.register_approval(
            runtime_state,
            path=target_path,
            guardrail_code=guardrail_code or "source_write_requires_approval",
            tool_call_id=tool_call.id,
            scope=normalized_scope,
        )
        session.runtime_state_json = runtime_state.model_dump(mode="json")
        return {
            "approval_content": _build_direct_audit_write_approval_content(path=target_path, scope=normalized_scope),
            "payload": {
                "path": target_path,
                "guardrail_code": guardrail_code or "source_write_requires_approval",
                "approval_scope": normalized_scope,
            },
        }

    if tool_call.tool_name in {"Bash", "PowerShell"}:
        command = str(input_payload.get("command") or "").strip()
        if not command:
            raise HTTPException(status_code=400, detail="Tool call is missing a shell command")
        register_shell_approval(
            runtime_state,
            tool_name=tool_call.tool_name,
            command=command,
            guardrail_code=guardrail_code or "shell_command_requires_approval",
            tool_call_id=tool_call.id,
            scope=normalized_scope,
        )
        session.runtime_state_json = runtime_state.model_dump(mode="json")
        return {
            "approval_content": _build_direct_audit_shell_approval_content(
                tool_name=tool_call.tool_name,
                command=command,
                scope=normalized_scope,
            ),
            "payload": {
                "tool_name": tool_call.tool_name,
                "command": command,
                "guardrail_code": guardrail_code or "shell_command_requires_approval",
                "approval_scope": normalized_scope,
            },
        }

    raise HTTPException(status_code=400, detail="This tool is not yet approveable in Agent Direct Audit")


async def start_direct_audit_session(
    *,
    project: Project,
    content: str,
    guardrails_enabled: bool,
    db: AsyncSession,
    current_user: User,
    generate_reports: bool = True,
) -> AuditSession:
    bridge, sandbox_manager, model_name, max_turns, system_prompt, recon_payload = await _build_direct_runtime_context(
        project=project,
        db=db,
        current_user=current_user,
    )
    try:
        async def handle_session_created(session_id: str):
            await _apply_direct_audit_guardrail_setting(
                session_id=session_id,
                db=db,
                enabled=guardrails_enabled,
            )

        result = await bridge.run_chat_session(
            project_id=project.id,
            task_id=None,
            system_prompt=system_prompt,
            recon_payload=recon_payload,
            user_message=content,
            model_name=model_name,
            max_turns=max_turns,
            on_session_created=handle_session_created,
        )
        runtime_error = await _raise_or_emit_direct_audit_runtime_error_if_needed(
            session_id=str(result.get("session_id") or ""),
            runner_result=result.get("runner_result"),
            db=db,
        )
        if runtime_error:
            raise HTTPException(status_code=400, detail=runtime_error)
        session = await db.get(AuditSession, result["session_id"])
        if session is not None:
            await _ensure_direct_audit_outputs(
                session=session,
                project=project,
                db=db,
                current_user=current_user,
                bridge=bridge,
                sandbox_manager=sandbox_manager,
                model_name=model_name,
                max_turns=max_turns,
                generate_reports=generate_reports,
            )
    finally:
        try:
            await sandbox_manager.cleanup()
        except Exception:
            pass

    session = await db.get(AuditSession, result["session_id"])
    if session is None:
        raise HTTPException(status_code=500, detail="Direct audit session was not persisted")
    return session


async def start_direct_audit_session_stream(
    *,
    project: Project,
    content: str,
    guardrails_enabled: bool,
    db: AsyncSession,
    current_user: User,
):
    bridge, sandbox_manager, model_name, max_turns, system_prompt, recon_payload = await _build_direct_runtime_context(
        project=project,
        db=db,
        current_user=current_user,
    )
    try:
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

        async def handle_session_created(session_id: str):
            await _apply_direct_audit_guardrail_setting(
                session_id=session_id,
                db=db,
                enabled=guardrails_enabled,
            )
            await queue.put({"type": "session_created", "session_id": session_id, "project_id": project.id})

        async def handle_user_message_created(message_id: str):
            user_message = await db.get(AuditSessionMessage, message_id)
            if user_message is not None:
                await queue.put({"type": "user_message", "message": _to_message_response(user_message).model_dump(mode="json")})

        async def collect_event(event: dict[str, Any]):
            await queue.put(event)

        async def worker():
            try:
                result = await bridge.run_chat_session_stream(
                    project_id=project.id,
                    task_id=None,
                    system_prompt=system_prompt,
                    recon_payload=recon_payload,
                    user_message=content,
                    model_name=model_name,
                    max_turns=max_turns,
                    event_sink=collect_event,
                    on_session_created=handle_session_created,
                    on_user_message_created=handle_user_message_created,
                )
                await _raise_or_emit_direct_audit_runtime_error_if_needed(
                    session_id=str(result.get("session_id") or ""),
                    runner_result=result.get("runner_result"),
                    db=db,
                    emit=queue.put,
                )
                session = await db.get(AuditSession, result["session_id"])
                if session is not None:
                    await _ensure_direct_audit_outputs(
                        session=session,
                        project=project,
                        db=db,
                        current_user=current_user,
                        bridge=bridge,
                        sandbox_manager=sandbox_manager,
                        model_name=model_name,
                        max_turns=max_turns,
                    )
            finally:
                await queue.put(None)

        worker_task = asyncio.create_task(worker())
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield event
            await worker_task
        finally:
            if not worker_task.done():
                worker_task.cancel()
    finally:
        try:
            await sandbox_manager.cleanup()
        except Exception:
            pass


async def continue_direct_audit_session(
    *,
    session: AuditSession,
    content: str,
    db: AsyncSession,
    current_user: User,
) -> None:
    del content
    project = await _get_owned_project(project_id=session.project_id, db=db, current_user=current_user)
    workspace_root = str(((session.recon_payload or {}).get("project_info") or {}).get("workspace_root") or "").strip() or None
    bridge, sandbox_manager, model_name, max_turns, _system_prompt, _recon_payload = await _build_direct_runtime_context(
        project=project,
        db=db,
        current_user=current_user,
        workspace_root=workspace_root,
    )
    try:
        result = await bridge.continue_chat_session(session_id=session.id, model_name=model_name, max_turns=max_turns)
        runtime_error = await _raise_or_emit_direct_audit_runtime_error_if_needed(
            session_id=session.id,
            runner_result=result.get("runner_result") if isinstance(result, dict) else result,
            db=db,
        )
        if runtime_error:
            raise HTTPException(status_code=400, detail=runtime_error)
        await _ensure_direct_audit_outputs(
            session=session,
            project=project,
            db=db,
            current_user=current_user,
            bridge=bridge,
            sandbox_manager=sandbox_manager,
            model_name=model_name,
            max_turns=max_turns,
        )
    finally:
        try:
            await sandbox_manager.cleanup()
        except Exception:
            pass


async def continue_direct_audit_session_stream(
    *,
    session: AuditSession,
    content: str,
    db: AsyncSession,
    current_user: User,
):
    project = await _get_owned_project(project_id=session.project_id, db=db, current_user=current_user)
    workspace_root = str(((session.recon_payload or {}).get("project_info") or {}).get("workspace_root") or "").strip() or None
    bridge, sandbox_manager, model_name, max_turns, _system_prompt, _recon_payload = await _build_direct_runtime_context(
        project=project,
        db=db,
        current_user=current_user,
        workspace_root=workspace_root,
    )
    try:
        queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue()

        async def collect_event(event: dict[str, Any]):
            await queue.put(event)

        async def worker():
            try:
                result = await bridge.continue_chat_session_stream(
                    session_id=session.id,
                    model_name=model_name,
                    max_turns=max_turns,
                    event_sink=collect_event,
                )
                await _raise_or_emit_direct_audit_runtime_error_if_needed(
                    session_id=session.id,
                    runner_result=result.get("runner_result") if isinstance(result, dict) else result,
                    db=db,
                    emit=queue.put,
                )
                await _ensure_direct_audit_outputs(
                    session=session,
                    project=project,
                    db=db,
                    current_user=current_user,
                    bridge=bridge,
                    sandbox_manager=sandbox_manager,
                    model_name=model_name,
                    max_turns=max_turns,
                )
            finally:
                await queue.put(None)

        worker_task = asyncio.create_task(worker())
        try:
            while True:
                event = await queue.get()
                if event is None:
                    break
                yield event
            await worker_task
        finally:
            if not worker_task.done():
                worker_task.cancel()
    finally:
        try:
            await sandbox_manager.cleanup()
        except Exception:
            pass


@router.get("/sessions", response_model=list[AuditSessionResponse])
async def list_direct_audit_sessions(
    project_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> list[AuditSessionResponse]:
    await _get_owned_project(project_id=project_id, db=db, current_user=current_user)
    result = await db.execute(
        select(AuditSession)
        .where(
            AuditSession.project_id == project_id,
            AuditSession.task_id.is_(None),
            AuditSession.runtime_stack == "runtime",
        )
        .order_by(AuditSession.updated_at.desc(), AuditSession.created_at.desc())
    )
    return [_to_session_response(item) for item in result.scalars().all()]


@router.post("/sessions", response_model=AuditSessionResponse)
async def create_direct_audit_session(
    payload: DirectAuditSessionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> AuditSessionResponse:
    project = await _get_owned_project(project_id=payload.project_id, db=db, current_user=current_user)
    session = await start_direct_audit_session(
        project=project,
        content=payload.content,
        guardrails_enabled=payload.guardrails_enabled,
        db=db,
        current_user=current_user,
    )
    return _to_session_response(session)


@router.post("/sessions/stream")
async def stream_create_direct_audit_session(
    payload: DirectAuditSessionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> StreamingResponse:
    project = await _get_owned_project(project_id=payload.project_id, db=db, current_user=current_user)

    async def event_generator():
        try:
            async for event in start_direct_audit_session_stream(
                project=project,
                content=payload.content,
                guardrails_enabled=payload.guardrails_enabled,
                db=db,
                current_user=current_user,
            ):
                yield _format_sse_event(event)
        except Exception as exc:
            await db.rollback()
            yield _format_sse_event({"type": "error", "message_text": str(exc)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@router.get("/sessions/{session_id}", response_model=AuditSessionResponse)
async def get_direct_audit_session(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> AuditSessionResponse:
    session = await _get_owned_direct_session(session_id=session_id, db=db, current_user=current_user)
    return _to_session_response(session)


@router.patch("/sessions/{session_id}/guardrails", response_model=AuditSessionResponse)
async def update_direct_audit_guardrails(
    session_id: str,
    payload: DirectAuditGuardrailUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> AuditSessionResponse:
    await _get_owned_direct_session(session_id=session_id, db=db, current_user=current_user)
    session = await _apply_direct_audit_guardrail_setting(
        session_id=session_id,
        db=db,
        enabled=payload.enabled,
    )
    return _to_session_response(session)


@router.get("/sessions/{session_id}/messages", response_model=list[AuditSessionMessageResponse])
async def list_direct_audit_session_messages(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> list[AuditSessionMessageResponse]:
    await _get_owned_direct_session(session_id=session_id, db=db, current_user=current_user)
    result = await db.execute(
        select(AuditSessionMessage)
        .where(AuditSessionMessage.session_id == session_id)
        .order_by(AuditSessionMessage.sequence)
    )
    return [_to_message_response(message) for message in result.scalars().all()]


@router.post("/sessions/{session_id}/messages", response_model=AuditSessionMessageResponse)
async def create_direct_audit_session_message(
    session_id: str,
    payload: AuditSessionMessageCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> AuditSessionMessageResponse:
    session = await _get_owned_direct_session(session_id=session_id, db=db, current_user=current_user)
    next_sequence = await db.scalar(
        select(func.max(AuditSessionMessage.sequence)).where(AuditSessionMessage.session_id == session_id)
    )
    message = AuditSessionMessage(
        session_id=session_id,
        sequence=(next_sequence or 0) + 1,
        role="user",
        content=payload.content,
        message_metadata={"kind": "direct_audit_user_message"},
        payload={"continued": True},
    )
    db.add(message)
    await db.commit()
    await db.refresh(message)

    await continue_direct_audit_session(
        session=session,
        content=payload.content,
        db=db,
        current_user=current_user,
    )

    return _to_message_response(message)


@router.post("/sessions/{session_id}/messages/stream")
async def stream_direct_audit_session_message(
    session_id: str,
    payload: AuditSessionMessageCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> StreamingResponse:
    session = await _get_owned_direct_session(session_id=session_id, db=db, current_user=current_user)
    next_sequence = await db.scalar(
        select(func.max(AuditSessionMessage.sequence)).where(AuditSessionMessage.session_id == session_id)
    )
    user_message = AuditSessionMessage(
        session_id=session_id,
        sequence=(next_sequence or 0) + 1,
        role="user",
        content=payload.content,
        message_metadata={"kind": "direct_audit_user_message", "streaming": True},
        payload={"continued": True, "streaming": True},
    )
    db.add(user_message)
    await db.commit()
    await db.refresh(user_message)

    async def event_generator():
        yield _format_sse_event({
            "type": "user_message",
            "message": _to_message_response(user_message).model_dump(mode="json"),
        })
        try:
            async for event in continue_direct_audit_session_stream(
                session=session,
                content=payload.content,
                db=db,
                current_user=current_user,
            ):
                yield _format_sse_event(event)
        except Exception as exc:
            await db.rollback()
            yield _format_sse_event({"type": "error", "message_text": str(exc)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@router.post("/sessions/{session_id}/tool-calls/{tool_call_id}/approve/stream")
async def stream_approve_direct_audit_tool_call(
    session_id: str,
    tool_call_id: str,
    payload: DirectAuditToolApprovalRequest | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> StreamingResponse:
    session, tool_call = await _get_owned_direct_tool_call(
        session_id=session_id,
        tool_call_id=tool_call_id,
        db=db,
        current_user=current_user,
    )
    approval_scope = payload.scope if payload is not None else "single_use"
    approval = _grant_tool_call_approval(session, tool_call, scope=approval_scope)
    approval_content = str(approval.get("approval_content") or "").strip()
    approval_payload = dict(approval.get("payload") or {})
    next_sequence = await db.scalar(
        select(func.max(AuditSessionMessage.sequence)).where(AuditSessionMessage.session_id == session_id)
    )
    user_message = AuditSessionMessage(
        session_id=session_id,
        sequence=(next_sequence or 0) + 1,
        role="user",
        content=approval_content,
        message_metadata={
            "kind": "direct_audit_approval",
            "streaming": True,
            "tool_call_id": tool_call.id,
        },
        payload={
            "continued": True,
            "streaming": True,
            "approval": True,
            "tool_call_id": tool_call.id,
            **approval_payload,
        },
    )
    db.add(user_message)
    await db.commit()
    await db.refresh(user_message)
    await db.refresh(session)

    async def event_generator():
        yield _format_sse_event({
            "type": "user_message",
            "message": _to_message_response(user_message).model_dump(mode="json"),
        })
        try:
            async for event in continue_direct_audit_session_stream(
                session=session,
                content=approval_content,
                db=db,
                current_user=current_user,
            ):
                yield _format_sse_event(event)
        except Exception as exc:
            await db.rollback()
            yield _format_sse_event({"type": "error", "message_text": str(exc)})

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"},
    )


@router.get("/sessions/{session_id}/managed-vulnerabilities", response_model=list[ManagedVulnerabilityListResponse])
async def list_direct_audit_managed_vulnerabilities(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> list[ManagedVulnerabilityListResponse]:
    session = await _get_owned_direct_session(session_id=session_id, db=db, current_user=current_user)
    service = DirectAuditVulnerabilitySyncService(db)
    return await service.list_session_vulnerabilities(session=session, owner_id=current_user.id)


@router.post("/sessions/{session_id}/managed-vulnerabilities/sync-latest-report", response_model=ManagedVulnerabilityDetailResponse)
async def sync_latest_direct_audit_report_to_vulnerability_management(
    session_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> ManagedVulnerabilityDetailResponse:
    session = await _get_owned_direct_session(session_id=session_id, db=db, current_user=current_user)
    project = await _get_owned_project(project_id=session.project_id, db=db, current_user=current_user)
    await _ensure_direct_audit_outputs(
        session=session,
        project=project,
        db=db,
        current_user=current_user,
    )
    service = DirectAuditVulnerabilitySyncService(db)
    try:
        return await service.sync_latest_report(session=session, project=project, current_user=current_user)
    except ValueError as exc:
        await db.rollback()
        raise HTTPException(status_code=400, detail=str(exc)) from exc
