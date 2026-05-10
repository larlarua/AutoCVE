from __future__ import annotations

import json
from copy import deepcopy
from typing import Any, Dict, Optional

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.api import deps
from app.core.config import settings
from app.core.encryption import decrypt_sensitive_data, encrypt_sensitive_data
from app.db.session import get_db
from app.models.user import User
from app.models.user_config import UserConfig
from app.services.agent.skill_service import SkillService
from app.services.init_agent_assets import init_agent_assets
from app.services.llm.factory import LLMFactory
from app.services.llm.service import LLMService
from app.services.report_template_file_service import ReportTemplateFileService
from app.services.skill_file_service import SkillFileService

router = APIRouter()

AGENT_TYPES = ["orchestrator", "recon", "scan", "triage", "finding", "verification"]
WORKFLOW_AGENT_TYPES = ["orchestrator", "recon", "scan", "triage", "finding", "verification"]
WORKFLOW_LOCKED_AGENTS = {"orchestrator", "recon"}
SENSITIVE_LLM_FIELDS = [
    "llmApiKey",
    "geminiApiKey",
    "openaiApiKey",
    "claudeApiKey",
    "qwenApiKey",
    "deepseekApiKey",
    "zhipuApiKey",
    "moonshotApiKey",
    "baiduApiKey",
    "minimaxApiKey",
    "doubaoApiKey",
]
SENSITIVE_OTHER_FIELDS = ["githubToken", "gitlabToken"]
PROVIDER_KEY_MAP = {
    "openai": "openaiApiKey",
    "gemini": "geminiApiKey",
    "claude": "claudeApiKey",
    "qwen": "qwenApiKey",
    "deepseek": "deepseekApiKey",
    "zhipu": "zhipuApiKey",
    "moonshot": "moonshotApiKey",
    "baidu": "baiduApiKey",
    "minimax": "minimaxApiKey",
    "doubao": "doubaoApiKey",
}


class AgentModelConfigSchema(BaseModel):
    enabled: bool = False
    llmProvider: Optional[str] = None
    llmApiKey: Optional[str] = None
    llmModel: Optional[str] = None
    llmBaseUrl: Optional[str] = None
    llmTimeout: Optional[int] = None
    llmTemperature: Optional[float] = None
    llmMaxTokens: Optional[int] = None
    maxIterations: Optional[int] = None
    env: Dict[str, str] = Field(default_factory=dict)
    alwaysThinkingEnabled: Optional[bool] = None


class ModelProfileSchema(BaseModel):
    id: str
    name: str
    llmProvider: Optional[str] = None
    llmApiKey: Optional[str] = None
    llmModel: Optional[str] = None
    llmBaseUrl: Optional[str] = None
    llmTimeout: Optional[int] = None
    llmTemperature: Optional[float] = None
    llmMaxTokens: Optional[int] = None
    env: Dict[str, str] = Field(default_factory=dict)


class LLMConfigSchema(BaseModel):
    llmProvider: Optional[str] = None
    llmApiKey: Optional[str] = None
    llmModel: Optional[str] = None
    llmBaseUrl: Optional[str] = None
    llmTimeout: Optional[int] = None
    llmTemperature: Optional[float] = None
    llmMaxTokens: Optional[int] = None
    llmCustomHeaders: Optional[str] = None
    llmFirstTokenTimeout: Optional[int] = None
    llmStreamTimeout: Optional[int] = None
    agentTimeout: Optional[int] = None
    subAgentTimeout: Optional[int] = None
    toolTimeout: Optional[int] = None
    geminiApiKey: Optional[str] = None
    openaiApiKey: Optional[str] = None
    claudeApiKey: Optional[str] = None
    qwenApiKey: Optional[str] = None
    deepseekApiKey: Optional[str] = None
    zhipuApiKey: Optional[str] = None
    moonshotApiKey: Optional[str] = None
    baiduApiKey: Optional[str] = None
    minimaxApiKey: Optional[str] = None
    doubaoApiKey: Optional[str] = None
    ollamaBaseUrl: Optional[str] = None
    env: Dict[str, str] = Field(default_factory=dict)
    alwaysThinkingEnabled: Optional[bool] = None
    agentConfigs: Dict[str, AgentModelConfigSchema] = Field(default_factory=dict)
    modelProfiles: list[ModelProfileSchema] = Field(default_factory=list)


class OtherConfigSchema(BaseModel):
    githubToken: Optional[str] = None
    gitlabToken: Optional[str] = None
    maxAnalyzeFiles: Optional[int] = None
    llmConcurrency: Optional[int] = None
    llmGapMs: Optional[int] = None
    outputLanguage: Optional[str] = None
    workflowConfig: Optional[Dict[str, Any]] = None


class UserConfigRequest(BaseModel):
    llmConfig: Optional[LLMConfigSchema] = None
    otherConfig: Optional[OtherConfigSchema] = None


class UserConfigResponse(BaseModel):
    id: str
    user_id: str
    llmConfig: Dict[str, Any]
    otherConfig: Dict[str, Any]
    created_at: str
    updated_at: Optional[str] = None


class LLMConnectionTestRequest(BaseModel):
    provider: str
    apiKey: Optional[str] = None
    model: Optional[str] = None
    baseUrl: Optional[str] = None
    prompt: str = "请只回复：模型连接成功。"


class AgentModelTestRequest(BaseModel):
    agent_type: str
    prompt: str = "请介绍你当前加载到的 Skills，并说明你最适合执行什么任务。"
    include_skills: bool = True
    agent_model_config: Optional[AgentModelConfigSchema] = None
    messages: list[dict[str, str]] = Field(default_factory=list)


class SyncAssetsResponse(BaseModel):
    skills_synced: int
    templates_synced: int
    skill_library: str
    report_template_library: str


def _build_agent_test_messages(
    *,
    system_prompt: str,
    agent_type: str,
    latest_prompt: str,
    skill_briefing: str,
    messages: list[dict[str, str]],
) -> list[dict[str, str]]:
    conversation: list[dict[str, str]] = [{"role": "system", "content": system_prompt}]

    if messages:
        first_user_content = messages[0].get("content", "").strip() or latest_prompt
        if skill_briefing:
            first_user_content = f"{first_user_content}\n\n{skill_briefing}"
        conversation.append({"role": "user", "content": first_user_content})
        for item in messages[1:]:
            content = item.get("content", "").strip()
            if content:
                conversation.append({"role": item.get("role", "user"), "content": content})
    else:
        first_user_content = latest_prompt
        if skill_briefing:
            first_user_content = f"{first_user_content}\n\n{skill_briefing}"
        conversation.append({"role": "user", "content": first_user_content})

    return conversation


def _default_agent_configs() -> Dict[str, Dict[str, Any]]:
    return {
        agent: {
            "enabled": False,
            "llmProvider": "",
            "llmApiKey": "",
            "llmModel": "",
            "llmBaseUrl": "",
            "llmTimeout": None,
            "llmTemperature": None,
            "llmMaxTokens": None,
            "maxIterations": None,
            "env": {},
            "alwaysThinkingEnabled": False,
        }
        for agent in AGENT_TYPES
    }


def _default_workflow_config() -> Dict[str, Any]:
    return {
        "agentStates": {
            agent: {
                "enabled": True,
                "locked": agent in WORKFLOW_LOCKED_AGENTS,
            }
            for agent in WORKFLOW_AGENT_TYPES
        }
    }


def _normalize_workflow_config(config: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    defaults = _default_workflow_config()
    normalized = deepcopy(defaults)
    incoming_states = (config or {}).get("agentStates", {})

    if isinstance(incoming_states, dict):
        for agent in WORKFLOW_AGENT_TYPES:
            raw_state = incoming_states.get(agent)
            if isinstance(raw_state, dict):
                normalized["agentStates"][agent]["enabled"] = bool(raw_state.get("enabled", True))
            elif isinstance(raw_state, bool):
                normalized["agentStates"][agent]["enabled"] = raw_state

    for agent in WORKFLOW_LOCKED_AGENTS:
        normalized["agentStates"][agent]["enabled"] = True
        normalized["agentStates"][agent]["locked"] = True

    return normalized


def _merge_other_config_with_defaults(other_config: Dict[str, Any], defaults: Dict[str, Any]) -> Dict[str, Any]:
    merged = {**defaults, **(other_config or {})}
    merged["workflowConfig"] = _normalize_workflow_config((other_config or {}).get("workflowConfig"))
    return merged


def _encrypt_config(config: Dict[str, Any], sensitive_fields: list[str]) -> Dict[str, Any]:
    encrypted = deepcopy(config)
    for field in sensitive_fields:
        if encrypted.get(field):
            encrypted[field] = encrypt_sensitive_data(encrypted[field])
    if isinstance(encrypted.get("env"), dict):
        encrypted["env"] = {
            key: encrypt_sensitive_data(str(value))
            for key, value in encrypted["env"].items()
            if value not in (None, "")
        }
    agent_configs = encrypted.get("agentConfigs") or {}
    if isinstance(agent_configs, dict):
        for payload in agent_configs.values():
            if isinstance(payload, dict) and payload.get("llmApiKey"):
                payload["llmApiKey"] = encrypt_sensitive_data(payload["llmApiKey"])
            if isinstance(payload, dict) and isinstance(payload.get("env"), dict):
                payload["env"] = {
                    key: encrypt_sensitive_data(str(value))
                    for key, value in payload["env"].items()
                    if value not in (None, "")
                }
    encrypted["agentConfigs"] = agent_configs
    if "modelProfiles" in encrypted:
        model_profiles = encrypted.get("modelProfiles") or []
        if isinstance(model_profiles, list):
            for payload in model_profiles:
                if isinstance(payload, dict) and payload.get("llmApiKey"):
                    payload["llmApiKey"] = encrypt_sensitive_data(payload["llmApiKey"])
                if isinstance(payload, dict) and isinstance(payload.get("env"), dict):
                    payload["env"] = {
                        key: encrypt_sensitive_data(str(value))
                        for key, value in payload["env"].items()
                        if value not in (None, "")
                    }
        encrypted["modelProfiles"] = model_profiles
    return encrypted


def _decrypt_config(config: Dict[str, Any], sensitive_fields: list[str]) -> Dict[str, Any]:
    decrypted = deepcopy(config)
    for field in sensitive_fields:
        if decrypted.get(field):
            decrypted[field] = decrypt_sensitive_data(decrypted[field])
    if isinstance(decrypted.get("env"), dict):
        decrypted["env"] = {
            key: decrypt_sensitive_data(value)
            for key, value in decrypted["env"].items()
            if value not in (None, "")
        }
    agent_configs = decrypted.get("agentConfigs") or {}
    if isinstance(agent_configs, dict):
        for payload in agent_configs.values():
            if isinstance(payload, dict) and payload.get("llmApiKey"):
                payload["llmApiKey"] = decrypt_sensitive_data(payload["llmApiKey"])
            if isinstance(payload, dict) and isinstance(payload.get("env"), dict):
                payload["env"] = {
                    key: decrypt_sensitive_data(value)
                    for key, value in payload["env"].items()
                    if value not in (None, "")
                }
    decrypted["agentConfigs"] = agent_configs
    if "modelProfiles" in decrypted:
        model_profiles = decrypted.get("modelProfiles") or []
        if isinstance(model_profiles, list):
            for payload in model_profiles:
                if isinstance(payload, dict) and payload.get("llmApiKey"):
                    payload["llmApiKey"] = decrypt_sensitive_data(payload["llmApiKey"])
                if isinstance(payload, dict) and isinstance(payload.get("env"), dict):
                    payload["env"] = {
                        key: decrypt_sensitive_data(value)
                        for key, value in payload["env"].items()
                        if value not in (None, "")
                    }
        decrypted["modelProfiles"] = model_profiles
    return decrypted


def get_default_config() -> Dict[str, Any]:
    return {
        "llmConfig": {
            "llmProvider": settings.LLM_PROVIDER,
            "llmApiKey": "",
            "llmModel": settings.LLM_MODEL or "",
            "llmBaseUrl": settings.LLM_BASE_URL or "",
            "llmTimeout": int(settings.LLM_TIMEOUT * 1000),
            "llmTemperature": settings.LLM_TEMPERATURE,
            "llmMaxTokens": settings.LLM_MAX_TOKENS,
            "llmCustomHeaders": "",
            "llmFirstTokenTimeout": getattr(settings, "LLM_FIRST_TOKEN_TIMEOUT", 30),
            "llmStreamTimeout": getattr(settings, "LLM_STREAM_TIMEOUT", 60),
            "agentTimeout": settings.AGENT_TIMEOUT_SECONDS,
            "subAgentTimeout": getattr(settings, "SUB_AGENT_TIMEOUT_SECONDS", 600),
            "toolTimeout": getattr(settings, "TOOL_TIMEOUT_SECONDS", 60),
            "env": {},
            "alwaysThinkingEnabled": False,
            "modelProfiles": [],
            "geminiApiKey": settings.GEMINI_API_KEY or "",
            "openaiApiKey": settings.OPENAI_API_KEY or "",
            "claudeApiKey": settings.CLAUDE_API_KEY or "",
            "qwenApiKey": settings.QWEN_API_KEY or "",
            "deepseekApiKey": settings.DEEPSEEK_API_KEY or "",
            "zhipuApiKey": settings.ZHIPU_API_KEY or "",
            "moonshotApiKey": settings.MOONSHOT_API_KEY or "",
            "baiduApiKey": settings.BAIDU_API_KEY or "",
            "minimaxApiKey": settings.MINIMAX_API_KEY or "",
            "doubaoApiKey": settings.DOUBAO_API_KEY or "",
            "ollamaBaseUrl": settings.OLLAMA_BASE_URL or "http://localhost:11434/v1",
            "agentConfigs": _default_agent_configs(),
        },
        "otherConfig": {
            "githubToken": settings.GITHUB_TOKEN or "",
            "gitlabToken": settings.GITLAB_TOKEN or "",
            "maxAnalyzeFiles": settings.MAX_ANALYZE_FILES,
            "llmConcurrency": settings.LLM_CONCURRENCY,
            "llmGapMs": settings.LLM_GAP_MS,
            "outputLanguage": settings.OUTPUT_LANGUAGE,
            "workflowConfig": _default_workflow_config(),
        },
    }


async def _get_user_config_record(db: AsyncSession, user_id: str) -> Optional[UserConfig]:
    result = await db.execute(select(UserConfig).where(UserConfig.user_id == user_id))
    return result.scalar_one_or_none()


def _merge_user_config(record: Optional[UserConfig]) -> Dict[str, Any]:
    defaults = get_default_config()
    if record is None:
        return defaults

    llm_config = json.loads(record.llm_config) if record.llm_config else {}
    other_config = json.loads(record.other_config) if record.other_config else {}
    llm_config = _decrypt_config(llm_config, SENSITIVE_LLM_FIELDS)
    other_config = _decrypt_config(other_config, SENSITIVE_OTHER_FIELDS)

    merged_llm = {**defaults["llmConfig"], **llm_config}
    merged_llm["agentConfigs"] = {
        **defaults["llmConfig"]["agentConfigs"],
        **(llm_config.get("agentConfigs") or {}),
    }
    merged_other = _merge_other_config_with_defaults(other_config, defaults["otherConfig"])
    return {"llmConfig": merged_llm, "otherConfig": merged_other}


def _response_from_record(record: Optional[UserConfig], user_id: str) -> UserConfigResponse:
    merged = _merge_user_config(record)
    return UserConfigResponse(
        id=record.id if record else "",
        user_id=user_id,
        llmConfig=merged["llmConfig"],
        otherConfig=merged["otherConfig"],
        created_at=record.created_at.isoformat() if record and record.created_at else "",
        updated_at=record.updated_at.isoformat() if record and record.updated_at else None,
    )


def _build_test_user_config(saved_config: Dict[str, Any], agent_type: Optional[str] = None, override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    payload = deepcopy(saved_config)
    payload.setdefault("llmConfig", {})
    payload["llmConfig"].setdefault("agentConfigs", _default_agent_configs())
    if agent_type and override:
        payload["llmConfig"]["agentConfigs"][agent_type] = {
            **payload["llmConfig"]["agentConfigs"].get(agent_type, {}),
            **override,
        }
        if override.get("enabled"):
            for key in (
                "llmProvider",
                "llmApiKey",
                "llmModel",
                "llmBaseUrl",
                "llmTimeout",
                "llmTemperature",
                "llmMaxTokens",
                "alwaysThinkingEnabled",
            ):
                value = override.get(key)
                if value not in (None, ""):
                    payload["llmConfig"][key] = value
            override_env = override.get("env")
            if isinstance(override_env, dict) and override_env:
                base_env = payload["llmConfig"].get("env") if isinstance(payload["llmConfig"].get("env"), dict) else {}
                payload["llmConfig"]["env"] = {**base_env, **override_env}
    return payload


@router.get("/defaults")
async def get_default_config_endpoint() -> Any:
    return get_default_config()


@router.get("/me", response_model=UserConfigResponse)
async def get_my_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    record = await _get_user_config_record(db, current_user.id)
    return _response_from_record(record, current_user.id)


@router.put("/me", response_model=UserConfigResponse)
async def update_my_config(
    config_in: UserConfigRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    record = await _get_user_config_record(db, current_user.id)
    if record is None:
        record = UserConfig(user_id=current_user.id, llm_config="{}", other_config="{}")
        db.add(record)
        await db.flush()

    if config_in.llmConfig is not None:
        existing_llm = json.loads(record.llm_config) if record.llm_config else {}
        existing_llm = _decrypt_config(existing_llm, SENSITIVE_LLM_FIELDS)
        incoming_llm = config_in.llmConfig.model_dump(exclude_none=True, exclude_unset=True)
        if "agentConfigs" in incoming_llm:
            incoming_llm["agentConfigs"] = {
                **(existing_llm.get("agentConfigs") or {}),
                **incoming_llm["agentConfigs"],
            }
        existing_llm.update(incoming_llm)
        record.llm_config = json.dumps(_encrypt_config(existing_llm, SENSITIVE_LLM_FIELDS), ensure_ascii=False)

    if config_in.otherConfig is not None:
        existing_other = json.loads(record.other_config) if record.other_config else {}
        existing_other = _decrypt_config(existing_other, SENSITIVE_OTHER_FIELDS)
        incoming_other = config_in.otherConfig.model_dump(exclude_none=True)
        if "workflowConfig" in incoming_other:
            incoming_other["workflowConfig"] = _normalize_workflow_config(incoming_other.get("workflowConfig"))
        existing_other.update(incoming_other)
        record.other_config = json.dumps(_encrypt_config(existing_other, SENSITIVE_OTHER_FIELDS), ensure_ascii=False)

    await db.commit()
    await db.refresh(record)
    return _response_from_record(record, current_user.id)


@router.delete("/me")
async def delete_my_config(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    record = await _get_user_config_record(db, current_user.id)
    if record is not None:
        await db.delete(record)
        await db.commit()
    return {"ok": True}


@router.post("/test-llm")
async def test_llm_connection(
    payload: LLMConnectionTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    record = await _get_user_config_record(db, current_user.id)
    merged = _merge_user_config(record)
    test_user_config = _build_test_user_config(merged)
    provider_key = PROVIDER_KEY_MAP.get(payload.provider.lower())
    llm_config = test_user_config["llmConfig"]
    llm_config["llmProvider"] = payload.provider
    if payload.apiKey is not None:
        llm_config["llmApiKey"] = payload.apiKey
        if provider_key:
            llm_config[provider_key] = payload.apiKey
    if payload.model is not None:
        llm_config["llmModel"] = payload.model
    if payload.baseUrl is not None:
        llm_config["llmBaseUrl"] = payload.baseUrl

    try:
        llm_service = LLMService(user_config=test_user_config)
        result = await llm_service.chat_completion(
            messages=[
                {"role": "system", "content": "你是模型连通性测试助手，请简短回复。"},
                {"role": "user", "content": payload.prompt},
            ]
        )
        return {
            "success": True,
            "message": "模型连接成功",
            "provider": llm_service.config.provider.value,
            "model": llm_service.config.model,
            "response": result.get("content", ""),
        }
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "message": str(exc)}


@router.post("/test-agent-model")
async def test_agent_model(
    payload: AgentModelTestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    if payload.agent_type not in AGENT_TYPES:
        raise HTTPException(status_code=400, detail="不支持的 Agent 类型")

    record = await _get_user_config_record(db, current_user.id)
    merged = _merge_user_config(record)
    override = payload.agent_model_config.model_dump(exclude_none=True) if payload.agent_model_config else None
    test_user_config = _build_test_user_config(merged, payload.agent_type, override)

    skill_context = {"metadata": [], "matched": []}
    skill_briefing = ""
    latest_prompt = payload.prompt
    if payload.messages:
        latest_user_message = next((item.get("content", "") for item in reversed(payload.messages) if item.get("role") == "user"), "")
        if latest_user_message:
            latest_prompt = latest_user_message

    if payload.include_skills:
        skill_context = await SkillService.resolve_agent_skills(
            current_user.id,
            payload.agent_type,
            {
                "task": latest_prompt,
                "task_context": latest_prompt,
                "config": {},
                "project_info": {},
                "recon_data": {},
            },
        )
        skill_briefing = SkillService.build_skill_briefing(skill_context)

    system_prompt = (
        f"你正在测试 {payload.agent_type} Agent 的模型配置。"
        "请像真实 Agent 一样回答，并明确区分："
        "1）你当前扮演的 Agent；"
        "2）你现在只掌握了哪些 Skills 元数据；"
        "3）如果需要完整 Skill 正文或扩展资源，你会调用哪个工具。"
    )

    try:
        llm_service = LLMService(user_config=test_user_config)
        conversation = _build_agent_test_messages(
            system_prompt=system_prompt,
            agent_type=payload.agent_type,
            latest_prompt=latest_prompt,
            skill_briefing=skill_briefing,
            messages=payload.messages,
        )
        result = await llm_service.chat_completion(
            messages=conversation
        )
        return {
            "success": True,
            "agent_type": payload.agent_type,
            "provider": llm_service.config.provider.value,
            "model": llm_service.config.model,
            "response": result.get("content", ""),
            "conversation_count": len(conversation) - 1,
            "loaded_skills": [
                {"name": item.get("name"), "slug": item.get("slug"), "description": item.get("description")}
                for item in skill_context.get("metadata", [])
            ],
            "matched_skills": [
                {"name": item.get("name"), "slug": item.get("slug")}
                for item in skill_context.get("matched", [])
            ],
        }
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "agent_type": payload.agent_type, "message": str(exc)}


@router.post("/sync-assets", response_model=SyncAssetsResponse)
async def sync_assets(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(deps.get_current_user),
) -> Any:
    del db, current_user
    await init_agent_assets()
    SkillFileService.sync_all()
    skills = SkillFileService.list_skills()
    templates = ReportTemplateFileService.list_templates()
    return SyncAssetsResponse(
        skills_synced=len(skills),
        templates_synced=len(templates),
        skill_library=str(SkillFileService.library_root()),
        report_template_library=str(ReportTemplateFileService.library_root()),
    )


@router.get("/llm-providers")
async def get_llm_providers() -> Any:
    providers = []
    for provider in LLMFactory.get_supported_providers():
        providers.append(
            {
                "value": provider.value,
                "label": provider.value.upper(),
                "default_model": LLMFactory.get_default_model(provider),
                "models": LLMFactory.get_available_models(provider),
            }
        )
    return {"providers": providers, "agents": AGENT_TYPES}

