from __future__ import annotations

from typing import Any, Dict, Iterable, List, Sequence, Set


FIXED_FIRST_READS: List[str] = [
    "references/core/anti_hallucination.md",
    "references/core/false_positive_filter.md",
    "references/checklists/coverage_matrix.md",
    "references/core/comprehensive_audit_methodology.md",
    "references/core/data_flow_methodology.md",
    "references/core/taint_analysis.md",
]

LANGUAGE_RESOURCE_MAP: Dict[str, List[str]] = {
    "c": ["references/checklists/c_cpp.md", "references/languages/c_cpp.md"],
    "c++": ["references/checklists/c_cpp.md", "references/languages/c_cpp.md"],
    "cpp": ["references/checklists/c_cpp.md", "references/languages/c_cpp.md"],
    "c#": ["references/checklists/dotnet.md", "references/languages/dotnet.md"],
    ".net": ["references/checklists/dotnet.md", "references/languages/dotnet.md"],
    "dotnet": ["references/checklists/dotnet.md", "references/languages/dotnet.md"],
    "go": ["references/checklists/go.md", "references/languages/go.md"],
    "golang": ["references/checklists/go.md", "references/languages/go.md"],
    "java": ["references/checklists/java.md", "references/languages/java.md"],
    "javascript": ["references/checklists/javascript.md", "references/languages/javascript.md"],
    "node": ["references/checklists/javascript.md", "references/languages/javascript.md"],
    "node.js": ["references/checklists/javascript.md", "references/languages/javascript.md"],
    "php": ["references/checklists/php.md", "references/languages/php.md"],
    "python": ["references/checklists/python.md", "references/languages/python.md"],
    "ruby": ["references/checklists/ruby.md", "references/languages/ruby.md"],
    "rust": ["references/checklists/rust.md", "references/languages/rust.md"],
}

ADAPTER_RESOURCE_MAP: Dict[str, str] = {
    "go": "references/adapters/go.yaml",
    "golang": "references/adapters/go.yaml",
    "java": "references/adapters/java.yaml",
    "javascript": "references/adapters/javascript.yaml",
    "node": "references/adapters/javascript.yaml",
    "node.js": "references/adapters/javascript.yaml",
    "php": "references/adapters/php.yaml",
    "python": "references/adapters/python.yaml",
}

FRAMEWORK_RESOURCE_MAP: Dict[str, List[str]] = {
    "django": ["references/frameworks/django.md"],
    "dotnet": ["references/frameworks/dotnet.md"],
    "asp.net": ["references/frameworks/dotnet.md"],
    "express": ["references/frameworks/express.md"],
    "fastapi": ["references/frameworks/fastapi.md"],
    "flask": ["references/frameworks/flask.md"],
    "gin": ["references/frameworks/gin.md"],
    "graphql": ["references/security/graphql.md"],
    "java web": ["references/frameworks/java_web_framework.md"],
    "koa": ["references/frameworks/koa.md"],
    "laravel": ["references/frameworks/laravel.md"],
    "mybatis": ["references/frameworks/mybatis_security.md"],
    "nest": ["references/frameworks/nest_fastify.md"],
    "fastify": ["references/frameworks/nest_fastify.md"],
    "rails": ["references/frameworks/rails.md"],
    "rust web": ["references/frameworks/rust_web.md"],
    "spring": ["references/frameworks/spring.md"],
}

SECURITY_ROUTE_RULES: List[Dict[str, Any]] = [
    {
        "name": "authz",
        "keywords": {
            "access", "acl", "auth", "authz", "authorization", "authenticate", "authentication",
            "idor", "jwt", "login", "oauth", "oidc", "password", "permission", "rbac", "role",
            "saml", "session", "tenant", "user", "ownership", "owner",
        },
        "resources": [
            "references/security/authentication_authorization.md",
            "references/security/business_logic.md",
        ],
        "case_candidates": [
            "references/wooyun/unauthorized-access.md",
            "references/wooyun/logic-flaws.md",
        ],
    },
    {
        "name": "file_ops",
        "keywords": {
            "archive", "attachment", "download", "export", "file", "import", "path", "template",
            "traversal", "upload", "zip",
        },
        "resources": ["references/security/file_operations.md"],
        "case_candidates": [
            "references/wooyun/file-traversal.md",
            "references/wooyun/file-upload.md",
        ],
    },
    {
        "name": "input_validation",
        "keywords": {
            "body", "dto", "form", "input", "param", "parameter", "parser", "payload", "query",
            "schema", "serialize", "validation",
        },
        "resources": ["references/security/input_validation.md"],
    },
    {
        "name": "api_security",
        "keywords": {"api", "endpoint", "gateway", "graphql", "grpc", "http", "rest", "router"},
        "resources": ["references/security/api_security.md", "references/security/api_gateway_proxy.md"],
    },
    {
        "name": "race_conditions",
        "keywords": {
            "approval", "balance", "concurrent", "duplicate", "idempot", "inventory", "order",
            "payment", "queue", "race", "retry", "stock", "wallet",
        },
        "resources": ["references/security/race_conditions.md"],
        "case_candidates": ["references/wooyun/logic-flaws.md"],
    },
    {"name": "cross_service_trust", "keywords": {"internal", "service", "trust", "microservice", "signature"}, "resources": ["references/security/cross_service_trust.md"]},
    {"name": "message_queue_async", "keywords": {"async", "consumer", "kafka", "mq", "queue", "rabbitmq", "stream"}, "resources": ["references/security/message_queue_async.md"]},
    {"name": "oauth", "keywords": {"oauth", "oidc", "saml"}, "resources": ["references/security/oauth_oidc_saml.md"]},
    {"name": "realtime", "keywords": {"realtime", "socket", "websocket", "ws"}, "resources": ["references/security/realtime_protocols.md"]},
    {"name": "scheduled_tasks", "keywords": {"cron", "job", "schedule", "scheduler", "task"}, "resources": ["references/security/scheduled_tasks.md"]},
    {"name": "serverless", "keywords": {"function", "lambda", "serverless"}, "resources": ["references/security/serverless.md"]},
    {"name": "llm", "keywords": {"agent", "llm", "model", "prompt", "rag"}, "resources": ["references/security/llm_security.md"]},
]


def _stringify(value: Any) -> Iterable[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        items: List[str] = []
        for nested_value in value.values():
            items.extend(_stringify(nested_value))
        return items
    if isinstance(value, (list, tuple, set)):
        items: List[str] = []
        for nested_value in value:
            items.extend(_stringify(nested_value))
        return items
    return [str(value)]


def _normalized_tokens(values: Iterable[Any]) -> Set[str]:
    tokens: Set[str] = set()
    for value in values:
        for raw in _stringify(value):
            lowered = raw.lower()
            for piece in lowered.replace("/", " ").replace("\\", " ").replace("-", " ").replace("_", " ").split():
                token = piece.strip(".,:;()[]{}'\"")
                if token:
                    tokens.add(token)
            if lowered:
                tokens.add(lowered)
    return tokens


def _append_unique(items: List[str], values: Sequence[str]) -> None:
    for value in values:
        if value not in items:
            items.append(value)


def resolve_finding_skill_routes(context: Dict[str, Any], skill_context: Dict[str, Any] | None = None) -> Dict[str, Any]:
    recon_data = context.get("recon_data", {}) or {}
    project_profile = recon_data.get("project_profile", {}) or {}
    project_info = context.get("project_info", {}) or {}
    config = context.get("config", {}) or {}
    route_plan = (skill_context or {}).get("route_plan") or {}

    language_tokens = _normalized_tokens([project_profile.get("languages", []), project_info.get("languages", [])])
    framework_tokens = _normalized_tokens([project_profile.get("frameworks", []), project_info.get("frameworks", [])])
    signal_tokens = _normalized_tokens(
        [
            context.get("task"),
            context.get("task_context"),
            context.get("focus_vulnerabilities", []),

            recon_data.get("summary"),
            recon_data.get("priority_paths", []),
            recon_data.get("entry_points", []),
            context.get("target_files", []),
            route_plan.get("secondary_skills", []),
        ]
    )

    mandatory_reads: List[str] = []
    recommended_reads: List[str] = []
    case_candidates: List[str] = []

    for token in sorted(language_tokens):
        resources = LANGUAGE_RESOURCE_MAP.get(token)
        if resources:
            _append_unique(mandatory_reads, resources)
        adapter = ADAPTER_RESOURCE_MAP.get(token)
        if adapter:
            _append_unique(mandatory_reads, [adapter])

    for token in sorted(framework_tokens | signal_tokens):
        resources = FRAMEWORK_RESOURCE_MAP.get(token)
        if resources:
            _append_unique(mandatory_reads, resources)

    for rule in SECURITY_ROUTE_RULES:
        if signal_tokens.intersection(rule["keywords"]) or framework_tokens.intersection(rule["keywords"]):
            _append_unique(mandatory_reads, rule["resources"])
            _append_unique(case_candidates, rule.get("case_candidates", []))

    if mandatory_reads:
        _append_unique(mandatory_reads, ["references/checklists/universal.md"])

    if any(path.endswith("references/security/llm_security.md") for path in mandatory_reads):
        _append_unique(recommended_reads, ["references/security/llm_security.md"])

    return {
        "primary_skill": route_plan.get("primary_skill"),
        "secondary_skills": list(route_plan.get("secondary_skills", [])),
        "mandatory_reads": mandatory_reads,
        "recommended_reads": recommended_reads,
        "case_candidates": case_candidates,
        "progressive_disclosure": [
            "references/wooyun/INDEX.md",
            "references/cases/real_world_vulns.md",
        ],
        "selection_reason": list(route_plan.get("selection_reason", [])),
    }


def build_finding_skill_route_message(context: Dict[str, Any], skill_context: Dict[str, Any] | None = None) -> str:
    skill_context = skill_context or {}
    route = resolve_finding_skill_routes(context, skill_context)
    skill_prompt = (skill_context.get("prompt") or "").strip()
    primary_skill = route.get("primary_skill") or "the bound primary skill"
    secondary_skills = route.get("secondary_skills") or []

    lines: List[str] = [
        "Skills runtime catalog:",
        "Startup metadata is only a catalog. Read the actual SKILL.md before relying on a skill.",
    ]
    if skill_prompt:
        lines.append(skill_prompt)

    lines.extend(
        [
            "",
            "Finding 技能路由计划：",
            f"- 主审计技能：{primary_skill}",
            f"- 启动步骤：先读取 {primary_skill} 目录条目中的 skill_file_path；仅在兼容旧流程时才回退使用 load_skill_body。",
        ]
    )
    if secondary_skills:
        lines.append(f"- 定向跟进的辅助技能：{', '.join(secondary_skills)}")
    for reason in route.get("selection_reason", []):
        lines.append(f"- 路由原因：{reason}")

    lines.extend(
        [
            "",
            "批量读取建议：",
            "- 对比 source、sink、controller、service、mapper 或 xml 文件时，优先读取少量相关文件。",
            "- 如果一次读取不够，请在一个循环中通过原生工具调用读取多个明确文件。",
            "- 启动主技能后，只读取开始代码审计所需的最少核心参考。",
            "- 打开新的技能参考目录前，先在目录条目的 references_root 下列出相关文件。",
            "- 不要在阅读候选代码前耗尽所有 mandatory reference。",
        ]
    )

    if route["mandatory_reads"]:
        lines.extend(["", "项目相关参考文件清单（按需读取）："])
        lines.extend(f"- {path}" for path in route["mandatory_reads"])
    if route["recommended_reads"]:
        lines.extend(["", "项目相关可选参考："])
        lines.extend(f"- {path}" for path in route["recommended_reads"])

    lines.extend(
        [
            "",
            "案例渐进披露规则：",
            f"- 阅读任何 WooYun 案例正文前，先读取 {route['progressive_disclosure'][0]}。",
            "- 只有已经掌握项目源码证据后，才可以读取一到两个相关案例文件。",
            f"- 可选真实案例补充：{route['progressive_disclosure'][1]}",
            "- 不要把 WooYun 案例当作证据，它们只能作为搜索方向提示。",
        ]
    )
    if route["case_candidates"]:
        lines.append("- 本项目候选案例文件：")
        lines.extend(f"  - {path}" for path in route["case_candidates"][:4])
    return "\n".join(lines)
