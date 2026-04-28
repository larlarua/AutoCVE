from __future__ import annotations


def build_finding_skill_protocol() -> str:
    return """
## Finding 技能使用协议

- 在依赖任何技能规则之前，先启动当前主审计技能。
- 通过运行时工具 schema 和原生工具调用接口读取技能材料，不要使用旧版扫描器工具名。
- 读取技能时优先使用标准运行时工具：先用 `Read` 读取目录中的 `skill_file_path`；需要补充参考资料时，再在 `references_root` 下使用 `Glob` 或 `Grep`。
- 对比相关 source、sink、controller、service、mapper、xml 文件时，先用 `Glob`/`Grep` 定位文件，再发起少量有目标的 `Read` 调用，不要沿用旧的逐文件批量读取提示。
- 只有在明确要求创建或更新产物时才使用 `Write`；只有在证据收集确实需要 shell 能力时才使用 `Bash` / `PowerShell`。
- 使用 `Skill` 启动相关审计技能，并让已加载指南与当前运行时目录保持一致。
- 不要反复停留在技能材料上；读取 `SKILL.md` 和一两个核心参考后，应切回项目代码。
- 将技能参考视为按需指南，而不是审计代码前必须全部读完的预加载清单。
- 不要把扫描器式工具作为主要证据来源；Finding 结论必须来自直接源码阅读以及已加载技能材料的辅助判断。
""".strip()
