from __future__ import annotations

NO_TOOLS_PREAMBLE = """关键要求：只能用文本回复，禁止调用任何工具。

- 不要使用 Read、Bash、Grep、Glob、Edit、Write 或任何其他工具。
- 上方对话已经包含你需要的全部上下文。
- 工具调用会被拒绝，并浪费你唯一的一轮回复，导致任务失败。
- 你的完整回复必须是纯文本：先给出一个 <analysis> 块，再给出一个 <summary> 块。
- 请使用简体中文撰写总结；代码、路径、函数名和协议标签可以保留原文。
"""

NO_TOOLS_TRAILER = """
不要调用任何工具。只返回纯文本，其中包含一个 <analysis> 块和一个 <summary> 块。
""".lstrip("\n")

_DETAILED_ANALYSIS_INSTRUCTION_BASE = """在提供最终总结前，请用 <analysis> 标签包裹分析过程，以组织思路并确保覆盖所有必要要点。分析过程中：

1. 按时间顺序分析对话中的每条消息和每个部分。对每个部分都要识别：
   - 用户的明确请求和意图
   - 你处理用户请求的方法
   - 关键决策、技术概念和代码模式
   - 具体细节，例如：
     - 文件名
     - 完整代码片段
     - 函数签名
     - 文件修改
   - 遇到的错误以及修复方式
   - 特别关注收到的用户反馈，尤其是用户要求你改变做法的地方。
2. 复核技术准确性和完整性，逐项覆盖必要元素。"""

_DETAILED_ANALYSIS_INSTRUCTION_PARTIAL = """在提供最终总结前，请用 <analysis> 标签包裹分析过程，以组织思路并确保覆盖所有必要要点。分析过程中：

1. 按时间顺序分析最近的消息。对每个部分都要识别：
   - 用户的明确请求和意图
   - 你处理用户请求的方法
   - 关键决策、技术概念和代码模式
   - 具体细节，例如：
     - 文件名
     - 完整代码片段
     - 函数签名
     - 文件修改
   - 遇到的错误以及修复方式
   - 特别关注收到的用户反馈，尤其是用户要求你改变做法的地方。
2. 复核技术准确性和完整性，逐项覆盖必要元素。"""

BASE_COMPACT_PROMPT = f"""你的任务是为目前为止的对话创建一份详细总结，重点关注用户的明确请求以及你之前采取的行动。
总结必须充分捕捉技术细节、代码模式和架构决策，以便后续继续开发时不丢失上下文。

{_DETAILED_ANALYSIS_INSTRUCTION_BASE}

总结应包含以下部分：

1. 主要请求和意图
2. 关键技术概念
3. 文件和代码位置
4. 错误和修复
5. 问题解决过程
6. 所有用户消息
7. 待办任务
8. 当前工作
9. 可选下一步
"""

PARTIAL_COMPACT_PROMPT = f"""你的任务是为对话的最近部分创建详细总结，也就是早先保留上下文之后的新消息。更早的消息会原样保留，不需要总结。请只关注最近消息中讨论、了解到和完成的内容。

{_DETAILED_ANALYSIS_INSTRUCTION_PARTIAL}

总结应包含以下部分：

1. 主要请求和意图
2. 关键技术概念
3. 文件和代码位置
4. 错误和修复
5. 问题解决过程
6. 所有用户消息
7. 待办任务
8. 当前工作
9. 可选下一步
"""

PARTIAL_COMPACT_UP_TO_PROMPT = f"""你的任务是为这段对话创建详细总结。该总结会放在后续会话的开头；新的消息会接在总结后继续展开（你在这里看不到它们）。请充分总结，使只阅读你的总结和后续新消息的人也能理解发生了什么并继续工作。

{_DETAILED_ANALYSIS_INSTRUCTION_BASE}

总结应包含以下部分：

1. 主要请求和意图
2. 关键技术概念
3. 文件和代码位置
4. 错误和修复
5. 问题解决过程
6. 所有用户消息
7. 待办任务
8. 已完成工作
9. 继续工作的上下文
"""


def build_compaction_prompt(*, mode: str, custom_instructions: str | None = None) -> str:
    prompt_map = {
        "base": BASE_COMPACT_PROMPT,
        "partial": PARTIAL_COMPACT_PROMPT,
        "partial_up_to": PARTIAL_COMPACT_UP_TO_PROMPT,
    }
    try:
        prompt_body = prompt_map[mode]
    except KeyError as exc:
        raise ValueError(f"Unknown compaction prompt mode: {mode}") from exc

    instructions_block = ""
    if custom_instructions:
        instructions_block = (
            "\n\n额外总结要求：\n"
            f"{custom_instructions.strip()}\n"
        )
    return f"{NO_TOOLS_PREAMBLE}{prompt_body}{instructions_block}\n{NO_TOOLS_TRAILER}"


def format_compact_summary(summary: str) -> str:
    text = str(summary or "").strip()
    if "<summary>" in text and "</summary>" in text:
        text = text.split("<summary>", 1)[1].split("</summary>", 1)[0].strip()
    if "<analysis>" in text and "</analysis>" in text:
        before = text.split("<analysis>", 1)[0]
        after = text.split("</analysis>", 1)[1] if "</analysis>" in text else ""
        text = f"{before} {after}".strip()
    return text


def get_compact_user_summary_message(summary: str, suppress_follow_up_questions: bool, transcript_path: str | None = None) -> str:
    formatted = format_compact_summary(summary)
    lines = [formatted]
    if transcript_path:
        lines.append(f"转录引用：{transcript_path}")
    if not suppress_follow_up_questions:
        lines.append("对于尚未解决的缺口，后续可能仍需提问。")
    return "\n\n".join(line for line in lines if line)
