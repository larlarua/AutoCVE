from __future__ import annotations

from typing import Any

from pydantic import ValidationError

from app.services.finding_runtime.final_finding_contract import (
    FinalizedFindingPayload,
    format_validation_errors,
)
from app.services.finding_runtime.models import ToolExecutionPayload
from app.services.runtime_core.tool_runtime import RuntimeTool, ToolExecutionContext


class InvalidFinalizeFindingInput:
    def __init__(self, raw_input: dict[str, Any], validation_error: ValidationError):
        self.raw_input = dict(raw_input or {})
        self.validation_error = validation_error


class FinalizeFindingTool(RuntimeTool):
    name = "FinalizeFinding"
    description = (
        "仅在证据已经完整时提交最终结构化漏洞结论。"
        "每个 finding 必须包含 title、description、file_path、line_start、line_end、code_snippet、"
        "source、sink、suggestion、exploit_chain、poc、impact、cve_justification 和 verification_notes。"
        "不要把最终漏洞细节放在 reason、notes 等自由文本字段中。"
    )
    input_model = FinalizedFindingPayload
    always_load = True

    def validate_input(self, raw_input: dict[str, Any]) -> FinalizedFindingPayload | InvalidFinalizeFindingInput:
        try:
            return FinalizedFindingPayload.model_validate(raw_input or {})
        except ValidationError as exc:
            return InvalidFinalizeFindingInput(raw_input or {}, exc)

    def is_concurrency_safe(self, parsed_input: Any = None) -> bool:
        del parsed_input
        return False

    async def execute(
        self,
        parsed_input: FinalizedFindingPayload | InvalidFinalizeFindingInput,
        context: ToolExecutionContext,
    ) -> ToolExecutionPayload:
        del context
        if isinstance(parsed_input, InvalidFinalizeFindingInput):
            validation_errors = format_validation_errors(parsed_input.validation_error)
            return ToolExecutionPayload(
                content=(
                    "FinalizeFinding 已拒绝本次提交，因为最终漏洞结论不是完整的结构化对象。"
                    "请继续调用工具补齐缺失字段，然后再次调用 FinalizeFinding。"
                ),
                output_payload={
                    "finalization_rejected": True,
                    "validation_errors": validation_errors,
                    "required_fields": [
                        "vulnerability_type",
                        "severity",
                        "title",
                        "description",
                        "file_path",
                        "line_start",
                        "line_end",
                        "code_snippet",
                        "source",
                        "sink",
                        "suggestion",
                        "confidence",
                        "needs_verification",
                        "verdict",
                        "exploit_chain",
                        "poc",
                        "impact",
                        "cve_justification",
                        "verification_notes",
                    ],
                },
                metadata={"finalization_rejected": True},
            )

        final_payload = parsed_input.model_dump(mode="json", exclude_none=True)
        return ToolExecutionPayload(
            content="Received final structured vulnerability findings.",
            output_payload={
                "final_payload": final_payload,
                "completion_mode": "finalize_tool",
                "terminal_action": "finalize_finding",
            },
            metadata={"finalize_finding": True},
        )
