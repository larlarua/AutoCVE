from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from app.services.finding_runtime.final_finding_contract import FinalizedFinding, format_validation_errors
from app.services.finding_runtime.models import ToolExecutionPayload
from app.services.runtime_core.tool_runtime import RuntimeTool, ToolExecutionContext
from app.services.triage_runtime.queue import TriageQueue


class GetTriageBatchInput(BaseModel):
    batch_size: int = Field(default=5, ge=1, le=20)
    index_ref: str | None = None

    @field_validator("index_ref", mode="before")
    @classmethod
    def _strip_index_ref(cls, value: Any) -> str | None:
        if value is None:
            return None
        return str(value or "").strip() or None


class GetScanFindingInput(BaseModel):
    finding_id: str = Field(min_length=1)
    index_ref: str | None = None

    @field_validator("finding_id", "index_ref", mode="before")
    @classmethod
    def _strip_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        return str(value or "").strip()


class TriageDecisionInput(BaseModel):
    finding_id: str = Field(min_length=1)
    decision: Literal["keep", "false_positive", "duplicate", "low_value", "needs_more_context", "error"]
    finding: FinalizedFinding | None = None
    reason: str = ""
    duplicate_of: str = ""
    notes: str = ""

    @field_validator("finding_id", "reason", "duplicate_of", "notes", mode="before")
    @classmethod
    def _strip_text(cls, value: Any) -> str:
        return str(value or "").strip()

    @model_validator(mode="after")
    def _validate_decision_payload(self):
        if self.decision == "keep" and self.finding is None:
            raise ValueError("keep decision requires finding")
        if self.decision == "duplicate" and not self.duplicate_of:
            raise ValueError("duplicate decision requires duplicate_of")
        if self.decision in {"false_positive", "low_value"} and not self.reason:
            raise ValueError(f"{self.decision} decision requires reason")
        if self.decision == "needs_more_context" and not (self.reason or self.notes):
            raise ValueError("needs_more_context decision requires reason or notes")
        if self.decision == "error" and not (self.reason or self.notes):
            raise ValueError("error decision requires reason or notes")
        return self


class FinalizeTriageBatchInput(BaseModel):
    batch_id: str = Field(min_length=1)
    decisions: list[TriageDecisionInput] = Field(min_length=1)
    summary: str = Field(min_length=1)
    index_ref: str | None = None

    @field_validator("batch_id", "summary", "index_ref", mode="before")
    @classmethod
    def _strip_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        return str(value or "").strip()


class FinalizeTriageInput(BaseModel):
    summary: str = ""
    index_ref: str | None = None
    allow_incomplete: bool = False

    @field_validator("summary", "index_ref", mode="before")
    @classmethod
    def _strip_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        return str(value or "").strip()


class InvalidFinalizeTriageBatchInput:
    def __init__(self, raw_input: dict[str, Any], validation_error: ValidationError):
        self.raw_input = dict(raw_input or {})
        self.validation_error = validation_error


class GetTriageBatchTool(RuntimeTool):
    name = "GetTriageBatch"
    description = "Claim the next pending batch of scan findings for triage."
    input_model = GetTriageBatchInput
    always_load = True

    def __init__(self, queue: TriageQueue | None = None, *, project_root: str | None = None, index_ref: str | None = None):
        self.queue = queue
        self.project_root = project_root
        self.index_ref = index_ref

    def is_concurrency_safe(self, parsed_input: Any = None) -> bool:
        del parsed_input
        return False

    async def execute(self, parsed_input: GetTriageBatchInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        queue = _resolve_queue(
            queue=self.queue,
            context=context,
            project_root=self.project_root,
            index_ref=parsed_input.index_ref or self.index_ref,
        )
        batch = queue.claim_next_batch(batch_size=parsed_input.batch_size)
        return ToolExecutionPayload(
            content=f"Claimed triage batch {batch.get('batch_id') or '<empty>'} with {len(batch.get('findings') or [])} findings.",
            output_payload=batch,
            metadata={"triage_batch_claimed": bool(batch.get("batch_id"))},
        )


class GetScanFindingTool(RuntimeTool):
    name = "GetScanFinding"
    description = "Load the lightweight index item and raw scanner finding by finding_id."
    input_model = GetScanFindingInput
    always_load = True

    def __init__(self, queue: TriageQueue | None = None, *, project_root: str | None = None, index_ref: str | None = None):
        self.queue = queue
        self.project_root = project_root
        self.index_ref = index_ref

    def is_concurrency_safe(self, parsed_input: Any = None) -> bool:
        del parsed_input
        return True

    async def execute(self, parsed_input: GetScanFindingInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        queue = _resolve_queue(
            queue=self.queue,
            context=context,
            project_root=self.project_root,
            index_ref=parsed_input.index_ref or self.index_ref,
        )
        payload = queue.get_scan_finding(parsed_input.finding_id)
        return ToolExecutionPayload(
            content=f"Loaded scan finding {parsed_input.finding_id}.",
            output_payload=payload,
            metadata={"finding_id": parsed_input.finding_id},
        )


class FinalizeTriageBatchTool(RuntimeTool):
    name = "FinalizeTriageBatch"
    description = (
        "Submit decisions for every finding_id in the active triage batch. "
        "A keep decision must include a Finding-compatible structured finding."
    )
    input_model = FinalizeTriageBatchInput
    always_load = True

    def __init__(self, queue: TriageQueue | None = None, *, project_root: str | None = None, index_ref: str | None = None):
        self.queue = queue
        self.project_root = project_root
        self.index_ref = index_ref

    def validate_input(self, raw_input: dict[str, Any]) -> FinalizeTriageBatchInput | InvalidFinalizeTriageBatchInput:
        try:
            return FinalizeTriageBatchInput.model_validate(raw_input or {})
        except ValidationError as exc:
            return InvalidFinalizeTriageBatchInput(raw_input or {}, exc)

    def is_concurrency_safe(self, parsed_input: Any = None) -> bool:
        del parsed_input
        return False

    async def execute(
        self,
        parsed_input: FinalizeTriageBatchInput | InvalidFinalizeTriageBatchInput,
        context: ToolExecutionContext,
    ) -> ToolExecutionPayload:
        if isinstance(parsed_input, InvalidFinalizeTriageBatchInput):
            return ToolExecutionPayload(
                content="FinalizeTriageBatch rejected invalid input. Fix the validation errors and call it again.",
                output_payload={
                    "finalization_rejected": True,
                    "validation_errors": format_validation_errors(parsed_input.validation_error),
                },
                metadata={"finalization_rejected": True},
                is_error=False,
            )

        decisions = [
            decision.model_dump(mode="json", exclude_none=True)
            for decision in parsed_input.decisions
        ]
        try:
            queue = _resolve_queue(
                queue=self.queue,
                context=context,
                project_root=self.project_root,
                index_ref=parsed_input.index_ref or self.index_ref,
            )
            result = queue.finalize_batch(batch_id=parsed_input.batch_id, decisions=decisions)
        except ValueError as exc:
            return ToolExecutionPayload(
                content=f"FinalizeTriageBatch rejected this batch: {exc}",
                output_payload={
                    "finalization_rejected": True,
                    "error": str(exc),
                    "batch_id": parsed_input.batch_id,
                },
                metadata={"finalization_rejected": True},
                is_error=False,
            )

        final_payload = {
            "batch_id": parsed_input.batch_id,
            "decisions": decisions,
            "summary": parsed_input.summary,
            "coverage": result.get("coverage", {}),
            "result": result,
        }
        return ToolExecutionPayload(
            content=f"Received triage decisions for batch {parsed_input.batch_id}.",
            output_payload={
                "final_payload": final_payload,
                "completion_mode": "finalize_tool",
                "terminal_action": "finalize_triage_batch",
            },
            metadata={"finalize_triage_batch": True},
        )


class FinalizeTriageTool(RuntimeTool):
    name = "FinalizeTriage"
    description = "Summarize the completed triage queue into final findings and summary."
    input_model = FinalizeTriageInput
    always_load = True

    def __init__(self, queue: TriageQueue | None = None, *, project_root: str | None = None, index_ref: str | None = None):
        self.queue = queue
        self.project_root = project_root
        self.index_ref = index_ref

    def is_concurrency_safe(self, parsed_input: Any = None) -> bool:
        del parsed_input
        return False

    async def execute(self, parsed_input: FinalizeTriageInput, context: ToolExecutionContext) -> ToolExecutionPayload:
        try:
            queue = _resolve_queue(
                queue=self.queue,
                context=context,
                project_root=self.project_root,
                index_ref=parsed_input.index_ref or self.index_ref,
            )
            final_payload = queue.finalize_triage(
                summary=parsed_input.summary,
                require_complete=not parsed_input.allow_incomplete,
            )
        except ValueError as exc:
            return ToolExecutionPayload(
                content=f"FinalizeTriage rejected this request: {exc}",
                output_payload={
                    "finalization_rejected": True,
                    "error": str(exc),
                },
                metadata={"finalization_rejected": True},
                is_error=False,
            )

        return ToolExecutionPayload(
            content="Received final triage findings.",
            output_payload={
                "final_payload": final_payload,
                "completion_mode": "finalize_tool",
                "terminal_action": "finalize_triage",
            },
            metadata={"finalize_triage": True},
        )


def _resolve_queue(
    *,
    queue: TriageQueue | None,
    context: ToolExecutionContext,
    project_root: str | None,
    index_ref: str | None,
) -> TriageQueue:
    if queue is not None:
        return queue
    resolved_project_root = _resolve_project_root(context=context, configured_project_root=project_root)
    resolved_index_ref = index_ref or _resolve_index_ref(context=context)
    if not resolved_index_ref:
        raise ValueError("Missing triage index_ref. Provide index_ref or include scan_result.index_ref in runtime payload.")
    return TriageQueue(project_root=resolved_project_root, index_ref=resolved_index_ref)


def _resolve_project_root(*, context: ToolExecutionContext, configured_project_root: str | None) -> str:
    if configured_project_root:
        return configured_project_root
    payload = dict(context.recon_payload or {})
    project_info = payload.get("project_info") if isinstance(payload.get("project_info"), dict) else {}
    for value in (
        payload.get("project_root"),
        payload.get("workspace_root"),
        project_info.get("workspace_root"),
        project_info.get("root"),
    ):
        if str(value or "").strip():
            return str(value).strip()
    raise ValueError("Missing project root for triage runtime tools")


def _resolve_index_ref(*, context: ToolExecutionContext) -> str | None:
    payload = dict(context.recon_payload or {})
    scan_result = payload.get("scan_result") if isinstance(payload.get("scan_result"), dict) else {}
    handoff = payload.get("handoff") if isinstance(payload.get("handoff"), dict) else {}
    for value in (
        payload.get("index_ref"),
        scan_result.get("index_ref"),
        handoff.get("index_ref"),
        handoff.get("context_data", {}).get("index_ref") if isinstance(handoff.get("context_data"), dict) else None,
    ):
        if str(value or "").strip():
            return str(value).strip()
    return None
