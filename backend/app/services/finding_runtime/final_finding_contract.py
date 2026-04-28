from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _has_text(value: Any) -> bool:
    return bool(_clean_text(value))


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ExploitChainStep(_StrictModel):
    step: int = Field(ge=1)
    location: str = Field(min_length=1)
    description: str = Field(min_length=1)
    data_state: str = ""
    bypass_reason: str = ""

    @field_validator("location", "description", "data_state", "bypass_reason", mode="before")
    @classmethod
    def _strip_text_fields(cls, value: Any) -> str:
        return _clean_text(value)


class PocStep(_StrictModel):
    step: int = Field(ge=1)
    action: str = Field(min_length=1)
    request: str = ""
    expected_response: str = ""

    @field_validator("action", "request", "expected_response", mode="before")
    @classmethod
    def _strip_text_fields(cls, value: Any) -> str:
        return _clean_text(value)


class PocPayload(_StrictModel):
    description: str = Field(min_length=1)
    preconditions: list[str] = Field(default_factory=list)
    steps: list[PocStep] = Field(min_length=1)
    payload: str = ""
    impact: str = Field(min_length=1)
    cve_justification: str = Field(min_length=1)

    @field_validator("description", "payload", "impact", "cve_justification", mode="before")
    @classmethod
    def _strip_text_fields(cls, value: Any) -> str:
        return _clean_text(value)

    @field_validator("preconditions", mode="before")
    @classmethod
    def _strip_preconditions(cls, value: Any) -> list[str]:
        if not isinstance(value, list):
            return []
        return [_clean_text(item) for item in value if _has_text(item)]


class FinalizedFinding(_StrictModel):
    vulnerability_type: str = Field(min_length=1)
    severity: Literal["critical", "high"]
    title: str = Field(min_length=1)
    description: str = Field(min_length=1)
    file_path: str = Field(min_length=1)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    code_snippet: str = Field(min_length=1)
    source: str = Field(min_length=1)
    sink: str = Field(min_length=1)
    suggestion: str = Field(min_length=1)
    confidence: float = Field(ge=0.0, le=1.0)
    needs_verification: bool
    verdict: Literal["candidate", "confirmed"]
    exploit_chain: list[ExploitChainStep] = Field(min_length=1)
    poc: PocPayload
    impact: str = Field(min_length=1)
    cve_justification: str = Field(min_length=1)
    verification_notes: str = Field(min_length=1)

    @field_validator(
        "vulnerability_type",
        "title",
        "description",
        "file_path",
        "code_snippet",
        "source",
        "sink",
        "suggestion",
        "impact",
        "cve_justification",
        "verification_notes",
        mode="before",
    )
    @classmethod
    def _strip_required_text(cls, value: Any) -> str:
        return _clean_text(value)

    @field_validator("severity", "verdict", mode="before")
    @classmethod
    def _normalize_lowercase(cls, value: Any) -> str:
        return _clean_text(value).lower()

    @field_validator("line_end")
    @classmethod
    def _line_end_must_not_precede_start(cls, value: int, info) -> int:
        line_start = info.data.get("line_start")
        if isinstance(line_start, int) and value < line_start:
            raise ValueError("line_end must be greater than or equal to line_start")
        return value


class FinalizedFindingPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    findings: list[FinalizedFinding] = Field(default_factory=list)
    summary: str = Field(min_length=1)
    completion_note: str | None = None
    needs_handoff: bool | None = None

    @field_validator("summary", "completion_note", mode="before")
    @classmethod
    def _strip_optional_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        return _clean_text(value)


def has_meaningful_poc(poc: Any) -> bool:
    if not isinstance(poc, dict):
        return False
    if _has_text(poc.get("description")) or _has_text(poc.get("payload")):
        return True
    preconditions = poc.get("preconditions")
    if isinstance(preconditions, list) and any(_has_text(item) for item in preconditions):
        return True
    steps = poc.get("steps")
    if isinstance(steps, list):
        for step in steps:
            if not isinstance(step, dict):
                continue
            if any(_has_text(step.get(key)) for key in ("action", "request", "expected_response")):
                return True
    return False


def filter_meaningful_exploit_chain(exploit_chain: Any) -> list[dict[str, Any]]:
    if not isinstance(exploit_chain, list):
        return []
    filtered: list[dict[str, Any]] = []
    for step in exploit_chain:
        if not isinstance(step, dict):
            continue
        if _has_text(step.get("location")) or _has_text(step.get("description")):
            filtered.append(step)
    return filtered


def has_meaningful_exploit_chain(exploit_chain: Any) -> bool:
    return bool(filter_meaningful_exploit_chain(exploit_chain))


def is_placeholder_finding(finding: Any) -> bool:
    if not isinstance(finding, dict):
        return False
    if set(finding.keys()) <= {"reason", "summary", "notes", "note"}:
        return True
    title = _clean_text(finding.get("title")).lower()
    return (
        title in {"unknown finding", "other vulnerability", "vulnerability"}
        and not _has_text(finding.get("description"))
        and not _has_text(finding.get("file_path"))
        and not _has_text(finding.get("source"))
        and not _has_text(finding.get("sink"))
    )


def format_validation_errors(exc: ValidationError) -> list[dict[str, str]]:
    details: list[dict[str, str]] = []
    messages: list[str] = []
    for error in exc.errors():
        field = ".".join(str(part) for part in error.get("loc", ())) or "payload"
        message = f"{field}: {error.get('msg', 'invalid value')}"
        details.append({"field": field, "message": message})
        messages.append(message)
    if not details:
        return [{"field": "payload", "message": "FinalizeFinding payload is invalid."}]
    return [
        {
            "field": "payload",
            "message": "FinalizeFinding payload is invalid: " + "; ".join(messages),
        },
        *details,
    ]
