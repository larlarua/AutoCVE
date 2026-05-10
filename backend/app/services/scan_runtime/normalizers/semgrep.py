from __future__ import annotations

import hashlib
from typing import Any


SEVERITY_MAP = {
    "ERROR": "high",
    "WARNING": "medium",
    "INFO": "low",
}

PRIORITY_BY_SEVERITY = {
    "critical": 100,
    "high": 85,
    "medium": 55,
    "low": 25,
    "info": 10,
}


def normalize_semgrep_results(
    payload: dict[str, Any],
    *,
    artifact_ref: str,
    max_index_findings: int = 200,
) -> list[dict[str, Any]]:
    raw_results = payload.get("results") if isinstance(payload, dict) else []
    if not isinstance(raw_results, list):
        return []

    indexed: list[dict[str, Any]] = []
    for raw_index, finding in enumerate(raw_results):
        if not isinstance(finding, dict):
            continue
        extra = finding.get("extra") if isinstance(finding.get("extra"), dict) else {}
        start = finding.get("start") if isinstance(finding.get("start"), dict) else {}
        end = finding.get("end") if isinstance(finding.get("end"), dict) else {}
        rule_id = str(finding.get("check_id") or "").strip()
        file_path = _normalize_path(str(finding.get("path") or "").strip())
        line_start = _as_int(start.get("line"), default=0)
        line_end = _as_int(end.get("line"), default=line_start)
        message = str(extra.get("message") or rule_id or "Semgrep finding").strip()
        severity = _normalize_severity(str(extra.get("severity") or "").strip())
        code_snippet = str(extra.get("lines") or "").strip()

        indexed.append(
            {
                "finding_id": _finding_id(
                    source_tool="SemgrepScan",
                    rule_id=rule_id,
                    file_path=file_path,
                    line_start=line_start,
                    code_snippet=code_snippet,
                ),
                "source_tool": "SemgrepScan",
                "rule_id": rule_id,
                "severity": severity,
                "title": message[:160],
                "description_preview": message[:500],
                "file_path": file_path,
                "line_start": line_start,
                "line_end": line_end,
                "code_snippet_preview": code_snippet[:500],
                "artifact_ref": artifact_ref,
                "raw_finding_index": raw_index,
                "priority": _priority(severity=severity, file_path=file_path, metadata=extra.get("metadata")),
                "status": "pending",
            }
        )
        if len(indexed) >= max_index_findings:
            break
    return indexed


def _normalize_severity(raw_severity: str) -> str:
    normalized = raw_severity.upper()
    return SEVERITY_MAP.get(normalized, raw_severity.lower() or "low")


def _priority(*, severity: str, file_path: str, metadata: Any) -> int:
    priority = PRIORITY_BY_SEVERITY.get(severity, 20)
    lowered_path = file_path.lower()
    if any(part in lowered_path for part in ("/test/", "/tests/", "__tests__", ".spec.", ".test.")):
        priority -= 20
    if isinstance(metadata, dict):
        if metadata.get("cwe") or metadata.get("owasp"):
            priority += 5
    return max(0, min(100, priority))


def _finding_id(*, source_tool: str, rule_id: str, file_path: str, line_start: int, code_snippet: str) -> str:
    fingerprint = "|".join(
        [
            source_tool,
            rule_id,
            file_path,
            str(line_start),
            hashlib.sha256(code_snippet.encode("utf-8", errors="ignore")).hexdigest()[:16],
        ]
    )
    return hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()


def _normalize_path(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def _as_int(value: Any, *, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
