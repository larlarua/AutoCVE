from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


DEFAULT_SEMGREP_CONFIGS = [
    "p/default",
    "p/security-audit",
    "p/owasp-top-ten",
    "p/cwe-top-25",
    "p/trailofbits",
]


@dataclass(slots=True)
class ScannerRequest:
    scanner: str
    enabled: bool = True
    configs: list[str] = field(default_factory=list)
    target_paths: list[str] = field(default_factory=lambda: ["."])
    exclude_patterns: list[str] = field(default_factory=list)
    timeout_seconds: int = 600
    max_index_findings: int = 200
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScannerExecutionResult:
    scanner: str
    status: str
    artifact_ref: str | None = None
    indexed_findings: list[dict[str, Any]] = field(default_factory=list)
    raw_count: int = 0
    indexed_count: int = 0
    duration_ms: int = 0
    exit_code: int | None = None
    error: str | None = None
    stderr_preview: str = ""
    command_summary: str = ""
    targets_scanned: int | None = None
    reported_findings: int | None = None
    artifact_error: str | None = None

    def scanner_run(self) -> dict[str, Any]:
        return {
            "scanner": self.scanner,
            "status": self.status,
            "artifact_ref": self.artifact_ref,
            "indexed_count": self.indexed_count,
            "raw_count": self.raw_count,
            "duration_ms": self.duration_ms,
            "exit_code": self.exit_code,
            "error": self.error,
            "stderr_preview": self.stderr_preview,
            "command_summary": self.command_summary,
            "targets_scanned": self.targets_scanned,
            "reported_findings": self.reported_findings,
            "artifact_error": self.artifact_error,
        }
