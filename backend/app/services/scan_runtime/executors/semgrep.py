from __future__ import annotations

import json
import shlex
import time
from json import JSONDecoder
from pathlib import Path
from typing import Any

from app.services.scan_runtime.models import DEFAULT_SEMGREP_CONFIGS, ScannerExecutionResult, ScannerRequest
from app.services.scan_runtime.normalizers import normalize_semgrep_results
from app.services.scan_runtime.store import ScanResultStore

CONTAINER_OUTPUT_PATH = "/tmp/semgrep.json"


class SemgrepScanExecutor:
    scanner_name = "SemgrepScan"

    def __init__(self, *, project_root: str | Path, sandbox_manager: Any, store: ScanResultStore | None = None):
        self.project_root = Path(project_root).resolve()
        self.sandbox_manager = sandbox_manager
        self.store = store or ScanResultStore(self.project_root)

    async def run(self, *, scan_run_id: str, request: ScannerRequest | None = None) -> ScannerExecutionResult:
        request = request or ScannerRequest(scanner=self.scanner_name, configs=list(DEFAULT_SEMGREP_CONFIGS))
        started_at = time.time()

        await self.sandbox_manager.initialize()
        if not getattr(self.sandbox_manager, "is_available", False):
            return ScannerExecutionResult(
                scanner=self.scanner_name,
                status="failed",
                duration_ms=self._duration_ms(started_at),
                error=self._sandbox_diagnosis(),
            )

        try:
            command = self._build_command(request)
            command_summary = self._build_command_summary(request)
        except ValueError as exc:
            return ScannerExecutionResult(
                scanner=self.scanner_name,
                status="failed",
                duration_ms=self._duration_ms(started_at),
                error=str(exc),
            )

        result = await self.sandbox_manager.execute_tool_command(
            command=command,
            host_workdir=str(self.project_root),
            timeout=max(1, int(request.timeout_seconds)),
            network_mode="bridge",
            artifact_paths=[CONTAINER_OUTPUT_PATH],
        )
        duration_ms = self._duration_ms(started_at)
        exit_code = result.get("exit_code")
        stderr_preview = str(result.get("stderr") or "")[:2000]
        semgrep_artifact = (result.get("artifacts") or {}).get(CONTAINER_OUTPUT_PATH) or {}
        artifact_error = str(semgrep_artifact.get("error") or "").strip() or None
        semgrep_json = str(semgrep_artifact.get("content") or "")
        if not semgrep_json.strip():
            semgrep_json = self._extract_stdout_json(str(result.get("stdout") or ""))
        artifact_ref: str | None = None
        payload: dict[str, Any] = {}
        parse_error: str | None = None

        if semgrep_json.strip():
            artifact_ref = self.store.write_text_artifact(
                scan_run_id=scan_run_id,
                filename="semgrep.json",
                content=semgrep_json,
            )
            try:
                parsed = json.loads(semgrep_json)
                if isinstance(parsed, dict):
                    payload = parsed
            except json.JSONDecodeError as exc:
                parse_error = f"Unable to parse Semgrep JSON artifact: {exc}"

        raw_results = payload.get("results") if isinstance(payload.get("results"), list) else []
        targets_scanned = self._targets_scanned(payload, stderr_preview)
        reported_findings = self._reported_findings(stderr_preview)
        indexed_findings = (
            normalize_semgrep_results(
                payload,
                artifact_ref=artifact_ref or "",
                max_index_findings=request.max_index_findings,
            )
            if artifact_ref and not parse_error
            else []
        )
        allowed_exit = exit_code in (0, 1)
        raw_count = len(raw_results) if raw_results else (reported_findings or 0)
        if parse_error:
            status = "partial" if allowed_exit else "failed"
            error = parse_error
        elif not payload and allowed_exit:
            status = "partial"
            details = []
            if reported_findings is not None:
                details.append(f"Semgrep reported {reported_findings} findings")
            if targets_scanned is not None:
                details.append(f"targets_scanned={targets_scanned}")
            if artifact_error:
                details.append(f"artifact_error={artifact_error}")
            suffix = f" ({'; '.join(details)})" if details else ""
            error = f"Semgrep JSON artifact was not captured, so findings were not indexed{suffix}"
        elif allowed_exit:
            status = "success"
            error = None
        else:
            status = "failed"
            error = stderr_preview or str(result.get("error") or "Semgrep execution failed")

        return ScannerExecutionResult(
            scanner=self.scanner_name,
            status=status,
            artifact_ref=artifact_ref,
            indexed_findings=indexed_findings,
            raw_count=raw_count,
            indexed_count=len(indexed_findings),
            duration_ms=duration_ms,
            exit_code=exit_code,
            error=error,
            stderr_preview=stderr_preview,
            command_summary=command_summary,
            targets_scanned=targets_scanned,
            reported_findings=reported_findings,
            artifact_error=artifact_error,
        )

    def _build_command(self, request: ScannerRequest) -> str:
        semgrep_command = self._build_command_summary(request)
        output_path = shlex.quote(CONTAINER_OUTPUT_PATH)
        return f"{semgrep_command} >/tmp/semgrep.stdout; rc=$?; cat {output_path} 2>/dev/null; exit $rc"

    def _build_command_summary(self, request: ScannerRequest) -> str:
        configs = request.configs or list(DEFAULT_SEMGREP_CONFIGS)
        target_paths = request.target_paths or ["."]
        args = ["semgrep", "scan"]
        for config in configs:
            args.extend(["--config", self._validate_config(config)])
        for pattern in request.exclude_patterns:
            if str(pattern or "").strip():
                args.extend(["--exclude", str(pattern).strip()])
        args.extend(["--json-output", CONTAINER_OUTPUT_PATH, "--metrics=off"])
        args.extend(self._validate_target_path(path) for path in target_paths)
        return " ".join(shlex.quote(str(arg)) for arg in args)

    def _validate_config(self, config: str) -> str:
        normalized = str(config or "").strip()
        if not normalized:
            raise ValueError("Semgrep config cannot be empty")
        if normalized.startswith("-"):
            raise ValueError(f"Semgrep config cannot start with '-': {normalized}")
        if normalized.startswith("p/"):
            return normalized

        candidate = (self.project_root / normalized).resolve()
        try:
            candidate.relative_to(self.project_root)
        except ValueError as exc:
            raise ValueError(f"Semgrep config escapes project root: {normalized}") from exc
        return normalized.replace("\\", "/")

    def _validate_target_path(self, target_path: str) -> str:
        normalized = str(target_path or ".").strip() or "."
        if normalized in {".", "./"}:
            return "."
        if normalized.startswith("-"):
            raise ValueError(f"Semgrep target cannot start with '-': {normalized}")
        candidate = (self.project_root / normalized).resolve()
        try:
            candidate.relative_to(self.project_root)
        except ValueError as exc:
            raise ValueError(f"Semgrep target escapes project root: {normalized}") from exc
        return normalized.replace("\\", "/").lstrip("/")

    def _sandbox_diagnosis(self) -> str:
        diagnosis = getattr(self.sandbox_manager, "get_diagnosis", None)
        if callable(diagnosis):
            return str(diagnosis())
        return "Docker sandbox is unavailable"

    @staticmethod
    def _duration_ms(started_at: float) -> int:
        return int((time.time() - started_at) * 1000)

    @staticmethod
    def _extract_stdout_json(stdout: str) -> str:
        text = str(stdout or "").strip()
        if not text:
            return ""
        decoder = JSONDecoder()
        for marker in ('{"version"', '{"paths"', '{"results"', '{"errors"'):
            start = text.find(marker)
            while start >= 0:
                try:
                    payload, end = decoder.raw_decode(text[start:])
                except json.JSONDecodeError:
                    start = text.find(marker, start + 1)
                    continue
                if isinstance(payload, dict) and isinstance(payload.get("results"), list):
                    return text[start : start + end]
                start = text.find(marker, start + 1)
        return ""

    @staticmethod
    def _targets_scanned(payload: dict[str, Any], stderr_preview: str) -> int | None:
        paths = payload.get("paths") if isinstance(payload, dict) else None
        if isinstance(paths, dict):
            scanned = paths.get("scanned")
            if isinstance(scanned, list):
                return len(scanned)
        text = str(stderr_preview or "")
        for line in text.splitlines():
            stripped = line.strip()
            lowered = stripped.lower().lstrip("•- \t")
            if not lowered.startswith("targets scanned"):
                continue
            parts = stripped.replace(":", " ").split()
            for part in reversed(parts):
                try:
                    return int(part.replace(",", ""))
                except ValueError:
                    continue
        return None

    @staticmethod
    def _reported_findings(stderr_preview: str) -> int | None:
        text = str(stderr_preview or "")
        for line in text.splitlines():
            stripped = line.strip()
            lowered = stripped.lower()
            if lowered.startswith("findings"):
                parts = stripped.replace(":", " ").split()
                for part in parts:
                    try:
                        return int(part.replace(",", ""))
                    except ValueError:
                        continue
            if " findings." in lowered or lowered.endswith(" findings"):
                parts = stripped.replace(":", " ").split()
                for index, part in enumerate(parts):
                    if part.lower().rstrip(".") != "findings" or index == 0:
                        continue
                    try:
                        return int(parts[index - 1].replace(",", ""))
                    except ValueError:
                        continue
        return None
