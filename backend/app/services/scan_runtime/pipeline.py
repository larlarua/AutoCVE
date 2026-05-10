from __future__ import annotations

import inspect
from pathlib import Path
from typing import Any, Callable

from app.services.scan_runtime.executors import SemgrepScanExecutor
from app.services.scan_runtime.models import DEFAULT_SEMGREP_CONFIGS, ScannerExecutionResult, ScannerRequest
from app.services.scan_runtime.store import ScanResultStore


class ScanPipeline:
    def __init__(
        self,
        *,
        project_root: str | Path,
        sandbox_manager: Any,
        store: ScanResultStore | None = None,
        event_sink: Callable[[dict[str, Any]], Any] | None = None,
    ):
        self.project_root = Path(project_root).resolve()
        self.sandbox_manager = sandbox_manager
        self.store = store or ScanResultStore(self.project_root)
        self.event_sink = event_sink

    async def run(
        self,
        *,
        project_id: str | None = None,
        task_id: str | None = None,
        project_profile: dict[str, Any] | None = None,
        scan_plan: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del project_id
        scan_run_id = self.store.create_scan_run_id(task_id=task_id)
        semgrep_request = self._semgrep_request_from_plan(scan_plan or {})
        await self._emit(
            "scan_started",
            "Scan pipeline started.",
            scanner="SemgrepScan",
            scan_run_id=scan_run_id,
            target_paths=semgrep_request.target_paths,
            configs=semgrep_request.configs,
        )
        try:
            command_summary = SemgrepScanExecutor(
                project_root=self.project_root,
                sandbox_manager=self.sandbox_manager,
                store=self.store,
            )._build_command_summary(semgrep_request)
        except ValueError as exc:
            command_summary = f"Invalid SemgrepScan request: {exc}"
        await self._emit(
            "scanner_started",
            "SemgrepScan started.",
            scanner="SemgrepScan",
            scan_run_id=scan_run_id,
            command_summary=command_summary,
            target_paths=semgrep_request.target_paths,
        )
        semgrep_result = await SemgrepScanExecutor(
            project_root=self.project_root,
            sandbox_manager=self.sandbox_manager,
            store=self.store,
        ).run(scan_run_id=scan_run_id, request=semgrep_request)
        await self._emit_result("scanner_completed", "SemgrepScan completed.", scan_run_id, semgrep_result)

        scanner_results = [semgrep_result]
        index = self._combine_index(scanner_results)
        index_ref = self.store.write_json_artifact(scan_run_id=scan_run_id, filename="index.json", payload=index)
        summary = self._build_summary(
            scanner_results=scanner_results,
            index=index,
            project_profile=project_profile or {},
        )
        summary_ref = self.store.write_json_artifact(scan_run_id=scan_run_id, filename="summary.json", payload=summary)
        await self._emit(
            "scan_completed",
            "Scan pipeline completed.",
            scan_run_id=scan_run_id,
            index_ref=index_ref,
            summary_ref=summary_ref,
            raw_count=sum(result.raw_count for result in scanner_results),
            indexed_count=len(index),
            scanner_statuses=summary.get("scanner_statuses", {}),
        )

        return {
            "scan_run_id": scan_run_id,
            "scanner_runs": [result.scanner_run() for result in scanner_results],
            "artifact_refs": {
                result.scanner: result.artifact_ref for result in scanner_results if result.artifact_ref
            },
            "index_ref": index_ref,
            "summary_ref": summary_ref,
            "summary": summary,
        }

    def _semgrep_request_from_plan(self, scan_plan: dict[str, Any]) -> ScannerRequest:
        scanner_requests = scan_plan.get("scanner_requests")
        if isinstance(scanner_requests, list):
            for item in scanner_requests:
                if not isinstance(item, dict):
                    continue
                if str(item.get("scanner") or "").strip() != "SemgrepScan":
                    continue
                return ScannerRequest(
                    scanner="SemgrepScan",
                    enabled=True,
                    configs=self._string_list(item.get("configs")) or list(DEFAULT_SEMGREP_CONFIGS),
                    target_paths=self._string_list(item.get("target_paths")) or ["."],
                    exclude_patterns=self._string_list(item.get("exclude_patterns")),
                    timeout_seconds=self._positive_int(item.get("timeout_seconds"), default=600),
                    max_index_findings=self._positive_int(
                        item.get("max_index_findings") or scan_plan.get("max_index_findings"),
                        default=200,
                    ),
                    metadata={key: value for key, value in item.items() if key not in {"configs", "target_paths", "exclude_patterns"}},
                )
        return ScannerRequest(
            scanner="SemgrepScan",
            configs=list(DEFAULT_SEMGREP_CONFIGS),
            target_paths=self._string_list(scan_plan.get("target_paths")) or ["."],
            exclude_patterns=self._string_list(scan_plan.get("exclude_patterns")),
            timeout_seconds=self._positive_int(scan_plan.get("timeout_seconds"), default=600),
            max_index_findings=self._positive_int(scan_plan.get("max_index_findings"), default=200),
        )

    @staticmethod
    def _combine_index(scanner_results: list[ScannerExecutionResult]) -> list[dict[str, Any]]:
        combined: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for result in scanner_results:
            for finding in result.indexed_findings:
                finding_id = str(finding.get("finding_id") or "")
                if finding_id and finding_id in seen_ids:
                    continue
                if finding_id:
                    seen_ids.add(finding_id)
                combined.append(dict(finding))
        combined.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
        return combined

    @staticmethod
    def _build_summary(
        *,
        scanner_results: list[ScannerExecutionResult],
        index: list[dict[str, Any]],
        project_profile: dict[str, Any],
    ) -> dict[str, Any]:
        by_scanner: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_file: dict[str, int] = {}
        for finding in index:
            source_tool = str(finding.get("source_tool") or "unknown")
            severity = str(finding.get("severity") or "unknown")
            file_path = str(finding.get("file_path") or "")
            by_scanner[source_tool] = by_scanner.get(source_tool, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
            if file_path:
                by_file[file_path] = by_file.get(file_path, 0) + 1
        top_files = [
            {"file_path": file_path, "count": count}
            for file_path, count in sorted(by_file.items(), key=lambda item: item[1], reverse=True)[:20]
        ]
        return {
            "total_candidates": len(index),
            "by_scanner": by_scanner,
            "by_severity": by_severity,
            "top_files": top_files,
            "scanner_statuses": {result.scanner: result.status for result in scanner_results},
            "scanner_diagnostics": {
                result.scanner: {
                    "status": result.status,
                    "error": result.error,
                    "raw_count": result.raw_count,
                    "indexed_count": result.indexed_count,
                    "reported_findings": result.reported_findings,
                    "targets_scanned": result.targets_scanned,
                    "artifact_ref": result.artifact_ref,
                    "artifact_error": result.artifact_error,
                    "exit_code": result.exit_code,
                }
                for result in scanner_results
                if result.status != "success" or result.error or result.artifact_error
            },
            "project_profile": project_profile,
        }

    @staticmethod
    def _string_list(value: Any) -> list[str]:
        if isinstance(value, list):
            return [str(item).strip() for item in value if str(item or "").strip()]
        if isinstance(value, str) and value.strip():
            return [value.strip()]
        return []

    @staticmethod
    def _positive_int(value: Any, *, default: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            return default
        return parsed if parsed > 0 else default

    async def _emit(self, event: str, message: str, **metadata: Any) -> None:
        if self.event_sink is None:
            return
        payload = {"event": event, "message": message, "metadata": metadata}
        result = self.event_sink(payload)
        if inspect.isawaitable(result):
            await result

    async def _emit_result(
        self,
        event: str,
        message: str,
        scan_run_id: str,
        result: ScannerExecutionResult,
    ) -> None:
        await self._emit(
            event,
            message,
            scan_run_id=scan_run_id,
            scanner=result.scanner,
            status=result.status,
            exit_code=result.exit_code,
            targets_scanned=result.targets_scanned,
            raw_count=result.raw_count,
            indexed_count=result.indexed_count,
            artifact_ref=result.artifact_ref,
            command_summary=result.command_summary,
            stderr_preview=result.stderr_preview,
            duration_ms=result.duration_ms,
            error=result.error,
            reported_findings=result.reported_findings,
            artifact_error=result.artifact_error,
        )
