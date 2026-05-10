from __future__ import annotations

import asyncio
import json

from app.services.scan_runtime.normalizers import normalize_semgrep_results
from app.services.scan_runtime.pipeline import ScanPipeline
from app.services.scan_runtime.executors.semgrep import SemgrepScanExecutor


def _semgrep_payload() -> dict:
    return {
        "paths": {"scanned": ["app/routes.py"]},
        "results": [
            {
                "check_id": "python.flask.security.audit.xss.direct-response-write",
                "path": "app/routes.py",
                "start": {"line": 42, "col": 12},
                "end": {"line": 42, "col": 40},
                "extra": {
                    "severity": "ERROR",
                    "message": "Potential XSS from direct response write",
                    "lines": "return request.args['name']",
                    "metadata": {"cwe": ["CWE-79"], "owasp": ["A03:2021"]},
                },
            }
        ]
    }


class FakeSandboxManager:
    def __init__(
        self,
        payload: dict,
        *,
        artifact_content: bool = True,
        stdout: str | None = None,
        stderr: str = "",
        exit_code: int = 1,
        artifact_error: str | None = None,
    ):
        self.payload = payload
        self.artifact_content = artifact_content
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
        self.artifact_error = artifact_error
        self.calls: list[dict] = []
        self.is_available = True

    async def initialize(self):
        return None

    async def execute_tool_command(self, **kwargs):
        self.calls.append(dict(kwargs))
        content = json.dumps(self.payload)
        artifact = {
            "content": content if self.artifact_content else "",
            "bytes": len(content.encode("utf-8")) if self.artifact_content else 0,
            "encoding": "utf-8",
        }
        if self.artifact_error:
            artifact["error"] = self.artifact_error
        return {
            "success": self.exit_code == 0,
            "exit_code": self.exit_code,
            "stdout": self.stdout if self.stdout is not None else (content if not self.artifact_content else ""),
            "stderr": self.stderr,
            "error": None,
            "artifacts": {
                "/tmp/semgrep.json": artifact
            },
        }


def test_semgrep_normalizer_builds_lightweight_index():
    findings = normalize_semgrep_results(
        _semgrep_payload(),
        artifact_ref=".auditai/scans/run/semgrep.json",
        max_index_findings=20,
    )

    assert len(findings) == 1
    finding = findings[0]
    assert finding["source_tool"] == "SemgrepScan"
    assert finding["severity"] == "high"
    assert finding["rule_id"] == "python.flask.security.audit.xss.direct-response-write"
    assert finding["file_path"] == "app/routes.py"
    assert finding["line_start"] == 42
    assert finding["status"] == "pending"
    assert finding["artifact_ref"] == ".auditai/scans/run/semgrep.json"


def test_scan_pipeline_runs_semgrep_and_writes_artifacts(tmp_path):
    sandbox = FakeSandboxManager(_semgrep_payload())
    pipeline = ScanPipeline(project_root=tmp_path, sandbox_manager=sandbox)

    result = asyncio.run(
        pipeline.run(
            project_id="project-1",
            task_id="task-1",
            project_profile={"languages": ["Python"]},
            scan_plan={},
        )
    )

    assert result["scan_run_id"].startswith("task-1-")
    assert result["scanner_runs"][0]["scanner"] == "SemgrepScan"
    assert result["scanner_runs"][0]["status"] == "success"
    assert result["scanner_runs"][0]["command_summary"].startswith("semgrep scan")
    assert result["scanner_runs"][0]["targets_scanned"] == 1
    assert result["scanner_runs"][0]["stderr_preview"] == ""
    assert result["summary"]["total_candidates"] == 1
    assert result["summary"]["by_scanner"] == {"SemgrepScan": 1}

    semgrep_ref = result["artifact_refs"]["SemgrepScan"]
    index_ref = result["index_ref"]
    summary_ref = result["summary_ref"]
    assert (tmp_path / semgrep_ref).exists()
    assert (tmp_path / index_ref).exists()
    assert (tmp_path / summary_ref).exists()

    command = sandbox.calls[0]["command"]
    assert "semgrep scan" in command
    assert "--config p/default" in command
    assert "--config p/security-audit" in command
    assert "--json-output /tmp/semgrep.json" in command
    assert "--metrics=off" in command
    assert sandbox.calls[0]["network_mode"] == "bridge"
    assert sandbox.calls[0]["artifact_paths"] == ["/tmp/semgrep.json"]


def test_scan_pipeline_emits_activity_events(tmp_path):
    events: list[dict] = []
    sandbox = FakeSandboxManager(_semgrep_payload())
    pipeline = ScanPipeline(project_root=tmp_path, sandbox_manager=sandbox, event_sink=events.append)

    result = asyncio.run(
        pipeline.run(
            project_id="project-1",
            task_id="task-events",
            project_profile={"languages": ["Python"]},
            scan_plan={},
        )
    )

    event_names = [event["event"] for event in events]
    assert event_names == ["scan_started", "scanner_started", "scanner_completed", "scan_completed"]
    assert events[0]["metadata"]["scanner"] == "SemgrepScan"
    assert events[1]["metadata"]["command_summary"].startswith("semgrep scan")
    assert events[2]["metadata"]["exit_code"] == 1
    assert events[2]["metadata"]["raw_count"] == 1
    assert events[2]["metadata"]["indexed_count"] == 1
    assert events[2]["metadata"]["targets_scanned"] == 1
    assert events[2]["metadata"]["artifact_ref"] == result["artifact_refs"]["SemgrepScan"]
    assert events[3]["metadata"]["index_ref"] == result["index_ref"]


def test_scan_pipeline_recovers_semgrep_json_from_stdout_when_artifact_missing(tmp_path):
    sandbox = FakeSandboxManager(_semgrep_payload(), artifact_content=False)
    pipeline = ScanPipeline(project_root=tmp_path, sandbox_manager=sandbox)

    result = asyncio.run(
        pipeline.run(
            project_id="project-1",
            task_id="task-stdout",
            project_profile={"languages": ["Python"]},
            scan_plan={},
        )
    )

    assert result["scanner_runs"][0]["status"] == "success"
    assert result["summary"]["total_candidates"] == 1
    assert (tmp_path / result["artifact_refs"]["SemgrepScan"]).exists()


def test_scan_pipeline_marks_semgrep_partial_when_findings_reported_but_json_missing(tmp_path):
    stderr = """
Scan completed successfully.
 • Findings: 50 (50 blocking)
 • Rules run: 318
 • Targets scanned: 719
Ran 318 rules on 719 files: 50 findings.
"""
    sandbox = FakeSandboxManager(
        _semgrep_payload(),
        artifact_content=False,
        stdout="",
        stderr=stderr,
        exit_code=0,
        artifact_error="Could not find the file /tmp/semgrep.json",
    )
    pipeline = ScanPipeline(project_root=tmp_path, sandbox_manager=sandbox)

    result = asyncio.run(
        pipeline.run(
            project_id="project-1",
            task_id="task-missing-json",
            project_profile={"languages": ["Python"]},
            scan_plan={},
        )
    )

    scanner_run = result["scanner_runs"][0]
    assert scanner_run["status"] == "partial"
    assert scanner_run["raw_count"] == 50
    assert scanner_run["indexed_count"] == 0
    assert scanner_run["targets_scanned"] == 719
    assert "JSON artifact was not captured" in scanner_run["error"]
    assert result["summary"]["scanner_statuses"] == {"SemgrepScan": "partial"}
    assert result["summary"]["scanner_diagnostics"]["SemgrepScan"]["reported_findings"] == 50


def test_semgrep_stdout_json_extractor_skips_human_findings_with_braces():
    payload = {"version": "1.161.0", **_semgrep_payload()}
    polluted_stdout = (
        "{{...}} with github context data in a run step could allow injection.\n"
        "Details: https://sg.run/pkzk\n\n"
        + json.dumps(payload)
    )

    extracted = SemgrepScanExecutor._extract_stdout_json(polluted_stdout)

    assert json.loads(extracted)["results"][0]["check_id"] == "python.flask.security.audit.xss.direct-response-write"
