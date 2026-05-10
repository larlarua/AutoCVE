from __future__ import annotations

import json

import pytest

from app.services.triage_runtime.queue import TriageQueue


def _finding_payload() -> dict:
    return {
        "results": [
            {"check_id": "rule.one", "path": "app/a.py", "start": {"line": 1}, "extra": {"message": "one"}},
            {"check_id": "rule.two", "path": "app/b.py", "start": {"line": 2}, "extra": {"message": "two"}},
            {"check_id": "rule.three", "path": "app/c.py", "start": {"line": 3}, "extra": {"message": "three"}},
        ]
    }


def _write_scan_artifacts(tmp_path):
    scan_dir = tmp_path / ".auditai" / "scans" / "run-1"
    scan_dir.mkdir(parents=True)
    semgrep_ref = ".auditai/scans/run-1/semgrep.json"
    index_ref = ".auditai/scans/run-1/index.json"
    (tmp_path / semgrep_ref).write_text(json.dumps(_finding_payload()), encoding="utf-8")
    index = [
        {
            "finding_id": "f1",
            "source_tool": "SemgrepScan",
            "rule_id": "rule.one",
            "severity": "high",
            "file_path": "app/a.py",
            "line_start": 1,
            "line_end": 1,
            "artifact_ref": semgrep_ref,
            "raw_finding_index": 0,
            "priority": 90,
            "status": "pending",
        },
        {
            "finding_id": "f2",
            "source_tool": "SemgrepScan",
            "rule_id": "rule.two",
            "severity": "medium",
            "file_path": "app/b.py",
            "line_start": 2,
            "line_end": 2,
            "artifact_ref": semgrep_ref,
            "raw_finding_index": 1,
            "priority": 50,
            "status": "pending",
        },
        {
            "finding_id": "f3",
            "source_tool": "SemgrepScan",
            "rule_id": "rule.three",
            "severity": "low",
            "file_path": "app/c.py",
            "line_start": 3,
            "line_end": 3,
            "artifact_ref": semgrep_ref,
            "raw_finding_index": 2,
            "priority": 10,
            "status": "pending",
        },
    ]
    (tmp_path / index_ref).write_text(json.dumps(index), encoding="utf-8")
    return index_ref


def test_triage_queue_claims_priority_batch_and_reads_raw_finding(tmp_path):
    index_ref = _write_scan_artifacts(tmp_path)
    queue = TriageQueue(project_root=tmp_path, index_ref=index_ref)

    batch = queue.claim_next_batch(batch_size=2)

    assert batch["batch_id"]
    assert [item["finding_id"] for item in batch["findings"]] == ["f1", "f2"]
    raw = queue.get_scan_finding("f2")
    assert raw["index_finding"]["finding_id"] == "f2"
    assert raw["raw_finding"]["check_id"] == "rule.two"


def test_triage_queue_rejects_incomplete_batch_finalization(tmp_path):
    index_ref = _write_scan_artifacts(tmp_path)
    queue = TriageQueue(project_root=tmp_path, index_ref=index_ref)
    batch = queue.claim_next_batch(batch_size=2)

    with pytest.raises(ValueError, match="cover every finding"):
        queue.finalize_batch(
            batch_id=batch["batch_id"],
            decisions=[{"finding_id": "f1", "decision": "false_positive", "reason": "not reachable"}],
        )


def test_triage_queue_finalizes_batch_and_persists_kept_findings(tmp_path):
    index_ref = _write_scan_artifacts(tmp_path)
    queue = TriageQueue(project_root=tmp_path, index_ref=index_ref)
    batch = queue.claim_next_batch(batch_size=2)
    finding = {
        "vulnerability_type": "xss",
        "severity": "high",
        "title": "Reflected XSS",
        "description": "User input reaches response output.",
        "file_path": "app/a.py",
        "line_start": 1,
        "line_end": 1,
        "code_snippet": "return request.args['name']",
        "source": "request.args['name']",
        "sink": "HTTP response body",
        "suggestion": "Escape output.",
        "confidence": 0.9,
        "needs_verification": True,
        "verdict": "candidate",
        "exploit_chain": [{"step": 1, "location": "app/a.py:1", "description": "input to response"}],
        "poc": {
            "description": "Send reflected payload.",
            "preconditions": ["route is reachable"],
            "steps": [{"step": 1, "action": "send request", "request": "GET /?name=<script>", "expected_response": "payload reflected"}],
            "payload": "<script>alert(1)</script>",
            "impact": "script execution",
            "cve_justification": "remote XSS",
        },
        "impact": "Attacker can execute script in victim browser.",
        "cve_justification": "Remote reflected XSS.",
        "verification_notes": "Verify route reachability.",
    }

    result = queue.finalize_batch(
        batch_id=batch["batch_id"],
        decisions=[
            {"finding_id": "f1", "decision": "keep", "finding": finding},
            {"finding_id": "f2", "decision": "false_positive", "reason": "Sanitized before sink"},
        ],
    )

    assert result["kept_count"] == 1
    assert result["false_positive_count"] == 1
    assert queue.coverage_summary()["pending_count"] == 1
    persisted = json.loads((tmp_path / ".auditai/scans/run-1/triage_findings.json").read_text(encoding="utf-8"))
    assert persisted[0]["title"] == "Reflected XSS"
