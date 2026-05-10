from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from app.services.scan_runtime.store import ScanResultStore

PENDING_STATUS = "pending"
REVIEWING_STATUS = "reviewing"
KEEP_STATUS = "triaged_keep"
FALSE_POSITIVE_STATUS = "triaged_false_positive"
DUPLICATE_STATUS = "triaged_duplicate"
LOW_VALUE_STATUS = "triaged_low_value"
NEEDS_MORE_CONTEXT_STATUS = "needs_more_context"
ERROR_RETRYABLE_STATUS = "error_retryable"
ERROR_TERMINAL_STATUS = "error_terminal"

TERMINAL_STATUSES = {
    KEEP_STATUS,
    FALSE_POSITIVE_STATUS,
    DUPLICATE_STATUS,
    LOW_VALUE_STATUS,
    ERROR_TERMINAL_STATUS,
}

DECISION_TO_STATUS = {
    "keep": KEEP_STATUS,
    "false_positive": FALSE_POSITIVE_STATUS,
    "duplicate": DUPLICATE_STATUS,
    "low_value": LOW_VALUE_STATUS,
    "needs_more_context": NEEDS_MORE_CONTEXT_STATUS,
    "error": ERROR_RETRYABLE_STATUS,
}


class TriageQueue:
    def __init__(
        self,
        *,
        project_root: str | Path,
        index_ref: str,
        lease_seconds: int = 900,
        max_attempts: int = 3,
    ):
        self.project_root = Path(project_root).resolve()
        self.index_ref = index_ref
        self.store = ScanResultStore(self.project_root)
        self.index_path = self.store.resolve_ref(index_ref)
        self.lease_seconds = max(1, int(lease_seconds or 900))
        self.max_attempts = max(1, int(max_attempts or 3))

    def claim_next_batch(self, *, batch_size: int = 5) -> dict[str, Any]:
        batch_size = max(1, min(20, int(batch_size or 5)))
        index = self._load_index()
        self._reclaim_expired(index)
        candidates = [
            item
            for item in index
            if str(item.get("status") or PENDING_STATUS) in {PENDING_STATUS, ERROR_RETRYABLE_STATUS, NEEDS_MORE_CONTEXT_STATUS}
            and int(item.get("triage_attempts") or 0) < self.max_attempts
        ]
        candidates.sort(key=lambda item: int(item.get("priority") or 0), reverse=True)
        selected = candidates[:batch_size]
        if not selected:
            self._save_index(index)
            return {"batch_id": None, "findings": [], "remaining": self.coverage_summary(index=index)}

        batch_id = f"triage-batch-{uuid.uuid4().hex[:12]}"
        lease_expires_at = (datetime.now(timezone.utc) + timedelta(seconds=self.lease_seconds)).isoformat()
        selected_ids = {str(item.get("finding_id")) for item in selected}
        for item in index:
            if str(item.get("finding_id")) not in selected_ids:
                continue
            item["status"] = REVIEWING_STATUS
            item["batch_id"] = batch_id
            item["lease_expires_at"] = lease_expires_at
            item["triage_attempts"] = int(item.get("triage_attempts") or 0) + 1
        self._save_index(index)
        return {
            "batch_id": batch_id,
            "findings": [self._public_index_item(item) for item in selected],
            "remaining": self.coverage_summary(index=index),
        }

    def get_scan_finding(self, finding_id: str) -> dict[str, Any]:
        index_item = self._find_index_item(finding_id)
        artifact_ref = str(index_item.get("artifact_ref") or "").strip()
        if not artifact_ref:
            raise ValueError(f"Finding has no artifact_ref: {finding_id}")
        artifact_payload = self.store.read_json_ref(artifact_ref)
        raw_results = artifact_payload.get("results") if isinstance(artifact_payload, dict) else None
        if not isinstance(raw_results, list):
            raise ValueError(f"Artifact does not contain scanner results: {artifact_ref}")
        raw_index = int(index_item.get("raw_finding_index") or 0)
        if raw_index < 0 or raw_index >= len(raw_results):
            raise ValueError(f"raw_finding_index out of range for {finding_id}: {raw_index}")
        return {
            "finding_id": finding_id,
            "index_finding": self._public_index_item(index_item),
            "raw_finding": raw_results[raw_index],
            "artifact_ref": artifact_ref,
            "raw_finding_index": raw_index,
        }

    def finalize_batch(self, *, batch_id: str, decisions: list[dict[str, Any]]) -> dict[str, Any]:
        if not batch_id:
            raise ValueError("batch_id is required")
        if not isinstance(decisions, list) or not decisions:
            raise ValueError("decisions must be a non-empty list")

        index = self._load_index()
        batch_items = [
            item
            for item in index
            if item.get("batch_id") == batch_id and str(item.get("status") or "") == REVIEWING_STATUS
        ]
        if not batch_items:
            raise ValueError(f"No active reviewing findings for batch: {batch_id}")

        expected_ids = {str(item.get("finding_id")) for item in batch_items}
        provided_ids = [str(item.get("finding_id") or "") for item in decisions]
        if len(set(provided_ids)) != len(provided_ids):
            raise ValueError("decisions contain duplicate finding_id values")
        if set(provided_ids) != expected_ids:
            raise ValueError("FinalizeTriageBatch decisions must cover every finding in the active batch")

        decisions_by_id = {str(item.get("finding_id")): dict(item) for item in decisions}
        kept_findings = self._load_triage_findings()
        counts: dict[str, int] = {}
        for item in index:
            finding_id = str(item.get("finding_id") or "")
            if finding_id not in decisions_by_id:
                continue
            decision = decisions_by_id[finding_id]
            decision_name = str(decision.get("decision") or "").strip()
            status = DECISION_TO_STATUS.get(decision_name)
            if status is None:
                raise ValueError(f"Unsupported triage decision for {finding_id}: {decision_name}")
            if decision_name == "keep":
                finding = decision.get("finding")
                if not isinstance(finding, dict):
                    raise ValueError(f"keep decision requires finding payload: {finding_id}")
                kept_findings.append({**finding, "source_scan_finding_id": finding_id})
            elif decision_name == "duplicate" and not str(decision.get("duplicate_of") or "").strip():
                raise ValueError(f"duplicate decision requires duplicate_of: {finding_id}")
            elif decision_name not in {"needs_more_context", "error"} and not str(decision.get("reason") or "").strip():
                raise ValueError(f"{decision_name} decision requires reason: {finding_id}")

            item["status"] = self._status_after_attempts(status, item)
            item["triage_decision"] = decision
            item.pop("lease_expires_at", None)
            counts[item["status"]] = counts.get(item["status"], 0) + 1

        self._save_index(index)
        self._save_triage_findings(kept_findings)
        return {
            "batch_id": batch_id,
            "processed_count": len(decisions),
            "kept_count": counts.get(KEEP_STATUS, 0),
            "false_positive_count": counts.get(FALSE_POSITIVE_STATUS, 0),
            "duplicate_count": counts.get(DUPLICATE_STATUS, 0),
            "low_value_count": counts.get(LOW_VALUE_STATUS, 0),
            "needs_more_context_count": counts.get(NEEDS_MORE_CONTEXT_STATUS, 0),
            "error_retryable_count": counts.get(ERROR_RETRYABLE_STATUS, 0),
            "error_terminal_count": counts.get(ERROR_TERMINAL_STATUS, 0),
            "coverage": self.coverage_summary(index=index),
        }

    def finalize_triage(self, *, summary: str | None = None, require_complete: bool = True) -> dict[str, Any]:
        coverage = self.coverage_summary()
        if require_complete and not coverage.get("is_complete"):
            raise ValueError("Triage queue is not complete; finish all pending scan findings before finalizing triage")
        findings = self._load_triage_findings()
        self._save_triage_findings(findings)
        final_summary = str(summary or "").strip()
        if not final_summary:
            total = int(coverage.get("total_count") or 0)
            kept = len(findings)
            final_summary = f"Triage reviewed {total} scan candidates and kept {kept} findings."
        payload = {
            "findings": findings,
            "summary": final_summary,
            "coverage": coverage,
            "triage_findings_ref": self.store.to_ref(self._triage_findings_path()),
            "index_ref": self.index_ref,
        }
        self._save_triage_summary(payload)
        return payload

    def coverage_summary(self, *, index: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        index = index if index is not None else self._load_index()
        counts: dict[str, int] = {}
        for item in index:
            status = str(item.get("status") or PENDING_STATUS)
            counts[status] = counts.get(status, 0) + 1
        return {
            "total_count": len(index),
            "pending_count": counts.get(PENDING_STATUS, 0),
            "reviewing_count": counts.get(REVIEWING_STATUS, 0),
            "retryable_count": counts.get(ERROR_RETRYABLE_STATUS, 0),
            "needs_more_context_count": counts.get(NEEDS_MORE_CONTEXT_STATUS, 0),
            "terminal_count": sum(counts.get(status, 0) for status in TERMINAL_STATUSES),
            "by_status": counts,
            "is_complete": (
                counts.get(PENDING_STATUS, 0) == 0
                and counts.get(REVIEWING_STATUS, 0) == 0
                and counts.get(ERROR_RETRYABLE_STATUS, 0) == 0
                and counts.get(NEEDS_MORE_CONTEXT_STATUS, 0) == 0
            ),
        }

    def _status_after_attempts(self, status: str, item: dict[str, Any]) -> str:
        if status not in {ERROR_RETRYABLE_STATUS, NEEDS_MORE_CONTEXT_STATUS}:
            return status
        attempts = int(item.get("triage_attempts") or 0)
        return ERROR_TERMINAL_STATUS if attempts >= self.max_attempts else status

    def _reclaim_expired(self, index: list[dict[str, Any]]) -> None:
        now = datetime.now(timezone.utc)
        for item in index:
            if str(item.get("status") or "") != REVIEWING_STATUS:
                continue
            raw_expiry = str(item.get("lease_expires_at") or "")
            try:
                expiry = datetime.fromisoformat(raw_expiry)
            except ValueError:
                expiry = now
            if expiry <= now:
                item["status"] = ERROR_RETRYABLE_STATUS
                item.pop("lease_expires_at", None)

    def _find_index_item(self, finding_id: str) -> dict[str, Any]:
        needle = str(finding_id or "").strip()
        for item in self._load_index():
            if str(item.get("finding_id") or "") == needle:
                return item
        raise ValueError(f"Unknown scan finding_id: {finding_id}")

    def _public_index_item(self, item: dict[str, Any]) -> dict[str, Any]:
        hidden = {"triage_decision"}
        return {key: value for key, value in item.items() if key not in hidden}

    def _load_index(self) -> list[dict[str, Any]]:
        payload = json.loads(self.index_path.read_text(encoding="utf-8"))
        if not isinstance(payload, list):
            raise ValueError(f"Triage index must be a list: {self.index_ref}")
        return [dict(item) for item in payload if isinstance(item, dict)]

    def _save_index(self, index: list[dict[str, Any]]) -> None:
        self.index_path.write_text(json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")

    def _triage_findings_path(self) -> Path:
        return self.index_path.parent / "triage_findings.json"

    def _load_triage_findings(self) -> list[dict[str, Any]]:
        path = self._triage_findings_path()
        if not path.exists():
            return []
        payload = json.loads(path.read_text(encoding="utf-8"))
        return [dict(item) for item in payload if isinstance(item, dict)] if isinstance(payload, list) else []

    def _save_triage_findings(self, findings: list[dict[str, Any]]) -> None:
        path = self._triage_findings_path()
        path.write_text(json.dumps(findings, ensure_ascii=False, indent=2), encoding="utf-8")

    def _save_triage_summary(self, payload: dict[str, Any]) -> None:
        path = self.index_path.parent / "triage_summary.json"
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
