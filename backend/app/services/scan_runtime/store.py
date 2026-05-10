from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any


class ScanResultStore:
    def __init__(self, project_root: str | Path):
        self.project_root = Path(project_root).resolve()
        self.scan_root = self.project_root / ".auditai" / "scans"

    def create_scan_run_id(self, *, task_id: str | None = None) -> str:
        prefix = str(task_id or "scan").strip() or "scan"
        safe_prefix = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in prefix)[:48]
        return f"{safe_prefix}-{uuid.uuid4().hex[:12]}"

    def run_dir(self, scan_run_id: str) -> Path:
        safe_id = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in scan_run_id)
        return self.scan_root / safe_id

    def write_text_artifact(self, *, scan_run_id: str, filename: str, content: str) -> str:
        path = self._artifact_path(scan_run_id=scan_run_id, filename=filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return self.to_ref(path)

    def write_json_artifact(self, *, scan_run_id: str, filename: str, payload: Any) -> str:
        return self.write_text_artifact(
            scan_run_id=scan_run_id,
            filename=filename,
            content=json.dumps(payload, ensure_ascii=False, indent=2),
        )

    def read_json_ref(self, artifact_ref: str) -> Any:
        path = self.resolve_ref(artifact_ref)
        return json.loads(path.read_text(encoding="utf-8"))

    def resolve_ref(self, artifact_ref: str) -> Path:
        candidate = Path(str(artifact_ref or ""))
        resolved = candidate.resolve() if candidate.is_absolute() else (self.project_root / candidate).resolve()
        try:
            resolved.relative_to(self.project_root)
        except ValueError as exc:
            raise ValueError(f"Artifact ref escapes project root: {artifact_ref}") from exc
        return resolved

    def to_ref(self, path: str | Path) -> str:
        resolved = Path(path).resolve()
        return resolved.relative_to(self.project_root).as_posix()

    def _artifact_path(self, *, scan_run_id: str, filename: str) -> Path:
        name = Path(filename).name
        if not name:
            raise ValueError("Artifact filename is required")
        return self.run_dir(scan_run_id) / name
