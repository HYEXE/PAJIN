"""Append-only local audit and artifact storage for the MVP backend."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: f"event_{uuid4().hex}")
    run_id: str
    event_type: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)


class RunStore:
    """Store one campaign run under an isolated, append-only directory."""

    def __init__(self, run_id: str, path: Path) -> None:
        self.run_id = run_id
        self.path = path
        self.evidence_path = path / "evidence"
        self.events_path = path / "events.jsonl"

    @classmethod
    def create(cls, root: Path, campaign_name: str) -> RunStore:
        run_id = f"run_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:8]}"
        path = (root / campaign_name / run_id).resolve()
        evidence_path = path / "evidence"
        evidence_path.mkdir(parents=True, exist_ok=False)
        return cls(run_id=run_id, path=path)

    def append_event(self, event_type: str, payload: dict[str, Any] | None = None) -> AuditEvent:
        event = AuditEvent(
            run_id=self.run_id,
            event_type=event_type,
            payload=payload or {},
        )
        with self.events_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(event.model_dump_json())
            handle.write("\n")
        return event

    def write_json(self, relative_path: str, data: Any) -> str:
        destination = self._safe_destination(relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, default=str)
            handle.write("\n")
        return destination.relative_to(self.path).as_posix()

    def write_text(self, relative_path: str, content: str) -> str:
        destination = self._safe_destination(relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
        return destination.relative_to(self.path).as_posix()

    def _safe_destination(self, relative_path: str) -> Path:
        candidate = (self.path / relative_path).resolve()
        root = self.path.resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError("artifact path escapes the run directory")
        return candidate
