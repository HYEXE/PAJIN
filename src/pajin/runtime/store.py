"""Append-only audit, artifact, and tamper-evident Run storage."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

_HASH_PATTERN = r"^[a-f0-9]{64}$"
_INTEGRITY_API_VERSION = "pajin.dev/run-integrity/v1"
_RESERVED_ARTIFACTS = frozenset({"events.jsonl", "run-integrity.jsonl"})
_MEDIA_TYPES = {
    ".json": "application/json",
    ".jsonl": "application/x-ndjson",
    ".md": "text/markdown",
    ".txt": "text/plain",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
}


class RunIntegrityError(ValueError):
    """A Run's event chain, seal chain, or sealed artifact set is invalid."""


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _file_digest(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: f"event_{uuid4().hex}")
    run_id: str
    sequence: int = Field(ge=1)
    event_type: str
    occurred_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str | None = Field(default=None, pattern=_HASH_PATTERN)
    event_hash: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def require_aware_timestamp(self) -> AuditEvent:
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("Audit Event timestamps must include a UTC offset or Z")
        return self

    def computed_hash(self) -> str:
        material = self.model_dump(mode="json", exclude={"event_hash"})
        return _canonical_digest(material)


class ArtifactProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str | None = None
    tool_id: str | None = None
    execution_id: str | None = None
    event_ids: list[str] = Field(default_factory=list)


class SealedArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    sha256: str = Field(pattern=_HASH_PATTERN)
    size_bytes: int = Field(ge=0)
    media_type: str
    provenance: ArtifactProvenance | None = None


class RunIntegritySeal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_version: str = _INTEGRITY_API_VERSION
    seal_id: str = Field(default_factory=lambda: f"seal_{uuid4().hex}")
    run_id: str
    sequence: int = Field(ge=1)
    sealed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    previous_root_digest: str | None = Field(default=None, pattern=_HASH_PATTERN)
    event_count: int = Field(ge=1)
    event_head_hash: str = Field(pattern=_HASH_PATTERN)
    artifact_root_digest: str = Field(pattern=_HASH_PATTERN)
    artifacts: list[SealedArtifact] = Field(default_factory=list)
    root_digest: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def require_aware_timestamp(self) -> RunIntegritySeal:
        if self.sealed_at.tzinfo is None or self.sealed_at.utcoffset() is None:
            raise ValueError("Run seal timestamps must include a UTC offset or Z")
        return self

    def computed_artifact_root_digest(self) -> str:
        return _canonical_digest([artifact.model_dump(mode="json") for artifact in self.artifacts])

    def computed_root_digest(self) -> str:
        material = self.model_dump(mode="json", exclude={"root_digest"})
        return _canonical_digest(material)


class RunIntegrityVerification(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    seal_count: int = Field(ge=1)
    artifact_count: int = Field(ge=0)
    event_count: int = Field(ge=1)
    root_digest: str = Field(pattern=_HASH_PATTERN)
    valid: bool = True


@dataclass(frozen=True)
class _IntegrityState:
    run_id: str
    events: list[AuditEvent]
    seals: list[RunIntegritySeal]
    sealed_paths: set[str]
    unsealed_paths: list[str]


def _load_events(events_path: Path, *, expected_run_id: str | None = None) -> list[AuditEvent]:
    if not events_path.is_file():
        raise RunIntegrityError("Run event stream is missing")
    lines = events_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise RunIntegrityError("Run event stream is empty")

    events: list[AuditEvent] = []
    previous_hash: str | None = None
    run_id = expected_run_id
    for expected_sequence, line in enumerate(lines, start=1):
        if not line.strip():
            raise RunIntegrityError("Run event stream contains a blank record")
        try:
            event = AuditEvent.model_validate_json(line)
        except ValueError as exc:
            raise RunIntegrityError(f"invalid Audit Event at sequence {expected_sequence}") from exc
        if run_id is None:
            run_id = event.run_id
        if event.run_id != run_id:
            raise RunIntegrityError("Run event stream contains inconsistent run identifiers")
        if event.sequence != expected_sequence:
            raise RunIntegrityError("Run event sequence is not contiguous")
        if event.previous_hash != previous_hash:
            raise RunIntegrityError("Run event previous-hash link is invalid")
        if event.event_hash != event.computed_hash():
            raise RunIntegrityError("Run event hash does not match its canonical content")
        events.append(event)
        previous_hash = event.event_hash
    return events


def _load_seals(integrity_path: Path, *, expected_run_id: str) -> list[RunIntegritySeal]:
    if not integrity_path.is_file():
        return []
    lines = integrity_path.read_text(encoding="utf-8").splitlines()
    if not lines:
        raise RunIntegrityError("Run integrity log is empty")

    seals: list[RunIntegritySeal] = []
    previous_root: str | None = None
    for expected_sequence, line in enumerate(lines, start=1):
        if not line.strip():
            raise RunIntegrityError("Run integrity log contains a blank record")
        try:
            seal = RunIntegritySeal.model_validate_json(line)
        except ValueError as exc:
            raise RunIntegrityError(f"invalid Run seal at sequence {expected_sequence}") from exc
        if seal.api_version != _INTEGRITY_API_VERSION:
            raise RunIntegrityError("unsupported Run integrity version")
        if seal.run_id != expected_run_id:
            raise RunIntegrityError("Run seal belongs to a different run")
        if seal.sequence != expected_sequence:
            raise RunIntegrityError("Run seal sequence is not contiguous")
        if seal.previous_root_digest != previous_root:
            raise RunIntegrityError("Run seal previous-root link is invalid")
        if seal.artifacts != sorted(seal.artifacts, key=lambda item: item.path):
            raise RunIntegrityError("Run seal artifacts are not canonically ordered")
        if seal.artifact_root_digest != seal.computed_artifact_root_digest():
            raise RunIntegrityError("Run seal artifact root does not match its artifact records")
        if seal.root_digest != seal.computed_root_digest():
            raise RunIntegrityError("Run seal root digest does not match its canonical content")
        seals.append(seal)
        previous_root = seal.root_digest
    return seals


def _contains_scalar(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    if isinstance(value, list):
        return any(_contains_scalar(item, expected) for item in value)
    if isinstance(value, dict):
        return any(_contains_scalar(item, expected) for item in value.values())
    return False


def _artifact_provenance(
    path: Path,
    relative_path: str,
    events: list[AuditEvent],
) -> ArtifactProvenance | None:
    request_id: str | None = None
    tool_id: str | None = None
    execution_id: str | None = None
    if relative_path.startswith("evidence/") and path.suffix.lower() == ".json":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raw = None
        if isinstance(raw, dict):
            request = raw.get("request")
            worker_job = raw.get("workerJob")
            if isinstance(request, dict):
                raw_request_id = request.get("request_id")
                raw_tool_id = request.get("tool_id")
                request_id = raw_request_id if isinstance(raw_request_id, str) else None
                tool_id = raw_tool_id if isinstance(raw_tool_id, str) else None
            if isinstance(worker_job, dict):
                raw_execution_id = worker_job.get("executionId")
                execution_id = raw_execution_id if isinstance(raw_execution_id, str) else None

    event_ids = [
        event.event_id
        for event in events
        if _contains_scalar(event.payload, relative_path)
        or (request_id is not None and _contains_scalar(event.payload, request_id))
    ]
    if not any((request_id, tool_id, execution_id, event_ids)):
        return None
    return ArtifactProvenance(
        request_id=request_id,
        tool_id=tool_id,
        execution_id=execution_id,
        event_ids=event_ids,
    )


def _artifact_record(
    root: Path,
    relative_path: str,
    events: list[AuditEvent],
) -> SealedArtifact:
    path = root / relative_path
    media_type = _MEDIA_TYPES.get(path.suffix.lower(), "application/octet-stream")
    return SealedArtifact(
        path=relative_path,
        sha256=_file_digest(path),
        size_bytes=path.stat().st_size,
        media_type=media_type,
        provenance=_artifact_provenance(path, relative_path, events),
    )


def _artifact_paths(root: Path) -> list[str]:
    paths: list[str] = []
    for candidate in root.rglob("*"):
        if candidate.is_symlink():
            raise RunIntegrityError("Run artifacts cannot contain symbolic links")
        if not candidate.is_file():
            continue
        resolved = candidate.resolve()
        if root != resolved and root not in resolved.parents:
            raise RunIntegrityError("Run artifact resolves outside the Run directory")
        relative = candidate.relative_to(root).as_posix()
        if relative not in _RESERVED_ARTIFACTS:
            paths.append(relative)
    return sorted(paths)


def _integrity_state(run_path: Path, *, allow_extensions: bool) -> _IntegrityState:
    root = run_path.resolve()
    if not root.is_dir():
        raise RunIntegrityError("Run path must be an existing directory")
    events = _load_events(root / "events.jsonl")
    run_id = events[0].run_id
    seals = _load_seals(root / "run-integrity.jsonl", expected_run_id=run_id)
    if not seals and not allow_extensions:
        raise RunIntegrityError("Run has not been integrity-sealed")

    sealed_paths: set[str] = set()
    previous_event_count = 0
    for seal in seals:
        if seal.event_count < previous_event_count or seal.event_count > len(events):
            raise RunIntegrityError("Run seal references an invalid event checkpoint")
        if events[seal.event_count - 1].event_hash != seal.event_head_hash:
            raise RunIntegrityError("Run seal event checkpoint does not match the event chain")
        previous_event_count = seal.event_count
        event_prefix = events[: seal.event_count]
        for artifact in seal.artifacts:
            if artifact.path in _RESERVED_ARTIFACTS or artifact.path in sealed_paths:
                raise RunIntegrityError("Run seal contains a duplicate or reserved artifact path")
            candidate = (root / artifact.path).resolve()
            if root not in candidate.parents or not candidate.is_file() or candidate.is_symlink():
                raise RunIntegrityError(f"sealed Run artifact is missing: {artifact.path}")
            observed = _artifact_record(root, artifact.path, event_prefix)
            if observed != artifact:
                raise RunIntegrityError(f"sealed Run artifact changed: {artifact.path}")
            sealed_paths.add(artifact.path)

    current_paths = set(_artifact_paths(root))
    unsealed_paths = sorted(current_paths - sealed_paths)
    if not allow_extensions:
        if seals[-1].event_count != len(events):
            raise RunIntegrityError("Run event stream has unsealed appended events")
        if unsealed_paths:
            raise RunIntegrityError(f"Run contains unsealed artifacts: {', '.join(unsealed_paths)}")
    return _IntegrityState(
        run_id=run_id,
        events=events,
        seals=seals,
        sealed_paths=sealed_paths,
        unsealed_paths=unsealed_paths,
    )


def verify_run_integrity(run_path: Path) -> RunIntegrityVerification:
    """Verify every event link, seal link, and sealed file in one Run directory."""

    state = _integrity_state(run_path, allow_extensions=False)
    last_seal = state.seals[-1]
    return RunIntegrityVerification(
        run_id=state.run_id,
        seal_count=len(state.seals),
        artifact_count=len(state.sealed_paths),
        event_count=len(state.events),
        root_digest=last_seal.root_digest,
    )


class RunStore:
    """Store and append integrity extensions under one isolated Run directory."""

    def __init__(self, run_id: str, path: Path) -> None:
        self.run_id = run_id
        self.path = path.resolve()
        self.evidence_path = self.path / "evidence"
        self.events_path = self.path / "events.jsonl"
        self.integrity_path = self.path / "run-integrity.jsonl"
        self._event_count: int | None = None
        self._event_head_hash: str | None = None

    @classmethod
    def create(cls, root: Path, campaign_name: str) -> RunStore:
        run_id = f"run_{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}_{uuid4().hex[:8]}"
        path = (root / campaign_name / run_id).resolve()
        evidence_path = path / "evidence"
        evidence_path.mkdir(parents=True, exist_ok=False)
        return cls(run_id=run_id, path=path)

    def append_event(
        self,
        event_type: str,
        payload: dict[str, Any] | None = None,
        *,
        occurred_at: datetime | None = None,
    ) -> AuditEvent:
        self._ensure_event_state()
        assert self._event_count is not None
        sequence = self._event_count + 1
        event = AuditEvent(
            run_id=self.run_id,
            sequence=sequence,
            event_type=event_type,
            occurred_at=occurred_at or datetime.now(UTC),
            payload=payload or {},
            previous_hash=self._event_head_hash,
            event_hash="0" * 64,
        )
        event = event.model_copy(update={"event_hash": event.computed_hash()})
        with self.events_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(event.model_dump_json())
            handle.write("\n")
        self._event_count = sequence
        self._event_head_hash = event.event_hash
        return event

    def write_json(self, relative_path: str, data: Any) -> str:
        destination = self._safe_destination(relative_path)
        self._require_unsealed(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, default=str)
            handle.write("\n")
        return destination.relative_to(self.path).as_posix()

    def write_text(self, relative_path: str, content: str) -> str:
        destination = self._safe_destination(relative_path)
        self._require_unsealed(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            if not content.endswith("\n"):
                handle.write("\n")
        return destination.relative_to(self.path).as_posix()

    def seal(self) -> RunIntegritySeal:
        """Append a seal for every new artifact and event since the previous seal."""

        state = _integrity_state(self.path, allow_extensions=True)
        if state.run_id != self.run_id:
            raise RunIntegrityError("RunStore identifier differs from the Run event stream")
        previous = state.seals[-1] if state.seals else None
        if (
            previous is not None
            and not state.unsealed_paths
            and previous.event_count == len(state.events)
        ):
            raise RunIntegrityError("Run has no new artifacts or events to seal")
        artifacts = sorted(
            (
                _artifact_record(self.path, relative, state.events)
                for relative in state.unsealed_paths
            ),
            key=lambda item: item.path,
        )
        artifact_root = _canonical_digest(
            [artifact.model_dump(mode="json") for artifact in artifacts]
        )
        seal = RunIntegritySeal(
            run_id=self.run_id,
            sequence=len(state.seals) + 1,
            previous_root_digest=previous.root_digest if previous else None,
            event_count=len(state.events),
            event_head_hash=state.events[-1].event_hash,
            artifact_root_digest=artifact_root,
            artifacts=artifacts,
            root_digest="0" * 64,
        )
        seal = seal.model_copy(update={"root_digest": seal.computed_root_digest()})
        with self.integrity_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(seal.model_dump_json())
            handle.write("\n")
        return seal

    def _ensure_event_state(self) -> None:
        if self._event_count is not None:
            return
        if not self.events_path.exists():
            self._event_count = 0
            self._event_head_hash = None
            return
        events = _load_events(self.events_path, expected_run_id=self.run_id)
        self._event_count = len(events)
        self._event_head_hash = events[-1].event_hash

    def _require_unsealed(self, destination: Path) -> None:
        relative = destination.relative_to(self.path).as_posix()
        if relative in _RESERVED_ARTIFACTS:
            raise ValueError(f"artifact path is reserved by RunStore: {relative}")
        if not self.integrity_path.exists():
            return
        seals = _load_seals(self.integrity_path, expected_run_id=self.run_id)
        if any(relative == artifact.path for seal in seals for artifact in seal.artifacts):
            raise RunIntegrityError(f"sealed Run artifact cannot be overwritten: {relative}")

    def _safe_destination(self, relative_path: str) -> Path:
        candidate = (self.path / relative_path).resolve()
        root = self.path.resolve()
        if candidate != root and root not in candidate.parents:
            raise ValueError("artifact path escapes the run directory")
        return candidate
