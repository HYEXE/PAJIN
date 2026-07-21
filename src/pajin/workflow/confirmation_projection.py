"""Atomic persistence and recovery for replay-confirmation projections.

Policy derivation is injected by the public confirmation facade.  Keeping that
callback explicit both separates the responsibilities and preserves the historic
test seam without making this storage layer import the facade back.
"""

from __future__ import annotations

import errno
import importlib
import json
import os
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, BinaryIO, Protocol

if sys.platform != "win32":
    import fcntl

from pajin.domain.models import AgentPlan, CampaignManifest, Finding
from pajin.domain.validation import (
    CandidateFinding,
    FindingDisposition,
    FindingValidationSet,
    ValidationDecision,
)
from pajin.replay.runtime import VerifiedReplayResult, load_verified_replay_result
from pajin.replay.tickets import ReplayTicketFinalizationVerifier
from pajin.runtime.safe_files import (
    load_bounded_strict_json,
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)
from pajin.runtime.store import (
    AuditEvent,
    RunIntegrityError,
    RunIntegritySeal,
    RunStore,
    _integrity_state,
    verify_run_integrity,
)
from pajin.workflow.confirmation_policy import (
    _ConfirmationProjection,
    _load_source_context,
)
from pajin.workflow.validation_artifacts import (
    VERSIONED_VALIDATION_DECISIONS_PATH,
    VERSIONED_VALIDATION_FINDINGS_PATH,
    VERSIONED_VALIDATION_INDEX_PATH,
    VERSIONED_VALIDATION_REPORT_PATH,
    LoadedValidationSnapshot,
    load_source_validation_artifacts,
    load_validation_snapshot,
)

_PROJECTION_TRANSACTION_PATH = "validation/v1alpha1/transaction.json"
_PROJECTION_TRANSACTION_VERSION = "pajin.dev/confirmation-projection-transaction/v1"
_PROJECTION_EVENT_TYPE = "validation.confirmation-projection.created"
_MAX_SEALED_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_RUN_LOG_BYTES = 64 * 1024 * 1024


class _ProjectionBuilder(Protocol):
    def __call__(
        self,
        *,
        root: Path,
        source_run_id: str,
        source_validation: FindingValidationSet,
        campaign: CampaignManifest,
        plan: AgentPlan,
        verified_results: list[VerifiedReplayResult],
        evaluated_at: datetime,
    ) -> _ConfirmationProjection: ...


class _FsyncFile(Protocol):
    def __call__(self, path: Path) -> None: ...


class _IntegrityStateView(Protocol):
    @property
    def run_id(self) -> str: ...

    @property
    def events(self) -> list[AuditEvent]: ...

    @property
    def seals(self) -> list[RunIntegritySeal]: ...

    @property
    def unsealed_paths(self) -> list[str]: ...


def apply_confirmed_gate(
    *,
    source_run_path: Path,
    replay_run_paths: Sequence[Path],
    tickets: ReplayTicketFinalizationVerifier,
    build_projection: _ProjectionBuilder,
    fsync_file: _FsyncFile,
    decided_at: datetime | None = None,
) -> LoadedValidationSnapshot:
    """Apply or recover one cross-process serialized confirmation projection."""

    root = source_run_path.resolve()
    with _confirmation_projection_lock(root):
        if _recover_confirmation_projection(
            root,
            replay_run_paths=replay_run_paths,
            tickets=tickets,
            build_projection=build_projection,
            fsync_file=fsync_file,
        ):
            return load_validation_snapshot(root)
        return _apply_confirmed_gate_locked(
            source_run_path=root,
            replay_run_paths=replay_run_paths,
            tickets=tickets,
            build_projection=build_projection,
            fsync_file=fsync_file,
            decided_at=decided_at,
        )


def _apply_confirmed_gate_locked(
    *,
    source_run_path: Path,
    replay_run_paths: Sequence[Path],
    tickets: ReplayTicketFinalizationVerifier,
    build_projection: _ProjectionBuilder,
    fsync_file: _FsyncFile,
    decided_at: datetime | None = None,
) -> LoadedValidationSnapshot:
    """Reload verified receipts, derive one gate, then append a sealed v1 projection."""

    root = source_run_path.resolve()
    source_verification = verify_run_integrity(root)
    if (root / VERSIONED_VALIDATION_INDEX_PATH).exists():
        raise ValueError("source Run already has a versioned validation projection")
    source_validation = load_source_validation_artifacts(root)
    campaign, plan = _load_source_context(root)
    if not replay_run_paths:
        raise ValueError("confirmed gate requires at least one replay receipt")
    if any(
        decision.disposition is FindingDisposition.CONFIRMED
        or decision.replay_request_ids
        or decision.replay_outcome_ids
        or decision.replay_lineage
        for decision in source_validation.decisions
    ):
        raise ValueError("source validation is not an unreproduced pre-confirmation snapshot")

    resolved_replay_paths = [path.resolve() for path in replay_run_paths]
    if len(resolved_replay_paths) != len(set(resolved_replay_paths)):
        raise ValueError("confirmed gate replay Run paths must be unique")
    verified_results = [
        load_verified_replay_result(path, tickets=tickets) for path in resolved_replay_paths
    ]
    evaluated_at = decided_at or datetime.now(UTC)
    if evaluated_at.tzinfo is None or evaluated_at.utcoffset() is None:
        raise ValueError("confirmed gate decision time must include a UTC offset or Z")
    evaluated_at = evaluated_at.astimezone(UTC)
    projection = build_projection(
        root=root,
        source_run_id=source_verification.run_id,
        source_validation=source_validation,
        campaign=campaign,
        plan=plan,
        verified_results=verified_results,
        evaluated_at=evaluated_at,
    )

    if verify_run_integrity(root).root_digest != source_verification.root_digest:
        raise ValueError("source Run changed while the confirmed gate was evaluating receipts")
    _commit_confirmation_projection(
        root=root,
        source_run_id=source_verification.run_id,
        source_root_digest=source_verification.root_digest,
        projection=projection,
        verified_results=verified_results,
        fsync_file=fsync_file,
    )
    return load_validation_snapshot(root)


@contextmanager
def _confirmation_projection_lock(root: Path) -> Iterator[None]:
    """Serialize confirmation writers without adding an artifact to the source Run."""

    lock_root = root.parent / ".pajin-confirmation-locks"
    lock_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_root_stat = lock_root.lstat()
    if not stat.S_ISDIR(lock_root_stat.st_mode) or lock_root.is_symlink():
        raise RunIntegrityError("confirmation lock root must be a real directory")
    getuid = getattr(os, "getuid", None)
    if getuid is not None and lock_root_stat.st_uid != getuid():
        raise PermissionError("confirmation lock root is owned by another user")
    os.chmod(lock_root, 0o700)
    lock_name = sha256(str(root).encode("utf-8")).hexdigest() + ".lock"
    lock_path = lock_root / lock_name
    flags = os.O_RDWR | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RunIntegrityError("confirmation lock must be a regular file")
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
    except BaseException:
        os.close(descriptor)
        raise
    with os.fdopen(descriptor, "a+b") as handle:
        _lock_confirmation_handle(handle)
        try:
            yield
        finally:
            _unlock_confirmation_handle(handle)


def _lock_confirmation_handle(handle: BinaryIO) -> None:
    if sys.platform != "win32":
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return
    if os.fstat(handle.fileno()).st_size == 0:
        handle.write(b"\0")
        handle.flush()
    msvcrt = importlib.import_module("msvcrt")
    while True:
        handle.seek(0)
        try:
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise
            time.sleep(0.05)


def _unlock_confirmation_handle(handle: BinaryIO) -> None:
    if sys.platform != "win32":
        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
        return
    msvcrt = importlib.import_module("msvcrt")
    handle.seek(0)
    msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def _projection_artifact_bytes(projection: _ConfirmationProjection) -> dict[str, bytes]:
    return {
        VERSIONED_VALIDATION_DECISIONS_PATH: _json_bytes(
            projection.decision_set.model_dump(mode="json", by_alias=True)
        ),
        VERSIONED_VALIDATION_FINDINGS_PATH: _json_bytes(
            projection.finding_set.model_dump(mode="json", by_alias=True)
        ),
        VERSIONED_VALIDATION_INDEX_PATH: _json_bytes(
            projection.index.model_dump(mode="json", by_alias=True)
        ),
        VERSIONED_VALIDATION_REPORT_PATH: _text_bytes(projection.report),
    }


def _json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + "\n").encode("utf-8")


def _text_bytes(value: str) -> bytes:
    return (value if value.endswith("\n") else value + "\n").encode("utf-8")


def _transaction_payload(
    *,
    source_run_id: str,
    source_root_digest: str,
    projection: _ConfirmationProjection,
    verified_results: list[VerifiedReplayResult],
    artifacts: dict[str, bytes],
) -> dict[str, Any]:
    event_id = _projection_event_id(
        source_run_id=source_run_id,
        source_root_digest=source_root_digest,
        projection=projection,
    )
    material: dict[str, Any] = {
        "apiVersion": _PROJECTION_TRANSACTION_VERSION,
        "sourceRunId": source_run_id,
        "sourceRootDigest": source_root_digest,
        "evaluatedAt": _utc_wire(projection.evaluated_at),
        "replayRuns": _replay_run_material(verified_results),
        "artifacts": {
            path: sha256(content).hexdigest() for path, content in sorted(artifacts.items())
        },
        "event": {
            "eventId": event_id,
            "eventType": _PROJECTION_EVENT_TYPE,
            "occurredAt": _utc_wire(projection.evaluated_at),
            "payload": projection.event_payload,
        },
    }
    material["projectionDigest"] = sha256(
        json.dumps(
            material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return material


def _replay_run_material(
    verified_results: Sequence[VerifiedReplayResult],
) -> list[dict[str, str]]:
    return sorted(
        (
            {
                "replayRunId": result.receipt.replay_run_id,
                "runRootDigest": result.verification.root_digest,
                "receiptSealRootDigest": result.receipt_seal_root_digest,
                "artifactSetDigest": result.receipt.artifact_set_digest,
                "candidateSourceRootDigest": result.receipt.candidate_source_root_digest,
            }
            for result in verified_results
        ),
        key=lambda item: item["replayRunId"],
    )


def _projection_event_id(
    *,
    source_run_id: str,
    source_root_digest: str,
    projection: _ConfirmationProjection,
) -> str:
    material = {
        "sourceRunId": source_run_id,
        "sourceRootDigest": source_root_digest,
        "occurredAt": _utc_wire(projection.evaluated_at),
        "payload": projection.event_payload,
    }
    digest = sha256(
        json.dumps(
            material,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    return f"event_confirmation_{digest[:24]}"


def _utc_wire(value: datetime) -> str:
    normalized = value.astimezone(UTC).isoformat()
    return normalized.removesuffix("+00:00") + "Z"


def _commit_confirmation_projection(
    *,
    root: Path,
    source_run_id: str,
    source_root_digest: str,
    projection: _ConfirmationProjection,
    verified_results: list[VerifiedReplayResult],
    fsync_file: _FsyncFile,
) -> None:
    """Atomically install all files, then append their event and seal as one extension."""

    destination = root / "validation"
    if destination.exists():
        raise ValueError("source Run already contains confirmation projection artifacts")
    artifacts = _projection_artifact_bytes(projection)
    transaction = _transaction_payload(
        source_run_id=source_run_id,
        source_root_digest=source_root_digest,
        projection=projection,
        verified_results=verified_results,
        artifacts=artifacts,
    )
    artifacts[_PROJECTION_TRANSACTION_PATH] = _json_bytes(transaction)
    event_id = _projection_event_id(
        source_run_id=source_run_id,
        source_root_digest=source_root_digest,
        projection=projection,
    )
    temporary_root = Path(tempfile.mkdtemp(prefix=f".{root.name}.confirmation-", dir=root.parent))
    staged_validation = temporary_root / "validation"
    installed = False
    try:
        for relative_path, content in artifacts.items():
            staged_path = temporary_root / relative_path
            staged_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            _make_private_directories(staged_path.parent, stop=temporary_root)
            _write_durable(staged_path, content)
        _fsync_directory(staged_validation / "v1alpha1")
        _fsync_directory(staged_validation)
        _fsync_directory(temporary_root)
        os.replace(staged_validation, destination)
        installed = True
        _fsync_directory(root)

        # Recovery must inspect an unsealed extension.  The private store parser is
        # intentionally confined to this module and never escapes this seam.
        state = _integrity_state(root, allow_extensions=True)
        _require_exact_projection_extension(
            state=state,
            source_run_id=source_run_id,
            source_root_digest=source_root_digest,
            expected_paths=set(artifacts),
            allow_confirmation_event=False,
        )
        _append_confirmation_event_atomic(root, projection, event_id=event_id)
        fsync_file(root / "events.jsonl")
        store = RunStore(run_id=source_run_id, path=root)
        store.seal()
        fsync_file(root / "run-integrity.jsonl")
        _fsync_directory(root)
        verify_run_integrity(root)
    except BaseException:
        if not installed:
            shutil.rmtree(temporary_root, ignore_errors=True)
        raise
    finally:
        if temporary_root.exists():
            shutil.rmtree(temporary_root, ignore_errors=True)


def _recover_confirmation_projection(
    root: Path,
    *,
    replay_run_paths: Sequence[Path],
    tickets: ReplayTicketFinalizationVerifier,
    build_projection: _ProjectionBuilder,
    fsync_file: _FsyncFile,
) -> bool:
    """Finish an interrupted projection only after independently re-deriving every byte."""

    try:
        verification = verify_run_integrity(root)
    except RunIntegrityError:
        pass
    else:
        if (root / VERSIONED_VALIDATION_INDEX_PATH).is_file():
            _require_completed_projection_inputs(
                root,
                run_id=verification.run_id,
                replay_run_paths=replay_run_paths,
                tickets=tickets,
            )
            return True
        if (root / "validation" / "v1alpha1").exists():
            raise RunIntegrityError("sealed Run contains an incomplete validation projection")
        return False

    state = _integrity_state(root, allow_extensions=True)
    if not state.seals:
        raise RunIntegrityError("confirmation recovery requires a sealed source Run")
    transaction_content, transaction = _read_projection_transaction(root)

    source_run_id = transaction.get("sourceRunId")
    source_root_digest = transaction.get("sourceRootDigest")
    if not isinstance(source_run_id, str) or not isinstance(source_root_digest, str):
        raise RunIntegrityError("confirmation transaction source identity is invalid")
    expected_paths = {
        VERSIONED_VALIDATION_DECISIONS_PATH,
        VERSIONED_VALIDATION_FINDINGS_PATH,
        VERSIONED_VALIDATION_INDEX_PATH,
        VERSIONED_VALIDATION_REPORT_PATH,
        _PROJECTION_TRANSACTION_PATH,
    }
    _require_exact_projection_extension(
        state=state,
        source_run_id=source_run_id,
        source_root_digest=source_root_digest,
        expected_paths=expected_paths,
        allow_confirmation_event=True,
    )

    source_validation = _load_sealed_source_validation(root, state.sealed_paths)
    campaign, plan = _load_source_context(root)
    resolved_replay_paths = [path.resolve() for path in replay_run_paths]
    if not resolved_replay_paths or len(resolved_replay_paths) != len(set(resolved_replay_paths)):
        raise ValueError("confirmation recovery requires unique replay Run paths")
    verified_results = [
        load_verified_replay_result(path, tickets=tickets) for path in resolved_replay_paths
    ]
    evaluated_at = _transaction_time(transaction.get("evaluatedAt"))
    projection = build_projection(
        root=root,
        source_run_id=source_run_id,
        source_validation=source_validation,
        campaign=campaign,
        plan=plan,
        verified_results=verified_results,
        evaluated_at=evaluated_at,
    )
    artifacts = _projection_artifact_bytes(projection)
    expected_transaction = _transaction_payload(
        source_run_id=source_run_id,
        source_root_digest=source_root_digest,
        projection=projection,
        verified_results=verified_results,
        artifacts=artifacts,
    )
    if transaction != expected_transaction or transaction_content != _json_bytes(
        expected_transaction
    ):
        raise RunIntegrityError("confirmation transaction differs from re-derived inputs")
    for relative_path, expected_content in artifacts.items():
        try:
            observed_content = read_bounded_regular_bytes(
                root / relative_path,
                max_bytes=_MAX_SEALED_ARTIFACT_BYTES,
                label="confirmation projection artifact",
            )
        except (OSError, ValueError) as exc:
            raise RunIntegrityError("confirmation projection artifact is missing") from exc
        if observed_content != expected_content:
            raise RunIntegrityError(f"confirmation projection artifact differs: {relative_path}")

    event_id = _projection_event_id(
        source_run_id=source_run_id,
        source_root_digest=source_root_digest,
        projection=projection,
    )
    sealed_event_count = state.seals[-1].event_count
    appended_events = state.events[sealed_event_count:]
    if appended_events:
        _require_confirmation_event(appended_events[0], projection, event_id=event_id)
    else:
        _append_confirmation_event_atomic(root, projection, event_id=event_id)
        fsync_file(root / "events.jsonl")
    RunStore(run_id=source_run_id, path=root).seal()
    fsync_file(root / "run-integrity.jsonl")
    _fsync_directory(root)
    verify_run_integrity(root)
    return True


def _require_completed_projection_inputs(
    root: Path,
    *,
    run_id: str,
    replay_run_paths: Sequence[Path],
    tickets: ReplayTicketFinalizationVerifier,
) -> None:
    """Keep successful retries exactly bound to the replay receipts used originally."""

    resolved_replay_paths = [path.resolve() for path in replay_run_paths]
    if not resolved_replay_paths or len(resolved_replay_paths) != len(set(resolved_replay_paths)):
        raise ValueError("completed confirmation projection requires unique replay Run paths")
    verified_results = [
        load_verified_replay_result(path, tickets=tickets) for path in resolved_replay_paths
    ]
    _, transaction = _read_projection_transaction(root)
    if (
        transaction.get("apiVersion") != _PROJECTION_TRANSACTION_VERSION
        or transaction.get("sourceRunId") != run_id
        or transaction.get("replayRuns") != _replay_run_material(verified_results)
    ):
        raise ValueError("completed confirmation projection was created from different inputs")


def _read_projection_transaction(root: Path) -> tuple[bytes, dict[str, Any]]:
    transaction_path = root / _PROJECTION_TRANSACTION_PATH
    try:
        transaction_content = read_bounded_regular_bytes(
            transaction_path,
            max_bytes=_MAX_SEALED_ARTIFACT_BYTES,
            label="confirmation transaction",
        )
        raw_transaction = parse_strict_json_bytes(
            transaction_content,
            label="confirmation transaction",
        )
    except (OSError, ValueError) as exc:
        raise RunIntegrityError("confirmation transaction could not be loaded") from exc
    if not isinstance(raw_transaction, dict):
        raise RunIntegrityError("confirmation transaction must be a JSON object")
    return transaction_content, raw_transaction


def _require_exact_projection_extension(
    *,
    state: _IntegrityStateView,
    source_run_id: str,
    source_root_digest: str,
    expected_paths: set[str],
    allow_confirmation_event: bool,
) -> None:
    if state.run_id != source_run_id or state.seals[-1].root_digest != source_root_digest:
        raise RunIntegrityError("confirmation source Run changed before projection sealing")
    if set(state.unsealed_paths) != expected_paths:
        raise RunIntegrityError("Run contains an unexpected unsealed projection extension")
    appended_events = state.events[state.seals[-1].event_count :]
    maximum_events = 1 if allow_confirmation_event else 0
    if len(appended_events) > maximum_events:
        raise RunIntegrityError("Run contains unexpected unsealed confirmation events")
    if appended_events and appended_events[0].event_type != _PROJECTION_EVENT_TYPE:
        raise RunIntegrityError("Run contains an unexpected unsealed event")


def _require_confirmation_event(
    event: AuditEvent,
    projection: _ConfirmationProjection,
    *,
    event_id: str,
) -> None:
    if (
        event.event_id != event_id
        or event.event_type != _PROJECTION_EVENT_TYPE
        or event.payload != projection.event_payload
        or event.occurred_at != projection.evaluated_at
    ):
        raise RunIntegrityError("unsealed confirmation event differs from the transaction")


def _append_confirmation_event_atomic(
    root: Path,
    projection: _ConfirmationProjection,
    *,
    event_id: str,
) -> AuditEvent:
    """Replace the reserved event stream atomically with one complete appended record."""

    state = _integrity_state(root, allow_extensions=True)
    previous = state.events[-1]
    event = AuditEvent(
        event_id=event_id,
        run_id=state.run_id,
        sequence=len(state.events) + 1,
        event_type=_PROJECTION_EVENT_TYPE,
        occurred_at=projection.evaluated_at,
        payload=projection.event_payload,
        previous_hash=previous.event_hash,
        event_hash="0" * 64,
    )
    event = event.model_copy(update={"event_hash": event.computed_hash()})
    try:
        existing = read_bounded_regular_bytes(
            root / "events.jsonl",
            max_bytes=_MAX_RUN_LOG_BYTES,
            label="Run event stream",
        )
    except (OSError, ValueError) as exc:
        raise RunIntegrityError("Run event stream could not be loaded") from exc
    if not existing.endswith(b"\n"):
        raise RunIntegrityError("Run event stream is not newline-terminated")
    updated = existing + event.model_dump_json().encode("utf-8") + b"\n"
    temporary_root = Path(
        tempfile.mkdtemp(prefix=f".{root.name}.confirmation-event-", dir=root.parent)
    )
    staged_events = temporary_root / "events.jsonl"
    try:
        _write_durable(staged_events, updated)
        _fsync_directory(temporary_root)
        os.replace(staged_events, root / "events.jsonl")
        _fsync_directory(root)
    finally:
        shutil.rmtree(temporary_root, ignore_errors=True)
    return event


def _load_sealed_source_validation(
    root: Path,
    sealed_paths: set[str],
) -> FindingValidationSet:
    required_paths = {
        "candidate-findings.json",
        "validation-decisions.json",
        "findings.json",
        "campaign.json",
        "plan.json",
    }
    if not required_paths <= sealed_paths:
        raise RunIntegrityError("source seal predates required validation artifacts")
    try:
        candidates = [
            CandidateFinding.model_validate(item)
            for item in _read_json_list(root / "candidate-findings.json")
        ]
        decisions = [
            ValidationDecision.model_validate(item)
            for item in _read_json_list(root / "validation-decisions.json")
        ]
        findings = [
            Finding.model_validate(item) for item in _read_json_list(root / "findings.json")
        ]
        return FindingValidationSet(
            candidates=candidates,
            decisions=decisions,
            confirmed_findings=findings,
        )
    except ValueError as exc:
        raise RunIntegrityError("sealed source validation artifacts are invalid") from exc


def _read_json_list(path: Path) -> list[object]:
    try:
        value = load_bounded_strict_json(
            path,
            max_bytes=_MAX_SEALED_ARTIFACT_BYTES,
            label=f"validation artifact {path.name}",
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"validation artifact could not be loaded: {path.name}") from exc
    if not isinstance(value, list):
        raise ValueError(f"validation artifact must contain a list: {path.name}")
    return value


def _transaction_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise RunIntegrityError("confirmation transaction time is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RunIntegrityError("confirmation transaction time is invalid") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RunIntegrityError("confirmation transaction time must include UTC")
    return parsed.astimezone(UTC)


def _write_durable(path: Path, content: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())


def _make_private_directories(path: Path, *, stop: Path) -> None:
    current = path
    while current != stop:
        os.chmod(current, 0o700)
        if stop not in current.parents:
            raise RunIntegrityError("confirmation staging directory escaped its private root")
        current = current.parent


def _fsync_file(path: Path) -> None:
    # Windows requires a writable file descriptor for FlushFileBuffers/os.fsync.
    # No bytes are changed; the handle only makes the preceding append durable.
    with path.open("r+b") as handle:
        os.fsync(handle.fileno())


def _fsync_directory(path: Path) -> None:
    if sys.platform == "win32":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
