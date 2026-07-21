"""Sealed replay snapshot loading, compatibility, and ticket verification."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal, Protocol

from pydantic import ConfigDict, Field, model_validator

from pajin.domain.models import StrictModel
from pajin.domain.replay import (
    ReplayArtifactSet,
    ReplayCompilation,
    load_legacy_v1_replay_artifact_set,
    replay_argument_digest,
)
from pajin.replay.tickets import (
    ReplayExecutionTicket,
    ReplayTicketClaimer,
    ReplayTicketContext,
    ReplayTicketFinalizationVerifier,
    canonicalize_replay_compilation_wire_sets,
    replay_context_digest,
)
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes
from pajin.runtime.store import (
    RunIntegritySeal,
    RunIntegrityVerification,
    locked_run_snapshot,
    verify_run_integrity,
)

_REPLAY_RECEIPT_V1 = "pajin.dev/replay-verification-receipt/v1"
_REPLAY_RECEIPT_V2 = "pajin.dev/replay-verification-receipt/v2"
MAX_REPLAY_SNAPSHOT_FILE_BYTES = 64 * 1024 * 1024


class ReplaySnapshotReader(Protocol):
    """Read one regular file from a locked replay Run snapshot."""

    def __call__(self, root: Path, path: Path, *, label: str) -> bytes: ...


class ReplayVerificationReceipt(StrictModel):
    """Persisted proof that replay artifacts were sealed and verified."""

    api_version: Literal[
        "pajin.dev/replay-verification-receipt/v1",
        "pajin.dev/replay-verification-receipt/v2",
    ] = Field(
        default="pajin.dev/replay-verification-receipt/v2",
        alias="apiVersion",
    )
    ticket_id: str
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_source_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    replay_run_id: str
    artifact_set_path: str
    artifact_set_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    ticket_context: ReplayTicketContext | None = Field(default=None, alias="ticketContext")
    verified_at: datetime

    @model_validator(mode="after")
    def validate_versioned_ticket_context(self) -> ReplayVerificationReceipt:
        if self.api_version == _REPLAY_RECEIPT_V2:
            if self.ticket_context is None:
                raise ValueError("v2 replay receipt requires its complete ticket context")
            if (
                self.ticket_context.candidate_source_root_digest
                != self.candidate_source_root_digest
            ):
                raise ValueError("replay receipt ticket context differs from its source seal")
        elif self.ticket_context is not None:
            raise ValueError("legacy v1 replay receipt cannot contain v2 ticket context")
        return self


class VerifiedReplayResult(StrictModel):
    """Verified snapshot; confirmation gates must reload it from the sealed Run."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    artifact_set: ReplayArtifactSet
    receipt: ReplayVerificationReceipt
    verification: RunIntegrityVerification
    receipt_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    run_path: Path


@dataclass(frozen=True, slots=True)
class _SealedReplayArtifacts:
    artifact_set: ReplayArtifactSet
    receipt: ReplayVerificationReceipt
    verification: RunIntegrityVerification
    receipt_seal_root_digest: str
    run_path: Path


def load_verified_replay_result(
    run_path: Path,
    *,
    tickets: ReplayTicketFinalizationVerifier,
) -> VerifiedReplayResult:
    """Reload and cross-check replay artifacts, both seals, and ticket finalization."""

    return _load_verified_replay_result(
        run_path,
        tickets=tickets,
        reader=_read_regular_file_bytes,
    )


def _load_verified_replay_result(
    run_path: Path,
    *,
    tickets: ReplayTicketFinalizationVerifier,
    reader: ReplaySnapshotReader,
) -> VerifiedReplayResult:
    sealed = _load_sealed_replay_artifacts(run_path, reader=reader)
    receipt = sealed.receipt
    tickets.verify_finalized(
        receipt.ticket_id,
        final_seal_root_digest=sealed.receipt_seal_root_digest,
        artifact_set_digest=receipt.artifact_set_digest,
        compilation_digest=receipt.compilation_digest,
        candidate_source_root_digest=receipt.candidate_source_root_digest,
        replay_run_id=receipt.replay_run_id,
    )
    return _verified_replay_result(sealed)


def inspect_sealed_replay_result(run_path: Path) -> VerifiedReplayResult:
    """Read and fully verify sealed output without trusting or mutating ticket state.

    Durable authorities use this before their own atomic finalization transition.
    The returned result is derived exclusively from the sealed Run tree.
    """

    return _inspect_sealed_replay_result(run_path, reader=_read_regular_file_bytes)


def _inspect_sealed_replay_result(
    run_path: Path,
    *,
    reader: ReplaySnapshotReader,
) -> VerifiedReplayResult:
    return _verified_replay_result(_load_sealed_replay_artifacts(run_path, reader=reader))


def recover_verified_replay_result(
    run_path: Path,
    *,
    tickets: ReplayTicketClaimer,
    recovered_at: datetime | None = None,
) -> VerifiedReplayResult:
    """Recover a claimed ticket only from an exact, complete v2 sealed replay receipt."""

    return _recover_verified_replay_result(
        run_path,
        tickets=tickets,
        recovered_at=recovered_at,
        reader=_read_regular_file_bytes,
    )


def _recover_verified_replay_result(
    run_path: Path,
    *,
    tickets: ReplayTicketClaimer,
    recovered_at: datetime | None,
    reader: ReplaySnapshotReader,
) -> VerifiedReplayResult:
    sealed = _load_sealed_replay_artifacts(run_path, reader=reader)
    receipt = sealed.receipt
    if receipt.api_version != _REPLAY_RECEIPT_V2 or receipt.ticket_context is None:
        raise ValueError("replay finalization recovery requires a v2 receipt context")
    if sealed.verification.root_digest != sealed.receipt_seal_root_digest:
        raise ValueError("replay finalization recovery requires the receipt seal to be final")
    recovery_time = recovered_at or datetime.now(UTC)
    if recovery_time.tzinfo is None or recovery_time.utcoffset() is None:
        raise ValueError("replay recovery time must include a UTC offset or Z")
    tickets.recover_finalization(
        ReplayExecutionTicket(receipt.ticket_id),
        final_seal_root_digest=sealed.receipt_seal_root_digest,
        artifact_set_digest=receipt.artifact_set_digest,
        compilation_digest=receipt.compilation_digest,
        context=receipt.ticket_context,
        replay_run_id=receipt.replay_run_id,
        finalized_at=recovery_time.astimezone(UTC),
    )
    return _load_verified_replay_result(
        sealed.run_path,
        tickets=tickets,
        reader=reader,
    )


def _verified_replay_result(sealed: _SealedReplayArtifacts) -> VerifiedReplayResult:
    return VerifiedReplayResult(
        artifact_set=sealed.artifact_set,
        receipt=sealed.receipt,
        verification=sealed.verification,
        receipt_seal_root_digest=sealed.receipt_seal_root_digest,
        run_path=sealed.run_path,
    )


def _load_sealed_replay_artifacts(
    run_path: Path,
    *,
    reader: ReplaySnapshotReader,
) -> _SealedReplayArtifacts:
    """Validate sealed replay artifacts without changing ticket authority state."""

    root = run_path.resolve()
    with locked_run_snapshot(root):
        return _load_locked_replay_artifacts(root, reader=reader)


def _load_locked_replay_artifacts(
    root: Path,
    *,
    reader: ReplaySnapshotReader,
) -> _SealedReplayArtifacts:
    """Load one replay snapshot while cooperative Run writers are excluded."""

    verification = verify_run_integrity(root)
    artifact_relative = "replay/artifact-set.json"
    receipt_relative = "replay/verification-receipt.json"
    compilation_relative = "replay/compilation.json"
    artifact_path = root / artifact_relative
    receipt_path = root / receipt_relative
    compilation_path = root / compilation_relative
    try:
        artifact_bytes = reader(root, artifact_path, label="artifact set")
        receipt_bytes = reader(root, receipt_path, label="verification receipt")
        compilation_bytes = reader(root, compilation_path, label="compilation")
        integrity_bytes = reader(
            root,
            root / "run-integrity.jsonl",
            label="integrity log",
        )
        receipt_payload = parse_strict_json_bytes(
            receipt_bytes,
            label="sealed replay verification receipt",
            max_bytes=MAX_REPLAY_SNAPSHOT_FILE_BYTES,
        )
        artifact_payload = parse_strict_json_bytes(
            artifact_bytes,
            label="sealed replay artifact set",
            max_bytes=MAX_REPLAY_SNAPSHOT_FILE_BYTES,
        )
        compilation_payload = parse_strict_json_bytes(
            compilation_bytes,
            label="sealed replay compilation",
            max_bytes=MAX_REPLAY_SNAPSHOT_FILE_BYTES,
        )
        receipt = ReplayVerificationReceipt.model_validate(receipt_payload)
        artifact_set = (
            load_legacy_v1_replay_artifact_set(artifact_bytes)
            if receipt.api_version == _REPLAY_RECEIPT_V1
            else ReplayArtifactSet.model_validate(artifact_payload)
        )
        if not isinstance(compilation_payload, dict):
            raise ValueError("sealed replay compilation must be a JSON object")
        # Digest the sealed wire object before Pydantic supplies defaults. This keeps
        # v1 confirmation artifacts verifiable when newer readers add default fields,
        # while the separate typed parse below still enforces the current contract.
        compilation_digest = replay_context_digest(compilation_payload)
        seals = [
            RunIntegritySeal.model_validate(
                parse_strict_json_bytes(
                    line.encode("utf-8"),
                    label="sealed replay integrity record",
                    max_bytes=MAX_REPLAY_SNAPSHOT_FILE_BYTES,
                )
            )
            for line in integrity_bytes.decode("utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("sealed replay receipt artifacts could not be loaded") from exc

    artifact_digest = sha256(artifact_bytes).hexdigest()
    compilation = _validated_sealed_compilation(
        compilation_payload,
        receipt=receipt,
        wire_digest=compilation_digest,
    )
    actual_artifact_binding = (
        receipt.replay_run_id,
        artifact_set.outcome.binding.replay_run_id,
        receipt.artifact_set_path,
        receipt.artifact_set_digest,
        artifact_set.validation_packet,
        artifact_set.contract,
        artifact_set.intent,
        artifact_set.spec,
    )
    expected_artifact_binding = (
        verification.run_id,
        verification.run_id,
        artifact_relative,
        artifact_digest,
        compilation.validation_packet,
        compilation.contract,
        compilation.intent,
        compilation.spec,
    )
    if actual_artifact_binding != expected_artifact_binding:
        raise ValueError("sealed replay receipt does not match its canonical artifacts")
    loaded_artifact_bytes = {
        artifact_relative: artifact_bytes,
        receipt_relative: receipt_bytes,
        compilation_relative: compilation_bytes,
    }
    _validate_materialized_evidence(
        root,
        artifact_set,
        loaded_artifact_bytes=loaded_artifact_bytes,
        reader=reader,
    )

    artifact_seal_index = next(
        (
            index
            for index, seal in enumerate(seals)
            if seal.root_digest == receipt.artifact_seal_root_digest
        ),
        None,
    )
    if artifact_seal_index is None or artifact_seal_index + 1 >= len(seals):
        raise ValueError("replay artifact seal is missing its receipt extension")
    artifact_record = next(
        (
            artifact
            for seal in seals[: artifact_seal_index + 1]
            for artifact in seal.artifacts
            if artifact.path == artifact_relative
        ),
        None,
    )
    receipt_seal = seals[artifact_seal_index + 1]
    direct_extension = (
        artifact_record.sha256 if artifact_record is not None else None,
        receipt_seal.previous_root_digest,
        receipt_relative in {artifact.path for artifact in receipt_seal.artifacts},
    )
    if direct_extension != (artifact_digest, receipt.artifact_seal_root_digest, True):
        raise ValueError("replay receipt is not the direct sealed extension of its artifact set")

    final_verification = verify_run_integrity(root)
    final_integrity_bytes = reader(
        root,
        root / "run-integrity.jsonl",
        label="final integrity log",
    )
    if final_verification != verification or final_integrity_bytes != integrity_bytes:
        raise ValueError("sealed replay Run changed while its read snapshot was loaded")
    _validate_loaded_seal_snapshot(seals, final_verification)
    _validate_loaded_artifact_bytes(seals, loaded_artifact_bytes)

    return _SealedReplayArtifacts(
        artifact_set=artifact_set,
        receipt=receipt,
        verification=final_verification,
        receipt_seal_root_digest=receipt_seal.root_digest,
        run_path=root,
    )


def _read_regular_file_bytes(root: Path, path: Path, *, label: str) -> bytes:
    """Read one bounded-identity regular file from the locked Run snapshot."""

    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"sealed replay {label} escapes the Run root") from exc
    try:
        return read_bounded_regular_bytes(
            path,
            max_bytes=MAX_REPLAY_SNAPSHOT_FILE_BYTES,
            label=f"sealed replay {label}",
            require_single_link=True,
        )
    except (OSError, ValueError) as exc:
        raise ValueError(f"sealed replay {label} could not be read as a regular file") from exc


def _validate_loaded_seal_snapshot(
    seals: list[RunIntegritySeal],
    verification: RunIntegrityVerification,
) -> None:
    """Bind the exact integrity-log bytes read by the loader to final verification."""

    previous_root: str | None = None
    artifact_paths: set[str] = set()
    for expected_sequence, seal in enumerate(seals, start=1):
        if (
            seal.api_version != "pajin.dev/run-integrity/v1"
            or seal.run_id != verification.run_id
            or seal.sequence != expected_sequence
            or seal.previous_root_digest != previous_root
            or seal.artifacts != sorted(seal.artifacts, key=lambda item: item.path)
            or seal.artifact_root_digest != seal.computed_artifact_root_digest()
            or seal.root_digest != seal.computed_root_digest()
        ):
            raise ValueError("loaded replay integrity snapshot is not a valid seal chain")
        for artifact in seal.artifacts:
            if artifact.path in artifact_paths:
                raise ValueError("loaded replay integrity snapshot repeats an artifact path")
            artifact_paths.add(artifact.path)
        previous_root = seal.root_digest
    if not seals or (
        len(seals),
        len(artifact_paths),
        seals[-1].event_count,
        seals[-1].root_digest,
    ) != (
        verification.seal_count,
        verification.artifact_count,
        verification.event_count,
        verification.root_digest,
    ):
        raise ValueError("loaded replay integrity snapshot differs from final verification")


def _validate_loaded_artifact_bytes(
    seals: list[RunIntegritySeal],
    loaded_artifact_bytes: Mapping[str, bytes],
) -> None:
    records = {artifact.path: artifact for seal in seals for artifact in seal.artifacts}
    for relative_path, content in loaded_artifact_bytes.items():
        record = records.get(relative_path)
        if (
            record is None
            or record.size_bytes != len(content)
            or record.sha256 != sha256(content).hexdigest()
        ):
            raise ValueError("loaded replay snapshot bytes differ from their final seal records")


def _validated_sealed_compilation(
    payload: dict[str, object],
    *,
    receipt: ReplayVerificationReceipt,
    wire_digest: str,
) -> ReplayCompilation:
    try:
        compilation = ReplayCompilation.model_validate(payload)
    except ValueError as exc:
        raise ValueError("sealed replay compilation could not be validated") from exc
    if receipt.compilation_digest == wire_digest:
        return compilation
    # Compatibility for already-sealed v1 artifacts written before compilation set
    # fields shared one deterministic serializer. Semantic comparisons remain mandatory.
    compatible_digests = {
        replay_context_digest(compilation.model_dump(mode="json", by_alias=True)),
        replay_context_digest(compilation),
        replay_context_digest(canonicalize_replay_compilation_wire_sets(payload)),
    }
    if receipt.compilation_digest not in compatible_digests:
        raise ValueError("sealed replay receipt does not match its canonical compilation")
    return compilation


def _validate_materialized_evidence(
    root: Path,
    artifact_set: ReplayArtifactSet,
    *,
    loaded_artifact_bytes: dict[str, bytes],
    reader: ReplaySnapshotReader,
) -> None:
    """Rebind sealed fresh-session records to the exact Gateway request evidence."""

    for attempt in artifact_set.outcome.attempts:
        materialization = attempt.materialization
        if not attempt.evidence:
            continue
        expected_reference = f"evidence/{attempt.replay_request_id}.json"
        if attempt.evidence != [expected_reference]:
            raise ValueError("materialized replay evidence lineage is not exact")
        evidence_path = root / expected_reference
        try:
            evidence_bytes = reader(root, evidence_path, label="materialized evidence")
            payload = parse_strict_json_bytes(
                evidence_bytes,
                label="sealed replay materialized evidence",
                max_bytes=MAX_REPLAY_SNAPSHOT_FILE_BYTES,
            )
        except (UnicodeError, ValueError) as exc:
            raise ValueError("materialized replay evidence could not be loaded") from exc
        previous = loaded_artifact_bytes.setdefault(expected_reference, evidence_bytes)
        if previous != evidence_bytes:
            raise ValueError("materialized replay evidence changed within the read snapshot")
        request = payload.get("request") if isinstance(payload, dict) else None
        if not isinstance(request, dict) or request.get("request_id") != attempt.replay_request_id:
            raise ValueError("materialized replay evidence does not match its sealed request")
        if materialization is not None and (
            request.get("arguments") != materialization.arguments
            or replay_argument_digest(materialization.arguments) != materialization.argument_digest
        ):
            raise ValueError("materialized replay evidence does not match its sealed request")
