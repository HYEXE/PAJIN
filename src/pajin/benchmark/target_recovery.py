"""Durable P0-C2A provider-operation fencing and Target cleanup recovery."""

from __future__ import annotations

import os
import sqlite3
from abc import abstractmethod
from collections.abc import Awaitable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.measurement import WalkingBenchmarkRunObservation
from pajin.benchmark.models import BenchmarkManifest, benchmark_digest
from pajin.benchmark.target_factory import (
    BenchmarkMeasurementAttestation,
    BenchmarkMeasurementAttestationStatement,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkTargetCoordinate,
    BenchmarkTargetFactoryRunner,
    BenchmarkTargetRunOutcome,
    BenchmarkTargetStage,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
    benchmark_target_coordinate,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

BENCHMARK_TARGET_OPERATION_API_VERSION: Literal["pajin.dev/benchmark-target-operation/v1alpha1"] = (
    "pajin.dev/benchmark-target-operation/v1alpha1"
)
BENCHMARK_TARGET_RECOVERY_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/benchmark-target-recovery-authority/v1alpha1"
] = "pajin.dev/benchmark-target-recovery-authority/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_RECOVERY_AUTHORITY_ARTIFACT = "benchmark-target-recovery-authority.json"
_MAX_RECOVERY_AUTHORITY_BYTES = 16 * 1024 * 1024
_BUSY_TIMEOUT_MS = 5_000
_Stage = Literal["reset", "isolation", "execution", "cleanup"]


class BenchmarkTargetRecoveryError(RuntimeError):
    """Raised when durable provider reconciliation cannot prove cleanup."""


class BenchmarkTargetAttempt(StrictModel):
    """Durable identity and monotonically fenced ownership of one coordinate attempt."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    attempt_id: str = Field(default="", alias="attemptId", max_length=110)
    attempt_digest: str = Field(default="", alias="attemptDigest", max_length=64)
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    coordinate_digest: _Sha256 = Field(alias="coordinateDigest")
    fence: int = Field(ge=1, le=2**63 - 1)
    started_at: datetime = Field(alias="startedAt")

    @field_validator("started_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark Target attempt timestamp requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_attempt(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"attempt_id", "attempt_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-attempt/v1",
            material,
            max_bytes=64 * 1024,
        )
        attempt_id = f"benchmark-target-attempt:{digest}"
        if self.attempt_digest and self.attempt_digest != digest:
            raise ValueError("Benchmark Target Attempt Digest differs")
        if self.attempt_id and self.attempt_id != attempt_id:
            raise ValueError("Benchmark Target Attempt ID differs")
        object.__setattr__(self, "attempt_digest", digest)
        object.__setattr__(self, "attempt_id", attempt_id)
        return self


class BenchmarkTargetOperation(StrictModel):
    """One provider call identity carrying an idempotency key and active fence."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-target-operation/v1alpha1"] = Field(
        default=BENCHMARK_TARGET_OPERATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetOperation"] = "BenchmarkTargetOperation"
    operation_id: str = Field(default="", alias="operationId", max_length=110)
    operation_digest: str = Field(default="", alias="operationDigest", max_length=64)
    attempt_id: str = Field(alias="attemptId", min_length=1, max_length=110)
    attempt_digest: _Sha256 = Field(alias="attemptDigest")
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    coordinate_digest: _Sha256 = Field(alias="coordinateDigest")
    fence: int = Field(ge=1, le=2**63 - 1)
    stage: Literal["reset", "isolation", "execution", "cleanup"]
    ordinal: int = Field(ge=1, le=10)

    @model_validator(mode="after")
    def bind_operation(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"operation_id", "operation_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-operation/v1",
            material,
            max_bytes=64 * 1024,
        )
        operation_id = f"benchmark-target-operation:{digest}"
        if self.operation_digest and self.operation_digest != digest:
            raise ValueError("Benchmark Target Operation Digest differs")
        if self.operation_id and self.operation_id != operation_id:
            raise ValueError("Benchmark Target Operation ID differs")
        object.__setattr__(self, "operation_digest", digest)
        object.__setattr__(self, "operation_id", operation_id)
        return self


class BenchmarkTargetOperationRecord(StrictModel):
    """Hash-chained intent, receipt, or provider-error entry from the durable journal."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    sequence: int = Field(ge=1, le=10_000)
    record_type: Literal["intent", "receipt", "provider-error"] = Field(alias="recordType")
    operation: BenchmarkTargetOperation
    receipt: BenchmarkTargetStageReceipt | None = None
    error_code: Literal["provider-exception"] | None = Field(default=None, alias="errorCode")
    occurred_at: datetime = Field(alias="occurredAt")
    previous_record_digest: _Sha256 | None = Field(default=None, alias="previousRecordDigest")
    record_digest: str = Field(default="", alias="recordDigest", max_length=64)

    @field_validator("occurred_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark Target journal timestamp requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_record(self) -> Self:
        if self.record_type == "receipt":
            if self.receipt is None or self.error_code is not None:
                raise ValueError("Receipt journal record requires only a receipt")
            if (
                self.receipt.operation_id != self.operation.operation_id
                or self.receipt.adapter_digest != self.operation.adapter_digest
                or self.receipt.coordinate_digest != self.operation.coordinate_digest
                or self.receipt.stage != self.operation.stage
            ):
                raise ValueError("Provider receipt differs from exact fenced operation")
        elif self.record_type == "provider-error":
            if self.receipt is not None or self.error_code != "provider-exception":
                raise ValueError("Provider-error journal record requires only a stable error code")
        elif self.receipt is not None or self.error_code is not None:
            raise ValueError("Intent journal record cannot contain a result")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"record_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-operation-record/v1",
            material,
            max_bytes=256 * 1024,
        )
        if self.record_digest and self.record_digest != digest:
            raise ValueError("Benchmark Target Operation Record Digest differs")
        object.__setattr__(self, "record_digest", digest)
        return self


class BenchmarkTargetRecoveryRequest(StrictModel):
    """Exact abandoned attempt and newly fenced cleanup request given to a provider."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    abandoned_attempt: BenchmarkTargetAttempt = Field(alias="abandonedAttempt")
    cleanup_operation: BenchmarkTargetOperation = Field(alias="cleanupOperation")
    known_isolation_receipt: BenchmarkTargetStageReceipt | None = Field(
        default=None,
        alias="knownIsolationReceipt",
    )

    @model_validator(mode="after")
    def bind_request(self) -> Self:
        operation = self.cleanup_operation
        attempt = self.abandoned_attempt
        if (
            operation.stage != BenchmarkTargetStage.CLEANUP
            or operation.attempt_id != attempt.attempt_id
            or operation.attempt_digest != attempt.attempt_digest
            or operation.adapter_digest != attempt.adapter_digest
            or operation.coordinate_digest != attempt.coordinate_digest
            or operation.fence <= attempt.fence
        ):
            raise ValueError("Recovery cleanup does not supersede the abandoned attempt")
        if self.known_isolation_receipt is not None and (
            self.known_isolation_receipt.stage != BenchmarkTargetStage.ISOLATION
            or self.known_isolation_receipt.adapter_digest != attempt.adapter_digest
            or self.known_isolation_receipt.coordinate_digest != attempt.coordinate_digest
        ):
            raise ValueError("Recovery isolation receipt differs from abandoned attempt")
        return self


class BenchmarkTargetRecoveryAuthority(StrictModel):
    """Sealed, measurement-ineligible proof of one interrupted lifecycle reconciliation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-target-recovery-authority/v1alpha1"] = Field(
        default=BENCHMARK_TARGET_RECOVERY_AUTHORITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetRecoveryAuthority"] = "BenchmarkTargetRecoveryAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    adapter: RegisteredBenchmarkTargetFactoryAdapter
    coordinate: BenchmarkTargetCoordinate
    abandoned_attempt: BenchmarkTargetAttempt = Field(alias="abandonedAttempt")
    journal_records: tuple[BenchmarkTargetOperationRecord, ...] = Field(alias="journalRecords")
    resolution_fence: int = Field(alias="resolutionFence", ge=1, le=2**63 - 1)
    cleanup_receipt: BenchmarkTargetStageReceipt | None = Field(
        default=None,
        alias="cleanupReceipt",
    )
    lifecycle_state: Literal["cleanup-reconciled", "cleanup-unresolved"] = Field(
        alias="lifecycleState"
    )
    failure_reason: Literal["attempt-not-journaled-complete"] = Field(
        default="attempt-not-journaled-complete",
        alias="failureReason",
    )
    measurement_admission_eligible: Literal[False] = Field(
        default=False,
        alias="measurementAdmissionEligible",
    )
    sealed_at: datetime = Field(alias="sealedAt")

    @field_validator("sealed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark Target recovery seal time requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        attempt = self.abandoned_attempt
        if (
            self.adapter.adapter_digest != attempt.adapter_digest
            or self.coordinate.coordinate_digest != attempt.coordinate_digest
            or not self.journal_records
        ):
            raise ValueError("Recovery Authority differs from abandoned attempt")
        cleanup_receipts = _validated_authority_journal(self)
        successful = tuple(receipt for receipt in cleanup_receipts if receipt.status == "succeeded")
        if self.lifecycle_state == "cleanup-reconciled":
            if (
                self.cleanup_receipt is None
                or not successful
                or self.cleanup_receipt != successful[-1]
                or self.cleanup_receipt != cleanup_receipts[-1]
            ):
                raise ValueError("Reconciled Recovery Authority requires exact successful cleanup")
        elif self.cleanup_receipt is not None or successful:
            raise ValueError("Unresolved Recovery Authority cannot claim successful cleanup")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-recovery-authority/v1",
            material,
            max_bytes=_MAX_RECOVERY_AUTHORITY_BYTES,
        )
        authority_id = f"benchmark-target-recovery:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Benchmark Target Recovery Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Benchmark Target Recovery Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def _validated_authority_journal(
    authority: BenchmarkTargetRecoveryAuthority,
) -> tuple[BenchmarkTargetStageReceipt, ...]:
    attempt = authority.abandoned_attempt
    previous: str | None = None
    intents: dict[str, BenchmarkTargetOperation] = {}
    completed_operations: set[str] = set()
    original_stage_indexes: list[int] = []
    stage_indexes = {"reset": 0, "isolation": 1, "execution": 2, "cleanup": 3}
    cleanup_receipts: list[BenchmarkTargetStageReceipt] = []
    for sequence, record in enumerate(authority.journal_records, start=1):
        operation = record.operation
        if (
            record.sequence != sequence
            or record.previous_record_digest != previous
            or operation.attempt_id != attempt.attempt_id
            or operation.attempt_digest != attempt.attempt_digest
            or operation.adapter_digest != attempt.adapter_digest
            or operation.coordinate_digest != attempt.coordinate_digest
            or operation.fence > authority.resolution_fence
        ):
            raise ValueError("Recovery Authority journal chain differs")
        if operation.fence < attempt.fence or (
            operation.fence > attempt.fence and operation.stage != BenchmarkTargetStage.CLEANUP
        ):
            raise ValueError("Recovery Authority contains an invalid fenced stage")
        if operation.fence == attempt.fence and record.record_type == "intent":
            original_stage_indexes.append(stage_indexes[operation.stage])
        if record.record_type == "intent":
            if operation.operation_id in intents:
                raise ValueError("Recovery Authority repeats an operation intent")
            intents[operation.operation_id] = operation
        elif (
            intents.get(operation.operation_id) != operation
            or operation.operation_id in completed_operations
        ):
            raise ValueError("Recovery Authority result lacks one exact prior intent")
        else:
            completed_operations.add(operation.operation_id)
        if record.record_type == "receipt" and operation.stage == BenchmarkTargetStage.CLEANUP:
            cleanup_receipts.append(cast(BenchmarkTargetStageReceipt, record.receipt))
        previous = record.record_digest
    if original_stage_indexes != list(range(len(original_stage_indexes))):
        raise ValueError("Recovery Authority original lifecycle order differs")
    if authority.resolution_fence != max(
        record.operation.fence for record in authority.journal_records
    ):
        raise ValueError("Recovery Authority resolution fence differs from journal head")
    return tuple(cleanup_receipts)


class RecoverableBenchmarkTargetFactoryAdapter(Protocol):
    """Provider adapter that must enforce operation idempotency and monotonically newer fences."""

    @property
    @abstractmethod
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        """Return the exact non-secret adapter definition."""

    @abstractmethod
    async def reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        """Reset with an idempotency key and provider-enforced fence."""

    @abstractmethod
    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        """Create isolation under the same fenced attempt."""

    @abstractmethod
    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        """Execute the measured arm under the same fenced attempt."""

    @abstractmethod
    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        """Clean up the live attempt idempotently."""

    @abstractmethod
    async def reconcile_cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        request: BenchmarkTargetRecoveryRequest,
    ) -> BenchmarkTargetStageReceipt:
        """Discover and clean abandoned resources, including when isolation is not journaled."""

    @abstractmethod
    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        """Sign a completed lifecycle using the external authority."""


class BenchmarkTargetOperationJournal:
    """SQLite intent-before-call journal with transactional fence issuance."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        _initialize_journal(self.path)

    @classmethod
    def open_existing(cls, path: Path) -> BenchmarkTargetOperationJournal:
        """Open an existing journal without creating or mutating its schema."""

        resolved = Path(os.path.abspath(path))
        if not resolved.exists():
            raise BenchmarkTargetRecoveryError("Target operation journal is absent")
        _require_safe_journal_path(resolved)
        _require_safe_journal_sidecars(resolved)
        try:
            with _readonly_connection(resolved) as connection:
                tables = {
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    ).fetchall()
                }
                if not {"fences", "attempts", "records"}.issubset(tables):
                    raise BenchmarkTargetRecoveryError(
                        "Target operation journal schema is incomplete"
                    )
        except sqlite3.Error as exc:
            raise BenchmarkTargetRecoveryError(
                "Target operation journal could not be opened read-only"
            ) from exc
        journal = object.__new__(cls)
        journal.path = resolved
        return journal

    def begin_attempt(
        self,
        adapter: RegisteredBenchmarkTargetFactoryAdapter,
        coordinate: BenchmarkTargetCoordinate,
    ) -> BenchmarkTargetAttempt:
        scope = _scope_digest(adapter.adapter_digest, coordinate.coordinate_digest)
        with _write_transaction(self.path) as connection:
            pending = connection.execute(
                "SELECT attempt_id FROM attempts WHERE scope_digest = ? AND state = 'open'",
                (scope,),
            ).fetchone()
            if pending is not None:
                raise BenchmarkTargetRecoveryError(
                    "Abandoned Benchmark Target attempt must be reconciled before a new run"
                )
            fence = _next_fence(connection, scope)
            attempt = BenchmarkTargetAttempt(
                adapterDigest=adapter.adapter_digest,
                coordinateDigest=coordinate.coordinate_digest,
                fence=fence,
                startedAt=datetime.now(UTC),
            )
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, scope_digest, fence, attempt_json, adapter_json,
                    coordinate_json, state, active_recovery_fence
                ) VALUES (?, ?, ?, ?, ?, ?, 'open', NULL)
                """,
                (
                    attempt.attempt_id,
                    scope,
                    fence,
                    attempt.model_dump_json(by_alias=True),
                    adapter.model_dump_json(by_alias=True),
                    coordinate.model_dump_json(by_alias=True),
                ),
            )
        return attempt

    def append_intent(self, operation: BenchmarkTargetOperation) -> None:
        self._append_record(operation, record_type="intent")

    def append_receipt(
        self,
        operation: BenchmarkTargetOperation,
        receipt: BenchmarkTargetStageReceipt,
    ) -> None:
        self._append_record(operation, record_type="receipt", receipt=receipt)

    def append_provider_error(self, operation: BenchmarkTargetOperation) -> None:
        self._append_record(
            operation,
            record_type="provider-error",
            error_code="provider-exception",
        )

    def pending(
        self,
    ) -> tuple[
        tuple[
            RegisteredBenchmarkTargetFactoryAdapter,
            BenchmarkTargetCoordinate,
            BenchmarkTargetAttempt,
            tuple[BenchmarkTargetOperationRecord, ...],
        ],
        ...,
    ]:
        with _readonly_connection(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM attempts WHERE state = 'open' ORDER BY rowid"
            ).fetchall()
            return tuple(self._attempt_snapshot(connection, row) for row in rows)

    def current_open_attempt(
        self,
        attempt_id: str,
    ) -> tuple[
        RegisteredBenchmarkTargetFactoryAdapter,
        BenchmarkTargetCoordinate,
        BenchmarkTargetAttempt,
        int,
        tuple[BenchmarkTargetOperationRecord, ...],
    ]:
        """Read one authoritative open attempt, including its current effective fence."""

        with _readonly_connection(self.path) as connection:
            row = _required_open_attempt(connection, attempt_id)
            adapter, coordinate, attempt, records = self._attempt_snapshot(connection, row)
            recovery_fence = row["active_recovery_fence"]
            if recovery_fence is not None and type(recovery_fence) is not int:
                raise BenchmarkTargetRecoveryError("Journal recovery fence is not canonical")
            stored_fence = row["fence"]
            if type(stored_fence) is not int:
                raise BenchmarkTargetRecoveryError("Journal attempt fence is not canonical")
            active_fence = recovery_fence if recovery_fence is not None else stored_fence
            return adapter, coordinate, attempt, active_fence, records

    def completed_attempt_for_operation(
        self,
        operation_id: str,
    ) -> tuple[
        RegisteredBenchmarkTargetFactoryAdapter,
        BenchmarkTargetCoordinate,
        BenchmarkTargetAttempt,
        tuple[BenchmarkTargetOperationRecord, ...],
    ]:
        """Read the one completed durable attempt containing an exact provider operation."""

        if (
            not isinstance(operation_id, str)
            or not operation_id
            or len(operation_id) > 110
            or operation_id.strip() != operation_id
        ):
            raise BenchmarkTargetRecoveryError("Target operation identity is invalid")
        matches: list[
            tuple[
                RegisteredBenchmarkTargetFactoryAdapter,
                BenchmarkTargetCoordinate,
                BenchmarkTargetAttempt,
                tuple[BenchmarkTargetOperationRecord, ...],
            ]
        ] = []
        with _readonly_connection(self.path) as connection:
            rows = connection.execute(
                "SELECT * FROM attempts WHERE state = 'completed' ORDER BY rowid"
            ).fetchall()
            for row in rows:
                adapter, coordinate, attempt, records = self._attempt_snapshot(connection, row)
                if not any(record.operation.operation_id == operation_id for record in records):
                    continue
                recovery_fence = row["active_recovery_fence"]
                stored_fence = row["fence"]
                if (
                    recovery_fence is not None
                    or type(stored_fence) is not int
                    or stored_fence != attempt.fence
                ):
                    raise BenchmarkTargetRecoveryError(
                        "Completed Target attempt fence is not canonical"
                    )
                matches.append((adapter, coordinate, attempt, records))
        if len(matches) != 1:
            raise BenchmarkTargetRecoveryError(
                "Completed Target attempt for operation is absent or ambiguous"
            )
        return matches[0]

    def latest_scope_fence(self, *, adapter_digest: str, coordinate_digest: str) -> int:
        """Read the latest fence ever issued for one exact adapter-coordinate scope."""

        scope = _scope_digest(adapter_digest, coordinate_digest)
        with _readonly_connection(self.path) as connection:
            row = connection.execute(
                "SELECT value FROM fences WHERE scope_digest = ?",
                (scope,),
            ).fetchone()
            if row is None or len(row) != 1 or type(row[0]) is not int or row[0] < 1:
                raise BenchmarkTargetRecoveryError(
                    "Target operation scope fence is absent or noncanonical"
                )
            return row[0]

    def claim_recovery(self, attempt: BenchmarkTargetAttempt) -> int:
        scope = _scope_digest(attempt.adapter_digest, attempt.coordinate_digest)
        with _write_transaction(self.path) as connection:
            row = _required_open_attempt(connection, attempt.attempt_id)
            if int(row["fence"]) != attempt.fence:
                raise BenchmarkTargetRecoveryError("Journal attempt fence differs")
            fence = _next_fence(connection, scope)
            connection.execute(
                "UPDATE attempts SET active_recovery_fence = ? WHERE attempt_id = ?",
                (fence, attempt.attempt_id),
            )
        return fence

    def mark_reconciled(self, attempt_id: str, *, resolution_fence: int) -> None:
        with _write_transaction(self.path) as connection:
            row = _required_open_attempt(connection, attempt_id)
            active = row["active_recovery_fence"]
            if active is not None and int(active) != resolution_fence:
                raise BenchmarkTargetRecoveryError("Stale recovery fence cannot close attempt")
            if active is None and int(row["fence"]) != resolution_fence:
                raise BenchmarkTargetRecoveryError("Resolution fence differs from attempt")
            connection.execute(
                "UPDATE attempts SET state = 'reconciled' WHERE attempt_id = ?",
                (attempt_id,),
            )

    def mark_completed(self, attempt_id: str) -> None:
        with _write_transaction(self.path) as connection:
            _required_open_attempt(connection, attempt_id)
            connection.execute(
                "UPDATE attempts SET state = 'completed' WHERE attempt_id = ?",
                (attempt_id,),
            )

    def _append_record(
        self,
        operation: BenchmarkTargetOperation,
        *,
        record_type: Literal["intent", "receipt", "provider-error"],
        receipt: BenchmarkTargetStageReceipt | None = None,
        error_code: Literal["provider-exception"] | None = None,
    ) -> None:
        with _write_transaction(self.path) as connection:
            row = _required_open_attempt(connection, operation.attempt_id)
            attempt = BenchmarkTargetAttempt.model_validate_json(str(row["attempt_json"]))
            active_recovery_fence = row["active_recovery_fence"]
            expected_fence = (
                int(active_recovery_fence)
                if active_recovery_fence is not None
                else int(row["fence"])
            )
            if (
                str(row["adapter_json"]) == ""
                or operation.fence != expected_fence
                or operation.attempt_digest != attempt.attempt_digest
                or operation.adapter_digest != attempt.adapter_digest
                or operation.coordinate_digest != attempt.coordinate_digest
            ):
                raise BenchmarkTargetRecoveryError(
                    "Stale or foreign operation cannot mutate journal"
                )
            prior = connection.execute(
                """
                SELECT record_json FROM records
                WHERE attempt_id = ? ORDER BY sequence DESC LIMIT 1
                """,
                (operation.attempt_id,),
            ).fetchone()
            previous = (
                BenchmarkTargetOperationRecord.model_validate_json(str(prior[0])).record_digest
                if prior is not None
                else None
            )
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM records WHERE attempt_id = ?",
                    (operation.attempt_id,),
                ).fetchone()[0]
            )
            record = BenchmarkTargetOperationRecord(
                sequence=sequence,
                recordType=record_type,
                operation=operation,
                receipt=receipt,
                errorCode=error_code,
                occurredAt=datetime.now(UTC),
                previousRecordDigest=previous,
            )
            connection.execute(
                "INSERT INTO records(attempt_id, sequence, record_json) VALUES (?, ?, ?)",
                (operation.attempt_id, sequence, record.model_dump_json(by_alias=True)),
            )

    @staticmethod
    def _attempt_snapshot(
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> tuple[
        RegisteredBenchmarkTargetFactoryAdapter,
        BenchmarkTargetCoordinate,
        BenchmarkTargetAttempt,
        tuple[BenchmarkTargetOperationRecord, ...],
    ]:
        adapter_json = str(row["adapter_json"])
        coordinate_json = str(row["coordinate_json"])
        attempt_json = str(row["attempt_json"])
        stored_fence = row["fence"]
        active_recovery_fence = row["active_recovery_fence"]
        adapter = RegisteredBenchmarkTargetFactoryAdapter.model_validate_json(adapter_json)
        coordinate = BenchmarkTargetCoordinate.model_validate_json(coordinate_json)
        attempt = BenchmarkTargetAttempt.model_validate_json(attempt_json)
        if (
            adapter_json != adapter.model_dump_json(by_alias=True)
            or coordinate_json != coordinate.model_dump_json(by_alias=True)
            or attempt_json != attempt.model_dump_json(by_alias=True)
            or attempt.attempt_id != str(row["attempt_id"])
            or attempt.adapter_digest != adapter.adapter_digest
            or attempt.coordinate_digest != coordinate.coordinate_digest
            or type(stored_fence) is not int
            or attempt.fence != stored_fence
            or (
                active_recovery_fence is not None
                and (
                    type(active_recovery_fence) is not int or active_recovery_fence <= stored_fence
                )
            )
        ):
            raise BenchmarkTargetRecoveryError("Journal attempt identity differs")
        record_jsons = tuple(
            str(item[0])
            for item in connection.execute(
                "SELECT record_json FROM records WHERE attempt_id = ? ORDER BY sequence",
                (attempt.attempt_id,),
            ).fetchall()
        )
        records = tuple(
            BenchmarkTargetOperationRecord.model_validate_json(raw) for raw in record_jsons
        )
        if any(
            raw != record.model_dump_json(by_alias=True)
            for raw, record in zip(record_jsons, records, strict=True)
        ):
            raise BenchmarkTargetRecoveryError("Journal record wire is not canonical")
        _require_record_chain(records)
        highest_allowed_fence = (
            stored_fence if active_recovery_fence is None else active_recovery_fence
        )
        if any(
            record.operation.attempt_id != attempt.attempt_id
            or record.operation.attempt_digest != attempt.attempt_digest
            or record.operation.adapter_digest != adapter.adapter_digest
            or record.operation.coordinate_digest != coordinate.coordinate_digest
            or not stored_fence <= record.operation.fence <= highest_allowed_fence
            for record in records
        ):
            raise BenchmarkTargetRecoveryError(
                "Journal record operation differs from its durable attempt"
            )
        return adapter, coordinate, attempt, records


class _JournaledAdapter:
    def __init__(
        self,
        provider: RecoverableBenchmarkTargetFactoryAdapter,
        journal: BenchmarkTargetOperationJournal,
    ) -> None:
        self._provider = provider
        self._journal = journal
        self._attempt: BenchmarkTargetAttempt | None = None

    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        return self._provider.definition

    @property
    def attempt(self) -> BenchmarkTargetAttempt:
        if self._attempt is None:
            raise BenchmarkTargetRecoveryError("Target attempt has not started")
        return self._attempt

    async def reset(self, coordinate: BenchmarkTargetCoordinate) -> BenchmarkTargetStageReceipt:
        self._attempt = self._journal.begin_attempt(self.definition, coordinate)
        operation = _operation(self.attempt, "reset")
        return await self._receipt_call(operation, self._provider.reset(coordinate, operation))

    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
    ) -> BenchmarkTargetStageReceipt:
        operation = _operation(self.attempt, "isolation")
        return await self._receipt_call(
            operation,
            self._provider.establish_isolation(coordinate, reset, operation),
        )

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        operation = _operation(self.attempt, "execution")
        self._journal.append_intent(operation)
        try:
            receipt, observation = await self._provider.execute(coordinate, isolation, operation)
            canonical = BenchmarkTargetStageReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
            )
            self._journal.append_receipt(operation, canonical)
            return canonical, observation
        except Exception:
            self._journal.append_provider_error(operation)
            raise

    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
    ) -> BenchmarkTargetStageReceipt:
        operation = _operation(self.attempt, "cleanup")
        return await self._receipt_call(
            operation,
            self._provider.cleanup(coordinate, isolation, operation),
        )

    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        return await self._provider.attest(statement)

    async def _receipt_call(
        self,
        operation: BenchmarkTargetOperation,
        call: Awaitable[BenchmarkTargetStageReceipt],
    ) -> BenchmarkTargetStageReceipt:
        self._journal.append_intent(operation)
        try:
            receipt = await call
            canonical = BenchmarkTargetStageReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
            )
            self._journal.append_receipt(operation, canonical)
            return canonical
        except Exception:
            self._journal.append_provider_error(operation)
            raise


class RecoverableBenchmarkTargetFactoryRunner:
    """Reconcile every abandoned provider attempt before running a new P0-C1 coordinate."""

    def __init__(
        self,
        *,
        output_root: Path,
        journal_path: Path,
        adapter: RecoverableBenchmarkTargetFactoryAdapter,
        trust_anchor: BenchmarkMeasurementTrustAnchor,
        cleanup_retry_limit: int = 3,
    ) -> None:
        if not 1 <= cleanup_retry_limit <= 10:
            raise ValueError("Benchmark cleanup retry limit must be between 1 and 10")
        self._output_root = output_root
        self._provider = adapter
        self._trust_anchor = trust_anchor
        self._journal = BenchmarkTargetOperationJournal(journal_path)
        self._cleanup_retry_limit = cleanup_retry_limit

    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        """Expose the provider identity for additive preflight policy wrappers."""

        return self._provider.definition

    async def reconcile_pending(self) -> tuple[Path, ...]:
        """Fence and reconcile all unfinished attempts before admitting new work."""

        outcomes: list[Path] = []
        for adapter, coordinate, attempt, initial_records in self._journal.pending():
            if adapter != self._provider.definition:
                raise BenchmarkTargetRecoveryError(
                    "Pending Target attempt belongs to a different provider adapter"
                )
            records = initial_records
            successful = _successful_cleanup(records)
            resolution_fence = attempt.fence
            if successful is None:
                resolution_fence = self._journal.claim_recovery(attempt)
                known_isolation = _latest_receipt(records, BenchmarkTargetStage.ISOLATION)
                for ordinal in range(1, self._cleanup_retry_limit + 1):
                    operation = _operation(
                        attempt,
                        "cleanup",
                        fence=resolution_fence,
                        ordinal=ordinal,
                    )
                    request = BenchmarkTargetRecoveryRequest(
                        abandonedAttempt=attempt,
                        cleanupOperation=operation,
                        knownIsolationReceipt=known_isolation,
                    )
                    self._journal.append_intent(operation)
                    try:
                        raw = await self._provider.reconcile_cleanup(coordinate, request)
                        receipt = BenchmarkTargetStageReceipt.model_validate(
                            raw.model_dump(mode="json", by_alias=True)
                        )
                        _require_recovery_receipt(request, receipt)
                        self._journal.append_receipt(operation, receipt)
                    except Exception:
                        self._journal.append_provider_error(operation)
                        continue
                    if receipt.status == "succeeded":
                        successful = receipt
                        break
                current = next(
                    item
                    for item in self._journal.pending()
                    if item[2].attempt_id == attempt.attempt_id
                )
                records = current[3]
            state: Literal["cleanup-reconciled", "cleanup-unresolved"] = (
                "cleanup-reconciled" if successful is not None else "cleanup-unresolved"
            )
            authority = BenchmarkTargetRecoveryAuthority(
                adapter=adapter,
                coordinate=coordinate,
                abandonedAttempt=attempt,
                journalRecords=records,
                resolutionFence=resolution_fence,
                cleanupReceipt=successful,
                lifecycleState=state,
                sealedAt=datetime.now(UTC),
            )
            outcomes.append(_seal_recovery_authority(self._output_root, authority))
            if successful is None:
                raise BenchmarkTargetRecoveryError(
                    "Abandoned Benchmark Target cleanup remains unresolved; new work is fenced"
                )
            self._journal.mark_reconciled(
                attempt.attempt_id,
                resolution_fence=resolution_fence,
            )
        return tuple(outcomes)

    async def run(
        self,
        manifest: BenchmarkManifest,
        *,
        arm_id: str,
        seed: int,
        repetition: int,
    ) -> BenchmarkTargetRunOutcome:
        await self.reconcile_pending()
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        coordinate = benchmark_target_coordinate(
            authoritative_manifest,
            arm_id=arm_id,
            seed=seed,
            repetition=repetition,
        )
        if coordinate.coordinate_digest == "":
            raise AssertionError("Benchmark coordinate digest was not bound")
        adapter = _JournaledAdapter(self._provider, self._journal)
        try:
            outcome = await BenchmarkTargetFactoryRunner(
                output_root=self._output_root,
                adapter=adapter,
                trust_anchor=self._trust_anchor,
            ).run(
                authoritative_manifest,
                arm_id=arm_id,
                seed=seed,
                repetition=repetition,
            )
        except Exception:
            try:
                await self.reconcile_pending()
            except BenchmarkTargetRecoveryError as recovery_error:
                raise BenchmarkTargetRecoveryError(
                    "Target execution failed and cleanup reconciliation remains unresolved"
                ) from recovery_error
            raise
        if outcome.authority.cleanup_receipt.status == "succeeded":
            self._journal.mark_completed(adapter.attempt.attempt_id)
        else:
            await self.reconcile_pending()
        return outcome


def load_benchmark_target_recovery_authority(
    run_path: Path,
) -> BenchmarkTargetRecoveryAuthority:
    """Load one exact sealed recovery authority and its terminal audit sequence."""

    try:
        snapshot = load_verified_run_artifacts(
            run_path,
            requests={_RECOVERY_AUTHORITY_ARTIFACT: _MAX_RECOVERY_AUTHORITY_BYTES},
        )
        authority = BenchmarkTargetRecoveryAuthority.model_validate_json(
            snapshot.artifact_bytes(_RECOVERY_AUTHORITY_ARTIFACT)
        )
        event_types = [event.event_type for event in snapshot.events]
        expected = [
            "campaign.started",
            "benchmark.target-recovery.sealed",
            "campaign.failed",
        ]
        if event_types != expected:
            raise RunIntegrityError("Benchmark Target recovery audit sequence differs")
        sealed = snapshot.events[1].payload
        if (
            sealed.get("artifact") != _RECOVERY_AUTHORITY_ARTIFACT
            or sealed.get("authorityId") != authority.authority_id
            or sealed.get("authorityDigest") != authority.authority_digest
            or sealed.get("lifecycleState") != authority.lifecycle_state
            or sealed.get("measurementAdmissionEligible") is not False
        ):
            raise RunIntegrityError("Benchmark Target recovery audit payload differs")
        return authority
    except (KeyError, OSError, ValueError) as exc:
        raise BenchmarkTargetRecoveryError(
            "P0-C2A sealed Target Recovery Authority could not be verified"
        ) from exc


def _operation(
    attempt: BenchmarkTargetAttempt,
    stage: _Stage,
    *,
    fence: int | None = None,
    ordinal: int = 1,
) -> BenchmarkTargetOperation:
    return BenchmarkTargetOperation(
        attemptId=attempt.attempt_id,
        attemptDigest=attempt.attempt_digest,
        adapterDigest=attempt.adapter_digest,
        coordinateDigest=attempt.coordinate_digest,
        fence=fence or attempt.fence,
        stage=stage,
        ordinal=ordinal,
    )


def _scope_digest(adapter_digest: str, coordinate_digest: str) -> str:
    return benchmark_digest(
        "pajin.benchmark.target-operation-scope/v1",
        {"adapterDigest": adapter_digest, "coordinateDigest": coordinate_digest},
        max_bytes=4 * 1024,
    )


def _latest_receipt(
    records: tuple[BenchmarkTargetOperationRecord, ...],
    stage: str,
) -> BenchmarkTargetStageReceipt | None:
    return next(
        (
            cast(BenchmarkTargetStageReceipt, record.receipt)
            for record in reversed(records)
            if record.record_type == "receipt" and record.operation.stage == stage
        ),
        None,
    )


def _successful_cleanup(
    records: tuple[BenchmarkTargetOperationRecord, ...],
) -> BenchmarkTargetStageReceipt | None:
    latest = _latest_receipt(records, BenchmarkTargetStage.CLEANUP)
    return latest if latest is not None and latest.status == "succeeded" else None


def _require_recovery_receipt(
    request: BenchmarkTargetRecoveryRequest,
    receipt: BenchmarkTargetStageReceipt,
) -> None:
    operation = request.cleanup_operation
    if (
        receipt.operation_id != operation.operation_id
        or receipt.adapter_digest != operation.adapter_digest
        or receipt.coordinate_digest != operation.coordinate_digest
        or receipt.stage != BenchmarkTargetStage.CLEANUP
    ):
        raise ValueError("Recovery cleanup receipt differs from exact fenced operation")
    known = request.known_isolation_receipt
    if known is not None and (
        receipt.environment_id != known.environment_id or receipt.isolation_id != known.isolation_id
    ):
        raise ValueError("Recovery cleanup receipt differs from known isolation identity")


def _require_record_chain(records: tuple[BenchmarkTargetOperationRecord, ...]) -> None:
    previous: str | None = None
    for sequence, record in enumerate(records, start=1):
        if record.sequence != sequence or record.previous_record_digest != previous:
            raise BenchmarkTargetRecoveryError("Benchmark Target operation journal chain differs")
        previous = record.record_digest


def _seal_recovery_authority(
    output_root: Path,
    authority: BenchmarkTargetRecoveryAuthority,
) -> Path:
    store = RunStore.create(output_root, "benchmark-target-recovery")
    store.append_event(
        "campaign.started",
        {
            "purpose": "benchmark-target-recovery",
            "attemptId": authority.abandoned_attempt.attempt_id,
        },
        occurred_at=authority.abandoned_attempt.started_at,
    )
    path = store.write_json(
        _RECOVERY_AUTHORITY_ARTIFACT,
        authority.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "benchmark.target-recovery.sealed",
        {
            "artifact": path,
            "authorityId": authority.authority_id,
            "authorityDigest": authority.authority_digest,
            "lifecycleState": authority.lifecycle_state,
            "measurementAdmissionEligible": False,
        },
        occurred_at=authority.sealed_at,
    )
    store.write_json(
        "run.json",
        {
            "runId": store.run_id,
            "status": "failed",
            "stage": authority.lifecycle_state,
            "authorityId": authority.authority_id,
        },
    )
    store.append_event(
        "campaign.failed",
        {
            "purpose": "benchmark-target-recovery",
            "artifact": path,
            "failureReason": authority.failure_reason,
        },
        occurred_at=authority.sealed_at,
    )
    store.seal()
    return store.path


def _initialize_journal(path: Path) -> None:
    _require_safe_journal_path(path)
    _require_safe_journal_sidecars(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_safe_journal_path(path)
    connection: sqlite3.Connection | None = None
    try:
        connection = _open_write_connection(path)
        mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            raise BenchmarkTargetRecoveryError("Target operation journal mode differs")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS fences (
                scope_digest TEXT PRIMARY KEY,
                value INTEGER NOT NULL CHECK(value >= 1)
            );
            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY,
                scope_digest TEXT NOT NULL,
                fence INTEGER NOT NULL CHECK(fence >= 1),
                attempt_json TEXT NOT NULL,
                adapter_json TEXT NOT NULL,
                coordinate_json TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('open', 'reconciled', 'completed')),
                active_recovery_fence INTEGER,
                UNIQUE(scope_digest, fence)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_open_attempt_per_scope
            ON attempts(scope_digest) WHERE state = 'open';
            CREATE TABLE IF NOT EXISTS records (
                attempt_id TEXT NOT NULL REFERENCES attempts(attempt_id),
                sequence INTEGER NOT NULL CHECK(sequence >= 1),
                record_json TEXT NOT NULL,
                PRIMARY KEY(attempt_id, sequence)
            );
            """
        )
        connection.commit()
        path.chmod(0o600)
        _require_safe_journal_path(path)
        _require_safe_journal_sidecars(path)
    except sqlite3.Error as exc:
        raise BenchmarkTargetRecoveryError("Target operation journal could not initialize") from exc
    finally:
        if connection is not None:
            connection.close()


def _require_safe_journal_path(path: Path) -> None:
    parent = path.parent
    existing_ancestors = (parent, *parent.parents)
    if any(
        ancestor.exists() and (ancestor.is_symlink() or ancestor.is_junction())
        for ancestor in existing_ancestors
    ):
        raise BenchmarkTargetRecoveryError("Target operation journal ancestor is unsafe")
    if parent.exists() and not parent.is_dir():
        raise BenchmarkTargetRecoveryError("Target operation journal parent is unsafe")
    if (path.exists() or path.is_symlink() or path.is_junction()) and (
        not path.is_file() or path.is_symlink() or path.is_junction() or path.stat().st_nlink != 1
    ):
        raise BenchmarkTargetRecoveryError(
            "Target operation journal is not a single-link regular file"
        )


def _require_safe_journal_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not (sidecar.exists() or sidecar.is_symlink() or sidecar.is_junction()):
            continue
        if (
            not sidecar.is_file()
            or sidecar.is_symlink()
            or sidecar.is_junction()
            or sidecar.stat().st_nlink != 1
        ):
            raise BenchmarkTargetRecoveryError(
                "Target operation journal sidecar is not a single-link regular file"
            )


@contextmanager
def _write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_journal_path(path)
    _require_safe_journal_sidecars(path)
    connection = _open_write_connection(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
        _require_safe_journal_path(path)
        _require_safe_journal_sidecars(path)


@contextmanager
def _readonly_connection(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_journal_path(path)
    _require_safe_journal_sidecars(path)
    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA query_only = ON")
    connection.execute("BEGIN")
    try:
        yield connection
    finally:
        connection.rollback()
        connection.close()
        _require_safe_journal_path(path)
        _require_safe_journal_sidecars(path)


def _open_write_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    return connection


def _next_fence(connection: sqlite3.Connection, scope: str) -> int:
    row = connection.execute(
        "SELECT value FROM fences WHERE scope_digest = ?",
        (scope,),
    ).fetchone()
    value = 1 if row is None else int(row[0]) + 1
    connection.execute(
        """
        INSERT INTO fences(scope_digest, value) VALUES (?, ?)
        ON CONFLICT(scope_digest) DO UPDATE SET value = excluded.value
        """,
        (scope, value),
    )
    return value


def _required_open_attempt(connection: sqlite3.Connection, attempt_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM attempts WHERE attempt_id = ? AND state = 'open'",
        (attempt_id,),
    ).fetchone()
    if row is None:
        raise BenchmarkTargetRecoveryError("Target operation attempt is not open")
    return cast(sqlite3.Row, row)
