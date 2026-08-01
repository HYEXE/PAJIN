"""Provider-neutral P0-C1 Target Factory lifecycle and measurement attestation."""

from __future__ import annotations

import base64
from abc import abstractmethod
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.measurement import (
    WalkingBenchmarkRunObservation,
    WalkingBenchmarkRunObservationOutcome,
)
from pajin.benchmark.models import (
    BenchmarkArm,
    BenchmarkManifest,
    benchmark_digest,
    canonical_benchmark_json,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

BENCHMARK_TARGET_FACTORY_ADAPTER_API_VERSION: Literal[
    "pajin.dev/benchmark-target-factory-adapter/v1alpha1"
] = "pajin.dev/benchmark-target-factory-adapter/v1alpha1"
BENCHMARK_TARGET_COORDINATE_API_VERSION: Literal[
    "pajin.dev/benchmark-target-coordinate/v1alpha1"
] = "pajin.dev/benchmark-target-coordinate/v1alpha1"
BENCHMARK_MEASUREMENT_TRUST_ANCHOR_API_VERSION: Literal[
    "pajin.dev/benchmark-measurement-trust-anchor/v1alpha1"
] = "pajin.dev/benchmark-measurement-trust-anchor/v1alpha1"
BENCHMARK_TARGET_RUN_AUTHORITY_API_VERSION: Literal[
    "pajin.dev/benchmark-target-run-authority/v1alpha1"
] = "pajin.dev/benchmark-target-run-authority/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Base64Url = Annotated[str, Field(min_length=43, max_length=86, pattern=r"^[A-Za-z0-9_-]+$")]
_MAX_AUTHORITY_BYTES = 16 * 1024 * 1024
_SIGNATURE_DOMAIN = b"pajin.benchmark.measurement-attestation/v1\x00"
_OBSERVATION_ARTIFACT = "walking-benchmark-run-observation.json"
_AUTHORITY_ARTIFACT = "benchmark-target-run-authority.json"


class BenchmarkTargetFactoryError(RuntimeError):
    """Raised when one provider Target lifecycle cannot be proven exactly."""


class BenchmarkTargetStage(str):
    RESET = "reset"
    ISOLATION = "isolation"
    EXECUTION = "execution"
    CLEANUP = "cleanup"


class RegisteredBenchmarkTargetFactoryAdapter(StrictModel):
    """Content-addressed public identity of one provider Target implementation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-target-factory-adapter/v1alpha1"] = Field(
        default=BENCHMARK_TARGET_FACTORY_ADAPTER_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredBenchmarkTargetFactoryAdapter"] = (
        "RegisteredBenchmarkTargetFactoryAdapter"
    )
    adapter_id: _Identifier = Field(alias="adapterId")
    adapter_version: _Identifier = Field(alias="adapterVersion")
    adapter_digest: str = Field(default="", alias="adapterDigest", max_length=64)
    target_factory_id: _Identifier = Field(alias="targetFactoryId")
    target_factory_version: _Identifier = Field(alias="targetFactoryVersion")
    target_factory_digest: _Sha256 = Field(alias="targetFactoryDigest")
    measurement_authority_id: _Identifier = Field(alias="measurementAuthorityId")
    measurement_authority_version: _Identifier = Field(alias="measurementAuthorityVersion")
    measurement_authority_digest: _Sha256 = Field(alias="measurementAuthorityDigest")
    lifecycle_stages: tuple[
        Literal["reset"],
        Literal["isolation"],
        Literal["execution"],
        Literal["cleanup"],
    ] = Field(
        default=("reset", "isolation", "execution", "cleanup"),
        alias="lifecycleStages",
    )
    per_coordinate_environment: Literal[True] = Field(
        default=True,
        alias="perCoordinateEnvironment",
    )
    network_policy_external: Literal[True] = Field(
        default=True,
        alias="networkPolicyExternal",
    )

    @model_validator(mode="after")
    def bind_definition(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"adapter_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-factory-adapter/v1",
            material,
            max_bytes=256 * 1024,
        )
        if self.adapter_digest and self.adapter_digest != digest:
            raise ValueError("Benchmark Target Factory Adapter Digest differs")
        object.__setattr__(self, "adapter_digest", digest)
        return self


class BenchmarkMeasurementTrustAnchor(StrictModel):
    """One externally provisioned Ed25519 measurement authority key."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-measurement-trust-anchor/v1alpha1"] = Field(
        default=BENCHMARK_MEASUREMENT_TRUST_ANCHOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkMeasurementTrustAnchor"] = "BenchmarkMeasurementTrustAnchor"
    authority_id: _Identifier = Field(alias="authorityId")
    authority_version: _Identifier = Field(alias="authorityVersion")
    key_id: _Identifier = Field(alias="keyId")
    public_key_base64url: _Base64Url = Field(alias="publicKeyBase64url")
    anchor_digest: str = Field(default="", alias="anchorDigest", max_length=64)

    @model_validator(mode="after")
    def bind_anchor(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="Benchmark measurement public key",
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"anchor_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.measurement-trust-anchor/v1",
            material,
            max_bytes=64 * 1024,
        )
        if self.anchor_digest and self.anchor_digest != digest:
            raise ValueError("Benchmark Measurement Trust Anchor Digest differs")
        object.__setattr__(self, "anchor_digest", digest)
        return self


class BenchmarkTargetCoordinate(StrictModel):
    """One exact Manifest arm/seed/repetition execution coordinate."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-target-coordinate/v1alpha1"] = Field(
        default=BENCHMARK_TARGET_COORDINATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetCoordinate"] = "BenchmarkTargetCoordinate"
    coordinate_id: str = Field(default="", alias="coordinateId", max_length=110)
    coordinate_digest: str = Field(default="", alias="coordinateDigest", max_length=64)
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    arm: BenchmarkArm
    seed: int = Field(ge=0, le=2**63 - 1)
    repetition: int = Field(ge=1, le=20)

    @model_validator(mode="after")
    def bind_coordinate(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"coordinate_id", "coordinate_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-coordinate/v1",
            material,
            max_bytes=64 * 1024,
        )
        coordinate_id = f"benchmark-coordinate:{digest}"
        if self.coordinate_digest and self.coordinate_digest != digest:
            raise ValueError("Benchmark Target Coordinate Digest differs")
        if self.coordinate_id and self.coordinate_id != coordinate_id:
            raise ValueError("Benchmark Target Coordinate ID differs")
        object.__setattr__(self, "coordinate_digest", digest)
        object.__setattr__(self, "coordinate_id", coordinate_id)
        return self


class BenchmarkTargetStageReceipt(StrictModel):
    """Provider-issued fact for one ordered Target lifecycle stage."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    coordinate_digest: _Sha256 = Field(alias="coordinateDigest")
    stage: Literal["reset", "isolation", "execution", "cleanup"]
    operation_id: _Identifier = Field(alias="operationId")
    environment_id: _Identifier = Field(alias="environmentId")
    isolation_id: _Identifier | None = Field(default=None, alias="isolationId")
    status: Literal["succeeded", "failed"]
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")
    provider_evidence_digest: _Sha256 = Field(alias="providerEvidenceDigest")

    @field_validator("started_at", "completed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark Target stage timestamp requires an explicit UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("Benchmark Target stage completes before it starts")
        if self.stage == BenchmarkTargetStage.RESET:
            if self.isolation_id is not None:
                raise ValueError("Reset receipt cannot claim an isolation identity")
        elif self.isolation_id is None:
            raise ValueError("Post-reset Target stage requires an isolation identity")
        if self.stage != BenchmarkTargetStage.CLEANUP and self.status != "succeeded":
            raise ValueError("Reset, isolation, and execution must succeed before measurement")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-stage-receipt/v1",
            material,
            max_bytes=128 * 1024,
        )
        receipt_id = f"benchmark-target-stage:{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Benchmark Target Stage Receipt Digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Benchmark Target Stage Receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class BenchmarkMeasurementAttestationStatement(StrictModel):
    """Exact lifecycle and Observation material signed by the measurement authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    statement_id: str = Field(default="", alias="statementId", max_length=110)
    statement_digest: str = Field(default="", alias="statementDigest", max_length=64)
    adapter_id: _Identifier = Field(alias="adapterId")
    adapter_version: _Identifier = Field(alias="adapterVersion")
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    coordinate_id: str = Field(alias="coordinateId", min_length=1, max_length=110)
    coordinate_digest: _Sha256 = Field(alias="coordinateDigest")
    reset_receipt_digest: _Sha256 = Field(alias="resetReceiptDigest")
    isolation_receipt_digest: _Sha256 = Field(alias="isolationReceiptDigest")
    execution_receipt_digest: _Sha256 = Field(alias="executionReceiptDigest")
    cleanup_receipt_digest: _Sha256 = Field(alias="cleanupReceiptDigest")
    observation_id: str = Field(alias="observationId", min_length=1, max_length=110)
    observation_digest: _Sha256 = Field(alias="observationDigest")
    issued_at: datetime = Field(alias="issuedAt")

    @field_validator("issued_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark measurement attestation time requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_statement(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"statement_id", "statement_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.measurement-attestation-statement/v1",
            material,
            max_bytes=256 * 1024,
        )
        statement_id = f"benchmark-measurement-statement:{digest}"
        if self.statement_digest and self.statement_digest != digest:
            raise ValueError("Benchmark Measurement Attestation Statement Digest differs")
        if self.statement_id and self.statement_id != statement_id:
            raise ValueError("Benchmark Measurement Attestation Statement ID differs")
        object.__setattr__(self, "statement_digest", digest)
        object.__setattr__(self, "statement_id", statement_id)
        return self


class BenchmarkMeasurementAttestation(StrictModel):
    """Detached Ed25519 signature over one exact measurement statement."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    key_id: _Identifier = Field(alias="keyId")
    statement: BenchmarkMeasurementAttestationStatement
    statement_digest: _Sha256 = Field(alias="statementDigest")
    signature_base64url: _Base64Url = Field(alias="signatureBase64url")

    @model_validator(mode="after")
    def bind_attestation(self) -> Self:
        if self.statement_digest != self.statement.statement_digest:
            raise ValueError("Benchmark Measurement Attestation statement digest differs")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Benchmark measurement signature",
        )
        return self

    @property
    def digest(self) -> str:
        return benchmark_digest(
            "pajin.benchmark.measurement-attestation/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=512 * 1024,
        )


@dataclass(frozen=True, slots=True)
class BenchmarkMeasurementAttestor:
    """External-key signer helper; callers provision key bytes outside repository artifacts."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: BenchmarkMeasurementTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: BenchmarkMeasurementTrustAnchor,
    ) -> BenchmarkMeasurementAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 Benchmark measurement private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )

    def __post_init__(self) -> None:
        if self.active_key_id != self.trust_anchor.key_id:
            raise ValueError("Benchmark measurement signer key differs from Trust Anchor")
        expected = _base64url_decode(
            self.trust_anchor.public_key_base64url,
            expected_length=32,
            label="Benchmark measurement public key",
        )
        actual = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if actual != expected:
            raise ValueError("Benchmark measurement private key differs from Trust Anchor")

    def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        canonical = _statement_bytes(statement)
        return BenchmarkMeasurementAttestation(
            keyId=self.active_key_id,
            statement=statement,
            statementDigest=statement.statement_digest,
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


class BenchmarkTargetFactoryAdapter(Protocol):
    """Provider-neutral lifecycle implementation supplied outside the benchmark core."""

    @property
    @abstractmethod
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        """Return the exact non-secret adapter definition."""

    @abstractmethod
    async def reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
    ) -> BenchmarkTargetStageReceipt:
        """Reset the Target before this coordinate."""

    @abstractmethod
    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
    ) -> BenchmarkTargetStageReceipt:
        """Create a fresh per-coordinate isolation boundary."""

    @abstractmethod
    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        """Run the arm and return raw measured facts before cleanup admission."""

    @abstractmethod
    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
    ) -> BenchmarkTargetStageReceipt:
        """Attempt cleanup even when execution raises."""

    @abstractmethod
    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        """Sign the complete lifecycle using the external measurement authority."""


class BenchmarkTargetRunAuthority(StrictModel):
    """Complete provider lifecycle, Observation, and verified external attestation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-target-run-authority/v1alpha1"] = Field(
        default=BENCHMARK_TARGET_RUN_AUTHORITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetRunAuthority"] = "BenchmarkTargetRunAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    manifest: BenchmarkManifest
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    adapter: RegisteredBenchmarkTargetFactoryAdapter
    trust_anchor: BenchmarkMeasurementTrustAnchor = Field(alias="trustAnchor")
    coordinate: BenchmarkTargetCoordinate
    reset_receipt: BenchmarkTargetStageReceipt = Field(alias="resetReceipt")
    isolation_receipt: BenchmarkTargetStageReceipt = Field(alias="isolationReceipt")
    execution_receipt: BenchmarkTargetStageReceipt = Field(alias="executionReceipt")
    cleanup_receipt: BenchmarkTargetStageReceipt = Field(alias="cleanupReceipt")
    observation: WalkingBenchmarkRunObservation
    attestation: BenchmarkMeasurementAttestation
    lifecycle_state: Literal["completed-attested"] = Field(
        default="completed-attested",
        alias="lifecycleState",
    )
    measurement_admission_eligible: Literal[True] = Field(
        default=True,
        alias="measurementAdmissionEligible",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        _require_definition_matches_manifest(self.manifest, self.adapter, self.trust_anchor)
        expected_coordinate = benchmark_target_coordinate(
            self.manifest,
            arm_id=self.coordinate.arm.arm_id,
            seed=self.coordinate.seed,
            repetition=self.coordinate.repetition,
        )
        _require_lifecycle(
            self.adapter,
            expected_coordinate,
            self.reset_receipt,
            self.isolation_receipt,
            self.execution_receipt,
            self.cleanup_receipt,
            self.observation,
        )
        expected_statement = _attestation_statement(
            self.adapter,
            self.trust_anchor,
            expected_coordinate,
            self.reset_receipt,
            self.isolation_receipt,
            self.execution_receipt,
            self.cleanup_receipt,
            self.observation,
            issued_at=self.attestation.statement.issued_at,
        )
        if (
            self.manifest_digest != self.manifest.digest()
            or self.coordinate != expected_coordinate
            or self.attestation.statement != expected_statement
        ):
            raise ValueError("P0-C1 Target Run Authority differs from exact lifecycle")
        verify_benchmark_measurement_attestation(
            self.attestation,
            trust_anchor=self.trust_anchor,
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-run-authority/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"benchmark-target-run:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Benchmark Target Run Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Benchmark Target Run Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


@dataclass(frozen=True, slots=True)
class BenchmarkTargetRunOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    observation_path: str
    authority: BenchmarkTargetRunAuthority

    def as_observation_outcome(self) -> WalkingBenchmarkRunObservationOutcome:
        """Expose the same sealed Run through BENCH-003B1's observation reader."""

        return WalkingBenchmarkRunObservationOutcome(
            run_id=self.run_id,
            run_path=self.run_path,
            artifact_path=self.observation_path,
            observation=self.authority.observation.model_copy(deep=True),
        )


class BenchmarkTargetFactoryRunner:
    """Execute one coordinate and always attempt cleanup after isolation succeeds."""

    def __init__(
        self,
        *,
        output_root: Path,
        adapter: BenchmarkTargetFactoryAdapter,
        trust_anchor: BenchmarkMeasurementTrustAnchor,
    ) -> None:
        self._output_root = output_root
        self._adapter = adapter
        self._trust_anchor = trust_anchor

    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        """Expose the adapter identity for additive preflight policy wrappers."""

        return self._adapter.definition

    async def run(
        self,
        manifest: BenchmarkManifest,
        *,
        arm_id: str,
        seed: int,
        repetition: int,
    ) -> BenchmarkTargetRunOutcome:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        try:
            adapter = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
                self._adapter.definition.model_dump(mode="json", by_alias=True)
            )
            trust_anchor = BenchmarkMeasurementTrustAnchor.model_validate(
                self._trust_anchor.model_dump(mode="json", by_alias=True)
            )
            _require_definition_matches_manifest(authoritative_manifest, adapter, trust_anchor)
            coordinate = benchmark_target_coordinate(
                authoritative_manifest,
                arm_id=arm_id,
                seed=seed,
                repetition=repetition,
            )
            try:
                reset = _canonical_receipt(await self._adapter.reset(coordinate))
            except Exception as reset_error:
                raise BenchmarkTargetFactoryError("P0-C1 Target reset failed") from reset_error
            _require_stage_receipt(adapter, coordinate, reset, BenchmarkTargetStage.RESET)
            try:
                isolation = _canonical_receipt(
                    await self._adapter.establish_isolation(coordinate, reset)
                )
            except Exception as isolation_error:
                raise BenchmarkTargetFactoryError(
                    "P0-C1 Target isolation failed"
                ) from isolation_error
            _require_stage_receipt(
                adapter,
                coordinate,
                isolation,
                BenchmarkTargetStage.ISOLATION,
            )
            _require_stage_transition(reset, isolation)
            execution: BenchmarkTargetStageReceipt
            raw_observation: WalkingBenchmarkRunObservation
            cleanup_predecessor = isolation
            try:
                _require_fresh_receipts(reset, isolation)
                raw_execution, raw_observation = await self._adapter.execute(
                    coordinate,
                    isolation,
                )
                execution = _canonical_receipt(raw_execution)
                _require_stage_receipt(
                    adapter,
                    coordinate,
                    execution,
                    BenchmarkTargetStage.EXECUTION,
                )
                _require_stage_transition(isolation, execution)
                cleanup_predecessor = execution
                _require_fresh_receipts(reset, isolation, execution)
                _require_raw_observation_identity(
                    authoritative_manifest,
                    adapter,
                    coordinate,
                    execution,
                    raw_observation,
                )
            except Exception as execution_error:
                try:
                    cleanup_after_error = _canonical_receipt(
                        await self._adapter.cleanup(coordinate, isolation)
                    )
                    _require_stage_receipt(
                        adapter,
                        coordinate,
                        cleanup_after_error,
                        BenchmarkTargetStage.CLEANUP,
                    )
                    _require_stage_transition(cleanup_predecessor, cleanup_after_error)
                except Exception as cleanup_error:
                    raise BenchmarkTargetFactoryError(
                        "P0-C1 execution and mandatory cleanup both failed"
                    ) from cleanup_error
                raise BenchmarkTargetFactoryError(
                    "P0-C1 execution failed after mandatory cleanup"
                ) from execution_error
            try:
                cleanup = _canonical_receipt(
                    await self._adapter.cleanup(coordinate, isolation)
                )
            except Exception as cleanup_error:
                raise BenchmarkTargetFactoryError(
                    "P0-C1 mandatory cleanup failed"
                ) from cleanup_error
            _require_stage_receipt(
                adapter,
                coordinate,
                cleanup,
                BenchmarkTargetStage.CLEANUP,
            )
            _require_stage_transition(execution, cleanup)
            _require_fresh_receipts(reset, isolation, execution, cleanup)
            observation = _final_observation(
                authoritative_manifest,
                adapter,
                coordinate,
                execution,
                cleanup,
                raw_observation,
            )
            _require_lifecycle(
                adapter,
                coordinate,
                reset,
                isolation,
                execution,
                cleanup,
                observation,
            )
            statement = _attestation_statement(
                adapter,
                trust_anchor,
                coordinate,
                reset,
                isolation,
                execution,
                cleanup,
                observation,
                issued_at=cleanup.completed_at,
            )
            try:
                raw_attestation = await self._adapter.attest(statement)
                attestation = BenchmarkMeasurementAttestation.model_validate(
                    raw_attestation.model_dump(mode="json", by_alias=True)
                )
            except Exception as attestation_error:
                raise BenchmarkTargetFactoryError(
                    "P0-C1 external measurement attestation failed"
                ) from attestation_error
            verify_benchmark_measurement_attestation(
                attestation,
                trust_anchor=trust_anchor,
            )
            authority = BenchmarkTargetRunAuthority(
                manifest=authoritative_manifest,
                manifestDigest=authoritative_manifest.digest(),
                adapter=adapter,
                trustAnchor=trust_anchor,
                coordinate=coordinate,
                resetReceipt=reset,
                isolationReceipt=isolation,
                executionReceipt=execution,
                cleanupReceipt=cleanup,
                observation=observation,
                attestation=attestation,
            )
        except Exception as exc:
            if isinstance(exc, BenchmarkTargetFactoryError):
                raise
            raise BenchmarkTargetFactoryError(
                "P0-C1 Target Factory lifecycle could not be verified"
            ) from exc

        store = RunStore.create(self._output_root, "benchmark-target-factory")
        store.append_event(
            "campaign.started",
            {
                "benchmarkId": authoritative_manifest.benchmark_id,
                "purpose": "benchmark-target-factory-coordinate",
            },
            occurred_at=reset.started_at,
        )
        store.write_json(
            "benchmark-manifest.json",
            authoritative_manifest.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            "target-factory-adapter.json",
            adapter.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            "benchmark-coordinate.json",
            coordinate.model_dump(mode="json", by_alias=True),
        )
        store.write_json("reset-receipt.json", reset.model_dump(mode="json", by_alias=True))
        store.write_json("isolation-receipt.json", isolation.model_dump(mode="json", by_alias=True))
        store.write_json("execution-receipt.json", execution.model_dump(mode="json", by_alias=True))
        store.write_json("cleanup-receipt.json", cleanup.model_dump(mode="json", by_alias=True))
        observation_path = store.write_json(
            _OBSERVATION_ARTIFACT,
            observation.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            "measurement-attestation.json",
            attestation.model_dump(mode="json", by_alias=True),
        )
        authority_path = store.write_json(
            _AUTHORITY_ARTIFACT,
            authority.model_dump(mode="json", by_alias=True),
        )
        for receipt in (reset, isolation, execution, cleanup):
            store.append_event(
                f"benchmark.target-factory.{receipt.stage}",
                _stage_event_payload(receipt),
                occurred_at=receipt.completed_at,
            )
        store.append_event(
            "benchmark.walking-run-observation.created",
            _observation_event_payload(observation_path, observation),
            occurred_at=cleanup.completed_at,
        )
        store.append_event(
            "benchmark.target-factory.measurement-attested",
            _authority_event_payload(authority_path, authority),
            occurred_at=attestation.statement.issued_at,
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "benchmark-target-factory-measurement-sealed",
                "authorityId": authority.authority_id,
                "observationId": observation.observation_id,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "benchmark-target-factory-coordinate", "artifact": authority_path},
            occurred_at=attestation.statement.issued_at,
        )
        store.seal()
        return BenchmarkTargetRunOutcome(
            run_id=store.run_id,
            run_path=store.path,
            authority_path=authority_path,
            observation_path=observation_path,
            authority=authority.model_copy(deep=True),
        )


def load_benchmark_target_run_authority(
    manifest: BenchmarkManifest,
    outcome: BenchmarkTargetRunOutcome,
) -> BenchmarkTargetRunAuthority:
    """Reload the entire P0-C1 lifecycle and exact audit sequence."""

    requests = {
        "benchmark-manifest.json": 256 * 1024,
        "target-factory-adapter.json": 256 * 1024,
        "benchmark-coordinate.json": 128 * 1024,
        "reset-receipt.json": 128 * 1024,
        "isolation-receipt.json": 128 * 1024,
        "execution-receipt.json": 128 * 1024,
        "cleanup-receipt.json": 128 * 1024,
        _OBSERVATION_ARTIFACT: 256 * 1024,
        "measurement-attestation.json": 512 * 1024,
        _AUTHORITY_ARTIFACT: _MAX_AUTHORITY_BYTES,
    }
    try:
        if (
            outcome.authority_path != _AUTHORITY_ARTIFACT
            or outcome.observation_path != _OBSERVATION_ARTIFACT
        ):
            raise ValueError("P0-C1 output artifact path differs")
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests=requests,
            expected_run_id=outcome.run_id,
        )
        sealed_manifest = BenchmarkManifest.model_validate_json(
            snapshot.artifact_bytes("benchmark-manifest.json")
        )
        authority = BenchmarkTargetRunAuthority.model_validate_json(
            snapshot.artifact_bytes(_AUTHORITY_ARTIFACT)
        )
        adapter = RegisteredBenchmarkTargetFactoryAdapter.model_validate_json(
            snapshot.artifact_bytes("target-factory-adapter.json")
        )
        coordinate = BenchmarkTargetCoordinate.model_validate_json(
            snapshot.artifact_bytes("benchmark-coordinate.json")
        )
        receipts = tuple(
            BenchmarkTargetStageReceipt.model_validate_json(snapshot.artifact_bytes(path))
            for path in (
                "reset-receipt.json",
                "isolation-receipt.json",
                "execution-receipt.json",
                "cleanup-receipt.json",
            )
        )
        observation = WalkingBenchmarkRunObservation.model_validate_json(
            snapshot.artifact_bytes(_OBSERVATION_ARTIFACT)
        )
        attestation = BenchmarkMeasurementAttestation.model_validate_json(
            snapshot.artifact_bytes("measurement-attestation.json")
        )
    except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
        raise BenchmarkTargetFactoryError("P0-C1 Target Run is not sealed and valid") from exc
    if (
        sealed_manifest != manifest
        or authority != outcome.authority
        or adapter != authority.adapter
        or coordinate != authority.coordinate
        or receipts
        != (
            authority.reset_receipt,
            authority.isolation_receipt,
            authority.execution_receipt,
            authority.cleanup_receipt,
        )
        or observation != authority.observation
        or attestation != authority.attestation
    ):
        raise BenchmarkTargetFactoryError("P0-C1 artifacts differ from exact authority")
    expected_types = [
        "campaign.started",
        "benchmark.target-factory.reset",
        "benchmark.target-factory.isolation",
        "benchmark.target-factory.execution",
        "benchmark.target-factory.cleanup",
        "benchmark.walking-run-observation.created",
        "benchmark.target-factory.measurement-attested",
        "campaign.completed",
    ]
    if [event.event_type for event in snapshot.events] != expected_types:
        raise BenchmarkTargetFactoryError("P0-C1 audit event sequence differs")
    for event, receipt in zip(snapshot.events[1:5], receipts, strict=True):
        if event.payload != _stage_event_payload(receipt):
            raise BenchmarkTargetFactoryError("P0-C1 stage event differs")
    if (
        snapshot.events[5].payload
        != _observation_event_payload(_OBSERVATION_ARTIFACT, observation)
        or snapshot.events[6].payload
        != _authority_event_payload(_AUTHORITY_ARTIFACT, authority)
    ):
        raise BenchmarkTargetFactoryError("P0-C1 publication event differs")
    return authority.model_copy(deep=True)


def benchmark_target_coordinate(
    manifest: BenchmarkManifest,
    *,
    arm_id: str,
    seed: int,
    repetition: int,
) -> BenchmarkTargetCoordinate:
    """Build one coordinate only when it exists in the Manifest protocol."""

    arms = [arm for arm in manifest.arms if arm.arm_id == arm_id]
    if len(arms) != 1:
        raise ValueError("Benchmark Target coordinate Arm is absent from Manifest")
    if seed not in manifest.protocol.seeds:
        raise ValueError("Benchmark Target coordinate seed is absent from Manifest")
    if repetition < 1 or repetition > manifest.protocol.repetitions_per_seed:
        raise ValueError("Benchmark Target coordinate repetition is absent from Manifest")
    return BenchmarkTargetCoordinate(
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        arm=arms[0],
        seed=seed,
        repetition=repetition,
    )


def benchmark_measurement_public_key_base64url(private_key: bytes) -> str:
    """Return the raw Ed25519 public key without persisting private material."""

    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def verify_benchmark_measurement_attestation(
    attestation: BenchmarkMeasurementAttestation,
    *,
    trust_anchor: BenchmarkMeasurementTrustAnchor,
) -> str:
    """Verify one exact external measurement signature against its explicit anchor."""

    if attestation.key_id != trust_anchor.key_id:
        raise ValueError("Benchmark measurement attestation key is not trusted")
    statement = attestation.statement
    if statement.trust_anchor_digest != trust_anchor.anchor_digest:
        raise ValueError("Benchmark measurement statement Trust Anchor differs")
    public_key = Ed25519PublicKey.from_public_bytes(
        _base64url_decode(
            trust_anchor.public_key_base64url,
            expected_length=32,
            label="Benchmark measurement public key",
        )
    )
    try:
        public_key.verify(
            _base64url_decode(
                attestation.signature_base64url,
                expected_length=64,
                label="Benchmark measurement signature",
            ),
            _SIGNATURE_DOMAIN + _statement_bytes(statement),
        )
    except InvalidSignature as exc:
        raise ValueError("Benchmark measurement attestation signature is invalid") from exc
    return attestation.key_id


def _require_definition_matches_manifest(
    manifest: BenchmarkManifest,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    trust_anchor: BenchmarkMeasurementTrustAnchor,
) -> None:
    if (
        adapter.target_factory_id != manifest.target_factory_id
        or adapter.target_factory_version != manifest.target_factory_version
        or adapter.target_factory_digest != manifest.target_factory_digest
        or adapter.measurement_authority_id != trust_anchor.authority_id
        or adapter.measurement_authority_version != trust_anchor.authority_version
        or adapter.measurement_authority_digest != trust_anchor.anchor_digest
    ):
        raise ValueError("P0-C1 Adapter or measurement authority differs from Manifest")


def _canonical_receipt(
    receipt: BenchmarkTargetStageReceipt,
) -> BenchmarkTargetStageReceipt:
    return BenchmarkTargetStageReceipt.model_validate(
        receipt.model_dump(mode="json", by_alias=True)
    )


def _require_lifecycle(
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    coordinate: BenchmarkTargetCoordinate,
    reset: BenchmarkTargetStageReceipt,
    isolation: BenchmarkTargetStageReceipt,
    execution: BenchmarkTargetStageReceipt,
    cleanup: BenchmarkTargetStageReceipt,
    observation: WalkingBenchmarkRunObservation,
) -> None:
    receipts = (reset, isolation, execution, cleanup)
    if tuple(item.stage for item in receipts) != adapter.lifecycle_stages:
        raise ValueError("P0-C1 lifecycle stages are missing or reordered")
    if any(
        item.adapter_digest != adapter.adapter_digest
        or item.coordinate_digest != coordinate.coordinate_digest
        for item in receipts
    ):
        raise ValueError("P0-C1 stage receipt differs from Adapter or coordinate")
    if len({item.operation_id for item in receipts}) != len(receipts):
        raise ValueError("P0-C1 provider operation identities must be fresh")
    if len({item.provider_evidence_digest for item in receipts}) != len(receipts):
        raise ValueError("P0-C1 provider evidence digests must be fresh")
    if any(item.environment_id != reset.environment_id for item in receipts):
        raise ValueError("P0-C1 lifecycle changed Target environment")
    if any(item.isolation_id != isolation.isolation_id for item in receipts[1:]):
        raise ValueError("P0-C1 post-reset lifecycle changed isolation identity")
    if not (
        reset.completed_at <= isolation.started_at
        and isolation.completed_at <= execution.started_at
        and execution.completed_at <= cleanup.started_at
    ):
        raise ValueError("P0-C1 lifecycle timestamps overlap or reorder stages")
    _require_observation_matches(
        coordinate,
        adapter,
        execution,
        cleanup,
        observation,
    )


def _require_stage_receipt(
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    coordinate: BenchmarkTargetCoordinate,
    receipt: BenchmarkTargetStageReceipt,
    expected_stage: str,
) -> None:
    if (
        receipt.stage != expected_stage
        or receipt.adapter_digest != adapter.adapter_digest
        or receipt.coordinate_digest != coordinate.coordinate_digest
    ):
        raise ValueError("P0-C1 stage receipt differs before the next provider operation")


def _require_stage_transition(
    previous: BenchmarkTargetStageReceipt,
    current: BenchmarkTargetStageReceipt,
) -> None:
    if (
        current.environment_id != previous.environment_id
        or current.started_at < previous.completed_at
        or (
            previous.stage != BenchmarkTargetStage.RESET
            and current.isolation_id != previous.isolation_id
        )
    ):
        raise ValueError("P0-C1 lifecycle transition changes identity or overlaps")


def _require_fresh_receipts(*receipts: BenchmarkTargetStageReceipt) -> None:
    operation_ids = [receipt.operation_id for receipt in receipts]
    evidence_digests = [receipt.provider_evidence_digest for receipt in receipts]
    if (
        len(operation_ids) != len(set(operation_ids))
        or len(evidence_digests) != len(set(evidence_digests))
    ):
        raise ValueError("P0-C1 lifecycle receipt identities must be fresh")


def _require_observation_matches(
    coordinate: BenchmarkTargetCoordinate,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    execution: BenchmarkTargetStageReceipt,
    cleanup: BenchmarkTargetStageReceipt,
    observation: WalkingBenchmarkRunObservation,
) -> None:
    if (
        observation.benchmark_id != coordinate.benchmark_id
        or observation.manifest_digest != coordinate.manifest_digest
        or observation.arm_id != coordinate.arm.arm_id
        or observation.arm_kind is not coordinate.arm.kind
        or observation.configuration_digest != coordinate.arm.configuration_digest
        or observation.seed != coordinate.seed
        or observation.repetition != coordinate.repetition
        or observation.measurement_authority_id != adapter.measurement_authority_id
        or observation.measurement_authority_version != adapter.measurement_authority_version
        or observation.measurement_authority_digest != adapter.measurement_authority_digest
        or observation.started_at != execution.started_at
        or observation.completed_at != execution.completed_at
        or observation.cleanup_succeeded != (cleanup.status == "succeeded")
    ):
        raise ValueError("P0-C1 Observation differs from lifecycle authority")


def _final_observation(
    manifest: BenchmarkManifest,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    coordinate: BenchmarkTargetCoordinate,
    execution: BenchmarkTargetStageReceipt,
    cleanup: BenchmarkTargetStageReceipt,
    raw: WalkingBenchmarkRunObservation,
) -> WalkingBenchmarkRunObservation:
    _require_raw_observation_identity(
        manifest,
        adapter,
        coordinate,
        execution,
        raw,
    )
    value = raw.model_dump(mode="json", by_alias=True)
    value["observationId"] = ""
    value["observationDigest"] = ""
    value["cleanupSucceeded"] = cleanup.status == "succeeded"
    observation = WalkingBenchmarkRunObservation.model_validate(value)
    elapsed = (observation.completed_at - observation.started_at).total_seconds()
    if (
        elapsed > manifest.protocol.timeout_seconds
        or observation.cost_usd > manifest.protocol.max_cost_usd
        or observation.tool_call_count > manifest.protocol.max_tool_calls
        or observation.model_call_count > manifest.protocol.max_model_calls
    ):
        raise ValueError("P0-C1 Observation exceeds Manifest budget")
    return observation


def _require_raw_observation_identity(
    manifest: BenchmarkManifest,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    coordinate: BenchmarkTargetCoordinate,
    execution: BenchmarkTargetStageReceipt,
    observation: WalkingBenchmarkRunObservation,
) -> None:
    if (
        observation.benchmark_id != manifest.benchmark_id
        or observation.manifest_digest != manifest.digest()
        or observation.arm_id != coordinate.arm.arm_id
        or observation.arm_kind is not coordinate.arm.kind
        or observation.configuration_digest != coordinate.arm.configuration_digest
        or observation.target_factory_digest != manifest.target_factory_digest
        or observation.campaign_digest != manifest.campaign_digest
        or observation.ground_truth_digest != manifest.ground_truth_digest
        or observation.protocol_id != manifest.protocol.protocol_id
        or observation.protocol_version != manifest.protocol.protocol_version
        or observation.measurement_authority_id != adapter.measurement_authority_id
        or observation.measurement_authority_version != adapter.measurement_authority_version
        or observation.measurement_authority_digest != adapter.measurement_authority_digest
        or observation.seed != coordinate.seed
        or observation.repetition != coordinate.repetition
        or observation.started_at != execution.started_at
        or observation.completed_at != execution.completed_at
    ):
        raise ValueError("P0-C1 raw Observation identity differs before cleanup")


def _attestation_statement(
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    trust_anchor: BenchmarkMeasurementTrustAnchor,
    coordinate: BenchmarkTargetCoordinate,
    reset: BenchmarkTargetStageReceipt,
    isolation: BenchmarkTargetStageReceipt,
    execution: BenchmarkTargetStageReceipt,
    cleanup: BenchmarkTargetStageReceipt,
    observation: WalkingBenchmarkRunObservation,
    *,
    issued_at: datetime,
) -> BenchmarkMeasurementAttestationStatement:
    return BenchmarkMeasurementAttestationStatement(
        adapterId=adapter.adapter_id,
        adapterVersion=adapter.adapter_version,
        adapterDigest=adapter.adapter_digest,
        trustAnchorDigest=trust_anchor.anchor_digest,
        coordinateId=coordinate.coordinate_id,
        coordinateDigest=coordinate.coordinate_digest,
        resetReceiptDigest=reset.receipt_digest,
        isolationReceiptDigest=isolation.receipt_digest,
        executionReceiptDigest=execution.receipt_digest,
        cleanupReceiptDigest=cleanup.receipt_digest,
        observationId=observation.observation_id,
        observationDigest=observation.observation_digest,
        issuedAt=issued_at,
    )


def _statement_bytes(statement: BenchmarkMeasurementAttestationStatement) -> bytes:
    return canonical_benchmark_json(
        statement.model_dump(mode="json", by_alias=True),
        label="BenchmarkMeasurementAttestationStatement",
        max_bytes=256 * 1024,
    )


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{label} is not valid base64url") from exc
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} has invalid length or non-canonical encoding")
    return decoded


def _stage_event_payload(receipt: BenchmarkTargetStageReceipt) -> dict[str, object]:
    return {
        "receiptId": receipt.receipt_id,
        "receiptDigest": receipt.receipt_digest,
        "stage": receipt.stage,
        "operationId": receipt.operation_id,
        "environmentId": receipt.environment_id,
        "isolationId": receipt.isolation_id,
        "status": receipt.status,
    }


def _observation_event_payload(
    artifact_path: str,
    observation: WalkingBenchmarkRunObservation,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "observationId": observation.observation_id,
        "observationDigest": observation.observation_digest,
        "armId": observation.arm_id,
        "armKind": observation.arm_kind.value,
        "seed": observation.seed,
        "repetition": observation.repetition,
        "measurementAuthorityId": observation.measurement_authority_id,
    }


def _authority_event_payload(
    artifact_path: str,
    authority: BenchmarkTargetRunAuthority,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "coordinateId": authority.coordinate.coordinate_id,
        "observationId": authority.observation.observation_id,
        "attestationDigest": authority.attestation.digest,
        "lifecycleState": authority.lifecycle_state,
        "measurementAdmissionEligible": authority.measurement_admission_eligible,
    }
