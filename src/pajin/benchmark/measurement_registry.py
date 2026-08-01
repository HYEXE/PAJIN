"""P0-C2B1 Benchmark measurement Trust Anchor registry and sealed admission."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.measurement import WalkingBenchmarkRunObservationOutcome
from pajin.benchmark.models import BenchmarkManifest, benchmark_digest
from pajin.benchmark.target_factory import (
    BenchmarkMeasurementTrustAnchor,
    BenchmarkTargetFactoryError,
    BenchmarkTargetRunOutcome,
    RegisteredBenchmarkTargetFactoryAdapter,
    load_benchmark_target_run_authority,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

BENCHMARK_MEASUREMENT_TRUST_REGISTRY_API_VERSION: Literal[
    "pajin.dev/benchmark-measurement-trust-registry/v1alpha1"
] = "pajin.dev/benchmark-measurement-trust-registry/v1alpha1"
BENCHMARK_MEASUREMENT_REGISTRY_ADMISSION_API_VERSION: Literal[
    "pajin.dev/benchmark-measurement-registry-admission/v1alpha1"
] = "pajin.dev/benchmark-measurement-registry-admission/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_REGISTRY_ARTIFACT = "benchmark-measurement-trust-registry.json"
_ADMISSION_AUTHORITY_ARTIFACT = "benchmark-measurement-registry-admission.json"
_MAX_ADMISSION_AUTHORITY_BYTES = 16 * 1024 * 1024


class BenchmarkMeasurementRegistryError(RuntimeError):
    """Raised when measurement key lifecycle or sealed admission cannot be trusted."""


class BenchmarkMeasurementKeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class BenchmarkMeasurementAdmissionMode(StrEnum):
    FRESH_MEASUREMENT = "fresh-measurement"
    HISTORICAL_VERIFICATION = "historical-verification"


class BenchmarkMeasurementRegistryKey(StrictModel):
    """One exact P0-C1 public Trust Anchor plus externally managed lifecycle."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    trust_anchor: BenchmarkMeasurementTrustAnchor = Field(alias="trustAnchor")
    state: BenchmarkMeasurementKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @field_validator("not_before", "not_after", "revoked_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark measurement key timestamp requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_lifecycle(self) -> Self:
        if self.not_after is not None and self.not_after <= self.not_before:
            raise ValueError("Benchmark measurement key validity window is empty")
        if self.state is BenchmarkMeasurementKeyState.RETIRED and self.not_after is None:
            raise ValueError("Retired Benchmark measurement key requires notAfter")
        if self.state is BenchmarkMeasurementKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("Revoked Benchmark measurement key requires revokedAt")
        elif self.revoked_at is not None:
            raise ValueError("Non-revoked Benchmark measurement key cannot have revokedAt")
        return self

    @property
    def key_id(self) -> str:
        return self.trust_anchor.key_id


class BenchmarkMeasurementTrustRegistry(StrictModel):
    """Versioned out-of-band keyring for one measurement authority identity."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-measurement-trust-registry/v1alpha1"] = (
        Field(
            default=BENCHMARK_MEASUREMENT_TRUST_REGISTRY_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["BenchmarkMeasurementTrustRegistry"] = "BenchmarkMeasurementTrustRegistry"
    registry_id: _Identifier = Field(alias="registryId")
    registry_revision: int = Field(alias="registryRevision", ge=1, le=2**31 - 1)
    previous_registry_digest: _Sha256 | None = Field(
        default=None,
        alias="previousRegistryDigest",
    )
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    measurement_authority_id: _Identifier = Field(alias="measurementAuthorityId")
    measurement_authority_version: _Identifier = Field(alias="measurementAuthorityVersion")
    issued_at: datetime = Field(alias="issuedAt")
    keys: tuple[BenchmarkMeasurementRegistryKey, ...] = Field(min_length=1, max_length=32)

    @field_validator("issued_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark measurement registry timestamp requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        if (self.registry_revision == 1) != (self.previous_registry_digest is None):
            raise ValueError(
                "Benchmark measurement registry revision one starts the chain and later "
                "revisions bind a predecessor"
            )
        key_ids = [key.key_id for key in self.keys]
        if key_ids != sorted(key_ids) or len(key_ids) != len(set(key_ids)):
            raise ValueError("Benchmark measurement registry keys must be uniquely sorted")
        if len(set(key.trust_anchor.anchor_digest for key in self.keys)) != len(self.keys):
            raise ValueError("Benchmark measurement registry Trust Anchors must be unique")
        active = [key for key in self.keys if key.state is BenchmarkMeasurementKeyState.ACTIVE]
        if len(active) != 1:
            raise ValueError("Benchmark measurement registry requires exactly one active key")
        for key in self.keys:
            anchor = key.trust_anchor
            if (
                anchor.authority_id != self.measurement_authority_id
                or anchor.authority_version != self.measurement_authority_version
            ):
                raise ValueError("Benchmark measurement registry key belongs to another authority")
            if key.not_before > self.issued_at:
                raise ValueError("Benchmark measurement registry publishes a key before validity")
            if key.state is BenchmarkMeasurementKeyState.ACTIVE and (
                key.not_after is not None and key.not_after <= self.issued_at
            ):
                raise ValueError("Active Benchmark measurement key is expired at registry issue")
            if key.state is BenchmarkMeasurementKeyState.RETIRED and (
                key.not_after is None or key.not_after > self.issued_at
            ):
                raise ValueError("Retired Benchmark measurement key cutoff exceeds registry issue")
            if key.state is BenchmarkMeasurementKeyState.REVOKED and (
                key.revoked_at is None or key.revoked_at > self.issued_at
            ):
                raise ValueError("Benchmark measurement key revocation postdates registry issue")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.measurement-trust-registry/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Benchmark Measurement Trust Registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    @property
    def active_key(self) -> BenchmarkMeasurementRegistryKey:
        return next(key for key in self.keys if key.state is BenchmarkMeasurementKeyState.ACTIVE)

    def key(self, key_id: str) -> BenchmarkMeasurementRegistryKey:
        selected = next((key for key in self.keys if key.key_id == key_id), None)
        if selected is None:
            raise BenchmarkMeasurementRegistryError(
                "Benchmark measurement key is absent from the Trust Registry"
            )
        return selected


class BenchmarkMeasurementRegistryAdmissionAuthority(StrictModel):
    """Sealed binding from one P0-C1 Run to one exact registry revision and key state."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-measurement-registry-admission/v1alpha1"
    ] = Field(
        default=BENCHMARK_MEASUREMENT_REGISTRY_ADMISSION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkMeasurementRegistryAdmissionAuthority"] = (
        "BenchmarkMeasurementRegistryAdmissionAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    registry: BenchmarkMeasurementTrustRegistry
    predecessor_registry: BenchmarkMeasurementTrustRegistry | None = Field(
        default=None,
        alias="predecessorRegistry",
    )
    registry_digest: _Sha256 = Field(alias="registryDigest")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_authority_path: Literal["benchmark-target-run-authority.json"] = Field(
        default="benchmark-target-run-authority.json",
        alias="sourceAuthorityPath",
    )
    source_authority_sha256: _Sha256 = Field(alias="sourceAuthoritySha256")
    source_authority_digest: _Sha256 = Field(alias="sourceAuthorityDigest")
    source_attestation_digest: _Sha256 = Field(alias="sourceAttestationDigest")
    measurement_authority_id: _Identifier = Field(alias="measurementAuthorityId")
    measurement_authority_version: _Identifier = Field(alias="measurementAuthorityVersion")
    measurement_authority_digest: _Sha256 = Field(alias="measurementAuthorityDigest")
    key_id: _Identifier = Field(alias="keyId")
    key_state: BenchmarkMeasurementKeyState = Field(alias="keyState")
    admission_mode: BenchmarkMeasurementAdmissionMode = Field(alias="admissionMode")
    measurement_admission_eligible: bool = Field(alias="measurementAdmissionEligible")
    historical_verification_eligible: Literal[True] = Field(
        default=True,
        alias="historicalVerificationEligible",
    )
    measurement_issued_at: datetime = Field(alias="measurementIssuedAt")
    admitted_at: datetime = Field(alias="admittedAt")

    @field_validator("measurement_issued_at", "admitted_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark measurement admission timestamp requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        _require_registry_predecessor(self.registry, self.predecessor_registry)
        key = resolve_benchmark_measurement_registry_key(
            self.registry,
            key_id=self.key_id,
            issued_at=self.measurement_issued_at,
            mode=self.admission_mode,
        )
        anchor = key.trust_anchor
        expected_eligible = (
            self.admission_mode is BenchmarkMeasurementAdmissionMode.FRESH_MEASUREMENT
        )
        if (
            self.registry_digest != self.registry.registry_digest
            or self.key_state is not key.state
            or self.measurement_authority_id != anchor.authority_id
            or self.measurement_authority_version != anchor.authority_version
            or self.measurement_authority_digest != anchor.anchor_digest
            or self.measurement_admission_eligible != expected_eligible
            or self.admitted_at < self.measurement_issued_at
            or self.admitted_at < self.registry.issued_at
        ):
            raise ValueError("Benchmark Measurement Registry Admission differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.measurement-registry-admission/v1",
            material,
            max_bytes=_MAX_ADMISSION_AUTHORITY_BYTES,
        )
        authority_id = f"benchmark-measurement-admission:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Benchmark Measurement Registry Admission Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Benchmark Measurement Registry Admission ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


@dataclass(frozen=True, slots=True)
class BenchmarkMeasurementRegistryAdmissionOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    authority: BenchmarkMeasurementRegistryAdmissionAuthority


@dataclass(frozen=True, slots=True)
class BenchmarkRegistryBoundTargetRunOutcome:
    target: BenchmarkTargetRunOutcome
    admission: BenchmarkMeasurementRegistryAdmissionOutcome

    def as_observation_outcome(self) -> WalkingBenchmarkRunObservationOutcome:
        return self.target.as_observation_outcome()


class BenchmarkTargetRunExecutor(Protocol):
    """P0-C1/P0-C2A common surface required by the registry preflight wrapper."""

    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        """Return the adapter identity without executing provider operations."""
        ...

    async def run(
        self,
        manifest: BenchmarkManifest,
        *,
        arm_id: str,
        seed: int,
        repetition: int,
    ) -> BenchmarkTargetRunOutcome:
        """Execute one exact coordinate after registry preflight."""
        ...


class BenchmarkMeasurementRegistryAdmissionRunner:
    """Seal fresh or historical registry admission for one verified P0-C1 source Run."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def admit(
        self,
        manifest: BenchmarkManifest,
        target: BenchmarkTargetRunOutcome,
        registry: BenchmarkMeasurementTrustRegistry,
        *,
        predecessor_registry: BenchmarkMeasurementTrustRegistry | None = None,
        mode: BenchmarkMeasurementAdmissionMode = (
            BenchmarkMeasurementAdmissionMode.FRESH_MEASUREMENT
        ),
    ) -> BenchmarkMeasurementRegistryAdmissionOutcome:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        authoritative_registry = BenchmarkMeasurementTrustRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
        authoritative_predecessor = (
            BenchmarkMeasurementTrustRegistry.model_validate(
                predecessor_registry.model_dump(mode="json", by_alias=True)
            )
            if predecessor_registry is not None
            else None
        )
        _require_registry_predecessor(
            authoritative_registry,
            authoritative_predecessor,
        )
        source = load_benchmark_target_run_authority(authoritative_manifest, target)
        key = resolve_benchmark_measurement_registry_key(
            authoritative_registry,
            key_id=source.trust_anchor.key_id,
            issued_at=source.attestation.statement.issued_at,
            mode=mode,
        )
        if key.trust_anchor != source.trust_anchor:
            raise BenchmarkMeasurementRegistryError(
                "P0-C1 Trust Anchor differs from the selected registry key"
            )
        snapshot = load_verified_run_artifacts(
            target.run_path,
            requests={target.authority_path: _MAX_ADMISSION_AUTHORITY_BYTES},
            expected_run_id=target.run_id,
        )
        source_bytes = snapshot.artifact_bytes(target.authority_path)
        admitted_at = datetime.now(UTC)
        if admitted_at < authoritative_registry.issued_at:
            raise BenchmarkMeasurementRegistryError(
                "Benchmark measurement registry revision has not been issued yet"
            )
        authority = BenchmarkMeasurementRegistryAdmissionAuthority(
            manifestDigest=authoritative_manifest.digest(),
            registry=authoritative_registry,
            predecessorRegistry=authoritative_predecessor,
            registryDigest=authoritative_registry.registry_digest,
            sourceRunId=target.run_id,
            sourceRootDigest=snapshot.verification.root_digest,
            sourceAuthorityPath="benchmark-target-run-authority.json",
            sourceAuthoritySha256=sha256(source_bytes).hexdigest(),
            sourceAuthorityDigest=source.authority_digest,
            sourceAttestationDigest=source.attestation.digest,
            measurementAuthorityId=source.trust_anchor.authority_id,
            measurementAuthorityVersion=source.trust_anchor.authority_version,
            measurementAuthorityDigest=source.trust_anchor.anchor_digest,
            keyId=key.key_id,
            keyState=key.state,
            admissionMode=mode,
            measurementAdmissionEligible=(
                mode is BenchmarkMeasurementAdmissionMode.FRESH_MEASUREMENT
            ),
            measurementIssuedAt=source.attestation.statement.issued_at,
            admittedAt=admitted_at,
        )
        return _seal_registry_admission(self._output_root, authority)


class BenchmarkRegistryTargetFactoryRunner:
    """Require the active registry key before provider reset and seal source admission after run."""

    def __init__(
        self,
        *,
        output_root: Path,
        target_runner: BenchmarkTargetRunExecutor,
        registry: BenchmarkMeasurementTrustRegistry,
        predecessor_registry: BenchmarkMeasurementTrustRegistry | None = None,
    ) -> None:
        self._output_root = output_root
        self._target_runner = target_runner
        self._registry = BenchmarkMeasurementTrustRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
        self._predecessor_registry = (
            BenchmarkMeasurementTrustRegistry.model_validate(
                predecessor_registry.model_dump(mode="json", by_alias=True)
            )
            if predecessor_registry is not None
            else None
        )
        _require_registry_predecessor(self._registry, self._predecessor_registry)

    async def run(
        self,
        manifest: BenchmarkManifest,
        *,
        arm_id: str,
        seed: int,
        repetition: int,
    ) -> BenchmarkRegistryBoundTargetRunOutcome:
        definition = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
            self._target_runner.definition.model_dump(mode="json", by_alias=True)
        )
        key = active_benchmark_measurement_registry_key(
            self._registry,
            adapter=definition,
            at=datetime.now(UTC),
        )
        if key.trust_anchor.anchor_digest != definition.measurement_authority_digest:
            raise BenchmarkMeasurementRegistryError(
                "Registry preflight selected a different measurement Trust Anchor"
            )
        target = await self._target_runner.run(
            manifest,
            arm_id=arm_id,
            seed=seed,
            repetition=repetition,
        )
        admission = BenchmarkMeasurementRegistryAdmissionRunner(
            output_root=self._output_root
        ).admit(
            manifest,
            target,
            self._registry,
            predecessor_registry=self._predecessor_registry,
            mode=BenchmarkMeasurementAdmissionMode.FRESH_MEASUREMENT,
        )
        return BenchmarkRegistryBoundTargetRunOutcome(target=target, admission=admission)


def verify_benchmark_measurement_registry_transition(
    previous: BenchmarkMeasurementTrustRegistry,
    current: BenchmarkMeasurementTrustRegistry,
) -> None:
    """Reject rollback, gaps, equivocation, key substitution, and lifecycle resurrection."""

    if (
        current.registry_id != previous.registry_id
        or current.measurement_authority_id != previous.measurement_authority_id
        or current.measurement_authority_version != previous.measurement_authority_version
    ):
        raise BenchmarkMeasurementRegistryError(
            "Benchmark measurement registry transition changes authority identity"
        )
    if (
        current.registry_revision != previous.registry_revision + 1
        or current.previous_registry_digest != previous.registry_digest
        or current.issued_at <= previous.issued_at
    ):
        raise BenchmarkMeasurementRegistryError(
            "Benchmark measurement registry rollback, gap, or predecessor mismatch"
        )
    current_by_id = {key.key_id: key for key in current.keys}
    previous_ids = {key.key_id for key in previous.keys}
    for old in previous.keys:
        new = current_by_id.get(old.key_id)
        if new is None or new.trust_anchor != old.trust_anchor or new.not_before != old.not_before:
            raise BenchmarkMeasurementRegistryError(
                "Benchmark measurement registry removes or substitutes an existing key"
            )
        _require_key_state_transition(old, new, transition_time=current.issued_at)
    for new in current.keys:
        if new.key_id not in previous_ids and (
            new.state is not BenchmarkMeasurementKeyState.ACTIVE
            or new.not_before > current.issued_at
        ):
            raise BenchmarkMeasurementRegistryError(
                "Benchmark measurement registry adds a non-active or not-yet-valid key"
            )


def _require_registry_predecessor(
    registry: BenchmarkMeasurementTrustRegistry,
    predecessor: BenchmarkMeasurementTrustRegistry | None,
) -> None:
    if registry.registry_revision == 1:
        if predecessor is not None:
            raise BenchmarkMeasurementRegistryError(
                "Benchmark measurement registry revision one cannot have a predecessor"
            )
        return
    if predecessor is None:
        raise BenchmarkMeasurementRegistryError(
            "Benchmark measurement registry admission requires its exact predecessor"
        )
    verify_benchmark_measurement_registry_transition(predecessor, registry)


def resolve_benchmark_measurement_registry_key(
    registry: BenchmarkMeasurementTrustRegistry,
    *,
    key_id: str,
    issued_at: datetime,
    mode: BenchmarkMeasurementAdmissionMode,
) -> BenchmarkMeasurementRegistryKey:
    """Resolve one exact key under fresh or historical admission semantics."""

    timestamp = _aware_utc(issued_at, label="Benchmark measurement issue time")
    key = registry.key(key_id)
    if key.state is BenchmarkMeasurementKeyState.REVOKED:
        raise BenchmarkMeasurementRegistryError("Benchmark measurement key is revoked")
    if timestamp < key.not_before or (
        key.not_after is not None and timestamp >= key.not_after
    ):
        raise BenchmarkMeasurementRegistryError(
            "Benchmark measurement was issued outside the registry key validity window"
        )
    if mode is BenchmarkMeasurementAdmissionMode.FRESH_MEASUREMENT:
        if key.state is not BenchmarkMeasurementKeyState.ACTIVE:
            raise BenchmarkMeasurementRegistryError(
                "Fresh Benchmark measurement requires the active registry key"
            )
        if timestamp < registry.issued_at:
            raise BenchmarkMeasurementRegistryError(
                "Fresh Benchmark measurement predates its registry revision"
            )
    return key


def active_benchmark_measurement_registry_key(
    registry: BenchmarkMeasurementTrustRegistry,
    *,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    at: datetime,
) -> BenchmarkMeasurementRegistryKey:
    """Preflight exact active measurement authority before any provider side effect."""

    timestamp = _aware_utc(at, label="Benchmark registry preflight time")
    key = registry.active_key
    anchor = key.trust_anchor
    if timestamp < registry.issued_at or timestamp < key.not_before or (
        key.not_after is not None and timestamp >= key.not_after
    ):
        raise BenchmarkMeasurementRegistryError(
            "Active Benchmark measurement registry key is not currently valid"
        )
    if (
        adapter.measurement_authority_id != anchor.authority_id
        or adapter.measurement_authority_version != anchor.authority_version
        or adapter.measurement_authority_digest != anchor.anchor_digest
    ):
        raise BenchmarkMeasurementRegistryError(
            "Target Factory adapter does not use the active measurement registry key"
        )
    return key


def load_benchmark_measurement_registry_admission(
    manifest: BenchmarkManifest,
    target: BenchmarkTargetRunOutcome,
    outcome: BenchmarkMeasurementRegistryAdmissionOutcome,
) -> BenchmarkMeasurementRegistryAdmissionAuthority:
    """Reopen the source P0-C1 Run and exact sealed registry admission together."""

    try:
        source = load_benchmark_target_run_authority(manifest, target)
        source_snapshot = load_verified_run_artifacts(
            target.run_path,
            requests={target.authority_path: _MAX_ADMISSION_AUTHORITY_BYTES},
            expected_run_id=target.run_id,
        )
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                _REGISTRY_ARTIFACT: 2 * 1024 * 1024,
                _ADMISSION_AUTHORITY_ARTIFACT: _MAX_ADMISSION_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        registry = BenchmarkMeasurementTrustRegistry.model_validate_json(
            snapshot.artifact_bytes(_REGISTRY_ARTIFACT)
        )
        authority = BenchmarkMeasurementRegistryAdmissionAuthority.model_validate_json(
            snapshot.artifact_bytes(_ADMISSION_AUTHORITY_ARTIFACT)
        )
    except (
        BenchmarkTargetFactoryError,
        OSError,
        RunIntegrityError,
        ValidationError,
        ValueError,
    ) as exc:
        raise BenchmarkMeasurementRegistryError(
            "P0-C2B1 sealed Benchmark Measurement Registry Admission could not be verified"
        ) from exc
    source_bytes = source_snapshot.artifact_bytes(target.authority_path)
    if (
        outcome.authority_path != _ADMISSION_AUTHORITY_ARTIFACT
        or outcome.authority != authority
        or registry != authority.registry
        or authority.manifest_digest != manifest.digest()
        or authority.source_run_id != target.run_id
        or authority.source_root_digest != source_snapshot.verification.root_digest
        or authority.source_authority_path != target.authority_path
        or authority.source_authority_sha256 != sha256(source_bytes).hexdigest()
        or authority.source_authority_digest != source.authority_digest
        or authority.source_attestation_digest != source.attestation.digest
        or authority.measurement_authority_digest != source.trust_anchor.anchor_digest
        or authority.key_id != source.trust_anchor.key_id
    ):
        raise BenchmarkMeasurementRegistryError(
            "Benchmark Measurement Registry Admission differs from its source Run"
        )
    expected_types = [
        "campaign.started",
        "benchmark.measurement-registry.admitted",
        "campaign.completed",
    ]
    if [event.event_type for event in snapshot.events] != expected_types:
        raise BenchmarkMeasurementRegistryError(
            "Benchmark Measurement Registry Admission audit sequence differs"
        )
    if snapshot.events[1].payload != _admission_event_payload(
        _ADMISSION_AUTHORITY_ARTIFACT,
        authority,
    ) or snapshot.events[0].payload != {
        "purpose": "benchmark-measurement-registry-admission",
        "sourceRunId": authority.source_run_id,
    } or snapshot.events[2].payload != {
        "purpose": "benchmark-measurement-registry-admission",
        "artifact": _ADMISSION_AUTHORITY_ARTIFACT,
    }:
        raise BenchmarkMeasurementRegistryError(
            "Benchmark Measurement Registry Admission event differs"
        )
    return authority.model_copy(deep=True)


def _require_key_state_transition(
    old: BenchmarkMeasurementRegistryKey,
    new: BenchmarkMeasurementRegistryKey,
    *,
    transition_time: datetime,
) -> None:
    allowed = {
        BenchmarkMeasurementKeyState.ACTIVE: {
            BenchmarkMeasurementKeyState.ACTIVE,
            BenchmarkMeasurementKeyState.RETIRED,
            BenchmarkMeasurementKeyState.REVOKED,
        },
        BenchmarkMeasurementKeyState.RETIRED: {
            BenchmarkMeasurementKeyState.RETIRED,
            BenchmarkMeasurementKeyState.REVOKED,
        },
        BenchmarkMeasurementKeyState.REVOKED: {BenchmarkMeasurementKeyState.REVOKED},
    }
    if new.state not in allowed[old.state]:
        raise BenchmarkMeasurementRegistryError(
            "Benchmark measurement registry resurrects a retired or revoked key"
        )
    if old.state is new.state and (
        new.not_after != old.not_after or new.revoked_at != old.revoked_at
    ):
        raise BenchmarkMeasurementRegistryError(
            "Benchmark measurement registry rewrites unchanged lifecycle metadata"
        )
    if new.state is BenchmarkMeasurementKeyState.RETIRED and (
        new.not_after is None or new.not_after > transition_time
    ):
        raise BenchmarkMeasurementRegistryError(
            "Benchmark measurement key retirement cutoff exceeds transition time"
        )
    if new.state is BenchmarkMeasurementKeyState.REVOKED and (
        new.revoked_at is None or new.revoked_at > transition_time
    ):
        raise BenchmarkMeasurementRegistryError(
            "Benchmark measurement key revocation postdates transition"
        )


def _seal_registry_admission(
    output_root: Path,
    authority: BenchmarkMeasurementRegistryAdmissionAuthority,
) -> BenchmarkMeasurementRegistryAdmissionOutcome:
    store = RunStore.create(output_root, "benchmark-measurement-registry")
    store.append_event(
        "campaign.started",
        {
            "purpose": "benchmark-measurement-registry-admission",
            "sourceRunId": authority.source_run_id,
        },
        occurred_at=authority.admitted_at,
    )
    store.write_json(
        _REGISTRY_ARTIFACT,
        authority.registry.model_dump(mode="json", by_alias=True),
    )
    authority_path = store.write_json(
        _ADMISSION_AUTHORITY_ARTIFACT,
        authority.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "benchmark.measurement-registry.admitted",
        _admission_event_payload(authority_path, authority),
        occurred_at=authority.admitted_at,
    )
    store.write_json(
        "run.json",
        {
            "runId": store.run_id,
            "status": "completed",
            "stage": "benchmark-measurement-registry-admitted",
            "authorityId": authority.authority_id,
        },
    )
    store.append_event(
        "campaign.completed",
        {
            "purpose": "benchmark-measurement-registry-admission",
            "artifact": authority_path,
        },
        occurred_at=authority.admitted_at,
    )
    store.seal()
    return BenchmarkMeasurementRegistryAdmissionOutcome(
        run_id=store.run_id,
        run_path=store.path,
        authority_path=authority_path,
        authority=authority.model_copy(deep=True),
    )


def _admission_event_payload(
    artifact_path: str,
    authority: BenchmarkMeasurementRegistryAdmissionAuthority,
) -> dict[str, object]:
    return {
        "artifact": artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "registryId": authority.registry.registry_id,
        "registryRevision": authority.registry.registry_revision,
        "registryDigest": authority.registry_digest,
        "sourceRunId": authority.source_run_id,
        "keyId": authority.key_id,
        "keyState": authority.key_state.value,
        "admissionMode": authority.admission_mode.value,
        "measurementAdmissionEligible": authority.measurement_admission_eligible,
    }


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires UTC offset")
    return value.astimezone(UTC)
