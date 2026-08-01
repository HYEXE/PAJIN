"""P0-C2B2A2 mandatory sealed registry-governed Benchmark Harness."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.measurement import WalkingBenchmarkRunObservationOutcome
from pajin.benchmark.measurement_registry import (
    BenchmarkMeasurementAdmissionMode,
    BenchmarkMeasurementRegistryAdmissionAuthority,
    BenchmarkMeasurementRegistryAdmissionOutcome,
    BenchmarkMeasurementRegistryError,
    BenchmarkRegistryTargetFactoryRunner,
    BenchmarkTargetRunExecutor,
    load_benchmark_measurement_registry_admission,
)
from pajin.benchmark.measurement_registry_distribution import (
    BenchmarkMeasurementRegistryActivation,
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionBundle,
    BenchmarkMeasurementRegistryDistributionError,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    verify_benchmark_measurement_registry_distribution_bundle,
)
from pajin.benchmark.models import BenchmarkManifest, benchmark_digest
from pajin.benchmark.target_factory import (
    BenchmarkTargetFactoryError,
    BenchmarkTargetRunOutcome,
    load_benchmark_target_run_authority,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

BENCHMARK_REGISTRY_GOVERNED_HARNESS_API_VERSION: Literal[
    "pajin.dev/benchmark-registry-governed-harness/v1alpha1"
] = "pajin.dev/benchmark-registry-governed-harness/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ACTIVATION_ARTIFACT = "benchmark-measurement-registry-activation.json"
_HARNESS_AUTHORITY_ARTIFACT = "benchmark-registry-governed-harness-authority.json"
_TARGET_AUTHORITY_ARTIFACT: Literal["benchmark-target-run-authority.json"] = (
    "benchmark-target-run-authority.json"
)
_REGISTRY_ADMISSION_ARTIFACT: Literal[
    "benchmark-measurement-registry-admission.json"
] = "benchmark-measurement-registry-admission.json"
_MAX_SOURCE_BYTES = 32 * 1024 * 1024
_MAX_HARNESS_AUTHORITY_BYTES = 48 * 1024 * 1024


class BenchmarkRegistryGovernedHarnessError(RuntimeError):
    """Raised when a measurement cannot claim registry-governed admission."""


class BenchmarkRegistryGovernedHarnessAuthority(StrictModel):
    """Complete binding from signed activation to exact target and admission Runs."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-registry-governed-harness/v1alpha1"] = (
        Field(
            default=BENCHMARK_REGISTRY_GOVERNED_HARNESS_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["BenchmarkRegistryGovernedHarnessAuthority"] = (
        "BenchmarkRegistryGovernedHarnessAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor = Field(
        alias="distributionTrustAnchor"
    )
    activation: BenchmarkMeasurementRegistryActivation
    registry_admission_authority: BenchmarkMeasurementRegistryAdmissionAuthority = Field(
        alias="registryAdmissionAuthority"
    )
    target_run_id: _Identifier = Field(alias="targetRunId")
    target_root_digest: _Sha256 = Field(alias="targetRootDigest")
    target_authority_path: Literal["benchmark-target-run-authority.json"] = Field(
        default=_TARGET_AUTHORITY_ARTIFACT,
        alias="targetAuthorityPath",
    )
    target_authority_sha256: _Sha256 = Field(alias="targetAuthoritySha256")
    target_authority_digest: _Sha256 = Field(alias="targetAuthorityDigest")
    target_attestation_digest: _Sha256 = Field(alias="targetAttestationDigest")
    observation_digest: _Sha256 = Field(alias="observationDigest")
    admission_run_id: _Identifier = Field(alias="admissionRunId")
    admission_root_digest: _Sha256 = Field(alias="admissionRootDigest")
    admission_authority_path: Literal[
        "benchmark-measurement-registry-admission.json"
    ] = Field(
        default=_REGISTRY_ADMISSION_ARTIFACT,
        alias="admissionAuthorityPath",
    )
    admission_authority_sha256: _Sha256 = Field(alias="admissionAuthoritySha256")
    sealed_at: datetime = Field(alias="sealedAt")
    measurement_admission_eligible: Literal[True] = Field(
        default=True,
        alias="measurementAdmissionEligible",
    )

    @field_validator("sealed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Benchmark registry-governed Harness timestamp requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        admission = self.registry_admission_authority
        statement = self.activation.bundle.statement
        try:
            verify_benchmark_measurement_registry_distribution_bundle(
                self.activation.bundle,
                trust_anchor=self.distribution_trust_anchor,
                now=self.sealed_at,
            )
        except BenchmarkMeasurementRegistryDistributionError as exc:
            raise ValueError("Benchmark Harness distribution authority is invalid") from exc
        if (
            self.activation.trust_anchor_digest
            != self.distribution_trust_anchor.anchor_digest
            or admission.manifest_digest != self.manifest_digest
            or admission.registry != statement.registry
            or admission.predecessor_registry != statement.predecessor_registry
            or admission.registry_digest != statement.registry.registry_digest
            or admission.admission_mode
            is not BenchmarkMeasurementAdmissionMode.FRESH_MEASUREMENT
            or not admission.measurement_admission_eligible
            or self.target_run_id != admission.source_run_id
            or self.target_root_digest != admission.source_root_digest
            or self.target_authority_path != admission.source_authority_path
            or self.target_authority_sha256 != admission.source_authority_sha256
            or self.target_authority_digest != admission.source_authority_digest
            or self.target_attestation_digest != admission.source_attestation_digest
            or self.sealed_at < self.activation.activated_at
            or self.sealed_at < admission.admitted_at
        ):
            raise ValueError("Benchmark Registry-Governed Harness Authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.registry-governed-harness/v1",
            material,
            max_bytes=_MAX_HARNESS_AUTHORITY_BYTES,
        )
        authority_id = f"benchmark-registry-harness:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Benchmark Registry-Governed Harness Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Benchmark Registry-Governed Harness ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


@dataclass(frozen=True, slots=True)
class BenchmarkRegistryGovernedHarnessOutcome:
    target: BenchmarkTargetRunOutcome
    admission: BenchmarkMeasurementRegistryAdmissionOutcome
    run_id: str
    run_path: Path
    authority_path: str
    authority: BenchmarkRegistryGovernedHarnessAuthority


class BenchmarkRegistryGovernedHarnessRunner:
    """Activate before reset and publish only a fully verified registry-governed outcome."""

    def __init__(
        self,
        *,
        output_root: Path,
        activation_store: BenchmarkMeasurementRegistryActivationStore,
        bundle: BenchmarkMeasurementRegistryDistributionBundle,
        distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
        target_runner: BenchmarkTargetRunExecutor,
    ) -> None:
        self._output_root = output_root
        self._activation_store = activation_store
        try:
            self._bundle = BenchmarkMeasurementRegistryDistributionBundle.model_validate(
                bundle.model_dump(mode="json", by_alias=True)
            )
            self._distribution_trust_anchor = (
                BenchmarkMeasurementRegistryDistributionTrustAnchor.model_validate(
                    distribution_trust_anchor.model_dump(mode="json", by_alias=True)
                )
            )
        except ValueError as exc:
            raise BenchmarkRegistryGovernedHarnessError(
                "Benchmark Harness distribution input is structurally invalid"
            ) from exc
        self._target_runner = target_runner

    async def run(
        self,
        manifest: BenchmarkManifest,
        *,
        arm_id: str,
        seed: int,
        repetition: int,
    ) -> BenchmarkRegistryGovernedHarnessOutcome:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        try:
            activation = self._activation_store.activate(
                self._bundle,
                trust_anchor=self._distribution_trust_anchor,
                now=datetime.now(UTC),
            )
        except BenchmarkMeasurementRegistryDistributionError as exc:
            raise BenchmarkRegistryGovernedHarnessError(
                "Benchmark Harness registry activation failed before provider reset"
            ) from exc
        statement = activation.bundle.statement
        bound = await BenchmarkRegistryTargetFactoryRunner(
            output_root=self._output_root,
            target_runner=self._target_runner,
            registry=statement.registry,
            predecessor_registry=statement.predecessor_registry,
        ).run(
            authoritative_manifest,
            arm_id=arm_id,
            seed=seed,
            repetition=repetition,
        )
        try:
            target_authority = load_benchmark_target_run_authority(
                authoritative_manifest,
                bound.target,
            )
            admission_authority = load_benchmark_measurement_registry_admission(
                authoritative_manifest,
                bound.target,
                bound.admission,
            )
            sealed_at = datetime.now(UTC)
            verify_benchmark_measurement_registry_distribution_bundle(
                activation.bundle,
                trust_anchor=self._distribution_trust_anchor,
                now=sealed_at,
            )
            latest = self._activation_store.latest(
                trust_domain=statement.trust_domain,
                issuer=statement.issuer,
                registry_id=statement.registry.registry_id,
            )
            if latest != activation:
                raise BenchmarkRegistryGovernedHarnessError(
                    "Benchmark Harness activation changed during provider execution"
                )
            target_snapshot = load_verified_run_artifacts(
                bound.target.run_path,
                requests={bound.target.authority_path: _MAX_SOURCE_BYTES},
                expected_run_id=bound.target.run_id,
            )
            admission_snapshot = load_verified_run_artifacts(
                bound.admission.run_path,
                requests={bound.admission.authority_path: _MAX_SOURCE_BYTES},
                expected_run_id=bound.admission.run_id,
            )
        except (
            BenchmarkMeasurementRegistryDistributionError,
            BenchmarkMeasurementRegistryError,
            BenchmarkRegistryGovernedHarnessError,
            BenchmarkTargetFactoryError,
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
        ) as exc:
            if isinstance(exc, BenchmarkRegistryGovernedHarnessError):
                raise
            raise BenchmarkRegistryGovernedHarnessError(
                "Benchmark Harness source authority verification failed"
            ) from exc
        target_bytes = target_snapshot.artifact_bytes(bound.target.authority_path)
        admission_bytes = admission_snapshot.artifact_bytes(bound.admission.authority_path)
        authority = BenchmarkRegistryGovernedHarnessAuthority(
            manifestDigest=authoritative_manifest.digest(),
            distributionTrustAnchor=self._distribution_trust_anchor,
            activation=activation,
            registryAdmissionAuthority=admission_authority,
            targetRunId=bound.target.run_id,
            targetRootDigest=target_snapshot.verification.root_digest,
            targetAuthorityPath=_TARGET_AUTHORITY_ARTIFACT,
            targetAuthoritySha256=sha256(target_bytes).hexdigest(),
            targetAuthorityDigest=target_authority.authority_digest,
            targetAttestationDigest=target_authority.attestation.digest,
            observationDigest=target_authority.observation.observation_digest,
            admissionRunId=bound.admission.run_id,
            admissionRootDigest=admission_snapshot.verification.root_digest,
            admissionAuthorityPath=_REGISTRY_ADMISSION_ARTIFACT,
            admissionAuthoritySha256=sha256(admission_bytes).hexdigest(),
            sealedAt=sealed_at,
        )
        return _seal_harness_authority(
            self._output_root,
            bound.target,
            bound.admission,
            authority,
        )


def load_registry_governed_benchmark_observation(
    manifest: BenchmarkManifest,
    outcome: BenchmarkRegistryGovernedHarnessOutcome,
    *,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> WalkingBenchmarkRunObservationOutcome:
    """Return an Observation only after every mandatory sealed authority re-verifies."""

    try:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        target = load_benchmark_target_run_authority(authoritative_manifest, outcome.target)
        admission = load_benchmark_measurement_registry_admission(
            authoritative_manifest,
            outcome.target,
            outcome.admission,
        )
        target_snapshot = load_verified_run_artifacts(
            outcome.target.run_path,
            requests={outcome.target.authority_path: _MAX_SOURCE_BYTES},
            expected_run_id=outcome.target.run_id,
        )
        admission_snapshot = load_verified_run_artifacts(
            outcome.admission.run_path,
            requests={outcome.admission.authority_path: _MAX_SOURCE_BYTES},
            expected_run_id=outcome.admission.run_id,
        )
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                _ACTIVATION_ARTIFACT: _MAX_SOURCE_BYTES,
                _HARNESS_AUTHORITY_ARTIFACT: _MAX_HARNESS_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_activation = BenchmarkMeasurementRegistryActivation.model_validate_json(
            snapshot.artifact_bytes(_ACTIVATION_ARTIFACT)
        )
        authority = BenchmarkRegistryGovernedHarnessAuthority.model_validate_json(
            snapshot.artifact_bytes(_HARNESS_AUTHORITY_ARTIFACT)
        )
        authoritative_distribution_anchor = (
            BenchmarkMeasurementRegistryDistributionTrustAnchor.model_validate(
                distribution_trust_anchor.model_dump(mode="json", by_alias=True)
            )
        )
        verify_benchmark_measurement_registry_distribution_bundle(
            authority.activation.bundle,
            trust_anchor=authoritative_distribution_anchor,
            now=authority.sealed_at,
        )
        statement = authority.activation.bundle.statement
        durable_activation = activation_store.get(
            trust_domain=statement.trust_domain,
            issuer=statement.issuer,
            registry_id=statement.registry.registry_id,
            revision=statement.registry.registry_revision,
        )
    except (
        BenchmarkMeasurementRegistryDistributionError,
        BenchmarkMeasurementRegistryError,
        BenchmarkTargetFactoryError,
        OSError,
        RunIntegrityError,
        ValidationError,
        ValueError,
    ) as exc:
        raise BenchmarkRegistryGovernedHarnessError(
            "P0-C2B2A2 sealed Benchmark Harness could not be verified"
        ) from exc
    target_bytes = target_snapshot.artifact_bytes(outcome.target.authority_path)
    admission_bytes = admission_snapshot.artifact_bytes(outcome.admission.authority_path)
    if (
        outcome.authority_path != _HARNESS_AUTHORITY_ARTIFACT
        or outcome.authority != authority
        or sealed_activation != authority.activation
        or durable_activation != authority.activation
        or authority.distribution_trust_anchor != authoritative_distribution_anchor
        or authority.manifest_digest != authoritative_manifest.digest()
        or authority.registry_admission_authority != admission
        or authority.target_run_id != outcome.target.run_id
        or authority.target_root_digest != target_snapshot.verification.root_digest
        or authority.target_authority_path != outcome.target.authority_path
        or authority.target_authority_sha256 != sha256(target_bytes).hexdigest()
        or authority.target_authority_digest != target.authority_digest
        or authority.target_attestation_digest != target.attestation.digest
        or authority.observation_digest != target.observation.observation_digest
        or authority.admission_run_id != outcome.admission.run_id
        or authority.admission_root_digest != admission_snapshot.verification.root_digest
        or authority.admission_authority_path != outcome.admission.authority_path
        or authority.admission_authority_sha256 != sha256(admission_bytes).hexdigest()
    ):
        raise BenchmarkRegistryGovernedHarnessError(
            "Benchmark Registry-Governed Harness differs from its source authorities"
        )
    if [event.event_type for event in snapshot.events] != [
        "campaign.started",
        "benchmark.registry-governed-harness.admitted",
        "campaign.completed",
    ]:
        raise BenchmarkRegistryGovernedHarnessError(
            "Benchmark Registry-Governed Harness audit sequence differs"
        )
    if snapshot.events[0].payload != {
        "purpose": "benchmark-registry-governed-harness",
        "targetRunId": authority.target_run_id,
        "admissionRunId": authority.admission_run_id,
    } or snapshot.events[1].payload != _harness_event_payload(
        _HARNESS_AUTHORITY_ARTIFACT,
        authority,
    ) or snapshot.events[2].payload != {
        "purpose": "benchmark-registry-governed-harness",
        "artifact": _HARNESS_AUTHORITY_ARTIFACT,
    }:
        raise BenchmarkRegistryGovernedHarnessError(
            "Benchmark Registry-Governed Harness audit event differs"
        )
    return WalkingBenchmarkRunObservationOutcome(
        run_id=outcome.target.run_id,
        run_path=outcome.target.run_path,
        artifact_path=outcome.target.observation_path,
        observation=target.observation.model_copy(deep=True),
    )


def _seal_harness_authority(
    output_root: Path,
    target: BenchmarkTargetRunOutcome,
    admission: BenchmarkMeasurementRegistryAdmissionOutcome,
    authority: BenchmarkRegistryGovernedHarnessAuthority,
) -> BenchmarkRegistryGovernedHarnessOutcome:
    store = RunStore.create(output_root, "benchmark-registry-harness")
    store.append_event(
        "campaign.started",
        {
            "purpose": "benchmark-registry-governed-harness",
            "targetRunId": authority.target_run_id,
            "admissionRunId": authority.admission_run_id,
        },
        occurred_at=authority.sealed_at,
    )
    store.write_json(
        _ACTIVATION_ARTIFACT,
        authority.activation.model_dump(mode="json", by_alias=True),
    )
    authority_path = store.write_json(
        _HARNESS_AUTHORITY_ARTIFACT,
        authority.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "benchmark.registry-governed-harness.admitted",
        _harness_event_payload(authority_path, authority),
        occurred_at=authority.sealed_at,
    )
    store.write_json(
        "run.json",
        {
            "runId": store.run_id,
            "status": "completed",
            "stage": "benchmark-registry-governed-harness-admitted",
            "authorityId": authority.authority_id,
        },
    )
    store.append_event(
        "campaign.completed",
        {
            "purpose": "benchmark-registry-governed-harness",
            "artifact": authority_path,
        },
        occurred_at=authority.sealed_at,
    )
    store.seal()
    return BenchmarkRegistryGovernedHarnessOutcome(
        target=target,
        admission=admission,
        run_id=store.run_id,
        run_path=store.path,
        authority_path=authority_path,
        authority=authority.model_copy(deep=True),
    )


def _harness_event_payload(
    artifact_path: str,
    authority: BenchmarkRegistryGovernedHarnessAuthority,
) -> dict[str, object]:
    statement = authority.activation.bundle.statement
    return {
        "artifact": artifact_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "activationDigest": authority.activation.activation_digest,
        "bundleDigest": authority.activation.bundle_digest,
        "registryId": statement.registry.registry_id,
        "registryRevision": statement.registry.registry_revision,
        "targetRunId": authority.target_run_id,
        "admissionRunId": authority.admission_run_id,
        "observationDigest": authority.observation_digest,
        "measurementAdmissionEligible": True,
    }
