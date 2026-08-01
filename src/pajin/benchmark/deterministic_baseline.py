"""P0-E1 sealed deterministic PAJIN baseline measurement authority."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.benchmark.docker_provider import DockerBenchmarkProviderEvidence
from pajin.benchmark.measurement import (
    WalkingBenchmarkRunObservation,
    aggregate_walking_benchmark_metrics,
)
from pajin.benchmark.measurement_harness import (
    BenchmarkRegistryGovernedHarnessError,
    BenchmarkRegistryGovernedHarnessOutcome,
    load_registry_governed_benchmark_observation,
)
from pajin.benchmark.measurement_registry_distribution import (
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
)
from pajin.benchmark.models import (
    BenchmarkArmKind,
    BenchmarkEvidenceReference,
    BenchmarkManifest,
    BenchmarkResult,
    BenchmarkResultStatus,
    BenchmarkRunBinding,
    benchmark_digest,
    canonical_benchmark_json,
)
from pajin.benchmark.target_catalog import (
    BenchmarkTargetCatalogError,
    BenchmarkTargetProfileSelectionAuthority,
    CatalogBoundDockerBugBountyTargetFactoryAdapter,
)
from pajin.benchmark.target_factory import (
    BenchmarkTargetFactoryError,
    load_benchmark_target_run_authority,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

DETERMINISTIC_BASELINE_SOURCE_BINDING_API_VERSION: Literal[
    "pajin.dev/deterministic-baseline-source-binding/v1alpha1"
] = "pajin.dev/deterministic-baseline-source-binding/v1alpha1"
DETERMINISTIC_BASELINE_MEASUREMENT_API_VERSION: Literal[
    "pajin.dev/deterministic-baseline-measurement/v1alpha1"
] = "pajin.dev/deterministic-baseline-measurement/v1alpha1"

_Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_HARNESS_AUTHORITY_ARTIFACT = "benchmark-registry-governed-harness-authority.json"
_MANIFEST_ARTIFACT = "benchmark-manifest.json"
_CATALOG_SELECTION_ARTIFACT = "benchmark-target-catalog-selection.json"
_SOURCE_BINDINGS_ARTIFACT = "deterministic-baseline-source-bindings.json"
_OBSERVATION_BUNDLE_ARTIFACT = "evidence/deterministic-baseline-observations.json"
_RESULT_ARTIFACT = "deterministic-baseline-result.json"
_AUTHORITY_ARTIFACT = "deterministic-baseline-measurement-authority.json"
_MAX_SOURCE_AUTHORITY_BYTES = 48 * 1024 * 1024
_MAX_BINDING_BYTES = 2 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 32 * 1024 * 1024
_MAX_RESULT_BYTES = 4 * 1024 * 1024
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024


class DeterministicBaselineMeasurementError(RuntimeError):
    """Raised when deterministic baseline sources or publication fail closed."""


class DeterministicBaselineSourceBinding(StrictModel):
    """One verified registry-governed raw Observation and its sealed provenance."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/deterministic-baseline-source-binding/v1alpha1"
    ] = Field(
        default=DETERMINISTIC_BASELINE_SOURCE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DeterministicBaselineSourceBinding"] = (
        "DeterministicBaselineSourceBinding"
    )
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    harness_run_id: _Identifier = Field(alias="harnessRunId")
    harness_root_digest: _Sha256 = Field(alias="harnessRootDigest")
    harness_authority_sha256: _Sha256 = Field(alias="harnessAuthoritySha256")
    harness_authority_digest: _Sha256 = Field(alias="harnessAuthorityDigest")
    activation_digest: _Sha256 = Field(alias="activationDigest")
    registry_admission_authority_digest: _Sha256 = Field(
        alias="registryAdmissionAuthorityDigest"
    )
    target_run_id: _Identifier = Field(alias="targetRunId")
    target_root_digest: _Sha256 = Field(alias="targetRootDigest")
    target_authority_sha256: _Sha256 = Field(alias="targetAuthoritySha256")
    target_authority_digest: _Sha256 = Field(alias="targetAuthorityDigest")
    target_attestation_digest: _Sha256 = Field(alias="targetAttestationDigest")
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    target_coordinate_digest: _Sha256 = Field(alias="targetCoordinateDigest")
    execution_receipt_digest: _Sha256 = Field(alias="executionReceiptDigest")
    execution_operation_id: _Identifier = Field(alias="executionOperationId")
    execution_provider_evidence_digest: _Sha256 = Field(
        alias="executionProviderEvidenceDigest"
    )
    provider_evidence: DockerBenchmarkProviderEvidence = Field(alias="providerEvidence")
    observation: WalkingBenchmarkRunObservation

    @model_validator(mode="after")
    def bind_source(self) -> Self:
        if (
            self.provider_evidence.stage != "execution"
            or self.provider_evidence.adapter_digest != self.adapter_digest
            or self.provider_evidence.coordinate_digest != self.target_coordinate_digest
            or self.provider_evidence.operation_id != self.execution_operation_id
            or self.provider_evidence.evidence_digest
            != self.execution_provider_evidence_digest
        ):
            raise ValueError("Deterministic Baseline provider evidence differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.deterministic-baseline-source-binding/v1",
            material,
            max_bytes=_MAX_BINDING_BYTES,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Deterministic Baseline Source Binding Digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


class DeterministicBaselineMeasurementAuthority(StrictModel):
    """Exact catalog, source, and computed baseline Result in one sealed authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/deterministic-baseline-measurement/v1alpha1"
    ] = Field(
        default=DETERMINISTIC_BASELINE_MEASUREMENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DeterministicBaselineMeasurementAuthority"] = (
        "DeterministicBaselineMeasurementAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    manifest: BenchmarkManifest
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    catalog_selection: BenchmarkTargetProfileSelectionAuthority = Field(
        alias="catalogSelection"
    )
    sources: tuple[DeterministicBaselineSourceBinding, ...] = Field(
        min_length=1,
        max_length=2_000,
    )
    baseline_result: BenchmarkResult = Field(alias="baselineResult")
    baseline_result_digest: _Sha256 = Field(alias="baselineResultDigest")
    measurement_state: Literal[
        "registry-governed-deterministic-baseline-measured"
    ] = Field(
        default="registry-governed-deterministic-baseline-measured",
        alias="measurementState",
    )
    candidate_comparison_eligible: Literal[False] = Field(
        default=False,
        alias="candidateComparisonEligible",
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False,
        alias="supervisorActivationEligible",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        canonical_sources = _canonical_sources(
            self.manifest,
            self.catalog_selection,
            self.sources,
        )
        expected_result = _build_baseline_result(
            self.manifest,
            canonical_sources,
            catalog_selection_digest=self.catalog_selection.authority_digest,
        )
        if (
            self.manifest_digest != self.manifest.digest()
            or self.sources != canonical_sources
            or self.baseline_result != expected_result
            or self.baseline_result_digest != expected_result.digest()
        ):
            raise ValueError("Deterministic Baseline Measurement Authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        canonical_benchmark_json(
            material,
            label="DeterministicBaselineMeasurementAuthority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.deterministic-baseline-measurement/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"deterministic-baseline-measurement:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Deterministic Baseline Measurement Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Deterministic Baseline Measurement Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


@dataclass(frozen=True, slots=True)
class DeterministicBaselineMeasurementOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    result_path: str
    source_bindings_path: str
    observation_bundle_path: str
    authority: DeterministicBaselineMeasurementAuthority


class DeterministicBaselineMeasurementRunner:
    """Reopen exact governed sources and seal one baseline-only Result."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        manifest: BenchmarkManifest,
        *,
        catalog_provider: CatalogBoundDockerBugBountyTargetFactoryAdapter,
        source_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
        activation_store: BenchmarkMeasurementRegistryActivationStore,
        distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
    ) -> DeterministicBaselineMeasurementOutcome:
        try:
            authoritative_manifest = BenchmarkManifest.model_validate(
                manifest.model_dump(mode="json", by_alias=True)
            )
            selection = catalog_provider.selection
            sources = tuple(
                _load_source_binding(
                    authoritative_manifest,
                    outcome,
                    catalog_provider=catalog_provider,
                    activation_store=activation_store,
                    distribution_trust_anchor=distribution_trust_anchor,
                )
                for outcome in source_outcomes
            )
            canonical_sources = _canonical_sources(
                authoritative_manifest,
                selection,
                sources,
            )
            result = _build_baseline_result(
                authoritative_manifest,
                canonical_sources,
                catalog_selection_digest=selection.authority_digest,
            )
            authority = DeterministicBaselineMeasurementAuthority(
                manifest=authoritative_manifest,
                manifestDigest=authoritative_manifest.digest(),
                catalogSelection=selection,
                sources=canonical_sources,
                baselineResult=result,
                baselineResultDigest=result.digest(),
            )
        except (
            BenchmarkRegistryGovernedHarnessError,
            BenchmarkTargetCatalogError,
            BenchmarkTargetFactoryError,
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
        ) as exc:
            raise DeterministicBaselineMeasurementError(
                "Deterministic PAJIN baseline measurement source verification failed"
            ) from exc
        return _seal_authority(self._output_root, authority)


def load_deterministic_baseline_measurement_authority(
    manifest: BenchmarkManifest,
    outcome: DeterministicBaselineMeasurementOutcome,
    *,
    catalog_provider: CatalogBoundDockerBugBountyTargetFactoryAdapter,
    source_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> DeterministicBaselineMeasurementAuthority:
    """Reopen result and every governed source before returning measured authority."""

    try:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        selection = catalog_provider.selection
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                _MANIFEST_ARTIFACT: 256 * 1024,
                _CATALOG_SELECTION_ARTIFACT: 512 * 1024,
                outcome.source_bindings_path: _MAX_AUTHORITY_BYTES,
                outcome.observation_bundle_path: _MAX_BUNDLE_BYTES,
                outcome.result_path: _MAX_RESULT_BYTES,
                outcome.authority_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_manifest = BenchmarkManifest.model_validate_json(
            snapshot.artifact_bytes(_MANIFEST_ARTIFACT)
        )
        sealed_selection = BenchmarkTargetProfileSelectionAuthority.model_validate_json(
            snapshot.artifact_bytes(_CATALOG_SELECTION_ARTIFACT)
        )
        sealed_sources = _parse_source_bindings(
            snapshot.artifact_bytes(outcome.source_bindings_path)
        )
        sealed_observations = _parse_observations(
            snapshot.artifact_bytes(outcome.observation_bundle_path)
        )
        sealed_result = BenchmarkResult.model_validate_json(
            snapshot.artifact_bytes(outcome.result_path)
        )
        authority = DeterministicBaselineMeasurementAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.authority_path)
        )
        rebuilt_sources = tuple(
            _load_source_binding(
                authoritative_manifest,
                source,
                catalog_provider=catalog_provider,
                activation_store=activation_store,
                distribution_trust_anchor=distribution_trust_anchor,
            )
            for source in source_outcomes
        )
        rebuilt_sources = _canonical_sources(
            authoritative_manifest,
            selection,
            rebuilt_sources,
        )
    except (
        BenchmarkRegistryGovernedHarnessError,
        BenchmarkTargetCatalogError,
        BenchmarkTargetFactoryError,
        OSError,
        RunIntegrityError,
        ValidationError,
        ValueError,
    ) as exc:
        raise DeterministicBaselineMeasurementError(
            "Deterministic PAJIN baseline measurement is not sealed and valid"
        ) from exc
    expected_observations = tuple(source.observation for source in rebuilt_sources)
    bundle_bytes = snapshot.artifact_bytes(outcome.observation_bundle_path)
    if (
        outcome.authority_path != _AUTHORITY_ARTIFACT
        or outcome.result_path != _RESULT_ARTIFACT
        or outcome.source_bindings_path != _SOURCE_BINDINGS_ARTIFACT
        or outcome.observation_bundle_path != _OBSERVATION_BUNDLE_ARTIFACT
        or sealed_manifest != authoritative_manifest
        or sealed_selection != selection
        or sealed_sources != rebuilt_sources
        or sealed_observations != expected_observations
        or sealed_result != authority.baseline_result
        or authority != outcome.authority
        or authority.sources != rebuilt_sources
        or authority.baseline_result.evidence[0].sha256
        != sha256(bundle_bytes).hexdigest()
    ):
        raise DeterministicBaselineMeasurementError(
            "Deterministic PAJIN baseline measurement differs from exact sources"
        )
    expected_events = [
        "campaign.started",
        "benchmark.deterministic-baseline.measured",
        "campaign.completed",
    ]
    if [event.event_type for event in snapshot.events] != expected_events:
        raise DeterministicBaselineMeasurementError(
            "Deterministic PAJIN baseline audit sequence differs"
        )
    if snapshot.events[1].payload != _measurement_event_payload(authority):
        raise DeterministicBaselineMeasurementError(
            "Deterministic PAJIN baseline audit event differs"
        )
    return authority.model_copy(deep=True)


def _load_source_binding(
    manifest: BenchmarkManifest,
    outcome: BenchmarkRegistryGovernedHarnessOutcome,
    *,
    catalog_provider: CatalogBoundDockerBugBountyTargetFactoryAdapter,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> DeterministicBaselineSourceBinding:
    observation_outcome = load_registry_governed_benchmark_observation(
        manifest,
        outcome,
        activation_store=activation_store,
        distribution_trust_anchor=distribution_trust_anchor,
    )
    target = load_benchmark_target_run_authority(manifest, outcome.target)
    provider_evidence = catalog_provider.verify_target_run_match(target)
    harness_snapshot = load_verified_run_artifacts(
        outcome.run_path,
        requests={outcome.authority_path: _MAX_SOURCE_AUTHORITY_BYTES},
        expected_run_id=outcome.run_id,
    )
    harness_bytes = harness_snapshot.artifact_bytes(outcome.authority_path)
    authority = outcome.authority
    if (
        outcome.authority_path != _HARNESS_AUTHORITY_ARTIFACT
        or authority.target_authority_digest != target.authority_digest
        or authority.observation_digest != target.observation.observation_digest
        or observation_outcome.observation != target.observation
    ):
        raise ValueError("Deterministic baseline Harness source differs")
    return DeterministicBaselineSourceBinding(
        harnessRunId=outcome.run_id,
        harnessRootDigest=harness_snapshot.verification.root_digest,
        harnessAuthoritySha256=sha256(harness_bytes).hexdigest(),
        harnessAuthorityDigest=authority.authority_digest,
        activationDigest=authority.activation.activation_digest,
        registryAdmissionAuthorityDigest=(
            authority.registry_admission_authority.authority_digest
        ),
        targetRunId=authority.target_run_id,
        targetRootDigest=authority.target_root_digest,
        targetAuthoritySha256=authority.target_authority_sha256,
        targetAuthorityDigest=authority.target_authority_digest,
        targetAttestationDigest=authority.target_attestation_digest,
        adapterDigest=target.adapter.adapter_digest,
        targetCoordinateDigest=target.coordinate.coordinate_digest,
        executionReceiptDigest=target.execution_receipt.receipt_digest,
        executionOperationId=target.execution_receipt.operation_id,
        executionProviderEvidenceDigest=(
            target.execution_receipt.provider_evidence_digest
        ),
        providerEvidence=provider_evidence,
        observation=target.observation,
    )


def _canonical_sources(
    manifest: BenchmarkManifest,
    selection: BenchmarkTargetProfileSelectionAuthority,
    sources: tuple[DeterministicBaselineSourceBinding, ...],
) -> tuple[DeterministicBaselineSourceBinding, ...]:
    if len(manifest.arms) != 1:
        raise ValueError("P0-E1 requires one deterministic baseline arm")
    arm = manifest.arms[0]
    if (
        arm.kind is not BenchmarkArmKind.DETERMINISTIC_BASELINE
        or arm.adaptive_supervisor is not False
        or selection.manifest_digest != manifest.digest()
        or selection.registration.target_factory_digest != manifest.target_factory_digest
    ):
        raise ValueError("P0-E1 Manifest or catalog selection differs")
    canonical = tuple(
        DeterministicBaselineSourceBinding.model_validate(
            source.model_dump(mode="json", by_alias=True)
        )
        for source in sources
    )
    ordered = tuple(
        sorted(
            canonical,
            key=lambda source: (
                source.observation.seed,
                source.observation.repetition,
                source.target_run_id,
            ),
        )
    )
    expected_coordinates = [
        (seed, repetition)
        for seed in manifest.protocol.seeds
        for repetition in range(1, manifest.protocol.repetitions_per_seed + 1)
    ]
    actual_coordinates = [
        (source.observation.seed, source.observation.repetition) for source in ordered
    ]
    for source in ordered:
        observation = source.observation
        if (
            source.adapter_digest != selection.adapter_digest
            or observation.benchmark_id != manifest.benchmark_id
            or observation.manifest_digest != manifest.digest()
            or observation.arm_id != arm.arm_id
            or observation.arm_kind is not arm.kind
            or observation.configuration_digest != arm.configuration_digest
            or observation.target_factory_digest != manifest.target_factory_digest
            or observation.campaign_digest != manifest.campaign_digest
            or observation.ground_truth_digest != manifest.ground_truth_digest
            or observation.protocol_id != manifest.protocol.protocol_id
            or observation.protocol_version != manifest.protocol.protocol_version
        ):
            raise ValueError("Deterministic baseline source differs from authority")
    if actual_coordinates != expected_coordinates:
        raise ValueError("P0-E1 requires every baseline seed/repetition coordinate once")
    unique_sets = (
        {source.harness_run_id for source in ordered},
        {source.harness_root_digest for source in ordered},
        {source.harness_authority_digest for source in ordered},
        {source.target_run_id for source in ordered},
        {source.target_root_digest for source in ordered},
        {source.target_authority_digest for source in ordered},
        {source.target_attestation_digest for source in ordered},
        {source.target_coordinate_digest for source in ordered},
        {source.execution_receipt_digest for source in ordered},
        {source.execution_provider_evidence_digest for source in ordered},
        {source.observation.observation_digest for source in ordered},
        {source.binding_digest for source in ordered},
    )
    if any(len(values) != len(ordered) for values in unique_sets):
        raise ValueError("Deterministic baseline sources must be fresh and unique")
    return ordered


def _build_baseline_result(
    manifest: BenchmarkManifest,
    sources: tuple[DeterministicBaselineSourceBinding, ...],
    *,
    catalog_selection_digest: str,
) -> BenchmarkResult:
    arm = manifest.arms[0]
    observations = tuple(source.observation for source in sources)
    bundle = [observation.model_dump(mode="json", by_alias=True) for observation in observations]
    bundle_sha = sha256(_json_bytes(bundle)).hexdigest()
    identity = benchmark_digest(
        "pajin.benchmark.deterministic-baseline-result-identity/v1",
        {
            "manifestDigest": manifest.digest(),
            "catalogSelectionDigest": catalog_selection_digest,
            "sources": [source.binding_digest for source in sources],
        },
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    return BenchmarkResult(
        resultId=f"benchmark-result:{identity}",
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        armId=arm.arm_id,
        armKind=arm.kind,
        targetFactoryDigest=manifest.target_factory_digest,
        campaignDigest=manifest.campaign_digest,
        groundTruthDigest=manifest.ground_truth_digest,
        protocolId=manifest.protocol.protocol_id,
        protocolVersion=manifest.protocol.protocol_version,
        status=BenchmarkResultStatus.COMPLETED,
        startedAt=min(observation.started_at for observation in observations),
        completedAt=max(observation.completed_at for observation in observations),
        runs=[
            BenchmarkRunBinding(
                runId=source.target_run_id,
                seed=source.observation.seed,
                repetition=source.observation.repetition,
                runRootDigest=source.target_root_digest,
                cleanupSucceeded=source.observation.cleanup_succeeded,
            )
            for source in sources
        ],
        metrics=aggregate_walking_benchmark_metrics(observations),
        evidence=[
            BenchmarkEvidenceReference(
                reference=_OBSERVATION_BUNDLE_ARTIFACT,
                sha256=bundle_sha,
            )
        ],
        openWorldCandidateIds=sorted(
            {
                candidate
                for observation in observations
                for candidate in observation.open_world_candidate_ids
            }
        ),
    )


def _seal_authority(
    output_root: Path,
    authority: DeterministicBaselineMeasurementAuthority,
) -> DeterministicBaselineMeasurementOutcome:
    store = RunStore.create(output_root, "deterministic-baseline-measurement")
    store.append_event(
        "campaign.started",
        {
            "purpose": "deterministic-baseline-measurement",
            "benchmarkId": authority.manifest.benchmark_id,
        },
    )
    store.write_json(
        _MANIFEST_ARTIFACT,
        authority.manifest.model_dump(mode="json", by_alias=True),
    )
    store.write_json(
        _CATALOG_SELECTION_ARTIFACT,
        authority.catalog_selection.model_dump(mode="json", by_alias=True),
    )
    source_path = store.write_json(
        _SOURCE_BINDINGS_ARTIFACT,
        [source.model_dump(mode="json", by_alias=True) for source in authority.sources],
    )
    bundle_path = store.write_json(
        _OBSERVATION_BUNDLE_ARTIFACT,
        [source.observation.model_dump(mode="json", by_alias=True) for source in authority.sources],
    )
    result_path = store.write_json(
        _RESULT_ARTIFACT,
        authority.baseline_result.model_dump(mode="json", by_alias=True),
    )
    authority_path = store.write_json(
        _AUTHORITY_ARTIFACT,
        authority.model_dump(mode="json", by_alias=True),
    )
    store.append_event(
        "benchmark.deterministic-baseline.measured",
        _measurement_event_payload(authority),
    )
    store.write_json(
        "run.json",
        {
            "runId": store.run_id,
            "status": "completed",
            "stage": "deterministic-baseline-measured",
            "authorityId": authority.authority_id,
        },
    )
    store.append_event(
        "campaign.completed",
        {"purpose": "deterministic-baseline-measurement", "artifact": authority_path},
    )
    store.seal()
    return DeterministicBaselineMeasurementOutcome(
        run_id=store.run_id,
        run_path=store.path,
        authority_path=authority_path,
        result_path=result_path,
        source_bindings_path=source_path,
        observation_bundle_path=bundle_path,
        authority=authority.model_copy(deep=True),
    )


def _parse_source_bindings(raw: bytes) -> tuple[DeterministicBaselineSourceBinding, ...]:
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ValueError("Deterministic baseline source bindings must be a JSON array")
    return tuple(DeterministicBaselineSourceBinding.model_validate(item) for item in value)


def _parse_observations(raw: bytes) -> tuple[WalkingBenchmarkRunObservation, ...]:
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ValueError("Deterministic baseline observation bundle must be a JSON array")
    return tuple(WalkingBenchmarkRunObservation.model_validate(item) for item in value)


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _measurement_event_payload(
    authority: DeterministicBaselineMeasurementAuthority,
) -> dict[str, object]:
    return {
        "artifact": _AUTHORITY_ARTIFACT,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "manifestDigest": authority.manifest_digest,
        "catalogSelectionDigest": authority.catalog_selection.authority_digest,
        "sourceCount": len(authority.sources),
        "baselineResult": _RESULT_ARTIFACT,
        "baselineResultDigest": authority.baseline_result_digest,
        "measurementState": authority.measurement_state,
        "candidateComparisonEligible": authority.candidate_comparison_eligible,
        "supervisorActivationEligible": authority.supervisor_activation_eligible,
    }
