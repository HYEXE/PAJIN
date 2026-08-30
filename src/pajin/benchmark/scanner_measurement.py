"""P0-E2B sealed registry-governed OWASP ZAP baseline measurement."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.benchmark.docker_provider import (
    DockerBenchmarkProviderError,
    DockerBenchmarkProviderEvidence,
)
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
from pajin.benchmark.scanner_baseline import ScannerBaselineMeasurementPlanAuthority
from pajin.benchmark.scanner_docker_provider import (
    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
)
from pajin.benchmark.scanner_sarif import (
    ZAPSarifNormalization,
    ZAPScannerRegistration,
    parse_zap_sarif,
)
from pajin.benchmark.target_catalog import (
    BenchmarkTargetCatalogError,
    BenchmarkTargetProfileSelectionAuthority,
)
from pajin.benchmark.target_factory import (
    BenchmarkTargetFactoryError,
    load_benchmark_target_run_authority,
)
from pajin.domain.models import StrictModel
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

SCANNER_BASELINE_SOURCE_BINDING_API_VERSION: Literal[
    "pajin.dev/scanner-baseline-source-binding/v1alpha1"
] = "pajin.dev/scanner-baseline-source-binding/v1alpha1"
SCANNER_BASELINE_MEASUREMENT_API_VERSION: Literal[
    "pajin.dev/scanner-baseline-measurement/v1alpha1"
] = "pajin.dev/scanner-baseline-measurement/v1alpha1"

_Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_HARNESS_AUTHORITY_ARTIFACT = "benchmark-registry-governed-harness-authority.json"
_PLAN_ARTIFACT = "scanner-baseline-plan.json"
_REGISTRATION_ARTIFACT = "zap-scanner-registration.json"
_SELECTION_ARTIFACT = "benchmark-target-catalog-selection.json"
_SOURCES_ARTIFACT = "scanner-baseline-source-bindings.json"
_OBSERVATIONS_ARTIFACT = "evidence/scanner-baseline-observations.json"
_RESULT_ARTIFACT = "scanner-baseline-result.json"
_AUTHORITY_ARTIFACT = "scanner-baseline-measurement-authority.json"
_MAX_SOURCE_BYTES = 48 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 32 * 1024 * 1024
_MAX_BUNDLE_BYTES = 16 * 1024 * 1024
_MAX_RESULT_BYTES = 4 * 1024 * 1024
_MAX_SARIF_BYTES = 16 * 1024 * 1024


class ScannerBaselineMeasurementError(RuntimeError):
    """Raised when concrete Scanner sources or sealed output fail closed."""


class ScannerBaselineSourceBinding(StrictModel):
    """One governed Target Run plus its exact raw and normalized ZAP output."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/scanner-baseline-source-binding/v1alpha1"] = Field(
        default=SCANNER_BASELINE_SOURCE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ScannerBaselineSourceBinding"] = "ScannerBaselineSourceBinding"
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    harness_run_id: _Identifier = Field(alias="harnessRunId")
    harness_root_digest: _Sha256 = Field(alias="harnessRootDigest")
    harness_authority_sha256: _Sha256 = Field(alias="harnessAuthoritySha256")
    harness_authority_digest: _Sha256 = Field(alias="harnessAuthorityDigest")
    activation_digest: _Sha256 = Field(alias="activationDigest")
    registry_admission_authority_digest: _Sha256 = Field(alias="registryAdmissionAuthorityDigest")
    target_run_id: _Identifier = Field(alias="targetRunId")
    target_root_digest: _Sha256 = Field(alias="targetRootDigest")
    target_authority_sha256: _Sha256 = Field(alias="targetAuthoritySha256")
    target_authority_digest: _Sha256 = Field(alias="targetAuthorityDigest")
    target_attestation_digest: _Sha256 = Field(alias="targetAttestationDigest")
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    target_coordinate_digest: _Sha256 = Field(alias="targetCoordinateDigest")
    execution_receipt_digest: _Sha256 = Field(alias="executionReceiptDigest")
    execution_operation_id: _Identifier = Field(alias="executionOperationId")
    execution_provider_evidence_digest: _Sha256 = Field(alias="executionProviderEvidenceDigest")
    provider_evidence: DockerBenchmarkProviderEvidence = Field(alias="providerEvidence")
    raw_sarif_artifact: str = Field(alias="rawSarifArtifact", min_length=1, max_length=300)
    raw_sarif_sha256: _Sha256 = Field(alias="rawSarifSha256")
    normalization: ZAPSarifNormalization
    observation: WalkingBenchmarkRunObservation

    @model_validator(mode="after")
    def bind_source(self) -> Self:
        expected_path = (
            f"evidence/raw-sarif/{self.observation.seed}-{self.observation.repetition}.sarif.json"
        )
        if (
            self.provider_evidence.stage != "execution"
            or self.provider_evidence.evidence_digest != self.execution_provider_evidence_digest
            or self.provider_evidence.operation_id != self.execution_operation_id
            or self.provider_evidence.raw_sarif_sha256 != self.raw_sarif_sha256
            or self.provider_evidence.raw_sarif_size_bytes
            != self.normalization.raw_sarif_size_bytes
            or self.provider_evidence.scanner_registration_digest
            != self.normalization.registration_digest
            or self.normalization.raw_sarif_sha256 != self.raw_sarif_sha256
            or self.provider_evidence.sarif_normalization_digest
            != self.normalization.normalization_digest
            or self.raw_sarif_artifact != expected_path
        ):
            raise ValueError("Scanner baseline source evidence differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"binding_digest"})
        digest = benchmark_digest(
            "pajin.benchmark.scanner-baseline-source-binding/v1",
            material,
            max_bytes=4 * 1024 * 1024,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Scanner Baseline Source Binding Digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


class ScannerBaselineMeasurementAuthority(StrictModel):
    """Exact P0-E2A plan, ZAP runtime, governed sources, and completed Result."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/scanner-baseline-measurement/v1alpha1"] = Field(
        default=SCANNER_BASELINE_MEASUREMENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ScannerBaselineMeasurementAuthority"] = "ScannerBaselineMeasurementAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    plan: ScannerBaselineMeasurementPlanAuthority
    registration: ZAPScannerRegistration
    catalog_selection: BenchmarkTargetProfileSelectionAuthority = Field(alias="catalogSelection")
    sources: tuple[ScannerBaselineSourceBinding, ...] = Field(min_length=1, max_length=2_000)
    baseline_result: BenchmarkResult = Field(alias="baselineResult")
    baseline_result_digest: _Sha256 = Field(alias="baselineResultDigest")
    measurement_state: Literal["registry-governed-zap-baseline-measured"] = Field(
        default="registry-governed-zap-baseline-measured", alias="measurementState"
    )
    candidate_comparison_eligible: Literal[False] = Field(
        default=False, alias="candidateComparisonEligible"
    )
    supervisor_activation_eligible: Literal[False] = Field(
        default=False, alias="supervisorActivationEligible"
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        sources = _canonical_sources(self.plan, self.catalog_selection, self.sources)
        expected_result = _build_result(
            self.plan.manifest,
            sources,
            plan_digest=self.plan.authority_digest,
            registration_digest=self.registration.registration_digest,
        )
        if (
            self.registration.parser_contract_digest
            != self.plan.scanner_contract.parser_contract_digest
            or self.catalog_selection != self.plan.target_selection
            or any(
                source.normalization.registration_digest != self.registration.registration_digest
                or source.provider_evidence.scanner_registration_digest
                != self.registration.registration_digest
                or source.provider_evidence.scanner_image_id != self.registration.scanner_image_id
                for source in sources
            )
            or self.sources != sources
            or self.baseline_result != expected_result
            or self.baseline_result_digest != expected_result.digest()
        ):
            raise ValueError("Scanner Baseline Measurement Authority differs")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"authority_id", "authority_digest"}
        )
        canonical_benchmark_json(
            material,
            label="ScannerBaselineMeasurementAuthority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.scanner-baseline-measurement/v1",
            material,
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        authority_id = f"scanner-baseline-measurement:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Scanner Baseline Measurement Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Scanner Baseline Measurement Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


@dataclass(frozen=True, slots=True)
class ScannerBaselineMeasurementOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    result_path: str
    source_bindings_path: str
    observation_bundle_path: str
    authority: ScannerBaselineMeasurementAuthority


@dataclass(frozen=True, slots=True)
class _LoadedSource:
    binding: ScannerBaselineSourceBinding
    raw_sarif: bytes


class ScannerBaselineMeasurementRunner:
    """Reopen every governed ZAP Run and seal one baseline-only Result."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        plan: ScannerBaselineMeasurementPlanAuthority,
        *,
        catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
        source_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
        activation_store: BenchmarkMeasurementRegistryActivationStore,
        distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
    ) -> ScannerBaselineMeasurementOutcome:
        try:
            authoritative_plan = ScannerBaselineMeasurementPlanAuthority.model_validate(
                plan.model_dump(mode="json", by_alias=True)
            )
            loaded = tuple(
                _load_source(
                    authoritative_plan,
                    outcome,
                    catalog_provider=catalog_provider,
                    activation_store=activation_store,
                    distribution_trust_anchor=distribution_trust_anchor,
                )
                for outcome in source_outcomes
            )
            sources = _canonical_sources(
                authoritative_plan,
                catalog_provider.selection,
                tuple(item.binding for item in loaded),
            )
            by_digest = {item.binding.binding_digest: item.raw_sarif for item in loaded}
            raw_sarif = tuple(by_digest[source.binding_digest] for source in sources)
            result = _build_result(
                authoritative_plan.manifest,
                sources,
                plan_digest=authoritative_plan.authority_digest,
                registration_digest=catalog_provider.scanner_registration.registration_digest,
            )
            authority = ScannerBaselineMeasurementAuthority(
                plan=authoritative_plan,
                registration=catalog_provider.scanner_registration,
                catalogSelection=catalog_provider.selection,
                sources=sources,
                baselineResult=result,
                baselineResultDigest=result.digest(),
            )
        except (
            BenchmarkRegistryGovernedHarnessError,
            DockerBenchmarkProviderError,
            BenchmarkTargetCatalogError,
            BenchmarkTargetFactoryError,
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
        ) as exc:
            raise ScannerBaselineMeasurementError(
                "ZAP baseline measurement source verification failed"
            ) from exc
        return _seal(self._output_root, authority, raw_sarif)


def load_scanner_baseline_measurement_authority(
    plan: ScannerBaselineMeasurementPlanAuthority,
    outcome: ScannerBaselineMeasurementOutcome,
    *,
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    source_outcomes: tuple[BenchmarkRegistryGovernedHarnessOutcome, ...],
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> ScannerBaselineMeasurementAuthority:
    """Reopen the seal, raw SARIF, and original governed sources before return."""

    try:
        authoritative_plan = ScannerBaselineMeasurementPlanAuthority.model_validate(
            plan.model_dump(mode="json", by_alias=True)
        )
        loaded = tuple(
            _load_source(
                authoritative_plan,
                source,
                catalog_provider=catalog_provider,
                activation_store=activation_store,
                distribution_trust_anchor=distribution_trust_anchor,
            )
            for source in source_outcomes
        )
        sources = _canonical_sources(
            authoritative_plan,
            catalog_provider.selection,
            tuple(item.binding for item in loaded),
        )
        requests = {
            _PLAN_ARTIFACT: 2 * 1024 * 1024,
            _REGISTRATION_ARTIFACT: 256 * 1024,
            _SELECTION_ARTIFACT: 512 * 1024,
            outcome.source_bindings_path: _MAX_AUTHORITY_BYTES,
            outcome.observation_bundle_path: _MAX_BUNDLE_BYTES,
            outcome.result_path: _MAX_RESULT_BYTES,
            outcome.authority_path: _MAX_AUTHORITY_BYTES,
            **{source.raw_sarif_artifact: _MAX_SARIF_BYTES for source in sources},
        }
        snapshot = load_verified_run_artifacts(
            outcome.run_path, requests=requests, expected_run_id=outcome.run_id
        )
        sealed_plan = ScannerBaselineMeasurementPlanAuthority.model_validate_json(
            snapshot.artifact_bytes(_PLAN_ARTIFACT)
        )
        sealed_registration = ZAPScannerRegistration.model_validate_json(
            snapshot.artifact_bytes(_REGISTRATION_ARTIFACT)
        )
        sealed_selection = BenchmarkTargetProfileSelectionAuthority.model_validate_json(
            snapshot.artifact_bytes(_SELECTION_ARTIFACT)
        )
        sealed_sources = _parse_sources(snapshot.artifact_bytes(outcome.source_bindings_path))
        sealed_observations = _parse_observations(
            snapshot.artifact_bytes(outcome.observation_bundle_path)
        )
        sealed_result = BenchmarkResult.model_validate_json(
            snapshot.artifact_bytes(outcome.result_path)
        )
        authority = ScannerBaselineMeasurementAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.authority_path)
        )
        loaded_by_digest = {item.binding.binding_digest: item for item in loaded}
        for source in sources:
            loaded_source = loaded_by_digest[source.binding_digest]
            raw = snapshot.artifact_bytes(source.raw_sarif_artifact)
            if (
                raw != loaded_source.raw_sarif
                or sha256(raw).hexdigest() != source.raw_sarif_sha256
                or parse_zap_sarif(raw, registration=sealed_registration) != source.normalization
            ):
                raise ValueError("sealed ZAP SARIF differs from provider source")
    except (
        BenchmarkRegistryGovernedHarnessError,
        DockerBenchmarkProviderError,
        BenchmarkTargetCatalogError,
        BenchmarkTargetFactoryError,
        OSError,
        RunIntegrityError,
        ValidationError,
        ValueError,
    ) as exc:
        raise ScannerBaselineMeasurementError(
            "ZAP baseline measurement is not sealed and valid"
        ) from exc
    if (
        sealed_plan != authoritative_plan
        or sealed_registration != catalog_provider.scanner_registration
        or sealed_selection != catalog_provider.selection
        or sealed_sources != sources
        or sealed_observations != tuple(source.observation for source in sources)
        or sealed_result != authority.baseline_result
        or authority != outcome.authority
        or [event.event_type for event in snapshot.events]
        != [
            "campaign.started",
            "benchmark.scanner-baseline.measured",
            "campaign.completed",
        ]
        or snapshot.events[1].payload != _event_payload(authority)
    ):
        raise ScannerBaselineMeasurementError(
            "ZAP baseline measurement differs from exact authority"
        )
    return authority.model_copy(deep=True)


def _load_source(
    plan: ScannerBaselineMeasurementPlanAuthority,
    outcome: BenchmarkRegistryGovernedHarnessOutcome,
    *,
    catalog_provider: CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    activation_store: BenchmarkMeasurementRegistryActivationStore,
    distribution_trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
) -> _LoadedSource:
    observation_outcome = load_registry_governed_benchmark_observation(
        plan.manifest,
        outcome,
        activation_store=activation_store,
        distribution_trust_anchor=distribution_trust_anchor,
    )
    target = load_benchmark_target_run_authority(plan.manifest, outcome.target)
    evidence, raw, normalization = catalog_provider.verify_target_run_match(target)
    harness_snapshot = load_verified_run_artifacts(
        outcome.run_path,
        requests={outcome.authority_path: _MAX_SOURCE_BYTES},
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
        raise ValueError("ZAP baseline Harness source differs")
    observation = target.observation
    raw_path = f"evidence/raw-sarif/{observation.seed}-{observation.repetition}.sarif.json"
    return _LoadedSource(
        binding=ScannerBaselineSourceBinding(
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
            executionProviderEvidenceDigest=target.execution_receipt.provider_evidence_digest,
            providerEvidence=evidence,
            rawSarifArtifact=raw_path,
            rawSarifSha256=sha256(raw).hexdigest(),
            normalization=normalization,
            observation=observation,
        ),
        raw_sarif=raw,
    )


def _canonical_sources(
    plan: ScannerBaselineMeasurementPlanAuthority,
    selection: BenchmarkTargetProfileSelectionAuthority,
    sources: tuple[ScannerBaselineSourceBinding, ...],
) -> tuple[ScannerBaselineSourceBinding, ...]:
    manifest = plan.manifest
    if (
        len(manifest.arms) != 1
        or manifest.arms[0].kind is not BenchmarkArmKind.DETERMINISTIC_BASELINE
    ):
        raise ValueError("P0-E2B requires one deterministic Scanner baseline arm")
    canonical = tuple(
        ScannerBaselineSourceBinding.model_validate(source.model_dump(mode="json", by_alias=True))
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
    expected = [(item.seed, item.repetition) for item in plan.coordinates]
    actual = [(item.observation.seed, item.observation.repetition) for item in ordered]
    for source in ordered:
        observation = source.observation
        if (
            source.adapter_digest != selection.adapter_digest
            or source.provider_evidence.scanner_plan_digest != plan.authority_digest
            or observation.manifest_digest != manifest.digest()
            or observation.arm_id != manifest.arms[0].arm_id
            or observation.configuration_digest != manifest.arms[0].configuration_digest
        ):
            raise ValueError("ZAP baseline source differs from plan")
    if actual != expected:
        raise ValueError("P0-E2B requires every Scanner coordinate exactly once")
    uniqueness = (
        {item.harness_run_id for item in ordered},
        {item.target_run_id for item in ordered},
        {item.execution_receipt_digest for item in ordered},
        {item.binding_digest for item in ordered},
    )
    if any(len(values) != len(ordered) for values in uniqueness):
        raise ValueError("P0-E2B Scanner sources must be fresh and unique")
    return ordered


def _build_result(
    manifest: BenchmarkManifest,
    sources: tuple[ScannerBaselineSourceBinding, ...],
    *,
    plan_digest: str,
    registration_digest: str,
) -> BenchmarkResult:
    observations = tuple(source.observation for source in sources)
    bundle = [item.model_dump(mode="json", by_alias=True) for item in observations]
    identity = benchmark_digest(
        "pajin.benchmark.scanner-baseline-result-identity/v1",
        {
            "manifestDigest": manifest.digest(),
            "planDigest": plan_digest,
            "registrationDigest": registration_digest,
            "sources": [source.binding_digest for source in sources],
        },
        max_bytes=_MAX_AUTHORITY_BYTES,
    )
    return BenchmarkResult(
        resultId=f"benchmark-result:{identity}",
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        armId=manifest.arms[0].arm_id,
        armKind=manifest.arms[0].kind,
        targetFactoryDigest=manifest.target_factory_digest,
        campaignDigest=manifest.campaign_digest,
        groundTruthDigest=manifest.ground_truth_digest,
        protocolId=manifest.protocol.protocol_id,
        protocolVersion=manifest.protocol.protocol_version,
        status=BenchmarkResultStatus.COMPLETED,
        startedAt=min(item.started_at for item in observations),
        completedAt=max(item.completed_at for item in observations),
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
        evidence=sorted(
            [
                BenchmarkEvidenceReference(
                    reference=_OBSERVATIONS_ARTIFACT,
                    sha256=sha256(_json_bytes(bundle)).hexdigest(),
                ),
                *[
                    BenchmarkEvidenceReference(
                        reference=source.raw_sarif_artifact,
                        sha256=source.raw_sarif_sha256,
                    )
                    for source in sources
                ],
            ],
            key=lambda item: item.reference,
        ),
        openWorldCandidateIds=[],
    )


def _seal(
    output_root: Path,
    authority: ScannerBaselineMeasurementAuthority,
    raw_sarif: tuple[bytes, ...],
) -> ScannerBaselineMeasurementOutcome:
    store = RunStore.create(output_root, "scanner-baseline-measurement")
    store.append_event(
        "campaign.started",
        {
            "purpose": "scanner-baseline-measurement",
            "benchmarkId": authority.plan.manifest.benchmark_id,
        },
    )
    store.write_json(_PLAN_ARTIFACT, authority.plan.model_dump(mode="json", by_alias=True))
    store.write_json(
        _REGISTRATION_ARTIFACT, authority.registration.model_dump(mode="json", by_alias=True)
    )
    store.write_json(
        _SELECTION_ARTIFACT, authority.catalog_selection.model_dump(mode="json", by_alias=True)
    )
    source_path = store.write_json(
        _SOURCES_ARTIFACT,
        [source.model_dump(mode="json", by_alias=True) for source in authority.sources],
    )
    observation_path = store.write_json(
        _OBSERVATIONS_ARTIFACT,
        [source.observation.model_dump(mode="json", by_alias=True) for source in authority.sources],
    )
    for source, raw in zip(authority.sources, raw_sarif, strict=True):
        if sha256(raw).hexdigest() != source.raw_sarif_sha256:
            raise ScannerBaselineMeasurementError("ZAP SARIF changed before sealing")
        store.write_bytes(source.raw_sarif_artifact, raw)
    result_path = store.write_json(
        _RESULT_ARTIFACT, authority.baseline_result.model_dump(mode="json", by_alias=True)
    )
    authority_path = store.write_json(
        _AUTHORITY_ARTIFACT, authority.model_dump(mode="json", by_alias=True)
    )
    store.append_event("benchmark.scanner-baseline.measured", _event_payload(authority))
    store.write_json(
        "run.json",
        {
            "runId": store.run_id,
            "status": "completed",
            "stage": "scanner-baseline-measured",
            "authorityId": authority.authority_id,
        },
    )
    store.append_event(
        "campaign.completed",
        {"purpose": "scanner-baseline-measurement", "artifact": authority_path},
    )
    store.seal()
    return ScannerBaselineMeasurementOutcome(
        run_id=store.run_id,
        run_path=store.path,
        authority_path=authority_path,
        result_path=result_path,
        source_bindings_path=source_path,
        observation_bundle_path=observation_path,
        authority=authority.model_copy(deep=True),
    )


def _parse_sources(raw: bytes) -> tuple[ScannerBaselineSourceBinding, ...]:
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ValueError("Scanner source bindings must be a JSON array")
    sources = tuple(ScannerBaselineSourceBinding.model_validate(item) for item in value)
    if raw != _json_bytes([source.model_dump(mode="json", by_alias=True) for source in sources]):
        raise ValueError("Scanner source binding wire is not canonical")
    return sources


def _parse_observations(raw: bytes) -> tuple[WalkingBenchmarkRunObservation, ...]:
    value = json.loads(raw)
    if not isinstance(value, list):
        raise ValueError("Scanner observations must be a JSON array")
    observations = tuple(WalkingBenchmarkRunObservation.model_validate(item) for item in value)
    if raw != _json_bytes(
        [observation.model_dump(mode="json", by_alias=True) for observation in observations]
    ):
        raise ValueError("Scanner observation wire is not canonical")
    return observations


def _json_bytes(value: object) -> bytes:
    return (
        json.dumps(value, allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _event_payload(authority: ScannerBaselineMeasurementAuthority) -> dict[str, object]:
    return {
        "artifact": _AUTHORITY_ARTIFACT,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "planDigest": authority.plan.authority_digest,
        "registrationDigest": authority.registration.registration_digest,
        "sourceCount": len(authority.sources),
        "baselineResult": _RESULT_ARTIFACT,
        "baselineResultDigest": authority.baseline_result_digest,
        "measurementState": authority.measurement_state,
        "candidateComparisonEligible": authority.candidate_comparison_eligible,
        "supervisorActivationEligible": authority.supervisor_activation_eligible,
    }
