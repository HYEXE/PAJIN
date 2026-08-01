from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.benchmark import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkRunProtocol,
    BenchmarkTargetCatalogError,
    BenchmarkTargetProfileCatalog,
    BenchmarkTargetProfileRegistration,
    BenchmarkTargetStageReceipt,
    CatalogBoundDockerBugBountyTargetFactoryAdapter,
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetProfile,
    RegisteredBenchmarkTargetFactoryAdapter,
    WalkingBenchmarkRunObservation,
    benchmark_target_coordinate,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
    select_traditional_web_api_target_profile,
)

NOW = datetime(2026, 8, 1, tzinfo=UTC)
TARGET_IMAGE_ID = "sha256:" + "a" * 64
WORKER_IMAGE_ID = "sha256:" + "b" * 64
MEASUREMENT_DIGEST = "c" * 64


def _profile(
    *,
    target_image_id: str = TARGET_IMAGE_ID,
) -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=target_image_id,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId=WORKER_IMAGE_ID,
    )


def _ground_truth(profile: DockerBugBountyTargetProfile) -> BenchmarkGroundTruth:
    return registered_traditional_web_api_ground_truth(
        profile,
        benchmark_id="benchmark:docker-bug-bounty-v1",
    )


def _manifest(
    profile: DockerBugBountyTargetProfile,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId=ground_truth.benchmark_id,
        targetFactoryId="target-factory:docker-bug-bounty",
        targetFactoryVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        mutationProfileId=None,
        campaignDigest="d" * 64,
        groundTruthDigest=ground_truth.digest(),
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:docker-bug-bounty-protocol",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=1,
            timeoutSeconds=120,
            maxCostUsd=1,
            maxToolCalls=10,
            maxModelCalls=1,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:docker-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId="pajin:docker-bug-bounty-baseline",
                implementationVersion="1.0.0",
                configurationDigest="e" * 64,
                adaptiveSupervisor=False,
            )
        ],
    )


def _definition(
    profile: DockerBugBountyTargetProfile,
) -> RegisteredBenchmarkTargetFactoryAdapter:
    return RegisteredBenchmarkTargetFactoryAdapter(
        adapterId="target-adapter:docker-bug-bounty",
        adapterVersion="1.0.0",
        targetFactoryId="target-factory:docker-bug-bounty",
        targetFactoryVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        measurementAuthorityId="measurement-authority:docker-bug-bounty",
        measurementAuthorityVersion="1.0.0",
        measurementAuthorityDigest=MEASUREMENT_DIGEST,
    )


def _selection_inputs() -> tuple[
    DockerBugBountyTargetProfile,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkTargetProfileCatalog,
    RegisteredBenchmarkTargetFactoryAdapter,
]:
    profile = _profile()
    ground_truth = _ground_truth(profile)
    manifest = _manifest(profile, ground_truth)
    catalog = registered_traditional_web_api_target_catalog(profile, ground_truth)
    return profile, ground_truth, manifest, catalog, _definition(profile)


def test_catalog_keeps_private_ground_truth_out_of_public_registration() -> None:
    profile, ground_truth, manifest, catalog, definition = _selection_inputs()

    selection = select_traditional_web_api_target_profile(
        manifest,
        adapter=definition,
        profile=profile,
        catalog=catalog,
        ground_truth=ground_truth,
    )

    public = catalog.model_dump(mode="json", by_alias=True)
    selected = selection.model_dump(mode="json", by_alias=True)
    assert "cases" not in str(public)
    assert "cases" not in str(selected)
    assert public["registrations"][0]["groundTruthDigest"] == ground_truth.digest()
    assert selection.provider_execution_authorized is False
    assert selection.target_profile_admitted is True
    assert selection.authority_digest == selection.model_copy().authority_digest


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("targetProfileId", "bug-bounty.api.unknown-lab"),
        ("targetProfileVersion", "2.0.0"),
        ("mutationProfileId", "mutation:unregistered"),
        ("groundTruthDigest", "f" * 64),
    ],
)
def test_selection_rejects_manifest_profile_mutation_or_ground_truth_substitution(
    field: str,
    value: str,
) -> None:
    profile, ground_truth, manifest, catalog, definition = _selection_inputs()
    raw = manifest.model_dump(mode="json", by_alias=True)
    raw[field] = value
    substituted = BenchmarkManifest.model_validate(raw)

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        select_traditional_web_api_target_profile(
            substituted,
            adapter=definition,
            profile=profile,
            catalog=catalog,
            ground_truth=ground_truth,
        )


def test_selection_rejects_cross_profile_catalog_and_private_ground_truth() -> None:
    profile, ground_truth, manifest, catalog, definition = _selection_inputs()
    other_profile = _profile(target_image_id="sha256:" + "9" * 64)
    other_ground_truth = _ground_truth(other_profile)
    other_catalog = registered_traditional_web_api_target_catalog(
        other_profile,
        other_ground_truth,
    )

    with pytest.raises(BenchmarkTargetCatalogError):
        select_traditional_web_api_target_profile(
            manifest,
            adapter=definition,
            profile=profile,
            catalog=other_catalog,
            ground_truth=other_ground_truth,
        )

    with pytest.raises(BenchmarkTargetCatalogError):
        select_traditional_web_api_target_profile(
            manifest,
            adapter=_definition(other_profile),
            profile=profile,
            catalog=catalog,
            ground_truth=ground_truth,
        )

    with pytest.raises(BenchmarkTargetCatalogError):
        select_traditional_web_api_target_profile(
            manifest,
            adapter=definition,
            profile=profile,
            catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
            ground_truth=other_ground_truth,
        )


def test_catalog_rejects_duplicate_profile_versions_and_forged_digest() -> None:
    _, _, _, catalog, _ = _selection_inputs()
    registration = catalog.registrations[0]

    with pytest.raises(ValidationError, match="uniquely sorted"):
        BenchmarkTargetProfileCatalog(registrations=(registration, registration))

    raw = registration.model_dump(mode="json", by_alias=True)
    raw["registrationDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Registration Digest differs"):
        BenchmarkTargetProfileRegistration.model_validate(raw)


def _execution_evidence(
    profile: DockerBugBountyTargetProfile,
    definition: RegisteredBenchmarkTargetFactoryAdapter,
    coordinate_digest: str,
) -> DockerBenchmarkProviderEvidence:
    return DockerBenchmarkProviderEvidence(
        adapterDigest=definition.adapter_digest,
        coordinateDigest=coordinate_digest,
        operationId="operation:execution",
        operationDigest="1" * 64,
        fence=1,
        stage="execution",
        environmentId="environment:catalog-test",
        isolationId="isolation:catalog-test",
        dockerServerVersion="29.5.3",
        targetImageId=profile.target_image_id,
        workerImageId=profile.worker_image_id,
        targetContainerId="2" * 64,
        workerContainerId="3" * 64,
        networkId="4" * 64,
        networkInternal=True,
        publishedPortCount=0,
        networkContainerCount=1,
        targetHealthy=True,
        workerExitCode=0,
        probeVulnerable=True,
        probeOutputSha256="5" * 64,
        resourcesAbsent=None,
        observedAt=NOW + timedelta(seconds=1),
    )


def _observation(
    manifest: BenchmarkManifest,
    definition: RegisteredBenchmarkTargetFactoryAdapter,
) -> WalkingBenchmarkRunObservation:
    arm = manifest.arms[0]
    return WalkingBenchmarkRunObservation(
        benchmarkId=manifest.benchmark_id,
        manifestDigest=manifest.digest(),
        armId=arm.arm_id,
        armKind=arm.kind,
        configurationDigest=arm.configuration_digest,
        targetFactoryDigest=manifest.target_factory_digest,
        campaignDigest=manifest.campaign_digest,
        groundTruthDigest=manifest.ground_truth_digest,
        protocolId=manifest.protocol.protocol_id,
        protocolVersion=manifest.protocol.protocol_version,
        measurementAuthorityId=definition.measurement_authority_id,
        measurementAuthorityVersion=definition.measurement_authority_version,
        measurementAuthorityDigest=definition.measurement_authority_digest,
        seed=7,
        repetition=1,
        startedAt=NOW,
        completedAt=NOW + timedelta(seconds=1),
        cleanupSucceeded=False,
        toolCallCount=1,
        modelCallCount=0,
        costUsd=0,
        knownAttackSurfaceCount=1,
        discoveredKnownAttackSurfaceCount=1,
        knownFindingCount=1,
        matchedKnownFindingCount=1,
        candidateFindingCount=1,
        validCandidateFindingCount=1,
        unexpectedValidFindingCount=0,
        confirmedFindingCount=1,
        groundTruthChainCount=1,
        completedGroundTruthChainCount=1,
        firstValidOrConfirmedFindingSeconds=0,
        replayAttemptCount=1,
        replaySuccessCount=1,
        policyRejectionOrViolationCount=0,
        humanDecisionCount=1,
        humanInterventionOrOverturnCount=0,
    )


class _ExecutionProvider:
    def __init__(
        self,
        profile: DockerBugBountyTargetProfile,
        definition: RegisteredBenchmarkTargetFactoryAdapter,
        evidence: DockerBenchmarkProviderEvidence,
        observation: WalkingBenchmarkRunObservation,
    ) -> None:
        self.profile = profile
        self.definition = definition
        self._evidence = evidence
        self._observation = observation

    def evidence(self, receipt: BenchmarkTargetStageReceipt) -> DockerBenchmarkProviderEvidence:
        return self._evidence

    async def execute(
        self,
        coordinate: object,
        isolation: BenchmarkTargetStageReceipt,
        operation: object,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        return isolation, self._observation


@pytest.mark.asyncio
async def test_catalog_wrapper_requires_receipt_bound_evidence_to_match_ground_truth() -> None:
    profile, ground_truth, manifest, catalog, definition = _selection_inputs()
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    evidence = _execution_evidence(profile, definition, coordinate.coordinate_digest)
    receipt = BenchmarkTargetStageReceipt(
        adapterDigest=definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        stage="execution",
        operationId=evidence.operation_id,
        environmentId=evidence.environment_id,
        isolationId=evidence.isolation_id,
        status="succeeded",
        startedAt=NOW,
        completedAt=NOW + timedelta(seconds=1),
        providerEvidenceDigest=evidence.evidence_digest,
    )
    observation = _observation(manifest, definition)
    provider = _ExecutionProvider(profile, definition, evidence, observation)
    wrapper = CatalogBoundDockerBugBountyTargetFactoryAdapter(
        provider=provider,  # type: ignore[arg-type]
        manifest=manifest,
        catalog=catalog,
        ground_truth=ground_truth,
    )

    returned_receipt, returned_observation = await wrapper.execute(
        coordinate,
        receipt,
        object(),  # type: ignore[arg-type]
    )

    assert returned_receipt == receipt
    assert returned_observation == observation
    mismatched_observation = observation.model_dump(mode="json", by_alias=True)
    mismatched_observation.pop("observationId")
    mismatched_observation.pop("observationDigest")
    mismatched_observation["matchedKnownFindingCount"] = 0
    provider._observation = WalkingBenchmarkRunObservation.model_validate(
        mismatched_observation
    )
    with pytest.raises(BenchmarkTargetCatalogError, match="does not match"):
        await wrapper.execute(
            coordinate,
            receipt,
            object(),  # type: ignore[arg-type]
        )

    provider._observation = observation
    mismatched_evidence = evidence.model_dump(mode="json", by_alias=True)
    mismatched_evidence.pop("evidenceDigest")
    mismatched_evidence["operationId"] = "operation:other"
    provider._evidence = DockerBenchmarkProviderEvidence.model_validate(mismatched_evidence)
    with pytest.raises(BenchmarkTargetCatalogError, match="does not match"):
        await wrapper.execute(
            coordinate,
            receipt,
            object(),  # type: ignore[arg-type]
        )

    provider._evidence = evidence
    provider.profile = _profile(target_image_id="sha256:" + "8" * 64)
    with pytest.raises(BenchmarkTargetCatalogError, match="identity changed"):
        await wrapper.execute(
            coordinate,
            receipt,
            object(),  # type: ignore[arg-type]
        )
