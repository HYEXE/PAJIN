from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.benchmark import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkManifest,
    BenchmarkMeasurementAttestation,
    BenchmarkMeasurementAttestationStatement,
    BenchmarkMeasurementAttestor,
    BenchmarkMeasurementKeyState,
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionKey,
    BenchmarkMeasurementRegistryDistributionSigner,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkRegistryGovernedHarnessRunner,
    BenchmarkRunProtocol,
    BenchmarkTargetCoordinate,
    BenchmarkTargetOperation,
    BenchmarkTargetRecoveryRequest,
    BenchmarkTargetStageReceipt,
    CatalogBoundDockerBugBountyTargetFactoryAdapter,
    DeterministicBaselineMeasurementAuthority,
    DeterministicBaselineMeasurementError,
    DeterministicBaselineMeasurementRunner,
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetProfile,
    RecoverableBenchmarkTargetFactoryRunner,
    RegisteredBenchmarkTargetFactoryAdapter,
    WalkingBenchmarkRunObservation,
    benchmark_measurement_public_key_base64url,
    benchmark_measurement_registry_distribution_public_key_base64url,
    load_deterministic_baseline_measurement_authority,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
)
from pajin.benchmark.measurement_registry import (
    BenchmarkMeasurementRegistryKey,
    BenchmarkMeasurementTrustRegistry,
)

MEASUREMENT_KEY = bytes(range(32))
DISTRIBUTION_KEY = bytes(range(32, 64))
NOW = datetime.now(UTC) - timedelta(minutes=1)


def _profile(*, target_image_id: str = "sha256:" + "a" * 64) -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=target_image_id,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId="sha256:" + "b" * 64,
    )


def _measurement_anchor() -> BenchmarkMeasurementTrustAnchor:
    return BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:docker-bug-bounty",
        authorityVersion="1.0.0",
        keyId="measurement-key:deterministic-baseline",
        publicKeyBase64url=benchmark_measurement_public_key_base64url(MEASUREMENT_KEY),
    )


def _manifest(
    profile: DockerBugBountyTargetProfile,
    *,
    candidate: bool = False,
) -> BenchmarkManifest:
    ground_truth = registered_traditional_web_api_ground_truth(
        profile,
        benchmark_id="benchmark:deterministic-pajin-baseline-v1",
    )
    arms = [
        BenchmarkArm(
            armId="arm:deterministic-pajin-baseline",
            kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
            implementationId="pajin:deterministic-baseline",
            implementationVersion="1.0.0",
            configurationDigest="e" * 64,
            adaptiveSupervisor=False,
        )
    ]
    if candidate:
        arms.append(
            BenchmarkArm(
                armId="arm:adaptive-candidate",
                kind=BenchmarkArmKind.ADAPTIVE_CANDIDATE,
                implementationId="pajin:adaptive-candidate",
                implementationVersion="1.0.0",
                configurationDigest="f" * 64,
                adaptiveSupervisor=True,
            )
        )
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
            protocolId="pajin:deterministic-baseline-protocol",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=1,
            timeoutSeconds=120,
            maxCostUsd=1,
            maxToolCalls=10,
            maxModelCalls=1,
        ),
        arms=arms,
    )


class _CatalogProvider:
    def __init__(self, manifest: BenchmarkManifest, profile: DockerBugBountyTargetProfile) -> None:
        self.profile = profile
        self.definition = RegisteredBenchmarkTargetFactoryAdapter(
            adapterId="target-adapter:docker-bug-bounty",
            adapterVersion="1.0.0",
            targetFactoryId=manifest.target_factory_id,
            targetFactoryVersion=manifest.target_factory_version,
            targetFactoryDigest=manifest.target_factory_digest,
            measurementAuthorityId=_measurement_anchor().authority_id,
            measurementAuthorityVersion=_measurement_anchor().authority_version,
            measurementAuthorityDigest=_measurement_anchor().anchor_digest,
        )
        self._manifest = manifest
        self._attestor = BenchmarkMeasurementAttestor.from_private_key_bytes(
            active_key_id=_measurement_anchor().key_id,
            private_key=MEASUREMENT_KEY,
            trust_anchor=_measurement_anchor(),
        )
        self._evidence: dict[str, DockerBenchmarkProviderEvidence] = {}

    def evidence(self, receipt: BenchmarkTargetStageReceipt) -> DockerBenchmarkProviderEvidence:
        return self._evidence[receipt.receipt_digest]

    def _stage(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        *,
        isolation_id: str | None,
    ) -> BenchmarkTargetStageReceipt:
        stage = operation.stage
        stage_offset = {
            "reset": 0,
            "isolation": 2,
            "execution": 4,
            "cleanup": 6,
        }[stage]
        evidence = DockerBenchmarkProviderEvidence(
            adapterDigest=self.definition.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            operationId=operation.operation_id,
            operationDigest=operation.operation_digest,
            fence=operation.fence,
            stage=stage,
            environmentId="environment:deterministic-baseline",
            isolationId=isolation_id,
            dockerServerVersion="29.5.3",
            targetImageId=self.profile.target_image_id,
            workerImageId=self.profile.worker_image_id,
            targetContainerId=(None if stage == "reset" else "1" * 64),
            workerContainerId=("2" * 64 if stage == "execution" else None),
            networkId=(None if stage == "reset" else "3" * 64),
            networkInternal=(None if stage in {"reset", "cleanup"} else True),
            publishedPortCount=(None if stage in {"reset", "cleanup"} else 0),
            networkContainerCount=(None if stage in {"reset", "cleanup"} else 1),
            targetHealthy=(None if stage in {"reset", "cleanup"} else True),
            workerExitCode=(0 if stage == "execution" else None),
            probeVulnerable=(True if stage == "execution" else None),
            probeOutputSha256=("4" * 64 if stage == "execution" else None),
            resourcesAbsent=(True if stage in {"reset", "cleanup"} else None),
            observedAt=NOW + timedelta(seconds=stage_offset),
        )
        receipt = BenchmarkTargetStageReceipt(
            adapterDigest=self.definition.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            stage=stage,
            operationId=operation.operation_id,
            environmentId="environment:deterministic-baseline",
            isolationId=isolation_id,
            status="succeeded",
            startedAt=NOW + timedelta(seconds=stage_offset),
            completedAt=NOW + timedelta(seconds=stage_offset + 1),
            providerEvidenceDigest=evidence.evidence_digest,
        )
        self._evidence[receipt.receipt_digest] = evidence
        return receipt

    async def reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        return self._stage(coordinate, operation, isolation_id=None)

    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        assert reset.stage == "reset"
        return self._stage(
            coordinate,
            operation,
            isolation_id="isolation:deterministic-baseline",
        )

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        receipt = self._stage(
            coordinate,
            operation,
            isolation_id=isolation.isolation_id,
        )
        arm = coordinate.arm
        return receipt, WalkingBenchmarkRunObservation(
            benchmarkId=self._manifest.benchmark_id,
            manifestDigest=self._manifest.digest(),
            armId=arm.arm_id,
            armKind=arm.kind,
            configurationDigest=arm.configuration_digest,
            targetFactoryDigest=self._manifest.target_factory_digest,
            campaignDigest=self._manifest.campaign_digest,
            groundTruthDigest=self._manifest.ground_truth_digest,
            protocolId=self._manifest.protocol.protocol_id,
            protocolVersion=self._manifest.protocol.protocol_version,
            measurementAuthorityId=self.definition.measurement_authority_id,
            measurementAuthorityVersion=self.definition.measurement_authority_version,
            measurementAuthorityDigest=self.definition.measurement_authority_digest,
            seed=coordinate.seed,
            repetition=coordinate.repetition,
            startedAt=receipt.started_at,
            completedAt=receipt.completed_at,
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

    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        return self._stage(
            coordinate,
            operation,
            isolation_id=isolation.isolation_id,
        )

    async def reconcile_cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        request: BenchmarkTargetRecoveryRequest,
    ) -> BenchmarkTargetStageReceipt:
        return self._stage(
            coordinate,
            request.cleanup_operation,
            isolation_id=(
                request.known_isolation_receipt.isolation_id
                if request.known_isolation_receipt is not None
                else "isolation:deterministic-baseline"
            ),
        )

    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        return self._attestor.attest(statement)


def _registry() -> BenchmarkMeasurementTrustRegistry:
    return BenchmarkMeasurementTrustRegistry(
        registryId="measurement-registry:deterministic-baseline",
        registryRevision=1,
        measurementAuthorityId=_measurement_anchor().authority_id,
        measurementAuthorityVersion=_measurement_anchor().authority_version,
        issuedAt=NOW - timedelta(minutes=10),
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_measurement_anchor(),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(hours=1),
            )
        ],
    )


def _distribution():
    registry = _registry()
    anchor = BenchmarkMeasurementRegistryDistributionTrustAnchor(
        trustDomain="benchmark-registry:deterministic-baseline",
        issuer="benchmark-registry-issuer:deterministic-baseline",
        keys=[
            BenchmarkMeasurementRegistryDistributionKey(
                keyId="distribution-key:deterministic-baseline",
                publicKeyBase64url=(
                    benchmark_measurement_registry_distribution_public_key_base64url(
                        DISTRIBUTION_KEY
                    )
                ),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(hours=1),
            )
        ],
    )
    signer = BenchmarkMeasurementRegistryDistributionSigner.from_private_key_bytes(
        active_key_id=anchor.active_key.key_id,
        private_key=DISTRIBUTION_KEY,
        trust_anchor=anchor,
    )
    issued_at = max(datetime.now(UTC) - timedelta(minutes=1), registry.issued_at)
    bundle = signer.sign(
        registry=registry,
        issued_at=issued_at,
        not_before=issued_at,
        expires_at=issued_at + timedelta(days=1),
    )
    return anchor, bundle


def _run_source(tmp_path: Path, *, candidate: bool = False):
    profile = _profile()
    manifest = _manifest(profile, candidate=candidate)
    ground_truth = registered_traditional_web_api_ground_truth(
        profile,
        benchmark_id=manifest.benchmark_id,
    )
    catalog = registered_traditional_web_api_target_catalog(profile, ground_truth)
    provider = _CatalogProvider(manifest, profile)
    catalog_provider = CatalogBoundDockerBugBountyTargetFactoryAdapter(
        provider=provider,  # type: ignore[arg-type]
        manifest=manifest,
        catalog=catalog,
        ground_truth=ground_truth,
    )
    activation_store = BenchmarkMeasurementRegistryActivationStore(
        tmp_path / "registry-activation.sqlite3"
    )
    distribution_anchor, bundle = _distribution()
    target_runner = RecoverableBenchmarkTargetFactoryRunner(
        output_root=tmp_path / "runs",
        journal_path=tmp_path / "target-journal.sqlite3",
        adapter=catalog_provider,
        trust_anchor=_measurement_anchor(),
    )
    source = asyncio.run(
        BenchmarkRegistryGovernedHarnessRunner(
            output_root=tmp_path / "runs",
            activation_store=activation_store,
            bundle=bundle,
            distribution_trust_anchor=distribution_anchor,
            target_runner=target_runner,
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )
    return (
        manifest,
        catalog_provider,
        activation_store,
        distribution_anchor,
        source,
        provider,
    )


def test_deterministic_baseline_seals_registry_and_catalog_governed_result(
    tmp_path: Path,
) -> None:
    manifest, catalog_provider, store, anchor, source, _ = _run_source(tmp_path)
    outcome = DeterministicBaselineMeasurementRunner(
        output_root=tmp_path / "baseline"
    ).run(
        manifest,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )

    authority = load_deterministic_baseline_measurement_authority(
        manifest,
        outcome,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )

    assert authority.baseline_result.status.value == "completed"
    assert len(authority.baseline_result.metrics) == 12
    assert authority.baseline_result.runs[0].cleanup_succeeded is True
    assert authority.sources[0].provider_evidence.probe_vulnerable is True
    assert authority.candidate_comparison_eligible is False
    assert authority.supervisor_activation_eligible is False


def test_deterministic_baseline_requires_every_coordinate_once(tmp_path: Path) -> None:
    manifest, catalog_provider, store, anchor, source, _ = _run_source(tmp_path)
    runner = DeterministicBaselineMeasurementRunner(output_root=tmp_path / "baseline")

    for sources in ((), (source, source)):
        with pytest.raises(DeterministicBaselineMeasurementError):
            runner.run(
                manifest,
                catalog_provider=catalog_provider,
                source_outcomes=sources,
                activation_store=store,
                distribution_trust_anchor=anchor,
            )


def test_deterministic_baseline_rejects_candidate_manifest(tmp_path: Path) -> None:
    manifest, catalog_provider, store, anchor, source, _ = _run_source(
        tmp_path,
        candidate=True,
    )

    with pytest.raises(DeterministicBaselineMeasurementError):
        DeterministicBaselineMeasurementRunner(output_root=tmp_path / "baseline").run(
            manifest,
            catalog_provider=catalog_provider,
            source_outcomes=(source,),
            activation_store=store,
            distribution_trust_anchor=anchor,
        )


def test_deterministic_baseline_reader_rejects_provider_evidence_substitution(
    tmp_path: Path,
) -> None:
    manifest, catalog_provider, store, anchor, source, provider = _run_source(tmp_path)
    outcome = DeterministicBaselineMeasurementRunner(
        output_root=tmp_path / "baseline"
    ).run(
        manifest,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )
    receipt = source.target.authority.execution_receipt
    evidence = provider.evidence(receipt)
    raw = evidence.model_dump(mode="json", by_alias=True)
    raw.pop("evidenceDigest")
    raw["probeOutputSha256"] = "f" * 64
    provider._evidence[receipt.receipt_digest] = DockerBenchmarkProviderEvidence.model_validate(raw)

    with pytest.raises(DeterministicBaselineMeasurementError):
        load_deterministic_baseline_measurement_authority(
            manifest,
            outcome,
            catalog_provider=catalog_provider,
            source_outcomes=(source,),
            activation_store=store,
            distribution_trust_anchor=anchor,
        )


@pytest.mark.parametrize(
    "field",
    ["candidateComparisonEligible", "supervisorActivationEligible"],
)
def test_deterministic_baseline_cannot_forge_eligibility_flags(
    tmp_path: Path,
    field: str,
) -> None:
    manifest, catalog_provider, store, anchor, source, _ = _run_source(tmp_path)
    authority = DeterministicBaselineMeasurementRunner(
        output_root=tmp_path / "baseline"
    ).run(
        manifest,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    ).authority
    raw = authority.model_dump(mode="json", by_alias=True)
    raw[field] = True

    with pytest.raises(ValidationError, match="Input should be False"):
        DeterministicBaselineMeasurementAuthority.model_validate(raw)
