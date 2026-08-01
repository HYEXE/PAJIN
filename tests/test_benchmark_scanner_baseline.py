from __future__ import annotations

import pytest
from pydantic import ValidationError

from pajin.benchmark import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkRunProtocol,
    BenchmarkTargetCatalogError,
    DockerBugBountyTargetProfile,
    GenericScannerAdapterContract,
    RegisteredBenchmarkTargetFactoryAdapter,
    ScannerBaselineMeasurementPlanAuthority,
    benchmark_digest,
    plan_generic_scanner_baseline,
    registered_generic_scanner_adapter_contract,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
)

TARGET_IMAGE_ID = "sha256:" + "a" * 64
WORKER_IMAGE_ID = "sha256:" + "b" * 64
MEASUREMENT_DIGEST = "c" * 64


def _profile(*, target_image_id: str = TARGET_IMAGE_ID) -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=target_image_id,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId=WORKER_IMAGE_ID,
    )


def _ground_truth(profile: DockerBugBountyTargetProfile) -> BenchmarkGroundTruth:
    return registered_traditional_web_api_ground_truth(
        profile,
        benchmark_id="benchmark:generic-scanner-baseline-v1",
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


def _manifest(
    profile: DockerBugBountyTargetProfile,
    ground_truth: BenchmarkGroundTruth,
    *,
    candidate: bool = False,
) -> BenchmarkManifest:
    contract = registered_generic_scanner_adapter_contract()
    arms = [
        BenchmarkArm(
            armId="arm:generic-scanner-baseline",
            kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
            implementationId=contract.benchmark_implementation_id,
            implementationVersion=contract.benchmark_implementation_version,
            configurationDigest=contract.benchmark_configuration_digest,
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
            protocolId="pajin:generic-scanner-baseline-protocol",
            protocolVersion="1.0.0",
            seeds=[7, 11],
            repetitionsPerSeed=2,
            timeoutSeconds=120,
            maxCostUsd=1,
            maxToolCalls=10,
            maxModelCalls=1,
        ),
        arms=arms,
    )


def _plan(*, candidate: bool = False) -> ScannerBaselineMeasurementPlanAuthority:
    profile = _profile()
    ground_truth = _ground_truth(profile)
    manifest = _manifest(profile, ground_truth, candidate=candidate)
    return plan_generic_scanner_baseline(
        manifest,
        adapter=_definition(profile),
        profile=profile,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )


def test_scanner_baseline_plan_binds_exact_target_and_all_coordinates() -> None:
    plan = _plan()

    assert [(item.seed, item.repetition) for item in plan.coordinates] == [
        (7, 1),
        (7, 2),
        (11, 1),
        (11, 2),
    ]
    assert plan.target_selection.manifest_digest == plan.manifest_digest
    assert plan.scanner_contract.output_format == "sarif-2.1.0"
    assert plan.scanner_identity_bound is False
    assert plan.invocation_receipt_bound is False
    assert plan.raw_output_bound is False
    assert plan.benchmark_result_eligible is False
    assert "cases" not in str(plan.model_dump(mode="json", by_alias=True))


def test_scanner_baseline_plan_rejects_candidate_manifest() -> None:
    with pytest.raises(ValueError, match="one Scanner baseline arm"):
        _plan(candidate=True)


def test_scanner_baseline_plan_rejects_alternate_target_profile() -> None:
    profile = _profile()
    ground_truth = _ground_truth(profile)
    manifest = _manifest(profile, ground_truth)
    alternate = _profile(target_image_id="sha256:" + "9" * 64)

    with pytest.raises(BenchmarkTargetCatalogError):
        plan_generic_scanner_baseline(
            manifest,
            adapter=_definition(alternate),
            profile=alternate,
            catalog=registered_traditional_web_api_target_catalog(
                alternate,
                _ground_truth(alternate),
            ),
            ground_truth=_ground_truth(alternate),
        )


def test_scanner_contract_rejects_parser_substitution() -> None:
    contract = registered_generic_scanner_adapter_contract()
    raw = contract.model_dump(mode="json", by_alias=True)
    raw.pop("contractDigest")
    raw["parserContractDigest"] = "f" * 64

    with pytest.raises(ValidationError, match="parser contract differs"):
        GenericScannerAdapterContract.model_validate(raw)


def test_scanner_plan_rejects_missing_or_duplicate_coordinate() -> None:
    plan = _plan()
    for coordinates in (plan.coordinates[:-1], (*plan.coordinates, plan.coordinates[-1])):
        raw = plan.model_dump(mode="json", by_alias=True)
        raw.pop("authorityId")
        raw.pop("authorityDigest")
        raw["coordinates"] = [
            item.model_dump(mode="json", by_alias=True) for item in coordinates
        ]
        with pytest.raises(ValidationError, match="Plan differs"):
            ScannerBaselineMeasurementPlanAuthority.model_validate(raw)


@pytest.mark.parametrize(
    "field",
    [
        "scannerIdentityBound",
        "invocationReceiptBound",
        "rawOutputBound",
        "benchmarkResultEligible",
        "candidateComparisonEligible",
        "supervisorActivationEligible",
    ],
)
def test_scanner_plan_cannot_forge_authority_flags(field: str) -> None:
    plan = _plan()
    raw = plan.model_dump(mode="json", by_alias=True)
    raw[field] = True

    with pytest.raises(ValidationError, match="Input should be False"):
        ScannerBaselineMeasurementPlanAuthority.model_validate(raw)


def test_scanner_plan_rejects_unregistered_implementation_identity() -> None:
    plan = _plan()
    raw = plan.manifest.model_dump(mode="json", by_alias=True)
    raw["arms"][0]["implementationId"] = "scanner:unregistered"
    manifest = BenchmarkManifest.model_validate(raw)

    with pytest.raises(ValueError, match="Manifest differs"):
        ScannerBaselineMeasurementPlanAuthority(
            manifest=manifest,
            manifestDigest=manifest.digest(),
            targetSelection=plan.target_selection,
            scannerContract=plan.scanner_contract,
            coordinates=plan.coordinates,
        )


def test_scanner_contract_digest_is_domain_separated() -> None:
    contract = registered_generic_scanner_adapter_contract()
    generic = benchmark_digest(
        "pajin.benchmark.unrelated/v1",
        contract.model_dump(mode="json", by_alias=True, exclude={"contract_digest"}),
        max_bytes=128 * 1024,
    )
    assert contract.contract_digest != generic
