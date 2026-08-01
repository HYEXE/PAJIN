from __future__ import annotations

import pytest
from pydantic import ValidationError

from pajin.benchmark import (
    AIRAGMCPWalkingTargetProfile,
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkRunProtocol,
    BenchmarkTargetCatalogError,
    BenchmarkTargetFixtureSelectionAuthority,
    BenchmarkTargetProfileCatalog,
    DockerBugBountyTargetProfile,
    registered_ai_rag_mcp_ground_truth,
    registered_ai_rag_mcp_target_catalog,
    registered_ai_rag_mcp_walking_target_profile,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
    select_ai_rag_mcp_target_fixture,
)


def _manifest(
    profile: AIRAGMCPWalkingTargetProfile,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId=ground_truth.benchmark_id,
        targetFactoryId=profile.target_factory_id,
        targetFactoryVersion=profile.target_factory_version,
        targetFactoryDigest=profile.target_factory_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        mutationProfileId=None,
        campaignDigest="a" * 64,
        groundTruthDigest=ground_truth.digest(),
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:ai-rag-mcp-fixture-protocol",
            protocolVersion="1.0.0",
            seeds=[17],
            repetitionsPerSeed=1,
            timeoutSeconds=300,
            maxCostUsd=1,
            maxToolCalls=4,
            maxModelCalls=0,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:walking-fixture-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId="pajin:walking-fixture-baseline",
                implementationVersion="1.0.0",
                configurationDigest="b" * 64,
                adaptiveSupervisor=False,
            )
        ],
    )


def _inputs() -> tuple[
    AIRAGMCPWalkingTargetProfile,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkTargetProfileCatalog,
]:
    profile = registered_ai_rag_mcp_walking_target_profile()
    ground_truth = registered_ai_rag_mcp_ground_truth(
        profile,
        benchmark_id="benchmark:ai-rag-mcp-walking-v1",
    )
    manifest = _manifest(profile, ground_truth)
    catalog = registered_ai_rag_mcp_target_catalog(profile, ground_truth)
    return profile, ground_truth, manifest, catalog


def test_ai_rag_mcp_fixture_selection_is_public_safe_and_non_runnable() -> None:
    profile, ground_truth, manifest, catalog = _inputs()

    selection = select_ai_rag_mcp_target_fixture(
        manifest,
        profile=profile,
        catalog=catalog,
        ground_truth=ground_truth,
    )

    public_catalog = catalog.model_dump(mode="json", by_alias=True)
    public_selection = selection.model_dump(mode="json", by_alias=True)
    assert "cases" not in str(public_catalog)
    assert "cases" not in str(public_selection)
    assert "adapterDigest" not in public_selection
    assert catalog.catalog_id == "target-catalog:pajin-ai-rag-mcp"
    assert selection.registration.target_family == "ai-rag-mcp"
    assert selection.registration.network_policy == "not-provisioned-contract-only"
    assert selection.selection_state == "registered-fixture-not-runnable"
    assert selection.provider_execution_authorized is False
    assert selection.measurement_admission_eligible is False
    assert selection.ground_truth_digest == ground_truth.digest()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("targetProfileId", "ai-rag-mcp.unknown"),
        ("targetProfileVersion", "2.0.0"),
        ("mutationProfileId", "mutation:unregistered"),
        ("groundTruthDigest", "f" * 64),
    ],
)
def test_ai_rag_mcp_selection_rejects_manifest_expansion(
    field: str,
    value: str,
) -> None:
    profile, ground_truth, manifest, catalog = _inputs()
    raw = manifest.model_dump(mode="json", by_alias=True)
    raw[field] = value
    substituted = BenchmarkManifest.model_validate(raw)

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        select_ai_rag_mcp_target_fixture(
            substituted,
            profile=profile,
            catalog=catalog,
            ground_truth=ground_truth,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("visibility", "holdout"),
        ("matcherDigest", "f" * 64),
        ("expectedFindingId", "finding:substituted"),
    ],
)
def test_ai_rag_mcp_catalog_rejects_ground_truth_semantic_substitution(
    field: str,
    value: str,
) -> None:
    profile, ground_truth, _, _ = _inputs()
    raw = ground_truth.model_dump(mode="json", by_alias=True)
    raw["cases"][0][field] = value
    substituted = BenchmarkGroundTruth.model_validate(raw)

    with pytest.raises(BenchmarkTargetCatalogError, match="differs"):
        registered_ai_rag_mcp_target_catalog(profile, substituted)


def test_ai_rag_mcp_selection_rejects_traditional_web_api_catalog() -> None:
    profile, ground_truth, manifest, ai_catalog = _inputs()
    docker_profile = DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId="sha256:" + "1" * 64,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId="sha256:" + "2" * 64,
    )
    docker_ground_truth = registered_traditional_web_api_ground_truth(
        docker_profile,
        benchmark_id=manifest.benchmark_id,
    )
    docker_catalog = registered_traditional_web_api_target_catalog(
        docker_profile,
        docker_ground_truth,
    )

    with pytest.raises(BenchmarkTargetCatalogError):
        select_ai_rag_mcp_target_fixture(
            manifest,
            profile=profile,
            catalog=docker_catalog,
            ground_truth=ground_truth,
        )

    with pytest.raises(ValidationError, match="catalog ID and registration family differ"):
        BenchmarkTargetProfileCatalog(
            catalogId="target-catalog:pajin-traditional-web-api",
            registrations=ai_catalog.registrations,
        )


def test_ai_rag_mcp_profile_and_selection_reject_forged_authority() -> None:
    profile, ground_truth, manifest, catalog = _inputs()
    raw_profile = profile.model_dump(mode="json", by_alias=True)
    raw_profile["targetFactoryDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Target Factory Digest differs"):
        AIRAGMCPWalkingTargetProfile.model_validate(raw_profile)

    raw_contracts = profile.model_dump(mode="json", by_alias=True)
    raw_contracts["sourceContracts"] = raw_contracts["sourceContracts"][:-1]
    raw_contracts["targetFactoryDigest"] = ""
    with pytest.raises(ValidationError, match="at least 5 items"):
        AIRAGMCPWalkingTargetProfile.model_validate(raw_contracts)

    reordered_contracts = profile.model_dump(mode="json", by_alias=True)
    reordered_contracts["sourceContracts"] = list(
        reversed(reordered_contracts["sourceContracts"])
    )
    reordered_contracts["targetFactoryDigest"] = ""
    with pytest.raises(ValidationError, match="differ from code registration"):
        AIRAGMCPWalkingTargetProfile.model_validate(reordered_contracts)

    selection = select_ai_rag_mcp_target_fixture(
        manifest,
        profile=profile,
        catalog=catalog,
        ground_truth=ground_truth,
    )
    for field in ("providerExecutionAuthorized", "measurementAdmissionEligible"):
        raw_selection = selection.model_dump(mode="json", by_alias=True)
        raw_selection[field] = True
        with pytest.raises(ValidationError, match="Input should be False"):
            BenchmarkTargetFixtureSelectionAuthority.model_validate(raw_selection)
