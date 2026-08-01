from __future__ import annotations

from dataclasses import dataclass

import pytest
from pydantic import ValidationError

from pajin.benchmark import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkRunProtocol,
    BenchmarkTargetCatalogError,
    BenchmarkTargetGroundTruthBinding,
    BenchmarkTargetProfileCatalog,
    BenchmarkTargetProfileRegistration,
    BenchmarkTargetProfileSelectionAuthority,
    DockerAIRAGMCPTargetProfile,
    DockerBugBountyTargetProfile,
    HybridTargetCompositionAuthority,
    HybridTargetGroundTruthBinding,
    HybridTargetSelectionAuthority,
    RegisteredBenchmarkTargetFactoryAdapter,
    bind_hybrid_target_ground_truth,
    registered_ai_rag_mcp_docker_ground_truth,
    registered_ai_rag_mcp_docker_target_catalog,
    registered_hybrid_target_composition,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
    select_ai_rag_mcp_docker_target_profile,
    select_hybrid_target_composition,
    select_traditional_web_api_target_profile,
)

MEASUREMENT_DIGEST = "9" * 64


@dataclass(frozen=True, slots=True)
class _Inputs:
    traditional_manifest: BenchmarkManifest
    traditional_profile: DockerBugBountyTargetProfile
    traditional_catalog: BenchmarkTargetProfileCatalog
    traditional_adapter: RegisteredBenchmarkTargetFactoryAdapter
    traditional_selection: BenchmarkTargetProfileSelectionAuthority
    traditional_binding: BenchmarkTargetGroundTruthBinding
    ai_profile: DockerAIRAGMCPTargetProfile
    ai_manifest: BenchmarkManifest
    ai_catalog: BenchmarkTargetProfileCatalog
    ai_adapter: RegisteredBenchmarkTargetFactoryAdapter
    ai_selection: BenchmarkTargetProfileSelectionAuthority
    ai_binding: BenchmarkTargetGroundTruthBinding


def _traditional_profile() -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId="sha256:" + "1" * 64,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId="sha256:" + "2" * 64,
    )


def _ai_profile() -> DockerAIRAGMCPTargetProfile:
    return DockerAIRAGMCPTargetProfile(
        targetImage="pajin-ai-rag-mcp-target:dev",
        targetImageId="sha256:" + "3" * 64,
        workerImage="pajin-ai-rag-mcp-benchmark-worker:dev",
        workerImageId="sha256:" + "4" * 64,
    )


def _manifest(
    *,
    benchmark_id: str,
    factory_id: str,
    factory_digest: str,
    profile_id: str,
    ground_truth_digest: str,
    arm_id: str,
) -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId=benchmark_id,
        targetFactoryId=factory_id,
        targetFactoryVersion="1.0.0",
        targetFactoryDigest=factory_digest,
        targetProfileId=profile_id,
        targetProfileVersion="1.0.0",
        mutationProfileId=None,
        campaignDigest="5" * 64,
        groundTruthDigest=ground_truth_digest,
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:hybrid-component-protocol",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=1,
            timeoutSeconds=120,
            maxCostUsd=1,
            maxToolCalls=10,
            maxModelCalls=0,
        ),
        arms=[
            BenchmarkArm(
                armId=arm_id,
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId=f"pajin:{arm_id}",
                implementationVersion="1.0.0",
                configurationDigest="6" * 64,
                adaptiveSupervisor=False,
            )
        ],
    )


def _adapter(
    *,
    adapter_id: str,
    factory_id: str,
    factory_digest: str,
) -> RegisteredBenchmarkTargetFactoryAdapter:
    return RegisteredBenchmarkTargetFactoryAdapter(
        adapterId=adapter_id,
        adapterVersion="1.0.0",
        targetFactoryId=factory_id,
        targetFactoryVersion="1.0.0",
        targetFactoryDigest=factory_digest,
        measurementAuthorityId="measurement-authority:hybrid-fixture",
        measurementAuthorityVersion="1.0.0",
        measurementAuthorityDigest=MEASUREMENT_DIGEST,
    )


def _inputs() -> _Inputs:
    traditional_profile = _traditional_profile()
    traditional_ground_truth = registered_traditional_web_api_ground_truth(
        traditional_profile,
        benchmark_id="benchmark:hybrid-traditional-component",
    )
    traditional_manifest = _manifest(
        benchmark_id=traditional_ground_truth.benchmark_id,
        factory_id="target-factory:docker-bug-bounty",
        factory_digest=traditional_profile.target_factory_digest,
        profile_id=traditional_profile.profile_id,
        ground_truth_digest=traditional_ground_truth.digest(),
        arm_id="arm:hybrid-traditional",
    )
    traditional_adapter = _adapter(
        adapter_id="target-adapter:docker-bug-bounty",
        factory_id="target-factory:docker-bug-bounty",
        factory_digest=traditional_profile.target_factory_digest,
    )
    traditional_catalog = registered_traditional_web_api_target_catalog(
        traditional_profile,
        traditional_ground_truth,
    )
    traditional_selection = select_traditional_web_api_target_profile(
        traditional_manifest,
        adapter=traditional_adapter,
        profile=traditional_profile,
        catalog=traditional_catalog,
        ground_truth=traditional_ground_truth,
    )
    traditional_binding = BenchmarkTargetGroundTruthBinding(
        registration=traditional_selection.registration,
        groundTruth=traditional_ground_truth,
    )

    ai_profile = _ai_profile()
    ai_ground_truth = registered_ai_rag_mcp_docker_ground_truth(
        ai_profile,
        benchmark_id="benchmark:hybrid-ai-component",
    )
    ai_manifest = _manifest(
        benchmark_id=ai_ground_truth.benchmark_id,
        factory_id="target-factory:docker-ai-rag-mcp",
        factory_digest=ai_profile.target_factory_digest,
        profile_id=ai_profile.profile_id,
        ground_truth_digest=ai_ground_truth.digest(),
        arm_id="arm:hybrid-ai",
    )
    ai_adapter = _adapter(
        adapter_id="target-adapter:docker-ai-rag-mcp",
        factory_id="target-factory:docker-ai-rag-mcp",
        factory_digest=ai_profile.target_factory_digest,
    )
    ai_catalog = registered_ai_rag_mcp_docker_target_catalog(
        ai_profile,
        ai_ground_truth,
    )
    ai_selection = select_ai_rag_mcp_docker_target_profile(
        ai_manifest,
        adapter=ai_adapter,
        profile=ai_profile,
        catalog=ai_catalog,
        ground_truth=ai_ground_truth,
    )
    ai_binding = BenchmarkTargetGroundTruthBinding(
        registration=ai_selection.registration,
        groundTruth=ai_ground_truth,
    )
    return _Inputs(
        traditional_profile=traditional_profile,
        traditional_manifest=traditional_manifest,
        traditional_catalog=traditional_catalog,
        traditional_adapter=traditional_adapter,
        traditional_selection=traditional_selection,
        traditional_binding=traditional_binding,
        ai_profile=ai_profile,
        ai_manifest=ai_manifest,
        ai_catalog=ai_catalog,
        ai_adapter=ai_adapter,
        ai_selection=ai_selection,
        ai_binding=ai_binding,
    )


def _registered_composition(
    inputs: _Inputs,
    *,
    traditional_selection: BenchmarkTargetProfileSelectionAuthority | None = None,
    ai_selection: BenchmarkTargetProfileSelectionAuthority | None = None,
    ai_manifest: BenchmarkManifest | None = None,
    ai_profile: DockerAIRAGMCPTargetProfile | None = None,
    ai_adapter: RegisteredBenchmarkTargetFactoryAdapter | None = None,
) -> HybridTargetCompositionAuthority:
    return registered_hybrid_target_composition(
        traditional_selection=traditional_selection or inputs.traditional_selection,
        traditional_manifest=inputs.traditional_manifest,
        traditional_profile=inputs.traditional_profile,
        traditional_catalog=inputs.traditional_catalog,
        traditional_adapter=inputs.traditional_adapter,
        ai_selection=ai_selection or inputs.ai_selection,
        ai_manifest=ai_manifest or inputs.ai_manifest,
        ai_profile=ai_profile or inputs.ai_profile,
        ai_catalog=inputs.ai_catalog,
        ai_adapter=ai_adapter or inputs.ai_adapter,
    )


def _composition_inputs():
    inputs = _inputs()
    composition = _registered_composition(inputs)
    private_binding = bind_hybrid_target_ground_truth(
        composition,
        traditional_ground_truth=inputs.traditional_binding,
        ai_ground_truth=inputs.ai_binding,
    )
    return composition, private_binding


def test_hybrid_composition_binds_exact_components_without_claiming_execution() -> None:
    composition, private_binding = _composition_inputs()

    selection = select_hybrid_target_composition(composition, private_binding)

    public = composition.model_dump(mode="json", by_alias=True)
    selected = selection.model_dump(mode="json", by_alias=True)
    private = private_binding.model_dump(mode="json", by_alias=True)
    assert "cases" not in str(public)
    assert "cases" not in str(selected)
    assert "cases" in str(private)
    assert [component.ordinal for component in composition.components] == [1, 2]
    assert [component.role for component in composition.components] == [
        "entry-traditional-web-api",
        "follow-on-ai-rag-mcp",
    ]
    assert composition.bridge.bridge_state == "declared-not-executed"
    assert composition.target_factory_registered is False
    assert composition.benchmark_manifest_eligible is False
    assert composition.provider_execution_authorized is False
    assert private_binding.chain_state == "declared-not-executed"
    assert selection.selection_state == "registered-composition-not-runnable"
    assert selection.provider_execution_authorized is False
    assert selection.measurement_admission_eligible is False
    assert selection.benchmark_manifest_eligible is False


def test_hybrid_composition_rejects_reversed_or_repeated_components() -> None:
    inputs = _inputs()

    with pytest.raises(BenchmarkTargetCatalogError, match="composition failed"):
        registered_hybrid_target_composition(
            traditional_selection=inputs.ai_selection,
            traditional_manifest=inputs.traditional_manifest,
            traditional_profile=inputs.traditional_profile,
            traditional_catalog=inputs.traditional_catalog,
            traditional_adapter=inputs.traditional_adapter,
            ai_selection=inputs.traditional_selection,
            ai_manifest=inputs.ai_manifest,
            ai_profile=inputs.ai_profile,
            ai_catalog=inputs.ai_catalog,
            ai_adapter=inputs.ai_adapter,
        )
    with pytest.raises(BenchmarkTargetCatalogError, match="composition failed"):
        _registered_composition(
            inputs,
            ai_selection=inputs.traditional_selection,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("targetProfileVersion", "2.0.0"),
        ("providerProfileApiVersion", "pajin.dev/substituted-provider/v1alpha1"),
        ("networkPolicy", "not-provisioned-contract-only"),
        ("mutationProfileIds", ["mutation:scope-expansion"]),
    ],
)
def test_hybrid_composition_rejects_component_policy_expansion(
    field: str,
    value: str | list[str],
) -> None:
    inputs = _inputs()
    raw_registration = inputs.ai_selection.registration.model_dump(
        mode="json", by_alias=True
    )
    raw_registration["registrationId"] = ""
    raw_registration["registrationDigest"] = ""
    raw_registration[field] = value
    substituted_registration = BenchmarkTargetProfileRegistration.model_validate(
        raw_registration
    )
    raw_selection = inputs.ai_selection.model_dump(mode="json", by_alias=True)
    raw_selection["authorityId"] = ""
    raw_selection["authorityDigest"] = ""
    raw_selection["registration"] = substituted_registration.model_dump(
        mode="json", by_alias=True
    )
    raw_selection["providerProfileDigest"] = (
        substituted_registration.provider_profile_digest
    )
    substituted_selection = type(inputs.ai_selection).model_validate(raw_selection)

    with pytest.raises(BenchmarkTargetCatalogError, match="composition failed"):
        _registered_composition(
            inputs,
            ai_selection=substituted_selection,
        )


def test_hybrid_builder_rejects_profile_and_adapter_source_substitution() -> None:
    inputs = _inputs()
    alternate_adapter = _adapter(
        adapter_id="target-adapter:docker-ai-rag-mcp-alternate",
        factory_id="target-factory:docker-ai-rag-mcp",
        factory_digest=inputs.ai_profile.target_factory_digest,
    )
    substituted_profile = DockerAIRAGMCPTargetProfile(
        targetImage="pajin-ai-rag-mcp-target:dev",
        targetImageId="sha256:" + "7" * 64,
        workerImage="pajin-ai-rag-mcp-benchmark-worker:dev",
        workerImageId="sha256:" + "4" * 64,
    )
    substituted_manifest = inputs.ai_manifest.model_copy(
        update={"campaign_digest": "7" * 64}
    )

    with pytest.raises(BenchmarkTargetCatalogError, match="composition failed"):
        _registered_composition(inputs, ai_adapter=alternate_adapter)
    with pytest.raises(BenchmarkTargetCatalogError, match="composition failed"):
        _registered_composition(inputs, ai_profile=substituted_profile)
    with pytest.raises(BenchmarkTargetCatalogError, match="composition failed"):
        _registered_composition(inputs, ai_manifest=substituted_manifest)


def test_hybrid_private_binding_rejects_scope_expansion() -> None:
    composition, _ = _composition_inputs()
    inputs = _inputs()
    raw_ground_truth = inputs.ai_binding.ground_truth.model_dump(
        mode="json", by_alias=True
    )
    raw_ground_truth["cases"][0]["surfaceIds"].append("surface:scope-expansion")
    expanded_ground_truth = BenchmarkGroundTruth.model_validate(raw_ground_truth)
    expanded_registration = BenchmarkTargetProfileRegistration.model_validate(
        {
            **inputs.ai_selection.registration.model_dump(mode="json", by_alias=True),
            "registrationId": "",
            "registrationDigest": "",
            "groundTruthDigest": expanded_ground_truth.digest(),
        }
    )
    expanded_binding = BenchmarkTargetGroundTruthBinding(
        registration=expanded_registration,
        groundTruth=expanded_ground_truth,
    )

    with pytest.raises(ValidationError, match="semantics differ"):
        HybridTargetGroundTruthBinding(
            compositionDigest=composition.composition_digest,
            bridgeDigest=composition.bridge.bridge_digest,
            componentBindings=(inputs.traditional_binding, expanded_binding),
        )
    assert inputs.traditional_selection.ground_truth_digest != expanded_ground_truth.digest()


def test_hybrid_selection_rejects_cross_composition_private_binding() -> None:
    composition, private_binding = _composition_inputs()
    inputs = _inputs()
    alternate_adapter = _adapter(
        adapter_id="target-adapter:docker-ai-rag-mcp-alternate",
        factory_id="target-factory:docker-ai-rag-mcp",
        factory_digest=inputs.ai_profile.target_factory_digest,
    )
    raw_ai = inputs.ai_selection.model_dump(mode="json", by_alias=True)
    raw_ai["authorityId"] = ""
    raw_ai["authorityDigest"] = ""
    raw_ai["adapterDigest"] = alternate_adapter.adapter_digest
    alternate_ai_selection = type(inputs.ai_selection).model_validate(raw_ai)
    alternate = _registered_composition(
        inputs,
        ai_selection=alternate_ai_selection,
        ai_adapter=alternate_adapter,
    )
    assert alternate.composition_digest != composition.composition_digest

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        select_hybrid_target_composition(alternate, private_binding)


def test_hybrid_selection_rejects_private_registration_substitution() -> None:
    composition, _ = _composition_inputs()
    inputs = _inputs()
    raw_registration = inputs.ai_selection.registration.model_dump(
        mode="json", by_alias=True
    )
    raw_registration["registrationId"] = ""
    raw_registration["registrationDigest"] = ""
    raw_registration["targetProfileId"] = "ai-rag-mcp.docker.substituted-profile"
    substituted_registration = BenchmarkTargetProfileRegistration.model_validate(
        raw_registration
    )
    substituted_binding = BenchmarkTargetGroundTruthBinding(
        registration=substituted_registration,
        groundTruth=inputs.ai_binding.ground_truth,
    )
    forged_private = HybridTargetGroundTruthBinding(
        compositionDigest=composition.composition_digest,
        bridgeDigest=composition.bridge.bridge_digest,
        componentBindings=(inputs.traditional_binding, substituted_binding),
    )

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        select_hybrid_target_composition(composition, forged_private)


def test_hybrid_authorities_reject_digest_bridge_and_flag_forgery() -> None:
    composition, private_binding = _composition_inputs()
    selection = select_hybrid_target_composition(composition, private_binding)

    raw_composition = composition.model_dump(mode="json", by_alias=True)
    raw_composition["compositionDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Composition Digest differs"):
        HybridTargetCompositionAuthority.model_validate(raw_composition)

    expanded_composition = composition.model_dump(mode="json", by_alias=True)
    expanded_composition["providerExecutionAuthorized"] = True
    with pytest.raises(ValidationError, match="Input should be False"):
        HybridTargetCompositionAuthority.model_validate(expanded_composition)

    partial = composition.model_dump(mode="json", by_alias=True)
    partial["compositionId"] = ""
    partial["compositionDigest"] = ""
    partial["components"] = partial["components"][:1]
    with pytest.raises(ValidationError, match="at least 2 items"):
        HybridTargetCompositionAuthority.model_validate(partial)

    raw_bridge = composition.model_dump(mode="json", by_alias=True)
    raw_bridge["compositionId"] = ""
    raw_bridge["compositionDigest"] = ""
    raw_bridge["bridge"]["destinationSurfaceIds"].append("surface:scope-expansion")
    raw_bridge["bridge"]["bridgeDigest"] = ""
    with pytest.raises(ValidationError, match="at most 3 items"):
        HybridTargetCompositionAuthority.model_validate(raw_bridge)

    for field in (
        "providerExecutionAuthorized",
        "measurementAdmissionEligible",
        "benchmarkManifestEligible",
    ):
        raw_selection = selection.model_dump(mode="json", by_alias=True)
        raw_selection[field] = True
        with pytest.raises(ValidationError, match="Input should be False"):
            HybridTargetSelectionAuthority.model_validate(raw_selection)
