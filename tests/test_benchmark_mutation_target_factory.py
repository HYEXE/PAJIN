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
    BenchmarkTargetProfileCatalog,
    BenchmarkTargetProfileRegistration,
    DockerBugBountyTargetProfile,
    MutationResetPlanAuthority,
    MutationTargetProfile,
    MutationTargetRegistration,
    MutationTargetSelectionAuthority,
    RegisteredBenchmarkTargetFactoryAdapter,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_mutation_manifest,
    registered_traditional_web_api_mutation_profile,
    registered_traditional_web_api_mutation_registration,
    registered_traditional_web_api_target_catalog,
    select_traditional_web_api_mutation_target,
)

BENCHMARK_ID = "benchmark:docker-bug-bounty-mutation-v1"
MUTATION_ID = "mutation:traditional-web-api.seeded-account-layout-v1"


def _profile(*, target_image_id: str = "sha256:" + "a" * 64) -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=target_image_id,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId="sha256:" + "b" * 64,
    )


def _adapter(
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
        measurementAuthorityDigest="c" * 64,
    )


def _manifest(
    profile: DockerBugBountyTargetProfile,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId=BENCHMARK_ID,
        targetFactoryId="target-factory:docker-bug-bounty",
        targetFactoryVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        mutationProfileId=None,
        campaignDigest="d" * 64,
        groundTruthDigest=ground_truth.digest(),
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:docker-bug-bounty-mutation-protocol",
            protocolVersion="1.0.0",
            seeds=[7, 11],
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


def _inputs() -> tuple[
    DockerBugBountyTargetProfile,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkManifest,
    BenchmarkTargetProfileCatalog,
    RegisteredBenchmarkTargetFactoryAdapter,
    MutationTargetProfile,
    MutationTargetRegistration,
]:
    base_profile = _profile()
    ground_truth = registered_traditional_web_api_ground_truth(
        base_profile,
        benchmark_id=BENCHMARK_ID,
    )
    base_manifest = _manifest(base_profile, ground_truth)
    base_catalog = registered_traditional_web_api_target_catalog(
        base_profile,
        ground_truth,
    )
    mutation_profile = registered_traditional_web_api_mutation_profile(
        base_catalog.registrations[0]
    )
    mutation_registration = registered_traditional_web_api_mutation_registration(
        mutation_profile,
        base_catalog.registrations[0],
    )
    mutation_manifest = registered_traditional_web_api_mutation_manifest(
        base_manifest,
        mutation_profile,
        base_catalog.registrations[0],
        ground_truth,
    )
    return (
        base_profile,
        ground_truth,
        base_manifest,
        mutation_manifest,
        base_catalog,
        _adapter(base_profile),
        mutation_profile,
        mutation_registration,
    )


def _select(
    *,
    base_manifest: BenchmarkManifest | None = None,
    mutation_manifest: BenchmarkManifest | None = None,
    base_catalog: BenchmarkTargetProfileCatalog | None = None,
    mutation_profile: MutationTargetProfile | None = None,
    mutation_registration: MutationTargetRegistration | None = None,
) -> MutationTargetSelectionAuthority:
    (
        profile,
        ground_truth,
        default_base_manifest,
        default_mutation_manifest,
        default_catalog,
        adapter,
        default_profile,
        default_registration,
    ) = _inputs()
    return select_traditional_web_api_mutation_target(
        default_base_manifest if base_manifest is None else base_manifest,
        default_mutation_manifest if mutation_manifest is None else mutation_manifest,
        adapter=adapter,
        base_profile=profile,
        base_catalog=default_catalog if base_catalog is None else base_catalog,
        base_ground_truth=ground_truth,
        mutation_profile=default_profile if mutation_profile is None else mutation_profile,
        mutation_registration=(
            default_registration
            if mutation_registration is None
            else mutation_registration
        ),
    )


def test_mutation_selection_binds_exact_derived_manifest_and_reset_plan() -> None:
    *_, base_manifest, mutation_manifest, base_catalog, _, profile, registration = (
        _inputs()
    )
    selection = _select()

    base_raw = base_manifest.model_dump(mode="json", by_alias=True)
    mutation_raw = mutation_manifest.model_dump(mode="json", by_alias=True)
    changed = {
        key
        for key in base_raw
        if base_raw[key] != mutation_raw[key]
    }
    assert changed == {"mutationProfileId"}
    assert mutation_manifest.mutation_profile_id == MUTATION_ID
    assert base_catalog.registrations[0].mutation_profile_ids == ()
    assert (
        registration.base_registration_digest
        == base_catalog.registrations[0].registration_digest
    )
    assert selection.reset_plan.benchmark_seeds == tuple(base_manifest.protocol.seeds)
    assert selection.reset_plan.mutation_seed == profile.mutation_seed
    assert selection.reset_plan.operation_digests == tuple(
        item.operation_digest for item in profile.operations
    )
    assert selection.selection_state == "mutation-bound-not-runnable"
    assert selection.provider_execution_authorized is False
    assert selection.measurement_admission_eligible is False
    assert selection.mutation_materialization_authorized is False
    assert selection.reset_plan.reset_receipt_bound is False


def test_mutation_profile_has_exact_ordered_state_chain() -> None:
    *_, profile, _ = _inputs()

    assert [item.ordinal for item in profile.operations] == [1, 2, 3]
    assert [item.action for item in profile.operations] == [
        "restore-base-snapshot",
        "apply-seeded-account-layout",
        "verify-expected-state",
    ]
    assert profile.operations[0].input_state_digest == profile.base_state_digest
    assert profile.operations[-1].output_state_digest == profile.expected_state_digest


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mutationSeed", 8),
        ("baseStateDigest", "f" * 64),
        ("expectedStateDigest", "f" * 64),
    ],
)
def test_mutation_profile_rejects_seed_state_and_base_substitution(
    field: str,
    value: object,
) -> None:
    *_, profile, _ = _inputs()
    raw = profile.model_dump(mode="json", by_alias=True)
    raw.pop("mutationProfileDigest")
    raw[field] = value

    with pytest.raises(ValidationError):
        MutationTargetProfile.model_validate(raw)


def test_mutation_profile_rejects_operation_reorder_and_chain_break() -> None:
    *_, profile, _ = _inputs()
    raw = profile.model_dump(mode="json", by_alias=True)
    raw.pop("mutationProfileDigest")
    raw["operations"] = list(reversed(raw["operations"]))
    with pytest.raises(ValidationError, match="canonical ordinals"):
        MutationTargetProfile.model_validate(raw)

    raw = profile.model_dump(mode="json", by_alias=True)
    raw.pop("mutationProfileDigest")
    raw["operations"][1].pop("operationDigest")
    raw["operations"][1]["inputStateDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="state chain"):
        MutationTargetProfile.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("mutationProfileId", "mutation:unregistered"),
        ("campaignDigest", "f" * 64),
        ("groundTruthDigest", "f" * 64),
        ("targetProfileVersion", "2.0.0"),
    ],
)
def test_mutation_selection_rejects_manifest_scope_expansion(
    field: str,
    value: str,
) -> None:
    *_, mutation_manifest, _, _, _, _ = _inputs()
    raw = mutation_manifest.model_dump(mode="json", by_alias=True)
    raw[field] = value
    substituted = BenchmarkManifest.model_validate(raw)

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        _select(mutation_manifest=substituted)


def test_mutation_selection_rejects_cross_base_profile_replay() -> None:
    (
        _,
        _,
        base_manifest,
        mutation_manifest,
        _,
        _,
        mutation_profile,
        mutation_registration,
    ) = _inputs()
    other = _profile(target_image_id="sha256:" + "9" * 64)
    other_ground_truth = registered_traditional_web_api_ground_truth(
        other,
        benchmark_id=BENCHMARK_ID,
    )
    other_catalog = registered_traditional_web_api_target_catalog(
        other,
        other_ground_truth,
    )

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        select_traditional_web_api_mutation_target(
            base_manifest,
            mutation_manifest,
            adapter=_adapter(other),
            base_profile=other,
            base_catalog=other_catalog,
            base_ground_truth=other_ground_truth,
            mutation_profile=mutation_profile,
            mutation_registration=mutation_registration,
        )


def test_mutation_selection_rejects_base_catalog_scope_expansion() -> None:
    *_, base_catalog, _, _, _ = _inputs()
    original = base_catalog.registrations[0]
    extra = BenchmarkTargetProfileRegistration(
        targetFamily="traditional-web-api",
        targetProfileId="bug-bounty.api.mutation-expanded",
        targetProfileVersion="1.0.0",
        targetFactoryId=original.target_factory_id,
        targetFactoryVersion=original.target_factory_version,
        targetFactoryDigest=original.target_factory_digest,
        providerProfileApiVersion=original.provider_profile_api_version,
        providerProfileDigest=original.provider_profile_digest,
        mutationProfileIds=(),
        networkPolicy=original.network_policy,
        groundTruthDigest=original.ground_truth_digest,
    )
    expanded = BenchmarkTargetProfileCatalog(
        registrations=tuple(
            sorted(
                (original, extra),
                key=lambda item: (item.target_profile_id, item.target_profile_version),
            )
        )
    )

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        _select(base_catalog=expanded)


def test_mutation_registration_rejects_profile_and_digest_substitution() -> None:
    *_, base_catalog, _, profile, registration = _inputs()
    other_base = BenchmarkTargetProfileRegistration.model_validate(
        {
            **base_catalog.registrations[0].model_dump(mode="json", by_alias=True),
            "registrationId": "",
            "registrationDigest": "",
            "targetProfileId": "bug-bounty.api.other-base",
        }
    )
    with pytest.raises(BenchmarkTargetCatalogError, match="differs from code registration"):
        registered_traditional_web_api_mutation_registration(profile, other_base)

    raw = registration.model_dump(mode="json", by_alias=True)
    raw["registrationDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Registration Digest differs"):
        MutationTargetRegistration.model_validate(raw)


def test_mutation_manifest_derivation_rejects_already_mutated_base() -> None:
    _, ground_truth, _, mutation_manifest, catalog, _, profile, _ = _inputs()

    with pytest.raises(BenchmarkTargetCatalogError, match="already contains"):
        registered_traditional_web_api_mutation_manifest(
            mutation_manifest,
            profile,
            catalog.registrations[0],
            ground_truth,
        )


def test_mutation_manifest_derivation_rejects_benchmark_ground_truth_replay() -> None:
    _, ground_truth, base_manifest, _, catalog, _, profile, _ = _inputs()
    raw = base_manifest.model_dump(mode="json", by_alias=True)
    raw["benchmarkId"] = "benchmark:replayed-base"
    replayed = BenchmarkManifest.model_validate(raw)

    with pytest.raises(BenchmarkTargetCatalogError, match="differs from base registration"):
        registered_traditional_web_api_mutation_manifest(
            replayed,
            profile,
            catalog.registrations[0],
            ground_truth,
        )


@pytest.mark.parametrize(
    "field",
    [
        "providerExecutionAuthorized",
        "measurementAdmissionEligible",
        "mutationMaterializationAuthorized",
    ],
)
def test_mutation_selection_cannot_forge_authority_flags(field: str) -> None:
    selection = _select()
    raw = selection.model_dump(mode="json", by_alias=True)
    raw[field] = True

    with pytest.raises(ValidationError, match="Input should be False"):
        MutationTargetSelectionAuthority.model_validate(raw)


def test_mutation_reset_plan_rejects_receipt_claim_and_forged_digest() -> None:
    plan = _select().reset_plan
    raw = plan.model_dump(mode="json", by_alias=True)
    raw["resetReceiptBound"] = True
    with pytest.raises(ValidationError, match="Input should be False"):
        MutationResetPlanAuthority.model_validate(raw)

    raw = plan.model_dump(mode="json", by_alias=True)
    raw["planDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Reset Plan Digest differs"):
        MutationResetPlanAuthority.model_validate(raw)
