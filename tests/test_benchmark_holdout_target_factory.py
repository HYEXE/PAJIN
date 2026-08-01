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
    GroundTruthVisibility,
    HoldoutTargetFactoryProfile,
    HoldoutTargetPrivateBinding,
    HoldoutTargetPrivateSuite,
    HoldoutTargetRegistration,
    HoldoutTargetSelectionAuthority,
    RegisteredBenchmarkTargetFactoryAdapter,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_holdout_private_suite,
    registered_traditional_web_api_holdout_profile,
    registered_traditional_web_api_holdout_registration,
    registered_traditional_web_api_target_catalog,
    select_traditional_web_api_holdout_factory,
)

BENCHMARK_ID = "benchmark:docker-bug-bounty-holdout-v1"
HOLDOUT_SEED = 780_984_302_134_771


def _profile(*, target_image_id: str = "sha256:" + "a" * 64) -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=target_image_id,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId="sha256:" + "b" * 64,
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
        measurementAuthorityDigest="c" * 64,
    )


def _manifest(
    profile: DockerBugBountyTargetProfile,
    ground_truth: BenchmarkGroundTruth,
    *,
    seeds: list[int] | None = None,
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
            protocolId="pajin:docker-bug-bounty-holdout-protocol",
            protocolVersion="1.0.0",
            seeds=[7] if seeds is None else seeds,
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
    BenchmarkTargetProfileCatalog,
    RegisteredBenchmarkTargetFactoryAdapter,
    HoldoutTargetFactoryProfile,
    HoldoutTargetPrivateSuite,
    HoldoutTargetRegistration,
]:
    active_profile = _profile()
    active_ground_truth = registered_traditional_web_api_ground_truth(
        active_profile,
        benchmark_id=BENCHMARK_ID,
    )
    manifest = _manifest(active_profile, active_ground_truth)
    active_catalog = registered_traditional_web_api_target_catalog(
        active_profile,
        active_ground_truth,
    )
    active_registration = active_catalog.registrations[0]
    holdout_profile = registered_traditional_web_api_holdout_profile(
        active_registration
    )
    private_suite = registered_traditional_web_api_holdout_private_suite(
        holdout_profile,
        active_registration,
        benchmark_id=BENCHMARK_ID,
    )
    registration = registered_traditional_web_api_holdout_registration(
        holdout_profile,
        active_registration,
        private_suite,
    )
    return (
        active_profile,
        active_ground_truth,
        manifest,
        active_catalog,
        _definition(active_profile),
        holdout_profile,
        private_suite,
        registration,
    )


def _select(
    *,
    manifest: BenchmarkManifest | None = None,
    active_catalog: BenchmarkTargetProfileCatalog | None = None,
    private_suite: HoldoutTargetPrivateSuite | None = None,
    registration: HoldoutTargetRegistration | None = None,
) -> HoldoutTargetSelectionAuthority:
    (
        active_profile,
        active_ground_truth,
        default_manifest,
        default_catalog,
        adapter,
        holdout_profile,
        default_suite,
        default_registration,
    ) = _inputs()
    return select_traditional_web_api_holdout_factory(
        default_manifest if manifest is None else manifest,
        adapter=adapter,
        active_profile=active_profile,
        active_catalog=default_catalog if active_catalog is None else active_catalog,
        active_ground_truth=active_ground_truth,
        holdout_profile=holdout_profile,
        holdout_registration=(
            default_registration if registration is None else registration
        ),
        private_suite=default_suite if private_suite is None else private_suite,
    )


def test_holdout_selection_keeps_private_case_matcher_and_seed_out_of_public_artifacts() -> None:
    (
        _,
        _,
        manifest,
        active_catalog,
        _,
        profile,
        private_suite,
        registration,
    ) = _inputs()
    selection = _select()

    public_artifacts = [
        manifest.model_dump(mode="json", by_alias=True),
        active_catalog.model_dump(mode="json", by_alias=True),
        profile.model_dump(mode="json", by_alias=True),
        registration.model_dump(mode="json", by_alias=True),
        selection.model_dump(mode="json", by_alias=True),
    ]
    public_text = str(public_artifacts)
    private_case = private_suite.ground_truth.cases[0]

    assert private_case.visibility is GroundTruthVisibility.HOLDOUT
    assert private_case.ground_truth_id not in public_text
    assert private_case.expected_finding_id not in public_text
    assert private_case.matcher_id not in public_text
    assert private_case.matcher_digest not in public_text
    assert str(HOLDOUT_SEED) not in public_text
    assert "cases" not in str(selection.model_dump(mode="json", by_alias=True))
    assert selection.selection_state == "holdout-bound-not-runnable"
    assert selection.provider_execution_authorized is False
    assert selection.measurement_admission_eligible is False
    assert selection.holdout_content_disclosure_authorized is False


def test_holdout_factory_and_ground_truth_are_distinct_from_active_identity() -> None:
    (
        active_profile,
        active_ground_truth,
        _,
        active_catalog,
        _,
        holdout_profile,
        private_suite,
        registration,
    ) = _inputs()

    assert holdout_profile.target_factory_digest != active_profile.target_factory_digest
    assert private_suite.ground_truth.target_factory_digest == holdout_profile.target_factory_digest
    assert private_suite.ground_truth.digest() != active_ground_truth.digest()
    assert (
        registration.active_registration_digest
        == active_catalog.registrations[0].registration_digest
    )
    binding = HoldoutTargetPrivateBinding(
        registration=registration,
        privateSuite=private_suite,
    )
    assert binding.binding_digest == binding.model_copy().binding_digest


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("evaluationSeeds",), [8]),
        (("groundTruth", "cases", 0, "matcherDigest"), "f" * 64),
        (("groundTruth", "cases", 0, "expectedFindingId"), "finding:active-replay"),
    ],
)
def test_holdout_registration_rejects_private_suite_substitution(
    path: tuple[str | int, ...],
    value: object,
) -> None:
    *_, active_catalog, _, holdout_profile, private_suite, _ = _inputs()
    raw = private_suite.model_dump(mode="json", by_alias=True)
    raw.pop("suiteId")
    raw.pop("suiteDigest")
    cursor: object = raw
    for key in path[:-1]:
        cursor = cursor[key]  # type: ignore[index]
    cursor[path[-1]] = value  # type: ignore[index]
    substituted = HoldoutTargetPrivateSuite.model_validate(raw)

    with pytest.raises(BenchmarkTargetCatalogError, match="differs from code registration"):
        registered_traditional_web_api_holdout_registration(
            holdout_profile,
            active_catalog.registrations[0],
            substituted,
        )


def test_holdout_private_suite_rejects_seeded_case_replay() -> None:
    *_, private_suite, _ = _inputs()
    raw = private_suite.model_dump(mode="json", by_alias=True)
    raw.pop("suiteId")
    raw.pop("suiteDigest")
    raw["groundTruth"]["cases"][0]["visibility"] = "seeded"

    with pytest.raises(ValidationError, match="only holdout cases"):
        HoldoutTargetPrivateSuite.model_validate(raw)


def test_holdout_selection_rejects_active_seed_reuse() -> None:
    (
        active_profile,
        active_ground_truth,
        _,
        active_catalog,
        _,
        _,
        _,
        _,
    ) = _inputs()
    replay_manifest = _manifest(
        active_profile,
        active_ground_truth,
        seeds=[HOLDOUT_SEED],
    )

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed") as exc_info:
        _select(manifest=replay_manifest, active_catalog=active_catalog)
    assert "replays an active seed" in str(exc_info.value.__cause__)


def test_holdout_selection_rejects_active_catalog_scope_expansion() -> None:
    *_, active_catalog, _, _, _, _ = _inputs()
    original = active_catalog.registrations[0]
    expanded_registration = BenchmarkTargetProfileRegistration(
        targetFamily="traditional-web-api",
        targetProfileId="bug-bounty.api.scope-expanded",
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
                (original, expanded_registration),
                key=lambda item: (item.target_profile_id, item.target_profile_version),
            )
        )
    )

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        _select(active_catalog=expanded)


def test_holdout_selection_rejects_cross_active_profile_replay() -> None:
    (
        _,
        _,
        manifest,
        _,
        _,
        holdout_profile,
        private_suite,
        registration,
    ) = _inputs()
    other_profile = _profile(target_image_id="sha256:" + "9" * 64)
    other_ground_truth = registered_traditional_web_api_ground_truth(
        other_profile,
        benchmark_id=BENCHMARK_ID,
    )
    other_catalog = registered_traditional_web_api_target_catalog(
        other_profile,
        other_ground_truth,
    )

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        select_traditional_web_api_holdout_factory(
            manifest,
            adapter=_definition(other_profile),
            active_profile=other_profile,
            active_catalog=other_catalog,
            active_ground_truth=other_ground_truth,
            holdout_profile=holdout_profile,
            holdout_registration=registration,
            private_suite=private_suite,
        )


def test_holdout_selection_rejects_registration_and_private_binding_substitution() -> None:
    *_, registration = _inputs()
    raw = registration.model_dump(mode="json", by_alias=True)
    raw.pop("registrationId")
    raw.pop("registrationDigest")
    raw["privateSuiteDigest"] = "f" * 64
    substituted = HoldoutTargetRegistration.model_validate(raw)

    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        _select(registration=substituted)

    *_, private_suite, registration = _inputs()
    raw_suite = private_suite.model_dump(mode="json", by_alias=True)
    raw_suite.pop("suiteId")
    raw_suite.pop("suiteDigest")
    raw_suite["evaluationSeeds"] = [HOLDOUT_SEED + 1]
    other_suite = HoldoutTargetPrivateSuite.model_validate(raw_suite)
    with pytest.raises(ValidationError, match="differs from registration"):
        HoldoutTargetPrivateBinding(
            registration=registration,
            privateSuite=other_suite,
        )


@pytest.mark.parametrize(
    "field",
    [
        "providerExecutionAuthorized",
        "measurementAdmissionEligible",
        "holdoutContentDisclosureAuthorized",
    ],
)
def test_holdout_selection_cannot_forge_authority_flags(field: str) -> None:
    selection = _select()
    raw = selection.model_dump(mode="json", by_alias=True)
    raw[field] = True

    with pytest.raises(ValidationError, match="Input should be False"):
        HoldoutTargetSelectionAuthority.model_validate(raw)


def test_holdout_models_reject_forged_content_digests() -> None:
    *_, holdout_profile, private_suite, registration = _inputs()
    raw_profile = holdout_profile.model_dump(mode="json", by_alias=True)
    raw_profile["targetFactoryDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Factory Digest differs"):
        HoldoutTargetFactoryProfile.model_validate(raw_profile)

    raw_suite = private_suite.model_dump(mode="json", by_alias=True)
    raw_suite["suiteDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Suite Digest differs"):
        HoldoutTargetPrivateSuite.model_validate(raw_suite)

    raw_registration = registration.model_dump(mode="json", by_alias=True)
    raw_registration["registrationDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="Registration Digest differs"):
        HoldoutTargetRegistration.model_validate(raw_registration)
