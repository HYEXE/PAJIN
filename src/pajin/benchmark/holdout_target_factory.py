"""P0-D4 private Holdout Target Factory authority for one registered active Target."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.docker_provider import DockerBugBountyTargetProfile
from pajin.benchmark.models import (
    BenchmarkGroundTruth,
    BenchmarkGroundTruthCase,
    BenchmarkManifest,
    GroundTruthVisibility,
    benchmark_digest,
    canonical_benchmark_json,
)
from pajin.benchmark.target_catalog import (
    BenchmarkTargetCatalogError,
    BenchmarkTargetProfileCatalog,
    BenchmarkTargetProfileRegistration,
    select_traditional_web_api_target_profile,
)
from pajin.benchmark.target_factory import RegisteredBenchmarkTargetFactoryAdapter
from pajin.domain.models import StrictModel

HOLDOUT_TARGET_FACTORY_PROFILE_API_VERSION: Literal[
    "pajin.dev/holdout-target-factory-profile/v1alpha1"
] = "pajin.dev/holdout-target-factory-profile/v1alpha1"
HOLDOUT_TARGET_PRIVATE_SUITE_API_VERSION: Literal[
    "pajin.dev/holdout-target-private-suite/v1alpha1"
] = "pajin.dev/holdout-target-private-suite/v1alpha1"
HOLDOUT_TARGET_PRIVATE_BINDING_API_VERSION: Literal[
    "pajin.dev/holdout-target-private-binding/v1alpha1"
] = "pajin.dev/holdout-target-private-binding/v1alpha1"
HOLDOUT_TARGET_REGISTRATION_API_VERSION: Literal[
    "pajin.dev/holdout-target-registration/v1alpha1"
] = "pajin.dev/holdout-target-registration/v1alpha1"
HOLDOUT_TARGET_SELECTION_API_VERSION: Literal[
    "pajin.dev/holdout-target-selection/v1alpha1"
] = "pajin.dev/holdout-target-selection/v1alpha1"

_Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_PROFILE_BYTES = 128 * 1024
_MAX_SUITE_BYTES = 4 * 1024 * 1024
_MAX_REGISTRATION_BYTES = 256 * 1024
_MAX_BINDING_BYTES = 5 * 1024 * 1024
_MAX_SELECTION_BYTES = 512 * 1024

_HOLDOUT_GROUND_TRUTH_ID = "ground-truth:holdout-boolean-sqli-account-export"
_HOLDOUT_FINDING_ID = "finding:holdout-boolean-sqli-account-export"
_HOLDOUT_SURFACE_ID = "surface:http-api-account-export"
_HOLDOUT_CHAIN_ID = "chain:holdout-single-surface-boolean-sqli"
_HOLDOUT_MATCHER_ID = "matcher:holdout-boolean-sqli-account-export"
_HOLDOUT_MATCHER_VERSION = "1.0.0"
_HOLDOUT_EVALUATION_SEEDS = (780_984_302_134_771,)

_TRADITIONAL_WEB_API_HOLDOUT_MATCHER_DIGEST = benchmark_digest(
    "pajin.benchmark.traditional-web-api-holdout-matcher/v1",
    {
        "matcherId": _HOLDOUT_MATCHER_ID,
        "matcherVersion": _HOLDOUT_MATCHER_VERSION,
        "expectedFindingId": _HOLDOUT_FINDING_ID,
        "surfaceIds": [_HOLDOUT_SURFACE_ID],
        "chainId": _HOLDOUT_CHAIN_ID,
        "oracle": "private-provider-evidence-and-observation-match",
    },
    max_bytes=64 * 1024,
)


class HoldoutTargetFactoryProfile(StrictModel):
    """Public-safe identity of a separate, not-yet-runnable Holdout Factory."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/holdout-target-factory-profile/v1alpha1"
    ] = Field(default=HOLDOUT_TARGET_FACTORY_PROFILE_API_VERSION, alias="apiVersion")
    kind: Literal["HoldoutTargetFactoryProfile"] = "HoldoutTargetFactoryProfile"
    profile_id: Literal["traditional-web-api.holdout.account-export"] = Field(
        default="traditional-web-api.holdout.account-export",
        alias="profileId",
    )
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    target_family: Literal["traditional-web-api"] = Field(
        default="traditional-web-api",
        alias="targetFamily",
    )
    target_factory_id: Literal[
        "target-factory:holdout-traditional-web-api-contract"
    ] = Field(
        default="target-factory:holdout-traditional-web-api-contract",
        alias="targetFactoryId",
    )
    target_factory_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="targetFactoryVersion",
    )
    target_factory_digest: str = Field(default="", alias="targetFactoryDigest", max_length=64)
    active_registration_digest: _Sha256 = Field(alias="activeRegistrationDigest")
    execution_availability: Literal["holdout-provider-not-implemented"] = Field(
        default="holdout-provider-not-implemented",
        alias="executionAvailability",
    )
    network_policy: Literal["not-provisioned-contract-only"] = Field(
        default="not-provisioned-contract-only",
        alias="networkPolicy",
    )

    @model_validator(mode="after")
    def bind_profile(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"target_factory_digest"},
        )
        canonical_benchmark_json(
            material,
            label="HoldoutTargetFactoryProfile",
            max_bytes=_MAX_PROFILE_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.holdout-target-factory-profile/v1",
            material,
            max_bytes=_MAX_PROFILE_BYTES,
        )
        if self.target_factory_digest and self.target_factory_digest != digest:
            raise ValueError("Holdout Target Factory Digest differs")
        object.__setattr__(self, "target_factory_digest", digest)
        return self


class HoldoutTargetPrivateSuite(StrictModel):
    """Private Holdout cases and evaluation seeds, never embedded in public authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/holdout-target-private-suite/v1alpha1"
    ] = Field(default=HOLDOUT_TARGET_PRIVATE_SUITE_API_VERSION, alias="apiVersion")
    kind: Literal["HoldoutTargetPrivateSuite"] = "HoldoutTargetPrivateSuite"
    suite_id: str = Field(default="", alias="suiteId", max_length=110)
    suite_digest: str = Field(default="", alias="suiteDigest", max_length=64)
    benchmark_id: _Identifier = Field(alias="benchmarkId")
    active_registration_digest: _Sha256 = Field(alias="activeRegistrationDigest")
    holdout_factory_digest: _Sha256 = Field(alias="holdoutFactoryDigest")
    evaluation_seeds: tuple[int, ...] = Field(
        alias="evaluationSeeds",
        min_length=1,
        max_length=100,
    )
    ground_truth: BenchmarkGroundTruth = Field(alias="groundTruth")

    @field_validator("evaluation_seeds")
    @classmethod
    def require_private_canonical_seeds(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if any(seed < 0 or seed > 2**63 - 1 for seed in value):
            raise ValueError("Holdout evaluation seeds must be signed 64-bit integers")
        if value != tuple(sorted(set(value))):
            raise ValueError("Holdout evaluation seeds must be unique and sorted")
        return value

    @model_validator(mode="after")
    def bind_private_suite(self) -> Self:
        if self.ground_truth.benchmark_id != self.benchmark_id:
            raise ValueError("Holdout Ground Truth benchmark differs from private suite")
        if self.ground_truth.target_factory_digest != self.holdout_factory_digest:
            raise ValueError("Holdout Ground Truth differs from Holdout Factory")
        if any(
            case.visibility is not GroundTruthVisibility.HOLDOUT
            for case in self.ground_truth.cases
        ):
            raise ValueError("Holdout private suite can contain only holdout cases")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"suite_id", "suite_digest"},
        )
        canonical_benchmark_json(
            material,
            label="HoldoutTargetPrivateSuite",
            max_bytes=_MAX_SUITE_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.holdout-target-private-suite/v1",
            material,
            max_bytes=_MAX_SUITE_BYTES,
        )
        suite_id = f"benchmark-holdout-suite:{digest}"
        if self.suite_digest and self.suite_digest != digest:
            raise ValueError("Holdout Target Private Suite Digest differs")
        if self.suite_id and self.suite_id != suite_id:
            raise ValueError("Holdout Target Private Suite ID differs")
        object.__setattr__(self, "suite_digest", digest)
        object.__setattr__(self, "suite_id", suite_id)
        return self


class HoldoutTargetRegistration(StrictModel):
    """Public commitment to private Holdout material without disclosing that material."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/holdout-target-registration/v1alpha1"
    ] = Field(default=HOLDOUT_TARGET_REGISTRATION_API_VERSION, alias="apiVersion")
    kind: Literal["HoldoutTargetRegistration"] = "HoldoutTargetRegistration"
    registration_id: str = Field(default="", alias="registrationId", max_length=110)
    registration_digest: str = Field(default="", alias="registrationDigest", max_length=64)
    active_registration_digest: _Sha256 = Field(alias="activeRegistrationDigest")
    holdout_profile_id: _Identifier = Field(alias="holdoutProfileId")
    holdout_profile_version: _Identifier = Field(alias="holdoutProfileVersion")
    holdout_factory_id: _Identifier = Field(alias="holdoutFactoryId")
    holdout_factory_version: _Identifier = Field(alias="holdoutFactoryVersion")
    holdout_factory_digest: _Sha256 = Field(alias="holdoutFactoryDigest")
    private_suite_digest: _Sha256 = Field(alias="privateSuiteDigest")
    ground_truth_digest: _Sha256 = Field(alias="groundTruthDigest")
    execution_availability: Literal["holdout-provider-not-implemented"] = Field(
        default="holdout-provider-not-implemented",
        alias="executionAvailability",
    )

    @model_validator(mode="after")
    def bind_registration(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registration_id", "registration_digest"},
        )
        canonical_benchmark_json(
            material,
            label="HoldoutTargetRegistration",
            max_bytes=_MAX_REGISTRATION_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.holdout-target-registration/v1",
            material,
            max_bytes=_MAX_REGISTRATION_BYTES,
        )
        registration_id = f"benchmark-holdout-target:{digest}"
        if self.registration_digest and self.registration_digest != digest:
            raise ValueError("Holdout Target Registration Digest differs")
        if self.registration_id and self.registration_id != registration_id:
            raise ValueError("Holdout Target Registration ID differs")
        object.__setattr__(self, "registration_digest", digest)
        object.__setattr__(self, "registration_id", registration_id)
        return self


class HoldoutTargetSelectionAuthority(StrictModel):
    """Public-safe binding of active selection to a private, non-runnable Holdout suite."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/holdout-target-selection/v1alpha1"] = Field(
        default=HOLDOUT_TARGET_SELECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HoldoutTargetSelectionAuthority"] = (
        "HoldoutTargetSelectionAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    active_catalog_digest: _Sha256 = Field(alias="activeCatalogDigest")
    active_selection_digest: _Sha256 = Field(alias="activeSelectionDigest")
    active_registration_digest: _Sha256 = Field(alias="activeRegistrationDigest")
    holdout_profile_digest: _Sha256 = Field(alias="holdoutProfileDigest")
    holdout_registration: HoldoutTargetRegistration = Field(alias="holdoutRegistration")
    private_binding_digest: _Sha256 = Field(alias="privateBindingDigest")
    selection_state: Literal["holdout-bound-not-runnable"] = Field(
        default="holdout-bound-not-runnable",
        alias="selectionState",
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="providerExecutionAuthorized",
    )
    measurement_admission_eligible: Literal[False] = Field(
        default=False,
        alias="measurementAdmissionEligible",
    )
    holdout_content_disclosure_authorized: Literal[False] = Field(
        default=False,
        alias="holdoutContentDisclosureAuthorized",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        if (
            self.active_registration_digest
            != self.holdout_registration.active_registration_digest
            or self.holdout_profile_digest
            != self.holdout_registration.holdout_factory_digest
        ):
            raise ValueError("Holdout selection differs from registration")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        canonical_benchmark_json(
            material,
            label="HoldoutTargetSelectionAuthority",
            max_bytes=_MAX_SELECTION_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.holdout-target-selection/v1",
            material,
            max_bytes=_MAX_SELECTION_BYTES,
        )
        authority_id = f"benchmark-holdout-selection:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Holdout Target Selection Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Holdout Target Selection Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


class HoldoutTargetPrivateBinding(StrictModel):
    """Private exact binding used only inside the holdout evaluator boundary."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/holdout-target-private-binding/v1alpha1"
    ] = Field(default=HOLDOUT_TARGET_PRIVATE_BINDING_API_VERSION, alias="apiVersion")
    kind: Literal["HoldoutTargetPrivateBinding"] = "HoldoutTargetPrivateBinding"
    registration: HoldoutTargetRegistration
    private_suite: HoldoutTargetPrivateSuite = Field(alias="privateSuite")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)

    @model_validator(mode="after")
    def bind_private_material(self) -> Self:
        if (
            self.private_suite.active_registration_digest
            != self.registration.active_registration_digest
            or self.private_suite.holdout_factory_digest
            != self.registration.holdout_factory_digest
            or self.private_suite.suite_digest != self.registration.private_suite_digest
            or self.private_suite.ground_truth.digest()
            != self.registration.ground_truth_digest
        ):
            raise ValueError("Holdout private material differs from registration")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.holdout-target-private-binding/v1",
            material,
            max_bytes=_MAX_BINDING_BYTES,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Holdout Target Private Binding Digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


def registered_traditional_web_api_holdout_profile(
    active_registration: BenchmarkTargetProfileRegistration,
) -> HoldoutTargetFactoryProfile:
    """Return the separate Holdout Factory identity for one exact active registration."""

    authoritative = _canonical_active_registration(active_registration)
    return HoldoutTargetFactoryProfile(
        activeRegistrationDigest=authoritative.registration_digest,
    )


def registered_traditional_web_api_holdout_private_suite(
    profile: HoldoutTargetFactoryProfile,
    active_registration: BenchmarkTargetProfileRegistration,
    *,
    benchmark_id: str,
) -> HoldoutTargetPrivateSuite:
    """Build the private case and seed suite outside public benchmark artifacts."""

    authoritative_profile = _canonical_profile(profile)
    authoritative_active = _canonical_active_registration(active_registration)
    if authoritative_profile.active_registration_digest != authoritative_active.registration_digest:
        raise BenchmarkTargetCatalogError("Holdout profile differs from active registration")
    ground_truth = BenchmarkGroundTruth(
        benchmarkId=benchmark_id,
        targetFactoryDigest=authoritative_profile.target_factory_digest,
        cases=[
            BenchmarkGroundTruthCase(
                groundTruthId=_HOLDOUT_GROUND_TRUTH_ID,
                expectedFindingId=_HOLDOUT_FINDING_ID,
                surfaceIds=[_HOLDOUT_SURFACE_ID],
                chainId=_HOLDOUT_CHAIN_ID,
                matcherId=_HOLDOUT_MATCHER_ID,
                matcherVersion=_HOLDOUT_MATCHER_VERSION,
                matcherDigest=_TRADITIONAL_WEB_API_HOLDOUT_MATCHER_DIGEST,
                visibility=GroundTruthVisibility.HOLDOUT,
            )
        ],
    )
    return HoldoutTargetPrivateSuite(
        benchmarkId=benchmark_id,
        activeRegistrationDigest=authoritative_active.registration_digest,
        holdoutFactoryDigest=authoritative_profile.target_factory_digest,
        evaluationSeeds=_HOLDOUT_EVALUATION_SEEDS,
        groundTruth=ground_truth,
    )


def registered_traditional_web_api_holdout_registration(
    profile: HoldoutTargetFactoryProfile,
    active_registration: BenchmarkTargetProfileRegistration,
    private_suite: HoldoutTargetPrivateSuite,
) -> HoldoutTargetRegistration:
    """Create a public commitment after exact code-registration validation."""

    authoritative_profile = _canonical_profile(profile)
    authoritative_active = _canonical_active_registration(active_registration)
    authoritative_suite = _canonical_private_suite(private_suite)
    expected = registered_traditional_web_api_holdout_private_suite(
        authoritative_profile,
        authoritative_active,
        benchmark_id=authoritative_suite.benchmark_id,
    )
    if authoritative_suite != expected:
        raise BenchmarkTargetCatalogError(
            "Holdout private suite differs from code registration"
        )
    return _registered_holdout_registration(
        authoritative_profile,
        authoritative_active,
        authoritative_suite,
    )


def select_traditional_web_api_holdout_factory(
    manifest: BenchmarkManifest,
    *,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    active_profile: DockerBugBountyTargetProfile,
    active_catalog: BenchmarkTargetProfileCatalog,
    active_ground_truth: BenchmarkGroundTruth,
    holdout_profile: HoldoutTargetFactoryProfile,
    holdout_registration: HoldoutTargetRegistration,
    private_suite: HoldoutTargetPrivateSuite,
) -> HoldoutTargetSelectionAuthority:
    """Bind exact active authority to disjoint private Holdout material without execution."""

    try:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        authoritative_active_ground_truth = BenchmarkGroundTruth.model_validate(
            active_ground_truth.model_dump(mode="json", by_alias=True)
        )
        active_selection = select_traditional_web_api_target_profile(
            authoritative_manifest,
            adapter=adapter,
            profile=active_profile,
            catalog=active_catalog,
            ground_truth=authoritative_active_ground_truth,
        )
        if any(
            case.visibility is not GroundTruthVisibility.SEEDED
            for case in authoritative_active_ground_truth.cases
        ):
            raise ValueError("Active Ground Truth can contain only seeded cases")
        authoritative_profile = _canonical_profile(holdout_profile)
        expected_profile = registered_traditional_web_api_holdout_profile(
            active_selection.registration
        )
        if authoritative_profile != expected_profile:
            raise ValueError("Holdout profile differs from active selection")
        authoritative_suite = _canonical_private_suite(private_suite)
        expected_suite = registered_traditional_web_api_holdout_private_suite(
            authoritative_profile,
            active_selection.registration,
            benchmark_id=authoritative_manifest.benchmark_id,
        )
        if authoritative_suite != expected_suite:
            raise ValueError("Holdout private suite differs from code registration")
        if set(authoritative_suite.evaluation_seeds).intersection(
            authoritative_manifest.protocol.seeds
        ):
            raise ValueError("Holdout evaluation seed replays an active seed")
        _require_disjoint_active_and_holdout_cases(
            authoritative_active_ground_truth,
            authoritative_suite.ground_truth,
        )
        authoritative_registration = HoldoutTargetRegistration.model_validate(
            holdout_registration.model_dump(mode="json", by_alias=True)
        )
        expected_registration = _registered_holdout_registration(
            authoritative_profile,
            active_selection.registration,
            authoritative_suite,
        )
        if authoritative_registration != expected_registration:
            raise ValueError("Holdout registration differs from private suite")
        private_binding = HoldoutTargetPrivateBinding(
            registration=authoritative_registration,
            privateSuite=authoritative_suite,
        )
        return HoldoutTargetSelectionAuthority(
            manifestDigest=authoritative_manifest.digest(),
            activeCatalogDigest=active_catalog.catalog_digest,
            activeSelectionDigest=active_selection.authority_digest,
            activeRegistrationDigest=active_selection.registration.registration_digest,
            holdoutProfileDigest=authoritative_profile.target_factory_digest,
            holdoutRegistration=authoritative_registration,
            privateBindingDigest=private_binding.binding_digest,
        )
    except (BenchmarkTargetCatalogError, ValueError, TypeError) as exc:
        raise BenchmarkTargetCatalogError("Holdout Target Factory selection failed") from exc


def _registered_holdout_registration(
    profile: HoldoutTargetFactoryProfile,
    active_registration: BenchmarkTargetProfileRegistration,
    private_suite: HoldoutTargetPrivateSuite,
) -> HoldoutTargetRegistration:
    if profile.active_registration_digest != active_registration.registration_digest:
        raise ValueError("Holdout profile differs from active registration")
    if private_suite.active_registration_digest != active_registration.registration_digest:
        raise ValueError("Holdout private suite differs from active registration")
    return HoldoutTargetRegistration(
        activeRegistrationDigest=active_registration.registration_digest,
        holdoutProfileId=profile.profile_id,
        holdoutProfileVersion=profile.profile_version,
        holdoutFactoryId=profile.target_factory_id,
        holdoutFactoryVersion=profile.target_factory_version,
        holdoutFactoryDigest=profile.target_factory_digest,
        privateSuiteDigest=private_suite.suite_digest,
        groundTruthDigest=private_suite.ground_truth.digest(),
    )


def _require_disjoint_active_and_holdout_cases(
    active: BenchmarkGroundTruth,
    holdout: BenchmarkGroundTruth,
) -> None:
    active_ids = {
        value
        for case in active.cases
        for value in (
            case.ground_truth_id,
            case.expected_finding_id,
            case.matcher_id,
            case.matcher_digest,
        )
    }
    holdout_ids = {
        value
        for case in holdout.cases
        for value in (
            case.ground_truth_id,
            case.expected_finding_id,
            case.matcher_id,
            case.matcher_digest,
        )
    }
    if active_ids.intersection(holdout_ids):
        raise ValueError("Active and Holdout case identities must be disjoint")


def _canonical_active_registration(
    registration: BenchmarkTargetProfileRegistration,
) -> BenchmarkTargetProfileRegistration:
    authoritative = BenchmarkTargetProfileRegistration.model_validate(
        registration.model_dump(mode="json", by_alias=True)
    )
    if (
        authoritative.target_family != "traditional-web-api"
        or authoritative.network_policy
        != "docker-internal-bridge-no-published-ports"
    ):
        raise BenchmarkTargetCatalogError(
            "Holdout authority requires one runnable Traditional Web/API registration"
        )
    return authoritative


def _canonical_profile(profile: HoldoutTargetFactoryProfile) -> HoldoutTargetFactoryProfile:
    return HoldoutTargetFactoryProfile.model_validate(
        profile.model_dump(mode="json", by_alias=True)
    )


def _canonical_private_suite(
    private_suite: HoldoutTargetPrivateSuite,
) -> HoldoutTargetPrivateSuite:
    return HoldoutTargetPrivateSuite.model_validate(
        private_suite.model_dump(mode="json", by_alias=True)
    )
