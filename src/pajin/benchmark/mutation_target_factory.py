"""P0-D5 non-runnable Mutation Target Factory authority."""

from __future__ import annotations

from itertools import pairwise
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.docker_provider import DockerBugBountyTargetProfile
from pajin.benchmark.models import (
    BenchmarkGroundTruth,
    BenchmarkManifest,
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

MUTATION_TARGET_OPERATION_API_VERSION: Literal[
    "pajin.dev/mutation-target-operation/v1alpha1"
] = "pajin.dev/mutation-target-operation/v1alpha1"
MUTATION_TARGET_PROFILE_API_VERSION: Literal[
    "pajin.dev/mutation-target-profile/v1alpha1"
] = "pajin.dev/mutation-target-profile/v1alpha1"
MUTATION_TARGET_REGISTRATION_API_VERSION: Literal[
    "pajin.dev/mutation-target-registration/v1alpha1"
] = "pajin.dev/mutation-target-registration/v1alpha1"
MUTATION_RESET_PLAN_API_VERSION: Literal[
    "pajin.dev/mutation-reset-plan/v1alpha1"
] = "pajin.dev/mutation-reset-plan/v1alpha1"
MUTATION_TARGET_SELECTION_API_VERSION: Literal[
    "pajin.dev/mutation-target-selection/v1alpha1"
] = "pajin.dev/mutation-target-selection/v1alpha1"

_Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_OPERATION_BYTES = 64 * 1024
_MAX_PROFILE_BYTES = 256 * 1024
_MAX_REGISTRATION_BYTES = 256 * 1024
_MAX_RESET_PLAN_BYTES = 512 * 1024
_MAX_SELECTION_BYTES = 512 * 1024

_MUTATION_PROFILE_ID = "mutation:traditional-web-api.seeded-account-layout-v1"
_MUTATION_SEED = 4_240_017
_BASE_STATE_DIGEST = benchmark_digest(
    "pajin.benchmark.mutation-base-state/v1",
    {
        "dataset": "synthetic-user-lookup-v1",
        "layout": "default",
        "vulnerability": "boolean-sqli-present",
    },
    max_bytes=64 * 1024,
)
_MUTATED_STATE_DIGEST = benchmark_digest(
    "pajin.benchmark.mutation-expected-state/v1",
    {
        "dataset": "synthetic-user-lookup-v1",
        "layout": "seeded-account-layout-v1",
        "mutationSeed": _MUTATION_SEED,
        "vulnerability": "boolean-sqli-present",
    },
    max_bytes=64 * 1024,
)


class MutationTargetOperation(StrictModel):
    """One code-owned, ordered operation in a non-runnable mutation plan."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mutation-target-operation/v1alpha1"] = Field(
        default=MUTATION_TARGET_OPERATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MutationTargetOperation"] = "MutationTargetOperation"
    operation_id: _Identifier = Field(alias="operationId")
    ordinal: int = Field(ge=1, le=32)
    action: Literal[
        "restore-base-snapshot",
        "apply-seeded-account-layout",
        "verify-expected-state",
    ]
    input_state_digest: _Sha256 = Field(alias="inputStateDigest")
    output_state_digest: _Sha256 = Field(alias="outputStateDigest")
    operation_digest: str = Field(default="", alias="operationDigest", max_length=64)

    @model_validator(mode="after")
    def bind_operation(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"operation_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.mutation-target-operation/v1",
            material,
            max_bytes=_MAX_OPERATION_BYTES,
        )
        if self.operation_digest and self.operation_digest != digest:
            raise ValueError("Mutation Target Operation Digest differs")
        object.__setattr__(self, "operation_digest", digest)
        return self


class MutationTargetProfile(StrictModel):
    """Code-registered mutation identity bound to one exact base Target registration."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mutation-target-profile/v1alpha1"] = Field(
        default=MUTATION_TARGET_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MutationTargetProfile"] = "MutationTargetProfile"
    mutation_profile_id: Literal[
        "mutation:traditional-web-api.seeded-account-layout-v1"
    ] = Field(
        default="mutation:traditional-web-api.seeded-account-layout-v1",
        alias="mutationProfileId",
    )
    mutation_profile_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="mutationProfileVersion",
    )
    mutation_factory_id: Literal[
        "mutation-factory:traditional-web-api-contract"
    ] = Field(
        default="mutation-factory:traditional-web-api-contract",
        alias="mutationFactoryId",
    )
    mutation_factory_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="mutationFactoryVersion",
    )
    mutation_profile_digest: str = Field(
        default="",
        alias="mutationProfileDigest",
        max_length=64,
    )
    base_registration_digest: _Sha256 = Field(alias="baseRegistrationDigest")
    mutation_seed: int = Field(alias="mutationSeed", ge=0, le=2**63 - 1)
    base_state_digest: _Sha256 = Field(alias="baseStateDigest")
    expected_state_digest: _Sha256 = Field(alias="expectedStateDigest")
    reset_policy: Literal["fresh-base-before-every-mutation"] = Field(
        default="fresh-base-before-every-mutation",
        alias="resetPolicy",
    )
    materialization_state: Literal["registered-contract-not-materialized"] = Field(
        default="registered-contract-not-materialized",
        alias="materializationState",
    )
    operations: tuple[MutationTargetOperation, ...] = Field(
        min_length=3,
        max_length=3,
    )

    @field_validator("operations")
    @classmethod
    def require_ordered_state_chain(
        cls,
        value: tuple[MutationTargetOperation, ...],
    ) -> tuple[MutationTargetOperation, ...]:
        if [item.ordinal for item in value] != [1, 2, 3]:
            raise ValueError("Mutation operations must use exact canonical ordinals")
        if [item.action for item in value] != [
            "restore-base-snapshot",
            "apply-seeded-account-layout",
            "verify-expected-state",
        ]:
            raise ValueError("Mutation operations differ from the registered order")
        if any(
            current.output_state_digest != following.input_state_digest
            for current, following in pairwise(value)
        ):
            raise ValueError("Mutation operations do not form one state chain")
        return value

    @model_validator(mode="after")
    def bind_profile(self) -> Self:
        if (
            self.mutation_seed != _MUTATION_SEED
            or self.base_state_digest != _BASE_STATE_DIGEST
            or self.expected_state_digest != _MUTATED_STATE_DIGEST
            or self.operations[0].input_state_digest != self.base_state_digest
            or self.operations[-1].output_state_digest != self.expected_state_digest
        ):
            raise ValueError("Mutation profile state or seed differs from code registration")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"mutation_profile_digest"},
        )
        canonical_benchmark_json(
            material,
            label="MutationTargetProfile",
            max_bytes=_MAX_PROFILE_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.mutation-target-profile/v1",
            material,
            max_bytes=_MAX_PROFILE_BYTES,
        )
        if self.mutation_profile_digest and self.mutation_profile_digest != digest:
            raise ValueError("Mutation Target Profile Digest differs")
        object.__setattr__(self, "mutation_profile_digest", digest)
        return self


class MutationTargetRegistration(StrictModel):
    """Public registration of one mutation above an unchanged base Target catalog."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mutation-target-registration/v1alpha1"] = Field(
        default=MUTATION_TARGET_REGISTRATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MutationTargetRegistration"] = "MutationTargetRegistration"
    registration_id: str = Field(default="", alias="registrationId", max_length=110)
    registration_digest: str = Field(default="", alias="registrationDigest", max_length=64)
    base_registration_digest: _Sha256 = Field(alias="baseRegistrationDigest")
    mutation_profile_id: _Identifier = Field(alias="mutationProfileId")
    mutation_profile_version: _Identifier = Field(alias="mutationProfileVersion")
    mutation_profile_digest: _Sha256 = Field(alias="mutationProfileDigest")
    mutation_factory_id: _Identifier = Field(alias="mutationFactoryId")
    mutation_factory_version: _Identifier = Field(alias="mutationFactoryVersion")
    selection_availability: Literal["registered-not-runnable"] = Field(
        default="registered-not-runnable",
        alias="selectionAvailability",
    )

    @model_validator(mode="after")
    def bind_registration(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registration_id", "registration_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.mutation-target-registration/v1",
            material,
            max_bytes=_MAX_REGISTRATION_BYTES,
        )
        registration_id = f"benchmark-mutation-target:{digest}"
        if self.registration_digest and self.registration_digest != digest:
            raise ValueError("Mutation Target Registration Digest differs")
        if self.registration_id and self.registration_id != registration_id:
            raise ValueError("Mutation Target Registration ID differs")
        object.__setattr__(self, "registration_digest", digest)
        object.__setattr__(self, "registration_id", registration_id)
        return self


class MutationResetPlanAuthority(StrictModel):
    """Declared reset and mutation provenance; not a provider receipt."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mutation-reset-plan/v1alpha1"] = Field(
        default=MUTATION_RESET_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MutationResetPlanAuthority"] = "MutationResetPlanAuthority"
    plan_id: str = Field(default="", alias="planId", max_length=110)
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    base_manifest_digest: _Sha256 = Field(alias="baseManifestDigest")
    mutation_manifest_digest: _Sha256 = Field(alias="mutationManifestDigest")
    base_registration_digest: _Sha256 = Field(alias="baseRegistrationDigest")
    mutation_profile_digest: _Sha256 = Field(alias="mutationProfileDigest")
    benchmark_seeds: tuple[int, ...] = Field(alias="benchmarkSeeds", min_length=1, max_length=100)
    mutation_seed: int = Field(alias="mutationSeed", ge=0, le=2**63 - 1)
    base_state_digest: _Sha256 = Field(alias="baseStateDigest")
    expected_state_digest: _Sha256 = Field(alias="expectedStateDigest")
    operation_digests: tuple[_Sha256, ...] = Field(
        alias="operationDigests",
        min_length=3,
        max_length=3,
    )
    plan_state: Literal["declared-not-applied"] = Field(
        default="declared-not-applied",
        alias="planState",
    )
    reset_receipt_bound: Literal[False] = Field(
        default=False,
        alias="resetReceiptBound",
    )

    @field_validator("benchmark_seeds")
    @classmethod
    def require_canonical_benchmark_seeds(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("Mutation reset plan benchmark seeds must be unique and sorted")
        return value

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_id", "plan_digest"},
        )
        canonical_benchmark_json(
            material,
            label="MutationResetPlanAuthority",
            max_bytes=_MAX_RESET_PLAN_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.mutation-reset-plan/v1",
            material,
            max_bytes=_MAX_RESET_PLAN_BYTES,
        )
        plan_id = f"benchmark-mutation-reset-plan:{digest}"
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("Mutation Reset Plan Digest differs")
        if self.plan_id and self.plan_id != plan_id:
            raise ValueError("Mutation Reset Plan ID differs")
        object.__setattr__(self, "plan_digest", digest)
        object.__setattr__(self, "plan_id", plan_id)
        return self


class MutationTargetSelectionAuthority(StrictModel):
    """Non-runnable binding of base selection, mutation registration, Manifest, and reset plan."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mutation-target-selection/v1alpha1"] = Field(
        default=MUTATION_TARGET_SELECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MutationTargetSelectionAuthority"] = (
        "MutationTargetSelectionAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    base_catalog_digest: _Sha256 = Field(alias="baseCatalogDigest")
    base_selection_digest: _Sha256 = Field(alias="baseSelectionDigest")
    base_manifest_digest: _Sha256 = Field(alias="baseManifestDigest")
    mutation_manifest_digest: _Sha256 = Field(alias="mutationManifestDigest")
    registration: MutationTargetRegistration
    reset_plan: MutationResetPlanAuthority = Field(alias="resetPlan")
    selection_state: Literal["mutation-bound-not-runnable"] = Field(
        default="mutation-bound-not-runnable",
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
    mutation_materialization_authorized: Literal[False] = Field(
        default=False,
        alias="mutationMaterializationAuthorized",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        if (
            self.base_manifest_digest != self.reset_plan.base_manifest_digest
            or self.mutation_manifest_digest != self.reset_plan.mutation_manifest_digest
            or self.registration.base_registration_digest
            != self.reset_plan.base_registration_digest
            or self.registration.mutation_profile_digest
            != self.reset_plan.mutation_profile_digest
        ):
            raise ValueError("Mutation Target selection differs from reset plan")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.mutation-target-selection/v1",
            material,
            max_bytes=_MAX_SELECTION_BYTES,
        )
        authority_id = f"benchmark-mutation-selection:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Mutation Target Selection Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Mutation Target Selection Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_traditional_web_api_mutation_profile(
    base_registration: BenchmarkTargetProfileRegistration,
) -> MutationTargetProfile:
    """Return the only P0-D5 mutation profile for one exact base registration."""

    authoritative_base = _canonical_base_registration(base_registration)
    restore = MutationTargetOperation(
        operationId="mutation-operation:restore-base-snapshot",
        ordinal=1,
        action="restore-base-snapshot",
        inputStateDigest=_BASE_STATE_DIGEST,
        outputStateDigest=_BASE_STATE_DIGEST,
    )
    apply = MutationTargetOperation(
        operationId="mutation-operation:apply-seeded-account-layout",
        ordinal=2,
        action="apply-seeded-account-layout",
        inputStateDigest=_BASE_STATE_DIGEST,
        outputStateDigest=_MUTATED_STATE_DIGEST,
    )
    verify = MutationTargetOperation(
        operationId="mutation-operation:verify-expected-state",
        ordinal=3,
        action="verify-expected-state",
        inputStateDigest=_MUTATED_STATE_DIGEST,
        outputStateDigest=_MUTATED_STATE_DIGEST,
    )
    return MutationTargetProfile(
        baseRegistrationDigest=authoritative_base.registration_digest,
        mutationSeed=_MUTATION_SEED,
        baseStateDigest=_BASE_STATE_DIGEST,
        expectedStateDigest=_MUTATED_STATE_DIGEST,
        operations=(restore, apply, verify),
    )


def registered_traditional_web_api_mutation_registration(
    profile: MutationTargetProfile,
    base_registration: BenchmarkTargetProfileRegistration,
) -> MutationTargetRegistration:
    """Register exact code-owned mutation semantics without widening the base catalog."""

    authoritative_base = _canonical_base_registration(base_registration)
    authoritative_profile = _canonical_profile(profile)
    expected_profile = registered_traditional_web_api_mutation_profile(authoritative_base)
    if authoritative_profile != expected_profile:
        raise BenchmarkTargetCatalogError("Mutation profile differs from code registration")
    return _registration(authoritative_profile, authoritative_base)


def registered_traditional_web_api_mutation_manifest(
    base_manifest: BenchmarkManifest,
    profile: MutationTargetProfile,
    base_registration: BenchmarkTargetProfileRegistration,
    base_ground_truth: BenchmarkGroundTruth,
) -> BenchmarkManifest:
    """Derive the exact non-runnable Manifest carrying the registered mutation ID."""

    authoritative_base = _canonical_manifest(base_manifest)
    authoritative_profile = _canonical_profile(profile)
    authoritative_registration = _canonical_base_registration(base_registration)
    authoritative_ground_truth = BenchmarkGroundTruth.model_validate(
        base_ground_truth.model_dump(mode="json", by_alias=True)
    )
    if authoritative_profile != registered_traditional_web_api_mutation_profile(
        authoritative_registration
    ):
        raise BenchmarkTargetCatalogError("Mutation profile differs from base registration")
    if authoritative_base.mutation_profile_id is not None:
        raise BenchmarkTargetCatalogError("Base Manifest already contains a mutation profile")
    if (
        authoritative_base.target_profile_id
        != authoritative_registration.target_profile_id
        or authoritative_base.benchmark_id != authoritative_ground_truth.benchmark_id
        or authoritative_base.target_profile_version
        != authoritative_registration.target_profile_version
        or authoritative_base.target_factory_id
        != authoritative_registration.target_factory_id
        or authoritative_base.target_factory_version
        != authoritative_registration.target_factory_version
        or authoritative_base.target_factory_digest
        != authoritative_registration.target_factory_digest
        or authoritative_base.ground_truth_digest
        != authoritative_registration.ground_truth_digest
        or authoritative_ground_truth.digest()
        != authoritative_registration.ground_truth_digest
        or authoritative_ground_truth.target_factory_digest
        != authoritative_registration.target_factory_digest
    ):
        raise BenchmarkTargetCatalogError("Base Manifest differs from base registration")
    raw = authoritative_base.model_dump(mode="json", by_alias=True)
    raw["mutationProfileId"] = authoritative_profile.mutation_profile_id
    return BenchmarkManifest.model_validate(raw)


def select_traditional_web_api_mutation_target(
    base_manifest: BenchmarkManifest,
    mutation_manifest: BenchmarkManifest,
    *,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    base_profile: DockerBugBountyTargetProfile,
    base_catalog: BenchmarkTargetProfileCatalog,
    base_ground_truth: BenchmarkGroundTruth,
    mutation_profile: MutationTargetProfile,
    mutation_registration: MutationTargetRegistration,
) -> MutationTargetSelectionAuthority:
    """Rebuild every base and mutation identity while granting no materialization authority."""

    try:
        authoritative_base_manifest = _canonical_manifest(base_manifest)
        base_selection = select_traditional_web_api_target_profile(
            authoritative_base_manifest,
            adapter=adapter,
            profile=base_profile,
            catalog=base_catalog,
            ground_truth=base_ground_truth,
        )
        authoritative_profile = _canonical_profile(mutation_profile)
        expected_profile = registered_traditional_web_api_mutation_profile(
            base_selection.registration
        )
        if authoritative_profile != expected_profile:
            raise ValueError("Mutation profile differs from base selection")
        authoritative_registration = MutationTargetRegistration.model_validate(
            mutation_registration.model_dump(mode="json", by_alias=True)
        )
        expected_registration = _registration(
            authoritative_profile,
            base_selection.registration,
        )
        if authoritative_registration != expected_registration:
            raise ValueError("Mutation registration differs from base selection")
        authoritative_mutation_manifest = _canonical_manifest(mutation_manifest)
        expected_manifest = registered_traditional_web_api_mutation_manifest(
            authoritative_base_manifest,
            authoritative_profile,
            base_selection.registration,
            base_ground_truth,
        )
        if authoritative_mutation_manifest != expected_manifest:
            raise ValueError("Mutation Manifest differs from registered derivation")
        reset_plan = MutationResetPlanAuthority(
            baseManifestDigest=authoritative_base_manifest.digest(),
            mutationManifestDigest=authoritative_mutation_manifest.digest(),
            baseRegistrationDigest=base_selection.registration.registration_digest,
            mutationProfileDigest=authoritative_profile.mutation_profile_digest,
            benchmarkSeeds=tuple(authoritative_base_manifest.protocol.seeds),
            mutationSeed=authoritative_profile.mutation_seed,
            baseStateDigest=authoritative_profile.base_state_digest,
            expectedStateDigest=authoritative_profile.expected_state_digest,
            operationDigests=tuple(
                item.operation_digest for item in authoritative_profile.operations
            ),
        )
        return MutationTargetSelectionAuthority(
            baseCatalogDigest=base_catalog.catalog_digest,
            baseSelectionDigest=base_selection.authority_digest,
            baseManifestDigest=authoritative_base_manifest.digest(),
            mutationManifestDigest=authoritative_mutation_manifest.digest(),
            registration=authoritative_registration,
            resetPlan=reset_plan,
        )
    except (BenchmarkTargetCatalogError, ValueError, TypeError) as exc:
        raise BenchmarkTargetCatalogError("Mutation Target Factory selection failed") from exc


def _registration(
    profile: MutationTargetProfile,
    base_registration: BenchmarkTargetProfileRegistration,
) -> MutationTargetRegistration:
    if profile.base_registration_digest != base_registration.registration_digest:
        raise ValueError("Mutation profile differs from base registration")
    return MutationTargetRegistration(
        baseRegistrationDigest=base_registration.registration_digest,
        mutationProfileId=profile.mutation_profile_id,
        mutationProfileVersion=profile.mutation_profile_version,
        mutationProfileDigest=profile.mutation_profile_digest,
        mutationFactoryId=profile.mutation_factory_id,
        mutationFactoryVersion=profile.mutation_factory_version,
    )


def _canonical_base_registration(
    registration: BenchmarkTargetProfileRegistration,
) -> BenchmarkTargetProfileRegistration:
    authoritative = BenchmarkTargetProfileRegistration.model_validate(
        registration.model_dump(mode="json", by_alias=True)
    )
    if (
        authoritative.target_family != "traditional-web-api"
        or authoritative.network_policy
        != "docker-internal-bridge-no-published-ports"
        or authoritative.mutation_profile_ids
    ):
        raise BenchmarkTargetCatalogError(
            "Mutation authority requires the exact unexpanded Traditional Web/API base registration"
        )
    return authoritative


def _canonical_profile(profile: MutationTargetProfile) -> MutationTargetProfile:
    return MutationTargetProfile.model_validate(
        profile.model_dump(mode="json", by_alias=True)
    )


def _canonical_manifest(manifest: BenchmarkManifest) -> BenchmarkManifest:
    return BenchmarkManifest.model_validate(
        manifest.model_dump(mode="json", by_alias=True)
    )
