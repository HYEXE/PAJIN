"""P0-D1 code-registered Traditional Web/API Target catalog boundary."""

from __future__ import annotations

from typing import Annotated, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.docker_provider import (
    DOCKER_BENCHMARK_PROVIDER_EVIDENCE_API_VERSION,
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetProfile,
    DockerTargetProfile,
)
from pajin.benchmark.measurement import WalkingBenchmarkRunObservation
from pajin.benchmark.models import (
    BenchmarkGroundTruth,
    BenchmarkGroundTruthCase,
    BenchmarkManifest,
    GroundTruthVisibility,
    benchmark_digest,
    canonical_benchmark_json,
)
from pajin.benchmark.target_factory import (
    BenchmarkMeasurementAttestation,
    BenchmarkMeasurementAttestationStatement,
    BenchmarkTargetCoordinate,
    BenchmarkTargetStage,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetOperation,
    BenchmarkTargetRecoveryRequest,
)
from pajin.domain.models import StrictModel

BENCHMARK_TARGET_PROFILE_REGISTRATION_API_VERSION: Literal[
    "pajin.dev/benchmark-target-profile-registration/v1alpha1"
] = "pajin.dev/benchmark-target-profile-registration/v1alpha1"
BENCHMARK_TARGET_PROFILE_CATALOG_API_VERSION: Literal[
    "pajin.dev/benchmark-target-profile-catalog/v1alpha1"
] = "pajin.dev/benchmark-target-profile-catalog/v1alpha1"
BENCHMARK_TARGET_GROUND_TRUTH_BINDING_API_VERSION: Literal[
    "pajin.dev/benchmark-target-ground-truth-binding/v1alpha1"
] = "pajin.dev/benchmark-target-ground-truth-binding/v1alpha1"
BENCHMARK_TARGET_PROFILE_SELECTION_API_VERSION: Literal[
    "pajin.dev/benchmark-target-profile-selection/v1alpha1"
] = "pajin.dev/benchmark-target-profile-selection/v1alpha1"

_Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ApiVersion = Annotated[
    str,
    Field(pattern=r"^pajin\.dev/[a-z0-9][a-z0-9./-]{1,198}$"),
]
_MAX_REGISTRATION_BYTES = 128 * 1024
_MAX_CATALOG_BYTES = 512 * 1024
_MAX_BINDING_BYTES = 512 * 1024
_MAX_SELECTION_BYTES = 512 * 1024

_TARGET_FACTORY_ID = "target-factory:docker-bug-bounty"
_MATCHER_ID = "matcher:docker-boolean-sqli-probe"
_MATCHER_VERSION = "1.0.0"
_GROUND_TRUTH_ID = "ground-truth:boolean-sqli-user-lookup"
_FINDING_ID = "finding:boolean-sqli-user-lookup"
_SURFACE_ID = "surface:http-api-user-lookup"
_CHAIN_ID = "chain:single-surface-boolean-sqli"

TRADITIONAL_WEB_API_BOOLEAN_SQLI_MATCHER_DIGEST = benchmark_digest(
    "pajin.benchmark.traditional-web-api-matcher/v1",
    {
        "matcherId": _MATCHER_ID,
        "matcherVersion": _MATCHER_VERSION,
        "providerEvidenceApiVersion": DOCKER_BENCHMARK_PROVIDER_EVIDENCE_API_VERSION,
        "requiredStage": BenchmarkTargetStage.EXECUTION,
        "requiredWorkerExitCode": 0,
        "requiredProbeVulnerable": True,
        "expectedFindingId": _FINDING_ID,
        "surfaceIds": [_SURFACE_ID],
        "chainId": _CHAIN_ID,
        "requiredObservation": {
            "toolCallCount": 1,
            "modelCallCount": 0,
            "costUsd": 0.0,
            "knownAttackSurfaceCount": 1,
            "discoveredKnownAttackSurfaceCount": 1,
            "knownFindingCount": 1,
            "matchedKnownFindingCount": 1,
            "candidateFindingCount": 1,
            "validCandidateFindingCount": 1,
            "unexpectedValidFindingCount": 0,
            "confirmedFindingCount": 1,
            "groundTruthChainCount": 1,
            "completedGroundTruthChainCount": 1,
            "firstValidOrConfirmedFindingSeconds": 0.0,
            "replayAttemptCount": 1,
            "replaySuccessCount": 1,
            "policyRejectionOrViolationCount": 0,
            "humanDecisionCount": 1,
            "humanInterventionOrOverturnCount": 0,
            "openWorldCandidateIds": [],
        },
    },
    max_bytes=64 * 1024,
)


class BenchmarkTargetCatalogError(RuntimeError):
    """Raised when Target catalog selection or evidence matching fails closed."""


class BenchmarkTargetProfileRegistration(StrictModel):
    """Public content-addressed registration without private Ground Truth cases."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-target-profile-registration/v1alpha1"
    ] = Field(
        default=BENCHMARK_TARGET_PROFILE_REGISTRATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetProfileRegistration"] = (
        "BenchmarkTargetProfileRegistration"
    )
    registration_id: str = Field(default="", alias="registrationId", max_length=110)
    registration_digest: str = Field(
        default="",
        alias="registrationDigest",
        max_length=64,
    )
    target_family: Literal["traditional-web-api", "ai-rag-mcp", "hybrid"] = Field(
        alias="targetFamily"
    )
    target_profile_id: _Identifier = Field(alias="targetProfileId")
    target_profile_version: _Identifier = Field(alias="targetProfileVersion")
    target_factory_id: _Identifier = Field(alias="targetFactoryId")
    target_factory_version: _Identifier = Field(alias="targetFactoryVersion")
    target_factory_digest: _Sha256 = Field(alias="targetFactoryDigest")
    provider_profile_api_version: _ApiVersion = Field(alias="providerProfileApiVersion")
    provider_profile_digest: _Sha256 = Field(alias="providerProfileDigest")
    mutation_profile_ids: tuple[_Identifier, ...] = Field(
        default=(),
        alias="mutationProfileIds",
        max_length=32,
    )
    network_policy: Literal[
        "docker-internal-bridge-no-published-ports",
        "not-provisioned-contract-only",
    ] = Field(
        default="docker-internal-bridge-no-published-ports",
        alias="networkPolicy",
    )
    ground_truth_digest: _Sha256 = Field(alias="groundTruthDigest")

    @field_validator("mutation_profile_ids")
    @classmethod
    def require_canonical_mutation_profiles(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if tuple(sorted(set(value))) != value:
            raise ValueError("Target mutation profile IDs must be unique and sorted")
        return value

    @model_validator(mode="after")
    def bind_registration(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registration_id", "registration_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-profile-registration/v1",
            material,
            max_bytes=_MAX_REGISTRATION_BYTES,
        )
        registration_id = f"benchmark-target-profile:{digest}"
        if self.registration_digest and self.registration_digest != digest:
            raise ValueError("Benchmark Target Profile Registration Digest differs")
        if self.registration_id and self.registration_id != registration_id:
            raise ValueError("Benchmark Target Profile Registration ID differs")
        object.__setattr__(self, "registration_digest", digest)
        object.__setattr__(self, "registration_id", registration_id)
        return self


class BenchmarkTargetProfileCatalog(StrictModel):
    """Canonical public registry of approved Target profile registrations."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/benchmark-target-profile-catalog/v1alpha1"] = Field(
        default=BENCHMARK_TARGET_PROFILE_CATALOG_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetProfileCatalog"] = "BenchmarkTargetProfileCatalog"
    catalog_id: Literal[
        "target-catalog:pajin-traditional-web-api",
        "target-catalog:pajin-ai-rag-mcp",
        "target-catalog:pajin-ai-rag-mcp-local-docker",
        "target-catalog:pajin-hybrid-local-docker",
    ] = Field(
        default="target-catalog:pajin-traditional-web-api",
        alias="catalogId",
    )
    catalog_version: Literal["1.0.0"] = Field(default="1.0.0", alias="catalogVersion")
    catalog_revision: Literal[1] = Field(default=1, alias="catalogRevision")
    catalog_digest: str = Field(default="", alias="catalogDigest", max_length=64)
    registrations: tuple[BenchmarkTargetProfileRegistration, ...] = Field(
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def bind_catalog(self) -> Self:
        expected_family = {
            "target-catalog:pajin-traditional-web-api": "traditional-web-api",
            "target-catalog:pajin-ai-rag-mcp": "ai-rag-mcp",
            "target-catalog:pajin-ai-rag-mcp-local-docker": "ai-rag-mcp",
            "target-catalog:pajin-hybrid-local-docker": "hybrid",
        }[self.catalog_id]
        if any(item.target_family != expected_family for item in self.registrations):
            raise ValueError("Benchmark Target catalog ID and registration family differ")
        keys = [
            (item.target_profile_id, item.target_profile_version)
            for item in self.registrations
        ]
        if keys != sorted(set(keys)):
            raise ValueError("Benchmark Target catalog registrations must be uniquely sorted")
        digests = [item.registration_digest for item in self.registrations]
        if len(digests) != len(set(digests)):
            raise ValueError("Benchmark Target catalog registration Digests must be unique")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"catalog_digest"},
        )
        canonical_benchmark_json(
            material,
            label="BenchmarkTargetProfileCatalog",
            max_bytes=_MAX_CATALOG_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-profile-catalog/v1",
            material,
            max_bytes=_MAX_CATALOG_BYTES,
        )
        if self.catalog_digest and self.catalog_digest != digest:
            raise ValueError("Benchmark Target Profile Catalog Digest differs")
        object.__setattr__(self, "catalog_digest", digest)
        return self


class BenchmarkTargetGroundTruthBinding(StrictModel):
    """Private exact Ground Truth contents bound to one public registration."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-target-ground-truth-binding/v1alpha1"
    ] = Field(
        default=BENCHMARK_TARGET_GROUND_TRUTH_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetGroundTruthBinding"] = (
        "BenchmarkTargetGroundTruthBinding"
    )
    binding_id: str = Field(default="", alias="bindingId", max_length=110)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    registration: BenchmarkTargetProfileRegistration
    ground_truth: BenchmarkGroundTruth = Field(alias="groundTruth")

    @model_validator(mode="after")
    def bind_private_ground_truth(self) -> Self:
        if (
            self.ground_truth.target_factory_digest
            != self.registration.target_factory_digest
            or self.ground_truth.digest() != self.registration.ground_truth_digest
        ):
            raise ValueError("Private Ground Truth differs from Target registration")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-ground-truth-binding/v1",
            material,
            max_bytes=_MAX_BINDING_BYTES,
        )
        binding_id = f"benchmark-target-ground-truth:{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Benchmark Target Ground Truth Binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("Benchmark Target Ground Truth Binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


class BenchmarkTargetProfileSelectionAuthority(StrictModel):
    """Non-executable proof of one exact catalog, Manifest, adapter, and private binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-target-profile-selection/v1alpha1"
    ] = Field(
        default=BENCHMARK_TARGET_PROFILE_SELECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetProfileSelectionAuthority"] = (
        "BenchmarkTargetProfileSelectionAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    catalog_id: _Identifier = Field(alias="catalogId")
    catalog_revision: int = Field(alias="catalogRevision", ge=1)
    catalog_digest: _Sha256 = Field(alias="catalogDigest")
    registration: BenchmarkTargetProfileRegistration
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    provider_profile_digest: _Sha256 = Field(alias="providerProfileDigest")
    ground_truth_binding_digest: _Sha256 = Field(alias="groundTruthBindingDigest")
    ground_truth_digest: _Sha256 = Field(alias="groundTruthDigest")
    selection_state: Literal["registered-ground-truth-bound"] = Field(
        default="registered-ground-truth-bound",
        alias="selectionState",
    )
    target_profile_admitted: Literal[True] = Field(
        default=True,
        alias="targetProfileAdmitted",
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="providerExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        if (
            self.provider_profile_digest != self.registration.provider_profile_digest
            or self.ground_truth_digest != self.registration.ground_truth_digest
        ):
            raise ValueError("Target Profile Selection differs from its registration")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-profile-selection/v1",
            material,
            max_bytes=_MAX_SELECTION_BYTES,
        )
        authority_id = f"benchmark-target-selection:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Benchmark Target Profile Selection Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Benchmark Target Profile Selection Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_traditional_web_api_ground_truth(
    profile: DockerBugBountyTargetProfile,
    *,
    benchmark_id: str,
) -> BenchmarkGroundTruth:
    """Build the only P0-D1 private Ground Truth profile from code-owned matcher semantics."""

    authoritative_profile = _canonical_profile(profile)
    return BenchmarkGroundTruth(
        benchmarkId=benchmark_id,
        targetFactoryDigest=authoritative_profile.target_factory_digest,
        cases=[
            BenchmarkGroundTruthCase(
                groundTruthId=_GROUND_TRUTH_ID,
                expectedFindingId=_FINDING_ID,
                surfaceIds=[_SURFACE_ID],
                chainId=_CHAIN_ID,
                matcherId=_MATCHER_ID,
                matcherVersion=_MATCHER_VERSION,
                matcherDigest=TRADITIONAL_WEB_API_BOOLEAN_SQLI_MATCHER_DIGEST,
                visibility=GroundTruthVisibility.SEEDED,
            )
        ],
    )


def registered_traditional_web_api_target_catalog(
    profile: DockerBugBountyTargetProfile,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkTargetProfileCatalog:
    """Build revision one containing the exact provisioned Docker image identities."""

    authoritative_profile = _canonical_profile(profile)
    authoritative_ground_truth = _canonical_ground_truth(ground_truth)
    expected_ground_truth = registered_traditional_web_api_ground_truth(
        authoritative_profile,
        benchmark_id=authoritative_ground_truth.benchmark_id,
    )
    if authoritative_ground_truth != expected_ground_truth:
        raise BenchmarkTargetCatalogError(
            "Traditional Web/API Ground Truth differs from the code-registered profile"
        )
    registration = BenchmarkTargetProfileRegistration(
        targetFamily="traditional-web-api",
        targetProfileId=authoritative_profile.profile_id,
        targetProfileVersion=authoritative_profile.profile_version,
        targetFactoryId=_TARGET_FACTORY_ID,
        targetFactoryVersion=authoritative_profile.profile_version,
        targetFactoryDigest=authoritative_profile.target_factory_digest,
        providerProfileApiVersion=authoritative_profile.api_version,
        providerProfileDigest=authoritative_profile.target_factory_digest,
        mutationProfileIds=(),
        groundTruthDigest=authoritative_ground_truth.digest(),
    )
    return BenchmarkTargetProfileCatalog(registrations=(registration,))


def select_traditional_web_api_target_profile(
    manifest: BenchmarkManifest,
    *,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    profile: DockerBugBountyTargetProfile,
    catalog: BenchmarkTargetProfileCatalog,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkTargetProfileSelectionAuthority:
    """Fail closed unless every public and private identity selects the exact P0-D1 profile."""

    try:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        authoritative_adapter = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
            adapter.model_dump(mode="json", by_alias=True)
        )
        authoritative_profile = _canonical_profile(profile)
        authoritative_catalog = BenchmarkTargetProfileCatalog.model_validate(
            catalog.model_dump(mode="json", by_alias=True)
        )
        authoritative_ground_truth = _canonical_ground_truth(ground_truth)
        expected_catalog = registered_traditional_web_api_target_catalog(
            authoritative_profile,
            authoritative_ground_truth,
        )
        if authoritative_catalog != expected_catalog:
            raise ValueError("Target catalog differs from the registered profile")
        registration = authoritative_catalog.registrations[0]
        binding = BenchmarkTargetGroundTruthBinding(
            registration=registration,
            groundTruth=authoritative_ground_truth,
        )
        allowed_mutation = (
            authoritative_manifest.mutation_profile_id is None
            if not registration.mutation_profile_ids
            else authoritative_manifest.mutation_profile_id
            in registration.mutation_profile_ids
        )
        if (
            authoritative_manifest.benchmark_id != authoritative_ground_truth.benchmark_id
            or authoritative_manifest.target_profile_id != registration.target_profile_id
            or authoritative_manifest.target_profile_version
            != registration.target_profile_version
            or authoritative_manifest.target_factory_id != registration.target_factory_id
            or authoritative_manifest.target_factory_version
            != registration.target_factory_version
            or authoritative_manifest.target_factory_digest
            != registration.target_factory_digest
            or authoritative_manifest.ground_truth_digest
            != registration.ground_truth_digest
            or not allowed_mutation
        ):
            raise ValueError("Benchmark Manifest differs from Target catalog selection")
        if (
            authoritative_adapter.target_factory_id != registration.target_factory_id
            or authoritative_adapter.target_factory_version
            != registration.target_factory_version
            or authoritative_adapter.target_factory_digest
            != registration.target_factory_digest
        ):
            raise ValueError("Benchmark adapter differs from Target catalog selection")
        return BenchmarkTargetProfileSelectionAuthority(
            catalogId=authoritative_catalog.catalog_id,
            catalogRevision=authoritative_catalog.catalog_revision,
            catalogDigest=authoritative_catalog.catalog_digest,
            registration=registration,
            manifestDigest=authoritative_manifest.digest(),
            adapterDigest=authoritative_adapter.adapter_digest,
            providerProfileDigest=authoritative_profile.target_factory_digest,
            groundTruthBindingDigest=binding.binding_digest,
            groundTruthDigest=authoritative_ground_truth.digest(),
        )
    except (ValueError, TypeError) as exc:
        raise BenchmarkTargetCatalogError(
            "Traditional Web/API Target catalog selection failed"
        ) from exc


class _DockerCatalogProvider(Protocol):
    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter: ...

    @property
    def profile(self) -> DockerTargetProfile: ...

    def evidence(
        self,
        receipt: BenchmarkTargetStageReceipt,
    ) -> DockerBenchmarkProviderEvidence: ...

    async def reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt: ...

    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt: ...

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]: ...

    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt: ...

    async def reconcile_cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        request: BenchmarkTargetRecoveryRequest,
    ) -> BenchmarkTargetStageReceipt: ...

    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation: ...


class _CatalogBoundDockerTargetFactoryAdapter:
    """Shared catalog gate for fixed, code-owned Docker benchmark scenarios."""

    def __init__(
        self,
        *,
        provider: _DockerCatalogProvider,
        manifest: BenchmarkManifest,
        catalog: BenchmarkTargetProfileCatalog,
        ground_truth: BenchmarkGroundTruth,
    ) -> None:
        self._provider = provider
        self._profile: DockerTargetProfile = _canonical_profile(
            cast(DockerBugBountyTargetProfile, provider.profile)
        )
        self._definition = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
            provider.definition.model_dump(mode="json", by_alias=True)
        )
        self._manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        self._ground_truth = _canonical_ground_truth(ground_truth)
        self._selection = select_traditional_web_api_target_profile(
            self._manifest,
            adapter=self._definition,
            profile=self._profile,
            catalog=catalog,
            ground_truth=self._ground_truth,
        )

    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        return self._definition.model_copy(deep=True)

    @property
    def profile(self) -> DockerTargetProfile:
        return DockerBugBountyTargetProfile.model_validate(
            cast(DockerBugBountyTargetProfile, self._profile).model_dump(
                mode="json", by_alias=True
            )
        )

    @property
    def selection(self) -> BenchmarkTargetProfileSelectionAuthority:
        return self._selection.model_copy(deep=True)

    def evidence(
        self,
        receipt: BenchmarkTargetStageReceipt,
    ) -> DockerBenchmarkProviderEvidence:
        return self._provider.evidence(receipt)

    async def reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        authoritative_coordinate = self._require_coordinate(coordinate)
        return await self._provider.reset(authoritative_coordinate, operation)

    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        authoritative_coordinate = self._require_coordinate(coordinate)
        return await self._provider.establish_isolation(
            authoritative_coordinate,
            reset,
            operation,
        )

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        authoritative_coordinate = self._require_coordinate(coordinate)
        receipt, observation = await self._provider.execute(
            authoritative_coordinate,
            isolation,
            operation,
        )
        evidence = self._provider.evidence(receipt)
        canonical_receipt, canonical_observation = self._require_registered_match(
            authoritative_coordinate,
            receipt,
            evidence,
            observation,
        )
        return canonical_receipt, canonical_observation

    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        authoritative_coordinate = self._require_coordinate(coordinate)
        return await self._provider.cleanup(
            authoritative_coordinate,
            isolation,
            operation,
        )

    async def reconcile_cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        request: BenchmarkTargetRecoveryRequest,
    ) -> BenchmarkTargetStageReceipt:
        authoritative_coordinate = self._require_coordinate(coordinate)
        return await self._provider.reconcile_cleanup(authoritative_coordinate, request)

    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        self._require_provider_identity()
        try:
            authoritative_statement = BenchmarkMeasurementAttestationStatement.model_validate(
                statement.model_dump(mode="json", by_alias=True)
            )
        except (ValueError, TypeError) as exc:
            raise BenchmarkTargetCatalogError(
                "Measurement attestation statement is structurally invalid"
            ) from exc
        if authoritative_statement.adapter_digest != self._selection.adapter_digest:
            raise BenchmarkTargetCatalogError(
                "Measurement attestation differs from Target catalog selection"
            )
        return await self._provider.attest(authoritative_statement)

    def _require_coordinate(
        self,
        coordinate: BenchmarkTargetCoordinate,
    ) -> BenchmarkTargetCoordinate:
        self._require_provider_identity()
        try:
            authoritative_coordinate = BenchmarkTargetCoordinate.model_validate(
                coordinate.model_dump(mode="json", by_alias=True)
            )
        except (ValueError, TypeError) as exc:
            raise BenchmarkTargetCatalogError(
                "Target coordinate is structurally invalid"
            ) from exc
        if (
            authoritative_coordinate.benchmark_id != self._manifest.benchmark_id
            or authoritative_coordinate.manifest_digest != self._selection.manifest_digest
        ):
            raise BenchmarkTargetCatalogError(
                "Target coordinate differs from catalog-selected Manifest"
            )
        return authoritative_coordinate

    def _require_provider_identity(self) -> None:
        try:
            current_definition = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
                self._provider.definition.model_dump(mode="json", by_alias=True)
            )
            current_profile = _canonical_profile(
                cast(DockerBugBountyTargetProfile, self._provider.profile)
            )
        except (ValueError, TypeError) as exc:
            raise BenchmarkTargetCatalogError(
                "Target provider identity is structurally invalid"
            ) from exc
        if current_definition != self._definition or current_profile != self._profile:
            raise BenchmarkTargetCatalogError(
                "Target provider identity changed after catalog selection"
            )

    def _require_registered_match(
        self,
        coordinate: BenchmarkTargetCoordinate,
        receipt: BenchmarkTargetStageReceipt,
        evidence: DockerBenchmarkProviderEvidence,
        observation: WalkingBenchmarkRunObservation,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        try:
            authoritative_receipt = BenchmarkTargetStageReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
            )
            authoritative_evidence = DockerBenchmarkProviderEvidence.model_validate(
                evidence.model_dump(mode="json", by_alias=True)
            )
            authoritative_observation = WalkingBenchmarkRunObservation.model_validate(
                observation.model_dump(mode="json", by_alias=True)
            )
        except (ValueError, TypeError) as exc:
            raise BenchmarkTargetCatalogError(
                "Docker execution match input is structurally invalid"
            ) from exc
        case_count = len(self._ground_truth.cases)
        surface_count = len(
            {surface for case in self._ground_truth.cases for surface in case.surface_ids}
        )
        chain_count = len(
            {case.chain_id for case in self._ground_truth.cases if case.chain_id is not None}
        )
        arm = coordinate.arm
        if (
            authoritative_evidence.stage != BenchmarkTargetStage.EXECUTION
            or authoritative_receipt.stage != BenchmarkTargetStage.EXECUTION
            or authoritative_evidence.adapter_digest != self._definition.adapter_digest
            or authoritative_evidence.coordinate_digest != coordinate.coordinate_digest
            or authoritative_evidence.operation_id != authoritative_receipt.operation_id
            or authoritative_evidence.evidence_digest
            != authoritative_receipt.provider_evidence_digest
            or authoritative_receipt.adapter_digest != self._definition.adapter_digest
            or authoritative_receipt.coordinate_digest != coordinate.coordinate_digest
            or authoritative_evidence.target_image_id != self._profile.target_image_id
            or authoritative_evidence.worker_image_id != self._profile.worker_image_id
            or authoritative_evidence.worker_exit_code != 0
            or authoritative_evidence.probe_vulnerable is not True
            or authoritative_observation.benchmark_id != self._manifest.benchmark_id
            or authoritative_observation.manifest_digest != self._selection.manifest_digest
            or authoritative_observation.arm_id != arm.arm_id
            or authoritative_observation.arm_kind != arm.kind
            or authoritative_observation.configuration_digest != arm.configuration_digest
            or authoritative_observation.target_factory_digest
            != self._selection.registration.target_factory_digest
            or authoritative_observation.campaign_digest != self._manifest.campaign_digest
            or authoritative_observation.ground_truth_digest != self._ground_truth.digest()
            or authoritative_observation.protocol_id != self._manifest.protocol.protocol_id
            or authoritative_observation.protocol_version
            != self._manifest.protocol.protocol_version
            or authoritative_observation.measurement_authority_id
            != self._definition.measurement_authority_id
            or authoritative_observation.measurement_authority_version
            != self._definition.measurement_authority_version
            or authoritative_observation.measurement_authority_digest
            != self._definition.measurement_authority_digest
            or authoritative_observation.seed != coordinate.seed
            or authoritative_observation.repetition != coordinate.repetition
            or authoritative_observation.tool_call_count != 1
            or authoritative_observation.model_call_count != 0
            or authoritative_observation.cost_usd != 0.0
            or authoritative_observation.known_attack_surface_count != surface_count
            or authoritative_observation.discovered_known_attack_surface_count != surface_count
            or authoritative_observation.known_finding_count != case_count
            or authoritative_observation.matched_known_finding_count != case_count
            or authoritative_observation.candidate_finding_count != case_count
            or authoritative_observation.valid_candidate_finding_count != case_count
            or authoritative_observation.confirmed_finding_count != case_count
            or authoritative_observation.unexpected_valid_finding_count != 0
            or authoritative_observation.ground_truth_chain_count != chain_count
            or authoritative_observation.completed_ground_truth_chain_count != chain_count
            or authoritative_observation.first_valid_or_confirmed_finding_seconds != 0.0
            or authoritative_observation.replay_attempt_count != 1
            or authoritative_observation.replay_success_count != 1
            or authoritative_observation.policy_rejection_or_violation_count != 0
            or authoritative_observation.human_decision_count != 1
            or authoritative_observation.human_intervention_or_overturn_count != 0
            or authoritative_observation.open_world_candidate_ids != ()
        ):
            raise BenchmarkTargetCatalogError(
                "Docker execution evidence does not match registered Ground Truth"
            )
        return authoritative_receipt, authoritative_observation


class CatalogBoundDockerBugBountyTargetFactoryAdapter(
    _CatalogBoundDockerTargetFactoryAdapter
):
    """Add the P0-D1 catalog and private Ground Truth gate to the SQLi provider."""

    @property
    def profile(self) -> DockerBugBountyTargetProfile:
        return DockerBugBountyTargetProfile.model_validate(
            cast(DockerBugBountyTargetProfile, self._profile).model_dump(
                mode="json", by_alias=True
            )
        )


def _canonical_profile(
    profile: DockerBugBountyTargetProfile,
) -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile.model_validate(
        profile.model_dump(mode="json", by_alias=True)
    )


def _canonical_ground_truth(ground_truth: BenchmarkGroundTruth) -> BenchmarkGroundTruth:
    return BenchmarkGroundTruth.model_validate(
        ground_truth.model_dump(mode="json", by_alias=True)
    )
