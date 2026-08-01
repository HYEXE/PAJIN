"""P0-D2 non-executable AI/RAG/MCP benchmark Target profile catalog."""

from __future__ import annotations

from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.docker_provider import (
    DOCKER_AI_RAG_MCP_TARGET_PROFILE_API_VERSION,
    DOCKER_BENCHMARK_PROVIDER_EVIDENCE_API_VERSION,
    DockerAIRAGMCPTargetFactoryAdapter,
    DockerAIRAGMCPTargetProfile,
)
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
    BenchmarkTargetGroundTruthBinding,
    BenchmarkTargetProfileCatalog,
    BenchmarkTargetProfileRegistration,
    BenchmarkTargetProfileSelectionAuthority,
    _CatalogBoundDockerTargetFactoryAdapter,
)
from pajin.benchmark.target_factory import RegisteredBenchmarkTargetFactoryAdapter
from pajin.discovery.walking import WALKING_HYPOTHESIS_API_VERSION
from pajin.discovery.walking_closure import WALKING_MCP_CONFIRMATION_API_VERSION
from pajin.discovery.walking_mcp import WALKING_MCP_AUTHORIZATION_API_VERSION
from pajin.discovery.walking_replay import WALKING_MCP_CLAIM_REPLAY_API_VERSION
from pajin.discovery.walking_validation import WALKING_CANDIDATE_ADMISSION_API_VERSION
from pajin.domain.models import StrictModel

AI_RAG_MCP_WALKING_TARGET_PROFILE_API_VERSION: Literal[
    "pajin.dev/ai-rag-mcp-walking-target-profile/v1alpha1"
] = "pajin.dev/ai-rag-mcp-walking-target-profile/v1alpha1"
BENCHMARK_TARGET_FIXTURE_SELECTION_API_VERSION: Literal[
    "pajin.dev/benchmark-target-fixture-selection/v1alpha1"
] = "pajin.dev/benchmark-target-fixture-selection/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")]
_ApiVersion = Annotated[
    str,
    Field(pattern=r"^pajin\.dev/[a-z0-9][a-z0-9./-]{1,198}$"),
]
_MAX_PROFILE_BYTES = 128 * 1024
_MAX_SELECTION_BYTES = 512 * 1024

_CATALOG_ID: Literal["target-catalog:pajin-ai-rag-mcp"] = (
    "target-catalog:pajin-ai-rag-mcp"
)
_LOCAL_DOCKER_CATALOG_ID: Literal[
    "target-catalog:pajin-ai-rag-mcp-local-docker"
] = "target-catalog:pajin-ai-rag-mcp-local-docker"
_GROUND_TRUTH_ID = "ground-truth:rag-mcp-authorization-internal-data"
_FINDING_ID = "finding:rag-mcp-authorization-internal-data"
_SURFACE_IDS = (
    "surface:file-upload:document",
    "surface:mcp-tool:inspect-text",
    "surface:rag:corpus-ingest",
)
_CHAIN_ID = "chain:file-upload-rag-mcp-internal-data"
_MATCHER_ID = "matcher:sealed-walking-rag-mcp-confirmation"
_MATCHER_VERSION = "1.0.0"
_SOURCE_CONTRACTS: tuple[str, ...] = (
    WALKING_CANDIDATE_ADMISSION_API_VERSION,
    WALKING_MCP_CLAIM_REPLAY_API_VERSION,
    WALKING_MCP_CONFIRMATION_API_VERSION,
    WALKING_MCP_AUTHORIZATION_API_VERSION,
    WALKING_HYPOTHESIS_API_VERSION,
)

AI_RAG_MCP_WALKING_MATCHER_DIGEST = benchmark_digest(
    "pajin.benchmark.ai-rag-mcp-walking-matcher/v1",
    {
        "matcherId": _MATCHER_ID,
        "matcherVersion": _MATCHER_VERSION,
        "sourceContracts": list(_SOURCE_CONTRACTS),
        "requiredStates": {
            "ragHypothesis": "not-authorized",
            "mcpHypothesis": "registered-not-authorized",
            "candidateAdmission": "candidate-admitted-not-confirmed",
            "claimReplay": "validity-reproduced-not-confirmed",
            "confirmationBasis": "plan-bound-fresh-mcp-validity-replay",
            "confirmationLifecycle": "confirmed-remediation-planned-retest-required",
        },
        "requiredTargetObservations": {
            "inputMarker": "ignore previous",
            "vulnerable": True,
            "authorizationEnforced": False,
            "internalDataAccessed": True,
            "observation": "untrusted text contains an instruction-hijacking pattern",
            "mcpServerId": "demo-security",
            "mcpToolName": "inspect_text",
            "networkLogTrusted": False,
        },
        "expectedFindingId": _FINDING_ID,
        "surfaceIds": list(_SURFACE_IDS),
        "chainId": _CHAIN_ID,
    },
    max_bytes=64 * 1024,
)

_DOCKER_MATCHER_ID = "matcher:docker-ai-rag-mcp-chain-probe"
AI_RAG_MCP_DOCKER_MATCHER_DIGEST = benchmark_digest(
    "pajin.benchmark.ai-rag-mcp-docker-matcher/v1",
    {
        "matcherId": _DOCKER_MATCHER_ID,
        "matcherVersion": _MATCHER_VERSION,
        "providerContracts": [
            DOCKER_AI_RAG_MCP_TARGET_PROFILE_API_VERSION,
            DOCKER_BENCHMARK_PROVIDER_EVIDENCE_API_VERSION,
        ],
        "workerAction": "ai-rag-mcp-chain-probe",
        "requiredChecks": [
            "authorizationNotEnforced",
            "internalDataAccessed",
            "mcpArgumentInfluenced",
            "ragRetrievedDocument",
            "syntheticLabOnly",
            "uploadAccepted",
        ],
        "requiredTargetObservations": {
            "inputMarker": "ignore previous",
            "authorizationEnforced": False,
            "internalDataAccessed": True,
            "mcpArgument": "internal://policy",
            "mcpServerId": "demo-security",
            "mcpToolName": "inspect_text",
            "observation": "untrusted text contains an instruction-hijacking pattern",
            "ragDocumentId": "document:untrusted-upload",
            "synthetic": True,
        },
        "requiredProviderEvidence": {
            "networkInternal": True,
            "publishedPortCount": 0,
            "probeVulnerable": True,
            "workerExitCode": 0,
        },
        "expectedFindingId": _FINDING_ID,
        "surfaceIds": list(_SURFACE_IDS),
        "chainId": _CHAIN_ID,
    },
    max_bytes=64 * 1024,
)


class AIRAGMCPWalkingTargetProfile(StrictModel):
    """Content-addressed fixture contract; no runnable Target provider is registered."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-rag-mcp-walking-target-profile/v1alpha1"] = Field(
        default=AI_RAG_MCP_WALKING_TARGET_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIRAGMCPWalkingTargetProfile"] = "AIRAGMCPWalkingTargetProfile"
    profile_id: Literal[
        "ai-rag-mcp.walking.file-upload-rag-tool-authorization"
    ] = Field(
        default="ai-rag-mcp.walking.file-upload-rag-tool-authorization",
        alias="profileId",
    )
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    target_family: Literal["ai-rag-mcp"] = Field(default="ai-rag-mcp", alias="targetFamily")
    target_factory_id: Literal[
        "target-factory:walking-ai-rag-mcp-fixture-contract"
    ] = Field(
        default="target-factory:walking-ai-rag-mcp-fixture-contract",
        alias="targetFactoryId",
    )
    target_factory_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="targetFactoryVersion",
    )
    target_factory_digest: str = Field(default="", alias="targetFactoryDigest", max_length=64)
    execution_availability: Literal["fixture-contract-only"] = Field(
        default="fixture-contract-only",
        alias="executionAvailability",
    )
    evidence_trust: Literal["sealed-walking-fixture-network-untrusted"] = Field(
        default="sealed-walking-fixture-network-untrusted",
        alias="evidenceTrust",
    )
    network_policy: Literal["not-provisioned-contract-only"] = Field(
        default="not-provisioned-contract-only",
        alias="networkPolicy",
    )
    source_contracts: tuple[_ApiVersion, ...] = Field(
        default=_SOURCE_CONTRACTS,
        alias="sourceContracts",
        min_length=len(_SOURCE_CONTRACTS),
        max_length=len(_SOURCE_CONTRACTS),
    )

    @field_validator("source_contracts")
    @classmethod
    def require_exact_source_contracts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _SOURCE_CONTRACTS:
            raise ValueError("AI/RAG/MCP fixture source contracts differ from code registration")
        return value

    @model_validator(mode="after")
    def bind_profile(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"target_factory_digest"},
        )
        canonical_benchmark_json(
            material,
            label="AIRAGMCPWalkingTargetProfile",
            max_bytes=_MAX_PROFILE_BYTES,
        )
        digest = benchmark_digest(
            "pajin.benchmark.ai-rag-mcp-walking-target-profile/v1",
            material,
            max_bytes=_MAX_PROFILE_BYTES,
        )
        if self.target_factory_digest and self.target_factory_digest != digest:
            raise ValueError("AI/RAG/MCP Walking Target Factory Digest differs")
        object.__setattr__(self, "target_factory_digest", digest)
        return self


class BenchmarkTargetFixtureSelectionAuthority(StrictModel):
    """Non-runnable selection of one catalogued fixture and private Ground Truth."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-target-fixture-selection/v1alpha1"
    ] = Field(
        default=BENCHMARK_TARGET_FIXTURE_SELECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkTargetFixtureSelectionAuthority"] = (
        "BenchmarkTargetFixtureSelectionAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    catalog_id: _Identifier = Field(alias="catalogId")
    catalog_revision: int = Field(alias="catalogRevision", ge=1)
    catalog_digest: _Sha256 = Field(alias="catalogDigest")
    registration: BenchmarkTargetProfileRegistration
    manifest_digest: _Sha256 = Field(alias="manifestDigest")
    fixture_profile_digest: _Sha256 = Field(alias="fixtureProfileDigest")
    ground_truth_binding_digest: _Sha256 = Field(alias="groundTruthBindingDigest")
    ground_truth_digest: _Sha256 = Field(alias="groundTruthDigest")
    selection_state: Literal["registered-fixture-not-runnable"] = Field(
        default="registered-fixture-not-runnable",
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
    measurement_admission_eligible: Literal[False] = Field(
        default=False,
        alias="measurementAdmissionEligible",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        if (
            self.fixture_profile_digest != self.registration.provider_profile_digest
            or self.ground_truth_digest != self.registration.ground_truth_digest
            or self.registration.target_family != "ai-rag-mcp"
            or self.registration.network_policy != "not-provisioned-contract-only"
        ):
            raise ValueError("AI/RAG/MCP fixture selection differs from registration")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.target-fixture-selection/v1",
            material,
            max_bytes=_MAX_SELECTION_BYTES,
        )
        authority_id = f"benchmark-target-fixture:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Benchmark Target Fixture Selection Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Benchmark Target Fixture Selection Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_ai_rag_mcp_walking_target_profile() -> AIRAGMCPWalkingTargetProfile:
    """Return the only code-owned P0-D2 fixture profile."""

    return AIRAGMCPWalkingTargetProfile()


def registered_ai_rag_mcp_ground_truth(
    profile: AIRAGMCPWalkingTargetProfile,
    *,
    benchmark_id: str,
) -> BenchmarkGroundTruth:
    """Build the seeded private case without claiming a runnable provider."""

    authoritative_profile = _canonical_profile(profile)
    return BenchmarkGroundTruth(
        benchmarkId=benchmark_id,
        targetFactoryDigest=authoritative_profile.target_factory_digest,
        cases=[
            BenchmarkGroundTruthCase(
                groundTruthId=_GROUND_TRUTH_ID,
                expectedFindingId=_FINDING_ID,
                surfaceIds=list(_SURFACE_IDS),
                chainId=_CHAIN_ID,
                matcherId=_MATCHER_ID,
                matcherVersion=_MATCHER_VERSION,
                matcherDigest=AI_RAG_MCP_WALKING_MATCHER_DIGEST,
                visibility=GroundTruthVisibility.SEEDED,
            )
        ],
    )


def registered_ai_rag_mcp_target_catalog(
    profile: AIRAGMCPWalkingTargetProfile,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkTargetProfileCatalog:
    """Register a contract-only profile while keeping private cases outside the catalog."""

    authoritative_profile = _canonical_profile(profile)
    authoritative_ground_truth = _canonical_ground_truth(ground_truth)
    expected_ground_truth = registered_ai_rag_mcp_ground_truth(
        authoritative_profile,
        benchmark_id=authoritative_ground_truth.benchmark_id,
    )
    if authoritative_ground_truth != expected_ground_truth:
        raise BenchmarkTargetCatalogError(
            "AI/RAG/MCP Ground Truth differs from the code-registered fixture"
        )
    registration = BenchmarkTargetProfileRegistration(
        targetFamily=authoritative_profile.target_family,
        targetProfileId=authoritative_profile.profile_id,
        targetProfileVersion=authoritative_profile.profile_version,
        targetFactoryId=authoritative_profile.target_factory_id,
        targetFactoryVersion=authoritative_profile.target_factory_version,
        targetFactoryDigest=authoritative_profile.target_factory_digest,
        providerProfileApiVersion=authoritative_profile.api_version,
        providerProfileDigest=authoritative_profile.target_factory_digest,
        mutationProfileIds=(),
        networkPolicy=authoritative_profile.network_policy,
        groundTruthDigest=authoritative_ground_truth.digest(),
    )
    return BenchmarkTargetProfileCatalog(
        catalogId=_CATALOG_ID,
        registrations=(registration,),
    )


def select_ai_rag_mcp_target_fixture(
    manifest: BenchmarkManifest,
    *,
    profile: AIRAGMCPWalkingTargetProfile,
    catalog: BenchmarkTargetProfileCatalog,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkTargetFixtureSelectionAuthority:
    """Admit exact fixture identity without producing adapter or measurement authority."""

    try:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        authoritative_profile = _canonical_profile(profile)
        authoritative_catalog = BenchmarkTargetProfileCatalog.model_validate(
            catalog.model_dump(mode="json", by_alias=True)
        )
        authoritative_ground_truth = _canonical_ground_truth(ground_truth)
        expected_catalog = registered_ai_rag_mcp_target_catalog(
            authoritative_profile,
            authoritative_ground_truth,
        )
        if authoritative_catalog != expected_catalog:
            raise ValueError("AI/RAG/MCP catalog differs from registered fixture")
        registration = authoritative_catalog.registrations[0]
        binding = BenchmarkTargetGroundTruthBinding(
            registration=registration,
            groundTruth=authoritative_ground_truth,
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
            or authoritative_manifest.mutation_profile_id is not None
        ):
            raise ValueError("Benchmark Manifest differs from AI/RAG/MCP fixture selection")
        return BenchmarkTargetFixtureSelectionAuthority(
            catalogId=authoritative_catalog.catalog_id,
            catalogRevision=authoritative_catalog.catalog_revision,
            catalogDigest=authoritative_catalog.catalog_digest,
            registration=registration,
            manifestDigest=authoritative_manifest.digest(),
            fixtureProfileDigest=authoritative_profile.target_factory_digest,
            groundTruthBindingDigest=binding.binding_digest,
            groundTruthDigest=authoritative_ground_truth.digest(),
        )
    except (ValueError, TypeError) as exc:
        raise BenchmarkTargetCatalogError(
            "AI/RAG/MCP Target fixture selection failed"
        ) from exc


def registered_ai_rag_mcp_docker_ground_truth(
    profile: DockerAIRAGMCPTargetProfile,
    *,
    benchmark_id: str,
) -> BenchmarkGroundTruth:
    """Build the seeded private case for the runnable local Docker profile."""

    authoritative_profile = _canonical_docker_profile(profile)
    return BenchmarkGroundTruth(
        benchmarkId=benchmark_id,
        targetFactoryDigest=authoritative_profile.target_factory_digest,
        cases=[
            BenchmarkGroundTruthCase(
                groundTruthId=_GROUND_TRUTH_ID,
                expectedFindingId=_FINDING_ID,
                surfaceIds=list(_SURFACE_IDS),
                chainId=_CHAIN_ID,
                matcherId=_DOCKER_MATCHER_ID,
                matcherVersion=_MATCHER_VERSION,
                matcherDigest=AI_RAG_MCP_DOCKER_MATCHER_DIGEST,
                visibility=GroundTruthVisibility.SEEDED,
            )
        ],
    )


def registered_ai_rag_mcp_docker_target_catalog(
    profile: DockerAIRAGMCPTargetProfile,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkTargetProfileCatalog:
    """Register exact runnable local images without changing the fixture-only catalog."""

    authoritative_profile = _canonical_docker_profile(profile)
    authoritative_ground_truth = _canonical_ground_truth(ground_truth)
    expected_ground_truth = registered_ai_rag_mcp_docker_ground_truth(
        authoritative_profile,
        benchmark_id=authoritative_ground_truth.benchmark_id,
    )
    if authoritative_ground_truth != expected_ground_truth:
        raise BenchmarkTargetCatalogError(
            "Docker AI/RAG/MCP Ground Truth differs from the code-registered profile"
        )
    registration = BenchmarkTargetProfileRegistration(
        targetFamily="ai-rag-mcp",
        targetProfileId=authoritative_profile.profile_id,
        targetProfileVersion=authoritative_profile.profile_version,
        targetFactoryId="target-factory:docker-ai-rag-mcp",
        targetFactoryVersion=authoritative_profile.profile_version,
        targetFactoryDigest=authoritative_profile.target_factory_digest,
        providerProfileApiVersion=authoritative_profile.api_version,
        providerProfileDigest=authoritative_profile.target_factory_digest,
        mutationProfileIds=(),
        networkPolicy="docker-internal-bridge-no-published-ports",
        groundTruthDigest=authoritative_ground_truth.digest(),
    )
    return BenchmarkTargetProfileCatalog(
        catalogId=_LOCAL_DOCKER_CATALOG_ID,
        registrations=(registration,),
    )


def select_ai_rag_mcp_docker_target_profile(
    manifest: BenchmarkManifest,
    *,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
    profile: DockerAIRAGMCPTargetProfile,
    catalog: BenchmarkTargetProfileCatalog,
    ground_truth: BenchmarkGroundTruth,
) -> BenchmarkTargetProfileSelectionAuthority:
    """Select one exact runnable profile, adapter, Manifest, and private binding."""

    try:
        authoritative_manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        authoritative_adapter = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
            adapter.model_dump(mode="json", by_alias=True)
        )
        authoritative_profile = _canonical_docker_profile(profile)
        authoritative_catalog = BenchmarkTargetProfileCatalog.model_validate(
            catalog.model_dump(mode="json", by_alias=True)
        )
        authoritative_ground_truth = _canonical_ground_truth(ground_truth)
        expected_catalog = registered_ai_rag_mcp_docker_target_catalog(
            authoritative_profile,
            authoritative_ground_truth,
        )
        if authoritative_catalog != expected_catalog:
            raise ValueError("Docker AI/RAG/MCP catalog differs from registered profile")
        registration = authoritative_catalog.registrations[0]
        binding = BenchmarkTargetGroundTruthBinding(
            registration=registration,
            groundTruth=authoritative_ground_truth,
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
            or authoritative_manifest.mutation_profile_id is not None
            or authoritative_adapter.target_factory_id != registration.target_factory_id
            or authoritative_adapter.target_factory_version
            != registration.target_factory_version
            or authoritative_adapter.target_factory_digest
            != registration.target_factory_digest
        ):
            raise ValueError("Benchmark Manifest or adapter differs from Docker AI selection")
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
            "Docker AI/RAG/MCP Target catalog selection failed"
        ) from exc


class CatalogBoundDockerAIRAGMCPTargetFactoryAdapter(
    _CatalogBoundDockerTargetFactoryAdapter
):
    """Apply the runnable AI catalog and private Ground Truth gate to the provider."""

    def __init__(
        self,
        *,
        provider: DockerAIRAGMCPTargetFactoryAdapter,
        manifest: BenchmarkManifest,
        catalog: BenchmarkTargetProfileCatalog,
        ground_truth: BenchmarkGroundTruth,
    ) -> None:
        self._provider = provider
        self._profile = _canonical_docker_profile(provider.profile)
        self._definition = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
            provider.definition.model_dump(mode="json", by_alias=True)
        )
        self._manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        self._ground_truth = _canonical_ground_truth(ground_truth)
        self._selection = select_ai_rag_mcp_docker_target_profile(
            self._manifest,
            adapter=self._definition,
            profile=self.profile,
            catalog=catalog,
            ground_truth=self._ground_truth,
        )

    @property
    def profile(self) -> DockerAIRAGMCPTargetProfile:
        return DockerAIRAGMCPTargetProfile.model_validate(
            self._profile.model_dump(mode="json", by_alias=True)
        )

    def _require_provider_identity(self) -> None:
        try:
            current_definition = RegisteredBenchmarkTargetFactoryAdapter.model_validate(
                self._provider.definition.model_dump(mode="json", by_alias=True)
            )
            current_profile = _canonical_docker_profile(
                cast(DockerAIRAGMCPTargetProfile, self._provider.profile)
            )
        except (ValueError, TypeError) as exc:
            raise BenchmarkTargetCatalogError(
                "Docker AI/RAG/MCP provider identity is structurally invalid"
            ) from exc
        if current_definition != self._definition or current_profile != self._profile:
            raise BenchmarkTargetCatalogError(
                "Docker AI/RAG/MCP provider identity changed after catalog selection"
            )


def _canonical_profile(profile: AIRAGMCPWalkingTargetProfile) -> AIRAGMCPWalkingTargetProfile:
    return AIRAGMCPWalkingTargetProfile.model_validate(
        profile.model_dump(mode="json", by_alias=True)
    )


def _canonical_ground_truth(ground_truth: BenchmarkGroundTruth) -> BenchmarkGroundTruth:
    return BenchmarkGroundTruth.model_validate(
        ground_truth.model_dump(mode="json", by_alias=True)
    )


def _canonical_docker_profile(
    profile: DockerAIRAGMCPTargetProfile,
) -> DockerAIRAGMCPTargetProfile:
    return DockerAIRAGMCPTargetProfile.model_validate(
        profile.model_dump(mode="json", by_alias=True)
    )
