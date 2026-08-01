"""P0-D3 non-runnable composition of exact Traditional and AI Target selections."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.ai_target_catalog import AI_RAG_MCP_DOCKER_MATCHER_DIGEST
from pajin.benchmark.docker_provider import (
    DockerAIRAGMCPTargetProfile,
    DockerBugBountyTargetProfile,
)
from pajin.benchmark.models import BenchmarkManifest, GroundTruthVisibility, benchmark_digest
from pajin.benchmark.target_catalog import (
    TRADITIONAL_WEB_API_BOOLEAN_SQLI_MATCHER_DIGEST,
    BenchmarkTargetCatalogError,
    BenchmarkTargetGroundTruthBinding,
    BenchmarkTargetProfileCatalog,
    BenchmarkTargetProfileSelectionAuthority,
)
from pajin.benchmark.target_factory import RegisteredBenchmarkTargetFactoryAdapter
from pajin.domain.models import StrictModel

HYBRID_TARGET_COMPONENT_API_VERSION: Literal[
    "pajin.dev/hybrid-target-component/v1alpha1"
] = "pajin.dev/hybrid-target-component/v1alpha1"
HYBRID_TARGET_BRIDGE_API_VERSION: Literal[
    "pajin.dev/hybrid-target-bridge/v1alpha1"
] = "pajin.dev/hybrid-target-bridge/v1alpha1"
HYBRID_TARGET_COMPOSITION_API_VERSION: Literal[
    "pajin.dev/hybrid-target-composition/v1alpha1"
] = "pajin.dev/hybrid-target-composition/v1alpha1"
HYBRID_TARGET_GROUND_TRUTH_BINDING_API_VERSION: Literal[
    "pajin.dev/hybrid-target-ground-truth-binding/v1alpha1"
] = "pajin.dev/hybrid-target-ground-truth-binding/v1alpha1"
HYBRID_TARGET_SELECTION_API_VERSION: Literal[
    "pajin.dev/hybrid-target-selection/v1alpha1"
] = "pajin.dev/hybrid-target-selection/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_COMPONENT_BYTES = 768 * 1024
_MAX_BRIDGE_BYTES = 64 * 1024
_MAX_COMPOSITION_BYTES = 2 * 1024 * 1024
_MAX_PRIVATE_BINDING_BYTES = 8 * 1024 * 1024
_MAX_SELECTION_BYTES = 3 * 1024 * 1024

_TRADITIONAL_CATALOG_ID = "target-catalog:pajin-traditional-web-api"
_TRADITIONAL_PROFILE_ID = "bug-bounty.api.boolean-sqli-lab"
_TRADITIONAL_FACTORY_ID = "target-factory:docker-bug-bounty"
_TRADITIONAL_GT_ID = "ground-truth:boolean-sqli-user-lookup"
_TRADITIONAL_FINDING_ID = "finding:boolean-sqli-user-lookup"
_TRADITIONAL_SURFACE_IDS = ("surface:http-api-user-lookup",)
_TRADITIONAL_CHAIN_ID = "chain:single-surface-boolean-sqli"
_TRADITIONAL_MATCHER_ID = "matcher:docker-boolean-sqli-probe"

_AI_CATALOG_ID = "target-catalog:pajin-ai-rag-mcp-local-docker"
_AI_PROFILE_ID = "ai-rag-mcp.docker.file-upload-rag-tool-authorization"
_AI_FACTORY_ID = "target-factory:docker-ai-rag-mcp"
_AI_GT_ID = "ground-truth:rag-mcp-authorization-internal-data"
_AI_FINDING_ID = "finding:rag-mcp-authorization-internal-data"
_AI_SURFACE_IDS = (
    "surface:file-upload:document",
    "surface:mcp-tool:inspect-text",
    "surface:rag:corpus-ingest",
)
_AI_CHAIN_ID = "chain:file-upload-rag-mcp-internal-data"
_AI_MATCHER_ID = "matcher:docker-ai-rag-mcp-chain-probe"


class HybridTargetComponent(StrictModel):
    """One ordered, independently selected Target profile in the Hybrid contract."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/hybrid-target-component/v1alpha1"] = Field(
        default=HYBRID_TARGET_COMPONENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HybridTargetComponent"] = "HybridTargetComponent"
    component_digest: str = Field(default="", alias="componentDigest", max_length=64)
    ordinal: Literal[1, 2]
    role: Literal["entry-traditional-web-api", "follow-on-ai-rag-mcp"]
    selection: BenchmarkTargetProfileSelectionAuthority

    @model_validator(mode="after")
    def bind_component(self) -> Self:
        registration = self.selection.registration
        if self.ordinal == 1:
            expected = (
                "entry-traditional-web-api",
                _TRADITIONAL_CATALOG_ID,
                "traditional-web-api",
                _TRADITIONAL_PROFILE_ID,
                "1.0.0",
                _TRADITIONAL_FACTORY_ID,
                "1.0.0",
                "pajin.dev/docker-bug-bounty-target-profile/v1alpha1",
            )
        else:
            expected = (
                "follow-on-ai-rag-mcp",
                _AI_CATALOG_ID,
                "ai-rag-mcp",
                _AI_PROFILE_ID,
                "1.0.0",
                _AI_FACTORY_ID,
                "1.0.0",
                "pajin.dev/docker-ai-rag-mcp-target-profile/v1alpha1",
            )
        actual = (
            self.role,
            self.selection.catalog_id,
            registration.target_family,
            registration.target_profile_id,
            registration.target_profile_version,
            registration.target_factory_id,
            registration.target_factory_version,
            registration.provider_profile_api_version,
        )
        if actual != expected:
            raise ValueError("Hybrid Target component role or registered identity differs")
        if (
            registration.mutation_profile_ids
            or registration.network_policy != "docker-internal-bridge-no-published-ports"
            or registration.provider_profile_digest != registration.target_factory_digest
            or self.selection.catalog_revision != 1
        ):
            raise ValueError("Hybrid Target component policy or profile binding differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"component_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.hybrid-target-component/v1",
            material,
            max_bytes=_MAX_COMPONENT_BYTES,
        )
        if self.component_digest and self.component_digest != digest:
            raise ValueError("Hybrid Target Component Digest differs")
        object.__setattr__(self, "component_digest", digest)
        return self


class HybridTargetBridge(StrictModel):
    """Code-owned intended data-flow edge with no execution evidence in P0-D3."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/hybrid-target-bridge/v1alpha1"] = Field(
        default=HYBRID_TARGET_BRIDGE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HybridTargetBridge"] = "HybridTargetBridge"
    bridge_id: Literal[
        "bridge:boolean-sqli-output-to-untrusted-document-upload"
    ] = Field(
        default="bridge:boolean-sqli-output-to-untrusted-document-upload",
        alias="bridgeId",
    )
    bridge_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bridgeVersion")
    bridge_digest: str = Field(default="", alias="bridgeDigest", max_length=64)
    source_component_ordinal: Literal[1] = Field(
        default=1,
        alias="sourceComponentOrdinal",
    )
    destination_component_ordinal: Literal[2] = Field(
        default=2,
        alias="destinationComponentOrdinal",
    )
    source_finding_id: Literal["finding:boolean-sqli-user-lookup"] = Field(
        default="finding:boolean-sqli-user-lookup",
        alias="sourceFindingId",
    )
    source_surface_id: Literal["surface:http-api-user-lookup"] = Field(
        default="surface:http-api-user-lookup",
        alias="sourceSurfaceId",
    )
    destination_finding_id: Literal[
        "finding:rag-mcp-authorization-internal-data"
    ] = Field(
        default="finding:rag-mcp-authorization-internal-data",
        alias="destinationFindingId",
    )
    destination_surface_ids: tuple[str, ...] = Field(
        default=_AI_SURFACE_IDS,
        alias="destinationSurfaceIds",
        min_length=len(_AI_SURFACE_IDS),
        max_length=len(_AI_SURFACE_IDS),
    )
    transfer_semantics: Literal["synthetic-record-to-untrusted-document"] = Field(
        default="synthetic-record-to-untrusted-document",
        alias="transferSemantics",
    )
    bridge_state: Literal["declared-not-executed"] = Field(
        default="declared-not-executed",
        alias="bridgeState",
    )
    execution_evidence_required: Literal[True] = Field(
        default=True,
        alias="executionEvidenceRequired",
    )

    @field_validator("destination_surface_ids")
    @classmethod
    def require_exact_destination_surfaces(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _AI_SURFACE_IDS:
            raise ValueError("Hybrid Target bridge destination Surface set differs")
        return value

    @model_validator(mode="after")
    def bind_bridge(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"bridge_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.hybrid-target-bridge/v1",
            material,
            max_bytes=_MAX_BRIDGE_BYTES,
        )
        if self.bridge_digest and self.bridge_digest != digest:
            raise ValueError("Hybrid Target Bridge Digest differs")
        object.__setattr__(self, "bridge_digest", digest)
        return self


class HybridTargetCompositionAuthority(StrictModel):
    """Public structural composition that does not register a runnable Target Factory."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/hybrid-target-composition/v1alpha1"] = Field(
        default=HYBRID_TARGET_COMPOSITION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HybridTargetCompositionAuthority"] = (
        "HybridTargetCompositionAuthority"
    )
    composition_id: str = Field(default="", alias="compositionId", max_length=110)
    composition_digest: str = Field(default="", alias="compositionDigest", max_length=64)
    profile_id: Literal["hybrid.docker.sqli-to-rag-mcp-authorization"] = Field(
        default="hybrid.docker.sqli-to-rag-mcp-authorization",
        alias="profileId",
    )
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    components: tuple[HybridTargetComponent, ...] = Field(min_length=2, max_length=2)
    bridge: HybridTargetBridge
    execution_availability: Literal["composition-contract-only"] = Field(
        default="composition-contract-only",
        alias="executionAvailability",
    )
    target_factory_registered: Literal[False] = Field(
        default=False,
        alias="targetFactoryRegistered",
    )
    benchmark_manifest_eligible: Literal[False] = Field(
        default=False,
        alias="benchmarkManifestEligible",
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="providerExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_composition(self) -> Self:
        if tuple(component.ordinal for component in self.components) != (1, 2):
            raise ValueError("Hybrid Target components must preserve code-owned order")
        identities = (
            tuple(component.selection.catalog_id for component in self.components),
            tuple(
                component.selection.registration.target_factory_id
                for component in self.components
            ),
            tuple(component.selection.adapter_digest for component in self.components),
            tuple(component.selection.manifest_digest for component in self.components),
            tuple(component.selection.ground_truth_binding_digest for component in self.components),
        )
        if any(len(set(values)) != 2 for values in identities):
            raise ValueError("Hybrid Target components must use distinct exact authorities")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"composition_id", "composition_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.hybrid-target-composition/v1",
            material,
            max_bytes=_MAX_COMPOSITION_BYTES,
        )
        composition_id = f"hybrid-target-composition:{digest}"
        if self.composition_digest and self.composition_digest != digest:
            raise ValueError("Hybrid Target Composition Digest differs")
        if self.composition_id and self.composition_id != composition_id:
            raise ValueError("Hybrid Target Composition ID differs")
        object.__setattr__(self, "composition_digest", digest)
        object.__setattr__(self, "composition_id", composition_id)
        return self


class HybridTargetGroundTruthBinding(StrictModel):
    """Private component cases and intended cross-profile chain bound to the composition."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/hybrid-target-ground-truth-binding/v1alpha1"
    ] = Field(
        default=HYBRID_TARGET_GROUND_TRUTH_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HybridTargetGroundTruthBinding"] = (
        "HybridTargetGroundTruthBinding"
    )
    binding_id: str = Field(default="", alias="bindingId", max_length=110)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    composition_digest: _Sha256 = Field(alias="compositionDigest")
    bridge_digest: _Sha256 = Field(alias="bridgeDigest")
    component_bindings: tuple[BenchmarkTargetGroundTruthBinding, ...] = Field(
        alias="componentBindings",
        min_length=2,
        max_length=2,
    )
    hybrid_chain_id: Literal["chain:hybrid-sqli-to-rag-mcp-internal-data"] = Field(
        default="chain:hybrid-sqli-to-rag-mcp-internal-data",
        alias="hybridChainId",
    )
    chain_state: Literal["declared-not-executed"] = Field(
        default="declared-not-executed",
        alias="chainState",
    )

    @model_validator(mode="after")
    def bind_private_ground_truth(self) -> Self:
        _require_exact_component_ground_truth(self.component_bindings)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.hybrid-target-ground-truth-binding/v1",
            material,
            max_bytes=_MAX_PRIVATE_BINDING_BYTES,
        )
        binding_id = f"hybrid-target-ground-truth:{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Hybrid Target Ground Truth Binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("Hybrid Target Ground Truth Binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self


class HybridTargetSelectionAuthority(StrictModel):
    """Final non-runnable selection of one public composition and private binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/hybrid-target-selection/v1alpha1"] = Field(
        default=HYBRID_TARGET_SELECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HybridTargetSelectionAuthority"] = "HybridTargetSelectionAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    composition: HybridTargetCompositionAuthority
    ground_truth_binding_digest: _Sha256 = Field(alias="groundTruthBindingDigest")
    selection_state: Literal["registered-composition-not-runnable"] = Field(
        default="registered-composition-not-runnable",
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
    benchmark_manifest_eligible: Literal[False] = Field(
        default=False,
        alias="benchmarkManifestEligible",
    )

    @model_validator(mode="after")
    def bind_selection(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.hybrid-target-selection/v1",
            material,
            max_bytes=_MAX_SELECTION_BYTES,
        )
        authority_id = f"hybrid-target-selection:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Hybrid Target Selection Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Hybrid Target Selection Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_hybrid_target_composition(
    *,
    traditional_selection: BenchmarkTargetProfileSelectionAuthority,
    traditional_manifest: BenchmarkManifest,
    traditional_profile: DockerBugBountyTargetProfile,
    traditional_catalog: BenchmarkTargetProfileCatalog,
    traditional_adapter: RegisteredBenchmarkTargetFactoryAdapter,
    ai_selection: BenchmarkTargetProfileSelectionAuthority,
    ai_manifest: BenchmarkManifest,
    ai_profile: DockerAIRAGMCPTargetProfile,
    ai_catalog: BenchmarkTargetProfileCatalog,
    ai_adapter: RegisteredBenchmarkTargetFactoryAdapter,
) -> HybridTargetCompositionAuthority:
    """Build the only P0-D3 component order and declared bridge."""

    try:
        traditional = BenchmarkTargetProfileSelectionAuthority.model_validate(
            traditional_selection.model_dump(mode="json", by_alias=True)
        )
        ai = BenchmarkTargetProfileSelectionAuthority.model_validate(
            ai_selection.model_dump(mode="json", by_alias=True)
        )
        _require_component_source(
            traditional,
            manifest=BenchmarkManifest.model_validate(
                traditional_manifest.model_dump(mode="json", by_alias=True)
            ),
            profile=DockerBugBountyTargetProfile.model_validate(
                traditional_profile.model_dump(mode="json", by_alias=True)
            ),
            catalog=BenchmarkTargetProfileCatalog.model_validate(
                traditional_catalog.model_dump(mode="json", by_alias=True)
            ),
            adapter=RegisteredBenchmarkTargetFactoryAdapter.model_validate(
                traditional_adapter.model_dump(mode="json", by_alias=True)
            ),
        )
        _require_component_source(
            ai,
            manifest=BenchmarkManifest.model_validate(
                ai_manifest.model_dump(mode="json", by_alias=True)
            ),
            profile=DockerAIRAGMCPTargetProfile.model_validate(
                ai_profile.model_dump(mode="json", by_alias=True)
            ),
            catalog=BenchmarkTargetProfileCatalog.model_validate(
                ai_catalog.model_dump(mode="json", by_alias=True)
            ),
            adapter=RegisteredBenchmarkTargetFactoryAdapter.model_validate(
                ai_adapter.model_dump(mode="json", by_alias=True)
            ),
        )
        return HybridTargetCompositionAuthority(
            components=(
                HybridTargetComponent(
                    ordinal=1,
                    role="entry-traditional-web-api",
                    selection=traditional,
                ),
                HybridTargetComponent(
                    ordinal=2,
                    role="follow-on-ai-rag-mcp",
                    selection=ai,
                ),
            ),
            bridge=HybridTargetBridge(),
        )
    except (TypeError, ValueError) as exc:
        raise BenchmarkTargetCatalogError("Hybrid Target composition failed") from exc


def bind_hybrid_target_ground_truth(
    composition: HybridTargetCompositionAuthority,
    *,
    traditional_ground_truth: BenchmarkTargetGroundTruthBinding,
    ai_ground_truth: BenchmarkTargetGroundTruthBinding,
) -> HybridTargetGroundTruthBinding:
    """Bind exact private component cases without exposing them in the composition."""

    try:
        authoritative_composition = HybridTargetCompositionAuthority.model_validate(
            composition.model_dump(mode="json", by_alias=True)
        )
        bindings = (
            BenchmarkTargetGroundTruthBinding.model_validate(
                traditional_ground_truth.model_dump(mode="json", by_alias=True)
            ),
            BenchmarkTargetGroundTruthBinding.model_validate(
                ai_ground_truth.model_dump(mode="json", by_alias=True)
            ),
        )
        for component, binding in zip(
            authoritative_composition.components,
            bindings,
            strict=True,
        ):
            if (
                binding.registration != component.selection.registration
                or binding.binding_digest
                != component.selection.ground_truth_binding_digest
            ):
                raise ValueError("Hybrid private Ground Truth differs from component selection")
        return HybridTargetGroundTruthBinding(
            compositionDigest=authoritative_composition.composition_digest,
            bridgeDigest=authoritative_composition.bridge.bridge_digest,
            componentBindings=bindings,
        )
    except (TypeError, ValueError) as exc:
        raise BenchmarkTargetCatalogError("Hybrid Target Ground Truth binding failed") from exc


def select_hybrid_target_composition(
    composition: HybridTargetCompositionAuthority,
    ground_truth: HybridTargetGroundTruthBinding,
) -> HybridTargetSelectionAuthority:
    """Select the exact structural composition while permanently denying execution."""

    try:
        authoritative_composition = HybridTargetCompositionAuthority.model_validate(
            composition.model_dump(mode="json", by_alias=True)
        )
        authoritative_ground_truth = HybridTargetGroundTruthBinding.model_validate(
            ground_truth.model_dump(mode="json", by_alias=True)
        )
        if (
            authoritative_ground_truth.composition_digest
            != authoritative_composition.composition_digest
            or authoritative_ground_truth.bridge_digest
            != authoritative_composition.bridge.bridge_digest
            or any(
                binding.registration != component.selection.registration
                or binding.binding_digest
                != component.selection.ground_truth_binding_digest
                for component, binding in zip(
                    authoritative_composition.components,
                    authoritative_ground_truth.component_bindings,
                    strict=True,
                )
            )
        ):
            raise ValueError("Hybrid selection differs from private Ground Truth binding")
        return HybridTargetSelectionAuthority(
            composition=authoritative_composition,
            groundTruthBindingDigest=authoritative_ground_truth.binding_digest,
        )
    except (TypeError, ValueError) as exc:
        raise BenchmarkTargetCatalogError("Hybrid Target selection failed") from exc


def _require_exact_component_ground_truth(
    bindings: tuple[BenchmarkTargetGroundTruthBinding, ...],
) -> None:
    expected = (
        (
            "traditional-web-api",
            _TRADITIONAL_GT_ID,
            _TRADITIONAL_FINDING_ID,
            _TRADITIONAL_SURFACE_IDS,
            _TRADITIONAL_CHAIN_ID,
            _TRADITIONAL_MATCHER_ID,
            "1.0.0",
            TRADITIONAL_WEB_API_BOOLEAN_SQLI_MATCHER_DIGEST,
        ),
        (
            "ai-rag-mcp",
            _AI_GT_ID,
            _AI_FINDING_ID,
            _AI_SURFACE_IDS,
            _AI_CHAIN_ID,
            _AI_MATCHER_ID,
            "1.0.0",
            AI_RAG_MCP_DOCKER_MATCHER_DIGEST,
        ),
    )
    for binding, expected_case in zip(bindings, expected, strict=True):
        cases = binding.ground_truth.cases
        if len(cases) != 1:
            raise ValueError("Hybrid component Ground Truth cardinality differs")
        case = cases[0]
        actual = (
            binding.registration.target_family,
            case.ground_truth_id,
            case.expected_finding_id,
            tuple(case.surface_ids),
            case.chain_id,
            case.matcher_id,
            case.matcher_version,
            case.matcher_digest,
        )
        if actual != expected_case or case.visibility is not GroundTruthVisibility.SEEDED:
            raise ValueError("Hybrid component Ground Truth semantics differ")


def _require_component_source(
    selection: BenchmarkTargetProfileSelectionAuthority,
    *,
    manifest: BenchmarkManifest,
    profile: DockerBugBountyTargetProfile | DockerAIRAGMCPTargetProfile,
    catalog: BenchmarkTargetProfileCatalog,
    adapter: RegisteredBenchmarkTargetFactoryAdapter,
) -> None:
    registration = selection.registration
    if (
        catalog.catalog_id != selection.catalog_id
        or catalog.catalog_revision != selection.catalog_revision
        or catalog.catalog_digest != selection.catalog_digest
        or catalog.registrations != (registration,)
        or adapter.adapter_digest != selection.adapter_digest
        or adapter.target_factory_id != registration.target_factory_id
        or adapter.target_factory_version != registration.target_factory_version
        or adapter.target_factory_digest != registration.target_factory_digest
        or manifest.digest() != selection.manifest_digest
        or manifest.target_profile_id != registration.target_profile_id
        or manifest.target_profile_version != registration.target_profile_version
        or manifest.target_factory_id != registration.target_factory_id
        or manifest.target_factory_version != registration.target_factory_version
        or manifest.target_factory_digest != registration.target_factory_digest
        or manifest.ground_truth_digest != registration.ground_truth_digest
        or manifest.mutation_profile_id is not None
        or profile.profile_id != registration.target_profile_id
        or profile.profile_version != registration.target_profile_version
        or profile.target_factory_digest != registration.provider_profile_digest
        or profile.target_factory_digest != registration.target_factory_digest
    ):
        raise ValueError("Hybrid component source differs from selected authority")
