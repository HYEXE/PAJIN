"""AI-001A typed AI Surface classification without runtime authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import (
    DISCOVERY_API_VERSION,
    HTTPRAGSurfaceLocator,
    MCPPromptSurfaceLocator,
    MCPResourceSurfaceLocator,
    MCPResourceTemplateSurfaceLocator,
    MCPServerSurfaceLocator,
    MCPToolSurfaceLocator,
    MCPURLToolSurfaceLocator,
    ToolInterfaceSurfaceLocator,
)
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import (
    SECURITY_DOMAIN_TAXONOMY_API_VERSION,
    SecurityDomain,
    SecurityDomainClassificationRef,
    registered_security_domain_taxonomy,
)
from pajin.graph.domain_semantics import (
    MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
    SecurityDomainGraphTypeSetRef,
    registered_multi_domain_graph_semantics,
)

AI_SURFACE_LOCATOR_API_VERSION: Literal[
    "pajin.dev/ai-surface-locator/v1alpha1"
] = "pajin.dev/ai-surface-locator/v1alpha1"
AI_SURFACE_CLASSIFICATION_REGISTRY_API_VERSION: Literal[
    "pajin.dev/ai-surface-classification-registry/v1alpha1"
] = "pajin.dev/ai-surface-classification-registry/v1alpha1"
AI_SECURITY_SURFACE_API_VERSION: Literal[
    "pajin.dev/ai-security-surface/v1alpha1"
] = "pajin.dev/ai-security-surface/v1alpha1"

AI_SECURITY_SURFACE_TYPE: Literal["ai.model-rag-agent-tool"] = (
    "ai.model-rag-agent-tool"
)
AI_SECURITY_LOCATOR_SCHEMA: Literal[
    "pajin.locator.ai.model-rag-agent-tool.v1"
] = "pajin.locator.ai.model-rag-agent-tool.v1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_ProviderIdentifier = Annotated[
    str,
    Field(min_length=2, max_length=31, pattern=r"^[a-z0-9][a-z0-9-]{1,30}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SurfaceId = Annotated[str, Field(pattern=r"^ai-security-surface_[a-f0-9]{64}$")]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 512 * 1024
_MAX_TYPED_SURFACE_BYTES = 256 * 1024


class AISurfaceRegistryError(RuntimeError):
    """Raised when an exact AI Surface registry reference cannot be resolved."""


class AISurfaceClass(StrEnum):
    """Orthogonal AI knowledge classes; values grant no authority."""

    MODEL = "model"
    RAG = "rag"
    AGENT = "agent"
    MCP = "mcp"
    TOOL = "tool"


class AIModelSurfaceLocator(StrictModel):
    """Secret-free identity of one provider/model revision as inert knowledge."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    kind: Literal["ai-model"] = "ai-model"
    provider_id: _ProviderIdentifier = Field(alias="providerId")
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    model_revision: str = Field(alias="modelRevision", min_length=1, max_length=200)
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    secret_reference_embedded: Literal[False] = Field(
        default=False,
        alias="secretReferenceEmbedded",
    )

    @field_validator("model_id", "model_revision")
    @classmethod
    def require_safe_identity_text(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ValueError("AI model identity cannot contain surrounding or control whitespace")
        return value

    @field_validator("model_revision")
    @classmethod
    def reject_mutable_revision_aliases(cls, value: str) -> str:
        if value.casefold() in {"auto", "default", "latest"}:
            raise ValueError("AI model revision must be immutable")
        return value

    @field_validator("secret_reference_embedded", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI model secret marker must be a boolean")
        return value


class AIAgentSurfaceLocator(StrictModel):
    """Trace-compatible identity of one agent implementation and immutable inputs."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    kind: Literal["ai-agent"] = "ai-agent"
    agent_implementation_id: _Identifier = Field(alias="agentImplementationId")
    agent_implementation_version: str = Field(
        alias="agentImplementationVersion",
        min_length=1,
        max_length=200,
    )
    agent_implementation_digest: _Sha256 = Field(alias="agentImplementationDigest")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")
    model_revision: str = Field(alias="modelRevision", min_length=1, max_length=200)
    prompt_bundle_digest: _Sha256 = Field(alias="promptBundleDigest")
    tool_catalog_digest: _Sha256 = Field(alias="toolCatalogDigest")
    runtime_configuration_digest: _Sha256 = Field(alias="runtimeConfigurationDigest")

    @field_validator("agent_implementation_version", "model_revision")
    @classmethod
    def require_immutable_identity_text(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 0x20 or ord(character) == 0x7F for character in value
        ):
            raise ValueError("AI agent identity cannot contain surrounding or control whitespace")
        if value.casefold() in {"auto", "default", "latest"}:
            raise ValueError("AI agent identity revisions must be immutable")
        return value


AISecuritySurfaceLocator = Annotated[
    AIModelSurfaceLocator
    | HTTPRAGSurfaceLocator
    | AIAgentSurfaceLocator
    | MCPServerSurfaceLocator
    | MCPPromptSurfaceLocator
    | MCPResourceSurfaceLocator
    | MCPResourceTemplateSurfaceLocator
    | MCPToolSurfaceLocator
    | MCPURLToolSurfaceLocator
    | ToolInterfaceSurfaceLocator,
    Field(discriminator="kind"),
]

AISurfaceLocatorKind = Literal[
    "ai-model",
    "http-rag",
    "ai-agent",
    "mcp-server",
    "mcp-prompt",
    "mcp-resource",
    "mcp-resource-template",
    "mcp-tool",
    "mcp-url-tool",
    "tool-interface",
]


@dataclass(frozen=True, slots=True)
class _AILocatorSpec:
    locator_id: str
    locator_kind: AISurfaceLocatorKind
    surface_class: AISurfaceClass
    source_model_id: str
    existing_discovery_locator: bool


_AI_LOCATOR_SPECS = (
    _AILocatorSpec(
        "pajin.locator.ai.provider-model",
        "ai-model",
        AISurfaceClass.MODEL,
        "pajin.discovery.ai_surfaces.AIModelSurfaceLocator",
        False,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.rag-http-boundary",
        "http-rag",
        AISurfaceClass.RAG,
        "pajin.discovery.models.HTTPRAGSurfaceLocator",
        True,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.agent-implementation",
        "ai-agent",
        AISurfaceClass.AGENT,
        "pajin.discovery.ai_surfaces.AIAgentSurfaceLocator",
        False,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.mcp-server",
        "mcp-server",
        AISurfaceClass.MCP,
        "pajin.discovery.models.MCPServerSurfaceLocator",
        True,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.mcp-prompt",
        "mcp-prompt",
        AISurfaceClass.MCP,
        "pajin.discovery.models.MCPPromptSurfaceLocator",
        True,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.mcp-resource",
        "mcp-resource",
        AISurfaceClass.MCP,
        "pajin.discovery.models.MCPResourceSurfaceLocator",
        True,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.mcp-resource-template",
        "mcp-resource-template",
        AISurfaceClass.MCP,
        "pajin.discovery.models.MCPResourceTemplateSurfaceLocator",
        True,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.mcp-tool",
        "mcp-tool",
        AISurfaceClass.TOOL,
        "pajin.discovery.models.MCPToolSurfaceLocator",
        True,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.mcp-url-tool",
        "mcp-url-tool",
        AISurfaceClass.TOOL,
        "pajin.discovery.models.MCPURLToolSurfaceLocator",
        True,
    ),
    _AILocatorSpec(
        "pajin.locator.ai.tool-interface",
        "tool-interface",
        AISurfaceClass.TOOL,
        "pajin.discovery.models.ToolInterfaceSurfaceLocator",
        True,
    ),
)


class AISurfaceLocatorRef(StrictModel):
    """Exact content-addressed reference to one classified AI locator."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: AISurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: AISurfaceClass = Field(alias="surfaceClass")


class AISurfaceClassificationRegistryRef(StrictModel):
    """Exact reference to the complete AI-001A classification registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    registry_id: Literal["pajin.ai.surface-classification"] = Field(alias="registryId")
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")


class AISecuritySurfaceRef(StrictModel):
    """Exact reference to one inert typed AI Surface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["ai.model-rag-agent-tool"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.ai.model-rag-agent-tool.v1"] = Field(
        alias="locatorSchema"
    )
    surface_class: AISurfaceClass = Field(alias="surfaceClass")
    locator_kind: AISurfaceLocatorKind = Field(alias="locatorKind")
    classification_registry: AISurfaceClassificationRegistryRef = Field(
        alias="classificationRegistry"
    )


class RegisteredAISurfaceLocator(StrictModel):
    """One code-owned AI class-to-locator mapping with no discovery authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-surface-locator/v1alpha1"] = Field(
        default=AI_SURFACE_LOCATOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredAISurfaceLocator"] = "RegisteredAISurfaceLocator"
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: AISurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: AISurfaceClass = Field(alias="surfaceClass")
    source_model_id: _Identifier = Field(alias="sourceModelId")
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(
        alias="domainGraphTypeSet"
    )
    existing_discovery_locator: bool = Field(alias="existingDiscoveryLocator")
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    classification_only: Literal[True] = Field(default=True, alias="classificationOnly")
    discovery_authorized: Literal[False] = Field(default=False, alias="discoveryAuthorized")
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "existing_discovery_locator",
        "locator_schema_implementation_available",
        "classification_only",
        "discovery_authorized",
        "graph_admission_authorized",
        "tool_selection_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI locator classification markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _AI_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.surface_class,
                self.source_model_id,
                self.existing_discovery_locator,
            )
            != (
                spec.locator_kind,
                spec.surface_class,
                spec.source_model_id,
                spec.existing_discovery_locator,
            )
            or self.domain_classification != _ai_domain_classification()
            or self.domain_graph_type_set != _ai_graph_type_set()
        ):
            raise ValueError("AI Surface locator classification differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"locator_digest"},
        )
        canonical_json_bytes(
            material,
            label="AI Surface locator classification",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest("pajin.discovery.ai-surface-locator/v1", material)
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("AI Surface locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> AISurfaceLocatorRef:
        """Return the exact classification reference without authority transfer."""

        return AISurfaceLocatorRef(
            locatorId=self.locator_id,
            locatorVersion=self.locator_version,
            locatorDigest=self.locator_digest,
            locatorKind=self.locator_kind,
            surfaceClass=self.surface_class,
        )


class AISurfaceClassificationRegistry(StrictModel):
    """Complete model/RAG/agent/MCP/Tool classification with no runtime authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/ai-surface-classification-registry/v1alpha1"
    ] = Field(
        default=AI_SURFACE_CLASSIFICATION_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AISurfaceClassificationRegistry"] = "AISurfaceClassificationRegistry"
    registry_id: Literal["pajin.ai.surface-classification"] = Field(
        default="pajin.ai.surface-classification",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    security_domain_taxonomy_api_version: Literal[
        "pajin.dev/security-domain-taxonomy/v1alpha1"
    ] = Field(
        default=SECURITY_DOMAIN_TAXONOMY_API_VERSION,
        alias="securityDomainTaxonomyApiVersion",
    )
    security_domain_taxonomy_digest: _Sha256 = Field(
        alias="securityDomainTaxonomyDigest"
    )
    multi_domain_graph_semantics_api_version: Literal[
        "pajin.dev/multi-domain-graph-semantics/v1alpha1"
    ] = Field(
        default=MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
        alias="multiDomainGraphSemanticsApiVersion",
    )
    multi_domain_graph_semantics_digest: _Sha256 = Field(
        alias="multiDomainGraphSemanticsDigest"
    )
    discovery_api_version: Literal["pajin.dev/discovery/v1alpha1"] = Field(
        default=DISCOVERY_API_VERSION,
        alias="discoveryApiVersion",
    )
    surface_type: Literal["ai.model-rag-agent-tool"] = Field(
        default=AI_SECURITY_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.ai.model-rag-agent-tool.v1"] = Field(
        default=AI_SECURITY_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(
        alias="domainGraphTypeSet"
    )
    locators: tuple[RegisteredAISurfaceLocator, ...] = Field(
        min_length=len(_AI_LOCATOR_SPECS),
        max_length=len(_AI_LOCATOR_SPECS),
    )
    discovered_surface_initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="discoveredSurfaceInitialState",
    )
    registry_only: Literal[True] = Field(default=True, alias="registryOnly")
    discovery_wire_changed: Literal[False] = Field(
        default=False,
        alias="discoveryWireChanged",
    )
    attack_surface_wire_changed: Literal[False] = Field(
        default=False,
        alias="attackSurfaceWireChanged",
    )
    domain_semantics_registry_changed: Literal[False] = Field(
        default=False,
        alias="domainSemanticsRegistryChanged",
    )
    profile_selected: Literal[False] = Field(default=False, alias="profileSelected")
    discovery_authorized: Literal[False] = Field(default=False, alias="discoveryAuthorized")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "registry_only",
        "discovery_wire_changed",
        "attack_surface_wire_changed",
        "domain_semantics_registry_changed",
        "profile_selected",
        "discovery_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "permit_issuance_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "credential_access_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("AI Surface registry authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _ai_domain_classification()
            or self.domain_graph_type_set != _ai_graph_type_set()
            or self.locators != _registered_ai_surface_locators()
        ):
            raise ValueError("AI Surface classification registry differs from code authority")
        if tuple(dict.fromkeys(item.surface_class for item in self.locators)) != tuple(
            AISurfaceClass
        ):
            raise ValueError("AI Surface classes must be complete and canonically ordered")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        canonical_json_bytes(
            material,
            label="AI Surface classification registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest("pajin.discovery.ai-surface-registry/v1", material)
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("AI Surface classification registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> AISurfaceClassificationRegistryRef:
        """Return the exact complete registry reference."""

        return AISurfaceClassificationRegistryRef(
            registryId=self.registry_id,
            registryVersion=self.registry_version,
            registryDigest=self.registry_digest,
        )


class AISecuritySurface(StrictModel):
    """Typed AI knowledge that is neither observed nor Graph-admitted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/ai-security-surface/v1alpha1"] = Field(
        default=AI_SECURITY_SURFACE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AISecuritySurface"] = "AISecuritySurface"
    surface_id: str = Field(default="", alias="surfaceId", max_length=84)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["ai.model-rag-agent-tool"] = Field(
        default=AI_SECURITY_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.ai.model-rag-agent-tool.v1"] = Field(
        default=AI_SECURITY_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    surface_class: AISurfaceClass = Field(alias="surfaceClass")
    domain_classification: SecurityDomainClassificationRef = Field(
        alias="domainClassification"
    )
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(
        alias="domainGraphTypeSet"
    )
    classification_registry: AISurfaceClassificationRegistryRef = Field(
        alias="classificationRegistry"
    )
    locator: AISecuritySurfaceLocator
    initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="initialState",
    )
    typed_surface_only: Literal[True] = Field(default=True, alias="typedSurfaceOnly")
    discovery_observed: Literal[False] = Field(default=False, alias="discoveryObserved")
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    profile_selected: Literal[False] = Field(default=False, alias="profileSelected")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    tool_selection_authorized: Literal[False] = Field(
        default=False,
        alias="toolSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    runtime_support_asserted: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAsserted",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "typed_surface_only",
        "discovery_observed",
        "evidence_sealed",
        "graph_admitted",
        "profile_selected",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "credential_access_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed AI Surface authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_ai_surface_classification_registry()
        registered = next(
            (item for item in registry.locators if item.locator_kind == self.locator.kind),
            None,
        )
        if (
            self.domain_classification != _ai_domain_classification()
            or self.domain_graph_type_set != _ai_graph_type_set()
            or self.classification_registry != registry.reference()
            or registered is None
            or registered.surface_class is not self.surface_class
        ):
            raise ValueError("Typed AI Surface differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed AI Security Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest("pajin.discovery.ai-security-surface/v1", material)
        surface_id: _SurfaceId = f"ai-security-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed AI Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed AI Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> AISecuritySurfaceRef:
        """Return a content-addressed inert Surface reference."""

        return AISecuritySurfaceRef(
            surfaceId=self.surface_id,
            surfaceDigest=self.surface_digest,
            surfaceType=self.surface_type,
            locatorSchema=self.locator_schema,
            surfaceClass=self.surface_class,
            locatorKind=self.locator.kind,
            classificationRegistry=self.classification_registry,
        )


def registered_ai_surface_classification_registry() -> AISurfaceClassificationRegistry:
    """Return the complete AI-001A registry without discovery or execution authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return AISurfaceClassificationRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_ai_domain_classification(),
        domainGraphTypeSet=_ai_graph_type_set(),
        locators=_registered_ai_surface_locators(),
    )


def resolve_registered_ai_surface_locator(
    reference: AISurfaceLocatorRef,
) -> RegisteredAISurfaceLocator:
    """Resolve one exact AI class mapping without transferring authority."""

    for locator in registered_ai_surface_classification_registry().locators:
        if locator.reference() == reference:
            return locator.model_copy(deep=True)
    raise AISurfaceRegistryError("AI Surface locator is not registered exactly")


def resolve_ai_surface_classification_registry(
    reference: AISurfaceClassificationRegistryRef,
) -> AISurfaceClassificationRegistry:
    """Resolve the exact complete classification registry."""

    registry = registered_ai_surface_classification_registry()
    if registry.reference() == reference:
        return registry.model_copy(deep=True)
    raise AISurfaceRegistryError("AI Surface classification registry is not registered exactly")


def typed_ai_security_surface(*, locator: AISecuritySurfaceLocator) -> AISecuritySurface:
    """Classify one locator as inert registered-not-authorized AI knowledge."""

    registry = registered_ai_surface_classification_registry()
    registered = next(
        item for item in registry.locators if item.locator_kind == locator.kind
    )
    return AISecuritySurface(
        surfaceClass=registered.surface_class,
        domainClassification=_ai_domain_classification(),
        domainGraphTypeSet=_ai_graph_type_set(),
        classificationRegistry=registry.reference(),
        locator=locator.model_copy(deep=True),
    )


@cache
def _registered_ai_surface_locators() -> tuple[RegisteredAISurfaceLocator, ...]:
    return tuple(
        RegisteredAISurfaceLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            surfaceClass=spec.surface_class,
            sourceModelId=spec.source_model_id,
            domainClassification=_ai_domain_classification(),
            domainGraphTypeSet=_ai_graph_type_set(),
            existingDiscoveryLocator=spec.existing_discovery_locator,
        )
        for spec in _AI_LOCATOR_SPECS
    )


@cache
def _ai_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.AI
    )


@cache
def _ai_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.AI
    )
