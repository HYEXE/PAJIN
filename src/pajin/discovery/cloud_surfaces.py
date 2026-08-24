"""CLOUD-001A typed Cloud Surfaces without credential or provider authority."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from functools import cache
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.models import DISCOVERY_API_VERSION
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

CLOUD_ACCOUNT_RESOURCE_LOCATOR_API_VERSION: Literal[
    "pajin.dev/cloud-account-resource-locator/v1alpha1"
] = "pajin.dev/cloud-account-resource-locator/v1alpha1"
CLOUD_ACCOUNT_RESOURCE_LOCATOR_REGISTRY_API_VERSION: Literal[
    "pajin.dev/cloud-account-resource-locator-registry/v1alpha1"
] = "pajin.dev/cloud-account-resource-locator-registry/v1alpha1"
CLOUD_ACCOUNT_RESOURCE_SURFACE_API_VERSION: Literal[
    "pajin.dev/cloud-account-resource-surface/v1alpha1"
] = "pajin.dev/cloud-account-resource-surface/v1alpha1"

CLOUD_ACCOUNT_RESOURCE_SURFACE_TYPE: Literal["cloud.account-resource"] = "cloud.account-resource"
CLOUD_ACCOUNT_RESOURCE_LOCATOR_SCHEMA: Literal["pajin.locator.cloud.account-resource.v1"] = (
    "pajin.locator.cloud.account-resource.v1"
)

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_ProviderIdentifier = Annotated[
    str,
    Field(min_length=2, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]{1,62}$"),
]
_CloudCoordinate = Annotated[
    str,
    Field(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9.-]{0,99}$"),
]
_AccountOrProjectId = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_ResourceIdentity = Annotated[
    str,
    Field(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@+=,-]{0,511}$",
    ),
]
_ContainerIdentity = Annotated[
    str,
    Field(min_length=8, max_length=256, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,255}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_OCIImageDigest = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_SurfaceId = Annotated[
    str,
    Field(pattern=r"^cloud-account-resource-surface_[a-f0-9]{64}$"),
]
_MAX_LOCATOR_DEFINITION_BYTES = 64 * 1024
_MAX_LOCATOR_REGISTRY_BYTES = 256 * 1024
_MAX_TYPED_SURFACE_BYTES = 128 * 1024
_MUTABLE_IDENTITY_ALIASES = frozenset({"auto", "current", "default", "latest", "unknown"})


class CloudSurfaceRegistryError(RuntimeError):
    """Raised when an exact CLOUD-001A registry reference cannot be resolved."""


class CloudSurfaceClass(StrEnum):
    """Cloud knowledge classes; values grant no provider or credential authority."""

    ACCOUNT = "account"
    PROJECT = "project"
    RESOURCE = "resource"
    IAM = "iam"
    CONTAINER = "container"


class CloudIAMObjectKind(StrEnum):
    """Bounded IAM identity kinds without policy-content or effective-access claims."""

    PRINCIPAL = "principal"
    ROLE = "role"
    GROUP = "group"
    POLICY = "policy"
    BINDING = "binding"


class _SecretFreeCloudLocator(StrictModel):
    """Common negative markers for locator values that must never carry credentials."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    secret_reference_embedded: Literal[False] = Field(
        default=False,
        alias="secretReferenceEmbedded",
    )
    credential_reference_embedded: Literal[False] = Field(
        default=False,
        alias="credentialReferenceEmbedded",
    )

    @field_validator(
        "secret_reference_embedded",
        "credential_reference_embedded",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud locator secret markers must be booleans")
        return value


class CloudAccountSurfaceLocator(_SecretFreeCloudLocator):
    """One provider-partition account identity without registration or tenant authority."""

    kind: Literal["cloud-account"] = "cloud-account"
    provider_id: _ProviderIdentifier = Field(alias="providerId")
    provider_partition: _CloudCoordinate = Field(alias="providerPartition")
    account_id: _AccountOrProjectId = Field(alias="accountId")

    @field_validator("provider_id", "provider_partition", mode="before")
    @classmethod
    def canonicalize_provider_coordinate(cls, value: object) -> object:
        return _canonical_cloud_coordinate(value, label="Cloud provider coordinate")

    @field_validator("account_id")
    @classmethod
    def require_stable_account_id(cls, value: str) -> str:
        return _stable_cloud_identity(value, label="Cloud account ID")


class CloudProjectSurfaceLocator(_SecretFreeCloudLocator):
    """One exact project below one account, without ownership or access claims."""

    kind: Literal["cloud-project"] = "cloud-project"
    account: CloudAccountSurfaceLocator
    project_id: _AccountOrProjectId = Field(alias="projectId")

    @field_validator("project_id")
    @classmethod
    def require_stable_project_id(cls, value: str) -> str:
        return _stable_cloud_identity(value, label="Cloud project ID")


CloudAccountOrProjectSurfaceLocator = Annotated[
    CloudAccountSurfaceLocator | CloudProjectSurfaceLocator,
    Field(discriminator="kind"),
]


class CloudResourceSurfaceLocator(_SecretFreeCloudLocator):
    """One provider-local resource coordinate under an exact account or project."""

    kind: Literal["cloud-resource"] = "cloud-resource"
    parent: CloudAccountOrProjectSurfaceLocator
    service_id: _ProviderIdentifier = Field(alias="serviceId")
    location_id: _CloudCoordinate = Field(alias="locationId")
    resource_type: _CloudCoordinate = Field(alias="resourceType")
    resource_id: _ResourceIdentity = Field(alias="resourceId")

    @field_validator("service_id", "location_id", "resource_type", mode="before")
    @classmethod
    def canonicalize_resource_coordinate(cls, value: object) -> object:
        return _canonical_cloud_coordinate(value, label="Cloud resource coordinate")

    @field_validator("resource_id")
    @classmethod
    def require_stable_resource_id(cls, value: str) -> str:
        return _stable_cloud_identity(value, label="Cloud resource ID")


class CloudIAMSurfaceLocator(_SecretFreeCloudLocator):
    """One IAM object identity without policy content or effective-permission claims."""

    kind: Literal["cloud-iam"] = "cloud-iam"
    parent: CloudAccountOrProjectSurfaceLocator
    iam_object_kind: CloudIAMObjectKind = Field(alias="iamObjectKind")
    iam_id: _ResourceIdentity = Field(alias="iamId")

    @field_validator("iam_id")
    @classmethod
    def require_stable_iam_id(cls, value: str) -> str:
        return _stable_cloud_identity(value, label="Cloud IAM ID")


class CloudContainerSurfaceLocator(_SecretFreeCloudLocator):
    """One immutable runtime/container/image coordinate without container access."""

    kind: Literal["cloud-container"] = "cloud-container"
    parent: CloudAccountOrProjectSurfaceLocator
    orchestrator_id: _ProviderIdentifier = Field(alias="orchestratorId")
    runtime_scope_id: _ResourceIdentity = Field(alias="runtimeScopeId")
    namespace: _CloudCoordinate
    container_id: _ContainerIdentity = Field(alias="containerId")
    image_digest: _OCIImageDigest = Field(alias="imageDigest")

    @field_validator("orchestrator_id", mode="before")
    @classmethod
    def canonicalize_orchestrator_id(cls, value: object) -> object:
        return _canonical_cloud_coordinate(value, label="Cloud container orchestrator")

    @field_validator("namespace", mode="before")
    @classmethod
    def canonicalize_namespace(cls, value: object) -> object:
        return _canonical_cloud_coordinate(
            value,
            label="Cloud container namespace",
            mutable_aliases_allowed=True,
        )

    @field_validator("runtime_scope_id", "container_id")
    @classmethod
    def require_stable_container_identity(cls, value: str) -> str:
        return _stable_cloud_identity(value, label="Cloud container identity")


CloudAccountResourceSurfaceLocator = Annotated[
    CloudAccountSurfaceLocator
    | CloudProjectSurfaceLocator
    | CloudResourceSurfaceLocator
    | CloudIAMSurfaceLocator
    | CloudContainerSurfaceLocator,
    Field(discriminator="kind"),
]

CloudSurfaceLocatorKind = Literal[
    "cloud-account",
    "cloud-project",
    "cloud-resource",
    "cloud-iam",
    "cloud-container",
]
CloudParentRequirement = Literal["none", "account", "account-or-project"]


@dataclass(frozen=True, slots=True)
class _CloudLocatorSpec:
    locator_id: str
    locator_kind: CloudSurfaceLocatorKind
    surface_class: CloudSurfaceClass
    source_model_id: str
    parent_requirement: CloudParentRequirement
    location_required: bool
    iam_object_kind_required: bool
    image_digest_required: bool


_CLOUD_LOCATOR_SPECS = (
    _CloudLocatorSpec(
        "pajin.locator.cloud.account",
        "cloud-account",
        CloudSurfaceClass.ACCOUNT,
        "pajin.discovery.cloud_surfaces.CloudAccountSurfaceLocator",
        "none",
        False,
        False,
        False,
    ),
    _CloudLocatorSpec(
        "pajin.locator.cloud.project",
        "cloud-project",
        CloudSurfaceClass.PROJECT,
        "pajin.discovery.cloud_surfaces.CloudProjectSurfaceLocator",
        "account",
        False,
        False,
        False,
    ),
    _CloudLocatorSpec(
        "pajin.locator.cloud.resource",
        "cloud-resource",
        CloudSurfaceClass.RESOURCE,
        "pajin.discovery.cloud_surfaces.CloudResourceSurfaceLocator",
        "account-or-project",
        True,
        False,
        False,
    ),
    _CloudLocatorSpec(
        "pajin.locator.cloud.iam",
        "cloud-iam",
        CloudSurfaceClass.IAM,
        "pajin.discovery.cloud_surfaces.CloudIAMSurfaceLocator",
        "account-or-project",
        False,
        True,
        False,
    ),
    _CloudLocatorSpec(
        "pajin.locator.cloud.container",
        "cloud-container",
        CloudSurfaceClass.CONTAINER,
        "pajin.discovery.cloud_surfaces.CloudContainerSurfaceLocator",
        "account-or-project",
        False,
        False,
        True,
    ),
)


class CloudAccountResourceLocatorRef(StrictModel):
    """Exact content-addressed reference to one registered Cloud locator."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(alias="locatorVersion")
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    locator_kind: CloudSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: CloudSurfaceClass = Field(alias="surfaceClass")


class CloudAccountResourceLocatorRegistryRef(StrictModel):
    """Exact reference to the complete CLOUD-001A locator registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    registry_id: Literal["pajin.cloud.account-resource-locators"] = Field(alias="registryId")
    registry_version: Literal["1.0.0"] = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")


class CloudAccountResourceSurfaceRef(StrictModel):
    """Exact reference to one inert typed Cloud Surface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    surface_id: _SurfaceId = Field(alias="surfaceId")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    surface_type: Literal["cloud.account-resource"] = Field(alias="surfaceType")
    locator_schema: Literal["pajin.locator.cloud.account-resource.v1"] = Field(
        alias="locatorSchema"
    )
    surface_class: CloudSurfaceClass = Field(alias="surfaceClass")
    locator_kind: CloudSurfaceLocatorKind = Field(alias="locatorKind")
    locator_registry: CloudAccountResourceLocatorRegistryRef = Field(alias="locatorRegistry")


class RegisteredCloudAccountResourceLocator(StrictModel):
    """One code-owned Cloud locator mapping without inventory or credential authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-account-resource-locator/v1alpha1"] = Field(
        default=CLOUD_ACCOUNT_RESOURCE_LOCATOR_API_VERSION, alias="apiVersion"
    )
    kind: Literal["RegisteredCloudAccountResourceLocator"] = "RegisteredCloudAccountResourceLocator"
    locator_id: _Identifier = Field(alias="locatorId")
    locator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="locatorVersion")
    locator_digest: str = Field(default="", alias="locatorDigest", max_length=64)
    locator_kind: CloudSurfaceLocatorKind = Field(alias="locatorKind")
    surface_class: CloudSurfaceClass = Field(alias="surfaceClass")
    source_model_id: _Identifier = Field(alias="sourceModelId")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    parent_requirement: CloudParentRequirement = Field(alias="parentRequirement")
    location_required: bool = Field(alias="locationRequired")
    iam_object_kind_required: bool = Field(alias="iamObjectKindRequired")
    image_digest_required: bool = Field(alias="imageDigestRequired")
    secret_free: Literal[True] = Field(default=True, alias="secretFree")
    locator_schema_implementation_available: Literal[True] = Field(
        default=True,
        alias="locatorSchemaImplementationAvailable",
    )
    registration_only: Literal[True] = Field(default=True, alias="registrationOnly")
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    credential_lease_authorized: Literal[False] = Field(
        default=False,
        alias="credentialLeaseAuthorized",
    )
    inventory_authorized: Literal[False] = Field(
        default=False,
        alias="inventoryAuthorized",
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
        "location_required",
        "iam_object_kind_required",
        "image_digest_required",
        "secret_free",
        "locator_schema_implementation_available",
        "registration_only",
        "provider_selection_authorized",
        "credential_lease_authorized",
        "inventory_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud locator registry markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registered_locator(self) -> Self:
        spec = next(
            (item for item in _CLOUD_LOCATOR_SPECS if item.locator_id == self.locator_id),
            None,
        )
        if (
            spec is None
            or (
                self.locator_kind,
                self.surface_class,
                self.source_model_id,
                self.parent_requirement,
                self.location_required,
                self.iam_object_kind_required,
                self.image_digest_required,
            )
            != (
                spec.locator_kind,
                spec.surface_class,
                spec.source_model_id,
                spec.parent_requirement,
                spec.location_required,
                spec.iam_object_kind_required,
                spec.image_digest_required,
            )
            or self.domain_classification != _cloud_domain_classification()
            or self.domain_graph_type_set != _cloud_graph_type_set()
        ):
            raise ValueError("Cloud account/resource locator differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"locator_digest"},
        )
        canonical_json_bytes(
            material,
            label="Cloud account/resource locator definition",
            max_bytes=_MAX_LOCATOR_DEFINITION_BYTES,
        )
        digest = discovery_digest("pajin.discovery.cloud-account-resource-locator/v1", material)
        if self.locator_digest and self.locator_digest != digest:
            raise ValueError("Cloud account/resource locator Digest differs")
        object.__setattr__(self, "locator_digest", digest)
        return self

    def reference(self) -> CloudAccountResourceLocatorRef:
        """Return the exact locator reference without authority transfer."""

        return CloudAccountResourceLocatorRef(
            locatorId=self.locator_id,
            locatorVersion=self.locator_version,
            locatorDigest=self.locator_digest,
            locatorKind=self.locator_kind,
            surfaceClass=self.surface_class,
        )


class CloudAccountResourceLocatorRegistry(StrictModel):
    """Complete account/project/resource/IAM/container registry without runtime authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-account-resource-locator-registry/v1alpha1"] = Field(
        default=CLOUD_ACCOUNT_RESOURCE_LOCATOR_REGISTRY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudAccountResourceLocatorRegistry"] = "CloudAccountResourceLocatorRegistry"
    registry_id: Literal["pajin.cloud.account-resource-locators"] = Field(
        default="pajin.cloud.account-resource-locators",
        alias="registryId",
    )
    registry_version: Literal["1.0.0"] = Field(default="1.0.0", alias="registryVersion")
    registry_digest: str = Field(default="", alias="registryDigest", max_length=64)
    security_domain_taxonomy_api_version: Literal["pajin.dev/security-domain-taxonomy/v1alpha1"] = (
        Field(
            default=SECURITY_DOMAIN_TAXONOMY_API_VERSION,
            alias="securityDomainTaxonomyApiVersion",
        )
    )
    security_domain_taxonomy_digest: _Sha256 = Field(alias="securityDomainTaxonomyDigest")
    multi_domain_graph_semantics_api_version: Literal[
        "pajin.dev/multi-domain-graph-semantics/v1alpha1"
    ] = Field(
        default=MULTI_DOMAIN_GRAPH_SEMANTICS_API_VERSION,
        alias="multiDomainGraphSemanticsApiVersion",
    )
    multi_domain_graph_semantics_digest: _Sha256 = Field(alias="multiDomainGraphSemanticsDigest")
    discovery_api_version: Literal["pajin.dev/discovery/v1alpha1"] = Field(
        default=DISCOVERY_API_VERSION,
        alias="discoveryApiVersion",
    )
    surface_type: Literal["cloud.account-resource"] = Field(
        default=CLOUD_ACCOUNT_RESOURCE_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.cloud.account-resource.v1"] = Field(
        default=CLOUD_ACCOUNT_RESOURCE_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locators: tuple[RegisteredCloudAccountResourceLocator, ...] = Field(
        min_length=len(_CLOUD_LOCATOR_SPECS),
        max_length=len(_CLOUD_LOCATOR_SPECS),
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
    discovery_authorized: Literal[False] = Field(default=False, alias="discoveryAuthorized")
    inventory_authorized: Literal[False] = Field(default=False, alias="inventoryAuthorized")
    policy_read_authorized: Literal[False] = Field(
        default=False,
        alias="policyReadAuthorized",
    )
    policy_evaluation_authorized: Literal[False] = Field(
        default=False,
        alias="policyEvaluationAuthorized",
    )
    credential_lease_authorized: Literal[False] = Field(
        default=False,
        alias="credentialLeaseAuthorized",
    )
    ambient_credential_authorized: Literal[False] = Field(
        default=False,
        alias="ambientCredentialAuthorized",
    )
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
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
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
    container_access_authorized: Literal[False] = Field(
        default=False,
        alias="containerAccessAuthorized",
    )
    resource_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="resourceMutationAuthorized",
    )
    iam_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="iamMutationAuthorized",
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
        "discovery_authorized",
        "inventory_authorized",
        "policy_read_authorized",
        "policy_evaluation_authorized",
        "credential_lease_authorized",
        "ambient_credential_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "permit_issuance_authorized",
        "provider_selection_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "container_access_authorized",
        "resource_mutation_authorized",
        "iam_mutation_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud locator registry authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_registry(self) -> Self:
        taxonomy = registered_security_domain_taxonomy()
        graph_semantics = registered_multi_domain_graph_semantics()
        if (
            self.security_domain_taxonomy_digest != taxonomy.taxonomy_digest
            or self.multi_domain_graph_semantics_digest != graph_semantics.registry_digest
            or self.domain_classification != _cloud_domain_classification()
            or self.domain_graph_type_set != _cloud_graph_type_set()
            or self.locators != _registered_cloud_locators()
            or tuple(item.surface_class for item in self.locators) != tuple(CloudSurfaceClass)
        ):
            raise ValueError("Cloud account/resource locator registry differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"registry_digest"},
        )
        canonical_json_bytes(
            material,
            label="Cloud account/resource locator registry",
            max_bytes=_MAX_LOCATOR_REGISTRY_BYTES,
        )
        digest = discovery_digest("pajin.discovery.cloud-account-resource-registry/v1", material)
        if self.registry_digest and self.registry_digest != digest:
            raise ValueError("Cloud account/resource locator registry Digest differs")
        object.__setattr__(self, "registry_digest", digest)
        return self

    def reference(self) -> CloudAccountResourceLocatorRegistryRef:
        """Return the exact complete registry reference."""

        return CloudAccountResourceLocatorRegistryRef(
            registryId=self.registry_id,
            registryVersion=self.registry_version,
            registryDigest=self.registry_digest,
        )


class CloudAccountResourceSurface(StrictModel):
    """Typed Cloud knowledge that is neither inventoried nor Graph-admitted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-account-resource-surface/v1alpha1"] = Field(
        default=CLOUD_ACCOUNT_RESOURCE_SURFACE_API_VERSION, alias="apiVersion"
    )
    kind: Literal["CloudAccountResourceSurface"] = "CloudAccountResourceSurface"
    surface_id: str = Field(default="", alias="surfaceId", max_length=95)
    surface_digest: str = Field(default="", alias="surfaceDigest", max_length=64)
    surface_type: Literal["cloud.account-resource"] = Field(
        default=CLOUD_ACCOUNT_RESOURCE_SURFACE_TYPE,
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.cloud.account-resource.v1"] = Field(
        default=CLOUD_ACCOUNT_RESOURCE_LOCATOR_SCHEMA,
        alias="locatorSchema",
    )
    surface_class: CloudSurfaceClass = Field(alias="surfaceClass")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    domain_graph_type_set: SecurityDomainGraphTypeSetRef = Field(alias="domainGraphTypeSet")
    locator_registry: CloudAccountResourceLocatorRegistryRef = Field(alias="locatorRegistry")
    locator: CloudAccountResourceSurfaceLocator
    initial_state: Literal["registered-not-authorized"] = Field(
        default="registered-not-authorized",
        alias="initialState",
    )
    typed_surface_only: Literal[True] = Field(default=True, alias="typedSurfaceOnly")
    discovery_observed: Literal[False] = Field(default=False, alias="discoveryObserved")
    resource_existence_verified: Literal[False] = Field(
        default=False,
        alias="resourceExistenceVerified",
    )
    iam_policy_verified: Literal[False] = Field(default=False, alias="iamPolicyVerified")
    container_runtime_verified: Literal[False] = Field(
        default=False,
        alias="containerRuntimeVerified",
    )
    provider_registration_asserted: Literal[False] = Field(
        default=False,
        alias="providerRegistrationAsserted",
    )
    tenant_authority_asserted: Literal[False] = Field(
        default=False,
        alias="tenantAuthorityAsserted",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
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
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    inventory_authorized: Literal[False] = Field(default=False, alias="inventoryAuthorized")
    policy_read_authorized: Literal[False] = Field(
        default=False,
        alias="policyReadAuthorized",
    )
    policy_evaluation_authorized: Literal[False] = Field(
        default=False,
        alias="policyEvaluationAuthorized",
    )
    credential_lease_authorized: Literal[False] = Field(
        default=False,
        alias="credentialLeaseAuthorized",
    )
    ambient_credential_authorized: Literal[False] = Field(
        default=False,
        alias="ambientCredentialAuthorized",
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
    container_access_authorized: Literal[False] = Field(
        default=False,
        alias="containerAccessAuthorized",
    )
    resource_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="resourceMutationAuthorized",
    )
    iam_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="iamMutationAuthorized",
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
        "resource_existence_verified",
        "iam_policy_verified",
        "container_runtime_verified",
        "provider_registration_asserted",
        "tenant_authority_asserted",
        "evidence_sealed",
        "graph_admitted",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "provider_selection_authorized",
        "inventory_authorized",
        "policy_read_authorized",
        "policy_evaluation_authorized",
        "credential_lease_authorized",
        "ambient_credential_authorized",
        "tool_selection_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "container_access_authorized",
        "resource_mutation_authorized",
        "iam_mutation_authorized",
        "runtime_support_asserted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Typed Cloud Surface authority markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_typed_surface(self) -> Self:
        registry = registered_cloud_account_resource_locator_registry()
        registered = next(
            (item for item in registry.locators if item.locator_kind == self.locator.kind),
            None,
        )
        if (
            self.domain_classification != _cloud_domain_classification()
            or self.domain_graph_type_set != _cloud_graph_type_set()
            or self.locator_registry != registry.reference()
            or registered is None
            or registered.surface_class is not self.surface_class
        ):
            raise ValueError("Typed Cloud account/resource Surface differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"surface_id", "surface_digest"},
        )
        canonical_json_bytes(
            material,
            label="Typed Cloud account/resource Surface",
            max_bytes=_MAX_TYPED_SURFACE_BYTES,
        )
        digest = discovery_digest("pajin.discovery.cloud-account-resource-surface/v1", material)
        surface_id: _SurfaceId = f"cloud-account-resource-surface_{digest}"
        if self.surface_digest and self.surface_digest != digest:
            raise ValueError("Typed Cloud Surface Digest differs")
        if self.surface_id and self.surface_id != surface_id:
            raise ValueError("Typed Cloud Surface ID differs")
        object.__setattr__(self, "surface_digest", digest)
        object.__setattr__(self, "surface_id", surface_id)
        return self

    def reference(self) -> CloudAccountResourceSurfaceRef:
        """Return a content-addressed inert Surface reference."""

        return CloudAccountResourceSurfaceRef(
            surfaceId=self.surface_id,
            surfaceDigest=self.surface_digest,
            surfaceType=self.surface_type,
            locatorSchema=self.locator_schema,
            surfaceClass=self.surface_class,
            locatorKind=self.locator.kind,
            locatorRegistry=self.locator_registry,
        )


def registered_cloud_account_resource_locator_registry() -> CloudAccountResourceLocatorRegistry:
    """Return the CLOUD-001A registry without inventory or credential authority."""

    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    return CloudAccountResourceLocatorRegistry(
        securityDomainTaxonomyDigest=taxonomy.taxonomy_digest,
        multiDomainGraphSemanticsDigest=graph_semantics.registry_digest,
        domainClassification=_cloud_domain_classification(),
        domainGraphTypeSet=_cloud_graph_type_set(),
        locators=_registered_cloud_locators(),
    )


def resolve_registered_cloud_account_resource_locator(
    reference: CloudAccountResourceLocatorRef,
) -> RegisteredCloudAccountResourceLocator:
    """Resolve one exact Cloud locator without transferring authority."""

    for locator in registered_cloud_account_resource_locator_registry().locators:
        if locator.reference() == reference:
            return locator.model_copy(deep=True)
    raise CloudSurfaceRegistryError("Cloud account/resource locator is not registered exactly")


def resolve_cloud_account_resource_locator_registry(
    reference: CloudAccountResourceLocatorRegistryRef,
) -> CloudAccountResourceLocatorRegistry:
    """Resolve the exact complete Cloud registry without activating runtime behavior."""

    registry = registered_cloud_account_resource_locator_registry()
    if registry.reference() == reference:
        return registry.model_copy(deep=True)
    raise CloudSurfaceRegistryError(
        "Cloud account/resource locator registry is not registered exactly"
    )


def typed_cloud_account_resource_surface(
    *,
    locator: CloudAccountResourceSurfaceLocator,
) -> CloudAccountResourceSurface:
    """Type a locator as inert registered-not-authorized Cloud knowledge."""

    registry = registered_cloud_account_resource_locator_registry()
    registered = next(item for item in registry.locators if item.locator_kind == locator.kind)
    return CloudAccountResourceSurface(
        surfaceClass=registered.surface_class,
        domainClassification=_cloud_domain_classification(),
        domainGraphTypeSet=_cloud_graph_type_set(),
        locatorRegistry=registry.reference(),
        locator=locator.model_copy(deep=True),
    )


def cloud_account_surface_locator(
    *,
    provider_id: str,
    provider_partition: str,
    account_id: str,
) -> CloudAccountSurfaceLocator:
    """Build one provider-partition account locator without provider access."""

    return CloudAccountSurfaceLocator(
        providerId=provider_id,
        providerPartition=provider_partition,
        accountId=account_id,
    )


def cloud_project_surface_locator(
    *,
    account: CloudAccountSurfaceLocator,
    project_id: str,
) -> CloudProjectSurfaceLocator:
    """Build one project under an exact account without ownership claims."""

    return CloudProjectSurfaceLocator(
        account=account.model_copy(deep=True),
        projectId=project_id,
    )


def cloud_resource_surface_locator(
    *,
    parent: CloudAccountOrProjectSurfaceLocator,
    service_id: str,
    location_id: str,
    resource_type: str,
    resource_id: str,
) -> CloudResourceSurfaceLocator:
    """Build one exact provider-local resource locator without inventory access."""

    return CloudResourceSurfaceLocator(
        parent=parent.model_copy(deep=True),
        serviceId=service_id,
        locationId=location_id,
        resourceType=resource_type,
        resourceId=resource_id,
    )


def cloud_iam_surface_locator(
    *,
    parent: CloudAccountOrProjectSurfaceLocator,
    iam_object_kind: CloudIAMObjectKind,
    iam_id: str,
) -> CloudIAMSurfaceLocator:
    """Build one IAM object locator without reading or evaluating policy."""

    return CloudIAMSurfaceLocator(
        parent=parent.model_copy(deep=True),
        iamObjectKind=iam_object_kind,
        iamId=iam_id,
    )


def cloud_container_surface_locator(
    *,
    parent: CloudAccountOrProjectSurfaceLocator,
    orchestrator_id: str,
    runtime_scope_id: str,
    namespace: str,
    container_id: str,
    image_digest: str,
) -> CloudContainerSurfaceLocator:
    """Build an immutable container/image coordinate without runtime access."""

    return CloudContainerSurfaceLocator(
        parent=parent.model_copy(deep=True),
        orchestratorId=orchestrator_id,
        runtimeScopeId=runtime_scope_id,
        namespace=namespace,
        containerId=container_id,
        imageDigest=image_digest,
    )


@cache
def _registered_cloud_locators() -> tuple[RegisteredCloudAccountResourceLocator, ...]:
    return tuple(
        RegisteredCloudAccountResourceLocator(
            locatorId=spec.locator_id,
            locatorKind=spec.locator_kind,
            surfaceClass=spec.surface_class,
            sourceModelId=spec.source_model_id,
            domainClassification=_cloud_domain_classification(),
            domainGraphTypeSet=_cloud_graph_type_set(),
            parentRequirement=spec.parent_requirement,
            locationRequired=spec.location_required,
            iamObjectKindRequired=spec.iam_object_kind_required,
            imageDigestRequired=spec.image_digest_required,
        )
        for spec in _CLOUD_LOCATOR_SPECS
    )


@cache
def _cloud_domain_classification() -> SecurityDomainClassificationRef:
    taxonomy = registered_security_domain_taxonomy()
    return next(
        item.reference() for item in taxonomy.domains if item.domain is SecurityDomain.CLOUD
    )


@cache
def _cloud_graph_type_set() -> SecurityDomainGraphTypeSetRef:
    semantics = registered_multi_domain_graph_semantics()
    return next(
        item.reference()
        for item in semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.CLOUD
    )


def _canonical_cloud_coordinate(
    value: object,
    *,
    label: str,
    mutable_aliases_allowed: bool = False,
) -> object:
    if not isinstance(value, str):
        return value
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError(f"{label} cannot contain surrounding or control whitespace")
    canonical = value.lower()
    if not mutable_aliases_allowed and canonical in _MUTABLE_IDENTITY_ALIASES:
        raise ValueError(f"{label} must be an explicit stable identifier")
    return canonical


def _stable_cloud_identity(value: str, *, label: str) -> str:
    if value != value.strip() or any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    ):
        raise ValueError(f"{label} cannot contain surrounding or control whitespace")
    if value.casefold() in _MUTABLE_IDENTITY_ALIASES:
        raise ValueError(f"{label} must be immutable")
    if "://" in value or any(character in value for character in "?#\\*"):
        raise ValueError(f"{label} cannot contain URL, query, fragment, or wildcard syntax")
    return value


__all__ = [
    "CLOUD_ACCOUNT_RESOURCE_LOCATOR_API_VERSION",
    "CLOUD_ACCOUNT_RESOURCE_LOCATOR_REGISTRY_API_VERSION",
    "CLOUD_ACCOUNT_RESOURCE_LOCATOR_SCHEMA",
    "CLOUD_ACCOUNT_RESOURCE_SURFACE_API_VERSION",
    "CLOUD_ACCOUNT_RESOURCE_SURFACE_TYPE",
    "CloudAccountOrProjectSurfaceLocator",
    "CloudAccountResourceLocatorRef",
    "CloudAccountResourceLocatorRegistry",
    "CloudAccountResourceLocatorRegistryRef",
    "CloudAccountResourceSurface",
    "CloudAccountResourceSurfaceLocator",
    "CloudAccountResourceSurfaceRef",
    "CloudAccountSurfaceLocator",
    "CloudContainerSurfaceLocator",
    "CloudIAMObjectKind",
    "CloudIAMSurfaceLocator",
    "CloudParentRequirement",
    "CloudProjectSurfaceLocator",
    "CloudResourceSurfaceLocator",
    "CloudSurfaceClass",
    "CloudSurfaceLocatorKind",
    "CloudSurfaceRegistryError",
    "RegisteredCloudAccountResourceLocator",
    "cloud_account_surface_locator",
    "cloud_container_surface_locator",
    "cloud_iam_surface_locator",
    "cloud_project_surface_locator",
    "cloud_resource_surface_locator",
    "registered_cloud_account_resource_locator_registry",
    "resolve_cloud_account_resource_locator_registry",
    "resolve_registered_cloud_account_resource_locator",
    "typed_cloud_account_resource_surface",
]
