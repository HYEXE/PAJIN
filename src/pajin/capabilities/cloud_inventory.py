"""CLOUD-001B read-only Cloud inventory/policy preparation boundaries."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from functools import cache
from hashlib import sha256
from ipaddress import ip_address
from typing import Annotated, ClassVar, Literal, Self, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import ConfigDict, Field, JsonValue, ValidationError, field_validator, model_validator

from pajin.capabilities.activation import (
    PreparedCapabilityAction,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.adapters import (
    ToolCapabilityRegistration,
    capability_definition_from_tool,
    registered_action_capability,
)
from pajin.capabilities.authorities import (
    CapabilityAuthorityAdapter,
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
    CodeBackedCapabilityRef,
    RegisteredCapabilityAuthority,
)
from pajin.capabilities.domain_projection import CapabilityDomainClassificationRef
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleError,
    CapabilityLifecycleRegistry,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityUseProfile,
    ResolvedCapabilityRelease,
)
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.capabilities.scaffold import capability_parameter_schema_digest
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    RegisteredDomainWorkerBoundaryProfile,
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    registered_domain_worker_boundary_profiles,
)
from pajin.discovery.cloud_surfaces import (
    CloudAccountResourceLocatorRef,
    CloudAccountResourceLocatorRegistryRef,
    CloudAccountResourceSurface,
    CloudAccountResourceSurfaceRef,
    CloudAccountSurfaceLocator,
    CloudContainerSurfaceLocator,
    CloudIAMSurfaceLocator,
    CloudProjectSurfaceLocator,
    CloudResourceSurfaceLocator,
    CloudSurfaceClass,
    CloudSurfaceLocatorKind,
    registered_cloud_account_resource_locator_registry,
)
from pajin.domain.models import (
    CampaignManifest,
    Scope,
    StrictModel,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.domain.security_domain import SecurityDomain, SecurityDomainClassificationRef
from pajin.graph.authority import (
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    RegisteredActionCapability,
)
from pajin.policy.scope import (
    InvalidScopeURL,
    normalize_scope_pattern,
    normalize_target_url,
    scope_matches,
)
from pajin.runtime.secrets import SecretBroker, SecretLease, SecretLeaseStatus
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import Tool, ToolRegistry, ToolSpec

CLOUD_READ_ONLY_CAPABILITY_ADAPTER_VERSION = "pajin.cloud-read-only-capability-adapter/v1"
CLOUD_READ_ONLY_CAPABILITY_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/cloud-read-only-capability-activation-set/v1alpha1"
] = "pajin.dev/cloud-read-only-capability-activation-set/v1alpha1"
CLOUD_READ_ONLY_BINDING_API_VERSION: Literal[
    "pajin.dev/cloud-read-only-inventory-policy-binding/v1alpha1"
] = "pajin.dev/cloud-read-only-inventory-policy-binding/v1alpha1"
CLOUD_READ_ONLY_PREPARATION_API_VERSION: Literal[
    "pajin.dev/cloud-read-only-inventory-policy-preparation/v1alpha1"
] = "pajin.dev/cloud-read-only-inventory-policy-preparation/v1alpha1"
CLOUD_CAMPAIGN_SCOPE_BINDING_API_VERSION: Literal[
    "pajin.dev/cloud-campaign-scope-binding/v1alpha1"
] = "pajin.dev/cloud-campaign-scope-binding/v1alpha1"
CLOUD_PROVIDER_ADAPTER_API_VERSION: Literal[
    "pajin.dev/cloud-read-only-provider-adapter/v1alpha1"
] = "pajin.dev/cloud-read-only-provider-adapter/v1alpha1"
CLOUD_PROVIDER_ROUTE_API_VERSION: Literal["pajin.dev/cloud-read-only-provider-route/v1alpha1"] = (
    "pajin.dev/cloud-read-only-provider-route/v1alpha1"
)
CLOUD_CREDENTIAL_LEASE_REFERENCE_API_VERSION: Literal[
    "pajin.dev/cloud-credential-lease-reference/v1alpha1"
] = "pajin.dev/cloud-credential-lease-reference/v1alpha1"
CLOUD_PROVIDER_READ_REQUEST_API_VERSION: Literal[
    "pajin.dev/cloud-provider-read-request/v1alpha1"
] = "pajin.dev/cloud-provider-read-request/v1alpha1"
CLOUD_READ_ONLY_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/cloud-read-only-capability-domain-classification/v1alpha1"
] = "pajin.dev/cloud-read-only-capability-domain-classification/v1alpha1"

CLOUD_READ_ONLY_CAPABILITY_ID = "pajin.cloud.read-only-inventory-policy"
CLOUD_READ_ONLY_CAPABILITY_VERSION = "1.0.0"
CLOUD_READ_ONLY_TOOL_ID = "cloud.read-only-inventory-policy"
CLOUD_SURFACE_SCOPE_ORIGIN = "https://cloud-scope.pajin.invalid"
CLOUD_CREDENTIAL_BINDING = "cloud-provider-credential"

_AUTHORITY_VERSION = "1.0.0"
_MAX_CREDENTIAL_TTL_SECONDS = 60
_MAX_RUNTIME_SECONDS = 60
_MAX_PROVIDER_RESPONSE_BYTES = 1_048_576
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SecretFingerprint = Annotated[str, Field(pattern=r"^[a-f0-9]{16}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_ProviderIdentifier = Annotated[
    str,
    Field(min_length=2, max_length=63, pattern=r"^[a-z0-9][a-z0-9-]{1,62}$"),
]


class CloudReadOnlyCapabilityError(ValueError):
    """Raised when CLOUD-001B identity, lease, Scope, or preparation drifts."""


class CloudReadOnlyOperation(StrEnum):
    """The only provider operations admitted by the first Cloud slice."""

    INVENTORY = "inventory-read"
    POLICY = "policy-read"


class CloudReadOnlyProviderRoute(StrictModel):
    """One exact Surface-to-GET route with no write or redirect semantics."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-read-only-provider-route/v1alpha1"] = Field(
        default=CLOUD_PROVIDER_ROUTE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudReadOnlyProviderRoute"] = "CloudReadOnlyProviderRoute"
    route_digest: str = Field(default="", alias="routeDigest", max_length=64)
    operation: CloudReadOnlyOperation
    surface: CloudAccountResourceSurfaceRef
    target: str = Field(min_length=9, max_length=2_000)
    method: Literal["GET"] = "GET"
    max_response_bytes: int = Field(
        default=262_144,
        alias="maxResponseBytes",
        ge=1_024,
        le=_MAX_PROVIDER_RESPONSE_BYTES,
    )
    request_body_allowed: Literal[False] = Field(
        default=False,
        alias="requestBodyAllowed",
    )
    redirects_allowed: Literal[False] = Field(default=False, alias="redirectsAllowed")
    resource_mutation_allowed: Literal[False] = Field(
        default=False,
        alias="resourceMutationAllowed",
    )
    policy_mutation_allowed: Literal[False] = Field(
        default=False,
        alias="policyMutationAllowed",
    )

    @field_validator("max_response_bytes", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Cloud provider route budget must be an integer")
        return value

    @field_validator(
        "request_body_allowed",
        "redirects_allowed",
        "resource_mutation_allowed",
        "policy_mutation_allowed",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud provider route markers must be booleans")
        return value

    @field_validator("target")
    @classmethod
    def require_canonical_target(cls, value: str) -> str:
        return _canonical_provider_target(value)

    @model_validator(mode="after")
    def bind_route(self) -> Self:
        if self.operation is CloudReadOnlyOperation.POLICY and (
            self.surface.surface_class is not CloudSurfaceClass.IAM
            or self.surface.locator_kind != "cloud-iam"
        ):
            raise ValueError("Cloud policy read requires an exact IAM Surface")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"route_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cloud-provider-route/v1",
            material,
        )
        if self.route_digest and self.route_digest != digest:
            raise ValueError("Cloud provider route digest differs")
        object.__setattr__(self, "route_digest", digest)
        return self


class CloudReadOnlyProviderAdapterRef(StrictModel):
    """Exact non-secret reference to one explicitly supplied provider adapter."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    adapter_id: _Identifier = Field(alias="adapterId")
    adapter_version: Literal["1.0.0"] = Field(alias="adapterVersion")
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    provider_id: _ProviderIdentifier = Field(alias="providerId")
    provider_partition: _ProviderIdentifier = Field(alias="providerPartition")


class CloudReadOnlyProviderAdapterDefinition(StrictModel):
    """Bounded provider request mapping; it is not a provider client or selector."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-read-only-provider-adapter/v1alpha1"] = Field(
        default=CLOUD_PROVIDER_ADAPTER_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudReadOnlyProviderAdapterDefinition"] = (
        "CloudReadOnlyProviderAdapterDefinition"
    )
    adapter_id: _Identifier = Field(alias="adapterId")
    adapter_version: Literal["1.0.0"] = Field(default="1.0.0", alias="adapterVersion")
    adapter_digest: str = Field(default="", alias="adapterDigest", max_length=64)
    provider_id: _ProviderIdentifier = Field(alias="providerId")
    provider_partition: _ProviderIdentifier = Field(alias="providerPartition")
    endpoint_origin: str = Field(alias="endpointOrigin", min_length=9, max_length=512)
    credential_audience: _Identifier = Field(alias="credentialAudience")
    credential_binding: Literal["cloud-provider-credential"] = Field(
        default="cloud-provider-credential",
        alias="credentialBinding",
    )
    max_credential_ttl_seconds: int = Field(
        default=60,
        alias="maxCredentialTtlSeconds",
        ge=1,
        le=_MAX_CREDENTIAL_TTL_SECONDS,
    )
    max_runtime_seconds: int = Field(
        default=30,
        alias="maxRuntimeSeconds",
        ge=1,
        le=_MAX_RUNTIME_SECONDS,
    )
    routes: tuple[CloudReadOnlyProviderRoute, ...] = Field(min_length=1, max_length=100)
    explicit_registration_required: Literal[True] = Field(
        default=True,
        alias="explicitRegistrationRequired",
    )
    request_adaptation_only: Literal[True] = Field(
        default=True,
        alias="requestAdaptationOnly",
    )
    ambient_credential_allowed: Literal[False] = Field(
        default=False,
        alias="ambientCredentialAllowed",
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    provider_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="providerInvocationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("provider_id", "provider_partition", mode="before")
    @classmethod
    def canonicalize_provider_coordinates(cls, value: object) -> object:
        if not isinstance(value, str):
            raise TypeError("Cloud provider coordinates must be strings")
        if value != value.strip().lower():
            raise ValueError("Cloud provider coordinates must be canonical lowercase text")
        return value

    @field_validator("endpoint_origin")
    @classmethod
    def require_canonical_origin(cls, value: str) -> str:
        return _canonical_provider_origin(value)

    @field_validator("max_credential_ttl_seconds", "max_runtime_seconds", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Cloud provider adapter budgets must be integers")
        return value

    @field_validator(
        "explicit_registration_required",
        "request_adaptation_only",
        "ambient_credential_allowed",
        "provider_selection_authorized",
        "provider_invocation_authorized",
        "network_access_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud provider adapter markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_adapter(self) -> Self:
        route_order = tuple(
            (route.surface.surface_id, route.operation.value, route.target) for route in self.routes
        )
        route_keys = tuple((surface_id, operation) for surface_id, operation, _ in route_order)
        if route_order != tuple(sorted(route_order)) or len(route_keys) != len(set(route_keys)):
            raise ValueError("Cloud provider routes must be sorted and unique")
        if any(_target_origin(route.target) != self.endpoint_origin for route in self.routes):
            raise ValueError("Cloud provider route differs from adapter endpoint origin")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"adapter_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cloud-provider-adapter/v1",
            material,
        )
        if self.adapter_digest and self.adapter_digest != digest:
            raise ValueError("Cloud provider adapter digest differs")
        object.__setattr__(self, "adapter_digest", digest)
        return self

    def reference(self) -> CloudReadOnlyProviderAdapterRef:
        return CloudReadOnlyProviderAdapterRef(
            adapterId=self.adapter_id,
            adapterVersion=self.adapter_version,
            adapterDigest=self.adapter_digest,
            providerId=self.provider_id,
            providerPartition=self.provider_partition,
        )


class CloudCredentialLeaseReference(StrictModel):
    """Fingerprint-only active lease snapshot without a bearer lease ID or material."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-credential-lease-reference/v1alpha1"] = Field(
        default=CLOUD_CREDENTIAL_LEASE_REFERENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudCredentialLeaseReference"] = "CloudCredentialLeaseReference"
    reference_id: str = Field(default="", alias="referenceId", max_length=97)
    reference_digest: str = Field(default="", alias="referenceDigest", max_length=64)
    lease_id_fingerprint: _Sha256 = Field(alias="leaseIdFingerprint")
    secret_ref_fingerprint: _SecretFingerprint = Field(alias="secretRefFingerprint")
    audience: _Identifier
    binding: Literal["cloud-provider-credential"] = "cloud-provider-credential"
    scope: _Identifier
    issued_at: datetime = Field(alias="issuedAt")
    expires_at: datetime = Field(alias="expiresAt")
    max_uses: Literal[1] = Field(alias="maxUses")
    remaining_uses: Literal[1] = Field(alias="remainingUses")
    status: Literal[SecretLeaseStatus.ACTIVE] = SecretLeaseStatus.ACTIVE
    lease_id_embedded: Literal[False] = Field(default=False, alias="leaseIdEmbedded")
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    materialization_authorized: Literal[False] = Field(
        default=False,
        alias="materializationAuthorized",
    )
    broker_recheck_required: Literal[True] = Field(
        default=True,
        alias="brokerRecheckRequired",
    )

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Cloud credential lease timestamps require an explicit offset")
        return value.astimezone(UTC)

    @field_validator("max_uses", "remaining_uses", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Cloud credential lease use counts must be integers")
        return value

    @field_validator(
        "lease_id_embedded",
        "credential_material_embedded",
        "materialization_authorized",
        "broker_recheck_required",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud credential lease markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        if self.expires_at <= self.issued_at:
            raise ValueError("Cloud credential lease expiry must follow issuance")
        ttl = (self.expires_at - self.issued_at).total_seconds()
        if not 1 <= ttl <= _MAX_CREDENTIAL_TTL_SECONDS or not ttl.is_integer():
            raise ValueError("Cloud credential lease TTL is outside the exact bound")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"reference_id", "reference_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cloud-credential-lease-reference/v1",
            material,
        )
        reference_id = f"cloud-credential-lease-ref_{digest}"
        if self.reference_digest and self.reference_digest != digest:
            raise ValueError("Cloud credential lease reference digest differs")
        if self.reference_id and self.reference_id != reference_id:
            raise ValueError("Cloud credential lease reference ID differs")
        object.__setattr__(self, "reference_digest", digest)
        object.__setattr__(self, "reference_id", reference_id)
        return self


class CloudReadOnlyBudget(StrictModel):
    """Attenuating Cloud Worker dimensions without reservation or spend."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    request_count: Literal[1] = Field(default=1, alias="requestCount")
    credential_ttl_seconds: int = Field(
        alias="credentialTtlSeconds",
        ge=1,
        le=_MAX_CREDENTIAL_TTL_SECONDS,
    )
    runtime_seconds: int = Field(alias="runtimeSeconds", ge=1, le=_MAX_RUNTIME_SECONDS)
    max_response_bytes: int = Field(
        alias="maxResponseBytes",
        ge=1_024,
        le=_MAX_PROVIDER_RESPONSE_BYTES,
    )
    provider_write_requests: Literal[0] = Field(
        default=0,
        alias="providerWriteRequests",
    )
    attenuation_only: Literal[True] = Field(default=True, alias="attenuationOnly")
    reservation_created: Literal[False] = Field(default=False, alias="reservationCreated")

    @field_validator(
        "request_count",
        "credential_ttl_seconds",
        "runtime_seconds",
        "max_response_bytes",
        "provider_write_requests",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Cloud read-only budget values must be integers")
        return value

    @field_validator("attenuation_only", "reservation_created", mode="before")
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud read-only budget markers must be booleans")
        return value


class CloudProviderReadRequest(StrictModel):
    """Secret-free provider GET description emitted by the bounded adapter."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-provider-read-request/v1alpha1"] = Field(
        default=CLOUD_PROVIDER_READ_REQUEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudProviderReadRequest"] = "CloudProviderReadRequest"
    adapter: CloudReadOnlyProviderAdapterRef
    route_digest: _Sha256 = Field(alias="routeDigest")
    operation: CloudReadOnlyOperation
    surface: CloudAccountResourceSurfaceRef
    target: str = Field(min_length=9, max_length=2_000)
    method: Literal["GET"] = "GET"
    credential_lease: CloudCredentialLeaseReference = Field(alias="credentialLease")
    budget: CloudReadOnlyBudget
    request_body_embedded: Literal[False] = Field(
        default=False,
        alias="requestBodyEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    provider_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="providerInvocationAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )

    @field_validator("target")
    @classmethod
    def require_canonical_target(cls, value: str) -> str:
        return _canonical_provider_target(value)

    @field_validator(
        "request_body_embedded",
        "credential_material_embedded",
        "provider_invocation_authorized",
        "network_access_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud provider read request markers must be booleans")
        return value

    @model_validator(mode="after")
    def require_operation_surface(self) -> Self:
        if self.operation is CloudReadOnlyOperation.POLICY and (
            self.surface.surface_class is not CloudSurfaceClass.IAM
            or self.surface.locator_kind != "cloud-iam"
        ):
            raise ValueError("Cloud policy request requires an exact IAM Surface")
        return self


@dataclass(frozen=True, slots=True)
class BoundedCloudReadOnlyProviderAdapter:
    """Adapt exact typed Surfaces to registered GET routes without invoking them."""

    _definition: CloudReadOnlyProviderAdapterDefinition

    def __post_init__(self) -> None:
        try:
            canonical = CloudReadOnlyProviderAdapterDefinition.model_validate(
                self._definition.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise CloudReadOnlyCapabilityError(
                "Cloud provider adapter definition is not canonical"
            ) from exc
        object.__setattr__(self, "_definition", canonical)

    @property
    def definition(self) -> CloudReadOnlyProviderAdapterDefinition:
        return self._definition.model_copy(deep=True)

    def prepare_request(
        self,
        *,
        surface: CloudAccountResourceSurface,
        operation: CloudReadOnlyOperation,
        credential_lease: CloudCredentialLeaseReference,
    ) -> CloudProviderReadRequest:
        """Return one bounded request description without creating network authority."""

        canonical_surface = _canonical_surface(surface)
        provider_id, provider_partition = _surface_provider_coordinate(canonical_surface)
        if (
            provider_id != self._definition.provider_id
            or provider_partition != self._definition.provider_partition
        ):
            raise CloudReadOnlyCapabilityError(
                "Cloud Surface provider coordinate differs from the explicit adapter"
            )
        route = next(
            (
                item
                for item in self._definition.routes
                if item.surface == canonical_surface.reference() and item.operation is operation
            ),
            None,
        )
        if route is None:
            raise CloudReadOnlyCapabilityError(
                "Cloud provider adapter has no exact Surface and operation route"
            )
        budget = CloudReadOnlyBudget(
            credentialTtlSeconds=self._definition.max_credential_ttl_seconds,
            runtimeSeconds=self._definition.max_runtime_seconds,
            maxResponseBytes=route.max_response_bytes,
        )
        if (
            credential_lease.audience != self._definition.credential_audience
            or credential_lease.binding != self._definition.credential_binding
            or (credential_lease.expires_at - credential_lease.issued_at).total_seconds()
            > budget.credential_ttl_seconds
        ):
            raise CloudReadOnlyCapabilityError(
                "Cloud credential lease differs from the explicit provider adapter"
            )
        return CloudProviderReadRequest(
            adapter=self._definition.reference(),
            routeDigest=route.route_digest,
            operation=operation,
            surface=canonical_surface.reference(),
            target=route.target,
            credentialLease=credential_lease,
            budget=budget,
        )


class CloudReadOnlyInventoryPolicyTool(Tool):
    """CAP-001 Tool identity whose provider runtime remains deployment-owned."""

    spec = ToolSpec(
        tool_id=CLOUD_READ_ONLY_TOOL_ID,
        version="1.0.0",
        description="Prepare one explicitly registered read-only Cloud inventory or policy GET",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"cloud", "inventory", "policy", "read-only"}),
        evidence_types=frozenset({"cloud-provider-json", "json"}),
        network_access=True,
        network_request_cost=1,
        parallel_safe=False,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return {
            **self._stable_spec_context(),
            "providerRuntimeAdapterAvailable": False,
            "workerJobMaterializationAvailable": False,
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        _validate_cloud_tool_request(request)
        raise CloudReadOnlyCapabilityError("CLOUD-001B does not materialize a provider Worker job")

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        _validate_cloud_tool_request(request)
        raise CloudReadOnlyCapabilityError("CLOUD-001B has no provider runtime result to normalize")


class CloudReadOnlyCapabilityDomainClassification(StrictModel):
    """Exact Cloud classification for the additive CLOUD-001B CAP-002 bundle."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-read-only-capability-domain-classification/v1alpha1"] = (
        Field(
            default=CLOUD_READ_ONLY_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["CloudReadOnlyCapabilityDomainClassification"] = (
        "CloudReadOnlyCapabilityDomainClassification"
    )
    classification_id: str = Field(default="", alias="classificationId", max_length=97)
    classification_digest: str = Field(
        default="",
        alias="classificationDigest",
        max_length=64,
    )
    capability: CapabilityDefinitionRef
    code_backed_capability: CodeBackedCapabilityRef = Field(alias="codeBackedCapability")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    reviewed_surface_types: tuple[CloudSurfaceLocatorKind, ...] = Field(
        default=(
            "cloud-account",
            "cloud-container",
            "cloud-iam",
            "cloud-project",
            "cloud-resource",
        ),
        alias="reviewedSurfaceTypes",
    )
    mapping_basis: Literal["cloud-001b-explicit-code-reviewed-capability-and-surface-set"] = Field(
        default="cloud-001b-explicit-code-reviewed-capability-and-surface-set",
        alias="mappingBasis",
    )
    projection_only: Literal[True] = Field(default=True, alias="projectionOnly")
    complete_code_authority_set_verified: Literal[True] = Field(
        default=True,
        alias="completeCodeAuthoritySetVerified",
    )
    global_domain_inventory_changed: Literal[False] = Field(
        default=False,
        alias="globalDomainInventoryChanged",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "projection_only",
        "complete_code_authority_set_verified",
        "global_domain_inventory_changed",
        "capability_activation_authorized",
        "worker_selection_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud Capability Domain markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        capability = _cloud_code_backed_capability()
        worker = _cloud_worker_boundary_profile()
        expected_surfaces = tuple(sorted(_supported_locator_kinds()))
        if (
            self.capability != capability.capability
            or self.code_backed_capability != capability
            or self.domain_classification != worker.domain_classification
            or self.reviewed_surface_types != expected_surfaces
        ):
            raise ValueError("Cloud Capability Domain classification differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_id", "classification_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cloud-domain-classification/v1",
            material,
        )
        classification_id = f"capability-domain-classification_{digest}"
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("Cloud Capability Domain classification digest differs")
        if self.classification_id and self.classification_id != classification_id:
            raise ValueError("Cloud Capability Domain classification ID differs")
        object.__setattr__(self, "classification_digest", digest)
        object.__setattr__(self, "classification_id", classification_id)
        return self

    def reference(self) -> CapabilityDomainClassificationRef:
        return CapabilityDomainClassificationRef(
            classificationId=self.classification_id,
            classificationDigest=self.classification_digest,
            capability=self.capability,
            domainClassification=self.domain_classification,
        )


class CloudCampaignScopeBinding(StrictModel):
    """Content-addressed current Campaign projection for exact Cloud GET preparation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-campaign-scope-binding/v1alpha1"] = Field(
        default=CLOUD_CAMPAIGN_SCOPE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudCampaignScopeBinding"] = "CloudCampaignScopeBinding"
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    campaign_name: str = Field(
        alias="campaignName",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    scope: Scope
    allowed_methods: tuple[str, ...] = Field(
        alias="allowedMethods",
        min_length=1,
        max_length=32,
    )
    allow_private_networks: bool = Field(alias="allowPrivateNetworks")
    projection_only: Literal[True] = Field(default=True, alias="projectionOnly")
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "allow_private_networks",
        "projection_only",
        "approval_satisfied",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud Campaign Scope markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_scope_projection(self) -> Self:
        if self.allowed_methods != tuple(sorted(set(self.allowed_methods))):
            raise ValueError("Cloud Campaign allowed methods must be sorted and unique")
        if "GET" not in self.allowed_methods:
            raise ValueError("Cloud Campaign Scope requires reviewed GET authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cloud-campaign-scope-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Cloud Campaign Scope binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class CloudReadOnlyCapabilityBundle:
    """Frozen CAP-001/CAP-002 registries for one Cloud read-only Capability."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capability(self) -> CodeBackedCapabilityRef:
        manifests = self.authorities.capabilities()
        if len(manifests) != 1:
            raise CloudReadOnlyCapabilityError(
                "Cloud read-only Capability authority inventory drifted"
            )
        return manifests[0].reference()


class CloudReadOnlyCapabilityActivationBinding(StrictModel):
    """One exact externally signed release admitted for Range-only use."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release: CapabilityReleaseRef
    release_bundle_digest: _Sha256 = Field(alias="releaseBundleDigest")
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")

    @model_validator(mode="after")
    def bind_exact_capability(self) -> Self:
        definition = self.capability.capability
        action = self.action_capability
        if (
            definition.capability_id != CLOUD_READ_ONLY_CAPABILITY_ID
            or definition.capability_version != CLOUD_READ_ONLY_CAPABILITY_VERSION
            or action.capability_id != definition.capability_id
            or action.capability_version != definition.capability_version
            or action.definition_digest != definition.capability_digest
        ):
            raise ValueError("Cloud read-only activation references another Capability")
        return self


class CloudReadOnlyCapabilityActivationSet(StrictModel):
    """Content-addressed activation of exactly one signed Cloud read-only release."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-read-only-capability-activation-set/v1alpha1"] = Field(
        default=CLOUD_READ_ONLY_CAPABILITY_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudReadOnlyCapabilityActivationSet"] = "CloudReadOnlyCapabilityActivationSet"
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=128)
    activation_set_digest: str = Field(
        default="",
        alias="activationSetDigest",
        max_length=64,
    )
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: CloudReadOnlyCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cloud-read-only-activation-set/v1",
            material,
        )
        activation_set_id = f"cloud-read-only-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("Cloud read-only activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("Cloud read-only activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class CloudReadOnlyCapabilityActivation:
    """Runtime activation that rechecks the signed current release on every use."""

    bundle: CloudReadOnlyCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: CloudReadOnlyCapabilityActivationSet

    def __post_init__(self) -> None:
        _verify_activation(self)

    def action_registry(self) -> ActionCapabilityRegistry:
        _verify_activation(self)
        return ActionCapabilityRegistry((self.activation_set.binding.action_capability,))

    def definition(self) -> CapabilityDefinition:
        _verify_activation(self)
        try:
            return self.bundle.definitions.resolve(
                self.activation_set.binding.capability.capability
            )
        except CapabilityDefinitionError as exc:
            raise CloudReadOnlyCapabilityError(
                "Cloud read-only activated Definition is unavailable"
            ) from exc

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise CloudReadOnlyCapabilityError(
                "Cloud read-only CAP-002 authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(self, reference: ActionCapabilityRef) -> ResolvedCapabilityRelease:
        try:
            canonical = ActionCapabilityRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise CloudReadOnlyCapabilityError(
                "Cloud read-only GRAPH Capability reference is not canonical"
            ) from exc
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise CloudReadOnlyCapabilityError(
                "Cloud read-only GRAPH Capability is outside the activation"
            )
        return _resolve_activation_binding(self, binding)

    def prepare_action(
        self,
        *,
        release: CapabilityReleaseRef,
        request: ToolRequest,
        parameters: Mapping[str, JsonValue],
    ) -> PreparedCapabilityAction:
        binding = self.activation_set.binding
        canonical_release = _canonical_release_ref(release)
        if binding.release != canonical_release:
            raise CloudReadOnlyCapabilityError("Cloud read-only release is outside the activation")
        resolved = self.resolve_for_dispatch(binding.action_capability.reference())
        canonical_request = _canonical_tool_request(request)
        try:
            materializer = self.bundle.authorities.authority(
                resolved.capability.reference(),
                CapabilityAuthorityRole.MATERIALIZER,
            )
            compiler = self.bundle.authorities.authority(
                resolved.capability.reference(),
                CapabilityAuthorityRole.ACTION_COMPILER,
            )
            materialized = materializer.materialize(parameters)
            compiled = compiler.compile(canonical_request, materialized)
        except CapabilityAuthorityError as exc:
            raise CloudReadOnlyCapabilityError(
                "Cloud read-only CAP-002 request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


class _CloudReadOnlyAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        definition: CapabilityDefinition,
        tool: CloudReadOnlyInventoryPolicyTool,
    ) -> None:
        self._definition = definition
        self._tool = tool

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{CLOUD_READ_ONLY_CAPABILITY_ID}.{self.authority_role.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        tool_spec = self._tool.spec.model_dump(mode="json")
        tool_spec["categories"] = sorted(self._tool.spec.categories)
        tool_spec["evidence_types"] = sorted(self._tool.spec.evidence_types)
        return {
            "adapterContractVersion": CLOUD_READ_ONLY_CAPABILITY_ADAPTER_VERSION,
            "method": "GET",
            "parameterSchemaDigest": self._definition.parameter_schema_digest,
            "providerRequestAdaptationAvailable": True,
            "providerRuntimeAdapterAvailable": False,
            "workerJobMaterializationAvailable": False,
            "replayAuthorized": False,
            "cleanupAuthorized": False,
            "tool": {
                "type": f"{type(self._tool).__module__}.{type(self._tool).__qualname__}",
                "context": {
                    "implementationVersion": "pajin.tool-adapter/v1",
                    "providerRuntimeAdapterAvailable": False,
                    "workerJobMaterializationAvailable": False,
                    "spec": tool_spec,
                },
            },
        }


class _CloudReadOnlyMaterializer(_CloudReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            request = CloudProviderReadRequest.model_validate(dict(parameters))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Cloud provider parameters differ from the bounded read request"
            ) from exc
        return cast(Mapping[str, JsonValue], request.model_dump(mode="json", by_alias=True))


class _CloudReadOnlyActionCompiler(_CloudReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        try:
            provider_request = CloudProviderReadRequest.model_validate(dict(materialized_arguments))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Cloud provider materialized request is invalid"
            ) from exc
        if (
            request.tool_id != CLOUD_READ_ONLY_TOOL_ID
            or request.method != "GET"
            or request.target != provider_request.target
            or request.arguments
        ):
            raise CapabilityAuthorityError(
                "Cloud compiler accepts only one exact empty GET request"
            )
        return request.model_copy(
            update={"arguments": provider_request.model_dump(mode="json", by_alias=True)}
        )


class _CloudReadOnlyExecutorAdapter(_CloudReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)


class _CloudReadOnlyResultNormalizer(_CloudReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)


class _CloudReadOnlySuccessOracle(_CloudReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        del request, result
        return CapabilityOracleDecision.INCONCLUSIVE


class _CloudReadOnlyReplayStrategy(_CloudReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        return None


class _CloudReadOnlyCleanupHandler(_CloudReadOnlyAuthorityBase):
    ROLE = CapabilityAuthorityRole.CLEANUP_HANDLER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del request, result
        return None


@cache
def registered_cloud_read_only_capability_definition() -> CapabilityDefinition:
    """Return exact CAP-001 metadata for bounded Cloud GET preparation."""

    raw_schema = CloudProviderReadRequest.model_json_schema(by_alias=True)
    raw_schema["required"] = sorted(raw_schema["required"])
    schema = cast(Mapping[str, JsonValue], raw_schema)
    return capability_definition_from_tool(
        CloudReadOnlyInventoryPolicyTool.spec,
        ToolCapabilityRegistration(
            capabilityId=CLOUD_READ_ONLY_CAPABILITY_ID,
            capabilityVersion=CLOUD_READ_ONLY_CAPABILITY_VERSION,
            toolId=CLOUD_READ_ONLY_TOOL_ID,
            domain="cloud",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=_supported_locator_kinds(),
            threatClasses=("cloud-inventory", "cloud-policy"),
            preconditions=(
                "active-ephemeral-credential-lease-reference",
                "bounded-provider-get-route",
                "current-campaign-scope",
                "fresh-signed-authorization",
                "one-use-action-permit",
            ),
            parameterSchemaDigest=capability_parameter_schema_digest(schema),
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=1,
        ),
    )


def cloud_read_only_capability_bundle(tools: ToolRegistry) -> CloudReadOnlyCapabilityBundle:
    """Bind the exact Cloud Tool identity to all seven required CAP-002 roles."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("Cloud read-only Capability requires a ToolRegistry")
    try:
        tool = tools.tool(CLOUD_READ_ONLY_TOOL_ID)
        spec = tools.spec(CLOUD_READ_ONLY_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise CloudReadOnlyCapabilityError("Cloud read-only Tool is unavailable") from exc
    if type(tool) is not CloudReadOnlyInventoryPolicyTool or spec != (
        CloudReadOnlyInventoryPolicyTool.spec
    ):
        raise CloudReadOnlyCapabilityError("Cloud read-only Tool implementation drifted")
    typed_tool = tool
    definition = registered_cloud_read_only_capability_definition()
    definitions = CapabilityDefinitionRegistry((definition,))
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _CloudReadOnlyActionCompiler(definition, typed_tool),
        _CloudReadOnlyCleanupHandler(definition, typed_tool),
        _CloudReadOnlyExecutorAdapter(definition, typed_tool),
        _CloudReadOnlyMaterializer(definition, typed_tool),
        _CloudReadOnlyReplayStrategy(definition, typed_tool),
        _CloudReadOnlyResultNormalizer(definition, typed_tool),
        _CloudReadOnlySuccessOracle(definition, typed_tool),
    )
    return CloudReadOnlyCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_cloud_read_only_capability(
    *,
    bundle: CloudReadOnlyCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> CloudReadOnlyCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if not isinstance(bundle, CloudReadOnlyCapabilityBundle):
        raise TypeError("Cloud read-only activation requires its exact Capability bundle")
    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("Cloud read-only activation requires a verified lifecycle registry")
    canonical_release = _canonical_release_ref(release)
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        capability = bundle.capability()
        definition = bundle.definitions.resolve(capability.capability)
    except (CapabilityAuthorityError, CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise CloudReadOnlyCapabilityError(
            "Cloud read-only signed release activation failed closed"
        ) from exc
    if (
        resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition != registered_cloud_read_only_capability_definition()
    ):
        raise CloudReadOnlyCapabilityError(
            "Cloud read-only signed release differs from code authority"
        )
    binding = CloudReadOnlyCapabilityActivationBinding(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    activation_set = CloudReadOnlyCapabilityActivationSet(binding=binding)
    return CloudReadOnlyCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=activation_set,
    )


class CloudReadOnlyInventoryPolicyBindingRef(StrictModel):
    """Exact content-addressed reference to the CLOUD-001B static binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: Literal["pajin.cloud.read-only-inventory-policy.binding"] = Field(alias="bindingId")
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")


class CloudReadOnlyInventoryPolicyBinding(StrictModel):
    """Exact Cloud Surface/CAP-002/Worker contract without provider invocation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-read-only-inventory-policy-binding/v1alpha1"] = Field(
        default=CLOUD_READ_ONLY_BINDING_API_VERSION, alias="apiVersion"
    )
    kind: Literal["CloudReadOnlyInventoryPolicyBinding"] = "CloudReadOnlyInventoryPolicyBinding"
    binding_id: Literal["pajin.cloud.read-only-inventory-policy.binding"] = Field(
        default="pajin.cloud.read-only-inventory-policy.binding",
        alias="bindingId",
    )
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    surface_type: Literal["cloud.account-resource"] = Field(
        default="cloud.account-resource",
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.cloud.account-resource.v1"] = Field(
        default="pajin.locator.cloud.account-resource.v1",
        alias="locatorSchema",
    )
    locator_registry: CloudAccountResourceLocatorRegistryRef = Field(alias="locatorRegistry")
    supported_locators: tuple[CloudAccountResourceLocatorRef, ...] = Field(
        alias="supportedLocators",
        min_length=5,
        max_length=5,
    )
    capability: CodeBackedCapabilityRef
    capability_domain_classification: CloudReadOnlyCapabilityDomainClassification = Field(
        alias="capabilityDomainClassification"
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    supported_operations: tuple[CloudReadOnlyOperation, ...] = Field(
        default=(CloudReadOnlyOperation.INVENTORY, CloudReadOnlyOperation.POLICY),
        alias="supportedOperations",
    )
    binding_only: Literal[True] = Field(default=True, alias="bindingOnly")
    complete_cap_002_verified: Literal[True] = Field(
        default=True,
        alias="completeCAP002Verified",
    )
    preparation_available: Literal[True] = Field(default=True, alias="preparationAvailable")
    bounded_provider_adapter_required: Literal[True] = Field(
        default=True,
        alias="boundedProviderAdapterRequired",
    )
    current_capability_activation_required: Literal[True] = Field(
        default=True,
        alias="currentCapabilityActivationRequired",
    )
    current_campaign_scope_required: Literal[True] = Field(
        default=True,
        alias="currentCampaignScopeRequired",
    )
    active_ephemeral_credential_lease_required: Literal[True] = Field(
        default=True,
        alias="activeEphemeralCredentialLeaseRequired",
    )
    action_permit_required: Literal[True] = Field(default=True, alias="actionPermitRequired")
    gateway_policy_reentry_required: Literal[True] = Field(
        default=True,
        alias="gatewayPolicyReentryRequired",
    )
    worker_deployment_binding_required: Literal[True] = Field(
        default=True,
        alias="workerDeploymentBindingRequired",
    )
    worker_direct_mtls_required: Literal[True] = Field(
        default=True,
        alias="workerDirectMTLSRequired",
    )
    ambient_credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="ambientCredentialUseAuthorized",
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    policy_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="policyMutationAuthorized",
    )
    iam_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="iamMutationAuthorized",
    )
    container_write_authorized: Literal[False] = Field(
        default=False,
        alias="containerWriteAuthorized",
    )
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
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    observation_production_authorized: Literal[False] = Field(
        default=False,
        alias="observationProductionAuthorized",
    )
    evidence_sealing_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceSealingAuthorized",
    )
    graph_admission_authorized: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthorized",
    )
    runtime_support_asserted_by_binding: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAssertedByBinding",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "binding_only",
        "complete_cap_002_verified",
        "preparation_available",
        "bounded_provider_adapter_required",
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "active_ephemeral_credential_lease_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "worker_deployment_binding_required",
        "worker_direct_mtls_required",
        "ambient_credential_use_authorized",
        "provider_selection_authorized",
        "policy_mutation_authorized",
        "iam_mutation_authorized",
        "container_write_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "worker_selection_authorized",
        "network_access_authorized",
        "observation_production_authorized",
        "evidence_sealing_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted_by_binding",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud read-only binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_binding(self) -> Self:
        definition = registered_cloud_read_only_capability_definition()
        registry = registered_cloud_account_resource_locator_registry()
        worker = _cloud_worker_boundary_profile()
        expected_locators = tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        )
        if (
            self.locator_registry != registry.reference()
            or self.supported_locators != expected_locators
            or self.capability != _cloud_code_backed_capability()
            or self.capability_domain_classification
            != registered_cloud_read_only_capability_domain_classification()
            or self.worker_profile != worker.reference()
            or self.supported_operations
            != (CloudReadOnlyOperation.INVENTORY, CloudReadOnlyOperation.POLICY)
            or definition.supported_surface_types != _supported_locator_kinds()
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.tool.tool_id != CLOUD_READ_ONLY_TOOL_ID
            or definition.network_access is not True
            or definition.approval_required is not True
            or worker.network_boundary is not WorkerNetworkBoundary.BOUNDED_EGRESS
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.NO_HOST_ACCESS
            or worker.credential_boundary is not WorkerCredentialBoundary.EPHEMERAL_LEASE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.ISOLATED_NON_ROOT
            or worker.required_identity_dimensions
            != ("account-or-project", "credential-lease", "resource")
            or worker.required_budget_dimensions != ("credential-ttl", "request-count", "runtime")
        ):
            raise ValueError("Cloud read-only binding differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cloud-read-only-inventory-policy-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Cloud read-only binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self

    def reference(self) -> CloudReadOnlyInventoryPolicyBindingRef:
        return CloudReadOnlyInventoryPolicyBindingRef(
            bindingId=self.binding_id,
            bindingVersion=self.binding_version,
            bindingDigest=self.binding_digest,
        )


class CloudReadOnlyInventoryPolicyPreparation(StrictModel):
    """Exact signed preparation with no credential use, provider call, or dispatch."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/cloud-read-only-inventory-policy-preparation/v1alpha1"] = Field(
        default=CLOUD_READ_ONLY_PREPARATION_API_VERSION, alias="apiVersion"
    )
    kind: Literal["CloudReadOnlyInventoryPolicyPreparation"] = (
        "CloudReadOnlyInventoryPolicyPreparation"
    )
    preparation_id: str = Field(default="", alias="preparationId", max_length=100)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: CloudReadOnlyInventoryPolicyBinding
    surface: CloudAccountResourceSurface
    operation: CloudReadOnlyOperation
    provider_adapter: CloudReadOnlyProviderAdapterDefinition = Field(alias="providerAdapter")
    provider_request: CloudProviderReadRequest = Field(alias="providerRequest")
    campaign_scope: CloudCampaignScopeBinding = Field(alias="campaignScope")
    matched_surface_allow_rule: str = Field(
        alias="matchedSurfaceAllowRule",
        min_length=1,
        max_length=2_000,
    )
    matched_provider_allow_rule: str = Field(
        alias="matchedProviderAllowRule",
        min_length=1,
        max_length=2_000,
    )
    credential_lease: CloudCredentialLeaseReference = Field(alias="credentialLease")
    evaluated_at: datetime = Field(alias="evaluatedAt")
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    state: Literal["prepared-not-authorized"] = "prepared-not-authorized"
    current_campaign_bound: Literal[True] = Field(default=True, alias="currentCampaignBound")
    provider_request_adapted: Literal[True] = Field(
        default=True,
        alias="providerRequestAdapted",
    )
    credential_lease_reference_bound: Literal[True] = Field(
        default=True,
        alias="credentialLeaseReferenceBound",
    )
    capability_prepared: Literal[True] = Field(default=True, alias="capabilityPrepared")
    provider_runtime_adapter_available: Literal[False] = Field(
        default=False,
        alias="providerRuntimeAdapterAvailable",
    )
    lease_id_embedded: Literal[False] = Field(default=False, alias="leaseIdEmbedded")
    credential_materialized: Literal[False] = Field(
        default=False,
        alias="credentialMaterialized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    provider_invoked: Literal[False] = Field(default=False, alias="providerInvoked")
    policy_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="policyMutationAuthorized",
    )
    iam_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="iamMutationAuthorized",
    )
    container_write_authorized: Literal[False] = Field(
        default=False,
        alias="containerWriteAuthorized",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    egress_policy_materialized: Literal[False] = Field(
        default=False,
        alias="egressPolicyMaterialized",
    )
    network_request_performed: Literal[False] = Field(
        default=False,
        alias="networkRequestPerformed",
    )
    observation_produced: Literal[False] = Field(
        default=False,
        alias="observationProduced",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    gateway_dispatch_authorized: Literal[False] = Field(
        default=False,
        alias="gatewayDispatchAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("evaluated_at")
    @classmethod
    def require_aware_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Cloud preparation evaluation time requires an explicit offset")
        return value.astimezone(UTC)

    @field_validator(
        "current_campaign_bound",
        "provider_request_adapted",
        "credential_lease_reference_bound",
        "capability_prepared",
        "provider_runtime_adapter_available",
        "lease_id_embedded",
        "credential_materialized",
        "credential_use_authorized",
        "provider_invoked",
        "policy_mutation_authorized",
        "iam_mutation_authorized",
        "container_write_authorized",
        "worker_job_materialized",
        "egress_policy_materialized",
        "network_request_performed",
        "observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "approval_satisfied",
        "permit_issuance_authorized",
        "gateway_dispatch_authorized",
        "worker_selection_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Cloud read-only preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        expected_action = registered_action_capability(
            registered_cloud_read_only_capability_definition()
        ).reference()
        expected_surface_rule = _require_exact_scope_allow(
            self.campaign_scope,
            cloud_surface_scope_target(self.surface),
            label="Cloud Surface",
        )
        expected_provider_rule = _require_exact_scope_allow(
            self.campaign_scope,
            self.provider_request.target,
            label="Cloud provider route",
        )
        expected_request = BoundedCloudReadOnlyProviderAdapter(
            self.provider_adapter
        ).prepare_request(
            surface=self.surface,
            operation=self.operation,
            credential_lease=self.credential_lease,
        )
        request = self.prepared_action.request
        if (
            not self.credential_lease.issued_at
            <= self.evaluated_at
            < (self.credential_lease.expires_at)
        ):
            raise ValueError("Cloud credential lease was not active at preparation")
        if self.credential_lease.scope != _credential_scope_for_binding(
            self.campaign_scope.campaign_digest
        ):
            raise ValueError("Cloud credential lease scope differs from the Campaign")
        if (
            self.binding != registered_cloud_read_only_inventory_policy_binding()
            or self.surface.initial_state != "registered-not-authorized"
            or self.provider_request != expected_request
            or self.matched_surface_allow_rule != expected_surface_rule
            or self.matched_provider_allow_rule != expected_provider_rule
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != CLOUD_READ_ONLY_TOOL_ID
            or request.method != "GET"
            or request.target != self.provider_request.target
            or request.arguments != self.provider_request.model_dump(mode="json", by_alias=True)
        ):
            raise ValueError("Cloud read-only preparation differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.cloud-read-only-inventory-policy-preparation/v1",
            material,
        )
        preparation_id = f"cloud-read-only-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Cloud read-only preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("Cloud read-only preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


@cache
def registered_cloud_read_only_inventory_policy_binding() -> CloudReadOnlyInventoryPolicyBinding:
    """Return the exact CLOUD-001B binding without provider or Worker selection."""

    registry = registered_cloud_account_resource_locator_registry()
    return CloudReadOnlyInventoryPolicyBinding(
        locatorRegistry=registry.reference(),
        supportedLocators=tuple(
            item.reference()
            for item in sorted(registry.locators, key=lambda item: item.locator_kind)
        ),
        capability=_cloud_code_backed_capability(),
        capabilityDomainClassification=(
            registered_cloud_read_only_capability_domain_classification()
        ),
        workerProfile=_cloud_worker_boundary_profile().reference(),
    )


def resolve_cloud_read_only_inventory_policy_binding(
    reference: CloudReadOnlyInventoryPolicyBindingRef,
) -> CloudReadOnlyInventoryPolicyBinding:
    binding = registered_cloud_read_only_inventory_policy_binding()
    if binding.reference() == reference:
        return binding.model_copy(deep=True)
    raise CloudReadOnlyCapabilityError(
        "Cloud read-only inventory/policy binding is not registered exactly"
    )


@cache
def registered_cloud_read_only_capability_domain_classification() -> (
    CloudReadOnlyCapabilityDomainClassification
):
    capability = _cloud_code_backed_capability()
    return CloudReadOnlyCapabilityDomainClassification(
        capability=capability.capability,
        codeBackedCapability=capability,
        domainClassification=_cloud_worker_boundary_profile().domain_classification,
    )


def resolve_cloud_read_only_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
) -> CloudReadOnlyCapabilityDomainClassification:
    classification = registered_cloud_read_only_capability_domain_classification()
    if classification.reference() == reference:
        return classification.model_copy(deep=True)
    raise CloudReadOnlyCapabilityError(
        "Cloud read-only Capability Domain classification is not registered exactly"
    )


def cloud_surface_scope_target(surface: CloudAccountResourceSurface) -> str:
    """Return a non-routable exact Campaign Scope token for one typed Cloud Surface."""

    canonical = _canonical_surface(surface)
    return f"{CLOUD_SURFACE_SCOPE_ORIGIN}/surfaces/{canonical.surface_id}"


def cloud_credential_lease_scope(campaign: CampaignManifest) -> str:
    """Return the exact SecretBroker scope required for one current Campaign."""

    canonical = _canonical_campaign(campaign)
    return _credential_scope_for_binding(campaign_manifest_digest(canonical))


def bind_cloud_credential_lease_reference(
    *,
    broker: SecretBroker,
    lease: SecretLease,
    campaign: CampaignManifest,
    provider_adapter: CloudReadOnlyProviderAdapterDefinition,
    evaluated_at: datetime,
) -> CloudCredentialLeaseReference:
    """Bind an active lease snapshot without serializing its bearer lease ID."""

    if not isinstance(broker, SecretBroker):
        raise TypeError("Cloud credential lease binding requires a SecretBroker")
    canonical_campaign = _canonical_campaign(campaign)
    canonical_adapter = _canonical_provider_adapter(provider_adapter)
    canonical_lease = _canonical_secret_lease(lease)
    evaluated = _canonical_time(evaluated_at, label="Cloud lease evaluation time")
    expected_scope = cloud_credential_lease_scope(canonical_campaign)
    try:
        broker_lease = broker.inspect(
            canonical_lease.lease_id,
            audience=canonical_adapter.credential_audience,
            scope=expected_scope,
        )
    except (KeyError, PermissionError, ValueError) as exc:
        raise CloudReadOnlyCapabilityError(
            "Cloud credential lease is not current in the trusted SecretBroker"
        ) from exc
    if _canonical_secret_lease(broker_lease) != canonical_lease:
        raise CloudReadOnlyCapabilityError(
            "Cloud credential lease snapshot differs from the trusted SecretBroker"
        )
    ttl = (canonical_lease.expires_at - canonical_lease.issued_at).total_seconds()
    if (
        re.fullmatch(r"lease_[A-Za-z0-9]+", canonical_lease.lease_id) is None
        or canonical_lease.audience != canonical_adapter.credential_audience
        or canonical_lease.binding != canonical_adapter.credential_binding
        or canonical_lease.scope != expected_scope
        or canonical_lease.status is not SecretLeaseStatus.ACTIVE
        or canonical_lease.max_uses != 1
        or canonical_lease.remaining_uses != 1
        or not canonical_lease.issued_at <= evaluated < canonical_lease.expires_at
        or not ttl.is_integer()
        or not 1 <= ttl <= canonical_adapter.max_credential_ttl_seconds
    ):
        raise CloudReadOnlyCapabilityError(
            "Cloud credential lease is not an active exact one-use Campaign lease"
        )
    return CloudCredentialLeaseReference(
        leaseIdFingerprint=sha256(canonical_lease.lease_id.encode("utf-8")).hexdigest(),
        secretRefFingerprint=canonical_lease.secret_ref_fingerprint,
        audience=canonical_lease.audience,
        binding=canonical_lease.binding,
        scope=canonical_lease.scope,
        issuedAt=canonical_lease.issued_at,
        expiresAt=canonical_lease.expires_at,
        maxUses=1,
        remainingUses=1,
        status=canonical_lease.status,
    )


def prepare_cloud_read_only_inventory_policy(
    *,
    activation: CloudReadOnlyCapabilityActivation,
    release: CapabilityReleaseRef,
    campaign: CampaignManifest,
    surface: CloudAccountResourceSurface,
    operation: CloudReadOnlyOperation,
    provider_adapter: BoundedCloudReadOnlyProviderAdapter,
    secret_broker: SecretBroker,
    credential_lease: SecretLease,
    evaluated_at: datetime,
    request_id: str,
    agent_id: str,
) -> CloudReadOnlyInventoryPolicyPreparation:
    """Compile one exact scoped Cloud GET through signed CAP-002 and stop before dispatch."""

    if not isinstance(activation, CloudReadOnlyCapabilityActivation):
        raise TypeError("Cloud read-only preparation requires Cloud activation")
    if not isinstance(provider_adapter, BoundedCloudReadOnlyProviderAdapter):
        raise TypeError("Cloud read-only preparation requires a bounded provider adapter")
    try:
        canonical_operation = CloudReadOnlyOperation(operation)
    except ValueError as exc:
        raise CloudReadOnlyCapabilityError("Cloud read-only operation is unsupported") from exc
    canonical_campaign = _canonical_campaign(campaign)
    canonical_surface = _canonical_surface(surface)
    canonical_adapter = provider_adapter.definition
    evaluated = _canonical_time(evaluated_at, label="Cloud preparation evaluation time")
    scope_binding = _campaign_scope_binding(canonical_campaign)
    surface_allow = _require_exact_scope_allow(
        scope_binding,
        cloud_surface_scope_target(canonical_surface),
        label="Cloud Surface",
    )
    lease_reference = bind_cloud_credential_lease_reference(
        broker=secret_broker,
        lease=credential_lease,
        campaign=canonical_campaign,
        provider_adapter=canonical_adapter,
        evaluated_at=evaluated,
    )
    provider_request = provider_adapter.prepare_request(
        surface=canonical_surface,
        operation=canonical_operation,
        credential_lease=lease_reference,
    )
    provider_allow = _require_exact_scope_allow(
        scope_binding,
        provider_request.target,
        label="Cloud provider route",
    )
    binding = registered_cloud_read_only_inventory_policy_binding()
    try:
        if (
            activation.bundle.capability() != binding.capability
            or activation.definition() != registered_cloud_read_only_capability_definition()
        ):
            raise CloudReadOnlyCapabilityError(
                "Cloud read-only activation differs from the registered Capability"
            )
        request = ToolRequest(
            request_id=request_id,
            agent_id=agent_id,
            tool_id=CLOUD_READ_ONLY_TOOL_ID,
            target=provider_request.target,
            method="GET",
            arguments={},
        )
        prepared = activation.prepare_action(
            release=release,
            request=request,
            parameters=cast(
                Mapping[str, JsonValue],
                provider_request.model_dump(mode="json", by_alias=True),
            ),
        )
        return CloudReadOnlyInventoryPolicyPreparation(
            binding=binding,
            surface=canonical_surface,
            operation=canonical_operation,
            providerAdapter=canonical_adapter,
            providerRequest=provider_request,
            campaignScope=scope_binding,
            matchedSurfaceAllowRule=surface_allow,
            matchedProviderAllowRule=provider_allow,
            credentialLease=lease_reference,
            evaluatedAt=evaluated,
            release=release,
            preparedAction=prepared,
        )
    except (CapabilityAuthorityError, ValidationError, ValueError) as exc:
        if isinstance(exc, CloudReadOnlyCapabilityError):
            raise
        raise CloudReadOnlyCapabilityError(
            "Cloud read-only CAP-002 preparation failed closed"
        ) from exc


def _verify_activation(activation: CloudReadOnlyCapabilityActivation) -> None:
    try:
        canonical_set = CloudReadOnlyCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise CloudReadOnlyCapabilityError(
            "Cloud read-only activation set is not canonical"
        ) from exc
    if canonical_set != activation.activation_set:
        raise CloudReadOnlyCapabilityError("Cloud read-only activation set drifted")
    _resolve_activation_binding(activation, canonical_set.binding)


def _resolve_activation_binding(
    activation: CloudReadOnlyCapabilityActivation,
    binding: CloudReadOnlyCapabilityActivationBinding,
) -> ResolvedCapabilityRelease:
    try:
        resolved = activation.lifecycle.resolve_for_use(
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        signed_bundle = activation.lifecycle.resolve_release(binding.release)
    except CapabilityLifecycleError as exc:
        raise CloudReadOnlyCapabilityError(
            "Cloud read-only current signed release could not be resolved"
        ) from exc
    if (
        resolved.capability.reference() != binding.capability
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(signed_bundle) != binding.release_bundle_digest
    ):
        raise CloudReadOnlyCapabilityError("Cloud read-only signed release binding drifted")
    return resolved


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.cloud-read-only-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    try:
        return CapabilityReleaseRef.model_validate(reference.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise CloudReadOnlyCapabilityError(
            "Cloud read-only release reference is not canonical"
        ) from exc


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    try:
        return ToolRequest.model_validate(request.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise CloudReadOnlyCapabilityError("Cloud read-only Tool request is not canonical") from exc


def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
    try:
        return CampaignManifest.model_validate(campaign.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise CloudReadOnlyCapabilityError("Cloud Campaign is not canonical") from exc


def _canonical_surface(surface: CloudAccountResourceSurface) -> CloudAccountResourceSurface:
    try:
        return CloudAccountResourceSurface.model_validate(
            surface.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise CloudReadOnlyCapabilityError("Cloud Surface is not canonical") from exc


def _canonical_provider_adapter(
    adapter: CloudReadOnlyProviderAdapterDefinition,
) -> CloudReadOnlyProviderAdapterDefinition:
    try:
        return CloudReadOnlyProviderAdapterDefinition.model_validate(
            adapter.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise CloudReadOnlyCapabilityError("Cloud provider adapter is not canonical") from exc


def _canonical_secret_lease(lease: SecretLease) -> SecretLease:
    try:
        return SecretLease.model_validate(lease.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise CloudReadOnlyCapabilityError("Cloud credential lease is not canonical") from exc


def _canonical_time(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise CloudReadOnlyCapabilityError(f"{label} requires an explicit UTC offset")
    return value.astimezone(UTC)


def _campaign_scope_binding(campaign: CampaignManifest) -> CloudCampaignScopeBinding:
    return CloudCampaignScopeBinding(
        campaignName=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        scope=campaign.spec.scope.model_copy(deep=True),
        allowedMethods=tuple(sorted(campaign.spec.rules_of_engagement.allowed_methods)),
        allowPrivateNetworks=campaign.spec.rules_of_engagement.allow_private_networks,
    )


def _require_exact_scope_allow(
    scope_binding: CloudCampaignScopeBinding,
    target: str,
    *,
    label: str,
) -> str:
    try:
        canonical_target = normalize_target_url(target)
        normalized_allow = tuple(
            normalize_scope_pattern(rule) for rule in scope_binding.scope.allow
        )
        normalized_deny = tuple(normalize_scope_pattern(rule) for rule in scope_binding.scope.deny)
    except InvalidScopeURL as exc:
        raise CloudReadOnlyCapabilityError(
            f"{label} Campaign Scope cannot be evaluated safely"
        ) from exc
    if canonical_target not in normalized_allow:
        raise CloudReadOnlyCapabilityError(f"{label} lacks an exact current Campaign allow rule")
    if any(scope_matches(rule, canonical_target) for rule in normalized_deny):
        raise CloudReadOnlyCapabilityError(f"{label} overlaps a current Campaign deny rule")
    _require_private_network_authority(scope_binding, canonical_target, label=label)
    return canonical_target


def _require_private_network_authority(
    scope_binding: CloudCampaignScopeBinding,
    target: str,
    *,
    label: str,
) -> None:
    if scope_binding.allow_private_networks:
        return
    hostname = urlsplit(target).hostname
    if hostname is None:
        raise CloudReadOnlyCapabilityError(f"{label} hostname is invalid")
    canonical_hostname = hostname.lower().rstrip(".")
    if canonical_hostname in {"localhost", "host.docker.internal"} or canonical_hostname.endswith(
        ".localhost"
    ):
        raise CloudReadOnlyCapabilityError(
            f"{label} requires explicit private-network Campaign authority"
        )
    try:
        address = ip_address(canonical_hostname)
    except ValueError:
        return
    if not address.is_global:
        raise CloudReadOnlyCapabilityError(
            f"{label} requires explicit private-network Campaign authority"
        )


def _credential_scope_for_binding(campaign_digest: str) -> str:
    return f"campaign-cloud:{campaign_digest}"


def _canonical_provider_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Cloud provider endpoint origin is invalid") from exc
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or "*" in value
        or hostname != hostname.lower()
        or hostname.startswith(".")
        or hostname.endswith(".")
        or ".." in hostname
        or port == 443
    ):
        raise ValueError("Cloud provider endpoint must be one canonical HTTPS origin")
    try:
        canonical_host = hostname.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Cloud provider endpoint hostname is invalid") from exc
    host = f"[{canonical_host}]" if ":" in canonical_host else canonical_host
    canonical = f"https://{host}" + (f":{port}" if port is not None else "")
    if canonical != value:
        raise ValueError("Cloud provider endpoint must be one canonical HTTPS origin")
    return value


def _canonical_provider_target(value: str) -> str:
    try:
        canonical = normalize_target_url(value)
        parsed = urlsplit(canonical)
    except InvalidScopeURL as exc:
        raise ValueError("Cloud provider route target is invalid") from exc
    if (
        parsed.scheme != "https"
        or parsed.query
        or not parsed.path.startswith("/")
        or "*" in value
        or canonical != value
    ):
        raise ValueError("Cloud provider route must be one canonical query-free HTTPS target")
    return value


def _target_origin(value: str) -> str:
    parsed = urlsplit(_canonical_provider_target(value))
    return urlunsplit((parsed.scheme, parsed.netloc, "", "", ""))


def _surface_provider_coordinate(surface: CloudAccountResourceSurface) -> tuple[str, str]:
    locator = surface.locator
    if isinstance(locator, CloudAccountSurfaceLocator):
        account = locator
    elif isinstance(locator, CloudProjectSurfaceLocator):
        account = locator.account
    elif isinstance(
        locator,
        (CloudResourceSurfaceLocator, CloudIAMSurfaceLocator, CloudContainerSurfaceLocator),
    ):
        parent = locator.parent
        account = parent if isinstance(parent, CloudAccountSurfaceLocator) else parent.account
    else:
        raise CloudReadOnlyCapabilityError("Cloud Surface locator type is unsupported")
    return account.provider_id, account.provider_partition


def _validate_cloud_tool_request(request: ToolRequest) -> CloudProviderReadRequest:
    try:
        provider_request = CloudProviderReadRequest.model_validate(request.arguments)
    except (ValidationError, ValueError) as exc:
        raise CloudReadOnlyCapabilityError("Cloud Tool request arguments are invalid") from exc
    if (
        request.tool_id != CLOUD_READ_ONLY_TOOL_ID
        or request.method != "GET"
        or request.target != provider_request.target
    ):
        raise CloudReadOnlyCapabilityError("Cloud Tool request differs from bounded GET authority")
    return provider_request


def _supported_locator_kinds() -> tuple[CloudSurfaceLocatorKind, ...]:
    return (
        "cloud-account",
        "cloud-container",
        "cloud-iam",
        "cloud-project",
        "cloud-resource",
    )


@cache
def _cloud_code_backed_capability() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(CloudReadOnlyInventoryPolicyTool())
    return cloud_read_only_capability_bundle(tools).capability()


@cache
def _cloud_worker_boundary_profile() -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.CLOUD
    )


__all__ = [
    "CLOUD_CAMPAIGN_SCOPE_BINDING_API_VERSION",
    "CLOUD_CREDENTIAL_BINDING",
    "CLOUD_CREDENTIAL_LEASE_REFERENCE_API_VERSION",
    "CLOUD_PROVIDER_ADAPTER_API_VERSION",
    "CLOUD_PROVIDER_READ_REQUEST_API_VERSION",
    "CLOUD_PROVIDER_ROUTE_API_VERSION",
    "CLOUD_READ_ONLY_BINDING_API_VERSION",
    "CLOUD_READ_ONLY_CAPABILITY_ACTIVATION_SET_API_VERSION",
    "CLOUD_READ_ONLY_CAPABILITY_ADAPTER_VERSION",
    "CLOUD_READ_ONLY_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION",
    "CLOUD_READ_ONLY_CAPABILITY_ID",
    "CLOUD_READ_ONLY_CAPABILITY_VERSION",
    "CLOUD_READ_ONLY_PREPARATION_API_VERSION",
    "CLOUD_READ_ONLY_TOOL_ID",
    "CLOUD_SURFACE_SCOPE_ORIGIN",
    "BoundedCloudReadOnlyProviderAdapter",
    "CloudCampaignScopeBinding",
    "CloudCredentialLeaseReference",
    "CloudProviderReadRequest",
    "CloudReadOnlyBudget",
    "CloudReadOnlyCapabilityActivation",
    "CloudReadOnlyCapabilityActivationBinding",
    "CloudReadOnlyCapabilityActivationSet",
    "CloudReadOnlyCapabilityBundle",
    "CloudReadOnlyCapabilityDomainClassification",
    "CloudReadOnlyCapabilityError",
    "CloudReadOnlyInventoryPolicyBinding",
    "CloudReadOnlyInventoryPolicyBindingRef",
    "CloudReadOnlyInventoryPolicyPreparation",
    "CloudReadOnlyInventoryPolicyTool",
    "CloudReadOnlyOperation",
    "CloudReadOnlyProviderAdapterDefinition",
    "CloudReadOnlyProviderAdapterRef",
    "CloudReadOnlyProviderRoute",
    "activate_cloud_read_only_capability",
    "bind_cloud_credential_lease_reference",
    "cloud_credential_lease_scope",
    "cloud_read_only_capability_bundle",
    "cloud_surface_scope_target",
    "prepare_cloud_read_only_inventory_policy",
    "registered_cloud_read_only_capability_definition",
    "registered_cloud_read_only_capability_domain_classification",
    "registered_cloud_read_only_inventory_policy_binding",
    "resolve_cloud_read_only_capability_domain_classification",
    "resolve_cloud_read_only_inventory_policy_binding",
]
