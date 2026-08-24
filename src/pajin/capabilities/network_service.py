"""NET-001B exact passive service-identification Capability and preparation."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Annotated, ClassVar, Literal, Self
from urllib.parse import urlsplit

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
from pajin.capabilities.domain_projection import (
    CapabilityDomainClassificationRef,
)
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
from pajin.discovery.network_surfaces import (
    NetworkAddressFamily,
    NetworkHostServiceLocatorRef,
    NetworkHostServiceLocatorRegistryRef,
    NetworkHostServiceSurface,
    NetworkPortSurfaceLocator,
    NetworkSurfaceClass,
    NetworkTransportProtocol,
    RegisteredNetworkHostServiceLocator,
    registered_network_host_service_locator_registry,
)
from pajin.domain.models import (
    CampaignManifest,
    Scope,
    StrictModel,
    ToolRequest,
    ToolResult,
    campaign_manifest_digest,
)
from pajin.domain.security_domain import SecurityDomain, SecurityDomainClassificationRef
from pajin.graph.authority import (
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    RegisteredActionCapability,
)
from pajin.policy.scope import InvalidScopeURL, normalize_scope_pattern
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import ToolRegistry
from pajin.tools.network import (
    MAX_NETWORK_SERVICE_BANNER_BYTES,
    NETWORK_PASSIVE_BANNER_PROFILE,
    NETWORK_SERVICE_CONNECT_TIMEOUT_MILLISECONDS,
    NETWORK_SERVICE_READ_TIMEOUT_MILLISECONDS,
    NetworkServiceIdentificationInput,
    NetworkServiceIdentificationTool,
    network_service_scope_allow_rule,
    network_service_scope_target,
)

NETWORK_SERVICE_CAPABILITY_ADAPTER_VERSION = (
    "pajin.network-service-identification-capability-adapter/v1"
)
NETWORK_SERVICE_CAPABILITY_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/network-service-capability-activation-set/v1alpha1"
] = "pajin.dev/network-service-capability-activation-set/v1alpha1"
NETWORK_SERVICE_IDENTIFICATION_BINDING_API_VERSION: Literal[
    "pajin.dev/network-service-identification-binding/v1alpha1"
] = "pajin.dev/network-service-identification-binding/v1alpha1"
NETWORK_SERVICE_IDENTIFICATION_PREPARATION_API_VERSION: Literal[
    "pajin.dev/network-service-identification-preparation/v1alpha1"
] = "pajin.dev/network-service-identification-preparation/v1alpha1"
NETWORK_CAMPAIGN_SCOPE_BINDING_API_VERSION: Literal[
    "pajin.dev/network-campaign-scope-binding/v1alpha1"
] = "pajin.dev/network-campaign-scope-binding/v1alpha1"
NETWORK_SERVICE_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION: Literal[
    "pajin.dev/network-service-capability-domain-classification/v1alpha1"
] = "pajin.dev/network-service-capability-domain-classification/v1alpha1"

NETWORK_SERVICE_CAPABILITY_ID = "pajin.network.tcp-passive-service-identification"
NETWORK_SERVICE_CAPABILITY_VERSION = "1.0.0"

_AUTHORITY_VERSION = "1.0.0"
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]

_PARAMETER_SCHEMA: dict[str, JsonValue] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "additionalProperties": False,
    "properties": {
        "addressFamily": {"enum": ["ipv4", "ipv6"], "type": "string"},
        "connectTimeoutMilliseconds": {
            "const": NETWORK_SERVICE_CONNECT_TIMEOUT_MILLISECONDS,
            "type": "integer",
        },
        "host": {"maxLength": 45, "minLength": 1, "type": "string"},
        "maxBannerBytes": {
            "const": MAX_NETWORK_SERVICE_BANNER_BYTES,
            "type": "integer",
        },
        "port": {"maximum": 65_535, "minimum": 1, "type": "integer"},
        "protocolProfile": {"const": NETWORK_PASSIVE_BANNER_PROFILE, "type": "string"},
        "readTimeoutMilliseconds": {
            "const": NETWORK_SERVICE_READ_TIMEOUT_MILLISECONDS,
            "type": "integer",
        },
        "transportProtocol": {"const": "tcp", "type": "string"},
    },
    "required": [
        "addressFamily",
        "connectTimeoutMilliseconds",
        "host",
        "maxBannerBytes",
        "port",
        "protocolProfile",
        "readTimeoutMilliseconds",
        "transportProtocol",
    ],
    "type": "object",
}


class NetworkServiceIdentificationError(ValueError):
    """Raised when NET-001B authority, Scope, Surface, or preparation drifts."""


class NetworkServiceCapabilityDomainClassification(StrictModel):
    """Exact Network classification for the additive NET-001B CAP-002 bundle."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/network-service-capability-domain-classification/v1alpha1"] = (
        Field(
            default=NETWORK_SERVICE_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["NetworkServiceCapabilityDomainClassification"] = (
        "NetworkServiceCapabilityDomainClassification"
    )
    classification_id: str = Field(
        default="",
        alias="classificationId",
        max_length=97,
    )
    classification_digest: str = Field(
        default="",
        alias="classificationDigest",
        max_length=64,
    )
    capability: CapabilityDefinitionRef
    code_backed_capability: CodeBackedCapabilityRef = Field(alias="codeBackedCapability")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    reviewed_surface_types: tuple[Literal["network-port"], ...] = Field(
        default=("network-port",),
        alias="reviewedSurfaceTypes",
    )
    mapping_basis: Literal["net-001b-explicit-code-reviewed-capability-and-surface-set"] = Field(
        default="net-001b-explicit-code-reviewed-capability-and-surface-set",
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
            raise ValueError("Network Capability Domain markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_classification_identity(self) -> Self:
        capability = _network_code_backed_capability()
        worker = _network_worker_boundary_profile()
        if (
            self.capability != capability.capability
            or self.code_backed_capability != capability
            or self.domain_classification != worker.domain_classification
            or self.reviewed_surface_types != ("network-port",)
        ):
            raise ValueError("Network Capability Domain classification differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"classification_id", "classification_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.network-domain-classification/v1",
            material,
        )
        classification_id = f"capability-domain-classification_{digest}"
        if self.classification_digest and self.classification_digest != digest:
            raise ValueError("Network Capability Domain classification digest differs")
        if self.classification_id and self.classification_id != classification_id:
            raise ValueError("Network Capability Domain classification ID differs")
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


class NetworkServiceProtocolBudget(StrictModel):
    """Reviewed passive-banner profile with no application-protocol writes."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    protocol_profile: Literal["tcp-passive-banner-v1"] = Field(
        default="tcp-passive-banner-v1",
        alias="protocolProfile",
    )
    transport_protocol: Literal[NetworkTransportProtocol.TCP] = Field(
        default=NetworkTransportProtocol.TCP,
        alias="transportProtocol",
    )
    connection_units: Literal[1] = Field(default=1, alias="connectionUnits")
    application_write_bytes: Literal[0] = Field(default=0, alias="applicationWriteBytes")
    max_banner_bytes: Literal[1024] = Field(default=1024, alias="maxBannerBytes")
    connect_timeout_milliseconds: Literal[5000] = Field(
        default=5000,
        alias="connectTimeoutMilliseconds",
    )
    read_timeout_milliseconds: Literal[2000] = Field(
        default=2000,
        alias="readTimeoutMilliseconds",
    )

    @field_validator(
        "connection_units",
        "application_write_bytes",
        "max_banner_bytes",
        "connect_timeout_milliseconds",
        "read_timeout_milliseconds",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Network service protocol budgets must be integers")
        return value


class NetworkCampaignScopeBinding(StrictModel):
    """Content-addressed projection of the Campaign fields relevant to one CONNECT."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/network-campaign-scope-binding/v1alpha1"] = Field(
        default=NETWORK_CAMPAIGN_SCOPE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkCampaignScopeBinding"] = "NetworkCampaignScopeBinding"
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
            raise ValueError("Network Campaign Scope markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_scope_projection(self) -> Self:
        if self.allowed_methods != tuple(sorted(set(self.allowed_methods))):
            raise ValueError("Network Campaign allowed methods must be sorted and unique")
        if "CONNECT" not in self.allowed_methods:
            raise ValueError("Network Campaign Scope requires reviewed CONNECT authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.network-campaign-scope-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Network Campaign Scope binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class NetworkServiceCapabilityBundle:
    """Frozen CAP-001/CAP-002 registries for one passive TCP Capability."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capability(self) -> CodeBackedCapabilityRef:
        manifests = self.authorities.capabilities()
        if len(manifests) != 1:
            raise NetworkServiceIdentificationError(
                "Network service Capability authority inventory drifted"
            )
        return manifests[0].reference()


class NetworkServiceCapabilityActivationBinding(StrictModel):
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
            definition.capability_id != NETWORK_SERVICE_CAPABILITY_ID
            or definition.capability_version != NETWORK_SERVICE_CAPABILITY_VERSION
            or action.capability_id != definition.capability_id
            or action.capability_version != definition.capability_version
            or action.definition_digest != definition.capability_digest
        ):
            raise ValueError("Network service activation references another Capability")
        return self


class NetworkServiceCapabilityActivationSet(StrictModel):
    """Content-addressed activation of exactly one signed Network release."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/network-service-capability-activation-set/v1alpha1"] = Field(
        default=NETWORK_SERVICE_CAPABILITY_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkServiceCapabilityActivationSet"] = "NetworkServiceCapabilityActivationSet"
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=128)
    activation_set_digest: str = Field(default="", alias="activationSetDigest", max_length=64)
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: NetworkServiceCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.network-service-activation-set/v1",
            material,
        )
        activation_set_id = f"network-service-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("Network service activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("Network service activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class NetworkServiceCapabilityActivation:
    """Runtime activation that rechecks the signed current release on every use."""

    bundle: NetworkServiceCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: NetworkServiceCapabilityActivationSet

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
            raise NetworkServiceIdentificationError(
                "Network service activated Definition is unavailable"
            ) from exc

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise NetworkServiceIdentificationError(
                "Network service CAP-002 authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(self, reference: ActionCapabilityRef) -> ResolvedCapabilityRelease:
        try:
            canonical = ActionCapabilityRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise NetworkServiceIdentificationError(
                "Network service GRAPH Capability reference is not canonical"
            ) from exc
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise NetworkServiceIdentificationError(
                "Network service GRAPH Capability is outside the activation"
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
            raise NetworkServiceIdentificationError(
                "Network service release is outside the activation"
            )
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
            raise NetworkServiceIdentificationError(
                "Network service CAP-002 request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


class _NetworkServiceAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        definition: CapabilityDefinition,
        tool: NetworkServiceIdentificationTool,
    ) -> None:
        self._definition = definition
        self._tool = tool

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{NETWORK_SERVICE_CAPABILITY_ID}.{self.authority_role.value}"

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
            "adapterContractVersion": NETWORK_SERVICE_CAPABILITY_ADAPTER_VERSION,
            "method": "CONNECT",
            "parameterSchemaDigest": self._definition.parameter_schema_digest,
            "protocolBudget": NetworkServiceProtocolBudget().model_dump(
                mode="json",
                by_alias=True,
            ),
            "replayAuthorized": False,
            "cleanupAuthorized": False,
            "tool": {
                "type": (f"{type(self._tool).__module__}.{type(self._tool).__qualname__}"),
                "context": {
                    "implementationVersion": "pajin.tool-adapter/v1",
                    "spec": tool_spec,
                },
            },
        }


class _NetworkServiceMaterializer(_NetworkServiceAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            probe = NetworkServiceIdentificationInput.model_validate(dict(parameters))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Network service parameters differ from the fixed passive profile"
            ) from exc
        return probe.model_dump(mode="json", by_alias=True)


class _NetworkServiceActionCompiler(_NetworkServiceAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        try:
            probe = NetworkServiceIdentificationInput.model_validate(dict(materialized_arguments))
        except (TypeError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "Network service materialized parameters are invalid"
            ) from exc
        expected_target = network_service_scope_target(
            address_family=probe.address_family,
            host=probe.host,
            port=probe.port,
        )
        if (
            request.tool_id != NetworkServiceIdentificationTool.spec.tool_id
            or request.method != "CONNECT"
            or request.target != expected_target
            or request.arguments
        ):
            raise CapabilityAuthorityError(
                "Network service compiler accepts only one exact empty CONNECT request"
            )
        return request.model_copy(
            update={"arguments": probe.model_dump(mode="json", by_alias=True)}
        )


class _NetworkServiceExecutorAdapter(_NetworkServiceAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)


class _NetworkServiceResultNormalizer(_NetworkServiceAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)


class _NetworkServiceSuccessOracle(_NetworkServiceAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        del request
        if result.data.get("connected") is True and result.error is None:
            return CapabilityOracleDecision.SUCCEEDED
        if result.data.get("connected") is False or result.error is not None:
            return CapabilityOracleDecision.FAILED
        return CapabilityOracleDecision.INCONCLUSIVE


class _NetworkServiceReplayStrategy(_NetworkServiceAuthorityBase):
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


class _NetworkServiceCleanupHandler(_NetworkServiceAuthorityBase):
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


def registered_network_service_capability_definition() -> CapabilityDefinition:
    """Return the exact CAP-001 metadata for the passive TCP Capability."""

    return capability_definition_from_tool(
        NetworkServiceIdentificationTool.spec,
        ToolCapabilityRegistration(
            capabilityId=NETWORK_SERVICE_CAPABILITY_ID,
            capabilityVersion=NETWORK_SERVICE_CAPABILITY_VERSION,
            toolId=NetworkServiceIdentificationTool.spec.tool_id,
            domain="network",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=("network-port",),
            threatClasses=("service-identification",),
            preconditions=(
                "current-campaign-scope",
                "fresh-signed-authorization",
                "one-use-action-permit",
                "reviewed-passive-banner-protocol",
                "worker-direct-mtls",
            ),
            parameterSchemaDigest=capability_parameter_schema_digest(_PARAMETER_SCHEMA),
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=1,
        ),
    )


def network_service_capability_bundle(tools: ToolRegistry) -> NetworkServiceCapabilityBundle:
    """Bind the exact Network Tool to all seven required CAP-002 roles."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("Network service Capability requires a ToolRegistry")
    try:
        tool = tools.tool(NetworkServiceIdentificationTool.spec.tool_id)
        spec = tools.spec(NetworkServiceIdentificationTool.spec.tool_id)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise NetworkServiceIdentificationError(
            "Network service identification Tool is unavailable"
        ) from exc
    if (
        type(tool) is not NetworkServiceIdentificationTool
        or spec != NetworkServiceIdentificationTool.spec
    ):
        raise NetworkServiceIdentificationError(
            "Network service identification Tool implementation drifted"
        )
    definition = registered_network_service_capability_definition()
    definitions = CapabilityDefinitionRegistry((definition,))
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _NetworkServiceActionCompiler(definition, tool),
        _NetworkServiceCleanupHandler(definition, tool),
        _NetworkServiceExecutorAdapter(definition, tool),
        _NetworkServiceMaterializer(definition, tool),
        _NetworkServiceReplayStrategy(definition, tool),
        _NetworkServiceResultNormalizer(definition, tool),
        _NetworkServiceSuccessOracle(definition, tool),
    )
    return NetworkServiceCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_network_service_capability(
    *,
    bundle: NetworkServiceCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> NetworkServiceCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if not isinstance(bundle, NetworkServiceCapabilityBundle):
        raise TypeError("Network service activation requires its exact Capability bundle")
    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("Network service activation requires a verified lifecycle registry")
    canonical_release = _canonical_release_ref(release)
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        capability = bundle.capability()
        definition = bundle.definitions.resolve(capability.capability)
    except (CapabilityAuthorityError, CapabilityDefinitionError, CapabilityLifecycleError) as exc:
        raise NetworkServiceIdentificationError(
            "Network service signed release activation failed closed"
        ) from exc
    if (
        resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition != registered_network_service_capability_definition()
    ):
        raise NetworkServiceIdentificationError(
            "Network service signed release differs from code authority"
        )
    binding = NetworkServiceCapabilityActivationBinding(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    activation_set = NetworkServiceCapabilityActivationSet(binding=binding)
    return NetworkServiceCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=activation_set,
    )


class NetworkServiceIdentificationBindingRef(StrictModel):
    """Exact content-addressed reference to the NET-001B binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: Literal["pajin.network.service-identification.passive-banner-binding"] = Field(
        alias="bindingId"
    )
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")


class NetworkServiceIdentificationBinding(StrictModel):
    """Exact Surface/CAP-002/Network Worker binding without dispatch authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/network-service-identification-binding/v1alpha1"] = Field(
        default=NETWORK_SERVICE_IDENTIFICATION_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkServiceIdentificationBinding"] = "NetworkServiceIdentificationBinding"
    binding_id: Literal["pajin.network.service-identification.passive-banner-binding"] = Field(
        default="pajin.network.service-identification.passive-banner-binding",
        alias="bindingId",
    )
    binding_version: Literal["1.0.0"] = Field(default="1.0.0", alias="bindingVersion")
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    surface_type: Literal["network.host-service"] = Field(
        default="network.host-service",
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.network.host-service.v1"] = Field(
        default="pajin.locator.network.host-service.v1",
        alias="locatorSchema",
    )
    locator_registry: NetworkHostServiceLocatorRegistryRef = Field(alias="locatorRegistry")
    supported_locator: NetworkHostServiceLocatorRef = Field(alias="supportedLocator")
    capability: CodeBackedCapabilityRef
    capability_domain_classification: NetworkServiceCapabilityDomainClassification = Field(
        alias="capabilityDomainClassification"
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    protocol_budget: NetworkServiceProtocolBudget = Field(alias="protocolBudget")
    supported_address_families: tuple[Literal["ipv4", "ipv6"], ...] = Field(
        default=("ipv4", "ipv6"),
        alias="supportedAddressFamilies",
    )
    connect_method: Literal["CONNECT"] = Field(default="CONNECT", alias="connectMethod")
    scope_projection: Literal["exact-https-connect-authority"] = Field(
        default="exact-https-connect-authority",
        alias="scopeProjection",
    )
    binding_only: Literal[True] = Field(default=True, alias="bindingOnly")
    complete_cap_002_verified: Literal[True] = Field(
        default=True,
        alias="completeCAP002Verified",
    )
    preparation_available: Literal[True] = Field(
        default=True,
        alias="preparationAvailable",
    )
    current_capability_activation_required: Literal[True] = Field(
        default=True,
        alias="currentCapabilityActivationRequired",
    )
    current_campaign_scope_required: Literal[True] = Field(
        default=True,
        alias="currentCampaignScopeRequired",
    )
    reviewed_connect_protocol_required: Literal[True] = Field(
        default=True,
        alias="reviewedConnectProtocolRequired",
    )
    action_permit_required: Literal[True] = Field(default=True, alias="actionPermitRequired")
    gateway_policy_reentry_required: Literal[True] = Field(
        default=True,
        alias="gatewayPolicyReentryRequired",
    )
    trusted_connect_receipt_required: Literal[True] = Field(
        default=True,
        alias="trustedConnectReceiptRequired",
    )
    worker_deployment_binding_required: Literal[True] = Field(
        default=True,
        alias="workerDeploymentBindingRequired",
    )
    worker_direct_mtls_required: Literal[True] = Field(
        default=True,
        alias="workerDirectMTLSRequired",
    )
    name_resolution_authorized: Literal[False] = Field(
        default=False,
        alias="nameResolutionAuthorized",
    )
    udp_authorized: Literal[False] = Field(default=False, alias="udpAuthorized")
    application_protocol_write_authorized: Literal[False] = Field(
        default=False,
        alias="applicationProtocolWriteAuthorized",
    )
    port_enumeration_authorized: Literal[False] = Field(
        default=False,
        alias="portEnumerationAuthorized",
    )
    raw_socket_authorized: Literal[False] = Field(default=False, alias="rawSocketAuthorized")
    ambient_credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="ambientCredentialUseAuthorized",
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
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "reviewed_connect_protocol_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "trusted_connect_receipt_required",
        "worker_deployment_binding_required",
        "worker_direct_mtls_required",
        "name_resolution_authorized",
        "udp_authorized",
        "application_protocol_write_authorized",
        "port_enumeration_authorized",
        "raw_socket_authorized",
        "ambient_credential_use_authorized",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "worker_selection_authorized",
        "graph_admission_authorized",
        "runtime_support_asserted_by_binding",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Network service binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_binding(self) -> Self:
        definition = registered_network_service_capability_definition()
        worker = _network_worker_boundary_profile()
        registry = registered_network_host_service_locator_registry()
        if (
            self.locator_registry != registry.reference()
            or self.supported_locator != _network_port_registration().reference()
            or self.capability != _network_code_backed_capability()
            or self.capability_domain_classification
            != registered_network_service_capability_domain_classification()
            or self.worker_profile != worker.reference()
            or self.protocol_budget != NetworkServiceProtocolBudget()
            or self.supported_address_families != ("ipv4", "ipv6")
            or definition.supported_surface_types != ("network-port",)
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.tool.tool_id != NetworkServiceIdentificationTool.spec.tool_id
            or definition.network_access is not True
            or definition.approval_required is not True
            or worker.network_boundary is not WorkerNetworkBoundary.EXACT_HOST_PROTOCOL_PORT
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.NO_HOST_ACCESS
            or worker.credential_boundary is not WorkerCredentialBoundary.NONE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.ISOLATED_NON_ROOT
            or worker.required_identity_dimensions != ("address-family", "host", "port", "protocol")
            or worker.required_budget_dimensions != ("probe-count", "response-bytes", "runtime")
            or worker.protocol_privilege_review_required is not True
        ):
            raise ValueError("Network service identification binding differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.network-service-identification-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Network service identification binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self

    def reference(self) -> NetworkServiceIdentificationBindingRef:
        return NetworkServiceIdentificationBindingRef(
            bindingId=self.binding_id,
            bindingVersion=self.binding_version,
            bindingDigest=self.binding_digest,
        )


class NetworkServiceIdentificationPreparation(StrictModel):
    """Exact scoped CAP-002 preparation with no Permit, Worker, or network authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/network-service-identification-preparation/v1alpha1"] = Field(
        default=NETWORK_SERVICE_IDENTIFICATION_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkServiceIdentificationPreparation"] = (
        "NetworkServiceIdentificationPreparation"
    )
    preparation_id: str = Field(default="", alias="preparationId", max_length=100)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: NetworkServiceIdentificationBinding
    surface: NetworkHostServiceSurface
    campaign_scope: NetworkCampaignScopeBinding = Field(alias="campaignScope")
    matched_allow_rule: str = Field(alias="matchedAllowRule", min_length=1, max_length=2_000)
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    protocol_budget: NetworkServiceProtocolBudget = Field(alias="protocolBudget")
    state: Literal["prepared-not-authorized"] = "prepared-not-authorized"
    capability_prepared: Literal[True] = Field(default=True, alias="capabilityPrepared")
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    egress_policy_materialized: Literal[False] = Field(
        default=False,
        alias="egressPolicyMaterialized",
    )
    name_resolution_performed: Literal[False] = Field(
        default=False,
        alias="nameResolutionPerformed",
    )
    network_connection_opened: Literal[False] = Field(
        default=False,
        alias="networkConnectionOpened",
    )
    service_observation_produced: Literal[False] = Field(
        default=False,
        alias="serviceObservationProduced",
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

    @field_validator(
        "capability_prepared",
        "worker_job_materialized",
        "egress_policy_materialized",
        "name_resolution_performed",
        "network_connection_opened",
        "service_observation_produced",
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
            raise ValueError("Network service preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        locator = self.surface.locator
        expected_action = registered_action_capability(
            registered_network_service_capability_definition()
        ).reference()
        if not isinstance(locator, NetworkPortSurfaceLocator):
            raise ValueError("Network service preparation requires a network-port Surface")
        expected_rule = _require_surface_in_scope(self.campaign_scope, locator)
        expected_parameters = _parameters_for_locator(locator)
        request = self.prepared_action.request
        if (
            self.binding != registered_network_service_identification_binding()
            or self.surface.initial_state != "registered-not-authorized"
            or self.matched_allow_rule != expected_rule
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != NetworkServiceIdentificationTool.spec.tool_id
            or request.method != "CONNECT"
            or request.target != _target_for_locator(locator)
            or request.arguments != expected_parameters
            or self.protocol_budget != NetworkServiceProtocolBudget()
        ):
            raise ValueError("Network service preparation differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.network-service-identification-preparation/v1",
            material,
        )
        preparation_id = f"network-service-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Network service preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("Network service preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


def registered_network_service_identification_binding() -> NetworkServiceIdentificationBinding:
    """Return the exact NET-001B binding without activation or Worker selection."""

    registry = registered_network_host_service_locator_registry()
    return NetworkServiceIdentificationBinding(
        locatorRegistry=registry.reference(),
        supportedLocator=_network_port_registration().reference(),
        capability=_network_code_backed_capability(),
        capabilityDomainClassification=(
            registered_network_service_capability_domain_classification()
        ),
        workerProfile=_network_worker_boundary_profile().reference(),
        protocolBudget=NetworkServiceProtocolBudget(),
    )


def resolve_network_service_identification_binding(
    reference: NetworkServiceIdentificationBindingRef,
) -> NetworkServiceIdentificationBinding:
    binding = registered_network_service_identification_binding()
    if binding.reference() == reference:
        return binding.model_copy(deep=True)
    raise NetworkServiceIdentificationError(
        "Network service identification binding is not registered exactly"
    )


def registered_network_service_capability_domain_classification() -> (
    NetworkServiceCapabilityDomainClassification
):
    capability = _network_code_backed_capability()
    return NetworkServiceCapabilityDomainClassification(
        capability=capability.capability,
        codeBackedCapability=capability,
        domainClassification=_network_worker_boundary_profile().domain_classification,
    )


def resolve_network_service_capability_domain_classification(
    reference: CapabilityDomainClassificationRef,
) -> NetworkServiceCapabilityDomainClassification:
    classification = registered_network_service_capability_domain_classification()
    if classification.reference() == reference:
        return classification.model_copy(deep=True)
    raise NetworkServiceIdentificationError(
        "Network service Capability Domain classification is not registered exactly"
    )


def prepare_network_service_identification(
    *,
    activation: NetworkServiceCapabilityActivation,
    release: CapabilityReleaseRef,
    campaign: CampaignManifest,
    surface: NetworkHostServiceSurface,
    request_id: str,
    agent_id: str,
) -> NetworkServiceIdentificationPreparation:
    """Compile one scoped IP-literal TCP Surface through current signed CAP-002 only."""

    if not isinstance(activation, NetworkServiceCapabilityActivation):
        raise TypeError("Network service preparation requires Network service activation")
    canonical_campaign = _canonical_campaign(campaign)
    canonical_surface = _canonical_surface(surface)
    locator = canonical_surface.locator
    if not isinstance(locator, NetworkPortSurfaceLocator):
        raise NetworkServiceIdentificationError(
            "Network service preparation accepts only a network-port Surface"
        )
    scope_binding = _campaign_scope_binding(canonical_campaign)
    matched_rule = _require_surface_in_scope(scope_binding, locator)
    binding = registered_network_service_identification_binding()
    try:
        if (
            activation.bundle.capability() != binding.capability
            or activation.definition() != registered_network_service_capability_definition()
        ):
            raise NetworkServiceIdentificationError(
                "Network service activation differs from the registered Capability"
            )
        parameters = _parameters_for_locator(locator)
        request = ToolRequest(
            request_id=request_id,
            agent_id=agent_id,
            tool_id=NetworkServiceIdentificationTool.spec.tool_id,
            target=_target_for_locator(locator),
            method="CONNECT",
            arguments={},
        )
        prepared = activation.prepare_action(
            release=release,
            request=request,
            parameters=parameters,
        )
        return NetworkServiceIdentificationPreparation(
            binding=binding,
            surface=canonical_surface,
            campaignScope=scope_binding,
            matchedAllowRule=matched_rule,
            release=release,
            preparedAction=prepared,
            protocolBudget=NetworkServiceProtocolBudget(),
        )
    except (CapabilityAuthorityError, ValidationError, ValueError) as exc:
        if isinstance(exc, NetworkServiceIdentificationError):
            raise
        raise NetworkServiceIdentificationError(
            "Network service CAP-002 preparation failed closed"
        ) from exc


def _verify_activation(activation: NetworkServiceCapabilityActivation) -> None:
    try:
        canonical_set = NetworkServiceCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise NetworkServiceIdentificationError(
            "Network service activation set is not canonical"
        ) from exc
    if canonical_set != activation.activation_set:
        raise NetworkServiceIdentificationError("Network service activation set drifted")
    _resolve_activation_binding(activation, canonical_set.binding)


def _resolve_activation_binding(
    activation: NetworkServiceCapabilityActivation,
    binding: NetworkServiceCapabilityActivationBinding,
) -> ResolvedCapabilityRelease:
    try:
        resolved = activation.lifecycle.resolve_for_use(
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        signed_bundle = activation.lifecycle.resolve_release(binding.release)
        code_capability = activation.bundle.capability()
    except (CapabilityAuthorityError, CapabilityLifecycleError) as exc:
        raise NetworkServiceIdentificationError(
            "Network service current signed release could not be resolved"
        ) from exc
    if (
        resolved.capability.reference() != binding.capability
        or code_capability != binding.capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(signed_bundle) != binding.release_bundle_digest
    ):
        raise NetworkServiceIdentificationError("Network service signed activation drifted")
    return resolved


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.network-service-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    try:
        return CapabilityReleaseRef.model_validate(reference.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise NetworkServiceIdentificationError(
            "Network service release reference is not canonical"
        ) from exc


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    try:
        return ToolRequest.model_validate(request.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise NetworkServiceIdentificationError(
            "Network service Tool request is not canonical"
        ) from exc


def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
    try:
        return CampaignManifest.model_validate(campaign.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise NetworkServiceIdentificationError(
            "Network service Campaign is not canonical"
        ) from exc


def _canonical_surface(surface: NetworkHostServiceSurface) -> NetworkHostServiceSurface:
    try:
        return NetworkHostServiceSurface.model_validate(
            surface.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise NetworkServiceIdentificationError("Network service Surface is not canonical") from exc


def _campaign_scope_binding(campaign: CampaignManifest) -> NetworkCampaignScopeBinding:
    return NetworkCampaignScopeBinding(
        campaignName=campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(campaign),
        scope=campaign.spec.scope.model_copy(deep=True),
        allowedMethods=tuple(sorted(campaign.spec.rules_of_engagement.allowed_methods)),
        allowPrivateNetworks=campaign.spec.rules_of_engagement.allow_private_networks,
    )


def _require_surface_in_scope(
    scope_binding: NetworkCampaignScopeBinding,
    locator: NetworkPortSurfaceLocator,
) -> str:
    if (
        locator.transport_protocol is not NetworkTransportProtocol.TCP
        or locator.host.address_family not in {NetworkAddressFamily.IPV4, NetworkAddressFamily.IPV6}
    ):
        raise NetworkServiceIdentificationError(
            "Network service preparation supports only IP-literal TCP coordinates"
        )
    address = ip_address(locator.host.host)
    if not address.is_global and not scope_binding.allow_private_networks:
        raise NetworkServiceIdentificationError(
            "Network service target requires explicit private-network Campaign authority"
        )
    expected = network_service_scope_allow_rule(
        address_family=locator.host.address_family.value,
        host=locator.host.host,
        port=locator.port,
    )
    try:
        normalized_allow = [normalize_scope_pattern(rule) for rule in scope_binding.scope.allow]
        normalized_deny = [normalize_scope_pattern(rule) for rule in scope_binding.scope.deny]
    except InvalidScopeURL as exc:
        raise NetworkServiceIdentificationError(
            "Network service Campaign Scope cannot be evaluated safely"
        ) from exc
    if expected not in normalized_allow:
        raise NetworkServiceIdentificationError(
            "Network service coordinate lacks an exact host-wide Campaign allow rule"
        )
    expected_authority = urlsplit(expected).netloc
    if any(urlsplit(rule).netloc == expected_authority for rule in normalized_deny):
        raise NetworkServiceIdentificationError(
            "Network service coordinate overlaps a Campaign deny rule"
        )
    return expected


def _parameters_for_locator(locator: NetworkPortSurfaceLocator) -> dict[str, JsonValue]:
    return NetworkServiceIdentificationInput(
        addressFamily=locator.host.address_family.value,
        host=locator.host.host,
        transportProtocol=locator.transport_protocol.value,
        port=locator.port,
        protocolProfile=NETWORK_PASSIVE_BANNER_PROFILE,
        connectTimeoutMilliseconds=NETWORK_SERVICE_CONNECT_TIMEOUT_MILLISECONDS,
        readTimeoutMilliseconds=NETWORK_SERVICE_READ_TIMEOUT_MILLISECONDS,
        maxBannerBytes=MAX_NETWORK_SERVICE_BANNER_BYTES,
    ).model_dump(mode="json", by_alias=True)


def _target_for_locator(locator: NetworkPortSurfaceLocator) -> str:
    return network_service_scope_target(
        address_family=locator.host.address_family.value,
        host=locator.host.host,
        port=locator.port,
    )


def _network_code_backed_capability() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(NetworkServiceIdentificationTool())
    return network_service_capability_bundle(tools).capability()


def _network_worker_boundary_profile() -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.NETWORK
    )


def _network_port_registration() -> RegisteredNetworkHostServiceLocator:
    return next(
        item
        for item in registered_network_host_service_locator_registry().locators
        if item.surface_class is NetworkSurfaceClass.PORT
    )


__all__ = [
    "NETWORK_CAMPAIGN_SCOPE_BINDING_API_VERSION",
    "NETWORK_SERVICE_CAPABILITY_ACTIVATION_SET_API_VERSION",
    "NETWORK_SERVICE_CAPABILITY_ADAPTER_VERSION",
    "NETWORK_SERVICE_CAPABILITY_DOMAIN_CLASSIFICATION_API_VERSION",
    "NETWORK_SERVICE_CAPABILITY_ID",
    "NETWORK_SERVICE_CAPABILITY_VERSION",
    "NETWORK_SERVICE_IDENTIFICATION_BINDING_API_VERSION",
    "NETWORK_SERVICE_IDENTIFICATION_PREPARATION_API_VERSION",
    "NetworkCampaignScopeBinding",
    "NetworkServiceCapabilityActivation",
    "NetworkServiceCapabilityActivationBinding",
    "NetworkServiceCapabilityActivationSet",
    "NetworkServiceCapabilityBundle",
    "NetworkServiceCapabilityDomainClassification",
    "NetworkServiceIdentificationBinding",
    "NetworkServiceIdentificationBindingRef",
    "NetworkServiceIdentificationError",
    "NetworkServiceIdentificationPreparation",
    "NetworkServiceProtocolBudget",
    "activate_network_service_capability",
    "network_service_capability_bundle",
    "prepare_network_service_identification",
    "registered_network_service_capability_definition",
    "registered_network_service_capability_domain_classification",
    "registered_network_service_identification_binding",
    "resolve_network_service_capability_domain_classification",
    "resolve_network_service_identification_binding",
]
