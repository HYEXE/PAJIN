"""WEB-001B binding for read-only HTTP discovery through existing CAP-002 authority."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.activation import PreparedCapabilityAction
from pajin.capabilities.adapters import registered_action_capability
from pajin.capabilities.authorities import CodeBackedCapabilityRef
from pajin.capabilities.domain_projection import (
    CapabilityDomainClassificationRef,
    RegisteredCapabilityDomainClassification,
)
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.capabilities.models import CapabilitySideEffectClass, capability_definition_digest
from pajin.capabilities.pentest_recon import (
    PENTEST_RECON_CAPABILITY_ID,
    PENTEST_RECON_CAPABILITY_VERSION,
    PentestReconCapabilityActivation,
    PentestReconCapabilityError,
    pentest_recon_capability_bundle,
    registered_pentest_recon_capability_definition,
)
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    RegisteredDomainWorkerBoundaryProfile,
    WorkerCredentialBoundary,
    WorkerFilesystemBoundary,
    WorkerNetworkBoundary,
    WorkerRuntimeBoundary,
    registered_domain_worker_boundary_profiles,
)
from pajin.discovery.models import HTTPRouteSurfaceLocator, HTTPSurfaceLocator
from pajin.discovery.web_surfaces import (
    RegisteredWebHTTPOperationLocator,
    WebHTTPOperationLocatorRef,
    WebHTTPOperationLocatorRegistryRef,
    WebHTTPOperationSurface,
    registered_web_http_operation_locator_registry,
)
from pajin.domain.models import StrictModel, ToolRequest
from pajin.domain.security_domain import SecurityDomain
from pajin.tools.base import ToolRegistry
from pajin.tools.http import MAX_HTTP_GET_RESPONSE_BYTES, HTTPGetTool

WEB_READ_ONLY_DISCOVERY_BINDING_API_VERSION: Literal[
    "pajin.dev/web-read-only-discovery-binding/v1alpha1"
] = "pajin.dev/web-read-only-discovery-binding/v1alpha1"
WEB_READ_ONLY_DISCOVERY_PREPARATION_API_VERSION: Literal[
    "pajin.dev/web-read-only-discovery-preparation/v1alpha1"
] = "pajin.dev/web-read-only-discovery-preparation/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_PreparationId = Annotated[
    str,
    Field(pattern=r"^web-discovery-preparation_[a-f0-9]{64}$"),
]


class WebReadOnlyDiscoveryError(ValueError):
    """Raised when WEB-001B source, Surface, activation, or preparation drifts."""


class WebReadOnlyDiscoveryBindingRef(StrictModel):
    """Exact content-addressed reference to the WEB-001B binding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding_id: Literal["pajin.web.discovery.http-get-binding"] = Field(alias="bindingId")
    binding_version: Literal["1.0.0"] = Field(alias="bindingVersion")
    binding_digest: _Sha256 = Field(alias="bindingDigest")


class WebReadOnlyDiscoveryBinding(StrictModel):
    """Exact Web Surface/CAP-002/Worker-boundary binding without activation authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-read-only-discovery-binding/v1alpha1"] = Field(
        default=WEB_READ_ONLY_DISCOVERY_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebReadOnlyDiscoveryBinding"] = "WebReadOnlyDiscoveryBinding"
    binding_id: Literal["pajin.web.discovery.http-get-binding"] = Field(
        default="pajin.web.discovery.http-get-binding",
        alias="bindingId",
    )
    binding_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="bindingVersion",
    )
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    surface_type: Literal["web.http-operation"] = Field(
        default="web.http-operation",
        alias="surfaceType",
    )
    locator_schema: Literal["pajin.locator.web.http-operation.v1"] = Field(
        default="pajin.locator.web.http-operation.v1",
        alias="locatorSchema",
    )
    locator_registry: WebHTTPOperationLocatorRegistryRef = Field(alias="locatorRegistry")
    supported_locator: WebHTTPOperationLocatorRef = Field(alias="supportedLocator")
    capability: CodeBackedCapabilityRef
    capability_domain_classification: CapabilityDomainClassificationRef = Field(
        alias="capabilityDomainClassification"
    )
    worker_profile: DomainWorkerBoundaryProfileRef = Field(alias="workerProfile")
    method: Literal["GET"] = "GET"
    side_effect_class: Literal[CapabilitySideEffectClass.READ_ONLY] = Field(
        default=CapabilitySideEffectClass.READ_ONLY,
        alias="sideEffectClass",
    )
    request_units: Literal[1] = Field(default=1, alias="requestUnits")
    max_response_bytes: Literal[4096] = Field(default=4096, alias="maxResponseBytes")
    binding_only: Literal[True] = Field(default=True, alias="bindingOnly")
    complete_cap_002_verified: Literal[True] = Field(
        default=True,
        alias="completeCAP002Verified",
    )
    preparation_available: Literal[True] = Field(
        default=True,
        alias="preparationAvailable",
    )
    gateway_egress_required: Literal[True] = Field(
        default=True,
        alias="gatewayEgressRequired",
    )
    current_capability_activation_required: Literal[True] = Field(
        default=True,
        alias="currentCapabilityActivationRequired",
    )
    current_campaign_scope_required: Literal[True] = Field(
        default=True,
        alias="currentCampaignScopeRequired",
    )
    action_permit_required: Literal[True] = Field(
        default=True,
        alias="actionPermitRequired",
    )
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
    uri_template_materialization_available: Literal[False] = Field(
        default=False,
        alias="uriTemplateMaterializationAvailable",
    )
    redirect_follow_authorized: Literal[False] = Field(
        default=False,
        alias="redirectFollowAuthorized",
    )
    ambient_credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="ambientCredentialUseAuthorized",
    )
    domain_metadata_authority: Literal[False] = Field(
        default=False,
        alias="domainMetadataAuthority",
    )
    surface_metadata_authority: Literal[False] = Field(
        default=False,
        alias="surfaceMetadataAuthority",
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
    finding_confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="findingConfirmationAuthorized",
    )
    runtime_support_asserted_by_binding: Literal[False] = Field(
        default=False,
        alias="runtimeSupportAssertedByBinding",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "request_units",
        "max_response_bytes",
        mode="before",
    )
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Web discovery budget limits must be integers")
        return value

    @field_validator(
        "binding_only",
        "complete_cap_002_verified",
        "preparation_available",
        "gateway_egress_required",
        "current_capability_activation_required",
        "current_campaign_scope_required",
        "action_permit_required",
        "gateway_policy_reentry_required",
        "worker_deployment_binding_required",
        "worker_direct_mtls_required",
        "uri_template_materialization_available",
        "redirect_follow_authorized",
        "ambient_credential_use_authorized",
        "domain_metadata_authority",
        "surface_metadata_authority",
        "scope_expansion_authorized",
        "capability_activation_authorized",
        "approval_satisfied",
        "permit_issuance_authorized",
        "worker_selection_authorized",
        "graph_admission_authorized",
        "finding_confirmation_authorized",
        "runtime_support_asserted_by_binding",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Web discovery binding markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_exact_binding(self) -> Self:
        definition = registered_pentest_recon_capability_definition()
        worker = _web_worker_boundary_profile()
        locator_registry = registered_web_http_operation_locator_registry()
        if (
            self.locator_registry != locator_registry.reference()
            or self.supported_locator != _concrete_locator_registration().reference()
            or self.capability != _pentest_recon_code_backed_capability()
            or self.capability_domain_classification != _capability_domain_classification()
            or self.worker_profile != worker.reference()
            or definition.capability_id != PENTEST_RECON_CAPABILITY_ID
            or definition.capability_version != PENTEST_RECON_CAPABILITY_VERSION
            or definition.supported_surface_types != ("http-endpoint",)
            or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
            or definition.tool.tool_id != HTTPGetTool.spec.tool_id
            or definition.tool.tool_version != HTTPGetTool.spec.version
            or definition.network_access is not True
            or worker.network_boundary is not WorkerNetworkBoundary.BOUNDED_EGRESS
            or worker.filesystem_boundary is not WorkerFilesystemBoundary.NO_HOST_ACCESS
            or worker.credential_boundary is not WorkerCredentialBoundary.NONE
            or worker.runtime_boundary is not WorkerRuntimeBoundary.ISOLATED_NON_ROOT
            or self.max_response_bytes != MAX_HTTP_GET_RESPONSE_BYTES
        ):
            raise ValueError("Web read-only discovery binding differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.web-read-only-discovery-binding/v1",
            material,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Web read-only discovery binding digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self

    def reference(self) -> WebReadOnlyDiscoveryBindingRef:
        """Return the exact detached binding identity."""

        return WebReadOnlyDiscoveryBindingRef(
            bindingId=self.binding_id,
            bindingVersion=self.binding_version,
            bindingDigest=self.binding_digest,
        )


class WebReadOnlyDiscoveryPreparation(StrictModel):
    """Exact prepared GET request that still requires Permit, Gateway, and Worker authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-read-only-discovery-preparation/v1alpha1"] = Field(
        default=WEB_READ_ONLY_DISCOVERY_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebReadOnlyDiscoveryPreparation"] = "WebReadOnlyDiscoveryPreparation"
    preparation_id: str = Field(default="", alias="preparationId", max_length=91)
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    binding: WebReadOnlyDiscoveryBinding
    surface: WebHTTPOperationSurface
    release: CapabilityReleaseRef
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    state: Literal["prepared-not-authorized"] = "prepared-not-authorized"
    request_units: Literal[1] = Field(default=1, alias="requestUnits")
    capability_prepared: Literal[True] = Field(default=True, alias="capabilityPrepared")
    gateway_egress_required: Literal[True] = Field(
        default=True,
        alias="gatewayEgressRequired",
    )
    worker_job_materialized: Literal[False] = Field(
        default=False,
        alias="workerJobMaterialized",
    )
    egress_policy_materialized: Literal[False] = Field(
        default=False,
        alias="egressPolicyMaterialized",
    )
    discovery_observation_produced: Literal[False] = Field(
        default=False,
        alias="discoveryObservationProduced",
    )
    evidence_sealed: Literal[False] = Field(default=False, alias="evidenceSealed")
    graph_admitted: Literal[False] = Field(default=False, alias="graphAdmitted")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
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
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator("request_units", mode="before")
    @classmethod
    def require_exact_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Web discovery preparation request units must be an integer")
        return value

    @field_validator(
        "capability_prepared",
        "gateway_egress_required",
        "worker_job_materialized",
        "egress_policy_materialized",
        "discovery_observation_produced",
        "evidence_sealed",
        "graph_admitted",
        "scope_expansion_authorized",
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
            raise ValueError("Web discovery preparation markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        binding = registered_web_read_only_discovery_binding()
        expected_action = registered_action_capability(
            registered_pentest_recon_capability_definition()
        ).reference()
        locator = self.surface.locator
        request = self.prepared_action.request
        if (
            self.binding != binding
            or not isinstance(locator, HTTPSurfaceLocator)
            or locator.method != "GET"
            or self.surface.initial_state != "registered-not-authorized"
            or self.prepared_action.release != self.release
            or self.prepared_action.capability != expected_action
            or request.tool_id != HTTPGetTool.spec.tool_id
            or request.method != "GET"
            or request.target != locator.url
            or request.arguments != {}
        ):
            raise ValueError("Web read-only discovery preparation differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_id", "preparation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.web-read-only-discovery-preparation/v1",
            material,
        )
        preparation_id: _PreparationId = f"web-discovery-preparation_{digest}"
        if self.preparation_digest and self.preparation_digest != digest:
            raise ValueError("Web read-only discovery preparation digest differs")
        if self.preparation_id and self.preparation_id != preparation_id:
            raise ValueError("Web read-only discovery preparation ID differs")
        object.__setattr__(self, "preparation_digest", digest)
        object.__setattr__(self, "preparation_id", preparation_id)
        return self


def registered_web_read_only_discovery_binding() -> WebReadOnlyDiscoveryBinding:
    """Return the exact WEB-001B binding without activating or selecting a Worker."""

    locator_registry = registered_web_http_operation_locator_registry()
    return WebReadOnlyDiscoveryBinding(
        locatorRegistry=locator_registry.reference(),
        supportedLocator=_concrete_locator_registration().reference(),
        capability=_pentest_recon_code_backed_capability(),
        capabilityDomainClassification=_capability_domain_classification(),
        workerProfile=_web_worker_boundary_profile().reference(),
    )


def resolve_web_read_only_discovery_binding(
    reference: WebReadOnlyDiscoveryBindingRef,
) -> WebReadOnlyDiscoveryBinding:
    """Resolve the one exact WEB-001B binding without activation or dispatch authority."""

    binding = registered_web_read_only_discovery_binding()
    if binding.reference() == reference:
        return binding.model_copy(deep=True)
    raise WebReadOnlyDiscoveryError("Web read-only discovery binding is not registered exactly")


def prepare_web_read_only_discovery(
    *,
    activation: PentestReconCapabilityActivation,
    release: CapabilityReleaseRef,
    surface: WebHTTPOperationSurface,
    request_id: str,
    agent_id: str,
) -> WebReadOnlyDiscoveryPreparation:
    """Compile one concrete GET Surface through current signed CAP-002 authority only."""

    if not isinstance(activation, PentestReconCapabilityActivation):
        raise TypeError("Web discovery preparation requires Pentest Recon activation")
    canonical_surface = _canonical_surface(surface)
    locator = canonical_surface.locator
    if isinstance(locator, HTTPRouteSurfaceLocator):
        raise WebReadOnlyDiscoveryError(
            "Web discovery does not materialize URI-template route parameters"
        )
    if locator.method != "GET":
        raise WebReadOnlyDiscoveryError("Web discovery prepares only an exact concrete GET")
    binding = registered_web_read_only_discovery_binding()
    try:
        if (
            activation.bundle.capability() != binding.capability
            or activation.definition() != registered_pentest_recon_capability_definition()
        ):
            raise WebReadOnlyDiscoveryError(
                "Web discovery activation differs from the registered Capability"
            )
        request = ToolRequest(
            request_id=request_id,
            agent_id=agent_id,
            tool_id=HTTPGetTool.spec.tool_id,
            target=locator.url,
            method="GET",
            arguments={},
        )
        prepared = activation.prepare_action(
            release=release,
            request=request,
            parameters={},
        )
        return WebReadOnlyDiscoveryPreparation(
            binding=binding,
            surface=canonical_surface,
            release=release,
            preparedAction=prepared,
        )
    except (PentestReconCapabilityError, ValidationError, ValueError) as exc:
        if isinstance(exc, WebReadOnlyDiscoveryError):
            raise
        raise WebReadOnlyDiscoveryError("Web discovery CAP-002 preparation failed closed") from exc


def _canonical_surface(surface: WebHTTPOperationSurface) -> WebHTTPOperationSurface:
    try:
        return WebHTTPOperationSurface.model_validate(
            surface.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise WebReadOnlyDiscoveryError("Web discovery Surface is not canonical") from exc


def _pentest_recon_code_backed_capability() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(HTTPGetTool())
    return pentest_recon_capability_bundle(tools).capability()


def _capability_domain_classification() -> CapabilityDomainClassificationRef:
    capability = _pentest_recon_code_backed_capability()
    worker = _web_worker_boundary_profile()
    return RegisteredCapabilityDomainClassification(
        capability=capability.capability,
        codeBackedCapability=capability,
        domainClassification=worker.domain_classification,
        reviewedSurfaceTypes=("http-endpoint",),
    ).reference()


def _web_worker_boundary_profile() -> RegisteredDomainWorkerBoundaryProfile:
    return next(
        item
        for item in registered_domain_worker_boundary_profiles().profiles
        if item.domain_classification.domain is SecurityDomain.WEB
    )


def _concrete_locator_registration() -> RegisteredWebHTTPOperationLocator:
    return next(
        item
        for item in registered_web_http_operation_locator_registry().locators
        if item.locator_kind == "http-endpoint"
    )


__all__ = [
    "WEB_READ_ONLY_DISCOVERY_BINDING_API_VERSION",
    "WEB_READ_ONLY_DISCOVERY_PREPARATION_API_VERSION",
    "WebReadOnlyDiscoveryBinding",
    "WebReadOnlyDiscoveryBindingRef",
    "WebReadOnlyDiscoveryError",
    "WebReadOnlyDiscoveryPreparation",
    "prepare_web_read_only_discovery",
    "registered_web_read_only_discovery_binding",
    "resolve_web_read_only_discovery_binding",
]
