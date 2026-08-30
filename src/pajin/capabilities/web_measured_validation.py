"""Additive WEB-002 controlled-validation Capability and Profile identities."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import ClassVar, Literal, cast

from pydantic import ConfigDict, Field, JsonValue, ValidationError, field_validator, model_validator

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
    CodeBackedCapability,
    CodeBackedCapabilityRef,
)
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.control_plane.domain_worker_boundaries import (
    DomainWorkerBoundaryProfileRef,
    registered_domain_worker_boundary_profiles,
    resolve_registered_domain_worker_boundary_profile,
)
from pajin.discovery.models import HTTPSurfaceLocator
from pajin.discovery.web_surfaces import (
    WebHTTPOperationSurface,
    WebHTTPOperationSurfaceRef,
    typed_web_http_operation_surface,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.authority import RegisteredActionCapability
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import (
    BOOLEAN_SQLI_SCENARIO,
    MAX_BOOLEAN_SQLI_RESPONSE_BYTES,
    BooleanSQLiObservation,
    BooleanSQLiProbeInput,
    BooleanSQLiProbeOutput,
    BooleanSQLiProbeTool,
)

WEB_MEASURED_VALIDATION_PROFILE_API_VERSION: Literal[
    "pajin.dev/web-measured-validation-profile/v1alpha1"
] = "pajin.dev/web-measured-validation-profile/v1alpha1"
WEB_MEASURED_VALIDATION_PROFILE_ID = "pajin.profile.web.measured-boolean-sqli"
WEB_MEASURED_VALIDATION_PROFILE_VERSION = "1.0.0"
WEB_MEASURED_VALIDATION_CAPABILITY_ID = "pajin.web.measured.boolean-sqli-validation"
WEB_MEASURED_VALIDATION_CAPABILITY_VERSION = "1.0.0"
WEB_MEASURED_VALIDATION_TARGET = "http://target:8080/v1/users/lookup"
WEB_MEASURED_VALIDATION_REQUEST_UNITS = 3

_AUTHORITY_VERSION = "1.0.0"
_PROFILE_FALSE_FIELDS = (
    "capability_activation_authorized",
    "approval_satisfied",
    "permit_issuance_authorized",
    "proxy_route_materialized",
    "worker_selected",
    "network_access_authorized",
    "measurement_observed",
    "graph_admission_authorized",
    "profile_validation_floor_satisfied",
    "finding_authority",
    "product_activation_authorized",
    "report_delivery_authorized",
    "execution_authorized",
)


class WebMeasuredValidationError(ValueError):
    """Raised when the additive WEB-002 Capability or Profile drifts."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class WebControlledValidationRequest(_FrozenStrictModel):
    """One code-owned request semantic; it is data, never caller payload authority."""

    name: Literal["baseline", "negative-control", "boolean-probe"]
    query_parameter: Literal["id"] = Field(default="id", alias="queryParameter")
    query_value: str = Field(alias="queryValue", min_length=1, max_length=80)


class WebMeasuredValidationProfileRef(_FrozenStrictModel):
    """Exact content-addressed Profile lookup."""

    profile_id: Literal["pajin.profile.web.measured-boolean-sqli"] = Field(alias="profileId")
    profile_version: Literal["1.0.0"] = Field(alias="profileVersion")
    profile_digest: str = Field(alias="profileDigest", pattern=r"^[a-f0-9]{64}$")


class WebMeasuredValidationProfile(_FrozenStrictModel):
    """Registered internal-target validation semantics without activation authority."""

    api_version: Literal["pajin.dev/web-measured-validation-profile/v1alpha1"] = Field(
        default=WEB_MEASURED_VALIDATION_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebMeasuredValidationProfile"] = "WebMeasuredValidationProfile"
    profile_id: Literal["pajin.profile.web.measured-boolean-sqli"] = Field(
        default="pajin.profile.web.measured-boolean-sqli",
        alias="profileId",
    )
    profile_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="profileVersion",
    )
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")
    worker_boundary: DomainWorkerBoundaryProfileRef = Field(alias="workerBoundary")
    surface: WebHTTPOperationSurfaceRef
    target_endpoint: Literal["http://target:8080/v1/users/lookup"] = Field(
        default="http://target:8080/v1/users/lookup",
        alias="targetEndpoint",
    )
    method: Literal["GET"] = "GET"
    scenario_id: Literal["bug-bounty.api.boolean-sqli-lab"] = Field(
        default=BOOLEAN_SQLI_SCENARIO,
        alias="scenarioId",
    )
    controlled_requests: tuple[WebControlledValidationRequest, ...] = Field(
        alias="controlledRequests",
        min_length=3,
        max_length=3,
    )
    request_units: Literal[3] = Field(
        default=3,
        alias="requestUnits",
    )
    max_response_bytes_per_request: Literal[32768] = Field(
        default=32768,
        alias="maxResponseBytesPerRequest",
    )
    proxy_route_required: Literal[True] = Field(default=True, alias="proxyRouteRequired")
    proxy_route_cleanup_required: Literal[True] = Field(
        default=True,
        alias="proxyRouteCleanupRequired",
    )
    host_observed_receipts_required: Literal[True] = Field(
        default=True,
        alias="hostObservedReceiptsRequired",
    )
    fresh_target_operation_required: Literal[True] = Field(
        default=True,
        alias="freshTargetOperationRequired",
    )
    worker_proxy_only_network_required: Literal[True] = Field(
        default=True,
        alias="workerProxyOnlyNetworkRequired",
    )
    state: Literal["registered-not-activated"] = "registered-not-activated"
    capability_activation_authorized: Literal[False] = Field(
        default=False, alias="capabilityActivationAuthorized"
    )
    approval_satisfied: Literal[False] = Field(default=False, alias="approvalSatisfied")
    permit_issuance_authorized: Literal[False] = Field(
        default=False, alias="permitIssuanceAuthorized"
    )
    proxy_route_materialized: Literal[False] = Field(default=False, alias="proxyRouteMaterialized")
    worker_selected: Literal[False] = Field(default=False, alias="workerSelected")
    network_access_authorized: Literal[False] = Field(
        default=False, alias="networkAccessAuthorized"
    )
    measurement_observed: Literal[False] = Field(default=False, alias="measurementObserved")
    graph_admission_authorized: Literal[False] = Field(
        default=False, alias="graphAdmissionAuthorized"
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False, alias="profileValidationFloorSatisfied"
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    product_activation_authorized: Literal[False] = Field(
        default=False, alias="productActivationAuthorized"
    )
    report_delivery_authorized: Literal[False] = Field(
        default=False, alias="reportDeliveryAuthorized"
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "request_units",
        "max_response_bytes_per_request",
        mode="before",
    )
    @classmethod
    def require_literal_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("WEB-002A Profile numbers must be literal integers")
        return value

    @field_validator(
        "proxy_route_required",
        "proxy_route_cleanup_required",
        "host_observed_receipts_required",
        "fresh_target_operation_required",
        "worker_proxy_only_network_required",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-002A Profile requirements must be boolean true")
        return value

    @field_validator(*_PROFILE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-002A Profile authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_profile_identity(self) -> WebMeasuredValidationProfile:
        definition = registered_web_measured_validation_capability_definition()
        action = registered_action_capability(definition)
        worker = _web_worker_boundary()
        surface = registered_web_measured_internal_surface()
        if (
            self.capability.capability != definition.reference()
            or self.action_capability != action
            or self.worker_boundary != worker
            or self.surface != surface.reference()
            or self.controlled_requests != _controlled_requests()
        ):
            raise ValueError("WEB-002A Profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.web-measured-validation-profile/v1",
            material,
        )
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("WEB-002A Profile digest differs")
        object.__setattr__(self, "profile_digest", digest)
        return self

    def reference(self) -> WebMeasuredValidationProfileRef:
        """Return an exact Profile reference without activating it."""

        return WebMeasuredValidationProfileRef(
            profileId=self.profile_id,
            profileVersion=self.profile_version,
            profileDigest=self.profile_digest,
        )


@dataclass(frozen=True, slots=True)
class WebMeasuredValidationCapabilityBundle:
    """Detached CAP-001/CAP-002 registries for the additive WEB-002 Capability."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    @property
    def capability(self) -> CodeBackedCapability:
        return self.authorities.capabilities()[0]


@dataclass(frozen=True, slots=True)
class _WebMeasuredContract:
    definition: CapabilityDefinition
    tool: BooleanSQLiProbeTool

    def stable_context(self) -> Mapping[str, object]:
        tool_type = type(self.tool)
        tool_spec = self.tool.spec.model_dump(mode="json")
        tool_spec["categories"] = sorted(self.tool.spec.categories)
        tool_spec["evidence_types"] = sorted(self.tool.spec.evidence_types)
        return {
            "adapterContractVersion": "pajin.web-measured-validation-capability-adapter/v1",
            "capabilityId": self.definition.capability_id,
            "capabilityVersion": self.definition.capability_version,
            "method": "GET",
            "target": WEB_MEASURED_VALIDATION_TARGET,
            "scenarioId": BOOLEAN_SQLI_SCENARIO,
            "requestUnits": WEB_MEASURED_VALIDATION_REQUEST_UNITS,
            "maxResponseBytesPerRequest": MAX_BOOLEAN_SQLI_RESPONSE_BYTES,
            "callerAuthoredPayload": False,
            "proxyRouteRequired": True,
            "tool": {
                "type": f"{tool_type.__module__}.{tool_type.__qualname__}",
                "context": {
                    "implementationVersion": "pajin.tool-adapter/v1",
                    "spec": tool_spec,
                },
            },
        }


class _WebMeasuredAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(self, contract: _WebMeasuredContract) -> None:
        self._contract = contract

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{WEB_MEASURED_VALIDATION_CAPABILITY_ID}.{self.ROLE.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._contract.definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._contract.stable_context()

    def _require_request(self, request: ToolRequest) -> None:
        if (
            request.tool_id != BooleanSQLiProbeTool.spec.tool_id
            or request.method != "GET"
            or request.target != WEB_MEASURED_VALIDATION_TARGET
        ):
            raise CapabilityAuthorityError(
                "WEB-002 measured validation request differs from its exact internal target"
            )


class _WebMeasuredMaterializer(_WebMeasuredAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            parsed = BooleanSQLiProbeInput.model_validate(parameters)
        except ValidationError as exc:
            raise CapabilityAuthorityError(
                "WEB-002 measured validation parameters differ from the fixed scenario"
            ) from exc
        return cast(dict[str, JsonValue], parsed.model_dump(mode="json", by_alias=True))


class _WebMeasuredActionCompiler(_WebMeasuredAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        self._require_request(request)
        return request.model_copy(update={"arguments": dict(materialized_arguments)})


class _WebMeasuredExecutor(_WebMeasuredAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._require_request(request)
        return self._contract.tool.prepare(request)


class _WebMeasuredNormalizer(_WebMeasuredAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        self._require_request(request)
        return self._contract.tool.interpret(request, result)


class _WebMeasuredOracle(_WebMeasuredAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        self._require_request(request)
        if not result.success:
            return CapabilityOracleDecision.INCONCLUSIVE
        try:
            output = BooleanSQLiProbeOutput.model_validate(result.data)
            supported = _observations_support_exact_case(output, request=request)
        except (TypeError, ValidationError, ValueError):
            return CapabilityOracleDecision.INCONCLUSIVE
        return CapabilityOracleDecision.SUCCEEDED if supported else CapabilityOracleDecision.FAILED


class _WebMeasuredReplay(_WebMeasuredAuthorityBase):
    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        self._require_request(request)
        del result
        return None


class _WebMeasuredCleanup(_WebMeasuredAuthorityBase):
    ROLE = CapabilityAuthorityRole.CLEANUP_HANDLER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        self._require_request(request)
        del result
        return None


def registered_web_measured_validation_capability_definition() -> CapabilityDefinition:
    """Return the additive metadata identity while preserving the existing Tool identity."""

    return capability_definition_from_tool(
        BooleanSQLiProbeTool.spec,
        _registration(),
    )


def web_measured_validation_capability_bundle(
    tools: ToolRegistry,
) -> WebMeasuredValidationCapabilityBundle:
    """Bind the exact reviewed Tool to seven new code-owned authority roles."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("WEB-002 measured validation requires a ToolRegistry")
    try:
        tool = tools.tool(BooleanSQLiProbeTool.spec.tool_id)
        spec = tools.spec(BooleanSQLiProbeTool.spec.tool_id)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise WebMeasuredValidationError("WEB-002 measured validation Tool is unavailable") from exc
    if type(tool) is not BooleanSQLiProbeTool or spec != BooleanSQLiProbeTool.spec:
        raise WebMeasuredValidationError(
            "WEB-002 measured validation Tool implementation or specification drifted"
        )
    definition = capability_definition_from_tool(spec, _registration())
    definitions = CapabilityDefinitionRegistry((definition,))
    contract = _WebMeasuredContract(definition=definition, tool=tool)
    adapters: tuple[CapabilityAuthorityAdapter, ...] = (
        _WebMeasuredMaterializer(contract),
        _WebMeasuredActionCompiler(contract),
        _WebMeasuredExecutor(contract),
        _WebMeasuredNormalizer(contract),
        _WebMeasuredOracle(contract),
        _WebMeasuredReplay(contract),
        _WebMeasuredCleanup(contract),
    )
    return WebMeasuredValidationCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, adapters),
    )


def registered_web_measured_validation_profile(
    bundle: WebMeasuredValidationCapabilityBundle,
) -> WebMeasuredValidationProfile:
    """Register the exact Profile without resolving a signed release for use."""

    capability = _resolved_bundle_capability(bundle)
    return WebMeasuredValidationProfile(
        capability=capability.reference(),
        actionCapability=registered_action_capability(
            bundle.definitions.resolve(capability.capability)
        ),
        workerBoundary=_web_worker_boundary(),
        surface=registered_web_measured_internal_surface().reference(),
        controlledRequests=_controlled_requests(),
    )


def resolve_web_measured_validation_profile(
    reference: WebMeasuredValidationProfileRef,
    *,
    bundle: WebMeasuredValidationCapabilityBundle,
) -> WebMeasuredValidationProfile:
    """Resolve only the exact Profile and current immutable Capability authority set."""

    profile = registered_web_measured_validation_profile(bundle)
    if profile.reference() != reference:
        raise WebMeasuredValidationError("WEB-002 measured validation Profile is not registered")
    return profile.model_copy(deep=True)


def registered_web_measured_internal_surface() -> WebHTTPOperationSurface:
    """Return the inert WEB-001A Surface for the Docker-internal lab endpoint."""

    return typed_web_http_operation_surface(
        locator=HTTPSurfaceLocator(url=WEB_MEASURED_VALIDATION_TARGET, method="GET")
    )


def _resolved_bundle_capability(
    bundle: WebMeasuredValidationCapabilityBundle,
) -> CodeBackedCapability:
    if not isinstance(bundle, WebMeasuredValidationCapabilityBundle):
        raise TypeError("WEB-002 Profile requires its Capability bundle")
    capabilities = bundle.authorities.capabilities()
    if len(capabilities) != 1:
        raise WebMeasuredValidationError("WEB-002 Capability bundle is not singular")
    capability = capabilities[0]
    definition = bundle.definitions.resolve(capability.capability)
    if definition != registered_web_measured_validation_capability_definition():
        raise WebMeasuredValidationError("WEB-002 Capability definition drifted")
    return capability


def _registration() -> ToolCapabilityRegistration:
    constraints: dict[str, JsonValue] = {
        "scenarioId": BOOLEAN_SQLI_SCENARIO,
        "target": WEB_MEASURED_VALIDATION_TARGET,
        "method": "GET",
        "callerAuthoredPayload": False,
        "requestUnits": WEB_MEASURED_VALIDATION_REQUEST_UNITS,
    }
    schema_digest = capability_definition_digest(
        "pajin.capability.web-measured-parameter-schema/v1",
        {
            "model": f"{BooleanSQLiProbeInput.__module__}.{BooleanSQLiProbeInput.__qualname__}",
            "schema": BooleanSQLiProbeInput.model_json_schema(by_alias=True),
            "constraints": constraints,
        },
    )
    return ToolCapabilityRegistration(
        capabilityId=WEB_MEASURED_VALIDATION_CAPABILITY_ID,
        capabilityVersion=WEB_MEASURED_VALIDATION_CAPABILITY_VERSION,
        toolId=BooleanSQLiProbeTool.spec.tool_id,
        domain="web",
        maturity=CapabilityMaturity.EXPERIMENTAL,
        supportedSurfaceTypes=("web.http-operation",),
        threatClasses=("CWE-89",),
        preconditions=tuple(
            sorted(
                (
                    "current-authorized-scope",
                    "exact-p0-d1-target-operation",
                    "fresh-action-permit",
                    "host-observed-http-receipts",
                    "signed-single-use-proxy-route",
                    "synthetic-local-lab",
                )
            )
        ),
        parameterSchemaDigest=schema_digest,
        sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
        approvalRequired=True,
        cleanupRequired=False,
        requestUnitCost=WEB_MEASURED_VALIDATION_REQUEST_UNITS,
    )


def _web_worker_boundary() -> DomainWorkerBoundaryProfileRef:
    registry = registered_domain_worker_boundary_profiles()
    profile = next(
        item
        for item in registry.profiles
        if item.domain_classification.domain is SecurityDomain.WEB
    )
    resolved = resolve_registered_domain_worker_boundary_profile(profile.reference())
    return resolved.reference()


def _controlled_requests() -> tuple[WebControlledValidationRequest, ...]:
    return (
        WebControlledValidationRequest(name="baseline", queryValue="1"),
        WebControlledValidationRequest(
            name="negative-control",
            queryValue="1' AND '1'='2",
        ),
        WebControlledValidationRequest(
            name="boolean-probe",
            queryValue="1' OR '1'='1",
        ),
    )


def _observations_support_exact_case(
    output: BooleanSQLiProbeOutput,
    *,
    request: ToolRequest,
) -> bool:
    if (
        output.target != request.target
        or output.scenario_id != BOOLEAN_SQLI_SCENARIO
        or not output.network_performed
        or len(output.observations) != 3
    ):
        raise ValueError("WEB-002 Boolean SQLi output identity differs")
    by_name: dict[str, BooleanSQLiObservation] = {item.name: item for item in output.observations}
    if set(by_name) != {"baseline", "negative-control", "boolean-probe"}:
        raise ValueError("WEB-002 Boolean SQLi observations are incomplete")
    baseline = by_name["baseline"]
    negative = by_name["negative-control"]
    probe = by_name["boolean-probe"]
    checks = (
        baseline.status == 200 and baseline.record_count == 1,
        negative.status in {200, 400} and negative.record_count == 0,
        probe.status == 200 and probe.record_count > baseline.record_count,
        all(item.synthetic for item in output.observations),
    )
    if (
        output.checks.baseline_single_record,
        output.checks.negative_control_empty,
        output.checks.boolean_probe_expanded,
        output.checks.synthetic_lab_only,
    ) != checks or output.vulnerable is not all(checks):
        raise ValueError("WEB-002 Boolean SQLi checks differ from observations")
    return output.vulnerable


__all__ = [
    "WEB_MEASURED_VALIDATION_CAPABILITY_ID",
    "WEB_MEASURED_VALIDATION_CAPABILITY_VERSION",
    "WEB_MEASURED_VALIDATION_PROFILE_API_VERSION",
    "WEB_MEASURED_VALIDATION_PROFILE_ID",
    "WEB_MEASURED_VALIDATION_PROFILE_VERSION",
    "WEB_MEASURED_VALIDATION_REQUEST_UNITS",
    "WEB_MEASURED_VALIDATION_TARGET",
    "WebControlledValidationRequest",
    "WebMeasuredValidationCapabilityBundle",
    "WebMeasuredValidationError",
    "WebMeasuredValidationProfile",
    "WebMeasuredValidationProfileRef",
    "registered_web_measured_internal_surface",
    "registered_web_measured_validation_capability_definition",
    "registered_web_measured_validation_profile",
    "resolve_web_measured_validation_profile",
    "web_measured_validation_capability_bundle",
]
