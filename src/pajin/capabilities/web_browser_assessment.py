"""Registration-only Capability boundary for the exact WEB-003 browser plan.

This module deliberately stops before lifecycle activation, ActionPermit issuance,
Gateway dispatch, or Worker materialization.  It records the reviewed static
Capability and its seven code-backed roles without reinterpreting WEB-003 local
authorization as product execution authority.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import ClassVar, Literal, Self, cast

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
from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.graph.authority import RegisteredActionCapability
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.web_assessment.recipes import juice_shop_plan

WEB_BROWSER_ASSESSMENT_CAPABILITY_ID = "pajin.bug-bounty.web-browser-assessment"
WEB_BROWSER_ASSESSMENT_CAPABILITY_VERSION = "1.0.0"
WEB_BROWSER_ASSESSMENT_TOOL_ID = "web.browser-assessment"
WEB_BROWSER_ASSESSMENT_TOOL_VERSION = "1.0.0"
WEB_BROWSER_ASSESSMENT_ORIGIN: Literal["http://127.0.0.1:3000"] = "http://127.0.0.1:3000"
WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST: Literal[
    "3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96"
] = "3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96"
WEB_BROWSER_ASSESSMENT_REQUEST_UNITS = 100
WEB_BROWSER_ASSESSMENT_METHODS: tuple[Literal["GET", "HEAD", "POST"], ...] = (
    "GET",
    "HEAD",
    "POST",
)
WEB_BROWSER_ASSESSMENT_TOP_LEVEL_METHOD: Literal["POST"] = "POST"
WEB_BROWSER_ASSESSMENT_PROFILE_API_VERSION: Literal[
    "pajin.dev/web-browser-assessment-profile/v1alpha1"
] = "pajin.dev/web-browser-assessment-profile/v1alpha1"
WEB_BROWSER_ASSESSMENT_PLAN_API_VERSION: Literal[
    "pajin.dev/web-browser-assessment-plan/v1alpha1"
] = "pajin.dev/web-browser-assessment-plan/v1alpha1"
WEB_BROWSER_ACCOUNT_RECEIPT_API_VERSION: Literal[
    "pajin.dev/web-browser-provisioned-account-receipt/v1alpha1"
] = "pajin.dev/web-browser-provisioned-account-receipt/v1alpha1"

_AUTHORITY_VERSION = "1.0.0"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_ROUTE_LIMITATIONS = tuple(
    sorted(
        (
            "account-receipt-authentication-not-configured",
            "browser-worker-route-not-configured",
            "caller-authored-forms-and-routes-forbidden",
            "cleanup-route-not-configured",
            "credential-delivery-not-configured",
            "gateway-dispatch-not-configured",
            "login-state-mutation-not-authorized",
            "signed-lifecycle-activation-required",
        )
    )
)


class WebBrowserAssessmentCapabilityError(ValueError):
    """Raised when the exact registration-only browser contract drifts."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class _NonAuthorityState(_FrozenStrictModel):
    lifecycle_activated: Literal[False] = Field(default=False, alias="lifecycleActivated")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    action_permit_issued: Literal[False] = Field(default=False, alias="actionPermitIssued")
    gateway_dispatched: Literal[False] = Field(default=False, alias="gatewayDispatched")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    credential_delivery_authorized: Literal[False] = Field(
        default=False,
        alias="credentialDeliveryAuthorized",
    )
    login_state_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="loginStateMutationAuthorized",
    )
    cleanup_authority_bound: Literal[False] = Field(
        default=False,
        alias="cleanupAuthorityBound",
    )
    cleanup_reservation_held: Literal[False] = Field(
        default=False,
        alias="cleanupReservationHeld",
    )
    cleanup_permit_issued: Literal[False] = Field(
        default=False,
        alias="cleanupPermitIssued",
    )
    account_deletion_authorized: Literal[False] = Field(
        default=False,
        alias="accountDeletionAuthorized",
    )

    @field_validator(
        "lifecycle_activated",
        "execution_authorized",
        "action_permit_issued",
        "gateway_dispatched",
        "finding_authority",
        "credential_delivery_authorized",
        "login_state_mutation_authorized",
        "cleanup_authority_bound",
        "cleanup_reservation_held",
        "cleanup_permit_issued",
        "account_deletion_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("browser assessment authority markers must be boolean false")
        return value


class WebBrowserProvisionedAccountReceipt(_FrozenStrictModel):
    """Content-addressed account-provisioning evidence, not authenticated authority."""

    api_version: Literal["pajin.dev/web-browser-provisioned-account-receipt/v1alpha1"] = Field(
        default=WEB_BROWSER_ACCOUNT_RECEIPT_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebBrowserProvisionedAccountReceipt"] = "WebBrowserProvisionedAccountReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=120)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    origin: Literal["http://127.0.0.1:3000"] = WEB_BROWSER_ASSESSMENT_ORIGIN
    source_plan_digest: Literal[
        "3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96"
    ] = Field(
        default=WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST,
        alias="sourcePlanDigest",
    )
    account_reference_digest: str = Field(
        alias="accountReferenceDigest",
        pattern=_SHA256_PATTERN,
    )
    provisioning_evidence_digest: str = Field(
        alias="provisioningEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    issuer_authority_digest: str = Field(
        alias="issuerAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    issued_at: datetime = Field(alias="issuedAt")
    expires_at: datetime = Field(alias="expiresAt")
    account_already_provisioned: Literal[True] = Field(
        default=True,
        alias="accountAlreadyProvisioned",
    )
    account_creation_authorized: Literal[False] = Field(
        default=False,
        alias="accountCreationAuthorized",
    )
    credential_material_included: Literal[False] = Field(
        default=False,
        alias="credentialMaterialIncluded",
    )
    issuer_authenticated: Literal[False] = Field(
        default=False,
        alias="issuerAuthenticated",
    )

    @field_validator("issued_at", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("provisioned account receipt time requires an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("account_already_provisioned", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("accountAlreadyProvisioned must be boolean true")
        return value

    @field_validator(
        "account_creation_authorized",
        "credential_material_included",
        "issuer_authenticated",
        mode="before",
    )
    @classmethod
    def require_receipt_false_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("provisioned account receipt authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=30):
            raise ValueError("provisioned account receipt lifetime must be at most 30 minutes")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.web-browser-provisioned-account-receipt/v1",
            material,
        )
        receipt_id = f"web-browser-account-receipt_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("provisioned account receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("provisioned account receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class WebBrowserAssessmentParameters(_FrozenStrictModel):
    """Only caller material accepted by the registration-only Capability."""

    origin: Literal["http://127.0.0.1:3000"] = WEB_BROWSER_ASSESSMENT_ORIGIN
    source_plan_digest: Literal[
        "3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96"
    ] = Field(
        default=WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST,
        alias="sourcePlanDigest",
    )
    account_receipt: WebBrowserProvisionedAccountReceipt = Field(alias="accountReceipt")

    @model_validator(mode="after")
    def bind_exact_receipt(self) -> Self:
        _require_source_plan()
        if (
            self.account_receipt.origin != self.origin
            or self.account_receipt.source_plan_digest != self.source_plan_digest
        ):
            raise ValueError("provisioned account receipt belongs to another origin or plan")
        return self


class WebBrowserAssessmentProfileRef(_FrozenStrictModel):
    profile_id: Literal["pajin.profile.web-browser-assessment"] = Field(alias="profileId")
    profile_version: Literal["1.0.0"] = Field(alias="profileVersion")
    profile_digest: str = Field(alias="profileDigest", pattern=_SHA256_PATTERN)


class WebBrowserAssessmentProfile(_NonAuthorityState):
    """Registered static profile that explicitly carries no execution authority."""

    api_version: Literal["pajin.dev/web-browser-assessment-profile/v1alpha1"] = Field(
        default=WEB_BROWSER_ASSESSMENT_PROFILE_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebBrowserAssessmentProfile"] = "WebBrowserAssessmentProfile"
    profile_id: Literal["pajin.profile.web-browser-assessment"] = Field(
        default="pajin.profile.web-browser-assessment",
        alias="profileId",
    )
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")
    origin: Literal["http://127.0.0.1:3000"] = WEB_BROWSER_ASSESSMENT_ORIGIN
    source_plan_digest: Literal[
        "3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96"
    ] = Field(
        default=WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST,
        alias="sourcePlanDigest",
    )
    top_level_method: Literal["POST"] = Field(
        default=WEB_BROWSER_ASSESSMENT_TOP_LEVEL_METHOD,
        alias="topLevelMethod",
    )
    allowed_methods: tuple[Literal["GET", "HEAD", "POST"], ...] = Field(
        default=WEB_BROWSER_ASSESSMENT_METHODS,
        alias="allowedMethods",
        min_length=3,
        max_length=3,
    )
    account_receipt_digest: str = Field(
        alias="accountReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    account_receipt_present: Literal[True] = Field(
        default=True,
        alias="accountReceiptPresent",
    )
    account_receipt_authenticated: Literal[False] = Field(
        default=False,
        alias="accountReceiptAuthenticated",
    )
    account_creation_allowed: Literal[False] = Field(
        default=False,
        alias="accountCreationAllowed",
    )
    caller_authored_routes_allowed: Literal[False] = Field(
        default=False,
        alias="callerAuthoredRoutesAllowed",
    )
    side_effect_class: Literal["irreversible-write"] = Field(
        default="irreversible-write",
        alias="sideEffectClass",
    )
    cleanup_required: Literal[True] = Field(default=True, alias="cleanupRequired")
    route_limitations: tuple[str, ...] = Field(
        default=_ROUTE_LIMITATIONS,
        alias="routeLimitations",
        min_length=len(_ROUTE_LIMITATIONS),
        max_length=len(_ROUTE_LIMITATIONS),
    )
    state: Literal["registered-not-activated"] = "registered-not-activated"

    @field_validator("account_receipt_present", mode="before")
    @classmethod
    def require_receipt_present(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("accountReceiptPresent must be boolean true")
        return value

    @field_validator("cleanup_required", mode="before")
    @classmethod
    def require_cleanup(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("browser assessment login state requires cleanup")
        return value

    @field_validator(
        "account_receipt_authenticated",
        "account_creation_allowed",
        "caller_authored_routes_allowed",
        mode="before",
    )
    @classmethod
    def require_profile_false_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("browser assessment Profile limitation markers must be false")
        return value

    @model_validator(mode="after")
    def bind_profile(self) -> Self:
        _require_source_plan()
        definition = registered_web_browser_assessment_capability_definition()
        if (
            self.capability != _code_owned_capability_reference()
            or self.action_capability != registered_action_capability(definition)
            or self.allowed_methods != WEB_BROWSER_ASSESSMENT_METHODS
            or self.route_limitations != _ROUTE_LIMITATIONS
            or definition.side_effect_class is not CapabilitySideEffectClass.IRREVERSIBLE_WRITE
            or not definition.cleanup_required
        ):
            raise ValueError("browser assessment Profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.web-browser-assessment-profile/v1",
            material,
        )
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("browser assessment Profile digest differs")
        object.__setattr__(self, "profile_digest", digest)
        return self

    def reference(self) -> WebBrowserAssessmentProfileRef:
        return WebBrowserAssessmentProfileRef(
            profileId=self.profile_id,
            profileVersion=self.profile_version,
            profileDigest=self.profile_digest,
        )


class WebBrowserAssessmentPlanRef(_FrozenStrictModel):
    plan_id: str = Field(alias="planId", pattern=r"^web-browser-plan_[a-f0-9]{64}$")
    plan_digest: str = Field(alias="planDigest", pattern=_SHA256_PATTERN)


class WebBrowserAssessmentPlan(_NonAuthorityState):
    """Inert plan binding the exact receipt to the exact registered Profile."""

    api_version: Literal["pajin.dev/web-browser-assessment-plan/v1alpha1"] = Field(
        default=WEB_BROWSER_ASSESSMENT_PLAN_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebBrowserAssessmentPlan"] = "WebBrowserAssessmentPlan"
    plan_id: str = Field(default="", alias="planId", max_length=90)
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    profile: WebBrowserAssessmentProfile
    parameters: WebBrowserAssessmentParameters
    allowed_methods: tuple[Literal["GET", "HEAD", "POST"], ...] = Field(
        default=WEB_BROWSER_ASSESSMENT_METHODS,
        alias="allowedMethods",
        min_length=3,
        max_length=3,
    )
    route_limitations: tuple[str, ...] = Field(
        default=_ROUTE_LIMITATIONS,
        alias="routeLimitations",
        min_length=len(_ROUTE_LIMITATIONS),
        max_length=len(_ROUTE_LIMITATIONS),
    )
    side_effect_class: Literal["irreversible-write"] = Field(
        default="irreversible-write",
        alias="sideEffectClass",
    )
    cleanup_required: Literal[True] = Field(default=True, alias="cleanupRequired")
    state: Literal["planned-not-authorized"] = "planned-not-authorized"

    @field_validator("cleanup_required", mode="before")
    @classmethod
    def require_cleanup(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("browser assessment Plan requires cleanup")
        return value

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        if (
            self.profile.origin != self.parameters.origin
            or self.profile.source_plan_digest != self.parameters.source_plan_digest
            or self.profile.account_receipt_digest != self.parameters.account_receipt.receipt_digest
            or self.allowed_methods != WEB_BROWSER_ASSESSMENT_METHODS
            or self.route_limitations != _ROUTE_LIMITATIONS
            or self.side_effect_class != self.profile.side_effect_class
            or self.cleanup_required != self.profile.cleanup_required
        ):
            raise ValueError("browser assessment Plan differs from its Profile or receipt")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_id", "plan_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.web-browser-assessment-plan/v1",
            material,
        )
        plan_id = f"web-browser-plan_{digest}"
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("browser assessment Plan digest differs")
        if self.plan_id and self.plan_id != plan_id:
            raise ValueError("browser assessment Plan ID differs")
        object.__setattr__(self, "plan_digest", digest)
        object.__setattr__(self, "plan_id", plan_id)
        return self

    def reference(self) -> WebBrowserAssessmentPlanRef:
        return WebBrowserAssessmentPlanRef(
            planId=self.plan_id,
            planDigest=self.plan_digest,
        )


class WebBrowserAssessmentTool(Tool):
    """Registered Tool identity with no executable Worker route in this slice."""

    spec = ToolSpec(
        tool_id=WEB_BROWSER_ASSESSMENT_TOOL_ID,
        version=WEB_BROWSER_ASSESSMENT_TOOL_VERSION,
        description="Bind the exact WEB-003 browser assessment to host orchestration",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"active-test", "browser", "bug-bounty", "web"}),
        evidence_types=frozenset({"browser-screenshot", "http-observation", "json"}),
        network_access=True,
        network_request_cost=WEB_BROWSER_ASSESSMENT_REQUEST_UNITS,
        parallel_safe=False,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        del request
        raise ValueError("browser assessment has no activated Worker route")

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del request, result
        raise ValueError("browser assessment has no Worker result route")


@dataclass(frozen=True, slots=True)
class WebBrowserAssessmentCapabilityBundle:
    """Singular registration-only CAP-001/CAP-002 authority bundle."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    @property
    def capability(self) -> CodeBackedCapability:
        capabilities = self.authorities.capabilities()
        if len(capabilities) != 1:
            raise WebBrowserAssessmentCapabilityError(
                "browser assessment Capability bundle is not singular"
            )
        return capabilities[0]


@dataclass(frozen=True, slots=True)
class _WebBrowserAssessmentContract:
    definition: CapabilityDefinition
    tool: WebBrowserAssessmentTool

    def stable_context(self) -> Mapping[str, object]:
        tool_spec = self.tool.spec.model_dump(mode="json")
        tool_spec["categories"] = sorted(self.tool.spec.categories)
        tool_spec["evidence_types"] = sorted(self.tool.spec.evidence_types)
        return {
            "adapterContractVersion": "pajin.web-browser-assessment-adapter/v1",
            "capabilityId": self.definition.capability_id,
            "capabilityVersion": self.definition.capability_version,
            "origin": WEB_BROWSER_ASSESSMENT_ORIGIN,
            "sourcePlanDigest": WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST,
            "topLevelMethod": WEB_BROWSER_ASSESSMENT_TOP_LEVEL_METHOD,
            "allowedMethods": list(WEB_BROWSER_ASSESSMENT_METHODS),
            "requestUnits": WEB_BROWSER_ASSESSMENT_REQUEST_UNITS,
            "accountReceiptRequired": True,
            "accountCreationAllowed": False,
            "credentialParametersAllowed": False,
            "callerAuthoredRoutesAllowed": False,
            "routeLimitations": list(_ROUTE_LIMITATIONS),
            "sideEffectClass": CapabilitySideEffectClass.IRREVERSIBLE_WRITE.value,
            "cleanupRequired": True,
            "lifecycleActivated": False,
            "executionAuthorized": False,
            "actionPermitIssued": False,
            "gatewayDispatched": False,
            "findingAuthority": False,
            "credentialDeliveryAuthorized": False,
            "loginStateMutationAuthorized": False,
            "cleanupAuthorityBound": False,
            "cleanupReservationHeld": False,
            "cleanupPermitIssued": False,
            "accountDeletionAuthorized": False,
            "tool": {
                "type": f"{type(self.tool).__module__}.{type(self.tool).__qualname__}",
                "context": {
                    "implementationVersion": "pajin.tool-adapter/v1",
                    "spec": tool_spec,
                },
            },
        }


class _WebBrowserAssessmentAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(self, contract: _WebBrowserAssessmentContract) -> None:
        self._contract = contract

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{WEB_BROWSER_ASSESSMENT_CAPABILITY_ID}.{self.ROLE.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._contract.definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._contract.stable_context()

    def _require_request(self, request: ToolRequest) -> WebBrowserAssessmentParameters:
        if (
            request.tool_id != WEB_BROWSER_ASSESSMENT_TOOL_ID
            or request.method != WEB_BROWSER_ASSESSMENT_TOP_LEVEL_METHOD
            or request.target != WEB_BROWSER_ASSESSMENT_ORIGIN
        ):
            raise CapabilityAuthorityError(
                "browser assessment request differs from the exact registered target"
            )
        try:
            return WebBrowserAssessmentParameters.model_validate(request.arguments)
        except ValidationError as exc:
            raise CapabilityAuthorityError(
                "browser assessment parameters differ from the exact registered plan"
            ) from exc


class _WebBrowserAssessmentMaterializer(_WebBrowserAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            parsed = WebBrowserAssessmentParameters.model_validate(parameters)
        except ValidationError as exc:
            raise CapabilityAuthorityError(
                "browser assessment parameters require an exact provisioned-account receipt"
            ) from exc
        return cast(dict[str, JsonValue], parsed.model_dump(mode="json", by_alias=True))


class _WebBrowserAssessmentActionCompiler(_WebBrowserAssessmentAuthorityBase):
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


class _WebBrowserAssessmentExecutor(_WebBrowserAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._require_request(request)
        raise CapabilityAuthorityError(
            "browser assessment is registered for host orchestration but has no Worker route"
        )


class _WebBrowserAssessmentNormalizer(_WebBrowserAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        self._require_request(request)
        del result
        raise CapabilityAuthorityError(
            "browser assessment has no authenticated Worker result to normalize"
        )


class _WebBrowserAssessmentOracle(_WebBrowserAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        self._require_request(request)
        del result
        return CapabilityOracleDecision.INCONCLUSIVE


class _WebBrowserAssessmentReplay(_WebBrowserAssessmentAuthorityBase):
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


class _WebBrowserAssessmentCleanup(_WebBrowserAssessmentAuthorityBase):
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


def registered_web_browser_assessment_capability_definition() -> CapabilityDefinition:
    """Return the exact static Definition without activating its release."""

    _require_source_plan()
    return capability_definition_from_tool(WebBrowserAssessmentTool.spec, _registration())


def web_browser_assessment_capability_bundle(
    tools: ToolRegistry,
) -> WebBrowserAssessmentCapabilityBundle:
    """Bind the reviewed Tool to all seven registration-only code authorities."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("browser assessment Capability requires a ToolRegistry")
    try:
        tool = tools.tool(WEB_BROWSER_ASSESSMENT_TOOL_ID)
        spec = tools.spec(WEB_BROWSER_ASSESSMENT_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise WebBrowserAssessmentCapabilityError("browser assessment Tool is unavailable") from exc
    if type(tool) is not WebBrowserAssessmentTool or spec != WebBrowserAssessmentTool.spec:
        raise WebBrowserAssessmentCapabilityError(
            "browser assessment Tool implementation or specification drifted"
        )
    definition = capability_definition_from_tool(spec, _registration())
    definitions = CapabilityDefinitionRegistry((definition,))
    contract = _WebBrowserAssessmentContract(definition=definition, tool=tool)
    adapters: tuple[CapabilityAuthorityAdapter, ...] = (
        _WebBrowserAssessmentMaterializer(contract),
        _WebBrowserAssessmentActionCompiler(contract),
        _WebBrowserAssessmentExecutor(contract),
        _WebBrowserAssessmentNormalizer(contract),
        _WebBrowserAssessmentOracle(contract),
        _WebBrowserAssessmentReplay(contract),
        _WebBrowserAssessmentCleanup(contract),
    )
    return WebBrowserAssessmentCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, adapters),
    )


def registered_web_browser_assessment_profile(
    bundle: WebBrowserAssessmentCapabilityBundle,
    receipt: WebBrowserProvisionedAccountReceipt,
) -> WebBrowserAssessmentProfile:
    """Bind one inert Profile to an exact receipt without authenticating its issuer."""

    capability = _resolved_bundle_capability(bundle)
    canonical_receipt = _canonical_receipt(receipt)
    return WebBrowserAssessmentProfile(
        capability=capability.reference(),
        actionCapability=registered_action_capability(
            bundle.definitions.resolve(capability.capability)
        ),
        accountReceiptDigest=canonical_receipt.receipt_digest,
    )


def registered_web_browser_assessment_plan(
    bundle: WebBrowserAssessmentCapabilityBundle,
    receipt: WebBrowserProvisionedAccountReceipt,
) -> WebBrowserAssessmentPlan:
    """Return one non-executable plan for the exact source plan and receipt."""

    canonical_receipt = _canonical_receipt(receipt)
    profile = registered_web_browser_assessment_profile(bundle, canonical_receipt)
    return WebBrowserAssessmentPlan(
        profile=profile,
        parameters=WebBrowserAssessmentParameters(accountReceipt=canonical_receipt),
    )


def resolve_web_browser_assessment_profile(
    reference: WebBrowserAssessmentProfileRef,
    *,
    bundle: WebBrowserAssessmentCapabilityBundle,
    receipt: WebBrowserProvisionedAccountReceipt,
) -> WebBrowserAssessmentProfile:
    """Resolve only the code-owned exact Profile; never imply activation."""

    profile = registered_web_browser_assessment_profile(bundle, receipt)
    if profile.reference() != reference:
        raise WebBrowserAssessmentCapabilityError("browser assessment Profile is not registered")
    return profile.model_copy(deep=True)


def resolve_web_browser_assessment_plan(
    reference: WebBrowserAssessmentPlanRef,
    *,
    bundle: WebBrowserAssessmentCapabilityBundle,
    receipt: WebBrowserProvisionedAccountReceipt,
) -> WebBrowserAssessmentPlan:
    """Resolve only the exact inert Plan; never imply Permit or dispatch authority."""

    plan = registered_web_browser_assessment_plan(bundle, receipt)
    if plan.reference() != reference:
        raise WebBrowserAssessmentCapabilityError("browser assessment Plan is not registered")
    return plan.model_copy(deep=True)


def _resolved_bundle_capability(
    bundle: WebBrowserAssessmentCapabilityBundle,
) -> CodeBackedCapability:
    if not isinstance(bundle, WebBrowserAssessmentCapabilityBundle):
        raise TypeError("browser assessment Profile requires its exact Capability bundle")
    capability = bundle.capability
    definition = bundle.definitions.resolve(capability.capability)
    if definition != registered_web_browser_assessment_capability_definition():
        raise WebBrowserAssessmentCapabilityError(
            "browser assessment Capability definition drifted"
        )
    return capability


def _code_owned_capability_reference() -> CodeBackedCapabilityRef:
    tools = ToolRegistry()
    tools.register(WebBrowserAssessmentTool())
    return web_browser_assessment_capability_bundle(tools).capability.reference()


def _canonical_receipt(
    receipt: WebBrowserProvisionedAccountReceipt,
) -> WebBrowserProvisionedAccountReceipt:
    try:
        return WebBrowserProvisionedAccountReceipt.model_validate(
            receipt.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError) as exc:
        raise WebBrowserAssessmentCapabilityError(
            "provisioned account receipt is not canonical"
        ) from exc


def _registration() -> ToolCapabilityRegistration:
    constraints: dict[str, JsonValue] = {
        "origin": WEB_BROWSER_ASSESSMENT_ORIGIN,
        "sourcePlanDigest": WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST,
        "topLevelMethod": WEB_BROWSER_ASSESSMENT_TOP_LEVEL_METHOD,
        "allowedMethods": list(WEB_BROWSER_ASSESSMENT_METHODS),
        "accountReceiptRequired": True,
        "accountCreationAllowed": False,
        "credentialParametersAllowed": False,
        "callerAuthoredRoutesAllowed": False,
        "sideEffectClass": CapabilitySideEffectClass.IRREVERSIBLE_WRITE.value,
        "cleanupRequired": True,
        "requestUnits": WEB_BROWSER_ASSESSMENT_REQUEST_UNITS,
        "workerRouteAvailable": False,
    }
    schema_digest = capability_definition_digest(
        "pajin.capability.web-browser-assessment-parameter-schema/v1",
        {
            "model": (
                f"{WebBrowserAssessmentParameters.__module__}."
                f"{WebBrowserAssessmentParameters.__qualname__}"
            ),
            "schema": WebBrowserAssessmentParameters.model_json_schema(by_alias=True),
            "constraints": constraints,
        },
    )
    return ToolCapabilityRegistration(
        capabilityId=WEB_BROWSER_ASSESSMENT_CAPABILITY_ID,
        capabilityVersion=WEB_BROWSER_ASSESSMENT_CAPABILITY_VERSION,
        toolId=WEB_BROWSER_ASSESSMENT_TOOL_ID,
        domain="bug-bounty",
        maturity=CapabilityMaturity.EXPERIMENTAL,
        supportedSurfaceTypes=("web.application",),
        threatClasses=tuple(sorted(("CWE-79", "CWE-89", "CWE-639"))),
        preconditions=tuple(
            sorted(
                (
                    "already-provisioned-account-receipt",
                    "cleanup-authority-and-permit-required",
                    "credential-delivery-authority-required",
                    "exact-numeric-loopback-origin",
                    "exact-web-003-plan-digest",
                    "fresh-action-approval-required",
                    "irreversible-login-state-review-required",
                    "no-account-creation",
                    "no-caller-authored-routes",
                    "signed-lifecycle-release-required",
                )
            )
        ),
        parameterSchemaDigest=schema_digest,
        sideEffectClass=CapabilitySideEffectClass.IRREVERSIBLE_WRITE,
        approvalRequired=True,
        cleanupRequired=True,
        requestUnitCost=WEB_BROWSER_ASSESSMENT_REQUEST_UNITS,
    )


def _require_source_plan() -> None:
    try:
        plan = juice_shop_plan(WEB_BROWSER_ASSESSMENT_ORIGIN)
    except (TypeError, ValidationError, ValueError) as exc:
        raise WebBrowserAssessmentCapabilityError("WEB-003 source plan is unavailable") from exc
    if plan.plan_digest != WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST:
        raise WebBrowserAssessmentCapabilityError("WEB-003 source plan digest drifted")


__all__ = [
    "WEB_BROWSER_ASSESSMENT_CAPABILITY_ID",
    "WEB_BROWSER_ASSESSMENT_CAPABILITY_VERSION",
    "WEB_BROWSER_ASSESSMENT_METHODS",
    "WEB_BROWSER_ASSESSMENT_ORIGIN",
    "WEB_BROWSER_ASSESSMENT_REQUEST_UNITS",
    "WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST",
    "WEB_BROWSER_ASSESSMENT_TOOL_ID",
    "WEB_BROWSER_ASSESSMENT_TOOL_VERSION",
    "WebBrowserAssessmentCapabilityBundle",
    "WebBrowserAssessmentCapabilityError",
    "WebBrowserAssessmentParameters",
    "WebBrowserAssessmentPlan",
    "WebBrowserAssessmentPlanRef",
    "WebBrowserAssessmentProfile",
    "WebBrowserAssessmentProfileRef",
    "WebBrowserAssessmentTool",
    "WebBrowserProvisionedAccountReceipt",
    "registered_web_browser_assessment_capability_definition",
    "registered_web_browser_assessment_plan",
    "registered_web_browser_assessment_profile",
    "resolve_web_browser_assessment_plan",
    "resolve_web_browser_assessment_profile",
    "web_browser_assessment_capability_bundle",
]
