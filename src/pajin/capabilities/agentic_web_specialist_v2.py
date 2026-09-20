"""Planning and signed-release identity for the governed SQL specialist v2.

This module is intentionally additive.  It leaves the v1 specialist module and
all v1 identity-bearing types unchanged while defining the exact Tool,
Capability Definition, seven-role authority set, and Range activation that the
C3C live runtime must use from the start of planning.  The materializer and
compiler can validate and deterministically compile a request.  Every role that
could execute, interpret, replay, or clean up remains fail-closed until the
schema-v6 specialist Gateway owns that later boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Annotated, ClassVar, Final, Literal, Never, Self, cast

from pydantic import ConfigDict, Field, JsonValue, ValidationError, model_validator

from pajin.agentic.models import PentestSpecialization
from pajin.agentic.specialist_attempts import (
    AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION,
    AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION,
)
from pajin.agentic.specialist_preparation import AgenticSpecialistPreparation
from pajin.agentic.specialist_verifications import (
    AGENTIC_SPECIALIST_CLAIM_VERIFICATION_API_VERSION,
    AGENTIC_SPECIALIST_DISPATCH_VERIFICATION_API_VERSION,
)
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
from pajin.capabilities.agentic_web_specialist import (
    WEB_SPECIALIST_REQUEST_UNITS,
    WEB_SPECIALIST_TOOL_VERSION,
    WEB_SQLI_SPECIALIST_CAPABILITY_ID,
    WEB_SQLI_SPECIALIST_TOOL_ID,
    AgenticSpecialistPreparationRegistry,
    AgenticWebSpecialistCapabilityError,
    WebSpecialistAssessmentParameters,
    WebSpecialistAssessmentTool,
)
from pajin.capabilities.authorities import (
    CapabilityAuthorityAdapter,
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
    CodeBackedCapability,
    CodeBackedCapabilityRef,
    RegisteredCapabilityAuthority,
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
from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.graph.authority import (
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    RegisteredActionCapability,
)
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.web_assessment.governed_models import (
    ProvisionedWebAccountReceipt,
    ProvisionedWebAccountReceiptRef,
    ProvisionedWebAccountReceiptRegistry,
    WebAssessmentAdapterManifest,
    WebAssessmentAdapterRegistry,
)

WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID: Final = WEB_SQLI_SPECIALIST_CAPABILITY_ID
WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION: Final = "2.0.0"
WEB_SQLI_SPECIALIST_V2_TOOL_ID: Final = "web.specialist.sql-login.v2"
WEB_SQLI_SPECIALIST_V2_TOOL_VERSION: Final = "2.0.0"
WEB_SQLI_SPECIALIST_V2_AUTHORITY_VERSION: Final = "2.0.0"
WEB_SQLI_SPECIALIST_V2_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/agentic-web-sqli-specialist-activation-set/v2alpha1"
] = "pajin.dev/agentic-web-sqli-specialist-activation-set/v2alpha1"

_REQUEST_IDENTITY_DOMAIN: Final = "pajin.agentic.web-specialist-tool-request/v2"
_PARAMETER_SCHEMA_DOMAIN: Final = "pajin.capability.agentic-web-specialist-parameter-schema/v2"
_LEGACY_REQUEST_IDENTITY_DOMAIN: Final = "pajin.agentic.web-specialist-tool-request/v1"
_AUTHORITY_CONTRACT_VERSION: Final = "pajin.agentic-web-sqli-specialist-authority/v2"
_ACTIVATION_FACTORY_TOKEN: Final = object()
_V1_VALIDATE_REQUEST_IMPLEMENTATION: Final = WebSpecialistAssessmentTool.validate_request
_V1_STABLE_CONTEXT_IMPLEMENTATION: Final = WebSpecialistAssessmentTool.stable_execution_context
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class AgenticWebSpecialistV2CapabilityError(ValueError):
    """Raised when the additive v2 planning contract fails closed."""


class WebSQLSpecialistAuthorizationToolV2(Tool):
    """Validate and compile SQL-specialist v2 requests without dispatching them."""

    def __init__(
        self,
        *,
        preparations: AgenticSpecialistPreparationRegistry,
        adapters: WebAssessmentAdapterRegistry,
        account_receipts: ProvisionedWebAccountReceiptRegistry,
    ) -> None:
        if type(preparations) is not AgenticSpecialistPreparationRegistry:
            raise TypeError("SQL specialist v2 requires its exact preparation registry")
        if type(adapters) is not WebAssessmentAdapterRegistry:
            raise TypeError("SQL specialist v2 requires a signed adapter registry")
        if type(account_receipts) is not ProvisionedWebAccountReceiptRegistry:
            raise TypeError("SQL specialist v2 requires a signed account receipt registry")
        self.preparations = preparations
        self.adapters = adapters
        self.account_receipts = account_receipts
        self.spec = ToolSpec(
            tool_id=WEB_SQLI_SPECIALIST_V2_TOOL_ID,
            version=WEB_SQLI_SPECIALIST_V2_TOOL_VERSION,
            description=(
                "Compile the exact governed SQL-login specialist request for the "
                "scheduler-owned C3C live runtime"
            ),
            risk_tier=ToolRiskTier.T2,
            categories=frozenset(
                {"active-test", "bug-bounty", "governed-runtime", "specialist", "web"}
            ),
            evidence_types=frozenset(
                {
                    "http-observation",
                    "json",
                    "signed-attestation",
                    "terminal-receipt",
                }
            ),
            network_access=True,
            network_request_cost=WEB_SPECIALIST_REQUEST_UNITS,
            parallel_safe=False,
        )
        predecessor = _new_validation_predecessor_v2(
            preparations=preparations,
            adapters=adapters,
            account_receipts=account_receipts,
        )
        self._identity_preparations = preparations
        self._identity_adapters = adapters
        self._identity_account_receipts = account_receipts
        self._identity_spec = self.spec
        self._identity_spec_snapshot = ToolSpec.model_validate(self.spec.model_dump(mode="python"))
        self._identity_predecessor_spec = ToolSpec.model_validate(
            predecessor.spec.model_dump(mode="python")
        )
        self._identity_predecessor_context_digest = capability_definition_digest(
            "pajin.agentic.web-specialist-v2-validation-predecessor/v1",
            _V1_STABLE_CONTEXT_IMPLEMENTATION(predecessor),
        )
        self._identity_registry_state = WebSQLSpecialistAuthorizationToolV2._registry_state(self)
        _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION(self)

    def stable_execution_context(self) -> dict[str, object]:
        """Return the immutable v2 authorization contract, never runtime state."""

        _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION(self)
        spec = self.spec.model_dump(mode="json")
        spec["categories"] = sorted(self.spec.categories)
        spec["evidence_types"] = sorted(self.spec.evidence_types)
        return {
            "implementationVersion": "pajin.agentic-web-specialist-authorization-tool/v2",
            "specialization": PentestSpecialization.SQL_INJECTION.value,
            "threatClass": "sql-injection",
            "spec": spec,
            "preparationRegistryDigest": self.preparations.registry_digest,
            "adapterRegistryDigest": self.adapters.registry_digest,
            "adapterCatalogDigest": self.adapters.catalog_digest,
            "accountReceiptTrustAnchorDigest": self.account_receipts.trust_anchor_digest,
            "requestIdentityVersion": _REQUEST_IDENTITY_DOMAIN,
            "validationPredecessor": {
                "toolId": WEB_SQLI_SPECIALIST_TOOL_ID,
                "toolVersion": WEB_SPECIALIST_TOOL_VERSION,
                "contextDigest": self._identity_predecessor_context_digest,
            },
            "minimumCoordinationSchemaVersion": 6,
            "jobAttemptContract": AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION,
            "terminalReceiptContract": AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION,
            "claimVerificationContract": (AGENTIC_SPECIALIST_CLAIM_VERIFICATION_API_VERSION),
            "dispatchVerificationContract": (AGENTIC_SPECIALIST_DISPATCH_VERIFICATION_API_VERSION),
            "dispatchBindingMode": "store-db-task-bound-one-shot/v1",
            "schedulerOwnedTaskRequired": True,
            "currentGraphReverificationRequired": True,
            "grantConsumptionReceiptRequired": True,
            "freshApprovalRequired": True,
            "oneUseActionPermitRequired": True,
            "specialistGatewayRequired": True,
            "deploymentPinnedWorkerVerifierRequired": True,
            "completeAuthoritySetRequiredForRelease": True,
            "directToolDispatchAllowed": False,
            "v1PlanOrPermitUpgradeAllowed": False,
            "callerAuthoredRoutesAllowed": False,
            "callerAuthoredPayloadsAllowed": False,
            "callerAuthoredPoliciesAllowed": False,
            "callerAuthoredTransportAllowed": False,
            "accountCreationAllowed": False,
            "targetMutationAllowed": False,
        }

    def compile_request(
        self,
        *,
        preparation_id: str,
        preparation_digest: str,
        account_receipt_ref: ProvisionedWebAccountReceiptRef,
    ) -> ToolRequest:
        """Compile one deterministic v2 request from sealed references only."""

        _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION(self)
        parameters = _strict_parameters(
            WebSpecialistAssessmentParameters(
                preparationId=preparation_id,
                preparationDigest=preparation_digest,
                accountReceiptRef=account_receipt_ref,
            ).model_dump(mode="json", by_alias=True)
        )
        preparation, _adapter, _receipt = _WEB_SQL_SPECIALIST_V2_RESOLVE_PARAMETERS_IMPLEMENTATION(
            self,
            parameters,
        )
        request = ToolRequest(
            request_id=_request_id(preparation, parameters),
            agent_id=preparation.target_agent_id,
            tool_id=self.spec.tool_id,
            target=preparation.target_endpoint,
            method="POST",
            arguments=parameters.model_dump(mode="json", by_alias=True),
        )
        _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION(self, request)
        return request

    def validate_request(
        self,
        request: ToolRequest,
    ) -> tuple[
        WebSpecialistAssessmentParameters,
        AgenticSpecialistPreparation,
        WebAssessmentAdapterManifest,
        ProvisionedWebAccountReceipt,
    ]:
        """Strict-reload and bind a request to v2 plus current signed material."""

        _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION(self)
        try:
            canonical = ToolRequest.model_validate(request.model_dump(mode="json"))
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 request is not canonical"
            ) from exc
        if canonical != request:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 request differs after strict reload"
            )
        if canonical.tool_id != self.spec.tool_id or canonical.method != "POST":
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 request identity is unsupported"
            )
        parameters = _strict_parameters(canonical.arguments)
        preparation, adapter, receipt = _WEB_SQL_SPECIALIST_V2_RESOLVE_PARAMETERS_IMPLEMENTATION(
            self,
            parameters,
        )
        if (
            canonical.request_id != _request_id(preparation, parameters)
            or canonical.agent_id != preparation.target_agent_id
            or canonical.target != preparation.target_endpoint
        ):
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 request differs from sealed preparation"
            )
        _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION(self)
        return parameters, preparation, adapter, receipt

    def network_request_cost(self, request: ToolRequest) -> int:
        _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION(self, request)
        return WEB_SPECIALIST_REQUEST_UNITS

    def prepare(self, request: ToolRequest) -> WorkerJob:
        _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION(self, request)
        _direct_dispatch_unavailable()

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION(self, request)
        _direct_dispatch_unavailable()

    def _resolve_parameters(
        self,
        parameters: WebSpecialistAssessmentParameters,
    ) -> tuple[
        AgenticSpecialistPreparation,
        WebAssessmentAdapterManifest,
        ProvisionedWebAccountReceipt,
    ]:
        _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION(self)
        try:
            preparation = self.preparations.resolve(
                parameters.preparation_id,
                parameters.preparation_digest,
            )
            legacy_request = ToolRequest(
                request_id=_legacy_request_id(preparation, parameters),
                agent_id=preparation.target_agent_id,
                tool_id=WEB_SQLI_SPECIALIST_TOOL_ID,
                target=preparation.target_endpoint,
                method="POST",
                arguments=parameters.model_dump(mode="json", by_alias=True),
            )
            predecessor = _new_validation_predecessor_v2(
                preparations=self.preparations,
                adapters=self.adapters,
                account_receipts=self.account_receipts,
            )
            _require_validation_predecessor_v2(
                predecessor,
                preparations=self._identity_preparations,
                adapters=self._identity_adapters,
                account_receipts=self._identity_account_receipts,
                expected_spec=self._identity_predecessor_spec,
                expected_context_digest=self._identity_predecessor_context_digest,
            )
            _parsed, resolved, adapter, receipt = _V1_VALIDATE_REQUEST_IMPLEMENTATION(
                predecessor,
                legacy_request,
            )
        except (AgenticWebSpecialistCapabilityError, ValidationError, ValueError) as exc:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 references untrusted deployment material"
            ) from exc
        _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION(self)
        return resolved, adapter, receipt

    def _registry_state(self) -> tuple[str, str, str, str]:
        return (
            self.preparations.registry_digest,
            self.adapters.registry_digest,
            self.adapters.catalog_digest,
            self.account_receipts.trust_anchor_digest,
        )

    def _require_identity(self) -> None:
        try:
            invalid = (
                type(self) is not WebSQLSpecialistAuthorizationToolV2
                or self.preparations is not self._identity_preparations
                or self.adapters is not self._identity_adapters
                or self.account_receipts is not self._identity_account_receipts
                or self.spec is not self._identity_spec
                or self.spec != self._identity_spec_snapshot
                or WebSQLSpecialistAuthorizationToolV2._registry_state(self)
                != self._identity_registry_state
                or "_v1_validator" in vars(self)
                or "_new_validation_predecessor" in vars(self)
                or "_require_validation_predecessor" in vars(self)
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 Tool identity drifted"
            ) from exc
        if invalid:
            raise AgenticWebSpecialistV2CapabilityError("SQL specialist v2 Tool identity drifted")
        predecessor = _new_validation_predecessor_v2(
            preparations=self.preparations,
            adapters=self.adapters,
            account_receipts=self.account_receipts,
        )
        _require_validation_predecessor_v2(
            predecessor,
            preparations=self._identity_preparations,
            adapters=self._identity_adapters,
            account_receipts=self._identity_account_receipts,
            expected_spec=self._identity_predecessor_spec,
            expected_context_digest=self._identity_predecessor_context_digest,
        )


def _new_validation_predecessor_v2(
    *,
    preparations: AgenticSpecialistPreparationRegistry,
    adapters: WebAssessmentAdapterRegistry,
    account_receipts: ProvisionedWebAccountReceiptRegistry,
) -> WebSpecialistAssessmentTool:
    return WebSpecialistAssessmentTool(
        specialization=PentestSpecialization.SQL_INJECTION,
        preparations=preparations,
        adapters=adapters,
        account_receipts=account_receipts,
    )


def _require_validation_predecessor_v2(
    predecessor: WebSpecialistAssessmentTool,
    *,
    preparations: AgenticSpecialistPreparationRegistry,
    adapters: WebAssessmentAdapterRegistry,
    account_receipts: ProvisionedWebAccountReceiptRegistry,
    expected_spec: ToolSpec,
    expected_context_digest: str,
) -> None:
    try:
        context_digest = capability_definition_digest(
            "pajin.agentic.web-specialist-v2-validation-predecessor/v1",
            _V1_STABLE_CONTEXT_IMPLEMENTATION(predecessor),
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 validation predecessor drifted"
        ) from exc
    if (
        type(predecessor) is not WebSpecialistAssessmentTool
        or type(predecessor).validate_request is not _V1_VALIDATE_REQUEST_IMPLEMENTATION
        or type(predecessor).stable_execution_context is not _V1_STABLE_CONTEXT_IMPLEMENTATION
        or "validate_request" in vars(predecessor)
        or "stable_execution_context" in vars(predecessor)
        or predecessor.specialization is not PentestSpecialization.SQL_INJECTION
        or predecessor.preparations is not preparations
        or predecessor.adapters is not adapters
        or predecessor.account_receipts is not account_receipts
        or predecessor.spec != expected_spec
        or context_digest != expected_context_digest
    ):
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 validation predecessor identity drifted"
        )


@dataclass(frozen=True, slots=True)
class WebSQLSpecialistPlanningContractV2:
    """Definition usable by planning without claiming release or dispatch authority."""

    tool: WebSQLSpecialistAuthorizationToolV2
    definition: CapabilityDefinition
    action_capability: RegisteredActionCapability


def registered_web_sqli_specialist_capability_definition_v2(
    tool: WebSQLSpecialistAuthorizationToolV2,
) -> CapabilityDefinition:
    """Bind the v2 planning Tool to an exact SQL Capability Definition."""

    if type(tool) is not WebSQLSpecialistAuthorizationToolV2:
        raise TypeError("SQL specialist v2 Definition requires its exact Tool")
    _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION(tool)
    constraints: dict[str, JsonValue] = {
        "specialization": PentestSpecialization.SQL_INJECTION.value,
        "threatClass": "sql-injection",
        "preparationRegistryDigest": tool.preparations.registry_digest,
        "adapterRegistryDigest": tool.adapters.registry_digest,
        "adapterCatalogDigest": tool.adapters.catalog_digest,
        "accountReceiptTrustAnchorDigest": tool.account_receipts.trust_anchor_digest,
        "minimumCoordinationSchemaVersion": 6,
        "jobAttemptContract": AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION,
        "terminalReceiptContract": AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION,
        "claimVerificationContract": AGENTIC_SPECIALIST_CLAIM_VERIFICATION_API_VERSION,
        "dispatchVerificationContract": (AGENTIC_SPECIALIST_DISPATCH_VERIFICATION_API_VERSION),
        "dispatchBindingMode": "store-db-task-bound-one-shot/v1",
        "schedulerOwnedTaskRequired": True,
        "currentGraphReverificationRequired": True,
        "grantConsumptionReceiptRequired": True,
        "freshApprovalRequired": True,
        "oneUseActionPermitRequired": True,
        "specialistGatewayRequired": True,
        "deploymentPinnedWorkerVerifierRequired": True,
        "completeAuthoritySetRequiredForRelease": True,
        "directToolDispatchAllowed": False,
        "v1PlanOrPermitUpgradeAllowed": False,
        "callerSelectsReferencesOnly": True,
        "callerAuthoredRoutesAllowed": False,
        "callerAuthoredPayloadsAllowed": False,
        "callerAuthoredPoliciesAllowed": False,
        "callerAuthoredTransportAllowed": False,
        "accountCreationAllowed": False,
        "targetMutationAllowed": False,
        "requestUnits": WEB_SPECIALIST_REQUEST_UNITS,
    }
    schema_digest = capability_definition_digest(
        _PARAMETER_SCHEMA_DOMAIN,
        {
            "model": (
                f"{WebSpecialistAssessmentParameters.__module__}."
                f"{WebSpecialistAssessmentParameters.__qualname__}"
            ),
            "schema": WebSpecialistAssessmentParameters.model_json_schema(by_alias=True),
            "constraints": constraints,
        },
    )
    return capability_definition_from_tool(
        tool.spec,
        ToolCapabilityRegistration(
            capabilityId=WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID,
            capabilityVersion=WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION,
            toolId=WEB_SQLI_SPECIALIST_V2_TOOL_ID,
            domain="bug-bounty",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=("web.application",),
            threatClasses=("CWE-89",),
            preconditions=tuple(
                sorted(
                    (
                        "complete-code-backed-authority-set-required-before-release",
                        "current-durable-specialist-reservation-required-at-dispatch",
                        "exact-code-owned-specialist-preparation",
                        "fresh-action-approval-required",
                        "one-call-non-delegable-grant-required",
                        "one-use-action-permit-required",
                        "preprovisioned-signed-account-receipt",
                        "scheduler-owned-task-required",
                        "schema-v6-job-attempt-required",
                        "signed-lifecycle-range-release-required",
                        "specialist-gateway-required",
                        "terminal-receipt-required",
                        "v1-plan-or-permit-upgrade-forbidden",
                    )
                )
            ),
            parameterSchemaDigest=schema_digest,
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=WEB_SPECIALIST_REQUEST_UNITS,
        ),
    )


@dataclass(frozen=True, slots=True)
class _WebSQLSpecialistAuthorityContractV2:
    """Exact immutable inputs shared by the seven SQLi-only authorities."""

    definition: CapabilityDefinition
    tool: WebSQLSpecialistAuthorizationToolV2

    def stable_context(self) -> Mapping[str, object]:
        return {
            "adapterContractVersion": _AUTHORITY_CONTRACT_VERSION,
            "capabilityId": self.definition.capability_id,
            "capabilityVersion": self.definition.capability_version,
            "specialization": PentestSpecialization.SQL_INJECTION.value,
            "threatClass": "sql-injection",
            "sideEffectClass": CapabilitySideEffectClass.READ_ONLY.value,
            "materializationAllowed": True,
            "requestCompilationAllowed": True,
            "directExecutionAllowed": False,
            "resultNormalizationAllowed": False,
            "successClassificationAllowed": False,
            "replayPlanningAllowed": False,
            "cleanupPlanningAllowed": False,
            "v1AuthorityUpgradeAllowed": False,
            "tool": self.tool.stable_execution_context(),
        }


class _WebSQLSpecialistAuthorityBaseV2:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(self, contract: _WebSQLSpecialistAuthorityContractV2) -> None:
        self._contract = contract

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID}.v2.{self.authority_role.value}"

    @property
    def authority_version(self) -> str:
        return WEB_SQLI_SPECIALIST_V2_AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._contract.definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._contract.stable_context()

    def _require_request(
        self,
        request: ToolRequest,
    ) -> WebSpecialistAssessmentParameters:
        try:
            parameters, _preparation, _adapter, _receipt = self._contract.tool.validate_request(
                request
            )
        except AgenticWebSpecialistV2CapabilityError as exc:
            raise CapabilityAuthorityError(
                "SQL specialist v2 request differs from exact signed material"
            ) from exc
        return parameters

    @staticmethod
    def _dispatch_unavailable() -> Never:
        raise CapabilityAuthorityError(
            "SQL specialist v2 execution requires the schema-v6 specialist Gateway"
        )


class _WebSQLSpecialistMaterializerV2(_WebSQLSpecialistAuthorityBaseV2):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(
        self,
        parameters: Mapping[str, JsonValue],
    ) -> Mapping[str, JsonValue]:
        try:
            parsed = _strict_parameters(dict(parameters))
            self._contract.tool._resolve_parameters(parsed)
        except (AgenticWebSpecialistV2CapabilityError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "SQL specialist v2 parameters require exact installed references"
            ) from exc
        return cast(
            dict[str, JsonValue],
            parsed.model_dump(mode="json", by_alias=True),
        )


class _WebSQLSpecialistActionCompilerV2(_WebSQLSpecialistAuthorityBaseV2):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        requested = self._require_request(request)
        try:
            parsed = _strict_parameters(dict(materialized_arguments))
        except (AgenticWebSpecialistV2CapabilityError, ValidationError) as exc:
            raise CapabilityAuthorityError(
                "SQL specialist v2 materialized parameters are invalid"
            ) from exc
        if parsed != requested:
            raise CapabilityAuthorityError(
                "SQL specialist v2 compiler parameters differ from the request"
            )
        try:
            expected = _WEB_SQL_SPECIALIST_V2_COMPILE_REQUEST_IMPLEMENTATION(
                self._contract.tool,
                preparation_id=parsed.preparation_id,
                preparation_digest=parsed.preparation_digest,
                account_receipt_ref=parsed.account_receipt_ref,
            )
        except (AgenticWebSpecialistV2CapabilityError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError("SQL specialist v2 compiler references drifted") from exc
        if expected != request:
            raise CapabilityAuthorityError(
                "SQL specialist v2 compiler accepts only the exact derived request"
            )
        return expected


class _WebSQLSpecialistExecutorV2(_WebSQLSpecialistAuthorityBaseV2):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._require_request(request)
        self._dispatch_unavailable()


class _WebSQLSpecialistNormalizerV2(_WebSQLSpecialistAuthorityBaseV2):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        del result
        self._require_request(request)
        self._dispatch_unavailable()


class _WebSQLSpecialistOracleV2(_WebSQLSpecialistAuthorityBaseV2):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> CapabilityOracleDecision:
        del result
        self._require_request(request)
        self._dispatch_unavailable()


class _WebSQLSpecialistReplayV2(_WebSQLSpecialistAuthorityBaseV2):
    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del result
        self._require_request(request)
        self._dispatch_unavailable()


class _WebSQLSpecialistCleanupV2(_WebSQLSpecialistAuthorityBaseV2):
    ROLE = CapabilityAuthorityRole.CLEANUP_HANDLER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_cleanup(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        del result
        self._require_request(request)
        self._dispatch_unavailable()


@dataclass(frozen=True, slots=True)
class WebSQLSpecialistCapabilityBundleV2:
    """One SQLi-only v2 Definition and its complete seven-role authority set."""

    tool: WebSQLSpecialistAuthorizationToolV2
    definition: CapabilityDefinition
    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    def capability(self) -> CodeBackedCapability:
        _require_bundle_runtime_v2(self)
        manifests = _CAPABILITY_AUTHORITY_REGISTRY_CAPABILITIES_IMPLEMENTATION(self.authorities)
        if len(manifests) != 1 or manifests[0].capability != self.definition.reference():
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 authority inventory drifted"
            )
        return manifests[0]


class WebSQLSpecialistCapabilityActivationBindingV2(StrictModel):
    """One exact externally signed release admitted for SQLi v2 Range use."""

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
            definition.capability_id != WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID
            or definition.capability_version != WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION
            or action.capability_id != definition.capability_id
            or action.capability_version != definition.capability_version
            or action.definition_digest != definition.capability_digest
            or action.tool_id != WEB_SQLI_SPECIALIST_V2_TOOL_ID
        ):
            raise ValueError("SQL specialist v2 activation references another Capability")
        return self


class WebSQLSpecialistCapabilityActivationSetV2(StrictModel):
    """Content-addressed activation of exactly one signed SQLi v2 release."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-web-sqli-specialist-activation-set/v2alpha1"] = Field(
        default=WEB_SQLI_SPECIALIST_V2_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebSQLSpecialistCapabilityActivationSetV2"] = (
        "WebSQLSpecialistCapabilityActivationSetV2"
    )
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=128)
    activation_set_digest: str = Field(
        default="",
        alias="activationSetDigest",
        max_length=64,
    )
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: WebSQLSpecialistCapabilityActivationBindingV2

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.agentic-web-sqli-specialist-activation-set/v2",
            material,
        )
        activation_set_id = f"agentic-web-sqli-specialist-v2-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("SQL specialist v2 activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("SQL specialist v2 activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class WebSQLSpecialistCapabilityActivationV2:
    """Current signed Range activation that can only prepare a v2 action."""

    bundle: WebSQLSpecialistCapabilityBundleV2
    lifecycle: CapabilityLifecycleRegistry
    activation_set: WebSQLSpecialistCapabilityActivationSetV2
    _factory_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not WebSQLSpecialistCapabilityActivationV2
            or self._factory_token is not _ACTIVATION_FACTORY_TOKEN
        ):
            raise TypeError("SQL specialist v2 activation requires its code-owned factory")
        _verify_activation_v2(self)

    def action_registry(self) -> ActionCapabilityRegistry:
        _verify_activation_v2(self)
        return ActionCapabilityRegistry((self.activation_set.binding.action_capability,))

    def definition(self) -> CapabilityDefinition:
        _verify_activation_v2(self)
        try:
            return _CAPABILITY_DEFINITION_REGISTRY_RESOLVE_IMPLEMENTATION(
                self.bundle.definitions, self.activation_set.binding.capability.capability
            )
        except CapabilityDefinitionError as exc:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 activated Definition is unavailable"
            ) from exc

    def authority(
        self,
        role: CapabilityAuthorityRole,
    ) -> RegisteredCapabilityAuthority:
        _verify_activation_v2(self)
        resolved = _WEB_SQL_SPECIALIST_V2_RESOLVE_FOR_DISPATCH_IMPLEMENTATION(
            self, self.activation_set.binding.action_capability.reference()
        )
        try:
            return _CAPABILITY_AUTHORITY_REGISTRY_AUTHORITY_IMPLEMENTATION(
                self.bundle.authorities,
                resolved.capability.reference(),
                role,
            )
        except (CapabilityAuthorityError, ValueError) as exc:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(
        self,
        reference: ActionCapabilityRef,
    ) -> ResolvedCapabilityRelease:
        _verify_activation_v2(self)
        try:
            canonical = ActionCapabilityRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 GRAPH Capability reference is not canonical"
            ) from exc
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 GRAPH Capability is outside the activation"
            )
        return _resolve_activation_binding_v2(self, binding)

    def prepare_action(
        self,
        *,
        release: CapabilityReleaseRef,
        preparation_id: str,
        preparation_digest: str,
        account_receipt_ref: ProvisionedWebAccountReceiptRef,
    ) -> PreparedCapabilityAction:
        """Compile one v2 action from sealed references without executing it."""

        _verify_activation_v2(self)
        binding = self.activation_set.binding
        canonical_release = _canonical_release_ref_v2(release)
        if binding.release != canonical_release:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 release is outside the activation"
            )
        resolved = _WEB_SQL_SPECIALIST_V2_RESOLVE_FOR_DISPATCH_IMPLEMENTATION(
            self,
            binding.action_capability.reference(),
        )
        request = _WEB_SQL_SPECIALIST_V2_COMPILE_REQUEST_IMPLEMENTATION(
            self.bundle.tool,
            preparation_id=preparation_id,
            preparation_digest=preparation_digest,
            account_receipt_ref=account_receipt_ref,
        )
        try:
            materializer = _CAPABILITY_AUTHORITY_REGISTRY_AUTHORITY_IMPLEMENTATION(
                self.bundle.authorities,
                resolved.capability.reference(),
                CapabilityAuthorityRole.MATERIALIZER,
            )
            compiler = _CAPABILITY_AUTHORITY_REGISTRY_AUTHORITY_IMPLEMENTATION(
                self.bundle.authorities,
                resolved.capability.reference(),
                CapabilityAuthorityRole.ACTION_COMPILER,
            )
            materialized = _REGISTERED_CAPABILITY_AUTHORITY_MATERIALIZE_IMPLEMENTATION(
                materializer, cast(Mapping[str, JsonValue], request.arguments)
            )
            compiled = _REGISTERED_CAPABILITY_AUTHORITY_COMPILE_IMPLEMENTATION(
                compiler,
                request,
                materialized,
            )
        except CapabilityAuthorityError as exc:
            raise AgenticWebSpecialistV2CapabilityError(
                "SQL specialist v2 request preparation failed closed"
            ) from exc
        _verify_activation_v2(self)
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=(capability_normalized_parameters_digest(materialized)),
        )


_WEB_SQL_SPECIALIST_V2_ACTION_REGISTRY_IMPLEMENTATION: Final = (
    WebSQLSpecialistCapabilityActivationV2.action_registry
)
_CAPABILITY_LIFECYCLE_RESOLVE_FOR_USE_IMPLEMENTATION: Final = (
    CapabilityLifecycleRegistry.resolve_for_use
)
_CAPABILITY_LIFECYCLE_RESOLVE_RELEASE_IMPLEMENTATION: Final = (
    CapabilityLifecycleRegistry.resolve_release
)
_CAPABILITY_DEFINITION_REGISTRY_RESOLVE_IMPLEMENTATION: Final = CapabilityDefinitionRegistry.resolve
_CAPABILITY_AUTHORITY_REGISTRY_RESOLVE_IMPLEMENTATION: Final = CapabilityAuthorityRegistry.resolve
_CAPABILITY_AUTHORITY_REGISTRY_AUTHORITY_IMPLEMENTATION: Final = (
    CapabilityAuthorityRegistry.authority
)
_CAPABILITY_AUTHORITY_REGISTRY_CAPABILITIES_IMPLEMENTATION: Final = (
    CapabilityAuthorityRegistry.capabilities
)
_CAPABILITY_AUTHORITY_REGISTRY_VALIDATE_MANIFEST_IMPLEMENTATION: Final = (
    CapabilityAuthorityRegistry._validate_manifest_handles
)
_REGISTERED_CAPABILITY_AUTHORITY_ROLE_IMPLEMENTATION: Final = RegisteredCapabilityAuthority.role
_REGISTERED_CAPABILITY_AUTHORITY_BINDING_IMPLEMENTATION: Final = (
    RegisteredCapabilityAuthority.binding
)
_REGISTERED_CAPABILITY_AUTHORITY_CAPABILITY_IMPLEMENTATION: Final = (
    RegisteredCapabilityAuthority.capability
)
_REGISTERED_CAPABILITY_AUTHORITY_VALIDATE_IMPLEMENTATION: Final = (
    RegisteredCapabilityAuthority.validate_adapter_identity
)
_REGISTERED_CAPABILITY_AUTHORITY_VALIDATE_DECLARED_IMPLEMENTATION: Final = (
    RegisteredCapabilityAuthority.validate_declared_identity
)
_REGISTERED_CAPABILITY_AUTHORITY_MATERIALIZE_IMPLEMENTATION: Final = (
    RegisteredCapabilityAuthority.materialize
)
_REGISTERED_CAPABILITY_AUTHORITY_COMPILE_IMPLEMENTATION: Final = (
    RegisteredCapabilityAuthority.compile
)
_REGISTERED_CAPABILITY_AUTHORITY_BOUND_REQUEST_IMPLEMENTATION: Final = (
    RegisteredCapabilityAuthority._bound_request
)
_REGISTERED_CAPABILITY_AUTHORITY_REQUIRE_ROLE_IMPLEMENTATION: Final = (
    RegisteredCapabilityAuthority._require_role
)
_WEB_SQL_SPECIALIST_V2_BUNDLE_CAPABILITY_IMPLEMENTATION: Final = (
    WebSQLSpecialistCapabilityBundleV2.capability
)
_WEB_SQL_SPECIALIST_V2_COMPILE_REQUEST_IMPLEMENTATION: Final = (
    WebSQLSpecialistAuthorizationToolV2.compile_request
)
_WEB_SQL_SPECIALIST_V2_DEFINITION_IMPLEMENTATION: Final = (
    WebSQLSpecialistCapabilityActivationV2.definition
)
_WEB_SQL_SPECIALIST_V2_PREPARE_ACTION_IMPLEMENTATION: Final = (
    WebSQLSpecialistCapabilityActivationV2.prepare_action
)
_WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION: Final = (
    WebSQLSpecialistAuthorizationToolV2._require_identity
)
_WEB_SQL_SPECIALIST_V2_RESOLVE_FOR_DISPATCH_IMPLEMENTATION: Final = (
    WebSQLSpecialistCapabilityActivationV2.resolve_for_dispatch
)
_WEB_SQL_SPECIALIST_V2_RESOLVE_PARAMETERS_IMPLEMENTATION: Final = (
    WebSQLSpecialistAuthorizationToolV2._resolve_parameters
)
_WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION: Final = (
    WebSQLSpecialistAuthorizationToolV2.validate_request
)
_WEB_SQL_SPECIALIST_V2_STABLE_CONTEXT_IMPLEMENTATION: Final = (
    WebSQLSpecialistAuthorizationToolV2.stable_execution_context
)
_WEB_SQL_SPECIALIST_V2_AUTHORITY_CONTRACT_STABLE_CONTEXT_IMPLEMENTATION: Final = (
    _WebSQLSpecialistAuthorityContractV2.stable_context
)
_WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_STABLE_CONTEXT_IMPLEMENTATION: Final = (
    _WebSQLSpecialistAuthorityBaseV2.stable_execution_context
)
_WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_ROLE_IMPLEMENTATION: Final = (
    _WebSQLSpecialistAuthorityBaseV2.authority_role
)
_WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_ID_IMPLEMENTATION: Final = (
    _WebSQLSpecialistAuthorityBaseV2.authority_id
)
_WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_VERSION_IMPLEMENTATION: Final = (
    _WebSQLSpecialistAuthorityBaseV2.authority_version
)
_WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_CAPABILITY_IMPLEMENTATION: Final = (
    _WebSQLSpecialistAuthorityBaseV2.capability_reference
)
_WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_REQUIRE_REQUEST_IMPLEMENTATION: Final = (
    _WebSQLSpecialistAuthorityBaseV2._require_request
)
_WEB_SQL_SPECIALIST_V2_MATERIALIZER_STABLE_CONTEXT_IMPLEMENTATION: Final = (
    _WebSQLSpecialistMaterializerV2.stable_execution_context
)
_WEB_SQL_SPECIALIST_V2_MATERIALIZE_IMPLEMENTATION: Final = (
    _WebSQLSpecialistMaterializerV2.materialize
)
_WEB_SQL_SPECIALIST_V2_COMPILER_STABLE_CONTEXT_IMPLEMENTATION: Final = (
    _WebSQLSpecialistActionCompilerV2.stable_execution_context
)
_WEB_SQL_SPECIALIST_V2_COMPILE_IMPLEMENTATION: Final = _WebSQLSpecialistActionCompilerV2.compile
_WEB_SQL_SPECIALIST_V2_AUTHORITY_TYPES: Final = (
    (
        CapabilityAuthorityRole.ACTION_COMPILER,
        _WebSQLSpecialistActionCompilerV2,
        _WEB_SQL_SPECIALIST_V2_COMPILER_STABLE_CONTEXT_IMPLEMENTATION,
        "compile",
        _WEB_SQL_SPECIALIST_V2_COMPILE_IMPLEMENTATION,
    ),
    (
        CapabilityAuthorityRole.CLEANUP_HANDLER,
        _WebSQLSpecialistCleanupV2,
        _WebSQLSpecialistCleanupV2.stable_execution_context,
        "plan_cleanup",
        _WebSQLSpecialistCleanupV2.plan_cleanup,
    ),
    (
        CapabilityAuthorityRole.EXECUTOR_ADAPTER,
        _WebSQLSpecialistExecutorV2,
        _WebSQLSpecialistExecutorV2.stable_execution_context,
        "prepare",
        _WebSQLSpecialistExecutorV2.prepare,
    ),
    (
        CapabilityAuthorityRole.MATERIALIZER,
        _WebSQLSpecialistMaterializerV2,
        _WEB_SQL_SPECIALIST_V2_MATERIALIZER_STABLE_CONTEXT_IMPLEMENTATION,
        "materialize",
        _WEB_SQL_SPECIALIST_V2_MATERIALIZE_IMPLEMENTATION,
    ),
    (
        CapabilityAuthorityRole.REPLAY_STRATEGY,
        _WebSQLSpecialistReplayV2,
        _WebSQLSpecialistReplayV2.stable_execution_context,
        "plan_replay",
        _WebSQLSpecialistReplayV2.plan_replay,
    ),
    (
        CapabilityAuthorityRole.RESULT_NORMALIZER,
        _WebSQLSpecialistNormalizerV2,
        _WebSQLSpecialistNormalizerV2.stable_execution_context,
        "normalize",
        _WebSQLSpecialistNormalizerV2.normalize,
    ),
    (
        CapabilityAuthorityRole.SUCCESS_ORACLE,
        _WebSQLSpecialistOracleV2,
        _WebSQLSpecialistOracleV2.stable_execution_context,
        "evaluate",
        _WebSQLSpecialistOracleV2.evaluate,
    ),
)


def web_sqli_specialist_capability_bundle_v2(
    tools: ToolRegistry,
) -> WebSQLSpecialistCapabilityBundleV2:
    """Bind the one exact SQLi v2 Tool to all seven code-backed roles."""

    contract = web_sqli_specialist_planning_contract_v2(tools)
    definitions = CapabilityDefinitionRegistry((contract.definition,))
    authority_contract = _WebSQLSpecialistAuthorityContractV2(
        definition=contract.definition,
        tool=contract.tool,
    )
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _WebSQLSpecialistActionCompilerV2(authority_contract),
        _WebSQLSpecialistCleanupV2(authority_contract),
        _WebSQLSpecialistExecutorV2(authority_contract),
        _WebSQLSpecialistMaterializerV2(authority_contract),
        _WebSQLSpecialistReplayV2(authority_contract),
        _WebSQLSpecialistNormalizerV2(authority_contract),
        _WebSQLSpecialistOracleV2(authority_contract),
    )
    return WebSQLSpecialistCapabilityBundleV2(
        tool=contract.tool,
        definition=contract.definition,
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_web_sqli_specialist_capability_v2(
    *,
    bundle: WebSQLSpecialistCapabilityBundleV2,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> WebSQLSpecialistCapabilityActivationV2:
    """Admit one externally signed current experimental SQLi v2 Range release."""

    if type(bundle) is not WebSQLSpecialistCapabilityBundleV2:
        raise TypeError("SQL specialist v2 activation requires its exact bundle")
    if type(lifecycle) is not CapabilityLifecycleRegistry:
        raise TypeError("SQL specialist v2 activation requires a lifecycle registry")
    canonical_release = _canonical_release_ref_v2(release)
    capability = _WEB_SQL_SPECIALIST_V2_BUNDLE_CAPABILITY_IMPLEMENTATION(bundle).reference()
    try:
        resolved = _CAPABILITY_LIFECYCLE_RESOLVE_FOR_USE_IMPLEMENTATION(
            lifecycle,
            canonical_release,
            CapabilityUseProfile.RANGE,
        )
        signed_bundle = _CAPABILITY_LIFECYCLE_RESOLVE_RELEASE_IMPLEMENTATION(
            lifecycle,
            canonical_release,
        )
        definition = _CAPABILITY_DEFINITION_REGISTRY_RESOLVE_IMPLEMENTATION(
            bundle.definitions,
            capability.capability,
        )
    except (
        CapabilityAuthorityError,
        CapabilityDefinitionError,
        CapabilityLifecycleError,
    ) as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 signed release activation failed closed"
        ) from exc
    if (
        definition != bundle.definition
        or definition != registered_web_sqli_specialist_capability_definition_v2(bundle.tool)
        or resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
        or not definition.approval_required
        or definition.cleanup_required
        or definition.risk_tier is not ToolRiskTier.T2
    ):
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 signed release differs from code authority"
        )
    binding = WebSQLSpecialistCapabilityActivationBindingV2(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest_v2(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    return WebSQLSpecialistCapabilityActivationV2(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=WebSQLSpecialistCapabilityActivationSetV2(binding=binding),
        _factory_token=_ACTIVATION_FACTORY_TOKEN,
    )


def web_sqli_specialist_planning_contract_v2(
    tools: ToolRegistry,
) -> WebSQLSpecialistPlanningContractV2:
    """Resolve the exact v2 Tool and expose planning metadata only."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("SQL specialist v2 planning requires a ToolRegistry")
    try:
        raw_tool = tools.tool(WEB_SQLI_SPECIALIST_V2_TOOL_ID)
        spec = tools.spec(WEB_SQLI_SPECIALIST_V2_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 Tool is unavailable"
        ) from exc
    if type(raw_tool) is not WebSQLSpecialistAuthorizationToolV2 or spec != raw_tool.spec:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 Tool implementation or specification drifted"
        )
    definition = registered_web_sqli_specialist_capability_definition_v2(raw_tool)
    return WebSQLSpecialistPlanningContractV2(
        tool=raw_tool,
        definition=definition,
        action_capability=registered_action_capability(definition),
    )


def _require_bundle_runtime_v2(
    bundle: WebSQLSpecialistCapabilityBundleV2,
) -> None:
    """Revalidate the complete mutable registry and wrapper path before use."""

    try:
        definitions = bundle.definitions
        authorities = bundle.authorities
        definition_records = definitions._records
        handles = authorities._handles
        manifests = authorities._manifests
        definition_key = (
            bundle.definition.capability_id,
            bundle.definition.capability_version,
        )
        capability_key = (
            *definition_key,
            bundle.definition.capability_digest,
        )
        expected_handle_keys = {(*capability_key, role) for role in CapabilityAuthorityRole}
        definition_shadows = getattr(definitions, "__dict__", {})
        authority_shadows = getattr(authorities, "__dict__", {})
        invalid = (
            type(bundle) is not WebSQLSpecialistCapabilityBundleV2
            or type(definitions) is not CapabilityDefinitionRegistry
            or type(authorities) is not CapabilityAuthorityRegistry
            or type(definition_records) is not dict
            or set(definition_records) != {definition_key}
            or definition_records[definition_key] != bundle.definition
            or type(handles) is not dict
            or set(handles) != expected_handle_keys
            or type(manifests) is not dict
            or set(manifests) != {capability_key}
            or manifests[capability_key].capability != bundle.definition.reference()
            or CapabilityDefinitionRegistry.resolve
            is not _CAPABILITY_DEFINITION_REGISTRY_RESOLVE_IMPLEMENTATION
            or CapabilityAuthorityRegistry.resolve
            is not _CAPABILITY_AUTHORITY_REGISTRY_RESOLVE_IMPLEMENTATION
            or CapabilityAuthorityRegistry.authority
            is not _CAPABILITY_AUTHORITY_REGISTRY_AUTHORITY_IMPLEMENTATION
            or CapabilityAuthorityRegistry.capabilities
            is not _CAPABILITY_AUTHORITY_REGISTRY_CAPABILITIES_IMPLEMENTATION
            or CapabilityAuthorityRegistry._validate_manifest_handles
            is not _CAPABILITY_AUTHORITY_REGISTRY_VALIDATE_MANIFEST_IMPLEMENTATION
            or RegisteredCapabilityAuthority.role
            is not _REGISTERED_CAPABILITY_AUTHORITY_ROLE_IMPLEMENTATION
            or RegisteredCapabilityAuthority.binding
            is not _REGISTERED_CAPABILITY_AUTHORITY_BINDING_IMPLEMENTATION
            or RegisteredCapabilityAuthority.capability
            is not _REGISTERED_CAPABILITY_AUTHORITY_CAPABILITY_IMPLEMENTATION
            or RegisteredCapabilityAuthority.validate_adapter_identity
            is not _REGISTERED_CAPABILITY_AUTHORITY_VALIDATE_IMPLEMENTATION
            or RegisteredCapabilityAuthority.validate_declared_identity
            is not _REGISTERED_CAPABILITY_AUTHORITY_VALIDATE_DECLARED_IMPLEMENTATION
            or RegisteredCapabilityAuthority.materialize
            is not _REGISTERED_CAPABILITY_AUTHORITY_MATERIALIZE_IMPLEMENTATION
            or RegisteredCapabilityAuthority.compile
            is not _REGISTERED_CAPABILITY_AUTHORITY_COMPILE_IMPLEMENTATION
            or RegisteredCapabilityAuthority._bound_request
            is not _REGISTERED_CAPABILITY_AUTHORITY_BOUND_REQUEST_IMPLEMENTATION
            or RegisteredCapabilityAuthority._require_role
            is not _REGISTERED_CAPABILITY_AUTHORITY_REQUIRE_ROLE_IMPLEMENTATION
            or _WebSQLSpecialistAuthorityContractV2.stable_context
            is not _WEB_SQL_SPECIALIST_V2_AUTHORITY_CONTRACT_STABLE_CONTEXT_IMPLEMENTATION
            or _WebSQLSpecialistAuthorityBaseV2.authority_role
            is not _WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_ROLE_IMPLEMENTATION
            or _WebSQLSpecialistAuthorityBaseV2.authority_id
            is not _WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_ID_IMPLEMENTATION
            or _WebSQLSpecialistAuthorityBaseV2.authority_version
            is not _WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_VERSION_IMPLEMENTATION
            or _WebSQLSpecialistAuthorityBaseV2.capability_reference
            is not _WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_CAPABILITY_IMPLEMENTATION
            or _WebSQLSpecialistAuthorityBaseV2.stable_execution_context
            is not _WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_STABLE_CONTEXT_IMPLEMENTATION
            or _WebSQLSpecialistAuthorityBaseV2._require_request
            is not _WEB_SQL_SPECIALIST_V2_AUTHORITY_BASE_REQUIRE_REQUEST_IMPLEMENTATION
            or "resolve" in definition_shadows
            or any(
                name in authority_shadows
                for name in (
                    "resolve",
                    "authority",
                    "capabilities",
                    "_validate_manifest_handles",
                )
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 registry runtime identity drifted"
        ) from exc
    if invalid:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 registry runtime identity drifted"
        )

    shared_contract: _WebSQLSpecialistAuthorityContractV2 | None = None
    try:
        for (
            role,
            adapter_type,
            stable_implementation,
            action_name,
            action_implementation,
        ) in _WEB_SQL_SPECIALIST_V2_AUTHORITY_TYPES:
            handle = handles[(*capability_key, role)]
            adapter = handle._adapter
            contract = getattr(adapter, "_contract", None)
            adapter_shadows = getattr(adapter, "__dict__", {})
            if (
                type(handle) is not RegisteredCapabilityAuthority
                or type(adapter) is not adapter_type
                or getattr(adapter_type, "ROLE", None) is not role
                or getattr(adapter_type, "stable_execution_context", None)
                is not stable_implementation
                or getattr(adapter_type, action_name, None) is not action_implementation
                or type(contract) is not _WebSQLSpecialistAuthorityContractV2
                or contract.tool is not bundle.tool
                or contract.definition != bundle.definition
                or handle._definition != bundle.definition
                or handle._binding.role is not role
                or any(
                    name in adapter_shadows
                    for name in (
                        "authority_role",
                        "authority_id",
                        "authority_version",
                        "capability_reference",
                        "stable_execution_context",
                        "_require_request",
                        action_name,
                    )
                )
            ):
                raise AgenticWebSpecialistV2CapabilityError(
                    "SQL specialist v2 authority runtime identity drifted"
                )
            if shared_contract is None:
                shared_contract = contract
            elif contract is not shared_contract:
                raise AgenticWebSpecialistV2CapabilityError(
                    "SQL specialist v2 authority contract identity drifted"
                )
            _REGISTERED_CAPABILITY_AUTHORITY_VALIDATE_IMPLEMENTATION(handle)
            _REGISTERED_CAPABILITY_AUTHORITY_VALIDATE_DECLARED_IMPLEMENTATION(handle)
        _CAPABILITY_AUTHORITY_REGISTRY_VALIDATE_MANIFEST_IMPLEMENTATION(
            authorities,
            manifests[capability_key],
        )
    except AgenticWebSpecialistV2CapabilityError:
        raise
    except (AttributeError, CapabilityAuthorityError, KeyError, TypeError, ValueError) as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 authority registry validation failed closed"
        ) from exc


def _verify_activation_v2(
    activation: WebSQLSpecialistCapabilityActivationV2,
) -> None:
    tool = activation.bundle.tool
    tool_shadows = getattr(tool, "__dict__", {})
    lifecycle_shadows = getattr(activation.lifecycle, "__dict__", {})
    if (
        type(activation) is not WebSQLSpecialistCapabilityActivationV2
        or activation._factory_token is not _ACTIVATION_FACTORY_TOKEN
        or type(activation.bundle) is not WebSQLSpecialistCapabilityBundleV2
        or type(activation.lifecycle) is not CapabilityLifecycleRegistry
        or type(activation.activation_set) is not WebSQLSpecialistCapabilityActivationSetV2
        or type(tool) is not WebSQLSpecialistAuthorizationToolV2
        or WebSQLSpecialistAuthorizationToolV2.stable_execution_context
        is not _WEB_SQL_SPECIALIST_V2_STABLE_CONTEXT_IMPLEMENTATION
        or WebSQLSpecialistCapabilityActivationV2.resolve_for_dispatch
        is not _WEB_SQL_SPECIALIST_V2_RESOLVE_FOR_DISPATCH_IMPLEMENTATION
        or WebSQLSpecialistAuthorizationToolV2.compile_request
        is not _WEB_SQL_SPECIALIST_V2_COMPILE_REQUEST_IMPLEMENTATION
        or WebSQLSpecialistAuthorizationToolV2._resolve_parameters
        is not _WEB_SQL_SPECIALIST_V2_RESOLVE_PARAMETERS_IMPLEMENTATION
        or WebSQLSpecialistAuthorizationToolV2._require_identity
        is not _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION
        or WebSQLSpecialistAuthorizationToolV2.validate_request
        is not _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION
        or WebSQLSpecialistCapabilityBundleV2.capability
        is not _WEB_SQL_SPECIALIST_V2_BUNDLE_CAPABILITY_IMPLEMENTATION
        or CapabilityLifecycleRegistry.resolve_for_use
        is not _CAPABILITY_LIFECYCLE_RESOLVE_FOR_USE_IMPLEMENTATION
        or CapabilityLifecycleRegistry.resolve_release
        is not _CAPABILITY_LIFECYCLE_RESOLVE_RELEASE_IMPLEMENTATION
        or any(
            name in tool_shadows
            for name in (
                "compile_request",
                "validate_request",
                "stable_execution_context",
                "_resolve_parameters",
                "_require_identity",
            )
        )
        or "resolve_for_use" in lifecycle_shadows
        or "resolve_release" in lifecycle_shadows
    ):
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 activation runtime identity drifted"
        )
    _require_bundle_runtime_v2(activation.bundle)
    try:
        canonical = WebSQLSpecialistCapabilityActivationSetV2.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 activation set is not canonical"
        ) from exc
    if canonical != activation.activation_set:
        raise AgenticWebSpecialistV2CapabilityError("SQL specialist v2 activation set drifted")
    _resolve_activation_binding_v2(activation, canonical.binding)


def _resolve_activation_binding_v2(
    activation: WebSQLSpecialistCapabilityActivationV2,
    binding: WebSQLSpecialistCapabilityActivationBindingV2,
) -> ResolvedCapabilityRelease:
    if type(binding) is not WebSQLSpecialistCapabilityActivationBindingV2:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 activation binding type drifted"
        )
    try:
        resolved = _CAPABILITY_LIFECYCLE_RESOLVE_FOR_USE_IMPLEMENTATION(
            activation.lifecycle,
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        signed_bundle = _CAPABILITY_LIFECYCLE_RESOLVE_RELEASE_IMPLEMENTATION(
            activation.lifecycle,
            binding.release,
        )
        code_capability = _WEB_SQL_SPECIALIST_V2_BUNDLE_CAPABILITY_IMPLEMENTATION(
            activation.bundle
        ).reference()
        current_definition = registered_web_sqli_specialist_capability_definition_v2(
            activation.bundle.tool
        )
        registered_definition = _CAPABILITY_DEFINITION_REGISTRY_RESOLVE_IMPLEMENTATION(
            activation.bundle.definitions, current_definition.reference()
        )
        expected_action = registered_action_capability(current_definition)
    except (
        CapabilityAuthorityError,
        CapabilityDefinitionError,
        CapabilityLifecycleError,
    ) as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 current signed release could not be resolved"
        ) from exc
    if (
        current_definition != activation.bundle.definition
        or registered_definition != current_definition
        or resolved.capability.reference() != binding.capability
        or code_capability != binding.capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest_v2(signed_bundle) != binding.release_bundle_digest
        or binding.action_capability != expected_action
    ):
        raise AgenticWebSpecialistV2CapabilityError("SQL specialist v2 signed activation drifted")
    return resolved


def _release_bundle_digest_v2(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.agentic-web-sqli-specialist-release-bundle/v2",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref_v2(
    reference: CapabilityReleaseRef,
) -> CapabilityReleaseRef:
    try:
        return CapabilityReleaseRef.model_validate(reference.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 release reference is not canonical"
        ) from exc


def _strict_parameters(value: object) -> WebSpecialistAssessmentParameters:
    if type(value) is not dict:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 parameters must be one exact JSON object"
        )
    raw = cast(dict[object, object], value)
    if set(raw) != {"preparationId", "preparationDigest", "accountReceiptRef"} or any(
        type(key) is not str for key in raw
    ):
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 parameters contain unsupported fields or aliases"
        )
    receipt = raw["accountReceiptRef"]
    if type(receipt) is not dict or set(cast(dict[object, object], receipt)) != {
        "receiptId",
        "receiptDigest",
    }:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 account receipt reference is not exact JSON"
        )
    try:
        parsed = WebSpecialistAssessmentParameters.model_validate(value)
    except ValidationError as exc:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 parameters failed strict validation"
        ) from exc
    if parsed.model_dump(mode="json", by_alias=True) != value:
        raise AgenticWebSpecialistV2CapabilityError(
            "SQL specialist v2 parameters differ after strict reload"
        )
    return parsed


def _request_id(
    preparation: AgenticSpecialistPreparation,
    parameters: WebSpecialistAssessmentParameters,
) -> str:
    digest = capability_definition_digest(
        _REQUEST_IDENTITY_DOMAIN,
        {
            "toolId": WEB_SQLI_SPECIALIST_V2_TOOL_ID,
            "toolVersion": WEB_SQLI_SPECIALIST_V2_TOOL_VERSION,
            "specialization": PentestSpecialization.SQL_INJECTION.value,
            "agentId": preparation.target_agent_id,
            "target": preparation.target_endpoint,
            "parameters": parameters.model_dump(mode="json", by_alias=True),
        },
    )
    return f"agentic-specialist-v2-request_{digest}"


def _legacy_request_id(
    preparation: AgenticSpecialistPreparation,
    parameters: WebSpecialistAssessmentParameters,
) -> str:
    digest = capability_definition_digest(
        _LEGACY_REQUEST_IDENTITY_DOMAIN,
        {
            "toolId": WEB_SQLI_SPECIALIST_TOOL_ID,
            "toolVersion": WEB_SPECIALIST_TOOL_VERSION,
            "specialization": PentestSpecialization.SQL_INJECTION.value,
            "agentId": preparation.target_agent_id,
            "target": preparation.target_endpoint,
            "parameters": parameters.model_dump(mode="json", by_alias=True),
        },
    )
    return f"agentic-specialist-request_{digest}"


def _direct_dispatch_unavailable() -> Never:
    raise AgenticWebSpecialistV2CapabilityError(
        "SQL specialist v2 requires the schema-v6 specialist Gateway authority"
    )


__all__ = [
    "AGENTIC_SPECIALIST_CLAIM_VERIFICATION_API_VERSION",
    "AGENTIC_SPECIALIST_DISPATCH_VERIFICATION_API_VERSION",
    "AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION",
    "AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION",
    "WEB_SQLI_SPECIALIST_V2_ACTIVATION_SET_API_VERSION",
    "WEB_SQLI_SPECIALIST_V2_AUTHORITY_VERSION",
    "WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID",
    "WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION",
    "WEB_SQLI_SPECIALIST_V2_TOOL_ID",
    "WEB_SQLI_SPECIALIST_V2_TOOL_VERSION",
    "AgenticWebSpecialistV2CapabilityError",
    "WebSQLSpecialistAuthorizationToolV2",
    "WebSQLSpecialistCapabilityActivationBindingV2",
    "WebSQLSpecialistCapabilityActivationSetV2",
    "WebSQLSpecialistCapabilityActivationV2",
    "WebSQLSpecialistCapabilityBundleV2",
    "WebSQLSpecialistPlanningContractV2",
    "activate_web_sqli_specialist_capability_v2",
    "registered_web_sqli_specialist_capability_definition_v2",
    "web_sqli_specialist_capability_bundle_v2",
    "web_sqli_specialist_planning_contract_v2",
]
