"""Executable, approved read-only Capability for authenticated Web assessment.

This Capability is intentionally separate from WEB-004's registration-only,
irreversible-write boundary.  It accepts only references to deployment-installed
signed material, consumes a per-dispatch Permit binding once, and delegates job
compilation plus signed result verification to code-owned deployment adapters.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import ClassVar, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, JsonValue, ValidationError, model_validator

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
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.graph.approval import (
    ActionApprovalEnvelope,
    ApprovedActionDispatchResult,
)
from pajin.graph.authority import (
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
)
from pajin.graph.consistency import GraphDecision
from pajin.runtime.stable_context import stable_execution_context
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolRegistry, ToolSpec, audit_safe_worker_failure
from pajin.web_assessment.governed_models import (
    GovernedWebAssessmentModelError,
    ProvisionedWebAccountReceipt,
    ProvisionedWebAccountReceiptRef,
    ProvisionedWebAccountReceiptRegistry,
    WebAssessmentAdapterManifest,
    WebAssessmentAdapterRef,
    WebAssessmentAdapterRegistry,
    WebAssessmentDispatchBinding,
    WebAssessmentDispatchBindingRegistry,
    WebAssessmentDispatchDeployment,
    WebAuthenticatedAssessmentWorkerOutput,
)

WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_ID = (
    "pajin.bug-bounty.web-authenticated-read-only-assessment"
)
WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_VERSION = "1.0.0"
WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID = "web.authenticated-read-only-assessment"
WEB_AUTHENTICATED_ASSESSMENT_TOOL_VERSION = "1.0.0"
WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS = 100
WEB_AUTHENTICATED_ASSESSMENT_ACTIVATION_SET_API_VERSION: Literal[
    "pajin.dev/web-authenticated-assessment-activation-set/v1alpha1"
] = "pajin.dev/web-authenticated-assessment-activation-set/v1alpha1"

_AUTHORITY_VERSION = "1.0.0"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"


class WebAuthenticatedAssessmentCapabilityError(ValueError):
    """Raised when WEB-005 code, signed inputs, or lifecycle activation drift."""


class WebAuthenticatedAssessmentParameters(StrictModel):
    """The only caller-selectable inputs: two exact deployment-owned references."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    adapter: WebAssessmentAdapterRef
    account_receipt: ProvisionedWebAccountReceiptRef = Field(alias="accountReceipt")


class WebAuthenticatedAssessmentJobCompiler(Protocol):
    """Deployment adapter compiling verified inputs into a secret-free Worker job."""

    def stable_execution_context(self) -> Mapping[str, object]: ...

    def compile_job(
        self,
        *,
        request: ToolRequest,
        adapter: WebAssessmentAdapterManifest,
        account_receipt: ProvisionedWebAccountReceipt,
        dispatch: WebAssessmentDispatchBinding,
    ) -> WorkerJob: ...


class WebAuthenticatedAssessmentOutputVerifier(Protocol):
    """Deployment adapter verifying a signed Worker attestation and sealed Run."""

    def stable_execution_context(self) -> Mapping[str, object]: ...

    def verify_output(
        self,
        *,
        request: ToolRequest,
        dispatch: WebAssessmentDispatchBinding,
        worker_result: WorkerResult,
    ) -> WebAuthenticatedAssessmentWorkerOutput: ...


class WebAuthenticatedAssessmentTool(Tool):
    """Prepare and verify one Permit-bound authenticated read-only assessment."""

    spec = ToolSpec(
        tool_id=WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID,
        version=WEB_AUTHENTICATED_ASSESSMENT_TOOL_VERSION,
        description=(
            "Run a signed exact-origin authenticated Web assessment with a preprovisioned account"
        ),
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"active-test", "browser", "bug-bounty", "web"}),
        evidence_types=frozenset(
            {"browser-screenshot", "http-observation", "json", "signed-attestation"}
        ),
        network_access=True,
        network_request_cost=WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
        parallel_safe=False,
    )

    def __init__(
        self,
        *,
        adapters: WebAssessmentAdapterRegistry,
        account_receipts: ProvisionedWebAccountReceiptRegistry,
        dispatch_bindings: WebAssessmentDispatchBindingRegistry,
        job_compiler: WebAuthenticatedAssessmentJobCompiler,
        output_verifier: WebAuthenticatedAssessmentOutputVerifier,
    ) -> None:
        if not isinstance(adapters, WebAssessmentAdapterRegistry):
            raise TypeError("authenticated Web Tool requires an adapter registry")
        if not isinstance(account_receipts, ProvisionedWebAccountReceiptRegistry):
            raise TypeError("authenticated Web Tool requires an account receipt registry")
        if not isinstance(dispatch_bindings, WebAssessmentDispatchBindingRegistry):
            raise TypeError("authenticated Web Tool requires a dispatch binding registry")
        self.adapters = adapters
        self.account_receipts = account_receipts
        self.dispatch_bindings = dispatch_bindings
        self.job_compiler = job_compiler
        self.output_verifier = output_verifier
        self._compiler_context = stable_execution_context(
            job_compiler,
            component="authenticated Web job compiler",
        )
        self._verifier_context = stable_execution_context(
            output_verifier,
            component="authenticated Web output verifier",
        )

    def stable_execution_context(self) -> dict[str, object]:
        tool_spec = self.spec.model_dump(mode="json")
        tool_spec["categories"] = sorted(self.spec.categories)
        tool_spec["evidence_types"] = sorted(self.spec.evidence_types)
        return {
            "implementationVersion": "pajin.web-authenticated-assessment-tool/v1",
            "spec": tool_spec,
            "adapterRegistryDigest": self.adapters.registry_digest,
            "accountReceiptTrustAnchorDigest": self.account_receipts.trust_anchor_digest,
            "dispatchBindingVersion": "pajin.web-assessment.dispatch-binding/v4",
            "dispatchAuthority": self.dispatch_bindings.stable_execution_context(),
            "jobCompiler": self._compiler_context,
            "outputVerifier": self._verifier_context,
            "callerAuthoredRoutesAllowed": False,
            "callerAuthoredPayloadsAllowed": False,
            "accountCreationAllowed": False,
            "targetMutationAllowed": False,
        }

    async def dispatch_approved_once[DispatchResultT](
        self,
        *,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        worker_execution_id: str,
        target_observer_execution_id: str,
        output_root_reference: str,
        worker_signing_material_ref: str,
        target_observer_signing_material_ref: str,
        dispatch: Callable[[WebAssessmentDispatchBinding], Awaitable[DispatchResultT]],
    ) -> ApprovedActionDispatchResult[DispatchResultT]:
        """Dispatch only through the first live Graph approval-consumption callback."""

        _parameters, adapter, account_receipt = self.validate_request(request)
        definition = registered_web_authenticated_assessment_capability_definition(self)
        return await self.dispatch_bindings.dispatch_approved_once(
            envelope=envelope,
            proposal=proposal,
            decision=decision,
            approval=approval,
            campaign=campaign,
            grant=grant,
            capability=registered_action_capability(definition),
            request=request,
            adapter=adapter,
            account_receipt=account_receipt,
            deployment=WebAssessmentDispatchDeployment(
                expectedRunId=envelope.run_id,
                workerExecutionId=worker_execution_id,
                targetObserverExecutionId=target_observer_execution_id,
                outputRootReference=output_root_reference,
                workerSigningMaterialRef=worker_signing_material_ref,
                targetObserverSigningMaterialRef=target_observer_signing_material_ref,
            ),
            dispatch=dispatch,
        )

    def validate_request(
        self,
        request: ToolRequest,
    ) -> tuple[
        WebAuthenticatedAssessmentParameters,
        WebAssessmentAdapterManifest,
        ProvisionedWebAccountReceipt,
    ]:
        if request.tool_id != self.spec.tool_id or request.method != "POST" or not request.target:
            raise ValueError("authenticated Web request identity is unsupported")
        try:
            parameters = WebAuthenticatedAssessmentParameters.model_validate(request.arguments)
            adapter = self.adapters.resolve(parameters.adapter)
            receipt = self.account_receipts.resolve(parameters.account_receipt)
        except (GovernedWebAssessmentModelError, ValidationError, ValueError) as exc:
            raise ValueError(
                "authenticated Web request references untrusted deployment material"
            ) from exc
        if (
            request.target != adapter.origin
            or receipt.adapter != adapter.reference()
            or receipt.origin != adapter.origin
        ):
            raise ValueError("authenticated Web request target, adapter, and account differ")
        return parameters, adapter, receipt

    def network_request_cost(self, request: ToolRequest) -> int:
        self.validate_request(request)
        return WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS

    def network_response_byte_limit(self, request: ToolRequest) -> int | None:
        self.validate_request(request)
        return 8_000_000

    def prepare(self, request: ToolRequest) -> WorkerJob:
        parameters, adapter, receipt = self.validate_request(request)
        dispatch = self.dispatch_bindings.consume(request.request_id)
        definition = registered_web_authenticated_assessment_capability_definition(self)
        if (
            dispatch.request_id != request.request_id
            or dispatch.request_digest != capability_tool_request_digest(request)
            or dispatch.capability_id != definition.capability_id
            or dispatch.capability_version != definition.capability_version
            or dispatch.capability_digest != definition.capability_digest
            or dispatch.adapter != parameters.adapter
            or dispatch.account_receipt != parameters.account_receipt
        ):
            raise ValueError("authenticated Web dispatch differs from request authority")
        try:
            compiled = self.job_compiler.compile_job(
                request=request.model_copy(deep=True),
                adapter=adapter.model_copy(deep=True),
                account_receipt=receipt.model_copy(deep=True),
                dispatch=dispatch.model_copy(deep=True),
            )
            job = WorkerJob.model_validate(compiled.model_dump(mode="python"))
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise ValueError("authenticated Web Worker job compilation failed closed") from exc
        secret_bindings = {item.binding: item.secret_ref for item in job.secret_requests}
        expected_secrets = {
            "account-name": receipt.identity_material_ref,
            "account-proof": receipt.proof_material_ref,
            "target-observer-signing-key": dispatch.target_observer_signing_material_ref,
            "worker-signing-key": dispatch.worker_signing_material_ref,
        }
        forbidden_material = tuple(expected_secrets.values())
        if (
            job.execution_id != dispatch.worker_execution_id
            or job.network is not NetworkMode.NONE
            or job.egress_policy is not None
            or secret_bindings != expected_secrets
            or len(job.secret_requests) != len(expected_secrets)
            or any(item in job.stdin for item in forbidden_material)
        ):
            raise ValueError("authenticated Web Worker job expanded trusted authority")
        return job

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        self.validate_request(request)
        if result.status is not WorkerStatus.SUCCEEDED:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_worker_failure(result),
            )
        try:
            output = self._verified_output(request, result)
        except (AttributeError, TypeError, ValidationError, ValueError):
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error="authenticated Web Worker returned invalid or mismatched evidence",
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data={
                "workerOutput": output.model_dump(mode="json", by_alias=True),
            },
            evidence=[],
        )

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        del network_log_trusted
        output = self._verified_output(request, worker_result)
        try:
            projected = WebAuthenticatedAssessmentWorkerOutput.model_validate(
                result.data["workerOutput"]
            )
        except (KeyError, TypeError, ValidationError) as exc:
            raise ValueError("authenticated Web Tool result lacks verified Worker output") from exc
        if projected != output or not result.success:
            raise ValueError("authenticated Web Tool projection differs from signed Worker output")
        self.dispatch_bindings.complete(request.request_id)

    def _verified_output(
        self,
        request: ToolRequest,
        worker_result: WorkerResult,
    ) -> WebAuthenticatedAssessmentWorkerOutput:
        parameters, adapter, _receipt = self.validate_request(request)
        dispatch = self.dispatch_bindings.consumed(request.request_id)
        output = self.output_verifier.verify_output(
            request=request.model_copy(deep=True),
            dispatch=dispatch.model_copy(deep=True),
            worker_result=worker_result.model_copy(deep=True),
        )
        canonical = WebAuthenticatedAssessmentWorkerOutput.model_validate(
            output.model_dump(mode="json", by_alias=True)
        )
        if (
            worker_result.execution_id != dispatch.worker_execution_id
            or canonical.worker_execution_id != dispatch.worker_execution_id
            or canonical.dispatch_binding_digest != dispatch.binding_digest
            or canonical.adapter != parameters.adapter
            or canonical.account_receipt != parameters.account_receipt
            or canonical.origin != adapter.origin
        ):
            raise ValueError("signed Web Worker output differs from the dispatch binding")
        return canonical


@dataclass(frozen=True, slots=True)
class WebAuthenticatedAssessmentCapabilityBundle:
    """One complete executable CAP-001/CAP-002 bundle."""

    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry

    @property
    def capability(self) -> CodeBackedCapability:
        capabilities = self.authorities.capabilities()
        if len(capabilities) != 1:
            raise WebAuthenticatedAssessmentCapabilityError(
                "authenticated Web authority inventory is not singular"
            )
        return capabilities[0]


class WebAuthenticatedAssessmentCapabilityActivationBinding(StrictModel):
    """One exact externally signed release bound to GRAPH Action metadata."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release: CapabilityReleaseRef
    release_bundle_digest: str = Field(alias="releaseBundleDigest", pattern=_SHA256_PATTERN)
    capability: CodeBackedCapabilityRef
    action_capability: RegisteredActionCapability = Field(alias="actionCapability")

    @model_validator(mode="after")
    def bind_exact_capability(self) -> Self:
        definition = self.capability.capability
        action = self.action_capability
        if (
            definition.capability_id != WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_ID
            or definition.capability_version != WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_VERSION
            or action.capability_id != definition.capability_id
            or action.capability_version != definition.capability_version
            or action.definition_digest != definition.capability_digest
        ):
            raise ValueError("authenticated Web activation references another Capability")
        return self


class WebAuthenticatedAssessmentCapabilityActivationSet(StrictModel):
    """Content-addressed activation of exactly one signed Range release."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-authenticated-assessment-activation-set/v1alpha1"] = Field(
        default=WEB_AUTHENTICATED_ASSESSMENT_ACTIVATION_SET_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAuthenticatedAssessmentCapabilityActivationSet"] = (
        "WebAuthenticatedAssessmentCapabilityActivationSet"
    )
    activation_set_id: str = Field(default="", alias="activationSetId", max_length=120)
    activation_set_digest: str = Field(
        default="",
        alias="activationSetDigest",
        max_length=64,
    )
    profile: Literal[CapabilityUseProfile.RANGE] = CapabilityUseProfile.RANGE
    binding: WebAuthenticatedAssessmentCapabilityActivationBinding

    @model_validator(mode="after")
    def bind_activation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.web-authenticated-assessment-activation-set/v1",
            material,
        )
        activation_set_id = f"web-authenticated-activation-set_{digest}"
        if self.activation_set_digest and self.activation_set_digest != digest:
            raise ValueError("authenticated Web activation-set digest differs")
        if self.activation_set_id and self.activation_set_id != activation_set_id:
            raise ValueError("authenticated Web activation-set ID differs")
        object.__setattr__(self, "activation_set_digest", digest)
        object.__setattr__(self, "activation_set_id", activation_set_id)
        return self


@dataclass(frozen=True, slots=True)
class WebAuthenticatedAssessmentCapabilityActivation:
    """Runtime activation that revalidates the signed current release on every use."""

    bundle: WebAuthenticatedAssessmentCapabilityBundle
    lifecycle: CapabilityLifecycleRegistry
    activation_set: WebAuthenticatedAssessmentCapabilityActivationSet

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
            raise WebAuthenticatedAssessmentCapabilityError(
                "activated Web Definition is unavailable"
            ) from exc

    def authority(self, role: CapabilityAuthorityRole) -> RegisteredCapabilityAuthority:
        resolved = self.resolve_for_dispatch(
            self.activation_set.binding.action_capability.reference()
        )
        try:
            return self.bundle.authorities.authority(resolved.capability.reference(), role)
        except CapabilityAuthorityError as exc:
            raise WebAuthenticatedAssessmentCapabilityError(
                "authenticated Web authority resolution failed closed"
            ) from exc

    def resolve_for_dispatch(
        self,
        reference: ActionCapabilityRef,
    ) -> ResolvedCapabilityRelease:
        try:
            canonical = ActionCapabilityRef.model_validate(
                reference.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise WebAuthenticatedAssessmentCapabilityError(
                "authenticated Web GRAPH Capability reference is not canonical"
            ) from exc
        binding = self.activation_set.binding
        if binding.action_capability.reference() != canonical:
            raise WebAuthenticatedAssessmentCapabilityError(
                "authenticated Web GRAPH Capability is outside the activation"
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
            raise WebAuthenticatedAssessmentCapabilityError(
                "authenticated Web release is outside the activation"
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
            raise WebAuthenticatedAssessmentCapabilityError(
                "authenticated Web request preparation failed closed"
            ) from exc
        return PreparedCapabilityAction(
            activationSetDigest=self.activation_set.activation_set_digest,
            release=canonical_release,
            capability=binding.action_capability.reference(),
            request=compiled,
            requestDigest=capability_tool_request_digest(compiled),
            normalizedParametersDigest=capability_normalized_parameters_digest(materialized),
        )


@dataclass(frozen=True, slots=True)
class _WebAuthenticatedAssessmentContract:
    definition: CapabilityDefinition
    tool: WebAuthenticatedAssessmentTool

    def stable_context(self) -> Mapping[str, object]:
        return {
            "adapterContractVersion": "pajin.web-authenticated-assessment-adapter/v1",
            "capabilityId": self.definition.capability_id,
            "capabilityVersion": self.definition.capability_version,
            "sideEffectClass": CapabilitySideEffectClass.READ_ONLY.value,
            "freshApprovalRequired": True,
            "cleanupRequired": False,
            "tool": self.tool.stable_execution_context(),
        }


class _WebAuthenticatedAssessmentAuthorityBase:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(self, contract: _WebAuthenticatedAssessmentContract) -> None:
        self._contract = contract

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_ID}.{self.ROLE.value}"

    @property
    def authority_version(self) -> str:
        return _AUTHORITY_VERSION

    @property
    def capability_reference(self) -> CapabilityDefinitionRef:
        return self._contract.definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return self._contract.stable_context()

    def _require_request(self, request: ToolRequest) -> WebAuthenticatedAssessmentParameters:
        try:
            parameters, _adapter, _receipt = self._contract.tool.validate_request(request)
            return parameters
        except ValueError as exc:
            raise CapabilityAuthorityError(
                "authenticated Web request differs from signed deployment material"
            ) from exc


class _WebAuthenticatedAssessmentMaterializer(_WebAuthenticatedAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.MATERIALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def materialize(self, parameters: Mapping[str, JsonValue]) -> Mapping[str, JsonValue]:
        try:
            parsed = WebAuthenticatedAssessmentParameters.model_validate(parameters)
            self._contract.tool.adapters.resolve(parsed.adapter)
            receipt = self._contract.tool.account_receipts.resolve(parsed.account_receipt)
        except (GovernedWebAssessmentModelError, ValidationError, ValueError) as exc:
            raise CapabilityAuthorityError(
                "authenticated Web parameters require signed installed references"
            ) from exc
        if receipt.adapter != parsed.adapter:
            raise CapabilityAuthorityError(
                "authenticated Web account receipt belongs to another adapter"
            )
        return cast(dict[str, JsonValue], parsed.model_dump(mode="json", by_alias=True))


class _WebAuthenticatedAssessmentActionCompiler(_WebAuthenticatedAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.ACTION_COMPILER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        self._require_request(request)
        parsed = WebAuthenticatedAssessmentParameters.model_validate(materialized_arguments)
        compiled = request.model_copy(
            update={"arguments": parsed.model_dump(mode="json", by_alias=True)}
        )
        self._require_request(compiled)
        return compiled


class _WebAuthenticatedAssessmentExecutor(_WebAuthenticatedAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.EXECUTOR_ADAPTER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self._require_request(request)
        return self._contract.tool.prepare(request)


class _WebAuthenticatedAssessmentNormalizer(_WebAuthenticatedAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.RESULT_NORMALIZER

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        self._require_request(request)
        return self._contract.tool.interpret(request, result)


class _WebAuthenticatedAssessmentOracle(_WebAuthenticatedAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.SUCCESS_ORACLE

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def evaluate(self, request: ToolRequest, result: ToolResult) -> CapabilityOracleDecision:
        self._require_request(request)
        if not result.success:
            return CapabilityOracleDecision.FAILED
        try:
            output = WebAuthenticatedAssessmentWorkerOutput.model_validate(
                result.data["workerOutput"]
            )
        except (KeyError, TypeError, ValidationError):
            return CapabilityOracleDecision.INCONCLUSIVE
        return (
            CapabilityOracleDecision.SUCCEEDED
            if output.authenticated
            and output.browser_closed
            and not output.target_mutated
            and not output.server_session_material_persisted
            else CapabilityOracleDecision.INCONCLUSIVE
        )


class _WebAuthenticatedAssessmentReplay(_WebAuthenticatedAssessmentAuthorityBase):
    ROLE = CapabilityAuthorityRole.REPLAY_STRATEGY

    def stable_execution_context(self) -> Mapping[str, object]:
        return super().stable_execution_context()

    def plan_replay(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> Mapping[str, JsonValue] | None:
        parameters = self._require_request(request)
        if not result.success:
            return None
        return {
            "strategy": "independent-worker-new-permit",
            "adapter": cast(JsonValue, parameters.adapter.model_dump(mode="json", by_alias=True)),
            "accountReceipt": cast(
                JsonValue,
                parameters.account_receipt.model_dump(mode="json", by_alias=True),
            ),
            "executionAuthorized": False,
        }


class _WebAuthenticatedAssessmentCleanup(_WebAuthenticatedAssessmentAuthorityBase):
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


def registered_web_authenticated_assessment_capability_definition(
    tool: WebAuthenticatedAssessmentTool,
) -> CapabilityDefinition:
    """Return the exact read-only Definition for one installed deployment adapter set."""

    if type(tool) is not WebAuthenticatedAssessmentTool:
        raise TypeError("authenticated Web Definition requires its exact Tool")
    constraints: dict[str, JsonValue] = {
        "adapterRegistryDigest": tool.adapters.registry_digest,
        "accountReceiptTrustAnchorDigest": tool.account_receipts.trust_anchor_digest,
        "callerSelectsReferencesOnly": True,
        "callerAuthoredRoutesAllowed": False,
        "callerAuthoredPayloadsAllowed": False,
        "accountCreationAllowed": False,
        "authenticationState": "client-memory-only",
        "targetMutationAllowed": False,
        "freshApprovalRequired": True,
        "cleanupRequired": False,
        "requestUnits": WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
    }
    schema_digest = capability_definition_digest(
        "pajin.capability.web-authenticated-assessment-parameter-schema/v1",
        {
            "model": (
                f"{WebAuthenticatedAssessmentParameters.__module__}."
                f"{WebAuthenticatedAssessmentParameters.__qualname__}"
            ),
            "schema": WebAuthenticatedAssessmentParameters.model_json_schema(by_alias=True),
            "constraints": constraints,
        },
    )
    return capability_definition_from_tool(
        tool.spec,
        ToolCapabilityRegistration(
            capabilityId=WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_ID,
            capabilityVersion=WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_VERSION,
            toolId=tool.spec.tool_id,
            domain="bug-bounty",
            maturity=CapabilityMaturity.EXPERIMENTAL,
            supportedSurfaceTypes=("web.application",),
            threatClasses=tuple(sorted(("CWE-79", "CWE-89", "CWE-639"))),
            preconditions=tuple(
                sorted(
                    (
                        "already-provisioned-signed-account-receipt",
                        "caller-selects-installed-adapter-reference-only",
                        "client-memory-only-authentication",
                        "code-owned-job-compiler",
                        "exact-origin-signed-adapter",
                        "fresh-action-approval-required",
                        "one-use-action-permit",
                        "signed-lifecycle-release-required",
                        "signed-worker-output-verification",
                    )
                )
            ),
            parameterSchemaDigest=schema_digest,
            sideEffectClass=CapabilitySideEffectClass.READ_ONLY,
            approvalRequired=True,
            cleanupRequired=False,
            requestUnitCost=WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
        ),
    )


def web_authenticated_assessment_capability_bundle(
    tools: ToolRegistry,
) -> WebAuthenticatedAssessmentCapabilityBundle:
    """Bind one exact Tool instance to all seven executable CAP-002 authorities."""

    if not isinstance(tools, ToolRegistry):
        raise TypeError("authenticated Web Capability requires a ToolRegistry")
    try:
        tool = tools.tool(WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID)
        spec = tools.spec(WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID)
    except (KeyError, RuntimeError, ValueError) as exc:
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web Tool is unavailable"
        ) from exc
    if type(tool) is not WebAuthenticatedAssessmentTool or spec != tool.spec:
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web Tool implementation or specification drifted"
        )
    definition = registered_web_authenticated_assessment_capability_definition(tool)
    definitions = CapabilityDefinitionRegistry((definition,))
    contract = _WebAuthenticatedAssessmentContract(definition=definition, tool=tool)
    authorities: tuple[CapabilityAuthorityAdapter, ...] = (
        _WebAuthenticatedAssessmentActionCompiler(contract),
        _WebAuthenticatedAssessmentCleanup(contract),
        _WebAuthenticatedAssessmentExecutor(contract),
        _WebAuthenticatedAssessmentMaterializer(contract),
        _WebAuthenticatedAssessmentReplay(contract),
        _WebAuthenticatedAssessmentNormalizer(contract),
        _WebAuthenticatedAssessmentOracle(contract),
    )
    return WebAuthenticatedAssessmentCapabilityBundle(
        definitions=definitions,
        authorities=CapabilityAuthorityRegistry(definitions, authorities),
    )


def activate_web_authenticated_assessment_capability(
    *,
    bundle: WebAuthenticatedAssessmentCapabilityBundle,
    lifecycle: CapabilityLifecycleRegistry,
    release: CapabilityReleaseRef,
) -> WebAuthenticatedAssessmentCapabilityActivation:
    """Admit one externally signed current experimental release for Range use."""

    if not isinstance(bundle, WebAuthenticatedAssessmentCapabilityBundle):
        raise TypeError("authenticated Web activation requires its exact Capability bundle")
    if not isinstance(lifecycle, CapabilityLifecycleRegistry):
        raise TypeError("authenticated Web activation requires a lifecycle registry")
    canonical_release = _canonical_release_ref(release)
    try:
        resolved = lifecycle.resolve_for_use(canonical_release, CapabilityUseProfile.RANGE)
        signed_bundle = lifecycle.resolve_release(canonical_release)
        capability = bundle.capability.reference()
        definition = bundle.definitions.resolve(capability.capability)
    except (
        CapabilityAuthorityError,
        CapabilityDefinitionError,
        CapabilityLifecycleError,
    ) as exc:
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web signed release activation failed closed"
        ) from exc
    if (
        resolved.capability.reference() != capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != capability
        or definition.side_effect_class is not CapabilitySideEffectClass.READ_ONLY
        or not definition.approval_required
        or definition.cleanup_required
    ):
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web signed release differs from code authority"
        )
    binding = WebAuthenticatedAssessmentCapabilityActivationBinding(
        release=canonical_release,
        releaseBundleDigest=_release_bundle_digest(signed_bundle),
        capability=capability,
        actionCapability=registered_action_capability(definition),
    )
    return WebAuthenticatedAssessmentCapabilityActivation(
        bundle=bundle,
        lifecycle=lifecycle,
        activation_set=WebAuthenticatedAssessmentCapabilityActivationSet(binding=binding),
    )


def _verify_activation(activation: WebAuthenticatedAssessmentCapabilityActivation) -> None:
    try:
        canonical = WebAuthenticatedAssessmentCapabilityActivationSet.model_validate(
            activation.activation_set.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web activation set is not canonical"
        ) from exc
    if canonical != activation.activation_set:
        raise WebAuthenticatedAssessmentCapabilityError("authenticated Web activation set drifted")
    _resolve_activation_binding(activation, canonical.binding)


def _resolve_activation_binding(
    activation: WebAuthenticatedAssessmentCapabilityActivation,
    binding: WebAuthenticatedAssessmentCapabilityActivationBinding,
) -> ResolvedCapabilityRelease:
    try:
        resolved = activation.lifecycle.resolve_for_use(
            binding.release,
            CapabilityUseProfile.RANGE,
        )
        signed_bundle = activation.lifecycle.resolve_release(binding.release)
        code_capability = activation.bundle.capability.reference()
    except (CapabilityAuthorityError, CapabilityLifecycleError) as exc:
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web current signed release could not be resolved"
        ) from exc
    if (
        resolved.capability.reference() != binding.capability
        or code_capability != binding.capability
        or resolved.maturity is not CapabilityMaturity.EXPERIMENTAL
        or signed_bundle.release.statement.capability != binding.capability
        or _release_bundle_digest(signed_bundle) != binding.release_bundle_digest
    ):
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web signed activation drifted"
        )
    return resolved


def _release_bundle_digest(bundle: CapabilityReleaseBundle) -> str:
    return capability_definition_digest(
        "pajin.capability.web-authenticated-assessment-release-bundle/v1",
        bundle.model_dump(mode="json", by_alias=True),
    )


def _canonical_release_ref(reference: CapabilityReleaseRef) -> CapabilityReleaseRef:
    try:
        return CapabilityReleaseRef.model_validate(reference.model_dump(mode="json", by_alias=True))
    except (AttributeError, ValidationError) as exc:
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web release reference is not canonical"
        ) from exc


def _canonical_tool_request(request: ToolRequest) -> ToolRequest:
    try:
        return ToolRequest.model_validate_json(
            json.dumps(
                request.model_dump(mode="json"),
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise WebAuthenticatedAssessmentCapabilityError(
            "authenticated Web Tool request is not canonical"
        ) from exc


__all__ = [
    "WEB_AUTHENTICATED_ASSESSMENT_ACTIVATION_SET_API_VERSION",
    "WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_ID",
    "WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_VERSION",
    "WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS",
    "WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID",
    "WEB_AUTHENTICATED_ASSESSMENT_TOOL_VERSION",
    "WebAuthenticatedAssessmentCapabilityActivation",
    "WebAuthenticatedAssessmentCapabilityActivationBinding",
    "WebAuthenticatedAssessmentCapabilityActivationSet",
    "WebAuthenticatedAssessmentCapabilityBundle",
    "WebAuthenticatedAssessmentCapabilityError",
    "WebAuthenticatedAssessmentJobCompiler",
    "WebAuthenticatedAssessmentOutputVerifier",
    "WebAuthenticatedAssessmentParameters",
    "WebAuthenticatedAssessmentTool",
    "activate_web_authenticated_assessment_capability",
    "registered_web_authenticated_assessment_capability_definition",
    "web_authenticated_assessment_capability_bundle",
]
