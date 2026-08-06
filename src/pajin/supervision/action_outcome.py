"""PERMIT-004A authenticated result, data-flow, Oracle, and cleanup gate."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, Self, cast

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)

from pajin.capabilities.activation import (
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    ExistingModeCapabilityActivation,
    PreparedCapabilityAction,
    capability_gateway_outcome_digest,
    capability_grant_digest,
)
from pajin.capabilities.authorities import (
    CapabilityAuthorityBinding,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
    CodeBackedCapabilityRef,
    RegisteredCapabilityAuthority,
)
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilitySideEffectClass,
    capability_definition_digest,
)
from pajin.capabilities.reconciliation import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CapabilityDispatchReconciliationObservation,
    CapabilityDispatchReconciliationStatus,
    CapabilityGraphRunAuditAnchor,
    reconcile_capability_dispatch,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.hypothesis import AttackHypothesisSet, SurfaceBoundPlan
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit, ActionProposal, GraphActionPermitStore
from pajin.policy.engine import PolicyDecision
from pajin.runtime.secrets import SecretLease, SecretLeaseStatus
from pajin.runtime.store import (
    SealedArtifact,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)
from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerLimits, WorkerResult
from pajin.supervision.action_compiler import (
    GeneralAttackCompiledIntent,
    verify_general_attack_compiled_intent,
)
from pajin.supervision.action_permit import GeneralAttackActionPermitResult
from pajin.supervision.action_proposal import GeneralAttackActionProposal
from pajin.tools.gateway import GatewayOutcome

GENERAL_ATTACK_ACTION_OUTCOME_ASSESSMENT_API_VERSION: Literal[
    "pajin.dev/general-attack-action-outcome-assessment/v1alpha1"
] = "pajin.dev/general-attack-action-outcome-assessment/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_GATEWAY_EVIDENCE_BYTES = 32 * 1024 * 1024
_SUPPORTED_SIDE_EFFECTS = {
    CapabilitySideEffectClass.NONE,
    CapabilitySideEffectClass.READ_ONLY,
}
_OUTCOME_ROLES = (
    CapabilityAuthorityRole.CLEANUP_HANDLER,
    CapabilityAuthorityRole.EXECUTOR_ADAPTER,
    CapabilityAuthorityRole.RESULT_NORMALIZER,
    CapabilityAuthorityRole.SUCCESS_ORACLE,
)


class GeneralAttackActionOutcomeError(RuntimeError):
    """Raised when a consumed general attack result is not exactly authenticated."""


@dataclass(frozen=True, slots=True)
class GeneralAttackActionOutcomeInputs:
    """Deployment-authenticated Run, anchor, and Grant for one consumed result."""

    run_path: Path
    run_anchor: CapabilityGraphRunAuditAnchor
    grant: CapabilityGrant


@dataclass(frozen=True, slots=True)
class _AuthenticatedGeneralAttackActionResult:
    """Private sealed execution identity shared by later outcome policy gates."""

    canonical_intent: GeneralAttackCompiledIntent
    prepared: PreparedCapabilityAction
    graph_proposal: ActionProposal
    permit: ActionPermit
    definition: CapabilityDefinition
    release: CapabilityReleaseRef
    code_backed_capability: CodeBackedCapabilityRef
    run_path: Path
    run_anchor: CapabilityGraphRunAuditAnchor
    run_anchor_event_hash: str
    run_anchor_seal_root_digest: str
    verified_run_root_digest: str
    reconciliation: CapabilityDispatchReconciliationObservation
    terminal: CapabilityDispatchAuditEvent
    gateway_outcome: GatewayOutcome
    gateway_outcome_digest: str
    grant: CapabilityGrant
    grant_digest: str
    worker_result: WorkerResult
    worker_execution_id: str
    normalized_result: ToolResult
    approval_receipt: ActionApprovalConsumptionReceipt | None
    evidence: GeneralAttackSealedEvidenceRef
    data_flow: GeneralAttackDataFlowObservation
    active_authorities: CapabilityAuthorityRegistry
    cleanup_handler: RegisteredCapabilityAuthority
    executor_adapter: RegisteredCapabilityAuthority
    result_normalizer: RegisteredCapabilityAuthority
    success_oracle: RegisteredCapabilityAuthority


class GeneralAttackActionOutcomeInputAuthority(Protocol):
    """Trusted resolver for result inputs that PERMIT-003 does not retain.

    Implementations must resolve the authoritative deployment-owned Run path, its exact
    pre-claim Graph Run anchor, and the Capability Grant used for the dispatch. A caller-selected
    path or a self-sealed alternate Run is not an implementation of this authority.
    """

    def resolve_for_outcome(
        self,
        *,
        permit: ActionPermit,
        prepared: PreparedCapabilityAction,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
    ) -> GeneralAttackActionOutcomeInputs: ...


class _GatewaySecretRequestMetadata(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    binding: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    secret_ref_fingerprint: str = Field(
        alias="secretRefFingerprint",
        pattern=r"^[a-f0-9]{16}$",
    )
    ttl_seconds: int = Field(alias="ttlSeconds", ge=1, le=300)

    @field_validator("ttl_seconds", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Gateway secret-request TTL must be a JSON integer")
        return value


class _GatewayWorkerJobMetadata(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    execution_id: str = Field(alias="executionId", min_length=1, max_length=200)
    image: str = Field(min_length=1, max_length=300)
    command: tuple[str, ...] = Field(min_length=1, max_length=100)
    network: NetworkMode
    egress_policy: EgressPolicy | None = Field(alias="egressPolicy")
    limits: WorkerLimits
    stdin_bytes: int = Field(alias="stdinBytes", ge=0, le=1_000_000)
    stdin_sha256: _Sha256 = Field(alias="stdinSha256")
    secret_requests: tuple[_GatewaySecretRequestMetadata, ...] = Field(
        alias="secretRequests",
        max_length=4,
    )
    secret_lease_ids: tuple[str, ...] = Field(alias="secretLeaseIds", max_length=4)

    @field_validator("stdin_bytes", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Gateway Worker stdin size must be a JSON integer")
        return value

    @model_validator(mode="after")
    def require_network_contract(self) -> Self:
        if self.network is NetworkMode.NONE and self.egress_policy is not None:
            raise ValueError("network-none Gateway job cannot include an egress policy")
        if self.network is NetworkMode.EGRESS_PROXY and self.egress_policy is None:
            raise ValueError("egress-proxy Gateway job requires an egress policy")
        if len(set(self.secret_lease_ids)) != len(self.secret_lease_ids):
            raise ValueError("Gateway Worker secret lease IDs must be unique")
        return self


class GeneralAttackSealedEvidenceRef(StrictModel):
    """Exact sealed artifact coordinate used by the outcome assessment."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    path: str = Field(min_length=1, max_length=500)
    sha256: _Sha256
    size_bytes: int = Field(alias="sizeBytes", ge=1, le=_MAX_GATEWAY_EVIDENCE_BYTES)
    media_type: str = Field(alias="mediaType", min_length=1, max_length=200)
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    tool_id: str = Field(alias="toolId", min_length=1, max_length=200)
    execution_id: str = Field(alias="executionId", min_length=1, max_length=200)
    event_ids: tuple[str, ...] = Field(alias="eventIds", min_length=1, max_length=100)
    seal_root_digest: _Sha256 = Field(alias="sealRootDigest")

    @field_validator("size_bytes", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("sealed evidence size must be a JSON integer")
        return value

    @model_validator(mode="after")
    def require_canonical_events(self) -> Self:
        if self.event_ids != tuple(sorted(set(self.event_ids))):
            raise ValueError("sealed evidence event IDs must be unique and sorted")
        return self


class GeneralAttackDataFlowObservation(StrictModel):
    """Bounded transport observation; it does not attest semantic information flow."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_definition_digest: _Sha256 = Field(alias="sourceDefinitionDigest")
    declared_network_access: bool = Field(alias="declaredNetworkAccess")
    worker_network_mode: NetworkMode = Field(alias="workerNetworkMode")
    network_log_trusted: bool = Field(alias="networkLogTrusted")
    network_log_observed: bool = Field(alias="networkLogObserved")
    network_log_digest: _Sha256 = Field(alias="networkLogDigest")
    state: Literal[
        "network-disabled-no-egress-observed",
        "network-enabled-host-observation-bound",
    ]
    information_flow_attested: Literal[False] = Field(
        default=False,
        alias="informationFlowAttested",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )

    @field_validator(
        "declared_network_access",
        "network_log_trusted",
        "network_log_observed",
        "information_flow_attested",
        "scope_expansion_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("general attack data-flow flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def require_bounded_network_observation(self) -> Self:
        if self.worker_network_mode is NetworkMode.NONE:
            if (
                self.network_log_trusted
                or self.network_log_observed
                or self.state != "network-disabled-no-egress-observed"
            ):
                raise ValueError("network-disabled action claimed a network observation")
        elif (
            not self.declared_network_access
            or not self.network_log_trusted
            or self.state != "network-enabled-host-observation-bound"
        ):
            raise ValueError("network-enabled action lacks trusted declared egress authority")
        return self


class GeneralAttackActionOutcomeAssessment(StrictModel):
    """Content-addressed PERMIT-004A projection with no new execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/general-attack-action-outcome-assessment/v1alpha1"
    ] = Field(
        default=GENERAL_ATTACK_ACTION_OUTCOME_ASSESSMENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GeneralAttackActionOutcomeAssessment"] = (
        "GeneralAttackActionOutcomeAssessment"
    )
    assessment_id: str = Field(default="", alias="assessmentId", max_length=120)
    assessment_digest: str = Field(
        default="",
        alias="assessmentDigest",
        pattern=r"^$|^[a-f0-9]{64}$",
    )
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    source_intent_digest: _Sha256 = Field(alias="sourceIntentDigest")
    source_general_proposal_digest: _Sha256 = Field(
        alias="sourceGeneralProposalDigest"
    )
    graph_proposal_id: str = Field(alias="graphProposalId", min_length=1, max_length=100)
    graph_proposal_digest: _Sha256 = Field(alias="graphProposalDigest")
    permit_id: str = Field(alias="permitId", min_length=1, max_length=100)
    permit_digest: _Sha256 = Field(alias="permitDigest")
    dispatch_id: str = Field(alias="dispatchId", min_length=1, max_length=100)
    approval_id: str | None = Field(default=None, alias="approvalId", max_length=100)
    approval_digest: _Sha256 | None = Field(default=None, alias="approvalDigest")
    approval_receipt_id: str | None = Field(
        default=None,
        alias="approvalReceiptId",
        max_length=120,
    )
    approval_receipt_digest: _Sha256 | None = Field(
        default=None,
        alias="approvalReceiptDigest",
    )
    run_audit_anchor: CapabilityGraphRunAuditAnchor = Field(alias="runAuditAnchor")
    run_audit_anchor_event_hash: _Sha256 = Field(alias="runAuditAnchorEventHash")
    run_audit_anchor_seal_root_digest: _Sha256 = Field(
        alias="runAuditAnchorSealRootDigest"
    )
    verified_run_root_digest: _Sha256 = Field(alias="verifiedRunRootDigest")
    reconciliation_id: str = Field(alias="reconciliationId", min_length=1, max_length=120)
    reconciliation_digest: _Sha256 = Field(alias="reconciliationDigest")
    terminal_event_digest: _Sha256 = Field(alias="terminalEventDigest")
    gateway_outcome_digest: _Sha256 = Field(alias="gatewayOutcomeDigest")
    capability_grant_digest: _Sha256 = Field(alias="capabilityGrantDigest")
    worker_execution_id: str = Field(
        alias="workerExecutionId",
        min_length=1,
        max_length=200,
    )
    capability: CodeBackedCapabilityRef
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    release: CapabilityReleaseRef
    outcome_authorities: tuple[CapabilityAuthorityBinding, ...] = Field(
        alias="outcomeAuthorities",
        min_length=len(_OUTCOME_ROLES),
        max_length=len(_OUTCOME_ROLES),
    )
    expected_evidence_types: tuple[str, ...] = Field(
        alias="expectedEvidenceTypes",
        min_length=1,
        max_length=100,
    )
    evidence: GeneralAttackSealedEvidenceRef
    oracle_decision: CapabilityOracleDecision = Field(alias="oracleDecision")
    side_effect_class: CapabilitySideEffectClass = Field(alias="sideEffectClass")
    side_effect_state: Literal["definition-ceiling-bound"] = Field(
        default="definition-ceiling-bound",
        alias="sideEffectState",
    )
    side_effect_absence_attested: Literal[False] = Field(
        default=False,
        alias="sideEffectAbsenceAttested",
    )
    write_side_effect_admitted: Literal[False] = Field(
        default=False,
        alias="writeSideEffectAdmitted",
    )
    data_flow: GeneralAttackDataFlowObservation = Field(alias="dataFlow")
    cleanup_required: Literal[False] = Field(default=False, alias="cleanupRequired")
    cleanup_state: Literal["not-required-handler-returned-none"] = Field(
        default="not-required-handler-returned-none",
        alias="cleanupState",
    )
    cleanup_plan_created: Literal[False] = Field(
        default=False,
        alias="cleanupPlanCreated",
    )
    cleanup_permit_issued: Literal[False] = Field(
        default=False,
        alias="cleanupPermitIssued",
    )
    cleanup_execution_authorized: Literal[False] = Field(
        default=False,
        alias="cleanupExecutionAuthorized",
    )
    executor_job_bound: Literal[False] = Field(default=False, alias="executorJobBound")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    redispatch_allowed: Literal[False] = Field(default=False, alias="redispatchAllowed")

    @field_validator(
        "side_effect_absence_attested",
        "write_side_effect_admitted",
        "cleanup_required",
        "cleanup_plan_created",
        "cleanup_permit_issued",
        "cleanup_execution_authorized",
        "executor_job_bound",
        "finding_authority",
        "redispatch_allowed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value:
            raise ValueError("general attack outcome authority flags must be literal false")
        return value

    @model_validator(mode="after")
    def bind_assessment(self) -> Self:
        roles = tuple(binding.role for binding in self.outcome_authorities)
        if roles != _OUTCOME_ROLES:
            raise ValueError("general attack outcome authorities are incomplete or unordered")
        if self.side_effect_class not in _SUPPORTED_SIDE_EFFECTS:
            raise ValueError("write side effects require a separate one-shot cleanup authority")
        if (
            self.run_audit_anchor.campaign_id != self.campaign_id
            or self.run_audit_anchor.run_id != self.run_id
            or self.run_audit_anchor.activation_set_digest != self.activation_set_digest
        ):
            raise ValueError("general attack Run anchor differs from the assessment lineage")
        if self.data_flow.source_definition_digest != self.capability.capability.capability_digest:
            raise ValueError("general attack data-flow Definition differs from its Capability")
        if self.expected_evidence_types != tuple(sorted(set(self.expected_evidence_types))):
            raise ValueError("expected evidence types must be unique and sorted")
        approval_fields = (
            self.approval_id,
            self.approval_digest,
            self.approval_receipt_id,
            self.approval_receipt_digest,
        )
        if any(value is not None for value in approval_fields) and not all(
            value is not None for value in approval_fields
        ):
            raise ValueError("general attack approval audit binding is incomplete")
        excluded = {"assessment_id", "assessment_digest"}
        if self.approval_receipt_id is None:
            excluded.update(
                {
                    "approval_id",
                    "approval_digest",
                    "approval_receipt_id",
                    "approval_receipt_digest",
                }
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude=excluded,
        )
        digest = capability_definition_digest(
            "pajin.supervision.general-attack-action-outcome-assessment/v1",
            material,
        )
        assessment_id = f"general-attack-action-outcome-assessment_{digest}"
        if self.assessment_digest and self.assessment_digest != digest:
            raise ValueError("general attack outcome assessment digest differs")
        if self.assessment_id and self.assessment_id != assessment_id:
            raise ValueError("general attack outcome assessment ID differs")
        object.__setattr__(self, "assessment_digest", digest)
        object.__setattr__(self, "assessment_id", assessment_id)
        return self


class GeneralAttackActionOutcomeGate:
    """Authenticate one consumed result before invoking current CAP-002 outcome roles."""

    def __init__(
        self,
        *,
        activation: ExistingModeCapabilityActivation,
        permit_store: GraphActionPermitStore,
        inputs: GeneralAttackActionOutcomeInputAuthority,
    ) -> None:
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise TypeError("General attack outcome gate requires a verified activation")
        if not callable(getattr(permit_store, "permit", None)):
            raise TypeError("General attack outcome gate requires the GRAPH Permit store")
        if not callable(getattr(inputs, "resolve_for_outcome", None)):
            raise TypeError("General attack outcome gate requires an external input authority")
        self._activation = activation
        self._permit_store = permit_store
        self._inputs = inputs

    def assess(
        self,
        result: GeneralAttackActionPermitResult[GatewayOutcome],
        source_proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        hypothesis_set: AttackHypothesisSet,
        plan: SurfaceBoundPlan,
        task_digest: str,
        action_definition: CapabilityDefinitionRef,
        definitions: CapabilityDefinitionRegistry,
        code_backed_capability: CodeBackedCapabilityRef,
        authorities: CapabilityAuthorityRegistry,
    ) -> GeneralAttackActionOutcomeAssessment:
        """Rebuild exact authority and admit only a sealed, completed Gateway result."""

        try:
            authenticated = self._authenticate_result(
                result,
                source_proposal,
                campaign,
                hypothesis_set,
                plan,
                task_digest,
                action_definition,
                definitions,
                code_backed_capability,
                authorities,
            )
            if authenticated.definition.side_effect_class not in _SUPPORTED_SIDE_EFFECTS:
                raise ValueError(
                    "write side effects require a separate one-shot cleanup authority"
                )
            if authenticated.definition.cleanup_required:
                raise ValueError(
                    "cleanup-required action has no separate one-shot cleanup authority"
                )
            oracle_decision = authenticated.success_oracle.evaluate(
                authenticated.prepared.request,
                authenticated.normalized_result,
            )
            cleanup_plan = authenticated.cleanup_handler.plan_cleanup(
                authenticated.prepared.request,
                authenticated.normalized_result,
            )
            if cleanup_plan is not None:
                raise ValueError("cleanup-not-required Handler returned a cleanup plan")
            self._revalidate_authenticated_roles(authenticated, authorities)
            bindings = tuple(
                handle.binding
                for handle in (
                    authenticated.cleanup_handler,
                    authenticated.executor_adapter,
                    authenticated.result_normalizer,
                    authenticated.success_oracle,
                )
            )
            return GeneralAttackActionOutcomeAssessment(
                campaignId=authenticated.permit.campaign_id,
                runId=authenticated.permit.run_id,
                sourceIntentDigest=authenticated.canonical_intent.intent_digest,
                sourceGeneralProposalDigest=(
                    authenticated.canonical_intent.source_proposal.proposal_digest
                ),
                graphProposalId=authenticated.graph_proposal.proposal_id,
                graphProposalDigest=authenticated.graph_proposal.proposal_digest,
                permitId=authenticated.permit.permit_id,
                permitDigest=authenticated.permit.permit_digest,
                dispatchId=authenticated.permit.dispatch_id,
                approvalId=(
                    authenticated.approval_receipt.approval.approval_id
                    if authenticated.approval_receipt is not None
                    else None
                ),
                approvalDigest=(
                    authenticated.approval_receipt.approval.approval_digest
                    if authenticated.approval_receipt is not None
                    else None
                ),
                approvalReceiptId=(
                    authenticated.approval_receipt.receipt_id
                    if authenticated.approval_receipt is not None
                    else None
                ),
                approvalReceiptDigest=(
                    authenticated.approval_receipt.receipt_digest
                    if authenticated.approval_receipt is not None
                    else None
                ),
                runAuditAnchor=authenticated.run_anchor,
                runAuditAnchorEventHash=authenticated.run_anchor_event_hash,
                runAuditAnchorSealRootDigest=(
                    authenticated.run_anchor_seal_root_digest
                ),
                verifiedRunRootDigest=authenticated.verified_run_root_digest,
                reconciliationId=(
                    authenticated.reconciliation.record.reconciliation_id
                ),
                reconciliationDigest=(
                    authenticated.reconciliation.record.reconciliation_digest
                ),
                terminalEventDigest=authenticated.terminal.event_digest,
                gatewayOutcomeDigest=authenticated.gateway_outcome_digest,
                capabilityGrantDigest=authenticated.grant_digest,
                workerExecutionId=authenticated.worker_execution_id,
                capability=authenticated.code_backed_capability,
                activationSetDigest=authenticated.prepared.activation_set_digest,
                release=authenticated.release,
                outcomeAuthorities=bindings,
                expectedEvidenceTypes=authenticated.definition.evidence_types,
                evidence=authenticated.evidence,
                oracleDecision=oracle_decision,
                sideEffectClass=authenticated.definition.side_effect_class,
                dataFlow=authenticated.data_flow,
            )
        except Exception as exc:
            raise GeneralAttackActionOutcomeError(
                "General attack outcome authority failed closed"
            ) from exc

    def _authenticate_result(
        self,
        result: GeneralAttackActionPermitResult[GatewayOutcome],
        source_proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        hypothesis_set: AttackHypothesisSet,
        plan: SurfaceBoundPlan,
        task_digest: str,
        action_definition: CapabilityDefinitionRef,
        definitions: CapabilityDefinitionRegistry,
        code_backed_capability: CodeBackedCapabilityRef,
        authorities: CapabilityAuthorityRegistry,
    ) -> _AuthenticatedGeneralAttackActionResult:
        """Authenticate sealed execution evidence without applying outcome policy."""

        dispatch = result.dispatch
        if type(dispatch.dispatched) is not bool or not dispatch.dispatched:
            raise ValueError("general attack result did not start a first dispatch")
        if dispatch.result is None:
            raise ValueError("general attack result is missing its Gateway outcome")
        permit = ActionPermit.model_validate(
            dispatch.permit.model_dump(mode="json", by_alias=True)
        )
        outcome = GatewayOutcome.model_validate(dispatch.result.model_dump(mode="json"))
        canonical_intent = verify_general_attack_compiled_intent(
            result.intent,
            source_proposal,
            campaign,
            hypothesis_set,
            plan,
            task_digest,
            action_definition,
            definitions,
            code_backed_capability,
            authorities,
        )
        prepared, definition, release = self._rebuild_current_preparation(
            canonical_intent,
            definitions,
        )
        graph_proposal = ActionProposal.model_validate(
            result.proposal.model_dump(mode="json", by_alias=True)
        )
        approval_receipt = self._require_exact_consumed_action(
            result,
            canonical_intent,
            prepared,
            graph_proposal,
            permit,
            definition,
        )
        inputs = self._resolve_inputs(permit, prepared, campaign, definition)
        evidence_path = f"evidence/{permit.request_id}.json"
        snapshot = load_verified_run_artifacts(
            inputs.run_path,
            requests={evidence_path: _MAX_GATEWAY_EVIDENCE_BYTES},
            expected_run_id=permit.run_id,
        )
        anchor_event_hash, anchor_seal_root_digest = self._require_run_anchor(
            snapshot,
            inputs.run_anchor,
            permit,
            prepared,
            campaign,
        )
        reconciliation = reconcile_capability_dispatch(snapshot, permit)
        terminal = reconciliation.terminal_event
        if (
            reconciliation.record.status
            is not CapabilityDispatchReconciliationStatus.COMPLETED
            or terminal is None
            or terminal.stage is not CapabilityDispatchStage.COMPLETED
        ):
            raise ValueError("general attack result is missing a sealed completed dispatch")
        outcome_digest = capability_gateway_outcome_digest(outcome)
        grant_digest = capability_grant_digest(inputs.grant)
        worker_result = self._require_terminal_outcome(
            terminal,
            outcome,
            outcome_digest,
            prepared,
            release,
            grant_digest,
            evidence_path,
        )
        evidence_ref, evidence_result, evidence_job, leases = (
            self._verify_sealed_gateway_evidence(
                snapshot,
                evidence_path,
                prepared,
                outcome,
                worker_result,
            )
        )
        dispatched_job = self._require_worker_dispatch(
            snapshot,
            evidence_job,
            leases,
            prepared,
            worker_result,
        )
        active_authorities = self._activation.rollout.bundle.authorities
        if active_authorities.resolve(code_backed_capability) != authorities.resolve(
            code_backed_capability
        ):
            raise ValueError("current outcome authority set differs from PERMIT-002")
        handles = {
            role: active_authorities.authority(code_backed_capability, role)
            for role in _OUTCOME_ROLES
        }
        normalized = handles[CapabilityAuthorityRole.RESULT_NORMALIZER].normalize(
            prepared.request,
            worker_result,
        )
        if normalized.evidence or normalized != evidence_result:
            raise ValueError("current Result Normalizer differs from sealed Gateway evidence")
        expected_outcome_result = normalized.model_copy(
            update={"evidence": [evidence_path]},
            deep=True,
        )
        if outcome.result != expected_outcome_result:
            raise ValueError("Gateway outcome differs from the exact normalized sealed result")
        data_flow = self._data_flow_observation(
            definition,
            dispatched_job,
            outcome,
            worker_result,
        )
        return _AuthenticatedGeneralAttackActionResult(
            canonical_intent=canonical_intent,
            prepared=prepared,
            graph_proposal=graph_proposal,
            permit=permit,
            definition=definition,
            release=release,
            code_backed_capability=code_backed_capability,
            run_path=inputs.run_path,
            run_anchor=inputs.run_anchor,
            run_anchor_event_hash=anchor_event_hash,
            run_anchor_seal_root_digest=anchor_seal_root_digest,
            verified_run_root_digest=snapshot.verification.root_digest,
            reconciliation=reconciliation,
            terminal=terminal,
            gateway_outcome=outcome,
            gateway_outcome_digest=outcome_digest,
            grant=inputs.grant,
            grant_digest=grant_digest,
            worker_result=worker_result,
            worker_execution_id=worker_result.execution_id,
            normalized_result=normalized,
            approval_receipt=approval_receipt,
            evidence=evidence_ref,
            data_flow=data_flow,
            active_authorities=active_authorities,
            cleanup_handler=handles[CapabilityAuthorityRole.CLEANUP_HANDLER],
            executor_adapter=handles[CapabilityAuthorityRole.EXECUTOR_ADAPTER],
            result_normalizer=handles[CapabilityAuthorityRole.RESULT_NORMALIZER],
            success_oracle=handles[CapabilityAuthorityRole.SUCCESS_ORACLE],
        )

    def _revalidate_authenticated_roles(
        self,
        authenticated: _AuthenticatedGeneralAttackActionResult,
        authorities: CapabilityAuthorityRegistry,
    ) -> None:
        current_release = self._activation.resolve_for_dispatch(
            authenticated.prepared.capability
        )
        current_authorities = self._activation.rollout.bundle.authorities
        current_manifest = current_authorities.resolve(
            authenticated.code_backed_capability
        )
        if (
            self._activation.activation_set.activation_set_digest
            != authenticated.prepared.activation_set_digest
            or current_release.release != authenticated.release
            or current_release.capability.reference()
            != authenticated.code_backed_capability
            or current_manifest
            != authenticated.active_authorities.resolve(
                authenticated.code_backed_capability
            )
            or current_manifest
            != authorities.resolve(authenticated.code_backed_capability)
        ):
            raise ValueError("current outcome authority changed during evaluation")
        authenticated_handles = {
            CapabilityAuthorityRole.CLEANUP_HANDLER: authenticated.cleanup_handler,
            CapabilityAuthorityRole.EXECUTOR_ADAPTER: authenticated.executor_adapter,
            CapabilityAuthorityRole.RESULT_NORMALIZER: authenticated.result_normalizer,
            CapabilityAuthorityRole.SUCCESS_ORACLE: authenticated.success_oracle,
        }
        for role in _OUTCOME_ROLES:
            current = current_authorities.authority(
                authenticated.code_backed_capability,
                role,
            )
            if current.binding != authenticated_handles[role].binding:
                raise ValueError("current outcome authority changed during evaluation")

    def _resolve_inputs(
        self,
        permit: ActionPermit,
        prepared: PreparedCapabilityAction,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
    ) -> GeneralAttackActionOutcomeInputs:
        resolved = self._inputs.resolve_for_outcome(
            permit=ActionPermit.model_validate(
                permit.model_dump(mode="json", by_alias=True)
            ),
            prepared=PreparedCapabilityAction.model_validate(
                prepared.model_dump(mode="json", by_alias=True)
            ),
            campaign=CampaignManifest.model_validate(
                campaign.model_dump(mode="json", by_alias=True)
            ),
            definition=CapabilityDefinition.model_validate(
                definition.model_dump(mode="json", by_alias=True)
            ),
        )
        if type(resolved) is not GeneralAttackActionOutcomeInputs:
            raise TypeError("external outcome authority returned another result type")
        if not isinstance(resolved.run_path, Path):
            raise TypeError("external outcome authority returned another Run path type")
        return GeneralAttackActionOutcomeInputs(
            run_path=resolved.run_path.resolve(strict=True),
            run_anchor=CapabilityGraphRunAuditAnchor.model_validate(
                resolved.run_anchor.model_dump(mode="json", by_alias=True)
            ),
            grant=CapabilityGrant.model_validate(
                resolved.grant.model_dump(mode="json", by_alias=True)
            ),
        )

    def verify_assessment(
        self,
        assessment: GeneralAttackActionOutcomeAssessment,
        result: GeneralAttackActionPermitResult[GatewayOutcome],
        source_proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        hypothesis_set: AttackHypothesisSet,
        plan: SurfaceBoundPlan,
        task_digest: str,
        action_definition: CapabilityDefinitionRef,
        definitions: CapabilityDefinitionRegistry,
        code_backed_capability: CodeBackedCapabilityRef,
        authorities: CapabilityAuthorityRegistry,
    ) -> GeneralAttackActionOutcomeAssessment:
        """Rebuild every authority and require exact equality with an output projection."""

        try:
            candidate = GeneralAttackActionOutcomeAssessment.model_validate(
                assessment.model_dump(mode="json", by_alias=True)
            )
            expected = self.assess(
                result,
                source_proposal,
                campaign,
                hypothesis_set,
                plan,
                task_digest,
                action_definition,
                definitions,
                code_backed_capability,
                authorities,
            )
            if candidate != expected:
                raise ValueError(
                    "general attack outcome assessment differs from current authority"
                )
            return expected
        except GeneralAttackActionOutcomeError:
            raise
        except Exception as exc:
            raise GeneralAttackActionOutcomeError(
                "General attack outcome assessment verification failed closed"
            ) from exc

    def _require_run_anchor(
        self,
        snapshot: VerifiedRunSnapshot,
        expected: CapabilityGraphRunAuditAnchor,
        permit: ActionPermit,
        prepared: PreparedCapabilityAction,
        campaign: CampaignManifest,
    ) -> tuple[str, str]:
        anchors = tuple(
            event
            for event in snapshot.events
            if event.event_type == CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE
        )
        if len(anchors) != 1:
            raise ValueError("authoritative Run requires one sealed deployment anchor")
        anchor_event = anchors[0]
        actual = _exact_model(
            CapabilityGraphRunAuditAnchor,
            anchor_event.payload,
            label="Capability Graph Run anchor",
        )
        if (
            actual != expected
            or actual.campaign_id != campaign.metadata.name
            or actual.campaign_digest != campaign_manifest_digest(campaign)
            or actual.run_id != permit.run_id
            or actual.envelope_id != permit.envelope_id
            or actual.envelope_digest != permit.envelope_digest
            or actual.release_set_digest
            != self._activation.activation_set.release_set_digest
            or actual.activation_set_digest != prepared.activation_set_digest
            or actual.compiler_id != permit.compiler_id
            or actual.compiler_version != permit.compiler_version
            or actual.compiler_digest != permit.compiler_digest
        ):
            raise ValueError("sealed Run anchor differs from current dispatch authority")
        claimed = tuple(
            event
            for event in snapshot.events
            if event.event_type == "capability.dispatch.claimed"
            and event.payload.get("permitId") == permit.permit_id
        )
        if len(claimed) != 1:
            raise ValueError("authoritative Run lacks one exact claimed audit event")
        claimed_event = claimed[0]
        _exact_model(
            CapabilityDispatchAuditEvent,
            claimed_event.payload,
            label="Capability claimed audit event",
        )
        if (
            anchor_event.sequence >= claimed_event.sequence
            or anchor_event.occurred_at > claimed_event.occurred_at
        ):
            raise ValueError("deployment Run anchor was not sealed before the Permit claim")
        anchor_seal = next(
            (
                seal
                for seal in snapshot.seals
                if anchor_event.sequence <= seal.event_count < claimed_event.sequence
            ),
            None,
        )
        if anchor_seal is None:
            raise ValueError("deployment Run anchor lacks a pre-claim integrity seal")
        return anchor_event.event_hash, anchor_seal.root_digest

    def _rebuild_current_preparation(
        self,
        intent: Any,
        definitions: CapabilityDefinitionRegistry,
    ) -> tuple[PreparedCapabilityAction, CapabilityDefinition, Any]:
        matches = tuple(
            binding
            for binding in self._activation.activation_set.bindings
            if binding.capability == intent.code_backed_capability
        )
        if len(matches) != 1:
            raise ValueError("current activation lacks one exact outcome Capability")
        binding = matches[0]
        first = self._activation.resolve_for_dispatch(
            binding.action_capability.reference()
        )
        prepared = self._activation.prepare_action(
            release=binding.release,
            request=intent.request,
            parameters=cast(Mapping[str, JsonValue], intent.request.arguments),
        )
        second = self._activation.resolve_for_dispatch(
            binding.action_capability.reference()
        )
        source_definition = definitions.resolve(intent.source_proposal.action_definition)
        active_definition = self._activation.rollout.bundle.definitions.resolve(
            intent.source_proposal.action_definition
        )
        if (
            first != second
            or first.release != binding.release
            or first.capability.reference() != intent.code_backed_capability
            or source_definition != active_definition
            or prepared.activation_set_digest
            != self._activation.activation_set.activation_set_digest
            or prepared.release != binding.release
            or prepared.capability != binding.action_capability.reference()
            or prepared.request != intent.request
            or prepared.request_digest != intent.request_digest
            or prepared.normalized_parameters_digest
            != intent.normalized_parameters_digest
        ):
            raise ValueError("current outcome preparation differs from PERMIT-003")
        return prepared, active_definition, binding.release

    def _require_exact_consumed_action(
        self,
        result: GeneralAttackActionPermitResult[GatewayOutcome],
        intent: Any,
        prepared: PreparedCapabilityAction,
        proposal: ActionProposal,
        permit: ActionPermit,
        definition: CapabilityDefinition,
    ) -> ActionApprovalConsumptionReceipt | None:
        canonical_prepared = PreparedCapabilityAction.model_validate(
            result.prepared.model_dump(mode="json", by_alias=True)
        )
        stored = self._permit_store.permit(permit.permit_id)
        if stored is None:
            raise ValueError("consumed ActionPermit is absent from the GRAPH store")
        stored = ActionPermit.model_validate(stored.model_dump(mode="json", by_alias=True))
        proposal_fields = (
            "campaign_id",
            "run_id",
            "envelope_id",
            "envelope_digest",
            "decision_id",
            "decision_digest",
            "snapshot",
            "capability",
            "target_digest",
            "request_id",
            "request_digest",
            "normalized_parameters_digest",
            "reservation",
        )
        if (
            result.intent != intent
            or canonical_prepared != prepared
            or stored != permit
            or permit.proposal_id != proposal.proposal_id
            or permit.proposal_digest != proposal.proposal_digest
            or any(getattr(permit, name) != getattr(proposal, name) for name in proposal_fields)
            or proposal.campaign_id != intent.source_proposal.campaign_id
            or proposal.capability != prepared.capability
            or proposal.target_digest != intent.target_digest
            or proposal.request_id != intent.request.request_id
            or proposal.request_digest != intent.request_digest
            or proposal.normalized_parameters_digest
            != intent.normalized_parameters_digest
        ):
            raise ValueError("consumed ActionPermit lineage differs from PERMIT-003")
        requires_approval = (
            permit.capability.risk_tier >= ToolRiskTier.T2
            or definition.approval_required
        )
        if not requires_approval:
            if result.approval_receipt is not None:
                raise ValueError("approval receipt is present outside current policy")
            return None
        if result.approval_receipt is None:
            raise ValueError("approval-required result lacks its consumption receipt")
        receipt = ActionApprovalConsumptionReceipt.model_validate(
            result.approval_receipt.model_dump(mode="json", by_alias=True)
        )
        lookup = getattr(self._permit_store, "approval_consumption", None)
        if not callable(lookup):
            raise ValueError("outcome store cannot resolve approval consumption receipts")
        stored_receipt = lookup(receipt.receipt_id)
        if stored_receipt is None:
            raise ValueError("approval consumption receipt is absent from the GRAPH store")
        stored_receipt = ActionApprovalConsumptionReceipt.model_validate(
            stored_receipt.model_dump(mode="json", by_alias=True)
        )
        if (
            stored_receipt != receipt
            or receipt.action_permit != permit
            or receipt.approval.proposal != proposal
            or receipt.approval.release.release_id != prepared.release.release_id
            or receipt.approval.release.release_digest != prepared.release.release_digest
            or receipt.approval.release.capability_id
            != prepared.capability.capability_id
            or receipt.approval.release.capability_version
            != prepared.capability.capability_version
            or receipt.approval.release.capability_digest
            != prepared.capability.definition_digest
        ):
            raise ValueError("approval consumption differs from the sealed action")
        return receipt

    def _require_terminal_outcome(
        self,
        terminal: Any,
        outcome: GatewayOutcome,
        outcome_digest: str,
        prepared: PreparedCapabilityAction,
        release: Any,
        grant_digest: str,
        evidence_path: str,
    ) -> WorkerResult:
        worker_result = outcome.worker_result
        if (
            not outcome.executed
            or not outcome.decision.allowed
            or not outcome.result_identity_valid
            or worker_result is None
            or outcome.result.request_id != prepared.request.request_id
            or outcome.result.tool_id != prepared.request.tool_id
            or terminal.activation_set_digest != prepared.activation_set_digest
            or terminal.release != release
            or terminal.capability_grant_digest != grant_digest
            or terminal.gateway_outcome_digest != outcome_digest
            or terminal.gateway_execution_id != worker_result.execution_id
            or terminal.executed is not outcome.executed
            or terminal.policy_allowed is not outcome.decision.allowed
            or terminal.tool_success is not outcome.result.success
            or terminal.evidence != (evidence_path,)
            or outcome.result.evidence != [evidence_path]
        ):
            raise ValueError("sealed terminal dispatch differs from the Gateway outcome")
        return worker_result

    def _verify_sealed_gateway_evidence(
        self,
        snapshot: VerifiedRunSnapshot,
        evidence_path: str,
        prepared: PreparedCapabilityAction,
        outcome: GatewayOutcome,
        worker_result: WorkerResult,
    ) -> tuple[
        GeneralAttackSealedEvidenceRef,
        ToolResult,
        _GatewayWorkerJobMetadata,
        tuple[SecretLease, ...],
    ]:
        content = snapshot.artifact_bytes(evidence_path)
        payload = _strict_gateway_evidence(content)
        required = {
            "request",
            "policyDecision",
            "result",
            "networkLogTrusted",
            "workerJob",
            "workerResult",
        }
        if not required <= payload.keys() or set(payload) - required - {"secretLeases"}:
            raise ValueError("sealed Gateway evidence has another top-level contract")
        request = _exact_model(ToolRequest, payload["request"], label="Gateway request")
        decision = _exact_model(
            PolicyDecision,
            payload["policyDecision"],
            label="Gateway policy decision",
        )
        evidence_result = _exact_model(
            ToolResult,
            payload["result"],
            label="Gateway pre-evidence Tool result",
        )
        evidence_worker = _exact_model(
            WorkerResult,
            payload["workerResult"],
            label="Gateway Worker result",
        )
        job = _exact_model(
            _GatewayWorkerJobMetadata,
            payload["workerJob"],
            label="Gateway Worker job metadata",
        )
        if type(payload["networkLogTrusted"]) is not bool:
            raise ValueError("Gateway evidence network trust flag is not a JSON boolean")
        leases_raw = payload.get("secretLeases", [])
        if not isinstance(leases_raw, list):
            raise ValueError("Gateway evidence secret leases are not an array")
        leases = tuple(
            _exact_model(SecretLease, item, label="Gateway secret lease")
            for item in leases_raw
        )
        if (
            request != prepared.request
            or decision != outcome.decision
            or evidence_worker != worker_result
            or job.request_id != request.request_id
            or job.execution_id != worker_result.execution_id
            or payload["networkLogTrusted"] is not outcome.network_log_trusted
            or evidence_result.request_id != request.request_id
            or evidence_result.tool_id != request.tool_id
            or evidence_result.evidence
            or job.secret_lease_ids
        ):
            raise ValueError("sealed Gateway evidence differs from the exact execution")
        artifact, seal_root = _sealed_artifact(snapshot, evidence_path)
        provenance = artifact.provenance
        if (
            provenance is None
            or provenance.request_id != request.request_id
            or provenance.tool_id != request.tool_id
            or provenance.execution_id != worker_result.execution_id
            or not provenance.event_ids
        ):
            raise ValueError("sealed Gateway evidence provenance is incomplete or substituted")
        return (
            GeneralAttackSealedEvidenceRef(
                path=artifact.path,
                sha256=artifact.sha256,
                sizeBytes=artifact.size_bytes,
                mediaType=artifact.media_type,
                requestId=request.request_id,
                toolId=request.tool_id,
                executionId=worker_result.execution_id,
                eventIds=tuple(sorted(provenance.event_ids)),
                sealRootDigest=seal_root,
            ),
            evidence_result,
            job,
            leases,
        )

    @staticmethod
    def _require_worker_dispatch(
        snapshot: VerifiedRunSnapshot,
        evidence_job: _GatewayWorkerJobMetadata,
        leases: tuple[SecretLease, ...],
        prepared: PreparedCapabilityAction,
        worker_result: WorkerResult,
    ) -> _GatewayWorkerJobMetadata:
        matches: list[_GatewayWorkerJobMetadata] = []
        for event in snapshot.events:
            if event.event_type != "worker.dispatched":
                continue
            if (
                event.payload.get("requestId") != prepared.request.request_id
                or event.payload.get("executionId") != worker_result.execution_id
            ):
                continue
            matches.append(
                _exact_model(
                    _GatewayWorkerJobMetadata,
                    event.payload,
                    label="Worker dispatched audit metadata",
                )
            )
        if len(matches) != 1:
            raise ValueError("sealed Run lacks one exact Worker dispatch audit")
        dispatched_job = matches[0]
        if dispatched_job.model_copy(update={"secret_lease_ids": ()}) != evidence_job:
            raise ValueError("sealed Gateway evidence job differs from Worker dispatch audit")
        lease_ids = tuple(lease.lease_id for lease in leases)
        if dispatched_job.secret_lease_ids != lease_ids:
            raise ValueError("Worker dispatch lease IDs differ from sealed Gateway leases")
        if len(leases) != len(dispatched_job.secret_requests):
            raise ValueError("sealed Gateway secret lease set differs from Worker job")
        for lease, request in zip(
            leases,
            dispatched_job.secret_requests,
            strict=True,
        ):
            if (
                lease.binding != request.binding
                or lease.secret_ref_fingerprint != request.secret_ref_fingerprint
                or lease.audience
                != f"{prepared.request.agent_id}:{worker_result.execution_id}"
                or lease.scope != snapshot.verification.run_id
                or lease.max_uses != 1
                or lease.remaining_uses != 0
                or lease.status is not SecretLeaseStatus.REVOKED
                or lease.revoked_reason != "Worker execution finished"
                or (lease.expires_at - lease.issued_at).total_seconds()
                != request.ttl_seconds
            ):
                raise ValueError("sealed Gateway secret lease differs from Worker job")
        return dispatched_job

    @staticmethod
    def _data_flow_observation(
        definition: CapabilityDefinition,
        job: _GatewayWorkerJobMetadata,
        outcome: GatewayOutcome,
        worker_result: WorkerResult,
    ) -> GeneralAttackDataFlowObservation:
        state: Literal[
            "network-disabled-no-egress-observed",
            "network-enabled-host-observation-bound",
        ]
        observed = bool(worker_result.network_log)
        if job.network is NetworkMode.NONE:
            if outcome.network_log_trusted or observed:
                raise ValueError("network-disabled action produced a network observation")
            state = "network-disabled-no-egress-observed"
        else:
            if not definition.network_access or not outcome.network_log_trusted:
                raise ValueError("network-enabled action lacks trusted Definition authority")
            state = "network-enabled-host-observation-bound"
        return GeneralAttackDataFlowObservation(
            sourceDefinitionDigest=definition.capability_digest,
            declaredNetworkAccess=definition.network_access,
            workerNetworkMode=job.network,
            networkLogTrusted=outcome.network_log_trusted,
            networkLogObserved=observed,
            networkLogDigest=sha256(
                worker_result.network_log.encode("utf-8", errors="strict")
            ).hexdigest(),
            state=state,
        )


def _strict_gateway_evidence(content: bytes) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON constant is not allowed: {value}")

    def pairs_to_dict(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key is not allowed")
            result[key] = value
        return result

    try:
        decoded = content.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            parse_constant=reject_constant,
            object_pairs_hook=pairs_to_dict,
        )
    except (json.JSONDecodeError, RecursionError, UnicodeError, ValueError) as exc:
        raise ValueError("sealed Gateway evidence is not strict UTF-8 JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("sealed Gateway evidence must be one JSON object")
    canonical_json_bytes(
        value,
        label="sealed Gateway evidence",
        max_bytes=_MAX_GATEWAY_EVIDENCE_BYTES,
    )
    return value


def _exact_model[ModelT: BaseModel](
    model: type[ModelT],
    value: object,
    *,
    label: str,
) -> ModelT:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    parsed = model.model_validate(value)
    dumped = parsed.model_dump(mode="json", by_alias=True)
    if canonical_json_bytes(value, label=label) != canonical_json_bytes(dumped, label=label):
        raise ValueError(f"{label} changed during canonical validation")
    return parsed


def _sealed_artifact(
    snapshot: VerifiedRunSnapshot,
    path: str,
) -> tuple[SealedArtifact, str]:
    matches = tuple(
        (artifact, seal.root_digest)
        for seal in snapshot.seals
        for artifact in seal.artifacts
        if artifact.path == path
    )
    if len(matches) != 1:
        raise ValueError("Gateway evidence is absent or duplicated in the Run seal chain")
    return matches[0]
