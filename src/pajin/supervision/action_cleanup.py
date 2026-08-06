"""PERMIT-004B2 authenticated reversible-write cleanup orchestration."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, JsonValue, model_validator

from pajin.capabilities import (
    CapabilityAuthorityBinding,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityDefinition,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityOracleDecision,
    CapabilityReleaseRef,
    CapabilitySideEffectClass,
    CleanupCapabilityDispatchReconciliationStatus,
    CodeBackedCapabilityRef,
    ExistingModeCapabilityActivation,
    ExistingModeCleanupCapabilityGatewayDispatcher,
    PreparedCapabilityAction,
    capability_gateway_outcome_digest,
    capability_grant_digest,
    reconcile_cleanup_capability_dispatch,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.hypothesis import AttackHypothesisSet, SurfaceBoundPlan
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolResult,
)
from pajin.graph import (
    ActionBudgetReservation,
    ActionCapabilityRef,
    ActionCleanupReservation,
    ActionCleanupReservationRequest,
    ActionProposal,
    CleanupPermit,
    CleanupPermitInputAuthority,
    CleanupRequest,
    GraphCleanupPermitAuthority,
    GraphCleanupPermitDispatcher,
    GraphCleanupPermitStore,
    GraphDecision,
    MissionEnvelope,
    ReversibleActionPermitInputAuthority,
    cleanup_permit_attempt_id,
)
from pajin.runtime.stable_context import stable_execution_context
from pajin.runtime.store import load_verified_run_artifacts
from pajin.supervision.action_compiler import GeneralAttackCompiledIntent
from pajin.supervision.action_outcome import (
    GeneralAttackActionOutcomeGate,
    GeneralAttackSealedEvidenceRef,
    _AuthenticatedGeneralAttackActionResult,
)
from pajin.supervision.action_permit import (
    GeneralAttackActionPermitResult,
    GeneralAttackReversibleCleanupClaim,
)
from pajin.supervision.action_proposal import GeneralAttackActionProposal
from pajin.supervision.cleanup_mapping import (
    CleanupCapabilityMappingRegistry,
    ResolvedCleanupCapabilityMapping,
)
from pajin.tools.gateway import GatewayOutcome

GENERAL_ATTACK_CLEANUP_PLAN_API_VERSION: Literal[
    "pajin.dev/general-attack-cleanup-plan/v1alpha1"
] = "pajin.dev/general-attack-cleanup-plan/v1alpha1"
GENERAL_ATTACK_CLEANUP_ASSESSMENT_API_VERSION: Literal[
    "pajin.dev/general-attack-cleanup-assessment/v1alpha1"
] = "pajin.dev/general-attack-cleanup-assessment/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_CLEANUP_AGENT_ID = "pajin.supervision.general-attack-cleanup"
_MAX_GATEWAY_EVIDENCE_BYTES = 32 * 1024 * 1024


class GeneralAttackActionCleanupError(RuntimeError):
    """Raised when reversible cleanup cannot be proven exactly."""


class GeneralAttackCleanupPlan(StrictModel):
    """One bounded Handler operation; it is not execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/general-attack-cleanup-plan/v1alpha1"] = Field(
        default=GENERAL_ATTACK_CLEANUP_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GeneralAttackCleanupPlan"] = "GeneralAttackCleanupPlan"
    operation: Literal["restore-target"] = "restore-target"
    parameters: dict[str, JsonValue]
    expected_state_digest: _Sha256 = Field(alias="expectedStateDigest")

    @model_validator(mode="after")
    def require_bounded_canonical_plan(self) -> Self:
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="General attack cleanup plan",
            max_bytes=256 * 1024,
        )
        return self


class GeneralAttackCleanupSourceRef(StrictModel):
    """Authenticated source identity for an external cleanup Graph Decision."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_outcome_id: str = Field(alias="sourceOutcomeId", min_length=1, max_length=200)
    source_outcome_digest: _Sha256 = Field(alias="sourceOutcomeDigest")
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    source_action_permit_id: str = Field(
        alias="sourceActionPermitId", min_length=1, max_length=78
    )
    source_run_root_digest: _Sha256 = Field(alias="sourceRunRootDigest")
    source_terminal_event_digest: _Sha256 = Field(
        alias="sourceTerminalEventDigest"
    )

    @model_validator(mode="after")
    def bind_source_identity(self) -> Self:
        if self.source_outcome_id != (
            f"general-attack-authenticated-outcome:{self.source_outcome_digest}"
        ):
            raise ValueError("cleanup source reference identity differs")
        return self


@dataclass(frozen=True, slots=True)
class GeneralAttackCleanupReservationInputs:
    """Trusted fixed-point cleanup price and bounded claim deadline."""

    cost_microusd: int
    claim_expires_at: datetime


class GeneralAttackCleanupReservationInputAuthority(Protocol):
    """Resolve trusted cleanup price and deadline for one exact mapping."""

    def resolve_for_cleanup_reservation(
        self,
        *,
        intent: Any,
        source_definition: CapabilityDefinition,
        cleanup_definition: CapabilityDefinition,
        mapping: ResolvedCleanupCapabilityMapping,
        campaign: CampaignManifest,
        envelope: MissionEnvelope,
        evaluated_at: datetime,
    ) -> GeneralAttackCleanupReservationInputs: ...


class GeneralAttackCleanupGrantInputAuthority(Protocol):
    """Resolve a deployment-owned, fresh least-authority cleanup Grant."""

    def resolve_for_cleanup(
        self,
        *,
        request: CleanupRequest,
        prepared: PreparedCapabilityAction,
        source_grant: CapabilityGrant,
        source_terminal_occurred_at: datetime,
        envelope: MissionEnvelope,
        campaign: CampaignManifest,
    ) -> CapabilityGrant: ...


class GeneralAttackCleanupRestoredStateVerifier(Protocol):
    """Code-identified authority that independently observes current target state."""

    @property
    def authority_id(self) -> str: ...

    @property
    def authority_version(self) -> str: ...

    def stable_execution_context(self) -> Mapping[str, object]: ...

    def observe_state_digest(
        self,
        *,
        campaign: CampaignManifest,
        target: str,
        target_digest: str,
        source_outcome_digest: str,
        cleanup_request: CleanupRequest,
        cleanup_permit: CleanupPermit,
        cleanup_result: ToolResult,
    ) -> str: ...


class GeneralAttackCleanupVerifierBinding(StrictModel):
    """Exact code identity of the independent restored-state observer."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    authority_id: str = Field(alias="authorityId", min_length=1, max_length=200)
    authority_version: str = Field(alias="authorityVersion", min_length=1, max_length=200)
    implementation_type: str = Field(alias="implementationType", min_length=1, max_length=500)
    context_digest: _Sha256 = Field(alias="contextDigest")
    authority_digest: _Sha256 = Field(alias="authorityDigest")


@dataclass(frozen=True, slots=True)
class GeneralAttackCleanupDispatch:
    """Non-authoritative observation pending sealed reconciliation and state proof."""

    source_outcome_id: str
    source_outcome_digest: str
    plan: GeneralAttackCleanupPlan
    plan_digest: str
    request: CleanupRequest
    prepared: PreparedCapabilityAction
    grant: CapabilityGrant
    permit: CleanupPermit
    envelope: MissionEnvelope
    decision: GraphDecision
    dispatched: bool
    outcome: GatewayOutcome | None


class GeneralAttackCleanupAssessment(StrictModel):
    """Content-addressed proof that cleanup executed and target state was restored."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/general-attack-cleanup-assessment/v1alpha1"] = Field(
        default=GENERAL_ATTACK_CLEANUP_ASSESSMENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GeneralAttackCleanupAssessment"] = "GeneralAttackCleanupAssessment"
    assessment_id: str = Field(default="", alias="assessmentId", max_length=120)
    assessment_digest: str = Field(default="", alias="assessmentDigest", max_length=64)
    campaign_id: str = Field(alias="campaignId", min_length=1, max_length=200)
    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    source_outcome_id: str = Field(alias="sourceOutcomeId", min_length=1, max_length=200)
    source_outcome_digest: _Sha256 = Field(alias="sourceOutcomeDigest")
    source_action_permit_id: str = Field(alias="sourceActionPermitId", min_length=1, max_length=78)
    source_action_permit_digest: _Sha256 = Field(alias="sourceActionPermitDigest")
    source_run_root_digest: _Sha256 = Field(alias="sourceRunRootDigest")
    cleanup_reservation_id: str = Field(alias="cleanupReservationId", min_length=1, max_length=91)
    cleanup_reservation_digest: _Sha256 = Field(alias="cleanupReservationDigest")
    cleanup_plan_digest: _Sha256 = Field(alias="cleanupPlanDigest")
    cleanup_request_id: str = Field(alias="cleanupRequestId", min_length=1, max_length=80)
    cleanup_request_digest: _Sha256 = Field(alias="cleanupRequestDigest")
    cleanup_permit_id: str = Field(alias="cleanupPermitId", min_length=1, max_length=79)
    cleanup_permit_digest: _Sha256 = Field(alias="cleanupPermitDigest")
    cleanup_dispatch_id: str = Field(alias="cleanupDispatchId", min_length=1, max_length=81)
    cleanup_reconciliation_digest: _Sha256 = Field(alias="cleanupReconciliationDigest")
    cleanup_terminal_event_digest: _Sha256 = Field(alias="cleanupTerminalEventDigest")
    cleanup_gateway_outcome_digest: _Sha256 = Field(alias="cleanupGatewayOutcomeDigest")
    cleanup_grant_digest: _Sha256 = Field(alias="cleanupGrantDigest")
    cleanup_worker_execution_id: str = Field(
        alias="cleanupWorkerExecutionId", min_length=1, max_length=200
    )
    cleanup_capability: ActionCapabilityRef = Field(alias="cleanupCapability")
    cleanup_release: CapabilityReleaseRef = Field(alias="cleanupRelease")
    cleanup_authorities: tuple[CapabilityAuthorityBinding, ...] = Field(
        alias="cleanupAuthorities", min_length=4, max_length=4
    )
    cleanup_evidence: GeneralAttackSealedEvidenceRef = Field(alias="cleanupEvidence")
    verifier: GeneralAttackCleanupVerifierBinding
    expected_state_digest: _Sha256 = Field(alias="expectedStateDigest")
    observed_state_digest: _Sha256 = Field(alias="observedStateDigest")
    restored: Literal[True] = True
    original_action_permit_reused: Literal[False] = Field(
        default=False, alias="originalActionPermitReused"
    )
    redispatch_allowed: Literal[False] = Field(default=False, alias="redispatchAllowed")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if self.observed_state_digest != self.expected_state_digest:
            raise ValueError("cleanup assessment state was not restored")
        expected_roles = (
            CapabilityAuthorityRole.CLEANUP_HANDLER,
            CapabilityAuthorityRole.EXECUTOR_ADAPTER,
            CapabilityAuthorityRole.RESULT_NORMALIZER,
            CapabilityAuthorityRole.SUCCESS_ORACLE,
        )
        if tuple(item.role for item in self.cleanup_authorities) != expected_roles:
            raise ValueError("cleanup assessment authority roles are incomplete or unordered")
        if self.source_outcome_id != (
            f"general-attack-authenticated-outcome:{self.source_outcome_digest}"
        ):
            raise ValueError("cleanup assessment source outcome identity differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"assessment_id", "assessment_digest"},
        )
        digest = _digest("pajin.supervision.general-attack-cleanup-assessment/v1", material)
        assessment_id = f"general-attack-cleanup-assessment_{digest}"
        if self.assessment_digest and self.assessment_digest != digest:
            raise ValueError("cleanup assessment digest differs")
        if self.assessment_id and self.assessment_id != assessment_id:
            raise ValueError("cleanup assessment ID differs")
        object.__setattr__(self, "assessment_digest", digest)
        object.__setattr__(self, "assessment_id", assessment_id)
        return self


class GeneralAttackReversibleCleanupBinder:
    """Production B1 pre-action verifier backed by current signed Capabilities."""

    def __init__(
        self,
        *,
        activation: ExistingModeCapabilityActivation,
        mappings: CleanupCapabilityMappingRegistry,
        inputs: GeneralAttackCleanupReservationInputAuthority,
    ) -> None:
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise TypeError("cleanup binder requires a verified activation")
        if not isinstance(mappings, CleanupCapabilityMappingRegistry):
            raise TypeError("cleanup binder requires code-owned mappings")
        if not callable(getattr(inputs, "resolve_for_cleanup_reservation", None)):
            raise TypeError("cleanup binder requires trusted reservation inputs")
        self._activation = activation
        self._mappings = mappings
        self._inputs = inputs

    def bind_for_action(
        self,
        *,
        intent: GeneralAttackCompiledIntent,
        prepared: PreparedCapabilityAction,
        proposal: ActionProposal,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
        envelope: MissionEnvelope,
        decision: GraphDecision,
        evaluated_at: datetime,
    ) -> GeneralAttackReversibleCleanupClaim:
        try:
            _require_reversible_source(definition)
            mapping = self._mappings.resolve(intent.code_backed_capability)
            cleanup_definition = _cleanup_definition(self._activation, mapping)
            _require_cleanup_definition(cleanup_definition)
            source_handler = self._activation.rollout.bundle.authorities.authority(
                intent.code_backed_capability,
                CapabilityAuthorityRole.CLEANUP_HANDLER,
            ).binding
            cleanup_executor = self._activation.rollout.bundle.authorities.authority(
                mapping.cleanup_binding.capability,
                CapabilityAuthorityRole.EXECUTOR_ADAPTER,
            ).binding
            reservation_inputs = _resolve_reservation_inputs(
                self._inputs,
                intent=intent,
                source_definition=definition,
                cleanup_definition=cleanup_definition,
                mapping=mapping,
                campaign=campaign,
                envelope=envelope,
                evaluated_at=evaluated_at,
            )
            request = ActionCleanupReservationRequest(
                campaignId=envelope.campaign_id,
                runId=envelope.run_id,
                envelopeId=envelope.envelope_id,
                envelopeDigest=envelope.envelope_digest,
                sourceActionProposalId=proposal.proposal_id,
                sourceActionProposalDigest=proposal.proposal_digest,
                cleanupCapability=mapping.cleanup_binding.action_capability.reference(),
                targetDigest=proposal.target_digest,
                cleanupHandlerId=source_handler.authority_id,
                cleanupHandlerVersion=source_handler.authority_version,
                cleanupHandlerDigest=source_handler.authority_digest,
                cleanupExecutorId=cleanup_executor.authority_id,
                cleanupExecutorVersion=cleanup_executor.authority_version,
                cleanupExecutorDigest=cleanup_executor.authority_digest,
                reservation=ActionBudgetReservation(
                    requestUnits=cleanup_definition.request_unit_cost,
                    costMicrousd=reservation_inputs.cost_microusd,
                ),
                createdAt=evaluated_at,
                claimExpiresAt=reservation_inputs.claim_expires_at,
            )
            verifier = _BoundReversibleActionAuthority(
                activation=self._activation,
                mappings=self._mappings,
                reservation_inputs=self._inputs,
                intent=intent,
                definition=definition,
                cleanup_definition=cleanup_definition,
                mapping=mapping,
                campaign=campaign,
                envelope=envelope,
                proposal=proposal,
                decision=decision,
                evaluated_at=evaluated_at,
                expected=request,
                source_handler=source_handler,
                cleanup_executor=cleanup_executor,
            )
            verifier.verify_reversible_action(envelope, proposal, decision, request)
            return GeneralAttackReversibleCleanupClaim(
                request=request,
                input_authority=verifier,
            )
        except Exception as exc:
            raise GeneralAttackActionCleanupError(
                "reversible action cleanup reservation failed closed"
            ) from exc


@dataclass(frozen=True, slots=True)
class _BoundReversibleActionAuthority(ReversibleActionPermitInputAuthority):
    activation: ExistingModeCapabilityActivation
    mappings: CleanupCapabilityMappingRegistry
    reservation_inputs: GeneralAttackCleanupReservationInputAuthority
    intent: GeneralAttackCompiledIntent
    definition: CapabilityDefinition
    cleanup_definition: CapabilityDefinition
    mapping: ResolvedCleanupCapabilityMapping
    campaign: CampaignManifest
    envelope: MissionEnvelope
    proposal: ActionProposal
    decision: GraphDecision
    evaluated_at: datetime
    expected: ActionCleanupReservationRequest
    source_handler: CapabilityAuthorityBinding
    cleanup_executor: CapabilityAuthorityBinding

    def verify_reversible_action(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        cleanup_request: ActionCleanupReservationRequest,
    ) -> None:
        current_mapping = self.mappings.resolve(self.intent.code_backed_capability)
        current_source = self.activation.rollout.bundle.definitions.resolve(
            self.intent.code_backed_capability.capability
        )
        current_cleanup = _cleanup_definition(self.activation, current_mapping)
        current_handler = self.activation.rollout.bundle.authorities.authority(
            self.intent.code_backed_capability,
            CapabilityAuthorityRole.CLEANUP_HANDLER,
        ).binding
        current_executor = self.activation.rollout.bundle.authorities.authority(
            current_mapping.cleanup_binding.capability,
            CapabilityAuthorityRole.EXECUTOR_ADAPTER,
        ).binding
        resolved = _resolve_reservation_inputs(
            self.reservation_inputs,
            intent=self.intent,
            source_definition=current_source,
            cleanup_definition=current_cleanup,
            mapping=current_mapping,
            campaign=self.campaign,
            envelope=self.envelope,
            evaluated_at=self.evaluated_at,
        )
        if (
            envelope != self.envelope
            or proposal != self.proposal
            or decision != self.decision
            or cleanup_request != self.expected
            or current_mapping != self.mapping
            or current_source != self.definition
            or current_cleanup != self.cleanup_definition
            or current_handler != self.source_handler
            or current_executor != self.cleanup_executor
            or resolved.cost_microusd != self.expected.reservation.cost_microusd
            or resolved.claim_expires_at != self.expected.claim_expires_at
        ):
            raise ValueError("reversible cleanup hold authority changed")
        _require_reversible_source(current_source)
        _require_cleanup_definition(current_cleanup)


class GeneralAttackActionCleanupGate:
    """Compile, consume, dispatch, and later prove one exact cleanup operation."""

    def __init__(
        self,
        *,
        activation: ExistingModeCapabilityActivation,
        outcome_gate: GeneralAttackActionOutcomeGate,
        mappings: CleanupCapabilityMappingRegistry,
        cleanup_store: GraphCleanupPermitStore,
        grants: GeneralAttackCleanupGrantInputAuthority,
        gateway: Any,
        audit_store: Any,
        verifier: GeneralAttackCleanupRestoredStateVerifier,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise TypeError("cleanup gate requires a verified activation")
        if not isinstance(outcome_gate, GeneralAttackActionOutcomeGate):
            raise TypeError("cleanup gate requires the shared sealed outcome gate")
        if not isinstance(mappings, CleanupCapabilityMappingRegistry):
            raise TypeError("cleanup gate requires code-owned mappings")
        if (
            not callable(getattr(cleanup_store, "authorize_cleanup_for_dispatch", None))
            or not callable(getattr(cleanup_store, "cleanup_permit", None))
        ):
            raise TypeError("cleanup gate requires the B1 CleanupPermit store")
        if not callable(getattr(grants, "resolve_for_cleanup", None)):
            raise TypeError("cleanup gate requires a fresh Grant authority")
        if not callable(getattr(gateway, "execute", None)):
            raise TypeError("cleanup gate requires the deployment Tool Gateway")
        if (
            not isinstance(getattr(audit_store, "run_id", None), str)
            or not isinstance(getattr(audit_store, "path", None), Path)
            or not callable(getattr(audit_store, "append_event", None))
        ):
            raise TypeError("cleanup gate requires the deployment managed Run store")
        if not callable(getattr(verifier, "observe_state_digest", None)):
            raise TypeError("cleanup gate requires a restored-state verifier authority")
        self._activation = activation
        self._outcome_gate = outcome_gate
        self._mappings = mappings
        self._cleanup_store = cleanup_store
        self._grants = grants
        self._gateway = gateway
        self._audit_store = audit_store
        self._verifier = verifier
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_ttl = permit_ttl

    def source_outcome_ref(
        self,
        source_result: GeneralAttackActionPermitResult[GatewayOutcome],
        source_proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        hypothesis_set: AttackHypothesisSet,
        plan: SurfaceBoundPlan,
        task_digest: str,
        action_definition: CapabilityDefinitionRef,
        definitions: CapabilityDefinitionRegistry,
        code_backed_capability: CodeBackedCapabilityRef,
        authorities: CapabilityAuthorityRegistry,
    ) -> GeneralAttackCleanupSourceRef:
        """Authenticate a reversible result before an external cleanup Decision."""

        try:
            authenticated = self._authenticate_source(
                source_result,
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
            source_id, source_digest = _source_outcome_identity(authenticated)
            return GeneralAttackCleanupSourceRef(
                sourceOutcomeId=source_id,
                sourceOutcomeDigest=source_digest,
                campaignId=authenticated.permit.campaign_id,
                runId=authenticated.permit.run_id,
                sourceActionPermitId=authenticated.permit.permit_id,
                sourceRunRootDigest=authenticated.evidence.seal_root_digest,
                sourceTerminalEventDigest=authenticated.terminal.event_digest,
            )
        except Exception as exc:
            raise GeneralAttackActionCleanupError(
                "general attack cleanup source authentication failed closed"
            ) from exc

    async def dispatch_once(
        self,
        source_result: GeneralAttackActionPermitResult[GatewayOutcome],
        source_proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        hypothesis_set: AttackHypothesisSet,
        plan: SurfaceBoundPlan,
        task_digest: str,
        action_definition: CapabilityDefinitionRef,
        definitions: CapabilityDefinitionRegistry,
        code_backed_capability: CodeBackedCapabilityRef,
        authorities: CapabilityAuthorityRegistry,
        envelope: MissionEnvelope,
        decision: GraphDecision,
    ) -> GeneralAttackCleanupDispatch:
        try:
            authenticated = self._authenticate_source(
                source_result,
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
            self._require_managed_runtime(authenticated)
            reservation = self._require_source_reservation(source_result, authenticated)
            compiled = self._compile_cleanup(authenticated, reservation, decision)
            input_authority = _BoundCleanupPermitAuthority(
                gate=self,
                source_args=(
                    source_result,
                    source_proposal,
                    campaign,
                    hypothesis_set,
                    plan,
                    task_digest,
                    action_definition,
                    definitions,
                    code_backed_capability,
                    authorities,
                ),
                authenticated=authenticated,
                mapping=compiled.mapping,
                reservation=reservation,
                plan=compiled.plan,
                request=compiled.request,
                prepared=compiled.prepared,
                plan_digest=compiled.plan_digest,
                decision=decision,
                envelope=envelope,
            )
            permit_authority = GraphCleanupPermitAuthority(
                campaign_id=envelope.campaign_id,
                compiler_id=envelope.compiler_id,
                compiler_version=envelope.compiler_version,
                compiler_digest=envelope.compiler_digest,
                capabilities=self._activation.action_registry(),
                permit_store=self._cleanup_store,
                input_authority=input_authority,
                claim_authority=self,
                clock=lambda: claim_at,
                permit_ttl=self._permit_ttl,
            )
            grant = self._resolve_grant(
                compiled.request,
                compiled.prepared,
                authenticated,
                envelope,
                campaign,
            )
            claim_at = self._evaluated_at()
            self._validate_grant_before_claim(
                grant,
                authenticated,
                compiled.prepared,
                envelope,
                reservation,
                compiled.request,
                decision,
                claim_at,
            )
            dispatcher = ExistingModeCleanupCapabilityGatewayDispatcher(
                activation=self._activation,
                permits=GraphCleanupPermitDispatcher(permit_authority),
                gateway=self._gateway,
                audit_store=self._audit_store,
                clock=self._evaluated_at,
            )
            dispatched = await dispatcher.dispatch_once(
                envelope,
                compiled.request,
                decision,
                compiled.prepared,
                campaign=campaign,
                grant=grant,
                source_grant=authenticated.grant,
                source_terminal_occurred_at=authenticated.terminal.occurred_at,
                used_calls=0,
            )
            return GeneralAttackCleanupDispatch(
                source_outcome_id=compiled.source_outcome_id,
                source_outcome_digest=compiled.source_outcome_digest,
                plan=compiled.plan,
                plan_digest=compiled.plan_digest,
                request=compiled.request,
                prepared=compiled.prepared,
                grant=grant,
                permit=dispatched.permit,
                envelope=envelope,
                decision=decision,
                dispatched=dispatched.dispatched,
                outcome=dispatched.result,
            )
        except Exception as exc:
            raise GeneralAttackActionCleanupError(
                "general attack cleanup dispatch failed closed"
            ) from exc

    def verify_restored(
        self,
        dispatch: GeneralAttackCleanupDispatch,
        source_result: GeneralAttackActionPermitResult[GatewayOutcome],
        source_proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        hypothesis_set: AttackHypothesisSet,
        plan: SurfaceBoundPlan,
        task_digest: str,
        action_definition: CapabilityDefinitionRef,
        definitions: CapabilityDefinitionRegistry,
        code_backed_capability: CodeBackedCapabilityRef,
        authorities: CapabilityAuthorityRegistry,
    ) -> GeneralAttackCleanupAssessment:
        """Require sealed cleanup completion, semantic success, and actual restored state."""

        try:
            authenticated = self._authenticate_source(
                source_result,
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
            source_id, source_digest = _source_outcome_identity(authenticated)
            if (
                not dispatch.dispatched
                or dispatch.outcome is None
                or dispatch.source_outcome_id != source_id
                or dispatch.source_outcome_digest != source_digest
            ):
                raise ValueError("cleanup dispatch lacks one exact source outcome")
            permit = CleanupPermit.model_validate(
                dispatch.permit.model_dump(mode="json", by_alias=True)
            )
            stored_permit = self._cleanup_store.cleanup_permit(
                permit.cleanup_permit_id
            )
            if stored_permit is None or stored_permit != permit:
                raise ValueError("cleanup Permit is not the exact consumed GRAPH authority")
            request = CleanupRequest.model_validate(
                dispatch.request.model_dump(mode="json", by_alias=True)
            )
            prepared = PreparedCapabilityAction.model_validate(
                dispatch.prepared.model_dump(mode="json", by_alias=True)
            )
            outcome = GatewayOutcome.model_validate(dispatch.outcome.model_dump(mode="json"))
            envelope = MissionEnvelope.model_validate(
                dispatch.envelope.model_dump(mode="json", by_alias=True)
            )
            decision = GraphDecision.model_validate(
                dispatch.decision.model_dump(mode="json", by_alias=True)
            )
            reservation = self._require_source_reservation(
                source_result,
                authenticated,
            )
            mapping = self._mappings.resolve(authenticated.code_backed_capability)
            rebuilt = self._rebuild_cleanup_plan(authenticated, mapping)
            if rebuilt.plan != dispatch.plan or rebuilt.prepared != prepared:
                raise ValueError("current cleanup Handler plan or preparation changed")
            _validate_cleanup_dispatch_lineage(
                dispatch,
                authenticated,
                reservation,
                request,
                permit,
                prepared,
                envelope,
                decision,
                mapping,
                rebuilt.plan_digest,
            )
            _validate_cleanup_grant(
                dispatch.grant,
                authenticated,
                prepared,
                envelope,
                permit,
            )
            evidence_path = f"evidence/{prepared.request.request_id}.json"
            snapshot = load_verified_run_artifacts(
                authenticated.run_path,
                requests={evidence_path: _MAX_GATEWAY_EVIDENCE_BYTES},
                expected_run_id=permit.run_id,
            )
            reconciliation = reconcile_cleanup_capability_dispatch(snapshot, permit)
            terminal = reconciliation.terminal_event
            if (
                reconciliation.record.status
                is not CleanupCapabilityDispatchReconciliationStatus.COMPLETED
                or terminal is None
            ):
                raise ValueError("cleanup result is not sealed completed evidence")
            if terminal.source_capability_grant_digest != authenticated.grant_digest:
                raise ValueError("cleanup terminal binds another source Grant")
            outcome_digest = capability_gateway_outcome_digest(outcome)
            grant_digest = capability_grant_digest(dispatch.grant)
            worker_result = self._outcome_gate._require_terminal_outcome(
                terminal,
                outcome,
                outcome_digest,
                prepared,
                prepared.release,
                grant_digest,
                evidence_path,
            )
            evidence_ref, evidence_result, evidence_job, leases = (
                self._outcome_gate._verify_sealed_gateway_evidence(
                    snapshot,
                    evidence_path,
                    prepared,
                    outcome,
                    worker_result,
                )
            )
            self._outcome_gate._require_worker_dispatch(
                snapshot,
                evidence_job,
                leases,
                prepared,
                worker_result,
            )
            if mapping.cleanup_binding.action_capability.reference() != prepared.capability:
                raise ValueError("cleanup mapping differs from sealed dispatch")
            handles = _cleanup_outcome_handles(self._activation, prepared)
            normalized = handles[CapabilityAuthorityRole.RESULT_NORMALIZER].normalize(
                prepared.request,
                worker_result,
            )
            if normalized.evidence or normalized != evidence_result:
                raise ValueError("cleanup Result Normalizer differs from sealed evidence")
            expected_result = normalized.model_copy(
                update={"evidence": [evidence_path]},
                deep=True,
            )
            if outcome.result != expected_result:
                raise ValueError("cleanup Gateway result differs from sealed evidence")
            if (
                handles[CapabilityAuthorityRole.SUCCESS_ORACLE].evaluate(
                    prepared.request,
                    normalized,
                )
                is not CapabilityOracleDecision.SUCCEEDED
            ):
                raise ValueError("cleanup semantic outcome is not successful")
            if (
                handles[CapabilityAuthorityRole.CLEANUP_HANDLER].plan_cleanup(
                    prepared.request,
                    normalized,
                )
                is not None
            ):
                raise ValueError("cleanup Capability requires recursive cleanup")
            observed_digest, verifier_binding = _observe_restored_state(
                self._verifier,
                campaign=campaign,
                target=prepared.request.target,
                target_digest=request.target_digest,
                source_outcome_digest=source_digest,
                cleanup_request=request,
                cleanup_permit=permit,
                cleanup_result=normalized,
            )
            if observed_digest != dispatch.plan.expected_state_digest:
                raise ValueError("independent target observation is not restored")
            _revalidate_cleanup_roles(self._activation, mapping, prepared, handles)
            bindings = tuple(
                handles[role].binding
                for role in (
                    CapabilityAuthorityRole.CLEANUP_HANDLER,
                    CapabilityAuthorityRole.EXECUTOR_ADAPTER,
                    CapabilityAuthorityRole.RESULT_NORMALIZER,
                    CapabilityAuthorityRole.SUCCESS_ORACLE,
                )
            )
            return GeneralAttackCleanupAssessment(
                campaignId=permit.campaign_id,
                runId=permit.run_id,
                sourceOutcomeId=source_id,
                sourceOutcomeDigest=source_digest,
                sourceActionPermitId=authenticated.permit.permit_id,
                sourceActionPermitDigest=authenticated.permit.permit_digest,
                sourceRunRootDigest=authenticated.evidence.seal_root_digest,
                cleanupReservationId=reservation.cleanup_reservation_id,
                cleanupReservationDigest=reservation.cleanup_reservation_digest,
                cleanupPlanDigest=dispatch.plan_digest,
                cleanupRequestId=request.cleanup_request_id,
                cleanupRequestDigest=request.cleanup_request_digest,
                cleanupPermitId=permit.cleanup_permit_id,
                cleanupPermitDigest=permit.cleanup_permit_digest,
                cleanupDispatchId=permit.cleanup_dispatch_id,
                cleanupReconciliationDigest=reconciliation.record.reconciliation_digest,
                cleanupTerminalEventDigest=terminal.event_digest,
                cleanupGatewayOutcomeDigest=outcome_digest,
                cleanupGrantDigest=grant_digest,
                cleanupWorkerExecutionId=worker_result.execution_id,
                cleanupCapability=prepared.capability,
                cleanupRelease=prepared.release,
                cleanupAuthorities=bindings,
                cleanupEvidence=evidence_ref,
                verifier=verifier_binding,
                expectedStateDigest=dispatch.plan.expected_state_digest,
                observedStateDigest=observed_digest,
            )
        except Exception as exc:
            raise GeneralAttackActionCleanupError(
                "general attack restored-state verification failed closed"
            ) from exc

    def _authenticate_source(self, *args: Any) -> _AuthenticatedGeneralAttackActionResult:
        authenticated = self._outcome_gate._authenticate_result(*args)
        _require_reversible_source(authenticated.definition)
        return authenticated

    def _require_source_reservation(
        self,
        source_result: GeneralAttackActionPermitResult[GatewayOutcome],
        authenticated: _AuthenticatedGeneralAttackActionResult,
    ) -> ActionCleanupReservation:
        reservation = source_result.cleanup_reservation
        if reservation is None:
            raise ValueError("reversible Action lacks its pre-action cleanup hold")
        canonical = ActionCleanupReservation.model_validate(
            reservation.model_dump(mode="json", by_alias=True)
        )
        stored = self._cleanup_store.cleanup_reservation(canonical.cleanup_reservation_id)
        if (
            stored is None
            or stored != canonical
            or canonical.source_action_permit_id != authenticated.permit.permit_id
            or canonical.source_action_permit_digest != authenticated.permit.permit_digest
            or canonical.source_action_dispatch_id != authenticated.permit.dispatch_id
        ):
            raise ValueError("cleanup hold differs from the authenticated source Action")
        return canonical

    def _require_managed_runtime(
        self,
        authenticated: _AuthenticatedGeneralAttackActionResult,
    ) -> None:
        audit_path = self._audit_store.path.resolve(strict=True)
        if (
            self._audit_store.run_id != authenticated.permit.run_id
            or audit_path != authenticated.run_path
        ):
            raise ValueError("cleanup dispatch runtime differs from the authenticated managed Run")

    def _compile_cleanup(
        self,
        authenticated: _AuthenticatedGeneralAttackActionResult,
        reservation: ActionCleanupReservation,
        decision: GraphDecision,
    ) -> _CompiledCleanup:
        mapping = self._mappings.resolve(authenticated.code_backed_capability)
        rebuilt = self._rebuild_cleanup_plan(authenticated, mapping)
        cleanup_definition = rebuilt.definition
        plan = rebuilt.plan
        prepared = rebuilt.prepared
        executor = rebuilt.executor
        plan_digest = rebuilt.plan_digest
        source_outcome_id, source_outcome_digest = _source_outcome_identity(authenticated)
        if (
            reservation.cleanup_capability != prepared.capability
            or reservation.target_digest != authenticated.permit.target_digest
            or reservation.cleanup_handler_digest
            != authenticated.cleanup_handler.binding.authority_digest
            or reservation.cleanup_executor_digest != executor.authority_digest
            or reservation.reservation.request_units != cleanup_definition.request_unit_cost
        ):
            raise ValueError("cleanup plan differs from pre-action held authority")
        request = CleanupRequest(
            campaignId=authenticated.permit.campaign_id,
            runId=authenticated.permit.run_id,
            envelopeId=authenticated.permit.envelope_id,
            envelopeDigest=authenticated.permit.envelope_digest,
            cleanupReservationId=reservation.cleanup_reservation_id,
            cleanupReservationDigest=reservation.cleanup_reservation_digest,
            sourceActionPermitId=authenticated.permit.permit_id,
            sourceActionPermitDigest=authenticated.permit.permit_digest,
            sourceActionDispatchId=authenticated.permit.dispatch_id,
            sourceOutcomeId=source_outcome_id,
            sourceOutcomeDigest=source_outcome_digest,
            sourceRunRootDigest=authenticated.evidence.seal_root_digest,
            sourceTerminalEventDigest=authenticated.terminal.event_digest,
            sourceGatewayOutcomeDigest=authenticated.gateway_outcome_digest,
            sourceWorkerExecutionId=authenticated.worker_execution_id,
            decisionId=decision.decision_id,
            decisionDigest=decision.decision_digest,
            snapshot=decision.snapshot,
            cleanupHandlerId=authenticated.cleanup_handler.binding.authority_id,
            cleanupHandlerVersion=authenticated.cleanup_handler.binding.authority_version,
            cleanupHandlerDigest=authenticated.cleanup_handler.binding.authority_digest,
            cleanupExecutorId=executor.authority_id,
            cleanupExecutorVersion=executor.authority_version,
            cleanupExecutorDigest=executor.authority_digest,
            cleanupPlanDigest=plan_digest,
            capability=prepared.capability,
            targetDigest=authenticated.permit.target_digest,
            requestId=prepared.request.request_id,
            requestDigest=prepared.request_digest,
            normalizedParametersDigest=prepared.normalized_parameters_digest,
            reservation=reservation.reservation,
            createdAt=decision.created_at,
        )
        return _CompiledCleanup(
            source_outcome_id=source_outcome_id,
            source_outcome_digest=source_outcome_digest,
            mapping=mapping,
            plan=plan,
            plan_digest=plan_digest,
            prepared=prepared,
            request=request,
        )

    def _rebuild_cleanup_plan(
        self,
        authenticated: _AuthenticatedGeneralAttackActionResult,
        mapping: ResolvedCleanupCapabilityMapping,
    ) -> _RebuiltCleanupPlan:
        cleanup_definition = _cleanup_definition(self._activation, mapping)
        _require_cleanup_definition(cleanup_definition)
        raw_plan = authenticated.cleanup_handler.plan_cleanup(
            authenticated.prepared.request,
            authenticated.normalized_result,
        )
        if raw_plan is None:
            raise ValueError("cleanup-required Handler returned no operation")
        plan = GeneralAttackCleanupPlan.model_validate(raw_plan)
        _, source_outcome_digest = _source_outcome_identity(authenticated)
        seed = ToolRequest(
            request_id=_cleanup_request_id(source_outcome_digest, mapping, plan),
            agent_id=_CLEANUP_AGENT_ID,
            tool_id=cleanup_definition.tool.tool_id,
            target=authenticated.prepared.request.target,
            method=mapping.cleanup_method,
            arguments=cast(dict[str, Any], plan.parameters),
        )
        prepared = self._activation.prepare_action(
            release=mapping.cleanup_binding.release,
            request=seed,
            parameters=plan.parameters,
        )
        if (
            prepared.capability != mapping.cleanup_binding.action_capability.reference()
            or prepared.request.target != authenticated.prepared.request.target
            or prepared.request.request_id == authenticated.prepared.request.request_id
        ):
            raise ValueError("compiled cleanup expands or reuses source authority")
        executor = self._activation.rollout.bundle.authorities.authority(
            mapping.cleanup_binding.capability,
            CapabilityAuthorityRole.EXECUTOR_ADAPTER,
        ).binding
        plan_digest = _cleanup_plan_digest(
            plan,
            mapping,
            authenticated.cleanup_handler.binding,
            executor,
            prepared,
        )
        return _RebuiltCleanupPlan(
            definition=cleanup_definition,
            plan=plan,
            prepared=prepared,
            executor=executor,
            plan_digest=plan_digest,
        )

    def _resolve_grant(
        self,
        request: CleanupRequest,
        prepared: PreparedCapabilityAction,
        authenticated: _AuthenticatedGeneralAttackActionResult,
        envelope: MissionEnvelope,
        campaign: CampaignManifest,
    ) -> CapabilityGrant:
        resolved = self._grants.resolve_for_cleanup(
            request=CleanupRequest.model_validate(request.model_dump(mode="json", by_alias=True)),
            prepared=PreparedCapabilityAction.model_validate(
                prepared.model_dump(mode="json", by_alias=True)
            ),
            source_grant=CapabilityGrant.model_validate(
                authenticated.grant.model_dump(mode="json", by_alias=True)
            ),
            source_terminal_occurred_at=authenticated.terminal.occurred_at,
            envelope=MissionEnvelope.model_validate(
                envelope.model_dump(mode="json", by_alias=True)
            ),
            campaign=CampaignManifest.model_validate(
                campaign.model_dump(mode="json", by_alias=True)
            ),
        )
        return CapabilityGrant.model_validate(resolved.model_dump(mode="json", by_alias=True))

    def _validate_grant_before_claim(
        self,
        grant: CapabilityGrant,
        authenticated: _AuthenticatedGeneralAttackActionResult,
        prepared: PreparedCapabilityAction,
        envelope: MissionEnvelope,
        reservation: ActionCleanupReservation,
        request: CleanupRequest,
        decision: GraphDecision,
        claim_at: datetime,
    ) -> None:
        attempt_id = cleanup_permit_attempt_id(envelope, request, decision)
        stored = self._cleanup_store.cleanup_permit(attempt_id)
        if stored is not None:
            _validate_cleanup_grant(
                grant,
                authenticated,
                prepared,
                envelope,
                stored,
            )
            return
        canonical = CapabilityGrant.model_validate(
            grant.model_dump(mode="json", by_alias=True)
        )
        expires_at = min(
            envelope.expires_at,
            reservation.claim_expires_at,
            claim_at + self._permit_ttl,
        )
        if (
            canonical.grant_id == authenticated.grant.grant_id
            or capability_grant_digest(canonical) == authenticated.grant_digest
            or canonical.campaign != envelope.campaign_id
            or canonical.subject != prepared.request.agent_id
            or canonical.tools != {prepared.request.tool_id}
            or canonical.targets != {prepared.request.target}
            or canonical.max_risk_tier != prepared.capability.risk_tier
            or canonical.max_calls != 1
            or canonical.delegable
            or canonical.issued_at <= authenticated.terminal.occurred_at
            or canonical.issued_at > claim_at
            or canonical.expires_at > expires_at
        ):
            raise ValueError("cleanup Grant cannot fit the prospective Permit window")

    def _evaluated_at(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("cleanup gate clock requires a UTC offset or Z")
        return value.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class _CompiledCleanup:
    source_outcome_id: str
    source_outcome_digest: str
    mapping: ResolvedCleanupCapabilityMapping
    plan: GeneralAttackCleanupPlan
    plan_digest: str
    prepared: PreparedCapabilityAction
    request: CleanupRequest


@dataclass(frozen=True, slots=True)
class _RebuiltCleanupPlan:
    definition: CapabilityDefinition
    plan: GeneralAttackCleanupPlan
    prepared: PreparedCapabilityAction
    executor: CapabilityAuthorityBinding
    plan_digest: str


@dataclass(frozen=True, slots=True)
class _BoundCleanupPermitAuthority(CleanupPermitInputAuthority):
    gate: GeneralAttackActionCleanupGate
    source_args: tuple[Any, ...]
    authenticated: _AuthenticatedGeneralAttackActionResult
    mapping: ResolvedCleanupCapabilityMapping
    reservation: ActionCleanupReservation
    plan: GeneralAttackCleanupPlan
    request: CleanupRequest
    prepared: PreparedCapabilityAction
    plan_digest: str
    decision: GraphDecision
    envelope: MissionEnvelope

    def verify_cleanup_request(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
    ) -> None:
        current = self.gate._authenticate_source(*self.source_args)
        current_id, current_digest = _source_outcome_identity(current)
        current_mapping = self.gate._mappings.resolve(current.code_backed_capability)
        rebuilt = self.gate._rebuild_cleanup_plan(current, current_mapping)
        if (
            envelope != self.envelope
            or request != self.request
            or decision != self.decision
            or current_id != request.source_outcome_id
            or current_digest != request.source_outcome_digest
            or current_mapping != self.mapping
            or rebuilt.plan != self.plan
            or rebuilt.prepared != self.prepared
            or request.cleanup_reservation_id != self.reservation.cleanup_reservation_id
            or request.cleanup_reservation_digest != self.reservation.cleanup_reservation_digest
            or request.cleanup_handler_digest != current.cleanup_handler.binding.authority_digest
            or request.cleanup_executor_digest != rebuilt.executor.authority_digest
            or request.cleanup_plan_digest != rebuilt.plan_digest
            or rebuilt.plan_digest != self.plan_digest
            or request.capability != self.prepared.capability
            or request.request_digest != self.prepared.request_digest
            or request.normalized_parameters_digest != self.prepared.normalized_parameters_digest
        ):
            raise ValueError("cleanup Permit input authority changed")


def _validate_cleanup_dispatch_lineage(
    dispatch: GeneralAttackCleanupDispatch,
    authenticated: _AuthenticatedGeneralAttackActionResult,
    reservation: ActionCleanupReservation,
    request: CleanupRequest,
    permit: CleanupPermit,
    prepared: PreparedCapabilityAction,
    envelope: MissionEnvelope,
    decision: GraphDecision,
    mapping: ResolvedCleanupCapabilityMapping,
    expected_plan_digest: str,
) -> None:
    if (
        dispatch.plan_digest != expected_plan_digest
        or request.cleanup_plan_digest != expected_plan_digest
        or permit.cleanup_plan_digest != expected_plan_digest
        or request.campaign_id != authenticated.permit.campaign_id
        or request.run_id != authenticated.permit.run_id
        or request.envelope_id != envelope.envelope_id
        or request.envelope_digest != envelope.envelope_digest
        or request.cleanup_reservation_id != reservation.cleanup_reservation_id
        or request.cleanup_reservation_digest != reservation.cleanup_reservation_digest
        or request.source_action_permit_id != authenticated.permit.permit_id
        or request.source_action_permit_digest != authenticated.permit.permit_digest
        or request.source_action_dispatch_id != authenticated.permit.dispatch_id
        or request.source_run_root_digest != authenticated.evidence.seal_root_digest
        or request.source_terminal_event_digest != authenticated.terminal.event_digest
        or request.source_gateway_outcome_digest != authenticated.gateway_outcome_digest
        or request.source_worker_execution_id != authenticated.worker_execution_id
        or request.decision_id != decision.decision_id
        or request.decision_digest != decision.decision_digest
        or request.snapshot != decision.snapshot
        or decision.decision_payload_digest != request.source_outcome_digest
        or request.capability != mapping.cleanup_binding.action_capability.reference()
        or request.capability != prepared.capability
        or request.target_digest != authenticated.permit.target_digest
        or request.request_id != prepared.request.request_id
        or request.request_digest != prepared.request_digest
        or request.normalized_parameters_digest != prepared.normalized_parameters_digest
        or request.reservation != reservation.reservation
        or permit.cleanup_request_id != request.cleanup_request_id
        or permit.cleanup_request_digest != request.cleanup_request_digest
        or permit.cleanup_reservation_id != request.cleanup_reservation_id
        or permit.cleanup_reservation_digest != request.cleanup_reservation_digest
        or permit.source_outcome_id != request.source_outcome_id
        or permit.source_outcome_digest != request.source_outcome_digest
        or permit.request_id != request.request_id
        or permit.request_digest != request.request_digest
        or permit.normalized_parameters_digest != request.normalized_parameters_digest
        or permit.capability != request.capability
        or permit.target_digest != request.target_digest
        or permit.reservation != request.reservation
    ):
        raise ValueError("cleanup dispatch lineage differs from current authority")


def _validate_cleanup_grant(
    grant: CapabilityGrant,
    authenticated: _AuthenticatedGeneralAttackActionResult,
    prepared: PreparedCapabilityAction,
    envelope: MissionEnvelope,
    permit: CleanupPermit,
) -> None:
    canonical = CapabilityGrant.model_validate(grant.model_dump(mode="json", by_alias=True))
    if (
        canonical.grant_id == authenticated.grant.grant_id
        or capability_grant_digest(canonical) == authenticated.grant_digest
        or canonical.campaign != permit.campaign_id
        or canonical.subject != prepared.request.agent_id
        or canonical.tools != {prepared.request.tool_id}
        or canonical.targets != {prepared.request.target}
        or canonical.max_risk_tier != prepared.capability.risk_tier
        or canonical.max_calls != 1
        or canonical.delegable
        or canonical.issued_at <= authenticated.terminal.occurred_at
        or canonical.issued_at > permit.issued_at
        or canonical.expires_at > permit.expires_at
        or canonical.expires_at > envelope.expires_at
    ):
        raise ValueError("cleanup Grant is stale, reused, or overbroad")


def _resolve_reservation_inputs(
    authority: GeneralAttackCleanupReservationInputAuthority,
    **kwargs: Any,
) -> GeneralAttackCleanupReservationInputs:
    resolved = authority.resolve_for_cleanup_reservation(**kwargs)
    if type(resolved) is not GeneralAttackCleanupReservationInputs:
        raise TypeError("cleanup reservation authority returned another type")
    if type(resolved.cost_microusd) is not int or resolved.cost_microusd < 0:
        raise ValueError("cleanup cost must be a non-negative exact integer")
    if (
        not isinstance(resolved.claim_expires_at, datetime)
        or resolved.claim_expires_at.tzinfo is None
        or resolved.claim_expires_at.utcoffset() is None
    ):
        raise ValueError("cleanup claim expiry requires a UTC offset or Z")
    return GeneralAttackCleanupReservationInputs(
        cost_microusd=resolved.cost_microusd,
        claim_expires_at=resolved.claim_expires_at.astimezone(UTC),
    )


def _require_reversible_source(definition: CapabilityDefinition) -> None:
    if (
        definition.side_effect_class is not CapabilitySideEffectClass.REVERSIBLE_WRITE
        or not definition.cleanup_required
    ):
        raise ValueError("source is not reversible-write with required cleanup")


def _require_cleanup_definition(definition: CapabilityDefinition) -> None:
    if (
        definition.side_effect_class is CapabilitySideEffectClass.IRREVERSIBLE_WRITE
        or definition.cleanup_required
    ):
        raise ValueError("cleanup Capability is irreversible or recursively requires cleanup")


def _cleanup_definition(
    activation: ExistingModeCapabilityActivation,
    mapping: ResolvedCleanupCapabilityMapping,
) -> CapabilityDefinition:
    resolved = activation.resolve_for_dispatch(
        mapping.cleanup_binding.action_capability.reference()
    )
    if (
        resolved.release != mapping.cleanup_binding.release
        or resolved.capability.reference() != mapping.cleanup_binding.capability
    ):
        raise ValueError("cleanup mapping differs from current signed activation")
    return activation.rollout.bundle.definitions.resolve(
        mapping.cleanup_binding.capability.capability
    )


def _source_outcome_identity(
    authenticated: _AuthenticatedGeneralAttackActionResult,
) -> tuple[str, str]:
    material = {
        "campaignId": authenticated.permit.campaign_id,
        "runId": authenticated.permit.run_id,
        "intentDigest": authenticated.canonical_intent.intent_digest,
        "proposalId": authenticated.graph_proposal.proposal_id,
        "proposalDigest": authenticated.graph_proposal.proposal_digest,
        "permitId": authenticated.permit.permit_id,
        "permitDigest": authenticated.permit.permit_digest,
        "dispatchId": authenticated.permit.dispatch_id,
        "definition": authenticated.definition.reference().model_dump(mode="json", by_alias=True),
        "capability": authenticated.code_backed_capability.model_dump(mode="json", by_alias=True),
        "release": authenticated.release.model_dump(mode="json", by_alias=True),
        "activationSetDigest": authenticated.prepared.activation_set_digest,
        "runAnchorDigest": authenticated.run_anchor.anchor_digest,
        "sourceEvidenceSealRootDigest": authenticated.evidence.seal_root_digest,
        "reconciliationDigest": authenticated.reconciliation.record.reconciliation_digest,
        "terminalEventDigest": authenticated.terminal.event_digest,
        "gatewayOutcomeDigest": authenticated.gateway_outcome_digest,
        "grantDigest": authenticated.grant_digest,
        "workerExecutionId": authenticated.worker_execution_id,
        "evidenceSha256": authenticated.evidence.sha256,
        "evidenceSealRootDigest": authenticated.evidence.seal_root_digest,
        "cleanupHandlerDigest": authenticated.cleanup_handler.binding.authority_digest,
        "executorDigest": authenticated.executor_adapter.binding.authority_digest,
        "resultNormalizerDigest": authenticated.result_normalizer.binding.authority_digest,
        "successOracleDigest": authenticated.success_oracle.binding.authority_digest,
    }
    digest = _digest("pajin.supervision.authenticated-action-result/v1", material)
    return f"general-attack-authenticated-outcome:{digest}", digest


def _cleanup_request_id(
    source_outcome_digest: str,
    mapping: ResolvedCleanupCapabilityMapping,
    plan: GeneralAttackCleanupPlan,
) -> str:
    digest = _digest(
        "pajin.supervision.cleanup-request-id/v1",
        {
            "sourceOutcomeDigest": source_outcome_digest,
            "mappingDigest": mapping.mapping_digest,
            "plan": plan.model_dump(mode="json", by_alias=True),
        },
    )
    return f"general-attack-cleanup_{digest}"


def _cleanup_plan_digest(
    plan: GeneralAttackCleanupPlan,
    mapping: ResolvedCleanupCapabilityMapping,
    source_handler: CapabilityAuthorityBinding,
    cleanup_executor: CapabilityAuthorityBinding,
    prepared: PreparedCapabilityAction,
) -> str:
    return _digest(
        "pajin.supervision.general-attack-cleanup-plan/v1",
        {
            "plan": plan.model_dump(mode="json", by_alias=True),
            "mappingDigest": mapping.mapping_digest,
            "sourceHandler": source_handler.model_dump(mode="json", by_alias=True),
            "cleanupExecutor": cleanup_executor.model_dump(mode="json", by_alias=True),
            "prepared": prepared.model_dump(mode="json", by_alias=True),
        },
    )


def _cleanup_outcome_handles(
    activation: ExistingModeCapabilityActivation,
    prepared: PreparedCapabilityAction,
) -> dict[CapabilityAuthorityRole, Any]:
    authorities = activation.rollout.bundle.authorities
    return {
        role: authorities.authority(
            next(
                item.capability
                for item in activation.activation_set.bindings
                if item.action_capability.reference() == prepared.capability
            ),
            role,
        )
        for role in (
            CapabilityAuthorityRole.CLEANUP_HANDLER,
            CapabilityAuthorityRole.EXECUTOR_ADAPTER,
            CapabilityAuthorityRole.RESULT_NORMALIZER,
            CapabilityAuthorityRole.SUCCESS_ORACLE,
        )
    }


def _revalidate_cleanup_roles(
    activation: ExistingModeCapabilityActivation,
    mapping: ResolvedCleanupCapabilityMapping,
    prepared: PreparedCapabilityAction,
    handles: Mapping[CapabilityAuthorityRole, Any],
) -> None:
    resolved = activation.resolve_for_dispatch(prepared.capability)
    current_mapping = next(
        item
        for item in activation.activation_set.bindings
        if item.capability == mapping.cleanup_binding.capability
    )
    if (
        current_mapping != mapping.cleanup_binding
        or resolved.release != prepared.release
        or resolved.capability.reference() != mapping.cleanup_binding.capability
    ):
        raise ValueError("cleanup activation changed during restored-state verification")
    authorities = activation.rollout.bundle.authorities
    for role, handle in handles.items():
        if (
            authorities.authority(mapping.cleanup_binding.capability, role).binding
            != handle.binding
        ):
            raise ValueError("cleanup outcome authority changed during verification")


def _observe_restored_state(
    verifier: GeneralAttackCleanupRestoredStateVerifier,
    **kwargs: Any,
) -> tuple[str, GeneralAttackCleanupVerifierBinding]:
    before = _verifier_binding(verifier)
    observed = verifier.observe_state_digest(**kwargs)
    after = _verifier_binding(verifier)
    if before != after or not isinstance(observed, str) or len(observed) != 64:
        raise ValueError("restored-state verifier identity or observation is invalid")
    try:
        int(observed, 16)
    except ValueError as exc:
        raise ValueError("restored-state observation digest is invalid") from exc
    return observed, before


def _verifier_binding(
    verifier: GeneralAttackCleanupRestoredStateVerifier,
) -> GeneralAttackCleanupVerifierBinding:
    authority_id = verifier.authority_id
    authority_version = verifier.authority_version
    stable = stable_execution_context(
        verifier,
        component=f"cleanup restored-state verifier {authority_id}@{authority_version}",
    )
    implementation_type = cast(str, stable["type"])
    context_digest = _digest(
        "pajin.supervision.cleanup-state-verifier-context/v1",
        {"implementationType": implementation_type, "context": stable["context"]},
    )
    authority_digest = _digest(
        "pajin.supervision.cleanup-state-verifier/v1",
        {
            "authorityId": authority_id,
            "authorityVersion": authority_version,
            "implementationType": implementation_type,
            "contextDigest": context_digest,
        },
    )
    return GeneralAttackCleanupVerifierBinding(
        authorityId=authority_id,
        authorityVersion=authority_version,
        implementationType=implementation_type,
        contextDigest=context_digest,
        authorityDigest=authority_digest,
    )


def _digest(domain: str, material: object) -> str:
    from pajin.capabilities.models import capability_definition_digest

    return capability_definition_digest(domain, material)
