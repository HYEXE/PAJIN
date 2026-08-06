"""PERMIT-003 exact bridge into the existing single-use GRAPH ActionPermit path."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import ROUND_FLOOR, Decimal
from inspect import iscoroutinefunction
from typing import Protocol, cast

from pydantic import ValidationError

from pajin.capabilities import (
    CapabilityAuthorityRegistry,
    CapabilityDefinition,
    CapabilityDefinitionError,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilitySideEffectClass,
    CodeBackedCapabilityRef,
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationBinding,
    ExistingModeCapabilityActivationError,
    PreparedCapabilityAction,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.hypothesis import AttackHypothesisSet, SurfaceBoundPlan
from pajin.domain.models import CampaignManifest, ToolRiskTier, campaign_manifest_digest
from pajin.graph import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalInputAuthority,
    ActionApprovalIssuerAuthorityBinding,
    ActionBudgetReservation,
    ActionCleanupReservation,
    ActionCleanupReservationRequest,
    ActionDispatchResult,
    ActionPermit,
    ActionProposal,
    GraphActionPermitAuthority,
    GraphActionPermitDispatcher,
    GraphActionPermitStore,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
    GraphApprovedActionPermitStore,
    GraphApprovedReversibleActionPermitAuthority,
    GraphApprovedReversibleActionPermitDispatcher,
    GraphApprovedReversibleActionPermitStore,
    GraphDecision,
    GraphDecisionKind,
    GraphReversibleActionPermitAuthority,
    GraphReversibleActionPermitDispatcher,
    GraphReversibleActionPermitStore,
    MissionEnvelope,
    ReversibleActionPermitInputAuthority,
)
from pajin.supervision.action_compiler import (
    GeneralAttackActionCompilerError,
    GeneralAttackCompiledIntent,
    verify_general_attack_compiled_intent,
)
from pajin.supervision.action_proposal import GeneralAttackActionProposal


class GeneralAttackActionPermitError(RuntimeError):
    """Raised when PERMIT-003 cannot reach the existing atomic Permit boundary."""


@dataclass(frozen=True, slots=True)
class GeneralAttackActionPermitInputs:
    """In-process result supplied by the trusted external input authority.

    The provider, not this value, is the trust root for Envelope provenance, Graph Decision
    actor/provenance, and the fixed-point micro-USD cost. This value deliberately adds no
    persisted authority wire or alternate Permit store.
    """

    envelope: MissionEnvelope
    decision: GraphDecision
    cost_microusd: int


class GeneralAttackActionPermitInputAuthority(Protocol):
    """External authority for the three PERMIT-003 inputs not produced by PERMIT-002.

    Implementations must authenticate a pre-existing run-level MissionEnvelope, authenticate the
    current external Graph Decision including its actor, and derive a trusted fixed-point cost.
    PERMIT-003 independently intersects those outputs with current source, activation, Capability,
    Campaign, budget, and latest-Graph authority.
    """

    def resolve_for_action(
        self,
        *,
        intent: GeneralAttackCompiledIntent,
        prepared: PreparedCapabilityAction,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
        evaluated_at: datetime,
    ) -> GeneralAttackActionPermitInputs: ...


@dataclass(frozen=True, slots=True)
class GeneralAttackReversibleCleanupClaim:
    """Exact pre-action cleanup hold and its mandatory B1 verifier."""

    request: ActionCleanupReservationRequest
    input_authority: ReversibleActionPermitInputAuthority


class GeneralAttackReversibleCleanupAuthority(Protocol):
    """Bind one verified reversible action to its exact cleanup capacity hold."""

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
    ) -> GeneralAttackReversibleCleanupClaim: ...


def _activation_action_policy_registry(
    activation: ExistingModeCapabilityActivation,
) -> ActionApprovalCapabilityPolicyRegistry:
    return ActionApprovalCapabilityPolicyRegistry(
        tuple(
            ActionApprovalCapabilityPolicy(
                capability=binding.action_capability.reference(),
                sideEffectClass=definition.side_effect_class.value,
                approvalRequired=definition.approval_required,
                cleanupRequired=definition.cleanup_required,
            )
            for binding in activation.activation_set.bindings
            for definition in (
                activation.rollout.bundle.definitions.resolve(
                    binding.capability.capability
                ),
            )
        )
    )


@dataclass(frozen=True, slots=True)
class GeneralAttackApprovalClaim:
    """Exact operator approval returned by a deployment-bound provider."""

    envelope: ActionApprovalEnvelope


class GeneralAttackApprovalAuthority(Protocol):
    """Bind one current no-write action to deployment/operator approval authority."""

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
    ) -> GeneralAttackApprovalClaim: ...


@dataclass(frozen=True, slots=True)
class GeneralAttackActionPermitResult[DispatchResultT]:
    """Non-authoritative observation of one exact GRAPH Permit dispatch claim."""

    intent: GeneralAttackCompiledIntent
    prepared: PreparedCapabilityAction
    proposal: ActionProposal
    dispatch: ActionDispatchResult[DispatchResultT]
    cleanup_reservation: ActionCleanupReservation | None = None
    approval_receipt: ActionApprovalConsumptionReceipt | None = None


class GeneralAttackActionPermitGate:
    """Exact-rebuild PERMIT-002 and consume the existing Permit only at callback dispatch."""

    def __init__(
        self,
        *,
        activation: ExistingModeCapabilityActivation,
        permit_store: GraphActionPermitStore,
        inputs: GeneralAttackActionPermitInputAuthority,
        approval: GeneralAttackApprovalAuthority | None = None,
        approval_input_authority: ActionApprovalInputAuthority | None = None,
        approval_issuer: ActionApprovalIssuerAuthorityBinding | None = None,
        reversible_cleanup: GeneralAttackReversibleCleanupAuthority | None = None,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise TypeError("General attack Permit gate requires a verified Capability activation")
        if not callable(getattr(inputs, "resolve_for_action", None)):
            raise TypeError("General attack Permit gate requires an external input authority")
        self._activation = activation
        self._policies = _activation_action_policy_registry(activation)
        self._permit_store = permit_store
        self._inputs = inputs
        if approval is not None and not callable(getattr(approval, "bind_for_action", None)):
            raise TypeError("General attack approval authority must bind an exact approval")
        if approval is None and (
            approval_input_authority is not None or approval_issuer is not None
        ):
            raise TypeError("approval verifier and issuer require an approval provider")
        if approval is not None and (
            approval_input_authority is None or approval_issuer is None
        ):
            raise TypeError(
                "General attack approval requires a deployment-bound verifier and issuer"
            )
        if approval_input_authority is not None and not callable(
            getattr(approval_input_authority, "verify_action_approval", None)
        ):
            raise TypeError("General attack approval verifier is invalid")
        self._approval = approval
        self._approval_input_authority = approval_input_authority
        self._approval_issuer = (
            ActionApprovalIssuerAuthorityBinding.model_validate(
                approval_issuer.model_dump(mode="json", by_alias=True)
            )
            if approval_issuer is not None
            else None
        )
        if reversible_cleanup is not None and not callable(
            getattr(reversible_cleanup, "bind_for_action", None)
        ):
            raise TypeError("General attack reversible cleanup authority must bind an exact hold")
        self._reversible_cleanup = reversible_cleanup
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_ttl = permit_ttl
        self._bound_envelope_digest: str | None = None
        self._bound_activation_set_digest: str | None = None
        self._dispatcher: GraphActionPermitDispatcher | None = None

    async def dispatch_once[DispatchResultT](
        self,
        intent: GeneralAttackCompiledIntent,
        proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        hypothesis_set: AttackHypothesisSet,
        plan: SurfaceBoundPlan,
        task_digest: str,
        action_definition: CapabilityDefinitionRef,
        definitions: CapabilityDefinitionRegistry,
        code_backed_capability: CodeBackedCapabilityRef,
        authorities: CapabilityAuthorityRegistry,
        dispatch: Callable[
            [ActionPermit, PreparedCapabilityAction, ActionProposal],
            Awaitable[DispatchResultT],
        ],
    ) -> GeneralAttackActionPermitResult[DispatchResultT]:
        """Rebuild every predecessor, claim one existing Permit, and call a consumer once."""

        if not _is_async_callable(dispatch):
            raise TypeError("General attack Permit dispatch callback must be async")
        canonical_campaign = self._canonical_campaign(campaign)
        try:
            canonical_intent = verify_general_attack_compiled_intent(
                intent,
                proposal,
                canonical_campaign,
                hypothesis_set,
                plan,
                task_digest,
                action_definition,
                definitions,
                code_backed_capability,
                authorities,
            )
        except GeneralAttackActionCompilerError as exc:
            raise GeneralAttackActionPermitError(
                "General attack Permit source intent verification failed closed"
            ) from exc
        binding = self._current_activation_binding(canonical_intent)
        prepared, definition = self._prepare_current_action(
            binding,
            canonical_intent,
            definitions,
        )
        requires_approval = self._requires_action_approval(definition, prepared)
        evaluated_at = self._evaluated_at()
        inputs, reservation = self._resolve_inputs(
            canonical_intent,
            prepared,
            canonical_campaign,
            definition,
            evaluated_at,
        )
        self._validate_inputs(
            canonical_intent,
            prepared,
            canonical_campaign,
            definition,
            inputs,
            reservation,
            evaluated_at,
        )
        self._revalidate_current_activation(binding, canonical_intent, prepared)
        action_proposal = ActionProposal(
            campaignId=canonical_campaign.metadata.name,
            runId=inputs.envelope.run_id,
            envelopeId=inputs.envelope.envelope_id,
            envelopeDigest=inputs.envelope.envelope_digest,
            decisionId=inputs.decision.decision_id,
            decisionDigest=inputs.decision.decision_digest,
            snapshot=inputs.decision.snapshot,
            proposerId=inputs.decision.actor_id,
            proposerDigest=inputs.decision.actor_digest,
            capability=prepared.capability,
            targetDigest=canonical_intent.target_digest,
            requestId=canonical_intent.request.request_id,
            requestDigest=canonical_intent.request_digest,
            normalizedParametersDigest=canonical_intent.normalized_parameters_digest,
            riskTier=prepared.capability.risk_tier,
            reservation=reservation,
            createdAt=inputs.decision.created_at,
        )

        approval_claim: GeneralAttackApprovalClaim | None = None
        if requires_approval:
            approval_claim = self._bind_action_approval(
                canonical_intent,
                prepared,
                action_proposal,
                canonical_campaign,
                definition,
                inputs,
                evaluated_at,
            )
            self._revalidate_current_activation(binding, canonical_intent, prepared)

        async def consume(permit: ActionPermit) -> DispatchResultT:
            return await dispatch(permit, prepared, action_proposal)

        cleanup_reservation: ActionCleanupReservation | None = None
        approval_receipt: ActionApprovalConsumptionReceipt | None = None
        if definition.side_effect_class.value.endswith("write"):
            if (
                definition.side_effect_class.value != "reversible-write"
                or not definition.cleanup_required
                or self._reversible_cleanup is None
            ):
                raise GeneralAttackActionPermitError(
                    "write action lacks a reversible cleanup hold authority"
                )
            claim = self._bind_reversible_cleanup(
                canonical_intent,
                prepared,
                action_proposal,
                canonical_campaign,
                definition,
                inputs,
                evaluated_at,
            )
            if approval_claim is not None:
                approved_reversible_dispatcher = self._approved_reversible_dispatcher(
                    inputs.envelope,
                    canonical_campaign,
                    self._required_approval_input_authority(),
                    claim.input_authority,
                )

                async def consume_approved_reversible(
                    permit: ActionPermit,
                    receipt: ActionApprovalConsumptionReceipt,
                ) -> DispatchResultT:
                    del receipt
                    return await consume(permit)

                approved_reversible = (
                    await approved_reversible_dispatcher.dispatch_once(
                        inputs.envelope,
                        action_proposal,
                        inputs.decision,
                        approval_claim.envelope,
                        claim.request,
                        consume_approved_reversible,
                    )
                )
                reversible_authorization = (
                    approved_reversible.authorization.reversible
                )
                action = reversible_authorization.action
                cleanup_reservation = reversible_authorization.cleanup_reservation
                approval_receipt = approved_reversible.authorization.receipt
                dispatch_result = ActionDispatchResult(
                    permit=action.permit,
                    dispatched=approved_reversible.dispatched,
                    result=approved_reversible.result,
                )
            else:
                reversible_dispatcher = self._reversible_dispatcher(
                    inputs.envelope,
                    canonical_campaign,
                    claim.input_authority,
                )
                reversible = await reversible_dispatcher.dispatch_once(
                    inputs.envelope,
                    action_proposal,
                    inputs.decision,
                    claim.request,
                    consume,
                )
                action = reversible.authorization.action
                cleanup_reservation = reversible.authorization.cleanup_reservation
                dispatch_result = ActionDispatchResult(
                    permit=action.permit,
                    dispatched=reversible.dispatched,
                    result=reversible.result,
                )
        elif approval_claim is not None:
            approved_dispatcher = self._approved_dispatcher(
                inputs.envelope,
                canonical_campaign,
                self._required_approval_input_authority(),
            )

            async def consume_approved(
                permit: ActionPermit,
                receipt: ActionApprovalConsumptionReceipt,
            ) -> DispatchResultT:
                del receipt
                return await consume(permit)

            approved = await approved_dispatcher.dispatch_once(
                inputs.envelope,
                action_proposal,
                inputs.decision,
                approval_claim.envelope,
                consume_approved,
            )
            action = approved.authorization.action
            approval_receipt = approved.authorization.receipt
            dispatch_result = ActionDispatchResult(
                permit=action.permit,
                dispatched=approved.dispatched,
                result=approved.result,
            )
        else:
            action_dispatcher = self._bound_dispatcher(
                inputs.envelope,
                canonical_campaign,
            )
            dispatch_result = await action_dispatcher.dispatch_once(
                inputs.envelope,
                action_proposal,
                inputs.decision,
                consume,
            )
        return GeneralAttackActionPermitResult(
            intent=canonical_intent,
            prepared=prepared,
            proposal=action_proposal,
            dispatch=dispatch_result,
            cleanup_reservation=cleanup_reservation,
            approval_receipt=approval_receipt,
        )

    def _requires_action_approval(
        self,
        definition: CapabilityDefinition,
        prepared: PreparedCapabilityAction,
    ) -> bool:
        risk = prepared.capability.risk_tier
        if risk >= ToolRiskTier.T3:
            raise GeneralAttackActionPermitError(
                "T3 or higher actions are outside the single-action approval baseline"
            )
        no_write = definition.side_effect_class in {
            CapabilitySideEffectClass.NONE,
            CapabilitySideEffectClass.READ_ONLY,
        }
        if no_write and definition.cleanup_required:
            raise GeneralAttackActionPermitError(
                "no-write action cannot require a cleanup hold"
            )
        required = risk is ToolRiskTier.T2 or definition.approval_required
        if required and self._approval is None:
            raise GeneralAttackActionPermitError(
                "action requires an operator approval authority"
            )
        if required and not no_write and self._reversible_cleanup is None:
            raise GeneralAttackActionPermitError(
                "approved write action requires a cleanup-hold authority"
            )
        return required

    def _bind_action_approval(
        self,
        intent: GeneralAttackCompiledIntent,
        prepared: PreparedCapabilityAction,
        proposal: ActionProposal,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
        inputs: GeneralAttackActionPermitInputs,
        evaluated_at: datetime,
    ) -> GeneralAttackApprovalClaim:
        authority = self._approval
        if authority is None:
            raise GeneralAttackActionPermitError(
                "action requires an operator approval authority"
            )
        try:
            bound = authority.bind_for_action(
                intent=GeneralAttackCompiledIntent.model_validate(
                    intent.model_dump(mode="json", by_alias=True)
                ),
                prepared=PreparedCapabilityAction.model_validate(
                    prepared.model_dump(mode="json", by_alias=True)
                ),
                proposal=ActionProposal.model_validate(
                    proposal.model_dump(mode="json", by_alias=True)
                ),
                campaign=CampaignManifest.model_validate(
                    campaign.model_dump(mode="json", by_alias=True)
                ),
                definition=CapabilityDefinition.model_validate(
                    definition.model_dump(mode="json", by_alias=True)
                ),
                envelope=MissionEnvelope.model_validate(
                    inputs.envelope.model_dump(mode="json", by_alias=True)
                ),
                decision=GraphDecision.model_validate(
                    inputs.decision.model_dump(mode="json", by_alias=True)
                ),
                evaluated_at=evaluated_at,
            )
            if type(bound) is not GeneralAttackApprovalClaim:
                raise TypeError("approval authority returned another claim type")
            approval = ActionApprovalEnvelope.model_validate(
                bound.envelope.model_dump(mode="json", by_alias=True)
            )
            if (
                approval.issuer != self._required_approval_issuer()
                or approval.mission_envelope != inputs.envelope
                or approval.graph_decision != inputs.decision
                or approval.proposal != proposal
                or approval.campaign_digest != campaign_manifest_digest(campaign)
                or approval.source_intent_digest != intent.intent_digest
                or approval.activation_set_digest != prepared.activation_set_digest
                or approval.release.release_id != prepared.release.release_id
                or approval.release.release_digest != prepared.release.release_digest
                or approval.release.capability_id != prepared.capability.capability_id
                or approval.release.capability_version != prepared.capability.capability_version
                or approval.release.capability_digest != prepared.capability.definition_digest
                or approval.side_effect_class != definition.side_effect_class.value
                or approval.cleanup_required != definition.cleanup_required
            ):
                raise GeneralAttackActionPermitError(
                    "operator approval differs from the current exact action"
                )
            return GeneralAttackApprovalClaim(envelope=approval)
        except GeneralAttackActionPermitError:
            raise
        except Exception as exc:
            raise GeneralAttackActionPermitError("operator approval binding failed closed") from exc

    def _required_approval_input_authority(self) -> ActionApprovalInputAuthority:
        authority = self._approval_input_authority
        if authority is None:
            raise GeneralAttackActionPermitError(
                "operator approval verifier is not deployment-bound"
            )
        return authority

    def _required_approval_issuer(self) -> ActionApprovalIssuerAuthorityBinding:
        issuer = self._approval_issuer
        if issuer is None:
            raise GeneralAttackActionPermitError(
                "operator approval issuer is not deployment-bound"
            )
        return issuer

    def _bind_reversible_cleanup(
        self,
        intent: GeneralAttackCompiledIntent,
        prepared: PreparedCapabilityAction,
        proposal: ActionProposal,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
        inputs: GeneralAttackActionPermitInputs,
        evaluated_at: datetime,
    ) -> GeneralAttackReversibleCleanupClaim:
        authority = self._reversible_cleanup
        if authority is None:
            raise GeneralAttackActionPermitError(
                "write action lacks a reversible cleanup hold authority"
            )
        try:
            bound = authority.bind_for_action(
                intent=GeneralAttackCompiledIntent.model_validate(
                    intent.model_dump(mode="json", by_alias=True)
                ),
                prepared=PreparedCapabilityAction.model_validate(
                    prepared.model_dump(mode="json", by_alias=True)
                ),
                proposal=ActionProposal.model_validate(
                    proposal.model_dump(mode="json", by_alias=True)
                ),
                campaign=CampaignManifest.model_validate(
                    campaign.model_dump(mode="json", by_alias=True)
                ),
                definition=CapabilityDefinition.model_validate(
                    definition.model_dump(mode="json", by_alias=True)
                ),
                envelope=MissionEnvelope.model_validate(
                    inputs.envelope.model_dump(mode="json", by_alias=True)
                ),
                decision=GraphDecision.model_validate(
                    inputs.decision.model_dump(mode="json", by_alias=True)
                ),
                evaluated_at=evaluated_at,
            )
            if type(bound) is not GeneralAttackReversibleCleanupClaim:
                raise TypeError("cleanup authority returned another claim type")
            request = ActionCleanupReservationRequest.model_validate(
                bound.request.model_dump(mode="json", by_alias=True)
            )
            if not callable(getattr(bound.input_authority, "verify_reversible_action", None)):
                raise TypeError("cleanup claim lacks its mandatory B1 verifier")
            return GeneralAttackReversibleCleanupClaim(
                request=request,
                input_authority=bound.input_authority,
            )
        except GeneralAttackActionPermitError:
            raise
        except Exception as exc:
            raise GeneralAttackActionPermitError(
                "reversible cleanup hold binding failed closed"
            ) from exc

    def _reversible_dispatcher(
        self,
        envelope: MissionEnvelope,
        campaign: CampaignManifest,
        input_authority: ReversibleActionPermitInputAuthority,
    ) -> GraphReversibleActionPermitDispatcher:
        store = self._permit_store
        if not callable(getattr(store, "authorize_reversible_for_dispatch", None)):
            raise GeneralAttackActionPermitError(
                "GRAPH Permit store lacks atomic reversible cleanup holds"
            )
        authority = GraphReversibleActionPermitAuthority(
            campaign_id=envelope.campaign_id,
            compiler_id=envelope.compiler_id,
            compiler_version=envelope.compiler_version,
            compiler_digest=envelope.compiler_digest,
            capabilities=self._activation.action_registry(),
            policies=self._policies,
            permit_store=cast(GraphReversibleActionPermitStore, store),
            input_authority=input_authority,
            claim_authority=self._reversible_cleanup,
            clock=lambda: self._claim_evaluated_at(campaign, envelope),
            permit_ttl=self._permit_ttl,
        )
        return GraphReversibleActionPermitDispatcher(authority)

    def _approved_dispatcher(
        self,
        envelope: MissionEnvelope,
        campaign: CampaignManifest,
        input_authority: ActionApprovalInputAuthority,
    ) -> GraphApprovedActionPermitDispatcher:
        activation_digest = self._activation.activation_set.activation_set_digest
        if self._bound_envelope_digest is not None and (
            self._bound_envelope_digest != envelope.envelope_digest
            or self._bound_activation_set_digest != activation_digest
        ):
            raise GeneralAttackActionPermitError(
                "General attack Permit gate is pinned to another authority"
            )
        store = self._permit_store
        if not callable(getattr(store, "authorize_approved_for_dispatch", None)):
            raise GeneralAttackActionPermitError(
                "GRAPH Permit store lacks atomic approval consumption"
            )
        authority = GraphApprovedActionPermitAuthority(
            campaign_id=envelope.campaign_id,
            compiler_id=envelope.compiler_id,
            compiler_version=envelope.compiler_version,
            compiler_digest=envelope.compiler_digest,
            capabilities=self._activation.action_registry(),
            policies=self._policies,
            permit_store=cast(GraphApprovedActionPermitStore, store),
            input_authority=input_authority,
            clock=lambda: self._claim_evaluated_at(campaign, envelope),
            permit_ttl=self._permit_ttl,
        )
        self._bound_envelope_digest = envelope.envelope_digest
        self._bound_activation_set_digest = activation_digest
        return GraphApprovedActionPermitDispatcher(authority)

    def _approved_reversible_dispatcher(
        self,
        envelope: MissionEnvelope,
        campaign: CampaignManifest,
        approval_input_authority: ActionApprovalInputAuthority,
        reversible_input_authority: ReversibleActionPermitInputAuthority,
    ) -> GraphApprovedReversibleActionPermitDispatcher:
        activation_digest = self._activation.activation_set.activation_set_digest
        if self._bound_envelope_digest is not None and (
            self._bound_envelope_digest != envelope.envelope_digest
            or self._bound_activation_set_digest != activation_digest
        ):
            raise GeneralAttackActionPermitError(
                "General attack Permit gate is pinned to another authority"
            )
        store = self._permit_store
        if not callable(
            getattr(store, "authorize_approved_reversible_for_dispatch", None)
        ):
            raise GeneralAttackActionPermitError(
                "GRAPH Permit store lacks atomic approval plus cleanup holds"
            )
        authority = GraphApprovedReversibleActionPermitAuthority(
            campaign_id=envelope.campaign_id,
            compiler_id=envelope.compiler_id,
            compiler_version=envelope.compiler_version,
            compiler_digest=envelope.compiler_digest,
            capabilities=self._activation.action_registry(),
            policies=self._policies,
            permit_store=cast(GraphApprovedReversibleActionPermitStore, store),
            approval_input_authority=approval_input_authority,
            reversible_input_authority=reversible_input_authority,
            approval_claim_authority=self._approval,
            cleanup_claim_authority=self._reversible_cleanup,
            clock=lambda: self._claim_evaluated_at(campaign, envelope),
            permit_ttl=self._permit_ttl,
        )
        self._bound_envelope_digest = envelope.envelope_digest
        self._bound_activation_set_digest = activation_digest
        return GraphApprovedReversibleActionPermitDispatcher(authority)

    def _current_activation_binding(
        self,
        intent: GeneralAttackCompiledIntent,
    ) -> ExistingModeCapabilityActivationBinding:
        matches = tuple(
            binding
            for binding in self._activation.activation_set.bindings
            if binding.capability == intent.code_backed_capability
        )
        if len(matches) != 1:
            raise GeneralAttackActionPermitError(
                "current activation does not contain one exact compiled Capability"
            )
        return matches[0]

    def _prepare_current_action(
        self,
        binding: ExistingModeCapabilityActivationBinding,
        intent: GeneralAttackCompiledIntent,
        definitions: CapabilityDefinitionRegistry,
    ) -> tuple[PreparedCapabilityAction, CapabilityDefinition]:
        try:
            resolved = self._activation.resolve_for_dispatch(binding.action_capability.reference())
            prepared = self._activation.prepare_action(
                release=binding.release,
                request=intent.request,
                parameters=intent.request.arguments,
            )
            revalidated = self._activation.resolve_for_dispatch(
                binding.action_capability.reference()
            )
            source_definition = definitions.resolve(intent.source_proposal.action_definition)
            active_definition = self._activation.rollout.bundle.definitions.resolve(
                intent.source_proposal.action_definition
            )
        except (
            CapabilityDefinitionError,
            ExistingModeCapabilityActivationError,
        ) as exc:
            raise GeneralAttackActionPermitError(
                "current signed Capability activation failed closed"
            ) from exc
        if (
            resolved != revalidated
            or resolved.release != binding.release
            or resolved.capability.reference() != intent.code_backed_capability
            or source_definition != active_definition
            or prepared.activation_set_digest
            != self._activation.activation_set.activation_set_digest
            or prepared.release != binding.release
            or prepared.capability != binding.action_capability.reference()
            or prepared.request_digest != intent.request_digest
            or prepared.normalized_parameters_digest != intent.normalized_parameters_digest
            or not self._same_request(prepared, intent)
        ):
            raise GeneralAttackActionPermitError(
                "current Capability preparation differs from the compiled intent"
            )
        return prepared, active_definition

    def _resolve_inputs(
        self,
        intent: GeneralAttackCompiledIntent,
        prepared: PreparedCapabilityAction,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
        evaluated_at: datetime,
    ) -> tuple[GeneralAttackActionPermitInputs, ActionBudgetReservation]:
        try:
            provider_intent = GeneralAttackCompiledIntent.model_validate(
                intent.model_dump(mode="json", by_alias=True)
            )
            provider_prepared = PreparedCapabilityAction.model_validate(
                prepared.model_dump(mode="json", by_alias=True)
            )
            provider_campaign = CampaignManifest.model_validate(
                campaign.model_dump(mode="json", by_alias=True)
            )
            provider_definition = CapabilityDefinition.model_validate(
                definition.model_dump(mode="json", by_alias=True)
            )
            resolved = self._inputs.resolve_for_action(
                intent=provider_intent,
                prepared=provider_prepared,
                campaign=provider_campaign,
                definition=provider_definition,
                evaluated_at=evaluated_at,
            )
            if type(resolved) is not GeneralAttackActionPermitInputs:
                raise TypeError("external input authority returned another result type")
            if type(resolved.cost_microusd) is not int:
                raise TypeError("external cost reservation must be an exact integer")
            canonical = GeneralAttackActionPermitInputs(
                envelope=MissionEnvelope.model_validate(
                    resolved.envelope.model_dump(mode="json", by_alias=True)
                ),
                decision=GraphDecision.model_validate(
                    resolved.decision.model_dump(mode="json", by_alias=True)
                ),
                cost_microusd=resolved.cost_microusd,
            )
            reservation = ActionBudgetReservation(
                requestUnits=definition.request_unit_cost,
                costMicrousd=canonical.cost_microusd,
            )
            return canonical, reservation
        except GeneralAttackActionPermitError:
            raise
        except Exception as exc:
            raise GeneralAttackActionPermitError(
                "external General attack Permit inputs failed closed"
            ) from exc

    def _revalidate_current_activation(
        self,
        binding: ExistingModeCapabilityActivationBinding,
        intent: GeneralAttackCompiledIntent,
        prepared: PreparedCapabilityAction,
    ) -> None:
        try:
            resolved = self._activation.resolve_for_dispatch(binding.action_capability.reference())
        except ExistingModeCapabilityActivationError as exc:
            raise GeneralAttackActionPermitError(
                "current signed Capability activation changed before Permit claim"
            ) from exc
        if (
            resolved.release != binding.release
            or resolved.capability.reference() != intent.code_backed_capability
            or prepared.activation_set_digest
            != self._activation.activation_set.activation_set_digest
            or prepared.release != binding.release
            or prepared.capability != binding.action_capability.reference()
        ):
            raise GeneralAttackActionPermitError(
                "current signed Capability activation changed before Permit claim"
            )

    def _validate_campaign_ceiling(
        self,
        campaign: CampaignManifest,
        envelope: MissionEnvelope,
        *,
        evaluated_at: datetime,
    ) -> None:
        authorization = campaign.spec.authorization
        budgets = campaign.spec.budgets
        rules = campaign.spec.rules_of_engagement
        campaign_cost_microusd = int(
            (Decimal(str(budgets.max_cost_usd)) * Decimal(1_000_000)).to_integral_value(
                rounding=ROUND_FLOOR
            )
        )
        if (
            not authorization.is_active(evaluated_at)
            or envelope.authorized_at < authorization.approved_at
            or envelope.not_before < authorization.approved_at
            or envelope.expires_at > authorization.expires_at
            or envelope.expires_at
            > envelope.not_before + timedelta(seconds=budgets.duration_seconds)
        ):
            raise GeneralAttackActionPermitError(
                "MissionEnvelope exceeds the current Campaign authorization timeline"
            )
        windows = rules.testing_windows
        if windows and not any(window.is_active(evaluated_at) for window in windows):
            raise GeneralAttackActionPermitError(
                "current Campaign testing window does not allow a Permit claim"
            )
        if (
            envelope.autonomy != campaign.spec.autonomy
            or envelope.max_risk_tier > rules.max_tool_risk_tier
            or envelope.budget.tool_call_limit > budgets.max_tool_calls
            or envelope.budget.cost_limit_microusd > campaign_cost_microusd
        ):
            raise GeneralAttackActionPermitError(
                "MissionEnvelope expands the current Campaign authority ceiling"
            )
        requests_per_minute = rules.max_requests_per_minute
        if requests_per_minute is not None and (
            envelope.budget.rolling_window_seconds != 60
            or envelope.budget.rolling_request_unit_limit is None
            or envelope.budget.rolling_request_unit_limit > requests_per_minute
        ):
            raise GeneralAttackActionPermitError(
                "MissionEnvelope expands the current Campaign rolling-rate ceiling"
            )

    def _validate_inputs(
        self,
        intent: GeneralAttackCompiledIntent,
        prepared: PreparedCapabilityAction,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
        inputs: GeneralAttackActionPermitInputs,
        reservation: ActionBudgetReservation,
        evaluated_at: datetime,
    ) -> None:
        envelope = inputs.envelope
        decision = inputs.decision
        if (
            envelope.campaign_id != campaign.metadata.name
            or envelope.source_campaign_digest != campaign_manifest_digest(campaign)
        ):
            raise GeneralAttackActionPermitError(
                "MissionEnvelope differs from the exact current Campaign"
            )
        self._validate_campaign_ceiling(
            campaign,
            envelope,
            evaluated_at=evaluated_at,
        )
        if (
            prepared.capability not in envelope.allowed_capabilities
            or intent.target_digest not in envelope.allowed_target_digests
            or prepared.capability.risk_tier > envelope.max_risk_tier
        ):
            raise GeneralAttackActionPermitError(
                "compiled action exceeds the MissionEnvelope authority ceiling"
            )
        if not envelope.not_before <= evaluated_at < envelope.expires_at:
            raise GeneralAttackActionPermitError("MissionEnvelope is not currently active")
        if (
            decision.campaign_id != campaign.metadata.name
            or decision.snapshot.campaign_id != campaign.metadata.name
            or decision.decision_kind is not GraphDecisionKind.ACTION_PROPOSAL
            or decision.decision_payload_digest != intent.intent_digest
            or not envelope.not_before <= decision.created_at <= evaluated_at
        ):
            raise GeneralAttackActionPermitError(
                "Graph Decision does not authorize the exact compiled action"
            )
        if reservation.request_units != definition.request_unit_cost:
            raise GeneralAttackActionPermitError(
                "trusted reservation differs from current Capability request-unit cost"
            )
        if (
            reservation.tool_calls > envelope.budget.tool_call_limit
            or reservation.request_units > envelope.budget.request_unit_limit
            or reservation.cost_microusd > envelope.budget.cost_limit_microusd
        ):
            raise GeneralAttackActionPermitError(
                "trusted reservation exceeds the MissionEnvelope budget"
            )

    def _bound_dispatcher(
        self,
        envelope: MissionEnvelope,
        campaign: CampaignManifest,
    ) -> GraphActionPermitDispatcher:
        activation_digest = self._activation.activation_set.activation_set_digest
        if self._dispatcher is not None:
            if (
                self._bound_envelope_digest != envelope.envelope_digest
                or self._bound_activation_set_digest != activation_digest
            ):
                raise GeneralAttackActionPermitError(
                    "General attack Permit gate is pinned to another authority"
                )
            return self._dispatcher
        authority = GraphActionPermitAuthority(
            campaign_id=envelope.campaign_id,
            compiler_id=envelope.compiler_id,
            compiler_version=envelope.compiler_version,
            compiler_digest=envelope.compiler_digest,
            capabilities=self._activation.action_registry(),
            policies=self._policies,
            permit_store=self._permit_store,
            clock=lambda: self._claim_evaluated_at(campaign, envelope),
            permit_ttl=self._permit_ttl,
        )
        self._dispatcher = GraphActionPermitDispatcher(authority)
        self._bound_envelope_digest = envelope.envelope_digest
        self._bound_activation_set_digest = activation_digest
        return self._dispatcher

    def _claim_evaluated_at(
        self,
        campaign: CampaignManifest,
        envelope: MissionEnvelope,
    ) -> datetime:
        evaluated_at = self._evaluated_at()
        self._validate_campaign_ceiling(
            campaign,
            envelope,
            evaluated_at=evaluated_at,
        )
        return evaluated_at

    def _evaluated_at(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise GeneralAttackActionPermitError("General attack Permit gate clock failed") from exc
        if value.tzinfo is None or value.utcoffset() is None:
            raise GeneralAttackActionPermitError(
                "General attack Permit gate clock requires a UTC offset or Z"
            )
        return value.astimezone(UTC)

    @staticmethod
    def _canonical_campaign(campaign: CampaignManifest) -> CampaignManifest:
        try:
            return CampaignManifest.model_validate(campaign.model_dump(mode="json", by_alias=True))
        except (AttributeError, ValidationError, ValueError) as exc:
            raise GeneralAttackActionPermitError(
                "General attack Permit Campaign is not canonical"
            ) from exc

    @staticmethod
    def _same_request(
        prepared: PreparedCapabilityAction,
        intent: GeneralAttackCompiledIntent,
    ) -> bool:
        try:
            return canonical_json_bytes(
                prepared.request.model_dump(mode="json", by_alias=True),
                label="Prepared General attack Tool Request",
            ) == canonical_json_bytes(
                intent.request.model_dump(mode="json", by_alias=True),
                label="Compiled General attack Tool Request",
            )
        except (AttributeError, TypeError, UnicodeError, ValueError) as exc:
            raise GeneralAttackActionPermitError(
                "General attack Tool Request comparison failed closed"
            ) from exc


def _is_async_callable(value: object) -> bool:
    if iscoroutinefunction(value):
        return True
    if not callable(value):
        return False
    return iscoroutinefunction(value.__call__)
