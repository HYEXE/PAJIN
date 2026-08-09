"""SUP-007A opt-in composition for one bounded General Attack execution."""

from __future__ import annotations

import os
import re
from collections.abc import Awaitable, Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from pydantic import ValidationError

from pajin.capabilities import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CapabilityAuthorityRegistry,
    CapabilityDefinition,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilityGraphRunAuditAnchor,
    CapabilitySideEffectClass,
    CodeBackedCapabilityRef,
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityGatewayDispatcher,
    PreparedCapabilityAction,
)
from pajin.discovery.hypothesis import AttackHypothesisSet, SurfaceBoundPlan
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph import (
    ActionApprovalInputAuthority,
    ActionApprovalIssuerAuthorityBinding,
    ActionDispatchResult,
    ActionPermit,
    ActionProposal,
    GraphActionPermitStore,
    GraphDecision,
    GraphDecisionKind,
    MissionEnvelope,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_events
from pajin.runtime.worker import WorkerBackend
from pajin.supervision.action_compiler import GeneralAttackCompiledIntent
from pajin.supervision.action_outcome import (
    GeneralAttackActionOutcomeAssessment,
    GeneralAttackActionOutcomeError,
    GeneralAttackActionOutcomeGate,
    GeneralAttackActionOutcomeInputs,
)
from pajin.supervision.action_permit import (
    GeneralAttackActionPermitError,
    GeneralAttackActionPermitGate,
    GeneralAttackActionPermitInputAuthority,
    GeneralAttackActionPermitInputs,
    GeneralAttackActionPermitResult,
    GeneralAttackApprovalAuthority,
)
from pajin.supervision.action_proposal import GeneralAttackActionProposal
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, RequestRateLimitLedger, ToolGateway


class GeneralAttackActionExecutionError(RuntimeError):
    """Raised when the SUP-007A product composition fails closed."""


@dataclass(frozen=True, slots=True)
class GeneralAttackActionExecutionInputs:
    """Deployment-authenticated runtime inputs resolved before Permit consumption."""

    envelope: MissionEnvelope
    decision: GraphDecision
    grant: CapabilityGrant
    used_calls: int


class GeneralAttackActionExecutionInputAuthority(Protocol):
    """Resolve the exact Envelope, Decision, Grant, and call count for one opt-in action."""

    def resolve_for_execution(
        self,
        *,
        intent: GeneralAttackCompiledIntent,
        proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        evaluated_at: datetime,
    ) -> GeneralAttackActionExecutionInputs: ...


@dataclass(frozen=True, slots=True)
class GeneralAttackActionExecutionResult:
    """Existing Permit and outcome projections returned by one first dispatch."""

    permit: GeneralAttackActionPermitResult[GatewayOutcome]
    outcome: GeneralAttackActionOutcomeAssessment


@dataclass(frozen=True, slots=True)
class _ConsumedPermitDispatcher:
    """Adapt only one already-consumed exact Permit to the existing Gateway dispatcher."""

    permit: ActionPermit

    async def dispatch_once[DispatchResultT](
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        dispatch: Callable[[ActionPermit], Awaitable[DispatchResultT]],
    ) -> ActionDispatchResult[DispatchResultT]:
        if (
            self.permit.campaign_id != envelope.campaign_id
            or self.permit.run_id != envelope.run_id
            or self.permit.envelope_id != envelope.envelope_id
            or self.permit.envelope_digest != envelope.envelope_digest
            or self.permit.proposal_id != proposal.proposal_id
            or self.permit.proposal_digest != proposal.proposal_digest
            or self.permit.decision_id != decision.decision_id
            or self.permit.decision_digest != decision.decision_digest
            or self.permit.snapshot != decision.snapshot
        ):
            raise GeneralAttackActionExecutionError(
                "Consumed General attack Permit differs from the managed Gateway authority"
            )
        return ActionDispatchResult(
            permit=self.permit,
            dispatched=True,
            result=await dispatch(self.permit),
        )


@dataclass(frozen=True, slots=True)
class _BoundOutcomeInputAuthority:
    permit: ActionPermit
    prepared: PreparedCapabilityAction
    campaign: CampaignManifest
    definition: CapabilityDefinition
    inputs: GeneralAttackActionOutcomeInputs

    def resolve_for_outcome(
        self,
        *,
        permit: ActionPermit,
        prepared: PreparedCapabilityAction,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
    ) -> GeneralAttackActionOutcomeInputs:
        if (
            permit != self.permit
            or prepared != self.prepared
            or campaign != self.campaign
            or definition != self.definition
        ):
            raise GeneralAttackActionExecutionError(
                "General attack outcome inputs differ from the managed dispatch"
            )
        return GeneralAttackActionOutcomeInputs(
            run_path=self.inputs.run_path,
            run_anchor=self.inputs.run_anchor.model_copy(deep=True),
            grant=self.inputs.grant.model_copy(deep=True),
        )


@dataclass(frozen=True, slots=True)
class _BoundPermitInputAuthority:
    authority: GeneralAttackActionPermitInputAuthority
    expected: GeneralAttackActionExecutionInputs

    def resolve_for_action(
        self,
        *,
        intent: GeneralAttackCompiledIntent,
        prepared: PreparedCapabilityAction,
        campaign: CampaignManifest,
        definition: CapabilityDefinition,
        evaluated_at: datetime,
    ) -> GeneralAttackActionPermitInputs:
        resolved = self.authority.resolve_for_action(
            intent=intent,
            prepared=prepared,
            campaign=campaign,
            definition=definition,
            evaluated_at=evaluated_at,
        )
        if (
            type(resolved) is not GeneralAttackActionPermitInputs
            or resolved.envelope != self.expected.envelope
            or resolved.decision != self.expected.decision
        ):
            raise GeneralAttackActionPermitError(
                "General attack Permit inputs differ from pre-resolved execution authority"
            )
        return resolved


class GeneralAttackActionExecutionGate:
    """Compose existing Permit, Gateway, Run audit, and outcome authorities for T0/T1."""

    def __init__(
        self,
        *,
        deployment_id: str,
        run_root: Path,
        activation: ExistingModeCapabilityActivation,
        permit_store: GraphActionPermitStore,
        permit_inputs: GeneralAttackActionPermitInputAuthority,
        execution_inputs: GeneralAttackActionExecutionInputAuthority,
        tools: ToolRegistry,
        worker: WorkerBackend,
        policy: PolicyEngine | None = None,
        secrets: SecretBroker | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
        approval: GeneralAttackApprovalAuthority | None = None,
        approval_input_authority: ActionApprovalInputAuthority | None = None,
        approval_issuer: ActionApprovalIssuerAuthorityBinding | None = None,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if (
            not isinstance(deployment_id, str)
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}", deployment_id) is None
        ):
            raise TypeError("General attack execution deployment ID is invalid")
        if not isinstance(activation, ExistingModeCapabilityActivation):
            raise TypeError("General attack execution requires a verified Capability activation")
        if not callable(getattr(permit_inputs, "resolve_for_action", None)):
            raise TypeError("General attack execution requires an external Permit input authority")
        if not callable(getattr(execution_inputs, "resolve_for_execution", None)):
            raise TypeError("General attack execution requires an external runtime input authority")
        if not isinstance(tools, ToolRegistry):
            raise TypeError("General attack execution requires a deployment-owned Tool registry")
        if not callable(getattr(worker, "run", None)):
            raise TypeError("General attack execution requires a Worker backend")
        if policy is not None and not isinstance(policy, PolicyEngine):
            raise TypeError("General attack execution Policy engine is invalid")
        if approval is not None and not callable(getattr(approval, "bind_for_action", None)):
            raise TypeError("General attack execution approval authority is invalid")
        if approval is None and (
            approval_input_authority is not None or approval_issuer is not None
        ):
            raise TypeError("General attack execution approval verifier requires a provider")
        if approval is not None and (approval_input_authority is None or approval_issuer is None):
            raise TypeError("General attack execution approval authority is incomplete")
        if approval_input_authority is not None and not callable(
            getattr(approval_input_authority, "verify_action_approval", None)
        ):
            raise TypeError("General attack execution approval verifier is invalid")
        selected_root = Path(run_root)
        if not selected_root.is_absolute():
            raise TypeError("General attack execution Run root must be absolute")
        selected_root = Path(os.path.abspath(selected_root))
        self._deployment_id = deployment_id
        self._run_root = selected_root
        self._activation = activation
        self._permit_store = permit_store
        self._permit_inputs = permit_inputs
        self._execution_inputs = execution_inputs
        self._tools = tools
        self._worker = worker
        self._policy = policy or PolicyEngine()
        self._secrets = secrets
        self._rate_limits = rate_limits
        self._clock = clock or (lambda: datetime.now(UTC))
        self._approval = approval
        self._approval_input_authority = approval_input_authority
        self._approval_issuer = (
            ActionApprovalIssuerAuthorityBinding.model_validate(
                approval_issuer.model_dump(mode="json", by_alias=True)
            )
            if approval_issuer is not None
            else None
        )
        self._permit_ttl = permit_ttl

    async def execute_once(
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
    ) -> GeneralAttackActionExecutionResult:
        """Execute and authenticate one explicit T0/T1 no-write General Attack action."""

        canonical_intent, canonical_proposal, canonical_campaign = self._canonical_sources(
            intent,
            proposal,
            campaign,
        )
        self._require_t0_t1_no_write(canonical_intent, canonical_proposal)
        evaluated_at = self._evaluated_at()
        runtime_inputs = self._resolve_execution_inputs(
            canonical_intent,
            canonical_proposal,
            canonical_campaign,
            evaluated_at,
        )
        self._validate_preclaim_inputs(
            canonical_intent,
            canonical_campaign,
            runtime_inputs,
            evaluated_at,
        )
        store, anchor = self._open_managed_run(canonical_campaign, runtime_inputs.envelope)
        gateway = ToolGateway(
            policy=self._policy,
            tools=self._tools,
            worker=self._worker,
            store=store,
            secrets=self._secrets,
            rate_limits=self._rate_limits,
            allow_secret_requests=self._secrets is not None,
            clock=self._clock,
        )
        dispatched_prepared: PreparedCapabilityAction | None = None

        async def dispatch(
            permit: ActionPermit,
            prepared: PreparedCapabilityAction,
            graph_proposal: ActionProposal,
        ) -> GatewayOutcome:
            nonlocal dispatched_prepared
            self._validate_consumed_authority(
                permit,
                prepared,
                graph_proposal,
                runtime_inputs,
            )
            dispatched_prepared = prepared
            dispatcher = ExistingModeCapabilityGatewayDispatcher(
                activation=self._activation,
                permits=_ConsumedPermitDispatcher(permit),
                gateway=gateway,
                audit_store=store,
                clock=self._clock,
            )
            try:
                result = await dispatcher.dispatch_once(
                    runtime_inputs.envelope,
                    graph_proposal,
                    runtime_inputs.decision,
                    prepared,
                    campaign=canonical_campaign,
                    grant=runtime_inputs.grant,
                    used_calls=runtime_inputs.used_calls,
                )
            except BaseException:
                with suppress(OSError, RunIntegrityError, ValueError):
                    store.seal()
                raise
            try:
                store.seal()
            except (OSError, RunIntegrityError, ValueError) as exc:
                raise GeneralAttackActionExecutionError(
                    "General attack Gateway audit could not be sealed"
                ) from exc
            if result.result is None:
                raise GeneralAttackActionExecutionError(
                    "General attack Gateway dispatch returned no outcome"
                )
            return result.result

        try:
            permit_result = await self._permit_gate(runtime_inputs).dispatch_once(
                canonical_intent,
                canonical_proposal,
                canonical_campaign,
                hypothesis_set,
                plan,
                task_digest,
                action_definition,
                definitions,
                code_backed_capability,
                authorities,
                dispatch,
            )
        except GeneralAttackActionExecutionError:
            raise
        except GeneralAttackActionPermitError as exc:
            raise GeneralAttackActionExecutionError(
                "General attack execution Permit path failed closed"
            ) from exc
        if (
            not permit_result.dispatch.dispatched
            or permit_result.dispatch.result is None
            or dispatched_prepared is None
        ):
            raise GeneralAttackActionExecutionError(
                "General attack execution was already consumed; automatic redispatch is prohibited"
            )
        definition = definitions.resolve(code_backed_capability.capability)
        outcome_inputs = GeneralAttackActionOutcomeInputs(
            run_path=store.path,
            run_anchor=anchor,
            grant=runtime_inputs.grant,
        )
        outcome_gate = GeneralAttackActionOutcomeGate(
            activation=self._activation,
            permit_store=self._permit_store,
            inputs=_BoundOutcomeInputAuthority(
                permit=permit_result.dispatch.permit,
                prepared=dispatched_prepared,
                campaign=canonical_campaign,
                definition=definition,
                inputs=outcome_inputs,
            ),
        )
        try:
            outcome = outcome_gate.assess(
                permit_result,
                canonical_proposal,
                canonical_campaign,
                hypothesis_set,
                plan,
                task_digest,
                action_definition,
                definitions,
                code_backed_capability,
                authorities,
            )
        except GeneralAttackActionOutcomeError as exc:
            raise GeneralAttackActionExecutionError(
                "General attack execution outcome failed closed"
            ) from exc
        return GeneralAttackActionExecutionResult(
            permit=permit_result,
            outcome=outcome,
        )

    def _permit_gate(
        self,
        runtime_inputs: GeneralAttackActionExecutionInputs,
    ) -> GeneralAttackActionPermitGate:
        return GeneralAttackActionPermitGate(
            activation=self._activation,
            permit_store=self._permit_store,
            inputs=_BoundPermitInputAuthority(
                authority=self._permit_inputs,
                expected=runtime_inputs,
            ),
            approval=self._approval,
            approval_input_authority=self._approval_input_authority,
            approval_issuer=self._approval_issuer,
            clock=self._clock,
            permit_ttl=self._permit_ttl,
        )

    @staticmethod
    def _canonical_sources(
        intent: GeneralAttackCompiledIntent,
        proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
    ) -> tuple[GeneralAttackCompiledIntent, GeneralAttackActionProposal, CampaignManifest]:
        try:
            return (
                GeneralAttackCompiledIntent.model_validate(
                    intent.model_dump(mode="json", by_alias=True)
                ),
                GeneralAttackActionProposal.model_validate(
                    proposal.model_dump(mode="json", by_alias=True)
                ),
                CampaignManifest.model_validate(campaign.model_dump(mode="json", by_alias=True)),
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise GeneralAttackActionExecutionError(
                "General attack execution source is not canonical"
            ) from exc

    @staticmethod
    def _require_t0_t1_no_write(
        intent: GeneralAttackCompiledIntent,
        proposal: GeneralAttackActionProposal,
    ) -> None:
        cleanup = proposal.cleanup
        if intent.source_proposal != proposal:
            raise GeneralAttackActionExecutionError(
                "General attack execution intent differs from its source proposal"
            )
        if proposal.risk_tier > ToolRiskTier.T1:
            raise GeneralAttackActionExecutionError(
                "General attack opt-in execution is restricted to T0/T1"
            )
        if (
            cleanup.side_effect_class
            not in {CapabilitySideEffectClass.NONE, CapabilitySideEffectClass.READ_ONLY}
            or cleanup.cleanup_required
        ):
            raise GeneralAttackActionExecutionError(
                "General attack opt-in execution is restricted to no-write actions"
            )

    def _resolve_execution_inputs(
        self,
        intent: GeneralAttackCompiledIntent,
        proposal: GeneralAttackActionProposal,
        campaign: CampaignManifest,
        evaluated_at: datetime,
    ) -> GeneralAttackActionExecutionInputs:
        try:
            resolved = self._execution_inputs.resolve_for_execution(
                intent=intent.model_copy(deep=True),
                proposal=proposal.model_copy(deep=True),
                campaign=campaign.model_copy(deep=True),
                evaluated_at=evaluated_at,
            )
            if type(resolved) is not GeneralAttackActionExecutionInputs:
                raise TypeError("execution input authority returned another result type")
            if type(resolved.used_calls) is not int or resolved.used_calls < 0:
                raise TypeError("execution input authority returned an invalid used-call count")
            return GeneralAttackActionExecutionInputs(
                envelope=MissionEnvelope.model_validate(
                    resolved.envelope.model_dump(mode="json", by_alias=True)
                ),
                decision=GraphDecision.model_validate(
                    resolved.decision.model_dump(mode="json", by_alias=True)
                ),
                grant=CapabilityGrant.model_validate(
                    resolved.grant.model_dump(mode="json", by_alias=True)
                ),
                used_calls=resolved.used_calls,
            )
        except GeneralAttackActionExecutionError:
            raise
        except Exception as exc:
            raise GeneralAttackActionExecutionError(
                "General attack execution inputs failed closed"
            ) from exc

    def _validate_preclaim_inputs(
        self,
        intent: GeneralAttackCompiledIntent,
        campaign: CampaignManifest,
        inputs: GeneralAttackActionExecutionInputs,
        evaluated_at: datetime,
    ) -> None:
        envelope = inputs.envelope
        decision = inputs.decision
        grant = inputs.grant
        request = intent.request
        bindings = tuple(
            item
            for item in self._activation.activation_set.bindings
            if item.capability == intent.code_backed_capability
        )
        if len(bindings) != 1:
            raise GeneralAttackActionExecutionError(
                "General attack execution Capability is not uniquely activated"
            )
        capability = bindings[0].action_capability.reference()
        if (
            envelope.campaign_id != campaign.metadata.name
            or envelope.source_campaign_digest != campaign_manifest_digest(campaign)
            or capability not in envelope.allowed_capabilities
            or intent.target_digest not in envelope.allowed_target_digests
            or envelope.max_risk_tier < intent.source_proposal.risk_tier
            or not envelope.not_before <= evaluated_at < envelope.expires_at
        ):
            raise GeneralAttackActionExecutionError(
                "General attack execution Envelope differs from source authority"
            )
        if (
            decision.campaign_id != campaign.metadata.name
            or decision.decision_kind is not GraphDecisionKind.ACTION_PROPOSAL
            or decision.decision_payload_digest != intent.intent_digest
        ):
            raise GeneralAttackActionExecutionError(
                "General attack execution Decision differs from source authority"
            )
        if (
            grant.campaign != campaign.metadata.name
            or grant.subject != request.agent_id
            or request.tool_id not in grant.tools
            or request.target not in grant.targets
            or grant.max_risk_tier < intent.source_proposal.risk_tier
            or inputs.used_calls >= grant.max_calls
            or not grant.issued_at <= evaluated_at < grant.expires_at
        ):
            raise GeneralAttackActionExecutionError(
                "General attack execution Grant differs from source authority"
            )

    def _open_managed_run(
        self,
        campaign: CampaignManifest,
        envelope: MissionEnvelope,
    ) -> tuple[RunStore, CapabilityGraphRunAuditAnchor]:
        if re.fullmatch(r"run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}", envelope.run_id) is None:
            raise GeneralAttackActionExecutionError(
                "General attack managed Run ID is not generated by RunStore"
            )
        campaign_path = self._run_root / campaign.metadata.name
        run_path = campaign_path / envelope.run_id
        for path in (self._run_root, campaign_path, run_path):
            if path.is_symlink() or path.is_junction():
                raise GeneralAttackActionExecutionError(
                    "General attack managed Run path cannot contain a link boundary"
                )
        try:
            if run_path.exists():
                store = RunStore(envelope.run_id, run_path)
            else:
                try:
                    store = RunStore.create(
                        self._run_root,
                        campaign.metadata.name,
                        run_id=envelope.run_id,
                    )
                except FileExistsError as exc:
                    for path in (self._run_root, campaign_path, run_path):
                        if path.is_symlink() or path.is_junction():
                            raise GeneralAttackActionExecutionError(
                                "General attack managed Run path changed to a link boundary"
                            ) from exc
                    store = RunStore(envelope.run_id, run_path)
            anchor = CapabilityGraphRunAuditAnchor(
                deploymentId=self._deployment_id,
                campaignId=campaign.metadata.name,
                campaignDigest=campaign_manifest_digest(campaign),
                runId=envelope.run_id,
                envelopeId=envelope.envelope_id,
                envelopeDigest=envelope.envelope_digest,
                releaseSetDigest=self._activation.activation_set.release_set_digest,
                activationSetDigest=self._activation.activation_set.activation_set_digest,
                compilerId=envelope.compiler_id,
                compilerVersion=envelope.compiler_version,
                compilerDigest=envelope.compiler_digest,
            )
            store.append_unique_event(
                CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
                anchor.model_dump(mode="json", by_alias=True),
                occurred_at=self._evaluated_at(),
            )
            with suppress(RunIntegrityError):
                store.seal()
            events = load_verified_run_events(store.path, expected_run_id=store.run_id)
        except GeneralAttackActionExecutionError:
            raise
        except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
            raise GeneralAttackActionExecutionError(
                "General attack managed Run anchor failed verification"
            ) from exc
        anchors = tuple(
            event
            for event in events
            if event.event_type == CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE
        )
        if (
            len(anchors) != 1
            or not events
            or events[0] != anchors[0]
            or anchors[0].payload != anchor.model_dump(mode="json", by_alias=True)
        ):
            raise GeneralAttackActionExecutionError(
                "General attack managed Run anchor differs from deployment"
            )
        return store, anchor

    @staticmethod
    def _validate_consumed_authority(
        permit: ActionPermit,
        prepared: PreparedCapabilityAction,
        proposal: ActionProposal,
        inputs: GeneralAttackActionExecutionInputs,
    ) -> None:
        if prepared.capability.risk_tier > ToolRiskTier.T1:
            raise GeneralAttackActionExecutionError(
                "Consumed General attack action exceeds the T0/T1 product ceiling"
            )
        if (
            permit.campaign_id != inputs.envelope.campaign_id
            or permit.run_id != inputs.envelope.run_id
            or permit.envelope_id != inputs.envelope.envelope_id
            or permit.envelope_digest != inputs.envelope.envelope_digest
            or permit.decision_id != inputs.decision.decision_id
            or permit.decision_digest != inputs.decision.decision_digest
            or permit.snapshot != inputs.decision.snapshot
            or permit.proposal_id != proposal.proposal_id
            or permit.proposal_digest != proposal.proposal_digest
            or permit.capability != prepared.capability
            or permit.request_id != prepared.request.request_id
        ):
            raise GeneralAttackActionExecutionError(
                "Consumed General attack authority differs from pre-resolved execution inputs"
            )

    def _evaluated_at(self) -> datetime:
        try:
            value = self._clock()
        except Exception as exc:
            raise GeneralAttackActionExecutionError(
                "General attack execution clock failed"
            ) from exc
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise GeneralAttackActionExecutionError(
                "General attack execution clock must return an aware datetime"
            )
        return value.astimezone(UTC)
