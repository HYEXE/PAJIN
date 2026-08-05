from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.capabilities import (
    CapabilityUseProfile,
    ExistingModeCapabilityActivation,
    ExistingModeCapabilityActivationError,
    activate_existing_mode_capabilities,
    admit_existing_mode_capability_releases,
)
from pajin.domain.models import AutonomyLevel, CampaignManifest, campaign_manifest_digest
from pajin.graph import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionPermit,
    ActionPermitStaleDecision,
    GraphAdmissionAuthority,
    GraphContentOrigin,
    GraphDecision,
    GraphDecisionKind,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProposalKind,
    GraphProposalLineage,
    MissionEnvelope,
    SQLiteGraphStore,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
)
from pajin.supervision import (
    GeneralAttackActionPermitError,
    GeneralAttackActionPermitGate,
    GeneralAttackActionPermitInputs,
    GeneralAttackCompiledIntent,
    compile_general_attack_action_intent,
)
from tests.test_existing_capability_rollout import (
    NOW as RELEASE_NOW,
)
from tests.test_existing_capability_rollout import (
    _release_for,
    _rollout_inputs,
    _seed_worker_graph,
)
from tests.test_general_attack_action_proposal import NOW as SOURCE_NOW
from tests.test_general_attack_action_proposal import _proposal

_CAPABILITY_ID = "pajin.ai.kisa.indirect-tool-hijacking"
_ARGUMENTS = {"simulation": {"unauthorizedToolCall": True}}
_GATE_NOW = SOURCE_NOW + timedelta(minutes=30)


class _StaticPermitInputAuthority:
    def __init__(self, value: GeneralAttackActionPermitInputs) -> None:
        self.value = value
        self.calls = 0

    def resolve_for_action(self, **kwargs) -> GeneralAttackActionPermitInputs:
        del kwargs
        self.calls += 1
        return self.value


@dataclass(frozen=True, slots=True)
class _PermitContext:
    campaign: CampaignManifest
    intent: GeneralAttackCompiledIntent
    source_proposal: object
    hypotheses: object
    plan: object
    task: object
    definition: object
    definitions: object
    code_backed: object
    authorities: object
    activation: ExistingModeCapabilityActivation
    graph: SQLiteGraphStore
    envelope: MissionEnvelope
    decision: GraphDecision
    reservation: ActionBudgetReservation


@pytest.fixture
def permit_context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> _PermitContext:
    bundle, policy, keys, releases = _rollout_inputs()
    rollout = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=keys,
        releases=releases,
        clock=lambda: RELEASE_NOW,
    )
    release = _release_for(rollout, _CAPABILITY_ID)
    activation = activate_existing_mode_capabilities(
        rollout=rollout,
        releases=(release,),
        profile=CapabilityUseProfile.RANGE,
    )
    binding = activation.activation_set.bindings[0]
    definition = bundle.definitions.resolve(binding.capability.capability)
    source_proposal, hypotheses, plan, task, _, _ = _proposal(
        sample_campaign,
        definition=definition,
        arguments=_ARGUMENTS,
    )
    intent = compile_general_attack_action_intent(
        source_proposal,
        sample_campaign,
        hypotheses,
        plan,
        task.task_digest,
        definition.reference(),
        bundle.definitions,
        binding.capability,
        bundle.authorities,
    )
    prepared = activation.prepare_action(
        release=release,
        request=intent.request,
        parameters=intent.request.arguments,
    )
    run_id = "general-attack-permit-run"
    graph, seeded_decision = _seed_worker_graph(
        tmp_path / "graph" / "canonical.sqlite3",
        campaign=sample_campaign,
        graph_run_id=run_id,
        request=intent.request,
    )
    decision = GraphDecision(
        campaignId=sample_campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=intent.intent_digest,
        snapshot=seeded_decision.snapshot,
        actorId="pajin.graph.general-attack-planner",
        actorDigest="c" * 64,
        createdAt=_GATE_NOW - timedelta(minutes=1),
    )
    envelope = MissionEnvelope(
        campaignId=sample_campaign.metadata.name,
        runId=run_id,
        profileId="general-attack-range",
        profileVersion="1.0.0",
        profileDigest="e" * 64,
        compilerId="pajin.general-attack.envelope-compiler",
        compilerVersion="1.0.0",
        compilerDigest="d" * 64,
        sourceCampaignDigest=campaign_manifest_digest(sample_campaign),
        allowedCapabilities=(prepared.capability,),
        allowedTargetDigests=(
            sha256(intent.request.target.encode("utf-8", errors="strict")).hexdigest(),
        ),
        maxRiskTier=prepared.capability.risk_tier,
        budget=ActionBudgetLimit(
            toolCallLimit=2,
            requestUnitLimit=10,
            costLimitMicrousd=0,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=_GATE_NOW - timedelta(minutes=10),
        notBefore=_GATE_NOW - timedelta(minutes=5),
        expiresAt=_GATE_NOW + timedelta(minutes=5),
    )
    reservation = ActionBudgetReservation(
        requestUnits=definition.request_unit_cost,
        costMicrousd=0,
    )
    return _PermitContext(
        campaign=sample_campaign,
        intent=intent,
        source_proposal=source_proposal,
        hypotheses=hypotheses,
        plan=plan,
        task=task,
        definition=definition,
        definitions=bundle.definitions,
        code_backed=binding.capability,
        authorities=bundle.authorities,
        activation=activation,
        graph=graph,
        envelope=envelope,
        decision=decision,
        reservation=reservation,
    )


def _inputs(context: _PermitContext) -> GeneralAttackActionPermitInputs:
    return GeneralAttackActionPermitInputs(
        envelope=context.envelope,
        decision=context.decision,
        cost_microusd=context.reservation.cost_microusd,
    )


def _gate(
    context: _PermitContext,
    authority: _StaticPermitInputAuthority,
) -> GeneralAttackActionPermitGate:
    return GeneralAttackActionPermitGate(
        activation=context.activation,
        permit_store=context.graph.permit_store,
        inputs=authority,
        clock=lambda: _GATE_NOW,
    )


async def _dispatch(
    gate: GeneralAttackActionPermitGate,
    context: _PermitContext,
    callback,
):
    return await gate.dispatch_once(
        context.intent,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.definition.reference(),
        context.definitions,
        context.code_backed,
        context.authorities,
        callback,
    )


def _replace_envelope(
    envelope: MissionEnvelope,
    **changes: object,
) -> MissionEnvelope:
    raw = envelope.model_dump(mode="json", by_alias=True)
    raw.pop("envelopeId")
    raw.pop("envelopeDigest")
    raw.update(changes)
    return MissionEnvelope.model_validate(raw)


def _replace_decision(
    decision: GraphDecision,
    **changes: object,
) -> GraphDecision:
    raw = decision.model_dump(mode="json", by_alias=True)
    raw.pop("decisionId")
    raw.pop("decisionDigest")
    raw.update(changes)
    return GraphDecision.model_validate(raw)


def _rebind_campaign(
    context: _PermitContext,
    campaign: CampaignManifest,
) -> _PermitContext:
    source_proposal, hypotheses, plan, task, _, _ = _proposal(
        campaign,
        definition=context.definition,
        arguments=_ARGUMENTS,
    )
    intent = compile_general_attack_action_intent(
        source_proposal,
        campaign,
        hypotheses,
        plan,
        task.task_digest,
        context.definition.reference(),
        context.definitions,
        context.code_backed,
        context.authorities,
    )
    return replace(
        context,
        campaign=campaign,
        intent=intent,
        source_proposal=source_proposal,
        hypotheses=hypotheses,
        plan=plan,
        task=task,
        envelope=_replace_envelope(
            context.envelope,
            sourceCampaignDigest=campaign_manifest_digest(campaign),
        ),
        decision=_replace_decision(
            context.decision,
            decisionPayloadDigest=intent.intent_digest,
        ),
    )


@pytest.mark.asyncio
async def test_general_attack_gate_consumes_existing_permit_once(
    permit_context: _PermitContext,
) -> None:
    authority = _StaticPermitInputAuthority(_inputs(permit_context))
    gate = _gate(permit_context, authority)
    calls: list[ActionPermit] = []

    async def consume(permit: ActionPermit, prepared, proposal) -> str:
        assert prepared.request == permit_context.intent.request
        assert proposal.request_digest == permit_context.intent.request_digest
        calls.append(permit)
        return permit.dispatch_id

    first = await _dispatch(gate, permit_context, consume)
    retry = await _dispatch(gate, permit_context, consume)

    assert first.intent == permit_context.intent
    assert first.prepared.request == permit_context.intent.request
    assert first.proposal.capability == first.prepared.capability
    assert first.proposal.target_digest == permit_context.intent.target_digest
    assert first.proposal.request_digest == permit_context.intent.request_digest
    assert first.proposal.normalized_parameters_digest == (
        permit_context.intent.normalized_parameters_digest
    )
    assert first.proposal.proposer_id == permit_context.decision.actor_id
    assert first.proposal.proposer_digest == permit_context.decision.actor_digest
    assert first.proposal.reservation == permit_context.reservation
    assert first.dispatch.dispatched is True
    assert first.dispatch.result == first.dispatch.permit.dispatch_id
    assert retry.dispatch.dispatched is False
    assert retry.dispatch.result is None
    assert retry.dispatch.permit == first.dispatch.permit
    assert calls == [first.dispatch.permit]
    assert authority.calls == 2
    assert permit_context.graph.permit_store.permits() == (first.dispatch.permit,)
    assert permit_context.intent.permit_granted is False
    assert permit_context.intent.execution_authorized is False


@pytest.mark.asyncio
async def test_general_attack_gate_rejects_sync_callback_before_permit(
    permit_context: _PermitContext,
) -> None:
    authority = _StaticPermitInputAuthority(_inputs(permit_context))
    gate = _gate(permit_context, authority)
    calls = 0

    def consume(_: ActionPermit, prepared, proposal) -> None:
        nonlocal calls
        del prepared, proposal
        calls += 1

    with pytest.raises(TypeError, match="callback must be async"):
        await _dispatch(gate, permit_context, consume)

    assert calls == 0
    assert authority.calls == 0
    assert permit_context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_wraps_external_authority_failure(
    permit_context: _PermitContext,
) -> None:
    class _FailingAuthority:
        def resolve_for_action(self, **kwargs):
            del kwargs
            raise RuntimeError("provider unavailable")

    gate = GeneralAttackActionPermitGate(
        activation=permit_context.activation,
        permit_store=permit_context.graph.permit_store,
        inputs=_FailingAuthority(),
        clock=lambda: _GATE_NOW,
    )

    async def consume(_: ActionPermit, prepared, proposal) -> None:
        del prepared, proposal
        raise AssertionError("failed authority reached the Permit consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="external"):
        await _dispatch(gate, permit_context, consume)

    assert permit_context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_detaches_request_material_from_external_authority(
    permit_context: _PermitContext,
) -> None:
    class _MutatingAuthority:
        def resolve_for_action(self, *, intent, prepared, **kwargs):
            del kwargs
            intent.request.target = "https://foreign.example.invalid/admin"
            prepared.request.arguments["simulation"] = {"expanded": True}
            return _inputs(permit_context)

    gate = GeneralAttackActionPermitGate(
        activation=permit_context.activation,
        permit_store=permit_context.graph.permit_store,
        inputs=_MutatingAuthority(),
        clock=lambda: _GATE_NOW,
    )
    observed = []

    async def consume(permit: ActionPermit, prepared, proposal) -> str:
        observed.append((prepared.request, proposal))
        return permit.dispatch_id

    result = await _dispatch(gate, permit_context, consume)

    assert result.dispatch.dispatched is True
    assert result.prepared.request == permit_context.intent.request
    assert observed == [(result.prepared.request, result.proposal)]
    assert result.proposal.request_digest == permit_context.intent.request_digest
    assert result.proposal.normalized_parameters_digest == (
        permit_context.intent.normalized_parameters_digest
    )


@pytest.mark.asyncio
async def test_general_attack_gate_rejects_provider_campaign_mutation_forgery(
    permit_context: _PermitContext,
) -> None:
    class _MutatingAuthority:
        def resolve_for_action(self, *, campaign, **kwargs):
            del kwargs
            campaign.spec.budgets.max_cost_usd = 1
            campaign.spec.authorization.expires_at = _GATE_NOW + timedelta(hours=1)
            return GeneralAttackActionPermitInputs(
                envelope=_replace_envelope(
                    permit_context.envelope,
                    sourceCampaignDigest=campaign_manifest_digest(campaign),
                ),
                decision=permit_context.decision,
                cost_microusd=0,
            )

    gate = GeneralAttackActionPermitGate(
        activation=permit_context.activation,
        permit_store=permit_context.graph.permit_store,
        inputs=_MutatingAuthority(),
        clock=lambda: _GATE_NOW,
    )

    async def consume(_, prepared, proposal) -> None:
        del prepared, proposal
        raise AssertionError("mutated Campaign reached the Permit consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="exact current Campaign"):
        await _dispatch(gate, permit_context, consume)

    assert permit_context.campaign.spec.budgets.max_cost_usd == 0
    assert permit_context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_revalidates_activation_after_external_authority(
    permit_context: _PermitContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = ExistingModeCapabilityActivation.resolve_for_dispatch
    calls = 0

    def drift_after_provider(self, reference):
        nonlocal calls
        calls += 1
        if calls == 4:
            raise ExistingModeCapabilityActivationError("release changed")
        return original(self, reference)

    monkeypatch.setattr(
        ExistingModeCapabilityActivation,
        "resolve_for_dispatch",
        drift_after_provider,
    )
    authority = _StaticPermitInputAuthority(_inputs(permit_context))
    gate = _gate(permit_context, authority)

    async def consume(_: ActionPermit, prepared, proposal) -> None:
        del prepared, proposal
        raise AssertionError("drifted activation reached the Permit consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="changed before Permit"):
        await _dispatch(gate, permit_context, consume)

    assert calls == 4
    assert authority.calls == 1
    assert permit_context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_rejects_cross_source_intent_before_permit(
    permit_context: _PermitContext,
) -> None:
    foreign_proposal, hypotheses, plan, task, _, _ = _proposal(
        permit_context.campaign,
        definition=permit_context.definition,
        wave_digest="f" * 64,
        arguments=_ARGUMENTS,
    )
    authority = _StaticPermitInputAuthority(_inputs(permit_context))
    gate = _gate(permit_context, authority)
    calls = 0

    async def consume(_: ActionPermit, prepared, proposal) -> None:
        nonlocal calls
        del prepared, proposal
        calls += 1

    with pytest.raises(GeneralAttackActionPermitError, match="source intent"):
        await gate.dispatch_once(
            permit_context.intent,
            foreign_proposal,
            permit_context.campaign,
            hypotheses,
            plan,
            task.task_digest,
            permit_context.definition.reference(),
            permit_context.definitions,
            permit_context.code_backed,
            permit_context.authorities,
            consume,
        )

    assert calls == 0
    assert authority.calls == 0
    assert permit_context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["kind", "payload", "campaign"])
async def test_general_attack_gate_rejects_unauthorized_decision_before_permit(
    permit_context: _PermitContext,
    mutation: str,
) -> None:
    if mutation == "kind":
        decision = _replace_decision(
            permit_context.decision,
            decisionKind=GraphDecisionKind.STOP.value,
        )
    elif mutation == "payload":
        decision = _replace_decision(
            permit_context.decision,
            decisionPayloadDigest="f" * 64,
        )
    else:
        foreign_snapshot = permit_context.decision.snapshot.model_copy(
            update={"campaign_id": "foreign-campaign"}
        )
        decision = GraphDecision(
            campaignId="foreign-campaign",
            decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
            decisionPayloadDigest=permit_context.intent.intent_digest,
            snapshot=foreign_snapshot,
            actorId=permit_context.decision.actor_id,
            actorDigest=permit_context.decision.actor_digest,
            createdAt=permit_context.decision.created_at,
        )
    authority = _StaticPermitInputAuthority(
        GeneralAttackActionPermitInputs(
            envelope=permit_context.envelope,
            decision=decision,
            cost_microusd=permit_context.reservation.cost_microusd,
        )
    )
    gate = _gate(permit_context, authority)

    async def consume(_: ActionPermit, prepared, proposal) -> None:
        del prepared, proposal
        raise AssertionError("unauthorized Decision reached the Permit consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="Graph Decision"):
        await _dispatch(gate, permit_context, consume)

    assert permit_context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    ["campaign-digest", "target", "autonomy", "tool-calls", "campaign-cost", "cost-type", "cost"],
)
async def test_general_attack_gate_rejects_scope_or_budget_expansion_before_permit(
    permit_context: _PermitContext,
    mutation: str,
) -> None:
    envelope = permit_context.envelope
    cost_microusd: object = permit_context.reservation.cost_microusd
    if mutation == "campaign-digest":
        envelope = _replace_envelope(envelope, sourceCampaignDigest="f" * 64)
    elif mutation == "target":
        envelope = _replace_envelope(envelope, allowedTargetDigests=["f" * 64])
    elif mutation == "autonomy":
        envelope = _replace_envelope(envelope, autonomy="lab-autonomous")
    elif mutation == "tool-calls":
        budget = envelope.budget.model_dump(mode="json", by_alias=True)
        budget["toolCallLimit"] = permit_context.campaign.spec.budgets.max_tool_calls + 1
        envelope = _replace_envelope(envelope, budget=budget)
    elif mutation == "campaign-cost":
        budget = envelope.budget.model_dump(mode="json", by_alias=True)
        budget["costLimitMicrousd"] = 1
        envelope = _replace_envelope(envelope, budget=budget)
    elif mutation == "cost-type":
        cost_microusd = True
    else:
        cost_microusd = permit_context.envelope.budget.cost_limit_microusd + 1
    authority = _StaticPermitInputAuthority(
        GeneralAttackActionPermitInputs(
            envelope=envelope,
            decision=permit_context.decision,
            cost_microusd=cost_microusd,
        )
    )
    gate = _gate(permit_context, authority)

    async def consume(_: ActionPermit, prepared, proposal) -> None:
        del prepared, proposal
        raise AssertionError("scope or budget expansion reached the Permit consumer")

    with pytest.raises(GeneralAttackActionPermitError):
        await _dispatch(gate, permit_context, consume)

    assert permit_context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_rejects_expired_campaign_before_permit(
    permit_context: _PermitContext,
) -> None:
    raw = permit_context.campaign.model_dump(mode="json", by_alias=True)
    raw["spec"]["authorization"]["expiresAt"] = (_GATE_NOW - timedelta(minutes=1)).isoformat()
    expired = _rebind_campaign(
        permit_context,
        CampaignManifest.model_validate(raw),
    )
    authority = _StaticPermitInputAuthority(_inputs(expired))
    gate = _gate(expired, authority)

    async def consume(_, prepared, proposal) -> None:
        del prepared, proposal
        raise AssertionError("expired Campaign reached the Permit consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="authorization timeline"):
        await _dispatch(gate, expired, consume)

    assert expired.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_requires_campaign_rolling_rate_attenuation(
    permit_context: _PermitContext,
) -> None:
    raw = permit_context.campaign.model_dump(mode="json", by_alias=True)
    raw["spec"]["rulesOfEngagement"]["maxRequestsPerMinute"] = 1
    rate_limited = _rebind_campaign(
        permit_context,
        CampaignManifest.model_validate(raw),
    )
    authority = _StaticPermitInputAuthority(_inputs(rate_limited))
    gate = _gate(rate_limited, authority)

    async def consume(_, prepared, proposal) -> None:
        del prepared, proposal
        raise AssertionError("unattenuated rate limit reached the Permit consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="rolling-rate"):
        await _dispatch(gate, rate_limited, consume)

    assert rate_limited.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_rechecks_campaign_window_at_atomic_claim(
    permit_context: _PermitContext,
) -> None:
    raw = permit_context.campaign.model_dump(mode="json", by_alias=True)
    raw["spec"]["rulesOfEngagement"]["testingWindows"] = [
        {
            "days": ["wednesday"],
            "startTime": "09:00:00",
            "endTime": "09:31:00",
            "timezone": "UTC",
        }
    ]
    windowed = _rebind_campaign(
        permit_context,
        CampaignManifest.model_validate(raw),
    )
    clock_values = iter((_GATE_NOW, _GATE_NOW + timedelta(minutes=2)))
    authority = _StaticPermitInputAuthority(_inputs(windowed))
    gate = GeneralAttackActionPermitGate(
        activation=windowed.activation,
        permit_store=windowed.graph.permit_store,
        inputs=authority,
        clock=lambda: next(clock_values),
    )
    calls = 0

    async def consume(_, prepared, proposal) -> None:
        nonlocal calls
        del prepared, proposal
        calls += 1

    with pytest.raises(GeneralAttackActionPermitError, match="testing window"):
        await _dispatch(gate, windowed, consume)

    assert authority.calls == 1
    assert calls == 0
    assert windowed.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_pins_one_run_envelope(
    permit_context: _PermitContext,
) -> None:
    authority = _StaticPermitInputAuthority(_inputs(permit_context))
    gate = _gate(permit_context, authority)
    calls = 0

    async def consume(_: ActionPermit, prepared, proposal) -> None:
        nonlocal calls
        del prepared, proposal
        calls += 1

    first = await _dispatch(gate, permit_context, consume)
    authority.value = GeneralAttackActionPermitInputs(
        envelope=_replace_envelope(
            permit_context.envelope,
            profileDigest="f" * 64,
        ),
        decision=permit_context.decision,
        cost_microusd=permit_context.reservation.cost_microusd,
    )

    with pytest.raises(GeneralAttackActionPermitError, match="pinned"):
        await _dispatch(gate, permit_context, consume)

    assert calls == 1
    assert permit_context.graph.permit_store.permits() == (first.dispatch.permit,)


@pytest.mark.asyncio
async def test_general_attack_gate_requires_current_signed_activation(
    permit_context: _PermitContext,
) -> None:
    foreign_release = _release_for(
        permit_context.activation.rollout,
        "pajin.ai.kisa.system-prompt-disclosure",
    )
    foreign_activation = activate_existing_mode_capabilities(
        rollout=permit_context.activation.rollout,
        releases=(foreign_release,),
        profile=CapabilityUseProfile.RANGE,
    )
    authority = _StaticPermitInputAuthority(_inputs(permit_context))
    gate = GeneralAttackActionPermitGate(
        activation=foreign_activation,
        permit_store=permit_context.graph.permit_store,
        inputs=authority,
        clock=lambda: _GATE_NOW,
    )

    async def consume(_: ActionPermit, prepared, proposal) -> None:
        del prepared, proposal
        raise AssertionError("foreign activation reached the Permit consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="current activation"):
        await _dispatch(gate, permit_context, consume)

    assert authority.calls == 0
    assert permit_context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_general_attack_gate_rejects_stale_graph_in_atomic_claim(
    permit_context: _PermitContext,
) -> None:
    late_lineage = GraphProposalLineage(
        campaignId=permit_context.campaign.metadata.name,
        runId=permit_context.envelope.run_id,
        agentId="agent:late-general-attack-specialist",
        taskId="task:late-general-attack-surface",
        requestId="request_late_general_attack_surface",
        requestDigest="b" * 64,
        capabilityGrantId="grant:late-general-attack-surface",
        capabilityGrantDigest="b" * 64,
        capabilityId=_CAPABILITY_ID,
        capabilityVersion="1.0.0",
        capabilityDigest="c" * 64,
        sourceRootDigest="a" * 64,
        evidence=[{"reference": "evidence/late-surface.json", "sha256": "b" * 64}],
        producedAt=_GATE_NOW,
    )
    late = SurfaceProposal(
        proposalId="proposal:surface:late-general-attack",
        producerId="pajin.graph.capability-worker-test",
        producerVersion="1.0.0",
        producerDigest="c" * 64,
        lineage=late_lineage,
        surface={
            "campaignId": permit_context.campaign.metadata.name,
            "targetId": "target:late-general-attack",
            "surfaceType": "mock-agent",
            "locatorSchema": "pajin.discovery.mock-agent.v1",
            "locatorDigest": "b" * 64,
            "origin": GraphContentOrigin.TRUSTED_CORE,
        },
    )
    late_store = SQLiteGraphStore(
        permit_context.graph.event_log.path,
        campaign_id=permit_context.campaign.metadata.name,
    )
    admission = GraphAdmissionAuthority(
        campaign_id=permit_context.campaign.metadata.name,
        authority_id="pajin.graph.capability-worker-admission",
        authority_digest="a" * 64,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=late.producer_id,
                    producerVersion=late.producer_version,
                    producerDigest=late.producer_digest,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry([late_lineage]),
        event_log=late_store.event_log,
        clock=lambda: _GATE_NOW,
    )
    admission.submit(late)
    authority = _StaticPermitInputAuthority(_inputs(permit_context))
    gate = _gate(permit_context, authority)
    calls = 0

    async def consume(_: ActionPermit, prepared, proposal) -> None:
        nonlocal calls
        del prepared, proposal
        calls += 1

    with pytest.raises(ActionPermitStaleDecision):
        await _dispatch(gate, permit_context, consume)

    assert calls == 0
    assert permit_context.graph.permit_store.permits() == ()
