from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_ctf_runtime import ContractCTFWorker, _challenge
from test_ctf_runtime import _trusted_docker_backend as ctf_backend
from test_engine_behavioral_parity import _ctf_campaign
from test_engine_mission_envelope import (
    _activation_for_capability,
    _all_capability_activation,
    _parity,
)

from pajin.capabilities import ExistingModeCapabilityActivation
from pajin.capabilities.activation import capability_tool_request_digest
from pajin.domain.models import CampaignManifest, CapabilityGrant
from pajin.graph import (
    ActionPermitStaleDecision,
    GraphAdmissionAuthority,
    GraphContentOrigin,
    GraphDecision,
    GraphDecisionKind,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProposalKind,
    GraphProposalLineage,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    SQLiteGraphStore,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_snapshot_ref,
)
from pajin.modes.ctf import CTFChallengeService
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import RunStore, load_verified_run_events
from pajin.tools.base import ToolRegistry
from pajin.tools.ctf import CTFWebBackupProbeTool
from pajin.tools.gateway import ToolGateway
from pajin.workflow.engine_execution_gate import (
    CommonEngineActionIntent,
    CommonEngineExecutionGate,
    CommonEngineExecutionGateAuthority,
    CommonEngineExecutionGateError,
    compile_common_engine_action_intent,
    compile_common_engine_execution_gate_authority,
)
from pajin.workflow.engine_mission_envelope import (
    CommonEngineMissionEnvelopeCompilationAuthority,
    compile_common_engine_mission_envelope,
)
from pajin.workflow.profile_compatibility import compile_legacy_campaign_profile

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64


@dataclass(frozen=True)
class _C2Context:
    campaign: CampaignManifest
    activation: ExistingModeCapabilityActivation
    authority: CommonEngineMissionEnvelopeCompilationAuthority
    gate_authority: CommonEngineExecutionGateAuthority


@pytest.fixture(scope="module")
def c2_context(tmp_path_factory: pytest.TempPathFactory) -> _C2Context:
    campaign = _ctf_campaign()
    parity = _parity(
        tmp_path_factory.mktemp("engine-execution-gate-parity"),
        campaign,
        CTFWebBackupProbeTool,
        lambda: ctf_backend(ContractCTFWorker()),
        _challenge(),
    )
    activation = _all_capability_activation()
    authority = compile_common_engine_mission_envelope(
        compile_legacy_campaign_profile(campaign),
        parity,
        activation,
        run_id=RunStore.new_run_id(),
        not_before=campaign.spec.authorization.approved_at + timedelta(seconds=1),
    )
    gate_authority = compile_common_engine_execution_gate_authority(
        authority,
        activation,
    )
    return _C2Context(
        campaign=campaign,
        activation=activation,
        authority=authority,
        gate_authority=gate_authority,
    )


def _surface_proposal(
    context: _C2Context,
    intent: CommonEngineActionIntent,
    *,
    tag: str,
) -> SurfaceProposal:
    return SurfaceProposal(
        proposalId=f"proposal:surface:common-engine:{tag}",
        producerId="pajin.graph.common-engine-gate-test",
        producerVersion="1.0.0",
        producerDigest=_DIGEST_C,
        lineage=GraphProposalLineage(
            campaignId=context.campaign.metadata.name,
            runId=context.authority.run_id,
            agentId=intent.request.agent_id,
            taskId=f"task:common-engine:{tag}",
            requestId=(intent.request.request_id if tag == "first" else f"late_{tag}"),
            requestDigest=(intent.request_digest if tag == "first" else _DIGEST_B),
            capabilityGrantId=f"grant:common-engine:{tag}",
            capabilityGrantDigest=_DIGEST_A,
            capabilityId=intent.capability.capability_id,
            capabilityVersion=intent.capability.capability_version,
            capabilityDigest=intent.capability.definition_digest,
            sourceRootDigest=_DIGEST_B,
            evidence=[
                {
                    "reference": f"evidence/common-engine-{tag}.json",
                    "sha256": _DIGEST_A,
                }
            ],
            producedAt=context.gate_authority.envelope.not_before + timedelta(seconds=1),
        ),
        surface={
            "campaignId": context.campaign.metadata.name,
            "targetId": f"target:common-engine:{tag}",
            "surfaceType": "ctf-web-endpoint",
            "locatorSchema": "pajin.discovery.ctf-web-endpoint.v1",
            "locatorDigest": _DIGEST_B if tag == "first" else _DIGEST_C,
            "origin": GraphContentOrigin.TRUSTED_CORE,
        },
    )


def _graph_decision(
    tmp_path: Path,
    context: _C2Context,
    intent: CommonEngineActionIntent,
) -> tuple[SQLiteGraphStore, GraphAdmissionAuthority, GraphDecision]:
    proposal = _surface_proposal(context, intent, tag="first")
    store = SQLiteGraphStore(
        tmp_path / "graph" / "canonical.sqlite3",
        campaign_id=context.campaign.metadata.name,
    )
    admission = GraphAdmissionAuthority(
        campaign_id=context.campaign.metadata.name,
        authority_id="pajin.graph.common-engine-gate-admission",
        authority_digest=_DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=proposal.producer_id,
                    producerVersion=proposal.producer_version,
                    producerDigest=proposal.producer_digest,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry(
            [
                proposal.lineage,
                _surface_proposal(context, intent, tag="late").lineage,
            ]
        ),
        event_log=store.event_log,
        clock=lambda: context.gate_authority.envelope.not_before
        + timedelta(seconds=2),
    )
    admission.submit(proposal)
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    snapshot = GraphSnapshotAuthority(
        creator_id="pajin.graph.common-engine-gate-snapshot",
        creator_digest=_DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: context.gate_authority.envelope.not_before
        + timedelta(seconds=3),
    ).capture(GraphSnapshotReason.CHECKPOINT)
    decision = GraphDecision(
        campaignId=context.campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=intent.intent_digest,
        snapshot=graph_snapshot_ref(snapshot),
        actorId="pajin.graph.common-engine-gate-planner",
        actorDigest=_DIGEST_C,
        createdAt=context.gate_authority.envelope.not_before + timedelta(seconds=4),
    )
    return store, admission, decision


def _grant(
    context: _C2Context,
    intent: CommonEngineActionIntent,
    *,
    target: str | None = None,
    max_calls: int | None = None,
) -> CapabilityGrant:
    return CapabilityGrant(
        subject=intent.request.agent_id,
        campaign=context.campaign.metadata.name,
        tools={intent.request.tool_id},
        targets={target or intent.request.target},
        max_risk_tier=intent.capability.risk_tier,
        max_calls=(
            context.gate_authority.envelope.budget.tool_call_limit
            if max_calls is None
            else max_calls
        ),
        issued_at=context.gate_authority.envelope.not_before,
        expires_at=context.gate_authority.envelope.expires_at,
    )


def _gate(
    tmp_path: Path,
    context: _C2Context,
    intent: CommonEngineActionIntent,
    graph: SQLiteGraphStore,
    *,
    activation: ExistingModeCapabilityActivation | None = None,
) -> tuple[CommonEngineExecutionGate, RunStore, ContractCTFWorker]:
    audit_store = RunStore.create(
        tmp_path / "runs",
        context.campaign.metadata.name,
        run_id=context.gate_authority.envelope.run_id,
    )
    tools = ToolRegistry()
    tools.register(CTFWebBackupProbeTool())
    worker = ContractCTFWorker()
    evaluated_at = context.gate_authority.envelope.not_before + timedelta(seconds=5)
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=tools,
        worker=ctf_backend(worker),
        store=audit_store,
        clock=lambda: evaluated_at,
    )
    gate = CommonEngineExecutionGate(
        activation=activation or context.activation,
        permit_store=graph.permit_store,
        gateway=gateway,
        audit_store=audit_store,
        clock=lambda: evaluated_at,
    )
    assert intent.run_id == audit_store.run_id
    return gate, audit_store, worker


@pytest.mark.asyncio
async def test_explicit_gate_dispatches_once_through_existing_permit_and_gateway(
    tmp_path: Path,
    c2_context: _C2Context,
) -> None:
    intent = compile_common_engine_action_intent(
        c2_context.gate_authority,
        0,
        cost_microusd=0,
    )
    graph, _, decision = _graph_decision(tmp_path, c2_context, intent)
    gate, audit_store, worker = _gate(tmp_path, c2_context, intent, graph)
    grant = _grant(c2_context, intent)

    first = await gate.dispatch_once(
        c2_context.gate_authority,
        intent,
        decision,
        campaign=c2_context.campaign,
        grant=grant,
    )
    retry = await gate.dispatch_once(
        c2_context.gate_authority,
        intent,
        decision,
        campaign=c2_context.campaign,
        grant=grant,
    )

    assert intent.request.request_id != (
        c2_context.authority.capability_bindings[0].request.request_id
    )
    assert c2_context.authority.compiler.action_permit_issuance_authorized is False
    assert c2_context.gate_authority.compiler.action_permit_issuance_authorized is True
    assert (
        c2_context.gate_authority.source_envelope_digest
        == c2_context.authority.envelope.envelope_digest
    )
    source_envelope = c2_context.authority.envelope.model_dump(
        mode="json",
        by_alias=True,
        exclude={
            "envelope_id",
            "envelope_digest",
            "compiler_id",
            "compiler_version",
            "compiler_digest",
        },
    )
    executable_envelope = c2_context.gate_authority.envelope.model_dump(
        mode="json",
        by_alias=True,
        exclude={
            "envelope_id",
            "envelope_digest",
            "compiler_id",
            "compiler_version",
            "compiler_digest",
        },
    )
    assert executable_envelope == source_envelope
    assert (
        CommonEngineExecutionGateAuthority.model_validate(
            c2_context.gate_authority.model_dump(mode="json", by_alias=True)
        )
        == c2_context.gate_authority
    )
    assert (
        CommonEngineActionIntent.model_validate(
            intent.model_dump(mode="json", by_alias=True)
        )
        == intent
    )
    assert first.dispatch.dispatched is True
    assert first.dispatch.result is not None
    assert first.dispatch.result.executed is True
    assert retry.dispatch.dispatched is False
    assert retry.dispatch.result is None
    assert retry.dispatch.permit == first.dispatch.permit
    assert len(worker.jobs) == 1
    assert graph.permit_store.permits() == (first.dispatch.permit,)
    audit_store.seal()
    dispatch_events = [
        event
        for event in load_verified_run_events(audit_store.path)
        if event.event_type.startswith("capability.dispatch.")
    ]
    assert [event.event_type for event in dispatch_events] == [
        "capability.dispatch.claimed",
        "capability.dispatch.completed",
    ]


@pytest.mark.asyncio
async def test_gate_rejects_stale_graph_before_permit_or_worker(
    tmp_path: Path,
    c2_context: _C2Context,
) -> None:
    intent = compile_common_engine_action_intent(
        c2_context.gate_authority,
        0,
        cost_microusd=0,
    )
    graph, admission, decision = _graph_decision(tmp_path, c2_context, intent)
    admission.submit(_surface_proposal(c2_context, intent, tag="late"))
    gate, audit_store, worker = _gate(tmp_path, c2_context, intent, graph)

    with pytest.raises(ActionPermitStaleDecision):
        await gate.dispatch_once(
            c2_context.gate_authority,
            intent,
            decision,
            campaign=c2_context.campaign,
            grant=_grant(c2_context, intent),
        )

    assert graph.permit_store.permits() == ()
    assert worker.jobs == []
    assert not audit_store.events_path.exists()


@pytest.mark.asyncio
async def test_gate_rejects_intent_decision_activation_or_grant_substitution(
    tmp_path: Path,
    c2_context: _C2Context,
) -> None:
    intent = compile_common_engine_action_intent(
        c2_context.gate_authority,
        0,
        cost_microusd=0,
    )
    graph, _, decision = _graph_decision(tmp_path, c2_context, intent)
    gate, _, worker = _gate(tmp_path, c2_context, intent, graph)

    payload = deepcopy(intent.model_dump(mode="json", by_alias=True))
    payload["request"]["target"] = "https://forged.example.invalid/"
    forged_request = intent.request.model_copy(
        update={"target": payload["request"]["target"]}
    )
    payload["requestDigest"] = capability_tool_request_digest(forged_request)
    payload["targetDigest"] = sha256(
        forged_request.target.encode("utf-8")
    ).hexdigest()
    payload["intentId"] = ""
    payload["intentDigest"] = ""
    forged_intent = CommonEngineActionIntent.model_validate(payload)
    with pytest.raises(CommonEngineExecutionGateError, match="differs from C2"):
        await gate.dispatch_once(
            c2_context.gate_authority,
            forged_intent,
            decision,
            campaign=c2_context.campaign,
            grant=_grant(c2_context, intent),
        )

    foreign_decision = GraphDecision(
        campaignId=decision.campaign_id,
        decisionKind=decision.decision_kind,
        decisionPayloadDigest=_DIGEST_A,
        snapshot=decision.snapshot,
        actorId=decision.actor_id,
        actorDigest=decision.actor_digest,
        createdAt=decision.created_at,
    )
    with pytest.raises(CommonEngineExecutionGateError, match="does not authorize"):
        await gate.dispatch_once(
            c2_context.gate_authority,
            intent,
            foreign_decision,
            campaign=c2_context.campaign,
            grant=_grant(c2_context, intent),
        )

    wrong_activation = _activation_for_capability(
        "pajin.bug-bounty.boolean-sqli-lab"
    )
    with pytest.raises(CommonEngineExecutionGateError, match="failed closed"):
        compile_common_engine_execution_gate_authority(
            c2_context.authority,
            wrong_activation,
        )
    wrong_root = tmp_path / "wrong-activation"
    wrong_root.mkdir()
    wrong_gate, _, _ = _gate(
        wrong_root,
        c2_context,
        intent,
        graph,
        activation=wrong_activation,
    )
    with pytest.raises(CommonEngineExecutionGateError, match="activation differs"):
        await wrong_gate.dispatch_once(
            c2_context.gate_authority,
            intent,
            decision,
            campaign=c2_context.campaign,
            grant=_grant(c2_context, intent),
        )

    with pytest.raises(CommonEngineExecutionGateError, match="Grant does not cover"):
        await gate.dispatch_once(
            c2_context.gate_authority,
            intent,
            decision,
            campaign=c2_context.campaign,
            grant=_grant(
                c2_context,
                intent,
                target="https://foreign.example.invalid/",
            ),
        )

    assert graph.permit_store.permits() == ()
    assert worker.jobs == []


def test_action_intent_rejects_flag_or_cost_forgery(c2_context: _C2Context) -> None:
    intent = compile_common_engine_action_intent(
        c2_context.gate_authority,
        0,
        cost_microusd=0,
    )
    for field, value in (
        ("explicitOptIn", False),
        ("actionPermitIssued", True),
        ("commonRuntimeDispatched", True),
    ):
        payload = deepcopy(intent.model_dump(mode="json", by_alias=True))
        payload[field] = value
        with pytest.raises(ValidationError):
            CommonEngineActionIntent.model_validate(payload)

    for field, value in (
        ("actionPermitIssuanceAuthorized", False),
        ("commonRuntimeDispatchAuthorized", False),
        ("legacyDefaultPathChanged", True),
    ):
        payload = deepcopy(
            c2_context.gate_authority.model_dump(mode="json", by_alias=True)
        )
        payload[field] = value
        with pytest.raises(ValidationError):
            CommonEngineExecutionGateAuthority.model_validate(payload)

    payload = deepcopy(
        c2_context.gate_authority.model_dump(mode="json", by_alias=True)
    )
    payload["envelope"]["budget"]["toolCallLimit"] += 1
    payload["envelope"]["envelopeId"] = ""
    payload["envelope"]["envelopeDigest"] = ""
    forged_envelope = type(c2_context.gate_authority.envelope).model_validate(
        payload["envelope"]
    )
    payload["envelope"] = forged_envelope.model_dump(mode="json", by_alias=True)
    payload["envelopeDigest"] = forged_envelope.envelope_digest
    payload["authorityId"] = ""
    payload["authorityDigest"] = ""
    with pytest.raises(ValidationError, match="Gate Authority differs"):
        CommonEngineExecutionGateAuthority.model_validate(payload)

    with pytest.raises(CommonEngineExecutionGateError, match="cost reservation"):
        compile_common_engine_action_intent(
            c2_context.gate_authority,
            0,
            cost_microusd=c2_context.gate_authority.envelope.budget.cost_limit_microusd
            + 1,
        )

    assert CTFChallengeService().compile_campaign(_challenge()) == c2_context.campaign
