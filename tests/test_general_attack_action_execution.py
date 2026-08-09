from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.capabilities import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CapabilityGraphRunAuditAnchor,
    CapabilityUseProfile,
    CodeBackedCapabilityRef,
    activate_existing_mode_capabilities,
    admit_existing_mode_capability_releases,
)
from pajin.domain.ctf import CTFScenario
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CapabilityGrant,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    GraphDecision,
    GraphDecisionKind,
    MissionEnvelope,
)
from pajin.modes.ctf import CTFChallengeService, load_ctf_challenge
from pajin.runtime.store import RunStore, load_verified_run_events
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.supervision import (
    GeneralAttackActionExecutionError,
    GeneralAttackActionExecutionGate,
    GeneralAttackActionExecutionInputs,
    compile_general_attack_action_intent,
)
from pajin.supervision.action_proposal import GeneralAttackActionProposal
from pajin.tools.base import ToolRegistry
from pajin.tools.ctf import (
    CTFCryptoXORTool,
    crypto_artifact_target,
)
from tests.test_ctf_crypto import ARTIFACT_SHA256, CIPHERTEXT_HEX, CRYPTO_FLAG
from tests.test_existing_capability_rollout import (
    NOW as RELEASE_NOW,
)
from tests.test_existing_capability_rollout import (
    _dispatch_grant,
    _release_for,
    _rollout_inputs,
    _seed_worker_graph,
)
from tests.test_general_attack_action_permit import (
    _GATE_NOW,
    _inputs,
    _PermitContext,
    _replace_decision,
    _StaticPermitInputAuthority,
)
from tests.test_general_attack_action_permit import permit_context as _t2_permit_context
from tests.test_general_attack_action_proposal import _proposal


@dataclass(slots=True)
class _StaticExecutionInputAuthority:
    value: GeneralAttackActionExecutionInputs
    calls: int = 0

    def resolve_for_execution(self, **_kwargs) -> GeneralAttackActionExecutionInputs:
        self.calls += 1
        return self.value


class _CountingWorker:
    def __init__(self) -> None:
        self.calls = 0

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "tests.sup-007a-crypto-worker/v1",
            "supportedCommands": ["ctf-crypto-single-byte-xor"],
            "networkMode": NetworkMode.NONE.value,
            "secretLeases": False,
        }

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets=None,
    ) -> WorkerResult:
        self.calls += 1
        assert secrets is None
        assert job.command == ["ctf-crypto-single-byte-xor"]
        assert job.network is NetworkMode.NONE
        payload = json.loads(job.stdin)
        output = {
            "target": payload["target"],
            "challengeId": payload["challengeId"],
            "scenarioId": payload["scenarioId"],
            "artifactSha256": payload["artifactSha256"],
            "solved": True,
            "candidateFlag": CRYPTO_FLAG,
            "key": 55,
            "attemptedKeys": 256,
            "synthetic": True,
            "networkPerformed": False,
        }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="sup-007a-crypto-test",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=_GATE_NOW,
            finished_at=_GATE_NOW,
        )


@pytest.fixture
def permit_context_fixture(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> _PermitContext:
    return _t2_permit_context.__wrapped__(tmp_path, sample_campaign)


@pytest.fixture
def low_risk_context(tmp_path: Path) -> _PermitContext:
    challenge = load_ctf_challenge(Path("examples/ctf-crypto-xor-lab.yaml"))
    campaign = CTFChallengeService().compile_campaign(
        challenge,
        evaluated_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )
    bundle, policy, keys, releases = _rollout_inputs()
    rollout = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=keys,
        releases=releases,
        clock=lambda: RELEASE_NOW,
    )
    release = _release_for(rollout, "pajin.ctf.crypto-single-byte-xor")
    activation = activate_existing_mode_capabilities(
        rollout=rollout,
        releases=(release,),
        profile=CapabilityUseProfile.RANGE,
    )
    binding = activation.activation_set.bindings[0]
    definition = bundle.definitions.resolve(binding.capability.capability)
    target = crypto_artifact_target("crypto-xor-lab", ARTIFACT_SHA256)
    source_proposal, hypotheses, plan, task, _, _ = _proposal(
        campaign,
        definition=definition,
        method="POST",
        target=target,
        target_id="crypto-xor-lab",
        threat_class="CTF-CRYPTO",
        arguments={
            "challengeId": "crypto-xor-lab",
            "scenarioId": CTFScenario.CRYPTO_SINGLE_BYTE_XOR.value,
            "artifactSha256": ARTIFACT_SHA256,
            "ciphertextHex": CIPHERTEXT_HEX,
        },
    )
    intent = compile_general_attack_action_intent(
        source_proposal,
        campaign,
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
    run_id = RunStore.new_run_id()
    graph, seeded = _seed_worker_graph(
        tmp_path / "graph" / "sup-007a.sqlite3",
        campaign=campaign,
        graph_run_id=run_id,
        request=intent.request,
    )
    decision = GraphDecision(
        campaignId=campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=intent.intent_digest,
        snapshot=seeded.snapshot,
        actorId="pajin.graph.sup-007a-planner",
        actorDigest="c" * 64,
        createdAt=_GATE_NOW - timedelta(seconds=15),
    )
    envelope = MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=run_id,
        profileId="general-attack-sup-007a",
        profileVersion="1.0.0",
        profileDigest="e" * 64,
        compilerId="pajin.general-attack.envelope-compiler",
        compilerVersion="1.0.0",
        compilerDigest="d" * 64,
        sourceCampaignDigest=campaign_manifest_digest(campaign),
        allowedCapabilities=(prepared.capability,),
        allowedTargetDigests=(sha256(intent.request.target.encode()).hexdigest(),),
        maxRiskTier=ToolRiskTier.T0,
        budget=ActionBudgetLimit(
            toolCallLimit=1,
            requestUnitLimit=definition.request_unit_cost,
            costLimitMicrousd=0,
        ),
        autonomy=AutonomyLevel.LAB_AUTONOMOUS,
        authorizedAt=_GATE_NOW - timedelta(seconds=30),
        notBefore=_GATE_NOW - timedelta(seconds=30),
        expiresAt=_GATE_NOW + timedelta(seconds=30),
    )
    reservation = ActionBudgetReservation(
        requestUnits=definition.request_unit_cost,
        costMicrousd=0,
    )
    return _PermitContext(
        campaign=campaign,
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


def _prepared_and_grant(context: _PermitContext) -> tuple[object, CapabilityGrant]:
    prepared = context.activation.prepare_action(
        release=context.activation.activation_set.bindings[0].release,
        request=context.intent.request,
        parameters=context.intent.request.arguments,
    )
    return prepared, _dispatch_grant(prepared, context.campaign)


def _execution_inputs(
    context: _PermitContext,
    grant: CapabilityGrant,
    *,
    decision=None,
    envelope=None,
) -> GeneralAttackActionExecutionInputs:
    return GeneralAttackActionExecutionInputs(
        envelope=envelope or context.envelope,
        decision=decision or context.decision,
        grant=grant,
        used_calls=0,
    )


def _gate(
    tmp_path: Path,
    context: _PermitContext,
    worker: _CountingWorker,
    execution_inputs: _StaticExecutionInputAuthority,
) -> GeneralAttackActionExecutionGate:
    tools = ToolRegistry()
    tools.register(CTFCryptoXORTool())
    return GeneralAttackActionExecutionGate(
        deployment_id="deployment:general-attack-sup-007a-test",
        run_root=tmp_path / "runs",
        activation=context.activation,
        permit_store=context.graph.permit_store,
        permit_inputs=_StaticPermitInputAuthority(_inputs(context)),
        execution_inputs=execution_inputs,
        tools=tools,
        worker=worker,
        clock=lambda: _GATE_NOW,
    )


def test_opt_in_requires_an_absolute_managed_run_root(
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    _, grant = _prepared_and_grant(context)
    tools = ToolRegistry()
    tools.register(CTFCryptoXORTool())

    with pytest.raises(TypeError, match="Run root must be absolute"):
        GeneralAttackActionExecutionGate(
            deployment_id="deployment:general-attack-sup-007a-test",
            run_root=Path("relative-runs"),
            activation=context.activation,
            permit_store=context.graph.permit_store,
            permit_inputs=_StaticPermitInputAuthority(_inputs(context)),
            execution_inputs=_StaticExecutionInputAuthority(_execution_inputs(context, grant)),
            tools=tools,
            worker=_CountingWorker(),
            clock=lambda: _GATE_NOW,
        )


async def _execute(gate: GeneralAttackActionExecutionGate, context: _PermitContext):
    return await gate.execute_once(
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
    )


@pytest.mark.asyncio
async def test_opt_in_t0_t1_executes_once_and_authenticates_sealed_outcome(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    _, grant = _prepared_and_grant(context)
    execution_inputs = _StaticExecutionInputAuthority(_execution_inputs(context, grant))
    worker = _CountingWorker()
    gate = _gate(tmp_path, context, worker, execution_inputs)

    result = await _execute(gate, context)

    assert result.permit.dispatch.dispatched is True
    assert result.permit.dispatch.result is not None
    assert result.outcome.oracle_decision.value == "succeeded"
    assert result.outcome.run_audit_anchor.deployment_id == (
        "deployment:general-attack-sup-007a-test"
    )
    assert result.outcome.permit_id == result.permit.dispatch.permit.permit_id
    assert worker.calls == 1
    events = load_verified_run_events(
        tmp_path / "runs" / context.campaign.metadata.name / context.envelope.run_id,
        expected_run_id=context.envelope.run_id,
    )
    assert events[0].event_type == CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE

    with pytest.raises(GeneralAttackActionExecutionError, match="already consumed"):
        await _execute(gate, context)
    assert worker.calls == 1


@pytest.mark.asyncio
async def test_opt_in_rejects_t2_before_runtime_inputs_and_permit(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    context = permit_context_fixture
    _, grant = _prepared_and_grant(context)
    execution_inputs = _StaticExecutionInputAuthority(_execution_inputs(context, grant))
    worker = _CountingWorker()
    gate = _gate(tmp_path, context, worker, execution_inputs)

    with pytest.raises(GeneralAttackActionExecutionError, match="T0/T1"):
        await _execute(gate, context)

    assert worker.calls == 0
    assert execution_inputs.calls == 0
    assert context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_opt_in_rejects_cross_decision_substitution_before_worker(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    _, grant = _prepared_and_grant(context)
    substituted = _replace_decision(context.decision, actorDigest="d" * 64)
    execution_inputs = _StaticExecutionInputAuthority(
        _execution_inputs(context, grant, decision=substituted)
    )
    worker = _CountingWorker()
    gate = _gate(tmp_path, context, worker, execution_inputs)

    with pytest.raises(GeneralAttackActionExecutionError, match="Permit path"):
        await _execute(gate, context)

    assert worker.calls == 0
    assert context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_opt_in_rejects_cross_grant_substitution_before_permit(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    _, grant = _prepared_and_grant(context)
    substituted = grant.model_copy(update={"targets": {"http://artifact.invalid/foreign"}})
    execution_inputs = _StaticExecutionInputAuthority(_execution_inputs(context, substituted))
    worker = _CountingWorker()
    gate = _gate(tmp_path, context, worker, execution_inputs)

    with pytest.raises(GeneralAttackActionExecutionError, match="Grant differs"):
        await _execute(gate, context)

    assert worker.calls == 0
    assert context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_opt_in_rejects_cross_run_substitution_before_worker(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    _, grant = _prepared_and_grant(context)
    raw = context.envelope.model_dump(mode="json", by_alias=True)
    raw.pop("envelopeId")
    raw.pop("envelopeDigest")
    raw["runId"] = RunStore.new_run_id()
    substituted = MissionEnvelope.model_validate(raw)
    execution_inputs = _StaticExecutionInputAuthority(
        _execution_inputs(context, grant, envelope=substituted)
    )
    worker = _CountingWorker()
    gate = _gate(tmp_path, context, worker, execution_inputs)

    with pytest.raises(GeneralAttackActionExecutionError, match="Permit path"):
        await _execute(gate, context)

    assert worker.calls == 0
    assert context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_opt_in_rejects_activation_reference_substitution_before_worker(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    _, grant = _prepared_and_grant(context)
    execution_inputs = _StaticExecutionInputAuthority(_execution_inputs(context, grant))
    worker = _CountingWorker()
    gate = _gate(tmp_path, context, worker, execution_inputs)
    raw = context.code_backed.model_dump(mode="json", by_alias=True)
    raw["capability"]["capabilityDigest"] = "f" * 64
    substituted = CodeBackedCapabilityRef.model_validate(raw)

    with pytest.raises(GeneralAttackActionExecutionError, match="Permit path"):
        await gate.execute_once(
            context.intent,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.definition.reference(),
            context.definitions,
            substituted,
            context.authorities,
        )

    assert worker.calls == 0
    assert context.graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_opt_in_rejects_substituted_run_anchor_before_permit(
    tmp_path: Path,
    low_risk_context: _PermitContext,
) -> None:
    context = low_risk_context
    _, grant = _prepared_and_grant(context)
    run_root = tmp_path / "runs"
    store = RunStore.create(
        run_root,
        context.campaign.metadata.name,
        run_id=context.envelope.run_id,
    )
    wrong = CapabilityGraphRunAuditAnchor(
        deploymentId="deployment:substituted",
        campaignId=context.campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(context.campaign),
        runId=context.envelope.run_id,
        envelopeId=context.envelope.envelope_id,
        envelopeDigest=context.envelope.envelope_digest,
        releaseSetDigest=context.activation.activation_set.release_set_digest,
        activationSetDigest=context.activation.activation_set.activation_set_digest,
        compilerId=context.envelope.compiler_id,
        compilerVersion=context.envelope.compiler_version,
        compilerDigest=context.envelope.compiler_digest,
    )
    store.append_unique_event(
        CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
        wrong.model_dump(mode="json", by_alias=True),
        occurred_at=_GATE_NOW,
    )
    store.seal()
    permit_inputs = _StaticPermitInputAuthority(_inputs(context))
    execution_inputs = _StaticExecutionInputAuthority(_execution_inputs(context, grant))
    worker = _CountingWorker()
    tools = ToolRegistry()
    tools.register(CTFCryptoXORTool())
    gate = GeneralAttackActionExecutionGate(
        deployment_id="deployment:general-attack-sup-007a-test",
        run_root=run_root,
        activation=context.activation,
        permit_store=context.graph.permit_store,
        permit_inputs=permit_inputs,
        execution_inputs=execution_inputs,
        tools=tools,
        worker=worker,
        clock=lambda: _GATE_NOW,
    )

    with pytest.raises(GeneralAttackActionExecutionError, match="anchor failed verification"):
        await _execute(gate, context)

    assert worker.calls == 0
    assert permit_inputs.calls == 0
    assert context.graph.permit_store.permits() == ()


@pytest.mark.parametrize("risk_tier", [ToolRiskTier.T2, ToolRiskTier.T3])
def test_product_ceiling_rejects_t2_and_t3_sources(
    low_risk_context: _PermitContext,
    risk_tier: ToolRiskTier,
) -> None:
    raw = low_risk_context.source_proposal.model_dump(mode="json", by_alias=True)
    raw.pop("proposalId")
    raw.pop("proposalDigest")
    raw.pop("actionSemanticsDigest")
    raw["riskTier"] = risk_tier.value
    elevated = GeneralAttackActionProposal.model_validate(raw)
    intent = low_risk_context.intent.model_copy(update={"source_proposal": elevated})

    with pytest.raises(GeneralAttackActionExecutionError, match="T0/T1"):
        GeneralAttackActionExecutionGate._require_t0_t1_no_write(intent, elevated)


def test_product_ceiling_rejects_cleanup_required_write(
    low_risk_context: _PermitContext,
) -> None:
    raw = low_risk_context.source_proposal.model_dump(mode="json", by_alias=True)
    raw.pop("proposalId")
    raw.pop("proposalDigest")
    raw.pop("actionSemanticsDigest")
    raw["cleanup"]["sideEffectClass"] = "reversible-write"
    raw["cleanup"]["cleanupRequired"] = True
    write = GeneralAttackActionProposal.model_validate(raw)
    intent = low_risk_context.intent.model_copy(update={"source_proposal": write})

    with pytest.raises(GeneralAttackActionExecutionError, match="no-write"):
        GeneralAttackActionExecutionGate._require_t0_t1_no_write(intent, write)
