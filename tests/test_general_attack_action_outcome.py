from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.capabilities import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CapabilityDispatchAuditEvent,
    CapabilityDispatchStage,
    CapabilityGraphRunAuditAnchor,
    ExistingModeCapabilityGatewayDispatcher,
    capability_grant_digest,
)
from pajin.capabilities.authorities import RegisteredCapabilityAuthority
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    ToolRequest,
    campaign_manifest_digest,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunStore
from pajin.runtime.worker import SimulatedWorkerBackend, WorkerJob, WorkerSecretRequest
from pajin.supervision import (
    GeneralAttackActionOutcomeAssessment,
    GeneralAttackActionOutcomeError,
    GeneralAttackActionOutcomeGate,
    GeneralAttackActionOutcomeInputs,
    GeneralAttackActionPermitGate,
    GeneralAttackActionPermitResult,
)
from pajin.tools import gateway as gateway_module
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, ToolGateway
from pajin.tools.mock import MockAgentProbe
from tests.test_existing_capability_rollout import (
    _dispatch_grant,
    _PermitDispatcherStub,
    _seed_worker_graph,
)
from tests.test_general_attack_action_permit import (
    _GATE_NOW,
    _dispatch,
    _gate,
    _inputs,
    _PermitContext,
    _replace_decision,
    _replace_envelope,
    _StaticPermitInputAuthority,
)
from tests.test_general_attack_action_permit import (
    permit_context as _source_permit_context,
)


@dataclass(frozen=True, slots=True)
class _AuthenticatedOutcome:
    context: _PermitContext
    permit_gate: GeneralAttackActionPermitGate
    permit_result: GeneralAttackActionPermitResult[GatewayOutcome]
    store: RunStore
    run_anchor: CapabilityGraphRunAuditAnchor
    grant: CapabilityGrant


@dataclass(frozen=True, slots=True)
class _StaticOutcomeInputAuthority:
    inputs: GeneralAttackActionOutcomeInputs

    def resolve_for_outcome(self, **_kwargs) -> GeneralAttackActionOutcomeInputs:
        return self.inputs


class _SecretMockAgentProbe(MockAgentProbe):
    def prepare(self, request: ToolRequest) -> WorkerJob:
        job = super().prepare(request)
        return job.model_copy(
            update={
                "secret_requests": [
                    WorkerSecretRequest(
                        secret_ref="secret:outcome-fixture",
                        binding="api-token",
                        ttl_seconds=30,
                    )
                ]
            },
            deep=True,
        )


class _SecretCapableSimulatedWorkerBackend(SimulatedWorkerBackend):
    async def run(self, job: WorkerJob, *, secrets=None):
        if not job.secret_requests or not secrets:
            raise AssertionError("secret fixture Worker did not receive exact secret material")
        stripped = job.model_copy(update={"secret_requests": []}, deep=True)
        return await super().run(stripped, secrets=None)


@pytest.fixture
def permit_context_fixture(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> _PermitContext:
    return _source_permit_context.__wrapped__(tmp_path, sample_campaign)


def _generated_run_context(
    context: _PermitContext,
    tmp_path: Path,
) -> _PermitContext:
    run_id = RunStore.new_run_id()
    graph, seeded = _seed_worker_graph(
        tmp_path / "graph" / "outcome.sqlite3",
        campaign=context.campaign,
        graph_run_id=run_id,
        request=context.intent.request,
    )
    return replace(
        context,
        graph=graph,
        envelope=_replace_envelope(context.envelope, runId=run_id),
        decision=_replace_decision(context.decision, snapshot=seeded.snapshot),
    )


async def _authenticated_outcome(
    tmp_path: Path,
    context: _PermitContext,
    *,
    terminal: bool = True,
    seal_anchor_before_claim: bool = True,
    secret_job: bool = False,
) -> _AuthenticatedOutcome:
    context = _generated_run_context(context, tmp_path)
    store = RunStore.create(
        tmp_path / "runs",
        context.campaign.metadata.name,
        run_id=context.envelope.run_id,
    )
    anchor = CapabilityGraphRunAuditAnchor(
        deploymentId="deployment:general-attack-outcome-test",
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
    store.append_event(
        CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
        anchor.model_dump(mode="json", by_alias=True),
        occurred_at=_GATE_NOW,
    )
    if seal_anchor_before_claim:
        store.seal()
    tools = ToolRegistry()
    tools.register(_SecretMockAgentProbe() if secret_job else MockAgentProbe())
    secrets = SecretBroker(clock=lambda: _GATE_NOW)
    if secret_job:
        secrets.register("secret:outcome-fixture", "fixture-secret-value")
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=tools,
        worker=(
            _SecretCapableSimulatedWorkerBackend()
            if secret_job
            else SimulatedWorkerBackend()
        ),
        store=store,
        secrets=secrets,
        clock=lambda: _GATE_NOW,
    )
    grant = _dispatch_grant(
        context.activation.prepare_action(
            release=context.activation.activation_set.bindings[0].release,
            request=context.intent.request,
            parameters=context.intent.request.arguments,
        ),
        context.campaign,
    )
    permit_gate = _gate(
        context,
        _StaticPermitInputAuthority(_inputs(context)),
    )

    async def consume(permit, prepared, proposal) -> GatewayOutcome:
        if terminal:
            dispatcher = ExistingModeCapabilityGatewayDispatcher(
                activation=context.activation,
                permits=_PermitDispatcherStub(permit),
                gateway=gateway,
                audit_store=store,
                clock=lambda: _GATE_NOW,
            )
            dispatched = await dispatcher.dispatch_once(
                context.envelope,
                proposal,
                context.decision,
                prepared,
                campaign=context.campaign,
                grant=grant,
                used_calls=0,
            )
            assert dispatched.result is not None
            return dispatched.result

        claimed = CapabilityDispatchAuditEvent(
            stage=CapabilityDispatchStage.CLAIMED,
            occurredAt=_GATE_NOW,
            activationSetDigest=prepared.activation_set_digest,
            release=prepared.release,
            permitId=permit.permit_id,
            permitDigest=permit.permit_digest,
            dispatchId=permit.dispatch_id,
            campaignId=permit.campaign_id,
            runId=permit.run_id,
            proposalId=permit.proposal_id,
            proposalDigest=permit.proposal_digest,
            requestId=permit.request_id,
            requestDigest=permit.request_digest,
            normalizedParametersDigest=permit.normalized_parameters_digest,
            capabilityGrantDigest=capability_grant_digest(grant),
        )
        store.append_event(
            "capability.dispatch.claimed",
            claimed.model_dump(mode="json", by_alias=True),
            occurred_at=claimed.occurred_at,
        )
        return await gateway.execute(
            context.campaign,
            grant,
            prepared.request,
            used_calls=0,
        )

    permit_result = await _dispatch(permit_gate, context, consume)
    store.seal()
    return _AuthenticatedOutcome(
        context=context,
        permit_gate=permit_gate,
        permit_result=permit_result,
        store=store,
        run_anchor=anchor,
        grant=grant,
    )


def _outcome_inputs(
    authenticated: _AuthenticatedOutcome,
) -> GeneralAttackActionOutcomeInputs:
    return GeneralAttackActionOutcomeInputs(
        run_path=authenticated.store.path,
        run_anchor=authenticated.run_anchor,
        grant=authenticated.grant,
    )


def _outcome_gate(
    authenticated: _AuthenticatedOutcome,
    *,
    inputs: GeneralAttackActionOutcomeInputs | None = None,
) -> GeneralAttackActionOutcomeGate:
    return GeneralAttackActionOutcomeGate(
        activation=authenticated.context.activation,
        permit_store=authenticated.context.graph.permit_store,
        inputs=_StaticOutcomeInputAuthority(inputs or _outcome_inputs(authenticated)),
    )


def _assess(
    authenticated: _AuthenticatedOutcome,
    *,
    result: GeneralAttackActionPermitResult[GatewayOutcome] | None = None,
    gate: GeneralAttackActionOutcomeGate | None = None,
) -> GeneralAttackActionOutcomeAssessment:
    context = authenticated.context
    return (gate or _outcome_gate(authenticated)).assess(
        authenticated.permit_result if result is None else result,
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
async def test_outcome_gate_binds_sealed_result_oracle_data_flow_and_cleanup(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)

    assessment = _assess(authenticated)

    assert assessment.oracle_decision.value == "succeeded"
    assert assessment.side_effect_class.value == "none"
    assert assessment.side_effect_absence_attested is False
    assert assessment.data_flow.state == "network-disabled-no-egress-observed"
    assert assessment.data_flow.information_flow_attested is False
    assert assessment.cleanup_required is False
    assert assessment.cleanup_plan_created is False
    assert assessment.cleanup_permit_issued is False
    assert assessment.cleanup_execution_authorized is False
    assert assessment.executor_job_bound is False
    assert assessment.finding_authority is False
    assert assessment.redispatch_allowed is False
    assert assessment.evidence.path == (
        f"evidence/{authenticated.permit_result.dispatch.permit.request_id}.json"
    )
    assert assessment.evidence.sha256
    assert assessment.gateway_outcome_digest
    assert assessment.run_audit_anchor == authenticated.run_anchor
    assert assessment.run_audit_anchor_seal_root_digest
    assert assessment.capability_grant_digest == capability_grant_digest(
        authenticated.grant
    )


@pytest.mark.asyncio
async def test_outcome_gate_accepts_exact_gateway_secret_lease_wire(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(
        tmp_path,
        permit_context_fixture,
        secret_job=True,
    )

    assessment = _assess(authenticated)

    assert assessment.oracle_decision.value == "succeeded"


@pytest.mark.asyncio
async def test_outcome_gate_rejects_foreign_secret_lease_scope(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_revoke = SecretBroker.revoke

    def forge_scope(self, lease_id, reason, *, scope=None):
        revoked = original_revoke(self, lease_id, reason, scope=scope)
        return revoked.model_copy(update={"scope": "run_foreign"}, deep=True)

    monkeypatch.setattr(SecretBroker, "revoke", forge_scope)
    authenticated = await _authenticated_outcome(
        tmp_path,
        permit_context_fixture,
        secret_job=True,
    )

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        _assess(authenticated)

    assert "secret lease differs" in str(failure.value.__cause__)


@pytest.mark.asyncio
async def test_outcome_gate_rejects_exact_retry_without_result(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)

    async def forbidden(*_args):
        raise AssertionError("exact retry reached the dispatch callback")

    retry = await _dispatch(
        authenticated.permit_gate,
        authenticated.context,
        forbidden,
    )

    with pytest.raises(GeneralAttackActionOutcomeError):
        _assess(authenticated, result=retry)


@pytest.mark.asyncio
async def test_outcome_gate_rejects_claimed_outcome_unknown(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(
        tmp_path,
        permit_context_fixture,
        terminal=False,
    )

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        _assess(authenticated)

    assert "sealed completed dispatch" in str(failure.value.__cause__)


@pytest.mark.asyncio
async def test_outcome_gate_rejects_forged_live_gateway_result(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)
    original = authenticated.permit_result
    outcome = original.dispatch.result
    assert outcome is not None
    forged_tool_result = outcome.result.model_copy(
        update={"data": {"simulation": {"authorized": True}}},
        deep=True,
    )
    forged_outcome = outcome.model_copy(update={"result": forged_tool_result}, deep=True)
    forged = replace(
        original,
        dispatch=replace(original.dispatch, result=forged_outcome),
    )

    with pytest.raises(GeneralAttackActionOutcomeError):
        _assess(authenticated, result=forged)


@pytest.mark.asyncio
async def test_outcome_gate_rejects_grant_substitution_from_result_authority(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)
    forged_grant = authenticated.grant.model_copy(
        update={"grant_id": "grant_forged-result-authority"},
        deep=True,
    )
    gate = _outcome_gate(
        authenticated,
        inputs=replace(_outcome_inputs(authenticated), grant=forged_grant),
    )

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        _assess(authenticated, gate=gate)

    assert "terminal dispatch differs" in str(failure.value.__cause__)


@pytest.mark.asyncio
async def test_outcome_gate_rejects_authority_run_missing_result_evidence(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)
    alternate = RunStore.create(
        tmp_path / "alternate-runs",
        authenticated.context.campaign.metadata.name,
        run_id=authenticated.context.envelope.run_id,
    )
    alternate.append_event(
        CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
        authenticated.run_anchor.model_dump(mode="json", by_alias=True),
        occurred_at=_GATE_NOW,
    )
    alternate.seal()
    gate = _outcome_gate(
        authenticated,
        inputs=replace(_outcome_inputs(authenticated), run_path=alternate.path),
    )

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        _assess(authenticated, gate=gate)

    assert "not sealed by this Run" in str(failure.value.__cause__)


@pytest.mark.asyncio
async def test_outcome_gate_rejects_anchor_first_sealed_with_claim(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(
        tmp_path,
        permit_context_fixture,
        seal_anchor_before_claim=False,
    )

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        _assess(authenticated)

    assert "pre-claim integrity seal" in str(failure.value.__cause__)


@pytest.mark.asyncio
async def test_outcome_gate_rejects_evidence_job_different_from_dispatch_audit(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    original = gateway_module.safe_job_metadata

    def forge_second_projection(*args, **kwargs):
        nonlocal calls
        calls += 1
        metadata = original(*args, **kwargs)
        if calls == 2:
            metadata["image"] = "foreign.example/forged:latest"
        return metadata

    monkeypatch.setattr(gateway_module, "safe_job_metadata", forge_second_projection)
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        _assess(authenticated)

    assert "differs from Worker dispatch audit" in str(failure.value.__cause__)


@pytest.mark.asyncio
async def test_outcome_gate_rejects_mutated_sealed_evidence(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)
    oracle_calls = 0
    original_evaluate = RegisteredCapabilityAuthority.evaluate

    def track_oracle(self, request, result):
        nonlocal oracle_calls
        oracle_calls += 1
        return original_evaluate(self, request, result)

    monkeypatch.setattr(RegisteredCapabilityAuthority, "evaluate", track_oracle)
    evidence = authenticated.store.path / (
        f"evidence/{authenticated.permit_result.dispatch.permit.request_id}.json"
    )
    evidence.write_bytes(b"{}")

    with pytest.raises(GeneralAttackActionOutcomeError):
        _assess(authenticated)
    assert oracle_calls == 0


@pytest.mark.asyncio
async def test_outcome_gate_binds_executor_identity_without_preparing_second_job(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)

    def forbidden_prepare(self, request):
        del self, request
        raise AssertionError("outcome assessment prepared a second Worker job")

    monkeypatch.setattr(
        RegisteredCapabilityAuthority,
        "prepare",
        forbidden_prepare,
    )

    assessment = _assess(authenticated)

    assert assessment.executor_job_bound is False


@pytest.mark.asyncio
async def test_outcome_gate_rejects_permit_absent_from_current_store(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)

    class _MissingPermitStore:
        def permit(self, _permit_id: str):
            return None

    gate = GeneralAttackActionOutcomeGate(
        activation=authenticated.context.activation,
        permit_store=_MissingPermitStore(),
        inputs=_StaticOutcomeInputAuthority(
            GeneralAttackActionOutcomeInputs(
                run_path=authenticated.store.path,
                run_anchor=authenticated.run_anchor,
                grant=authenticated.grant,
            )
        ),
    )
    context = authenticated.context
    with pytest.raises(GeneralAttackActionOutcomeError):
        gate.assess(
            authenticated.permit_result,
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
async def test_outcome_gate_rejects_cleanup_plan_without_cleanup_authority(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)

    def forged_cleanup(self, request, result):
        del self, request, result
        return {"delete": "target"}

    monkeypatch.setattr(
        RegisteredCapabilityAuthority,
        "plan_cleanup",
        forged_cleanup,
    )

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        _assess(authenticated)

    assert "returned a cleanup plan" in str(failure.value.__cause__)


@pytest.mark.asyncio
async def test_outcome_gate_wraps_authority_runtime_error(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)

    def explode(self, request, result):
        del self, request, result
        raise RuntimeError("adapter exploded")

    monkeypatch.setattr(RegisteredCapabilityAuthority, "evaluate", explode)

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        _assess(authenticated)

    assert type(failure.value.__cause__) is RuntimeError


@pytest.mark.asyncio
async def test_outcome_assessment_requires_exact_gate_reverification(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    authenticated = await _authenticated_outcome(tmp_path, permit_context_fixture)
    gate = _outcome_gate(authenticated)
    assessment = _assess(authenticated, gate=gate)
    forged_payload = assessment.model_dump(mode="json", by_alias=True)
    forged_payload.pop("assessmentId")
    forged_payload.pop("assessmentDigest")
    forged_payload["dataFlow"]["networkLogDigest"] = "f" * 64
    forged = GeneralAttackActionOutcomeAssessment.model_validate(forged_payload)
    context = authenticated.context

    with pytest.raises(GeneralAttackActionOutcomeError) as failure:
        gate.verify_assessment(
            forged,
            authenticated.permit_result,
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

    assert "differs from current authority" in str(failure.value.__cause__)


@pytest.mark.asyncio
async def test_outcome_assessment_rejects_write_and_untrusted_egress_claims(
    tmp_path: Path,
    permit_context_fixture: _PermitContext,
) -> None:
    assessment = _assess(await _authenticated_outcome(tmp_path, permit_context_fixture))
    write = assessment.model_dump(mode="json", by_alias=True)
    write.pop("assessmentId")
    write.pop("assessmentDigest")
    write["sideEffectClass"] = "reversible-write"

    with pytest.raises(ValidationError, match="one-shot cleanup authority"):
        GeneralAttackActionOutcomeAssessment.model_validate(write)

    untrusted = assessment.model_dump(mode="json", by_alias=True)
    untrusted.pop("assessmentId")
    untrusted.pop("assessmentDigest")
    untrusted["dataFlow"]["workerNetworkMode"] = "egress-proxy"
    untrusted["dataFlow"]["declaredNetworkAccess"] = False
    untrusted["dataFlow"]["networkLogTrusted"] = False
    untrusted["dataFlow"]["state"] = "network-enabled-host-observation-bound"

    with pytest.raises(ValidationError, match="trusted declared egress"):
        GeneralAttackActionOutcomeAssessment.model_validate(untrusted)
