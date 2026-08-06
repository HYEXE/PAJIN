from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import JsonValue

from pajin.capabilities import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CapabilityDefinitionRegistry,
    CapabilityGraphRunAuditAnchor,
    CapabilityLifecyclePolicy,
    CapabilityMaturity,
    CapabilityOracleDecision,
    CapabilitySideEffectClass,
    CapabilityToolBinding,
    ExistingModeCapabilityBundle,
    ExistingModeCapabilityGatewayDispatcher,
    activate_existing_mode_capabilities,
    admit_existing_mode_capability_releases,
    capability_grant_digest,
)
from pajin.capabilities.models import CapabilityDefinition
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CapabilityGrant,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph import (
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
    ActionBudgetLimit,
    ActionPermit,
    GraphDecision,
    GraphDecisionKind,
    MissionEnvelope,
    action_permit_attempt_id,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.store import RunStore
from pajin.runtime.worker import (
    NetworkMode,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.supervision import (
    CleanupCapabilityMappingRegistry,
    GeneralAttackActionCleanupError,
    GeneralAttackActionCleanupGate,
    GeneralAttackActionOutcomeGate,
    GeneralAttackActionOutcomeInputs,
    GeneralAttackActionPermitError,
    GeneralAttackActionPermitGate,
    GeneralAttackActionPermitInputs,
    GeneralAttackApprovalClaim,
    GeneralAttackCleanupReservationInputs,
    GeneralAttackReversibleCleanupBinder,
    compile_general_attack_action_intent,
)
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.tools.gateway import GatewayOutcome, ToolGateway
from tests.test_existing_capability_rollout import (
    NOW as RELEASE_NOW,
)
from tests.test_existing_capability_rollout import (
    _PermitDispatcherStub,
    _release_for,
    _seed_worker_graph,
    _signed_releases,
    _signing_authority,
)
from tests.test_general_attack_action_permit import _GATE_NOW
from tests.test_general_attack_action_proposal import _proposal

SOURCE_CAPABILITY = "pajin.bug-bounty.boolean-sqli-lab"
CLEANUP_CAPABILITY = "pajin.ctf.web-exposed-backup-config"
DUMMY_CAPABILITIES = (
    "pajin.ai.kisa.indirect-tool-hijacking",
    "pajin.ai.kisa.jailbreak-policy-bypass",
    "pajin.ai.kisa.memory-poisoning-persistence",
    "pajin.ai.kisa.system-prompt-disclosure",
    "pajin.ctf.crypto-single-byte-xor",
)
SOURCE_TOOL = "test.state-write"
CLEANUP_TOOL = "test.state-restore"
BASELINE = b"baseline"
CHANGED = b"changed"
BASELINE_DIGEST = sha256(BASELINE).hexdigest()
SOURCE_NOW = _GATE_NOW
CLEANUP_NOW = SOURCE_NOW + timedelta(minutes=1)


def _cleanup_plan(
    *,
    state: str = "baseline",
    expected_state_digest: str = BASELINE_DIGEST,
    operation: str = "restore-target",
) -> dict[str, JsonValue]:
    return {
        "apiVersion": "pajin.dev/general-attack-cleanup-plan/v1alpha1",
        "kind": "GeneralAttackCleanupPlan",
        "operation": operation,
        "parameters": {"state": state},
        "expectedStateDigest": expected_state_digest,
    }


class _StateTool(Tool):
    def __init__(self, *, tool_id: str, command: str) -> None:
        self.spec = ToolSpec(
            tool_id=tool_id,
            version="1.0.0",
            description=f"isolated {command} fixture",
            risk_tier=ToolRiskTier.T1,
            categories=frozenset({"active-test"}),
            evidence_types=frozenset({"state-digest"}),
            network_access=False,
            network_request_cost=1,
            parallel_safe=False,
        )
        self._command = command

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "toolId": self.spec.tool_id,
            "toolVersion": self.spec.version,
            "command": self._command,
        }

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.tool_id != self.spec.tool_id or request.method != "POST":
            raise ValueError("state fixture request identity differs")
        return WorkerJob(
            image="pajin-state-fixture:dev",
            command=[self._command],
            stdin=json.dumps(request.arguments, sort_keys=True),
            network=NetworkMode.NONE,
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error="fixture Worker failed",
            )
        payload = json.loads(result.stdout)
        expected_digest = (
            sha256(CHANGED).hexdigest()
            if self._command == "write-state"
            else sha256(BASELINE).hexdigest()
        )
        if payload != {"stateDigest": expected_digest}:
            raise ValueError("state fixture Worker output differs")
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=payload,
        )


class _StateWorker:
    def __init__(self, state_path: Path) -> None:
        self._state_path = state_path
        self.calls: list[str] = []

    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.state-worker/v1"}

    async def run(self, job: WorkerJob, *, secrets=None) -> WorkerResult:
        if secrets or job.network is not NetworkMode.NONE:
            raise AssertionError("state fixture received expanded Worker authority")
        command = job.command[0]
        self.calls.append(command)
        if command == "write-state":
            self._state_path.write_bytes(CHANGED)
        elif command == "restore-state":
            self._state_path.write_bytes(BASELINE)
        else:
            raise AssertionError("unknown state fixture command")
        digest = sha256(self._state_path.read_bytes()).hexdigest()
        occurred_at = SOURCE_NOW if command == "write-state" else CLEANUP_NOW
        return WorkerResult(
            execution_id=job.execution_id,
            backend="state-fixture",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps({"stateDigest": digest}, sort_keys=True),
            started_at=occurred_at,
            finished_at=occurred_at + timedelta(milliseconds=1),
        )


class _RuntimeClock:
    def __init__(self) -> None:
        self.value = SOURCE_NOW

    def __call__(self):
        return self.value


class _AuthorityAdapter:
    ROLE: ClassVar[CapabilityAuthorityRole]

    def __init__(
        self,
        *,
        role: CapabilityAuthorityRole,
        definition: CapabilityDefinition,
        tool: _StateTool,
        cleanup_plans: list[dict[str, JsonValue]] | None = None,
    ) -> None:
        self.ROLE = role
        self._definition = definition
        self._tool = tool
        self._cleanup_plans = cleanup_plans
        self.cleanup_plan_calls = 0

    @property
    def authority_role(self) -> CapabilityAuthorityRole:
        return self.ROLE

    @property
    def authority_id(self) -> str:
        return f"{self._definition.capability_id}.{self.ROLE.value}"

    @property
    def authority_version(self) -> str:
        return "1.0.0"

    @property
    def capability_reference(self):
        return self._definition.reference()

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "role": self.ROLE.value,
            "tool": self._tool.stable_execution_context(),
            "fixture": "isolated-reversible-cleanup",
        }

    def materialize(self, parameters: Mapping[str, JsonValue]):
        return dict(parameters)

    def compile(
        self,
        request: ToolRequest,
        materialized_arguments: Mapping[str, JsonValue],
    ) -> ToolRequest:
        return request.model_copy(update={"arguments": dict(materialized_arguments)}, deep=True)

    def prepare(self, request: ToolRequest) -> WorkerJob:
        return self._tool.prepare(request)

    def normalize(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        return self._tool.interpret(request, result)

    def evaluate(self, request: ToolRequest, result: ToolResult):
        del request
        return (
            CapabilityOracleDecision.SUCCEEDED
            if result.success
            else CapabilityOracleDecision.FAILED
        )

    def plan_replay(self, request: ToolRequest, result: ToolResult):
        del request, result
        return None

    def plan_cleanup(self, request: ToolRequest, result: ToolResult):
        del request, result
        if self._definition.capability_id != SOURCE_CAPABILITY:
            return None
        default_plan = _cleanup_plan()
        sequence = self._cleanup_plans or [default_plan]
        selected = sequence[min(self.cleanup_plan_calls, len(sequence) - 1)]
        self.cleanup_plan_calls += 1
        return dict(selected)

    def set_cleanup_plans(self, *plans: dict[str, JsonValue]) -> None:
        if self._cleanup_plans is None:
            raise AssertionError("fixture adapter is not the source Cleanup Handler")
        self._cleanup_plans[:] = plans
        self.cleanup_plan_calls = 0


class _MappingAdapter:
    def __init__(self, source, cleanup) -> None:
        self._source = source
        self._cleanup = cleanup

    @property
    def authority_id(self) -> str:
        return "test.general-attack.cleanup-mapping"

    @property
    def authority_version(self) -> str:
        return "1.0.0"

    @property
    def source_capability(self):
        return self._source

    @property
    def cleanup_binding(self):
        return self._cleanup

    @property
    def cleanup_method(self) -> str:
        return "POST"

    def stable_execution_context(self) -> Mapping[str, object]:
        return {"mapping": "write-to-restore", "expectedState": BASELINE_DIGEST}


class _PermitInputs:
    def __init__(self, value: GeneralAttackActionPermitInputs) -> None:
        self._value = value

    def resolve_for_action(self, **_kwargs):
        return self._value


class _ReservationInputs:
    def __init__(self, claim_expires_at) -> None:
        self._claim_expires_at = claim_expires_at

    def resolve_for_cleanup_reservation(self, **_kwargs):
        return GeneralAttackCleanupReservationInputs(
            cost_microusd=0,
            claim_expires_at=self._claim_expires_at,
        )


class _ApprovalInputAuthority:
    def verify_action_approval(self, envelope, proposal, decision, approval) -> None:
        if (
            approval.mission_envelope != envelope
            or approval.proposal != proposal
            or approval.graph_decision != decision
        ):
            raise ValueError("fixture approval lineage differs")


class _ApprovalAuthority:
    def __init__(self, issuer: ActionApprovalIssuerAuthorityBinding) -> None:
        self.issuer = issuer

    def bind_for_action(
        self,
        *,
        intent,
        prepared,
        proposal,
        campaign,
        definition,
        envelope,
        decision,
        evaluated_at,
    ) -> GeneralAttackApprovalClaim:
        approval = ActionApprovalEnvelope(
            issuer=self.issuer,
            requestedBy="principal:general-attack-planner",
            approvedBy="principal:range-operator",
            campaignId=campaign.metadata.name,
            campaignDigest=campaign_manifest_digest(campaign),
            runId=envelope.run_id,
            missionEnvelope=envelope,
            sourceIntentDigest=intent.intent_digest,
            activationSetDigest=prepared.activation_set_digest,
            release=ActionApprovalReleaseRef(
                releaseId=prepared.release.release_id,
                releaseDigest=prepared.release.release_digest,
                capabilityId=prepared.capability.capability_id,
                capabilityVersion=prepared.capability.capability_version,
                capabilityDigest=prepared.capability.definition_digest,
            ),
            graphDecision=decision,
            proposal=proposal,
            expectedActionPermitId=action_permit_attempt_id(
                envelope,
                proposal,
                decision,
            ),
            sideEffectClass=definition.side_effect_class.value,
            cleanupRequired=definition.cleanup_required,
            reservation=proposal.reservation,
            approvedAt=evaluated_at,
            notBefore=evaluated_at,
            expiresAt=min(
                envelope.expires_at,
                evaluated_at + timedelta(minutes=2),
            ),
        )
        return GeneralAttackApprovalClaim(envelope=approval)


class _UnexpectedCleanupAuthority:
    def __init__(self) -> None:
        self.calls = 0

    def bind_for_action(self, **_kwargs):
        self.calls += 1
        raise AssertionError("ineligible write reached cleanup hold authority")


class _OutcomeInputs:
    def __init__(self, value: GeneralAttackActionOutcomeInputs) -> None:
        self._value = value

    def resolve_for_outcome(self, **_kwargs):
        return self._value


class _GrantInputs:
    def __init__(self, *, expires_at=None) -> None:
        self._expires_at = expires_at or (CLEANUP_NOW + timedelta(seconds=20))

    def resolve_for_cleanup(
        self,
        *,
        request,
        prepared,
        source_grant,
        source_terminal_occurred_at,
        envelope,
        campaign,
    ) -> CapabilityGrant:
        del request, source_grant, campaign
        return CapabilityGrant(
            grant_id="grant_general_attack_cleanup",
            subject=prepared.request.agent_id,
            campaign=envelope.campaign_id,
            tools={prepared.request.tool_id},
            targets={prepared.request.target},
            max_risk_tier=prepared.capability.risk_tier,
            max_calls=1,
            delegable=False,
            issued_at=source_terminal_occurred_at + timedelta(seconds=1),
            expires_at=self._expires_at,
        )


class _StateVerifier:
    def __init__(self, state_path: Path, *, forged: bool = False) -> None:
        self._state_path = state_path
        self._forged = forged

    @property
    def authority_id(self) -> str:
        return "test.general-attack.restored-state-verifier"

    @property
    def authority_version(self) -> str:
        return "1.0.0"

    def stable_execution_context(self) -> Mapping[str, object]:
        return {"algorithm": "sha256", "fixture": "isolated-state-file"}

    def observe_state_digest(self, **_kwargs) -> str:
        if self._forged:
            return sha256(CHANGED).hexdigest()
        return sha256(self._state_path.read_bytes()).hexdigest()


@dataclass(frozen=True, slots=True)
class _Context:
    campaign: CampaignManifest
    source_definition: CapabilityDefinition
    cleanup_definition: CapabilityDefinition
    definitions: CapabilityDefinitionRegistry
    authorities: CapabilityAuthorityRegistry
    activation: object
    source_binding: object
    cleanup_binding: object
    source_cleanup_handler: _AuthorityAdapter
    source_proposal: object
    hypotheses: object
    plan: object
    task: object
    intent: object
    graph: object
    envelope: MissionEnvelope
    source_decision: GraphDecision
    run_store: RunStore
    run_anchor: CapabilityGraphRunAuditAnchor
    source_grant: CapabilityGrant
    worker: _StateWorker
    tools: ToolRegistry
    runtime_clock: _RuntimeClock
    state_path: Path


def _definition(
    *,
    capability_id: str,
    tool_id: str,
    cleanup_required: bool,
    approval_required: bool = False,
    side_effect_class: CapabilitySideEffectClass = (
        CapabilitySideEffectClass.REVERSIBLE_WRITE
    ),
    risk_tier: ToolRiskTier = ToolRiskTier.T1,
) -> CapabilityDefinition:
    return CapabilityDefinition(
        capabilityId=capability_id,
        capabilityVersion="1.0.0",
        domain="ai-redteam",
        maturity=CapabilityMaturity.EXPERIMENTAL,
        supportedSurfaceTypes=("mock-agent",),
        threatClasses=("A02",),
        parameterSchemaDigest=sha256(f"schema:{capability_id}".encode()).hexdigest(),
        tool=CapabilityToolBinding(
            toolId=tool_id,
            toolVersion="1.0.0",
            toolDigest=sha256(f"tool:{tool_id}".encode()).hexdigest(),
        ),
        riskTier=risk_tier,
        sideEffectClass=side_effect_class,
        evidenceTypes=("state-digest",),
        networkAccess=False,
        approvalRequired=approval_required,
        requestUnitCost=1,
        cleanupRequired=cleanup_required,
        parallelSafe=False,
    )


def _context(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    source_cleanup_required: bool = True,
    source_approval_required: bool = False,
    source_risk_tier: ToolRiskTier = ToolRiskTier.T1,
    source_side_effect: CapabilitySideEffectClass = (
        CapabilitySideEffectClass.REVERSIBLE_WRITE
    ),
) -> _Context:
    state_path = tmp_path / "target-state.bin"
    state_path.write_bytes(BASELINE)
    source_tool = _StateTool(tool_id=SOURCE_TOOL, command="write-state")
    cleanup_tool = _StateTool(tool_id=CLEANUP_TOOL, command="restore-state")
    source_definition = _definition(
        capability_id=SOURCE_CAPABILITY,
        tool_id=SOURCE_TOOL,
        cleanup_required=source_cleanup_required,
        approval_required=source_approval_required,
        side_effect_class=source_side_effect,
        risk_tier=source_risk_tier,
    )
    cleanup_definition = _definition(
        capability_id=CLEANUP_CAPABILITY,
        tool_id=CLEANUP_TOOL,
        cleanup_required=False,
    )
    dummy_definitions = tuple(
        _definition(
            capability_id=capability_id,
            tool_id=SOURCE_TOOL,
            cleanup_required=False,
        )
        for capability_id in DUMMY_CAPABILITIES
    )
    definitions = CapabilityDefinitionRegistry(
        (source_definition, cleanup_definition, *dummy_definitions)
    )
    tool_by_capability = {
        SOURCE_CAPABILITY: source_tool,
        CLEANUP_CAPABILITY: cleanup_tool,
        **{item.capability_id: source_tool for item in dummy_definitions},
    }
    cleanup_plans: list[dict[str, JsonValue]] = []
    adapters_list: list[_AuthorityAdapter] = []
    source_cleanup_handler: _AuthorityAdapter | None = None
    for definition in (source_definition, cleanup_definition, *dummy_definitions):
        for role in CapabilityAuthorityRole:
            adapter = _AuthorityAdapter(
                role=role,
                definition=definition,
                tool=tool_by_capability[definition.capability_id],
                cleanup_plans=(
                    cleanup_plans
                    if definition == source_definition
                    and role is CapabilityAuthorityRole.CLEANUP_HANDLER
                    else None
                ),
            )
            adapters_list.append(adapter)
            if (
                definition == source_definition
                and role is CapabilityAuthorityRole.CLEANUP_HANDLER
            ):
                source_cleanup_handler = adapter
    assert source_cleanup_handler is not None
    adapters = tuple(adapters_list)
    authorities = CapabilityAuthorityRegistry(definitions, adapters)
    bundle = ExistingModeCapabilityBundle(definitions=definitions, authorities=authorities)
    policy = CapabilityLifecyclePolicy.reference_policy()
    keys, publisher, reviewer = _signing_authority()
    releases = _signed_releases(
        bundle,
        policy=policy,
        publisher=publisher,
        reviewer=reviewer,
    )
    rollout = admit_existing_mode_capability_releases(
        bundle=bundle,
        policy=policy,
        trust_keys=keys,
        releases=releases,
        clock=lambda: RELEASE_NOW,
    )
    source_release = _release_for(rollout, SOURCE_CAPABILITY)
    cleanup_release = _release_for(rollout, CLEANUP_CAPABILITY)
    activation = activate_existing_mode_capabilities(
        rollout=rollout,
        releases=(source_release, cleanup_release),
        profile="range",
    )
    source_binding = next(
        item
        for item in activation.activation_set.bindings
        if item.capability.capability.capability_id == SOURCE_CAPABILITY
    )
    cleanup_binding = next(
        item
        for item in activation.activation_set.bindings
        if item.capability.capability.capability_id == CLEANUP_CAPABILITY
    )
    source_proposal, hypotheses, plan, task, _, _ = _proposal(
        sample_campaign,
        definition=source_definition,
        arguments={"state": "changed"},
    )
    intent = compile_general_attack_action_intent(
        source_proposal,
        sample_campaign,
        hypotheses,
        plan,
        task.task_digest,
        source_definition.reference(),
        definitions,
        source_binding.capability,
        authorities,
    )
    run_id = RunStore.new_run_id()
    graph, seeded = _seed_worker_graph(
        tmp_path / "graph" / "cleanup.sqlite3",
        campaign=sample_campaign,
        graph_run_id=run_id,
        request=intent.request,
    )
    source_decision = GraphDecision(
        campaignId=sample_campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=intent.intent_digest,
        snapshot=seeded.snapshot,
        actorId="test.general-attack.source-decision",
        actorDigest="a" * 64,
        createdAt=SOURCE_NOW - timedelta(seconds=1),
    )
    prepared = activation.prepare_action(
        release=source_binding.release,
        request=intent.request,
        parameters=intent.request.arguments,
    )
    envelope = MissionEnvelope(
        campaignId=sample_campaign.metadata.name,
        runId=run_id,
        profileId="general-attack-cleanup-fixture",
        profileVersion="1.0.0",
        profileDigest="b" * 64,
        compilerId="test.general-attack.cleanup-compiler",
        compilerVersion="1.0.0",
        compilerDigest="c" * 64,
        sourceCampaignDigest=campaign_manifest_digest(sample_campaign),
        allowedCapabilities=(
            source_binding.action_capability.reference(),
            cleanup_binding.action_capability.reference(),
        ),
        allowedTargetDigests=(intent.target_digest,),
        maxRiskTier=max(
            source_binding.action_capability.risk_tier,
            cleanup_binding.action_capability.risk_tier,
        ),
        budget=ActionBudgetLimit(
            toolCallLimit=2,
            requestUnitLimit=2,
            costLimitMicrousd=0,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=SOURCE_NOW - timedelta(minutes=10),
        notBefore=SOURCE_NOW - timedelta(minutes=5),
        expiresAt=SOURCE_NOW + timedelta(minutes=5),
    )
    run_store = RunStore.create(
        tmp_path / "runs",
        sample_campaign.metadata.name,
        run_id=run_id,
    )
    anchor = CapabilityGraphRunAuditAnchor(
        deploymentId="test.general-attack.cleanup-deployment",
        campaignId=sample_campaign.metadata.name,
        campaignDigest=campaign_manifest_digest(sample_campaign),
        runId=run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        releaseSetDigest=activation.activation_set.release_set_digest,
        activationSetDigest=activation.activation_set.activation_set_digest,
        compilerId=envelope.compiler_id,
        compilerVersion=envelope.compiler_version,
        compilerDigest=envelope.compiler_digest,
    )
    run_store.append_event(
        CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
        anchor.model_dump(mode="json", by_alias=True),
        occurred_at=SOURCE_NOW - timedelta(seconds=2),
    )
    run_store.seal()
    source_grant = CapabilityGrant(
        grant_id="grant_general_attack_source_write",
        subject=prepared.request.agent_id,
        campaign=sample_campaign.metadata.name,
        tools={prepared.request.tool_id},
        targets={prepared.request.target},
        max_risk_tier=prepared.capability.risk_tier,
        max_calls=1,
        issued_at=SOURCE_NOW - timedelta(minutes=1),
        expires_at=envelope.expires_at,
    )
    tools = ToolRegistry()
    tools.register(source_tool)
    tools.register(cleanup_tool)
    runtime_clock = _RuntimeClock()
    return _Context(
        campaign=sample_campaign,
        source_definition=source_definition,
        cleanup_definition=cleanup_definition,
        definitions=definitions,
        authorities=authorities,
        activation=activation,
        source_binding=source_binding,
        cleanup_binding=cleanup_binding,
        source_cleanup_handler=source_cleanup_handler,
        source_proposal=source_proposal,
        hypotheses=hypotheses,
        plan=plan,
        task=task,
        intent=intent,
        graph=graph,
        envelope=envelope,
        source_decision=source_decision,
        run_store=run_store,
        run_anchor=anchor,
        source_grant=source_grant,
        worker=_StateWorker(state_path),
        tools=tools,
        runtime_clock=runtime_clock,
        state_path=state_path,
    )


async def _execute_source(context: _Context):
    mappings = CleanupCapabilityMappingRegistry(
        activation=context.activation,
        adapters=(
            _MappingAdapter(context.source_binding.capability, context.cleanup_binding),
        ),
    )
    binder = GeneralAttackReversibleCleanupBinder(
        activation=context.activation,
        mappings=mappings,
        inputs=_ReservationInputs(context.envelope.expires_at),
    )
    approval = None
    approval_input = None
    approval_issuer = None
    if (
        context.source_binding.action_capability.risk_tier >= ToolRiskTier.T2
        or context.source_definition.approval_required
    ):
        approval_issuer = ActionApprovalIssuerAuthorityBinding(
            authorityId="deployment:general-attack-cleanup-operator",
            authorityVersion="1.0.0",
            implementationType="tests.cleanup.StaticApprovalAuthority",
            contextDigest=campaign_manifest_digest(context.campaign),
        )
        approval = _ApprovalAuthority(approval_issuer)
        approval_input = _ApprovalInputAuthority()
    permit_gate = GeneralAttackActionPermitGate(
        activation=context.activation,
        permit_store=context.graph.permit_store,
        inputs=_PermitInputs(
            GeneralAttackActionPermitInputs(
                envelope=context.envelope,
                decision=context.source_decision,
                cost_microusd=0,
            )
        ),
        approval=approval,
        approval_input_authority=approval_input,
        approval_issuer=approval_issuer,
        reversible_cleanup=binder,
        clock=lambda: SOURCE_NOW,
    )
    gateway = ToolGateway(
        policy=PolicyEngine(),
        tools=context.tools,
        worker=context.worker,
        store=context.run_store,
        clock=context.runtime_clock,
    )

    async def consume(permit: ActionPermit, prepared, proposal) -> GatewayOutcome:
        dispatcher = ExistingModeCapabilityGatewayDispatcher(
            activation=context.activation,
            permits=_PermitDispatcherStub(permit),
            gateway=gateway,
            audit_store=context.run_store,
            clock=lambda: SOURCE_NOW,
        )
        dispatched = await dispatcher.dispatch_once(
            context.envelope,
            proposal,
            context.source_decision,
            prepared,
            campaign=context.campaign,
            grant=context.source_grant,
            used_calls=0,
        )
        assert dispatched.result is not None
        return dispatched.result

    result = await permit_gate.dispatch_once(
        context.intent,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
        consume,
    )
    context.run_store.seal()
    return result, mappings, gateway


def _cleanup_authority(
    context: _Context,
    source_result,
    mappings: CleanupCapabilityMappingRegistry,
    gateway: ToolGateway,
    *,
    grants: _GrantInputs | None = None,
    audit_store: RunStore | None = None,
):
    outcome_gate = GeneralAttackActionOutcomeGate(
        activation=context.activation,
        permit_store=context.graph.permit_store,
        inputs=_OutcomeInputs(
            GeneralAttackActionOutcomeInputs(
                run_path=context.run_store.path,
                run_anchor=context.run_anchor,
                grant=context.source_grant,
            )
        ),
    )
    cleanup_gate = GeneralAttackActionCleanupGate(
        activation=context.activation,
        outcome_gate=outcome_gate,
        mappings=mappings,
        cleanup_store=context.graph.permit_store,
        grants=grants or _GrantInputs(),
        gateway=gateway,
        audit_store=audit_store or context.run_store,
        verifier=_StateVerifier(context.state_path),
        clock=lambda: CLEANUP_NOW,
    )
    source_ref = cleanup_gate.source_outcome_ref(
        source_result,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
    )
    decision = GraphDecision(
        campaignId=context.campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=source_ref.source_outcome_digest,
        snapshot=context.source_decision.snapshot,
        actorId="test.general-attack.cleanup-decision",
        actorDigest="d" * 64,
        createdAt=CLEANUP_NOW - timedelta(seconds=1),
    )
    return cleanup_gate, decision


@pytest.mark.asyncio
async def test_irreversible_write_is_rejected_before_cleanup_hold_and_worker(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(
        tmp_path,
        sample_campaign,
        source_cleanup_required=True,
        source_side_effect=CapabilitySideEffectClass.IRREVERSIBLE_WRITE,
    )
    cleanup_authority = _UnexpectedCleanupAuthority()
    gate = GeneralAttackActionPermitGate(
        activation=context.activation,
        permit_store=context.graph.permit_store,
        inputs=_PermitInputs(
            GeneralAttackActionPermitInputs(
                envelope=context.envelope,
                decision=context.source_decision,
                cost_microusd=0,
            )
        ),
        reversible_cleanup=cleanup_authority,
        clock=lambda: SOURCE_NOW,
    )

    async def consume(*_args):
        raise AssertionError("ineligible write reached its Worker consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="reversible cleanup"):
        await gate.dispatch_once(
            context.intent,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
            consume,
        )

    assert cleanup_authority.calls == 0
    assert context.worker.calls == []
    assert context.graph.permit_store.permits() == ()
    assert context.graph.permit_store.cleanup_reservations() == ()


@pytest.mark.asyncio
async def test_reversible_write_without_hold_authority_is_rejected_before_worker(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(tmp_path, sample_campaign)
    gate = GeneralAttackActionPermitGate(
        activation=context.activation,
        permit_store=context.graph.permit_store,
        inputs=_PermitInputs(
            GeneralAttackActionPermitInputs(
                envelope=context.envelope,
                decision=context.source_decision,
                cost_microusd=0,
            )
        ),
        clock=lambda: SOURCE_NOW,
    )

    async def consume(*_args):
        raise AssertionError("unreserved write reached its Worker consumer")

    with pytest.raises(GeneralAttackActionPermitError, match="cleanup hold authority"):
        await gate.dispatch_once(
            context.intent,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
            consume,
        )

    assert context.worker.calls == []
    assert context.graph.permit_store.permits() == ()
    assert context.graph.permit_store.cleanup_reservations() == ()


@pytest.mark.asyncio
async def test_approval_required_write_without_approval_fails_before_cleanup_hold(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(
        tmp_path,
        sample_campaign,
        source_approval_required=True,
    )
    cleanup_authority = _UnexpectedCleanupAuthority()
    gate = GeneralAttackActionPermitGate(
        activation=context.activation,
        permit_store=context.graph.permit_store,
        inputs=_PermitInputs(
            GeneralAttackActionPermitInputs(
                envelope=context.envelope,
                decision=context.source_decision,
                cost_microusd=0,
            )
        ),
        reversible_cleanup=cleanup_authority,
        clock=lambda: SOURCE_NOW,
    )

    async def consume(*_args):
        raise AssertionError("unapproved write reached its Worker consumer")

    with pytest.raises(GeneralAttackActionPermitError, match=r"requires.*approval"):
        await gate.dispatch_once(
            context.intent,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
            consume,
        )

    assert cleanup_authority.calls == 0
    assert context.worker.calls == []
    assert context.graph.permit_store.permits() == ()
    assert context.graph.permit_store.cleanup_reservations() == ()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("stable_plan_calls", "expected_cleanup_permits"),
    ((1, 0), (2, 0)),
)
async def test_cleanup_handler_plan_equivocation_fails_before_worker(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    stable_plan_calls: int,
    expected_cleanup_permits: int,
) -> None:
    context = _context(tmp_path, sample_campaign)
    source_result, mappings, gateway = await _execute_source(context)
    stable = _cleanup_plan()
    drifted = _cleanup_plan(
        state="other",
        expected_state_digest=sha256(b"other").hexdigest(),
    )
    context.source_cleanup_handler.set_cleanup_plans(
        *([stable] * stable_plan_calls),
        drifted,
    )
    cleanup_gate, cleanup_decision = _cleanup_authority(
        context,
        source_result,
        mappings,
        gateway,
    )
    context.runtime_clock.value = CLEANUP_NOW

    with pytest.raises(GeneralAttackActionCleanupError, match="dispatch"):
        await cleanup_gate.dispatch_once(
            source_result,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
            context.envelope,
            cleanup_decision,
        )

    assert context.source_cleanup_handler.cleanup_plan_calls == stable_plan_calls + 1
    assert len(context.graph.permit_store.cleanup_permits()) == expected_cleanup_permits
    assert context.worker.calls == ["write-state"]
    assert (tmp_path / "target-state.bin").read_bytes() == CHANGED


@pytest.mark.asyncio
async def test_malformed_cleanup_handler_plan_fails_before_permit_and_worker(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(tmp_path, sample_campaign)
    source_result, mappings, gateway = await _execute_source(context)
    context.source_cleanup_handler.set_cleanup_plans(
        _cleanup_plan(operation="delete-target")
    )
    cleanup_gate, cleanup_decision = _cleanup_authority(
        context,
        source_result,
        mappings,
        gateway,
    )
    context.runtime_clock.value = CLEANUP_NOW

    with pytest.raises(GeneralAttackActionCleanupError, match="dispatch"):
        await cleanup_gate.dispatch_once(
            source_result,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
            context.envelope,
            cleanup_decision,
        )

    assert context.graph.permit_store.cleanup_permits() == ()
    assert context.worker.calls == ["write-state"]
    assert (tmp_path / "target-state.bin").read_bytes() == CHANGED


@pytest.mark.asyncio
async def test_cleanup_grant_that_outlives_prospective_permit_fails_before_claim(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(tmp_path, sample_campaign)
    source_result, mappings, gateway = await _execute_source(context)
    cleanup_gate, cleanup_decision = _cleanup_authority(
        context,
        source_result,
        mappings,
        gateway,
        grants=_GrantInputs(expires_at=CLEANUP_NOW + timedelta(minutes=1)),
    )
    context.runtime_clock.value = CLEANUP_NOW

    with pytest.raises(GeneralAttackActionCleanupError, match="dispatch"):
        await cleanup_gate.dispatch_once(
            source_result,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
            context.envelope,
            cleanup_decision,
        )

    assert context.graph.permit_store.cleanup_permits() == ()
    assert context.worker.calls == ["write-state"]
    assert (tmp_path / "target-state.bin").read_bytes() == CHANGED


@pytest.mark.asyncio
async def test_cleanup_dispatch_rejects_alternate_same_run_audit_store_before_claim(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(tmp_path, sample_campaign)
    source_result, mappings, gateway = await _execute_source(context)
    alternate = RunStore.create(
        tmp_path / "alternate-runs",
        context.campaign.metadata.name,
        run_id=context.run_store.run_id,
    )
    cleanup_gate, cleanup_decision = _cleanup_authority(
        context,
        source_result,
        mappings,
        gateway,
        audit_store=alternate,
    )
    context.runtime_clock.value = CLEANUP_NOW

    with pytest.raises(GeneralAttackActionCleanupError, match="dispatch"):
        await cleanup_gate.dispatch_once(
            source_result,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
            context.envelope,
            cleanup_decision,
        )

    assert context.source_cleanup_handler.cleanup_plan_calls == 0
    assert context.graph.permit_store.cleanup_permits() == ()
    assert context.worker.calls == ["write-state"]
    assert (tmp_path / "target-state.bin").read_bytes() == CHANGED


@pytest.mark.asyncio
async def test_t2_approved_reversible_write_holds_cleanup_before_worker(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(
        tmp_path,
        sample_campaign,
        source_risk_tier=ToolRiskTier.T2,
    )

    source_result, mappings, gateway = await _execute_source(context)

    assert source_result.dispatch.dispatched is True
    assert source_result.approval_receipt is not None
    assert source_result.cleanup_reservation is not None
    assert source_result.approval_receipt.action_permit == source_result.dispatch.permit
    assert (
        source_result.cleanup_reservation.source_action_permit_id
        == source_result.dispatch.permit.permit_id
    )
    assert context.graph.permit_store.action_approvals() == (
        source_result.approval_receipt.approval,
    )
    assert context.graph.permit_store.approval_consumptions() == (
        source_result.approval_receipt,
    )
    assert context.graph.permit_store.cleanup_reservations() == (
        source_result.cleanup_reservation,
    )
    assert context.worker.calls == ["write-state"]

    cleanup_gate, cleanup_decision = _cleanup_authority(
        context,
        source_result,
        mappings,
        gateway,
    )
    context.runtime_clock.value = CLEANUP_NOW
    cleanup_result = await cleanup_gate.dispatch_once(
        source_result,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
        context.envelope,
        cleanup_decision,
    )

    assert cleanup_result.dispatched is True
    assert context.worker.calls == ["write-state", "restore-state"]
    assert context.state_path.read_bytes() == BASELINE


@pytest.mark.asyncio
async def test_reversible_write_cleanup_dispatch_and_restored_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(tmp_path, sample_campaign)
    source_result, mappings, gateway = await _execute_source(context)
    state_path = tmp_path / "target-state.bin"
    assert state_path.read_bytes() == CHANGED
    assert source_result.cleanup_reservation is not None
    outcome_gate = GeneralAttackActionOutcomeGate(
        activation=context.activation,
        permit_store=context.graph.permit_store,
        inputs=_OutcomeInputs(
            GeneralAttackActionOutcomeInputs(
                run_path=context.run_store.path,
                run_anchor=context.run_anchor,
                grant=context.source_grant,
            )
        ),
    )
    cleanup_gate = GeneralAttackActionCleanupGate(
        activation=context.activation,
        outcome_gate=outcome_gate,
        mappings=mappings,
        cleanup_store=context.graph.permit_store,
        grants=_GrantInputs(),
        gateway=gateway,
        audit_store=context.run_store,
        verifier=_StateVerifier(context.state_path),
        clock=lambda: CLEANUP_NOW,
    )
    source_ref = cleanup_gate.source_outcome_ref(
        source_result,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
    )
    cleanup_decision = GraphDecision(
        campaignId=context.campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=source_ref.source_outcome_digest,
        snapshot=context.source_decision.snapshot,
        actorId="test.general-attack.cleanup-decision",
        actorDigest="d" * 64,
        createdAt=CLEANUP_NOW - timedelta(seconds=1),
    )
    context.runtime_clock.value = CLEANUP_NOW
    dispatched = await cleanup_gate.dispatch_once(
        source_result,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
        context.envelope,
        cleanup_decision,
    )
    assert dispatched.dispatched is True
    assert dispatched.outcome is not None
    assert dispatched.outcome.decision.allowed, dispatched.outcome
    assert dispatched.outcome.executed is True
    assert dispatched.outcome.result.success is True
    assert dispatched.permit.cleanup_permit_id != source_result.dispatch.permit.permit_id
    assert capability_grant_digest(dispatched.grant) != capability_grant_digest(
        context.source_grant
    )
    assert context.worker.calls == ["write-state", "restore-state"]
    assert state_path.read_bytes() == BASELINE
    context.run_store.seal()
    retry = await cleanup_gate.dispatch_once(
        source_result,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
        context.envelope,
        cleanup_decision,
    )
    assert retry.dispatched is False
    assert retry.outcome is None
    assert retry.permit == dispatched.permit
    assert context.worker.calls == ["write-state", "restore-state"]
    assessment = cleanup_gate.verify_restored(
        dispatched,
        source_result,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
    )
    assert assessment.restored is True
    assert assessment.expected_state_digest == BASELINE_DIGEST
    assert assessment.observed_state_digest == BASELINE_DIGEST
    assert assessment.original_action_permit_reused is False
    assert assessment.redispatch_allowed is False
    forged_raw = dispatched.permit.model_dump(mode="json", by_alias=True)
    for field in ("cleanupPermitId", "cleanupPermitDigest", "cleanupDispatchId"):
        forged_raw.pop(field)
    forged_raw["cleanupPlanDigest"] = "f" * 64
    forged_permit = type(dispatched.permit).model_validate(forged_raw)
    with pytest.raises(GeneralAttackActionCleanupError, match="restored-state"):
        cleanup_gate.verify_restored(
            replace(dispatched, permit=forged_permit),
            source_result,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
        )


@pytest.mark.asyncio
async def test_cleanup_success_does_not_prove_unrestored_state(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    context = _context(tmp_path, sample_campaign)
    source_result, mappings, gateway = await _execute_source(context)
    outcome_gate = GeneralAttackActionOutcomeGate(
        activation=context.activation,
        permit_store=context.graph.permit_store,
        inputs=_OutcomeInputs(
            GeneralAttackActionOutcomeInputs(
                run_path=context.run_store.path,
                run_anchor=context.run_anchor,
                grant=context.source_grant,
            )
        ),
    )
    cleanup_gate = GeneralAttackActionCleanupGate(
        activation=context.activation,
        outcome_gate=outcome_gate,
        mappings=mappings,
        cleanup_store=context.graph.permit_store,
        grants=_GrantInputs(),
        gateway=gateway,
        audit_store=context.run_store,
        verifier=_StateVerifier(context.state_path, forged=True),
        clock=lambda: CLEANUP_NOW,
    )
    source_ref = cleanup_gate.source_outcome_ref(
        source_result,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
    )
    cleanup_decision = GraphDecision(
        campaignId=context.campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=source_ref.source_outcome_digest,
        snapshot=context.source_decision.snapshot,
        actorId="test.general-attack.cleanup-decision",
        actorDigest="d" * 64,
        createdAt=CLEANUP_NOW - timedelta(seconds=1),
    )
    context.runtime_clock.value = CLEANUP_NOW
    dispatched = await cleanup_gate.dispatch_once(
        source_result,
        context.source_proposal,
        context.campaign,
        context.hypotheses,
        context.plan,
        context.task.task_digest,
        context.source_definition.reference(),
        context.definitions,
        context.source_binding.capability,
        context.authorities,
        context.envelope,
        cleanup_decision,
    )
    context.run_store.seal()
    with pytest.raises(GeneralAttackActionCleanupError, match="restored-state"):
        cleanup_gate.verify_restored(
            dispatched,
            source_result,
            context.source_proposal,
            context.campaign,
            context.hypotheses,
            context.plan,
            context.task.task_digest,
            context.source_definition.reference(),
            context.definitions,
            context.source_binding.capability,
            context.authorities,
        )
