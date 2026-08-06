from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from pajin.domain.models import AutonomyLevel, ToolRiskTier
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalError,
    ActionApprovalInputAuthority,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionCapabilityRegistry,
    ActionPermitAuthorization,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
    action_permit_attempt_id,
    build_action_permit,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.graph.projection import GraphSnapshotRef

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
CAMPAIGN = "approval-lab"
RUN_ID = "run:approval:single"
COMPILER_ID = "pajin.action.compiler"
COMPILER_VERSION = "1.0.0"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64


def _capability(risk_tier: ToolRiskTier = ToolRiskTier.T2) -> RegisteredActionCapability:
    return RegisteredActionCapability(
        capabilityId="capability:http-observe",
        capabilityVersion="1.0.0",
        definitionDigest=DIGEST_C,
        toolId="http.request",
        toolVersion="1.0.0",
        toolDigest=DIGEST_B,
        riskTier=risk_tier,
    )


def _mission_envelope(capability: RegisteredActionCapability) -> MissionEnvelope:
    return MissionEnvelope(
        campaignId=CAMPAIGN,
        runId=RUN_ID,
        profileId="hybrid-web-ai",
        profileVersion="1.0.0",
        profileDigest=DIGEST_A,
        compilerId=COMPILER_ID,
        compilerVersion=COMPILER_VERSION,
        compilerDigest=DIGEST_D,
        sourceCampaignDigest=DIGEST_E,
        allowedCapabilities=(capability.reference(),),
        allowedTargetDigests=(DIGEST_F,),
        maxRiskTier=capability.risk_tier,
        budget=ActionBudgetLimit(
            toolCallLimit=1,
            requestUnitLimit=10,
            costLimitMicrousd=10_000,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=NOW,
        notBefore=NOW,
        expiresAt=NOW + timedelta(hours=1),
    )


def _decision() -> GraphDecision:
    return GraphDecision(
        campaignId=CAMPAIGN,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=DIGEST_D,
        snapshot=GraphSnapshotRef(
            snapshotId=f"graph-snapshot_{DIGEST_A}",
            snapshotDigest=DIGEST_B,
            campaignId=CAMPAIGN,
            revision=1,
            eventLogHeadDigest=DIGEST_C,
            projectionDigest=DIGEST_D,
        ),
        actorId="pajin.graph.planner",
        actorDigest=DIGEST_F,
        createdAt=NOW + timedelta(seconds=1),
    )


def _proposal(
    envelope: MissionEnvelope,
    capability: RegisteredActionCapability,
    decision: GraphDecision,
) -> ActionProposal:
    return ActionProposal(
        campaignId=CAMPAIGN,
        runId=RUN_ID,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        proposerId="pajin.graph.planner",
        proposerDigest=DIGEST_F,
        capability=capability.reference(),
        targetDigest=DIGEST_F,
        requestId="tool_approval_single",
        requestDigest=DIGEST_A,
        normalizedParametersDigest=DIGEST_E,
        riskTier=capability.risk_tier,
        reservation=ActionBudgetReservation(requestUnits=2, costMicrousd=1_000),
        createdAt=NOW + timedelta(seconds=2),
    )


def _approval(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
) -> ActionApprovalEnvelope:
    return ActionApprovalEnvelope(
        issuer=ActionApprovalIssuerAuthorityBinding(
            authorityId="deployment:operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.operator.StaticApprovalIssuer",
            contextDigest=DIGEST_A,
        ),
        requestedBy="principal:planner",
        approvedBy="principal:operator",
        campaignId=CAMPAIGN,
        campaignDigest=DIGEST_E,
        runId=RUN_ID,
        missionEnvelope=envelope,
        sourceIntentDigest=DIGEST_D,
        activationSetDigest=DIGEST_F,
        release=ActionApprovalReleaseRef(
            releaseId=f"capability-release_{DIGEST_B}",
            releaseDigest=DIGEST_B,
            capabilityId=proposal.capability.capability_id,
            capabilityVersion=proposal.capability.capability_version,
            capabilityDigest=proposal.capability.definition_digest,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        reservation=proposal.reservation,
        approvedAt=NOW + timedelta(seconds=3),
        notBefore=NOW + timedelta(seconds=4),
        expiresAt=NOW + timedelta(seconds=30),
    )


def _authority_inputs(
    risk_tier: ToolRiskTier = ToolRiskTier.T2,
) -> tuple[
    RegisteredActionCapability,
    MissionEnvelope,
    GraphDecision,
    ActionProposal,
    ActionApprovalEnvelope,
]:
    capability = _capability(risk_tier)
    envelope = _mission_envelope(capability)
    decision = _decision()
    proposal = _proposal(envelope, capability, decision)
    approval = _approval(envelope, proposal, decision)
    return capability, envelope, decision, proposal, approval


def _receipt(
    approval: ActionApprovalEnvelope,
    *,
    evaluated_at: datetime = NOW + timedelta(seconds=5),
    permit_ttl: timedelta = timedelta(seconds=20),
) -> ActionApprovalConsumptionReceipt:
    permit = build_action_permit(
        approval.mission_envelope,
        approval.proposal,
        approval.graph_decision,
        evaluated_at=evaluated_at,
        permit_ttl=permit_ttl,
    )
    return ActionApprovalConsumptionReceipt(
        approval=approval,
        actionPermit=permit,
        dispatchId=permit.dispatch_id,
        proposalId=permit.proposal_id,
        proposalDigest=permit.proposal_digest,
        requestId=permit.request_id,
        requestDigest=permit.request_digest,
        normalizedParametersDigest=permit.normalized_parameters_digest,
    )


class _InputAuthority:
    def __init__(self, *, fail_on_call: int | None = None) -> None:
        self.calls = 0
        self.fail_on_call = fail_on_call

    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        self.calls += 1
        assert approval.mission_envelope == envelope
        assert approval.proposal == proposal
        assert approval.graph_decision == decision
        if self.calls == self.fail_on_call:
            raise RuntimeError("approval authority changed")


class _AtomicApprovalStore:
    def __init__(self) -> None:
        self.writer = object()
        self.calls = 0
        self.lookup_calls = 0
        self.authorization: ActionApprovalAuthorization | None = None
        self.policies: ActionApprovalCapabilityPolicyRegistry | None = None
        self.input_authority: ActionApprovalInputAuthority | None = None

    def claim_approved_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        policies: ActionApprovalCapabilityPolicyRegistry,
        input_authority: ActionApprovalInputAuthority,
    ) -> object:
        assert (compiler_id, compiler_version, compiler_digest) == (
            COMPILER_ID,
            COMPILER_VERSION,
            DIGEST_D,
        )
        if self.policies is not None:
            assert self.policies.registry_digest == policies.registry_digest
            assert self.input_authority is input_authority
            return self.writer
        self.policies = ActionApprovalCapabilityPolicyRegistry(policies.policies())
        self.input_authority = input_authority
        return self.writer

    def approved_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ActionApprovalAuthorization | None:
        self.lookup_calls += 1
        if self.authorization is None:
            return None
        assert self.authorization.approval.approval_id == approval_id
        assert self.authorization.action.permit.permit_id == permit_id
        return ActionApprovalAuthorization(
            approval=self.authorization.approval,
            action=ActionPermitAuthorization(
                permit=self.authorization.action.permit,
                newlyConsumed=False,
            ),
            receipt=self.authorization.receipt,
        )

    def authorize_approved_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        capability: RegisteredActionCapability,
        approval: ActionApprovalEnvelope,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ActionApprovalAuthorization:
        self.calls += 1
        assert writer is self.writer
        assert capability.reference() == proposal.capability
        assert self.policies is not None
        policy = self.policies.resolve(capability.reference())
        assert policy.capability == capability.reference()
        assert policy.side_effect_class == "read-only"
        assert approval.mission_envelope == envelope
        assert approval.proposal == proposal
        assert approval.graph_decision == decision
        assert self.input_authority is not None
        try:
            self.input_authority.verify_action_approval(
                envelope,
                proposal,
                decision,
                approval,
            )
        except ActionApprovalError:
            raise
        except Exception as exc:
            raise ActionApprovalError("approval input authority rejected the claim") from exc
        if self.authorization is None:
            receipt = _receipt(
                approval,
                evaluated_at=evaluated_at,
                permit_ttl=permit_ttl,
            )
            self.authorization = ActionApprovalAuthorization(
                approval=approval,
                action=ActionPermitAuthorization(
                    permit=receipt.action_permit,
                    newlyConsumed=True,
                ),
                receipt=receipt,
            )
            authorization = self.authorization
        else:
            authorization = ActionApprovalAuthorization(
                approval=self.authorization.approval,
                action=ActionPermitAuthorization(
                    permit=self.authorization.action.permit,
                    newlyConsumed=False,
                ),
                receipt=self.authorization.receipt,
            )
        try:
            self.input_authority.verify_action_approval(
                envelope,
                proposal,
                decision,
                approval,
            )
        except ActionApprovalError:
            raise
        except Exception as exc:
            raise ActionApprovalError("approval input authority rejected the claim") from exc
        return authorization


def _authority(
    capability: RegisteredActionCapability,
    store: _AtomicApprovalStore,
    inputs: _InputAuthority,
    *,
    clock: datetime = NOW + timedelta(seconds=5),
    side_effect_class: str = "read-only",
    approval_required: bool = False,
    cleanup_required: bool = False,
) -> GraphApprovedActionPermitAuthority:
    return GraphApprovedActionPermitAuthority(
        campaign_id=CAMPAIGN,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        compiler_digest=DIGEST_D,
        capabilities=ActionCapabilityRegistry([capability]),
        policies=ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=capability.reference(),
                    sideEffectClass=side_effect_class,
                    approvalRequired=approval_required,
                    cleanupRequired=cleanup_required,
                ),
            )
        ),
        permit_store=store,
        input_authority=inputs,
        clock=lambda: clock,
        permit_ttl=timedelta(seconds=30),
    )


def test_single_action_approval_and_receipt_are_content_addressed() -> None:
    _, _, _, _, approval = _authority_inputs()
    receipt = _receipt(approval)

    assert approval.mode == "single"
    assert approval.max_actions == 1
    assert approval.approval_id == f"action-approval_{approval.approval_digest}"
    assert approval.release.capability_digest == approval.proposal.capability.definition_digest
    assert receipt.receipt_id == f"action-approval-receipt_{receipt.receipt_digest}"
    assert receipt.action_permit.permit_id == approval.expected_action_permit_id
    assert receipt.reusable is False
    assert receipt.redispatch_authority is False
    assert (
        ActionApprovalEnvelope.model_validate(approval.model_dump(mode="json", by_alias=True))
        == approval
    )
    assert (
        ActionApprovalConsumptionReceipt.model_validate(
            receipt.model_dump(mode="json", by_alias=True)
        )
        == receipt
    )


@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("mode", "batch", "literal_error"),
        ("maxActions", 2, "JSON integer 1"),
        ("maxActions", True, "JSON integer 1"),
        ("maxActions", 1.0, "JSON integer 1"),
        ("approvedBy", "principal:planner", "cannot approve"),
        ("sourceIntentDigest", DIGEST_A, "source intent"),
        ("expectedActionPermitId", f"action-permit_{DIGEST_F}", "expected ActionPermit"),
        ("sideEffectClass", "reversible-write", "literal_error"),
        ("cleanupRequired", True, "JSON boolean false"),
        ("cleanupRequired", 0, "JSON boolean false"),
        ("notBefore", NOW + timedelta(seconds=2), "window is invalid"),
    ],
)
def test_approval_rejects_scope_and_identity_forgery(
    field: str,
    value: object,
    match: str,
) -> None:
    _, _, _, _, approval = _authority_inputs()
    raw = approval.model_dump(mode="json", by_alias=True)
    raw.pop("approvalId")
    raw.pop("approvalDigest")
    raw[field] = value

    with pytest.raises(ValidationError, match=match):
        ActionApprovalEnvelope.model_validate(raw)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("reusable", 0),
        ("reusable", None),
        ("redispatchAuthority", 0),
        ("redispatchAuthority", None),
    ],
)
def test_approval_receipt_requires_exact_non_reusable_json_booleans(
    field: str,
    value: object,
) -> None:
    _, _, _, _, approval = _authority_inputs()
    receipt = _receipt(approval)
    raw = receipt.model_dump(mode="json", by_alias=True)
    raw.pop("receiptId")
    raw.pop("receiptDigest")
    raw[field] = value

    with pytest.raises(ValidationError, match="JSON boolean false"):
        ActionApprovalConsumptionReceipt.model_validate(raw)


def test_approval_rejects_release_and_reservation_substitution() -> None:
    _, _, _, _, approval = _authority_inputs()
    raw = approval.model_dump(mode="json", by_alias=True)
    raw.pop("approvalId")
    raw.pop("approvalDigest")
    raw["release"]["capabilityDigest"] = DIGEST_A
    with pytest.raises(ValidationError, match="release differs"):
        ActionApprovalEnvelope.model_validate(raw)

    raw = approval.model_dump(mode="json", by_alias=True)
    raw.pop("approvalId")
    raw.pop("approvalDigest")
    raw["reservation"]["requestUnits"] = 3
    with pytest.raises(ValidationError, match="reservation differs"):
        ActionApprovalEnvelope.model_validate(raw)


def test_issuer_release_and_receipt_reject_content_address_forgery() -> None:
    _, _, _, _, approval = _authority_inputs()
    issuer = approval.issuer.model_dump(mode="json", by_alias=True)
    issuer["authorityDigest"] = DIGEST_F
    with pytest.raises(ValidationError, match="issuer authority digest differs"):
        ActionApprovalIssuerAuthorityBinding.model_validate(issuer)

    release = approval.release.model_dump(mode="json", by_alias=True)
    release["releaseId"] = f"capability-release_{DIGEST_A}"
    with pytest.raises(ValidationError, match="release ID differs"):
        ActionApprovalReleaseRef.model_validate(release)

    receipt = _receipt(approval)
    raw = receipt.model_dump(mode="json", by_alias=True)
    raw.pop("receiptId")
    raw.pop("receiptDigest")
    raw["requestDigest"] = DIGEST_B
    with pytest.raises(ValidationError, match="exact approved Permit"):
        ActionApprovalConsumptionReceipt.model_validate(raw)


def test_t3_approval_is_rejected_before_authority_construction() -> None:
    capability = _capability(ToolRiskTier.T3)
    envelope = _mission_envelope(capability)
    decision = _decision()
    proposal = _proposal(envelope, capability, decision)

    with pytest.raises(ValidationError, match="T2 or below"):
        _approval(envelope, proposal, decision)


@pytest.mark.asyncio
async def test_atomic_approval_dispatches_once_and_retry_never_redispatches() -> None:
    capability, envelope, decision, proposal, approval = _authority_inputs()
    store = _AtomicApprovalStore()
    inputs = _InputAuthority()
    dispatcher = GraphApprovedActionPermitDispatcher(_authority(capability, store, inputs))
    dispatch_calls = 0

    async def dispatch(*_: object) -> str:
        nonlocal dispatch_calls
        dispatch_calls += 1
        return "observed"

    first = await dispatcher.dispatch_once(envelope, proposal, decision, approval, dispatch)
    retry = await dispatcher.dispatch_once(envelope, proposal, decision, approval, dispatch)

    assert first.dispatched is True
    assert first.result == "observed"
    assert retry.dispatched is False
    assert retry.result is None
    assert retry.authorization.receipt == first.authorization.receipt
    assert dispatch_calls == 1
    assert store.calls == 1
    assert store.lookup_calls == 2
    assert inputs.calls == 6


@pytest.mark.asyncio
async def test_sync_callback_and_input_drift_fail_closed_before_worker() -> None:
    capability, envelope, decision, proposal, approval = _authority_inputs()
    store = _AtomicApprovalStore()
    inputs = _InputAuthority(fail_on_call=2)
    dispatcher = GraphApprovedActionPermitDispatcher(_authority(capability, store, inputs))
    dispatch_calls = 0

    def sync_dispatch(*_: object) -> str:
        return "invalid"

    with pytest.raises(TypeError, match="must be async"):
        await dispatcher.dispatch_once(envelope, proposal, decision, approval, sync_dispatch)  # type: ignore[arg-type]
    assert store.calls == 0

    async def dispatch(*_: object) -> str:
        nonlocal dispatch_calls
        dispatch_calls += 1
        return "must-not-run"

    with pytest.raises(ActionApprovalError, match="input authority rejected"):
        await dispatcher.dispatch_once(envelope, proposal, decision, approval, dispatch)
    assert store.calls == 1
    assert dispatch_calls == 0


def test_expired_approval_and_preclaim_rejection_do_not_reach_store() -> None:
    capability, envelope, decision, proposal, approval = _authority_inputs()
    expired_store = _AtomicApprovalStore()
    expired = _authority(
        capability,
        expired_store,
        _InputAuthority(),
        clock=approval.expires_at,
    )
    with pytest.raises(ActionApprovalError, match="not currently active"):
        expired.authorize_for_dispatch(envelope, proposal, decision, approval)
    assert expired_store.calls == 0

    rejected_store = _AtomicApprovalStore()
    rejected = _authority(
        capability,
        rejected_store,
        _InputAuthority(fail_on_call=1),
    )
    with pytest.raises(ActionApprovalError, match="input authority rejected"):
        rejected.authorize_for_dispatch(envelope, proposal, decision, approval)
    assert rejected_store.calls == 0


def test_deployment_policy_rejects_self_declared_read_only_write_before_store() -> None:
    capability, envelope, decision, proposal, approval = _authority_inputs()
    store = _AtomicApprovalStore()
    authority = _authority(
        capability,
        store,
        _InputAuthority(),
        side_effect_class="reversible-write",
        approval_required=True,
        cleanup_required=True,
    )

    with pytest.raises(ActionApprovalError, match="cleanup-free no-write"):
        authority.authorize_for_dispatch(envelope, proposal, decision, approval)

    assert store.lookup_calls == 0
    assert store.calls == 0
