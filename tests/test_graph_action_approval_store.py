from __future__ import annotations

import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

import pajin.graph.sqlite_store as sqlite_store_module
from pajin.domain.models import AutonomyLevel, ToolRiskTier
from pajin.graph.admission import (
    GraphAdmissionAuthority,
    GraphProducerRegistration,
    GraphProducerRegistry,
    TrustedGraphLineageRegistry,
)
from pajin.graph.approval import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalEnvelope,
    ActionApprovalError,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionCapabilityRegistry,
    ActionProposal,
    GraphActionPermitAuthority,
    MissionEnvelope,
    RegisteredActionCapability,
    action_permit_attempt_id,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.graph.models import (
    GraphContentOrigin,
    GraphEvidenceBinding,
    GraphProposalKind,
    GraphProposalLineage,
    GraphSurface,
    SurfaceProposal,
)
from pajin.graph.projection import (
    GraphProjectionCoordinator,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    graph_snapshot_ref,
)
from pajin.graph.sqlite_store import SQLiteGraphStore, SQLiteGraphStoreError

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
CAMPAIGN = "approval-store-lab"
RUN_ID = "run:approval:store"
PRODUCER_ID = "pajin.graph.approval-store-test-producer"
ADMISSION_AUTHORITY_ID = "pajin.graph.admission-authority"
SNAPSHOT_CREATOR_ID = "pajin.graph.snapshot-authority"
COMPILER_ID = "pajin.action.compiler"
COMPILER_VERSION = "1.0.0"
DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
DIGEST_C = "c" * 64
DIGEST_D = "d" * 64
DIGEST_E = "e" * 64
DIGEST_F = "f" * 64
TARGET_DIGEST = DIGEST_C


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


def _graph_proposal() -> SurfaceProposal:
    return SurfaceProposal(
        proposalId="proposal:surface:approval-store",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        lineage=GraphProposalLineage(
            campaignId=CAMPAIGN,
            runId=RUN_ID,
            agentId="agent:graph-specialist",
            taskId="task:graph:approval-store",
            requestId="tool_graph_approval_store",
            requestDigest=DIGEST_A,
            capabilityGrantId="grant:graph:approval-store",
            capabilityGrantDigest=DIGEST_E,
            capabilityId="capability:graph-observe",
            capabilityVersion="1.0.0",
            capabilityDigest=DIGEST_F,
            sourceRootDigest=DIGEST_D,
            evidence=[
                GraphEvidenceBinding(
                    reference="evidence/graph-approval-store.json",
                    sha256=DIGEST_A,
                )
            ],
            producedAt=NOW + timedelta(seconds=1),
        ),
        surface=GraphSurface(
            campaignId=CAMPAIGN,
            targetId="target:approval-store",
            surfaceType="http-endpoint",
            locatorSchema="pajin.discovery.http-surface.v1",
            locatorDigest=DIGEST_A,
            origin=GraphContentOrigin.TRUSTED_CORE,
        ),
    )


def _capability(
    risk_tier: ToolRiskTier = ToolRiskTier.T2,
) -> RegisteredActionCapability:
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
        allowedTargetDigests=(TARGET_DIGEST,),
        maxRiskTier=capability.risk_tier,
        budget=ActionBudgetLimit(
            toolCallLimit=10,
            requestUnitLimit=100,
            costLimitMicrousd=1_000_000,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=NOW,
        notBefore=NOW,
        expiresAt=NOW + timedelta(hours=1),
    )


def _action_proposal(
    envelope: MissionEnvelope,
    capability: RegisteredActionCapability,
    decision: GraphDecision,
    *,
    request_id: str = "tool_approval_store_first",
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
        targetDigest=TARGET_DIGEST,
        requestId=request_id,
        requestDigest=DIGEST_A if request_id.endswith("first") else DIGEST_B,
        normalizedParametersDigest=DIGEST_E,
        riskTier=capability.risk_tier,
        reservation=ActionBudgetReservation(requestUnits=2, costMicrousd=1_000),
        createdAt=NOW + timedelta(seconds=6),
    )


def _approval(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    *,
    approved_by: str = "principal:operator",
) -> ActionApprovalEnvelope:
    return ActionApprovalEnvelope(
        issuer=ActionApprovalIssuerAuthorityBinding(
            authorityId="deployment:operator-approval",
            authorityVersion="1.0.0",
            implementationType="tests.operator.StaticApprovalIssuer",
            contextDigest=DIGEST_A,
        ),
        requestedBy="principal:planner",
        approvedBy=approved_by,
        campaignId=CAMPAIGN,
        campaignDigest=DIGEST_E,
        runId=RUN_ID,
        missionEnvelope=envelope,
        sourceIntentDigest=decision.decision_payload_digest,
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
        approvedAt=NOW + timedelta(seconds=7),
        notBefore=NOW + timedelta(seconds=8),
        expiresAt=NOW + timedelta(seconds=40),
    )


def _seed(
    path: Path,
    *,
    risk_tier: ToolRiskTier = ToolRiskTier.T2,
) -> tuple[
    SQLiteGraphStore,
    GraphDecision,
    RegisteredActionCapability,
    MissionEnvelope,
    ActionProposal,
    ActionApprovalEnvelope,
]:
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    graph_proposal = _graph_proposal()
    admission = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN,
        authority_id=ADMISSION_AUTHORITY_ID,
        authority_digest=DIGEST_A,
        producers=GraphProducerRegistry(
            [
                GraphProducerRegistration(
                    producerId=PRODUCER_ID,
                    producerVersion="1.0.0",
                    producerDigest=DIGEST_F,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                )
            ]
        ),
        lineage_verifier=TrustedGraphLineageRegistry([graph_proposal.lineage]),
        event_log=store.event_log,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    admission.submit(graph_proposal)
    projection = (
        GraphProjectionCoordinator(
            event_log=store.event_log,
            projection_store=store.projection_store,
        )
        .refresh()
        .projection
    )
    snapshot = GraphSnapshotAuthority(
        creator_id=SNAPSHOT_CREATOR_ID,
        creator_digest=DIGEST_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=4),
    ).capture(GraphSnapshotReason.CHECKPOINT)
    assert snapshot.projection == projection
    decision = GraphDecision(
        campaignId=CAMPAIGN,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=DIGEST_C,
        snapshot=graph_snapshot_ref(snapshot),
        actorId="pajin.graph.planner",
        actorDigest=DIGEST_F,
        createdAt=NOW + timedelta(seconds=5),
    )
    capability = _capability(risk_tier)
    envelope = _mission_envelope(capability)
    proposal = _action_proposal(envelope, capability, decision)
    approval = _approval(envelope, proposal, decision)
    return store, decision, capability, envelope, proposal, approval


def _approved_authority(
    store: SQLiteGraphStore,
    capability: RegisteredActionCapability,
    input_authority: _InputAuthority | None = None,
    *,
    evaluated_at: datetime = NOW + timedelta(seconds=9),
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
                    sideEffectClass="read-only",
                    approvalRequired=False,
                    cleanupRequired=False,
                ),
            )
        ),
        permit_store=store.permit_store,
        input_authority=input_authority or _InputAuthority(),
        clock=lambda: evaluated_at,
        permit_ttl=timedelta(seconds=30),
    )


def _normal_authority(
    store: SQLiteGraphStore,
    capability: RegisteredActionCapability,
) -> GraphActionPermitAuthority:
    return GraphActionPermitAuthority(
        campaign_id=CAMPAIGN,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        compiler_digest=DIGEST_D,
        capabilities=ActionCapabilityRegistry([capability]),
        policies=ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=capability.reference(),
                    sideEffectClass="read-only",
                    approvalRequired=False,
                    cleanupRequired=False,
                ),
            )
        ),
        permit_store=store.permit_store,
        clock=lambda: NOW + timedelta(seconds=9),
    )


def test_atomic_approval_permit_and_receipt_survive_reopen_exact_retry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    inputs = _InputAuthority()
    first = _approved_authority(store, capability, inputs).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )

    assert first.action.newly_consumed is True
    assert first.approval == approval
    assert first.receipt.approval == approval
    assert first.receipt.action_permit == first.action.permit
    assert store.permit_store.action_approvals() == (approval,)
    assert store.permit_store.permits() == (first.action.permit,)
    assert store.permit_store.approval_consumptions() == (first.receipt,)
    assert inputs.calls == 4

    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    retry_inputs = _InputAuthority()
    retry = _approved_authority(reopened, capability, retry_inputs).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )

    assert retry.action.newly_consumed is False
    assert retry.action.permit == first.action.permit
    assert retry.receipt == first.receipt
    assert retry.receipt.redispatch_authority is False
    assert retry_inputs.calls == 2
    assert reopened.permit_store.action_approval(approval.approval_id) == approval
    assert reopened.permit_store.approval_consumption(first.receipt.receipt_id) == first.receipt


def test_store_post_verification_failure_rolls_back_all_approval_ledgers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    inputs = _InputAuthority(fail_on_call=3)
    authority = _approved_authority(store, capability, inputs)

    with pytest.raises(ActionApprovalError, match="input authority rejected"):
        authority.authorize_for_dispatch(envelope, proposal, decision, approval)

    assert store.permit_store.action_approvals() == ()
    assert store.permit_store.permits() == ()
    assert store.permit_store.approval_consumptions() == ()

    recovered = _approved_authority(store, capability, inputs).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )
    assert recovered.action.newly_consumed is True


def test_authority_post_verification_failure_preserves_consumed_non_retryable_tuple(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    inputs = _InputAuthority(fail_on_call=4)
    authority = _approved_authority(store, capability, inputs)

    with pytest.raises(ActionApprovalError, match="input authority rejected"):
        authority.authorize_for_dispatch(envelope, proposal, decision, approval)

    assert len(store.permit_store.action_approvals()) == 1
    assert len(store.permit_store.permits()) == 1
    assert len(store.permit_store.approval_consumptions()) == 1

    recovered = authority.authorize_for_dispatch(envelope, proposal, decision, approval)
    assert recovered.action.newly_consumed is False
    assert recovered.receipt == store.permit_store.approval_consumptions()[0]


def test_approved_writer_rejects_different_full_policy_registry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, capability, _, _, _ = _seed(path)
    inputs = _InputAuthority()
    _approved_authority(store, capability, inputs)

    with pytest.raises(ActionApprovalError, match="already claimed"):
        GraphApprovedActionPermitAuthority(
            campaign_id=CAMPAIGN,
            compiler_id=COMPILER_ID,
            compiler_version=COMPILER_VERSION,
            compiler_digest=DIGEST_D,
            capabilities=ActionCapabilityRegistry([capability]),
            policies=ActionApprovalCapabilityPolicyRegistry(
                (
                    ActionApprovalCapabilityPolicy(
                        capability=capability.reference(),
                        sideEffectClass="read-only",
                        approvalRequired=True,
                        cleanupRequired=False,
                    ),
                )
            ),
            permit_store=store.permit_store,
            input_authority=inputs,
            clock=lambda: NOW + timedelta(seconds=9),
            permit_ttl=timedelta(seconds=30),
        )


def test_cross_approval_and_cross_proposal_retry_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    authority = _approved_authority(store, capability)
    authority.authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )
    alternate_approval = _approval(
        envelope,
        proposal,
        decision,
        approved_by="principal:operator-2",
    )
    alternate_proposal = _action_proposal(
        envelope,
        capability,
        decision,
        request_id="tool_approval_store_second",
    )

    with pytest.raises(ActionApprovalError, match="partially committed"):
        authority.authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            alternate_approval,
        )
    with pytest.raises(ActionApprovalError, match="differs from current action authority"):
        authority.authorize_for_dispatch(
            envelope,
            alternate_proposal,
            decision,
            approval,
        )


def test_generic_permit_writer_cannot_claim_approved_transaction(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    writer = store.permit_store.claim_writer(
        COMPILER_ID,
        COMPILER_VERSION,
        DIGEST_D,
    )

    with pytest.raises(ActionApprovalError, match="compiler write authority is invalid"):
        store.permit_store.authorize_approved_for_dispatch(
            envelope,
            proposal,
            decision,
            capability,
            approval,
            writer=writer,
            evaluated_at=NOW + timedelta(seconds=9),
            permit_ttl=timedelta(seconds=30),
        )

    assert store.permit_store.action_approvals() == ()
    assert store.permit_store.permits() == ()
    assert store.permit_store.approval_consumptions() == ()


def test_preexisting_partial_approval_tuple_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    with sqlite_store_module._write_transaction(path) as connection:
        sqlite_store_module._insert_action_approval(connection, approval)

    with pytest.raises(ActionApprovalError, match="partially committed"):
        _approved_authority(store, capability).authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            approval,
        )

    assert store.permit_store.action_approvals() == (approval,)
    assert store.permit_store.permits() == ()
    assert store.permit_store.approval_consumptions() == ()


def test_receipt_insert_failure_rolls_back_the_atomic_triple(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    connection = sqlite3.connect(path)
    try:
        connection.execute(
            """
            CREATE TRIGGER fail_approval_receipt_insert
            BEFORE INSERT ON graph_action_approval_consumptions
            BEGIN
                SELECT RAISE(ABORT, 'injected receipt failure');
            END
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ActionApprovalError, match="compare-and-set conflicted"):
        _approved_authority(store, capability).authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            approval,
        )

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER fail_approval_receipt_insert")
        connection.commit()
    finally:
        connection.close()
    assert store.permit_store.action_approvals() == ()
    assert store.permit_store.permits() == ()
    assert store.permit_store.approval_consumptions() == ()


def test_concurrent_approved_claim_has_one_durable_winner(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    other = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    authorities = (
        _approved_authority(store, capability),
        _approved_authority(other, capability),
    )
    barrier = threading.Barrier(2)

    def claim(authority: GraphApprovedActionPermitAuthority):
        barrier.wait()
        return authority.authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            approval,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(claim, authorities))

    assert sorted(result.action.newly_consumed for result in results) == [False, True]
    assert results[0].action.permit == results[1].action.permit
    assert results[0].receipt == results[1].receipt
    assert store.permit_store.action_approvals() == (approval,)
    assert store.permit_store.approval_consumptions() == (results[0].receipt,)


@pytest.mark.asyncio
async def test_unknown_worker_outcome_never_redispatches_after_reopen(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    dispatcher = GraphApprovedActionPermitDispatcher(_approved_authority(store, capability))
    calls = 0

    async def uncertain(*_args: object) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("worker outcome is unknown")

    with pytest.raises(RuntimeError, match="unknown"):
        await dispatcher.dispatch_once(
            envelope,
            proposal,
            decision,
            approval,
            uncertain,
        )

    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    retry_dispatcher = GraphApprovedActionPermitDispatcher(
        _approved_authority(reopened, capability)
    )

    async def must_not_run(*_args: object) -> None:
        nonlocal calls
        calls += 1

    retry = await retry_dispatcher.dispatch_once(
        envelope,
        proposal,
        decision,
        approval,
        must_not_run,
    )

    assert retry.dispatched is False
    assert calls == 1
    assert reopened.permit_store.action_approvals() == (approval,)
    assert reopened.permit_store.approval_consumptions() == (retry.authorization.receipt,)


@pytest.mark.asyncio
async def test_expired_exact_retry_recovers_receipt_without_redispatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    first = _approved_authority(store, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )
    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    dispatcher = GraphApprovedActionPermitDispatcher(
        _approved_authority(
            reopened,
            capability,
            evaluated_at=approval.expires_at,
        )
    )
    calls = 0

    async def must_not_run(*_args: object) -> None:
        nonlocal calls
        calls += 1

    retry = await dispatcher.dispatch_once(
        envelope,
        proposal,
        decision,
        approval,
        must_not_run,
    )

    assert retry.authorization.action.newly_consumed is False
    assert retry.authorization.receipt == first.receipt
    assert retry.dispatched is False
    assert calls == 0


def test_approval_ledgers_are_append_only_and_schema_fingerprinted(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    authorization = _approved_authority(store, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE graph_action_approval_envelopes SET request_units = 3 "
                "WHERE approval_id = ?",
                (approval.approval_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM graph_action_approval_consumptions WHERE receipt_id = ?",
                (authorization.receipt.receipt_id,),
            )
        connection.execute("DROP TRIGGER graph_action_approval_consumptions_no_delete")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SQLiteGraphStoreError, match="schema fingerprint"):
        SQLiteGraphStore(path, campaign_id=CAMPAIGN)


def test_backup_restore_preserves_approval_counts_heads_and_exact_retry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    authorization = _approved_authority(store, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )
    backup = tmp_path / "backups" / "approval-store.sqlite3"

    manifest = store.create_backup(backup, created_at=NOW + timedelta(seconds=10))
    restored = SQLiteGraphStore.restore_backup(
        backup,
        destination=tmp_path / "restored" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
    )

    assert manifest.schema_version == 4
    assert manifest.action_approval_count == 1
    assert manifest.action_approval_head_digest == approval.approval_digest
    assert manifest.approval_consumption_count == 1
    assert manifest.approval_consumption_head_digest == authorization.receipt.receipt_digest
    assert restored.permit_store.action_approvals() == (approval,)
    assert restored.permit_store.approval_consumptions() == (authorization.receipt,)
    retry = _approved_authority(restored, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )
    assert retry.action.newly_consumed is False
    assert retry.receipt == authorization.receipt


def _restore_immutable_update_trigger(connection: sqlite3.Connection, table: str) -> None:
    statement = sqlite_store_module._immutable_triggers(table, "ordinal")[
        ("trigger", f"{table}_no_update")
    ]
    connection.execute(statement)


def test_approval_index_tampering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    _approved_authority(store, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER graph_action_approval_envelopes_no_update")
        connection.execute(
            "UPDATE graph_action_approval_envelopes SET request_units = 3 WHERE approval_id = ?",
            (approval.approval_id,),
        )
        _restore_immutable_update_trigger(connection, "graph_action_approval_envelopes")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ActionApprovalError, match="index differs"):
        store.permit_store.action_approval(approval.approval_id)
    with pytest.raises(SQLiteGraphStoreError, match="backup creation failed"):
        store.create_backup(
            tmp_path / "backups" / "tampered-approval.sqlite3",
            created_at=NOW + timedelta(seconds=10),
        )


def test_approval_receipt_index_tampering_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    authorization = _approved_authority(store, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER graph_action_approval_consumptions_no_update")
        connection.execute(
            "UPDATE graph_action_approval_consumptions SET request_digest = ? WHERE receipt_id = ?",
            (DIGEST_F, authorization.receipt.receipt_id),
        )
        _restore_immutable_update_trigger(connection, "graph_action_approval_consumptions")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ActionApprovalError, match="index differs"):
        store.permit_store.approval_consumption(authorization.receipt.receipt_id)


def test_backup_rejects_approval_and_receipt_ordinal_equivocation(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, decision, capability, envelope, proposal, approval = _seed(path)
    authority = _approved_authority(store, capability)
    first = authority.authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        approval,
    )
    second_proposal = _action_proposal(
        envelope,
        capability,
        decision,
        request_id="tool_approval_store_second",
    )
    second_approval = _approval(
        envelope,
        second_proposal,
        decision,
        approved_by="principal:operator-2",
    )
    second = authority.authorize_for_dispatch(
        envelope,
        second_proposal,
        decision,
        second_approval,
    )
    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP TRIGGER graph_action_approval_consumptions_no_update")
        connection.execute(
            "UPDATE graph_action_approval_consumptions SET ordinal = 3 WHERE receipt_id = ?",
            (first.receipt.receipt_id,),
        )
        connection.execute(
            "UPDATE graph_action_approval_consumptions SET ordinal = 1 WHERE receipt_id = ?",
            (second.receipt.receipt_id,),
        )
        connection.execute(
            "UPDATE graph_action_approval_consumptions SET ordinal = 2 WHERE receipt_id = ?",
            (first.receipt.receipt_id,),
        )
        _restore_immutable_update_trigger(
            connection,
            "graph_action_approval_consumptions",
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SQLiteGraphStoreError, match="source authority"):
        store.create_backup(
            tmp_path / "backups" / "equivocated-order.sqlite3",
            created_at=NOW + timedelta(seconds=11),
        )


def _copy_current_store_as_v3(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700)
    connection = sqlite3.connect(destination)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        for statement in sqlite_store_module._CLEANUP_SCHEMA_OBJECT_SQL.values():
            connection.execute(statement)
        connection.executemany(
            "INSERT INTO graph_store_metadata (key, value) VALUES (?, ?)",
            (
                ("schema_version", "3"),
                ("schema_digest", sqlite_store_module._CLEANUP_SCHEMA_DIGEST),
                ("campaign_id", CAMPAIGN),
            ),
        )
        connection.execute("ATTACH DATABASE ? AS current_store", (str(source),))
        for table in (
            "graph_store_writers",
            "graph_events",
            "graph_nodes",
            "graph_projections",
            "graph_snapshots",
            "graph_action_permit_writers",
            "graph_action_permits",
            "graph_action_cleanup_reservations",
            "graph_cleanup_permits",
        ):
            columns = tuple(
                row[1] for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            column_sql = ", ".join(columns)
            connection.execute(
                f"INSERT INTO {table} ({column_sql}) SELECT {column_sql} FROM current_store.{table}"
            )
        connection.execute("PRAGMA user_version = 3")
        connection.execute(f"PRAGMA application_id = {sqlite_store_module._APPLICATION_ID}")
        connection.commit()
        connection.execute("DETACH DATABASE current_store")
    finally:
        connection.close()


def test_v3_store_migrates_without_fabricating_approval_authority(
    tmp_path: Path,
) -> None:
    current_path = tmp_path / "current" / "canonical-graph.sqlite3"
    current, decision, capability, envelope, proposal, _ = _seed(
        current_path,
        risk_tier=ToolRiskTier.T1,
    )
    permit = (
        _normal_authority(current, capability)
        .authorize_for_dispatch(
            envelope,
            proposal,
            decision,
        )
        .permit
    )
    v3_path = tmp_path / "v3" / "canonical-graph.sqlite3"
    _copy_current_store_as_v3(current_path, v3_path)

    migrated = SQLiteGraphStore(v3_path, campaign_id=CAMPAIGN)

    assert migrated.permit_store.permits() == (permit,)
    assert migrated.permit_store.action_approvals() == ()
    assert migrated.permit_store.approval_consumptions() == ()
    connection = sqlite3.connect(v3_path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        connection.close()
    assert "graph_action_approval_envelopes" in tables
    assert "graph_action_approval_consumptions" in tables
