from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import pajin.graph.sqlite_store as sqlite_store_module
from pajin.domain.models import AutonomyLevel, ToolRiskTier
from pajin.graph import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionCapabilityRegistry,
    ActionPermitBudgetExceeded,
    ActionPermitError,
    ActionPermitStaleDecision,
    ActionProposal,
    GraphActionPermitAuthority,
    GraphActionPermitDispatcher,
    GraphAdmissionAuthority,
    GraphContentOrigin,
    GraphDecision,
    GraphDecisionKind,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProjectionReconciler,
    GraphProposalKind,
    GraphProposalLineage,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    MissionEnvelope,
    RegisteredActionCapability,
    SQLiteGraphStore,
    SQLiteGraphStoreError,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_snapshot_ref,
)

NOW = datetime(2026, 7, 26, 18, 0, tzinfo=UTC)
CAMPAIGN = "graph-lab"
RUN_ID = "run:graph:permit"
PRODUCER_ID = "pajin.graph.permit-test-producer"
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


def _graph_proposal(tag: str) -> SurfaceProposal:
    request_digest = DIGEST_A if tag == "first" else DIGEST_B
    return SurfaceProposal(
        proposalId=f"proposal:surface:permit:{tag}",
        producerId=PRODUCER_ID,
        producerVersion="1.0.0",
        producerDigest=DIGEST_F,
        lineage=GraphProposalLineage(
            campaignId=CAMPAIGN,
            runId=RUN_ID,
            agentId="agent:graph-specialist",
            taskId=f"task:graph:permit:{tag}",
            requestId=f"tool_graph_permit_{tag}",
            requestDigest=request_digest,
            capabilityGrantId=f"grant:graph:permit:{tag}",
            capabilityGrantDigest=DIGEST_E,
            capabilityId="capability:graph-observe",
            capabilityVersion="1.0.0",
            capabilityDigest=DIGEST_F,
            sourceRootDigest=DIGEST_D,
            evidence=[
                {
                    "reference": f"evidence/graph-permit-{tag}.json",
                    "sha256": request_digest,
                }
            ],
            producedAt=NOW + timedelta(seconds=1),
        ),
        surface={
            "campaignId": CAMPAIGN,
            "targetId": f"target:{tag}",
            "surfaceType": "http-endpoint",
            "locatorSchema": "pajin.discovery.http-surface.v1",
            "locatorDigest": request_digest,
            "origin": GraphContentOrigin.TRUSTED_CORE,
        },
    )


def _admission_authority(
    store: SQLiteGraphStore,
    proposals: list[SurfaceProposal],
) -> GraphAdmissionAuthority:
    return GraphAdmissionAuthority(
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
        lineage_verifier=TrustedGraphLineageRegistry(proposal.lineage for proposal in proposals),
        event_log=store.event_log,
        clock=lambda: NOW + timedelta(seconds=2),
    )


def _capability(*, tool_digest: str = DIGEST_B) -> RegisteredActionCapability:
    return RegisteredActionCapability(
        capabilityId="capability:http-observe",
        capabilityVersion="1.0.0",
        toolId="http.request",
        toolVersion="1.0.0",
        toolDigest=tool_digest,
        riskTier=ToolRiskTier.T2,
    )


def _envelope(
    capability: RegisteredActionCapability,
    *,
    tool_call_limit: int = 10,
    request_unit_limit: int = 100,
    rolling_window_seconds: int | None = None,
    rolling_request_unit_limit: int | None = None,
) -> MissionEnvelope:
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
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(
            toolCallLimit=tool_call_limit,
            requestUnitLimit=request_unit_limit,
            costLimitMicrousd=1_000_000,
            rollingWindowSeconds=rolling_window_seconds,
            rollingRequestUnitLimit=rolling_request_unit_limit,
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
    request_id: str = "tool_action_permit_first",
    target_digest: str = TARGET_DIGEST,
    request_units: int = 2,
) -> ActionProposal:
    request_digest = DIGEST_A if request_id.endswith("first") else DIGEST_B
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
        targetDigest=target_digest,
        requestId=request_id,
        requestDigest=request_digest,
        normalizedParametersDigest=DIGEST_E,
        riskTier=ToolRiskTier.T2,
        reservation=ActionBudgetReservation(
            requestUnits=request_units,
            costMicrousd=1_000,
        ),
        createdAt=NOW + timedelta(seconds=6),
    )


def _seed(
    path: Path,
) -> tuple[
    SQLiteGraphStore,
    GraphAdmissionAuthority,
    GraphDecision,
    RegisteredActionCapability,
    MissionEnvelope,
    ActionProposal,
]:
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    first = _graph_proposal("first")
    late = _graph_proposal("late")
    admission = _admission_authority(store, [first, late])
    admission.submit(first)
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
    capability = _capability()
    envelope = _envelope(capability)
    proposal = _action_proposal(envelope, capability, decision)
    return store, admission, decision, capability, envelope, proposal


def _permit_authority(
    store: SQLiteGraphStore,
    capability: RegisteredActionCapability,
    *,
    clock: datetime = NOW + timedelta(seconds=7),
) -> GraphActionPermitAuthority:
    return GraphActionPermitAuthority(
        campaign_id=CAMPAIGN,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        compiler_digest=DIGEST_D,
        capabilities=ActionCapabilityRegistry([capability]),
        permit_store=store.permit_store,
        clock=lambda: clock,
    )


def test_action_contracts_are_canonical_and_registry_requires_exact_version() -> None:
    capability = _capability()
    assert capability.reference().capability_digest == capability.capability_digest
    raw = capability.model_dump(mode="json", by_alias=True)
    raw["toolDigest"] = DIGEST_C
    with pytest.raises(ValidationError, match="digest differs"):
        RegisteredActionCapability.model_validate(raw)

    registry = ActionCapabilityRegistry([capability])
    assert registry.resolve(capability.reference()) == capability
    different = _capability(tool_digest=DIGEST_C)
    with pytest.raises(ActionPermitError, match="differs"):
        registry.resolve(different.reference())


def test_final_authority_transaction_persists_one_consumed_permit_and_retry(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, capability, envelope, proposal = _seed(path)
    first = _permit_authority(store, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
    )

    assert first.newly_consumed is True
    assert first.permit.status == "consumed"
    assert first.permit.snapshot == decision.snapshot
    assert store.permit_store.permit(first.permit.permit_id) == first.permit
    assert store.permit_store.permits() == (first.permit,)

    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    retry = _permit_authority(reopened, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
    )

    assert retry.newly_consumed is False
    assert retry.permit == first.permit
    assert reopened.permit_store.permits() == (first.permit,)


def test_action_permit_fails_closed_before_and_after_projection_recovery(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, admission, decision, capability, envelope, proposal = _seed(path)
    admission.submit(_graph_proposal("late"))
    authority = _permit_authority(store, capability)

    with pytest.raises(ActionPermitStaleDecision, match="recovery is required"):
        authority.authorize_for_dispatch(envelope, proposal, decision)

    GraphProjectionReconciler(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).reconcile()
    with pytest.raises(ActionPermitStaleDecision, match="Graph changed"):
        authority.authorize_for_dispatch(envelope, proposal, decision)
    assert store.permit_store.permits() == ()


def test_cross_instance_exact_retry_has_one_dispatch_winner(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    _, _, decision, capability, envelope, proposal = _seed(path)
    left = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    right = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    left_authority = _permit_authority(left, capability)
    right_authority = _permit_authority(right, capability)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                left_authority.authorize_for_dispatch,
                envelope,
                proposal,
                decision,
            ),
            pool.submit(
                right_authority.authorize_for_dispatch,
                envelope,
                proposal,
                decision,
            ),
        ]
    results = [future.result() for future in futures]

    assert sorted(result.newly_consumed for result in results) == [False, True]
    assert results[0].permit == results[1].permit
    assert len(left.permit_store.permits()) == 1


@pytest.mark.asyncio
async def test_dispatch_failure_is_terminal_and_exact_retry_does_not_redispatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, capability, envelope, proposal = _seed(path)
    dispatcher = GraphActionPermitDispatcher(_permit_authority(store, capability))
    dispatch_calls = 0

    async def fail_after_claim(_: object) -> str:
        nonlocal dispatch_calls
        dispatch_calls += 1
        raise RuntimeError("Worker start is uncertain")

    with pytest.raises(RuntimeError, match="uncertain"):
        await dispatcher.dispatch_once(
            envelope,
            proposal,
            decision,
            fail_after_claim,
        )

    async def must_not_run(_: object) -> str:
        nonlocal dispatch_calls
        dispatch_calls += 1
        return "unexpected"

    retry = await dispatcher.dispatch_once(
        envelope,
        proposal,
        decision,
        must_not_run,
    )

    assert retry.dispatched is False
    assert retry.result is None
    assert dispatch_calls == 1
    assert store.permit_store.permits() == (retry.permit,)


def test_envelope_budget_and_rolling_rate_are_durable(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, capability, _, _ = _seed(path)
    envelope = _envelope(
        capability,
        rolling_window_seconds=60,
        rolling_request_unit_limit=2,
    )
    first = _action_proposal(envelope, capability, decision)
    second = _action_proposal(
        envelope,
        capability,
        decision,
        request_id="tool_action_permit_second",
    )
    authority = _permit_authority(store, capability)

    assert authority.authorize_for_dispatch(
        envelope,
        first,
        decision,
    ).newly_consumed
    with pytest.raises(ActionPermitBudgetExceeded, match="rolling"):
        authority.authorize_for_dispatch(envelope, second, decision)
    assert len(store.permit_store.permits()) == 1


def test_same_request_identity_cannot_equivocate_across_proposals(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, capability, envelope, proposal = _seed(path)
    authority = _permit_authority(store, capability)
    authority.authorize_for_dispatch(envelope, proposal, decision)
    raw = proposal.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "proposalId": "",
            "proposalDigest": "",
            "normalizedParametersDigest": DIGEST_F,
        }
    )
    equivocation = ActionProposal.model_validate(raw)

    with pytest.raises(ActionPermitError, match="already consumed"):
        authority.authorize_for_dispatch(envelope, equivocation, decision)
    assert len(store.permit_store.permits()) == 1


def test_scope_expiry_and_capability_drift_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, capability, envelope, _ = _seed(path)
    outside = _action_proposal(
        envelope,
        capability,
        decision,
        target_digest=DIGEST_F,
    )
    with pytest.raises(ActionPermitError, match="outside"):
        _permit_authority(store, capability).authorize_for_dispatch(
            envelope,
            outside,
            decision,
        )

    expired_store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    valid = _action_proposal(envelope, capability, decision)
    with pytest.raises(ActionPermitError, match="not active"):
        _permit_authority(
            expired_store,
            capability,
            clock=NOW + timedelta(hours=2),
        ).authorize_for_dispatch(envelope, valid, decision)


def test_action_permit_ledger_is_append_only_and_tamper_evident(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, capability, envelope, proposal = _seed(path)
    permit = (
        _permit_authority(store, capability)
        .authorize_for_dispatch(
            envelope,
            proposal,
            decision,
        )
        .permit
    )

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE graph_action_permits SET request_units = 1 WHERE permit_id = ?",
                (permit.permit_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM graph_action_permits WHERE permit_id = ?",
                (permit.permit_id,),
            )
        connection.execute("DROP TRIGGER graph_action_permits_no_delete")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SQLiteGraphStoreError, match="schema fingerprint"):
        SQLiteGraphStore(path, campaign_id=CAMPAIGN)


def test_v1_store_migrates_without_fabricating_permit_authority(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    path.parent.mkdir(mode=0o700)
    if os.name == "posix":
        path.parent.chmod(0o700)
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        for statement in sqlite_store_module._LEGACY_SCHEMA_OBJECT_SQL.values():
            connection.execute(statement)
        connection.executemany(
            "INSERT INTO graph_store_metadata (key, value) VALUES (?, ?)",
            (
                ("schema_version", "1"),
                ("schema_digest", sqlite_store_module._LEGACY_SCHEMA_DIGEST),
                ("campaign_id", CAMPAIGN),
            ),
        )
        connection.execute("PRAGMA user_version = 1")
        connection.execute(f"PRAGMA application_id = {sqlite_store_module._APPLICATION_ID}")
        genesis = sqlite_store_module.GraphProjector.project(
            campaign_id=CAMPAIGN,
            events=(),
        )
        connection.execute(
            """
            INSERT INTO graph_projections (
                revision, event_log_head_digest, projection_id,
                projection_digest, projection_json
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                genesis.revision,
                genesis.event_log_head_digest,
                genesis.projection_id,
                genesis.projection_digest,
                sqlite3.Binary(sqlite_store_module._projection_bytes(genesis)),
            ),
        )
        connection.commit()
    finally:
        connection.close()
    if os.name == "posix":
        path.chmod(0o600)

    migrated = SQLiteGraphStore(path, campaign_id=CAMPAIGN)

    assert migrated.event_log.events() == ()
    assert migrated.projection_store.current() == genesis
    assert migrated.permit_store.permits() == ()
    check = sqlite3.connect(path)
    try:
        assert check.execute("PRAGMA user_version").fetchone() == (2,)
        tables = {
            row[0]
            for row in check.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        check.close()
    assert "graph_action_permits" in tables
