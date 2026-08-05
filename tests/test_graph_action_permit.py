from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

import pajin.graph.backup_retention as backup_retention_module
import pajin.graph.sqlite_store as sqlite_store_module
from pajin.domain.models import AutonomyLevel, ToolRiskTier
from pajin.graph import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionCapabilityRegistry,
    ActionCleanupReservation,
    ActionCleanupReservationRequest,
    ActionPermit,
    ActionPermitBudgetExceeded,
    ActionPermitError,
    ActionPermitStaleDecision,
    ActionProposal,
    CleanupPermit,
    CleanupPermitBudgetExceeded,
    CleanupPermitError,
    CleanupPermitInputAuthority,
    CleanupRequest,
    GraphActionPermitAuthority,
    GraphActionPermitDispatcher,
    GraphAdmissionAuthority,
    GraphCleanupPermitAuthority,
    GraphCleanupPermitDispatcher,
    GraphContentOrigin,
    GraphDecision,
    GraphDecisionKind,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProjectionReconciler,
    GraphProposalKind,
    GraphProposalLineage,
    GraphReversibleActionPermitAuthority,
    GraphReversibleActionPermitDispatcher,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    GraphSnapshotRef,
    MissionEnvelope,
    RegisteredActionCapability,
    ReversibleActionPermitInputAuthority,
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
        definitionDigest=DIGEST_C,
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
    assert capability.reference().definition_digest == DIGEST_C
    raw = capability.model_dump(mode="json", by_alias=True)
    raw["toolDigest"] = DIGEST_C
    with pytest.raises(ValidationError, match="digest differs"):
        RegisteredActionCapability.model_validate(raw)

    raw = capability.model_dump(mode="json", by_alias=True)
    raw["definitionDigest"] = DIGEST_A
    with pytest.raises(ValidationError, match="digest differs"):
        RegisteredActionCapability.model_validate(raw)

    raw = capability.model_dump(mode="json", by_alias=True)
    raw["apiVersion"] = "pajin.dev/registered-action-capability/v1alpha1"
    with pytest.raises(ValidationError, match="literal_error"):
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


def test_verified_backup_restore_preserves_consumed_action_permit(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, capability, envelope, proposal = _seed(path)
    authorization = _permit_authority(store, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
    )
    backup = tmp_path / "backups" / "graph-lab.sqlite3"

    manifest = store.create_backup(
        backup,
        created_at=NOW + timedelta(seconds=8),
    )
    restored = SQLiteGraphStore.restore_backup(
        backup,
        destination=tmp_path / "restored" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
    )

    assert manifest.action_permit_count == 1
    assert manifest.action_permit_head_digest == authorization.permit.permit_digest
    assert restored.permit_store.permits() == (authorization.permit,)
    retry = _permit_authority(restored, capability).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
    )
    assert retry.newly_consumed is False
    assert retry.permit == authorization.permit


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
        assert check.execute("PRAGMA user_version").fetchone() == (3,)
        tables = {
            row[0]
            for row in check.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
    finally:
        check.close()
    assert "graph_action_permits" in tables
    assert "graph_action_cleanup_reservations" in tables
    assert "graph_cleanup_permits" in tables


def _cleanup_capability() -> RegisteredActionCapability:
    return RegisteredActionCapability(
        capabilityId="capability:state-restore",
        capabilityVersion="1.0.0",
        definitionDigest=DIGEST_D,
        toolId="state.restore",
        toolVersion="1.0.0",
        toolDigest=DIGEST_E,
        riskTier=ToolRiskTier.T2,
    )


def _reversible_envelope(
    action: RegisteredActionCapability,
    cleanup: RegisteredActionCapability,
    *,
    tool_call_limit: int = 4,
    request_unit_limit: int = 100,
    cost_limit_microusd: int = 1_000_000,
    rolling_window_seconds: int | None = None,
    rolling_request_unit_limit: int | None = None,
) -> MissionEnvelope:
    capabilities = tuple(
        sorted(
            (action.reference(), cleanup.reference()),
            key=lambda item: (
                item.capability_id,
                item.capability_version,
                item.capability_digest,
            ),
        )
    )
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
        allowedCapabilities=capabilities,
        allowedTargetDigests=(TARGET_DIGEST,),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(
            toolCallLimit=tool_call_limit,
            requestUnitLimit=request_unit_limit,
            costLimitMicrousd=cost_limit_microusd,
            rollingWindowSeconds=rolling_window_seconds,
            rollingRequestUnitLimit=rolling_request_unit_limit,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=NOW,
        notBefore=NOW,
        expiresAt=NOW + timedelta(hours=1),
    )


def _cleanup_reservation_request(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    cleanup: RegisteredActionCapability,
    *,
    request_units: int = 3,
) -> ActionCleanupReservationRequest:
    return ActionCleanupReservationRequest(
        campaignId=CAMPAIGN,
        runId=RUN_ID,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        sourceActionProposalId=proposal.proposal_id,
        sourceActionProposalDigest=proposal.proposal_digest,
        cleanupCapability=cleanup.reference(),
        targetDigest=proposal.target_digest,
        cleanupHandlerId="pajin.cleanup.handler",
        cleanupHandlerVersion="1.0.0",
        cleanupHandlerDigest=DIGEST_B,
        cleanupExecutorId="pajin.cleanup.executor",
        cleanupExecutorVersion="1.0.0",
        cleanupExecutorDigest=DIGEST_C,
        reservation=ActionBudgetReservation(
            requestUnits=request_units,
            costMicrousd=2_000,
        ),
        createdAt=NOW + timedelta(seconds=6),
        claimExpiresAt=NOW + timedelta(minutes=10),
    )


class _FixtureCleanupInputAuthority(
    ReversibleActionPermitInputAuthority,
    CleanupPermitInputAuthority,
):
    """Test-owned authority for one signed reversible definition and cleanup mapping."""

    def __init__(
        self,
        action: RegisteredActionCapability,
        cleanup: RegisteredActionCapability,
        *,
        source_action: ActionPermit | None = None,
    ) -> None:
        self._action = action.reference()
        self._cleanup = cleanup.reference()
        self._source_action = source_action

    def verify_reversible_action(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        cleanup_request: ActionCleanupReservationRequest,
    ) -> None:
        expected = (
            self._action,
            self._cleanup,
            "pajin.cleanup.handler",
            "1.0.0",
            DIGEST_B,
            "pajin.cleanup.executor",
            "1.0.0",
            DIGEST_C,
        )
        actual = (
            proposal.capability,
            cleanup_request.cleanup_capability,
            cleanup_request.cleanup_handler_id,
            cleanup_request.cleanup_handler_version,
            cleanup_request.cleanup_handler_digest,
            cleanup_request.cleanup_executor_id,
            cleanup_request.cleanup_executor_version,
            cleanup_request.cleanup_executor_digest,
        )
        if actual != expected or decision.decision_payload_digest != DIGEST_C:
            raise ValueError(
                "fixture definition is not reversible-write with required cleanup"
            )
        if (
            envelope.run_id != RUN_ID
            or cleanup_request.source_action_proposal_id != proposal.proposal_id
            or cleanup_request.source_action_proposal_digest != proposal.proposal_digest
        ):
            raise ValueError("fixture reversible definition lineage differs")

    def verify_cleanup_request(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
    ) -> None:
        expected = (
            self._cleanup,
            "outcome:reversible:first",
            DIGEST_B,
            DIGEST_C,
            DIGEST_D,
            DIGEST_E,
            "worker:reversible:first",
            "pajin.cleanup.handler",
            "1.0.0",
            DIGEST_B,
            "pajin.cleanup.executor",
            "1.0.0",
            DIGEST_C,
            DIGEST_F,
        )
        actual = (
            request.capability,
            request.source_outcome_id,
            request.source_outcome_digest,
            request.source_run_root_digest,
            request.source_terminal_event_digest,
            request.source_gateway_outcome_digest,
            request.source_worker_execution_id,
            request.cleanup_handler_id,
            request.cleanup_handler_version,
            request.cleanup_handler_digest,
            request.cleanup_executor_id,
            request.cleanup_executor_version,
            request.cleanup_executor_digest,
            request.cleanup_plan_digest,
        )
        if actual != expected:
            raise ValueError("fixture sealed outcome or cleanup plan differs")
        if self._source_action is None or (
            request.source_action_permit_id != self._source_action.permit_id
            or request.source_action_permit_digest != self._source_action.permit_digest
            or request.source_action_dispatch_id != self._source_action.dispatch_id
        ):
            raise ValueError("fixture sealed source ActionPermit differs")
        if (
            envelope.run_id != RUN_ID
            or decision.decision_payload_digest != request.source_outcome_digest
            or decision.decision_id != request.decision_id
            or decision.decision_digest != request.decision_digest
        ):
            raise ValueError("fixture cleanup decision lineage differs")


class _RejectingCleanupInputAuthority(
    ReversibleActionPermitInputAuthority,
    CleanupPermitInputAuthority,
):
    def verify_reversible_action(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        cleanup_request: ActionCleanupReservationRequest,
    ) -> None:
        raise ValueError("reversible input is not externally authenticated")

    def verify_cleanup_request(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
    ) -> None:
        raise ValueError("cleanup input is not externally authenticated")


def _reversible_authority(
    store: SQLiteGraphStore,
    action: RegisteredActionCapability,
    cleanup: RegisteredActionCapability,
    *,
    clock: datetime = NOW + timedelta(seconds=7),
    input_authority: ReversibleActionPermitInputAuthority | None = None,
) -> GraphReversibleActionPermitAuthority:
    return GraphReversibleActionPermitAuthority(
        campaign_id=CAMPAIGN,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        compiler_digest=DIGEST_D,
        capabilities=ActionCapabilityRegistry([action, cleanup]),
        permit_store=store.permit_store,
        input_authority=input_authority
        or _FixtureCleanupInputAuthority(action, cleanup),
        clock=lambda: clock,
    )


def _cleanup_authority(
    store: SQLiteGraphStore,
    action: RegisteredActionCapability,
    cleanup: RegisteredActionCapability,
    *,
    clock: datetime = NOW + timedelta(seconds=10),
    input_authority: CleanupPermitInputAuthority | None = None,
) -> GraphCleanupPermitAuthority:
    source_actions = store.permit_store.permits()
    default_input_authority = _FixtureCleanupInputAuthority(
        action,
        cleanup,
        source_action=source_actions[0] if len(source_actions) == 1 else None,
    )
    return GraphCleanupPermitAuthority(
        campaign_id=CAMPAIGN,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        compiler_digest=DIGEST_D,
        capabilities=ActionCapabilityRegistry([action, cleanup]),
        permit_store=store.permit_store,
        input_authority=input_authority or default_input_authority,
        clock=lambda: clock,
    )


def _cleanup_request(
    envelope: MissionEnvelope,
    action_permit: ActionPermit,
    reservation: ActionCleanupReservation,
    cleanup: RegisteredActionCapability,
    snapshot: GraphSnapshotRef,
) -> tuple[GraphDecision, CleanupRequest]:
    outcome_digest = DIGEST_B
    decision = GraphDecision(
        campaignId=CAMPAIGN,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=outcome_digest,
        snapshot=snapshot,
        actorId="pajin.graph.cleanup-planner",
        actorDigest=DIGEST_F,
        createdAt=NOW + timedelta(seconds=8),
    )
    request = CleanupRequest(
        campaignId=CAMPAIGN,
        runId=RUN_ID,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        cleanupReservationId=reservation.cleanup_reservation_id,
        cleanupReservationDigest=reservation.cleanup_reservation_digest,
        sourceActionPermitId=action_permit.permit_id,
        sourceActionPermitDigest=action_permit.permit_digest,
        sourceActionDispatchId=action_permit.dispatch_id,
        sourceOutcomeId="outcome:reversible:first",
        sourceOutcomeDigest=outcome_digest,
        sourceRunRootDigest=DIGEST_C,
        sourceTerminalEventDigest=DIGEST_D,
        sourceGatewayOutcomeDigest=DIGEST_E,
        sourceWorkerExecutionId="worker:reversible:first",
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        cleanupHandlerId=reservation.cleanup_handler_id,
        cleanupHandlerVersion=reservation.cleanup_handler_version,
        cleanupHandlerDigest=reservation.cleanup_handler_digest,
        cleanupExecutorId=reservation.cleanup_executor_id,
        cleanupExecutorVersion=reservation.cleanup_executor_version,
        cleanupExecutorDigest=reservation.cleanup_executor_digest,
        cleanupPlanDigest=DIGEST_F,
        capability=cleanup.reference(),
        targetDigest=reservation.target_digest,
        requestId="tool_cleanup_permit_first",
        requestDigest=DIGEST_A,
        normalizedParametersDigest=DIGEST_B,
        reservation=reservation.reservation,
        createdAt=NOW + timedelta(seconds=9),
    )
    return decision, request


def test_reversible_action_atomically_holds_cleanup_and_consumes_once(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    hold_request = _cleanup_reservation_request(envelope, proposal, cleanup)
    raw_hold = hold_request.model_dump(mode="json", by_alias=True)
    raw_hold["executable"] = 0
    with pytest.raises(ValidationError, match="literal non-executable"):
        ActionCleanupReservationRequest.model_validate(raw_hold)

    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        hold_request,
    )

    assert reversible.action.newly_consumed is True
    assert reversible.cleanup_reservation.source_action_permit_id == (
        reversible.action.permit.permit_id
    )
    assert store.permit_store.permits() == (reversible.action.permit,)
    assert store.permit_store.cleanup_reservations() == (
        reversible.cleanup_reservation,
    )

    cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    assert request.executable is False
    assert request.permit_granted is False
    raw_request = request.model_dump(mode="json", by_alias=True)
    raw_request["permitGranted"] = 0
    with pytest.raises(ValidationError, match="literal false"):
        CleanupRequest.model_validate(raw_request)
    authorization = _cleanup_authority(
        store,
        action,
        cleanup,
    ).authorize_for_dispatch(envelope, request, cleanup_decision)

    assert authorization.newly_consumed is True
    assert authorization.permit.cleanup_reservation_id == (
        reversible.cleanup_reservation.cleanup_reservation_id
    )
    assert store.permit_store.cleanup_permits() == (authorization.permit,)

    reopened = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    retry = _cleanup_authority(reopened, action, cleanup).authorize_for_dispatch(
        envelope,
        request,
        cleanup_decision,
    )
    assert retry.newly_consumed is False
    assert retry.permit == authorization.permit


def test_reversible_pair_budget_is_atomic_and_outstanding_hold_blocks_action(
    tmp_path: Path,
) -> None:
    overflow_path = tmp_path / "overflow" / "canonical-graph.sqlite3"
    overflow, _, decision, action, _, _ = _seed(overflow_path)
    cleanup = _cleanup_capability()
    too_small = _reversible_envelope(action, cleanup, tool_call_limit=1)
    proposal = _action_proposal(too_small, action, decision)
    request = _cleanup_reservation_request(too_small, proposal, cleanup)

    with pytest.raises(CleanupPermitBudgetExceeded, match="budget"):
        _reversible_authority(overflow, action, cleanup).authorize_for_dispatch(
            too_small,
            proposal,
            decision,
            request,
        )
    assert overflow.permit_store.permits() == ()
    assert overflow.permit_store.cleanup_reservations() == ()

    path = tmp_path / "held" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    request = _cleanup_reservation_request(envelope, proposal, cleanup)
    _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        request,
    )
    next_action = _action_proposal(
        envelope,
        action,
        decision,
        request_id="tool_action_permit_second",
    )
    with pytest.raises(ActionPermitBudgetExceeded, match="budget"):
        _permit_authority(store, action).authorize_for_dispatch(
            envelope,
            next_action,
            decision,
        )


@pytest.mark.parametrize(
    ("envelope_options", "error_pattern"),
    (
        ({"request_unit_limit": 4}, "budget"),
        ({"cost_limit_microusd": 2_999}, "budget"),
        (
            {
                "rolling_window_seconds": 60,
                "rolling_request_unit_limit": 4,
            },
            "rolling",
        ),
    ),
)
def test_reversible_pair_enforces_units_cost_and_rolling_budget(
    tmp_path: Path,
    envelope_options: dict[str, int],
    error_pattern: str,
) -> None:
    path = tmp_path / error_pattern / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(
        action,
        cleanup,
        tool_call_limit=2,
        **envelope_options,
    )
    proposal = _action_proposal(envelope, action, decision, request_units=2)
    request = _cleanup_reservation_request(
        envelope,
        proposal,
        cleanup,
        request_units=3,
    )

    with pytest.raises(CleanupPermitBudgetExceeded, match=error_pattern):
        _reversible_authority(store, action, cleanup).authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            request,
        )
    assert store.permit_store.permits() == ()
    assert store.permit_store.cleanup_reservations() == ()


@pytest.mark.asyncio
async def test_cleanup_dispatch_uncertainty_is_terminal_and_not_retried(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        _cleanup_reservation_request(envelope, proposal, cleanup),
    )
    cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    dispatcher = GraphCleanupPermitDispatcher(
        _cleanup_authority(store, action, cleanup)
    )
    calls = 0

    async def uncertain(_: object) -> str:
        nonlocal calls
        calls += 1
        raise RuntimeError("cleanup start is uncertain")

    with pytest.raises(RuntimeError, match="uncertain"):
        await dispatcher.dispatch_once(
            envelope,
            request,
            cleanup_decision,
            uncertain,
        )

    async def must_not_run(_: object) -> str:
        nonlocal calls
        calls += 1
        return "unexpected"

    retry = await dispatcher.dispatch_once(
        envelope,
        request,
        cleanup_decision,
        must_not_run,
    )
    assert retry.dispatched is False
    assert retry.result is None
    assert calls == 1


@pytest.mark.asyncio
async def test_external_input_authority_rejects_before_claim_or_dispatch(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    hold_request = _cleanup_reservation_request(envelope, proposal, cleanup)
    rejecting = _RejectingCleanupInputAuthority()
    reversible_dispatcher = GraphReversibleActionPermitDispatcher(
        _reversible_authority(
            store,
            action,
            cleanup,
            input_authority=rejecting,
        )
    )
    calls = 0

    async def must_not_dispatch(_: object) -> str:
        nonlocal calls
        calls += 1
        return "unexpected"

    with pytest.raises(CleanupPermitError, match="input authority rejected"):
        await reversible_dispatcher.dispatch_once(
            envelope,
            proposal,
            decision,
            hold_request,
            must_not_dispatch,
        )
    assert calls == 0
    assert store.permit_store.permits() == ()
    assert store.permit_store.cleanup_reservations() == ()

    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        hold_request,
    )
    cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    cleanup_dispatcher = GraphCleanupPermitDispatcher(
        _cleanup_authority(
            store,
            action,
            cleanup,
            input_authority=rejecting,
        )
    )
    with pytest.raises(CleanupPermitError, match="input authority rejected"):
        await cleanup_dispatcher.dispatch_once(
            envelope,
            request,
            cleanup_decision,
            must_not_dispatch,
        )
    assert calls == 0
    assert store.permit_store.cleanup_permits() == ()


def test_cleanup_cross_action_and_equivocating_plan_are_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        _cleanup_reservation_request(envelope, proposal, cleanup),
    )
    cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    authority = _cleanup_authority(store, action, cleanup)
    authority.authorize_for_dispatch(envelope, request, cleanup_decision)

    raw = request.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "cleanupRequestId": "",
            "cleanupRequestDigest": "",
            "cleanupPlanDigest": DIGEST_A,
        }
    )
    equivocation = CleanupRequest.model_validate(raw)
    with pytest.raises(CleanupPermitError, match="input authority rejected"):
        authority.authorize_for_dispatch(envelope, equivocation, cleanup_decision)

    raw = request.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "cleanupRequestId": "",
            "cleanupRequestDigest": "",
            "sourceActionPermitDigest": DIGEST_F,
        }
    )
    cross_action = CleanupRequest.model_validate(raw)
    with pytest.raises(CleanupPermitError, match="input authority rejected"):
        authority.authorize_for_dispatch(envelope, cross_action, cleanup_decision)


def test_concurrent_reversible_claim_has_one_action_and_one_cleanup_hold(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    _, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    request = _cleanup_reservation_request(envelope, proposal, cleanup)
    left = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    right = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    authorities = (
        _reversible_authority(left, action, cleanup),
        _reversible_authority(right, action, cleanup),
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda authority: authority.authorize_for_dispatch(
                    envelope,
                    proposal,
                    decision,
                    request,
                ),
                authorities,
            )
        )

    assert sorted(result.action.newly_consumed for result in results) == [False, True]
    assert results[0].action.permit == results[1].action.permit
    assert results[0].cleanup_reservation == results[1].cleanup_reservation
    assert len(left.permit_store.permits()) == 1
    assert len(left.permit_store.cleanup_reservations()) == 1


def test_reversible_pair_rolls_back_if_cleanup_hold_insert_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    request = _cleanup_reservation_request(envelope, proposal, cleanup)

    def fail_hold_insert(_: object, __: object) -> None:
        raise RuntimeError("injected cleanup hold failure")

    monkeypatch.setattr(
        sqlite_store_module,
        "_insert_cleanup_reservation",
        fail_hold_insert,
    )
    with pytest.raises(RuntimeError, match="injected"):
        _reversible_authority(store, action, cleanup).authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            request,
        )
    assert store.permit_store.permits() == ()
    assert store.permit_store.cleanup_reservations() == ()


def test_cleanup_authority_backup_restore_preserves_exact_retry(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        _cleanup_reservation_request(envelope, proposal, cleanup),
    )
    cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    cleanup_authorization = _cleanup_authority(
        store,
        action,
        cleanup,
    ).authorize_for_dispatch(envelope, request, cleanup_decision)
    backup = tmp_path / "backups" / "graph-lab.sqlite3"

    manifest = store.create_backup(backup, created_at=NOW + timedelta(seconds=11))
    restored = SQLiteGraphStore.restore_backup(
        backup,
        destination=tmp_path / "restored" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
    )

    assert manifest.schema_version == 3
    assert manifest.cleanup_reservation_count == 1
    assert manifest.cleanup_reservation_head_digest == (
        reversible.cleanup_reservation.cleanup_reservation_digest
    )
    assert manifest.cleanup_permit_count == 1
    assert manifest.cleanup_permit_head_digest == (
        cleanup_authorization.permit.cleanup_permit_digest
    )
    retry = _cleanup_authority(restored, action, cleanup).authorize_for_dispatch(
        envelope,
        request,
        cleanup_decision,
    )
    assert retry.newly_consumed is False
    assert retry.permit == cleanup_authorization.permit


def test_backup_rejects_canonical_cleanup_hold_with_substituted_lineage(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    source = _permit_authority(store, action).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
    ).permit
    hold_request = _cleanup_reservation_request(envelope, proposal, cleanup)
    legitimate = sqlite_store_module.build_action_cleanup_reservation(
        envelope,
        source,
        hold_request,
        evaluated_at=NOW + timedelta(seconds=7),
    )
    baseline = sqlite_store_module._verified_graph_store_state(
        path,
        campaign_id=CAMPAIGN,
    )
    raw = legitimate.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "cleanupReservationId": "",
            "cleanupReservationDigest": "",
            "runId": "run:graph:forged-cleanup",
        }
    )
    forged = ActionCleanupReservation.model_validate(raw)
    with sqlite_store_module._write_transaction(path) as connection:
        sqlite_store_module._insert_cleanup_reservation(connection, forged)

    with pytest.raises(SQLiteGraphStoreError, match="differs from its ActionPermit"):
        store.create_backup(
            tmp_path / "backups" / "forged-hold.sqlite3",
            created_at=NOW + timedelta(seconds=11),
        )

    database = path.read_bytes()
    malicious_manifest = sqlite_store_module.SQLiteGraphBackupManifest(
        campaignId=CAMPAIGN,
        createdAt=NOW + timedelta(seconds=11),
        databaseSha256=sqlite_store_module.sha256(database).hexdigest(),
        databaseBytes=len(database),
        eventCount=baseline.event_count,
        eventLogHeadDigest=baseline.event_log_head_digest,
        projectionRevision=baseline.projection_revision,
        projectionDigest=baseline.projection_digest,
        snapshotCount=baseline.snapshot_count,
        snapshotHeadDigest=baseline.snapshot_head_digest,
        actionPermitCount=baseline.action_permit_count,
        actionPermitHeadDigest=baseline.action_permit_head_digest,
        cleanupReservationCount=1,
        cleanupReservationHeadDigest=forged.cleanup_reservation_digest,
        cleanupPermitCount=0,
        cleanupPermitHeadDigest=None,
    )
    sqlite_store_module.sqlite_graph_backup_manifest_path(path).write_bytes(
        sqlite_store_module._backup_manifest_bytes(malicious_manifest)
    )
    with pytest.raises(SQLiteGraphStoreError, match="differs from its ActionPermit"):
        SQLiteGraphStore.restore_backup(
            path,
            destination=tmp_path / "restored-forged-hold" / "canonical-graph.sqlite3",
            campaign_id=CAMPAIGN,
        )


def test_backup_rejects_canonical_cleanup_permit_with_substituted_authority(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        _cleanup_reservation_request(envelope, proposal, cleanup),
    )
    _cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    legitimate = sqlite_store_module.build_cleanup_permit(
        envelope,
        request,
        reversible.cleanup_reservation,
        evaluated_at=NOW + timedelta(seconds=10),
        permit_ttl=timedelta(seconds=30),
    )
    raw = legitimate.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "cleanupPermitId": "",
            "cleanupPermitDigest": "",
            "cleanupDispatchId": "",
            "cleanupHandlerDigest": DIGEST_F,
        }
    )
    forged = CleanupPermit.model_validate(raw)
    with sqlite_store_module._write_transaction(path) as connection:
        sqlite_store_module._insert_cleanup_permit(connection, forged)

    with pytest.raises(SQLiteGraphStoreError, match="differs from its source authority"):
        store.create_backup(
            tmp_path / "backups" / "forged-permit.sqlite3",
            created_at=NOW + timedelta(seconds=11),
        )


def test_backup_and_restore_reject_cleanup_permit_beyond_held_deadline(
    tmp_path: Path,
) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        _cleanup_reservation_request(envelope, proposal, cleanup),
    )
    _cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    baseline = sqlite_store_module._verified_graph_store_state(
        path,
        campaign_id=CAMPAIGN,
    )
    legitimate = sqlite_store_module.build_cleanup_permit(
        envelope,
        request,
        reversible.cleanup_reservation,
        evaluated_at=NOW + timedelta(seconds=10),
        permit_ttl=timedelta(seconds=30),
    )
    raw = legitimate.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "cleanupPermitId": "",
            "cleanupPermitDigest": "",
            "cleanupDispatchId": "",
            "expiresAt": (
                reversible.cleanup_reservation.claim_expires_at
                + timedelta(seconds=1)
            ).isoformat(),
        }
    )
    forged = CleanupPermit.model_validate(raw)
    with sqlite_store_module._write_transaction(path) as connection:
        sqlite_store_module._insert_cleanup_permit(connection, forged)

    with pytest.raises(SQLiteGraphStoreError, match="differs from its source authority"):
        store.create_backup(
            tmp_path / "backups" / "extended-permit.sqlite3",
            created_at=NOW + timedelta(seconds=11),
        )

    database = path.read_bytes()
    malicious_manifest = sqlite_store_module.SQLiteGraphBackupManifest(
        campaignId=CAMPAIGN,
        createdAt=NOW + timedelta(seconds=11),
        databaseSha256=sqlite_store_module.sha256(database).hexdigest(),
        databaseBytes=len(database),
        eventCount=baseline.event_count,
        eventLogHeadDigest=baseline.event_log_head_digest,
        projectionRevision=baseline.projection_revision,
        projectionDigest=baseline.projection_digest,
        snapshotCount=baseline.snapshot_count,
        snapshotHeadDigest=baseline.snapshot_head_digest,
        actionPermitCount=baseline.action_permit_count,
        actionPermitHeadDigest=baseline.action_permit_head_digest,
        cleanupReservationCount=baseline.cleanup_reservation_count,
        cleanupReservationHeadDigest=baseline.cleanup_reservation_head_digest,
        cleanupPermitCount=1,
        cleanupPermitHeadDigest=forged.cleanup_permit_digest,
    )
    sqlite_store_module.sqlite_graph_backup_manifest_path(path).write_bytes(
        sqlite_store_module._backup_manifest_bytes(malicious_manifest)
    )
    with pytest.raises(SQLiteGraphStoreError, match="differs from its source authority"):
        SQLiteGraphStore.restore_backup(
            path,
            destination=(
                tmp_path / "restored-extended-permit" / "canonical-graph.sqlite3"
            ),
            campaign_id=CAMPAIGN,
        )


def _copy_current_store_as_v2(source: Path, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700)
    connection = sqlite3.connect(destination)
    try:
        connection.execute("PRAGMA journal_mode = DELETE")
        for statement in sqlite_store_module._ACTION_PERMIT_SCHEMA_OBJECT_SQL.values():
            connection.execute(statement)
        connection.executemany(
            "INSERT INTO graph_store_metadata (key, value) VALUES (?, ?)",
            (
                ("schema_version", "2"),
                (
                    "schema_digest",
                    sqlite_store_module._ACTION_PERMIT_SCHEMA_DIGEST,
                ),
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
        ):
            columns = tuple(
                row[1]
                for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
            )
            column_sql = ", ".join(columns)
            connection.execute(
                f"INSERT INTO {table} ({column_sql}) "
                f"SELECT {column_sql} FROM current_store.{table}"
            )
        connection.execute("PRAGMA user_version = 2")
        connection.execute(f"PRAGMA application_id = {sqlite_store_module._APPLICATION_ID}")
        connection.commit()
        connection.execute("DETACH DATABASE current_store")
    finally:
        connection.close()


def test_v2_store_migration_preserves_action_without_fabricating_cleanup(
    tmp_path: Path,
) -> None:
    current_path = tmp_path / "current" / "canonical-graph.sqlite3"
    current, _, decision, action, envelope, proposal = _seed(current_path)
    action_permit = _permit_authority(current, action).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
    ).permit
    v2_path = tmp_path / "v2" / "canonical-graph.sqlite3"
    _copy_current_store_as_v2(current_path, v2_path)

    migrated = SQLiteGraphStore(v2_path, campaign_id=CAMPAIGN)

    assert migrated.permit_store.permits() == (action_permit,)
    assert migrated.permit_store.cleanup_reservations() == ()
    assert migrated.permit_store.cleanup_permits() == ()
    connection = sqlite3.connect(v2_path)
    try:
        assert connection.execute("PRAGMA user_version").fetchone() == (3,)
    finally:
        connection.close()


def test_legacy_v2_backup_is_verified_then_migrated_on_restore(tmp_path: Path) -> None:
    current_path = tmp_path / "current" / "canonical-graph.sqlite3"
    current, _, decision, action, envelope, proposal = _seed(current_path)
    action_permit = _permit_authority(current, action).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
    ).permit
    backup = tmp_path / "legacy-backup" / "graph-lab.sqlite3"
    _copy_current_store_as_v2(current_path, backup)
    database = backup.read_bytes()
    state = sqlite_store_module._verified_v2_graph_store_state(
        backup,
        campaign_id=CAMPAIGN,
    )
    manifest = sqlite_store_module._SQLiteGraphBackupManifestV1(
        campaignId=CAMPAIGN,
        createdAt=NOW + timedelta(seconds=11),
        databaseSha256=sqlite_store_module.sha256(database).hexdigest(),
        databaseBytes=len(database),
        eventCount=state.event_count,
        eventLogHeadDigest=state.event_log_head_digest,
        projectionRevision=state.projection_revision,
        projectionDigest=state.projection_digest,
        snapshotCount=state.snapshot_count,
        snapshotHeadDigest=state.snapshot_head_digest,
        actionPermitCount=state.action_permit_count,
        actionPermitHeadDigest=state.action_permit_head_digest,
    )
    sqlite_store_module.sqlite_graph_backup_manifest_path(backup).write_bytes(
        sqlite_store_module._backup_manifest_bytes(manifest)
    )

    restored = SQLiteGraphStore.restore_backup(
        backup,
        destination=tmp_path / "legacy-restored" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
    )

    assert restored.permit_store.permits() == (action_permit,)
    assert restored.permit_store.cleanup_reservations() == ()
    assert restored.permit_store.cleanup_permits() == ()


def test_legacy_retained_v1alpha1_backup_is_read_without_wire_reinterpretation(
    tmp_path: Path,
) -> None:
    current_path = tmp_path / "current" / "canonical-graph.sqlite3"
    current, _, decision, action, envelope, proposal = _seed(current_path)
    action_permit = _permit_authority(current, action).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
    ).permit
    plaintext = tmp_path / "legacy-plaintext" / "graph-lab.sqlite3"
    _copy_current_store_as_v2(current_path, plaintext)
    database = plaintext.read_bytes()
    state = sqlite_store_module._verified_v2_graph_store_state(
        plaintext,
        campaign_id=CAMPAIGN,
    )
    low_level_manifest = sqlite_store_module._SQLiteGraphBackupManifestV1(
        campaignId=CAMPAIGN,
        createdAt=NOW + timedelta(seconds=11),
        databaseSha256=sqlite_store_module.sha256(database).hexdigest(),
        databaseBytes=len(database),
        eventCount=state.event_count,
        eventLogHeadDigest=state.event_log_head_digest,
        projectionRevision=state.projection_revision,
        projectionDigest=state.projection_digest,
        snapshotCount=state.snapshot_count,
        snapshotHeadDigest=state.snapshot_head_digest,
        actionPermitCount=state.action_permit_count,
        actionPermitHeadDigest=state.action_permit_head_digest,
    )
    encryption_key = bytes(reversed(range(32)))
    signing_seed = bytes(range(32))
    signer_key = backup_retention_module.SQLiteGraphBackupVerificationKey(
        keyId="legacy-retained-signing",
        publicKeyBase64url=backup_retention_module.sqlite_graph_backup_public_key(
            signing_seed
        ),
    )
    signer = backup_retention_module.SQLiteGraphBackupSigner.from_private_key_bytes(
        key=signer_key,
        private_key=signing_seed,
    )
    nonce = bytes(range(12))
    nonce_base64url = backup_retention_module._base64url_encode(nonce)
    ciphertext = backup_retention_module.AESGCM(encryption_key).encrypt(
        nonce,
        database,
        backup_retention_module._retained_backup_aad(
            low_level_manifest,
            encryption_key_id="legacy-retained-encryption",
            nonce_base64url=nonce_base64url,
        ),
    )
    statement = backup_retention_module._SQLiteGraphRetainedBackupStatementV1(
        backupManifest=low_level_manifest,
        encryptionKeyId="legacy-retained-encryption",
        nonceBase64url=nonce_base64url,
        ciphertextSha256=sqlite_store_module.sha256(ciphertext).hexdigest(),
        ciphertextBytes=len(ciphertext),
    )
    statement_bytes = backup_retention_module._retained_backup_statement_bytes(
        statement
    )
    manifest = backup_retention_module._SQLiteGraphRetainedBackupManifestV1(
        statement=statement,
        signingKeyId=signer_key.key_id,
        signatureBase64url=backup_retention_module._base64url_encode(
            signer.private_key.sign(
                backup_retention_module._SIGNATURE_DOMAIN_V1 + statement_bytes
            )
        ),
    )
    retained = tmp_path / "legacy-retained" / "graph-lab.sqlite3.enc"
    retained.parent.mkdir(mode=0o700)
    retained.write_bytes(ciphertext)
    backup_retention_module.sqlite_graph_retained_backup_manifest_path(
        retained
    ).write_bytes(backup_retention_module._retained_backup_manifest_bytes(manifest))

    verified = backup_retention_module.verify_retained_sqlite_graph_backup(
        retained,
        trusted_signing_keys=(signer_key,),
    )
    restored = SQLiteGraphStore.restore_retained_backup(
        retained,
        destination=tmp_path / "legacy-retained-restored" / "canonical-graph.sqlite3",
        campaign_id=CAMPAIGN,
        encryption_key_id="legacy-retained-encryption",
        encryption_key=encryption_key,
        trusted_signing_keys=(signer_key,),
    )

    assert verified.manifest.api_version.endswith("/v1alpha1")
    assert verified.manifest.statement.api_version.endswith("/v1alpha1")
    assert restored.permit_store.permits() == (action_permit,)
    assert restored.permit_store.cleanup_reservations() == ()
    assert restored.permit_store.cleanup_permits() == ()


def test_concurrent_cleanup_claim_has_one_dispatch_winner(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        _cleanup_reservation_request(envelope, proposal, cleanup),
    )
    cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    left = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    right = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    authorities = (
        _cleanup_authority(left, action, cleanup),
        _cleanup_authority(right, action, cleanup),
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(
            pool.map(
                lambda authority: authority.authorize_for_dispatch(
                    envelope,
                    request,
                    cleanup_decision,
                ),
                authorities,
            )
        )

    assert sorted(result.newly_consumed for result in results) == [False, True]
    assert results[0].permit == results[1].permit
    assert len(left.permit_store.cleanup_permits()) == 1


def test_cleanup_ledgers_are_append_only_and_schema_fingerprinted(tmp_path: Path) -> None:
    path = tmp_path / "graph-state" / "canonical-graph.sqlite3"
    store, _, decision, action, _, _ = _seed(path)
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup, tool_call_limit=2)
    proposal = _action_proposal(envelope, action, decision)
    reversible = _reversible_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        proposal,
        decision,
        _cleanup_reservation_request(envelope, proposal, cleanup),
    )
    cleanup_decision, request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        decision.snapshot,
    )
    permit = _cleanup_authority(store, action, cleanup).authorize_for_dispatch(
        envelope,
        request,
        cleanup_decision,
    ).permit

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                UPDATE graph_action_cleanup_reservations
                SET request_units = 1
                WHERE cleanup_reservation_id = ?
                """,
                (reversible.cleanup_reservation.cleanup_reservation_id,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "DELETE FROM graph_cleanup_permits WHERE cleanup_permit_id = ?",
                (permit.cleanup_permit_id,),
            )
        connection.execute("DROP TRIGGER graph_cleanup_permits_no_delete")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(SQLiteGraphStoreError, match="schema fingerprint"):
        SQLiteGraphStore(path, campaign_id=CAMPAIGN)
