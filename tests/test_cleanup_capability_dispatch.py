from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from pajin.capabilities import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CLEANUP_CAPABILITY_DISPATCH_EVENT_PREFIX,
    CapabilityGraphRunAuditAnchor,
    CapabilityMaturity,
    CapabilityReleaseRef,
    CapabilitySideEffectClass,
    CapabilityToolBinding,
    CleanupCapabilityDispatchAuditEvent,
    CleanupCapabilityDispatchError,
    CleanupCapabilityDispatchReconciliationStatus,
    CleanupCapabilityDispatchStage,
    ExistingModeCleanupCapabilityGatewayDispatcher,
    PreparedCapabilityAction,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
    reconcile_cleanup_capability_dispatch,
)
from pajin.capabilities.models import CapabilityDefinition
from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolResult
from pajin.graph import (
    ActionCapabilityRegistry,
    CleanupPermitInputAuthority,
    CleanupRequest,
    GraphCleanupPermitAuthority,
    GraphCleanupPermitDispatcher,
    GraphDecision,
    MissionEnvelope,
    SQLiteGraphStore,
)
from pajin.policy.engine import PolicyDecision
from pajin.runtime.store import RunStore, load_verified_run_snapshot
from pajin.tools.gateway import GatewayOutcome
from tests.test_graph_action_permit import (
    CAMPAIGN,
    COMPILER_ID,
    COMPILER_VERSION,
    DIGEST_A,
    DIGEST_B,
    DIGEST_C,
    DIGEST_D,
    DIGEST_E,
    DIGEST_F,
    NOW,
    _action_proposal,
    _cleanup_capability,
    _cleanup_request,
    _cleanup_reservation_request,
    _reversible_authority,
    _reversible_envelope,
    _seed,
)

ACTIVATION_DIGEST = "1" * 64
RELEASE_DIGEST = "2" * 64
SOURCE_TERMINAL_AT = NOW + timedelta(seconds=8)


class _ExactCleanupInputAuthority(CleanupPermitInputAuthority):
    def __init__(self, expected: CleanupRequest) -> None:
        self._expected = expected

    def verify_cleanup_request(
        self,
        envelope: MissionEnvelope,
        request: CleanupRequest,
        decision: GraphDecision,
    ) -> None:
        if request != self._expected:
            raise ValueError("cleanup request differs from fixture authority")
        if (
            envelope.envelope_id != request.envelope_id
            or decision.decision_id != request.decision_id
            or decision.decision_digest != request.decision_digest
        ):
            raise ValueError("cleanup lineage differs from fixture authority")


class _DefinitionRegistry:
    def __init__(self, definition: CapabilityDefinition) -> None:
        self.definition = definition

    def resolve(self, reference: object) -> CapabilityDefinition:
        if reference != self.definition.reference():
            raise ValueError("definition reference differs")
        return self.definition


class _Activation:
    def __init__(
        self,
        definition: CapabilityDefinition,
        release: CapabilityReleaseRef,
    ) -> None:
        self.activation_set = SimpleNamespace(activation_set_digest=ACTIVATION_DIGEST)
        self.rollout = SimpleNamespace(
            bundle=SimpleNamespace(definitions=_DefinitionRegistry(definition))
        )
        self.release = release
        self.definition = definition

    def resolve_for_dispatch(self, _reference: object) -> object:
        return SimpleNamespace(
            release=self.release,
            capability=SimpleNamespace(capability=self.definition.reference()),
        )


class _Gateway:
    def __init__(self, *, failure: BaseException | None = None) -> None:
        self.failure = failure
        self.calls: list[tuple[CampaignManifest, CapabilityGrant, ToolRequest, int]] = []

    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome:
        self.calls.append((campaign, grant, request, used_calls))
        if self.failure is not None:
            raise self.failure
        result = ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=NOW + timedelta(seconds=12),
            finished_at=NOW + timedelta(seconds=13),
            data={"restored": True},
            evidence=[f"evidence/{request.request_id}.json"],
        )
        return GatewayOutcome(
            decision=PolicyDecision(allowed=True, reason="fixture", policy="fixture"),
            result=result,
            executed=True,
        )


@dataclass(slots=True)
class _Fixture:
    campaign: CampaignManifest
    envelope: MissionEnvelope
    request: CleanupRequest
    decision: GraphDecision
    prepared: PreparedCapabilityAction
    activation: _Activation
    grant: CapabilityGrant
    source_grant: CapabilityGrant
    graph_store: SQLiteGraphStore
    graph_dispatcher: GraphCleanupPermitDispatcher
    graph_authority: GraphCleanupPermitAuthority
    audit_store: RunStore


def _definition(*, request_unit_cost: int = 3) -> CapabilityDefinition:
    return CapabilityDefinition(
        capabilityId="capability:state-restore",
        capabilityVersion="1.0.0",
        domain="hybrid-web-ai",
        maturity=CapabilityMaturity.EXPERIMENTAL,
        supportedSurfaceTypes=("http-endpoint",),
        threatClasses=("state-change",),
        parameterSchemaDigest=DIGEST_A,
        tool=CapabilityToolBinding(
            toolId="state.restore",
            toolVersion="1.0.0",
            toolDigest=DIGEST_E,
        ),
        riskTier="T2",
        sideEffectClass=CapabilitySideEffectClass.REVERSIBLE_WRITE,
        evidenceTypes=("state-restored",),
        networkAccess=False,
        approvalRequired=True,
        requestUnitCost=request_unit_cost,
        cleanupRequired=True,
        parallelSafe=False,
    )


def _campaign(sample_campaign: CampaignManifest) -> CampaignManifest:
    return CampaignManifest.model_validate(
        sample_campaign.model_copy(
            update={"metadata": sample_campaign.metadata.model_copy(update={"name": CAMPAIGN})},
            deep=True,
        ).model_dump(mode="json", by_alias=True)
    )


def _run_store(tmp_path: Path, envelope: MissionEnvelope) -> RunStore:
    run_path = tmp_path / "run"
    (run_path / "evidence").mkdir(parents=True)
    store = RunStore(run_id=envelope.run_id, path=run_path)
    anchor = CapabilityGraphRunAuditAnchor(
        deploymentId="fixture.cleanup-dispatch",
        campaignId=envelope.campaign_id,
        campaignDigest=DIGEST_A,
        runId=envelope.run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        releaseSetDigest=DIGEST_B,
        activationSetDigest=ACTIVATION_DIGEST,
        compilerId=envelope.compiler_id,
        compilerVersion=envelope.compiler_version,
        compilerDigest=envelope.compiler_digest,
    )
    store.append_event(
        CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
        anchor.model_dump(mode="json", by_alias=True),
        occurred_at=NOW + timedelta(seconds=1),
    )
    store.seal()
    return store


def _fixture(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    *,
    request_unit_cost: int = 3,
) -> _Fixture:
    graph_store, _, graph_decision, action, _, _ = _seed(
        tmp_path / "graph" / "canonical-graph.sqlite3"
    )
    cleanup = _cleanup_capability()
    envelope = _reversible_envelope(action, cleanup)
    audit_store = _run_store(tmp_path, envelope)
    source_run_root = load_verified_run_snapshot(audit_store.path).verification.root_digest
    proposal = _action_proposal(envelope, action, graph_decision)
    reversible = _reversible_authority(
        graph_store,
        action,
        cleanup,
    ).authorize_for_dispatch(
        envelope,
        proposal,
        graph_decision,
        _cleanup_reservation_request(envelope, proposal, cleanup),
    )
    cleanup_decision, base_request = _cleanup_request(
        envelope,
        reversible.action.permit,
        reversible.cleanup_reservation,
        cleanup,
        graph_decision.snapshot,
    )
    tool_request = ToolRequest(
        request_id="tool_cleanup_permit_first",
        agent_id="agent:cleanup-worker",
        tool_id=cleanup.tool_id,
        target="https://target.example.test/resource",
        method="POST",
        arguments={"expectedState": "baseline"},
    )
    request_digest = capability_tool_request_digest(tool_request)
    parameters_digest = capability_normalized_parameters_digest(tool_request.arguments)
    raw_request = base_request.model_dump(mode="json", by_alias=True)
    raw_request.pop("cleanupRequestId")
    raw_request.pop("cleanupRequestDigest")
    raw_request.update(
        {
            "sourceRunRootDigest": source_run_root,
            "requestId": tool_request.request_id,
            "requestDigest": request_digest,
            "normalizedParametersDigest": parameters_digest,
        }
    )
    cleanup_request = CleanupRequest.model_validate(raw_request)
    release = CapabilityReleaseRef(
        releaseId=f"capability-release_{RELEASE_DIGEST}",
        releaseDigest=RELEASE_DIGEST,
    )
    prepared = PreparedCapabilityAction(
        activationSetDigest=ACTIVATION_DIGEST,
        release=release,
        capability=cleanup.reference(),
        request=tool_request,
        requestDigest=request_digest,
        normalizedParametersDigest=parameters_digest,
    )
    definition = _definition(request_unit_cost=request_unit_cost)
    activation = _Activation(definition, release)
    source_grant = CapabilityGrant(
        grant_id="grant_source_action",
        subject="agent:source-worker",
        campaign=CAMPAIGN,
        tools={action.tool_id},
        targets={tool_request.target},
        max_risk_tier=action.risk_tier,
        max_calls=1,
        issued_at=NOW,
        expires_at=envelope.expires_at,
    )
    grant = CapabilityGrant(
        grant_id="grant_cleanup_action",
        subject=tool_request.agent_id,
        campaign=CAMPAIGN,
        tools={tool_request.tool_id},
        targets={tool_request.target},
        max_risk_tier=cleanup.risk_tier,
        max_calls=1,
        delegable=False,
        issued_at=SOURCE_TERMINAL_AT + timedelta(milliseconds=1),
        expires_at=NOW + timedelta(seconds=35),
    )
    graph_authority = GraphCleanupPermitAuthority(
        campaign_id=CAMPAIGN,
        compiler_id=COMPILER_ID,
        compiler_version=COMPILER_VERSION,
        compiler_digest=DIGEST_D,
        capabilities=ActionCapabilityRegistry([action, cleanup]),
        permit_store=graph_store.permit_store,
        input_authority=_ExactCleanupInputAuthority(cleanup_request),
        clock=lambda: NOW + timedelta(seconds=10),
    )
    return _Fixture(
        campaign=_campaign(sample_campaign),
        envelope=envelope,
        request=cleanup_request,
        decision=cleanup_decision,
        prepared=prepared,
        activation=activation,
        grant=grant,
        source_grant=source_grant,
        graph_store=graph_store,
        graph_dispatcher=GraphCleanupPermitDispatcher(graph_authority),
        graph_authority=graph_authority,
        audit_store=audit_store,
    )


def _dispatcher(
    fixture: _Fixture,
    gateway: _Gateway,
    *,
    dispatch_at=NOW + timedelta(seconds=11),
) -> ExistingModeCleanupCapabilityGatewayDispatcher:
    return ExistingModeCleanupCapabilityGatewayDispatcher(
        activation=fixture.activation,  # type: ignore[arg-type]
        permits=fixture.graph_dispatcher,
        gateway=gateway,
        audit_store=fixture.audit_store,
        clock=lambda: dispatch_at,
    )


async def _dispatch(
    dispatcher: ExistingModeCleanupCapabilityGatewayDispatcher,
    fixture: _Fixture,
    *,
    grant: CapabilityGrant | None = None,
    source_grant: CapabilityGrant | None = None,
    prepared: PreparedCapabilityAction | None = None,
):
    return await dispatcher.dispatch_once(
        fixture.envelope,
        fixture.request,
        fixture.decision,
        prepared or fixture.prepared,
        campaign=fixture.campaign,
        grant=grant or fixture.grant,
        source_grant=source_grant or fixture.source_grant,
        source_terminal_occurred_at=SOURCE_TERMINAL_AT,
        used_calls=0,
    )


@pytest.mark.asyncio
async def test_cleanup_dispatch_uses_gateway_once_and_retry_is_non_executable(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    gateway = _Gateway()
    dispatcher = _dispatcher(fixture, gateway)

    first = await _dispatch(dispatcher, fixture)
    retry = await _dispatch(dispatcher, fixture)

    assert first.dispatched is True
    assert first.result is not None and first.result.result.success is True
    assert retry.dispatched is False
    assert retry.permit == first.permit
    assert len(gateway.calls) == 1
    fixture.audit_store.seal()
    observation = reconcile_cleanup_capability_dispatch(
        load_verified_run_snapshot(fixture.audit_store.path),
        first.permit,
    )
    assert observation.record.status is CleanupCapabilityDispatchReconciliationStatus.COMPLETED
    assert observation.record.redispatch_allowed is False
    assert observation.record.manual_review_required is False
    assert observation.terminal_event is not None
    assert observation.terminal_event.stage is CleanupCapabilityDispatchStage.COMPLETED
    assert [
        event.event_type
        for event in load_verified_run_snapshot(fixture.audit_store.path).events
        if event.event_type.startswith(CLEANUP_CAPABILITY_DISPATCH_EVENT_PREFIX)
    ] == [
        "capability.cleanup-dispatch.claimed",
        "capability.cleanup-dispatch.completed",
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "grant_update",
    (
        {"grant_id": "grant_source_action"},
        {"tools": {"state.restore", "source.write"}},
        {"targets": {"https://target.example.test/resource", "https://other.test"}},
        {"max_calls": 2},
        {"delegable": True},
        {"issued_at": SOURCE_TERMINAL_AT},
    ),
)
async def test_cleanup_dispatch_rejects_non_fresh_or_overbroad_grant_before_claim(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    grant_update: dict[str, object],
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    gateway = _Gateway()
    forged = fixture.grant.model_copy(update=grant_update)

    with pytest.raises(CleanupCapabilityDispatchError, match="Grant"):
        await _dispatch(_dispatcher(fixture, gateway), fixture, grant=forged)

    assert gateway.calls == []
    assert fixture.graph_store.permit_store.cleanup_permits() == ()


@pytest.mark.asyncio
async def test_cleanup_dispatch_rejects_request_release_and_price_drift_before_claim(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    request_fixture = _fixture(tmp_path / "request", sample_campaign)
    other_request = request_fixture.prepared.request.model_copy(
        update={"request_id": "tool_cleanup_substituted"}
    )
    forged_prepared = request_fixture.prepared.model_copy(
        update={
            "request": other_request,
            "request_digest": capability_tool_request_digest(other_request),
        }
    )
    gateway = _Gateway()
    with pytest.raises(CleanupCapabilityDispatchError, match="CleanupRequest"):
        await _dispatch(
            _dispatcher(request_fixture, gateway),
            request_fixture,
            prepared=forged_prepared,
        )
    assert gateway.calls == []

    release_fixture = _fixture(tmp_path / "release", sample_campaign)
    release_fixture.activation.release = CapabilityReleaseRef(
        releaseId=f"capability-release_{DIGEST_F}",
        releaseDigest=DIGEST_F,
    )
    with pytest.raises(CleanupCapabilityDispatchError, match="release"):
        await _dispatch(_dispatcher(release_fixture, _Gateway()), release_fixture)

    price_fixture = _fixture(
        tmp_path / "price",
        sample_campaign,
        request_unit_cost=4,
    )
    with pytest.raises(CleanupCapabilityDispatchError, match="request-unit"):
        await _dispatch(_dispatcher(price_fixture, _Gateway()), price_fixture)


@pytest.mark.asyncio
async def test_cleanup_gateway_failure_is_terminal_and_never_retried(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    gateway = _Gateway(failure=RuntimeError("cleanup failed"))
    dispatcher = _dispatcher(fixture, gateway)

    with pytest.raises(RuntimeError, match="cleanup failed"):
        await _dispatch(dispatcher, fixture)
    retry = await _dispatch(dispatcher, fixture)

    assert retry.dispatched is False
    assert len(gateway.calls) == 1
    fixture.audit_store.seal()
    observation = reconcile_cleanup_capability_dispatch(
        load_verified_run_snapshot(fixture.audit_store.path),
        retry.permit,
    )
    assert observation.record.status is CleanupCapabilityDispatchReconciliationStatus.FAILED
    assert observation.record.redispatch_allowed is False


@pytest.mark.asyncio
async def test_cleanup_expired_permit_is_terminal_before_gateway(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    gateway = _Gateway()
    dispatcher = _dispatcher(
        fixture,
        gateway,
        dispatch_at=NOW + timedelta(seconds=41),
    )

    with pytest.raises(CleanupCapabilityDispatchError, match="expired"):
        await _dispatch(dispatcher, fixture)
    retry = await _dispatch(dispatcher, fixture)

    assert retry.dispatched is False
    assert gateway.calls == []
    fixture.audit_store.seal()
    observation = reconcile_cleanup_capability_dispatch(
        load_verified_run_snapshot(fixture.audit_store.path),
        retry.permit,
    )
    assert observation.record.status is CleanupCapabilityDispatchReconciliationStatus.EXPIRED


@pytest.mark.asyncio
async def test_cleanup_grant_cannot_outlive_consumed_permit(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    gateway = _Gateway()
    overlong = fixture.grant.model_copy(update={"expires_at": NOW + timedelta(seconds=50)})

    with pytest.raises(CleanupCapabilityDispatchError, match="Permit window"):
        await _dispatch(
            _dispatcher(fixture, gateway),
            fixture,
            grant=overlong,
        )

    assert gateway.calls == []
    permit = fixture.graph_store.permit_store.cleanup_permits()[0]
    fixture.audit_store.seal()
    observation = reconcile_cleanup_capability_dispatch(
        load_verified_run_snapshot(fixture.audit_store.path),
        permit,
    )
    assert observation.record.status is CleanupCapabilityDispatchReconciliationStatus.FAILED


@pytest.mark.asyncio
async def test_cleanup_cancellation_is_terminal(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    gateway = _Gateway(failure=asyncio.CancelledError())

    with pytest.raises(asyncio.CancelledError):
        await _dispatch(_dispatcher(fixture, gateway), fixture)

    permit = fixture.graph_store.permit_store.cleanup_permits()[0]
    fixture.audit_store.seal()
    observation = reconcile_cleanup_capability_dispatch(
        load_verified_run_snapshot(fixture.audit_store.path),
        permit,
    )
    assert observation.record.status is CleanupCapabilityDispatchReconciliationStatus.CANCELLED
    assert len(gateway.calls) == 1


@pytest.mark.asyncio
async def test_cleanup_crash_before_claim_reconciles_consumed_without_claim(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    dispatcher = _dispatcher(fixture, _Gateway())
    original = ExistingModeCleanupCapabilityGatewayDispatcher._append_dispatch_event

    def crash(self, **kwargs):
        if kwargs["stage"] is CleanupCapabilityDispatchStage.CLAIMED:
            raise SystemExit("after cleanup permit claim")
        return original(self, **kwargs)

    monkeypatch.setattr(
        ExistingModeCleanupCapabilityGatewayDispatcher,
        "_append_dispatch_event",
        crash,
    )
    with pytest.raises(SystemExit, match="after cleanup permit claim"):
        await _dispatch(dispatcher, fixture)

    permit = fixture.graph_store.permit_store.cleanup_permits()[0]
    observation = reconcile_cleanup_capability_dispatch(
        load_verified_run_snapshot(fixture.audit_store.path),
        permit,
    )
    assert (
        observation.record.status
        is CleanupCapabilityDispatchReconciliationStatus.CONSUMED_WITHOUT_CLAIM
    )
    assert observation.record.manual_review_required is True
    assert observation.record.redispatch_allowed is False


@pytest.mark.asyncio
async def test_cleanup_post_gateway_crash_reconciles_claimed_outcome_unknown(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    gateway = _Gateway()
    dispatcher = _dispatcher(fixture, gateway)
    original = ExistingModeCleanupCapabilityGatewayDispatcher._append_dispatch_event

    def crash(self, **kwargs):
        if kwargs["stage"] is CleanupCapabilityDispatchStage.COMPLETED:
            raise SystemExit("after cleanup Gateway side effect")
        return original(self, **kwargs)

    monkeypatch.setattr(
        ExistingModeCleanupCapabilityGatewayDispatcher,
        "_append_dispatch_event",
        crash,
    )
    with pytest.raises(SystemExit, match="after cleanup Gateway side effect"):
        await _dispatch(dispatcher, fixture)

    retry = await _dispatch(dispatcher, fixture)
    assert retry.dispatched is False
    assert len(gateway.calls) == 1
    fixture.audit_store.seal()
    observation = reconcile_cleanup_capability_dispatch(
        load_verified_run_snapshot(fixture.audit_store.path),
        retry.permit,
    )
    assert (
        observation.record.status
        is CleanupCapabilityDispatchReconciliationStatus.CLAIMED_OUTCOME_UNKNOWN
    )
    assert observation.record.manual_review_required is True
    assert observation.record.redispatch_allowed is False


def test_cleanup_reconciliation_rejects_cross_request_audit(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    fixture = _fixture(tmp_path, sample_campaign)
    authorization = fixture.graph_authority.authorize_for_dispatch(
        fixture.envelope,
        fixture.request,
        fixture.decision,
    )
    permit = authorization.permit
    forged = CleanupCapabilityDispatchAuditEvent(
        stage=CleanupCapabilityDispatchStage.CLAIMED,
        occurredAt=NOW + timedelta(seconds=11),
        activationSetDigest=ACTIVATION_DIGEST,
        release=fixture.prepared.release,
        cleanupPermitId=permit.cleanup_permit_id,
        cleanupPermitDigest=permit.cleanup_permit_digest,
        cleanupDispatchId=permit.cleanup_dispatch_id,
        campaignId=permit.campaign_id,
        runId=permit.run_id,
        cleanupRequestId=permit.cleanup_request_id,
        cleanupRequestDigest=permit.cleanup_request_digest,
        sourceActionPermitId=permit.source_action_permit_id,
        sourceActionPermitDigest=permit.source_action_permit_digest,
        sourceActionDispatchId=permit.source_action_dispatch_id,
        requestId="tool_cleanup_cross_request",
        requestDigest=permit.request_digest,
        normalizedParametersDigest=permit.normalized_parameters_digest,
        sourceCapabilityGrantDigest=DIGEST_C,
        capabilityGrantDigest=DIGEST_D,
    )
    fixture.audit_store.append_event(
        f"{CLEANUP_CAPABILITY_DISPATCH_EVENT_PREFIX}claimed",
        forged.model_dump(mode="json", by_alias=True),
        occurred_at=forged.occurred_at,
    )
    fixture.audit_store.seal()

    with pytest.raises(CleanupCapabilityDispatchError, match="differs"):
        reconcile_cleanup_capability_dispatch(
            load_verified_run_snapshot(fixture.audit_store.path),
            permit,
        )
