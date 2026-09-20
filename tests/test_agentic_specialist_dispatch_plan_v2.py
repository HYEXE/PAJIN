from __future__ import annotations

import asyncio
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Protocol

import httpx
import pytest
from pydantic import ValidationError

import pajin.agentic.durable as durable_module
from pajin.agentic.durable import (
    AgenticCoordinationError,
    AgenticCoordinationStore,
    AgenticSpecialistDispatchPlanEntry,
    AgenticSpecialistDispatchPlanState,
    AgenticSpecialistExecutionState,
    AgenticSpecialistRuntimeGeneration,
    AgenticSQLSpecialistDispatchPlanEntryV2,
    VerifiedPlannedSQLSpecialistDispatchStartedV2,
    VerifiedSpecialistExecutionReservation,
    VerifiedSQLSpecialistDispatchPlanV2,
    VerifiedSQLSpecialistPermitDispatcherV2,
)
from pajin.agentic.frontier import (
    FrontierCandidate,
    compile_frontier_candidate,
)
from pajin.agentic.models import (
    HypothesisProposal,
    ModelPathEstimate,
    PentestSpecialization,
    TrustedPathFeatures,
)
from pajin.agentic.specialist_preparation import (
    AgenticSpecialistPreparation,
    prepare_agentic_specialist_action,
)
from pajin.capabilities.activation import PreparedCapabilityAction
from pajin.capabilities.agentic_web_specialist import (
    AgenticSpecialistPreparationRegistry,
)
from pajin.capabilities.agentic_web_specialist_v2 import (
    WebSQLSpecialistAuthorizationToolV2,
    WebSQLSpecialistCapabilityActivationV2,
    WebSQLSpecialistCapabilityBundleV2,
    activate_web_sqli_specialist_capability_v2,
    web_sqli_specialist_capability_bundle_v2,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import CapabilityMaturity
from pajin.domain.models import CapabilityGrant, ToolRiskTier
from pajin.graph.approval import ActionApprovalEnvelope, GraphApprovedActionPermitDispatcher
from pajin.policy.capability import CapabilityLedger
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import ToolGateway
from pajin.web_assessment.governed_adapter_profile import GOVERNED_WEB_TARGET_ID
from pajin.web_assessment.governed_models import (
    SignedWebActionApproval,
    sign_web_action_approval,
    web_action_approval_issuer_binding,
)
from tests import test_agentic_specialist_dispatch_plan as legacy
from tests.test_agentic_web_specialist_capability import (
    _adapter_registry,
    _manifest,
    _receipt,
    _receipt_registry,
)

NOW = legacy.NOW


def _lifecycle_seed(label: str) -> bytes:
    return sha256(f"agentic-sqli-v2-plan:{label}".encode()).digest()


def _lifecycle_trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"agentic.sqli-v2.plan.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_lifecycle_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=2),
        notAfter=NOW + timedelta(days=2),
    )


def _signed_lifecycle(
    bundle: WebSQLSpecialistCapabilityBundleV2,
) -> tuple[CapabilityLifecycleRegistry, tuple[CapabilityReleaseRef, ...]]:
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _lifecycle_trust_key(
        "publisher",
        principal="agentic.sqli-v2.plan.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _lifecycle_trust_key(
        "reviewer",
        principal="agentic.sqli-v2.plan.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=_lifecycle_seed("publisher"),
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=_lifecycle_seed("reviewer"),
    )
    capability = bundle.capability().reference()
    review = CapabilityReviewStatement(
        capability=capability,
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"sqli-v2-plan-review:1").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(minutes=26),
        expiresAt=NOW + timedelta(hours=1),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=capability,
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(signed_review.statement.review_digest,),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=NOW - timedelta(minutes=25),
    )
    signed_bundle = CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(signed_bundle,),
        clock=lambda: NOW,
    )
    return lifecycle, (signed_bundle.release.statement.reference(),)


@dataclass(frozen=True, slots=True)
class SQLSpecialistV2Fixture:
    harness: legacy.GovernedDurableHarness
    reservation: VerifiedSpecialistExecutionReservation
    preparation: AgenticSpecialistPreparation
    activation: WebSQLSpecialistCapabilityActivationV2
    prepared_action: PreparedCapabilityAction
    ledger: CapabilityLedger
    root_grant: CapabilityGrant
    grant: CapabilityGrant
    approval: ActionApprovalEnvelope
    signed_approval: SignedWebActionApproval


class SQLHarnessFactory(Protocol):
    def __call__(
        self,
        name: str,
        *,
        generation: AgenticSpecialistRuntimeGeneration = (
            AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
        ),
        approval_clock: Any | None = None,
        coordination_clock: Any | None = None,
    ) -> legacy.GovernedDurableHarness: ...


def _sql_candidate(
    name: str,
    *,
    campaign_id: str,
    snapshot: Any,
    parent_hypothesis_id: str,
) -> FrontierCandidate:
    proposal = HypothesisProposal(
        campaignId=campaign_id,
        sourceSnapshotId=snapshot.snapshot_id,
        sourceSnapshotDigest=snapshot.snapshot_digest,
        parentHypothesisId=parent_hypothesis_id,
        ancestorHypothesisIds=(parent_hypothesis_id,),
        targetId=GOVERNED_WEB_TARGET_ID,
        threatClass="sql-injection",
        specialization=PentestSpecialization.SQL_INJECTION,
        depth=1,
        statement=f"Investigate the bounded governed SQL injection hypothesis {name}.",
        expectedObservable=f"Observe an independently replayable SQL marker {name}.",
        requiredEvidenceTypes=("web.independent-replay", "web.negative-control"),
        estimate=ModelPathEstimate(successLikelihoodBps=7_000),
    )
    features = TrustedPathFeatures(
        sourceSnapshotId=snapshot.snapshot_id,
        sourceSnapshotDigest=snapshot.snapshot_digest,
        sourceEvidenceIds=(f"evidence:{name}",),
        expectedImpactBps=7_000,
        privilegeGainBps=5_000,
        reachabilityGainBps=5_000,
        evidenceQualityBps=7_000,
        noveltyBps=7_000,
        executionCostBps=2_000,
        safetyRiskBps=1_000,
    )
    return compile_frontier_candidate(proposal, features)


@pytest.fixture
def sql_harness_factory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[SQLHarnessFactory]:
    if sys.platform != "linux":
        pytest.skip("authoritative durable coordination requires Linux /proc descriptors")
    harnesses: list[legacy.GovernedDurableHarness] = []

    def factory(
        name: str,
        *,
        generation: AgenticSpecialistRuntimeGeneration = (
            AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
        ),
        approval_clock: Any | None = None,
        coordination_clock: Any | None = None,
    ) -> legacy.GovernedDurableHarness:
        def store_factory(*args: object, **kwargs: object) -> AgenticCoordinationStore:
            return AgenticCoordinationStore(
                *args,
                **kwargs,
                specialist_runtime_generation=generation,
            )

        with monkeypatch.context() as scoped:
            scoped.setattr(legacy, "AgenticCoordinationStore", store_factory)
            scoped.setattr(legacy, "_candidate", _sql_candidate)
            harness = legacy._make_harness(
                tmp_path,
                name,
                approval_clock=approval_clock,
                coordination_clock=coordination_clock,
            )
        harnesses.append(harness)
        return harness

    yield factory
    for harness in harnesses:
        harness.store.close()
        harness.resolver.close()


def _signed_approval(
    harness: legacy.GovernedDurableHarness,
    approval: ActionApprovalEnvelope,
) -> tuple[ActionApprovalEnvelope, SignedWebActionApproval]:
    approval_values = approval.model_dump(mode="json", by_alias=True)
    approval_values.update(
        {
            "approvalId": "",
            "approvalDigest": "",
            "issuer": web_action_approval_issuer_binding(
                harness.approval_key,
                role="source",
            ).model_dump(mode="json", by_alias=True),
            "approvedBy": harness.approval_key.principal_id,
        }
    )
    canonical = ActionApprovalEnvelope.model_validate(approval_values)
    return canonical, sign_web_action_approval(
        canonical,
        role="source",
        key=harness.approval_key,
        private_key=harness.approval_private_key,
    )


def _specialist_fixture_v2(
    harness: legacy.GovernedDurableHarness,
) -> SQLSpecialistV2Fixture:
    reservation = legacy._reserve_current_assignment(harness)
    preparation = prepare_agentic_specialist_action(
        store=harness.store,
        reservation=reservation,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        campaign=harness.campaign,
    )
    assert preparation.specialization is PentestSpecialization.SQL_INJECTION
    preparations = AgenticSpecialistPreparationRegistry((preparation,))
    manifest = _manifest()
    receipt = _receipt(manifest)
    registry = ToolRegistry()
    registry.register(
        WebSQLSpecialistAuthorizationToolV2(
            preparations=preparations,
            adapters=_adapter_registry(manifest),
            account_receipts=_receipt_registry(receipt),
        )
    )
    bundle = web_sqli_specialist_capability_bundle_v2(registry)
    lifecycle, releases = _signed_lifecycle(bundle)
    activation = activate_web_sqli_specialist_capability_v2(
        bundle=bundle,
        lifecycle=lifecycle,
        release=releases[-1],
    )
    prepared_action = activation.prepare_action(
        release=activation.activation_set.binding.release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=receipt.reference(),
    )
    ledger = harness.specialist_ledger
    root_grant = ledger.issue_root(
        harness.campaign,
        subject="agent:agentic-sql-specialist-v2-root",
        tools={prepared_action.request.tool_id},
        targets={preparation.target_endpoint},
    )
    grant = ledger.delegate(
        root_grant.grant_id,
        subject=preparation.target_agent_id,
        tools={prepared_action.request.tool_id},
        targets={preparation.target_endpoint},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=NOW + timedelta(minutes=10),
        delegable=False,
    )
    approval, signed_approval = _signed_approval(
        harness,
        legacy._approval(
            harness=harness,
            preparation=preparation,
            prepared_action=prepared_action,
        ),
    )
    return SQLSpecialistV2Fixture(
        harness=harness,
        reservation=reservation,
        preparation=preparation,
        activation=activation,
        prepared_action=prepared_action,
        ledger=ledger,
        root_grant=root_grant,
        grant=grant,
        approval=approval,
        signed_approval=signed_approval,
    )


def _plan_v2(fixture: SQLSpecialistV2Fixture) -> VerifiedSQLSpecialistDispatchPlanV2:
    return durable_module._SQL_SPECIALIST_V2_PLAN_IMPLEMENTATION(
        fixture.harness.store,
        fixture.reservation,
        preparation=fixture.preparation,
        activation=fixture.activation,
        prepared_action=fixture.prepared_action,
        campaign=fixture.harness.campaign,
        capability_ledger=fixture.ledger,
        capability_grant=fixture.grant,
        approval_envelope=fixture.approval,
        graph_resolver=fixture.harness.resolver,
        graph_head=fixture.harness.graph_head,
    )


def _bind_v2(
    fixture: SQLSpecialistV2Fixture,
    plan: VerifiedSQLSpecialistDispatchPlanV2,
) -> VerifiedSQLSpecialistPermitDispatcherV2:
    return durable_module._SQL_SPECIALIST_V2_BIND_IMPLEMENTATION(
        fixture.harness.store,
        plan,
        campaign=fixture.harness.campaign,
        preparation=fixture.preparation,
        capability_ledger=fixture.ledger,
        capability_grant=fixture.grant,
        activation=fixture.activation,
        prepared_action=fixture.prepared_action,
        approval_envelope=fixture.approval,
        signed_approval=fixture.signed_approval,
        graph_resolver=fixture.harness.resolver,
        graph_head=fixture.harness.graph_head,
    )


async def _dispatch_and_transfer_v2(
    fixture: SQLSpecialistV2Fixture,
) -> tuple[VerifiedPlannedSQLSpecialistDispatchStartedV2, Any]:
    plan = _plan_v2(fixture)
    runtime = _bind_v2(fixture, plan)
    result = await durable_module._SQL_SPECIALIST_V2_PUBLIC_DISPATCH_IMPLEMENTATION(
        fixture.harness.store,
        plan,
        runtime,
        graph_resolver=fixture.harness.resolver,
        graph_head=fixture.harness.graph_head,
    )
    assert result.dispatched is True
    assert type(result.result) is VerifiedPlannedSQLSpecialistDispatchStartedV2
    started = result.result
    capsule = durable_module._SQL_SPECIALIST_V2_TRANSFER_IMPLEMENTATION(
        fixture.harness.store,
        started,
    )
    return started, capsule


def test_v2_plan_permit_and_capsule_stay_on_one_task_without_target_io(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-plan-permit-happy"),
        )
        calls: list[str] = []

        def sync_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("sync")

        async def async_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("async")

        monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
        monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
        monkeypatch.setattr(socket, "create_connection", sync_tripwire)
        monkeypatch.setattr(socket, "getaddrinfo", sync_tripwire)
        monkeypatch.setattr(subprocess, "run", sync_tripwire)
        monkeypatch.setattr(subprocess, "Popen", sync_tripwire)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", async_tripwire)
        monkeypatch.setattr(asyncio, "create_subprocess_shell", async_tripwire)
        monkeypatch.setattr(httpx.Client, "send", sync_tripwire)
        monkeypatch.setattr(httpx.AsyncClient, "send", async_tripwire)

        plan = _plan_v2(fixture)
        assert type(plan) is VerifiedSQLSpecialistDispatchPlanV2
        assert plan.entry.runtime_generation is AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
        assert plan.entry.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
        assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
        runtime = _bind_v2(fixture, plan)
        result = await durable_module._SQL_SPECIALIST_V2_PUBLIC_DISPATCH_IMPLEMENTATION(
            fixture.harness.store,
            plan,
            runtime,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert result.dispatched is True
        assert type(result.result) is VerifiedPlannedSQLSpecialistDispatchStartedV2
        started = result.result
        assert (
            started.plan.state
            is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        )
        assert (
            started.execution.state
            is AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        )
        assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 0
        capsule = fixture.harness.store._transfer_planned_sql_specialist_v2_dispatch_started(
            started
        )
        assert capsule.activation is fixture.activation
        assert capsule.preparation is fixture.preparation
        with fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
            capsule,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        ):
            pass
        with pytest.raises(AgenticCoordinationError, match="foreign or consumed"):
            fixture.harness.store._transfer_planned_sql_specialist_v2_dispatch_started(started)
        assert calls == []

    asyncio.run(scenario())


def test_v1_v2_wires_and_store_generations_reject_each_other(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        v2_fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-wire-rejection"),
        )
        v2_plan = _plan_v2(v2_fixture)
        with pytest.raises(ValidationError):
            AgenticSpecialistDispatchPlanEntry.model_validate(
                v2_plan.entry.model_dump(mode="json", by_alias=True)
            )
        with pytest.raises(AgenticCoordinationError):
            v2_fixture.harness.store.specialist_dispatch_plan_entry(
                plan_id=v2_plan.entry.plan_id,
                graph_resolver=v2_fixture.harness.resolver,
                graph_head=v2_fixture.harness.graph_head,
            )

        legacy_generation_fixture = _specialist_fixture_v2(
            sql_harness_factory(
                "sql-v2-on-legacy-store",
                generation=AgenticSpecialistRuntimeGeneration.LEGACY_V1,
            ),
        )
        with pytest.raises(AgenticCoordinationError, match="not pinned"):
            _plan_v2(legacy_generation_fixture)

        v1_on_v2 = legacy._specialist_fixture(sql_harness_factory("sql-v1-on-v2-store"))
        with pytest.raises(AgenticCoordinationError, match="not pinned"):
            legacy._plan(v1_on_v2)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("created_generation", "reopen_generation"),
    (
        (
            AgenticSpecialistRuntimeGeneration.LEGACY_V1,
            AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2,
        ),
        (
            AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2,
            AgenticSpecialistRuntimeGeneration.LEGACY_V1,
        ),
    ),
)
def test_store_reopen_rejects_specialist_runtime_generation_change(
    sql_harness_factory: SQLHarnessFactory,
    created_generation: AgenticSpecialistRuntimeGeneration,
    reopen_generation: AgenticSpecialistRuntimeGeneration,
) -> None:
    harness = sql_harness_factory(
        f"sql-v2-generation-{created_generation.value}",
        generation=created_generation,
    )

    with pytest.raises(AgenticCoordinationError, match="binding metadata differs"):
        AgenticCoordinationStore(
            harness.store.path,
            binding=harness.binding,
            graph_resolver=harness.resolver,
            graph_head=harness.graph_head,
            specialist_graph_store=harness.graph_store,
            specialist_capability_ledger=harness.specialist_ledger,
            specialist_approval_keys=(harness.approval_key,),
            specialist_approval_clock=harness.approval_clock,
            specialist_runtime_generation=reopen_generation,
            allow_create=False,
            expected_store_id=harness.store.store_id,
            clock=lambda: NOW + timedelta(seconds=20),
        )


def test_v2_generation_tamper_is_rejected(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-generation-tamper"),
        )
        plan = _plan_v2(fixture)
        payload = plan.entry.model_dump(mode="json", by_alias=True)
        payload["runtimeGeneration"] = AgenticSpecialistRuntimeGeneration.LEGACY_V1.value
        payload["planId"] = ""
        payload["planDigest"] = ""
        payload["stateDigest"] = ""
        with pytest.raises(ValidationError):
            AgenticSQLSpecialistDispatchPlanEntryV2.model_validate(payload)

    asyncio.run(scenario())


def test_v2_cross_task_bind_fails_before_mutation(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-cross-task"),
        )
        plan = _plan_v2(fixture)

        async def cross_task_bind() -> None:
            _bind_v2(fixture, plan)

        with pytest.raises(AgenticCoordinationError, match="another scheduler Task"):
            await asyncio.create_task(cross_task_bind())
        audit = fixture.harness.store.sql_specialist_dispatch_plan_v2_entry(
            plan_id=plan.entry.plan_id,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert audit.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
        assert audit.action_permit is None
        assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
        assert type(_bind_v2(fixture, plan)) is VerifiedSQLSpecialistPermitDispatcherV2

    asyncio.run(scenario())


def test_v2_task_completion_retires_live_authority_but_keeps_audit_data(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        async def create_in_child() -> tuple[
            SQLSpecialistV2Fixture,
            VerifiedSQLSpecialistDispatchPlanV2,
        ]:
            fixture = _specialist_fixture_v2(
                sql_harness_factory("sql-v2-task-retirement"),
            )
            return fixture, _plan_v2(fixture)

        fixture, plan = await asyncio.create_task(create_in_child())
        await asyncio.sleep(0)
        with pytest.raises(AgenticCoordinationError, match="retired or unavailable"):
            _bind_v2(fixture, plan)
        audit = fixture.harness.store.sql_specialist_dispatch_plan_v2_entry(
            plan_id=plan.entry.plan_id,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert audit == plan.entry
        assert type(audit) is AgenticSQLSpecialistDispatchPlanEntryV2
        recovery = fixture.harness.store.recovery_snapshot(
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert plan.entry in recovery.awaiting_specialist_dispatch_plans
        assert recovery.automatic_redispatch_authorized is False

    asyncio.run(scenario())


def test_v2_active_permit_dispatch_makes_store_close_fail_closed(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-close-race"),
        )
        plan = _plan_v2(fixture)
        runtime = _bind_v2(fixture, plan)
        entered = threading.Event()
        close_finished = threading.Event()
        close_errors: list[BaseException] = []
        original_dispatch = durable_module._GRAPH_APPROVED_DISPATCH_IMPLEMENTATION

        async def blocked_dispatch(
            dispatcher: GraphApprovedActionPermitDispatcher,
            envelope: Any,
            proposal: Any,
            decision: Any,
            approval: Any,
            callback: Any,
        ) -> Any:
            entered.set()
            while not close_finished.is_set():
                await asyncio.sleep(0)
            return await original_dispatch(
                dispatcher,
                envelope,
                proposal,
                decision,
                approval,
                callback,
            )

        monkeypatch.setattr(
            GraphApprovedActionPermitDispatcher,
            "dispatch_once",
            blocked_dispatch,
        )
        monkeypatch.setattr(
            durable_module,
            "_GRAPH_APPROVED_DISPATCH_IMPLEMENTATION",
            blocked_dispatch,
        )

        def close_during_dispatch() -> None:
            assert entered.wait(timeout=5)
            try:
                durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(fixture.harness.store)
            except BaseException as exc:
                close_errors.append(exc)
            finally:
                close_finished.set()

        closer = threading.Thread(target=close_during_dispatch, daemon=True)
        closer.start()
        result = await durable_module._SQL_SPECIALIST_V2_PUBLIC_DISPATCH_IMPLEMENTATION(
            fixture.harness.store,
            plan,
            runtime,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        closer.join(timeout=5)

        assert not closer.is_alive()
        assert len(close_errors) == 1
        assert isinstance(close_errors[0], AgenticCoordinationError)
        assert "active SQL specialist v2 Permit dispatch" in str(close_errors[0])
        assert result.dispatched is True
        assert type(result.result) is VerifiedPlannedSQLSpecialistDispatchStartedV2
        fixture.harness.store._database.require_open()

    asyncio.run(scenario())


def test_v2_transferred_capsule_claim_is_one_shot(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-capsule-one-shot"),
        )
        _started, capsule = await _dispatch_and_transfer_v2(fixture)

        with fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
            capsule,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        ):
            pass

        with (
            pytest.raises(AgenticCoordinationError, match="foreign or consumed"),
            fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
                capsule,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            ),
        ):
            pass

    asyncio.run(scenario())


def test_v2_store_close_retires_unclaimed_transferred_capsule(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-capsule-close"),
        )
        _started, capsule = await _dispatch_and_transfer_v2(fixture)
        retired_field = "_AgenticSQLSpecialistDispatchRuntimeCapsuleV2__retired"

        assert getattr(capsule, retired_field) is False

        durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(fixture.harness.store)

        assert getattr(capsule, retired_field) is True
        assert not (
            fixture.harness.store._AgenticCoordinationStore__transferred_sql_specialist_v2_dispatch_capsules
        )

        with (
            pytest.raises(AgenticCoordinationError),
            durable_module._SQL_SPECIALIST_V2_RUNTIME_CLAIM_IMPLEMENTATION(
                fixture.harness.store,
                capsule,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            ),
        ):
            pass

    asyncio.run(scenario())


def test_v2_active_capsule_claim_makes_store_close_fail_closed_without_blocking(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-capsule-close-race"),
        )
        _started, capsule = await _dispatch_and_transfer_v2(fixture)
        close_errors: list[BaseException] = []

        def close_during_claim() -> None:
            try:
                durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(fixture.harness.store)
            except BaseException as exc:
                close_errors.append(exc)

        with fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
            capsule,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        ):
            closer = threading.Thread(target=close_during_claim, daemon=True)
            closer.start()
            closer.join(timeout=5)
            assert not closer.is_alive()

        assert len(close_errors) == 1
        assert isinstance(close_errors[0], AgenticCoordinationError)
        assert "active SQL specialist v2 Permit dispatch" in str(close_errors[0])
        fixture.harness.store._database.require_open()

    asyncio.run(scenario())


def test_v2_foreign_task_cannot_end_claim_or_release_store_lifecycle_lease(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-capsule-foreign-exit"),
        )
        ready = asyncio.Event()
        finish_owner = asyncio.Event()
        holder: dict[str, Any] = {}
        calls: list[str] = []

        def sync_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("sync-io")

        async def async_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("async-io")

        monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
        monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
        monkeypatch.setattr(socket, "create_connection", sync_tripwire)
        monkeypatch.setattr(socket, "getaddrinfo", sync_tripwire)
        monkeypatch.setattr(subprocess, "run", sync_tripwire)
        monkeypatch.setattr(subprocess, "Popen", sync_tripwire)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", async_tripwire)
        monkeypatch.setattr(asyncio, "create_subprocess_shell", async_tripwire)
        monkeypatch.setattr(httpx.Client, "send", sync_tripwire)
        monkeypatch.setattr(httpx.AsyncClient, "send", async_tripwire)

        async def owner() -> None:
            _started, capsule = await _dispatch_and_transfer_v2(fixture)
            claim = fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
                capsule,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
            claim.__enter__()
            holder["claim"] = claim
            holder["capsule"] = capsule
            ready.set()
            await finish_owner.wait()

        owner_task = asyncio.create_task(owner())
        await ready.wait()

        async def foreign_exit() -> None:
            claim = holder["claim"]
            with pytest.raises(
                AgenticCoordinationError,
                match="lifecycle lease is foreign or retired",
            ):
                claim.__exit__(None, None, None)

        await asyncio.create_task(foreign_exit())

        assert not owner_task.done()
        with pytest.raises(
            AgenticCoordinationError,
            match="active SQL specialist v2 Permit dispatch",
        ):
            durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(fixture.harness.store)
        fixture.harness.store._database.require_open()

        finish_owner.set()
        await owner_task
        await asyncio.sleep(0)

        assert not (
            fixture.harness.store._AgenticCoordinationStore__transferred_sql_specialist_v2_dispatch_capsules
        )
        assert not (
            fixture.harness.store._AgenticCoordinationStore__active_sql_specialist_v2_dispatch_operations
        )
        assert holder["capsule"]._AgenticSQLSpecialistDispatchRuntimeCapsuleV2__retired is True
        durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(fixture.harness.store)
        assert calls == []

    asyncio.run(scenario())


def test_v2_grant_revocation_after_transfer_consumes_failed_claim(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-capsule-revoked-grant"),
        )
        _started, capsule = await _dispatch_and_transfer_v2(fixture)
        fixture.ledger.revoke(fixture.root_grant.grant_id, "test parent revocation")

        with (
            pytest.raises(AgenticCoordinationError, match="Grant authority changed"),
            fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
                capsule,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            ),
        ):
            pass

        with (
            pytest.raises(AgenticCoordinationError, match="foreign or consumed"),
            fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
                capsule,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            ),
        ):
            pass

    asyncio.run(scenario())


def test_v2_permit_expiry_after_transfer_consumes_failed_claim(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        clock = legacy._MutableClock(NOW + timedelta(seconds=10))
        fixture = _specialist_fixture_v2(
            sql_harness_factory(
                "sql-v2-capsule-expired-permit",
                approval_clock=clock,
                coordination_clock=clock,
            ),
        )
        started, capsule = await _dispatch_and_transfer_v2(fixture)
        assert started.permit.expires_at < fixture.approval.expires_at
        clock.current = started.permit.expires_at

        with (
            pytest.raises(AgenticCoordinationError, match="authority is no longer active"),
            fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
                capsule,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            ),
        ):
            pass

        clock.current = NOW + timedelta(seconds=10)
        with (
            pytest.raises(AgenticCoordinationError, match="foreign or consumed"),
            fixture.harness.store._claim_transferred_sql_specialist_v2_dispatch_runtime(
                capsule,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            ),
        ):
            pass

    asyncio.run(scenario())


def test_v2_dispatch_rejects_deployment_runtime_validator_replacement_before_mutation(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-deployment-validator-replacement"),
        )
        plan = _plan_v2(fixture)
        runtime = _bind_v2(fixture, plan)
        deployment = fixture.harness.store._AgenticCoordinationStore__specialist_deployment
        deployment_type = type(deployment)
        forged_calls = 0

        def forged(*_args: object, **_kwargs: object) -> None:
            nonlocal forged_calls
            forged_calls += 1

        with monkeypatch.context() as scoped:
            scoped.setattr(deployment_type, "require_runtime", forged)
            with pytest.raises(
                AgenticCoordinationError,
                match="not pinned by this deployment",
            ):
                await durable_module._SQL_SPECIALIST_V2_PUBLIC_DISPATCH_IMPLEMENTATION(
                    fixture.harness.store,
                    plan,
                    runtime,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )

        assert forged_calls == 0
        assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
        audit = fixture.harness.store.sql_specialist_dispatch_plan_v2_entry(
            plan_id=plan.entry.plan_id,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert audit.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "method_name",
    (
        "plan_sql_specialist_dispatch_v2",
        "_require_specialist_deployment_locked",
    ),
)
def test_v2_captured_plan_rejects_entrypoint_replacement_before_row_creation(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory(f"sql-v2-plan-entrypoint-replacement-{method_name}"),
        )
        forged_calls = 0

        def forged(*_args: object, **_kwargs: object) -> None:
            nonlocal forged_calls
            forged_calls += 1

        with monkeypatch.context() as scoped:
            scoped.setattr(AgenticCoordinationStore, method_name, forged)
            with pytest.raises(AgenticCoordinationError, match="implementation changed"):
                _plan_v2(fixture)

        assert forged_calls == 0
        execution = fixture.harness.store.specialist_execution_entry(
            command_id=fixture.reservation.entry.command_id,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert execution.state is AgenticSpecialistExecutionState.RESERVED
        assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "method_name",
    (
        "bind_sql_specialist_v2_permit_dispatcher",
        "_require_specialist_deployment_locked",
    ),
)
def test_v2_captured_bind_rejects_entrypoint_replacement_before_configuration(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory(f"sql-v2-bind-entrypoint-replacement-{method_name}"),
        )
        plan = _plan_v2(fixture)
        forged_calls = 0

        def forged(*_args: object, **_kwargs: object) -> None:
            nonlocal forged_calls
            forged_calls += 1

        assert (
            fixture.harness.store._AgenticCoordinationStore__specialist_configured_runtime_identity
            is None
        )
        with monkeypatch.context() as scoped:
            scoped.setattr(AgenticCoordinationStore, method_name, forged)
            with pytest.raises(AgenticCoordinationError, match="implementation changed"):
                _bind_v2(fixture, plan)

        assert forged_calls == 0
        assert (
            fixture.harness.store._AgenticCoordinationStore__specialist_configured_runtime_identity
            is None
        )
        assert plan.entry.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT

    asyncio.run(scenario())


def test_v2_captured_close_ignores_replaced_retirement_chain(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-close-entrypoint-replacement"),
        )
        _started, capsule = await _dispatch_and_transfer_v2(fixture)
        database = fixture.harness.store._database
        retired_field = "_AgenticSQLSpecialistDispatchRuntimeCapsuleV2__retired"
        forged_calls = 0

        def forged(*_args: object, **_kwargs: object) -> None:
            nonlocal forged_calls
            forged_calls += 1

        with monkeypatch.context() as scoped:
            scoped.setattr(AgenticCoordinationStore, "close", forged)
            scoped.setattr(AgenticCoordinationStore, "__exit__", forged)
            scoped.setattr(
                AgenticCoordinationStore,
                "_retire_issued_sql_specialist_v2_plans",
                forged,
            )
            scoped.setattr(
                AgenticCoordinationStore,
                "_abandon_specialist_dispatch_binding_registries",
                forged,
            )
            scoped.setattr(VerifiedSQLSpecialistDispatchPlanV2, "_retire", forged)
            scoped.setattr(type(database), "close", forged)
            scoped.setattr(
                durable_module,
                "_sql_specialist_v2_retire_plan_callback",
                forged,
            )
            scoped.setattr(
                durable_module,
                "_sql_specialist_v2_retire_dispatch_callback",
                forged,
            )
            durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(fixture.harness.store)

        assert forged_calls == 0
        assert getattr(capsule, retired_field) is True
        assert not (
            fixture.harness.store._AgenticCoordinationStore__transferred_sql_specialist_v2_dispatch_capsules
        )
        assert not (fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_plans)
        with pytest.raises(
            AgenticCoordinationError,
            match="coordination descriptor authority is closed",
        ):
            database.require_open()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "method_name",
    (
        "plan_sql_specialist_dispatch_v2",
        "bind_sql_specialist_v2_permit_dispatcher",
        "close",
        "__exit__",
        "_begin_sql_specialist_v2_dispatch_operation",
        "_dispatch_sql_specialist_v2_permit_once_active",
        "_retire_issued_sql_specialist_v2_plans",
        "_require_specialist_deployment_locked",
        "_abandon_specialist_dispatch_binding_registries",
        "_pin_specialist_configured_runtime",
        "_register_sql_specialist_v2_plan",
        "_release_sql_specialist_v2_dispatch_operation",
    ),
)
def test_v2_captured_dispatch_rejects_store_class_helper_replacement_before_mutation(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
    method_name: str,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory(f"sql-v2-class-replacement-{method_name}"),
        )
        plan = _plan_v2(fixture)
        runtime = _bind_v2(fixture, plan)
        forged_calls = 0

        def forged(*_args: object, **_kwargs: object) -> None:
            nonlocal forged_calls
            forged_calls += 1

        monkeypatch.setattr(AgenticCoordinationStore, method_name, forged)

        with pytest.raises(AgenticCoordinationError, match="implementation changed"):
            await durable_module._SQL_SPECIALIST_V2_PUBLIC_DISPATCH_IMPLEMENTATION(
                fixture.harness.store,
                plan,
                runtime,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )

        assert forged_calls == 0
        assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
        audit = fixture.harness.store.sql_specialist_dispatch_plan_v2_entry(
            plan_id=plan.entry.plan_id,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert audit.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
        fixture.harness.store._database.require_open()

    asyncio.run(scenario())


def test_v2_captured_dispatch_rejects_store_instance_shadow_before_mutation(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-instance-shadow"),
        )
        plan = _plan_v2(fixture)
        runtime = _bind_v2(fixture, plan)
        forged_calls = 0

        def forged(*_args: object, **_kwargs: object) -> None:
            nonlocal forged_calls
            forged_calls += 1

        monkeypatch.setattr(
            fixture.harness.store,
            "_begin_sql_specialist_v2_dispatch_operation",
            forged,
        )

        with pytest.raises(AgenticCoordinationError, match="implementation changed"):
            await durable_module._SQL_SPECIALIST_V2_PUBLIC_DISPATCH_IMPLEMENTATION(
                fixture.harness.store,
                plan,
                runtime,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )

        assert forged_calls == 0
        assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
        assert plan.entry.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("owner_type", "method_name"),
    (
        (WebSQLSpecialistCapabilityActivationV2, "action_registry"),
        (WebSQLSpecialistCapabilityActivationV2, "definition"),
        (WebSQLSpecialistCapabilityActivationV2, "prepare_action"),
        (WebSQLSpecialistCapabilityActivationV2, "resolve_for_dispatch"),
        (WebSQLSpecialistAuthorizationToolV2, "validate_request"),
        (WebSQLSpecialistAuthorizationToolV2, "compile_request"),
        (WebSQLSpecialistCapabilityBundleV2, "capability"),
    ),
)
def test_v2_plan_rejects_activation_class_replacement_before_mutation(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
    owner_type: type[object],
    method_name: str,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory(f"sql-v2-activation-replacement-{method_name}"),
        )
        forged_calls = 0

        def forged(*_args: object, **_kwargs: object) -> None:
            nonlocal forged_calls
            forged_calls += 1

        monkeypatch.setattr(owner_type, method_name, forged)

        with pytest.raises(AgenticCoordinationError, match="implementation changed"):
            _plan_v2(fixture)

        assert forged_calls == 0
        assert fixture.ledger.record(fixture.grant.grant_id).remaining_calls == 1
        execution = fixture.harness.store.specialist_execution_entry(
            command_id=fixture.reservation.entry.command_id,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert execution.state is AgenticSpecialistExecutionState.RESERVED

    asyncio.run(scenario())


def test_v2_capsule_claim_replacement_is_rejected_without_consuming_genuine_capsule(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-capsule-claim-replacement"),
        )
        _started, capsule = await _dispatch_and_transfer_v2(fixture)
        capsule_type = type(capsule)
        original_claim = capsule_type._claim
        forged_calls = 0

        def forged(*_args: object, **_kwargs: object) -> None:
            nonlocal forged_calls
            forged_calls += 1

        monkeypatch.setattr(capsule_type, "_claim", forged)
        with (
            pytest.raises(AgenticCoordinationError, match="implementation changed"),
            durable_module._SQL_SPECIALIST_V2_RUNTIME_CLAIM_IMPLEMENTATION(
                fixture.harness.store,
                capsule,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            ),
        ):
            pass
        assert forged_calls == 0

        monkeypatch.setattr(capsule_type, "_claim", original_claim)
        with durable_module._SQL_SPECIALIST_V2_RUNTIME_CLAIM_IMPLEMENTATION(
            fixture.harness.store,
            capsule,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        ):
            pass

    asyncio.run(scenario())


def test_v1_wire_identity_constants_remain_frozen() -> None:
    assert AgenticSpecialistDispatchPlanEntry.model_fields["api_version"].default == (
        "pajin.dev/agentic-specialist-dispatch-plan/v1alpha1"
    )
    assert AgenticSpecialistDispatchPlanEntry.model_fields["kind"].default == (
        "AgenticSpecialistDispatchPlan"
    )
    assert "runtime_generation" not in AgenticSpecialistDispatchPlanEntry.model_fields
    assert durable_module.AGENTIC_COORDINATION_SCHEMA_V5_DIGEST == (
        "dc32a91970da8cddd0bd6a4d2c02cffcbe9bcba484676eb18072e0fb8f52c314"
    )
    assert durable_module.AGENTIC_COORDINATION_SCHEMA_V6_DIGEST == (
        "0a20a2ffbd8d5bb07519ec95c62382303ef9fca20595657851f84d994eccf6ee"
    )
