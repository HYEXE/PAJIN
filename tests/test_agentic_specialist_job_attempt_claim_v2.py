from __future__ import annotations

import asyncio
import copy
import os
import pickle
import socket
import sqlite3
import subprocess
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from hashlib import sha256
from typing import cast

import httpx
import pytest

import pajin.agentic._specialist_gateway_runtime_owner_v2 as runtime_owner_module
import pajin.agentic.durable as durable_module
import pajin.agentic.specialist_backend_v2 as backend_module
import pajin.agentic.specialist_gateway_v2 as gateway_module
from pajin.agentic.durable import (
    AgenticCoordinationError,
    AgenticCoordinationStore,
    AgenticSpecialistRuntimeGeneration,
    VerifiedPlannedSQLSpecialistDispatchStartedV2,
    VerifiedSQLSpecialistJobAttemptClaimV2,
)
from pajin.agentic.specialist_attempts import (
    AgenticSpecialistJobAttempt,
    AgenticSpecialistJobAttemptState,
    AgenticSpecialistTargetIOState,
    AgenticSpecialistTerminalKind,
    AgenticSpecialistTerminalReceipt,
)
from pajin.agentic.specialist_gateway_v2 import (
    SpecialistGatewayDeploymentSnapshotV2,
    SpecialistGatewayDeploymentV2Error,
    VerifiedSpecialistGatewayDeploymentV2,
    structured_fake_specialist_gateway_deployment_v2,
)
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.gateway import ToolGateway
from tests.test_agentic_specialist_dispatch_plan_v2 import (
    NOW,
    SQLHarnessFactory,
    SQLSpecialistV2Fixture,
    _bind_v2,
    _plan_v2,
    _specialist_fixture_v2,
)

pytest_plugins = ("tests.test_agentic_specialist_dispatch_plan_v2",)


class _FixtureDatetimeMeta(type):
    def __instancecheck__(cls, instance: object) -> bool:
        return isinstance(instance, datetime)


class _FixtureDatetime(metaclass=_FixtureDatetimeMeta):
    @classmethod
    def now(cls, tz: object = None) -> datetime:
        return NOW + timedelta(seconds=10)


class _ExpiredFixtureDatetime(metaclass=_FixtureDatetimeMeta):
    @classmethod
    def now(cls, tz: object = None) -> datetime:
        return NOW + timedelta(minutes=10)


class _CancelledFixtureDatetime(metaclass=_FixtureDatetimeMeta):
    @classmethod
    def now(cls, tz: object = None) -> datetime:
        raise asyncio.CancelledError


def _gateway_deployment(label: str) -> VerifiedSpecialistGatewayDeploymentV2:
    return structured_fake_specialist_gateway_deployment_v2(
        signing_private_key=sha256(f"specialist-gateway:{label}".encode()).digest(),
        verification_key_id=f"key:agentic-specialist-gateway:{label}",
        trust_domain="trust:agentic-specialist-v2",
        issuer="PAJIN structured fake specialist Gateway",
    )


async def _started(
    fixture: SQLSpecialistV2Fixture,
) -> VerifiedPlannedSQLSpecialistDispatchStartedV2:
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
    return result.result


def test_live_job_attempt_claim_is_fresh_same_task_and_zero_io(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-happy"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("happy")
        calls: list[str] = []

        def sync_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("sync-io")

        async def async_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("async-io")

        monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
        monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
        monkeypatch.setattr(socket, "create_connection", sync_tripwire)
        monkeypatch.setattr(socket, "getaddrinfo", sync_tripwire)
        monkeypatch.setattr(socket.socket, "connect", sync_tripwire)
        monkeypatch.setattr(socket.socket, "connect_ex", sync_tripwire)
        monkeypatch.setattr(socket.socket, "send", sync_tripwire)
        monkeypatch.setattr(socket.socket, "sendall", sync_tripwire)
        monkeypatch.setattr(os, "system", sync_tripwire)
        monkeypatch.setattr(subprocess, "run", sync_tripwire)
        monkeypatch.setattr(subprocess, "Popen", sync_tripwire)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", async_tripwire)
        monkeypatch.setattr(asyncio, "create_subprocess_shell", async_tripwire)
        monkeypatch.setattr(httpx.Client, "send", sync_tripwire)
        monkeypatch.setattr(httpx.AsyncClient, "send", async_tripwire)

        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert type(claim) is VerifiedSQLSpecialistJobAttemptClaimV2
        attempt = claim.attempt
        assert type(attempt) is AgenticSpecialistJobAttempt
        assert attempt.state is AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
        assert attempt.plan_id == started.plan.plan_id
        assert attempt.plan_state_digest == started.plan.state_digest
        assert attempt.reservation_state_digest == started.execution.state_digest
        assert attempt.claim_verification.verification_digest
        assert attempt.backend_dispatch_started_at is None
        assert attempt.execution_authority is False
        assert attempt.finding_authority is False
        assert attempt.graph_authority is False
        assert attempt.report_authority is False
        assert deployment.invocation_count == 0
        assert calls == []
        for attribute in (
            "context",
            "deployment",
            "deployment_claim",
            "store",
            "store_authority",
        ):
            with pytest.raises(AttributeError):
                object.__getattribute__(
                    claim,
                    f"_VerifiedSQLSpecialistJobAttemptClaimV2__{attribute}",
                )

        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == (attempt,)
        assert recovery.unknown_job_attempts == ()
        assert recovery.terminal_receipts == ()
        assert not (
            fixture.harness.store._AgenticCoordinationStore__transferred_sql_specialist_v2_dispatch_capsules
        )
        assert (
            fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims[
                attempt.attempt_id
            ][0]
            is claim
        )
        store = fixture.harness.store
        issued_claims = store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        deployment_claim = issued_claims[attempt.attempt_id][4]

        with pytest.raises(TypeError):
            copy.copy(claim)
        with pytest.raises(TypeError):
            copy.deepcopy(claim)
        with pytest.raises(TypeError):
            pickle.dumps(claim)
        with pytest.raises(TypeError):
            copy.copy(deployment)
        with pytest.raises(TypeError):
            copy.deepcopy(deployment)
        with pytest.raises(TypeError):
            pickle.dumps(deployment)
        with pytest.raises(TypeError):
            copy.copy(deployment_claim)
        with pytest.raises(TypeError):
            copy.deepcopy(deployment_claim)
        with pytest.raises(TypeError):
            pickle.dumps(deployment_claim)
        with pytest.raises(AgenticCoordinationError, match="foreign or consumed"):
            fixture.harness.store._transfer_planned_sql_specialist_v2_dispatch_started(started)

    asyncio.run(scenario())


def test_gateway_deployment_is_one_shot_across_stores(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        first = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-one-shot-first"),
        )
        second = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-one-shot-second"),
        )
        first_started = await _started(first)
        second_started = await _started(second)
        deployment = _gateway_deployment("one-shot")

        first_claim = first.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            first_started,
            gateway_deployment=deployment,
            graph_resolver=first.harness.resolver,
            graph_head=first.harness.graph_head,
        )
        with pytest.raises(
            AgenticCoordinationError,
            match="already claimed or retired",
        ):
            second.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                second_started,
                gateway_deployment=deployment,
                graph_resolver=second.harness.resolver,
                graph_head=second.harness.graph_head,
            )

        assert first_claim.attempt.backend_dispatch_started_at is None
        assert not (
            second.harness.store._AgenticCoordinationStore__transferred_sql_specialist_v2_dispatch_capsules
        )
        second_claim = second.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            second_started,
            gateway_deployment=_gateway_deployment("one-shot-second"),
            graph_resolver=second.harness.resolver,
            graph_head=second.harness.graph_head,
        )
        assert second_claim.attempt.backend_dispatch_started_at is None
        assert deployment.invocation_count == 0

    asyncio.run(scenario())


def test_live_gateway_deployment_exposes_no_raw_runtime_component() -> None:
    deployment = _gateway_deployment("opaque-public-token")

    for attribute in ("backend", "verifier", "key", "template", "inventory"):
        with pytest.raises(AttributeError):
            object.__getattribute__(
                deployment,
                f"_VerifiedSpecialistGatewayDeploymentV2__{attribute}",
            )
    state = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[deployment]
    assert not hasattr(state, "runtime")
    assert deployment.invocation_count == 0


def test_verified_completion_is_task_bound_one_shot_and_tamper_evident(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(backend_module, "datetime", _FixtureDatetime)
        deployment = _gateway_deployment("opaque-completion")
        owner_task = asyncio.current_task()
        assert type(owner_task) is asyncio.Task
        store_identity_token = object()
        owner_token = object()
        attempt_digest = "a" * 64
        dispatch_verification_digest = "b" * 64

        with gateway_module._VERIFIED_DEPLOYMENT_CLAIM_SCOPE_IMPLEMENTATION(
            deployment,
            claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
            store_identity_token=store_identity_token,
            owner_task=owner_task,
            owner_token=owner_token,
        ) as lease:
            completion = await gateway_module._VERIFIED_DEPLOYMENT_EXECUTE_CLAIM_IMPLEMENTATION(
                deployment,
                lease,
                claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                store_identity_token=store_identity_token,
                owner_task=owner_task,
                owner_token=owner_token,
                attempt_digest=attempt_digest,
                dispatch_verification_digest=dispatch_verification_digest,
                backend_handoff_deadline=NOW + timedelta(minutes=5),
            )

            with pytest.raises(TypeError):
                copy.copy(completion)
            with pytest.raises(TypeError):
                copy.deepcopy(completion)
            with pytest.raises(TypeError):
                pickle.dumps(completion)

            async def consume_from_foreign_task() -> None:
                with pytest.raises(
                    SpecialistGatewayDeploymentV2Error,
                    match="foreign, consumed, or changed",
                ):
                    gateway_module._VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION(
                        completion,
                        claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                        deployment=deployment,
                        lease=lease,
                        store_identity_token=store_identity_token,
                        owner_task=owner_task,
                        owner_token=owner_token,
                        attempt_digest=attempt_digest,
                        dispatch_verification_digest=dispatch_verification_digest,
                    )

            await asyncio.create_task(consume_from_foreign_task())
            with pytest.raises(
                SpecialistGatewayDeploymentV2Error,
                match="foreign, consumed, or changed",
            ):
                gateway_module._VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION(
                    completion,
                    claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                    deployment=deployment,
                    lease=lease,
                    store_identity_token=store_identity_token,
                    owner_task=owner_task,
                    owner_token=object(),
                    attempt_digest=attempt_digest,
                    dispatch_verification_digest=dispatch_verification_digest,
                )

            signed_result_attribute = (
                "_VerifiedSpecialistGatewayCompletionV2__signed_result"
            )
            signed_result = object.__getattribute__(
                completion,
                signed_result_attribute,
            )
            tampered_result = signed_result.model_copy(
                update={"signature_base64url": "A" * 86},
            )
            object.__setattr__(completion, signed_result_attribute, tampered_result)
            with pytest.raises(
                SpecialistGatewayDeploymentV2Error,
                match="foreign, consumed, or changed",
            ):
                gateway_module._VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION(
                    completion,
                    claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                    deployment=deployment,
                    lease=lease,
                    store_identity_token=store_identity_token,
                    owner_task=owner_task,
                    owner_token=owner_token,
                    attempt_digest=attempt_digest,
                    dispatch_verification_digest=dispatch_verification_digest,
                )
            object.__setattr__(completion, signed_result_attribute, signed_result)

            envelope, consumed_result, result_digest = (
                gateway_module._VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION(
                    completion,
                    claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                    deployment=deployment,
                    lease=lease,
                    store_identity_token=store_identity_token,
                    owner_task=owner_task,
                    owner_token=owner_token,
                    attempt_digest=attempt_digest,
                    dispatch_verification_digest=dispatch_verification_digest,
                )
            )
            assert envelope.attempt_digest == attempt_digest
            assert consumed_result is signed_result
            assert result_digest == signed_result.result_digest
            with pytest.raises(
                SpecialistGatewayDeploymentV2Error,
                match="foreign, consumed, or changed",
            ):
                gateway_module._VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION(
                    completion,
                    claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                    deployment=deployment,
                    lease=lease,
                    store_identity_token=store_identity_token,
                    owner_task=owner_task,
                    owner_token=owner_token,
                    attempt_digest=attempt_digest,
                    dispatch_verification_digest=dispatch_verification_digest,
                )

            gateway_module._VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION(
                deployment,
                lease,
                claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                store_identity_token=store_identity_token,
                owner_token=owner_token,
            )

        assert deployment not in runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION

    asyncio.run(scenario())


@pytest.mark.parametrize("attribute", ("backend", "verifier"))
def test_private_runtime_component_substitution_fails_before_transfer(
    sql_harness_factory: SQLHarnessFactory,
    attribute: str,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory(f"sql-v2-live-attempt-swap-{attribute}"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment(f"equal-swap-{attribute}")
        foreign = _gateway_deployment(f"equal-swap-{attribute}")
        entry = runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[deployment]
        foreign_entry = runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[foreign]
        object.__setattr__(
            entry,
            "owner",
            replace(
                entry.owner,
                **{attribute: getattr(foreign_entry.owner, attribute)},
            ),
        )

        with pytest.raises(
            AgenticCoordinationError,
            match=r"exact claim verification|private runtime owner changed",
        ):
            fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                started,
                gateway_deployment=deployment,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )

        assert fixture.harness.store.specialist_job_recovery_snapshot().claimed_job_attempts == ()
        assert not (
            fixture.harness.store._AgenticCoordinationStore__transferred_sql_specialist_v2_dispatch_capsules
        )
        recovered = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=_gateway_deployment(f"swap-recovery-{attribute}"),
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert recovered.attempt.backend_dispatch_started_at is None

    asyncio.run(scenario())


def test_gateway_claim_scope_releases_global_lock_while_lease_is_live() -> None:
    async def scenario() -> None:
        first = _gateway_deployment("lock-release-first")
        second = _gateway_deployment("lock-release-second")
        current = asyncio.current_task()
        assert type(current) is asyncio.Task
        first_store = object()
        first_owner = object()
        finished = threading.Event()
        failures: list[BaseException] = []

        def claim_second() -> None:
            async def run() -> None:
                task = asyncio.current_task()
                assert type(task) is asyncio.Task
                owner = object()
                with gateway_module._VERIFIED_DEPLOYMENT_CLAIM_SCOPE_IMPLEMENTATION(
                    second,
                    claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                    store_identity_token=object(),
                    owner_task=task,
                    owner_token=owner,
                ) as lease:
                    gateway_module._VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION(
                        second,
                        lease,
                        claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                        store_identity_token=(
                            gateway_module._MINT_LEASE_IDENTITY_IMPLEMENTATION(lease)[1]
                        ),
                        owner_token=owner,
                    )

            try:
                asyncio.run(run())
            except BaseException as exc:
                failures.append(exc)
            finally:
                finished.set()

        with gateway_module._VERIFIED_DEPLOYMENT_CLAIM_SCOPE_IMPLEMENTATION(
            first,
            claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
            store_identity_token=first_store,
            owner_task=current,
            owner_token=first_owner,
        ) as first_lease:
            thread = threading.Thread(target=claim_second)
            thread.start()
            assert finished.wait(timeout=3)
            thread.join(timeout=3)
            assert not thread.is_alive()
            assert failures == []
            gateway_module._VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION(
                first,
                first_lease,
                claim_authority=gateway_module._DEPLOYMENT_CLAIM_AUTHORITY,
                store_identity_token=first_store,
                owner_token=first_owner,
            )

    asyncio.run(scenario())


def test_serialized_gateway_snapshot_is_audit_only_not_bearer_authority(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-detached-gateway"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("detached-gateway")
        detached = SpecialistGatewayDeploymentSnapshotV2.model_validate_json(
            deployment.snapshot.model_dump_json(by_alias=True)
        )
        assert detached == deployment.snapshot
        assert detached is not deployment.snapshot

        with pytest.raises(AgenticCoordinationError, match="exact live authorities"):
            fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                started,
                gateway_deployment=cast(VerifiedSpecialistGatewayDeploymentV2, detached),
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )

        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert claim.attempt.gateway_digest == detached.gateway_digest
        assert deployment.invocation_count == 0

    asyncio.run(scenario())


def test_concurrent_gateway_claims_have_exactly_one_winner(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    deployment = _gateway_deployment("concurrent-one-shot")
    setup_lock = threading.Lock()
    result_lock = threading.Lock()
    race = threading.Barrier(2)
    results: list[bool] = []
    failures: list[BaseException] = []
    winner_invocation_counts: list[int] = []

    def contender(label: str) -> None:
        async def run() -> None:
            with setup_lock:
                harness = sql_harness_factory(f"sql-v2-live-attempt-concurrent-{label}")
                fixture = _specialist_fixture_v2(
                    harness,
                )
                started = await _started(fixture)
            race.wait(timeout=10)
            try:
                fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                    started,
                    gateway_deployment=deployment,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )
            except AgenticCoordinationError:
                won = False
            else:
                won = True
                invocation_count = deployment.invocation_count
            with result_lock:
                results.append(won)
                if won:
                    winner_invocation_counts.append(invocation_count)

        try:
            asyncio.run(run())
        except BaseException as exc:
            with result_lock:
                failures.append(exc)

    threads = tuple(threading.Thread(target=contender, args=(label,)) for label in ("a", "b"))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=20)

    assert not any(thread.is_alive() for thread in threads)
    assert failures == []
    assert sorted(results) == [False, True]
    assert winner_invocation_counts == [0]
    with pytest.raises(SpecialistGatewayDeploymentV2Error):
        _ = deployment.invocation_count


def test_existing_job_attempt_row_cannot_mint_fresh_authority(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-no-remint"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("no-remint")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        attempt = claim.attempt

        with pytest.raises(
            AgenticCoordinationError,
            match="existing specialist JobAttempt cannot mint live authority",
        ):
            fixture.harness.store._record_specialist_job_attempt(
                attempt,
                authority=fixture.harness.store._authority,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
                require_new=True,
            )
        detached = AgenticSpecialistJobAttempt.model_validate(
            attempt.model_dump(mode="json", by_alias=True)
        )
        assert detached == attempt
        assert detached is not attempt
        assert (
            len(
                fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
            )
            == 1
        )

    asyncio.run(scenario())


def test_owner_task_completion_retires_live_claim_but_preserves_audit(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        async def mint_in_child() -> tuple[
            SQLSpecialistV2Fixture,
            VerifiedSQLSpecialistJobAttemptClaimV2,
            AgenticSpecialistJobAttempt,
        ]:
            fixture = _specialist_fixture_v2(
                sql_harness_factory("sql-v2-live-attempt-task-retire"),
            )
            started = await _started(fixture)
            claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                started,
                gateway_deployment=_gateway_deployment("task-retire"),
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
            return fixture, claim, claim.attempt

        fixture, claim, attempt = await asyncio.create_task(mint_in_child())
        await asyncio.sleep(0)

        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert not (
            fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        )
        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert len(recovery.terminal_receipts) == 1
        receipt = recovery.terminal_receipts[0]
        assert receipt.attempt_id == attempt.attempt_id
        assert receipt.terminal_kind is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
        assert receipt.target_io_state is AgenticSpecialistTargetIOState.NOT_STARTED
        assert receipt.succeeded is False
        assert receipt.backend_terminal_proven is False
        assert recovery.automatic_redispatch_authorized is False

    asyncio.run(scenario())


def test_cancelled_owner_task_retires_live_claim_and_preserves_cancellation(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-task-cancel"),
        )
        deployment = _gateway_deployment("task-cancel")
        owner_ready = asyncio.Event()
        wait_forever = asyncio.Event()
        holder: dict[str, object] = {}

        async def owner() -> None:
            started = await _started(fixture)
            claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                started,
                gateway_deployment=deployment,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
            holder["claim"] = claim
            owner_ready.set()
            await wait_forever.wait()

        owner_task = asyncio.create_task(owner())
        await owner_ready.wait()
        runtime_identity_token = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[
            deployment
        ].runtime_identity_token
        owner_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await owner_task
        await asyncio.sleep(0)

        claim = cast(VerifiedSQLSpecialistJobAttemptClaimV2, holder["claim"])
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert not (
            fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        )
        with pytest.raises(runtime_owner_module._SpecialistGatewayRuntimeOwnerV2Error):
            runtime_owner_module._RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
                deployment,
                access_authority=runtime_owner_module._RUNTIME_OWNER_ACCESS_AUTHORITY,
                identity_token=runtime_identity_token,
            )
        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert len(recovery.terminal_receipts) == 1
        assert recovery.terminal_receipts[0].attempt_id == claim.attempt.attempt_id
        assert (
            recovery.terminal_receipts[0].terminal_kind
            is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
        )

    asyncio.run(scenario())


def test_owner_done_receipt_failure_zeroizes_and_reports_loop_error(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-owner-receipt-fault"),
        )
        deployment = _gateway_deployment("owner-receipt-fault")
        owner_ready = asyncio.Event()
        release_owner = asyncio.Event()
        holder: dict[str, object] = {}
        loop_errors: list[dict[str, object]] = []

        async def owner() -> None:
            started = await _started(fixture)
            claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                started,
                gateway_deployment=deployment,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
            holder["claim"] = claim
            owner_ready.set()
            await release_owner.wait()

        owner_task = asyncio.create_task(owner())
        await owner_ready.wait()
        runtime_identity_token = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[
            deployment
        ].runtime_identity_token
        loop = asyncio.get_running_loop()
        prior_handler = loop.get_exception_handler()

        def capture_loop_error(
            _loop: asyncio.AbstractEventLoop, context: dict[str, object]
        ) -> None:
            loop_errors.append(context)

        def fail_receipt(*_args: object, **_kwargs: object) -> None:
            raise AgenticCoordinationError("injected owner callback receipt failure")

        loop.set_exception_handler(capture_loop_error)
        try:
            with monkeypatch.context() as scoped:
                scoped.setattr(
                    durable_module,
                    "_SQL_SPECIALIST_V2_RECORD_ABANDONMENT_IMPLEMENTATION",
                    fail_receipt,
                )
                release_owner.set()
                await owner_task
                await asyncio.sleep(0)
        finally:
            loop.set_exception_handler(prior_handler)

        claim = cast(VerifiedSQLSpecialistJobAttemptClaimV2, holder["claim"])
        assert any(
            isinstance(context.get("exception"), AgenticCoordinationError)
            for context in loop_errors
        )
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert not (
            fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        )
        with pytest.raises(runtime_owner_module._SpecialistGatewayRuntimeOwnerV2Error):
            runtime_owner_module._RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
                deployment,
                access_authority=runtime_owner_module._RUNTIME_OWNER_ACCESS_AUTHORITY,
                identity_token=runtime_identity_token,
            )
        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert len(recovery.claimed_job_attempts) == 1
        assert recovery.claimed_job_attempts[0].attempt_id == claim.attempt.attempt_id
        assert recovery.terminal_receipts == ()
        assert recovery.automatic_redispatch_authorized is False

    asyncio.run(scenario())


def test_store_close_retires_unconsumed_live_job_attempt_claim(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-close"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("close")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        attempt = claim.attempt
        store = fixture.harness.store
        store_id = store.store_id
        runtime_identity_token = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[
            deployment
        ].runtime_identity_token
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is False

        durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(store)

        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert not (store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims)
        with pytest.raises(runtime_owner_module._SpecialistGatewayRuntimeOwnerV2Error):
            runtime_owner_module._RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
                deployment,
                access_authority=runtime_owner_module._RUNTIME_OWNER_ACCESS_AUTHORITY,
                identity_token=runtime_identity_token,
            )

        reopened = AgenticCoordinationStore(
            store.path,
            binding=fixture.harness.binding,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
            specialist_graph_store=fixture.harness.graph_store,
            specialist_capability_ledger=fixture.harness.specialist_ledger,
            specialist_approval_keys=(fixture.harness.approval_key,),
            specialist_approval_clock=fixture.harness.approval_clock,
            specialist_runtime_generation=(AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2),
            allow_create=False,
            expected_store_id=store_id,
            clock=lambda: NOW + timedelta(seconds=20),
        )
        try:
            recovery = reopened.specialist_job_recovery_snapshot()
            assert recovery.claimed_job_attempts == ()
            assert len(recovery.terminal_receipts) == 1
            receipt = recovery.terminal_receipts[0]
            assert receipt.attempt_id == attempt.attempt_id
            assert receipt.terminal_kind is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
            assert receipt.target_io_state is AgenticSpecialistTargetIOState.NOT_STARTED
        finally:
            reopened.close()

    asyncio.run(scenario())


def test_store_close_receipt_failure_still_closes_and_purges_live_authority(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-close-receipt-fault"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("close-receipt-fault")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        store = fixture.harness.store
        store_id = store.store_id
        runtime_identity_token = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[
            deployment
        ].runtime_identity_token

        def fail_receipt(*_args: object, **_kwargs: object) -> None:
            raise AgenticCoordinationError("injected close receipt failure")

        with monkeypatch.context() as scoped:
            scoped.setattr(
                durable_module,
                "_SQL_SPECIALIST_V2_RECORD_ABANDONMENT_IMPLEMENTATION",
                fail_receipt,
            )
            with pytest.raises(
                AgenticCoordinationError,
                match="close completed with cleanup failures",
            ):
                durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(store)

        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert not (store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims)
        with pytest.raises(AgenticCoordinationError, match="closed"):
            store._database.require_open()
        with pytest.raises(runtime_owner_module._SpecialistGatewayRuntimeOwnerV2Error):
            runtime_owner_module._RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
                deployment,
                access_authority=runtime_owner_module._RUNTIME_OWNER_ACCESS_AUTHORITY,
                identity_token=runtime_identity_token,
            )

        reopened = AgenticCoordinationStore(
            store.path,
            binding=fixture.harness.binding,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
            specialist_graph_store=fixture.harness.graph_store,
            specialist_capability_ledger=fixture.harness.specialist_ledger,
            specialist_approval_keys=(fixture.harness.approval_key,),
            specialist_approval_clock=fixture.harness.approval_clock,
            specialist_runtime_generation=(AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2),
            allow_create=False,
            expected_store_id=store_id,
            clock=lambda: NOW + timedelta(seconds=20),
        )
        try:
            recovery = reopened.specialist_job_recovery_snapshot()
            assert len(recovery.claimed_job_attempts) == 1
            assert recovery.claimed_job_attempts[0].attempt_id == claim.attempt.attempt_id
            assert recovery.terminal_receipts == ()
            assert recovery.automatic_redispatch_authorized is False
        finally:
            reopened.close()

    asyncio.run(scenario())


def test_store_close_and_owner_completion_race_has_one_terminal_receipt(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-close-owner-race"),
        )
        release_owner = asyncio.Event()
        owner_ready = asyncio.Event()
        close_start = threading.Event()
        close_failures: list[BaseException] = []
        holder: dict[str, object] = {}
        deployment = _gateway_deployment("close-owner-race")

        async def owner() -> None:
            started = await _started(fixture)
            claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                started,
                gateway_deployment=deployment,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
            holder["claim"] = claim
            owner_ready.set()
            await release_owner.wait()

        owner_task = asyncio.create_task(owner())
        await owner_ready.wait()
        store = fixture.harness.store
        store_id = store.store_id
        runtime_identity_token = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[
            deployment
        ].runtime_identity_token

        def close_store() -> None:
            close_start.wait(timeout=10)
            try:
                durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(store)
            except BaseException as exc:
                close_failures.append(exc)

        close_thread = threading.Thread(target=close_store)
        close_thread.start()
        release_owner.set()
        close_start.set()
        await owner_task
        while close_thread.is_alive():
            await asyncio.sleep(0.01)
        close_thread.join(timeout=1)
        await asyncio.sleep(0)

        claim = cast(VerifiedSQLSpecialistJobAttemptClaimV2, holder["claim"])
        assert close_failures == []
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert not (store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims)
        with pytest.raises(runtime_owner_module._SpecialistGatewayRuntimeOwnerV2Error):
            runtime_owner_module._RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
                deployment,
                access_authority=runtime_owner_module._RUNTIME_OWNER_ACCESS_AUTHORITY,
                identity_token=runtime_identity_token,
            )

        reopened = AgenticCoordinationStore(
            store.path,
            binding=fixture.harness.binding,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
            specialist_graph_store=fixture.harness.graph_store,
            specialist_capability_ledger=fixture.harness.specialist_ledger,
            specialist_approval_keys=(fixture.harness.approval_key,),
            specialist_approval_clock=fixture.harness.approval_clock,
            specialist_runtime_generation=(AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2),
            allow_create=False,
            expected_store_id=store_id,
            clock=lambda: NOW + timedelta(seconds=20),
        )
        try:
            recovery = reopened.specialist_job_recovery_snapshot()
            assert recovery.claimed_job_attempts == ()
            assert len(recovery.terminal_receipts) == 1
            assert recovery.terminal_receipts[0].attempt_id == claim.attempt.attempt_id
            assert (
                recovery.terminal_receipts[0].terminal_kind
                is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
            )
        finally:
            reopened.close()

    asyncio.run(scenario())


def test_explicit_discard_records_abandonment_and_purges_runtime_owner(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-explicit-discard"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("explicit-discard")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        store = fixture.harness.store
        issued_claims = store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        issued = issued_claims[claim.attempt.attempt_id]
        current = asyncio.current_task()
        assert type(current) is asyncio.Task

        durable_module._SQL_SPECIALIST_V2_DISCARD_JOB_ATTEMPT_CLAIM_IMPLEMENTATION(
            fixture.harness.store,
            claim,
            owner_task=current,
            owner_token=issued[2],
            claim_identity_token=issued[7],
            abandonment_reason="claim-discarded",
            retire_gateway=True,
        )

        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert len(recovery.terminal_receipts) == 1
        assert (
            recovery.terminal_receipts[0].terminal_kind
            is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
        )
        with pytest.raises(runtime_owner_module._SpecialistGatewayRuntimeOwnerV2Error):
            runtime_owner_module._RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
                deployment,
                access_authority=runtime_owner_module._RUNTIME_OWNER_ACCESS_AUTHORITY,
                identity_token=(
                    gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[
                        deployment
                    ].runtime_identity_token
                ),
            )

    asyncio.run(scenario())


def test_receipt_failure_still_retires_live_claim_and_gateway_owner(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-receipt-fault"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("receipt-fault")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        store = fixture.harness.store
        issued_claims = store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        issued = issued_claims[claim.attempt.attempt_id]
        runtime_identity_token = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[
            deployment
        ].runtime_identity_token
        current = asyncio.current_task()
        assert type(current) is asyncio.Task

        def fail_receipt(*_args: object, **_kwargs: object) -> None:
            raise AgenticCoordinationError("injected abandonment receipt failure")

        with monkeypatch.context() as scoped:
            scoped.setattr(
                durable_module,
                "_SQL_SPECIALIST_V2_RECORD_ABANDONMENT_IMPLEMENTATION",
                fail_receipt,
            )
            with pytest.raises(
                AgenticCoordinationError,
                match="discard cleanup did not complete",
            ):
                durable_module._SQL_SPECIALIST_V2_DISCARD_JOB_ATTEMPT_CLAIM_IMPLEMENTATION(
                    store,
                    claim,
                    owner_task=current,
                    owner_token=issued[2],
                    claim_identity_token=issued[7],
                    abandonment_reason="claim-discarded",
                    retire_gateway=True,
                )

        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert not issued_claims
        with pytest.raises(runtime_owner_module._SpecialistGatewayRuntimeOwnerV2Error):
            runtime_owner_module._RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
                deployment,
                access_authority=runtime_owner_module._RUNTIME_OWNER_ACCESS_AUTHORITY,
                identity_token=runtime_identity_token,
            )
        recovery = store.specialist_job_recovery_snapshot()
        assert len(recovery.claimed_job_attempts) == 1
        assert recovery.claimed_job_attempts[0].attempt_id == claim.attempt.attempt_id
        assert recovery.terminal_receipts == ()
        assert recovery.automatic_redispatch_authorized is False

    asyncio.run(scenario())


def test_cancelled_publication_preserves_cancellation_when_receipt_cleanup_fails(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CancellingCoordinationClock:
        armed = False
        calls = 0
        baseline = NOW + timedelta(seconds=10)

        def __call__(self) -> datetime:
            if not self.armed:
                return self.baseline
            self.calls += 1
            if self.calls == 2:
                raise asyncio.CancelledError
            return self.baseline

    async def scenario() -> None:
        clock = CancellingCoordinationClock()
        fixture = _specialist_fixture_v2(
            sql_harness_factory(
                "sql-v2-live-attempt-cancel-receipt-fault",
                approval_clock=lambda: NOW + timedelta(seconds=10),
                coordination_clock=clock,
            ),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("cancel-receipt-fault")
        runtime_identity_token = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[
            deployment
        ].runtime_identity_token

        def fail_terminal_insert(*_args: object, **_kwargs: object) -> None:
            raise sqlite3.OperationalError("injected terminal receipt write failure")

        clock.armed = True
        with monkeypatch.context() as scoped:
            scoped.setattr(
                durable_module,
                "_insert_specialist_terminal_receipt",
                fail_terminal_insert,
            )
            with pytest.raises(asyncio.CancelledError) as raised:
                fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                    started,
                    gateway_deployment=deployment,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )

        assert any(
            "mint cleanup also failed" in note for note in getattr(raised.value, "__notes__", ())
        )
        store = fixture.harness.store
        issued_claims = store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        assert not issued_claims
        with pytest.raises(runtime_owner_module._SpecialistGatewayRuntimeOwnerV2Error):
            runtime_owner_module._RESOLVE_RUNTIME_OWNER_IMPLEMENTATION(
                deployment,
                access_authority=runtime_owner_module._RUNTIME_OWNER_ACCESS_AUTHORITY,
                identity_token=runtime_identity_token,
            )
        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert len(recovery.claimed_job_attempts) == 1
        assert recovery.terminal_receipts == ()
        assert recovery.automatic_redispatch_authorized is False

    asyncio.run(scenario())


def test_publication_expiry_after_insert_records_mint_failed_abandonment(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    class AdvancingCoordinationClock:
        armed = False
        calls = 0
        baseline = NOW + timedelta(seconds=10)

        def __call__(self) -> datetime:
            if not self.armed:
                return self.baseline
            self.calls += 1
            if self.calls == 1:
                return self.baseline
            return NOW + timedelta(minutes=1)

    async def scenario() -> None:
        clock = AdvancingCoordinationClock()
        fixture = _specialist_fixture_v2(
            sql_harness_factory(
                "sql-v2-live-attempt-publication-expiry",
                approval_clock=lambda: NOW + timedelta(seconds=10),
                coordination_clock=clock,
            ),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("publication-expiry")
        clock.armed = True

        with pytest.raises(
            AgenticCoordinationError,
            match="publication authority is no longer active",
        ):
            fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                started,
                gateway_deployment=deployment,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )

        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert len(recovery.terminal_receipts) == 1
        receipt = recovery.terminal_receipts[0]
        assert receipt.terminal_kind is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
        assert receipt.target_io_state is AgenticSpecialistTargetIOState.NOT_STARTED
        assert not (
            fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        )

    asyncio.run(scenario())


def test_claim_constructor_replacement_fails_before_wrapper_execution(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-claim-init-pin"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("claim-init-pin")
        calls: list[str] = []
        original = VerifiedSQLSpecialistJobAttemptClaimV2.__init__

        def wrapper(self: object, **kwargs: object) -> None:
            calls.append("wrapper")
            original(self, **kwargs)

        with monkeypatch.context() as scoped:
            scoped.setattr(VerifiedSQLSpecialistJobAttemptClaimV2, "__init__", wrapper)
            with pytest.raises(
                AgenticCoordinationError,
                match="Store or capsule implementation changed",
            ):
                fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
                    started,
                    gateway_deployment=deployment,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )
        assert calls == []
        recovered = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert recovered.attempt.state is AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND

    asyncio.run(scenario())


def test_live_claim_dispatches_private_zero_io_worker_and_records_terminal_receipt(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(backend_module, "datetime", _FixtureDatetime)
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-terminal-zero-io"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("terminal-zero-io")
        calls: list[str] = []

        def sync_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("sync-io")

        async def async_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("async-io")

        monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
        monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
        monkeypatch.setattr(socket, "create_connection", sync_tripwire)
        monkeypatch.setattr(socket, "getaddrinfo", sync_tripwire)
        monkeypatch.setattr(socket.socket, "connect", sync_tripwire)
        monkeypatch.setattr(socket.socket, "connect_ex", sync_tripwire)
        monkeypatch.setattr(socket.socket, "send", sync_tripwire)
        monkeypatch.setattr(socket.socket, "sendall", sync_tripwire)
        monkeypatch.setattr(os, "system", sync_tripwire)
        monkeypatch.setattr(subprocess, "run", sync_tripwire)
        monkeypatch.setattr(subprocess, "Popen", sync_tripwire)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", async_tripwire)
        monkeypatch.setattr(asyncio, "create_subprocess_shell", async_tripwire)
        monkeypatch.setattr(httpx.Client, "send", sync_tripwire)
        monkeypatch.setattr(httpx.AsyncClient, "send", async_tripwire)

        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        receipt = await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
            claim,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )

        assert receipt.terminal_kind is AgenticSpecialistTerminalKind.FAILED_BEFORE_TARGET_IO
        assert (
            receipt.attempt_state
            is AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        )
        assert receipt.target_io_state is AgenticSpecialistTargetIOState.NOT_STARTED
        assert receipt.succeeded is False
        assert receipt.backend_terminal_proven is True
        assert receipt.worker_result_digest is not None
        assert receipt.backend_terminal_proof_digest is not None
        assert receipt.backend_finished_at is not None
        assert receipt.automatic_redispatch_authorized is False
        assert receipt.execution_authority is False
        assert receipt.finding_authority is False
        assert receipt.graph_authority is False
        assert receipt.report_authority is False
        assert receipt.poc_authority is False
        assert calls == []
        with pytest.raises(
            AgenticCoordinationError,
            match="lacks exact proof provenance",
        ):
            fixture.harness.store._record_specialist_terminal_receipt(
                receipt,
                authority=fixture.harness.store._authority,
            )
        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert recovery.unknown_job_attempts == ()
        assert recovery.terminal_receipts == (receipt,)
        assert not (
            fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        )
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        with pytest.raises(SpecialistGatewayDeploymentV2Error):
            _ = deployment.invocation_count

    asyncio.run(scenario())


def test_terminal_dispatch_is_one_shot_and_foreign_task_cannot_consume_claim(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(backend_module, "datetime", _FixtureDatetime)
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-terminal-one-shot"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("terminal-one-shot")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )

        async def foreign_dispatch() -> None:
            with pytest.raises(
                AgenticCoordinationError,
                match="another scheduler Task",
            ):
                await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
                    claim,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )

        await asyncio.create_task(foreign_dispatch())
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__consumed is False
        receipt = await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
            claim,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert receipt.terminal_kind is AgenticSpecialistTerminalKind.FAILED_BEFORE_TARGET_IO
        with pytest.raises(
            AgenticCoordinationError,
            match="retired or unavailable",
        ):
            await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
                claim,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )
        assert fixture.harness.store.specialist_job_recovery_snapshot().terminal_receipts == (
            receipt,
        )

    asyncio.run(scenario())


def test_expired_live_claim_is_abandoned_before_backend_dispatch(
    sql_harness_factory: SQLHarnessFactory,
) -> None:
    class MutableClock:
        def __init__(self) -> None:
            self.current = NOW + timedelta(seconds=10)

        def __call__(self) -> datetime:
            return self.current

    async def scenario() -> None:
        clock = MutableClock()
        fixture = _specialist_fixture_v2(
            sql_harness_factory(
                "sql-v2-live-attempt-terminal-expired",
                approval_clock=clock,
                coordination_clock=clock,
            ),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("terminal-expired")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        backend = runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[
            deployment
        ].owner.backend
        clock.current = claim.attempt.action_permit_expires_at

        with pytest.raises(
            AgenticCoordinationError,
            match="publication authority is no longer active",
        ):
            await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
                claim,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )

        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert recovery.unknown_job_attempts == ()
        assert len(recovery.terminal_receipts) == 1
        assert (
            recovery.terminal_receipts[0].terminal_kind
            is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
        )
        assert backend.invocation_count == 0

    asyncio.run(scenario())


def test_backend_failure_after_dispatch_marker_records_unknown_terminal_receipt(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(backend_module, "datetime", _ExpiredFixtureDatetime)
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-terminal-unknown"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("terminal-unknown")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        backend = runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[
            deployment
        ].owner.backend

        with pytest.raises(
            SpecialistGatewayDeploymentV2Error,
            match="backend execution failed closed",
        ):
            await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
                claim,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )

        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert recovery.unknown_job_attempts == ()
        assert len(recovery.terminal_receipts) == 1
        receipt = recovery.terminal_receipts[0]
        assert receipt.attempt_id == claim.attempt.attempt_id
        assert (
            receipt.attempt_state
            is AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        )
        assert receipt.terminal_kind is AgenticSpecialistTerminalKind.STARTED_OUTCOME_UNKNOWN
        assert receipt.target_io_state is AgenticSpecialistTargetIOState.UNKNOWN
        assert receipt.succeeded is None
        assert receipt.backend_terminal_proven is False
        assert receipt.worker_result_digest is None
        assert receipt.backend_terminal_proof_digest is None
        assert receipt.backend_finished_at is None
        assert receipt.automatic_redispatch_authorized is False
        assert backend.invocation_count == 1
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        with pytest.raises(SpecialistGatewayDeploymentV2Error):
            _ = deployment.invocation_count

    asyncio.run(scenario())


def test_dispatch_marker_commit_success_then_return_failure_stays_unreceipted_unknown(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-marker-return-fault"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("marker-return-fault")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        backend = runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[
            deployment
        ].owner.backend
        original_write_transaction = durable_module._write_transaction

        @contextmanager
        def commit_then_fail(
            database: object,
        ) -> object:
            with original_write_transaction(database) as connection:
                yield connection
            raise RuntimeError("injected post-commit marker return failure")

        with monkeypatch.context() as scoped:
            scoped.setattr(durable_module, "_write_transaction", commit_then_fail)
            with pytest.raises(
                RuntimeError,
                match="post-commit marker return failure",
            ):
                await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
                    claim,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )

        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert len(recovery.unknown_job_attempts) == 1
        assert recovery.unknown_job_attempts[0].attempt_id == claim.attempt.attempt_id
        assert (
            recovery.unknown_job_attempts[0].state
            is AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        )
        assert recovery.terminal_receipts == ()
        assert recovery.automatic_redispatch_authorized is False
        assert backend.invocation_count == 0
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert deployment not in runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION

    asyncio.run(scenario())


def test_backend_cancellation_after_dispatch_marker_preserves_unknown_terminal_receipt(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(backend_module, "datetime", _CancelledFixtureDatetime)
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-terminal-cancelled"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("terminal-cancelled")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        backend = runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[
            deployment
        ].owner.backend

        with pytest.raises(asyncio.CancelledError):
            await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
                claim,
                graph_resolver=fixture.harness.resolver,
                graph_head=fixture.harness.graph_head,
            )

        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert recovery.unknown_job_attempts == ()
        assert len(recovery.terminal_receipts) == 1
        receipt = recovery.terminal_receipts[0]
        assert receipt.attempt_id == claim.attempt.attempt_id
        assert receipt.terminal_kind is AgenticSpecialistTerminalKind.STARTED_OUTCOME_UNKNOWN
        assert receipt.target_io_state is AgenticSpecialistTargetIOState.UNKNOWN
        assert receipt.backend_terminal_proven is False
        assert receipt.automatic_redispatch_authorized is False
        assert backend.invocation_count == 1
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        assert not (
            fixture.harness.store._AgenticCoordinationStore__active_sql_specialist_v2_dispatch_operations
        )
        assert not (
            fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_claims
        )
        assert not (
            fixture.harness.store._AgenticCoordinationStore__issued_sql_specialist_v2_job_attempt_owner_tasks
        )
        deployment_state = gateway_module._DEPLOYMENT_REGISTRY_IMPLEMENTATION[deployment]
        assert deployment_state.state == "retired"
        assert deployment_state.backend_attempted is True
        for attribute in (
            "active_backend_task",
            "runtime_identity_token",
            "store_identity_token",
            "owner_task",
            "owner_token",
            "lease_identity_token",
        ):
            assert getattr(deployment_state, attribute) is None
        assert deployment not in runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION
        with pytest.raises(SpecialistGatewayDeploymentV2Error):
            _ = deployment.invocation_count

    asyncio.run(scenario())


def test_verified_completion_receipt_insert_failure_stays_unreceipted_unknown(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(backend_module, "datetime", _FixtureDatetime)
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-terminal-insert-fault"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("terminal-insert-fault")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        backend = runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[
            deployment
        ].owner.backend
        store = fixture.harness.store
        store_id = store.store_id
        captured_receipts: list[AgenticSpecialistTerminalReceipt] = []

        def fail_terminal_insert(
            _connection: sqlite3.Connection,
            receipt: AgenticSpecialistTerminalReceipt,
        ) -> None:
            captured_receipts.append(receipt)
            raise sqlite3.OperationalError("injected terminal receipt insert failure")

        with monkeypatch.context() as scoped:
            scoped.setattr(
                durable_module,
                "_insert_specialist_terminal_receipt",
                fail_terminal_insert,
            )
            with pytest.raises(
                AgenticCoordinationError,
                match="terminal-receipt insertion failed closed",
            ):
                await store.dispatch_sql_specialist_v2_job_attempt_once(
                    claim,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )

        assert len(captured_receipts) == 1
        captured_receipt = captured_receipts[0]
        with pytest.raises(
            AgenticCoordinationError,
            match="lacks exact proof provenance",
        ):
            store._record_specialist_terminal_receipt(
                captured_receipt,
                authority=store._authority,
            )
        with pytest.raises(
            AgenticCoordinationError,
            match="lacks Store authority",
        ):
            store._record_specialist_terminal_receipt(
                captured_receipt,
                authority=store._authority,
                proven_terminal_authority=object(),
            )

        recovery = store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert len(recovery.unknown_job_attempts) == 1
        assert recovery.unknown_job_attempts[0].attempt_id == claim.attempt.attempt_id
        assert recovery.terminal_receipts == ()
        assert recovery.automatic_redispatch_authorized is False
        assert backend.invocation_count == 1
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        with pytest.raises(SpecialistGatewayDeploymentV2Error):
            _ = deployment.invocation_count

        durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(store)
        reopened = AgenticCoordinationStore(
            store.path,
            binding=fixture.harness.binding,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
            specialist_graph_store=fixture.harness.graph_store,
            specialist_capability_ledger=fixture.harness.specialist_ledger,
            specialist_approval_keys=(fixture.harness.approval_key,),
            specialist_approval_clock=fixture.harness.approval_clock,
            specialist_runtime_generation=(AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2),
            allow_create=False,
            expected_store_id=store_id,
            clock=lambda: NOW + timedelta(seconds=20),
        )
        try:
            reopened_recovery = reopened.specialist_job_recovery_snapshot()
            assert reopened_recovery.claimed_job_attempts == ()
            assert len(reopened_recovery.unknown_job_attempts) == 1
            assert (
                reopened_recovery.unknown_job_attempts[0].attempt_id
                == claim.attempt.attempt_id
            )
            assert reopened_recovery.terminal_receipts == ()
            assert reopened_recovery.automatic_redispatch_authorized is False
        finally:
            reopened.close()

    asyncio.run(scenario())


def test_store_close_is_fenced_while_backend_dispatch_is_active(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    entered_backend = threading.Event()
    release_backend = threading.Event()

    class BlockingFixtureDatetime(metaclass=_FixtureDatetimeMeta):
        @classmethod
        def now(cls, tz: object = None) -> datetime:
            entered_backend.set()
            if not release_backend.wait(timeout=10):
                raise AssertionError("backend test clock was not released")
            return NOW + timedelta(seconds=10)

    async def scenario() -> None:
        monkeypatch.setattr(backend_module, "datetime", BlockingFixtureDatetime)
        fixture = _specialist_fixture_v2(
            sql_harness_factory("sql-v2-live-attempt-active-close"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment("active-close")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        store = fixture.harness.store
        close_failures: list[BaseException] = []

        def close_while_active() -> None:
            if not entered_backend.wait(timeout=10):
                close_failures.append(AssertionError("backend did not start"))
                release_backend.set()
                return
            try:
                durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(store)
            except BaseException as exc:
                close_failures.append(exc)
            finally:
                release_backend.set()

        close_thread = threading.Thread(target=close_while_active)
        close_thread.start()
        receipt = await store.dispatch_sql_specialist_v2_job_attempt_once(
            claim,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        close_thread.join(timeout=10)

        assert not close_thread.is_alive()
        assert len(close_failures) == 1
        assert isinstance(close_failures[0], AgenticCoordinationError)
        assert "active SQL specialist v2 Permit dispatch" in str(close_failures[0])
        assert receipt.terminal_kind is AgenticSpecialistTerminalKind.FAILED_BEFORE_TARGET_IO
        assert store.specialist_job_recovery_snapshot().terminal_receipts == (receipt,)
        durable_module._SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(store)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("owner", "method_name"),
    (
        (AgenticCoordinationStore, "_dispatch_sql_specialist_v2_job_attempt_once_active"),
        (AgenticCoordinationStore, "_mark_specialist_job_attempt_dispatched"),
        (AgenticCoordinationStore, "_build_sql_specialist_v2_zero_io_terminal_receipt"),
        (AgenticCoordinationStore, "_record_specialist_terminal_receipt"),
        (VerifiedSpecialistGatewayDeploymentV2, "_execute_job_attempt_claim"),
        (gateway_module._VerifiedSpecialistGatewayCompletionV2, "__init__"),
        (
            gateway_module._VerifiedSpecialistGatewayCompletionV2,
            "_consume_for_terminal_receipt",
        ),
    ),
)
def test_execution_method_substitution_fails_before_claim_consumption(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
    owner: type[object],
    method_name: str,
) -> None:
    async def scenario() -> None:
        monkeypatch.setattr(backend_module, "datetime", _FixtureDatetime)
        fixture = _specialist_fixture_v2(
            sql_harness_factory(f"sql-v2-live-attempt-pin-{method_name}"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment(f"pin-{method_name}")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        calls: list[str] = []
        original = getattr(owner, method_name)

        def wrapper(*args: object, **kwargs: object) -> object:
            calls.append(method_name)
            return original(*args, **kwargs)

        with monkeypatch.context() as scoped:
            scoped.setattr(owner, method_name, wrapper)
            with pytest.raises(
                AgenticCoordinationError,
                match="Store or capsule implementation changed",
            ):
                await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
                    claim,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )

        assert calls == []
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__consumed is False
        assert deployment.invocation_count == 0
        receipt = await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
            claim,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        assert receipt.terminal_kind is AgenticSpecialistTerminalKind.FAILED_BEFORE_TARGET_IO

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("owner", "method_name"),
    (
        (backend_module.StructuredFakeSpecialistBackendV2, "run"),
        (backend_module.SpecialistBackendOutputVerifierV2, "verify_output"),
        (backend_module.SignedSpecialistBackendResultV2, "result_digest"),
    ),
)
def test_backend_or_verifier_substitution_abandons_before_dispatch_marker(
    sql_harness_factory: SQLHarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
    owner: type[object],
    method_name: str,
) -> None:
    async def scenario() -> None:
        fixture = _specialist_fixture_v2(
            sql_harness_factory(f"sql-v2-live-attempt-runtime-pin-{method_name}"),
        )
        started = await _started(fixture)
        deployment = _gateway_deployment(f"runtime-pin-{method_name}")
        claim = fixture.harness.store.mint_sql_specialist_v2_job_attempt_claim(
            started,
            gateway_deployment=deployment,
            graph_resolver=fixture.harness.resolver,
            graph_head=fixture.harness.graph_head,
        )
        backend = runtime_owner_module._RUNTIME_OWNER_REGISTRY_IMPLEMENTATION[
            deployment
        ].owner.backend
        calls: list[str] = []
        original = getattr(owner, method_name)

        def wrapper(*args: object, **kwargs: object) -> object:
            calls.append(method_name)
            return original(*args, **kwargs)

        with monkeypatch.context() as scoped:
            scoped.setattr(owner, method_name, wrapper)
            with pytest.raises(
                SpecialistGatewayDeploymentV2Error,
                match="implementation or exact runtime changed",
            ):
                await fixture.harness.store.dispatch_sql_specialist_v2_job_attempt_once(
                    claim,
                    graph_resolver=fixture.harness.resolver,
                    graph_head=fixture.harness.graph_head,
                )

        assert calls == []
        assert backend.invocation_count == 0
        assert claim._VerifiedSQLSpecialistJobAttemptClaimV2__retired is True
        recovery = fixture.harness.store.specialist_job_recovery_snapshot()
        assert recovery.claimed_job_attempts == ()
        assert recovery.unknown_job_attempts == ()
        assert len(recovery.terminal_receipts) == 1
        assert (
            recovery.terminal_receipts[0].terminal_kind
            is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
        )

    asyncio.run(scenario())
