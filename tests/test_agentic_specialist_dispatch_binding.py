from __future__ import annotations

import asyncio
import copy
import gc
import pickle
import socket
import subprocess
import sys
import weakref
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from threading import Event, Thread
from typing import Any, cast

import httpx
import pytest
from pydantic import ValidationError

import pajin.agentic.durable as durable_module
import pajin.agentic.specialist_dispatch as specialist_dispatch_module
from pajin.agentic.durable import (
    AgenticCoordinationError,
    AgenticSpecialistCapabilityGrantConsumptionReceipt,
    AgenticSpecialistDispatchPlanEntry,
    AgenticSpecialistExecutionEntry,
    VerifiedPlannedSpecialistDispatchStarted,
    _AgenticSpecialistDispatchRuntimeCapsule,
)
from pajin.agentic.models import PentestSpecialization
from pajin.agentic.specialist_dispatch import (
    AgenticSpecialistDispatchBinding,
    AgenticSpecialistDispatchBindingError,
    AgenticSpecialistDispatchBindingRegistry,
    AgenticSpecialistDispatchBindingState,
)
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.gateway import ToolGateway
from tests.test_agentic_specialist_dispatch_plan import (
    GovernedDurableHarness,
    HarnessFactory,
    SpecialistPlanFixture,
    _bind_runtime,
    _graph_args,
    _make_harness,
    _plan,
    _signed_fixture,
    _specialist_fixture,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


def _audit_binding() -> AgenticSpecialistDispatchBinding:
    return AgenticSpecialistDispatchBinding(
        storeId="agentic-store:0123456789abcdef0123456789abcdef",
        coordinationBindingId=f"agentic-binding_{SHA_A}",
        coordinationBindingDigest=SHA_A,
        controlPlaneRunId="run:agentic:c3c",
        deploymentDigest=SHA_B,
        campaignId="campaign-c3c",
        campaignManifestDigest=SHA_C,
        planId=f"agentic-specialist-plan_{SHA_D}",
        planDigest=SHA_D,
        planStateDigest=SHA_E,
        reservationId=f"agentic-specialist-reservation_{SHA_F}",
        reservationDigest=SHA_F,
        reservationStateDigest=SHA_A,
        reservationSourceStateDigest=SHA_B,
        commandId=f"agent-command_{SHA_B}",
        commandDigest=SHA_B,
        preparationId=f"agentic-specialist-preparation_{SHA_C}",
        preparationDigest=SHA_C,
        preparedActionDigest=SHA_D,
        profileRegistryDigest=SHA_E,
        profileId="profile:agentic:c3c",
        profileVersion="1.0.0",
        profileDigest=SHA_F,
        executorCatalogDigest=SHA_A,
        executorId="executor:agentic:c3c",
        executorVersion="1.0.0",
        executorDigest=SHA_B,
        activationSetDigest=SHA_C,
        releaseId="release:agentic:c3c",
        releaseDigest=SHA_D,
        capabilityId="capability:agentic:c3c",
        capabilityVersion="1.0.0",
        capabilityDefinitionDigest=SHA_E,
        capabilityDigest=SHA_F,
        toolId="tool:agentic:c3c",
        toolVersion="1.0.0",
        toolDigest=SHA_A,
        requestId="request:agentic:c3c",
        requestDigest=SHA_B,
        capabilityGrantId="grant:agentic:c3c",
        capabilityGrantDigest=SHA_C,
        grantConsumptionReceiptId=f"agentic-specialist-grant-consumption_{SHA_D}",
        grantConsumptionReceiptDigest=SHA_D,
        actionPermitId=f"action-permit_{SHA_E}",
        actionPermitDigest=SHA_E,
        approvalId="action-approval:agentic:c3c",
        approvalDigest=SHA_F,
        approvalConsumptionReceiptId=f"action-approval-receipt_{SHA_A}",
        approvalConsumptionReceiptDigest=SHA_A,
        dispatchId=f"action-dispatch_{SHA_B}",
        targetAgentId="agent:agentic:c3c",
        taskId="task:agentic:c3c",
        targetId="target:agentic:c3c",
        targetDigest=SHA_C,
        specialization=PentestSpecialization.XSS,
    )


def test_binding_model_is_strict_content_addressed_and_authority_free() -> None:
    binding = _audit_binding()
    wire = binding.model_dump(mode="json", by_alias=True)

    assert binding.binding_id == f"agentic-specialist-dispatch-binding_{binding.binding_digest}"
    assert AgenticSpecialistDispatchBinding.model_validate(wire) == binding
    for marker in (
        "automaticRedispatchAuthorized",
        "approvalAuthority",
        "permitAuthority",
        "grantAuthority",
        "capabilityAuthority",
        "gatewayAuthority",
        "workerAuthority",
        "executionAuthority",
        "evidenceAuthority",
        "independentValidationPerformed",
        "findingAuthority",
        "graphAuthority",
        "reportAuthority",
        "sarifAuthority",
        "pocAuthority",
        "callerAuthoredRoutesAllowed",
        "callerAuthoredPayloadsAllowed",
        "callerAuthoredPoliciesAllowed",
        "callerAuthoredTransportAllowed",
        "serializedBearerAuthority",
        "targetIoPerformed",
    ):
        assert wire[marker] is False

    changed = dict(wire)
    changed["requestDigest"] = SHA_D
    with pytest.raises(ValidationError, match="Binding Digest differs"):
        AgenticSpecialistDispatchBinding.model_validate(changed)


def test_coordination_reload_rejects_foreign_type_before_property_access() -> None:
    class Trap:
        calls = 0

        @property
        def binding(self) -> object:
            self.calls += 1
            raise AssertionError("foreign binding property must not run")

    foreign = Trap()
    with pytest.raises(
        AgenticSpecialistDispatchBindingError,
        match="failed strict reload",
    ):
        specialist_dispatch_module._strict_coordination_binding(cast(Any, foreign))
    assert foreign.calls == 0


@pytest.fixture
def harness_factory(tmp_path: Path) -> Iterator[HarnessFactory]:
    if sys.platform != "linux":
        pytest.skip("authoritative durable coordination requires Linux /proc descriptors")
    harnesses: list[GovernedDurableHarness] = []

    def factory(
        name: str,
        *,
        approval_clock: Any = None,
        coordination_clock: Any = None,
    ) -> GovernedDurableHarness:
        harness = _make_harness(
            tmp_path,
            name,
            approval_clock=approval_clock,
            coordination_clock=coordination_clock,
        )
        harnesses.append(harness)
        return harness

    yield cast(HarnessFactory, factory)
    for harness in harnesses:
        harness.store.close()
        harness.resolver.close()


async def _dispatch_started(
    fixture: SpecialistPlanFixture,
    signed_approval: object,
) -> VerifiedPlannedSpecialistDispatchStarted:
    plan = _plan(fixture)
    runtime = _bind_runtime(fixture, plan, cast(Any, signed_approval))
    dispatched = await fixture.harness.store.dispatch_specialist_permit_once(
        plan,
        runtime,
        **cast(Any, _graph_args(fixture.harness)),
    )
    assert dispatched.dispatched is True
    assert type(dispatched.result) is VerifiedPlannedSpecialistDispatchStarted
    return dispatched.result


def test_binding_is_content_addressed_complete_and_authority_free(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-binding"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-binding")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        binding = handle.binding

        assert registry.state(binding.binding_id) is AgenticSpecialistDispatchBindingState.AVAILABLE
        assert binding.binding_id == f"agentic-specialist-dispatch-binding_{binding.binding_digest}"
        assert binding.store_id == fixture.harness.store.store_id
        assert binding.coordination_binding_id == fixture.harness.binding.binding_id
        assert binding.coordination_binding_digest == fixture.harness.binding.binding_digest
        assert binding.deployment_digest == fixture.harness.binding.deployment_digest
        assert binding.plan_id == started.plan.plan_id
        assert binding.plan_digest == started.plan.plan_digest
        assert binding.plan_state_digest == started.plan.state_digest
        assert binding.reservation_id == started.execution.reservation_id
        assert binding.reservation_digest == started.execution.reservation_digest
        assert binding.reservation_state_digest == started.execution.state_digest
        assert binding.reservation_source_state_digest == started.plan.reservation_state_digest
        assert binding.command_id == started.execution.command_id
        assert binding.command_digest == started.execution.command_digest
        assert binding.preparation_id == fixture.preparation.preparation_id
        assert binding.preparation_digest == fixture.preparation.preparation_digest
        assert binding.profile_digest == fixture.preparation.profile.profile_digest
        assert binding.executor_digest == fixture.preparation.executor_digest
        assert binding.capability_id == fixture.prepared_action.capability.capability_id
        assert binding.capability_digest == fixture.prepared_action.capability.capability_digest
        assert binding.tool_id == fixture.prepared_action.request.tool_id
        assert binding.request_id == fixture.prepared_action.request.request_id
        assert binding.request_digest == fixture.prepared_action.request_digest
        assert binding.capability_grant_id == fixture.grant.grant_id
        assert binding.grant_consumption_receipt_id == started.grant_consumption_receipt.receipt_id
        assert binding.action_permit_id == started.permit.permit_id
        assert binding.approval_consumption_receipt_id == started.approval_receipt.receipt_id
        assert binding.target_agent_id == fixture.preparation.target_agent_id
        assert binding.task_id == fixture.preparation.task_id

        wire = binding.model_dump(mode="json", by_alias=True)
        assert AgenticSpecialistDispatchBinding.model_validate(wire) == binding
        for marker in (
            "automaticRedispatchAuthorized",
            "approvalAuthority",
            "permitAuthority",
            "grantAuthority",
            "capabilityAuthority",
            "gatewayAuthority",
            "workerAuthority",
            "executionAuthority",
            "evidenceAuthority",
            "independentValidationPerformed",
            "findingAuthority",
            "graphAuthority",
            "reportAuthority",
            "sarifAuthority",
            "pocAuthority",
            "callerAuthoredRoutesAllowed",
            "callerAuthoredPayloadsAllowed",
            "callerAuthoredPoliciesAllowed",
            "callerAuthoredTransportAllowed",
            "serializedBearerAuthority",
            "targetIoPerformed",
        ):
            assert wire[marker] is False

    asyncio.run(scenario())


def test_registry_enforces_exact_task_one_use_and_tombstone(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-one-use"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-one-use")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        raw = handle.binding

        async def foreign_consumer() -> None:
            with pytest.raises(
                AgenticSpecialistDispatchBindingError,
                match="absent, foreign, or consumed",
            ):
                registry.consume(handle)

        await asyncio.create_task(foreign_consumer())
        assert registry.state(raw.binding_id) is AgenticSpecialistDispatchBindingState.AVAILABLE

        consumed = handle.consume()
        assert consumed is handle
        assert registry.state(raw.binding_id) is AgenticSpecialistDispatchBindingState.CONSUMED
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="absent, foreign, or consumed",
        ):
            registry.consume(handle)

        handle.retire()
        assert registry.state(raw.binding_id) is AgenticSpecialistDispatchBindingState.RETIRED
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="absent, foreign, or consumed",
        ):
            registry.retire(handle)
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="absent, foreign, or consumed",
        ):
            registry.describe(handle)

    asyncio.run(scenario())


def test_raw_serialization_is_not_bearer_and_local_authority_is_untransferable(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-non-bearer"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-non-bearer")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        binding = handle.binding
        reloaded = AgenticSpecialistDispatchBinding.model_validate_json(
            binding.model_dump_json(by_alias=True)
        )

        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="absent, foreign, or consumed",
        ):
            registry.consume(cast(Any, reloaded))
        assert registry.state(binding.binding_id) is AgenticSpecialistDispatchBindingState.AVAILABLE

        for authority in (handle, registry):
            with pytest.raises(TypeError, match="cannot be copied"):
                copy.copy(authority)
            with pytest.raises(TypeError, match="cannot be copied"):
                copy.deepcopy(authority)
            with pytest.raises(TypeError, match="cannot be serialized"):
                pickle.dumps(authority)

        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="foreign or consumed",
        ):
            registry.bind(started)

    asyncio.run(scenario())


def test_audit_reconstruction_cannot_replay_store_issued_started_authority(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-replay"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-replay")
        started = await _dispatch_started(fixture, signed)
        forged = VerifiedPlannedSpecialistDispatchStarted(
            plan=AgenticSpecialistDispatchPlanEntry.model_validate(
                started.plan.model_dump(mode="json", by_alias=True)
            ),
            execution=AgenticSpecialistExecutionEntry.model_validate(
                started.execution.model_dump(mode="json", by_alias=True)
            ),
            permit=ActionPermit.model_validate(
                started.permit.model_dump(mode="json", by_alias=True)
            ),
            receipt=ActionApprovalConsumptionReceipt.model_validate(
                started.approval_receipt.model_dump(mode="json", by_alias=True)
            ),
            grant_receipt=(
                AgenticSpecialistCapabilityGrantConsumptionReceipt.model_validate(
                    started.grant_consumption_receipt.model_dump(
                        mode="json",
                        by_alias=True,
                    )
                )
            ),
        )
        assert forged.plan == started.plan
        assert forged.execution == started.execution

        forged_registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="foreign or consumed",
        ):
            forged_registry.bind(forged)

        genuine_registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = genuine_registry.bind(started)
        assert handle.binding.plan_id == started.plan.plan_id

        second_registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="foreign or consumed",
        ):
            second_registry.bind(forged)
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="foreign or consumed",
        ):
            second_registry.bind(started)

    asyncio.run(scenario())


def test_started_authority_is_bound_to_the_callback_asyncio_task(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-task"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-task")
        started = await _dispatch_started(fixture, signed)

        async def foreign_task() -> None:
            registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
            with pytest.raises(
                AgenticSpecialistDispatchBindingError,
                match="foreign or consumed",
            ):
                registry.bind(started)

        await asyncio.create_task(foreign_task())
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        assert registry.bind(started).binding.plan_id == started.plan.plan_id

    asyncio.run(scenario())


def test_finished_callback_task_retires_untransferred_store_capsule(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-store-owner"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-store-owner")

        async def owner() -> tuple[
            VerifiedPlannedSpecialistDispatchStarted,
            weakref.ReferenceType[_AgenticSpecialistDispatchRuntimeCapsule],
        ]:
            started = await _dispatch_started(fixture, signed)
            issued = cast(
                dict[str, Any],
                cast(
                    Any,
                    fixture.harness.store,
                )._AgenticCoordinationStore__issued_specialist_dispatch_started,
            )
            capsule = cast(
                _AgenticSpecialistDispatchRuntimeCapsule,
                issued[started.plan.plan_id][1],
            )
            return started, weakref.ref(capsule)

        started, capsule_ref = await asyncio.create_task(owner())
        await asyncio.sleep(0)
        gc.collect()
        issued = cast(
            dict[str, Any],
            cast(
                Any,
                fixture.harness.store,
            )._AgenticCoordinationStore__issued_specialist_dispatch_started,
        )
        assert started.plan.plan_id not in issued
        assert capsule_ref() is None
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="foreign or consumed",
        ):
            registry.bind(started)

    asyncio.run(scenario())


def test_revoked_parent_grant_blocks_started_authority_transfer(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-parent-revoked"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-parent-revoked")
        started = await _dispatch_started(fixture, signed)
        assert fixture.ledger.revoke(
            fixture.root_grant.grant_id,
            "test parent revocation",
            cascade=False,
        ) == [fixture.root_grant.grant_id]
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="foreign or consumed",
        ):
            registry.bind(started)

    asyncio.run(scenario())


def test_revoked_parent_grant_blocks_available_binding_claim(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-claim-revoked"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-claim-revoked")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        assert fixture.ledger.revoke(
            fixture.root_grant.grant_id,
            "test claim-time parent revocation",
            cascade=False,
        ) == [fixture.root_grant.grant_id]
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="runtime authority changed before claim",
        ):
            handle.consume()
        assert registry.state(handle.binding_id) is AgenticSpecialistDispatchBindingState.RETIRED

    asyncio.run(scenario())


def test_grant_revocation_cannot_interleave_inside_binding_claim(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-claim-race"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-claim-race")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        observed = Event()
        revoke_started = Event()
        revoke_done = Event()
        original = durable_module._specialist_capability_lineage_observation

        def blocking_observation(*args: Any, **kwargs: Any) -> Any:
            result = original(*args, **kwargs)
            observed.set()
            assert revoke_started.wait(timeout=5)
            assert revoke_done.is_set() is False
            return result

        monkeypatch.setattr(
            durable_module,
            "_specialist_capability_lineage_observation",
            blocking_observation,
        )

        def revoke_parent() -> None:
            assert observed.wait(timeout=5)
            revoke_started.set()
            fixture.ledger.revoke(
                fixture.root_grant.grant_id,
                "test concurrent parent revocation",
                cascade=False,
            )
            revoke_done.set()

        revoker = Thread(target=revoke_parent)
        revoker.start()
        assert handle.consume() is handle
        revoker.join(timeout=5)
        assert revoke_done.is_set()
        handle.retire()

    asyncio.run(scenario())


def test_registry_rejects_coordination_database_object_replacement(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        class ForeignDatabase:
            close_calls = 0

            def close(self) -> None:
                self.close_calls += 1

        unsigned = _specialist_fixture(harness_factory("specialist-c3c-database"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-database")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        original_database = fixture.harness.store._database
        foreign_database = ForeignDatabase()
        try:
            cast(Any, fixture.harness.store)._database = foreign_database
            with pytest.raises(
                AgenticCoordinationError,
                match="database identity changed before close",
            ):
                fixture.harness.store.close()
            assert foreign_database.close_calls == 0
            with pytest.raises(
                AgenticSpecialistDispatchBindingError,
                match="Store identity changed",
            ):
                registry.bind(started)
        finally:
            cast(Any, fixture.harness.store)._database = original_database
        assert registry.bind(started).binding.plan_id == started.plan.plan_id

    asyncio.run(scenario())


def test_registry_rejects_entry_binding_identity_substitution(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-entry"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-entry")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        binding = handle.binding
        values = binding.model_dump(mode="json", by_alias=True)
        del values["bindingId"]
        del values["bindingDigest"]
        values["requestDigest"] = SHA_A if binding.request_digest != SHA_A else SHA_B
        substituted = AgenticSpecialistDispatchBinding.model_validate(values)
        available = cast(
            dict[str, Any],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
        )
        available[binding.binding_id] = replace(
            available[binding.binding_id],
            binding=substituted,
        )
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="absent, foreign, or consumed",
        ):
            handle.consume()

    asyncio.run(scenario())


def test_registry_rejects_foreign_entry_before_property_access(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        class TrapEntry:
            calls = 0

            @property
            def binding(self) -> object:
                self.calls += 1
                raise AssertionError("foreign entry binding must not run")

        unsigned = _specialist_fixture(harness_factory("specialist-c3c-entry-type"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-entry-type")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        available = cast(
            dict[str, Any],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
        )
        trap = TrapEntry()
        original_entry = available[handle.binding_id]
        try:
            available[handle.binding_id] = trap
            with pytest.raises(
                AgenticSpecialistDispatchBindingError,
                match="absent, foreign, or consumed",
            ):
                handle.consume()
        finally:
            available[handle.binding_id] = original_entry
        assert trap.calls == 0

    asyncio.run(scenario())


def test_registry_rejects_entry_runtime_capsule_substitution(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-capsule"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-capsule")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        binding_id = handle.binding_id
        available = cast(
            dict[str, Any],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
        )
        entry = available[binding_id]
        original = cast(_AgenticSpecialistDispatchRuntimeCapsule, entry.runtime)
        substituted = _AgenticSpecialistDispatchRuntimeCapsule(
            campaign=original.campaign,
            preparation=original.preparation,
            capability_ledger=original.capability_ledger,
            capability_grant=original.capability_grant,
            activation=original.activation,
            prepared_action=original.prepared_action,
            approval_envelope=original.approval_envelope,
        )
        assert substituted is not original
        available[binding_id] = replace(entry, runtime=substituted)
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="absent, foreign, or consumed",
        ):
            handle.consume()

    asyncio.run(scenario())


def test_owner_task_completion_retires_stranded_capsule(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        async def owner() -> tuple[
            AgenticSpecialistDispatchBindingRegistry,
            Any,
            str,
            weakref.ReferenceType[_AgenticSpecialistDispatchRuntimeCapsule],
        ]:
            unsigned = _specialist_fixture(harness_factory("specialist-c3c-owner"))
            fixture, signed = _signed_fixture(unsigned, "specialist-c3c-owner")
            started = await _dispatch_started(fixture, signed)
            registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
            handle = registry.bind(started)
            available = cast(
                dict[str, Any],
                cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
            )
            capsule = cast(
                _AgenticSpecialistDispatchRuntimeCapsule,
                available[handle.binding_id].runtime,
            )
            return registry, handle, handle.binding_id, weakref.ref(capsule)

        registry, handle, binding_id, capsule_ref = await asyncio.create_task(owner())
        await asyncio.sleep(0)
        gc.collect()
        assert registry.state(binding_id) is AgenticSpecialistDispatchBindingState.RETIRED
        assert capsule_ref() is None
        with pytest.raises(
            AgenticSpecialistDispatchBindingError,
            match="absent, foreign, or consumed",
        ):
            registry.describe(handle)

    asyncio.run(scenario())


def test_successful_retire_releases_capsule_and_long_lived_task_callbacks(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-retire-release"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-retire-release")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        available = cast(
            dict[str, Any],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
        )
        capsule_ref = weakref.ref(available[handle.binding_id].runtime)
        owner_task = asyncio.current_task()
        assert owner_task is not None
        store_owner_tasks = cast(
            set[asyncio.Task[object]],
            cast(
                Any,
                fixture.harness.store,
            )._AgenticCoordinationStore__issued_specialist_dispatch_owner_tasks,
        )
        registry_owner_tasks = cast(
            set[asyncio.Task[object]],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__owner_tasks,
        )
        assert owner_task not in store_owner_tasks
        assert owner_task in registry_owner_tasks

        handle.consume()
        handle.retire()
        gc.collect()
        assert capsule_ref() is None
        assert owner_task not in registry_owner_tasks

    asyncio.run(scenario())


@pytest.mark.parametrize("consume_before_close", (False, True), ids=("available", "consumed"))
def test_store_close_retires_and_releases_transferred_registry_capsule(
    harness_factory: HarnessFactory,
    *,
    consume_before_close: bool,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-close-release"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-close-release")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        available = cast(
            dict[str, Any],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
        )
        capsule_ref = weakref.ref(available[handle.binding_id].runtime)
        if consume_before_close:
            handle.consume()

        fixture.harness.store.close()
        await asyncio.sleep(0)
        gc.collect()

        assert capsule_ref() is None
        assert registry.state(handle.binding_id) is AgenticSpecialistDispatchBindingState.RETIRED
        assert not cast(
            dict[str, Any],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
        )
        assert not cast(
            dict[str, Any],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__consumed,
        )
        assert not cast(
            set[asyncio.Task[object]],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__owner_tasks,
        )

    asyncio.run(scenario())


def test_store_close_waits_for_in_flight_registry_transition(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-close-race"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-close-race")
        started = await _dispatch_started(fixture, signed)
        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        available = cast(
            dict[str, Any],
            cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
        )
        capsule_ref = weakref.ref(available[handle.binding_id].runtime)
        entered = Event()
        close_started = Event()
        close_done = Event()
        original = specialist_dispatch_module._strict_dispatch_binding

        def blocking_strict(
            binding: AgenticSpecialistDispatchBinding,
        ) -> AgenticSpecialistDispatchBinding:
            entered.set()
            assert close_started.wait(timeout=5)
            assert close_done.is_set() is False
            return original(binding)

        monkeypatch.setattr(
            specialist_dispatch_module,
            "_strict_dispatch_binding",
            blocking_strict,
        )

        def close_store() -> None:
            assert entered.wait(timeout=5)
            close_started.set()
            fixture.harness.store.close()
            close_done.set()

        closer = Thread(target=close_store)
        closer.start()
        assert handle.consume() is handle
        closer.join(timeout=5)
        assert close_done.is_set()
        await asyncio.sleep(0)
        gc.collect()
        assert capsule_ref() is None
        assert registry.state(handle.binding_id) is AgenticSpecialistDispatchBindingState.RETIRED

    asyncio.run(scenario())


def test_store_close_and_owner_task_cancellation_zeroize_once(
    harness_factory: HarnessFactory,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-close-cancel"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-close-cancel")
        ready: asyncio.Future[
            tuple[
                AgenticSpecialistDispatchBindingRegistry,
                str,
                weakref.ReferenceType[_AgenticSpecialistDispatchRuntimeCapsule],
            ]
        ] = asyncio.get_running_loop().create_future()
        block = asyncio.Event()

        async def owner() -> None:
            started = await _dispatch_started(fixture, signed)
            registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
            handle = registry.bind(started)
            available = cast(
                dict[str, Any],
                cast(Any, registry)._AgenticSpecialistDispatchBindingRegistry__available,
            )
            capsule_ref = weakref.ref(available[handle.binding_id].runtime)
            handle.consume()
            ready.set_result((registry, handle.binding_id, capsule_ref))
            await block.wait()

        owner_task = asyncio.create_task(owner())
        registry, binding_id, capsule_ref = await ready
        close_errors: list[BaseException] = []

        def close_store() -> None:
            try:
                fixture.harness.store.close()
            except BaseException as exc:
                close_errors.append(exc)

        closer = Thread(target=close_store)
        closer.start()
        owner_task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await owner_task
        closer.join(timeout=5)
        assert not closer.is_alive()
        assert close_errors == []
        await asyncio.sleep(0)
        gc.collect()
        assert capsule_ref() is None
        assert registry.state(binding_id) is AgenticSpecialistDispatchBindingState.RETIRED

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "marker",
    (
        "automaticRedispatchAuthorized",
        "approvalAuthority",
        "permitAuthority",
        "grantAuthority",
        "capabilityAuthority",
        "gatewayAuthority",
        "workerAuthority",
        "executionAuthority",
        "evidenceAuthority",
        "independentValidationPerformed",
        "findingAuthority",
        "graphAuthority",
        "reportAuthority",
        "sarifAuthority",
        "pocAuthority",
        "callerAuthoredRoutesAllowed",
        "callerAuthoredPayloadsAllowed",
        "callerAuthoredPoliciesAllowed",
        "callerAuthoredTransportAllowed",
        "serializedBearerAuthority",
        "targetIoPerformed",
    ),
)
def test_binding_rejects_non_literal_false_authority_markers(
    marker: str,
) -> None:
    values = _audit_binding().model_dump(mode="json", by_alias=True)
    values.update({"bindingId": "", "bindingDigest": "", marker: 0})
    with pytest.raises(ValidationError):
        AgenticSpecialistDispatchBinding.model_validate(values)
    values[marker] = True
    with pytest.raises(ValidationError):
        AgenticSpecialistDispatchBinding.model_validate(values)


def test_binding_performs_zero_gateway_worker_network_or_target_io(
    harness_factory: HarnessFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        unsigned = _specialist_fixture(harness_factory("specialist-c3c-zero-io"))
        fixture, signed = _signed_fixture(unsigned, "specialist-c3c-zero-io")
        started = await _dispatch_started(fixture, signed)
        calls: list[str] = []

        async def async_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("async")

        def sync_tripwire(*_args: object, **_kwargs: object) -> None:
            calls.append("sync")

        monkeypatch.setattr(ToolGateway, "execute", async_tripwire)
        monkeypatch.setattr(SimulatedWorkerBackend, "run", async_tripwire)
        monkeypatch.setattr(socket, "create_connection", sync_tripwire)

        monkeypatch.setattr(socket, "getaddrinfo", sync_tripwire)
        monkeypatch.setattr(subprocess, "Popen", sync_tripwire)
        monkeypatch.setattr(httpx.Client, "send", sync_tripwire)
        monkeypatch.setattr(httpx.AsyncClient, "send", async_tripwire)

        registry = AgenticSpecialistDispatchBindingRegistry(store=fixture.harness.store)
        handle = registry.bind(started)
        handle.consume()
        handle.retire()

        assert calls == []

    asyncio.run(scenario())
