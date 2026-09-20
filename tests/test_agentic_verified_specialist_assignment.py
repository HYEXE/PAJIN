from __future__ import annotations

import copy
import pickle
import sys
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from typing import Any, cast

import pytest

from pajin.agentic.durable import AgenticCoordinationError, AgenticCoordinationStore
from pajin.agentic.models import AgentControlCommandKind, AgentEvent, AgentEventKind
from tests.test_agentic_durable import (
    NOW,
    DurableHarness,
    _admit_and_ack,
    _graph_args,
    _make_harness,
    _publish_cycle,
)


def _state_value(value: object) -> str:
    state = cast(Any, value).state
    return str(getattr(state, "value", state))


@pytest.fixture
def harness_factory(tmp_path: Path) -> Iterator[Callable[[str], DurableHarness]]:
    if sys.platform != "linux":
        pytest.skip("authoritative durable coordination requires Linux /proc descriptors")
    resolvers = []

    def factory(name: str) -> DurableHarness:
        harness = _make_harness(tmp_path, name)
        resolvers.append(harness.resolver)
        return harness

    yield factory
    for resolver in resolvers:
        resolver.close()


def _admitted_current_assignment(harness: DurableHarness):
    cycle = _publish_cycle(harness)
    spawn_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert spawn_claim is not None
    assert spawn_claim.command.command is AgentControlCommandKind.SPAWN
    _admit_and_ack(harness, spawn_claim)
    spawn_event = AgentEvent(
        campaignId=spawn_claim.command.campaign_id,
        sequence=1,
        agentId=spawn_claim.command.target_agent_id,
        commandId=spawn_claim.command.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="Spawn command durably admitted.",
    )
    current = harness.store.publish_event(cycle.head, spawn_event, **_graph_args(harness))
    assignment_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert assignment_claim is not None
    assert assignment_claim.command.command is AgentControlCommandKind.ASSIGN
    admission, acknowledgement = _admit_and_ack(harness, assignment_claim)
    return current.head, assignment_claim, admission, acknowledgement


def _verify(harness: DurableHarness, head: object, command_id: str):
    return harness.store.verified_admitted_specialist_assignment(
        head,
        command_id=command_id,
        **_graph_args(harness),
    )


def _reopen(harness: DurableHarness, *, seconds: int) -> AgenticCoordinationStore:
    return AgenticCoordinationStore(
        harness.store.path,
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        allow_create=False,
        expected_store_id=harness.store.store_id,
        clock=lambda: NOW + timedelta(seconds=seconds),
    )


def test_verified_admitted_specialist_assignment_binds_exact_current_live_assignment(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-verified")
    head, claim, admission, _acknowledgement = _admitted_current_assignment(harness)

    verified = _verify(harness, head, claim.command.command_id)
    candidate = next(
        item for item in harness.cycle.candidates if item.candidate_id == claim.command.candidate_id
    )
    decision = next(
        item for item in harness.cycle.decisions if item.candidate_id == candidate.candidate_id
    )
    specialist = harness.binding.exploit_group.specialist_for(
        claim.command.specialization,
        candidate.proposal.threat_class,
    )

    assert verified.command == claim.command
    assert verified.candidate == candidate
    assert verified.decision == decision
    assert verified.specialist == specialist
    assert verified.admission == admission
    assert verified.source_head_digest == head.checkpoint.checkpoint_digest
    assert verified.command.capability_granted is False
    assert verified.command.permit_granted is False
    assert verified.command.tool_execution_authorized is False
    assert verified.candidate.capability_granted is False
    assert verified.candidate.permit_granted is False
    assert verified.candidate.execution_authorized is False
    assert verified.admission.command_consumed is False
    assert verified.admission.task_completed is False
    assert verified.admission.execution_authorized is False

    with pytest.raises(AgenticCoordinationError, match="missing"):
        harness.store.specialist_execution_entry(
            command_id=claim.command.command_id,
            **_graph_args(harness),
        )


def test_raw_admission_and_audit_values_never_reserve_specialist_execution(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-raw-values")
    head, claim, admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)

    for raw in (
        admission,
        claim.command,
        verified.candidate,
        verified.decision,
        admission.model_copy(),
    ):
        with pytest.raises((AgenticCoordinationError, TypeError), match=r"verified|handle|store"):
            harness.store.reserve_specialist_execution(raw, **_graph_args(harness))
        with pytest.raises(AgenticCoordinationError, match="missing"):
            harness.store.specialist_execution_entry(
                command_id=claim.command.command_id,
                **_graph_args(harness),
            )


def test_store_issued_assignment_and_reservation_handles_cannot_be_copied_or_serialized(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-uncopyable-handles")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)

    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(verified)

    reserved = harness.store.reserve_specialist_execution(verified, **_graph_args(harness))
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(reserved)

    started = harness.store.begin_specialist_dispatch(reserved, **_graph_args(harness))
    for operation in (copy.copy, copy.deepcopy, pickle.dumps):
        with pytest.raises(TypeError, match=r"copied|serialized"):
            operation(started)


def test_specialist_verification_rejects_unadmitted_and_non_assignment_commands(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-unadmitted")
    cycle = _publish_cycle(harness)
    spawn = next(
        item for item in harness.cycle.commands if item.command is AgentControlCommandKind.SPAWN
    )
    assignment = next(
        item for item in harness.cycle.commands if item.command is AgentControlCommandKind.ASSIGN
    )

    with pytest.raises(AgenticCoordinationError, match=r"admission|admitted|acknowledg|transport"):
        _verify(harness, cycle.head, assignment.command_id)

    spawn_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert spawn_claim is not None and spawn_claim.command == spawn
    _admit_and_ack(harness, spawn_claim)
    with pytest.raises(AgenticCoordinationError, match="assignment"):
        _verify(harness, cycle.head, spawn.command_id)

    with pytest.raises(AgenticCoordinationError, match="missing"):
        harness.store.specialist_execution_entry(
            command_id=assignment.command_id,
            **_graph_args(harness),
        )


def test_receiver_admission_without_sender_acknowledgement_is_not_execution_authority(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-admitted-not-acknowledged")
    cycle = _publish_cycle(harness)
    spawn_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert spawn_claim is not None
    _admit_and_ack(harness, spawn_claim)
    current = harness.store.publish_event(
        cycle.head,
        AgentEvent(
            campaignId=spawn_claim.command.campaign_id,
            sequence=1,
            agentId=spawn_claim.command.target_agent_id,
            commandId=spawn_claim.command.command_id,
            event=AgentEventKind.ACKNOWLEDGED,
            summary="Spawn command durably admitted.",
        ),
        **_graph_args(harness),
    )
    assignment_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert assignment_claim is not None
    admission = harness.store.admit_delivery(assignment_claim, **_graph_args(harness))
    assert admission.receiver_durable_admission is True
    assert admission.execution_authorized is False

    with pytest.raises(AgenticCoordinationError, match=r"acknowledg|transport"):
        _verify(harness, current.head, assignment_claim.command.command_id)
    with pytest.raises(AgenticCoordinationError, match="missing"):
        harness.store.specialist_execution_entry(
            command_id=assignment_claim.command.command_id,
            **_graph_args(harness),
        )

    harness.store.acknowledge_delivery(
        assignment_claim,
        admission,
        **_graph_args(harness),
    )
    verified = _verify(harness, current.head, assignment_claim.command.command_id)
    assert verified.admission == admission


def test_verified_assignment_becomes_stale_before_reservation(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-stale-before-reserve")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)
    progress = AgentEvent(
        campaignId=claim.command.campaign_id,
        sequence=1,
        agentId=claim.command.target_agent_id,
        commandId=claim.command.command_id,
        event=AgentEventKind.PROGRESS,
        taskId=claim.command.task_id,
        candidateId=claim.command.candidate_id,
        summary="Assignment remains live but the durable head advances.",
    )
    advanced = harness.store.publish_event(head, progress, **_graph_args(harness))

    with pytest.raises(AgenticCoordinationError, match=r"stale|current"):
        harness.store.reserve_specialist_execution(verified, **_graph_args(harness))
    with pytest.raises(AgenticCoordinationError, match="missing"):
        harness.store.specialist_execution_entry(
            command_id=claim.command.command_id,
            **_graph_args(harness),
        )

    refreshed = _verify(harness, advanced.head, claim.command.command_id)
    assert refreshed.source_head_digest == advanced.head.checkpoint.checkpoint_digest


def test_terminal_assignment_cannot_be_verified_or_reserved(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-terminal")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    terminal = harness.store.publish_event(
        head,
        AgentEvent(
            campaignId=claim.command.campaign_id,
            sequence=1,
            agentId=claim.command.target_agent_id,
            commandId=claim.command.command_id,
            event=AgentEventKind.FINAL,
            taskId=claim.command.task_id,
            candidateId=claim.command.candidate_id,
            summary="The specialist assignment is terminal.",
        ),
        **_graph_args(harness),
    )

    with pytest.raises(AgenticCoordinationError, match=r"live|terminal|current"):
        _verify(harness, terminal.head, claim.command.command_id)
    with pytest.raises(AgenticCoordinationError, match="missing"):
        harness.store.specialist_execution_entry(
            command_id=claim.command.command_id,
            **_graph_args(harness),
        )


def test_specialist_execution_reservation_is_one_use_under_concurrency(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-concurrent-reserve")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)
    barrier = Barrier(2)

    def reserve(_: int):
        barrier.wait()
        try:
            return harness.store.reserve_specialist_execution(
                verified,
                **_graph_args(harness),
            )
        except AgenticCoordinationError as exc:
            return exc

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(reserve, range(2)))

    successes = tuple(item for item in results if not isinstance(item, Exception))
    failures = tuple(item for item in results if isinstance(item, AgenticCoordinationError))
    assert len(successes) == 1
    assert len(failures) == 1
    assert "reserved" in str(failures[0]).lower() or "one-use" in str(failures[0]).lower()
    reserved = successes[0]
    assert _state_value(reserved.entry) == "reserved"
    assert reserved.entry.automatic_redispatch_authorized is False
    assert reserved.entry.execution_authorized is False
    assert reserved.entry.finding_authority is False
    assert reserved.entry.graph_authority is False
    assert (
        harness.store.specialist_execution_entry(
            command_id=claim.command.command_id,
            **_graph_args(harness),
        )
        == reserved.entry
    )
    with pytest.raises(AgenticCoordinationError, match=r"reserved|one-use|redispatch"):
        harness.store.reserve_specialist_execution(verified, **_graph_args(harness))


def test_reserved_specialist_execution_survives_reopen_without_reissuing_authority(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-reserved-reopen")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)
    reserved = harness.store.reserve_specialist_execution(verified, **_graph_args(harness))
    reopened = _reopen(harness, seconds=30)

    audit_entry = reopened.specialist_execution_entry(
        command_id=claim.command.command_id,
        **_graph_args(harness),
    )
    assert audit_entry == reserved.entry
    assert _state_value(audit_entry) == "reserved"
    recovery = reopened.recovery_snapshot(**_graph_args(harness))
    assert recovery.reserved_specialist_executions == (reserved.entry,)
    assert recovery.unknown_specialist_executions == ()
    assert recovery.automatic_redispatch_authorized is False
    assert audit_entry.automatic_redispatch_authorized is False
    assert audit_entry.execution_authorized is False
    assert audit_entry.finding_authority is False
    assert audit_entry.graph_authority is False
    with pytest.raises(AgenticCoordinationError, match=r"foreign|consumed|store|handle"):
        reopened.begin_specialist_dispatch(reserved, **_graph_args(harness))
    with pytest.raises((AgenticCoordinationError, TypeError), match=r"verified|handle|authority"):
        reopened.begin_specialist_dispatch(audit_entry, **_graph_args(harness))

    reopened_head = reopened.current_head(**_graph_args(harness))
    refreshed = reopened.verified_admitted_specialist_assignment(
        reopened_head,
        command_id=claim.command.command_id,
        **_graph_args(harness),
    )
    with pytest.raises(AgenticCoordinationError, match=r"reserved|one-use|redispatch"):
        reopened.reserve_specialist_execution(refreshed, **_graph_args(harness))


def test_begin_specialist_dispatch_is_one_use_and_audit_entry_is_not_authority(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-begin-once")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)
    reserved = harness.store.reserve_specialist_execution(verified, **_graph_args(harness))

    started = harness.store.begin_specialist_dispatch(reserved, **_graph_args(harness))
    assert _state_value(started.entry) == "dispatch-started-outcome-unknown"
    assert started.entry.automatic_redispatch_authorized is False
    assert started.entry.execution_authorized is False
    assert started.entry.finding_authority is False
    assert started.entry.graph_authority is False
    audit_entry = harness.store.specialist_execution_entry(
        command_id=claim.command.command_id,
        **_graph_args(harness),
    )
    assert audit_entry == started.entry
    with pytest.raises(AgenticCoordinationError, match=r"redispatch|started|one-use"):
        harness.store.begin_specialist_dispatch(reserved, **_graph_args(harness))
    with pytest.raises(AgenticCoordinationError, match=r"redispatch|started|one-use"):
        harness.store.begin_specialist_dispatch(started, **_graph_args(harness))
    with pytest.raises((AgenticCoordinationError, TypeError), match=r"verified|handle|authority"):
        harness.store.begin_specialist_dispatch(audit_entry, **_graph_args(harness))
    with pytest.raises(AgenticCoordinationError, match=r"reserved|one-use|redispatch"):
        harness.store.reserve_specialist_execution(verified, **_graph_args(harness))


def test_specialist_preparation_requires_current_store_local_reservation(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-preparation")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)
    reserved = harness.store.reserve_specialist_execution(verified, **_graph_args(harness))

    prepared = harness.store.specialist_preparation_entry(
        reserved,
        **_graph_args(harness),
    )
    assert prepared == reserved.entry
    assert _state_value(prepared) == "reserved"
    assert prepared.execution_authorized is False
    assert prepared.finding_authority is False
    assert prepared.graph_authority is False

    with pytest.raises(
        (AgenticCoordinationError, TypeError), match=r"verified|reservation|authority"
    ):
        harness.store.specialist_preparation_entry(
            prepared,  # type: ignore[arg-type]
            **_graph_args(harness),
        )

    foreign = harness_factory("specialist-preparation-foreign")
    with pytest.raises(AgenticCoordinationError, match=r"foreign|store|consumed|authority"):
        foreign.store.specialist_preparation_entry(
            reserved,
            **_graph_args(foreign),
        )

    harness.store.begin_specialist_dispatch(reserved, **_graph_args(harness))
    with pytest.raises(AgenticCoordinationError, match=r"consumed|reserved|live"):
        harness.store.specialist_preparation_entry(
            reserved,
            **_graph_args(harness),
        )


def test_specialist_preparation_rejects_durable_head_drift_without_consuming_reservation(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-preparation-stale")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)
    reserved = harness.store.reserve_specialist_execution(verified, **_graph_args(harness))
    harness.store.publish_event(
        head,
        AgentEvent(
            campaignId=claim.command.campaign_id,
            sequence=1,
            agentId=claim.command.target_agent_id,
            commandId=claim.command.command_id,
            event=AgentEventKind.PROGRESS,
            taskId=claim.command.task_id,
            candidateId=claim.command.candidate_id,
            summary="The durable head advanced after specialist reservation.",
        ),
        **_graph_args(harness),
    )

    with pytest.raises(AgenticCoordinationError, match=r"stale|current"):
        harness.store.specialist_preparation_entry(
            reserved,
            **_graph_args(harness),
        )
    audit_entry = harness.store.specialist_execution_entry(
        command_id=claim.command.command_id,
        **_graph_args(harness),
    )
    assert _state_value(audit_entry) == "reserved"


def test_assignment_that_terminates_after_reservation_cannot_begin_dispatch(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-terminal-after-reserve")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)
    reserved = harness.store.reserve_specialist_execution(verified, **_graph_args(harness))
    harness.store.publish_event(
        head,
        AgentEvent(
            campaignId=claim.command.campaign_id,
            sequence=1,
            agentId=claim.command.target_agent_id,
            commandId=claim.command.command_id,
            event=AgentEventKind.FINAL,
            taskId=claim.command.task_id,
            candidateId=claim.command.candidate_id,
            summary="The specialist assignment terminated before dispatch.",
        ),
        **_graph_args(harness),
    )

    with pytest.raises(AgenticCoordinationError, match=r"live|terminal|current|stale"):
        harness.store.begin_specialist_dispatch(reserved, **_graph_args(harness))
    audit_entry = harness.store.specialist_execution_entry(
        command_id=claim.command.command_id,
        **_graph_args(harness),
    )
    assert _state_value(audit_entry) == "reserved"
    assert audit_entry.automatic_redispatch_authorized is False
    assert audit_entry.execution_authorized is False
    assert audit_entry.finding_authority is False
    assert audit_entry.graph_authority is False


def test_outcome_unknown_survives_reopen_and_never_redispatches(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("specialist-unknown-reopen")
    head, claim, _admission, _acknowledgement = _admitted_current_assignment(harness)
    verified = _verify(harness, head, claim.command.command_id)
    reserved = harness.store.reserve_specialist_execution(verified, **_graph_args(harness))
    started = harness.store.begin_specialist_dispatch(reserved, **_graph_args(harness))
    reopened = _reopen(harness, seconds=86_400)

    audit_entry = reopened.specialist_execution_entry(
        command_id=claim.command.command_id,
        **_graph_args(harness),
    )
    assert audit_entry == started.entry
    assert _state_value(audit_entry) == "dispatch-started-outcome-unknown"
    assert audit_entry.automatic_redispatch_authorized is False
    assert audit_entry.execution_authorized is False
    assert audit_entry.finding_authority is False
    assert audit_entry.graph_authority is False
    recovery = reopened.recovery_snapshot(**_graph_args(harness))
    assert recovery.reserved_specialist_executions == ()
    assert recovery.unknown_specialist_executions == (started.entry,)
    assert recovery.automatic_redispatch_authorized is False
    reopened_head = reopened.current_head(**_graph_args(harness))
    refreshed = reopened.verified_admitted_specialist_assignment(
        reopened_head,
        command_id=claim.command.command_id,
        **_graph_args(harness),
    )
    with pytest.raises(AgenticCoordinationError, match=r"redispatch|started|one-use"):
        reopened.reserve_specialist_execution(refreshed, **_graph_args(harness))
    with pytest.raises((AgenticCoordinationError, TypeError), match=r"verified|handle|authority"):
        reopened.begin_specialist_dispatch(audit_entry, **_graph_args(harness))
