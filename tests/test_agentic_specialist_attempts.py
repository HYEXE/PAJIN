from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest

from pajin.agentic import durable
from pajin.agentic.models import PentestSpecialization
from pajin.agentic.specialist_attempts import (
    AgenticSpecialistJobAttempt,
    AgenticSpecialistJobAttemptState,
    AgenticSpecialistTargetIOState,
    AgenticSpecialistTerminalKind,
    AgenticSpecialistTerminalReceipt,
    build_specialist_claim_verification,
    build_specialist_dispatch_verification,
)
from pajin.agentic.specialist_verifications import (
    AgenticSpecialistClaimVerification,
    AgenticSpecialistDispatchVerification,
)

NOW = datetime(2026, 9, 20, 4, 0, tzinfo=UTC)
SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64


def _timestamp(*, seconds: int = 0) -> str:
    return (NOW + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


def _attempt(
    state: AgenticSpecialistJobAttemptState = (
        AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
    ),
    *,
    namespace: str = "primary",
) -> AgenticSpecialistJobAttempt:
    values: dict[str, object] = {
        "state": AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND,
        "storeId": "agentic-store:" + "1" * 32,
        "coordinationBindingDigest": SHA_A,
        "databaseIdentityDigest": SHA_B,
        "deploymentDigest": SHA_C,
        "controlPlaneRunId": "agentic-control-plane:test",
        "campaignId": "campaign:test",
        "campaignManifestDigest": SHA_D,
        "planId": "agentic-specialist-plan_" + SHA_A,
        "planDigest": SHA_A,
        "planStateDigest": SHA_B,
        "reservationId": "agentic-specialist-reservation_" + SHA_C,
        "reservationDigest": SHA_C,
        "reservationStateDigest": SHA_D,
        "commandId": "agent-command_" + SHA_E,
        "commandDigest": SHA_E,
        "targetAgentId": "agent:sqli-specialist",
        "taskId": "task:sqli-specialist",
        "schedulerTaskName": "task:agentic-sqli-dispatch",
        "schedulerTaskTokenDigest": SHA_F,
        "runtimeCapsuleTokenDigest": SHA_A,
        "specialization": PentestSpecialization.SQL_INJECTION,
        "dispatchBindingId": "agentic-specialist-dispatch-binding_" + SHA_B,
        "dispatchBindingDigest": SHA_B,
        "claimVerificationDigest": "",
        "dispatchVerification": None,
        "dispatchVerificationDigest": None,
        "dispatchEventDigest": None,
        "graphSnapshotId": "graph-snapshot:test",
        "graphSnapshotDigest": SHA_F,
        "preparationId": "agentic-specialist-preparation_" + SHA_A,
        "preparationDigest": SHA_A,
        "profileRegistryDigest": SHA_B,
        "profileId": "pajin.web-specialist.juice-shop.sql-login-only",
        "profileVersion": "1.0.0",
        "profileDigest": SHA_C,
        "executorCatalogDigest": SHA_D,
        "executorId": "pajin.web-specialist.sql-login",
        "executorVersion": "1.0.0",
        "executorDigest": SHA_E,
        "preparedActionDigest": SHA_A,
        "activationSetDigest": SHA_B,
        "releaseId": "capability-release:test",
        "releaseDigest": SHA_C,
        "capabilityId": "pajin.bug-bounty.web-specialist.sql-login",
        "capabilityVersion": "2.0.0",
        "capabilityDefinitionDigest": SHA_D,
        "capabilityDigest": SHA_E,
        "capabilityAuthoritySetId": "capability-authority-set_" + SHA_F,
        "capabilityAuthoritySetDigest": SHA_F,
        "toolId": "web.specialist.sql-login.v2",
        "toolVersion": "2.0.0",
        "toolDigest": SHA_F,
        "requestId": "agentic-specialist-v2-request:" + SHA_A,
        "requestDigest": SHA_A,
        "capabilityGrantId": "grant:test",
        "capabilityGrantDigest": SHA_A,
        "grantLineageStateDigest": SHA_B,
        "capabilityGrantExpiresAt": _timestamp(seconds=33),
        "grantConsumptionReceiptId": "agentic-specialist-grant-consumption_" + SHA_B,
        "grantConsumptionReceiptDigest": SHA_B,
        "actionPermitId": "action-permit_" + SHA_C,
        "actionPermitDigest": SHA_C,
        "actionPermitExpiresAt": _timestamp(seconds=31),
        "approvalId": "approval:test",
        "approvalDigest": SHA_C,
        "approvalExpiresAt": _timestamp(seconds=32),
        "approvalConsumptionReceiptId": "action-approval-receipt_" + SHA_D,
        "approvalConsumptionReceiptDigest": SHA_D,
        "dispatchId": "action-dispatch_" + SHA_E,
        "targetId": "target:juice-shop",
        "targetDigest": SHA_F,
        "gatewayId": "pajin.gateway.agentic-specialist",
        "gatewayVersion": "1.0.0",
        "gatewayDigest": SHA_A,
        "executionInventoryId": "agentic-specialist-execution-inventory_" + SHA_B,
        "executionInventoryDigest": SHA_B,
        "workerBackendId": "pajin.worker.specialist",
        "workerBackendVersion": "1.0.0",
        "workerBackendDigest": SHA_B,
        "workerJobId": "worker-job:sqli",
        "workerJobDigest": SHA_C,
        "workerCommandDigest": SHA_D,
        "workerCompilerId": "pajin.worker-compiler.specialist",
        "workerCompilerVersion": "1.0.0",
        "workerCompilerDigest": SHA_E,
        "workerImageReference": "image:agentic-specialist",
        "workerImageDigest": SHA_D,
        "workerVerifierId": "pajin.worker-verifier.specialist",
        "workerVerifierVersion": "1.0.0",
        "workerVerifierDigest": SHA_E,
        "workerVerificationKeyId": "key:specialist-v2",
        "workerVerificationKeyDigest": SHA_F,
        "claimedAt": _timestamp(),
        "backendDispatchStartedAt": None,
    }
    if namespace != "primary":

        def digest(label: str) -> str:
            return sha256(f"{namespace}:{label}".encode()).hexdigest()

        values.update(
            {
                "planId": "agentic-specialist-plan_" + digest("plan-id"),
                "planDigest": digest("plan-digest"),
                "planStateDigest": digest("plan-state"),
                "reservationId": ("agentic-specialist-reservation_" + digest("reservation-id")),
                "reservationDigest": digest("reservation-digest"),
                "reservationStateDigest": digest("reservation-state"),
                "commandId": "agent-command_" + digest("command-id"),
                "commandDigest": digest("command-digest"),
                "schedulerTaskTokenDigest": digest("scheduler-task-token"),
                "runtimeCapsuleTokenDigest": digest("runtime-capsule-token"),
                "dispatchBindingId": (
                    "agentic-specialist-dispatch-binding_" + digest("dispatch-binding-id")
                ),
                "dispatchBindingDigest": digest("dispatch-binding-digest"),
                "preparedActionDigest": digest("prepared-action"),
                "requestId": f"agentic-specialist-v2-request:{namespace}",
                "requestDigest": digest("request-digest"),
                "grantConsumptionReceiptId": (
                    "agentic-specialist-grant-consumption_" + digest("grant-consumption-id")
                ),
                "grantConsumptionReceiptDigest": digest("grant-consumption-digest"),
                "actionPermitId": "action-permit_" + digest("permit-id"),
                "actionPermitDigest": digest("permit-digest"),
                "approvalConsumptionReceiptId": (f"action-approval-receipt:{namespace}"),
                "approvalConsumptionReceiptDigest": digest("approval-consumption-digest"),
                "dispatchId": "action-dispatch_" + digest("dispatch-id"),
                "workerJobId": f"worker-job:{namespace}",
                "workerJobDigest": digest("worker-job-digest"),
            }
        )
    values["claimVerification"] = build_specialist_claim_verification(values)
    claimed = AgenticSpecialistJobAttempt.model_validate(values)
    if state is AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND:
        return claimed
    dispatch_verification = build_specialist_dispatch_verification(
        claimed,
        verified_at=NOW + timedelta(seconds=1),
        backend_handoff_deadline=NOW + timedelta(seconds=31),
    )
    started_values = claimed.model_dump(mode="json", by_alias=True)
    started_values.update(
        {
            "state": state.value,
            "stateDigest": "",
            "dispatchVerification": dispatch_verification.model_dump(
                mode="json",
                by_alias=True,
            ),
            "dispatchVerificationDigest": dispatch_verification.verification_digest,
            "dispatchEventDigest": None,
            "backendDispatchStartedAt": _timestamp(seconds=1),
        }
    )
    return AgenticSpecialistJobAttempt.model_validate(started_values)


def _receipt(
    attempt: AgenticSpecialistJobAttempt,
    kind: AgenticSpecialistTerminalKind,
) -> AgenticSpecialistTerminalReceipt:
    values: dict[str, object] = {
        "storeId": attempt.store_id,
        "coordinationBindingDigest": attempt.coordination_binding_digest,
        "attemptId": attempt.attempt_id,
        "attemptDigest": attempt.attempt_digest,
        "attemptState": attempt.state,
        "attemptStateDigest": attempt.state_digest,
        "planId": attempt.plan_id,
        "requestId": attempt.request_id,
        "workerJobId": attempt.worker_job_id,
        "terminalKind": kind,
        "terminalReasonDigest": SHA_D,
        "recordedAt": _timestamp(seconds=3),
    }
    if kind is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND:
        values.update(
            targetIoState=AgenticSpecialistTargetIOState.NOT_STARTED,
            succeeded=False,
            backendTerminalProven=False,
        )
    elif kind is AgenticSpecialistTerminalKind.STARTED_OUTCOME_UNKNOWN:
        values.update(
            targetIoState=AgenticSpecialistTargetIOState.UNKNOWN,
            succeeded=None,
            backendTerminalProven=False,
        )
    else:
        values.update(
            targetIoState=(
                AgenticSpecialistTargetIOState.NOT_STARTED
                if kind is AgenticSpecialistTerminalKind.FAILED_BEFORE_TARGET_IO
                else AgenticSpecialistTargetIOState.PERFORMED
            ),
            succeeded=kind is AgenticSpecialistTerminalKind.COMPLETED_VERIFIED,
            backendTerminalProven=True,
            workerResultDigest=SHA_E,
            backendTerminalProofDigest=SHA_F,
            backendFinishedAt=_timestamp(seconds=2),
        )
    return AgenticSpecialistTerminalReceipt.model_validate(values)


def _insert_started_parent_rows(
    connection: sqlite3.Connection,
    attempt: AgenticSpecialistJobAttempt,
) -> None:
    connection.execute(
        """
        INSERT INTO agentic_specialist_executions(
            reservation_id, reservation_digest, state_digest, store_id,
            coordination_binding_digest, source_head_checkpoint_id,
            source_head_checkpoint_digest, graph_snapshot_id,
            graph_snapshot_digest, cycle_id, cycle_digest, command_id,
            command_digest, admission_receipt_id, admission_receipt_digest,
            target_agent_id, task_id, candidate_id, candidate_digest,
            proposal_digest, target_id, threat_class, specialization,
            specialist_definition_digest, canonical_entry, state,
            reserved_at, dispatch_started_at
        ) VALUES (
            :reservation_id, :reservation_digest, :state_digest, :store_id,
            :binding_digest, :source_head_id, :source_head_digest,
            :graph_snapshot_id, :graph_snapshot_digest, :cycle_id,
            :cycle_digest, :command_id, :command_digest, :admission_id,
            :admission_digest, :target_agent_id, :task_id, :candidate_id,
            :candidate_digest, :proposal_digest, :target_id, :threat_class,
            :specialization, :specialist_definition_digest, :canonical_entry,
            'dispatch-started-outcome-unknown', :reserved_at, :dispatch_started_at
        )
        """,
        {
            "reservation_id": attempt.reservation_id,
            "reservation_digest": attempt.reservation_digest,
            "state_digest": attempt.reservation_state_digest,
            "store_id": attempt.store_id,
            "binding_digest": attempt.coordination_binding_digest,
            "source_head_id": "checkpoint:source",
            "source_head_digest": SHA_A,
            "graph_snapshot_id": attempt.graph_snapshot_id,
            "graph_snapshot_digest": attempt.graph_snapshot_digest,
            "cycle_id": "cycle:test",
            "cycle_digest": SHA_B,
            "command_id": attempt.command_id,
            "command_digest": attempt.command_digest,
            "admission_id": "admission:test",
            "admission_digest": SHA_C,
            "target_agent_id": attempt.target_agent_id,
            "task_id": attempt.task_id,
            "candidate_id": "candidate:test",
            "candidate_digest": SHA_D,
            "proposal_digest": SHA_E,
            "target_id": attempt.target_id,
            "threat_class": "sql-injection",
            "specialization": attempt.specialization.value,
            "specialist_definition_digest": SHA_F,
            "canonical_entry": sqlite3.Binary(b"{}"),
            "reserved_at": _timestamp(),
            "dispatch_started_at": _timestamp(seconds=1),
        },
    )
    connection.execute(
        """
        INSERT INTO agentic_specialist_dispatch_plans(
            plan_id, plan_digest, state_digest, store_id,
            coordination_binding_digest, reservation_id, reservation_digest,
            command_id, command_digest, preparation_id, preparation_digest,
            prepared_action_digest, request_id, grant_id, grant_digest,
            approval_id, approval_digest, action_proposal_id,
            action_proposal_digest, expected_action_permit_id,
            canonical_entry, state, planned_at, action_permit_id,
            action_permit_digest, approval_receipt_id, approval_receipt_digest,
            grant_consumption_receipt_id, grant_consumption_receipt_digest,
            grant_consumed_at, callback_entered_at, reconciled_at
        ) VALUES (
            :plan_id, :plan_digest, :state_digest, :store_id, :binding_digest,
            :reservation_id, :reservation_digest, :command_id, :command_digest,
            :preparation_id, :preparation_digest, :prepared_action_digest,
            :request_id, :grant_id, :grant_digest, :approval_id,
            :approval_digest, :proposal_id, :proposal_digest,
            :expected_permit_id, :canonical_entry,
            'dispatch-started-outcome-unknown', :planned_at,
            :permit_id, :permit_digest, :approval_receipt_id,
            :approval_receipt_digest, :grant_receipt_id, :grant_receipt_digest,
            :grant_consumed_at, :callback_entered_at, NULL
        )
        """,
        {
            "plan_id": attempt.plan_id,
            "plan_digest": attempt.plan_digest,
            "state_digest": attempt.plan_state_digest,
            "store_id": attempt.store_id,
            "binding_digest": attempt.coordination_binding_digest,
            "reservation_id": attempt.reservation_id,
            "reservation_digest": attempt.reservation_digest,
            "command_id": attempt.command_id,
            "command_digest": attempt.command_digest,
            "preparation_id": attempt.preparation_id,
            "preparation_digest": attempt.preparation_digest,
            "prepared_action_digest": attempt.prepared_action_digest,
            "request_id": attempt.request_id,
            "grant_id": attempt.capability_grant_id,
            "grant_digest": attempt.capability_grant_digest,
            "approval_id": attempt.approval_id,
            "approval_digest": attempt.approval_digest,
            "proposal_id": "proposal:test",
            "proposal_digest": SHA_D,
            "expected_permit_id": "expected-permit:test",
            "canonical_entry": sqlite3.Binary(b"{}"),
            "planned_at": _timestamp(),
            "permit_id": attempt.action_permit_id,
            "permit_digest": attempt.action_permit_digest,
            "approval_receipt_id": attempt.approval_consumption_receipt_id,
            "approval_receipt_digest": (attempt.approval_consumption_receipt_digest),
            "grant_receipt_id": attempt.grant_consumption_receipt_id,
            "grant_receipt_digest": attempt.grant_consumption_receipt_digest,
            "grant_consumed_at": _timestamp(),
            "callback_entered_at": _timestamp(seconds=1),
        },
    )


def test_job_attempt_is_deterministic_and_marks_backend_dispatch_once() -> None:
    claimed = _attempt()
    assert claimed.attempt_id == (f"agentic-specialist-job-attempt_{claimed.attempt_digest}")
    assert claimed.automatic_redispatch_authorized is False
    assert claimed.execution_authority is False
    assert _attempt() == claimed

    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    assert started.attempt_id == claimed.attempt_id
    assert started.attempt_digest == claimed.attempt_digest
    assert started.backend_dispatch_started_at == NOW + timedelta(seconds=1)
    assert started.dispatch_verification is not None
    assert started.dispatch_verification_digest == started.dispatch_verification.verification_digest
    assert started.dispatch_event_digest is not None
    assert len(started.dispatch_event_digest) == 64
    assert started.state_digest != claimed.state_digest

    values = claimed.model_dump(mode="json", by_alias=True)
    values.update(
        {
            "state": AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value,
            "stateDigest": "",
        }
    )
    with pytest.raises(ValueError, match="state timestamp"):
        AgenticSpecialistJobAttempt.model_validate(values)


def test_started_job_attempt_requires_dispatch_verification() -> None:
    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    values = started.model_dump(mode="json", by_alias=True)
    values.update(
        {
            "attemptId": "",
            "attemptDigest": "",
            "stateDigest": "",
            "dispatchVerificationDigest": None,
        }
    )
    with pytest.raises(ValueError, match="dispatch verification"):
        AgenticSpecialistJobAttempt.model_validate(values)


def test_started_job_attempt_derives_and_rejects_a_foreign_dispatch_event_digest() -> None:
    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    values = started.model_dump(mode="json", by_alias=True)
    values.update(
        {
            "attemptId": "",
            "attemptDigest": "",
            "stateDigest": "",
            "dispatchEventDigest": SHA_A,
        }
    )
    with pytest.raises(ValueError, match="dispatch event Digest differs"):
        AgenticSpecialistJobAttempt.model_validate(values)


def test_verification_digest_dag_is_canonical_and_one_way() -> None:
    claimed = _attempt()
    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)

    assert claimed.claim_verification.subject_digest != claimed.attempt_digest
    assert claimed.claim_verification.verification_digest == (claimed.claim_verification_digest)
    assert started.attempt_digest == claimed.attempt_digest
    assert started.state_digest != claimed.state_digest
    assert started.dispatch_verification is not None
    assert started.dispatch_verification.attempt_digest == claimed.attempt_digest
    assert started.dispatch_verification.claimed_state_digest == claimed.state_digest

    later_dispatch = build_specialist_dispatch_verification(
        claimed,
        verified_at=NOW + timedelta(seconds=2),
        backend_handoff_deadline=NOW + timedelta(seconds=31),
    )
    assert later_dispatch.verification_digest != (started.dispatch_verification.verification_digest)
    assert claimed.attempt_digest == _attempt().attempt_digest
    assert claimed.state_digest == _attempt().state_digest


def test_verification_records_reject_backward_or_forward_references() -> None:
    claimed = _attempt()
    claim_values = claimed.claim_verification.model_dump(mode="json", by_alias=True)
    claim_values["attemptId"] = claimed.attempt_id
    with pytest.raises(ValueError, match="Extra inputs"):
        AgenticSpecialistClaimVerification.model_validate(claim_values)

    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    assert started.dispatch_verification is not None
    dispatch_values = started.dispatch_verification.model_dump(
        mode="json",
        by_alias=True,
    )
    dispatch_values["dispatchEventDigest"] = started.dispatch_event_digest
    with pytest.raises(ValueError, match="Extra inputs"):
        AgenticSpecialistDispatchVerification.model_validate(dispatch_values)


def test_claim_verification_cannot_be_transplanted_to_another_subject() -> None:
    claimed = _attempt()
    values = claimed.model_dump(mode="json", by_alias=True)
    values.update(
        {
            "attemptId": "",
            "attemptDigest": "",
            "stateDigest": "",
            "runtimeCapsuleTokenDigest": SHA_B,
        }
    )
    with pytest.raises(ValueError, match="claim verification differs"):
        AgenticSpecialistJobAttempt.model_validate(values)


def test_dispatch_verification_requires_a_fresh_deadline() -> None:
    claimed = _attempt()
    with pytest.raises(ValueError, match="deadline is not fresh"):
        build_specialist_dispatch_verification(
            claimed,
            verified_at=NOW + timedelta(seconds=1),
            backend_handoff_deadline=NOW + timedelta(seconds=1),
        )


@pytest.mark.parametrize("kind", tuple(AgenticSpecialistTerminalKind))
def test_terminal_receipt_grammar_is_closed_and_non_authorizing(
    kind: AgenticSpecialistTerminalKind,
) -> None:
    attempt = _attempt(
        AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
        if kind is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
        else AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    )
    receipt = _receipt(attempt, kind)

    assert receipt.receipt_id == f"agentic-specialist-terminal_{receipt.receipt_digest}"
    assert receipt.automatic_redispatch_authorized is False
    assert receipt.execution_authority is False
    assert receipt.finding_authority is False
    assert receipt.graph_authority is False
    assert receipt.report_authority is False
    assert receipt.poc_authority is False
    assert _receipt(attempt, kind) == receipt


def test_terminal_receipt_rejects_false_terminal_or_target_io_claims() -> None:
    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    receipt = _receipt(started, AgenticSpecialistTerminalKind.COMPLETED_VERIFIED)
    values = receipt.model_dump(mode="json", by_alias=True)
    values.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "targetIoState": AgenticSpecialistTargetIOState.UNKNOWN.value,
        }
    )
    with pytest.raises(ValueError, match="post-target-I/O"):
        AgenticSpecialistTerminalReceipt.model_validate(values)

    values = receipt.model_dump(mode="json", by_alias=True)
    values.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "backendTerminalProven": False,
        }
    )
    with pytest.raises(ValueError, match="lacks backend proof"):
        AgenticSpecialistTerminalReceipt.model_validate(values)


def test_outcome_unknown_receipt_cannot_carry_invented_worker_result() -> None:
    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    receipt = _receipt(started, AgenticSpecialistTerminalKind.STARTED_OUTCOME_UNKNOWN)
    values = receipt.model_dump(mode="json", by_alias=True)
    values.update(
        {
            "receiptId": "",
            "receiptDigest": "",
            "workerResultDigest": SHA_A,
        }
    )
    with pytest.raises(ValueError, match="outcome-unknown"):
        AgenticSpecialistTerminalReceipt.model_validate(values)


@pytest.mark.parametrize(
    ("field", "value", "match"),
    (
        ("succeeded", 0, "exact boolean"),
        ("succeeded", "false", "exact boolean"),
        ("backendTerminalProven", 1, "exact boolean"),
        ("backendTerminalProven", "true", "exact boolean"),
    ),
)
def test_terminal_receipt_rejects_coerced_boolean_markers(
    field: str,
    value: object,
    match: str,
) -> None:
    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    receipt = _receipt(started, AgenticSpecialistTerminalKind.COMPLETED_VERIFIED)
    values = receipt.model_dump(mode="json", by_alias=True)
    values.update({"receiptId": "", "receiptDigest": "", field: value})
    with pytest.raises(ValueError, match=match):
        AgenticSpecialistTerminalReceipt.model_validate(values)


def test_terminal_receipt_requires_a_reason_digest() -> None:
    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    receipt = _receipt(started, AgenticSpecialistTerminalKind.COMPLETED_VERIFIED)
    values = receipt.model_dump(mode="json", by_alias=True)
    values.pop("terminalReasonDigest")
    values.update({"receiptId": "", "receiptDigest": ""})
    with pytest.raises(ValueError, match="terminalReasonDigest"):
        AgenticSpecialistTerminalReceipt.model_validate(values)


def test_schema_v6_job_attempt_round_trip_and_terminal_fences() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    for statement in durable._SCHEMA_OBJECTS:
        connection.execute(durable._SCHEMA_OBJECTS[statement])

    claimed = _attempt()
    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    _insert_started_parent_rows(connection, claimed)
    mismatched_values = claimed.model_dump(mode="json", by_alias=True)
    mismatched_values.update(
        {
            "attemptId": "",
            "attemptDigest": "",
            "stateDigest": "",
            "planStateDigest": SHA_F,
            "claimVerificationDigest": "",
        }
    )
    mismatched_values["claimVerification"] = build_specialist_claim_verification(
        mismatched_values
    ).model_dump(mode="json", by_alias=True)
    mismatched = AgenticSpecialistJobAttempt.model_validate(mismatched_values)
    with pytest.raises(sqlite3.IntegrityError, match="job attempt parent differs"):
        durable._insert_specialist_job_attempt(connection, mismatched)
    durable._insert_specialist_job_attempt(connection, claimed)
    durable._cas_specialist_job_attempt_started(
        connection,
        before=claimed,
        after=started,
    )
    receipt = _receipt(started, AgenticSpecialistTerminalKind.COMPLETED_VERIFIED)
    durable._insert_specialist_terminal_receipt(connection, receipt)

    assert (
        durable._specialist_job_attempt_from_row(
            durable._specialist_job_attempt_row(connection, started.attempt_id)
        )
        == started
    )
    receipt_row = durable._specialist_terminal_receipt_row(
        connection,
        started.attempt_id,
    )
    assert receipt_row is not None
    assert durable._specialist_terminal_receipt_from_row(receipt_row) == receipt

    attempt_bytes = bytes(
        connection.execute(
            "SELECT canonical_entry FROM agentic_specialist_job_attempts WHERE attempt_id = ?",
            (started.attempt_id,),
        ).fetchone()[0]
    )
    receipt_bytes = bytes(receipt_row["canonical_receipt"])
    with pytest.raises(sqlite3.IntegrityError, match="job attempt insert collision"):
        connection.execute(
            "INSERT OR REPLACE INTO agentic_specialist_job_attempts "
            "SELECT * FROM agentic_specialist_job_attempts WHERE attempt_id = ?",
            (started.attempt_id,),
        )
    with pytest.raises(sqlite3.IntegrityError, match="receipt insert collision"):
        connection.execute(
            "INSERT OR REPLACE INTO agentic_specialist_terminal_receipts "
            "SELECT * FROM agentic_specialist_terminal_receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        )
    assert (
        bytes(
            connection.execute(
                "SELECT canonical_entry FROM agentic_specialist_job_attempts WHERE attempt_id = ?",
                (started.attempt_id,),
            ).fetchone()[0]
        )
        == attempt_bytes
    )
    assert (
        bytes(
            connection.execute(
                "SELECT canonical_receipt FROM agentic_specialist_terminal_receipts "
                "WHERE receipt_id = ?",
                (receipt.receipt_id,),
            ).fetchone()[0]
        )
        == receipt_bytes
    )

    with pytest.raises(sqlite3.IntegrityError, match="job attempt is terminal"):
        connection.execute(
            "UPDATE agentic_specialist_job_attempts SET state = ? WHERE attempt_id = ?",
            (
                AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND.value,
                started.attempt_id,
            ),
        )
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute(
            "UPDATE agentic_specialist_terminal_receipts "
            "SET terminal_reason_digest = ? WHERE receipt_id = ?",
            (SHA_A, receipt.receipt_id),
        )
    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute(
            "DELETE FROM agentic_specialist_terminal_receipts WHERE receipt_id = ?",
            (receipt.receipt_id,),
        )


def test_schema_v6_replace_cannot_delete_another_job_attempt() -> None:
    connection = sqlite3.connect(":memory:")
    connection.row_factory = sqlite3.Row
    durable._configure_connection(connection, readonly=False)
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert connection.execute("PRAGMA recursive_triggers").fetchone()[0] == 1
    connection.execute("PRAGMA foreign_keys = OFF")
    for key, statement in durable._SCHEMA_OBJECTS.items():
        if key[0] == "table":
            connection.execute(statement)
    for key in (
        ("trigger", "agentic_specialist_job_attempt_identity_immutable"),
        ("trigger", "agentic_specialist_job_attempts_no_delete"),
        ("trigger", "agentic_specialist_job_attempt_insert_collision"),
        (
            "trigger",
            "agentic_specialist_job_attempt_dispatch_verification_collision",
        ),
        ("trigger", "agentic_specialist_job_attempts_monotonic"),
        ("trigger", "agentic_specialist_job_attempt_terminal_fence"),
    ):
        connection.execute(durable._SCHEMA_OBJECTS[key])

    started = _attempt(AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN)
    claimed = _attempt(namespace="replace-target")
    replacement = _attempt(
        AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
        namespace="replace-target",
    )
    durable._insert_specialist_job_attempt(connection, started)
    durable._insert_specialist_job_attempt(connection, claimed)
    connection.commit()
    connection.execute("PRAGMA foreign_keys = ON")
    assert connection.execute("PRAGMA foreign_keys").fetchone()[0] == 1

    original_rows = tuple(
        connection.execute(
            "SELECT rowid, attempt_id, canonical_entry "
            "FROM agentic_specialist_job_attempts ORDER BY attempt_id"
        )
    )
    started_rowid = connection.execute(
        "SELECT rowid FROM agentic_specialist_job_attempts WHERE attempt_id = ?",
        (started.attempt_id,),
    ).fetchone()[0]

    with pytest.raises(sqlite3.IntegrityError, match="append-only"):
        connection.execute(
            "UPDATE OR REPLACE agentic_specialist_job_attempts SET rowid = ? WHERE attempt_id = ?",
            (started_rowid, claimed.attempt_id),
        )

    assert (
        tuple(
            connection.execute(
                "SELECT rowid, attempt_id, canonical_entry "
                "FROM agentic_specialist_job_attempts ORDER BY attempt_id"
            )
        )
        == original_rows
    )
    assert started.dispatch_verification is not None

    insert_candidate = _attempt(
        AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
        namespace="insert-target",
    )
    staging = sqlite3.connect(":memory:")
    staging.row_factory = sqlite3.Row
    staging.execute(durable._SCHEMA_OBJECTS[("table", "agentic_specialist_job_attempts")])
    durable._insert_specialist_job_attempt(staging, insert_candidate)
    staged_row = staging.execute("SELECT * FROM agentic_specialist_job_attempts").fetchone()
    assert staged_row is not None
    insert_columns = tuple(staged_row.keys())
    insert_values = [staged_row[column] for column in insert_columns]
    staging.close()
    insert_values[insert_columns.index("dispatch_verification_id")] = (
        started.dispatch_verification.verification_id
    )
    with pytest.raises(sqlite3.IntegrityError, match="job attempt insert collision"):
        connection.execute(
            "INSERT OR REPLACE INTO agentic_specialist_job_attempts ("
            + ", ".join(insert_columns)
            + ") VALUES ("
            + ", ".join("?" for _column in insert_columns)
            + ")",
            insert_values,
        )

    assert (
        tuple(
            connection.execute(
                "SELECT rowid, attempt_id, canonical_entry "
                "FROM agentic_specialist_job_attempts ORDER BY attempt_id"
            )
        )
        == original_rows
    )
    with pytest.raises(sqlite3.IntegrityError, match="dispatch verification collision"):
        connection.execute(
            """
            UPDATE OR REPLACE agentic_specialist_job_attempts
            SET canonical_entry = ?, state = ?, state_digest = ?,
                dispatch_verification_id = ?, dispatch_verification_digest = ?,
                dispatch_event_digest = ?, backend_dispatch_started_at = ?
            WHERE attempt_id = ?
            """,
            (
                sqlite3.Binary(durable._specialist_job_attempt_bytes(replacement)),
                replacement.state.value,
                replacement.state_digest,
                started.dispatch_verification.verification_id,
                replacement.dispatch_verification_digest,
                replacement.dispatch_event_digest,
                _timestamp(seconds=1),
                claimed.attempt_id,
            ),
        )

    assert (
        tuple(
            connection.execute(
                "SELECT rowid, attempt_id, canonical_entry "
                "FROM agentic_specialist_job_attempts ORDER BY attempt_id"
            )
        )
        == original_rows
    )
    durable._cas_specialist_job_attempt_started(
        connection,
        before=claimed,
        after=replacement,
    )
    assert (
        durable._specialist_job_attempt_from_row(
            durable._specialist_job_attempt_row(connection, claimed.attempt_id)
        )
        == replacement
    )
