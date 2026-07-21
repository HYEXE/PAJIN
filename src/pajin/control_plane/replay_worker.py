"""Lease-aware daemon dedicated to one exact Control Plane Replay profile."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, model_validator

from pajin.control_plane.client import (
    ControlPlaneAuthenticationError,
    ControlPlaneLeaseLost,
    ControlPlaneLocalLeaseDeadlineExceeded,
    ControlPlaneProtocolError,
    ControlPlaneTransientError,
)
from pajin.control_plane.error_safety import (
    control_plane_cancellation_reason,
    control_plane_status_diagnostic,
)
from pajin.control_plane.lease_deadline import MonotonicLeaseDeadline
from pajin.control_plane.models import (
    KISA_EXACT_REPLAY_EXECUTOR_PROFILE,
    JobState,
    ReplayBatchState,
    ReplayClaimRequest,
    ReplayExecutionClaimView,
    ReplayFinalizationView,
    ReplayFinalizeRequest,
    ReplayItemState,
    ReplayLeaseRequest,
    ReplayTicketState,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
    canonical_control_plane_json,
)
from pajin.control_plane.status_file import write_status_file
from pajin.control_plane.worker_lifecycle import (
    FinalizationMessages,
    LeaseDaemonLifecycle,
    encode_status,
    validate_lifecycle_timing,
)
from pajin.domain.models import StrictModel
from pajin.domain.validation import (
    ConfirmationBasis,
    FindingDisposition,
    ValidationCheckStatus,
    ValidationDecision,
    ValidationMethod,
    ValidationReasonCode,
)
from pajin.replay.tickets import replay_context_digest
from pajin.runtime.control import (
    CancellationKind,
    ExecutionCancellationContext,
    ExecutionCancellationSnapshot,
)
from pajin.runtime.error_safety import audit_safe_exception_type

_REPLAY_OUTPUT_MEDIA_TYPE = "application/vnd.pajin.run+directory"
_REPLAY_OUTPUT_SCHEMA_KIND = "pajin.replay.output.sealed.v1"
ReplayWorkerState = Literal[
    "starting",
    "idle",
    "running",
    "finalizing",
    "degraded",
    "lease-lost",
    "fatal",
    "cancelled",
    "crashed",
    "stopped",
]


class ReplayWorkerQuiescenceError(RuntimeError):
    """The trusted Replay executor could not be stopped within its hard bound."""


class ReplayWorkerControlPlanePort(Protocol):
    async def claim_replay(
        self,
        request: ReplayClaimRequest,
    ) -> ReplayExecutionClaimView | None: ...

    async def heartbeat_replay(
        self,
        job_id: str,
        request: ReplayLeaseRequest,
    ) -> ReplayExecutionClaimView: ...

    async def issue_replay_tool_permit(
        self,
        job_id: str,
        request: ReplayToolPermitRequest,
    ) -> ReplayToolPermitView: ...

    async def finalize_replay(
        self,
        job_id: str,
        request: ReplayFinalizeRequest,
    ) -> ReplayFinalizationView: ...


class ReplayClaimExecutor(Protocol):
    @property
    def profile(self) -> str: ...

    async def execute(
        self,
        claim: ReplayExecutionClaimView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ReplayFinalizeRequest: ...


class ReplayWorkerConfig(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    executor_profile: Literal["kisa-exact-v1"] = KISA_EXACT_REPLAY_EXECUTOR_PROFILE
    lease_seconds: int = Field(default=30, strict=True, ge=5, le=300)
    heartbeat_seconds: float = Field(default=5, ge=0.05, le=120)
    long_poll_seconds: int = Field(default=10, strict=True, ge=0, le=20)
    idle_delay_seconds: float = Field(default=0.2, ge=0.05, le=10)
    retry_base_seconds: float = Field(default=0.25, ge=0.05, le=10)
    retry_max_seconds: float = Field(default=5, ge=0.1, le=60)
    finalize_attempts: int = Field(default=3, strict=True, ge=1, le=10)
    cancellation_grace_seconds: float = Field(default=2, ge=0.05, le=30)
    cancellation_force_seconds: float = Field(default=25, ge=0.05, le=30)
    status_path: Path | None = None

    @model_validator(mode="after")
    def heartbeat_precedes_expiry(self) -> ReplayWorkerConfig:
        validate_lifecycle_timing(self, owner="Replay")
        return self


class ReplayWorkerStatus(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    executor_profile: Literal["kisa-exact-v1"]
    state: ReplayWorkerState
    active_job_id: str | None = Field(default=None, pattern=r"^job_[0-9a-f]{32}$")
    active_run_id: str | None = Field(
        default=None,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$",
    )
    active_ticket_id: str | None = Field(
        default=None,
        pattern=r"^replay-ticket_[0-9a-f]{32}$",
    )
    handled_replays: int = Field(default=0, ge=0)
    last_contact_at: datetime
    last_error: str | None = Field(default=None, max_length=500)
    last_cancellation: ExecutionCancellationSnapshot | None = None


class ReplayWorkerDaemon:
    """Claim, execute, and finalize one server-issued Replay at a time."""

    def __init__(
        self,
        *,
        client: ReplayWorkerControlPlanePort,
        executor: ReplayClaimExecutor,
        config: ReplayWorkerConfig,
    ) -> None:
        if executor.profile != config.executor_profile:
            raise ValueError("Replay executor profile differs from daemon configuration")
        self._client = client
        self._executor = executor
        self._config = config
        self._handled_replays = 0
        self._last_cancellation: ExecutionCancellationSnapshot | None = None
        self._phase: ReplayWorkerState = "starting"
        self._lifecycle = LeaseDaemonLifecycle(
            timing=config,
            owner="Replay Worker",
            status=lambda state, error: self._status(state, error=error),
            record_cancellation=self._record_cancellation,
            quiescence_error=ReplayWorkerQuiescenceError,
        )

    async def run_forever(self, stop: asyncio.Event) -> None:
        await self._lifecycle.run_forever(
            stop,
            self.run_once,
            diagnostic_stage="replay-worker-control-plane",
        )

    async def run_once(self) -> bool:
        self._lifecycle.require_active()
        claim = await self._client.claim_replay(
            ReplayClaimRequest(
                executor_profile=self._config.executor_profile,
                lease_seconds=self._config.lease_seconds,
                wait_seconds=self._config.long_poll_seconds,
            )
        )
        claim_received_at = asyncio.get_running_loop().time()
        self._lifecycle.require_active()
        if claim is not None:
            # A custom transport can retain its response model.  Establish a
            # private authority snapshot before the daemon next yields so that a
            # later mutation cannot redirect heartbeat, permits, or finalization.
            claim = claim.model_copy(deep=True)
        self._status("idle" if claim is None else "running", claim=claim)
        if claim is None:
            return False
        try:
            lease_deadline = MonotonicLeaseDeadline.from_server_timestamps(
                lease_expires_at=claim.job.lease_expires_at,
                lease_reference_at=claim.job.heartbeat_at,
                requested_lease_seconds=self._config.lease_seconds,
                observed_at=claim_received_at,
            )
            await self._process_claim(claim, lease_deadline=lease_deadline)
        except ControlPlaneAuthenticationError:
            self._status(
                "fatal",
                error="Control Plane authentication rejected",
            )
            raise
        except ControlPlaneProtocolError as exc:
            self._status(
                "fatal",
                error=control_plane_status_diagnostic(
                    exc,
                    stage="replay-worker-control-plane-protocol",
                ),
            )
            raise
        except ControlPlaneLeaseLost as exc:
            self._status(
                "lease-lost",
                error=control_plane_status_diagnostic(
                    exc,
                    stage="replay-worker-control-plane-lease",
                ),
            )
            raise
        except ControlPlaneTransientError as exc:
            self._status(
                "degraded",
                error=control_plane_status_diagnostic(
                    exc,
                    stage="replay-worker-control-plane-transport",
                ),
            )
            raise
        except (asyncio.CancelledError, ReplayWorkerQuiescenceError):
            raise
        except Exception as exc:
            self._status(
                "crashed",
                error=f"Replay executor crashed: {audit_safe_exception_type(exc)}",
            )
            raise
        self._handled_replays += 1
        self._status("idle")
        return True

    async def _process_claim(
        self,
        claim: ReplayExecutionClaimView,
        *,
        lease_deadline: MonotonicLeaseDeadline,
    ) -> None:
        lease_deadline.require_active()
        cancellation = ExecutionCancellationContext(
            job_id=claim.job.job_id,
            control_plane_run_id=claim.job.run_id,
        )
        self._phase = "running"
        heartbeat = asyncio.create_task(self._heartbeat_loop(claim, lease_deadline=lease_deadline))
        execution: asyncio.Task[ReplayFinalizeRequest] | None = None
        finalization: asyncio.Task[ReplayFinalizationView] | None = None
        try:
            execution = asyncio.create_task(
                # The claimed authority remains daemon-owned.  A custom executor
                # receives an isolated snapshot so it cannot retarget subsequent
                # heartbeat or finalization by mutating the shared Pydantic model.
                self._executor.execute(claim.model_copy(deep=True), cancellation=cancellation)
            )
            request = await self._lifecycle.await_with_heartbeat(
                execution,
                heartbeat,
                cancellation=cancellation,
                finalization_operation="Replay finalization",
                heartbeat_stopped="Replay heartbeat loop stopped unexpectedly",
            )
            lease_deadline.require_active()
            self._phase = "finalizing"
            self._status("finalizing", claim=claim)
            finalization = asyncio.create_task(self._finalize_with_retry(claim, request))
            await self._await_finalization_with_heartbeat(
                finalization,
                heartbeat,
                lease_deadline=lease_deadline,
            )
            lease_deadline.require_active()
        except (
            ControlPlaneAuthenticationError,
            ControlPlaneLeaseLost,
            ControlPlaneProtocolError,
            ControlPlaneTransientError,
        ) as exc:
            cancellation.cancel(
                self._lifecycle.cancellation_kind(exc),
                control_plane_cancellation_reason(exc),
            )
            if execution is not None and not execution.done():
                await self._lifecycle.stop_execution(execution, cancellation)
            else:
                if finalization is not None and not finalization.done():
                    await self._lifecycle.cancel_and_drain(
                        finalization,
                        operation="Replay finalization",
                    )
                cancellation.mark_executor_drained()
                self._last_cancellation = cancellation.snapshot()
            raise
        except asyncio.CancelledError:
            cancellation.cancel(
                CancellationKind.DAEMON_SHUTDOWN,
                "Replay Worker daemon execution was cancelled",
            )
            if execution is not None and not execution.done():
                await self._lifecycle.stop_execution(execution, cancellation)
            else:
                if finalization is not None and not finalization.done():
                    await self._lifecycle.cancel_and_drain(
                        finalization,
                        operation="Replay finalization",
                    )
                cancellation.mark_executor_drained()
                self._last_cancellation = cancellation.snapshot()
            self._status("cancelled", error=cancellation.snapshot().reason)
            raise
        finally:
            await self._lifecycle.drain_claim_tasks((execution, finalization, heartbeat))

    async def _heartbeat_loop(
        self,
        claim: ReplayExecutionClaimView,
        *,
        lease_deadline: MonotonicLeaseDeadline,
    ) -> None:
        current = claim
        while True:
            self._lifecycle.require_active()
            request_started_at = asyncio.get_running_loop().time()
            lease_deadline.require_active()
            try:
                async with asyncio.timeout_at(lease_deadline.expires_at):
                    refreshed = await self._client.heartbeat_replay(
                        claim.job.job_id,
                        ReplayLeaseRequest(
                            executor_profile=self._config.executor_profile,
                            lease_token=claim.lease_token,
                            lease_seconds=self._config.lease_seconds,
                            ticket_id=claim.ticket.ticket_id,
                            fencing_value=claim.ticket.fencing_value,
                        ),
                    )
                self._lifecycle.require_active()
            except TimeoutError as exc:
                if lease_deadline.remaining() <= 0:
                    raise ControlPlaneLocalLeaseDeadlineExceeded(
                        "local Replay lease deadline elapsed while heartbeat was unavailable"
                    ) from exc
                raise
            self._validate_heartbeat_claim(current, refreshed)
            lease_deadline.renew_from_server_timestamps(
                lease_expires_at=refreshed.job.lease_expires_at,
                lease_reference_at=refreshed.job.heartbeat_at,
                requested_lease_seconds=self._config.lease_seconds,
                request_started_at=request_started_at,
            )
            current = refreshed
            self._status(self._phase, claim=refreshed)
            await lease_deadline.wait_for_renewal_interval(self._config.heartbeat_seconds)

    async def _finalize_with_retry(
        self,
        claim: ReplayExecutionClaimView,
        request: ReplayFinalizeRequest,
    ) -> ReplayFinalizationView:
        async def operation() -> ReplayFinalizationView:
            result = await self._client.finalize_replay(claim.job.job_id, request)
            self._validate_finalization(claim, result)
            return result

        return await self._lifecycle.finalize_with_retry(operation)

    async def _await_finalization_with_heartbeat(
        self,
        operation: asyncio.Task[ReplayFinalizationView],
        heartbeat: asyncio.Task[None],
        *,
        lease_deadline: MonotonicLeaseDeadline,
    ) -> ReplayFinalizationView:
        return await self._lifecycle.await_finalization_with_heartbeat(
            operation,
            heartbeat,
            lease_deadline=lease_deadline,
            messages=FinalizationMessages(
                operation="Replay finalization",
                heartbeat_stopped="Replay heartbeat loop stopped unexpectedly",
                local_deadline=(
                    "local Replay lease deadline elapsed during finalization reconciliation"
                ),
            ),
        )

    @staticmethod
    def _validate_heartbeat_claim(
        previous: ReplayExecutionClaimView,
        refreshed: ReplayExecutionClaimView,
    ) -> None:
        expected = previous.model_copy(
            update={
                "job": previous.job.model_copy(
                    update={
                        "lease_expires_at": refreshed.job.lease_expires_at,
                        "heartbeat_at": refreshed.job.heartbeat_at,
                        "updated_at": refreshed.job.updated_at,
                    }
                ),
                "ticket": previous.ticket.model_copy(
                    update={
                        "lease_expires_at": refreshed.ticket.lease_expires_at,
                        "updated_at": refreshed.ticket.updated_at,
                    }
                ),
            }
        )
        if refreshed != expected or refreshed.lease_token != previous.lease_token:
            raise ControlPlaneProtocolError(
                "Replay heartbeat response changed immutable claim authority"
            )

    @staticmethod
    def _validate_finalization(
        claim: ReplayExecutionClaimView,
        result: ReplayFinalizationView,
    ) -> None:
        if not ReplayWorkerDaemon._finalization_claim_authority_is_exact(claim, result):
            raise ControlPlaneProtocolError(
                "Replay finalization response differs from the claimed authority"
            )
        if not ReplayWorkerDaemon._finalization_result_authority_is_exact(claim, result):
            raise ControlPlaneProtocolError(
                "Replay finalization response has inconsistent result authority"
            )

    @staticmethod
    def _finalization_claim_authority_is_exact(
        claim: ReplayExecutionClaimView,
        result: ReplayFinalizationView,
    ) -> bool:
        expected_job = claim.job.model_copy(
            update={
                "state": JobState.SUCCEEDED,
                # Heartbeats may renew these fields after the daemon retained its
                # original claim snapshot but before finalization commits.
                "lease_expires_at": result.job.lease_expires_at,
                "heartbeat_at": result.job.heartbeat_at,
                "result": result.job.result,
                "updated_at": result.job.updated_at,
            }
        )
        expected_batch = claim.batch.model_copy(
            update={
                # Other items in the same batch may finish before an exact retry
                # reconstructs this response.
                "state": result.batch.state,
                "cas_version": result.batch.cas_version,
                "updated_at": result.batch.updated_at,
            }
        )
        expected_item = claim.item.model_copy(
            update={
                "state": result.item.state,
                "updated_at": result.item.updated_at,
            }
        )
        expected_ticket = claim.ticket.model_copy(
            update={
                "state": ReplayTicketState.FINALIZED,
                "lease_expires_at": result.ticket.lease_expires_at,
                "updated_at": result.ticket.updated_at,
            }
        )

        claim_lease_expiry = claim.job.lease_expires_at
        claim_heartbeat = claim.job.heartbeat_at
        result_lease_expiry = result.job.lease_expires_at
        result_heartbeat = result.job.heartbeat_at
        timestamps = (
            result.finalized_at,
            result.job.updated_at,
            result.batch.updated_at,
            result.item.updated_at,
            result.ticket.updated_at,
            result.gate_decision.decided_at,
            result_lease_expiry,
            result_heartbeat,
        )
        if (
            claim_lease_expiry is None
            or claim_heartbeat is None
            or result_lease_expiry is None
            or result_heartbeat is None
            or any(
                timestamp is None or timestamp.tzinfo is None or timestamp.utcoffset() is None
                for timestamp in timestamps
            )
        ):
            return False

        return (
            result.job == expected_job
            and result.batch == expected_batch
            and result.item == expected_item
            and result.ticket == expected_ticket
            and result.item.state in {ReplayItemState.VERIFIED, ReplayItemState.GATED}
            and result.batch.state
            in {
                ReplayBatchState.RUNNING,
                ReplayBatchState.GATING,
                ReplayBatchState.COMPLETED,
            }
            and (
                result.item.state is not ReplayItemState.GATED
                or result.batch.state is ReplayBatchState.COMPLETED
            )
            and result.batch.cas_version > claim.batch.cas_version
            and result.job.lease_expires_at == result.ticket.lease_expires_at
            and result_lease_expiry >= claim_lease_expiry
            and result_heartbeat >= claim_heartbeat
            and result.job.updated_at == result.finalized_at
            and result.item.updated_at >= result.finalized_at
            and result.ticket.updated_at == result.finalized_at
            and result.batch.updated_at >= result.finalized_at
            and result.gate_decision.decided_at <= result.finalized_at
            and result.finalized_at <= result_lease_expiry
        )

    @staticmethod
    def _finalization_result_authority_is_exact(
        claim: ReplayExecutionClaimView,
        result: ReplayFinalizationView,
    ) -> bool:
        decision = result.gate_decision
        if len(decision.replay_lineage) != 1 or result.job.result is None:
            return False
        lineage = decision.replay_lineage[0]
        if lineage.verified_at.tzinfo is None or lineage.verified_at.utcoffset() is None:
            return False

        gate_digest = replay_context_digest(decision.model_dump(mode="json", by_alias=True))
        expected_result_digest = replay_context_digest(
            {
                "artifact": result.artifact.model_dump(mode="json"),
                "artifactSetDigest": result.artifact_set_digest,
                "artifactSealRootDigest": result.artifact_seal_root_digest,
                "batchId": result.batch.batch_id,
                "compilationId": result.ticket.compilation_id,
                "fencingValue": result.ticket.fencing_value,
                "gateDecisionDigest": gate_digest,
                "itemId": result.item.item_id,
                "jobId": result.job.job_id,
                "receiptSealRootDigest": result.receipt_seal_root_digest,
                "ticketId": result.ticket.ticket_id,
            }
        )
        expected_job_result = {
            "kind": "pajin.replay.finalization.v1",
            "finalizationId": result.finalization_id,
            "artifactId": result.artifact.artifact_id,
            "repositoryVersion": result.artifact.repository_version,
            "gateDecisionId": decision.decision_id,
            "resultDigest": expected_result_digest,
        }

        return (
            result.result_digest == expected_result_digest
            and canonical_control_plane_json(result.job.result)
            == canonical_control_plane_json(expected_job_result)
            and result.artifact.media_type == _REPLAY_OUTPUT_MEDIA_TYPE
            and result.artifact.schema_kind == _REPLAY_OUTPUT_SCHEMA_KIND
            and result.artifact.producer_run_id == claim.item.replay_run_id
            and result.artifact.run_id == claim.item.replay_run_id
            and result.artifact.created_by == claim.ticket.claimed_by
            and result.finalized_by == claim.ticket.claimed_by
            and decision.candidate_id == claim.item.candidate_id
            and decision.validator_id == "trusted-core:confirmed-gate"
            and decision.method is ValidationMethod.RESTRICTED_REPLAY_GATE
            and ReplayWorkerDaemon._canonical_gate_result_is_consistent(decision)
            and lineage.replay_run_id == claim.item.replay_run_id
            and lineage.ticket_id == claim.ticket.ticket_id
            and lineage.candidate_source_root_digest == claim.batch.source.integrity_root_digest
            and lineage.artifact_set_digest == result.artifact_set_digest
            and lineage.artifact_seal_root_digest == result.artifact_seal_root_digest
            and lineage.receipt_seal_root_digest == result.receipt_seal_root_digest
            and lineage.verified_at <= decision.decided_at
            and result.artifact.integrity_root_digest == result.receipt_seal_root_digest
        )

    @staticmethod
    def _canonical_gate_result_is_consistent(decision: ValidationDecision) -> bool:
        gate = decision
        if (
            len(gate.reason_codes) != 1
            or len(gate.replay_outcome_ids) != 1
            or gate.supersedes_decision_id is None
        ):
            return False
        reason = gate.reason_codes[0]
        outcome_id = gate.replay_outcome_ids[0]
        expected_decision_id = (
            "decision_replay_"
            + sha256(
                (
                    f"{gate.supersedes_decision_id}|{outcome_id}|pajin.dev/validation/v1alpha1"
                ).encode()
            ).hexdigest()[:24]
        )
        checks = {check.check_id: check for check in gate.checks}
        receipt = checks.get("replay-receipt-integrity")
        lineage = checks.get("replay-lineage")
        oracle = checks.get("replay-oracle")
        reproduction = checks.get("independent-reproduction")
        if any(check is None for check in (receipt, lineage, oracle, reproduction)):
            return False
        assert receipt is not None
        assert lineage is not None
        assert oracle is not None
        assert reproduction is not None

        receipt_exact = (
            receipt.status is ValidationCheckStatus.PASS
            and receipt.reason_code is None
            and receipt.summary
            == "Replay artifacts, both seals, and ticket finalization were reloaded."
        )
        lineage_exact = (
            lineage.status is ValidationCheckStatus.PASS
            and lineage.reason_code is None
            and lineage.summary
            == "Replay Candidate, Run, request, target, and evidence lineage are bound."
        )
        oracle_summaries = {
            ValidationCheckStatus.PASS: "Mode Oracle verdict: supports.",
            ValidationCheckStatus.FAIL: "Mode Oracle verdict: contradicts.",
            ValidationCheckStatus.ERROR: "Mode Oracle verdict: inconclusive.",
            ValidationCheckStatus.NOT_APPLICABLE: (
                "Mode Oracle could not support the claim after terminal replay status."
            ),
        }
        oracle_exact = (
            oracle.status in oracle_summaries
            and oracle.summary == oracle_summaries[oracle.status]
            and (
                oracle.reason_code is None
                if oracle.status is ValidationCheckStatus.PASS
                else oracle.reason_code is reason
            )
        )

        confirmed = gate.disposition is FindingDisposition.CONFIRMED
        reproduction_exact = (
            reproduction.reason_code is reason
            and (
                (confirmed and reproduction.status is ValidationCheckStatus.PASS)
                or (
                    not confirmed
                    and reproduction.status
                    in {
                        ValidationCheckStatus.FAIL,
                        ValidationCheckStatus.NOT_APPLICABLE,
                    }
                )
            )
            and reproduction.summary
            == (
                "Verified Candidate-bound replay satisfied the confirmation invariant."
                if confirmed
                else "Verified replay did not satisfy every confirmation condition."
            )
        )
        confirmation_exact = (
            gate.confirmation_basis is ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY
            and reason is ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED
            and reproduction.status is ValidationCheckStatus.PASS
            if confirmed
            else gate.confirmation_basis is None
            and reproduction.status is not ValidationCheckStatus.PASS
        )
        objective_reasons = {
            ValidationReasonCode.TARGET_UNDECLARED,
            ValidationReasonCode.TARGET_OUT_OF_SCOPE,
            ValidationReasonCode.THREAT_CLASS_UNDECLARED,
            ValidationReasonCode.EVIDENCE_MISSING,
            ValidationReasonCode.EVIDENCE_UNLINKED,
            ValidationReasonCode.EVIDENCE_FILE_MISSING,
            ValidationReasonCode.SOURCE_REQUEST_MISMATCH,
        }
        branch_exact = False
        if reason is ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED:
            branch_exact = (
                gate.disposition is FindingDisposition.CONFIRMED
                and oracle.status is ValidationCheckStatus.PASS
                and reproduction.status is ValidationCheckStatus.PASS
            )
        elif reason is ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING:
            branch_exact = (
                gate.disposition is FindingDisposition.NEEDS_REVIEW
                and oracle.status is ValidationCheckStatus.PASS
                and reproduction.status is ValidationCheckStatus.FAIL
            )
        elif reason is ValidationReasonCode.REPLAY_ORACLE_CONTRADICTED:
            branch_exact = (
                gate.disposition is FindingDisposition.REJECTED_OBJECTIVE
                and oracle.status is ValidationCheckStatus.FAIL
                and reproduction.status is ValidationCheckStatus.FAIL
            )
        elif reason is ValidationReasonCode.REPLAY_ORACLE_INCONCLUSIVE:
            branch_exact = (
                gate.disposition is FindingDisposition.INCONCLUSIVE
                and oracle.status is ValidationCheckStatus.ERROR
                and reproduction.status is ValidationCheckStatus.FAIL
            )
        elif reason in {
            ValidationReasonCode.REPLAY_EXECUTION_FAILED,
            ValidationReasonCode.REPLAY_CANCELLED,
            ValidationReasonCode.REPLAY_TIMED_OUT,
            ValidationReasonCode.REPLAY_TARGET_UNAVAILABLE,
        }:
            branch_exact = (
                gate.disposition is FindingDisposition.INCONCLUSIVE
                and oracle.status is ValidationCheckStatus.NOT_APPLICABLE
                and reproduction.status is ValidationCheckStatus.FAIL
            )
        elif reason is ValidationReasonCode.REPLAY_NOT_ELIGIBLE:
            branch_exact = (
                gate.disposition is FindingDisposition.NEEDS_REVIEW
                and oracle.status is ValidationCheckStatus.NOT_APPLICABLE
                and reproduction.status is ValidationCheckStatus.NOT_APPLICABLE
            )
        elif reason in objective_reasons:
            branch_exact = gate.disposition is FindingDisposition.REJECTED_OBJECTIVE
        elif reason is ValidationReasonCode.CANDIDATE_PRODUCER_NOT_ADMITTED:
            branch_exact = gate.disposition is FindingDisposition.NEEDS_REVIEW
        elif reason is ValidationReasonCode.EXECUTION_FAILED:
            branch_exact = gate.disposition is FindingDisposition.INCONCLUSIVE
        elif reason in {
            ValidationReasonCode.VALIDATOR_DISAGREED,
            ValidationReasonCode.VALIDATOR_OMITTED,
        }:
            branch_exact = (
                gate.disposition is FindingDisposition.NEEDS_REVIEW
                and oracle.status is ValidationCheckStatus.PASS
                and reproduction.status is ValidationCheckStatus.FAIL
            )
        elif reason in {
            ValidationReasonCode.VALIDATOR_UNAVAILABLE,
            ValidationReasonCode.VALIDATOR_CANCELLED,
        }:
            branch_exact = (
                gate.disposition is FindingDisposition.INCONCLUSIVE
                and oracle.status is ValidationCheckStatus.PASS
                and reproduction.status is ValidationCheckStatus.FAIL
            )

        return (
            gate.decision_id == expected_decision_id
            and receipt_exact
            and lineage_exact
            and oracle_exact
            and reproduction_exact
            and confirmation_exact
            and branch_exact
        )

    def _record_cancellation(self, snapshot: ExecutionCancellationSnapshot) -> None:
        self._last_cancellation = snapshot

    def _status(
        self,
        state: ReplayWorkerState,
        *,
        claim: ReplayExecutionClaimView | None = None,
        error: str | None = None,
    ) -> None:
        lifecycle = getattr(self, "_lifecycle", None)
        if lifecycle is not None:
            if state == "fatal":
                lifecycle.fence()
            elif lifecycle.fenced:
                return
        self._phase = state
        path = self._config.status_path
        if path is None:
            return
        status = ReplayWorkerStatus(
            worker_id=self._config.worker_id,
            executor_profile=self._config.executor_profile,
            state=state,
            active_job_id=claim.job.job_id if claim else None,
            active_run_id=claim.job.run_id if claim else None,
            active_ticket_id=claim.ticket.ticket_id if claim else None,
            handled_replays=self._handled_replays,
            last_contact_at=datetime.now(UTC),
            last_error=error[:500] if error else None,
            last_cancellation=self._last_cancellation,
        )
        payload = encode_status(status)
        self._write_status(path, payload)

    @staticmethod
    def _write_status(path: Path, payload: str) -> None:
        write_status_file(path, payload, owner_label="Replay Worker")
