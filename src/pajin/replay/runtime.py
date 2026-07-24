"""Restricted replay execution through the ordinary Tool Gateway boundary."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from pydantic import JsonValue, TypeAdapter

from pajin.domain.models import CampaignManifest, ToolRequest
from pajin.domain.replay import (
    CompiledReplaySpec,
    ReplayArtifactSet,
    ReplayAttempt,
    ReplayAttemptStatus,
    ReplayCompilation,
    ReplayExecutionStatus,
    ReplayMaterialization,
    ReplayOracleResult,
    ReplayOracleVerdict,
    ReplayOutcome,
    ReplaySessionPolicy,
    replay_argument_digest,
)
from pajin.policy.engine import PolicyEngine
from pajin.replay import verified_result as _verified_result
from pajin.replay.materializer import (
    ReplayMaterializerRegistry,
    ReplaySessionMaterializer,
)
from pajin.replay.oracle import (
    ReplayModeOracle as ReplayModeOracle,
)
from pajin.replay.oracle import (
    ReplayOracleRegistry as ReplayOracleRegistry,
)
from pajin.replay.tickets import (
    ClaimedReplayExecution,
    ReplayExecutionTicket,
    ReplayTicketClaimer,
    ReplayTicketContext,
    ReplayTicketFinalizationVerifier,
    canonical_replay_compilation_bytes,
    canonical_replay_compilation_payload,
    replay_context_digest,
)
from pajin.replay.verified_result import (
    ReplayVerificationReceipt as ReplayVerificationReceipt,
)
from pajin.replay.verified_result import (
    VerifiedReplayResult as VerifiedReplayResult,
)
from pajin.runtime.control import BudgetController, BudgetExceeded, ExecutionCancellationContext
from pajin.runtime.error_safety import audit_safe_exception_type
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import (
    RunStore,
    load_verified_run_artifacts,
    verify_run_integrity,
)
from pajin.runtime.worker import WorkerBackend, WorkerStatus
from pajin.target_attestation import TargetExecutionChallenge
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import (
    GatewayOutcome,
    RequestRateLimitLedger,
    ToolGateway,
)
from pajin.workflow.cancellation import (
    await_with_cancellation,
    ensure_cancellation_context,
    record_engine_cleanup,
)

_ObservationAdapter = TypeAdapter(dict[str, JsonValue])
_REPLAY_REQUEST_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}\Z")
_REPLAY_SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{2,127}\Z")
_MAX_REPLAY_SNAPSHOT_FILE_BYTES = _verified_result.MAX_REPLAY_SNAPSHOT_FILE_BYTES


class ReplayRuntimeReason(StrEnum):
    """Bounded, secret-free reasons emitted by the restricted runtime."""

    CAMPAIGN_MISMATCH = "campaign-mismatch"
    AUTHORITY_EXPIRED = "authority-expired"
    SECRET_LEASE_UNSUPPORTED = "secret-lease-unsupported"
    TOOL_UNREGISTERED = "tool-unregistered"
    TOOL_CONTRACT_MISMATCH = "tool-contract-mismatch"
    ORACLE_UNREGISTERED = "oracle-unregistered"
    MATERIALIZER_UNREGISTERED = "materializer-unregistered"
    SESSION_MATERIALIZATION_INVALID = "session-materialization-invalid"
    SESSION_POLICY_UNSUPPORTED = "session-policy-unsupported"
    BUDGET_EXHAUSTED = "budget-exhausted"
    REQUEST_ID_INVALID = "request-id-invalid"
    EVIDENCE_LINEAGE_INVALID = "evidence-lineage-invalid"
    ORACLE_FAILED = "oracle-failed"


class RestrictedReplayRuntimeError(RuntimeError):
    """Fail-closed runtime invariant violation raised before Tool dispatch."""

    def __init__(self, reason: ReplayRuntimeReason, message: str) -> None:
        self.reason = reason
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class ReplayDispatchAuthority:
    """One short-lived server authorization for the next exact Tool dispatch."""

    request_id: str
    expires_at: datetime
    target_execution_challenge: TargetExecutionChallenge | None = None


class ReplayDispatchAuthorizer(Protocol):
    """Obtain durable authority immediately before one replay Tool dispatch."""

    async def authorize(
        self,
        spec: CompiledReplaySpec,
        *,
        call_ordinal: int,
        request: ToolRequest,
    ) -> ReplayDispatchAuthority: ...


def load_verified_replay_result(
    run_path: Path,
    *,
    tickets: ReplayTicketFinalizationVerifier,
) -> VerifiedReplayResult:
    """Reload and cross-check replay artifacts, both seals, and ticket finalization."""

    return _verified_result._load_verified_replay_result(
        run_path,
        tickets=tickets,
        reader=_read_regular_file_bytes,
    )


def inspect_sealed_replay_result(run_path: Path) -> VerifiedReplayResult:
    """Read and fully verify sealed output without trusting ticket state."""

    return _verified_result._inspect_sealed_replay_result(
        run_path,
        reader=_read_regular_file_bytes,
    )


def recover_verified_replay_result(
    run_path: Path,
    *,
    tickets: ReplayTicketClaimer,
    recovered_at: datetime | None = None,
) -> VerifiedReplayResult:
    """Recover a claimed ticket from an exact, complete v2 sealed receipt."""

    return _verified_result._recover_verified_replay_result(
        run_path,
        tickets=tickets,
        recovered_at=recovered_at,
        reader=_read_regular_file_bytes,
    )


def _read_regular_file_bytes(root: Path, path: Path, *, label: str) -> bytes:
    """Compatibility hook for bounded replay reads and TOCTOU regression injection."""

    return _verified_result._read_regular_file_bytes(root, path, label=label)


class RestrictedReproducerRuntime(Protocol):
    """Interface for one Candidate-bound, separately sealed replay execution."""

    async def reproduce(
        self,
        campaign: CampaignManifest,
        ticket: ReplayExecutionTicket,
        *,
        candidate_source_root_digest: str,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> VerifiedReplayResult:
        """Claim and execute one compiler-issued replay ticket exactly once."""


@dataclass(slots=True)
class _ReplayExecutionState:
    """Mutable state owned by one single-use restricted replay execution."""

    compilation: ReplayCompilation
    oracle: ReplayModeOracle
    materializer: ReplaySessionMaterializer | None
    gateway: ToolGateway
    cancellation: ExecutionCancellationContext | None
    attempts: list[ReplayAttempt]
    seen_request_ids: set[str]
    seen_session_ids: set[str]
    used_calls: int = 0


@dataclass(frozen=True, slots=True)
class _PreparedReplayAttempt:
    """Exact request and authority window prepared for one Tool dispatch."""

    attempt_number: int
    request: ToolRequest
    materialization: ReplayMaterialization | None
    started_at: datetime
    remaining_seconds: float
    dispatch_authority: ReplayDispatchAuthority | None


@dataclass(frozen=True, slots=True)
class _ReplayTermination:
    """Typed terminal decision awaiting the ordinary sealed finalization path."""

    status: ReplayExecutionStatus
    reason: ReplayRuntimeReason | str
    oracle_result: ReplayOracleResult | None = None
    cancellation_receipt: str | None = None


class GatewayRestrictedReproducerRuntime:
    """Execute a compiled replay with no planning or authority-expansion surface."""

    def __init__(
        self,
        *,
        tools: ToolRegistry,
        policy: PolicyEngine,
        worker: WorkerBackend,
        store: RunStore,
        oracles: ReplayOracleRegistry,
        materializers: ReplayMaterializerRegistry | None = None,
        tickets: ReplayTicketClaimer,
        budget: BudgetController,
        rate_limits: RequestRateLimitLedger,
        secrets: SecretBroker | None = None,
        clock: Callable[[], datetime] | None = None,
        request_id_factory: Callable[[CompiledReplaySpec, int], str] | None = None,
        dispatch_authorizer: ReplayDispatchAuthorizer | None = None,
    ) -> None:
        self._tools = tools
        self._policy = policy
        self._worker = worker
        self._store = store
        self._oracles = oracles
        self._materializers = materializers or ReplayMaterializerRegistry()
        self._tickets = tickets
        self._budget = budget
        self._rate_limits = rate_limits
        self._secrets = secrets
        self._clock = clock or (lambda: datetime.now(UTC))
        self._request_id_factory = request_id_factory or self._new_request_id
        self._dispatch_authorizer = dispatch_authorizer
        self._started = False
        self._claim: ClaimedReplayExecution | None = None

    async def reproduce(
        self,
        campaign: CampaignManifest,
        ticket: ReplayExecutionTicket,
        *,
        candidate_source_root_digest: str,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> VerifiedReplayResult:
        trusted_campaign = CampaignManifest.model_validate_json(campaign.model_dump_json())
        trusted, replay_cancellation = self._start_execution(
            trusted_campaign,
            ReplayExecutionTicket(ticket.ticket_id),
            candidate_source_root_digest=candidate_source_root_digest,
            cancellation=cancellation,
        )
        unsupported = self._preflight(trusted_campaign, trusted)
        if unsupported is not None:
            return self._finish_termination(
                trusted,
                attempts=[],
                termination=_ReplayTermination(
                    status=ReplayExecutionStatus.UNSUPPORTED,
                    reason=unsupported,
                ),
            )

        state = self._execution_state(
            trusted,
            cancellation=replay_cancellation,
        )
        termination = await self._execute_attempts(trusted_campaign, state)
        if termination is None:
            termination = await self._evaluate_oracle(state)
        return self._finish_termination(
            trusted,
            attempts=state.attempts,
            termination=termination,
        )

    def _start_execution(
        self,
        campaign: CampaignManifest,
        ticket: ReplayExecutionTicket,
        *,
        candidate_source_root_digest: str,
        cancellation: ExecutionCancellationContext | None,
    ) -> tuple[ReplayCompilation, ExecutionCancellationContext | None]:
        if self._started:
            raise RuntimeError("restricted replay runtime instances are single-use")
        self._started = True

        self._validate_empty_store()
        claimed = self._tickets.claim(
            ticket,
            expected_replay_run_id=self._store.run_id,
            expected_candidate_source_root_digest=candidate_source_root_digest,
            expected_campaign_digest=replay_context_digest(campaign),
            claimed_at=self._now(),
        )
        self._claim = self._snapshot_claim(claimed)
        trusted = self._claim.compilation
        self._validate_fresh_store(trusted)
        replay_cancellation = self._cancellation_for_run(cancellation)

        self._store.append_event(
            "replay.started",
            self._binding_payload(trusted.spec, grant_id=trusted.grant.grant_id),
        )
        self._write_compilation_artifacts(trusted)
        return trusted, replay_cancellation

    @staticmethod
    def _snapshot_claim(claim: ClaimedReplayExecution) -> ClaimedReplayExecution:
        """Detach the runtime authority from a ticket backend's retained aliases."""

        canonical = canonical_replay_compilation_bytes(claim.compilation)
        return ClaimedReplayExecution(
            ticket=ReplayExecutionTicket(claim.ticket.ticket_id),
            compilation=ReplayCompilation.model_validate_json(canonical),
            compilation_digest=str(claim.compilation_digest),
            context=ReplayTicketContext(
                candidate_source_root_digest=claim.context.candidate_source_root_digest,
                campaign_digest=claim.context.campaign_digest,
                tool_spec_digest=claim.context.tool_spec_digest,
                scenario_digest=claim.context.scenario_digest,
            ),
        )

    def _cancellation_for_run(
        self,
        cancellation: ExecutionCancellationContext | None,
    ) -> ExecutionCancellationContext | None:
        if cancellation is None:
            return None
        binding = cancellation.binding
        if (
            binding is not None
            and binding.engine == "restricted-reproducer"
            and binding.run_id == self._store.run_id
            and binding.path == self._store.path.resolve()
        ):
            # A trusted enclosing executor may already have created the run-local
            # child. Reuse it so that executor quiescence can extend the engine's
            # cancellation receipt after this stack has fully unwound.
            return cancellation
        return cancellation.fork_for_run(
            engine="restricted-reproducer",
            run_id=self._store.run_id,
            path=self._store.path,
        )

    def _execution_state(
        self,
        trusted: ReplayCompilation,
        *,
        cancellation: ExecutionCancellationContext | None,
    ) -> _ReplayExecutionState:
        oracle = self._oracles.resolve(trusted.spec.model_copy(deep=True))
        materializer = (
            self._materializers.resolve(trusted.spec.model_copy(deep=True))
            if trusted.spec.session_policy is ReplaySessionPolicy.FRESH_SESSION
            else None
        )
        gateway = ToolGateway(
            policy=self._policy,
            tools=self._tools,
            worker=self._worker,
            store=self._store,
            secrets=self._secrets,
            rate_limits=self._rate_limits,
            allow_secret_requests=False,
            clock=self._clock,
        )
        return _ReplayExecutionState(
            compilation=trusted,
            oracle=oracle,
            materializer=materializer,
            gateway=gateway,
            cancellation=cancellation,
            attempts=[],
            seen_request_ids=set(),
            seen_session_ids=set(),
        )

    async def _execute_attempts(
        self,
        campaign: CampaignManifest,
        state: _ReplayExecutionState,
    ) -> _ReplayTermination | None:
        for attempt_number in range(1, state.compilation.spec.repetitions + 1):
            prepared = await self._prepare_attempt(state, attempt_number)
            if isinstance(prepared, _ReplayTermination):
                return prepared
            dispatched = await self._dispatch_attempt(campaign, state, prepared)
            if isinstance(dispatched, _ReplayTermination):
                return dispatched

            if dispatched.executed:
                state.used_calls += 1
            attempt, lineage_valid = self._attempt_from_gateway(
                state.compilation,
                state.oracle,
                dispatched,
                attempt_number=prepared.attempt_number,
                request=prepared.request,
                materialization=prepared.materialization,
                started_at=prepared.started_at,
            )
            state.attempts.append(attempt)
            self._record_attempt(attempt)
            if not lineage_valid:
                return _ReplayTermination(
                    status=ReplayExecutionStatus.FAILED,
                    reason=ReplayRuntimeReason.EVIDENCE_LINEAGE_INVALID,
                )
            if attempt.status is not ReplayAttemptStatus.SUCCEEDED:
                if (
                    attempt.status
                    in {
                        ReplayAttemptStatus.CANCELLED,
                        ReplayAttemptStatus.TIMED_OUT,
                        ReplayAttemptStatus.TARGET_UNAVAILABLE,
                    }
                    or not dispatched.decision.allowed
                ):
                    return _ReplayTermination(
                        status=self._execution_status(attempt.status),
                        reason=attempt.status.value,
                    )
                continue
            if state.cancellation is not None and state.cancellation.active:
                verified = self._finish_cancelled(
                    state,
                    reason="cancelled-before-oracle",
                )
                raise asyncio.CancelledError(verified.artifact_set.outcome.outcome_id)
        return None

    async def _prepare_attempt(
        self,
        state: _ReplayExecutionState,
        attempt_number: int,
    ) -> _PreparedReplayAttempt | _ReplayTermination:
        trusted = state.compilation
        try:
            request, materialization = self._request(
                trusted.spec,
                attempt_number,
                state.seen_request_ids,
                state.seen_session_ids,
                state.materializer,
            )
        except RestrictedReplayRuntimeError as exc:
            self._store.append_event(
                "replay.request.rejected",
                {
                    **self._binding_payload(trusted.spec),
                    "attemptNumber": attempt_number,
                    "reason": exc.reason.value,
                },
            )
            return _ReplayTermination(
                status=(
                    ReplayExecutionStatus.FAILED
                    if state.attempts
                    else ReplayExecutionStatus.UNSUPPORTED
                ),
                reason=exc.reason,
            )

        started_at = self._now()
        try:
            self._budget.check_tool_call()
            self._budget.record_tool_call()
        except BudgetExceeded:
            self._append_failed_attempt(
                state,
                attempt_number=attempt_number,
                request=request,
                materialization=materialization,
                status=ReplayAttemptStatus.FAILED,
                started_at=started_at,
                error="shared campaign budget was exhausted before replay dispatch",
            )
            return _ReplayTermination(
                status=ReplayExecutionStatus.FAILED,
                reason=ReplayRuntimeReason.BUDGET_EXHAUSTED,
            )

        remaining = self._remaining_seconds(trusted, started_at)
        if remaining <= 0:
            self._append_failed_attempt(
                state,
                attempt_number=attempt_number,
                request=request,
                materialization=materialization,
                status=ReplayAttemptStatus.TIMED_OUT,
                started_at=started_at,
                error="restricted replay deadline expired before dispatch",
            )
            return _ReplayTermination(
                status=ReplayExecutionStatus.TIMED_OUT,
                reason=self._deadline_reason(trusted, started_at),
            )

        dispatch_authority: ReplayDispatchAuthority | None = None
        if self._dispatch_authorizer is not None:
            authorized = await self._dispatch_authorizer.authorize(
                trusted.spec.model_copy(deep=True),
                call_ordinal=attempt_number,
                request=request.model_copy(deep=True),
            )
            dispatch_authority = ReplayDispatchAuthority(
                request_id=authorized.request_id,
                expires_at=authorized.expires_at,
                target_execution_challenge=authorized.target_execution_challenge,
            )
            request, materialization = self._apply_dispatch_authority(
                trusted.spec,
                attempt_number=attempt_number,
                request=request,
                materialization=materialization,
                authority=dispatch_authority,
                seen_request_ids=state.seen_request_ids,
            )
        state.seen_request_ids.add(request.request_id)
        if materialization is not None:
            session_id = materialization.arguments["session_id"]
            assert isinstance(session_id, str)
            state.seen_session_ids.add(session_id)
        self._store.append_event(
            "replay.attempt.started",
            {
                **self._binding_payload(trusted.spec),
                "attemptNumber": attempt_number,
                "replayRequestId": request.request_id,
                "materializationId": (
                    materialization.materialization_id if materialization is not None else None
                ),
            },
            occurred_at=started_at,
        )
        return _PreparedReplayAttempt(
            attempt_number=attempt_number,
            request=request,
            materialization=materialization,
            started_at=started_at,
            remaining_seconds=remaining,
            dispatch_authority=dispatch_authority,
        )

    async def _dispatch_attempt(
        self,
        campaign: CampaignManifest,
        state: _ReplayExecutionState,
        prepared: _PreparedReplayAttempt,
    ) -> GatewayOutcome | _ReplayTermination:
        trusted = state.compilation
        try:
            authority = prepared.dispatch_authority
            if authority is not None and self._now() >= self._utc(authority.expires_at):
                raise RestrictedReplayRuntimeError(
                    ReplayRuntimeReason.AUTHORITY_EXPIRED,
                    "Replay dispatch permit expired before Tool dispatch",
                )
            async with asyncio.timeout(prepared.remaining_seconds):
                return await await_with_cancellation(
                    state.gateway.execute(
                        campaign.model_copy(deep=True),
                        trusted.grant.model_copy(deep=True),
                        prepared.request.model_copy(deep=True),
                        used_calls=state.used_calls,
                    ),
                    state.cancellation,
                )
        except TimeoutError:
            self._append_failed_attempt(
                state,
                attempt_number=prepared.attempt_number,
                request=prepared.request,
                materialization=prepared.materialization,
                status=ReplayAttemptStatus.TIMED_OUT,
                started_at=prepared.started_at,
                error="restricted replay dispatch exceeded its authority deadline",
            )
            return _ReplayTermination(
                status=ReplayExecutionStatus.TIMED_OUT,
                reason="dispatch-timeout",
            )
        except asyncio.CancelledError:
            self._append_failed_attempt(
                state,
                attempt_number=prepared.attempt_number,
                request=prepared.request,
                materialization=prepared.materialization,
                status=ReplayAttemptStatus.CANCELLED,
                started_at=prepared.started_at,
                error="restricted replay execution was cancelled",
            )
            self._finish_cancelled(state, reason="cancelled")
            raise

    def _append_failed_attempt(
        self,
        state: _ReplayExecutionState,
        *,
        attempt_number: int,
        request: ToolRequest,
        materialization: ReplayMaterialization | None,
        status: ReplayAttemptStatus,
        started_at: datetime,
        error: str,
    ) -> ReplayAttempt:
        attempt = self._failed_attempt(
            state.compilation.spec,
            attempt_number,
            request.request_id,
            status,
            started_at,
            error,
            materialization=materialization,
        )
        state.attempts.append(attempt)
        self._record_attempt(attempt)
        return attempt

    async def _evaluate_oracle(
        self,
        state: _ReplayExecutionState,
    ) -> _ReplayTermination:
        trusted = state.compilation
        failed_attempts = [
            attempt
            for attempt in state.attempts
            if attempt.status is not ReplayAttemptStatus.SUCCEEDED
        ]
        if failed_attempts:
            return _ReplayTermination(
                status=ReplayExecutionStatus.FAILED,
                reason="one-or-more-attempts-failed",
            )

        evaluated_at = self._now()
        oracle_remaining = self._remaining_seconds(trusted, evaluated_at)
        if oracle_remaining <= 0:
            return _ReplayTermination(
                status=ReplayExecutionStatus.TIMED_OUT,
                reason=self._deadline_reason(trusted, evaluated_at),
            )
        private_spec = trusted.spec.model_copy(deep=True)
        private_attempts = tuple(attempt.model_copy(deep=True) for attempt in state.attempts)
        try:
            async with asyncio.timeout(oracle_remaining):
                evaluated = await await_with_cancellation(
                    state.oracle.evaluate(
                        private_spec.model_copy(deep=True),
                        tuple(attempt.model_copy(deep=True) for attempt in private_attempts),
                        evaluated_at=evaluated_at,
                    ),
                    state.cancellation,
                )
            oracle_result = ReplayOracleResult.model_validate_json(
                evaluated.model_dump_json(by_alias=True)
            )
            self._validate_oracle_identity(private_spec, private_attempts, oracle_result)
        except TimeoutError:
            return _ReplayTermination(
                status=ReplayExecutionStatus.TIMED_OUT,
                reason="oracle-timeout",
            )
        except asyncio.CancelledError:
            verified = self._finish_cancelled(
                state,
                reason="cancelled-during-oracle",
            )
            raise asyncio.CancelledError(verified.artifact_set.outcome.outcome_id) from None
        except Exception as exc:
            self._store.append_event(
                "replay.oracle.failed",
                {
                    **self._binding_payload(trusted.spec),
                    "errorType": audit_safe_exception_type(exc),
                },
            )
            return _ReplayTermination(
                status=ReplayExecutionStatus.FAILED,
                reason=ReplayRuntimeReason.ORACLE_FAILED,
            )

        completed_at = self._now()
        if state.cancellation is not None and state.cancellation.active:
            verified = self._finish_cancelled(
                state,
                reason="cancelled-after-oracle",
            )
            raise asyncio.CancelledError(verified.artifact_set.outcome.outcome_id)
        if self._remaining_seconds(trusted, completed_at) <= 0:
            return _ReplayTermination(
                status=ReplayExecutionStatus.TIMED_OUT,
                reason=self._deadline_reason(trusted, completed_at),
            )

        self._store.append_event(
            "replay.oracle.completed",
            {
                **self._binding_payload(trusted.spec),
                "oracleResultId": oracle_result.oracle_result_id,
                "verdict": oracle_result.verdict.value,
                "supportCount": oracle_result.support_count,
                "requiredSupportCount": oracle_result.required_support_count,
            },
            occurred_at=oracle_result.evaluated_at,
        )
        return _ReplayTermination(
            status=ReplayExecutionStatus.SUCCEEDED,
            reason=f"oracle-{oracle_result.verdict.value}",
            oracle_result=oracle_result,
        )

    def _finish_cancelled(
        self,
        state: _ReplayExecutionState,
        *,
        reason: str,
    ) -> VerifiedReplayResult:
        context = ensure_cancellation_context(
            state.cancellation,
            engine="restricted-reproducer",
            store=self._store,
        )
        receipt = record_engine_cleanup(self._store, context)
        return self._finish_termination(
            state.compilation,
            attempts=state.attempts,
            termination=_ReplayTermination(
                status=ReplayExecutionStatus.CANCELLED,
                reason=reason,
                cancellation_receipt=receipt,
            ),
        )

    def _finish_termination(
        self,
        compilation: ReplayCompilation,
        *,
        attempts: list[ReplayAttempt],
        termination: _ReplayTermination,
    ) -> VerifiedReplayResult:
        return self._finish(
            compilation,
            self._outcome(
                compilation.spec,
                termination.status,
                attempts=attempts,
                oracle_result=termination.oracle_result,
            ),
            reason=termination.reason,
            cancellation_receipt=termination.cancellation_receipt,
        )

    def _preflight(
        self,
        campaign: CampaignManifest,
        compilation: ReplayCompilation,
    ) -> ReplayRuntimeReason | None:
        spec = compilation.spec
        binding = spec.binding
        claim = self._claim
        if claim is None:
            return ReplayRuntimeReason.TOOL_CONTRACT_MISMATCH
        campaign_binding = (
            campaign.metadata.name,
            campaign.spec.mode,
            any(
                target.id == binding.target_id and target.endpoint == binding.target
                for target in campaign.spec.targets
            ),
        )
        if campaign_binding != (binding.campaign, binding.mode, True):
            return ReplayRuntimeReason.CAMPAIGN_MISMATCH
        if self._now() >= min(spec.expires_at, compilation.grant.expires_at):
            return ReplayRuntimeReason.AUTHORITY_EXPIRED
        if spec.session_policy is ReplaySessionPolicy.PRESERVE_SCENARIO_SESSION:
            return ReplayRuntimeReason.SESSION_POLICY_UNSUPPORTED
        if spec.session_policy is ReplaySessionPolicy.FRESH_SESSION:
            try:
                materializer = self._materializers.resolve(spec.model_copy(deep=True))
            except KeyError:
                return ReplayRuntimeReason.MATERIALIZER_UNREGISTERED
            if claim.context.scenario_digest != materializer.scenario_digest:
                return ReplayRuntimeReason.MATERIALIZER_UNREGISTERED
        if spec.secret_lease_ids:
            return ReplayRuntimeReason.SECRET_LEASE_UNSUPPORTED
        try:
            tool = self._tools.tool(binding.tool_id)
        except KeyError:
            return ReplayRuntimeReason.TOOL_UNREGISTERED
        actual_tool_contract = (
            tool.spec.tool_id,
            tool.spec.version,
            tool.spec.risk_tier,
            compilation.contract.tool_id,
            compilation.contract.tool_version,
            claim.context.tool_spec_digest,
        )
        expected_tool_contract = (
            binding.tool_id,
            binding.tool_version,
            spec.risk_tier,
            tool.spec.tool_id,
            tool.spec.version,
            replay_context_digest(tool.spec),
        )
        if actual_tool_contract != expected_tool_contract:
            return ReplayRuntimeReason.TOOL_CONTRACT_MISMATCH
        try:
            oracle = self._oracles.resolve(spec.model_copy(deep=True))
        except KeyError:
            return ReplayRuntimeReason.ORACLE_UNREGISTERED
        if claim.context.scenario_digest != oracle.scenario_digest:
            return ReplayRuntimeReason.ORACLE_UNREGISTERED
        return None

    def _attempt_from_gateway(
        self,
        compilation: ReplayCompilation,
        oracle: ReplayModeOracle,
        outcome: GatewayOutcome,
        *,
        attempt_number: int,
        request: ToolRequest,
        materialization: ReplayMaterialization | None,
        started_at: datetime,
    ) -> tuple[ReplayAttempt, bool]:
        spec = compilation.spec
        evidence, lineage_valid = self._validated_evidence(
            compilation,
            request,
            outcome,
        )
        identity_valid = (
            outcome.result.request_id == request.request_id
            and outcome.result.tool_id == spec.binding.tool_id
        )
        lineage_valid = lineage_valid and outcome.result_identity_valid and identity_valid
        finished_at = self._now()
        if outcome.result.success and lineage_valid:
            try:
                return (
                    self._successful_attempt_from_observation(
                        spec=spec,
                        oracle=oracle,
                        outcome=outcome,
                        attempt_number=attempt_number,
                        request=request,
                        materialization=materialization,
                        evidence=evidence,
                        started_at=started_at,
                        finished_at=finished_at,
                    ),
                    lineage_valid,
                )
            except Exception as exc:
                return (
                    self._failed_attempt(
                        spec,
                        attempt_number,
                        request.request_id,
                        ReplayAttemptStatus.FAILED,
                        started_at,
                        f"typed observation rejected: {audit_safe_exception_type(exc)}",
                        evidence=evidence,
                        finished_at=finished_at,
                        materialization=materialization,
                    ),
                    lineage_valid,
                )

        status = self._classified_failure_status(oracle, outcome)
        error = outcome.result.error or "replay Tool execution failed"
        if not identity_valid:
            error = "Tool result identity did not match the fresh replay request"
        elif not lineage_valid:
            error = "Tool evidence did not match the fresh replay lineage"
        return (
            self._failed_attempt(
                spec,
                attempt_number,
                request.request_id,
                status,
                started_at,
                error,
                evidence=evidence,
                finished_at=finished_at,
                materialization=materialization,
            ),
            lineage_valid,
        )

    def _successful_attempt_from_observation(
        self,
        *,
        spec: CompiledReplaySpec,
        oracle: ReplayModeOracle,
        outcome: GatewayOutcome,
        attempt_number: int,
        request: ToolRequest,
        materialization: ReplayMaterialization | None,
        evidence: list[str],
        started_at: datetime,
        finished_at: datetime,
    ) -> ReplayAttempt:
        validated = _ObservationAdapter.validate_python(
            dict(
                oracle.observation(
                    spec.model_copy(deep=True),
                    request.model_copy(deep=True),
                    (
                        materialization.model_copy(deep=True)
                        if materialization is not None
                        else None
                    ),
                    outcome.model_copy(deep=True),
                )
            )
        )
        if not validated:
            raise ValueError("successful replay observation cannot be empty")
        canonical = json.dumps(
            validated,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        if len(canonical) > 1_000_000:
            raise ValueError("typed replay observation exceeds one megabyte")
        return ReplayAttempt(
            attempt_id=self._attempt_id(spec, attempt_number, request.request_id),
            spec_id=spec.spec_id,
            binding=spec.binding,
            attempt_number=attempt_number,
            replay_request_id=request.request_id,
            status=ReplayAttemptStatus.SUCCEEDED,
            observation_schema=spec.observation_schema,
            materialization=materialization,
            observation=_ObservationAdapter.validate_json(canonical),
            evidence=evidence,
            started_at=started_at,
            finished_at=finished_at,
        )

    @staticmethod
    def _classified_failure_status(
        oracle: ReplayModeOracle,
        outcome: GatewayOutcome,
    ) -> ReplayAttemptStatus:
        if outcome.worker_result is not None and (
            outcome.worker_result.status is WorkerStatus.TIMED_OUT
        ):
            return ReplayAttemptStatus.TIMED_OUT
        if outcome.result.success:
            return ReplayAttemptStatus.FAILED
        try:
            classified = oracle.classify_failure(outcome.model_copy(deep=True))
        except Exception:
            return ReplayAttemptStatus.FAILED
        allowed = {
            ReplayAttemptStatus.FAILED,
            ReplayAttemptStatus.TIMED_OUT,
            ReplayAttemptStatus.TARGET_UNAVAILABLE,
        }
        return classified if classified in allowed else ReplayAttemptStatus.FAILED

    def _validated_evidence(
        self,
        compilation: ReplayCompilation,
        request: ToolRequest,
        outcome: GatewayOutcome,
    ) -> tuple[list[str], bool]:
        references = outcome.result.evidence
        unique = list(dict.fromkeys(references))
        expected = f"evidence/{request.request_id}.json"
        if unique != [expected]:
            return [], False
        original = set(compilation.original_evidence)
        root = self._store.path.resolve()
        candidate = root / expected
        if expected in original:
            return [], False
        try:
            payload = parse_strict_json_bytes(
                _read_regular_file_bytes(root, candidate, label="pending evidence"),
                label="pending replay evidence",
                max_bytes=_MAX_REPLAY_SNAPSHOT_FILE_BYTES,
            )
        except (OSError, UnicodeError, ValueError):
            return [], False
        if not isinstance(payload, dict):
            return [], False
        expected_result = outcome.result.model_dump(mode="json")
        expected_result["evidence"] = []
        expected_worker = (
            outcome.worker_result.model_dump(mode="json")
            if outcome.worker_result is not None
            else None
        )
        if (
            payload.get("request") != request.model_dump(mode="json")
            or payload.get("policyDecision") != outcome.decision.model_dump(mode="json")
            or payload.get("result") != expected_result
            or payload.get("networkLogTrusted") is not outcome.network_log_trusted
            or (expected_worker is None and "workerResult" in payload)
            or (expected_worker is not None and payload.get("workerResult") != expected_worker)
        ):
            return [], False
        return [expected], True

    def _request(
        self,
        spec: CompiledReplaySpec,
        attempt_number: int,
        seen_request_ids: set[str],
        seen_session_ids: set[str],
        materializer: ReplaySessionMaterializer | None,
    ) -> tuple[ToolRequest, ReplayMaterialization | None]:
        try:
            generated_request_id = self._request_id_factory(
                spec.model_copy(deep=True),
                attempt_number,
            )
        except Exception as exc:
            raise RestrictedReplayRuntimeError(
                ReplayRuntimeReason.REQUEST_ID_INVALID,
                "replay request identity factory failed",
            ) from exc
        request_id = generated_request_id.strip() if isinstance(generated_request_id, str) else ""
        if (
            _REPLAY_REQUEST_ID.fullmatch(request_id) is None
            or request_id == spec.binding.original_request_id
            or request_id in seen_request_ids
        ):
            raise RestrictedReplayRuntimeError(
                ReplayRuntimeReason.REQUEST_ID_INVALID,
                "replay request identity must be fresh, unique, and bounded",
            )
        arguments = json.loads(
            json.dumps(
                spec.arguments,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
        )
        materialization: ReplayMaterialization | None = None
        if spec.session_policy is ReplaySessionPolicy.FRESH_SESSION:
            if materializer is None:
                raise RestrictedReplayRuntimeError(
                    ReplayRuntimeReason.MATERIALIZER_UNREGISTERED,
                    "fresh-session replay requires a registered materializer",
                )
            try:
                candidate = dict(
                    materializer.materialize(spec.model_copy(deep=True), attempt_number)
                )
                validated_arguments = _ObservationAdapter.validate_python(candidate)
                arguments = _ObservationAdapter.validate_json(
                    json.dumps(
                        validated_arguments,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode()
                )
                self._validate_fresh_arguments(
                    spec,
                    arguments,
                    seen_session_ids=seen_session_ids,
                )
            except Exception as exc:
                raise RestrictedReplayRuntimeError(
                    ReplayRuntimeReason.SESSION_MATERIALIZATION_INVALID,
                    "fresh-session materializer violated the compiled argument boundary",
                ) from exc
            source_session = spec.arguments["session_id"]
            materialized_session = arguments["session_id"]
            assert isinstance(source_session, str)
            assert isinstance(materialized_session, str)
            argument_digest = replay_argument_digest(arguments)
            identity = "|".join(
                [
                    spec.spec_id,
                    str(attempt_number),
                    request_id,
                    argument_digest,
                ]
            )
            materialization = ReplayMaterialization(
                materialization_id=(
                    f"replay-materialization_{sha256(identity.encode('utf-8')).hexdigest()[:32]}"
                ),
                spec_id=spec.spec_id,
                attempt_number=attempt_number,
                replay_request_id=request_id,
                materializer_id=materializer.materializer_id,
                materializer_version=materializer.materializer_version,
                changed_fields={"session_id"},
                source_argument_digest=spec.argument_digest,
                arguments=arguments,
                argument_digest=argument_digest,
                source_session_digest=sha256(source_session.encode("utf-8")).hexdigest(),
                materialized_session_digest=sha256(
                    materialized_session.encode("utf-8")
                ).hexdigest(),
                materialized_at=self._now(),
            )
        request = ToolRequest(
            request_id=request_id,
            agent_id=f"reproducer:{spec.grant_id}",
            tool_id=spec.binding.tool_id,
            target=spec.binding.target,
            method=spec.method,
            arguments=arguments,
        )
        return request, materialization

    @staticmethod
    def _apply_dispatch_authority(
        spec: CompiledReplaySpec,
        *,
        attempt_number: int,
        request: ToolRequest,
        materialization: ReplayMaterialization | None,
        authority: ReplayDispatchAuthority,
        seen_request_ids: set[str],
    ) -> tuple[ToolRequest, ReplayMaterialization | None]:
        request_id = authority.request_id.strip()
        if (
            _REPLAY_REQUEST_ID.fullmatch(request_id) is None
            or request_id == spec.binding.original_request_id
            or request_id in seen_request_ids
            or authority.expires_at.tzinfo is None
            or authority.expires_at.utcoffset() is None
        ):
            raise RestrictedReplayRuntimeError(
                ReplayRuntimeReason.REQUEST_ID_INVALID,
                "Replay dispatch authority returned an invalid request identity",
            )
        authorized_request = request.model_copy(update={"request_id": request_id})
        if materialization is None:
            return authorized_request, None
        identity = "|".join(
            [
                spec.spec_id,
                str(attempt_number),
                request_id,
                materialization.argument_digest,
            ]
        )
        authorized_materialization = materialization.model_copy(
            update={
                "materialization_id": (
                    "replay-materialization_" + sha256(identity.encode("utf-8")).hexdigest()[:32]
                ),
                "replay_request_id": request_id,
            }
        )
        return authorized_request, authorized_materialization

    @staticmethod
    def _validate_fresh_arguments(
        spec: CompiledReplaySpec,
        arguments: Mapping[str, JsonValue],
        *,
        seen_session_ids: set[str],
    ) -> None:
        if set(arguments) != set(spec.arguments):
            raise ValueError("materializer changed the argument field set")
        if spec.ephemeral_argument_fields != {"session_id"}:
            raise ValueError("compiled fresh-session boundary is not session_id-only")
        for field, original in spec.arguments.items():
            if field != "session_id" and arguments[field] != original:
                raise ValueError("materializer changed a non-ephemeral argument")
        source_session = spec.arguments.get("session_id")
        fresh_session = arguments.get("session_id")
        if (
            not isinstance(source_session, str)
            or not isinstance(fresh_session, str)
            or _REPLAY_SESSION_ID.fullmatch(fresh_session) is None
            or fresh_session == source_session
            or fresh_session in seen_session_ids
        ):
            raise ValueError("materializer did not produce a fresh bounded session")

    def _failed_attempt(
        self,
        spec: CompiledReplaySpec,
        attempt_number: int,
        request_id: str,
        status: ReplayAttemptStatus,
        started_at: datetime,
        error: str,
        *,
        evidence: list[str] | None = None,
        finished_at: datetime | None = None,
        materialization: ReplayMaterialization | None = None,
    ) -> ReplayAttempt:
        if status is ReplayAttemptStatus.SUCCEEDED:
            raise ValueError("failed replay attempt cannot use succeeded status")
        return ReplayAttempt(
            attempt_id=self._attempt_id(spec, attempt_number, request_id),
            spec_id=spec.spec_id,
            binding=spec.binding,
            attempt_number=attempt_number,
            replay_request_id=request_id,
            status=status,
            observation_schema=spec.observation_schema,
            materialization=materialization,
            evidence=evidence or [],
            error=error.strip()[:2_000] or "restricted replay attempt failed",
            started_at=self._utc(started_at),
            finished_at=self._utc(finished_at or self._now()),
        )

    def _outcome(
        self,
        spec: CompiledReplaySpec,
        status: ReplayExecutionStatus,
        *,
        attempts: list[ReplayAttempt],
        oracle_result: ReplayOracleResult | None = None,
    ) -> ReplayOutcome:
        completed_at = self._now()
        for attempt in attempts:
            completed_at = max(completed_at, attempt.finished_at)
        if oracle_result is not None:
            completed_at = max(completed_at, oracle_result.evaluated_at)
        identity = "|".join(
            [
                spec.spec_id,
                status.value,
                *(attempt.attempt_id for attempt in attempts),
                oracle_result.oracle_result_id if oracle_result else "no-oracle",
            ]
        )
        return ReplayOutcome(
            outcome_id=f"replay-outcome_{sha256(identity.encode('utf-8')).hexdigest()[:32]}",
            spec_id=spec.spec_id,
            binding=spec.binding,
            execution_status=status,
            attempts=attempts,
            attempt_ids=[attempt.attempt_id for attempt in attempts],
            replay_request_ids=[attempt.replay_request_id for attempt in attempts],
            evidence=list(
                dict.fromkeys(reference for attempt in attempts for reference in attempt.evidence)
            ),
            oracle_result=oracle_result,
            completed_at=completed_at,
        )

    def _finish(
        self,
        compilation: ReplayCompilation,
        outcome: ReplayOutcome,
        *,
        reason: ReplayRuntimeReason | str,
        cancellation_receipt: str | None = None,
    ) -> VerifiedReplayResult:
        artifact_set = ReplayArtifactSet(
            validation_packet=compilation.validation_packet,
            contract=compilation.contract,
            intent=compilation.intent,
            spec=compilation.spec,
            outcome=outcome,
        )
        self._store.write_json(
            "replay/outcome.json",
            outcome.model_dump(mode="json", by_alias=True),
        )
        artifact_set_path = self._store.write_json(
            "replay/artifact-set.json",
            artifact_set.model_dump(mode="json", by_alias=True),
        )
        run_payload: dict[str, object] = {
            "runId": self._store.run_id,
            "status": outcome.execution_status.value,
            "reason": reason.value if isinstance(reason, ReplayRuntimeReason) else reason,
            "candidateId": outcome.binding.candidate_id,
            "candidateRunId": outcome.binding.candidate_run_id,
            "originalRequestId": outcome.binding.original_request_id,
            "specId": outcome.spec_id,
            "outcomeId": outcome.outcome_id,
            "attemptCount": len(outcome.attempts),
            "replayRequestIds": outcome.replay_request_ids,
            "oracleVerdict": (
                outcome.oracle_result.verdict.value if outcome.oracle_result else None
            ),
        }
        if cancellation_receipt is not None:
            run_payload["cancellationReceipt"] = cancellation_receipt
        self._store.write_json("run.json", run_payload)
        self._store.append_event(
            "replay.completed",
            {
                **self._binding_payload(compilation.spec),
                "outcomeId": outcome.outcome_id,
                "executionStatus": outcome.execution_status.value,
                "reason": run_payload["reason"],
                "attemptCount": len(outcome.attempts),
                "replayRequestIds": outcome.replay_request_ids,
                "evidence": outcome.evidence,
            },
            occurred_at=outcome.completed_at,
        )
        artifact_seal = self._store.seal()
        artifact_snapshot = load_verified_run_artifacts(
            self._store.path,
            requests={artifact_set_path: _MAX_REPLAY_SNAPSHOT_FILE_BYTES},
            expected_run_id=self._store.run_id,
        )
        if artifact_snapshot.verification.root_digest != artifact_seal.root_digest:
            raise RuntimeError("replay artifact seal verification returned a different root")
        artifact_set_digest = sha256(artifact_snapshot.artifacts[artifact_set_path]).hexdigest()
        if self._claim is None:
            raise RuntimeError("replay ticket claim is missing at finalization")
        receipt = ReplayVerificationReceipt(
            ticket_id=self._claim.ticket.ticket_id,
            compilation_digest=self._claim.compilation_digest,
            candidate_source_root_digest=(self._claim.context.candidate_source_root_digest),
            replay_run_id=self._store.run_id,
            artifact_set_path=artifact_set_path,
            artifact_set_digest=artifact_set_digest,
            artifact_seal_root_digest=artifact_snapshot.verification.root_digest,
            ticketContext=self._claim.context,
            verified_at=self._now(),
        )
        receipt_path = self._store.write_json(
            "replay/verification-receipt.json",
            receipt.model_dump(mode="json", by_alias=True),
        )
        self._store.append_event(
            "replay.verified",
            {
                **self._binding_payload(compilation.spec),
                "receipt": receipt_path,
                "artifactSet": artifact_set_path,
                "artifactSetDigest": artifact_set_digest,
                "artifactSealRootDigest": artifact_snapshot.verification.root_digest,
            },
            occurred_at=receipt.verified_at,
        )
        self._store.seal()
        final_verification = verify_run_integrity(self._store.path)
        self._tickets.finalize(
            self._claim.ticket,
            final_seal_root_digest=final_verification.root_digest,
            artifact_set_digest=artifact_set_digest,
            finalized_at=self._now(),
        )
        return load_verified_replay_result(
            self._store.path,
            tickets=self._tickets,
        )

    def _write_compilation_artifacts(self, compilation: ReplayCompilation) -> None:
        artifacts = {
            "replay/validation-packet.json": compilation.validation_packet,
            "replay/mode-contract.json": compilation.contract,
            "replay/intent.json": compilation.intent,
            "replay/compiled-spec.json": compilation.spec,
            "replay/capability-grant.json": compilation.grant,
        }
        for path, artifact in artifacts.items():
            self._store.write_json(
                path,
                artifact.model_dump(mode="json", by_alias=True),
            )
        compilation_payload = canonical_replay_compilation_payload(compilation)
        claim = self._claim
        if claim is None:
            raise RuntimeError("replay ticket claim is missing while persisting compilation")
        if replay_context_digest(compilation_payload) != claim.compilation_digest:
            raise RuntimeError("replay ticket digest differs from canonical compilation wire")
        self._store.write_json("replay/compilation.json", compilation_payload)

    def _record_attempt(self, attempt: ReplayAttempt) -> None:
        self._store.append_event(
            "replay.attempt.completed",
            {
                "candidateId": attempt.binding.candidate_id,
                "candidateRunId": attempt.binding.candidate_run_id,
                "originalRequestId": attempt.binding.original_request_id,
                "replayRunId": attempt.binding.replay_run_id,
                "specId": attempt.spec_id,
                "attemptId": attempt.attempt_id,
                "attemptNumber": attempt.attempt_number,
                "replayRequestId": attempt.replay_request_id,
                "materializationId": (
                    attempt.materialization.materialization_id
                    if attempt.materialization is not None
                    else None
                ),
                "status": attempt.status.value,
                "evidence": attempt.evidence,
            },
            occurred_at=attempt.finished_at,
        )

    def _validate_oracle_identity(
        self,
        spec: CompiledReplaySpec,
        attempts: Sequence[ReplayAttempt],
        oracle: ReplayOracleResult,
    ) -> None:
        supporting_attempt_count = sum(
            any(reference in oracle.supporting_evidence for reference in attempt.evidence)
            for attempt in attempts
        )
        contradicting_attempt_count = sum(
            any(reference in oracle.contradicting_evidence for reference in attempt.evidence)
            for attempt in attempts
        )
        verdict_consistent = (
            (
                oracle.verdict is ReplayOracleVerdict.SUPPORTS
                and oracle.support_count >= oracle.required_support_count
                and bool(oracle.supporting_evidence)
            )
            or (
                oracle.verdict is ReplayOracleVerdict.CONTRADICTS
                and oracle.support_count == 0
                and not oracle.supporting_evidence
                and oracle.required_contradiction_count > 0
                and oracle.contradiction_count >= oracle.required_contradiction_count
                and bool(oracle.contradicting_evidence)
            )
            or (
                oracle.verdict is ReplayOracleVerdict.INCONCLUSIVE
                and oracle.support_count < oracle.required_support_count
            )
        )
        if (
            oracle.spec_id != spec.spec_id
            or oracle.binding != spec.binding
            or oracle.oracle_id != spec.oracle_id
            or oracle.oracle_version != spec.oracle_version
            or oracle.observation_schema != spec.observation_schema
            or oracle.attempt_ids != [attempt.attempt_id for attempt in attempts]
            or oracle.required_support_count != spec.required_successes
            or oracle.support_count != supporting_attempt_count
            or oracle.required_contradiction_count != spec.required_contradictions
            or oracle.contradiction_count != contradicting_attempt_count
            or not verdict_consistent
            or any(
                reference not in {item for attempt in attempts for item in attempt.evidence}
                for reference in oracle.supporting_evidence
            )
            or any(
                reference not in {item for attempt in attempts for item in attempt.evidence}
                for reference in oracle.contradicting_evidence
            )
        ):
            raise ValueError("Mode Oracle result does not match the compiled replay")

    def _validate_fresh_store(self, compilation: ReplayCompilation) -> None:
        if self._store.run_id != compilation.spec.binding.replay_run_id:
            raise ValueError("RunStore identity must match the compiled replay Run")
        self._validate_empty_store()

    def _validate_empty_store(self) -> None:
        if (
            self._store.events_path.exists()
            or self._store.integrity_path.exists()
            or (self._store.path / "replay").exists()
        ):
            raise ValueError("restricted replay requires a fresh, unsealed RunStore")

    @staticmethod
    def _binding_payload(
        spec: CompiledReplaySpec,
        *,
        grant_id: str | None = None,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "candidateId": spec.binding.candidate_id,
            "candidateRunId": spec.binding.candidate_run_id,
            "replayRunId": spec.binding.replay_run_id,
            "originalRequestId": spec.binding.original_request_id,
            "specId": spec.spec_id,
            "contractId": spec.contract_id,
            "toolId": spec.binding.tool_id,
            "targetId": spec.binding.target_id,
            "scenarioId": spec.binding.scenario_id,
        }
        if grant_id is not None:
            payload["grantId"] = grant_id
        return payload

    @staticmethod
    def _execution_status(status: ReplayAttemptStatus) -> ReplayExecutionStatus:
        mapping = {
            ReplayAttemptStatus.FAILED: ReplayExecutionStatus.FAILED,
            ReplayAttemptStatus.CANCELLED: ReplayExecutionStatus.CANCELLED,
            ReplayAttemptStatus.TIMED_OUT: ReplayExecutionStatus.TIMED_OUT,
            ReplayAttemptStatus.TARGET_UNAVAILABLE: ReplayExecutionStatus.TARGET_UNAVAILABLE,
        }
        try:
            return mapping[status]
        except KeyError as exc:
            raise ValueError("successful attempt cannot be mapped to a failure outcome") from exc

    @staticmethod
    def _attempt_id(
        spec: CompiledReplaySpec,
        attempt_number: int,
        request_id: str,
    ) -> str:
        digest = sha256(f"{spec.spec_id}|{attempt_number}|{request_id}".encode()).hexdigest()
        return f"replay-attempt_{digest[:32]}"

    @staticmethod
    def _new_request_id(_spec: CompiledReplaySpec, _attempt_number: int) -> str:
        return f"tool_replay_{uuid4().hex}"

    def _now(self) -> datetime:
        return self._utc(self._clock())

    def _remaining_seconds(
        self,
        compilation: ReplayCompilation,
        evaluated_at: datetime,
    ) -> float:
        now = self._utc(evaluated_at)
        return min(
            (compilation.spec.expires_at - now).total_seconds(),
            (compilation.grant.expires_at - now).total_seconds(),
            self._budget.remaining_seconds,
        )

    def _deadline_reason(
        self,
        compilation: ReplayCompilation,
        evaluated_at: datetime,
    ) -> ReplayRuntimeReason:
        if self._budget.remaining_seconds <= 0:
            return ReplayRuntimeReason.BUDGET_EXHAUSTED
        now = self._utc(evaluated_at)
        if now >= compilation.spec.expires_at or now >= compilation.grant.expires_at:
            return ReplayRuntimeReason.AUTHORITY_EXPIRED
        return ReplayRuntimeReason.BUDGET_EXHAUSTED

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)


def replay_run_store(root: Path, campaign_name: str) -> RunStore:
    """Create the fresh replay Run whose ID must be supplied to the compiler."""

    return RunStore.create(root, campaign_name)
