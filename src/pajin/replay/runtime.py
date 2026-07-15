"""Restricted replay execution through the ordinary Tool Gateway boundary."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from pydantic import ConfigDict, Field, JsonValue, TypeAdapter, ValidationError

from pajin.domain.models import CampaignManifest, CampaignMode, StrictModel, ToolRequest
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
from pajin.replay.materializer import (
    ReplayMaterializerRegistry,
    ReplaySessionMaterializer,
)
from pajin.replay.tickets import (
    ClaimedReplayExecution,
    ReplayExecutionTicket,
    ReplayTicketClaimer,
    ReplayTicketFinalizationVerifier,
    replay_context_digest,
)
from pajin.runtime.control import BudgetController, BudgetExceeded, ExecutionCancellationContext
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import (
    RunIntegritySeal,
    RunIntegrityVerification,
    RunStore,
    verify_run_integrity,
)
from pajin.runtime.worker import WorkerBackend, WorkerStatus
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


class ReplayModeOracle(Protocol):
    """Trusted cooperative-async adapter; CPU work needs a separately bounded executor."""

    oracle_id: str
    oracle_version: str
    observation_schema: str
    mode: CampaignMode
    scenario_id: str
    tool_id: str
    scenario_digest: str

    def observation(
        self,
        spec: CompiledReplaySpec,
        request: ToolRequest,
        materialization: ReplayMaterialization | None,
        outcome: GatewayOutcome,
    ) -> Mapping[str, JsonValue]:
        """Normalize a successful Tool result into the declared observation schema."""

    def classify_failure(self, outcome: GatewayOutcome) -> ReplayAttemptStatus:
        """Classify a failed dispatch without turning attacker text into policy."""

    async def evaluate(
        self,
        spec: CompiledReplaySpec,
        attempts: Sequence[ReplayAttempt],
        *,
        evaluated_at: datetime,
    ) -> ReplayOracleResult:
        """Evaluate successful fresh observations against the Mode-owned contract."""


class ReplayOracleRegistry:
    """Explicit allowlist of trusted Mode Oracles keyed by immutable identity."""

    def __init__(self) -> None:
        self._oracles: dict[tuple[str, str, str, str, str, str], ReplayModeOracle] = {}
        self._frozen = False

    def register(self, oracle: ReplayModeOracle) -> None:
        if self._frozen:
            raise RuntimeError("replay Oracle registry is frozen")
        key = self._key(
            oracle.oracle_id,
            oracle.oracle_version,
            oracle.observation_schema,
            oracle.mode,
            oracle.scenario_id,
            oracle.tool_id,
        )
        if len(oracle.scenario_digest) != 64 or any(
            character not in "0123456789abcdef" for character in oracle.scenario_digest
        ):
            raise ValueError("replay Oracle scenario_digest must be a lowercase SHA-256")
        if key in self._oracles:
            raise ValueError(
                "replay Oracle is already registered: "
                f"{oracle.oracle_id}@{oracle.oracle_version}/{oracle.observation_schema}"
            )
        self._oracles[key] = oracle

    def resolve(self, spec: CompiledReplaySpec) -> ReplayModeOracle:
        self._frozen = True
        key = self._key(
            spec.oracle_id,
            spec.oracle_version,
            spec.observation_schema,
            spec.binding.mode,
            spec.binding.scenario_id,
            spec.binding.tool_id,
        )
        try:
            oracle = self._oracles[key]
        except KeyError as exc:
            raise KeyError(
                "unknown replay Oracle: "
                f"{spec.oracle_id}@{spec.oracle_version}/{spec.observation_schema}"
            ) from exc
        if (
            self._key(
                oracle.oracle_id,
                oracle.oracle_version,
                oracle.observation_schema,
                oracle.mode,
                oracle.scenario_id,
                oracle.tool_id,
            )
            != key
        ):
            raise KeyError("registered replay Oracle identity changed after registration")
        return oracle

    @staticmethod
    def _key(
        oracle_id: str,
        version: str,
        observation_schema: str,
        mode: CampaignMode,
        scenario_id: str,
        tool_id: str,
    ) -> tuple[str, str, str, str, str, str]:
        values = (
            oracle_id.strip(),
            version.strip(),
            observation_schema.strip(),
            mode.value,
            scenario_id.strip(),
            tool_id.strip(),
        )
        if any(not value or len(value) > 200 for value in values):
            raise ValueError("replay Oracle identity fields must contain 1-200 characters")
        return values


class ReplayVerificationReceipt(StrictModel):
    """Persisted proof that replay artifacts were sealed and verified."""

    api_version: str = Field(
        default="pajin.dev/replay-verification-receipt/v1",
        alias="apiVersion",
    )
    ticket_id: str
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    candidate_source_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    replay_run_id: str
    artifact_set_path: str
    artifact_set_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    verified_at: datetime


class VerifiedReplayResult(StrictModel):
    """Verified snapshot; confirmation gates must reload it from the sealed Run."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    artifact_set: ReplayArtifactSet
    receipt: ReplayVerificationReceipt
    verification: RunIntegrityVerification
    receipt_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    run_path: Path


def load_verified_replay_result(
    run_path: Path,
    *,
    tickets: ReplayTicketFinalizationVerifier,
) -> VerifiedReplayResult:
    """Reload and cross-check replay artifacts, both seals, and ticket finalization."""

    root = run_path.resolve()
    verification = verify_run_integrity(root)
    artifact_relative = "replay/artifact-set.json"
    receipt_relative = "replay/verification-receipt.json"
    compilation_relative = "replay/compilation.json"
    artifact_path = root / artifact_relative
    receipt_path = root / receipt_relative
    compilation_path = root / compilation_relative
    try:
        artifact_bytes = artifact_path.read_bytes()
        receipt = ReplayVerificationReceipt.model_validate_json(receipt_path.read_bytes())
        artifact_set = ReplayArtifactSet.model_validate_json(artifact_bytes)
        compilation = ReplayCompilation.model_validate_json(compilation_path.read_bytes())
        seals = [
            RunIntegritySeal.model_validate_json(line)
            for line in (root / "run-integrity.jsonl").read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("sealed replay receipt artifacts could not be loaded") from exc

    artifact_digest = sha256(artifact_bytes).hexdigest()
    compilation_digest = replay_context_digest(compilation.model_dump(mode="json", by_alias=True))
    if (
        receipt.replay_run_id != verification.run_id
        or artifact_set.outcome.binding.replay_run_id != verification.run_id
        or receipt.artifact_set_path != artifact_relative
        or receipt.artifact_set_digest != artifact_digest
        or receipt.compilation_digest != compilation_digest
        or artifact_set.validation_packet != compilation.validation_packet
        or artifact_set.contract != compilation.contract
        or artifact_set.intent != compilation.intent
        or artifact_set.spec != compilation.spec
    ):
        raise ValueError("sealed replay receipt does not match its canonical artifacts")
    _validate_materialized_evidence(root, artifact_set)

    artifact_seal_index = next(
        (
            index
            for index, seal in enumerate(seals)
            if seal.root_digest == receipt.artifact_seal_root_digest
        ),
        None,
    )
    if artifact_seal_index is None or artifact_seal_index + 1 >= len(seals):
        raise ValueError("replay artifact seal is missing its receipt extension")
    artifact_record = next(
        (
            artifact
            for seal in seals[: artifact_seal_index + 1]
            for artifact in seal.artifacts
            if artifact.path == artifact_relative
        ),
        None,
    )
    receipt_seal = seals[artifact_seal_index + 1]
    if (
        artifact_record is None
        or artifact_record.sha256 != artifact_digest
        or receipt_seal.previous_root_digest != receipt.artifact_seal_root_digest
        or receipt_relative not in {artifact.path for artifact in receipt_seal.artifacts}
    ):
        raise ValueError("replay receipt is not the direct sealed extension of its artifact set")

    tickets.verify_finalized(
        receipt.ticket_id,
        final_seal_root_digest=receipt_seal.root_digest,
        artifact_set_digest=artifact_digest,
    )
    return VerifiedReplayResult(
        artifact_set=artifact_set,
        receipt=receipt,
        verification=verification,
        receipt_seal_root_digest=receipt_seal.root_digest,
        run_path=root,
    )


def _validate_materialized_evidence(root: Path, artifact_set: ReplayArtifactSet) -> None:
    """Rebind sealed fresh-session records to the exact Gateway request evidence."""

    for attempt in artifact_set.outcome.attempts:
        materialization = attempt.materialization
        if materialization is None or not attempt.evidence:
            continue
        expected_reference = f"evidence/{attempt.replay_request_id}.json"
        if attempt.evidence != [expected_reference]:
            raise ValueError("materialized replay evidence lineage is not exact")
        evidence_path = (root / expected_reference).resolve()
        if root not in evidence_path.parents or not evidence_path.is_file():
            raise ValueError("materialized replay evidence is missing")
        try:
            payload = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("materialized replay evidence could not be loaded") from exc
        request = payload.get("request") if isinstance(payload, dict) else None
        if (
            not isinstance(request, dict)
            or request.get("request_id") != attempt.replay_request_id
            or request.get("arguments") != materialization.arguments
            or replay_argument_digest(materialization.arguments) != materialization.argument_digest
        ):
            raise ValueError("materialized replay evidence does not match its sealed request")


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
        if self._started:
            raise RuntimeError("restricted replay runtime instances are single-use")
        self._started = True

        self._validate_empty_store()
        self._claim = self._tickets.claim(
            ticket,
            expected_replay_run_id=self._store.run_id,
            expected_candidate_source_root_digest=candidate_source_root_digest,
            expected_campaign_digest=replay_context_digest(
                campaign.model_dump(mode="json", by_alias=True)
            ),
            claimed_at=self._now(),
        )
        trusted = self._claim.compilation
        self._validate_fresh_store(trusted)
        replay_cancellation = (
            cancellation.fork_for_run(
                engine="restricted-reproducer",
                run_id=self._store.run_id,
                path=self._store.path,
            )
            if cancellation is not None
            else None
        )

        self._store.append_event(
            "replay.started",
            self._binding_payload(trusted.spec, grant_id=trusted.grant.grant_id),
        )
        self._write_compilation_artifacts(trusted)

        unsupported = self._preflight(campaign, trusted)
        if unsupported is not None:
            return self._finish(
                trusted,
                self._outcome(
                    trusted.spec,
                    ReplayExecutionStatus.UNSUPPORTED,
                    attempts=[],
                ),
                reason=unsupported,
            )

        oracle = self._oracles.resolve(trusted.spec)
        materializer = (
            self._materializers.resolve(trusted.spec)
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
        attempts: list[ReplayAttempt] = []
        seen_request_ids: set[str] = set()
        seen_session_ids: set[str] = set()
        used_calls = 0

        for attempt_number in range(1, trusted.spec.repetitions + 1):
            try:
                request, materialization = self._request(
                    trusted.spec,
                    attempt_number,
                    seen_request_ids,
                    seen_session_ids,
                    materializer,
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
                return self._finish(
                    trusted,
                    self._outcome(
                        trusted.spec,
                        (
                            ReplayExecutionStatus.FAILED
                            if attempts
                            else ReplayExecutionStatus.UNSUPPORTED
                        ),
                        attempts=attempts,
                    ),
                    reason=exc.reason,
                )
            seen_request_ids.add(request.request_id)
            if materialization is not None:
                session_id = materialization.arguments["session_id"]
                assert isinstance(session_id, str)
                seen_session_ids.add(session_id)
            started_at = self._now()
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
            try:
                self._budget.check_tool_call()
                self._budget.record_tool_call()
            except BudgetExceeded:
                attempt = self._failed_attempt(
                    trusted.spec,
                    attempt_number,
                    request.request_id,
                    ReplayAttemptStatus.FAILED,
                    started_at,
                    "shared campaign budget was exhausted before replay dispatch",
                    materialization=materialization,
                )
                attempts.append(attempt)
                self._record_attempt(attempt)
                return self._finish(
                    trusted,
                    self._outcome(
                        trusted.spec,
                        ReplayExecutionStatus.FAILED,
                        attempts=attempts,
                    ),
                    reason=ReplayRuntimeReason.BUDGET_EXHAUSTED,
                )
            remaining = self._remaining_seconds(trusted, started_at)
            if remaining <= 0:
                attempt = self._failed_attempt(
                    trusted.spec,
                    attempt_number,
                    request.request_id,
                    ReplayAttemptStatus.TIMED_OUT,
                    started_at,
                    "restricted replay deadline expired before dispatch",
                    materialization=materialization,
                )
                attempts.append(attempt)
                self._record_attempt(attempt)
                return self._finish(
                    trusted,
                    self._outcome(
                        trusted.spec,
                        ReplayExecutionStatus.TIMED_OUT,
                        attempts=attempts,
                    ),
                    reason=self._deadline_reason(trusted, started_at),
                )

            try:
                async with asyncio.timeout(remaining):
                    gateway_outcome = await await_with_cancellation(
                        gateway.execute(
                            campaign,
                            trusted.grant,
                            request,
                            used_calls=used_calls,
                        ),
                        replay_cancellation,
                    )
            except TimeoutError:
                attempt = self._failed_attempt(
                    trusted.spec,
                    attempt_number,
                    request.request_id,
                    ReplayAttemptStatus.TIMED_OUT,
                    started_at,
                    "restricted replay dispatch exceeded its authority deadline",
                    materialization=materialization,
                )
                attempts.append(attempt)
                self._record_attempt(attempt)
                return self._finish(
                    trusted,
                    self._outcome(
                        trusted.spec,
                        ReplayExecutionStatus.TIMED_OUT,
                        attempts=attempts,
                    ),
                    reason="dispatch-timeout",
                )
            except asyncio.CancelledError:
                attempt = self._failed_attempt(
                    trusted.spec,
                    attempt_number,
                    request.request_id,
                    ReplayAttemptStatus.CANCELLED,
                    started_at,
                    "restricted replay execution was cancelled",
                    materialization=materialization,
                )
                attempts.append(attempt)
                self._record_attempt(attempt)
                context = ensure_cancellation_context(
                    replay_cancellation,
                    engine="restricted-reproducer",
                    store=self._store,
                )
                receipt = record_engine_cleanup(self._store, context)
                self._finish(
                    trusted,
                    self._outcome(
                        trusted.spec,
                        ReplayExecutionStatus.CANCELLED,
                        attempts=attempts,
                    ),
                    reason="cancelled",
                    cancellation_receipt=receipt,
                )
                raise

            if gateway_outcome.executed:
                used_calls += 1
            attempt, lineage_valid = self._attempt_from_gateway(
                trusted,
                oracle,
                gateway_outcome,
                attempt_number=attempt_number,
                request=request,
                materialization=materialization,
                started_at=started_at,
            )
            attempts.append(attempt)
            self._record_attempt(attempt)
            if not lineage_valid:
                return self._finish(
                    trusted,
                    self._outcome(
                        trusted.spec,
                        ReplayExecutionStatus.FAILED,
                        attempts=attempts,
                    ),
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
                    or not gateway_outcome.decision.allowed
                ):
                    return self._finish(
                        trusted,
                        self._outcome(
                            trusted.spec,
                            self._execution_status(attempt.status),
                            attempts=attempts,
                        ),
                        reason=attempt.status.value,
                    )
                continue
            if replay_cancellation is not None and replay_cancellation.active:
                context = ensure_cancellation_context(
                    replay_cancellation,
                    engine="restricted-reproducer",
                    store=self._store,
                )
                receipt = record_engine_cleanup(self._store, context)
                verified = self._finish(
                    trusted,
                    self._outcome(
                        trusted.spec,
                        ReplayExecutionStatus.CANCELLED,
                        attempts=attempts,
                    ),
                    reason="cancelled-before-oracle",
                    cancellation_receipt=receipt,
                )
                raise asyncio.CancelledError(verified.artifact_set.outcome.outcome_id)

        failed_attempts = [
            attempt for attempt in attempts if attempt.status is not ReplayAttemptStatus.SUCCEEDED
        ]
        if failed_attempts:
            return self._finish(
                trusted,
                self._outcome(
                    trusted.spec,
                    ReplayExecutionStatus.FAILED,
                    attempts=attempts,
                ),
                reason="one-or-more-attempts-failed",
            )

        evaluated_at = self._now()
        oracle_remaining = self._remaining_seconds(trusted, evaluated_at)
        if oracle_remaining <= 0:
            return self._finish(
                trusted,
                self._outcome(
                    trusted.spec,
                    ReplayExecutionStatus.TIMED_OUT,
                    attempts=attempts,
                ),
                reason=self._deadline_reason(trusted, evaluated_at),
            )
        try:
            async with asyncio.timeout(oracle_remaining):
                evaluated = await await_with_cancellation(
                    oracle.evaluate(
                        trusted.spec,
                        tuple(attempts),
                        evaluated_at=evaluated_at,
                    ),
                    replay_cancellation,
                )
            oracle_result = ReplayOracleResult.model_validate(
                evaluated.model_dump(mode="python", by_alias=True)
            )
            self._validate_oracle_identity(trusted.spec, attempts, oracle_result)
        except TimeoutError:
            return self._finish(
                trusted,
                self._outcome(
                    trusted.spec,
                    ReplayExecutionStatus.TIMED_OUT,
                    attempts=attempts,
                ),
                reason="oracle-timeout",
            )
        except asyncio.CancelledError:
            context = ensure_cancellation_context(
                replay_cancellation,
                engine="restricted-reproducer",
                store=self._store,
            )
            receipt = record_engine_cleanup(self._store, context)
            verified = self._finish(
                trusted,
                self._outcome(
                    trusted.spec,
                    ReplayExecutionStatus.CANCELLED,
                    attempts=attempts,
                ),
                reason="cancelled-during-oracle",
                cancellation_receipt=receipt,
            )
            raise asyncio.CancelledError(verified.artifact_set.outcome.outcome_id) from None
        except Exception as exc:
            self._store.append_event(
                "replay.oracle.failed",
                {
                    **self._binding_payload(trusted.spec),
                    "errorType": type(exc).__name__,
                },
            )
            return self._finish(
                trusted,
                self._outcome(
                    trusted.spec,
                    ReplayExecutionStatus.FAILED,
                    attempts=attempts,
                ),
                reason=ReplayRuntimeReason.ORACLE_FAILED,
            )

        completed_at = self._now()
        if replay_cancellation is not None and replay_cancellation.active:
            context = ensure_cancellation_context(
                replay_cancellation,
                engine="restricted-reproducer",
                store=self._store,
            )
            receipt = record_engine_cleanup(self._store, context)
            verified = self._finish(
                trusted,
                self._outcome(
                    trusted.spec,
                    ReplayExecutionStatus.CANCELLED,
                    attempts=attempts,
                ),
                reason="cancelled-after-oracle",
                cancellation_receipt=receipt,
            )
            raise asyncio.CancelledError(verified.artifact_set.outcome.outcome_id)
        if self._remaining_seconds(trusted, completed_at) <= 0:
            return self._finish(
                trusted,
                self._outcome(
                    trusted.spec,
                    ReplayExecutionStatus.TIMED_OUT,
                    attempts=attempts,
                ),
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
        return self._finish(
            trusted,
            self._outcome(
                trusted.spec,
                ReplayExecutionStatus.SUCCEEDED,
                attempts=attempts,
                oracle_result=oracle_result,
            ),
            reason=f"oracle-{oracle_result.verdict.value}",
        )

    def _preflight(
        self,
        campaign: CampaignManifest,
        compilation: ReplayCompilation,
    ) -> ReplayRuntimeReason | None:
        spec = compilation.spec
        binding = spec.binding
        if (
            campaign.metadata.name != binding.campaign
            or campaign.spec.mode is not binding.mode
            or not any(
                target.id == binding.target_id and target.endpoint == binding.target
                for target in campaign.spec.targets
            )
        ):
            return ReplayRuntimeReason.CAMPAIGN_MISMATCH
        if self._now() >= spec.expires_at or self._now() >= compilation.grant.expires_at:
            return ReplayRuntimeReason.AUTHORITY_EXPIRED
        if spec.session_policy is ReplaySessionPolicy.PRESERVE_SCENARIO_SESSION:
            return ReplayRuntimeReason.SESSION_POLICY_UNSUPPORTED
        if spec.session_policy is ReplaySessionPolicy.FRESH_SESSION:
            try:
                materializer = self._materializers.resolve(spec)
            except KeyError:
                return ReplayRuntimeReason.MATERIALIZER_UNREGISTERED
            if self._claim.context.scenario_digest != materializer.scenario_digest:
                return ReplayRuntimeReason.MATERIALIZER_UNREGISTERED
        if spec.secret_lease_ids:
            return ReplayRuntimeReason.SECRET_LEASE_UNSUPPORTED
        try:
            tool = self._tools.tool(binding.tool_id)
        except KeyError:
            return ReplayRuntimeReason.TOOL_UNREGISTERED
        if (
            tool.spec.tool_id != binding.tool_id
            or tool.spec.version != binding.tool_version
            or tool.spec.risk_tier != spec.risk_tier
            or compilation.contract.tool_id != tool.spec.tool_id
            or compilation.contract.tool_version != tool.spec.version
            or self._claim is None
            or self._claim.context.tool_spec_digest
            != replay_context_digest(tool.spec.model_dump(mode="json"))
        ):
            return ReplayRuntimeReason.TOOL_CONTRACT_MISMATCH
        try:
            oracle = self._oracles.resolve(spec)
        except KeyError:
            return ReplayRuntimeReason.ORACLE_UNREGISTERED
        if self._claim.context.scenario_digest != oracle.scenario_digest:
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
        lineage_valid = lineage_valid and identity_valid
        finished_at = self._now()
        if outcome.result.success and lineage_valid:
            try:
                observation = _ObservationAdapter.validate_python(
                    dict(oracle.observation(spec, request, materialization, outcome))
                )
                if not observation:
                    raise ValueError("successful replay observation cannot be empty")
                if (
                    len(
                        json.dumps(
                            observation,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode()
                    )
                    > 1_000_000
                ):
                    raise ValueError("typed replay observation exceeds one megabyte")
                return (
                    ReplayAttempt(
                        attempt_id=self._attempt_id(
                            spec,
                            attempt_number,
                            request.request_id,
                        ),
                        spec_id=spec.spec_id,
                        binding=spec.binding,
                        attempt_number=attempt_number,
                        replay_request_id=request.request_id,
                        status=ReplayAttemptStatus.SUCCEEDED,
                        observation_schema=spec.observation_schema,
                        materialization=materialization,
                        observation=observation,
                        evidence=evidence,
                        started_at=started_at,
                        finished_at=finished_at,
                    ),
                    True,
                )
            except (TypeError, ValueError, ValidationError) as exc:
                return (
                    self._failed_attempt(
                        spec,
                        attempt_number,
                        request.request_id,
                        ReplayAttemptStatus.FAILED,
                        started_at,
                        f"typed observation rejected: {type(exc).__name__}",
                        evidence=evidence,
                        finished_at=finished_at,
                        materialization=materialization,
                    ),
                    lineage_valid,
                )

        status = ReplayAttemptStatus.FAILED
        if outcome.worker_result is not None and (
            outcome.worker_result.status is WorkerStatus.TIMED_OUT
        ):
            status = ReplayAttemptStatus.TIMED_OUT
        elif not outcome.result.success:
            try:
                classified = oracle.classify_failure(outcome)
                if classified in {
                    ReplayAttemptStatus.FAILED,
                    ReplayAttemptStatus.TIMED_OUT,
                    ReplayAttemptStatus.TARGET_UNAVAILABLE,
                }:
                    status = classified
            except Exception:
                status = ReplayAttemptStatus.FAILED
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
        candidate = (root / expected).resolve()
        if expected in original or root not in candidate.parents or not candidate.is_file():
            return [], False
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
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
        request_id = self._request_id_factory(spec, attempt_number).strip()
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
                arguments = _ObservationAdapter.validate_python(candidate)
                self._validate_fresh_arguments(
                    spec,
                    arguments,
                    seen_session_ids=seen_session_ids,
                )
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
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
        artifact_verification = verify_run_integrity(self._store.path)
        if artifact_verification.root_digest != artifact_seal.root_digest:
            raise RuntimeError("replay artifact seal verification returned a different root")
        artifact_set_digest = sha256(
            (self._store.path / artifact_set_path).read_bytes()
        ).hexdigest()
        if self._claim is None:
            raise RuntimeError("replay ticket claim is missing at finalization")
        receipt = ReplayVerificationReceipt(
            ticket_id=self._claim.ticket.ticket_id,
            compilation_digest=self._claim.compilation_digest,
            candidate_source_root_digest=(self._claim.context.candidate_source_root_digest),
            replay_run_id=self._store.run_id,
            artifact_set_path=artifact_set_path,
            artifact_set_digest=artifact_set_digest,
            artifact_seal_root_digest=artifact_verification.root_digest,
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
                "artifactSealRootDigest": artifact_verification.root_digest,
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
            "replay/compilation.json": compilation,
        }
        for path, artifact in artifacts.items():
            self._store.write_json(
                path,
                artifact.model_dump(mode="json", by_alias=True),
            )

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
            or not verdict_consistent
            or any(
                reference not in {item for attempt in attempts for item in attempt.evidence}
                for reference in oracle.supporting_evidence
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
