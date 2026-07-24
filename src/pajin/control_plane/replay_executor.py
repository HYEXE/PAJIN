"""Dedicated executor for server-issued exact KISA Replay authorities."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import stat
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from pajin.control_plane.artifact_transfer import PortableArtifactBundle
from pajin.control_plane.artifacts import build_portable_artifact_bundle
from pajin.control_plane.client import (
    ControlPlaneAuthenticationError,
    ControlPlaneLeaseLost,
    ControlPlaneProtocolError,
    ControlPlaneRunCancelled,
    ControlPlaneTransientError,
)
from pajin.control_plane.error_safety import control_plane_cancellation_reason
from pajin.control_plane.execution_attestation import (
    ExecutorExecutionAttestation,
    ExecutorExecutionAttestor,
)
from pajin.control_plane.kisa_derivation import KISA_TARGET_ATTESTED_CLAIM_POLICY_VERSION
from pajin.control_plane.models import (
    KISA_EXACT_REPLAY_EXECUTOR_PROFILE,
    ReplayExecutionClaimView,
    ReplayFinalizeRequest,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
)
from pajin.domain.models import ToolRequest, ToolResult
from pajin.domain.replay import CompiledReplaySpec, replay_argument_digest
from pajin.modes.ai_redteam.replay import kisa_replay_registries
from pajin.policy.engine import PolicyEngine
from pajin.replay.runtime import (
    GatewayRestrictedReproducerRuntime,
    ReplayDispatchAuthority,
    VerifiedReplayResult,
)
from pajin.replay.target_attestation import (
    TargetExecutionChallenge,
    TargetExecutionProxyBinding,
)
from pajin.replay.tickets import (
    ClaimedReplayExecution,
    ReplayExecutionTicket,
    ReplayTicketClaimer,
    ReplayTicketContext,
)
from pajin.runtime.control import (
    BudgetController,
    CancellationKind,
    ExecutionCancellationContext,
)
from pajin.runtime.store import RunStore
from pajin.runtime.worker import WorkerBackend, WorkerJob, WorkerResult
from pajin.tools.ai import (
    AIChatProbeOutput,
    AIChatProbeTool,
    target_execution_proxy_bindings,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.cancellation import record_engine_cleanup, seal_executor_quiescence


class ReplayExecutorControlPlanePort(Protocol):
    async def issue_replay_tool_permit(
        self,
        job_id: str,
        request: ReplayToolPermitRequest,
    ) -> ReplayToolPermitView: ...


@dataclass(frozen=True, slots=True)
class _LocalPortableStage:
    path: Path
    device: int
    inode: int


class _TargetExecutionProofLedger:
    """Per-execution bridge from Control Plane challenges to signed executor proof."""

    def __init__(self, *, required: bool) -> None:
        self.required = required
        self._challenges: dict[str, TargetExecutionChallenge] = {}
        self._proofs: dict[str, list[TargetExecutionProxyBinding]] = {}

    def register(
        self,
        request_id: str,
        challenge: TargetExecutionChallenge | None,
    ) -> None:
        if not self.required:
            return
        if challenge is None or challenge.replay_request_id != request_id:
            raise ControlPlaneProtocolError(
                "target-attested Replay permit omitted its exact challenge"
            )
        if request_id in self._challenges:
            raise ControlPlaneProtocolError("target execution challenge was issued twice")
        self._challenges[request_id] = challenge

    def challenge(self, request_id: str) -> TargetExecutionChallenge | None:
        return self._challenges.get(request_id)

    def record(
        self,
        request_id: str,
        proofs: list[TargetExecutionProxyBinding],
    ) -> None:
        if not self.required or not proofs:
            raise ValueError("target-attested Replay requires at least one exchange proof")
        if request_id in self._proofs:
            raise ValueError("target execution proof was recorded twice")
        self._proofs[request_id] = proofs

    def finalize(
        self,
        permits: tuple[ReplayToolPermitView, ...],
    ) -> list[TargetExecutionProxyBinding] | None:
        if not self.required:
            if self._challenges or self._proofs:
                raise ControlPlaneProtocolError(
                    "legacy Replay unexpectedly accumulated target execution proof"
                )
            return None
        request_ids = [permit.replay_request_id for permit in permits]
        if list(self._challenges) != request_ids or list(self._proofs) != request_ids:
            raise ControlPlaneProtocolError(
                "target execution proof set does not cover every Replay permit"
            )
        return [proof for request_id in request_ids for proof in self._proofs[request_id]]


class _ClaimTicketBackend:
    """Process-local adapter used only to create a self-consistent sealed receipt."""

    def __init__(self, claim: ReplayExecutionClaimView) -> None:
        self.claim = claim
        self.token = object()
        self.final_seal_root_digest: str | None = None
        self.artifact_set_digest: str | None = None

    def claimer(self) -> ReplayTicketClaimer:
        return ReplayTicketClaimer(self, self.token)  # type: ignore[arg-type]

    def _context(self) -> ReplayTicketContext:
        execution = self.claim.execution_context
        return ReplayTicketContext(
            candidate_source_root_digest=self.claim.batch.source.integrity_root_digest,
            campaign_digest=execution.campaign_digest,
            tool_spec_digest=execution.tool_spec_digest,
            scenario_digest=execution.scenario_digest,
        )

    def _claim(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        expected_replay_run_id: str,
        expected_candidate_source_root_digest: str,
        expected_campaign_digest: str,
        claimed_at: datetime,
    ) -> ClaimedReplayExecution:
        context = self._context()
        if (
            token is not self.token
            or ticket.ticket_id != self.claim.ticket.ticket_id
            or expected_replay_run_id != self.claim.execution_context.replay_run_id
            or expected_candidate_source_root_digest != context.candidate_source_root_digest
            or expected_campaign_digest != context.campaign_digest
            or claimed_at.tzinfo is None
            or claimed_at.utcoffset() is None
        ):
            raise PermissionError("Control Plane Replay claim authority differs from execution")
        return ClaimedReplayExecution(
            ticket=ticket,
            compilation=self.claim.compilation,
            compilation_digest=self.claim.item.compilation_digest,
            context=context,
        )

    def _finalize(
        self,
        token: object,
        ticket: ReplayExecutionTicket,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        finalized_at: datetime,
    ) -> None:
        if (
            token is not self.token
            or ticket.ticket_id != self.claim.ticket.ticket_id
            or finalized_at.tzinfo is None
            or finalized_at.utcoffset() is None
        ):
            raise PermissionError("invalid local Replay receipt finalization")
        self.final_seal_root_digest = final_seal_root_digest
        self.artifact_set_digest = artifact_set_digest

    def _verify_finalized(
        self,
        token: object,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        if (
            token is not self.token
            or ticket_id != self.claim.ticket.ticket_id
            or final_seal_root_digest != self.final_seal_root_digest
            or artifact_set_digest != self.artifact_set_digest
            or compilation_digest != self.claim.item.compilation_digest
            or candidate_source_root_digest != self.claim.batch.source.integrity_root_digest
            or replay_run_id != self.claim.item.replay_run_id
        ):
            raise PermissionError("local Replay receipt verification differs from its claim")


class _ControlPlaneDispatchAuthorizer:
    def __init__(
        self,
        *,
        client: ReplayExecutorControlPlanePort,
        claim: ReplayExecutionClaimView,
        clock: Callable[[], datetime],
        permit_attempts: int,
        retry_base_seconds: float,
        retry_max_seconds: float,
        target_proofs: _TargetExecutionProofLedger,
    ) -> None:
        self._client = client
        self._claim = claim
        self._clock = clock
        self._permit_attempts = permit_attempts
        self._retry_base_seconds = retry_base_seconds
        self._retry_max_seconds = retry_max_seconds
        self._target_proofs = target_proofs
        self._permits: list[ReplayToolPermitView] = []

    async def authorize(
        self,
        spec: CompiledReplaySpec,
        *,
        call_ordinal: int,
        request: ToolRequest,
    ) -> ReplayDispatchAuthority:
        claim = self._claim
        permit_request = ReplayToolPermitRequest(
            executor_profile=KISA_EXACT_REPLAY_EXECUTOR_PROFILE,
            lease_token=claim.lease_token,
            ticket_id=claim.ticket.ticket_id,
            fencing_value=claim.ticket.fencing_value,
            call_ordinal=call_ordinal,
        )
        delay = self._retry_base_seconds
        for attempt in range(1, self._permit_attempts + 1):
            try:
                permit = await self._client.issue_replay_tool_permit(
                    claim.job.job_id,
                    permit_request,
                )
                break
            except ControlPlaneTransientError:
                if attempt == self._permit_attempts:
                    raise
                await asyncio.sleep(delay)
                delay = min(delay * 2, self._retry_max_seconds)
        else:
            raise AssertionError("bounded Replay permit retry loop did not return")
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Replay executor clock must be timezone-aware")
        now = now.astimezone(UTC)
        expected_request_units = AIChatProbeTool().network_request_cost(request)
        permit_deadline = min(
            claim.compilation.spec.expires_at,
            claim.compilation.grant.expires_at,
        )
        if not (
            permit.job_id == claim.job.job_id
            and permit.batch_id == claim.batch.batch_id
            and permit.item_id == claim.item.item_id
            and permit.ticket_id == claim.ticket.ticket_id
            and permit.compilation_id == claim.ticket.compilation_id
            and permit.budget_reservation_id == claim.ticket.budget_reservation_id
            and permit.rate_reservation_id == claim.ticket.rate_reservation_id
            and permit.replay_run_id == claim.item.replay_run_id
            and permit.attempt == claim.ticket.attempt
            and permit.fencing_value == claim.ticket.fencing_value
            and permit.call_ordinal == call_ordinal
            and permit.issued_to == claim.ticket.claimed_by
            and permit.executor_profile == KISA_EXACT_REPLAY_EXECUTOR_PROFILE
            and permit.source_root_digest == claim.batch.source.integrity_root_digest
            and permit.compilation_digest == claim.item.compilation_digest
            and permit.grant_digest == claim.item.grant_digest
            and permit.original_request_id == spec.binding.original_request_id
            and permit.tool_id == request.tool_id == spec.binding.tool_id
            and permit.tool_version == spec.binding.tool_version
            and permit.target_id == spec.binding.target_id
            and permit.target == request.target == spec.binding.target
            and permit.method == request.method == spec.method
            and permit.compiled_argument_digest == spec.argument_digest
            and self._request_arguments_match_spec(spec, request)
            and permit.tool_call_units == 1
            and permit.request_units == expected_request_units
            and permit.expires_at <= permit_deadline
            and permit.issued_at <= now < permit.expires_at
        ):
            raise ControlPlaneProtocolError(
                "durable Replay Tool permit differs from the exact dispatch"
            )
        if len(self._permits) != call_ordinal - 1:
            raise ControlPlaneProtocolError(
                "durable Replay Tool permits were not consumed in canonical order"
            )
        self._permits.append(permit)
        self._target_proofs.register(
            permit.replay_request_id,
            permit.target_execution_challenge,
        )
        return ReplayDispatchAuthority(
            request_id=permit.replay_request_id,
            expires_at=permit.expires_at,
            target_execution_challenge=(
                permit.target_execution_challenge if self._target_proofs.required else None
            ),
        )

    @staticmethod
    def _request_arguments_match_spec(
        spec: CompiledReplaySpec,
        request: ToolRequest,
    ) -> bool:
        if set(request.arguments) != set(spec.arguments):
            return False
        if any(
            request.arguments[field] != value
            for field, value in spec.arguments.items()
            if field not in spec.ephemeral_argument_fields
        ):
            return False
        return bool(spec.ephemeral_argument_fields) or (
            replay_argument_digest(request.arguments) == spec.argument_digest
        )

    @property
    def permits(self) -> tuple[ReplayToolPermitView, ...]:
        return tuple(self._permits)


class _ReplayAIChatProbeTool(AIChatProbeTool):
    """Bind the otherwise fixed Tool adapter to one startup-allowlisted image."""

    def __init__(
        self,
        image: str,
        *,
        target_proofs: _TargetExecutionProofLedger | None = None,
    ) -> None:
        probe = WorkerJob(image=image, command=["ai-chat-probe"])
        self._image = probe.image
        self._target_proofs = target_proofs

    def prepare(self, request: ToolRequest) -> WorkerJob:
        prepared = super().prepare(request)
        challenge = (
            self._target_proofs.challenge(request.request_id)
            if self._target_proofs is not None
            else None
        )
        stdin = prepared.stdin
        if challenge is not None:
            payload = json.loads(stdin)
            if not isinstance(payload, dict) or "targetChallenge" in payload:
                raise ValueError("Replay Worker input target challenge is ambiguous")
            payload["targetChallenge"] = challenge.model_dump(mode="json")
            stdin = json.dumps(payload, separators=(",", ":"), allow_nan=False)
        return WorkerJob.model_validate(
            {
                **prepared.model_dump(mode="python"),
                "image": self._image,
                "stdin": stdin,
            }
        )

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        super().validate_trusted_execution(
            request,
            result,
            worker_result,
            network_log_trusted=network_log_trusted,
        )
        if self._target_proofs is None or not self._target_proofs.required:
            return
        challenge = self._target_proofs.challenge(request.request_id)
        if challenge is None:
            raise ValueError("target-attested Replay Tool has no issued challenge")
        typed_result = AIChatProbeOutput.model_validate(result.data)
        proofs = target_execution_proxy_bindings(
            request,
            worker_result,
            typed_result,
            expected_challenge=challenge,
            network_log_trusted=network_log_trusted,
        )
        self._target_proofs.record(request.request_id, proofs)


class KISAExactReplayExecutor:
    """The only Worker executor permitted to consume ``kisa-exact-v1`` claims."""

    profile = KISA_EXACT_REPLAY_EXECUTOR_PROFILE

    def __init__(
        self,
        *,
        client: ReplayExecutorControlPlanePort,
        staging_root: Path,
        worker: WorkerBackend,
        policy: PolicyEngine | None = None,
        clock: Callable[[], datetime] | None = None,
        worker_image: str = "pajin-worker:dev",
        permit_attempts: int = 3,
        retry_base_seconds: float = 0.25,
        retry_max_seconds: float = 5,
        execution_attestor: ExecutorExecutionAttestor | None = None,
    ) -> None:
        if (
            type(permit_attempts) is not int
            or not 1 <= permit_attempts <= 10
            or isinstance(retry_base_seconds, bool)
            or not isinstance(retry_base_seconds, (int, float))
            or isinstance(retry_max_seconds, bool)
            or not isinstance(retry_max_seconds, (int, float))
            or not 0.05 <= retry_base_seconds <= retry_max_seconds <= 60
        ):
            raise ValueError("Replay permit retry configuration is invalid")
        self._client = client
        self._staging_root_input = staging_root.absolute()
        self._staging_root = self._resolve_private_directory(
            self._staging_root_input,
            label="Replay staging root",
        )
        root = self._staging_root.stat()
        self._staging_root_identity = (root.st_dev, root.st_ino)
        self._worker = worker
        self._worker_image = _ReplayAIChatProbeTool(worker_image)._image
        self._policy = policy or PolicyEngine()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_attempts = permit_attempts
        self._retry_base_seconds = float(retry_base_seconds)
        self._retry_max_seconds = float(retry_max_seconds)
        self._execution_attestor = execution_attestor

    async def execute(
        self,
        claim: ReplayExecutionClaimView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ReplayFinalizeRequest:
        if (
            claim.execution_context.required_executor_profile != self.profile
            or claim.ticket.executor_profile != self.profile
        ):
            raise PermissionError("Replay claim requires a different executor profile")
        target_proofs = _TargetExecutionProofLedger(
            required=(claim.batch.policy_version == KISA_TARGET_ATTESTED_CLAIM_POLICY_VERSION)
        )
        replay_tool = _ReplayAIChatProbeTool(
            self._worker_image,
            target_proofs=target_proofs,
        )
        store, local_portable_stage = self._staging_store(claim)
        tools = ToolRegistry()
        tools.register(replay_tool)
        materializers, oracles = kisa_replay_registries(purpose=claim.batch.purpose)
        ticket_backend = _ClaimTicketBackend(claim)
        dispatch_authorizer = _ControlPlaneDispatchAuthorizer(
            client=self._client,
            claim=claim,
            clock=self._clock,
            permit_attempts=self._permit_attempts,
            retry_base_seconds=self._retry_base_seconds,
            retry_max_seconds=self._retry_max_seconds,
            target_proofs=target_proofs,
        )
        runtime = GatewayRestrictedReproducerRuntime(
            tools=tools,
            policy=self._policy,
            worker=self._worker,
            store=store,
            oracles=oracles,
            materializers=materializers,
            tickets=ticket_backend.claimer(),
            budget=BudgetController(claim.execution_context.campaign.spec.budgets),
            rate_limits=RequestRateLimitLedger(),
            clock=self._clock,
            dispatch_authorizer=dispatch_authorizer,
        )
        replay_cancellation = (
            cancellation.fork_for_run(
                engine="restricted-reproducer",
                run_id=store.run_id,
                path=store.path,
            )
            if cancellation is not None
            else None
        )
        verified: VerifiedReplayResult | None = None
        try:
            verified = await runtime.reproduce(
                claim.execution_context.campaign,
                ReplayExecutionTicket(claim.ticket.ticket_id),
                candidate_source_root_digest=claim.batch.source.integrity_root_digest,
                cancellation=replay_cancellation,
            )
        except (
            ControlPlaneAuthenticationError,
            ControlPlaneLeaseLost,
            ControlPlaneProtocolError,
            ControlPlaneTransientError,
        ) as exc:
            if cancellation is not None:
                cancellation.cancel(
                    self._cancellation_kind(exc),
                    control_plane_cancellation_reason(exc),
                )
            if replay_cancellation is not None and replay_cancellation.active:
                receipt_path = store.path / "cancellation.json"
                if not receipt_path.exists():
                    record_engine_cleanup(store, replay_cancellation)
            raise
        finally:
            if replay_cancellation is not None and replay_cancellation.active:
                seal_executor_quiescence(replay_cancellation)
            if verified is None and local_portable_stage is not None:
                with suppress(PermissionError):
                    self._remove_local_portable_stage(local_portable_stage)
                local_portable_stage = None
        if verified is None:  # pragma: no cover - every unsuccessful path raises
            raise RuntimeError("Replay execution returned without a verified result")
        try:
            artifact_bundle, executor_attestation = self._portable_finalization(
                claim=claim,
                verified=verified,
                permits=dispatch_authorizer.permits,
                store=store,
                target_proofs=target_proofs,
            )
        finally:
            if local_portable_stage is not None:
                self._remove_local_portable_stage(local_portable_stage)
        return ReplayFinalizeRequest(
            executor_profile=self.profile,
            lease_token=claim.lease_token,
            ticket_id=claim.ticket.ticket_id,
            fencing_value=claim.ticket.fencing_value,
            output_staging_id=claim.execution_context.output_staging_id,
            artifact_bundle=artifact_bundle,
            executor_attestation=executor_attestation,
        )

    def _portable_finalization(
        self,
        *,
        claim: ReplayExecutionClaimView,
        verified: VerifiedReplayResult,
        permits: tuple[ReplayToolPermitView, ...],
        store: RunStore,
        target_proofs: _TargetExecutionProofLedger,
    ) -> tuple[PortableArtifactBundle | None, ExecutorExecutionAttestation | None]:
        attestor = self._execution_attestor
        if attestor is None:
            return None, None
        if len(permits) != claim.compilation.spec.repetitions:
            raise ControlPlaneProtocolError(
                "executor attestation requires the exact Replay Tool permit set"
            )
        bundle = build_portable_artifact_bundle(store.path)
        attestation = attestor.attest(
            {
                "executor_profile": self.profile,
                "batch_id": claim.batch.batch_id,
                "item_id": claim.item.item_id,
                "job_id": claim.job.job_id,
                "ticket_id": claim.ticket.ticket_id,
                "fencing_value": claim.ticket.fencing_value,
                "replay_run_id": claim.item.replay_run_id,
                "source_root_digest": claim.batch.source.integrity_root_digest,
                "compilation_digest": claim.item.compilation_digest,
                "execution_context_digest": claim.execution_context_digest,
                "permit_digests": [permit.permit_digest for permit in permits],
                "replay_request_ids": [permit.replay_request_id for permit in permits],
                "target_execution_proofs": target_proofs.finalize(permits),
                "artifact_bundle_manifest_sha256": bundle.manifest_sha256,
                "artifact_bundle_file_count": bundle.file_count,
                "artifact_bundle_total_bytes": bundle.total_bytes,
                "artifact_set_digest": verified.receipt.artifact_set_digest,
                "artifact_seal_root_digest": verified.receipt.artifact_seal_root_digest,
                "receipt_seal_root_digest": verified.receipt_seal_root_digest,
            },
            issued_at=self._clock(),
        )
        return bundle, attestation

    def _staging_store(
        self,
        claim: ReplayExecutionClaimView,
    ) -> tuple[RunStore, _LocalPortableStage | None]:
        staging_id = claim.execution_context.output_staging_id
        root = self._resolve_private_directory(
            self._staging_root_input,
            label="Replay staging root",
        )
        root_observed = root.stat()
        if (
            root != self._staging_root
            or (root_observed.st_dev, root_observed.st_ino) != self._staging_root_identity
        ):
            raise PermissionError("Replay staging root identity changed after startup")
        stage_input = root / staging_id
        created_local_stage = False
        if not os.path.lexists(stage_input):
            if self._execution_attestor is None:
                raise PermissionError("Replay staging capability is unavailable")
            try:
                stage_input.mkdir(mode=0o700, exist_ok=False)
                created_local_stage = True
            except OSError as exc:
                raise PermissionError(
                    "portable Replay staging capability cannot be created"
                ) from exc
        stage = self._resolve_private_directory(
            stage_input,
            label="Replay staging capability",
        )
        try:
            stage.relative_to(root)
        except ValueError as exc:
            raise PermissionError("Replay staging capability escapes its configured root") from exc
        observed = stage.stat()
        if any(stage.iterdir()):
            raise PermissionError("Replay staging capability is not fresh")
        (stage / "evidence").mkdir(mode=0o700, exist_ok=False)
        current = stage.stat()
        if (current.st_dev, current.st_ino) != (observed.st_dev, observed.st_ino):
            raise PermissionError("Replay staging capability identity changed during setup")
        if not os.path.lexists(stage_input):
            raise PermissionError("Replay staging capability disappeared during setup")
        local_portable_stage = (
            _LocalPortableStage(
                path=stage,
                device=observed.st_dev,
                inode=observed.st_ino,
            )
            if created_local_stage
            else None
        )
        return RunStore(claim.item.replay_run_id, stage), local_portable_stage

    def _remove_local_portable_stage(self, stage: _LocalPortableStage) -> None:
        if not shutil.rmtree.avoids_symlink_attacks:
            raise PermissionError("portable Replay staging cleanup is not symlink-safe")
        root = self._resolve_private_directory(
            self._staging_root_input,
            label="Replay staging root",
        )
        observed_root = root.stat()
        if (
            root != self._staging_root
            or (observed_root.st_dev, observed_root.st_ino) != self._staging_root_identity
            or stage.path.parent != root
        ):
            raise PermissionError("Replay staging root changed before local cleanup")
        try:
            observed = stage.path.lstat()
        except OSError as exc:
            raise PermissionError(
                "local portable Replay staging disappeared before cleanup"
            ) from exc
        if not stat.S_ISDIR(observed.st_mode) or (observed.st_dev, observed.st_ino) != (
            stage.device,
            stage.inode,
        ):
            raise PermissionError("local portable Replay staging identity changed before cleanup")
        try:
            shutil.rmtree(stage.path)
        except OSError as exc:
            raise PermissionError("local portable Replay staging cleanup failed") from exc
        if os.path.lexists(stage.path):
            raise PermissionError("local portable Replay staging cleanup was incomplete")

    @staticmethod
    def _cancellation_kind(exception: BaseException) -> CancellationKind:
        if isinstance(exception, ControlPlaneRunCancelled):
            return CancellationKind.RUN_CANCELLED
        if isinstance(exception, ControlPlaneLeaseLost):
            return CancellationKind.LEASE_LOST
        return CancellationKind.HEARTBEAT_UNAVAILABLE

    @staticmethod
    def _resolve_private_directory(path: Path, *, label: str) -> Path:
        current = Path(path.anchor)
        try:
            parts = path.parts[1:] if path.anchor else path.parts
            for part in parts:
                current /= part
                observed = current.lstat()
                if stat.S_ISLNK(observed.st_mode):
                    raise PermissionError(f"{label} cannot contain symbolic links")
            resolved = path.resolve(strict=True)
            observed = resolved.stat()
        except PermissionError:
            raise
        except OSError as exc:
            raise PermissionError(f"{label} is unavailable") from exc
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else observed.st_uid
        if not stat.S_ISDIR(observed.st_mode) or observed.st_uid != expected_uid:
            raise PermissionError(f"{label} is not an owner-controlled directory")
        if stat.S_IMODE(observed.st_mode) & 0o077:
            raise PermissionError(f"{label} is accessible by another account")
        return resolved
