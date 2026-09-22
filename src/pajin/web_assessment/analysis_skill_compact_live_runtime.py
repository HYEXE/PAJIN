"""Cleanup-bound, one-call runtime for the compact WEB-007 request.

This is the additive Gate D path.  It consumes the compact ``system`` plus
``user`` projection and deliberately has no import or fallback to the legacy
analysis runtime, legacy receipt, or a host-path model runtime.

The coordinator keeps the security order explicit: strict reload,
authorization, dual-identity claim, descriptor-bound materialization,
immediate revalidation, one dispatch, durable pending-cleanup, transport then
model cleanup, one sealed receipt, terminal CAS, and strict reload.  A proposal
is returned only after that final reload.
"""

from __future__ import annotations

import asyncio
import os
import sqlite3
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal, Never, Protocol, cast

from pydantic import JsonValue

from pajin.benchmark.effectiveness.suite import RuntimePin
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import ToolRequest
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderRegistration
from pajin.runtime.error_safety import audit_safe_exception_diagnostic
from pajin.runtime.secrets import (
    SecretBroker,
    SecretLease,
    SecretLeaseStatus,
    SecretMaterial,
)
from pajin.runtime.worker import (
    DockerPreCleanupBarrierDeadlineExceeded,
    DockerPreCleanupBarrierError,
    DockerPreCleanupBarrierObservation,
    DockerWorkerBackend,
    DockerWorkerSynchronousPreCleanupBarrier,
    WorkerAttemptOutcome,
    WorkerCleanupError,
    WorkerJob,
    WorkerResult,
)
from pajin.tools.execution_receipts import normalize_host_receipt
from pajin.web_assessment.analysis_capacity_v2 import (
    VerifiedWebAnalysisCapacityV2Run,
    WebAnalysisLiveModelCleanupOnlyResult,
    WebAnalysisLiveModelMaterializationAttestation,
    WebAnalysisLiveModelProviderRouteAttestation,
    WebAnalysisLiveModelResourceAbsenceProof,
)
from pajin.web_assessment.analysis_live_authorization import (
    SignedWebAnalysisOneCallAuthorization,
    VerifiedWebAnalysisOneCallAuthorization,
    WebAnalysisOneCallAuthorizationTrustAnchor,
    WebAnalysisOneCallAuthorizationVerifier,
)
from pajin.web_assessment.analysis_live_claim_journal import (
    DispatchStartedWebAnalysisLiveClaim,
    StartedWebAnalysisLiveClaim,
    WebAnalysisLiveClaimBinding,
    WebAnalysisLiveClaimJournal,
    WebAnalysisLiveClaimJournalEntry,
    WebAnalysisLiveClaimJournalError,
    WebAnalysisLiveClaimPendingOutcome,
    WebAnalysisLiveClaimPhase,
    WebAnalysisLiveClaimTerminalDisposition,
    WebAnalysisLiveClaimTerminalPublication,
    build_web_analysis_live_claim_binding,
)
from pajin.web_assessment.analysis_skill_compact_live_receipts import (
    CompactSkillBoundWebAnalysisCleanupResult,
    CompactSkillBoundWebAnalysisDispatchObservation,
    CompactSkillBoundWebAnalysisTerminalPublication,
    CompactSkillBoundWebAnalysisTerminalReceipt,
    CompactSkillBoundWebAnalysisTransportBinding,
    VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication,
    VerifiedCompactSkillBoundWebAnalysisTerminalRun,
    compact_skill_bound_web_analysis_lease_id,
    compact_skill_bound_web_analysis_terminal_run_id,
    compact_skill_bound_web_analysis_terminal_run_path,
    load_verified_compact_skill_bound_web_analysis_pending_terminal_publication,
    load_verified_compact_skill_bound_web_analysis_terminal_publication_candidate,
    load_verified_compact_skill_bound_web_analysis_terminal_run,
    publish_compact_skill_bound_web_analysis_terminal_run,
    require_compact_skill_bound_web_analysis_terminal_output_root,
)
from pajin.web_assessment.analysis_skill_invocation import (
    CompiledSkillBoundWebAnalysisProposal,
    SkillBoundWebAnalysisProposalDraft,
    compile_skill_bound_web_analysis_proposal,
    parse_skill_bound_web_analysis_proposal_draft,
    verify_compiled_skill_bound_web_analysis_proposal,
)
from pajin.web_assessment.analysis_skill_live_invocation import (
    PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
    PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    plan_prepared_compact_skill_bound_web_analysis_admission,
    verify_planned_prepared_compact_skill_bound_web_analysis_admission,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    VerifiedCompactSkillBoundWebAnalysisPreparationRun,
)
from pajin.web_assessment.analysis_skill_projection import (
    SkillRegistryRef,
    VerifiedWebAnalysisSkillProjectionRun,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportCleanupProof,
    WebAnalysisTransportRuntimePin,
    cleanup_web_analysis_transport_resources,
    expected_web_analysis_provider_worker_context,
    expected_web_analysis_transport_job_metadata,
    interpret_web_analysis_transport_result,
    prepare_web_analysis_transport_job,
    verify_web_analysis_provider_worker_context,
    verify_web_analysis_transport_cleanup_proof,
    verify_web_analysis_transport_job_metadata,
    web_analysis_transport_pre_cleanup_barrier_context,
)
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun

_FailureStage = Literal[
    "reservation",
    "live-start",
    "materialization",
    "materialization-attestation",
    "pre-dispatch-revalidation",
    "dispatch-marker",
    "dispatch",
    "response-validation",
    "proposal-compilation",
    "post-observation-recovery",
    "terminal-publication",
    "quiescent-recovery",
]


class CompactSkillBoundWebAnalysisLiveRuntimeError(RuntimeError):
    """A Gate D operation failed closed without granting retry authority."""

    def __init__(
        self,
        message: str,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry | None = None,
        terminal_run: VerifiedCompactSkillBoundWebAnalysisTerminalRun | None = None,
    ) -> None:
        super().__init__(message)
        self.pending_claim = pending_claim
        self.terminal_run = terminal_run


class CompactSkillBoundWebAnalysisCleanupBlockedError(CompactSkillBoundWebAnalysisLiveRuntimeError):
    """Cleanup or absence proof failed; the exact claim remains pending."""


class _ResultProcessingError(ValueError):
    def __init__(self, stage: _FailureStage, message: str) -> None:
        super().__init__(message)
        self.stage = stage


class CompactSkillBoundWebAnalysisLiveMaterializer(Protocol):
    """Gate A operations required by the compact live coordinator."""

    def materialize(self, capacity_run: VerifiedWebAnalysisCapacityV2Run) -> None: ...

    def live_attestation(self) -> WebAnalysisLiveModelMaterializationAttestation: ...

    def reattest_provider_route(
        self,
        *,
        claim_digest: str,
        resource_owner: str,
        provider_registration_digest: str,
        provider_endpoint: str,
    ) -> WebAnalysisLiveModelProviderRouteAttestation: ...

    def cleanup_owned_resources_and_verify_absent(
        self,
    ) -> tuple[
        WebAnalysisLiveModelCleanupOnlyResult,
        WebAnalysisLiveModelResourceAbsenceProof,
    ]: ...


@dataclass(frozen=True, slots=True)
class CompactSkillBoundWebAnalysisLiveAnchors:
    """Independent anchors retained outside the executing path."""

    source_run_id: str
    source_root_digest: str
    skill_run_id: str
    skill_root_digest: str
    registry_ref: SkillRegistryRef
    policy_digest: str
    capacity_run_id: str
    capacity_root_digest: str
    capacity_pin_digest: str
    capacity_proof_digest: str
    capacity_materialization_attestation_digest: str
    transport_pin_digest: str
    preparation_run_id: str
    preparation_root_digest: str
    preparation_digest: str
    preparation_index_digest: str
    live_request_digest: str
    trust_anchor_digest: str
    claim_store_id: str


@dataclass(frozen=True, slots=True)
class CompactSkillBoundWebAnalysisProcessedResponse:
    """Strict result retained inside the pre-cleanup durability barrier."""

    response_bytes: bytes
    draft: SkillBoundWebAnalysisProposalDraft
    proposal: CompiledSkillBoundWebAnalysisProposal


@dataclass(frozen=True, slots=True)
class CompactSkillBoundWebAnalysisPreparedDispatch:
    """Secret-free, exact projection prepared before the dispatch marker."""

    request: ToolRequest
    job: WorkerJob
    execution_id: str
    external_network: str
    barrier_context: dict[str, JsonValue]
    worker_context: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class CompactSkillBoundWebAnalysisDispatchSettlement:
    """Durable outcome plus positively verified transport cleanup evidence."""

    pending_claim: WebAnalysisLiveClaimJournalEntry
    transport_binding: CompactSkillBoundWebAnalysisTransportBinding
    observation: CompactSkillBoundWebAnalysisDispatchObservation
    transport_cleanup: WebAnalysisTransportCleanupProof
    revoked_lease_ids: tuple[str, ...]
    draft: SkillBoundWebAnalysisProposalDraft | None
    proposal: CompiledSkillBoundWebAnalysisProposal | None
    failure_stage: _FailureStage | None
    failure_digest: str | None


class _CompactLiveDispatchInterrupted(BaseException):
    """Original worker interruption retained until cleanup-bound terminalization."""

    def __init__(
        self,
        settlement: CompactSkillBoundWebAnalysisDispatchSettlement,
        error: BaseException,
    ) -> None:
        super().__init__("compact live dispatch was interrupted after durable observation")
        self.settlement = settlement
        self.error = error


class _CompactLiveDispatchRecoveryRequired(BaseException):
    """Original worker failure retained while transport cleanup is retried."""

    def __init__(
        self,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        error: BaseException,
    ) -> None:
        super().__init__("compact live dispatch requires cleanup-only recovery")
        self.pending_claim = pending_claim
        self.error = error


@dataclass(frozen=True, slots=True)
class CompactSkillBoundWebAnalysisPreparedContext:
    """Exact pre-marker transport evidence persisted by Gate B."""

    transport_binding: CompactSkillBoundWebAnalysisTransportBinding


class CompactSkillBoundWebAnalysisDispatchAdapter(Protocol):
    """Single-use transport with a durable pre-cleanup result barrier."""

    def prepare(
        self,
        *,
        binding: WebAnalysisLiveClaimBinding,
        journal: WebAnalysisLiveClaimJournal,
        registration: ProviderRegistration,
        chat: ProviderChatRequest,
        result_processor: Callable[[WorkerResult], CompactSkillBoundWebAnalysisProcessedResponse],
    ) -> CompactSkillBoundWebAnalysisPreparedDispatch: ...

    def stage_one_call(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> None: ...

    def revalidate_prepared(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> None: ...

    def prepared_context(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> CompactSkillBoundWebAnalysisPreparedContext: ...

    def restore_recovery_context(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        lease_ids: tuple[str, ...],
        transport_binding_digest: str,
        worker_context_digest: str,
        job_metadata_digest: str,
    ) -> None: ...

    def restore_possible_pre_context_recovery(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> None: ...

    async def dispatch_one(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        handle: DispatchStartedWebAnalysisLiveClaim,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement: ...

    def settle_without_dispatch(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        failure_stage: _FailureStage,
        failure_digest: str,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement: ...

    def settle_recovery(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        failure_stage: _FailureStage,
        failure_digest: str,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement: ...


@dataclass(frozen=True, slots=True)
class CompactSkillBoundWebAnalysisLiveCompletion:
    """Strictly reloaded success with every downstream authority fixed false."""

    terminal_run: VerifiedCompactSkillBoundWebAnalysisTerminalRun
    proposal: CompiledSkillBoundWebAnalysisProposal
    dispatch_count: Literal[1] = 1
    target_request_authority: Literal[False] = False
    tool_request_authority: Literal[False] = False
    finding_authority: Literal[False] = False
    graph_admission_authority: Literal[False] = False
    report_authority: Literal[False] = False
    retry_authority: Literal[False] = False
    automatic_redispatch_authority: Literal[False] = False


def _failure_digest(stage: _FailureStage, error: BaseException | None = None) -> str:
    material = {
        "stage": stage,
        "exceptionType": None
        if error is None
        else f"{type(error).__module__}.{type(error).__qualname__}",
    }
    return sha256(
        b"pajin.web-analysis.compact-live-failure/v1\x00"
        + canonical_json_bytes(
            material,
            label="compact live failure class",
            max_bytes=8 * 1024,
        )
    ).hexdigest()


def _is_process_control(error: BaseException) -> bool:
    return isinstance(
        error,
        (
            DockerPreCleanupBarrierError,
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ),
    )


def _raise_original_after_cleanup_failure(
    original_error: BaseException,
    cleanup_error: BaseException,
    *,
    stage: str,
) -> Never:
    original_error.add_note(
        "Cleanup also failed while preserving the original compact live failure: "
        + audit_safe_exception_diagnostic(cleanup_error, stage=stage)
    )
    try:
        raise cleanup_error
    except BaseException:
        raise original_error from original_error.__cause__


def _timestamp(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def _require_proposal_only_result(result: ProviderChatResult) -> bytes:
    if (
        result.streamed
        or result.chunks != 1
        or result.refusal is not None
        or result.tool_calls
        or result.content is None
        or result.content == ""
    ):
        raise ValueError("compact live Provider returned non-proposal output")
    encoded = result.content.encode("utf-8", errors="strict")
    if len(encoded) > 512 * 1024:
        raise ValueError("compact live Provider proposal exceeds the bounded draft size")
    return encoded


def _deterministic_lease_id(
    *,
    claim_digest: str,
    secret_ref: str,
    binding: str,
) -> str:
    return compact_skill_bound_web_analysis_lease_id(
        claim_digest=claim_digest,
        secret_ref=secret_ref,
        binding=binding,
    )


def _pending_after_uncertainty(
    journal: WebAnalysisLiveClaimJournal,
    binding: WebAnalysisLiveClaimBinding,
) -> WebAnalysisLiveClaimJournalEntry:
    current = journal.inspect(binding.claim_id)
    if current is None or current.binding != binding:
        raise CompactSkillBoundWebAnalysisLiveRuntimeError(
            "uncertain live claim has no exact durable binding"
        )
    if current.phase is WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
        return current
    if current.phase is WebAnalysisLiveClaimPhase.TERMINAL:
        raise CompactSkillBoundWebAnalysisLiveRuntimeError(
            "terminal live claim cannot become pending cleanup"
        )
    return journal.recover_binding_pending_cleanup(binding)


def _mark_pending_or_recover(
    journal: WebAnalysisLiveClaimJournal,
    binding: WebAnalysisLiveClaimBinding,
    handle: StartedWebAnalysisLiveClaim | DispatchStartedWebAnalysisLiveClaim,
    *,
    outcome: WebAnalysisLiveClaimPendingOutcome,
) -> WebAnalysisLiveClaimJournalEntry:
    try:
        return journal.mark_pending_cleanup(handle, outcome=outcome)
    except (
        DockerPreCleanupBarrierDeadlineExceeded,
        asyncio.CancelledError,
        SystemExit,
        KeyboardInterrupt,
    ):
        raise
    except BaseException as transition_error:
        try:
            return _pending_after_uncertainty(journal, binding)
        except BaseException as recovery_error:
            recovery_error.add_note(
                "Original pending-cleanup transition failed as "
                f"{type(transition_error).__module__}."
                f"{type(transition_error).__qualname__}"
            )
            raise


def _record_cleanup_failure(
    journal: WebAnalysisLiveClaimJournal,
    pending: WebAnalysisLiveClaimJournalEntry,
    *,
    error: BaseException,
) -> WebAnalysisLiveClaimJournalEntry:
    current = journal.inspect(pending.binding.claim_id)
    if current is None or current.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
        return pending
    return journal.record_cleanup_failure(
        current,
        failure_digest=_failure_digest("terminal-publication", error),
    )


class _JournalPreCleanupBarrier(DockerWorkerSynchronousPreCleanupBarrier):
    """Normalize and compile the raw result before committing pending-cleanup."""

    def __init__(
        self,
        *,
        journal: WebAnalysisLiveClaimJournal,
        binding: WebAnalysisLiveClaimBinding,
        execution_id: str,
        context: dict[str, JsonValue],
        job: WorkerJob,
        result_processor: Callable[[WorkerResult], CompactSkillBoundWebAnalysisProcessedResponse],
    ) -> None:
        self.journal = journal
        self.binding = binding
        self._execution_id = execution_id
        self._context = dict(context)
        self._job = WorkerJob.model_validate(job.model_dump(mode="python"))
        self._result_processor = result_processor
        self._backend: DockerWorkerBackend | None = None
        self._materials: tuple[SecretMaterial, ...] = ()
        self._handle: DispatchStartedWebAnalysisLiveClaim | None = None
        self._called = False
        self.pending_claim: WebAnalysisLiveClaimJournalEntry | None = None
        self.processed: CompactSkillBoundWebAnalysisProcessedResponse | None = None
        self.failure_stage: _FailureStage | None = None
        self.failure_digest: str | None = None

    def stable_barrier_context(self) -> Mapping[str, object]:
        return dict(self._context)

    def bind_normalizer(
        self,
        *,
        backend: DockerWorkerBackend,
        materials: tuple[SecretMaterial, ...],
    ) -> None:
        if self._backend is not None or self._handle is not None or self._called:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live result normalizer was already bound"
            )
        self._backend = backend
        self._materials = tuple(materials)

    def arm(self, handle: DispatchStartedWebAnalysisLiveClaim) -> None:
        if self._backend is None or self._handle is not None or self._called:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live transport barrier cannot be armed"
            )
        self._handle = handle

    def before_cleanup_sync(
        self,
        observation: DockerPreCleanupBarrierObservation,
        result: WorkerResult | None,
    ) -> None:
        if self._called:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live transport barrier was invoked more than once"
            )
        self._called = True
        handle = self._handle
        backend = self._backend
        if handle is None or backend is None:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live transport barrier is not fully armed"
            )
        if observation.execution_id != self._execution_id:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live transport barrier execution identity differs"
            )

        outcome = WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN
        if observation.outcome is WorkerAttemptOutcome.RESULT_OBSERVED and result is not None:
            try:
                raw = WorkerResult.model_validate(result.model_dump(mode="python"))
                if DockerPreCleanupBarrierObservation.from_result(raw) != observation:
                    raise _ResultProcessingError(
                        "response-validation",
                        "raw Worker result differs from its barrier observation",
                    )
                normalized = normalize_host_receipt(
                    backend=backend,
                    job=self._job,
                    result=raw,
                    materials=list(self._materials),
                )
                if normalized.redaction_failed or not normalized.network_log_trusted:
                    raise _ResultProcessingError(
                        "response-validation",
                        "normalized Worker result lacks redaction or host provenance",
                    )
                self.processed = self._result_processor(normalized.worker_result)
                outcome = WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ):
                raise
            except BaseException as error:
                self.failure_stage = (
                    error.stage
                    if isinstance(error, _ResultProcessingError)
                    else "response-validation"
                )
                self.failure_digest = _failure_digest(self.failure_stage, error)
                outcome = WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED
        else:
            self.failure_stage = "dispatch"
            self.failure_digest = _failure_digest("dispatch")

        pending = _mark_pending_or_recover(
            self.journal,
            self.binding,
            handle,
            outcome=outcome,
        )
        if pending.pending_outcome is not outcome:
            self.processed = None
            self.failure_stage = "post-observation-recovery"
            self.failure_digest = _failure_digest("post-observation-recovery")
        self.pending_claim = pending


@dataclass(slots=True)
class _PreparedProductionDispatchState:
    public: CompactSkillBoundWebAnalysisPreparedDispatch
    barrier: _JournalPreCleanupBarrier
    backend: DockerWorkerBackend
    registration: ProviderRegistration
    journal: WebAnalysisLiveClaimJournal
    binding: WebAnalysisLiveClaimBinding
    audience: str
    scope: str
    job_metadata: dict[str, object]
    leases: list[SecretLease] = field(default_factory=list)
    materials: list[SecretMaterial] = field(default_factory=list)
    recovery_lease_ids: tuple[str, ...] = ()
    staged: bool = False
    revalidated: bool = False


class DockerCompactSkillBoundWebAnalysisDispatchAdapter:
    """Production Docker transport; construction and staging never dispatch."""

    def __init__(
        self,
        *,
        runtime: RuntimePin,
        transport_pin: WebAnalysisTransportRuntimePin,
        expected_transport_pin_digest: str,
        secrets: SecretBroker,
        docker_executable: str = "docker",
    ) -> None:
        self._runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        self._transport_pin = WebAnalysisTransportRuntimePin.model_validate(
            transport_pin.model_dump(mode="json", by_alias=True)
        )
        self._expected_transport_pin_digest = expected_transport_pin_digest
        self._secrets = secrets
        self._docker = docker_executable
        self._prepared: _PreparedProductionDispatchState | None = None
        self._attempted = False

    def prepare(
        self,
        *,
        binding: WebAnalysisLiveClaimBinding,
        journal: WebAnalysisLiveClaimJournal,
        registration: ProviderRegistration,
        chat: ProviderChatRequest,
        result_processor: Callable[[WorkerResult], CompactSkillBoundWebAnalysisProcessedResponse],
    ) -> CompactSkillBoundWebAnalysisPreparedDispatch:
        if self._prepared is not None or self._attempted:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live production transport is single-use"
            )
        canonical_registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        execution_id = f"exec_{binding.resources.resource_owner}"
        request = ToolRequest(
            request_id=f"tool_{binding.resources.resource_owner}",
            agent_id="web-analysis-compact-live",
            tool_id=f"provider.{canonical_registration.provider_id}.chat",
            target=str(canonical_registration.endpoint),
            method="POST",
            arguments=chat.model_dump(mode="python", by_alias=True),
        )
        job = prepare_web_analysis_transport_job(
            request,
            registration=canonical_registration,
            runtime=self._runtime,
            transport_pin=self._transport_pin,
            expected_transport_pin_digest=self._expected_transport_pin_digest,
            execution_id=execution_id,
        )
        if len(job.secret_requests) > 1:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live transport requested more than one credential lease"
            )
        barrier_context = web_analysis_transport_pre_cleanup_barrier_context(
            claim_digest=binding.claim_digest,
            execution_id=execution_id,
        )
        barrier = _JournalPreCleanupBarrier(
            journal=journal,
            binding=binding,
            execution_id=execution_id,
            context=barrier_context,
            job=job,
            result_processor=result_processor,
        )
        backend = DockerWorkerBackend(
            allowed_images={self._transport_pin.worker_image},
            docker_executable=self._docker,
            egress_proxy_image=self._transport_pin.proxy_image,
            external_network=binding.resources.network_name,
            external_network_routes={
                self._transport_pin.worker_action: binding.resources.network_name
            },
            pre_cleanup_barrier=barrier,
        )
        worker_context = self._verified_worker_context(
            backend=backend,
            barrier=barrier,
            binding=binding,
            execution_id=execution_id,
        )
        metadata = self._verified_job_metadata(
            request=request,
            registration=canonical_registration,
            execution_id=execution_id,
            lease_ids=(),
        )
        public = CompactSkillBoundWebAnalysisPreparedDispatch(
            request=request,
            job=job,
            execution_id=execution_id,
            external_network=binding.resources.network_name,
            barrier_context=barrier_context,
            worker_context=worker_context,
        )
        self._prepared = _PreparedProductionDispatchState(
            public=public,
            barrier=barrier,
            backend=backend,
            registration=canonical_registration,
            journal=journal,
            binding=binding,
            audience=f"{request.agent_id}:{execution_id}",
            scope=f"claim:{binding.claim_digest}",
            job_metadata=metadata,
        )
        return public

    def stage_one_call(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> None:
        state = self._require_prepared(prepared)
        if state.staged or self._attempted:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live credential staging was already attempted"
            )
        state.staged = True
        possible_lease_ids = tuple(
            _deterministic_lease_id(
                claim_digest=state.binding.claim_digest,
                secret_ref=request.secret_ref,
                binding=request.binding,
            )
            for request in prepared.job.secret_requests
        )
        if len(possible_lease_ids) > 1:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live transport derived too many credential leases"
            )
        state.job_metadata = self._verified_job_metadata(
            request=prepared.request,
            registration=state.registration,
            execution_id=prepared.execution_id,
            lease_ids=possible_lease_ids,
        )
        # Retain every exact identifier before issuance.  issue_exact may
        # durably store a lease and then be interrupted before returning its
        # SecretLease object, so state.leases alone is not recovery authority.
        state.recovery_lease_ids = possible_lease_ids
        try:
            for request, lease_id in zip(
                prepared.job.secret_requests,
                possible_lease_ids,
                strict=True,
            ):
                lease = self._secrets.issue_exact(
                    request.secret_ref,
                    lease_id=lease_id,
                    audience=state.audience,
                    binding=request.binding,
                    scope=state.scope,
                    ttl_seconds=request.ttl_seconds,
                    max_uses=1,
                )
                state.leases.append(lease)
                material = self._secrets.materialize(
                    lease.lease_id,
                    audience=state.audience,
                    scope=state.scope,
                )
                if material.lease_id != lease.lease_id or material.binding != lease.binding:
                    raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                        "compact live secret material binding differs"
                    )
                state.materials.append(material)
            if len(state.leases) > 1:
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live transport staged too many credential leases"
                )
            if tuple(lease.lease_id for lease in state.leases) != possible_lease_ids:
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live staged credential lease identity differs"
                )
            state.barrier.bind_normalizer(
                backend=state.backend,
                materials=tuple(state.materials),
            )
        except BaseException:
            # Do not hide partial state.  The caller already owns a durable
            # claim and will enter settle_without_dispatch, which proves every
            # revocation before any terminal receipt can exist.
            raise

    def revalidate_prepared(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> None:
        state = self._require_prepared(prepared)
        if not state.staged or state.revalidated or self._attempted:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live prepared transport cannot be revalidated"
            )
        rebound = prepare_web_analysis_transport_job(
            prepared.request,
            registration=state.registration,
            runtime=self._runtime,
            transport_pin=self._transport_pin,
            expected_transport_pin_digest=self._expected_transport_pin_digest,
            execution_id=prepared.execution_id,
        )
        if rebound != prepared.job:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live Worker job changed before dispatch"
            )
        context = self._verified_worker_context(
            backend=state.backend,
            barrier=state.barrier,
            binding=state.binding,
            execution_id=prepared.execution_id,
        )
        if context != prepared.worker_context:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live Worker context changed before dispatch"
            )
        lease_ids = tuple(lease.lease_id for lease in state.leases)
        metadata = self._verified_job_metadata(
            request=prepared.request,
            registration=state.registration,
            execution_id=prepared.execution_id,
            lease_ids=lease_ids,
        )
        if metadata != state.job_metadata:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live Worker metadata changed before dispatch"
            )
        for issued in state.leases:
            observed = self._secrets.inspect(
                issued.lease_id,
                audience=state.audience,
                scope=state.scope,
            )
            if (
                observed.lease_id != issued.lease_id
                or observed.audience != state.audience
                or observed.scope != state.scope
                or observed.binding != issued.binding
                or observed.max_uses != 1
                or observed.remaining_uses != 0
                or observed.status is not SecretLeaseStatus.ACTIVE
            ):
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live credential lease changed before dispatch"
                )
        state.revalidated = True

    def prepared_context(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> CompactSkillBoundWebAnalysisPreparedContext:
        state = self._require_prepared(prepared)
        if not state.revalidated or self._attempted:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live pre-marker context is not revalidated"
            )
        lease_ids = tuple(lease.lease_id for lease in state.leases)
        return CompactSkillBoundWebAnalysisPreparedContext(
            transport_binding=self._transport_binding(state, lease_ids=lease_ids)
        )

    def restore_recovery_context(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        lease_ids: tuple[str, ...],
        transport_binding_digest: str,
        worker_context_digest: str,
        job_metadata_digest: str,
    ) -> None:
        state = self._require_prepared(prepared)
        if state.staged or state.revalidated or self._attempted:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live recovery transport was already activated"
            )
        state.job_metadata = self._verified_job_metadata(
            request=prepared.request,
            registration=state.registration,
            execution_id=prepared.execution_id,
            lease_ids=lease_ids,
        )
        binding = self._transport_binding(state, lease_ids=lease_ids)
        if (
            binding.binding_digest != transport_binding_digest
            or binding.worker_context_digest != worker_context_digest
            or binding.job_metadata_digest != job_metadata_digest
        ):
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live recovery transport evidence differs"
            )
        state.recovery_lease_ids = lease_ids
        # No credential is issued or materialized in recovery.  A later cleanup
        # step may only prove the exact deterministic ID revoked/absent.
        state.revalidated = True

    def restore_possible_pre_context_recovery(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> None:
        """Assume every deterministic pre-context lease may have been issued.

        A crash can occur after exact-ID issuance but before the Gate-D context
        CAS.  Recovery therefore never treats a missing optional context group
        as evidence that the fixed Worker job held no credential.
        """

        state = self._require_prepared(prepared)
        if state.staged or state.revalidated or self._attempted:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live pre-context recovery transport was already activated"
            )
        possible = tuple(
            _deterministic_lease_id(
                claim_digest=state.binding.claim_digest,
                secret_ref=request.secret_ref,
                binding=request.binding,
            )
            for request in prepared.job.secret_requests
        )
        if len(possible) > 1:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live pre-context recovery derived too many leases"
            )
        state.job_metadata = self._verified_job_metadata(
            request=prepared.request,
            registration=state.registration,
            execution_id=prepared.execution_id,
            lease_ids=possible,
        )
        state.recovery_lease_ids = possible
        state.revalidated = True

    async def dispatch_one(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        handle: DispatchStartedWebAnalysisLiveClaim,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        state = self._require_prepared(prepared)
        if self._attempted or not state.revalidated:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live production transport cannot dispatch"
            )
        self._attempted = True
        state.barrier.arm(handle)
        worker_error: BaseException | None = None
        try:
            await state.backend.run(prepared.job, secrets=list(state.materials))
        except BaseException as error:
            worker_error = error
            if state.barrier.pending_claim is None:
                try:
                    state.barrier.pending_claim = _mark_pending_or_recover(
                        state.journal,
                        state.binding,
                        handle,
                        outcome=WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN,
                    )
                except (
                    DockerPreCleanupBarrierDeadlineExceeded,
                    asyncio.CancelledError,
                    SystemExit,
                    KeyboardInterrupt,
                ) as transition_interruption:
                    # Preserve process-control/deadline identity, but defer its
                    # propagation until independent transport cleanup finishes.
                    worker_error = transition_interruption
                    state.barrier.pending_claim = _pending_after_uncertainty(
                        state.journal,
                        state.binding,
                    )
                except BaseException:
                    state.barrier.pending_claim = _pending_after_uncertainty(
                        state.journal,
                        state.binding,
                    )
                state.barrier.failure_stage = "dispatch"
                state.barrier.failure_digest = _failure_digest("dispatch", error)

        pending = state.barrier.pending_claim
        if pending is None:
            pending = _pending_after_uncertainty(state.journal, state.binding)
            state.barrier.pending_claim = pending
            state.barrier.failure_stage = "dispatch"
            state.barrier.failure_digest = _failure_digest("dispatch", worker_error)

        cleanup, revoked = self._cleanup_after_dispatch_attempt(
            state,
            prepared=prepared,
            pending=pending,
            worker_error=worker_error,
        )
        primary_worker_error = (
            worker_error
            if worker_error is not None and not isinstance(worker_error, WorkerCleanupError)
            else None
        )
        if primary_worker_error is not None:
            interruption_digest = _failure_digest(
                "post-observation-recovery",
                primary_worker_error,
            )
            state.barrier.processed = None
            state.barrier.failure_stage = "post-observation-recovery"
            state.barrier.failure_digest = interruption_digest
            settlement = self._dispatch_settlement(
                state,
                transport_cleanup=cleanup,
                revoked_lease_ids=revoked,
            )
            raise _CompactLiveDispatchInterrupted(
                settlement,
                primary_worker_error,
            ) from primary_worker_error

        return self._dispatch_settlement(
            state,
            transport_cleanup=cleanup,
            revoked_lease_ids=revoked,
        )

    def _cleanup_after_dispatch_attempt(
        self,
        state: _PreparedProductionDispatchState,
        *,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        pending: WebAnalysisLiveClaimJournalEntry,
        worker_error: BaseException | None,
    ) -> tuple[WebAnalysisTransportCleanupProof, tuple[str, ...]]:
        revoked, revoke_error, revoke_process_control = self._revoke_staged(state)
        cleanup: WebAnalysisTransportCleanupProof | None = None
        cleanup_error: BaseException | None = None
        cleanup_process_control: BaseException | None = None
        try:
            cleanup = self._cleanup_transport(prepared)
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ) as error:
            cleanup_process_control = error
        except BaseException as error:
            cleanup_error = error
        process_control = (
            worker_error
            if worker_error is not None and _is_process_control(worker_error)
            else revoke_process_control or cleanup_process_control
        )
        blocking_error = revoke_error or cleanup_error
        primary_worker_error = (
            worker_error
            if worker_error is not None and not isinstance(worker_error, WorkerCleanupError)
            else None
        )
        if process_control is not None and (blocking_error is not None or cleanup is None):
            try:
                _record_cleanup_failure(
                    state.journal,
                    pending,
                    error=blocking_error or RuntimeError("transport cleanup evidence is absent"),
                )
            except BaseException as record_error:
                _raise_original_after_cleanup_failure(
                    process_control,
                    record_error,
                    stage="docker-cleanup",
                )
            if blocking_error is not None:
                _raise_original_after_cleanup_failure(
                    process_control,
                    blocking_error,
                    stage="docker-cleanup",
                )
            raise process_control from process_control.__cause__
        if blocking_error is not None or cleanup is None:
            recorded = _record_cleanup_failure(
                state.journal,
                pending,
                error=blocking_error or RuntimeError("transport cleanup evidence is absent"),
            )
            if primary_worker_error is not None:
                raise _CompactLiveDispatchRecoveryRequired(
                    recorded,
                    primary_worker_error,
                ) from primary_worker_error
            raise CompactSkillBoundWebAnalysisCleanupBlockedError(
                "compact live transport or credential cleanup failed",
                pending_claim=recorded,
            ) from blocking_error

        return cleanup, revoked

    def settle_without_dispatch(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        failure_stage: _FailureStage,
        failure_digest: str,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        state = self._require_prepared(prepared)
        cleanup, revoked = self._cleanup_before_terminal(state, pending_claim)
        return self._non_dispatch_settlement(
            state,
            pending_claim=pending_claim,
            cleanup=cleanup,
            revoked_lease_ids=revoked,
            failure_stage=failure_stage,
            failure_digest=failure_digest,
        )

    def settle_recovery(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        failure_stage: _FailureStage,
        failure_digest: str,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        state = self._require_prepared(prepared)
        cleanup, revoked = self._cleanup_before_terminal(state, pending_claim)
        return self._recovery_settlement(
            state,
            pending_claim=pending_claim,
            cleanup=cleanup,
            revoked_lease_ids=revoked,
            failure_stage=failure_stage,
            failure_digest=failure_digest,
        )

    def _require_prepared(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> _PreparedProductionDispatchState:
        state = self._prepared
        if state is None or prepared != state.public:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live prepared transport identity differs"
            )
        return state

    def _verified_worker_context(
        self,
        *,
        backend: DockerWorkerBackend,
        barrier: _JournalPreCleanupBarrier,
        binding: WebAnalysisLiveClaimBinding,
        execution_id: str,
    ) -> dict[str, JsonValue]:
        observed: dict[str, object] = {
            "type": "pajin.runtime.worker.DockerWorkerBackend",
            "context": backend.stable_execution_context(),
        }
        verified = verify_web_analysis_provider_worker_context(
            observed,
            transport_pin=self._transport_pin,
            expected_external_network=binding.resources.network_name,
            expected_claim_digest=binding.claim_digest,
            expected_execution_id=execution_id,
        )
        expected = expected_web_analysis_provider_worker_context(
            self._transport_pin,
            external_network=binding.resources.network_name,
            claim_digest=binding.claim_digest,
            execution_id=execution_id,
        )
        if verified != expected or not backend.binds_pre_cleanup_barrier(barrier):
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live Docker Worker context or barrier binding differs"
            )
        return verified

    def _verified_job_metadata(
        self,
        *,
        request: ToolRequest,
        registration: ProviderRegistration,
        execution_id: str,
        lease_ids: tuple[str, ...],
    ) -> dict[str, object]:
        expected = expected_web_analysis_transport_job_metadata(
            request,
            registration=registration,
            runtime=self._runtime,
            transport_pin=self._transport_pin,
            expected_transport_pin_digest=self._expected_transport_pin_digest,
            execution_id=execution_id,
            lease_ids=list(lease_ids),
        )
        return verify_web_analysis_transport_job_metadata(
            expected,
            request,
            registration=registration,
            runtime=self._runtime,
            transport_pin=self._transport_pin,
            expected_transport_pin_digest=self._expected_transport_pin_digest,
            execution_id=execution_id,
            lease_ids=list(lease_ids),
        )

    def _revoke_staged(
        self,
        state: _PreparedProductionDispatchState,
    ) -> tuple[tuple[str, ...], BaseException | None, BaseException | None]:
        revoked: list[str] = []
        first_error: BaseException | None = None
        process_control: BaseException | None = None
        expected: list[tuple[str, str]] = [
            (lease.lease_id, lease.binding) for lease in state.leases
        ]
        if not expected and state.recovery_lease_ids:
            request_bindings = tuple(
                request.binding for request in state.public.job.secret_requests
            )
            if len(request_bindings) != len(state.recovery_lease_ids):
                return (
                    (),
                    CompactSkillBoundWebAnalysisLiveRuntimeError(
                        "compact live recovery lease count differs from the exact job"
                    ),
                    None,
                )
            expected = list(zip(state.recovery_lease_ids, request_bindings, strict=True))
        for lease_id, binding in expected:
            try:
                returned = self._secrets.revoke(
                    lease_id,
                    "compact live Worker execution finished",
                    scope=state.scope,
                )
                observed = self._secrets.inspect(
                    lease_id,
                    audience=state.audience,
                    scope=state.scope,
                )
                for proof in (returned, observed):
                    if (
                        proof.lease_id != lease_id
                        or proof.audience != state.audience
                        or proof.scope != state.scope
                        or proof.binding != binding
                        or proof.max_uses != 1
                        or proof.remaining_uses != 0
                        or proof.status is not SecretLeaseStatus.REVOKED
                    ):
                        raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                            "compact live credential revocation proof differs"
                        )
                revoked.append(lease_id)
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ) as error:
                if process_control is None:
                    process_control = error
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is None and tuple(revoked) != tuple(item[0] for item in expected):
            first_error = CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live credential revocation proof is incomplete"
            )
        return tuple(revoked), first_error, process_control

    def _cleanup_before_terminal(
        self,
        state: _PreparedProductionDispatchState,
        pending: WebAnalysisLiveClaimJournalEntry,
    ) -> tuple[WebAnalysisTransportCleanupProof, tuple[str, ...]]:
        revoked, revoke_error, revoke_process_control = self._revoke_staged(state)
        cleanup: WebAnalysisTransportCleanupProof | None = None
        cleanup_error: BaseException | None = None
        cleanup_process_control: BaseException | None = None
        try:
            cleanup = self._cleanup_transport(state.public)
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ) as error:
            cleanup_process_control = error
        except BaseException as error:
            cleanup_error = error
        blocking = revoke_error or cleanup_error
        process_control = revoke_process_control or cleanup_process_control
        if process_control is not None:
            try:
                _record_cleanup_failure(
                    state.journal,
                    pending,
                    error=blocking or RuntimeError("transport cleanup evidence is absent"),
                )
            except BaseException as record_error:
                _raise_original_after_cleanup_failure(
                    process_control,
                    record_error,
                    stage="docker-cleanup",
                )
            if blocking is not None:
                _raise_original_after_cleanup_failure(
                    process_control,
                    blocking,
                    stage="docker-cleanup",
                )
            raise process_control from process_control.__cause__
        if blocking is not None or cleanup is None:
            recorded = _record_cleanup_failure(
                state.journal,
                pending,
                error=blocking or RuntimeError("transport cleanup evidence is absent"),
            )
            raise CompactSkillBoundWebAnalysisCleanupBlockedError(
                "compact live transport or credential cleanup failed",
                pending_claim=recorded,
            ) from blocking
        return cleanup, revoked

    def _cleanup_transport(
        self,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
    ) -> WebAnalysisTransportCleanupProof:
        proof = cleanup_web_analysis_transport_resources(
            execution_id=prepared.execution_id,
            external_network=prepared.external_network,
            runtime=self._runtime,
            transport_pin=self._transport_pin,
            expected_transport_pin_digest=self._expected_transport_pin_digest,
            docker_executable=self._docker,
        )
        return verify_web_analysis_transport_cleanup_proof(
            proof,
            execution_id=prepared.execution_id,
            external_network=prepared.external_network,
            runtime=self._runtime,
            transport_pin=self._transport_pin,
            expected_transport_pin_digest=self._expected_transport_pin_digest,
        )

    def _transport_binding(
        self,
        state: _PreparedProductionDispatchState,
        *,
        lease_ids: tuple[str, ...],
    ) -> CompactSkillBoundWebAnalysisTransportBinding:
        expected = self._verified_job_metadata(
            request=state.public.request,
            registration=state.registration,
            execution_id=state.public.execution_id,
            lease_ids=lease_ids,
        )
        if expected != state.job_metadata:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live settlement metadata differs from pre-marker evidence"
            )
        return CompactSkillBoundWebAnalysisTransportBinding(
            bindingDigest="",
            runtimePin=self._runtime,
            toolRequest=state.public.request,
            providerRegistration=state.registration,
            transportPin=self._transport_pin,
            transportPinDigest=self._transport_pin.pin_digest,
            liveClaimDigest=state.binding.claim_digest,
            transportExecutionId=state.public.execution_id,
            externalNetwork=state.public.external_network,
            leaseIds=lease_ids,
            workerContext=state.public.worker_context,
            workerContextDigest="",
            jobMetadata=cast(dict[str, JsonValue], state.job_metadata),
            jobMetadataDigest="",
            secretMaterialEmbedded=False,
            externalEgressAuthority=False,
        )

    def _dispatch_settlement(
        self,
        state: _PreparedProductionDispatchState,
        *,
        transport_cleanup: WebAnalysisTransportCleanupProof,
        revoked_lease_ids: tuple[str, ...],
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        pending = state.barrier.pending_claim
        if pending is None or pending.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live Worker returned before durable pending cleanup"
            )
        processed = state.barrier.processed
        failure_stage = state.barrier.failure_stage
        failure_digest = state.barrier.failure_digest
        if pending.pending_outcome is not WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED:
            processed = None
            failure_stage = failure_stage or "dispatch"
            failure_digest = failure_digest or _failure_digest(failure_stage)
        response = None if processed is None else processed.response_bytes
        binding = self._transport_binding(state, lease_ids=revoked_lease_ids)
        observation = self._observation(
            state,
            pending=pending,
            binding=binding,
            response=response,
            failure_digest=failure_digest,
        )
        return CompactSkillBoundWebAnalysisDispatchSettlement(
            pending_claim=pending,
            transport_binding=binding,
            observation=observation,
            transport_cleanup=transport_cleanup,
            revoked_lease_ids=revoked_lease_ids,
            draft=None if processed is None else processed.draft,
            proposal=None if processed is None else processed.proposal,
            failure_stage=failure_stage,
            failure_digest=failure_digest,
        )

    def _non_dispatch_settlement(
        self,
        state: _PreparedProductionDispatchState,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        cleanup: WebAnalysisTransportCleanupProof,
        revoked_lease_ids: tuple[str, ...],
        failure_stage: _FailureStage,
        failure_digest: str,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        if (
            pending_claim.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP
            or pending_claim.dispatch_count != 0
        ):
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "non-dispatch settlement differs from durable claim"
            )
        binding = self._transport_binding(state, lease_ids=revoked_lease_ids)
        observation = self._observation(
            state,
            pending=pending_claim,
            binding=binding,
            response=None,
            failure_digest=failure_digest,
        )
        return CompactSkillBoundWebAnalysisDispatchSettlement(
            pending_claim=pending_claim,
            transport_binding=binding,
            observation=observation,
            transport_cleanup=cleanup,
            revoked_lease_ids=revoked_lease_ids,
            draft=None,
            proposal=None,
            failure_stage=failure_stage,
            failure_digest=failure_digest,
        )

    def _recovery_settlement(
        self,
        state: _PreparedProductionDispatchState,
        *,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
        cleanup: WebAnalysisTransportCleanupProof,
        revoked_lease_ids: tuple[str, ...],
        failure_stage: _FailureStage,
        failure_digest: str,
    ) -> CompactSkillBoundWebAnalysisDispatchSettlement:
        if pending_claim.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "quiescent recovery requires pending cleanup"
            )
        binding = self._transport_binding(state, lease_ids=revoked_lease_ids)
        observation = self._observation(
            state,
            pending=pending_claim,
            binding=binding,
            response=None,
            failure_digest=failure_digest,
        )
        return CompactSkillBoundWebAnalysisDispatchSettlement(
            pending_claim=pending_claim,
            transport_binding=binding,
            observation=observation,
            transport_cleanup=cleanup,
            revoked_lease_ids=revoked_lease_ids,
            draft=None,
            proposal=None,
            failure_stage=failure_stage,
            failure_digest=failure_digest,
        )

    @staticmethod
    def _observation(
        state: _PreparedProductionDispatchState,
        *,
        pending: WebAnalysisLiveClaimJournalEntry,
        binding: CompactSkillBoundWebAnalysisTransportBinding,
        response: bytes | None,
        failure_digest: str | None,
    ) -> CompactSkillBoundWebAnalysisDispatchObservation:
        if pending.pending_outcome is None:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live settlement lacks a pending outcome"
            )
        return CompactSkillBoundWebAnalysisDispatchObservation(
            observationDigest="",
            providerId=state.registration.provider_id,
            modelId=state.registration.model,
            transportExecutionId=state.public.execution_id,
            transportBindingDigest=binding.binding_digest,
            transportWorkerContextDigest=binding.worker_context_digest,
            transportJobMetadataDigest=binding.job_metadata_digest,
            providerRegistrationDigest=pending.binding.provider_registration_digest,
            providerChatRequestDigest=pending.binding.provider_chat_request_digest,
            pendingOutcome=pending.pending_outcome,
            dispatchCount=pending.dispatch_count,
            responseSha256=None if response is None else sha256(response).hexdigest(),
            responseBytes=0 if response is None else len(response),
            responseEvidenceAvailable=response is not None,
            failureDigest=failure_digest,
            targetRequestCount=0,
            toolCallCount=0,
            streamed=False,
            automaticRedispatchPerformed=False,
        )


class CompactSkillBoundWebAnalysisLiveRuntime:
    """Execute one exact compact completion under the four cumulative gates."""

    def __init__(
        self,
        *,
        source: VerifiedAuthenticatedDiscoveryRun,
        skill_run: VerifiedWebAnalysisSkillProjectionRun,
        capacity_run: VerifiedWebAnalysisCapacityV2Run,
        preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
        admission: PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
        runtime: RuntimePin,
        transport_pin: WebAnalysisTransportRuntimePin,
        signed_authorization: SignedWebAnalysisOneCallAuthorization,
        trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor,
        authorization_verifier: WebAnalysisOneCallAuthorizationVerifier,
        journal: WebAnalysisLiveClaimJournal,
        materializer_factory: Callable[[str], CompactSkillBoundWebAnalysisLiveMaterializer],
        dispatch_adapter: CompactSkillBoundWebAnalysisDispatchAdapter,
        terminal_output_root: Path,
        anchors: CompactSkillBoundWebAnalysisLiveAnchors,
    ) -> None:
        self._source = source
        self._skill_run = skill_run
        self._capacity_run = capacity_run
        self._preparation_run = preparation_run
        self._admission = admission
        self._runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        self._transport_pin = WebAnalysisTransportRuntimePin.model_validate(
            transport_pin.model_dump(mode="json", by_alias=True)
        )
        self._signed_authorization = signed_authorization
        self._trust_anchor = trust_anchor
        self._authorization_verifier = authorization_verifier
        self._journal = journal
        self._materializer_factory = materializer_factory
        self._dispatch_adapter = dispatch_adapter
        self._terminal_output_root = Path(terminal_output_root)
        self._anchors = anchors
        self._lock = asyncio.Lock()
        self._attempted = False
        if journal.store_id != anchors.claim_store_id:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live claim store differs from its independent anchor"
            )
        if trust_anchor.digest != anchors.trust_anchor_digest:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live trust anchor differs from its independent digest"
            )

    async def invoke(self) -> CompactSkillBoundWebAnalysisLiveCompletion:  # noqa: C901
        """Run at most one dispatch; expose success only after strict reload."""

        async with self._lock:
            if self._attempted:
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live runtime already consumed its one invocation attempt"
                )
            self._attempted = True

            # Steps 1-2: no durable or live authority exists yet.
            planned = self._strict_admission_reload()
            initial_authorization = self._verify_authorization(planned)
            binding = build_web_analysis_live_claim_binding(
                admission=planned.admission,
                authorization=initial_authorization.coordinate,
            )
            if (
                self._journal.inspect_preparation(binding.preparation_identity) is not None
                or self._journal.inspect_authorization(binding.authorization_identity) is not None
            ):
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live preparation or authorization identity was already consumed"
                )

            # Materializer construction is deliberately pre-claim and must be
            # side-effect free.  Once the identities are consumed, every
            # failure path must have an object capable of cleanup-only recovery.
            materializer = self._materializer_factory(binding.resources.resource_owner)

            # Step 3: initial verification evidence and both unique identities
            # commit in the same journal transaction.
            try:
                reserved = self._journal.reserve_with_gate_d_context(
                    binding,
                    initial_authorization_verification_digest=(
                        initial_authorization.verification_digest
                    ),
                    initial_authorization_evaluated_at=initial_authorization.evaluated_at,
                    initial_authorization_expires_at=initial_authorization.expires_at,
                )
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ) as interruption:
                try:
                    observed_reservation = self._journal.inspect(binding.claim_id)
                except BaseException as inspection_error:
                    _raise_original_after_cleanup_failure(
                        interruption,
                        inspection_error,
                        stage="run-terminalization",
                    )
                if observed_reservation is None:
                    raise
                if observed_reservation.binding != binding:
                    _raise_original_after_cleanup_failure(
                        interruption,
                        CompactSkillBoundWebAnalysisLiveRuntimeError(
                            "interrupted reservation differs from the exact live binding"
                        ),
                        stage="run-terminalization",
                    )
                pending = self._pending_after_process_control(
                    binding=binding,
                    process_control=interruption,
                    handle=None,
                    outcome=None,
                )
                self._finish_process_control_failure(
                    process_control=interruption,
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=None,
                    materializer=materializer,
                    prepared=None,
                    pending=pending,
                    live_attestation=None,
                    provider_route_attestation=None,
                    failure_stage="reservation",
                    recovery=True,
                )
            except WebAnalysisLiveClaimJournalError as error:
                if isinstance(error.__cause__, sqlite3.IntegrityError):
                    raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                        "compact live dual-identity reservation lost its known atomic race"
                    ) from error
                try:
                    pending = _pending_after_uncertainty(self._journal, binding)
                except (
                    DockerPreCleanupBarrierDeadlineExceeded,
                    asyncio.CancelledError,
                    SystemExit,
                    KeyboardInterrupt,
                ):
                    raise
                except BaseException as recovery_error:
                    raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                        "compact live reservation failed before recoverable claim authority"
                    ) from recovery_error
                verified = self._finish_claim_failure(
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=None,
                    materializer=materializer,
                    prepared=None,
                    pending=pending,
                    live_attestation=None,
                    provider_route_attestation=None,
                    failure_stage="reservation",
                    failure_digest=_failure_digest("reservation", error),
                    recovery=True,
                )
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live reservation acknowledgement was uncertain",
                    terminal_run=verified,
                ) from error

            try:
                started = self._journal.begin_live(reserved)
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ) as interruption:
                pending = self._pending_after_process_control(
                    binding=binding,
                    process_control=interruption,
                    handle=None,
                    outcome=None,
                )
                self._finish_process_control_failure(
                    process_control=interruption,
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=None,
                    materializer=materializer,
                    prepared=None,
                    pending=pending,
                    live_attestation=None,
                    provider_route_attestation=None,
                    failure_stage="live-start",
                    recovery=True,
                )
            except BaseException as error:
                pending = _pending_after_uncertainty(self._journal, binding)
                verified = self._finish_claim_failure(
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=None,
                    materializer=materializer,
                    prepared=None,
                    pending=pending,
                    live_attestation=None,
                    provider_route_attestation=None,
                    failure_stage="live-start",
                    failure_digest=_failure_digest("live-start", error),
                    recovery=True,
                )
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live start acknowledgement was uncertain",
                    terminal_run=verified,
                ) from error

            prepared: CompactSkillBoundWebAnalysisPreparedDispatch | None = None
            live_attestation: WebAnalysisLiveModelMaterializationAttestation | None = None
            provider_route_attestation: WebAnalysisLiveModelProviderRouteAttestation | None = None

            # Step 4: the descriptor-held model enters claim-owned resources.
            try:
                materializer.materialize(self._capacity_run)
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ) as interruption:
                pending = self._pending_after_process_control(
                    binding=binding,
                    process_control=interruption,
                    handle=started,
                    outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                )
                self._finish_process_control_failure(
                    process_control=interruption,
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=None,
                    materializer=materializer,
                    prepared=None,
                    pending=pending,
                    live_attestation=None,
                    provider_route_attestation=None,
                    failure_stage="materialization",
                    recovery=False,
                )
            except BaseException as error:
                pending = _mark_pending_or_recover(
                    self._journal,
                    binding,
                    started,
                    outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                )
                verified = self._finish_claim_failure(
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=None,
                    materializer=materializer,
                    prepared=None,
                    pending=pending,
                    live_attestation=None,
                    provider_route_attestation=None,
                    failure_stage="materialization",
                    failure_digest=_failure_digest("materialization", error),
                    recovery=False,
                )
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live materialization failed without dispatch",
                    terminal_run=verified,
                ) from error
            try:
                live_attestation = materializer.live_attestation()
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ) as interruption:
                pending = self._pending_after_process_control(
                    binding=binding,
                    process_control=interruption,
                    handle=started,
                    outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                )
                self._finish_process_control_failure(
                    process_control=interruption,
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=None,
                    materializer=materializer,
                    prepared=None,
                    pending=pending,
                    live_attestation=None,
                    provider_route_attestation=None,
                    failure_stage="materialization-attestation",
                    recovery=False,
                )
            except BaseException as error:
                pending = _mark_pending_or_recover(
                    self._journal,
                    binding,
                    started,
                    outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                )
                verified = self._finish_claim_failure(
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=None,
                    materializer=materializer,
                    prepared=None,
                    pending=pending,
                    live_attestation=None,
                    provider_route_attestation=None,
                    failure_stage="materialization-attestation",
                    failure_digest=_failure_digest("materialization-attestation", error),
                    recovery=False,
                )
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live materialization attestation failed",
                    terminal_run=verified,
                ) from error

            # Step 5: every fallible call-authority check, credential staging,
            # request reconstruction, and Worker-context check precedes the marker.
            pre_dispatch_authorization: VerifiedWebAnalysisOneCallAuthorization | None = None
            try:
                current = self._strict_admission_reload()
                if current != planned:
                    raise ValueError("compact live admission changed before dispatch")
                pre_dispatch_authorization = self._verify_authorization(current)
                durable = self._journal.inspect(binding.claim_id)
                if durable is None or durable != started.entry:
                    raise ValueError("compact live claim changed before dispatch")
                prepared = self._prepare_dispatch(planned, binding)
                self._dispatch_adapter.stage_one_call(prepared)
                self._dispatch_adapter.revalidate_prepared(prepared)
                context = self._dispatch_adapter.prepared_context(prepared)
                transport = context.transport_binding
                if prepared is None or pre_dispatch_authorization is None:
                    raise ValueError("compact live pre-dispatch evidence is incomplete")
                # The route attestation re-runs the final model and network
                # topology checks.  Its context CAS is the final fallible
                # evidence operation before the dispatch marker.
                observed_route = materializer.reattest_provider_route(
                    claim_digest=binding.claim_digest,
                    resource_owner=binding.resources.resource_owner,
                    provider_registration_digest=binding.provider_registration_digest,
                    provider_endpoint=str(planned.registration.endpoint),
                )
                if type(observed_route) is not WebAnalysisLiveModelProviderRouteAttestation:
                    raise ValueError("compact live Provider route attestation type differs")
                provider_route_attestation = (
                    WebAnalysisLiveModelProviderRouteAttestation.model_validate(
                        observed_route.model_dump(mode="python", by_alias=True)
                    )
                )
                if (
                    provider_route_attestation != observed_route
                    or live_attestation is None
                    or provider_route_attestation.claim_digest != binding.claim_digest
                    or provider_route_attestation.resource_owner != binding.resources.resource_owner
                    or provider_route_attestation.live_materialization_attestation_digest
                    != live_attestation.attestation_digest
                    or provider_route_attestation.runtime_container_name
                    != live_attestation.runtime_container_name
                    or provider_route_attestation.runtime_container_id
                    != live_attestation.runtime_container_id
                    or provider_route_attestation.network_name != live_attestation.network_name
                    or provider_route_attestation.network_id != live_attestation.network_id
                    or provider_route_attestation.provider_registration_digest
                    != binding.provider_registration_digest
                    or provider_route_attestation.provider_endpoint
                    != str(planned.registration.endpoint)
                ):
                    raise ValueError("compact live Provider route attestation differs")
                self._verify_pre_marker_transport_binding(
                    planned=planned,
                    binding=binding,
                    prepared=prepared,
                    transport=transport,
                    provider_route_attestation=provider_route_attestation,
                )
                started = self._journal.record_gate_d_pre_dispatch_context(
                    started,
                    pre_dispatch_authorization_verification_digest=(
                        pre_dispatch_authorization.verification_digest
                    ),
                    pre_dispatch_authorization_evaluated_at=(
                        pre_dispatch_authorization.evaluated_at
                    ),
                    pre_dispatch_authorization_expires_at=(pre_dispatch_authorization.expires_at),
                    provider_route_attestation_digest=(
                        provider_route_attestation.attestation_digest
                    ),
                    transport_execution_id=transport.transport_execution_id,
                    lease_ids=transport.lease_ids,
                    worker_context_digest=transport.worker_context_digest,
                    job_metadata_digest=transport.job_metadata_digest,
                    transport_binding_digest=transport.binding_digest,
                )
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ) as interruption:
                pending = self._pending_after_process_control(
                    binding=binding,
                    process_control=interruption,
                    handle=started,
                    outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                )
                try:
                    durable_gate_d = self._journal.inspect_gate_d_context(binding.claim_id)
                except BaseException as cleanup_error:
                    _raise_original_after_cleanup_failure(
                        interruption,
                        cleanup_error,
                        stage="run-terminalization",
                    )
                retained_pre_dispatch_authorization = (
                    pre_dispatch_authorization
                    if (
                        pre_dispatch_authorization is not None
                        and durable_gate_d is not None
                        and durable_gate_d.pre_dispatch_authorization_verification_digest
                        == pre_dispatch_authorization.verification_digest
                    )
                    else None
                )
                retained_provider_route_attestation = (
                    provider_route_attestation
                    if (
                        provider_route_attestation is not None
                        and durable_gate_d is not None
                        and durable_gate_d.provider_route_attestation_digest
                        == provider_route_attestation.attestation_digest
                    )
                    else None
                )
                self._finish_process_control_failure(
                    process_control=interruption,
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=retained_pre_dispatch_authorization,
                    materializer=materializer,
                    prepared=prepared,
                    pending=pending,
                    live_attestation=live_attestation,
                    provider_route_attestation=retained_provider_route_attestation,
                    failure_stage="pre-dispatch-revalidation",
                    recovery=False,
                )
            except BaseException as error:
                try:
                    pending = _mark_pending_or_recover(
                        self._journal,
                        binding,
                        started,
                        outcome=WebAnalysisLiveClaimPendingOutcome.NOT_DISPATCHED,
                    )
                except (
                    DockerPreCleanupBarrierDeadlineExceeded,
                    asyncio.CancelledError,
                    SystemExit,
                    KeyboardInterrupt,
                ) as interruption:
                    pending = self._pending_after_process_control(
                        binding=binding,
                        process_control=interruption,
                        handle=None,
                        outcome=None,
                    )
                    self._finish_process_control_failure(
                        process_control=interruption,
                        planned=planned,
                        binding=binding,
                        initial_authorization=initial_authorization,
                        pre_dispatch_authorization=None,
                        materializer=materializer,
                        prepared=prepared,
                        pending=pending,
                        live_attestation=live_attestation,
                        provider_route_attestation=None,
                        failure_stage="pre-dispatch-revalidation",
                        recovery=True,
                    )
                except BaseException:
                    pending = _pending_after_uncertainty(self._journal, binding)
                durable_gate_d = self._journal.inspect_gate_d_context(binding.claim_id)
                retained_pre_dispatch_authorization = (
                    pre_dispatch_authorization
                    if (
                        pre_dispatch_authorization is not None
                        and durable_gate_d is not None
                        and durable_gate_d.pre_dispatch_authorization_verification_digest
                        == pre_dispatch_authorization.verification_digest
                    )
                    else None
                )
                retained_provider_route_attestation = (
                    provider_route_attestation
                    if (
                        provider_route_attestation is not None
                        and durable_gate_d is not None
                        and durable_gate_d.provider_route_attestation_digest
                        == provider_route_attestation.attestation_digest
                    )
                    else None
                )
                verified = self._finish_claim_failure(
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=retained_pre_dispatch_authorization,
                    materializer=materializer,
                    prepared=prepared,
                    pending=pending,
                    live_attestation=live_attestation,
                    provider_route_attestation=retained_provider_route_attestation,
                    failure_stage="pre-dispatch-revalidation",
                    failure_digest=_failure_digest("pre-dispatch-revalidation", error),
                    recovery=False,
                )
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live immediate pre-dispatch revalidation failed",
                    terminal_run=verified,
                ) from error

            # Step 6: after this CAS, the next external operation is the only
            # backend dispatch.  No authorization or topology call remains.
            try:
                dispatch_handle = self._journal.mark_dispatch_started(started)
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ) as interruption:
                pending = self._pending_after_process_control(
                    binding=binding,
                    process_control=interruption,
                    handle=started,
                    outcome=WebAnalysisLiveClaimPendingOutcome.OUTCOME_UNKNOWN,
                )
                self._finish_process_control_failure(
                    process_control=interruption,
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=pre_dispatch_authorization,
                    materializer=materializer,
                    prepared=prepared,
                    pending=pending,
                    live_attestation=live_attestation,
                    provider_route_attestation=provider_route_attestation,
                    failure_stage="dispatch-marker",
                    recovery=True,
                )
            except BaseException as error:
                pending = _pending_after_uncertainty(self._journal, binding)
                verified = self._finish_claim_failure(
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=pre_dispatch_authorization,
                    materializer=materializer,
                    prepared=prepared,
                    pending=pending,
                    live_attestation=live_attestation,
                    provider_route_attestation=provider_route_attestation,
                    failure_stage="dispatch-marker",
                    failure_digest=_failure_digest("dispatch-marker", error),
                    recovery=True,
                )
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live dispatch marker was uncertain; no redispatch occurred",
                    terminal_run=verified,
                ) from error

            try:
                settlement = await self._dispatch_adapter.dispatch_one(
                    prepared,
                    handle=dispatch_handle,
                )
            except _CompactLiveDispatchRecoveryRequired as interruption:
                try:
                    verified = self._finish_claim_failure(
                        planned=planned,
                        binding=binding,
                        initial_authorization=initial_authorization,
                        pre_dispatch_authorization=pre_dispatch_authorization,
                        materializer=materializer,
                        prepared=prepared,
                        pending=interruption.pending_claim,
                        live_attestation=live_attestation,
                        provider_route_attestation=provider_route_attestation,
                        failure_stage="post-observation-recovery",
                        failure_digest=_failure_digest(
                            "post-observation-recovery",
                            interruption.error,
                        ),
                        recovery=True,
                    )
                except (
                    DockerPreCleanupBarrierDeadlineExceeded,
                    asyncio.CancelledError,
                    SystemExit,
                    KeyboardInterrupt,
                ):
                    raise
                except BaseException as cleanup_error:
                    _raise_original_after_cleanup_failure(
                        interruption.error,
                        cleanup_error,
                        stage="run-terminalization",
                    )
                if (
                    verified.proposal is not None
                    or verified.terminal_claim.terminal_disposition
                    is WebAnalysisLiveClaimTerminalDisposition.SUCCESS
                ):
                    raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                        "failed compact live dispatch exposed a successful proposal",
                        terminal_run=verified,
                    ) from interruption.error
                disposition = verified.terminal_claim.terminal_disposition
                assert disposition is not None
                interruption.error.add_note(
                    "Cleanup-bound terminal disposition was durably recorded as "
                    f"{disposition.value}."
                )
                raise interruption.error from interruption.error.__cause__
            except _CompactLiveDispatchInterrupted as interruption:
                try:
                    verified = self._cleanup_publish_finalize_reload(
                        planned=planned,
                        initial_authorization=initial_authorization,
                        pre_dispatch_authorization=pre_dispatch_authorization,
                        materializer=materializer,
                        settlement=interruption.settlement,
                        live_attestation=live_attestation,
                        provider_route_attestation=provider_route_attestation,
                    )
                except BaseException as followup_error:
                    if _is_process_control(interruption.error):
                        _raise_original_after_cleanup_failure(
                            interruption.error,
                            followup_error,
                            stage="run-terminalization",
                        )
                    raise
                if (
                    verified.proposal is not None
                    or verified.terminal_claim.terminal_disposition
                    is WebAnalysisLiveClaimTerminalDisposition.SUCCESS
                ):
                    raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                        "interrupted compact live dispatch exposed a successful proposal",
                        terminal_run=verified,
                    ) from interruption.error
                recovered_terminal_disposition = verified.terminal_claim.terminal_disposition
                assert recovered_terminal_disposition is not None
                interruption.error.add_note(
                    "Cleanup-bound terminal disposition was durably recorded as "
                    f"{recovered_terminal_disposition.value}."
                )
                original_cause = interruption.error.__cause__
                if original_cause is None:
                    raise interruption.error from None
                raise interruption.error from original_cause
            except (
                DockerPreCleanupBarrierError,
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ) as interruption:
                pending = self._pending_after_process_control(
                    binding=binding,
                    process_control=interruption,
                    handle=None,
                    outcome=None,
                )
                self._finish_process_control_failure(
                    process_control=interruption,
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=pre_dispatch_authorization,
                    materializer=materializer,
                    prepared=prepared,
                    pending=pending,
                    live_attestation=live_attestation,
                    provider_route_attestation=provider_route_attestation,
                    failure_stage="post-observation-recovery",
                    recovery=True,
                )
            except CompactSkillBoundWebAnalysisCleanupBlockedError as error:
                pending = error.pending_claim or _pending_after_uncertainty(self._journal, binding)
                self._cleanup_model_while_pending(materializer, pending, cause=error)
                raise
            except BaseException as error:
                pending = _pending_after_uncertainty(self._journal, binding)
                verified = self._finish_claim_failure(
                    planned=planned,
                    binding=binding,
                    initial_authorization=initial_authorization,
                    pre_dispatch_authorization=pre_dispatch_authorization,
                    materializer=materializer,
                    prepared=prepared,
                    pending=pending,
                    live_attestation=live_attestation,
                    provider_route_attestation=provider_route_attestation,
                    failure_stage="post-observation-recovery",
                    failure_digest=_failure_digest("post-observation-recovery", error),
                    recovery=True,
                )
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live dispatch failed without redispatch",
                    terminal_run=verified,
                ) from error

            # Steps 7-9: the adapter returned only after pending-cleanup and
            # transport cleanup.  Gate A cleanup, seal, CAS, and strict reload follow.
            verified = self._cleanup_publish_finalize_reload(
                planned=planned,
                initial_authorization=initial_authorization,
                pre_dispatch_authorization=pre_dispatch_authorization,
                materializer=materializer,
                settlement=settlement,
                live_attestation=live_attestation,
                provider_route_attestation=provider_route_attestation,
            )
            proposal = verified.proposal
            if (
                proposal is None
                or verified.terminal_claim.terminal_disposition
                is not WebAnalysisLiveClaimTerminalDisposition.SUCCESS
            ):
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live completion ended without a successful proposal",
                    terminal_run=verified,
                )
            return CompactSkillBoundWebAnalysisLiveCompletion(
                terminal_run=verified,
                proposal=proposal,
            )

    def recover_pending(
        self,
        pending_claim: WebAnalysisLiveClaimJournalEntry,
    ) -> VerifiedCompactSkillBoundWebAnalysisTerminalRun:
        """Resume only cleanup/finalization; never reserve, mark, or dispatch."""

        if self._attempted:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live runtime instance already consumed its one operation"
            )
        self._attempted = True
        planned = self._strict_admission_reload()
        exact = WebAnalysisLiveClaimJournalEntry.model_validate(
            pending_claim.model_dump(mode="python", by_alias=True)
        )
        durable = self._journal.inspect(exact.binding.claim_id)
        if exact.phase is not WebAnalysisLiveClaimPhase.PENDING_CLEANUP or durable != exact:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "quiescent recovery requires the exact durable pending claim"
            )
        run_path = compact_skill_bound_web_analysis_terminal_run_path(
            self._terminal_output_root,
            exact,
        )
        durable_publication = self._journal.inspect_terminal_publication(exact.binding.claim_id)
        if durable_publication is not None:
            return self._finalize_existing_publication(
                planned=planned,
                pending=exact,
                publication=durable_publication,
            )
        if run_path.exists():
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "terminal Run exists without a durable publication intent",
                pending_claim=exact,
            )

        context = self._journal.inspect_gate_d_context(exact.binding.claim_id)
        if context is None or context.claim_digest != exact.binding.claim_digest:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "quiescent recovery lacks exact durable Gate D context",
                pending_claim=exact,
            )
        initial_authorization = self._verify_authorization_at(
            planned,
            _timestamp(context.initial_authorization_evaluated_at),
        )
        if (
            initial_authorization.verification_digest
            != context.initial_authorization_verification_digest
            or _timestamp(context.initial_authorization_expires_at)
            != initial_authorization.expires_at
        ):
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "quiescent recovery initial authorization evidence differs",
                pending_claim=exact,
            )
        binding = build_web_analysis_live_claim_binding(
            admission=planned.admission,
            authorization=initial_authorization.coordinate,
        )
        if binding != exact.binding:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "quiescent recovery binding differs from strict inputs",
                pending_claim=exact,
            )

        pre_dispatch_authorization: VerifiedWebAnalysisOneCallAuthorization | None = None
        if context.pre_dispatch_authorization_evaluated_at is not None:
            pre_dispatch_authorization = self._verify_authorization_at(
                planned,
                _timestamp(context.pre_dispatch_authorization_evaluated_at),
            )
            if (
                pre_dispatch_authorization.verification_digest
                != context.pre_dispatch_authorization_verification_digest
                or context.pre_dispatch_authorization_expires_at is None
                or _timestamp(context.pre_dispatch_authorization_expires_at)
                != pre_dispatch_authorization.expires_at
            ):
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "quiescent recovery pre-dispatch authorization evidence differs",
                    pending_claim=exact,
                )

        materializer = self._construct_recovery_materializer(binding, pending=exact)
        prepared = self._prepare_dispatch(planned, binding)
        if context.transport_execution_id is not None:
            assert context.transport_binding_digest is not None
            assert context.worker_context_digest is not None
            assert context.job_metadata_digest is not None
            self._dispatch_adapter.restore_recovery_context(
                prepared,
                lease_ids=context.lease_ids or (),
                transport_binding_digest=context.transport_binding_digest,
                worker_context_digest=context.worker_context_digest,
                job_metadata_digest=context.job_metadata_digest,
            )
        else:
            self._dispatch_adapter.restore_possible_pre_context_recovery(prepared)
        failure = _failure_digest("quiescent-recovery")
        try:
            settlement = self._dispatch_adapter.settle_recovery(
                prepared,
                pending_claim=exact,
                failure_stage="quiescent-recovery",
                failure_digest=failure,
            )
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ) as interruption:
            self._cleanup_pending_and_raise_original(
                materializer=materializer,
                pending=exact,
                original_error=interruption,
            )
        except CompactSkillBoundWebAnalysisCleanupBlockedError as error:
            pending = error.pending_claim or exact
            self._cleanup_model_while_pending(materializer, pending, cause=error)
            raise
        verified = self._cleanup_publish_finalize_reload(
            planned=planned,
            initial_authorization=initial_authorization,
            pre_dispatch_authorization=pre_dispatch_authorization,
            materializer=materializer,
            settlement=settlement,
            live_attestation=None,
            provider_route_attestation=None,
        )
        if verified.proposal is not None:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "quiescent recovery without a seal cannot expose a success proposal",
                terminal_run=verified,
            )
        return verified

    def _construct_recovery_materializer(
        self,
        binding: WebAnalysisLiveClaimBinding,
        *,
        pending: WebAnalysisLiveClaimJournalEntry,
    ) -> CompactSkillBoundWebAnalysisLiveMaterializer:
        try:
            return self._materializer_factory(binding.resources.resource_owner)
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ) as interruption:
            try:
                _record_cleanup_failure(self._journal, pending, error=interruption)
            except BaseException as record_error:
                _raise_original_after_cleanup_failure(
                    interruption,
                    record_error,
                    stage="run-terminalization",
                )
            interruption.add_note(
                "The compact live claim remains durably pending because its "
                "cleanup-only materializer was not constructed."
            )
            raise
        except BaseException as error:
            recorded = _record_cleanup_failure(self._journal, pending, error=error)
            raise CompactSkillBoundWebAnalysisCleanupBlockedError(
                "quiescent recovery could not construct its cleanup-only materializer",
                pending_claim=recorded,
            ) from error

    def _strict_admission_reload(
        self,
    ) -> PlannedPreparedCompactSkillBoundWebAnalysisAdmission:
        anchors = self._anchors
        planned = plan_prepared_compact_skill_bound_web_analysis_admission(
            source=self._source,
            skill_run=self._skill_run,
            capacity_run=self._capacity_run,
            preparation_run=self._preparation_run,
            expected_source_run_id=anchors.source_run_id,
            expected_source_root_digest=anchors.source_root_digest,
            expected_skill_run_id=anchors.skill_run_id,
            expected_skill_root_digest=anchors.skill_root_digest,
            expected_registry_ref=anchors.registry_ref,
            expected_policy_digest=anchors.policy_digest,
            expected_capacity_run_id=anchors.capacity_run_id,
            expected_capacity_root_digest=anchors.capacity_root_digest,
            expected_capacity_pin_digest=anchors.capacity_pin_digest,
            expected_capacity_proof_digest=anchors.capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                anchors.capacity_materialization_attestation_digest
            ),
            expected_transport_pin_digest=anchors.transport_pin_digest,
            expected_preparation_run_id=anchors.preparation_run_id,
            expected_preparation_root_digest=anchors.preparation_root_digest,
            expected_preparation_digest=anchors.preparation_digest,
            expected_preparation_index_digest=anchors.preparation_index_digest,
            expected_live_request_digest=anchors.live_request_digest,
        )
        planned = verify_planned_prepared_compact_skill_bound_web_analysis_admission(
            planned,
            source=self._source,
            skill_run=self._skill_run,
            capacity_run=self._capacity_run,
            preparation_run=self._preparation_run,
            expected_source_run_id=anchors.source_run_id,
            expected_source_root_digest=anchors.source_root_digest,
            expected_skill_run_id=anchors.skill_run_id,
            expected_skill_root_digest=anchors.skill_root_digest,
            expected_registry_ref=anchors.registry_ref,
            expected_policy_digest=anchors.policy_digest,
            expected_capacity_run_id=anchors.capacity_run_id,
            expected_capacity_root_digest=anchors.capacity_root_digest,
            expected_capacity_pin_digest=anchors.capacity_pin_digest,
            expected_capacity_proof_digest=anchors.capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                anchors.capacity_materialization_attestation_digest
            ),
            expected_transport_pin_digest=anchors.transport_pin_digest,
            expected_preparation_run_id=anchors.preparation_run_id,
            expected_preparation_root_digest=anchors.preparation_root_digest,
            expected_preparation_digest=anchors.preparation_digest,
            expected_preparation_index_digest=anchors.preparation_index_digest,
            expected_live_request_digest=anchors.live_request_digest,
        )
        if planned.admission != self._admission:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live admission differs from strict replan"
            )
        return planned

    def _verify_authorization(
        self,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
    ) -> VerifiedWebAnalysisOneCallAuthorization:
        return self._authorization_verifier.verify(
            self._signed_authorization,
            admission=planned.admission,
            live_request=self._preparation_run.live_request,
            capacity_pin=self._capacity_run.pin,
            transport_pin=self._transport_pin,
        )

    def _verify_authorization_at(
        self,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        evaluated_at: datetime,
    ) -> VerifiedWebAnalysisOneCallAuthorization:
        verifier = WebAnalysisOneCallAuthorizationVerifier(
            trust_anchor=self._trust_anchor,
            expected_trust_anchor_digest=self._anchors.trust_anchor_digest,
            clock=lambda: evaluated_at,
        )
        return verifier.verify(
            self._signed_authorization,
            admission=planned.admission,
            live_request=self._preparation_run.live_request,
            capacity_pin=self._capacity_run.pin,
            transport_pin=self._transport_pin,
        )

    def _prepare_dispatch(
        self,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        binding: WebAnalysisLiveClaimBinding,
    ) -> CompactSkillBoundWebAnalysisPreparedDispatch:
        return self._dispatch_adapter.prepare(
            binding=binding,
            journal=self._journal,
            registration=planned.registration,
            chat=planned.chat,
            result_processor=self._result_processor(planned, binding),
        )

    def _pending_after_process_control(
        self,
        *,
        binding: WebAnalysisLiveClaimBinding,
        process_control: BaseException,
        handle: StartedWebAnalysisLiveClaim | DispatchStartedWebAnalysisLiveClaim | None,
        outcome: WebAnalysisLiveClaimPendingOutcome | None,
    ) -> WebAnalysisLiveClaimJournalEntry:
        try:
            if handle is None:
                return _pending_after_uncertainty(self._journal, binding)
            if outcome is None:
                raise AssertionError("pending-cleanup outcome is required with a live handle")
            return _mark_pending_or_recover(
                self._journal,
                binding,
                handle,
                outcome=outcome,
            )
        except BaseException as transition_error:
            try:
                return _pending_after_uncertainty(self._journal, binding)
            except BaseException as recovery_error:
                process_control.add_note(
                    "The initial pending-cleanup transition also failed as "
                    f"{type(transition_error).__module__}."
                    f"{type(transition_error).__qualname__}."
                )
                _raise_original_after_cleanup_failure(
                    process_control,
                    recovery_error,
                    stage="run-terminalization",
                )

    def _finish_process_control_failure(
        self,
        *,
        process_control: BaseException,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        binding: WebAnalysisLiveClaimBinding,
        initial_authorization: VerifiedWebAnalysisOneCallAuthorization,
        pre_dispatch_authorization: VerifiedWebAnalysisOneCallAuthorization | None,
        materializer: CompactSkillBoundWebAnalysisLiveMaterializer,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch | None,
        pending: WebAnalysisLiveClaimJournalEntry,
        live_attestation: WebAnalysisLiveModelMaterializationAttestation | None,
        provider_route_attestation: WebAnalysisLiveModelProviderRouteAttestation | None,
        failure_stage: _FailureStage,
        recovery: bool,
    ) -> Never:
        try:
            verified = self._finish_claim_failure(
                planned=planned,
                binding=binding,
                initial_authorization=initial_authorization,
                pre_dispatch_authorization=pre_dispatch_authorization,
                materializer=materializer,
                prepared=prepared,
                pending=pending,
                live_attestation=live_attestation,
                provider_route_attestation=provider_route_attestation,
                failure_stage=failure_stage,
                failure_digest=_failure_digest(failure_stage, process_control),
                recovery=recovery,
            )
        except BaseException as cleanup_error:
            if cleanup_error is process_control:
                raise process_control from process_control.__cause__
            _raise_original_after_cleanup_failure(
                process_control,
                cleanup_error,
                stage="run-terminalization",
            )
        disposition = verified.terminal_claim.terminal_disposition
        if (
            verified.proposal is not None
            or disposition is WebAnalysisLiveClaimTerminalDisposition.SUCCESS
        ):
            _raise_original_after_cleanup_failure(
                process_control,
                CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "process-control failure produced a successful terminal publication",
                    terminal_run=verified,
                ),
                stage="run-terminalization",
            )
        assert disposition is not None
        process_control.add_note(
            f"Cleanup-bound terminal disposition was durably recorded as {disposition.value}."
        )
        raise process_control from process_control.__cause__

    def _cleanup_pending_and_raise_original(
        self,
        *,
        materializer: CompactSkillBoundWebAnalysisLiveMaterializer,
        pending: WebAnalysisLiveClaimJournalEntry,
        original_error: BaseException,
    ) -> Never:
        try:
            recorded = _record_cleanup_failure(
                self._journal,
                pending,
                error=original_error,
            )
        except BaseException as record_error:
            _raise_original_after_cleanup_failure(
                original_error,
                record_error,
                stage="run-terminalization",
            )
        try:
            materializer.cleanup_owned_resources_and_verify_absent()
        except BaseException as cleanup_error:
            try:
                _record_cleanup_failure(
                    self._journal,
                    recorded,
                    error=cleanup_error,
                )
            except BaseException as record_error:
                cleanup_error.add_note(
                    "The cleanup-failure journal update also failed as "
                    f"{type(record_error).__module__}.{type(record_error).__qualname__}."
                )
            _raise_original_after_cleanup_failure(
                original_error,
                cleanup_error,
                stage="docker-cleanup",
            )
        original_error.add_note(
            "The compact live claim remains durably pending after cleanup-only recovery."
        )
        raise original_error from original_error.__cause__

    def _verify_pre_marker_transport_binding(
        self,
        *,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        binding: WebAnalysisLiveClaimBinding,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch,
        transport: CompactSkillBoundWebAnalysisTransportBinding,
        provider_route_attestation: WebAnalysisLiveModelProviderRouteAttestation,
    ) -> None:
        if type(transport) is not CompactSkillBoundWebAnalysisTransportBinding:
            raise ValueError("compact live transport binding type differs")
        canonical_transport = CompactSkillBoundWebAnalysisTransportBinding.model_validate(
            transport.model_dump(mode="python", by_alias=True)
        )
        execution_id = f"exec_{binding.resources.resource_owner}"
        expected_request = ToolRequest(
            request_id=f"tool_{binding.resources.resource_owner}",
            agent_id="web-analysis-compact-live",
            tool_id=f"provider.{planned.registration.provider_id}.chat",
            target=str(planned.registration.endpoint),
            method="POST",
            arguments=planned.chat.model_dump(mode="python", by_alias=True),
        )
        expected_job = prepare_web_analysis_transport_job(
            expected_request,
            registration=planned.registration,
            runtime=self._runtime,
            transport_pin=self._transport_pin,
            expected_transport_pin_digest=self._anchors.transport_pin_digest,
            execution_id=execution_id,
        )
        expected_worker_context = expected_web_analysis_provider_worker_context(
            self._transport_pin,
            external_network=binding.resources.network_name,
            claim_digest=binding.claim_digest,
            execution_id=execution_id,
        )
        if len(prepared.job.secret_requests) != 1:
            raise ValueError("compact live transport requires exactly one credential request")
        secret_request = prepared.job.secret_requests[0]
        expected_lease_id = _deterministic_lease_id(
            claim_digest=binding.claim_digest,
            secret_ref=secret_request.secret_ref,
            binding=secret_request.binding,
        )
        expected_job_metadata = expected_web_analysis_transport_job_metadata(
            expected_request,
            registration=planned.registration,
            runtime=self._runtime,
            transport_pin=self._transport_pin,
            expected_transport_pin_digest=self._anchors.transport_pin_digest,
            execution_id=execution_id,
            lease_ids=[expected_lease_id],
        )
        expected_barrier_context = web_analysis_transport_pre_cleanup_barrier_context(
            claim_digest=binding.claim_digest,
            execution_id=execution_id,
        )
        parsed_chat = ProviderChatRequest.model_validate(transport.tool_request.arguments)
        if (
            canonical_transport != transport
            or binding.provider_registration_digest
            != planned.admission.provider_registration_digest
            or binding.provider_chat_request_digest
            != planned.admission.provider_chat_request_digest
            or transport.runtime_pin != self._runtime
            or transport.transport_pin != self._transport_pin
            or transport.transport_pin_digest != self._anchors.transport_pin_digest
            or transport.live_claim_digest != binding.claim_digest
            or transport.transport_execution_id != execution_id
            or transport.external_network != binding.resources.network_name
            or transport.lease_ids != (expected_lease_id,)
            or transport.provider_registration != planned.registration
            or transport.tool_request != expected_request
            or parsed_chat != planned.chat
            or prepared.request != expected_request
            or prepared.job != expected_job
            or prepared.execution_id != execution_id
            or prepared.external_network != binding.resources.network_name
            or prepared.barrier_context != expected_barrier_context
            or prepared.worker_context != expected_worker_context
            or transport.worker_context != expected_worker_context
            or transport.job_metadata != expected_job_metadata
            or provider_route_attestation.claim_digest != transport.live_claim_digest
            or provider_route_attestation.resource_owner != binding.resources.resource_owner
            or provider_route_attestation.network_name != transport.external_network
            or provider_route_attestation.provider_registration_digest
            != binding.provider_registration_digest
            or provider_route_attestation.provider_endpoint
            != str(transport.provider_registration.endpoint)
            or transport.tool_request.target != provider_route_attestation.provider_endpoint
        ):
            raise ValueError(
                "compact live transport binding differs from admission or live Provider route"
            )

    def _result_processor(
        self,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        binding: WebAnalysisLiveClaimBinding,
    ) -> Callable[[WorkerResult], CompactSkillBoundWebAnalysisProcessedResponse]:
        execution_id = f"exec_{binding.resources.resource_owner}"
        request = ToolRequest(
            request_id=f"tool_{binding.resources.resource_owner}",
            agent_id="web-analysis-compact-live",
            tool_id=f"provider.{planned.registration.provider_id}.chat",
            target=str(planned.registration.endpoint),
            method="POST",
            arguments=planned.chat.model_dump(mode="python", by_alias=True),
        )

        def process(result: WorkerResult) -> CompactSkillBoundWebAnalysisProcessedResponse:
            if result.execution_id != execution_id:
                raise _ResultProcessingError(
                    "response-validation",
                    "compact live Worker execution identity differs",
                )
            try:
                provider = interpret_web_analysis_transport_result(
                    request,
                    result,
                    registration=planned.registration,
                    runtime=self._runtime,
                    transport_pin=self._transport_pin,
                    expected_transport_pin_digest=self._anchors.transport_pin_digest,
                    expected_execution_id=execution_id,
                )
                raw = _require_proposal_only_result(provider)
                draft = parse_skill_bound_web_analysis_proposal_draft(
                    raw,
                    snapshot=self._skill_run.snapshot,
                )
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ):
                raise
            except BaseException as error:
                raise _ResultProcessingError(
                    "response-validation",
                    "compact live response validation failed",
                ) from error
            try:
                proposal = compile_skill_bound_web_analysis_proposal(
                    source=self._source,
                    skill_run=self._skill_run,
                    draft=draft,
                    transport_pin=self._transport_pin,
                    expected_source_run_id=self._anchors.source_run_id,
                    expected_source_root_digest=self._anchors.source_root_digest,
                    expected_skill_run_id=self._anchors.skill_run_id,
                    expected_skill_root_digest=self._anchors.skill_root_digest,
                    expected_registry_ref=self._anchors.registry_ref,
                    expected_policy_digest=self._anchors.policy_digest,
                    expected_transport_pin_digest=self._anchors.transport_pin_digest,
                )
                proposal = verify_compiled_skill_bound_web_analysis_proposal(
                    proposal,
                    source=self._source,
                    skill_run=self._skill_run,
                    draft=draft,
                    transport_pin=self._transport_pin,
                    expected_source_run_id=self._anchors.source_run_id,
                    expected_source_root_digest=self._anchors.source_root_digest,
                    expected_skill_run_id=self._anchors.skill_run_id,
                    expected_skill_root_digest=self._anchors.skill_root_digest,
                    expected_registry_ref=self._anchors.registry_ref,
                    expected_policy_digest=self._anchors.policy_digest,
                    expected_transport_pin_digest=self._anchors.transport_pin_digest,
                )
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ):
                raise
            except BaseException as error:
                raise _ResultProcessingError(
                    "proposal-compilation",
                    "compact live proposal compilation failed",
                ) from error
            retained = canonical_json_bytes(
                draft.model_dump(mode="json", by_alias=True),
                label="compact live retained response draft",
                max_bytes=512 * 1024,
            )
            return CompactSkillBoundWebAnalysisProcessedResponse(
                response_bytes=retained,
                draft=draft,
                proposal=proposal,
            )

        return process

    def _finish_claim_failure(
        self,
        *,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        binding: WebAnalysisLiveClaimBinding,
        initial_authorization: VerifiedWebAnalysisOneCallAuthorization,
        pre_dispatch_authorization: VerifiedWebAnalysisOneCallAuthorization | None,
        materializer: CompactSkillBoundWebAnalysisLiveMaterializer,
        prepared: CompactSkillBoundWebAnalysisPreparedDispatch | None,
        pending: WebAnalysisLiveClaimJournalEntry,
        live_attestation: WebAnalysisLiveModelMaterializationAttestation | None,
        provider_route_attestation: WebAnalysisLiveModelProviderRouteAttestation | None,
        failure_stage: _FailureStage,
        failure_digest: str,
        recovery: bool,
    ) -> VerifiedCompactSkillBoundWebAnalysisTerminalRun:
        try:
            exact_prepared = prepared or self._prepare_dispatch(planned, binding)
            settlement = (
                self._dispatch_adapter.settle_recovery(
                    exact_prepared,
                    pending_claim=pending,
                    failure_stage=failure_stage,
                    failure_digest=failure_digest,
                )
                if recovery
                else self._dispatch_adapter.settle_without_dispatch(
                    exact_prepared,
                    pending_claim=pending,
                    failure_stage=failure_stage,
                    failure_digest=failure_digest,
                )
            )
        except CompactSkillBoundWebAnalysisCleanupBlockedError as error:
            exact = error.pending_claim or pending
            self._cleanup_model_while_pending(materializer, exact, cause=error)
            raise
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ) as interruption:
            self._cleanup_pending_and_raise_original(
                materializer=materializer,
                pending=pending,
                original_error=interruption,
            )
        except BaseException as error:
            recorded = _record_cleanup_failure(self._journal, pending, error=error)
            self._cleanup_model_while_pending(materializer, recorded, cause=error)
            raise CompactSkillBoundWebAnalysisCleanupBlockedError(
                "compact live failure settlement could not prove transport cleanup",
                pending_claim=recorded,
            ) from error
        return self._cleanup_publish_finalize_reload(
            planned=planned,
            initial_authorization=initial_authorization,
            pre_dispatch_authorization=pre_dispatch_authorization,
            materializer=materializer,
            settlement=settlement,
            live_attestation=live_attestation,
            provider_route_attestation=provider_route_attestation,
        )

    def _cleanup_model_while_pending(
        self,
        materializer: CompactSkillBoundWebAnalysisLiveMaterializer,
        pending: WebAnalysisLiveClaimJournalEntry,
        *,
        cause: BaseException,
    ) -> None:
        try:
            materializer.cleanup_owned_resources_and_verify_absent()
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ) as interruption:
            try:
                _record_cleanup_failure(
                    self._journal,
                    pending,
                    error=interruption,
                )
            except BaseException as record_error:
                _raise_original_after_cleanup_failure(
                    interruption,
                    record_error,
                    stage="run-terminalization",
                )
            interruption.add_note(
                "The compact live claim remains durably pending because model cleanup "
                "was interrupted."
            )
            raise
        except BaseException as cleanup_error:
            recorded = _record_cleanup_failure(
                self._journal,
                pending,
                error=cleanup_error,
            )
            raise CompactSkillBoundWebAnalysisCleanupBlockedError(
                "compact live model cleanup failed after another cleanup failure",
                pending_claim=recorded,
            ) from cleanup_error
        raise CompactSkillBoundWebAnalysisCleanupBlockedError(
            "compact live claim remains pending after cleanup evidence failure",
            pending_claim=pending,
        ) from cause

    def _cleanup_publish_finalize_reload(
        self,
        *,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        initial_authorization: VerifiedWebAnalysisOneCallAuthorization,
        pre_dispatch_authorization: VerifiedWebAnalysisOneCallAuthorization | None,
        materializer: CompactSkillBoundWebAnalysisLiveMaterializer,
        settlement: CompactSkillBoundWebAnalysisDispatchSettlement,
        live_attestation: WebAnalysisLiveModelMaterializationAttestation | None,
        provider_route_attestation: WebAnalysisLiveModelProviderRouteAttestation | None,
    ) -> VerifiedCompactSkillBoundWebAnalysisTerminalRun:
        pending = settlement.pending_claim
        try:
            model_cleanup, model_absence = materializer.cleanup_owned_resources_and_verify_absent()
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ) as interruption:
            try:
                _record_cleanup_failure(self._journal, pending, error=interruption)
            except BaseException as record_error:
                _raise_original_after_cleanup_failure(
                    interruption,
                    record_error,
                    stage="run-terminalization",
                )
            interruption.add_note(
                "The compact live claim remains durably pending because model cleanup or "
                "absence verification was interrupted."
            )
            raise
        except BaseException as error:
            recorded = _record_cleanup_failure(self._journal, pending, error=error)
            raise CompactSkillBoundWebAnalysisCleanupBlockedError(
                "compact live model cleanup or absence verification failed",
                pending_claim=recorded,
            ) from error

        gate_d_context = self._journal.inspect_gate_d_context(pending.binding.claim_id)
        if gate_d_context is None:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live terminal receipt lacks durable Gate D context",
                pending_claim=pending,
            )
        route_attestation_digest = gate_d_context.provider_route_attestation_digest
        if (
            provider_route_attestation is not None
            and route_attestation_digest != provider_route_attestation.attestation_digest
        ):
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live Provider route differs from durable Gate D context",
                pending_claim=pending,
            )
        cleanup = CompactSkillBoundWebAnalysisCleanupResult(
            cleanupDigest="",
            resourceAbsenceDigest="",
            claimStoreId=self._journal.store_id,
            claimDigest=pending.binding.claim_digest,
            pendingClaimStateDigest=pending.state_digest,
            dispatchObservationDigest=settlement.observation.observation_digest,
            liveAttestationDigest=(
                None if live_attestation is None else live_attestation.attestation_digest
            ),
            providerRouteAttestationDigest=route_attestation_digest,
            modelCleanup=model_cleanup,
            modelAbsence=model_absence,
            transportCleanup=settlement.transport_cleanup,
            revokedLeaseIds=settlement.revoked_lease_ids,
            credentialLeasesRevoked=True,
            allOwnedResourcesRemovedOrAbsent=True,
            aggregateAbsenceVerified=True,
        )
        disposition = self._terminal_disposition(settlement)
        terminal_run_id = compact_skill_bound_web_analysis_terminal_run_id(pending)
        receipt = CompactSkillBoundWebAnalysisTerminalReceipt(
            receiptId="",
            receiptDigest="",
            terminalRunId=terminal_run_id,
            admission=planned.admission,
            capacityPin=self._capacity_run.pin,
            transportPin=self._transport_pin,
            signedAuthorization=self._signed_authorization,
            initialAuthorizationVerification=initial_authorization,
            preDispatchAuthorizationVerification=pre_dispatch_authorization,
            claimStoreId=self._journal.store_id,
            gateDContextDigest=gate_d_context.context_digest,
            pendingClaim=pending,
            liveMaterializationAttestation=live_attestation,
            providerRouteAttestation=provider_route_attestation,
            providerRegistration=planned.registration,
            providerChatRequest=planned.chat,
            transportBinding=settlement.transport_binding,
            transportExecutionId=settlement.transport_binding.transport_execution_id,
            dispatchObservation=settlement.observation,
            cleanupResult=cleanup,
            draft=settlement.draft,
            compiledProposal=settlement.proposal,
            intendedTerminalDisposition=disposition,
            failureStage=settlement.failure_stage,
            failureDigest=settlement.failure_digest,
            cleanupBound=True,
            terminalJournalCrossLinkRequired=True,
            targetRequestAuthority=False,
            toolRequestAuthority=False,
            capabilityAuthority=False,
            permitAuthority=False,
            findingAuthority=False,
            graphAdmissionAuthority=False,
            reportAuthority=False,
            deliveryAuthority=False,
            retryAuthority=False,
            automaticRedispatchAuthority=False,
        )
        output_root = require_compact_skill_bound_web_analysis_terminal_output_root(
            Path(os.path.abspath(self._terminal_output_root))
        )
        run_path = compact_skill_bound_web_analysis_terminal_run_path(output_root, pending)
        try:
            durable_publication = self._journal.record_terminal_publication_intent(
                pending,
                output_root=output_root,
                run_path=run_path,
                run_id=terminal_run_id,
                receipt_digest=receipt.receipt_digest,
                cleanup_result_digest=cleanup.cleanup_digest,
                resource_absence_digest=cleanup.resource_absence_digest,
                disposition=disposition,
                live_attestation_digest=(
                    None if live_attestation is None else live_attestation.attestation_digest
                ),
            )
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ):
            raise
        except BaseException as error:
            observed = self._journal.inspect_terminal_publication(pending.binding.claim_id)
            if observed is None or not self._publication_intent_matches(
                observed,
                pending=pending,
                output_root=output_root,
                run_path=run_path,
                run_id=terminal_run_id,
                receipt_digest=receipt.receipt_digest,
                cleanup_result_digest=cleanup.cleanup_digest,
                resource_absence_digest=cleanup.resource_absence_digest,
                disposition=disposition,
                live_attestation_digest=(
                    None if live_attestation is None else live_attestation.attestation_digest
                ),
            ):
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live terminal publication intent CAS failed",
                    pending_claim=pending,
                ) from error
            durable_publication = observed
        if run_path.exists():
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "deterministic terminal Run already exists; finalize-only recovery is required",
                pending_claim=pending,
            )
        try:
            publication = publish_compact_skill_bound_web_analysis_terminal_run(
                output_root,
                receipt=receipt,
                signed_authorization=self._signed_authorization,
                draft=settlement.draft,
                proposal=settlement.proposal,
            )
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ):
            raise
        except BaseException as error:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live terminal receipt publication failed",
                pending_claim=pending,
            ) from error
        if (
            os.path.abspath(publication.run_path) != durable_publication.run_path
            or publication.run_id != durable_publication.run_id
        ):
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "compact live terminal publication path differs from durable intent",
                pending_claim=pending,
            )
        durable_publication = self._strict_load_and_anchor_publication(
            planned=planned,
            pending=pending,
            publication=durable_publication,
            observed_root_digest=publication.root_digest,
        )
        return self._finalize_existing_publication(
            planned=planned,
            pending=pending,
            publication=durable_publication,
        )

    @staticmethod
    def _terminal_disposition(
        settlement: CompactSkillBoundWebAnalysisDispatchSettlement,
    ) -> WebAnalysisLiveClaimTerminalDisposition:
        outcome = settlement.pending_claim.pending_outcome
        if (
            outcome is WebAnalysisLiveClaimPendingOutcome.SUCCESS_OBSERVED
            and settlement.proposal is not None
            and settlement.draft is not None
            and settlement.failure_digest is None
        ):
            return WebAnalysisLiveClaimTerminalDisposition.SUCCESS
        if outcome is WebAnalysisLiveClaimPendingOutcome.FAILURE_OBSERVED:
            return WebAnalysisLiveClaimTerminalDisposition.FAILURE
        return WebAnalysisLiveClaimTerminalDisposition.ABANDONED

    def _finalize_terminal(
        self,
        pending: WebAnalysisLiveClaimJournalEntry,
        *,
        disposition: WebAnalysisLiveClaimTerminalDisposition,
        cleanup_result_digest: str,
        resource_absence_digest: str,
        receipt_digest: str,
    ) -> WebAnalysisLiveClaimJournalEntry:
        try:
            return self._journal.finalize_terminal(
                pending,
                disposition=disposition,
                cleanup_result_digest=cleanup_result_digest,
                resource_absence_digest=resource_absence_digest,
                terminal_receipt_digest=receipt_digest,
            )
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ):
            raise
        except BaseException as first_error:
            current = self._journal.inspect(pending.binding.claim_id)
            if self._terminal_matches(
                current,
                disposition=disposition,
                cleanup_result_digest=cleanup_result_digest,
                resource_absence_digest=resource_absence_digest,
                receipt_digest=receipt_digest,
            ):
                assert current is not None
                return current
            if current is None or current != pending:
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live terminal CAS result is uncertain",
                    pending_claim=current,
                ) from first_error
            try:
                return self._journal.finalize_terminal(
                    current,
                    disposition=disposition,
                    cleanup_result_digest=cleanup_result_digest,
                    resource_absence_digest=resource_absence_digest,
                    terminal_receipt_digest=receipt_digest,
                )
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ):
                raise
            except BaseException as second_error:
                after = self._journal.inspect(pending.binding.claim_id)
                if self._terminal_matches(
                    after,
                    disposition=disposition,
                    cleanup_result_digest=cleanup_result_digest,
                    resource_absence_digest=resource_absence_digest,
                    receipt_digest=receipt_digest,
                ):
                    assert after is not None
                    return after
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "compact live terminal CAS failed after bounded same-receipt retry",
                    pending_claim=after,
                ) from second_error

    @staticmethod
    def _terminal_matches(
        entry: WebAnalysisLiveClaimJournalEntry | None,
        *,
        disposition: WebAnalysisLiveClaimTerminalDisposition,
        cleanup_result_digest: str,
        resource_absence_digest: str,
        receipt_digest: str,
    ) -> bool:
        return bool(
            entry is not None
            and entry.phase is WebAnalysisLiveClaimPhase.TERMINAL
            and entry.terminal_disposition is disposition
            and entry.cleanup_result_digest == cleanup_result_digest
            and entry.resource_absence_digest == resource_absence_digest
            and entry.terminal_receipt_digest == receipt_digest
        )

    def _finalize_existing_publication(
        self,
        *,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        pending: WebAnalysisLiveClaimJournalEntry,
        publication: WebAnalysisLiveClaimTerminalPublication,
    ) -> VerifiedCompactSkillBoundWebAnalysisTerminalRun:
        anchored = self._strict_load_and_anchor_publication(
            planned=planned,
            pending=pending,
            publication=publication,
        )
        assert anchored.root_digest is not None
        sealed = self._load_pending_publication(
            Path(anchored.run_path),
            run_id=anchored.run_id,
            planned=planned,
            pending=pending,
            root_digest=anchored.root_digest,
            receipt_digest=anchored.receipt_digest,
            live_attestation_digest=anchored.live_attestation_digest,
        )
        terminal = self._finalize_terminal(
            pending,
            disposition=sealed.intended_terminal_disposition,
            cleanup_result_digest=sealed.cleanup_result_digest,
            resource_absence_digest=sealed.resource_absence_digest,
            receipt_digest=sealed.receipt_digest,
        )
        sealed_publication = CompactSkillBoundWebAnalysisTerminalPublication(
            run_path=sealed.run_path,
            run_id=sealed.run_id,
            root_digest=sealed.root_digest,
        )
        return self._strict_terminal_reload(
            sealed_publication,
            receipt_digest=sealed.receipt_digest,
            terminal=terminal,
            live_attestation_digest=sealed.live_attestation_digest,
            planned=planned,
        )

    def _strict_load_and_anchor_publication(
        self,
        *,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        pending: WebAnalysisLiveClaimJournalEntry,
        publication: WebAnalysisLiveClaimTerminalPublication,
        observed_root_digest: str | None = None,
    ) -> WebAnalysisLiveClaimTerminalPublication:
        output_root = Path(os.path.abspath(self._terminal_output_root))
        run_path = compact_skill_bound_web_analysis_terminal_run_path(output_root, pending)
        run_id = compact_skill_bound_web_analysis_terminal_run_id(pending)
        if not self._publication_intent_matches(
            publication,
            pending=pending,
            output_root=output_root,
            run_path=run_path,
            run_id=run_id,
            receipt_digest=publication.receipt_digest,
            cleanup_result_digest=publication.cleanup_result_digest,
            resource_absence_digest=publication.resource_absence_digest,
            disposition=publication.intended_terminal_disposition,
            live_attestation_digest=publication.live_attestation_digest,
        ):
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "durable terminal publication intent differs from exact recovery inputs",
                pending_claim=pending,
            )
        if not run_path.exists():
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "durable terminal publication intent has no sealed Run",
                pending_claim=pending,
            )
        if publication.root_digest is not None:
            if observed_root_digest is not None and publication.root_digest != observed_root_digest:
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "published terminal Run differs from its durable root anchor",
                    pending_claim=pending,
                )
            return publication

        # The immutable intent predates the Run.  Full receipt and lineage
        # verification must complete against an unchanged unanchored intent
        # before the root CAS.  A merely self-consistent RunStore seal is not a
        # publication candidate.
        candidate = self._load_unanchored_publication_candidate(
            run_path,
            run_id=run_id,
            planned=planned,
            pending=pending,
            receipt_digest=publication.receipt_digest,
            live_attestation_digest=publication.live_attestation_digest,
        )
        verified_candidate = candidate.verified_candidate
        if verified_candidate is None:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "strict terminal loader returned no verified root candidate",
                pending_claim=pending,
            )
        candidate_root_digest = verified_candidate.root_digest
        if observed_root_digest is not None and observed_root_digest != candidate_root_digest:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "published terminal Run root differs from strict candidate reload",
                pending_claim=pending,
            )
        try:
            return self._journal.anchor_terminal_publication(
                pending,
                publication,
                verified_candidate,
            )
        except (
            DockerPreCleanupBarrierDeadlineExceeded,
            asyncio.CancelledError,
            SystemExit,
            KeyboardInterrupt,
        ):
            raise
        except BaseException as error:
            observed = self._journal.inspect_terminal_publication(pending.binding.claim_id)
            if (
                observed is None
                or observed.intent_digest != publication.intent_digest
                or observed.root_digest != candidate_root_digest
                or observed.publication_digest is None
            ):
                raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                    "terminal publication root anchor CAS failed",
                    pending_claim=pending,
                ) from error
            return observed

    def _load_unanchored_publication_candidate(
        self,
        run_path: Path,
        *,
        run_id: str,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        pending: WebAnalysisLiveClaimJournalEntry,
        receipt_digest: str,
        live_attestation_digest: str | None,
    ) -> VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication:
        independent = self._anchors
        return load_verified_compact_skill_bound_web_analysis_terminal_publication_candidate(
            run_path,
            expected_output_root=Path(os.path.abspath(self._terminal_output_root)),
            expected_run_id=run_id,
            expected_receipt_digest=receipt_digest,
            expected_claim_digest=pending.binding.claim_digest,
            expected_live_attestation_digest=live_attestation_digest,
            source=self._source,
            skill_run=self._skill_run,
            capacity_run=self._capacity_run,
            preparation_run=self._preparation_run,
            admission=planned.admission,
            transport_pin=self._transport_pin,
            trust_anchor=self._trust_anchor,
            expected_trust_anchor_digest=independent.trust_anchor_digest,
            journal=self._journal,
            expected_claim_store_id=independent.claim_store_id,
            expected_source_run_id=independent.source_run_id,
            expected_source_root_digest=independent.source_root_digest,
            expected_skill_run_id=independent.skill_run_id,
            expected_skill_root_digest=independent.skill_root_digest,
            expected_registry_ref=independent.registry_ref,
            expected_policy_digest=independent.policy_digest,
            expected_capacity_run_id=independent.capacity_run_id,
            expected_capacity_root_digest=independent.capacity_root_digest,
            expected_capacity_pin_digest=independent.capacity_pin_digest,
            expected_capacity_proof_digest=independent.capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                independent.capacity_materialization_attestation_digest
            ),
            expected_transport_pin_digest=independent.transport_pin_digest,
            expected_preparation_run_id=independent.preparation_run_id,
            expected_preparation_root_digest=independent.preparation_root_digest,
            expected_preparation_digest=independent.preparation_digest,
            expected_preparation_index_digest=independent.preparation_index_digest,
            expected_live_request_digest=independent.live_request_digest,
        )

    @staticmethod
    def _publication_intent_matches(
        publication: WebAnalysisLiveClaimTerminalPublication,
        *,
        pending: WebAnalysisLiveClaimJournalEntry,
        output_root: Path,
        run_path: Path,
        run_id: str,
        receipt_digest: str,
        cleanup_result_digest: str,
        resource_absence_digest: str,
        disposition: WebAnalysisLiveClaimTerminalDisposition,
        live_attestation_digest: str | None,
    ) -> bool:
        return bool(
            publication.claim_id == pending.binding.claim_id
            and publication.claim_digest == pending.binding.claim_digest
            and publication.pending_claim_state_digest == pending.state_digest
            and publication.output_root == os.path.abspath(output_root)
            and publication.run_path == os.path.abspath(run_path)
            and publication.run_id == run_id
            and publication.receipt_digest == receipt_digest
            and publication.cleanup_result_digest == cleanup_result_digest
            and publication.resource_absence_digest == resource_absence_digest
            and publication.intended_terminal_disposition is disposition
            and publication.live_attestation_digest == live_attestation_digest
        )

    def _load_pending_publication(
        self,
        run_path: Path,
        *,
        run_id: str,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
        pending: WebAnalysisLiveClaimJournalEntry,
        root_digest: str,
        receipt_digest: str,
        live_attestation_digest: str | None,
    ) -> VerifiedCompactSkillBoundWebAnalysisPendingTerminalPublication:
        independent = self._anchors
        return load_verified_compact_skill_bound_web_analysis_pending_terminal_publication(
            run_path,
            expected_output_root=Path(os.path.abspath(self._terminal_output_root)),
            expected_run_id=run_id,
            expected_root_digest=root_digest,
            expected_receipt_digest=receipt_digest,
            expected_claim_digest=pending.binding.claim_digest,
            expected_live_attestation_digest=live_attestation_digest,
            source=self._source,
            skill_run=self._skill_run,
            capacity_run=self._capacity_run,
            preparation_run=self._preparation_run,
            admission=planned.admission,
            transport_pin=self._transport_pin,
            trust_anchor=self._trust_anchor,
            expected_trust_anchor_digest=independent.trust_anchor_digest,
            journal=self._journal,
            expected_claim_store_id=independent.claim_store_id,
            expected_source_run_id=independent.source_run_id,
            expected_source_root_digest=independent.source_root_digest,
            expected_skill_run_id=independent.skill_run_id,
            expected_skill_root_digest=independent.skill_root_digest,
            expected_registry_ref=independent.registry_ref,
            expected_policy_digest=independent.policy_digest,
            expected_capacity_run_id=independent.capacity_run_id,
            expected_capacity_root_digest=independent.capacity_root_digest,
            expected_capacity_pin_digest=independent.capacity_pin_digest,
            expected_capacity_proof_digest=independent.capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                independent.capacity_materialization_attestation_digest
            ),
            expected_transport_pin_digest=independent.transport_pin_digest,
            expected_preparation_run_id=independent.preparation_run_id,
            expected_preparation_root_digest=independent.preparation_root_digest,
            expected_preparation_digest=independent.preparation_digest,
            expected_preparation_index_digest=independent.preparation_index_digest,
            expected_live_request_digest=independent.live_request_digest,
        )

    def _strict_terminal_reload(
        self,
        publication: CompactSkillBoundWebAnalysisTerminalPublication,
        *,
        receipt_digest: str,
        terminal: WebAnalysisLiveClaimJournalEntry,
        live_attestation_digest: str | None,
        planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
    ) -> VerifiedCompactSkillBoundWebAnalysisTerminalRun:
        independent = self._anchors
        durable_publication = self._journal.inspect_terminal_publication(terminal.binding.claim_id)
        if (
            durable_publication is None
            or durable_publication.root_digest != publication.root_digest
            or durable_publication.receipt_digest != receipt_digest
            or durable_publication.run_id != publication.run_id
            or durable_publication.run_path != os.path.abspath(publication.run_path)
            or durable_publication.live_attestation_digest != live_attestation_digest
            or durable_publication.publication_digest is None
        ):
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "strict terminal reload lacks its durable publication anchor",
                pending_claim=terminal,
            )
        verified = load_verified_compact_skill_bound_web_analysis_terminal_run(
            publication.run_path,
            expected_output_root=Path(os.path.abspath(self._terminal_output_root)),
            expected_run_id=publication.run_id,
            expected_root_digest=publication.root_digest,
            expected_receipt_digest=receipt_digest,
            expected_claim_digest=terminal.binding.claim_digest,
            expected_live_attestation_digest=live_attestation_digest,
            source=self._source,
            skill_run=self._skill_run,
            capacity_run=self._capacity_run,
            preparation_run=self._preparation_run,
            admission=planned.admission,
            transport_pin=self._transport_pin,
            trust_anchor=self._trust_anchor,
            expected_trust_anchor_digest=independent.trust_anchor_digest,
            journal=self._journal,
            expected_claim_store_id=independent.claim_store_id,
            expected_source_run_id=independent.source_run_id,
            expected_source_root_digest=independent.source_root_digest,
            expected_skill_run_id=independent.skill_run_id,
            expected_skill_root_digest=independent.skill_root_digest,
            expected_registry_ref=independent.registry_ref,
            expected_policy_digest=independent.policy_digest,
            expected_capacity_run_id=independent.capacity_run_id,
            expected_capacity_root_digest=independent.capacity_root_digest,
            expected_capacity_pin_digest=independent.capacity_pin_digest,
            expected_capacity_proof_digest=independent.capacity_proof_digest,
            expected_capacity_model_materialization_attestation_digest=(
                independent.capacity_materialization_attestation_digest
            ),
            expected_transport_pin_digest=independent.transport_pin_digest,
            expected_preparation_run_id=independent.preparation_run_id,
            expected_preparation_root_digest=independent.preparation_root_digest,
            expected_preparation_digest=independent.preparation_digest,
            expected_preparation_index_digest=independent.preparation_index_digest,
            expected_live_request_digest=independent.live_request_digest,
        )
        if verified.terminal_claim != terminal:
            raise CompactSkillBoundWebAnalysisLiveRuntimeError(
                "strict terminal loader returned a different durable claim",
                terminal_run=verified,
            )
        return verified


__all__ = [
    "CompactSkillBoundWebAnalysisCleanupBlockedError",
    "CompactSkillBoundWebAnalysisDispatchAdapter",
    "CompactSkillBoundWebAnalysisDispatchSettlement",
    "CompactSkillBoundWebAnalysisLiveAnchors",
    "CompactSkillBoundWebAnalysisLiveCompletion",
    "CompactSkillBoundWebAnalysisLiveMaterializer",
    "CompactSkillBoundWebAnalysisLiveRuntime",
    "CompactSkillBoundWebAnalysisLiveRuntimeError",
    "CompactSkillBoundWebAnalysisPreparedContext",
    "CompactSkillBoundWebAnalysisPreparedDispatch",
    "CompactSkillBoundWebAnalysisProcessedResponse",
    "DockerCompactSkillBoundWebAnalysisDispatchAdapter",
]
