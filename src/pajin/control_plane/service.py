"""Transactional Control Plane application service."""

from __future__ import annotations

import hmac
import json
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, load_only

from pajin.control_plane.artifacts import (
    ArtifactNotFound,
    ArtifactRepositoryError,
    ManagedArtifactRepository,
    ManagedArtifactSnapshot,
)
from pajin.control_plane.claim_service import (
    _MAX_REPLAY_RATE_LIMIT_SNAPSHOT_BYTES as _MAX_REPLAY_RATE_LIMIT_SNAPSHOT_BYTES,
)
from pajin.control_plane.claim_service import (
    _MAX_REPLAY_RATE_LIMIT_SNAPSHOT_DEPTH as _MAX_REPLAY_RATE_LIMIT_SNAPSHOT_DEPTH,
)
from pajin.control_plane.claim_service import (
    _MAX_REPLAY_RATE_LIMIT_SNAPSHOT_NODES as _MAX_REPLAY_RATE_LIMIT_SNAPSHOT_NODES,
)
from pajin.control_plane.claim_service import (
    MIN_JOB_HEARTBEAT_EVENT_INTERVAL_SECONDS as MIN_JOB_HEARTBEAT_EVENT_INTERVAL_SECONDS,
)
from pajin.control_plane.claim_service import (
    ClaimServiceHooks,
    ControlPlaneClaimService,
)
from pajin.control_plane.claim_service import (
    LockedReplayAttempt as _LockedReplayAttempt,
)
from pajin.control_plane.collaborator_hooks import ControlPlaneTransactionHooks
from pajin.control_plane.database import (
    ApprovalRecord,
    ArtifactRecord,
    CheckpointRecord,
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayCompilationRecord,
    ReplayEventRecord,
    ReplayFinalizationRecord,
    ReplayItemRecord,
    ReplayProjectionRecord,
    ReplayTicketRecord,
    ReplayToolPermitRecord,
    RunRecord,
    utc_now,
)
from pajin.control_plane.errors import (
    ControlPlaneError,
    LeaseRejected,
    ResourceNotFound,
    RunCancelled,
    StateConflict,
)
from pajin.control_plane.kisa_derivation import (
    DerivedKISAReplayBatch,
    derive_kisa_confirmation_batch,
    derive_kisa_retest_batch,
)
from pajin.control_plane.lifecycle_service import (
    ControlPlaneLifecycleService,
    LifecycleServiceHooks,
)
from pajin.control_plane.models import (
    CHECKPOINT_STATE_JSON_POLICY,
    COMPLETE_JOB_RESULT_JSON_POLICY,
    SUBMIT_RUN_INPUT_JSON_POLICY,
    AdmitSourceArtifactRequest,
    ApprovalIntent,
    ApprovalState,
    ApprovalView,
    ArtifactLocator,
    ArtifactRef,
    AuditEventView,
    CancelRunRequest,
    CancelRunView,
    CheckpointCreationView,
    ClaimedJob,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    CreateReplayBatchRequest,
    DecideApprovalRequest,
    FailJobRequest,
    InternalJobKind,
    JobKind,
    JobState,
    JobView,
    LeaseRequest,
    ReplayBatchIssuanceView,
    ReplayBatchState,
    ReplayBatchView,
    ReplayClaimRequest,
    ReplayExecutionClaimView,
    ReplayFinalizationView,
    ReplayFinalizeRequest,
    ReplayItemState,
    ReplayItemView,
    ReplayLeaseRequest,
    ReplayProjectionInputAuthority,
    ReplayProjectionItemAuthority,
    ReplayProjectionView,
    ReplayRetestProjectionInputAuthority,
    ReplayTicketState,
    ReplayTicketView,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
    ResumeView,
    RunListView,
    RunState,
    RunView,
    SubmissionView,
    SubmitRunRequest,
    canonical_control_plane_json,
    job_submission_authority_digest,
    owned_bounded_json_object,
    submission_authority_digest,
    validate_bounded_json_object,
)
from pajin.control_plane.records import ControlPlaneRecords
from pajin.control_plane.replay_authority import (
    ReplayBindingAuthority,
    replay_tool_permit_digest,
    require_exact_replay_account_permit_consumption,
    require_exact_replay_budget_ledger,
    require_replay_permit_rate_capacity,
    trusted_replay_compilation,
)
from pajin.control_plane.replay_issuance import (
    ReplayIssuanceHooks,
    ReplayIssuanceService,
)
from pajin.control_plane.replay_reads import ReplayReadService
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.control_plane.view_mapper import ControlPlaneViewMapper
from pajin.domain.replay import ReplayPurpose, ReplayRetestContext
from pajin.domain.validation import ReplayConfirmationLineage, ValidationDecision
from pajin.modes.ai_redteam.replay import KISAReplayBatchOutcome
from pajin.modes.ai_redteam.retest import KISARetestService
from pajin.replay.runtime import VerifiedReplayResult, inspect_sealed_replay_result
from pajin.replay.tickets import replay_context_digest
from pajin.runtime.store import VerifiedRunSnapshot, load_verified_run_artifacts
from pajin.tools.ai import AIChatProbeTool
from pajin.workflow.confirmation import apply_confirmed_gate, decide_replay_confirmation
from pajin.workflow.validation_artifacts import load_source_validation_artifacts

MAX_AUDIT_EVENT_PAGE_SIZE = 200
MAX_AUDIT_EVENT_RESPONSE_BYTES = 4 * 1024 * 1024
_AUDIT_EVENT_RESPONSE_SAFETY_BYTES = 64 * 1024
_CANCELLABLE_RUN_STATES = frozenset(
    {
        RunState.QUEUED.value,
        RunState.RUNNING.value,
        RunState.AWAITING_APPROVAL.value,
    }
)
_CANCELLABLE_JOB_STATES = frozenset({JobState.QUEUED.value, JobState.LEASED.value})
_REVOCABLE_APPROVAL_STATES = frozenset({ApprovalState.PENDING.value, ApprovalState.APPROVED.value})
_INTERNAL_REPLAY_KIND = InternalJobKind.REPLAY.value
_REPLAY_TOOL_PERMIT_TTL = timedelta(seconds=30)
_REPLAY_RETRY_ISSUER_ACTOR = "control-plane:replay-retry"
_SOURCE_ARTIFACT_MEDIA_TYPE = "application/vnd.pajin.run+directory"
_SOURCE_ARTIFACT_SCHEMA_KIND = "pajin.run.sealed.v1"
_REPLAY_OUTPUT_ARTIFACT_SCHEMA_KIND = "pajin.replay.output.sealed.v1"
_REPLAY_PROJECTION_ARTIFACT_SCHEMA_KIND = "pajin.validation.projection.sealed.v1"
_REPLAY_PROJECTION_ACTOR = "control-plane:replay-projection"
_ACTIVE_REPLAY_TICKET_STATES = frozenset(
    {ReplayTicketState.ISSUED.value, ReplayTicketState.CLAIMED.value}
)
def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@dataclass(slots=True)
class _ReplayFinalizationPreflight:
    attempt: _LockedReplayAttempt
    source_ref: ArtifactRef
    source_storage_key: str


@dataclass(frozen=True, slots=True)
class _ReplayProjectionSnapshot:
    authority: ReplayProjectionInputAuthority | ReplayRetestProjectionInputAuthority
    authority_digest: str
    source_storage_key: str
    retest_source_storage_key: str | None
    output_storage_keys: tuple[str, ...]
    retest_contexts: Mapping[str, ReplayRetestContext]
    decided_at: datetime


class _ReplayProjectionTicketVerifier:
    """Read-only verifier backed only by the immutable publication snapshot."""

    def __init__(
        self,
        authority: ReplayProjectionInputAuthority | ReplayRetestProjectionInputAuthority,
    ) -> None:
        self._items = {item.ticket_id: item for item in authority.items}
        self._source_root_digest = authority.source.integrity_root_digest

    def verify_finalized(
        self,
        ticket_id: str,
        *,
        final_seal_root_digest: str,
        artifact_set_digest: str,
        compilation_digest: str,
        candidate_source_root_digest: str,
        replay_run_id: str,
    ) -> None:
        item = self._items.get(ticket_id)
        if item is None or (
            final_seal_root_digest,
            artifact_set_digest,
            compilation_digest,
            candidate_source_root_digest,
            replay_run_id,
        ) != (
            item.receipt_seal_root_digest,
            item.artifact_set_digest,
            item.compilation_digest,
            self._source_root_digest,
            item.replay_run_id,
        ):
            raise ValueError("Replay receipt differs from projection finalization authority")


@dataclass(frozen=True, slots=True)
class _SubmissionAuthority:
    """One caller-detached, exact public submission identity."""

    actor: str
    campaign_name: str
    input_value: dict[str, Any]
    canonical_input: bytes
    idempotency_key: str
    job_kind: str
    max_attempts: int
    digest: str


class ControlPlaneService:
    """Coordinate durable state transitions under database transactions."""

    def __init__(
        self,
        repository: ControlPlaneRepository,
        signer: CheckpointSigner,
        *,
        replay_executor_profiles: Mapping[str, frozenset[str]] | None = None,
        artifact_repository: ManagedArtifactRepository | None = None,
    ) -> None:
        self.repository = repository
        self.signer = signer
        self._replay_executor_profiles = {
            subject: frozenset(profiles)
            for subject, profiles in (replay_executor_profiles or {}).items()
        }
        self._artifact_repository = artifact_repository
        self._records = ControlPlaneRecords()
        self._views = ControlPlaneViewMapper()

        def write_event(
            session: Session,
            run: RunRecord,
            event_type: str,
            actor: str,
            payload: dict[str, Any],
        ) -> EventRecord:
            return self._event(session, run, event_type, actor, payload)

        def write_replay_event(
            session: Session,
            batch: ReplayBatchRecord,
            event_type: str,
            actor: str,
            payload: dict[str, Any],
            *,
            item: ReplayItemRecord | None = None,
            ticket: ReplayTicketRecord | None = None,
            job: JobRecord | None = None,
            run_id: str | None = None,
        ) -> ReplayEventRecord:
            return self._replay_event(
                session,
                batch,
                event_type,
                actor,
                payload,
                item=item,
                ticket=ticket,
                job=job,
                run_id=run_id,
            )

        def derive_replay_batch(
            *,
            source_root: Path,
            artifact_ref: ArtifactRef,
            retest_root: Path | None = None,
            retest_artifact_ref: ArtifactRef | None = None,
        ) -> DerivedKISAReplayBatch:
            if retest_root is not None and retest_artifact_ref is not None:
                return derive_kisa_retest_batch(
                    source_root=source_root,
                    artifact_ref=artifact_ref,
                    retest_root=retest_root,
                    retest_artifact_ref=retest_artifact_ref,
                )
            if retest_root is not None or retest_artifact_ref is not None:
                raise ValueError("parent Retest path and ArtifactRef must be supplied together")
            return derive_kisa_confirmation_batch(
                source_root=source_root,
                artifact_ref=artifact_ref,
            )

        def load_run_artifacts(
            run_path: Path,
            *,
            requests: Mapping[str, int],
            expected_run_id: str | None = None,
        ) -> VerifiedRunSnapshot:
            return load_verified_run_artifacts(
                run_path,
                requests=requests,
                expected_run_id=expected_run_id,
            )

        transaction_hooks = ControlPlaneTransactionHooks(
            clock=lambda: utc_now(),
            event_writer=write_event,
            replay_event_writer=write_replay_event,
        )

        def sweep_leases(session: Session, *, now: datetime, actor: str) -> int:
            return self._lifecycle.expire_leases(session, now=now, actor=actor)

        self._claims = ControlPlaneClaimService(
            repository,
            self._records,
            self._views,
            artifact_repository,
            self._replay_executor_profiles,
            ClaimServiceHooks(
                transaction=transaction_hooks,
                lease_sweeper=sweep_leases,
                artifact_loader=load_run_artifacts,
            ),
        )
        self._lifecycle = ControlPlaneLifecycleService(
            repository,
            signer,
            self._records,
            self._views,
            self._claims,
            LifecycleServiceHooks(transaction=transaction_hooks),
        )
        self._replay_issuance = ReplayIssuanceService(
            repository,
            self._records,
            self._views,
            artifact_repository,
            ReplayIssuanceHooks(
                transaction=transaction_hooks,
                binding_verifier=self._claims.verify_replay_binding,
                deriver=derive_replay_batch,
            ),
        )
        self._replay_reads = ReplayReadService(repository, self._records, self._views)

    def submit_run(self, request: SubmitRunRequest, *, actor: str) -> SubmissionView:
        authority = self._submission_authority(request, actor=actor)
        try:
            with self.repository.transaction() as session:
                existing = session.scalar(
                    select(RunRecord).where(RunRecord.submission_key == authority.idempotency_key)
                )
                if existing is not None:
                    return self._existing_submission(
                        session,
                        existing,
                        authority=authority,
                    )
                now = utc_now()
                run = RunRecord(
                    run_id=f"run_{uuid4().hex}",
                    campaign_name=authority.campaign_name,
                    state=RunState.QUEUED.value,
                    input=owned_bounded_json_object(
                        authority.input_value,
                        policy=SUBMIT_RUN_INPUT_JSON_POLICY,
                    ),
                    submission_key=authority.idempotency_key,
                    submission_authority_digest=authority.digest,
                    current_checkpoint_id=None,
                    created_at=now,
                    updated_at=now,
                )
                job_id = f"job_{uuid4().hex}"
                job_payload = {
                    "input": owned_bounded_json_object(
                        authority.input_value,
                        policy=SUBMIT_RUN_INPUT_JSON_POLICY,
                    )
                }
                job_idempotency_key = f"submission:{authority.idempotency_key}"
                job = JobRecord(
                    job_id=job_id,
                    run_id=run.run_id,
                    kind=authority.job_kind,
                    state=JobState.QUEUED.value,
                    payload=job_payload,
                    priority=0,
                    attempts=0,
                    max_attempts=authority.max_attempts,
                    idempotency_key=job_idempotency_key,
                    available_at=now,
                    lease_owner=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    lease_deadline_at=None,
                    heartbeat_at=None,
                    heartbeat_event_at=None,
                    result=None,
                    error=None,
                    created_at=now,
                    updated_at=now,
                    submission_authority_digest=job_submission_authority_digest(
                        job_id=job_id,
                        run_id=run.run_id,
                        job_kind=authority.job_kind,
                        payload=job_payload,
                        max_attempts=authority.max_attempts,
                        idempotency_key=job_idempotency_key,
                    ),
                )
                session.add(run)
                session.flush()
                session.add(job)
                session.flush()
                self._event(
                    session,
                    run,
                    "run.submitted",
                    actor,
                    {
                        "campaignName": authority.campaign_name,
                        "jobId": job.job_id,
                        "jobKind": authority.job_kind,
                    },
                )
                return SubmissionView(
                    run=self._views.run(run), job=self._views.job(job), created=True
                )
        except IntegrityError:
            with self.repository.transaction() as session:
                existing = session.scalar(
                    select(RunRecord).where(RunRecord.submission_key == authority.idempotency_key)
                )
                if existing is None:
                    raise
                return self._existing_submission(
                    session,
                    existing,
                    authority=authority,
                )

    def admit_source_artifact(
        self,
        request: AdmitSourceArtifactRequest,
        *,
        actor: str,
    ) -> ArtifactRef:
        """Import one completed public Campaign Job's sealed Run into managed storage."""

        artifact_repository = self._require_artifact_repository()
        if not isinstance(actor, str) or not 1 <= len(actor) <= 200:
            raise StateConflict("Artifact admission actor is invalid")
        admission_digest = self._artifact_admission_digest(request, actor=actor)
        existing_ref: ArtifactRef | None = None
        existing_storage_key: str | None = None
        producer_attempt: int | None = None
        expected_sealed_run_id: str | None = None

        # This is an optimistic eligibility read only. Copying and integrity verification can
        # be slow, so no database row lock may span the managed repository import.
        with self.repository.transaction() as session:
            existing = self._records.artifact_by_idempotency_key(
                session,
                request.idempotency_key,
            )
            if existing is not None:
                existing_ref = self._existing_artifact_admission(
                    existing,
                    request=request,
                    actor=actor,
                    admission_digest=admission_digest,
                )
                existing_storage_key = existing.storage_key
            else:
                producer_job = self._records.job(session, request.producer_job_id)
                producer_run = self._records.run(session, request.producer_run_id)
                expected_sealed_run_id = self._require_artifact_producer(
                    producer_run,
                    producer_job,
                    request=request,
                )
                producer_attempt = producer_job.attempts

        if existing_ref is not None:
            assert existing_storage_key is not None
            return self._reconfirm_source_artifact_admission(
                artifact_repository,
                request=request,
                actor=actor,
                admission_digest=admission_digest,
                expected_ref=existing_ref,
                expected_storage_key=existing_storage_key,
            )

        assert producer_attempt is not None
        assert expected_sealed_run_id is not None
        try:
            snapshot = artifact_repository.import_run(
                staging_id=request.staging_id,
                producer_run_id=request.producer_run_id,
                media_type=_SOURCE_ARTIFACT_MEDIA_TYPE,
                schema_kind=_SOURCE_ARTIFACT_SCHEMA_KIND,
                created_by=actor,
            )
        except ArtifactRepositoryError as exc:
            with self.repository.transaction() as session:
                committed = self._records.artifact_by_idempotency_key(
                    session,
                    request.idempotency_key,
                )
                if committed is not None:
                    existing_ref = self._existing_artifact_admission(
                        committed,
                        request=request,
                        actor=actor,
                        admission_digest=admission_digest,
                    )
                    existing_storage_key = committed.storage_key
            if existing_ref is not None and existing_storage_key is not None:
                return self._reconfirm_source_artifact_admission(
                    artifact_repository,
                    request=request,
                    actor=actor,
                    admission_digest=admission_digest,
                    expected_ref=existing_ref,
                    expected_storage_key=existing_storage_key,
                )
            if isinstance(exc, ArtifactNotFound):
                raise ResourceNotFound("staged source Artifact not found") from exc
            raise StateConflict("staged source Artifact failed managed admission") from exc

        source_ref = snapshot.ref
        if (
            source_ref.producer_run_id != request.producer_run_id
            or source_ref.run_id != expected_sealed_run_id
            or source_ref.media_type != _SOURCE_ARTIFACT_MEDIA_TYPE
            or source_ref.schema_kind != _SOURCE_ARTIFACT_SCHEMA_KIND
            or source_ref.created_by != actor
        ):
            raise StateConflict("managed source Artifact metadata is not admission-bound")

        try:
            with self._artifact_commit_transaction(
                artifact_repository,
                staging_id=request.staging_id,
            ) as (session, consume_after_commit):
                existing = self._records.artifact_by_idempotency_key(
                    session,
                    request.idempotency_key,
                    lock=True,
                )
                if existing is not None:
                    existing_ref = self._existing_artifact_admission(
                        existing,
                        request=request,
                        actor=actor,
                        admission_digest=admission_digest,
                    )
                    self._require_artifact_snapshot(
                        existing,
                        source_ref,
                        storage_key=snapshot.storage_key,
                    )
                    consume_after_commit(existing_ref)
                    return existing_ref

                # Match the global Job -> Run lock order used by claim/completion. State and
                # attempts must still equal the eligibility snapshot taken before import.
                producer_job = self._records.job(session, request.producer_job_id, lock=True)
                producer_run = self._records.run(session, request.producer_run_id, lock=True)
                final_sealed_run_id = self._require_artifact_producer(
                    producer_run,
                    producer_job,
                    request=request,
                )
                if producer_job.attempts != producer_attempt:
                    raise StateConflict("producer Job attempt changed during Artifact admission")
                if source_ref.run_id != final_sealed_run_id:
                    raise StateConflict("sealed Artifact Run does not match producer Job result")

                now = utc_now()
                artifact = ArtifactRecord(
                    artifact_id=source_ref.artifact_id,
                    repository_version=source_ref.repository_version,
                    producer_run_id=request.producer_run_id,
                    producer_job_id=request.producer_job_id,
                    producer_attempt=producer_attempt,
                    sealed_run_id=source_ref.run_id,
                    media_type=source_ref.media_type,
                    schema_kind=source_ref.schema_kind,
                    byte_length=source_ref.byte_length,
                    content_digest=source_ref.content_digest,
                    root_digest=source_ref.integrity_root_digest,
                    created_by=actor,
                    storage_key=snapshot.storage_key,
                    idempotency_key=request.idempotency_key,
                    admission_digest=admission_digest,
                    created_at=now,
                )
                session.add(artifact)
                session.flush()
                self._event(
                    session,
                    producer_run,
                    "artifact.source-admitted",
                    actor,
                    {
                        "artifactId": source_ref.artifact_id,
                        "repositoryVersion": source_ref.repository_version,
                        "producerJobId": request.producer_job_id,
                        "producerAttempt": producer_attempt,
                        "sealedRunId": source_ref.run_id,
                        "contentDigest": source_ref.content_digest,
                        "integrityRootDigest": source_ref.integrity_root_digest,
                    },
                )
                consume_after_commit(source_ref)
                return source_ref
        except IntegrityError as exc:
            with self._artifact_commit_transaction(
                artifact_repository,
                staging_id=request.staging_id,
            ) as (session, consume_after_commit):
                existing = self._records.artifact_by_idempotency_key(
                    session,
                    request.idempotency_key,
                )
                if existing is None:
                    raise StateConflict(
                        "managed Artifact identity conflicts with existing authority"
                    ) from exc
                existing_ref = self._existing_artifact_admission(
                    existing,
                    request=request,
                    actor=actor,
                    admission_digest=admission_digest,
                )
                self._require_artifact_snapshot(
                    existing,
                    source_ref,
                    storage_key=snapshot.storage_key,
                )
                consume_after_commit(existing_ref)
                return existing_ref

    def create_replay_batch(
        self,
        request: CreateReplayBatchRequest,
        *,
        actor: str,
    ) -> ReplayBatchView:
        return self._replay_issuance.create_replay_batch(request, actor=actor)

    def issue_replay_batch(
        self,
        batch_id: str,
        *,
        actor: str,
    ) -> ReplayBatchIssuanceView:
        return self._replay_issuance.issue_replay_batch(batch_id, actor=actor)

    @contextmanager
    def _replay_issuance_transaction(
        self,
        artifact_repository: ManagedArtifactRepository,
    ) -> Iterator[tuple[Session, list[str]]]:
        with self._replay_issuance.transaction(artifact_repository) as transaction:
            yield transaction

    def get_replay_batch(self, batch_id: str) -> ReplayBatchView:
        return self._replay_reads.get_batch(batch_id)

    def get_replay_item(self, item_id: str) -> ReplayItemView:
        return self._replay_reads.get_item(item_id)

    def get_replay_ticket(self, ticket_id: str) -> ReplayTicketView:
        return self._replay_reads.get_ticket(ticket_id)

    def get_replay_finalization(self, ticket_id: str) -> ReplayFinalizationView | None:
        return self._replay_reads.get_finalization(ticket_id)

    def get_replay_projection(self, batch_id: str) -> ReplayProjectionView | None:
        return self._replay_reads.get_projection(batch_id)

    def get_run(self, run_id: str) -> RunView:
        with self.repository.read_transaction() as session:
            return self._views.run(self._records.run(session, run_id))

    def list_runs(
        self,
        *,
        state: RunState | None,
        limit: int,
        offset: int,
    ) -> RunListView:
        with self.repository.read_transaction() as session:
            filters = () if state is None else (RunRecord.state == state.value,)
            total = session.scalar(select(func.count()).select_from(RunRecord).where(*filters))
            records = session.scalars(
                select(RunRecord)
                .options(
                    load_only(
                        RunRecord.run_id,
                        RunRecord.campaign_name,
                        RunRecord.state,
                        RunRecord.current_checkpoint_id,
                        RunRecord.created_at,
                        RunRecord.updated_at,
                    )
                )
                .where(*filters)
                .order_by(RunRecord.updated_at.desc(), RunRecord.run_id.desc())
                .offset(offset)
                .limit(limit)
            ).all()
            return RunListView(
                items=[self._views.run_summary(record) for record in records],
                total=int(total or 0),
                limit=limit,
                offset=offset,
            )

    def get_current_approval(self, run_id: str, *, actor: str) -> ApprovalView | None:
        with self.repository.transaction() as session:
            run_reference = self._records.run(session, run_id)
            run_state = run_reference.state
            checkpoint_id = run_reference.current_checkpoint_id
            if checkpoint_id is None:
                if run_state == RunState.AWAITING_APPROVAL.value:
                    raise StateConflict("awaiting-approval Run has no current checkpoint")
                return None
            # Match decision/resume ordering: checkpoint -> approval -> Run. The initial
            # Run read only discovers the immutable current checkpoint identifier.
            checkpoint = self._records.checkpoint(session, checkpoint_id, lock=True)
            approval = self._records.approval_for_checkpoint(session, checkpoint_id, lock=True)
            run = self._records.run(session, run_id, lock=True)
            if run.current_checkpoint_id != checkpoint_id:
                if (
                    run.current_checkpoint_id is None
                    and run.state != RunState.AWAITING_APPROVAL.value
                ):
                    return None
                raise StateConflict("Run current checkpoint changed during approval read")
            run_state = run.state
            if run_state not in {
                RunState.AWAITING_APPROVAL.value,
                RunState.CANCELLED.value,
            }:
                raise StateConflict(f"run in {run_state} state cannot have a current checkpoint")
            if checkpoint.run_id != run.run_id or approval.run_id != run.run_id:
                raise StateConflict("current checkpoint ownership is inconsistent")
            self._lifecycle.verify_checkpoint(checkpoint)
            intent = self._views.checkpoint_intent(checkpoint)
            if not self._lifecycle.approval_matches_intent(approval, intent):
                raise StateConflict("approval fields do not match signed checkpoint intent")
            now = utc_now()
            if (
                run_state == RunState.AWAITING_APPROVAL.value
                and approval.state in _REVOCABLE_APPROVAL_STATES
                and _aware(approval.expires_at) <= now
            ):
                self._lifecycle.expire_approval(
                    session,
                    approval,
                    run,
                    actor=actor,
                    now=now,
                )
                run_state = run.state
            allowed_states = (
                {ApprovalState.PENDING.value, ApprovalState.APPROVED.value}
                if run_state == RunState.AWAITING_APPROVAL.value
                else {
                    ApprovalState.DENIED.value,
                    ApprovalState.EXPIRED.value,
                    ApprovalState.REVOKED.value,
                }
            )
            if approval.state not in allowed_states:
                raise StateConflict("approval state does not match the Run lifecycle")
            return self._views.approval(approval)

    def cancel_run(
        self,
        run_id: str,
        request: CancelRunRequest,
        *,
        actor: str,
    ) -> CancelRunView:
        return self._lifecycle.cancel_run(run_id, request, actor=actor)

    def get_job(self, job_id: str) -> JobView:
        with self.repository.read_transaction() as session:
            return self._views.job(self._records.job(session, job_id))

    def list_events(
        self,
        run_id: str,
        *,
        limit: int = MAX_AUDIT_EVENT_PAGE_SIZE,
        before_sequence: int | None = None,
    ) -> list[AuditEventView]:
        if type(limit) is not int or not 1 <= limit <= MAX_AUDIT_EVENT_PAGE_SIZE:
            raise ControlPlaneError("Audit Event page limit is invalid")
        if before_sequence is not None and (
            type(before_sequence) is not int or not 1 <= before_sequence <= 2_147_483_647
        ):
            raise ControlPlaneError("Audit Event page cursor is invalid")
        with self.repository.read_transaction() as session:
            self._records.run(session, run_id)
            statement = select(EventRecord).where(EventRecord.run_id == run_id)
            if before_sequence is not None:
                statement = statement.where(EventRecord.sequence < before_sequence)
            statement = statement.order_by(EventRecord.sequence.desc()).limit(limit)

            # Iterate a bounded database page newest-first and stop at a bounded
            # serialized response budget. Returning only a contiguous suffix
            # preserves an exclusive `before` cursor without skipping history.
            events_descending: list[AuditEventView] = []
            response_bytes = 2  # JSON array brackets.
            response_budget = MAX_AUDIT_EVENT_RESPONSE_BYTES - _AUDIT_EVENT_RESPONSE_SAFETY_BYTES
            for record in session.scalars(statement).yield_per(10):
                event = self._views.event(record)
                event_bytes = len(
                    json.dumps(
                        event.model_dump(mode="json"),
                        allow_nan=False,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode("utf-8")
                )
                separator_bytes = 1 if events_descending else 0
                if response_bytes + separator_bytes + event_bytes > response_budget:
                    break
                response_bytes += separator_bytes + event_bytes
                events_descending.append(event)
            events_descending.reverse()
            return events_descending

    def claim_job(self, request: ClaimJobRequest, *, actor: str) -> ClaimedJob | None:
        return self._claims.claim_job(request, actor=actor)

    def claim_replay_job(
        self,
        request: ReplayClaimRequest,
        *,
        actor: str,
    ) -> ReplayExecutionClaimView | None:
        claimed = self._claims.claim_replay_job(request, actor=actor)
        if claimed is not None:
            return claimed
        if not self._replay_issuance.issue_pending_replay_retries(actor=_REPLAY_RETRY_ISSUER_ACTOR):
            return None
        return self._claims.claim_replay_job(request, actor=actor)

    def heartbeat_replay_job(
        self,
        job_id: str,
        request: ReplayLeaseRequest,
        *,
        actor: str,
    ) -> ReplayExecutionClaimView:
        return self._claims.heartbeat_replay_job(job_id, request, actor=actor)

    def issue_replay_tool_permit(
        self,
        job_id: str,
        request: ReplayToolPermitRequest,
        *,
        actor: str,
    ) -> ReplayToolPermitView:
        """Consume exactly one canonical call from an active Replay attempt.

        The returned permit is an immutable audit handle, not a bearer secret. Its
        existence means the budget and rolling request-rate authority were consumed,
        even when the caller later cannot determine whether execution occurred.
        """

        self._claims.require_replay_executor_profile(actor, request.executor_profile)
        expired_reason: str | None = None
        result: ReplayToolPermitView | None = None
        with self.repository.transaction() as session:
            attempt = self._replay_attempt(session, job_id, lock=True)
            self._require_uncancelled_replay_attempt(attempt)
            now = utc_now()
            self._claims.require_replay_lease_identity(
                attempt.job,
                attempt.ticket,
                request=request,
                actor=actor,
            )
            lease_deadline, compilation_deadline = self._replay_permit_deadlines(attempt, now)
            expired_reason = self._expire_replay_permit_authority(
                session,
                attempt=attempt,
                actor=actor,
                now=now,
                lease_deadline=lease_deadline,
                compilation_deadline=compilation_deadline,
            )
            if expired_reason is None:
                self._require_active_replay_permit_states(attempt)
                result = self._issue_or_reuse_replay_tool_permit(
                    session,
                    attempt=attempt,
                    request=request,
                    actor=actor,
                    now=now,
                    lease_deadline=lease_deadline,
                    compilation_deadline=compilation_deadline,
                )
        if expired_reason is not None:
            raise LeaseRejected(expired_reason)
        if result is None:
            raise RuntimeError("Replay Tool permit issuance did not produce a result")
        return result

    @staticmethod
    def _require_uncancelled_replay_attempt(attempt: _LockedReplayAttempt) -> None:
        if (
            attempt.run.state == RunState.CANCELLED.value
            or attempt.batch.state == ReplayBatchState.CANCELLED.value
            or attempt.item.state == ReplayItemState.CANCELLED.value
        ):
            raise RunCancelled("run has been cancelled")

    @staticmethod
    def _replay_permit_deadlines(
        attempt: _LockedReplayAttempt,
        now: datetime,
    ) -> tuple[datetime, datetime]:
        lease_deadline = min(
            _aware(attempt.job.lease_expires_at) if attempt.job.lease_expires_at else now,
            (_aware(attempt.ticket.lease_expires_at) if attempt.ticket.lease_expires_at else now),
            _aware(attempt.job.lease_deadline_at) if attempt.job.lease_deadline_at else now,
        )
        compilation_deadline = min(
            _aware(attempt.authority.compilation.spec.expires_at),
            _aware(attempt.authority.compilation.grant.expires_at),
        )
        return lease_deadline, compilation_deadline

    def _expire_replay_permit_authority(
        self,
        session: Session,
        *,
        attempt: _LockedReplayAttempt,
        actor: str,
        now: datetime,
        lease_deadline: datetime,
        compilation_deadline: datetime,
    ) -> str | None:
        if lease_deadline <= now:
            reason = "Replay lease expired before Tool permit issuance"
            event_type = "replay.ticket.lease-expired"
            rejection = "Replay job lease has expired"
        elif compilation_deadline <= now:
            reason = "Replay compilation authority expired before Tool permit issuance"
            event_type = "replay.ticket.compilation-expired"
            rejection = "Replay compilation authority has expired"
        else:
            return None
        self._claims.terminate_replay_attempt(
            session,
            job=attempt.job,
            ticket=attempt.ticket,
            item=attempt.item,
            batch=attempt.batch,
            run=attempt.run,
            actor=actor,
            now=now,
            reason=reason,
            retryable=True,
            event_type=event_type,
        )
        return rejection

    def _require_active_replay_permit_states(self, attempt: _LockedReplayAttempt) -> None:
        self._lifecycle.require_run_state(attempt.run, RunState.RUNNING)
        if attempt.batch.state != ReplayBatchState.RUNNING.value:
            raise LeaseRejected("Replay batch is not running")
        if attempt.item.state != ReplayItemState.RUNNING.value:
            raise LeaseRejected("Replay item is not running")
        if attempt.ticket.state != ReplayTicketState.CLAIMED.value:
            raise LeaseRejected("Replay ticket is not claimed")

    def _issue_or_reuse_replay_tool_permit(
        self,
        session: Session,
        *,
        attempt: _LockedReplayAttempt,
        request: ReplayToolPermitRequest,
        actor: str,
        now: datetime,
        lease_deadline: datetime,
        compilation_deadline: datetime,
    ) -> ReplayToolPermitView:
        existing = next(
            (
                permit
                for permit in attempt.authority.permits
                if permit.call_ordinal == request.call_ordinal
            ),
            None,
        )
        if existing is not None:
            return self._views.replay_tool_permit(existing)
        self._require_next_replay_permit_ordinal(attempt.authority, request.call_ordinal)
        request_units = AIChatProbeTool().network_request_cost(
            attempt.authority.compilation.original_request
        )
        require_replay_permit_rate_capacity(
            session,
            authority=attempt.authority,
            request_units=request_units,
            now=now,
        )
        permit_expires_at = min(
            now + _REPLAY_TOOL_PERMIT_TTL,
            lease_deadline,
            compilation_deadline,
        )
        if permit_expires_at <= now:
            raise LeaseRejected("Replay Tool permit authority expired before issuance")
        permit = self._new_replay_tool_permit(
            attempt=attempt,
            request=request,
            actor=actor,
            request_units=request_units,
            now=now,
            permit_expires_at=permit_expires_at,
        )
        session.add(permit)
        self._consume_replay_permit_capacity(
            attempt.authority,
            request_units=request_units,
            now=now,
        )
        session.flush()
        self._verify_consumed_replay_permit_capacity(session, attempt.authority)
        self._record_replay_permit_issuance(
            session,
            attempt=attempt,
            permit=permit,
            actor=actor,
        )
        return self._views.replay_tool_permit(permit)

    @staticmethod
    def _require_next_replay_permit_ordinal(
        authority: ReplayBindingAuthority,
        call_ordinal: int,
    ) -> None:
        expected_ordinal = authority.budget_reservation.consumed_calls + 1
        if call_ordinal != expected_ordinal:
            raise StateConflict("Replay Tool permit ordinal must be the next unconsumed call")
        if call_ordinal > authority.compilation.spec.repetitions:
            raise StateConflict("Replay Tool call budget is already exhausted")

    def _new_replay_tool_permit(
        self,
        *,
        attempt: _LockedReplayAttempt,
        request: ReplayToolPermitRequest,
        actor: str,
        request_units: int,
        now: datetime,
        permit_expires_at: datetime,
    ) -> ReplayToolPermitRecord:
        authority = attempt.authority
        binding = authority.compilation.spec.binding
        permit_values: dict[str, Any] = {
            "permit_id": f"replay-permit_{uuid4().hex}",
            "replay_request_id": f"tool_replay_{uuid4().hex}",
            "job_id": attempt.job.job_id,
            "batch_id": attempt.batch.batch_id,
            "item_id": attempt.item.item_id,
            "ticket_id": attempt.ticket.ticket_id,
            "compilation_id": authority.compilation_record.compilation_id,
            "budget_reservation_id": authority.budget_reservation.budget_reservation_id,
            "rate_reservation_id": authority.rate_reservation.rate_reservation_id,
            "replay_run_id": attempt.ticket.replay_run_id,
            "attempt_number": attempt.ticket.attempt_number,
            "fencing_value": attempt.ticket.fencing_value,
            "call_ordinal": request.call_ordinal,
            "issued_to": actor,
            "executor_profile": request.executor_profile,
            "lease_token_hash": attempt.job.lease_token_hash,
            "source_root_digest": attempt.ticket.source_root_digest,
            "compilation_digest": attempt.ticket.compilation_digest,
            "grant_digest": attempt.ticket.grant_digest,
            "original_request_id": binding.original_request_id,
            "tool_id": binding.tool_id,
            "tool_version": binding.tool_version,
            "target_id": binding.target_id,
            "target": binding.target,
            "method": authority.compilation.spec.method,
            "compiled_argument_digest": authority.compilation.spec.argument_digest,
            "tool_call_units": 1,
            "request_units": request_units,
            "issued_at": now,
            "expires_at": permit_expires_at,
            "rate_window_expires_at": now
            + timedelta(seconds=authority.rate_account.window_seconds),
        }
        permit_values["permit_digest"] = replay_tool_permit_digest(permit_values)
        return ReplayToolPermitRecord(**permit_values)

    @staticmethod
    def _consume_replay_permit_capacity(
        authority: ReplayBindingAuthority,
        *,
        request_units: int,
        now: datetime,
    ) -> None:
        budget = authority.budget_reservation
        remaining_calls = budget.total_calls - budget.consumed_calls - budget.released_calls
        if (
            budget.state != "active"
            or remaining_calls < 1
            or authority.budget_account.reserved_calls < 1
        ):
            raise StateConflict("Replay Tool-call budget reservation is exhausted")
        rate = authority.rate_reservation
        remaining_request_units = (
            rate.total_request_units - rate.consumed_request_units - rate.released_request_units
        )
        if rate.state != "active" or remaining_request_units < request_units:
            raise StateConflict("Replay request-unit reservation is exhausted")
        budget.consumed_calls += 1
        budget.updated_at = now
        if budget.consumed_calls == budget.total_calls:
            budget.state = "consumed"
        authority.budget_account.reserved_calls -= 1
        authority.budget_account.consumed_calls += 1
        authority.budget_account.cas_version += 1
        authority.budget_account.updated_at = now
        rate.consumed_request_units += request_units
        rate.updated_at = now
        if rate.consumed_request_units == rate.total_request_units:
            rate.state = "consumed"
        authority.rate_account.cas_version += 1
        authority.rate_account.updated_at = now

    def _verify_consumed_replay_permit_capacity(
        self,
        session: Session,
        authority: ReplayBindingAuthority,
    ) -> None:
        require_exact_replay_budget_ledger(
            authority.budget_account,
            authority.budget_reservations,
        )
        require_exact_replay_account_permit_consumption(
            session,
            budget_reservations=authority.budget_reservations,
            rate_reservations=authority.rate_reservations,
        )

    def _record_replay_permit_issuance(
        self,
        session: Session,
        *,
        attempt: _LockedReplayAttempt,
        permit: ReplayToolPermitRecord,
        actor: str,
    ) -> None:
        self._replay_event(
            session,
            attempt.batch,
            "replay.tool-permit.issued",
            actor,
            {
                "permitId": permit.permit_id,
                "permitDigest": permit.permit_digest,
                "replayRequestId": permit.replay_request_id,
                "callOrdinal": permit.call_ordinal,
                "toolId": permit.tool_id,
                "targetId": permit.target_id,
                "toolCallUnits": permit.tool_call_units,
                "requestUnits": permit.request_units,
                "expiresAt": permit.expires_at.isoformat(),
                "rateWindowExpiresAt": permit.rate_window_expires_at.isoformat(),
            },
            item=attempt.item,
            ticket=attempt.ticket,
            job=attempt.job,
            run_id=attempt.run.run_id,
        )

    def _prepare_replay_finalization(
        self,
        session: Session,
        *,
        job_id: str,
        request: ReplayFinalizeRequest,
        actor: str,
    ) -> _ReplayFinalizationPreflight:
        attempt = self._replay_attempt(session, job_id, lock=False)
        self._claims.require_replay_lease_identity(
            attempt.job,
            attempt.ticket,
            request=request,
            actor=actor,
        )
        self._require_finalizable_replay_attempt(attempt, request=request, now=utc_now())
        source_ref = self._views.replay_source(attempt.batch)
        source_record = self._records.artifact(
            session,
            ArtifactLocator(
                artifact_id=source_ref.artifact_id,
                repository_version=source_ref.repository_version,
            ),
        )
        return _ReplayFinalizationPreflight(
            attempt=attempt,
            source_ref=source_ref,
            source_storage_key=source_record.storage_key,
        )

    @staticmethod
    def _require_finalizable_replay_attempt(
        attempt: _LockedReplayAttempt,
        *,
        request: ReplayFinalizeRequest,
        now: datetime,
    ) -> None:
        job_deadline = attempt.job.lease_expires_at
        ticket_deadline = attempt.ticket.lease_expires_at
        hard_deadline = attempt.job.lease_deadline_at
        if (
            job_deadline is None
            or ticket_deadline is None
            or hard_deadline is None
            or min(
                _aware(job_deadline),
                _aware(ticket_deadline),
                _aware(hard_deadline),
            )
            <= now
        ):
            raise LeaseRejected("Replay job lease has expired")
        if not (
            attempt.run.state == RunState.RUNNING.value
            and attempt.batch.state == ReplayBatchState.RUNNING.value
            and attempt.item.state == ReplayItemState.RUNNING.value
            and attempt.ticket.state == ReplayTicketState.CLAIMED.value
        ):
            raise StateConflict("Replay authority is not in a finalizable state")
        if request.output_staging_id != attempt.authority.execution_context.output_staging_id:
            raise LeaseRejected("Replay output capability does not match the issued context")
        if len(attempt.authority.permits) != attempt.authority.compilation.spec.repetitions:
            raise StateConflict("Replay output cannot finalize before every Tool permit exists")

    @staticmethod
    def _require_unchanged_replay_finalization_authority(
        attempt: _LockedReplayAttempt,
        *,
        request: ReplayFinalizeRequest,
        expected_ticket: ReplayTicketRecord,
        verified: VerifiedReplayResult,
        now: datetime,
    ) -> None:
        lease_deadline = min(
            _aware(attempt.job.lease_expires_at) if attempt.job.lease_expires_at else now,
            _aware(attempt.ticket.lease_expires_at) if attempt.ticket.lease_expires_at else now,
            _aware(attempt.job.lease_deadline_at) if attempt.job.lease_deadline_at else now,
        )
        if lease_deadline <= now:
            raise LeaseRejected("Replay job lease has expired")
        authority = attempt.authority
        unchanged = (
            attempt.run.state == RunState.RUNNING.value
            and attempt.batch.state == ReplayBatchState.RUNNING.value
            and attempt.item.state == ReplayItemState.RUNNING.value
            and attempt.ticket.state == ReplayTicketState.CLAIMED.value
            and request.output_staging_id == authority.execution_context.output_staging_id
            and len(authority.permits) == authority.compilation.spec.repetitions
            and attempt.ticket.compilation_id == expected_ticket.compilation_id
            and attempt.ticket.fencing_value == expected_ticket.fencing_value
            and attempt.ticket.replay_run_id == verified.receipt.replay_run_id
        )
        if not unchanged:
            raise StateConflict("Replay authority changed during output verification")

    def _admit_replay_output_artifact(
        self,
        session: Session,
        *,
        attempt: _LockedReplayAttempt,
        output_snapshot: ManagedArtifactSnapshot,
        admission_digest: str,
        actor: str,
        now: datetime,
    ) -> ArtifactRecord:
        output_ref = output_snapshot.ref
        idempotency_key = f"replay-output:{attempt.ticket.ticket_id}"
        artifact = self._records.artifact_by_idempotency_key(
            session,
            idempotency_key,
            lock=True,
        )
        if artifact is None:
            artifact = ArtifactRecord(
                artifact_id=output_ref.artifact_id,
                repository_version=output_ref.repository_version,
                producer_run_id=attempt.run.run_id,
                producer_job_id=attempt.job.job_id,
                producer_attempt=attempt.job.attempts,
                sealed_run_id=output_ref.run_id,
                media_type=output_ref.media_type,
                schema_kind=output_ref.schema_kind,
                byte_length=output_ref.byte_length,
                content_digest=output_ref.content_digest,
                root_digest=output_ref.integrity_root_digest,
                created_by=actor,
                storage_key=output_snapshot.storage_key,
                idempotency_key=idempotency_key,
                admission_digest=admission_digest,
                created_at=now,
            )
            session.add(artifact)
            session.flush()
            return artifact
        if not (
            self._views.artifact(artifact) == output_ref
            and artifact.storage_key == output_snapshot.storage_key
            and artifact.admission_digest == admission_digest
        ):
            raise StateConflict("Replay output Artifact authority is already different")
        return artifact

    def finalize_replay_job(
        self,
        job_id: str,
        request: ReplayFinalizeRequest,
        *,
        actor: str,
    ) -> ReplayFinalizationView:
        """Import sealed output and atomically derive every authoritative result."""

        self._claims.require_replay_executor_profile(actor, request.executor_profile)
        artifact_repository = self._require_artifact_repository()

        # Do not hold database locks across a bounded filesystem copy and typed seal
        # verification. The write transaction below rechecks the complete authority.
        existing_view: ReplayFinalizationView | None = None
        preflight: _ReplayFinalizationPreflight | None = None
        with self._artifact_commit_transaction(
            artifact_repository,
            staging_id=request.output_staging_id,
        ) as (session, consume_after_commit):
            existing = self._records.replay_finalization_for_ticket(
                session,
                request.ticket_id,
            )
            if existing is not None:
                existing_view = self._existing_replay_finalization(
                    session,
                    existing,
                    job_id=job_id,
                    request=request,
                    actor=actor,
                    artifact_repository=artifact_repository,
                )
                consume_after_commit(existing_view.artifact)
            else:
                preflight = self._prepare_replay_finalization(
                    session,
                    job_id=job_id,
                    request=request,
                    actor=actor,
                )

        if existing_view is not None:
            self._publish_ready_replay_projection(existing_view.batch.batch_id)
            refreshed = self.get_replay_finalization(request.ticket_id)
            if refreshed is None:
                raise StateConflict("Replay finalization authority disappeared")
            return refreshed
        if preflight is None:
            raise StateConflict("Replay finalization preflight was not established")

        attempt = preflight.attempt
        job = attempt.job
        ticket = attempt.ticket
        item = attempt.item
        batch = attempt.batch
        authority = attempt.authority
        source_ref = preflight.source_ref

        source_snapshot = self._resolve_managed_artifact(
            artifact_repository,
            source_ref,
            expected_storage_key=preflight.source_storage_key,
        )
        try:
            output_snapshot = artifact_repository.import_run(
                staging_id=request.output_staging_id,
                producer_run_id=job.run_id,
                media_type=_SOURCE_ARTIFACT_MEDIA_TYPE,
                schema_kind=_REPLAY_OUTPUT_ARTIFACT_SCHEMA_KIND,
                created_by=actor,
            )
            verified = inspect_sealed_replay_result(output_snapshot.path)
        except ArtifactNotFound as exc:
            raise ResourceNotFound("staged Replay output not found") from exc
        except (ArtifactRepositoryError, ValueError) as exc:
            raise StateConflict("staged Replay output failed authoritative verification") from exc

        gate_decision = self._verify_replay_output_and_gate(
            authority=authority,
            batch=batch,
            item=item,
            ticket=ticket,
            output_snapshot=output_snapshot,
            verified=verified,
            source_snapshot=source_snapshot,
            now=utc_now(),
        )
        gate_payload = gate_decision.model_dump(mode="json", by_alias=True)
        gate_digest = replay_context_digest(gate_payload)
        finalization_material = {
            "artifact": output_snapshot.ref.model_dump(mode="json"),
            "artifactSetDigest": verified.receipt.artifact_set_digest,
            "artifactSealRootDigest": verified.receipt.artifact_seal_root_digest,
            "batchId": batch.batch_id,
            "compilationId": ticket.compilation_id,
            "fencingValue": ticket.fencing_value,
            "gateDecisionDigest": gate_digest,
            "itemId": item.item_id,
            "jobId": job.job_id,
            "receiptSealRootDigest": verified.receipt_seal_root_digest,
            "ticketId": ticket.ticket_id,
        }
        result_digest = replay_context_digest(finalization_material)
        admission_digest = replay_context_digest(
            {
                "domain": "pajin.control-plane.replay-output-admission/v1",
                "resultDigest": result_digest,
                "stagingId": request.output_staging_id,
            }
        )

        try:
            with self._artifact_commit_transaction(
                artifact_repository,
                staging_id=request.output_staging_id,
            ) as (session, consume_after_commit):
                existing = self._records.replay_finalization_for_ticket(
                    session,
                    request.ticket_id,
                    lock=True,
                )
                if existing is not None:
                    existing_view = self._existing_replay_finalization(
                        session,
                        existing,
                        job_id=job_id,
                        request=request,
                        actor=actor,
                        artifact_repository=artifact_repository,
                    )
                    consume_after_commit(existing_view.artifact)
                    return existing_view

                locked_attempt = self._replay_attempt(session, job_id, lock=True)
                locked_job = locked_attempt.job
                locked_ticket = locked_attempt.ticket
                locked_item = locked_attempt.item
                locked_batch = locked_attempt.batch
                locked_run = locked_attempt.run
                self._claims.require_replay_lease_identity(
                    locked_job,
                    locked_ticket,
                    request=request,
                    actor=actor,
                )
                finalized_at = utc_now()
                self._require_unchanged_replay_finalization_authority(
                    locked_attempt,
                    request=request,
                    expected_ticket=ticket,
                    verified=verified,
                    now=finalized_at,
                )

                artifact = self._admit_replay_output_artifact(
                    session,
                    attempt=locked_attempt,
                    output_snapshot=output_snapshot,
                    admission_digest=admission_digest,
                    actor=actor,
                    now=finalized_at,
                )

                finalization = ReplayFinalizationRecord(
                    finalization_id=f"replay-finalization_{uuid4().hex}",
                    ticket_id=locked_ticket.ticket_id,
                    batch_id=locked_batch.batch_id,
                    item_id=locked_item.item_id,
                    job_id=locked_job.job_id,
                    replay_run_id=locked_run.run_id,
                    compilation_id=locked_ticket.compilation_id,
                    attempt_number=locked_ticket.attempt_number,
                    fencing_value=locked_ticket.fencing_value,
                    output_staging_id=request.output_staging_id,
                    artifact_id=artifact.artifact_id,
                    repository_version=artifact.repository_version,
                    artifact_set_digest=verified.receipt.artifact_set_digest,
                    artifact_seal_root_digest=verified.receipt.artifact_seal_root_digest,
                    receipt_seal_root_digest=verified.receipt_seal_root_digest,
                    gate_decision=gate_payload,
                    gate_decision_digest=gate_digest,
                    result_digest=result_digest,
                    finalized_by=actor,
                    finalized_at=finalized_at,
                )
                session.add(finalization)

                locked_ticket.state = ReplayTicketState.FINALIZED.value
                locked_ticket.result_digest = result_digest
                locked_ticket.finalized_at = finalized_at
                locked_ticket.updated_at = finalized_at
                locked_job.state = JobState.SUCCEEDED.value
                locked_job.result = {
                    "kind": "pajin.replay.finalization.v1",
                    "finalizationId": finalization.finalization_id,
                    "artifactId": artifact.artifact_id,
                    "repositoryVersion": artifact.repository_version,
                    "gateDecisionId": gate_decision.decision_id,
                    "resultDigest": result_digest,
                }
                locked_job.error = None
                locked_job.lease_deadline_at = None
                locked_job.heartbeat_event_at = None
                locked_job.updated_at = finalized_at
                locked_run.state = RunState.COMPLETED.value
                locked_run.updated_at = finalized_at
                locked_item.state = ReplayItemState.VERIFIED.value
                locked_item.updated_at = finalized_at
                self._replay_event(
                    session,
                    locked_batch,
                    "replay.output.verified",
                    actor,
                    {
                        "artifactId": artifact.artifact_id,
                        "artifactSetDigest": verified.receipt.artifact_set_digest,
                        "receiptSealRootDigest": verified.receipt_seal_root_digest,
                    },
                    item=locked_item,
                    ticket=locked_ticket,
                    job=locked_job,
                    run_id=locked_run.run_id,
                )
                locked_batch.cas_version += 1
                batch_items = list(
                    session.scalars(
                        select(ReplayItemRecord)
                        .where(ReplayItemRecord.batch_id == locked_batch.batch_id)
                        .order_by(ReplayItemRecord.ordinal, ReplayItemRecord.item_id)
                    ).all()
                )
                if all(
                    item_record.state == ReplayItemState.VERIFIED.value
                    for item_record in batch_items
                ):
                    locked_batch.state = ReplayBatchState.GATING.value
                locked_batch.updated_at = finalized_at
                self._event(
                    session,
                    locked_run,
                    "job.replay-finalized",
                    actor,
                    {
                        "jobId": locked_job.job_id,
                        "replayTicketId": locked_ticket.ticket_id,
                        "finalizationId": finalization.finalization_id,
                        "resultDigest": result_digest,
                    },
                )
                session.flush()
                consume_after_commit(self._views.artifact(artifact))
                retest_artifact = self._replay_retest_artifact(
                    session,
                    locked_batch,
                    lock=True,
                )
                committed_view = self._views.replay_finalization(
                    finalization,
                    job=locked_job,
                    batch=locked_batch,
                    item=locked_item,
                    ticket=locked_ticket,
                    artifact=artifact,
                    retest_artifact=retest_artifact,
                )
            self._publish_ready_replay_projection(committed_view.batch.batch_id)
            refreshed = self.get_replay_finalization(request.ticket_id)
            if refreshed is None:
                raise StateConflict("Replay finalization authority disappeared")
            return refreshed
        except IntegrityError as exc:
            with self._artifact_commit_transaction(
                artifact_repository,
                staging_id=request.output_staging_id,
            ) as (session, consume_after_commit):
                existing = self._records.replay_finalization_for_ticket(
                    session,
                    request.ticket_id,
                )
                if existing is None:
                    raise StateConflict("Replay finalization authority conflicted") from exc
                existing_view = self._existing_replay_finalization(
                    session,
                    existing,
                    job_id=job_id,
                    request=request,
                    actor=actor,
                    artifact_repository=artifact_repository,
                )
                consume_after_commit(existing_view.artifact)
            self._publish_ready_replay_projection(existing_view.batch.batch_id)
            refreshed = self.get_replay_finalization(request.ticket_id)
            if refreshed is None:
                raise StateConflict("Replay finalization authority disappeared") from exc
            return refreshed

    def _replay_retest_artifact(
        self,
        session: Session,
        batch: ReplayBatchRecord,
        *,
        lock: bool = False,
    ) -> ArtifactRecord | None:
        source = self._records.replay_retest_source(session, batch.batch_id, lock=lock)
        if source is None:
            if batch.purpose == ReplayPurpose.REMEDIATION_RETEST.value:
                raise StateConflict("Replay retest batch has no parent Retest authority")
            return None
        if batch.purpose != ReplayPurpose.REMEDIATION_RETEST.value:
            raise StateConflict("Replay confirmation batch cannot have a parent Retest authority")
        return self._records.artifact(
            session,
            ArtifactLocator(
                artifact_id=source.artifact_id,
                repository_version=source.repository_version,
            ),
            lock=lock,
        )

    def _publish_ready_replay_projection(
        self,
        batch_id: str,
    ) -> ReplayProjectionView | None:
        """Publish one immutable aggregate projection when every item is verified."""

        artifact_repository = self._require_artifact_repository()
        with self.repository.transaction() as session:
            batch = self._records.replay_batch(session, batch_id, lock=True)
            retest_artifact = self._replay_retest_artifact(session, batch, lock=True)
            existing = self._records.replay_projection_for_batch(
                session,
                batch_id,
                lock=True,
            )
            if existing is not None:
                artifact = self._records.artifact(
                    session,
                    ArtifactLocator(
                        artifact_id=existing.artifact_id,
                        repository_version=existing.repository_version,
                    ),
                )
                existing_view = self._views.replay_projection(
                    existing,
                    batch=batch,
                    artifact=artifact,
                    retest_artifact=retest_artifact,
                )
                existing_storage_key = artifact.storage_key
                snapshot = None
            elif batch.state != ReplayBatchState.GATING.value:
                return None
            else:
                snapshot = self._replay_projection_snapshot(session, batch, lock=True)
                existing_view = None
                existing_storage_key = None

        if existing_view is not None:
            assert existing_storage_key is not None
            self._resolve_managed_artifact(
                artifact_repository,
                existing_view.artifact,
                expected_storage_key=existing_storage_key,
            )
            return existing_view
        if snapshot is None:
            return None

        source_snapshot = self._resolve_managed_artifact(
            artifact_repository,
            snapshot.authority.source,
            expected_storage_key=snapshot.source_storage_key,
        )
        retest_source_snapshot: ManagedArtifactSnapshot | None = None
        if isinstance(snapshot.authority, ReplayRetestProjectionInputAuthority):
            if snapshot.retest_source_storage_key is None:
                raise StateConflict("Replay retest projection source authority is incomplete")
            retest_source_snapshot = self._resolve_managed_artifact(
                artifact_repository,
                snapshot.authority.retest_source,
                expected_storage_key=snapshot.retest_source_storage_key,
            )
        elif snapshot.retest_source_storage_key is not None or snapshot.retest_contexts:
            raise StateConflict("Replay confirmation projection contains Retest authority")
        output_snapshots = [
            self._resolve_managed_artifact(
                artifact_repository,
                item.output,
                expected_storage_key=storage_key,
            )
            for item, storage_key in zip(
                snapshot.authority.items,
                snapshot.output_storage_keys,
                strict=True,
            )
        ]
        projection_staging_id = f"stage_{uuid4().hex}"
        try:
            projection_source = retest_source_snapshot or source_snapshot
            staged_projection_path = artifact_repository.stage_managed_run_copy(
                staging_id=projection_staging_id,
                source=projection_source.ref,
            )
            tickets = _ReplayProjectionTicketVerifier(snapshot.authority)
            replay_run_paths = [output.path for output in output_snapshots]
            if isinstance(snapshot.authority, ReplayRetestProjectionInputAuthority):
                replay_batch = KISAReplayBatchOutcome.from_verified_retest_results(
                    source_snapshot.path,
                    staged_projection_path,
                    replay_run_paths,
                    tickets=tickets,
                    contexts=snapshot.retest_contexts,
                )
                KISARetestService().compare(
                    source_snapshot.path,
                    staged_projection_path,
                    replay_batch,
                )
            else:
                apply_confirmed_gate(
                    source_run_path=staged_projection_path,
                    replay_run_paths=replay_run_paths,
                    tickets=tickets,
                    decided_at=snapshot.decided_at,
                )
            projection_snapshot = artifact_repository.import_run(
                staging_id=projection_staging_id,
                producer_run_id=projection_source.ref.producer_run_id,
                media_type=_SOURCE_ARTIFACT_MEDIA_TYPE,
                schema_kind=_REPLAY_PROJECTION_ARTIFACT_SCHEMA_KIND,
                created_by=_REPLAY_PROJECTION_ACTOR,
            )
        except (ArtifactRepositoryError, OSError, ValueError) as exc:
            raise StateConflict("Replay projection failed authoritative derivation") from exc

        admission_digest = replay_context_digest(
            {
                "artifact": projection_snapshot.ref.model_dump(mode="json"),
                "batchId": batch_id,
                "domain": "pajin.control-plane.replay-projection-admission/v1",
                "inputAuthorityDigest": snapshot.authority_digest,
            }
        )
        idempotency_key = f"replay-projection:{batch_id}:{snapshot.authority_digest}"
        with self._projection_artifact_commit_transaction(
            artifact_repository,
            staging_id=projection_staging_id,
            expected_ref=projection_snapshot.ref,
        ) as (session, consume_after_commit):
            locked_batch = self._records.replay_batch(session, batch_id, lock=True)
            locked_retest_artifact = self._replay_retest_artifact(
                session,
                locked_batch,
                lock=True,
            )
            existing = self._records.replay_projection_for_batch(
                session,
                batch_id,
                lock=True,
            )
            if existing is not None:
                artifact = self._records.artifact(
                    session,
                    ArtifactLocator(
                        artifact_id=existing.artifact_id,
                        repository_version=existing.repository_version,
                    ),
                )
                existing_view = self._views.replay_projection(
                    existing,
                    batch=locked_batch,
                    artifact=artifact,
                    retest_artifact=locked_retest_artifact,
                )
                if (
                    existing_view.input_authority != snapshot.authority
                    or existing_view.artifact != projection_snapshot.ref
                ):
                    raise StateConflict("Replay projection retry differs from publication")
                consume_after_commit(existing_view.artifact)
                return existing_view

            current_snapshot = self._replay_projection_snapshot(
                session,
                locked_batch,
                lock=True,
            )
            if (
                locked_batch.state != ReplayBatchState.GATING.value
                or current_snapshot.authority != snapshot.authority
                or current_snapshot.authority_digest != snapshot.authority_digest
                or current_snapshot.source_storage_key != snapshot.source_storage_key
                or current_snapshot.retest_source_storage_key
                != snapshot.retest_source_storage_key
                or current_snapshot.output_storage_keys != snapshot.output_storage_keys
                or current_snapshot.retest_contexts != snapshot.retest_contexts
            ):
                raise StateConflict("Replay projection authority changed before publication")

            published_at = utc_now()
            source_artifact = self._records.artifact(
                session,
                ArtifactLocator(
                    artifact_id=locked_batch.source_artifact_id,
                    repository_version=locked_batch.source_repository_version,
                ),
            )
            projection_source_artifact = locked_retest_artifact or source_artifact
            artifact = self._admit_replay_projection_artifact(
                session,
                snapshot=projection_snapshot,
                source_artifact=projection_source_artifact,
                idempotency_key=idempotency_key,
                admission_digest=admission_digest,
                now=published_at,
            )
            projection = ReplayProjectionRecord(
                projection_id=f"replay-projection_{uuid4().hex}",
                batch_id=locked_batch.batch_id,
                source_root_digest=locked_batch.source_root_digest,
                artifact_id=artifact.artifact_id,
                repository_version=artifact.repository_version,
                batch_cas_version=snapshot.authority.batch_cas_version,
                input_authority=snapshot.authority.model_dump(mode="json", by_alias=True),
                input_authority_digest=snapshot.authority_digest,
                published_by=_REPLAY_PROJECTION_ACTOR,
                published_at=published_at,
            )
            session.add(projection)

            locked_batch.state = ReplayBatchState.COMPLETED.value
            locked_batch.cas_version += 1
            locked_batch.updated_at = published_at
            for authority_item in snapshot.authority.items:
                item = self._records.replay_item(session, authority_item.item_id, lock=True)
                if item.state != ReplayItemState.VERIFIED.value:
                    raise StateConflict("Replay item changed before projection publication")
                ticket = self._records.replay_ticket(
                    session,
                    authority_item.ticket_id,
                    lock=True,
                )
                job = self._records.job(session, ticket.job_id, lock=True)
                item.state = ReplayItemState.GATED.value
                item.updated_at = published_at
                gated_event_type = (
                    "replay.retest.gated"
                    if locked_batch.purpose == ReplayPurpose.REMEDIATION_RETEST.value
                    else "replay.confirmation.gated"
                )
                self._replay_event(
                    session,
                    locked_batch,
                    gated_event_type,
                    _REPLAY_PROJECTION_ACTOR,
                    {
                        "finalizationId": authority_item.finalization_id,
                        "projectionId": projection.projection_id,
                        "projectionArtifactId": artifact.artifact_id,
                        "resultDigest": authority_item.result_digest,
                    },
                    item=item,
                    ticket=ticket,
                    job=job,
                    run_id=item.replay_run_id,
                )
            self._replay_event(
                session,
                locked_batch,
                "replay.projection.published",
                _REPLAY_PROJECTION_ACTOR,
                {
                    "artifactId": artifact.artifact_id,
                    "inputAuthorityDigest": snapshot.authority_digest,
                    "itemCount": len(snapshot.authority.items),
                    "projectionId": projection.projection_id,
                    "repositoryVersion": artifact.repository_version,
                },
            )
            session.flush()
            consume_after_commit(self._views.artifact(artifact))
            return self._views.replay_projection(
                projection,
                batch=locked_batch,
                artifact=artifact,
                retest_artifact=locked_retest_artifact,
            )

    @staticmethod
    def _replay_projection_retest_context(
        session: Session,
        *,
        batch: ReplayBatchRecord,
        item: ReplayItemRecord,
        finalization: ReplayFinalizationRecord,
        lock: bool,
    ) -> ReplayRetestContext | None:
        statement = select(ReplayCompilationRecord).where(
            ReplayCompilationRecord.compilation_id == finalization.compilation_id
        )
        if lock:
            statement = statement.with_for_update()
        record = session.scalar(statement)
        if record is None:
            raise StateConflict("Replay projection item has no compilation authority")
        compilation = trusted_replay_compilation(record)
        context = compilation.validation_packet.retest_context
        if not (
            record.batch_id == batch.batch_id
            and record.item_id == item.item_id
            and record.candidate_id == item.candidate_id
            and record.candidate_digest == item.candidate_digest
            and record.contract_digest == item.contract_digest
            and record.replay_run_id == item.replay_run_id
            and record.replay_run_id == finalization.replay_run_id
            and record.compilation_id == finalization.compilation_id
            and record.compilation_digest == item.compilation_digest
            and record.grant_digest == item.grant_digest
        ):
            raise StateConflict("Replay projection compilation graph is inconsistent")
        if batch.purpose == ReplayPurpose.REMEDIATION_RETEST.value:
            if context is None:
                raise StateConflict("Replay retest projection context set is inconsistent")
            return context
        if context is not None:
            raise StateConflict("Replay confirmation projection contains Retest context")
        return None

    def _replay_projection_snapshot(
        self,
        session: Session,
        batch: ReplayBatchRecord,
        *,
        lock: bool,
    ) -> _ReplayProjectionSnapshot:
        if batch.state != ReplayBatchState.GATING.value:
            raise StateConflict("Replay batch is not ready for projection publication")
        source_artifact = self._records.artifact(
            session,
            ArtifactLocator(
                artifact_id=batch.source_artifact_id,
                repository_version=batch.source_repository_version,
            ),
            lock=lock,
        )
        source_ref = self._views.artifact(source_artifact)
        retest_artifact = self._replay_retest_artifact(session, batch, lock=lock)
        batch_view = self._views.replay_batch(batch, retest_artifact=retest_artifact)
        if source_ref != batch_view.source:
            raise StateConflict("Replay projection source authority is inconsistent")

        item_statement = (
            select(ReplayItemRecord)
            .where(ReplayItemRecord.batch_id == batch.batch_id)
            .order_by(ReplayItemRecord.ordinal, ReplayItemRecord.item_id)
        )
        finalization_statement = select(ReplayFinalizationRecord).where(
            ReplayFinalizationRecord.batch_id == batch.batch_id
        )
        if lock:
            item_statement = item_statement.with_for_update()
            finalization_statement = finalization_statement.with_for_update()
        items = list(session.scalars(item_statement).all())
        finalizations = list(session.scalars(finalization_statement).all())
        if not items or any(item.state != ReplayItemState.VERIFIED.value for item in items):
            raise StateConflict("Replay projection requires every item to be verified")
        finalizations_by_item = {record.item_id: record for record in finalizations}
        if len(finalizations_by_item) != len(items) or len(finalizations) != len(items):
            raise StateConflict("Replay projection finalization set is incomplete")

        authority_items: list[ReplayProjectionItemAuthority] = []
        output_storage_keys: list[str] = []
        retest_contexts: dict[str, ReplayRetestContext] = {}
        for item in items:
            finalization = finalizations_by_item.get(item.item_id)
            if finalization is None:
                raise StateConflict("Replay projection item has no finalization")
            ticket = self._records.replay_ticket(session, finalization.ticket_id, lock=lock)
            output_artifact = self._records.artifact(
                session,
                ArtifactLocator(
                    artifact_id=finalization.artifact_id,
                    repository_version=finalization.repository_version,
                ),
                lock=lock,
            )
            output_ref = self._views.artifact(output_artifact)
            if not (
                finalization.batch_id == batch.batch_id
                and finalization.item_id == item.item_id
                and finalization.replay_run_id == item.replay_run_id
                and ticket.item_id == item.item_id
                and ticket.batch_id == batch.batch_id
                and ticket.replay_run_id == item.replay_run_id
                and ticket.compilation_id == finalization.compilation_id
                and ticket.compilation_digest == item.compilation_digest
                and ticket.state == ReplayTicketState.FINALIZED.value
                and ticket.result_digest == finalization.result_digest
                and output_ref.run_id == item.replay_run_id
            ):
                raise StateConflict("Replay projection finalization graph is inconsistent")
            retest_context = self._replay_projection_retest_context(
                session,
                batch=batch,
                item=item,
                finalization=finalization,
                lock=lock,
            )
            if retest_context is not None:
                if item.candidate_id in retest_contexts:
                    raise StateConflict("Replay retest projection context set is ambiguous")
                retest_contexts[item.candidate_id] = retest_context
            authority_items.append(
                ReplayProjectionItemAuthority(
                    ordinal=item.ordinal,
                    item_id=item.item_id,
                    ticket_id=ticket.ticket_id,
                    finalization_id=finalization.finalization_id,
                    replay_run_id=item.replay_run_id,
                    compilation_digest=item.compilation_digest,
                    output=output_ref,
                    artifact_set_digest=finalization.artifact_set_digest,
                    receipt_seal_root_digest=finalization.receipt_seal_root_digest,
                    gate_decision_digest=finalization.gate_decision_digest,
                    result_digest=finalization.result_digest,
                    finalized_at=_aware(finalization.finalized_at),
                )
            )
            output_storage_keys.append(output_artifact.storage_key)

        if retest_artifact is None:
            authority: ReplayProjectionInputAuthority | ReplayRetestProjectionInputAuthority = (
                ReplayProjectionInputAuthority(
                    batch_id=batch.batch_id,
                    source=source_ref,
                    batch_cas_version=batch.cas_version,
                    items=authority_items,
                )
            )
            retest_source_storage_key = None
        else:
            authority = ReplayRetestProjectionInputAuthority(
                batch_id=batch.batch_id,
                source=source_ref,
                retest_source=self._views.artifact(retest_artifact),
                batch_cas_version=batch.cas_version,
                items=authority_items,
            )
            retest_source_storage_key = retest_artifact.storage_key
        return _ReplayProjectionSnapshot(
            authority=authority,
            authority_digest=replay_context_digest(
                authority.model_dump(mode="json", by_alias=True)
            ),
            source_storage_key=source_artifact.storage_key,
            retest_source_storage_key=retest_source_storage_key,
            output_storage_keys=tuple(output_storage_keys),
            retest_contexts=retest_contexts,
            decided_at=_aware(batch.updated_at),
        )

    @staticmethod
    def _admit_replay_projection_artifact(
        session: Session,
        *,
        snapshot: ManagedArtifactSnapshot,
        source_artifact: ArtifactRecord,
        idempotency_key: str,
        admission_digest: str,
        now: datetime,
    ) -> ArtifactRecord:
        ref = snapshot.ref
        existing = session.scalar(
            select(ArtifactRecord).where(ArtifactRecord.idempotency_key == idempotency_key)
        )
        if existing is None:
            artifact = ArtifactRecord(
                artifact_id=ref.artifact_id,
                repository_version=ref.repository_version,
                producer_run_id=ref.producer_run_id,
                producer_job_id=source_artifact.producer_job_id,
                producer_attempt=source_artifact.producer_attempt,
                sealed_run_id=ref.run_id,
                media_type=ref.media_type,
                schema_kind=ref.schema_kind,
                byte_length=ref.byte_length,
                content_digest=ref.content_digest,
                root_digest=ref.integrity_root_digest,
                created_by=ref.created_by,
                storage_key=snapshot.storage_key,
                idempotency_key=idempotency_key,
                admission_digest=admission_digest,
                created_at=now,
            )
            session.add(artifact)
            session.flush()
            return artifact
        if not (
            ControlPlaneViewMapper.artifact(existing) == ref
            and existing.storage_key == snapshot.storage_key
            and existing.admission_digest == admission_digest
            and existing.producer_job_id == source_artifact.producer_job_id
            and existing.producer_attempt == source_artifact.producer_attempt
        ):
            raise StateConflict("Replay projection Artifact authority is already different")
        return existing

    def heartbeat(self, job_id: str, request: LeaseRequest, *, actor: str) -> JobView:
        return self._claims.heartbeat(job_id, request, actor=actor)

    def complete_job(self, job_id: str, request: CompleteJobRequest, *, actor: str) -> JobView:
        worker_id = request.worker_id
        lease_token = request.lease_token
        result = owned_bounded_json_object(
            request.result,
            policy=COMPLETE_JOB_RESULT_JSON_POLICY,
        )
        with self.repository.transaction() as session:
            job = self._records.job(session, job_id, lock=True)
            if job.kind == _INTERNAL_REPLAY_KIND:
                raise StateConflict("internal Replay Job requires typed server-side finalization")
            run = self._records.run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                raise RunCancelled("run has been cancelled")
            self._claims.require_lease_identity(
                job,
                worker_id,
                lease_token,
                actor=actor,
            )
            if job.state == JobState.SUCCEEDED.value:
                if not isinstance(job.result, dict) or canonical_control_plane_json(
                    job.result
                ) != canonical_control_plane_json(result):
                    raise StateConflict(
                        "completion retry result differs from the persisted terminal result"
                    )
                return self._views.job(job)
            self._lifecycle.require_run_state(run, RunState.RUNNING)
            now = utc_now()
            self._claims.require_active_lease(
                job,
                worker_id,
                lease_token,
                now,
                actor=actor,
            )
            job.state = JobState.SUCCEEDED.value
            job.result = result
            job.error = None
            job.lease_expires_at = None
            job.lease_deadline_at = None
            job.heartbeat_event_at = None
            job.updated_at = now
            run.state = RunState.COMPLETED.value
            run.updated_at = now
            self._event(session, run, "job.completed", actor, {"jobId": job.job_id})
            self._event(session, run, "run.completed", actor, {"jobId": job.job_id})
            return self._views.job(job)

    def fail_job(self, job_id: str, request: FailJobRequest, *, actor: str) -> JobView:
        with self.repository.transaction() as session:
            job = self._records.job(session, job_id, lock=True)
            if job.kind == _INTERNAL_REPLAY_KIND:
                raise StateConflict("internal Replay Job cannot use generic failure/requeue")
            run = self._records.run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                raise RunCancelled("run has been cancelled")
            self._lifecycle.require_run_state(run, RunState.RUNNING)
            now = utc_now()
            self._claims.require_active_lease(
                job,
                request.worker_id,
                request.lease_token,
                now,
                actor=actor,
            )
            job.error = request.error
            job.lease_owner = None
            job.lease_token_hash = None
            job.lease_expires_at = None
            job.lease_deadline_at = None
            job.heartbeat_at = None
            job.heartbeat_event_at = None
            job.updated_at = now
            if request.retryable and job.attempts < job.max_attempts:
                job.state = JobState.QUEUED.value
                job.available_at = now
                run.state = RunState.QUEUED.value
                event_type = "job.requeued"
            else:
                job.state = (
                    JobState.DEAD_LETTER.value
                    if job.attempts >= job.max_attempts
                    else JobState.FAILED.value
                )
                run.state = RunState.FAILED.value
                event_type = "job.failed"
            run.updated_at = now
            self._event(
                session,
                run,
                event_type,
                actor,
                {"jobId": job.job_id, "error": request.error, "attempt": job.attempts},
            )
            return self._views.job(job)

    def create_checkpoint(
        self,
        job_id: str,
        request: CreateCheckpointRequest,
        *,
        actor: str,
    ) -> CheckpointCreationView:
        worker_id = request.worker_id
        lease_token = request.lease_token
        state = owned_bounded_json_object(
            request.state,
            policy=CHECKPOINT_STATE_JSON_POLICY,
        )
        pending_intent = ApprovalIntent.model_validate(
            request.pending_intent.model_dump(mode="python")
        )
        with self.repository.transaction() as session:
            job = self._records.job(session, job_id, lock=True)
            if job.kind == _INTERNAL_REPLAY_KIND:
                raise StateConflict("internal Replay Job cannot create approval checkpoints")
            run = self._records.run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                raise RunCancelled("run has been cancelled")
            self._lifecycle.require_run_state(run, RunState.RUNNING)
            now = utc_now()
            if pending_intent.expires_at <= now:
                raise StateConflict("approval intent is already expired")
            self._claims.require_active_lease(
                job,
                worker_id,
                lease_token,
                now,
                actor=actor,
            )
            current_sequence = session.scalar(
                select(func.max(CheckpointRecord.sequence)).where(
                    CheckpointRecord.run_id == run.run_id
                )
            )
            sequence = int(current_sequence or 0) + 1
            checkpoint_id = f"checkpoint_{uuid4().hex}"
            payload = owned_bounded_json_object(
                {
                    "state": state,
                    "pendingIntent": pending_intent.model_dump(mode="json"),
                    "job": {"kind": job.kind, "maxAttempts": job.max_attempts},
                }
            )
            signed = self.signer.sign(
                checkpoint_id=checkpoint_id,
                run_id=run.run_id,
                sequence=sequence,
                schema_version=1,
                payload=payload,
            )
            checkpoint = CheckpointRecord(
                checkpoint_id=checkpoint_id,
                run_id=run.run_id,
                sequence=sequence,
                schema_version=1,
                payload=payload,
                payload_sha256=signed.payload_sha256,
                signature=signed.signature,
                key_id=signed.key_id,
                created_at=now,
                claimed_at=None,
                claimed_by=None,
                continuation_job_id=None,
            )
            approval = ApprovalRecord(
                approval_id=f"approval_{uuid4().hex}",
                run_id=run.run_id,
                checkpoint_id=checkpoint_id,
                call_fingerprint=pending_intent.call_fingerprint,
                tool_id=pending_intent.tool_id,
                target=pending_intent.target,
                risk_tier=int(pending_intent.risk_tier),
                state=ApprovalState.PENDING.value,
                requested_by=actor,
                requested_at=now,
                expires_at=pending_intent.expires_at,
                decided_by=None,
                decided_at=None,
                decision_reason=None,
                consumed_by=None,
                consumed_at=None,
            )
            session.add(checkpoint)
            session.flush()
            session.add(approval)
            job.state = JobState.SUCCEEDED.value
            job.result = {"checkpointId": checkpoint_id, "awaitingApproval": True}
            job.lease_expires_at = None
            job.lease_deadline_at = None
            job.heartbeat_event_at = None
            job.updated_at = now
            run.state = RunState.AWAITING_APPROVAL.value
            run.current_checkpoint_id = checkpoint_id
            run.updated_at = now
            self._event(
                session,
                run,
                "checkpoint.created",
                actor,
                {
                    "checkpointId": checkpoint_id,
                    "sequence": sequence,
                    "payloadSha256": signed.payload_sha256,
                },
            )
            self._event(
                session,
                run,
                "approval.requested",
                actor,
                {
                    "approvalId": approval.approval_id,
                    "checkpointId": checkpoint_id,
                    "riskTier": int(pending_intent.risk_tier),
                    "callFingerprint": pending_intent.call_fingerprint,
                },
            )
            return CheckpointCreationView(
                checkpoint=self._views.checkpoint(checkpoint),
                approval=self._views.approval(approval),
            )

    def decide_approval(
        self,
        approval_id: str,
        request: DecideApprovalRequest,
        *,
        actor: str,
    ) -> ApprovalView:
        expired = False
        view: ApprovalView | None = None
        with self.repository.transaction() as session:
            approval_reference = self._records.approval(session, approval_id)
            checkpoint = self._records.checkpoint(
                session, approval_reference.checkpoint_id, lock=True
            )
            approval = self._records.approval(session, approval_id, lock=True)
            if (
                approval.checkpoint_id != checkpoint.checkpoint_id
                or approval.run_id != checkpoint.run_id
            ):
                raise StateConflict("approval does not belong to its signed checkpoint")
            run = self._records.run(session, approval.run_id, lock=True)
            if approval.state != ApprovalState.PENDING.value:
                raise StateConflict("approval has already been decided")
            self._lifecycle.require_run_state(run, RunState.AWAITING_APPROVAL)
            self._lifecycle.require_current_checkpoint(run, approval.checkpoint_id)
            self._lifecycle.verify_checkpoint(checkpoint)
            intent = self._views.checkpoint_intent(checkpoint)
            if not self._lifecycle.approval_matches_intent(approval, intent):
                raise StateConflict("approval fields do not match signed checkpoint intent")
            if approval.requested_by == actor:
                raise StateConflict("approval requester cannot decide their own request")
            now = utc_now()
            if _aware(approval.expires_at) <= now:
                self._lifecycle.expire_approval(
                    session,
                    approval,
                    run,
                    actor=actor,
                    now=now,
                )
                expired = True
            else:
                approval.state = (
                    ApprovalState.APPROVED.value if request.approve else ApprovalState.DENIED.value
                )
                approval.decided_by = actor
                approval.decided_at = now
                approval.decision_reason = request.reason
                run.updated_at = now
                self._event(
                    session,
                    run,
                    "approval.approved" if request.approve else "approval.denied",
                    actor,
                    {
                        "approvalId": approval.approval_id,
                        "checkpointId": approval.checkpoint_id,
                        "reason": request.reason,
                    },
                )
                if not request.approve:
                    self._lifecycle.cancel_run_record(
                        session,
                        run,
                        actor=actor,
                        now=now,
                        reason=request.reason,
                        cause="approval-denied",
                        extra={"approvalId": approval.approval_id},
                    )
                view = self._views.approval(approval)
        if expired:
            raise StateConflict("approval request has expired")
        if view is None:
            raise RuntimeError("approval decision did not produce a view")
        return view

    def resume_checkpoint(
        self,
        checkpoint_id: str,
        approval_id: str,
        *,
        actor: str,
    ) -> ResumeView:
        expired = False
        result: ResumeView | None = None
        with self.repository.transaction() as session:
            checkpoint = self._records.checkpoint(session, checkpoint_id, lock=True)
            approval = self._records.approval(session, approval_id, lock=True)
            if (
                approval.checkpoint_id != checkpoint.checkpoint_id
                or approval.run_id != checkpoint.run_id
            ):
                raise StateConflict("approval does not authorize this checkpoint")
            run = self._records.run(session, checkpoint.run_id, lock=True)
            self._lifecycle.verify_checkpoint(checkpoint)
            # A claimed checkpoint is an immutable, single-use authority boundary.
            # Report that terminal fact before inspecting the Run's post-resume state;
            # otherwise a legitimate duplicate resume is misclassified as a generic
            # lifecycle conflict after the first claimant moves the Run back to queued.
            if checkpoint.claimed_at is not None:
                raise StateConflict("checkpoint has already been claimed")
            self._lifecycle.require_run_state(run, RunState.AWAITING_APPROVAL)
            self._lifecycle.require_current_checkpoint(run, checkpoint.checkpoint_id)
            if approval.state != ApprovalState.APPROVED.value:
                raise StateConflict("checkpoint requires an active approved decision")
            now = utc_now()
            if _aware(approval.expires_at) <= now:
                self._lifecycle.expire_approval(
                    session,
                    approval,
                    run,
                    actor=actor,
                    now=now,
                )
                expired = True
            else:
                intent = self._views.checkpoint_intent(checkpoint)
                if not self._lifecycle.approval_matches_intent(approval, intent):
                    raise StateConflict("approval fields do not match signed checkpoint intent")
                raw_job_context = checkpoint.payload.get("job", {})
                job_context = raw_job_context if isinstance(raw_job_context, dict) else {}
                continuation_kind = str(job_context.get("kind", "campaign"))
                continuation_max_attempts = int(job_context.get("maxAttempts", 3))
                continuation_job_id = f"job_{uuid4().hex}"
                continuation_payload = {
                    "resumeFromCheckpointId": checkpoint.checkpoint_id,
                    "state": checkpoint.payload["state"],
                    "approvalId": approval.approval_id,
                    "approval": {
                        "callFingerprint": approval.call_fingerprint,
                        "toolId": approval.tool_id,
                        "target": approval.target,
                        "riskTier": approval.risk_tier,
                        "approvedBy": approval.decided_by,
                        "approvedAt": (
                            approval.decided_at.isoformat() if approval.decided_at else None
                        ),
                        "expiresAt": approval.expires_at.isoformat(),
                    },
                }
                continuation_idempotency_key = f"resume:{checkpoint.checkpoint_id}"
                job = JobRecord(
                    job_id=continuation_job_id,
                    run_id=run.run_id,
                    kind=continuation_kind,
                    state=JobState.QUEUED.value,
                    payload=continuation_payload,
                    priority=10,
                    attempts=0,
                    max_attempts=continuation_max_attempts,
                    idempotency_key=continuation_idempotency_key,
                    available_at=now,
                    lease_owner=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    lease_deadline_at=None,
                    heartbeat_at=None,
                    heartbeat_event_at=None,
                    result=None,
                    error=None,
                    created_at=now,
                    updated_at=now,
                    submission_authority_digest=job_submission_authority_digest(
                        job_id=continuation_job_id,
                        run_id=run.run_id,
                        job_kind=continuation_kind,
                        payload=continuation_payload,
                        max_attempts=continuation_max_attempts,
                        idempotency_key=continuation_idempotency_key,
                    ),
                )
                session.add(job)
                session.flush()
                checkpoint.claimed_at = now
                checkpoint.claimed_by = actor
                checkpoint.continuation_job_id = job.job_id
                approval.state = ApprovalState.CONSUMED.value
                approval.consumed_by = actor
                approval.consumed_at = now
                run.state = RunState.QUEUED.value
                run.current_checkpoint_id = None
                run.updated_at = now
                self._event(
                    session,
                    run,
                    "checkpoint.claimed",
                    actor,
                    {
                        "checkpointId": checkpoint.checkpoint_id,
                        "approvalId": approval.approval_id,
                        "continuationJobId": job.job_id,
                    },
                )
                result = ResumeView(
                    run=self._views.run(run),
                    job=self._views.job(job),
                    checkpoint=self._views.checkpoint(checkpoint),
                    approval=self._views.approval(approval),
                )
        if expired:
            raise StateConflict("approval has expired")
        if result is None:
            raise RuntimeError("checkpoint resume did not produce a result")
        return result

    def requeue_expired(self, *, actor: str) -> int:
        return self._lifecycle.requeue_expired(actor=actor)

    def _expire_leases(self, session: Session, *, now: datetime, actor: str) -> int:
        return self._lifecycle.expire_leases(session, now=now, actor=actor)

    @staticmethod
    def _prelock_replay_capacity(
        session: Session,
        tickets: list[ReplayTicketRecord],
    ) -> None:
        ControlPlaneLifecycleService._prelock_replay_capacity(session, tickets)

    def _verify_checkpoint(self, checkpoint: CheckpointRecord) -> None:
        self._lifecycle.verify_checkpoint(checkpoint)

    def _replay_attempt(
        self,
        session: Session,
        job_id: str,
        *,
        lock: bool,
    ) -> _LockedReplayAttempt:
        """Load one authority graph without changing its established lock order."""

        job = self._records.job(session, job_id, lock=lock)
        if job.kind != _INTERNAL_REPLAY_KIND:
            raise StateConflict("Job is not an internal Replay Job")
        ticket = self._records.replay_ticket_for_job(session, job.job_id, lock=lock)
        item = self._records.replay_item(session, ticket.item_id, lock=lock)
        batch = self._records.replay_batch(session, ticket.batch_id, lock=lock)
        run = self._records.run(session, job.run_id, lock=lock)
        authority = self._claims.verify_replay_binding(session, job, ticket, item, batch)
        return _LockedReplayAttempt(
            job=job,
            ticket=ticket,
            item=item,
            batch=batch,
            run=run,
            authority=authority,
        )

    @staticmethod
    def _verify_replay_output_and_gate(
        *,
        authority: ReplayBindingAuthority,
        batch: ReplayBatchRecord,
        item: ReplayItemRecord,
        ticket: ReplayTicketRecord,
        output_snapshot: ManagedArtifactSnapshot,
        verified: VerifiedReplayResult,
        source_snapshot: ManagedArtifactSnapshot,
        now: datetime,
    ) -> ValidationDecision:
        if now.tzinfo is None or now.utcoffset() is None:
            raise StateConflict("Replay finalization clock is not timezone-aware")
        now = now.astimezone(UTC)
        receipt = verified.receipt
        artifact_set = verified.artifact_set
        compilation = authority.compilation
        context = authority.execution_context
        output_ref = output_snapshot.ref
        permit_request_ids = [permit.replay_request_id for permit in authority.permits]
        expected_ticket_context = {
            "candidate_source_root_digest": batch.source_root_digest,
            "campaign_digest": context.campaign_digest,
            "tool_spec_digest": context.tool_spec_digest,
            "scenario_digest": context.scenario_digest,
        }
        observed_ticket_context = (
            None
            if receipt.ticket_context is None
            else {
                "candidate_source_root_digest": (
                    receipt.ticket_context.candidate_source_root_digest
                ),
                "campaign_digest": receipt.ticket_context.campaign_digest,
                "tool_spec_digest": receipt.ticket_context.tool_spec_digest,
                "scenario_digest": receipt.ticket_context.scenario_digest,
            }
        )
        if not (
            receipt.api_version == "pajin.dev/replay-verification-receipt/v2"
            and observed_ticket_context == expected_ticket_context
            and receipt.ticket_id == ticket.ticket_id
            and receipt.compilation_digest == ticket.compilation_digest
            and receipt.candidate_source_root_digest == batch.source_root_digest
            and receipt.replay_run_id == ticket.replay_run_id
            and receipt.artifact_seal_root_digest == verified.receipt.artifact_seal_root_digest
            and verified.receipt_seal_root_digest == verified.verification.root_digest
            and receipt.verified_at <= now
            and output_ref.producer_run_id == ticket.replay_run_id
            and output_ref.run_id == ticket.replay_run_id
            and output_ref.media_type == _SOURCE_ARTIFACT_MEDIA_TYPE
            and output_ref.schema_kind == _REPLAY_OUTPUT_ARTIFACT_SCHEMA_KIND
            and output_ref.integrity_root_digest == verified.verification.root_digest
            and source_snapshot.ref == ControlPlaneViewMapper.replay_source(batch)
            and artifact_set.validation_packet == compilation.validation_packet
            and artifact_set.contract == compilation.contract
            and artifact_set.intent == compilation.intent
            and artifact_set.spec == compilation.spec
            and artifact_set.outcome.binding == compilation.spec.binding
            and artifact_set.outcome.replay_request_ids == permit_request_ids
            and [attempt.replay_request_id for attempt in artifact_set.outcome.attempts]
            == permit_request_ids
            and [attempt.attempt_number for attempt in artifact_set.outcome.attempts]
            == list(range(1, compilation.spec.repetitions + 1))
        ):
            raise StateConflict("sealed Replay output differs from issued durable authority")

        try:
            source_validation = load_source_validation_artifacts(
                source_snapshot.path,
                expected_run_id=source_snapshot.ref.run_id,
                expected_root_digest=source_snapshot.ref.integrity_root_digest,
            )
        except ValueError as exc:
            raise StateConflict("managed Replay source validation cannot be loaded") from exc
        candidates = [
            candidate
            for candidate in source_validation.candidates
            if candidate.candidate_id == item.candidate_id
        ]
        decisions = [
            decision
            for decision in source_validation.decisions
            if decision.candidate_id == item.candidate_id
        ]
        if (
            len(candidates) != 1
            or len(decisions) != 1
            or candidates[0] != compilation.validation_packet.candidate
        ):
            raise StateConflict("sealed Replay output Candidate differs from its source")
        outcome = artifact_set.outcome
        oracle = outcome.oracle_result
        lineage = ReplayConfirmationLineage(
            replay_run_id=outcome.binding.replay_run_id,
            replay_outcome_id=outcome.outcome_id,
            replay_request_ids=outcome.replay_request_ids,
            replay_evidence=outcome.evidence,
            oracle_result_id=oracle.oracle_result_id if oracle is not None else None,
            ticket_id=receipt.ticket_id,
            candidate_source_root_digest=receipt.candidate_source_root_digest,
            artifact_set_digest=receipt.artifact_set_digest,
            artifact_seal_root_digest=receipt.artifact_seal_root_digest,
            receipt_seal_root_digest=verified.receipt_seal_root_digest,
            verified_at=receipt.verified_at,
        )
        try:
            return decide_replay_confirmation(
                candidate=candidates[0],
                source_decision=decisions[0],
                artifact_set=artifact_set,
                lineage=lineage,
                decided_at=now,
            )
        except ValueError as exc:
            raise StateConflict(
                "verified Replay output failed the common confirmation Gate"
            ) from exc

    def _require_artifact_repository(self) -> ManagedArtifactRepository:
        if self._artifact_repository is None:
            raise StateConflict("managed Artifact repository is not configured")
        return self._artifact_repository

    @contextmanager
    def _consume_staged_run_after_commit(
        self,
        repository: ManagedArtifactRepository,
        *,
        staging_id: str,
    ) -> Iterator[Callable[[ArtifactRef], None]]:
        """Schedule cleanup that runs only after an enclosing transaction exits cleanly."""

        committed_ref: ArtifactRef | None = None

        def schedule(ref: ArtifactRef) -> None:
            nonlocal committed_ref
            if committed_ref is not None and committed_ref != ref:
                raise StateConflict("staging cleanup authority changed during commit")
            committed_ref = ref

        yield schedule
        if committed_ref is not None:
            repository.consume_staged_run(
                staging_id=staging_id,
                expected_ref=committed_ref,
            )

    @contextmanager
    def _artifact_commit_transaction(
        self,
        repository: ManagedArtifactRepository,
        *,
        staging_id: str,
    ) -> Iterator[tuple[Session, Callable[[ArtifactRef], None]]]:
        """Commit database authority before consuming its exact staging capability."""

        with (
            self._consume_staged_run_after_commit(
                repository,
                staging_id=staging_id,
            ) as consume_after_commit,
            self.repository.transaction() as session,
        ):
            yield session, consume_after_commit

    @contextmanager
    def _projection_artifact_commit_transaction(
        self,
        repository: ManagedArtifactRepository,
        *,
        staging_id: str,
        expected_ref: ArtifactRef,
    ) -> Iterator[tuple[Session, Callable[[ArtifactRef], None]]]:
        """Discard server-owned projection staging after a rejected CAS commit."""

        try:
            with self._artifact_commit_transaction(
                repository,
                staging_id=staging_id,
            ) as transaction:
                yield transaction
        except BaseException:
            # Preserve the authoritative database/CAS failure. A failed cleanup
            # leaves only an opaque server staging directory, never publication.
            with suppress(ArtifactRepositoryError):
                repository.consume_staged_run(
                    staging_id=staging_id,
                    expected_ref=expected_ref,
                )
            raise

    def _reconfirm_source_artifact_admission(
        self,
        repository: ManagedArtifactRepository,
        *,
        request: AdmitSourceArtifactRequest,
        actor: str,
        admission_digest: str,
        expected_ref: ArtifactRef,
        expected_storage_key: str,
    ) -> ArtifactRef:
        snapshot = self._resolve_managed_artifact(
            repository,
            expected_ref,
            expected_storage_key=expected_storage_key,
        )
        with self._artifact_commit_transaction(
            repository,
            staging_id=request.staging_id,
        ) as (session, consume_after_commit):
            current = self._records.artifact_by_idempotency_key(
                session,
                request.idempotency_key,
                lock=True,
            )
            if current is None:
                raise StateConflict("admitted Artifact metadata disappeared")
            current_ref = self._existing_artifact_admission(
                current,
                request=request,
                actor=actor,
                admission_digest=admission_digest,
            )
            self._require_artifact_snapshot(
                current,
                snapshot.ref,
                storage_key=snapshot.storage_key,
            )
            consume_after_commit(current_ref)
            return current_ref

    @staticmethod
    def _artifact_admission_digest(
        request: AdmitSourceArtifactRequest,
        *,
        actor: str,
    ) -> str:
        material = json.dumps(
            {
                "actor": actor,
                "domain": "pajin.control-plane.artifact-admission/v1",
                "producerJobId": request.producer_job_id,
                "producerRunId": request.producer_run_id,
                "mediaType": _SOURCE_ARTIFACT_MEDIA_TYPE,
                "schemaKind": _SOURCE_ARTIFACT_SCHEMA_KIND,
                "stagingId": request.staging_id,
            },
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return sha256(material).hexdigest()

    @staticmethod
    def _require_artifact_producer(
        run: RunRecord,
        job: JobRecord,
        *,
        request: AdmitSourceArtifactRequest,
    ) -> str:
        if run.run_id != request.producer_run_id:
            raise StateConflict("Artifact producer Run binding is inconsistent")
        if run.state != RunState.COMPLETED.value:
            raise StateConflict("source Artifact producer Run must be completed")
        if job.job_id != request.producer_job_id or job.run_id != run.run_id:
            raise StateConflict("source Artifact producer Job does not belong to its Run")
        if job.kind != JobKind.CAMPAIGN.value:
            raise StateConflict("source Artifact requires a public Campaign Job")
        if job.state != JobState.SUCCEEDED.value:
            raise StateConflict("source Artifact producer Job must have succeeded")
        if not 1 <= job.attempts <= 2_147_483_647:
            raise StateConflict("source Artifact producer Job attempt is outside authority bounds")
        engine_run_id = job.result.get("engineRunId") if isinstance(job.result, dict) else None
        if not isinstance(engine_run_id, str) or not engine_run_id:
            raise StateConflict("source Artifact producer Job has no sealed engine Run ID")
        return engine_run_id

    @staticmethod
    def _require_artifact_snapshot(
        record: ArtifactRecord,
        ref: ArtifactRef,
        *,
        storage_key: str,
    ) -> None:
        if ControlPlaneViewMapper.artifact(record) != ref or record.storage_key != storage_key:
            raise StateConflict("managed Artifact metadata changed during verification")

    @staticmethod
    def _resolve_managed_artifact(
        repository: ManagedArtifactRepository,
        ref: ArtifactRef,
        *,
        expected_storage_key: str,
    ) -> ManagedArtifactSnapshot:
        try:
            snapshot = repository.resolve(ref)
        except ArtifactNotFound as exc:
            raise ResourceNotFound("managed source Artifact not found") from exc
        except ArtifactRepositoryError as exc:
            raise StateConflict("managed source Artifact failed reverification") from exc
        if snapshot.ref != ref or snapshot.storage_key != expected_storage_key:
            raise StateConflict("managed source Artifact resolution was substituted")
        return snapshot

    @staticmethod
    def _existing_artifact_admission(
        record: ArtifactRecord,
        *,
        request: AdmitSourceArtifactRequest,
        actor: str,
        admission_digest: str,
    ) -> ArtifactRef:
        if (
            record.admission_digest != admission_digest
            or record.idempotency_key != request.idempotency_key
            or record.producer_run_id != request.producer_run_id
            or record.producer_job_id != request.producer_job_id
            or record.created_by != actor
        ):
            raise StateConflict(
                "Artifact admission idempotency key was already used for different input"
            )
        return ControlPlaneViewMapper.artifact(record)

    @staticmethod
    def _canonical_submission_input(value: dict[str, Any]) -> bytes:
        try:
            return json.dumps(
                value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, UnicodeEncodeError, ValueError) as exc:
            raise StateConflict("submission input must be canonical JSON") from exc

    @classmethod
    def _submission_authority(
        cls,
        request: SubmitRunRequest,
        *,
        actor: str,
    ) -> _SubmissionAuthority:
        input_value = owned_bounded_json_object(
            request.input,
            policy=SUBMIT_RUN_INPUT_JSON_POLICY,
        )
        campaign_name = request.campaign_name
        idempotency_key = request.idempotency_key
        job_kind = request.job_kind.value
        max_attempts = request.max_attempts
        return _SubmissionAuthority(
            actor=actor,
            campaign_name=campaign_name,
            input_value=input_value,
            canonical_input=cls._canonical_submission_input(input_value),
            idempotency_key=idempotency_key,
            job_kind=job_kind,
            max_attempts=max_attempts,
            digest=submission_authority_digest(
                actor=actor,
                campaign_name=campaign_name,
                input_value=input_value,
                idempotency_key=idempotency_key,
                job_kind=job_kind,
                max_attempts=max_attempts,
            ),
        )

    def _existing_submission(
        self,
        session: Session,
        run: RunRecord,
        *,
        authority: _SubmissionAuthority,
    ) -> SubmissionView:
        job = session.scalar(
            select(JobRecord).where(JobRecord.idempotency_key == f"submission:{run.submission_key}")
        )
        if job is None:
            raise StateConflict("idempotent run exists without its initial job")
        submitted = session.scalar(
            select(EventRecord).where(
                EventRecord.run_id == run.run_id,
                EventRecord.sequence == 1,
                EventRecord.event_type == "run.submitted",
            )
        )
        if (
            submitted is None
            or not isinstance(submitted.payload, dict)
            or not isinstance(run.submission_authority_digest, str)
            or not hmac.compare_digest(run.submission_authority_digest, authority.digest)
            or submitted.actor != authority.actor
            or submitted.payload.get("campaignName") != authority.campaign_name
            or submitted.payload.get("jobId") != job.job_id
            or submitted.payload.get("jobKind") != authority.job_kind
            or run.submission_key != authority.idempotency_key
            or run.campaign_name != authority.campaign_name
            or self._canonical_submission_input(run.input) != authority.canonical_input
            or job.run_id != run.run_id
            or job.kind != authority.job_kind
            or job.max_attempts != authority.max_attempts
            or self._canonical_submission_input(job.payload)
            != self._canonical_submission_input({"input": authority.input_value})
        ):
            raise StateConflict(
                "submission idempotency key was already used for different authority input"
            )
        return SubmissionView(run=self._views.run(run), job=self._views.job(job), created=False)

    def _event(
        self,
        session: Session,
        run: RunRecord,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> EventRecord:
        bounded_payload = validate_bounded_json_object(payload)
        event = EventRecord(
            event_id=f"event_{uuid4().hex}",
            run_id=run.run_id,
            sequence=self.repository.next_event_sequence(session, run.run_id),
            event_type=event_type,
            actor=actor,
            payload=bounded_payload,
            occurred_at=utc_now(),
        )
        session.add(event)
        session.flush()
        return event

    def _replay_event(
        self,
        session: Session,
        batch: ReplayBatchRecord,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        *,
        item: ReplayItemRecord | None = None,
        ticket: ReplayTicketRecord | None = None,
        job: JobRecord | None = None,
        run_id: str | None = None,
    ) -> ReplayEventRecord:
        if ticket is not None and (item is None or job is None or run_id is None):
            raise StateConflict("Replay ticket events require exact item, Job, and Run context")
        if item is not None and item.batch_id != batch.batch_id:
            raise StateConflict("Replay event item belongs to another batch")
        if ticket is not None:
            if item is None or job is None or run_id is None:
                raise StateConflict("Replay ticket events require exact item, Job, and Run context")
            if (
                ticket.batch_id != batch.batch_id
                or ticket.item_id != item.item_id
                or ticket.job_id != job.job_id
                or ticket.replay_run_id != run_id
            ):
                raise StateConflict("Replay event authority binding is inconsistent")
        bounded_payload = validate_bounded_json_object(payload)
        event = ReplayEventRecord(
            event_id=f"replay-event_{uuid4().hex}",
            batch_id=batch.batch_id,
            item_id=item.item_id if item else None,
            ticket_id=ticket.ticket_id if ticket else None,
            job_id=job.job_id if job else None,
            run_id=run_id,
            sequence=self.repository.next_replay_event_sequence(session, batch.batch_id),
            event_type=event_type,
            actor=actor,
            payload=bounded_payload,
            occurred_at=utc_now(),
        )
        session.add(event)
        session.flush()
        return event

    def _existing_replay_finalization(
        self,
        session: Session,
        record: ReplayFinalizationRecord,
        *,
        job_id: str,
        request: ReplayFinalizeRequest,
        actor: str,
        artifact_repository: ManagedArtifactRepository,
    ) -> ReplayFinalizationView:
        job = self._records.job(session, job_id)
        ticket = self._records.replay_ticket_for_job(session, job.job_id)
        item = self._records.replay_item(session, ticket.item_id)
        batch = self._records.replay_batch(session, ticket.batch_id)
        artifact = self._records.artifact(
            session,
            ArtifactLocator(
                artifact_id=record.artifact_id,
                repository_version=record.repository_version,
            ),
        )
        supplied_digest = token_digest(request.lease_token)
        if not (
            request.ticket_id == record.ticket_id == ticket.ticket_id
            and request.fencing_value == record.fencing_value == ticket.fencing_value
            and request.output_staging_id == record.output_staging_id
            and request.executor_profile == ticket.executor_profile
            and actor == record.finalized_by == ticket.claim_principal
            and job.lease_token_hash is not None
            and ticket.lease_token_hash is not None
            and hmac.compare_digest(job.lease_token_hash, supplied_digest)
            and hmac.compare_digest(ticket.lease_token_hash, supplied_digest)
        ):
            raise StateConflict("Replay finalization idempotency authority does not match")
        artifact_ref = self._views.artifact(artifact)
        self._resolve_managed_artifact(
            artifact_repository,
            artifact_ref,
            expected_storage_key=artifact.storage_key,
        )
        retest_artifact = self._replay_retest_artifact(session, batch)
        return self._views.replay_finalization(
            record,
            job=job,
            batch=batch,
            item=item,
            ticket=ticket,
            artifact=artifact,
            retest_artifact=retest_artifact,
        )
