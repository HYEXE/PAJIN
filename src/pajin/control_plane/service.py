"""Transactional Control Plane application service."""

from __future__ import annotations

import hmac
import json
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any
from uuid import uuid4

from pydantic import ValidationError
from sqlalchemy import Select, and_, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, load_only

from pajin.control_plane.artifacts import (
    ArtifactNotFound,
    ArtifactRepositoryError,
    ManagedArtifactRepository,
    ManagedArtifactSnapshot,
)
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
    ReplayItemRecord,
    ReplayTicketRecord,
    RunRecord,
    utc_now,
)
from pajin.control_plane.kisa_derivation import (
    KISA_CONFIRMATION_POLICY_VERSION,
    DerivedKISAReplayBatch,
    derive_kisa_confirmation_batch,
)
from pajin.control_plane.models import (
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
    CheckpointView,
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
    ReplayBatchState,
    ReplayBatchView,
    ReplayClaimRequest,
    ReplayClaimView,
    ReplayItemState,
    ReplayItemView,
    ReplayJobPayload,
    ReplayLeaseRequest,
    ReplayTicketState,
    ReplayTicketView,
    ResumeView,
    RunListView,
    RunState,
    RunSummaryView,
    RunView,
    SubmissionView,
    SubmitRunRequest,
)
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.domain.replay import ReplayPurpose


class ControlPlaneError(RuntimeError):
    """Base class for expected Control Plane errors."""


class ResourceNotFound(ControlPlaneError):
    pass


class StateConflict(ControlPlaneError):
    pass


class RunCancelled(StateConflict):
    """Signal that an active Worker must stop because its Run was cancelled."""


class LeaseRejected(ControlPlaneError):
    pass


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
_REPLAY_TICKET_TTL = timedelta(minutes=5)
_SOURCE_ARTIFACT_MEDIA_TYPE = "application/vnd.pajin.run+directory"
_SOURCE_ARTIFACT_SCHEMA_KIND = "pajin.run.sealed.v1"
_ACTIVE_REPLAY_TICKET_STATES = frozenset(
    {ReplayTicketState.ISSUED.value, ReplayTicketState.CLAIMED.value}
)
_TERMINAL_REPLAY_ITEM_STATES = frozenset(
    {
        ReplayItemState.GATED.value,
        ReplayItemState.FAILED.value,
        ReplayItemState.CANCELLED.value,
    }
)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


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

    def submit_run(self, request: SubmitRunRequest, *, actor: str) -> SubmissionView:
        try:
            with self.repository.transaction() as session:
                existing = session.scalar(
                    select(RunRecord).where(RunRecord.submission_key == request.idempotency_key)
                )
                if existing is not None:
                    return self._existing_submission(session, existing)
                now = utc_now()
                run = RunRecord(
                    run_id=f"run_{uuid4().hex}",
                    campaign_name=request.campaign_name,
                    state=RunState.QUEUED.value,
                    input=request.input,
                    submission_key=request.idempotency_key,
                    current_checkpoint_id=None,
                    created_at=now,
                    updated_at=now,
                )
                job = JobRecord(
                    job_id=f"job_{uuid4().hex}",
                    run_id=run.run_id,
                    kind=request.job_kind.value,
                    state=JobState.QUEUED.value,
                    payload={"input": request.input},
                    priority=0,
                    attempts=0,
                    max_attempts=request.max_attempts,
                    idempotency_key=f"submission:{request.idempotency_key}",
                    available_at=now,
                    lease_owner=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    heartbeat_at=None,
                    result=None,
                    error=None,
                    created_at=now,
                    updated_at=now,
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
                        "campaignName": request.campaign_name,
                        "jobId": job.job_id,
                        "jobKind": request.job_kind.value,
                    },
                )
                return SubmissionView(
                    run=self._run_view(run), job=self._job_view(job), created=True
                )
        except IntegrityError:
            with self.repository.transaction() as session:
                existing = session.scalar(
                    select(RunRecord).where(RunRecord.submission_key == request.idempotency_key)
                )
                if existing is None:
                    raise
                return self._existing_submission(session, existing)

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
            existing = self._artifact_by_idempotency_key(
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
                producer_job = self._job(session, request.producer_job_id)
                producer_run = self._run(session, request.producer_run_id)
                expected_sealed_run_id = self._require_artifact_producer(
                    producer_run,
                    producer_job,
                    request=request,
                )
                producer_attempt = producer_job.attempts

        if existing_ref is not None:
            assert existing_storage_key is not None
            snapshot = self._resolve_managed_artifact(
                artifact_repository,
                existing_ref,
                expected_storage_key=existing_storage_key,
            )
            with self.repository.transaction() as session:
                current = self._artifact_by_idempotency_key(
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
                return current_ref

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
        except ArtifactNotFound as exc:
            raise ResourceNotFound("staged source Artifact not found") from exc
        except ArtifactRepositoryError as exc:
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
            with self.repository.transaction() as session:
                existing = self._artifact_by_idempotency_key(
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
                    return existing_ref

                # Match the global Job -> Run lock order used by claim/completion. State and
                # attempts must still equal the eligibility snapshot taken before import.
                producer_job = self._job(session, request.producer_job_id, lock=True)
                producer_run = self._run(session, request.producer_run_id, lock=True)
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
                return source_ref
        except IntegrityError as exc:
            with self.repository.transaction() as session:
                existing = self._artifact_by_idempotency_key(
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
                return existing_ref

    def create_replay_batch(
        self,
        request: CreateReplayBatchRequest,
        *,
        actor: str,
    ) -> ReplayBatchView:
        """Derive a planned KISA confirmation batch from one managed sealed source."""

        artifact_repository = self._require_artifact_repository()
        with self.repository.transaction() as session:
            existing = session.scalar(
                select(ReplayBatchRecord).where(
                    ReplayBatchRecord.idempotency_key == request.idempotency_key
                )
            )
            if existing is not None:
                source = self._artifact_ref(existing)
                self._existing_replay_batch(
                    session,
                    existing,
                    request=request,
                    source=source,
                    actor=actor,
                )
                stored_locator = ArtifactLocator(
                    artifact_id=source.artifact_id,
                    repository_version=source.repository_version,
                )
                artifact = self._artifact(session, stored_locator)
            else:
                artifact = self._artifact(session, request.source)
                source = self._artifact_record_ref(artifact)
            storage_key = artifact.storage_key
        snapshot = self._resolve_managed_artifact(
            artifact_repository,
            source,
            expected_storage_key=storage_key,
        )
        derived: DerivedKISAReplayBatch | None = None
        if existing is None:
            try:
                derived = derive_kisa_confirmation_batch(
                    source_root=snapshot.path,
                    artifact_ref=source,
                )
            except (OSError, ValueError) as exc:
                raise StateConflict("managed source is not eligible for KISA Replay") from exc
            # Re-open the immutable repository object after derivation. This catches a
            # substituted or modified source before any Replay authority is committed.
            snapshot = self._resolve_managed_artifact(
                artifact_repository,
                source,
                expected_storage_key=storage_key,
            )
        return self._create_replay_batch_from_source(
            request,
            source=source,
            verified_storage_key=snapshot.storage_key,
            derived=derived,
            actor=actor,
        )

    def _create_replay_batch_from_source(
        self,
        request: CreateReplayBatchRequest,
        *,
        source: ArtifactRef,
        verified_storage_key: str,
        derived: DerivedKISAReplayBatch | None,
        actor: str,
    ) -> ReplayBatchView:
        """Atomically persist server-derived, non-issuable Replay planning authority."""

        try:
            with self.repository.transaction() as session:
                artifact = self._artifact(session, request.source, lock=True)
                self._require_artifact_snapshot(
                    artifact,
                    source,
                    storage_key=verified_storage_key,
                )
                existing = session.scalar(
                    select(ReplayBatchRecord).where(
                        ReplayBatchRecord.idempotency_key == request.idempotency_key
                    )
                )
                if existing is not None:
                    return self._existing_replay_batch(
                        session,
                        existing,
                        request=request,
                        source=source,
                        actor=actor,
                    )

                source_run = self._run(session, source.producer_run_id, lock=True)
                self._require_run_state(source_run, RunState.COMPLETED)
                if derived is None:
                    raise StateConflict("Replay batch derivation is missing")
                if (
                    derived.artifact_ref != source
                    or derived.candidate_run_id != source.run_id
                    or derived.source_root_digest != source.integrity_root_digest
                    or derived.campaign_name != source_run.campaign_name
                    or derived.mode is not CampaignMode.AI_REDTEAM
                    or derived.purpose is not ReplayPurpose.CONFIRMATION
                    or derived.policy_version != KISA_CONFIRMATION_POLICY_VERSION
                    or not derived.items
                ):
                    raise StateConflict(
                        "derived KISA Replay authority does not match the admitted source"
                    )
                now = utc_now()
                batch = ReplayBatchRecord(
                    batch_id=f"replay-batch_{uuid4().hex}",
                    source_run_id=source.producer_run_id,
                    idempotency_key=request.idempotency_key,
                    campaign_name=derived.campaign_name,
                    created_by=actor,
                    source_artifact_id=source.artifact_id,
                    source_repository_version=source.repository_version,
                    source_content_digest=source.content_digest,
                    source_root_digest=source.integrity_root_digest,
                    source_artifact_run_id=source.run_id,
                    source_media_type=source.media_type,
                    source_schema_kind=source.schema_kind,
                    source_byte_length=source.byte_length,
                    source_created_by=source.created_by,
                    mode=derived.mode.value,
                    purpose=derived.purpose.value,
                    policy_version=derived.policy_version,
                    state=ReplayBatchState.PLANNED.value,
                    cas_version=1,
                    cancellation_reason=None,
                    created_at=now,
                    updated_at=now,
                    cancelled_at=None,
                )
                session.add(batch)
                session.flush()
                self._replay_event(
                    session,
                    batch,
                    "replay.batch.created",
                    actor,
                    {
                        "sourceArtifactId": source.artifact_id,
                        "sourceRepositoryVersion": source.repository_version,
                        "sourceRootDigest": source.integrity_root_digest,
                        "itemCount": len(derived.items),
                        "policyVersion": derived.policy_version,
                        "budgetDigest": derived.budget_digest,
                        "rateLimitsDigest": derived.rate_limits_digest,
                        "usedToolCalls": derived.used_tool_calls,
                        "requiredToolCalls": derived.required_tool_calls,
                    },
                    run_id=source_run.run_id,
                )

                for ordinal, admitted in enumerate(derived.items):
                    replay_run_id = admitted.replay_run_id
                    item_id = f"replay-item_{uuid4().hex}"
                    replay_run = RunRecord(
                        run_id=replay_run_id,
                        campaign_name=derived.campaign_name,
                        state=RunState.QUEUED.value,
                        input={
                            "replayPlan": {
                                "batchId": batch.batch_id,
                                "itemId": item_id,
                                "candidateId": admitted.candidate_id,
                                "candidateDigest": admitted.candidate_digest,
                                "contractDigest": admitted.contract_digest,
                                "compilationDigest": admitted.compilation_digest,
                                "grantDigest": admitted.grant_digest,
                                "policyVersion": derived.policy_version,
                                "sourceArtifactId": source.artifact_id,
                                "sourceRepositoryVersion": source.repository_version,
                                "sourceRootDigest": source.integrity_root_digest,
                            }
                        },
                        submission_key=f"replay-plan:{batch.batch_id}:{ordinal}",
                        current_checkpoint_id=None,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(replay_run)
                    session.flush()
                    item = ReplayItemRecord(
                        item_id=item_id,
                        batch_id=batch.batch_id,
                        source_run_id=batch.source_run_id,
                        replay_run_id=replay_run_id,
                        ordinal=ordinal,
                        candidate_id=admitted.candidate_id,
                        candidate_digest=admitted.candidate_digest,
                        contract_digest=admitted.contract_digest,
                        compilation_digest=admitted.compilation_digest,
                        grant_digest=admitted.grant_digest,
                        state=ReplayItemState.PENDING.value,
                        required_attempts=admitted.required_attempts,
                        max_attempts=admitted.max_attempts,
                        attempts=0,
                        created_at=now,
                        updated_at=now,
                    )
                    session.add(item)
                    session.flush()
                    compilation = ReplayCompilationRecord(
                        compilation_id=f"replay-compilation_{uuid4().hex}",
                        item_id=item.item_id,
                        batch_id=batch.batch_id,
                        replay_run_id=replay_run.run_id,
                        candidate_id=item.candidate_id,
                        candidate_digest=item.candidate_digest,
                        contract_digest=item.contract_digest,
                        compilation_digest=item.compilation_digest,
                        grant_digest=item.grant_digest,
                        canonical_compilation=admitted.canonical_compilation,
                        byte_length=len(admitted.canonical_compilation),
                        created_at=now,
                    )
                    session.add(compilation)
                    session.flush()
                    self._event(
                        session,
                        replay_run,
                        "run.replay-planned",
                        actor,
                        {
                            "campaignName": derived.campaign_name,
                            "replayBatchId": batch.batch_id,
                            "replayItemId": item.item_id,
                            "compilationDigest": item.compilation_digest,
                        },
                    )
                    self._replay_event(
                        session,
                        batch,
                        "replay.compilation.derived",
                        actor,
                        {
                            "compilationId": compilation.compilation_id,
                            "candidateDigest": item.candidate_digest,
                            "contractDigest": item.contract_digest,
                            "compilationDigest": item.compilation_digest,
                            "grantDigest": item.grant_digest,
                        },
                        item=item,
                        run_id=replay_run.run_id,
                    )
                return self._replay_batch_view(batch)
        except IntegrityError:
            with self.repository.transaction() as session:
                existing = session.scalar(
                    select(ReplayBatchRecord).where(
                        ReplayBatchRecord.idempotency_key == request.idempotency_key
                    )
                )
                if existing is None:
                    raise
                return self._existing_replay_batch(
                    session,
                    existing,
                    request=request,
                    source=source,
                    actor=actor,
                )

    def get_replay_batch(self, batch_id: str) -> ReplayBatchView:
        with self.repository.transaction() as session:
            return self._replay_batch_view(self._replay_batch(session, batch_id))

    def get_replay_item(self, item_id: str) -> ReplayItemView:
        with self.repository.transaction() as session:
            return self._replay_item_view(self._replay_item(session, item_id))

    def get_replay_ticket(self, ticket_id: str) -> ReplayTicketView:
        with self.repository.transaction() as session:
            return self._replay_ticket_view(self._replay_ticket(session, ticket_id))

    def get_run(self, run_id: str) -> RunView:
        with self.repository.transaction() as session:
            return self._run_view(self._run(session, run_id))

    def list_runs(
        self,
        *,
        state: RunState | None,
        limit: int,
        offset: int,
    ) -> RunListView:
        with self.repository.transaction() as session:
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
                items=[self._run_summary_view(record) for record in records],
                total=int(total or 0),
                limit=limit,
                offset=offset,
            )

    def get_current_approval(self, run_id: str) -> ApprovalView | None:
        with self.repository.transaction() as session:
            row = session.execute(
                select(
                    RunRecord.state,
                    RunRecord.current_checkpoint_id,
                    CheckpointRecord,
                    ApprovalRecord,
                )
                .select_from(RunRecord)
                .outerjoin(
                    CheckpointRecord,
                    and_(
                        CheckpointRecord.checkpoint_id == RunRecord.current_checkpoint_id,
                        CheckpointRecord.run_id == RunRecord.run_id,
                    ),
                )
                .outerjoin(
                    ApprovalRecord,
                    and_(
                        ApprovalRecord.checkpoint_id == CheckpointRecord.checkpoint_id,
                        ApprovalRecord.run_id == RunRecord.run_id,
                    ),
                )
                .where(RunRecord.run_id == run_id)
            ).one_or_none()
            if row is None:
                raise ResourceNotFound("run not found")
            run_state, checkpoint_id, checkpoint, approval = row
            if checkpoint_id is None:
                if run_state == RunState.AWAITING_APPROVAL.value:
                    raise StateConflict("awaiting-approval Run has no current checkpoint")
                return None
            if run_state not in {
                RunState.AWAITING_APPROVAL.value,
                RunState.CANCELLED.value,
            }:
                raise StateConflict(f"run in {run_state} state cannot have a current checkpoint")
            if checkpoint is None or approval is None:
                raise StateConflict("current checkpoint ownership is inconsistent")
            self._verify_checkpoint(checkpoint)
            intent = self._checkpoint_intent(checkpoint)
            if not self._approval_matches_intent(approval, intent):
                raise StateConflict("approval fields do not match signed checkpoint intent")
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
            return self._approval_view(approval)

    def cancel_run(
        self,
        run_id: str,
        request: CancelRunRequest,
        *,
        actor: str,
    ) -> CancelRunView:
        with self.repository.transaction() as session:
            replay_item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.replay_run_id == run_id)
            )
            if replay_item is not None:
                return self._cancel_replay_run(
                    session,
                    replay_item,
                    request=request,
                    actor=actor,
                )
            jobs_by_id = {job.job_id: job for job in self._lock_cancellable_jobs(session, run_id)}
            approvals = self._lock_revocable_approvals(session, run_id)
            # Resume locks its Approval before it inserts a continuation Job. Re-read Jobs after
            # acquiring Approval locks so a continuation created while cancellation was waiting
            # cannot escape the same transaction.
            jobs_by_id.update(
                {job.job_id: job for job in self._lock_cancellable_jobs(session, run_id)}
            )
            run = self._run(session, run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                return CancelRunView(
                    run=self._run_view(run),
                    applied=False,
                    cancelled_job_ids=[],
                    revoked_approval_ids=[],
                )
            if run.state not in _CANCELLABLE_RUN_STATES:
                raise StateConflict(f"run in {run.state} state cannot be cancelled")

            now = utc_now()
            cancelled_job_ids: list[str] = []
            for job in sorted(jobs_by_id.values(), key=lambda item: item.job_id):
                previous_lease_owner = job.lease_owner
                self._cancel_job(job, now=now)
                cancelled_job_ids.append(job.job_id)
                self._event(
                    session,
                    run,
                    "job.cancelled",
                    actor,
                    {
                        "jobId": job.job_id,
                        "previousLeaseOwner": previous_lease_owner,
                        "reason": request.reason,
                    },
                )

            revoked_approval_ids: list[str] = []
            for approval in approvals:
                approval.state = ApprovalState.REVOKED.value
                revoked_approval_ids.append(approval.approval_id)
                self._event(
                    session,
                    run,
                    "approval.revoked",
                    actor,
                    {
                        "approvalId": approval.approval_id,
                        "checkpointId": approval.checkpoint_id,
                        "reason": request.reason,
                    },
                )

            self._cancel_run_record(
                session,
                run,
                actor=actor,
                now=now,
                reason=request.reason,
                cause="operator-request",
                extra={
                    "cancelledJobIds": cancelled_job_ids,
                    "revokedApprovalIds": revoked_approval_ids,
                },
            )
            return CancelRunView(
                run=self._run_view(run),
                applied=True,
                cancelled_job_ids=cancelled_job_ids,
                revoked_approval_ids=revoked_approval_ids,
            )

    def get_job(self, job_id: str) -> JobView:
        with self.repository.transaction() as session:
            return self._job_view(self._job(session, job_id))

    def list_events(self, run_id: str) -> list[AuditEventView]:
        with self.repository.transaction() as session:
            self._run(session, run_id)
            records = session.scalars(
                select(EventRecord)
                .where(EventRecord.run_id == run_id)
                .order_by(EventRecord.sequence)
            ).all()
            return [self._event_view(record) for record in records]

    def claim_job(self, request: ClaimJobRequest, *, actor: str) -> ClaimedJob | None:
        requested_kinds = [
            kind.value if isinstance(kind, JobKind) else str(kind) for kind in request.kinds
        ]
        if _INTERNAL_REPLAY_KIND in requested_kinds:
            raise StateConflict("internal Replay Jobs require the trusted Replay claim service")
        public_kinds = {kind.value for kind in JobKind}
        if not requested_kinds or not set(requested_kinds).issubset(public_kinds):
            raise StateConflict("generic claim accepts only public Job kinds")
        sweep_time = utc_now()
        # Keep opportunistic cleanup outside the claim transaction. A sweep locks
        # Job -> Replay graph -> Run; acquiring another queued Job afterwards would
        # invert that global order and can deadlock concurrent PostgreSQL claimers.
        with self.repository.transaction() as session:
            self._expire_leases(session, now=sweep_time, actor=actor)
        claim_time = utc_now()
        with self.repository.transaction() as session:
            statement: Select[tuple[JobRecord]] = (
                select(JobRecord)
                .where(
                    JobRecord.state == JobState.QUEUED.value,
                    JobRecord.available_at <= claim_time,
                    JobRecord.kind.in_(requested_kinds),
                )
                .order_by(JobRecord.priority.desc(), JobRecord.created_at, JobRecord.job_id)
                .limit(1)
            )
            if self.repository.dialect_name == "postgresql":
                statement = statement.with_for_update(skip_locked=True)
            else:
                statement = statement.with_for_update()
            job = session.scalar(statement)
            if job is None:
                return None
            run = self._run(session, job.run_id, lock=True)
            now = utc_now()
            if run.state == RunState.CANCELLED.value:
                self._cancel_job(job, now=now)
                self._event(
                    session,
                    run,
                    "job.cancelled",
                    actor,
                    {"jobId": job.job_id, "reason": "run was already cancelled"},
                )
                return None
            self._require_run_state(run, RunState.QUEUED)
            lease_token = secrets.token_urlsafe(32)
            job.state = JobState.LEASED.value
            job.lease_owner = request.worker_id
            job.lease_token_hash = token_digest(lease_token)
            job.lease_expires_at = now + timedelta(seconds=request.lease_seconds)
            job.heartbeat_at = now
            job.attempts += 1
            job.updated_at = now
            run.state = RunState.RUNNING.value
            run.updated_at = now
            self._event(
                session,
                run,
                "job.claimed",
                actor,
                {
                    "jobId": job.job_id,
                    "workerId": request.worker_id,
                    "attempt": job.attempts,
                    "leaseExpiresAt": job.lease_expires_at.isoformat(),
                },
            )
            return ClaimedJob(job=self._job_view(job), lease_token=lease_token)

    def claim_replay_job(
        self,
        request: ReplayClaimRequest,
        *,
        actor: str,
    ) -> ReplayClaimView | None:
        """Burn exactly one issued Replay ticket while leasing its one-shot Job."""

        self._require_replay_executor_profile(actor, request.executor_profile)
        sweep_time = utc_now()
        # The cleanup transaction must commit before claim starts. Besides avoiding
        # SQLite reader-to-writer upgrade deadlocks, this keeps PostgreSQL claimers
        # from returning to a Job lock after they already locked Replay dependants.
        with self.repository.transaction() as session:
            self._expire_leases(session, now=sweep_time, actor=actor)
        with self.repository.transaction() as session:
            lease_token = secrets.token_urlsafe(32)
            lease_hash = token_digest(lease_token)
            claim_started_at = utc_now()
            claimable = (
                JobRecord.kind == _INTERNAL_REPLAY_KIND,
                JobRecord.state == JobState.QUEUED.value,
                JobRecord.available_at <= claim_started_at,
                JobRecord.attempts == 0,
                JobRecord.max_attempts == 1,
                JobRecord.lease_owner.is_(None),
                JobRecord.lease_token_hash.is_(None),
                JobRecord.lease_expires_at.is_(None),
                JobRecord.heartbeat_at.is_(None),
            )
            job: JobRecord | None
            if self.repository.dialect_name == "sqlite":
                candidate = (
                    select(JobRecord.job_id)
                    .where(*claimable)
                    .order_by(
                        JobRecord.priority.desc(),
                        JobRecord.created_at,
                        JobRecord.job_id,
                    )
                    .limit(1)
                    .scalar_subquery()
                )
                claimed_job_id = session.scalar(
                    update(JobRecord)
                    .where(JobRecord.job_id == candidate, *claimable)
                    .values(
                        state=JobState.LEASED.value,
                        lease_owner=actor,
                        lease_token_hash=lease_hash,
                        lease_expires_at=claim_started_at
                        + timedelta(seconds=request.lease_seconds),
                        heartbeat_at=claim_started_at,
                        attempts=1,
                        updated_at=claim_started_at,
                    )
                    .returning(JobRecord.job_id)
                )
                if claimed_job_id is None:
                    return None
                job = self._job(session, claimed_job_id)
            else:
                statement: Select[tuple[JobRecord]] = (
                    select(JobRecord)
                    .where(*claimable)
                    .order_by(
                        JobRecord.priority.desc(),
                        JobRecord.created_at,
                        JobRecord.job_id,
                    )
                    .limit(1)
                )
                if self.repository.dialect_name == "postgresql":
                    statement = statement.with_for_update(skip_locked=True)
                else:
                    statement = statement.with_for_update()
                job = session.scalar(statement)
            if job is None:
                return None

            ticket = self._replay_ticket_for_job(session, job.job_id, lock=True)
            item = self._replay_item(session, ticket.item_id, lock=True)
            batch = self._replay_batch(session, ticket.batch_id, lock=True)
            run = self._run(session, job.run_id, lock=True)
            self._verify_replay_binding(job, ticket, item, batch)
            now = utc_now()

            if (
                run.state == RunState.CANCELLED.value
                or batch.state == ReplayBatchState.CANCELLED.value
                or item.state == ReplayItemState.CANCELLED.value
            ):
                self._abandon_replay_ticket(
                    ticket,
                    now=now,
                    reason="replay authority was cancelled before claim",
                )
                self._cancel_job(job, now=now)
                item.state = ReplayItemState.CANCELLED.value
                item.updated_at = now
                self._replay_event(
                    session,
                    batch,
                    "replay.ticket.abandoned",
                    actor,
                    {"reason": ticket.abandon_reason},
                    item=item,
                    ticket=ticket,
                    job=job,
                    run_id=run.run_id,
                )
                return None

            self._require_run_state(run, RunState.QUEUED)
            if batch.state != ReplayBatchState.RUNNING.value:
                raise StateConflict(f"Replay batch in {batch.state} state cannot be claimed")
            if item.state != ReplayItemState.QUEUED.value:
                raise StateConflict(f"Replay item in {item.state} state cannot be claimed")
            if ticket.state != ReplayTicketState.ISSUED.value:
                raise StateConflict(f"Replay ticket is already {ticket.state}")
            expected_attempts = 1 if self.repository.dialect_name == "sqlite" else 0
            if job.attempts != expected_attempts or job.max_attempts != 1:
                raise StateConflict("internal Replay Job attempt authority is inconsistent")
            if _aware(ticket.expires_at) <= now:
                self._terminate_replay_attempt(
                    session,
                    job=job,
                    ticket=ticket,
                    item=item,
                    batch=batch,
                    run=run,
                    actor=actor,
                    now=now,
                    reason="Replay ticket expired before claim",
                    retryable=True,
                    event_type="replay.ticket.expired-before-claim",
                )
                return None

            # expires_at is the unclaimed issuance deadline. Once the ticket is
            # atomically burned, the claimed authority is governed by its lease.
            lease_expires_at = now + timedelta(seconds=request.lease_seconds)
            job.state = JobState.LEASED.value
            job.lease_owner = actor
            job.lease_token_hash = lease_hash
            job.lease_expires_at = lease_expires_at
            job.heartbeat_at = now
            job.attempts = 1
            job.updated_at = now
            claimed_ticket_id = session.scalar(
                update(ReplayTicketRecord)
                .where(
                    ReplayTicketRecord.ticket_id == ticket.ticket_id,
                    ReplayTicketRecord.state == ReplayTicketState.ISSUED.value,
                    ReplayTicketRecord.claim_principal.is_(None),
                    ReplayTicketRecord.executor_profile.is_(None),
                    ReplayTicketRecord.lease_token_hash.is_(None),
                    ReplayTicketRecord.claimed_at.is_(None),
                    ReplayTicketRecord.lease_expires_at.is_(None),
                )
                .values(
                    state=ReplayTicketState.CLAIMED.value,
                    executor_profile=request.executor_profile,
                    claim_principal=actor,
                    lease_token_hash=lease_hash,
                    claimed_at=now,
                    lease_expires_at=lease_expires_at,
                    updated_at=now,
                )
                .returning(ReplayTicketRecord.ticket_id)
            )
            if claimed_ticket_id != ticket.ticket_id:
                raise StateConflict("Replay ticket claim authority changed concurrently")
            session.refresh(ticket)
            item.state = ReplayItemState.RUNNING.value
            item.updated_at = now
            run.state = RunState.RUNNING.value
            run.updated_at = now
            self._event(
                session,
                run,
                "job.claimed",
                actor,
                {
                    "jobId": job.job_id,
                    "workerId": actor,
                    "attempt": job.attempts,
                    "leaseExpiresAt": lease_expires_at.isoformat(),
                    "replayTicketId": ticket.ticket_id,
                    "fencingValue": ticket.fencing_value,
                },
            )
            self._replay_event(
                session,
                batch,
                "replay.ticket.claimed",
                actor,
                {
                    "attempt": ticket.attempt_number,
                    "fencingValue": ticket.fencing_value,
                    "executorProfile": request.executor_profile,
                    "leaseExpiresAt": lease_expires_at.isoformat(),
                },
                item=item,
                ticket=ticket,
                job=job,
                run_id=run.run_id,
            )
            return self._replay_claim_view(
                job=job,
                batch=batch,
                item=item,
                ticket=ticket,
                lease_token=lease_token,
            )

    def heartbeat_replay_job(
        self,
        job_id: str,
        request: ReplayLeaseRequest,
        *,
        actor: str,
    ) -> ReplayClaimView:
        """Extend only the exact principal/token/ticket/fence Replay lease."""

        self._require_replay_executor_profile(actor, request.executor_profile)
        expired = False
        result: ReplayClaimView | None = None
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            if job.kind != _INTERNAL_REPLAY_KIND:
                raise StateConflict("Job is not an internal Replay Job")
            ticket = self._replay_ticket_for_job(session, job.job_id, lock=True)
            item = self._replay_item(session, ticket.item_id, lock=True)
            batch = self._replay_batch(session, ticket.batch_id, lock=True)
            run = self._run(session, job.run_id, lock=True)
            self._verify_replay_binding(job, ticket, item, batch)
            if (
                run.state == RunState.CANCELLED.value
                or batch.state == ReplayBatchState.CANCELLED.value
                or item.state == ReplayItemState.CANCELLED.value
            ):
                raise RunCancelled("run has been cancelled")
            now = utc_now()
            self._require_replay_lease_identity(
                job,
                ticket,
                request=request,
                actor=actor,
            )
            lease_deadline = min(
                _aware(job.lease_expires_at) if job.lease_expires_at else now,
                _aware(ticket.lease_expires_at) if ticket.lease_expires_at else now,
            )
            if lease_deadline <= now:
                self._terminate_replay_attempt(
                    session,
                    job=job,
                    ticket=ticket,
                    item=item,
                    batch=batch,
                    run=run,
                    actor=actor,
                    now=now,
                    reason="Replay lease expired",
                    retryable=True,
                    event_type="replay.ticket.lease-expired",
                )
                expired = True
            else:
                self._require_run_state(run, RunState.RUNNING)
                if batch.state != ReplayBatchState.RUNNING.value:
                    raise LeaseRejected("Replay batch is not running")
                if item.state != ReplayItemState.RUNNING.value:
                    raise LeaseRejected("Replay item is not running")
                if ticket.state != ReplayTicketState.CLAIMED.value:
                    raise LeaseRejected("Replay ticket is not claimed")
                lease_expires_at = now + timedelta(seconds=request.lease_seconds)
                job.heartbeat_at = now
                job.lease_expires_at = lease_expires_at
                job.updated_at = now
                ticket.lease_expires_at = lease_expires_at
                ticket.updated_at = now
                self._event(
                    session,
                    run,
                    "job.heartbeat",
                    actor,
                    {
                        "jobId": job.job_id,
                        "leaseExpiresAt": lease_expires_at.isoformat(),
                        "replayTicketId": ticket.ticket_id,
                        "fencingValue": ticket.fencing_value,
                    },
                )
                self._replay_event(
                    session,
                    batch,
                    "replay.ticket.heartbeat",
                    actor,
                    {
                        "fencingValue": ticket.fencing_value,
                        "leaseExpiresAt": lease_expires_at.isoformat(),
                    },
                    item=item,
                    ticket=ticket,
                    job=job,
                    run_id=run.run_id,
                )
                result = self._replay_claim_view(
                    job=job,
                    batch=batch,
                    item=item,
                    ticket=ticket,
                    lease_token=request.lease_token,
                )
        if expired:
            raise LeaseRejected("Replay job lease has expired")
        if result is None:
            raise RuntimeError("Replay heartbeat did not produce a result")
        return result

    def heartbeat(self, job_id: str, request: LeaseRequest, *, actor: str) -> JobView:
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            if job.kind == _INTERNAL_REPLAY_KIND:
                raise StateConflict("internal Replay Job requires the Replay heartbeat service")
            run = self._run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                # Keep this message deliberately generic. The operator's cancellation
                # reason is audit data and must not be disclosed to Worker credentials.
                raise RunCancelled("run has been cancelled")
            self._require_run_state(run, RunState.RUNNING)
            now = utc_now()
            self._require_active_lease(job, request.worker_id, request.lease_token, now)
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=request.lease_seconds)
            job.updated_at = now
            self._event(
                session,
                run,
                "job.heartbeat",
                actor,
                {"jobId": job.job_id, "leaseExpiresAt": job.lease_expires_at.isoformat()},
            )
            return self._job_view(job)

    def complete_job(self, job_id: str, request: CompleteJobRequest, *, actor: str) -> JobView:
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            if job.kind == _INTERNAL_REPLAY_KIND:
                raise StateConflict("internal Replay Job requires typed server-side finalization")
            run = self._run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                raise RunCancelled("run has been cancelled")
            self._require_lease_identity(job, request.worker_id, request.lease_token)
            if job.state == JobState.SUCCEEDED.value:
                return self._job_view(job)
            self._require_run_state(run, RunState.RUNNING)
            now = utc_now()
            self._require_active_lease(job, request.worker_id, request.lease_token, now)
            job.state = JobState.SUCCEEDED.value
            job.result = request.result
            job.error = None
            job.lease_expires_at = None
            job.updated_at = now
            run.state = RunState.COMPLETED.value
            run.updated_at = now
            self._event(session, run, "job.completed", actor, {"jobId": job.job_id})
            self._event(session, run, "run.completed", actor, {"jobId": job.job_id})
            return self._job_view(job)

    def fail_job(self, job_id: str, request: FailJobRequest, *, actor: str) -> JobView:
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            if job.kind == _INTERNAL_REPLAY_KIND:
                raise StateConflict("internal Replay Job cannot use generic failure/requeue")
            run = self._run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                raise RunCancelled("run has been cancelled")
            self._require_run_state(run, RunState.RUNNING)
            now = utc_now()
            self._require_active_lease(job, request.worker_id, request.lease_token, now)
            job.error = request.error
            job.lease_owner = None
            job.lease_token_hash = None
            job.lease_expires_at = None
            job.heartbeat_at = None
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
            return self._job_view(job)

    def create_checkpoint(
        self,
        job_id: str,
        request: CreateCheckpointRequest,
        *,
        actor: str,
    ) -> CheckpointCreationView:
        with self.repository.transaction() as session:
            job = self._job(session, job_id, lock=True)
            if job.kind == _INTERNAL_REPLAY_KIND:
                raise StateConflict("internal Replay Job cannot create approval checkpoints")
            run = self._run(session, job.run_id, lock=True)
            if run.state == RunState.CANCELLED.value:
                raise RunCancelled("run has been cancelled")
            self._require_run_state(run, RunState.RUNNING)
            now = utc_now()
            if request.pending_intent.expires_at <= now:
                raise StateConflict("approval intent is already expired")
            self._require_active_lease(job, request.worker_id, request.lease_token, now)
            current_sequence = session.scalar(
                select(func.max(CheckpointRecord.sequence)).where(
                    CheckpointRecord.run_id == run.run_id
                )
            )
            sequence = int(current_sequence or 0) + 1
            checkpoint_id = f"checkpoint_{uuid4().hex}"
            payload = {
                "state": request.state,
                "pendingIntent": request.pending_intent.model_dump(mode="json"),
                "job": {"kind": job.kind, "maxAttempts": job.max_attempts},
            }
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
                call_fingerprint=request.pending_intent.call_fingerprint,
                tool_id=request.pending_intent.tool_id,
                target=request.pending_intent.target,
                risk_tier=int(request.pending_intent.risk_tier),
                state=ApprovalState.PENDING.value,
                requested_by=actor,
                requested_at=now,
                expires_at=request.pending_intent.expires_at,
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
                    "riskTier": int(request.pending_intent.risk_tier),
                    "callFingerprint": request.pending_intent.call_fingerprint,
                },
            )
            return CheckpointCreationView(
                checkpoint=self._checkpoint_view(checkpoint),
                approval=self._approval_view(approval),
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
            approval_reference = self._approval(session, approval_id)
            checkpoint = self._checkpoint(session, approval_reference.checkpoint_id, lock=True)
            approval = self._approval(session, approval_id, lock=True)
            if (
                approval.checkpoint_id != checkpoint.checkpoint_id
                or approval.run_id != checkpoint.run_id
            ):
                raise StateConflict("approval does not belong to its signed checkpoint")
            run = self._run(session, approval.run_id, lock=True)
            if approval.state != ApprovalState.PENDING.value:
                raise StateConflict("approval has already been decided")
            self._require_run_state(run, RunState.AWAITING_APPROVAL)
            self._require_current_checkpoint(run, approval.checkpoint_id)
            self._verify_checkpoint(checkpoint)
            intent = self._checkpoint_intent(checkpoint)
            if not self._approval_matches_intent(approval, intent):
                raise StateConflict("approval fields do not match signed checkpoint intent")
            if approval.requested_by == actor:
                raise StateConflict("approval requester cannot decide their own request")
            now = utc_now()
            if _aware(approval.expires_at) <= now:
                self._expire_approval(session, approval, run, actor=actor, now=now)
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
                    self._cancel_run_record(
                        session,
                        run,
                        actor=actor,
                        now=now,
                        reason=request.reason,
                        cause="approval-denied",
                        extra={"approvalId": approval.approval_id},
                    )
                view = self._approval_view(approval)
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
            checkpoint = self._checkpoint(session, checkpoint_id, lock=True)
            approval = self._approval(session, approval_id, lock=True)
            if (
                approval.checkpoint_id != checkpoint.checkpoint_id
                or approval.run_id != checkpoint.run_id
            ):
                raise StateConflict("approval does not authorize this checkpoint")
            run = self._run(session, checkpoint.run_id, lock=True)
            self._verify_checkpoint(checkpoint)
            # A claimed checkpoint is an immutable, single-use authority boundary.
            # Report that terminal fact before inspecting the Run's post-resume state;
            # otherwise a legitimate duplicate resume is misclassified as a generic
            # lifecycle conflict after the first claimant moves the Run back to queued.
            if checkpoint.claimed_at is not None:
                raise StateConflict("checkpoint has already been claimed")
            self._require_run_state(run, RunState.AWAITING_APPROVAL)
            self._require_current_checkpoint(run, checkpoint.checkpoint_id)
            if approval.state != ApprovalState.APPROVED.value:
                raise StateConflict("checkpoint requires an active approved decision")
            now = utc_now()
            if _aware(approval.expires_at) <= now:
                self._expire_approval(session, approval, run, actor=actor, now=now)
                expired = True
            else:
                intent = self._checkpoint_intent(checkpoint)
                if not self._approval_matches_intent(approval, intent):
                    raise StateConflict("approval fields do not match signed checkpoint intent")
                raw_job_context = checkpoint.payload.get("job", {})
                job_context = raw_job_context if isinstance(raw_job_context, dict) else {}
                continuation_kind = str(job_context.get("kind", "campaign"))
                continuation_max_attempts = int(job_context.get("maxAttempts", 3))
                job = JobRecord(
                    job_id=f"job_{uuid4().hex}",
                    run_id=run.run_id,
                    kind=continuation_kind,
                    state=JobState.QUEUED.value,
                    payload={
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
                    },
                    priority=10,
                    attempts=0,
                    max_attempts=continuation_max_attempts,
                    idempotency_key=f"resume:{checkpoint.checkpoint_id}",
                    available_at=now,
                    lease_owner=None,
                    lease_token_hash=None,
                    lease_expires_at=None,
                    heartbeat_at=None,
                    result=None,
                    error=None,
                    created_at=now,
                    updated_at=now,
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
                    run=self._run_view(run),
                    job=self._job_view(job),
                    checkpoint=self._checkpoint_view(checkpoint),
                    approval=self._approval_view(approval),
                )
        if expired:
            raise StateConflict("approval has expired")
        if result is None:
            raise RuntimeError("checkpoint resume did not produce a result")
        return result

    def requeue_expired(self, *, actor: str) -> int:
        with self.repository.transaction() as session:
            return self._expire_leases(session, now=utc_now(), actor=actor)

    def _expire_leases(self, session: Session, *, now: datetime, actor: str) -> int:
        statement = (
            select(JobRecord)
            .where(
                JobRecord.state == JobState.LEASED.value,
                JobRecord.lease_expires_at <= now,
            )
            .order_by(JobRecord.job_id)
        )
        if self.repository.dialect_name == "postgresql":
            statement = statement.with_for_update(skip_locked=True)
        jobs = list(session.scalars(statement).all())

        # Do not lazily walk each Replay graph. Concurrent SKIP LOCKED sweepers can
        # partition sibling Jobs from multiple batches; per-Job traversal would then
        # let each transaction hold one batch while waiting for the other. Pre-lock
        # every selected graph table-by-table in the canonical global order instead:
        # Job (above) -> ticket -> item -> batch -> Run.
        replay_jobs = [job for job in jobs if job.kind == _INTERNAL_REPLAY_KIND]
        tickets_by_job_id: dict[str, ReplayTicketRecord] = {}
        items_by_id: dict[str, ReplayItemRecord] = {}
        batches_by_id: dict[str, ReplayBatchRecord] = {}
        if replay_jobs:
            replay_job_ids = sorted(job.job_id for job in replay_jobs)
            tickets = list(
                session.scalars(
                    select(ReplayTicketRecord)
                    .where(ReplayTicketRecord.job_id.in_(replay_job_ids))
                    .order_by(ReplayTicketRecord.ticket_id)
                    .with_for_update()
                ).all()
            )
            tickets_by_job_id = {ticket.job_id: ticket for ticket in tickets}
            missing_ticket_jobs = set(replay_job_ids).difference(tickets_by_job_id)
            if missing_ticket_jobs:
                raise StateConflict("internal Replay Job exists without its ticket")

            item_ids = sorted({ticket.item_id for ticket in tickets})
            items = list(
                session.scalars(
                    select(ReplayItemRecord)
                    .where(ReplayItemRecord.item_id.in_(item_ids))
                    .order_by(ReplayItemRecord.item_id)
                    .with_for_update()
                ).all()
            )
            items_by_id = {item.item_id: item for item in items}
            if set(item_ids).difference(items_by_id):
                raise StateConflict("Replay ticket exists without its item")

            batch_ids = sorted({ticket.batch_id for ticket in tickets})
            batches = list(
                session.scalars(
                    select(ReplayBatchRecord)
                    .where(ReplayBatchRecord.batch_id.in_(batch_ids))
                    .order_by(ReplayBatchRecord.batch_id)
                    .with_for_update()
                ).all()
            )
            batches_by_id = {batch.batch_id: batch for batch in batches}
            if set(batch_ids).difference(batches_by_id):
                raise StateConflict("Replay item exists without its batch")

        run_ids = sorted({job.run_id for job in jobs})
        runs = (
            list(
                session.scalars(
                    select(RunRecord)
                    .where(RunRecord.run_id.in_(run_ids))
                    .order_by(RunRecord.run_id)
                    .with_for_update()
                ).all()
            )
            if run_ids
            else []
        )
        runs_by_id = {run.run_id: run for run in runs}
        if set(run_ids).difference(runs_by_id):
            raise StateConflict("leased Job exists without its Run")

        requeued_or_dead_lettered = 0
        for job in jobs:
            run = runs_by_id[job.run_id]
            if job.kind == _INTERNAL_REPLAY_KIND:
                ticket = tickets_by_job_id[job.job_id]
                item = items_by_id[ticket.item_id]
                batch = batches_by_id[ticket.batch_id]
                self._verify_replay_binding(job, ticket, item, batch)
                transition_time = utc_now()
                if (
                    run.state == RunState.CANCELLED.value
                    or batch.state == ReplayBatchState.CANCELLED.value
                ):
                    self._abandon_replay_ticket(
                        ticket,
                        now=transition_time,
                        reason="cancelled Replay lease was reaped",
                    )
                    self._cancel_job(job, now=transition_time)
                    item.state = ReplayItemState.CANCELLED.value
                    item.updated_at = transition_time
                    self._replay_event(
                        session,
                        batch,
                        "replay.ticket.abandoned",
                        actor,
                        {"reason": ticket.abandon_reason},
                        item=item,
                        ticket=ticket,
                        job=job,
                        run_id=run.run_id,
                    )
                    continue
                self._require_run_state(run, RunState.RUNNING)
                if ticket.state != ReplayTicketState.CLAIMED.value:
                    raise StateConflict("leased Replay Job does not own a claimed ticket")
                if item.state != ReplayItemState.RUNNING.value:
                    raise StateConflict("leased Replay Job does not own a running item")
                self._terminate_replay_attempt(
                    session,
                    job=job,
                    ticket=ticket,
                    item=item,
                    batch=batch,
                    run=run,
                    actor=actor,
                    now=transition_time,
                    reason="Replay lease expired",
                    retryable=True,
                    event_type="replay.ticket.lease-expired",
                )
                requeued_or_dead_lettered += 1
                continue
            transition_time = utc_now()
            if run.state == RunState.CANCELLED.value:
                self._cancel_job(job, now=transition_time)
                self._event(
                    session,
                    run,
                    "job.cancelled",
                    actor,
                    {"jobId": job.job_id, "reason": "cancelled run lease was reaped"},
                )
                continue
            self._require_run_state(run, RunState.RUNNING)
            job.lease_owner = None
            job.lease_token_hash = None
            job.lease_expires_at = None
            job.heartbeat_at = None
            job.updated_at = transition_time
            if job.attempts < job.max_attempts:
                job.state = JobState.QUEUED.value
                job.available_at = transition_time
                run.state = RunState.QUEUED.value
                event_type = "job.lease-expired-requeued"
            else:
                job.state = JobState.DEAD_LETTER.value
                run.state = RunState.FAILED.value
                event_type = "job.lease-expired-dead-lettered"
            run.updated_at = transition_time
            requeued_or_dead_lettered += 1
            self._event(
                session,
                run,
                event_type,
                actor,
                {"jobId": job.job_id, "attempt": job.attempts},
            )
        return requeued_or_dead_lettered

    def _cancel_replay_run(
        self,
        session: Session,
        replay_item_hint: ReplayItemRecord,
        *,
        request: CancelRunRequest,
        actor: str,
    ) -> CancelRunView:
        """Cancel one Replay item under the Job -> ticket -> item -> batch -> Run order."""

        jobs = self._lock_cancellable_jobs(session, replay_item_hint.replay_run_id)
        tickets = list(
            session.scalars(
                select(ReplayTicketRecord)
                .where(ReplayTicketRecord.item_id == replay_item_hint.item_id)
                .order_by(ReplayTicketRecord.attempt_number, ReplayTicketRecord.ticket_id)
                .with_for_update()
            ).all()
        )
        items = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == replay_item_hint.batch_id)
                .order_by(ReplayItemRecord.ordinal, ReplayItemRecord.item_id)
                .with_for_update()
            ).all()
        )
        batch = self._replay_batch(session, replay_item_hint.batch_id, lock=True)
        requested_run = self._run(session, replay_item_hint.replay_run_id, lock=True)
        jobs_by_id = {job.job_id: job for job in jobs}
        items_by_id = {item.item_id: item for item in items}
        current_item = items_by_id.get(replay_item_hint.item_id)
        if current_item is None:
            raise StateConflict("Replay item disappeared during cancellation")
        if (
            current_item.batch_id != batch.batch_id
            or current_item.replay_run_id != requested_run.run_id
        ):
            raise StateConflict("Replay item cancellation authority changed concurrently")
        if current_item.state == ReplayItemState.CANCELLED.value:
            return CancelRunView(
                run=self._run_view(requested_run),
                applied=False,
                cancelled_job_ids=[],
                revoked_approval_ids=[],
            )

        retry_authority_cancel = (
            current_item.state == ReplayItemState.RETRY_PENDING.value
            and requested_run.state == RunState.FAILED.value
        )
        if requested_run.state == RunState.CANCELLED.value:
            raise StateConflict("cancelled Replay Run still owns active item authority")
        if requested_run.state not in _CANCELLABLE_RUN_STATES and not retry_authority_cancel:
            raise StateConflict(f"run in {requested_run.state} state cannot be cancelled")
        if current_item.state in _TERMINAL_REPLAY_ITEM_STATES:
            raise StateConflict(f"Replay item in {current_item.state} state cannot be cancelled")
        if batch.state in {
            ReplayBatchState.COMPLETED.value,
            ReplayBatchState.FAILED.value,
            ReplayBatchState.CANCELLED.value,
        }:
            raise StateConflict(f"Replay batch in {batch.state} state cannot be cancelled")

        now = utc_now()
        cancelled_job_ids: list[str] = []
        for job in jobs:
            if job.kind != _INTERNAL_REPLAY_KIND:
                raise StateConflict("Replay batch owns a non-Replay active Job")
            previous_lease_owner = job.lease_owner
            self._cancel_job(job, now=now)
            cancelled_job_ids.append(job.job_id)
            if job.run_id != requested_run.run_id:
                raise StateConflict("Replay Job belongs to an unexpected Run")
            self._event(
                session,
                requested_run,
                "job.cancelled",
                actor,
                {
                    "jobId": job.job_id,
                    "previousLeaseOwner": previous_lease_owner,
                    "reason": request.reason,
                    "replayBatchId": batch.batch_id,
                },
            )

        for ticket in tickets:
            item = items_by_id.get(ticket.item_id)
            if item is None:
                raise StateConflict("Replay ticket exists without its item")
            if ticket.state in _ACTIVE_REPLAY_TICKET_STATES:
                self._abandon_replay_ticket(
                    ticket,
                    now=now,
                    reason="Replay item cancelled by operator",
                )
                self._replay_event(
                    session,
                    batch,
                    "replay.ticket.abandoned",
                    actor,
                    {"reason": request.reason},
                    item=item,
                    ticket=ticket,
                    job=jobs_by_id.get(ticket.job_id),
                    run_id=ticket.replay_run_id,
                )

        current_item.state = ReplayItemState.CANCELLED.value
        current_item.updated_at = now
        batch.updated_at = now
        batch.cas_version += 1
        if batch.cancellation_reason is None:
            batch.cancellation_reason = request.reason
            batch.cancelled_at = now
        terminal_batch_state = self._refresh_terminal_replay_batch_state(
            batch,
            items,
            now=now,
        )
        batch_cancelled = terminal_batch_state == ReplayBatchState.CANCELLED.value

        if retry_authority_cancel:
            # The expired one-shot attempt is immutable terminal history. Cancelling
            # retry authority fences future attempts without rewriting its failed Run.
            self._event(
                session,
                requested_run,
                "run.replay-retry-authority-cancelled",
                actor,
                {
                    "reason": request.reason,
                    "replayBatchId": batch.batch_id,
                    "replayItemId": current_item.item_id,
                },
            )
        else:
            self._cancel_run_record(
                session,
                requested_run,
                actor=actor,
                now=now,
                reason=request.reason,
                cause="replay-item-cancelled",
                extra={"replayBatchId": batch.batch_id, "replayItemId": current_item.item_id},
            )
        self._replay_event(
            session,
            batch,
            "replay.batch.cancelled" if batch_cancelled else "replay.item.cancelled",
            actor,
            {
                "reason": request.reason,
                "cancelledJobIds": cancelled_job_ids,
                "batchCancelled": batch_cancelled,
            },
            item=current_item,
            run_id=requested_run.run_id,
        )
        return CancelRunView(
            run=self._run_view(requested_run),
            applied=True,
            cancelled_job_ids=cancelled_job_ids,
            revoked_approval_ids=[],
        )

    def _lock_cancellable_jobs(self, session: Session, run_id: str) -> list[JobRecord]:
        statement = (
            select(JobRecord)
            .where(
                JobRecord.run_id == run_id,
                JobRecord.state.in_(_CANCELLABLE_JOB_STATES),
            )
            .order_by(JobRecord.job_id)
            .with_for_update()
        )
        return list(session.scalars(statement).all())

    def _lock_revocable_approvals(self, session: Session, run_id: str) -> list[ApprovalRecord]:
        statement = (
            select(ApprovalRecord)
            .where(
                ApprovalRecord.run_id == run_id,
                ApprovalRecord.state.in_(_REVOCABLE_APPROVAL_STATES),
            )
            .order_by(ApprovalRecord.approval_id)
            .with_for_update()
        )
        return list(session.scalars(statement).all())

    @staticmethod
    def _cancel_job(job: JobRecord, *, now: datetime) -> None:
        job.state = JobState.CANCELLED.value
        job.lease_owner = None
        job.lease_token_hash = None
        job.lease_expires_at = None
        job.heartbeat_at = None
        job.updated_at = now

    def _cancel_run_record(
        self,
        session: Session,
        run: RunRecord,
        *,
        actor: str,
        now: datetime,
        reason: str,
        cause: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        if run.state == RunState.CANCELLED.value:
            return
        if run.state not in _CANCELLABLE_RUN_STATES:
            raise StateConflict(f"run in {run.state} state cannot be cancelled")
        run.state = RunState.CANCELLED.value
        run.updated_at = now
        self._event(
            session,
            run,
            "run.cancelled",
            actor,
            {"cause": cause, "reason": reason, **(extra or {})},
        )

    def _expire_approval(
        self,
        session: Session,
        approval: ApprovalRecord,
        run: RunRecord,
        *,
        actor: str,
        now: datetime,
    ) -> None:
        approval.state = ApprovalState.EXPIRED.value
        self._event(
            session,
            run,
            "approval.expired",
            actor,
            {
                "approvalId": approval.approval_id,
                "checkpointId": approval.checkpoint_id,
                "expiredAt": approval.expires_at.isoformat(),
            },
        )
        self._cancel_run_record(
            session,
            run,
            actor=actor,
            now=now,
            reason="approval expired before it could be consumed",
            cause="approval-expired",
            extra={"approvalId": approval.approval_id},
        )

    @staticmethod
    def _require_run_state(run: RunRecord, expected: RunState) -> None:
        if run.state == expected.value:
            return
        if run.state == RunState.CANCELLED.value:
            raise StateConflict("run has been cancelled")
        raise StateConflict(f"run must be {expected.value}, not {run.state}")

    @staticmethod
    def _require_current_checkpoint(run: RunRecord, checkpoint_id: str) -> None:
        if run.current_checkpoint_id != checkpoint_id:
            raise StateConflict("checkpoint is not the Run's current approval boundary")

    @staticmethod
    def _require_lease_identity(job: JobRecord, worker_id: str, token: str) -> None:
        if job.lease_owner != worker_id or job.lease_token_hash is None:
            raise LeaseRejected("job lease is not owned by this worker")
        if not hmac.compare_digest(job.lease_token_hash, token_digest(token)):
            raise LeaseRejected("job lease token is invalid")

    @classmethod
    def _require_active_lease(
        cls, job: JobRecord, worker_id: str, token: str, now: datetime
    ) -> None:
        cls._require_lease_identity(job, worker_id, token)
        if job.state != JobState.LEASED.value:
            raise LeaseRejected("job is not actively leased")
        if job.lease_expires_at is None or _aware(job.lease_expires_at) <= now:
            raise LeaseRejected("job lease has expired")

    @staticmethod
    def _verify_replay_binding(
        job: JobRecord,
        ticket: ReplayTicketRecord,
        item: ReplayItemRecord,
        batch: ReplayBatchRecord,
    ) -> ReplayJobPayload:
        try:
            payload = ReplayJobPayload.model_validate(job.payload)
        except ValueError as exc:
            raise StateConflict("internal Replay Job payload is not canonical") from exc
        source = ControlPlaneService._artifact_ref(batch)
        if not (
            job.kind == _INTERNAL_REPLAY_KIND
            and job.max_attempts == 1
            and job.job_id == ticket.job_id
            and job.run_id == ticket.replay_run_id
            and item.item_id == ticket.item_id
            and item.batch_id == ticket.batch_id == batch.batch_id
            and item.source_run_id == batch.source_run_id
            and item.replay_run_id == ticket.replay_run_id
            and item.grant_digest == ticket.grant_digest
            and item.compilation_digest == ticket.compilation_digest
            and batch.source_root_digest == ticket.source_root_digest
            and item.attempts == ticket.attempt_number
            and payload.batch_id == batch.batch_id
            and payload.item_id == item.item_id
            and payload.ticket_id == ticket.ticket_id
            and payload.replay_run_id == ticket.replay_run_id
            and payload.source == source
            and payload.mode.value == batch.mode
            and payload.purpose.value == batch.purpose
            and payload.policy_version == batch.policy_version
            and payload.candidate_id == item.candidate_id
            and payload.candidate_digest == item.candidate_digest
            and payload.contract_digest == item.contract_digest
            and payload.compilation_digest == item.compilation_digest
            and payload.grant_digest == item.grant_digest
            and payload.attempt == ticket.attempt_number
            and payload.fencing_value == ticket.fencing_value
        ):
            raise StateConflict("internal Replay Job authority binding is inconsistent")
        return payload

    def _require_replay_executor_profile(self, actor: str, executor_profile: str) -> None:
        allowed = self._replay_executor_profiles.get(actor, frozenset())
        if executor_profile not in allowed:
            raise StateConflict(
                "authenticated Worker principal is not registered for this Replay executor"
            )

    @staticmethod
    def _require_replay_lease_identity(
        job: JobRecord,
        ticket: ReplayTicketRecord,
        *,
        request: ReplayLeaseRequest,
        actor: str,
    ) -> None:
        if (
            request.ticket_id != ticket.ticket_id
            or request.fencing_value != ticket.fencing_value
            or request.executor_profile != ticket.executor_profile
            or actor != ticket.claim_principal
            or actor != job.lease_owner
        ):
            raise LeaseRejected("Replay lease identity or fencing value does not match")
        if (
            job.state != JobState.LEASED.value
            or ticket.state != ReplayTicketState.CLAIMED.value
            or job.lease_token_hash is None
            or ticket.lease_token_hash is None
        ):
            raise LeaseRejected("Replay job is not actively leased")
        supplied_digest = token_digest(request.lease_token)
        if not (
            hmac.compare_digest(job.lease_token_hash, supplied_digest)
            and hmac.compare_digest(ticket.lease_token_hash, supplied_digest)
            and hmac.compare_digest(job.lease_token_hash, ticket.lease_token_hash)
        ):
            raise LeaseRejected("Replay lease token is invalid")
        if (
            job.lease_expires_at is None
            or ticket.lease_expires_at is None
            or _aware(job.lease_expires_at) != _aware(ticket.lease_expires_at)
        ):
            raise LeaseRejected("Replay Job and ticket lease deadlines do not match")

    @staticmethod
    def _abandon_replay_ticket(
        ticket: ReplayTicketRecord,
        *,
        now: datetime,
        reason: str,
    ) -> None:
        if ticket.state not in _ACTIVE_REPLAY_TICKET_STATES:
            raise StateConflict(f"Replay ticket in {ticket.state} state cannot be abandoned")
        bounded_reason = reason.strip()[:2_000]
        if not bounded_reason:
            raise ValueError("Replay ticket abandonment reason must not be blank")
        ticket.state = ReplayTicketState.ABANDONED.value
        ticket.abandoned_at = now
        ticket.abandon_reason = bounded_reason
        ticket.updated_at = now

    @staticmethod
    def _refresh_terminal_replay_batch_state(
        batch: ReplayBatchRecord,
        items: list[ReplayItemRecord],
        *,
        now: datetime,
    ) -> str | None:
        """Resolve a terminal batch solely from its final item-state set.

        Cancellation has precedence over failure so the same terminal item set
        always produces the same aggregate regardless of transition order.
        """

        item_states = {item.state for item in items}
        if not item_states or any(
            state not in _TERMINAL_REPLAY_ITEM_STATES for state in item_states
        ):
            return None
        if ReplayItemState.CANCELLED.value in item_states:
            resolved = ReplayBatchState.CANCELLED.value
            if batch.cancellation_reason is None:
                batch.cancellation_reason = "one or more Replay items were cancelled"
                batch.cancelled_at = now
        elif ReplayItemState.FAILED.value in item_states:
            resolved = ReplayBatchState.FAILED.value
        else:
            resolved = ReplayBatchState.COMPLETED.value
        batch.state = resolved
        batch.updated_at = now
        return resolved

    def _terminate_replay_attempt(
        self,
        session: Session,
        *,
        job: JobRecord,
        ticket: ReplayTicketRecord,
        item: ReplayItemRecord,
        batch: ReplayBatchRecord,
        run: RunRecord,
        actor: str,
        now: datetime,
        reason: str,
        retryable: bool,
        event_type: str,
    ) -> None:
        self._abandon_replay_ticket(ticket, now=now, reason=reason)
        job.state = JobState.FAILED.value
        job.error = reason[:2_000]
        job.result = None
        job.lease_owner = None
        job.lease_token_hash = None
        job.lease_expires_at = None
        job.heartbeat_at = None
        job.updated_at = now
        retry_pending = retryable and item.attempts < item.max_attempts
        item.state = (
            ReplayItemState.RETRY_PENDING.value if retry_pending else ReplayItemState.FAILED.value
        )
        item.updated_at = now
        run.state = RunState.FAILED.value
        run.updated_at = now
        batch.updated_at = now
        batch.cas_version += 1
        batch_items = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == batch.batch_id)
                .order_by(ReplayItemRecord.ordinal, ReplayItemRecord.item_id)
            ).all()
        )
        self._refresh_terminal_replay_batch_state(batch, batch_items, now=now)
        self._event(
            session,
            run,
            "job.replay-attempt-abandoned",
            actor,
            {
                "jobId": job.job_id,
                "replayTicketId": ticket.ticket_id,
                "attempt": ticket.attempt_number,
                "fencingValue": ticket.fencing_value,
                "retryPending": retry_pending,
                "reason": reason,
            },
        )
        self._replay_event(
            session,
            batch,
            event_type,
            actor,
            {
                "reason": reason,
                "attempt": ticket.attempt_number,
                "fencingValue": ticket.fencing_value,
                "retryPending": retry_pending,
            },
            item=item,
            ticket=ticket,
            job=job,
            run_id=run.run_id,
        )

    def _verify_checkpoint(self, checkpoint: CheckpointRecord) -> None:
        self.signer.verify(
            checkpoint_id=checkpoint.checkpoint_id,
            run_id=checkpoint.run_id,
            sequence=checkpoint.sequence,
            schema_version=checkpoint.schema_version,
            payload=checkpoint.payload,
            payload_sha256=checkpoint.payload_sha256,
            signature=checkpoint.signature,
            key_id=checkpoint.key_id,
        )

    @staticmethod
    def _checkpoint_intent(checkpoint: CheckpointRecord) -> ApprovalIntent:
        value = checkpoint.payload.get("pendingIntent")
        if not isinstance(value, dict):
            raise StateConflict("signed checkpoint does not contain an approval intent")
        return ApprovalIntent.model_validate(value)

    @staticmethod
    def _approval_matches_intent(approval: ApprovalRecord, intent: ApprovalIntent) -> bool:
        return (
            approval.call_fingerprint == intent.call_fingerprint
            and approval.tool_id == intent.tool_id
            and approval.target == intent.target
            and approval.risk_tier == int(intent.risk_tier)
            and _aware(approval.expires_at) == intent.expires_at
        )

    def _require_artifact_repository(self) -> ManagedArtifactRepository:
        if self._artifact_repository is None:
            raise StateConflict("managed Artifact repository is not configured")
        return self._artifact_repository

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
    def _artifact_record_ref(record: ArtifactRecord) -> ArtifactRef:
        try:
            return ArtifactRef(
                artifact_id=record.artifact_id,
                repository_version=record.repository_version,
                producer_run_id=record.producer_run_id,
                media_type=record.media_type,
                schema_kind=record.schema_kind,
                byte_length=record.byte_length,
                content_digest=record.content_digest,
                run_id=record.sealed_run_id,
                integrity_root_digest=record.root_digest,
                created_by=record.created_by,
            )
        except ValidationError as exc:
            raise StateConflict("managed Artifact metadata is invalid") from exc

    @staticmethod
    def _require_artifact_snapshot(
        record: ArtifactRecord,
        ref: ArtifactRef,
        *,
        storage_key: str,
    ) -> None:
        if (
            ControlPlaneService._artifact_record_ref(record) != ref
            or record.storage_key != storage_key
        ):
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
        return ControlPlaneService._artifact_record_ref(record)

    def _existing_submission(self, session: Session, run: RunRecord) -> SubmissionView:
        job = session.scalar(
            select(JobRecord).where(JobRecord.idempotency_key == f"submission:{run.submission_key}")
        )
        if job is None:
            raise StateConflict("idempotent run exists without its initial job")
        return SubmissionView(run=self._run_view(run), job=self._job_view(job), created=False)

    def _existing_replay_batch(
        self,
        session: Session,
        batch: ReplayBatchRecord,
        *,
        request: CreateReplayBatchRequest,
        source: ArtifactRef,
        actor: str,
    ) -> ReplayBatchView:
        items = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == batch.batch_id)
                .order_by(ReplayItemRecord.ordinal)
            ).all()
        )
        compilations = list(
            session.scalars(
                select(ReplayCompilationRecord).where(
                    ReplayCompilationRecord.batch_id == batch.batch_id
                )
            ).all()
        )
        source_run = self._run(session, source.producer_run_id)
        batch_matches = (
            batch.created_by == actor
            and batch.campaign_name == source_run.campaign_name
            and request.source.artifact_id == source.artifact_id
            and request.source.repository_version == source.repository_version
            and self._artifact_ref(batch) == source
            and batch.mode == CampaignMode.AI_REDTEAM.value
            and batch.purpose == ReplayPurpose.CONFIRMATION.value
            and batch.policy_version == KISA_CONFIRMATION_POLICY_VERSION
        )
        stored_item_ids = {item.item_id for item in items}
        compilation_item_ids = {compilation.item_id for compilation in compilations}
        current_compilation_counts = {
            item.item_id: sum(
                compilation.item_id == item.item_id
                and compilation.candidate_id == item.candidate_id
                and compilation.candidate_digest == item.candidate_digest
                and compilation.contract_digest == item.contract_digest
                and compilation.replay_run_id == item.replay_run_id
                and compilation.compilation_digest == item.compilation_digest
                and compilation.grant_digest == item.grant_digest
                for compilation in compilations
            )
            for item in items
        }
        if (
            not batch_matches
            or not items
            or [item.ordinal for item in items] != list(range(len(items)))
            or compilation_item_ids != stored_item_ids
            or any(count != 1 for count in current_compilation_counts.values())
        ):
            raise StateConflict(
                "Replay batch idempotency key was already used for different authority input"
            )
        return self._replay_batch_view(batch)

    @staticmethod
    def _run(session: Session, run_id: str, *, lock: bool = False) -> RunRecord:
        statement = select(RunRecord).where(RunRecord.run_id == run_id)
        if lock:
            statement = statement.with_for_update()
        run = session.scalar(statement)
        if run is None:
            raise ResourceNotFound("run not found")
        return run

    @staticmethod
    def _artifact(
        session: Session,
        locator: ArtifactLocator,
        *,
        lock: bool = False,
    ) -> ArtifactRecord:
        statement = select(ArtifactRecord).where(
            ArtifactRecord.artifact_id == locator.artifact_id,
            ArtifactRecord.repository_version == locator.repository_version,
        )
        if lock:
            statement = statement.with_for_update()
        artifact = session.scalar(statement)
        if artifact is None:
            raise ResourceNotFound("managed source Artifact not found")
        return artifact

    @staticmethod
    def _artifact_by_idempotency_key(
        session: Session,
        idempotency_key: str,
        *,
        lock: bool = False,
    ) -> ArtifactRecord | None:
        statement = select(ArtifactRecord).where(ArtifactRecord.idempotency_key == idempotency_key)
        if lock:
            statement = statement.with_for_update()
        return session.scalar(statement)

    @staticmethod
    def _job(session: Session, job_id: str, *, lock: bool = False) -> JobRecord:
        statement = select(JobRecord).where(JobRecord.job_id == job_id)
        if lock:
            statement = statement.with_for_update()
        job = session.scalar(statement)
        if job is None:
            raise ResourceNotFound("job not found")
        return job

    @staticmethod
    def _replay_batch(session: Session, batch_id: str, *, lock: bool = False) -> ReplayBatchRecord:
        statement = select(ReplayBatchRecord).where(ReplayBatchRecord.batch_id == batch_id)
        if lock:
            statement = statement.with_for_update()
        batch = session.scalar(statement)
        if batch is None:
            raise ResourceNotFound("Replay batch not found")
        return batch

    @staticmethod
    def _replay_item(session: Session, item_id: str, *, lock: bool = False) -> ReplayItemRecord:
        statement = select(ReplayItemRecord).where(ReplayItemRecord.item_id == item_id)
        if lock:
            statement = statement.with_for_update()
        item = session.scalar(statement)
        if item is None:
            raise ResourceNotFound("Replay item not found")
        return item

    @staticmethod
    def _replay_ticket(
        session: Session, ticket_id: str, *, lock: bool = False
    ) -> ReplayTicketRecord:
        statement = select(ReplayTicketRecord).where(ReplayTicketRecord.ticket_id == ticket_id)
        if lock:
            statement = statement.with_for_update()
        ticket = session.scalar(statement)
        if ticket is None:
            raise ResourceNotFound("Replay ticket not found")
        return ticket

    @staticmethod
    def _replay_ticket_for_job(
        session: Session, job_id: str, *, lock: bool = False
    ) -> ReplayTicketRecord:
        statement = select(ReplayTicketRecord).where(ReplayTicketRecord.job_id == job_id)
        if lock:
            statement = statement.with_for_update()
        ticket = session.scalar(statement)
        if ticket is None:
            raise StateConflict("internal Replay Job exists without its ticket")
        return ticket

    @staticmethod
    def _checkpoint(
        session: Session, checkpoint_id: str, *, lock: bool = False
    ) -> CheckpointRecord:
        statement = select(CheckpointRecord).where(CheckpointRecord.checkpoint_id == checkpoint_id)
        if lock:
            statement = statement.with_for_update()
        checkpoint = session.scalar(statement)
        if checkpoint is None:
            raise ResourceNotFound("checkpoint not found")
        return checkpoint

    @staticmethod
    def _approval(session: Session, approval_id: str, *, lock: bool = False) -> ApprovalRecord:
        statement = select(ApprovalRecord).where(ApprovalRecord.approval_id == approval_id)
        if lock:
            statement = statement.with_for_update()
        approval = session.scalar(statement)
        if approval is None:
            raise ResourceNotFound("approval not found")
        return approval

    def _event(
        self,
        session: Session,
        run: RunRecord,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
    ) -> EventRecord:
        event = EventRecord(
            event_id=f"event_{uuid4().hex}",
            run_id=run.run_id,
            sequence=self.repository.next_event_sequence(session, run.run_id),
            event_type=event_type,
            actor=actor,
            payload=payload,
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
            payload=payload,
            occurred_at=utc_now(),
        )
        session.add(event)
        session.flush()
        return event

    @staticmethod
    def _run_view(record: RunRecord) -> RunView:
        return RunView(
            run_id=record.run_id,
            campaign_name=record.campaign_name,
            state=RunState(record.state),
            input=record.input,
            current_checkpoint_id=record.current_checkpoint_id,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _run_summary_view(record: RunRecord) -> RunSummaryView:
        return RunSummaryView(
            run_id=record.run_id,
            campaign_name=record.campaign_name,
            state=RunState(record.state),
            current_checkpoint_id=record.current_checkpoint_id,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _job_view(record: JobRecord) -> JobView:
        return JobView(
            job_id=record.job_id,
            run_id=record.run_id,
            kind=record.kind,
            state=JobState(record.state),
            payload=record.payload,
            priority=record.priority,
            attempts=record.attempts,
            max_attempts=record.max_attempts,
            available_at=_aware(record.available_at),
            lease_owner=record.lease_owner,
            lease_expires_at=(_aware(record.lease_expires_at) if record.lease_expires_at else None),
            heartbeat_at=_aware(record.heartbeat_at) if record.heartbeat_at else None,
            result=record.result,
            error=record.error,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _artifact_ref(record: ReplayBatchRecord) -> ArtifactRef:
        try:
            return ArtifactRef(
                artifact_id=record.source_artifact_id,
                repository_version=record.source_repository_version,
                producer_run_id=record.source_run_id,
                media_type=record.source_media_type,
                schema_kind=record.source_schema_kind,
                byte_length=record.source_byte_length,
                content_digest=record.source_content_digest,
                run_id=record.source_artifact_run_id,
                integrity_root_digest=record.source_root_digest,
                created_by=record.source_created_by,
            )
        except ValidationError as exc:
            raise StateConflict("Replay batch Artifact metadata is invalid") from exc

    @staticmethod
    def _replay_batch_view(record: ReplayBatchRecord) -> ReplayBatchView:
        return ReplayBatchView(
            batch_id=record.batch_id,
            campaign_name=record.campaign_name,
            source=ControlPlaneService._artifact_ref(record),
            mode=CampaignMode(record.mode),
            purpose=ReplayPurpose(record.purpose),
            policy_version=record.policy_version,
            state=ReplayBatchState(record.state),
            cas_version=record.cas_version,
            created_by=record.created_by,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _replay_item_view(record: ReplayItemRecord) -> ReplayItemView:
        return ReplayItemView(
            item_id=record.item_id,
            batch_id=record.batch_id,
            replay_run_id=record.replay_run_id,
            state=ReplayItemState(record.state),
            candidate_id=record.candidate_id,
            candidate_digest=record.candidate_digest,
            contract_digest=record.contract_digest,
            compilation_digest=record.compilation_digest,
            grant_digest=record.grant_digest,
            required_attempts=record.required_attempts,
            max_attempts=record.max_attempts,
            attempts=record.attempts,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _replay_ticket_view(record: ReplayTicketRecord) -> ReplayTicketView:
        return ReplayTicketView(
            ticket_id=record.ticket_id,
            batch_id=record.batch_id,
            item_id=record.item_id,
            job_id=record.job_id,
            replay_run_id=record.replay_run_id,
            state=ReplayTicketState(record.state),
            attempt=record.attempt_number,
            fencing_value=record.fencing_value,
            executor_profile=record.executor_profile,
            claimed_by=record.claim_principal,
            lease_expires_at=(_aware(record.lease_expires_at) if record.lease_expires_at else None),
            created_at=_aware(record.issued_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def _replay_claim_view(
        *,
        job: JobRecord,
        batch: ReplayBatchRecord,
        item: ReplayItemRecord,
        ticket: ReplayTicketRecord,
        lease_token: str,
    ) -> ReplayClaimView:
        return ReplayClaimView(
            job=ControlPlaneService._job_view(job),
            batch=ControlPlaneService._replay_batch_view(batch),
            item=ControlPlaneService._replay_item_view(item),
            ticket=ControlPlaneService._replay_ticket_view(ticket),
            lease_token=lease_token,
        )

    @staticmethod
    def _checkpoint_view(record: CheckpointRecord) -> CheckpointView:
        state = record.payload.get("state")
        return CheckpointView(
            checkpoint_id=record.checkpoint_id,
            run_id=record.run_id,
            sequence=record.sequence,
            schema_version=record.schema_version,
            state=state if isinstance(state, dict) else {},
            pending_intent=ControlPlaneService._checkpoint_intent(record),
            payload_sha256=record.payload_sha256,
            signature=record.signature,
            key_id=record.key_id,
            created_at=_aware(record.created_at),
            claimed_at=_aware(record.claimed_at) if record.claimed_at else None,
            claimed_by=record.claimed_by,
            continuation_job_id=record.continuation_job_id,
        )

    @staticmethod
    def _approval_view(record: ApprovalRecord) -> ApprovalView:
        return ApprovalView(
            approval_id=record.approval_id,
            run_id=record.run_id,
            checkpoint_id=record.checkpoint_id,
            intent=ApprovalIntent(
                call_fingerprint=record.call_fingerprint,
                tool_id=record.tool_id,
                target=record.target,
                risk_tier=ToolRiskTier(record.risk_tier),
                expires_at=_aware(record.expires_at),
            ),
            state=ApprovalState(record.state),
            requested_by=record.requested_by,
            requested_at=_aware(record.requested_at),
            decided_by=record.decided_by,
            decided_at=_aware(record.decided_at) if record.decided_at else None,
            decision_reason=record.decision_reason,
            consumed_by=record.consumed_by,
            consumed_at=_aware(record.consumed_at) if record.consumed_at else None,
        )

    @staticmethod
    def _event_view(record: EventRecord) -> AuditEventView:
        return AuditEventView(
            event_id=record.event_id,
            run_id=record.run_id,
            sequence=record.sequence,
            event_type=record.event_type,
            actor=record.actor,
            payload=record.payload,
            occurred_at=_aware(record.occurred_at),
        )
