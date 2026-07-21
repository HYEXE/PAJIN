"""Replay batch planning and first-attempt issuance transactions."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
from uuid import uuid4

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from pajin.control_plane.artifacts import (
    ArtifactNotFound,
    ArtifactRepositoryError,
    ManagedArtifactRepository,
    ManagedArtifactSnapshot,
)
from pajin.control_plane.collaborator_hooks import ControlPlaneTransactionHooks
from pajin.control_plane.database import (
    ArtifactRecord,
    ControlPlaneRepository,
    JobRecord,
    ReplayBatchRecord,
    ReplayBudgetAccountRecord,
    ReplayBudgetReservationRecord,
    ReplayCompilationRecord,
    ReplayExecutionContextRecord,
    ReplayItemRecord,
    ReplayRateAccountRecord,
    ReplayRateReservationRecord,
    ReplayTicketRecord,
    ReplayToolPermitRecord,
    RunRecord,
)
from pajin.control_plane.errors import ResourceNotFound, StateConflict
from pajin.control_plane.kisa_derivation import (
    KISA_CONFIRMATION_POLICY_VERSION,
    DerivedKISAReplayBatch,
    DerivedKISAReplayItem,
)
from pajin.control_plane.models import (
    KISA_EXACT_REPLAY_EXECUTOR_PROFILE,
    ArtifactLocator,
    ArtifactRef,
    CreateReplayBatchRequest,
    InternalJobKind,
    JobState,
    ReplayBatchIssuanceView,
    ReplayBatchState,
    ReplayBatchView,
    ReplayExecutionContext,
    ReplayItemState,
    ReplayJobPayload,
    ReplayTicketState,
    RunState,
    canonical_replay_execution_context_bytes,
    job_submission_authority_digest,
    non_replayable_submission_authority_digest,
    replay_execution_component_digest,
    replay_execution_context_digest,
)
from pajin.control_plane.records import ControlPlaneRecords
from pajin.control_plane.replay_authority import (
    ReplayBindingAuthority,
    replay_issuance_lifecycle_is_exact,
    replay_rate_reservation_lifecycle_exact,
    require_exact_replay_account_permit_consumption,
    require_exact_replay_budget_ledger,
    require_fresh_issuance_derivation,
    trusted_fresh_issuance_compilation,
    trusted_replay_compilation,
)
from pajin.control_plane.view_mapper import ControlPlaneViewMapper
from pajin.domain.models import CampaignMode
from pajin.domain.replay import ReplayCompilation, ReplayPurpose
from pajin.tools.ai import AIChatProbeTool

_ACTIVE_REPLAY_TICKET_STATES = frozenset(
    {ReplayTicketState.ISSUED.value, ReplayTicketState.CLAIMED.value}
)

type ReplayBindingVerifier = Callable[
    [Session, JobRecord, ReplayTicketRecord, ReplayItemRecord, ReplayBatchRecord],
    ReplayBindingAuthority,
]


class ReplayBatchDeriver(Protocol):
    """Derive fresh Replay authority from an immutable managed source."""

    def __call__(
        self,
        *,
        source_root: Path,
        artifact_ref: ArtifactRef,
    ) -> DerivedKISAReplayBatch: ...


@dataclass(frozen=True, slots=True)
class ReplayIssuanceHooks:
    """Small boundary to service-owned audit and binding primitives."""

    transaction: ControlPlaneTransactionHooks
    binding_verifier: ReplayBindingVerifier
    deriver: ReplayBatchDeriver


@dataclass(slots=True)
class _ReplayIssuanceGraph:
    """One issued batch reconstructed under its lifecycle locks."""

    batch: ReplayBatchRecord
    items: list[ReplayItemRecord]
    tickets: list[ReplayTicketRecord]
    jobs_by_id: dict[str, JobRecord]
    runs_by_id: dict[str, RunRecord]


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class ReplayIssuanceService:
    """Own Replay planning and atomic first-attempt issuance."""

    def __init__(
        self,
        repository: ControlPlaneRepository,
        records: ControlPlaneRecords,
        views: ControlPlaneViewMapper,
        artifact_repository: ManagedArtifactRepository | None,
        hooks: ReplayIssuanceHooks,
    ) -> None:
        self.repository = repository
        self._records = records
        self._views = views
        self._artifact_repository = artifact_repository
        self._hooks = hooks

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
                source = self._views.replay_source(existing)
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
                artifact = self._records.artifact(session, stored_locator)
            else:
                artifact = self._records.artifact(session, request.source)
                source = self._views.artifact(artifact)
            storage_key = artifact.storage_key
        snapshot = self._resolve_managed_artifact(
            artifact_repository,
            source,
            expected_storage_key=storage_key,
        )
        derived: DerivedKISAReplayBatch | None = None
        if existing is None:
            try:
                derived = self._hooks.deriver(
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
                artifact = self._records.artifact(session, request.source, lock=True)
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

                source_run = self._records.run(session, source.producer_run_id, lock=True)
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
                now = self._hooks.transaction.clock()
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
                self._hooks.transaction.replay_event_writer(
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
                        submission_authority_digest=(
                            non_replayable_submission_authority_digest(
                                run_id=replay_run_id,
                                authority_kind="replay-plan",
                            )
                        ),
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
                    self._hooks.transaction.event_writer(
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
                    self._hooks.transaction.replay_event_writer(
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
                return self._views.replay_batch(batch)
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

    def issue_replay_batch(
        self,
        batch_id: str,
        *,
        actor: str,
    ) -> ReplayBatchIssuanceView:
        """Atomically reserve and issue every first attempt of one planned batch."""

        artifact_repository = self._require_artifact_repository()
        with self.repository.transaction() as session:
            batch = self._records.replay_batch(session, batch_id)
            if batch.state != ReplayBatchState.PLANNED.value:
                return self._existing_replay_issuance(session, batch)
            source = self._views.replay_source(batch)
            locator = ArtifactLocator(
                artifact_id=source.artifact_id,
                repository_version=source.repository_version,
            )
            artifact = self._records.artifact(session, locator)
            self._require_artifact_snapshot(
                artifact,
                source,
                storage_key=artifact.storage_key,
            )
            storage_key = artifact.storage_key

        snapshot = self._resolve_managed_artifact(
            artifact_repository,
            source,
            expected_storage_key=storage_key,
        )
        try:
            derived = self._hooks.deriver(
                source_root=snapshot.path,
                artifact_ref=source,
            )
        except (OSError, ValueError) as exc:
            raise StateConflict("managed source is not eligible for KISA Replay issuance") from exc
        snapshot = self._resolve_managed_artifact(
            artifact_repository,
            source,
            expected_storage_key=storage_key,
        )

        with self.transaction(artifact_repository) as (session, reserved_staging_ids):
            if self.repository.dialect_name == "sqlite":
                # BEGIN is deferred on SQLite. Make the first statement a conditional
                # write so concurrent issuers serialize before either creates a stale
                # read snapshot and attempts a reader-to-writer upgrade.
                acquired_batch_id = session.scalar(
                    update(ReplayBatchRecord)
                    .where(
                        ReplayBatchRecord.batch_id == batch_id,
                        ReplayBatchRecord.state == ReplayBatchState.PLANNED.value,
                    )
                    .values(updated_at=ReplayBatchRecord.updated_at)
                    .returning(ReplayBatchRecord.batch_id)
                )
                if acquired_batch_id is None:
                    return self._existing_replay_issuance(
                        session,
                        self._records.replay_batch(session, batch_id),
                    )
            # The immutable Artifact row and source Run serialize account bootstrap.
            # Existing rows follow item -> batch -> Run, then the shared capacity
            # layer follows budget account -> rate account -> budget reservations
            # -> rate reservations. Job/ticket rows do not exist before issuance.
            artifact = self._records.artifact(session, locator, lock=True)
            self._require_artifact_snapshot(
                artifact,
                source,
                storage_key=snapshot.storage_key,
            )
            locked_items = list(
                session.scalars(
                    select(ReplayItemRecord)
                    .where(ReplayItemRecord.batch_id == batch_id)
                    .order_by(ReplayItemRecord.item_id)
                    .with_for_update()
                ).all()
            )
            items = sorted(
                locked_items,
                key=lambda item: (item.ordinal, item.item_id),
            )
            batch = self._records.replay_batch(session, batch_id, lock=True)
            if batch.state != ReplayBatchState.PLANNED.value:
                return self._existing_replay_issuance(
                    session,
                    batch,
                    locked_items=items,
                )
            source_run = self._records.run(session, batch.source_run_id, lock=True)
            self._require_run_state(source_run, RunState.COMPLETED)
            require_fresh_issuance_derivation(
                batch,
                items,
                derived=derived,
                source=source,
            )

            planning_compilations = list(
                session.scalars(
                    select(ReplayCompilationRecord)
                    .where(ReplayCompilationRecord.batch_id == batch.batch_id)
                    .order_by(
                        ReplayCompilationRecord.item_id,
                        ReplayCompilationRecord.created_at,
                        ReplayCompilationRecord.compilation_id,
                    )
                ).all()
            )
            if len(planning_compilations) != len(items):
                raise StateConflict("planned Replay batch has an incomplete compilation proof")
            planning_by_item = {
                compilation.item_id: compilation for compilation in planning_compilations
            }
            if len(planning_by_item) != len(items):
                raise StateConflict("planned Replay compilation proof is ambiguous")
            for item in items:
                planning = planning_by_item.get(item.item_id)
                if planning is None or not (
                    planning.batch_id == batch.batch_id
                    and planning.replay_run_id == item.replay_run_id
                    and planning.candidate_id == item.candidate_id
                    and planning.candidate_digest == item.candidate_digest
                    and planning.contract_digest == item.contract_digest
                    and planning.compilation_digest == item.compilation_digest
                    and planning.grant_digest == item.grant_digest
                ):
                    raise StateConflict(
                        "planned Replay compilation pointer changed before issuance"
                    )
                trusted_replay_compilation(planning)

            now = self._hooks.transaction.clock()
            trusted_fresh = [
                trusted_fresh_issuance_compilation(admitted, now=now) for admitted in derived.items
            ]
            budget_account, rate_account = self._reserve_replay_capacity(
                session,
                batch=batch,
                derived=derived,
                observed_at=_aware(artifact.created_at),
                now=now,
            )

            issued_tickets: list[ReplayTicketRecord] = []
            for item, admitted, trusted in zip(items, derived.items, trusted_fresh, strict=True):
                issued_tickets.append(
                    self._issue_first_replay_attempt(
                        session,
                        artifact_repository=artifact_repository,
                        reserved_staging_ids=reserved_staging_ids,
                        batch=batch,
                        item=item,
                        admitted=admitted,
                        trusted=trusted,
                        source=source,
                        derived=derived,
                        budget_account=budget_account,
                        rate_account=rate_account,
                        actor=actor,
                        now=now,
                    )
                )

            batch.state = ReplayBatchState.RUNNING.value
            batch.cas_version += 1
            batch.updated_at = now
            self._hooks.transaction.replay_event_writer(
                session,
                batch,
                "replay.batch.issued",
                actor,
                {
                    "itemCount": len(items),
                    "attempt": 1,
                    "budgetAccountId": budget_account.budget_account_id,
                    "rateAccountId": rate_account.rate_account_id,
                    "reservedToolCalls": derived.required_tool_calls,
                    "reservedRequestUnits": derived.required_request_units,
                },
                run_id=batch.source_run_id,
            )
            return ReplayBatchIssuanceView(
                batch=self._views.replay_batch(batch),
                items=[self._views.replay_item(item) for item in items],
                tickets=[self._views.replay_ticket(ticket) for ticket in issued_tickets],
            )

    def _issue_first_replay_attempt(
        self,
        session: Session,
        *,
        artifact_repository: ManagedArtifactRepository,
        reserved_staging_ids: list[str],
        batch: ReplayBatchRecord,
        item: ReplayItemRecord,
        admitted: DerivedKISAReplayItem,
        trusted: ReplayCompilation,
        source: ArtifactRef,
        derived: DerivedKISAReplayBatch,
        budget_account: ReplayBudgetAccountRecord,
        rate_account: ReplayRateAccountRecord,
        actor: str,
        now: datetime,
    ) -> ReplayTicketRecord:
        """Create one first-attempt authority graph in the issuance transaction."""

        compilation_id = f"replay-compilation_{uuid4().hex}"
        execution_context_id = f"replay-context_{uuid4().hex}"
        output_staging_id = f"stage_{uuid4().hex}"
        reserved_staging_ids.append(output_staging_id)
        artifact_repository.reserve_staging(output_staging_id)
        budget_reservation_id = f"budget-reservation_{uuid4().hex}"
        rate_reservation_id = f"rate-reservation_{uuid4().hex}"
        ticket_id = f"replay-ticket_{uuid4().hex}"
        job_id = f"job_{uuid4().hex}"
        attempt = 1
        fencing_value = 1
        rate_expires_at = now + timedelta(seconds=rate_account.window_seconds)
        ticket_expires_at = min(
            _aware(trusted.spec.expires_at),
            _aware(trusted.grant.expires_at),
            rate_expires_at,
        )
        if ticket_expires_at <= now:
            raise StateConflict("fresh Replay issuance authority expired before commit")

        execution_context = ReplayExecutionContext(
            context_id=execution_context_id,
            batch_id=batch.batch_id,
            item_id=item.item_id,
            compilation_id=compilation_id,
            replay_run_id=admitted.replay_run_id,
            source=source,
            source_root_digest=derived.source_root_digest,
            campaign=derived.campaign,
            campaign_digest=replay_execution_component_digest(derived.campaign),
            scenario=admitted.scenario,
            scenario_digest=replay_execution_component_digest(admitted.scenario),
            tool_spec=AIChatProbeTool.spec,
            tool_spec_digest=replay_execution_component_digest(AIChatProbeTool.spec),
            policy_version=derived.policy_version,
            required_executor_profile=KISA_EXACT_REPLAY_EXECUTOR_PROFILE,
            secret_policy="forbidden",
            secret_lease_ids=(),
            output_staging_id=output_staging_id,
            created_at=now,
        )
        canonical_execution_context = canonical_replay_execution_context_bytes(execution_context)
        execution_context_digest = replay_execution_context_digest(execution_context)
        payload = ReplayJobPayload(
            batch_id=batch.batch_id,
            item_id=item.item_id,
            ticket_id=ticket_id,
            compilation_id=compilation_id,
            execution_context_id=execution_context.context_id,
            execution_context_digest=execution_context_digest,
            budget_reservation_id=budget_reservation_id,
            rate_reservation_id=rate_reservation_id,
            replay_run_id=admitted.replay_run_id,
            source=source,
            mode=derived.mode,
            purpose=derived.purpose,
            policy_version=derived.policy_version,
            candidate_id=item.candidate_id,
            candidate_digest=item.candidate_digest,
            contract_digest=item.contract_digest,
            compilation_digest=admitted.compilation_digest,
            grant_digest=admitted.grant_digest,
            attempt=attempt,
            fencing_value=fencing_value,
        )
        replay_run = RunRecord(
            run_id=admitted.replay_run_id,
            campaign_name=batch.campaign_name,
            state=RunState.QUEUED.value,
            input={"replay": payload.model_dump(mode="json")},
            submission_key=f"replay-attempt:{item.item_id}:{attempt}",
            submission_authority_digest=non_replayable_submission_authority_digest(
                run_id=admitted.replay_run_id,
                authority_kind="replay-attempt",
            ),
            current_checkpoint_id=None,
            created_at=now,
            updated_at=now,
        )
        session.add(replay_run)
        session.flush()
        compilation = ReplayCompilationRecord(
            compilation_id=compilation_id,
            item_id=item.item_id,
            batch_id=batch.batch_id,
            candidate_id=item.candidate_id,
            replay_run_id=replay_run.run_id,
            candidate_digest=item.candidate_digest,
            contract_digest=item.contract_digest,
            compilation_digest=admitted.compilation_digest,
            grant_digest=admitted.grant_digest,
            canonical_compilation=admitted.canonical_compilation,
            byte_length=len(admitted.canonical_compilation),
            created_at=now,
        )
        session.add(compilation)
        session.flush()
        execution_context_record = ReplayExecutionContextRecord(
            context_id=execution_context.context_id,
            compilation_id=compilation.compilation_id,
            item_id=item.item_id,
            batch_id=batch.batch_id,
            replay_run_id=replay_run.run_id,
            compilation_digest=admitted.compilation_digest,
            grant_digest=admitted.grant_digest,
            context_digest=execution_context_digest,
            canonical_context=canonical_execution_context,
            byte_length=len(canonical_execution_context),
            required_executor_profile=execution_context.required_executor_profile,
            output_staging_id=execution_context.output_staging_id,
            created_at=now,
        )
        session.add(execution_context_record)
        session.flush()
        budget_reservation = ReplayBudgetReservationRecord(
            budget_reservation_id=budget_reservation_id,
            budget_account_id=budget_account.budget_account_id,
            batch_id=batch.batch_id,
            item_id=item.item_id,
            attempt_number=attempt,
            compilation_id=compilation.compilation_id,
            total_calls=admitted.contract.repetitions,
            consumed_calls=0,
            released_calls=0,
            state="active",
            created_at=now,
            updated_at=now,
            released_at=None,
        )
        rate_reservation = ReplayRateReservationRecord(
            rate_reservation_id=rate_reservation_id,
            rate_account_id=rate_account.rate_account_id,
            batch_id=batch.batch_id,
            item_id=item.item_id,
            attempt_number=attempt,
            compilation_id=compilation.compilation_id,
            total_request_units=admitted.required_request_units,
            consumed_request_units=0,
            released_request_units=0,
            state="active",
            reserved_at=now,
            expires_at=rate_expires_at,
            updated_at=now,
            released_at=None,
        )
        session.add_all([budget_reservation, rate_reservation])
        session.flush()
        job_payload = payload.model_dump(mode="json")
        job_idempotency_key = f"replay:{item.item_id}:{attempt}"
        job = JobRecord(
            job_id=job_id,
            run_id=replay_run.run_id,
            kind=InternalJobKind.REPLAY.value,
            state=JobState.QUEUED.value,
            payload=job_payload,
            priority=0,
            attempts=0,
            max_attempts=1,
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
                run_id=replay_run.run_id,
                job_kind=InternalJobKind.REPLAY.value,
                payload=job_payload,
                max_attempts=1,
                idempotency_key=job_idempotency_key,
            ),
        )
        session.add(job)
        session.flush()
        ticket = ReplayTicketRecord(
            ticket_id=ticket_id,
            batch_id=batch.batch_id,
            item_id=item.item_id,
            job_id=job.job_id,
            compilation_id=compilation.compilation_id,
            budget_reservation_id=budget_reservation.budget_reservation_id,
            rate_reservation_id=rate_reservation.rate_reservation_id,
            replay_run_id=replay_run.run_id,
            attempt_number=attempt,
            fencing_value=fencing_value,
            state=ReplayTicketState.ISSUED.value,
            grant_digest=admitted.grant_digest,
            source_root_digest=batch.source_root_digest,
            compilation_digest=admitted.compilation_digest,
            executor_profile=None,
            claim_principal=None,
            lease_token_hash=None,
            result_digest=None,
            abandon_reason=None,
            issued_at=now,
            expires_at=ticket_expires_at,
            claimed_at=None,
            lease_expires_at=None,
            finalized_at=None,
            abandoned_at=None,
            updated_at=now,
        )
        session.add(ticket)

        item.replay_run_id = replay_run.run_id
        item.compilation_digest = admitted.compilation_digest
        item.grant_digest = admitted.grant_digest
        item.state = ReplayItemState.QUEUED.value
        item.attempts = attempt
        item.updated_at = now
        session.flush()
        self._hooks.transaction.event_writer(
            session,
            replay_run,
            "run.submitted",
            actor,
            {
                "campaignName": batch.campaign_name,
                "jobId": job.job_id,
                "jobKind": InternalJobKind.REPLAY.value,
                "replayBatchId": batch.batch_id,
                "replayItemId": item.item_id,
                "replayTicketId": ticket.ticket_id,
                "compilationId": compilation.compilation_id,
            },
        )
        self._hooks.transaction.replay_event_writer(
            session,
            batch,
            "replay.compilation.derived",
            actor,
            {
                "attempt": attempt,
                "compilationId": compilation.compilation_id,
                "candidateDigest": item.candidate_digest,
                "contractDigest": item.contract_digest,
                "compilationDigest": item.compilation_digest,
                "grantDigest": item.grant_digest,
            },
            item=item,
            run_id=replay_run.run_id,
        )
        self._hooks.transaction.replay_event_writer(
            session,
            batch,
            "replay.execution-context.derived",
            actor,
            {
                "attempt": attempt,
                "compilationId": compilation.compilation_id,
                "executionContextId": execution_context.context_id,
                "executionContextDigest": execution_context_digest,
                "requiredExecutorProfile": execution_context.required_executor_profile,
                "outputStagingId": execution_context.output_staging_id,
            },
            item=item,
            run_id=replay_run.run_id,
        )
        self._hooks.transaction.replay_event_writer(
            session,
            batch,
            "replay.ticket.issued",
            actor,
            {
                "attempt": attempt,
                "fencingValue": fencing_value,
                "compilationId": compilation.compilation_id,
                "budgetReservationId": budget_reservation.budget_reservation_id,
                "rateReservationId": rate_reservation.rate_reservation_id,
                "compilationDigest": item.compilation_digest,
                "expiresAt": ticket.expires_at.isoformat(),
            },
            item=item,
            ticket=ticket,
            job=job,
            run_id=replay_run.run_id,
        )
        return ticket

    @contextmanager
    def transaction(
        self,
        artifact_repository: ManagedArtifactRepository,
    ) -> Iterator[tuple[Session, list[str]]]:
        """Release empty capabilities after proven pre-commit transaction-body failure."""

        reserved_staging_ids: list[str] = []
        body_failed = False
        try:
            with self.repository.transaction() as session:
                try:
                    yield session, reserved_staging_ids
                except BaseException:
                    body_failed = True
                    raise
        except BaseException:
            if body_failed:
                for staging_id in reversed(reserved_staging_ids):
                    # Preserve the transaction failure. Empty-only release fails
                    # closed if a Worker managed to place output in the capability.
                    with suppress(ArtifactRepositoryError):
                        artifact_repository.release_staging_reservation(staging_id)
            raise

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
        source_run = self._records.run(session, source.producer_run_id)
        batch_matches = (
            batch.created_by == actor
            and batch.campaign_name == source_run.campaign_name
            and request.source.artifact_id == source.artifact_id
            and request.source.repository_version == source.repository_version
            and self._views.replay_source(batch) == source
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
        return self._views.replay_batch(batch)

    def _existing_replay_issuance(
        self,
        session: Session,
        batch: ReplayBatchRecord,
        *,
        locked_items: list[ReplayItemRecord] | None = None,
    ) -> ReplayBatchIssuanceView:
        """Return only a complete, exact current issuance graph after response loss."""

        graph = self._reconstruct_replay_issuance_graph(
            session,
            batch,
            locked_items=locked_items,
        )
        current_tickets = self._require_exact_replay_issuance_graph(session, graph)
        return ReplayBatchIssuanceView(
            batch=self._views.replay_batch(graph.batch),
            items=[self._views.replay_item(item) for item in graph.items],
            tickets=[self._views.replay_ticket(ticket) for ticket in current_tickets],
        )

    def _reconstruct_replay_issuance_graph(
        self,
        session: Session,
        batch: ReplayBatchRecord,
        *,
        locked_items: list[ReplayItemRecord] | None,
    ) -> _ReplayIssuanceGraph:
        if locked_items is not None:
            return self._read_owned_replay_issuance_graph(session, batch, locked_items)
        return self._lock_replay_issuance_graph(session, batch.batch_id)

    def _lock_replay_issuance_graph(
        self,
        session: Session,
        batch_id: str,
    ) -> _ReplayIssuanceGraph:
        if self.repository.dialect_name == "sqlite":
            # SQLite has no row-level FOR UPDATE. Acquire its writer lock before
            # reconstruction so every following SELECT observes one lifecycle.
            session.execute(
                update(ReplayBatchRecord)
                .where(ReplayBatchRecord.batch_id == batch_id)
                .values(updated_at=ReplayBatchRecord.updated_at)
            )
        discovered_job_ids = sorted(
            session.scalars(
                select(ReplayTicketRecord.job_id).where(ReplayTicketRecord.batch_id == batch_id)
            ).all()
        )
        if not discovered_job_ids:
            raise StateConflict("issued Replay batch has no Job authority graph")
        jobs = list(
            session.scalars(
                select(JobRecord)
                .where(JobRecord.job_id.in_(discovered_job_ids))
                .order_by(JobRecord.job_id)
                .with_for_update()
            ).all()
        )
        if [job.job_id for job in jobs] != discovered_job_ids:
            raise StateConflict("issued Replay Job authority graph changed concurrently")
        tickets = list(
            session.scalars(
                select(ReplayTicketRecord)
                .where(ReplayTicketRecord.batch_id == batch_id)
                .order_by(ReplayTicketRecord.ticket_id)
                .with_for_update()
            ).all()
        )
        if sorted(ticket.job_id for ticket in tickets) != discovered_job_ids:
            raise StateConflict("issued Replay ticket authority graph changed concurrently")
        item_rows = list(
            session.scalars(
                select(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == batch_id)
                .order_by(ReplayItemRecord.item_id)
                .with_for_update()
            ).all()
        )
        batch = self._records.replay_batch(session, batch_id, lock=True)
        session.refresh(batch)
        run_ids = sorted({ticket.replay_run_id for ticket in tickets})
        runs = list(
            session.scalars(
                select(RunRecord)
                .where(RunRecord.run_id.in_(run_ids))
                .order_by(RunRecord.run_id)
                .with_for_update()
            ).all()
        )
        if [run.run_id for run in runs] != run_ids:
            raise StateConflict("issued Replay Run authority graph changed concurrently")
        return _ReplayIssuanceGraph(
            batch=batch,
            items=sorted(item_rows, key=lambda item: (item.ordinal, item.item_id)),
            tickets=tickets,
            jobs_by_id={job.job_id: job for job in jobs},
            runs_by_id={run.run_id: run for run in runs},
        )

    def _read_owned_replay_issuance_graph(
        self,
        session: Session,
        batch: ReplayBatchRecord,
        locked_items: list[ReplayItemRecord],
    ) -> _ReplayIssuanceGraph:
        # A concurrent issuer loser already owns every item and the batch. All
        # lifecycle writers need an item lock before mutation, so committed
        # Job/ticket/Run state cannot change until this transaction returns.
        tickets = list(
            session.scalars(
                select(ReplayTicketRecord)
                .where(ReplayTicketRecord.batch_id == batch.batch_id)
                .order_by(ReplayTicketRecord.ticket_id)
            ).all()
        )
        job_ids = sorted({ticket.job_id for ticket in tickets})
        jobs = list(
            session.scalars(
                select(JobRecord).where(JobRecord.job_id.in_(job_ids)).order_by(JobRecord.job_id)
            ).all()
        )
        run_ids = sorted({ticket.replay_run_id for ticket in tickets})
        runs = list(
            session.scalars(
                select(RunRecord).where(RunRecord.run_id.in_(run_ids)).order_by(RunRecord.run_id)
            ).all()
        )
        return _ReplayIssuanceGraph(
            batch=batch,
            items=sorted(locked_items, key=lambda item: (item.ordinal, item.item_id)),
            tickets=tickets,
            jobs_by_id={job.job_id: job for job in jobs},
            runs_by_id={run.run_id: run for run in runs},
        )

    def _require_exact_replay_issuance_graph(
        self,
        session: Session,
        graph: _ReplayIssuanceGraph,
    ) -> list[ReplayTicketRecord]:
        if graph.batch.state != ReplayBatchState.RUNNING.value:
            raise StateConflict(f"Replay batch in {graph.batch.state} state cannot be issued")
        if not graph.items or [item.ordinal for item in graph.items] != list(
            range(len(graph.items))
        ):
            raise StateConflict("issued Replay batch has an invalid item set")
        return [
            self._require_exact_replay_issuance_item(session, graph, item) for item in graph.items
        ]

    def _require_exact_replay_issuance_item(
        self,
        session: Session,
        graph: _ReplayIssuanceGraph,
        item: ReplayItemRecord,
    ) -> ReplayTicketRecord:
        matches = [
            ticket
            for ticket in graph.tickets
            if ticket.item_id == item.item_id and ticket.attempt_number == item.attempts
        ]
        active = [
            ticket
            for ticket in graph.tickets
            if ticket.item_id == item.item_id and ticket.state in _ACTIVE_REPLAY_TICKET_STATES
        ]
        if (
            item.attempts != 1
            or item.state not in {ReplayItemState.QUEUED.value, ReplayItemState.RUNNING.value}
            or len(matches) != 1
            or active != matches
        ):
            raise StateConflict("issued Replay batch has no exact current attempt graph")
        ticket = matches[0]
        job = graph.jobs_by_id.get(ticket.job_id)
        run = graph.runs_by_id.get(ticket.replay_run_id)
        if job is None or run is None:
            raise StateConflict("issued Replay attempt graph is incomplete")
        self._hooks.binding_verifier(session, job, ticket, item, graph.batch)
        if not replay_issuance_lifecycle_is_exact(job, ticket, item, run):
            raise StateConflict("issued Replay attempt lifecycle is inconsistent")
        return ticket

    def _reserve_replay_capacity(
        self,
        session: Session,
        *,
        batch: ReplayBatchRecord,
        derived: DerivedKISAReplayBatch,
        observed_at: datetime,
        now: datetime,
    ) -> tuple[ReplayBudgetAccountRecord, ReplayRateAccountRecord]:
        """Lock accounts before reservations and reserve the complete first attempt.

        Every writer follows the same capacity-layer order: budget account, rate
        account, budget reservations, then rate reservations. The earlier Replay
        graph is locked Job -> ticket -> item -> batch -> Run when those rows exist.
        """

        budget_account = session.scalar(
            select(ReplayBudgetAccountRecord)
            .where(ReplayBudgetAccountRecord.source_run_id == batch.source_run_id)
            .with_for_update()
        )
        if budget_account is None:
            budget_account = ReplayBudgetAccountRecord(
                budget_account_id=f"replay-budget-account_{uuid4().hex}",
                source_run_id=batch.source_run_id,
                source_root_digest=batch.source_root_digest,
                campaign_name=batch.campaign_name,
                budget_digest=derived.budget_digest,
                baseline_used_calls=derived.used_tool_calls,
                max_tool_calls=derived.max_tool_calls,
                reserved_calls=0,
                consumed_calls=0,
                released_calls=0,
                cas_version=1,
                created_at=now,
                updated_at=now,
            )
            session.add(budget_account)
            session.flush()
        elif not (
            budget_account.source_root_digest == batch.source_root_digest
            and budget_account.campaign_name == batch.campaign_name
            and budget_account.budget_digest == derived.budget_digest
            and budget_account.baseline_used_calls == derived.used_tool_calls
            and budget_account.max_tool_calls == derived.max_tool_calls
        ):
            raise StateConflict("durable Replay budget account differs from the sealed source")

        rate_account = session.scalar(
            select(ReplayRateAccountRecord)
            .where(ReplayRateAccountRecord.source_run_id == batch.source_run_id)
            .with_for_update()
        )
        if rate_account is None:
            rate_account = ReplayRateAccountRecord(
                rate_account_id=f"replay-rate-account_{uuid4().hex}",
                source_run_id=batch.source_run_id,
                source_root_digest=batch.source_root_digest,
                campaign_name=batch.campaign_name,
                rate_limits_digest=derived.rate_limits_digest,
                ledger_id=derived.rate_ledger_id,
                max_requests_per_minute=derived.max_requests_per_minute,
                observed_request_units=derived.observed_campaign_request_units,
                observed_at=observed_at,
                window_seconds=60,
                cas_version=1,
                created_at=now,
                updated_at=now,
            )
            session.add(rate_account)
            session.flush()
        elif not (
            rate_account.source_root_digest == batch.source_root_digest
            and rate_account.campaign_name == batch.campaign_name
            and rate_account.rate_limits_digest == derived.rate_limits_digest
            and rate_account.ledger_id == derived.rate_ledger_id
            and rate_account.max_requests_per_minute == derived.max_requests_per_minute
            and rate_account.observed_request_units == derived.observed_campaign_request_units
            and _aware(rate_account.observed_at) == observed_at
            and rate_account.window_seconds == 60
        ):
            raise StateConflict("durable Replay rate account differs from the sealed source")

        budget_reservations = list(
            session.scalars(
                select(ReplayBudgetReservationRecord)
                .where(
                    ReplayBudgetReservationRecord.budget_account_id
                    == budget_account.budget_account_id
                )
                .order_by(ReplayBudgetReservationRecord.budget_reservation_id)
                .with_for_update()
            ).all()
        )
        require_exact_replay_budget_ledger(
            budget_account,
            budget_reservations,
        )
        total_after_reservation = (
            budget_account.baseline_used_calls
            + budget_account.reserved_calls
            + budget_account.consumed_calls
            + derived.required_tool_calls
        )
        if total_after_reservation > budget_account.max_tool_calls:
            raise StateConflict("durable Replay budget reservation exceeds Campaign capacity")

        rate_reservations = list(
            session.scalars(
                select(ReplayRateReservationRecord)
                .where(ReplayRateReservationRecord.rate_account_id == rate_account.rate_account_id)
                .order_by(ReplayRateReservationRecord.rate_reservation_id)
                .with_for_update()
            ).all()
        )
        if any(
            not replay_rate_reservation_lifecycle_exact(reservation)
            for reservation in rate_reservations
        ):
            raise StateConflict("durable Replay rate reservation ledger is inconsistent")
        require_exact_replay_account_permit_consumption(
            session,
            budget_reservations=budget_reservations,
            rate_reservations=rate_reservations,
        )
        if rate_account.max_requests_per_minute is not None:
            baseline_units = (
                rate_account.observed_request_units
                if now
                < _aware(rate_account.observed_at) + timedelta(seconds=rate_account.window_seconds)
                else 0
            )
            reserved_units = sum(
                reservation.total_request_units
                - reservation.consumed_request_units
                - reservation.released_request_units
                for reservation in rate_reservations
                if _aware(reservation.expires_at) > now
            )
            active_permit_units = int(
                session.scalar(
                    select(func.coalesce(func.sum(ReplayToolPermitRecord.request_units), 0))
                    .join(
                        ReplayRateReservationRecord,
                        ReplayRateReservationRecord.rate_reservation_id
                        == ReplayToolPermitRecord.rate_reservation_id,
                    )
                    .where(
                        ReplayRateReservationRecord.rate_account_id == rate_account.rate_account_id,
                        ReplayToolPermitRecord.rate_window_expires_at > now,
                    )
                )
                or 0
            )
            if (
                baseline_units
                + reserved_units
                + active_permit_units
                + derived.required_request_units
                > rate_account.max_requests_per_minute
            ):
                raise StateConflict("durable Replay rate reservation exceeds Campaign capacity")

        budget_account.reserved_calls += derived.required_tool_calls
        budget_account.cas_version += 1
        budget_account.updated_at = now
        rate_account.cas_version += 1
        rate_account.updated_at = now
        return budget_account, rate_account

    def _require_artifact_repository(self) -> ManagedArtifactRepository:
        if self._artifact_repository is None:
            raise StateConflict("managed Artifact repository is not configured")
        return self._artifact_repository

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
    def _require_run_state(run: RunRecord, expected: RunState) -> None:
        if run.state == expected.value:
            return
        if run.state == RunState.CANCELLED.value:
            raise StateConflict("run has been cancelled")
        raise StateConflict(f"run must be {expected.value}, not {run.state}")
