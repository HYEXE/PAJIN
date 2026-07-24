"""Pure record-to-API view mapping for the Control Plane facade."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import ValidationError

from pajin.control_plane.artifact_transfer import PortableArtifactTransportReceipt
from pajin.control_plane.database import (
    ApprovalRecord,
    ArtifactRecord,
    CheckpointRecord,
    EventRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayClaimBindingRecord,
    ReplayFinalizationRecord,
    ReplayItemRecord,
    ReplayProjectionRecord,
    ReplayTicketRecord,
    ReplayToolPermitRecord,
    RunRecord,
)
from pajin.control_plane.errors import StateConflict
from pajin.control_plane.execution_attestation import ExecutorExecutionAttestation
from pajin.control_plane.models import (
    ApprovalIntent,
    ApprovalState,
    ApprovalView,
    ArtifactRef,
    AuditEventView,
    CheckpointView,
    InternalJobKind,
    JobKind,
    JobState,
    JobView,
    ReplayBatchState,
    ReplayBatchView,
    ReplayClaimProjectionInputAuthority,
    ReplayExecutionClaimView,
    ReplayExecutionContext,
    ReplayFinalizationView,
    ReplayItemState,
    ReplayItemView,
    ReplayProjectionInputAuthority,
    ReplayProjectionView,
    ReplayRetestProjectionInputAuthority,
    ReplayTicketState,
    ReplayTicketView,
    ReplayToolPermitView,
    RunState,
    RunSummaryView,
    RunView,
)
from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.domain.replay import ReplayClaimBinding, ReplayCompilation, ReplayPurpose
from pajin.domain.validation import ValidationDecision
from pajin.replay.tickets import replay_context_digest
from pajin.target_attestation import (
    TargetExecutionVerificationSummary,
    derive_target_execution_challenge,
)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class ControlPlaneViewMapper:
    """Build immutable public views while checking cross-record presentation authority."""

    @staticmethod
    def run(record: RunRecord) -> RunView:
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
    def run_summary(record: RunRecord) -> RunSummaryView:
        return RunSummaryView(
            run_id=record.run_id,
            campaign_name=record.campaign_name,
            state=RunState(record.state),
            current_checkpoint_id=record.current_checkpoint_id,
            created_at=_aware(record.created_at),
            updated_at=_aware(record.updated_at),
        )

    @staticmethod
    def job(record: JobRecord) -> JobView:
        return JobView(
            job_id=record.job_id,
            run_id=record.run_id,
            kind=(
                InternalJobKind(record.kind)
                if record.kind == InternalJobKind.REPLAY.value
                else JobKind(record.kind)
            ),
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
    def artifact(record: ArtifactRecord) -> ArtifactRef:
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
    def replay_source(record: ReplayBatchRecord) -> ArtifactRef:
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

    @classmethod
    def replay_batch(
        cls,
        record: ReplayBatchRecord,
        *,
        retest_artifact: ArtifactRecord | None = None,
    ) -> ReplayBatchView:
        return ReplayBatchView(
            batch_id=record.batch_id,
            campaign_name=record.campaign_name,
            source=cls.replay_source(record),
            retest_source=(cls.artifact(retest_artifact) if retest_artifact is not None else None),
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
    def replay_item(
        record: ReplayItemRecord,
        *,
        claim_authority: ReplayClaimBindingRecord | None = None,
    ) -> ReplayItemView:
        try:
            if claim_authority is None:
                candidate_id = record.candidate_id
                claim = None
            else:
                claim = ReplayClaimBinding.model_validate(claim_authority.claim_binding)
                if not (
                    claim_authority.item_id == record.item_id
                    and claim_authority.batch_id == record.batch_id
                    and claim_authority.claim_id == record.candidate_id
                    and claim.claim_id == claim_authority.claim_id
                    and claim_authority.binding_digest
                    == replay_context_digest(claim.model_dump(mode="json"))
                ):
                    raise ValueError("Replay Claim binding record is inconsistent")
                candidate_id = claim_authority.source_candidate_id
            return ReplayItemView(
                item_id=record.item_id,
                batch_id=record.batch_id,
                replay_run_id=record.replay_run_id,
                state=ReplayItemState(record.state),
                candidate_id=candidate_id,
                claim=claim,
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
        except (TypeError, ValueError) as exc:
            raise StateConflict("durable Replay item Claim authority is invalid") from exc

    @staticmethod
    def replay_ticket(record: ReplayTicketRecord) -> ReplayTicketView:
        return ReplayTicketView(
            ticket_id=record.ticket_id,
            batch_id=record.batch_id,
            item_id=record.item_id,
            job_id=record.job_id,
            compilation_id=record.compilation_id,
            budget_reservation_id=record.budget_reservation_id,
            rate_reservation_id=record.rate_reservation_id,
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
    def replay_tool_permit(
        record: ReplayToolPermitRecord,
        *,
        target_attestation: bool = False,
    ) -> ReplayToolPermitView:
        return ReplayToolPermitView(
            permit_id=record.permit_id,
            permit_digest=record.permit_digest,
            replay_request_id=record.replay_request_id,
            job_id=record.job_id,
            batch_id=record.batch_id,
            item_id=record.item_id,
            ticket_id=record.ticket_id,
            compilation_id=record.compilation_id,
            budget_reservation_id=record.budget_reservation_id,
            rate_reservation_id=record.rate_reservation_id,
            replay_run_id=record.replay_run_id,
            attempt=record.attempt_number,
            fencing_value=record.fencing_value,
            call_ordinal=record.call_ordinal,
            issued_to=record.issued_to,
            executor_profile=record.executor_profile,
            source_root_digest=record.source_root_digest,
            compilation_digest=record.compilation_digest,
            grant_digest=record.grant_digest,
            original_request_id=record.original_request_id,
            tool_id=record.tool_id,
            tool_version=record.tool_version,
            target_id=record.target_id,
            target=record.target,
            method=record.method,
            compiled_argument_digest=record.compiled_argument_digest,
            tool_call_units=record.tool_call_units,
            request_units=record.request_units,
            issued_at=_aware(record.issued_at),
            expires_at=_aware(record.expires_at),
            target_execution_challenge=(
                derive_target_execution_challenge(
                    permit_digest=record.permit_digest,
                    replay_request_id=record.replay_request_id,
                    batch_id=record.batch_id,
                    item_id=record.item_id,
                    ticket_id=record.ticket_id,
                    fencing_value=record.fencing_value,
                    call_ordinal=record.call_ordinal,
                    target=record.target,
                    method=record.method,
                    compiled_argument_digest=record.compiled_argument_digest,
                    issued_at=_aware(record.issued_at),
                    expires_at=_aware(record.expires_at),
                )
                if target_attestation
                else None
            ),
        )

    @classmethod
    def replay_finalization(
        cls,
        record: ReplayFinalizationRecord,
        *,
        job: JobRecord,
        batch: ReplayBatchRecord,
        item: ReplayItemRecord,
        ticket: ReplayTicketRecord,
        artifact: ArtifactRecord,
        claim_authority: ReplayClaimBindingRecord | None = None,
        retest_artifact: ArtifactRecord | None = None,
    ) -> ReplayFinalizationView:
        try:
            decision = ValidationDecision.model_validate(record.gate_decision)
        except ValueError as exc:
            raise StateConflict("durable Replay Gate decision is invalid") from exc
        gate_digest = replay_context_digest(decision.model_dump(mode="json", by_alias=True))
        if not isinstance(job.result, dict):
            raise StateConflict("durable Replay finalization Job result is invalid")
        portable_fields = (
            job.result.get("artifactTransport"),
            job.result.get("artifactTransportDigest"),
            job.result.get("executorAttestation"),
            job.result.get("executorAttestationDigest"),
            job.result.get("executorAttestationTrustAnchorDigest"),
        )
        artifact_transport: PortableArtifactTransportReceipt | None
        executor_attestation: ExecutorExecutionAttestation | None
        target_execution_verification: TargetExecutionVerificationSummary | None
        if all(value is None for value in portable_fields):
            artifact_transport = None
            executor_attestation = None
            target_execution_verification = None
        elif any(value is None for value in portable_fields):
            raise StateConflict("durable portable Replay finalization is incomplete")
        else:
            try:
                artifact_transport = PortableArtifactTransportReceipt.model_validate(
                    portable_fields[0]
                )
                executor_attestation = ExecutorExecutionAttestation.model_validate(
                    portable_fields[2]
                )
            except ValueError as exc:
                raise StateConflict("durable portable Replay finalization is invalid") from exc
            statement = executor_attestation.statement
            anchor_digest = portable_fields[4]
            if not (
                portable_fields[1]
                == replay_context_digest(artifact_transport.model_dump(mode="json", by_alias=True))
                and portable_fields[3] == executor_attestation.digest
                and isinstance(anchor_digest, str)
                and len(anchor_digest) == 64
                and all(character in "0123456789abcdef" for character in anchor_digest)
                and artifact_transport.output_staging_id == record.output_staging_id
                and artifact_transport.manifest_sha256 == artifact.content_digest
                and statement.artifact_bundle_manifest_sha256 == artifact_transport.manifest_sha256
                and statement.artifact_bundle_file_count == artifact_transport.file_count
                and statement.artifact_bundle_total_bytes == artifact_transport.total_bytes
                and statement.batch_id == batch.batch_id
                and statement.item_id == item.item_id
                and statement.job_id == job.job_id
                and statement.ticket_id == ticket.ticket_id
                and statement.fencing_value == ticket.fencing_value
                and statement.replay_run_id == record.replay_run_id
                and statement.compilation_digest == item.compilation_digest
                and statement.artifact_set_digest == record.artifact_set_digest
                and statement.artifact_seal_root_digest == record.artifact_seal_root_digest
                and statement.receipt_seal_root_digest == record.receipt_seal_root_digest
            ):
                raise StateConflict("durable portable Replay finalization graph is inconsistent")
            raw_target_verification = job.result.get("targetExecutionVerification")
            raw_target_verification_digest = job.result.get("targetExecutionVerificationDigest")
            target_proofs_present = statement.target_execution_proofs is not None
            if not target_proofs_present:
                if (
                    raw_target_verification is not None
                    or raw_target_verification_digest is not None
                ):
                    raise StateConflict("legacy portable Replay contains target verification state")
                target_execution_verification = None
            else:
                try:
                    target_execution_verification = (
                        TargetExecutionVerificationSummary.model_validate(raw_target_verification)
                    )
                except ValueError as exc:
                    raise StateConflict("durable target execution verification is invalid") from exc
                if raw_target_verification_digest != target_execution_verification.digest:
                    raise StateConflict(
                        "durable target execution verification digest is inconsistent"
                    )
        artifact_ref = cls.artifact(artifact)
        finalization_material: dict[str, object] = {
            "artifact": artifact_ref.model_dump(mode="json"),
            "artifactSetDigest": record.artifact_set_digest,
            "artifactSealRootDigest": record.artifact_seal_root_digest,
            "batchId": batch.batch_id,
            "compilationId": ticket.compilation_id,
            "fencingValue": ticket.fencing_value,
            "gateDecisionDigest": gate_digest,
            "itemId": item.item_id,
            "jobId": job.job_id,
            "receiptSealRootDigest": record.receipt_seal_root_digest,
            "ticketId": ticket.ticket_id,
        }
        if artifact_transport is not None:
            finalization_material.update(
                {
                    "artifactTransportDigest": portable_fields[1],
                    "executorAttestationDigest": portable_fields[3],
                    "executorAttestationTrustAnchorDigest": portable_fields[4],
                }
            )
            if target_execution_verification is not None:
                finalization_material.update(
                    {
                        "targetExecutionVerificationDigest": (target_execution_verification.digest),
                        "targetAttestationTrustAnchorDigest": (
                            target_execution_verification.trust_anchor_digest
                        ),
                    }
                )
        expected_result_digest = replay_context_digest(finalization_material)
        if not (
            record.job_id == job.job_id
            and record.batch_id == batch.batch_id
            and record.item_id == item.item_id
            and record.ticket_id == ticket.ticket_id
            and record.replay_run_id == job.run_id == ticket.replay_run_id
            and record.compilation_id == ticket.compilation_id
            and record.attempt_number == ticket.attempt_number
            and record.fencing_value == ticket.fencing_value
            and record.artifact_id == artifact.artifact_id
            and record.repository_version == artifact.repository_version
            and record.gate_decision_digest == gate_digest
            and record.result_digest == expected_result_digest
            and ticket.result_digest == record.result_digest
            and isinstance(job.result, dict)
            and job.result.get("finalizationId") == record.finalization_id
            and job.result.get("resultDigest") == record.result_digest
        ):
            raise StateConflict("durable Replay finalization graph is inconsistent")
        return ReplayFinalizationView(
            finalization_id=record.finalization_id,
            job=cls.job(job),
            batch=cls.replay_batch(batch, retest_artifact=retest_artifact),
            item=cls.replay_item(item, claim_authority=claim_authority),
            ticket=cls.replay_ticket(ticket),
            artifact=artifact_ref,
            artifact_set_digest=record.artifact_set_digest,
            artifact_seal_root_digest=record.artifact_seal_root_digest,
            receipt_seal_root_digest=record.receipt_seal_root_digest,
            artifact_transport=artifact_transport,
            executor_attestation=executor_attestation,
            target_execution_verification=target_execution_verification,
            gate_decision=decision,
            result_digest=record.result_digest,
            finalized_by=record.finalized_by,
            finalized_at=_aware(record.finalized_at),
        )

    @classmethod
    def replay_projection(
        cls,
        record: ReplayProjectionRecord,
        *,
        batch: ReplayBatchRecord,
        artifact: ArtifactRecord,
        retest_artifact: ArtifactRecord | None = None,
    ) -> ReplayProjectionView:
        try:
            authority: (
                ReplayProjectionInputAuthority
                | ReplayRetestProjectionInputAuthority
                | ReplayClaimProjectionInputAuthority
            )
            api_version = record.input_authority.get("api_version")
            if api_version == "pajin.control-plane.replay-projection-inputs/v1":
                authority = ReplayProjectionInputAuthority.model_validate(record.input_authority)
            elif api_version == "pajin.control-plane.replay-projection-inputs/v2":
                authority = ReplayRetestProjectionInputAuthority.model_validate(
                    record.input_authority
                )
            elif api_version == "pajin.control-plane.replay-projection-inputs/v3":
                authority = ReplayClaimProjectionInputAuthority.model_validate(
                    record.input_authority
                )
            else:
                raise ValueError("unsupported Replay projection input authority version")
        except ValueError as exc:
            raise StateConflict("durable Replay projection inputs are invalid") from exc
        authority_digest = replay_context_digest(authority.model_dump(mode="json", by_alias=True))
        if not (
            record.batch_id == batch.batch_id
            and record.source_root_digest == batch.source_root_digest
            and record.artifact_id == artifact.artifact_id
            and record.repository_version == artifact.repository_version
            and record.batch_cas_version == authority.batch_cas_version
            and record.input_authority_digest == authority_digest
        ):
            raise StateConflict("durable Replay projection graph is inconsistent")
        return ReplayProjectionView(
            projection_id=record.projection_id,
            batch=cls.replay_batch(batch, retest_artifact=retest_artifact),
            artifact=cls.artifact(artifact),
            input_authority=authority,
            input_authority_digest=record.input_authority_digest,
            published_by=record.published_by,
            published_at=_aware(record.published_at),
        )

    @classmethod
    def replay_claim(
        cls,
        *,
        job: JobRecord,
        batch: ReplayBatchRecord,
        item: ReplayItemRecord,
        ticket: ReplayTicketRecord,
        compilation: ReplayCompilation,
        execution_context: ReplayExecutionContext,
        execution_context_digest: str,
        lease_token: str,
        claim_authority: ReplayClaimBindingRecord | None = None,
        retest_artifact: ArtifactRecord | None = None,
    ) -> ReplayExecutionClaimView:
        return ReplayExecutionClaimView(
            job=cls.job(job),
            batch=cls.replay_batch(batch, retest_artifact=retest_artifact),
            item=cls.replay_item(item, claim_authority=claim_authority),
            ticket=cls.replay_ticket(ticket),
            compilation=compilation,
            execution_context=execution_context,
            execution_context_digest=execution_context_digest,
            lease_token=lease_token,
        )

    @staticmethod
    def checkpoint_intent(checkpoint: CheckpointRecord) -> ApprovalIntent:
        value = checkpoint.payload.get("pendingIntent")
        if not isinstance(value, dict):
            raise StateConflict("signed checkpoint does not contain an approval intent")
        return ApprovalIntent.model_validate(value)

    @classmethod
    def checkpoint(cls, record: CheckpointRecord) -> CheckpointView:
        state = record.payload.get("state")
        return CheckpointView(
            checkpoint_id=record.checkpoint_id,
            run_id=record.run_id,
            sequence=record.sequence,
            schema_version=record.schema_version,
            state=state if isinstance(state, dict) else {},
            pending_intent=cls.checkpoint_intent(record),
            payload_sha256=record.payload_sha256,
            signature=record.signature,
            key_id=record.key_id,
            created_at=_aware(record.created_at),
            claimed_at=_aware(record.claimed_at) if record.claimed_at else None,
            claimed_by=record.claimed_by,
            continuation_job_id=record.continuation_job_id,
        )

    @staticmethod
    def approval(record: ApprovalRecord) -> ApprovalView:
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
    def event(record: EventRecord) -> AuditEventView:
        return AuditEventView(
            event_id=record.event_id,
            run_id=record.run_id,
            sequence=record.sequence,
            event_type=record.event_type,
            actor=record.actor,
            payload=record.payload,
            occurred_at=_aware(record.occurred_at),
        )
