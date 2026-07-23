"""Pure invariant checks for a locked Control Plane Replay authority graph."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from pajin.control_plane.database import (
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
from pajin.control_plane.errors import StateConflict
from pajin.control_plane.kisa_derivation import DerivedKISAReplayBatch, DerivedKISAReplayItem
from pajin.control_plane.models import (
    KISA_EXACT_REPLAY_EXECUTOR_PROFILE,
    ArtifactRef,
    InternalJobKind,
    JobState,
    ReplayExecutionContext,
    ReplayItemState,
    ReplayJobPayload,
    ReplayRateAccountAuthority,
    ReplayTicketState,
    RunState,
    canonical_replay_execution_context_bytes,
    replay_execution_context_digest,
)
from pajin.domain.replay import ReplayCompilation
from pajin.replay.tickets import canonical_replay_compilation_bytes, replay_context_digest
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.tools.ai import AIChatProbeTool

_REPLAY_TICKET_TTL = timedelta(minutes=5)
_REPLAY_TOOL_PERMIT_TTL = timedelta(seconds=30)
_REPLAY_TOOL_PERMIT_DIGEST_FIELDS = (
    "permit_id",
    "replay_request_id",
    "job_id",
    "batch_id",
    "item_id",
    "ticket_id",
    "compilation_id",
    "budget_reservation_id",
    "rate_reservation_id",
    "replay_run_id",
    "attempt_number",
    "fencing_value",
    "call_ordinal",
    "issued_to",
    "executor_profile",
    "lease_token_hash",
    "source_root_digest",
    "compilation_digest",
    "grant_digest",
    "original_request_id",
    "tool_id",
    "tool_version",
    "target_id",
    "target",
    "method",
    "compiled_argument_digest",
    "tool_call_units",
    "request_units",
    "issued_at",
    "expires_at",
    "rate_window_expires_at",
)
_MAX_REPLAY_COMPILATION_JSON_BYTES = 64 * 1024 * 1024
_MAX_REPLAY_COMPILATION_JSON_DEPTH = 64
_MAX_REPLAY_COMPILATION_JSON_NODES = 200_000
_MAX_REPLAY_EXECUTION_CONTEXT_JSON_BYTES = 64 * 1024 * 1024
_MAX_REPLAY_EXECUTION_CONTEXT_JSON_DEPTH = 64
_MAX_REPLAY_EXECUTION_CONTEXT_JSON_NODES = 200_000


@dataclass(slots=True)
class ReplayBindingAuthority:
    """Locked, reconciled rows and immutable authority for one Replay attempt."""

    payload: ReplayJobPayload
    compilation_record: ReplayCompilationRecord
    compilation: ReplayCompilation
    execution_context_record: ReplayExecutionContextRecord
    execution_context: ReplayExecutionContext
    budget_account: ReplayBudgetAccountRecord
    rate_account: ReplayRateAccountRecord
    budget_reservation: ReplayBudgetReservationRecord
    rate_reservation: ReplayRateReservationRecord
    budget_reservations: list[ReplayBudgetReservationRecord]
    rate_reservations: list[ReplayRateReservationRecord]
    permits: list[ReplayToolPermitRecord]


def replay_rate_account_is_exact(
    account: ReplayRateAccountRecord,
    batch: ReplayBatchRecord,
    authority: ReplayRateAccountAuthority,
    *,
    capacity_source: ArtifactRef,
) -> bool:
    """Compare a mutable rate account with its reconstructed sealed authority."""

    return (
        account.source_run_id == capacity_source.producer_run_id
        and account.source_root_digest == capacity_source.integrity_root_digest
        and account.campaign_name == batch.campaign_name
        and account.rate_limits_digest == authority.rate_limits_digest
        and account.ledger_id == authority.ledger_id
        and account.max_requests_per_minute == authority.max_requests_per_minute
        and account.observed_request_units == authority.observed_request_units
        and _aware(account.observed_at) == authority.observed_at
        and account.window_seconds == authority.window_seconds
    )


def replay_binding_is_exact(
    job: JobRecord,
    ticket: ReplayTicketRecord,
    item: ReplayItemRecord,
    batch: ReplayBatchRecord,
    source: ArtifactRef,
    capacity_source: ArtifactRef,
    authority: ReplayBindingAuthority,
    *,
    budget_lifecycle_exact: bool,
    rate_lifecycle_exact: bool,
) -> bool:
    """Check all cross-row bindings after callers acquire the canonical locks."""

    ticket_lifecycle_exact = _ticket_reservation_lifecycle_is_exact(ticket, authority)
    return (
        _core_binding_is_exact(job, ticket, item, batch, authority)
        and _execution_binding_is_exact(ticket, batch, source, authority)
        and _capacity_binding_is_exact(
            ticket,
            batch,
            capacity_source,
            authority,
            budget_lifecycle_exact=budget_lifecycle_exact,
            rate_lifecycle_exact=rate_lifecycle_exact,
            ticket_lifecycle_exact=ticket_lifecycle_exact,
        )
        and _payload_binding_is_exact(ticket, item, batch, source, authority)
    )


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _ticket_reservation_lifecycle_is_exact(
    ticket: ReplayTicketRecord,
    authority: ReplayBindingAuthority,
) -> bool:
    budget = authority.budget_reservation
    rate = authority.rate_reservation
    permit_count = len(authority.permits)
    required_calls = authority.compilation.spec.repetitions
    if ticket.state == ReplayTicketState.ISSUED.value:
        return budget.state == "active" and rate.state == "active" and permit_count == 0
    if ticket.state == ReplayTicketState.CLAIMED.value:
        required_state = "consumed" if permit_count == required_calls else "active"
        return budget.state == required_state and rate.state == required_state
    if ticket.state == ReplayTicketState.ABANDONED.value:
        return budget.state in {"released", "consumed"} and rate.state in {
            "released",
            "consumed",
        }
    if ticket.state == ReplayTicketState.FINALIZED.value:
        return (
            budget.state == "consumed"
            and rate.state == "consumed"
            and permit_count == required_calls
        )
    return False


def _core_binding_is_exact(
    job: JobRecord,
    ticket: ReplayTicketRecord,
    item: ReplayItemRecord,
    batch: ReplayBatchRecord,
    authority: ReplayBindingAuthority,
) -> bool:
    compilation = authority.compilation_record
    binding = authority.compilation.spec.binding
    return (
        job.kind == InternalJobKind.REPLAY.value
        and job.max_attempts == 1
        and job.job_id == ticket.job_id
        and job.run_id == ticket.replay_run_id
        and compilation.compilation_id == ticket.compilation_id
        and compilation.item_id == ticket.item_id
        and compilation.batch_id == ticket.batch_id
        and compilation.replay_run_id == ticket.replay_run_id
        and compilation.candidate_id == item.candidate_id
        and compilation.candidate_digest == item.candidate_digest
        and compilation.contract_digest == item.contract_digest
        and compilation.compilation_digest == ticket.compilation_digest
        and compilation.grant_digest == ticket.grant_digest
        and item.item_id == ticket.item_id
        and item.batch_id == ticket.batch_id == batch.batch_id
        and item.source_run_id == batch.source_run_id
        and item.replay_run_id == ticket.replay_run_id
        and item.grant_digest == ticket.grant_digest
        and item.compilation_digest == ticket.compilation_digest
        and batch.source_root_digest == ticket.source_root_digest
        and item.attempts == ticket.attempt_number
        and item.candidate_id
        == (binding.claim.claim_id if binding.claim is not None else binding.candidate_id)
        and binding.candidate_run_id == batch.source_artifact_run_id
        and binding.replay_run_id == item.replay_run_id
        and binding.campaign == batch.campaign_name
        and binding.mode.value == batch.mode
        and binding.purpose.value == batch.purpose
    )


def _execution_binding_is_exact(
    ticket: ReplayTicketRecord,
    batch: ReplayBatchRecord,
    source: ArtifactRef,
    authority: ReplayBindingAuthority,
) -> bool:
    compilation = authority.compilation_record
    trusted = authority.compilation
    record = authority.execution_context_record
    context = authority.execution_context
    binding = trusted.spec.binding
    return (
        record.compilation_id == compilation.compilation_id
        and record.item_id == ticket.item_id
        and record.batch_id == batch.batch_id
        and record.replay_run_id == ticket.replay_run_id
        and record.compilation_digest == ticket.compilation_digest
        and record.grant_digest == ticket.grant_digest
        and context.context_id == record.context_id
        and context.batch_id == batch.batch_id
        and context.item_id == ticket.item_id
        and context.compilation_id == compilation.compilation_id
        and context.replay_run_id == ticket.replay_run_id
        and context.source == source
        and context.source_root_digest == batch.source_root_digest
        and context.policy_version == batch.policy_version
        and context.required_executor_profile == KISA_EXACT_REPLAY_EXECUTOR_PROFILE
        and context.required_executor_profile == record.required_executor_profile
        and context.output_staging_id == record.output_staging_id
        and _aware(context.created_at) == _aware(compilation.created_at)
        and context.campaign.metadata.name == batch.campaign_name
        and context.campaign.spec.mode.value == batch.mode
        and any(
            target.id == binding.target_id
            and target.endpoint == binding.target
            and target.type in context.scenario.target_types
            for target in context.campaign.spec.targets
        )
        and binding.threat_class in context.campaign.spec.threat_classes
        and context.scenario.scenario_id == binding.scenario_id
        and context.scenario.threat_classes == {binding.threat_class}
        and context.scenario.tool_id == binding.tool_id
        and context.scenario.method.upper() == trusted.spec.method
        and context.tool_spec == AIChatProbeTool.spec
        and context.tool_spec.tool_id == binding.tool_id
        and context.tool_spec.version == binding.tool_version
        and context.tool_spec.risk_tier == trusted.spec.risk_tier
        and not context.secret_lease_ids
        and not trusted.spec.secret_lease_ids
    )


def _capacity_binding_is_exact(
    ticket: ReplayTicketRecord,
    batch: ReplayBatchRecord,
    capacity_source: ArtifactRef,
    authority: ReplayBindingAuthority,
    *,
    budget_lifecycle_exact: bool,
    rate_lifecycle_exact: bool,
    ticket_lifecycle_exact: bool,
) -> bool:
    trusted = authority.compilation
    context = authority.execution_context
    budget = authority.budget_reservation
    rate = authority.rate_reservation
    budget_account = authority.budget_account
    rate_account = authority.rate_account
    return (
        (
            ticket.executor_profile is None
            or ticket.executor_profile == context.required_executor_profile
        )
        and budget.budget_reservation_id == ticket.budget_reservation_id
        and budget.budget_account_id == budget_account.budget_account_id
        and budget.batch_id == ticket.batch_id
        and budget.item_id == ticket.item_id
        and budget.attempt_number == ticket.attempt_number
        and budget.compilation_id == ticket.compilation_id
        and budget_lifecycle_exact
        and budget.total_calls == trusted.contract.repetitions
        and 0 <= budget.consumed_calls <= budget.total_calls
        and rate.rate_reservation_id == ticket.rate_reservation_id
        and rate.rate_account_id == rate_account.rate_account_id
        and rate.batch_id == ticket.batch_id
        and rate.item_id == ticket.item_id
        and rate.attempt_number == ticket.attempt_number
        and rate.compilation_id == ticket.compilation_id
        and rate_lifecycle_exact
        and ticket_lifecycle_exact
        and rate.total_request_units
        == AIChatProbeTool().network_request_cost(trusted.original_request)
        * trusted.contract.repetitions
        and 0 <= rate.consumed_request_units <= rate.total_request_units
        and _aware(ticket.expires_at) <= _aware(rate.expires_at)
        and _aware(ticket.expires_at) <= _aware(trusted.spec.expires_at)
        and _aware(ticket.expires_at) <= _aware(trusted.grant.expires_at)
        and budget_account.source_run_id == capacity_source.producer_run_id
        and budget_account.source_root_digest == capacity_source.integrity_root_digest
        and budget_account.campaign_name == batch.campaign_name
    )


def _payload_binding_is_exact(
    ticket: ReplayTicketRecord,
    item: ReplayItemRecord,
    batch: ReplayBatchRecord,
    source: ArtifactRef,
    authority: ReplayBindingAuthority,
) -> bool:
    payload = authority.payload
    record = authority.execution_context_record
    context = authority.execution_context
    return (
        payload.batch_id == batch.batch_id
        and payload.item_id == item.item_id
        and payload.ticket_id == ticket.ticket_id
        and payload.compilation_id == ticket.compilation_id
        and payload.execution_context_id == context.context_id
        and payload.execution_context_digest == record.context_digest
        and payload.budget_reservation_id == ticket.budget_reservation_id
        and payload.rate_reservation_id == ticket.rate_reservation_id
        and payload.replay_run_id == ticket.replay_run_id
        and payload.source == source
        and payload.mode.value == batch.mode
        and payload.purpose.value == batch.purpose
        and payload.policy_version == batch.policy_version
        and payload.candidate_id == authority.compilation.spec.binding.candidate_id
        and payload.claim == authority.compilation.spec.binding.claim
        and payload.candidate_digest == item.candidate_digest
        and payload.contract_digest == item.contract_digest
        and payload.compilation_digest == item.compilation_digest
        and payload.grant_digest == item.grant_digest
        and payload.attempt == ticket.attempt_number
        and payload.fencing_value == ticket.fencing_value
    )


def require_exact_replay_rate_account(
    account: ReplayRateAccountRecord,
    batch: ReplayBatchRecord,
    authority: ReplayRateAccountAuthority,
    *,
    capacity_source: ArtifactRef,
) -> None:
    if not replay_rate_account_is_exact(
        account,
        batch,
        authority,
        capacity_source=capacity_source,
    ):
        raise StateConflict("durable Replay rate account differs from the sealed source")


def require_exact_replay_binding(
    job: JobRecord,
    ticket: ReplayTicketRecord,
    item: ReplayItemRecord,
    batch: ReplayBatchRecord,
    authority: ReplayBindingAuthority,
    *,
    source: ArtifactRef,
    capacity_source: ArtifactRef,
) -> None:
    if not replay_binding_is_exact(
        job,
        ticket,
        item,
        batch,
        source,
        capacity_source,
        authority,
        budget_lifecycle_exact=replay_budget_reservation_lifecycle_exact(
            authority.budget_reservation
        ),
        rate_lifecycle_exact=replay_rate_reservation_lifecycle_exact(authority.rate_reservation),
    ):
        raise StateConflict("internal Replay Job authority binding is inconsistent")


def replay_issuance_lifecycle_is_exact(
    job: JobRecord,
    ticket: ReplayTicketRecord,
    item: ReplayItemRecord,
    run: RunRecord,
) -> bool:
    if ticket.state == ReplayTicketState.ISSUED.value:
        return (
            job.state == JobState.QUEUED.value
            and run.state == RunState.QUEUED.value
            and item.state == ReplayItemState.QUEUED.value
            and job.attempts == 0
            and job.lease_owner is None
            and job.lease_token_hash is None
        )
    if ticket.state == ReplayTicketState.CLAIMED.value:
        return (
            job.state == JobState.LEASED.value
            and run.state == RunState.RUNNING.value
            and item.state == ReplayItemState.RUNNING.value
            and job.attempts == 1
            and job.lease_owner == ticket.claim_principal
            and job.lease_token_hash == ticket.lease_token_hash
        )
    return False


def require_fresh_issuance_derivation(
    batch: ReplayBatchRecord,
    items: list[ReplayItemRecord],
    *,
    derived: DerivedKISAReplayBatch,
    source: ArtifactRef,
    retest_source: ArtifactRef | None = None,
) -> None:
    if (
        derived.artifact_ref != source
        or derived.retest_artifact_ref != retest_source
        or derived.candidate_run_id != source.run_id
        or derived.source_root_digest != source.integrity_root_digest
        or derived.campaign.metadata.name != derived.campaign_name
        or derived.campaign.spec.mode is not derived.mode
        or derived.campaign_name != batch.campaign_name
        or derived.mode.value != batch.mode
        or derived.purpose.value != batch.purpose
        or derived.policy_version != batch.policy_version
        or derived.required_tool_calls
        != sum(admitted.contract.repetitions for admitted in derived.items)
        or derived.required_request_units
        != sum(admitted.required_request_units for admitted in derived.items)
        or len(items) != len(derived.items)
        or not items
    ):
        raise StateConflict("fresh Replay derivation does not match the planned batch")
    if len({admitted.replay_run_id for admitted in derived.items}) != len(derived.items):
        raise StateConflict("fresh Replay derivation reused a Run identity")
    for ordinal, (item, admitted) in enumerate(zip(items, derived.items, strict=True)):
        binding = admitted.compilation.spec.binding
        if not (
            item.ordinal == ordinal
            and item.state == ReplayItemState.PENDING.value
            and item.attempts == 0
            and item.candidate_id
            == (
                admitted.claim.claim_id
                if admitted.claim is not None
                else admitted.candidate_id
            )
            and item.candidate_digest == admitted.candidate_digest
            and item.contract_digest == admitted.contract_digest
            and item.required_attempts == admitted.required_attempts
            and item.max_attempts == admitted.max_attempts
            and item.replay_run_id != admitted.replay_run_id
            and admitted.required_request_units > 0
            and binding.scenario_id == admitted.scenario.scenario_id
            and binding.threat_class in admitted.scenario.threat_classes
            and admitted.scenario.tool_id == binding.tool_id
            and admitted.scenario.method.upper() == admitted.compilation.spec.method
            and binding.tool_id == AIChatProbeTool.spec.tool_id
            and binding.tool_version == AIChatProbeTool.spec.version
            and admitted.compilation.spec.risk_tier == AIChatProbeTool.spec.risk_tier
        ):
            raise StateConflict("fresh Replay derivation changed the planned item set")


def require_fresh_retry_derivation(
    batch: ReplayBatchRecord,
    items: list[ReplayItemRecord],
    *,
    derived: DerivedKISAReplayBatch,
    source: ArtifactRef,
    retest_source: ArtifactRef | None = None,
) -> None:
    """Require a fresh compilation set without rewriting the stable item plan.

    Retry derivation rereads the immutable source and may mint only new execution
    identities. Candidate, contract, required-attempt, and policy authority must
    remain identical to the admitted batch plan.
    """

    if (
        derived.artifact_ref != source
        or derived.retest_artifact_ref != retest_source
        or derived.candidate_run_id != source.run_id
        or derived.source_root_digest != source.integrity_root_digest
        or derived.campaign.metadata.name != derived.campaign_name
        or derived.campaign.spec.mode is not derived.mode
        or derived.campaign_name != batch.campaign_name
        or derived.mode.value != batch.mode
        or derived.purpose.value != batch.purpose
        or derived.policy_version != batch.policy_version
        or derived.required_tool_calls
        != sum(admitted.contract.repetitions for admitted in derived.items)
        or derived.required_request_units
        != sum(admitted.required_request_units for admitted in derived.items)
        or len(items) != len(derived.items)
        or not items
    ):
        raise StateConflict("fresh Replay retry derivation does not match the admitted batch")
    if len({admitted.replay_run_id for admitted in derived.items}) != len(derived.items):
        raise StateConflict("fresh Replay retry derivation reused a Run identity")

    derived_by_candidate = {
        (
            admitted.claim.claim_id
            if admitted.claim is not None
            else admitted.candidate_id
        ): admitted
        for admitted in derived.items
    }
    if len(derived_by_candidate) != len(derived.items):
        raise StateConflict("fresh Replay retry derivation has duplicate Candidates")
    for item in items:
        admitted = derived_by_candidate.get(item.candidate_id)
        if admitted is None:
            raise StateConflict("fresh Replay retry derivation changed the admitted item set")
        binding = admitted.compilation.spec.binding
        if not (
            item.candidate_digest == admitted.candidate_digest
            and item.contract_digest == admitted.contract_digest
            and item.required_attempts == admitted.required_attempts
            and item.max_attempts == admitted.max_attempts
            and item.replay_run_id != admitted.replay_run_id
            and item.compilation_digest != admitted.compilation_digest
            and item.grant_digest != admitted.grant_digest
            and admitted.required_request_units > 0
            and binding.candidate_id == admitted.candidate_id
            and binding.candidate_run_id == batch.source_artifact_run_id
            and binding.replay_run_id == admitted.replay_run_id
            and binding.scenario_id == admitted.scenario.scenario_id
            and binding.threat_class in admitted.scenario.threat_classes
            and admitted.scenario.tool_id == binding.tool_id
            and admitted.scenario.method.upper() == admitted.compilation.spec.method
            and binding.tool_id == AIChatProbeTool.spec.tool_id
            and binding.tool_version == AIChatProbeTool.spec.version
            and admitted.compilation.spec.risk_tier == AIChatProbeTool.spec.risk_tier
        ):
            raise StateConflict("fresh Replay retry derivation changed admitted authority")


def trusted_replay_compilation(record: ReplayCompilationRecord) -> ReplayCompilation:
    try:
        raw = parse_strict_json_bytes(
            record.canonical_compilation,
            label="stored Replay compilation",
            max_bytes=_MAX_REPLAY_COMPILATION_JSON_BYTES,
            max_depth=_MAX_REPLAY_COMPILATION_JSON_DEPTH,
            max_nodes=_MAX_REPLAY_COMPILATION_JSON_NODES,
        )
        trusted = ReplayCompilation.model_validate(raw)
    except (TypeError, ValueError) as exc:
        raise StateConflict("stored Replay compilation is invalid") from exc
    canonical = canonical_replay_compilation_bytes(trusted)
    if not (
        canonical == record.canonical_compilation
        and len(canonical) == record.byte_length
        and sha256(canonical).hexdigest() == record.compilation_digest
        and replay_context_digest(trusted.validation_packet.candidate) == record.candidate_digest
        and replay_context_digest(trusted.contract) == record.contract_digest
        and replay_context_digest(trusted.grant) == record.grant_digest
        and record.candidate_id
        == (
            trusted.spec.binding.claim.claim_id
            if trusted.spec.binding.claim is not None
            else trusted.spec.binding.candidate_id
        )
        and trusted.validation_packet.candidate.candidate_id
        == trusted.spec.binding.candidate_id
        and trusted.spec.binding.replay_run_id == record.replay_run_id
    ):
        raise StateConflict("stored Replay compilation authority is inconsistent")
    return trusted


def trusted_replay_execution_context(
    record: ReplayExecutionContextRecord,
) -> ReplayExecutionContext:
    try:
        raw = parse_strict_json_bytes(
            record.canonical_context,
            label="stored Replay execution context",
            max_bytes=_MAX_REPLAY_EXECUTION_CONTEXT_JSON_BYTES,
            max_depth=_MAX_REPLAY_EXECUTION_CONTEXT_JSON_DEPTH,
            max_nodes=_MAX_REPLAY_EXECUTION_CONTEXT_JSON_NODES,
        )
        trusted = ReplayExecutionContext.model_validate(raw)
    except (TypeError, ValueError) as exc:
        raise StateConflict("stored Replay execution context is invalid") from exc
    canonical = canonical_replay_execution_context_bytes(trusted)
    if not (
        canonical == record.canonical_context
        and len(canonical) == record.byte_length
        and replay_execution_context_digest(trusted) == record.context_digest
        and trusted.context_id == record.context_id
        and trusted.compilation_id == record.compilation_id
        and trusted.item_id == record.item_id
        and trusted.batch_id == record.batch_id
        and trusted.replay_run_id == record.replay_run_id
        and trusted.required_executor_profile == record.required_executor_profile
        and trusted.output_staging_id == record.output_staging_id
        and _aware(trusted.created_at) == _aware(record.created_at)
    ):
        raise StateConflict("stored Replay execution context authority is inconsistent")
    return trusted


def trusted_fresh_issuance_compilation(
    admitted: DerivedKISAReplayItem,
    *,
    now: datetime,
) -> ReplayCompilation:
    transient = ReplayCompilationRecord(
        compilation_id=f"replay-compilation_{'0' * 32}",
        item_id="fresh-validation",
        batch_id="fresh-validation",
        candidate_id=(
            admitted.claim.claim_id
            if admitted.claim is not None
            else admitted.candidate_id
        ),
        replay_run_id=admitted.replay_run_id,
        candidate_digest=admitted.candidate_digest,
        contract_digest=admitted.contract_digest,
        compilation_digest=admitted.compilation_digest,
        grant_digest=admitted.grant_digest,
        canonical_compilation=admitted.canonical_compilation,
        byte_length=len(admitted.canonical_compilation),
        created_at=now,
    )
    trusted = trusted_replay_compilation(transient)
    compiled_at = _aware(trusted.spec.compiled_at)
    expires_at = _aware(trusted.spec.expires_at)
    if not (
        trusted == admitted.compilation
        and compiled_at == _aware(trusted.grant.issued_at)
        and expires_at == _aware(trusted.grant.expires_at)
        and compiled_at == _aware(admitted.compilation.spec.compiled_at)
        and compiled_at <= now
        and expires_at > now
        and expires_at <= compiled_at + _REPLAY_TICKET_TTL
        and admitted.contract.repetitions == trusted.spec.repetitions
        and admitted.contract.repetitions == trusted.grant.max_calls
        and admitted.required_request_units
        == AIChatProbeTool().network_request_cost(trusted.original_request)
        * trusted.contract.repetitions
    ):
        raise StateConflict("fresh Replay compilation has no valid short-lived authority")
    return trusted


def replay_tool_permit_values(record: ReplayToolPermitRecord) -> dict[str, Any]:
    return {
        field_name: getattr(record, field_name) for field_name in _REPLAY_TOOL_PERMIT_DIGEST_FIELDS
    }


def replay_tool_permit_digest(values: Mapping[str, Any]) -> str:
    canonical: dict[str, Any] = {}
    for field_name in _REPLAY_TOOL_PERMIT_DIGEST_FIELDS:
        value = values[field_name]
        canonical[field_name] = _aware(value).isoformat() if isinstance(value, datetime) else value
    document = {
        "apiVersion": "pajin.dev/control-plane/v1alpha1",
        "kind": "ReplayToolPermit",
        "authority": canonical,
    }
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(encoded).hexdigest()


def require_exact_replay_permit_ledger(
    permits: list[ReplayToolPermitRecord],
    *,
    job: JobRecord,
    ticket: ReplayTicketRecord,
    item: ReplayItemRecord,
    batch: ReplayBatchRecord,
    compilation: ReplayCompilationRecord,
    trusted: ReplayCompilation,
    budget_reservation: ReplayBudgetReservationRecord,
    rate_reservation: ReplayRateReservationRecord,
    rate_window_seconds: int,
) -> None:
    """Reconcile immutable permits with both mutable reservation counters."""

    expected_request_units = AIChatProbeTool().network_request_cost(trusted.original_request)
    expected_ordinals = list(range(1, len(permits) + 1))
    if (
        [permit.call_ordinal for permit in permits] != expected_ordinals
        or len(permits) > trusted.spec.repetitions
        or budget_reservation.consumed_calls != len(permits)
        or rate_reservation.consumed_request_units != expected_request_units * len(permits)
    ):
        raise StateConflict("durable Replay Tool permit ledger counters are inconsistent")

    for permit in permits:
        issued_at = _aware(permit.issued_at)
        expires_at = _aware(permit.expires_at)
        rate_window_expires_at = _aware(permit.rate_window_expires_at)
        if not (
            permit.job_id == job.job_id
            and permit.batch_id == batch.batch_id
            and permit.item_id == item.item_id
            and permit.ticket_id == ticket.ticket_id
            and permit.compilation_id == compilation.compilation_id
            and permit.budget_reservation_id == budget_reservation.budget_reservation_id
            and permit.rate_reservation_id == rate_reservation.rate_reservation_id
            and permit.replay_run_id == ticket.replay_run_id
            and permit.attempt_number == ticket.attempt_number
            and permit.fencing_value == ticket.fencing_value
            and permit.issued_to == ticket.claim_principal
            and permit.executor_profile == ticket.executor_profile
            and permit.lease_token_hash == ticket.lease_token_hash
            and permit.source_root_digest == ticket.source_root_digest
            and permit.compilation_digest == ticket.compilation_digest
            and permit.grant_digest == ticket.grant_digest
            and permit.original_request_id == trusted.spec.binding.original_request_id
            and permit.tool_id == trusted.spec.binding.tool_id
            and permit.tool_version == trusted.spec.binding.tool_version
            and permit.target_id == trusted.spec.binding.target_id
            and permit.target == trusted.spec.binding.target
            and permit.method == trusted.spec.method
            and permit.compiled_argument_digest == trusted.spec.argument_digest
            and permit.tool_call_units == 1
            and permit.request_units == expected_request_units
            and expires_at > issued_at
            and expires_at <= issued_at + _REPLAY_TOOL_PERMIT_TTL
            and expires_at <= _aware(trusted.spec.expires_at)
            and expires_at <= _aware(trusted.grant.expires_at)
            and rate_window_expires_at == issued_at + timedelta(seconds=rate_window_seconds)
            and permit.permit_digest == replay_tool_permit_digest(replay_tool_permit_values(permit))
        ):
            raise StateConflict("durable Replay Tool permit authority is inconsistent")


def require_replay_permit_rate_capacity(
    session: Session,
    *,
    authority: ReplayBindingAuthority,
    request_units: int,
    now: datetime,
) -> None:
    """Admit one call against reservations plus issued rolling-window entries."""

    rate_account = authority.rate_account
    if rate_account.max_requests_per_minute is None:
        return
    baseline_units = (
        rate_account.observed_request_units
        if now < _aware(rate_account.observed_at) + timedelta(seconds=rate_account.window_seconds)
        else 0
    )
    reserved_units_after = sum(
        reservation.total_request_units
        - reservation.consumed_request_units
        - reservation.released_request_units
        for reservation in authority.rate_reservations
        if _aware(reservation.expires_at) > now
    )
    if _aware(authority.rate_reservation.expires_at) > now:
        reserved_units_after -= request_units
    if reserved_units_after < 0:
        raise StateConflict("durable Replay rate reservation counters are inconsistent")

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
        baseline_units + reserved_units_after + active_permit_units + request_units
        > rate_account.max_requests_per_minute
    ):
        raise StateConflict("durable Replay Tool permit exceeds Campaign request rate")


def require_exact_replay_account_permit_consumption(
    session: Session,
    *,
    budget_reservations: list[ReplayBudgetReservationRecord],
    rate_reservations: list[ReplayRateReservationRecord],
) -> None:
    """Reject mutable counter drift from the append-only consumption proof."""

    budget_by_authority = {
        (
            reservation.batch_id,
            reservation.item_id,
            reservation.attempt_number,
            reservation.compilation_id,
        ): reservation
        for reservation in budget_reservations
    }
    rate_by_authority = {
        (
            reservation.batch_id,
            reservation.item_id,
            reservation.attempt_number,
            reservation.compilation_id,
        ): reservation
        for reservation in rate_reservations
    }
    if set(budget_by_authority) != set(rate_by_authority):
        raise StateConflict("durable Replay reservation account graphs do not match")

    budget_ids = {reservation.budget_reservation_id for reservation in budget_reservations}
    rate_ids = {reservation.rate_reservation_id for reservation in rate_reservations}
    if not budget_ids and not rate_ids:
        return
    permits = list(
        session.scalars(
            select(ReplayToolPermitRecord).where(
                or_(
                    ReplayToolPermitRecord.budget_reservation_id.in_(budget_ids),
                    ReplayToolPermitRecord.rate_reservation_id.in_(rate_ids),
                )
            )
        ).all()
    )
    budget_consumed = {reservation_id: 0 for reservation_id in budget_ids}
    rate_consumed = {reservation_id: 0 for reservation_id in rate_ids}
    for permit in permits:
        authority_key = (
            permit.batch_id,
            permit.item_id,
            permit.attempt_number,
            permit.compilation_id,
        )
        budget = budget_by_authority.get(authority_key)
        rate = rate_by_authority.get(authority_key)
        if (
            budget is None
            or rate is None
            or permit.budget_reservation_id != budget.budget_reservation_id
            or permit.rate_reservation_id != rate.rate_reservation_id
        ):
            raise StateConflict("durable Replay permit belongs to a different account graph")
        budget_consumed[budget.budget_reservation_id] += permit.tool_call_units
        rate_consumed[rate.rate_reservation_id] += permit.request_units

    if any(
        reservation.consumed_calls != budget_consumed[reservation.budget_reservation_id]
        for reservation in budget_reservations
    ) or any(
        reservation.consumed_request_units != rate_consumed[reservation.rate_reservation_id]
        for reservation in rate_reservations
    ):
        raise StateConflict("durable Replay reservation consumption lacks exact permit proof")


def require_exact_replay_budget_ledger(
    account: ReplayBudgetAccountRecord,
    reservations: list[ReplayBudgetReservationRecord],
) -> None:
    if any(not replay_budget_reservation_lifecycle_exact(item) for item in reservations):
        raise StateConflict("durable Replay budget reservation ledger is inconsistent")
    expected_reserved = sum(
        reservation.total_calls - reservation.consumed_calls - reservation.released_calls
        for reservation in reservations
    )
    expected_consumed = sum(reservation.consumed_calls for reservation in reservations)
    expected_released = sum(reservation.released_calls for reservation in reservations)
    if not (
        account.reserved_calls == expected_reserved
        and account.consumed_calls == expected_consumed
        and account.released_calls == expected_released
        and account.baseline_used_calls + account.reserved_calls + account.consumed_calls
        <= account.max_tool_calls
    ):
        raise StateConflict("durable Replay budget account counters differ from its ledger")


def replay_budget_reservation_lifecycle_exact(
    reservation: ReplayBudgetReservationRecord,
) -> bool:
    return (
        (
            reservation.state == "active"
            and reservation.released_at is None
            and reservation.released_calls == 0
            and 0 <= reservation.consumed_calls < reservation.total_calls
        )
        or (
            reservation.state == "consumed"
            and reservation.released_at is None
            and reservation.released_calls == 0
            and reservation.consumed_calls == reservation.total_calls
        )
        or (
            reservation.state == "released"
            and reservation.released_at is not None
            and reservation.consumed_calls + reservation.released_calls == reservation.total_calls
        )
    )


def replay_rate_reservation_lifecycle_exact(
    reservation: ReplayRateReservationRecord,
) -> bool:
    return (
        (
            reservation.state == "active"
            and reservation.released_at is None
            and reservation.released_request_units == 0
            and 0 <= reservation.consumed_request_units < reservation.total_request_units
        )
        or (
            reservation.state == "consumed"
            and reservation.released_at is None
            and reservation.released_request_units == 0
            and reservation.consumed_request_units == reservation.total_request_units
        )
        or (
            reservation.state == "released"
            and reservation.released_at is not None
            and reservation.consumed_request_units + reservation.released_request_units
            == reservation.total_request_units
        )
    )
