from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from kisa_control_plane_support import build_kisa_control_plane_source
from pydantic import BaseModel, ValidationError

from pajin.control_plane.kisa_derivation import derive_kisa_confirmation_batch
from pajin.control_plane.models import (
    AdmitSourceArtifactRequest,
    ArtifactLocator,
    ArtifactRef,
    ClaimJobRequest,
    CreateReplayBatchRequest,
    InternalJobKind,
    JobKind,
    JobState,
    JobView,
    ReplayBatchIssuanceView,
    ReplayBatchState,
    ReplayBatchView,
    ReplayClaimRequest,
    ReplayClaimView,
    ReplayExecutionClaimView,
    ReplayExecutionContext,
    ReplayItemState,
    ReplayItemView,
    ReplayJobPayload,
    ReplayLeaseRequest,
    ReplayProjectionItemAuthority,
    ReplayRetestProjectionInputAuthority,
    ReplayTicketState,
    ReplayTicketView,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
    replay_execution_component_digest,
    replay_execution_context_digest,
)
from pajin.domain.models import CampaignMode
from pajin.domain.replay import ReplayPurpose
from pajin.target_attestation import derive_target_execution_challenge
from pajin.tools.ai import AIChatProbeTool

NOW = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)


def test_replay_component_digest_rejects_non_string_nested_mapping_keys() -> None:
    with pytest.raises(ValueError, match="mapping keys must be strings"):
        replay_execution_component_digest(
            {
                "nested": {
                    1: "integer-key",
                    "1": "string-key",
                }
            }
        )


def test_replay_component_digest_preserves_canonical_string_mapping_order() -> None:
    assert replay_execution_component_digest(
        {"nested": {"b": 2, "a": 1}}
    ) == replay_execution_component_digest({"nested": {"a": 1, "b": 2}})


def _artifact(**updates: object) -> ArtifactRef:
    values: dict[str, object] = {
        "artifact_id": f"artifact_{'a' * 32}",
        "repository_version": 1,
        "media_type": "application/vnd.pajin.run+tar",
        "schema_kind": "pajin.run.v1",
        "byte_length": 4_096,
        "content_digest": "b" * 64,
        "producer_run_id": f"run_{'d' * 32}",
        "run_id": "run_20260717T120000Z_deadbeef",
        "integrity_root_digest": "c" * 64,
        "created_by": "alice-operator",
    }
    values.update(updates)
    return ArtifactRef.model_validate(values)


def _locator(**updates: object) -> ArtifactLocator:
    values: dict[str, object] = {
        "artifact_id": f"artifact_{'a' * 32}",
        "repository_version": 1,
    }
    values.update(updates)
    return ArtifactLocator.model_validate(values)


def _batch_request(**updates: object) -> CreateReplayBatchRequest:
    values: dict[str, object] = {
        "source": _locator(),
        "idempotency_key": "kisa-replay-batch-1",
    }
    values.update(updates)
    return CreateReplayBatchRequest.model_validate(values)


def test_retest_projection_input_authority_round_trips_database_json_version() -> None:
    replay_run_id = f"run_{'7' * 32}"
    authority = ReplayRetestProjectionInputAuthority(
        batch_id=f"replay-batch_{'1' * 32}",
        source=_artifact(),
        retest_source=_artifact(
            artifact_id=f"artifact_{'2' * 32}",
            content_digest="3" * 64,
            producer_run_id=f"run_{'4' * 32}",
            run_id=f"run_{'5' * 32}",
            integrity_root_digest="6" * 64,
            created_by="retest-operator",
        ),
        batch_cas_version=4,
        items=[
            ReplayProjectionItemAuthority(
                ordinal=0,
                item_id=f"replay-item_{'8' * 32}",
                ticket_id=f"replay-ticket_{'9' * 32}",
                finalization_id=f"replay-finalization_{'a' * 32}",
                replay_run_id=replay_run_id,
                compilation_digest="b" * 64,
                output=_artifact(
                    artifact_id=f"artifact_{'c' * 32}",
                    content_digest="d" * 64,
                    producer_run_id=replay_run_id,
                    run_id=replay_run_id,
                    integrity_root_digest="e" * 64,
                    created_by="replay-projection-publisher",
                ),
                artifact_set_digest="f" * 64,
                receipt_seal_root_digest="1" * 64,
                gate_decision_digest="2" * 64,
                result_digest="3" * 64,
                finalized_at=NOW,
            )
        ],
    )

    stored = authority.model_dump(mode="json", by_alias=True)

    assert stored["api_version"] == "pajin.control-plane.replay-projection-inputs/v2"
    assert "apiVersion" not in stored
    assert "artifact_transport_digest" not in stored["items"][0]
    assert "executor_attestation_digest" not in stored["items"][0]
    assert ReplayRetestProjectionInputAuthority.model_validate(stored) == authority


def _claim_view_payload() -> dict[str, object]:
    batch_id = f"replay-batch_{'1' * 32}"
    item_id = f"replay-item_{'2' * 32}"
    ticket_id = f"replay-ticket_{'3' * 32}"
    job_id = f"job_{'4' * 32}"
    compilation_id = f"replay-compilation_{'5' * 32}"
    execution_context_id = f"replay-context_{'8' * 32}"
    execution_context_digest = "8" * 64
    budget_reservation_id = f"budget-reservation_{'6' * 32}"
    rate_reservation_id = f"rate-reservation_{'7' * 32}"
    replay_run_id = "run_20260717T120000Z_cafebabe"
    batch = ReplayBatchView(
        batch_id=batch_id,
        campaign_name="kisa-replay",
        source=_artifact(),
        mode=CampaignMode.AI_REDTEAM,
        purpose=ReplayPurpose.CONFIRMATION,
        policy_version="policy-v1",
        state=ReplayBatchState.RUNNING,
        cas_version=1,
        created_by="control-plane",
        created_at=NOW,
        updated_at=NOW,
    )
    item = ReplayItemView(
        item_id=item_id,
        batch_id=batch_id,
        replay_run_id=replay_run_id,
        state=ReplayItemState.RUNNING,
        candidate_id="candidate-kisa-m03-1",
        candidate_digest="1" * 64,
        contract_digest="d" * 64,
        compilation_digest="e" * 64,
        grant_digest="f" * 64,
        required_attempts=2,
        max_attempts=3,
        attempts=1,
        created_at=NOW,
        updated_at=NOW,
    )
    ticket = ReplayTicketView(
        ticket_id=ticket_id,
        batch_id=batch_id,
        item_id=item_id,
        job_id=job_id,
        compilation_id=compilation_id,
        budget_reservation_id=budget_reservation_id,
        rate_reservation_id=rate_reservation_id,
        replay_run_id=replay_run_id,
        state=ReplayTicketState.CLAIMED,
        attempt=1,
        fencing_value=7,
        executor_profile="kisa-exact-v1",
        claimed_by="worker-service",
        lease_expires_at=NOW + timedelta(seconds=30),
        created_at=NOW,
        updated_at=NOW,
    )
    job = JobView(
        job_id=job_id,
        run_id=replay_run_id,
        kind=InternalJobKind.REPLAY.value,
        state=JobState.LEASED,
        payload={
            "batch_id": batch_id,
            "item_id": item_id,
            "ticket_id": ticket_id,
            "compilation_id": compilation_id,
            "execution_context_id": execution_context_id,
            "execution_context_digest": execution_context_digest,
            "budget_reservation_id": budget_reservation_id,
            "rate_reservation_id": rate_reservation_id,
            "replay_run_id": replay_run_id,
            "source": batch.source.model_dump(mode="json"),
            "mode": batch.mode.value,
            "purpose": batch.purpose.value,
            "policy_version": batch.policy_version,
            "candidate_id": item.candidate_id,
            "candidate_digest": item.candidate_digest,
            "contract_digest": item.contract_digest,
            "compilation_digest": "e" * 64,
            "grant_digest": item.grant_digest,
            "attempt": ticket.attempt,
            "fencing_value": ticket.fencing_value,
        },
        priority=0,
        attempts=1,
        max_attempts=1,
        available_at=NOW,
        lease_owner="worker-service",
        lease_expires_at=NOW + timedelta(seconds=30),
        heartbeat_at=NOW,
        result=None,
        error=None,
        created_at=NOW,
        updated_at=NOW,
    )
    return {
        "job": job,
        "batch": batch,
        "item": item,
        "ticket": ticket,
        "lease_token": "lease-token-that-is-at-least-32-characters",
    }


def _execution_claim_view_payload(root: Path) -> dict[str, object]:
    source = build_kisa_control_plane_source(root / "source", scenario_count=1)
    derived = derive_kisa_confirmation_batch(
        source_root=source.path,
        artifact_ref=source.artifact_ref,
        replay_run_id_factory=lambda: f"run_{'8' * 32}",
        clock=lambda: source.compilation_time,
    )
    admitted = derived.items[0]
    payload = _claim_view_payload()
    batch = payload["batch"]
    item = payload["item"]
    ticket = payload["ticket"]
    job = payload["job"]
    assert isinstance(batch, ReplayBatchView)
    assert isinstance(item, ReplayItemView)
    assert isinstance(ticket, ReplayTicketView)
    assert isinstance(job, JobView)

    batch = batch.model_copy(
        update={
            "campaign_name": derived.campaign_name,
            "source": derived.artifact_ref,
            "mode": derived.mode,
            "purpose": derived.purpose,
            "policy_version": derived.policy_version,
        }
    )
    item = item.model_copy(
        update={
            "replay_run_id": admitted.replay_run_id,
            "candidate_id": admitted.candidate_id,
            "candidate_digest": admitted.candidate_digest,
            "contract_digest": admitted.contract_digest,
            "compilation_digest": admitted.compilation_digest,
            "grant_digest": admitted.grant_digest,
            "required_attempts": admitted.required_attempts,
            "max_attempts": admitted.max_attempts,
        }
    )
    ticket = ticket.model_copy(update={"replay_run_id": admitted.replay_run_id})
    execution_context = ReplayExecutionContext(
        context_id=f"replay-context_{'8' * 32}",
        batch_id=batch.batch_id,
        item_id=item.item_id,
        compilation_id=ticket.compilation_id,
        replay_run_id=admitted.replay_run_id,
        source=derived.artifact_ref,
        source_root_digest=derived.source_root_digest,
        campaign=derived.campaign,
        campaign_digest=replay_execution_component_digest(derived.campaign),
        scenario=admitted.scenario,
        scenario_digest=replay_execution_component_digest(admitted.scenario),
        tool_spec=AIChatProbeTool.spec,
        tool_spec_digest=replay_execution_component_digest(AIChatProbeTool.spec),
        policy_version=derived.policy_version,
        required_executor_profile="kisa-exact-v1",
        secret_policy="forbidden",
        secret_lease_ids=(),
        output_staging_id=f"stage_{'9' * 32}",
        created_at=source.compilation_time,
    )
    context_digest = replay_execution_context_digest(execution_context)
    job_payload = {
        **job.payload,
        "execution_context_id": execution_context.context_id,
        "execution_context_digest": context_digest,
        "replay_run_id": admitted.replay_run_id,
        "source": derived.artifact_ref.model_dump(mode="json"),
        "mode": derived.mode.value,
        "purpose": derived.purpose.value,
        "policy_version": derived.policy_version,
        "candidate_id": admitted.candidate_id,
        "candidate_digest": admitted.candidate_digest,
        "contract_digest": admitted.contract_digest,
        "compilation_digest": admitted.compilation_digest,
        "grant_digest": admitted.grant_digest,
    }
    job = job.model_copy(
        update={
            "run_id": admitted.replay_run_id,
            "payload": job_payload,
        }
    )
    return {
        "job": job,
        "batch": batch,
        "item": item,
        "ticket": ticket,
        "lease_token": payload["lease_token"],
        "compilation": admitted.compilation,
        "execution_context": execution_context,
        "execution_context_digest": context_digest,
    }


@pytest.fixture(scope="module")
def execution_claim_payload(
    tmp_path_factory: pytest.TempPathFactory,
) -> dict[str, object]:
    return _execution_claim_view_payload(tmp_path_factory.mktemp("execution-claim"))


def _permit_request(**updates: object) -> ReplayToolPermitRequest:
    values: dict[str, object] = {
        "executor_profile": "kisa-exact-v1",
        "lease_token": "lease-token-that-is-at-least-32-characters",
        "ticket_id": f"replay-ticket_{'3' * 32}",
        "fencing_value": 7,
        "call_ordinal": 1,
    }
    values.update(updates)
    return ReplayToolPermitRequest.model_validate(values)


def _permit_view(**updates: object) -> ReplayToolPermitView:
    values: dict[str, object] = {
        "permit_id": f"replay-permit_{'8' * 32}",
        "permit_digest": "c" * 64,
        "replay_request_id": f"tool_replay_{'9' * 32}",
        "job_id": f"job_{'4' * 32}",
        "batch_id": f"replay-batch_{'1' * 32}",
        "item_id": f"replay-item_{'2' * 32}",
        "ticket_id": f"replay-ticket_{'3' * 32}",
        "compilation_id": f"replay-compilation_{'5' * 32}",
        "budget_reservation_id": f"budget-reservation_{'6' * 32}",
        "rate_reservation_id": f"rate-reservation_{'7' * 32}",
        "replay_run_id": "run_20260717T120000Z_cafebabe",
        "attempt": 1,
        "fencing_value": 7,
        "call_ordinal": 1,
        "issued_to": "worker-service",
        "executor_profile": "kisa-exact-v1",
        "source_root_digest": "a" * 64,
        "compilation_digest": "e" * 64,
        "grant_digest": "f" * 64,
        "original_request_id": "tool_original_request",
        "tool_id": "ai.chat-probe",
        "tool_version": "1.0.0",
        "target_id": "target-ai-chat",
        "target": "http://127.0.0.1:8080/v1/chat",
        "method": "post",
        "compiled_argument_digest": "b" * 64,
        "tool_call_units": 1,
        "request_units": 3,
        "issued_at": NOW,
        "expires_at": NOW + timedelta(seconds=15),
    }
    values.update(updates)
    return ReplayToolPermitView.model_validate(values)


def _authority_integer_cases() -> list[tuple[type[BaseModel], dict[str, object], tuple[str, ...]]]:
    claim_payload = _claim_view_payload()
    job = claim_payload["job"]
    batch = claim_payload["batch"]
    item = claim_payload["item"]
    ticket = claim_payload["ticket"]
    assert isinstance(job, JobView)
    assert isinstance(batch, ReplayBatchView)
    assert isinstance(item, ReplayItemView)
    assert isinstance(ticket, ReplayTicketView)

    lease = ReplayLeaseRequest(
        executor_profile="kisa-exact-v1",
        lease_token="lease-token-that-is-at-least-32-characters",
        lease_seconds=45,
        ticket_id=ticket.ticket_id,
        fencing_value=ticket.fencing_value,
    )
    permit_request = _permit_request()
    permit_view = _permit_view()
    return [
        (
            ArtifactRef,
            _artifact().model_dump(),
            ("repository_version", "byte_length"),
        ),
        (
            ReplayJobPayload,
            job.payload,
            ("attempt", "fencing_value"),
        ),
        (
            ReplayClaimRequest,
            ReplayClaimRequest(executor_profile="kisa-exact-v1").model_dump(),
            ("lease_seconds",),
        ),
        (
            ReplayLeaseRequest,
            lease.model_dump(),
            ("lease_seconds", "fencing_value"),
        ),
        (
            ReplayToolPermitRequest,
            permit_request.model_dump(),
            ("fencing_value", "call_ordinal"),
        ),
        (ReplayBatchView, batch.model_dump(), ("cas_version",)),
        (
            ReplayItemView,
            item.model_dump(),
            ("required_attempts", "max_attempts", "attempts"),
        ),
        (
            ReplayTicketView,
            ticket.model_dump(),
            ("attempt", "fencing_value"),
        ),
        (
            ReplayToolPermitView,
            permit_view.model_dump(),
            (
                "attempt",
                "fencing_value",
                "call_ordinal",
                "tool_call_units",
                "request_units",
            ),
        ),
    ]


def test_internal_replay_kind_is_not_a_public_job_kind() -> None:
    assert InternalJobKind.REPLAY.value == "internal-replay"
    assert {kind.value for kind in JobKind} == {"campaign", "tool-loop"}

    request = ClaimJobRequest(worker_id="worker-1", kinds=["campaign", "tool-loop"])
    assert request.kinds == [JobKind.CAMPAIGN, JobKind.TOOL_LOOP]

    with pytest.raises(ValidationError):
        ClaimJobRequest(worker_id="worker-1", kinds=[InternalJobKind.REPLAY.value])


def test_artifact_ref_is_strict_immutable_repository_metadata() -> None:
    artifact = _artifact()

    with pytest.raises(ValidationError, match="frozen"):
        artifact.byte_length = 8_192
    with pytest.raises(ValidationError):
        _artifact(content_digest="A" * 64)
    with pytest.raises(ValidationError):
        ArtifactRef.model_validate({**artifact.model_dump(), "path": "/tmp/untrusted"})


def test_artifact_admission_and_replay_batch_accept_only_opaque_exact_locators() -> None:
    request = AdmitSourceArtifactRequest(
        staging_id=f"stage_{'1' * 32}",
        producer_run_id=f"run_{'2' * 32}",
        producer_job_id=f"job_{'3' * 32}",
        idempotency_key="artifact-admission-one",
    )
    assert request.staging_id == f"stage_{'1' * 32}"

    batch = _batch_request()
    assert batch.source == _locator()
    assert set(batch.source.model_dump()) == {"artifact_id", "repository_version"}

    with pytest.raises(ValidationError):
        AdmitSourceArtifactRequest.model_validate(
            {**request.model_dump(), "staging_id": "/tmp/untrusted"}
        )
    with pytest.raises(ValidationError):
        CreateReplayBatchRequest.model_validate(
            {**batch.model_dump(), "source": _artifact().model_dump()}
        )


@pytest.mark.parametrize("invalid_value", ["1", True])
def test_replay_authority_integers_do_not_coerce(invalid_value: object) -> None:
    for model_type, values, field_names in _authority_integer_cases():
        for field_name in field_names:
            with pytest.raises(ValidationError):
                model_type.model_validate({**values, field_name: invalid_value})


def test_replay_authority_integers_fit_postgresql_int4() -> None:
    out_of_range = 2_147_483_648

    for model_type, values, field_names in _authority_integer_cases():
        for field_name in field_names:
            with pytest.raises(ValidationError):
                model_type.model_validate({**values, field_name: out_of_range})


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("priority", "0"),
        ("priority", False),
        ("attempts", "1"),
        ("attempts", True),
        ("max_attempts", "1"),
        ("max_attempts", True),
    ],
)
def test_job_view_authority_integers_do_not_coerce(field_name: str, invalid_value: object) -> None:
    job = _claim_view_payload()["job"]
    assert isinstance(job, JobView)
    values = job.model_dump()
    values[field_name] = invalid_value

    with pytest.raises(ValidationError):
        JobView.model_validate(values)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("campaign_name", "caller-selected-campaign"),
        ("mode", CampaignMode.AI_REDTEAM.value),
        ("purpose", ReplayPurpose.CONFIRMATION.value),
        ("policy_version", "caller-policy-v1"),
        ("items", []),
        ("candidate_id", "candidate-kisa-m03-1"),
        ("candidate_digest", "1" * 64),
        ("candidate", {}),
        ("contract_digest", "d" * 64),
        ("contract", {}),
        ("compilation_digest", "e" * 64),
        ("compilation", {}),
        ("grant_digest", "f" * 64),
        ("grant", {}),
        ("run_path", "/tmp/untrusted-run"),
        ("path", "/tmp/untrusted-source"),
        ("source_path", "/tmp/untrusted-source"),
        ("url", "https://attacker.invalid/run.tar"),
        ("source_url", "https://attacker.invalid/run.tar"),
    ],
)
def test_create_replay_batch_rejects_caller_authored_authority(
    field_name: str, value: object
) -> None:
    request = _batch_request()
    assert set(request.model_dump()) == {
        "source",
        "retest_source",
        "claim_projection",
        "portable_attestation",
        "target_attestation",
        "idempotency_key",
    }

    with pytest.raises(ValidationError):
        CreateReplayBatchRequest.model_validate({**request.model_dump(), field_name: value})


def test_create_replay_batch_target_attestation_requires_portable_claim_projection() -> None:
    with pytest.raises(
        ValidationError,
        match="target attestation requires portable Replay attestation",
    ):
        _batch_request(claim_projection=True, target_attestation=True)

    request = _batch_request(
        claim_projection=True,
        portable_attestation=True,
        target_attestation=True,
    )
    assert request.target_attestation is True


def test_create_replay_batch_requires_distinct_optional_retest_source() -> None:
    request = _batch_request(
        retest_source=_locator(artifact_id=f"artifact_{'b' * 32}"),
    )
    assert request.retest_source is not None
    assert request.retest_source != request.source

    with pytest.raises(ValidationError, match="must be distinct"):
        _batch_request(retest_source=_locator())


def test_replay_claim_and_lease_requests_use_authenticated_actor_identity() -> None:
    claim = ReplayClaimRequest(executor_profile="kisa-exact-v1", lease_seconds=45)
    assert "worker_id" not in claim.model_fields_set

    lease = ReplayLeaseRequest(
        executor_profile="kisa-exact-v1",
        lease_token="lease-token-that-is-at-least-32-characters",
        lease_seconds=45,
        ticket_id=f"replay-ticket_{'3' * 32}",
        fencing_value=7,
    )
    assert lease.fencing_value == 7

    with pytest.raises(ValidationError):
        ReplayClaimRequest.model_validate(
            {
                "worker_id": "body-controlled-worker",
                "executor_profile": "kisa-exact-v1",
            }
        )
    with pytest.raises(ValidationError):
        ReplayLeaseRequest.model_validate(
            {
                **lease.model_dump(),
                "worker_id": "body-controlled-worker",
            }
        )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("worker_id", "body-controlled-worker"),
        ("lease_seconds", 60),
        ("idempotency_key", "caller-selected-key"),
        ("tool_id", "caller-selected-tool"),
        ("target", "https://caller.invalid"),
        ("method", "DELETE"),
        ("arguments", {"caller": "selected"}),
        ("request_units", 1),
        ("compilation_id", f"replay-compilation_{'a' * 32}"),
    ],
)
def test_replay_tool_permit_request_accepts_only_lease_identity_and_ordinal(
    field_name: str,
    value: object,
) -> None:
    request = _permit_request()
    assert set(request.model_dump()) == {
        "executor_profile",
        "lease_token",
        "ticket_id",
        "fencing_value",
        "call_ordinal",
    }

    with pytest.raises(ValidationError):
        ReplayToolPermitRequest.model_validate({**request.model_dump(), field_name: value})


@pytest.mark.parametrize("call_ordinal", [0, 21])
def test_replay_tool_permit_request_uses_bounded_one_based_ordinal(call_ordinal: int) -> None:
    with pytest.raises(ValidationError):
        _permit_request(call_ordinal=call_ordinal)


def test_replay_tool_permit_view_is_immutable_canonical_and_non_bearer() -> None:
    permit = _permit_view()
    assert permit.method == "POST"
    assert permit.tool_call_units == 1
    assert permit.request_units == 3
    assert set(permit.model_dump()) == {
        "permit_id",
        "permit_digest",
        "replay_request_id",
        "job_id",
        "batch_id",
        "item_id",
        "ticket_id",
        "compilation_id",
        "budget_reservation_id",
        "rate_reservation_id",
        "replay_run_id",
        "attempt",
        "fencing_value",
        "call_ordinal",
        "issued_to",
        "executor_profile",
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
    }

    with pytest.raises(ValidationError, match="frozen"):
        permit.call_ordinal = 2
    for field_name in ("lease_token", "lease_token_hash", "permit_token", "arguments"):
        with pytest.raises(ValidationError):
            ReplayToolPermitView.model_validate(
                {**permit.model_dump(), field_name: "must-not-be-exposed"}
            )


def test_replay_tool_permit_view_rejects_a_foreign_target_challenge() -> None:
    permit = _permit_view()
    challenge = derive_target_execution_challenge(
        permit_digest=permit.permit_digest,
        replay_request_id=permit.replay_request_id,
        batch_id=permit.batch_id,
        item_id=permit.item_id,
        ticket_id=permit.ticket_id,
        fencing_value=permit.fencing_value,
        call_ordinal=permit.call_ordinal,
        target=permit.target,
        method=permit.method,
        compiled_argument_digest=permit.compiled_argument_digest,
        issued_at=permit.issued_at,
        expires_at=permit.expires_at,
    )
    bound = _permit_view(target_execution_challenge=challenge)
    assert bound.target_execution_challenge == challenge

    with pytest.raises(
        ValidationError,
        match=r"target execution challenge.*inconsistent",
    ):
        _permit_view(
            target_execution_challenge=challenge.model_copy(update={"permit_digest": "d" * 64})
        )


@pytest.mark.parametrize(
    "updates",
    [
        {"issued_at": NOW.replace(tzinfo=None)},
        {"expires_at": (NOW + timedelta(seconds=15)).replace(tzinfo=None)},
        {"expires_at": NOW},
        {"expires_at": NOW + timedelta(seconds=31)},
    ],
)
def test_replay_tool_permit_view_requires_short_aware_positive_lifetime(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _permit_view(**updates)


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("permit_id", f"replay-permit_{'A' * 32}"),
        ("permit_digest", "A" * 64),
        ("replay_request_id", f"tool_replay_{'A' * 32}"),
        ("source_root_digest", "A" * 64),
        ("compiled_argument_digest", "A" * 64),
        ("tool_call_units", 2),
        ("request_units", 101),
    ],
)
def test_replay_tool_permit_view_rejects_noncanonical_authority(
    field_name: str,
    invalid_value: object,
) -> None:
    with pytest.raises(ValidationError):
        _permit_view(**{field_name: invalid_value})


def test_replay_claim_view_binds_job_batch_item_ticket_attempt_and_fence() -> None:
    payload = _claim_view_payload()
    claim = ReplayClaimView.model_validate(payload)
    assert claim.ticket.state is ReplayTicketState.CLAIMED
    assert claim.ticket.claimed_by == "worker-service"
    assert claim.ticket.fencing_value == 7
    assert claim.job.lease_owner == claim.ticket.claimed_by
    assert claim.job.lease_expires_at == claim.ticket.lease_expires_at
    assert claim.job.attempts == claim.job.max_attempts == 1
    assert claim.job.payload["compilation_id"] == claim.ticket.compilation_id
    assert claim.job.payload["execution_context_id"].startswith("replay-context_")
    assert len(claim.job.payload["execution_context_digest"]) == 64
    assert claim.job.payload["budget_reservation_id"] == claim.ticket.budget_reservation_id
    assert claim.job.payload["rate_reservation_id"] == claim.ticket.rate_reservation_id

    wrong_ticket = claim.ticket.model_copy(update={"item_id": f"replay-item_{'9' * 32}"})
    with pytest.raises(ValidationError, match="ticket and item IDs must match"):
        ReplayClaimView.model_validate({**payload, "ticket": wrong_ticket})

    wrong_job = claim.job.model_copy(update={"kind": JobKind.CAMPAIGN.value})
    with pytest.raises(ValidationError, match="internal Replay Job"):
        ReplayClaimView.model_validate({**payload, "job": wrong_job})


def test_replay_execution_claim_binds_exact_compilation_and_context(
    execution_claim_payload: dict[str, object],
) -> None:
    claim = ReplayExecutionClaimView.model_validate(execution_claim_payload)

    assert claim.execution_context.context_id == claim.job.payload["execution_context_id"]
    assert claim.execution_context_digest == replay_execution_context_digest(
        claim.execution_context
    )
    assert claim.execution_context.campaign.metadata.name == claim.batch.campaign_name
    assert (
        claim.execution_context.scenario.scenario_id == claim.compilation.spec.binding.scenario_id
    )
    assert claim.execution_context.tool_spec.tool_id == claim.compilation.spec.binding.tool_id
    assert claim.execution_context.required_executor_profile == claim.ticket.executor_profile


@pytest.mark.parametrize("field_name", ["execution_context_id", "execution_context_digest"])
def test_replay_job_payload_requires_execution_context_authority(
    field_name: str,
) -> None:
    job = _claim_view_payload()["job"]
    assert isinstance(job, JobView)
    missing = dict(job.payload)
    missing.pop(field_name)

    with pytest.raises(ValidationError):
        ReplayJobPayload.model_validate(missing)
    with pytest.raises(ValidationError):
        ReplayJobPayload.model_validate(
            {
                **job.payload,
                field_name: (
                    f"replay-context_{'A' * 32}"
                    if field_name == "execution_context_id"
                    else "A" * 64
                ),
            }
        )


def test_replay_execution_claim_rejects_context_tamper(
    execution_claim_payload: dict[str, object],
) -> None:
    context = execution_claim_payload["execution_context"]
    job = execution_claim_payload["job"]
    assert isinstance(context, ReplayExecutionContext)
    assert isinstance(job, JobView)
    forged_context = context.model_copy(update={"policy_version": "forged-policy-v1"})
    forged_digest = replay_execution_context_digest(forged_context)
    forged_job = job.model_copy(
        update={
            "payload": {
                **job.payload,
                "execution_context_digest": forged_digest,
            }
        }
    )

    with pytest.raises(ValidationError, match="execution context authority binding"):
        ReplayExecutionClaimView.model_validate(
            {
                **execution_claim_payload,
                "job": forged_job,
                "execution_context": forged_context,
                "execution_context_digest": forged_digest,
            }
        )


def test_replay_execution_claim_rejects_context_digest_tamper(
    execution_claim_payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="execution context authority binding"):
        ReplayExecutionClaimView.model_validate(
            {
                **execution_claim_payload,
                "execution_context_digest": "0" * 64,
            }
        )


def test_replay_execution_claim_rejects_context_id_tamper(
    execution_claim_payload: dict[str, object],
) -> None:
    job = execution_claim_payload["job"]
    assert isinstance(job, JobView)
    forged_job = job.model_copy(
        update={
            "payload": {
                **job.payload,
                "execution_context_id": f"replay-context_{'0' * 32}",
            }
        }
    )

    with pytest.raises(ValidationError, match="execution context authority binding"):
        ReplayExecutionClaimView.model_validate({**execution_claim_payload, "job": forged_job})


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("compilation_id", f"replay-compilation_{'A' * 32}"),
        ("budget_reservation_id", f"budget-reservation_{'B' * 32}"),
        ("rate_reservation_id", f"rate-reservation_{'C' * 32}"),
    ],
)
def test_replay_ticket_and_job_payload_require_exact_issuance_authority_ids(
    field_name: str,
    invalid_value: str,
) -> None:
    payload = _claim_view_payload()
    job = payload["job"]
    ticket = payload["ticket"]
    assert isinstance(job, JobView)
    assert isinstance(ticket, ReplayTicketView)

    missing_ticket_values = ticket.model_dump()
    missing_ticket_values.pop(field_name)
    with pytest.raises(ValidationError):
        ReplayTicketView.model_validate(missing_ticket_values)
    with pytest.raises(ValidationError):
        ReplayTicketView.model_validate({**ticket.model_dump(), field_name: invalid_value})

    missing_payload_values = dict(job.payload)
    missing_payload_values.pop(field_name)
    with pytest.raises(ValidationError):
        ReplayJobPayload.model_validate(missing_payload_values)
    with pytest.raises(ValidationError):
        ReplayJobPayload.model_validate({**job.payload, field_name: invalid_value})


@pytest.mark.parametrize(
    "field_name",
    ["compilation_id", "budget_reservation_id", "rate_reservation_id"],
)
def test_replay_claim_view_binds_job_payload_to_ticket_issuance_authority(
    field_name: str,
) -> None:
    payload = _claim_view_payload()
    job = payload["job"]
    assert isinstance(job, JobView)
    forged_payload = {
        **job.payload,
        field_name: {
            "compilation_id": f"replay-compilation_{'8' * 32}",
            "budget_reservation_id": f"budget-reservation_{'8' * 32}",
            "rate_reservation_id": f"rate-reservation_{'8' * 32}",
        }[field_name],
    }

    with pytest.raises(ValidationError, match="payload authority binding is inconsistent"):
        ReplayClaimView.model_validate(
            {**payload, "job": job.model_copy(update={"payload": forged_payload})}
        )


def test_replay_batch_issuance_view_binds_the_exact_item_ticket_set() -> None:
    payload = _claim_view_payload()
    batch = payload["batch"]
    item = payload["item"]
    ticket = payload["ticket"]
    assert isinstance(batch, ReplayBatchView)
    assert isinstance(item, ReplayItemView)
    assert isinstance(ticket, ReplayTicketView)

    issuance = ReplayBatchIssuanceView(batch=batch, items=[item], tickets=[ticket])
    assert issuance.items[0].item_id == issuance.tickets[0].item_id

    with pytest.raises(ValidationError, match="cover the exact item set"):
        ReplayBatchIssuanceView(
            batch=batch,
            items=[item],
            tickets=[ticket.model_copy(update={"item_id": f"replay-item_{'8' * 32}"})],
        )
    with pytest.raises(ValidationError, match="Replay Run IDs must match"):
        ReplayBatchIssuanceView(
            batch=batch,
            items=[item],
            tickets=[ticket.model_copy(update={"replay_run_id": "run_other"})],
        )
    with pytest.raises(ValidationError, match="attempt must match"):
        ReplayBatchIssuanceView(
            batch=batch,
            items=[item],
            tickets=[ticket.model_copy(update={"attempt": 2})],
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"lease_owner": "other-worker"}, "principals must match"),
        (
            {"lease_expires_at": NOW + timedelta(seconds=31)},
            "lease deadlines must match",
        ),
        ({"attempts": 2}, "Job attempts must equal one"),
        ({"max_attempts": 2}, "Job max attempts must equal one"),
    ],
)
def test_replay_claim_view_rejects_misaligned_job_authority(
    updates: dict[str, object], message: str
) -> None:
    payload = _claim_view_payload()
    job = payload["job"]
    assert isinstance(job, JobView)

    with pytest.raises(ValidationError, match=message):
        ReplayClaimView.model_validate({**payload, "job": job.model_copy(update=updates)})


def test_replay_claim_view_requires_live_batch_and_item_states() -> None:
    payload = _claim_view_payload()
    batch = payload["batch"]
    item = payload["item"]
    assert isinstance(batch, ReplayBatchView)
    assert isinstance(item, ReplayItemView)

    with pytest.raises(ValidationError, match="batch must be running"):
        ReplayClaimView.model_validate(
            {
                **payload,
                "batch": batch.model_copy(update={"state": ReplayBatchState.CANCELLED}),
            }
        )

    with pytest.raises(ValidationError, match="item must be running"):
        ReplayClaimView.model_validate(
            {
                **payload,
                "item": item.model_copy(update={"state": ReplayItemState.RETRY_PENDING}),
            }
        )


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("attempts", "1"),
        ("attempts", True),
        ("max_attempts", "1"),
        ("max_attempts", True),
    ],
)
def test_replay_claim_view_does_not_inherit_generic_job_integer_coercion(
    field_name: str, invalid_value: object
) -> None:
    payload = _claim_view_payload()
    job = payload["job"]
    assert isinstance(job, JobView)
    job_values = job.model_dump()
    job_values[field_name] = invalid_value

    with pytest.raises(ValidationError, match="must be a strict integer"):
        ReplayClaimView.model_validate({**payload, "job": job_values})


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("priority", True),
        ("attempts", True),
        ("max_attempts", "1"),
    ],
)
def test_replay_claim_view_rejects_preconstructed_job_integer_bypass(
    field_name: str, invalid_value: object
) -> None:
    payload = _claim_view_payload()
    job = payload["job"]
    assert isinstance(job, JobView)
    forged_job = job.model_copy(update={field_name: invalid_value})

    with pytest.raises(ValidationError, match="authority fields must be strict integers"):
        ReplayClaimView.model_validate({**payload, "job": forged_job})


def test_replay_claim_view_accepts_new_job_for_later_ticket_attempt() -> None:
    payload = _claim_view_payload()
    job = payload["job"]
    item = payload["item"]
    ticket = payload["ticket"]
    assert isinstance(job, JobView)
    assert isinstance(item, ReplayItemView)
    assert isinstance(ticket, ReplayTicketView)

    later_attempt = 2
    later_job_id = f"job_{'5' * 32}"
    later_ticket_id = f"replay-ticket_{'6' * 32}"
    later_compilation_id = f"replay-compilation_{'7' * 32}"
    later_budget_reservation_id = f"budget-reservation_{'8' * 32}"
    later_rate_reservation_id = f"rate-reservation_{'9' * 32}"
    later_run_id = "run_20260717T120100Z_feedface"
    claim = ReplayClaimView.model_validate(
        {
            **payload,
            "job": job.model_copy(
                update={
                    "job_id": later_job_id,
                    "run_id": later_run_id,
                    "payload": {
                        **job.payload,
                        "ticket_id": later_ticket_id,
                        "compilation_id": later_compilation_id,
                        "budget_reservation_id": later_budget_reservation_id,
                        "rate_reservation_id": later_rate_reservation_id,
                        "replay_run_id": later_run_id,
                        "attempt": later_attempt,
                    },
                }
            ),
            "item": item.model_copy(
                update={"replay_run_id": later_run_id, "attempts": later_attempt}
            ),
            "ticket": ticket.model_copy(
                update={
                    "ticket_id": later_ticket_id,
                    "job_id": later_job_id,
                    "compilation_id": later_compilation_id,
                    "budget_reservation_id": later_budget_reservation_id,
                    "rate_reservation_id": later_rate_reservation_id,
                    "replay_run_id": later_run_id,
                    "attempt": later_attempt,
                }
            ),
        }
    )

    assert claim.ticket.attempt == claim.item.attempts == later_attempt
    assert claim.job.attempts == claim.job.max_attempts == 1
    assert claim.ticket.job_id == claim.job.job_id == later_job_id
    assert claim.ticket.replay_run_id == claim.job.run_id == later_run_id


def test_claimed_ticket_view_requires_principal_profile_and_lease_expiry() -> None:
    payload = _claim_view_payload()
    ticket = payload["ticket"]
    assert isinstance(ticket, ReplayTicketView)

    values = ticket.model_dump()
    values["claimed_by"] = None
    with pytest.raises(ValidationError, match="requires principal"):
        ReplayTicketView.model_validate(values)


def test_replay_state_contracts_cover_terminal_authority_states() -> None:
    assert {state.value for state in ReplayBatchState} == {
        "planned",
        "running",
        "gating",
        "completed",
        "failed",
        "cancelled",
    }
    assert "retry-pending" in {state.value for state in ReplayItemState}
    assert {state.value for state in ReplayTicketState} == {
        "issued",
        "claimed",
        "finalized",
        "abandoned",
    }
