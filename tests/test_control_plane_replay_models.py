from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel, ValidationError

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
)
from pajin.domain.models import CampaignMode
from pajin.domain.replay import ReplayPurpose

NOW = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)


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


def _claim_view_payload() -> dict[str, object]:
    batch_id = f"replay-batch_{'1' * 32}"
    item_id = f"replay-item_{'2' * 32}"
    ticket_id = f"replay-ticket_{'3' * 32}"
    job_id = f"job_{'4' * 32}"
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
    assert set(request.model_dump()) == {"source", "idempotency_key"}

    with pytest.raises(ValidationError):
        CreateReplayBatchRequest.model_validate({**request.model_dump(), field_name: value})


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


def test_replay_claim_view_binds_job_batch_item_ticket_attempt_and_fence() -> None:
    payload = _claim_view_payload()
    claim = ReplayClaimView.model_validate(payload)
    assert claim.ticket.state is ReplayTicketState.CLAIMED
    assert claim.ticket.claimed_by == "worker-service"
    assert claim.ticket.fencing_value == 7
    assert claim.job.lease_owner == claim.ticket.claimed_by
    assert claim.job.lease_expires_at == claim.ticket.lease_expires_at
    assert claim.job.attempts == claim.job.max_attempts == 1

    wrong_ticket = claim.ticket.model_copy(update={"item_id": f"replay-item_{'9' * 32}"})
    with pytest.raises(ValidationError, match="ticket and item IDs must match"):
        ReplayClaimView.model_validate({**payload, "ticket": wrong_ticket})

    wrong_job = claim.job.model_copy(update={"kind": JobKind.CAMPAIGN.value})
    with pytest.raises(ValidationError, match="internal Replay Job"):
        ReplayClaimView.model_validate({**payload, "job": wrong_job})


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
