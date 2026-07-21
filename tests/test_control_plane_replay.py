from __future__ import annotations

import asyncio
import json
import shutil
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Barrier
from types import SimpleNamespace
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import pytest
from fastapi.testclient import TestClient
from kisa_control_plane_support import SupportingKISAWorker, build_kisa_control_plane_source
from pydantic import ValidationError
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

import pajin.control_plane.replay_authority as replay_authority_module
import pajin.control_plane.service as control_plane_service_module
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.artifacts import ManagedArtifactRepository
from pajin.control_plane.client import (
    ControlPlaneLeaseLost,
    ControlPlaneLocalLeaseDeadlineExceeded,
    ControlPlaneProtocolError,
    ControlPlaneRunCancelled,
    ControlPlaneTransientError,
)
from pajin.control_plane.database import (
    ArtifactRecord,
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayBudgetAccountRecord,
    ReplayBudgetReservationRecord,
    ReplayCompilationRecord,
    ReplayEventRecord,
    ReplayExecutionContextRecord,
    ReplayFinalizationRecord,
    ReplayItemRecord,
    ReplayRateAccountRecord,
    ReplayRateReservationRecord,
    ReplayTicketRecord,
    ReplayToolPermitRecord,
    RunRecord,
)
from pajin.control_plane.kisa_derivation import (
    KISA_CONFIRMATION_MAX_ATTEMPTS,
    KISA_CONFIRMATION_POLICY_VERSION,
    KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
)
from pajin.control_plane.lease_deadline import MonotonicLeaseDeadline
from pajin.control_plane.models import (
    AdmitSourceArtifactRequest,
    ApprovalIntent,
    ArtifactLocator,
    ArtifactRef,
    CancelRunRequest,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    CreateReplayBatchRequest,
    FailJobRequest,
    InternalJobKind,
    JobState,
    LeaseRequest,
    Principal,
    PrincipalRole,
    ReplayBatchIssuanceView,
    ReplayBatchState,
    ReplayClaimRequest,
    ReplayExecutionClaimView,
    ReplayExecutionContext,
    ReplayFinalizationView,
    ReplayFinalizeRequest,
    ReplayItemState,
    ReplayJobPayload,
    ReplayLeaseRequest,
    ReplayTicketState,
    ReplayToolPermitRequest,
    RunState,
    SubmitRunRequest,
    canonical_replay_execution_context_bytes,
    job_submission_authority_digest,
    non_replayable_submission_authority_digest,
    replay_execution_component_digest,
    replay_execution_context_digest,
)
from pajin.control_plane.replay_executor import KISAExactReplayExecutor
from pajin.control_plane.replay_worker import (
    ReplayWorkerConfig,
    ReplayWorkerDaemon,
    ReplayWorkerStatus,
)
from pajin.control_plane.security import CheckpointSigner, token_digest
from pajin.control_plane.service import (
    ControlPlaneService,
    LeaseRejected,
    ResourceNotFound,
    RunCancelled,
    StateConflict,
)
from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.domain.replay import ReplayCompilation, ReplayPurpose
from pajin.domain.validation import FindingDisposition, ValidationDecision, ValidationReasonCode
from pajin.replay.tickets import canonical_replay_compilation_bytes, replay_context_digest
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.runtime.worker import DockerWorkerBackend, WorkerJob, WorkerResult
from pajin.tools.ai import AI_CHAT_PROXY_RECEIPT_VERSION, AIChatProbeTool

OPERATOR_TOKEN = "replay-operator-token-that-is-long-and-distinct"
APPROVER_TOKEN = "replay-approver-token-that-is-long-and-distinct"
AUDITOR_TOKEN = "replay-auditor-token-that-is-long-and-distinct"
WORKER_TOKEN = "replay-worker-token-that-is-long-and-distinct"
OTHER_WORKER_TOKEN = "other-replay-worker-token-that-is-long-and-distinct"
EXECUTOR_PROFILE = "kisa-exact-v1"
REGISTERED_REPLAY_ACTORS = frozenset(
    {
        "replay-worker-a",
        "authenticated-worker-a",
        "authenticated-worker-b",
        "race-worker-a",
        "race-worker-b",
        "heartbeat-worker",
        "stale-worker",
        "expired-worker",
        "replacement-worker",
        "cancelled-worker",
    }
)


class _ReplayServicePort:
    def __init__(self, service: ControlPlaneService, *, actor: str) -> None:
        self._service = service
        self._actor = actor

    async def issue_replay_tool_permit(
        self,
        job_id: str,
        request: ReplayToolPermitRequest,
    ):
        return self._service.issue_replay_tool_permit(
            job_id,
            request,
            actor=self._actor,
        )


class _ReplayDaemonServicePort(_ReplayServicePort):
    def __init__(
        self,
        service: ControlPlaneService,
        *,
        actor: str,
        permit_transient_failures_before_server: int = 0,
        drop_first_permit_response: bool = False,
        drop_first_finalize_response: bool = False,
        mutate_retained_claim: bool = False,
        transient_error_detail: str = "permit transport unavailable before response",
    ) -> None:
        super().__init__(service, actor=actor)
        self._service = service
        self._actor = actor
        self.permit_transient_failures_before_server = permit_transient_failures_before_server
        self.drop_first_permit_response = drop_first_permit_response
        self.drop_first_finalize_response = drop_first_finalize_response
        self.mutate_retained_claim = mutate_retained_claim
        self.transient_error_detail = transient_error_detail
        self.claimed: ReplayExecutionClaimView | None = None
        self.original_claim: ReplayExecutionClaimView | None = None
        self.heartbeat_calls = 0
        self.permit_calls = 0
        self.finalize_calls = 0
        self.heartbeat_job_ids: list[str] = []
        self.permit_job_ids: list[str] = []
        self.finalize_job_ids: list[str] = []
        self.finalizing_statuses: list[ReplayWorkerStatus] = []
        self.status_path: Path | None = None

    async def claim_replay(
        self,
        request: ReplayClaimRequest,
    ) -> ReplayExecutionClaimView | None:
        self.claimed = self._service.claim_replay_job(
            request,
            actor=self._actor,
        )
        if self.claimed is not None:
            self.original_claim = self.claimed.model_copy(deep=True)
            if self.mutate_retained_claim:
                asyncio.get_running_loop().call_soon(self._retarget_retained_claim)
        return self.claimed

    def _retarget_retained_claim(self) -> None:
        assert self.claimed is not None
        self.claimed.job.job_id = f"job_{'f' * 32}"
        self.claimed.lease_token = "m" * 43

    async def heartbeat_replay(
        self,
        job_id: str,
        request: ReplayLeaseRequest,
    ) -> ReplayExecutionClaimView:
        self.heartbeat_calls += 1
        self.heartbeat_job_ids.append(job_id)
        try:
            return self._service.heartbeat_replay_job(
                job_id,
                request,
                actor=self._actor,
            )
        except RunCancelled as exc:
            raise ControlPlaneRunCancelled(str(exc)) from exc
        except (LeaseRejected, StateConflict) as exc:
            raise ControlPlaneLeaseLost(str(exc)) from exc

    async def issue_replay_tool_permit(
        self,
        job_id: str,
        request: ReplayToolPermitRequest,
    ):
        self.permit_calls += 1
        self.permit_job_ids.append(job_id)
        if self.permit_calls <= self.permit_transient_failures_before_server:
            raise ControlPlaneTransientError(self.transient_error_detail)
        result = self._service.issue_replay_tool_permit(
            job_id,
            request,
            actor=self._actor,
        )
        if self.drop_first_permit_response and self.permit_calls == 1:
            raise ControlPlaneTransientError("response dropped after permit commit")
        return result

    async def finalize_replay(
        self,
        job_id: str,
        request: ReplayFinalizeRequest,
    ):
        self.finalize_calls += 1
        self.finalize_job_ids.append(job_id)
        if self.status_path is not None:
            self.finalizing_statuses.append(
                ReplayWorkerStatus.model_validate_json(self.status_path.read_text(encoding="utf-8"))
            )
        result = self._service.finalize_replay_job(
            job_id,
            request,
            actor=self._actor,
        )
        if self.drop_first_finalize_response and self.finalize_calls == 1:
            raise ControlPlaneTransientError("response dropped after finalization commit")
        return result


def _canonical_json_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode()
    ).hexdigest()


def _host_proxy_receipt_log(job: WorkerJob, result: WorkerResult) -> str:
    payload = json.loads(job.stdin)
    output = json.loads(result.stdout)
    probe = payload["probe"]
    parsed_target = urlsplit(payload["target"])
    redacted_target = urlunsplit(
        (
            parsed_target.scheme,
            parsed_target.netloc,
            parsed_target.path,
            "<redacted>" if parsed_target.query else "",
            "",
        )
    )
    events = [json.dumps({"event": "ready", "port": 8080}, separators=(",", ":"))]
    for index, (turn, observed) in enumerate(zip(probe["turns"], output["turns"], strict=True)):
        request_body = {
            "sessionId": probe["session_id"],
            "messages": turn["messages"],
            "metadata": {"scenarioId": probe["scenario_id"], "turn": index},
        }
        events.append(
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": AI_CHAT_PROXY_RECEIPT_VERSION,
                    "sequence": index + 1,
                    "method": "POST",
                    "target": redacted_target,
                    "targetSha256": sha256(payload["target"].encode()).hexdigest(),
                    "address": "172.17.0.1",
                    "status": 200,
                    "requestJsonSha256": _canonical_json_digest(request_body),
                    "responseBodySha256": _canonical_json_digest(observed["response"]),
                    "responseJsonSha256": _canonical_json_digest(observed["response"]),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(events)


def _trusted_replay_backend() -> DockerWorkerBackend:
    transcript_worker = SupportingKISAWorker()
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})

    async def run(job: WorkerJob, *, secrets: object = None) -> WorkerResult:
        del secrets
        result = await transcript_worker.run(job)
        return result.model_copy(
            update={
                "backend": DockerWorkerBackend.name,
                "network_log": _host_proxy_receipt_log(job, result),
            }
        )

    backend.run = run  # type: ignore[method-assign]
    return backend


def _settings(path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{path.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="replay-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="replay-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"replay-v1": b"replay-test-signing-key-at-least-32-bytes"},
        active_checkpoint_key_id="replay-v1",
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _service(
    path: Path,
    *,
    replay_executor_profiles: dict[str, frozenset[str]] | None = None,
) -> tuple[ControlPlaneRepository, ControlPlaneService]:
    repository = ControlPlaneRepository(f"sqlite:///{path.as_posix()}")
    repository.initialize()
    signer = CheckpointSigner(
        active_key_id="replay-v1",
        keys={"replay-v1": b"replay-test-signing-key-at-least-32-bytes"},
    )
    profiles = replay_executor_profiles
    if profiles is None:
        profiles = {actor: frozenset({EXECUTOR_PROFILE}) for actor in REGISTERED_REPLAY_ACTORS}
    staging_root, artifact_root = _artifact_roots(path)
    return repository, ControlPlaneService(
        repository,
        signer,
        replay_executor_profiles=profiles,
        artifact_repository=ManagedArtifactRepository(
            staging_root=staging_root,
            repository_root=artifact_root,
        ),
    )


def _disable_sqlite_job_update_authority_guard(session: Session) -> None:
    """Expose the service-level binding check behind the normal database guard."""

    session.execute(text("DROP TRIGGER cp_jobs_lease_authority_guard_update"))


def _disable_sqlite_replay_authority_update_guard(
    session: Session,
    *,
    table_name: str,
) -> None:
    """Inject a damaged append-only row to exercise the service trust boundary."""

    assert table_name in {
        ReplayCompilationRecord.__tablename__,
        ReplayExecutionContextRecord.__tablename__,
    }
    session.execute(text(f"DROP TRIGGER {table_name}_no_update"))


def _artifact_roots(database_path: Path) -> tuple[Path, Path]:
    stem = database_path.name.replace(".", "-")
    return (
        database_path.parent / f"{stem}-artifact-staging",
        database_path.parent / f"{stem}-artifact-repository",
    )


def _seed_completed_source(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    suffix: str,
    *,
    item_count: int = 1,
) -> ArtifactRef:
    request = _stage_completed_source(repository, suffix, item_count=item_count)
    return service.admit_source_artifact(
        request,
        actor="trusted-source-admission",
    )


def _stage_completed_source(
    repository: ControlPlaneRepository,
    suffix: str,
    *,
    item_count: int = 1,
) -> AdmitSourceArtifactRequest:
    """Create one server-staged, completed producer fixture without admitting it."""

    identity = sha256(suffix.encode()).hexdigest()
    run_id = f"run_{identity[:32]}"
    job_id = f"job_{sha256(f'job:{suffix}'.encode()).hexdigest()[:32]}"
    stage_id = f"stage_{sha256(f'stage:{suffix}'.encode()).hexdigest()[:32]}"
    database_path = Path(str(repository.engine.url.database))
    staging_root, _ = _artifact_roots(database_path)
    stage_path = staging_root / stage_id
    fixture = build_kisa_control_plane_source(
        database_path.parent / f"{database_path.stem}-kisa-source-builds",
        scenario_count=item_count,
        producer_run_id=run_id,
    )
    shutil.copytree(fixture.path, stage_path)
    now = datetime.now(UTC)
    with repository.transaction() as session:
        run = RunRecord(
            run_id=run_id,
            campaign_name=fixture.campaign.metadata.name,
            state=RunState.COMPLETED.value,
            input={"sealedSource": True},
            submission_key=f"sealed-source-{identity}",
            submission_authority_digest=non_replayable_submission_authority_digest(
                run_id=run_id,
                authority_kind="sealed-source-fixture",
            ),
            current_checkpoint_id=None,
            created_at=now,
            updated_at=now,
        )
        session.add(run)
        session.flush()
        session.add(
            JobRecord(
                job_id=job_id,
                run_id=run_id,
                kind="campaign",
                state=JobState.SUCCEEDED.value,
                payload={"input": {}},
                priority=0,
                attempts=1,
                max_attempts=3,
                idempotency_key=f"sealed-source-job-{identity}",
                submission_authority_digest=job_submission_authority_digest(
                    job_id=job_id,
                    run_id=run_id,
                    job_kind="campaign",
                    payload={"input": {}},
                    max_attempts=3,
                    idempotency_key=f"sealed-source-job-{identity}",
                ),
                available_at=now,
                lease_owner=None,
                lease_token_hash=None,
                lease_expires_at=None,
                heartbeat_at=None,
                result={
                    "engineRunId": fixture.artifact_ref.run_id,
                    "runPath": "/ignored/untrusted",
                },
                error=None,
                created_at=now,
                updated_at=now,
            )
        )
    return AdmitSourceArtifactRequest(
        staging_id=stage_id,
        producer_run_id=run_id,
        producer_job_id=job_id,
        idempotency_key=f"artifact-admission-{suffix}",
    )


def _batch_request(
    source: ArtifactRef,
    suffix: str,
) -> CreateReplayBatchRequest:
    return CreateReplayBatchRequest(
        source=ArtifactLocator(
            artifact_id=source.artifact_id,
            repository_version=source.repository_version,
        ),
        idempotency_key=f"replay-batch-{suffix}",
    )


def _issue_planned_batch_for_state_machine_tests(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    request: CreateReplayBatchRequest,
    *,
    required_attempts: int,
    max_attempts: int,
) -> ReplayBatchIssuanceView:
    """Use production issuance, then tune only state-machine policy counts for tests."""

    with repository.transaction() as session:
        batch = session.scalar(
            select(ReplayBatchRecord).where(
                ReplayBatchRecord.idempotency_key == request.idempotency_key
            )
        )
        assert batch is not None
        assert batch.state == ReplayBatchState.PLANNED.value
        batch_id = batch.batch_id

    issued = service.issue_replay_batch(
        batch_id,
        actor="trusted-replay-admission",
    )
    if (
        required_attempts != KISA_CONFIRMATION_REQUIRED_ATTEMPTS
        or max_attempts != KISA_CONFIRMATION_MAX_ATTEMPTS
    ):
        with repository.transaction() as session:
            session.execute(
                update(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == batch_id)
                .values(
                    required_attempts=required_attempts,
                    max_attempts=max_attempts,
                )
            )
    return issued


def _create_batch(
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    suffix: str,
    *,
    required_attempts: int = 2,
    max_attempts: int = 3,
    item_count: int = 1,
) -> CreateReplayBatchRequest:
    request = _batch_request(
        _seed_completed_source(repository, service, suffix, item_count=item_count),
        suffix,
    )
    service.create_replay_batch(request, actor="trusted-replay-admission")
    _issue_planned_batch_for_state_machine_tests(
        repository,
        service,
        request,
        required_attempts=required_attempts,
        max_attempts=max_attempts,
    )
    return request


def _claim(service: ControlPlaneService, *, actor: str = "replay-worker-a"):
    claimed = service.claim_replay_job(
        ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE, lease_seconds=30),
        actor=actor,
    )
    assert claimed is not None
    return claimed


def _permit_request(claimed, call_ordinal: int) -> ReplayToolPermitRequest:
    return ReplayToolPermitRequest(
        executor_profile=EXECUTOR_PROFILE,
        lease_token=claimed.lease_token,
        ticket_id=claimed.ticket.ticket_id,
        fencing_value=claimed.ticket.fencing_value,
        call_ordinal=call_ordinal,
    )


def _force_replay_lease_expired(
    repository: ControlPlaneRepository,
    *,
    job_id: str,
    ticket_id: str,
) -> None:
    expired_at = datetime.now(UTC) - timedelta(seconds=1)
    with repository.transaction() as session:
        session.execute(
            update(JobRecord).where(JobRecord.job_id == job_id).values(lease_expires_at=expired_at)
        )
        session.execute(
            update(ReplayTicketRecord)
            .where(ReplayTicketRecord.ticket_id == ticket_id)
            .values(lease_expires_at=expired_at)
        )


def test_source_artifact_admission_is_managed_exact_and_idempotent(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "artifact-admission.db")
    suffix = "artifact-admission"
    identity = sha256(suffix.encode()).hexdigest()
    request = AdmitSourceArtifactRequest(
        staging_id=f"stage_{sha256(f'stage:{suffix}'.encode()).hexdigest()[:32]}",
        producer_run_id=f"run_{identity[:32]}",
        producer_job_id=f"job_{sha256(f'job:{suffix}'.encode()).hexdigest()[:32]}",
        idempotency_key=f"artifact-admission-{suffix}",
    )
    try:
        admitted = _seed_completed_source(repository, service, suffix)
        repeated = service.admit_source_artifact(
            request,
            actor="trusted-source-admission",
        )

        assert repeated == admitted
        assert admitted.producer_run_id == request.producer_run_id
        assert admitted.run_id != admitted.producer_run_id
        with repository.transaction() as session:
            artifact = session.scalar(select(ArtifactRecord))
            events = list(
                session.scalars(
                    select(EventRecord).where(EventRecord.event_type == "artifact.source-admitted")
                ).all()
            )
            assert artifact is not None
            assert artifact.producer_job_id == request.producer_job_id
            assert artifact.producer_attempt == 1
            assert artifact.sealed_run_id == admitted.run_id
            assert len(events) == 1
            exposed = f"{admitted.model_dump(mode='json')} {events[0].payload}"
            assert request.staging_id not in exposed
            assert artifact.storage_key not in exposed

        drifted = request.model_copy(update={"staging_id": f"stage_{'f' * 32}"})
        with pytest.raises(StateConflict, match="idempotency"):
            service.admit_source_artifact(
                drifted,
                actor="trusted-source-admission",
            )
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(EventRecord)
                    .where(EventRecord.event_type == "artifact.source-admitted")
                )
                == 1
            )
    finally:
        repository.close()


def test_artifact_admission_and_batch_fail_closed_without_managed_repository(
    tmp_path: Path,
) -> None:
    repository = ControlPlaneRepository(f"sqlite:///{(tmp_path / 'missing-repo.db').as_posix()}")
    repository.initialize()
    signer = CheckpointSigner(
        active_key_id="replay-v1",
        keys={"replay-v1": b"replay-test-signing-key-at-least-32-bytes"},
    )
    service = ControlPlaneService(repository, signer)
    try:
        with pytest.raises(StateConflict, match="repository is not configured"):
            service.admit_source_artifact(
                AdmitSourceArtifactRequest(
                    staging_id=f"stage_{'1' * 32}",
                    producer_run_id=f"run_{'2' * 32}",
                    producer_job_id=f"job_{'3' * 32}",
                    idempotency_key="missing-artifact-repository",
                ),
                actor="trusted-source-admission",
            )
        with pytest.raises(StateConflict, match="repository is not configured"):
            service.create_replay_batch(
                _batch_request(
                    ArtifactRef(
                        artifact_id=f"artifact_{'4' * 32}",
                        repository_version=1,
                        producer_run_id=f"run_{'2' * 32}",
                        media_type="application/vnd.pajin.run+directory",
                        schema_kind="pajin.run.sealed.v1",
                        byte_length=1,
                        content_digest="5" * 64,
                        run_id="sealed-run",
                        integrity_root_digest="6" * 64,
                        created_by="trusted-source-admission",
                    ),
                    "missing-repository",
                ),
                actor="trusted-replay-admission",
            )
    finally:
        repository.close()


@pytest.mark.parametrize("job_kind", ["replay", InternalJobKind.REPLAY.value])
def test_public_api_rejects_replay_job_injection_and_exposes_bounded_replay_routes(
    tmp_path: Path,
    job_kind: str,
) -> None:
    app = create_app(_settings(tmp_path / f"public-{job_kind}.db"))
    with TestClient(app) as client:
        response = client.post(
            "/v1/runs",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "campaign_name": "public-replay-injection",
                "input": {"runPath": "/tmp/untrusted", "verdict": "confirmed"},
                "idempotency_key": f"public-replay-{job_kind}",
                "job_kind": job_kind,
            },
        )
        assert response.status_code == 422
        generic_claim = client.post(
            "/v1/worker/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={
                "worker_id": "body-controlled-worker",
                "kinds": [job_kind],
                "lease_seconds": 30,
            },
        )
        assert generic_claim.status_code == 422
        paths = app.openapi()["paths"]
        assert {path for path in paths if path.startswith("/v1/replay")} == {
            "/v1/replay/source-artifacts",
            "/v1/replay/batches",
            "/v1/replay/batches/{batch_id}",
            "/v1/replay/items/{item_id}",
            "/v1/replay/tickets/{ticket_id}",
            "/v1/replay/tickets/{ticket_id}/finalization",
        }
        assert set(path for path in paths if path.startswith("/v1/worker/replay/")) == {
            "/v1/worker/replay/jobs/claim",
            "/v1/worker/replay/jobs/{job_id}/heartbeat",
            "/v1/worker/replay/jobs/{job_id}/tool-permits",
            "/v1/worker/replay/jobs/{job_id}/finalize",
        }

        with app.state.repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(RunRecord)) == 0
            assert session.scalar(select(func.count()).select_from(JobRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 0


def test_public_replay_admission_and_reads_are_opaque_role_scoped_and_idempotent(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "public-replay-admission.db"
    staging_root, artifact_root = _artifact_roots(database_path)
    base = _settings(database_path)
    settings = replace(
        base,
        credentials={
            **base.credentials,
            APPROVER_TOKEN: Principal(
                subject="replay-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            AUDITOR_TOKEN: Principal(
                subject="replay-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
        },
        artifact_staging_root=staging_root,
        artifact_repository_root=artifact_root,
    )
    app = create_app(settings)

    with TestClient(app) as client:
        admission_request = _stage_completed_source(
            app.state.repository,
            "public-replay-admission",
        )
        admission_body = admission_request.model_dump(mode="json")
        admitted = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(OPERATOR_TOKEN),
            json=admission_body,
        )
        repeated_admission = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(OPERATOR_TOKEN),
            json=admission_body,
        )
        rejected_worker_admission = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(WORKER_TOKEN),
            json=admission_body,
        )
        rejected_auditor_admission = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(AUDITOR_TOKEN),
            json=admission_body,
        )
        injected_admission = client.post(
            "/v1/replay/source-artifacts",
            headers=_auth(OPERATOR_TOKEN),
            json={**admission_body, "runPath": "/tmp/untrusted"},
        )

        assert admitted.status_code == 200, admitted.text
        assert repeated_admission.status_code == 200
        assert repeated_admission.json() == admitted.json()
        assert rejected_worker_admission.status_code == 403
        assert rejected_auditor_admission.status_code == 403
        assert injected_admission.status_code == 422
        serialized_admission = admitted.text
        assert admission_request.staging_id not in serialized_admission
        assert "runPath" not in serialized_admission
        assert "storageKey" not in serialized_admission

        source = ArtifactRef.model_validate(admitted.json())
        batch_request = CreateReplayBatchRequest(
            source=ArtifactLocator(
                artifact_id=source.artifact_id,
                repository_version=source.repository_version,
            ),
            idempotency_key="public-replay-batch-admission",
        )
        batch_body = batch_request.model_dump(mode="json")
        created = client.post(
            "/v1/replay/batches",
            headers=_auth(OPERATOR_TOKEN),
            json=batch_body,
        )
        repeated_batch = client.post(
            "/v1/replay/batches",
            headers=_auth(OPERATOR_TOKEN),
            json=batch_body,
        )
        injected_batch = client.post(
            "/v1/replay/batches",
            headers=_auth(OPERATOR_TOKEN),
            json={
                **batch_body,
                "candidate": {"id": "caller-authored"},
                "target": "https://attacker.invalid",
            },
        )
        rejected_auditor_batch = client.post(
            "/v1/replay/batches",
            headers=_auth(AUDITOR_TOKEN),
            json=batch_body,
        )

        assert created.status_code == 200, created.text
        assert repeated_batch.status_code == 200
        assert repeated_batch.json() == created.json()
        assert created.json()["state"] == ReplayBatchState.PLANNED.value
        assert created.json()["created_by"] == "replay-operator"
        assert injected_batch.status_code == 422
        assert rejected_auditor_batch.status_code == 403

        batch_id = created.json()["batch_id"]
        operator_read = client.get(
            f"/v1/replay/batches/{batch_id}",
            headers=_auth(OPERATOR_TOKEN),
        )
        auditor_read = client.get(
            f"/v1/replay/batches/{batch_id}",
            headers=_auth(AUDITOR_TOKEN),
        )
        approver_read = client.get(
            f"/v1/replay/batches/{batch_id}",
            headers=_auth(APPROVER_TOKEN),
        )
        worker_read = client.get(
            f"/v1/replay/batches/{batch_id}",
            headers=_auth(WORKER_TOKEN),
        )
        assert operator_read.status_code == 200
        assert auditor_read.status_code == 200
        assert approver_read.status_code == 200
        assert approver_read.json() == auditor_read.json() == operator_read.json() == created.json()
        assert worker_read.status_code == 403

        issued = app.state.control_plane.issue_replay_batch(
            batch_id,
            actor="trusted-replay-issuer",
        )
        item = issued.items[0]
        ticket = issued.tickets[0]
        item_read = client.get(
            f"/v1/replay/items/{item.item_id}",
            headers=_auth(AUDITOR_TOKEN),
        )
        ticket_read = client.get(
            f"/v1/replay/tickets/{ticket.ticket_id}",
            headers=_auth(AUDITOR_TOKEN),
        )
        pending_finalization = client.get(
            f"/v1/replay/tickets/{ticket.ticket_id}/finalization",
            headers=_auth(AUDITOR_TOKEN),
        )
        unknown_ticket = client.get(
            f"/v1/replay/tickets/replay-ticket_{'f' * 32}",
            headers=_auth(AUDITOR_TOKEN),
        )

        assert item_read.status_code == 200
        assert item_read.json() == item.model_dump(mode="json")
        assert ticket_read.status_code == 200
        assert ticket_read.json() == ticket.model_dump(mode="json")
        assert "lease_token" not in ticket_read.text
        assert pending_finalization.status_code == 200
        assert pending_finalization.json() is None
        assert unknown_ticket.status_code == 404

        with app.state.repository.read_transaction() as session:
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 1


def test_internal_replay_http_transport_is_worker_only_exact_and_idempotent(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "internal-replay-transport.db"
    staging_root, artifact_root = _artifact_roots(database_path)
    base = _settings(database_path)
    settings = replace(
        base,
        credentials={
            **base.credentials,
            OTHER_WORKER_TOKEN: Principal(
                subject="other-replay-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        replay_executor_profiles={
            "replay-worker": frozenset({EXECUTOR_PROFILE}),
            "other-replay-worker": frozenset({EXECUTOR_PROFILE}),
        },
        artifact_staging_root=staging_root,
        artifact_repository_root=artifact_root,
    )
    app = create_app(settings)
    with TestClient(app) as client:
        repository = app.state.repository
        service = app.state.control_plane
        _create_batch(repository, service, "internal-replay-transport")

        missing_auth = client.post(
            "/v1/worker/replay/jobs/claim",
            json={"executor_profile": EXECUTOR_PROFILE, "lease_seconds": 30},
        )
        assert missing_auth.status_code == 401
        wrong_role = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(OPERATOR_TOKEN),
            json={"executor_profile": EXECUTOR_PROFILE, "lease_seconds": 30},
        )
        assert wrong_role.status_code == 403
        injected_identity = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={
                "executor_profile": EXECUTOR_PROFILE,
                "lease_seconds": 30,
                "worker_id": "body-controlled-worker",
            },
        )
        assert injected_identity.status_code == 422
        unregistered_profile = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={"executor_profile": "unregistered-profile", "lease_seconds": 30},
        )
        assert unregistered_profile.status_code == 403

        claimed_response = client.post(
            "/v1/worker/replay/jobs/claim",
            headers=_auth(WORKER_TOKEN),
            json={"executor_profile": EXECUTOR_PROFILE, "lease_seconds": 30},
        )
        assert claimed_response.status_code == 200, claimed_response.text
        assert claimed_response.headers["cache-control"] == "no-store, max-age=0"
        claimed = ReplayExecutionClaimView.model_validate(claimed_response.json())
        assert claimed.job.lease_owner == "replay-worker"
        assert (
            sha256(canonical_replay_compilation_bytes(claimed.compilation)).hexdigest()
            == claimed.item.compilation_digest
        )

        lease_request = ReplayLeaseRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claimed.lease_token,
            lease_seconds=45,
            ticket_id=claimed.ticket.ticket_id,
            fencing_value=claimed.ticket.fencing_value,
        )
        wrong_principal = client.post(
            f"/v1/worker/replay/jobs/{claimed.job.job_id}/heartbeat",
            headers=_auth(OTHER_WORKER_TOKEN),
            json=lease_request.model_dump(mode="json"),
        )
        assert wrong_principal.status_code == 409
        assert wrong_principal.json()["code"] == "lease_lost"
        heartbeat = client.post(
            f"/v1/worker/replay/jobs/{claimed.job.job_id}/heartbeat",
            headers=_auth(WORKER_TOKEN),
            json=lease_request.model_dump(mode="json"),
        )
        assert heartbeat.status_code == 200, heartbeat.text
        refreshed = ReplayExecutionClaimView.model_validate(heartbeat.json())

        permit_request = ReplayToolPermitRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=refreshed.lease_token,
            ticket_id=refreshed.ticket.ticket_id,
            fencing_value=refreshed.ticket.fencing_value,
            call_ordinal=1,
        )
        injected_call = client.post(
            f"/v1/worker/replay/jobs/{refreshed.job.job_id}/tool-permits",
            headers=_auth(WORKER_TOKEN),
            json={
                **permit_request.model_dump(mode="json"),
                "target": "https://attacker.invalid/injected",
                "tool_id": "attacker-controlled-tool",
                "request_units": 0,
            },
        )
        assert injected_call.status_code == 422
        wrong_permit_principal = client.post(
            f"/v1/worker/replay/jobs/{refreshed.job.job_id}/tool-permits",
            headers=_auth(OTHER_WORKER_TOKEN),
            json=permit_request.model_dump(mode="json"),
        )
        assert wrong_permit_principal.status_code == 409
        assert wrong_permit_principal.json()["code"] == "lease_lost"

        first = client.post(
            f"/v1/worker/replay/jobs/{refreshed.job.job_id}/tool-permits",
            headers=_auth(WORKER_TOKEN),
            json=permit_request.model_dump(mode="json"),
        )
        duplicate = client.post(
            f"/v1/worker/replay/jobs/{refreshed.job.job_id}/tool-permits",
            headers=_auth(WORKER_TOKEN),
            json=permit_request.model_dump(mode="json"),
        )
        assert first.status_code == duplicate.status_code == 200
        assert first.json() == duplicate.json()
        permit_body = first.json()
        assert not {"lease_token", "lease_token_hash", "arguments", "redeem_token"}.intersection(
            permit_body
        )

        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ReplayEventRecord)
                    .where(ReplayEventRecord.event_type == "replay.tool-permit.issued")
                )
                == 1
            )


@pytest.mark.parametrize("kind", [InternalJobKind.REPLAY.value, "future-unregistered-kind"])
def test_generic_claim_service_rejects_bypassed_nonpublic_job_kinds(
    tmp_path: Path,
    kind: str,
) -> None:
    repository, service = _service(tmp_path / f"generic-claim-{kind}.db")
    try:
        ordinary = service.submit_run(
            SubmitRunRequest(
                campaign_name="ordinary-campaign",
                idempotency_key=f"ordinary-before-{kind}",
            ),
            actor="ordinary-operator",
        )
        _create_batch(repository, service, f"generic-claim-{kind}")
        bypassed = ClaimJobRequest.model_construct(
            worker_id="body-controlled-worker",
            kinds=[kind],
            lease_seconds=30,
            wait_seconds=0,
        )

        with pytest.raises(StateConflict, match=r"public|Replay|kind"):
            service.claim_job(bypassed, actor="ordinary-worker-principal")

        assert service.get_job(ordinary.job.job_id).state is JobState.QUEUED
        with repository.transaction() as session:
            replay_job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket = session.scalar(select(ReplayTicketRecord))
            assert replay_job is not None and ticket is not None
            assert replay_job.state == JobState.QUEUED.value
            assert ticket.state == ReplayTicketState.ISSUED.value
    finally:
        repository.close()


def test_generic_claim_rejects_tampered_job_submission_authority(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "generic-job-authority.db")
    try:
        submitted = service.submit_run(
            SubmitRunRequest(
                campaign_name="authority-bound-campaign",
                input={"command": "original"},
                idempotency_key="generic-job-authority-submission",
            ),
            actor="ordinary-operator",
        )
        with repository.transaction() as session:
            _disable_sqlite_job_update_authority_guard(session)
            job = session.get(JobRecord, submitted.job.job_id)
            assert job is not None
            job.payload = {"input": {"command": "tampered"}}

        with pytest.raises(StateConflict, match=r"authority|integrity"):
            service.claim_job(
                ClaimJobRequest(worker_id="ordinary-worker", lease_seconds=30),
                actor="ordinary-worker-principal",
            )

        with repository.transaction() as session:
            job = session.get(JobRecord, submitted.job.job_id)
            run = session.get(RunRecord, submitted.run.run_id)
            assert job is not None and run is not None
            assert job.state == JobState.QUEUED.value
            assert job.attempts == 0
            assert job.lease_owner is None
            assert job.lease_token_hash is None
            assert run.state == RunState.QUEUED.value
    finally:
        repository.close()


def test_batch_creation_is_atomic_idempotent_and_stops_before_ticket_issuance(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "batch.db")
    try:
        source = _seed_completed_source(repository, service, "batch")
        request = _batch_request(source, "batch")

        created = service.create_replay_batch(request, actor="trusted-replay-admission")
        repeated = service.create_replay_batch(request, actor="trusted-replay-admission")

        assert repeated == created
        assert created.source == source
        assert created.mode is CampaignMode.AI_REDTEAM
        assert created.purpose is ReplayPurpose.CONFIRMATION
        assert created.policy_version == KISA_CONFIRMATION_POLICY_VERSION
        assert created.state is ReplayBatchState.PLANNED
        with repository.transaction() as session:
            batch = session.scalar(
                select(ReplayBatchRecord).where(ReplayBatchRecord.batch_id == created.batch_id)
            )
            items = session.scalars(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == created.batch_id)
            ).all()
            tickets = session.scalars(
                select(ReplayTicketRecord).where(ReplayTicketRecord.batch_id == created.batch_id)
            ).all()
            compilations = session.scalars(
                select(ReplayCompilationRecord).where(
                    ReplayCompilationRecord.batch_id == created.batch_id
                )
            ).all()
            assert batch is not None
            assert len(items) == len(compilations) == 1
            assert tickets == []
            item = items[0]
            compilation = compilations[0]
            replay_run = session.get(RunRecord, item.replay_run_id)
            assert replay_run is not None

            assert batch.source_run_id == source.producer_run_id
            assert batch.source_artifact_run_id == source.run_id
            assert batch.source_artifact_id == source.artifact_id
            assert batch.source_content_digest == source.content_digest
            assert batch.source_root_digest == source.integrity_root_digest
            assert item.state == ReplayItemState.PENDING.value
            assert item.required_attempts == KISA_CONFIRMATION_REQUIRED_ATTEMPTS
            assert item.max_attempts == KISA_CONFIRMATION_MAX_ATTEMPTS
            assert item.attempts == 0
            assert compilation.item_id == item.item_id
            assert compilation.compilation_id.startswith("replay-compilation_")
            assert compilation.replay_run_id == item.replay_run_id
            assert compilation.candidate_digest == item.candidate_digest
            assert compilation.contract_digest == item.contract_digest
            assert compilation.compilation_digest == item.compilation_digest
            assert compilation.grant_digest == item.grant_digest
            assert compilation.byte_length == len(compilation.canonical_compilation)
            assert sha256(compilation.canonical_compilation).hexdigest() == item.compilation_digest
            trusted_compilation = ReplayCompilation.model_validate_json(
                compilation.canonical_compilation
            )
            assert replay_context_digest(trusted_compilation.validation_packet.candidate) == (
                item.candidate_digest
            )
            assert replay_context_digest(trusted_compilation.contract) == item.contract_digest
            assert replay_context_digest(trusted_compilation.grant) == item.grant_digest
            assert replay_run.state == RunState.QUEUED.value
            assert "replayPlan" in replay_run.input
            assert "replay" not in replay_run.input

            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayItemRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayExecutionContextRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 0
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 0
            )

        with pytest.raises(StateConflict, match="idempot"):
            service.create_replay_batch(request, actor="different-replay-admission")

        unknown_locator = ArtifactLocator(
            artifact_id=f"artifact_{'f' * 32}",
            repository_version=1,
        )
        with pytest.raises(StateConflict, match="idempot"):
            service.create_replay_batch(
                request.model_copy(update={"source": unknown_locator}),
                actor="trusted-replay-admission",
            )
        with pytest.raises(ResourceNotFound, match="Artifact"):
            service.create_replay_batch(
                request.model_copy(
                    update={
                        "source": unknown_locator,
                        "idempotency_key": "replay-batch-unknown-locator",
                    }
                ),
                actor="trusted-replay-admission",
            )
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 1
    finally:
        repository.close()


def test_replay_issuance_appends_fresh_compilation_and_exact_durable_reservations(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "issuance.db")
    try:
        source = _seed_completed_source(repository, service, "issuance")
        request = _batch_request(source, "issuance")
        planned = service.create_replay_batch(request, actor="trusted-replay-admission")
        with repository.transaction() as session:
            planned_item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
            )
            planned_compilation = session.scalar(
                select(ReplayCompilationRecord).where(
                    ReplayCompilationRecord.batch_id == planned.batch_id
                )
            )
            assert planned_item is not None and planned_compilation is not None
            planned_run_id = planned_item.replay_run_id
            planned_compilation_id = planned_compilation.compilation_id
            planned_canonical = bytes(planned_compilation.canonical_compilation)

        issued = service.issue_replay_batch(
            planned.batch_id,
            actor="trusted-replay-admission",
        )

        assert issued.batch.state is ReplayBatchState.RUNNING
        assert len(issued.items) == len(issued.tickets) == 1
        assert issued.items[0].state is ReplayItemState.QUEUED
        assert issued.items[0].attempts == issued.tickets[0].attempt == 1
        assert issued.items[0].replay_run_id != planned_run_id
        with repository.transaction() as session:
            item = session.get(ReplayItemRecord, issued.items[0].item_id)
            ticket = session.get(ReplayTicketRecord, issued.tickets[0].ticket_id)
            job = session.get(JobRecord, issued.tickets[0].job_id)
            fresh_compilation = session.get(
                ReplayCompilationRecord,
                issued.tickets[0].compilation_id,
            )
            execution_context_record = session.scalar(
                select(ReplayExecutionContextRecord).where(
                    ReplayExecutionContextRecord.compilation_id == issued.tickets[0].compilation_id
                )
            )
            preserved_proof = session.get(ReplayCompilationRecord, planned_compilation_id)
            planned_run = session.get(RunRecord, planned_run_id)
            fresh_run = session.get(RunRecord, issued.items[0].replay_run_id)
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget_reservation = session.scalar(select(ReplayBudgetReservationRecord))
            rate_account = session.scalar(select(ReplayRateAccountRecord))
            rate_reservation = session.scalar(select(ReplayRateReservationRecord))
            assert all(
                record is not None
                for record in (
                    item,
                    ticket,
                    job,
                    fresh_compilation,
                    execution_context_record,
                    preserved_proof,
                    planned_run,
                    fresh_run,
                    budget_account,
                    budget_reservation,
                    rate_account,
                    rate_reservation,
                )
            )
            assert item is not None
            assert ticket is not None
            assert job is not None
            assert fresh_compilation is not None
            assert execution_context_record is not None
            assert preserved_proof is not None
            assert planned_run is not None
            assert fresh_run is not None
            assert budget_account is not None
            assert budget_reservation is not None
            assert rate_account is not None
            assert rate_reservation is not None

            assert preserved_proof.canonical_compilation == planned_canonical
            assert preserved_proof.replay_run_id == planned_run_id
            assert fresh_compilation.compilation_id != preserved_proof.compilation_id
            assert fresh_compilation.replay_run_id == item.replay_run_id == ticket.replay_run_id
            assert fresh_compilation.compilation_digest == item.compilation_digest
            assert fresh_compilation.grant_digest == item.grant_digest
            assert sha256(fresh_compilation.canonical_compilation).hexdigest() == (
                item.compilation_digest
            )
            trusted = ReplayCompilation.model_validate_json(fresh_compilation.canonical_compilation)
            trusted_context = ReplayExecutionContext.model_validate_json(
                execution_context_record.canonical_context
            )
            assert canonical_replay_compilation_bytes(trusted) == (
                fresh_compilation.canonical_compilation
            )
            assert trusted.spec.binding.replay_run_id == item.replay_run_id
            assert replay_context_digest(trusted.grant) == item.grant_digest
            assert canonical_replay_execution_context_bytes(trusted_context) == (
                execution_context_record.canonical_context
            )
            assert execution_context_record.byte_length == len(
                execution_context_record.canonical_context
            )
            assert replay_execution_context_digest(trusted_context) == (
                execution_context_record.context_digest
            )
            assert sha256(execution_context_record.canonical_context).hexdigest() == (
                execution_context_record.context_digest
            )
            assert trusted_context.context_id == execution_context_record.context_id
            assert execution_context_record.compilation_id == fresh_compilation.compilation_id
            assert execution_context_record.item_id == item.item_id
            assert execution_context_record.batch_id == item.batch_id
            assert execution_context_record.replay_run_id == fresh_compilation.replay_run_id
            assert execution_context_record.compilation_digest == item.compilation_digest
            assert execution_context_record.grant_digest == item.grant_digest
            assert trusted_context.compilation_id == fresh_compilation.compilation_id
            assert trusted_context.item_id == item.item_id
            assert trusted_context.batch_id == item.batch_id
            assert trusted_context.replay_run_id == fresh_compilation.replay_run_id
            assert trusted_context.source == source
            assert trusted_context.source_root_digest == source.integrity_root_digest
            assert trusted_context.policy_version == issued.batch.policy_version
            assert trusted_context.required_executor_profile == EXECUTOR_PROFILE
            assert trusted_context.secret_policy == "forbidden"
            assert trusted_context.secret_lease_ids == ()
            assert trusted_context.output_staging_id == execution_context_record.output_staging_id
            assert trusted_context.campaign_digest == replay_execution_component_digest(
                trusted_context.campaign
            )
            assert trusted_context.scenario_digest == replay_execution_component_digest(
                trusted_context.scenario
            )
            assert trusted_context.tool_spec_digest == replay_execution_component_digest(
                trusted_context.tool_spec
            )
            assert planned_run.state == RunState.QUEUED.value
            assert "replayPlan" in planned_run.input and "replay" not in planned_run.input
            assert fresh_run.state == RunState.QUEUED.value

            payload = ReplayJobPayload.model_validate(job.payload)
            assert job.kind == InternalJobKind.REPLAY.value
            assert job.state == JobState.QUEUED.value
            assert payload.compilation_id == ticket.compilation_id
            assert payload.execution_context_id == execution_context_record.context_id
            assert payload.execution_context_digest == execution_context_record.context_digest
            assert payload.budget_reservation_id == ticket.budget_reservation_id
            assert payload.rate_reservation_id == ticket.rate_reservation_id
            assert "rate_authority" not in job.payload
            assert payload.replay_run_id == fresh_compilation.replay_run_id
            assert payload.compilation_digest == fresh_compilation.compilation_digest
            assert payload.grant_digest == fresh_compilation.grant_digest
            assert fresh_run.input == {"replay": payload.model_dump(mode="json")}

            assert budget_reservation.budget_reservation_id == ticket.budget_reservation_id
            assert budget_reservation.compilation_id == ticket.compilation_id
            assert budget_reservation.attempt_number == ticket.attempt_number == 1
            assert budget_reservation.total_calls == trusted.spec.max_calls
            assert budget_reservation.consumed_calls == budget_reservation.released_calls == 0
            assert budget_reservation.state == "active"
            assert budget_account.source_run_id == source.producer_run_id
            assert budget_account.reserved_calls == budget_reservation.total_calls
            assert budget_account.consumed_calls == 0
            assert (
                budget_account.baseline_used_calls
                + budget_account.reserved_calls
                + budget_account.consumed_calls
                <= budget_account.max_tool_calls
            )

            expected_rate_units = (
                AIChatProbeTool().network_request_cost(trusted.original_request)
                * trusted.spec.repetitions
            )
            assert rate_reservation.rate_reservation_id == ticket.rate_reservation_id
            assert rate_reservation.compilation_id == ticket.compilation_id
            assert rate_reservation.attempt_number == ticket.attempt_number == 1
            assert rate_reservation.total_request_units == expected_rate_units
            assert (
                rate_reservation.consumed_request_units
                == rate_reservation.released_request_units
                == 0
            )
            assert rate_reservation.state == "active"
            assert rate_account.source_run_id == source.producer_run_id
            assert ticket.compilation_id == fresh_compilation.compilation_id

            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 2
            assert (
                session.scalar(select(func.count()).select_from(ReplayExecutionContextRecord)) == 1
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 1
            )
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 1
            )
    finally:
        repository.close()


def test_replay_issuance_exact_retry_is_idempotent_without_double_reservation(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "issuance-idempotent.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-idempotent")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-idempotent"),
            actor="trusted-replay-admission",
        )

        first = service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")
        repeated = service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        assert repeated == first
        with repository.transaction() as session:
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget_reservations = list(session.scalars(select(ReplayBudgetReservationRecord)))
            rate_reservations = list(session.scalars(select(ReplayRateReservationRecord)))
            assert budget_account is not None
            assert len(budget_reservations) == len(rate_reservations) == len(first.items)
            assert budget_account.reserved_calls == sum(
                reservation.total_calls for reservation in budget_reservations
            )
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == (
                len(first.items) * 2
            )
            assert session.scalar(
                select(func.count()).select_from(ReplayExecutionContextRecord)
            ) == len(first.items)
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == len(
                first.items
            )
            assert session.scalar(
                select(func.count())
                .select_from(JobRecord)
                .where(JobRecord.kind == InternalJobKind.REPLAY.value)
            ) == len(first.items)
    finally:
        repository.close()


def test_two_sqlite_issuers_converge_on_one_replay_authority_graph(tmp_path: Path) -> None:
    database_path = tmp_path / "issuance-race.db"
    repository_a, service_a = _service(database_path)
    repository_b, service_b = _service(database_path)
    try:
        source = _seed_completed_source(repository_a, service_a, "issuance-race")
        planned = service_a.create_replay_batch(
            _batch_request(source, "issuance-race"),
            actor="trusted-replay-admission",
        )
        barrier = Barrier(2)

        def issue(service: ControlPlaneService) -> ReplayBatchIssuanceView:
            barrier.wait()
            return service.issue_replay_batch(
                planned.batch_id,
                actor="trusted-replay-admission",
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(issue, (service_a, service_b)))

        assert results[0] == results[1]
        with repository_a.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 2
            assert (
                session.scalar(select(func.count()).select_from(ReplayExecutionContextRecord)) == 1
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 1
            )
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 1
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 1
            )
    finally:
        repository_b.close()
        repository_a.close()


@pytest.mark.parametrize("limit", ["budget", "rate"])
def test_replay_issuance_fails_closed_when_aggregate_reservation_is_insufficient(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit: str,
) -> None:
    repository, service = _service(tmp_path / f"issuance-insufficient-{limit}.db")
    try:
        source = _seed_completed_source(repository, service, f"issuance-insufficient-{limit}")
        planned = service.create_replay_batch(
            _batch_request(source, f"issuance-insufficient-{limit}"),
            actor="trusted-replay-admission",
        )
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_insufficient(**kwargs):
            derived = real_derive(**kwargs)
            if limit == "budget":
                return replace(
                    derived,
                    max_tool_calls=(derived.used_tool_calls + derived.required_tool_calls - 1),
                )
            return replace(
                derived,
                max_requests_per_minute=(
                    derived.observed_campaign_request_units + derived.required_request_units - 1
                ),
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_insufficient,
        )
        with pytest.raises(StateConflict, match=r"budget|rate|reservation|eligible"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            batch = session.get(ReplayBatchRecord, planned.batch_id)
            item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
            )
            assert batch is not None and item is not None
            assert batch.state == ReplayBatchState.PLANNED.value
            assert item.state == ReplayItemState.PENDING.value
            assert item.attempts == 0
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 0
            )
    finally:
        repository.close()


def test_replay_issuance_rolls_back_all_fresh_authority_after_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-rollback.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-rollback")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-rollback"),
            actor="trusted-replay-admission",
        )
        artifact_repository = service._require_artifact_repository()
        staging_before = {entry.name for entry in artifact_repository.staging_root.iterdir()}
        original_event = service._replay_event
        reached_late_failure = False

        def fail_after_ticket(session, batch, event_type, actor, payload, **context):
            nonlocal reached_late_failure
            if event_type != "replay.ticket.issued":
                return original_event(
                    session,
                    batch,
                    event_type,
                    actor,
                    payload,
                    **context,
                )
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 2
            assert (
                session.scalar(select(func.count()).select_from(ReplayExecutionContextRecord)) == 1
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 1
            )
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 1
            )
            reached_late_failure = True
            raise RuntimeError("simulated failure after durable Replay issuance")

        monkeypatch.setattr(service, "_replay_event", fail_after_ticket)
        with pytest.raises(RuntimeError, match="after durable Replay issuance"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        assert reached_late_failure
        with repository.transaction() as session:
            batch = session.get(ReplayBatchRecord, planned.batch_id)
            item = session.scalar(
                select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
            )
            assert batch is not None and item is not None
            assert batch.state == ReplayBatchState.PLANNED.value
            assert batch.cas_version == 1
            assert item.state == ReplayItemState.PENDING.value
            assert item.attempts == 0
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayExecutionContextRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayRateReservationRecord)) == 0
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 0
            )
        staging_after = {entry.name for entry in artifact_repository.staging_root.iterdir()}
        assert staging_after == staging_before
    finally:
        repository.close()


def test_replay_issuance_cleanup_distinguishes_body_failure_from_commit_ambiguity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-cleanup.db")
    artifact_repository = service._require_artifact_repository()
    body_failure_id = f"stage_{'a' * 32}"
    ambiguous_commit_id = f"stage_{'b' * 32}"
    try:
        with (
            pytest.raises(RuntimeError, match="transaction body failed"),
            service._replay_issuance_transaction(artifact_repository) as (
                _session,
                reservations,
            ),
        ):
            reservations.append(body_failure_id)
            artifact_repository.reserve_staging(body_failure_id)
            raise RuntimeError("transaction body failed")
        assert not (artifact_repository.staging_root / body_failure_id).exists()

        @contextmanager
        def ambiguous_transaction():
            yield None
            raise RuntimeError("commit result is ambiguous")

        monkeypatch.setattr(repository, "transaction", ambiguous_transaction)
        with (
            pytest.raises(RuntimeError, match="commit result is ambiguous"),
            service._replay_issuance_transaction(artifact_repository) as (
                _session,
                reservations,
            ),
        ):
            reservations.append(ambiguous_commit_id)
            artifact_repository.reserve_staging(ambiguous_commit_id)
        assert (artifact_repository.staging_root / ambiguous_commit_id).is_dir()
    finally:
        repository.close()


def test_replay_issuance_rejects_cancelled_or_drifted_planned_authority(
    tmp_path: Path,
) -> None:
    for condition in ("cancelled", "drifted"):
        repository, service = _service(tmp_path / f"issuance-{condition}.db")
        try:
            source = _seed_completed_source(repository, service, f"issuance-{condition}")
            planned = service.create_replay_batch(
                _batch_request(source, f"issuance-{condition}"),
                actor="trusted-replay-admission",
            )
            with repository.transaction() as session:
                item = session.scalar(
                    select(ReplayItemRecord).where(ReplayItemRecord.batch_id == planned.batch_id)
                )
                assert item is not None
                replay_run_id = item.replay_run_id
                if condition == "drifted":
                    item.grant_digest = "0" * 64
            if condition == "cancelled":
                service.cancel_run(
                    replay_run_id,
                    CancelRunRequest(reason="cancel planned Replay before issuance"),
                    actor="replay-operator",
                )

            with pytest.raises(StateConflict, match=r"cancelled|planned|authority|binding"):
                service.issue_replay_batch(
                    planned.batch_id,
                    actor="trusted-replay-admission",
                )
            with repository.transaction() as session:
                assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
                assert (
                    session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord))
                    == 0
                )
                assert (
                    session.scalar(select(func.count()).select_from(ReplayRateReservationRecord))
                    == 0
                )
        finally:
            repository.close()


def test_replay_issuance_rejects_an_expired_fresh_grant_without_partial_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-expired-grant.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-expired-grant")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-expired-grant"),
            actor="trusted-replay-admission",
        )
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_expired(**kwargs):
            derived = real_derive(**kwargs)
            expired_items = []
            for item in derived.items:
                compiled_at = item.compilation.spec.compiled_at
                expires_at = compiled_at + timedelta(microseconds=1)
                grant = item.compilation.grant.model_copy(update={"expires_at": expires_at})
                spec = item.compilation.spec.model_copy(update={"expires_at": expires_at})
                compilation = item.compilation.model_copy(update={"grant": grant, "spec": spec})
                canonical = canonical_replay_compilation_bytes(compilation)
                expired_items.append(
                    replace(
                        item,
                        compilation=compilation,
                        canonical_compilation=canonical,
                        compilation_digest=sha256(canonical).hexdigest(),
                        grant_digest=replay_context_digest(grant),
                    )
                )
            return replace(
                derived,
                items=tuple(expired_items),
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_expired,
        )
        with pytest.raises(StateConflict, match=r"expired|Grant|compilation"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
    finally:
        repository.close()


def test_replay_issuance_rejects_misreported_fresh_request_units(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-request-units.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-request-units")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-request-units"),
            actor="trusted-replay-admission",
        )
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_underreported(**kwargs):
            derived = real_derive(**kwargs)
            original = derived.items[0]
            assert original.required_request_units > 1
            underreported = replace(
                original,
                required_request_units=original.required_request_units - 1,
            )
            return replace(
                derived,
                required_request_units=derived.required_request_units - 1,
                items=(underreported, *derived.items[1:]),
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_underreported,
        )
        with pytest.raises(StateConflict, match=r"compilation|authority|eligible"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
    finally:
        repository.close()


def test_replay_issuance_rejects_a_future_fresh_grant_without_partial_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "issuance-future-grant.db")
    try:
        source = _seed_completed_source(repository, service, "issuance-future-grant")
        planned = service.create_replay_batch(
            _batch_request(source, "issuance-future-grant"),
            actor="trusted-replay-admission",
        )
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_future(**kwargs):
            derived = real_derive(**kwargs)
            compiled_at = datetime.now(UTC) + timedelta(minutes=10)
            expires_at = compiled_at + timedelta(minutes=5)
            future_items = []
            for item in derived.items:
                grant = item.compilation.grant.model_copy(
                    update={"issued_at": compiled_at, "expires_at": expires_at}
                )
                spec = item.compilation.spec.model_copy(
                    update={"compiled_at": compiled_at, "expires_at": expires_at}
                )
                compilation = item.compilation.model_copy(update={"grant": grant, "spec": spec})
                canonical = canonical_replay_compilation_bytes(compilation)
                future_items.append(
                    replace(
                        item,
                        compilation=compilation,
                        canonical_compilation=canonical,
                        compilation_digest=sha256(canonical).hexdigest(),
                        grant_digest=replay_context_digest(grant),
                    )
                )
            return replace(
                derived,
                compiled_at=compiled_at,
                items=tuple(future_items),
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_future,
        )
        with pytest.raises(StateConflict, match=r"compilation|authority|eligible"):
            service.issue_replay_batch(planned.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayBudgetAccountRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayRateAccountRecord)) == 0
    finally:
        repository.close()


def test_expired_unclaimed_replay_ticket_is_swept_and_releases_capacity(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "expired-unclaimed-ticket.db")
    try:
        _create_batch(repository, service, "expired-unclaimed-ticket")
        now = datetime.now(UTC)
        expired_at = now - timedelta(minutes=1)
        with repository.transaction() as session:
            ticket = session.scalar(select(ReplayTicketRecord))
            assert ticket is not None
            ticket.issued_at = now - timedelta(minutes=2)
            ticket.expires_at = expired_at
            ticket_id = ticket.ticket_id

        assert service.requeue_expired(actor="lease-reaper") == 1
        assert service.requeue_expired(actor="lease-reaper") == 0

        with repository.transaction() as session:
            ticket = session.get(ReplayTicketRecord, ticket_id)
            assert ticket is not None
            job = session.get(JobRecord, ticket.job_id)
            item = session.get(ReplayItemRecord, ticket.item_id)
            batch = session.get(ReplayBatchRecord, ticket.batch_id)
            run = session.get(RunRecord, ticket.replay_run_id)
            budget = session.get(
                ReplayBudgetReservationRecord,
                ticket.budget_reservation_id,
            )
            rate = session.get(
                ReplayRateReservationRecord,
                ticket.rate_reservation_id,
            )
            account = session.scalar(select(ReplayBudgetAccountRecord))
            assert all(
                record is not None for record in (job, item, batch, run, budget, rate, account)
            )
            assert job is not None
            assert item is not None
            assert batch is not None
            assert run is not None
            assert budget is not None
            assert rate is not None
            assert account is not None
            assert ticket.state == ReplayTicketState.ABANDONED.value
            assert ticket.abandon_reason == "Replay ticket expired before claim"
            assert job.state == JobState.FAILED.value
            assert item.state == ReplayItemState.RETRY_PENDING.value
            assert batch.state == ReplayBatchState.RUNNING.value
            assert run.state == RunState.FAILED.value
            assert budget.state == rate.state == "released"
            assert budget.released_calls == budget.total_calls
            assert rate.released_request_units == rate.total_request_units
            assert account.reserved_calls == account.consumed_calls == 0
            assert account.released_calls == budget.total_calls
    finally:
        repository.close()


def test_replay_issuance_fails_closed_on_budget_account_ledger_drift(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "budget-ledger-drift.db")
    try:
        source = _seed_completed_source(repository, service, "budget-ledger-drift")
        first = service.create_replay_batch(
            _batch_request(source, "budget-ledger-drift-first"),
            actor="trusted-replay-admission",
        )
        second = service.create_replay_batch(
            _batch_request(source, "budget-ledger-drift-second"),
            actor="trusted-replay-admission",
        )
        service.issue_replay_batch(first.batch_id, actor="trusted-replay-admission")
        with repository.transaction() as session:
            account = session.scalar(select(ReplayBudgetAccountRecord))
            assert account is not None and account.reserved_calls > 0
            account.reserved_calls = 0

        with pytest.raises(StateConflict, match=r"budget.*ledger|account counters"):
            service.issue_replay_batch(second.batch_id, actor="trusted-replay-admission")

        with repository.transaction() as session:
            stored_second = session.get(ReplayBatchRecord, second.batch_id)
            assert stored_second is not None
            assert stored_second.state == ReplayBatchState.PLANNED.value
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayBudgetReservationRecord)) == 1
            )
    finally:
        repository.close()


def test_v7_replay_payload_without_rate_snapshot_remains_claimable_after_upgrade(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "legacy-rate-payload-upgrade.db")
    try:
        _create_batch(repository, service, "legacy-rate-payload-upgrade")
        with repository.transaction() as session:
            job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            assert job is not None
            assert "rate_authority" not in job.payload
            ReplayJobPayload.model_validate(job.payload)

        claimed = service.claim_replay_job(
            ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
            actor="replay-worker-a",
        )
        assert claimed is not None
    finally:
        repository.close()


def test_v7_replay_payload_without_rate_snapshot_rejects_rate_cap_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "rate-account-policy-drift.db")
    try:
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_with_finite_rate_cap(**kwargs):
            derived = real_derive(**kwargs)
            rate_cap = derived.observed_campaign_request_units + derived.required_request_units
            rules = derived.campaign.spec.rules_of_engagement.model_copy(
                update={"max_requests_per_minute": rate_cap}
            )
            campaign = derived.campaign.model_copy(
                update={
                    "spec": derived.campaign.spec.model_copy(update={"rules_of_engagement": rules})
                }
            )
            return replace(
                derived,
                campaign=campaign,
                max_requests_per_minute=rate_cap,
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_with_finite_rate_cap,
        )
        _create_batch(repository, service, "rate-account-policy-drift")
        with repository.transaction() as session:
            job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            account = session.scalar(select(ReplayRateAccountRecord))
            assert job is not None and "rate_authority" not in job.payload
            assert account is not None and account.max_requests_per_minute is not None
            account.max_requests_per_minute = None

        with pytest.raises(StateConflict, match="rate account"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replay-worker-a",
            )
    finally:
        repository.close()


@pytest.mark.parametrize(
    "drift",
    [
        "rate_limits_digest",
        "ledger_id",
        "observed_request_units",
        "observed_at",
        "window_seconds",
    ],
)
def test_replay_claim_rejects_each_sealed_rate_authority_drift(
    tmp_path: Path,
    drift: str,
) -> None:
    repository, service = _service(tmp_path / f"rate-authority-{drift}.db")
    try:
        _create_batch(repository, service, f"rate-authority-{drift}")
        with repository.transaction() as session:
            account = session.scalar(select(ReplayRateAccountRecord))
            assert account is not None
            if drift == "rate_limits_digest":
                account.rate_limits_digest = "f" * 64
            elif drift == "ledger_id":
                account.ledger_id = f"rate-ledger_{'f' * 32}"
            elif drift == "observed_request_units":
                account.observed_request_units += 1
            elif drift == "observed_at":
                account.observed_at += timedelta(seconds=1)
            else:
                # Exercise the service-level verifier even though the schema also
                # rejects this value under normal operation.
                session.execute(text("PRAGMA ignore_check_constraints = ON"))
                account.window_seconds = 61

        with pytest.raises(StateConflict, match="rate account"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replay-worker-a",
            )
    finally:
        repository.close()


@pytest.mark.parametrize(
    "attack",
    ["duplicate-key", "oversize", "depth", "nodes", "root-substitution"],
)
def test_replay_claim_rejects_untrusted_rate_limit_snapshot_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    attack: str,
) -> None:
    repository, service = _service(tmp_path / f"rate-snapshot-{attack}.db")
    try:
        _create_batch(repository, service, f"rate-snapshot-{attack}")
        real_load = control_plane_service_module.load_verified_run_artifacts
        calls: list[dict[str, object]] = []

        def attacked_load(*args, **kwargs):
            calls.append(dict(kwargs))
            snapshot = real_load(*args, **kwargs)
            if attack == "root-substitution":
                return replace(
                    snapshot,
                    verification=snapshot.verification.model_copy(update={"root_digest": "f" * 64}),
                )

            ledger_id = f"rate-ledger_{'a' * 32}"
            if attack == "duplicate-key":
                content = (
                    f'{{"ledgerId":"{ledger_id}","reservationCounts":'
                    '{"campaign":1,"\\u0063ampaign":2}}'
                ).encode()
            elif attack == "oversize":
                content = b"{}" + b" " * (
                    control_plane_service_module._MAX_REPLAY_RATE_LIMIT_SNAPSHOT_BYTES
                )
            elif attack == "depth":
                content = (
                    (f'{{"ledgerId":"{ledger_id}","reservationCounts":{{"campaign":').encode()
                    + b"[" * 10
                    + b"0"
                    + b"]" * 10
                    + b"}}"
                )
            else:
                reservations = ",".join(f'"campaign-{index}":{index}' for index in range(2_100))
                content = (
                    f'{{"ledgerId":"{ledger_id}","reservationCounts":{{{reservations}}}}}'
                ).encode()
            return replace(
                snapshot,
                artifacts={"rate-limits.json": content},
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "load_verified_run_artifacts",
            attacked_load,
        )

        with pytest.raises(StateConflict, match="rate authority failed reverification"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replay-worker-a",
            )

        assert len(calls) == 1
        assert calls[0]["requests"] == {
            "rate-limits.json": (control_plane_service_module._MAX_REPLAY_RATE_LIMIT_SNAPSHOT_BYTES)
        }
        assert isinstance(calls[0]["expected_run_id"], str)
    finally:
        repository.close()


def test_replay_release_rejects_a_reservation_bound_to_another_source_account(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "reservation-account-drift.db")
    try:
        source_a = _seed_completed_source(repository, service, "reservation-account-drift-a")
        source_b = _seed_completed_source(repository, service, "reservation-account-drift-b")
        planned_a = service.create_replay_batch(
            _batch_request(source_a, "reservation-account-drift-a"),
            actor="trusted-replay-admission",
        )
        planned_b = service.create_replay_batch(
            _batch_request(source_b, "reservation-account-drift-b"),
            actor="trusted-replay-admission",
        )
        issued_a = service.issue_replay_batch(
            planned_a.batch_id,
            actor="trusted-replay-admission",
        )
        service.issue_replay_batch(
            planned_b.batch_id,
            actor="trusted-replay-admission",
        )

        with repository.transaction() as session:
            ticket_a = session.get(ReplayTicketRecord, issued_a.tickets[0].ticket_id)
            account_a = session.scalar(
                select(ReplayBudgetAccountRecord).where(
                    ReplayBudgetAccountRecord.source_run_id == source_a.producer_run_id
                )
            )
            account_b = session.scalar(
                select(ReplayBudgetAccountRecord).where(
                    ReplayBudgetAccountRecord.source_run_id == source_b.producer_run_id
                )
            )
            assert ticket_a is not None and account_a is not None and account_b is not None
            reservation_a = session.get(
                ReplayBudgetReservationRecord,
                ticket_a.budget_reservation_id,
            )
            assert reservation_a is not None
            moved_calls = reservation_a.total_calls
            account_a.reserved_calls -= moved_calls
            account_b.reserved_calls += moved_calls
            reservation_a.budget_account_id = account_b.budget_account_id
            counters_before = (
                account_a.reserved_calls,
                account_a.released_calls,
                account_b.reserved_calls,
                account_b.released_calls,
            )

        with pytest.raises(StateConflict, match=r"binding|source|account"):
            service.cancel_run(
                issued_a.items[0].replay_run_id,
                CancelRunRequest(reason="reject drifted reservation account"),
                actor="replay-operator",
            )

        with repository.transaction() as session:
            ticket_a = session.get(ReplayTicketRecord, issued_a.tickets[0].ticket_id)
            job_a = session.get(JobRecord, issued_a.tickets[0].job_id)
            item_a = session.get(ReplayItemRecord, issued_a.items[0].item_id)
            run_a = session.get(RunRecord, issued_a.items[0].replay_run_id)
            account_a = session.scalar(
                select(ReplayBudgetAccountRecord).where(
                    ReplayBudgetAccountRecord.source_run_id == source_a.producer_run_id
                )
            )
            account_b = session.scalar(
                select(ReplayBudgetAccountRecord).where(
                    ReplayBudgetAccountRecord.source_run_id == source_b.producer_run_id
                )
            )
            assert all(
                record is not None
                for record in (ticket_a, job_a, item_a, run_a, account_a, account_b)
            )
            assert ticket_a is not None
            assert job_a is not None
            assert item_a is not None
            assert run_a is not None
            assert account_a is not None
            assert account_b is not None
            assert ticket_a.state == ReplayTicketState.ISSUED.value
            assert job_a.state == JobState.QUEUED.value
            assert item_a.state == ReplayItemState.QUEUED.value
            assert run_a.state == RunState.QUEUED.value
            assert (
                account_a.reserved_calls,
                account_a.released_calls,
                account_b.reserved_calls,
                account_b.released_calls,
            ) == counters_before
    finally:
        repository.close()


def test_batch_creation_rolls_back_every_derived_row_after_late_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "batch-rollback.db")
    try:
        source = _seed_completed_source(repository, service, "batch-rollback")
        request = _batch_request(source, "batch-rollback")
        original_event = service._event
        reached_late_failure = False

        def fail_after_compilation(session, run, event_type, actor, payload):
            nonlocal reached_late_failure
            if event_type != "run.replay-planned":
                return original_event(session, run, event_type, actor, payload)

            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayItemRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 1
            assert (
                session.scalar(select(func.count()).select_from(ReplayExecutionContextRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(RunRecord)) == 2
            reached_late_failure = True
            raise RuntimeError("simulated failure after Replay compilation persistence")

        monkeypatch.setattr(service, "_event", fail_after_compilation)

        with pytest.raises(RuntimeError, match="after Replay compilation persistence"):
            service.create_replay_batch(request, actor="trusted-replay-admission")

        assert reached_late_failure
        with repository.transaction() as session:
            source_run = session.get(RunRecord, source.producer_run_id)
            artifact = session.get(
                ArtifactRecord,
                (source.artifact_id, source.repository_version),
            )
            assert source_run is not None
            assert source_run.state == RunState.COMPLETED.value
            assert artifact is not None
            assert artifact.sealed_run_id == source.run_id

            assert session.scalar(select(func.count()).select_from(RunRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayItemRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayCompilationRecord)) == 0
            assert (
                session.scalar(select(func.count()).select_from(ReplayExecutionContextRecord)) == 0
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayEventRecord)) == 0
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(EventRecord)
                    .where(EventRecord.event_type == "run.replay-planned")
                )
                == 0
            )
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 0
            )
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("replay_run_id", "source-run"),
        ("compilation_digest", "0" * 64),
        ("grant_digest", "0" * 64),
    ],
)
def test_replay_batch_idempotency_rejects_current_compilation_pointer_drift(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    repository, service = _service(tmp_path / f"batch-pointer-drift-{field}.db")
    try:
        source = _seed_completed_source(repository, service, f"batch-pointer-drift-{field}")
        request = _batch_request(source, f"batch-pointer-drift-{field}")
        created = service.create_replay_batch(request, actor="trusted-replay-admission")

        drifted_value = source.producer_run_id if replacement == "source-run" else replacement
        with repository.transaction() as session:
            session.execute(
                update(ReplayItemRecord)
                .where(ReplayItemRecord.batch_id == created.batch_id)
                .values({field: drifted_value})
            )

        with pytest.raises(StateConflict, match="authority input"):
            service.create_replay_batch(request, actor="trusted-replay-admission")
    finally:
        repository.close()


def test_claim_burns_ticket_and_binds_authenticated_actor_token_attempt_and_fence(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "claim.db")
    try:
        _create_batch(repository, service, "claim")
        claimed = _claim(service, actor="authenticated-worker-a")

        assert claimed.job.kind == InternalJobKind.REPLAY.value
        assert claimed.job.state is JobState.LEASED
        assert claimed.job.lease_owner == "authenticated-worker-a"
        assert claimed.item.state is ReplayItemState.RUNNING
        assert claimed.ticket.state is ReplayTicketState.CLAIMED
        assert claimed.ticket.claimed_by == "authenticated-worker-a"
        assert claimed.ticket.executor_profile == EXECUTOR_PROFILE
        assert claimed.ticket.attempt == claimed.item.attempts == 1
        assert claimed.ticket.fencing_value == 1
        assert claimed.ticket.job_id == claimed.job.job_id
        assert claimed.ticket.replay_run_id == claimed.job.run_id
        assert (
            sha256(canonical_replay_compilation_bytes(claimed.compilation)).hexdigest()
            == claimed.item.compilation_digest
        )
        assert claimed.compilation.spec.binding.replay_run_id == claimed.job.run_id
        assert claimed.compilation.spec.binding.candidate_id == claimed.item.candidate_id
        assert replay_context_digest(claimed.compilation.grant) == claimed.item.grant_digest
        assert replay_execution_context_digest(claimed.execution_context) == (
            claimed.execution_context_digest
        )
        assert claimed.execution_context.compilation_id == claimed.ticket.compilation_id
        assert claimed.execution_context.batch_id == claimed.batch.batch_id
        assert claimed.execution_context.item_id == claimed.item.item_id
        assert claimed.execution_context.replay_run_id == claimed.job.run_id
        assert claimed.execution_context.source == claimed.batch.source
        assert claimed.execution_context.source_root_digest == (
            claimed.batch.source.integrity_root_digest
        )
        assert claimed.execution_context.required_executor_profile == EXECUTOR_PROFILE
        assert claimed.execution_context.tool_spec.tool_id == (
            claimed.compilation.spec.binding.tool_id
        )
        assert claimed.execution_context.scenario.scenario_id == (
            claimed.compilation.spec.binding.scenario_id
        )
        source_payload = claimed.job.payload["source"]
        assert source_payload["producer_run_id"] == claimed.batch.source.producer_run_id
        assert source_payload["run_id"] == claimed.batch.source.run_id
        assert source_payload["producer_run_id"] != source_payload["run_id"]
        assert not {"storage_key", "staging_id", "path"}.intersection(source_payload)

        with repository.transaction() as session:
            job = session.get(JobRecord, claimed.job.job_id)
            ticket = session.get(ReplayTicketRecord, claimed.ticket.ticket_id)
            assert job is not None and ticket is not None
            expected_digest = token_digest(claimed.lease_token)
            assert job.lease_token_hash == ticket.lease_token_hash == expected_digest
            assert claimed.lease_token not in repr(job.payload)
            assert claimed.lease_token != expected_digest
            assert ticket.claim_principal == "authenticated-worker-a"
            assert ticket.fencing_value == claimed.ticket.fencing_value
            assert ticket.attempt_number == claimed.ticket.attempt
            compilation = session.get(ReplayCompilationRecord, ticket.compilation_id)
            execution_context_record = session.scalar(
                select(ReplayExecutionContextRecord).where(
                    ReplayExecutionContextRecord.compilation_id == ticket.compilation_id
                )
            )
            budget_reservation = session.get(
                ReplayBudgetReservationRecord,
                ticket.budget_reservation_id,
            )
            rate_reservation = session.get(
                ReplayRateReservationRecord,
                ticket.rate_reservation_id,
            )
            assert compilation is not None
            assert execution_context_record is not None
            assert budget_reservation is not None
            assert rate_reservation is not None
            payload = ReplayJobPayload.model_validate(job.payload)
            assert payload.compilation_id == ticket.compilation_id
            assert payload.execution_context_id == execution_context_record.context_id
            assert payload.execution_context_digest == execution_context_record.context_digest
            assert execution_context_record.context_id == claimed.execution_context.context_id
            assert execution_context_record.context_digest == claimed.execution_context_digest
            assert execution_context_record.required_executor_profile == ticket.executor_profile
            assert payload.budget_reservation_id == ticket.budget_reservation_id
            assert payload.rate_reservation_id == ticket.rate_reservation_id
            assert compilation.replay_run_id == ticket.replay_run_id
            assert budget_reservation.compilation_id == ticket.compilation_id
            assert rate_reservation.compilation_id == ticket.compilation_id

        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="authenticated-worker-b",
            )
            is None
        )
    finally:
        repository.close()


def test_replay_execution_claim_rejects_compilation_from_another_ticket(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "claim-compilation-swap.db")
    try:
        _create_batch(repository, service, "claim-compilation-swap-a")
        _create_batch(repository, service, "claim-compilation-swap-b")
        first = _claim(service, actor="authenticated-worker-a")
        second = _claim(service, actor="authenticated-worker-b")

        swapped = first.model_dump(mode="python")
        swapped["compilation"] = second.compilation.model_dump(mode="python")
        with pytest.raises(ValueError, match="execution context authority binding"):
            ReplayExecutionClaimView.model_validate(swapped)
    finally:
        repository.close()


def test_replay_execution_claim_rejects_context_from_another_compilation(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "claim-context-swap.db")
    try:
        _create_batch(repository, service, "claim-context-swap-a")
        _create_batch(repository, service, "claim-context-swap-b")
        first = _claim(service, actor="authenticated-worker-a")
        second = _claim(service, actor="authenticated-worker-b")

        swapped = first.model_dump(mode="python")
        swapped["execution_context"] = second.execution_context.model_dump(mode="python")
        swapped["execution_context_digest"] = second.execution_context_digest
        swapped_payload = dict(swapped["job"]["payload"])
        swapped_payload["execution_context_id"] = second.execution_context.context_id
        swapped_payload["execution_context_digest"] = second.execution_context_digest
        swapped["job"]["payload"] = swapped_payload
        with pytest.raises(ValueError, match="execution context authority binding"):
            ReplayExecutionClaimView.model_validate(swapped)
    finally:
        repository.close()


@pytest.mark.parametrize("record_kind", ["compilation", "execution-context"])
@pytest.mark.parametrize(
    ("attack", "expected_cause"),
    [
        ("deep", "nesting-depth limit"),
        ("duplicate-key", "is not strict JSON"),
        ("non-finite", "is not strict JSON"),
        ("node-count", "node-count limit"),
        ("oversize", "byte limit"),
    ],
)
def test_replay_claim_rejects_resource_hostile_stored_authority_json(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    record_kind: str,
    attack: str,
    expected_cause: str,
) -> None:
    repository, service = _service(tmp_path / f"stored-{record_kind}-{attack}.db")
    try:
        _create_batch(repository, service, f"stored-{record_kind}-{attack}")
        if attack == "deep":
            damaged = b"[" * 70 + b"0" + b"]" * 70
        elif attack == "duplicate-key":
            damaged = b'{"authority":1,"authority":2}'
        elif attack == "non-finite":
            damaged = b'{"authority":NaN}'
        elif attack == "node-count":
            monkeypatch.setattr(
                replay_authority_module,
                (
                    "_MAX_REPLAY_COMPILATION_JSON_NODES"
                    if record_kind == "compilation"
                    else "_MAX_REPLAY_EXECUTION_CONTEXT_JSON_NODES"
                ),
                8,
            )
            damaged = b"[0,1,2,3,4,5,6,7,8]"
        else:
            monkeypatch.setattr(
                replay_authority_module,
                (
                    "_MAX_REPLAY_COMPILATION_JSON_BYTES"
                    if record_kind == "compilation"
                    else "_MAX_REPLAY_EXECUTION_CONTEXT_JSON_BYTES"
                ),
                128,
            )
            damaged = b'{"padding":"' + b"a" * 128 + b'"}'

        with repository.transaction() as session:
            job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket = session.scalar(select(ReplayTicketRecord))
            item = session.scalar(select(ReplayItemRecord))
            assert job is not None and ticket is not None and item is not None
            identities = (job.job_id, ticket.ticket_id, item.item_id)
            if record_kind == "compilation":
                _disable_sqlite_replay_authority_update_guard(
                    session,
                    table_name=ReplayCompilationRecord.__tablename__,
                )
                session.execute(
                    update(ReplayCompilationRecord).values(
                        canonical_compilation=damaged,
                        byte_length=len(damaged),
                    )
                )
                expected_message = "stored Replay compilation is invalid"
            else:
                _disable_sqlite_replay_authority_update_guard(
                    session,
                    table_name=ReplayExecutionContextRecord.__tablename__,
                )
                session.execute(
                    update(ReplayExecutionContextRecord).values(
                        canonical_context=damaged,
                        byte_length=len(damaged),
                    )
                )
                expected_message = "stored Replay execution context is invalid"

        with pytest.raises(StateConflict, match=expected_message) as exc_info:
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="authenticated-worker-a",
            )
        assert exc_info.value.__cause__ is not None
        assert expected_cause in str(exc_info.value.__cause__)

        with repository.transaction() as session:
            job = session.get(JobRecord, identities[0])
            ticket = session.get(ReplayTicketRecord, identities[1])
            item = session.get(ReplayItemRecord, identities[2])
            assert job is not None and ticket is not None and item is not None
            assert job.state == JobState.QUEUED.value
            assert job.attempts == 0
            assert job.lease_owner is None
            assert job.lease_token_hash is None
            assert ticket.state == ReplayTicketState.ISSUED.value
            assert ticket.claim_principal is None
            assert ticket.lease_token_hash is None
            assert item.state == ReplayItemState.QUEUED.value
    finally:
        repository.close()


def test_replay_claim_rejects_allowed_but_wrong_required_profile_without_state_change(
    tmp_path: Path,
) -> None:
    alternate_profile = "kisa-exact-alternate-v1"
    repository, service = _service(
        tmp_path / "claim-wrong-required-profile.db",
        replay_executor_profiles={
            "authenticated-worker-a": frozenset({EXECUTOR_PROFILE, alternate_profile})
        },
    )
    try:
        _create_batch(repository, service, "claim-wrong-required-profile")
        with repository.transaction() as session:
            job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket = session.scalar(select(ReplayTicketRecord))
            item = session.scalar(select(ReplayItemRecord))
            context = session.scalar(select(ReplayExecutionContextRecord))
            assert job is not None and ticket is not None and item is not None
            assert context is not None
            assert context.required_executor_profile == EXECUTOR_PROFILE
            identities = (job.job_id, ticket.ticket_id, item.item_id)

        with pytest.raises(StateConflict, match="different registered executor profile"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=alternate_profile),
                actor="authenticated-worker-a",
            )

        with repository.transaction() as session:
            job = session.get(JobRecord, identities[0])
            ticket = session.get(ReplayTicketRecord, identities[1])
            item = session.get(ReplayItemRecord, identities[2])
            assert job is not None and ticket is not None and item is not None
            assert job.state == JobState.QUEUED.value
            assert job.attempts == 0
            assert job.lease_owner is None
            assert job.lease_token_hash is None
            assert ticket.state == ReplayTicketState.ISSUED.value
            assert ticket.executor_profile is None
            assert ticket.claim_principal is None
            assert ticket.lease_token_hash is None
            assert item.state == ReplayItemState.QUEUED.value
            assert item.attempts == 1
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 0
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ReplayEventRecord)
                    .where(ReplayEventRecord.event_type == "replay.ticket.claimed")
                )
                == 0
            )
    finally:
        repository.close()


@pytest.mark.parametrize(
    ("actor", "executor_profile"),
    [
        ("unregistered-worker", EXECUTOR_PROFILE),
        ("authenticated-worker-a", "unregistered-executor-profile"),
    ],
)
def test_replay_claim_rejects_unregistered_actor_profile_without_state_change(
    tmp_path: Path,
    actor: str,
    executor_profile: str,
) -> None:
    repository, service = _service(tmp_path / f"registry-{actor}-{executor_profile}.db")
    try:
        _create_batch(repository, service, f"registry-{actor}-{executor_profile}")
        with repository.transaction() as session:
            job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket = session.scalar(select(ReplayTicketRecord))
            item = session.scalar(select(ReplayItemRecord))
            assert job is not None and ticket is not None and item is not None
            identities = (job.job_id, ticket.ticket_id, item.item_id)

        with pytest.raises(StateConflict, match=r"executor|profile|registered"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=executor_profile),
                actor=actor,
            )

        with repository.transaction() as session:
            job = session.get(JobRecord, identities[0])
            ticket = session.get(ReplayTicketRecord, identities[1])
            item = session.get(ReplayItemRecord, identities[2])
            assert job is not None and ticket is not None and item is not None
            assert job.state == JobState.QUEUED.value
            assert job.attempts == 0
            assert job.lease_owner is None
            assert job.lease_token_hash is None
            assert ticket.state == ReplayTicketState.ISSUED.value
            assert ticket.claim_principal is None
            assert ticket.lease_token_hash is None
            assert item.state == ReplayItemState.QUEUED.value
    finally:
        repository.close()


@pytest.mark.parametrize(
    "tamper",
    [
        "extra-run-path",
        "compilation-id",
        "execution-context-id",
        "execution-context-digest",
        "budget-reservation-id",
        "rate-reservation-id",
        "compilation-digest",
        "ticket-id",
    ],
)
def test_replay_claim_rejects_tampered_job_payload_without_burning_ticket(
    tmp_path: Path,
    tamper: str,
) -> None:
    repository, service = _service(tmp_path / f"payload-{tamper}.db")
    try:
        _create_batch(repository, service, f"payload-{tamper}")
        with repository.transaction() as session:
            _disable_sqlite_job_update_authority_guard(session)
            job = session.scalar(
                select(JobRecord).where(JobRecord.kind == InternalJobKind.REPLAY.value)
            )
            ticket = session.scalar(select(ReplayTicketRecord))
            item = session.scalar(select(ReplayItemRecord))
            assert job is not None and ticket is not None and item is not None
            payload = dict(job.payload)
            if tamper == "extra-run-path":
                payload["run_path"] = "/tmp/worker-controlled"
            elif tamper == "compilation-id":
                payload["compilation_id"] = f"replay-compilation_{'0' * 32}"
            elif tamper == "execution-context-id":
                payload["execution_context_id"] = f"replay-context_{'0' * 32}"
            elif tamper == "execution-context-digest":
                payload["execution_context_digest"] = "0" * 64
            elif tamper == "budget-reservation-id":
                payload["budget_reservation_id"] = f"budget-reservation_{'0' * 32}"
            elif tamper == "rate-reservation-id":
                payload["rate_reservation_id"] = f"rate-reservation_{'0' * 32}"
            elif tamper == "compilation-digest":
                payload["compilation_digest"] = "0" * 64
            else:
                payload["ticket_id"] = f"replay-ticket_{'0' * 32}"
            job.payload = payload
            identities = (job.job_id, ticket.ticket_id, item.item_id)

        with pytest.raises(StateConflict, match=r"Replay|payload|binding|authority|integrity"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="authenticated-worker-a",
            )

        with repository.transaction() as session:
            job = session.get(JobRecord, identities[0])
            ticket = session.get(ReplayTicketRecord, identities[1])
            item = session.get(ReplayItemRecord, identities[2])
            assert job is not None and ticket is not None and item is not None
            assert job.state == JobState.QUEUED.value
            assert job.attempts == 0
            assert job.lease_owner is None
            assert job.lease_token_hash is None
            assert ticket.state == ReplayTicketState.ISSUED.value
            assert ticket.claim_principal is None
            assert ticket.lease_token_hash is None
            assert item.state == ReplayItemState.QUEUED.value
            assert item.attempts == 1
    finally:
        repository.close()


def test_two_workers_can_burn_one_sqlite_replay_ticket_exactly_once(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "claim-race.db")
    try:
        _create_batch(repository, service, "claim-race")
        barrier = Barrier(2)

        def claim(actor: str):
            barrier.wait()
            return service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor=actor,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, ["race-worker-a", "race-worker-b"]))

        winners = [result for result in results if result is not None]
        assert len(winners) == 1
        winner = winners[0]
        with repository.transaction() as session:
            ticket = session.get(ReplayTicketRecord, winner.ticket.ticket_id)
            job = session.get(JobRecord, winner.job.job_id)
            assert ticket is not None and job is not None
            assert ticket.state == ReplayTicketState.CLAIMED.value
            assert ticket.claim_principal == winner.ticket.claimed_by
            assert job.state == JobState.LEASED.value
            assert job.attempts == 1
    finally:
        repository.close()


def test_replay_tool_permit_is_canonical_and_idempotent_across_restart(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "tool-permit-idempotent.db"
    repository, service = _service(database_path)
    restarted_repository: ControlPlaneRepository | None = None
    try:
        _create_batch(repository, service, "tool-permit-idempotent")
        claimed = _claim(service, actor="heartbeat-worker")
        request = _permit_request(claimed, 1)

        first = service.issue_replay_tool_permit(
            claimed.job.job_id,
            request,
            actor="heartbeat-worker",
        )
        restarted_repository, restarted_service = _service(database_path)
        repeated = restarted_service.issue_replay_tool_permit(
            claimed.job.job_id,
            request,
            actor="heartbeat-worker",
        )

        assert repeated == first
        assert first.ticket_id == claimed.ticket.ticket_id
        assert first.job_id == claimed.job.job_id
        assert first.item_id == claimed.item.item_id
        assert first.batch_id == claimed.batch.batch_id
        assert first.replay_run_id == claimed.item.replay_run_id
        assert first.call_ordinal == 1
        assert first.issued_to == "heartbeat-worker"
        assert first.executor_profile == EXECUTOR_PROFILE
        assert first.tool_call_units == 1
        assert first.expires_at <= first.issued_at + timedelta(seconds=30)

        with repository.transaction() as session:
            permit = session.scalar(select(ReplayToolPermitRecord))
            compilation = session.get(ReplayCompilationRecord, first.compilation_id)
            execution_context_record = session.scalar(
                select(ReplayExecutionContextRecord).where(
                    ReplayExecutionContextRecord.compilation_id == first.compilation_id
                )
            )
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget = session.get(
                ReplayBudgetReservationRecord,
                first.budget_reservation_id,
            )
            rate = session.get(ReplayRateReservationRecord, first.rate_reservation_id)
            assert permit is not None
            assert compilation is not None
            assert execution_context_record is not None
            assert budget_account is not None
            assert budget is not None
            assert rate is not None
            trusted = ReplayCompilation.model_validate_json(compilation.canonical_compilation)
            trusted_context = ReplayExecutionContext.model_validate_json(
                execution_context_record.canonical_context
            )
            assert first.permit_digest == permit.permit_digest
            assert first.compilation_id == trusted_context.compilation_id
            assert first.compilation_id == claimed.execution_context.compilation_id
            assert execution_context_record.context_id == claimed.execution_context.context_id
            assert execution_context_record.context_digest == claimed.execution_context_digest
            assert replay_execution_context_digest(trusted_context) == (
                execution_context_record.context_digest
            )
            payload = ReplayJobPayload.model_validate(claimed.job.payload)
            assert payload.execution_context_id == execution_context_record.context_id
            assert payload.execution_context_digest == execution_context_record.context_digest
            assert first.compilation_digest == execution_context_record.compilation_digest
            assert first.grant_digest == execution_context_record.grant_digest
            assert first.replay_run_id == trusted_context.replay_run_id
            assert first.source_root_digest == trusted_context.source_root_digest
            assert first.original_request_id == trusted.original_request.request_id
            assert first.tool_id == trusted.original_request.tool_id
            assert first.tool_version == trusted.spec.binding.tool_version
            assert first.tool_id == trusted_context.tool_spec.tool_id
            assert first.tool_version == trusted_context.tool_spec.version
            assert first.target_id == trusted.spec.binding.target_id
            assert first.target == trusted.original_request.target
            context_target = next(
                target
                for target in trusted_context.campaign.spec.targets
                if target.id == first.target_id
            )
            assert first.target == context_target.endpoint
            assert first.method == trusted.original_request.method
            assert first.method == trusted_context.scenario.method.upper()
            assert first.compiled_argument_digest == trusted.spec.argument_digest
            assert first.request_units == AIChatProbeTool().network_request_cost(
                trusted.original_request
            )
            assert budget.consumed_calls == 1
            assert budget.released_calls == 0
            assert budget_account.consumed_calls == 1
            assert budget_account.reserved_calls == budget.total_calls - 1
            assert rate.consumed_request_units == first.request_units
            assert rate.released_request_units == 0
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ReplayEventRecord)
                    .where(ReplayEventRecord.event_type == "replay.tool-permit.issued")
                )
                == 1
            )
    finally:
        if restarted_repository is not None:
            restarted_repository.close()
        repository.close()


def test_replay_tool_permit_rejects_context_payload_swap_without_consumption(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "tool-permit-context-swap.db")
    try:
        _create_batch(repository, service, "tool-permit-context-swap-a")
        _create_batch(repository, service, "tool-permit-context-swap-b")
        first = _claim(service, actor="authenticated-worker-a")
        second = _claim(service, actor="authenticated-worker-b")

        with repository.transaction() as session:
            _disable_sqlite_job_update_authority_guard(session)
            job = session.get(JobRecord, first.job.job_id)
            assert job is not None
            payload = dict(job.payload)
            payload["execution_context_id"] = second.execution_context.context_id
            payload["execution_context_digest"] = second.execution_context_digest
            job.payload = payload

        with pytest.raises(StateConflict, match=r"Replay|payload|binding"):
            service.issue_replay_tool_permit(
                first.job.job_id,
                _permit_request(first, 1),
                actor="authenticated-worker-a",
            )

        with repository.transaction() as session:
            budget = session.get(
                ReplayBudgetReservationRecord,
                first.ticket.budget_reservation_id,
            )
            rate = session.get(
                ReplayRateReservationRecord,
                first.ticket.rate_reservation_id,
            )
            assert budget is not None and rate is not None
            assert budget.consumed_calls == 0
            assert rate.consumed_request_units == 0
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 0
    finally:
        repository.close()


def test_replay_tool_permits_are_sequential_and_exhaust_exact_reservations(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "tool-permit-sequential.db")
    try:
        _create_batch(repository, service, "tool-permit-sequential")
        claimed = _claim(service, actor="heartbeat-worker")

        with pytest.raises(StateConflict, match="ordinal"):
            service.issue_replay_tool_permit(
                claimed.job.job_id,
                _permit_request(claimed, 2),
                actor="heartbeat-worker",
            )
        first = service.issue_replay_tool_permit(
            claimed.job.job_id,
            _permit_request(claimed, 1),
            actor="heartbeat-worker",
        )
        second = service.issue_replay_tool_permit(
            claimed.job.job_id,
            _permit_request(claimed, 2),
            actor="heartbeat-worker",
        )
        assert first.call_ordinal == 1
        assert second.call_ordinal == 2
        assert second.permit_id != first.permit_id
        assert (
            service.issue_replay_tool_permit(
                claimed.job.job_id,
                _permit_request(claimed, 1),
                actor="heartbeat-worker",
            )
            == first
        )

        with pytest.raises(StateConflict, match="exhausted"):
            service.issue_replay_tool_permit(
                claimed.job.job_id,
                _permit_request(claimed, 3),
                actor="heartbeat-worker",
            )

        refreshed = service.heartbeat_replay_job(
            claimed.job.job_id,
            ReplayLeaseRequest(
                executor_profile=EXECUTOR_PROFILE,
                lease_token=claimed.lease_token,
                ticket_id=claimed.ticket.ticket_id,
                fencing_value=claimed.ticket.fencing_value,
            ),
            actor="heartbeat-worker",
        )
        assert refreshed.ticket.state is ReplayTicketState.CLAIMED
        with repository.transaction() as session:
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget = session.get(
                ReplayBudgetReservationRecord,
                claimed.ticket.budget_reservation_id,
            )
            rate = session.get(
                ReplayRateReservationRecord,
                claimed.ticket.rate_reservation_id,
            )
            assert budget_account is not None and budget is not None and rate is not None
            assert budget.state == "consumed"
            assert budget.consumed_calls == budget.total_calls == 2
            assert budget_account.reserved_calls == 0
            assert budget_account.consumed_calls == 2
            assert rate.state == "consumed"
            assert rate.consumed_request_units == rate.total_request_units
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 2
    finally:
        repository.close()


def test_replay_tool_permit_rejects_stale_identity_without_consumption(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "tool-permit-identity.db")
    try:
        _create_batch(repository, service, "tool-permit-identity")
        claimed = _claim(service, actor="heartbeat-worker")
        request = _permit_request(claimed, 1)

        for stale_request, stale_actor in (
            (request, "stale-worker"),
            (request.model_copy(update={"lease_token": "x" * 32}), "heartbeat-worker"),
            (
                request.model_copy(update={"ticket_id": f"replay-ticket_{'0' * 32}"}),
                "heartbeat-worker",
            ),
            (
                request.model_copy(update={"fencing_value": claimed.ticket.fencing_value + 1}),
                "heartbeat-worker",
            ),
        ):
            with pytest.raises(LeaseRejected):
                service.issue_replay_tool_permit(
                    claimed.job.job_id,
                    stale_request,
                    actor=stale_actor,
                )
        with pytest.raises(StateConflict, match=r"executor|profile|registered"):
            service.issue_replay_tool_permit(
                claimed.job.job_id,
                request.model_copy(update={"executor_profile": "unregistered-profile"}),
                actor="heartbeat-worker",
            )

        with repository.transaction() as session:
            budget = session.scalar(select(ReplayBudgetReservationRecord))
            rate = session.scalar(select(ReplayRateReservationRecord))
            assert budget is not None and rate is not None
            assert budget.consumed_calls == 0
            assert rate.consumed_request_units == 0
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 0
    finally:
        repository.close()


def test_unclaimed_replay_job_cannot_issue_tool_permit(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "tool-permit-unclaimed.db")
    try:
        _create_batch(repository, service, "tool-permit-unclaimed")
        with repository.transaction() as session:
            ticket = session.scalar(select(ReplayTicketRecord))
            assert ticket is not None
            job_id = ticket.job_id
            request = ReplayToolPermitRequest(
                executor_profile=EXECUTOR_PROFILE,
                lease_token="unclaimed-replay-token-is-never-authority",
                ticket_id=ticket.ticket_id,
                fencing_value=ticket.fencing_value,
                call_ordinal=1,
            )

        with pytest.raises(LeaseRejected):
            service.issue_replay_tool_permit(
                job_id,
                request,
                actor="heartbeat-worker",
            )
        with repository.transaction() as session:
            budget = session.scalar(select(ReplayBudgetReservationRecord))
            rate = session.scalar(select(ReplayRateReservationRecord))
            assert budget is not None and rate is not None
            assert budget.consumed_calls == 0
            assert rate.consumed_request_units == 0
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 0
    finally:
        repository.close()


def test_replay_tool_permit_rechecks_rate_window_after_original_reservation_expires(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "tool-permit-rate-readmission.db")
    try:
        _create_batch(repository, service, "tool-permit-rate-readmission")
        claimed = service.claim_replay_job(
            ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE, lease_seconds=300),
            actor="heartbeat-worker",
        )
        assert claimed is not None
        first = service.issue_replay_tool_permit(
            claimed.job.job_id,
            _permit_request(claimed, 1),
            actor="heartbeat-worker",
        )
        with repository.transaction() as session:
            rate = session.get(
                ReplayRateReservationRecord,
                claimed.ticket.rate_reservation_id,
            )
            permit = session.get(ReplayToolPermitRecord, first.permit_id)
            assert rate is not None and permit is not None
            rate_expires_at = (
                rate.expires_at
                if rate.expires_at.tzinfo is not None
                else rate.expires_at.replace(tzinfo=UTC)
            )
            permit_window_expires_at = (
                permit.rate_window_expires_at
                if permit.rate_window_expires_at.tzinfo is not None
                else permit.rate_window_expires_at.replace(tzinfo=UTC)
            )
        assert permit_window_expires_at > rate_expires_at
        readmission_time = rate_expires_at + (permit_window_expires_at - rate_expires_at) / 2
        monkeypatch.setattr(control_plane_service_module, "utc_now", lambda: readmission_time)

        second = service.issue_replay_tool_permit(
            claimed.job.job_id,
            _permit_request(claimed, 2),
            actor="heartbeat-worker",
        )

        assert second.call_ordinal == 2
        assert second.issued_at == readmission_time
        with repository.transaction() as session:
            rate = session.get(
                ReplayRateReservationRecord,
                claimed.ticket.rate_reservation_id,
            )
            assert rate is not None
            assert rate.state == "consumed"
            assert rate.consumed_request_units == rate.total_request_units
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 2
    finally:
        repository.close()


def test_expired_replay_lease_keeps_issued_permit_consumed_and_releases_only_remainder(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "tool-permit-expiry.db")
    try:
        _create_batch(repository, service, "tool-permit-expiry")
        claimed = _claim(service, actor="expired-worker")
        issued = service.issue_replay_tool_permit(
            claimed.job.job_id,
            _permit_request(claimed, 1),
            actor="expired-worker",
        )
        _force_replay_lease_expired(
            repository,
            job_id=claimed.job.job_id,
            ticket_id=claimed.ticket.ticket_id,
        )

        with pytest.raises(LeaseRejected, match="expired"):
            service.issue_replay_tool_permit(
                claimed.job.job_id,
                _permit_request(claimed, 2),
                actor="expired-worker",
            )

        assert service.get_job(claimed.job.job_id).state is JobState.FAILED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.ABANDONED
        )
        assert service.get_replay_item(claimed.item.item_id).state is ReplayItemState.FAILED
        assert service.get_replay_batch(claimed.batch.batch_id).state is ReplayBatchState.FAILED
        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replacement-worker",
            )
            is None
        )
        with repository.transaction() as session:
            permits = list(session.scalars(select(ReplayToolPermitRecord)))
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget = session.get(
                ReplayBudgetReservationRecord,
                claimed.ticket.budget_reservation_id,
            )
            rate = session.get(
                ReplayRateReservationRecord,
                claimed.ticket.rate_reservation_id,
            )
            assert [permit.permit_id for permit in permits] == [issued.permit_id]
            assert budget_account is not None and budget is not None and rate is not None
            assert budget.state == "released"
            assert budget.consumed_calls == 1
            assert budget.released_calls == budget.total_calls - 1
            assert budget_account.consumed_calls == 1
            assert budget_account.released_calls >= budget.released_calls
            assert rate.state == "released"
            assert rate.consumed_request_units == issued.request_units
            assert rate.released_request_units == rate.total_request_units - issued.request_units
            terminal_event = session.scalar(
                select(ReplayEventRecord).where(
                    ReplayEventRecord.ticket_id == claimed.ticket.ticket_id,
                    ReplayEventRecord.event_type == "replay.ticket.lease-expired",
                )
            )
            assert terminal_event is not None
            assert terminal_event.payload["retryPending"] is False
            assert terminal_event.payload["issuedPermitCount"] == 1
            assert terminal_event.payload["sideEffectsUncertain"] is True
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 1
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
    finally:
        repository.close()


def test_cancelling_replay_after_permit_never_refunds_consumed_call(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "tool-permit-cancel.db")
    try:
        _create_batch(repository, service, "tool-permit-cancel")
        claimed = _claim(service, actor="cancelled-worker")
        issued = service.issue_replay_tool_permit(
            claimed.job.job_id,
            _permit_request(claimed, 1),
            actor="cancelled-worker",
        )

        service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="cancel after an uncertain Tool execution"),
            actor="replay-operator",
        )

        with repository.transaction() as session:
            permit = session.get(ReplayToolPermitRecord, issued.permit_id)
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget = session.get(
                ReplayBudgetReservationRecord,
                issued.budget_reservation_id,
            )
            rate = session.get(ReplayRateReservationRecord, issued.rate_reservation_id)
            assert permit is not None
            assert budget_account is not None and budget is not None and rate is not None
            assert budget.consumed_calls == 1
            assert budget.released_calls == budget.total_calls - 1
            assert budget_account.consumed_calls == 1
            assert rate.consumed_request_units == issued.request_units
            assert rate.released_request_units == rate.total_request_units - issued.request_units
        with pytest.raises((RunCancelled, LeaseRejected, StateConflict)):
            service.issue_replay_tool_permit(
                claimed.job.job_id,
                _permit_request(claimed, 2),
                actor="cancelled-worker",
            )
    finally:
        repository.close()


def test_replay_tool_permit_rolls_back_after_late_audit_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "tool-permit-rollback.db")
    try:
        _create_batch(repository, service, "tool-permit-rollback")
        claimed = _claim(service, actor="heartbeat-worker")

        def fail_audit(*args, **kwargs):
            raise RuntimeError("injected permit audit failure")

        monkeypatch.setattr(service, "_replay_event", fail_audit)
        with pytest.raises(RuntimeError, match="injected permit audit failure"):
            service.issue_replay_tool_permit(
                claimed.job.job_id,
                _permit_request(claimed, 1),
                actor="heartbeat-worker",
            )

        with repository.transaction() as session:
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget = session.scalar(select(ReplayBudgetReservationRecord))
            rate = session.scalar(select(ReplayRateReservationRecord))
            assert budget_account is not None and budget is not None and rate is not None
            assert budget.consumed_calls == 0
            assert budget.state == "active"
            assert budget_account.consumed_calls == 0
            assert budget_account.reserved_calls == budget.total_calls
            assert rate.consumed_request_units == 0
            assert rate.state == "active"
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 0
    finally:
        repository.close()


def test_active_replay_permit_window_remains_counted_after_reservation_expiry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, service = _service(tmp_path / "tool-permit-rate-window.db")
    try:
        real_derive = control_plane_service_module.derive_kisa_confirmation_batch

        def derive_with_exact_rate_cap(**kwargs):
            derived = real_derive(**kwargs)
            rate_cap = derived.observed_campaign_request_units + derived.required_request_units
            rules = derived.campaign.spec.rules_of_engagement.model_copy(
                update={"max_requests_per_minute": rate_cap}
            )
            campaign = derived.campaign.model_copy(
                update={
                    "spec": derived.campaign.spec.model_copy(update={"rules_of_engagement": rules})
                }
            )
            return replace(
                derived,
                campaign=campaign,
                max_requests_per_minute=rate_cap,
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "derive_kisa_confirmation_batch",
            derive_with_exact_rate_cap,
        )
        source = _seed_completed_source(repository, service, "tool-permit-rate-window")
        first_request = _batch_request(source, "tool-permit-rate-window-first")
        first_batch = service.create_replay_batch(
            first_request,
            actor="trusted-replay-admission",
        )
        service.issue_replay_batch(first_batch.batch_id, actor="trusted-replay-admission")
        claimed = _claim(service, actor="heartbeat-worker")
        issued = service.issue_replay_tool_permit(
            claimed.job.job_id,
            _permit_request(claimed, 1),
            actor="heartbeat-worker",
        )

        now = datetime.now(UTC)
        with repository.transaction() as session:
            session.execute(
                update(ReplayRateReservationRecord)
                .where(
                    ReplayRateReservationRecord.rate_reservation_id == issued.rate_reservation_id
                )
                .values(
                    reserved_at=now - timedelta(minutes=2),
                    expires_at=now - timedelta(minutes=1),
                )
            )

        second_request = _batch_request(source, "tool-permit-rate-window-second")
        second_batch = service.create_replay_batch(
            second_request,
            actor="trusted-replay-admission",
        )
        with pytest.raises(StateConflict, match="rate reservation"):
            service.issue_replay_batch(
                second_batch.batch_id,
                actor="trusted-replay-admission",
            )

        with repository.transaction() as session:
            permit = session.get(ReplayToolPermitRecord, issued.permit_id)
            second_stored = session.get(ReplayBatchRecord, second_batch.batch_id)
            assert permit is not None and second_stored is not None
            permit_window_expires_at = (
                permit.rate_window_expires_at
                if permit.rate_window_expires_at.tzinfo is not None
                else permit.rate_window_expires_at.replace(tzinfo=UTC)
            )
            assert permit_window_expires_at > now
            assert second_stored.state == ReplayBatchState.PLANNED.value
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ReplayTicketRecord)
                    .where(ReplayTicketRecord.batch_id == second_batch.batch_id)
                )
                == 0
            )
    finally:
        repository.close()


def test_replay_heartbeat_requires_exact_actor_ticket_fence_and_dedicated_path(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "heartbeat.db")
    try:
        _create_batch(repository, service, "heartbeat")
        claimed = _claim(service, actor="heartbeat-worker")
        request = ReplayLeaseRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claimed.lease_token,
            lease_seconds=45,
            ticket_id=claimed.ticket.ticket_id,
            fencing_value=claimed.ticket.fencing_value,
        )

        refreshed = service.heartbeat_replay_job(
            claimed.job.job_id,
            request,
            actor="heartbeat-worker",
        )
        assert refreshed.ticket.lease_expires_at is not None
        assert refreshed.job.lease_expires_at == refreshed.ticket.lease_expires_at

        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request,
                actor="stale-worker",
            )
        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request.model_copy(update={"fencing_value": claimed.ticket.fencing_value + 1}),
                actor="heartbeat-worker",
            )
        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request.model_copy(update={"lease_token": "x" * 32}),
                actor="heartbeat-worker",
            )
        with pytest.raises(LeaseRejected):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request.model_copy(update={"ticket_id": f"replay-ticket_{'0' * 32}"}),
                actor="heartbeat-worker",
            )
        with pytest.raises(StateConflict, match=r"executor|profile|registered"):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                request.model_copy(update={"executor_profile": "unregistered-profile"}),
                actor="heartbeat-worker",
            )

        with pytest.raises(StateConflict, match="Replay"):
            service.heartbeat(
                claimed.job.job_id,
                LeaseRequest(
                    worker_id="heartbeat-worker",
                    lease_token=claimed.lease_token,
                ),
                actor="heartbeat-worker",
            )
        with pytest.raises(StateConflict, match="Replay"):
            service.complete_job(
                claimed.job.job_id,
                CompleteJobRequest(
                    worker_id="heartbeat-worker",
                    lease_token=claimed.lease_token,
                    result={"workerVerdict": "confirmed"},
                ),
                actor="heartbeat-worker",
            )
        with pytest.raises(StateConflict, match="Replay"):
            service.fail_job(
                claimed.job.job_id,
                FailJobRequest(
                    worker_id="heartbeat-worker",
                    lease_token=claimed.lease_token,
                    error="generic retry must not requeue Replay",
                    retryable=True,
                ),
                actor="heartbeat-worker",
            )
        with pytest.raises(StateConflict, match="Replay"):
            service.create_checkpoint(
                claimed.job.job_id,
                CreateCheckpointRequest(
                    worker_id="heartbeat-worker",
                    lease_token=claimed.lease_token,
                    state={"untrusted": "checkpoint"},
                    pending_intent=ApprovalIntent(
                        call_fingerprint="a" * 64,
                        tool_id="mock.replay-bypass",
                        target="lab://replay-bypass",
                        risk_tier=ToolRiskTier.T3,
                        expires_at=datetime.now(UTC) + timedelta(minutes=5),
                    ),
                ),
                actor="heartbeat-worker",
            )

        assert service.get_job(claimed.job.job_id).state is JobState.LEASED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.CLAIMED
        )
    finally:
        repository.close()


def test_claimed_replay_lease_ignores_burned_issuance_but_respects_authority_deadline(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "claimed-lease-deadline.db")
    try:
        _create_batch(repository, service, "claimed-lease-deadline")
        now = datetime.now(UTC)
        with repository.transaction() as session:
            ticket = session.scalar(select(ReplayTicketRecord))
            assert ticket is not None
            rate_reservation = session.get(
                ReplayRateReservationRecord,
                ticket.rate_reservation_id,
            )
            assert rate_reservation is not None
            rate_deadline = (
                rate_reservation.expires_at
                if rate_reservation.expires_at.tzinfo is not None
                else rate_reservation.expires_at.replace(tzinfo=UTC)
            )
            issuance_deadline = min(
                rate_deadline - timedelta(seconds=1),
                now + timedelta(seconds=1),
            )
            assert issuance_deadline > now
            session.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.ticket_id == ticket.ticket_id)
                .values(
                    issued_at=now - timedelta(minutes=1),
                    expires_at=issuance_deadline,
                )
            )
        claimed = service.claim_replay_job(
            ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE, lease_seconds=5),
            actor="heartbeat-worker",
        )
        assert claimed is not None
        assert claimed.ticket.lease_expires_at is not None
        with repository.transaction() as session:
            ticket = session.get(ReplayTicketRecord, claimed.ticket.ticket_id)
            assert ticket is not None
            stored_issuance_deadline = (
                ticket.expires_at
                if ticket.expires_at.tzinfo is not None
                else ticket.expires_at.replace(tzinfo=UTC)
            )
        assert stored_issuance_deadline == issuance_deadline
        assert claimed.ticket.lease_expires_at > stored_issuance_deadline

        refreshed = service.heartbeat_replay_job(
            claimed.job.job_id,
            ReplayLeaseRequest(
                executor_profile=EXECUTOR_PROFILE,
                lease_token=claimed.lease_token,
                lease_seconds=300,
                ticket_id=claimed.ticket.ticket_id,
                fencing_value=claimed.ticket.fencing_value,
            ),
            actor="heartbeat-worker",
        )
        assert refreshed.ticket.lease_expires_at is not None
        assert refreshed.ticket.lease_expires_at > claimed.ticket.lease_expires_at
        hard_authority_deadline = min(
            claimed.compilation.spec.expires_at,
            claimed.compilation.grant.expires_at,
        )
        assert refreshed.ticket.lease_expires_at <= hard_authority_deadline
        assert refreshed.ticket.lease_expires_at > stored_issuance_deadline
    finally:
        repository.close()


def test_expired_issued_replay_ticket_is_abandoned_before_claim(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "expired-issued-ticket.db")
    try:
        _create_batch(
            repository,
            service,
            "expired-issued-ticket",
            required_attempts=1,
            max_attempts=1,
        )
        now = datetime.now(UTC)
        with repository.transaction() as session:
            ticket = session.scalar(select(ReplayTicketRecord))
            assert ticket is not None
            ticket_id = ticket.ticket_id
            job_id = ticket.job_id
            item_id = ticket.item_id
            session.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.ticket_id == ticket_id)
                .values(issued_at=now - timedelta(minutes=2), expires_at=now - timedelta(minutes=1))
            )

        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="expired-worker",
            )
            is None
        )
        assert service.get_job(job_id).state is JobState.FAILED
        assert service.get_replay_ticket(ticket_id).state is ReplayTicketState.ABANDONED
        assert service.get_replay_item(item_id).state is ReplayItemState.FAILED
        with repository.transaction() as session:
            batch = session.scalar(select(ReplayBatchRecord))
            assert batch is not None
            assert batch.state == ReplayBatchState.FAILED.value

        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replacement-worker",
            )
            is None
        )
    finally:
        repository.close()


def test_replay_expiry_prelocks_complete_capacity_graph_in_global_order() -> None:
    class Result:
        def __init__(self, rows: list[object]) -> None:
            self.rows = rows

        def all(self) -> list[object]:
            return self.rows

    class RecordingSession:
        def __init__(self) -> None:
            self.calls: list[tuple[str, object]] = []
            self.execute_results = iter(
                [
                    Result([("budget-a", "budget-account-z"), ("budget-b", "budget-account-a")]),
                    Result([("rate-a", "rate-account-z"), ("rate-b", "rate-account-a")]),
                ]
            )
            self.scalar_results = iter(
                [
                    Result(
                        [
                            SimpleNamespace(budget_account_id="budget-account-a"),
                            SimpleNamespace(budget_account_id="budget-account-z"),
                        ]
                    ),
                    Result(
                        [
                            SimpleNamespace(rate_account_id="rate-account-a"),
                            SimpleNamespace(rate_account_id="rate-account-z"),
                        ]
                    ),
                    Result(["budget-a", "budget-b", "budget-sibling"]),
                    Result(["rate-a", "rate-b", "rate-sibling"]),
                ]
            )

        def execute(self, statement: object) -> Result:
            self.calls.append(("execute", statement))
            return next(self.execute_results)

        def scalars(self, statement: object) -> Result:
            self.calls.append(("scalars", statement))
            return next(self.scalar_results)

    tickets = [
        SimpleNamespace(budget_reservation_id="budget-a", rate_reservation_id="rate-a"),
        SimpleNamespace(budget_reservation_id="budget-b", rate_reservation_id="rate-b"),
    ]
    recording = RecordingSession()
    service = object.__new__(ControlPlaneService)

    service._prelock_replay_capacity(recording, tickets)  # type: ignore[arg-type]

    assert [kind for kind, _statement in recording.calls] == [
        "execute",
        "execute",
        "scalars",
        "scalars",
        "scalars",
        "scalars",
    ]
    statements = [
        " ".join(
            str(
                statement.compile(  # type: ignore[attr-defined]
                    dialect=postgresql.dialect(),
                    compile_kwargs={"literal_binds": False},
                )
            ).split()
        )
        for _kind, statement in recording.calls
    ]
    assert "cp_replay_budget_reservations.budget_reservation_id IN" in statements[0]
    assert "cp_replay_rate_reservations.rate_reservation_id IN" in statements[1]
    assert "ORDER BY cp_replay_budget_accounts.budget_account_id" in statements[2]
    assert "ORDER BY cp_replay_rate_accounts.rate_account_id" in statements[3]
    assert "cp_replay_budget_reservations.budget_account_id IN" in statements[4]
    assert "ORDER BY cp_replay_budget_reservations.budget_reservation_id" in statements[4]
    assert "cp_replay_rate_reservations.rate_account_id IN" in statements[5]
    assert "ORDER BY cp_replay_rate_reservations.rate_reservation_id" in statements[5]
    assert all(statement.endswith("FOR UPDATE") for statement in statements[2:])


def test_expired_replay_claim_gets_fresh_retry_and_stale_mutations_fail(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "expiry.db"
    repository, service = _service(database_path)
    try:
        _create_batch(
            repository,
            service,
            "expiry",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        claimed = _claim(service, actor="expired-worker")
        staging_root, _artifact_root = _artifact_roots(database_path)
        prior_staging = staging_root / claimed.execution_context.output_staging_id
        assert prior_staging.is_dir()
        expired_at = datetime.now(UTC) - timedelta(seconds=1)
        with repository.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id == claimed.job.job_id)
                .values(lease_expires_at=expired_at)
            )
            session.execute(
                update(ReplayTicketRecord)
                .where(ReplayTicketRecord.ticket_id == claimed.ticket.ticket_id)
                .values(lease_expires_at=expired_at)
            )

        assert service.requeue_expired(actor="lease-reaper") == 1
        assert service.requeue_expired(actor="lease-reaper") == 0
        assert service.get_job(claimed.job.job_id).state is JobState.FAILED
        assert service.get_run(claimed.job.run_id).state is RunState.FAILED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.ABANDONED
        )
        assert service.get_replay_item(claimed.item.item_id).state is (
            ReplayItemState.RETRY_PENDING
        )
        assert service.get_replay_batch(claimed.batch.batch_id).state is (ReplayBatchState.RUNNING)
        replacement = service.claim_replay_job(
            ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
            actor="replacement-worker",
        )
        assert replacement is not None
        assert replacement.item.item_id == claimed.item.item_id
        assert replacement.item.candidate_id == claimed.item.candidate_id
        assert replacement.item.candidate_digest == claimed.item.candidate_digest
        assert replacement.item.contract_digest == claimed.item.contract_digest
        assert replacement.item.attempts == replacement.ticket.attempt == 2
        assert replacement.ticket.fencing_value == 2
        assert replacement.job.job_id != claimed.job.job_id
        assert replacement.job.run_id != claimed.job.run_id
        assert replacement.ticket.ticket_id != claimed.ticket.ticket_id
        assert replacement.ticket.compilation_id != claimed.ticket.compilation_id
        assert replacement.item.compilation_digest != claimed.item.compilation_digest
        assert replacement.item.grant_digest != claimed.item.grant_digest
        assert replacement.execution_context.context_id != claimed.execution_context.context_id
        assert (
            replacement.execution_context.output_staging_id
            != claimed.execution_context.output_staging_id
        )
        assert not prior_staging.exists()
        assert (staging_root / replacement.execution_context.output_staging_id).is_dir()

        stale = ReplayLeaseRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claimed.lease_token,
            ticket_id=claimed.ticket.ticket_id,
            fencing_value=claimed.ticket.fencing_value,
        )
        with pytest.raises((LeaseRejected, StateConflict)):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                stale,
                actor="expired-worker",
            )
        with pytest.raises(StateConflict, match="Replay"):
            service.complete_job(
                claimed.job.job_id,
                CompleteJobRequest(
                    worker_id="expired-worker",
                    lease_token=claimed.lease_token,
                    result={"late": True},
                ),
                actor="expired-worker",
            )

        with repository.transaction() as session:
            jobs = list(
                session.scalars(
                    select(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                    .order_by(JobRecord.created_at, JobRecord.job_id)
                ).all()
            )
            tickets = list(
                session.scalars(
                    select(ReplayTicketRecord).order_by(ReplayTicketRecord.attempt_number)
                ).all()
            )
            budget_reservations = list(
                session.scalars(
                    select(ReplayBudgetReservationRecord).order_by(
                        ReplayBudgetReservationRecord.attempt_number
                    )
                ).all()
            )
            rate_reservations = list(
                session.scalars(
                    select(ReplayRateReservationRecord).order_by(
                        ReplayRateReservationRecord.attempt_number
                    )
                ).all()
            )
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            events = list(
                session.scalars(
                    select(ReplayEventRecord)
                    .where(ReplayEventRecord.batch_id == claimed.batch.batch_id)
                    .order_by(ReplayEventRecord.sequence)
                ).all()
            )
            assert len(jobs) == len(tickets) == 2
            assert [ticket.attempt_number for ticket in tickets] == [1, 2]
            assert [ticket.fencing_value for ticket in tickets] == [1, 2]
            assert [reservation.state for reservation in budget_reservations] == [
                "released",
                "active",
            ]
            assert [reservation.state for reservation in rate_reservations] == [
                "released",
                "active",
            ]
            assert budget_account is not None
            assert budget_account.reserved_calls == budget_reservations[1].total_calls
            assert budget_account.consumed_calls == 0
            assert budget_account.released_calls == budget_reservations[0].total_calls
            assert [event.sequence for event in events] == list(range(1, len(events) + 1))
            assert sum(event.event_type == "replay.retry-issued" for event in events) == 1
    finally:
        repository.close()


def test_replay_retry_mints_fresh_authority_until_max_attempts(tmp_path: Path) -> None:
    database_path = tmp_path / "retry-max-attempts.db"
    repository, service = _service(database_path)
    try:
        _create_batch(
            repository,
            service,
            "retry-max-attempts",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        claims = [_claim(service, actor="expired-worker")]
        for expected_attempt in (2, 3):
            previous = claims[-1]
            _force_replay_lease_expired(
                repository,
                job_id=previous.job.job_id,
                ticket_id=previous.ticket.ticket_id,
            )
            assert service.requeue_expired(actor="lease-reaper") == 1
            current = _claim(service, actor="replacement-worker")
            assert current.ticket.attempt == current.item.attempts == expected_attempt
            assert current.ticket.fencing_value == expected_attempt
            assert current.item.item_id == previous.item.item_id
            assert current.item.candidate_digest == previous.item.candidate_digest
            assert current.item.contract_digest == previous.item.contract_digest
            claims.append(current)

        final_attempt = claims[-1]
        _force_replay_lease_expired(
            repository,
            job_id=final_attempt.job.job_id,
            ticket_id=final_attempt.ticket.ticket_id,
        )
        assert service.requeue_expired(actor="lease-reaper") == 1
        assert service.get_replay_item(final_attempt.item.item_id).state is ReplayItemState.FAILED
        assert service.get_replay_batch(final_attempt.batch.batch_id).state is (
            ReplayBatchState.FAILED
        )
        assert (
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replacement-worker",
            )
            is None
        )

        assert len({claim.job.job_id for claim in claims}) == 3
        assert len({claim.job.run_id for claim in claims}) == 3
        assert len({claim.ticket.ticket_id for claim in claims}) == 3
        assert len({claim.ticket.compilation_id for claim in claims}) == 3
        assert len({claim.execution_context.context_id for claim in claims}) == 3
        assert len({claim.execution_context.output_staging_id for claim in claims}) == 3
        assert len({claim.item.compilation_digest for claim in claims}) == 3
        assert len({claim.item.grant_digest for claim in claims}) == 3

        with repository.transaction() as session:
            tickets = list(
                session.scalars(
                    select(ReplayTicketRecord).order_by(ReplayTicketRecord.attempt_number)
                ).all()
            )
            jobs = list(
                session.scalars(
                    select(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                    .order_by(JobRecord.created_at, JobRecord.job_id)
                ).all()
            )
            contexts = list(session.scalars(select(ReplayExecutionContextRecord)).all())
            budget_reservations = list(
                session.scalars(
                    select(ReplayBudgetReservationRecord).order_by(
                        ReplayBudgetReservationRecord.attempt_number
                    )
                ).all()
            )
            rate_reservations = list(
                session.scalars(
                    select(ReplayRateReservationRecord).order_by(
                        ReplayRateReservationRecord.attempt_number
                    )
                ).all()
            )
            retry_events = int(
                session.scalar(
                    select(func.count())
                    .select_from(ReplayEventRecord)
                    .where(ReplayEventRecord.event_type == "replay.retry-issued")
                )
                or 0
            )
            assert len(tickets) == len(jobs) == len(contexts) == 3
            assert [ticket.attempt_number for ticket in tickets] == [1, 2, 3]
            assert [ticket.fencing_value for ticket in tickets] == [1, 2, 3]
            assert {ticket.state for ticket in tickets} == {ReplayTicketState.ABANDONED.value}
            assert [reservation.state for reservation in budget_reservations] == [
                "released",
                "released",
                "released",
            ]
            assert [reservation.state for reservation in rate_reservations] == [
                "released",
                "released",
                "released",
            ]
            assert retry_events == 2
    finally:
        repository.close()


def test_replay_retry_rejects_abandoned_staging_that_contains_output(tmp_path: Path) -> None:
    database_path = tmp_path / "retry-staging-output.db"
    repository, service = _service(database_path)
    try:
        _create_batch(
            repository,
            service,
            "retry-staging-output",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        first = _claim(service, actor="expired-worker")
        _force_replay_lease_expired(
            repository,
            job_id=first.job.job_id,
            ticket_id=first.ticket.ticket_id,
        )
        assert service.requeue_expired(actor="lease-reaper") == 1
        staging_root, _artifact_root = _artifact_roots(database_path)
        old_staging = staging_root / first.execution_context.output_staging_id
        unexpected_output = old_staging / "untrusted-output.bin"
        unexpected_output.write_bytes(b"side effect may have happened")

        with pytest.raises(StateConflict, match="staging contains output"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replacement-worker",
            )

        assert unexpected_output.read_bytes() == b"side effect may have happened"
        assert service.get_replay_item(first.item.item_id).state is (ReplayItemState.RETRY_PENDING)
        with repository.transaction() as session:
            replay_jobs = int(
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                or 0
            )
            assert replay_jobs == 1
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1
    finally:
        repository.close()


def test_replay_retry_rollback_restores_empty_prior_staging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "retry-rollback.db"
    repository, service = _service(database_path)
    try:
        _create_batch(
            repository,
            service,
            "retry-rollback",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        first = _claim(service, actor="expired-worker")
        _force_replay_lease_expired(
            repository,
            job_id=first.job.job_id,
            ticket_id=first.ticket.ticket_id,
        )
        assert service.requeue_expired(actor="lease-reaper") == 1
        staging_root, _artifact_root = _artifact_roots(database_path)
        old_staging = staging_root / first.execution_context.output_staging_id
        original_issue = service._replay_issuance._issue_replay_attempt

        def reject_retry(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("forced Replay retry rollback")

        monkeypatch.setattr(service._replay_issuance, "_issue_replay_attempt", reject_retry)
        with pytest.raises(RuntimeError, match="forced Replay retry rollback"):
            service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor="replacement-worker",
            )

        assert old_staging.is_dir()
        assert not any(old_staging.iterdir())
        assert service.get_replay_item(first.item.item_id).state is (ReplayItemState.RETRY_PENDING)
        with repository.transaction() as session:
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 1
            )
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 1

        monkeypatch.setattr(
            service._replay_issuance,
            "_issue_replay_attempt",
            original_issue,
        )
        replacement = _claim(service, actor="replacement-worker")
        assert replacement.ticket.attempt == 2
        assert not old_staging.exists()
    finally:
        repository.close()


def test_two_sqlite_workers_issue_and_burn_one_fresh_replay_retry(tmp_path: Path) -> None:
    database_path = tmp_path / "retry-race.db"
    repository_a, service_a = _service(database_path)
    repository_b: ControlPlaneRepository | None = None
    try:
        _create_batch(
            repository_a,
            service_a,
            "retry-race",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        first = _claim(service_a, actor="expired-worker")
        _force_replay_lease_expired(
            repository_a,
            job_id=first.job.job_id,
            ticket_id=first.ticket.ticket_id,
        )
        assert service_a.requeue_expired(actor="lease-reaper") == 1
        repository_b, service_b = _service(database_path)
        barrier = Barrier(2)

        def claim(service: ControlPlaneService, actor: str):
            barrier.wait()
            return service.claim_replay_job(
                ReplayClaimRequest(executor_profile=EXECUTOR_PROFILE),
                actor=actor,
            )

        with ThreadPoolExecutor(max_workers=2) as pool:
            future_a = pool.submit(claim, service_a, "race-worker-a")
            future_b = pool.submit(claim, service_b, "race-worker-b")
            results = [future_a.result(timeout=30), future_b.result(timeout=30)]

        winners = [result for result in results if result is not None]
        assert len(winners) == 1
        assert winners[0].ticket.attempt == 2
        assert winners[0].ticket.fencing_value == 2
        with repository_a.transaction() as session:
            tickets = list(
                session.scalars(
                    select(ReplayTicketRecord).order_by(ReplayTicketRecord.attempt_number)
                ).all()
            )
            assert [ticket.attempt_number for ticket in tickets] == [1, 2]
            assert [ticket.fencing_value for ticket in tickets] == [1, 2]
            assert sum(ticket.state == ReplayTicketState.CLAIMED.value for ticket in tickets) == 1
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(ReplayEventRecord)
                    .where(ReplayEventRecord.event_type == "replay.retry-issued")
                )
                == 1
            )
    finally:
        if repository_b is not None:
            repository_b.close()
        repository_a.close()


def test_cancelling_single_replay_run_abandons_ticket_and_cancels_item_and_batch(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "cancel.db")
    try:
        _create_batch(repository, service, "cancel")
        claimed = _claim(service, actor="cancelled-worker")

        cancelled = service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="operator cancelled Replay validation"),
            actor="replay-operator",
        )
        assert cancelled.applied is True
        assert cancelled.cancelled_job_ids == [claimed.job.job_id]
        assert cancelled.run.state is RunState.CANCELLED
        assert service.get_job(claimed.job.job_id).state is JobState.CANCELLED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.ABANDONED
        )
        assert service.get_replay_item(claimed.item.item_id).state is ReplayItemState.CANCELLED
        assert service.get_replay_batch(claimed.batch.batch_id).state is (
            ReplayBatchState.CANCELLED
        )
        with repository.transaction() as session:
            budget_account = session.scalar(select(ReplayBudgetAccountRecord))
            budget_reservation = session.get(
                ReplayBudgetReservationRecord,
                claimed.ticket.budget_reservation_id,
            )
            rate_reservation = session.get(
                ReplayRateReservationRecord,
                claimed.ticket.rate_reservation_id,
            )
            assert budget_account is not None
            assert budget_reservation is not None
            assert rate_reservation is not None
            assert budget_account.reserved_calls == 0
            assert budget_reservation.state == "released"
            assert budget_reservation.released_calls == budget_reservation.total_calls
            assert rate_reservation.state == "released"
            assert rate_reservation.released_request_units == rate_reservation.total_request_units

        stale = ReplayLeaseRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claimed.lease_token,
            ticket_id=claimed.ticket.ticket_id,
            fencing_value=claimed.ticket.fencing_value,
        )
        with pytest.raises((RunCancelled, LeaseRejected, StateConflict)):
            service.heartbeat_replay_job(
                claimed.job.job_id,
                stale,
                actor="cancelled-worker",
            )

        repeated = service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="idempotent cancellation retry"),
            actor="replay-operator",
        )
        assert repeated.applied is False
    finally:
        repository.close()


def test_expired_retry_pending_authority_can_be_cancelled_without_rewriting_history(
    tmp_path: Path,
) -> None:
    repository, service = _service(tmp_path / "expiry-cancel.db")
    try:
        _create_batch(repository, service, "expiry-cancel", required_attempts=2, max_attempts=3)
        claimed = _claim(service, actor="heartbeat-worker")
        service.heartbeat_replay_job(
            claimed.job.job_id,
            ReplayLeaseRequest(
                executor_profile=EXECUTOR_PROFILE,
                lease_token=claimed.lease_token,
                ticket_id=claimed.ticket.ticket_id,
                fencing_value=claimed.ticket.fencing_value,
            ),
            actor="heartbeat-worker",
        )
        _force_replay_lease_expired(
            repository,
            job_id=claimed.job.job_id,
            ticket_id=claimed.ticket.ticket_id,
        )

        assert service.requeue_expired(actor="lease-reaper") == 1
        assert service.get_run(claimed.job.run_id).state is RunState.FAILED
        assert service.get_job(claimed.job.job_id).state is JobState.FAILED
        assert service.get_replay_item(claimed.item.item_id).state is (
            ReplayItemState.RETRY_PENDING
        )

        cancelled = service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="operator fenced future Replay retries"),
            actor="replay-operator",
        )
        assert cancelled.applied is True
        assert cancelled.cancelled_job_ids == []
        assert cancelled.run.state is RunState.FAILED
        assert service.get_run(claimed.job.run_id).state is RunState.FAILED
        assert service.get_job(claimed.job.job_id).state is JobState.FAILED
        assert service.get_replay_ticket(claimed.ticket.ticket_id).state is (
            ReplayTicketState.ABANDONED
        )
        assert service.get_replay_item(claimed.item.item_id).state is ReplayItemState.CANCELLED
        assert service.get_replay_batch(claimed.batch.batch_id).state is (
            ReplayBatchState.CANCELLED
        )

        repeated = service.cancel_run(
            claimed.item.replay_run_id,
            CancelRunRequest(reason="idempotent retry authority cancellation"),
            actor="replay-operator",
        )
        assert repeated.applied is False
        assert repeated.run.state is RunState.FAILED

        with repository.transaction() as session:
            events = list(
                session.scalars(
                    select(ReplayEventRecord)
                    .where(ReplayEventRecord.batch_id == claimed.batch.batch_id)
                    .order_by(ReplayEventRecord.sequence)
                ).all()
            )
        event_types = {event.event_type for event in events}
        assert {
            "replay.batch.created",
            "replay.ticket.issued",
            "replay.ticket.claimed",
            "replay.ticket.heartbeat",
            "replay.ticket.lease-expired",
            "replay.batch.cancelled",
        }.issubset(event_types)
        assert [event.sequence for event in events] == list(range(1, len(events) + 1))
    finally:
        repository.close()


@pytest.mark.parametrize("cancel_first", [True, False])
def test_multi_item_batch_terminal_state_is_order_independent(
    tmp_path: Path,
    cancel_first: bool,
) -> None:
    repository, service = _service(tmp_path / f"multi-order-{cancel_first}.db")
    try:
        _create_batch(
            repository,
            service,
            f"multi-order-{cancel_first}",
            required_attempts=1,
            max_attempts=1,
            item_count=2,
        )
        first = _claim(service, actor="replay-worker-a")
        if cancel_first:
            service.cancel_run(
                first.item.replay_run_id,
                CancelRunRequest(reason="cancel one Replay item first"),
                actor="replay-operator",
            )
            assert service.get_replay_item(first.item.item_id).state is ReplayItemState.CANCELLED
        else:
            _force_replay_lease_expired(
                repository,
                job_id=first.job.job_id,
                ticket_id=first.ticket.ticket_id,
            )
            assert service.requeue_expired(actor="lease-reaper") == 1
            assert service.get_replay_item(first.item.item_id).state is ReplayItemState.FAILED
        assert service.get_replay_batch(first.batch.batch_id).state is ReplayBatchState.RUNNING

        second = _claim(service, actor="replay-worker-a")
        assert second.item.item_id != first.item.item_id
        if cancel_first:
            _force_replay_lease_expired(
                repository,
                job_id=second.job.job_id,
                ticket_id=second.ticket.ticket_id,
            )
            assert service.requeue_expired(actor="lease-reaper") == 1
        else:
            service.cancel_run(
                second.item.replay_run_id,
                CancelRunRequest(reason="cancel one Replay item last"),
                actor="replay-operator",
            )

        with repository.transaction() as session:
            final_states = set(
                session.scalars(
                    select(ReplayItemRecord.state).where(
                        ReplayItemRecord.batch_id == first.batch.batch_id
                    )
                ).all()
            )
        assert final_states == {
            ReplayItemState.CANCELLED.value,
            ReplayItemState.FAILED.value,
        }
        assert service.get_replay_batch(first.batch.batch_id).state is (ReplayBatchState.CANCELLED)
    finally:
        repository.close()


def test_ordinary_campaign_lease_expiry_still_requeues_the_same_job(tmp_path: Path) -> None:
    repository, service = _service(tmp_path / "ordinary-regression.db")
    try:
        submitted = service.submit_run(
            SubmitRunRequest(
                campaign_name="ordinary-campaign",
                input={"regression": "at-least-once"},
                idempotency_key="ordinary-regression-submission",
                max_attempts=3,
            ),
            actor="ordinary-operator",
        )
        first = service.claim_job(
            ClaimJobRequest(worker_id="ordinary-worker-a", lease_seconds=30),
            actor="ordinary-worker-principal",
        )
        assert first is not None
        assert first.job.job_id == submitted.job.job_id
        with repository.transaction() as session:
            session.execute(
                update(JobRecord)
                .where(JobRecord.job_id == first.job.job_id)
                .values(lease_expires_at=datetime.now(UTC) - timedelta(seconds=1))
            )

        assert service.requeue_expired(actor="lease-reaper") == 1
        second = service.claim_job(
            ClaimJobRequest(worker_id="ordinary-worker-b", lease_seconds=30),
            actor="ordinary-worker-principal",
        )
        assert second is not None
        assert second.job.job_id == first.job.job_id
        assert second.job.attempts == 2
        assert second.lease_token != first.lease_token
    finally:
        repository.close()


def test_kisa_exact_executor_uses_durable_permits_and_server_finalizes_one_item(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "kisa-exact-execution.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    try:
        _create_batch(
            repository,
            service,
            "kisa-exact-execution",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        claim = _claim(service, actor=actor)
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=_ReplayServicePort(service, actor=actor),
            staging_root=staging_root,
            worker=_trusted_replay_backend(),
        )

        finalize_request = asyncio.run(executor.execute(claim))
        assert finalize_request == ReplayFinalizeRequest(
            executor_profile=EXECUTOR_PROFILE,
            lease_token=claim.lease_token,
            ticket_id=claim.ticket.ticket_id,
            fencing_value=claim.ticket.fencing_value,
            output_staging_id=claim.execution_context.output_staging_id,
        )
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            ReplayFinalizeRequest.model_validate(
                {
                    **finalize_request.model_dump(mode="json"),
                    "result": {"workerVerdict": "confirmed"},
                    "outputPath": "/tmp/worker-selected",
                }
            )

        finalized = service.finalize_replay_job(
            claim.job.job_id,
            finalize_request,
            actor=actor,
        )
        assert not (staging_root / finalize_request.output_staging_id).exists()
        repeated = service.finalize_replay_job(
            claim.job.job_id,
            finalize_request,
            actor=actor,
        )
        assert repeated == finalized
        assert service.get_replay_finalization(claim.ticket.ticket_id) == finalized
        serialized_finalization = finalized.model_dump_json(by_alias=True)
        assert finalize_request.output_staging_id not in serialized_finalization
        assert "lease_token" not in serialized_finalization
        assert "storage_key" not in serialized_finalization
        assert finalized.job.state is JobState.SUCCEEDED
        assert finalized.ticket.state is ReplayTicketState.FINALIZED
        assert finalized.item.state is ReplayItemState.GATED
        assert finalized.batch.state is ReplayBatchState.COMPLETED
        assert finalized.artifact.producer_run_id == claim.item.replay_run_id
        assert finalized.artifact.run_id == claim.item.replay_run_id
        assert finalized.gate_decision.candidate_id == claim.item.candidate_id
        assert finalized.gate_decision.disposition is FindingDisposition.NEEDS_REVIEW
        assert finalized.gate_decision.confirmation_basis is None
        assert finalized.gate_decision.reason_codes == [
            ValidationReasonCode.INDEPENDENT_EXECUTION_ATTESTATION_MISSING
        ]
        assert finalized.job.result == {
            "kind": "pajin.replay.finalization.v1",
            "finalizationId": finalized.finalization_id,
            "artifactId": finalized.artifact.artifact_id,
            "repositoryVersion": finalized.artifact.repository_version,
            "gateDecisionId": finalized.gate_decision.decision_id,
            "resultDigest": finalized.result_digest,
        }

        with repository.transaction() as session:
            permits = list(
                session.scalars(
                    select(ReplayToolPermitRecord)
                    .where(ReplayToolPermitRecord.ticket_id == claim.ticket.ticket_id)
                    .order_by(ReplayToolPermitRecord.call_ordinal)
                ).all()
            )
            assert [permit.call_ordinal for permit in permits] == list(
                range(1, claim.compilation.spec.repetitions + 1)
            )
            assert len({permit.replay_request_id for permit in permits}) == len(permits)
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 1
            budget = session.scalar(
                select(ReplayBudgetReservationRecord).where(
                    ReplayBudgetReservationRecord.budget_reservation_id
                    == claim.ticket.budget_reservation_id
                )
            )
            rate = session.scalar(
                select(ReplayRateReservationRecord).where(
                    ReplayRateReservationRecord.rate_reservation_id
                    == claim.ticket.rate_reservation_id
                )
            )
            assert budget is not None
            assert rate is not None
            assert budget.state == "consumed"
            assert budget.consumed_calls == budget.total_calls == len(permits)
            assert rate.state == "consumed"
            assert rate.consumed_request_units == rate.total_request_units
            replay_event_types = list(
                session.scalars(
                    select(ReplayEventRecord.event_type).where(
                        ReplayEventRecord.ticket_id == claim.ticket.ticket_id
                    )
                ).all()
            )
            assert replay_event_types.count("replay.output.verified") == 1
            assert replay_event_types.count("replay.confirmation.gated") == 1
    finally:
        repository.close()


def test_replay_finalization_rollback_preserves_staging_until_a_committed_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "replay-finalization-rollback.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    try:
        _create_batch(
            repository,
            service,
            "replay-finalization-rollback",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        claim = _claim(service, actor=actor)
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=_ReplayServicePort(service, actor=actor),
            staging_root=staging_root,
            worker=_trusted_replay_backend(),
        )
        request = asyncio.run(executor.execute(claim))
        stage = staging_root / request.output_staging_id
        original_event = service._event

        def reject_transaction_body(*_args: Any, **_kwargs: Any) -> None:
            raise RuntimeError("forced finalization rollback")

        monkeypatch.setattr(service, "_event", reject_transaction_body)
        with pytest.raises(RuntimeError, match="forced finalization rollback"):
            service.finalize_replay_job(claim.job.job_id, request, actor=actor)

        assert stage.is_dir()
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1

        monkeypatch.setattr(service, "_event", original_event)
        finalized = service.finalize_replay_job(claim.job.job_id, request, actor=actor)

        assert finalized.job.state is JobState.SUCCEEDED
        assert not stage.exists()
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 2
    finally:
        repository.close()


def test_replay_finalization_ambiguous_commit_is_recovered_by_exact_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "replay-finalization-ambiguous-commit.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    try:
        _create_batch(
            repository,
            service,
            "replay-finalization-ambiguous-commit",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        claim = _claim(service, actor=actor)
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=_ReplayServicePort(service, actor=actor),
            staging_root=staging_root,
            worker=_trusted_replay_backend(),
        )
        request = asyncio.run(executor.execute(claim))
        stage = staging_root / request.output_staging_id
        real_transaction = repository.transaction
        transaction_calls = 0

        @contextmanager
        def ambiguous_transaction():
            nonlocal transaction_calls
            transaction_calls += 1
            current_call = transaction_calls
            with real_transaction() as session:
                yield session
            if current_call == 2:
                raise RuntimeError("finalization commit result is ambiguous")

        monkeypatch.setattr(repository, "transaction", ambiguous_transaction)
        with pytest.raises(RuntimeError, match="commit result is ambiguous"):
            service.finalize_replay_job(claim.job.job_id, request, actor=actor)

        assert stage.is_dir()
        with real_transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 1
            committed_id = session.scalar(select(ReplayFinalizationRecord.finalization_id))

        recovered = service.finalize_replay_job(claim.job.job_id, request, actor=actor)

        assert recovered.finalization_id == committed_id
        assert not stage.exists()
        with real_transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 1
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 2
    finally:
        repository.close()


def test_replay_finalization_rejects_wrong_capability_and_tampered_sealed_output(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replay-finalization-tamper.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    try:
        _create_batch(
            repository,
            service,
            "replay-finalization-tamper",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        claim = _claim(service, actor=actor)
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=_ReplayServicePort(service, actor=actor),
            staging_root=staging_root,
            worker=_trusted_replay_backend(),
        )
        finalize_request = asyncio.run(executor.execute(claim))

        with pytest.raises(LeaseRejected, match="output capability"):
            service.finalize_replay_job(
                claim.job.job_id,
                finalize_request.model_copy(update={"output_staging_id": f"stage_{'f' * 32}"}),
                actor=actor,
            )

        run_summary = staging_root / finalize_request.output_staging_id / "run.json"
        stored_summary = json.loads(run_summary.read_text(encoding="utf-8"))
        stored_summary["reason"] = "worker-tampered-authoritative-result"
        run_summary.write_text(
            json.dumps(stored_summary, ensure_ascii=False, sort_keys=True),
            encoding="utf-8",
        )
        with pytest.raises(StateConflict, match="authoritative verification"):
            service.finalize_replay_job(
                claim.job.job_id,
                finalize_request,
                actor=actor,
            )

        assert service.get_job(claim.job.job_id).state is JobState.LEASED
        assert service.get_replay_ticket(claim.ticket.ticket_id).state is (
            ReplayTicketState.CLAIMED
        )
        assert service.get_replay_item(claim.item.item_id).state is ReplayItemState.RUNNING
        assert service.get_replay_batch(claim.batch.batch_id).state is ReplayBatchState.RUNNING
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ArtifactRecord)) == 1
    finally:
        repository.close()


def test_replay_worker_rejects_model_valid_retargeted_finalization(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replay-finalization-client-binding.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"

    def set_nested(
        payload: dict[str, Any],
        path: tuple[str | int, ...],
        value: Any,
    ) -> None:
        target: Any = payload
        for field_name in path[:-1]:
            if isinstance(field_name, int):
                assert isinstance(target, list)
            else:
                assert isinstance(target, dict)
            target = target[field_name]
        final_field = path[-1]
        if isinstance(final_field, int):
            assert isinstance(target, list)
        else:
            assert isinstance(target, dict)
        target[final_field] = value

    def reseal_response(payload: dict[str, Any]) -> ReplayFinalizationView:
        decision = ValidationDecision.model_validate(payload["gate_decision"])
        artifact = ArtifactRef.model_validate(payload["artifact"])
        result_digest = replay_context_digest(
            {
                "artifact": artifact.model_dump(mode="json"),
                "artifactSetDigest": payload["artifact_set_digest"],
                "artifactSealRootDigest": payload["artifact_seal_root_digest"],
                "batchId": payload["batch"]["batch_id"],
                "compilationId": payload["ticket"]["compilation_id"],
                "fencingValue": payload["ticket"]["fencing_value"],
                "gateDecisionDigest": replay_context_digest(
                    decision.model_dump(mode="json", by_alias=True)
                ),
                "itemId": payload["item"]["item_id"],
                "jobId": payload["job"]["job_id"],
                "receiptSealRootDigest": payload["receipt_seal_root_digest"],
                "ticketId": payload["ticket"]["ticket_id"],
            }
        )
        payload["result_digest"] = result_digest
        payload["job"]["result"] = {
            "kind": "pajin.replay.finalization.v1",
            "finalizationId": payload["finalization_id"],
            "artifactId": artifact.artifact_id,
            "repositoryVersion": artifact.repository_version,
            "gateDecisionId": decision.decision_id,
            "resultDigest": result_digest,
        }
        return ReplayFinalizationView.model_validate(payload)

    try:
        _create_batch(
            repository,
            service,
            "replay-finalization-client-binding",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        claim = _claim(service, actor=actor)
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=_ReplayServicePort(service, actor=actor),
            staging_root=staging_root,
            worker=_trusted_replay_backend(),
        )
        request = asyncio.run(executor.execute(claim))
        finalized = service.finalize_replay_job(claim.job.job_id, request, actor=actor)
        ReplayWorkerDaemon._validate_finalization(claim, finalized)
        check_indexes = {
            check.check_id: index for index, check in enumerate(finalized.gate_decision.checks)
        }
        reproduction_check_index = check_indexes["independent-reproduction"]
        receipt_check_index = check_indexes["replay-receipt-integrity"]

        retargeted_run_id = f"run_{'9' * 32}"
        mutations = (
            (
                "Job payload authority",
                ((("job", "payload", "candidate_id"), "candidate-payload-retargeted"),),
            ),
            ("Job priority", ((("job", "priority"), 137),)),
            (
                "Job identity graph",
                (
                    (("job", "job_id"), f"job_{'9' * 32}"),
                    (("ticket", "job_id"), f"job_{'9' * 32}"),
                ),
            ),
            (
                "batch identity graph",
                (
                    (("batch", "batch_id"), f"replay-batch_{'9' * 32}"),
                    (("item", "batch_id"), f"replay-batch_{'9' * 32}"),
                    (("ticket", "batch_id"), f"replay-batch_{'9' * 32}"),
                    (("job", "payload", "batch_id"), f"replay-batch_{'9' * 32}"),
                ),
            ),
            (
                "item identity graph",
                (
                    (("item", "item_id"), f"replay-item_{'9' * 32}"),
                    (("ticket", "item_id"), f"replay-item_{'9' * 32}"),
                    (("job", "payload", "item_id"), f"replay-item_{'9' * 32}"),
                ),
            ),
            (
                "Replay Run identity graph",
                (
                    (("job", "run_id"), retargeted_run_id),
                    (("item", "replay_run_id"), retargeted_run_id),
                    (("ticket", "replay_run_id"), retargeted_run_id),
                    (("artifact", "producer_run_id"), retargeted_run_id),
                    (("artifact", "run_id"), retargeted_run_id),
                    (("gate_decision", "replay_lineage", 0, "replay_run_id"), retargeted_run_id),
                    (("job", "payload", "replay_run_id"), retargeted_run_id),
                ),
            ),
            (
                "batch source digest",
                ((("batch", "source", "content_digest"), "f" * 64),),
            ),
            ("batch policy", ((("batch", "policy_version"), "policy-retargeted"),)),
            (
                "Candidate identity",
                (
                    (("item", "candidate_id"), "candidate-retargeted"),
                    (("gate_decision", "candidate_id"), "candidate-retargeted"),
                    (("job", "payload", "candidate_id"), "candidate-retargeted"),
                ),
            ),
            (
                "Candidate digest",
                (
                    (("item", "candidate_digest"), "f" * 64),
                    (("job", "payload", "candidate_digest"), "f" * 64),
                ),
            ),
            (
                "contract digest",
                (
                    (("item", "contract_digest"), "e" * 64),
                    (("job", "payload", "contract_digest"), "e" * 64),
                ),
            ),
            (
                "compilation digest",
                (
                    (("item", "compilation_digest"), "d" * 64),
                    (("job", "payload", "compilation_digest"), "d" * 64),
                ),
            ),
            (
                "grant digest",
                (
                    (("item", "grant_digest"), "c" * 64),
                    (("job", "payload", "grant_digest"), "c" * 64),
                ),
            ),
            (
                "ticket compilation",
                (
                    (("ticket", "compilation_id"), f"replay-compilation_{'9' * 32}"),
                    (("job", "payload", "compilation_id"), f"replay-compilation_{'9' * 32}"),
                ),
            ),
            (
                "ticket reservations",
                (
                    (("ticket", "budget_reservation_id"), f"budget-reservation_{'9' * 32}"),
                    (("ticket", "rate_reservation_id"), f"rate-reservation_{'9' * 32}"),
                    (
                        ("job", "payload", "budget_reservation_id"),
                        f"budget-reservation_{'9' * 32}",
                    ),
                    (
                        ("job", "payload", "rate_reservation_id"),
                        f"rate-reservation_{'9' * 32}",
                    ),
                ),
            ),
            (
                "attempt and fence",
                (
                    (("job", "attempts"), 2),
                    (("job", "max_attempts"), 2),
                    (("item", "attempts"), 2),
                    (("ticket", "attempt"), 2),
                    (("ticket", "fencing_value"), 2),
                    (("job", "payload", "attempt"), 2),
                    (("job", "payload", "fencing_value"), 2),
                ),
            ),
            (
                "Worker principal",
                (
                    (("job", "lease_owner"), "replay-worker-retargeted"),
                    (("ticket", "claimed_by"), "replay-worker-retargeted"),
                    (("artifact", "created_by"), "replay-worker-retargeted"),
                    (("finalized_by",), "replay-worker-retargeted"),
                ),
            ),
            (
                "Candidate source lineage",
                (
                    (
                        ("gate_decision", "replay_lineage", 0, "candidate_source_root_digest"),
                        "b" * 64,
                    ),
                ),
            ),
            ("Gate validator", ((("gate_decision", "validator_id"), "untrusted-gate"),)),
            ("Gate decision identity", ((("gate_decision", "decision_id"), "forged-decision"),)),
            (
                "Gate reason matrix",
                (
                    (("gate_decision", "reason_codes"), ["validator-confirmed"]),
                    (
                        (
                            "gate_decision",
                            "checks",
                            reproduction_check_index,
                            "reason_code",
                        ),
                        "validator-confirmed",
                    ),
                ),
            ),
            (
                "Gate receipt check",
                (
                    (
                        ("gate_decision", "checks", receipt_check_index, "status"),
                        "fail",
                    ),
                    (
                        (
                            "gate_decision",
                            "checks",
                            receipt_check_index,
                            "reason_code",
                        ),
                        "replay-execution-failed",
                    ),
                ),
            ),
            ("output media type", ((("artifact", "media_type"), "application/octet-stream"),)),
            ("output schema", ((("artifact", "schema_kind"), "forged.output.v1"),)),
        )

        for label, assignments in mutations:
            payload = finalized.model_dump(mode="python")
            for path, value in assignments:
                set_nested(payload, path, value)
            forged = reseal_response(payload)
            try:
                ReplayWorkerDaemon._validate_finalization(claim, forged)
            except ControlPlaneProtocolError:
                continue
            pytest.fail(f"model-valid retargeted Replay finalization was accepted: {label}")
    finally:
        repository.close()


def test_replay_finalization_rejects_managed_source_root_substitution_on_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "replay-finalization-source-substitution.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    try:
        _create_batch(
            repository,
            service,
            "replay-finalization-source-substitution",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        claim = _claim(service, actor=actor)
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=_ReplayServicePort(service, actor=actor),
            staging_root=staging_root,
            worker=_trusted_replay_backend(),
        )
        request = asyncio.run(executor.execute(claim))

        artifact_repository = service._require_artifact_repository()
        original_source = artifact_repository.resolve(claim.batch.source)
        replacement_stage_id = f"stage_{sha256(b'managed-source-replacement').hexdigest()[:32]}"
        replacement_stage = staging_root / replacement_stage_id
        shutil.copytree(original_source.path, replacement_stage)
        replacement_store = RunStore(
            run_id=original_source.ref.run_id,
            path=replacement_stage,
        )
        replacement_store.write_text(
            "substitution-marker.txt",
            "same validation artifacts under a different sealed root",
        )
        replacement_store.seal()
        replacement_source = artifact_repository.import_run(
            staging_id=replacement_stage_id,
            producer_run_id=original_source.ref.producer_run_id,
            media_type=original_source.ref.media_type,
            schema_kind=original_source.ref.schema_kind,
            created_by=original_source.ref.created_by,
        )
        assert replacement_source.ref.run_id == original_source.ref.run_id
        assert (
            replacement_source.ref.integrity_root_digest
            != original_source.ref.integrity_root_digest
        )

        real_load = control_plane_service_module.load_source_validation_artifacts
        observed_authority: list[tuple[str | None, str | None]] = []

        def substitute_managed_source(
            _run_path: Path,
            *,
            expected_run_id: str | None = None,
            expected_root_digest: str | None = None,
        ):
            observed_authority.append((expected_run_id, expected_root_digest))
            return real_load(
                replacement_source.path,
                expected_run_id=expected_run_id,
                expected_root_digest=expected_root_digest,
            )

        monkeypatch.setattr(
            control_plane_service_module,
            "load_source_validation_artifacts",
            substitute_managed_source,
        )
        with pytest.raises(StateConflict, match="managed Replay source validation"):
            service.finalize_replay_job(claim.job.job_id, request, actor=actor)

        assert observed_authority == [
            (
                original_source.ref.run_id,
                original_source.ref.integrity_root_digest,
            )
        ]
        assert service.get_job(claim.job.job_id).state is JobState.LEASED
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 0
    finally:
        repository.close()


@pytest.mark.asyncio
async def test_replay_worker_daemon_executes_heartbeats_and_reconciles_finalization(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replay-daemon-e2e.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    status_path = tmp_path / "replay-worker-status.json"
    try:
        await asyncio.to_thread(
            _create_batch,
            repository,
            service,
            "replay-daemon-e2e",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        port = _ReplayDaemonServicePort(
            service,
            actor=actor,
            drop_first_permit_response=True,
            drop_first_finalize_response=True,
            mutate_retained_claim=True,
        )
        port.status_path = status_path
        backend = _trusted_replay_backend()
        original_run = backend.run
        running_statuses: list[ReplayWorkerStatus] = []

        async def delayed_run(job: WorkerJob, *, secrets: object = None) -> WorkerResult:
            del secrets
            running_statuses.append(
                ReplayWorkerStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
            )
            await asyncio.sleep(0.08)
            return await original_run(job)

        backend.run = delayed_run  # type: ignore[method-assign]
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=port,
            staging_root=staging_root,
            worker=backend,
            retry_base_seconds=0.05,
            retry_max_seconds=0.05,
        )
        daemon = ReplayWorkerDaemon(
            client=port,
            executor=executor,
            config=ReplayWorkerConfig(
                worker_id=actor,
                lease_seconds=5,
                heartbeat_seconds=0.05,
                long_poll_seconds=0,
                retry_base_seconds=0.15,
                retry_max_seconds=0.15,
                finalize_attempts=3,
                cancellation_grace_seconds=0.05,
                cancellation_force_seconds=0.5,
                status_path=status_path,
            ),
        )

        assert await daemon.run_once() is True
        assert port.claimed is not None
        assert port.original_claim is not None
        claim = port.original_claim
        assert port.claimed.job.job_id != claim.job.job_id
        assert set(port.heartbeat_job_ids) == {claim.job.job_id}
        assert set(port.permit_job_ids) == {claim.job.job_id}
        assert set(port.finalize_job_ids) == {claim.job.job_id}
        assert port.heartbeat_calls >= 2
        assert port.permit_calls == 3
        assert port.finalize_calls == 2
        assert running_statuses
        assert all(status.state == "running" for status in running_statuses)
        assert port.finalizing_statuses
        assert all(status.state == "finalizing" for status in port.finalizing_statuses)

        status_payload = json.loads(status_path.read_text(encoding="utf-8"))
        status = ReplayWorkerStatus.model_validate(status_payload)
        assert status.state == "idle"
        assert status.handled_replays == 1
        assert status.active_job_id is None
        serialized_status = json.dumps(status_payload, sort_keys=True)
        assert claim.lease_token not in serialized_status
        assert claim.execution_context.output_staging_id not in serialized_status

        with repository.transaction() as session:
            permits = list(
                session.scalars(
                    select(ReplayToolPermitRecord)
                    .where(ReplayToolPermitRecord.ticket_id == claim.ticket.ticket_id)
                    .order_by(ReplayToolPermitRecord.call_ordinal)
                ).all()
            )
            assert [permit.call_ordinal for permit in permits] == [1, 2]
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 1
            event_types = list(
                session.scalars(
                    select(ReplayEventRecord.event_type).where(
                        ReplayEventRecord.ticket_id == claim.ticket.ticket_id
                    )
                ).all()
            )
            assert event_types.count("replay.output.verified") == 1
            assert event_types.count("replay.confirmation.gated") == 1
    finally:
        repository.close()


@pytest.mark.asyncio
async def test_replay_worker_stalled_heartbeat_quiesces_before_reclaim_overlap(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replay-daemon-deadline.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    claim_received = asyncio.Event()

    class StalledHeartbeatPort(_ReplayDaemonServicePort):
        async def claim_replay(
            self,
            request: ReplayClaimRequest,
        ) -> ReplayExecutionClaimView | None:
            claim = await super().claim_replay(request)
            assert claim is not None
            server_now = datetime.now(UTC)
            claim = claim.model_copy(
                update={
                    "job": claim.job.model_copy(
                        update={
                            "heartbeat_at": server_now,
                            "updated_at": server_now,
                            "lease_expires_at": server_now + timedelta(seconds=0.15),
                        }
                    ),
                    "ticket": claim.ticket.model_copy(
                        update={
                            "updated_at": server_now,
                            "lease_expires_at": server_now + timedelta(seconds=0.15),
                        }
                    ),
                }
            )
            self.claimed = claim
            self.original_claim = claim.model_copy(deep=True)
            claim_received.set()
            return claim

        async def heartbeat_replay(
            self,
            job_id: str,
            request: ReplayLeaseRequest,
        ) -> ReplayExecutionClaimView:
            del job_id, request
            self.heartbeat_calls += 1
            await asyncio.Event().wait()
            raise AssertionError("stalled Replay heartbeat unexpectedly resumed")

    class RepeatingReplayExecutor:
        profile = EXECUTOR_PROFILE

        def __init__(self, *, reclaim_started: asyncio.Event) -> None:
            self.side_effects = 0
            self.overlap_side_effects = 0
            self.stopped = asyncio.Event()
            self.reclaim_started = reclaim_started

        async def execute(self, _claim, *, cancellation=None):
            del cancellation
            try:
                while True:
                    self.side_effects += 1
                    if self.reclaim_started.is_set():
                        self.overlap_side_effects += 1
                    await asyncio.sleep(0.01)
            finally:
                self.stopped.set()

    try:
        await asyncio.to_thread(
            _create_batch,
            repository,
            service,
            "replay-daemon-deadline",
        )
        port = StalledHeartbeatPort(service, actor=actor)
        reclaim_started = asyncio.Event()
        executor = RepeatingReplayExecutor(reclaim_started=reclaim_started)
        daemon = ReplayWorkerDaemon(
            client=port,
            executor=executor,
            config=ReplayWorkerConfig(
                worker_id=actor,
                lease_seconds=5,
                heartbeat_seconds=0.05,
                long_poll_seconds=0,
                cancellation_grace_seconds=0.05,
                cancellation_force_seconds=0.25,
            ),
        )

        async def mark_reclaim_after_fresh_lease() -> None:
            await claim_received.wait()
            await asyncio.sleep(0.16)
            reclaim_started.set()

        reclaim_timer = asyncio.create_task(mark_reclaim_after_fresh_lease())

        with pytest.raises(ControlPlaneLeaseLost, match="local Replay lease deadline"):
            await asyncio.wait_for(daemon.run_once(), timeout=1)
        await reclaim_timer

        await asyncio.wait_for(executor.stopped.wait(), timeout=0.25)
        effects_at_reclaim = executor.side_effects
        await asyncio.sleep(0.08)
        assert executor.side_effects == effects_at_reclaim
        assert reclaim_started.is_set()
        assert executor.overlap_side_effects == 0
        assert port.finalize_calls == 0
    finally:
        repository.close()


@pytest.mark.asyncio
async def test_replay_local_deadline_wins_over_simultaneous_stale_finalization() -> None:
    daemon = ReplayWorkerDaemon(
        client=SimpleNamespace(),
        executor=SimpleNamespace(profile=EXECUTOR_PROFILE),
        config=ReplayWorkerConfig(
            worker_id="replay-worker-a",
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            cancellation_grace_seconds=0.05,
            cancellation_force_seconds=0.25,
        ),
    )

    async def stale_finalization():
        return None

    async def expired_heartbeat() -> None:
        raise ControlPlaneLocalLeaseDeadlineExceeded("local Replay lease deadline elapsed")

    finalization = asyncio.create_task(stale_finalization())
    heartbeat = asyncio.create_task(expired_heartbeat())
    await asyncio.sleep(0)

    with pytest.raises(ControlPlaneLocalLeaseDeadlineExceeded):
        await daemon._await_finalization_with_heartbeat(  # type: ignore[arg-type]
            finalization,
            heartbeat,
            lease_deadline=MonotonicLeaseDeadline(expires_at=asyncio.get_running_loop().time() + 1),
        )


@pytest.mark.asyncio
async def test_replay_finalization_reconciliation_cannot_outlive_local_lease() -> None:
    daemon = ReplayWorkerDaemon(
        client=SimpleNamespace(),
        executor=SimpleNamespace(profile=EXECUTOR_PROFILE),
        config=ReplayWorkerConfig(
            worker_id="replay-worker-a",
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            cancellation_grace_seconds=0.05,
            cancellation_force_seconds=0.5,
        ),
    )

    async def stalled_finalization():
        await asyncio.Event().wait()

    async def terminal_heartbeat() -> None:
        raise ControlPlaneLeaseLost("server heartbeat rejected the lease")

    finalization = asyncio.create_task(stalled_finalization())
    heartbeat = asyncio.create_task(terminal_heartbeat())
    deadline = MonotonicLeaseDeadline(expires_at=asyncio.get_running_loop().time() + 0.1)

    with pytest.raises(
        ControlPlaneLocalLeaseDeadlineExceeded,
        match="finalization reconciliation",
    ):
        await asyncio.wait_for(
            daemon._await_finalization_with_heartbeat(  # type: ignore[arg-type]
                finalization,
                heartbeat,
                lease_deadline=deadline,
            ),
            timeout=0.4,
        )

    assert finalization.done()


@pytest.mark.asyncio
async def test_replay_worker_daemon_forced_cancellation_seals_quiescence(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replay-daemon-cancel.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    status_path = tmp_path / "replay-worker-cancel-status.json"
    try:
        await asyncio.to_thread(
            _create_batch,
            repository,
            service,
            "replay-daemon-cancel",
            required_attempts=KISA_CONFIRMATION_REQUIRED_ATTEMPTS,
            max_attempts=KISA_CONFIRMATION_MAX_ATTEMPTS,
        )
        port = _ReplayDaemonServicePort(service, actor=actor)
        backend = _trusted_replay_backend()
        started = asyncio.Event()
        never = asyncio.Event()
        cancellation_count = 0

        async def stubborn_run(job: WorkerJob, *, secrets: object = None) -> WorkerResult:
            nonlocal cancellation_count
            del job, secrets
            started.set()
            while True:
                try:
                    await never.wait()
                except asyncio.CancelledError:
                    cancellation_count += 1
                    if cancellation_count == 1:
                        continue
                    raise

        backend.run = stubborn_run  # type: ignore[method-assign]
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=port,
            staging_root=staging_root,
            worker=backend,
        )
        daemon = ReplayWorkerDaemon(
            client=port,
            executor=executor,
            config=ReplayWorkerConfig(
                worker_id=actor,
                lease_seconds=5,
                heartbeat_seconds=0.05,
                long_poll_seconds=0,
                cancellation_grace_seconds=0.05,
                cancellation_force_seconds=0.5,
                status_path=status_path,
            ),
        )

        daemon_task = asyncio.create_task(daemon.run_once())
        await asyncio.wait_for(started.wait(), timeout=2)
        assert port.claimed is not None
        claim = port.claimed
        service.cancel_run(
            claim.job.run_id,
            CancelRunRequest(reason="operator cancelled active Replay daemon"),
            actor="replay-operator",
        )
        with pytest.raises(ControlPlaneRunCancelled):
            await asyncio.wait_for(daemon_task, timeout=3)

        stage = staging_root / claim.execution_context.output_staging_id
        cancellation = json.loads((stage / "cancellation.json").read_text(encoding="utf-8"))
        quiescence = json.loads((stage / "quiescence.json").read_text(encoding="utf-8"))
        assert cancellation["cancellation"]["kind"] == "run-cancelled"
        assert quiescence["cancellation"]["cleanupStatus"] == "quiesced"
        assert quiescence["cancellation"]["forcedAt"] is not None
        assert cancellation_count >= 2
        assert verify_run_integrity(stage).seal_count >= 3
        assert port.finalize_calls == 0
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 0

        status = ReplayWorkerStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
        assert status.state == "lease-lost"
        assert status.last_cancellation is not None
        assert status.last_cancellation.kind.value == "run-cancelled"
        assert status.last_cancellation.forced_at is not None
    finally:
        repository.close()


def test_replay_executor_rejects_symlinked_staging_capabilities(tmp_path: Path) -> None:
    database_path = tmp_path / "replay-staging-symlink.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    try:
        _create_batch(repository, service, "replay-staging-symlink")
        claim = _claim(service, actor=actor)
        staging_root, _artifact_root = _artifact_roots(database_path)
        stage = staging_root / claim.execution_context.output_staging_id
        sibling = staging_root / "owner-controlled-sibling"
        sibling.mkdir(mode=0o700)
        stage.rmdir()
        stage.symlink_to(sibling, target_is_directory=True)
        executor = KISAExactReplayExecutor(
            client=_ReplayServicePort(service, actor=actor),
            staging_root=staging_root,
            worker=_trusted_replay_backend(),
        )

        with pytest.raises(PermissionError, match="symbolic links"):
            asyncio.run(executor.execute(claim))
        assert not any(sibling.iterdir())

        root_link = tmp_path / "staging-root-link"
        root_link.symlink_to(staging_root, target_is_directory=True)
        with pytest.raises(PermissionError, match="symbolic links"):
            KISAExactReplayExecutor(
                client=_ReplayServicePort(service, actor=actor),
                staging_root=root_link,
                worker=_trusted_replay_backend(),
            )
    finally:
        repository.close()


def test_replay_worker_daemon_exhausts_exact_permit_retry_and_reports_degraded(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replay-daemon-transient.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    status_path = tmp_path / "replay-worker-transient-status.json"
    transient_secret = "replay-transport-secret-MUST-NOT-PERSIST"
    try:
        _create_batch(repository, service, "replay-daemon-transient")
        port = _ReplayDaemonServicePort(
            service,
            actor=actor,
            permit_transient_failures_before_server=3,
            transient_error_detail=transient_secret,
        )
        staging_root, _artifact_root = _artifact_roots(database_path)
        executor = KISAExactReplayExecutor(
            client=port,
            staging_root=staging_root,
            worker=_trusted_replay_backend(),
            permit_attempts=3,
            retry_base_seconds=0.05,
            retry_max_seconds=0.05,
        )
        daemon = ReplayWorkerDaemon(
            client=port,
            executor=executor,
            config=ReplayWorkerConfig(
                worker_id=actor,
                lease_seconds=5,
                heartbeat_seconds=0.05,
                long_poll_seconds=0,
                cancellation_grace_seconds=0.05,
                cancellation_force_seconds=0.5,
                status_path=status_path,
            ),
        )

        with pytest.raises(ControlPlaneTransientError):
            asyncio.run(daemon.run_once())
        assert port.claimed is not None
        claim = port.claimed
        assert port.permit_calls == 3
        assert port.finalize_calls == 0
        status = ReplayWorkerStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
        assert status.state == "degraded"
        assert status.last_cancellation is not None
        assert status.last_cancellation.kind.value == "heartbeat-unavailable"
        assert status.last_cancellation.cleanup_status.value == "executor-drained"
        stage = staging_root / claim.execution_context.output_staging_id
        quiescence = json.loads((stage / "quiescence.json").read_text(encoding="utf-8"))
        assert quiescence["cancellation"]["cleanupStatus"] == "quiesced"
        persisted_text = (
            status_path.read_text(encoding="utf-8")
            + "\n"
            + "\n".join(
                path.read_text(encoding="utf-8") for path in stage.rglob("*") if path.is_file()
            )
        )
        assert transient_secret not in persisted_text
        assert verify_run_integrity(stage).valid
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayToolPermitRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 0
    finally:
        repository.close()


def test_replay_worker_daemon_unexpected_executor_failure_reports_crashed(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "replay-daemon-crashed.db"
    repository, service = _service(database_path)
    actor = "replay-worker-a"
    status_path = tmp_path / "replay-worker-crashed-status.json"

    class CrashingExecutor:
        profile = EXECUTOR_PROFILE

        async def execute(self, _claim, *, cancellation=None):
            del cancellation
            raise RuntimeError("untrusted detail must not enter status")

    try:
        _create_batch(repository, service, "replay-daemon-crashed")
        port = _ReplayDaemonServicePort(service, actor=actor)
        daemon = ReplayWorkerDaemon(
            client=port,
            executor=CrashingExecutor(),
            config=ReplayWorkerConfig(
                worker_id=actor,
                lease_seconds=5,
                heartbeat_seconds=0.05,
                long_poll_seconds=0,
                cancellation_grace_seconds=0.05,
                cancellation_force_seconds=0.5,
                status_path=status_path,
            ),
        )

        with pytest.raises(RuntimeError, match="untrusted detail"):
            asyncio.run(daemon.run_once())
        status_payload = status_path.read_text(encoding="utf-8")
        status = ReplayWorkerStatus.model_validate_json(status_payload)
        assert status.state == "crashed"
        assert status.last_error == "Replay executor crashed: RuntimeError"
        assert "untrusted detail" not in status_payload
        assert port.finalize_calls == 0
        with repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayFinalizationRecord)) == 0
    finally:
        repository.close()
