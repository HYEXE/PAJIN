from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from threading import Barrier, Event

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from pajin.control_plane.artifacts import (
    ManagedArtifactRepository,
    ManagedArtifactSnapshot,
)
from pajin.control_plane.database import (
    ArtifactRecord,
    ControlPlaneRepository,
    EventRecord,
    JobRecord,
    ReplayBatchRecord,
    ReplayEventRecord,
    ReplayItemRecord,
    ReplayTicketRecord,
    RunRecord,
)
from pajin.control_plane.models import (
    AdmitSourceArtifactRequest,
    ArtifactLocator,
    ArtifactRef,
    CreateReplayBatchRequest,
    InternalJobKind,
    JobKind,
    JobState,
    RunState,
    job_submission_authority_digest,
    non_replayable_submission_authority_digest,
)
from pajin.control_plane.security import CheckpointSigner
from pajin.control_plane.service import ControlPlaneService, StateConflict
from pajin.runtime.store import RunStore


@dataclass(frozen=True)
class _Harness:
    repository: ControlPlaneRepository
    artifacts: ManagedArtifactRepository
    service: ControlPlaneService
    staging_root: Path
    repository_root: Path


@dataclass(frozen=True)
class _Producer:
    run_id: str
    job_id: str
    staging_id: str
    sealed_run_id: str

    def request(self, *, idempotency_key: str) -> AdmitSourceArtifactRequest:
        return AdmitSourceArtifactRequest(
            staging_id=self.staging_id,
            producer_run_id=self.run_id,
            producer_job_id=self.job_id,
            idempotency_key=idempotency_key,
        )


@dataclass(frozen=True)
class _IneligibleProducerCase:
    message: str
    run_state: RunState = RunState.COMPLETED
    job_state: JobState = JobState.SUCCEEDED
    job_kind: str = JobKind.CAMPAIGN.value
    job_owner_label: str | None = None
    include_engine_run_id: bool = True


class _BlockingManagedArtifactRepository(ManagedArtifactRepository):
    """Expose a deterministic seam after import and before the service recheck."""

    def __init__(self, delegate: ManagedArtifactRepository) -> None:
        self._delegate = delegate
        self.imported = Event()
        self.release = Event()

    def import_run(
        self,
        *,
        staging_id: str,
        producer_run_id: str,
        media_type: str,
        schema_kind: str,
        created_by: str,
    ) -> ManagedArtifactSnapshot:
        snapshot = self._delegate.import_run(
            staging_id=staging_id,
            producer_run_id=producer_run_id,
            media_type=media_type,
            schema_kind=schema_kind,
            created_by=created_by,
        )
        self.imported.set()
        if not self.release.wait(timeout=10):
            raise AssertionError("timed out waiting to release Artifact import")
        return snapshot

    def resolve(self, ref: ArtifactRef) -> ManagedArtifactSnapshot:
        return self._delegate.resolve(ref)

    def consume_staged_run(self, *, staging_id: str, expected_ref: ArtifactRef) -> bool:
        return self._delegate.consume_staged_run(
            staging_id=staging_id,
            expected_ref=expected_ref,
        )


def _identity(label: str) -> str:
    return sha256(label.encode()).hexdigest()


def _harness(path: Path) -> _Harness:
    repository = ControlPlaneRepository(f"sqlite:///{path.as_posix()}")
    repository.initialize()
    staging_root = path.parent / f"{path.stem}-staging"
    repository_root = path.parent / f"{path.stem}-repository"
    artifacts = ManagedArtifactRepository(
        staging_root=staging_root,
        repository_root=repository_root,
    )
    signer = CheckpointSigner(
        active_key_id="artifact-v1",
        keys={"artifact-v1": b"artifact-admission-signing-key-at-least-32-bytes"},
    )
    return _Harness(
        repository=repository,
        artifacts=artifacts,
        service=ControlPlaneService(
            repository,
            signer,
            artifact_repository=artifacts,
        ),
        staging_root=staging_root,
        repository_root=repository_root,
    )


def _seed_producer(
    harness: _Harness,
    label: str,
    *,
    run_state: RunState = RunState.COMPLETED,
    job_state: JobState = JobState.SUCCEEDED,
    job_kind: str = JobKind.CAMPAIGN.value,
    job_owner_label: str | None = None,
    engine_run_id: str | None = None,
    include_engine_run_id: bool = True,
) -> _Producer:
    identity = _identity(label)
    run_id = f"run_{identity[:32]}"
    owner_identity = _identity(job_owner_label or label)
    job_owner_run_id = f"run_{owner_identity[:32]}"
    job_id = f"job_{_identity(f'job:{label}')[:32]}"
    staging_id = f"stage_{_identity(f'stage:{label}')[:32]}"
    sealed_run_id = f"engine_{_identity(f'engine:{label}')[:24]}"

    stage_path = harness.staging_root / staging_id
    stage_path.mkdir(mode=0o700)
    store = RunStore(run_id=sealed_run_id, path=stage_path)
    store.append_event("campaign.completed", {"campaign": "kisa-replay"})
    store.write_text("evidence/report.md", f"sealed evidence for {label}")
    store.seal()

    now = datetime.now(UTC)
    runs = [
        RunRecord(
            run_id=run_id,
            campaign_name="kisa-replay",
            state=run_state.value,
            input={"source": label},
            submission_key=f"submission-{identity}",
            submission_authority_digest=non_replayable_submission_authority_digest(
                run_id=run_id,
                authority_kind="artifact-admission-fixture",
            ),
            current_checkpoint_id=None,
            created_at=now,
            updated_at=now,
        )
    ]
    if job_owner_run_id != run_id:
        runs.append(
            RunRecord(
                run_id=job_owner_run_id,
                campaign_name="kisa-replay",
                state=RunState.COMPLETED.value,
                input={"source": job_owner_label},
                submission_key=f"submission-owner-{owner_identity}",
                submission_authority_digest=non_replayable_submission_authority_digest(
                    run_id=job_owner_run_id,
                    authority_kind="artifact-admission-owner-fixture",
                ),
                current_checkpoint_id=None,
                created_at=now,
                updated_at=now,
            )
        )
    result: dict[str, str] = {}
    if include_engine_run_id:
        result["engineRunId"] = engine_run_id or sealed_run_id
        result["runPath"] = "/untrusted/worker/path/must-not-cross-boundary"
    with harness.repository.transaction() as session:
        session.add_all(runs)
        session.flush()
        session.add(
            JobRecord(
                job_id=job_id,
                run_id=job_owner_run_id,
                kind=job_kind,
                state=job_state.value,
                payload={"input": {}},
                priority=0,
                attempts=1,
                max_attempts=3,
                idempotency_key=f"producer-job-{identity}",
                submission_authority_digest=job_submission_authority_digest(
                    job_id=job_id,
                    run_id=job_owner_run_id,
                    job_kind=job_kind,
                    payload={"input": {}},
                    max_attempts=3,
                    idempotency_key=f"producer-job-{identity}",
                ),
                available_at=now,
                lease_owner=None,
                lease_token_hash=None,
                lease_expires_at=None,
                heartbeat_at=None,
                result=result,
                error=None,
                created_at=now,
                updated_at=now,
            )
        )
    return _Producer(
        run_id=run_id,
        job_id=job_id,
        staging_id=staging_id,
        sealed_run_id=sealed_run_id,
    )


def _batch_request(source: ArtifactRef, label: str) -> CreateReplayBatchRequest:
    return CreateReplayBatchRequest(
        source=ArtifactLocator(
            artifact_id=source.artifact_id,
            repository_version=source.repository_version,
        ),
        idempotency_key=f"replay-batch-{label}",
    )


def _artifact_authority_counts(
    repository: ControlPlaneRepository,
) -> tuple[int, int]:
    with repository.transaction() as session:
        artifacts = session.scalar(select(func.count()).select_from(ArtifactRecord))
        events = session.scalar(
            select(func.count())
            .select_from(EventRecord)
            .where(EventRecord.event_type == "artifact.source-admitted")
        )
        return int(artifacts or 0), int(events or 0)


def _assert_no_location_leaks(
    exposed: object,
    *,
    harness: _Harness,
    staging_id: str,
    storage_key: str | None = None,
) -> None:
    text = str(exposed)
    assert staging_id not in text
    assert str(harness.staging_root) not in text
    assert str(harness.repository_root) not in text
    assert "/untrusted/worker/path" not in text
    if storage_key is not None:
        assert storage_key not in text


@pytest.mark.parametrize(
    "case",
    [
        _IneligibleProducerCase(
            message="does not belong",
            job_owner_label="different-owner",
        ),
        _IneligibleProducerCase(
            message="public Campaign Job",
            job_kind=JobKind.TOOL_LOOP.value,
        ),
        _IneligibleProducerCase(
            message="must have succeeded",
            job_state=JobState.FAILED,
        ),
        _IneligibleProducerCase(
            message="must be completed",
            run_state=RunState.RUNNING,
        ),
        _IneligibleProducerCase(
            message="no sealed engine Run ID",
            include_engine_run_id=False,
        ),
    ],
)
def test_artifact_admission_rejects_ineligible_producer_without_authority(
    tmp_path: Path,
    case: _IneligibleProducerCase,
) -> None:
    harness = _harness(tmp_path / f"ineligible-{_identity(case.message)[:8]}.db")
    try:
        producer = _seed_producer(
            harness,
            f"ineligible-{case.message}",
            run_state=case.run_state,
            job_state=case.job_state,
            job_kind=case.job_kind,
            job_owner_label=case.job_owner_label,
            include_engine_run_id=case.include_engine_run_id,
        )
        request = producer.request(
            idempotency_key=f"admission-ineligible-{_identity(case.message)[:12]}"
        )

        with pytest.raises(StateConflict, match=case.message) as raised:
            harness.service.admit_source_artifact(
                request,
                actor="trusted-source-admission",
            )

        assert _artifact_authority_counts(harness.repository) == (0, 0)
        _assert_no_location_leaks(
            raised.value,
            harness=harness,
            staging_id=producer.staging_id,
        )
    finally:
        harness.repository.close()


def test_artifact_admission_rejects_mismatched_sealed_run_without_authority(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path / "mismatched-engine-run.db")
    try:
        producer = _seed_producer(
            harness,
            "mismatched-engine-run",
            engine_run_id="engine_different_result",
        )
        request = producer.request(idempotency_key="admission-mismatched-engine-run")

        with pytest.raises(StateConflict, match="not admission-bound") as raised:
            harness.service.admit_source_artifact(
                request,
                actor="trusted-source-admission",
            )

        assert _artifact_authority_counts(harness.repository) == (0, 0)
        _assert_no_location_leaks(
            raised.value,
            harness=harness,
            staging_id=producer.staging_id,
        )
    finally:
        harness.repository.close()


def test_exact_concurrent_artifact_admission_creates_one_record_and_event(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path / "concurrent-exact.db")
    try:
        producer = _seed_producer(harness, "concurrent-exact")
        request = producer.request(idempotency_key="admission-concurrent-exact")
        barrier = Barrier(3)

        def admit() -> ArtifactRef:
            barrier.wait(timeout=10)
            return harness.service.admit_source_artifact(
                request,
                actor="trusted-source-admission",
            )

        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [executor.submit(admit) for _ in range(2)]
            barrier.wait(timeout=10)
            results = [future.result(timeout=20) for future in futures]

        assert results[0] == results[1]
        assert _artifact_authority_counts(harness.repository) == (1, 1)
        with harness.repository.transaction() as session:
            artifact = session.scalar(select(ArtifactRecord))
            event = session.scalar(
                select(EventRecord).where(EventRecord.event_type == "artifact.source-admitted")
            )
            assert artifact is not None
            assert event is not None
            _assert_no_location_leaks(
                {"artifact": results[0].model_dump(mode="json"), "event": event.payload},
                harness=harness,
                staging_id=producer.staging_id,
                storage_key=artifact.storage_key,
            )
    finally:
        harness.repository.close()


def test_artifact_admission_idempotency_rejects_staging_and_input_drift(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path / "idempotency-drift.db")
    try:
        first = _seed_producer(harness, "idempotency-first")
        second = _seed_producer(harness, "idempotency-second")
        key = "admission-shared-idempotency-key"
        first_request = first.request(idempotency_key=key)
        admitted = harness.service.admit_source_artifact(
            first_request,
            actor="trusted-source-admission",
        )
        drifted_requests = [
            first_request.model_copy(update={"staging_id": f"stage_{'f' * 32}"}),
            second.request(idempotency_key=key),
        ]

        for drifted in drifted_requests:
            with pytest.raises(StateConflict, match="idempotency") as raised:
                harness.service.admit_source_artifact(
                    drifted,
                    actor="trusted-source-admission",
                )
            _assert_no_location_leaks(
                raised.value,
                harness=harness,
                staging_id=drifted.staging_id,
            )

        assert _artifact_authority_counts(harness.repository) == (1, 1)
        with harness.repository.transaction() as session:
            artifact = session.scalar(select(ArtifactRecord))
            assert artifact is not None
            assert artifact.artifact_id == admitted.artifact_id
            assert artifact.producer_run_id == first.run_id
            assert artifact.producer_job_id == first.job_id
    finally:
        harness.repository.close()


@pytest.mark.parametrize("drift", ["attempt", "result"])
def test_artifact_admission_producer_authority_cannot_drift_after_import(
    tmp_path: Path,
    drift: str,
) -> None:
    harness = _harness(tmp_path / f"producer-{drift}-drift.db")
    producer = _seed_producer(harness, f"producer-{drift}-drift")
    blocking = _BlockingManagedArtifactRepository(harness.artifacts)
    service = ControlPlaneService(
        harness.repository,
        CheckpointSigner(
            active_key_id="artifact-v1",
            keys={"artifact-v1": b"artifact-admission-signing-key-at-least-32-bytes"},
        ),
        artifact_repository=blocking,
    )
    request = producer.request(idempotency_key=f"admission-producer-{drift}-drift")
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(
                service.admit_source_artifact,
                request,
                actor="trusted-source-admission",
            )
            assert blocking.imported.wait(timeout=10)
            values: dict[str, object]
            if drift == "attempt":
                values = {"attempts": 2}
            else:
                values = {"result": {"engineRunId": "engine_changed_during_import"}}
            with (
                pytest.raises(IntegrityError, match="lease authority"),
                harness.repository.transaction() as session,
            ):
                session.execute(
                    update(JobRecord).where(JobRecord.job_id == producer.job_id).values(**values)
                )
            blocking.release.set()
            admitted = future.result(timeout=10)

        assert _artifact_authority_counts(harness.repository) == (1, 1)
        assert admitted.producer_run_id == producer.run_id
    finally:
        blocking.release.set()
        harness.repository.close()


def test_managed_artifact_tamper_blocks_all_replay_authority(
    tmp_path: Path,
) -> None:
    harness = _harness(tmp_path / "managed-tamper.db")
    try:
        producer = _seed_producer(harness, "managed-tamper")
        source = harness.service.admit_source_artifact(
            producer.request(idempotency_key="admission-managed-tamper"),
            actor="trusted-source-admission",
        )
        snapshot = harness.artifacts.resolve(source)
        (snapshot.path / "evidence" / "report.md").write_text(
            "tampered after admission",
            encoding="utf-8",
        )

        with pytest.raises(StateConflict, match="failed reverification") as raised:
            harness.service.create_replay_batch(
                _batch_request(source, "managed-tamper"),
                actor="trusted-replay-admission",
            )

        with harness.repository.transaction() as session:
            assert session.scalar(select(func.count()).select_from(ReplayBatchRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayItemRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayTicketRecord)) == 0
            assert session.scalar(select(func.count()).select_from(ReplayEventRecord)) == 0
            assert (
                session.scalar(
                    select(func.count())
                    .select_from(JobRecord)
                    .where(JobRecord.kind == InternalJobKind.REPLAY.value)
                )
                == 0
            )
            assert session.scalar(select(func.count()).select_from(RunRecord)) == 1
            artifact = session.scalar(select(ArtifactRecord))
            assert artifact is not None
            _assert_no_location_leaks(
                raised.value,
                harness=harness,
                staging_id=producer.staging_id,
                storage_key=artifact.storage_key,
            )
    finally:
        harness.repository.close()
