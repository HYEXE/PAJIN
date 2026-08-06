from __future__ import annotations

import asyncio
import json
import os
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

import pajin.control_plane.executors as executor_module
import pajin.control_plane.replay_worker_main as replay_worker_main_module
import pajin.control_plane.status_file as status_file_module
import pajin.control_plane.worker as worker_module
import pajin.control_plane.worker_main as worker_main_module
from pajin.control_plane.client import (
    ControlPlaneAuthenticationError,
    ControlPlaneClient,
    ControlPlaneLeaseLost,
    ControlPlaneProtocolError,
    ControlPlaneRunCancelled,
    ControlPlaneTransientError,
)
from pajin.control_plane.executors import (
    ApprovalCheckpointExecution,
    CampaignJobExecutor,
    CompletedExecution,
    ExecutorRegistry,
    PermanentExecutionError,
    ToolLoopJobExecutor,
)
from pajin.control_plane.models import (
    ApprovalIntent,
    ApprovalState,
    ApprovalView,
    CheckpointCreationView,
    CheckpointView,
    ClaimedJob,
    ClaimJobRequest,
    ControlPlaneConflictCode,
    JobKind,
    JobState,
    JobView,
    LeaseRequest,
    ReplayClaimRequest,
    ReplayLeaseRequest,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
)
from pajin.control_plane.replay_worker import ReplayWorkerDaemon
from pajin.control_plane.worker import (
    WorkerDaemon,
    WorkerDaemonConfig,
    WorkerDaemonStatus,
    WorkerQuiescenceError,
)
from pajin.control_plane.worker_lifecycle import LeaseDaemonFencedError, LeaseDaemonLifecycle
from pajin.domain.manifest import load_manifest
from pajin.domain.models import ToolRiskTier
from pajin.runtime.control import (
    CancellationCleanupStatus,
    CancellationKind,
    ExecutionCancellationContext,
)
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus


def _job(
    *,
    kind: str = "campaign",
    payload: dict[str, Any] | None = None,
    job_id: str = "job_11111111111111111111111111111111",
    attempts: int = 1,
) -> JobView:
    now = datetime.now(UTC)
    return JobView(
        job_id=job_id,
        run_id="run_11111111111111111111111111111111",
        kind=kind,
        state=JobState.LEASED,
        payload=payload or {},
        priority=0,
        attempts=attempts,
        max_attempts=3,
        available_at=now,
        lease_owner="worker-test",
        lease_expires_at=now + timedelta(seconds=30),
        heartbeat_at=now,
        result=None,
        error=None,
        created_at=now,
        updated_at=now,
    )


def _replay_tool_permit() -> ReplayToolPermitView:
    issued_at = datetime.now(UTC)
    return ReplayToolPermitView(
        permit_id=f"replay-permit_{'8' * 32}",
        permit_digest="c" * 64,
        replay_request_id=f"tool_replay_{'9' * 32}",
        job_id=f"job_{'4' * 32}",
        batch_id=f"replay-batch_{'1' * 32}",
        item_id=f"replay-item_{'2' * 32}",
        ticket_id=f"replay-ticket_{'3' * 32}",
        compilation_id=f"replay-compilation_{'5' * 32}",
        budget_reservation_id=f"budget-reservation_{'6' * 32}",
        rate_reservation_id=f"rate-reservation_{'7' * 32}",
        replay_run_id="run_replay_transport",
        attempt=1,
        fencing_value=7,
        call_ordinal=1,
        issued_to="worker-service",
        executor_profile="kisa-exact-v1",
        source_root_digest="a" * 64,
        compilation_digest="e" * 64,
        grant_digest="f" * 64,
        original_request_id="tool_original_request",
        tool_id="ai.chat-probe",
        tool_version="1.0.0",
        target_id="target-ai-chat",
        target="http://127.0.0.1:8080/v1/chat",
        method="POST",
        compiled_argument_digest="b" * 64,
        tool_call_units=1,
        request_units=3,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(seconds=15),
    )


class FakeControlPlane:
    def __init__(self, claimed: ClaimedJob) -> None:
        self.claimed: ClaimedJob | None = claimed
        self.heartbeat_authority = claimed.job.model_copy(deep=True)
        self.heartbeats = 0
        self.completed: list[Any] = []
        self.failed: list[Any] = []
        self.checkpoints: list[Any] = []
        self.transient_completions = 0
        self.lose_lease = False
        self.run_cancelled = False
        self.heartbeat_error: Exception | None = None
        self.cancel_completion = False
        self.heartbeat_gate: asyncio.Event | None = None
        self.completion_gate: asyncio.Event | None = None
        self.completion_started = asyncio.Event()

    async def claim(self, _request: Any) -> ClaimedJob | None:
        claimed, self.claimed = self.claimed, None
        return claimed

    async def heartbeat(self, _job_id: str, _request: Any) -> JobView:
        self.heartbeats += 1
        if self.heartbeat_gate is not None:
            await self.heartbeat_gate.wait()
        if self.heartbeat_error is not None:
            raise self.heartbeat_error
        if self.run_cancelled:
            raise ControlPlaneRunCancelled("run has been cancelled")
        if self.lose_lease:
            raise ControlPlaneLeaseLost("test lease expired")
        now = datetime.now(UTC)
        self.heartbeat_authority = self.heartbeat_authority.model_copy(
            update={
                "lease_expires_at": now + timedelta(seconds=_request.lease_seconds),
                "heartbeat_at": now,
                "updated_at": now,
            }
        )
        return self.heartbeat_authority

    async def complete(self, _job_id: str, request: Any) -> JobView:
        self.completion_started.set()
        if self.completion_gate is not None:
            await self.completion_gate.wait()
        if self.cancel_completion:
            raise ControlPlaneRunCancelled("run has been cancelled")
        if self.transient_completions:
            self.transient_completions -= 1
            raise ControlPlaneTransientError("temporary completion failure")
        self.completed.append(request)
        return self.heartbeat_authority.model_copy(
            update={
                "state": JobState.SUCCEEDED,
                "lease_expires_at": None,
                "result": request.result,
                "error": None,
                "updated_at": datetime.now(UTC),
            }
        )

    async def fail(self, _job_id: str, request: Any) -> JobView:
        self.failed.append(request)
        original = self.heartbeat_authority
        if request.retryable and original.attempts < original.max_attempts:
            state = JobState.QUEUED
        elif original.attempts >= original.max_attempts:
            state = JobState.DEAD_LETTER
        else:
            state = JobState.FAILED
        now = datetime.now(UTC)
        return original.model_copy(
            update={
                "state": state,
                "available_at": now if state is JobState.QUEUED else original.available_at,
                "lease_owner": None,
                "lease_expires_at": None,
                "heartbeat_at": None,
                "error": request.error,
                "updated_at": now,
            }
        )

    async def checkpoint(self, _job_id: str, request: Any) -> CheckpointCreationView:
        self.checkpoints.append(request)
        now = datetime.now(UTC)
        checkpoint = CheckpointView(
            checkpoint_id="checkpoint_" + "1" * 32,
            run_id="run_" + "1" * 32,
            sequence=1,
            schema_version=1,
            state=request.state,
            pending_intent=request.pending_intent,
            payload_sha256="a" * 64,
            signature="b" * 64,
            key_id="test",
            created_at=now,
            claimed_at=None,
            claimed_by=None,
            continuation_job_id=None,
        )
        approval = ApprovalView(
            approval_id="approval_" + "1" * 32,
            run_id=checkpoint.run_id,
            checkpoint_id=checkpoint.checkpoint_id,
            intent=request.pending_intent,
            state=ApprovalState.PENDING,
            requested_by="worker-test",
            requested_at=now,
            decided_by=None,
            decided_at=None,
            decision_reason=None,
            consumed_by=None,
            consumed_at=None,
        )
        return CheckpointCreationView(checkpoint=checkpoint, approval=approval)


class TerminalHeartbeatDuringCompletionControlPlane(FakeControlPlane):
    """Commit completion before a concurrent heartbeat observes terminal state."""

    def __init__(self, claimed: ClaimedJob) -> None:
        super().__init__(claimed)
        self.completion_committed = asyncio.Event()
        self.heartbeat_rejected = asyncio.Event()
        self.release_completion_response = asyncio.Event()

    async def heartbeat(self, _job_id: str, _request: Any) -> JobView:
        self.heartbeats += 1
        await self.completion_committed.wait()
        self.heartbeat_rejected.set()
        raise ControlPlaneLeaseLost("job is already terminal")

    async def complete(self, _job_id: str, request: Any) -> JobView:
        self.completion_started.set()
        self.completed.append(request)
        self.completion_committed.set()
        await self.release_completion_response.wait()
        return self.heartbeat_authority.model_copy(
            update={
                "state": JobState.SUCCEEDED,
                "lease_expires_at": None,
                "result": request.result,
                "error": None,
                "updated_at": datetime.now(UTC),
            }
        )


class RetainingMutatingControlPlane(FakeControlPlane):
    """Transport double that mutates its retained response after returning it."""

    def __init__(self, claimed: ClaimedJob) -> None:
        super().__init__(claimed)
        self.retained = claimed
        self.heartbeat_job_ids: list[str] = []
        self.completed_job_ids: list[str] = []

    async def claim(self, request: Any) -> ClaimedJob | None:
        claimed = await super().claim(request)
        asyncio.get_running_loop().call_soon(self._retarget_retained_claim)
        return claimed

    def _retarget_retained_claim(self) -> None:
        self.retained.job.job_id = "job_ffffffffffffffffffffffffffffffff"
        self.retained.lease_token = "m" * 43

    async def heartbeat(self, job_id: str, request: Any) -> JobView:
        self.heartbeat_job_ids.append(job_id)
        return await super().heartbeat(job_id, request)

    async def complete(self, job_id: str, request: Any) -> JobView:
        self.completed_job_ids.append(job_id)
        return await super().complete(job_id, request)


class DelayedClaimControlPlane(FakeControlPlane):
    def __init__(self, claimed: ClaimedJob) -> None:
        super().__init__(claimed)
        self.claim_returned_at: float | None = None

    async def claim(self, request: Any) -> ClaimedJob | None:
        await asyncio.sleep(0.05)
        claimed = await super().claim(request)
        self.claim_returned_at = asyncio.get_running_loop().time()
        return claimed


class CancellationResistantClaimControlPlane(FakeControlPlane):
    """Transport probe that suppresses cancellation until explicitly released."""

    def __init__(self, claimed: ClaimedJob) -> None:
        super().__init__(claimed)
        self.claim_started = asyncio.Event()
        self.release_claim = asyncio.Event()
        self.claim_finished = asyncio.Event()
        self.cancellation_count = 0

    async def claim(self, _request: Any) -> ClaimedJob | None:
        self.claim_started.set()
        try:
            while not self.release_claim.is_set():
                try:
                    await self.release_claim.wait()
                except asyncio.CancelledError:
                    self.cancellation_count += 1
        finally:
            self.claim_finished.set()
        return None


class CancellationResistantHeartbeatControlPlane(FakeControlPlane):
    """Heartbeat probe that proves claim cleanup itself has a hard bound."""

    def __init__(self, claimed: ClaimedJob) -> None:
        super().__init__(claimed)
        self.heartbeat_started = asyncio.Event()
        self.release_heartbeat = asyncio.Event()
        self.heartbeat_finished = asyncio.Event()
        self.cancellation_count = 0

    async def heartbeat(self, _job_id: str, _request: Any) -> JobView:
        self.heartbeat_started.set()
        try:
            while not self.release_heartbeat.is_set():
                try:
                    await self.release_heartbeat.wait()
                except asyncio.CancelledError:
                    self.cancellation_count += 1
        finally:
            self.heartbeat_finished.set()
        return self.heartbeat_authority


class MisdirectingFinalizationControlPlane(FakeControlPlane):
    async def complete(self, job_id: str, request: Any) -> JobView:
        response = await super().complete(job_id, request)
        return response.model_copy(update={"job_id": "job_ffffffffffffffffffffffffffffffff"})

    async def fail(self, job_id: str, request: Any) -> JobView:
        response = await super().fail(job_id, request)
        return response.model_copy(update={"state": JobState.SUCCEEDED})

    async def checkpoint(self, job_id: str, request: Any) -> CheckpointCreationView:
        response = await super().checkpoint(job_id, request)
        return response.model_copy(
            update={
                "approval": response.approval.model_copy(
                    update={"run_id": "run_ffffffffffffffffffffffffffffffff"}
                )
            }
        )


class DelayedExecutor:
    kind = JobKind.CAMPAIGN

    def __init__(self, *, delay: float = 0.12) -> None:
        self.delay = delay
        self.cancelled = False
        self.started = asyncio.Event()

    async def execute(
        self,
        _job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        self.started.set()
        delay = asyncio.create_task(asyncio.sleep(self.delay))
        cancellation_wait = (
            asyncio.create_task(cancellation.wait()) if cancellation is not None else None
        )
        try:
            watched = {delay}
            if cancellation_wait is not None:
                watched.add(cancellation_wait)
            done, _pending = await asyncio.wait(
                watched,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if cancellation_wait is not None and cancellation_wait in done:
                self.cancelled = True
                delay.cancel()
                await asyncio.gather(delay, return_exceptions=True)
                return CompletedExecution(result={"cancelled": True})
            if cancellation_wait is not None:
                cancellation_wait.cancel()
                await asyncio.gather(cancellation_wait, return_exceptions=True)
        except asyncio.CancelledError:
            self.cancelled = True
            for task in watched:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*watched, return_exceptions=True)
            raise
        return CompletedExecution(result={"ok": True})


class BlockingCampaignWorker:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = False

    async def run(
        self,
        _job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        assert not secrets
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        raise AssertionError("blocking campaign Worker unexpectedly resumed")


class RepeatingSideEffectExecutor:
    """Executor probe used to prove lease expiry quiesces the old owner."""

    kind = JobKind.CAMPAIGN

    def __init__(self, *, reclaim_started: asyncio.Event | None = None) -> None:
        self.side_effects = 0
        self.overlap_side_effects = 0
        self.stopped = asyncio.Event()
        self.reclaim_started = reclaim_started

    async def execute(
        self,
        _job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        del cancellation
        try:
            while True:
                self.side_effects += 1
                if self.reclaim_started is not None and self.reclaim_started.is_set():
                    self.overlap_side_effects += 1
                await asyncio.sleep(0.01)
        finally:
            self.stopped.set()


class FailedCampaignWorker:
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        assert not secrets
        now = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="failed-campaign-test",
            status=WorkerStatus.FAILED,
            exit_code=1,
            stderr="bounded Worker failure",
            started_at=now,
            finished_at=now,
        )


class ContextIgnoringExecutor:
    kind = JobKind.CAMPAIGN

    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.forced_cancelled = False

    async def execute(
        self,
        _job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        assert cancellation is not None
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.forced_cancelled = True
            raise
        raise AssertionError("ignoring executor unexpectedly resumed")


class LegacyExecutor:
    kind = JobKind.CAMPAIGN

    async def execute(self, _job: JobView) -> CompletedExecution:
        return CompletedExecution(result={"legacy": True})


class PermanentRejectingExecutor:
    kind = JobKind.CAMPAIGN

    async def execute(
        self,
        _job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        del cancellation
        raise PermanentExecutionError("bounded rejection")


class UnsupportedOutcomeExecutor:
    kind = JobKind.CAMPAIGN

    async def execute(
        self,
        _job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> Any:
        del cancellation
        return {"looks": "successful", "but": "is not a typed outcome"}


class UnboundedCompletedResultExecutor:
    kind = JobKind.CAMPAIGN

    async def execute(
        self,
        _job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        del cancellation
        nested: dict[str, Any] = {"leaf": True}
        for _depth in range(40):
            nested = {"nested": nested}
        return CompletedExecution(result=nested)


class RetainingMutatingOutcomeExecutor:
    kind = JobKind.CAMPAIGN

    def __init__(self) -> None:
        self.retained = CompletedExecution(result={"authority": "original"})

    async def execute(
        self,
        _job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        del cancellation
        asyncio.get_running_loop().call_soon(self._mutate_retained_outcome)
        return self.retained

    def _mutate_retained_outcome(self) -> None:
        self.retained.result = {"authority": "retargeted"}


class CheckpointExecutor:
    kind = JobKind.TOOL_LOOP

    def __init__(self, outcome: ApprovalCheckpointExecution) -> None:
        self.outcome = outcome

    async def execute(
        self,
        _job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ApprovalCheckpointExecution:
        del cancellation
        return self.outcome


class MutatingExecutor:
    kind = JobKind.CAMPAIGN

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        del cancellation
        job.job_id = "job_ffffffffffffffffffffffffffffffff"
        job.payload["mutated"] = True
        return CompletedExecution(result={"mutated": True})


def test_executor_registry_rejects_adapter_without_cancellation_contract() -> None:
    with pytest.raises(ValueError, match="cancellation context"):
        ExecutorRegistry([LegacyExecutor()])  # type: ignore[list-item]


@pytest.mark.asyncio
async def test_executor_registry_isolates_claimed_job_from_adapter_mutation() -> None:
    job = _job(payload={"input": {"command": "safe"}})
    original = job.model_copy(deep=True)

    outcome = await ExecutorRegistry([MutatingExecutor()]).execute(job)

    assert outcome == CompletedExecution(result={"mutated": True})
    assert job == original


def test_job_view_and_resume_directory_reject_path_traversal(tmp_path: Path) -> None:
    trusted = _job(kind="tool-loop")
    payload = trusted.model_dump(mode="python")
    payload["job_id"] = "../../escaped-job"
    with pytest.raises(ValidationError, match="job_id"):
        JobView.model_validate(payload)

    # Defense in depth: even a locally constructed object that bypasses model
    # validation cannot redirect the executor's checkpoint write.
    bypassed = trusted.model_copy(update={"job_id": "../../escaped-job"})
    executor = ToolLoopJobExecutor(output_root=tmp_path / "runs")
    with pytest.raises(PermanentExecutionError, match="escapes"):
        executor._safe_resume_directory(bypassed.job_id)
    assert not (tmp_path / "escaped-job").exists()


def test_resume_checkpoint_fails_closed_without_posix_dirfd_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not executor_module._secure_resume_platform_available(platform_name="nt")
    monkeypatch.setattr(
        executor_module,
        "_secure_resume_platform_available",
        lambda: False,
    )
    executor = ToolLoopJobExecutor(output_root=tmp_path / "runs")

    with pytest.raises(PermanentExecutionError, match="POSIX dirfd"):
        executor._open_resume_directory("job_" + "a" * 32)
    with pytest.raises(PermanentExecutionError, match="POSIX dirfd"):
        executor._write_resume_checkpoint(-1, "attempt-1.json", '{"safe":true}')

    assert not (tmp_path / "runs" / "_control-plane-resume").exists()


def test_resume_checkpoint_leaf_is_exclusive_private_and_never_follows_symlinks(
    tmp_path: Path,
) -> None:
    executor = ToolLoopJobExecutor(output_root=tmp_path)
    resume_dir = tmp_path / "resume-leaf-test"
    resume_dir.mkdir()
    resume_dir_fd = os.open(
        resume_dir,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    checkpoint = resume_dir / "attempt-1.json"
    victim = tmp_path / "victim.json"
    victim.write_text("owner-data", encoding="utf-8")
    checkpoint.symlink_to(victim)

    try:
        with pytest.raises(PermanentExecutionError, match="already exists"):
            executor._write_resume_checkpoint(
                resume_dir_fd,
                checkpoint.name,
                '{"safe":true}',
            )

        assert victim.read_text(encoding="utf-8") == "owner-data"
        checkpoint.unlink()
        checkpoint.write_text("existing", encoding="utf-8")
        with pytest.raises(PermanentExecutionError, match="already exists"):
            executor._write_resume_checkpoint(
                resume_dir_fd,
                checkpoint.name,
                '{"safe":true}',
            )
        assert checkpoint.read_text(encoding="utf-8") == "existing"

        checkpoint.unlink()
        executor._write_resume_checkpoint(
            resume_dir_fd,
            checkpoint.name,
            '{"safe":true}',
        )
        assert json.loads(checkpoint.read_text(encoding="utf-8")) == {"safe": True}
        assert stat.S_IMODE(checkpoint.stat().st_mode) == 0o600
    finally:
        os.close(resume_dir_fd)


def test_resume_checkpoint_write_is_anchored_against_directory_swap(tmp_path: Path) -> None:
    executor = ToolLoopJobExecutor(output_root=tmp_path / "runs")
    job_id = "job_" + "a" * 32
    resume_dir, resume_dir_fd = executor._open_resume_directory(job_id)
    anchored_dir = resume_dir.with_name(f"{resume_dir.name}-anchored")
    victim = tmp_path / "victim.json"
    victim.write_text("owner-data", encoding="utf-8")

    resume_dir.rename(anchored_dir)
    resume_dir.mkdir(mode=0o700)
    (resume_dir / "attempt-1.json").symlink_to(victim)
    try:
        executor._write_resume_checkpoint(
            resume_dir_fd,
            "attempt-1.json",
            '{"safe":true}',
        )
    finally:
        os.close(resume_dir_fd)

    assert victim.read_text(encoding="utf-8") == "owner-data"
    assert (resume_dir / "attempt-1.json").is_symlink()
    assert json.loads((anchored_dir / "attempt-1.json").read_text(encoding="utf-8")) == {
        "safe": True
    }


def test_worker_status_atomic_write_ignores_preclaimed_legacy_temp_and_is_private(
    tmp_path: Path,
) -> None:
    status_path = tmp_path / "status.json"
    victim = tmp_path / "victim.json"
    victim.write_text("owner-data", encoding="utf-8")
    status_path.with_suffix(".json.tmp").symlink_to(victim)
    daemon = WorkerDaemon(
        client=FakeControlPlane(ClaimedJob(job=_job(), lease_token="l" * 43)),
        executors=ExecutorRegistry([DelayedExecutor()]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            status_path=status_path,
        ),
    )

    daemon._status("idle")

    assert victim.read_text(encoding="utf-8") == "owner-data"
    assert status_path.parent == tmp_path
    assert status_path.is_file() and not status_path.is_symlink()
    assert stat.S_IMODE(status_path.stat().st_mode) == 0o600
    payload = status_path.read_text(encoding="utf-8")
    assert "NaN" not in payload and "Infinity" not in payload
    assert list(tmp_path.glob(".status.json.*.tmp")) == []


def test_worker_status_failed_replace_cleans_same_parent_temporary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=FakeControlPlane(ClaimedJob(job=_job(), lease_token="l" * 43)),
        executors=ExecutorRegistry([DelayedExecutor()]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            status_path=status_path,
        ),
    )
    observed: list[tuple[str, str, int | None, int | None]] = []

    def fail_replace(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        observed.append((source, destination, src_dir_fd, dst_dir_fd))
        raise OSError("replace failed")

    monkeypatch.setattr(status_file_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        daemon._status("idle")

    assert len(observed) == 1
    temporary, destination, src_dir_fd, dst_dir_fd = observed[0]
    assert temporary.startswith(".status.json.") and temporary.endswith(".tmp")
    assert destination == status_path.name
    assert src_dir_fd is not None and src_dir_fd == dst_dir_fd
    assert list(tmp_path.glob(".status.json.*.tmp")) == []


@pytest.mark.parametrize(
    "write_status",
    [WorkerDaemon._write_status, ReplayWorkerDaemon._write_status],
)
def test_worker_status_replaces_destination_symlink_without_following_it(
    tmp_path: Path,
    write_status,
) -> None:
    status_path = tmp_path / "status.json"
    victim = tmp_path / "victim.json"
    victim.write_text("owner-data", encoding="utf-8")
    status_path.symlink_to(victim)

    write_status(status_path, '{"state":"idle"}')

    assert victim.read_text(encoding="utf-8") == "owner-data"
    assert status_path.is_file() and not status_path.is_symlink()
    assert json.loads(status_path.read_text(encoding="utf-8")) == {"state": "idle"}
    assert stat.S_IMODE(status_path.stat().st_mode) == 0o600


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO regression is POSIX-only")
def test_worker_status_replaces_special_file_without_opening_it(tmp_path: Path) -> None:
    status_path = tmp_path / "status.json"
    os.mkfifo(status_path, mode=0o600)

    WorkerDaemon._write_status(status_path, '{"state":"idle"}')

    assert status_path.is_file()
    assert json.loads(status_path.read_text(encoding="utf-8")) == {"state": "idle"}


def test_worker_status_dirfd_anchors_replace_against_parent_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parent = tmp_path / "status-parent"
    parent.mkdir(mode=0o700)
    status_path = parent / "status.json"
    anchored_parent = tmp_path / "status-parent-anchored"
    victim = tmp_path / "victim.json"
    victim.write_text("owner-data", encoding="utf-8")
    real_replace = os.replace

    def swap_then_replace(
        source: str,
        destination: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
    ) -> None:
        parent.rename(anchored_parent)
        parent.mkdir(mode=0o700)
        (parent / destination).symlink_to(victim)
        real_replace(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
        )

    monkeypatch.setattr(status_file_module.os, "replace", swap_then_replace)

    WorkerDaemon._write_status(status_path, '{"state":"idle"}')

    assert victim.read_text(encoding="utf-8") == "owner-data"
    assert status_path.is_symlink()
    assert json.loads((anchored_parent / status_path.name).read_text(encoding="utf-8")) == {
        "state": "idle"
    }


@pytest.mark.parametrize(
    "write_status",
    [WorkerDaemon._write_status, ReplayWorkerDaemon._write_status],
)
def test_worker_status_rejects_symlink_parent_leaf(
    tmp_path: Path,
    write_status,
) -> None:
    actual_parent = tmp_path / "actual-parent"
    actual_parent.mkdir(mode=0o700)
    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink or non-directory"):
        write_status(linked_parent / "status.json", '{"state":"idle"}')

    assert not (actual_parent / "status.json").exists()


def test_worker_status_rejects_intermediate_parent_symlink(tmp_path: Path) -> None:
    trusted_parent = tmp_path / "trusted-parent"
    trusted_parent.mkdir(mode=0o700)
    actual_parent = tmp_path / "actual-parent"
    actual_parent.mkdir(mode=0o700)
    (trusted_parent / "jump").symlink_to(actual_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink or non-directory"):
        WorkerDaemon._write_status(
            trusted_parent / "jump" / "nested" / "status.json",
            '{"state":"idle"}',
        )

    assert not (actual_parent / "nested").exists()


def test_worker_status_rejects_non_directory_or_shared_parent(tmp_path: Path) -> None:
    non_directory = tmp_path / "not-a-directory"
    non_directory.write_text("owner-data", encoding="utf-8")
    with pytest.raises(ValueError, match="symlink or non-directory"):
        WorkerDaemon._write_status(
            non_directory / "status.json",
            '{"state":"idle"}',
        )

    shared_parent = tmp_path / "shared-parent"
    shared_parent.mkdir(mode=0o777)
    shared_parent.chmod(0o777)
    preoccupied = shared_parent / "status.json"
    preoccupied.write_text("lower-user-owned", encoding="utf-8")
    with pytest.raises(ValueError, match="private and owned"):
        WorkerDaemon._write_status(
            preoccupied,
            '{"state":"idle"}',
        )
    assert preoccupied.read_text(encoding="utf-8") == "lower-user-owned"

    shared_intermediate = tmp_path / "shared-intermediate"
    shared_intermediate.mkdir(mode=0o777)
    shared_intermediate.chmod(0o777)
    with pytest.raises(ValueError, match="untrusted writable component"):
        WorkerDaemon._write_status(
            shared_intermediate / "private-child" / "status.json",
            '{"state":"idle"}',
        )
    assert not (shared_intermediate / "private-child").exists()


def test_worker_status_canonicalizes_but_rejects_shared_system_tmp_root() -> None:
    canonical, is_private_root = status_file_module._canonical_status_parent(
        Path("/tmp"),
        owner_label="Worker",
    )

    assert canonical == Path("/tmp").resolve(strict=True)
    assert is_private_root is False
    with pytest.raises(ValueError, match="private and owned"):
        WorkerDaemon._write_status(
            Path("/tmp") / "pajin-shared-root-must-reject.json",
            '{"state":"idle"}',
        )


def test_worker_status_defaults_to_home_private_parent() -> None:
    worker_path = status_file_module.default_worker_status_path()
    replay_path = status_file_module.default_replay_worker_status_path()

    expected_parent = Path.home() / ".pajin" / "status"
    assert worker_path.parent == expected_parent
    assert replay_path.parent == expected_parent
    assert worker_path != replay_path
    assert not worker_path.is_relative_to(Path("/tmp"))


@pytest.mark.parametrize(
    "write_status",
    [WorkerDaemon._write_status, ReplayWorkerDaemon._write_status],
)
def test_worker_status_fails_closed_without_posix_dirfd_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    write_status,
) -> None:
    assert status_file_module._secure_status_platform_available(platform_name="nt") is False

    monkeypatch.setattr(
        status_file_module,
        "_secure_status_platform_available",
        lambda: False,
    )
    status_path = tmp_path / "status.json"

    with pytest.raises(RuntimeError, match="POSIX dirfd platform"):
        write_status(status_path, '{"state":"idle"}')

    assert not status_path.exists()


@pytest.mark.asyncio
async def test_daemon_heartbeats_and_retries_idempotent_completion(tmp_path: Path) -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    control.transient_completions = 1
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor()]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            retry_base_seconds=0.05,
            status_path=status_path,
        ),
    )

    assert await daemon.run_once() is True

    assert control.heartbeats >= 2
    assert len(control.completed) == 1
    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.state == "idle"
    assert status.handled_jobs == 1
    assert "l" * 43 not in status_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_initial_lease_deadline_starts_after_long_poll_claim_returns(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    control = DelayedClaimControlPlane(ClaimedJob(job=_job(), lease_token="l" * 43))
    observed_at: list[float] = []
    original = worker_module.MonotonicLeaseDeadline.from_server_timestamps.__func__

    def capture_observed_at(cls, **kwargs):
        observed_at.append(kwargs["observed_at"])
        return original(cls, **kwargs)

    monkeypatch.setattr(
        worker_module.MonotonicLeaseDeadline,
        "from_server_timestamps",
        classmethod(capture_observed_at),
    )
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor(delay=0)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=1,
            long_poll_seconds=1,
            status_path=tmp_path / "status.json",
        ),
    )

    assert await daemon.run_once() is True
    assert control.claim_returned_at is not None
    assert observed_at == pytest.approx([control.claim_returned_at], abs=0.01)


@pytest.mark.asyncio
async def test_terminal_heartbeat_cannot_hide_committed_completion_response() -> None:
    control = TerminalHeartbeatDuringCompletionControlPlane(
        ClaimedJob(job=_job(), lease_token="l" * 43)
    )
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor(delay=0)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    daemon_task = asyncio.create_task(daemon.run_once())
    await asyncio.wait_for(control.heartbeat_rejected.wait(), timeout=0.5)
    control.release_completion_response.set()

    assert await asyncio.wait_for(daemon_task, timeout=0.5) is True
    assert len(control.completed) == 1


@pytest.mark.asyncio
async def test_daemon_owns_claim_snapshot_after_transport_returns() -> None:
    original_job_id = "job_11111111111111111111111111111111"
    control = RetainingMutatingControlPlane(
        ClaimedJob(job=_job(job_id=original_job_id), lease_token="l" * 43)
    )
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor(delay=0.12)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    assert await daemon.run_once() is True

    assert control.retained.job.job_id != original_job_id
    assert control.completed_job_ids == [original_job_id]
    assert control.heartbeat_job_ids
    assert set(control.heartbeat_job_ids) == {original_job_id}


@pytest.mark.asyncio
async def test_daemon_owns_executor_outcome_before_adapter_can_mutate_it() -> None:
    control = FakeControlPlane(ClaimedJob(job=_job(), lease_token="l" * 43))
    executor = RetainingMutatingOutcomeExecutor()
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    assert await daemon.run_once() is True
    assert executor.retained.result == {"authority": "retargeted"}
    assert len(control.completed) == 1
    assert control.completed[0].result == {"authority": "original"}


@pytest.mark.asyncio
async def test_daemon_rejects_foreign_job_completion_response(tmp_path: Path) -> None:
    control = MisdirectingFinalizationControlPlane(ClaimedJob(job=_job(), lease_token="l" * 43))
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor(delay=0)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            status_path=status_path,
        ),
    )

    with pytest.raises(ControlPlaneProtocolError, match="immutable Job authority"):
        await daemon.run_once()

    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.state == "fatal"
    with pytest.raises(LeaseDaemonFencedError, match="lifecycle has been fenced"):
        await daemon.run_once()


@pytest.mark.asyncio
async def test_daemon_rejects_failure_response_without_requested_terminal_state() -> None:
    control = MisdirectingFinalizationControlPlane(ClaimedJob(job=_job(), lease_token="l" * 43))
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([PermanentRejectingExecutor()]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    with pytest.raises(ControlPlaneProtocolError, match="requested outcome"):
        await daemon.run_once()


@pytest.mark.asyncio
async def test_daemon_rejects_checkpoint_response_outside_claimed_run() -> None:
    intent = ApprovalIntent(
        call_fingerprint="a" * 64,
        tool_id="mock.high-risk",
        target="https://target.invalid/probe",
        risk_tier=ToolRiskTier.T3,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
    )
    outcome = ApprovalCheckpointExecution(
        state={"step": 1},
        pending_intent=intent,
    )
    control = MisdirectingFinalizationControlPlane(
        ClaimedJob(job=_job(kind="tool-loop"), lease_token="l" * 43)
    )
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([CheckpointExecutor(outcome)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.TOOL_LOOP],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    with pytest.raises(ControlPlaneProtocolError, match="claimed authority"):
        await daemon.run_once()


@pytest.mark.asyncio
async def test_stalled_heartbeat_quiesces_before_reclaim_can_overlap() -> None:
    server_now = datetime.now(UTC)
    short_lease_job = _job().model_copy(
        update={
            "heartbeat_at": server_now,
            "updated_at": server_now,
            "lease_expires_at": server_now + timedelta(seconds=0.15),
        }
    )
    control = FakeControlPlane(ClaimedJob(job=short_lease_job, lease_token="l" * 43))
    control.heartbeat_gate = asyncio.Event()
    reclaim_started = asyncio.Event()
    executor = RepeatingSideEffectExecutor(reclaim_started=reclaim_started)
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            cancellation_grace_seconds=0.05,
            cancellation_force_seconds=0.25,
        ),
    )
    asyncio.get_running_loop().call_later(0.16, reclaim_started.set)

    with pytest.raises(ControlPlaneLeaseLost, match="local lease deadline"):
        await asyncio.wait_for(daemon.run_once(), timeout=1)

    await asyncio.wait_for(executor.stopped.wait(), timeout=0.25)
    effects_at_reclaim = executor.side_effects
    # A replacement owner could be reclaimed now; the stale owner must remain
    # quiescent instead of emitting overlapping external effects.
    await asyncio.sleep(0.08)
    assert executor.side_effects == effects_at_reclaim
    assert reclaim_started.is_set()
    assert executor.overlap_side_effects == 0
    assert control.completed == []
    assert control.failed == []


@pytest.mark.asyncio
async def test_local_lease_deadline_cancels_stalled_completion() -> None:
    server_now = datetime.now(UTC)
    short_lease_job = _job().model_copy(
        update={
            "heartbeat_at": server_now,
            "updated_at": server_now,
            "lease_expires_at": server_now + timedelta(seconds=0.15),
        }
    )
    control = FakeControlPlane(ClaimedJob(job=short_lease_job, lease_token="l" * 43))
    control.heartbeat_gate = asyncio.Event()
    control.completion_gate = asyncio.Event()
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor(delay=0)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            cancellation_grace_seconds=0.05,
            cancellation_force_seconds=0.25,
        ),
    )

    daemon_task = asyncio.create_task(daemon.run_once())
    await asyncio.wait_for(control.completion_started.wait(), timeout=0.5)
    with pytest.raises(ControlPlaneLeaseLost, match="local lease deadline"):
        await asyncio.wait_for(daemon_task, timeout=1)

    assert control.completed == []
    assert control.failed == []


@pytest.mark.asyncio
async def test_heartbeat_lease_loss_cancels_inflight_execution(tmp_path: Path) -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    control.lose_lease = True
    executor = DelayedExecutor(delay=10)
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            status_path=status_path,
        ),
    )

    with pytest.raises(ControlPlaneLeaseLost, match="lease expired"):
        await daemon.run_once()

    assert executor.cancelled is True
    assert not control.completed
    assert not control.failed
    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.state == "lease-lost"
    assert status.active_job_id is None
    assert status.last_cancellation is not None
    assert status.last_cancellation.kind is CancellationKind.LEASE_LOST
    assert status.last_cancellation.cleanup_status is CancellationCleanupStatus.EXECUTOR_DRAINED
    assert status.last_cancellation.forced_at is None
    assert "l" * 43 not in status_path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_cancelled_run_maps_to_typed_worker_context(tmp_path: Path) -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    control.run_cancelled = True
    executor = DelayedExecutor(delay=10)
    control.heartbeat_gate = executor.started
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            status_path=status_path,
        ),
    )

    with pytest.raises(ControlPlaneRunCancelled):
        await asyncio.wait_for(daemon.run_once(), timeout=1)

    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.last_cancellation is not None
    assert status.last_cancellation.kind is CancellationKind.RUN_CANCELLED
    assert status.last_cancellation.reason == "run has been cancelled"


@pytest.mark.asyncio
async def test_control_plane_fence_seals_engine_cleanup_and_quiescence(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/multi-agent-cancel.yaml"))
    claimed = ClaimedJob(
        job=_job(payload={"input": {"manifest": campaign.model_dump(mode="json", by_alias=True)}}),
        lease_token="l" * 43,
    )
    control = FakeControlPlane(claimed)
    control.lose_lease = True
    worker = BlockingCampaignWorker()
    control.heartbeat_gate = worker.started
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([CampaignJobExecutor(output_root=tmp_path, worker=worker)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            cancellation_grace_seconds=1,
        ),
    )

    with pytest.raises(ControlPlaneLeaseLost, match="lease expired"):
        await asyncio.wait_for(daemon.run_once(), timeout=2)

    assert worker.cancelled
    run_path = next((tmp_path / campaign.metadata.name).glob("run_*"))
    cancellation = (run_path / "cancellation.json").read_text(encoding="utf-8")
    quiescence = (run_path / "quiescence.json").read_text(encoding="utf-8")
    assert '"cleanupStatus": "cleanup-completed"' in cancellation
    assert '"cleanupStatus": "quiesced"' in quiescence
    assert '"controlPlaneAttested": false' in quiescence
    assert verify_run_integrity(run_path).seal_count == 2
    assert not control.completed
    assert not control.failed


@pytest.mark.asyncio
async def test_lease_loss_forces_context_ignoring_executor_after_grace(
    tmp_path: Path,
) -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    control.lose_lease = True
    executor = ContextIgnoringExecutor()
    control.heartbeat_gate = executor.started
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            cancellation_grace_seconds=0.05,
            cancellation_force_seconds=0.5,
            status_path=status_path,
        ),
    )

    with pytest.raises(ControlPlaneLeaseLost, match="lease expired"):
        await asyncio.wait_for(daemon.run_once(), timeout=1)

    assert executor.forced_cancelled
    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.last_cancellation is not None
    assert status.last_cancellation.forced_at is not None
    assert status.last_cancellation.cleanup_status is CancellationCleanupStatus.EXECUTOR_DRAINED


@pytest.mark.asyncio
async def test_stop_signal_cooperatively_drains_active_execution(
    tmp_path: Path,
) -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    executor = DelayedExecutor(delay=10)
    stop = asyncio.Event()
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.5,
            long_poll_seconds=0,
            status_path=status_path,
        ),
    )
    daemon_task = asyncio.create_task(daemon.run_forever(stop))
    await asyncio.wait_for(executor.started.wait(), timeout=1)

    stop.set()
    await asyncio.wait_for(daemon_task, timeout=1)

    assert executor.cancelled
    assert not control.completed
    assert not control.failed
    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.state == "stopped"
    assert status.last_cancellation is not None
    assert status.last_cancellation.kind is CancellationKind.DAEMON_SHUTDOWN
    assert status.last_cancellation.cleanup_status is CancellationCleanupStatus.EXECUTOR_DRAINED


@pytest.mark.asyncio
async def test_stop_signal_bounds_a_cancellation_resistant_claim(
    tmp_path: Path,
) -> None:
    control = CancellationResistantClaimControlPlane(ClaimedJob(job=_job(), lease_token="l" * 43))
    stop = asyncio.Event()
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor(delay=0)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.5,
            long_poll_seconds=0,
            cancellation_grace_seconds=0.05,
            cancellation_force_seconds=0.1,
            status_path=status_path,
        ),
    )
    daemon_task = asyncio.create_task(daemon.run_forever(stop))
    await asyncio.wait_for(control.claim_started.wait(), timeout=0.5)

    stop.set()
    try:
        with pytest.raises(WorkerQuiescenceError, match="claim cycle did not stop"):
            await asyncio.wait_for(daemon_task, timeout=0.5)
    finally:
        control.release_claim.set()
        await asyncio.wait_for(control.claim_finished.wait(), timeout=0.5)

    assert control.cancellation_count >= 1
    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.state == "fatal"


@pytest.mark.asyncio
async def test_claim_cleanup_bounds_a_cancellation_resistant_heartbeat(
    tmp_path: Path,
) -> None:
    control = CancellationResistantHeartbeatControlPlane(
        ClaimedJob(job=_job(), lease_token="l" * 43)
    )
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor(delay=0.01)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.5,
            long_poll_seconds=0,
            cancellation_grace_seconds=0.05,
            cancellation_force_seconds=0.1,
            status_path=status_path,
        ),
    )
    daemon_task = asyncio.create_task(daemon.run_once())
    await asyncio.wait_for(control.heartbeat_started.wait(), timeout=0.5)

    try:
        with pytest.raises(WorkerQuiescenceError, match="claim tasks did not quiesce"):
            await asyncio.wait_for(daemon_task, timeout=0.5)
    finally:
        control.release_heartbeat.set()
        await asyncio.wait_for(control.heartbeat_finished.wait(), timeout=0.5)

    assert control.cancellation_count >= 1
    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.state == "fatal"


@pytest.mark.asyncio
async def test_repeated_cancellation_does_not_detach_owned_cleanup() -> None:
    config = WorkerDaemonConfig(
        worker_id="worker-test",
        kinds=[JobKind.CAMPAIGN],
        lease_seconds=5,
        heartbeat_seconds=0.5,
        long_poll_seconds=0,
        cancellation_grace_seconds=0.05,
        cancellation_force_seconds=0.5,
    )
    lifecycle = LeaseDaemonLifecycle(
        timing=config,
        owner="Worker",
        status=lambda _state, _error: None,
        record_cancellation=lambda _snapshot: None,
        quiescence_error=WorkerQuiescenceError,
    )
    started = asyncio.Event()
    cancellation_observed = asyncio.Event()
    release = asyncio.Event()

    async def cancellation_resistant_operation() -> None:
        started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            cancellation_observed.set()
            await release.wait()

    operation = asyncio.create_task(cancellation_resistant_operation())
    await started.wait()
    cleanup = asyncio.create_task(lifecycle.cancel_and_drain(operation, operation="test operation"))
    await cancellation_observed.wait()

    cleanup.cancel()
    await asyncio.sleep(0)
    assert not cleanup.done()
    assert not operation.done()

    release.set()
    with pytest.raises(asyncio.CancelledError):
        await cleanup
    assert operation.done()


@pytest.mark.asyncio
async def test_finalization_cancel_is_recorded_as_run_cancelled(tmp_path: Path) -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    control.cancel_completion = True
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([DelayedExecutor(delay=0)]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.5,
            long_poll_seconds=0,
            status_path=status_path,
        ),
    )

    with pytest.raises(ControlPlaneRunCancelled):
        await daemon.run_once()

    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.last_cancellation is not None
    assert status.last_cancellation.kind is CancellationKind.RUN_CANCELLED
    assert status.last_cancellation.cleanup_status is CancellationCleanupStatus.EXECUTOR_DRAINED


@pytest.mark.asyncio
async def test_protocol_failure_is_fatal_after_execution_cleanup(tmp_path: Path) -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    protocol_secret = "control-plane-protocol-secret-MUST-NOT-PERSIST"
    control.heartbeat_error = ControlPlaneProtocolError(protocol_secret)
    executor = DelayedExecutor(delay=10)
    control.heartbeat_gate = executor.started
    status_path = tmp_path / "status.json"
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
            status_path=status_path,
        ),
    )

    with pytest.raises(ControlPlaneProtocolError):
        await daemon.run_forever(asyncio.Event())

    status = WorkerDaemonStatus.model_validate_json(status_path.read_text(encoding="utf-8"))
    assert status.state == "fatal"
    assert status.last_cancellation is not None
    assert status.last_cancellation.kind is CancellationKind.HEARTBEAT_UNAVAILABLE
    status_payload = status_path.read_text(encoding="utf-8")
    assert protocol_secret not in status_payload
    assert protocol_secret not in status.last_cancellation.reason


@pytest.mark.asyncio
async def test_invalid_payload_is_permanently_failed() -> None:
    claimed = ClaimedJob(job=_job(payload={"input": {"command": "whoami"}}), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([CampaignJobExecutor(output_root=Path(".pajin/test"))]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    assert await daemon.run_once() is True
    assert len(control.failed) == 1
    assert control.failed[0].retryable is False
    assert "whoami" not in control.failed[0].error


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "executor",
    [UnsupportedOutcomeExecutor(), UnboundedCompletedResultExecutor()],
)
async def test_invalid_executor_outcome_is_permanently_failed(executor: Any) -> None:
    control = FakeControlPlane(ClaimedJob(job=_job(), lease_token="l" * 43))
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=[JobKind.CAMPAIGN],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    assert await daemon.run_once() is True
    assert control.completed == []
    assert len(control.failed) == 1
    assert control.failed[0].retryable is False


@pytest.mark.asyncio
async def test_campaign_executor_invokes_existing_local_runner_for_t0(tmp_path: Path) -> None:
    campaign = load_manifest(Path("examples/multi-agent-cancel.yaml"))
    target = campaign.spec.targets[0].model_copy(update={"simulation": {"seconds": 0.1}})
    campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"targets": [target]})}
    )
    executor = CampaignJobExecutor(output_root=tmp_path)
    job = _job(payload={"input": {"manifest": campaign.model_dump(mode="json", by_alias=True)}})

    result = await executor.execute(job)

    assert result.result["engine"] == "local-campaign"
    assert result.result["executionProfile"] == "deterministic-local"
    assert result.result["executionContext"]["backend"] == "simulated"
    assert result.result["executionContext"]["simulated"] is True
    assert result.result["executionContext"]["evidenceScope"] == "simulated-development-only"
    assert "development and unit tests only" in result.result["executionContext"]["warning"]
    assert result.result["toolCalls"] == 1
    assert result.result["validatedFindings"] == 0
    assert result.result["confirmedFindings"] == 0
    assert result.result["needsReviewCandidates"] == 0
    report_path = Path(str(result.result["reportPath"]))
    assert report_path.is_file()
    assert "Needs review: `0`" in report_path.read_text(encoding="utf-8")
    run_path = Path(str(result.result["runPath"]))
    execution_context = json.loads(
        (run_path / "execution-context.json").read_text(encoding="utf-8")
    )
    run_summary = json.loads((run_path / "run.json").read_text(encoding="utf-8"))
    assert result.result["executionContext"] == execution_context
    assert run_summary["executionContext"] == "execution-context.json"
    assert run_summary["workerBackend"] == execution_context["backend"]
    assert run_summary["simulated"] is execution_context["simulated"]
    assert run_summary["evidenceScope"] == execution_context["evidenceScope"]


@pytest.mark.asyncio
async def test_campaign_executor_rejects_legacy_t2_before_local_runner(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/ai-redteam.yaml"))
    executor = CampaignJobExecutor(output_root=tmp_path)
    job = _job(payload={"input": {"manifest": campaign.model_dump(mode="json", by_alias=True)}})

    with pytest.raises(PermanentExecutionError, match="approval-aware"):
        await executor.execute(job)

    assert not (tmp_path / campaign.metadata.name).exists()


@pytest.mark.asyncio
async def test_failed_campaign_tool_call_fails_control_plane_job(tmp_path: Path) -> None:
    campaign = load_manifest(Path("examples/multi-agent-cancel.yaml"))
    claimed = ClaimedJob(
        job=_job(payload={"input": {"manifest": campaign.model_dump(mode="json", by_alias=True)}}),
        lease_token="l" * 43,
    )
    control = FakeControlPlane(claimed)
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry(
            [
                CampaignJobExecutor(
                    output_root=tmp_path,
                    worker=FailedCampaignWorker(),
                )
            ]
        ),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    assert await daemon.run_once() is True

    assert not control.completed
    assert len(control.failed) == 1
    assert control.failed[0].retryable is False
    run_path = next((tmp_path / campaign.metadata.name).glob("run_*"))
    run_state = json.loads((run_path / "run.json").read_text(encoding="utf-8"))
    assert run_state["status"] == "failed"
    assert verify_run_integrity(run_path).valid


@pytest.mark.asyncio
async def test_tool_loop_executor_round_trips_control_plane_checkpoint(tmp_path: Path) -> None:
    campaign = load_manifest(Path("examples/tool-loop-approval-lab.yaml"))
    executor = ToolLoopJobExecutor(output_root=tmp_path)
    job_input = {
        "manifest": campaign.model_dump(mode="json", by_alias=True),
        "prompt": "Request the approval-gated mock probe exactly once.",
    }
    first = await executor.execute(_job(kind="tool-loop", payload={"input": job_input}))
    assert isinstance(first, ApprovalCheckpointExecution)

    now = datetime.now(UTC)
    continuation = _job(
        kind="tool-loop",
        job_id="job_22222222222222222222222222222222",
        payload={
            "resumeFromCheckpointId": "checkpoint_" + "2" * 32,
            "state": first.state,
            "approvalId": "approval_" + "2" * 32,
            "approval": {
                "callFingerprint": first.pending_intent.call_fingerprint,
                "toolId": first.pending_intent.tool_id,
                "target": first.pending_intent.target,
                "riskTier": int(first.pending_intent.risk_tier),
                "approvedBy": "security-owner",
                "approvedAt": now.isoformat(),
                "expiresAt": first.pending_intent.expires_at.isoformat(),
            },
        },
    )
    completed = await executor.execute(continuation)

    assert isinstance(completed, CompletedExecution)
    assert completed.result["engine"] == "policy-tool-loop"
    assert completed.result["executionProfile"] == "deterministic-approval-lab"
    assert completed.result["executionContext"]["backend"] == "simulated"
    assert completed.result["executionContext"]["simulated"] is True
    assert completed.result["executionContext"]["evidenceScope"] == "simulated-development-only"
    assert completed.result["toolCalls"] == 1
    assert completed.result["finalContent"] == (
        "Authorized specialist result was received and summarized."
    )
    run_path = Path(str(completed.result["runPath"]))
    execution_context = json.loads(
        (run_path / "execution-context.json").read_text(encoding="utf-8")
    )
    run_summary = json.loads((run_path / "run.json").read_text(encoding="utf-8"))
    assert completed.result["executionContext"] == execution_context
    assert run_summary["executionContext"] == "execution-context.json"
    assert run_summary["workerBackend"] == execution_context["backend"]
    assert run_summary["simulated"] is execution_context["simulated"]
    assert run_summary["evidenceScope"] == execution_context["evidenceScope"]


@pytest.mark.asyncio
async def test_tool_loop_executor_binds_checkpoint_to_exact_sealed_terminal_run(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/tool-loop-approval-lab.yaml"))
    executor = ToolLoopJobExecutor(output_root=tmp_path)
    job_input = executor_module.ToolLoopJobInput(
        manifest=campaign,
        prompt="Request the approval-gated mock probe exactly once.",
    )
    outcome = await executor._deterministic_runner(campaign).run(
        campaign,
        prompt=job_input.prompt,
    )

    translated = executor._translate_outcome(outcome, job_input=job_input)
    assert isinstance(translated, ApprovalCheckpointExecution)

    outside = tmp_path / "foreign-checkpoint.json"
    outside.write_bytes(outcome.checkpoint_path.read_bytes())
    with pytest.raises(PermanentExecutionError, match="exact sealed Run artifact"):
        executor._translate_outcome(
            outcome.model_copy(update={"checkpoint_path": outside}),
            job_input=job_input,
        )

    earlier_checkpoint = next(
        path
        for path in sorted((outcome.run_path / "checkpoints").glob("*.json"))
        if path != outcome.checkpoint_path
    )
    with pytest.raises(PermanentExecutionError, match="terminal Run outcome"):
        executor._translate_outcome(
            outcome.model_copy(update={"checkpoint_path": earlier_checkpoint}),
            job_input=job_input,
        )

    outcome.checkpoint_path.write_text("{}", encoding="utf-8")
    with pytest.raises(PermanentExecutionError, match="exact sealed Run artifact"):
        executor._translate_outcome(outcome, job_input=job_input)


@pytest.mark.asyncio
async def test_async_client_reuses_bearer_auth_and_classifies_stale_lease() -> None:
    seen_authorization: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers["Authorization"])
        if request.url.path.endswith("/claim"):
            return httpx.Response(204)
        return httpx.Response(409, json={"detail": "job lease has expired"})

    token = "worker-client-token-00000000000000000001"
    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token=token,
        transport=httpx.MockTransport(handler),
    ) as client:
        assert (
            await client.claim(
                ClaimJobRequest(
                    worker_id="worker-client",
                    kinds=["campaign"],
                    lease_seconds=30,
                )
            )
            is None
        )
        with pytest.raises(ControlPlaneLeaseLost, match="expired"):
            await client.heartbeat(
                "job_" + "1" * 32,
                LeaseRequest(
                    worker_id="worker-client",
                    lease_token="l" * 43,
                    lease_seconds=30,
                ),
            )

    assert seen_authorization == [f"Bearer {token}", f"Bearer {token}"]


@pytest.mark.parametrize(
    ("base_url", "allow_plaintext_lab", "message"),
    [
        ("http://control-plane:8090", False, "HTTPS"),
        ("http://api.example.invalid", False, "HTTPS"),
        ("http://api.example.invalid", True, "local lab"),
        ("http://192.168.1.20:8090", True, "local lab"),
        ("http://localhost.example.invalid:8090", True, "local lab"),
        ("http://control-plane.:8090", True, "local lab"),
        ("http://control-plane.example.invalid:8090", True, "local lab"),
        ("https://worker:secret@control-plane.invalid", False, "credentials"),
        ("https://control-plane.invalid?token=secret", False, "query"),
        ("https://control-plane.invalid?", False, "query"),
        ("https://control-plane.invalid#fragment", False, "fragment"),
        ("https://control-plane.invalid#", False, "fragment"),
        ("https://control-plane.invalid/v1", False, "origin"),
        ("https://control-plane.invalid\\@attacker.invalid", False, "invalid"),
        ("https://control-plane.invalid:", False, "authority"),
        ("ftp://control-plane.invalid", False, "HTTPS"),
        ("https:///missing-authority", False, "authority"),
    ],
)
def test_control_plane_client_rejects_unsafe_bearer_origins(
    base_url: str,
    allow_plaintext_lab: bool,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        ControlPlaneClient(
            base_url=base_url,
            bearer_token="worker-client-token-00000000000000000001",
            allow_plaintext_http_for_lab=allow_plaintext_lab,
            transport=httpx.MockTransport(lambda _request: httpx.Response(204)),
        )


@pytest.mark.parametrize(
    "token",
    [
        "x" * 31,
        "x" * 31 + "\n",
        "x" * 31 + "\r",
        "x" * 31 + "\t",
        "x" * 31 + " ",
        "x" * 31 + "é",
        "x" * 4_097,
    ],
    ids=["short", "newline", "carriage-return", "tab", "space", "non-ascii", "oversize"],
)
def test_control_plane_client_rejects_unsafe_bearer_tokens(token: str) -> None:
    with pytest.raises(ValueError, match="Worker bearer token"):
        ControlPlaneClient(
            base_url="https://control-plane.invalid",
            bearer_token=token,
            transport=httpx.MockTransport(lambda _request: httpx.Response(204)),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1:8090",
        "http://[::1]:8090/",
        "http://control-plane:8090",
    ],
)
async def test_control_plane_client_allows_explicit_local_lab_plaintext(base_url: str) -> None:
    seen_authorization: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        seen_authorization.append(request.headers["Authorization"])
        return httpx.Response(204)

    token = "worker-client-token-00000000000000000001"
    async with ControlPlaneClient(
        base_url=base_url,
        bearer_token=token,
        allow_plaintext_http_for_lab=True,
        transport=httpx.MockTransport(handler),
    ) as client:
        assert (
            await client.claim(
                ClaimJobRequest(
                    worker_id="worker-client",
                    kinds=["campaign"],
                    lease_seconds=30,
                )
            )
            is None
        )

    assert seen_authorization == [f"Bearer {token}"]


@pytest.mark.parametrize("entrypoint", [worker_main_module, replay_worker_main_module])
def test_worker_plaintext_lab_opt_in_is_strict(
    monkeypatch: pytest.MonkeyPatch,
    entrypoint: object,
) -> None:
    name = "PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB"
    monkeypatch.delenv(name, raising=False)
    assert entrypoint._plaintext_http_for_lab_enabled() is False  # type: ignore[attr-defined]

    monkeypatch.setenv(name, "true")
    assert entrypoint._plaintext_http_for_lab_enabled() is True  # type: ignore[attr-defined]

    for invalid in ("1", "TRUE", " true ", "yes"):
        monkeypatch.setenv(name, invalid)
        with pytest.raises(RuntimeError, match=name):
            entrypoint._plaintext_http_for_lab_enabled()  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_async_client_classifies_cancelled_run_as_specialized_lease_loss() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            409,
            json={
                "detail": "run has been cancelled",
                "code": ControlPlaneConflictCode.RUN_CANCELLED.value,
            },
        )

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token="worker-client-token-00000000000000000001",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(ControlPlaneRunCancelled, match="run has been cancelled") as caught:
            await client.heartbeat(
                "job_" + "1" * 32,
                LeaseRequest(
                    worker_id="worker-client",
                    lease_token="l" * 43,
                    lease_seconds=30,
                ),
            )

    assert isinstance(caught.value, ControlPlaneLeaseLost)


@pytest.mark.asyncio
async def test_async_client_rejects_malformed_success_response() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected": "payload"})

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token="worker-client-token-00000000000000000001",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(ControlPlaneProtocolError, match="invalid JobView"):
            await client.heartbeat(
                "job_" + "1" * 32,
                LeaseRequest(
                    worker_id="worker-client",
                    lease_token="l" * 43,
                    lease_seconds=30,
                ),
            )


@pytest.mark.asyncio
async def test_async_client_bounds_streamed_response_and_closes_connection() -> None:
    class OversizedResponseStream(httpx.AsyncByteStream):
        def __init__(self) -> None:
            self.yielded = 0
            self.closed = False
            self.chunk = b"x" * (1024 * 1024)

        async def __aiter__(self):
            for _ in range(20):
                self.yielded += 1
                yield self.chunk

        async def aclose(self) -> None:
            self.closed = True

    stream = OversizedResponseStream()

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=stream)

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token="worker-client-token-00000000000000000001",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(ControlPlaneProtocolError, match="byte limit"):
            await client.heartbeat(
                "job_" + "1" * 32,
                LeaseRequest(
                    worker_id="worker-client",
                    lease_token="l" * 43,
                    lease_seconds=30,
                ),
            )

    assert stream.yielded == 9
    assert stream.closed is True


@pytest.mark.asyncio
async def test_async_client_classifies_remote_protocol_failure_as_transient() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.RemoteProtocolError(
            "peer closed the connection before sending a complete response",
            request=request,
        )

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token="worker-client-token-00000000000000000001",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(ControlPlaneTransientError, match="Control Plane transport failed"):
            await client.claim(
                ClaimJobRequest(
                    worker_id="worker-client",
                    kinds=["campaign"],
                    lease_seconds=30,
                )
            )


@pytest.mark.asyncio
async def test_async_client_uses_dedicated_typed_replay_transport() -> None:
    permit = _replay_tool_permit()
    seen: list[tuple[str, dict[str, object], str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert isinstance(body, dict)
        seen.append((request.url.path, body, request.headers["Authorization"]))
        if request.url.path.endswith("/claim"):
            return httpx.Response(204)
        if request.url.path.endswith("/heartbeat"):
            return httpx.Response(
                409,
                json={
                    "detail": "Replay job lease has expired",
                    "code": ControlPlaneConflictCode.LEASE_LOST.value,
                },
            )
        return httpx.Response(200, json=permit.model_dump(mode="json"))

    token = "worker-client-token-00000000000000000001"
    job_id = f"job_{'4' * 32}"
    ticket_id = f"replay-ticket_{'3' * 32}"
    lease_token = "lease-token-that-is-at-least-32-characters"
    claim = ReplayClaimRequest(
        executor_profile="kisa-exact-v1",
        lease_seconds=30,
    )
    lease = ReplayLeaseRequest(
        executor_profile="kisa-exact-v1",
        lease_token=lease_token,
        lease_seconds=30,
        ticket_id=ticket_id,
        fencing_value=7,
    )
    permit_request = ReplayToolPermitRequest(
        executor_profile="kisa-exact-v1",
        lease_token=lease_token,
        ticket_id=ticket_id,
        fencing_value=7,
        call_ordinal=1,
    )

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token=token,
        transport=httpx.MockTransport(handler),
    ) as client:
        assert await client.claim_replay(claim) is None
        with pytest.raises(ControlPlaneLeaseLost, match="expired"):
            await client.heartbeat_replay(job_id, lease)
        issued = await client.issue_replay_tool_permit(job_id, permit_request)

    assert issued == permit
    assert seen == [
        (
            "/v1/worker/replay/jobs/claim",
            claim.model_dump(mode="json"),
            f"Bearer {token}",
        ),
        (
            f"/v1/worker/replay/jobs/{job_id}/heartbeat",
            lease.model_dump(mode="json"),
            f"Bearer {token}",
        ),
        (
            f"/v1/worker/replay/jobs/{job_id}/tool-permits",
            permit_request.model_dump(mode="json"),
            f"Bearer {token}",
        ),
    ]


@pytest.mark.asyncio
async def test_async_client_rejects_replay_permit_response_with_bearer_material() -> None:
    permit = _replay_tool_permit().model_dump(mode="json")
    permit["lease_token"] = "must-not-be-returned"

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=permit)

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token="worker-client-token-00000000000000000001",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(ControlPlaneProtocolError, match="invalid ReplayToolPermitView"):
            await client.issue_replay_tool_permit(
                f"job_{'4' * 32}",
                ReplayToolPermitRequest(
                    executor_profile="kisa-exact-v1",
                    lease_token="lease-token-that-is-at-least-32-characters",
                    ticket_id=f"replay-ticket_{'3' * 32}",
                    fencing_value=7,
                    call_ordinal=1,
                ),
            )


@pytest.mark.asyncio
async def test_async_client_treats_replay_executor_rejection_as_fatal_authz() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            403,
            json={
                "detail": (
                    "authenticated Worker principal is not registered for this Replay executor"
                )
            },
        )

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token="worker-client-token-00000000000000000001",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(ControlPlaneAuthenticationError):
            await client.claim_replay(
                ReplayClaimRequest(
                    executor_profile="unregistered-profile",
                    lease_seconds=30,
                )
            )
