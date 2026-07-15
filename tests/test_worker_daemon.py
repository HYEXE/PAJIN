from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest

from pajin.control_plane.client import (
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
    ToolLoopJobExecutor,
)
from pajin.control_plane.models import (
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
)
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig, WorkerDaemonStatus
from pajin.domain.manifest import load_manifest
from pajin.runtime.control import (
    CancellationCleanupStatus,
    CancellationKind,
    ExecutionCancellationContext,
)
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import verify_run_integrity
from pajin.runtime.worker import WorkerJob, WorkerResult


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


class FakeControlPlane:
    def __init__(self, claimed: ClaimedJob) -> None:
        self.claimed: ClaimedJob | None = claimed
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
        return _job()

    async def complete(self, _job_id: str, request: Any) -> JobView:
        if self.cancel_completion:
            raise ControlPlaneRunCancelled("run has been cancelled")
        if self.transient_completions:
            self.transient_completions -= 1
            raise ControlPlaneTransientError("temporary completion failure")
        self.completed.append(request)
        return _job()

    async def fail(self, _job_id: str, request: Any) -> JobView:
        self.failed.append(request)
        return _job()

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


def test_executor_registry_rejects_adapter_without_cancellation_contract() -> None:
    with pytest.raises(ValueError, match="cancellation context"):
        ExecutorRegistry([LegacyExecutor()])  # type: ignore[list-item]


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
    assert (
        status.last_cancellation.cleanup_status
        is CancellationCleanupStatus.EXECUTOR_DRAINED
    )
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
    campaign = load_manifest(Path("examples/ai-redteam.yaml"))
    claimed = ClaimedJob(
        job=_job(
            payload={
                "input": {"manifest": campaign.model_dump(mode="json", by_alias=True)}
            }
        ),
        lease_token="l" * 43,
    )
    control = FakeControlPlane(claimed)
    control.lose_lease = True
    worker = BlockingCampaignWorker()
    control.heartbeat_gate = worker.started
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry(
            [CampaignJobExecutor(output_root=tmp_path, worker=worker)]
        ),
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
    cancellation = (
        run_path / "cancellation.json"
    ).read_text(encoding="utf-8")
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
    assert (
        status.last_cancellation.cleanup_status
        is CancellationCleanupStatus.EXECUTOR_DRAINED
    )


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
    assert (
        status.last_cancellation.cleanup_status
        is CancellationCleanupStatus.EXECUTOR_DRAINED
    )


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
    assert (
        status.last_cancellation.cleanup_status
        is CancellationCleanupStatus.EXECUTOR_DRAINED
    )


@pytest.mark.asyncio
async def test_protocol_failure_is_fatal_after_execution_cleanup(tmp_path: Path) -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    control.heartbeat_error = ControlPlaneProtocolError("invalid heartbeat response")
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
async def test_campaign_executor_invokes_existing_local_runner(tmp_path: Path) -> None:
    campaign = load_manifest(Path("examples/ai-redteam.yaml"))
    executor = CampaignJobExecutor(output_root=tmp_path)
    job = _job(payload={"input": {"manifest": campaign.model_dump(mode="json", by_alias=True)}})

    result = await executor.execute(job)

    assert result.result["engine"] == "local-campaign"
    assert result.result["toolCalls"] == 1
    assert result.result["validatedFindings"] == 0
    assert result.result["confirmedFindings"] == 0
    assert result.result["needsReviewCandidates"] == 1
    report_path = Path(str(result.result["reportPath"]))
    assert report_path.is_file()
    assert "Needs review: `1`" in report_path.read_text(encoding="utf-8")


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
    assert completed.result["toolCalls"] == 1
    assert completed.result["finalContent"] == (
        "Authorized specialist result was received and summarized."
    )


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
