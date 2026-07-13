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
    JobKind,
    JobState,
    JobView,
    LeaseRequest,
)
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig, WorkerDaemonStatus
from pajin.domain.manifest import load_manifest


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

    async def claim(self, _request: Any) -> ClaimedJob | None:
        claimed, self.claimed = self.claimed, None
        return claimed

    async def heartbeat(self, _job_id: str, _request: Any) -> JobView:
        self.heartbeats += 1
        if self.lose_lease:
            raise ControlPlaneLeaseLost("test lease expired")
        return _job()

    async def complete(self, _job_id: str, request: Any) -> JobView:
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

    async def execute(self, _job: JobView) -> CompletedExecution:
        try:
            await asyncio.sleep(self.delay)
        except asyncio.CancelledError:
            self.cancelled = True
            raise
        return CompletedExecution(result={"ok": True})


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
async def test_heartbeat_lease_loss_cancels_inflight_execution() -> None:
    claimed = ClaimedJob(job=_job(), lease_token="l" * 43)
    control = FakeControlPlane(claimed)
    control.lose_lease = True
    executor = DelayedExecutor(delay=10)
    daemon = WorkerDaemon(
        client=control,
        executors=ExecutorRegistry([executor]),
        config=WorkerDaemonConfig(
            worker_id="worker-test",
            kinds=["campaign"],
            lease_seconds=5,
            heartbeat_seconds=0.05,
            long_poll_seconds=0,
        ),
    )

    with pytest.raises(ControlPlaneLeaseLost, match="lease expired"):
        await daemon.run_once()

    assert executor.cancelled is True
    assert not control.completed
    assert not control.failed


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
    assert result.result["validatedFindings"] == 1
    assert Path(str(result.result["reportPath"])).is_file()


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
