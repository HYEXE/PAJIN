"""Entrypoint for the PAJIN Control Plane Worker daemon."""

from __future__ import annotations

import asyncio
import os
import signal
import socket
from pathlib import Path

from pajin.control_plane.client import ControlPlaneClient
from pajin.control_plane.executors import (
    CampaignJobExecutor,
    ExecutorRegistry,
    ToolLoopJobExecutor,
)
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig


def _required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required Worker daemon setting: {name}")
    return value


async def run_from_env() -> None:
    output_root = Path(os.environ.get("PAJIN_DAEMON_OUTPUT_ROOT", ".pajin/daemon-runs")).resolve()
    executors = ExecutorRegistry(
        [
            CampaignJobExecutor(output_root=output_root),
            ToolLoopJobExecutor(output_root=output_root),
        ]
    )
    raw_kinds = os.environ.get("PAJIN_DAEMON_KINDS", "campaign,tool-loop")
    kinds = [item.strip() for item in raw_kinds.split(",") if item.strip()]
    config = WorkerDaemonConfig(
        worker_id=os.environ.get("PAJIN_WORKER_ID", f"worker-{socket.gethostname().lower()}"),
        kinds=kinds,
        lease_seconds=int(os.environ.get("PAJIN_DAEMON_LEASE_SECONDS", "15")),
        heartbeat_seconds=float(os.environ.get("PAJIN_DAEMON_HEARTBEAT_SECONDS", "5")),
        cancellation_grace_seconds=float(
            os.environ.get("PAJIN_DAEMON_CANCELLATION_GRACE_SECONDS", "2")
        ),
        cancellation_force_seconds=float(
            os.environ.get("PAJIN_DAEMON_CANCELLATION_FORCE_SECONDS", "5")
        ),
        long_poll_seconds=int(os.environ.get("PAJIN_DAEMON_LONG_POLL_SECONDS", "10")),
        status_path=Path(
            os.environ.get("PAJIN_DAEMON_STATUS_PATH", "/tmp/pajin-worker-status.json")
        ),
    )
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(selected_signal, stop.set)
        except (NotImplementedError, RuntimeError):
            signal.signal(
                selected_signal,
                lambda _signum, _frame: loop.call_soon_threadsafe(stop.set),
            )
    async with ControlPlaneClient(
        base_url=_required_env("PAJIN_CP_URL"),
        bearer_token=_required_env("PAJIN_CP_WORKER_TOKEN"),
    ) as client:
        daemon = WorkerDaemon(client=client, executors=executors, config=config)
        await daemon.run_forever(stop)


def main() -> None:
    asyncio.run(run_from_env())


if __name__ == "__main__":
    main()
