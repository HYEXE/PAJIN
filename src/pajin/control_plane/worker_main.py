"""Entrypoint for the PAJIN Control Plane Worker daemon."""

from __future__ import annotations

import asyncio
import os
import socket
from pathlib import Path

from pajin.control_plane.capability_deployment import (
    CapabilityGraphDeploymentRuntime,
    load_capability_graph_deployment,
)
from pajin.control_plane.client import ControlPlaneClient
from pajin.control_plane.daemon_runtime import (
    env,
    float_env,
    install_stop_event,
    integer_env,
    literal_bool_env,
    required_env,
)
from pajin.control_plane.executors import (
    CampaignJobExecutor,
    ExecutorRegistry,
    ToolLoopJobExecutor,
)
from pajin.control_plane.models import JobKind
from pajin.control_plane.status_file import default_worker_status_path
from pajin.control_plane.worker import WorkerDaemon, WorkerDaemonConfig

_PLAINTEXT_LAB_ENV = "PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB"
_CAPABILITY_DEPLOYMENT_PATH_ENV = "PAJIN_CAPABILITY_GRAPH_DEPLOYMENT_PATH"
_CAPABILITY_DEPLOYMENT_SHA256_ENV = "PAJIN_CAPABILITY_GRAPH_DEPLOYMENT_SHA256"


def _required_env(name: str) -> str:
    return required_env(name, owner="Worker daemon")


def _plaintext_http_for_lab_enabled() -> bool:
    return literal_bool_env(_PLAINTEXT_LAB_ENV, owner="Worker daemon")


def _capability_graph_deployment_from_env() -> CapabilityGraphDeploymentRuntime | None:
    raw_path = os.environ.get(_CAPABILITY_DEPLOYMENT_PATH_ENV)
    raw_digest = os.environ.get(_CAPABILITY_DEPLOYMENT_SHA256_ENV)
    if raw_path in {None, ""} and raw_digest in {None, ""}:
        return None
    if (
        raw_path is None
        or raw_digest is None
        or not raw_path
        or raw_path != raw_path.strip()
        or not raw_digest
        or raw_digest != raw_digest.strip()
    ):
        raise RuntimeError(
            "Worker daemon Capability Graph deployment path and SHA-256 must be configured together"
        )
    return load_capability_graph_deployment(
        Path(raw_path),
        expected_sha256=raw_digest,
    )


async def run_from_env() -> None:
    output_root = Path(
        env(
            "PAJIN_DAEMON_OUTPUT_ROOT",
            ".pajin/daemon-runs",
            owner="Worker daemon",
        )
    ).resolve()
    capability_deployment = _capability_graph_deployment_from_env()
    executors = ExecutorRegistry(
        [
            CampaignJobExecutor(
                output_root=output_root,
                capability_deployment=capability_deployment,
            ),
            ToolLoopJobExecutor(output_root=output_root),
        ]
    )
    raw_kinds = env(
        "PAJIN_DAEMON_KINDS",
        "campaign,tool-loop",
        owner="Worker daemon",
    )
    kinds = [JobKind(item.strip()) for item in raw_kinds.split(",") if item.strip()]
    config = WorkerDaemonConfig(
        worker_id=env(
            "PAJIN_WORKER_ID",
            f"worker-{socket.gethostname().lower()}",
            owner="Worker daemon",
        ),
        kinds=kinds,
        lease_seconds=integer_env(
            "PAJIN_DAEMON_LEASE_SECONDS",
            15,
            owner="Worker daemon",
        ),
        heartbeat_seconds=float_env(
            "PAJIN_DAEMON_HEARTBEAT_SECONDS",
            5,
            owner="Worker daemon",
        ),
        cancellation_grace_seconds=float_env(
            "PAJIN_DAEMON_CANCELLATION_GRACE_SECONDS",
            2,
            owner="Worker daemon",
        ),
        cancellation_force_seconds=float_env(
            "PAJIN_DAEMON_CANCELLATION_FORCE_SECONDS",
            5,
            owner="Worker daemon",
        ),
        long_poll_seconds=integer_env(
            "PAJIN_DAEMON_LONG_POLL_SECONDS",
            10,
            owner="Worker daemon",
        ),
        status_path=Path(
            env(
                "PAJIN_DAEMON_STATUS_PATH",
                str(default_worker_status_path()),
                owner="Worker daemon",
            )
        ),
    )
    stop = install_stop_event()
    async with ControlPlaneClient(
        base_url=_required_env("PAJIN_CP_URL"),
        bearer_token=_required_env("PAJIN_CP_WORKER_TOKEN"),
        allow_plaintext_http_for_lab=_plaintext_http_for_lab_enabled(),
        tls_ca_file=os.environ.get("PAJIN_CP_TLS_CA_FILE"),
        tls_client_cert_file=os.environ.get("PAJIN_CP_MTLS_CERT_FILE"),
        tls_client_key_file=os.environ.get("PAJIN_CP_MTLS_KEY_FILE"),
        tls_client_key_password=os.environ.get("PAJIN_CP_MTLS_KEY_PASSWORD"),
    ) as client:
        daemon = WorkerDaemon(client=client, executors=executors, config=config)
        await daemon.run_forever(stop)


def main() -> None:
    asyncio.run(run_from_env())


if __name__ == "__main__":
    main()
