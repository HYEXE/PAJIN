"""Entrypoint for the dedicated PAJIN Control Plane Replay Worker."""

from __future__ import annotations

import asyncio
import socket
from pathlib import Path

from pajin.control_plane.client import ControlPlaneClient
from pajin.control_plane.daemon_runtime import (
    env,
    float_env,
    install_stop_event,
    integer_env,
    literal_bool_env,
    required_env,
)
from pajin.control_plane.models import KISA_EXACT_REPLAY_EXECUTOR_PROFILE
from pajin.control_plane.replay_executor import KISAExactReplayExecutor
from pajin.control_plane.replay_worker import ReplayWorkerConfig, ReplayWorkerDaemon
from pajin.control_plane.status_file import default_replay_worker_status_path
from pajin.runtime.worker import DockerWorkerBackend

_DOCKER_CLEANUP_BOUND_SECONDS = 20.0
_PLAINTEXT_LAB_ENV = "PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB"


def _required_env(name: str) -> str:
    return required_env(name, owner="Replay Worker")


def _env(name: str, default: str) -> str:
    return env(name, default, owner="Replay Worker")


def _integer_env(name: str, default: int) -> int:
    return integer_env(name, default, owner="Replay Worker")


def _float_env(name: str, default: float) -> float:
    return float_env(name, default, owner="Replay Worker")


def _plaintext_http_for_lab_enabled() -> bool:
    return literal_bool_env(_PLAINTEXT_LAB_ENV, owner="Replay Worker")


async def run_from_env() -> None:
    worker_image = _env("PAJIN_REPLAY_WORKER_IMAGE", "pajin-worker:dev")
    executor_profile = _env(
        "PAJIN_REPLAY_EXECUTOR_PROFILE",
        KISA_EXACT_REPLAY_EXECUTOR_PROFILE,
    )
    if executor_profile != KISA_EXACT_REPLAY_EXECUTOR_PROFILE:
        raise RuntimeError("unsupported PAJIN_REPLAY_EXECUTOR_PROFILE")
    config = ReplayWorkerConfig(
        worker_id=_env(
            "PAJIN_REPLAY_WORKER_ID",
            f"replay-worker-{socket.gethostname().lower()}",
        ),
        executor_profile=KISA_EXACT_REPLAY_EXECUTOR_PROFILE,
        lease_seconds=_integer_env("PAJIN_REPLAY_LEASE_SECONDS", 30),
        heartbeat_seconds=_float_env("PAJIN_REPLAY_HEARTBEAT_SECONDS", 5),
        long_poll_seconds=_integer_env("PAJIN_REPLAY_LONG_POLL_SECONDS", 10),
        idle_delay_seconds=_float_env("PAJIN_REPLAY_IDLE_DELAY_SECONDS", 0.2),
        retry_base_seconds=_float_env("PAJIN_REPLAY_RETRY_BASE_SECONDS", 0.25),
        retry_max_seconds=_float_env("PAJIN_REPLAY_RETRY_MAX_SECONDS", 5),
        finalize_attempts=_integer_env("PAJIN_REPLAY_FINALIZE_ATTEMPTS", 3),
        cancellation_grace_seconds=_float_env(
            "PAJIN_REPLAY_CANCELLATION_GRACE_SECONDS",
            2,
        ),
        cancellation_force_seconds=_float_env(
            "PAJIN_REPLAY_CANCELLATION_FORCE_SECONDS",
            25,
        ),
        status_path=Path(
            _env(
                "PAJIN_REPLAY_STATUS_PATH",
                str(default_replay_worker_status_path()),
            )
        ),
    )
    if config.cancellation_force_seconds <= _DOCKER_CLEANUP_BOUND_SECONDS:
        raise RuntimeError(
            "PAJIN_REPLAY_CANCELLATION_FORCE_SECONDS must exceed the Docker "
            "cleanup bound of 20 seconds"
        )

    backend = DockerWorkerBackend(
        allowed_images={worker_image},
        docker_executable=_env("PAJIN_REPLAY_DOCKER_EXECUTABLE", "docker"),
        egress_proxy_image=_env(
            "PAJIN_REPLAY_EGRESS_PROXY_IMAGE",
            "pajin-egress-proxy:dev",
        ),
        external_network=_env("PAJIN_REPLAY_EXTERNAL_NETWORK", "bridge"),
    )
    stop = install_stop_event()

    async with ControlPlaneClient(
        base_url=_required_env("PAJIN_CP_URL"),
        bearer_token=_required_env("PAJIN_CP_REPLAY_WORKER_TOKEN"),
        allow_plaintext_http_for_lab=_plaintext_http_for_lab_enabled(),
    ) as client:
        executor = KISAExactReplayExecutor(
            client=client,
            staging_root=Path(_required_env("PAJIN_REPLAY_STAGING_ROOT")),
            worker=backend,
            worker_image=worker_image,
            retry_base_seconds=config.retry_base_seconds,
            retry_max_seconds=config.retry_max_seconds,
        )
        daemon = ReplayWorkerDaemon(client=client, executor=executor, config=config)
        await daemon.run_forever(stop)


def main() -> None:
    asyncio.run(run_from_env())


if __name__ == "__main__":
    main()
