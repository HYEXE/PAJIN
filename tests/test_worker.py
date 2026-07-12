import asyncio

import pytest
from pydantic import ValidationError

from pajin.runtime.worker import (
    DockerWorkerBackend,
    EgressPolicy,
    NetworkMode,
    SimulatedWorkerBackend,
    WorkerJob,
    WorkerStatus,
)


def test_simulated_worker_executes_allowlisted_action() -> None:
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["mock-agent-probe"],
        stdin='{"target":"https://example.invalid","simulation":{"unauthorizedToolCall":true}}',
    )

    result = asyncio.run(SimulatedWorkerBackend().run(job))

    assert result.status is WorkerStatus.SUCCEEDED
    assert '"vulnerable": true' in result.stdout


def test_worker_job_rejects_image_argument_injection() -> None:
    with pytest.raises(ValidationError):
        WorkerJob(image="pajin-worker:dev --privileged", command=["mock-agent-probe"])


def test_worker_job_requires_explicit_egress_policy_contract() -> None:
    with pytest.raises(ValidationError):
        WorkerJob(
            image="pajin-worker:dev",
            command=["http-get"],
            network=NetworkMode.EGRESS_PROXY,
        )

    with pytest.raises(ValidationError):
        WorkerJob(
            image="pajin-worker:dev",
            command=["http-get"],
            egress_policy=EgressPolicy(allow=["https://example.com/**"]),
        )


def test_docker_backend_builds_fail_closed_security_profile() -> None:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    job = WorkerJob(image="pajin-worker:dev", command=["mock-agent-probe"])

    args = backend._docker_args(job, "pajin-test")

    assert args[:5] == ["run", "--rm", "--interactive", "--pull", "never"]
    assert args[args.index("--network") : args.index("--network") + 2] == [
        "--network",
        "none",
    ]
    assert "--read-only" in args
    assert args[args.index("--cap-drop") : args.index("--cap-drop") + 2] == ["--cap-drop", "ALL"]
    assert args[args.index("--security-opt") : args.index("--security-opt") + 2] == [
        "--security-opt",
        "no-new-privileges",
    ]
    assert "--pids-limit" in args
    assert "--memory" in args
    assert "--cpus" in args
    assert any("/workspace:" in arg and "mode=1777" in arg for arg in args)
    assert args[-2:] == ["pajin-worker:dev", "mock-agent-probe"]


def test_docker_backend_routes_network_job_only_to_internal_proxy() -> None:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["http-get"],
        network=NetworkMode.EGRESS_PROXY,
        egress_policy=EgressPolicy(allow=["https://example.com/**"]),
    )

    args = backend._docker_args(job, "pajin-test", network_name="pajin-egress-test")

    assert args[args.index("--network") : args.index("--network") + 2] == [
        "--network",
        "pajin-egress-test",
    ]
    assert "HTTP_PROXY=http://egress-proxy:8080" in args
    assert "HTTPS_PROXY=http://egress-proxy:8080" in args
    assert "bridge" not in args


def test_docker_backend_rejects_non_allowlisted_image_without_starting_process() -> None:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    job = WorkerJob(image="untrusted-worker:latest", command=["mock-agent-probe"])

    result = asyncio.run(backend.run(job))

    assert result.status is WorkerStatus.REJECTED
    assert result.exit_code is None


def test_bounded_reader_discards_excess_output() -> None:
    async def read_output() -> tuple[bytes, bool]:
        reader = asyncio.StreamReader()
        reader.feed_data(b"a" * 20)
        reader.feed_eof()
        return await DockerWorkerBackend._read_bounded(reader, 8)

    output, truncated = asyncio.run(read_output())

    assert output == b"a" * 8
    assert truncated
