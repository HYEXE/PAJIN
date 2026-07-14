import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from pajin.runtime.worker import (
    DockerWorkerBackend,
    EgressPolicy,
    NetworkMode,
    SimulatedWorkerBackend,
    WorkerJob,
    WorkerLimits,
    WorkerStatus,
)


class _FakeStdin:
    def write(self, data: bytes) -> None:
        self.data = data

    async def drain(self) -> None:
        await asyncio.sleep(0)

    def close(self) -> None:
        return


class _FailingStdin(_FakeStdin):
    def write(self, data: bytes) -> None:
        del data
        raise RuntimeError("stdin write failed")


class _BlockingReader:
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def read(self, size: int) -> bytes:
        del size
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise
        return b""


class _FakeProcess:
    def __init__(
        self,
        *,
        stdout: asyncio.StreamReader | _BlockingReader,
        stderr: asyncio.StreamReader | _BlockingReader,
    ) -> None:
        self.stdin = _FakeStdin()
        self.stdout = stdout
        self.stderr = stderr
        self.returncode: int | None = None
        self.waited = asyncio.Event()
        self.kill_count = 0

    async def wait(self) -> int:
        self.returncode = 0
        self.waited.set()
        return self.returncode

    def kill(self) -> None:
        self.kill_count += 1
        self.returncode = -9


def _completed_reader(payload: bytes = b"") -> asyncio.StreamReader:
    reader = asyncio.StreamReader()
    reader.feed_data(payload)
    reader.feed_eof()
    return reader


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


def test_docker_backend_cancellation_during_reader_forces_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(image="pajin-worker:dev", command=["mock-agent-probe"])
        stdout = _BlockingReader()
        process = _FakeProcess(stdout=stdout, stderr=_completed_reader())
        removed = asyncio.Event()

        async def create_process(*args: object, **kwargs: object) -> _FakeProcess:
            del args, kwargs
            return process

        async def force_remove(container_name: str) -> None:
            assert container_name.startswith("pajin-")
            removed.set()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_force_remove", force_remove)

        task = asyncio.create_task(backend.run(job))
        await stdout.started.wait()
        await process.waited.wait()
        await asyncio.sleep(0)
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert removed.is_set()
        assert stdout.cancelled.is_set()

    asyncio.run(scenario())


def test_docker_backend_cancellation_during_spawn_removes_by_known_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(image="pajin-worker:dev", command=["mock-agent-probe"])
        spawn_started = asyncio.Event()
        removed = asyncio.Event()

        async def create_process(*args: object, **kwargs: object) -> _FakeProcess:
            del args, kwargs
            spawn_started.set()
            await asyncio.Event().wait()
            raise AssertionError("subprocess spawn unexpectedly resumed")

        async def force_remove(container_name: str) -> None:
            assert container_name.startswith("pajin-")
            removed.set()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_force_remove", force_remove)
        task = asyncio.create_task(backend.run(job))
        await spawn_started.wait()
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert removed.is_set()

    asyncio.run(scenario())


def test_docker_backend_exception_after_spawn_kills_and_removes_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(image="pajin-worker:dev", command=["mock-agent-probe"])
        process = _FakeProcess(stdout=_completed_reader(), stderr=_completed_reader())
        process.stdin = _FailingStdin()
        removed = asyncio.Event()

        async def create_process(*args: object, **kwargs: object) -> _FakeProcess:
            del args, kwargs
            return process

        async def force_remove(container_name: str) -> None:
            assert container_name.startswith("pajin-")
            removed.set()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_force_remove", force_remove)

        with pytest.raises(RuntimeError, match="stdin write failed"):
            await backend.run(job)

        assert process.kill_count == 1
        assert removed.is_set()

    asyncio.run(scenario())


def test_docker_cli_cancellation_kills_and_drains_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BlockingCliProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.started = asyncio.Event()
            self.kill_count = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            self.started.set()
            await asyncio.Event().wait()
            raise AssertionError("Docker CLI communicate unexpectedly resumed")

        def kill(self) -> None:
            self.kill_count += 1
            self.returncode = -9

        async def wait(self) -> int:
            assert self.returncode is not None
            return self.returncode

    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        process = BlockingCliProcess()

        async def create_process(*args: object, **kwargs: object) -> BlockingCliProcess:
            del args, kwargs
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        task = asyncio.create_task(backend._run_cli(["inspect", "test"]))
        await process.started.wait()
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert process.kill_count == 1
        assert process.returncode == -9

    asyncio.run(scenario())


def test_docker_backend_repeated_cancellation_drains_log_and_egress_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(
            image="pajin-worker:dev",
            command=["http-get"],
            network=NetworkMode.EGRESS_PROXY,
            egress_policy=EgressPolicy(allow=["https://example.com/**"]),
        )
        process = _FakeProcess(
            stdout=_completed_reader(b"ok"),
            stderr=_completed_reader(),
        )
        runtime = SimpleNamespace(
            network_name="pajin-egress-test",
            proxy_name="pajin-proxy-test",
        )
        logs_started = asyncio.Event()
        cleanup_started = asyncio.Event()
        cleanup_release = asyncio.Event()
        cleanup_finished = asyncio.Event()
        removed = asyncio.Event()

        async def setup_egress(worker_job: WorkerJob) -> SimpleNamespace:
            assert worker_job is job
            return runtime

        async def create_process(*args: object, **kwargs: object) -> _FakeProcess:
            del args, kwargs
            return process

        async def read_proxy_logs(proxy_name: str, limit: int) -> str:
            assert proxy_name == runtime.proxy_name
            assert limit == job.limits.stderr_bytes
            logs_started.set()
            await asyncio.Event().wait()
            return ""

        async def force_remove(container_name: str) -> None:
            assert container_name.startswith("pajin-")
            removed.set()

        async def cleanup_egress(cleanup_runtime: object) -> None:
            assert cleanup_runtime is runtime
            cleanup_started.set()
            await cleanup_release.wait()
            cleanup_finished.set()

        monkeypatch.setattr(backend, "_setup_egress", setup_egress)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_read_proxy_logs", read_proxy_logs)
        monkeypatch.setattr(backend, "_force_remove", force_remove)
        monkeypatch.setattr(backend, "_cleanup_egress", cleanup_egress)

        task = asyncio.create_task(backend.run(job))
        await logs_started.wait()
        task.cancel()
        await cleanup_started.wait()
        task.cancel()
        await asyncio.sleep(0)

        assert not cleanup_finished.is_set()
        cleanup_release.set()
        with pytest.raises(asyncio.CancelledError):
            await task

        assert removed.is_set()
        assert cleanup_finished.is_set()

    asyncio.run(scenario())


def test_docker_backend_completed_process_preserves_success_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(image="pajin-worker:dev", command=["mock-agent-probe"])
        process = _FakeProcess(
            stdout=_completed_reader(b'{"vulnerable": false}'),
            stderr=_completed_reader(b"diagnostic"),
        )
        remove_count = 0

        async def create_process(*args: object, **kwargs: object) -> _FakeProcess:
            del args, kwargs
            return process

        async def force_remove(container_name: str) -> None:
            nonlocal remove_count
            del container_name
            remove_count += 1

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_force_remove", force_remove)

        result = await backend.run(job)

        assert result.status is WorkerStatus.SUCCEEDED
        assert result.exit_code == 0
        assert result.stdout == '{"vulnerable": false}'
        assert result.stderr == "diagnostic"
        assert remove_count == 0

    asyncio.run(scenario())


def test_docker_backend_timeout_preserves_timed_out_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TimeoutProcess(_FakeProcess):
        async def wait(self) -> int:
            if self.returncode is None:
                await asyncio.Event().wait()
            assert self.returncode is not None
            return self.returncode

    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(
            image="pajin-worker:dev",
            command=["mock-agent-probe"],
            limits=WorkerLimits(timeout_seconds=0.1),
        )
        process = TimeoutProcess(
            stdout=_completed_reader(),
            stderr=_completed_reader(),
        )
        remove_count = 0

        async def create_process(*args: object, **kwargs: object) -> TimeoutProcess:
            del args, kwargs
            return process

        async def force_remove(container_name: str) -> None:
            nonlocal remove_count
            assert container_name.startswith("pajin-")
            remove_count += 1

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_force_remove", force_remove)

        result = await backend.run(job)

        assert result.status is WorkerStatus.TIMED_OUT
        assert result.exit_code == -9
        assert process.kill_count == 1
        assert remove_count >= 1

    asyncio.run(scenario())
