import asyncio
import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.worker import (
    DockerWorkerBackend,
    EgressPolicy,
    NetworkMode,
    SimulatedWorkerBackend,
    WorkerFailureCode,
    WorkerJob,
    WorkerLimits,
    WorkerResult,
    WorkerSecretRequest,
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


class _BrokenPipeStdin(_FakeStdin):
    async def drain(self) -> None:
        raise BrokenPipeError("container exited before reading stdin")


class _BlockingStdin(_FakeStdin):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()

    async def drain(self) -> None:
        self.started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            raise


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


@pytest.mark.parametrize("seconds", [-1, 31, "not-a-number", "1", True])
def test_simulated_worker_normalizes_invalid_sleep_input(seconds: object) -> None:
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["sleep-check"],
        stdin=json.dumps({"seconds": seconds}),
    )

    result = asyncio.run(SimulatedWorkerBackend().run(job))

    assert result.status is WorkerStatus.FAILED
    assert result.exit_code == 2
    assert result.stderr.startswith("invalid worker input:")


@pytest.mark.parametrize(
    "stdin",
    [
        '{"target":"https://example.invalid","simulation":{"unauthorizedToolCall":"false"}}',
        '{"target":"https://example.invalid","simulation":[]}',
        '{"target":"","simulation":{"unauthorizedToolCall":false}}',
    ],
)
def test_simulated_worker_matches_strict_mock_action_input_contract(stdin: str) -> None:
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["mock-agent-probe"],
        stdin=stdin,
    )

    result = asyncio.run(SimulatedWorkerBackend().run(job))

    assert result.status is WorkerStatus.FAILED
    assert result.exit_code == 2
    assert result.stderr.startswith("invalid worker input:")


def test_simulated_worker_does_not_reflect_invalid_input_in_diagnostic() -> None:
    secret = "simulated-worker-input-secret-MUST-NOT-PERSIST"
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["sleep-check"],
        stdin=json.dumps({"seconds": secret}),
    )

    result = asyncio.run(SimulatedWorkerBackend().run(job))

    assert result.status is WorkerStatus.FAILED
    assert secret not in result.stderr


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("execution_id", "../escape"),
        ("execution_id", "x" * 201),
        ("backend", "docker\nforged"),
        ("backend", "x" * 201),
    ],
)
def test_worker_result_rejects_unsafe_runtime_identifiers(field: str, value: str) -> None:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "execution_id": "exec_safe",
        "backend": "docker",
        "status": WorkerStatus.SUCCEEDED,
        "exit_code": 0,
        "started_at": now,
        "finished_at": now,
    }
    payload[field] = value

    with pytest.raises(ValidationError):
        WorkerResult.model_validate(payload)


@pytest.mark.parametrize("field", ["stdout", "stderr", "network_log"])
def test_worker_result_rejects_unbounded_transcript_fields(field: str) -> None:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "execution_id": "exec_safe",
        "backend": "docker",
        "status": WorkerStatus.SUCCEEDED,
        "exit_code": 0,
        "started_at": now,
        "finished_at": now,
        field: "x" * 10_000_001,
    }

    with pytest.raises(ValidationError):
        WorkerResult.model_validate(payload)


def test_worker_job_rejects_unsafe_execution_identifier() -> None:
    with pytest.raises(ValidationError):
        WorkerJob(
            execution_id="../escape",
            image="pajin-worker:dev",
            command=["mock-agent-probe"],
        )


@pytest.mark.parametrize(
    ("status", "exit_code"),
    [
        (WorkerStatus.SUCCEEDED, None),
        (WorkerStatus.SUCCEEDED, 1),
        (WorkerStatus.REJECTED, 1),
        (WorkerStatus.FAILED, 0),
        (WorkerStatus.TIMED_OUT, 0),
    ],
)
def test_worker_result_rejects_inconsistent_status_and_exit_code(
    status: WorkerStatus,
    exit_code: int | None,
) -> None:
    now = datetime.now(UTC)

    with pytest.raises(ValidationError):
        WorkerResult(
            execution_id="exec_safe",
            backend="docker",
            status=status,
            exit_code=exit_code,
            started_at=now,
            finished_at=now,
        )


@pytest.mark.parametrize(
    "status",
    [WorkerStatus.SUCCEEDED, WorkerStatus.TIMED_OUT, WorkerStatus.REJECTED],
)
def test_worker_result_rejects_failure_code_without_failed_status(
    status: WorkerStatus,
) -> None:
    now = datetime.now(UTC)
    exit_code = 0 if status is WorkerStatus.SUCCEEDED else None

    with pytest.raises(ValidationError, match="failure code requires failed status"):
        WorkerResult(
            execution_id="exec_safe",
            backend="configured-backend",
            status=status,
            failure_code=WorkerFailureCode.TARGET_UNAVAILABLE,
            exit_code=exit_code,
            started_at=now,
            finished_at=now,
        )


def test_worker_result_rejects_reversed_timestamps() -> None:
    now = datetime.now(UTC)

    with pytest.raises(ValidationError):
        WorkerResult(
            execution_id="exec_safe",
            backend="docker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            started_at=now,
            finished_at=now - timedelta(microseconds=1),
        )


def test_worker_job_rejects_image_argument_injection() -> None:
    with pytest.raises(ValidationError):
        WorkerJob(image="pajin-worker:dev --privileged", command=["mock-agent-probe"])


@pytest.mark.parametrize("stdin", ["한" * 400_000, "invalid-surrogate-\ud800"])
def test_worker_job_bounds_stdin_by_utf8_bytes(stdin: str) -> None:
    with pytest.raises(ValidationError):
        WorkerJob(
            image="pajin-worker:dev",
            command=["mock-agent-probe"],
            stdin=stdin,
        )


@pytest.mark.parametrize(
    "stdin",
    [
        '{"providerId":"first","providerId":"second"}',
        '{"temperature":NaN}',
        "[]",
    ],
)
def test_secret_bearing_worker_stdin_requires_one_strict_json_object(stdin: str) -> None:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["openai-chat-completion"],
        stdin=stdin,
        secret_requests=[
            WorkerSecretRequest(secret_ref="provider/test", binding="provider-api-key")
        ],
    )
    material = SecretMaterial(
        lease_id="lease_test",
        binding="provider-api-key",
        value="secret",
    )

    with pytest.raises(ValueError):
        backend._wire_stdin(job, [material])


def test_secret_bearing_worker_envelope_is_bounded_after_json_escaping() -> None:
    bindings = [f"provider-key-{index}" for index in range(4)]
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["openai-chat-completion"],
        stdin=json.dumps({"padding": "x" * 990_000}, separators=(",", ":")),
        secret_requests=[
            WorkerSecretRequest(secret_ref=f"provider/{index}", binding=binding)
            for index, binding in enumerate(bindings)
        ],
    )
    materials = [
        SecretMaterial(
            lease_id=f"lease_{index}",
            binding=binding,
            value="\\" * 16_384,
        )
        for index, binding in enumerate(bindings)
    ]

    with pytest.raises(ValueError, match="envelope exceeded"):
        backend._wire_stdin(job, materials)


def test_secret_bearing_worker_envelope_rejects_duplicate_supplied_bindings() -> None:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["openai-chat-completion"],
        stdin='{"providerId":"demo"}',
        secret_requests=[
            WorkerSecretRequest(secret_ref="provider/test", binding="provider-api-key")
        ],
    )
    materials = [
        SecretMaterial(
            lease_id=f"lease_{index}",
            binding="provider-api-key",
            value=f"secret-{index}",
        )
        for index in range(2)
    ]

    with pytest.raises(ValueError, match="bindings must be unique"):
        backend._wire_stdin(job, materials)


def test_secret_bearing_worker_envelope_is_deterministic_across_material_order() -> None:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["openai-chat-completion"],
        stdin='{"z":1,"a":2}',
        secret_requests=[
            WorkerSecretRequest(secret_ref="provider/a", binding="provider-key-a"),
            WorkerSecretRequest(secret_ref="provider/b", binding="provider-key-b"),
        ],
    )
    materials = [
        SecretMaterial(lease_id="lease_a", binding="provider-key-a", value="secret-a"),
        SecretMaterial(lease_id="lease_b", binding="provider-key-b", value="secret-b"),
    ]

    assert backend._wire_stdin(job, materials) == backend._wire_stdin(
        job,
        list(reversed(materials)),
    )


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


@pytest.mark.parametrize(
    "allowed_methods",
    ["GET", [], ["GET\rX-Injected: true"], [1]],
)
def test_egress_policy_rejects_ambiguous_method_collections(
    allowed_methods: object,
) -> None:
    with pytest.raises(ValidationError):
        EgressPolicy(
            allow=["https://example.com/**"],
            allowed_methods=allowed_methods,
        )


def test_egress_policy_bounds_responses_for_the_fixed_memory_proxy() -> None:
    policy = EgressPolicy(allow=["https://example.com/**"])

    assert policy.max_response_bytes == 8 * 1024 * 1024
    assert policy.model_dump(mode="json")["allowed_methods"] == ["GET", "HEAD", "POST"]
    with pytest.raises(ValidationError):
        EgressPolicy(
            allow=["https://example.com/**"],
            max_response_bytes=(8 * 1024 * 1024) + 1,
        )
    with pytest.raises(ValidationError):
        EgressPolicy(
            allow=["https://example.com/**", "https://example.com/**"],
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("allow_private_networks", "false"),
        ("allow_private_networks", 0),
        ("max_response_bytes", "1024"),
        ("max_response_bytes", True),
        ("max_requests", "1"),
        ("max_requests", False),
    ],
)
def test_egress_policy_rejects_coercible_primitive_types(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        EgressPolicy.model_validate({"allow": ["https://example.com/**"], field: value})


def test_docker_backend_builds_fail_closed_security_profile() -> None:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    job = WorkerJob(image="pajin-worker:dev", command=["mock-agent-probe"])

    args = backend._docker_args(job, "pajin-test")

    assert args[:6] == ["run", "--rm", "--interactive", "--init", "--pull", "never"]
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
    assert any(
        "/workspace:" in arg and "mode=0700" in arg and "uid=65532" in arg and "gid=65532" in arg
        for arg in args
    )
    assert "/tmp:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532,size=16m" in args
    assert args[-2:] == ["pajin-worker:dev", "mock-agent-probe"]


def test_docker_resource_names_keep_full_collision_resistant_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce = "0123456789abcdef0123456789abcdef"
    monkeypatch.setattr("pajin.runtime.worker.uuid4", lambda: SimpleNamespace(hex=nonce))

    container_name = DockerWorkerBackend._container_name("exec_test")

    assert container_name == f"pajin-exec_test-{nonce}"


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


@pytest.mark.parametrize("timeout_seconds", [0.1, 3_600])
def test_docker_backend_injects_canonical_proxy_deadline_without_mutating_policy(
    timeout_seconds: float,
) -> None:
    backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    policy = EgressPolicy(
        allow=["https://example.com/**"],
        allowed_methods={"POST", "GET"},
    )
    original = policy.model_dump(mode="json")
    job = WorkerJob(
        image="pajin-worker:dev",
        command=["http-get"],
        network=NetworkMode.EGRESS_PROXY,
        egress_policy=policy,
        limits=WorkerLimits(timeout_seconds=timeout_seconds),
    )

    encoded = backend._proxy_policy_json(job)
    payload = json.loads(encoded)

    assert payload == {
        **original,
        "max_exchange_seconds": timeout_seconds,
    }
    assert encoded == json.dumps(
        payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )
    assert policy.model_dump(mode="json") == original
    assert "max_exchange_seconds" not in policy.model_dump(mode="json")


@pytest.mark.parametrize(
    "configuration",
    [
        {"egress_proxy_image": "--privileged"},
        {"egress_proxy_image": "proxy image:latest"},
        {"external_network": "--network=host"},
        {"external_network": "bridge\nforged"},
    ],
)
def test_docker_backend_rejects_unsafe_runtime_resource_configuration(
    configuration: dict[str, str],
) -> None:
    with pytest.raises(ValueError):
        DockerWorkerBackend(
            allowed_images={"pajin-worker:dev"},
            **configuration,
        )

    with pytest.raises(ValueError):
        DockerWorkerBackend(allowed_images={"--privileged"})
    with pytest.raises(ValueError):
        DockerWorkerBackend(
            allowed_images={"pajin-worker:dev"},
            docker_executable="docker\x00alternate",
        )


def test_docker_backend_binds_and_routes_action_specific_external_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(
            allowed_images={"pajin-worker:dev"},
            external_network="bridge",
            external_network_routes={"bug-bounty-sqli-probe": "pajin-bench-fixed-net"},
        )
        context = backend.stable_execution_context()
        assert context["implementationVersion"] == "pajin.docker-worker/v2"
        assert context["externalNetworkRoutes"] == {
            "bug-bounty-sqli-probe": "pajin-bench-fixed-net"
        }
        calls: list[list[str]] = []

        async def run_cli(
            args: list[str], *, timeout: float = 10
        ) -> tuple[int, str, str]:
            del timeout
            calls.append(args)
            if args[:3] == ["inspect", "--format", "{{.State.Health.Status}}"]:
                return 0, "healthy", ""
            return 0, "created", ""

        monkeypatch.setattr(backend, "_run_cli", run_cli)
        monkeypatch.setattr(backend, "_proxy_health_initial_delay_seconds", 0.0)
        job = WorkerJob(
            image="pajin-worker:dev",
            command=["bug-bounty-sqli-probe"],
            network=NetworkMode.EGRESS_PROXY,
            egress_policy=EgressPolicy(allow=["http://target:8080/**"]),
        )

        await backend._setup_egress(job)

        proxy_run = next(args for args in calls if args[:2] == ["run", "--detach"])
        assert proxy_run[proxy_run.index("--network") + 1] == "pajin-bench-fixed-net"

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "routes",
    [
        {"--privileged": "bridge"},
        {"bug-bounty-sqli-probe": "bridge\nforeign"},
    ],
)
def test_docker_backend_rejects_unsafe_external_network_routes(
    routes: dict[str, str],
) -> None:
    with pytest.raises(ValueError, match="routes must use safe identifiers"):
        DockerWorkerBackend(
            allowed_images={"pajin-worker:dev"},
            external_network_routes=routes,
        )


def test_docker_proxy_health_wait_allows_delayed_parallel_health_checks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        monkeypatch.setattr(backend, "_proxy_health_initial_delay_seconds", 0.0)
        monkeypatch.setattr(backend, "_proxy_health_poll_interval_seconds", 0.0)
        monkeypatch.setattr(backend, "_proxy_health_timeout_seconds", 1.0)
        attempts: dict[str, int] = {}

        async def run_cli(
            args: list[str],
            *,
            timeout: float = 10,
        ) -> tuple[int, str, str]:
            assert args[:3] == ["inspect", "--format", "{{.State.Health.Status}}"]
            assert timeout == 2
            proxy_name = args[3]
            attempts[proxy_name] = attempts.get(proxy_name, 0) + 1
            await asyncio.sleep(0)
            status = "healthy" if attempts[proxy_name] > 40 else "starting"
            return 0, status, ""

        monkeypatch.setattr(backend, "_run_cli", run_cli)
        proxy_names = [f"pajin-proxy-parallel-{index}" for index in range(8)]

        readiness = await asyncio.gather(
            *(backend._wait_proxy_healthy(proxy_name) for proxy_name in proxy_names)
        )

        assert readiness == [True] * len(proxy_names)
        assert attempts == dict.fromkeys(proxy_names, 41)

    asyncio.run(scenario())


def test_docker_proxy_health_wait_fails_closed_then_recovers_for_next_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        monkeypatch.setattr(backend, "_proxy_health_initial_delay_seconds", 0.0)
        monkeypatch.setattr(backend, "_proxy_health_poll_interval_seconds", 0.0)
        attempts: dict[str, int] = {}

        async def run_cli(
            args: list[str],
            *,
            timeout: float = 10,
        ) -> tuple[int, str, str]:
            assert timeout == 2
            proxy_name = args[-1]
            attempts[proxy_name] = attempts.get(proxy_name, 0) + 1
            if proxy_name == "pajin-proxy-unhealthy":
                return 0, "unhealthy", ""
            status = "healthy" if attempts[proxy_name] == 2 else "starting"
            return 0, status, ""

        monkeypatch.setattr(backend, "_run_cli", run_cli)

        assert not await backend._wait_proxy_healthy("pajin-proxy-unhealthy")
        assert await backend._wait_proxy_healthy("pajin-proxy-recovered")
        assert attempts == {
            "pajin-proxy-unhealthy": 1,
            "pajin-proxy-recovered": 2,
        }

    asyncio.run(scenario())


def test_docker_backend_classifies_egress_setup_failure_without_raw_detail(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        secret = "egress-setup-secret-MUST-NOT-PERSIST"
        job = WorkerJob(
            image="pajin-worker:dev",
            command=["http-get"],
            network=NetworkMode.EGRESS_PROXY,
            egress_policy=EgressPolicy(allow=["https://example.com/**"]),
        )

        async def setup_egress(worker_job: WorkerJob) -> None:
            assert worker_job is job
            raise RuntimeError(secret)

        monkeypatch.setattr(backend, "_setup_egress", setup_egress)

        result = await backend.run(job)

        assert result.status is WorkerStatus.FAILED
        assert result.failure_code is WorkerFailureCode.EGRESS_PROXY_SETUP_FAILED
        assert result.exit_code is None
        assert secret not in result.stderr
        assert result.stderr == (
            "egress proxy setup failed: "
            "exception_type=RuntimeError; stage=egress-proxy-setup; detail=omitted"
        )

    asyncio.run(scenario())


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


def test_docker_backend_preserves_container_exit_when_stdin_pipe_closes_early(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class ExitedProcess(_FakeProcess):
        async def wait(self) -> int:
            self.returncode = 2
            self.waited.set()
            return self.returncode

    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(image="pajin-worker:dev", command=["mock-agent-probe"])
        process = ExitedProcess(
            stdout=_completed_reader(),
            stderr=_completed_reader(b"invalid input"),
        )
        process.stdin = _BrokenPipeStdin()

        async def create_process(*args: object, **kwargs: object) -> ExitedProcess:
            del args, kwargs
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)

        result = await backend.run(job)

        assert result.status is WorkerStatus.FAILED
        assert result.exit_code == 2
        assert result.stderr == "invalid input"
        assert process.kill_count == 0

    asyncio.run(scenario())


def test_docker_backend_timeout_covers_blocked_stdin_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BlockedInputProcess(_FakeProcess):
        def __init__(self) -> None:
            super().__init__(stdout=_completed_reader(), stderr=_completed_reader())
            self.stdin = _BlockingStdin()
            self.stopped = asyncio.Event()

        async def wait(self) -> int:
            if self.returncode is None:
                await self.stopped.wait()
            assert self.returncode is not None
            self.waited.set()
            return self.returncode

        def kill(self) -> None:
            super().kill()
            self.stopped.set()

    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(
            image="pajin-worker:dev",
            command=["mock-agent-probe"],
            stdin="x" * 1_000_000,
            limits=WorkerLimits(timeout_seconds=0.1),
        )
        process = BlockedInputProcess()
        removed = asyncio.Event()

        async def create_process(*args: object, **kwargs: object) -> BlockedInputProcess:
            del args, kwargs
            return process

        async def force_remove(container_name: str) -> None:
            assert container_name.startswith("pajin-")
            removed.set()

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_force_remove", force_remove)

        result = await asyncio.wait_for(backend.run(job), timeout=0.5)

        assert result.status is WorkerStatus.TIMED_OUT
        assert result.exit_code == -9
        assert process.stdin.cancelled.is_set()
        assert process.kill_count == 1
        assert removed.is_set()

    asyncio.run(scenario())


def test_docker_cli_cancellation_kills_and_drains_subprocess(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class BlockingCliProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.stdout = _BlockingReader()
            self.stderr = _completed_reader()
            self.stopped = asyncio.Event()
            self.kill_count = 0

        def kill(self) -> None:
            self.kill_count += 1
            self.returncode = -9
            self.stopped.set()

        async def wait(self) -> int:
            if self.returncode is None:
                await self.stopped.wait()
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
        await process.stdout.started.wait()
        task.cancel()

        with pytest.raises(asyncio.CancelledError):
            await task

        assert process.kill_count == 1
        assert process.returncode == -9
        assert process.stdout.cancelled.is_set()

    asyncio.run(scenario())


def test_docker_cli_drains_stdout_and_stderr_concurrently_before_waiting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DrainTrackingReader:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload
            self.drained = asyncio.Event()

        async def read(self, size: int) -> bytes:
            await asyncio.sleep(0)
            if not self._payload:
                self.drained.set()
                return b""
            chunk, self._payload = self._payload[:size], self._payload[size:]
            return chunk

    class DrainGatedProcess:
        def __init__(self) -> None:
            self.stdout = DrainTrackingReader(b"bounded stdout")
            self.stderr = DrainTrackingReader(b"bounded stderr")
            self.returncode: int | None = None
            self.kill_count = 0

        async def wait(self) -> int:
            await asyncio.gather(self.stdout.drained.wait(), self.stderr.drained.wait())
            self.returncode = 0
            return self.returncode

        def kill(self) -> None:
            self.kill_count += 1
            self.returncode = -9

    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        process = DrainGatedProcess()

        async def create_process(*args: object, **kwargs: object) -> DrainGatedProcess:
            del args, kwargs
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)

        code, stdout, stderr = await asyncio.wait_for(
            backend._run_cli(["inspect", "test"]),
            timeout=0.5,
        )

        assert code == 0
        assert stdout == "bounded stdout"
        assert stderr == "bounded stderr"
        assert process.kill_count == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    ("stdout", "stderr", "exceeded"),
    [
        (b"x" * (64 * 1024 + 1), b"", "stdout"),
        (b"", b"x" * (64 * 1024 + 1), "stderr"),
        (b"x" * (64 * 1024 + 1), b"x" * (64 * 1024 + 1), "stdout and stderr"),
    ],
)
def test_docker_cli_output_limit_fails_closed_after_draining_both_streams(
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    stderr: bytes,
    exceeded: str,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        process = _FakeProcess(
            stdout=_completed_reader(stdout),
            stderr=_completed_reader(stderr),
        )

        async def create_process(*args: object, **kwargs: object) -> _FakeProcess:
            del args, kwargs
            return process

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)

        code, output, error = await backend._run_cli(["inspect", "test"])

        assert code == backend._cli_output_limit_exit_code
        assert output == ""
        assert exceeded in error
        assert "bounded output limit" in error
        assert process.waited.is_set()
        assert process.kill_count == 0

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


@pytest.mark.parametrize(
    ("exit_code", "diagnostic"),
    [
        (1, "permission denied"),
        (124, "Docker CLI command timed out"),
        (127, "docker executable not found"),
    ],
)
def test_docker_force_remove_retries_and_reports_unconfirmed_container(
    monkeypatch: pytest.MonkeyPatch,
    exit_code: int,
    diagnostic: str,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        attempts = 0

        async def run_cli(
            args: list[str],
            *,
            timeout: float = 10,
        ) -> tuple[int, str, str]:
            nonlocal attempts
            assert args == ["rm", "--force", "pajin-test"]
            assert timeout == 5
            attempts += 1
            return exit_code, "", diagnostic

        monkeypatch.setattr(backend, "_run_cli", run_cli)

        with pytest.raises(RuntimeError, match="pajin-test") as exc_info:
            await backend._force_remove("pajin-test")

        assert attempts == backend._cleanup_attempts
        assert diagnostic in str(exc_info.value)

    asyncio.run(scenario())


def test_docker_force_remove_recovers_from_transient_cleanup_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        responses = iter(
            [
                (124, "", "Docker CLI command timed out"),
                (0, "pajin-test", ""),
            ]
        )
        attempts = 0

        async def run_cli(
            args: list[str],
            *,
            timeout: float = 10,
        ) -> tuple[int, str, str]:
            nonlocal attempts
            assert args == ["rm", "--force", "pajin-test"]
            assert timeout == 5
            attempts += 1
            return next(responses)

        monkeypatch.setattr(backend, "_run_cli", run_cli)

        await backend._force_remove("pajin-test")

        assert attempts == 2

    asyncio.run(scenario())


def test_docker_egress_cleanup_attempts_every_resource_and_preserves_identifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        runtime = SimpleNamespace(
            proxy_name="pajin-proxy-test",
            network_name="pajin-egress-test",
        )
        commands: list[list[str]] = []

        async def run_cli(
            args: list[str],
            *,
            timeout: float = 10,
        ) -> tuple[int, str, str]:
            assert timeout == 5
            commands.append(args)
            return 1, "", "daemon rejected cleanup"

        monkeypatch.setattr(backend, "_run_cli", run_cli)

        with pytest.raises(RuntimeError) as exc_info:
            await backend._cleanup_egress(runtime)

        diagnostic = str(exc_info.value)
        assert "pajin-proxy-test" in diagnostic
        assert "pajin-egress-test" in diagnostic
        assert commands.count(["rm", "--force", "pajin-proxy-test"]) == backend._cleanup_attempts
        assert commands.count(["network", "rm", "pajin-egress-test"]) == backend._cleanup_attempts

    asyncio.run(scenario())


def test_docker_backend_does_not_return_success_when_egress_cleanup_fails(
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
            stdout=_completed_reader(b'{"status": 200}'),
            stderr=_completed_reader(),
        )
        runtime = SimpleNamespace(
            proxy_name="pajin-proxy-test",
            network_name="pajin-egress-test",
        )

        async def setup_egress(worker_job: WorkerJob) -> SimpleNamespace:
            assert worker_job is job
            return runtime

        async def create_process(*args: object, **kwargs: object) -> _FakeProcess:
            del args, kwargs
            return process

        async def read_proxy_logs(proxy_name: str, limit: int) -> str:
            assert proxy_name == runtime.proxy_name
            assert limit == job.limits.stderr_bytes
            return ""

        async def cleanup_egress(cleanup_runtime: object) -> None:
            assert cleanup_runtime is runtime
            raise RuntimeError("egress cleanup failed")

        monkeypatch.setattr(backend, "_setup_egress", setup_egress)
        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_read_proxy_logs", read_proxy_logs)
        monkeypatch.setattr(backend, "_cleanup_egress", cleanup_egress)

        with pytest.raises(RuntimeError) as exc_info:
            await backend.run(job)

        diagnostic = str(exc_info.value)
        assert "pajin-proxy-test" in diagnostic
        assert "pajin-egress-test" in diagnostic

    asyncio.run(scenario())


def test_docker_backend_cleanup_failure_overrides_cancellation_with_diagnostics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailedCleanupProcess:
        returncode: int | None = None

        async def wait(self) -> int:
            self.returncode = 1
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

    async def scenario() -> None:
        backend = DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
        job = WorkerJob(image="pajin-worker:dev", command=["mock-agent-probe"])
        stdout = _BlockingReader()
        process = _FakeProcess(stdout=stdout, stderr=_completed_reader())
        cleanup_attempts = 0

        async def create_process(
            executable: str,
            *args: object,
            **kwargs: object,
        ) -> _FakeProcess | FailedCleanupProcess:
            nonlocal cleanup_attempts
            del executable, kwargs
            if args and args[0] == "run":
                return process
            cleanup_attempts += 1
            return FailedCleanupProcess()

        async def run_cli(
            args: list[str],
            *,
            timeout: float = 10,
        ) -> tuple[int, str, str]:
            nonlocal cleanup_attempts
            assert args[0:2] == ["rm", "--force"]
            assert timeout == 5
            cleanup_attempts += 1
            return 1, "", "daemon rejected cleanup"

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_run_cli", run_cli)

        task = asyncio.create_task(backend.run(job))
        await stdout.started.wait()
        await process.waited.wait()
        await asyncio.sleep(0)
        task.cancel()

        with pytest.raises(RuntimeError) as exc_info:
            await task

        assert "pajin-" in str(exc_info.value)
        assert cleanup_attempts >= backend._cleanup_attempts
        assert stdout.cancelled.is_set()

    asyncio.run(scenario())


def test_docker_backend_cleanup_timeout_cannot_return_timed_out_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TimeoutProcess(_FakeProcess):
        async def wait(self) -> int:
            if self.returncode is None:
                await asyncio.Event().wait()
            assert self.returncode is not None
            return self.returncode

    class FailedCleanupProcess:
        returncode: int | None = None

        async def wait(self) -> int:
            self.returncode = 124
            return self.returncode

        def kill(self) -> None:
            self.returncode = -9

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
        cleanup_attempts = 0

        async def create_process(
            executable: str,
            *args: object,
            **kwargs: object,
        ) -> TimeoutProcess | FailedCleanupProcess:
            del executable, kwargs
            if args and args[0] == "run":
                return process
            return FailedCleanupProcess()

        async def run_cli(
            args: list[str],
            *,
            timeout: float = 10,
        ) -> tuple[int, str, str]:
            nonlocal cleanup_attempts
            assert args[0:2] == ["rm", "--force"]
            assert timeout == 5
            cleanup_attempts += 1
            return 124, "", "Docker CLI command timed out"

        monkeypatch.setattr(asyncio, "create_subprocess_exec", create_process)
        monkeypatch.setattr(backend, "_run_cli", run_cli)

        with pytest.raises(RuntimeError) as exc_info:
            await backend.run(job)

        assert "pajin-" in str(exc_info.value)
        assert cleanup_attempts >= backend._cleanup_attempts
        assert process.kill_count == 1

    asyncio.run(scenario())
