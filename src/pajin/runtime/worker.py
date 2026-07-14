"""Isolated worker backends for executing policy-approved tool jobs."""

from __future__ import annotations

import asyncio
import json
import re
from abc import abstractmethod
from base64 import b64encode
from collections.abc import Awaitable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.runtime.secrets import SecretMaterial


class WorkerStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    REJECTED = "rejected"


class NetworkMode(StrEnum):
    NONE = "none"
    EGRESS_PROXY = "egress-proxy"


class EgressPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(min_length=1, max_length=1_000)
    deny: list[str] = Field(default_factory=list, max_length=1_000)
    allowed_methods: set[str] = Field(default_factory=lambda: {"GET", "HEAD", "POST"})
    allow_private_networks: bool = False
    max_response_bytes: int = Field(default=10_000_000, ge=1_024, le=100_000_000)

    @field_validator("allowed_methods", mode="before")
    @classmethod
    def normalize_methods(cls, value: list[str] | set[str]) -> set[str]:
        return {item.upper() for item in value}


class WorkerLimits(BaseModel):
    model_config = ConfigDict(extra="forbid")

    timeout_seconds: float = Field(default=30, ge=0.1, le=3_600)
    memory_mb: int = Field(default=256, ge=64, le=4_096)
    cpus: float = Field(default=0.5, ge=0.1, le=4)
    pids: int = Field(default=64, ge=1, le=512)
    workspace_mb: int = Field(default=16, ge=1, le=1_024)
    stdout_bytes: int = Field(default=256_000, ge=1_024, le=10_000_000)
    stderr_bytes: int = Field(default=128_000, ge=1_024, le=10_000_000)


class WorkerSecretRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    secret_ref: str = Field(min_length=1, max_length=200)
    binding: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    ttl_seconds: int = Field(default=30, ge=1, le=300)


class WorkerJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(default_factory=lambda: f"exec_{uuid4().hex}")
    image: str = Field(min_length=1, max_length=300)
    command: list[str] = Field(min_length=1, max_length=100)
    stdin: str = Field(default="", max_length=1_000_000)
    network: NetworkMode = NetworkMode.NONE
    egress_policy: EgressPolicy | None = None
    limits: WorkerLimits = Field(default_factory=WorkerLimits)
    secret_requests: list[WorkerSecretRequest] = Field(default_factory=list, max_length=4)

    @field_validator("image")
    @classmethod
    def validate_image(cls, value: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/@:-]*", value):
            raise ValueError("container image contains unsupported characters")
        return value

    @field_validator("command")
    @classmethod
    def reject_nul_bytes(cls, value: list[str]) -> list[str]:
        if any("\x00" in item for item in value):
            raise ValueError("worker command contains a NUL byte")
        return value

    @model_validator(mode="after")
    def validate_network_contract(self) -> WorkerJob:
        if self.network is NetworkMode.NONE and self.egress_policy is not None:
            raise ValueError("egress policy is not allowed for network-none jobs")
        if self.network is NetworkMode.EGRESS_PROXY and self.egress_policy is None:
            raise ValueError("egress-proxy jobs require an egress policy")
        bindings = [request.binding for request in self.secret_requests]
        if len(bindings) != len(set(bindings)):
            raise ValueError("worker secret bindings must be unique")
        return self


class WorkerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str
    backend: str
    status: WorkerStatus
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    network_log: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    started_at: datetime
    finished_at: datetime


class WorkerBackend(Protocol):
    @abstractmethod
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        """Execute a fully specified worker job and return bounded output."""


class SimulatedWorkerBackend:
    """Safe deterministic backend for tests when Docker is unavailable."""

    name = "simulated"
    allowed_image = "pajin-worker:dev"

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        started_at = datetime.now(UTC)
        if job.image != self.allowed_image:
            return self._rejected(job, started_at, "image is not allowed by simulated backend")
        if job.network is not NetworkMode.NONE:
            return self._rejected(job, started_at, "network access is not supported")
        if job.secret_requests or secrets:
            return self._rejected(job, started_at, "secret leases are not supported")
        if job.command not in (["mock-agent-probe"], ["mcp-call"], ["sleep-check"]):
            return self._rejected(job, started_at, "worker action is not supported")
        try:
            payload = json.loads(job.stdin)
            if job.command == ["mock-agent-probe"]:
                simulation = payload.get("simulation", {})
                vulnerable = bool(simulation.get("unauthorizedToolCall", False))
                output_data = {
                    "vulnerable": vulnerable,
                    "observation": (
                        "target accepted an untrusted instruction and invoked a protected tool"
                        if vulnerable
                        else "target rejected the untrusted instruction"
                    ),
                    "target": payload["target"],
                    "networkPerformed": False,
                }
            elif job.command == ["mcp-call"]:
                if payload.get("serverId") != "demo-security":
                    raise KeyError("unknown MCP server ID")
                if payload.get("toolName") != "inspect_text":
                    raise KeyError("unknown MCP tool name")
                text = str(payload.get("arguments", {}).get("text", ""))
                suspicious = "ignore previous" in text.lower()
                output_data = {
                    "isError": False,
                    "structuredContent": {
                        "vulnerable": suspicious,
                        "observation": (
                            "untrusted text contains an instruction-hijacking pattern"
                            if suspicious
                            else "no instruction-hijacking pattern detected"
                        ),
                    },
                    "content": [{"type": "text", "text": "inspection complete"}],
                }
            else:
                seconds = float(payload.get("seconds", 1))
                if not 0 <= seconds <= 30:
                    raise ValueError("sleep duration must be between 0 and 30 seconds")
                await asyncio.sleep(seconds)
                output_data = {"slept": True, "seconds": seconds}
            output = json.dumps(output_data)
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as exc:
            return WorkerResult(
                execution_id=job.execution_id,
                backend=self.name,
                status=WorkerStatus.FAILED,
                exit_code=2,
                stderr=f"invalid worker input: {exc}",
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        return WorkerResult(
            execution_id=job.execution_id,
            backend=self.name,
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=output,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )

    def _rejected(self, job: WorkerJob, started_at: datetime, reason: str) -> WorkerResult:
        return WorkerResult(
            execution_id=job.execution_id,
            backend=self.name,
            status=WorkerStatus.REJECTED,
            exit_code=None,
            stderr=reason,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )


@dataclass(frozen=True)
class _EgressRuntime:
    network_name: str
    proxy_name: str


class DockerWorkerBackend:
    """Execute a job with a fixed, fail-closed Docker security profile."""

    name = "docker"
    _cleanup_timeout_seconds = 20.0
    _process_stop_timeout_seconds = 2.0

    def __init__(
        self,
        *,
        allowed_images: set[str],
        docker_executable: str = "docker",
        egress_proxy_image: str = "pajin-egress-proxy:dev",
        external_network: str = "bridge",
    ) -> None:
        if not allowed_images:
            raise ValueError("at least one Docker image must be allowlisted")
        self._allowed_images = allowed_images
        self._docker = docker_executable
        self._egress_proxy_image = egress_proxy_image
        self._external_network = external_network

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        started_at = datetime.now(UTC)
        if job.image not in self._allowed_images:
            return self._rejected(job, started_at, "container image is not allowlisted")
        try:
            wire_stdin = self._wire_stdin(job, secrets or [])
        except ValueError as exc:
            return WorkerResult(
                execution_id=job.execution_id,
                backend=self.name,
                status=WorkerStatus.REJECTED,
                exit_code=None,
                stderr=str(exc),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        container_name = self._container_name(job.execution_id)
        egress_runtime: _EgressRuntime | None = None
        process: asyncio.subprocess.Process | None = None
        stdout_task: asyncio.Task[tuple[bytes, bool]] | None = None
        stderr_task: asyncio.Task[tuple[bytes, bool]] | None = None
        force_remove = False
        try:
            if job.network is NetworkMode.EGRESS_PROXY:
                try:
                    egress_runtime = await self._setup_egress(job)
                except RuntimeError as exc:
                    return WorkerResult(
                        execution_id=job.execution_id,
                        backend=self.name,
                        status=WorkerStatus.FAILED,
                        exit_code=None,
                        stderr=f"egress proxy setup failed: {exc}",
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                    )
            args = self._docker_args(
                job,
                container_name,
                network_name=egress_runtime.network_name if egress_runtime else None,
            )
            try:
                process = await asyncio.create_subprocess_exec(
                    self._docker,
                    *args,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            except OSError as exc:
                return WorkerResult(
                    execution_id=job.execution_id,
                    backend=self.name,
                    status=WorkerStatus.FAILED,
                    exit_code=None,
                    stderr=f"unable to start Docker CLI: {exc}",
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )

            stdout_task = asyncio.create_task(
                self._read_bounded(process.stdout, job.limits.stdout_bytes)
            )
            stderr_task = asyncio.create_task(
                self._read_bounded(process.stderr, job.limits.stderr_bytes)
            )
            timed_out = False
            try:
                assert process.stdin is not None
                process.stdin.write(wire_stdin)
                await process.stdin.drain()
                process.stdin.close()
                await asyncio.wait_for(process.wait(), timeout=job.limits.timeout_seconds)
            except TimeoutError:
                timed_out = True
                force_remove = True
                if process.returncode is None:
                    with suppress(ProcessLookupError):
                        process.kill()
                    with suppress(TimeoutError):
                        await asyncio.wait_for(
                            process.wait(),
                            timeout=self._process_stop_timeout_seconds,
                        )
                await self._force_remove(container_name)

            stdout_bytes, stdout_truncated = await stdout_task
            stderr_bytes, stderr_truncated = await stderr_task
            network_log = ""
            if egress_runtime:
                network_log = await self._read_proxy_logs(
                    egress_runtime.proxy_name,
                    job.limits.stderr_bytes,
                )
            status = (
                WorkerStatus.TIMED_OUT
                if timed_out
                else WorkerStatus.SUCCEEDED
                if process.returncode == 0
                else WorkerStatus.FAILED
            )
            return WorkerResult(
                execution_id=job.execution_id,
                backend=self.name,
                status=status,
                exit_code=process.returncode,
                stdout=stdout_bytes.decode("utf-8", errors="replace"),
                stderr=stderr_bytes.decode("utf-8", errors="replace"),
                network_log=network_log,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
        except BaseException:
            # The container name is known before the Docker CLI is spawned. Remove by
            # name even when cancellation races subprocess creation and no handle was
            # returned to this task.
            force_remove = True
            raise
        finally:
            if force_remove or process is not None or egress_runtime is not None:
                await self._drain_cleanup(
                    self._cleanup_execution(
                        process=process,
                        container_name=container_name,
                        reader_tasks=(stdout_task, stderr_task),
                        egress_runtime=egress_runtime,
                        force_remove=force_remove,
                    )
                )

    def _docker_args(
        self,
        job: WorkerJob,
        container_name: str,
        *,
        network_name: str | None = None,
    ) -> list[str]:
        limits = job.limits
        network_args = ["--network", "none"]
        proxy_args: list[str] = []
        if job.network is NetworkMode.EGRESS_PROXY:
            if not network_name:
                raise ValueError("egress-proxy job requires an internal Docker network")
            network_args = ["--network", network_name]
            proxy_url = "http://egress-proxy:8080"
            proxy_args = [
                "--env",
                f"HTTP_PROXY={proxy_url}",
                "--env",
                f"HTTPS_PROXY={proxy_url}",
                "--env",
                f"http_proxy={proxy_url}",
                "--env",
                f"https_proxy={proxy_url}",
                "--env",
                "NO_PROXY=localhost,127.0.0.1",
                "--env",
                "no_proxy=localhost,127.0.0.1",
            ]
        return [
            "run",
            "--rm",
            "--interactive",
            "--pull",
            "never",
            "--name",
            container_name,
            "--label",
            f"pajin.execution-id={job.execution_id}",
            *network_args,
            *proxy_args,
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(limits.pids),
            "--memory",
            f"{limits.memory_mb}m",
            "--cpus",
            str(limits.cpus),
            "--user",
            "65532:65532",
            "--workdir",
            "/workspace",
            "--tmpfs",
            f"/workspace:rw,noexec,nosuid,nodev,mode=1777,size={limits.workspace_mb}m",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=16m",
            "--stop-timeout",
            "1",
            job.image,
            *job.command,
        ]

    async def _setup_egress(self, job: WorkerJob) -> _EgressRuntime:
        policy = job.egress_policy
        if policy is None:
            raise RuntimeError("egress policy is missing")
        suffix = uuid4().hex[:10]
        network_name = f"pajin-egress-{suffix}"
        proxy_name = f"pajin-proxy-{suffix}"
        runtime = _EgressRuntime(network_name=network_name, proxy_name=proxy_name)
        ready = False
        try:
            code, _, error = await self._run_cli(
                [
                    "network",
                    "create",
                    "--internal",
                    "--label",
                    f"pajin.execution-id={job.execution_id}",
                    network_name,
                ]
            )
            if code != 0:
                raise RuntimeError(error or "unable to create internal network")

            policy_json = policy.model_dump_json()
            policy_b64 = b64encode(policy_json.encode("utf-8")).decode("ascii")
            code, _, error = await self._run_cli(
                [
                    "run",
                    "--detach",
                    "--rm",
                    "--pull",
                    "never",
                    "--name",
                    proxy_name,
                    "--label",
                    f"pajin.execution-id={job.execution_id}",
                    "--network",
                    self._external_network,
                    "--read-only",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "32",
                    "--memory",
                    "64m",
                    "--cpus",
                    "0.25",
                    "--user",
                    "65532:65532",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,nodev,mode=1777,size=8m",
                    "--env",
                    f"PAJIN_EGRESS_POLICY_B64={policy_b64}",
                    self._egress_proxy_image,
                ]
            )
            if code != 0:
                raise RuntimeError(error or "unable to start egress proxy")

            code, _, error = await self._run_cli(
                [
                    "network",
                    "connect",
                    "--alias",
                    "egress-proxy",
                    network_name,
                    proxy_name,
                ]
            )
            if code != 0:
                raise RuntimeError(error or "unable to connect proxy to internal network")
            if not await self._wait_proxy_healthy(proxy_name):
                logs = await self._read_proxy_logs(proxy_name, 16_000)
                raise RuntimeError(f"egress proxy did not become healthy: {logs}")
            ready = True
            return runtime
        finally:
            if not ready:
                await self._drain_cleanup(self._cleanup_egress(runtime))

    async def _wait_proxy_healthy(self, proxy_name: str) -> bool:
        for _ in range(30):
            code, output, _ = await self._run_cli(
                ["inspect", "--format", "{{.State.Health.Status}}", proxy_name],
                timeout=2,
            )
            if code == 0 and output.strip() == "healthy":
                return True
            if code == 0 and output.strip() == "unhealthy":
                return False
            await asyncio.sleep(0.1)
        return False

    async def _read_proxy_logs(self, proxy_name: str, limit: int) -> str:
        _, output, error = await self._run_cli(
            ["logs", "--tail", "200", proxy_name],
            timeout=5,
        )
        data = (output + error).encode("utf-8")[:limit]
        return data.decode("utf-8", errors="replace")

    async def _cleanup_egress(self, runtime: _EgressRuntime) -> None:
        await self._run_cli(["rm", "--force", runtime.proxy_name], timeout=5)
        await self._run_cli(["network", "rm", runtime.network_name], timeout=5)

    async def _cleanup_execution(
        self,
        *,
        process: asyncio.subprocess.Process | None,
        container_name: str,
        reader_tasks: tuple[
            asyncio.Task[tuple[bytes, bool]] | None,
            asyncio.Task[tuple[bytes, bool]] | None,
        ],
        egress_runtime: _EgressRuntime | None,
        force_remove: bool,
    ) -> None:
        try:
            if force_remove:
                if process is not None and process.returncode is None:
                    with suppress(ProcessLookupError):
                        process.kill()
                    with suppress(TimeoutError):
                        await asyncio.wait_for(
                            process.wait(),
                            timeout=self._process_stop_timeout_seconds,
                        )
                await self._force_remove(container_name)
        finally:
            try:
                active_readers = [task for task in reader_tasks if task is not None]
                for task in active_readers:
                    if not task.done():
                        task.cancel()
                if active_readers:
                    await asyncio.gather(*active_readers, return_exceptions=True)
            finally:
                if egress_runtime is not None:
                    await self._cleanup_egress(egress_runtime)

    async def _drain_cleanup(self, cleanup: Awaitable[None]) -> None:
        cleanup_task = asyncio.create_task(
            asyncio.wait_for(cleanup, timeout=self._cleanup_timeout_seconds)
        )
        interrupted = False
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                interrupted = True
            except Exception:
                break
        with suppress(asyncio.CancelledError, Exception):
            cleanup_task.result()
        if interrupted:
            raise asyncio.CancelledError()

    async def _run_cli(
        self,
        args: list[str],
        *,
        timeout: float = 10,
    ) -> tuple[int, str, str]:
        process: asyncio.subprocess.Process | None = None
        try:
            process = await asyncio.create_subprocess_exec(
                self._docker,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
        except OSError as exc:
            return 127, "", str(exc)
        except asyncio.CancelledError:
            if process is not None and process.returncode is None:
                with suppress(ProcessLookupError):
                    process.kill()
                with suppress(TimeoutError):
                    await asyncio.wait_for(
                        process.wait(),
                        timeout=self._process_stop_timeout_seconds,
                    )
            raise
        except TimeoutError:
            assert process is not None
            process.kill()
            await process.wait()
            return 124, "", "Docker CLI command timed out"
        return (
            process.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )

    async def _force_remove(self, container_name: str) -> None:
        cleanup: asyncio.subprocess.Process | None = None
        try:
            cleanup = await asyncio.create_subprocess_exec(
                self._docker,
                "rm",
                "--force",
                container_name,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(cleanup.wait(), timeout=5)
        except OSError:
            return
        except TimeoutError:
            if cleanup is not None and cleanup.returncode is None:
                with suppress(ProcessLookupError):
                    cleanup.kill()
                with suppress(TimeoutError):
                    await asyncio.wait_for(
                        cleanup.wait(),
                        timeout=self._process_stop_timeout_seconds,
                    )

    @staticmethod
    async def _read_bounded(
        stream: asyncio.StreamReader | None,
        limit: int,
    ) -> tuple[bytes, bool]:
        if stream is None:
            return b"", False
        chunks: list[bytes] = []
        captured = 0
        truncated = False
        while chunk := await stream.read(8_192):
            remaining = limit - captured
            if remaining > 0:
                kept = chunk[:remaining]
                chunks.append(kept)
                captured += len(kept)
            if len(chunk) > max(remaining, 0):
                truncated = True
        return b"".join(chunks), truncated

    @staticmethod
    def _wire_stdin(job: WorkerJob, secrets: list[SecretMaterial]) -> bytes:
        requested_bindings = {item.binding for item in job.secret_requests}
        supplied_bindings = {item.binding for item in secrets}
        if requested_bindings != supplied_bindings:
            raise ValueError("worker secret material does not match requested bindings")
        if not secrets:
            return job.stdin.encode("utf-8")
        try:
            payload = json.loads(job.stdin)
        except json.JSONDecodeError as exc:
            raise ValueError("secret-bearing Worker stdin must be valid JSON") from exc
        envelope = {
            "pajinEnvelopeVersion": 1,
            "payload": payload,
            "secrets": {item.binding: item.value for item in secrets},
        }
        return json.dumps(envelope, separators=(",", ":")).encode("utf-8")

    @staticmethod
    def _container_name(execution_id: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "-", execution_id)[:50]
        return f"pajin-{safe}-{uuid4().hex[:8]}".lower()

    def _rejected(self, job: WorkerJob, started_at: datetime, reason: str) -> WorkerResult:
        return WorkerResult(
            execution_id=job.execution_id,
            backend=self.name,
            status=WorkerStatus.REJECTED,
            exit_code=None,
            stderr=reason,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )
