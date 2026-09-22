"""Isolated worker backends for executing policy-approved tool jobs."""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import re
import signal
import threading
from abc import abstractmethod
from base64 import b64encode
from collections.abc import Awaitable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from types import FrameType
from typing import Never, Protocol
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from pajin.runtime.error_safety import audit_safe_exception_diagnostic
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import SecretMaterial

_SAFE_RUNTIME_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_HTTP_METHOD_PATTERN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Z]+$")
_MAX_WORKER_TRANSCRIPT_CHARS = 10_000_000
_MAX_WORKER_STDIN_BYTES = 1_000_000
_MAX_WORKER_WIRE_INPUT_BYTES = 1_100_000
LARGE_PROVIDER_ACTION = "openai-chat-completion-v2"
MAX_LARGE_PROVIDER_INPUT_BYTES = 16 * 1024 * 1024
_MAX_EGRESS_PROXY_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_EGRESS_OBSERVER_CONTEXT_BYTES = 64 * 1024
_MAX_PRE_CLEANUP_BARRIER_CONTEXT_BYTES = 64 * 1024
_PRE_CLEANUP_SIGNAL_DEADLINE_LOCK = threading.Lock()


class WorkerStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed-out"
    REJECTED = "rejected"


class WorkerFailureCode(StrEnum):
    """Host-classified Worker failure reasons safe for policy decisions."""

    EGRESS_PROXY_SETUP_FAILED = "egress-proxy-setup-failed"
    TARGET_UNAVAILABLE = "target-unavailable"


class NetworkMode(StrEnum):
    NONE = "none"
    EGRESS_PROXY = "egress-proxy"


class EgressPolicy(BaseModel):
    """Policy serialized to the per-execution forward proxy.

    Plain HTTP method and path rules are enforced by the proxy. For HTTPS the
    proxy can observe only the CONNECT authority: it requires a host-wide allow
    and denies the whole authority when any deny rule targets that authority.
    The trusted, fixed Worker action remains responsible for the exact HTTPS
    method and path; CONNECT receipts state that limitation explicitly.
    """

    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(min_length=1, max_length=1_000)
    deny: list[str] = Field(default_factory=list, max_length=1_000)
    allowed_methods: set[str] = Field(
        default_factory=lambda: {"GET", "HEAD", "POST"},
        min_length=1,
        max_length=32,
    )
    allow_private_networks: bool = False
    max_response_bytes: int = Field(
        default=_MAX_EGRESS_PROXY_RESPONSE_BYTES,
        ge=1_024,
        le=_MAX_EGRESS_PROXY_RESPONSE_BYTES,
    )
    max_requests: int = Field(default=1, ge=1, le=100)
    max_request_bytes: int | None = Field(
        default=None,
        ge=1,
        le=MAX_LARGE_PROVIDER_INPUT_BYTES,
        exclude_if=lambda value: value is None,
    )

    @field_validator("max_request_bytes", mode="before")
    @classmethod
    def require_request_byte_limit(cls, value: object) -> object:
        if value is not None and type(value) is not int:
            raise ValueError("egress request byte limit must be an integer")
        return value

    @field_validator("allowed_methods", mode="before")
    @classmethod
    def normalize_methods(cls, value: object) -> set[str]:
        if isinstance(value, (str, bytes)) or not isinstance(
            value,
            (list, set, tuple, frozenset),
        ):
            raise ValueError("allowed_methods must be a collection of HTTP method tokens")
        normalized: set[str] = set()
        for item in value:
            if not isinstance(item, str):
                raise ValueError("allowed_methods must contain strings")
            method = item.upper()
            if len(method) > 32 or _HTTP_METHOD_PATTERN.fullmatch(method) is None:
                raise ValueError("allowed_methods contains an invalid HTTP method token")
            normalized.add(method)
        return normalized

    @field_serializer("allowed_methods", when_used="json")
    def serialize_methods(self, value: set[str]) -> list[str]:
        return sorted(value)

    @field_validator("allow", "deny")
    @classmethod
    def bound_unique_rules(cls, value: list[str]) -> list[str]:
        if any(not rule or len(rule) > 4_096 for rule in value):
            raise ValueError("egress rules must contain 1 to 4096 characters")
        if len(set(value)) != len(value):
            raise ValueError("egress rules must be unique")
        return value

    @field_validator("allow_private_networks", mode="before")
    @classmethod
    def require_boolean_private_network_flag(cls, value: object) -> bool:
        if type(value) is not bool:
            raise ValueError("allow_private_networks must be boolean")
        return value

    @field_validator("max_response_bytes", "max_requests", mode="before")
    @classmethod
    def require_integer_limits(cls, value: object) -> int:
        if type(value) is not int:
            raise ValueError("egress limits must be integers")
        return value


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

    execution_id: str = Field(
        default_factory=lambda: f"exec_{uuid4().hex}",
        pattern=_SAFE_RUNTIME_IDENTIFIER_PATTERN,
    )
    image: str = Field(min_length=1, max_length=300)
    command: list[str] = Field(min_length=1, max_length=100)
    stdin: str = Field(default="", max_length=MAX_LARGE_PROVIDER_INPUT_BYTES)
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

    @field_validator("stdin")
    @classmethod
    def bound_stdin_bytes(cls, value: str) -> str:
        try:
            encoded = value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("worker stdin must be valid UTF-8 text") from exc
        if len(encoded) > MAX_LARGE_PROVIDER_INPUT_BYTES:
            raise ValueError("worker stdin exceeded its UTF-8 byte limit")
        return value

    @model_validator(mode="after")
    def validate_network_contract(self) -> WorkerJob:
        if len(self.stdin.encode("utf-8")) > self.stdin_byte_limit:
            raise ValueError("worker stdin exceeded its UTF-8 byte limit")
        if (
            self.egress_policy is not None
            and self.egress_policy.max_request_bytes is not None
            and self.egress_policy.max_request_bytes > self.stdin_byte_limit
        ):
            raise ValueError("egress request limit exceeds the Worker action transport")
        if self.network is NetworkMode.NONE and self.egress_policy is not None:
            raise ValueError("egress policy is not allowed for network-none jobs")
        if self.network is NetworkMode.EGRESS_PROXY and self.egress_policy is None:
            raise ValueError("egress-proxy jobs require an egress policy")
        bindings = [request.binding for request in self.secret_requests]
        if len(bindings) != len(set(bindings)):
            raise ValueError("worker secret bindings must be unique")
        return self

    @property
    def stdin_byte_limit(self) -> int:
        return (
            MAX_LARGE_PROVIDER_INPUT_BYTES
            if self.command == [LARGE_PROVIDER_ACTION]
            else _MAX_WORKER_STDIN_BYTES
        )

    @property
    def request_byte_limit_override(self) -> int | None:
        return MAX_LARGE_PROVIDER_INPUT_BYTES if self.command == [LARGE_PROVIDER_ACTION] else None


class WorkerResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    execution_id: str = Field(pattern=_SAFE_RUNTIME_IDENTIFIER_PATTERN)
    backend: str = Field(pattern=_SAFE_RUNTIME_IDENTIFIER_PATTERN)
    status: WorkerStatus
    failure_code: WorkerFailureCode | None = None
    exit_code: int | None
    stdout: str = Field(default="", max_length=_MAX_WORKER_TRANSCRIPT_CHARS)
    stderr: str = Field(default="", max_length=_MAX_WORKER_TRANSCRIPT_CHARS)
    network_log: str = Field(default="", max_length=_MAX_WORKER_TRANSCRIPT_CHARS)
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    started_at: datetime
    finished_at: datetime

    @field_validator("exit_code", mode="before")
    @classmethod
    def require_literal_exit_code(cls, value: object) -> object:
        if value is not None and type(value) is not int:
            raise ValueError("Worker exit code must use a JSON integer or null")
        return value

    @field_validator("stdout_truncated", "stderr_truncated", mode="before")
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Worker truncation flags must use JSON booleans")
        return value

    @model_validator(mode="after")
    def validate_execution_lifecycle(self) -> WorkerResult:
        try:
            if self.finished_at < self.started_at:
                raise ValueError("Worker result finished_at precedes started_at")
        except TypeError as exc:
            raise ValueError("Worker result timestamps are not comparable") from exc
        if self.status is WorkerStatus.SUCCEEDED and self.exit_code != 0:
            raise ValueError("successful Worker result requires exit code 0")
        if self.failure_code is not None and self.status is not WorkerStatus.FAILED:
            raise ValueError("Worker failure code requires failed status")
        if self.status is WorkerStatus.REJECTED and self.exit_code is not None:
            raise ValueError("rejected Worker result cannot include an exit code")
        if self.status in {WorkerStatus.FAILED, WorkerStatus.TIMED_OUT} and self.exit_code == 0:
            raise ValueError("unsuccessful Worker result cannot include exit code 0")
        return self


class WorkerBackend(Protocol):
    @abstractmethod
    def stable_execution_context(self) -> dict[str, object]:
        """Return non-secret configuration that can change resumable execution."""

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

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "pajin.simulated-worker/v1",
            "allowedImage": self.allowed_image,
            "supportedCommands": [
                "mcp-call",
                "mcp-discover",
                "mock-agent-probe",
                "sleep-check",
            ],
            "networkMode": NetworkMode.NONE.value,
            "secretLeases": False,
        }

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
        if job.command not in (
            ["mock-agent-probe"],
            ["mcp-call"],
            ["mcp-discover"],
            ["sleep-check"],
        ):
            return self._rejected(job, started_at, "worker action is not supported")
        try:
            decoded = parse_strict_json_bytes(
                job.stdin.encode("utf-8"),
                label="simulated Worker input",
                max_bytes=_MAX_WORKER_STDIN_BYTES,
            )
            if not isinstance(decoded, dict):
                raise TypeError("simulated Worker input must be an object")
            payload = decoded
            if job.command == ["mock-agent-probe"]:
                output_data = self._mock_agent_output(payload)
            elif job.command == ["mcp-discover"]:
                output_data = self._mcp_discovery_output(payload)
            elif job.command == ["mcp-call"]:
                if payload.get("serverId") != "demo-security":
                    output_data = {
                        "isError": True,
                        "structuredContent": {"rejectionCode": "server-not-registered"},
                        "content": [],
                    }
                elif payload.get("toolName") != "inspect_text":
                    output_data = {
                        "isError": True,
                        "structuredContent": {"rejectionCode": "tool-not-registered"},
                        "content": [],
                    }
                else:
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
                seconds = payload.get("seconds", 1)
                if isinstance(seconds, bool) or not isinstance(seconds, int | float):
                    raise TypeError("sleep duration must be a number")
                if not 0 <= seconds <= 30:
                    raise ValueError("sleep duration must be between 0 and 30 seconds")
                await asyncio.sleep(seconds)
                output_data = {"slept": True, "seconds": seconds}
            output = json.dumps(output_data)
        except (json.JSONDecodeError, KeyError, TypeError, AttributeError, ValueError) as exc:
            return WorkerResult(
                execution_id=job.execution_id,
                backend=self.name,
                status=WorkerStatus.FAILED,
                exit_code=2,
                stderr=(
                    "invalid worker input: "
                    + audit_safe_exception_diagnostic(exc, stage="simulated-worker-input")
                ),
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

    @staticmethod
    def _mock_agent_output(payload: dict[str, object]) -> dict[str, object]:
        simulation = payload.get("simulation", {})
        if not isinstance(simulation, dict):
            raise TypeError("mock simulation must be an object")
        vulnerable = simulation.get("unauthorizedToolCall", False)
        if not isinstance(vulnerable, bool):
            raise TypeError("mock unauthorizedToolCall must be boolean")
        target = payload.get("target")
        if not isinstance(target, str) or not target:
            raise TypeError("mock target must be a non-empty string")
        return {
            "vulnerable": vulnerable,
            "observation": (
                "target accepted an untrusted instruction and invoked a protected tool"
                if vulnerable
                else "target rejected the untrusted instruction"
            ),
            "target": target,
            "networkPerformed": False,
        }

    @staticmethod
    def _mcp_discovery_output(payload: dict[str, object]) -> dict[str, object]:
        if set(payload) != {"serverId"}:
            raise ValueError("MCP discovery input must contain only a server ID")
        if payload.get("serverId") != "demo-security":
            raise ValueError("MCP discovery server is not registered")

        def digest(value: object) -> str:
            encoded = json.dumps(
                value,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            return sha256(encoded).hexdigest()

        resource_uri = "pajin://policy"
        template_uri = "pajin://guidance/{topic}"
        input_schema = {
            "properties": {"text": {"type": "string"}},
            "required": ["text"],
            "type": "object",
        }
        url_input_schema = {
            "properties": {
                "url": {
                    "format": "uri",
                    "minLength": 1,
                    "type": "string",
                }
            },
            "required": ["url"],
            "type": "object",
        }
        return {
            "protocolVersion": "2025-06-18",
            "capabilities": ["prompts", "resources", "tools"],
            "tools": [
                {
                    "name": "inspect_text",
                    "inputSchemaDigest": digest(input_schema),
                },
                {
                    "name": "inspect_url",
                    "inputSchemaDigest": digest(url_input_schema),
                    "urlArguments": [{"name": "url", "required": True}],
                },
            ],
            "resources": [
                {
                    "uriScheme": "pajin",
                    "uriSha256": sha256(resource_uri.encode("utf-8")).hexdigest(),
                }
            ],
            "resourceTemplates": [
                {
                    "uriScheme": "pajin",
                    "templateSha256": sha256(template_uri.encode("utf-8")).hexdigest(),
                }
            ],
            "prompts": [
                {
                    "name": "inspect_prompt",
                    "arguments": [{"name": "text", "required": True}],
                }
            ],
        }


@dataclass(frozen=True, slots=True)
class DockerEgressLifecycleObservation:
    """Exact Docker resource names observed around one egress execution."""

    execution_id: str
    worker_container_name: str
    proxy_container_name: str
    internal_network_name: str
    external_network_name: str


class DockerEgressLifecycleObserver(Protocol):
    """Host-owned observer invoked outside the Worker container's trust boundary."""

    def stable_observer_context(self) -> Mapping[str, object]: ...

    async def attached(self, observation: DockerEgressLifecycleObservation) -> None: ...

    async def cleaned(self, observation: DockerEgressLifecycleObservation) -> None: ...


class DockerEgressLifecycleObservationError(RuntimeError):
    """Raised after an egress lifecycle observer fails closed."""

    def __init__(self, *, stage: str, cause: Exception) -> None:
        diagnostic = audit_safe_exception_diagnostic(
            cause,
            stage=f"docker-egress-observer-{stage}",
        )
        super().__init__(
            f"Docker egress lifecycle observation failed during {stage}: "
            f"{diagnostic or 'observer failed without a diagnostic'}"
        )


class WorkerAttemptOutcome(StrEnum):
    """Host-visible classification at the pre-cleanup durability boundary."""

    RESULT_OBSERVED = "result-observed"
    OUTCOME_UNKNOWN = "outcome-unknown"


class DockerPreCleanupBarrierObservation(BaseModel):
    """Bounded summary of one Worker attempt before Docker cleanup begins."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    execution_id: str = Field(pattern=_SAFE_RUNTIME_IDENTIFIER_PATTERN)
    outcome: WorkerAttemptOutcome
    worker_status: WorkerStatus | None = None
    failure_code: WorkerFailureCode | None = None
    result_sha256: str | None = Field(default=None, pattern=r"^sha256:[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_result_binding(self) -> DockerPreCleanupBarrierObservation:
        result_fields = (self.worker_status, self.failure_code, self.result_sha256)
        if self.outcome is WorkerAttemptOutcome.RESULT_OBSERVED:
            if self.worker_status is None or self.result_sha256 is None:
                raise ValueError("observed Worker result requires status and digest")
            if self.failure_code is not None and self.worker_status is not WorkerStatus.FAILED:
                raise ValueError("Worker failure code requires failed result status")
        elif any(value is not None for value in result_fields):
            raise ValueError("outcome-unknown cannot assert Worker result fields")
        return self

    @classmethod
    def from_result(cls, result: WorkerResult) -> DockerPreCleanupBarrierObservation:
        encoded = json.dumps(
            result.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return cls(
            execution_id=result.execution_id,
            outcome=WorkerAttemptOutcome.RESULT_OBSERVED,
            worker_status=result.status,
            failure_code=result.failure_code,
            result_sha256=f"sha256:{sha256(encoded).hexdigest()}",
        )

    @classmethod
    def outcome_unknown(cls, execution_id: str) -> DockerPreCleanupBarrierObservation:
        return cls(
            execution_id=execution_id,
            outcome=WorkerAttemptOutcome.OUTCOME_UNKNOWN,
        )


class DockerWorkerPreCleanupBarrier(Protocol):
    """Host-owned durable barrier invoked once before Docker resource cleanup."""

    def stable_barrier_context(self) -> Mapping[str, object]: ...

    async def before_cleanup(
        self,
        observation: DockerPreCleanupBarrierObservation,
        result: WorkerResult | None,
    ) -> None: ...


class DockerWorkerSynchronousPreCleanupBarrier(Protocol):
    """Host-owned durability barrier with a hard POSIX execution deadline.

    Unlike the additive legacy async callback, this callback must not yield.  It
    executes on the event-loop's main thread under a process real-time timer, so
    Python CPU work and interruptible blocking system calls cannot outlive Docker
    cleanup after the deadline fires. Implementations must never suppress
    :class:`DockerPreCleanupBarrierDeadlineExceeded`.
    """

    def stable_barrier_context(self) -> Mapping[str, object]: ...

    def before_cleanup_sync(
        self,
        observation: DockerPreCleanupBarrierObservation,
        result: WorkerResult | None,
    ) -> None: ...


class DockerPreCleanupBarrierDeadlineExceeded(BaseException):
    """Raised inside a synchronous barrier when its hard deadline expires."""


class DockerPreCleanupBarrierError(RuntimeError):
    """Raised after the durable pre-cleanup callback fails closed."""

    def __init__(self, *, cause: BaseException) -> None:
        diagnostic = audit_safe_exception_diagnostic(cause, stage="worker-backend")
        super().__init__(
            "Docker pre-cleanup durability barrier failed: "
            f"{diagnostic or 'barrier failed without a diagnostic'}"
        )


@dataclass(frozen=True)
class _EgressRuntime:
    network_name: str
    proxy_name: str
    external_network_name: str


@dataclass(frozen=True)
class _ContainerProcessCapture:
    timed_out: bool
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    stdout_truncated: bool
    stderr_truncated: bool


@dataclass(frozen=True)
class _CleanupFailure:
    resource_kind: str
    resource_id: str
    detail: str

    @property
    def resource_label(self) -> str:
        return f"{self.resource_kind} {self.resource_id!r}"


class WorkerCleanupError(RuntimeError):
    """Raised when Docker resource removal cannot be confirmed."""

    def __init__(self, failures: list[_CleanupFailure]) -> None:
        if not failures:
            raise ValueError("at least one cleanup failure is required")
        self.failures = tuple(failures)
        resources = ", ".join(dict.fromkeys(failure.resource_label for failure in self.failures))
        details = " | ".join(
            f"{failure.resource_label}: {failure.detail}" for failure in self.failures
        )
        super().__init__(
            "Docker cleanup could not confirm resource removal; "
            f"resources may remain: {resources}; details: {details}"
        )


class DockerWorkerBackend:
    """Execute a job with a fixed, fail-closed Docker security profile."""

    name = "docker"
    _cleanup_timeout_seconds = 20.0
    _cleanup_command_timeout_seconds = 5.0
    _cleanup_attempts = 3
    _process_stop_timeout_seconds = 2.0
    # The v6 backend identity fixes this host-owned synchronous durability deadline;
    # it is deliberately not caller-configurable or copied into callback context.
    _pre_cleanup_barrier_timeout_seconds = 30.0
    _cli_stdout_limit_bytes = 64 * 1024
    _cli_stderr_limit_bytes = 64 * 1024
    _cli_output_limit_exit_code = 125
    # Docker schedules image health checks independently of the container process.
    # Poll at a bounded one-second cadence while allowing several five-second
    # image health intervals of headroom on a loaded Docker daemon.
    _proxy_health_timeout_seconds = 20.0
    _proxy_health_initial_delay_seconds = 1.0
    _proxy_health_poll_interval_seconds = 1.0

    def __init__(
        self,
        *,
        allowed_images: set[str],
        docker_executable: str = "docker",
        egress_proxy_image: str = "pajin-egress-proxy:dev",
        external_network: str = "bridge",
        external_network_routes: Mapping[str, str] | None = None,
        runtime_image_bindings: Mapping[str, str] | None = None,
        egress_lifecycle_observer: DockerEgressLifecycleObserver | None = None,
        pre_cleanup_barrier: (
            DockerWorkerPreCleanupBarrier | DockerWorkerSynchronousPreCleanupBarrier | None
        ) = None,
    ) -> None:
        if not allowed_images:
            raise ValueError("at least one Docker image must be allowlisted")
        image_pattern = r"[A-Za-z0-9][A-Za-z0-9._/@:-]*"
        if any(
            not isinstance(image, str) or re.fullmatch(image_pattern, image) is None
            for image in allowed_images
        ):
            raise ValueError("allowed Docker image contains unsupported characters")
        if (
            not isinstance(docker_executable, str)
            or not docker_executable
            or "\x00" in docker_executable
        ):
            raise ValueError("Docker executable must be a non-empty path without NUL bytes")
        if (
            not isinstance(egress_proxy_image, str)
            or re.fullmatch(image_pattern, egress_proxy_image) is None
        ):
            raise ValueError("egress proxy image contains unsupported characters")
        if (
            not isinstance(external_network, str)
            or re.fullmatch(_SAFE_RUNTIME_IDENTIFIER_PATTERN, external_network) is None
        ):
            raise ValueError("external Docker network must be a safe identifier")
        routes = dict(external_network_routes or {})
        if any(
            not isinstance(action, str)
            or re.fullmatch(_SAFE_RUNTIME_IDENTIFIER_PATTERN, action) is None
            or not isinstance(network, str)
            or re.fullmatch(_SAFE_RUNTIME_IDENTIFIER_PATTERN, network) is None
            for action, network in routes.items()
        ):
            raise ValueError("external Docker network routes must use safe identifiers")
        image_bindings = dict(runtime_image_bindings or {})
        if any(
            logical_image not in allowed_images
            or not isinstance(observed_image_id, str)
            or re.fullmatch(r"sha256:[a-f0-9]{64}", observed_image_id) is None
            for logical_image, observed_image_id in image_bindings.items()
        ):
            raise ValueError(
                "runtime Docker image bindings must map allowlisted images to OCI image IDs"
            )
        self._allowed_images = set(allowed_images)
        self._runtime_image_bindings = image_bindings
        self._docker = docker_executable
        self._egress_proxy_image = egress_proxy_image
        self._external_network = external_network
        self._external_network_routes = routes
        self._egress_lifecycle_observer = egress_lifecycle_observer
        self._egress_observer_context: dict[str, object] | None = None
        if egress_lifecycle_observer is not None:
            try:
                raw_context = egress_lifecycle_observer.stable_observer_context()
                encoded_context = json.dumps(
                    raw_context,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("utf-8")
                if (
                    not isinstance(raw_context, Mapping)
                    or len(encoded_context) > _MAX_EGRESS_OBSERVER_CONTEXT_BYTES
                ):
                    raise ValueError("observer context is not a bounded mapping")
                parsed_context = json.loads(encoded_context)
                if type(parsed_context) is not dict:
                    raise ValueError("observer context is not a JSON object")
            except (TypeError, ValueError) as exc:
                raise ValueError("egress lifecycle observer context is not canonical JSON") from exc
            self._egress_observer_context = parsed_context
        self._configure_pre_cleanup_barrier(pre_cleanup_barrier)

    def _configure_pre_cleanup_barrier(
        self,
        barrier: DockerWorkerPreCleanupBarrier | DockerWorkerSynchronousPreCleanupBarrier | None,
    ) -> None:
        if barrier is None:
            return
        synchronous_callback = getattr(barrier, "before_cleanup_sync", None)
        asynchronous_callback = getattr(barrier, "before_cleanup", None)
        if bool(callable(synchronous_callback)) == bool(callable(asynchronous_callback)):
            raise ValueError("pre-cleanup barrier must provide exactly one callback execution mode")
        if callable(synchronous_callback) and inspect.iscoroutinefunction(synchronous_callback):
            raise ValueError("synchronous pre-cleanup barrier callback must not be async")
        try:
            raw_context = barrier.stable_barrier_context()
            if not isinstance(raw_context, Mapping) or any(
                not isinstance(key, str) for key in raw_context
            ):
                raise ValueError("barrier context is not a string-keyed mapping")
            encoded_context = json.dumps(
                raw_context,
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
            if len(encoded_context) > _MAX_PRE_CLEANUP_BARRIER_CONTEXT_BYTES:
                raise ValueError("barrier context exceeds its byte limit")
            parsed_context = json.loads(encoded_context)
            if type(parsed_context) is not dict:
                raise ValueError("barrier context is not a JSON object")
        except (RecursionError, TypeError, ValueError) as exc:
            raise ValueError("pre-cleanup barrier context is not canonical JSON") from exc
        # Preserve the exact historical Docker backend instance state when the
        # additive barrier is absent. Some sealed runtimes attest that state.
        self._pre_cleanup_barrier = barrier
        self._pre_cleanup_barrier_context = parsed_context
        self._pre_cleanup_barrier_is_synchronous = callable(synchronous_callback)

    def stable_execution_context(self) -> dict[str, object]:
        context: dict[str, object] = {
            "implementationVersion": "pajin.docker-worker/v1",
            "allowedImages": sorted(self._allowed_images),
            "dockerExecutable": self._docker,
            "egressProxyImage": self._egress_proxy_image,
            "externalNetwork": self._external_network,
        }
        if self._runtime_image_bindings:
            context["implementationVersion"] = "pajin.docker-worker/v4"
            context["runtimeImageBindings"] = dict(sorted(self._runtime_image_bindings.items()))
        if self._external_network_routes:
            if not self._runtime_image_bindings:
                context["implementationVersion"] = "pajin.docker-worker/v2"
            context["externalNetworkRoutes"] = dict(sorted(self._external_network_routes.items()))
        if self._egress_observer_context is not None:
            if not self._runtime_image_bindings:
                context["implementationVersion"] = "pajin.docker-worker/v3"
            context["egressLifecycleObserver"] = json.loads(
                json.dumps(
                    self._egress_observer_context,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
        barrier_context = getattr(self, "_pre_cleanup_barrier_context", None)
        if barrier_context is not None:
            synchronous = getattr(self, "_pre_cleanup_barrier_is_synchronous", False)
            context["implementationVersion"] = (
                "pajin.docker-worker/v6" if synchronous else "pajin.docker-worker/v5"
            )
            context["preCleanupBarrier"] = json.loads(
                json.dumps(
                    barrier_context,
                    allow_nan=False,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                )
            )
            if synchronous:
                context["preCleanupBarrierExecution"] = {
                    "mode": "posix-main-thread-real-timer",
                    "timeoutSeconds": self._pre_cleanup_barrier_timeout_seconds,
                }
        return context

    def binds_egress_lifecycle_observer(self, observer: object) -> bool:
        """Return whether this backend owns the exact observer instance."""

        return self._egress_lifecycle_observer is observer

    def binds_pre_cleanup_barrier(self, barrier: object) -> bool:
        """Return whether this backend owns the exact pre-cleanup barrier instance."""

        return getattr(self, "_pre_cleanup_barrier", None) is barrier

    @property
    def _has_pre_cleanup_barrier(self) -> bool:
        return getattr(self, "_pre_cleanup_barrier", None) is not None

    async def _run_attempt_pre_cleanup_barrier(
        self,
        job: WorkerJob,
        result: WorkerResult | None,
    ) -> None:
        if not self._has_pre_cleanup_barrier:
            return
        barrier_result = (
            result if result is not None and result.status is not WorkerStatus.TIMED_OUT else None
        )
        observation = (
            DockerPreCleanupBarrierObservation.from_result(barrier_result)
            if barrier_result is not None
            else DockerPreCleanupBarrierObservation.outcome_unknown(job.execution_id)
        )
        await self._run_pre_cleanup_barrier(observation, result=barrier_result)

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        started_at = datetime.now(UTC)
        if job.image not in self._allowed_images:
            result = self._rejected(job, started_at, "container image is not allowlisted")
            await self._run_attempt_pre_cleanup_barrier(job, result)
            return result
        try:
            wire_stdin = self._wire_stdin(job, secrets or [])
        except ValueError as exc:
            result = WorkerResult(
                execution_id=job.execution_id,
                backend=self.name,
                status=WorkerStatus.REJECTED,
                exit_code=None,
                stderr=(
                    "worker input rejected: "
                    + audit_safe_exception_diagnostic(exc, stage="docker-worker-input")
                ),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )
            await self._run_attempt_pre_cleanup_barrier(job, result)
            return result

        container_name = self._container_name(job.execution_id)
        egress_runtime: _EgressRuntime | None = None
        process: asyncio.subprocess.Process | None = None
        force_remove = False
        attempt_result: WorkerResult | None = None
        observer_observation: DockerEgressLifecycleObservation | None = None
        observer_attached = False
        body_control_flow: asyncio.CancelledError | SystemExit | KeyboardInterrupt | None = None
        try:
            if job.network is NetworkMode.EGRESS_PROXY:
                try:
                    if self._has_pre_cleanup_barrier:
                        egress_runtime = self._new_egress_runtime(job)
                        await self._setup_egress(
                            job,
                            runtime=egress_runtime,
                            cleanup_on_failure=False,
                        )
                    else:
                        egress_runtime = await self._setup_egress(job)
                except RuntimeError as exc:
                    attempt_result = WorkerResult(
                        execution_id=job.execution_id,
                        backend=self.name,
                        status=WorkerStatus.FAILED,
                        failure_code=WorkerFailureCode.EGRESS_PROXY_SETUP_FAILED,
                        exit_code=None,
                        stderr=(
                            "egress proxy setup failed: "
                            + audit_safe_exception_diagnostic(
                                exc,
                                stage="egress-proxy-setup",
                            )
                        ),
                        started_at=started_at,
                        finished_at=datetime.now(UTC),
                    )
                    return attempt_result
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
                attempt_result = WorkerResult(
                    execution_id=job.execution_id,
                    backend=self.name,
                    status=WorkerStatus.FAILED,
                    exit_code=None,
                    stderr=(
                        "unable to start Docker CLI: "
                        + audit_safe_exception_diagnostic(
                            exc,
                            stage="docker-cli-start",
                        )
                    ),
                    started_at=started_at,
                    finished_at=datetime.now(UTC),
                )
                return attempt_result

            if egress_runtime is not None and self._egress_lifecycle_observer is not None:
                observer_observation = DockerEgressLifecycleObservation(
                    execution_id=job.execution_id,
                    worker_container_name=container_name,
                    proxy_container_name=egress_runtime.proxy_name,
                    internal_network_name=egress_runtime.network_name,
                    external_network_name=egress_runtime.external_network_name,
                )
                try:
                    await self._egress_lifecycle_observer.attached(observer_observation)
                except Exception as exc:
                    raise DockerEgressLifecycleObservationError(
                        stage="attached",
                        cause=exc,
                    ) from exc
                observer_attached = True

            capture = await self._execute_container_process(
                process,
                job=job,
                wire_stdin=wire_stdin,
                container_name=container_name,
            )
            force_remove = capture.timed_out
            network_log = ""
            if egress_runtime:
                network_log = await self._read_proxy_logs(
                    egress_runtime.proxy_name,
                    job.limits.stderr_bytes,
                )
            attempt_result = self._result_from_process_capture(
                job,
                capture,
                network_log=network_log,
                started_at=started_at,
            )
            return attempt_result
        except (asyncio.CancelledError, SystemExit, KeyboardInterrupt) as exc:
            body_control_flow = exc
            # The container name is known before the Docker CLI is spawned. Remove by
            # name even when process control races subprocess creation and no handle was
            # returned to this task.
            force_remove = True
            raise
        except BaseException:
            # The container name is known before the Docker CLI is spawned. Remove by
            # name even when cancellation races subprocess creation and no handle was
            # returned to this task.
            force_remove = True
            raise
        finally:
            await self._finish_attempt_cleanup(
                job=job,
                attempt_result=attempt_result,
                process=process,
                container_name=container_name,
                egress_runtime=egress_runtime,
                force_remove=force_remove,
                observer_observation=(observer_observation if observer_attached else None),
                body_control_flow=body_control_flow,
            )

    async def _finish_attempt_cleanup(
        self,
        *,
        job: WorkerJob,
        attempt_result: WorkerResult | None,
        process: asyncio.subprocess.Process | None,
        container_name: str,
        egress_runtime: _EgressRuntime | None,
        force_remove: bool,
        observer_observation: DockerEgressLifecycleObservation | None,
        body_control_flow: asyncio.CancelledError | SystemExit | KeyboardInterrupt | None,
    ) -> None:
        barrier_failure: BaseException | None = None
        try:
            await self._run_attempt_pre_cleanup_barrier(job, attempt_result)
        except BaseException as exc:
            barrier_failure = exc

        try:
            await self._cleanup_after_attempt(
                process=process,
                container_name=container_name,
                egress_runtime=egress_runtime,
                force_remove=force_remove,
                observer_observation=observer_observation,
            )
        except BaseException as cleanup_error:
            if barrier_failure is None:
                if self._has_pre_cleanup_barrier and body_control_flow is not None:
                    self._raise_control_flow_after_cleanup_failure(
                        body_control_flow,
                        cleanup_error,
                    )
                raise
            barrier_failure.add_note(
                "Docker cleanup also failed after the pre-cleanup durability barrier: "
                + audit_safe_exception_diagnostic(
                    cleanup_error,
                    stage="docker-cleanup",
                )
            )
            if body_control_flow is not None:
                self._raise_control_flow_after_barrier_failure(
                    body_control_flow,
                    barrier_failure,
                )
            raise barrier_failure from barrier_failure.__cause__
        if barrier_failure is not None:
            if body_control_flow is not None:
                self._raise_control_flow_after_barrier_failure(
                    body_control_flow,
                    barrier_failure,
                )
            raise barrier_failure

    async def _execute_container_process(
        self,
        process: asyncio.subprocess.Process,
        *,
        job: WorkerJob,
        wire_stdin: bytes,
        container_name: str,
    ) -> _ContainerProcessCapture:
        stdout_task = asyncio.create_task(
            self._read_bounded(process.stdout, job.limits.stdout_bytes)
        )
        stderr_task = asyncio.create_task(
            self._read_bounded(process.stderr, job.limits.stderr_bytes)
        )
        try:
            timed_out = await self._write_stdin_and_wait(
                process,
                wire_stdin=wire_stdin,
                timeout_seconds=job.limits.timeout_seconds,
                container_name=container_name,
                defer_container_cleanup=self._has_pre_cleanup_barrier,
            )
            if timed_out and self._has_pre_cleanup_barrier:
                return _ContainerProcessCapture(
                    timed_out=True,
                    exit_code=None,
                    stdout=b"",
                    stderr=b"",
                    stdout_truncated=False,
                    stderr_truncated=False,
                )
            (stdout, stdout_truncated), (stderr, stderr_truncated) = await asyncio.gather(
                stdout_task,
                stderr_task,
            )
            return _ContainerProcessCapture(
                timed_out=timed_out,
                exit_code=process.returncode,
                stdout=stdout,
                stderr=stderr,
                stdout_truncated=stdout_truncated,
                stderr_truncated=stderr_truncated,
            )
        finally:
            for task in (stdout_task, stderr_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

    async def _write_stdin_and_wait(
        self,
        process: asyncio.subprocess.Process,
        *,
        wire_stdin: bytes,
        timeout_seconds: float,
        container_name: str,
        defer_container_cleanup: bool = False,
    ) -> bool:
        async def send_stdin_and_wait_for_exit() -> None:
            assert process.stdin is not None
            try:
                try:
                    process.stdin.write(wire_stdin)
                    await process.stdin.drain()
                except (BrokenPipeError, ConnectionResetError):
                    # A short-lived container may exit before consuming all stdin.
                    # Its exit status and bounded stderr remain authoritative.
                    pass
            finally:
                process.stdin.close()
            await process.wait()

        try:
            await asyncio.wait_for(send_stdin_and_wait_for_exit(), timeout=timeout_seconds)
        except TimeoutError:
            if not defer_container_cleanup:
                if process.returncode is None:
                    with suppress(ProcessLookupError):
                        process.kill()
                    with suppress(TimeoutError):
                        await asyncio.wait_for(
                            process.wait(),
                            timeout=self._process_stop_timeout_seconds,
                        )
                await self._force_remove(container_name)
            return True
        return False

    def _result_from_process_capture(
        self,
        job: WorkerJob,
        capture: _ContainerProcessCapture,
        *,
        network_log: str,
        started_at: datetime,
    ) -> WorkerResult:
        status = (
            WorkerStatus.TIMED_OUT
            if capture.timed_out
            else WorkerStatus.SUCCEEDED
            if capture.exit_code == 0
            else WorkerStatus.FAILED
        )
        exit_code = capture.exit_code
        if capture.timed_out and exit_code == 0:
            exit_code = None
        return WorkerResult(
            execution_id=job.execution_id,
            backend=self.name,
            status=status,
            exit_code=exit_code,
            stdout=capture.stdout.decode("utf-8", errors="replace"),
            stderr=capture.stderr.decode("utf-8", errors="replace"),
            network_log=network_log,
            stdout_truncated=capture.stdout_truncated,
            stderr_truncated=capture.stderr_truncated,
            started_at=started_at,
            finished_at=datetime.now(UTC),
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
        auto_remove_args = [] if self._has_pre_cleanup_barrier else ["--rm"]
        return [
            "run",
            *auto_remove_args,
            "--interactive",
            "--init",
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
            (
                "/workspace:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532,"
                f"size={limits.workspace_mb}m"
            ),
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,mode=0700,uid=65532,gid=65532,size=16m",
            "--stop-timeout",
            "1",
            self._runtime_image_bindings.get(job.image, job.image),
            *job.command,
        ]

    def _new_egress_runtime(self, job: WorkerJob) -> _EgressRuntime:
        # Keep resource ownership collision-resistant even on long-lived Docker
        # hosts. Cleanup is name-based after CLI timeouts, so truncating this
        # nonce could otherwise make an unrelated execution a removal target.
        suffix = uuid4().hex
        external_network = self._external_network_routes.get(job.command[0], self._external_network)
        return _EgressRuntime(
            network_name=f"pajin-egress-{suffix}",
            proxy_name=f"pajin-proxy-{suffix}",
            external_network_name=external_network,
        )

    async def _setup_egress(
        self,
        job: WorkerJob,
        *,
        runtime: _EgressRuntime | None = None,
        cleanup_on_failure: bool = True,
    ) -> _EgressRuntime:
        policy = job.egress_policy
        if policy is None:
            raise RuntimeError("egress policy is missing")
        runtime = runtime or self._new_egress_runtime(job)
        network_name = runtime.network_name
        proxy_name = runtime.proxy_name
        external_network = runtime.external_network_name
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

            policy_json = self._proxy_policy_json(job)
            policy_b64 = b64encode(policy_json.encode("utf-8")).decode("ascii")
            code, _, error = await self._run_cli(
                [
                    "run",
                    "--detach",
                    *([] if self._has_pre_cleanup_barrier else ["--rm"]),
                    "--init",
                    "--pull",
                    "never",
                    "--name",
                    proxy_name,
                    "--label",
                    f"pajin.execution-id={job.execution_id}",
                    "--network",
                    external_network,
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
            if not ready and cleanup_on_failure:
                await self._drain_cleanup(
                    self._cleanup_egress(runtime),
                    resources=[
                        ("egress proxy", runtime.proxy_name),
                        ("network", runtime.network_name),
                    ],
                )

    @staticmethod
    def _proxy_policy_json(job: WorkerJob) -> str:
        """Build the proxy-only policy without mutating caller-owned policy state."""

        policy = job.egress_policy
        if policy is None:
            raise ValueError("egress-proxy job requires an egress policy")
        payload = policy.model_dump(mode="json")
        payload["max_exchange_seconds"] = job.limits.timeout_seconds
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )

    async def _wait_proxy_healthy(self, proxy_name: str) -> bool:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._proxy_health_timeout_seconds
        initial_delay = min(
            self._proxy_health_initial_delay_seconds,
            max(0.0, deadline - loop.time()),
        )
        if initial_delay:
            await asyncio.sleep(initial_delay)

        while loop.time() < deadline:
            code, output, _ = await self._run_cli(
                ["inspect", "--format", "{{.State.Health.Status}}", proxy_name],
                timeout=2,
            )
            if code == 0 and output.strip() == "healthy":
                return True
            if code == 0 and output.strip() == "unhealthy":
                return False
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            await asyncio.sleep(min(self._proxy_health_poll_interval_seconds, remaining))
        return False

    async def _read_proxy_logs(self, proxy_name: str, limit: int) -> str:
        _, output, error = await self._run_cli(
            ["logs", "--tail", "200", proxy_name],
            timeout=5,
            stdout_limit=limit,
            stderr_limit=limit,
        )
        data = (output + error).encode("utf-8")[:limit]
        return data.decode("utf-8", errors="replace")

    async def _run_pre_cleanup_barrier(
        self,
        observation: DockerPreCleanupBarrierObservation,
        *,
        result: WorkerResult | None,
    ) -> None:
        barrier = getattr(self, "_pre_cleanup_barrier", None)
        if barrier is None:
            return

        if getattr(self, "_pre_cleanup_barrier_is_synchronous", False):
            try:
                self._run_synchronous_pre_cleanup_barrier(
                    barrier,
                    observation,
                    result=result,
                )
            except (
                DockerPreCleanupBarrierDeadlineExceeded,
                asyncio.CancelledError,
                SystemExit,
                KeyboardInterrupt,
            ):
                raise
            except BaseException as exc:
                raise DockerPreCleanupBarrierError(cause=exc) from exc
            return

        async def invoke_bounded_callback() -> None:
            async with asyncio.timeout(self._pre_cleanup_barrier_timeout_seconds):
                await barrier.before_cleanup(observation, result)

        try:
            callback_task = asyncio.create_task(invoke_bounded_callback())
        except BaseException as exc:
            raise DockerPreCleanupBarrierError(cause=exc) from exc

        interrupted = False
        while not callback_task.done():
            try:
                await asyncio.shield(callback_task)
            except asyncio.CancelledError:
                interrupted = True
            except BaseException:
                break
        try:
            callback_task.result()
        except BaseException as exc:
            raise DockerPreCleanupBarrierError(cause=exc) from exc
        if interrupted:
            raise asyncio.CancelledError()

    def _run_synchronous_pre_cleanup_barrier(
        self,
        barrier: object,
        observation: DockerPreCleanupBarrierObservation,
        *,
        result: WorkerResult | None,
    ) -> None:
        callback = getattr(barrier, "before_cleanup_sync", None)
        if not callable(callback):
            raise RuntimeError("synchronous pre-cleanup barrier callback is unavailable")
        if os.name != "posix" or not all(
            hasattr(signal, attribute)
            for attribute in ("SIGALRM", "ITIMER_REAL", "getitimer", "setitimer")
        ):
            raise RuntimeError("synchronous pre-cleanup barrier requires POSIX real timers")
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError("synchronous pre-cleanup barrier requires the main thread")
        if not _PRE_CLEANUP_SIGNAL_DEADLINE_LOCK.acquire(blocking=False):
            raise RuntimeError("synchronous pre-cleanup barrier deadline is already in use")

        previous_handler: signal._HANDLER | None = None
        previous_timer: tuple[float, float] | None = None
        handler_installed = False

        def deadline_handler(signum: int, frame: FrameType | None) -> None:
            del signum, frame
            raise DockerPreCleanupBarrierDeadlineExceeded(
                "synchronous pre-cleanup barrier exceeded its hard deadline"
            )

        try:
            previous_handler = signal.getsignal(signal.SIGALRM)
            previous_timer = signal.getitimer(signal.ITIMER_REAL)
            if previous_timer != (0.0, 0.0):
                raise RuntimeError(
                    "synchronous pre-cleanup barrier cannot replace an active real timer"
                )
            signal.signal(signal.SIGALRM, deadline_handler)
            handler_installed = True
            signal.setitimer(
                signal.ITIMER_REAL,
                self._pre_cleanup_barrier_timeout_seconds,
            )
            returned = callback(observation, result)
            if inspect.iscoroutine(returned):
                returned.close()
            if inspect.isawaitable(returned):
                raise TypeError("synchronous pre-cleanup barrier callback returned an awaitable")
            if returned is not None:
                raise TypeError("synchronous pre-cleanup barrier callback must return None")
        finally:
            try:
                if handler_installed:
                    signal.setitimer(signal.ITIMER_REAL, 0.0)
                    assert previous_handler is not None
                    signal.signal(signal.SIGALRM, previous_handler)
                    assert previous_timer is not None
                    signal.setitimer(signal.ITIMER_REAL, *previous_timer)
            finally:
                _PRE_CLEANUP_SIGNAL_DEADLINE_LOCK.release()

    async def _cleanup_after_attempt(
        self,
        *,
        process: asyncio.subprocess.Process | None,
        container_name: str,
        egress_runtime: _EgressRuntime | None,
        force_remove: bool,
        observer_observation: DockerEgressLifecycleObservation | None,
    ) -> None:
        if not (force_remove or process is not None or egress_runtime is not None):
            return
        remove_worker = force_remove or (self._has_pre_cleanup_barrier and process is not None)
        cleanup_resources: list[tuple[str, str]] = []
        if remove_worker or process is not None:
            cleanup_resources.append(("container", container_name))
        if egress_runtime is not None:
            cleanup_resources.extend(
                [
                    ("egress proxy", egress_runtime.proxy_name),
                    ("network", egress_runtime.network_name),
                ]
            )
        await self._drain_cleanup(
            self._cleanup_execution(
                process=process,
                container_name=container_name,
                egress_runtime=egress_runtime,
                force_remove=remove_worker,
                observer_observation=observer_observation,
            ),
            resources=cleanup_resources,
        )

    async def _cleanup_egress(self, runtime: _EgressRuntime) -> None:
        failures: list[_CleanupFailure] = []
        try:
            try:
                await self._remove_docker_resource(
                    resource_kind="egress proxy",
                    resource_id=runtime.proxy_name,
                    args=["rm", "--force", runtime.proxy_name],
                )
            except Exception as exc:
                failures.extend(
                    self._cleanup_failures_from_exception(
                        exc,
                        resources=[("egress proxy", runtime.proxy_name)],
                    )
                )
        finally:
            try:
                await self._remove_docker_resource(
                    resource_kind="network",
                    resource_id=runtime.network_name,
                    args=["network", "rm", runtime.network_name],
                )
            except Exception as exc:
                failures.extend(
                    self._cleanup_failures_from_exception(
                        exc,
                        resources=[("network", runtime.network_name)],
                    )
                )
        if failures:
            raise WorkerCleanupError(failures)

    async def _cleanup_execution(
        self,
        *,
        process: asyncio.subprocess.Process | None,
        container_name: str,
        egress_runtime: _EgressRuntime | None,
        force_remove: bool,
        observer_observation: DockerEgressLifecycleObservation | None,
    ) -> None:
        failures: list[_CleanupFailure] = []
        try:
            if force_remove:
                if process is not None and process.returncode is None:
                    with suppress(OSError, ProcessLookupError):
                        process.kill()
                    with suppress(OSError, ProcessLookupError, TimeoutError):
                        await asyncio.wait_for(
                            process.wait(),
                            timeout=self._process_stop_timeout_seconds,
                        )
                try:
                    await self._force_remove(container_name)
                except Exception as exc:
                    failures.extend(
                        self._cleanup_failures_from_exception(
                            exc,
                            resources=[("container", container_name)],
                        )
                    )
        finally:
            if egress_runtime is not None:
                try:
                    await self._cleanup_egress(egress_runtime)
                except Exception as exc:
                    failures.extend(
                        self._cleanup_failures_from_exception(
                            exc,
                            resources=[
                                ("egress proxy", egress_runtime.proxy_name),
                                ("network", egress_runtime.network_name),
                            ],
                        )
                    )
        if failures:
            raise WorkerCleanupError(failures)
        if observer_observation is not None and self._egress_lifecycle_observer is not None:
            try:
                await self._egress_lifecycle_observer.cleaned(observer_observation)
            except Exception as exc:
                raise DockerEgressLifecycleObservationError(
                    stage="cleaned",
                    cause=exc,
                ) from exc

    async def _drain_cleanup(
        self,
        cleanup: Awaitable[None],
        *,
        resources: list[tuple[str, str]],
    ) -> None:
        cleanup_task = asyncio.create_task(
            asyncio.wait_for(cleanup, timeout=self._cleanup_timeout_seconds)
        )
        interruption: asyncio.CancelledError | None = None
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError as exc:
                if interruption is None:
                    interruption = exc
            except Exception:
                break
        try:
            cleanup_task.result()
        except BaseException as exc:
            cleanup_error = self._normalize_cleanup_task_failure(exc, resources=resources)
            if interruption is not None and self._has_pre_cleanup_barrier:
                self._raise_control_flow_after_cleanup_failure(interruption, cleanup_error)
            if cleanup_error is exc:
                raise
            raise cleanup_error from exc
        if interruption is not None:
            if self._has_pre_cleanup_barrier:
                raise interruption
            raise asyncio.CancelledError()

    def _normalize_cleanup_task_failure(
        self,
        failure: BaseException,
        *,
        resources: list[tuple[str, str]],
    ) -> BaseException:
        if isinstance(
            failure,
            (DockerEgressLifecycleObservationError, WorkerCleanupError),
        ):
            return failure
        if isinstance(failure, asyncio.CancelledError):
            return WorkerCleanupError(
                self._cleanup_failures(
                    resources,
                    "cleanup task was cancelled before removal could be confirmed",
                )
            )
        if isinstance(failure, TimeoutError):
            return WorkerCleanupError(
                self._cleanup_failures(
                    resources,
                    f"cleanup exceeded {self._cleanup_timeout_seconds:g} seconds",
                )
            )
        if isinstance(failure, Exception):
            return WorkerCleanupError(
                self._cleanup_failures_from_exception(failure, resources=resources)
            )
        return failure

    @staticmethod
    def _raise_control_flow_after_cleanup_failure(
        control_flow: asyncio.CancelledError | SystemExit | KeyboardInterrupt,
        cleanup_error: BaseException,
    ) -> Never:
        control_flow.add_note(
            "Docker cleanup also failed while preserving Worker process control: "
            + audit_safe_exception_diagnostic(cleanup_error, stage="docker-cleanup")
        )
        try:
            raise cleanup_error
        except BaseException:
            raise control_flow from control_flow.__cause__

    @staticmethod
    def _raise_control_flow_after_barrier_failure(
        control_flow: asyncio.CancelledError | SystemExit | KeyboardInterrupt,
        barrier_failure: BaseException,
    ) -> Never:
        control_flow.add_note(
            "Docker pre-cleanup durability barrier also failed while preserving Worker "
            "process control: "
            + audit_safe_exception_diagnostic(barrier_failure, stage="worker-backend")
        )
        try:
            raise barrier_failure
        except BaseException:
            raise control_flow from control_flow.__cause__

    async def _remove_docker_resource(
        self,
        *,
        resource_kind: str,
        resource_id: str,
        args: list[str],
    ) -> None:
        attempt_diagnostics: list[str] = []
        for attempt in range(1, self._cleanup_attempts + 1):
            code, output, error = await self._run_cli(
                args,
                timeout=self._cleanup_command_timeout_seconds,
            )
            diagnostic = self._bounded_cli_diagnostic(output, error)
            if code == 0 or self._resource_is_absent(resource_kind, diagnostic):
                return
            attempt_diagnostics.append(
                f"attempt {attempt}/{self._cleanup_attempts} exited {code}: {diagnostic}"
            )
            if attempt < self._cleanup_attempts:
                await asyncio.sleep(0)
        raise WorkerCleanupError(
            [
                _CleanupFailure(
                    resource_kind=resource_kind,
                    resource_id=resource_id,
                    detail="; ".join(attempt_diagnostics),
                )
            ]
        )

    @staticmethod
    def _bounded_cli_diagnostic(output: str, error: str) -> str:
        diagnostic = " ".join(part.strip() for part in (error, output) if part.strip())
        return " ".join(diagnostic.split())[:500] or "Docker CLI returned no diagnostic"

    @staticmethod
    def _resource_is_absent(resource_kind: str, diagnostic: str) -> bool:
        normalized = diagnostic.casefold()
        if resource_kind in {"container", "egress proxy"}:
            return "no such container" in normalized
        return "no such network" in normalized or (
            "network" in normalized and "not found" in normalized
        )

    @staticmethod
    def _cleanup_failures(
        resources: list[tuple[str, str]],
        detail: str,
    ) -> list[_CleanupFailure]:
        return [
            _CleanupFailure(
                resource_kind=resource_kind,
                resource_id=resource_id,
                detail=detail,
            )
            for resource_kind, resource_id in resources
        ]

    @classmethod
    def _cleanup_failures_from_exception(
        cls,
        exc: Exception,
        *,
        resources: list[tuple[str, str]],
    ) -> list[_CleanupFailure]:
        if isinstance(exc, WorkerCleanupError):
            return list(exc.failures)
        detail = audit_safe_exception_diagnostic(exc, stage="docker-cleanup")
        return cls._cleanup_failures(
            resources,
            detail or "cleanup failed without a diagnostic",
        )

    async def _run_cli(
        self,
        args: list[str],
        *,
        timeout: float = 10,
        stdout_limit: int | None = None,
        stderr_limit: int | None = None,
    ) -> tuple[int, str, str]:
        if stdout_limit is None:
            stdout_limit = self._cli_stdout_limit_bytes
        if stderr_limit is None:
            stderr_limit = self._cli_stderr_limit_bytes
        if stdout_limit <= 0 or stderr_limit <= 0:
            raise ValueError("Docker CLI output limits must be positive")
        try:
            process = await asyncio.create_subprocess_exec(
                self._docker,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError as exc:
            return (
                127,
                "",
                audit_safe_exception_diagnostic(exc, stage="docker-cli-start"),
            )

        stdout_task = asyncio.create_task(self._read_bounded(process.stdout, stdout_limit))
        stderr_task = asyncio.create_task(self._read_bounded(process.stderr, stderr_limit))
        try:
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout)
            except TimeoutError:
                await self._stop_cli_process(process)
                return 124, "", "Docker CLI command timed out"
            (stdout, stdout_truncated), (stderr, stderr_truncated) = await asyncio.gather(
                stdout_task, stderr_task
            )
        except asyncio.CancelledError:
            await self._stop_cli_process(process)
            raise
        except BaseException:
            await self._stop_cli_process(process)
            raise
        finally:
            for task in (stdout_task, stderr_task):
                if not task.done():
                    task.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

        if stdout_truncated or stderr_truncated:
            exceeded = " and ".join(
                stream
                for stream, truncated in (
                    ("stdout", stdout_truncated),
                    ("stderr", stderr_truncated),
                )
                if truncated
            )
            return (
                self._cli_output_limit_exit_code,
                "",
                f"Docker CLI {exceeded} exceeded its bounded output limit",
            )
        return (
            process.returncode or 0,
            stdout.decode("utf-8", errors="replace"),
            stderr.decode("utf-8", errors="replace"),
        )

    async def _stop_cli_process(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        with suppress(OSError, ProcessLookupError):
            process.kill()
        with suppress(OSError, ProcessLookupError, TimeoutError):
            await asyncio.wait_for(
                process.wait(),
                timeout=self._process_stop_timeout_seconds,
            )

    async def _force_remove(self, container_name: str) -> None:
        await self._remove_docker_resource(
            resource_kind="container",
            resource_id=container_name,
            args=["rm", "--force", container_name],
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
        if len(supplied_bindings) != len(secrets):
            raise ValueError("worker secret material bindings must be unique")
        if requested_bindings != supplied_bindings:
            raise ValueError("worker secret material does not match requested bindings")
        encoded_stdin = job.stdin.encode("utf-8")
        if not secrets:
            return encoded_stdin
        payload = parse_strict_json_bytes(
            encoded_stdin,
            label="secret-bearing Worker stdin",
            max_bytes=job.stdin_byte_limit,
        )
        if not isinstance(payload, dict):
            raise ValueError("secret-bearing Worker stdin must be a JSON object")
        envelope = {
            "pajinEnvelopeVersion": 1,
            "payload": payload,
            "secrets": {
                item.binding: item.value for item in sorted(secrets, key=lambda item: item.binding)
            },
        }
        wire = json.dumps(
            envelope,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
        ).encode("utf-8")
        wire_limit = (
            MAX_LARGE_PROVIDER_INPUT_BYTES + 100_000
            if job.command == [LARGE_PROVIDER_ACTION]
            else _MAX_WORKER_WIRE_INPUT_BYTES
        )
        if len(wire) > wire_limit:
            raise ValueError("secret-bearing Worker envelope exceeded its byte limit")
        return wire

    @staticmethod
    def _container_name(execution_id: str) -> str:
        safe = re.sub(r"[^a-zA-Z0-9_.-]", "-", execution_id)[:50]
        return f"pajin-{safe}-{uuid4().hex}".lower()

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
