"""Isolated worker backends for executing policy-approved tool jobs."""

from __future__ import annotations

import asyncio
import json
import re
from abc import abstractmethod
from base64 import b64encode
from collections.abc import Awaitable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Protocol
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
_MAX_EGRESS_PROXY_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_EGRESS_OBSERVER_CONTEXT_BYTES = 64 * 1024


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
    stdin: str = Field(default="", max_length=_MAX_WORKER_STDIN_BYTES)
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
        if len(encoded) > _MAX_WORKER_STDIN_BYTES:
            raise ValueError("worker stdin exceeded its UTF-8 byte limit")
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
        return context

    def binds_egress_lifecycle_observer(self, observer: object) -> bool:
        """Return whether this backend owns the exact observer instance."""

        return self._egress_lifecycle_observer is observer

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
                stderr=(
                    "worker input rejected: "
                    + audit_safe_exception_diagnostic(exc, stage="docker-worker-input")
                ),
                started_at=started_at,
                finished_at=datetime.now(UTC),
            )

        container_name = self._container_name(job.execution_id)
        egress_runtime: _EgressRuntime | None = None
        process: asyncio.subprocess.Process | None = None
        force_remove = False
        observer_observation: DockerEgressLifecycleObservation | None = None
        observer_attached = False
        try:
            if job.network is NetworkMode.EGRESS_PROXY:
                try:
                    egress_runtime = await self._setup_egress(job)
                except RuntimeError as exc:
                    return WorkerResult(
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
            return self._result_from_process_capture(
                job,
                capture,
                network_log=network_log,
                started_at=started_at,
            )
        except BaseException:
            # The container name is known before the Docker CLI is spawned. Remove by
            # name even when cancellation races subprocess creation and no handle was
            # returned to this task.
            force_remove = True
            raise
        finally:
            if force_remove or process is not None or egress_runtime is not None:
                cleanup_resources: list[tuple[str, str]] = []
                if force_remove or process is not None:
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
                        force_remove=force_remove,
                        observer_observation=(observer_observation if observer_attached else None),
                    ),
                    resources=cleanup_resources,
                )

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
        return [
            "run",
            "--rm",
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

    async def _setup_egress(self, job: WorkerJob) -> _EgressRuntime:
        policy = job.egress_policy
        if policy is None:
            raise RuntimeError("egress policy is missing")
        # Keep resource ownership collision-resistant even on long-lived Docker
        # hosts. Cleanup is name-based after CLI timeouts, so truncating this
        # nonce could otherwise make an unrelated execution a removal target.
        suffix = uuid4().hex
        network_name = f"pajin-egress-{suffix}"
        proxy_name = f"pajin-proxy-{suffix}"
        external_network = self._external_network_routes.get(job.command[0], self._external_network)
        runtime = _EgressRuntime(
            network_name=network_name,
            proxy_name=proxy_name,
            external_network_name=external_network,
        )
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
                    "--rm",
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
            if not ready:
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
        interrupted = False
        while not cleanup_task.done():
            try:
                await asyncio.shield(cleanup_task)
            except asyncio.CancelledError:
                interrupted = True
            except Exception:
                break
        try:
            cleanup_task.result()
        except DockerEgressLifecycleObservationError:
            raise
        except WorkerCleanupError:
            raise
        except asyncio.CancelledError as exc:
            raise WorkerCleanupError(
                self._cleanup_failures(
                    resources,
                    "cleanup task was cancelled before removal could be confirmed",
                )
            ) from exc
        except TimeoutError as exc:
            raise WorkerCleanupError(
                self._cleanup_failures(
                    resources,
                    f"cleanup exceeded {self._cleanup_timeout_seconds:g} seconds",
                )
            ) from exc
        except Exception as exc:
            raise WorkerCleanupError(
                self._cleanup_failures_from_exception(exc, resources=resources)
            ) from exc
        if interrupted:
            raise asyncio.CancelledError()

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
            max_bytes=_MAX_WORKER_STDIN_BYTES,
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
        if len(wire) > _MAX_WORKER_WIRE_INPUT_BYTES:
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
