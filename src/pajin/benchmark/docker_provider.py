"""P0-C2B2B local Docker provider for the synthetic Bug Bounty benchmark."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sqlite3
import subprocess
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from typing import Annotated, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.measurement import WalkingBenchmarkRunObservation
from pajin.benchmark.models import BenchmarkManifest, benchmark_digest, canonical_benchmark_json
from pajin.benchmark.target_factory import (
    BenchmarkMeasurementAttestation,
    BenchmarkMeasurementAttestationStatement,
    BenchmarkMeasurementAttestor,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkTargetCoordinate,
    BenchmarkTargetStage,
    BenchmarkTargetStageReceipt,
    RegisteredBenchmarkTargetFactoryAdapter,
)
from pajin.benchmark.target_recovery import (
    BenchmarkTargetOperation,
    BenchmarkTargetRecoveryRequest,
)
from pajin.domain.models import StrictModel

DOCKER_BUG_BOUNTY_TARGET_PROFILE_API_VERSION: Literal[
    "pajin.dev/docker-bug-bounty-target-profile/v1alpha1"
] = "pajin.dev/docker-bug-bounty-target-profile/v1alpha1"
DOCKER_AI_RAG_MCP_TARGET_PROFILE_API_VERSION: Literal[
    "pajin.dev/docker-ai-rag-mcp-target-profile/v1alpha1"
] = "pajin.dev/docker-ai-rag-mcp-target-profile/v1alpha1"
DOCKER_BENCHMARK_PROVIDER_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/docker-benchmark-provider-evidence/v1alpha1"
] = "pajin.dev/docker-benchmark-provider-evidence/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageId = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
_MAX_PROVIDER_RESULT_BYTES = 4 * 1024 * 1024
_BUSY_TIMEOUT_MS = 5_000
_MANAGED_LABEL = "pajin.benchmark.managed"
_ADAPTER_LABEL = "pajin.benchmark.adapter-digest"
_COORDINATE_LABEL = "pajin.benchmark.coordinate-digest"
_FENCE_LABEL = "pajin.benchmark.fence"
_ROLE_LABEL = "pajin.benchmark.role"
_AI_RAG_MCP_SCENARIO = "ai-rag-mcp.docker.file-upload-rag-tool-authorization"
_AI_RAG_MCP_TARGET = "http://target:8080"
_AI_RAG_MCP_DOCUMENT_ID = "document:untrusted-upload"
_AI_RAG_MCP_INPUT_MARKER = "ignore previous"
_AI_RAG_MCP_TOOL_ARGUMENT = "internal://policy"
_AI_RAG_MCP_OBSERVATION = "untrusted text contains an instruction-hijacking pattern"


class DockerBenchmarkProviderError(RuntimeError):
    """Raised when Docker cannot prove an exact, fenced Target lifecycle fact."""


class DockerBugBountyTargetProfile(StrictModel):
    """Content-addressed images and policy for the one supported synthetic lab."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/docker-bug-bounty-target-profile/v1alpha1"] = Field(
        default=DOCKER_BUG_BOUNTY_TARGET_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DockerBugBountyTargetProfile"] = "DockerBugBountyTargetProfile"
    profile_id: Literal["bug-bounty.api.boolean-sqli-lab"] = Field(
        default="bug-bounty.api.boolean-sqli-lab",
        alias="profileId",
    )
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    target_image: Literal["pajin-bug-bounty-target:dev"] = Field(alias="targetImage")
    target_image_id: _ImageId = Field(alias="targetImageId")
    worker_image: Literal["pajin-benchmark-worker:dev"] = Field(alias="workerImage")
    worker_image_id: _ImageId = Field(alias="workerImageId")
    network_mode: Literal["internal-bridge"] = Field(
        default="internal-bridge",
        alias="networkMode",
    )
    target_profile: Literal["vulnerable"] = Field(
        default="vulnerable",
        alias="targetProfile",
    )
    target_factory_digest: str = Field(default="", alias="targetFactoryDigest", max_length=64)

    @field_validator("target_image", "worker_image")
    @classmethod
    def require_safe_image_reference(cls, value: str) -> str:
        if value.strip() != value or any(character in value for character in "\x00\r\n"):
            raise ValueError("Docker image reference is unsafe")
        return value

    @model_validator(mode="after")
    def bind_target_factory(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"target_factory_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.docker-bug-bounty-target-profile/v1",
            material,
            max_bytes=64 * 1024,
        )
        if self.target_factory_digest and self.target_factory_digest != digest:
            raise ValueError("Docker Bug Bounty Target Factory Digest differs")
        object.__setattr__(self, "target_factory_digest", digest)
        return self


class DockerAIRAGMCPTargetProfile(StrictModel):
    """Content-addressed images and policy for the runnable synthetic AI chain."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/docker-ai-rag-mcp-target-profile/v1alpha1"] = Field(
        default=DOCKER_AI_RAG_MCP_TARGET_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DockerAIRAGMCPTargetProfile"] = "DockerAIRAGMCPTargetProfile"
    profile_id: Literal[
        "ai-rag-mcp.docker.file-upload-rag-tool-authorization"
    ] = Field(
        default="ai-rag-mcp.docker.file-upload-rag-tool-authorization",
        alias="profileId",
    )
    profile_version: Literal["1.0.0"] = Field(default="1.0.0", alias="profileVersion")
    target_image: Literal["pajin-ai-rag-mcp-target:dev"] = Field(alias="targetImage")
    target_image_id: _ImageId = Field(alias="targetImageId")
    worker_image: Literal["pajin-ai-rag-mcp-benchmark-worker:dev"] = Field(
        alias="workerImage"
    )
    worker_image_id: _ImageId = Field(alias="workerImageId")
    network_mode: Literal["internal-bridge"] = Field(
        default="internal-bridge",
        alias="networkMode",
    )
    target_state: Literal["vulnerable-missing-independent-approval"] = Field(
        default="vulnerable-missing-independent-approval",
        alias="targetState",
    )
    target_factory_digest: str = Field(default="", alias="targetFactoryDigest", max_length=64)

    @field_validator("target_image", "worker_image")
    @classmethod
    def require_safe_image_reference(cls, value: str) -> str:
        if value.strip() != value or any(character in value for character in "\x00\r\n"):
            raise ValueError("Docker image reference is unsafe")
        return value

    @model_validator(mode="after")
    def bind_target_factory(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"target_factory_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.docker-ai-rag-mcp-target-profile/v1",
            material,
            max_bytes=64 * 1024,
        )
        if self.target_factory_digest and self.target_factory_digest != digest:
            raise ValueError("Docker AI/RAG/MCP Target Factory Digest differs")
        object.__setattr__(self, "target_factory_digest", digest)
        return self


class _DockerTargetProfile(Protocol):
    @property
    def profile_id(self) -> str: ...

    @property
    def profile_version(self) -> str: ...

    @property
    def target_image(self) -> str: ...

    @property
    def target_image_id(self) -> str: ...

    @property
    def worker_image(self) -> str: ...

    @property
    def worker_image_id(self) -> str: ...

    @property
    def target_factory_digest(self) -> str: ...


DockerTargetProfile = DockerBugBountyTargetProfile | DockerAIRAGMCPTargetProfile


class DockerBenchmarkProviderEvidence(StrictModel):
    """Bounded provider observations behind one Target stage receipt digest."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/docker-benchmark-provider-evidence/v1alpha1"] = Field(
        default=DOCKER_BENCHMARK_PROVIDER_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["DockerBenchmarkProviderEvidence"] = "DockerBenchmarkProviderEvidence"
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    adapter_digest: _Sha256 = Field(alias="adapterDigest")
    coordinate_digest: _Sha256 = Field(alias="coordinateDigest")
    operation_id: str = Field(alias="operationId", min_length=1, max_length=110)
    operation_digest: _Sha256 = Field(alias="operationDigest")
    fence: int = Field(ge=1, le=2**63 - 1)
    stage: Literal["reset", "isolation", "execution", "cleanup"]
    environment_id: str = Field(alias="environmentId", min_length=1, max_length=110)
    isolation_id: str | None = Field(default=None, alias="isolationId", max_length=110)
    docker_server_version: str = Field(alias="dockerServerVersion", min_length=1, max_length=100)
    target_image_id: _ImageId = Field(alias="targetImageId")
    worker_image_id: _ImageId = Field(alias="workerImageId")
    target_container_id: _Sha256 | None = Field(default=None, alias="targetContainerId")
    worker_container_id: _Sha256 | None = Field(default=None, alias="workerContainerId")
    network_id: _Sha256 | None = Field(default=None, alias="networkId")
    network_internal: bool | None = Field(default=None, alias="networkInternal")
    published_port_count: int | None = Field(default=None, alias="publishedPortCount", ge=0)
    network_container_count: int | None = Field(
        default=None,
        alias="networkContainerCount",
        ge=0,
    )
    target_healthy: bool | None = Field(default=None, alias="targetHealthy")
    worker_exit_code: int | None = Field(default=None, alias="workerExitCode", ge=0, le=255)
    probe_vulnerable: bool | None = Field(default=None, alias="probeVulnerable")
    probe_output_sha256: _Sha256 | None = Field(default=None, alias="probeOutputSha256")
    scanner_registration_digest: _Sha256 | None = Field(
        default=None, alias="scannerRegistrationDigest"
    )
    scanner_plan_digest: _Sha256 | None = Field(default=None, alias="scannerPlanDigest")
    scanner_image_id: _ImageId | None = Field(default=None, alias="scannerImageId")
    scanner_container_id: _Sha256 | None = Field(
        default=None, alias="scannerContainerId"
    )
    raw_sarif_sha256: _Sha256 | None = Field(default=None, alias="rawSarifSha256")
    raw_sarif_size_bytes: int | None = Field(
        default=None, alias="rawSarifSizeBytes", ge=1, le=16 * 1024 * 1024
    )
    sarif_normalization_digest: _Sha256 | None = Field(
        default=None, alias="sarifNormalizationDigest"
    )
    resources_absent: bool | None = Field(default=None, alias="resourcesAbsent")
    observed_at: datetime = Field(alias="observedAt")

    @field_validator("observed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Docker provider evidence timestamp requires UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        scanner_values = (
            self.scanner_registration_digest,
            self.scanner_plan_digest,
            self.scanner_image_id,
            self.scanner_container_id,
            self.raw_sarif_sha256,
            self.raw_sarif_size_bytes,
            self.sarif_normalization_digest,
        )
        if self.stage != BenchmarkTargetStage.EXECUTION and any(
            value is not None for value in scanner_values
        ):
            raise ValueError("Docker non-execution evidence cannot carry Scanner facts")
        if self.stage == BenchmarkTargetStage.RESET:
            if self.isolation_id is not None or self.resources_absent is not True:
                raise ValueError("Docker reset evidence must prove resource absence")
        elif self.stage == BenchmarkTargetStage.ISOLATION:
            if (
                self.isolation_id is None
                or self.target_container_id is None
                or self.network_id is None
                or self.network_internal is not True
                or self.published_port_count != 0
                or self.network_container_count != 1
                or self.target_healthy is not True
            ):
                raise ValueError("Docker isolation evidence does not prove the lab boundary")
        elif self.stage == BenchmarkTargetStage.EXECUTION:
            common_invalid = (
                self.isolation_id is None
                or self.target_container_id is None
                or self.worker_container_id is None
                or self.network_id is None
                or self.network_internal is not True
                or self.published_port_count != 0
                or self.network_container_count != 1
                or self.target_healthy is not True
                or self.worker_exit_code != 0
            )
            scanner_mode = self.scanner_registration_digest is not None
            scanner_invalid = scanner_mode and (
                any(value is None for value in scanner_values)
                or self.scanner_container_id != self.worker_container_id
                or self.probe_vulnerable is not None
                or self.probe_output_sha256 is not None
            )
            probe_invalid = not scanner_mode and (
                self.probe_vulnerable is not True
                or self.probe_output_sha256 is None
                or any(value is not None for value in scanner_values)
            )
            if common_invalid or scanner_invalid or probe_invalid:
                raise ValueError("Docker execution evidence does not prove its observed workload")
        elif (
            self.isolation_id is None
            or self.resources_absent is not True
            or any(
                value is not None
                for value in (
                    self.scanner_registration_digest,
                    self.scanner_plan_digest,
                    self.scanner_image_id,
                    self.scanner_container_id,
                    self.raw_sarif_sha256,
                    self.raw_sarif_size_bytes,
                    self.sarif_normalization_digest,
                )
            )
        ):
            raise ValueError("Docker cleanup evidence must prove resource absence")
        material = self.model_dump(mode="json", by_alias=True, exclude={"evidence_digest"})
        digest = benchmark_digest(
            "pajin.benchmark.docker-provider-evidence/v1",
            material,
            max_bytes=512 * 1024,
        )
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("Docker provider evidence Digest differs")
        object.__setattr__(self, "evidence_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class DockerCommandResult:
    """Bounded Docker CLI process result used by the concrete and fake runners."""

    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


class DockerCommandRunner(Protocol):
    """Injectable Docker CLI boundary for deterministic fault testing."""

    def run(self, arguments: tuple[str, ...], *, stdin: bytes | None = None) -> DockerCommandResult:
        """Run one Docker CLI command without invoking a shell."""


class SubprocessDockerCommandRunner:
    """Bounded, shell-free Docker CLI implementation."""

    def __init__(self, *, executable: str = "docker", timeout_seconds: int = 30) -> None:
        if not executable or executable.strip() != executable or "\x00" in executable:
            raise ValueError("Docker executable is unsafe")
        if not 1 <= timeout_seconds <= 300:
            raise ValueError("Docker command timeout must be between 1 and 300 seconds")
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    def run(self, arguments: tuple[str, ...], *, stdin: bytes | None = None) -> DockerCommandResult:
        try:
            result = subprocess.run(
                [self._executable, *arguments],
                input=stdin,
                capture_output=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DockerBenchmarkProviderError("Docker CLI invocation failed") from exc
        if (
            len(result.stdout) > _MAX_COMMAND_OUTPUT_BYTES
            or len(result.stderr) > _MAX_COMMAND_OUTPUT_BYTES
        ):
            raise DockerBenchmarkProviderError("Docker CLI output exceeded its byte limit")
        return DockerCommandResult(
            returncode=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
        )


class _DockerTargetFactoryAdapter:
    """Shared recoverable Docker lifecycle for fixed, code-owned benchmark scenarios."""

    def __init__(
        self,
        *,
        state_path: Path,
        profile: DockerBugBountyTargetProfile,
        manifest: BenchmarkManifest,
        trust_anchor: BenchmarkMeasurementTrustAnchor,
        measurement_private_key: bytes,
        command_runner: DockerCommandRunner | None = None,
    ) -> None:
        profile_copy = DockerBugBountyTargetProfile.model_validate(
            profile.model_dump(mode="json", by_alias=True)
        )
        self._initialize_provider(
            state_path=state_path,
            profile=profile_copy,
            manifest=manifest,
            trust_anchor=trust_anchor,
            measurement_private_key=measurement_private_key,
            command_runner=command_runner,
            adapter_id="target-adapter:docker-bug-bounty",
            target_factory_id="target-factory:docker-bug-bounty",
        )

    def _initialize_provider(
        self,
        *,
        state_path: Path,
        profile: _DockerTargetProfile,
        manifest: BenchmarkManifest,
        trust_anchor: BenchmarkMeasurementTrustAnchor,
        measurement_private_key: bytes,
        command_runner: DockerCommandRunner | None,
        adapter_id: str,
        target_factory_id: str,
    ) -> None:
        self._profile: _DockerTargetProfile = profile
        self._manifest = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json", by_alias=True)
        )
        self._trust_anchor = BenchmarkMeasurementTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
        self._attestor = BenchmarkMeasurementAttestor.from_private_key_bytes(
            active_key_id=self._trust_anchor.key_id,
            private_key=measurement_private_key,
            trust_anchor=self._trust_anchor,
        )
        self._definition = RegisteredBenchmarkTargetFactoryAdapter(
            adapterId=adapter_id,
            adapterVersion="1.0.0",
            targetFactoryId=target_factory_id,
            targetFactoryVersion=self._profile.profile_version,
            targetFactoryDigest=self._profile.target_factory_digest,
            measurementAuthorityId=self._trust_anchor.authority_id,
            measurementAuthorityVersion=self._trust_anchor.authority_version,
            measurementAuthorityDigest=self._trust_anchor.anchor_digest,
        )
        if (
            self._manifest.target_factory_id != self._definition.target_factory_id
            or self._manifest.target_factory_version != self._definition.target_factory_version
            or self._manifest.target_factory_digest != self._definition.target_factory_digest
        ):
            raise DockerBenchmarkProviderError("Docker provider Manifest differs from its profile")
        self._state_path = Path(os.path.abspath(state_path))
        _initialize_provider_state(self._state_path)
        self._docker = command_runner or SubprocessDockerCommandRunner()

    @property
    def definition(self) -> RegisteredBenchmarkTargetFactoryAdapter:
        return self._definition.model_copy(deep=True)

    @property
    def profile(self) -> DockerTargetProfile:
        return DockerBugBountyTargetProfile.model_validate(
            cast(DockerBugBountyTargetProfile, self._profile).model_dump(
                mode="json", by_alias=True
            )
        )

    def evidence(
        self,
        receipt: BenchmarkTargetStageReceipt,
    ) -> DockerBenchmarkProviderEvidence:
        """Retrieve evidence only through its exact sealed stage receipt."""

        with _provider_read_transaction(self._state_path) as connection:
            row = connection.execute(
                """
                SELECT result_json, evidence_json FROM operations
                WHERE operation_id = ? AND state = 'completed'
                """,
                (receipt.operation_id,),
            ).fetchone()
        if row is None or row["evidence_json"] is None:
            raise DockerBenchmarkProviderError("Docker provider evidence is unavailable")
        try:
            evidence = DockerBenchmarkProviderEvidence.model_validate_json(row["evidence_json"])
        except ValueError as exc:
            raise DockerBenchmarkProviderError("Docker provider evidence is invalid") from exc
        cached_receipt, _ = _parse_provider_result(row["result_json"])
        if (
            cached_receipt != receipt
            or evidence.operation_id != receipt.operation_id
            or evidence.evidence_digest != receipt.provider_evidence_digest
        ):
            raise DockerBenchmarkProviderError("Docker provider evidence receipt binding differs")
        return evidence

    async def reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        self._require_operation(coordinate, operation, BenchmarkTargetStage.RESET)
        result = await asyncio.to_thread(self._run_stage, coordinate, operation, self._reset)
        return result[0]

    async def establish_isolation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        reset: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        self._require_predecessor(coordinate, reset, BenchmarkTargetStage.RESET)
        self._require_operation(coordinate, operation, BenchmarkTargetStage.ISOLATION)
        result = await asyncio.to_thread(self._run_stage, coordinate, operation, self._isolate)
        return result[0]

    async def execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation]:
        self._require_predecessor(coordinate, isolation, BenchmarkTargetStage.ISOLATION)
        self._require_operation(coordinate, operation, BenchmarkTargetStage.EXECUTION)
        receipt, observation = await asyncio.to_thread(
            self._run_stage,
            coordinate,
            operation,
            self._execute,
        )
        if observation is None:
            raise DockerBenchmarkProviderError("Docker execution observation is unavailable")
        return receipt, observation

    async def cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        isolation: BenchmarkTargetStageReceipt,
        operation: BenchmarkTargetOperation,
    ) -> BenchmarkTargetStageReceipt:
        self._require_predecessor(coordinate, isolation, BenchmarkTargetStage.ISOLATION)
        self._require_operation(coordinate, operation, BenchmarkTargetStage.CLEANUP)
        result = await asyncio.to_thread(self._run_stage, coordinate, operation, self._cleanup)
        return result[0]

    async def reconcile_cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        request: BenchmarkTargetRecoveryRequest,
    ) -> BenchmarkTargetStageReceipt:
        operation = request.cleanup_operation
        self._require_operation(coordinate, operation, BenchmarkTargetStage.CLEANUP)
        result = await asyncio.to_thread(self._run_stage, coordinate, operation, self._cleanup)
        return result[0]

    async def attest(
        self,
        statement: BenchmarkMeasurementAttestationStatement,
    ) -> BenchmarkMeasurementAttestation:
        return self._attestor.attest(statement)

    def _run_stage(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        action: Callable[
            [BenchmarkTargetCoordinate, BenchmarkTargetOperation],
            tuple[
                BenchmarkTargetStageReceipt,
                WalkingBenchmarkRunObservation | None,
                DockerBenchmarkProviderEvidence,
            ],
        ],
    ) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation | None]:
        with _provider_operation_lock(self._state_path):
            cached = _accept_provider_operation(self._state_path, operation)
            if cached is not None:
                return cached
            try:
                receipt, observation, evidence = action(coordinate, operation)
                if receipt.provider_evidence_digest != evidence.evidence_digest:
                    raise DockerBenchmarkProviderError("Docker receipt evidence binding differs")
                _complete_provider_operation(
                    self._state_path,
                    operation,
                    receipt=receipt,
                    observation=observation,
                    evidence=evidence,
                )
                return receipt, observation
            except BaseException:
                _fail_provider_operation(self._state_path, operation)
                raise

    def _reset(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, None, DockerBenchmarkProviderEvidence]:
        started = datetime.now(UTC)
        server_version = self._server_version()
        self._require_images()
        self._remove_resources(coordinate, operation)
        if not self._resources_absent(coordinate):
            raise DockerBenchmarkProviderError("Docker reset left managed resources behind")
        completed = datetime.now(UTC)
        evidence = self._evidence(
            coordinate,
            operation,
            server_version=server_version,
            resources_absent=True,
            observed_at=completed,
        )
        return self._receipt(coordinate, operation, evidence, started, completed), None, evidence

    def _isolate(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, None, DockerBenchmarkProviderEvidence]:
        started = datetime.now(UTC)
        server_version = self._server_version()
        self._require_images()
        names = _resource_names(coordinate)
        labels = self._labels(coordinate, operation)
        self._checked(
            (
                "network",
                "create",
                "--internal",
                *self._label_arguments(labels, role="network"),
                names.network,
            )
        )
        self._checked(
            (
                "create",
                "--name",
                names.target,
                "--network",
                names.network,
                "--network-alias",
                "target",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "128m",
                "--cpus",
                "0.5",
                "--user",
                "65532:65532",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                *self._target_environment_arguments(),
                *self._label_arguments(labels, role="target"),
                self._profile.target_image_id,
            )
        )
        self._checked(("start", names.target))
        target = self._wait_for_healthy_target(names.target)
        network = self._network_inspect(names.network)
        self._require_isolation_state(
            coordinate,
            operation,
            target,
            network,
            network_name=names.network,
            expected_members=1,
        )
        completed = datetime.now(UTC)
        evidence = self._evidence(
            coordinate,
            operation,
            server_version=server_version,
            target_container_id=_docker_id(target, label="target container"),
            network_id=_network_id(network),
            network_internal=True,
            published_port_count=0,
            network_container_count=1,
            target_healthy=True,
            observed_at=completed,
        )
        return self._receipt(coordinate, operation, evidence, started, completed), None, evidence

    def _execute(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> tuple[
        BenchmarkTargetStageReceipt,
        WalkingBenchmarkRunObservation,
        DockerBenchmarkProviderEvidence,
    ]:
        started = datetime.now(UTC)
        server_version = self._server_version()
        self._require_images()
        names = _resource_names(coordinate)
        labels = self._labels(coordinate, operation)
        target = self._container_inspect(names.target)
        network = self._network_inspect(names.network)
        self._require_isolation_state(
            coordinate,
            operation,
            target,
            network,
            network_name=names.network,
            expected_members=1,
        )
        self._checked(
            (
                "create",
                "--interactive",
                "--name",
                names.worker,
                "--network",
                names.network,
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "64",
                "--memory",
                "128m",
                "--cpus",
                "0.5",
                "--user",
                "65532:65532",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=16m",
                *self._label_arguments(labels, role="worker"),
                self._profile.worker_image_id,
                self._worker_action(),
            )
        )
        payload = (
            canonical_benchmark_json(
                self._worker_payload(),
                label=self._worker_input_label(),
                max_bytes=16 * 1024,
            )
            + b"\n"
        )
        worker_result = self._checked(
            ("start", "--attach", "--interactive", names.worker), stdin=payload
        )
        probe = self._parse_worker_output(worker_result.stdout)
        worker = self._container_inspect(names.worker)
        target = self._container_inspect(names.target)
        network = self._network_inspect(names.network)
        self._require_isolation_state(
            coordinate,
            operation,
            target,
            network,
            network_name=names.network,
            expected_members=1,
        )
        self._require_worker_state(
            coordinate,
            operation,
            worker,
            network_name=names.network,
        )
        completed = datetime.now(UTC)
        evidence = self._evidence(
            coordinate,
            operation,
            server_version=server_version,
            target_container_id=_docker_id(target, label="target container"),
            worker_container_id=_docker_id(worker, label="worker container"),
            network_id=_network_id(network),
            network_internal=True,
            published_port_count=0,
            network_container_count=1,
            target_healthy=True,
            worker_exit_code=0,
            probe_vulnerable=cast(bool, probe["vulnerable"]),
            probe_output_sha256=sha256(
                canonical_benchmark_json(
                    probe,
                    label=self._worker_output_label(),
                    max_bytes=512 * 1024,
                )
            ).hexdigest(),
            observed_at=completed,
        )
        receipt = self._receipt(coordinate, operation, evidence, started, completed)
        return receipt, self._observation(coordinate, receipt), evidence

    def _target_environment_arguments(self) -> tuple[str, ...]:
        profile = cast(DockerBugBountyTargetProfile, self._profile)
        return ("--env", f"PAJIN_BUG_BOUNTY_LAB_PROFILE={profile.target_profile}")

    def _worker_action(self) -> str:
        return "bug-bounty-sqli-probe"

    def _worker_payload(self) -> Mapping[str, object]:
        return {
            "scenarioId": self._profile.profile_id,
            "target": "http://target:8080/v1/users/lookup",
        }

    def _worker_input_label(self) -> str:
        return "Docker Bug Bounty Worker input"

    def _worker_output_label(self) -> str:
        return "Docker Bug Bounty Worker output"

    def _parse_worker_output(self, raw: bytes) -> dict[str, object]:
        return _parse_probe_output(raw)

    def _cleanup(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> tuple[BenchmarkTargetStageReceipt, None, DockerBenchmarkProviderEvidence]:
        started = datetime.now(UTC)
        server_version = self._server_version()
        self._remove_resources(coordinate, operation)
        absent = self._resources_absent(coordinate)
        completed = datetime.now(UTC)
        evidence = self._evidence(
            coordinate,
            operation,
            server_version=server_version,
            resources_absent=absent,
            observed_at=completed,
        )
        return self._receipt(coordinate, operation, evidence, started, completed), None, evidence

    def _observation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        receipt: BenchmarkTargetStageReceipt,
    ) -> WalkingBenchmarkRunObservation:
        arm = coordinate.arm
        return WalkingBenchmarkRunObservation(
            benchmarkId=coordinate.benchmark_id,
            manifestDigest=coordinate.manifest_digest,
            armId=arm.arm_id,
            armKind=arm.kind,
            configurationDigest=arm.configuration_digest,
            targetFactoryDigest=self._profile.target_factory_digest,
            campaignDigest=self._manifest.campaign_digest,
            groundTruthDigest=self._manifest.ground_truth_digest,
            protocolId=self._manifest.protocol.protocol_id,
            protocolVersion=self._manifest.protocol.protocol_version,
            measurementAuthorityId=self._definition.measurement_authority_id,
            measurementAuthorityVersion=self._definition.measurement_authority_version,
            measurementAuthorityDigest=self._definition.measurement_authority_digest,
            seed=coordinate.seed,
            repetition=coordinate.repetition,
            startedAt=receipt.started_at,
            completedAt=receipt.completed_at,
            cleanupSucceeded=False,
            toolCallCount=1,
            modelCallCount=0,
            costUsd=0.0,
            knownAttackSurfaceCount=1,
            discoveredKnownAttackSurfaceCount=1,
            knownFindingCount=1,
            matchedKnownFindingCount=1,
            candidateFindingCount=1,
            validCandidateFindingCount=1,
            unexpectedValidFindingCount=0,
            confirmedFindingCount=1,
            groundTruthChainCount=1,
            completedGroundTruthChainCount=1,
            firstValidOrConfirmedFindingSeconds=0.0,
            replayAttemptCount=1,
            replaySuccessCount=1,
            policyRejectionOrViolationCount=0,
            humanDecisionCount=1,
            humanInterventionOrOverturnCount=0,
        )

    def _require_operation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        expected_stage: str,
    ) -> None:
        if (
            operation.adapter_digest != self._definition.adapter_digest
            or operation.coordinate_digest != coordinate.coordinate_digest
            or operation.stage != expected_stage
        ):
            raise DockerBenchmarkProviderError("Docker provider operation identity differs")
        if self._manifest.digest() != coordinate.manifest_digest:
            raise DockerBenchmarkProviderError("Docker provider coordinate Manifest differs")

    def _require_predecessor(
        self,
        coordinate: BenchmarkTargetCoordinate,
        receipt: BenchmarkTargetStageReceipt,
        stage: str,
    ) -> None:
        if (
            receipt.adapter_digest != self._definition.adapter_digest
            or receipt.coordinate_digest != coordinate.coordinate_digest
            or receipt.stage != stage
            or receipt.environment_id != _environment_id(coordinate)
            or receipt.status != "succeeded"
        ):
            raise DockerBenchmarkProviderError("Docker provider predecessor receipt differs")

    def _receipt(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        evidence: DockerBenchmarkProviderEvidence,
        started: datetime,
        completed: datetime,
    ) -> BenchmarkTargetStageReceipt:
        return BenchmarkTargetStageReceipt(
            adapterDigest=self._definition.adapter_digest,
            coordinateDigest=coordinate.coordinate_digest,
            stage=operation.stage,
            operationId=operation.operation_id,
            environmentId=_environment_id(coordinate),
            isolationId=None
            if operation.stage == BenchmarkTargetStage.RESET
            else _isolation_id(coordinate),
            status="succeeded",
            startedAt=started,
            completedAt=completed,
            providerEvidenceDigest=evidence.evidence_digest,
        )

    def _evidence(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        *,
        server_version: str,
        observed_at: datetime,
        **facts: object,
    ) -> DockerBenchmarkProviderEvidence:
        return DockerBenchmarkProviderEvidence.model_validate(
            {
                "adapterDigest": self._definition.adapter_digest,
                "coordinateDigest": coordinate.coordinate_digest,
                "operationId": operation.operation_id,
                "operationDigest": operation.operation_digest,
                "fence": operation.fence,
                "stage": operation.stage,
                "environmentId": _environment_id(coordinate),
                "isolationId": (
                    None
                    if operation.stage == BenchmarkTargetStage.RESET
                    else _isolation_id(coordinate)
                ),
                "dockerServerVersion": server_version,
                "targetImageId": self._profile.target_image_id,
                "workerImageId": self._profile.worker_image_id,
                "observedAt": observed_at,
                **facts,
            }
        )

    def _server_version(self) -> str:
        result = self._checked(("version", "--format", "{{.Server.Version}}"))
        value = _decode_command_output(result.stdout, label="server version").strip()
        if not value or len(value) > 100:
            raise DockerBenchmarkProviderError("Docker server version is invalid")
        return value

    def _require_images(self) -> None:
        for reference, expected in (
            (self._profile.target_image, self._profile.target_image_id),
            (self._profile.worker_image, self._profile.worker_image_id),
        ):
            result = self._checked(("image", "inspect", reference, "--format", "{{.Id}}"))
            if _decode_command_output(result.stdout, label="image identity").strip() != expected:
                raise DockerBenchmarkProviderError("Docker image identity differs from profile")

    def _labels(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> dict[str, str]:
        return {
            _MANAGED_LABEL: "true",
            _ADAPTER_LABEL: self._definition.adapter_digest,
            _COORDINATE_LABEL: coordinate.coordinate_digest,
            _FENCE_LABEL: str(operation.fence),
        }

    @staticmethod
    def _label_arguments(labels: Mapping[str, str], *, role: str) -> tuple[str, ...]:
        arguments: list[str] = []
        for key, value in sorted({**labels, _ROLE_LABEL: role}.items()):
            arguments.extend(("--label", f"{key}={value}"))
        return tuple(arguments)

    def _remove_resources(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
    ) -> None:
        names = _resource_names(coordinate)
        for name in (names.worker, names.target):
            if self._container_exists(name):
                details = self._container_inspect(name)
                self._require_owned_resource(coordinate, operation, details)
                self._checked(("rm", "--force", name))
        if self._network_exists(names.network):
            details = self._network_inspect(names.network)
            self._require_owned_resource(coordinate, operation, details)
            self._checked(("network", "rm", names.network))

    def _require_owned_resource(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        details: Mapping[str, object],
    ) -> None:
        labels = _resource_labels(details)
        try:
            fence = int(labels.get(_FENCE_LABEL, ""))
        except ValueError as exc:
            raise DockerBenchmarkProviderError("Docker managed resource fence is invalid") from exc
        if (
            labels.get(_MANAGED_LABEL) != "true"
            or labels.get(_ADAPTER_LABEL) != self._definition.adapter_digest
            or labels.get(_COORDINATE_LABEL) != coordinate.coordinate_digest
            or fence > operation.fence
        ):
            raise DockerBenchmarkProviderError("Docker resource ownership or fence differs")

    def _require_isolation_state(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        target: Mapping[str, object],
        network: Mapping[str, object],
        *,
        network_name: str,
        expected_members: int,
    ) -> None:
        self._require_owned_resource(coordinate, operation, target)
        self._require_owned_resource(coordinate, operation, network)
        state = _mapping(target.get("State"), label="target state")
        health = _mapping(state.get("Health"), label="target health")
        containers = _mapping(network.get("Containers"), label="network containers")
        if (
            network.get("Internal") is not True
            or network.get("Driver") != "bridge"
            or network.get("Scope") != "local"
            or len(containers) != expected_members
            or state.get("Running") is not True
            or health.get("Status") != "healthy"
        ):
            raise DockerBenchmarkProviderError("Docker isolation policy differs")
        _require_container_hardening(
            target,
            expected_image_id=self._profile.target_image_id,
            expected_network=network_name,
            expected_command=None,
        )

    def _require_worker_state(
        self,
        coordinate: BenchmarkTargetCoordinate,
        operation: BenchmarkTargetOperation,
        worker: Mapping[str, object],
        *,
        network_name: str,
    ) -> None:
        self._require_owned_resource(coordinate, operation, worker)
        state = _mapping(worker.get("State"), label="worker state")
        if state.get("Running") is not False or state.get("ExitCode") != 0:
            raise DockerBenchmarkProviderError("Docker worker policy differs")
        _require_container_hardening(
            worker,
            expected_image_id=self._profile.worker_image_id,
            expected_network=network_name,
            expected_command=[self._worker_action()],
        )

    def _wait_for_healthy_target(self, name: str) -> Mapping[str, object]:
        for _ in range(150):
            details = self._container_inspect(name)
            state = _mapping(details.get("State"), label="target state")
            health = _mapping(state.get("Health"), label="target health")
            if health.get("Status") == "healthy":
                return details
            if state.get("Running") is not True or health.get("Status") == "unhealthy":
                break
            import time

            time.sleep(0.1)
        raise DockerBenchmarkProviderError("Docker target did not become healthy")

    def _resources_absent(self, coordinate: BenchmarkTargetCoordinate) -> bool:
        names = _resource_names(coordinate)
        return not any(
            (
                self._container_exists(names.worker),
                self._container_exists(names.target),
                self._network_exists(names.network),
            )
        )

    def _container_exists(self, name: str) -> bool:
        result = self._checked(
            ("container", "ls", "--all", "--quiet", "--filter", f"name=^/{name}$")
        )
        return bool(result.stdout.strip())

    def _network_exists(self, name: str) -> bool:
        result = self._checked(("network", "ls", "--quiet", "--filter", f"name=^{name}$"))
        return bool(result.stdout.strip())

    def _container_inspect(self, name: str) -> Mapping[str, object]:
        return _single_inspect(self._checked(("container", "inspect", name)).stdout)

    def _network_inspect(self, name: str) -> Mapping[str, object]:
        return _single_inspect(self._checked(("network", "inspect", name)).stdout)

    def _checked(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> DockerCommandResult:
        result = self._docker.run(arguments, stdin=stdin)
        if (
            not isinstance(result, DockerCommandResult)
            or not isinstance(result.returncode, int)
            or isinstance(result.returncode, bool)
            or not isinstance(result.stdout, bytes)
            or not isinstance(result.stderr, bytes)
            or len(result.stdout) > _MAX_COMMAND_OUTPUT_BYTES
            or len(result.stderr) > _MAX_COMMAND_OUTPUT_BYTES
        ):
            raise DockerBenchmarkProviderError("Docker provider command result is invalid")
        if result.returncode != 0:
            raise DockerBenchmarkProviderError("Docker provider command failed")
        return result


class DockerBugBountyTargetFactoryAdapter(_DockerTargetFactoryAdapter):
    """Recoverable local Docker implementation for one synthetic Boolean-SQLi lab."""

    @property
    def profile(self) -> DockerBugBountyTargetProfile:
        return DockerBugBountyTargetProfile.model_validate(
            cast(DockerBugBountyTargetProfile, self._profile).model_dump(
                mode="json", by_alias=True
            )
        )


class DockerAIRAGMCPTargetFactoryAdapter(_DockerTargetFactoryAdapter):
    """Recoverable local Docker implementation of the synthetic AI/RAG/MCP chain."""

    def __init__(
        self,
        *,
        state_path: Path,
        profile: DockerAIRAGMCPTargetProfile,
        manifest: BenchmarkManifest,
        trust_anchor: BenchmarkMeasurementTrustAnchor,
        measurement_private_key: bytes,
        command_runner: DockerCommandRunner | None = None,
    ) -> None:
        profile_copy = DockerAIRAGMCPTargetProfile.model_validate(
            profile.model_dump(mode="json", by_alias=True)
        )
        self._initialize_provider(
            state_path=state_path,
            profile=profile_copy,
            manifest=manifest,
            trust_anchor=trust_anchor,
            measurement_private_key=measurement_private_key,
            command_runner=command_runner,
            adapter_id="target-adapter:docker-ai-rag-mcp",
            target_factory_id="target-factory:docker-ai-rag-mcp",
        )

    @property
    def profile(self) -> DockerAIRAGMCPTargetProfile:
        return DockerAIRAGMCPTargetProfile.model_validate(
            cast(DockerAIRAGMCPTargetProfile, self._profile).model_dump(
                mode="json", by_alias=True
            )
        )

    def _target_environment_arguments(self) -> tuple[str, ...]:
        profile = cast(DockerAIRAGMCPTargetProfile, self._profile)
        return ("--env", f"PAJIN_AI_RAG_MCP_TARGET_STATE={profile.target_state}")

    def _worker_action(self) -> str:
        return "ai-rag-mcp-chain-probe"

    def _worker_payload(self) -> Mapping[str, object]:
        return {"scenarioId": self._profile.profile_id, "target": _AI_RAG_MCP_TARGET}

    def _worker_input_label(self) -> str:
        return "Docker AI/RAG/MCP Worker input"

    def _worker_output_label(self) -> str:
        return "Docker AI/RAG/MCP Worker output"

    def _parse_worker_output(self, raw: bytes) -> dict[str, object]:
        return _parse_ai_rag_mcp_probe_output(raw)

    def _observation(
        self,
        coordinate: BenchmarkTargetCoordinate,
        receipt: BenchmarkTargetStageReceipt,
    ) -> WalkingBenchmarkRunObservation:
        arm = coordinate.arm
        return WalkingBenchmarkRunObservation(
            benchmarkId=coordinate.benchmark_id,
            manifestDigest=coordinate.manifest_digest,
            armId=arm.arm_id,
            armKind=arm.kind,
            configurationDigest=arm.configuration_digest,
            targetFactoryDigest=self._profile.target_factory_digest,
            campaignDigest=self._manifest.campaign_digest,
            groundTruthDigest=self._manifest.ground_truth_digest,
            protocolId=self._manifest.protocol.protocol_id,
            protocolVersion=self._manifest.protocol.protocol_version,
            measurementAuthorityId=self._definition.measurement_authority_id,
            measurementAuthorityVersion=self._definition.measurement_authority_version,
            measurementAuthorityDigest=self._definition.measurement_authority_digest,
            seed=coordinate.seed,
            repetition=coordinate.repetition,
            startedAt=receipt.started_at,
            completedAt=receipt.completed_at,
            cleanupSucceeded=False,
            toolCallCount=1,
            modelCallCount=0,
            costUsd=0.0,
            knownAttackSurfaceCount=3,
            discoveredKnownAttackSurfaceCount=3,
            knownFindingCount=1,
            matchedKnownFindingCount=1,
            candidateFindingCount=1,
            validCandidateFindingCount=1,
            unexpectedValidFindingCount=0,
            confirmedFindingCount=1,
            groundTruthChainCount=1,
            completedGroundTruthChainCount=1,
            firstValidOrConfirmedFindingSeconds=0.0,
            replayAttemptCount=1,
            replaySuccessCount=1,
            policyRejectionOrViolationCount=0,
            humanDecisionCount=1,
            humanInterventionOrOverturnCount=0,
        )


@dataclass(frozen=True, slots=True)
class _ResourceNames:
    network: str
    target: str
    worker: str


def _resource_names(coordinate: BenchmarkTargetCoordinate) -> _ResourceNames:
    suffix = coordinate.coordinate_digest[:24]
    prefix = f"pajin-bench-{suffix}"
    return _ResourceNames(
        network=f"{prefix}-net",
        target=f"{prefix}-target",
        worker=f"{prefix}-worker",
    )


def _environment_id(coordinate: BenchmarkTargetCoordinate) -> str:
    return f"environment:docker:{coordinate.coordinate_digest}"


def _isolation_id(coordinate: BenchmarkTargetCoordinate) -> str:
    return f"isolation:docker:{coordinate.coordinate_digest}"


def _parse_probe_output(raw: bytes) -> dict[str, object]:
    if not 1 <= len(raw) <= 512 * 1024:
        raise DockerBenchmarkProviderError("Docker worker output is missing or too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DockerBenchmarkProviderError("Docker worker output is not JSON") from exc
    if not isinstance(value, dict):
        raise DockerBenchmarkProviderError("Docker worker output is not an object")
    checks = value.get("checks")
    observations = value.get("observations")
    if (
        value.get("scenarioId") != "bug-bounty.api.boolean-sqli-lab"
        or value.get("target") != "http://target:8080/v1/users/lookup"
        or value.get("vulnerable") is not True
        or value.get("networkPerformed") is not True
        or not isinstance(checks, dict)
        or set(checks)
        != {
            "baselineSingleRecord",
            "booleanProbeExpanded",
            "negativeControlEmpty",
            "syntheticLabOnly",
        }
        or any(item is not True for item in checks.values())
        or not isinstance(observations, list)
        or len(observations) != 3
    ):
        raise DockerBenchmarkProviderError("Docker worker probe result differs")
    _require_probe_observations(observations)
    canonical_benchmark_json(
        value,
        label="Docker Bug Bounty Worker output",
        max_bytes=512 * 1024,
    )
    return cast(dict[str, object], value)


def _require_probe_observations(observations: list[object]) -> None:
    expected = (
        ("baseline", 1, "parameterized-identifier"),
        ("negative-control", 0, "false-control"),
        ("boolean-probe", 2, "unsafe-boolean-expression"),
    )
    for raw, (name, minimum_count, query_mode) in zip(observations, expected, strict=True):
        if not isinstance(raw, dict) or set(raw) != {
            "name",
            "status",
            "recordCount",
            "synthetic",
            "bodySha256",
            "responseBodyBase64",
        }:
            raise DockerBenchmarkProviderError("Docker worker probe observation shape differs")
        record_count = raw.get("recordCount")
        body_digest = raw.get("bodySha256")
        encoded_body = raw.get("responseBodyBase64")
        if (
            raw.get("name") != name
            or raw.get("status") != 200
            or not isinstance(record_count, int)
            or isinstance(record_count, bool)
            or record_count < minimum_count
            or raw.get("synthetic") is not True
            or not isinstance(body_digest, str)
            or len(body_digest) != 64
            or any(character not in "0123456789abcdef" for character in body_digest)
            or not isinstance(encoded_body, str)
        ):
            raise DockerBenchmarkProviderError("Docker worker probe observation differs")
        try:
            body = base64.b64decode(encoded_body, validate=True)
            body_value = json.loads(body)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DockerBenchmarkProviderError("Docker worker probe body is invalid") from exc
        if (
            not 1 <= len(body) <= 128 * 1024
            or not compare_digest(sha256(body).hexdigest(), body_digest)
            or not isinstance(body_value, dict)
            or body_value.get("synthetic") is not True
            or body_value.get("recordCount") != record_count
            or body_value.get("queryMode") != query_mode
        ):
            raise DockerBenchmarkProviderError("Docker worker probe body differs")


def _parse_ai_rag_mcp_probe_output(raw: bytes) -> dict[str, object]:
    if not 1 <= len(raw) <= 512 * 1024:
        raise DockerBenchmarkProviderError(
            "Docker AI/RAG/MCP worker output is missing or too large"
        )
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DockerBenchmarkProviderError("Docker AI/RAG/MCP worker output is not JSON") from exc
    if not isinstance(value, dict):
        raise DockerBenchmarkProviderError("Docker AI/RAG/MCP worker output is not an object")
    checks = value.get("checks")
    observations = value.get("observations")
    expected_checks = {
        "authorizationNotEnforced",
        "internalDataAccessed",
        "mcpArgumentInfluenced",
        "ragRetrievedDocument",
        "syntheticLabOnly",
        "uploadAccepted",
    }
    if (
        set(value)
        != {"checks", "networkPerformed", "observations", "scenarioId", "target", "vulnerable"}
        or value.get("scenarioId") != _AI_RAG_MCP_SCENARIO
        or value.get("target") != _AI_RAG_MCP_TARGET
        or value.get("vulnerable") is not True
        or value.get("networkPerformed") is not True
        or not isinstance(checks, dict)
        or set(checks) != expected_checks
        or any(item is not True for item in checks.values())
        or not isinstance(observations, list)
        or len(observations) != 2
    ):
        raise DockerBenchmarkProviderError("Docker AI/RAG/MCP worker probe result differs")
    _require_ai_rag_mcp_observations(observations)
    canonical_benchmark_json(
        value,
        label="Docker AI/RAG/MCP Worker output",
        max_bytes=512 * 1024,
    )
    return cast(dict[str, object], value)


def _require_ai_rag_mcp_observations(observations: list[object]) -> None:
    expected_bodies: tuple[tuple[str, dict[str, object]], ...] = (
        (
            "upload",
            {
                "accepted": True,
                "documentId": _AI_RAG_MCP_DOCUMENT_ID,
                "synthetic": True,
            },
        ),
        (
            "agent-query",
            {
                "authorizationEnforced": False,
                "inputMarker": _AI_RAG_MCP_INPUT_MARKER,
                "internalDataAccessed": True,
                "mcpArgument": _AI_RAG_MCP_TOOL_ARGUMENT,
                "mcpServerId": "demo-security",
                "mcpToolName": "inspect_text",
                "observation": _AI_RAG_MCP_OBSERVATION,
                "ragDocumentId": _AI_RAG_MCP_DOCUMENT_ID,
                "synthetic": True,
            },
        ),
    )
    for raw, (name, expected_body) in zip(observations, expected_bodies, strict=True):
        if not isinstance(raw, dict) or set(raw) != {
            "bodySha256",
            "name",
            "responseBodyBase64",
            "status",
            "synthetic",
        }:
            raise DockerBenchmarkProviderError(
                "Docker AI/RAG/MCP worker probe observation shape differs"
            )
        body_digest = raw.get("bodySha256")
        encoded_body = raw.get("responseBodyBase64")
        if (
            raw.get("name") != name
            or raw.get("status") != 200
            or raw.get("synthetic") is not True
            or not isinstance(body_digest, str)
            or len(body_digest) != 64
            or any(character not in "0123456789abcdef" for character in body_digest)
            or not isinstance(encoded_body, str)
        ):
            raise DockerBenchmarkProviderError("Docker AI/RAG/MCP worker probe observation differs")
        try:
            body = base64.b64decode(encoded_body, validate=True)
            body_value = json.loads(body)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise DockerBenchmarkProviderError(
                "Docker AI/RAG/MCP worker probe body is invalid"
            ) from exc
        if (
            not 1 <= len(body) <= 128 * 1024
            or not compare_digest(sha256(body).hexdigest(), body_digest)
            or body_value != expected_body
        ):
            raise DockerBenchmarkProviderError("Docker AI/RAG/MCP worker probe body differs")


def _decode_command_output(raw: bytes, *, label: str) -> str:
    try:
        return raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DockerBenchmarkProviderError(f"Docker {label} output is not UTF-8") from exc


def _single_inspect(raw: bytes) -> Mapping[str, object]:
    if not 2 <= len(raw) <= _MAX_COMMAND_OUTPUT_BYTES:
        raise DockerBenchmarkProviderError("Docker inspect output is missing or too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DockerBenchmarkProviderError("Docker inspect output is not JSON") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise DockerBenchmarkProviderError("Docker inspect output cardinality differs")
    return cast(Mapping[str, object], value[0])


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise DockerBenchmarkProviderError(f"Docker {label} is invalid")
    return cast(Mapping[str, object], value)


def _docker_id(details: Mapping[str, object], *, label: str) -> str:
    value = details.get("Id")
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise DockerBenchmarkProviderError(f"Docker {label} ID is invalid")
    return value


def _network_id(details: Mapping[str, object]) -> str:
    return _docker_id(details, label="network")


def _resource_labels(details: Mapping[str, object]) -> Mapping[str, str]:
    raw = details.get("Labels")
    if raw is None:
        config = _mapping(details.get("Config"), label="resource config")
        raw = config.get("Labels")
    if not isinstance(raw, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in raw.items()
    ):
        raise DockerBenchmarkProviderError("Docker resource labels are invalid")
    return cast(Mapping[str, str], raw)


def _has_no_new_privileges(host: Mapping[str, object]) -> bool:
    raw = host.get("SecurityOpt", [])
    return isinstance(raw, list) and any(
        isinstance(value, str) and value.startswith("no-new-privileges") for value in raw
    )


def _require_container_hardening(
    details: Mapping[str, object],
    *,
    expected_image_id: str,
    expected_network: str,
    expected_command: list[str] | None,
) -> None:
    host = _mapping(details.get("HostConfig"), label="container host config")
    config = _mapping(details.get("Config"), label="container config")
    tmpfs = _mapping(host.get("Tmpfs"), label="container tmpfs")
    cap_drop = host.get("CapDrop")
    if (
        details.get("Image") != expected_image_id
        or host.get("NetworkMode") != expected_network
        or host.get("ReadonlyRootfs") is not True
        or host.get("PortBindings") not in (None, {})
        or host.get("Memory") != 128 * 1024 * 1024
        or host.get("NanoCpus") != 500_000_000
        or host.get("PidsLimit") != 64
        or tmpfs != {"/tmp": "rw,noexec,nosuid,nodev,size=16m"}
        or config.get("User") != "65532:65532"
        or cap_drop != ["ALL"]
        or not _has_no_new_privileges(host)
        or config.get("Cmd") != expected_command
    ):
        raise DockerBenchmarkProviderError("Docker container hardening policy differs")


def _initialize_provider_state(path: Path) -> None:
    _require_safe_state_path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_safe_state_path(path)
    connection = _open_write_connection(path)
    try:
        mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            raise DockerBenchmarkProviderError("Docker provider journal mode differs")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scopes (
                scope_digest TEXT PRIMARY KEY,
                highest_fence INTEGER NOT NULL CHECK(highest_fence >= 1),
                attempt_digest TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS operations (
                operation_id TEXT PRIMARY KEY,
                operation_digest TEXT NOT NULL UNIQUE,
                scope_digest TEXT NOT NULL,
                fence INTEGER NOT NULL CHECK(fence >= 1),
                stage TEXT NOT NULL CHECK(stage IN ('reset', 'isolation', 'execution', 'cleanup')),
                state TEXT NOT NULL CHECK(state IN ('in-progress', 'completed', 'failed')),
                result_json TEXT,
                evidence_json TEXT,
                FOREIGN KEY(scope_digest) REFERENCES scopes(scope_digest)
            );
            """
        )
        _require_provider_schema(connection)
        connection.commit()
        path.chmod(0o600)
    except sqlite3.Error as exc:
        raise DockerBenchmarkProviderError("Docker provider state could not initialize") from exc
    finally:
        connection.close()
    _require_safe_state_path(path)
    _initialize_operation_lock(_operation_lock_path(path))


def _initialize_operation_lock(path: Path) -> None:
    _require_safe_lock_path(path)
    connection = _open_write_connection(path)
    try:
        mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            raise DockerBenchmarkProviderError("Docker provider lock journal mode differs")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS operation_lock (
                singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
                generation INTEGER NOT NULL CHECK(generation >= 0)
            );
            INSERT OR IGNORE INTO operation_lock(singleton, generation) VALUES (1, 0);
            """
        )
        _require_lock_schema(connection)
        connection.commit()
        path.chmod(0o600)
    except sqlite3.Error as exc:
        raise DockerBenchmarkProviderError(
            "Docker provider operation lock could not initialize"
        ) from exc
    finally:
        connection.close()
    _require_safe_lock_path(path)


def _require_provider_schema(connection: sqlite3.Connection) -> None:
    expected = {
        "scopes": {"scope_digest", "highest_fence", "attempt_digest"},
        "operations": {
            "operation_id",
            "operation_digest",
            "scope_digest",
            "fence",
            "stage",
            "state",
            "result_json",
            "evidence_json",
        },
    }
    for table, columns in expected.items():
        rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
        if {str(row[1]) for row in rows} != columns:
            raise DockerBenchmarkProviderError("Docker provider state schema differs")


def _require_lock_schema(connection: sqlite3.Connection) -> None:
    rows = connection.execute("PRAGMA table_info(operation_lock)").fetchall()
    if {str(row[1]) for row in rows} != {"singleton", "generation"}:
        raise DockerBenchmarkProviderError("Docker provider operation lock schema differs")


def _accept_provider_operation(
    path: Path,
    operation: BenchmarkTargetOperation,
    *,
    evidence_loader: Callable[[str], StrictModel] | None = None,
) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation | None] | None:
    scope = _provider_scope(operation)
    with _provider_write_transaction(path) as connection:
        row = connection.execute(
            "SELECT highest_fence, attempt_digest FROM scopes WHERE scope_digest = ?",
            (scope,),
        ).fetchone()
        if row is not None and operation.fence < int(row["highest_fence"]):
            raise DockerBenchmarkProviderError("Docker provider rejected a stale fence")
        existing = connection.execute(
            """
            SELECT operation_digest, state, result_json, evidence_json
            FROM operations WHERE operation_id = ?
            """,
            (operation.operation_id,),
        ).fetchone()
        if existing is not None:
            if existing["operation_digest"] != operation.operation_digest:
                raise DockerBenchmarkProviderError(
                    "Docker provider operation equivocation detected"
                )
            if row is None or operation.fence != int(row["highest_fence"]):
                raise DockerBenchmarkProviderError("Docker provider operation was superseded")
            if existing["state"] == "completed":
                receipt, observation = _parse_provider_result(existing["result_json"])
                try:
                    raw_evidence = existing["evidence_json"]
                    if not isinstance(raw_evidence, str):
                        raise ValueError("evidence is not text")
                    evidence = (
                        DockerBenchmarkProviderEvidence.model_validate_json(raw_evidence)
                        if evidence_loader is None
                        else evidence_loader(raw_evidence)
                    )
                except ValueError as exc:
                    raise DockerBenchmarkProviderError(
                        "Docker provider cached evidence is invalid"
                    ) from exc
                evidence_digest = getattr(evidence, "evidence_digest", None)
                if evidence_digest != receipt.provider_evidence_digest:
                    raise DockerBenchmarkProviderError(
                        "Docker provider cached evidence binding differs"
                    )
                return receipt, observation
            raise DockerBenchmarkProviderError("Docker provider operation is not replayable")
        new_fence = row is None or operation.fence > int(row["highest_fence"])
        _require_provider_stage_order(
            connection,
            operation,
            scope=scope,
            new_fence=new_fence,
        )
        if row is None:
            connection.execute(
                "INSERT INTO scopes(scope_digest, highest_fence, attempt_digest) VALUES (?, ?, ?)",
                (scope, operation.fence, operation.attempt_digest),
            )
        elif operation.fence > int(row["highest_fence"]):
            connection.execute(
                "UPDATE scopes SET highest_fence = ?, attempt_digest = ? WHERE scope_digest = ?",
                (operation.fence, operation.attempt_digest, scope),
            )
        elif row["attempt_digest"] != operation.attempt_digest:
            raise DockerBenchmarkProviderError("Docker provider fence belongs to another attempt")
        connection.execute(
            """
            INSERT INTO operations(
                operation_id, operation_digest, scope_digest, fence, stage, state,
                result_json, evidence_json
            ) VALUES (?, ?, ?, ?, ?, 'in-progress', NULL, NULL)
            """,
            (
                operation.operation_id,
                operation.operation_digest,
                scope,
                operation.fence,
                operation.stage,
            ),
        )
    return None


def _require_provider_stage_order(
    connection: sqlite3.Connection,
    operation: BenchmarkTargetOperation,
    *,
    scope: str,
    new_fence: bool,
) -> None:
    rows = connection.execute(
        """
        SELECT stage, state FROM operations
        WHERE scope_digest = ? AND fence = ?
        """,
        (scope, operation.fence),
    ).fetchall()
    completed = {str(row["stage"]) for row in rows if row["state"] == "completed"}
    attempted = {str(row["stage"]) for row in rows}
    stage = operation.stage
    allowed = (
        (stage == BenchmarkTargetStage.RESET and new_fence and not attempted)
        or (stage == BenchmarkTargetStage.ISOLATION and completed == {BenchmarkTargetStage.RESET})
        or (
            stage == BenchmarkTargetStage.EXECUTION
            and completed == {BenchmarkTargetStage.RESET, BenchmarkTargetStage.ISOLATION}
        )
        or (
            stage == BenchmarkTargetStage.CLEANUP
            and (
                new_fence
                or BenchmarkTargetStage.ISOLATION in completed
                or BenchmarkTargetStage.CLEANUP in attempted
            )
        )
    )
    if not allowed:
        raise DockerBenchmarkProviderError("Docker provider lifecycle order differs")


def _complete_provider_operation(
    path: Path,
    operation: BenchmarkTargetOperation,
    *,
    receipt: BenchmarkTargetStageReceipt,
    observation: WalkingBenchmarkRunObservation | None,
    evidence: StrictModel,
) -> None:
    result = {
        "receipt": receipt.model_dump(mode="json", by_alias=True),
        "observation": (
            None if observation is None else observation.model_dump(mode="json", by_alias=True)
        ),
    }
    result_json = canonical_benchmark_json(
        result,
        label="Docker provider operation result",
        max_bytes=_MAX_PROVIDER_RESULT_BYTES,
    ).decode("utf-8")
    evidence_json = evidence.model_dump_json(by_alias=True)
    scope = _provider_scope(operation)
    with _provider_write_transaction(path) as connection:
        current = connection.execute(
            "SELECT highest_fence FROM scopes WHERE scope_digest = ?",
            (scope,),
        ).fetchone()
        if current is None or int(current["highest_fence"]) != operation.fence:
            raise DockerBenchmarkProviderError("Docker provider completion lost its fence")
        updated = connection.execute(
            """
            UPDATE operations
            SET state = 'completed', result_json = ?, evidence_json = ?
            WHERE operation_id = ? AND operation_digest = ? AND state = 'in-progress'
            """,
            (result_json, evidence_json, operation.operation_id, operation.operation_digest),
        ).rowcount
        if updated != 1:
            raise DockerBenchmarkProviderError("Docker provider completion state differs")


def _fail_provider_operation(path: Path, operation: BenchmarkTargetOperation) -> None:
    try:
        with _provider_write_transaction(path) as connection:
            connection.execute(
                """
                UPDATE operations SET state = 'failed'
                WHERE operation_id = ? AND operation_digest = ? AND state = 'in-progress'
                """,
                (operation.operation_id, operation.operation_digest),
            )
    except (DockerBenchmarkProviderError, sqlite3.Error):
        return


def _parse_provider_result(
    raw: object,
) -> tuple[BenchmarkTargetStageReceipt, WalkingBenchmarkRunObservation | None]:
    if not isinstance(raw, str) or not 1 <= len(raw.encode("utf-8")) <= _MAX_PROVIDER_RESULT_BYTES:
        raise DockerBenchmarkProviderError("Docker provider cached result is invalid")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {"receipt", "observation"}:
            raise ValueError("result shape differs")
        receipt = BenchmarkTargetStageReceipt.model_validate(value["receipt"])
        observation = (
            None
            if value["observation"] is None
            else WalkingBenchmarkRunObservation.model_validate(value["observation"])
        )
    except ValueError as exc:
        raise DockerBenchmarkProviderError("Docker provider cached result is invalid") from exc
    return receipt, observation


def _provider_scope(operation: BenchmarkTargetOperation) -> str:
    return benchmark_digest(
        "pajin.benchmark.docker-provider-scope/v1",
        {
            "adapterDigest": operation.adapter_digest,
            "coordinateDigest": operation.coordinate_digest,
        },
        max_bytes=4 * 1024,
    )


def _require_safe_state_path(path: Path) -> None:
    parent = path.parent
    if any(
        ancestor.exists() and (ancestor.is_symlink() or ancestor.is_junction())
        for ancestor in (parent, *parent.parents)
    ):
        raise DockerBenchmarkProviderError("Docker provider state ancestor is unsafe")
    if parent.exists() and not parent.is_dir():
        raise DockerBenchmarkProviderError("Docker provider state parent is unsafe")
    for candidate in (path, Path(f"{path}-journal"), Path(f"{path}-wal"), Path(f"{path}-shm")):
        if not (candidate.exists() or candidate.is_symlink() or candidate.is_junction()):
            continue
        if (
            not candidate.is_file()
            or candidate.is_symlink()
            or candidate.is_junction()
            or candidate.stat().st_nlink != 1
        ):
            raise DockerBenchmarkProviderError("Docker provider state is not a safe regular file")


def _operation_lock_path(state_path: Path) -> Path:
    return Path(f"{state_path}.operation-lock")


def _require_safe_lock_path(path: Path) -> None:
    parent = path.parent
    if any(
        ancestor.exists() and (ancestor.is_symlink() or ancestor.is_junction())
        for ancestor in (parent, *parent.parents)
    ):
        raise DockerBenchmarkProviderError("Docker provider operation lock ancestor is unsafe")
    for candidate in (path, Path(f"{path}-journal"), Path(f"{path}-wal"), Path(f"{path}-shm")):
        if not (candidate.exists() or candidate.is_symlink() or candidate.is_junction()):
            continue
        if (
            not candidate.is_file()
            or candidate.is_symlink()
            or candidate.is_junction()
            or candidate.stat().st_nlink != 1
        ):
            raise DockerBenchmarkProviderError(
                "Docker provider operation lock is not a safe regular file"
            )


def _open_write_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _provider_operation_lock(state_path: Path) -> Iterator[None]:
    path = _operation_lock_path(state_path)
    _require_safe_lock_path(path)
    connection = _open_write_connection(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        updated = connection.execute(
            "UPDATE operation_lock SET generation = generation + 1 WHERE singleton = 1"
        ).rowcount
        if updated != 1:
            raise DockerBenchmarkProviderError("Docker provider operation lock state differs")
        yield
        connection.commit()
    except sqlite3.Error as exc:
        connection.rollback()
        raise DockerBenchmarkProviderError("Docker provider operation lock failed") from exc
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
        _require_safe_lock_path(path)


@contextmanager
def _provider_write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_state_path(path)
    connection = _open_write_connection(path)
    try:
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except sqlite3.Error as exc:
        connection.rollback()
        raise DockerBenchmarkProviderError("Docker provider state transaction failed") from exc
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
        _require_safe_state_path(path)


@contextmanager
def _provider_read_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_state_path(path)
    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA query_only = ON")
    connection.execute("BEGIN")
    try:
        yield connection
    except sqlite3.Error as exc:
        raise DockerBenchmarkProviderError("Docker provider state read failed") from exc
    finally:
        connection.rollback()
        connection.close()
        _require_safe_state_path(path)
