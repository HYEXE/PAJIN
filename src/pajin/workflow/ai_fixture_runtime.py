"""AI-002B immutable Docker identities and one disposable M03 Target lifecycle."""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from typing import Annotated, Literal, Protocol, Self
from uuid import uuid4

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import benchmark_digest
from pajin.domain.models import StrictModel
from pajin.runtime.worker import DockerEgressLifecycleObservation
from pajin.target_attestation import (
    AIMeasurementTargetExecutionReceipt,
    AISourceTargetExecutionReceipt,
    TargetAttestationKeyState,
    TargetAttestationTrustAnchor,
    TargetAttestationVerificationKey,
    target_public_key_base64url,
)
from pajin.workflow.ai_measured_case_authority import (
    AI_M03_PROXY_IMAGE,
    AI_M03_TARGET_CONTAINER_PORT,
    AI_M03_TARGET_IMAGE,
    AI_M03_TARGET_ROUTE,
    AI_M03_WORKER_IMAGE,
    AIImageContractIdentity,
    AIImageIdentityProfileRef,
    AIM03MeasuredTargetProfileRef,
    AIMeasuredCaseRef,
    AIMeasurementImageRole,
    registered_ai_image_identity_profile,
    registered_ai_m03_measured_target_profile,
)

AI_SOURCE_IMAGE_BINDING_API_VERSION: Literal["pajin.dev/ai-source-image-binding/v1alpha1"] = (
    "pajin.dev/ai-source-image-binding/v1alpha1"
)
AI_FIXTURE_TARGET_ATTEMPT_API_VERSION: Literal["pajin.dev/ai-fixture-target-attempt/v1alpha1"] = (
    "pajin.dev/ai-fixture-target-attempt/v1alpha1"
)
AI_FIXTURE_TARGET_COORDINATE_API_VERSION: Literal[
    "pajin.dev/ai-fixture-target-coordinate/v1alpha1"
] = "pajin.dev/ai-fixture-target-coordinate/v1alpha1"
AI_FIXTURE_PROXY_TOPOLOGY_API_VERSION: Literal["pajin.dev/ai-fixture-proxy-topology/v1alpha1"] = (
    "pajin.dev/ai-fixture-proxy-topology/v1alpha1"
)
AI_FIXTURE_LIFECYCLE_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/ai-fixture-lifecycle-evidence/v1alpha1"
] = "pajin.dev/ai-fixture-lifecycle-evidence/v1alpha1"
AI_MEASUREMENT_FIXTURE_LIFECYCLE_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/ai-measurement-fixture-lifecycle-evidence/v1alpha1"
] = "pajin.dev/ai-measurement-fixture-lifecycle-evidence/v1alpha1"

_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_MAX_DOCKER_OUTPUT_BYTES = 1024 * 1024
_MANAGED_LABEL = "pajin.ai-fixture.managed"
_ATTEMPT_LABEL = "pajin.ai-fixture.attempt-digest"
_CASE_LABEL = "pajin.ai-fixture.case-digest"
_ROLE_LABEL = "pajin.ai-fixture.role"
_AI_SOURCE_TARGET_HOST = "host.docker.internal"
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageId = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_SafeDockerName = Annotated[
    str,
    Field(min_length=1, max_length=63, pattern=r"^[a-z0-9][a-z0-9_.-]{0,62}$"),
]
_DockerObjectId = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class AIFixtureRuntimeError(RuntimeError):
    """Raised when AI-002B Docker identity, topology, receipt, or cleanup drifts."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
    )


def _expected_image_reference(role: AIMeasurementImageRole) -> str:
    return {
        AIMeasurementImageRole.TARGET: AI_M03_TARGET_IMAGE,
        AIMeasurementImageRole.WORKER: AI_M03_WORKER_IMAGE,
        AIMeasurementImageRole.PROXY: AI_M03_PROXY_IMAGE,
    }[role]


def _registered_image_contract(role: AIMeasurementImageRole) -> AIImageContractIdentity:
    return next(item for item in registered_ai_image_identity_profile().roles if item.role is role)


class AISourceImageRoleBinding(_FrozenStrictModel):
    """One fixed AI image contract bound to an independently observed OCI ID."""

    role: AIMeasurementImageRole
    contract: AIImageContractIdentity
    image_reference: str = Field(alias="imageReference", min_length=1, max_length=300)
    observed_image_id: _ImageId = Field(alias="observedImageId")
    independently_inspected: Literal[True] = Field(
        default=True,
        alias="independentlyInspected",
    )
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)

    @field_validator("independently_inspected", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI source image inspection marker must be boolean true")
        return value

    @model_validator(mode="after")
    def bind_role(self) -> Self:
        if self.contract != _registered_image_contract(
            self.role
        ) or self.image_reference != _expected_image_reference(self.role):
            raise ValueError("AI source image role differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-source-image-role-binding/v1",
            material,
            max_bytes=256 * 1024,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("AI source image role binding Digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


class AISourceImageBindingRef(_FrozenStrictModel):
    binding_id: str = Field(
        alias="bindingId",
        pattern=r"^ai-source-image-binding_[a-f0-9]{64}$",
    )
    binding_digest: _Sha256 = Field(alias="bindingDigest")

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        if self.binding_id != f"ai-source-image-binding_{self.binding_digest}":
            raise ValueError("AI source image binding reference differs")
        return self


class AISourceImageBinding(_FrozenStrictModel):
    """Exact Target/Worker/proxy runtime identities without image-build authority."""

    api_version: Literal["pajin.dev/ai-source-image-binding/v1alpha1"] = Field(
        default=AI_SOURCE_IMAGE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AISourceImageBinding"] = "AISourceImageBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=105)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    image_profile: AIImageIdentityProfileRef = Field(alias="imageProfile")
    target_profile: AIM03MeasuredTargetProfileRef = Field(alias="targetProfile")
    roles: tuple[AISourceImageRoleBinding, ...] = Field(min_length=3, max_length=3)
    docker_image_build_authorized: Literal[False] = Field(
        default=False,
        alias="dockerImageBuildAuthorized",
    )
    caller_selected_image_authorized: Literal[False] = Field(
        default=False,
        alias="callerSelectedImageAuthorized",
    )
    runtime_image_use_bound: Literal[True] = Field(
        default=True,
        alias="runtimeImageUseBound",
    )

    @field_validator(
        "docker_image_build_authorized",
        "caller_selected_image_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI source image authority markers must be boolean false")
        return value

    @field_validator("runtime_image_use_bound", mode="before")
    @classmethod
    def require_runtime_binding(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI source runtime image binding marker must be true")
        return value

    @model_validator(mode="after")
    def bind_images(self) -> Self:
        profile = registered_ai_image_identity_profile()
        expected_roles = tuple(AIMeasurementImageRole)
        if (
            self.image_profile != profile.reference()
            or self.target_profile != registered_ai_m03_measured_target_profile().reference()
            or tuple(item.role for item in self.roles) != expected_roles
            or tuple(item.contract for item in self.roles) != profile.roles
            or len({item.observed_image_id for item in self.roles}) != len(self.roles)
        ):
            raise ValueError("AI source image membership, order, or identity differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-source-image-binding/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        binding_id = f"ai-source-image-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("AI source image binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("AI source image binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self

    def reference(self) -> AISourceImageBindingRef:
        return AISourceImageBindingRef(
            bindingId=self.binding_id,
            bindingDigest=self.binding_digest,
        )

    def role(self, role: AIMeasurementImageRole) -> AISourceImageRoleBinding:
        return next(item for item in self.roles if item.role is role).model_copy(deep=True)


class AIFixtureTargetAttempt(_FrozenStrictModel):
    """One fresh, code-owned M03 Target attempt."""

    api_version: Literal["pajin.dev/ai-fixture-target-attempt/v1alpha1"] = Field(
        default=AI_FIXTURE_TARGET_ATTEMPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIFixtureTargetAttempt"] = "AIFixtureTargetAttempt"
    attempt_id: str = Field(
        default="",
        alias="attemptId",
        pattern=r"^ai-fixture-attempt_[a-f0-9]{64}$",
    )
    attempt_digest: str = Field(default="", alias="attemptDigest", max_length=64)
    nonce: str = Field(pattern=r"^[a-f0-9]{32}$")
    case: AIMeasuredCaseRef
    images: AISourceImageBindingRef
    created_at: datetime = Field(alias="createdAt")
    caller_configuration_authorized: Literal[False] = Field(
        default=False,
        alias="callerConfigurationAuthorized",
    )

    @field_validator("caller_configuration_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("AI fixture caller configuration authority must be false")
        return value

    @model_validator(mode="after")
    def bind_attempt(self) -> Self:
        if self.created_at.tzinfo is None:
            raise ValueError("AI fixture attempt time must be timezone-aware")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"attempt_id", "attempt_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-fixture-target-attempt/v1",
            material,
            max_bytes=512 * 1024,
        )
        attempt_id = f"ai-fixture-attempt_{digest}"
        if self.attempt_digest and self.attempt_digest != digest:
            raise ValueError("AI fixture attempt Digest differs")
        if self.attempt_id and self.attempt_id != attempt_id:
            raise ValueError("AI fixture attempt ID differs")
        object.__setattr__(self, "attempt_digest", digest)
        object.__setattr__(self, "attempt_id", attempt_id)
        return self


@dataclass(frozen=True, slots=True)
class AIFixtureResourceNames:
    target_container_name: str
    target_network_name: str


def ai_fixture_resource_names(attempt: AIFixtureTargetAttempt) -> AIFixtureResourceNames:
    suffix = attempt.attempt_digest[:32]
    return AIFixtureResourceNames(
        target_container_name=f"pajin-ai-target-{suffix}",
        target_network_name=f"pajin-ai-net-{suffix}",
    )


class AIFixtureTargetCoordinate(_FrozenStrictModel):
    """Private exact coordinate for one isolated vulnerable Target."""

    api_version: Literal["pajin.dev/ai-fixture-target-coordinate/v1alpha1"] = Field(
        default=AI_FIXTURE_TARGET_COORDINATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIFixtureTargetCoordinate"] = "AIFixtureTargetCoordinate"
    coordinate_digest: str = Field(default="", alias="coordinateDigest", max_length=64)
    attempt_id: _Identifier = Field(alias="attemptId")
    attempt_digest: _Sha256 = Field(alias="attemptDigest")
    case: AIMeasuredCaseRef
    images: AISourceImageBindingRef
    target_container_name: _SafeDockerName = Field(alias="targetContainerName")
    target_container_id: _DockerObjectId = Field(alias="targetContainerId")
    target_image_id: _ImageId = Field(alias="targetImageId")
    target_network_name: _SafeDockerName = Field(alias="targetNetworkName")
    target_network_id: _DockerObjectId = Field(alias="targetNetworkId")
    target_url: str = Field(alias="targetUrl", min_length=1, max_length=300)
    internal_container_port: Literal[8080] = Field(
        default=AI_M03_TARGET_CONTAINER_PORT,
        alias="internalContainerPort",
    )
    route_path: Literal["/v1/chat"] = Field(default=AI_M03_TARGET_ROUTE, alias="routePath")
    target_mode: Literal["vulnerable"] = Field(default="vulnerable", alias="targetMode")
    network_internal: Literal[True] = Field(default=True, alias="networkInternal")
    published_port_count: Literal[0] = Field(default=0, alias="publishedPortCount")
    read_only_root: Literal[True] = Field(default=True, alias="readOnlyRoot")
    capability_drop_all: Literal[True] = Field(default=True, alias="capabilityDropAll")
    no_new_privileges: Literal[True] = Field(default=True, alias="noNewPrivileges")
    non_root_user: Literal[True] = Field(default=True, alias="nonRootUser")
    observed_at: datetime = Field(alias="observedAt")

    @field_validator("internal_container_port", "published_port_count", mode="before")
    @classmethod
    def require_exact_integers(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("AI fixture coordinate integers must be exact")
        return value

    @field_validator(
        "network_internal",
        "read_only_root",
        "capability_drop_all",
        "no_new_privileges",
        "non_root_user",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI fixture isolation observations must be true")
        return value

    @model_validator(mode="after")
    def bind_coordinate(self) -> Self:
        expected_url = (
            f"http://{_AI_SOURCE_TARGET_HOST}:{AI_M03_TARGET_CONTAINER_PORT}{AI_M03_TARGET_ROUTE}"
        )
        if (
            self.target_url != expected_url
            or self.observed_at.tzinfo is None
            or self.target_container_name != f"pajin-ai-target-{self.attempt_digest[:32]}"
            or self.target_network_name != f"pajin-ai-net-{self.attempt_digest[:32]}"
        ):
            raise ValueError("AI fixture coordinate differs from the fixed Target")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"coordinate_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-fixture-target-coordinate/v1",
            material,
            max_bytes=1024 * 1024,
        )
        if self.coordinate_digest and self.coordinate_digest != digest:
            raise ValueError("AI fixture coordinate Digest differs")
        object.__setattr__(self, "coordinate_digest", digest)
        return self


class AIFixtureProxyTopologyObservation(_FrozenStrictModel):
    """Host-observed Worker/proxy/Target topology and ephemeral cleanup."""

    api_version: Literal["pajin.dev/ai-fixture-proxy-topology/v1alpha1"] = Field(
        default=AI_FIXTURE_PROXY_TOPOLOGY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIFixtureProxyTopologyObservation"] = "AIFixtureProxyTopologyObservation"
    topology_digest: str = Field(default="", alias="topologyDigest", max_length=64)
    execution_id: _Identifier = Field(alias="executionId")
    worker_container_name: str = Field(alias="workerContainerName", min_length=1, max_length=128)
    worker_container_id: _DockerObjectId = Field(alias="workerContainerId")
    worker_image_id: _ImageId = Field(alias="workerImageId")
    proxy_container_name: str = Field(alias="proxyContainerName", min_length=1, max_length=128)
    proxy_container_id: _DockerObjectId = Field(alias="proxyContainerId")
    proxy_image_id: _ImageId = Field(alias="proxyImageId")
    internal_network_name: str = Field(alias="internalNetworkName", min_length=1, max_length=128)
    internal_network_id: _DockerObjectId = Field(alias="internalNetworkId")
    target_network_name: _SafeDockerName = Field(alias="targetNetworkName")
    target_network_id: _DockerObjectId = Field(alias="targetNetworkId")
    target_container_id: _DockerObjectId = Field(alias="targetContainerId")
    target_image_id: _ImageId = Field(alias="targetImageId")
    worker_network_ids: tuple[_DockerObjectId, ...] = Field(
        alias="workerNetworkIds",
        min_length=1,
        max_length=1,
    )
    proxy_network_ids: tuple[_DockerObjectId, ...] = Field(
        alias="proxyNetworkIds",
        min_length=2,
        max_length=2,
    )
    target_network_ids: tuple[_DockerObjectId, ...] = Field(
        alias="targetNetworkIds",
        min_length=1,
        max_length=1,
    )
    published_port_count: Literal[0] = Field(default=0, alias="publishedPortCount")
    attached_at: datetime = Field(alias="attachedAt")
    ephemeral_resources_absent_at: datetime = Field(alias="ephemeralResourcesAbsentAt")

    @field_validator("published_port_count", mode="before")
    @classmethod
    def require_zero_ports(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("AI fixture topology requires exact zero published ports")
        return value

    @model_validator(mode="after")
    def bind_topology(self) -> Self:
        if (
            self.attached_at.tzinfo is None
            or self.ephemeral_resources_absent_at.tzinfo is None
            or self.attached_at > self.ephemeral_resources_absent_at
            or self.worker_network_ids != (self.internal_network_id,)
            or self.target_network_ids != (self.target_network_id,)
            or self.proxy_network_ids
            != tuple(sorted((self.internal_network_id, self.target_network_id)))
        ):
            raise ValueError("AI fixture proxy-only topology differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"topology_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-fixture-proxy-topology/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.topology_digest and self.topology_digest != digest:
            raise ValueError("AI fixture topology Digest differs")
        object.__setattr__(self, "topology_digest", digest)
        return self


class AIFixtureTargetLifecycleEvidence(_FrozenStrictModel):
    """Private sealed Target, topology, signed receipt, and cleanup evidence."""

    api_version: Literal["pajin.dev/ai-fixture-lifecycle-evidence/v1alpha1"] = Field(
        default=AI_FIXTURE_LIFECYCLE_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIFixtureTargetLifecycleEvidence"] = "AIFixtureTargetLifecycleEvidence"
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    attempt: AIFixtureTargetAttempt
    coordinate: AIFixtureTargetCoordinate
    topology: AIFixtureProxyTopologyObservation
    target_receipt: AISourceTargetExecutionReceipt = Field(alias="targetReceipt")
    target_receipt_digest: _Sha256 = Field(alias="targetReceiptDigest")
    target_resources_absent: Literal[True] = Field(
        default=True,
        alias="targetResourcesAbsent",
    )
    cleanup_completed_at: datetime = Field(alias="cleanupCompletedAt")

    @field_validator("target_resources_absent", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI fixture Target cleanup observation must be true")
        return value

    @model_validator(mode="after")
    def bind_lifecycle(self) -> Self:
        if (
            self.coordinate.attempt_id != self.attempt.attempt_id
            or self.coordinate.attempt_digest != self.attempt.attempt_digest
            or self.coordinate.case != self.attempt.case
            or self.coordinate.images != self.attempt.images
            or self.topology.target_container_id != self.coordinate.target_container_id
            or self.topology.target_image_id != self.coordinate.target_image_id
            or self.topology.target_network_id != self.coordinate.target_network_id
            or self.topology.target_network_name != self.coordinate.target_network_name
            or self.target_receipt_digest != self.target_receipt.digest
            or self.cleanup_completed_at.tzinfo is None
            or self.cleanup_completed_at < self.topology.ephemeral_resources_absent_at
        ):
            raise ValueError("AI fixture lifecycle Evidence differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-fixture-lifecycle-evidence/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("AI fixture lifecycle Evidence Digest differs")
        object.__setattr__(self, "evidence_digest", digest)
        return self


class AIMeasurementFixtureTargetLifecycleEvidence(_FrozenStrictModel):
    """Private AI-002C Target, topology, receipt, and cleanup evidence."""

    api_version: Literal["pajin.dev/ai-measurement-fixture-lifecycle-evidence/v1alpha1"] = Field(
        default=AI_MEASUREMENT_FIXTURE_LIFECYCLE_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AIMeasurementFixtureTargetLifecycleEvidence"] = (
        "AIMeasurementFixtureTargetLifecycleEvidence"
    )
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)
    attempt: AIFixtureTargetAttempt
    coordinate: AIFixtureTargetCoordinate
    topology: AIFixtureProxyTopologyObservation
    target_receipt: AIMeasurementTargetExecutionReceipt = Field(alias="targetReceipt")
    target_receipt_digest: _Sha256 = Field(alias="targetReceiptDigest")
    target_resources_absent: Literal[True] = Field(
        default=True,
        alias="targetResourcesAbsent",
    )
    cleanup_completed_at: datetime = Field(alias="cleanupCompletedAt")

    @field_validator("target_resources_absent", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("AI measurement Target cleanup observation must be true")
        return value

    @model_validator(mode="after")
    def bind_lifecycle(self) -> Self:
        if (
            self.coordinate.attempt_id != self.attempt.attempt_id
            or self.coordinate.attempt_digest != self.attempt.attempt_digest
            or self.coordinate.case != self.attempt.case
            or self.coordinate.images != self.attempt.images
            or self.topology.target_container_id != self.coordinate.target_container_id
            or self.topology.target_image_id != self.coordinate.target_image_id
            or self.topology.target_network_id != self.coordinate.target_network_id
            or self.topology.target_network_name != self.coordinate.target_network_name
            or self.target_receipt_digest != self.target_receipt.digest
            or self.cleanup_completed_at.tzinfo is None
            or self.cleanup_completed_at < self.topology.ephemeral_resources_absent_at
        ):
            raise ValueError("AI measurement fixture lifecycle Evidence differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.ai-measurement-fixture-lifecycle-evidence/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("AI measurement lifecycle Evidence Digest differs")
        object.__setattr__(self, "evidence_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class AIDockerCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class AIDockerCommandRunner(Protocol):
    def run(self, arguments: Sequence[str]) -> AIDockerCommandResult: ...


class SubprocessAIDockerCommandRunner:
    """Shell-free bounded Docker CLI boundary used only by AI-002B."""

    def __init__(self, *, executable: str = "docker", timeout_seconds: int = 30) -> None:
        if (
            not isinstance(executable, str)
            or not executable
            or executable.strip() != executable
            or "\x00" in executable
        ):
            raise ValueError("AI Docker executable is unsafe")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("AI Docker timeout is invalid")
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    def run(self, arguments: Sequence[str]) -> AIDockerCommandResult:
        if not arguments or any(
            not isinstance(argument, str) or "\x00" in argument for argument in arguments
        ):
            raise ValueError("AI Docker arguments are unsafe")
        try:
            completed = subprocess.run(
                [self._executable, *arguments],
                capture_output=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise AIFixtureRuntimeError("AI Docker command failed") from exc
        if (
            len(completed.stdout) > _MAX_DOCKER_OUTPUT_BYTES
            or len(completed.stderr) > _MAX_DOCKER_OUTPUT_BYTES
        ):
            raise AIFixtureRuntimeError("AI Docker command output exceeded its bound")
        return AIDockerCommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class AIDockerImageInspector(Protocol):
    def image_id(self, reference: str) -> str: ...


def registered_ai_source_image_binding(
    inspector: AIDockerImageInspector,
) -> AISourceImageBinding:
    """Inspect the three fixed references and bind only immutable OCI IDs."""

    if not callable(getattr(inspector, "image_id", None)):
        raise TypeError("AI source image binding requires a Docker image inspector")
    roles = tuple(
        AISourceImageRoleBinding(
            role=role,
            contract=_registered_image_contract(role),
            imageReference=_expected_image_reference(role),
            observedImageId=inspector.image_id(_expected_image_reference(role)),
        )
        for role in AIMeasurementImageRole
    )
    return AISourceImageBinding(
        imageProfile=registered_ai_image_identity_profile().reference(),
        targetProfile=registered_ai_m03_measured_target_profile().reference(),
        roles=roles,
    )


def load_ai_source_image_binding(
    binding: AISourceImageBinding,
    *,
    inspector: AIDockerImageInspector,
) -> AISourceImageBinding:
    """Reparse and independently re-inspect every fixed image identity."""

    try:
        canonical = AISourceImageBinding.model_validate_json(binding.model_dump_json(by_alias=True))
        rebuilt = registered_ai_source_image_binding(inspector)
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise AIFixtureRuntimeError("AI source image binding is invalid") from exc
    if canonical != binding or canonical != rebuilt:
        raise AIFixtureRuntimeError("AI source image reference or OCI identity differs")
    return canonical.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class _AttachedAITopology:
    observation: DockerEgressLifecycleObservation
    worker_container_id: str
    worker_image_id: str
    proxy_container_id: str
    proxy_image_id: str
    internal_network_id: str
    target_network_id: str
    target_container_id: str
    target_image_id: str
    worker_network_ids: tuple[str, ...]
    proxy_network_ids: tuple[str, ...]
    target_network_ids: tuple[str, ...]
    attached_at: datetime


class AIDockerBoundaryInspector(AIDockerImageInspector, Protocol):
    """Host-owned AI Target and Worker/proxy topology observations."""

    def stable_observer_context(self) -> Mapping[str, object]: ...

    async def attached(self, observation: DockerEgressLifecycleObservation) -> None: ...

    async def cleaned(self, observation: DockerEgressLifecycleObservation) -> None: ...

    def topology_observation(
        self,
        execution_id: str,
    ) -> AIFixtureProxyTopologyObservation: ...


class SubprocessAIDockerBoundaryInspector:
    """Bounded Docker inspection for one exact AI-002B Target attempt."""

    def __init__(
        self,
        *,
        coordinate: AIFixtureTargetCoordinate,
        images: AISourceImageBinding,
        command_runner: AIDockerCommandRunner,
        timeout_seconds: int = 20,
    ) -> None:
        try:
            self._coordinate = AIFixtureTargetCoordinate.model_validate_json(
                coordinate.model_dump_json(by_alias=True)
            )
            self._images = AISourceImageBinding.model_validate_json(
                images.model_dump_json(by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise AIFixtureRuntimeError("AI Docker inspector context is invalid") from exc
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("AI Docker observation timeout is invalid")
        self._docker = command_runner
        self._timeout_seconds = timeout_seconds
        self._lock = Lock()
        self._attached: dict[str, _AttachedAITopology] = {}
        self._completed: dict[str, AIFixtureProxyTopologyObservation] = {}

    def stable_observer_context(self) -> Mapping[str, object]:
        return {
            "observerId": "pajin.ai-fixture-docker-boundary",
            "observerVersion": "1.0.0",
            "coordinateDigest": self._coordinate.coordinate_digest,
            "imageBindingDigest": self._images.binding_digest,
            "timeoutSeconds": self._timeout_seconds,
        }

    def image_id(self, reference: str) -> str:
        output = self._require_success(
            ("image", "inspect", _safe_reference(reference), "--format", "{{.Id}}")
        )
        return _require_image_id(_decode_utf8(output), label="image")

    async def attached(self, observation: DockerEgressLifecycleObservation) -> None:
        attached = await asyncio.to_thread(self._observe_attached, observation)
        with self._lock:
            if (
                observation.execution_id in self._attached
                or observation.execution_id in self._completed
            ):
                raise AIFixtureRuntimeError("AI Docker execution identity was reused")
            self._attached[observation.execution_id] = attached

    async def cleaned(self, observation: DockerEgressLifecycleObservation) -> None:
        with self._lock:
            attached = self._attached.get(observation.execution_id)
        if attached is None or attached.observation != observation:
            raise AIFixtureRuntimeError("AI Docker cleanup lacks its attached topology observation")
        completed = await asyncio.to_thread(self._observe_cleaned, attached)
        with self._lock:
            if self._attached.pop(observation.execution_id, None) != attached:
                raise AIFixtureRuntimeError("AI Docker topology changed during cleanup")
            self._completed[observation.execution_id] = completed

    def topology_observation(
        self,
        execution_id: str,
    ) -> AIFixtureProxyTopologyObservation:
        with self._lock:
            observed = self._completed.get(execution_id)
        if observed is None:
            raise AIFixtureRuntimeError("AI Docker topology observation is incomplete")
        return observed.model_copy(deep=True)

    def _observe_attached(
        self,
        observation: DockerEgressLifecycleObservation,
    ) -> _AttachedAITopology:
        deadline = time.monotonic() + self._timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                return self._observe_attached_once(observation)
            except AIFixtureRuntimeError as exc:
                last_error = exc
                time.sleep(0.05)
        raise AIFixtureRuntimeError("AI Docker topology did not become observable") from last_error

    def _observe_attached_once(
        self,
        observation: DockerEgressLifecycleObservation,
    ) -> _AttachedAITopology:
        coordinate = self._coordinate
        if observation.external_network_name != coordinate.target_network_name:
            raise AIFixtureRuntimeError("AI Docker proxy route differs")
        worker = self._single_inspect(("container", "inspect", observation.worker_container_name))
        proxy = self._single_inspect(("container", "inspect", observation.proxy_container_name))
        target = self._single_inspect(("container", "inspect", coordinate.target_container_name))
        internal = self._single_inspect(("network", "inspect", observation.internal_network_name))
        target_network = self._single_inspect(
            ("network", "inspect", coordinate.target_network_name)
        )
        worker_id = _require_object_id(worker.get("Id"), label="Worker container")
        proxy_id = _require_object_id(proxy.get("Id"), label="proxy container")
        target_id = _require_object_id(target.get("Id"), label="Target container")
        internal_id = _require_object_id(internal.get("Id"), label="internal network")
        target_network_id = _require_object_id(
            target_network.get("Id"),
            label="Target network",
        )
        internal_members = _network_member_ids(internal)
        target_members = _network_member_ids(target_network)
        worker_network_ids = _container_network_ids(worker)
        proxy_network_ids = _container_network_ids(proxy)
        target_network_ids = _container_network_ids(target)
        if (
            internal.get("Internal") is not True
            or target_network.get("Internal") is not True
            or internal_members != {worker_id, proxy_id}
            or target_members != {target_id, proxy_id}
            or worker_network_ids != (internal_id,)
            or proxy_network_ids != tuple(sorted((internal_id, target_network_id)))
            or target_network_ids != (target_network_id,)
            or target_id != coordinate.target_container_id
            or target_network_id != coordinate.target_network_id
            or _require_image_id(worker.get("Image"), label="Worker image")
            != self._images.role(AIMeasurementImageRole.WORKER).observed_image_id
            or _require_image_id(proxy.get("Image"), label="proxy image")
            != self._images.role(AIMeasurementImageRole.PROXY).observed_image_id
            or _require_image_id(target.get("Image"), label="Target image")
            != coordinate.target_image_id
            or _container_label(worker, "pajin.execution-id") != observation.execution_id
            or _container_label(proxy, "pajin.execution-id") != observation.execution_id
            or _container_label(target, _ATTEMPT_LABEL) != coordinate.attempt_digest
            or sum(_published_port_count(item) for item in (worker, proxy, target)) != 0
            or not all(_container_isolated(item) for item in (worker, proxy, target))
        ):
            raise AIFixtureRuntimeError("AI Docker Worker/proxy/Target topology differs")
        return _AttachedAITopology(
            observation=observation,
            worker_container_id=worker_id,
            worker_image_id=_require_image_id(worker.get("Image"), label="Worker image"),
            proxy_container_id=proxy_id,
            proxy_image_id=_require_image_id(proxy.get("Image"), label="proxy image"),
            internal_network_id=internal_id,
            target_network_id=target_network_id,
            target_container_id=target_id,
            target_image_id=_require_image_id(target.get("Image"), label="Target image"),
            worker_network_ids=worker_network_ids,
            proxy_network_ids=proxy_network_ids,
            target_network_ids=target_network_ids,
            attached_at=datetime.now(UTC),
        )

    def _observe_cleaned(
        self,
        attached: _AttachedAITopology,
    ) -> AIFixtureProxyTopologyObservation:
        observation = attached.observation
        if (
            self._resource_ids("container", observation.worker_container_name)
            or self._resource_ids("container", observation.proxy_container_name)
            or self._resource_ids("network", observation.internal_network_name)
            or self._execution_resources(observation.execution_id)
        ):
            raise AIFixtureRuntimeError("AI Docker Worker/proxy resources remain after cleanup")
        target = self._single_inspect(
            ("container", "inspect", self._coordinate.target_container_name)
        )
        network = self._single_inspect(("network", "inspect", self._coordinate.target_network_name))
        if (
            _require_object_id(target.get("Id"), label="Target container")
            != attached.target_container_id
            or _require_image_id(target.get("Image"), label="Target image")
            != attached.target_image_id
            or _require_object_id(network.get("Id"), label="Target network")
            != attached.target_network_id
            or _network_member_ids(network) != {attached.target_container_id}
        ):
            raise AIFixtureRuntimeError("AI Docker Target changed before cleanup")
        return AIFixtureProxyTopologyObservation(
            executionId=observation.execution_id,
            workerContainerName=observation.worker_container_name,
            workerContainerId=attached.worker_container_id,
            workerImageId=attached.worker_image_id,
            proxyContainerName=observation.proxy_container_name,
            proxyContainerId=attached.proxy_container_id,
            proxyImageId=attached.proxy_image_id,
            internalNetworkName=observation.internal_network_name,
            internalNetworkId=attached.internal_network_id,
            targetNetworkName=self._coordinate.target_network_name,
            targetNetworkId=attached.target_network_id,
            targetContainerId=attached.target_container_id,
            targetImageId=attached.target_image_id,
            workerNetworkIds=attached.worker_network_ids,
            proxyNetworkIds=attached.proxy_network_ids,
            targetNetworkIds=attached.target_network_ids,
            attachedAt=attached.attached_at,
            ephemeralResourcesAbsentAt=datetime.now(UTC),
        )

    def _single_inspect(self, arguments: Sequence[str]) -> dict[str, object]:
        try:
            value = _strict_json_value(
                _decode_utf8(self._require_success(arguments)),
                label="AI Docker inspect output",
            )
        except ValueError as exc:
            raise AIFixtureRuntimeError("AI Docker inspect output is invalid") from exc
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise AIFixtureRuntimeError("AI Docker inspect output is ambiguous")
        return value[0]

    def _require_success(self, arguments: Sequence[str]) -> bytes:
        result = self._docker.run(arguments)
        if result.returncode != 0:
            raise AIFixtureRuntimeError("AI Docker inspection was rejected")
        return result.stdout

    def _resource_ids(self, resource: str, name: str) -> tuple[str, ...]:
        command = (
            ("container", "ls", "--all", "--quiet", "--filter", f"name=^/{name}$")
            if resource == "container"
            else ("network", "ls", "--quiet", "--filter", f"name=^{name}$")
        )
        return _listed(self._require_success(command))

    def _execution_resources(self, execution_id: str) -> tuple[str, ...]:
        label = f"label=pajin.execution-id={execution_id}"
        containers = _listed(
            self._require_success(("container", "ls", "--all", "--quiet", "--filter", label))
        )
        networks = _listed(self._require_success(("network", "ls", "--quiet", "--filter", label)))
        return (*containers, *networks)


@dataclass(frozen=True, slots=True)
class AIFixtureLiveTarget:
    attempt: AIFixtureTargetAttempt
    coordinate: AIFixtureTargetCoordinate
    trust_anchor: TargetAttestationTrustAnchor


class AIFixtureDockerProvider:
    """Exact Docker provider for one code-owned vulnerable M03 Target."""

    def __init__(
        self,
        *,
        command_runner: AIDockerCommandRunner | None = None,
        ready_timeout_seconds: int = 20,
    ) -> None:
        if type(ready_timeout_seconds) is not int or not 1 <= ready_timeout_seconds <= 120:
            raise ValueError("AI fixture ready timeout is invalid")
        self._docker = command_runner or SubprocessAIDockerCommandRunner()
        self._ready_timeout_seconds = ready_timeout_seconds

    def image_id(self, reference: str) -> str:
        output = self._require_success(
            ("image", "inspect", _safe_reference(reference), "--format", "{{.Id}}")
        )
        return _require_image_id(_decode_utf8(output), label="image")

    def boundary_inspector(
        self,
        *,
        coordinate: AIFixtureTargetCoordinate,
        images: AISourceImageBinding,
    ) -> SubprocessAIDockerBoundaryInspector:
        return SubprocessAIDockerBoundaryInspector(
            coordinate=coordinate,
            images=images,
            command_runner=self._docker,
        )

    def start(
        self,
        *,
        case: AIMeasuredCaseRef,
        images: AISourceImageBinding,
    ) -> AIFixtureLiveTarget:
        if not isinstance(case, AIMeasuredCaseRef):
            raise TypeError("AI fixture requires an exact measured case reference")
        canonical_images = load_ai_source_image_binding(images, inspector=self)
        attempt = AIFixtureTargetAttempt(
            nonce=uuid4().hex,
            case=case,
            images=canonical_images.reference(),
            createdAt=datetime.now(UTC),
        )
        names = ai_fixture_resource_names(attempt)
        if self._resource_ids("container", names.target_container_name) or self._resource_ids(
            "network", names.target_network_name
        ):
            raise AIFixtureRuntimeError("AI fixture found colliding Docker resources")
        private_key = os.urandom(32)
        key_id = f"ai-source-key-{attempt.attempt_digest[:16]}"
        now = datetime.now(UTC)
        trust_anchor = TargetAttestationTrustAnchor(
            trust_domain="pajin.local/ai-source-target",
            issuer="PAJIN deterministic AI source target",
            target_profile="kisa-m03-source-v1",
            keys=[
                TargetAttestationVerificationKey(
                    key_id=key_id,
                    public_key_base64url=target_public_key_base64url(private_key),
                    state=TargetAttestationKeyState.ACTIVE,
                    not_before=now - timedelta(seconds=1),
                    not_after=now + timedelta(minutes=10),
                )
            ],
        )
        labels = (
            "--label",
            f"{_MANAGED_LABEL}=true",
            "--label",
            f"{_ATTEMPT_LABEL}={attempt.attempt_digest}",
            "--label",
            f"{_CASE_LABEL}={case.case_digest}",
        )
        created_network = False
        created_target = False
        try:
            self._require_success(
                (
                    "network",
                    "create",
                    "--internal",
                    *labels,
                    "--label",
                    f"{_ROLE_LABEL}=target-network",
                    names.target_network_name,
                )
            )
            created_network = True
            target_image = canonical_images.role(AIMeasurementImageRole.TARGET)
            self._require_success(
                (
                    "run",
                    "--detach",
                    "--init",
                    "--pull",
                    "never",
                    "--name",
                    names.target_container_name,
                    *labels,
                    "--label",
                    f"{_ROLE_LABEL}=target",
                    "--network",
                    names.target_network_name,
                    "--network-alias",
                    _AI_SOURCE_TARGET_HOST,
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
                    "--stop-timeout",
                    "1",
                    "--env",
                    "PAJIN_LAB_PROFILE=vulnerable",
                    "--env",
                    f"PAJIN_TARGET_ATTESTATION_KEY_ID={key_id}",
                    "--env",
                    f"PAJIN_TARGET_ATTESTATION_PRIVATE_KEY={_base64url(private_key)}",
                    "--env",
                    f"PAJIN_TARGET_ATTESTATION_TRUST_DOMAIN={trust_anchor.trust_domain}",
                    "--env",
                    f"PAJIN_TARGET_ATTESTATION_ISSUER={trust_anchor.issuer}",
                    "--env",
                    f"PAJIN_TARGET_ATTESTATION_PROFILE={trust_anchor.target_profile}",
                    target_image.observed_image_id,
                )
            )
            created_target = True
            self._wait_ready(names.target_container_name)
            coordinate = self._observe_target(
                attempt=attempt,
                names=names,
                target_image_id=target_image.observed_image_id,
            )
            return AIFixtureLiveTarget(
                attempt=attempt,
                coordinate=coordinate,
                trust_anchor=trust_anchor,
            )
        except BaseException:
            if created_target:
                self._remove_if_present(
                    "container",
                    names.target_container_name,
                    ("container", "rm", "--force", names.target_container_name),
                )
            if created_network:
                self._remove_if_present(
                    "network",
                    names.target_network_name,
                    ("network", "rm", names.target_network_name),
                )
            raise

    def source_target_receipt(
        self,
        live: AIFixtureLiveTarget,
    ) -> AISourceTargetExecutionReceipt:
        lines = self._decode_log_lines(
            self._require_success(("logs", live.coordinate.target_container_name))
        )
        ready = tuple(item for item in lines if item.get("event") == "ready")
        receipts = tuple(item for item in lines if item.get("event") == "ai-source-target-receipt")
        if (
            len(lines) != 2
            or lines[0] != {"event": "ready", "port": 8080, "transport": "http"}
            or lines[1].get("event") != "ai-source-target-receipt"
            or ready != ({"event": "ready", "port": 8080, "transport": "http"},)
            or len(receipts) != 1
            or set(receipts[0]) != {"event", "receipt"}
        ):
            raise AIFixtureRuntimeError(
                "AI fixture Target log lacks one exact ready and source receipt"
            )
        try:
            return AISourceTargetExecutionReceipt.model_validate(receipts[0]["receipt"])
        except (TypeError, ValidationError, ValueError) as exc:
            raise AIFixtureRuntimeError("AI fixture Target receipt is invalid") from exc

    def measurement_target_receipt(
        self,
        live: AIFixtureLiveTarget,
    ) -> AIMeasurementTargetExecutionReceipt:
        lines = self._decode_log_lines(
            self._require_success(("logs", live.coordinate.target_container_name))
        )
        ready = tuple(item for item in lines if item.get("event") == "ready")
        receipts = tuple(
            item for item in lines if item.get("event") == "ai-measurement-target-receipt"
        )
        if (
            len(lines) != 2
            or lines[0] != {"event": "ready", "port": 8080, "transport": "http"}
            or lines[1].get("event") != "ai-measurement-target-receipt"
            or ready != ({"event": "ready", "port": 8080, "transport": "http"},)
            or len(receipts) != 1
            or set(receipts[0]) != {"event", "receipt"}
        ):
            raise AIFixtureRuntimeError(
                "AI fixture Target log lacks one exact ready and measurement receipt"
            )
        try:
            return AIMeasurementTargetExecutionReceipt.model_validate(receipts[0]["receipt"])
        except (TypeError, ValidationError, ValueError) as exc:
            raise AIFixtureRuntimeError("AI fixture measurement Target receipt is invalid") from exc

    def finish(
        self,
        live: AIFixtureLiveTarget,
        *,
        topology: AIFixtureProxyTopologyObservation,
        target_receipt: AISourceTargetExecutionReceipt,
    ) -> AIFixtureTargetLifecycleEvidence:
        if (
            topology.target_container_id != live.coordinate.target_container_id
            or topology.target_network_id != live.coordinate.target_network_id
            or topology.target_image_id != live.coordinate.target_image_id
        ):
            raise AIFixtureRuntimeError("AI fixture finish topology differs")
        self.abort(live)
        return AIFixtureTargetLifecycleEvidence(
            attempt=live.attempt,
            coordinate=live.coordinate,
            topology=topology,
            targetReceipt=target_receipt,
            targetReceiptDigest=target_receipt.digest,
            targetResourcesAbsent=True,
            cleanupCompletedAt=datetime.now(UTC),
        )

    def finish_measurement(
        self,
        live: AIFixtureLiveTarget,
        *,
        topology: AIFixtureProxyTopologyObservation,
        target_receipt: AIMeasurementTargetExecutionReceipt,
    ) -> AIMeasurementFixtureTargetLifecycleEvidence:
        if (
            topology.target_container_id != live.coordinate.target_container_id
            or topology.target_network_id != live.coordinate.target_network_id
            or topology.target_image_id != live.coordinate.target_image_id
        ):
            raise AIFixtureRuntimeError("AI measurement fixture finish topology differs")
        self.abort(live)
        return AIMeasurementFixtureTargetLifecycleEvidence(
            attempt=live.attempt,
            coordinate=live.coordinate,
            topology=topology,
            targetReceipt=target_receipt,
            targetReceiptDigest=target_receipt.digest,
            targetResourcesAbsent=True,
            cleanupCompletedAt=datetime.now(UTC),
        )

    def abort(self, live: AIFixtureLiveTarget) -> None:
        names = ai_fixture_resource_names(live.attempt)
        self._remove_if_present(
            "container",
            names.target_container_name,
            ("container", "rm", "--force", names.target_container_name),
        )
        self._remove_if_present(
            "network",
            names.target_network_name,
            ("network", "rm", names.target_network_name),
        )
        if self._resource_ids("container", names.target_container_name) or self._resource_ids(
            "network", names.target_network_name
        ):
            raise AIFixtureRuntimeError("AI fixture Target resources remain after cleanup")

    def managed_resources_absent(self) -> bool:
        label = f"label={_MANAGED_LABEL}=true"
        return not _listed(
            self._require_success(("container", "ls", "--all", "--quiet", "--filter", label))
        ) and not _listed(self._require_success(("network", "ls", "--quiet", "--filter", label)))

    def _observe_target(
        self,
        *,
        attempt: AIFixtureTargetAttempt,
        names: AIFixtureResourceNames,
        target_image_id: str,
    ) -> AIFixtureTargetCoordinate:
        target = self._single_inspect(("container", "inspect", names.target_container_name))
        network = self._single_inspect(("network", "inspect", names.target_network_name))
        target_id = _require_object_id(target.get("Id"), label="Target container")
        network_id = _require_object_id(network.get("Id"), label="Target network")
        config = _mapping(target.get("Config"), label="Target Config")
        state = _mapping(target.get("State"), label="Target State")
        settings = _mapping(target.get("NetworkSettings"), label="Target NetworkSettings")
        endpoints = _mapping(settings.get("Networks"), label="Target networks")
        endpoint = _mapping(
            endpoints.get(names.target_network_name),
            label="Target endpoint",
        )
        aliases_value = endpoint.get("Aliases")
        if not isinstance(aliases_value, list) or any(
            not isinstance(item, str) for item in aliases_value
        ):
            raise AIFixtureRuntimeError("AI fixture Target aliases differ")
        aliases = tuple(aliases_value)
        labels = _string_mapping(config.get("Labels"), label="Target labels")
        network_labels = _string_mapping(network.get("Labels"), label="Target network labels")
        env = _environment(config.get("Env"))
        required_env = {
            "PAJIN_LAB_PROFILE",
            "PAJIN_TARGET_ATTESTATION_KEY_ID",
            "PAJIN_TARGET_ATTESTATION_PRIVATE_KEY",
            "PAJIN_TARGET_ATTESTATION_TRUST_DOMAIN",
            "PAJIN_TARGET_ATTESTATION_ISSUER",
            "PAJIN_TARGET_ATTESTATION_PROFILE",
        }
        forbidden_env = {
            "PAJIN_PROVIDER_CREDENTIAL",
            "PAJIN_TARGET_TLS_CERTIFICATE",
            "PAJIN_TARGET_TLS_PRIVATE_KEY",
            "PAJIN_TARGET_TLS_SESSION_BINDING",
        }
        if (
            network.get("Internal") is not True
            or _network_member_ids(network) != {target_id}
            or target.get("Image") != target_image_id
            or state.get("Running") is not True
            or not _container_isolated(target)
            or config.get("Entrypoint") != ["python", "/app/target.py"]
            or config.get("Cmd") not in (None, [])
            or _published_port_count(target) != 0
            or tuple(endpoints) != (names.target_network_name,)
            or _AI_SOURCE_TARGET_HOST not in aliases
            or env.get("PAJIN_LAB_PROFILE") != "vulnerable"
            or not required_env.issubset(env)
            or not forbidden_env.isdisjoint(env)
            or labels.get(_MANAGED_LABEL) != "true"
            or labels.get(_ATTEMPT_LABEL) != attempt.attempt_digest
            or labels.get(_CASE_LABEL) != attempt.case.case_digest
            or labels.get(_ROLE_LABEL) != "target"
            or network_labels.get(_MANAGED_LABEL) != "true"
            or network_labels.get(_ATTEMPT_LABEL) != attempt.attempt_digest
            or network_labels.get(_CASE_LABEL) != attempt.case.case_digest
            or network_labels.get(_ROLE_LABEL) != "target-network"
        ):
            raise AIFixtureRuntimeError("AI fixture Target isolation or configuration differs")
        return AIFixtureTargetCoordinate(
            attemptId=attempt.attempt_id,
            attemptDigest=attempt.attempt_digest,
            case=attempt.case,
            images=attempt.images,
            targetContainerName=names.target_container_name,
            targetContainerId=target_id,
            targetImageId=target_image_id,
            targetNetworkName=names.target_network_name,
            targetNetworkId=network_id,
            targetUrl=(
                f"http://{_AI_SOURCE_TARGET_HOST}:"
                f"{AI_M03_TARGET_CONTAINER_PORT}{AI_M03_TARGET_ROUTE}"
            ),
            observedAt=datetime.now(UTC),
        )

    def _wait_ready(self, container_name: str) -> None:
        deadline = time.monotonic() + self._ready_timeout_seconds
        last_error: Exception | None = None
        expected = {"event": "ready", "port": 8080, "transport": "http"}
        while time.monotonic() < deadline:
            try:
                lines = self._decode_log_lines(self._require_success(("logs", container_name)))
                if lines == (expected,):
                    return
            except AIFixtureRuntimeError as exc:
                last_error = exc
            time.sleep(0.05)
        raise AIFixtureRuntimeError(
            "AI fixture Target did not report its exact ready event"
        ) from last_error

    @staticmethod
    def _decode_log_lines(raw: bytes) -> tuple[dict[str, object], ...]:
        values: list[dict[str, object]] = []
        for line in _decode_utf8(raw).splitlines():
            try:
                value = _strict_json_value(line, label="AI fixture Target log")
            except ValueError as exc:
                raise AIFixtureRuntimeError("AI fixture Target log is invalid") from exc
            if not isinstance(value, dict):
                raise AIFixtureRuntimeError("AI fixture Target log is not an object")
            values.append(value)
        return tuple(values)

    def _single_inspect(self, arguments: Sequence[str]) -> dict[str, object]:
        try:
            value = _strict_json_value(
                _decode_utf8(self._require_success(arguments)),
                label="AI Docker inspect output",
            )
        except ValueError as exc:
            raise AIFixtureRuntimeError("AI Docker inspect output is invalid") from exc
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise AIFixtureRuntimeError("AI Docker inspect output is ambiguous")
        return value[0]

    def _require_success(self, arguments: Sequence[str]) -> bytes:
        result = self._docker.run(arguments)
        if result.returncode != 0:
            raise AIFixtureRuntimeError("AI fixture Docker command was rejected")
        return result.stdout

    def _resource_ids(self, resource: str, name: str) -> tuple[str, ...]:
        command = (
            ("container", "ls", "--all", "--quiet", "--filter", f"name=^/{name}$")
            if resource == "container"
            else ("network", "ls", "--quiet", "--filter", f"name=^{name}$")
        )
        return _listed(self._require_success(command))

    def _remove_if_present(
        self,
        resource: str,
        name: str,
        remove_arguments: Sequence[str],
    ) -> None:
        if self._resource_ids(resource, name):
            self._require_success(remove_arguments)


def _safe_reference(value: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value or chr(0) in value:
        raise ValueError("AI Docker image reference is unsafe")
    return value


def _decode_utf8(value: bytes) -> str:
    try:
        return value.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise AIFixtureRuntimeError("AI Docker output is not UTF-8") from exc


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant is forbidden: {value}")


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _strict_json_value(raw: str, *, label: str) -> object:
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise ValueError(f"{label} is not strict JSON") from exc


def _listed(value: bytes) -> tuple[str, ...]:
    return tuple(line for line in _decode_utf8(value).splitlines() if line)


def _base64url(value: bytes) -> str:
    from base64 import urlsafe_b64encode

    return urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _require_object_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise AIFixtureRuntimeError(f"AI Docker {label} identity differs")
    return value


def _require_image_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None:
        raise AIFixtureRuntimeError(f"AI Docker {label} identity differs")
    return value


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise AIFixtureRuntimeError(f"AI Docker {label} is invalid")
    return value


def _string_mapping(value: object, *, label: str) -> Mapping[str, str]:
    if not isinstance(value, dict) or any(
        not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
    ):
        raise AIFixtureRuntimeError(f"AI Docker {label} is invalid")
    return value


def _environment(value: object) -> Mapping[str, str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise AIFixtureRuntimeError("AI Docker Target environment is invalid")
    result: dict[str, str] = {}
    for item in value:
        key, separator, setting = item.partition("=")
        if not separator or not key or key in result:
            raise AIFixtureRuntimeError("AI Docker Target environment is ambiguous")
        result[key] = setting
    return result


def _network_member_ids(network: Mapping[str, object]) -> set[str]:
    containers = network.get("Containers")
    if not isinstance(containers, dict):
        raise AIFixtureRuntimeError("AI Docker network members are invalid")
    return {_require_object_id(value, label="network member") for value in containers}


def _container_network_ids(container: Mapping[str, object]) -> tuple[str, ...]:
    settings = container.get("NetworkSettings")
    networks = settings.get("Networks") if isinstance(settings, dict) else None
    if not isinstance(networks, dict):
        raise AIFixtureRuntimeError("AI Docker container networks are invalid")
    identifiers: list[str] = []
    for endpoint in networks.values():
        if not isinstance(endpoint, dict):
            raise AIFixtureRuntimeError("AI Docker endpoint is invalid")
        identifiers.append(_require_object_id(endpoint.get("NetworkID"), label="container network"))
    return tuple(sorted(identifiers))


def _container_label(container: Mapping[str, object], label: str) -> object:
    config = container.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    return labels.get(label) if isinstance(labels, dict) else None


def _published_port_count(container: Mapping[str, object]) -> int:
    host = container.get("HostConfig")
    settings = container.get("NetworkSettings")
    bindings = host.get("PortBindings") if isinstance(host, dict) else None
    ports = settings.get("Ports") if isinstance(settings, dict) else None
    if bindings not in (None, {}) or not isinstance(ports, dict):
        raise AIFixtureRuntimeError("AI Docker port state differs")
    if any(value not in (None, []) for value in ports.values()):
        raise AIFixtureRuntimeError("AI Docker published ports are not zero")
    return 0


def _container_isolated(container: Mapping[str, object]) -> bool:
    config = container.get("Config")
    host = container.get("HostConfig")
    if not isinstance(config, dict) or not isinstance(host, dict):
        return False
    security_options = host.get("SecurityOpt")
    return (
        host.get("ReadonlyRootfs") is True
        and host.get("CapDrop") == ["ALL"]
        and isinstance(security_options, list)
        and any(
            isinstance(option, str) and option.split(":", maxsplit=1)[0] == "no-new-privileges"
            for option in security_options
        )
        and config.get("User") == "65532:65532"
    )


__all__ = [
    "AI_FIXTURE_LIFECYCLE_EVIDENCE_API_VERSION",
    "AI_FIXTURE_PROXY_TOPOLOGY_API_VERSION",
    "AI_FIXTURE_TARGET_ATTEMPT_API_VERSION",
    "AI_FIXTURE_TARGET_COORDINATE_API_VERSION",
    "AI_MEASUREMENT_FIXTURE_LIFECYCLE_EVIDENCE_API_VERSION",
    "AI_SOURCE_IMAGE_BINDING_API_VERSION",
    "AIDockerBoundaryInspector",
    "AIDockerCommandResult",
    "AIDockerCommandRunner",
    "AIDockerImageInspector",
    "AIFixtureDockerProvider",
    "AIFixtureLiveTarget",
    "AIFixtureProxyTopologyObservation",
    "AIFixtureRuntimeError",
    "AIFixtureTargetAttempt",
    "AIFixtureTargetCoordinate",
    "AIFixtureTargetLifecycleEvidence",
    "AIMeasurementFixtureTargetLifecycleEvidence",
    "AISourceImageBinding",
    "AISourceImageBindingRef",
    "AISourceImageRoleBinding",
    "SubprocessAIDockerBoundaryInspector",
    "SubprocessAIDockerCommandRunner",
    "ai_fixture_resource_names",
    "load_ai_source_image_binding",
    "registered_ai_source_image_binding",
]
