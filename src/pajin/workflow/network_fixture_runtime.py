"""NET-002B immutable Docker image and disposable Network fixture runtime."""

from __future__ import annotations

import asyncio
import json
import os
import re
import sqlite3
import subprocess
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from ipaddress import ip_address
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.models import benchmark_digest
from pajin.domain.models import StrictModel
from pajin.runtime.worker import (
    DockerEgressLifecycleObservation,
    DockerEgressLifecycleObserver,
)
from pajin.workflow.network_measured_case_authority import (
    NETWORK_TCP_BANNER_EMITTER_PORT,
    NetworkImageContractIdentity,
    NetworkImageIdentityProfileRef,
    NetworkMeasuredCaseRef,
    NetworkMeasurementImageRole,
    NetworkTCPBannerEmitterProfileRef,
    registered_network_image_identity_profile,
    registered_network_tcp_banner_emitter_profile,
)

NETWORK_SOURCE_IMAGE_BINDING_API_VERSION: Literal[
    "pajin.dev/network-source-image-binding/v1alpha1"
] = "pajin.dev/network-source-image-binding/v1alpha1"
NETWORK_FIXTURE_TARGET_ATTEMPT_API_VERSION: Literal[
    "pajin.dev/network-fixture-target-attempt/v1alpha1"
] = "pajin.dev/network-fixture-target-attempt/v1alpha1"
NETWORK_FIXTURE_TARGET_COORDINATE_API_VERSION: Literal[
    "pajin.dev/network-fixture-target-coordinate/v1alpha1"
] = "pajin.dev/network-fixture-target-coordinate/v1alpha1"
NETWORK_FIXTURE_TARGET_OPERATION_API_VERSION: Literal[
    "pajin.dev/network-fixture-target-operation/v1alpha1"
] = "pajin.dev/network-fixture-target-operation/v1alpha1"
NETWORK_FIXTURE_TARGET_RECEIPT_API_VERSION: Literal[
    "pajin.dev/network-fixture-target-receipt/v1alpha1"
] = "pajin.dev/network-fixture-target-receipt/v1alpha1"
NETWORK_FIXTURE_PROXY_TOPOLOGY_API_VERSION: Literal[
    "pajin.dev/network-fixture-proxy-topology/v1alpha1"
] = "pajin.dev/network-fixture-proxy-topology/v1alpha1"
NETWORK_FIXTURE_TARGET_RECOVERY_API_VERSION: Literal[
    "pajin.dev/network-fixture-target-recovery/v1alpha1"
] = "pajin.dev/network-fixture-target-recovery/v1alpha1"

NETWORK_BANNER_EMITTER_IMAGE = "pajin-network-banner-emitter:dev"
NETWORK_WORKER_IMAGE = "pajin-worker:dev"
NETWORK_EGRESS_PROXY_IMAGE = "pajin-egress-proxy:dev"

_MAX_CANONICAL_BYTES = 4 * 1024 * 1024
_MAX_DOCKER_OUTPUT_BYTES = 1024 * 1024
_BUSY_TIMEOUT_MS = 5_000
_MANAGED_LABEL = "pajin.network-fixture.managed"
_ATTEMPT_LABEL = "pajin.network-fixture.attempt-digest"
_CASE_LABEL = "pajin.network-fixture.case-digest"
_ROLE_LABEL = "pajin.network-fixture.role"
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
_DockerWorkerName = Annotated[
    str,
    Field(min_length=1, max_length=128, pattern=r"^[a-z0-9][a-z0-9_.-]{0,127}$"),
]


class NetworkFixtureRuntimeError(RuntimeError):
    """Raised when NET-002B Docker identity or lifecycle evidence drifts."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        frozen=True,
        strict=True,
    )


def _expected_image_reference(role: NetworkMeasurementImageRole) -> str:
    return {
        NetworkMeasurementImageRole.TARGET: NETWORK_BANNER_EMITTER_IMAGE,
        NetworkMeasurementImageRole.WORKER: NETWORK_WORKER_IMAGE,
        NetworkMeasurementImageRole.PROXY: NETWORK_EGRESS_PROXY_IMAGE,
    }[role]


def _registered_image_contract(role: NetworkMeasurementImageRole) -> NetworkImageContractIdentity:
    return next(
        item for item in registered_network_image_identity_profile().roles if item.role is role
    )


class NetworkSourceImageRoleBinding(_FrozenStrictModel):
    """One logical image reference bound to an independently observed OCI image ID."""

    role: NetworkMeasurementImageRole
    contract: NetworkImageContractIdentity
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
            raise ValueError("Network source image inspection marker must be boolean true")
        return value

    @model_validator(mode="after")
    def bind_role(self) -> Self:
        if self.contract != _registered_image_contract(
            self.role
        ) or self.image_reference != _expected_image_reference(self.role):
            raise ValueError("Network source image role differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-source-image-role-binding/v1",
            material,
            max_bytes=256 * 1024,
        )
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Network source image role binding Digest differs")
        object.__setattr__(self, "binding_digest", digest)
        return self


class NetworkSourceImageBindingRef(_FrozenStrictModel):
    binding_id: str = Field(
        alias="bindingId",
        pattern=r"^network-source-image-binding_[a-f0-9]{64}$",
    )
    binding_digest: _Sha256 = Field(alias="bindingDigest")

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        if self.binding_id != f"network-source-image-binding_{self.binding_digest}":
            raise ValueError("Network source image binding reference differs")
        return self


class NetworkSourceImageBinding(_FrozenStrictModel):
    """Exact Target/Worker/proxy runtime identities; image build is outside this authority."""

    api_version: Literal["pajin.dev/network-source-image-binding/v1alpha1"] = Field(
        default=NETWORK_SOURCE_IMAGE_BINDING_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkSourceImageBinding"] = "NetworkSourceImageBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=110)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    image_profile: NetworkImageIdentityProfileRef = Field(alias="imageProfile")
    emitter_profile: NetworkTCPBannerEmitterProfileRef = Field(alias="emitterProfile")
    roles: tuple[NetworkSourceImageRoleBinding, ...] = Field(min_length=3, max_length=3)
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
            raise ValueError("Network source image authority markers must be boolean false")
        return value

    @field_validator("runtime_image_use_bound", mode="before")
    @classmethod
    def require_runtime_binding(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Network source runtime image binding marker must be true")
        return value

    @model_validator(mode="after")
    def bind_images(self) -> Self:
        profile = registered_network_image_identity_profile()
        emitter = registered_network_tcp_banner_emitter_profile()
        expected_roles = tuple(NetworkMeasurementImageRole)
        if (
            self.image_profile != profile.reference()
            or self.emitter_profile != emitter.reference()
            or tuple(item.role for item in self.roles) != expected_roles
            or tuple(item.contract for item in self.roles) != profile.roles
            or len({item.observed_image_id for item in self.roles}) != len(self.roles)
        ):
            raise ValueError("Network source image binding membership or order differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-source-image-binding/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        binding_id = f"network-source-image-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Network source image binding Digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("Network source image binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self

    def reference(self) -> NetworkSourceImageBindingRef:
        return NetworkSourceImageBindingRef(
            bindingId=self.binding_id,
            bindingDigest=self.binding_digest,
        )

    def role(self, role: NetworkMeasurementImageRole) -> NetworkSourceImageRoleBinding:
        return next(item for item in self.roles if item.role is role).model_copy(deep=True)


class NetworkFixtureTargetAttempt(_FrozenStrictModel):
    """One fenced, case-bound disposable Target attempt."""

    api_version: Literal["pajin.dev/network-fixture-target-attempt/v1alpha1"] = Field(
        default=NETWORK_FIXTURE_TARGET_ATTEMPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkFixtureTargetAttempt"] = "NetworkFixtureTargetAttempt"
    attempt_id: str = Field(default="", alias="attemptId", max_length=110)
    attempt_digest: str = Field(default="", alias="attemptDigest", max_length=64)
    scope_digest: _Sha256 = Field(alias="scopeDigest")
    case: NetworkMeasuredCaseRef
    images: NetworkSourceImageBindingRef
    fence: int = Field(strict=True, ge=1, le=2**63 - 1)
    started_at: datetime = Field(alias="startedAt")

    @field_validator("started_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Network fixture attempt timestamp requires a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_attempt(self) -> Self:
        expected_scope = benchmark_digest(
            "pajin.workflow.network-fixture-target-scope/v1",
            {
                "case": self.case.model_dump(mode="json", by_alias=True),
                "images": self.images.model_dump(mode="json", by_alias=True),
            },
            max_bytes=512 * 1024,
        )
        if self.scope_digest != expected_scope:
            raise ValueError("Network fixture attempt scope differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"attempt_id", "attempt_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-fixture-target-attempt/v1",
            material,
            max_bytes=1024 * 1024,
        )
        attempt_id = f"network-fixture-attempt:{digest}"
        if self.attempt_digest and self.attempt_digest != digest:
            raise ValueError("Network fixture attempt Digest differs")
        if self.attempt_id and self.attempt_id != attempt_id:
            raise ValueError("Network fixture attempt ID differs")
        object.__setattr__(self, "attempt_digest", digest)
        object.__setattr__(self, "attempt_id", attempt_id)
        return self


@dataclass(frozen=True, slots=True)
class NetworkFixtureResourceNames:
    target_container_name: str
    target_network_name: str


def network_fixture_resource_names(
    attempt: NetworkFixtureTargetAttempt,
) -> NetworkFixtureResourceNames:
    suffix = attempt.attempt_digest[:20]
    return NetworkFixtureResourceNames(
        target_container_name=f"pajin-net-target-{suffix}",
        target_network_name=f"pajin-net-target-net-{suffix}",
    )


class NetworkFixtureTargetOperation(_FrozenStrictModel):
    """One intent-before-call Target operation under an active fence."""

    api_version: Literal["pajin.dev/network-fixture-target-operation/v1alpha1"] = Field(
        default=NETWORK_FIXTURE_TARGET_OPERATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkFixtureTargetOperation"] = "NetworkFixtureTargetOperation"
    operation_id: str = Field(default="", alias="operationId", max_length=110)
    operation_digest: str = Field(default="", alias="operationDigest", max_length=64)
    attempt_id: _Identifier = Field(alias="attemptId")
    attempt_digest: _Sha256 = Field(alias="attemptDigest")
    scope_digest: _Sha256 = Field(alias="scopeDigest")
    fence: int = Field(strict=True, ge=1, le=2**63 - 1)
    stage: Literal["reset", "isolation", "cleanup"]
    ordinal: int = Field(strict=True, ge=1, le=3)

    @model_validator(mode="after")
    def bind_operation(self) -> Self:
        expected_ordinal = {"reset": 1, "isolation": 2, "cleanup": 3}[self.stage]
        if self.ordinal != expected_ordinal:
            raise ValueError("Network fixture operation ordinal differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"operation_id", "operation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-fixture-target-operation/v1",
            material,
            max_bytes=512 * 1024,
        )
        operation_id = f"network-fixture-operation:{digest}"
        if self.operation_digest and self.operation_digest != digest:
            raise ValueError("Network fixture operation Digest differs")
        if self.operation_id and self.operation_id != operation_id:
            raise ValueError("Network fixture operation ID differs")
        object.__setattr__(self, "operation_digest", digest)
        object.__setattr__(self, "operation_id", operation_id)
        return self


class NetworkFixtureTargetCoordinate(_FrozenStrictModel):
    """Private inspected IP-literal Target coordinate with no host publication."""

    api_version: Literal["pajin.dev/network-fixture-target-coordinate/v1alpha1"] = Field(
        default=NETWORK_FIXTURE_TARGET_COORDINATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkFixtureTargetCoordinate"] = "NetworkFixtureTargetCoordinate"
    coordinate_id: str = Field(default="", alias="coordinateId", max_length=110)
    coordinate_digest: str = Field(default="", alias="coordinateDigest", max_length=64)
    case: NetworkMeasuredCaseRef
    attempt_id: _Identifier = Field(alias="attemptId")
    attempt_digest: _Sha256 = Field(alias="attemptDigest")
    target_container_name: _SafeDockerName = Field(alias="targetContainerName")
    target_container_id: _Sha256 = Field(alias="targetContainerId")
    target_image_id: _ImageId = Field(alias="targetImageId")
    target_network_name: _SafeDockerName = Field(alias="targetNetworkName")
    target_network_id: _Sha256 = Field(alias="targetNetworkId")
    address_family: Literal["ipv4"] = Field(default="ipv4", alias="addressFamily")
    host: str = Field(min_length=1, max_length=45)
    port: Literal[18080] = 18_080
    network_internal: Literal[True] = Field(default=True, alias="networkInternal")
    published_port_count: Literal[0] = Field(default=0, alias="publishedPortCount")
    read_only_root: Literal[True] = Field(default=True, alias="readOnlyRoot")
    capability_drop_all: Literal[True] = Field(default=True, alias="capabilityDropAll")
    no_new_privileges: Literal[True] = Field(default=True, alias="noNewPrivileges")
    non_root_user: Literal[True] = Field(default=True, alias="nonRootUser")
    observed_at: datetime = Field(alias="observedAt")

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
            raise ValueError("Network fixture isolation markers must be boolean true")
        return value

    @field_validator("published_port_count", mode="before")
    @classmethod
    def require_zero_ports(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("Network fixture published-port count must be integer zero")
        return value

    @field_validator("observed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Network fixture coordinate timestamp requires a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_coordinate(self) -> Self:
        try:
            address = ip_address(self.host)
        except ValueError as exc:
            raise ValueError("Network fixture Target host must be an IP literal") from exc
        if (
            address.version != 4
            or str(address) != self.host
            or address.is_global
            or address.is_loopback
            or address.is_unspecified
        ):
            raise ValueError("Network fixture Target host must be one canonical internal IPv4")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"coordinate_id", "coordinate_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-fixture-target-coordinate/v1",
            material,
            max_bytes=1024 * 1024,
        )
        coordinate_id = f"network-fixture-coordinate:{digest}"
        if self.coordinate_digest and self.coordinate_digest != digest:
            raise ValueError("Network fixture Target coordinate Digest differs")
        if self.coordinate_id and self.coordinate_id != coordinate_id:
            raise ValueError("Network fixture Target coordinate ID differs")
        object.__setattr__(self, "coordinate_digest", digest)
        object.__setattr__(self, "coordinate_id", coordinate_id)
        return self


class NetworkFixtureTargetStageReceipt(_FrozenStrictModel):
    """Content-addressed receipt for one exact Target lifecycle stage."""

    api_version: Literal["pajin.dev/network-fixture-target-receipt/v1alpha1"] = Field(
        default=NETWORK_FIXTURE_TARGET_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkFixtureTargetStageReceipt"] = "NetworkFixtureTargetStageReceipt"
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    operation_id: _Identifier = Field(alias="operationId")
    operation_digest: _Sha256 = Field(alias="operationDigest")
    attempt_id: _Identifier = Field(alias="attemptId")
    attempt_digest: _Sha256 = Field(alias="attemptDigest")
    fence: int = Field(strict=True, ge=1, le=2**63 - 1)
    stage: Literal["reset", "isolation", "cleanup"]
    status: Literal["succeeded"] = "succeeded"
    coordinate_digest: _Sha256 | None = Field(default=None, alias="coordinateDigest")
    resources_absent: bool = Field(alias="resourcesAbsent")
    completed_at: datetime = Field(alias="completedAt")

    @field_validator("resources_absent", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Network fixture absence marker must be a boolean")
        return value

    @field_validator("completed_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Network fixture receipt timestamp requires a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        if self.stage == "reset":
            if self.coordinate_digest is not None or self.resources_absent is not True:
                raise ValueError("Network fixture reset receipt differs")
        elif self.stage == "isolation":
            if self.coordinate_digest is None or self.resources_absent is not False:
                raise ValueError("Network fixture isolation receipt differs")
        elif self.resources_absent is not True:
            raise ValueError("Network fixture cleanup receipt differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-fixture-target-stage-receipt/v1",
            material,
            max_bytes=1024 * 1024,
        )
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Network fixture receipt Digest differs")
        object.__setattr__(self, "receipt_digest", digest)
        return self


class NetworkFixtureProxyTopologyObservation(_FrozenStrictModel):
    """Host-observed Worker/proxy/Target topology before and after Worker cleanup."""

    api_version: Literal["pajin.dev/network-fixture-proxy-topology/v1alpha1"] = Field(
        default=NETWORK_FIXTURE_PROXY_TOPOLOGY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkFixtureProxyTopologyObservation"] = (
        "NetworkFixtureProxyTopologyObservation"
    )
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    execution_id: _Identifier = Field(alias="executionId")
    worker_container_name: _DockerWorkerName = Field(alias="workerContainerName")
    worker_container_id: _Sha256 = Field(alias="workerContainerId")
    worker_image_id: _ImageId = Field(alias="workerImageId")
    proxy_container_name: _SafeDockerName = Field(alias="proxyContainerName")
    proxy_container_id: _Sha256 = Field(alias="proxyContainerId")
    proxy_image_id: _ImageId = Field(alias="proxyImageId")
    internal_network_name: _SafeDockerName = Field(alias="internalNetworkName")
    internal_network_id: _Sha256 = Field(alias="internalNetworkId")
    target_network_name: _SafeDockerName = Field(alias="targetNetworkName")
    target_network_id: _Sha256 = Field(alias="targetNetworkId")
    target_container_id: _Sha256 = Field(alias="targetContainerId")
    target_image_id: _ImageId = Field(alias="targetImageId")
    worker_network_ids: tuple[_Sha256, ...] = Field(alias="workerNetworkIds")
    proxy_network_ids: tuple[_Sha256, ...] = Field(alias="proxyNetworkIds")
    target_network_ids: tuple[_Sha256, ...] = Field(alias="targetNetworkIds")
    published_port_count: Literal[0] = Field(default=0, alias="publishedPortCount")
    attached_at: datetime = Field(alias="attachedAt")
    ephemeral_resources_absent_at: datetime = Field(alias="ephemeralResourcesAbsentAt")

    @field_validator("published_port_count", mode="before")
    @classmethod
    def require_zero_ports(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("Network fixture topology published-port count must be zero")
        return value

    @field_validator("attached_at", "ephemeral_resources_absent_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Network fixture topology timestamp requires a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_topology(self) -> Self:
        if (
            self.ephemeral_resources_absent_at < self.attached_at
            or self.worker_network_ids != (self.internal_network_id,)
            or self.proxy_network_ids
            != tuple(sorted((self.internal_network_id, self.target_network_id)))
            or self.target_network_ids != (self.target_network_id,)
        ):
            raise ValueError("Network fixture proxy-only topology differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"observation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-fixture-proxy-topology/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("Network fixture topology Digest differs")
        object.__setattr__(self, "observation_digest", digest)
        return self


class NetworkFixtureTargetRecoveryReceipt(_FrozenStrictModel):
    """Non-measurement receipt for cleanup of one abandoned fenced attempt."""

    api_version: Literal["pajin.dev/network-fixture-target-recovery/v1alpha1"] = Field(
        default=NETWORK_FIXTURE_TARGET_RECOVERY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["NetworkFixtureTargetRecoveryReceipt"] = "NetworkFixtureTargetRecoveryReceipt"
    recovery_digest: str = Field(default="", alias="recoveryDigest", max_length=64)
    attempt_id: _Identifier = Field(alias="attemptId")
    attempt_digest: _Sha256 = Field(alias="attemptDigest")
    abandoned_fence: int = Field(alias="abandonedFence", strict=True, ge=1, le=2**63 - 1)
    recovery_fence: int = Field(alias="recoveryFence", strict=True, ge=2, le=2**63 - 1)
    cleanup: NetworkFixtureTargetStageReceipt
    measurement_eligible: Literal[False] = Field(default=False, alias="measurementEligible")

    @field_validator("measurement_eligible", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Network fixture recovery cannot be measurement eligible")
        return value

    @model_validator(mode="after")
    def bind_recovery(self) -> Self:
        if (
            self.recovery_fence <= self.abandoned_fence
            or self.cleanup.stage != "cleanup"
            or self.cleanup.attempt_id != self.attempt_id
            or self.cleanup.attempt_digest != self.attempt_digest
            or self.cleanup.fence != self.recovery_fence
            or self.cleanup.resources_absent is not True
        ):
            raise ValueError("Network fixture recovery receipt differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"recovery_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-fixture-target-recovery/v1",
            material,
            max_bytes=1024 * 1024,
        )
        if self.recovery_digest and self.recovery_digest != digest:
            raise ValueError("Network fixture recovery Digest differs")
        object.__setattr__(self, "recovery_digest", digest)
        return self


class NetworkFixtureOperationRecord(_FrozenStrictModel):
    """Hash-chained durable intent, receipt, or provider-error record."""

    sequence: int = Field(strict=True, ge=1, le=10_000)
    record_type: Literal["intent", "receipt", "provider-error"] = Field(alias="recordType")
    operation: NetworkFixtureTargetOperation
    receipt: NetworkFixtureTargetStageReceipt | None = None
    error_code: Literal["provider-exception"] | None = Field(default=None, alias="errorCode")
    occurred_at: datetime = Field(alias="occurredAt")
    previous_record_digest: _Sha256 | None = Field(
        default=None,
        alias="previousRecordDigest",
    )
    record_digest: str = Field(default="", alias="recordDigest", max_length=64)

    @field_validator("occurred_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Network fixture journal timestamp requires a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_record(self) -> Self:
        if self.record_type == "receipt":
            if (
                self.receipt is None
                or self.error_code is not None
                or self.receipt.operation_id != self.operation.operation_id
                or self.receipt.operation_digest != self.operation.operation_digest
                or self.receipt.attempt_id != self.operation.attempt_id
                or self.receipt.attempt_digest != self.operation.attempt_digest
                or self.receipt.fence != self.operation.fence
                or self.receipt.stage != self.operation.stage
            ):
                raise ValueError("Network fixture journal receipt differs from its intent")
        elif self.record_type == "provider-error":
            if self.receipt is not None or self.error_code != "provider-exception":
                raise ValueError("Network fixture provider-error record differs")
        elif self.receipt is not None or self.error_code is not None:
            raise ValueError("Network fixture intent record cannot contain a result")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"record_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-fixture-operation-record/v1",
            material,
            max_bytes=2 * 1024 * 1024,
        )
        if self.record_digest and self.record_digest != digest:
            raise ValueError("Network fixture journal record Digest differs")
        object.__setattr__(self, "record_digest", digest)
        return self


class NetworkFixtureTargetLifecycleEvidence(_FrozenStrictModel):
    """Private exact Target, topology, journal, and cleanup evidence for one case."""

    attempt: NetworkFixtureTargetAttempt
    coordinate: NetworkFixtureTargetCoordinate
    reset: NetworkFixtureTargetStageReceipt
    isolation: NetworkFixtureTargetStageReceipt
    topology: NetworkFixtureProxyTopologyObservation
    target_banner_emission_count: Literal[1] = Field(
        default=1,
        alias="targetBannerEmissionCount",
    )
    target_application_read_bytes: Literal[0] = Field(
        default=0,
        alias="targetApplicationReadBytes",
    )
    cleanup: NetworkFixtureTargetStageReceipt
    journal_records: tuple[NetworkFixtureOperationRecord, ...] = Field(
        alias="journalRecords",
        min_length=6,
        max_length=6,
    )
    evidence_digest: str = Field(default="", alias="evidenceDigest", max_length=64)

    @model_validator(mode="after")
    def bind_lifecycle(self) -> Self:
        receipts = (self.reset, self.isolation, self.cleanup)
        if (
            tuple(item.stage for item in receipts) != ("reset", "isolation", "cleanup")
            or any(item.attempt_id != self.attempt.attempt_id for item in receipts)
            or any(item.attempt_digest != self.attempt.attempt_digest for item in receipts)
            or any(item.fence != self.attempt.fence for item in receipts)
            or self.coordinate.case != self.attempt.case
            or self.coordinate.attempt_id != self.attempt.attempt_id
            or self.coordinate.attempt_digest != self.attempt.attempt_digest
            or self.isolation.coordinate_digest != self.coordinate.coordinate_digest
            or self.cleanup.coordinate_digest != self.coordinate.coordinate_digest
            or self.cleanup.completed_at < self.topology.ephemeral_resources_absent_at
            or self.topology.target_container_id != self.coordinate.target_container_id
            or self.topology.target_image_id != self.coordinate.target_image_id
            or self.topology.target_network_name != self.coordinate.target_network_name
            or self.topology.target_network_id != self.coordinate.target_network_id
        ):
            raise ValueError("Network fixture Target lifecycle evidence differs")
        previous: str | None = None
        expected_record_types = (
            "intent",
            "receipt",
            "intent",
            "receipt",
            "intent",
            "receipt",
        )
        expected_operations = (
            self.reset.operation_id,
            self.reset.operation_id,
            self.isolation.operation_id,
            self.isolation.operation_id,
            self.cleanup.operation_id,
            self.cleanup.operation_id,
        )
        for sequence, record in enumerate(self.journal_records, start=1):
            if (
                record.sequence != sequence
                or record.previous_record_digest != previous
                or record.record_type != expected_record_types[sequence - 1]
                or record.operation.operation_id != expected_operations[sequence - 1]
            ):
                raise ValueError("Network fixture Target journal chain differs")
            previous = record.record_digest
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evidence_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.network-fixture-target-lifecycle-evidence/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.evidence_digest and self.evidence_digest != digest:
            raise ValueError("Network fixture lifecycle Evidence Digest differs")
        object.__setattr__(self, "evidence_digest", digest)
        return self


@dataclass(frozen=True, slots=True)
class NetworkDockerCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


class NetworkDockerCommandRunner(Protocol):
    """Shell-free bounded Docker CLI boundary used by NET-002B."""

    def run(self, arguments: Sequence[str]) -> NetworkDockerCommandResult: ...


class SubprocessNetworkDockerCommandRunner:
    """Run one bounded Docker command without a shell."""

    def __init__(self, *, executable: str = "docker", timeout_seconds: int = 30) -> None:
        if (
            not isinstance(executable, str)
            or not executable
            or executable.strip() != executable
            or "\x00" in executable
        ):
            raise ValueError("Network Docker executable is unsafe")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("Network Docker timeout is invalid")
        self._executable = executable
        self._timeout_seconds = timeout_seconds

    def run(self, arguments: Sequence[str]) -> NetworkDockerCommandResult:
        if not arguments or any(
            not isinstance(argument, str) or "\x00" in argument for argument in arguments
        ):
            raise ValueError("Network Docker arguments are unsafe")
        try:
            completed = subprocess.run(
                [self._executable, *arguments],
                capture_output=True,
                check=False,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise NetworkFixtureRuntimeError("Network Docker command failed") from exc
        if (
            len(completed.stdout) > _MAX_DOCKER_OUTPUT_BYTES
            or len(completed.stderr) > _MAX_DOCKER_OUTPUT_BYTES
        ):
            raise NetworkFixtureRuntimeError("Network Docker command output exceeded its bound")
        return NetworkDockerCommandResult(
            returncode=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )


class NetworkDockerImageInspector(Protocol):
    def image_id(self, reference: str) -> str: ...


def registered_network_source_image_binding(
    inspector: NetworkDockerImageInspector,
) -> NetworkSourceImageBinding:
    """Inspect the three fixed references and bind only their immutable OCI IDs."""

    if not callable(getattr(inspector, "image_id", None)):
        raise TypeError("Network source image binding requires a Docker image inspector")
    roles = tuple(
        NetworkSourceImageRoleBinding(
            role=role,
            contract=_registered_image_contract(role),
            imageReference=_expected_image_reference(role),
            observedImageId=inspector.image_id(_expected_image_reference(role)),
        )
        for role in NetworkMeasurementImageRole
    )
    return NetworkSourceImageBinding(
        imageProfile=registered_network_image_identity_profile().reference(),
        emitterProfile=registered_network_tcp_banner_emitter_profile().reference(),
        roles=roles,
    )


def load_network_source_image_binding(
    binding: NetworkSourceImageBinding,
    *,
    inspector: NetworkDockerImageInspector,
) -> NetworkSourceImageBinding:
    """Reparse and independently re-inspect every immutable image identity."""

    try:
        canonical = NetworkSourceImageBinding.model_validate_json(
            binding.model_dump_json(by_alias=True)
        )
        rebuilt = registered_network_source_image_binding(inspector)
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise NetworkFixtureRuntimeError("Network source image binding is invalid") from exc
    if canonical != binding or canonical != rebuilt:
        raise NetworkFixtureRuntimeError(
            "Network source image reference or observed OCI identity differs"
        )
    return canonical.model_copy(deep=True)


@dataclass(frozen=True, slots=True)
class _AttachedNetworkTopology:
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


class NetworkDockerBoundaryInspector(
    DockerEgressLifecycleObserver,
    NetworkDockerImageInspector,
    Protocol,
):
    """Host-owned Network fixture and Worker/proxy topology observations."""

    def topology_observation(
        self,
        execution_id: str,
    ) -> NetworkFixtureProxyTopologyObservation: ...

    def target_resources_absent(self) -> bool: ...


class SubprocessNetworkDockerBoundaryInspector:
    """Bounded Docker inspection for one exact NET-002B Target attempt."""

    def __init__(
        self,
        *,
        coordinate: NetworkFixtureTargetCoordinate,
        images: NetworkSourceImageBinding,
        command_runner: NetworkDockerCommandRunner | None = None,
        timeout_seconds: int = 20,
    ) -> None:
        try:
            self._coordinate = NetworkFixtureTargetCoordinate.model_validate_json(
                coordinate.model_dump_json(by_alias=True)
            )
            self._images = NetworkSourceImageBinding.model_validate_json(
                images.model_dump_json(by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise NetworkFixtureRuntimeError("Network Docker inspector context is invalid") from exc
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 120:
            raise ValueError("Network Docker observation timeout is invalid")
        self._docker = command_runner or SubprocessNetworkDockerCommandRunner()
        self._timeout_seconds = timeout_seconds
        self._topology_lock = Lock()
        self._attached: dict[str, _AttachedNetworkTopology] = {}
        self._completed: dict[str, NetworkFixtureProxyTopologyObservation] = {}

    def stable_observer_context(self) -> Mapping[str, object]:
        return {
            "observerId": "pajin.network-fixture-docker-boundary",
            "observerVersion": "1.0.0",
            "coordinateDigest": self._coordinate.coordinate_digest,
            "imageBindingDigest": self._images.binding_digest,
            "timeoutSeconds": self._timeout_seconds,
        }

    def image_id(self, reference: str) -> str:
        if (
            not isinstance(reference, str)
            or not reference
            or reference.strip() != reference
            or "\x00" in reference
        ):
            raise ValueError("Network Docker image reference is unsafe")
        output = self._require_success(("image", "inspect", reference, "--format", "{{.Id}}"))
        return self._docker_image_id(self._decode(output), label="image")

    async def attached(self, observation: DockerEgressLifecycleObservation) -> None:
        attached = await asyncio.to_thread(self._observe_attached, observation)
        with self._topology_lock:
            if (
                observation.execution_id in self._attached
                or observation.execution_id in self._completed
            ):
                raise NetworkFixtureRuntimeError(
                    "Network Docker topology execution identity was reused"
                )
            self._attached[observation.execution_id] = attached

    async def cleaned(self, observation: DockerEgressLifecycleObservation) -> None:
        with self._topology_lock:
            attached = self._attached.get(observation.execution_id)
        if attached is None or attached.observation != observation:
            raise NetworkFixtureRuntimeError(
                "Network Docker cleanup lacks its attached topology observation"
            )
        completed = await asyncio.to_thread(self._observe_cleaned, attached)
        with self._topology_lock:
            if self._attached.pop(observation.execution_id, None) != attached:
                raise NetworkFixtureRuntimeError("Network Docker topology changed during cleanup")
            self._completed[observation.execution_id] = completed

    def topology_observation(
        self,
        execution_id: str,
    ) -> NetworkFixtureProxyTopologyObservation:
        with self._topology_lock:
            observed = self._completed.get(execution_id)
        if observed is None:
            raise NetworkFixtureRuntimeError("Network Docker topology observation is incomplete")
        return observed.model_copy(deep=True)

    def target_resources_absent(self) -> bool:
        names = NetworkFixtureResourceNames(
            target_container_name=self._coordinate.target_container_name,
            target_network_name=self._coordinate.target_network_name,
        )
        return not self._resource_ids(
            "container",
            names.target_container_name,
        ) and not self._resource_ids(
            "network",
            names.target_network_name,
        )

    def _observe_attached(
        self,
        observation: DockerEgressLifecycleObservation,
    ) -> _AttachedNetworkTopology:
        deadline = time.monotonic() + self._timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                return self._observe_attached_once(observation)
            except NetworkFixtureRuntimeError as exc:
                last_error = exc
                time.sleep(0.05)
        raise NetworkFixtureRuntimeError(
            "Network Docker topology did not become observable"
        ) from last_error

    def _observe_attached_once(
        self,
        observation: DockerEgressLifecycleObservation,
    ) -> _AttachedNetworkTopology:
        coordinate = self._coordinate
        if observation.external_network_name != coordinate.target_network_name:
            raise NetworkFixtureRuntimeError("Network Docker proxy route differs")
        worker = self._single_inspect(("container", "inspect", observation.worker_container_name))
        proxy = self._single_inspect(("container", "inspect", observation.proxy_container_name))
        target = self._single_inspect(("container", "inspect", coordinate.target_container_name))
        internal = self._single_inspect(("network", "inspect", observation.internal_network_name))
        target_network = self._single_inspect(
            ("network", "inspect", coordinate.target_network_name)
        )
        worker_id = self._docker_sha256(worker.get("Id"), label="Worker container")
        proxy_id = self._docker_sha256(proxy.get("Id"), label="proxy container")
        target_id = self._docker_sha256(target.get("Id"), label="Target container")
        internal_id = self._docker_sha256(internal.get("Id"), label="internal network")
        target_network_id = self._docker_sha256(
            target_network.get("Id"),
            label="Target network",
        )
        internal_members = self._network_member_ids(internal)
        target_members = self._network_member_ids(target_network)
        worker_network_ids = self._container_network_ids(worker)
        proxy_network_ids = self._container_network_ids(proxy)
        target_network_ids = self._container_network_ids(target)
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
            or self._docker_image_id(worker.get("Image"), label="Worker image")
            != self._images.role(NetworkMeasurementImageRole.WORKER).observed_image_id
            or self._docker_image_id(proxy.get("Image"), label="proxy image")
            != self._images.role(NetworkMeasurementImageRole.PROXY).observed_image_id
            or self._docker_image_id(target.get("Image"), label="Target image")
            != coordinate.target_image_id
            or self._execution_label(worker) != observation.execution_id
            or self._execution_label(proxy) != observation.execution_id
            or self._target_label(target, _ATTEMPT_LABEL) != coordinate.attempt_digest
            or sum(self._published_port_count(item) for item in (worker, proxy, target)) != 0
        ):
            raise NetworkFixtureRuntimeError("Network Docker Worker/proxy/Target topology differs")
        return _AttachedNetworkTopology(
            observation=observation,
            worker_container_id=worker_id,
            worker_image_id=self._docker_image_id(worker.get("Image"), label="Worker image"),
            proxy_container_id=proxy_id,
            proxy_image_id=self._docker_image_id(proxy.get("Image"), label="proxy image"),
            internal_network_id=internal_id,
            target_network_id=target_network_id,
            target_container_id=target_id,
            target_image_id=self._docker_image_id(target.get("Image"), label="Target image"),
            worker_network_ids=worker_network_ids,
            proxy_network_ids=proxy_network_ids,
            target_network_ids=target_network_ids,
            attached_at=datetime.now(UTC),
        )

    def _observe_cleaned(
        self,
        attached: _AttachedNetworkTopology,
    ) -> NetworkFixtureProxyTopologyObservation:
        observation = attached.observation
        if (
            self._resource_ids("container", observation.worker_container_name)
            or self._resource_ids("container", observation.proxy_container_name)
            or self._resource_ids("network", observation.internal_network_name)
            or self._execution_resources(observation.execution_id)
        ):
            raise NetworkFixtureRuntimeError(
                "Network Docker Worker/proxy resources remain after cleanup"
            )
        target = self._single_inspect(
            ("container", "inspect", self._coordinate.target_container_name)
        )
        network = self._single_inspect(("network", "inspect", self._coordinate.target_network_name))
        if (
            self._docker_sha256(target.get("Id"), label="Target container")
            != attached.target_container_id
            or self._docker_image_id(target.get("Image"), label="Target image")
            != attached.target_image_id
            or self._docker_sha256(network.get("Id"), label="Target network")
            != attached.target_network_id
            or self._network_member_ids(network) != {attached.target_container_id}
        ):
            raise NetworkFixtureRuntimeError("Network Docker Target changed before Target cleanup")
        return NetworkFixtureProxyTopologyObservation(
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
            value = json.loads(self._decode(self._require_success(arguments)))
        except json.JSONDecodeError as exc:
            raise NetworkFixtureRuntimeError("Network Docker inspect output is invalid") from exc
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise NetworkFixtureRuntimeError("Network Docker inspect output is ambiguous")
        return value[0]

    def _require_success(self, arguments: Sequence[str]) -> bytes:
        result = self._docker.run(arguments)
        if result.returncode != 0:
            raise NetworkFixtureRuntimeError("Network Docker inspection was rejected")
        return result.stdout

    @staticmethod
    def _decode(value: bytes) -> str:
        try:
            return value.decode("utf-8", errors="strict").strip()
        except UnicodeDecodeError as exc:
            raise NetworkFixtureRuntimeError("Network Docker output is not UTF-8") from exc

    @staticmethod
    def _docker_sha256(value: object, *, label: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
            raise NetworkFixtureRuntimeError(f"Network Docker {label} identity differs")
        return value

    @staticmethod
    def _docker_image_id(value: object, *, label: str) -> str:
        if not isinstance(value, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None:
            raise NetworkFixtureRuntimeError(f"Network Docker {label} identity differs")
        return value

    @classmethod
    def _network_member_ids(cls, network: Mapping[str, object]) -> set[str]:
        containers = network.get("Containers")
        if not isinstance(containers, dict):
            raise NetworkFixtureRuntimeError("Network Docker members are invalid")
        return {cls._docker_sha256(value, label="network member") for value in containers}

    @classmethod
    def _container_network_ids(
        cls,
        container: Mapping[str, object],
    ) -> tuple[str, ...]:
        settings = container.get("NetworkSettings")
        networks = settings.get("Networks") if isinstance(settings, dict) else None
        if not isinstance(networks, dict):
            raise NetworkFixtureRuntimeError("Network Docker container networks are invalid")
        ids: list[str] = []
        for endpoint in networks.values():
            if not isinstance(endpoint, dict):
                raise NetworkFixtureRuntimeError("Network Docker endpoint is invalid")
            ids.append(cls._docker_sha256(endpoint.get("NetworkID"), label="container network"))
        return tuple(sorted(ids))

    @staticmethod
    def _execution_label(container: Mapping[str, object]) -> object:
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        return labels.get("pajin.execution-id") if isinstance(labels, dict) else None

    @staticmethod
    def _target_label(container: Mapping[str, object], label: str) -> object:
        config = container.get("Config")
        labels = config.get("Labels") if isinstance(config, dict) else None
        return labels.get(label) if isinstance(labels, dict) else None

    @staticmethod
    def _published_port_count(container: Mapping[str, object]) -> int:
        host = container.get("HostConfig")
        settings = container.get("NetworkSettings")
        bindings = host.get("PortBindings") if isinstance(host, dict) else None
        ports = settings.get("Ports") if isinstance(settings, dict) else None
        if bindings not in (None, {}) or not isinstance(ports, dict):
            raise NetworkFixtureRuntimeError("Network Docker port state differs")
        if any(value not in (None, []) for value in ports.values()):
            raise NetworkFixtureRuntimeError("Network Docker published ports are not zero")
        return 0

    def _resource_ids(self, resource: str, name: str) -> tuple[str, ...]:
        command = (
            ("container", "ls", "--all", "--quiet", "--filter", f"name=^/{name}$")
            if resource == "container"
            else ("network", "ls", "--quiet", "--filter", f"name=^{name}$")
        )
        output = self._decode(self._require_success(command))
        return tuple(line for line in output.splitlines() if line)

    def _execution_resources(self, execution_id: str) -> tuple[str, ...]:
        label = f"label=pajin.execution-id={execution_id}"
        containers = self._decode(
            self._require_success(("container", "ls", "--all", "--quiet", "--filter", label))
        )
        networks = self._decode(
            self._require_success(("network", "ls", "--quiet", "--filter", label))
        )
        return tuple(line for line in (*containers.splitlines(), *networks.splitlines()) if line)


class NetworkFixtureOperationJournal:
    """SQLite intent-before-call journal with monotonic per-case fences."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        _require_safe_journal_path(self.path)
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _initialize_journal(self.path)

    @classmethod
    def open_existing(cls, path: Path) -> NetworkFixtureOperationJournal:
        resolved = Path(os.path.abspath(path))
        if not resolved.exists():
            raise NetworkFixtureRuntimeError("Network fixture operation journal is absent")
        _require_safe_journal_path(resolved)
        with _journal_read_transaction(resolved) as connection:
            _require_journal_schema(connection)
        journal = object.__new__(cls)
        journal.path = resolved
        return journal

    def begin_attempt(
        self,
        *,
        case: NetworkMeasuredCaseRef,
        images: NetworkSourceImageBindingRef,
        started_at: datetime | None = None,
    ) -> NetworkFixtureTargetAttempt:
        canonical_case = NetworkMeasuredCaseRef.model_validate_json(
            case.model_dump_json(by_alias=True)
        )
        canonical_images = NetworkSourceImageBindingRef.model_validate_json(
            images.model_dump_json(by_alias=True)
        )
        scope_digest = benchmark_digest(
            "pajin.workflow.network-fixture-target-scope/v1",
            {
                "case": canonical_case.model_dump(mode="json", by_alias=True),
                "images": canonical_images.model_dump(mode="json", by_alias=True),
            },
            max_bytes=512 * 1024,
        )
        with _journal_write_transaction(self.path) as connection:
            pending = connection.execute(
                """
                SELECT attempt_id FROM attempts
                WHERE scope_digest = ? AND state IN ('open', 'recovering')
                """,
                (scope_digest,),
            ).fetchone()
            if pending is not None:
                raise NetworkFixtureRuntimeError(
                    "Network fixture abandoned attempt must be reconciled first"
                )
            fence = _next_fence(connection, scope_digest)
            attempt = NetworkFixtureTargetAttempt(
                scopeDigest=scope_digest,
                case=canonical_case,
                images=canonical_images,
                fence=fence,
                startedAt=started_at or datetime.now(UTC),
            )
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id, scope_digest, fence, attempt_json, coordinate_json, state
                ) VALUES (?, ?, ?, ?, NULL, 'open')
                """,
                (
                    attempt.attempt_id,
                    scope_digest,
                    fence,
                    attempt.model_dump_json(by_alias=True),
                ),
            )
        return attempt

    def operation(
        self,
        attempt: NetworkFixtureTargetAttempt,
        stage: Literal["reset", "isolation", "cleanup"],
        *,
        fence: int | None = None,
    ) -> NetworkFixtureTargetOperation:
        canonical = self._require_attempt(attempt)
        operation_fence = canonical.fence if fence is None else fence
        if stage != "cleanup" and operation_fence != canonical.fence:
            raise NetworkFixtureRuntimeError(
                "Network fixture non-cleanup operation must use the attempt fence"
            )
        if stage == "cleanup" and operation_fence < canonical.fence:
            raise NetworkFixtureRuntimeError("Network fixture cleanup fence cannot move backward")
        return NetworkFixtureTargetOperation(
            attemptId=canonical.attempt_id,
            attemptDigest=canonical.attempt_digest,
            scopeDigest=canonical.scope_digest,
            fence=operation_fence,
            stage=stage,
            ordinal={"reset": 1, "isolation": 2, "cleanup": 3}[stage],
        )

    def append_intent(self, operation: NetworkFixtureTargetOperation) -> None:
        with _journal_write_transaction(self.path) as connection:
            _append_journal_record(
                connection,
                operation,
                record_type="intent",
            )

    def append_receipt(
        self,
        operation: NetworkFixtureTargetOperation,
        receipt: NetworkFixtureTargetStageReceipt,
    ) -> None:
        with _journal_write_transaction(self.path) as connection:
            _append_journal_record(
                connection,
                operation,
                record_type="receipt",
                receipt=receipt,
            )

    def append_provider_error(self, operation: NetworkFixtureTargetOperation) -> None:
        with _journal_write_transaction(self.path) as connection:
            _append_journal_record(
                connection,
                operation,
                record_type="provider-error",
                error_code="provider-exception",
            )

    def store_coordinate(
        self,
        attempt: NetworkFixtureTargetAttempt,
        coordinate: NetworkFixtureTargetCoordinate,
    ) -> None:
        if (
            coordinate.attempt_id != attempt.attempt_id
            or coordinate.attempt_digest != attempt.attempt_digest
            or coordinate.case != attempt.case
        ):
            raise NetworkFixtureRuntimeError(
                "Network fixture coordinate differs from its journal attempt"
            )
        with _journal_write_transaction(self.path) as connection:
            row = _required_attempt_row(connection, attempt.attempt_id)
            if row["state"] != "open" or row["coordinate_json"] is not None:
                raise NetworkFixtureRuntimeError(
                    "Network fixture coordinate cannot replace journal state"
                )
            connection.execute(
                "UPDATE attempts SET coordinate_json = ? WHERE attempt_id = ?",
                (
                    coordinate.model_dump_json(by_alias=True),
                    attempt.attempt_id,
                ),
            )

    def complete(self, attempt: NetworkFixtureTargetAttempt) -> None:
        records = self.records(attempt.attempt_id)
        if (
            len(records) != 6
            or tuple(item.record_type for item in records)
            != ("intent", "receipt", "intent", "receipt", "intent", "receipt")
            or tuple(item.operation.stage for item in records if item.record_type == "receipt")
            != ("reset", "isolation", "cleanup")
        ):
            raise NetworkFixtureRuntimeError(
                "Network fixture attempt lacks one exact completed lifecycle"
            )
        with _journal_write_transaction(self.path) as connection:
            row = _required_attempt_row(connection, attempt.attempt_id)
            if row["state"] != "open" or row["coordinate_json"] is None:
                raise NetworkFixtureRuntimeError("Network fixture attempt cannot be completed")
            connection.execute(
                "UPDATE attempts SET state = 'complete' WHERE attempt_id = ?",
                (attempt.attempt_id,),
            )

    def open_attempts(
        self,
    ) -> tuple[
        tuple[NetworkFixtureTargetAttempt, NetworkFixtureTargetCoordinate | None],
        ...,
    ]:
        with _journal_read_transaction(self.path) as connection:
            rows = connection.execute(
                """
                SELECT attempt_json, coordinate_json
                FROM attempts
                WHERE state IN ('open', 'recovering')
                ORDER BY rowid
                """
            ).fetchall()
        result: list[tuple[NetworkFixtureTargetAttempt, NetworkFixtureTargetCoordinate | None]] = []
        for row in rows:
            try:
                attempt = NetworkFixtureTargetAttempt.model_validate_json(str(row["attempt_json"]))
                coordinate = (
                    NetworkFixtureTargetCoordinate.model_validate_json(str(row["coordinate_json"]))
                    if row["coordinate_json"] is not None
                    else None
                )
            except (ValidationError, ValueError) as exc:
                raise NetworkFixtureRuntimeError(
                    "Network fixture open journal state is invalid"
                ) from exc
            result.append((attempt, coordinate))
        return tuple(result)

    def begin_recovery(
        self,
        attempt: NetworkFixtureTargetAttempt,
    ) -> NetworkFixtureTargetOperation:
        canonical = self._require_attempt(attempt)
        with _journal_write_transaction(self.path) as connection:
            row = _required_attempt_row(connection, canonical.attempt_id)
            if row["state"] not in {"open", "recovering"}:
                raise NetworkFixtureRuntimeError(
                    "Network fixture recovery requires an abandoned attempt"
                )
            recovery_fence = _next_fence(connection, canonical.scope_digest)
            operation = NetworkFixtureTargetOperation(
                attemptId=canonical.attempt_id,
                attemptDigest=canonical.attempt_digest,
                scopeDigest=canonical.scope_digest,
                fence=recovery_fence,
                stage="cleanup",
                ordinal=3,
            )
            connection.execute(
                "UPDATE attempts SET state = 'recovering' WHERE attempt_id = ?",
                (canonical.attempt_id,),
            )
            _append_journal_record(
                connection,
                operation,
                record_type="intent",
            )
        return operation

    def mark_recovered(
        self,
        attempt: NetworkFixtureTargetAttempt,
        operation: NetworkFixtureTargetOperation,
        receipt: NetworkFixtureTargetStageReceipt,
    ) -> NetworkFixtureTargetRecoveryReceipt:
        self.append_receipt(operation, receipt)
        recovery = NetworkFixtureTargetRecoveryReceipt(
            attemptId=attempt.attempt_id,
            attemptDigest=attempt.attempt_digest,
            abandonedFence=attempt.fence,
            recoveryFence=operation.fence,
            cleanup=receipt,
        )
        with _journal_write_transaction(self.path) as connection:
            row = _required_attempt_row(connection, attempt.attempt_id)
            if row["state"] != "recovering":
                raise NetworkFixtureRuntimeError("Network fixture recovered state differs")
            connection.execute(
                "UPDATE attempts SET state = 'recovered' WHERE attempt_id = ?",
                (attempt.attempt_id,),
            )
        return recovery

    def records(self, attempt_id: str) -> tuple[NetworkFixtureOperationRecord, ...]:
        with _journal_read_transaction(self.path) as connection:
            rows = connection.execute(
                """
                SELECT record_json FROM records
                WHERE attempt_id = ?
                ORDER BY sequence
                """,
                (attempt_id,),
            ).fetchall()
        try:
            records = tuple(
                NetworkFixtureOperationRecord.model_validate_json(str(row["record_json"]))
                for row in rows
            )
        except (ValidationError, ValueError) as exc:
            raise NetworkFixtureRuntimeError("Network fixture journal record is invalid") from exc
        previous: str | None = None
        intents: dict[str, NetworkFixtureTargetOperation] = {}
        completed: set[str] = set()
        for sequence, record in enumerate(records, start=1):
            if record.sequence != sequence or record.previous_record_digest != previous:
                raise NetworkFixtureRuntimeError("Network fixture journal hash chain differs")
            if record.record_type == "intent":
                if record.operation.operation_id in intents:
                    raise NetworkFixtureRuntimeError(
                        "Network fixture journal repeats an operation intent"
                    )
                intents[record.operation.operation_id] = record.operation
            elif (
                intents.get(record.operation.operation_id) != record.operation
                or record.operation.operation_id in completed
            ):
                raise NetworkFixtureRuntimeError(
                    "Network fixture result lacks one exact prior intent"
                )
            else:
                completed.add(record.operation.operation_id)
            previous = record.record_digest
        return records

    def coordinate(
        self,
        attempt_id: str,
    ) -> NetworkFixtureTargetCoordinate | None:
        with _journal_read_transaction(self.path) as connection:
            row = _required_attempt_row(connection, attempt_id)
        if row["coordinate_json"] is None:
            return None
        try:
            return NetworkFixtureTargetCoordinate.model_validate_json(str(row["coordinate_json"]))
        except (ValidationError, ValueError) as exc:
            raise NetworkFixtureRuntimeError(
                "Network fixture journal coordinate is invalid"
            ) from exc

    def _require_attempt(
        self,
        attempt: NetworkFixtureTargetAttempt,
    ) -> NetworkFixtureTargetAttempt:
        try:
            canonical = NetworkFixtureTargetAttempt.model_validate_json(
                attempt.model_dump_json(by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise NetworkFixtureRuntimeError("Network fixture attempt is invalid") from exc
        with _journal_read_transaction(self.path) as connection:
            row = _required_attempt_row(connection, canonical.attempt_id)
        if str(row["attempt_json"]) != canonical.model_dump_json(by_alias=True):
            raise NetworkFixtureRuntimeError(
                "Network fixture attempt differs from durable journal state"
            )
        return canonical


def _initialize_journal(path: Path) -> None:
    with _journal_write_transaction(path, require_schema=False) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS fences (
                scope_digest TEXT PRIMARY KEY NOT NULL,
                fence INTEGER NOT NULL CHECK(fence >= 1)
            );
            CREATE TABLE IF NOT EXISTS attempts (
                attempt_id TEXT PRIMARY KEY NOT NULL,
                scope_digest TEXT NOT NULL,
                fence INTEGER NOT NULL CHECK(fence >= 1),
                attempt_json TEXT NOT NULL,
                coordinate_json TEXT,
                state TEXT NOT NULL CHECK(state IN ('open', 'recovering', 'complete', 'recovered'))
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_open_network_fixture_scope
                ON attempts(scope_digest)
                WHERE state IN ('open', 'recovering');
            CREATE TABLE IF NOT EXISTS records (
                attempt_id TEXT NOT NULL,
                sequence INTEGER NOT NULL CHECK(sequence >= 1),
                record_json TEXT NOT NULL,
                PRIMARY KEY(attempt_id, sequence),
                FOREIGN KEY(attempt_id) REFERENCES attempts(attempt_id)
            );
            PRAGMA user_version = 1;
            """
        )
        _require_journal_schema(connection)


def _require_journal_schema(connection: sqlite3.Connection) -> None:
    tables = {
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
        ).fetchall()
    }
    version = int(connection.execute("PRAGMA user_version").fetchone()[0])
    if version != 1 or not {"fences", "attempts", "records"}.issubset(tables):
        raise NetworkFixtureRuntimeError("Network fixture operation journal schema is invalid")


def _require_safe_journal_path(path: Path) -> None:
    if path.exists() and (path.is_symlink() or not path.is_file()):
        raise NetworkFixtureRuntimeError("Network fixture journal path is not a regular file")
    parent = path.parent
    if parent.exists() and (parent.is_symlink() or not parent.is_dir()):
        raise NetworkFixtureRuntimeError("Network fixture journal parent is unsafe")


@contextmanager
def _journal_write_transaction(
    path: Path,
    *,
    require_schema: bool = True,
) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(path, timeout=_BUSY_TIMEOUT_MS / 1000)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        connection.execute("BEGIN IMMEDIATE")
        if require_schema:
            _require_journal_schema(connection)
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


@contextmanager
def _journal_read_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro",
        uri=True,
        timeout=_BUSY_TIMEOUT_MS / 1000,
    )
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN")
        _require_journal_schema(connection)
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()


def _next_fence(connection: sqlite3.Connection, scope_digest: str) -> int:
    row = connection.execute(
        "SELECT fence FROM fences WHERE scope_digest = ?",
        (scope_digest,),
    ).fetchone()
    fence = 1 if row is None else int(row["fence"]) + 1
    connection.execute(
        """
        INSERT INTO fences(scope_digest, fence) VALUES (?, ?)
        ON CONFLICT(scope_digest) DO UPDATE SET fence = excluded.fence
        """,
        (scope_digest, fence),
    )
    return fence


def _required_attempt_row(
    connection: sqlite3.Connection,
    attempt_id: str,
) -> sqlite3.Row:
    row = connection.execute(
        """
        SELECT attempt_id, scope_digest, fence, attempt_json, coordinate_json, state
        FROM attempts WHERE attempt_id = ?
        """,
        (attempt_id,),
    ).fetchone()
    if row is None:
        raise NetworkFixtureRuntimeError("Network fixture attempt is absent from the journal")
    return cast(sqlite3.Row, row)


def _append_journal_record(
    connection: sqlite3.Connection,
    operation: NetworkFixtureTargetOperation,
    *,
    record_type: Literal["intent", "receipt", "provider-error"],
    receipt: NetworkFixtureTargetStageReceipt | None = None,
    error_code: Literal["provider-exception"] | None = None,
) -> None:
    row = _required_attempt_row(connection, operation.attempt_id)
    if row["state"] not in {"open", "recovering"}:
        raise NetworkFixtureRuntimeError("Network fixture journal attempt is not mutable")
    attempt = NetworkFixtureTargetAttempt.model_validate_json(str(row["attempt_json"]))
    if (
        operation.attempt_digest != attempt.attempt_digest
        or operation.scope_digest != attempt.scope_digest
        or operation.fence < attempt.fence
        or (operation.fence > attempt.fence and operation.stage != "cleanup")
    ):
        raise NetworkFixtureRuntimeError("Network fixture operation differs from journal fencing")
    prior_rows = connection.execute(
        """
        SELECT record_json FROM records
        WHERE attempt_id = ?
        ORDER BY sequence
        """,
        (operation.attempt_id,),
    ).fetchall()
    prior = tuple(
        NetworkFixtureOperationRecord.model_validate_json(str(item["record_json"]))
        for item in prior_rows
    )
    intents = {
        item.operation.operation_id: item.operation
        for item in prior
        if item.record_type == "intent"
    }
    completed = {item.operation.operation_id for item in prior if item.record_type != "intent"}
    if record_type == "intent":
        if operation.operation_id in intents:
            raise NetworkFixtureRuntimeError("Network fixture operation intent already exists")
    elif intents.get(operation.operation_id) != operation or operation.operation_id in completed:
        raise NetworkFixtureRuntimeError("Network fixture operation result lacks one prior intent")
    record = NetworkFixtureOperationRecord(
        sequence=len(prior) + 1,
        recordType=record_type,
        operation=operation,
        receipt=receipt,
        errorCode=error_code,
        occurredAt=datetime.now(UTC),
        previousRecordDigest=(prior[-1].record_digest if prior else None),
    )
    connection.execute(
        "INSERT INTO records(attempt_id, sequence, record_json) VALUES (?, ?, ?)",
        (
            operation.attempt_id,
            record.sequence,
            record.model_dump_json(by_alias=True),
        ),
    )


class NetworkFixtureDockerProvider:
    """Exact Docker provider for the one code-owned passive banner Target."""

    def __init__(
        self,
        *,
        command_runner: NetworkDockerCommandRunner | None = None,
        ready_timeout_seconds: int = 20,
    ) -> None:
        if type(ready_timeout_seconds) is not int or not 1 <= ready_timeout_seconds <= 120:
            raise ValueError("Network fixture ready timeout is invalid")
        self._docker = command_runner or SubprocessNetworkDockerCommandRunner()
        self._ready_timeout_seconds = ready_timeout_seconds

    def image_id(self, reference: str) -> str:
        if (
            not isinstance(reference, str)
            or not reference
            or reference.strip() != reference
            or "\x00" in reference
        ):
            raise ValueError("Network fixture image reference is unsafe")
        output = self._require_success(("image", "inspect", reference, "--format", "{{.Id}}"))
        return _require_image_id(_decode_utf8(output), label="image")

    def boundary_inspector(
        self,
        *,
        coordinate: NetworkFixtureTargetCoordinate,
        images: NetworkSourceImageBinding,
    ) -> SubprocessNetworkDockerBoundaryInspector:
        return SubprocessNetworkDockerBoundaryInspector(
            coordinate=coordinate,
            images=images,
            command_runner=self._docker,
        )

    def reset(
        self,
        attempt: NetworkFixtureTargetAttempt,
        operation: NetworkFixtureTargetOperation,
        images: NetworkSourceImageBinding,
    ) -> NetworkFixtureTargetStageReceipt:
        self._require_operation(attempt, operation, stage="reset")
        if images.reference() != attempt.images:
            raise NetworkFixtureRuntimeError("Network fixture reset image binding differs")
        for role in NetworkMeasurementImageRole:
            binding = images.role(role)
            if self.image_id(binding.image_reference) != binding.observed_image_id:
                raise NetworkFixtureRuntimeError(
                    "Network fixture reset observed image identity differs"
                )
        names = network_fixture_resource_names(attempt)
        if self._resource_ids("container", names.target_container_name) or self._resource_ids(
            "network", names.target_network_name
        ):
            raise NetworkFixtureRuntimeError("Network fixture reset found colliding resources")
        return NetworkFixtureTargetStageReceipt(
            operationId=operation.operation_id,
            operationDigest=operation.operation_digest,
            attemptId=attempt.attempt_id,
            attemptDigest=attempt.attempt_digest,
            fence=operation.fence,
            stage="reset",
            coordinateDigest=None,
            resourcesAbsent=True,
            completedAt=datetime.now(UTC),
        )

    def establish_isolation(
        self,
        attempt: NetworkFixtureTargetAttempt,
        reset: NetworkFixtureTargetStageReceipt,
        operation: NetworkFixtureTargetOperation,
        images: NetworkSourceImageBinding,
    ) -> tuple[NetworkFixtureTargetStageReceipt, NetworkFixtureTargetCoordinate]:
        self._require_operation(attempt, operation, stage="isolation")
        if (
            reset.stage != "reset"
            or reset.attempt_id != attempt.attempt_id
            or reset.attempt_digest != attempt.attempt_digest
            or reset.fence != attempt.fence
            or reset.resources_absent is not True
            or images.reference() != attempt.images
        ):
            raise NetworkFixtureRuntimeError("Network fixture isolation input differs")
        names = network_fixture_resource_names(attempt)
        labels = (
            "--label",
            f"{_MANAGED_LABEL}=true",
            "--label",
            f"{_ATTEMPT_LABEL}={attempt.attempt_digest}",
            "--label",
            f"{_CASE_LABEL}={attempt.case.case_digest}",
        )
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
        target_image = images.role(NetworkMeasurementImageRole.TARGET)
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
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--pids-limit",
                "16",
                "--memory",
                "32m",
                "--cpus",
                "0.25",
                "--user",
                "65532:65532",
                "--stop-timeout",
                "1",
                target_image.observed_image_id,
                attempt.case.case_id,
            )
        )
        self._wait_ready(names.target_container_name, attempt.case.case_id)
        coordinate = self._observe_target(
            attempt=attempt,
            names=names,
            target_image_id=target_image.observed_image_id,
        )
        receipt = NetworkFixtureTargetStageReceipt(
            operationId=operation.operation_id,
            operationDigest=operation.operation_digest,
            attemptId=attempt.attempt_id,
            attemptDigest=attempt.attempt_digest,
            fence=operation.fence,
            stage="isolation",
            coordinateDigest=coordinate.coordinate_digest,
            resourcesAbsent=False,
            completedAt=datetime.now(UTC),
        )
        return receipt, coordinate

    def cleanup(
        self,
        attempt: NetworkFixtureTargetAttempt,
        operation: NetworkFixtureTargetOperation,
        *,
        coordinate: NetworkFixtureTargetCoordinate | None,
    ) -> NetworkFixtureTargetStageReceipt:
        self._require_operation(attempt, operation, stage="cleanup")
        if coordinate is not None and (
            coordinate.attempt_id != attempt.attempt_id
            or coordinate.attempt_digest != attempt.attempt_digest
            or coordinate.case != attempt.case
        ):
            raise NetworkFixtureRuntimeError("Network fixture cleanup coordinate differs")
        names = network_fixture_resource_names(attempt)
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
            raise NetworkFixtureRuntimeError("Network fixture resources remain after cleanup")
        return NetworkFixtureTargetStageReceipt(
            operationId=operation.operation_id,
            operationDigest=operation.operation_digest,
            attemptId=attempt.attempt_id,
            attemptDigest=attempt.attempt_digest,
            fence=operation.fence,
            stage="cleanup",
            coordinateDigest=(coordinate.coordinate_digest if coordinate is not None else None),
            resourcesAbsent=True,
            completedAt=datetime.now(UTC),
        )

    def observe_single_banner_emission(
        self,
        attempt: NetworkFixtureTargetAttempt,
        coordinate: NetworkFixtureTargetCoordinate,
    ) -> Literal[1]:
        """Require the exact ready event followed by one passive banner emission."""

        if (
            coordinate.attempt_id != attempt.attempt_id
            or coordinate.attempt_digest != attempt.attempt_digest
            or coordinate.case != attempt.case
        ):
            raise NetworkFixtureRuntimeError("Network fixture emission coordinate differs")
        lines = self._decode_log_lines(
            self._require_success(("logs", coordinate.target_container_name))
        )
        expected = (
            {
                "event": "ready",
                "caseId": attempt.case.case_id,
                "port": NETWORK_TCP_BANNER_EMITTER_PORT,
            },
            {
                "event": "banner-emitted",
                "caseId": attempt.case.case_id,
                "port": NETWORK_TCP_BANNER_EMITTER_PORT,
                "sequence": 1,
            },
        )
        if lines != expected:
            raise NetworkFixtureRuntimeError(
                "Network fixture Target did not emit exactly one fixed banner"
            )
        return 1

    def managed_resources_absent(self) -> bool:
        label = f"label={_MANAGED_LABEL}=true"
        return not self._listed(
            ("container", "ls", "--all", "--quiet", "--filter", label)
        ) and not self._listed(("network", "ls", "--quiet", "--filter", label))

    def _observe_target(
        self,
        *,
        attempt: NetworkFixtureTargetAttempt,
        names: NetworkFixtureResourceNames,
        target_image_id: str,
    ) -> NetworkFixtureTargetCoordinate:
        target = self._single_inspect(("container", "inspect", names.target_container_name))
        network = self._single_inspect(("network", "inspect", names.target_network_name))
        target_id = _require_docker_sha256(target.get("Id"), label="Target container")
        network_id = _require_docker_sha256(network.get("Id"), label="Target network")
        config = _mapping(target.get("Config"), label="Target Config")
        host = _mapping(target.get("HostConfig"), label="Target HostConfig")
        state = _mapping(target.get("State"), label="Target State")
        settings = _mapping(target.get("NetworkSettings"), label="Target NetworkSettings")
        endpoints = _mapping(settings.get("Networks"), label="Target networks")
        endpoint = _mapping(endpoints.get(names.target_network_name), label="Target endpoint")
        ports = _mapping(settings.get("Ports"), label="Target ports")
        labels = _string_mapping(config.get("Labels"), label="Target labels")
        network_labels = _string_mapping(network.get("Labels"), label="Target network labels")
        members = _mapping(network.get("Containers"), label="Target network members")
        security_options = host.get("SecurityOpt")
        capabilities = host.get("CapDrop")
        if (
            network.get("Internal") is not True
            or set(members) != {target_id}
            or target.get("Image") != target_image_id
            or state.get("Running") is not True
            or host.get("ReadonlyRootfs") is not True
            or capabilities != ["ALL"]
            or not isinstance(security_options, list)
            or not any(
                isinstance(option, str) and option.split(":", maxsplit=1)[0] == "no-new-privileges"
                for option in security_options
            )
            or config.get("User") != "65532:65532"
            or config.get("Entrypoint") != ["python", "/opt/pajin/banner_emitter.py"]
            or config.get("Cmd") != [attempt.case.case_id]
            or host.get("PortBindings") not in (None, {})
            or any(value not in (None, []) for value in ports.values())
            or tuple(endpoints) != (names.target_network_name,)
            or labels.get(_MANAGED_LABEL) != "true"
            or labels.get(_ATTEMPT_LABEL) != attempt.attempt_digest
            or labels.get(_CASE_LABEL) != attempt.case.case_digest
            or labels.get(_ROLE_LABEL) != "target"
            or network_labels.get(_MANAGED_LABEL) != "true"
            or network_labels.get(_ATTEMPT_LABEL) != attempt.attempt_digest
            or network_labels.get(_CASE_LABEL) != attempt.case.case_digest
            or network_labels.get(_ROLE_LABEL) != "target-network"
        ):
            raise NetworkFixtureRuntimeError(
                "Network fixture Target isolation or configuration differs"
            )
        target_ip = endpoint.get("IPAddress")
        if not isinstance(target_ip, str):
            raise NetworkFixtureRuntimeError("Network fixture Target IP observation is absent")
        return NetworkFixtureTargetCoordinate(
            case=attempt.case,
            attemptId=attempt.attempt_id,
            attemptDigest=attempt.attempt_digest,
            targetContainerName=names.target_container_name,
            targetContainerId=target_id,
            targetImageId=target_image_id,
            targetNetworkName=names.target_network_name,
            targetNetworkId=network_id,
            addressFamily="ipv4",
            host=target_ip,
            networkInternal=True,
            publishedPortCount=0,
            readOnlyRoot=True,
            capabilityDropAll=True,
            noNewPrivileges=True,
            nonRootUser=True,
            observedAt=datetime.now(UTC),
        )

    def _wait_ready(self, container_name: str, case_id: str) -> None:
        deadline = time.monotonic() + self._ready_timeout_seconds
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                lines = self._decode_log_lines(self._require_success(("logs", container_name)))
                if any(
                    item
                    == {
                        "event": "ready",
                        "caseId": case_id,
                        "port": NETWORK_TCP_BANNER_EMITTER_PORT,
                    }
                    for item in lines
                ):
                    return
            except NetworkFixtureRuntimeError as exc:
                last_error = exc
            time.sleep(0.05)
        raise NetworkFixtureRuntimeError(
            "Network fixture Target did not report its exact ready event"
        ) from last_error

    @staticmethod
    def _decode_log_lines(raw: bytes) -> tuple[dict[str, object], ...]:
        text = _decode_utf8(raw)
        values: list[dict[str, object]] = []
        for line in text.splitlines():
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise NetworkFixtureRuntimeError("Network fixture Target log is invalid") from exc
            if not isinstance(value, dict):
                raise NetworkFixtureRuntimeError("Network fixture Target log is not an object")
            values.append(value)
        return tuple(values)

    def _single_inspect(self, arguments: Sequence[str]) -> dict[str, object]:
        try:
            value = json.loads(_decode_utf8(self._require_success(arguments)))
        except json.JSONDecodeError as exc:
            raise NetworkFixtureRuntimeError(
                "Network fixture Docker inspect output is invalid"
            ) from exc
        if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
            raise NetworkFixtureRuntimeError("Network fixture Docker inspect output is ambiguous")
        return value[0]

    def _require_success(self, arguments: Sequence[str]) -> bytes:
        result = self._docker.run(arguments)
        if result.returncode != 0:
            raise NetworkFixtureRuntimeError("Network fixture Docker provider command was rejected")
        return result.stdout

    def _resource_ids(self, resource: str, name: str) -> tuple[str, ...]:
        command = (
            ("container", "ls", "--all", "--quiet", "--filter", f"name=^/{name}$")
            if resource == "container"
            else ("network", "ls", "--quiet", "--filter", f"name=^{name}$")
        )
        return self._listed(command)

    def _listed(self, arguments: Sequence[str]) -> tuple[str, ...]:
        return tuple(
            line for line in _decode_utf8(self._require_success(arguments)).splitlines() if line
        )

    def _remove_if_present(
        self,
        resource: str,
        name: str,
        remove_arguments: Sequence[str],
    ) -> None:
        if self._resource_ids(resource, name):
            self._require_success(remove_arguments)

    @staticmethod
    def _require_operation(
        attempt: NetworkFixtureTargetAttempt,
        operation: NetworkFixtureTargetOperation,
        *,
        stage: Literal["reset", "isolation", "cleanup"],
    ) -> None:
        if (
            operation.stage != stage
            or operation.attempt_id != attempt.attempt_id
            or operation.attempt_digest != attempt.attempt_digest
            or operation.scope_digest != attempt.scope_digest
            or operation.fence < attempt.fence
            or (stage != "cleanup" and operation.fence != attempt.fence)
        ):
            raise NetworkFixtureRuntimeError(
                "Network fixture provider operation differs from its attempt"
            )


@dataclass(frozen=True, slots=True)
class NetworkFixtureLiveTarget:
    attempt: NetworkFixtureTargetAttempt
    reset: NetworkFixtureTargetStageReceipt
    isolation: NetworkFixtureTargetStageReceipt
    coordinate: NetworkFixtureTargetCoordinate


class NetworkFixtureTargetLifecycleRunner:
    """Journal and execute one recoverable Network-specific Target lifecycle."""

    def __init__(
        self,
        *,
        provider: NetworkFixtureDockerProvider,
        journal: NetworkFixtureOperationJournal,
    ) -> None:
        if not isinstance(provider, NetworkFixtureDockerProvider):
            raise TypeError("Network fixture lifecycle requires its Docker provider")
        if not isinstance(journal, NetworkFixtureOperationJournal):
            raise TypeError("Network fixture lifecycle requires its operation journal")
        self._provider = provider
        self._journal = journal

    @property
    def provider(self) -> NetworkFixtureDockerProvider:
        return self._provider

    def reconcile_abandoned(
        self,
    ) -> tuple[NetworkFixtureTargetRecoveryReceipt, ...]:
        recovered: list[NetworkFixtureTargetRecoveryReceipt] = []
        for attempt, coordinate in self._journal.open_attempts():
            operation = self._journal.begin_recovery(attempt)
            try:
                receipt = self._provider.cleanup(
                    attempt,
                    operation,
                    coordinate=coordinate,
                )
            except Exception:
                self._journal.append_provider_error(operation)
                raise
            recovered.append(
                self._journal.mark_recovered(
                    attempt,
                    operation,
                    receipt,
                )
            )
        return tuple(recovered)

    def start(
        self,
        *,
        case: NetworkMeasuredCaseRef,
        images: NetworkSourceImageBinding,
    ) -> NetworkFixtureLiveTarget:
        attempt = self._journal.begin_attempt(
            case=case,
            images=images.reference(),
        )
        reset_operation = self._journal.operation(attempt, "reset")
        self._journal.append_intent(reset_operation)
        try:
            reset = self._provider.reset(attempt, reset_operation, images)
        except Exception:
            self._journal.append_provider_error(reset_operation)
            raise
        self._journal.append_receipt(reset_operation, reset)

        isolation_operation = self._journal.operation(attempt, "isolation")
        self._journal.append_intent(isolation_operation)
        try:
            isolation, coordinate = self._provider.establish_isolation(
                attempt,
                reset,
                isolation_operation,
                images,
            )
        except Exception:
            self._journal.append_provider_error(isolation_operation)
            raise
        self._journal.append_receipt(isolation_operation, isolation)
        self._journal.store_coordinate(attempt, coordinate)
        return NetworkFixtureLiveTarget(
            attempt=attempt,
            reset=reset,
            isolation=isolation,
            coordinate=coordinate,
        )

    def finish(
        self,
        live: NetworkFixtureLiveTarget,
        *,
        topology: NetworkFixtureProxyTopologyObservation,
    ) -> NetworkFixtureTargetLifecycleEvidence:
        banner_emission_count = self._provider.observe_single_banner_emission(
            live.attempt,
            live.coordinate,
        )
        cleanup_operation = self._journal.operation(live.attempt, "cleanup")
        self._journal.append_intent(cleanup_operation)
        try:
            cleanup = self._provider.cleanup(
                live.attempt,
                cleanup_operation,
                coordinate=live.coordinate,
            )
        except Exception:
            self._journal.append_provider_error(cleanup_operation)
            raise
        self._journal.append_receipt(cleanup_operation, cleanup)
        self._journal.complete(live.attempt)
        records = self._journal.records(live.attempt.attempt_id)
        return NetworkFixtureTargetLifecycleEvidence(
            attempt=live.attempt,
            coordinate=live.coordinate,
            reset=live.reset,
            isolation=live.isolation,
            topology=topology,
            targetBannerEmissionCount=banner_emission_count,
            targetApplicationReadBytes=0,
            cleanup=cleanup,
            journalRecords=records,
        )


def _decode_utf8(value: bytes) -> str:
    try:
        return value.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise NetworkFixtureRuntimeError("Network fixture Docker output is not UTF-8") from exc


def _mapping(value: object, *, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        raise NetworkFixtureRuntimeError(f"Network fixture {label} is invalid")
    return value


def _string_mapping(value: object, *, label: str) -> Mapping[str, str]:
    mapping = _mapping(value, label=label)
    if any(not isinstance(key, str) or not isinstance(item, str) for key, item in mapping.items()):
        raise NetworkFixtureRuntimeError(f"Network fixture {label} is invalid")
    return mapping  # type: ignore[return-value]


def _require_docker_sha256(value: object, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[a-f0-9]{64}", value) is None:
        raise NetworkFixtureRuntimeError(f"Network fixture {label} identity differs")
    return value


def _require_image_id(value: object, *, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"sha256:[a-f0-9]{64}", value) is None:
        raise NetworkFixtureRuntimeError(f"Network fixture {label} identity differs")
    return value


__all__ = [
    "NETWORK_BANNER_EMITTER_IMAGE",
    "NETWORK_EGRESS_PROXY_IMAGE",
    "NETWORK_FIXTURE_PROXY_TOPOLOGY_API_VERSION",
    "NETWORK_FIXTURE_TARGET_ATTEMPT_API_VERSION",
    "NETWORK_FIXTURE_TARGET_COORDINATE_API_VERSION",
    "NETWORK_FIXTURE_TARGET_OPERATION_API_VERSION",
    "NETWORK_FIXTURE_TARGET_RECEIPT_API_VERSION",
    "NETWORK_FIXTURE_TARGET_RECOVERY_API_VERSION",
    "NETWORK_SOURCE_IMAGE_BINDING_API_VERSION",
    "NETWORK_WORKER_IMAGE",
    "NetworkDockerBoundaryInspector",
    "NetworkDockerCommandResult",
    "NetworkDockerCommandRunner",
    "NetworkDockerImageInspector",
    "NetworkFixtureDockerProvider",
    "NetworkFixtureLiveTarget",
    "NetworkFixtureOperationJournal",
    "NetworkFixtureOperationRecord",
    "NetworkFixtureProxyTopologyObservation",
    "NetworkFixtureResourceNames",
    "NetworkFixtureRuntimeError",
    "NetworkFixtureTargetAttempt",
    "NetworkFixtureTargetCoordinate",
    "NetworkFixtureTargetLifecycleEvidence",
    "NetworkFixtureTargetLifecycleRunner",
    "NetworkFixtureTargetOperation",
    "NetworkFixtureTargetRecoveryReceipt",
    "NetworkFixtureTargetStageReceipt",
    "NetworkSourceImageBinding",
    "NetworkSourceImageBindingRef",
    "NetworkSourceImageRoleBinding",
    "SubprocessNetworkDockerBoundaryInspector",
    "SubprocessNetworkDockerCommandRunner",
    "load_network_source_image_binding",
    "network_fixture_resource_names",
    "registered_network_source_image_binding",
]
