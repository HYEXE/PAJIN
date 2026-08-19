"""Provider-common black-box conformance for activated Object Storage transports."""

from __future__ import annotations

import base64
import json
import re
from abc import abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Literal, Protocol, Self
from urllib.parse import parse_qsl, quote_from_bytes, unquote, urlsplit

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.control_plane.object_storage_activation import ObjectStorageAuthorityHeadStore
from pajin.control_plane.object_storage_authority import (
    ObjectStorageTransportBinding,
    object_storage_part_key,
)
from pajin.control_plane.object_storage_provider import (
    ObjectStorageCleanupDisposition,
    ObjectStorageProviderAdapterDefinition,
)
from pajin.control_plane.object_storage_recovery import (
    ObjectStorageConcreteProviderActivation,
    ObjectStorageProviderAttemptJournal,
    ObjectStorageProviderDeploymentProfile,
    object_storage_provider_operation_fence,
)
from pajin.domain.models import StrictModel

OBJECT_STORAGE_PROVIDER_CONFORMANCE_PLAN_API_VERSION = (
    "pajin.control-plane.object-storage-provider-conformance-plan/v1"
)
OBJECT_STORAGE_PROVIDER_CONFORMANCE_CASE_PLAN_API_VERSION = (
    "pajin.control-plane.object-storage-provider-conformance-case-plan/v1"
)
OBJECT_STORAGE_PROVIDER_CONFORMANCE_REPORT_API_VERSION = (
    "pajin.control-plane.object-storage-provider-conformance-report/v1"
)
OBJECT_STORAGE_PROVIDER_CONFORMANCE_OPERATION_DOMAIN = (
    "pajin.control-plane.object-storage-provider-conformance-operation/v1"
)
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_OPERATION_ID_PATTERN = re.compile(
    r"^object-storage-attempt-operation_f([0-9]{20})_([a-f0-9]{64})$"
)
_MAX_CHALLENGE_BYTES = 4_096
_MIN_CHALLENGE_BYTES = 32
_MAX_CAPTURE_BYTES = 8 * 1024 * 1024
_MAX_CREDENTIAL_URLS = 256
_MAX_URL_CHARACTERS = 8_192
_MAX_SENSITIVE_VALUES = 256
_MAX_SENSITIVE_VALUE_BYTES = 4_096
_CAPTURE_CHANNELS = ("adapter", "http-transport", "provider-sdk")


class ObjectStorageProviderConformanceError(RuntimeError):
    """Raised when an activated provider fails the common black-box suite."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _domain_digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\x00" + _canonical_json(value)).hexdigest()


def _normalize_timestamp(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset")
    return value.astimezone(UTC)


class ObjectStorageProviderConformanceCase(StrEnum):
    """Fixed cases that every selected provider must execute in an isolated namespace."""

    OPERATION_FENCE = "operation-fence"
    MULTIPART_IDEMPOTENCY = "multipart-idempotency"
    REDIRECT_REFUSAL = "redirect-refusal"
    SERVER_SIDE_ENCRYPTION = "server-side-encryption"
    STRONG_READ_AFTER_WRITE = "strong-read-after-write"
    PREFIX_CLEANUP = "prefix-cleanup"
    SIGNATURE_COVERAGE = "signature-coverage"
    LOG_NON_DISCLOSURE = "log-non-disclosure"


_CASES = tuple(ObjectStorageProviderConformanceCase)
_OPERATION_COUNTS = {
    ObjectStorageProviderConformanceCase.OPERATION_FENCE: 2,
    ObjectStorageProviderConformanceCase.MULTIPART_IDEMPOTENCY: 2,
    ObjectStorageProviderConformanceCase.REDIRECT_REFUSAL: 5,
    ObjectStorageProviderConformanceCase.SERVER_SIDE_ENCRYPTION: 2,
    ObjectStorageProviderConformanceCase.STRONG_READ_AFTER_WRITE: 2,
    ObjectStorageProviderConformanceCase.PREFIX_CLEANUP: 1,
    ObjectStorageProviderConformanceCase.SIGNATURE_COVERAGE: 1,
    ObjectStorageProviderConformanceCase.LOG_NON_DISCLOSURE: 1,
}


class ObjectStorageProviderConformanceCasePlan(StrictModel):
    """One content-addressed black-box invocation without credentials or remote bytes."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-conformance-case-plan/v1"] = (
        Field(
            default="pajin.control-plane.object-storage-provider-conformance-case-plan/v1",
            alias="apiVersion",
        )
    )
    kind: Literal["ObjectStorageProviderConformanceCasePlan"] = (
        "ObjectStorageProviderConformanceCasePlan"
    )
    case_plan_digest: str = Field(default="", alias="casePlanDigest", max_length=64)
    case: ObjectStorageProviderConformanceCase
    binding_digest: str = Field(alias="bindingDigest", pattern=_SHA256_PATTERN)
    challenge_sha256: str = Field(alias="challengeSha256", pattern=_SHA256_PATTERN)
    exact_object_key_sha256: str = Field(
        alias="exactObjectKeySha256",
        pattern=_SHA256_PATTERN,
    )
    operation_ids: tuple[str, ...] = Field(
        alias="operationIds",
        min_length=1,
        max_length=5,
    )
    started_at: datetime = Field(alias="startedAt")
    expires_at: datetime = Field(alias="expiresAt")
    fresh_isolated_namespace_required: Literal[True] = Field(
        default=True,
        alias="freshIsolatedNamespaceRequired",
    )
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("started_at", "expires_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage conformance expiry")

    @field_validator(
        "fresh_isolated_namespace_required",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage conformance flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_case_plan(self) -> Self:
        if len(self.operation_ids) != _OPERATION_COUNTS[self.case]:
            raise ValueError("Object Storage conformance operation count differs")
        if len(set(self.operation_ids)) != len(self.operation_ids):
            raise ValueError("Object Storage conformance operation IDs must be unique")
        if any(_OPERATION_ID_PATTERN.fullmatch(item) is None for item in self.operation_ids):
            raise ValueError("Object Storage conformance operation ID is invalid")
        material = self.model_dump(mode="json", by_alias=True, exclude={"case_plan_digest"})
        digest = _domain_digest(OBJECT_STORAGE_PROVIDER_CONFORMANCE_CASE_PLAN_API_VERSION, material)
        if self.case_plan_digest and self.case_plan_digest != digest:
            raise ValueError("Object Storage conformance case-plan digest differs")
        object.__setattr__(self, "case_plan_digest", digest)
        return self


class ObjectStorageProviderConformancePlan(StrictModel):
    """Exact suite plan bound to one active provider, head, binding, and challenge."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-conformance-plan/v1"] = Field(
        default="pajin.control-plane.object-storage-provider-conformance-plan/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageProviderConformancePlan"] = "ObjectStorageProviderConformancePlan"
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    activation_digest: str = Field(alias="activationDigest", pattern=_SHA256_PATTERN)
    authority_checkpoint_digest: str = Field(
        alias="authorityCheckpointDigest",
        pattern=_SHA256_PATTERN,
    )
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)
    deployment_profile_digest: str = Field(
        alias="deploymentProfileDigest",
        pattern=_SHA256_PATTERN,
    )
    binding_digest: str = Field(alias="bindingDigest", pattern=_SHA256_PATTERN)
    local_conformance_profile_id: str = Field(
        alias="localConformanceProfileId",
        min_length=1,
        max_length=200,
    )
    challenge_sha256: str = Field(alias="challengeSha256", pattern=_SHA256_PATTERN)
    started_at: datetime = Field(alias="startedAt")
    cases: tuple[ObjectStorageProviderConformanceCasePlan, ...]
    transport_only: Literal[True] = Field(default=True, alias="transportOnly")
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("started_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage conformance start")

    @field_validator(
        "transport_only",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage conformance flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        if tuple(item.case for item in self.cases) != _CASES:
            raise ValueError("Object Storage conformance cases differ from the fixed suite")
        if any(
            item.binding_digest != self.binding_digest
            or item.challenge_sha256 != self.challenge_sha256
            or item.started_at != self.started_at
            for item in self.cases
        ):
            raise ValueError("Object Storage conformance case binding differs")
        operation_ids = tuple(
            operation_id for item in self.cases for operation_id in item.operation_ids
        )
        if len(set(operation_ids)) != len(operation_ids):
            raise ValueError("Object Storage conformance plan reuses an operation ID")
        fence_case = self.cases[0]
        if tuple(map(object_storage_provider_operation_fence, fence_case.operation_ids)) != (2, 1):
            raise ValueError("Object Storage conformance fence probe order differs")
        remaining_fences = tuple(
            object_storage_provider_operation_fence(operation_id)
            for item in self.cases[1:]
            for operation_id in item.operation_ids
        )
        if remaining_fences != tuple(range(3, 3 + len(remaining_fences))):
            raise ValueError("Object Storage conformance operation fence sequence differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"plan_digest"})
        digest = _domain_digest(OBJECT_STORAGE_PROVIDER_CONFORMANCE_PLAN_API_VERSION, material)
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("Object Storage conformance plan digest differs")
        object.__setattr__(self, "plan_digest", digest)
        return self


class _Observation(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    case_plan_digest: str = Field(alias="casePlanDigest", pattern=_SHA256_PATTERN)


class ObjectStorageFenceObservation(_Observation):
    kind: Literal["ObjectStorageFenceObservation"] = "ObjectStorageFenceObservation"
    high_operation_id: str = Field(alias="highOperationId")
    low_operation_id: str = Field(alias="lowOperationId")
    accepted_operation_ids: tuple[str, ...] = Field(alias="acceptedOperationIds")
    rejected_operation_ids: tuple[str, ...] = Field(alias="rejectedOperationIds")
    observed_high_water_fence: int = Field(alias="observedHighWaterFence", strict=True, ge=1)
    high_remote_effect_count: int = Field(alias="highRemoteEffectCount", strict=True, ge=0)
    low_remote_effect_count: int = Field(alias="lowRemoteEffectCount", strict=True, ge=0)
    namespace_initial_object_count: int = Field(
        alias="namespaceInitialObjectCount",
        strict=True,
        ge=0,
    )


class ObjectStorageMultipartIdempotencyObservation(_Observation):
    kind: Literal["ObjectStorageMultipartIdempotencyObservation"] = (
        "ObjectStorageMultipartIdempotencyObservation"
    )
    part_operation_id: str = Field(alias="partOperationId")
    completion_operation_id: str = Field(alias="completionOperationId")
    part_attempt_count: int = Field(alias="partAttemptCount", strict=True, ge=0)
    part_mutation_count: int = Field(alias="partMutationCount", strict=True, ge=0)
    completion_attempt_count: int = Field(alias="completionAttemptCount", strict=True, ge=0)
    completion_mutation_count: int = Field(alias="completionMutationCount", strict=True, ge=0)
    observed_content_sha256: str = Field(
        alias="observedContentSha256",
        pattern=_SHA256_PATTERN,
    )


class ObjectStorageRedirectObservation(_Observation):
    kind: Literal["ObjectStorageRedirectObservation"] = "ObjectStorageRedirectObservation"
    operation_ids: tuple[str, ...] = Field(alias="operationIds")
    redirect_response_count: int = Field(alias="redirectResponseCount", strict=True, ge=0)
    provider_rejection_count: int = Field(alias="providerRejectionCount", strict=True, ge=0)
    followed_redirect_count: int = Field(alias="followedRedirectCount", strict=True, ge=0)
    remote_effect_count: int = Field(alias="remoteEffectCount", strict=True, ge=0)


class ObjectStorageEncryptionObservation(_Observation):
    kind: Literal["ObjectStorageEncryptionObservation"] = "ObjectStorageEncryptionObservation"
    operation_ids: tuple[str, ...] = Field(alias="operationIds")
    write_status_code: int = Field(alias="writeStatusCode", strict=True, ge=100, le=599)
    receipt_policy_id: str = Field(alias="receiptPolicyId", min_length=1, max_length=200)
    receipt_sha256: str = Field(alias="receiptSha256", pattern=_SHA256_PATTERN)
    observed_content_sha256: str = Field(
        alias="observedContentSha256",
        pattern=_SHA256_PATTERN,
    )


class ObjectStorageReadAfterWriteObservation(_Observation):
    kind: Literal["ObjectStorageReadAfterWriteObservation"] = (
        "ObjectStorageReadAfterWriteObservation"
    )
    operation_ids: tuple[str, ...] = Field(alias="operationIds")
    write_status_code: int = Field(alias="writeStatusCode", strict=True, ge=100, le=599)
    immediate_read_attempt_count: int = Field(
        alias="immediateReadAttemptCount",
        strict=True,
        ge=0,
    )
    immediate_read_status_code: int = Field(
        alias="immediateReadStatusCode",
        strict=True,
        ge=100,
        le=599,
    )
    observed_content_sha256: str = Field(
        alias="observedContentSha256",
        pattern=_SHA256_PATTERN,
    )


class ObjectStorageCleanupObservation(_Observation):
    kind: Literal["ObjectStorageCleanupObservation"] = "ObjectStorageCleanupObservation"
    operation_id: str = Field(alias="operationId")
    first_disposition: ObjectStorageCleanupDisposition = Field(alias="firstDisposition")
    second_disposition: ObjectStorageCleanupDisposition = Field(alias="secondDisposition")
    remaining_object_count: int = Field(alias="remainingObjectCount", strict=True, ge=0)
    remaining_native_upload_count: int = Field(
        alias="remainingNativeUploadCount",
        strict=True,
        ge=0,
    )


class ObjectStorageSignatureObservation(_Observation):
    kind: Literal["ObjectStorageSignatureObservation"] = "ObjectStorageSignatureObservation"
    credential_operation_id: str = Field(alias="credentialOperationId")
    valid_method: Literal["PUT"] = Field(default="PUT", alias="validMethod")
    mutated_method: Literal["GET"] = Field(default="GET", alias="mutatedMethod")
    exact_object_key_sha256: str = Field(
        alias="exactObjectKeySha256",
        pattern=_SHA256_PATTERN,
    )
    mutated_object_key_sha256: str = Field(
        alias="mutatedObjectKeySha256",
        pattern=_SHA256_PATTERN,
    )
    expires_at: datetime = Field(alias="expiresAt")
    valid_probe_at: datetime = Field(alias="validProbeAt")
    expired_probe_at: datetime = Field(alias="expiredProbeAt")
    valid_status_code: int = Field(alias="validStatusCode", strict=True, ge=100, le=599)
    method_mutation_status_code: int = Field(
        alias="methodMutationStatusCode",
        strict=True,
        ge=100,
        le=599,
    )
    key_mutation_status_code: int = Field(
        alias="keyMutationStatusCode",
        strict=True,
        ge=100,
        le=599,
    )
    expired_status_code: int = Field(alias="expiredStatusCode", strict=True, ge=100, le=599)
    valid_remote_effect_count: int = Field(
        alias="validRemoteEffectCount",
        strict=True,
        ge=0,
    )
    invalid_remote_effect_count: int = Field(
        alias="invalidRemoteEffectCount",
        strict=True,
        ge=0,
    )
    observed_content_sha256: str = Field(
        alias="observedContentSha256",
        pattern=_SHA256_PATTERN,
    )

    @field_validator("expires_at", "valid_probe_at", "expired_probe_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage signature probe time")


@dataclass(frozen=True, slots=True, repr=False)
class ObjectStorageProviderLogCapture:
    """Runtime-only provider log bytes and credentials; never part of a durable model."""

    case_plan_digest: str
    captured_channels: tuple[str, ...]
    log_bytes: bytes = field(repr=False, compare=False)
    credential_urls: tuple[str, ...] = field(repr=False, compare=False)
    additional_sensitive_values: tuple[bytes, ...] = field(
        default=(),
        repr=False,
        compare=False,
    )

    def __repr__(self) -> str:
        return (
            "ObjectStorageProviderLogCapture("
            f"case_plan_digest={self.case_plan_digest!r}, "
            f"captured_channels={self.captured_channels!r}, "
            "log_bytes=<redacted>, credential_urls=<redacted>, "
            "additional_sensitive_values=<redacted>)"
        )


class ObjectStorageLogNonDisclosureObservation(_Observation):
    kind: Literal["ObjectStorageLogNonDisclosureObservation"] = (
        "ObjectStorageLogNonDisclosureObservation"
    )
    captured_channels: tuple[str, ...] = Field(alias="capturedChannels")
    captured_log_byte_count: int = Field(alias="capturedLogByteCount", strict=True, ge=0)
    captured_log_sha256: str = Field(alias="capturedLogSha256", pattern=_SHA256_PATTERN)
    tested_credential_url_count: int = Field(
        alias="testedCredentialUrlCount",
        strict=True,
        ge=1,
    )
    tested_additional_sensitive_value_count: int = Field(
        alias="testedAdditionalSensitiveValueCount",
        strict=True,
        ge=0,
    )
    matched_sensitive_token_count: Literal[0] = Field(
        default=0,
        alias="matchedSensitiveTokenCount",
    )

    @field_validator("matched_sensitive_token_count", mode="before")
    @classmethod
    def require_literal_zero(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Object Storage log match count must be a JSON integer")
        return value


ObjectStorageProviderConformanceObservation = (
    ObjectStorageFenceObservation
    | ObjectStorageMultipartIdempotencyObservation
    | ObjectStorageRedirectObservation
    | ObjectStorageEncryptionObservation
    | ObjectStorageReadAfterWriteObservation
    | ObjectStorageCleanupObservation
    | ObjectStorageSignatureObservation
    | ObjectStorageLogNonDisclosureObservation
)

_OBSERVATION_TYPES: dict[
    ObjectStorageProviderConformanceCase,
    type[_Observation],
] = {
    ObjectStorageProviderConformanceCase.OPERATION_FENCE: ObjectStorageFenceObservation,
    ObjectStorageProviderConformanceCase.MULTIPART_IDEMPOTENCY: (
        ObjectStorageMultipartIdempotencyObservation
    ),
    ObjectStorageProviderConformanceCase.REDIRECT_REFUSAL: ObjectStorageRedirectObservation,
    ObjectStorageProviderConformanceCase.SERVER_SIDE_ENCRYPTION: ObjectStorageEncryptionObservation,
    ObjectStorageProviderConformanceCase.STRONG_READ_AFTER_WRITE: (
        ObjectStorageReadAfterWriteObservation
    ),
    ObjectStorageProviderConformanceCase.PREFIX_CLEANUP: ObjectStorageCleanupObservation,
    ObjectStorageProviderConformanceCase.SIGNATURE_COVERAGE: ObjectStorageSignatureObservation,
    ObjectStorageProviderConformanceCase.LOG_NON_DISCLOSURE: (
        ObjectStorageLogNonDisclosureObservation
    ),
}


class ObjectStorageProviderConformanceTarget(Protocol):
    """Provider-specific fixture that returns raw observations from an isolated environment."""

    @property
    @abstractmethod
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        """Return the exact adapter definition used by the black-box target."""

    @property
    @abstractmethod
    def deployment_profile(self) -> ObjectStorageProviderDeploymentProfile:
        """Return the exact activated provider profile under test."""

    @abstractmethod
    def execute(
        self,
        *,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageProviderConformanceObservation | ObjectStorageProviderLogCapture:
        """Execute one case and return observations, not a caller-selected pass flag."""


class ObjectStorageProviderConformanceCaseResult(StrictModel):
    """Secret-free digest of one observation accepted by the common runner."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    case: ObjectStorageProviderConformanceCase
    case_plan_digest: str = Field(alias="casePlanDigest", pattern=_SHA256_PATTERN)
    observation: ObjectStorageProviderConformanceObservation
    observation_digest: str = Field(default="", alias="observationDigest", max_length=64)
    passed: Literal[True] = True
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator(
        "passed",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage conformance result flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_observation(self) -> Self:
        if (
            not isinstance(self.observation, _OBSERVATION_TYPES[self.case])
            or self.observation.case_plan_digest != self.case_plan_digest
        ):
            raise ValueError("Object Storage conformance result observation differs")
        digest = _domain_digest(
            f"pajin.control-plane.object-storage-provider-conformance-observation/"
            f"{self.case.value}/v1",
            self.observation.model_dump(mode="json", by_alias=True),
        )
        if self.observation_digest and self.observation_digest != digest:
            raise ValueError("Object Storage conformance observation digest differs")
        object.__setattr__(self, "observation_digest", digest)
        return self


class ObjectStorageProviderConformanceReport(StrictModel):
    """Content-addressed, secret-free report with no Artifact or finalization authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.object-storage-provider-conformance-report/v1"] = (
        Field(
            default="pajin.control-plane.object-storage-provider-conformance-report/v1",
            alias="apiVersion",
        )
    )
    kind: Literal["ObjectStorageProviderConformanceReport"] = (
        "ObjectStorageProviderConformanceReport"
    )
    report_digest: str = Field(default="", alias="reportDigest", max_length=64)
    plan: ObjectStorageProviderConformancePlan
    plan_digest: str = Field(alias="planDigest", pattern=_SHA256_PATTERN)
    activation_digest: str = Field(alias="activationDigest", pattern=_SHA256_PATTERN)
    authority_checkpoint_digest: str = Field(
        alias="authorityCheckpointDigest",
        pattern=_SHA256_PATTERN,
    )
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)
    deployment_profile_digest: str = Field(
        alias="deploymentProfileDigest",
        pattern=_SHA256_PATTERN,
    )
    binding_digest: str = Field(alias="bindingDigest", pattern=_SHA256_PATTERN)
    local_conformance_profile_id: str = Field(
        alias="localConformanceProfileId",
        min_length=1,
        max_length=200,
    )
    challenge_sha256: str = Field(alias="challengeSha256", pattern=_SHA256_PATTERN)
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    results: tuple[ObjectStorageProviderConformanceCaseResult, ...]
    black_box_observations_passed: Literal[True] = Field(
        default=True,
        alias="blackBoxObservationsPassed",
    )
    transport_only: Literal[True] = Field(default=True, alias="transportOnly")
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )

    @field_validator("started_at", "finished_at")
    @classmethod
    def require_utc_timestamp(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="Object Storage conformance report time")

    @field_validator(
        "black_box_observations_passed",
        "transport_only",
        "artifact_admission_eligible",
        "finalization_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Object Storage conformance report flags must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_report(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("Object Storage conformance report time regressed")
        if tuple(item.case for item in self.results) != _CASES:
            raise ValueError("Object Storage conformance report cases differ")
        if (
            self.plan.plan_digest != self.plan_digest
            or self.plan.activation_digest != self.activation_digest
            or self.plan.authority_checkpoint_digest != self.authority_checkpoint_digest
            or self.plan.adapter_digest != self.adapter_digest
            or self.plan.deployment_profile_digest != self.deployment_profile_digest
            or self.plan.binding_digest != self.binding_digest
            or self.plan.local_conformance_profile_id != self.local_conformance_profile_id
            or self.plan.challenge_sha256 != self.challenge_sha256
            or self.plan.started_at != self.started_at
            or any(
                result.case_plan_digest != case_plan.case_plan_digest
                for result, case_plan in zip(self.results, self.plan.cases, strict=True)
            )
        ):
            raise ValueError("Object Storage conformance report plan binding differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"report_digest"})
        digest = _domain_digest(OBJECT_STORAGE_PROVIDER_CONFORMANCE_REPORT_API_VERSION, material)
        if self.report_digest and self.report_digest != digest:
            raise ValueError("Object Storage conformance report digest differs")
        object.__setattr__(self, "report_digest", digest)
        return self


def compile_object_storage_provider_conformance_plan(
    activation: ObjectStorageConcreteProviderActivation,
    binding: ObjectStorageTransportBinding,
    *,
    challenge: bytes,
    started_at: datetime,
) -> ObjectStorageProviderConformancePlan:
    """Compile the fixed suite without granting network, Artifact, or cleanup authority."""

    trusted_activation = ObjectStorageConcreteProviderActivation.model_validate(
        activation.model_dump(mode="json", by_alias=True)
    )
    trusted_binding = ObjectStorageTransportBinding.model_validate(
        binding.model_dump(mode="json", by_alias=True)
    )
    challenge_sha256 = _require_challenge(challenge)
    normalized_start = _normalize_timestamp(started_at, label="Object Storage conformance start")
    if not (trusted_binding.issued_at <= normalized_start < trusted_binding.expires_at):
        raise ObjectStorageProviderConformanceError(
            "Object Storage conformance must start inside the binding window"
        )
    checkpoint = trusted_activation.authority_checkpoint
    deployment = trusted_binding.deployment
    if (
        checkpoint.deployment_id != deployment.deployment_id
        or checkpoint.tenant_id != deployment.tenant_id
        or checkpoint.revision != deployment.revision
        or checkpoint.authority_digest != deployment.authority_digest
        or trusted_activation.adapter.endpoint_origin != deployment.endpoint_origin
    ):
        raise ObjectStorageProviderConformanceError(
            "Object Storage conformance binding differs from the activated authority"
        )
    object_key = object_storage_part_key(trusted_binding, file_index=0, part_number=1)
    exact_object_key_sha256 = sha256(object_key.encode("utf-8")).hexdigest()
    cases: list[ObjectStorageProviderConformanceCasePlan] = []
    next_fence = 3
    for case in _CASES:
        count = _OPERATION_COUNTS[case]
        fences: tuple[int, ...]
        if case is ObjectStorageProviderConformanceCase.OPERATION_FENCE:
            fences = (2, 1)
        else:
            fences = tuple(range(next_fence, next_fence + count))
            next_fence += count
        operation_ids = tuple(
            _conformance_operation_id(
                activation_digest=trusted_activation.activation_digest,
                binding_digest=trusted_binding.binding_digest,
                challenge_sha256=challenge_sha256,
                started_at=normalized_start,
                case=case,
                step=step,
                fence=fence,
            )
            for step, fence in enumerate(fences, start=1)
        )
        cases.append(
            ObjectStorageProviderConformanceCasePlan(
                case=case,
                bindingDigest=trusted_binding.binding_digest,
                challengeSha256=challenge_sha256,
                exactObjectKeySha256=exact_object_key_sha256,
                operationIds=operation_ids,
                startedAt=normalized_start,
                expiresAt=trusted_binding.expires_at,
            )
        )
    return ObjectStorageProviderConformancePlan(
        activationDigest=trusted_activation.activation_digest,
        authorityCheckpointDigest=checkpoint.checkpoint_digest,
        adapterDigest=trusted_activation.adapter.adapter_digest,
        deploymentProfileDigest=trusted_activation.deployment_profile.profile_digest,
        bindingDigest=trusted_binding.binding_digest,
        localConformanceProfileId=(
            trusted_activation.deployment_profile.local_conformance_profile_id
        ),
        challengeSha256=challenge_sha256,
        startedAt=normalized_start,
        cases=tuple(cases),
    )


def run_object_storage_provider_conformance(
    *,
    authority_store: ObjectStorageAuthorityHeadStore,
    journal: ObjectStorageProviderAttemptJournal,
    binding: ObjectStorageTransportBinding,
    target: ObjectStorageProviderConformanceTarget,
    challenge: bytes,
    clock: Callable[[], datetime] | None = None,
) -> ObjectStorageProviderConformanceReport:
    """Run the fixed suite against one active provider-specific black-box target."""

    now = clock or (lambda: datetime.now(UTC))
    try:
        definition = ObjectStorageProviderAdapterDefinition.model_validate(
            target.definition.model_dump(mode="json", by_alias=True)
        )
        profile = ObjectStorageProviderDeploymentProfile.model_validate(
            target.deployment_profile.model_dump(mode="json", by_alias=True)
        )
        trusted_binding = ObjectStorageTransportBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, ValidationError, ValueError):
        raise ObjectStorageProviderConformanceError(
            "Object Storage conformance target identity is invalid"
        ) from None
    started_at = _safe_now(now, label="start")
    activation = _require_active_context(
        authority_store=authority_store,
        journal=journal,
        binding=trusted_binding,
        definition=definition,
        profile=profile,
    )
    plan = compile_object_storage_provider_conformance_plan(
        activation,
        trusted_binding,
        challenge=challenge,
        started_at=started_at,
    )
    results: list[ObjectStorageProviderConformanceCaseResult] = []
    minimum_finish_at = started_at
    for case_plan in plan.cases:
        _require_active_context(
            authority_store=authority_store,
            journal=journal,
            binding=trusted_binding,
            definition=definition,
            profile=profile,
        )
        try:
            raw = target.execute(
                case_plan=case_plan.model_copy(deep=True),
                binding=trusted_binding.model_copy(deep=True),
                challenge=bytes(challenge),
            )
        except Exception:
            raise ObjectStorageProviderConformanceError(
                f"Object Storage {case_plan.case.value} observation failed"
            ) from None
        observation = _validate_observation(
            case_plan,
            raw,
            profile=profile,
            challenge_sha256=plan.challenge_sha256,
            endpoint_origin=definition.endpoint_origin,
        )
        if isinstance(observation, ObjectStorageSignatureObservation):
            minimum_finish_at = max(minimum_finish_at, observation.expired_probe_at)
        _require_active_context(
            authority_store=authority_store,
            journal=journal,
            binding=trusted_binding,
            definition=definition,
            profile=profile,
        )
        results.append(
            ObjectStorageProviderConformanceCaseResult(
                case=case_plan.case,
                casePlanDigest=case_plan.case_plan_digest,
                observation=observation,
            )
        )
    finished_at = _safe_now(now, label="finish")
    if finished_at < minimum_finish_at:
        raise ObjectStorageProviderConformanceError(
            "Object Storage conformance finished before its observed probes"
        )
    return ObjectStorageProviderConformanceReport(
        plan=plan,
        planDigest=plan.plan_digest,
        activationDigest=plan.activation_digest,
        authorityCheckpointDigest=plan.authority_checkpoint_digest,
        adapterDigest=plan.adapter_digest,
        deploymentProfileDigest=plan.deployment_profile_digest,
        bindingDigest=plan.binding_digest,
        localConformanceProfileId=plan.local_conformance_profile_id,
        challengeSha256=plan.challenge_sha256,
        startedAt=started_at,
        finishedAt=finished_at,
        results=tuple(results),
    )


def _conformance_operation_id(
    *,
    activation_digest: str,
    binding_digest: str,
    challenge_sha256: str,
    started_at: datetime,
    case: ObjectStorageProviderConformanceCase,
    step: int,
    fence: int,
) -> str:
    digest = _domain_digest(
        OBJECT_STORAGE_PROVIDER_CONFORMANCE_OPERATION_DOMAIN,
        {
            "activationDigest": activation_digest,
            "bindingDigest": binding_digest,
            "challengeSha256": challenge_sha256,
            "startedAt": started_at.isoformat(),
            "case": case.value,
            "step": step,
            "fence": fence,
        },
    )
    return f"object-storage-attempt-operation_f{fence:020d}_{digest}"


def _require_challenge(challenge: bytes) -> str:
    if type(challenge) is not bytes or not (
        _MIN_CHALLENGE_BYTES <= len(challenge) <= _MAX_CHALLENGE_BYTES
    ):
        raise ObjectStorageProviderConformanceError(
            "Object Storage conformance challenge must be bounded runtime bytes"
        )
    return sha256(challenge).hexdigest()


def _safe_now(clock: Callable[[], datetime], *, label: str) -> datetime:
    try:
        return _normalize_timestamp(clock(), label=f"Object Storage conformance {label}")
    except Exception:
        raise ObjectStorageProviderConformanceError(
            "Object Storage conformance clock is invalid"
        ) from None


def _require_active_context(
    *,
    authority_store: ObjectStorageAuthorityHeadStore,
    journal: ObjectStorageProviderAttemptJournal,
    binding: ObjectStorageTransportBinding,
    definition: ObjectStorageProviderAdapterDefinition,
    profile: ObjectStorageProviderDeploymentProfile,
) -> ObjectStorageConcreteProviderActivation:
    try:
        checkpoint = authority_store.checkpoint()
        authority_store.require_current(binding.deployment, expected_checkpoint=checkpoint)
        journal.require_no_pending()
        activation = journal.require_active(
            authority_checkpoint=checkpoint,
            adapter=definition,
            deployment_profile=profile,
        )
    except Exception:
        raise ObjectStorageProviderConformanceError(
            "Object Storage conformance target is not the exact active provider"
        ) from None
    if definition.endpoint_origin != binding.deployment.endpoint_origin:
        raise ObjectStorageProviderConformanceError(
            "Object Storage conformance endpoint differs from the active binding"
        )
    return activation


def _validate_observation(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: ObjectStorageProviderConformanceObservation | ObjectStorageProviderLogCapture,
    *,
    profile: ObjectStorageProviderDeploymentProfile,
    challenge_sha256: str,
    endpoint_origin: str,
) -> ObjectStorageProviderConformanceObservation:
    try:
        if case_plan.case is ObjectStorageProviderConformanceCase.OPERATION_FENCE:
            return _validate_fence_observation(case_plan, raw)
        if case_plan.case is ObjectStorageProviderConformanceCase.MULTIPART_IDEMPOTENCY:
            return _validate_idempotency_observation(case_plan, raw, challenge_sha256)
        if case_plan.case is ObjectStorageProviderConformanceCase.REDIRECT_REFUSAL:
            return _validate_redirect_observation(case_plan, raw)
        if case_plan.case is ObjectStorageProviderConformanceCase.SERVER_SIDE_ENCRYPTION:
            return _validate_encryption_observation(
                case_plan,
                raw,
                profile=profile,
                challenge_sha256=challenge_sha256,
            )
        if case_plan.case is ObjectStorageProviderConformanceCase.STRONG_READ_AFTER_WRITE:
            return _validate_consistency_observation(case_plan, raw, challenge_sha256)
        if case_plan.case is ObjectStorageProviderConformanceCase.PREFIX_CLEANUP:
            return _validate_cleanup_observation(case_plan, raw)
        if case_plan.case is ObjectStorageProviderConformanceCase.SIGNATURE_COVERAGE:
            return _validate_signature_observation(case_plan, raw, challenge_sha256)
        if case_plan.case is ObjectStorageProviderConformanceCase.LOG_NON_DISCLOSURE:
            return _validate_log_capture(
                case_plan,
                raw,
                endpoint_origin=endpoint_origin,
            )
    except (AttributeError, TypeError, ValidationError, ValueError):
        raise ObjectStorageProviderConformanceError(
            f"Object Storage {case_plan.case.value} conformance observation was rejected"
        ) from None
    raise ObjectStorageProviderConformanceError("Object Storage conformance case is unsupported")


def _validate_fence_observation(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: object,
) -> ObjectStorageFenceObservation:
    value = _copy_observation(raw, ObjectStorageFenceObservation)
    high, low = case_plan.operation_ids
    if (
        value.case_plan_digest != case_plan.case_plan_digest
        or value.high_operation_id != high
        or value.low_operation_id != low
        or value.accepted_operation_ids != (high,)
        or value.rejected_operation_ids != (low,)
        or value.observed_high_water_fence != object_storage_provider_operation_fence(high)
        or value.high_remote_effect_count != 1
        or value.low_remote_effect_count != 0
        or value.namespace_initial_object_count != 0
    ):
        raise ValueError
    return value


def _validate_idempotency_observation(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: object,
    challenge_sha256: str,
) -> ObjectStorageMultipartIdempotencyObservation:
    value = _copy_observation(raw, ObjectStorageMultipartIdempotencyObservation)
    part, completion = case_plan.operation_ids
    if (
        value.case_plan_digest != case_plan.case_plan_digest
        or value.part_operation_id != part
        or value.completion_operation_id != completion
        or value.part_attempt_count != 2
        or value.part_mutation_count != 1
        or value.completion_attempt_count != 2
        or value.completion_mutation_count != 1
        or value.observed_content_sha256 != challenge_sha256
    ):
        raise ValueError
    return value


def _validate_redirect_observation(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: object,
) -> ObjectStorageRedirectObservation:
    value = _copy_observation(raw, ObjectStorageRedirectObservation)
    expected = len(case_plan.operation_ids)
    if (
        value.case_plan_digest != case_plan.case_plan_digest
        or value.operation_ids != case_plan.operation_ids
        or value.redirect_response_count != expected
        or value.provider_rejection_count != expected
        or value.followed_redirect_count != 0
        or value.remote_effect_count != 0
    ):
        raise ValueError
    return value


def _validate_encryption_observation(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: object,
    *,
    profile: ObjectStorageProviderDeploymentProfile,
    challenge_sha256: str,
) -> ObjectStorageEncryptionObservation:
    value = _copy_observation(raw, ObjectStorageEncryptionObservation)
    if (
        value.case_plan_digest != case_plan.case_plan_digest
        or value.operation_ids != case_plan.operation_ids
        or not 200 <= value.write_status_code < 300
        or value.receipt_policy_id != profile.server_side_encryption_policy_id
        or value.observed_content_sha256 != challenge_sha256
    ):
        raise ValueError
    return value


def _validate_consistency_observation(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: object,
    challenge_sha256: str,
) -> ObjectStorageReadAfterWriteObservation:
    value = _copy_observation(raw, ObjectStorageReadAfterWriteObservation)
    if (
        value.case_plan_digest != case_plan.case_plan_digest
        or value.operation_ids != case_plan.operation_ids
        or not 200 <= value.write_status_code < 300
        or value.immediate_read_attempt_count != 1
        or not 200 <= value.immediate_read_status_code < 300
        or value.observed_content_sha256 != challenge_sha256
    ):
        raise ValueError
    return value


def _validate_cleanup_observation(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: object,
) -> ObjectStorageCleanupObservation:
    value = _copy_observation(raw, ObjectStorageCleanupObservation)
    if (
        value.case_plan_digest != case_plan.case_plan_digest
        or value.operation_id != case_plan.operation_ids[0]
        or value.first_disposition is not ObjectStorageCleanupDisposition.CLEANED
        or value.second_disposition is not ObjectStorageCleanupDisposition.ALREADY_ABSENT
        or value.remaining_object_count != 0
        or value.remaining_native_upload_count != 0
    ):
        raise ValueError
    return value


def _validate_signature_observation(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: object,
    challenge_sha256: str,
) -> ObjectStorageSignatureObservation:
    value = _copy_observation(raw, ObjectStorageSignatureObservation)
    if (
        value.case_plan_digest != case_plan.case_plan_digest
        or value.credential_operation_id != case_plan.operation_ids[0]
        or value.exact_object_key_sha256 != case_plan.exact_object_key_sha256
        or value.mutated_object_key_sha256 == value.exact_object_key_sha256
        or value.expires_at != case_plan.expires_at
        or not value.valid_probe_at < value.expires_at
        or not value.expired_probe_at >= value.expires_at
        or not 200 <= value.valid_status_code < 300
        or value.method_mutation_status_code not in {401, 403}
        or value.key_mutation_status_code not in {401, 403}
        or value.expired_status_code not in {401, 403}
        or value.valid_remote_effect_count != 1
        or value.invalid_remote_effect_count != 0
        or value.observed_content_sha256 != challenge_sha256
    ):
        raise ValueError
    return value


def _copy_observation[ObservationT: _Observation](
    raw: object,
    expected: type[ObservationT],
) -> ObservationT:
    if not isinstance(raw, expected):
        raise TypeError
    return expected.model_validate(raw.model_dump(mode="json", by_alias=True))


def _validate_log_capture(
    case_plan: ObjectStorageProviderConformanceCasePlan,
    raw: object,
    *,
    endpoint_origin: str,
) -> ObjectStorageLogNonDisclosureObservation:
    if not isinstance(raw, ObjectStorageProviderLogCapture):
        raise TypeError
    if (
        raw.case_plan_digest != case_plan.case_plan_digest
        or raw.captured_channels != _CAPTURE_CHANNELS
        or type(raw.log_bytes) is not bytes
        or len(raw.log_bytes) > _MAX_CAPTURE_BYTES
        or not 1 <= len(raw.credential_urls) <= _MAX_CREDENTIAL_URLS
        or len(raw.additional_sensitive_values) > _MAX_SENSITIVE_VALUES
    ):
        raise ValueError
    tokens: set[bytes] = set()
    for credential_url in raw.credential_urls:
        if type(credential_url) is not str or len(credential_url) > _MAX_URL_CHARACTERS:
            raise ValueError
        parsed = urlsplit(credential_url)
        port = parsed.port
        origin = (
            f"https://{parsed.hostname}" + (f":{port}" if port is not None else "")
            if parsed.hostname is not None
            else ""
        )
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or not parsed.query
            or origin != endpoint_origin
        ):
            raise ValueError
        tokens.update(
            _expanded_sensitive_tokens(
                (
                    credential_url.encode("utf-8"),
                    parsed.query.encode("utf-8"),
                    unquote(parsed.query).encode("utf-8"),
                    *(
                        value.encode("utf-8")
                        for _name, value in parse_qsl(parsed.query, keep_blank_values=True)
                    ),
                )
            )
        )
    for value in raw.additional_sensitive_values:
        if type(value) is not bytes or not value or len(value) > _MAX_SENSITIVE_VALUE_BYTES:
            raise ValueError
        tokens.update(_expanded_sensitive_tokens((value,)))
    if any(token in raw.log_bytes for token in tokens):
        raise ValueError
    return ObjectStorageLogNonDisclosureObservation(
        casePlanDigest=case_plan.case_plan_digest,
        capturedChannels=raw.captured_channels,
        capturedLogByteCount=len(raw.log_bytes),
        capturedLogSha256=sha256(raw.log_bytes).hexdigest(),
        testedCredentialUrlCount=len(raw.credential_urls),
        testedAdditionalSensitiveValueCount=len(raw.additional_sensitive_values),
    )


def _expanded_sensitive_tokens(values: tuple[bytes, ...]) -> set[bytes]:
    expanded: set[bytes] = set()
    for value in values:
        expanded.add(value)
        expanded.add(quote_from_bytes(value, safe="").encode("ascii"))
        expanded.add(base64.b64encode(value))
        expanded.add(base64.urlsafe_b64encode(value))
        expanded.add(base64.urlsafe_b64encode(value).rstrip(b"="))
    return expanded
