"""Additive runtime and transport Pins for compact live Web analysis.

The Pins in this module close over the already verified Capacity v2, compact
live request, and Provider transport lineage.  They describe immutable runtime
configuration only; they do not carry or mint execution authority.
"""

from __future__ import annotations

import re
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Final, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import load_bounded_strict_json
from pajin.web_assessment.analysis_capacity import (
    WEB_ANALYSIS_COMPLETION_TOKENS,
    WEB_ANALYSIS_CONTEXT_TOKENS,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    VerifiedWebAnalysisCapacityV2Run,
    WebAnalysisCapacityV2Pin,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    CompactSkillBoundWebAnalysisLiveRequest,
)
from pajin.web_assessment.analysis_transport import (
    WEB_ANALYSIS_PINNED_PROVIDER_ACTION,
    WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
    WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION,
    WebAnalysisTransportRuntimePin,
)

COMPACT_WEB_ANALYSIS_RUNTIME_PIN_API_VERSION: Final = (
    "pajin.dev/compact-web-analysis-runtime-pin/v1alpha1"
)
COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_API_VERSION: Final = (
    "pajin.dev/compact-web-analysis-transport-pin/v1alpha1"
)
COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_VERSION: Final = (
    "pajin.web-analysis.compact-provider-transport/v1"
)
COMPACT_WEB_ANALYSIS_WORKER_WIRE_PROTOCOL_VERSION: Final = WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION

_MAX_PIN_BYTES: Final = 128 * 1024
_DIGEST_PREFIX: Final = b"PAJIN-COMPACT-WEB-ANALYSIS-LIVE-PIN\0"
_RUNTIME_DIGEST_DOMAIN: Final = "compact-runtime-pin/v1"
_TRANSPORT_DIGEST_DOMAIN: Final = "compact-transport-pin/v1"
_SHA256_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_ImageID = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
CapacityV2Input = VerifiedWebAnalysisCapacityV2Run | WebAnalysisCapacityV2Pin


class CompactWebAnalysisPinError(ValueError):
    """Raised when compact live runtime or transport Pin binding fails closed."""


def _digest(domain: str, value: object) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    payload = canonical_json_bytes(
        value,
        label=f"{domain} payload",
        max_bytes=_MAX_PIN_BYTES,
    )
    return sha256(
        _DIGEST_PREFIX
        + len(domain_bytes).to_bytes(4, "big")
        + domain_bytes
        + len(payload).to_bytes(8, "big")
        + payload
    ).hexdigest()


def _require_expected_digest(value: object, *, label: str) -> str:
    if type(value) is not str or _SHA256_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be an independently supplied SHA-256 digest")
    return value


class _FrozenPin(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class CompactWebAnalysisRuntimePin(_FrozenPin):
    """Exact compact model/runtime binding independent of the legacy RuntimePin."""

    api_version: Literal["pajin.dev/compact-web-analysis-runtime-pin/v1alpha1"] = Field(
        default=COMPACT_WEB_ANALYSIS_RUNTIME_PIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CompactWebAnalysisRuntimePin"] = "CompactWebAnalysisRuntimePin"
    pin_digest: str = Field(default="", alias="pinDigest", max_length=64)

    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    capacity_materialization_policy_digest: _Sha256 = Field(
        alias="capacityMaterializationPolicyDigest"
    )
    capacity_transport_pin_digest: _Sha256 = Field(alias="capacityTransportPinDigest")
    capacity_compact_projection_digest: _Sha256 = Field(alias="capacityCompactProjectionDigest")
    capacity_chat_request_digest: _Sha256 = Field(alias="capacityChatRequestDigest")

    live_request_digest: _Sha256 = Field(alias="liveRequestDigest")
    live_request_compact_projection_digest: _Sha256 = Field(
        alias="liveRequestCompactProjectionDigest"
    )
    live_request_chat_request_digest: _Sha256 = Field(alias="liveRequestChatRequestDigest")
    provider_registration_digest: _Sha256 = Field(alias="providerRegistrationDigest")

    skill_run_id: str = Field(
        alias="skillRunId",
        pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$",
        max_length=64,
    )
    skill_run_root_digest: _Sha256 = Field(alias="skillRunRootDigest")
    skill_snapshot_digest: _Sha256 = Field(alias="skillSnapshotDigest")

    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    model_repository: str = Field(alias="modelRepository", min_length=1, max_length=500)
    model_revision: str = Field(alias="modelRevision", min_length=1, max_length=200)
    model_filename: str = Field(alias="modelFilename", min_length=1, max_length=500)
    model_size_bytes: int = Field(alias="modelSizeBytes", ge=1)
    model_sha256: _Sha256 = Field(alias="modelSha256")
    model_pin_digest: _Sha256 = Field(alias="modelPinDigest")
    model_image: str = Field(alias="modelImage", min_length=1, max_length=500)
    model_platform: Literal["linux/arm64", "linux/amd64"] = Field(alias="modelPlatform")
    model_platform_manifest: _ImageID = Field(alias="modelPlatformManifest")

    context_tokens: Literal[4096] = Field(
        default=WEB_ANALYSIS_CONTEXT_TOKENS,
        alias="contextTokens",
    )
    completion_tokens: Literal[1024] = Field(
        default=WEB_ANALYSIS_COMPLETION_TOKENS,
        alias="completionTokens",
    )
    model_cpus: Literal[4] = Field(default=4, alias="modelCpus")
    model_memory_mb: Literal[6144] = Field(default=6144, alias="modelMemoryMb")
    model_pids: Literal[128] = Field(default=128, alias="modelPids")
    parallel: Literal[1] = 1
    cache_ram_mb: Literal[0] = Field(default=0, alias="cacheRamMb")
    lineage_transport_pin_digest: _Sha256 = Field(alias="lineageTransportPinDigest")

    @field_validator(
        "context_tokens",
        "completion_tokens",
        "model_cpus",
        "model_memory_mb",
        "model_pids",
        "parallel",
        "cache_ram_mb",
        mode="before",
    )
    @classmethod
    def require_exact_integer_profile(cls, value: object, info: ValidationInfo) -> int:
        expected = {
            "context_tokens": 4096,
            "completion_tokens": 1024,
            "model_cpus": 4,
            "model_memory_mb": 6144,
            "model_pids": 128,
            "parallel": 1,
            "cache_ram_mb": 0,
        }[cast(str, info.field_name)]
        if type(value) is not int or value != expected:
            raise ValueError("Compact Web analysis runtime resource profile differs")
        return expected

    @model_validator(mode="after")
    def bind_pin(self) -> Self:
        if self.capacity_transport_pin_digest != self.lineage_transport_pin_digest:
            raise ValueError("Compact runtime transport lineage differs from Capacity v2")
        material = self.model_dump(mode="json", by_alias=True, exclude={"pin_digest"})
        digest = _digest(_RUNTIME_DIGEST_DOMAIN, material)
        if self.pin_digest and self.pin_digest != digest:
            raise ValueError("Compact Web analysis runtime Pin digest differs")
        object.__setattr__(self, "pin_digest", digest)
        return self


class CompactWebAnalysisTransportPin(_FrozenPin):
    """Effective compact transport Pin derived from one exact runtime and lineage Pin."""

    api_version: Literal["pajin.dev/compact-web-analysis-transport-pin/v1alpha1"] = Field(
        default=COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CompactWebAnalysisTransportPin"] = "CompactWebAnalysisTransportPin"
    pin_digest: str = Field(default="", alias="pinDigest", max_length=64)
    runtime_pin_digest: _Sha256 = Field(alias="runtimePinDigest")
    lineage_transport_pin_digest: _Sha256 = Field(alias="lineageTransportPinDigest")
    transport_version: Literal["pajin.web-analysis.compact-provider-transport/v1"] = Field(
        default=COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_VERSION,
        alias="transportVersion",
    )
    worker_wire_protocol_version: Literal["pajin.web-analysis.provider-transport/v2"] = Field(
        default=COMPACT_WEB_ANALYSIS_WORKER_WIRE_PROTOCOL_VERSION,
        alias="workerWireProtocolVersion",
    )
    worker_action: Literal["openai-chat-completion-v3"] = Field(
        default=WEB_ANALYSIS_PINNED_PROVIDER_ACTION,
        alias="workerAction",
    )
    worker_image: _ImageID = Field(alias="workerImage")
    proxy_image: _ImageID = Field(alias="proxyImage")
    worker_open_timeout_seconds: Literal[180] = Field(
        default=WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
        alias="workerOpenTimeoutSeconds",
    )
    proxy_exchange_timeout_seconds: Literal[180] = Field(
        default=WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
        alias="proxyExchangeTimeoutSeconds",
    )
    job_timeout_seconds: Literal[180] = Field(
        default=WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS,
        alias="jobTimeoutSeconds",
    )
    single_dispatch_only: Literal[True] = Field(default=True, alias="singleDispatchOnly")

    @field_validator(
        "worker_open_timeout_seconds",
        "proxy_exchange_timeout_seconds",
        "job_timeout_seconds",
        mode="before",
    )
    @classmethod
    def require_exact_timeout(cls, value: object) -> Literal[180]:
        if type(value) is not int or value != WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS:
            raise ValueError("Compact Web analysis transport timeout differs")
        return WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS

    @field_validator("single_dispatch_only", mode="before")
    @classmethod
    def require_single_dispatch(cls, value: object) -> Literal[True]:
        if type(value) is not bool or value is not True:
            raise ValueError("Compact Web analysis transport must remain single-dispatch")
        return True

    @model_validator(mode="after")
    def bind_pin(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"pin_digest"})
        digest = _digest(_TRANSPORT_DIGEST_DOMAIN, material)
        if self.pin_digest and self.pin_digest != digest:
            raise ValueError("Compact Web analysis transport Pin digest differs")
        object.__setattr__(self, "pin_digest", digest)
        return self


def _canonical_capacity_pin(value: CapacityV2Input) -> WebAnalysisCapacityV2Pin:
    if type(value) is VerifiedWebAnalysisCapacityV2Run:
        pin = value.pin
    elif type(value) is WebAnalysisCapacityV2Pin:
        pin = value
    else:
        raise TypeError("Compact runtime requires the exact Capacity v2 Pin or verified Run")
    if type(pin) is not WebAnalysisCapacityV2Pin:
        raise TypeError("Compact runtime rejects non-v2 Capacity Pins")
    return WebAnalysisCapacityV2Pin.model_validate(pin.model_dump(mode="json", by_alias=True))


def _canonical_live_request(value: object) -> CompactSkillBoundWebAnalysisLiveRequest:
    if type(value) is not CompactSkillBoundWebAnalysisLiveRequest:
        raise TypeError("Compact runtime requires the exact compact live request type")
    request = value
    return CompactSkillBoundWebAnalysisLiveRequest.model_validate(
        request.model_dump(mode="json", by_alias=True)
    )


def _canonical_lineage_transport(value: object) -> WebAnalysisTransportRuntimePin:
    if type(value) is not WebAnalysisTransportRuntimePin:
        raise TypeError("Compact transport requires the exact predecessor transport Pin type")
    pin = value
    return WebAnalysisTransportRuntimePin.model_validate(pin.model_dump(mode="json", by_alias=True))


def _require_capacity_request_lineage(
    capacity: WebAnalysisCapacityV2Pin,
    request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport: WebAnalysisTransportRuntimePin,
) -> None:
    if capacity.transport_pin_digest != lineage_transport.pin_digest:
        raise ValueError("Compact runtime predecessor transport digest differs")
    if (
        request.capacity_compact_projection_digest != capacity.compact_projection_digest
        or request.capacity_chat_request_digest != capacity.chat_request_digest
    ):
        raise ValueError("Compact live request differs from its Capacity v2 anchors")
    if (
        request.skill_run_id != capacity.skill_run_id
        or request.skill_run_root_digest != capacity.skill_run_root_digest
        or request.skill_snapshot_digest != capacity.skill_projection_digest
    ):
        raise ValueError("Compact live request Skill lineage differs from Capacity v2")
    if request.provider_registration.model != capacity.model_id:
        raise ValueError("Compact live request model differs from Capacity v2")
    if (
        type(request.chat_request.max_completion_tokens) is not int
        or request.chat_request.max_completion_tokens != WEB_ANALYSIS_COMPLETION_TOKENS
    ):
        raise ValueError("Compact live request completion budget differs")


def build_compact_web_analysis_runtime_pin(
    capacity: CapacityV2Input,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
) -> CompactWebAnalysisRuntimePin:
    """Build the exact compact runtime Pin from verified, authority-free inputs."""

    try:
        capacity_pin = _canonical_capacity_pin(capacity)
        request = _canonical_live_request(live_request)
        lineage = _canonical_lineage_transport(lineage_transport_pin)
        _require_capacity_request_lineage(capacity_pin, request, lineage)
        return CompactWebAnalysisRuntimePin(
            capacityPinDigest=capacity_pin.pin_digest,
            capacityMaterializationPolicyDigest=(capacity_pin.model_materialization_policy_digest),
            capacityTransportPinDigest=capacity_pin.transport_pin_digest,
            capacityCompactProjectionDigest=capacity_pin.compact_projection_digest,
            capacityChatRequestDigest=capacity_pin.chat_request_digest,
            liveRequestDigest=request.request_digest,
            liveRequestCompactProjectionDigest=request.compact_projection_digest,
            liveRequestChatRequestDigest=request.chat_request_digest,
            providerRegistrationDigest=request.provider_registration_digest,
            skillRunId=request.skill_run_id,
            skillRunRootDigest=request.skill_run_root_digest,
            skillSnapshotDigest=request.skill_snapshot_digest,
            modelId=capacity_pin.model_id,
            modelRepository=capacity_pin.model_repository,
            modelRevision=capacity_pin.model_revision,
            modelFilename=capacity_pin.model_filename,
            modelSizeBytes=capacity_pin.model_size_bytes,
            modelSha256=capacity_pin.model_sha256,
            modelPinDigest=capacity_pin.model_pin_digest,
            modelImage=capacity_pin.model_image,
            modelPlatform=capacity_pin.model_platform,
            modelPlatformManifest=capacity_pin.model_platform_manifest,
            lineageTransportPinDigest=lineage.pin_digest,
        )
    except CompactWebAnalysisPinError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisPinError(
            "Compact Web analysis runtime Pin construction failed closed"
        ) from exc


def verify_compact_web_analysis_runtime_pin(
    runtime_pin: CompactWebAnalysisRuntimePin,
    *,
    capacity: CapacityV2Input,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    expected_pin_digest: str,
) -> CompactWebAnalysisRuntimePin:
    """Verify one runtime Pin against exact inputs and an independent digest anchor."""

    try:
        expected_digest = _require_expected_digest(
            expected_pin_digest,
            label="expected compact runtime Pin digest",
        )
        if type(runtime_pin) is not CompactWebAnalysisRuntimePin:
            raise TypeError("Compact runtime verification rejects predecessor Pin types")
        canonical = CompactWebAnalysisRuntimePin.model_validate(
            runtime_pin.model_dump(mode="json", by_alias=True)
        )
        expected = build_compact_web_analysis_runtime_pin(
            capacity,
            live_request,
            lineage_transport_pin,
        )
        if canonical != expected:
            raise ValueError("Compact runtime Pin differs from its exact source binding")
        if canonical.pin_digest != expected_digest:
            raise ValueError("Compact runtime Pin differs from its independent anchor")
        return canonical
    except CompactWebAnalysisPinError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisPinError(
            "Compact Web analysis runtime Pin verification failed closed"
        ) from exc


def build_compact_web_analysis_transport_pin(
    runtime_pin: CompactWebAnalysisRuntimePin,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
) -> CompactWebAnalysisTransportPin:
    """Build the effective compact transport without reusing the legacy runtime Pin."""

    try:
        if type(runtime_pin) is not CompactWebAnalysisRuntimePin:
            raise TypeError("Compact transport rejects predecessor runtime Pin types")
        runtime = CompactWebAnalysisRuntimePin.model_validate(
            runtime_pin.model_dump(mode="json", by_alias=True)
        )
        lineage = _canonical_lineage_transport(lineage_transport_pin)
        if runtime.lineage_transport_pin_digest != lineage.pin_digest:
            raise ValueError("Compact runtime and predecessor transport lineage differ")
        return CompactWebAnalysisTransportPin(
            runtimePinDigest=runtime.pin_digest,
            lineageTransportPinDigest=lineage.pin_digest,
            workerWireProtocolVersion=lineage.transport_version,
            workerAction=lineage.worker_action,
            workerImage=lineage.worker_image,
            proxyImage=lineage.proxy_image,
            workerOpenTimeoutSeconds=lineage.worker_open_timeout_seconds,
            proxyExchangeTimeoutSeconds=lineage.proxy_exchange_timeout_seconds,
            jobTimeoutSeconds=lineage.job_timeout_seconds,
            singleDispatchOnly=lineage.single_dispatch_only,
        )
    except CompactWebAnalysisPinError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisPinError(
            "Compact Web analysis transport Pin construction failed closed"
        ) from exc


def verify_compact_web_analysis_transport_pin(
    transport_pin: CompactWebAnalysisTransportPin,
    *,
    runtime_pin: CompactWebAnalysisRuntimePin,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    expected_pin_digest: str,
) -> CompactWebAnalysisTransportPin:
    """Verify one effective transport Pin against exact lineage and digest anchors."""

    try:
        expected_digest = _require_expected_digest(
            expected_pin_digest,
            label="expected compact transport Pin digest",
        )
        if type(transport_pin) is not CompactWebAnalysisTransportPin:
            raise TypeError("Compact transport verification rejects predecessor Pin types")
        canonical = CompactWebAnalysisTransportPin.model_validate(
            transport_pin.model_dump(mode="json", by_alias=True)
        )
        expected = build_compact_web_analysis_transport_pin(
            runtime_pin,
            lineage_transport_pin,
        )
        if canonical != expected:
            raise ValueError("Compact transport Pin differs from its exact source binding")
        if canonical.pin_digest != expected_digest:
            raise ValueError("Compact transport Pin differs from its independent anchor")
        return canonical
    except CompactWebAnalysisPinError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisPinError(
            "Compact Web analysis transport Pin verification failed closed"
        ) from exc


def verify_compact_web_analysis_live_pin_binding(
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    *,
    capacity: CapacityV2Input,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
) -> tuple[CompactWebAnalysisRuntimePin, CompactWebAnalysisTransportPin]:
    """Verify the complete Capacity/request/runtime/effective-transport binding."""

    runtime = verify_compact_web_analysis_runtime_pin(
        runtime_pin,
        capacity=capacity,
        live_request=live_request,
        lineage_transport_pin=lineage_transport_pin,
        expected_pin_digest=expected_runtime_pin_digest,
    )
    transport = verify_compact_web_analysis_transport_pin(
        transport_pin,
        runtime_pin=runtime,
        lineage_transport_pin=lineage_transport_pin,
        expected_pin_digest=expected_transport_pin_digest,
    )
    if transport.runtime_pin_digest != runtime.pin_digest:
        raise CompactWebAnalysisPinError(
            "Compact runtime and effective transport Pin digests differ"
        )
    return runtime, transport


def load_verified_compact_web_analysis_runtime_pin(
    path: Path,
    *,
    capacity: CapacityV2Input,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    expected_pin_digest: str,
) -> CompactWebAnalysisRuntimePin:
    """Strict-load one bounded runtime Pin with a separately retained digest."""

    try:
        decoded = load_bounded_strict_json(
            path,
            max_bytes=_MAX_PIN_BYTES,
            label="compact Web analysis runtime Pin artifact",
            require_single_link=True,
        )
        if type(decoded) is not dict:
            raise TypeError("Compact Web analysis runtime Pin artifact must be an object")
        raw_wire = canonical_json_bytes(
            decoded,
            label="compact Web analysis runtime Pin wire",
            max_bytes=_MAX_PIN_BYTES,
        )
        pin = CompactWebAnalysisRuntimePin.model_validate(decoded)
        canonical_wire = canonical_json_bytes(
            pin.model_dump(mode="json", by_alias=True),
            label="canonical compact Web analysis runtime Pin wire",
            max_bytes=_MAX_PIN_BYTES,
        )
        if raw_wire != canonical_wire:
            raise ValueError("Compact Web analysis runtime Pin wire is not exact")
        return verify_compact_web_analysis_runtime_pin(
            pin,
            capacity=capacity,
            live_request=live_request,
            lineage_transport_pin=lineage_transport_pin,
            expected_pin_digest=expected_pin_digest,
        )
    except CompactWebAnalysisPinError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisPinError(
            "Compact Web analysis runtime Pin artifact loading failed closed"
        ) from exc


def load_verified_compact_web_analysis_transport_pin(
    path: Path,
    *,
    runtime_pin: CompactWebAnalysisRuntimePin,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    expected_pin_digest: str,
) -> CompactWebAnalysisTransportPin:
    """Strict-load one bounded transport Pin with a separately retained digest."""

    try:
        decoded = load_bounded_strict_json(
            path,
            max_bytes=_MAX_PIN_BYTES,
            label="compact Web analysis transport Pin artifact",
            require_single_link=True,
        )
        if type(decoded) is not dict:
            raise TypeError("Compact Web analysis transport Pin artifact must be an object")
        raw_wire = canonical_json_bytes(
            decoded,
            label="compact Web analysis transport Pin wire",
            max_bytes=_MAX_PIN_BYTES,
        )
        pin = CompactWebAnalysisTransportPin.model_validate(decoded)
        canonical_wire = canonical_json_bytes(
            pin.model_dump(mode="json", by_alias=True),
            label="canonical compact Web analysis transport Pin wire",
            max_bytes=_MAX_PIN_BYTES,
        )
        if raw_wire != canonical_wire:
            raise ValueError("Compact Web analysis transport Pin wire is not exact")
        return verify_compact_web_analysis_transport_pin(
            pin,
            runtime_pin=runtime_pin,
            lineage_transport_pin=lineage_transport_pin,
            expected_pin_digest=expected_pin_digest,
        )
    except CompactWebAnalysisPinError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisPinError(
            "Compact Web analysis transport Pin artifact loading failed closed"
        ) from exc


__all__ = [
    "COMPACT_WEB_ANALYSIS_RUNTIME_PIN_API_VERSION",
    "COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_API_VERSION",
    "COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_VERSION",
    "COMPACT_WEB_ANALYSIS_WORKER_WIRE_PROTOCOL_VERSION",
    "CompactWebAnalysisPinError",
    "CompactWebAnalysisRuntimePin",
    "CompactWebAnalysisTransportPin",
    "build_compact_web_analysis_runtime_pin",
    "build_compact_web_analysis_transport_pin",
    "load_verified_compact_web_analysis_runtime_pin",
    "load_verified_compact_web_analysis_transport_pin",
    "verify_compact_web_analysis_live_pin_binding",
    "verify_compact_web_analysis_runtime_pin",
    "verify_compact_web_analysis_transport_pin",
]
