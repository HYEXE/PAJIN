"""Versioned Provider transport pin for Skill-bound WEB analysis."""

from __future__ import annotations

import json
import re
import subprocess
from contextlib import suppress
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from typing import Annotated, Literal, Self, cast
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, JsonValue, field_validator, model_validator

from pajin.benchmark.effectiveness.runtime import LocalEvaluationTool
from pajin.benchmark.effectiveness.suite import RuntimePin
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel, ToolRequest
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderRegistration
from pajin.runtime.safe_files import load_bounded_strict_json, parse_strict_json_bytes
from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.execution_receipts import safe_job_metadata
from pajin.web_assessment.analysis_skill_projection import canonical_skill_contract

WEB_ANALYSIS_TRANSPORT_RUNTIME_PIN_API_VERSION: Literal[
    "pajin.dev/web-analysis-transport-runtime-pin/v1alpha1"
] = "pajin.dev/web-analysis-transport-runtime-pin/v1alpha1"
WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION: Literal["pajin.web-analysis.provider-transport/v2"] = (
    "pajin.web-analysis.provider-transport/v2"
)
WEB_ANALYSIS_PINNED_PROVIDER_ACTION: Literal["openai-chat-completion-v3"] = (
    "openai-chat-completion-v3"
)
WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS: Literal[180] = 180
WEB_ANALYSIS_TRANSPORT_CLEANUP_PROOF_API_VERSION: Literal[
    "pajin.dev/web-analysis-transport-cleanup-proof/v1alpha1"
] = "pajin.dev/web-analysis-transport-cleanup-proof/v1alpha1"
WEB_ANALYSIS_PRE_CLEANUP_BARRIER_API_VERSION: Literal[
    "pajin.dev/web-analysis-live-claim-pre-cleanup-barrier/v1alpha1"
] = "pajin.dev/web-analysis-live-claim-pre-cleanup-barrier/v1alpha1"

_MAX_TRANSPORT_PIN_BYTES = 64 * 1024
_MAX_PROVIDER_PAYLOAD_BYTES = 1_000_000
_MAX_DOCKER_CLEANUP_OUTPUT_BYTES = 2 * 1024 * 1024
_DOCKER_CLEANUP_TIMEOUT_SECONDS = 20
_ImageID = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_DockerID = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_EXECUTION_ID_PATTERN = re.compile(r"^exec_[a-f0-9]{32}$")
_LEASE_ID_PATTERN = re.compile(r"^lease_[a-f0-9]{32}$")
_SAFE_RUNTIME_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_LIVE_NETWORK_PATTERN = re.compile(r"^pajin-web-analysis-live-network-[a-f0-9]{32}$")
_WORKER_CONTAINER_PATTERN = re.compile(r"^pajin-exec_[a-f0-9]{32}-[a-f0-9]{32}$")
_PROXY_CONTAINER_PATTERN = re.compile(r"^pajin-proxy-[a-f0-9]{32}$")
_EGRESS_NETWORK_PATTERN = re.compile(r"^pajin-egress-[a-f0-9]{32}$")
_DOCKER_WORKER_TYPE = "pajin.runtime.worker.DockerWorkerBackend"
_EXECUTION_LABEL = "pajin.execution-id"
_PRE_CLEANUP_BARRIER_EXECUTION_MODE = "posix-main-thread-real-timer"
_PRE_CLEANUP_BARRIER_TIMEOUT_SECONDS = 30.0


class WebAnalysisTransportError(ValueError):
    """Raised when the successor Provider transport differs from its immutable pin."""


class WebAnalysisTransportPreCleanupBarrierContext(StrictModel):
    """Code-owned identity for the durable callback that precedes Docker cleanup."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )

    api_version: Literal["pajin.dev/web-analysis-live-claim-pre-cleanup-barrier/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["WebAnalysisLiveClaimPreCleanupBarrier"]
    claim_digest: _Sha256 = Field(alias="claimDigest")
    execution_id: str = Field(
        alias="executionId",
        pattern=r"^exec_[a-f0-9]{32}$",
    )
    pending_cleanup_required: Literal[True] = Field(alias="pendingCleanupRequired")

    @field_validator("pending_cleanup_required", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> Literal[True]:
        if type(value) is not bool or value is not True:
            raise ValueError("Web analysis transport cleanup barrier marker must be literal true")
        return True


class WebAnalysisTransportOwnedResource(StrictModel):
    """One exact Docker resource observed under the transport execution label."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )

    resource_kind: Literal["worker-container", "proxy-container", "egress-network"] = Field(
        alias="resourceKind"
    )
    resource_id: _DockerID = Field(alias="resourceId")
    resource_name: str = Field(alias="resourceName", min_length=1, max_length=100)
    execution_id: str = Field(alias="executionId", pattern=r"^exec_[a-f0-9]{32}$")
    image_id: _ImageID | None = Field(default=None, alias="imageId")

    @model_validator(mode="after")
    def require_exact_resource_shape(self) -> Self:
        if self.resource_kind == "worker-container":
            valid = _WORKER_CONTAINER_PATTERN.fullmatch(self.resource_name) is not None
            image_required = True
        elif self.resource_kind == "proxy-container":
            valid = _PROXY_CONTAINER_PATTERN.fullmatch(self.resource_name) is not None
            image_required = True
        else:
            valid = _EGRESS_NETWORK_PATTERN.fullmatch(self.resource_name) is not None
            image_required = False
        if not valid or (self.image_id is not None) is not image_required:
            raise ValueError("Web analysis transport owned resource shape differs")
        return self


class WebAnalysisTransportCleanupProof(StrictModel):
    """Immutable owner-checked cleanup and independent absence proof."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )

    api_version: Literal["pajin.dev/web-analysis-transport-cleanup-proof/v1alpha1"] = Field(
        default=WEB_ANALYSIS_TRANSPORT_CLEANUP_PROOF_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebAnalysisTransportCleanupProof"] = "WebAnalysisTransportCleanupProof"
    cleanup_digest: str = Field(default="", alias="cleanupDigest", max_length=64)
    resource_absence_digest: str = Field(default="", alias="resourceAbsenceDigest", max_length=64)
    execution_id: str = Field(alias="executionId", pattern=r"^exec_[a-f0-9]{32}$")
    transport_pin_digest: _Sha256 = Field(alias="transportPinDigest")
    external_network: str = Field(alias="externalNetwork", min_length=1, max_length=100)
    observed_resources: tuple[WebAnalysisTransportOwnedResource, ...] = Field(
        default=(), alias="observedResources", max_length=3
    )
    cleanup_attempted: Literal[True] = Field(default=True, alias="cleanupAttempted")
    owned_resources_removed: Literal[True] = Field(default=True, alias="ownedResourcesRemoved")
    absence_verified: Literal[True] = Field(default=True, alias="absenceVerified")
    provider_dispatch_authority: Literal[False] = Field(
        default=False, alias="providerDispatchAuthority"
    )
    target_request_authority: Literal[False] = Field(default=False, alias="targetRequestAuthority")
    automatic_redispatch_authority: Literal[False] = Field(
        default=False, alias="automaticRedispatchAuthority"
    )

    @model_validator(mode="after")
    def bind_cleanup(self) -> Self:
        _require_claim_transport_coordinate(
            execution_id=self.execution_id,
            external_network=self.external_network,
        )
        resources = self.observed_resources
        if (
            tuple(sorted(resources, key=lambda item: (item.resource_kind, item.resource_name)))
            != resources
            or len({(item.resource_kind, item.resource_id) for item in resources}) != len(resources)
            or any(item.execution_id != self.execution_id for item in resources)
            or sum(item.resource_kind == "worker-container" for item in resources) > 1
            or sum(item.resource_kind == "proxy-container" for item in resources) > 1
            or sum(item.resource_kind == "egress-network" for item in resources) > 1
        ):
            raise ValueError("Web analysis transport cleanup resources differ")
        absence_digest = _transport_cleanup_digest(
            "pajin.web-analysis.transport-resource-absence/v1",
            {
                "executionId": self.execution_id,
                "transportPinDigest": self.transport_pin_digest,
                "externalNetwork": self.external_network,
                "workerContainerAbsent": True,
                "proxyContainerAbsent": True,
                "egressNetworkAbsent": True,
            },
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"cleanup_digest", "resource_absence_digest"},
        )
        cleanup_digest = _transport_cleanup_digest(
            "pajin.web-analysis.transport-cleanup/v1",
            {**material, "resourceAbsenceDigest": absence_digest},
        )
        if self.resource_absence_digest and self.resource_absence_digest != absence_digest:
            raise ValueError("Web analysis transport resource absence digest differs")
        if self.cleanup_digest and self.cleanup_digest != cleanup_digest:
            raise ValueError("Web analysis transport cleanup digest differs")
        object.__setattr__(self, "resource_absence_digest", absence_digest)
        object.__setattr__(self, "cleanup_digest", cleanup_digest)
        return self


class WebAnalysisTransportRuntimePin(StrictModel):
    """Exact Worker/proxy/action/time budget used by one successor invocation."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/web-analysis-transport-runtime-pin/v1alpha1"] = Field(
        default=WEB_ANALYSIS_TRANSPORT_RUNTIME_PIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAnalysisTransportRuntimePin"] = "WebAnalysisTransportRuntimePin"
    pin_digest: str = Field(default="", alias="pinDigest", max_length=64)
    transport_version: Literal["pajin.web-analysis.provider-transport/v2"] = Field(
        default=WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION,
        alias="transportVersion",
    )
    worker_action: Literal["openai-chat-completion-v3"] = Field(
        default=WEB_ANALYSIS_PINNED_PROVIDER_ACTION,
        alias="workerAction",
    )
    base_runtime_digest: _Sha256 = Field(alias="baseRuntimeDigest")
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
    external_egress_authorized: Literal[False] = Field(
        default=False,
        alias="externalEgressAuthorized",
    )

    @field_validator(
        "worker_open_timeout_seconds",
        "proxy_exchange_timeout_seconds",
        "job_timeout_seconds",
        mode="before",
    )
    @classmethod
    def require_exact_timeout(cls, value: object) -> Literal[180]:
        if type(value) is not int or value != WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS:
            raise ValueError("Web analysis transport timeout must be exact integer 180")
        return WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS

    @field_validator("single_dispatch_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> Literal[True]:
        if type(value) is not bool or value is not True:
            raise ValueError("Web analysis transport single-dispatch marker must be literal true")
        return True

    @field_validator("external_egress_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> Literal[False]:
        if type(value) is not bool or value is not False:
            raise ValueError("Web analysis transport egress marker must be literal false")
        return False

    @model_validator(mode="after")
    def bind_pin(self) -> Self:
        if self.single_dispatch_only is not True:
            raise ValueError("Web analysis transport must remain single-dispatch")
        if self.external_egress_authorized is not False:
            raise ValueError("Web analysis transport cannot authorize external egress")
        material = self.model_dump(mode="json", by_alias=True, exclude={"pin_digest"})
        digest = _transport_digest(material)
        if self.pin_digest and self.pin_digest != digest:
            raise ValueError("Web analysis transport runtime Pin digest differs")
        object.__setattr__(self, "pin_digest", digest)
        return self


def web_analysis_transport_runtime_pin(
    runtime: RuntimePin,
    *,
    worker_image: str,
    proxy_image: str,
) -> WebAnalysisTransportRuntimePin:
    """Bind new immutable transport images to an already verified model runtime."""

    try:
        canonical_skill_contract(runtime, RuntimePin)
        canonical = RuntimePin.model_validate_json(runtime.model_dump_json())
        if canonical.request_timeout_seconds != WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS:
            raise ValueError("Web analysis runtime timeout differs from the successor budget")
        _require_successor_image_ids(
            runtime=canonical,
            worker_image=worker_image,
            proxy_image=proxy_image,
        )
        return WebAnalysisTransportRuntimePin(
            baseRuntimeDigest=_runtime_digest(canonical),
            workerImage=worker_image,
            proxyImage=proxy_image,
        )
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis transport runtime Pin construction failed closed"
        ) from exc


def verify_web_analysis_transport_runtime_pin(
    transport_pin: WebAnalysisTransportRuntimePin,
    *,
    runtime: RuntimePin,
    expected_pin_digest: str,
) -> WebAnalysisTransportRuntimePin:
    """Strict-reload one transport Pin against an independently supplied base runtime."""

    try:
        if (
            type(expected_pin_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", expected_pin_digest) is None
        ):
            raise ValueError("Expected Web analysis transport Pin digest is invalid")
        canonical_skill_contract(runtime, RuntimePin)
        canonical_skill_contract(transport_pin, WebAnalysisTransportRuntimePin)
        canonical_runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        canonical_pin = WebAnalysisTransportRuntimePin.model_validate(
            transport_pin.model_dump(mode="json", by_alias=True)
        )
        if canonical_runtime.request_timeout_seconds != WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS:
            raise ValueError("Web analysis runtime timeout differs from the successor budget")
        _require_successor_image_ids(
            runtime=canonical_runtime,
            worker_image=canonical_pin.worker_image,
            proxy_image=canonical_pin.proxy_image,
        )
        if canonical_pin.base_runtime_digest != _runtime_digest(canonical_runtime):
            raise ValueError("Web analysis transport Pin differs from the verified base runtime")
        if canonical_pin.pin_digest != expected_pin_digest:
            raise ValueError("Web analysis transport Pin differs from its independent anchor")
        return canonical_pin
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis transport runtime Pin verification failed closed"
        ) from exc


def load_verified_web_analysis_transport_runtime_pin(
    path: Path,
    *,
    runtime: RuntimePin,
    expected_pin_digest: str,
) -> WebAnalysisTransportRuntimePin:
    """Load one bounded Pin artifact under a separately retained digest anchor."""

    try:
        decoded = load_bounded_strict_json(
            path,
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
            label="Web analysis transport runtime Pin artifact",
            require_single_link=True,
        )
        if type(decoded) is not dict:
            raise TypeError("Web analysis transport runtime Pin artifact must be an object")
        raw_wire = canonical_json_bytes(
            decoded,
            label="Web analysis transport runtime Pin artifact wire",
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
        )
        pin = WebAnalysisTransportRuntimePin.model_validate(decoded)
        canonical_skill_contract(pin, WebAnalysisTransportRuntimePin)
        canonical_wire = canonical_json_bytes(
            pin.model_dump(mode="json", by_alias=True),
            label="canonical Web analysis transport runtime Pin artifact",
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
        )
        if raw_wire != canonical_wire:
            raise ValueError("Web analysis transport runtime Pin wire is not exact")
        return verify_web_analysis_transport_runtime_pin(
            pin,
            runtime=runtime,
            expected_pin_digest=expected_pin_digest,
        )
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis transport runtime Pin artifact loading failed closed"
        ) from exc


def bind_web_analysis_transport_job(
    job: WorkerJob,
    *,
    runtime: RuntimePin,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
) -> WorkerJob:
    """Version one code-owned Provider job without changing its authority or target."""

    try:
        canonical_runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        canonical_pin = verify_web_analysis_transport_runtime_pin(
            transport_pin,
            runtime=canonical_runtime,
            expected_pin_digest=expected_transport_pin_digest,
        )
        canonical_skill_contract(job, WorkerJob)
        canonical_job = WorkerJob.model_validate(job.model_dump(mode="python"))
        if (
            canonical_job.command != ["openai-chat-completion"]
            or canonical_job.image != canonical_runtime.worker_image
            or canonical_job.limits.timeout_seconds != canonical_pin.job_timeout_seconds
        ):
            raise ValueError("Web analysis Provider job differs before transport binding")
        raw = parse_strict_json_bytes(
            canonical_job.stdin.encode("utf-8", errors="strict"),
            label="Web analysis Provider Worker payload",
            max_bytes=_MAX_PROVIDER_PAYLOAD_BYTES,
            max_depth=32,
            max_nodes=20_000,
        )
        if type(raw) is not dict or set(raw) != {"providerId", "request", "target"}:
            raise ValueError("Web analysis Provider Worker payload fields differ")
        payload = dict(raw)
        payload["requestTimeoutSeconds"] = canonical_pin.worker_open_timeout_seconds
        payload["transportVersion"] = canonical_pin.transport_version
        stdin = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
        rebound = WorkerJob.model_validate(
            {
                **canonical_job.model_dump(mode="python"),
                "command": [canonical_pin.worker_action],
                "image": canonical_pin.worker_image,
                "stdin": stdin,
            }
        )
        if rebound.execution_id != canonical_job.execution_id:
            raise ValueError("Web analysis transport changed the Worker execution identity")
        return rebound
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis Provider job transport binding failed closed"
        ) from exc


def prepare_web_analysis_transport_job(
    request: ToolRequest,
    *,
    registration: ProviderRegistration,
    runtime: RuntimePin,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
    execution_id: str,
) -> WorkerJob:
    """Prepare the exact one-request successor job under a caller-owned identity."""

    try:
        canonical_request = ToolRequest.model_validate(request.model_dump(mode="python"))
        canonical_registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        _require_local_successor_registration(canonical_registration)
        canonical_runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        canonical_pin = verify_web_analysis_transport_runtime_pin(
            transport_pin,
            runtime=canonical_runtime,
            expected_pin_digest=expected_transport_pin_digest,
        )
        if (
            type(execution_id) is not str
            or _EXECUTION_ID_PATTERN.fullmatch(execution_id) is None
            or canonical_request.method != "POST"
            or canonical_request.target != str(canonical_registration.endpoint)
            or canonical_request.tool_id != f"provider.{canonical_registration.provider_id}.chat"
        ):
            raise ValueError("Web analysis successor request or execution identity differs")
        ProviderChatRequest.model_validate(canonical_request.arguments)
        prepared = LocalEvaluationTool(canonical_registration, canonical_runtime).prepare(
            canonical_request
        )
        prepared = WorkerJob.model_validate(
            prepared.model_copy(update={"execution_id": execution_id}).model_dump(mode="python")
        )
        rebound = bind_web_analysis_transport_job(
            prepared,
            runtime=canonical_runtime,
            transport_pin=canonical_pin,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        scoped = WorkerJob.model_validate(
            rebound.model_copy(
                update={
                    "network": NetworkMode.EGRESS_PROXY,
                    "egress_policy": EgressPolicy(
                        allow=[str(canonical_registration.endpoint)],
                        deny=[],
                        allowed_methods={"POST"},
                        allow_private_networks=True,
                        max_response_bytes=EgressPolicy.model_fields["max_response_bytes"].default,
                        max_requests=1,
                        max_request_bytes=rebound.request_byte_limit_override,
                    ),
                },
                deep=True,
            ).model_dump(mode="python")
        )
        if scoped.execution_id != execution_id:
            raise ValueError("Web analysis successor job changed its execution identity")
        return scoped
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis successor Worker job preparation failed closed"
        ) from exc


def interpret_web_analysis_transport_result(
    request: ToolRequest,
    result: WorkerResult,
    *,
    registration: ProviderRegistration,
    runtime: RuntimePin,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
    expected_execution_id: str,
) -> ProviderChatResult:
    """Interpret one exact Worker result without granting retry or target authority."""

    try:
        canonical_request = ToolRequest.model_validate(request.model_dump(mode="python"))
        canonical_registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        canonical_runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        canonical_result = WorkerResult.model_validate(result.model_dump(mode="python"))
        expected_job = prepare_web_analysis_transport_job(
            canonical_request,
            registration=canonical_registration,
            runtime=canonical_runtime,
            transport_pin=transport_pin,
            expected_transport_pin_digest=expected_transport_pin_digest,
            execution_id=expected_execution_id,
        )
        if (
            canonical_result != result
            or canonical_result.execution_id != expected_job.execution_id
            or canonical_result.backend != "docker"
            or canonical_result.status is not WorkerStatus.SUCCEEDED
            or canonical_result.exit_code != 0
            or canonical_result.stdout_truncated
            or canonical_result.stderr_truncated
        ):
            raise ValueError("Web analysis successor Worker result differs")
        interpreted = LocalEvaluationTool(canonical_registration, canonical_runtime).interpret(
            canonical_request,
            canonical_result,
        )
        if not interpreted.success or interpreted.data is None or interpreted.error is not None:
            raise ValueError("Web analysis successor Provider result was rejected")
        provider_result = ProviderChatResult.model_validate(interpreted.data)
        if (
            provider_result.provider_id != canonical_registration.provider_id
            or provider_result.model != canonical_registration.model
            or provider_result.target != canonical_request.target
            or provider_result.streamed
            or provider_result.chunks != 1
        ):
            raise ValueError("Web analysis successor Provider result differs")
        return provider_result
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis successor Worker result interpretation failed closed"
        ) from exc


def expected_web_analysis_transport_job_metadata(
    request: ToolRequest,
    *,
    registration: ProviderRegistration,
    runtime: RuntimePin,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
    execution_id: str,
    lease_ids: list[str],
) -> dict[str, object]:
    """Reconstruct the exact successor Worker job metadata from trusted inputs."""

    try:
        canonical_request = ToolRequest.model_validate(request.model_dump(mode="python"))
        canonical_registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        _require_local_successor_registration(canonical_registration)
        canonical_runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        if (
            type(lease_ids) is not list
            or len(lease_ids) > 1
            or any(
                type(lease_id) is not str or _LEASE_ID_PATTERN.fullmatch(lease_id) is None
                for lease_id in lease_ids
            )
        ):
            raise ValueError("Web analysis successor lease identity differs")
        scoped = prepare_web_analysis_transport_job(
            canonical_request,
            registration=canonical_registration,
            runtime=canonical_runtime,
            transport_pin=transport_pin,
            expected_transport_pin_digest=expected_transport_pin_digest,
            execution_id=execution_id,
        )
        return safe_job_metadata(canonical_request, scoped, lease_ids=list(lease_ids))
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis successor Worker metadata reconstruction failed closed"
        ) from exc


def expected_web_analysis_legacy_job_metadata(
    request: ToolRequest,
    *,
    registration: ProviderRegistration,
    runtime: RuntimePin,
    execution_id: str,
    lease_ids: list[str],
) -> dict[str, object]:
    """Reconstruct the exact pre-successor local Provider Worker metadata."""

    try:
        canonical_request = ToolRequest.model_validate(request.model_dump(mode="python"))
        canonical_registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        canonical_runtime = RuntimePin.model_validate_json(runtime.model_dump_json())
        _require_local_successor_registration(canonical_registration)
        if (
            type(execution_id) is not str
            or _EXECUTION_ID_PATTERN.fullmatch(execution_id) is None
            or type(lease_ids) is not list
            or len(lease_ids) > 1
            or any(
                type(lease_id) is not str or _LEASE_ID_PATTERN.fullmatch(lease_id) is None
                for lease_id in lease_ids
            )
            or canonical_request.method != "POST"
            or canonical_request.target != str(canonical_registration.endpoint)
            or canonical_request.tool_id != f"provider.{canonical_registration.provider_id}.chat"
        ):
            raise ValueError("Web analysis legacy request or execution identity differs")
        ProviderChatRequest.model_validate(canonical_request.arguments)
        prepared = LocalEvaluationTool(canonical_registration, canonical_runtime).prepare(
            canonical_request
        )
        prepared = WorkerJob.model_validate(
            prepared.model_copy(update={"execution_id": execution_id}).model_dump(mode="python")
        )
        scoped = WorkerJob.model_validate(
            prepared.model_copy(
                update={
                    "network": NetworkMode.EGRESS_PROXY,
                    "egress_policy": EgressPolicy(
                        allow=[str(canonical_registration.endpoint)],
                        deny=[],
                        allowed_methods={"POST"},
                        allow_private_networks=True,
                        max_response_bytes=EgressPolicy.model_fields["max_response_bytes"].default,
                        max_requests=1,
                        max_request_bytes=prepared.request_byte_limit_override,
                    ),
                },
                deep=True,
            ).model_dump(mode="python")
        )
        return safe_job_metadata(canonical_request, scoped, lease_ids=list(lease_ids))
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis legacy Worker metadata reconstruction failed closed"
        ) from exc


def verify_web_analysis_legacy_job_metadata(
    metadata: object,
    request: ToolRequest,
    *,
    registration: ProviderRegistration,
    runtime: RuntimePin,
    execution_id: str,
    lease_ids: list[str],
) -> dict[str, object]:
    """Require observed legacy Worker metadata to equal its trusted reconstruction."""

    try:
        if type(metadata) is not dict:
            raise TypeError("Web analysis legacy Worker metadata must be a JSON object")
        encoded = canonical_json_bytes(
            metadata,
            label="Web analysis legacy Worker metadata",
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
        )
        expected = expected_web_analysis_legacy_job_metadata(
            request,
            registration=registration,
            runtime=runtime,
            execution_id=execution_id,
            lease_ids=lease_ids,
        )
        expected_encoded = canonical_json_bytes(
            expected,
            label="expected Web analysis legacy Worker metadata",
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
        )
        canonical = json.loads(encoded)
        canonical_expected = json.loads(expected_encoded)
        observed_stdin_digest = canonical.pop("stdinSha256", None)
        canonical_expected.pop("stdinSha256", None)
        if (
            type(observed_stdin_digest) is not str
            or re.fullmatch(r"[a-f0-9]{64}", observed_stdin_digest) is None
            or canonical_json_bytes(
                canonical,
                label="Web analysis legacy replayable Worker metadata",
                max_bytes=_MAX_TRANSPORT_PIN_BYTES,
            )
            != canonical_json_bytes(
                canonical_expected,
                label="expected Web analysis legacy replayable Worker metadata",
                max_bytes=_MAX_TRANSPORT_PIN_BYTES,
            )
        ):
            raise ValueError("Web analysis legacy Worker metadata differs")
        return expected
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis legacy Worker metadata verification failed closed"
        ) from exc


def verify_web_analysis_transport_job_metadata(
    metadata: object,
    request: ToolRequest,
    *,
    registration: ProviderRegistration,
    runtime: RuntimePin,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
    execution_id: str,
    lease_ids: list[str],
) -> dict[str, object]:
    """Require observed Worker metadata to equal the trusted successor reconstruction."""

    try:
        if type(metadata) is not dict:
            raise TypeError("Web analysis successor Worker metadata must be a JSON object")
        encoded = canonical_json_bytes(
            metadata,
            label="Web analysis successor Worker metadata",
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
        )
        expected = expected_web_analysis_transport_job_metadata(
            request,
            registration=registration,
            runtime=runtime,
            transport_pin=transport_pin,
            expected_transport_pin_digest=expected_transport_pin_digest,
            execution_id=execution_id,
            lease_ids=lease_ids,
        )
        expected_encoded = canonical_json_bytes(
            expected,
            label="expected Web analysis successor Worker metadata",
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
        )
        if encoded != expected_encoded:
            raise ValueError("Web analysis successor Worker metadata differs")
        return expected
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis successor Worker metadata verification failed closed"
        ) from exc


def web_analysis_transport_pre_cleanup_barrier_context(
    *,
    claim_digest: str,
    execution_id: str,
) -> dict[str, JsonValue]:
    """Build the exact secret-free identity exposed by the Gate D barrier."""

    try:
        context = WebAnalysisTransportPreCleanupBarrierContext(
            apiVersion=WEB_ANALYSIS_PRE_CLEANUP_BARRIER_API_VERSION,
            kind="WebAnalysisLiveClaimPreCleanupBarrier",
            claimDigest=claim_digest,
            executionId=execution_id,
            pendingCleanupRequired=True,
        )
        return cast(
            dict[str, JsonValue],
            context.model_dump(mode="json", by_alias=True),
        )
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis transport cleanup barrier context construction failed closed"
        ) from exc


def expected_web_analysis_provider_worker_context(
    transport_pin: WebAnalysisTransportRuntimePin,
    *,
    external_network: str,
    claim_digest: str | None = None,
    execution_id: str | None = None,
) -> dict[str, JsonValue]:
    """Build the exact Docker backend context required by the successor transport."""

    try:
        canonical_skill_contract(transport_pin, WebAnalysisTransportRuntimePin)
        canonical_pin = WebAnalysisTransportRuntimePin.model_validate(
            transport_pin.model_dump(mode="json", by_alias=True)
        )
        if (
            type(external_network) is not str
            or _SAFE_RUNTIME_IDENTIFIER_PATTERN.fullmatch(external_network) is None
        ):
            raise ValueError("Web analysis successor Docker network is not a safe identifier")
        context: dict[str, JsonValue] = {
            "implementationVersion": "pajin.docker-worker/v2",
            "allowedImages": [canonical_pin.worker_image],
            "dockerExecutable": "docker",
            "egressProxyImage": canonical_pin.proxy_image,
            "externalNetwork": external_network,
            "externalNetworkRoutes": {
                canonical_pin.worker_action: external_network,
            },
        }
        if (claim_digest is None) != (execution_id is None):
            raise ValueError("Web analysis successor cleanup barrier anchors are incomplete")
        if claim_digest is not None and execution_id is not None:
            _require_claim_transport_coordinate(
                execution_id=execution_id,
                external_network=external_network,
            )
            context["implementationVersion"] = "pajin.docker-worker/v6"
            context["preCleanupBarrier"] = web_analysis_transport_pre_cleanup_barrier_context(
                claim_digest=claim_digest,
                execution_id=execution_id,
            )
            context["preCleanupBarrierExecution"] = {
                "mode": _PRE_CLEANUP_BARRIER_EXECUTION_MODE,
                "timeoutSeconds": _PRE_CLEANUP_BARRIER_TIMEOUT_SECONDS,
            }
        return {
            "type": _DOCKER_WORKER_TYPE,
            "context": context,
        }
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis successor Worker context construction failed closed"
        ) from exc


def verify_web_analysis_provider_worker_context(
    worker_context: object,
    *,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_external_network: str | None = None,
    expected_claim_digest: str | None = None,
    expected_execution_id: str | None = None,
) -> dict[str, JsonValue]:
    """Strictly verify the actual Docker backend context bound to a successor Tool."""

    try:
        if type(worker_context) is not dict:
            raise TypeError("Web analysis successor Worker context must be a JSON object")
        raw = cast(dict[object, object], worker_context)
        if set(raw) != {"type", "context"} or raw.get("type") != _DOCKER_WORKER_TYPE:
            raise ValueError("Web analysis successor Worker implementation differs")
        nested = raw.get("context")
        if type(nested) is not dict:
            raise TypeError("Web analysis successor Worker stable context differs")
        nested_mapping = cast(dict[object, object], nested)
        expected_fields = {
            "implementationVersion",
            "allowedImages",
            "dockerExecutable",
            "egressProxyImage",
            "externalNetwork",
            "externalNetworkRoutes",
        }
        if (expected_claim_digest is None) != (expected_execution_id is None):
            raise ValueError("Web analysis successor cleanup barrier anchors are incomplete")
        if expected_claim_digest is not None:
            expected_fields.update({"preCleanupBarrier", "preCleanupBarrierExecution"})
        if set(nested_mapping) != expected_fields:
            raise ValueError("Web analysis successor Worker context fields differ")
        external_network = nested_mapping.get("externalNetwork")
        if (
            type(external_network) is not str
            or _SAFE_RUNTIME_IDENTIFIER_PATTERN.fullmatch(external_network) is None
            or (
                expected_external_network is not None
                and external_network != expected_external_network
            )
        ):
            raise ValueError("Web analysis successor Worker network differs")
        expected = expected_web_analysis_provider_worker_context(
            transport_pin,
            external_network=external_network,
            claim_digest=expected_claim_digest,
            execution_id=expected_execution_id,
        )
        encoded = canonical_json_bytes(
            raw,
            label="Web analysis successor Worker context",
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
        )
        canonical = json.loads(encoded)
        expected_encoded = canonical_json_bytes(
            expected,
            label="expected Web analysis successor Worker context",
            max_bytes=_MAX_TRANSPORT_PIN_BYTES,
        )
        if encoded != expected_encoded:
            raise ValueError("Web analysis successor Worker context differs from its Pin")
        return cast(dict[str, JsonValue], canonical)
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis successor Worker context verification failed closed"
        ) from exc


def cleanup_web_analysis_transport_resources(
    *,
    execution_id: str,
    external_network: str,
    runtime: RuntimePin,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
    docker_executable: str = "docker",
) -> WebAnalysisTransportCleanupProof:
    """Remove only exact execution-labelled transport resources and prove absence.

    The operation is deliberately idempotent so the same API can service normal
    cleanup and a quiescent crash-recovery pass.  It never removes the supplied
    external model network.
    """

    try:
        if (
            type(execution_id) is not str
            or type(external_network) is not str
            or type(docker_executable) is not str
            or not docker_executable
            or "\x00" in docker_executable
        ):
            raise ValueError("Web analysis transport cleanup coordinate differs")
        _require_claim_transport_coordinate(
            execution_id=execution_id,
            external_network=external_network,
        )
        canonical_pin = verify_web_analysis_transport_runtime_pin(
            transport_pin,
            runtime=runtime,
            expected_pin_digest=expected_transport_pin_digest,
        )
        container_ids = _listed_cleanup_resource_ids(
            docker_executable,
            resource_kind="container",
            execution_id=execution_id,
        )
        network_ids = _listed_cleanup_resource_ids(
            docker_executable,
            resource_kind="network",
            execution_id=execution_id,
        )
        containers: list[tuple[WebAnalysisTransportOwnedResource, frozenset[str]]] = []
        for container_id in container_ids:
            containers.append(
                _inspect_owned_transport_container(
                    docker_executable,
                    container_id=container_id,
                    execution_id=execution_id,
                    external_network=external_network,
                    transport_pin=canonical_pin,
                )
            )
        networks: list[tuple[WebAnalysisTransportOwnedResource, frozenset[str]]] = []
        for network_id in network_ids:
            networks.append(
                _inspect_owned_transport_network(
                    docker_executable,
                    network_id=network_id,
                    execution_id=execution_id,
                )
            )
        _verify_cleanup_inventory(
            containers=containers,
            networks=networks,
            external_network=external_network,
        )
        resources = tuple(
            sorted(
                [item[0] for item in containers] + [item[0] for item in networks],
                key=lambda item: (item.resource_kind, item.resource_name),
            )
        )
        ordered_containers = sorted(
            containers,
            key=lambda item: 0 if item[0].resource_kind == "worker-container" else 1,
        )
        for resource, attached_networks in ordered_containers:
            current = _inspect_owned_transport_container(
                docker_executable,
                container_id=resource.resource_id,
                execution_id=execution_id,
                external_network=external_network,
                transport_pin=canonical_pin,
            )
            if current != (resource, attached_networks):
                raise ValueError("Web analysis transport container changed before cleanup")
            _remove_transport_resource(
                docker_executable,
                resource_kind="container",
                resource_id=resource.resource_id,
            )
        for resource, _attached_containers in networks:
            current_resource, current_members = _inspect_owned_transport_network(
                docker_executable,
                network_id=resource.resource_id,
                execution_id=execution_id,
            )
            if current_resource != resource or current_members:
                raise ValueError("Web analysis transport network changed before cleanup")
            _remove_transport_resource(
                docker_executable,
                resource_kind="network",
                resource_id=resource.resource_id,
            )
        _verify_transport_resources_absent(
            docker_executable,
            execution_id=execution_id,
            observed_resources=resources,
        )
        return WebAnalysisTransportCleanupProof(
            executionId=execution_id,
            transportPinDigest=canonical_pin.pin_digest,
            externalNetwork=external_network,
            observedResources=resources,
        )
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError("Web analysis transport cleanup failed closed") from exc


def verify_web_analysis_transport_cleanup_proof(
    proof: WebAnalysisTransportCleanupProof,
    *,
    execution_id: str,
    external_network: str,
    runtime: RuntimePin,
    transport_pin: WebAnalysisTransportRuntimePin,
    expected_transport_pin_digest: str,
) -> WebAnalysisTransportCleanupProof:
    """Strictly reload immutable cleanup evidence under independent anchors."""

    try:
        canonical_pin = verify_web_analysis_transport_runtime_pin(
            transport_pin,
            runtime=runtime,
            expected_pin_digest=expected_transport_pin_digest,
        )
        if type(proof) is not WebAnalysisTransportCleanupProof:
            raise TypeError("Web analysis transport cleanup proof type differs")
        canonical = WebAnalysisTransportCleanupProof.model_validate(
            proof.model_dump(mode="python", by_alias=True)
        )
        if (
            canonical != proof
            or canonical.execution_id != execution_id
            or canonical.external_network != external_network
            or canonical.transport_pin_digest != canonical_pin.pin_digest
        ):
            raise ValueError("Web analysis transport cleanup proof differs")
        return canonical
    except WebAnalysisTransportError:
        raise
    except Exception as exc:
        raise WebAnalysisTransportError(
            "Web analysis transport cleanup proof verification failed closed"
        ) from exc


def _listed_cleanup_resource_ids(
    docker_executable: str,
    *,
    resource_kind: Literal["container", "network"],
    execution_id: str,
) -> tuple[str, ...]:
    noun = "container" if resource_kind == "container" else "network"
    arguments = (
        docker_executable,
        noun,
        "ls",
        *(("--all",) if resource_kind == "container" else ()),
        "--quiet",
        "--no-trunc",
        "--filter",
        f"label={_EXECUTION_LABEL}={execution_id}",
    )
    result = _run_transport_cleanup_command(arguments)
    if result.returncode != 0:
        raise ValueError(f"Docker {noun} ownership inventory failed")
    try:
        decoded = result.stdout.decode("ascii", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Docker {noun} ownership inventory is invalid") from exc
    identities = tuple(sorted(line.strip() for line in decoded.splitlines() if line.strip()))
    if (
        len(identities) != len(set(identities))
        or any(re.fullmatch(r"[a-f0-9]{64}", identity) is None for identity in identities)
        or (resource_kind == "container" and len(identities) > 2)
        or (resource_kind == "network" and len(identities) > 1)
    ):
        raise ValueError(f"Docker {noun} ownership inventory differs")
    return identities


def _inspect_owned_transport_container(
    docker_executable: str,
    *,
    container_id: str,
    execution_id: str,
    external_network: str,
    transport_pin: WebAnalysisTransportRuntimePin,
) -> tuple[WebAnalysisTransportOwnedResource, frozenset[str]]:
    inspection = _inspect_transport_resource(
        docker_executable,
        resource_kind="container",
        resource_id=container_id,
    )
    config = inspection.get("Config")
    network_settings = inspection.get("NetworkSettings")
    if type(config) is not dict or type(network_settings) is not dict:
        raise ValueError("Web analysis transport container inspection is incomplete")
    config_values = cast(dict[str, object], config)
    network_values = cast(dict[str, object], network_settings)
    labels = config_values.get("Labels")
    networks = network_values.get("Networks")
    raw_name = inspection.get("Name")
    if (
        type(raw_name) is not str
        or not raw_name.startswith("/")
        or type(labels) is not dict
        or type(networks) is not dict
        or inspection.get("Id") != container_id
    ):
        raise ValueError("Web analysis transport container identity differs")
    name = raw_name[1:]
    label_values = cast(dict[str, object], labels)
    _require_exact_execution_label(label_values, execution_id=execution_id)
    attached_networks = frozenset(cast(dict[str, object], networks))
    worker_prefix = f"pajin-{execution_id}-"
    if name.startswith(worker_prefix):
        resource_kind: Literal["worker-container", "proxy-container"] = "worker-container"
        expected_image = transport_pin.worker_image
        if (
            _WORKER_CONTAINER_PATTERN.fullmatch(name) is None
            or len(attached_networks) != 1
            or any(_EGRESS_NETWORK_PATTERN.fullmatch(item) is None for item in attached_networks)
        ):
            raise ValueError("Web analysis transport Worker ownership differs")
    elif _PROXY_CONTAINER_PATTERN.fullmatch(name) is not None:
        resource_kind = "proxy-container"
        expected_image = transport_pin.proxy_image
        if (
            external_network not in attached_networks
            or len(attached_networks) not in {1, 2}
            or any(
                item != external_network and _EGRESS_NETWORK_PATTERN.fullmatch(item) is None
                for item in attached_networks
            )
        ):
            raise ValueError("Web analysis transport proxy ownership differs")
    else:
        raise ValueError("Web analysis transport container name differs")
    if inspection.get("Image") != expected_image or config_values.get("Image") != expected_image:
        raise ValueError("Web analysis transport container image differs")
    return (
        WebAnalysisTransportOwnedResource(
            resourceKind=resource_kind,
            resourceId=container_id,
            resourceName=name,
            executionId=execution_id,
            imageId=expected_image,
        ),
        attached_networks,
    )


def _inspect_owned_transport_network(
    docker_executable: str,
    *,
    network_id: str,
    execution_id: str,
) -> tuple[WebAnalysisTransportOwnedResource, frozenset[str]]:
    inspection = _inspect_transport_resource(
        docker_executable,
        resource_kind="network",
        resource_id=network_id,
    )
    labels = inspection.get("Labels")
    containers = inspection.get("Containers")
    name = inspection.get("Name")
    if (
        inspection.get("Id") != network_id
        or type(name) is not str
        or _EGRESS_NETWORK_PATTERN.fullmatch(name) is None
        or inspection.get("Driver") != "bridge"
        or inspection.get("Internal") is not True
        or type(labels) is not dict
        or type(containers) is not dict
    ):
        raise ValueError("Web analysis transport egress network ownership differs")
    _require_exact_execution_label(cast(dict[str, object], labels), execution_id=execution_id)
    attached = frozenset(cast(dict[str, object], containers))
    if any(re.fullmatch(r"[a-f0-9]{64}", item) is None for item in attached):
        raise ValueError("Web analysis transport egress network members differ")
    return (
        WebAnalysisTransportOwnedResource(
            resourceKind="egress-network",
            resourceId=network_id,
            resourceName=name,
            executionId=execution_id,
            imageId=None,
        ),
        attached,
    )


def _verify_cleanup_inventory(
    *,
    containers: list[tuple[WebAnalysisTransportOwnedResource, frozenset[str]]],
    networks: list[tuple[WebAnalysisTransportOwnedResource, frozenset[str]]],
    external_network: str,
) -> None:
    del external_network
    if (
        sum(resource.resource_kind == "worker-container" for resource, _ in containers) > 1
        or sum(resource.resource_kind == "proxy-container" for resource, _ in containers) > 1
        or len(networks) > 1
    ):
        raise ValueError("Web analysis transport cleanup ownership is ambiguous")
    network_names = {resource.resource_name for resource, _ in networks}
    container_ids = {resource.resource_id for resource, _ in containers}
    network_suffixes = {name.removeprefix("pajin-egress-") for name in network_names}
    proxy_suffixes = {
        resource.resource_name.removeprefix("pajin-proxy-")
        for resource, _ in containers
        if resource.resource_kind == "proxy-container"
    }
    if network_suffixes and proxy_suffixes and network_suffixes != proxy_suffixes:
        raise ValueError("Web analysis transport proxy-network ownership differs")
    for resource, attached_networks in containers:
        egress_names = {item for item in attached_networks if item.startswith("pajin-egress-")}
        if resource.resource_kind == "worker-container" and egress_names != network_names:
            raise ValueError("Web analysis transport Worker network ownership differs")
        if not egress_names <= network_names:
            raise ValueError("Web analysis transport proxy network ownership differs")
    for _resource, attached_containers in networks:
        if not attached_containers <= container_ids:
            raise ValueError("Web analysis transport egress network has a foreign member")


def _require_exact_execution_label(labels: dict[str, object], *, execution_id: str) -> None:
    if labels != {_EXECUTION_LABEL: execution_id}:
        raise ValueError("Web analysis transport execution ownership label differs")


def _inspect_transport_resource(
    docker_executable: str,
    *,
    resource_kind: Literal["container", "network"],
    resource_id: str,
) -> dict[str, object]:
    result = _run_transport_cleanup_command(
        (docker_executable, resource_kind, "inspect", resource_id)
    )
    if result.returncode != 0:
        raise ValueError(f"Docker {resource_kind} ownership inspection failed")
    decoded = parse_strict_json_bytes(
        result.stdout,
        label=f"Web analysis transport {resource_kind} inspection",
        max_bytes=_MAX_DOCKER_CLEANUP_OUTPUT_BYTES,
        max_depth=32,
        max_nodes=100_000,
    )
    if type(decoded) is not list or len(decoded) != 1 or type(decoded[0]) is not dict:
        raise ValueError(f"Docker {resource_kind} ownership inspection differs")
    return cast(dict[str, object], decoded[0])


def _remove_transport_resource(
    docker_executable: str,
    *,
    resource_kind: Literal["container", "network"],
    resource_id: str,
) -> None:
    arguments = (
        (docker_executable, "container", "rm", "--force", resource_id)
        if resource_kind == "container"
        else (docker_executable, "network", "rm", resource_id)
    )
    result = _run_transport_cleanup_command(arguments)
    if result.returncode != 0 and not _cleanup_resource_is_absent(result, resource_kind):
        raise ValueError(f"Docker {resource_kind} cleanup failed")


def _verify_transport_resources_absent(
    docker_executable: str,
    *,
    execution_id: str,
    observed_resources: tuple[WebAnalysisTransportOwnedResource, ...],
) -> None:
    if _listed_cleanup_resource_ids(
        docker_executable,
        resource_kind="container",
        execution_id=execution_id,
    ) or _listed_cleanup_resource_ids(
        docker_executable,
        resource_kind="network",
        execution_id=execution_id,
    ):
        raise ValueError("Web analysis transport owned resources remain after cleanup")
    for resource in observed_resources:
        kind: Literal["container", "network"] = (
            "network" if resource.resource_kind == "egress-network" else "container"
        )
        result = _run_transport_cleanup_command(
            (docker_executable, kind, "inspect", resource.resource_id)
        )
        if result.returncode == 0 or not _cleanup_resource_is_absent(result, kind):
            raise ValueError("Web analysis transport resource absence could not be verified")


def _cleanup_resource_is_absent(
    result: subprocess.CompletedProcess[bytes],
    resource_kind: Literal["container", "network"],
) -> bool:
    diagnostic = (result.stderr + b" " + result.stdout).lower()
    if resource_kind == "container":
        return b"no such container" in diagnostic or b"no such object" in diagnostic
    return b"no such network" in diagnostic or (
        b"network" in diagnostic and b"not found" in diagnostic
    )


def _run_transport_cleanup_command(
    arguments: tuple[str, ...],
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=_DOCKER_CLEANUP_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Docker transport cleanup command failed") from exc
    if (
        len(result.stdout) > _MAX_DOCKER_CLEANUP_OUTPUT_BYTES
        or len(result.stderr) > _MAX_DOCKER_CLEANUP_OUTPUT_BYTES
    ):
        raise ValueError("Docker transport cleanup command output exceeded its bound")
    return result


def _transport_digest(value: object) -> str:
    encoded = canonical_json_bytes(
        value,
        label="Web analysis transport runtime Pin",
        max_bytes=_MAX_TRANSPORT_PIN_BYTES,
    )
    return sha256(b"PAJIN-WEB-ANALYSIS-TRANSPORT\0" + encoded).hexdigest()


def _transport_cleanup_digest(domain: str, value: object) -> str:
    encoded = canonical_json_bytes(
        value,
        label="Web analysis transport cleanup proof",
        max_bytes=_MAX_TRANSPORT_PIN_BYTES,
    )
    return sha256(domain.encode("ascii", errors="strict") + b"\x00" + encoded).hexdigest()


def _require_claim_transport_coordinate(*, execution_id: str, external_network: str) -> None:
    if (
        _EXECUTION_ID_PATTERN.fullmatch(execution_id) is None
        or _LIVE_NETWORK_PATTERN.fullmatch(external_network) is None
        or external_network.removeprefix("pajin-web-analysis-live-network-")
        != execution_id.removeprefix("exec_")
    ):
        raise ValueError("Web analysis transport claim resource coordinate differs")


def _require_successor_image_ids(
    *,
    runtime: RuntimePin,
    worker_image: object,
    proxy_image: object,
) -> None:
    if (
        type(worker_image) is not str
        or type(proxy_image) is not str
        or worker_image == proxy_image
        or worker_image in {runtime.worker_image, runtime.proxy_image}
        or proxy_image in {runtime.worker_image, runtime.proxy_image}
    ):
        raise ValueError(
            "Web analysis successor transport requires distinct newly built Worker and proxy images"
        )


def _require_local_successor_registration(registration: ProviderRegistration) -> None:
    """Keep the non-egress successor transport on one exact local Provider endpoint."""

    parsed = urlsplit(str(registration.endpoint))
    host = parsed.hostname
    if host is None:
        raise ValueError("Web analysis successor Provider endpoint host is absent")
    normalized_host = host.lower()
    local = normalized_host in {"localhost", "host.docker.internal"}
    with suppress(ValueError):
        local = local or ip_address(normalized_host).is_loopback
    if (
        not local
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/chat/completions"
        or parsed.query
        or parsed.fragment
        or not registration.allow_private_networks
        or registration.allow_streaming
        or registration.allowed_function_tools
    ):
        raise ValueError("Web analysis successor Provider must remain an exact local chat endpoint")


def _runtime_digest(runtime: RuntimePin) -> str:
    encoded = canonical_json_bytes(
        runtime.model_dump(mode="json"),
        label="Web analysis base model runtime Pin",
        max_bytes=_MAX_TRANSPORT_PIN_BYTES,
    )
    return sha256(b"PAJIN-WEB-ANALYSIS-BASE-RUNTIME\0" + encoded).hexdigest()


__all__ = [
    "WEB_ANALYSIS_PINNED_PROVIDER_ACTION",
    "WEB_ANALYSIS_PRE_CLEANUP_BARRIER_API_VERSION",
    "WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS",
    "WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION",
    "WEB_ANALYSIS_TRANSPORT_CLEANUP_PROOF_API_VERSION",
    "WEB_ANALYSIS_TRANSPORT_RUNTIME_PIN_API_VERSION",
    "WebAnalysisTransportCleanupProof",
    "WebAnalysisTransportError",
    "WebAnalysisTransportOwnedResource",
    "WebAnalysisTransportPreCleanupBarrierContext",
    "WebAnalysisTransportRuntimePin",
    "bind_web_analysis_transport_job",
    "cleanup_web_analysis_transport_resources",
    "expected_web_analysis_legacy_job_metadata",
    "expected_web_analysis_provider_worker_context",
    "expected_web_analysis_transport_job_metadata",
    "interpret_web_analysis_transport_result",
    "load_verified_web_analysis_transport_runtime_pin",
    "prepare_web_analysis_transport_job",
    "verify_web_analysis_legacy_job_metadata",
    "verify_web_analysis_provider_worker_context",
    "verify_web_analysis_transport_cleanup_proof",
    "verify_web_analysis_transport_job_metadata",
    "verify_web_analysis_transport_runtime_pin",
    "web_analysis_transport_pre_cleanup_barrier_context",
    "web_analysis_transport_runtime_pin",
]
