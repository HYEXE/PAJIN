"""Versioned Provider transport pin for Skill-bound WEB analysis."""

from __future__ import annotations

import json
import re
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
from pajin.providers.models import ProviderChatRequest, ProviderRegistration
from pajin.runtime.safe_files import load_bounded_strict_json, parse_strict_json_bytes
from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerJob
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

_MAX_TRANSPORT_PIN_BYTES = 64 * 1024
_MAX_PROVIDER_PAYLOAD_BYTES = 1_000_000
_ImageID = Annotated[str, Field(pattern=r"^sha256:[a-f0-9]{64}$")]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_EXECUTION_ID_PATTERN = re.compile(r"^exec_[a-f0-9]{32}$")
_LEASE_ID_PATTERN = re.compile(r"^lease_[a-f0-9]{32}$")
_SAFE_RUNTIME_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")
_DOCKER_WORKER_TYPE = "pajin.runtime.worker.DockerWorkerBackend"


class WebAnalysisTransportError(ValueError):
    """Raised when the successor Provider transport differs from its immutable pin."""


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
        canonical_pin = verify_web_analysis_transport_runtime_pin(
            transport_pin,
            runtime=canonical_runtime,
            expected_pin_digest=expected_transport_pin_digest,
        )
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


def expected_web_analysis_provider_worker_context(
    transport_pin: WebAnalysisTransportRuntimePin,
    *,
    external_network: str,
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
        return cast(
            dict[str, JsonValue],
            {
                "type": _DOCKER_WORKER_TYPE,
                "context": {
                    "implementationVersion": "pajin.docker-worker/v2",
                    "allowedImages": [canonical_pin.worker_image],
                    "dockerExecutable": "docker",
                    "egressProxyImage": canonical_pin.proxy_image,
                    "externalNetwork": external_network,
                    "externalNetworkRoutes": {
                        canonical_pin.worker_action: external_network,
                    },
                },
            },
        )
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
        if set(nested_mapping) != {
            "implementationVersion",
            "allowedImages",
            "dockerExecutable",
            "egressProxyImage",
            "externalNetwork",
            "externalNetworkRoutes",
        }:
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


def _transport_digest(value: object) -> str:
    encoded = canonical_json_bytes(
        value,
        label="Web analysis transport runtime Pin",
        max_bytes=_MAX_TRANSPORT_PIN_BYTES,
    )
    return sha256(b"PAJIN-WEB-ANALYSIS-TRANSPORT\0" + encoded).hexdigest()


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
    "WEB_ANALYSIS_PROVIDER_TIMEOUT_SECONDS",
    "WEB_ANALYSIS_PROVIDER_TRANSPORT_VERSION",
    "WEB_ANALYSIS_TRANSPORT_RUNTIME_PIN_API_VERSION",
    "WebAnalysisTransportError",
    "WebAnalysisTransportRuntimePin",
    "bind_web_analysis_transport_job",
    "expected_web_analysis_legacy_job_metadata",
    "expected_web_analysis_provider_worker_context",
    "expected_web_analysis_transport_job_metadata",
    "load_verified_web_analysis_transport_runtime_pin",
    "verify_web_analysis_legacy_job_metadata",
    "verify_web_analysis_provider_worker_context",
    "verify_web_analysis_transport_job_metadata",
    "verify_web_analysis_transport_runtime_pin",
    "web_analysis_transport_runtime_pin",
]
