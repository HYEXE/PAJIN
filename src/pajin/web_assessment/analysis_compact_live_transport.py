"""Compact-live Provider transport bound to the additive runtime Pins.

This module deliberately starts from :class:`OpenAICompatibleChatTool` and
binds its authority-free prepared job to the compact runtime and transport
Pins.  It does not import or reinterpret the historical effectiveness
``RuntimePin`` or ``LocalEvaluationTool``.
"""

from __future__ import annotations

import json
import re
from contextlib import suppress
from ipaddress import ip_address
from urllib.parse import urlsplit

from pydantic import JsonValue

from pajin.domain.models import ToolRequest
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderRegistration
from pajin.providers.openai_compatible import OpenAICompatibleChatTool
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.execution_receipts import safe_job_metadata
from pajin.web_assessment.analysis_capacity_v2 import WebAnalysisCapacityV2Pin
from pajin.web_assessment.analysis_compact_live_pins import (
    CompactWebAnalysisRuntimePin,
    CompactWebAnalysisTransportPin,
    verify_compact_web_analysis_live_pin_binding,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    CompactSkillBoundWebAnalysisLiveRequest,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportCleanupProof,
    WebAnalysisTransportRuntimePin,
    cleanup_web_analysis_bound_transport_resources,
    expected_web_analysis_bound_provider_worker_context,
    verify_web_analysis_bound_provider_worker_context,
    verify_web_analysis_bound_transport_cleanup_proof,
)

_MAX_PROVIDER_PAYLOAD_BYTES = 1_000_000
_EXECUTION_ID_PATTERN = re.compile(r"^exec_[a-f0-9]{32}$")
_LEASE_ID_PATTERN = re.compile(r"^lease_[a-f0-9]{32}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class CompactWebAnalysisTransportError(ValueError):
    """Raised when a compact-live Provider transport binding fails closed."""


def _verified_binding(
    *,
    capacity_pin: WebAnalysisCapacityV2Pin,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    expected_capacity_pin_digest: str,
    expected_lineage_transport_pin_digest: str,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
) -> tuple[
    CompactSkillBoundWebAnalysisLiveRequest,
    CompactWebAnalysisRuntimePin,
    CompactWebAnalysisTransportPin,
]:
    if (
        type(capacity_pin) is not WebAnalysisCapacityV2Pin
        or type(live_request) is not CompactSkillBoundWebAnalysisLiveRequest
        or type(lineage_transport_pin) is not WebAnalysisTransportRuntimePin
        or type(runtime_pin) is not CompactWebAnalysisRuntimePin
        or type(transport_pin) is not CompactWebAnalysisTransportPin
        or type(expected_capacity_pin_digest) is not str
        or _SHA256_PATTERN.fullmatch(expected_capacity_pin_digest) is None
        or type(expected_lineage_transport_pin_digest) is not str
        or _SHA256_PATTERN.fullmatch(expected_lineage_transport_pin_digest) is None
        or type(expected_runtime_pin_digest) is not str
        or _SHA256_PATTERN.fullmatch(expected_runtime_pin_digest) is None
        or type(expected_transport_pin_digest) is not str
        or _SHA256_PATTERN.fullmatch(expected_transport_pin_digest) is None
    ):
        raise TypeError("Compact-live transport inputs or independent anchors differ")
    capacity = WebAnalysisCapacityV2Pin.model_validate(
        capacity_pin.model_dump(mode="json", by_alias=True)
    )
    request = CompactSkillBoundWebAnalysisLiveRequest.model_validate(
        live_request.model_dump(mode="json", by_alias=True)
    )
    lineage = WebAnalysisTransportRuntimePin.model_validate(
        lineage_transport_pin.model_dump(mode="json", by_alias=True)
    )
    runtime, transport = verify_compact_web_analysis_live_pin_binding(
        runtime_pin,
        transport_pin,
        capacity=capacity,
        live_request=request,
        lineage_transport_pin=lineage,
        expected_runtime_pin_digest=expected_runtime_pin_digest,
        expected_transport_pin_digest=expected_transport_pin_digest,
    )
    if (
        capacity != capacity_pin
        or request != live_request
        or lineage != lineage_transport_pin
        or runtime != runtime_pin
        or transport != transport_pin
        or capacity.pin_digest != expected_capacity_pin_digest
        or lineage.pin_digest != expected_lineage_transport_pin_digest
        or capacity.transport_pin_digest != lineage.pin_digest
        or runtime.pin_digest != expected_runtime_pin_digest
        or transport.pin_digest != expected_transport_pin_digest
        or transport.runtime_pin_digest != runtime.pin_digest
        or transport.lineage_transport_pin_digest != runtime.lineage_transport_pin_digest
        or transport.worker_wire_protocol_version != lineage.transport_version
        or runtime.live_request_digest != request.request_digest
        or runtime.live_request_compact_projection_digest != request.compact_projection_digest
        or runtime.live_request_chat_request_digest != request.chat_request_digest
        or runtime.provider_registration_digest != request.provider_registration_digest
        or runtime.model_id != request.provider_registration.model
        or request.chat_request.max_completion_tokens != runtime.completion_tokens
        or runtime.completion_tokens != 1024
        or not transport.single_dispatch_only
    ):
        raise ValueError("Compact-live transport Pin or request binding differs")
    return request, runtime, transport


def _canonical_registration(
    registration: ProviderRegistration,
    *,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    runtime_pin: CompactWebAnalysisRuntimePin,
) -> ProviderRegistration:
    if type(registration) is not ProviderRegistration:
        raise TypeError("Compact-live Provider registration type differs")
    canonical = ProviderRegistration.model_validate(registration.model_dump(mode="python"))
    parsed = urlsplit(str(canonical.endpoint))
    host = parsed.hostname
    if host is None:
        raise ValueError("Compact-live Provider endpoint host is absent")
    normalized_host = host.lower()
    local = normalized_host in {"localhost", "host.docker.internal"}
    with suppress(ValueError):
        local = local or ip_address(normalized_host).is_loopback
    if (
        canonical != registration
        or canonical != live_request.provider_registration
        or canonical.model != runtime_pin.model_id
        or not local
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != "/v1/chat/completions"
        or parsed.query
        or parsed.fragment
        or not canonical.allow_private_networks
        or canonical.allow_streaming
        or canonical.allowed_function_tools
    ):
        raise ValueError("Compact-live Provider registration differs from its exact local binding")
    return canonical


def _canonical_tool_request(
    request: ToolRequest,
    *,
    registration: ProviderRegistration,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
) -> tuple[ToolRequest, ProviderChatRequest]:
    if type(request) is not ToolRequest:
        raise TypeError("Compact-live Tool request type differs")
    canonical = ToolRequest.model_validate(request.model_dump(mode="python"))
    chat = ProviderChatRequest.model_validate(canonical.arguments)
    if (
        canonical != request
        or canonical.method != "POST"
        or canonical.target != str(registration.endpoint)
        or canonical.tool_id != f"provider.{registration.provider_id}.chat"
        or chat != live_request.chat_request
        or chat.stream
        or chat.tools
        or chat.tool_choice != "none"
        or chat.max_completion_tokens != 1024
    ):
        raise ValueError("Compact-live Tool request differs from the prepared request")
    return canonical, chat


def _prepare_job(
    request: ToolRequest,
    *,
    registration: ProviderRegistration,
    transport_pin: CompactWebAnalysisTransportPin,
    execution_id: str,
) -> WorkerJob:
    if type(execution_id) is not str or _EXECUTION_ID_PATTERN.fullmatch(execution_id) is None:
        raise ValueError("Compact-live Worker execution identity differs")
    prepared = OpenAICompatibleChatTool(registration).prepare(request)
    canonical = WorkerJob.model_validate(prepared.model_dump(mode="python"))
    if (
        canonical.command != ["openai-chat-completion"]
        or canonical.network is not NetworkMode.NONE
        or canonical.egress_policy is not None
        or len(canonical.secret_requests) != 1
    ):
        raise ValueError("Generic Provider job differs before compact transport binding")
    raw = parse_strict_json_bytes(
        canonical.stdin.encode("utf-8", errors="strict"),
        label="compact-live Provider Worker payload",
        max_bytes=_MAX_PROVIDER_PAYLOAD_BYTES,
        max_depth=32,
        max_nodes=20_000,
    )
    if type(raw) is not dict or set(raw) != {"providerId", "request", "target"}:
        raise ValueError("Compact-live Provider Worker payload fields differ")
    payload = dict(raw)
    payload["requestTimeoutSeconds"] = transport_pin.worker_open_timeout_seconds
    payload["transportVersion"] = transport_pin.worker_wire_protocol_version
    rebound = WorkerJob.model_validate(
        {
            **canonical.model_dump(mode="python"),
            "execution_id": execution_id,
            "image": transport_pin.worker_image,
            "command": [transport_pin.worker_action],
            "stdin": json.dumps(
                payload,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ),
            "network": NetworkMode.EGRESS_PROXY,
            "egress_policy": EgressPolicy(
                allow=[str(registration.endpoint)],
                deny=[],
                allowed_methods={"POST"},
                allow_private_networks=True,
                max_response_bytes=EgressPolicy.model_fields["max_response_bytes"].default,
                max_requests=1,
                max_request_bytes=canonical.request_byte_limit_override,
            ),
            "limits": {
                **canonical.limits.model_dump(mode="python"),
                "timeout_seconds": transport_pin.job_timeout_seconds,
            },
        }
    )
    if rebound.execution_id != execution_id:
        raise ValueError("Compact-live transport changed the Worker execution identity")
    return rebound


def prepare_compact_web_analysis_transport_job(
    request: ToolRequest,
    *,
    capacity_pin: WebAnalysisCapacityV2Pin,
    registration: ProviderRegistration,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    expected_capacity_pin_digest: str,
    expected_lineage_transport_pin_digest: str,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
    execution_id: str,
) -> WorkerJob:
    """Prepare the exact one-request compact-live Provider Worker job."""

    try:
        exact_request, runtime, transport = _verified_binding(
            capacity_pin=capacity_pin,
            live_request=live_request,
            lineage_transport_pin=lineage_transport_pin,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_lineage_transport_pin_digest=expected_lineage_transport_pin_digest,
            expected_runtime_pin_digest=expected_runtime_pin_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        exact_registration = _canonical_registration(
            registration,
            live_request=exact_request,
            runtime_pin=runtime,
        )
        exact_tool_request, _chat = _canonical_tool_request(
            request,
            registration=exact_registration,
            live_request=exact_request,
        )
        return _prepare_job(
            exact_tool_request,
            registration=exact_registration,
            transport_pin=transport,
            execution_id=execution_id,
        )
    except CompactWebAnalysisTransportError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisTransportError(
            "Compact-live Provider Worker job preparation failed closed"
        ) from exc


def interpret_compact_web_analysis_transport_result(
    request: ToolRequest,
    result: WorkerResult,
    *,
    capacity_pin: WebAnalysisCapacityV2Pin,
    registration: ProviderRegistration,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    expected_capacity_pin_digest: str,
    expected_lineage_transport_pin_digest: str,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
    expected_execution_id: str,
) -> ProviderChatResult:
    """Interpret one exact compact-live Worker result without retry authority."""

    try:
        expected_job = prepare_compact_web_analysis_transport_job(
            request,
            capacity_pin=capacity_pin,
            registration=registration,
            live_request=live_request,
            lineage_transport_pin=lineage_transport_pin,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_lineage_transport_pin_digest=expected_lineage_transport_pin_digest,
            expected_runtime_pin_digest=expected_runtime_pin_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
            execution_id=expected_execution_id,
        )
        if type(result) is not WorkerResult:
            raise TypeError("Compact-live Worker result type differs")
        canonical_result = WorkerResult.model_validate(result.model_dump(mode="python"))
        if (
            canonical_result != result
            or canonical_result.execution_id != expected_job.execution_id
            or canonical_result.backend != "docker"
            or canonical_result.status is not WorkerStatus.SUCCEEDED
            or canonical_result.exit_code != 0
            or canonical_result.stdout_truncated
            or canonical_result.stderr_truncated
        ):
            raise ValueError("Compact-live Worker result differs")
        interpreted = OpenAICompatibleChatTool(registration).interpret(request, canonical_result)
        if not interpreted.success or interpreted.data is None or interpreted.error is not None:
            raise ValueError("Compact-live Provider result was rejected")
        provider_result = ProviderChatResult.model_validate(interpreted.data)
        if (
            provider_result.provider_id != registration.provider_id
            or provider_result.model != registration.model
            or provider_result.target != request.target
            or provider_result.streamed
            or provider_result.chunks != 1
        ):
            raise ValueError("Compact-live Provider result differs")
        return provider_result
    except CompactWebAnalysisTransportError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisTransportError(
            "Compact-live Worker result interpretation failed closed"
        ) from exc


def expected_compact_web_analysis_transport_job_metadata(
    request: ToolRequest,
    *,
    capacity_pin: WebAnalysisCapacityV2Pin,
    registration: ProviderRegistration,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    expected_capacity_pin_digest: str,
    expected_lineage_transport_pin_digest: str,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
    execution_id: str,
    lease_ids: list[str],
) -> dict[str, object]:
    """Reconstruct exact compact-live Worker metadata from trusted inputs."""

    try:
        if (
            type(lease_ids) is not list
            or len(lease_ids) > 1
            or any(
                type(lease_id) is not str or _LEASE_ID_PATTERN.fullmatch(lease_id) is None
                for lease_id in lease_ids
            )
        ):
            raise ValueError("Compact-live credential lease identity differs")
        job = prepare_compact_web_analysis_transport_job(
            request,
            capacity_pin=capacity_pin,
            registration=registration,
            live_request=live_request,
            lineage_transport_pin=lineage_transport_pin,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_lineage_transport_pin_digest=expected_lineage_transport_pin_digest,
            expected_runtime_pin_digest=expected_runtime_pin_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
            execution_id=execution_id,
        )
        return safe_job_metadata(request, job, lease_ids=list(lease_ids))
    except CompactWebAnalysisTransportError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisTransportError(
            "Compact-live Worker metadata reconstruction failed closed"
        ) from exc


def expected_compact_web_analysis_provider_worker_context(
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    *,
    capacity_pin: WebAnalysisCapacityV2Pin,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    expected_capacity_pin_digest: str,
    expected_lineage_transport_pin_digest: str,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    external_network: str,
    claim_digest: str | None = None,
    execution_id: str | None = None,
) -> dict[str, JsonValue]:
    """Build the exact Docker backend context for the compact transport."""

    try:
        _request, _runtime, transport = _verified_binding(
            capacity_pin=capacity_pin,
            live_request=live_request,
            lineage_transport_pin=lineage_transport_pin,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_lineage_transport_pin_digest=expected_lineage_transport_pin_digest,
            expected_runtime_pin_digest=expected_runtime_pin_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        return expected_web_analysis_bound_provider_worker_context(
            worker_image=transport.worker_image,
            proxy_image=transport.proxy_image,
            worker_action=transport.worker_action,
            external_network=external_network,
            claim_digest=claim_digest,
            execution_id=execution_id,
        )
    except CompactWebAnalysisTransportError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisTransportError(
            "Compact-live Provider Worker context construction failed closed"
        ) from exc


def verify_compact_web_analysis_provider_worker_context(
    worker_context: object,
    *,
    capacity_pin: WebAnalysisCapacityV2Pin,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    expected_capacity_pin_digest: str,
    expected_lineage_transport_pin_digest: str,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
    expected_external_network: str | None = None,
    expected_claim_digest: str | None = None,
    expected_execution_id: str | None = None,
) -> dict[str, JsonValue]:
    """Verify actual Docker context against the compact transport Pins."""

    try:
        _request, _runtime, transport = _verified_binding(
            capacity_pin=capacity_pin,
            live_request=live_request,
            lineage_transport_pin=lineage_transport_pin,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_lineage_transport_pin_digest=expected_lineage_transport_pin_digest,
            expected_runtime_pin_digest=expected_runtime_pin_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        return verify_web_analysis_bound_provider_worker_context(
            worker_context,
            worker_image=transport.worker_image,
            proxy_image=transport.proxy_image,
            worker_action=transport.worker_action,
            expected_external_network=expected_external_network,
            expected_claim_digest=expected_claim_digest,
            expected_execution_id=expected_execution_id,
        )
    except CompactWebAnalysisTransportError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisTransportError(
            "Compact-live Provider Worker context verification failed closed"
        ) from exc


def cleanup_compact_web_analysis_transport_resources(
    *,
    execution_id: str,
    external_network: str,
    capacity_pin: WebAnalysisCapacityV2Pin,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    expected_capacity_pin_digest: str,
    expected_lineage_transport_pin_digest: str,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
    docker_executable: str = "docker",
) -> WebAnalysisTransportCleanupProof:
    """Clean only exact execution-owned resources for the compact transport."""

    try:
        _request, _runtime, transport = _verified_binding(
            capacity_pin=capacity_pin,
            live_request=live_request,
            lineage_transport_pin=lineage_transport_pin,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_lineage_transport_pin_digest=expected_lineage_transport_pin_digest,
            expected_runtime_pin_digest=expected_runtime_pin_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        return cleanup_web_analysis_bound_transport_resources(
            execution_id=execution_id,
            external_network=external_network,
            transport_pin_digest=transport.pin_digest,
            worker_image=transport.worker_image,
            proxy_image=transport.proxy_image,
            docker_executable=docker_executable,
        )
    except CompactWebAnalysisTransportError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisTransportError(
            "Compact-live transport cleanup failed closed"
        ) from exc


def verify_compact_web_analysis_transport_cleanup_proof(
    proof: WebAnalysisTransportCleanupProof,
    *,
    execution_id: str,
    external_network: str,
    capacity_pin: WebAnalysisCapacityV2Pin,
    live_request: CompactSkillBoundWebAnalysisLiveRequest,
    lineage_transport_pin: WebAnalysisTransportRuntimePin,
    runtime_pin: CompactWebAnalysisRuntimePin,
    transport_pin: CompactWebAnalysisTransportPin,
    expected_capacity_pin_digest: str,
    expected_lineage_transport_pin_digest: str,
    expected_runtime_pin_digest: str,
    expected_transport_pin_digest: str,
) -> WebAnalysisTransportCleanupProof:
    """Verify cleanup evidence under compact transport anchors."""

    try:
        _request, _runtime, transport = _verified_binding(
            capacity_pin=capacity_pin,
            live_request=live_request,
            lineage_transport_pin=lineage_transport_pin,
            runtime_pin=runtime_pin,
            transport_pin=transport_pin,
            expected_capacity_pin_digest=expected_capacity_pin_digest,
            expected_lineage_transport_pin_digest=expected_lineage_transport_pin_digest,
            expected_runtime_pin_digest=expected_runtime_pin_digest,
            expected_transport_pin_digest=expected_transport_pin_digest,
        )
        return verify_web_analysis_bound_transport_cleanup_proof(
            proof,
            execution_id=execution_id,
            external_network=external_network,
            expected_transport_pin_digest=transport.pin_digest,
        )
    except CompactWebAnalysisTransportError:
        raise
    except Exception as exc:
        raise CompactWebAnalysisTransportError(
            "Compact-live transport cleanup proof verification failed closed"
        ) from exc


__all__ = [
    "CompactWebAnalysisTransportError",
    "cleanup_compact_web_analysis_transport_resources",
    "expected_compact_web_analysis_provider_worker_context",
    "expected_compact_web_analysis_transport_job_metadata",
    "interpret_compact_web_analysis_transport_result",
    "prepare_compact_web_analysis_transport_job",
    "verify_compact_web_analysis_provider_worker_context",
    "verify_compact_web_analysis_transport_cleanup_proof",
]
