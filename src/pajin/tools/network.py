"""Bounded passive TCP service identification through the PAJIN egress proxy."""

from __future__ import annotations

import json
from base64 import b64decode, b64encode
from binascii import Error as BinasciiError
from hashlib import sha256
from ipaddress import ip_address

from pydantic import ConfigDict, Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_safe_tool_interpretation_failure,
    audit_safe_worker_failure,
    decode_strict_worker_json_object,
    host_observed_https_connect_receipts,
    https_connect_authority,
)

NETWORK_PASSIVE_BANNER_PROFILE = "tcp-passive-banner-v1"
NETWORK_SERVICE_CONNECT_TIMEOUT_MILLISECONDS = 5_000
NETWORK_SERVICE_READ_TIMEOUT_MILLISECONDS = 2_000
MAX_NETWORK_SERVICE_BANNER_BYTES = 1_024
MAX_NETWORK_SERVICE_BANNER_BASE64_CHARS = ((MAX_NETWORK_SERVICE_BANNER_BYTES + 2) // 3) * 4


class NetworkServiceIdentificationInput(StrictModel):
    """Exact IP-literal TCP coordinate and immutable passive-banner budget."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    address_family: str = Field(alias="addressFamily", pattern=r"^ipv[46]$")
    host: str = Field(min_length=1, max_length=45)
    transport_protocol: str = Field(alias="transportProtocol", pattern=r"^tcp$")
    port: int = Field(strict=True, ge=1, le=65_535)
    protocol_profile: str = Field(
        alias="protocolProfile",
        pattern=r"^tcp-passive-banner-v1$",
    )
    connect_timeout_milliseconds: int = Field(
        alias="connectTimeoutMilliseconds",
        strict=True,
        ge=NETWORK_SERVICE_CONNECT_TIMEOUT_MILLISECONDS,
        le=NETWORK_SERVICE_CONNECT_TIMEOUT_MILLISECONDS,
    )
    read_timeout_milliseconds: int = Field(
        alias="readTimeoutMilliseconds",
        strict=True,
        ge=NETWORK_SERVICE_READ_TIMEOUT_MILLISECONDS,
        le=NETWORK_SERVICE_READ_TIMEOUT_MILLISECONDS,
    )
    max_banner_bytes: int = Field(
        alias="maxBannerBytes",
        strict=True,
        ge=MAX_NETWORK_SERVICE_BANNER_BYTES,
        le=MAX_NETWORK_SERVICE_BANNER_BYTES,
    )

    @model_validator(mode="after")
    def validate_ip_literal(self) -> NetworkServiceIdentificationInput:
        try:
            address = ip_address(self.host)
        except ValueError as exc:
            raise ValueError("Network service host must be an IP literal") from exc
        expected_version = 4 if self.address_family == "ipv4" else 6
        if address.version != expected_version or str(address) != self.host:
            raise ValueError("Network service host differs from its address family")
        return self


class _NetworkServiceIdentificationOutput(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, strict=True)

    target: str = Field(min_length=1, max_length=2_000)
    address_family: str = Field(alias="addressFamily", pattern=r"^ipv[46]$")
    host: str = Field(min_length=1, max_length=45)
    transport_protocol: str = Field(alias="transportProtocol", pattern=r"^tcp$")
    port: int = Field(strict=True, ge=1, le=65_535)
    protocol_profile: str = Field(
        alias="protocolProfile",
        pattern=r"^tcp-passive-banner-v1$",
    )
    connected: bool
    banner_bytes: int = Field(alias="bannerBytes", strict=True, ge=0, le=1_024)
    banner_base64: str = Field(
        alias="bannerBase64",
        max_length=MAX_NETWORK_SERVICE_BANNER_BASE64_CHARS,
    )
    banner_sha256: str = Field(alias="bannerSha256", pattern=r"^[a-f0-9]{64}$")
    service_name: str | None = Field(
        default=None,
        alias="serviceName",
        pattern=r"^(ftp|imap|pop3|smtp|ssh)$",
    )
    error: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def validate_banner_shape(self) -> _NetworkServiceIdentificationOutput:
        try:
            banner = b64decode(self.banner_base64, validate=True)
        except (BinasciiError, ValueError) as exc:
            raise ValueError("passive banner is not canonical base64") from exc
        if (
            len(banner) != self.banner_bytes
            or len(banner) > MAX_NETWORK_SERVICE_BANNER_BYTES
            or b64encode(banner).decode("ascii") != self.banner_base64
            or sha256(banner).hexdigest() != self.banner_sha256
        ):
            raise ValueError("passive banner identity differs")
        if self.connected:
            if self.error is not None:
                raise ValueError("connected service output cannot contain an error")
        elif self.banner_bytes or self.service_name is not None or self.error is None:
            raise ValueError("failed connection output has an invalid result shape")
        return self


class NetworkServiceIdentificationTool(Tool):
    """Open one proxy-mediated TCP connection and read only a bounded passive banner."""

    spec = ToolSpec(
        tool_id="network.service-identify",
        version="1.0.0",
        description=(
            "Identify a service from one authorized IP-literal TCP passive banner "
            "through the PAJIN egress proxy"
        ),
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"active-test", "network"}),
        evidence_types=frozenset({"network-service-identification-json"}),
        network_access=True,
        network_request_cost=1,
        parallel_safe=False,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return {
            **self._stable_spec_context(),
            "protocolProfile": NETWORK_PASSIVE_BANNER_PROFILE,
            "applicationWriteBytes": 0,
            "connectTimeoutMilliseconds": NETWORK_SERVICE_CONNECT_TIMEOUT_MILLISECONDS,
            "readTimeoutMilliseconds": NETWORK_SERVICE_READ_TIMEOUT_MILLISECONDS,
            "maxBannerBytes": MAX_NETWORK_SERVICE_BANNER_BYTES,
        }

    def network_response_byte_limit(self, request: ToolRequest) -> int | None:
        probe = NetworkServiceIdentificationInput.model_validate(request.arguments)
        if request.target != network_service_scope_target(
            address_family=probe.address_family,
            host=probe.host,
            port=probe.port,
        ):
            raise ValueError("Network service response budget target differs")
        return MAX_NETWORK_SERVICE_BANNER_BYTES

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "CONNECT":
            raise ValueError("network.service-identify requires CONNECT")
        probe = NetworkServiceIdentificationInput.model_validate(request.arguments)
        expected_target = network_service_scope_target(
            address_family=probe.address_family,
            host=probe.host,
            port=probe.port,
        )
        if request.target != expected_target:
            raise ValueError("network service request target differs from its exact coordinate")
        return WorkerJob(
            image="pajin-worker:dev",
            command=["network-service-identify"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    **probe.model_dump(mode="json", by_alias=True),
                },
                separators=(",", ":"),
                sort_keys=True,
            ),
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_worker_failure(result),
            )
        try:
            probe = NetworkServiceIdentificationInput.model_validate(request.arguments)
            output = _NetworkServiceIdentificationOutput.model_validate(
                decode_strict_worker_json_object(
                    result,
                    label="Network service identification output",
                )
            )
            if (
                request.method != "CONNECT"
                or output.target != request.target
                or output.address_family != probe.address_family
                or output.host != probe.host
                or output.transport_protocol != probe.transport_protocol
                or output.port != probe.port
                or output.protocol_profile != probe.protocol_profile
            ):
                raise ValueError("Network service output differs from the sealed request")
        except ValueError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_tool_interpretation_failure(
                    "invalid Network service identification output",
                    exc,
                ),
            )
        data = output.model_dump(mode="json", by_alias=True, exclude_none=True)
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=output.connected,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
            error=None if output.connected else "Network service target was unavailable",
        )

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        output = _NetworkServiceIdentificationOutput.model_validate(result.data)
        if not output.connected:
            raise ValueError("successful validation requires a connected service result")
        receipts = host_observed_https_connect_receipts(
            worker_result,
            network_log_trusted=network_log_trusted,
        )
        if receipts is None or len(receipts) != 1:
            raise ValueError(
                "network.service-identify requires exactly one host-observed CONNECT receipt"
            )
        receipt = receipts[0]
        if receipt.sequence != 1 or receipt.authority != https_connect_authority(request.target):
            raise ValueError("Network service output differs from its CONNECT receipt")


def network_service_scope_target(*, address_family: str, host: str, port: int) -> str:
    """Project one exact IP-literal TCP coordinate into the existing HTTPS scope engine."""

    rendered_host = f"[{host}]" if address_family == "ipv6" else host
    authority = rendered_host if port == 443 else f"{rendered_host}:{port}"
    return f"https://{authority}/"


def network_service_scope_allow_rule(*, address_family: str, host: str, port: int) -> str:
    """Return the exact host-wide CONNECT rule enforced by the egress proxy."""

    return (
        network_service_scope_target(
            address_family=address_family,
            host=host,
            port=port,
        )
        + "**"
    )


__all__ = [
    "MAX_NETWORK_SERVICE_BANNER_BYTES",
    "NETWORK_PASSIVE_BANNER_PROFILE",
    "NETWORK_SERVICE_CONNECT_TIMEOUT_MILLISECONDS",
    "NETWORK_SERVICE_READ_TIMEOUT_MILLISECONDS",
    "NetworkServiceIdentificationInput",
    "NetworkServiceIdentificationTool",
    "network_service_scope_allow_rule",
    "network_service_scope_target",
]
