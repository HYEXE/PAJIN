"""Async authenticated client used by PAJIN Worker daemons."""

from __future__ import annotations

from ipaddress import ip_address
from types import TracebackType
from typing import Any, Self
from urllib.parse import SplitResult, urlsplit

import httpx
from pydantic import BaseModel

from pajin.control_plane.artifact_transfer import (
    PortableArtifactMultipartPartView,
    PortableArtifactMultipartUploadView,
)
from pajin.control_plane.models import (
    CheckpointCreationView,
    ClaimedJob,
    ClaimJobRequest,
    CompleteJobRequest,
    ControlPlaneConflictCode,
    ControlPlaneConflictResponse,
    CreateCheckpointRequest,
    FailJobRequest,
    JobView,
    LeaseRequest,
    ReplayArtifactUploadBeginRequest,
    ReplayArtifactUploadPartRequest,
    ReplayClaimRequest,
    ReplayExecutionClaimView,
    ReplayFinalizationView,
    ReplayFinalizeRequest,
    ReplayLeaseRequest,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
)
from pajin.control_plane.security import validate_bearer_token

# Worker responses can contain a one-megabyte bounded Job payload plus the
# server-derived Replay authority envelope. Keep enough room for that typed
# response while placing a hard ceiling on an untrusted peer or proxy stream.
_MAX_CONTROL_PLANE_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_CONTROL_PLANE_BASE_URL_BYTES = 2_048
_PLAINTEXT_LAB_HOSTS = frozenset({"localhost", "control-plane"})


class ControlPlaneClientError(RuntimeError):
    """Base class for daemon-facing Control Plane failures."""


class ControlPlaneAuthenticationError(ControlPlaneClientError):
    pass


class ControlPlaneLeaseLost(ControlPlaneClientError):
    pass


class ControlPlaneLocalLeaseDeadlineExceeded(ControlPlaneLeaseLost):
    """The Worker can no longer prove that its server lease is still valid."""


class ControlPlaneRunCancelled(ControlPlaneLeaseLost):
    """The leased job's Run was cancelled by the Control Plane."""


class ControlPlaneTransientError(ControlPlaneClientError):
    pass


class ControlPlaneProtocolError(ControlPlaneClientError):
    pass


def _validated_control_plane_base_url(
    base_url: str,
    *,
    allow_plaintext_http_for_lab: bool,
) -> str:
    """Return an origin-only URL that cannot leak bearer credentials by default."""

    if type(allow_plaintext_http_for_lab) is not bool:
        raise ValueError("Control Plane plaintext lab opt-in must be a boolean")
    _require_valid_control_plane_url_text(base_url)
    parsed = _parse_control_plane_origin(base_url)
    _require_allowed_control_plane_transport(
        parsed,
        allow_plaintext_http_for_lab=allow_plaintext_http_for_lab,
    )
    return base_url[:-1] if base_url.endswith("/") else base_url


def _require_valid_control_plane_url_text(base_url: str) -> None:
    if not isinstance(base_url, str):
        raise ValueError("Control Plane base URL contains invalid characters")
    try:
        base_url_bytes = base_url.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("Control Plane base URL contains invalid characters") from exc
    if (
        not base_url
        or base_url != base_url.strip()
        or len(base_url_bytes) > _MAX_CONTROL_PLANE_BASE_URL_BYTES
        or any(ord(character) <= 0x20 or ord(character) == 0x7F for character in base_url)
        or "\\" in base_url
    ):
        raise ValueError("Control Plane base URL contains invalid characters")
    if "?" in base_url:
        raise ValueError("Control Plane base URL must not contain a query")
    if "#" in base_url:
        raise ValueError("Control Plane base URL must not contain a fragment")


def _parse_control_plane_origin(base_url: str) -> SplitResult:
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Control Plane base URL authority is invalid") from exc
    if parsed.scheme not in {"https", "http"}:
        raise ValueError("Control Plane base URL must use HTTPS")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("Control Plane base URL must contain an authority")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Control Plane base URL must not contain credentials")
    if "%" in parsed.netloc or parsed.netloc.endswith(":"):
        raise ValueError("Control Plane base URL authority is invalid")
    if port is not None and not 1 <= port <= 65_535:
        raise ValueError("Control Plane base URL authority is invalid")
    if parsed.path not in {"", "/"}:
        raise ValueError("Control Plane base URL must be an origin without a path")
    return parsed


def _require_allowed_control_plane_transport(
    parsed: SplitResult,
    *,
    allow_plaintext_http_for_lab: bool,
) -> None:
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("Control Plane base URL must contain an authority")
    host = hostname.lower()
    if not host.rstrip("."):
        raise ValueError("Control Plane base URL authority is invalid")
    if parsed.scheme == "http":
        if not allow_plaintext_http_for_lab:
            raise ValueError("Control Plane base URL must use HTTPS")
        if not _is_plaintext_lab_host(host):
            raise ValueError(
                "Control Plane plaintext HTTP exception is limited to a local lab authority"
            )


def _is_plaintext_lab_host(host: str) -> bool:
    if host in _PLAINTEXT_LAB_HOSTS:
        return True
    try:
        return ip_address(host).is_loopback
    except ValueError:
        return False


class ControlPlaneClient:
    """Reuse one bounded HTTP connection pool for all daemon operations."""

    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str,
        allow_plaintext_http_for_lab: bool = False,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        trusted_bearer_token = validate_bearer_token(
            bearer_token,
            label="Worker bearer token",
        )
        trusted_base_url = _validated_control_plane_base_url(
            base_url,
            allow_plaintext_http_for_lab=allow_plaintext_http_for_lab,
        )
        timeout = httpx.Timeout(connect=5, read=30, write=10, pool=5)
        self._client = httpx.AsyncClient(
            base_url=trusted_base_url,
            headers={
                "Authorization": f"Bearer {trusted_bearer_token}",
                "Accept-Encoding": "identity",
            },
            timeout=timeout,
            follow_redirects=False,
            transport=transport,
            trust_env=False,
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        _exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: TracebackType | None,
    ) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def claim(self, request: ClaimJobRequest) -> ClaimedJob | None:
        response = await self._request(
            "POST",
            "/v1/worker/jobs/claim",
            json=request.model_dump(mode="json"),
            timeout=httpx.Timeout(connect=5, read=request.wait_seconds + 5, write=10, pool=5),
        )
        if response.status_code == 204:
            return None
        return self._validated(response, ClaimedJob)

    async def heartbeat(self, job_id: str, request: LeaseRequest) -> JobView:
        response = await self._request(
            "POST",
            f"/v1/worker/jobs/{job_id}/heartbeat",
            json=request.model_dump(mode="json"),
        )
        return self._validated(response, JobView)

    async def claim_replay(
        self,
        request: ReplayClaimRequest,
    ) -> ReplayExecutionClaimView | None:
        response = await self._request(
            "POST",
            "/v1/worker/replay/jobs/claim",
            json=request.model_dump(mode="json"),
            timeout=httpx.Timeout(
                connect=5,
                read=request.wait_seconds + 5,
                write=10,
                pool=5,
            ),
        )
        if response.status_code == 204:
            return None
        return self._validated(response, ReplayExecutionClaimView)

    async def heartbeat_replay(
        self,
        job_id: str,
        request: ReplayLeaseRequest,
    ) -> ReplayExecutionClaimView:
        response = await self._request(
            "POST",
            f"/v1/worker/replay/jobs/{job_id}/heartbeat",
            json=request.model_dump(mode="json"),
        )
        return self._validated(response, ReplayExecutionClaimView)

    async def issue_replay_tool_permit(
        self,
        job_id: str,
        request: ReplayToolPermitRequest,
    ) -> ReplayToolPermitView:
        response = await self._request(
            "POST",
            f"/v1/worker/replay/jobs/{job_id}/tool-permits",
            json=request.model_dump(mode="json"),
        )
        return self._validated(response, ReplayToolPermitView)

    async def begin_replay_artifact_upload(
        self,
        job_id: str,
        request: ReplayArtifactUploadBeginRequest,
    ) -> PortableArtifactMultipartUploadView:
        response = await self._request(
            "POST",
            f"/v1/worker/replay/jobs/{job_id}/artifact-upload",
            json=request.model_dump(mode="json"),
        )
        return self._validated(response, PortableArtifactMultipartUploadView)

    async def put_replay_artifact_upload_part(
        self,
        job_id: str,
        request: ReplayArtifactUploadPartRequest,
    ) -> PortableArtifactMultipartPartView:
        response = await self._request(
            "PUT",
            f"/v1/worker/replay/jobs/{job_id}/artifact-upload/parts",
            json=request.model_dump(mode="json"),
            timeout=httpx.Timeout(connect=5, read=30, write=30, pool=5),
        )
        return self._validated(response, PortableArtifactMultipartPartView)

    async def finalize_replay(
        self,
        job_id: str,
        request: ReplayFinalizeRequest,
    ) -> ReplayFinalizationView:
        response = await self._request(
            "POST",
            f"/v1/worker/replay/jobs/{job_id}/finalize",
            json=request.model_dump(mode="json"),
        )
        return self._validated(response, ReplayFinalizationView)

    async def complete(self, job_id: str, request: CompleteJobRequest) -> JobView:
        response = await self._request(
            "POST",
            f"/v1/worker/jobs/{job_id}/complete",
            json=request.model_dump(mode="json"),
        )
        return self._validated(response, JobView)

    async def fail(self, job_id: str, request: FailJobRequest) -> JobView:
        response = await self._request(
            "POST",
            f"/v1/worker/jobs/{job_id}/fail",
            json=request.model_dump(mode="json"),
        )
        return self._validated(response, JobView)

    async def checkpoint(
        self,
        job_id: str,
        request: CreateCheckpointRequest,
    ) -> CheckpointCreationView:
        response = await self._request(
            "POST",
            f"/v1/worker/jobs/{job_id}/checkpoints",
            json=request.model_dump(mode="json"),
        )
        return self._validated(response, CheckpointCreationView)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any],
        timeout: httpx.Timeout | None = None,
    ) -> httpx.Response:
        try:
            async with self._client.stream(
                method,
                path,
                json=json,
                timeout=timeout or self._client.timeout,
            ) as streamed:
                response = await self._bounded_response(streamed)
        except (
            httpx.TimeoutException,
            httpx.NetworkError,
            httpx.ProxyError,
            httpx.RemoteProtocolError,
        ) as exc:
            raise ControlPlaneTransientError("Control Plane transport failed") from exc
        if response.status_code in {401, 403}:
            raise ControlPlaneAuthenticationError("Control Plane rejected Worker authentication")
        if response.status_code == 409:
            conflict = self._validated(response, ControlPlaneConflictResponse)
            if conflict.code is ControlPlaneConflictCode.RUN_CANCELLED:
                raise ControlPlaneRunCancelled("run has been cancelled")
            raise ControlPlaneLeaseLost("Control Plane lease was rejected or expired")
        if response.status_code >= 500:
            raise ControlPlaneTransientError("Control Plane server failure")
        if not 200 <= response.status_code < 300:
            raise ControlPlaneProtocolError(
                f"unexpected Control Plane status {response.status_code}"
            )
        return response

    @classmethod
    async def _bounded_response(cls, streamed: httpx.Response) -> httpx.Response:
        content_encoding = streamed.headers.get("content-encoding", "identity")
        if content_encoding.strip().lower() not in {"", "identity"}:
            raise ControlPlaneProtocolError(
                "Control Plane returned a compressed response despite identity encoding"
            )
        declared_length = cls._declared_content_length(streamed)
        if declared_length is not None and declared_length > _MAX_CONTROL_PLANE_RESPONSE_BYTES:
            raise ControlPlaneProtocolError("Control Plane response exceeds the byte limit")

        body = bytearray()
        if streamed.is_stream_consumed:
            # Mock/custom transports may return an already materialized response
            # even when the client requested streaming.
            if len(streamed.content) > _MAX_CONTROL_PLANE_RESPONSE_BYTES:
                raise ControlPlaneProtocolError("Control Plane response exceeds the byte limit")
            body.extend(streamed.content)
        else:
            async for chunk in streamed.aiter_raw():
                if len(body) + len(chunk) > _MAX_CONTROL_PLANE_RESPONSE_BYTES:
                    raise ControlPlaneProtocolError("Control Plane response exceeds the byte limit")
                body.extend(chunk)
        return httpx.Response(
            status_code=streamed.status_code,
            headers=streamed.headers,
            content=bytes(body),
            request=streamed.request,
        )

    @staticmethod
    def _declared_content_length(response: httpx.Response) -> int | None:
        raw = response.headers.get("content-length")
        if raw is None or not raw.isdecimal():
            return None
        try:
            return int(raw)
        except ValueError:  # pragma: no cover - guarded by isdecimal
            return None

    @staticmethod
    def _validated[T: BaseModel](response: httpx.Response, model: type[T]) -> T:
        try:
            return model.model_validate(response.json())
        except ValueError as exc:
            raise ControlPlaneProtocolError(
                f"Control Plane returned an invalid {model.__name__} response"
            ) from exc
