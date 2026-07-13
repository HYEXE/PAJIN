"""Async authenticated client used by PAJIN Worker daemons."""

from __future__ import annotations

from types import TracebackType
from typing import Any, Self

import httpx

from pajin.control_plane.models import (
    CheckpointCreationView,
    ClaimedJob,
    ClaimJobRequest,
    CompleteJobRequest,
    CreateCheckpointRequest,
    FailJobRequest,
    JobView,
    LeaseRequest,
)


class ControlPlaneClientError(RuntimeError):
    """Base class for daemon-facing Control Plane failures."""


class ControlPlaneAuthenticationError(ControlPlaneClientError):
    pass


class ControlPlaneLeaseLost(ControlPlaneClientError):
    pass


class ControlPlaneTransientError(ControlPlaneClientError):
    pass


class ControlPlaneProtocolError(ControlPlaneClientError):
    pass


class ControlPlaneClient:
    """Reuse one bounded HTTP connection pool for all daemon operations."""

    def __init__(
        self,
        *,
        base_url: str,
        bearer_token: str,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        if len(bearer_token) < 32:
            raise ValueError("Worker bearer token must contain at least 32 characters")
        timeout = httpx.Timeout(connect=5, read=30, write=10, pool=5)
        self._client = httpx.AsyncClient(
            base_url=base_url.rstrip("/"),
            headers={"Authorization": f"Bearer {bearer_token}"},
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
        return ClaimedJob.model_validate(response.json())

    async def heartbeat(self, job_id: str, request: LeaseRequest) -> JobView:
        response = await self._request(
            "POST",
            f"/v1/worker/jobs/{job_id}/heartbeat",
            json=request.model_dump(mode="json"),
        )
        return JobView.model_validate(response.json())

    async def complete(self, job_id: str, request: CompleteJobRequest) -> JobView:
        response = await self._request(
            "POST",
            f"/v1/worker/jobs/{job_id}/complete",
            json=request.model_dump(mode="json"),
        )
        return JobView.model_validate(response.json())

    async def fail(self, job_id: str, request: FailJobRequest) -> JobView:
        response = await self._request(
            "POST",
            f"/v1/worker/jobs/{job_id}/fail",
            json=request.model_dump(mode="json"),
        )
        return JobView.model_validate(response.json())

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
        return CheckpointCreationView.model_validate(response.json())

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any],
        timeout: httpx.Timeout | None = None,
    ) -> httpx.Response:
        try:
            response = await self._client.request(
                method,
                path,
                json=json,
                timeout=timeout or self._client.timeout,
            )
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise ControlPlaneTransientError(
                f"Control Plane transport failed: {type(exc).__name__}"
            ) from exc
        if response.status_code in {401, 403}:
            raise ControlPlaneAuthenticationError("Control Plane rejected Worker authentication")
        if response.status_code == 409:
            raise ControlPlaneLeaseLost(self._detail(response, "Worker lease was rejected"))
        if response.status_code >= 500:
            raise ControlPlaneTransientError(self._detail(response, "Control Plane server failure"))
        if not 200 <= response.status_code < 300:
            raise ControlPlaneProtocolError(
                self._detail(response, f"unexpected Control Plane status {response.status_code}")
            )
        return response

    @staticmethod
    def _detail(response: httpx.Response, fallback: str) -> str:
        try:
            body = response.json()
        except ValueError:
            return fallback
        detail = body.get("detail") if isinstance(body, dict) else None
        return str(detail)[:500] if detail else fallback
