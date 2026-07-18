"""Async authenticated client used by PAJIN Worker daemons."""

from __future__ import annotations

from types import TracebackType
from typing import Any, Self

import httpx
from pydantic import BaseModel

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
    ReplayClaimRequest,
    ReplayExecutionClaimView,
    ReplayLeaseRequest,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
)


class ControlPlaneClientError(RuntimeError):
    """Base class for daemon-facing Control Plane failures."""


class ControlPlaneAuthenticationError(ControlPlaneClientError):
    pass


class ControlPlaneLeaseLost(ControlPlaneClientError):
    pass


class ControlPlaneRunCancelled(ControlPlaneLeaseLost):
    """The leased job's Run was cancelled by the Control Plane."""


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
            conflict = self._validated(response, ControlPlaneConflictResponse)
            if conflict.code is ControlPlaneConflictCode.RUN_CANCELLED:
                raise ControlPlaneRunCancelled(conflict.detail)
            raise ControlPlaneLeaseLost(conflict.detail)
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

    @staticmethod
    def _validated[T: BaseModel](response: httpx.Response, model: type[T]) -> T:
        try:
            return model.model_validate(response.json())
        except ValueError as exc:
            raise ControlPlaneProtocolError(
                f"Control Plane returned an invalid {model.__name__} response"
            ) from exc
