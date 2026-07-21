"""Route-group registration for the PAJIN Control Plane API.

Keeping endpoint definitions outside the application composition root makes the
security boundary visible: every protected group receives an already-built
dependency rather than rebuilding authentication or role checks locally.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from typing import Annotated, Any

from fastapi import Depends, FastAPI, Query, Response, status
from sqlalchemy import text

from pajin.control_plane.database import ControlPlaneRepository
from pajin.control_plane.models import (
    ApprovalView,
    AuditEventView,
    CancelRunRequest,
    CancelRunView,
    CheckpointCreationView,
    ClaimedJob,
    ClaimJobRequest,
    CompleteJobRequest,
    ControlPlaneConflictResponse,
    CreateCheckpointRequest,
    DecideApprovalRequest,
    FailJobRequest,
    JobView,
    LeaseRequest,
    Principal,
    PrincipalRole,
    ReplayClaimRequest,
    ReplayExecutionClaimView,
    ReplayFinalizationView,
    ReplayFinalizeRequest,
    ReplayLeaseRequest,
    ReplayToolPermitRequest,
    ReplayToolPermitView,
    ResumeCheckpointRequest,
    ResumeView,
    RunListView,
    RunState,
    RunView,
    SubmissionView,
    SubmitRunRequest,
)
from pajin.control_plane.service import MAX_AUDIT_EVENT_PAGE_SIZE, ControlPlaneService
from pajin.control_plane.web_console import console_asset_response, console_index_response

PrincipalDependency = Callable[[Principal], Principal]
RoleDependencyFactory = Callable[..., PrincipalDependency]


@dataclass(frozen=True)
class ControlPlaneDependencies:
    """Pre-authorized dependency callables consumed by route groups."""

    require_roles: RoleDependencyFactory
    require_generic_worker: PrincipalDependency
    require_replay_worker: PrincipalDependency


_WORKER_CONFLICT_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_409_CONFLICT: {
        "model": ControlPlaneConflictResponse,
        "description": (
            "The Control Plane state, Run fence, or Worker lease rejected the operation."
        ),
    }
}


def register_health_and_ui_routes(
    app: FastAPI,
    *,
    repository: ControlPlaneRepository,
) -> None:
    """Register unauthenticated health probes and immutable console assets."""

    @app.get("/healthz", include_in_schema=False)
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/readyz", include_in_schema=False)
    def ready() -> dict[str, str]:
        with repository.engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return {"status": "ready"}

    @app.get("/ui", include_in_schema=False)
    @app.get("/ui/", include_in_schema=False)
    def web_console() -> Response:
        return console_index_response()

    @app.get("/ui/assets/app.css", include_in_schema=False)
    def web_console_css() -> Response:
        return console_asset_response("app.css")

    @app.get("/ui/assets/app.js", include_in_schema=False)
    def web_console_javascript() -> Response:
        return console_asset_response("app.js")

    @app.get("/ui/assets/protocol.js", include_in_schema=False)
    def web_console_protocol() -> Response:
        return console_asset_response("protocol.js")

    @app.get("/ui/assets/render.js", include_in_schema=False)
    def web_console_render_helpers() -> Response:
        return console_asset_response("render.js")


def register_session_and_run_routes(
    app: FastAPI,
    *,
    service: ControlPlaneService,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register operator/auditor session, Run, event, and Job read routes."""

    require_roles = dependencies.require_roles

    @app.get("/v1/session", response_model=Principal)
    def get_session(
        principal: Annotated[
            Principal,
            Depends(
                require_roles(
                    PrincipalRole.OPERATOR,
                    PrincipalRole.APPROVER,
                    PrincipalRole.AUDITOR,
                )
            ),
        ],
    ) -> Principal:
        return principal

    @app.post("/v1/runs", response_model=SubmissionView)
    def submit_run(
        request: SubmitRunRequest,
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.OPERATOR))],
    ) -> SubmissionView:
        return service.submit_run(request, actor=principal.subject)

    @app.get("/v1/runs", response_model=RunListView)
    def list_runs(
        _principal: Annotated[
            Principal,
            Depends(
                require_roles(
                    PrincipalRole.OPERATOR,
                    PrincipalRole.APPROVER,
                    PrincipalRole.AUDITOR,
                )
            ),
        ],
        state_filter: Annotated[RunState | None, Query(alias="state")] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        offset: Annotated[int, Query(ge=0, le=10_000)] = 0,
    ) -> RunListView:
        return service.list_runs(state=state_filter, limit=limit, offset=offset)

    @app.get("/v1/runs/{run_id}", response_model=RunView)
    def get_run(
        run_id: str,
        _principal: Annotated[
            Principal,
            Depends(
                require_roles(
                    PrincipalRole.OPERATOR,
                    PrincipalRole.APPROVER,
                    PrincipalRole.AUDITOR,
                )
            ),
        ],
    ) -> RunView:
        return service.get_run(run_id)

    @app.get("/v1/runs/{run_id}/approval", response_model=ApprovalView | None)
    def get_current_approval(
        run_id: str,
        principal: Annotated[
            Principal,
            Depends(
                require_roles(
                    PrincipalRole.OPERATOR,
                    PrincipalRole.APPROVER,
                    PrincipalRole.AUDITOR,
                )
            ),
        ],
    ) -> ApprovalView | None:
        return service.get_current_approval(run_id, actor=principal.subject)

    @app.post("/v1/runs/{run_id}/cancel", response_model=CancelRunView)
    def cancel_run(
        run_id: str,
        request: CancelRunRequest,
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.OPERATOR))],
    ) -> CancelRunView:
        return service.cancel_run(run_id, request, actor=principal.subject)

    @app.get("/v1/runs/{run_id}/events", response_model=list[AuditEventView])
    def list_events(
        run_id: str,
        _principal: Annotated[
            Principal,
            Depends(
                require_roles(
                    PrincipalRole.OPERATOR,
                    PrincipalRole.APPROVER,
                    PrincipalRole.AUDITOR,
                )
            ),
        ],
        limit: Annotated[int, Query(ge=1, le=MAX_AUDIT_EVENT_PAGE_SIZE)] = (
            MAX_AUDIT_EVENT_PAGE_SIZE
        ),
        before: Annotated[int | None, Query(ge=1, le=2_147_483_647)] = None,
    ) -> list[AuditEventView]:
        return service.list_events(
            run_id,
            limit=limit,
            before_sequence=before,
        )

    @app.get("/v1/jobs/{job_id}", response_model=JobView)
    def get_job(
        job_id: str,
        _principal: Annotated[
            Principal,
            Depends(
                require_roles(
                    PrincipalRole.OPERATOR,
                    PrincipalRole.APPROVER,
                    PrincipalRole.AUDITOR,
                )
            ),
        ],
    ) -> JobView:
        return service.get_job(job_id)


def register_generic_worker_claim_route(
    app: FastAPI,
    *,
    service: ControlPlaneService,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register the generic Worker's long-poll claim route."""

    @app.post("/v1/worker/jobs/claim", response_model=ClaimedJob | None)
    async def claim_job(
        request: ClaimJobRequest,
        principal: Annotated[Principal, Depends(dependencies.require_generic_worker)],
        response: Response,
    ) -> ClaimedJob | None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + request.wait_seconds
        immediate = request.model_copy(update={"wait_seconds": 0})
        while True:
            claimed = await asyncio.to_thread(
                partial(service.claim_job, immediate, actor=principal.subject)
            )
            if claimed is not None:
                return claimed
            remaining = deadline - loop.time()
            if remaining <= 0:
                response.status_code = status.HTTP_204_NO_CONTENT
                return None
            await asyncio.sleep(min(0.25, remaining))


def register_replay_worker_routes(
    app: FastAPI,
    *,
    service: ControlPlaneService,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register routes available only to a configured Replay Worker subject."""

    @app.post(
        "/v1/worker/replay/jobs/claim",
        response_model=ReplayExecutionClaimView | None,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    async def claim_replay_job(
        request: ReplayClaimRequest,
        principal: Annotated[Principal, Depends(dependencies.require_replay_worker)],
        response: Response,
    ) -> ReplayExecutionClaimView | None:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + request.wait_seconds
        immediate = request.model_copy(update={"wait_seconds": 0})
        while True:
            claimed = await asyncio.to_thread(
                partial(service.claim_replay_job, immediate, actor=principal.subject)
            )
            if claimed is not None:
                return claimed
            remaining = deadline - loop.time()
            if remaining <= 0:
                response.status_code = status.HTTP_204_NO_CONTENT
                return None
            await asyncio.sleep(min(0.25, remaining))

    @app.post(
        "/v1/worker/replay/jobs/{job_id}/heartbeat",
        response_model=ReplayExecutionClaimView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def heartbeat_replay_job(
        job_id: str,
        request: ReplayLeaseRequest,
        principal: Annotated[Principal, Depends(dependencies.require_replay_worker)],
    ) -> ReplayExecutionClaimView:
        return service.heartbeat_replay_job(job_id, request, actor=principal.subject)

    @app.post(
        "/v1/worker/replay/jobs/{job_id}/tool-permits",
        response_model=ReplayToolPermitView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def issue_replay_tool_permit(
        job_id: str,
        request: ReplayToolPermitRequest,
        principal: Annotated[Principal, Depends(dependencies.require_replay_worker)],
    ) -> ReplayToolPermitView:
        return service.issue_replay_tool_permit(job_id, request, actor=principal.subject)

    @app.post(
        "/v1/worker/replay/jobs/{job_id}/finalize",
        response_model=ReplayFinalizationView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def finalize_replay_job(
        job_id: str,
        request: ReplayFinalizeRequest,
        principal: Annotated[Principal, Depends(dependencies.require_replay_worker)],
    ) -> ReplayFinalizationView:
        return service.finalize_replay_job(job_id, request, actor=principal.subject)


def register_generic_worker_job_routes(
    app: FastAPI,
    *,
    service: ControlPlaneService,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register lease-fenced mutation routes for the generic Worker."""

    @app.post(
        "/v1/worker/jobs/{job_id}/heartbeat",
        response_model=JobView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def heartbeat(
        job_id: str,
        request: LeaseRequest,
        principal: Annotated[Principal, Depends(dependencies.require_generic_worker)],
    ) -> JobView:
        return service.heartbeat(job_id, request, actor=principal.subject)

    @app.post(
        "/v1/worker/jobs/{job_id}/complete",
        response_model=JobView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def complete_job(
        job_id: str,
        request: CompleteJobRequest,
        principal: Annotated[Principal, Depends(dependencies.require_generic_worker)],
    ) -> JobView:
        return service.complete_job(job_id, request, actor=principal.subject)

    @app.post(
        "/v1/worker/jobs/{job_id}/fail",
        response_model=JobView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def fail_job(
        job_id: str,
        request: FailJobRequest,
        principal: Annotated[Principal, Depends(dependencies.require_generic_worker)],
    ) -> JobView:
        return service.fail_job(job_id, request, actor=principal.subject)

    @app.post(
        "/v1/worker/jobs/{job_id}/checkpoints",
        response_model=CheckpointCreationView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def create_checkpoint(
        job_id: str,
        request: CreateCheckpointRequest,
        principal: Annotated[Principal, Depends(dependencies.require_generic_worker)],
    ) -> CheckpointCreationView:
        return service.create_checkpoint(job_id, request, actor=principal.subject)


def register_approval_and_maintenance_routes(
    app: FastAPI,
    *,
    service: ControlPlaneService,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register approval, resume, and explicit maintenance operations."""

    require_roles = dependencies.require_roles

    @app.post("/v1/approvals/{approval_id}/decision", response_model=ApprovalView)
    def decide_approval(
        approval_id: str,
        request: DecideApprovalRequest,
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.APPROVER))],
    ) -> ApprovalView:
        return service.decide_approval(approval_id, request, actor=principal.subject)

    @app.post("/v1/checkpoints/{checkpoint_id}/resume", response_model=ResumeView)
    def resume_checkpoint(
        checkpoint_id: str,
        request: ResumeCheckpointRequest,
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.OPERATOR))],
    ) -> ResumeView:
        return service.resume_checkpoint(
            checkpoint_id, request.approval_id, actor=principal.subject
        )

    @app.post("/v1/maintenance/requeue-expired")
    def requeue_expired(
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.OPERATOR))],
    ) -> dict[str, int]:
        return {"requeuedOrDeadLettered": service.requeue_expired(actor=principal.subject)}


def register_control_plane_routes(
    app: FastAPI,
    *,
    repository: ControlPlaneRepository,
    service: ControlPlaneService,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register all route groups in the established public route order."""

    register_health_and_ui_routes(app, repository=repository)
    register_session_and_run_routes(
        app,
        service=service,
        dependencies=dependencies,
    )
    # Preserve the established route/OpenAPI order while keeping the two Worker
    # security domains in separately registered groups.
    register_generic_worker_claim_route(
        app,
        service=service,
        dependencies=dependencies,
    )
    register_replay_worker_routes(
        app,
        service=service,
        dependencies=dependencies,
    )
    register_generic_worker_job_routes(
        app,
        service=service,
        dependencies=dependencies,
    )
    register_approval_and_maintenance_routes(
        app,
        service=service,
        dependencies=dependencies,
    )
