"""Authenticated FastAPI surface for the PAJIN Control Plane."""

import asyncio
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import text

from pajin.control_plane.artifacts import ManagedArtifactRepository
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
    ControlPlaneConflictCode,
    ControlPlaneConflictResponse,
    CreateCheckpointRequest,
    DecideApprovalRequest,
    FailJobRequest,
    JobView,
    LeaseRequest,
    Principal,
    PrincipalRole,
    ResumeCheckpointRequest,
    ResumeView,
    RunListView,
    RunState,
    RunView,
    SubmissionView,
    SubmitRunRequest,
)
from pajin.control_plane.security import (
    AuthenticationError,
    CheckpointIntegrityError,
    CheckpointSigner,
    TokenAuthenticator,
)
from pajin.control_plane.service import (
    ControlPlaneError,
    ControlPlaneService,
    LeaseRejected,
    ResourceNotFound,
    RunCancelled,
    StateConflict,
)
from pajin.control_plane.web_console import console_asset_response, console_index_response

_WORKER_CONFLICT_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_409_CONFLICT: {
        "model": ControlPlaneConflictResponse,
        "description": (
            "The Control Plane state, Run fence, or Worker lease rejected the operation."
        ),
    }
}


@dataclass(frozen=True)
class ControlPlaneSettings:
    database_url: str
    credentials: dict[str, Principal]
    checkpoint_keys: dict[str, bytes]
    active_checkpoint_key_id: str = "v1"
    initialize_schema: bool = True
    database_echo: bool = False
    artifact_staging_root: Path | None = None
    artifact_repository_root: Path | None = None

    @classmethod
    def from_env(cls) -> "ControlPlaneSettings":
        operator_token = os.environ.get("PAJIN_CP_OPERATOR_TOKEN")
        approver_token = os.environ.get("PAJIN_CP_APPROVER_TOKEN")
        worker_token = os.environ.get("PAJIN_CP_WORKER_TOKEN")
        checkpoint_key = os.environ.get("PAJIN_CP_CHECKPOINT_KEY")
        artifact_staging_root = os.environ.get("PAJIN_CP_ARTIFACT_STAGING_ROOT")
        artifact_repository_root = os.environ.get("PAJIN_CP_ARTIFACT_REPOSITORY_ROOT")
        missing = [
            name
            for name, value in (
                ("PAJIN_CP_OPERATOR_TOKEN", operator_token),
                ("PAJIN_CP_APPROVER_TOKEN", approver_token),
                ("PAJIN_CP_WORKER_TOKEN", worker_token),
                ("PAJIN_CP_CHECKPOINT_KEY", checkpoint_key),
            )
            if value is None
        ]
        if missing:
            raise RuntimeError(f"missing required Control Plane secrets: {', '.join(missing)}")
        assert operator_token is not None
        assert approver_token is not None
        assert worker_token is not None
        assert checkpoint_key is not None
        if len({operator_token, approver_token, worker_token}) != 3:
            raise RuntimeError("Control Plane role credentials must be distinct")
        if (artifact_staging_root is None) != (artifact_repository_root is None):
            raise RuntimeError(
                "PAJIN_CP_ARTIFACT_STAGING_ROOT and "
                "PAJIN_CP_ARTIFACT_REPOSITORY_ROOT must be configured together"
            )
        key_id = os.environ.get("PAJIN_CP_CHECKPOINT_KEY_ID", "v1")
        credentials = {
            operator_token: Principal(
                subject=os.environ.get("PAJIN_CP_OPERATOR_SUBJECT", "operator"),
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            approver_token: Principal(
                subject=os.environ.get("PAJIN_CP_APPROVER_SUBJECT", "security-approver"),
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            worker_token: Principal(
                subject=os.environ.get("PAJIN_CP_WORKER_SUBJECT", "worker-service"),
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        }
        return cls(
            database_url=os.environ.get(
                "PAJIN_CP_DATABASE_URL", "sqlite:///./.pajin/control-plane.db"
            ),
            credentials=credentials,
            checkpoint_keys={key_id: checkpoint_key.encode()},
            active_checkpoint_key_id=key_id,
            initialize_schema=os.environ.get("PAJIN_CP_INITIALIZE_SCHEMA", "true").lower()
            in {"1", "true", "yes"},
            database_echo=os.environ.get("PAJIN_CP_DATABASE_ECHO", "false").lower()
            in {"1", "true", "yes"},
            artifact_staging_root=(
                Path(artifact_staging_root) if artifact_staging_root is not None else None
            ),
            artifact_repository_root=(
                Path(artifact_repository_root)
                if artifact_repository_root is not None
                else None
            ),
        )


def create_app(settings: ControlPlaneSettings | None = None) -> FastAPI:
    resolved = settings or ControlPlaneSettings.from_env()
    if (resolved.artifact_staging_root is None) != (
        resolved.artifact_repository_root is None
    ):
        raise RuntimeError(
            "artifact_staging_root and artifact_repository_root must be configured together"
        )
    repository = ControlPlaneRepository(
        resolved.database_url,
        echo=resolved.database_echo,
    )
    signer = CheckpointSigner(
        active_key_id=resolved.active_checkpoint_key_id,
        keys=resolved.checkpoint_keys,
    )
    artifact_repository = None
    if (
        resolved.artifact_staging_root is not None
        and resolved.artifact_repository_root is not None
    ):
        artifact_repository = ManagedArtifactRepository(
            staging_root=resolved.artifact_staging_root,
            repository_root=resolved.artifact_repository_root,
        )
    service = ControlPlaneService(
        repository,
        signer,
        artifact_repository=artifact_repository,
    )
    authenticator = TokenAuthenticator(resolved.credentials)
    bearer = HTTPBearer(auto_error=False)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        if resolved.initialize_schema:
            repository.initialize()
        else:
            # Deployment-managed migrations may disable DDL at process startup, but
            # they must never disable the Control Plane's schema compatibility fence.
            repository.schema_version()
        app.state.repository = repository
        app.state.artifact_repository = artifact_repository
        app.state.control_plane = service
        try:
            yield
        finally:
            repository.close()

    app = FastAPI(
        title="PAJIN Control Plane",
        version="0.1.0",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def prevent_sensitive_response_caching(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        response = await call_next(request)
        if request.url.path.startswith("/v1/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    def authenticate(
        credential: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
    ) -> Principal:
        if credential is None or credential.scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="bearer credential required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        try:
            return authenticator.authenticate(credential.credentials)
        except AuthenticationError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(exc),
                headers={"WWW-Authenticate": "Bearer"},
            ) from exc

    def require_roles(
        *required: PrincipalRole,
    ) -> Callable[[Principal], Principal]:
        def dependency(
            principal: Annotated[Principal, Depends(authenticate)],
        ) -> Principal:
            if principal.roles.isdisjoint(required):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="credential lacks the required Control Plane role",
                )
            return principal

        return dependency

    @app.exception_handler(ResourceNotFound)
    async def not_found_handler(_request: object, exc: ResourceNotFound) -> JSONResponse:
        return JSONResponse(status_code=404, content={"detail": str(exc)})

    @app.exception_handler(StateConflict)
    @app.exception_handler(LeaseRejected)
    @app.exception_handler(CheckpointIntegrityError)
    async def conflict_handler(_request: object, exc: Exception) -> JSONResponse:
        code: ControlPlaneConflictCode | None = None
        if isinstance(exc, RunCancelled):
            code = ControlPlaneConflictCode.RUN_CANCELLED
        elif isinstance(exc, LeaseRejected):
            code = ControlPlaneConflictCode.LEASE_LOST
        content = ControlPlaneConflictResponse(detail=str(exc), code=code)
        return JSONResponse(
            status_code=status.HTTP_409_CONFLICT,
            content=content.model_dump(mode="json", exclude_none=True),
        )

    @app.exception_handler(ControlPlaneError)
    async def control_error_handler(_request: object, exc: ControlPlaneError) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})

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
    ) -> ApprovalView | None:
        return service.get_current_approval(run_id)

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
    ) -> list[AuditEventView]:
        return service.list_events(run_id)

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

    @app.post("/v1/worker/jobs/claim", response_model=ClaimedJob | None)
    async def claim_job(
        request: ClaimJobRequest,
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.WORKER))],
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

    @app.post(
        "/v1/worker/jobs/{job_id}/heartbeat",
        response_model=JobView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def heartbeat(
        job_id: str,
        request: LeaseRequest,
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.WORKER))],
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
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.WORKER))],
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
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.WORKER))],
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
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.WORKER))],
    ) -> CheckpointCreationView:
        return service.create_checkpoint(job_id, request, actor=principal.subject)

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

    return app
