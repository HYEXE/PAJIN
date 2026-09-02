"""Route-group registration for the PAJIN Control Plane API.

Keeping endpoint definitions outside the application composition root makes the
security boundary visible: every protected group receives an already-built
dependency rather than rebuilding authentication or role checks locally.
"""

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from functools import partial
from threading import Lock
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response, status
from fastapi import Path as FastAPIPath
from sqlalchemy import text

from pajin.control_plane.artifact_transfer import (
    PortableArtifactMultipartPartView,
    PortableArtifactMultipartUploadView,
)
from pajin.control_plane.attestation import (
    PortableReplayAttestationBundle,
    ReplayAttestationTrustAnchor,
)
from pajin.control_plane.campaign_drafts import (
    CAMPAIGN_DRAFT_DIGEST_PATTERN,
    CampaignDraftCompilationRequest,
    CampaignDraftCompilationView,
    CampaignDraftView,
    ControlPlaneCampaignDraftCompiler,
    ControlPlaneCampaignDraftReader,
)
from pajin.control_plane.database import ControlPlaneRepository
from pajin.control_plane.decision_views import (
    GraphDecisionAuditViewIntegrityError,
    GraphDecisionAuditViewNotFound,
    GraphDecisionAuditViewTooLarge,
    GraphDecisionAuditViewUnavailable,
    VerifiedGraphDecisionAuditView,
    VerifiedGraphDecisionAuditViewReader,
)
from pajin.control_plane.discovery_views import (
    DiscoveryViewIntegrityError,
    DiscoveryViewNotFound,
    DiscoveryViewUnavailable,
    VerifiedDiscoverySurfaceWaveView,
    VerifiedDiscoveryViewReader,
)
from pajin.control_plane.graph_views import (
    CanonicalGraphViewIntegrityError,
    CanonicalGraphViewNotFound,
    CanonicalGraphViewTooLarge,
    CanonicalGraphViewUnavailable,
    HypothesisAttentionRankingIntegrityError,
    HypothesisAttentionRankingNotFound,
    HypothesisAttentionRankingTooLarge,
    HypothesisAttentionRankingUnavailable,
    VerifiedCanonicalGraphView,
    VerifiedCanonicalGraphViewReader,
    VerifiedHypothesisAttentionRankingReader,
    VerifiedHypothesisAttentionRankingView,
)
from pajin.control_plane.models import (
    AdmitSourceArtifactRequest,
    ApprovalView,
    ArtifactRef,
    AuditEventView,
    CancelRunRequest,
    CancelRunView,
    CheckpointCreationView,
    ClaimedJob,
    ClaimJobRequest,
    CompleteJobRequest,
    ControlPlaneConflictResponse,
    CreateCheckpointRequest,
    CreateReplayBatchRequest,
    DecideApprovalRequest,
    FailJobRequest,
    HumanReviewQueueView,
    JobView,
    LeaseRequest,
    Principal,
    PrincipalRole,
    ReplayArtifactUploadBeginRequest,
    ReplayArtifactUploadPartRequest,
    ReplayBatchView,
    ReplayClaimRequest,
    ReplayExecutionClaimView,
    ReplayFinalizationView,
    ReplayFinalizeRequest,
    ReplayItemView,
    ReplayLeaseRequest,
    ReplayProjectionView,
    ReplayTicketView,
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
from pajin.control_plane.pentest_recon import (
    PentestReconDispatchRuntime,
    PentestReconOperatorDispatchRequest,
    PentestReconOperatorDispatchView,
)
from pajin.control_plane.pentest_replay import (
    PentestReplayDispatchRuntime,
    PentestReplayOperatorDispatchRequest,
    PentestReplayOperatorDispatchView,
)
from pajin.control_plane.pentest_workflow import (
    PentestOperatorWorkflowRequest,
    PentestOperatorWorkflowRuntime,
    PentestOperatorWorkflowView,
)
from pajin.control_plane.pentest_workflow_coordination import (
    PentestWorkflowCoordinationDispatchRuntime,
    PentestWorkflowCoordinationRequest,
    PentestWorkflowCoordinationView,
)
from pajin.control_plane.replay_comparison import (
    ReplayComparisonIntegrityError,
    VerifiedReplayEvidenceComparisonReader,
    VerifiedReplayEvidenceComparisonView,
)
from pajin.control_plane.service import MAX_AUDIT_EVENT_PAGE_SIZE, ControlPlaneService
from pajin.control_plane.validation_comparison import (
    VerifiedWalkingControlComparisonReader,
    VerifiedWalkingControlComparisonView,
    WalkingControlComparisonIntegrityError,
    WalkingControlComparisonNotFound,
    WalkingControlComparisonUnavailable,
)
from pajin.control_plane.web_console import console_asset_response, console_index_response

if TYPE_CHECKING:
    from pajin.workflow.ai_measured_product_reader import AIMeasuredProductReader
    from pajin.workflow.network_measured_product_reader import NetworkMeasuredProductReader
    from pajin.workflow.web_measured_product_reader import WebMeasuredProductReader

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

_PUBLIC_REPLAY_CONFLICT_RESPONSES: dict[int | str, dict[str, Any]] = {
    status.HTTP_409_CONFLICT: {
        "model": ControlPlaneConflictResponse,
        "description": ("The managed Artifact or Replay authority graph rejected the admission."),
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

    @app.get("/v1/review-queue", response_model=HumanReviewQueueView)
    def list_human_review_queue(
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
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
    ) -> HumanReviewQueueView:
        return service.list_human_review_queue(limit=limit)

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


def register_campaign_draft_routes(
    app: FastAPI,
    *,
    reader: ControlPlaneCampaignDraftReader,
    compiler: ControlPlaneCampaignDraftCompiler,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register operator-only Campaign draft reads and exact compiler handoff."""

    @app.get("/v1/campaign-drafts/{draft_digest}", response_model=CampaignDraftView)
    def get_campaign_draft(
        draft_digest: Annotated[
            str,
            FastAPIPath(
                min_length=64,
                max_length=64,
                pattern=CAMPAIGN_DRAFT_DIGEST_PATTERN,
            ),
        ],
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> CampaignDraftView:
        return reader.get(draft_digest)

    @app.post(
        "/v1/campaign-drafts/{draft_digest}/compile",
        response_model=CampaignDraftCompilationView,
    )
    def compile_campaign_draft(
        draft_digest: Annotated[
            str,
            FastAPIPath(
                min_length=64,
                max_length=64,
                pattern=CAMPAIGN_DRAFT_DIGEST_PATTERN,
            ),
        ],
        request: CampaignDraftCompilationRequest,
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> CampaignDraftCompilationView:
        return compiler.compile(draft_digest, request)


def register_discovery_view_routes(
    app: FastAPI,
    *,
    reader: VerifiedDiscoveryViewReader,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register the Operator-only sealed Discovery Surface/Wave projection."""

    @app.get(
        "/v1/discovery/campaigns/{campaign}/hypothesis-runs/{hypothesis_run_id}",
        response_model=VerifiedDiscoverySurfaceWaveView,
    )
    def get_verified_discovery_surface_wave_view(
        campaign: Annotated[
            str,
            FastAPIPath(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$"),
        ],
        hypothesis_run_id: Annotated[
            str,
            FastAPIPath(pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"),
        ],
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> VerifiedDiscoverySurfaceWaveView:
        try:
            return reader.read(
                campaign=campaign,
                hypothesis_run_id=hypothesis_run_id,
            )
        except DiscoveryViewUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except DiscoveryViewNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except DiscoveryViewIntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="Discovery Surface/Wave authority is not integrity-valid",
            ) from exc


def register_graph_view_routes(
    app: FastAPI,
    *,
    reader: VerifiedCanonicalGraphViewReader,
    ranking_reader: VerifiedHypothesisAttentionRankingReader,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register Operator-only current Graph and Hypothesis review views."""

    @app.get(
        "/v1/graphs/campaigns/{campaign}/snapshots/{snapshot_id}",
        response_model=VerifiedCanonicalGraphView,
    )
    def get_verified_canonical_graph_view(
        campaign: Annotated[
            str,
            FastAPIPath(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$"),
        ],
        snapshot_id: Annotated[
            str,
            FastAPIPath(pattern=r"^graph-snapshot_[a-f0-9]{64}$"),
        ],
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> VerifiedCanonicalGraphView:
        try:
            return reader.read(campaign=campaign, snapshot_id=snapshot_id)
        except CanonicalGraphViewUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except CanonicalGraphViewNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except CanonicalGraphViewTooLarge as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except CanonicalGraphViewIntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="Canonical Graph authority is not integrity-valid",
            ) from exc

    @app.get(
        ("/v1/hypotheses/campaigns/{campaign}/snapshots/{snapshot_id}/attention-ranking"),
        response_model=VerifiedHypothesisAttentionRankingView,
    )
    def get_verified_hypothesis_attention_ranking(
        campaign: Annotated[
            str,
            FastAPIPath(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$"),
        ],
        snapshot_id: Annotated[
            str,
            FastAPIPath(pattern=r"^graph-snapshot_[a-f0-9]{64}$"),
        ],
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> VerifiedHypothesisAttentionRankingView:
        try:
            return ranking_reader.read(campaign=campaign, snapshot_id=snapshot_id)
        except HypothesisAttentionRankingUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except HypothesisAttentionRankingNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except HypothesisAttentionRankingTooLarge as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except HypothesisAttentionRankingIntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="Hypothesis attention ranking authority is not integrity-valid",
            ) from exc


def register_decision_audit_routes(
    app: FastAPI,
    *,
    reader: VerifiedGraphDecisionAuditViewReader,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register the Operator-only complete Graph Decision audit view."""

    @app.get(
        "/v1/decisions/campaigns/{campaign}/snapshots/{snapshot_id}/audit",
        response_model=VerifiedGraphDecisionAuditView,
    )
    def get_verified_graph_decision_audit(
        campaign: Annotated[
            str,
            FastAPIPath(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$"),
        ],
        snapshot_id: Annotated[
            str,
            FastAPIPath(pattern=r"^graph-snapshot_[a-f0-9]{64}$"),
        ],
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> VerifiedGraphDecisionAuditView:
        try:
            return reader.read(campaign=campaign, snapshot_id=snapshot_id)
        except GraphDecisionAuditViewUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except GraphDecisionAuditViewNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except GraphDecisionAuditViewTooLarge as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except GraphDecisionAuditViewIntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="Graph Decision audit authority is not integrity-valid",
            ) from exc


def register_replay_comparison_routes(
    app: FastAPI,
    *,
    reader: VerifiedReplayEvidenceComparisonReader,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register the Operator-only coordinate comparison for one Replay projection."""

    @app.get(
        "/v1/replay-comparisons/batches/{batch_id}",
        response_model=VerifiedReplayEvidenceComparisonView,
    )
    def get_verified_replay_evidence_comparison(
        batch_id: Annotated[
            str,
            FastAPIPath(pattern=r"^replay-batch_[0-9a-f]{32}$"),
        ],
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> VerifiedReplayEvidenceComparisonView:
        try:
            return reader.read(batch_id=batch_id)
        except ReplayComparisonIntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="Replay comparison authority is not integrity-valid",
            ) from exc


def register_validation_comparison_routes(
    app: FastAPI,
    *,
    reader: VerifiedWalkingControlComparisonReader,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register the Operator-only exact sealed VAL-004C comparison view."""

    @app.get(
        "/v1/validation-comparisons/walking/{comparison_id}",
        response_model=VerifiedWalkingControlComparisonView,
    )
    def get_verified_walking_control_comparison(
        comparison_id: Annotated[
            str,
            FastAPIPath(pattern=r"^walking-control-comparison_[a-f0-9]{64}$"),
        ],
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> VerifiedWalkingControlComparisonView:
        try:
            return reader.read(comparison_id=comparison_id)
        except WalkingControlComparisonUnavailable as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except WalkingControlComparisonNotFound as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except WalkingControlComparisonIntegrityError as exc:
            raise HTTPException(
                status_code=409,
                detail="Walking Control comparison authority is not integrity-valid",
            ) from exc


def register_web_measured_product_route(
    app: FastAPI,
    *,
    reader: "WebMeasuredProductReader | None",
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register one body-free Operator read over the exact UX-009B reader."""

    from pajin.workflow.web_measured_product_flow import WebMeasuredProductFlowProjection
    from pajin.workflow.web_measured_product_reader import (
        WebMeasuredProductReader,
        WebMeasuredProductReaderError,
    )

    if reader is not None and type(reader) is not WebMeasuredProductReader:
        raise TypeError("Measured Web product reads require the exact UX-009B reader")

    reader_lock = Lock()

    def read_serialized(
        configured_reader: WebMeasuredProductReader,
    ) -> WebMeasuredProductFlowProjection:
        with reader_lock:
            return configured_reader.read()

    @app.get(
        "/v1/products/web-measured-flow",
        response_model=WebMeasuredProductFlowProjection,
    )
    async def get_web_measured_product_flow(
        request: Request,
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> WebMeasuredProductFlowProjection:
        if request.scope.get("query_string", b"") or await request.body():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Measured Web product read accepts no query or request body",
            )
        configured_reader = reader
        if configured_reader is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Measured Web product read is not configured",
            )
        try:
            return await asyncio.to_thread(read_serialized, configured_reader)
        except WebMeasuredProductReaderError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Measured Web product authority is not integrity-valid",
            ) from exc


def register_network_measured_product_route(
    app: FastAPI,
    *,
    reader: "NetworkMeasuredProductReader | None",
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register one body-free Operator read over the exact NET-002D reader."""

    from pajin.workflow.network_measured_product_flow import NetworkMeasuredProduct
    from pajin.workflow.network_measured_product_reader import (
        NetworkMeasuredProductReader,
        NetworkMeasuredProductReaderError,
    )

    if reader is not None and type(reader) is not NetworkMeasuredProductReader:
        raise TypeError("Measured Network product reads require the exact NET-002D reader")

    reader_lock = Lock()

    def read_serialized(
        configured_reader: NetworkMeasuredProductReader,
    ) -> NetworkMeasuredProduct:
        with reader_lock:
            return configured_reader.read()

    @app.get(
        "/v1/products/network-measured-service-identification",
        response_model=NetworkMeasuredProduct,
    )
    async def get_network_measured_service_identification(
        request: Request,
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> NetworkMeasuredProduct:
        if request.scope.get("query_string", b"") or await request.body():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Measured Network product read accepts no query or request body",
            )
        configured_reader = reader
        if configured_reader is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Measured Network product read is not configured",
            )
        try:
            return await asyncio.to_thread(read_serialized, configured_reader)
        except NetworkMeasuredProductReaderError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Measured Network product authority is not integrity-valid",
            ) from exc


def register_ai_measured_product_route(
    app: FastAPI,
    *,
    reader: "AIMeasuredProductReader | None",
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register one body-free Operator read over the exact AI-002D reader."""

    from pajin.workflow.ai_measured_product_flow import AIMeasuredProduct
    from pajin.workflow.ai_measured_product_reader import (
        AIMeasuredProductReader,
        AIMeasuredProductReaderError,
    )

    if reader is not None and type(reader) is not AIMeasuredProductReader:
        raise TypeError("Measured AI product reads require the exact AI-002D reader")

    reader_lock = Lock()

    def read_serialized(configured_reader: AIMeasuredProductReader) -> AIMeasuredProduct:
        with reader_lock:
            return configured_reader.read()

    @app.get(
        "/v1/products/ai-measured-system-prompt-disclosure",
        response_model=AIMeasuredProduct,
    )
    async def get_ai_measured_system_prompt_disclosure(
        request: Request,
        _principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> AIMeasuredProduct:
        if request.scope.get("query_string", b"") or await request.body():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Measured AI product read accepts no query or request body",
            )
        configured_reader = reader
        if configured_reader is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Measured AI product read is not configured",
            )
        try:
            return await asyncio.to_thread(read_serialized, configured_reader)
        except AIMeasuredProductReaderError as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Measured AI product authority is not integrity-valid",
            ) from exc


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


def register_pentest_recon_worker_route(
    app: FastAPI,
    *,
    runtime: PentestReconDispatchRuntime | None,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Dispatch one pinned Recon only from an authenticated direct-mTLS Worker call."""

    @app.post(
        "/v1/worker/pentest/recon/dispatch",
        response_model=PentestReconOperatorDispatchView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    async def dispatch_pentest_recon(
        dispatch_request: PentestReconOperatorDispatchRequest,
        http_request: Request,
        principal: Annotated[Principal, Depends(dependencies.require_generic_worker)],
    ) -> PentestReconOperatorDispatchView:
        if runtime is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Pentest Recon execution is not configured",
            )
        try:
            return await runtime.dispatch_once(
                dispatch_request,
                worker_scope=http_request.scope,
                worker_principal=principal,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Pentest Recon dispatch failed closed",
            ) from exc


def register_pentest_replay_worker_route(
    app: FastAPI,
    *,
    runtime: PentestReplayDispatchRuntime | None,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Dispatch one pinned Replay only from its dedicated Replay Worker session."""

    @app.post(
        "/v1/worker/pentest/replay/dispatch",
        response_model=PentestReplayOperatorDispatchView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    async def dispatch_pentest_replay(
        dispatch_request: PentestReplayOperatorDispatchRequest,
        http_request: Request,
        principal: Annotated[Principal, Depends(dependencies.require_replay_worker)],
    ) -> PentestReplayOperatorDispatchView:
        if runtime is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Pentest Replay execution is not configured",
            )
        try:
            return await runtime.dispatch_once(
                dispatch_request,
                worker_scope=http_request.scope,
                worker_principal=principal,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Pentest Replay dispatch failed closed",
            ) from exc


def register_pentest_workflow_coordination_routes(
    app: FastAPI,
    *,
    runtime: PentestWorkflowCoordinationDispatchRuntime | None,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Keep generic and Replay coordination calls in separate mTLS domains."""

    @app.post(
        "/v1/worker/pentest/workflows/stages/recon/dispatch",
        response_model=PentestWorkflowCoordinationView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    async def dispatch_pentest_workflow_recon_stage(
        dispatch_request: PentestWorkflowCoordinationRequest,
        http_request: Request,
        principal: Annotated[Principal, Depends(dependencies.require_generic_worker)],
    ) -> PentestWorkflowCoordinationView:
        if runtime is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Pentest workflow coordination is not configured",
            )
        try:
            return await runtime.dispatch_recon_stage(
                dispatch_request,
                worker_scope=http_request.scope,
                worker_principal=principal,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Pentest workflow Recon stage failed closed",
            ) from exc

    @app.post(
        "/v1/worker/pentest/workflows/stages/replay/dispatch",
        response_model=PentestWorkflowCoordinationView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    async def dispatch_pentest_workflow_replay_stage(
        dispatch_request: PentestWorkflowCoordinationRequest,
        http_request: Request,
        principal: Annotated[Principal, Depends(dependencies.require_replay_worker)],
    ) -> PentestWorkflowCoordinationView:
        if runtime is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Pentest workflow coordination is not configured",
            )
        try:
            return await runtime.dispatch_replay_stage(
                dispatch_request,
                worker_scope=http_request.scope,
                worker_principal=principal,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Pentest workflow Replay stage failed closed",
            ) from exc


def register_pentest_operator_workflow_route(
    app: FastAPI,
    *,
    runtime: PentestOperatorWorkflowRuntime | None,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Prepare or finalize one deployment-pinned, body-free operator workflow."""

    @app.post(
        "/v1/pentest/workflows/run",
        response_model=PentestOperatorWorkflowView,
    )
    def run_pentest_operator_workflow(
        workflow_request: PentestOperatorWorkflowRequest,
        principal: Annotated[
            Principal,
            Depends(dependencies.require_roles(PrincipalRole.OPERATOR)),
        ],
    ) -> PentestOperatorWorkflowView:
        if runtime is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Pentest operator workflow is not configured",
            )
        try:
            return runtime.run(workflow_request, principal=principal)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Pentest operator workflow failed closed",
            ) from exc


def register_public_replay_routes(
    app: FastAPI,
    *,
    service: ControlPlaneService,
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register opaque Operator admission and non-secret Replay reads.

    These routes never accept a raw path, URL, Candidate, contract, Capability,
    Tool request, verdict, or internal Job kind.  Replay issuance remains an
    internal service operation after server-owned admission and derivation.
    """

    require_roles = dependencies.require_roles
    require_reader = require_roles(
        PrincipalRole.OPERATOR,
        PrincipalRole.APPROVER,
        PrincipalRole.AUDITOR,
    )

    @app.post(
        "/v1/replay/source-artifacts",
        response_model=ArtifactRef,
        responses=_PUBLIC_REPLAY_CONFLICT_RESPONSES,
    )
    def admit_replay_source_artifact(
        request: AdmitSourceArtifactRequest,
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.OPERATOR))],
    ) -> ArtifactRef:
        return service.admit_source_artifact(request, actor=principal.subject)

    @app.post(
        "/v1/replay/batches",
        response_model=ReplayBatchView,
        responses=_PUBLIC_REPLAY_CONFLICT_RESPONSES,
    )
    def admit_replay_batch(
        request: CreateReplayBatchRequest,
        principal: Annotated[Principal, Depends(require_roles(PrincipalRole.OPERATOR))],
    ) -> ReplayBatchView:
        return service.create_replay_batch(request, actor=principal.subject)

    @app.get("/v1/replay/batches/{batch_id}", response_model=ReplayBatchView)
    def get_replay_batch(
        batch_id: str,
        _principal: Annotated[Principal, Depends(require_reader)],
    ) -> ReplayBatchView:
        return service.get_replay_batch(batch_id)

    @app.get(
        "/v1/replay/batches/{batch_id}/projection",
        response_model=ReplayProjectionView | None,
    )
    def get_replay_projection(
        batch_id: str,
        _principal: Annotated[Principal, Depends(require_reader)],
    ) -> ReplayProjectionView | None:
        return service.get_replay_projection(batch_id)

    @app.get(
        "/v1/replay/batches/{batch_id}/attestation",
        response_model=PortableReplayAttestationBundle | None,
    )
    def get_replay_attestation(
        batch_id: str,
        _principal: Annotated[Principal, Depends(require_reader)],
    ) -> PortableReplayAttestationBundle | None:
        return service.get_replay_attestation(batch_id)

    @app.get(
        "/v1/replay/attestation/trust-anchor",
        response_model=ReplayAttestationTrustAnchor | None,
    )
    def get_replay_attestation_trust_anchor(
        _principal: Annotated[Principal, Depends(require_reader)],
    ) -> ReplayAttestationTrustAnchor | None:
        return service.get_replay_attestation_trust_anchor()

    @app.get("/v1/replay/items/{item_id}", response_model=ReplayItemView)
    def get_replay_item(
        item_id: str,
        _principal: Annotated[Principal, Depends(require_reader)],
    ) -> ReplayItemView:
        return service.get_replay_item(item_id)

    @app.get("/v1/replay/tickets/{ticket_id}", response_model=ReplayTicketView)
    def get_replay_ticket(
        ticket_id: str,
        _principal: Annotated[Principal, Depends(require_reader)],
    ) -> ReplayTicketView:
        return service.get_replay_ticket(ticket_id)

    @app.get(
        "/v1/replay/tickets/{ticket_id}/finalization",
        response_model=ReplayFinalizationView | None,
    )
    def get_replay_finalization(
        ticket_id: str,
        _principal: Annotated[Principal, Depends(require_reader)],
    ) -> ReplayFinalizationView | None:
        return service.get_replay_finalization(ticket_id)


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
        "/v1/worker/replay/jobs/{job_id}/artifact-upload",
        response_model=PortableArtifactMultipartUploadView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def begin_replay_artifact_upload(
        job_id: str,
        request: ReplayArtifactUploadBeginRequest,
        principal: Annotated[Principal, Depends(dependencies.require_replay_worker)],
    ) -> PortableArtifactMultipartUploadView:
        return service.begin_replay_artifact_upload(
            job_id,
            request,
            actor=principal.subject,
        )

    @app.put(
        "/v1/worker/replay/jobs/{job_id}/artifact-upload/parts",
        response_model=PortableArtifactMultipartPartView,
        responses=_WORKER_CONFLICT_RESPONSES,
    )
    def put_replay_artifact_upload_part(
        job_id: str,
        request: ReplayArtifactUploadPartRequest,
        principal: Annotated[Principal, Depends(dependencies.require_replay_worker)],
    ) -> PortableArtifactMultipartPartView:
        return service.put_replay_artifact_upload_part(
            job_id,
            request,
            actor=principal.subject,
        )

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
    campaign_draft_reader: ControlPlaneCampaignDraftReader,
    campaign_draft_compiler: ControlPlaneCampaignDraftCompiler,
    discovery_view_reader: VerifiedDiscoveryViewReader,
    graph_view_reader: VerifiedCanonicalGraphViewReader,
    hypothesis_attention_ranking_reader: VerifiedHypothesisAttentionRankingReader,
    decision_audit_reader: VerifiedGraphDecisionAuditViewReader,
    replay_comparison_reader: VerifiedReplayEvidenceComparisonReader,
    validation_comparison_reader: VerifiedWalkingControlComparisonReader,
    ai_measured_product_reader: "AIMeasuredProductReader | None",
    network_measured_product_reader: "NetworkMeasuredProductReader | None",
    web_measured_product_reader: "WebMeasuredProductReader | None",
    pentest_recon_runtime: PentestReconDispatchRuntime | None,
    pentest_replay_runtime: PentestReplayDispatchRuntime | None,
    pentest_workflow_runtime: PentestOperatorWorkflowRuntime | None,
    pentest_workflow_coordination_runtime: (PentestWorkflowCoordinationDispatchRuntime | None),
    dependencies: ControlPlaneDependencies,
) -> None:
    """Register all route groups in the established public route order."""

    register_health_and_ui_routes(app, repository=repository)
    register_session_and_run_routes(
        app,
        service=service,
        dependencies=dependencies,
    )
    register_campaign_draft_routes(
        app,
        reader=campaign_draft_reader,
        compiler=campaign_draft_compiler,
        dependencies=dependencies,
    )
    register_discovery_view_routes(
        app,
        reader=discovery_view_reader,
        dependencies=dependencies,
    )
    register_graph_view_routes(
        app,
        reader=graph_view_reader,
        ranking_reader=hypothesis_attention_ranking_reader,
        dependencies=dependencies,
    )
    register_decision_audit_routes(
        app,
        reader=decision_audit_reader,
        dependencies=dependencies,
    )
    register_replay_comparison_routes(
        app,
        reader=replay_comparison_reader,
        dependencies=dependencies,
    )
    register_validation_comparison_routes(
        app,
        reader=validation_comparison_reader,
        dependencies=dependencies,
    )
    register_web_measured_product_route(
        app,
        reader=web_measured_product_reader,
        dependencies=dependencies,
    )
    register_network_measured_product_route(
        app,
        reader=network_measured_product_reader,
        dependencies=dependencies,
    )
    register_ai_measured_product_route(
        app,
        reader=ai_measured_product_reader,
        dependencies=dependencies,
    )
    register_public_replay_routes(
        app,
        service=service,
        dependencies=dependencies,
    )
    register_pentest_operator_workflow_route(
        app,
        runtime=pentest_workflow_runtime,
        dependencies=dependencies,
    )
    # Preserve the established route/OpenAPI order while keeping the two Worker
    # security domains in separately registered groups.
    register_generic_worker_claim_route(
        app,
        service=service,
        dependencies=dependencies,
    )
    register_pentest_recon_worker_route(
        app,
        runtime=pentest_recon_runtime,
        dependencies=dependencies,
    )
    register_pentest_workflow_coordination_routes(
        app,
        runtime=pentest_workflow_coordination_runtime,
        dependencies=dependencies,
    )
    register_replay_worker_routes(
        app,
        service=service,
        dependencies=dependencies,
    )
    register_pentest_replay_worker_route(
        app,
        runtime=pentest_replay_runtime,
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
