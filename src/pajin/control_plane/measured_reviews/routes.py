"""Human review endpoints using the application's authentication dependencies."""

import asyncio
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response

from pajin.control_plane.measured_reviews.evidence import ReviewEvidenceUnavailable
from pajin.control_plane.measured_reviews.models import (
    AssessmentRequest,
    AssignmentRequest,
    DecisionRequest,
    FollowupReviewRequest,
    MeasuredReviewView,
    NotificationAckRequest,
    NotificationReceipt,
    NotificationReceiptRequest,
    OpenReviewRequest,
    RetestRequest,
    ReviewDomain,
    ReviewEvidence,
    ReviewId,
    ReviewInbox,
    ReviewList,
    ReviewRevision,
    ReviewState,
    Subject,
)
from pajin.control_plane.measured_reviews.report import render_review_report
from pajin.control_plane.measured_reviews.search import (
    FilteredReviewInbox,
    ReviewFilters,
    ReviewSearchPage,
)
from pajin.control_plane.measured_reviews.service import MeasuredReviewService, require_review_role
from pajin.control_plane.models import Principal, PrincipalRole

if TYPE_CHECKING:
    from pajin.control_plane.api_routes import ControlPlaneDependencies


def register_measured_review_routes(
    app: FastAPI, *, service: MeasuredReviewService, dependencies: "ControlPlaneDependencies"
) -> None:
    read_role = dependencies.require_roles(
        PrincipalRole.OPERATOR, PrincipalRole.APPROVER, PrincipalRole.AUDITOR
    )
    operator = dependencies.require_roles(PrincipalRole.OPERATOR)
    approver = dependencies.require_roles(PrincipalRole.APPROVER)

    register_assignment_routes(app, service=service, dependencies=dependencies)
    register_review_work_routes(app, service=service, dependencies=dependencies)

    @app.exception_handler(ReviewEvidenceUnavailable)
    async def evidence_unavailable(_request: Request, exc: ReviewEvidenceUnavailable) -> Response:
        from fastapi.responses import JSONResponse

        return JSONResponse(status_code=503, content={"detail": str(exc)})

    @app.get("/v1/measured-review-evidence/{domain}", response_model=ReviewEvidence)
    async def get_evidence(
        domain: ReviewDomain,
        request: Request,
        principal: Annotated[Principal, Depends(read_role)],
    ) -> ReviewEvidence:
        require_review_role(
            principal, PrincipalRole.OPERATOR, PrincipalRole.APPROVER, PrincipalRole.AUDITOR
        )
        if request.scope.get("query_string", b"") or await request.body():
            raise HTTPException(status_code=400, detail="Evidence read accepts no query or body")
        return await asyncio.to_thread(service.evidence.read, domain)

    @app.get("/v1/measured-reviews", response_model=ReviewList)
    def list_reviews(
        principal: Annotated[Principal, Depends(read_role)],
        after: Annotated[ReviewId | None, Query()] = None,
    ) -> ReviewList:
        return service.list_reviews(principal=principal, after=after)

    @app.post("/v1/measured-reviews", response_model=MeasuredReviewView)
    def open_review(
        payload: OpenReviewRequest,
        principal: Annotated[Principal, Depends(operator)],
    ) -> MeasuredReviewView:
        return service.submit(payload, principal=principal)

    @app.get("/v1/measured-reviews/{review_id}", response_model=MeasuredReviewView)
    def get_review(
        review_id: ReviewId,
        principal: Annotated[Principal, Depends(read_role)],
    ) -> MeasuredReviewView:
        return service.get(review_id, principal=principal)

    @app.get("/v1/measured-reviews/{review_id}/history", response_model=tuple[ReviewRevision, ...])
    def get_history(
        review_id: ReviewId,
        principal: Annotated[Principal, Depends(read_role)],
    ) -> tuple[ReviewRevision, ...]:
        return service.history(review_id, principal=principal)

    @app.post("/v1/measured-reviews/{review_id}/assessment", response_model=MeasuredReviewView)
    def assess_review(
        review_id: ReviewId,
        payload: AssessmentRequest,
        principal: Annotated[Principal, Depends(operator)],
    ) -> MeasuredReviewView:
        return service.submit(payload, principal=principal, review_id=review_id)

    @app.post("/v1/measured-reviews/{review_id}/decision", response_model=MeasuredReviewView)
    def decide_review(
        review_id: ReviewId,
        payload: DecisionRequest,
        principal: Annotated[Principal, Depends(approver)],
    ) -> MeasuredReviewView:
        return service.submit(payload, principal=principal, review_id=review_id)

    @app.post("/v1/measured-reviews/{review_id}/retest", response_model=MeasuredReviewView)
    def attach_retest(
        review_id: ReviewId,
        payload: RetestRequest,
        principal: Annotated[Principal, Depends(operator)],
    ) -> MeasuredReviewView:
        return service.submit(payload, principal=principal, review_id=review_id)

    @app.get("/v1/measured-reviews/{review_id}/report.md", response_class=Response)
    def get_report(
        review_id: ReviewId,
        principal: Annotated[Principal, Depends(read_role)],
    ) -> Response:
        history, receipts = service.report_inputs(review_id, principal=principal)
        return Response(
            render_review_report(history, receipts=receipts),
            media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="{review_id}.md"'},
        )


def register_assignment_routes(
    app: FastAPI, *, service: MeasuredReviewService, dependencies: "ControlPlaneDependencies"
) -> None:
    read_role = dependencies.require_roles(
        PrincipalRole.OPERATOR, PrincipalRole.APPROVER, PrincipalRole.AUDITOR
    )
    operator = dependencies.require_roles(PrincipalRole.OPERATOR)
    acknowledger = dependencies.require_roles(PrincipalRole.OPERATOR, PrincipalRole.APPROVER)

    @app.get("/v1/measured-review-assignees", response_model=tuple[str, ...])
    def list_assignees(principal: Annotated[Principal, Depends(read_role)]) -> tuple[str, ...]:
        require_review_role(
            principal, PrincipalRole.OPERATOR, PrincipalRole.APPROVER, PrincipalRole.AUDITOR
        )
        return service.assignees

    @app.get("/v1/measured-review-inbox", response_model=ReviewInbox)
    def get_inbox(
        principal: Annotated[Principal, Depends(read_role)],
        after: Annotated[ReviewId | None, Query()] = None,
    ) -> ReviewInbox:
        return service.inbox(principal=principal, after=after)

    @app.post("/v1/measured-reviews/{review_id}/assignment", response_model=MeasuredReviewView)
    def assign_review(
        review_id: ReviewId,
        payload: AssignmentRequest,
        principal: Annotated[Principal, Depends(operator)],
    ) -> MeasuredReviewView:
        return service.submit(payload, principal=principal, review_id=review_id)

    @app.post(
        "/v1/measured-reviews/{review_id}/notification-ack", response_model=MeasuredReviewView
    )
    def acknowledge_notification(
        review_id: ReviewId,
        payload: NotificationAckRequest,
        principal: Annotated[Principal, Depends(acknowledger)],
    ) -> MeasuredReviewView:
        return service.submit(payload, principal=principal, review_id=review_id)


def register_review_work_routes(
    app: FastAPI,
    *,
    service: MeasuredReviewService,
    dependencies: "ControlPlaneDependencies",
) -> None:
    read_role = dependencies.require_roles(
        PrincipalRole.OPERATOR,
        PrincipalRole.APPROVER,
        PrincipalRole.AUDITOR,
    )
    operator = dependencies.require_roles(PrincipalRole.OPERATOR)
    acknowledger = dependencies.require_roles(PrincipalRole.OPERATOR, PrincipalRole.APPROVER)

    async def bounded_query(request: Request) -> None:
        pairs = list(request.query_params.multi_items())
        if (
            await request.body()
            or len(pairs) != len({k for k, _ in pairs})
            or any(
                k not in {"assignee", "unassigned", "state", "unread", "cursor"} for k, _ in pairs
            )
        ):
            raise HTTPException(
                status_code=400, detail="Review search accepts only its filter parameters"
            )

    def filters(
        assignee: Annotated[Subject | None, Query()] = None,
        unassigned: Annotated[bool, Query()] = False,
        state: Annotated[ReviewState | None, Query()] = None,
        unread: Annotated[bool, Query()] = False,
    ) -> ReviewFilters:
        try:
            return ReviewFilters(
                assignee=assignee, unassigned=unassigned, state=state, unread=unread
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="Review filters conflict") from exc

    @app.get(
        "/v2/measured-reviews",
        response_model=ReviewSearchPage,
        dependencies=[Depends(bounded_query)],
    )
    def search_reviews(
        principal: Annotated[Principal, Depends(read_role)],
        selected: Annotated[ReviewFilters, Depends(filters)],
        cursor: Annotated[str | None, Query(max_length=2048)] = None,
    ) -> ReviewSearchPage:
        try:
            return service.search_reviews(principal=principal, filters=selected, cursor=cursor)
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail="Review cursor does not match this search"
            ) from exc

    @app.get(
        "/v2/measured-review-inbox",
        response_model=FilteredReviewInbox,
        dependencies=[Depends(bounded_query)],
    )
    def search_inbox(
        principal: Annotated[Principal, Depends(read_role)],
        selected: Annotated[ReviewFilters, Depends(filters)],
        cursor: Annotated[str | None, Query(max_length=2048)] = None,
    ) -> FilteredReviewInbox:
        try:
            return service.search_inbox(principal=principal, filters=selected, cursor=cursor)
        except ValueError as exc:
            raise HTTPException(
                status_code=422, detail="Notification cursor does not match this search"
            ) from exc

    @app.post(
        "/v2/measured-reviews/{review_id}/notification-ack", response_model=NotificationReceipt
    )
    def receipt(
        review_id: ReviewId,
        payload: NotificationReceiptRequest,
        principal: Annotated[Principal, Depends(acknowledger)],
    ) -> NotificationReceipt:
        return service.acknowledge_notification(review_id, payload, principal=principal)

    @app.get(
        "/v2/measured-reviews/{review_id}/notification-receipts",
        response_model=tuple[NotificationReceipt, ...],
    )
    async def receipts(
        review_id: ReviewId,
        request: Request,
        principal: Annotated[Principal, Depends(read_role)],
    ) -> tuple[NotificationReceipt, ...]:
        if request.scope.get("query_string", b"") or await request.body():
            raise HTTPException(status_code=400, detail="Receipt read accepts no query or body")
        return await asyncio.to_thread(
            service.notification_receipts, review_id, principal=principal
        )

    @app.post("/v2/measured-reviews/{review_id}/follow-up", response_model=MeasuredReviewView)
    def followup(
        review_id: ReviewId,
        payload: FollowupReviewRequest,
        principal: Annotated[Principal, Depends(operator)],
    ) -> MeasuredReviewView:
        return service.open_followup(review_id, payload, principal=principal)
