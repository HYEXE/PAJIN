"""Single policy and evidence boundary for every tool invocation."""

from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import PurePosixPath
from threading import Lock
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, field_validator

from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolResult
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.runtime.error_safety import audit_safe_exception_diagnostic
from pajin.runtime.secrets import (
    SecretBroker,
    SecretLease,
    SecretMaterial,
    redact_text,
)
from pajin.runtime.store import RunStore
from pajin.runtime.worker import (
    EgressPolicy,
    NetworkMode,
    WorkerBackend,
    WorkerCleanupError,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import Tool, ToolRegistry, ToolSpec
from pajin.tools.execution_receipts import (
    bound_utf8,
    failed_tool_result,
    host_network_log_is_trusted,
    normalize_host_receipt,
    project_tool_result,
    safe_job_metadata,
    validate_strict_json,
)

_MAX_TOOL_REQUEST_JSON_BYTES = 10_000_000
_REQUEST_RESERVATION_API_VERSION = "pajin.dev/tool-request-reservation/v1"


class ToolRequestCanonicalizationError(ValueError):
    """Raised when a Tool request cannot be represented by the Gateway contract."""


def canonical_tool_request_digest(request: ToolRequest) -> str:
    """Return the exact SHA-256 persisted by Tool Gateway request reservations."""

    _canonical, digest = _canonical_tool_request_with_digest(request)
    return digest


def _canonical_tool_request_with_digest(
    request: ToolRequest,
) -> tuple[ToolRequest, str]:
    try:
        canonical = ToolRequest.model_validate(
            request.model_dump(
                mode="python",
                include=set(ToolRequest.model_fields),
            )
        )
        payload = canonical.model_dump(mode="python")
        validate_strict_json(payload, label="Tool request")
        encoded = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (
        AttributeError,
        OverflowError,
        RecursionError,
        TypeError,
        UnicodeError,
        ValueError,
    ) as exc:
        raise ToolRequestCanonicalizationError(
            "Tool request is not strict canonical JSON"
        ) from exc
    if len(encoded) > _MAX_TOOL_REQUEST_JSON_BYTES:
        raise ToolRequestCanonicalizationError(
            "Tool request exceeds the bounded canonical JSON size"
        )
    return canonical.model_copy(deep=True), sha256(encoded).hexdigest()


class GatewayOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    decision: PolicyDecision
    result: ToolResult
    worker_result: WorkerResult | None = None
    network_log_trusted: bool = False
    result_identity_valid: bool = True
    executed: bool = False

    @field_validator(
        "network_log_trusted",
        "result_identity_valid",
        "executed",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Gateway outcome flags must use JSON booleans")
        return value


@dataclass(frozen=True)
class _RateLimitUnit:
    evaluated_at: datetime
    reservation_id: str


@dataclass(frozen=True)
class _RateLimitReservation:
    campaign: str
    reservation_id: str
    request_cost: int


@dataclass(frozen=True)
class _PreflightApproval:
    campaign: CampaignManifest
    request: ToolRequest
    tool: Tool
    spec: ToolSpec
    decision: PolicyDecision
    job: WorkerJob
    job_metadata: dict[str, object]
    request_cost: int
    rate_reservation: _RateLimitReservation | None


@dataclass(frozen=True)
class _SecretExecutionScope:
    leases: list[SecretLease]
    materials: list[SecretMaterial]


class RequestRateLimitLedger:
    """Campaign-scoped request reservations shared by original and replay Gateways."""

    def __init__(self) -> None:
        self._ledger_id = f"rate-ledger_{uuid4().hex}"
        self._request_times: dict[str, deque[_RateLimitUnit]] = {}
        self._lock = Lock()

    @property
    def ledger_id(self) -> str:
        return self._ledger_id

    def snapshot(self) -> dict[str, object]:
        with self._lock:
            return {
                "ledgerId": self._ledger_id,
                "reservationCounts": {
                    campaign: len(times) for campaign, times in sorted(self._request_times.items())
                },
            }

    def reserve(
        self,
        campaign: CampaignManifest,
        evaluated_at: datetime,
        *,
        request_cost: int,
    ) -> PolicyDecision | None:
        decision, _ = self.reserve_for_dispatch(
            campaign,
            evaluated_at,
            request_cost=request_cost,
        )
        return decision

    def reserve_for_dispatch(
        self,
        campaign: CampaignManifest,
        evaluated_at: datetime,
        *,
        request_cost: int,
    ) -> tuple[PolicyDecision | None, _RateLimitReservation | None]:
        """Reserve exact units that can be rolled back until Worker dispatch."""

        if (
            isinstance(request_cost, bool)
            or not isinstance(request_cost, int)
            or not 1 <= request_cost <= 100
        ):
            raise ValueError("rate-limit request cost must be an integer between 1 and 100")
        limit = campaign.spec.rules_of_engagement.max_requests_per_minute
        if limit is None:
            return None, None
        evaluated_at = self._normalized_time(evaluated_at)
        cutoff = evaluated_at - timedelta(minutes=1)
        with self._lock:
            request_times = self._request_times.setdefault(campaign.metadata.name, deque())
            while request_times and request_times[0].evaluated_at <= cutoff:
                request_times.popleft()
            if len(request_times) + request_cost > limit:
                return (
                    PolicyDecision(
                        allowed=False,
                        reason=(
                            f"campaign rate limit of {limit} requests per minute cannot reserve "
                            f"{request_cost} request units"
                        ),
                        policy="rate-limit",
                    ),
                    None,
                )
            reservation = _RateLimitReservation(
                campaign=campaign.metadata.name,
                reservation_id=f"rate-reservation_{uuid4().hex}",
                request_cost=request_cost,
            )
            request_times.extend(
                _RateLimitUnit(
                    evaluated_at=evaluated_at,
                    reservation_id=reservation.reservation_id,
                )
                for _ in range(request_cost)
            )
        return None, reservation

    def release(self, reservation: _RateLimitReservation) -> None:
        """Release a pre-dispatch reservation without touching concurrent calls."""

        with self._lock:
            request_times = self._request_times.get(reservation.campaign)
            if request_times is None:
                return
            retained = deque(
                unit for unit in request_times if unit.reservation_id != reservation.reservation_id
            )
            removed = len(request_times) - len(retained)
            if removed not in {0, reservation.request_cost}:
                raise RuntimeError("rate-limit reservation ledger is internally inconsistent")
            if retained:
                self._request_times[reservation.campaign] = retained
            else:
                self._request_times.pop(reservation.campaign, None)

    @staticmethod
    def _normalized_time(value: datetime) -> datetime:
        if not isinstance(value, datetime):
            raise TypeError("rate-limit evaluation time must be a datetime")
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("rate-limit evaluation time must include a UTC offset or Z")
        return value.astimezone(UTC)


class ToolGateway:
    """Authorize, dispatch, bound, audit, and record a tool request."""

    def __init__(
        self,
        *,
        policy: PolicyEngine,
        tools: ToolRegistry,
        worker: WorkerBackend,
        store: RunStore,
        secrets: SecretBroker | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
        allow_secret_requests: bool = True,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._policy = policy
        self._tools = tools
        self._worker = worker
        self._store = store
        self._secrets = secrets or SecretBroker()
        self._rate_limits = rate_limits or RequestRateLimitLedger()
        self._allow_secret_requests = allow_secret_requests
        self._clock = clock or (lambda: datetime.now(UTC))

    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome:
        if self._cancellation_pending():
            raise asyncio.CancelledError
        preflight = self._preflight(campaign, grant, request, used_calls=used_calls)
        if isinstance(preflight, GatewayOutcome):
            return preflight
        secret_scope = self._open_secret_scope(preflight)
        if isinstance(secret_scope, GatewayOutcome):
            return secret_scope
        return await self._dispatch(preflight, secret_scope)

    def _preflight(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> _PreflightApproval | GatewayOutcome:
        canonical = self._canonical_inputs(campaign, grant, request, used_calls=used_calls)
        if isinstance(canonical, GatewayOutcome):
            return canonical
        campaign, grant, request = canonical
        resolved = self._resolve_tool(request)
        if isinstance(resolved, GatewayOutcome):
            return resolved
        tool, spec = resolved
        approved = self._evaluate_policy(campaign, grant, request, tool, spec, used_calls)
        if isinstance(approved, GatewayOutcome):
            return approved
        decision, request_cost, evaluated_at = approved
        prepared = self._prepare_job(campaign, request, tool, spec, request_cost)
        if isinstance(prepared, str):
            self._record_policy(request, decision)
            return self._fail_before_dispatch(
                request,
                decision,
                event_type="tool.preparation_failed",
                error=prepared,
            )
        job, job_metadata = prepared
        rate_denial, reservation = self._reserve_dispatch(
            campaign,
            evaluated_at,
            request_cost=request_cost,
        )
        if rate_denial is not None:
            return self._deny(request, rate_denial)
        try:
            self._record_policy(request, decision)
        except BaseException:
            # The audit record is the final pre-dispatch step.  If it cannot be
            # persisted, no Worker request has started and the in-memory rate
            # reservation must not survive as phantom consumed capacity.  Do
            # not call ``_release_rate_reservation`` here: that helper writes a
            # second audit event and could mask the original storage failure.
            if reservation is not None:
                self._rate_limits.release(reservation)
            raise
        return _PreflightApproval(
            campaign=campaign,
            request=request,
            tool=tool,
            spec=spec,
            decision=decision,
            job=job,
            job_metadata=job_metadata,
            request_cost=request_cost,
            rate_reservation=reservation,
        )

    def _canonical_inputs(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> tuple[CampaignManifest, CapabilityGrant, ToolRequest] | GatewayOutcome:
        canonical_request = self._canonical_request(request)
        if isinstance(canonical_request, GatewayOutcome):
            return canonical_request
        request, request_digest = canonical_request
        duplicate = self._reserve_request(request, request_digest=request_digest)
        if duplicate is not None:
            return duplicate
        return self._canonical_authority_inputs(
            campaign,
            grant,
            request,
            used_calls=used_calls,
        )

    def _canonical_request(
        self,
        request: ToolRequest,
    ) -> tuple[ToolRequest, str] | GatewayOutcome:
        try:
            return _canonical_tool_request_with_digest(request)
        except ToolRequestCanonicalizationError as exc:
            return self._reject_invalid_request(exc)

    def _reserve_request(
        self,
        request: ToolRequest,
        *,
        request_digest: str,
    ) -> GatewayOutcome | None:
        reservation_path = f"requests/{request.request_id}.json"
        evidence_path = f"evidence/{request.request_id}.json"
        try:
            self._store.write_json_create_only(
                reservation_path,
                {
                    "apiVersion": _REQUEST_RESERVATION_API_VERSION,
                    "kind": "ToolRequestReservation",
                    "requestId": request.request_id,
                    "requestSha256": request_digest,
                },
            )
        except FileExistsError:
            return self._reject_duplicate_request(request)
        if self._store.artifact_exists(evidence_path):
            return self._reject_duplicate_request(request)
        self._store.append_event(
            "tool.request_reserved",
            {
                "requestId": request.request_id,
                "requestSha256": request_digest,
                "reservation": reservation_path,
            },
        )
        return None

    def _canonical_authority_inputs(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> tuple[CampaignManifest, CapabilityGrant, ToolRequest] | GatewayOutcome:
        try:
            campaign = CampaignManifest.model_validate(
                campaign.model_dump(
                    mode="python",
                    include=set(CampaignManifest.model_fields),
                )
            )
            grant = CapabilityGrant.model_validate(
                grant.model_dump(
                    mode="python",
                    include=set(CapabilityGrant.model_fields),
                )
            )
        except (AttributeError, TypeError, ValueError):
            return self._deny(
                request,
                PolicyDecision(
                    allowed=False,
                    reason="campaign or capability authority contract is invalid",
                    policy="authority-contract",
                ),
            )
        if isinstance(used_calls, bool) or not isinstance(used_calls, int) or used_calls < 0:
            return self._deny(
                request,
                PolicyDecision(
                    allowed=False,
                    reason="used Tool-call count must be a non-negative integer",
                    policy="usage-contract",
                ),
            )
        return campaign, grant, request

    def _reject_duplicate_request(self, request: ToolRequest) -> GatewayOutcome:
        decision = PolicyDecision(
            allowed=False,
            reason="canonical Tool request identifier is already reserved in this Run",
            policy="request-id",
        )
        result = failed_tool_result(request, f"policy denied: {decision.reason}")
        return GatewayOutcome(decision=decision, result=result)

    def _resolve_tool(self, request: ToolRequest) -> tuple[Tool, ToolSpec] | GatewayOutcome:
        try:
            tool = self._tools.tool(request.tool_id)
            registered_spec = self._tools.spec(request.tool_id)
            spec = ToolSpec.model_validate(registered_spec.model_dump(mode="python"))
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError):
            return self._deny(
                request,
                PolicyDecision(
                    allowed=False,
                    reason="tool is not registered with a valid PAJIN Tool contract",
                    policy="tool-registry",
                ),
            )
        if spec.tool_id != request.tool_id:
            return self._deny(
                request,
                PolicyDecision(
                    allowed=False,
                    reason="registered Tool identity differs from the requested Tool",
                    policy="tool-registry",
                ),
            )
        return tool, spec

    def _evaluate_policy(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        tool: Tool,
        spec: ToolSpec,
        used_calls: int,
    ) -> tuple[PolicyDecision, int, datetime] | GatewayOutcome:
        try:
            evaluated_at = RequestRateLimitLedger._normalized_time(self._clock())
            evaluated = self._policy.evaluate_tool_request(
                campaign.model_copy(deep=True),
                grant.model_copy(deep=True),
                request.model_copy(deep=True),
                spec.model_copy(deep=True),
                used_calls=used_calls,
                now=evaluated_at,
            )
            decision = PolicyDecision.model_validate(evaluated.model_dump(mode="python"))
        except Exception:
            decision = PolicyDecision(
                allowed=False,
                reason="policy evaluation failed closed",
                policy="policy-engine",
            )
            return self._deny(request, decision)
        if not decision.allowed:
            return self._deny(request, decision)
        request_cost = self._network_request_cost(tool, spec, request)
        if request_cost is None:
            return self._deny(
                request,
                PolicyDecision(
                    allowed=False,
                    reason="tool request does not have a valid bounded network request cost",
                    policy="tool-network-request-cost",
                ),
            )
        return decision, request_cost, evaluated_at

    @staticmethod
    def _network_request_cost(tool: Tool, spec: ToolSpec, request: ToolRequest) -> int | None:
        try:
            request_cost = tool.network_request_cost(request.model_copy(deep=True))
        except Exception:
            return None
        if (
            isinstance(request_cost, bool)
            or not isinstance(request_cost, int)
            or not spec.network_request_cost <= request_cost <= 100
        ):
            return None
        return request_cost

    def _prepare_job(
        self,
        campaign: CampaignManifest,
        request: ToolRequest,
        tool: Tool,
        spec: ToolSpec,
        request_cost: int,
    ) -> tuple[WorkerJob, dict[str, object]] | str:
        try:
            prepared = tool.prepare(request.model_copy(deep=True))
            job = WorkerJob.model_validate(prepared.model_dump(mode="python"))
            if job.secret_requests and not self._allow_secret_requests:
                raise ValueError("this Tool Gateway execution forbids Secret Lease requests")
            if job.network is not NetworkMode.NONE or job.egress_policy is not None:
                raise ValueError("Tool Adapter cannot grant itself network access")
            if spec.network_access:
                job = self._grant_egress(campaign, job, request_cost=request_cost)
            metadata = safe_job_metadata(request, job)
            json.dumps(metadata, allow_nan=False, ensure_ascii=False, sort_keys=True)
        except Exception as exc:
            return "tool preparation failed; " + audit_safe_exception_diagnostic(
                exc, stage="tool-preparation"
            )
        return job, metadata

    @staticmethod
    def _grant_egress(
        campaign: CampaignManifest,
        job: WorkerJob,
        *,
        request_cost: int,
    ) -> WorkerJob:
        scoped = job.model_copy(
            update={
                "network": NetworkMode.EGRESS_PROXY,
                "egress_policy": EgressPolicy(
                    allow=list(campaign.spec.scope.allow),
                    deny=list(campaign.spec.scope.deny),
                    allowed_methods=set(campaign.spec.rules_of_engagement.allowed_methods),
                    allow_private_networks=(
                        campaign.spec.rules_of_engagement.allow_private_networks
                    ),
                    max_requests=request_cost,
                ),
            },
            deep=True,
        )
        return WorkerJob.model_validate(scoped.model_dump(mode="python"))

    def _reserve_dispatch(
        self,
        campaign: CampaignManifest,
        evaluated_at: datetime,
        *,
        request_cost: int,
    ) -> tuple[PolicyDecision | None, _RateLimitReservation | None]:
        try:
            return self._rate_limits.reserve_for_dispatch(
                campaign,
                evaluated_at,
                request_cost=request_cost,
            )
        except Exception:
            return (
                PolicyDecision(
                    allowed=False,
                    reason="campaign rate-limit authority failed closed",
                    policy="rate-limit",
                ),
                None,
            )

    def _open_secret_scope(
        self,
        approval: _PreflightApproval,
    ) -> _SecretExecutionScope | GatewayOutcome:
        try:
            leases, materials = self._materialize_secrets(approval.request, approval.job)
        except Exception as exc:
            self._release_rate_reservation(approval, reason="secret-lease-failed")
            return self._fail_before_dispatch(
                approval.request,
                approval.decision,
                event_type="secret.lease.failed",
                error=(
                    "secret lease failed; "
                    + audit_safe_exception_diagnostic(exc, stage="secret-lease")
                ),
                job=approval.job,
            )
        return _SecretExecutionScope(leases=leases, materials=materials)

    async def _dispatch(
        self,
        approval: _PreflightApproval,
        secret_scope: _SecretExecutionScope,
    ) -> GatewayOutcome:
        if self._cancellation_pending():
            self._cancel_before_dispatch(approval, secret_scope)
        dispatch_metadata = {
            **approval.job_metadata,
            "secretLeaseIds": [lease.lease_id for lease in secret_scope.leases],
        }
        try:
            self._store.append_event("worker.dispatched", dispatch_metadata)
        except BaseException:
            try:
                self._revoke_leases(secret_scope.leases, "Worker dispatch did not start")
            finally:
                self._release_rate_reservation(approval, reason="dispatch-audit-failed")
            raise
        worker_result, revoked_leases = await self._run_worker(approval, secret_scope)
        return self._finalize_execution(
            approval,
            secret_scope.materials,
            revoked_leases,
            worker_result,
        )

    @staticmethod
    def _cancellation_pending() -> bool:
        task = asyncio.current_task()
        return task is not None and task.cancelling() > 0

    def _cancel_before_dispatch(
        self,
        approval: _PreflightApproval,
        secret_scope: _SecretExecutionScope,
    ) -> None:
        try:
            revoked = self._revoke_leases(
                secret_scope.leases,
                "Worker dispatch cancelled before start",
            )
        finally:
            self._release_rate_reservation(approval, reason="cancelled-before-dispatch")
        self._store.append_event(
            "worker.cancelled",
            {
                "requestId": approval.request.request_id,
                "executionId": approval.job.execution_id,
                "secretLeasesRevoked": len(revoked),
                "beforeDispatch": True,
            },
        )
        raise asyncio.CancelledError

    async def _run_worker(
        self,
        approval: _PreflightApproval,
        secret_scope: _SecretExecutionScope,
    ) -> tuple[WorkerResult, list[SecretLease]]:
        dispatch_started_at = datetime.now(UTC)
        cancelled = False
        revoked_leases: list[SecretLease] = []
        try:
            job = approval.job.model_copy(deep=True)
            worker_result = (
                await self._worker.run(job, secrets=list(secret_scope.materials))
                if secret_scope.materials
                else await self._worker.run(job)
            )
        except asyncio.CancelledError:
            cancelled = True
            raise
        except WorkerCleanupError:
            self._store.append_event(
                "worker.cleanup_failed",
                {
                    "requestId": approval.request.request_id,
                    "executionId": approval.job.execution_id,
                    "reason": "Worker resource removal could not be confirmed",
                },
            )
            raise
        except Exception as exc:
            worker_result = self._worker_exception_result(
                approval.job,
                secret_scope.materials,
                exc,
                started_at=dispatch_started_at,
            )
        finally:
            revoked_leases = self._revoke_leases(
                secret_scope.leases,
                "Worker execution finished",
            )
            if cancelled:
                self._store.append_event(
                    "worker.cancelled",
                    {
                        "requestId": approval.request.request_id,
                        "executionId": approval.job.execution_id,
                        "secretLeasesRevoked": len(revoked_leases),
                    },
                )
        return worker_result, revoked_leases

    def _worker_exception_result(
        self,
        job: WorkerJob,
        materials: list[SecretMaterial],
        error: Exception,
        *,
        started_at: datetime,
    ) -> WorkerResult:
        diagnostic = redact_text(
            "worker backend failed; "
            + audit_safe_exception_diagnostic(error, stage="worker-backend"),
            materials,
        )
        diagnostic, truncated = bound_utf8(diagnostic, job.limits.stderr_bytes)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="backend-error",
            status=WorkerStatus.FAILED,
            exit_code=None,
            stderr=diagnostic,
            stderr_truncated=truncated,
            started_at=started_at,
            finished_at=datetime.now(UTC),
        )

    def _finalize_execution(
        self,
        approval: _PreflightApproval,
        materials: list[SecretMaterial],
        leases: list[SecretLease],
        worker_result: WorkerResult,
    ) -> GatewayOutcome:
        receipt = normalize_host_receipt(
            backend=self._worker,
            job=approval.job,
            result=worker_result,
            materials=materials,
        )
        self._record_worker_completed(approval.request, receipt.worker_result)
        projection = project_tool_result(
            request=approval.request,
            tool=approval.tool,
            receipt=receipt,
            materials=materials,
        )
        evidence = self._record_tool_result(
            approval,
            projection.result,
            receipt.worker_result,
            leases,
        )
        result = projection.result.model_copy(
            update={"evidence": [*projection.result.evidence, evidence]},
            deep=True,
        )
        return GatewayOutcome(
            decision=approval.decision,
            result=result,
            worker_result=receipt.worker_result,
            network_log_trusted=receipt.network_log_trusted,
            result_identity_valid=projection.result_identity_valid,
            executed=True,
        )

    def _record_worker_completed(
        self,
        request: ToolRequest,
        result: WorkerResult,
    ) -> None:
        self._store.append_event(
            "worker.completed",
            {
                "requestId": request.request_id,
                "executionId": result.execution_id,
                "backend": result.backend,
                "status": result.status.value,
                "exitCode": result.exit_code,
                "stdoutTruncated": result.stdout_truncated,
                "stderrTruncated": result.stderr_truncated,
            },
        )

    def _record_tool_result(
        self,
        approval: _PreflightApproval,
        result: ToolResult,
        worker_result: WorkerResult,
        leases: list[SecretLease],
    ) -> str:
        evidence = self._write_evidence(
            approval.request,
            approval.decision,
            result,
            approval.job,
            worker_result,
            leases,
        )
        self._store.append_event(
            "tool.completed" if result.success else "tool.failed",
            {
                "requestId": approval.request.request_id,
                "toolId": approval.request.tool_id,
                "success": result.success,
                "evidence": evidence,
            },
        )
        return evidence

    def _fail_before_dispatch(
        self,
        request: ToolRequest,
        decision: PolicyDecision,
        *,
        event_type: str,
        error: str,
        job: WorkerJob | None = None,
    ) -> GatewayOutcome:
        failed = failed_tool_result(request, error)
        self._store.append_event(
            event_type,
            {
                "requestId": request.request_id,
                "toolId": request.tool_id,
                "error": failed.error,
            },
        )
        evidence = self._write_evidence(request, decision, failed, job, None, [])
        failed = failed.model_copy(update={"evidence": [evidence]}, deep=True)
        self._store.append_event(
            "tool.failed",
            {
                "requestId": request.request_id,
                "toolId": request.tool_id,
                "success": False,
                "evidence": evidence,
            },
        )
        return GatewayOutcome(decision=decision, result=failed)

    def _release_rate_reservation(
        self,
        approval: _PreflightApproval,
        *,
        reason: str,
    ) -> None:
        reservation = approval.rate_reservation
        if reservation is None:
            return
        self._rate_limits.release(reservation)
        self._store.append_event(
            "tool.rate_reservation_released",
            {
                "requestId": approval.request.request_id,
                "reservationId": reservation.reservation_id,
                "requestCost": reservation.request_cost,
                "reason": reason,
            },
        )

    def _deny(
        self,
        request: ToolRequest,
        decision: PolicyDecision,
        *,
        policy_recorded: bool = False,
    ) -> GatewayOutcome:
        if not policy_recorded:
            self._record_policy(request, decision)
        result = failed_tool_result(request, f"policy denied: {decision.reason}")
        evidence = self._write_evidence(request, decision, result, None, None, [])
        result.evidence.append(evidence)
        self._store.append_event(
            "tool.failed",
            {
                "requestId": request.request_id,
                "toolId": request.tool_id,
                "success": False,
                "evidence": evidence,
            },
        )
        return GatewayOutcome(decision=decision, result=result)

    def _reject_invalid_request(self, error: BaseException) -> GatewayOutcome:
        decision = PolicyDecision(
            allowed=False,
            reason=(
                "Tool request contract is invalid; "
                + audit_safe_exception_diagnostic(error, stage="tool-request-validation")
            ),
            policy="request-contract",
        )
        self._store.append_event(
            "tool.request_invalid",
            {"reason": "Tool request failed canonical model revalidation"},
        )
        result = failed_tool_result(
            ToolRequest(
                request_id="tool_invalid_request",
                agent_id="gateway:request-validation",
                tool_id="gateway.invalid-request",
                target="invalid-request",
            ),
            f"policy denied: {decision.reason}",
        )
        return GatewayOutcome(decision=decision, result=result)

    def _record_policy(self, request: ToolRequest, decision: PolicyDecision) -> None:
        self._store.append_event(
            "tool.policy_evaluated",
            {
                "requestId": request.request_id,
                "toolId": request.tool_id,
                "allowed": decision.allowed,
                "policy": decision.policy,
                "reason": decision.reason,
            },
        )

    def _write_evidence(
        self,
        request: ToolRequest,
        decision: PolicyDecision,
        result: ToolResult,
        job: WorkerJob | None,
        worker_result: WorkerResult | None,
        leases: list[SecretLease],
    ) -> str:
        payload: dict[str, object] = {
            "request": request.model_dump(mode="json"),
            "policyDecision": decision.model_dump(mode="json"),
            "result": result.model_dump(mode="json"),
            "networkLogTrusted": host_network_log_is_trusted(
                self._worker,
                job,
                worker_result,
            ),
        }
        if job is not None:
            payload["workerJob"] = safe_job_metadata(request, job)
        if worker_result is not None:
            payload["workerResult"] = worker_result.model_dump(mode="json")
        if leases:
            payload["secretLeases"] = [lease.model_dump(mode="json") for lease in leases]
        filename = f"{request.request_id}.json"
        relative_path = PurePosixPath("evidence", filename)
        if relative_path.parent != PurePosixPath("evidence") or relative_path.name != filename:
            raise ValueError("Tool evidence destination must be a direct evidence child")
        return self._store.write_json_create_only(relative_path.as_posix(), payload)

    def _materialize_secrets(
        self,
        request: ToolRequest,
        job: WorkerJob,
    ) -> tuple[list[SecretLease], list[SecretMaterial]]:
        leases: list[SecretLease] = []
        materials: list[SecretMaterial] = []
        audience = f"{request.agent_id}:{job.execution_id}"
        try:
            for secret_request in job.secret_requests:
                lease = self._secrets.issue(
                    secret_request.secret_ref,
                    audience=audience,
                    binding=secret_request.binding,
                    scope=self._store.run_id,
                    ttl_seconds=secret_request.ttl_seconds,
                    max_uses=1,
                )
                leases.append(lease)
                self._store.append_event(
                    "secret.lease.issued",
                    {
                        "leaseId": lease.lease_id,
                        "scope": lease.scope,
                        "binding": lease.binding,
                        "secretRefFingerprint": lease.secret_ref_fingerprint,
                        "expiresAt": lease.expires_at,
                    },
                )
                materials.append(
                    self._secrets.materialize(
                        lease.lease_id,
                        audience=audience,
                        scope=self._store.run_id,
                    )
                )
        except Exception:
            self._revoke_leases(leases, "secret setup failed")
            raise
        return leases, materials

    def _revoke_leases(
        self,
        leases: list[SecretLease],
        reason: str,
    ) -> list[SecretLease]:
        revoked_leases: list[SecretLease] = []
        failures = 0
        for lease in leases:
            try:
                revoked_leases.append(
                    self._secrets.revoke(
                        lease.lease_id,
                        reason,
                        scope=self._store.run_id,
                    )
                )
            except Exception:
                failures += 1
        for revoked in revoked_leases:
            try:
                self._store.append_event(
                    "secret.lease.revoked",
                    {
                        "leaseId": revoked.lease_id,
                        "scope": revoked.scope,
                        "binding": revoked.binding,
                        "reason": revoked.revoked_reason,
                    },
                )
            except Exception:
                failures += 1
        if failures:
            raise RuntimeError("one or more Secret Lease cleanup operations failed")
        return revoked_leases
