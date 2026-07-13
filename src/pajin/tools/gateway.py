"""Single policy and evidence boundary for every tool invocation."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256

from pydantic import BaseModel, ConfigDict

from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolResult
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.runtime.secrets import (
    SecretBroker,
    SecretLease,
    SecretMaterial,
    redact_text,
    redact_value,
)
from pajin.runtime.store import RunStore
from pajin.runtime.worker import (
    EgressPolicy,
    NetworkMode,
    WorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry


class GatewayOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    decision: PolicyDecision
    result: ToolResult
    worker_result: WorkerResult | None = None
    executed: bool = False


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
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._policy = policy
        self._tools = tools
        self._worker = worker
        self._store = store
        self._secrets = secrets or SecretBroker()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._request_times: deque[datetime] = deque()

    async def execute(
        self,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        *,
        used_calls: int,
    ) -> GatewayOutcome:
        try:
            tool = self._tools.tool(request.tool_id)
        except KeyError:
            decision = PolicyDecision(
                allowed=False,
                reason="tool is not registered in the PAJIN tool registry",
                policy="tool-registry",
            )
            return self._deny(request, decision)

        evaluated_at = self._clock()
        decision = self._policy.evaluate_tool_request(
            campaign,
            grant,
            request,
            tool.spec,
            used_calls=used_calls,
            now=evaluated_at,
        )
        if decision.allowed:
            rate_limit_denial = self._reserve_rate_limit_slot(
                campaign,
                evaluated_at,
                request_cost=tool.spec.network_request_cost,
            )
            if rate_limit_denial is not None:
                decision = rate_limit_denial
        self._record_policy(request, decision)
        if not decision.allowed:
            return self._deny(request, decision, policy_recorded=True)

        try:
            job = tool.prepare(request)
            if job.network is not NetworkMode.NONE or job.egress_policy is not None:
                raise ValueError("Tool Adapter cannot grant itself network access")
            if tool.spec.network_access:
                job = job.model_copy(
                    update={
                        "network": NetworkMode.EGRESS_PROXY,
                        "egress_policy": EgressPolicy(
                            allow=campaign.spec.scope.allow,
                            deny=campaign.spec.scope.deny,
                            allowed_methods=campaign.spec.rules_of_engagement.allowed_methods,
                            allow_private_networks=(
                                campaign.spec.rules_of_engagement.allow_private_networks
                            ),
                        ),
                    }
                )
                job = WorkerJob.model_validate(job.model_dump())
        except Exception as exc:
            failed = self._failed_result(
                request,
                f"tool preparation failed: {type(exc).__name__}: {exc}",
            )
            self._store.append_event(
                "tool.preparation_failed",
                {"requestId": request.request_id, "toolId": request.tool_id, "error": failed.error},
            )
            evidence = self._write_evidence(request, decision, failed, None, None, [])
            failed.evidence.append(evidence)
            return GatewayOutcome(decision=decision, result=failed)

        try:
            leases, materials = self._materialize_secrets(request, job)
        except (KeyError, PermissionError, ValueError) as exc:
            failed = self._failed_result(
                request,
                f"secret lease failed: {type(exc).__name__}: {exc}",
            )
            self._store.append_event(
                "secret.lease.failed",
                {
                    "requestId": request.request_id,
                    "toolId": request.tool_id,
                    "error": failed.error,
                },
            )
            evidence = self._write_evidence(request, decision, failed, job, None, [])
            failed.evidence.append(evidence)
            return GatewayOutcome(decision=decision, result=failed)

        self._store.append_event(
            "worker.dispatched",
            self._safe_job_metadata(
                request,
                job,
                lease_ids=[lease.lease_id for lease in leases],
            ),
        )
        dispatch_started_at = datetime.now(UTC)
        try:
            worker_result = (
                await self._worker.run(job, secrets=materials)
                if materials
                else await self._worker.run(job)
            )
        except Exception as exc:
            worker_result = WorkerResult(
                execution_id=job.execution_id,
                backend="backend-error",
                status=WorkerStatus.FAILED,
                exit_code=None,
                stderr=redact_text(
                    f"worker backend raised {type(exc).__name__}: {exc}",
                    materials,
                ),
                started_at=dispatch_started_at,
                finished_at=datetime.now(UTC),
            )
        finally:
            for lease in leases:
                revoked = self._secrets.revoke(lease.lease_id, "Worker execution finished")
                self._store.append_event(
                    "secret.lease.revoked",
                    {
                        "leaseId": revoked.lease_id,
                        "binding": revoked.binding,
                        "reason": revoked.revoked_reason,
                    },
                )
        worker_result = self._redact_worker_result(worker_result, materials)
        self._store.append_event(
            "worker.completed",
            {
                "requestId": request.request_id,
                "executionId": worker_result.execution_id,
                "backend": worker_result.backend,
                "status": worker_result.status.value,
                "exitCode": worker_result.exit_code,
                "stdoutTruncated": worker_result.stdout_truncated,
                "stderrTruncated": worker_result.stderr_truncated,
            },
        )
        try:
            result = tool.interpret(request, worker_result)
        except Exception as exc:
            result = self._failed_result(
                request, f"tool result interpretation failed: {type(exc).__name__}: {exc}"
            )
        result = self._redact_tool_result(result, materials)
        evidence = self._write_evidence(
            request,
            decision,
            result,
            job,
            worker_result,
            leases,
        )
        result.evidence.append(evidence)
        self._store.append_event(
            "tool.completed" if result.success else "tool.failed",
            {
                "requestId": request.request_id,
                "toolId": request.tool_id,
                "success": result.success,
                "evidence": evidence,
            },
        )
        return GatewayOutcome(
            decision=decision,
            result=result,
            worker_result=worker_result,
            executed=True,
        )

    def _reserve_rate_limit_slot(
        self,
        campaign: CampaignManifest,
        evaluated_at: datetime,
        *,
        request_cost: int,
    ) -> PolicyDecision | None:
        limit = campaign.spec.rules_of_engagement.max_requests_per_minute
        if limit is None:
            return None
        if evaluated_at.tzinfo is None:
            evaluated_at = evaluated_at.replace(tzinfo=UTC)
        cutoff = evaluated_at - timedelta(minutes=1)
        while self._request_times and self._request_times[0] <= cutoff:
            self._request_times.popleft()
        if len(self._request_times) + request_cost > limit:
            return PolicyDecision(
                allowed=False,
                reason=(
                    f"campaign rate limit of {limit} requests per minute cannot reserve "
                    f"{request_cost} request units"
                ),
                policy="rate-limit",
            )
        self._request_times.extend(evaluated_at for _ in range(request_cost))
        return None

    def _deny(
        self,
        request: ToolRequest,
        decision: PolicyDecision,
        *,
        policy_recorded: bool = False,
    ) -> GatewayOutcome:
        if not policy_recorded:
            self._record_policy(request, decision)
        result = self._failed_result(request, f"policy denied: {decision.reason}")
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
        }
        if job is not None:
            payload["workerJob"] = self._safe_job_metadata(request, job)
        if worker_result is not None:
            payload["workerResult"] = worker_result.model_dump(mode="json")
        if leases:
            payload["secretLeases"] = [lease.model_dump(mode="json") for lease in leases]
        return self._store.write_json(f"evidence/{request.request_id}.json", payload)

    @staticmethod
    def _safe_job_metadata(
        request: ToolRequest,
        job: WorkerJob,
        *,
        lease_ids: list[str] | None = None,
    ) -> dict[str, object]:
        stdin_bytes = job.stdin.encode("utf-8")
        return {
            "requestId": request.request_id,
            "executionId": job.execution_id,
            "image": job.image,
            "command": job.command,
            "network": job.network.value,
            "egressPolicy": (
                job.egress_policy.model_dump(mode="json") if job.egress_policy else None
            ),
            "limits": job.limits.model_dump(mode="json"),
            "stdinBytes": len(stdin_bytes),
            "stdinSha256": sha256(stdin_bytes).hexdigest(),
            "secretRequests": [
                {
                    "binding": item.binding,
                    "secretRefFingerprint": SecretBroker.fingerprint(item.secret_ref),
                    "ttlSeconds": item.ttl_seconds,
                }
                for item in job.secret_requests
            ],
            "secretLeaseIds": lease_ids or [],
        }

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
                    ttl_seconds=secret_request.ttl_seconds,
                    max_uses=1,
                )
                leases.append(lease)
                self._store.append_event(
                    "secret.lease.issued",
                    {
                        "leaseId": lease.lease_id,
                        "binding": lease.binding,
                        "secretRefFingerprint": lease.secret_ref_fingerprint,
                        "expiresAt": lease.expires_at,
                    },
                )
                materials.append(self._secrets.materialize(lease.lease_id, audience=audience))
        except Exception:
            for lease in leases:
                self._secrets.revoke(lease.lease_id, "secret setup failed")
            raise
        return leases, materials

    @staticmethod
    def _redact_worker_result(
        result: WorkerResult,
        materials: list[SecretMaterial],
    ) -> WorkerResult:
        if not materials:
            return result
        return result.model_copy(
            update={
                "stdout": redact_text(result.stdout, materials),
                "stderr": redact_text(result.stderr, materials),
                "network_log": redact_text(result.network_log, materials),
            }
        )

    @staticmethod
    def _redact_tool_result(
        result: ToolResult,
        materials: list[SecretMaterial],
    ) -> ToolResult:
        if not materials:
            return result
        return result.model_copy(
            update={
                "data": redact_value(result.data, materials),
                "error": redact_text(result.error, materials) if result.error else None,
            }
        )

    @staticmethod
    def _failed_result(request: ToolRequest, error: str) -> ToolResult:
        now = datetime.now(UTC)
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=False,
            started_at=now,
            finished_at=now,
            error=error,
        )
