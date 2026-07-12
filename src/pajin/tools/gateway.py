"""Single policy and evidence boundary for every tool invocation."""

from __future__ import annotations

from datetime import UTC, datetime
from hashlib import sha256

from pydantic import BaseModel, ConfigDict

from pajin.domain.models import CampaignManifest, CapabilityGrant, ToolRequest, ToolResult
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.runtime.store import RunStore
from pajin.runtime.worker import (
    EgressPolicy,
    NetworkMode,
    WorkerBackend,
    WorkerJob,
    WorkerResult,
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
    ) -> None:
        self._policy = policy
        self._tools = tools
        self._worker = worker
        self._store = store

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

        decision = self._policy.evaluate_tool_request(
            campaign,
            grant,
            request,
            tool.spec,
            used_calls=used_calls,
        )
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
            evidence = self._write_evidence(request, decision, failed, None, None)
            failed.evidence.append(evidence)
            return GatewayOutcome(decision=decision, result=failed)

        self._store.append_event(
            "worker.dispatched",
            self._safe_job_metadata(request, job),
        )
        worker_result = await self._worker.run(job)
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
        evidence = self._write_evidence(request, decision, result, job, worker_result)
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
        evidence = self._write_evidence(request, decision, result, None, None)
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
        return self._store.write_json(f"evidence/{request.request_id}.json", payload)

    @staticmethod
    def _safe_job_metadata(request: ToolRequest, job: WorkerJob) -> dict[str, object]:
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
        }

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
