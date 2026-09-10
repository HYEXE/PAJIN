"""Pinned System agent Tool using the existing isolated Docker/egress/Secret Lease boundary."""

from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path

from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import (
    WorkerJob,
    WorkerLimits,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.system_read import models
from pajin.system_read.models import (
    SECRET_REF,
    TOOL_ID,
    SystemDeployment,
    SystemInput,
    SystemWorkerOutput,
    distribution_metadata,
)
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_safe_worker_failure,
    decode_strict_worker_json_object,
    host_observed_https_connect_receipts,
    https_connect_authority,
)


def system_worker_limits() -> WorkerLimits:
    return WorkerLimits(
        timeout_seconds=25,
        memory_mb=128,
        cpus=0.5,
        pids=16,
        workspace_mb=1,
        stdout_bytes=24576,
        stderr_bytes=1024,
    )


class SystemReadTool(Tool):
    spec = ToolSpec(
        tool_id=TOOL_ID,
        version="1.0.0",
        description="Read one authenticated Linux agent's userspace distribution metadata",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"system", "read-only", "authenticated-agent"}),
        network_access=True,
        parallel_safe=False,
    )

    def __init__(self, deployment: SystemDeployment) -> None:
        self.deployment = SystemDeployment.model_validate_json(deployment.model_dump_json())

    def stable_execution_context(self) -> dict[str, object]:
        spec = self.spec.model_dump(mode="json")
        spec["categories"] = sorted(self.spec.categories)
        spec["evidence_types"] = sorted(self.spec.evidence_types)
        return {
            "spec": spec,
            "version": "pajin.sys-002-tool/v1",
            "deployment": self.deployment.model_dump(mode="json"),
            "limits": system_worker_limits().model_dump(mode="json"),
            "transport": "fixed-mtls-get-over-observed-connect",
            "hostParserSha256": sha256(Path(models.__file__).read_bytes()).hexdigest(),
            "findingAuthority": False,
        }

    def validate_request(self, request: ToolRequest) -> SystemInput:
        value = SystemInput.model_validate(request.arguments)
        if (
            request.tool_id != TOOL_ID
            or request.method != "GET"
            or re.fullmatch(r"tool_[a-f0-9]{32}", request.request_id) is None
            or request.target != value.target
            or value != self.deployment.value
        ):
            raise ValueError("System request differs from its independently pinned deployment")
        return value

    def prepare(self, request: ToolRequest) -> WorkerJob:
        self.validate_request(request)
        return WorkerJob(
            image=self.deployment.image_id,
            command=["system-os-release"],
            stdin=json.dumps(
                {
                    "deployment": self.deployment.model_dump(mode="json"),
                    "requestId": request.request_id,
                }
            ),
            limits=system_worker_limits(),
            secret_requests=[
                WorkerSecretRequest(secret_ref=SECRET_REF, binding="system-mtls", ttl_seconds=30)
            ],
        )

    def checked_output(self, request: ToolRequest, result: WorkerResult) -> SystemWorkerOutput:
        self.validate_request(request)
        output = SystemWorkerOutput.model_validate(
            decode_strict_worker_json_object(result, label="System agent output")
        )
        deployment = self.deployment
        if (
            output.agent.request_id != request.request_id
            or output.agent.instance != deployment.value.instance
            or output.agent.agent_sha256 != deployment.agent_sha256
            or output.client_sha256 != deployment.client_sha256
            or output.server_cert_sha256 != deployment.server_cert_sha256
            or output.client_cert_sha256 != deployment.client_cert_sha256
        ):
            raise ValueError("System authenticated receipt differs from current request/deployment")
        distribution_metadata(output.agent.content())
        return output

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        data: dict[str, object] = {}
        error = None
        if result.status is not WorkerStatus.SUCCEEDED:
            error = audit_safe_worker_failure(result)
        else:
            try:
                output = self.checked_output(request, result)
                data = {
                    "metadata": distribution_metadata(output.agent.content()),
                    "receipt": output.model_dump(mode="json", by_alias=True),
                }
            except ValueError:
                error = "System agent returned invalid or mismatched evidence"
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=error is None,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
            error=error,
        )

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        self.checked_output(request, worker_result)
        receipts = host_observed_https_connect_receipts(
            worker_result, network_log_trusted=network_log_trusted
        )
        if (
            receipts is None
            or len(receipts) != 1
            or receipts[0].sequence != 1
            or receipts[0].authority != https_connect_authority(request.target)
        ):
            raise ValueError("System read lacks its exact host-observed HTTPS route")
