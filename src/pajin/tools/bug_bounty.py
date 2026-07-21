"""Fixed, minimum-impact probes for the Bug Bounty local lab profile."""

from __future__ import annotations

import json
from hashlib import sha256
from hmac import compare_digest
from typing import Literal
from urllib.parse import urlencode, urlsplit, urlunsplit

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_http_target,
    audit_safe_tool_interpretation_failure,
    audit_safe_worker_failure,
    decode_bounded_json_response,
    decode_strict_worker_json_object,
    host_observed_http_receipts,
    http_target_sha256,
)

BOOLEAN_SQLI_SCENARIO: Literal["bug-bounty.api.boolean-sqli-lab"] = (
    "bug-bounty.api.boolean-sqli-lab"
)
MAX_BOOLEAN_SQLI_RESPONSE_BYTES = 32_768
MAX_BOOLEAN_SQLI_RESPONSE_BASE64_CHARS = ((MAX_BOOLEAN_SQLI_RESPONSE_BYTES + 2) // 3) * 4


class BooleanSQLiProbeInput(StrictModel):
    scenario_id: Literal["bug-bounty.api.boolean-sqli-lab"] = BOOLEAN_SQLI_SCENARIO


class BooleanSQLiObservation(StrictModel):
    name: Literal["baseline", "negative-control", "boolean-probe"]
    status: int = Field(ge=100, le=599)
    record_count: int = Field(alias="recordCount", ge=0, le=100)
    synthetic: bool
    body_sha256: str = Field(alias="bodySha256", pattern=r"^[a-f0-9]{64}$")
    response_body_base64: str = Field(
        alias="responseBodyBase64",
        min_length=4,
        max_length=MAX_BOOLEAN_SQLI_RESPONSE_BASE64_CHARS,
    )


class BooleanSQLiChecks(StrictModel):
    baseline_single_record: bool = Field(alias="baselineSingleRecord")
    negative_control_empty: bool = Field(alias="negativeControlEmpty")
    boolean_probe_expanded: bool = Field(alias="booleanProbeExpanded")
    synthetic_lab_only: bool = Field(alias="syntheticLabOnly")


class BooleanSQLiProbeOutput(StrictModel):
    target: str
    scenario_id: Literal["bug-bounty.api.boolean-sqli-lab"] = Field(alias="scenarioId")
    vulnerable: bool
    checks: BooleanSQLiChecks
    observations: list[BooleanSQLiObservation] = Field(min_length=3, max_length=3)
    network_performed: bool = Field(alias="networkPerformed")

    @model_validator(mode="after")
    def require_complete_observation_set(self) -> BooleanSQLiProbeOutput:
        names = [observation.name for observation in self.observations]
        if set(names) != {"baseline", "negative-control", "boolean-probe"}:
            raise ValueError("SQLi probe output requires the three fixed observations")
        if len(names) != len(set(names)):
            raise ValueError("SQLi probe observations must be unique")
        return self


class BooleanSQLiProbeTool(Tool):
    """Run three fixed GET comparisons without accepting an agent-authored payload."""

    spec = ToolSpec(
        tool_id="bug-bounty.boolean-sqli-probe",
        version="1.0.0",
        description="Compare fixed baseline, negative-control, and boolean SQLi lab requests",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"active-test", "bug-bounty", "http", "injection"}),
        evidence_types=frozenset({"json", "http-observation"}),
        network_access=True,
        network_request_cost=3,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "GET":
            raise ValueError("boolean SQLi lab probe requires GET")
        parsed = urlsplit(request.target)
        if parsed.query or parsed.fragment:
            raise ValueError("boolean SQLi target must not contain a query or fragment")
        if not parsed.path.endswith("/v1/users/lookup"):
            raise ValueError("boolean SQLi probe is fixed to the lab lookup endpoint")
        probe = BooleanSQLiProbeInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["bug-bounty-sqli-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "scenarioId": probe.scenario_id,
                },
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_worker_failure(result),
            )
        try:
            raw = decode_strict_worker_json_object(
                result,
                label="boolean SQLi probe output",
            )
            output = BooleanSQLiProbeOutput.model_validate(raw)
            probe = BooleanSQLiProbeInput.model_validate(request.arguments)
            if output.target != request.target or output.scenario_id != probe.scenario_id:
                raise ValueError("worker output identity does not match the Tool request")
            if not output.network_performed:
                raise ValueError("worker did not attest network execution")
        except ValueError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_tool_interpretation_failure(
                    "invalid boolean SQLi probe output",
                    exc,
                ),
            )
        return ToolResult(
            request_id=request.request_id,
            tool_id=request.tool_id,
            success=True,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=output.model_dump(mode="json", by_alias=True),
        )

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        output = BooleanSQLiProbeOutput.model_validate(result.data)
        receipts = host_observed_http_receipts(
            worker_result,
            network_log_trusted=network_log_trusted,
        )
        if receipts is None:
            raise ValueError("boolean SQLi result requires host-observed HTTP receipts")
        if len(receipts) != 3:
            raise ValueError("boolean SQLi receipts must cover exactly three requests")

        parsed = urlsplit(request.target)
        fixed_values = (
            ("baseline", "1"),
            ("negative-control", "1' AND '1'='2"),
            ("boolean-probe", "1' OR '1'='1"),
        )
        for sequence, (receipt, observation, (name, value)) in enumerate(
            zip(receipts, output.observations, fixed_values, strict=True),
            start=1,
        ):
            expected_target = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    urlencode({"id": value}),
                    "",
                )
            )
            body, response, response_json_sha256 = decode_bounded_json_response(
                observation.response_body_base64,
                max_bytes=MAX_BOOLEAN_SQLI_RESPONSE_BYTES,
            )
            body_sha256 = sha256(body).hexdigest()
            record_count = response.get("recordCount")
            synthetic = response.get("synthetic")
            if (
                not isinstance(record_count, int)
                or isinstance(record_count, bool)
                or not 0 <= record_count <= 100
                or not isinstance(synthetic, bool)
            ):
                raise ValueError("boolean SQLi response body has invalid semantic fields")
            if (
                receipt.sequence != sequence
                or receipt.method != "GET"
                or receipt.target != audit_http_target(expected_target)
                or receipt.target_sha256 != http_target_sha256(expected_target)
                or observation.name != name
                or receipt.status != observation.status
                or not compare_digest(receipt.response_body_sha256, body_sha256)
                or not compare_digest(observation.body_sha256, body_sha256)
                or receipt.response_json_sha256 is None
                or not compare_digest(receipt.response_json_sha256, response_json_sha256)
                or record_count != observation.record_count
                or synthetic is not observation.synthetic
            ):
                raise ValueError(
                    "boolean SQLi observations differ from host-observed HTTP receipts"
                )
