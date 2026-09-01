"""Provider-neutral conversation probe for authorized AI application targets."""

from __future__ import annotations

import json
from enum import StrEnum
from hashlib import sha256
from urllib.parse import urlsplit

from pydantic import Field, JsonValue, StrictBool, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.target_attestation import (
    AISourceTargetExecutionChallenge,
    AISourceTargetExecutionReceipt,
    AISourceTargetProxyBinding,
    TargetExecutionChallenge,
    TargetExecutionProxyBinding,
    TargetExecutionReceipt,
    TargetExecutionReceiptStatementV2,
    TargetExecutionTLSBinding,
    TargetExecutionTLSBindingV2,
    TargetExecutionTLSBindingV3,
    TargetExecutionTransportBinding,
)
from pajin.tools.base import (
    EGRESS_HTTP_RECEIPT_VERSION,
    MAX_TRUSTED_NETWORK_LOG_BYTES,
    HTTPJSONProxyReceipt,
    HTTPSConnectProxyReceipt,
    Tool,
    ToolSpec,
    audit_http_target,
    audit_safe_tool_interpretation_failure,
    audit_safe_worker_failure,
    decode_strict_worker_json_object,
    host_observed_http_receipts,
    host_observed_https_connect_receipts,
    http_target_sha256,
    https_connect_authority,
)

AI_CHAT_PROXY_RECEIPT_VERSION = EGRESS_HTTP_RECEIPT_VERSION
MAX_AI_CHAT_NETWORK_LOG_BYTES = MAX_TRUSTED_NETWORK_LOG_BYTES
_AI_SOURCE_TARGET_URL = "http://host.docker.internal:8080/v1/chat"


class ChatRole(StrEnum):
    DEVELOPER = "developer"
    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"


class ChatMessage(StrictModel):
    role: ChatRole
    content: str = Field(min_length=1, max_length=32_768)


class ProbeTurn(StrictModel):
    name: str = Field(min_length=1, max_length=100)
    messages: list[ChatMessage] = Field(min_length=1, max_length=20)


class ProbeCheckKind(StrEnum):
    RESPONSE_CONTAINS = "response-contains"
    RESPONSE_EXCLUDES = "response-excludes"


class ProbeCheck(StrictModel):
    check_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-z0-9][a-z0-9.-]*$")
    kind: ProbeCheckKind
    turn: int = Field(ge=0, le=19)
    value: str = Field(min_length=1, max_length=4_096)
    sensitive: bool = False


class AIChatProbeInput(StrictModel):
    scenario_id: str = Field(pattern=r"^kisa\.[a-z0-9.-]+$")
    threat_class: str = Field(pattern=r"^[DMAS]\d{2}$")
    session_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    turns: list[ProbeTurn] = Field(min_length=1, max_length=20)
    checks: list[ProbeCheck] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def checks_reference_existing_turns(self) -> AIChatProbeInput:
        if any(check.turn >= len(self.turns) for check in self.checks):
            raise ValueError("probe check references a missing turn")
        return self


class AIChatRegressionInput(StrictModel):
    session_id: str = Field(
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    turns: list[ProbeTurn] = Field(min_length=1, max_length=20)
    checks: list[ProbeCheck] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def checks_reference_existing_turns(self) -> AIChatRegressionInput:
        if any(check.turn >= len(self.turns) for check in self.checks):
            raise ValueError("regression check references a missing turn")
        return self


class ProbePurpose(StrEnum):
    ATTACK = "attack"
    REGRESSION = "regression"


class AIChatProbeRequestMetadata(StrictModel):
    scenario_id: str = Field(alias="scenarioId", min_length=1, max_length=200)
    turn: int = Field(strict=True, ge=0, le=19)
    target_challenge: TargetExecutionChallenge | None = Field(
        default=None,
        alias="targetChallenge",
        exclude_if=lambda value: value is None,
    )
    target_exchange_ordinal: int | None = Field(
        default=None,
        alias="targetExchangeOrdinal",
        strict=True,
        ge=1,
        le=20,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def require_complete_target_challenge(self) -> AIChatProbeRequestMetadata:
        if (self.target_challenge is None) != (self.target_exchange_ordinal is None):
            raise ValueError(
                "AI probe target challenge and exchange ordinal must be supplied together"
            )
        return self


class AIChatProbeTurnRequest(StrictModel):
    session_id: str = Field(
        alias="sessionId",
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    messages: list[ChatMessage] = Field(min_length=1, max_length=20)
    metadata: AIChatProbeRequestMetadata | None = None


class AIChatProbeSafety(StrictModel):
    blocked: StrictBool = False
    reason: str | None = Field(default=None, max_length=500)


class AIChatProbeTurnResponse(StrictModel):
    session_id: str = Field(
        alias="sessionId",
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    message: ChatMessage
    tool_calls: list[JsonValue] = Field(default_factory=list, alias="toolCalls", max_length=100)
    safety: AIChatProbeSafety = Field(default_factory=AIChatProbeSafety)
    memory_writes: list[str] = Field(default_factory=list, alias="memoryWrites", max_length=100)
    model: str | None = Field(default=None, max_length=200)
    target_receipt: TargetExecutionReceipt | None = Field(
        default=None,
        alias="targetReceipt",
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def require_assistant_message(self) -> AIChatProbeTurnResponse:
        if self.message.role is not ChatRole.ASSISTANT:
            raise ValueError("AI probe response message role must be assistant")
        return self


class AIChatProbeTurnRecord(StrictModel):
    index: int = Field(strict=True, ge=0, le=19)
    name: str = Field(min_length=1, max_length=100)
    request: AIChatProbeTurnRequest
    response: AIChatProbeTurnResponse
    response_latency_seconds: float | None = Field(
        default=None,
        alias="responseLatencySeconds",
        strict=True,
        ge=0,
    )
    tls_peer_leaf_spki_sha256: str | None = Field(
        default=None,
        alias="tlsPeerLeafSpkiSha256",
        pattern=r"^[a-f0-9]{64}$",
        exclude_if=lambda value: value is None,
    )
    tls_session_binding_sha256: str | None = Field(
        default=None,
        alias="tlsSessionBindingSha256",
        pattern=r"^[a-f0-9]{64}$",
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def require_tls_endpoint_for_session_binding(self) -> AIChatProbeTurnRecord:
        if (
            self.tls_session_binding_sha256 is not None
            and self.tls_peer_leaf_spki_sha256 is None
        ):
            raise ValueError("TLS session binding requires a peer leaf SPKI observation")
        return self


class AIChatProbeCheckRecord(StrictModel):
    check_id: str = Field(
        alias="checkId",
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9.-]*$",
    )
    kind: ProbeCheckKind
    turn: int = Field(strict=True, ge=0, le=19)
    matched: StrictBool
    sensitive: StrictBool = False


class AIChatProbeOutput(StrictModel):
    """Typed Worker observation shared by the Tool and trusted Candidate Producer."""

    target: str = Field(min_length=1, max_length=2_000)
    scenario_id: str = Field(
        alias="scenarioId",
        pattern=r"^(kisa|retest)\.[a-z0-9.-]+$",
    )
    threat_class: str = Field(alias="threatClass", pattern=r"^[DMAS]\d{2}$")
    session_id: str = Field(
        alias="sessionId",
        min_length=3,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$",
    )
    purpose: ProbePurpose
    vulnerable: StrictBool
    observation: str = Field(min_length=1, max_length=2_000)
    turns: list[AIChatProbeTurnRecord] = Field(min_length=1, max_length=20)
    checks: list[AIChatProbeCheckRecord] = Field(min_length=1, max_length=20)
    sensitive_exposure_count: int = Field(
        alias="sensitiveExposureCount",
        strict=True,
        ge=0,
        le=20,
    )
    mean_response_latency_seconds: float = Field(
        alias="meanResponseLatencySeconds",
        strict=True,
        ge=0,
    )
    regression_passed: StrictBool | None = Field(default=None, alias="regressionPassed")
    network_performed: StrictBool = Field(alias="networkPerformed")

    @model_validator(mode="after")
    def validate_transcript_contract(self) -> AIChatProbeOutput:
        indexes = [turn.index for turn in self.turns]
        if indexes != list(range(len(self.turns))):
            raise ValueError("AI probe turn indexes must be contiguous and zero-based")
        if any(
            turn.request.session_id != self.session_id
            or turn.response.session_id != self.session_id
            for turn in self.turns
        ):
            raise ValueError("AI probe turn sessions must match the output session")
        for turn in self.turns:
            if turn.request.metadata is not None and (
                turn.request.metadata.scenario_id != self.scenario_id
                or turn.request.metadata.turn != turn.index
            ):
                raise ValueError("AI probe request metadata must match the output identity")
        check_ids = [check.check_id for check in self.checks]
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("AI probe output check IDs must be unique")
        if any(check.turn >= len(self.turns) for check in self.checks):
            raise ValueError("AI probe output check references a missing turn")
        if self.purpose is ProbePurpose.ATTACK and self.regression_passed is not None:
            raise ValueError("attack probe output must not contain a regression verdict")
        if self.purpose is ProbePurpose.REGRESSION:
            if self.regression_passed is None:
                raise ValueError("regressionPassed must be boolean for regression output")
            if self.vulnerable:
                raise ValueError("regression output cannot claim a vulnerability")
        return self


class AIChatProxyReceipt(HTTPJSONProxyReceipt):
    """Host-observed HTTP JSON exchange emitted by the isolated egress proxy."""


class AIChatProbeTool(Tool):
    """Execute bounded multi-turn probes against the PAJIN AI chat contract."""

    spec = ToolSpec(
        tool_id="ai.chat-probe",
        version="1.0.0",
        description="POST a bounded provider-neutral conversation to an authorized AI target",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"active-test", "ai-redteam", "llm", "rag", "agent"}),
        evidence_types=frozenset({"json", "conversation"}),
        network_access=True,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

    def network_request_cost(self, request: ToolRequest) -> int:
        """The Worker performs exactly one bounded POST for every declared turn."""

        return len(AIChatProbeInput.model_validate(request.arguments).turns)

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "POST":
            raise ValueError("AI chat probes require POST")
        probe = AIChatProbeInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["ai-chat-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "probe": probe.model_dump(mode="json"),
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
            raw = decode_strict_worker_json_object(result, label="AI probe output")
            output = AIChatProbeOutput.model_validate(raw)
            self._validate_output_identity(request, output)
        except ValueError as exc:
            return ToolResult(
                request_id=request.request_id,
                tool_id=request.tool_id,
                success=False,
                started_at=result.started_at,
                finished_at=result.finished_at,
                error=audit_safe_tool_interpretation_failure(
                    "invalid AI probe output",
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
        output = self._validated_trusted_output(request, result, worker_result)
        if not verify_ai_chat_proxy_receipts(
            request,
            worker_result,
            output,
            network_log_trusted=network_log_trusted,
        ):
            raise ValueError("AI probe requires complete host-observed HTTP receipts")

    def _validated_trusted_output(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
    ) -> AIChatProbeOutput:
        if worker_result.status is not WorkerStatus.SUCCEEDED:
            raise ValueError("successful AI probe requires a successful Worker execution")
        if worker_result.stdout_truncated or worker_result.stderr_truncated:
            raise ValueError("trusted AI probe requires a complete Worker transcript")
        if (
            result.started_at != worker_result.started_at
            or result.finished_at != worker_result.finished_at
            or result.error is not None
        ):
            raise ValueError("AI probe result timing or error differs from its Worker receipt")
        try:
            raw = decode_strict_worker_json_object(
                worker_result,
                label="raw AI probe transcript",
            )
            output = AIChatProbeOutput.model_validate(raw)
            self._validate_output_identity(request, output)
        except ValueError as exc:
            raise ValueError("raw AI probe transcript is invalid") from exc
        if result.data != output.model_dump(mode="json", by_alias=True):
            raise ValueError("AI probe Tool result differs from raw Worker stdout")
        return output

    def _validate_output_identity(
        self,
        request: ToolRequest,
        output: AIChatProbeOutput,
    ) -> None:
        probe = AIChatProbeInput.model_validate(request.arguments)
        if (
            output.target != request.target
            or output.scenario_id != probe.scenario_id
            or output.threat_class != probe.threat_class
            or output.session_id != probe.session_id
            or output.purpose is not ProbePurpose.ATTACK
        ):
            raise ValueError("worker output identity does not match the AI probe request")
        if not output.network_performed:
            raise ValueError("worker did not attest network execution")


class AIM03SourceChatProbeTool(AIChatProbeTool):
    """Inject one exact AI-002B source challenge without changing Tool identity."""

    def __init__(
        self,
        *,
        challenge: AISourceTargetExecutionChallenge,
        expected_request: ToolRequest,
    ) -> None:
        self._challenge = AISourceTargetExecutionChallenge.model_validate_json(
            challenge.model_dump_json()
        )
        self._expected_request = ToolRequest.model_validate_json(expected_request.model_dump_json())
        parsed = urlsplit(self._expected_request.target)
        if (
            self._expected_request.request_id != self._challenge.source_request_id
            or self._expected_request.method != "POST"
            or self._expected_request.target != _AI_SOURCE_TARGET_URL
            or parsed.scheme != "http"
            or parsed.path != self._challenge.route_path
            or parsed.query
            or parsed.fragment
            or sha256(self._expected_request.target.encode("utf-8")).hexdigest()
            != self._challenge.target_sha256
            or _canonical_json_sha256(self._expected_request.arguments)
            != self._challenge.compiled_argument_digest
        ):
            raise ValueError("AI-002B source challenge differs from its exact Tool request")
        probe = AIChatProbeInput.model_validate(self._expected_request.arguments)
        if (
            probe.scenario_id != "kisa.model.system-prompt-disclosure"
            or probe.threat_class != "M03"
            or len(probe.turns) != 1
            or len(probe.checks) != 1
        ):
            raise ValueError("AI-002B source Tool accepts only the exact single-turn M03 shape")

    @property
    def source_challenge(self) -> AISourceTargetExecutionChallenge:
        return self._challenge.model_copy(deep=True)

    def prepare(self, request: ToolRequest) -> WorkerJob:
        canonical = ToolRequest.model_validate_json(request.model_dump_json())
        if canonical != self._expected_request:
            raise ValueError("AI-002B source Tool request was substituted")
        prepared = super().prepare(canonical)
        payload = json.loads(prepared.stdin)
        if not isinstance(payload, dict) or "sourceTargetChallenge" in payload:
            raise ValueError("AI-002B source Worker challenge is ambiguous")
        payload["sourceTargetChallenge"] = self._challenge.model_dump(mode="json")
        return WorkerJob.model_validate(
            {
                **prepared.model_dump(mode="python"),
                "stdin": json.dumps(
                    payload,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ),
            }
        )


class AIChatRegressionTool(AIChatProbeTool):
    """Verify normal chat behavior without contributing an attack finding."""

    spec = ToolSpec(
        tool_id="ai.normal-probe",
        version="1.0.0",
        description="POST a bounded normal-use conversation to an authorized AI target",
        risk_tier=ToolRiskTier.T1,
        categories=frozenset({"active-test", "ai-redteam", "regression"}),
        evidence_types=frozenset({"json", "conversation"}),
        network_access=True,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

    def network_request_cost(self, request: ToolRequest) -> int:
        return len(AIChatRegressionInput.model_validate(request.arguments).turns)

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "POST":
            raise ValueError("AI normal-function probes require POST")
        probe = AIChatRegressionInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["ai-chat-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "probe": {
                        "scenario_id": "retest.normal-chat-function",
                        "threat_class": "A00",
                        "session_id": probe.session_id,
                        "turns": [turn.model_dump(mode="json") for turn in probe.turns],
                        "checks": [check.model_dump(mode="json") for check in probe.checks],
                        "purpose": "regression",
                    },
                },
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
        )

    def _validate_output_identity(
        self,
        request: ToolRequest,
        output: AIChatProbeOutput,
    ) -> None:
        probe = AIChatRegressionInput.model_validate(request.arguments)
        if (
            output.target != request.target
            or output.scenario_id != "retest.normal-chat-function"
            or output.threat_class != "A00"
            or output.session_id != probe.session_id
            or output.purpose is not ProbePurpose.REGRESSION
        ):
            raise ValueError("worker output identity does not match the AI regression request")
        if not output.network_performed:
            raise ValueError("worker did not attest network execution")


def evaluate_probe_check(check: ProbeCheck, turn_records: list[dict[str, object]]) -> bool:
    """Evaluate a scenario assertion over a normalized transcript."""

    try:
        response = turn_records[check.turn]["response"]
        if not isinstance(response, dict):
            return False
        message = response["message"]
        if not isinstance(message, dict):
            return False
        content = message["content"]
        if not isinstance(content, str):
            return False
    except (IndexError, KeyError, TypeError):
        return False
    contains = check.value in content
    if check.kind is ProbeCheckKind.RESPONSE_CONTAINS:
        return contains
    if check.kind is ProbeCheckKind.RESPONSE_EXCLUDES:
        return not contains
    return False


def _canonical_json_sha256(value: object) -> str:
    try:
        canonical = json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValueError("AI transcript contains non-canonical JSON") from exc
    return sha256(canonical).hexdigest()


def _host_observed_ai_transport_receipts(
    request: ToolRequest,
    worker_result: WorkerResult,
    *,
    network_log_trusted: bool,
    allow_target_attested_https: bool,
) -> list[HTTPJSONProxyReceipt | HTTPSConnectProxyReceipt] | None:
    scheme = urlsplit(request.target).scheme
    if scheme not in {"http", "https"}:
        raise ValueError("AI transport receipts require an HTTP(S) target")
    if scheme == "https" and allow_target_attested_https:
        https_receipts = host_observed_https_connect_receipts(
            worker_result,
            network_log_trusted=network_log_trusted,
        )
        return None if https_receipts is None else list(https_receipts)
    http_receipts = host_observed_http_receipts(
        worker_result,
        network_log_trusted=network_log_trusted,
    )
    return None if http_receipts is None else list(http_receipts)


def _ai_probe_and_scenario(
    request: ToolRequest,
) -> tuple[AIChatProbeInput | AIChatRegressionInput, str]:
    if request.tool_id == AIChatProbeTool.spec.tool_id:
        probe = AIChatProbeInput.model_validate(request.arguments)
        return probe, probe.scenario_id
    if request.tool_id == AIChatRegressionTool.spec.tool_id:
        return AIChatRegressionInput.model_validate(request.arguments), (
            "retest.normal-chat-function"
        )
    raise ValueError("AI proxy receipts require a registered AI chat Tool")


def verify_ai_chat_proxy_receipts(
    request: ToolRequest,
    worker_result: WorkerResult,
    output: AIChatProbeOutput,
    *,
    network_log_trusted: bool,
    allow_target_attested_https: bool = False,
) -> bool:
    """Bind each typed transcript turn to host-observed proxy request/response bytes.

    ``False`` means the trusted observation is unavailable, including HTTPS CONNECT
    where the proxy cannot observe plaintext. Malformed, partial, duplicate, mixed,
    or contradictory trusted logs are integrity errors and fail closed.
    """

    scheme = urlsplit(request.target).scheme
    receipts = _host_observed_ai_transport_receipts(
        request,
        worker_result,
        network_log_trusted=network_log_trusted,
        allow_target_attested_https=allow_target_attested_https,
    )
    if receipts is None:
        return False
    if len(receipts) != len(output.turns):
        raise ValueError("Docker egress proxy receipts do not cover every transcript turn")

    probe, scenario_id = _ai_probe_and_scenario(request)
    if len(probe.turns) != len(output.turns):
        raise ValueError("AI proxy receipt count differs from the sealed probe")

    try:
        raw_output = decode_strict_worker_json_object(
            worker_result,
            label="raw Worker transcript",
        )
        raw_turns = raw_output["turns"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("raw Worker transcript cannot be bound to proxy receipts") from exc
    if not isinstance(raw_turns, list) or len(raw_turns) != len(output.turns):
        raise ValueError("raw Worker transcript turn count differs from proxy receipts")

    expected_target = audit_http_target(request.target)
    expected_target_digest = http_target_sha256(request.target)
    expected_authority = https_connect_authority(request.target) if scheme == "https" else None
    for index, (receipt, turn, raw_turn) in enumerate(
        zip(receipts, probe.turns, raw_turns, strict=True)
    ):
        if (
            not isinstance(raw_turn, dict)
            or not isinstance(raw_turn.get("request"), dict)
            or not isinstance(raw_turn.get("response"), dict)
        ):
            raise ValueError("raw Worker transcript response is missing")
        raw_request = raw_turn["request"]
        expected_request = {
            "sessionId": probe.session_id,
            "messages": [message.model_dump(mode="json") for message in turn.messages],
            "metadata": {"scenarioId": scenario_id, "turn": index},
        }
        receipt_request = raw_request
        if "metadata" not in raw_request:
            if raw_request != {
                "sessionId": expected_request["sessionId"],
                "messages": expected_request["messages"],
            }:
                raise ValueError("raw Worker transcript request differs from the sealed probe")
            receipt_request = expected_request
        typed_request = AIChatProbeTurnRequest.model_validate(receipt_request)
        metadata = typed_request.metadata
        if (
            typed_request.session_id != probe.session_id
            or typed_request.messages != turn.messages
            or metadata is None
            or metadata.scenario_id != scenario_id
            or metadata.turn != index
        ):
            raise ValueError("raw Worker transcript request differs from the sealed probe")
        if isinstance(receipt, HTTPJSONProxyReceipt):
            if (
                receipt.method != request.method
                or receipt.method != "POST"
                or receipt.target != expected_target
                or receipt.target_sha256 != expected_target_digest
                or not 200 <= receipt.status < 300
                or receipt.request_json_sha256 != _canonical_json_sha256(receipt_request)
                or receipt.response_json_sha256 != _canonical_json_sha256(raw_turn["response"])
            ):
                raise ValueError("AI transcript differs from its host-observed proxy receipt")
        elif (
            expected_authority is None
            or receipt.sequence != index + 1
            or receipt.authority != expected_authority
            or receipt.authority_sha256 != sha256(expected_authority.encode("utf-8")).hexdigest()
        ):
            raise ValueError("AI transcript differs from its host-observed HTTPS CONNECT route")
    return True


def ai_source_target_proxy_binding(
    request: ToolRequest,
    worker_result: WorkerResult,
    output: AIChatProbeOutput,
    *,
    expected_challenge: AISourceTargetExecutionChallenge,
    target_receipt: AISourceTargetExecutionReceipt,
    network_log_trusted: bool,
) -> AISourceTargetProxyBinding:
    """Bind the private AI-002B Target receipt to one plaintext proxy exchange."""

    receipts = _host_observed_ai_transport_receipts(
        request,
        worker_result,
        network_log_trusted=network_log_trusted,
        allow_target_attested_https=False,
    )
    if (
        receipts is None
        or len(receipts) != 1
        or not isinstance(receipts[0], HTTPJSONProxyReceipt)
        or len(output.turns) != 1
    ):
        raise ValueError("AI source Target receipt requires one plaintext proxy exchange")
    if (
        expected_challenge.source_request_id != request.request_id
        or expected_challenge.target_sha256 != http_target_sha256(request.target)
        or expected_challenge.method != request.method
        or expected_challenge.compiled_argument_digest != _canonical_json_sha256(request.arguments)
    ):
        raise ValueError("AI source Target challenge differs from its exact Tool request")
    try:
        raw_output = decode_strict_worker_json_object(
            worker_result,
            label="raw AI source transcript",
        )
        raw_turns = raw_output["turns"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("AI source Worker transcript cannot be decoded") from exc
    if (
        not isinstance(raw_turns, list)
        or len(raw_turns) != 1
        or not isinstance(raw_turns[0], dict)
        or not isinstance(raw_turns[0].get("request"), dict)
        or not isinstance(raw_turns[0].get("response"), dict)
    ):
        raise ValueError("AI source Worker transcript turn is malformed")
    raw_turn = raw_turns[0]
    raw_request = raw_turn["request"]
    raw_response = raw_turn["response"]
    receipt = receipts[0]
    statement = target_receipt.statement
    request_digest = _canonical_json_sha256(raw_request)
    response_digest = _canonical_json_sha256(raw_response)
    if (
        statement.challenge_id != expected_challenge.challenge_id
        or statement.challenge_sha256 != expected_challenge.digest
        or statement.permit_digest != expected_challenge.permit_digest
        or statement.source_request_id != expected_challenge.source_request_id
        or statement.source_operation_id != expected_challenge.source_operation_id
        or statement.call_ordinal != 1
        or statement.exchange_ordinal != 1
        or statement.target_sha256 != expected_challenge.target_sha256
        or statement.method != "POST"
        or statement.route_path != "/v1/chat"
        or statement.request_json_sha256 != request_digest
        or statement.response_payload_sha256 != response_digest
        or not expected_challenge.issued_at <= statement.issued_at < expected_challenge.expires_at
        or receipt.sequence != 1
        or receipt.method != "POST"
        or receipt.target != audit_http_target(request.target)
        or receipt.target_sha256 != http_target_sha256(request.target)
        or receipt.status != statement.status
        or receipt.request_json_sha256 != request_digest
        or receipt.response_json_sha256 != response_digest
    ):
        raise ValueError(
            "AI source Target receipt differs from its challenge, transcript, or proxy receipt"
        )
    return AISourceTargetProxyBinding(
        source_request_id=request.request_id,
        challenge_sha256=expected_challenge.digest,
        target_receipt_sha256=target_receipt.digest,
        proxy_sequence=1,
        proxy_method="POST",
        proxy_target=receipt.target,
        proxy_target_sha256=receipt.target_sha256,
        proxy_address=receipt.address,
        proxy_status=receipt.status,
        proxy_request_json_sha256=request_digest,
        proxy_response_body_sha256=receipt.response_body_sha256,
        proxy_response_json_sha256=response_digest,
    )


def _target_execution_tls_binding(
    request: ToolRequest,
    *,
    expected_challenge: TargetExecutionChallenge,
    transport_receipt: HTTPSConnectProxyReceipt,
    typed_turn: AIChatProbeTurnRecord,
    raw_turn: dict[str, object],
    index: int,
    target_receipt: TargetExecutionReceipt,
    request_digest: str,
    full_response_digest: str,
) -> TargetExecutionTLSBinding | TargetExecutionTLSBindingV2 | TargetExecutionTLSBindingV3:
    expected_authority = https_connect_authority(request.target)
    if (
        transport_receipt.sequence != index
        or transport_receipt.authority != expected_authority
        or transport_receipt.authority_sha256
        != sha256(expected_authority.encode("utf-8")).hexdigest()
    ):
        raise ValueError("HTTPS Target receipt differs from its observed CONNECT route")
    raw_tls_peer_leaf_spki_sha256 = raw_turn.get("tlsPeerLeafSpkiSha256")
    if typed_turn.tls_peer_leaf_spki_sha256 != raw_tls_peer_leaf_spki_sha256:
        raise ValueError(
            "typed HTTPS peer leaf SPKI digest differs from the raw Worker observation"
        )
    raw_tls_session_binding_sha256 = raw_turn.get("tlsSessionBindingSha256")
    if typed_turn.tls_session_binding_sha256 != raw_tls_session_binding_sha256:
        raise ValueError(
            "typed HTTPS session binding digest differs from the raw Worker observation"
        )
    binding_fields: dict[str, object] = {
        "replay_request_id": request.request_id,
        "exchange_ordinal": index,
        "challenge_sha256": expected_challenge.digest,
        "target_receipt_sha256": target_receipt.digest,
        "target_sha256": expected_challenge.target_sha256,
        "connect_sequence": transport_receipt.sequence,
        "connect_authority": transport_receipt.authority,
        "connect_authority_sha256": transport_receipt.authority_sha256,
        "connect_address": transport_receipt.address,
        "application_method": "POST",
        "transcript_request_json_sha256": request_digest,
        "transcript_response_json_sha256": full_response_digest,
    }
    statement = target_receipt.statement
    if isinstance(statement, TargetExecutionReceiptStatementV2):
        if (
            raw_tls_peer_leaf_spki_sha256 is None
            or raw_tls_session_binding_sha256 is None
            or raw_tls_session_binding_sha256
            != statement.tls_session_binding_sha256
        ):
            raise ValueError(
                "Target-signed TLS session binding differs from the Worker observation"
            )
        return TargetExecutionTLSBindingV3.model_validate(
            {
                **binding_fields,
                "tls_peer_leaf_spki_sha256": raw_tls_peer_leaf_spki_sha256,
                "tls_version": statement.tls_version,
                "tls_session_binding": statement.tls_session_binding,
                "tls_session_binding_sha256": raw_tls_session_binding_sha256,
            }
        )
    if raw_tls_peer_leaf_spki_sha256 is None:
        return TargetExecutionTLSBinding.model_validate(binding_fields)
    return TargetExecutionTLSBindingV2.model_validate(
        {
            **binding_fields,
            "tls_peer_leaf_spki_sha256": raw_tls_peer_leaf_spki_sha256,
        }
    )


def target_execution_proxy_bindings(
    request: ToolRequest,
    worker_result: WorkerResult,
    output: AIChatProbeOutput,
    *,
    expected_challenge: TargetExecutionChallenge,
    network_log_trusted: bool,
) -> list[TargetExecutionTransportBinding]:
    """Bind Target receipts to plaintext exchanges or opaque HTTPS tunnel routes."""

    receipts = _host_observed_ai_transport_receipts(
        request,
        worker_result,
        network_log_trusted=network_log_trusted,
        allow_target_attested_https=True,
    )
    if receipts is None or len(receipts) != len(output.turns):
        raise ValueError("target execution receipts require complete proxy coverage")
    if expected_challenge.replay_request_id != request.request_id:
        raise ValueError("target execution challenge belongs to another Replay request")
    if expected_challenge.target_sha256 != http_target_sha256(request.target):
        raise ValueError("target execution challenge belongs to another target")
    if expected_challenge.method != request.method:
        raise ValueError("target execution challenge method differs from the Tool request")

    try:
        raw_output = decode_strict_worker_json_object(
            worker_result,
            label="raw target-attested AI transcript",
        )
        raw_turns = raw_output["turns"]
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("target-attested Worker transcript cannot be decoded") from exc
    if not isinstance(raw_turns, list) or len(raw_turns) != len(output.turns):
        raise ValueError("target-attested transcript turn count is inconsistent")

    bindings: list[TargetExecutionTransportBinding] = []
    for index, (transport_receipt, typed_turn, raw_turn) in enumerate(
        zip(receipts, output.turns, raw_turns, strict=True),
        start=1,
    ):
        if (
            not isinstance(raw_turn, dict)
            or not isinstance(raw_turn.get("request"), dict)
            or not isinstance(raw_turn.get("response"), dict)
        ):
            raise ValueError("target-attested transcript turn is malformed")
        metadata = typed_turn.request.metadata
        target_receipt = typed_turn.response.target_receipt
        if (
            metadata is None
            or metadata.target_challenge != expected_challenge
            or metadata.target_exchange_ordinal != index
            or target_receipt is None
        ):
            raise ValueError("target-attested transcript omitted its exact challenge or receipt")
        response_payload = dict(raw_turn["response"])
        raw_target_receipt = response_payload.pop("targetReceipt", None)
        if (
            not isinstance(raw_target_receipt, dict)
            or TargetExecutionReceipt.model_validate(raw_target_receipt) != target_receipt
        ):
            raise ValueError("target receipt differs from the raw Target response")
        statement = target_receipt.statement
        request_digest = _canonical_json_sha256(raw_turn["request"])
        response_payload_digest = _canonical_json_sha256(response_payload)
        full_response_digest = _canonical_json_sha256(raw_turn["response"])
        if (
            statement.challenge_id != expected_challenge.challenge_id
            or statement.challenge_sha256 != expected_challenge.digest
            or statement.permit_digest != expected_challenge.permit_digest
            or statement.replay_request_id != expected_challenge.replay_request_id
            or statement.batch_id != expected_challenge.batch_id
            or statement.item_id != expected_challenge.item_id
            or statement.ticket_id != expected_challenge.ticket_id
            or statement.fencing_value != expected_challenge.fencing_value
            or statement.call_ordinal != expected_challenge.call_ordinal
            or statement.exchange_ordinal != index
            or statement.target_sha256 != expected_challenge.target_sha256
            or statement.method != expected_challenge.method
            or statement.request_json_sha256 != request_digest
            or statement.response_payload_sha256 != response_payload_digest
            or not expected_challenge.issued_at
            <= statement.issued_at
            < expected_challenge.expires_at
        ):
            raise ValueError(
                "target receipt differs from its challenge, transcript, or proxy receipt"
            )
        if isinstance(transport_receipt, HTTPJSONProxyReceipt):
            if (
                statement.status != transport_receipt.status
                or transport_receipt.request_json_sha256 != request_digest
                or transport_receipt.response_json_sha256 != full_response_digest
            ):
                raise ValueError(
                    "target receipt differs from its challenge, transcript, or proxy receipt"
                )
            bindings.append(
                TargetExecutionProxyBinding(
                    replay_request_id=request.request_id,
                    exchange_ordinal=index,
                    challenge_sha256=expected_challenge.digest,
                    target_receipt_sha256=target_receipt.digest,
                    proxy_sequence=transport_receipt.sequence,
                    proxy_method="POST",
                    proxy_target=transport_receipt.target,
                    proxy_target_sha256=transport_receipt.target_sha256,
                    proxy_address=transport_receipt.address,
                    proxy_status=transport_receipt.status,
                    proxy_request_json_sha256=request_digest,
                    proxy_response_body_sha256=transport_receipt.response_body_sha256,
                    proxy_response_json_sha256=full_response_digest,
                )
            )
        else:
            bindings.append(
                _target_execution_tls_binding(
                    request,
                    expected_challenge=expected_challenge,
                    transport_receipt=transport_receipt,
                    typed_turn=typed_turn,
                    raw_turn=raw_turn,
                    index=index,
                    target_receipt=target_receipt,
                    request_digest=request_digest,
                    full_response_digest=full_response_digest,
                )
            )
    return bindings


def evaluate_trusted_regression(
    request: ToolRequest,
    result: ToolResult,
    worker_result: WorkerResult,
    *,
    network_log_trusted: bool,
) -> bool | None:
    """Recompute a normal-function verdict from sealed inputs and raw transcript.

    ``regressionPassed`` and the Worker's serialized check records remain useful
    observations, but neither is authoritative.  The trusted caller supplies the
    exact persisted request, Tool result, and raw Worker result; this function
    binds those three records before evaluating the request's checks itself.
    """

    if request.tool_id != AIChatRegressionTool.spec.tool_id or request.method != "POST":
        raise ValueError("trusted regression requires an ai.normal-probe request")
    if result.request_id != request.request_id or result.tool_id != request.tool_id:
        raise ValueError("AI regression Tool result identity differs from its request")
    if not result.success:
        return None
    if worker_result.status is not WorkerStatus.SUCCEEDED:
        raise ValueError("successful AI regression Tool result requires a successful Worker")
    if worker_result.stdout_truncated or worker_result.stderr_truncated:
        raise ValueError("trusted AI regression requires a complete Worker transcript")
    if (
        result.started_at != worker_result.started_at
        or result.finished_at != worker_result.finished_at
        or result.error is not None
    ):
        raise ValueError("AI regression Tool result timing or error differs from its Worker")

    try:
        raw = decode_strict_worker_json_object(
            worker_result,
            label="raw AI regression transcript",
        )
        output = AIChatProbeOutput.model_validate(raw)
    except ValueError as exc:
        raise ValueError(
            audit_safe_tool_interpretation_failure(
                "invalid raw AI regression transcript",
                exc,
            )
        ) from exc
    if result.data != output.model_dump(mode="json", by_alias=True):
        raise ValueError("AI regression Tool result data differs from raw Worker stdout")

    probe = AIChatRegressionInput.model_validate(request.arguments)
    if (
        output.target != request.target
        or output.scenario_id != "retest.normal-chat-function"
        or output.threat_class != "A00"
        or output.session_id != probe.session_id
        or output.purpose is not ProbePurpose.REGRESSION
        or not output.network_performed
    ):
        raise ValueError("raw AI regression transcript identity differs from its request")
    if len(output.turns) != len(probe.turns):
        raise ValueError("raw AI regression transcript turn count differs from its request")
    for index, (expected, observed) in enumerate(zip(probe.turns, output.turns, strict=True)):
        if (
            observed.index != index
            or observed.name != expected.name
            or observed.request.session_id != probe.session_id
            or observed.request.messages != expected.messages
        ):
            raise ValueError("raw AI regression transcript request differs from its sealed input")

    if not verify_ai_chat_proxy_receipts(
        request,
        worker_result,
        output,
        network_log_trusted=network_log_trusted,
    ):
        return None

    turn_records = output.model_dump(mode="json", by_alias=True)["turns"]
    assert isinstance(turn_records, list)
    return all(evaluate_probe_check(check, turn_records) for check in probe.checks)
