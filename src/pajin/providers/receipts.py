"""Secret-free authority projection for one successful bound Provider chat."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from math import isfinite
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import CapabilityGrant, StrictModel, ToolRequest
from pajin.providers.models import (
    ProviderChatRequest,
    ProviderChatResult,
    ProviderRegistration,
)
from pajin.providers.usage import provider_model_usage_upper_bound
from pajin.runtime.control import BudgetExceeded
from pajin.runtime.store import validate_run_artifact_path
from pajin.runtime.worker import WorkerStatus
from pajin.tools.execution_receipts import validate_strict_json
from pajin.tools.gateway import GatewayOutcome, canonical_tool_request_digest

PROVIDER_BOUND_CHAT_OUTCOME_API_VERSION: Literal[
    "pajin.dev/provider-bound-chat-outcome/v1alpha1"
] = "pajin.dev/provider-bound-chat-outcome/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_BOUND_OUTCOME_SOURCE_BYTES = 32 * 1024 * 1024
_MAX_BOUND_OUTCOME_BYTES = 2 * 1024 * 1024


class ProviderBoundOutcomeError(RuntimeError):
    """Raised when a Provider result cannot be bound without raw payload disclosure."""


class ProviderReportedUsage(StrictModel):
    """Exact untrusted usage reported by one successful Provider response."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    prompt_tokens: int = Field(alias="promptTokens", ge=0)
    completion_tokens: int = Field(alias="completionTokens", ge=0)
    total_tokens: int = Field(alias="totalTokens", ge=0)
    cost_usd: float = Field(alias="costUsd", ge=0)
    trust: Literal["provider-reported-untrusted"] = "provider-reported-untrusted"

    @field_validator("prompt_tokens", "completion_tokens", "total_tokens", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("reported Provider usage must use JSON integers")
        return value

    @field_validator("cost_usd", mode="before")
    @classmethod
    def require_finite_cost(cls, value: object) -> float:
        if type(value) not in {int, float}:
            raise ValueError("reported Provider cost must be a finite JSON number")
        number = cast(int | float, value)
        if not isfinite(float(number)):
            raise ValueError("reported Provider cost must be a finite JSON number")
        canonical = float(number)
        return 0.0 if canonical == 0 else canonical

    @model_validator(mode="after")
    def require_consistent_total(self) -> Self:
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("reported Provider token total differs")
        return self


class ProviderChargedUsage(StrictModel):
    """Conservative authority charged to the configured model-usage budget boundary."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    prompt_tokens: int = Field(alias="promptTokens", ge=0)
    completion_tokens: int = Field(alias="completionTokens", ge=0)
    total_tokens: int = Field(alias="totalTokens", ge=0)
    cost_usd: float = Field(alias="costUsd", ge=0)
    tool_calls: Literal[1] = Field(default=1, alias="toolCalls")
    model_calls: Literal[1] = Field(default=1, alias="modelCalls")
    budget_scope: Literal["campaign", "campaign-and-dedicated"] = Field(
        alias="budgetScope"
    )
    accounting: Literal["conservative-upper-bound"] = "conservative-upper-bound"

    @field_validator(
        "prompt_tokens",
        "completion_tokens",
        "total_tokens",
        "tool_calls",
        "model_calls",
        mode="before",
    )
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("charged Provider usage must use JSON integers")
        return value

    @field_validator("cost_usd", mode="before")
    @classmethod
    def require_finite_cost(cls, value: object) -> float:
        if type(value) not in {int, float}:
            raise ValueError("charged Provider cost must be a finite JSON number")
        number = cast(int | float, value)
        if not isfinite(float(number)):
            raise ValueError("charged Provider cost must be a finite JSON number")
        canonical = float(number)
        return 0.0 if canonical == 0 else canonical

    @model_validator(mode="after")
    def require_consistent_total(self) -> Self:
        if self.total_tokens != self.prompt_tokens + self.completion_tokens:
            raise ValueError("charged Provider token total differs")
        return self


class ProviderBoundChatOutcome(StrictModel):
    """Content-addressed successful Provider outcome with digest-only raw payload bindings."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/provider-bound-chat-outcome/v1alpha1"] = Field(
        default=PROVIDER_BOUND_CHAT_OUTCOME_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ProviderBoundChatOutcome"] = "ProviderBoundChatOutcome"
    outcome_id: str = Field(default="", alias="outcomeId", max_length=110)
    outcome_digest: str = Field(default="", alias="outcomeDigest", max_length=64)
    request_id: str = Field(
        alias="requestId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$",
    )
    agent_id: str = Field(
        alias="agentId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    tool_id: str = Field(
        alias="toolId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    provider_id: str = Field(alias="providerId", pattern=r"^[a-z0-9][a-z0-9-]{1,30}$")
    model: str = Field(min_length=1, max_length=200)
    provider_runtime_digest: _Sha256 = Field(alias="providerRuntimeDigest")
    capability_grant_digest: _Sha256 = Field(alias="capabilityGrantDigest")
    chat_request_digest: _Sha256 = Field(alias="chatRequestDigest")
    tool_request_digest: _Sha256 = Field(alias="toolRequestDigest")
    policy_decision_digest: _Sha256 = Field(alias="policyDecisionDigest")
    tool_result_digest: _Sha256 = Field(alias="toolResultDigest")
    worker_result_digest: _Sha256 = Field(alias="workerResultDigest")
    gateway_outcome_digest: _Sha256 = Field(alias="gatewayOutcomeDigest")
    provider_result_digest: _Sha256 = Field(alias="providerResultDigest")
    response_id_digest: _Sha256 = Field(alias="responseIdDigest")
    response_id_bytes: int = Field(alias="responseIdBytes", ge=1, le=2_000)
    target_digest: _Sha256 = Field(alias="targetDigest")
    content_digest: _Sha256 | None = Field(default=None, alias="contentDigest")
    content_bytes: int = Field(alias="contentBytes", ge=0, le=4_000_000)
    refusal_digest: _Sha256 | None = Field(default=None, alias="refusalDigest")
    refusal_bytes: int = Field(alias="refusalBytes", ge=0, le=4_000_000)
    finish_reason_digest: _Sha256 | None = Field(default=None, alias="finishReasonDigest")
    finish_reason_bytes: int = Field(alias="finishReasonBytes", ge=0, le=1_000)
    tool_calls_digest: _Sha256 = Field(alias="toolCallsDigest")
    evidence_reference_digests: tuple[_Sha256, ...] = Field(
        alias="evidenceReferenceDigests",
        min_length=1,
        max_length=100,
    )
    evidence_references: tuple[str, ...] = Field(
        alias="evidenceReferences",
        min_length=1,
        max_length=1,
    )
    tool_call_count: int = Field(alias="toolCallCount", ge=0, le=8)
    reported_usage: ProviderReportedUsage = Field(alias="reportedUsage")
    charged_usage: ProviderChargedUsage = Field(alias="chargedUsage")
    streamed: bool
    chunks: int = Field(ge=1)
    worker_status: Literal[WorkerStatus.SUCCEEDED] = Field(alias="workerStatus")
    worker_execution_id_digest: _Sha256 = Field(alias="workerExecutionIdDigest")
    worker_backend_digest: _Sha256 = Field(alias="workerBackendDigest")
    worker_exit_code: Literal[0] = Field(alias="workerExitCode")
    decision_allowed: Literal[True] = Field(default=True, alias="decisionAllowed")
    tool_result_success: Literal[True] = Field(default=True, alias="toolResultSuccess")
    result_identity_valid: Literal[True] = Field(default=True, alias="resultIdentityValid")
    executed: Literal[True] = True
    network_log_trusted: bool = Field(alias="networkLogTrusted")
    raw_request_embedded: Literal[False] = Field(default=False, alias="rawRequestEmbedded")
    raw_result_embedded: Literal[False] = Field(default=False, alias="rawResultEmbedded")
    secret_reference_embedded: Literal[False] = Field(
        default=False,
        alias="secretReferenceEmbedded",
    )
    raw_worker_transcript_embedded: Literal[False] = Field(
        default=False,
        alias="rawWorkerTranscriptEmbedded",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    task_created: Literal[False] = Field(default=False, alias="taskCreated")
    plan_mutated: Literal[False] = Field(default=False, alias="planMutated")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    activation_eligible: Literal[False] = Field(default=False, alias="activationEligible")

    @field_validator(
        "response_id_bytes",
        "content_bytes",
        "refusal_bytes",
        "finish_reason_bytes",
        "tool_call_count",
        "chunks",
        "worker_exit_code",
        mode="before",
    )
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("bound Provider counts must use JSON integers")
        return value

    @field_validator(
        "streamed",
        "decision_allowed",
        "tool_result_success",
        "result_identity_valid",
        "executed",
        "network_log_trusted",
        "raw_request_embedded",
        "raw_result_embedded",
        "secret_reference_embedded",
        "raw_worker_transcript_embedded",
        "automatic_redispatch_authorized",
        "task_created",
        "plan_mutated",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "activation_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("bound Provider flags must use JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_outcome(self) -> Self:
        expected_evidence = (f"evidence/{self.request_id}.json",)
        evidence_path = PurePosixPath(expected_evidence[0])
        try:
            portable_evidence = validate_run_artifact_path(expected_evidence[0])
        except ValueError as exc:
            raise ValueError("Provider bound outcome evidence reference differs") from exc
        if (
            self.evidence_references != expected_evidence
            or portable_evidence != expected_evidence[0]
            or evidence_path.parent != PurePosixPath("evidence")
            or len(evidence_path.parts) != 2
        ):
            raise ValueError("Provider bound outcome evidence reference differs")
        optional_texts = (
            (self.content_digest, self.content_bytes),
            (self.refusal_digest, self.refusal_bytes),
            (self.finish_reason_digest, self.finish_reason_bytes),
        )
        if any(digest is None and byte_count != 0 for digest, byte_count in optional_texts):
            raise ValueError("Provider bound outcome optional text binding differs")
        if self.evidence_reference_digests != tuple(
            _text_digest("evidence-reference", item) for item in self.evidence_references
        ):
            raise ValueError("Provider bound outcome evidence digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"outcome_id", "outcome_digest"},
        )
        digest = _provider_digest("pajin.provider.bound-chat-outcome/v1", material)
        outcome_id = f"provider-bound-chat-outcome:{digest}"
        if self.outcome_digest and self.outcome_digest != digest:
            raise ValueError("Provider bound outcome digest differs")
        if self.outcome_id and self.outcome_id != outcome_id:
            raise ValueError("Provider bound outcome ID differs")
        object.__setattr__(self, "outcome_digest", digest)
        object.__setattr__(self, "outcome_id", outcome_id)
        _canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Provider bound outcome",
            max_bytes=_MAX_BOUND_OUTCOME_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class BoundProviderChatCall:
    """Ephemeral raw result paired with its serializable secret-free outcome."""

    result: ProviderChatResult
    outcome: ProviderBoundChatOutcome


def bind_provider_chat_outcome(
    *,
    registration: ProviderRegistration,
    grant: CapabilityGrant,
    chat: ProviderChatRequest,
    request: ToolRequest,
    result: ProviderChatResult,
    gateway_outcome: GatewayOutcome,
    charged_usage: ProviderChargedUsage,
) -> ProviderBoundChatOutcome:
    """Validate every raw source and return its digest-only successful projection."""

    try:
        canonical_registration = ProviderRegistration.model_validate(
            registration.model_dump(mode="python")
        )
        canonical_grant = CapabilityGrant.model_validate(grant.model_dump(mode="python"))
        canonical_chat = ProviderChatRequest.model_validate(chat.model_dump(mode="python"))
        canonical_request = ToolRequest.model_validate(request.model_dump(mode="python"))
        canonical_result = ProviderChatResult.model_validate(result.model_dump(mode="python"))
        canonical_gateway = GatewayOutcome.model_validate(
            gateway_outcome.model_dump(mode="python")
        )
        canonical_charged = ProviderChargedUsage.model_validate(
            charged_usage.model_dump(mode="python", by_alias=True)
        )
        _require_charged_usage(
            canonical_registration,
            canonical_chat,
            canonical_charged,
        )
        _require_source_binding(
            canonical_registration,
            canonical_grant,
            canonical_chat,
            canonical_request,
            canonical_result,
            canonical_gateway,
        )
        usage = canonical_result.usage
        if (
            usage is None
            or usage.prompt_tokens is None
            or usage.completion_tokens is None
            or usage.total_tokens is None
        ):
            raise ProviderBoundOutcomeError(
                "Provider result usage disappeared after source validation"
            )
        reported_cost = (
            usage.prompt_tokens * canonical_registration.input_cost_per_million_usd
            + usage.completion_tokens * canonical_registration.output_cost_per_million_usd
        ) / 1_000_000
        provider_runtime = canonical_registration.model_dump(mode="json", by_alias=True)
        provider_runtime["allowed_function_tools"] = sorted(
            canonical_registration.allowed_function_tools
        )
        grant_material = canonical_grant.model_dump(mode="json", by_alias=True)
        grant_material["tools"] = sorted(canonical_grant.tools)
        grant_material["targets"] = sorted(canonical_grant.targets)
        worker_result = canonical_gateway.worker_result
        if worker_result is None:
            raise ProviderBoundOutcomeError(
                "Provider Worker result disappeared after source validation"
            )
        outcome = ProviderBoundChatOutcome(
            requestId=canonical_request.request_id,
            agentId=canonical_request.agent_id,
            toolId=canonical_request.tool_id,
            providerId=canonical_registration.provider_id,
            model=canonical_registration.model,
            providerRuntimeDigest=_provider_digest(
                "pajin.provider.runtime-registration/v1",
                provider_runtime,
            ),
            capabilityGrantDigest=_provider_digest(
                "pajin.provider.capability-grant/v1",
                grant_material,
            ),
            chatRequestDigest=_provider_digest(
                "pajin.provider.chat-request/v1",
                canonical_chat.model_dump(mode="json", by_alias=True, exclude_none=False),
            ),
            toolRequestDigest=canonical_tool_request_digest(canonical_request),
            policyDecisionDigest=_provider_digest(
                "pajin.provider.policy-decision/v1",
                canonical_gateway.decision.model_dump(mode="json"),
            ),
            toolResultDigest=_provider_digest(
                "pajin.provider.tool-result/v1",
                canonical_gateway.result.model_dump(mode="json", by_alias=True),
            ),
            workerResultDigest=_provider_digest(
                "pajin.provider.worker-result/v1",
                worker_result.model_dump(mode="json", by_alias=True),
            ),
            gatewayOutcomeDigest=_provider_digest(
                "pajin.provider.gateway-outcome/v1",
                canonical_gateway.model_dump(mode="json", by_alias=True),
            ),
            providerResultDigest=_provider_digest(
                "pajin.provider.chat-result/v1",
                canonical_result.model_dump(mode="json", by_alias=True),
            ),
            responseIdDigest=_text_digest("response-id", canonical_result.response_id),
            responseIdBytes=_text_bytes(canonical_result.response_id),
            targetDigest=_text_digest("target", canonical_result.target),
            contentDigest=_optional_text_digest("content", canonical_result.content),
            contentBytes=_optional_text_bytes(canonical_result.content),
            refusalDigest=_optional_text_digest("refusal", canonical_result.refusal),
            refusalBytes=_optional_text_bytes(canonical_result.refusal),
            finishReasonDigest=_optional_text_digest(
                "finish-reason",
                canonical_result.finish_reason,
            ),
            finishReasonBytes=_optional_text_bytes(canonical_result.finish_reason),
            toolCallsDigest=_provider_digest(
                "pajin.provider.normalized-tool-calls/v1",
                [
                    item.model_dump(mode="json", by_alias=True)
                    for item in canonical_result.tool_calls
                ],
            ),
            evidenceReferenceDigests=tuple(
                _text_digest("evidence-reference", item)
                for item in canonical_gateway.result.evidence
            ),
            evidenceReferences=tuple(canonical_gateway.result.evidence),
            toolCallCount=len(canonical_result.tool_calls),
            reportedUsage=ProviderReportedUsage(
                promptTokens=usage.prompt_tokens,
                completionTokens=usage.completion_tokens,
                totalTokens=usage.total_tokens,
                costUsd=reported_cost,
            ),
            chargedUsage=canonical_charged,
            streamed=canonical_result.streamed,
            chunks=canonical_result.chunks,
            workerStatus=cast(Literal[WorkerStatus.SUCCEEDED], worker_result.status),
            workerExecutionIdDigest=_text_digest(
                "worker-execution-id",
                worker_result.execution_id,
            ),
            workerBackendDigest=_text_digest("worker-backend", worker_result.backend),
            workerExitCode=cast(Literal[0], worker_result.exit_code),
            networkLogTrusted=canonical_gateway.network_log_trusted,
        )
        return ProviderBoundChatOutcome.model_validate(
            outcome.model_dump(mode="json", by_alias=True)
        )
    except ProviderBoundOutcomeError:
        raise
    except (
        AttributeError,
        OverflowError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise ProviderBoundOutcomeError(
            "Provider bound outcome construction failed closed"
        ) from exc


def verify_provider_bound_chat_outcome(
    outcome: ProviderBoundChatOutcome,
    *,
    registration: ProviderRegistration,
    grant: CapabilityGrant,
    chat: ProviderChatRequest,
    request: ToolRequest,
    result: ProviderChatResult,
    gateway_outcome: GatewayOutcome,
    charged_usage: ProviderChargedUsage,
    expected_budget_scope: Literal["campaign", "campaign-and-dedicated"],
) -> ProviderBoundChatOutcome:
    """Rebuild the complete projection from raw sources and require exact equality."""

    try:
        canonical = ProviderBoundChatOutcome.model_validate(
            outcome.model_dump(mode="json", by_alias=True)
        )
        if (
            type(expected_budget_scope) is not str
            or expected_budget_scope not in {"campaign", "campaign-and-dedicated"}
            or canonical.charged_usage.budget_scope != expected_budget_scope
            or charged_usage.budget_scope != expected_budget_scope
        ):
            raise ProviderBoundOutcomeError(
                "Provider bound outcome differs from the expected budget scope"
            )
        expected = bind_provider_chat_outcome(
            registration=registration,
            grant=grant,
            chat=chat,
            request=request,
            result=result,
            gateway_outcome=gateway_outcome,
            charged_usage=charged_usage,
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ProviderBoundOutcomeError(
            "Provider bound outcome verification failed closed"
        ) from exc
    if canonical != expected:
        raise ProviderBoundOutcomeError("Provider bound outcome differs from raw sources")
    return canonical


def _require_source_binding(
    registration: ProviderRegistration,
    grant: CapabilityGrant,
    chat: ProviderChatRequest,
    request: ToolRequest,
    result: ProviderChatResult,
    gateway: GatewayOutcome,
) -> None:
    expected_tool_id = f"provider.{registration.provider_id}.chat"
    expected_request = ToolRequest(
        request_id=request.request_id,
        agent_id=grant.subject,
        tool_id=expected_tool_id,
        target=str(registration.endpoint),
        method="POST",
        arguments=chat.model_dump(mode="json", by_alias=True),
    )
    if (
        canonical_tool_request_digest(request)
        != canonical_tool_request_digest(expected_request)
        or expected_tool_id not in grant.tools
        or request.target not in grant.targets
    ):
        raise ProviderBoundOutcomeError("Provider request differs from its grant or chat")
    if (
        not gateway.decision.allowed
        or not gateway.executed
        or not gateway.result_identity_valid
        or not gateway.result.success
        or gateway.result.request_id != request.request_id
        or gateway.result.tool_id != request.tool_id
        or tuple(gateway.result.evidence) != (f"evidence/{request.request_id}.json",)
        or gateway.worker_result is None
        or gateway.worker_result.status is not WorkerStatus.SUCCEEDED
    ):
        raise ProviderBoundOutcomeError("Provider Gateway outcome is not a bound success")
    if ProviderChatResult.model_validate(gateway.result.data) != result:
        raise ProviderBoundOutcomeError("Provider result differs from the Gateway Tool result")
    if (
        result.provider_id != registration.provider_id
        or result.model != registration.model
        or result.target != request.target
        or result.streamed != chat.stream
        or any(
            item.name not in {tool.function.name for tool in chat.tools}
            for item in result.tool_calls
        )
    ):
        raise ProviderBoundOutcomeError("Provider result differs from registration or chat")
    usage = result.usage
    if (
        usage is None
        or usage.prompt_tokens is None
        or usage.completion_tokens is None
        or usage.total_tokens is None
        or usage.total_tokens != usage.prompt_tokens + usage.completion_tokens
    ):
        raise ProviderBoundOutcomeError("Provider result usage is incomplete or inconsistent")


def _require_charged_usage(
    registration: ProviderRegistration,
    chat: ProviderChatRequest,
    charged: ProviderChargedUsage,
) -> None:
    try:
        expected = provider_model_usage_upper_bound(registration, chat)
    except BudgetExceeded as exc:
        raise ProviderBoundOutcomeError(
            "Provider charged usage has no conservative request bound"
        ) from exc
    if (
        charged.prompt_tokens != expected.prompt_tokens
        or charged.completion_tokens != expected.completion_tokens
        or charged.total_tokens != expected.prompt_tokens + expected.completion_tokens
        or charged.cost_usd != expected.cost_usd
    ):
        raise ProviderBoundOutcomeError(
            "Provider charged usage differs from the conservative request bound"
        )


def _provider_digest(domain: str, value: object) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    payload = _canonical_json_bytes(
        value,
        label="Provider bound outcome source",
        max_bytes=_MAX_BOUND_OUTCOME_SOURCE_BYTES,
    )
    return sha256(domain_bytes + b"\x00" + payload).hexdigest()


def _text_digest(label: str, value: str) -> str:
    return _provider_digest(
        f"pajin.provider.{label}/v1",
        {"text": value},
    )


def _optional_text_digest(label: str, value: str | None) -> str | None:
    return _text_digest(label, value) if value is not None else None


def _text_bytes(value: str) -> int:
    return len(value.encode("utf-8", errors="strict"))


def _optional_text_bytes(value: str | None) -> int:
    return _text_bytes(value) if value is not None else 0


def _canonical_json_bytes(value: object, *, label: str, max_bytes: int) -> bytes:
    validate_strict_json(value, label=label)
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (OverflowError, TypeError, UnicodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds its canonical byte limit")
    return encoded
