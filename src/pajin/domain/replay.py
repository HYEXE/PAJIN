"""Typed, non-executable contracts for independent restricted reproduction."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal

from pydantic import Field, JsonValue, field_validator, model_validator

from pajin.domain.models import CampaignMode, StrictModel, ToolRiskTier
from pajin.domain.validation import CandidateFinding

REPLAY_API_VERSION: Literal["pajin.dev/replay/v1alpha1"] = "pajin.dev/replay/v1alpha1"

_Identifier = Annotated[str, Field(min_length=1, max_length=200)]
_BoundedText = Annotated[str, Field(min_length=1, max_length=5_000)]
_EvidenceReference = Annotated[str, Field(min_length=1, max_length=2_000)]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Version = Annotated[str, Field(min_length=1, max_length=100)]


class ReplayArtifactModel(StrictModel):
    """Base wire contract for versioned replay artifacts."""

    api_version: Literal["pajin.dev/replay/v1alpha1"] = Field(
        default=REPLAY_API_VERSION,
        alias="apiVersion",
    )


class ReplaySessionPolicy(StrEnum):
    STATELESS = "stateless"
    FRESH_SESSION = "fresh-session"
    PRESERVE_SCENARIO_SESSION = "preserve-scenario-session"


class ReplayAttemptStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed-out"
    TARGET_UNAVAILABLE = "target-unavailable"


class ReplayExecutionStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed-out"
    TARGET_UNAVAILABLE = "target-unavailable"
    UNSUPPORTED = "unsupported"


class ReplayOracleVerdict(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    INCONCLUSIVE = "inconclusive"


class ValidationEvidenceExcerpt(StrictModel):
    """A bounded, redacted excerpt that remains explicitly untrusted."""

    reference: _EvidenceReference
    sha256: _Sha256
    excerpt: str = Field(min_length=1, max_length=4_096)
    media_type: str = Field(default="text/plain", min_length=1, max_length=100)
    redacted: Literal[True] = True
    untrusted: Literal[True] = True


class ValidationPacket(ReplayArtifactModel):
    """Minimal semantic-review input without Tool or replay authority."""

    kind: Literal["ValidationPacket"] = "ValidationPacket"
    packet_id: _Identifier
    candidate_run_id: _Identifier
    candidate: CandidateFinding
    mode: CampaignMode
    scenario_id: _Identifier
    target_id: _Identifier
    target: str = Field(min_length=1, max_length=2_000)
    threat_class: _Identifier
    original_request_ids: list[_Identifier] = Field(min_length=1, max_length=100)
    evidence: list[ValidationEvidenceExcerpt] = Field(min_length=1, max_length=20)
    semantic_support_required: bool
    replay_contract_id: _Identifier | None = None
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def bind_candidate_provenance(self) -> ValidationPacket:
        if self.original_request_ids != self.candidate.source_request_ids:
            raise ValueError("validation packet original request IDs must match the candidate")
        if self.threat_class != self.candidate.claim.threat_class:
            raise ValueError("validation packet threat class must match the candidate")
        if self.target != self.candidate.claim.target:
            raise ValueError("validation packet target must match the candidate")
        references = [item.reference for item in self.evidence]
        if len(references) != len(set(references)):
            raise ValueError("validation packet evidence references must be unique")
        candidate_evidence = set(self.candidate.claim.evidence)
        if any(reference not in candidate_evidence for reference in references):
            raise ValueError("validation packet may include only candidate evidence")
        return self


class ModeReplayContract(ReplayArtifactModel):
    """Trusted Mode opt-in metadata used to compile one bounded replay."""

    kind: Literal["ModeReplayContract"] = "ModeReplayContract"
    contract_id: _Identifier
    mode: CampaignMode
    scenario_id: _Identifier
    tool_id: _Identifier
    tool_version: _Version
    method: str = Field(min_length=1, max_length=20)
    risk_tier: ToolRiskTier
    automatic: bool = False
    replay_safe: bool = False
    idempotent: bool = False
    session_policy: ReplaySessionPolicy
    repetitions: int = Field(ge=1, le=20)
    required_successes: int = Field(ge=1, le=20)
    oracle_id: _Identifier
    oracle_version: _Version
    observation_schema: _Identifier
    semantic_support_required: bool
    allowed_argument_fields: set[_Identifier] = Field(min_length=1, max_length=100)

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @field_validator("risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @model_validator(mode="after")
    def validate_automatic_replay_boundary(self) -> ModeReplayContract:
        if self.required_successes > self.repetitions:
            raise ValueError("required successes cannot exceed repetitions")
        if not self.automatic:
            return self
        if not self.replay_safe:
            raise ValueError("automatic replay must be replay-safe")
        if not self.idempotent:
            raise ValueError("automatic replay must be idempotent")
        if self.risk_tier > ToolRiskTier.T2:
            raise ValueError("automatic replay is restricted to T0-T2")
        return self


class ReplayIntent(ReplayArtifactModel):
    """A model-safe replay request containing references, never execution fields."""

    kind: Literal["ReplayIntent"] = "ReplayIntent"
    intent_id: _Identifier
    replay_contract_id: _Identifier
    candidate_id: _Identifier
    candidate_run_id: _Identifier
    original_request_id: _Identifier
    mode: CampaignMode
    scenario_id: _Identifier
    threat_class: _Identifier
    comparison_goals: list[_BoundedText] = Field(min_length=1, max_length=10)
    rationale: _BoundedText
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="created_at")


class ReplayBinding(StrictModel):
    """Identity tuple that every compiled, executed, and evaluated record repeats."""

    candidate_id: _Identifier
    candidate_run_id: _Identifier
    replay_run_id: _Identifier
    original_request_id: _Identifier
    mode: CampaignMode
    scenario_id: _Identifier
    threat_class: _Identifier
    tool_id: _Identifier
    tool_version: _Version
    target_id: _Identifier
    target: str = Field(min_length=1, max_length=2_000)


class CompiledReplaySpec(ReplayArtifactModel):
    """Trusted executable specification produced after deterministic compilation."""

    kind: Literal["CompiledReplaySpec"] = "CompiledReplaySpec"
    spec_id: _Identifier
    intent_id: _Identifier | None = None
    contract_id: _Identifier
    binding: ReplayBinding
    method: str = Field(min_length=1, max_length=20)
    arguments: dict[str, JsonValue] = Field(max_length=100)
    argument_digest: _Sha256
    secret_lease_ids: list[_Identifier] = Field(default_factory=list, max_length=20)
    risk_tier: ToolRiskTier
    replay_safe: Literal[True]
    idempotent: Literal[True]
    session_policy: ReplaySessionPolicy
    repetitions: int = Field(ge=1, le=20)
    required_successes: int = Field(ge=1, le=20)
    oracle_id: _Identifier
    oracle_version: _Version
    observation_schema: _Identifier
    semantic_support_required: bool
    grant_id: _Identifier
    max_calls: int = Field(ge=1, le=20)
    compiled_at: datetime
    expires_at: datetime

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @field_validator("risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @field_validator("compiled_at", "expires_at")
    @classmethod
    def normalize_timestamps(cls, value: datetime, info: object) -> datetime:
        field_name = getattr(info, "field_name", "timestamp")
        return _normalize_utc(value, field_name=field_name)

    @model_validator(mode="after")
    def validate_compiled_authority(self) -> CompiledReplaySpec:
        if self.argument_digest != replay_argument_digest(self.arguments):
            raise ValueError("compiled replay argument digest does not match arguments")
        if len(self.secret_lease_ids) != len(set(self.secret_lease_ids)):
            raise ValueError("secret_lease_ids must be unique")
        if self.required_successes > self.repetitions:
            raise ValueError("required successes cannot exceed repetitions")
        if self.max_calls != self.repetitions:
            raise ValueError("compiled replay call budget must exactly match repetitions")
        if self.risk_tier > ToolRiskTier.T2:
            raise ValueError("compiled automatic replay is restricted to T0-T2")
        if self.expires_at <= self.compiled_at:
            raise ValueError("compiled replay authority must expire after compilation")
        return self


class ReplayAttempt(ReplayArtifactModel):
    """One fresh Tool execution and its Candidate-bound evidence lineage."""

    kind: Literal["ReplayAttempt"] = "ReplayAttempt"
    attempt_id: _Identifier
    spec_id: _Identifier
    binding: ReplayBinding
    attempt_number: int = Field(ge=1, le=20)
    replay_request_id: _Identifier
    status: ReplayAttemptStatus
    observation_schema: _Identifier
    observation: dict[str, JsonValue] = Field(default_factory=dict, max_length=100)
    evidence: list[_EvidenceReference] = Field(default_factory=list, max_length=100)
    error: str | None = Field(default=None, max_length=2_000)
    started_at: datetime
    finished_at: datetime

    @field_validator("started_at", "finished_at")
    @classmethod
    def normalize_timestamps(cls, value: datetime, info: object) -> datetime:
        field_name = getattr(info, "field_name", "timestamp")
        return _normalize_utc(value, field_name=field_name)

    @model_validator(mode="after")
    def validate_attempt(self) -> ReplayAttempt:
        if self.replay_request_id == self.binding.original_request_id:
            raise ValueError("replay request ID must differ from the original request")
        if self.finished_at < self.started_at:
            raise ValueError("replay attempt cannot finish before it starts")
        if len(self.evidence) != len(set(self.evidence)):
            raise ValueError("replay attempt evidence references must be unique")
        if self.status is ReplayAttemptStatus.SUCCEEDED:
            if not self.observation or not self.evidence:
                raise ValueError("successful replay attempt requires observation and evidence")
            if self.error is not None:
                raise ValueError("successful replay attempt cannot contain an error")
        elif self.error is None:
            raise ValueError("unsuccessful replay attempt requires an error summary")
        return self


class ReplayOracleResult(ReplayArtifactModel):
    """Typed Mode-owned evaluation over one or more replay observations."""

    kind: Literal["ReplayOracleResult"] = "ReplayOracleResult"
    oracle_result_id: _Identifier
    spec_id: _Identifier
    binding: ReplayBinding
    oracle_id: _Identifier
    oracle_version: _Version
    observation_schema: _Identifier
    verdict: ReplayOracleVerdict
    attempt_ids: list[_Identifier] = Field(min_length=1, max_length=20)
    supporting_evidence: list[_EvidenceReference] = Field(default_factory=list, max_length=100)
    support_count: int = Field(ge=0, le=20)
    required_support_count: int = Field(ge=1, le=20)
    summary: _BoundedText
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def normalize_evaluated_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="evaluated_at")

    @model_validator(mode="after")
    def validate_oracle_result(self) -> ReplayOracleResult:
        if len(self.attempt_ids) != len(set(self.attempt_ids)):
            raise ValueError("oracle attempt IDs must be unique")
        if len(self.supporting_evidence) != len(set(self.supporting_evidence)):
            raise ValueError("oracle supporting evidence must be unique")
        if self.support_count > len(self.attempt_ids):
            raise ValueError("oracle support count cannot exceed evaluated attempts")
        if self.required_support_count > len(self.attempt_ids):
            raise ValueError("oracle required support count cannot exceed evaluated attempts")
        if (
            self.verdict is ReplayOracleVerdict.SUPPORTS
            and self.support_count < self.required_support_count
        ):
            raise ValueError("supporting Oracle verdict must meet its required support count")
        return self


class ReplayOutcome(ReplayArtifactModel):
    """Aggregate reproduction result referenced by a validation Decision."""

    kind: Literal["ReplayOutcome"] = "ReplayOutcome"
    outcome_id: _Identifier
    spec_id: _Identifier
    binding: ReplayBinding
    execution_status: ReplayExecutionStatus
    attempts: list[ReplayAttempt] = Field(default_factory=list, max_length=20)
    attempt_ids: list[_Identifier] = Field(default_factory=list, max_length=20)
    replay_request_ids: list[_Identifier] = Field(default_factory=list, max_length=20)
    evidence: list[_EvidenceReference] = Field(default_factory=list, max_length=100)
    oracle_result: ReplayOracleResult | None = None
    completed_at: datetime

    @field_validator("completed_at")
    @classmethod
    def normalize_completed_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="completed_at")

    @model_validator(mode="after")
    def validate_outcome_lineage(self) -> ReplayOutcome:
        expected_attempt_ids = [attempt.attempt_id for attempt in self.attempts]
        expected_request_ids = [attempt.replay_request_id for attempt in self.attempts]
        expected_evidence = list(
            dict.fromkeys(reference for attempt in self.attempts for reference in attempt.evidence)
        )
        if len(expected_attempt_ids) != len(set(expected_attempt_ids)):
            raise ValueError("replay attempt IDs must be unique")
        if len(expected_request_ids) != len(set(expected_request_ids)):
            raise ValueError("replay request IDs must be unique")
        if self.attempt_ids != expected_attempt_ids:
            raise ValueError("outcome attempt IDs must exactly match its attempts")
        if self.replay_request_ids != expected_request_ids:
            raise ValueError("outcome replay request IDs must exactly match its attempts")
        if self.evidence != expected_evidence:
            raise ValueError("outcome evidence must exactly match replay attempt evidence")
        for attempt in self.attempts:
            if attempt.spec_id != self.spec_id:
                raise ValueError("replay attempt spec ID must match the outcome")
            if attempt.binding != self.binding:
                raise ValueError("replay attempt binding must match the outcome")

        if self.execution_status is ReplayExecutionStatus.UNSUPPORTED:
            if self.attempts:
                raise ValueError("unsupported replay outcome cannot contain attempts")
        elif not self.attempts:
            raise ValueError("executed replay outcome requires at least one attempt")

        oracle = self.oracle_result
        if self.execution_status is ReplayExecutionStatus.SUCCEEDED:
            if not any(
                attempt.status is ReplayAttemptStatus.SUCCEEDED for attempt in self.attempts
            ):
                raise ValueError("successful replay outcome requires a successful attempt")
            if oracle is None:
                raise ValueError("successful replay outcome requires a Mode Oracle result")
        elif oracle is not None and oracle.verdict is ReplayOracleVerdict.SUPPORTS:
            raise ValueError("unsuccessful replay outcome cannot claim Oracle support")

        if oracle is not None:
            if oracle.spec_id != self.spec_id:
                raise ValueError("replay Oracle spec ID must match the outcome")
            if oracle.binding != self.binding:
                raise ValueError("replay Oracle binding must match the outcome")
            if oracle.attempt_ids != self.attempt_ids:
                raise ValueError("replay Oracle attempts must exactly match the outcome")
            if any(reference not in self.evidence for reference in oracle.supporting_evidence):
                raise ValueError("replay Oracle references evidence outside the outcome")
            if oracle.evaluated_at > self.completed_at:
                raise ValueError("replay outcome cannot complete before Oracle evaluation")
        if any(attempt.finished_at > self.completed_at for attempt in self.attempts):
            raise ValueError("replay outcome cannot complete before its attempts")
        return self

    @property
    def supports_claim(self) -> bool:
        return (
            self.execution_status is ReplayExecutionStatus.SUCCEEDED
            and self.oracle_result is not None
            and self.oracle_result.verdict is ReplayOracleVerdict.SUPPORTS
        )


class ReplayArtifactSet(ReplayArtifactModel):
    """Cross-artifact integrity boundary for one compiled replay and outcome."""

    kind: Literal["ReplayArtifactSet"] = "ReplayArtifactSet"
    validation_packet: ValidationPacket
    contract: ModeReplayContract
    intent: ReplayIntent | None = None
    spec: CompiledReplaySpec
    outcome: ReplayOutcome

    @model_validator(mode="after")
    def validate_cross_artifact_bindings(self) -> ReplayArtifactSet:
        packet = self.validation_packet
        contract = self.contract
        spec = self.spec
        binding = spec.binding
        if packet.replay_contract_id != contract.contract_id:
            raise ValueError("validation packet must reference the Mode replay contract")
        if (
            binding.candidate_id != packet.candidate.candidate_id
            or binding.candidate_run_id != packet.candidate_run_id
            or binding.mode != packet.mode
            or binding.scenario_id != packet.scenario_id
            or binding.target_id != packet.target_id
            or binding.target != packet.target
            or binding.threat_class != packet.threat_class
            or binding.original_request_id not in packet.original_request_ids
        ):
            raise ValueError("compiled replay binding must match the validation packet")
        if packet.semantic_support_required != contract.semantic_support_required:
            raise ValueError("validation packet semantic policy must match the Mode contract")
        if spec.contract_id != contract.contract_id:
            raise ValueError("compiled replay contract ID must match the Mode contract")
        if (
            binding.mode != contract.mode
            or binding.scenario_id != contract.scenario_id
            or binding.tool_id != contract.tool_id
            or binding.tool_version != contract.tool_version
        ):
            raise ValueError("compiled replay binding must match the Mode contract")
        if (
            spec.method != contract.method
            or spec.risk_tier != contract.risk_tier
            or spec.session_policy != contract.session_policy
            or spec.repetitions != contract.repetitions
            or spec.required_successes != contract.required_successes
            or spec.oracle_id != contract.oracle_id
            or spec.oracle_version != contract.oracle_version
            or spec.observation_schema != contract.observation_schema
            or spec.semantic_support_required != contract.semantic_support_required
            or not contract.automatic
            or not contract.replay_safe
            or not contract.idempotent
        ):
            raise ValueError("compiled replay policy must match an automatic Mode contract")
        if not set(spec.arguments) <= contract.allowed_argument_fields:
            raise ValueError("compiled replay arguments exceed the Mode contract allowlist")

        if self.intent is not None:
            intent = self.intent
            if spec.intent_id != intent.intent_id:
                raise ValueError("compiled replay intent ID must match the ReplayIntent")
            if (
                intent.replay_contract_id != contract.contract_id
                or intent.candidate_id != binding.candidate_id
                or intent.candidate_run_id != binding.candidate_run_id
                or intent.original_request_id != binding.original_request_id
                or intent.mode != binding.mode
                or intent.scenario_id != binding.scenario_id
                or intent.threat_class != binding.threat_class
            ):
                raise ValueError("ReplayIntent references must match the compiled replay binding")
        elif spec.intent_id is not None:
            raise ValueError("compiled replay references a missing ReplayIntent")

        outcome = self.outcome
        if outcome.spec_id != spec.spec_id:
            raise ValueError("outcome spec ID must match the compiled replay spec")
        if outcome.binding != binding:
            raise ValueError("outcome binding must match the compiled replay spec")
        if len(outcome.attempts) > spec.repetitions:
            raise ValueError("replay outcome exceeds the compiled repetition budget")
        attempt_numbers = [attempt.attempt_number for attempt in outcome.attempts]
        if len(attempt_numbers) != len(set(attempt_numbers)):
            raise ValueError("replay attempt numbers must be unique")
        if any(number > spec.repetitions for number in attempt_numbers):
            raise ValueError("replay attempt number exceeds the compiled repetition budget")
        if any(
            attempt.observation_schema != spec.observation_schema
            for attempt in outcome.attempts
        ):
            raise ValueError("replay observation schema must match the compiled replay spec")
        oracle = outcome.oracle_result
        if oracle is not None and (
            oracle.oracle_id != spec.oracle_id
            or oracle.oracle_version != spec.oracle_version
            or oracle.observation_schema != spec.observation_schema
            or oracle.required_support_count != spec.required_successes
        ):
            raise ValueError("replay Oracle contract must match the compiled replay spec")
        return self


def replay_argument_digest(arguments: Mapping[str, object]) -> str:
    """Return the canonical digest used to bind allowlisted replay arguments."""

    canonical = json.dumps(
        arguments,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def _normalize_utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset or Z")
    return value.astimezone(UTC)
