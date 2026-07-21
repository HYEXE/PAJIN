"""Typed, non-executable contracts for independent restricted reproduction."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal

from pydantic import Field, JsonValue, ValidationInfo, field_validator, model_validator

from pajin.domain.models import (
    CampaignMode,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolRiskTier,
)
from pajin.domain.validation import CandidateFinding

REPLAY_API_VERSION: Literal["pajin.dev/replay/v1alpha1"] = "pajin.dev/replay/v1alpha1"
_ALLOW_LEGACY_CONFIRMATION_CONTRADICTION = "allow_legacy_confirmation_contradiction"

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


class ReplayPurpose(StrEnum):
    """The validation objective for one independently executed replay."""

    CONFIRMATION = "confirmation"
    REMEDIATION_RETEST = "remediation-retest"


class ReplayRetestContext(StrictModel):
    """Immutable baseline and parent-Run lineage for a remediation retest."""

    baseline_decision_id: _Identifier = Field(alias="baselineDecisionId")
    baseline_finding_id: _Identifier = Field(alias="baselineFindingId")
    remediation_id: _Identifier = Field(alias="remediationId")
    retest_run_id: _Identifier = Field(alias="retestRunId")
    retest_source_root_digest: _Sha256 = Field(alias="retestSourceRootDigest")


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
    purpose: ReplayPurpose = ReplayPurpose.CONFIRMATION
    retest_context: ReplayRetestContext | None = None
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
        _validate_packet_candidate(self)
        _validate_packet_evidence(self)
        _validate_packet_retest_context(self)
        return self


class ModeReplayContract(ReplayArtifactModel):
    """Trusted Mode opt-in metadata used to compile one bounded replay."""

    kind: Literal["ModeReplayContract"] = "ModeReplayContract"
    contract_id: _Identifier
    purpose: ReplayPurpose = ReplayPurpose.CONFIRMATION
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
    materializer_id: _Identifier | None = None
    materializer_version: _Version | None = None
    ephemeral_argument_fields: set[_Identifier] = Field(default_factory=set, max_length=10)
    repetitions: int = Field(ge=1, le=20)
    required_successes: int = Field(ge=1, le=20)
    required_contradictions: int = Field(default=0, ge=0, le=20)
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
        _validate_replay_thresholds(self)
        _validate_contract_session_policy(self)
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
    purpose: ReplayPurpose = ReplayPurpose.CONFIRMATION
    retest_context: ReplayRetestContext | None = None
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

    @model_validator(mode="after")
    def validate_retest_context(self) -> ReplayIntent:
        if self.purpose is ReplayPurpose.CONFIRMATION:
            if self.retest_context is not None:
                raise ValueError("confirmation ReplayIntent cannot contain retest context")
        else:
            context = self.retest_context
            if context is None:
                raise ValueError("remediation retest ReplayIntent requires retest context")
            if context.retest_run_id == self.candidate_run_id:
                raise ValueError("parent Retest Run must differ from the Candidate Run")
        return self


class ReplayBinding(StrictModel):
    """Identity tuple that every compiled, executed, and evaluated record repeats."""

    candidate_id: _Identifier
    campaign: _Identifier
    candidate_run_id: _Identifier
    replay_run_id: _Identifier
    purpose: ReplayPurpose = ReplayPurpose.CONFIRMATION
    context_run_id: _Identifier | None = None
    original_request_id: _Identifier
    mode: CampaignMode
    scenario_id: _Identifier
    threat_class: _Identifier
    tool_id: _Identifier
    tool_version: _Version
    target_id: _Identifier
    target: str = Field(min_length=1, max_length=2_000)

    @model_validator(mode="after")
    def validate_run_identities(self) -> ReplayBinding:
        if self.candidate_run_id == self.replay_run_id:
            raise ValueError("replay Run must differ from the Candidate Run")
        if self.purpose is ReplayPurpose.CONFIRMATION:
            if self.context_run_id is not None:
                raise ValueError("confirmation replay binding cannot contain a context Run")
        else:
            if self.context_run_id is None:
                raise ValueError("remediation retest replay binding requires a context Run")
            if self.context_run_id in {self.candidate_run_id, self.replay_run_id}:
                raise ValueError("parent Retest Run must differ from Candidate and replay Runs")
        return self


class ReplayCapabilityGrant(CapabilityGrant):
    """Dedicated, non-delegable authority issued only for one compiled replay."""

    api_version: Literal["pajin.dev/replay/v1alpha1"] = Field(
        default=REPLAY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ReplayCapabilityGrant"] = "ReplayCapabilityGrant"
    purpose: Literal["restricted-replay"] = "restricted-replay"
    contract_id: _Identifier
    candidate_id: _Identifier
    candidate_run_id: _Identifier
    replay_run_id: _Identifier
    original_request_id: _Identifier
    original_grant_id: _Identifier
    source_capability_digest: _Sha256
    original_subject: _Identifier
    tool_id: _Identifier
    target: str = Field(min_length=1, max_length=2_000)
    repetitions: int = Field(ge=1, le=20)
    ttl_seconds: Literal[300] = 300
    parent_grant_id: None = None
    delegable: Literal[False] = False
    depth: Literal[0] = 0

    @field_validator("issued_at", "expires_at")
    @classmethod
    def normalize_timestamps(cls, value: datetime, info: object) -> datetime:
        field_name = getattr(info, "field_name", "timestamp")
        return _normalize_utc(value, field_name=field_name)

    @model_validator(mode="after")
    def validate_replay_authority(self) -> ReplayCapabilityGrant:
        if self.subject != f"reproducer:{self.grant_id}":
            raise ValueError("replay capability subject must be derived from its grant ID")
        if self.subject == self.original_subject:
            raise ValueError("replay capability subject must differ from the Specialist")
        if self.grant_id == self.original_grant_id:
            raise ValueError("replay capability cannot reuse the Specialist grant ID")
        if self.candidate_run_id == self.replay_run_id:
            raise ValueError("replay capability requires a distinct replay Run")
        if self.tools != {self.tool_id}:
            raise ValueError("replay capability must contain exactly its compiled Tool")
        if self.targets != {self.target}:
            raise ValueError("replay capability must contain exactly its compiled target")
        if self.max_calls != self.repetitions:
            raise ValueError("replay capability call budget must match repetitions")
        if self.max_risk_tier > ToolRiskTier.T2:
            raise ValueError("replay capability risk ceiling is restricted to T0-T2")
        if self.expires_at > self.issued_at + timedelta(seconds=self.ttl_seconds):
            raise ValueError("replay capability exceeds the fixed TTL ceiling")
        return self


class ReplaySourceCapabilityReceipt(ReplayArtifactModel):
    """Canonical historical authority and execution window for the source Tool call."""

    kind: Literal["ReplaySourceCapabilityReceipt"] = "ReplaySourceCapabilityReceipt"
    request_id: _Identifier
    lineage: list[CapabilityGrant] = Field(min_length=2, max_length=101)
    execution_started_at: datetime
    execution_finished_at: datetime

    @field_validator("execution_started_at", "execution_finished_at")
    @classmethod
    def normalize_timestamps(cls, value: datetime, info: object) -> datetime:
        field_name = getattr(info, "field_name", "timestamp")
        return _normalize_utc(value, field_name=field_name)

    @model_validator(mode="after")
    def validate_historical_lineage(self) -> ReplaySourceCapabilityReceipt:
        grant_ids = [grant.grant_id for grant in self.lineage]
        if len(grant_ids) != len(set(grant_ids)):
            raise ValueError("source capability lineage grant IDs must be unique")
        if self.execution_finished_at < self.execution_started_at:
            raise ValueError("source Tool execution cannot finish before it starts")

        root = self.lineage[0]
        if root.parent_grant_id is not None or root.depth != 0 or not root.delegable:
            raise ValueError("source capability lineage must begin with a delegable root")
        for parent, child in zip(self.lineage, self.lineage[1:], strict=False):
            if not child.attenuates(parent):
                raise ValueError("source capability lineage is orphaned or not attenuated")

        specialist = self.lineage[-1]
        if specialist.parent_grant_id is None or specialist.depth == 0 or specialist.delegable:
            raise ValueError("source capability lineage must end with a Specialist grant")
        for grant in self.lineage:
            issued_at = _normalize_utc(grant.issued_at, field_name="grant.issued_at")
            expires_at = _normalize_utc(grant.expires_at, field_name="grant.expires_at")
            if issued_at > self.execution_started_at or self.execution_finished_at >= expires_at:
                raise ValueError("source Tool execution occurred outside capability authority")
        return self

    @property
    def specialist_grant(self) -> CapabilityGrant:
        """Return the terminal, least-privilege grant that authorized the source call."""

        return self.lineage[-1]


class CompiledReplaySpec(ReplayArtifactModel):
    """Trusted executable specification produced after deterministic compilation."""

    kind: Literal["CompiledReplaySpec"] = "CompiledReplaySpec"
    spec_id: _Identifier
    intent_id: _Identifier | None = None
    contract_id: _Identifier
    purpose: ReplayPurpose = ReplayPurpose.CONFIRMATION
    retest_context_digest: _Sha256 | None = None
    original_plan_step_id: _Identifier
    binding: ReplayBinding
    method: str = Field(min_length=1, max_length=20)
    arguments: dict[str, JsonValue] = Field(max_length=100)
    argument_digest: _Sha256
    original_request_digest: _Sha256
    original_evidence_digest: _Sha256
    source_capability_digest: _Sha256
    secret_lease_ids: list[_Identifier] = Field(default_factory=list, max_length=20)
    risk_tier: ToolRiskTier
    replay_safe: Literal[True]
    idempotent: Literal[True]
    session_policy: ReplaySessionPolicy
    materializer_id: _Identifier | None = None
    materializer_version: _Version | None = None
    ephemeral_argument_fields: set[_Identifier] = Field(default_factory=set, max_length=10)
    repetitions: int = Field(ge=1, le=20)
    required_successes: int = Field(ge=1, le=20)
    required_contradictions: int = Field(default=0, ge=0, le=20)
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
        _validate_compiled_digest_and_thresholds(self)
        _validate_compiled_purpose(self)
        _validate_compiled_session_policy(self)
        _validate_compiled_budget_and_window(self)
        return self


class ReplayCompilation(ReplayArtifactModel):
    """Complete deterministic compiler output before any replay is executed."""

    kind: Literal["ReplayCompilation"] = "ReplayCompilation"
    validation_packet: ValidationPacket
    contract: ModeReplayContract
    intent: ReplayIntent
    original_request: ToolRequest
    original_evidence: list[_EvidenceReference] = Field(min_length=1, max_length=100)
    source_capability: ReplaySourceCapabilityReceipt
    spec: CompiledReplaySpec
    grant: ReplayCapabilityGrant

    @model_validator(mode="before")
    @classmethod
    def detach_mutable_inputs(cls, value: object) -> object:
        return _detach_model_fields(
            value,
            {
                "validation_packet",
                "contract",
                "intent",
                "original_request",
                "source_capability",
                "spec",
                "grant",
            },
        )

    @model_validator(mode="after")
    def validate_compilation_bindings(self) -> ReplayCompilation:
        _validate_compilation_provenance(self)
        _validate_compilation_packet_binding(self)
        _validate_compilation_mode_contract(self)
        _validate_compilation_grant(self)
        return self


class ReplayMaterialization(ReplayArtifactModel):
    """Auditable arguments produced by one trusted session materializer."""

    kind: Literal["ReplayMaterialization"] = "ReplayMaterialization"
    materialization_id: _Identifier
    spec_id: _Identifier
    attempt_number: int = Field(ge=1, le=20)
    replay_request_id: _Identifier
    materializer_id: _Identifier
    materializer_version: _Version
    changed_fields: set[_Identifier] = Field(min_length=1, max_length=10)
    source_argument_digest: _Sha256
    arguments: dict[str, JsonValue] = Field(max_length=100)
    argument_digest: _Sha256
    source_session_digest: _Sha256
    materialized_session_digest: _Sha256
    materialized_at: datetime

    @field_validator("materialized_at")
    @classmethod
    def normalize_materialized_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="materialized_at")

    @model_validator(mode="after")
    def validate_materialization(self) -> ReplayMaterialization:
        if self.changed_fields != {"session_id"}:
            raise ValueError("fresh-session materialization may change only session_id")
        if self.argument_digest != replay_argument_digest(self.arguments):
            raise ValueError("materialized argument digest does not match arguments")
        session_id = self.arguments.get("session_id")
        if not isinstance(session_id, str):
            raise ValueError("fresh-session materialization requires a string session_id")
        digest = sha256(session_id.encode("utf-8")).hexdigest()
        if self.materialized_session_digest != digest:
            raise ValueError("materialized session digest does not match session_id")
        if self.source_session_digest == self.materialized_session_digest:
            raise ValueError("fresh-session materialization must not reuse the source session")
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
    materialization: ReplayMaterialization | None = None
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
        if self.materialization is not None and (
            self.materialization.spec_id != self.spec_id
            or self.materialization.attempt_number != self.attempt_number
            or self.materialization.replay_request_id != self.replay_request_id
            or self.materialization.materialized_at > self.started_at
        ):
            raise ValueError("replay materialization must match its attempt")
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
    contradicting_evidence: list[_EvidenceReference] = Field(default_factory=list, max_length=100)
    support_count: int = Field(ge=0, le=20)
    required_support_count: int = Field(ge=1, le=20)
    contradiction_count: int = Field(default=0, ge=0, le=20)
    required_contradiction_count: int = Field(default=0, ge=0, le=20)
    summary: _BoundedText
    evaluated_at: datetime

    @field_validator("evaluated_at")
    @classmethod
    def normalize_evaluated_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="evaluated_at")

    @model_validator(mode="after")
    def validate_oracle_result(self, info: ValidationInfo) -> ReplayOracleResult:
        _validate_oracle_identities(self)
        supports, contradicts = _oracle_threshold_state(self)
        legacy_contradicts = _is_legacy_confirmation_contradiction(self, info)
        _validate_oracle_verdict(self, supports, contradicts, legacy_contradicts)
        _validate_oracle_evidence(self, legacy_contradicts)
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

    @model_validator(mode="before")
    @classmethod
    def detach_mutable_inputs(cls, value: object) -> object:
        return _detach_model_fields(value, {"binding", "oracle_result"}, list_fields={"attempts"})

    @field_validator("completed_at")
    @classmethod
    def normalize_completed_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="completed_at")

    @model_validator(mode="after")
    def validate_outcome_lineage(self) -> ReplayOutcome:
        _validate_outcome_identity_lists(self)
        _validate_outcome_attempt_bindings(self)
        _validate_outcome_execution_state(self)
        _validate_outcome_oracle_lineage(self)
        _validate_outcome_timestamps(self)
        return self

    @property
    def supports_claim(self) -> bool:
        return (
            self.execution_status is ReplayExecutionStatus.SUCCEEDED
            and self.oracle_result is not None
            and self.oracle_result.verdict is ReplayOracleVerdict.SUPPORTS
        )

    @property
    def contradicts_claim(self) -> bool:
        return (
            self.execution_status is ReplayExecutionStatus.SUCCEEDED
            and self.oracle_result is not None
            and self.oracle_result.verdict is ReplayOracleVerdict.CONTRADICTS
        )


class ReplayArtifactSet(ReplayArtifactModel):
    """Cross-artifact integrity boundary for one compiled replay and outcome."""

    kind: Literal["ReplayArtifactSet"] = "ReplayArtifactSet"
    validation_packet: ValidationPacket
    contract: ModeReplayContract
    intent: ReplayIntent | None = None
    spec: CompiledReplaySpec
    outcome: ReplayOutcome

    @model_validator(mode="before")
    @classmethod
    def detach_mutable_inputs(cls, value: object) -> object:
        return _detach_model_fields(
            value,
            {"validation_packet", "contract", "intent", "spec", "outcome"},
        )

    @model_validator(mode="after")
    def validate_cross_artifact_bindings(self) -> ReplayArtifactSet:
        _validate_artifact_packet_binding(self.validation_packet, self.contract, self.spec)
        _validate_artifact_mode_contract(self.validation_packet, self.contract, self.spec)
        _validate_artifact_intent(self.validation_packet, self.contract, self.intent, self.spec)
        _validate_artifact_outcome(self.validation_packet, self.spec, self.outcome)
        return self


def _validate_packet_candidate(packet: ValidationPacket) -> None:
    if packet.created_at < packet.candidate.created_at:
        raise ValueError("validation packet cannot predate its Candidate")
    if packet.original_request_ids != packet.candidate.source_request_ids:
        raise ValueError("validation packet original request IDs must match the candidate")
    if packet.threat_class != packet.candidate.claim.threat_class:
        raise ValueError("validation packet threat class must match the candidate")
    if packet.target != packet.candidate.claim.target:
        raise ValueError("validation packet target must match the candidate")


def _validate_packet_evidence(packet: ValidationPacket) -> None:
    references = [item.reference for item in packet.evidence]
    if len(references) != len(set(references)):
        raise ValueError("validation packet evidence references must be unique")
    candidate_evidence = set(packet.candidate.claim.evidence)
    if any(reference not in candidate_evidence for reference in references):
        raise ValueError("validation packet may include only candidate evidence")


def _validate_packet_retest_context(packet: ValidationPacket) -> None:
    if packet.purpose is ReplayPurpose.CONFIRMATION:
        if packet.retest_context is not None:
            raise ValueError("confirmation validation packet cannot contain retest context")
        return
    context = packet.retest_context
    if context is None:
        raise ValueError("remediation retest validation packet requires retest context")
    if context.baseline_finding_id != packet.candidate.claim.finding_id:
        raise ValueError("retest baseline finding must match the packet Candidate")
    if context.retest_run_id == packet.candidate_run_id:
        raise ValueError("parent Retest Run must differ from the Candidate Run")


def _validate_replay_thresholds(
    replay: ModeReplayContract | CompiledReplaySpec,
) -> None:
    if replay.required_successes > replay.repetitions:
        raise ValueError("required successes cannot exceed repetitions")
    if replay.required_contradictions > replay.repetitions:
        raise ValueError("required contradictions cannot exceed repetitions")
    if (
        replay.required_contradictions > 0
        and replay.required_successes + replay.required_contradictions <= replay.repetitions
    ):
        raise ValueError(
            "support and contradiction thresholds must not be simultaneously reachable"
        )


def _validate_contract_session_policy(contract: ModeReplayContract) -> None:
    if contract.session_policy is ReplaySessionPolicy.STATELESS:
        if contract.materializer_id is not None or contract.materializer_version is not None:
            raise ValueError("stateless replay cannot declare a session materializer")
        if contract.ephemeral_argument_fields:
            raise ValueError("stateless replay cannot declare ephemeral arguments")
    elif contract.session_policy is ReplaySessionPolicy.FRESH_SESSION:
        if contract.materializer_id is None or contract.materializer_version is None:
            raise ValueError("fresh-session replay requires a session materializer")
        if contract.ephemeral_argument_fields != {"session_id"}:
            raise ValueError("fresh-session replay may change only session_id")
        if "session_id" not in contract.allowed_argument_fields:
            raise ValueError("fresh-session replay must allowlist session_id")
    elif contract.automatic:
        raise ValueError("automatic preserve-scenario-session replay is unsupported")


def _validate_compiled_digest_and_thresholds(spec: CompiledReplaySpec) -> None:
    if spec.argument_digest != replay_argument_digest(spec.arguments):
        raise ValueError("compiled replay argument digest does not match arguments")
    if len(spec.secret_lease_ids) != len(set(spec.secret_lease_ids)):
        raise ValueError("secret_lease_ids must be unique")
    _validate_replay_thresholds(spec)


def _validate_compiled_purpose(spec: CompiledReplaySpec) -> None:
    if spec.purpose != spec.binding.purpose:
        raise ValueError("compiled replay purpose must match its binding")
    if spec.purpose is ReplayPurpose.CONFIRMATION:
        if spec.retest_context_digest is not None:
            raise ValueError("confirmation compiled replay cannot bind retest context")
    elif spec.retest_context_digest is None:
        raise ValueError("remediation retest compiled replay requires a context digest")


def _validate_compiled_session_policy(spec: CompiledReplaySpec) -> None:
    if spec.session_policy is ReplaySessionPolicy.STATELESS:
        if spec.materializer_id is not None or spec.materializer_version is not None:
            raise ValueError("stateless replay cannot declare a session materializer")
        if spec.ephemeral_argument_fields:
            raise ValueError("stateless replay cannot declare ephemeral arguments")
    elif spec.session_policy is ReplaySessionPolicy.FRESH_SESSION:
        if spec.materializer_id is None or spec.materializer_version is None:
            raise ValueError("fresh-session replay requires a session materializer")
        if spec.ephemeral_argument_fields != {"session_id"}:
            raise ValueError("fresh-session replay may change only session_id")
    else:
        raise ValueError("compiled preserve-scenario-session replay is unsupported")


def _validate_compiled_budget_and_window(spec: CompiledReplaySpec) -> None:
    if spec.max_calls != spec.repetitions:
        raise ValueError("compiled replay call budget must exactly match repetitions")
    if spec.risk_tier > ToolRiskTier.T2:
        raise ValueError("compiled automatic replay is restricted to T0-T2")
    if spec.expires_at <= spec.compiled_at:
        raise ValueError("compiled replay authority must expire after compilation")
    if spec.expires_at > spec.compiled_at + timedelta(seconds=300):
        raise ValueError("compiled replay authority exceeds the fixed TTL ceiling")


def _validate_oracle_identities(oracle: ReplayOracleResult) -> None:
    if len(oracle.attempt_ids) != len(set(oracle.attempt_ids)):
        raise ValueError("oracle attempt IDs must be unique")
    if len(oracle.supporting_evidence) != len(set(oracle.supporting_evidence)):
        raise ValueError("oracle supporting evidence must be unique")
    if len(oracle.contradicting_evidence) != len(set(oracle.contradicting_evidence)):
        raise ValueError("oracle contradicting evidence must be unique")
    if set(oracle.supporting_evidence) & set(oracle.contradicting_evidence):
        raise ValueError("oracle supporting and contradicting evidence must be disjoint")


def _oracle_threshold_state(oracle: ReplayOracleResult) -> tuple[bool, bool]:
    if oracle.support_count + oracle.contradiction_count > len(oracle.attempt_ids):
        raise ValueError("oracle result counts cannot exceed evaluated attempts")
    if oracle.required_support_count > len(oracle.attempt_ids):
        raise ValueError("oracle required support count cannot exceed evaluated attempts")
    if oracle.required_contradiction_count > len(oracle.attempt_ids):
        raise ValueError("oracle required contradiction count cannot exceed evaluated attempts")
    supports = oracle.support_count >= oracle.required_support_count
    contradicts = (
        oracle.required_contradiction_count > 0
        and oracle.contradiction_count >= oracle.required_contradiction_count
    )
    if supports and contradicts:
        raise ValueError("oracle support and contradiction thresholds cannot both be met")
    return supports, contradicts


def _is_legacy_confirmation_contradiction(
    oracle: ReplayOracleResult,
    info: ValidationInfo,
) -> bool:
    # v1 confirmation artifacts predate typed contradiction thresholds. Retests
    # never receive this exception: a fixed projection needs an explicit threshold.
    return (
        oracle.verdict is ReplayOracleVerdict.CONTRADICTS
        and info.context is not None
        and info.context.get(_ALLOW_LEGACY_CONFIRMATION_CONTRADICTION) is True
        and oracle.binding.purpose is ReplayPurpose.CONFIRMATION
        and oracle.required_contradiction_count == 0
        and oracle.contradiction_count == 0
        and oracle.support_count == 0
    )


def _validate_oracle_verdict(
    oracle: ReplayOracleResult,
    supports: bool,
    contradicts: bool,
    legacy_contradicts: bool,
) -> None:
    if oracle.verdict is ReplayOracleVerdict.SUPPORTS and not supports:
        raise ValueError("supporting Oracle verdict must meet its required support count")
    if oracle.verdict is ReplayOracleVerdict.SUPPORTS and contradicts:
        raise ValueError("supporting Oracle verdict cannot meet contradiction threshold")
    if (
        oracle.verdict is ReplayOracleVerdict.CONTRADICTS
        and not contradicts
        and not legacy_contradicts
    ):
        raise ValueError("contradicting Oracle verdict must meet its required contradiction count")
    if oracle.verdict is ReplayOracleVerdict.CONTRADICTS and supports:
        raise ValueError("contradicting Oracle verdict cannot meet support threshold")
    if oracle.verdict is ReplayOracleVerdict.INCONCLUSIVE and (supports or contradicts):
        raise ValueError("inconclusive Oracle verdict cannot meet an Oracle threshold")


def _validate_oracle_evidence(
    oracle: ReplayOracleResult,
    legacy_contradicts: bool,
) -> None:
    if oracle.support_count == 0 and oracle.supporting_evidence:
        raise ValueError("Oracle cannot cite supporting evidence with zero support count")
    if oracle.contradiction_count == 0 and oracle.contradicting_evidence:
        raise ValueError("Oracle cannot cite contradicting evidence with zero contradiction count")
    if (
        oracle.verdict is ReplayOracleVerdict.CONTRADICTS
        and not legacy_contradicts
        and len(oracle.contradicting_evidence) != oracle.contradiction_count
    ):
        raise ValueError("contradicting Oracle verdict requires exact evidence for every count")


def _validate_outcome_identity_lists(outcome: ReplayOutcome) -> None:
    expected_attempt_ids = [attempt.attempt_id for attempt in outcome.attempts]
    expected_request_ids = [attempt.replay_request_id for attempt in outcome.attempts]
    attempt_evidence = [reference for attempt in outcome.attempts for reference in attempt.evidence]
    if len(expected_attempt_ids) != len(set(expected_attempt_ids)):
        raise ValueError("replay attempt IDs must be unique")
    if len(expected_request_ids) != len(set(expected_request_ids)):
        raise ValueError("replay request IDs must be unique")
    if len(attempt_evidence) != len(set(attempt_evidence)):
        raise ValueError("replay evidence references must be unique across attempts")
    if outcome.attempt_ids != expected_attempt_ids:
        raise ValueError("outcome attempt IDs must exactly match its attempts")
    if outcome.replay_request_ids != expected_request_ids:
        raise ValueError("outcome replay request IDs must exactly match its attempts")
    if outcome.evidence != list(dict.fromkeys(attempt_evidence)):
        raise ValueError("outcome evidence must exactly match replay attempt evidence")


def _validate_outcome_attempt_bindings(outcome: ReplayOutcome) -> None:
    for attempt in outcome.attempts:
        if attempt.spec_id != outcome.spec_id:
            raise ValueError("replay attempt spec ID must match the outcome")
        if attempt.binding != outcome.binding:
            raise ValueError("replay attempt binding must match the outcome")


def _validate_outcome_execution_state(outcome: ReplayOutcome) -> None:
    if outcome.execution_status is ReplayExecutionStatus.UNSUPPORTED:
        if outcome.attempts:
            raise ValueError("unsupported replay outcome cannot contain attempts")
    elif not outcome.attempts:
        raise ValueError("executed replay outcome requires at least one attempt")
    oracle = outcome.oracle_result
    if outcome.execution_status is ReplayExecutionStatus.SUCCEEDED:
        if not any(attempt.status is ReplayAttemptStatus.SUCCEEDED for attempt in outcome.attempts):
            raise ValueError("successful replay outcome requires a successful attempt")
        if oracle is None:
            raise ValueError("successful replay outcome requires a Mode Oracle result")
    elif oracle is not None and oracle.verdict is ReplayOracleVerdict.SUPPORTS:
        raise ValueError("unsuccessful replay outcome cannot claim Oracle support")


def _validate_outcome_oracle_lineage(outcome: ReplayOutcome) -> None:
    oracle = outcome.oracle_result
    if oracle is None:
        return
    if oracle.spec_id != outcome.spec_id:
        raise ValueError("replay Oracle spec ID must match the outcome")
    if oracle.binding != outcome.binding:
        raise ValueError("replay Oracle binding must match the outcome")
    if oracle.attempt_ids != outcome.attempt_ids:
        raise ValueError("replay Oracle attempts must exactly match the outcome")
    if any(reference not in outcome.evidence for reference in oracle.supporting_evidence):
        raise ValueError("replay Oracle references evidence outside the outcome")
    if any(reference not in outcome.evidence for reference in oracle.contradicting_evidence):
        raise ValueError("replay Oracle references evidence outside the outcome")


def _validate_outcome_timestamps(outcome: ReplayOutcome) -> None:
    oracle = outcome.oracle_result
    if oracle is not None:
        if oracle.evaluated_at > outcome.completed_at:
            raise ValueError("replay outcome cannot complete before Oracle evaluation")
        if any(attempt.finished_at > oracle.evaluated_at for attempt in outcome.attempts):
            raise ValueError("replay Oracle cannot evaluate before its attempts finish")
    if any(attempt.finished_at > outcome.completed_at for attempt in outcome.attempts):
        raise ValueError("replay outcome cannot complete before its attempts")


def _validate_compilation_provenance(compilation: ReplayCompilation) -> None:
    packet = compilation.validation_packet
    request = compilation.original_request
    source_capability = compilation.source_capability
    spec = compilation.spec
    binding = spec.binding
    grant = compilation.grant
    if not (
        source_capability.execution_finished_at
        <= packet.candidate.created_at
        <= packet.created_at
        <= compilation.intent.created_at
        <= spec.compiled_at
    ):
        raise ValueError("compiled replay artifact chronology is inconsistent")
    if len(compilation.original_evidence) != len(set(compilation.original_evidence)):
        raise ValueError("compiled original evidence references must be unique")
    if any(
        reference not in packet.candidate.claim.evidence
        for reference in compilation.original_evidence
    ):
        raise ValueError("compiled replay references evidence outside the Candidate")
    if spec.original_request_digest != replay_request_digest(request):
        raise ValueError("compiled replay original request digest does not match")
    if spec.original_evidence_digest != replay_evidence_digest(compilation.original_evidence):
        raise ValueError("compiled replay original evidence digest does not match")
    source_capability_digest = replay_source_capability_digest(source_capability)
    source_specialist = source_capability.specialist_grant
    if (
        spec.source_capability_digest != source_capability_digest
        or grant.source_capability_digest != source_capability_digest
        or grant.original_grant_id != source_specialist.grant_id
        or grant.original_subject != source_specialist.subject
        or source_capability.request_id != request.request_id
        or source_specialist.campaign != binding.campaign
        or request.tool_id not in source_specialist.tools
        or request.target not in source_specialist.targets
        or spec.risk_tier > source_specialist.max_risk_tier
        or source_specialist.max_calls < 1
        or source_capability.execution_finished_at > packet.candidate.created_at
    ):
        raise ValueError("compiled replay source capability receipt does not match")
    if spec.arguments != request.arguments:
        raise ValueError("compiled replay arguments must match the original request")
    if (
        binding.original_request_id != request.request_id
        or binding.tool_id != request.tool_id
        or binding.target != request.target
        or spec.method != request.method
    ):
        raise ValueError("compiled replay operation must match the original request")


def _validate_compilation_packet_binding(compilation: ReplayCompilation) -> None:
    packet = compilation.validation_packet
    intent = compilation.intent
    contract = compilation.contract
    spec = compilation.spec
    binding = spec.binding
    if (
        packet.replay_contract_id != contract.contract_id
        or packet.purpose != contract.purpose
        or packet.purpose != intent.purpose
        or packet.purpose != spec.purpose
        or packet.purpose != binding.purpose
        or binding.candidate_id != packet.candidate.candidate_id
        or binding.candidate_run_id != packet.candidate_run_id
        or binding.mode != packet.mode
        or binding.scenario_id != packet.scenario_id
        or binding.target_id != packet.target_id
        or binding.target != packet.target
        or binding.threat_class != packet.threat_class
        or binding.original_request_id not in packet.original_request_ids
    ):
        raise ValueError("compiled replay binding must match the validation packet")
    if packet.retest_context != intent.retest_context:
        raise ValueError("ReplayIntent retest context must match the validation packet")
    if packet.retest_context is None:
        if spec.retest_context_digest is not None or binding.context_run_id is not None:
            raise ValueError("confirmation replay cannot bind remediation retest context")
    elif (
        spec.retest_context_digest != replay_retest_context_digest(packet.retest_context)
        or binding.context_run_id != packet.retest_context.retest_run_id
    ):
        raise ValueError("compiled replay retest context must exactly match the packet")
    if (
        intent.intent_id != spec.intent_id
        or intent.replay_contract_id != contract.contract_id
        or intent.candidate_id != binding.candidate_id
        or intent.candidate_run_id != binding.candidate_run_id
        or intent.original_request_id != binding.original_request_id
        or intent.mode != binding.mode
        or intent.scenario_id != binding.scenario_id
        or intent.threat_class != binding.threat_class
    ):
        raise ValueError("ReplayIntent references must match the compiled replay binding")


def _validate_compilation_mode_contract(compilation: ReplayCompilation) -> None:
    packet = compilation.validation_packet
    contract = compilation.contract
    spec = compilation.spec
    binding = spec.binding
    if (
        spec.contract_id != contract.contract_id
        or binding.mode != contract.mode
        or binding.scenario_id != contract.scenario_id
        or binding.tool_id != contract.tool_id
        or binding.tool_version != contract.tool_version
        or spec.method != contract.method
        or spec.risk_tier != contract.risk_tier
        or spec.session_policy != contract.session_policy
        or spec.materializer_id != contract.materializer_id
        or spec.materializer_version != contract.materializer_version
        or spec.ephemeral_argument_fields != contract.ephemeral_argument_fields
        or spec.repetitions != contract.repetitions
        or spec.required_successes != contract.required_successes
        or spec.required_contradictions != contract.required_contradictions
        or spec.oracle_id != contract.oracle_id
        or spec.oracle_version != contract.oracle_version
        or spec.observation_schema != contract.observation_schema
        or spec.semantic_support_required != contract.semantic_support_required
        or packet.semantic_support_required != contract.semantic_support_required
        or not contract.automatic
        or not contract.replay_safe
        or not contract.idempotent
    ):
        raise ValueError("compiled replay policy must match the automatic Mode contract")
    if not set(spec.arguments) <= contract.allowed_argument_fields:
        raise ValueError("compiled replay arguments exceed the Mode contract allowlist")


def _validate_compilation_grant(compilation: ReplayCompilation) -> None:
    request = compilation.original_request
    contract = compilation.contract
    spec = compilation.spec
    binding = spec.binding
    grant = compilation.grant
    if (
        spec.grant_id != grant.grant_id
        or grant.contract_id != contract.contract_id
        or grant.candidate_id != binding.candidate_id
        or grant.candidate_run_id != binding.candidate_run_id
        or grant.replay_run_id != binding.replay_run_id
        or grant.original_request_id != binding.original_request_id
        or grant.original_subject != request.agent_id
        or grant.campaign != binding.campaign
        or grant.tool_id != binding.tool_id
        or grant.target != binding.target
        or grant.max_risk_tier != spec.risk_tier
        or grant.max_calls != spec.max_calls
        or grant.repetitions != spec.repetitions
        or grant.issued_at != spec.compiled_at
        or grant.expires_at != spec.expires_at
    ):
        raise ValueError("replay capability must match the compiled replay specification")


def _validate_artifact_packet_binding(
    packet: ValidationPacket,
    contract: ModeReplayContract,
    spec: CompiledReplaySpec,
) -> None:
    binding = spec.binding
    if packet.replay_contract_id != contract.contract_id:
        raise ValueError("validation packet must reference the Mode replay contract")
    if (
        packet.purpose != contract.purpose
        or packet.purpose != spec.purpose
        or packet.purpose != binding.purpose
        or binding.candidate_id != packet.candidate.candidate_id
        or binding.candidate_run_id != packet.candidate_run_id
        or binding.mode != packet.mode
        or binding.scenario_id != packet.scenario_id
        or binding.target_id != packet.target_id
        or binding.target != packet.target
        or binding.threat_class != packet.threat_class
        or binding.original_request_id not in packet.original_request_ids
    ):
        raise ValueError("compiled replay binding must match the validation packet")
    if packet.retest_context is None:
        if spec.retest_context_digest is not None or binding.context_run_id is not None:
            raise ValueError("confirmation replay cannot bind remediation retest context")
    elif (
        spec.retest_context_digest != replay_retest_context_digest(packet.retest_context)
        or binding.context_run_id != packet.retest_context.retest_run_id
    ):
        raise ValueError("compiled replay retest context must exactly match the packet")


def _validate_artifact_mode_contract(
    packet: ValidationPacket,
    contract: ModeReplayContract,
    spec: CompiledReplaySpec,
) -> None:
    binding = spec.binding
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
        or spec.materializer_id != contract.materializer_id
        or spec.materializer_version != contract.materializer_version
        or spec.ephemeral_argument_fields != contract.ephemeral_argument_fields
        or spec.repetitions != contract.repetitions
        or spec.required_successes != contract.required_successes
        or spec.required_contradictions != contract.required_contradictions
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


def _validate_artifact_intent(
    packet: ValidationPacket,
    contract: ModeReplayContract,
    intent: ReplayIntent | None,
    spec: CompiledReplaySpec,
) -> None:
    binding = spec.binding
    if intent is not None:
        if not packet.created_at <= intent.created_at <= spec.compiled_at:
            raise ValueError("ReplayIntent chronology must match replay compilation")
        if spec.intent_id != intent.intent_id:
            raise ValueError("compiled replay intent ID must match the ReplayIntent")
        if (
            intent.replay_contract_id != contract.contract_id
            or intent.purpose != packet.purpose
            or intent.candidate_id != binding.candidate_id
            or intent.candidate_run_id != binding.candidate_run_id
            or intent.original_request_id != binding.original_request_id
            or intent.mode != binding.mode
            or intent.scenario_id != binding.scenario_id
            or intent.threat_class != binding.threat_class
        ):
            raise ValueError("ReplayIntent references must match the compiled replay binding")
        if intent.retest_context != packet.retest_context:
            raise ValueError("ReplayIntent retest context must match the validation packet")
    elif packet.purpose is ReplayPurpose.REMEDIATION_RETEST:
        raise ValueError("remediation retest artifacts require a ReplayIntent")
    elif spec.intent_id is not None:
        raise ValueError("compiled replay references a missing ReplayIntent")
    elif packet.created_at > spec.compiled_at:
        raise ValueError("compiled replay cannot predate its ValidationPacket")


def _validate_artifact_outcome(
    packet: ValidationPacket,
    spec: CompiledReplaySpec,
    outcome: ReplayOutcome,
) -> None:
    if outcome.spec_id != spec.spec_id:
        raise ValueError("outcome spec ID must match the compiled replay spec")
    if outcome.binding != spec.binding:
        raise ValueError("outcome binding must match the compiled replay spec")
    if outcome.completed_at < spec.compiled_at:
        raise ValueError("replay outcome cannot complete before compilation")
    if set(outcome.replay_request_ids) & set(packet.original_request_ids):
        raise ValueError("replay request IDs must be distinct from all Candidate requests")
    if set(outcome.evidence) & set(packet.candidate.claim.evidence):
        raise ValueError("replay evidence must be independent from Candidate evidence")
    _validate_artifact_attempts(spec, outcome)
    _validate_artifact_materializations(spec, outcome)
    _validate_artifact_oracle(spec, outcome)


def _validate_artifact_attempts(spec: CompiledReplaySpec, outcome: ReplayOutcome) -> None:
    if len(outcome.attempts) > spec.repetitions:
        raise ValueError("replay outcome exceeds the compiled repetition budget")
    attempt_numbers = [attempt.attempt_number for attempt in outcome.attempts]
    if len(attempt_numbers) != len(set(attempt_numbers)):
        raise ValueError("replay attempt numbers must be unique")
    if attempt_numbers != list(range(1, len(attempt_numbers) + 1)):
        raise ValueError("replay attempt numbers must be contiguous and ordered from one")
    if any(number > spec.repetitions for number in attempt_numbers):
        raise ValueError("replay attempt number exceeds the compiled repetition budget")
    if any(
        attempt.started_at < spec.compiled_at or attempt.started_at >= spec.expires_at
        for attempt in outcome.attempts
    ):
        raise ValueError("replay attempt started outside compiled authority")
    if any(
        attempt.status is ReplayAttemptStatus.SUCCEEDED and attempt.finished_at > spec.expires_at
        for attempt in outcome.attempts
    ):
        raise ValueError("successful replay attempt finished outside compiled authority")
    if any(
        current.started_at < previous.finished_at
        for previous, current in zip(
            outcome.attempts,
            outcome.attempts[1:],
            strict=False,
        )
    ):
        raise ValueError("replay attempts must execute in chronological order")
    if any(attempt.observation_schema != spec.observation_schema for attempt in outcome.attempts):
        raise ValueError("replay observation schema must match the compiled replay spec")


def _validate_artifact_materializations(
    spec: CompiledReplaySpec,
    outcome: ReplayOutcome,
) -> None:
    if spec.session_policy is ReplaySessionPolicy.STATELESS:
        if any(attempt.materialization is not None for attempt in outcome.attempts):
            raise ValueError("stateless replay attempts cannot contain materialization")
        return
    if spec.session_policy is not ReplaySessionPolicy.FRESH_SESSION or not outcome.attempts:
        return
    source_session = spec.arguments.get("session_id")
    if not isinstance(source_session, str):
        raise ValueError("fresh-session replay spec requires a string session_id")
    source_session_digest = sha256(source_session.encode("utf-8")).hexdigest()
    materializations = _fresh_materializations(outcome)
    for item in materializations:
        _validate_materialization_against_spec(item, spec, source_session_digest)
    materialized_session_digests = [item.materialized_session_digest for item in materializations]
    materialization_ids = [item.materialization_id for item in materializations]
    if len(materialized_session_digests) != len(set(materialized_session_digests)):
        raise ValueError("fresh replay sessions must be unique across attempts")
    if len(materialization_ids) != len(set(materialization_ids)):
        raise ValueError("replay materialization IDs must be unique across attempts")


def _fresh_materializations(outcome: ReplayOutcome) -> list[ReplayMaterialization]:
    materializations = [attempt.materialization for attempt in outcome.attempts]
    if any(item is None for item in materializations):
        raise ValueError("fresh-session replay attempts require materialization")
    return [item for item in materializations if item is not None]


def _validate_materialization_against_spec(
    item: ReplayMaterialization,
    spec: CompiledReplaySpec,
    source_session_digest: str,
) -> None:
    if (
        item.materializer_id != spec.materializer_id
        or item.materializer_version != spec.materializer_version
        or item.changed_fields != spec.ephemeral_argument_fields
        or item.source_argument_digest != spec.argument_digest
        or item.source_session_digest != source_session_digest
        or item.materialized_at < spec.compiled_at
    ):
        raise ValueError("replay materialization must match the compiled spec")
    if set(item.arguments) != set(spec.arguments) or any(
        item.arguments[field] != value
        for field, value in spec.arguments.items()
        if field != "session_id"
    ):
        raise ValueError("replay materialization changed non-ephemeral arguments")


def _validate_artifact_oracle(spec: CompiledReplaySpec, outcome: ReplayOutcome) -> None:
    if outcome.execution_status is ReplayExecutionStatus.SUCCEEDED and (
        len(outcome.attempts) != spec.repetitions
        or any(attempt.status is not ReplayAttemptStatus.SUCCEEDED for attempt in outcome.attempts)
    ):
        raise ValueError("successful replay outcome requires every compiled repetition to succeed")
    oracle = outcome.oracle_result
    if oracle is None:
        return
    if (
        oracle.oracle_id != spec.oracle_id
        or oracle.oracle_version != spec.oracle_version
        or oracle.observation_schema != spec.observation_schema
        or oracle.required_support_count != spec.required_successes
        or oracle.required_contradiction_count != spec.required_contradictions
    ):
        raise ValueError("replay Oracle contract must match the compiled replay spec")

    supporting_evidence = set(oracle.supporting_evidence)
    contradicting_evidence = set(oracle.contradicting_evidence)
    supporting_attempts = [
        attempt
        for attempt in outcome.attempts
        if supporting_evidence.intersection(attempt.evidence)
    ]
    contradicting_attempts = [
        attempt
        for attempt in outcome.attempts
        if contradicting_evidence.intersection(attempt.evidence)
    ]
    if len(supporting_attempts) != oracle.support_count or any(
        attempt.status is not ReplayAttemptStatus.SUCCEEDED for attempt in supporting_attempts
    ):
        raise ValueError("Oracle support count must match distinct successful attempt evidence")
    if len(contradicting_attempts) != oracle.contradiction_count or any(
        attempt.status is not ReplayAttemptStatus.SUCCEEDED for attempt in contradicting_attempts
    ):
        raise ValueError(
            "Oracle contradiction count must match distinct successful attempt evidence"
        )


def load_legacy_v1_replay_artifact_set(
    payload: str | bytes | bytearray,
) -> ReplayArtifactSet:
    """Parse a sealed v1 artifact with its narrow confirmation-contradiction exception."""

    return ReplayArtifactSet.model_validate_json(
        payload,
        context={_ALLOW_LEGACY_CONFIRMATION_CONTRADICTION: True},
    )


def _detach_model_fields(
    value: object,
    model_fields: set[str],
    *,
    list_fields: set[str] | None = None,
) -> object:
    """Rebuild nested models so later caller mutations cannot alter validated artifacts."""

    if not isinstance(value, Mapping):
        return value
    detached = dict(value)
    for field_name in model_fields:
        item = detached.get(field_name)
        if isinstance(item, StrictModel):
            detached[field_name] = item.model_dump(mode="python", by_alias=True)
    for field_name in list_fields or set():
        items = detached.get(field_name)
        if isinstance(items, list):
            detached[field_name] = [
                item.model_dump(mode="python", by_alias=True)
                if isinstance(item, StrictModel)
                else item
                for item in items
            ]
    return detached


def replay_argument_digest(arguments: Mapping[str, object]) -> str:
    """Return the canonical digest used to bind allowlisted replay arguments."""

    canonical = json.dumps(
        arguments,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def replay_request_digest(request: ToolRequest) -> str:
    """Bind the exact original Tool request, including its Specialist identity."""

    canonical = json.dumps(
        request.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def replay_evidence_digest(references: list[str]) -> str:
    """Bind an ordered, duplicate-free original evidence lineage."""

    canonical = json.dumps(
        references,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def replay_retest_context_digest(context: ReplayRetestContext) -> str:
    """Bind every baseline and parent-Run field of a remediation retest."""

    canonical = json.dumps(
        context.model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def replay_source_capability_digest(receipt: ReplaySourceCapabilityReceipt) -> str:
    """Bind the complete source authority chain and exact Tool execution window."""

    lineage = []
    for grant in receipt.lineage:
        lineage.append(
            {
                "campaign": grant.campaign,
                "delegable": grant.delegable,
                "depth": grant.depth,
                "expiresAt": _normalize_utc(
                    grant.expires_at,
                    field_name="grant.expires_at",
                ).isoformat(),
                "grantId": grant.grant_id,
                "issuedAt": _normalize_utc(
                    grant.issued_at,
                    field_name="grant.issued_at",
                ).isoformat(),
                "maxCalls": grant.max_calls,
                "maxRiskTier": int(grant.max_risk_tier),
                "parentGrantId": grant.parent_grant_id,
                "subject": grant.subject,
                "targets": sorted(grant.targets),
                "tools": sorted(grant.tools),
            }
        )
    canonical = json.dumps(
        {
            "apiVersion": receipt.api_version,
            "executionFinishedAt": receipt.execution_finished_at.isoformat(),
            "executionStartedAt": receipt.execution_started_at.isoformat(),
            "kind": receipt.kind,
            "lineage": lineage,
            "requestId": receipt.request_id,
        },
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8")
    return sha256(canonical).hexdigest()


def _normalize_utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset or Z")
    return value.astimezone(UTC)
