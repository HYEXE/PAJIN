"""Typed contracts for preserving and classifying finding validation outcomes."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from pajin.domain.models import Finding, StrictModel

_Identifier = Annotated[str, Field(min_length=1, max_length=200)]
_EvidenceReference = Annotated[str, Field(min_length=1, max_length=2_000)]


class FindingDisposition(StrEnum):
    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs-review"
    INCONCLUSIVE = "inconclusive"
    REJECTED_OBJECTIVE = "rejected-objective"


class ValidationMethod(StrEnum):
    LEGACY_VALIDATOR = "legacy-validator"
    DETERMINISTIC_GATE = "deterministic-gate"
    HYBRID_LEGACY_GATE = "hybrid-legacy-gate"
    RESTRICTED_REPLAY_GATE = "restricted-replay-gate"


class ConfirmationBasis(StrEnum):
    VERIFIED_INDEPENDENT_REPLAY = "verified-independent-replay"


class ValidationReasonCode(StrEnum):
    VALIDATOR_CONFIRMED = "validator-confirmed"
    INDEPENDENT_REPRODUCTION_MISSING = "independent-reproduction-missing"
    INDEPENDENT_REPRODUCTION_CONFIRMED = "independent-reproduction-confirmed"
    REPLAY_NOT_ELIGIBLE = "replay-not-eligible"
    REPLAY_APPROVAL_REQUIRED = "replay-approval-required"
    REPLAY_CANCELLED = "replay-cancelled"
    REPLAY_TIMED_OUT = "replay-timed-out"
    REPLAY_RATE_LIMITED = "replay-rate-limited"
    REPLAY_TARGET_UNAVAILABLE = "replay-target-unavailable"
    REPLAY_EXECUTION_FAILED = "replay-execution-failed"
    REPLAY_ORACLE_INCONCLUSIVE = "replay-oracle-inconclusive"
    REPLAY_ORACLE_CONTRADICTED = "replay-oracle-contradicted"
    VALIDATOR_DISAGREED = "validator-disagreed"
    VALIDATOR_OMITTED = "validator-omitted"
    VALIDATOR_UNAVAILABLE = "validator-unavailable"
    VALIDATOR_CANCELLED = "validator-cancelled"
    CANDIDATE_PRODUCER_NOT_ADMITTED = "candidate-producer-not-admitted"
    TARGET_UNDECLARED = "target-undeclared"
    TARGET_OUT_OF_SCOPE = "target-out-of-scope"
    THREAT_CLASS_UNDECLARED = "threat-class-undeclared"
    EVIDENCE_MISSING = "evidence-missing"
    EVIDENCE_UNLINKED = "evidence-unlinked"
    EVIDENCE_FILE_MISSING = "evidence-file-missing"
    SOURCE_REQUEST_MISMATCH = "source-request-mismatch"
    EXECUTION_FAILED = "execution-failed"


class ValidationCheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not-applicable"


class ValidationCheckResult(StrictModel):
    check_id: _Identifier
    status: ValidationCheckStatus
    reason_code: ValidationReasonCode | None = None
    summary: str = Field(min_length=1, max_length=2_000)


class CandidateFinding(StrictModel):
    candidate_id: _Identifier
    claim: Finding
    source: str = Field(default="legacy-validator-output", min_length=1, max_length=200)
    source_agent_id: _Identifier
    source_request_ids: list[_Identifier] = Field(max_length=1_000)
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="created_at")

    @model_validator(mode="after")
    def require_unique_source_requests(self) -> CandidateFinding:
        if len(self.source_request_ids) != len(set(self.source_request_ids)):
            raise ValueError("source_request_ids must be unique")
        return self


class ReplayConfirmationLineage(StrictModel):
    replay_run_id: _Identifier
    replay_outcome_id: _Identifier
    replay_request_ids: list[_Identifier] = Field(max_length=20)
    replay_evidence: list[_EvidenceReference] = Field(max_length=100)
    oracle_result_id: _Identifier | None = None
    ticket_id: _Identifier
    candidate_source_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_set_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    receipt_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    verified_at: datetime

    @field_validator("verified_at")
    @classmethod
    def normalize_verified_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="verified_at")

    @model_validator(mode="after")
    def require_unique_lineage(self) -> ReplayConfirmationLineage:
        if len(self.replay_request_ids) != len(set(self.replay_request_ids)):
            raise ValueError("lineage replay request IDs must be unique")
        if len(self.replay_evidence) != len(set(self.replay_evidence)):
            raise ValueError("lineage replay evidence references must be unique")
        return self


class ValidationDecision(StrictModel):
    decision_id: _Identifier
    supersedes_decision_id: _Identifier | None = None
    candidate_id: _Identifier
    validator_id: _Identifier
    method: ValidationMethod
    disposition: FindingDisposition
    confirmation_basis: ConfirmationBasis | None = None
    reason_codes: list[ValidationReasonCode] = Field(min_length=1, max_length=20)
    decision_summary: str = Field(min_length=1, max_length=5_000)
    supporting_evidence: list[_EvidenceReference] = Field(max_length=1_000)
    contradicting_evidence: list[_EvidenceReference] = Field(max_length=1_000)
    replay_request_ids: list[_Identifier] = Field(max_length=1_000)
    replay_outcome_ids: list[_Identifier] = Field(default_factory=list, max_length=1_000)
    replay_lineage: list[ReplayConfirmationLineage] = Field(default_factory=list, max_length=20)
    checks: list[ValidationCheckResult] = Field(max_length=100)
    decided_at: datetime

    @field_validator("decided_at")
    @classmethod
    def normalize_decided_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="decided_at")

    @model_validator(mode="after")
    def require_unique_decision_entries(self) -> ValidationDecision:
        if len(self.reason_codes) != len(set(self.reason_codes)):
            raise ValueError("reason_codes must be unique")
        if len(self.supporting_evidence) != len(set(self.supporting_evidence)):
            raise ValueError("supporting_evidence must be unique")
        if len(self.contradicting_evidence) != len(set(self.contradicting_evidence)):
            raise ValueError("contradicting_evidence must be unique")
        if len(self.replay_request_ids) != len(set(self.replay_request_ids)):
            raise ValueError("replay_request_ids must be unique")
        if len(self.replay_outcome_ids) != len(set(self.replay_outcome_ids)):
            raise ValueError("replay_outcome_ids must be unique")
        replay_run_ids = [item.replay_run_id for item in self.replay_lineage]
        if len(replay_run_ids) != len(set(replay_run_ids)):
            raise ValueError("replay lineage Run IDs must be unique")
        lineage_request_ids = [
            request_id for item in self.replay_lineage for request_id in item.replay_request_ids
        ]
        lineage_outcome_ids = [item.replay_outcome_id for item in self.replay_lineage]
        if self.replay_lineage and self.replay_request_ids != lineage_request_ids:
            raise ValueError("decision replay request IDs must exactly match replay lineage")
        if self.replay_lineage and self.replay_outcome_ids != lineage_outcome_ids:
            raise ValueError("decision replay outcome IDs must exactly match replay lineage")
        if self.replay_lineage and self.method is not ValidationMethod.RESTRICTED_REPLAY_GATE:
            raise ValueError("replay lineage requires the restricted replay gate")
        if self.method is ValidationMethod.RESTRICTED_REPLAY_GATE:
            if self.supersedes_decision_id is None:
                raise ValueError("restricted replay gate must supersede a source decision")
            if not self.replay_lineage:
                raise ValueError("restricted replay gate requires receipt lineage")
        if self.confirmation_basis is ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY:
            if self.disposition is not FindingDisposition.CONFIRMED:
                raise ValueError(
                    "verified replay confirmation basis requires confirmed disposition"
                )
            if self.method is not ValidationMethod.RESTRICTED_REPLAY_GATE:
                raise ValueError("verified replay confirmation requires the restricted replay gate")
            if self.reason_codes != [ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED]:
                raise ValueError("verified replay confirmation requires its canonical reason")
        elif self.disposition is FindingDisposition.CONFIRMED and self.replay_lineage:
            raise ValueError("replay-backed confirmed decision requires a confirmation basis")
        check_ids = [check.check_id for check in self.checks]
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("validation check IDs must be unique within a decision")
        return self


class VersionedValidationDecisionSet(StrictModel):
    api_version: Literal["pajin.dev/validation/v1alpha1"] = Field(
        default="pajin.dev/validation/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ValidationDecisionSet"] = "ValidationDecisionSet"
    source_run_id: _Identifier = Field(alias="sourceRunId")
    decisions: list[ValidationDecision]


class VersionedConfirmedFindingSet(StrictModel):
    api_version: Literal["pajin.dev/validation/v1alpha1"] = Field(
        default="pajin.dev/validation/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ConfirmedFindingSet"] = "ConfirmedFindingSet"
    source_run_id: _Identifier = Field(alias="sourceRunId")
    confirmation_semantics: Literal["verified-independent-replay"] = Field(
        default="verified-independent-replay",
        alias="confirmationSemantics",
    )
    findings: list[Finding]


class VersionedValidationIndex(StrictModel):
    api_version: Literal["pajin.dev/validation/v1alpha1"] = Field(
        default="pajin.dev/validation/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ValidationProjectionIndex"] = "ValidationProjectionIndex"
    source_run_id: _Identifier = Field(alias="sourceRunId")
    candidate_source_root_digest: str = Field(
        alias="candidateSourceRootDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    confirmation_semantics: Literal["verified-independent-replay"] = Field(
        default="verified-independent-replay",
        alias="confirmationSemantics",
    )
    candidate_findings_path: Literal["candidate-findings.json"] = Field(
        default="candidate-findings.json",
        alias="candidateFindingsPath",
    )
    decisions_path: Literal["validation/v1alpha1/decisions.json"] = Field(
        default="validation/v1alpha1/decisions.json",
        alias="decisionsPath",
    )
    findings_path: Literal["validation/v1alpha1/findings.json"] = Field(
        default="validation/v1alpha1/findings.json",
        alias="findingsPath",
    )
    report_path: Literal["validation/v1alpha1/report.md"] = Field(
        default="validation/v1alpha1/report.md",
        alias="reportPath",
    )
    dispositions: dict[FindingDisposition, list[_Identifier]]
    confirmed_candidate_ids: list[_Identifier] = Field(alias="confirmedCandidateIds")
    generated_at: datetime = Field(alias="generatedAt")

    @field_validator("generated_at")
    @classmethod
    def normalize_generated_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="generated_at")

    @model_validator(mode="after")
    def validate_index_entries(self) -> VersionedValidationIndex:
        if set(self.dispositions) != set(FindingDisposition):
            raise ValueError("versioned validation index must include every disposition")
        all_candidate_ids = [
            candidate_id
            for disposition in FindingDisposition
            for candidate_id in self.dispositions[disposition]
        ]
        if len(all_candidate_ids) != len(set(all_candidate_ids)):
            raise ValueError("versioned validation index Candidate IDs must be unique")
        if self.confirmed_candidate_ids != self.dispositions[FindingDisposition.CONFIRMED]:
            raise ValueError("confirmed Candidate IDs must match the confirmed disposition")
        return self


class FindingValidationSet(StrictModel):
    candidates: list[CandidateFinding]
    decisions: list[ValidationDecision]
    confirmed_findings: list[Finding]

    @model_validator(mode="after")
    def validate_integrity(self) -> FindingValidationSet:
        candidate_ids = [candidate.candidate_id for candidate in self.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate IDs must be unique")

        decision_ids = [decision.decision_id for decision in self.decisions]
        if len(decision_ids) != len(set(decision_ids)):
            raise ValueError("decision IDs must be unique")

        known_candidates = set(candidate_ids)
        for decision in self.decisions:
            if decision.candidate_id not in known_candidates:
                raise ValueError(f"decision references unknown candidate: {decision.candidate_id}")

        decision_counts = Counter(decision.candidate_id for decision in self.decisions)
        for candidate_id in candidate_ids:
            if decision_counts[candidate_id] != 1:
                raise ValueError(f"candidate must have exactly one decision: {candidate_id}")

        decisions_by_candidate = {decision.candidate_id: decision for decision in self.decisions}
        expected = [
            candidate.claim.model_copy(update={"validated": True})
            for candidate in self.candidates
            if decisions_by_candidate[candidate.candidate_id].disposition
            is FindingDisposition.CONFIRMED
        ]
        if self.confirmed_findings != expected:
            raise ValueError(
                "confirmed_findings must exactly match validated projections of claims "
                "with confirmed decisions"
            )
        return self


def _normalize_utc(value: datetime, *, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset or Z")
    return value.astimezone(UTC)
