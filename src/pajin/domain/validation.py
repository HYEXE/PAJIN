"""Typed contracts for preserving and classifying finding validation outcomes."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated

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


class ValidationReasonCode(StrEnum):
    VALIDATOR_CONFIRMED = "validator-confirmed"
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


class ValidationDecision(StrictModel):
    decision_id: _Identifier
    candidate_id: _Identifier
    validator_id: _Identifier
    method: ValidationMethod
    disposition: FindingDisposition
    reason_codes: list[ValidationReasonCode] = Field(min_length=1, max_length=20)
    decision_summary: str = Field(min_length=1, max_length=5_000)
    supporting_evidence: list[_EvidenceReference] = Field(max_length=1_000)
    contradicting_evidence: list[_EvidenceReference] = Field(max_length=1_000)
    replay_request_ids: list[_Identifier] = Field(max_length=1_000)
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
        check_ids = [check.check_id for check in self.checks]
        if len(check_ids) != len(set(check_ids)):
            raise ValueError("validation check IDs must be unique within a decision")
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
