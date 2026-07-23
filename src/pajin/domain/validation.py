"""Typed contracts for preserving and classifying finding validation outcomes."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
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


class AtomicClaimType(StrEnum):
    VALIDITY = "validity"
    IMPACT = "impact"
    SEVERITY = "severity"


class AtomicClaimVerdict(StrEnum):
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    INSUFFICIENT = "insufficient"


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
    INDEPENDENT_EXECUTION_ATTESTATION_MISSING = "independent-execution-attestation-missing"
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


class AtomicClaim(StrictModel):
    """Trusted deterministic projection of one independently reviewable Candidate claim."""

    api_version: Literal["pajin.dev/atomic-claim/v1alpha1"] = Field(
        default="pajin.dev/atomic-claim/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["AtomicClaim"] = "AtomicClaim"
    claim_id: _Identifier = Field(alias="claimId")
    candidate_id: _Identifier = Field(alias="candidateId")
    candidate_claim_digest: str = Field(
        alias="candidateClaimDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    claim_type: AtomicClaimType = Field(alias="claimType")
    statement: str = Field(min_length=1, max_length=20_000)
    evidence: list[_EvidenceReference] = Field(max_length=1_000)
    claim_digest: str = Field(alias="claimDigest", pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def require_canonical_identity(self) -> AtomicClaim:
        if len(self.evidence) != len(set(self.evidence)):
            raise ValueError("Atomic Claim evidence references must be unique")
        if self.claim_id != _atomic_claim_id(self.candidate_id, self.claim_type):
            raise ValueError("Atomic Claim ID does not match its Candidate and type")
        if self.claim_digest != _atomic_claim_digest(
            candidate_id=self.candidate_id,
            candidate_claim_digest=self.candidate_claim_digest,
            claim_type=self.claim_type,
            statement=self.statement,
            evidence=self.evidence,
        ):
            raise ValueError("Atomic Claim digest does not match its canonical content")
        return self


class AtomicClaimDecision(StrictModel):
    """Validator-owned verdict bound to one exact trusted Atomic Claim."""

    api_version: Literal["pajin.dev/atomic-claim-decision/v1alpha1"] = Field(
        default="pajin.dev/atomic-claim-decision/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["AtomicClaimDecision"] = "AtomicClaimDecision"
    decision_id: _Identifier = Field(alias="decisionId")
    claim_id: _Identifier = Field(alias="claimId")
    claim_digest: str = Field(alias="claimDigest", pattern=r"^[a-f0-9]{64}$")
    candidate_id: _Identifier = Field(alias="candidateId")
    candidate_claim_digest: str = Field(
        alias="candidateClaimDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    verdict: AtomicClaimVerdict
    rationale: str = Field(min_length=1, max_length=5_000)
    supporting_evidence: list[_EvidenceReference] = Field(
        default_factory=list,
        alias="supportingEvidence",
        max_length=1_000,
    )
    contradicting_evidence: list[_EvidenceReference] = Field(
        default_factory=list,
        alias="contradictingEvidence",
        max_length=1_000,
    )

    @model_validator(mode="after")
    def require_canonical_decision(self) -> AtomicClaimDecision:
        if len(self.supporting_evidence) != len(set(self.supporting_evidence)):
            raise ValueError("Atomic Claim supporting evidence must be unique")
        if len(self.contradicting_evidence) != len(set(self.contradicting_evidence)):
            raise ValueError("Atomic Claim contradicting evidence must be unique")
        if set(self.supporting_evidence) & set(self.contradicting_evidence):
            raise ValueError("Atomic Claim evidence cannot both support and contradict")
        if self.verdict is AtomicClaimVerdict.SUPPORTS:
            if not self.supporting_evidence or self.contradicting_evidence:
                raise ValueError(
                    "supporting Atomic Claim decision requires only supporting evidence"
                )
        elif self.verdict is AtomicClaimVerdict.CONTRADICTS:
            if not self.contradicting_evidence or self.supporting_evidence:
                raise ValueError(
                    "contradicting Atomic Claim decision requires only contradicting evidence"
                )
        elif self.supporting_evidence or self.contradicting_evidence:
            raise ValueError("insufficient Atomic Claim decision cannot classify evidence")
        if self.decision_id != _atomic_claim_decision_id(
            claim_id=self.claim_id,
            claim_digest=self.claim_digest,
            candidate_id=self.candidate_id,
            candidate_claim_digest=self.candidate_claim_digest,
            verdict=self.verdict,
            rationale=self.rationale,
            supporting_evidence=self.supporting_evidence,
            contradicting_evidence=self.contradicting_evidence,
        ):
            raise ValueError("Atomic Claim decision ID does not match its canonical content")
        return self


class CandidateAssessment(StrictModel):
    """Validator-owned semantic decision bound to one exact trusted Candidate claim."""

    candidate_id: _Identifier
    claim_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    supports_claim: bool
    reason_code: ValidationReasonCode
    rationale: str = Field(min_length=1, max_length=5_000)
    supporting_evidence: list[_EvidenceReference] = Field(default_factory=list, max_length=1_000)

    @model_validator(mode="after")
    def require_unique_evidence(self) -> CandidateAssessment:
        if len(self.supporting_evidence) != len(set(self.supporting_evidence)):
            raise ValueError("Candidate assessment evidence references must be unique")
        if self.supports_claim and not self.supporting_evidence:
            raise ValueError("supporting Candidate assessment requires evidence")
        if not self.supports_claim and self.supporting_evidence:
            raise ValueError("unsupported Candidate assessment cannot cite supporting evidence")
        if self.supports_claim and self.reason_code is not ValidationReasonCode.VALIDATOR_CONFIRMED:
            raise ValueError("supporting Candidate assessment requires validator-confirmed")
        if not self.supports_claim and self.reason_code not in {
            ValidationReasonCode.VALIDATOR_DISAGREED,
            ValidationReasonCode.VALIDATOR_OMITTED,
        }:
            raise ValueError(
                "unsupported Candidate assessment requires validator-disagreed or omitted"
            )
        return self


class ValidatorOutputArtifact(StrictModel):
    """One validator phase's exact output, sealed with its source Run.

    The deterministic gate consumes this output in memory.  Durable consumers must
    reload the same typed bytes instead of recreating semantic approval from the
    Candidate they are supposed to assess.
    """

    api_version: Literal["pajin.dev/validator-output/v1alpha1"] = Field(
        default="pajin.dev/validator-output/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ValidatorOutput"] = "ValidatorOutput"
    source_run_id: _Identifier = Field(alias="sourceRunId")
    validator_id: _Identifier = Field(alias="validatorId")
    validation_task_id: _Identifier = Field(alias="validationTaskId")
    findings: list[Finding] = Field(default_factory=list, max_length=1_000)
    assessments: list[CandidateAssessment] = Field(default_factory=list, max_length=1_000)
    atomic_claims: list[AtomicClaim] = Field(
        default_factory=list,
        alias="atomicClaims",
        max_length=3_000,
    )
    claim_decisions: list[AtomicClaimDecision] = Field(
        default_factory=list,
        alias="claimDecisions",
        max_length=3_000,
    )

    @model_validator(mode="after")
    def require_unique_output_identities(self) -> ValidatorOutputArtifact:
        finding_ids = [finding.finding_id for finding in self.findings]
        if len(finding_ids) != len(set(finding_ids)):
            raise ValueError("Validator output Finding IDs must be unique")
        candidate_ids = [assessment.candidate_id for assessment in self.assessments]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("Validator output Candidate assessment IDs must be unique")
        _validate_atomic_output_contract(
            assessments=self.assessments,
            claims=self.atomic_claims,
            decisions=self.claim_decisions,
        )
        if (
            any(assessment.supports_claim for assessment in self.assessments)
            and not any(finding.validated for finding in self.findings)
            and not self.claim_decisions
        ):
            raise ValueError("supporting Validator output requires a validated Finding")
        return self


def candidate_claim_digest(candidate: CandidateFinding) -> str:
    """Return the canonical identity a semantic assessment must explicitly authorize."""

    claim = candidate.claim.model_dump(mode="json", by_alias=True)
    claim["validated"] = False
    canonical = json.dumps(
        claim,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return sha256(canonical).hexdigest()


def candidate_atomic_claims(candidate: CandidateFinding) -> list[AtomicClaim]:
    """Split one Candidate into deterministic validity, impact, and severity claims."""

    digest = candidate_claim_digest(candidate)
    validity = {
        "affectedComponent": candidate.claim.affected_component,
        "reproduction": candidate.claim.reproduction,
        "rootCause": candidate.claim.root_cause,
        "summary": candidate.claim.summary,
        "target": candidate.claim.target,
        "threatClass": candidate.claim.threat_class,
        "title": candidate.claim.title,
    }
    specifications: list[tuple[AtomicClaimType, str]] = [
        (
            AtomicClaimType.VALIDITY,
            json.dumps(
                validity,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ),
        )
    ]
    if candidate.claim.impact is not None:
        specifications.append((AtomicClaimType.IMPACT, candidate.claim.impact))
    specifications.append((AtomicClaimType.SEVERITY, candidate.claim.severity.value))
    return [
        _build_atomic_claim(
            candidate_id=candidate.candidate_id,
            candidate_claim_digest=digest,
            claim_type=claim_type,
            statement=statement,
            evidence=candidate.claim.evidence,
        )
        for claim_type, statement in specifications
    ]


def build_atomic_claim_decision(
    claim: AtomicClaim,
    *,
    verdict: AtomicClaimVerdict,
    rationale: str,
    supporting_evidence: Sequence[str] = (),
    contradicting_evidence: Sequence[str] = (),
) -> AtomicClaimDecision:
    """Bind a semantic verdict to trusted Claim identity in canonical code."""

    supporting = list(supporting_evidence)
    contradicting = list(contradicting_evidence)
    decision_id = _atomic_claim_decision_id(
        claim_id=claim.claim_id,
        claim_digest=claim.claim_digest,
        candidate_id=claim.candidate_id,
        candidate_claim_digest=claim.candidate_claim_digest,
        verdict=verdict,
        rationale=rationale,
        supporting_evidence=supporting,
        contradicting_evidence=contradicting,
    )
    return AtomicClaimDecision(
        decisionId=decision_id,
        claimId=claim.claim_id,
        claimDigest=claim.claim_digest,
        candidateId=claim.candidate_id,
        candidateClaimDigest=claim.candidate_claim_digest,
        verdict=verdict,
        rationale=rationale,
        supportingEvidence=supporting,
        contradictingEvidence=contradicting,
    )


def validate_candidate_atomic_refinement(
    candidates: Sequence[CandidateFinding],
    claims: Sequence[AtomicClaim],
    decisions: Sequence[AtomicClaimDecision],
    *,
    required: bool,
) -> None:
    """Verify an exact deterministic Claim set and one bound verdict per Claim."""

    if not claims and not decisions and not required:
        return
    expected = [claim for candidate in candidates for claim in candidate_atomic_claims(candidate)]
    if list(claims) != expected:
        raise ValueError("Atomic Claims differ from the trusted Candidate decomposition")
    _validate_atomic_claim_decisions(claims, decisions)


def _build_atomic_claim(
    *,
    candidate_id: str,
    candidate_claim_digest: str,
    claim_type: AtomicClaimType,
    statement: str,
    evidence: Sequence[str],
) -> AtomicClaim:
    references = list(evidence)
    return AtomicClaim(
        claimId=_atomic_claim_id(candidate_id, claim_type),
        candidateId=candidate_id,
        candidateClaimDigest=candidate_claim_digest,
        claimType=claim_type,
        statement=statement,
        evidence=references,
        claimDigest=_atomic_claim_digest(
            candidate_id=candidate_id,
            candidate_claim_digest=candidate_claim_digest,
            claim_type=claim_type,
            statement=statement,
            evidence=references,
        ),
    )


def _atomic_claim_id(candidate_id: str, claim_type: AtomicClaimType) -> str:
    payload = f"{candidate_id}\0{claim_type.value}".encode()
    return f"claim_{sha256(payload).hexdigest()}"


def _atomic_claim_digest(
    *,
    candidate_id: str,
    candidate_claim_digest: str,
    claim_type: AtomicClaimType,
    statement: str,
    evidence: Sequence[str],
) -> str:
    return _canonical_digest(
        {
            "candidateId": candidate_id,
            "candidateClaimDigest": candidate_claim_digest,
            "claimType": claim_type.value,
            "statement": statement,
            "evidence": list(evidence),
        }
    )


def _atomic_claim_decision_id(
    *,
    claim_id: str,
    claim_digest: str,
    candidate_id: str,
    candidate_claim_digest: str,
    verdict: AtomicClaimVerdict,
    rationale: str,
    supporting_evidence: Sequence[str],
    contradicting_evidence: Sequence[str],
) -> str:
    digest = _canonical_digest(
        {
            "claimId": claim_id,
            "claimDigest": claim_digest,
            "candidateId": candidate_id,
            "candidateClaimDigest": candidate_claim_digest,
            "verdict": verdict.value,
            "rationale": rationale,
            "supportingEvidence": list(supporting_evidence),
            "contradictingEvidence": list(contradicting_evidence),
        }
    )
    return f"claim_decision_{digest}"


def _canonical_digest(payload: dict[str, object]) -> str:
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return sha256(canonical).hexdigest()


def _validate_atomic_output_contract(
    *,
    assessments: Sequence[CandidateAssessment],
    claims: Sequence[AtomicClaim],
    decisions: Sequence[AtomicClaimDecision],
) -> None:
    if not claims and not decisions:
        return
    _validate_atomic_claim_decisions(claims, decisions)
    assessment_by_candidate = {assessment.candidate_id: assessment for assessment in assessments}
    if {claim.candidate_id for claim in claims} != set(assessment_by_candidate):
        raise ValueError("Atomic Claims must cover every Candidate assessment exactly")
    validity_by_candidate = {
        claim.candidate_id: (claim, decision)
        for claim, decision in zip(claims, decisions, strict=True)
        if claim.claim_type is AtomicClaimType.VALIDITY
    }
    if set(validity_by_candidate) != set(assessment_by_candidate):
        raise ValueError("each Candidate assessment requires one validity Claim decision")
    for candidate_id, assessment in assessment_by_candidate.items():
        _claim, decision = validity_by_candidate[candidate_id]
        expected_support = decision.verdict is AtomicClaimVerdict.SUPPORTS
        expected_reason = (
            ValidationReasonCode.VALIDATOR_CONFIRMED
            if expected_support
            else (
                ValidationReasonCode.VALIDATOR_DISAGREED
                if decision.verdict is AtomicClaimVerdict.CONTRADICTS
                else ValidationReasonCode.VALIDATOR_OMITTED
            )
        )
        if (
            assessment.claim_digest != decision.candidate_claim_digest
            or assessment.supports_claim is not expected_support
            or assessment.reason_code is not expected_reason
            or assessment.rationale != decision.rationale
            or assessment.supporting_evidence != decision.supporting_evidence
        ):
            raise ValueError("Candidate assessment differs from its validity Claim decision")


def _validate_atomic_claim_decisions(
    claims: Sequence[AtomicClaim],
    decisions: Sequence[AtomicClaimDecision],
) -> None:
    claim_ids = [claim.claim_id for claim in claims]
    if len(claim_ids) != len(set(claim_ids)):
        raise ValueError("Atomic Claim IDs must be unique")
    decision_ids = [decision.decision_id for decision in decisions]
    if len(decision_ids) != len(set(decision_ids)):
        raise ValueError("Atomic Claim decision IDs must be unique")
    if [decision.claim_id for decision in decisions] != claim_ids:
        raise ValueError("Atomic Claim decisions must follow the exact Claim order")
    for claim, decision in zip(claims, decisions, strict=True):
        if (
            decision.claim_id != claim.claim_id
            or decision.claim_digest != claim.claim_digest
            or decision.candidate_id != claim.candidate_id
            or decision.candidate_claim_digest != claim.candidate_claim_digest
        ):
            raise ValueError("Atomic Claim decision identity does not match its Claim")
        cited = set(decision.supporting_evidence) | set(decision.contradicting_evidence)
        if not cited <= set(claim.evidence):
            raise ValueError("Atomic Claim decision cites evidence outside its Claim")


def validator_finding_matches_candidate_claim(
    candidate_claim: Finding,
    finding: Finding,
) -> bool:
    """Compare every claim field while normalizing only opaque identity and review state.

    A legacy Validator does not receive the trusted Candidate and therefore creates its
    own ``finding_id``.  The Candidate-aware adapter owns the one-to-one identity binding,
    while every semantic field, including evidence order, must be identical.
    """

    candidate_payload = candidate_claim.model_dump(mode="json")
    validator_claim = finding.model_dump(mode="json")
    for normalized_field in ("finding_id", "validated"):
        candidate_payload.pop(normalized_field)
        validator_claim.pop(normalized_field)
    return candidate_payload == validator_claim


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
        _validate_decision_unique_collections(self)
        _validate_decision_replay_lineage(self)
        _validate_decision_replay_gate(self)
        _validate_decision_confirmation(self)
        _require_unique(
            [check.check_id for check in self.checks],
            "validation check IDs must be unique within a decision",
        )
        return self


def _require_unique(values: Sequence[object], message: str) -> None:
    if len(values) != len(set(values)):
        raise ValueError(message)


def _validate_decision_unique_collections(decision: ValidationDecision) -> None:
    for values, message in (
        (decision.reason_codes, "reason_codes must be unique"),
        (decision.supporting_evidence, "supporting_evidence must be unique"),
        (decision.contradicting_evidence, "contradicting_evidence must be unique"),
        (decision.replay_request_ids, "replay_request_ids must be unique"),
        (decision.replay_outcome_ids, "replay_outcome_ids must be unique"),
    ):
        _require_unique(list(values), message)


def _validate_decision_replay_lineage(decision: ValidationDecision) -> None:
    replay_run_ids = [item.replay_run_id for item in decision.replay_lineage]
    _require_unique(replay_run_ids, "replay lineage Run IDs must be unique")
    if not decision.replay_lineage:
        return
    lineage_request_ids = [
        request_id for item in decision.replay_lineage for request_id in item.replay_request_ids
    ]
    lineage_outcome_ids = [item.replay_outcome_id for item in decision.replay_lineage]
    if decision.replay_request_ids != lineage_request_ids:
        raise ValueError("decision replay request IDs must exactly match replay lineage")
    if decision.replay_outcome_ids != lineage_outcome_ids:
        raise ValueError("decision replay outcome IDs must exactly match replay lineage")
    if decision.method is not ValidationMethod.RESTRICTED_REPLAY_GATE:
        raise ValueError("replay lineage requires the restricted replay gate")


def _validate_decision_replay_gate(decision: ValidationDecision) -> None:
    if decision.method is not ValidationMethod.RESTRICTED_REPLAY_GATE:
        return
    if decision.supersedes_decision_id is None:
        raise ValueError("restricted replay gate must supersede a source decision")
    if not decision.replay_lineage:
        raise ValueError("restricted replay gate requires receipt lineage")


def _validate_decision_confirmation(decision: ValidationDecision) -> None:
    if decision.confirmation_basis is ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY:
        if decision.disposition is not FindingDisposition.CONFIRMED:
            raise ValueError("verified replay confirmation basis requires confirmed disposition")
        if decision.method is not ValidationMethod.RESTRICTED_REPLAY_GATE:
            raise ValueError("verified replay confirmation requires the restricted replay gate")
        if decision.reason_codes != [ValidationReasonCode.INDEPENDENT_REPRODUCTION_CONFIRMED]:
            raise ValueError("verified replay confirmation requires its canonical reason")
    elif decision.disposition is FindingDisposition.CONFIRMED and decision.replay_lineage:
        raise ValueError("replay-backed confirmed decision requires a confirmation basis")


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
    confirmation_semantics: Literal["verified-replay-evidence", "verified-independent-replay"] = (
        Field(
            default="verified-replay-evidence",
            alias="confirmationSemantics",
        )
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
    confirmation_semantics: Literal["verified-replay-evidence", "verified-independent-replay"] = (
        Field(
            default="verified-replay-evidence",
            alias="confirmationSemantics",
        )
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
