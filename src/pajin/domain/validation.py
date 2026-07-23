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

from pajin.domain.models import Finding, FindingSeverity, StrictModel

_Identifier = Annotated[str, Field(min_length=1, max_length=200)]
_EvidenceReference = Annotated[str, Field(min_length=1, max_length=2_000)]


class FindingDisposition(StrEnum):
    CONFIRMED = "confirmed"
    NEEDS_REVIEW = "needs-review"
    INCONCLUSIVE = "inconclusive"
    REJECTED_OBJECTIVE = "rejected-objective"


class PublicFindingState(StrEnum):
    """Consumer-facing status kept separate from the internal gate disposition."""

    CONFIRMED = "confirmed"
    PARTIALLY_CONFIRMED = "partially-confirmed"
    NOT_REPRODUCED = "not-reproduced"
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


class ClaimReviewOutcome(StrEnum):
    CORROBORATED = "corroborated"
    CONTESTED = "contested"
    INCONCLUSIVE = "inconclusive"


class ClaimReplayStatus(StrEnum):
    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not-reproduced"
    INCONCLUSIVE = "inconclusive"
    NOT_ELIGIBLE = "not-eligible"


class SeverityDerivationStatus(StrEnum):
    DERIVED = "derived"
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


class BlindEvidencePacket(StrictModel):
    """Minimal Claim evidence view that excludes Candidate and prior-review metadata."""

    api_version: Literal["pajin.dev/blind-evidence-packet/v1alpha1"] = Field(
        default="pajin.dev/blind-evidence-packet/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["BlindEvidencePacket"] = "BlindEvidencePacket"
    packet_id: _Identifier = Field(alias="packetId")
    packet_digest: str = Field(alias="packetDigest", pattern=r"^[a-f0-9]{64}$")
    claim_id: _Identifier = Field(alias="claimId")
    claim_digest: str = Field(alias="claimDigest", pattern=r"^[a-f0-9]{64}$")
    claim_type: AtomicClaimType = Field(alias="claimType")
    statement: str = Field(min_length=1, max_length=20_000)
    evidence: list[_EvidenceReference] = Field(max_length=1_000)

    @model_validator(mode="after")
    def require_canonical_packet(self) -> BlindEvidencePacket:
        if len(self.evidence) != len(set(self.evidence)):
            raise ValueError("Blind Evidence Packet references must be unique")
        expected_digest = _blind_evidence_packet_digest(
            claim_id=self.claim_id,
            claim_digest=self.claim_digest,
            claim_type=self.claim_type,
            statement=self.statement,
            evidence=self.evidence,
        )
        if self.packet_digest != expected_digest:
            raise ValueError("Blind Evidence Packet digest does not match its canonical content")
        if self.packet_id != _blind_evidence_packet_id(
            claim_id=self.claim_id,
            claim_digest=self.claim_digest,
            packet_digest=self.packet_digest,
        ):
            raise ValueError("Blind Evidence Packet ID does not match its Claim")
        return self


class BlindEvidenceDecision(StrictModel):
    """Independent role decision over one exact Blind Evidence Packet."""

    api_version: Literal["pajin.dev/blind-evidence-decision/v1alpha1"] = Field(
        default="pajin.dev/blind-evidence-decision/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["BlindEvidenceDecision"] = "BlindEvidenceDecision"
    decision_id: _Identifier = Field(alias="decisionId")
    packet_id: _Identifier = Field(alias="packetId")
    packet_digest: str = Field(alias="packetDigest", pattern=r"^[a-f0-9]{64}$")
    claim_id: _Identifier = Field(alias="claimId")
    claim_digest: str = Field(alias="claimDigest", pattern=r"^[a-f0-9]{64}$")
    reviewer_id: _Identifier = Field(alias="reviewerId")
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
    def require_canonical_decision(self) -> BlindEvidenceDecision:
        if len(self.supporting_evidence) != len(set(self.supporting_evidence)):
            raise ValueError("Blind review supporting evidence must be unique")
        if len(self.contradicting_evidence) != len(set(self.contradicting_evidence)):
            raise ValueError("Blind review contradicting evidence must be unique")
        if set(self.supporting_evidence) & set(self.contradicting_evidence):
            raise ValueError("Blind review evidence cannot both support and contradict")
        if self.verdict is AtomicClaimVerdict.SUPPORTS:
            if not self.supporting_evidence or self.contradicting_evidence:
                raise ValueError("supporting Blind review requires only supporting evidence")
        elif self.verdict is AtomicClaimVerdict.CONTRADICTS:
            if not self.contradicting_evidence or self.supporting_evidence:
                raise ValueError("contradicting Blind review requires only contradicting evidence")
        elif self.supporting_evidence or self.contradicting_evidence:
            raise ValueError("insufficient Blind review cannot classify evidence")
        if self.decision_id != _blind_evidence_decision_id(
            packet_id=self.packet_id,
            packet_digest=self.packet_digest,
            claim_id=self.claim_id,
            claim_digest=self.claim_digest,
            reviewer_id=self.reviewer_id,
            verdict=self.verdict,
            rationale=self.rationale,
            supporting_evidence=self.supporting_evidence,
            contradicting_evidence=self.contradicting_evidence,
        ):
            raise ValueError("Blind Evidence Decision ID does not match its canonical content")
        return self


class ClaimReviewReconciliation(StrictModel):
    """Deterministic comparison that cannot change Candidate disposition."""

    api_version: Literal["pajin.dev/claim-review-reconciliation/v1alpha1"] = Field(
        default="pajin.dev/claim-review-reconciliation/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ClaimReviewReconciliation"] = "ClaimReviewReconciliation"
    reconciliation_id: _Identifier = Field(alias="reconciliationId")
    claim_id: _Identifier = Field(alias="claimId")
    claim_digest: str = Field(alias="claimDigest", pattern=r"^[a-f0-9]{64}$")
    primary_decision_id: _Identifier = Field(alias="primaryDecisionId")
    blind_decision_id: _Identifier = Field(alias="blindDecisionId")
    outcome: ClaimReviewOutcome

    @model_validator(mode="after")
    def require_canonical_reconciliation(self) -> ClaimReviewReconciliation:
        if self.reconciliation_id != _claim_review_reconciliation_id(
            claim_id=self.claim_id,
            claim_digest=self.claim_digest,
            primary_decision_id=self.primary_decision_id,
            blind_decision_id=self.blind_decision_id,
            outcome=self.outcome,
        ):
            raise ValueError("Claim review reconciliation ID is not canonical")
        return self


class ProviderModelReviewBinding(StrictModel):
    """Exact diverse Provider/model identities used by primary and review calls."""

    api_version: Literal["pajin.dev/provider-model-review-binding/v1alpha1"] = Field(
        default="pajin.dev/provider-model-review-binding/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ProviderModelReviewBinding"] = "ProviderModelReviewBinding"
    binding_id: _Identifier = Field(alias="bindingId")
    primary_provider_id: _Identifier = Field(alias="primaryProviderId")
    primary_endpoint: str = Field(alias="primaryEndpoint", min_length=1, max_length=2_000)
    primary_model: _Identifier = Field(alias="primaryModel")
    reviewer_id: _Identifier = Field(alias="reviewerId")
    review_provider_id: _Identifier = Field(alias="reviewProviderId")
    review_endpoint: str = Field(alias="reviewEndpoint", min_length=1, max_length=2_000)
    review_model: _Identifier = Field(alias="reviewModel")
    provider_distinct: Literal[True] = Field(default=True, alias="providerDistinct")
    model_distinct: Literal[True] = Field(default=True, alias="modelDistinct")

    @model_validator(mode="after")
    def require_canonical_diverse_binding(self) -> ProviderModelReviewBinding:
        if (
            self.primary_provider_id == self.review_provider_id
            or self.primary_endpoint == self.review_endpoint
        ):
            raise ValueError("review Provider ID and endpoint must differ from the primary")
        if self.primary_model == self.review_model:
            raise ValueError("review model must differ from the primary model")
        if self.binding_id != _provider_model_review_binding_id(
            primary_provider_id=self.primary_provider_id,
            primary_endpoint=self.primary_endpoint,
            primary_model=self.primary_model,
            reviewer_id=self.reviewer_id,
            review_provider_id=self.review_provider_id,
            review_endpoint=self.review_endpoint,
            review_model=self.review_model,
        ):
            raise ValueError("Provider/model review binding ID is not canonical")
        return self


class SeverityDerivationPacket(StrictModel):
    """Minimal severity input that excludes the Candidate's proposed severity."""

    api_version: Literal["pajin.dev/severity-derivation-packet/v1alpha1"] = Field(
        default="pajin.dev/severity-derivation-packet/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["SeverityDerivationPacket"] = "SeverityDerivationPacket"
    packet_id: _Identifier = Field(alias="packetId")
    packet_digest: str = Field(alias="packetDigest", pattern=r"^[a-f0-9]{64}$")
    severity_claim_id: _Identifier = Field(alias="severityClaimId")
    context_packets: list[BlindEvidencePacket] = Field(
        alias="contextPackets",
        min_length=1,
        max_length=2,
    )

    @model_validator(mode="after")
    def require_canonical_packet(self) -> SeverityDerivationPacket:
        claim_types = [packet.claim_type for packet in self.context_packets]
        if claim_types.count(AtomicClaimType.VALIDITY) != 1:
            raise ValueError("severity derivation requires exactly one validity context")
        if claim_types.count(AtomicClaimType.IMPACT) > 1:
            raise ValueError("severity derivation accepts at most one impact context")
        packet_ids = [packet.packet_id for packet in self.context_packets]
        if len(packet_ids) != len(set(packet_ids)):
            raise ValueError("severity derivation context Packet IDs must be unique")
        expected_digest = _severity_derivation_packet_digest(
            severity_claim_id=self.severity_claim_id,
            context_packets=self.context_packets,
        )
        if self.packet_digest != expected_digest:
            raise ValueError("severity derivation Packet digest is not canonical")
        if self.packet_id != _severity_derivation_packet_id(
            severity_claim_id=self.severity_claim_id,
            packet_digest=self.packet_digest,
        ):
            raise ValueError("severity derivation Packet ID is not canonical")
        return self


class IndependentSeverityDecision(StrictModel):
    """One diverse review model's information-only severity derivation."""

    api_version: Literal["pajin.dev/independent-severity-decision/v1alpha1"] = Field(
        default="pajin.dev/independent-severity-decision/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["IndependentSeverityDecision"] = "IndependentSeverityDecision"
    decision_id: _Identifier = Field(alias="decisionId")
    packet_id: _Identifier = Field(alias="packetId")
    packet_digest: str = Field(alias="packetDigest", pattern=r"^[a-f0-9]{64}$")
    reviewer_id: _Identifier = Field(alias="reviewerId")
    review_binding_id: _Identifier = Field(alias="reviewBindingId")
    status: SeverityDerivationStatus
    severity: FindingSeverity | None = None
    rationale: str = Field(min_length=1, max_length=5_000)
    evidence: list[_EvidenceReference] = Field(default_factory=list, max_length=1_000)
    informational_only: Literal[True] = Field(default=True, alias="informationalOnly")
    confirmation_eligible: Literal[False] = Field(
        default=False,
        alias="confirmationEligible",
    )
    mutates_candidate: Literal[False] = Field(default=False, alias="mutatesCandidate")

    @model_validator(mode="after")
    def require_canonical_decision(self) -> IndependentSeverityDecision:
        if len(self.evidence) != len(set(self.evidence)):
            raise ValueError("independent severity evidence references must be unique")
        if self.status is SeverityDerivationStatus.DERIVED:
            if self.severity is None or not self.evidence:
                raise ValueError("derived severity requires a severity and cited evidence")
        elif self.severity is not None or self.evidence:
            raise ValueError("insufficient severity derivation cannot classify evidence")
        if self.decision_id != _independent_severity_decision_id(
            packet_id=self.packet_id,
            packet_digest=self.packet_digest,
            reviewer_id=self.reviewer_id,
            review_binding_id=self.review_binding_id,
            status=self.status,
            severity=self.severity,
            rationale=self.rationale,
            evidence=self.evidence,
        ):
            raise ValueError("independent severity Decision ID is not canonical")
        return self


class SeverityClaimReconciliation(StrictModel):
    """Compare an independent derivation with the proposed severity without mutation."""

    api_version: Literal["pajin.dev/severity-claim-reconciliation/v1alpha1"] = Field(
        default="pajin.dev/severity-claim-reconciliation/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["SeverityClaimReconciliation"] = "SeverityClaimReconciliation"
    reconciliation_id: _Identifier = Field(alias="reconciliationId")
    severity_claim_id: _Identifier = Field(alias="severityClaimId")
    severity_claim_digest: str = Field(
        alias="severityClaimDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    derivation_decision_id: _Identifier = Field(alias="derivationDecisionId")
    outcome: ClaimReviewOutcome
    informational_only: Literal[True] = Field(default=True, alias="informationalOnly")
    confirmation_eligible: Literal[False] = Field(
        default=False,
        alias="confirmationEligible",
    )
    mutates_candidate: Literal[False] = Field(default=False, alias="mutatesCandidate")

    @model_validator(mode="after")
    def require_canonical_reconciliation(self) -> SeverityClaimReconciliation:
        if self.reconciliation_id != _severity_claim_reconciliation_id(
            severity_claim_id=self.severity_claim_id,
            severity_claim_digest=self.severity_claim_digest,
            derivation_decision_id=self.derivation_decision_id,
            outcome=self.outcome,
        ):
            raise ValueError("severity Claim reconciliation ID is not canonical")
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

    api_version: Literal[
        "pajin.dev/validator-output/v1alpha1",
        "pajin.dev/validator-output/v1alpha2",
    ] = Field(
        default="pajin.dev/validator-output/v1alpha2",
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
    blind_evidence_packets: list[BlindEvidencePacket] = Field(
        default_factory=list,
        alias="blindEvidencePackets",
        max_length=3_000,
    )
    blind_evidence_decisions: list[BlindEvidenceDecision] = Field(
        default_factory=list,
        alias="blindEvidenceDecisions",
        max_length=3_000,
    )
    claim_review_reconciliations: list[ClaimReviewReconciliation] = Field(
        default_factory=list,
        alias="claimReviewReconciliations",
        max_length=3_000,
    )
    provider_model_review_binding: ProviderModelReviewBinding | None = Field(
        default=None,
        alias="providerModelReviewBinding",
    )
    severity_derivation_packets: list[SeverityDerivationPacket] = Field(
        default_factory=list,
        alias="severityDerivationPackets",
        max_length=1_000,
    )
    independent_severity_decisions: list[IndependentSeverityDecision] = Field(
        default_factory=list,
        alias="independentSeverityDecisions",
        max_length=1_000,
    )
    severity_claim_reconciliations: list[SeverityClaimReconciliation] = Field(
        default_factory=list,
        alias="severityClaimReconciliations",
        max_length=1_000,
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
        validate_candidate_blind_refinement(
            self.atomic_claims,
            self.claim_decisions,
            self.blind_evidence_packets,
            self.blind_evidence_decisions,
            self.claim_review_reconciliations,
            required=bool(
                self.blind_evidence_packets
                or self.blind_evidence_decisions
                or self.claim_review_reconciliations
            ),
        )
        if any(
            decision.reviewer_id == self.validator_id for decision in self.blind_evidence_decisions
        ):
            raise ValueError("Blind Evidence reviewer must differ from the primary Validator")
        validate_independent_severity_refinement(
            self.atomic_claims,
            self.severity_derivation_packets,
            self.independent_severity_decisions,
            self.severity_claim_reconciliations,
            self.provider_model_review_binding,
            required=bool(
                self.provider_model_review_binding
                or self.severity_derivation_packets
                or self.independent_severity_decisions
                or self.severity_claim_reconciliations
            ),
        )
        if self.provider_model_review_binding is not None:
            expected_reviewer = self.provider_model_review_binding.reviewer_id
            if any(
                decision.reviewer_id != expected_reviewer
                for decision in self.blind_evidence_decisions
            ):
                raise ValueError("Blind reviewer differs from the Provider/model review binding")
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


def blind_evidence_packets(claims: Sequence[AtomicClaim]) -> list[BlindEvidencePacket]:
    """Project validity and impact without Candidate, severity, or prior decisions."""

    packets: list[BlindEvidencePacket] = []
    for claim in claims:
        if claim.claim_type is AtomicClaimType.SEVERITY:
            continue
        packet_digest = _blind_evidence_packet_digest(
            claim_id=claim.claim_id,
            claim_digest=claim.claim_digest,
            claim_type=claim.claim_type,
            statement=claim.statement,
            evidence=claim.evidence,
        )
        packets.append(
            BlindEvidencePacket(
                packetId=_blind_evidence_packet_id(
                    claim_id=claim.claim_id,
                    claim_digest=claim.claim_digest,
                    packet_digest=packet_digest,
                ),
                packetDigest=packet_digest,
                claimId=claim.claim_id,
                claimDigest=claim.claim_digest,
                claimType=claim.claim_type,
                statement=claim.statement,
                evidence=list(claim.evidence),
            )
        )
    return packets


def build_blind_evidence_decision(
    packet: BlindEvidencePacket,
    *,
    reviewer_id: str,
    verdict: AtomicClaimVerdict,
    rationale: str,
    supporting_evidence: Sequence[str] = (),
    contradicting_evidence: Sequence[str] = (),
) -> BlindEvidenceDecision:
    """Bind an independent review verdict to one exact minimal packet."""

    supporting = list(supporting_evidence)
    contradicting = list(contradicting_evidence)
    return BlindEvidenceDecision(
        decisionId=_blind_evidence_decision_id(
            packet_id=packet.packet_id,
            packet_digest=packet.packet_digest,
            claim_id=packet.claim_id,
            claim_digest=packet.claim_digest,
            reviewer_id=reviewer_id,
            verdict=verdict,
            rationale=rationale,
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
        ),
        packetId=packet.packet_id,
        packetDigest=packet.packet_digest,
        claimId=packet.claim_id,
        claimDigest=packet.claim_digest,
        reviewerId=reviewer_id,
        verdict=verdict,
        rationale=rationale,
        supportingEvidence=supporting,
        contradictingEvidence=contradicting,
    )


def reconcile_claim_reviews(
    primary: AtomicClaimDecision,
    blind: BlindEvidenceDecision,
) -> ClaimReviewReconciliation:
    """Compare two sealed decisions without granting confirmation authority."""

    if primary.verdict is blind.verdict and primary.verdict is not AtomicClaimVerdict.INSUFFICIENT:
        outcome = ClaimReviewOutcome.CORROBORATED
    elif {
        primary.verdict,
        blind.verdict,
    } == {
        AtomicClaimVerdict.SUPPORTS,
        AtomicClaimVerdict.CONTRADICTS,
    }:
        outcome = ClaimReviewOutcome.CONTESTED
    else:
        outcome = ClaimReviewOutcome.INCONCLUSIVE
    reconciliation_id = _claim_review_reconciliation_id(
        claim_id=primary.claim_id,
        claim_digest=primary.claim_digest,
        primary_decision_id=primary.decision_id,
        blind_decision_id=blind.decision_id,
        outcome=outcome,
    )
    return ClaimReviewReconciliation(
        reconciliationId=reconciliation_id,
        claimId=primary.claim_id,
        claimDigest=primary.claim_digest,
        primaryDecisionId=primary.decision_id,
        blindDecisionId=blind.decision_id,
        outcome=outcome,
    )


def build_provider_model_review_binding(
    *,
    primary_provider_id: str,
    primary_endpoint: str,
    primary_model: str,
    reviewer_id: str,
    review_provider_id: str,
    review_endpoint: str,
    review_model: str,
) -> ProviderModelReviewBinding:
    """Bind exact, strongly diverse primary and review Provider/model identities."""

    return ProviderModelReviewBinding(
        bindingId=_provider_model_review_binding_id(
            primary_provider_id=primary_provider_id,
            primary_endpoint=primary_endpoint,
            primary_model=primary_model,
            reviewer_id=reviewer_id,
            review_provider_id=review_provider_id,
            review_endpoint=review_endpoint,
            review_model=review_model,
        ),
        primaryProviderId=primary_provider_id,
        primaryEndpoint=primary_endpoint,
        primaryModel=primary_model,
        reviewerId=reviewer_id,
        reviewProviderId=review_provider_id,
        reviewEndpoint=review_endpoint,
        reviewModel=review_model,
    )


def severity_derivation_packets(
    claims: Sequence[AtomicClaim],
) -> list[SeverityDerivationPacket]:
    """Project validity/impact context while withholding proposed severity and identity."""

    context_by_claim = {packet.claim_id: packet for packet in blind_evidence_packets(claims)}
    claims_by_candidate: dict[str, list[AtomicClaim]] = {}
    for claim in claims:
        claims_by_candidate.setdefault(claim.candidate_id, []).append(claim)
    packets: list[SeverityDerivationPacket] = []
    for candidate_claims in claims_by_candidate.values():
        severity_claims = [
            claim for claim in candidate_claims if claim.claim_type is AtomicClaimType.SEVERITY
        ]
        if len(severity_claims) != 1:
            raise ValueError("each Candidate requires exactly one severity Claim")
        severity_claim = severity_claims[0]
        context_packets = [
            context_by_claim[claim.claim_id]
            for claim in candidate_claims
            if claim.claim_type is not AtomicClaimType.SEVERITY
        ]
        packet_digest = _severity_derivation_packet_digest(
            severity_claim_id=severity_claim.claim_id,
            context_packets=context_packets,
        )
        packets.append(
            SeverityDerivationPacket(
                packetId=_severity_derivation_packet_id(
                    severity_claim_id=severity_claim.claim_id,
                    packet_digest=packet_digest,
                ),
                packetDigest=packet_digest,
                severityClaimId=severity_claim.claim_id,
                contextPackets=context_packets,
            )
        )
    return packets


def build_independent_severity_decision(
    packet: SeverityDerivationPacket,
    binding: ProviderModelReviewBinding,
    *,
    status: SeverityDerivationStatus,
    severity: FindingSeverity | None,
    rationale: str,
    evidence: Sequence[str] = (),
) -> IndependentSeverityDecision:
    """Bind one diverse review model's severity derivation to a minimal Packet."""

    references = list(evidence)
    return IndependentSeverityDecision(
        decisionId=_independent_severity_decision_id(
            packet_id=packet.packet_id,
            packet_digest=packet.packet_digest,
            reviewer_id=binding.reviewer_id,
            review_binding_id=binding.binding_id,
            status=status,
            severity=severity,
            rationale=rationale,
            evidence=references,
        ),
        packetId=packet.packet_id,
        packetDigest=packet.packet_digest,
        reviewerId=binding.reviewer_id,
        reviewBindingId=binding.binding_id,
        status=status,
        severity=severity,
        rationale=rationale,
        evidence=references,
    )


def reconcile_independent_severity(
    severity_claim: AtomicClaim,
    decision: IndependentSeverityDecision,
) -> SeverityClaimReconciliation:
    """Compare proposed and independently derived severity without changing either."""

    if severity_claim.claim_type is not AtomicClaimType.SEVERITY:
        raise ValueError("severity reconciliation requires a severity Atomic Claim")
    proposed = FindingSeverity(severity_claim.statement)
    if decision.status is SeverityDerivationStatus.INSUFFICIENT:
        outcome = ClaimReviewOutcome.INCONCLUSIVE
    elif decision.severity is proposed:
        outcome = ClaimReviewOutcome.CORROBORATED
    else:
        outcome = ClaimReviewOutcome.CONTESTED
    return SeverityClaimReconciliation(
        reconciliationId=_severity_claim_reconciliation_id(
            severity_claim_id=severity_claim.claim_id,
            severity_claim_digest=severity_claim.claim_digest,
            derivation_decision_id=decision.decision_id,
            outcome=outcome,
        ),
        severityClaimId=severity_claim.claim_id,
        severityClaimDigest=severity_claim.claim_digest,
        derivationDecisionId=decision.decision_id,
        outcome=outcome,
    )


def validate_independent_severity_refinement(
    claims: Sequence[AtomicClaim],
    packets: Sequence[SeverityDerivationPacket],
    decisions: Sequence[IndependentSeverityDecision],
    reconciliations: Sequence[SeverityClaimReconciliation],
    binding: ProviderModelReviewBinding | None,
    *,
    required: bool,
) -> None:
    """Verify diverse, minimal-input severity derivation and information-only comparison."""

    if not packets and not decisions and not reconciliations and binding is None and not required:
        return
    if binding is None:
        raise ValueError("independent severity derivation requires a Provider/model binding")
    expected_packets = severity_derivation_packets(claims)
    if list(packets) != expected_packets:
        raise ValueError("severity derivation Packets differ from trusted Atomic Claims")
    if [decision.packet_id for decision in decisions] != [packet.packet_id for packet in packets]:
        raise ValueError("severity Decisions must follow the exact Packet order")
    decision_ids = [decision.decision_id for decision in decisions]
    if len(decision_ids) != len(set(decision_ids)):
        raise ValueError("independent severity Decision IDs must be unique")
    for packet, decision in zip(packets, decisions, strict=True):
        if (
            decision.packet_digest != packet.packet_digest
            or decision.reviewer_id != binding.reviewer_id
            or decision.review_binding_id != binding.binding_id
        ):
            raise ValueError("independent severity Decision differs from its authority")
        allowed_evidence = {
            reference for context in packet.context_packets for reference in context.evidence
        }
        if not set(decision.evidence) <= allowed_evidence:
            raise ValueError("independent severity Decision cites evidence outside its Packet")
    severity_by_id = {
        claim.claim_id: claim for claim in claims if claim.claim_type is AtomicClaimType.SEVERITY
    }
    expected_reconciliations = [
        reconcile_independent_severity(
            severity_by_id[packet.severity_claim_id],
            decision,
        )
        for packet, decision in zip(packets, decisions, strict=True)
    ]
    if list(reconciliations) != expected_reconciliations:
        raise ValueError("severity reconciliations differ from their sealed inputs")


def validate_candidate_blind_refinement(
    claims: Sequence[AtomicClaim],
    primary_decisions: Sequence[AtomicClaimDecision],
    packets: Sequence[BlindEvidencePacket],
    blind_decisions: Sequence[BlindEvidenceDecision],
    reconciliations: Sequence[ClaimReviewReconciliation],
    *,
    required: bool,
) -> None:
    """Verify a complete blind-review set and its deterministic comparison."""

    if not packets and not blind_decisions and not reconciliations and not required:
        return
    expected_packets = blind_evidence_packets(claims)
    if list(packets) != expected_packets:
        raise ValueError("Blind Evidence Packets differ from the trusted Atomic Claims")
    if [decision.claim_id for decision in primary_decisions] != [
        claim.claim_id for claim in claims
    ]:
        raise ValueError("Blind review requires one primary decision per Atomic Claim")
    if [decision.packet_id for decision in blind_decisions] != [
        packet.packet_id for packet in packets
    ]:
        raise ValueError("Blind Evidence Decisions must follow the exact Packet order")
    decision_ids = [decision.decision_id for decision in blind_decisions]
    if len(decision_ids) != len(set(decision_ids)):
        raise ValueError("Blind Evidence Decision IDs must be unique")
    reviewer_ids = {decision.reviewer_id for decision in blind_decisions}
    if packets and len(reviewer_ids) != 1:
        raise ValueError("one independent Blind reviewer must assess the complete Packet set")
    for packet, decision in zip(packets, blind_decisions, strict=True):
        if (
            decision.packet_id != packet.packet_id
            or decision.packet_digest != packet.packet_digest
            or decision.claim_id != packet.claim_id
            or decision.claim_digest != packet.claim_digest
        ):
            raise ValueError("Blind Evidence Decision identity does not match its Packet")
        cited = set(decision.supporting_evidence) | set(decision.contradicting_evidence)
        if not cited <= set(packet.evidence):
            raise ValueError("Blind Evidence Decision cites evidence outside its Packet")
    primary_by_claim = {decision.claim_id: decision for decision in primary_decisions}
    if len(primary_by_claim) != len(primary_decisions):
        raise ValueError("primary Atomic Claim Decision IDs must be unique")
    expected_reconciliations = [
        reconcile_claim_reviews(primary_by_claim[blind.claim_id], blind)
        for blind in blind_decisions
    ]
    if list(reconciliations) != expected_reconciliations:
        raise ValueError("Claim review reconciliations differ from their sealed decisions")


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


def _blind_evidence_packet_digest(
    *,
    claim_id: str,
    claim_digest: str,
    claim_type: AtomicClaimType,
    statement: str,
    evidence: Sequence[str],
) -> str:
    return _canonical_digest(
        {
            "claimId": claim_id,
            "claimDigest": claim_digest,
            "claimType": claim_type.value,
            "statement": statement,
            "evidence": list(evidence),
        }
    )


def _blind_evidence_packet_id(
    *,
    claim_id: str,
    claim_digest: str,
    packet_digest: str,
) -> str:
    return f"blind_packet_{
        _canonical_digest(
            {
                'claimId': claim_id,
                'claimDigest': claim_digest,
                'packetDigest': packet_digest,
            }
        )
    }"


def _blind_evidence_decision_id(
    *,
    packet_id: str,
    packet_digest: str,
    claim_id: str,
    claim_digest: str,
    reviewer_id: str,
    verdict: AtomicClaimVerdict,
    rationale: str,
    supporting_evidence: Sequence[str],
    contradicting_evidence: Sequence[str],
) -> str:
    return f"blind_decision_{
        _canonical_digest(
            {
                'packetId': packet_id,
                'packetDigest': packet_digest,
                'claimId': claim_id,
                'claimDigest': claim_digest,
                'reviewerId': reviewer_id,
                'verdict': verdict.value,
                'rationale': rationale,
                'supportingEvidence': list(supporting_evidence),
                'contradictingEvidence': list(contradicting_evidence),
            }
        )
    }"


def _claim_review_reconciliation_id(
    *,
    claim_id: str,
    claim_digest: str,
    primary_decision_id: str,
    blind_decision_id: str,
    outcome: ClaimReviewOutcome,
) -> str:
    return f"claim_review_{
        _canonical_digest(
            {
                'claimId': claim_id,
                'claimDigest': claim_digest,
                'primaryDecisionId': primary_decision_id,
                'blindDecisionId': blind_decision_id,
                'outcome': outcome.value,
            }
        )
    }"


def _provider_model_review_binding_id(
    *,
    primary_provider_id: str,
    primary_endpoint: str,
    primary_model: str,
    reviewer_id: str,
    review_provider_id: str,
    review_endpoint: str,
    review_model: str,
) -> str:
    return f"review_binding_{
        _canonical_digest(
            {
                'primaryProviderId': primary_provider_id,
                'primaryEndpoint': primary_endpoint,
                'primaryModel': primary_model,
                'reviewerId': reviewer_id,
                'reviewProviderId': review_provider_id,
                'reviewEndpoint': review_endpoint,
                'reviewModel': review_model,
            }
        )
    }"


def _severity_derivation_packet_digest(
    *,
    severity_claim_id: str,
    context_packets: Sequence[BlindEvidencePacket],
) -> str:
    return _canonical_digest(
        {
            "severityClaimId": severity_claim_id,
            "contextPackets": [
                packet.model_dump(mode="json", by_alias=True) for packet in context_packets
            ],
        }
    )


def _severity_derivation_packet_id(
    *,
    severity_claim_id: str,
    packet_digest: str,
) -> str:
    return f"severity_packet_{
        _canonical_digest(
            {
                'severityClaimId': severity_claim_id,
                'packetDigest': packet_digest,
            }
        )
    }"


def _independent_severity_decision_id(
    *,
    packet_id: str,
    packet_digest: str,
    reviewer_id: str,
    review_binding_id: str,
    status: SeverityDerivationStatus,
    severity: FindingSeverity | None,
    rationale: str,
    evidence: Sequence[str],
) -> str:
    return f"severity_decision_{
        _canonical_digest(
            {
                'packetId': packet_id,
                'packetDigest': packet_digest,
                'reviewerId': reviewer_id,
                'reviewBindingId': review_binding_id,
                'status': status.value,
                'severity': severity.value if severity is not None else None,
                'rationale': rationale,
                'evidence': list(evidence),
            }
        )
    }"


def _severity_claim_reconciliation_id(
    *,
    severity_claim_id: str,
    severity_claim_digest: str,
    derivation_decision_id: str,
    outcome: ClaimReviewOutcome,
) -> str:
    return f"severity_review_{
        _canonical_digest(
            {
                'severityClaimId': severity_claim_id,
                'severityClaimDigest': severity_claim_digest,
                'derivationDecisionId': derivation_decision_id,
                'outcome': outcome.value,
            }
        )
    }"


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


class ClaimReplayAssessment(StrictModel):
    """Public, Claim-bound interpretation of one verified Candidate replay."""

    api_version: Literal["pajin.dev/claim-replay-assessment/v1alpha1"] = Field(
        default="pajin.dev/claim-replay-assessment/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ClaimReplayAssessment"] = "ClaimReplayAssessment"
    assessment_id: _Identifier = Field(alias="assessmentId")
    candidate_id: _Identifier = Field(alias="candidateId")
    candidate_claim_digest: str = Field(
        alias="candidateClaimDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    claim_id: _Identifier = Field(alias="claimId")
    claim_digest: str = Field(alias="claimDigest", pattern=r"^[a-f0-9]{64}$")
    claim_type: AtomicClaimType = Field(alias="claimType")
    status: ClaimReplayStatus
    replay_run_id: _Identifier = Field(alias="replayRunId")
    replay_outcome_id: _Identifier = Field(alias="replayOutcomeId")
    oracle_result_id: _Identifier | None = Field(default=None, alias="oracleResultId")
    replay_request_ids: list[_Identifier] = Field(alias="replayRequestIds", max_length=20)
    replay_evidence: list[_EvidenceReference] = Field(alias="replayEvidence", max_length=100)
    independent_execution_attested: bool = Field(alias="independentExecutionAttested")
    assessed_at: datetime = Field(alias="assessedAt")

    @field_validator("assessed_at")
    @classmethod
    def normalize_assessed_at(cls, value: datetime) -> datetime:
        return _normalize_utc(value, field_name="assessed_at")

    @model_validator(mode="after")
    def require_canonical_assessment(self) -> ClaimReplayAssessment:
        _require_unique(
            self.replay_request_ids,
            "Claim replay request IDs must be unique",
        )
        _require_unique(
            self.replay_evidence,
            "Claim replay evidence references must be unique",
        )
        if self.independent_execution_attested and self.status is not ClaimReplayStatus.REPRODUCED:
            raise ValueError("independent execution attestation requires a reproduced Claim")
        if self.assessment_id != _claim_replay_assessment_id(
            candidate_id=self.candidate_id,
            candidate_claim_digest=self.candidate_claim_digest,
            claim_id=self.claim_id,
            claim_digest=self.claim_digest,
            claim_type=self.claim_type,
            status=self.status,
            replay_run_id=self.replay_run_id,
            replay_outcome_id=self.replay_outcome_id,
            oracle_result_id=self.oracle_result_id,
            replay_request_ids=self.replay_request_ids,
            replay_evidence=self.replay_evidence,
            independent_execution_attested=self.independent_execution_attested,
            assessed_at=self.assessed_at,
        ):
            raise ValueError("Claim replay assessment ID does not match its canonical content")
        return self


def build_claim_replay_assessment(
    *,
    claim: AtomicClaim,
    lineage: ReplayConfirmationLineage,
    status: ClaimReplayStatus,
    independent_execution_attested: bool,
    assessed_at: datetime,
) -> ClaimReplayAssessment:
    """Bind verified replay lineage to the exact Atomic Claim it evaluated."""
    normalized_at = _normalize_utc(assessed_at, field_name="assessed_at")
    return ClaimReplayAssessment(
        assessmentId=_claim_replay_assessment_id(
            candidate_id=claim.candidate_id,
            candidate_claim_digest=claim.candidate_claim_digest,
            claim_id=claim.claim_id,
            claim_digest=claim.claim_digest,
            claim_type=claim.claim_type,
            status=status,
            replay_run_id=lineage.replay_run_id,
            replay_outcome_id=lineage.replay_outcome_id,
            oracle_result_id=lineage.oracle_result_id,
            replay_request_ids=lineage.replay_request_ids,
            replay_evidence=lineage.replay_evidence,
            independent_execution_attested=independent_execution_attested,
            assessed_at=normalized_at,
        ),
        candidateId=claim.candidate_id,
        candidateClaimDigest=claim.candidate_claim_digest,
        claimId=claim.claim_id,
        claimDigest=claim.claim_digest,
        claimType=claim.claim_type,
        status=status,
        replayRunId=lineage.replay_run_id,
        replayOutcomeId=lineage.replay_outcome_id,
        oracleResultId=lineage.oracle_result_id,
        replayRequestIds=lineage.replay_request_ids,
        replayEvidence=lineage.replay_evidence,
        independentExecutionAttested=independent_execution_attested,
        assessedAt=normalized_at,
    )


def _claim_replay_assessment_id(
    *,
    candidate_id: str,
    candidate_claim_digest: str,
    claim_id: str,
    claim_digest: str,
    claim_type: AtomicClaimType,
    status: ClaimReplayStatus,
    replay_run_id: str,
    replay_outcome_id: str,
    oracle_result_id: str | None,
    replay_request_ids: Sequence[str],
    replay_evidence: Sequence[str],
    independent_execution_attested: bool,
    assessed_at: datetime,
) -> str:
    digest = _canonical_digest(
        {
            "candidateId": candidate_id,
            "candidateClaimDigest": candidate_claim_digest,
            "claimId": claim_id,
            "claimDigest": claim_digest,
            "claimType": claim_type.value,
            "status": status.value,
            "replayRunId": replay_run_id,
            "replayOutcomeId": replay_outcome_id,
            "oracleResultId": oracle_result_id,
            "replayRequestIds": list(replay_request_ids),
            "replayEvidence": list(replay_evidence),
            "independentExecutionAttested": independent_execution_attested,
            "assessedAt": _normalize_utc(assessed_at, field_name="assessed_at")
            .isoformat()
            .replace("+00:00", "Z"),
        }
    )
    return f"claim_replay_{digest[:24]}"


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


class VersionedClaimReplaySet(StrictModel):
    api_version: Literal["pajin.dev/claim-replay/v1alpha1"] = Field(
        default="pajin.dev/claim-replay/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ClaimReplayAssessmentSet"] = "ClaimReplayAssessmentSet"
    source_run_id: _Identifier = Field(alias="sourceRunId")
    assessments: list[ClaimReplayAssessment]

    @model_validator(mode="after")
    def require_unique_assessments(self) -> VersionedClaimReplaySet:
        _require_unique(
            [assessment.assessment_id for assessment in self.assessments],
            "Claim replay assessment IDs must be unique",
        )
        _require_unique(
            [assessment.claim_id for assessment in self.assessments],
            "Claim replay assessments must bind unique Claims",
        )
        _require_unique(
            [assessment.replay_run_id for assessment in self.assessments],
            "Claim replay assessments must bind unique replay Runs",
        )
        _require_unique(
            [assessment.replay_outcome_id for assessment in self.assessments],
            "Claim replay assessments must bind unique ReplayOutcomes",
        )
        return self


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
    claim_replays_path: Literal["validation/v1alpha1/claim-replays.json"] | None = Field(
        default=None,
        alias="claimReplaysPath",
    )
    dispositions: dict[FindingDisposition, list[_Identifier]]
    public_states: dict[PublicFindingState, list[_Identifier]] | None = Field(
        default=None,
        alias="publicStates",
    )
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
        if (self.claim_replays_path is None) != (self.public_states is None):
            raise ValueError("Claim replay path and public states must be introduced together")
        if self.public_states is not None:
            if set(self.public_states) != set(PublicFindingState):
                raise ValueError("versioned validation index must include every public state")
            public_candidate_ids = [
                candidate_id
                for state in PublicFindingState
                for candidate_id in self.public_states[state]
            ]
            if len(public_candidate_ids) != len(set(public_candidate_ids)):
                raise ValueError("public validation state Candidate IDs must be unique")
            if set(public_candidate_ids) != set(all_candidate_ids):
                raise ValueError("public validation states must cover every Candidate exactly once")
            if self.confirmed_candidate_ids != self.public_states[PublicFindingState.CONFIRMED]:
                raise ValueError("confirmed Candidate IDs must match the public confirmed state")
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
