"""Deterministic scoring and ranking for an evidence-bound Hypothesis Frontier."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.agentic.models import (
    AGENTIC_CAMPAIGN_API_VERSION,
    AgenticStrictModel,
    BasisPoints,
    HypothesisProposal,
    Sha256,
    TrustedPathFeatures,
    _literal_false,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest


class PathScoringPolicy(AgenticStrictModel):
    """Versioned scheduling heuristic; it is not Finding or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["PathScoringPolicy"] = "PathScoringPolicy"
    policy_id: str = Field(default="", alias="policyId", max_length=96)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    model_likelihood_weight_bps: BasisPoints = Field(alias="modelLikelihoodWeightBps")
    evidence_quality_weight_bps: BasisPoints = Field(alias="evidenceQualityWeightBps")
    expected_impact_weight_bps: BasisPoints = Field(alias="expectedImpactWeightBps")
    privilege_gain_weight_bps: BasisPoints = Field(alias="privilegeGainWeightBps")
    reachability_gain_weight_bps: BasisPoints = Field(alias="reachabilityGainWeightBps")
    novelty_weight_bps: BasisPoints = Field(alias="noveltyWeightBps")
    execution_cost_penalty_bps: BasisPoints = Field(alias="executionCostPenaltyBps")
    safety_risk_penalty_bps: BasisPoints = Field(alias="safetyRiskPenaltyBps")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("finding_authority", "execution_authority", mode="before")
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        benefit = (
            self.model_likelihood_weight_bps
            + self.evidence_quality_weight_bps
            + self.expected_impact_weight_bps
            + self.privilege_gain_weight_bps
            + self.reachability_gain_weight_bps
            + self.novelty_weight_bps
        )
        if benefit != 10_000:
            raise ValueError("Path Scoring benefit weights must sum to 10000 basis points")
        if self.model_likelihood_weight_bps > 1_500:
            raise ValueError("model likelihood weight exceeds the advisory ceiling")
        if self.execution_cost_penalty_bps + self.safety_risk_penalty_bps > 5_000:
            raise ValueError("Path Scoring penalties exceed the bounded ceiling")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = discovery_digest("pajin.agentic.path-scoring-policy/v1", material)
        expected_id = f"path-scoring-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Path Scoring Policy Digest differs")
        if self.policy_id and self.policy_id != expected_id:
            raise ValueError("Path Scoring Policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", expected_id)
        return self


def default_path_scoring_policy() -> PathScoringPolicy:
    """Return the initial conservative policy with only 10% model influence."""

    return PathScoringPolicy(
        modelLikelihoodWeightBps=1_000,
        evidenceQualityWeightBps=2_500,
        expectedImpactWeightBps=2_000,
        privilegeGainWeightBps=1_500,
        reachabilityGainWeightBps=1_500,
        noveltyWeightBps=1_500,
        executionCostPenaltyBps=1_000,
        safetyRiskPenaltyBps=2_000,
    )


class FrontierCandidate(AgenticStrictModel):
    """Trusted compilation of one model proposal and independent path features."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["FrontierCandidate"] = "FrontierCandidate"
    candidate_id: str = Field(default="", alias="candidateId", max_length=96)
    candidate_digest: str = Field(default="", alias="candidateDigest", max_length=64)
    proposal: HypothesisProposal
    trusted_features: TrustedPathFeatures = Field(alias="trustedFeatures")
    candidate_state: Literal["compiled-not-authorized"] = Field(
        default="compiled-not-authorized",
        alias="candidateState",
    )
    task_graph_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="taskGraphMutationAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthority",
    )

    @field_validator(
        "task_graph_mutation_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "finding_authority",
        "graph_admission_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if (
            self.proposal.source_snapshot_id != self.trusted_features.source_snapshot_id
            or self.proposal.source_snapshot_digest
            != self.trusted_features.source_snapshot_digest
        ):
            raise ValueError("Frontier Candidate sources differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"candidate_id", "candidate_digest"},
        )
        digest = discovery_digest("pajin.agentic.frontier-candidate/v1", material)
        expected_id = f"frontier-candidate_{digest}"
        if self.candidate_digest and self.candidate_digest != digest:
            raise ValueError("Frontier Candidate Digest differs")
        if self.candidate_id and self.candidate_id != expected_id:
            raise ValueError("Frontier Candidate ID differs")
        object.__setattr__(self, "candidate_digest", digest)
        object.__setattr__(self, "candidate_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Frontier Candidate",
            max_bytes=128 * 1024,
        )
        return self


class ScoredFrontierCandidate(AgenticStrictModel):
    """One deterministic score and rank over a compiled Candidate."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    score_id: str = Field(default="", alias="scoreId", max_length=96)
    candidate_id: str = Field(
        alias="candidateId",
        pattern=r"^frontier-candidate_[a-f0-9]{64}$",
    )
    candidate_digest: Sha256 = Field(alias="candidateDigest")
    policy_id: str = Field(alias="policyId", pattern=r"^path-scoring-policy_[a-f0-9]{64}$")
    policy_digest: Sha256 = Field(alias="policyDigest")
    score_bps: BasisPoints = Field(alias="scoreBps")
    benefit_bps: BasisPoints = Field(alias="benefitBps")
    penalty_bps: BasisPoints = Field(alias="penaltyBps")
    rank: int = Field(strict=True, ge=1, le=10_000)
    score_origin: Literal["deterministic-policy"] = Field(
        default="deterministic-policy",
        alias="scoreOrigin",
    )
    decision_authority: Literal[False] = Field(default=False, alias="decisionAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("decision_authority", "execution_authority", mode="before")
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if self.score_bps != min(10_000, max(0, self.benefit_bps - self.penalty_bps)):
            raise ValueError("Path Score arithmetic differs")
        expected = "path-score_" + discovery_digest(
            "pajin.agentic.scored-frontier-candidate/v1",
            self.model_dump(mode="json", by_alias=True, exclude={"score_id"}),
        )
        if self.score_id and self.score_id != expected:
            raise ValueError("Path Score ID differs")
        object.__setattr__(self, "score_id", expected)
        return self


def compile_frontier_candidate(
    proposal: HypothesisProposal,
    trusted_features: TrustedPathFeatures,
) -> FrontierCandidate:
    """Compile inert model and trusted inputs without creating an executable request."""

    canonical_proposal = HypothesisProposal.model_validate(
        proposal.model_dump(mode="json", by_alias=True)
    )
    canonical_features = TrustedPathFeatures.model_validate(
        trusted_features.model_dump(mode="json", by_alias=True)
    )
    return FrontierCandidate(
        proposal=canonical_proposal,
        trustedFeatures=canonical_features,
    )


class PathScorer:
    """Pure deterministic scorer with stable integer arithmetic."""

    def __init__(self, policy: PathScoringPolicy | None = None) -> None:
        supplied = policy or default_path_scoring_policy()
        self.policy = PathScoringPolicy.model_validate(
            supplied.model_dump(mode="json", by_alias=True)
        )

    def rank(
        self,
        candidates: tuple[FrontierCandidate, ...],
    ) -> tuple[ScoredFrontierCandidate, ...]:
        self.policy = PathScoringPolicy.model_validate(
            self.policy.model_dump(mode="json", by_alias=True)
        )
        if len(candidates) > 500:
            raise ValueError("Hypothesis Frontier exceeds the candidate limit")
        canonical_candidates = tuple(
            FrontierCandidate.model_validate(item.model_dump(mode="json", by_alias=True))
            for item in candidates
        )
        candidate_ids = [item.candidate_id for item in canonical_candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("Hypothesis Frontier Candidate IDs must be unique")

        computed = [(item, *self._score(item)) for item in canonical_candidates]
        computed.sort(
            key=lambda item: (
                -item[1],
                -item[0].trusted_features.expected_impact_bps,
                -item[0].trusted_features.evidence_quality_bps,
                item[0].candidate_id,
            )
        )
        return tuple(
            ScoredFrontierCandidate(
                candidateId=candidate.candidate_id,
                candidateDigest=candidate.candidate_digest,
                policyId=self.policy.policy_id,
                policyDigest=self.policy.policy_digest,
                scoreBps=score,
                benefitBps=benefit,
                penaltyBps=penalty,
                rank=index,
            )
            for index, (candidate, score, benefit, penalty) in enumerate(computed, start=1)
        )

    def _score(self, candidate: FrontierCandidate) -> tuple[int, int, int]:
        features = candidate.trusted_features
        estimate = candidate.proposal.estimate
        policy = self.policy
        benefit = (
            estimate.success_likelihood_bps * policy.model_likelihood_weight_bps
            + features.evidence_quality_bps * policy.evidence_quality_weight_bps
            + features.expected_impact_bps * policy.expected_impact_weight_bps
            + features.privilege_gain_bps * policy.privilege_gain_weight_bps
            + features.reachability_gain_bps * policy.reachability_gain_weight_bps
            + features.novelty_bps * policy.novelty_weight_bps
        ) // 10_000
        penalty = (
            features.execution_cost_bps * policy.execution_cost_penalty_bps
            + features.safety_risk_bps * policy.safety_risk_penalty_bps
        ) // 10_000
        score = min(10_000, max(0, benefit - penalty))
        return score, benefit, min(10_000, penalty)
