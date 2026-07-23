"""Framework-independent agent runtime port."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from pajin.domain.models import AgentPlan, CampaignManifest, Finding, StrictModel, ToolResult
from pajin.domain.validation import (
    AtomicClaim,
    AtomicClaimDecision,
    BlindEvidenceDecision,
    BlindEvidencePacket,
    CandidateAssessment,
    CandidateFinding,
    ClaimReviewReconciliation,
)


class ModelCallFailure(RuntimeError):
    """A bounded provider attempt failed and may use the configured fallback."""


class AgentRuntime(Protocol):
    agent_id: str

    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        """Produce a typed plan for the authorized campaign."""

    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        """Independently validate tool observations into findings."""


class PlannerRuntime(Protocol):
    async def plan(self, campaign: CampaignManifest) -> AgentPlan:
        """Produce a typed plan without executing privileged tools."""


class ValidatorRuntime(Protocol):
    async def validate(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> list[Finding]:
        """Validate observations independently from the executing specialist."""


class CandidateValidation(StrictModel):
    """One validator call's Candidate-bound assessments and optional legacy findings."""

    findings: list[Finding]
    assessments: list[CandidateAssessment]
    atomic_claims: list[AtomicClaim] = Field(default_factory=list)
    claim_decisions: list[AtomicClaimDecision] = Field(default_factory=list)
    blind_evidence_packets: list[BlindEvidencePacket] = Field(default_factory=list)
    blind_evidence_decisions: list[BlindEvidenceDecision] = Field(default_factory=list)
    claim_review_reconciliations: list[ClaimReviewReconciliation] = Field(default_factory=list)


@runtime_checkable
class CandidateAwareValidatorRuntime(Protocol):
    async def validate_candidates(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        candidates: list[CandidateFinding],
    ) -> CandidateValidation:
        """Assess each supplied Candidate by ID and exact canonical claim digest."""


@dataclass(frozen=True, slots=True)
class CandidateAuthority:
    """One request's exact authority to support one target and threat class."""

    request_id: str
    target: str
    threat_class: str

    @property
    def claim_key(self) -> tuple[str, str]:
        return (self.target, self.threat_class)


@dataclass(frozen=True)
class CandidateProduction:
    """Atomic trusted-candidate output and the confirmation space it owns."""

    candidates: tuple[CandidateFinding, ...]
    authoritative_request_claims: frozenset[CandidateAuthority] = frozenset()

    @property
    def authoritative_request_ids(self) -> frozenset[str]:
        return frozenset(authority.request_id for authority in self.authoritative_request_claims)

    @property
    def authoritative_claim_keys(self) -> frozenset[tuple[str, str]]:
        return frozenset(authority.claim_key for authority in self.authoritative_request_claims)

    def __post_init__(self) -> None:
        candidate_ids = [candidate.candidate_id for candidate in self.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("candidate production IDs must be unique")
        for candidate in self.candidates:
            if candidate.claim.validated:
                raise ValueError("candidate production claims must have validated=False")
            if not candidate.source_request_ids:
                raise ValueError("candidate source requests must not be empty")
            required_authority = {
                CandidateAuthority(
                    request_id=request_id,
                    target=candidate.claim.target,
                    threat_class=candidate.claim.threat_class,
                )
                for request_id in candidate.source_request_ids
            }
            if not required_authority <= self.authoritative_request_claims:
                raise ValueError("candidate requires exact request-to-claim authority")


class CandidateProducerRuntime(Protocol):
    """Produce trusted, unconfirmed candidates from same-Run observations."""

    producer_id: str

    def produce(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
    ) -> CandidateProduction:
        """Derive candidates and bounded authority without tools or side effects."""


class AgentReportNarrative(StrictModel):
    summary: str
    risk_overview: str
    recommendations: list[str]
    limitations: list[str]


class ReporterRuntime(Protocol):
    async def report(
        self,
        campaign: CampaignManifest,
        plan: AgentPlan,
        results: list[ToolResult],
        findings: list[Finding],
    ) -> AgentReportNarrative:
        """Produce a bounded narrative supplement to the canonical report."""


class StructuredModelPort(Protocol):
    async def complete(
        self,
        *,
        role: str,
        attempt: int,
        messages: list[Any],
        schema_name: str,
        schema: dict[str, object],
        max_completion_tokens: int,
    ) -> Any:
        """Call one policy-bound model provider and return a normalized result."""

    def record_fallback(self, *, role: str, reason: str) -> None:
        """Audit a deterministic fallback without storing provider secrets."""


@runtime_checkable
class ModelBoundRuntime(Protocol):
    model_provider_registration: Any
    model_provider_tool_id: str
    model_provider_endpoint: str
    model_max_attempts: int

    def bind_model_port(self, port: StructuredModelPort) -> None:
        """Bind a run- and role-scoped provider port before invoking this runtime."""
