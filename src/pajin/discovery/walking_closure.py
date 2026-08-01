"""MCP-specific confirmation and remediation baseline for WALK-005C1."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.walking import _campaign_digest
from pajin.discovery.walking_replay import (
    WalkingMCPClaimReplayAuthority,
    WalkingMCPClaimReplayError,
    WalkingMCPClaimReplayOutcome,
    load_walking_mcp_claim_replay_authority,
)
from pajin.domain.models import CampaignManifest, Finding, StrictModel
from pajin.domain.validation import AtomicClaim, AtomicClaimType, ClaimReplayStatus
from pajin.reporting import escape_markdown_text, markdown_code_span
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts

WALKING_MCP_CONFIRMATION_API_VERSION: Literal[
    "pajin.dev/walking-mcp-confirmation/v1alpha1"
] = "pajin.dev/walking-mcp-confirmation/v1alpha1"
WALKING_MCP_RETEST_API_VERSION: Literal["pajin.dev/walking-mcp-retest/v1alpha1"] = (
    "pajin.dev/walking-mcp-retest/v1alpha1"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_AUTHORITY_BYTES = 8 * 1024 * 1024
_CONFIRMATION_BASIS: Literal["plan-bound-fresh-mcp-validity-replay"] = (
    "plan-bound-fresh-mcp-validity-replay"
)
_INFORMATION_ONLY: Literal["source-bound-information-only"] = (
    "source-bound-information-only"
)


class WalkingMCPConfirmationError(RuntimeError):
    """Raised when WALK-005C1 cannot prove its confirmation baseline."""


class WalkingMCPRetestError(RuntimeError):
    """Raised when WALK-005C2 cannot prove a baseline-bound fresh Retest."""


class WalkingMCPConfirmationDecision(StrictModel):
    """Content-addressed MCP confirmation policy result."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    decision_id: str = Field(default="", alias="decisionId", max_length=110)
    decision_digest: str = Field(default="", alias="decisionDigest", max_length=64)
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    finding_id: str = Field(alias="findingId", min_length=1, max_length=200)
    validity_claim_id: str = Field(alias="validityClaimId", min_length=1, max_length=200)
    validity_claim_digest: _Sha256 = Field(alias="validityClaimDigest")
    replay_authority_id: str = Field(alias="replayAuthorityId", min_length=1, max_length=110)
    replay_authority_digest: _Sha256 = Field(alias="replayAuthorityDigest")
    replay_projection_id: str = Field(alias="replayProjectionId", min_length=1, max_length=110)
    replay_projection_digest: _Sha256 = Field(alias="replayProjectionDigest")
    confirmation_basis: Literal["plan-bound-fresh-mcp-validity-replay"] = Field(
        default=_CONFIRMATION_BASIS,
        alias="confirmationBasis",
    )
    impact_assurance: Literal["source-bound-information-only"] = Field(
        default=_INFORMATION_ONLY,
        alias="impactAssurance",
    )
    severity_assurance: Literal["source-bound-information-only"] = Field(
        default=_INFORMATION_ONLY,
        alias="severityAssurance",
    )
    disposition: Literal["confirmed"] = "confirmed"
    report_eligible: Literal[True] = Field(default=True, alias="reportEligible")
    remediation_retest_eligible: Literal[True] = Field(
        default=True,
        alias="remediationRetestEligible",
    )

    @model_validator(mode="after")
    def bind_decision(self) -> Self:
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"decision_id", "decision_digest"}
        )
        digest = discovery_digest("pajin.walking.mcp-confirmation-decision/v1", material)
        decision_id = f"walking-mcp-confirmation_{digest}"
        if self.decision_digest and self.decision_digest != digest:
            raise ValueError("Walking MCP confirmation Decision Digest differs")
        if self.decision_id and self.decision_id != decision_id:
            raise ValueError("Walking MCP confirmation Decision ID differs")
        object.__setattr__(self, "decision_digest", digest)
        object.__setattr__(self, "decision_id", decision_id)
        return self


class WalkingMCPRemediationPlan(StrictModel):
    """Non-executable remediation baseline derived from the confirmed Finding."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    remediation_id: str = Field(default="", alias="remediationId", max_length=110)
    remediation_digest: str = Field(default="", alias="remediationDigest", max_length=64)
    decision_id: str = Field(alias="decisionId", min_length=1, max_length=110)
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    finding_id: str = Field(alias="findingId", min_length=1, max_length=200)
    controls: tuple[str, ...] = Field(min_length=1, max_length=20)
    acceptance_criteria: tuple[str, ...] = Field(
        alias="acceptanceCriteria", min_length=2, max_length=20
    )
    requires_human_assignment: Literal[True] = Field(
        default=True,
        alias="requiresHumanAssignment",
    )
    retest_required: Literal[True] = Field(default=True, alias="retestRequired")
    execution_state: Literal["planned-not-applied"] = Field(
        default="planned-not-applied",
        alias="executionState",
    )

    @model_validator(mode="after")
    def bind_remediation(self) -> Self:
        if self.controls != tuple(dict.fromkeys(self.controls)):
            raise ValueError("Walking MCP remediation controls must be unique")
        if self.acceptance_criteria != tuple(dict.fromkeys(self.acceptance_criteria)):
            raise ValueError("Walking MCP remediation acceptance criteria must be unique")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"remediation_id", "remediation_digest"},
        )
        digest = discovery_digest("pajin.walking.mcp-remediation-plan/v1", material)
        remediation_id = f"walking-mcp-remediation_{digest}"
        if self.remediation_digest and self.remediation_digest != digest:
            raise ValueError("Walking MCP remediation Plan Digest differs")
        if self.remediation_id and self.remediation_id != remediation_id:
            raise ValueError("Walking MCP remediation Plan ID differs")
        object.__setattr__(self, "remediation_digest", digest)
        object.__setattr__(self, "remediation_id", remediation_id)
        return self


class WalkingMCPFindingReport(StrictModel):
    """Typed report projection whose Markdown rendering is deterministic."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    report_id: str = Field(default="", alias="reportId", max_length=110)
    report_digest: str = Field(default="", alias="reportDigest", max_length=64)
    decision_id: str = Field(alias="decisionId", min_length=1, max_length=110)
    remediation_id: str = Field(alias="remediationId", min_length=1, max_length=110)
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    finding_id: str = Field(alias="findingId", min_length=1, max_length=200)
    title: str = Field(min_length=1, max_length=2_000)
    severity: str = Field(min_length=1, max_length=50)
    threat_class: str = Field(alias="threatClass", min_length=1, max_length=100)
    target: str = Field(min_length=1, max_length=2_000)
    summary: str = Field(min_length=1, max_length=20_000)
    impact: str = Field(min_length=1, max_length=20_000)
    evidence: tuple[str, ...] = Field(min_length=1, max_length=100)
    confirmation_basis: Literal["plan-bound-fresh-mcp-validity-replay"] = Field(
        default=_CONFIRMATION_BASIS,
        alias="confirmationBasis",
    )
    impact_assurance: Literal["source-bound-information-only"] = Field(
        default=_INFORMATION_ONLY,
        alias="impactAssurance",
    )
    severity_assurance: Literal["source-bound-information-only"] = Field(
        default=_INFORMATION_ONLY,
        alias="severityAssurance",
    )

    @model_validator(mode="after")
    def bind_report(self) -> Self:
        if self.evidence != tuple(sorted(set(self.evidence))):
            raise ValueError("Walking MCP report evidence must be unique and sorted")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"report_id", "report_digest"}
        )
        digest = discovery_digest("pajin.walking.mcp-finding-report/v1", material)
        report_id = f"walking-mcp-report_{digest}"
        if self.report_digest and self.report_digest != digest:
            raise ValueError("Walking MCP Finding Report Digest differs")
        if self.report_id and self.report_id != report_id:
            raise ValueError("Walking MCP Finding Report ID differs")
        object.__setattr__(self, "report_digest", digest)
        object.__setattr__(self, "report_id", report_id)
        return self


class WalkingMCPConfirmationAuthority(StrictModel):
    """Complete C1 authority for confirmation, reporting, and remediation baseline."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/walking-mcp-confirmation/v1alpha1"] = Field(
        default=WALKING_MCP_CONFIRMATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingMCPConfirmationAuthority"] = "WalkingMCPConfirmationAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source: WalkingMCPClaimReplayAuthority
    decision: WalkingMCPConfirmationDecision
    confirmed_finding: Finding = Field(alias="confirmedFinding")
    impact_claim: AtomicClaim = Field(alias="impactClaim")
    severity_claim: AtomicClaim = Field(alias="severityClaim")
    remediation: WalkingMCPRemediationPlan
    report: WalkingMCPFindingReport
    lifecycle_state: Literal["confirmed-remediation-planned-retest-required"] = Field(
        default="confirmed-remediation-planned-retest-required",
        alias="lifecycleState",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        claims = self.source.plan.source.atomic_claims
        impact = tuple(claim for claim in claims if claim.claim_type is AtomicClaimType.IMPACT)
        severity = tuple(claim for claim in claims if claim.claim_type is AtomicClaimType.SEVERITY)
        expected_finding = self.source.plan.source.candidate.claim.model_copy(
            update={"validated": True}
        )
        expected_decision = _confirmation_decision(self.source)
        expected_remediation = _remediation_plan(expected_decision, expected_finding)
        expected_report = _finding_report(
            self.source,
            expected_decision,
            expected_finding,
            expected_remediation,
        )
        projection = self.source.projection
        if (
            self.campaign_digest != self.source.campaign_digest
            or projection.status is not ClaimReplayStatus.REPRODUCED
            or projection.independent_execution_attested is not True
            or projection.confirmation_eligible is not False
            or len(impact) != 1
            or len(severity) != 1
            or self.impact_claim != impact[0]
            or self.severity_claim != severity[0]
            or self.decision != expected_decision
            or self.confirmed_finding != expected_finding
            or self.remediation != expected_remediation
            or self.report != expected_report
        ):
            raise ValueError("Walking MCP confirmation baseline differs from B2 authority")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"authority_id", "authority_digest"}
        )
        digest = discovery_digest("pajin.walking.mcp-confirmation-authority/v1", material)
        authority_id = f"walking-mcp-confirmation_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking MCP confirmation Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking MCP confirmation Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Walking MCP confirmation authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class WalkingMCPConfirmationOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    remediation_path: str
    report_projection_path: str
    report_path: str
    authority: WalkingMCPConfirmationAuthority


class WalkingMCPConfirmationRunner:
    """Re-verify B2 and seal a product confirmation baseline without executing tools."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        replay_outcome: WalkingMCPClaimReplayOutcome,
    ) -> WalkingMCPConfirmationOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        try:
            source = load_walking_mcp_claim_replay_authority(
                authoritative_campaign,
                replay_outcome,
            )
            decision = _confirmation_decision(source)
            finding = source.plan.source.candidate.claim.model_copy(update={"validated": True})
            claims = source.plan.source.atomic_claims
            impact = tuple(claim for claim in claims if claim.claim_type is AtomicClaimType.IMPACT)
            severity = tuple(
                claim for claim in claims if claim.claim_type is AtomicClaimType.SEVERITY
            )
            if len(impact) != 1 or len(severity) != 1:
                raise ValueError("WALK-005C1 requires exact impact and severity Claims")
            remediation = _remediation_plan(decision, finding)
            report = _finding_report(source, decision, finding, remediation)
            authority = WalkingMCPConfirmationAuthority(
                campaignDigest=_campaign_digest(authoritative_campaign),
                source=source,
                decision=decision,
                confirmedFinding=finding,
                impactClaim=impact[0],
                severityClaim=severity[0],
                remediation=remediation,
                report=report,
            )
            report_markdown = _render_report(authority)
        except (
            ValidationError,
            ValueError,
            WalkingMCPClaimReplayError,
        ) as exc:
            raise WalkingMCPConfirmationError(
                "WALK-005C1 MCP confirmation baseline could not be verified"
            ) from exc

        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-mcp-confirmation",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        remediation_path = store.write_json(
            "walking-mcp-remediation-plan.json",
            authority.remediation.model_dump(mode="json", by_alias=True),
        )
        report_projection_path = store.write_json(
            "walking-mcp-finding-report.json",
            authority.report.model_dump(mode="json", by_alias=True),
        )
        report_path = store.write_text("walking-mcp-finding-report.md", report_markdown)
        authority_path = store.write_json(
            "walking-mcp-confirmation-authority.json",
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "walking.mcp-confirmation-authority.created",
            {
                "artifact": authority_path,
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "decisionId": authority.decision.decision_id,
                "findingId": authority.confirmed_finding.finding_id,
                "remediationId": authority.remediation.remediation_id,
                "reportId": authority.report.report_id,
                "lifecycleState": authority.lifecycle_state,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-mcp-confirmation-sealed",
                "authorityId": authority.authority_id,
                "lifecycleState": authority.lifecycle_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-mcp-confirmation", "artifact": authority_path},
        )
        store.seal()
        return WalkingMCPConfirmationOutcome(
            run_id=store.run_id,
            run_path=store.path,
            authority_path=authority_path,
            remediation_path=remediation_path,
            report_projection_path=report_projection_path,
            report_path=report_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_mcp_confirmation_authority(
    campaign: CampaignManifest,
    outcome: WalkingMCPConfirmationOutcome,
) -> WalkingMCPConfirmationAuthority:
    """Rebuild C1 from sealed authority, typed projections, Markdown, and event."""

    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_AUTHORITY_BYTES,
                outcome.authority_path: _MAX_AUTHORITY_BYTES,
                outcome.remediation_path: _MAX_AUTHORITY_BYTES,
                outcome.report_projection_path: _MAX_AUTHORITY_BYTES,
                outcome.report_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = WalkingMCPConfirmationAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.authority_path)
        )
        remediation = WalkingMCPRemediationPlan.model_validate_json(
            snapshot.artifact_bytes(outcome.remediation_path)
        )
        report = WalkingMCPFindingReport.model_validate_json(
            snapshot.artifact_bytes(outcome.report_projection_path)
        )
        markdown = snapshot.artifact_bytes(outcome.report_path)
    except (OSError, RunIntegrityError, UnicodeDecodeError, ValidationError, ValueError) as exc:
        raise WalkingMCPConfirmationError(
            "WALK-005C1 MCP confirmation baseline is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or authority != outcome.authority:
        raise WalkingMCPConfirmationError(
            "WALK-005C1 MCP confirmation outcome differs from sealed authority"
        )
    if (
        remediation != authority.remediation
        or report != authority.report
        or markdown != _render_report(authority).encode("utf-8")
    ):
        raise WalkingMCPConfirmationError("WALK-005C1 report or remediation differs")
    created = [
        event
        for event in snapshot.events
        if event.event_type == "walking.mcp-confirmation-authority.created"
    ]
    expected = {
        "artifact": outcome.authority_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "decisionId": authority.decision.decision_id,
        "findingId": authority.confirmed_finding.finding_id,
        "remediationId": authority.remediation.remediation_id,
        "reportId": authority.report.report_id,
        "lifecycleState": authority.lifecycle_state,
    }
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingMCPConfirmationError("WALK-005C1 publication event differs")
    return authority.model_copy(deep=True)


def _confirmation_decision(
    source: WalkingMCPClaimReplayAuthority,
) -> WalkingMCPConfirmationDecision:
    return WalkingMCPConfirmationDecision(
        candidateId=source.plan.source.candidate.candidate_id,
        findingId=source.plan.source.candidate.claim.finding_id,
        validityClaimId=source.plan.claim.claim_id,
        validityClaimDigest=source.plan.claim.claim_digest,
        replayAuthorityId=source.authority_id,
        replayAuthorityDigest=source.authority_digest,
        replayProjectionId=source.projection.projection_id,
        replayProjectionDigest=source.projection.projection_digest,
    )


def _remediation_plan(
    decision: WalkingMCPConfirmationDecision,
    finding: Finding,
) -> WalkingMCPRemediationPlan:
    return WalkingMCPRemediationPlan(
        decisionId=decision.decision_id,
        candidateId=decision.candidate_id,
        findingId=finding.finding_id,
        controls=tuple(finding.remediation),
        acceptanceCriteria=(
            "동일한 MCP Tool, target, method, arguments를 사용하는 fresh Retest도 "
            "별도 승인을 요구한다.",
            "fresh Retest 증빙이 원 validity Claim의 내부 데이터 접근 관찰을 다시 "
            "지지하지 않아야 한다.",
        ),
    )


def _finding_report(
    source: WalkingMCPClaimReplayAuthority,
    decision: WalkingMCPConfirmationDecision,
    finding: Finding,
    remediation: WalkingMCPRemediationPlan,
) -> WalkingMCPFindingReport:
    if finding.impact is None:
        raise ValueError("Walking MCP confirmed Finding requires an impact statement")
    return WalkingMCPFindingReport(
        decisionId=decision.decision_id,
        remediationId=remediation.remediation_id,
        candidateId=decision.candidate_id,
        findingId=finding.finding_id,
        title=finding.title,
        severity=finding.severity.value,
        threatClass=finding.threat_class,
        target=finding.target,
        summary=finding.summary,
        impact=finding.impact,
        evidence=tuple(sorted(set(source.projection.replay_evidence))),
    )


def _render_report(authority: WalkingMCPConfirmationAuthority) -> str:
    report = authority.report
    lines = [
        "# PAJIN Walking MCP Confirmed Finding",
        "",
        f"- Finding ID: {markdown_code_span(report.finding_id)}",
        f"- Candidate ID: {markdown_code_span(report.candidate_id)}",
        f"- Decision ID: {markdown_code_span(report.decision_id)}",
        f"- Confirmation basis: {markdown_code_span(report.confirmation_basis)}",
        f"- Severity: {markdown_code_span(report.severity)}",
        f"- Threat class: {markdown_code_span(report.threat_class)}",
        f"- Target: {markdown_code_span(report.target)}",
        "- Impact and severity assurance: source-bound information only; validity alone was "
        "independently replayed.",
        "- This is an MCP-specific Plan-bound replay decision, not a KISA ReplayOutcome, "
        "typed Oracle result, or external-host attestation.",
        "",
        f"## {escape_markdown_text(report.title)}",
        "",
        escape_markdown_text(report.summary),
        "",
        "## Impact",
        "",
        escape_markdown_text(report.impact),
        "",
        "## Replay evidence",
        "",
    ]
    lines.extend(f"- {markdown_code_span(item)}" for item in report.evidence)
    lines.extend(
        [
            "",
            "## Remediation baseline",
            "",
            f"- Remediation ID: {markdown_code_span(report.remediation_id)}",
            f"- State: {markdown_code_span(authority.remediation.execution_state)}",
        ]
    )
    lines.extend(
        f"- {escape_markdown_text(item)}" for item in authority.remediation.controls
    )
    return "\n".join(lines) + "\n"


class WalkingMCPRetestAssessment(StrictModel):
    """Conservative lifecycle result for one post-baseline reproduced validity Claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    assessment_id: str = Field(default="", alias="assessmentId", max_length=110)
    assessment_digest: str = Field(default="", alias="assessmentDigest", max_length=64)
    baseline_authority_id: str = Field(alias="baselineAuthorityId", min_length=1, max_length=110)
    baseline_authority_digest: _Sha256 = Field(alias="baselineAuthorityDigest")
    baseline_run_id: str = Field(alias="baselineRunId", min_length=1, max_length=200)
    baseline_root_digest: _Sha256 = Field(alias="baselineRootDigest")
    baseline_confirmed_at: datetime = Field(alias="baselineConfirmedAt")
    remediation_id: str = Field(alias="remediationId", min_length=1, max_length=110)
    remediation_digest: _Sha256 = Field(alias="remediationDigest")
    retest_authority_id: str = Field(alias="retestAuthorityId", min_length=1, max_length=110)
    retest_authority_digest: _Sha256 = Field(alias="retestAuthorityDigest")
    retest_run_id: str = Field(alias="retestRunId", min_length=1, max_length=200)
    retest_root_digest: _Sha256 = Field(alias="retestRootDigest")
    candidate_id: str = Field(alias="candidateId", min_length=1, max_length=200)
    finding_id: str = Field(alias="findingId", min_length=1, max_length=200)
    claim_id: str = Field(alias="claimId", min_length=1, max_length=200)
    claim_digest: _Sha256 = Field(alias="claimDigest")
    baseline_execution_run_id: str = Field(
        alias="baselineExecutionRunId", min_length=1, max_length=200
    )
    baseline_request_id: str = Field(alias="baselineRequestId", min_length=1, max_length=200)
    retest_execution_run_id: str = Field(
        alias="retestExecutionRunId", min_length=1, max_length=200
    )
    retest_request_id: str = Field(alias="retestRequestId", min_length=1, max_length=200)
    status: Literal["still-vulnerable"] = "still-vulnerable"
    fixed_eligible: Literal[False] = Field(default=False, alias="fixedEligible")
    remediation_applied_attested: Literal[False] = Field(
        default=False,
        alias="remediationAppliedAttested",
    )
    regression_status: Literal["not-measured"] = Field(
        default="not-measured",
        alias="regressionStatus",
    )
    assessed_at: datetime = Field(alias="assessedAt")
    rationale: Literal[
        "A post-baseline fresh Plan-bound replay reproduced the exact validity Claim."
    ] = "A post-baseline fresh Plan-bound replay reproduced the exact validity Claim."

    @model_validator(mode="after")
    def bind_assessment(self) -> Self:
        baseline_at = _utc(self.baseline_confirmed_at, label="baseline confirmation time")
        assessed_at = _utc(self.assessed_at, label="MCP Retest assessment time")
        if assessed_at <= baseline_at:
            raise ValueError("Walking MCP Retest must occur after its confirmation baseline")
        if self.baseline_run_id == self.retest_run_id:
            raise ValueError("Walking MCP Retest publication Run must be fresh")
        if self.baseline_execution_run_id == self.retest_execution_run_id:
            raise ValueError("Walking MCP Retest execution Run must be fresh")
        if self.baseline_request_id == self.retest_request_id:
            raise ValueError("Walking MCP Retest request must be fresh")
        object.__setattr__(self, "baseline_confirmed_at", baseline_at)
        object.__setattr__(self, "assessed_at", assessed_at)
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"assessment_id", "assessment_digest"}
        )
        digest = discovery_digest("pajin.walking.mcp-retest-assessment/v1", material)
        assessment_id = f"walking-mcp-retest_{digest}"
        if self.assessment_digest and self.assessment_digest != digest:
            raise ValueError("Walking MCP Retest Assessment Digest differs")
        if self.assessment_id and self.assessment_id != assessment_id:
            raise ValueError("Walking MCP Retest Assessment ID differs")
        object.__setattr__(self, "assessment_digest", digest)
        object.__setattr__(self, "assessment_id", assessment_id)
        return self


class WalkingMCPRetestAuthority(StrictModel):
    """Complete C2 authority for one fresh still-vulnerable lifecycle decision."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/walking-mcp-retest/v1alpha1"] = Field(
        default=WALKING_MCP_RETEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WalkingMCPRetestAuthority"] = "WalkingMCPRetestAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    baseline: WalkingMCPConfirmationAuthority
    retest: WalkingMCPClaimReplayAuthority
    assessment: WalkingMCPRetestAssessment
    lifecycle_state: Literal["retest-completed-still-vulnerable"] = Field(
        default="retest-completed-still-vulnerable",
        alias="lifecycleState",
    )

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        baseline_replay = self.baseline.source
        retest = self.retest
        freshness_pairs = (
            (retest.execution.run_id, baseline_replay.execution.run_id),
            (
                retest.execution.request.request_id,
                baseline_replay.execution.request.request_id,
            ),
            (
                retest.execution.approval.approval.approval_id,
                baseline_replay.execution.approval.approval.approval_id,
            ),
            (retest.execution.grant.grant_id, baseline_replay.execution.grant.grant_id),
            (retest.execution.permit.permit_id, baseline_replay.execution.permit.permit_id),
            (retest.execution.permit.dispatch_id, baseline_replay.execution.permit.dispatch_id),
            (
                retest.execution.worker_result.execution_id,
                baseline_replay.execution.worker_result.execution_id,
            ),
        )
        expected = _retest_assessment(
            self.baseline,
            retest,
            baseline_run_id=self.assessment.baseline_run_id,
            baseline_root_digest=self.assessment.baseline_root_digest,
            baseline_confirmed_at=self.assessment.baseline_confirmed_at,
            retest_run_id=self.assessment.retest_run_id,
            retest_root_digest=self.assessment.retest_root_digest,
        )
        if (
            self.campaign_digest != self.baseline.campaign_digest
            or self.campaign_digest != retest.campaign_digest
            or retest.plan != baseline_replay.plan
            or retest.authority_id == baseline_replay.authority_id
            or retest.projection.projection_id == baseline_replay.projection.projection_id
            or retest.projection.claim_id != self.baseline.decision.validity_claim_id
            or retest.projection.claim_digest != self.baseline.decision.validity_claim_digest
            or retest.projection.status is not ClaimReplayStatus.REPRODUCED
            or retest.projection.independent_execution_attested is not True
            or any(current == prior for current, prior in freshness_pairs)
            or self.assessment != expected
        ):
            raise ValueError("Walking MCP Retest differs from its confirmation baseline")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"authority_id", "authority_digest"}
        )
        digest = discovery_digest("pajin.walking.mcp-retest-authority/v1", material)
        authority_id = f"walking-mcp-retest_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking MCP Retest Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking MCP Retest Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Walking MCP Retest authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class WalkingMCPRetestOutcome:
    run_id: str
    run_path: Path
    authority_path: str
    assessment_path: str
    report_path: str
    authority: WalkingMCPRetestAuthority


class WalkingMCPRetestRunner:
    """Re-verify C1 and a post-baseline B2 replay without executing a Tool."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        baseline_outcome: WalkingMCPConfirmationOutcome,
        retest_outcome: WalkingMCPClaimReplayOutcome,
    ) -> WalkingMCPRetestOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        try:
            baseline = load_walking_mcp_confirmation_authority(
                authoritative_campaign,
                baseline_outcome,
            )
            retest = load_walking_mcp_claim_replay_authority(
                authoritative_campaign,
                retest_outcome,
            )
            baseline_snapshot = load_verified_run_artifacts(
                baseline_outcome.run_path,
                requests={baseline_outcome.authority_path: _MAX_AUTHORITY_BYTES},
                expected_run_id=baseline_outcome.run_id,
            )
            retest_snapshot = load_verified_run_artifacts(
                retest_outcome.run_path,
                requests={retest_outcome.artifact_path: _MAX_AUTHORITY_BYTES},
                expected_run_id=retest_outcome.run_id,
            )
            sealed_baseline = WalkingMCPConfirmationAuthority.model_validate_json(
                baseline_snapshot.artifact_bytes(baseline_outcome.authority_path)
            )
            sealed_retest = WalkingMCPClaimReplayAuthority.model_validate_json(
                retest_snapshot.artifact_bytes(retest_outcome.artifact_path)
            )
            baseline_events = [
                event
                for event in baseline_snapshot.events
                if event.event_type == "walking.mcp-confirmation-authority.created"
                and event.payload.get("authorityId") == baseline.authority_id
            ]
            if (
                sealed_baseline != baseline
                or sealed_retest != retest
                or len(baseline_events) != 1
            ):
                raise ValueError("Walking MCP Retest source snapshots differ")
            confirmed_at = baseline_events[0].occurred_at
            if retest.execution.approval.approval.approved_at <= confirmed_at:
                raise ValueError("Walking MCP Retest approval predates its confirmation baseline")
            assessment = _retest_assessment(
                baseline,
                retest,
                baseline_run_id=baseline_snapshot.verification.run_id,
                baseline_root_digest=baseline_snapshot.verification.root_digest,
                baseline_confirmed_at=confirmed_at,
                retest_run_id=retest_snapshot.verification.run_id,
                retest_root_digest=retest_snapshot.verification.root_digest,
            )
            authority = WalkingMCPRetestAuthority(
                campaignDigest=_campaign_digest(authoritative_campaign),
                baseline=baseline,
                retest=retest,
                assessment=assessment,
            )
            report = _render_retest_report(authority)
        except (
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
            WalkingMCPClaimReplayError,
            WalkingMCPConfirmationError,
        ) as exc:
            raise WalkingMCPRetestError(
                "WALK-005C2 MCP Retest authority could not be verified"
            ) from exc

        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "walking-mcp-retest",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        assessment_path = store.write_json(
            "walking-mcp-retest-assessment.json",
            authority.assessment.model_dump(mode="json", by_alias=True),
        )
        report_path = store.write_text("walking-mcp-retest-report.md", report)
        authority_path = store.write_json(
            "walking-mcp-retest-authority.json",
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "walking.mcp-retest-authority.created",
            {
                "artifact": authority_path,
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "assessmentId": authority.assessment.assessment_id,
                "baselineAuthorityId": authority.baseline.authority_id,
                "retestAuthorityId": authority.retest.authority_id,
                "status": authority.assessment.status,
                "lifecycleState": authority.lifecycle_state,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "walking-mcp-retest-sealed",
                "authorityId": authority.authority_id,
                "lifecycleState": authority.lifecycle_state,
            },
        )
        store.append_event(
            "campaign.completed",
            {"purpose": "walking-mcp-retest", "artifact": authority_path},
        )
        store.seal()
        return WalkingMCPRetestOutcome(
            run_id=store.run_id,
            run_path=store.path,
            authority_path=authority_path,
            assessment_path=assessment_path,
            report_path=report_path,
            authority=authority.model_copy(deep=True),
        )


def load_walking_mcp_retest_authority(
    campaign: CampaignManifest,
    outcome: WalkingMCPRetestOutcome,
) -> WalkingMCPRetestAuthority:
    """Rebuild C2 from its sealed authority, assessment, report, and publication event."""

    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_AUTHORITY_BYTES,
                outcome.authority_path: _MAX_AUTHORITY_BYTES,
                outcome.assessment_path: _MAX_AUTHORITY_BYTES,
                outcome.report_path: _MAX_AUTHORITY_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = WalkingMCPRetestAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.authority_path)
        )
        assessment = WalkingMCPRetestAssessment.model_validate_json(
            snapshot.artifact_bytes(outcome.assessment_path)
        )
        report = snapshot.artifact_bytes(outcome.report_path)
    except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
        raise WalkingMCPRetestError(
            "WALK-005C2 MCP Retest authority is not sealed and valid"
        ) from exc
    if sealed_campaign != campaign or authority != outcome.authority:
        raise WalkingMCPRetestError("WALK-005C2 MCP Retest outcome differs")
    if (
        assessment != authority.assessment
        or report != _render_retest_report(authority).encode("utf-8")
    ):
        raise WalkingMCPRetestError("WALK-005C2 MCP Retest assessment or report differs")
    created = [
        event
        for event in snapshot.events
        if event.event_type == "walking.mcp-retest-authority.created"
    ]
    expected = {
        "artifact": outcome.authority_path,
        "authorityId": authority.authority_id,
        "authorityDigest": authority.authority_digest,
        "assessmentId": authority.assessment.assessment_id,
        "baselineAuthorityId": authority.baseline.authority_id,
        "retestAuthorityId": authority.retest.authority_id,
        "status": authority.assessment.status,
        "lifecycleState": authority.lifecycle_state,
    }
    if len(created) != 1 or created[0].payload != expected:
        raise WalkingMCPRetestError("WALK-005C2 publication event differs")
    return authority.model_copy(deep=True)


def _retest_assessment(
    baseline: WalkingMCPConfirmationAuthority,
    retest: WalkingMCPClaimReplayAuthority,
    *,
    baseline_run_id: str,
    baseline_root_digest: str,
    baseline_confirmed_at: datetime,
    retest_run_id: str,
    retest_root_digest: str,
) -> WalkingMCPRetestAssessment:
    baseline_replay = baseline.source
    return WalkingMCPRetestAssessment(
        baselineAuthorityId=baseline.authority_id,
        baselineAuthorityDigest=baseline.authority_digest,
        baselineRunId=baseline_run_id,
        baselineRootDigest=baseline_root_digest,
        baselineConfirmedAt=baseline_confirmed_at,
        remediationId=baseline.remediation.remediation_id,
        remediationDigest=baseline.remediation.remediation_digest,
        retestAuthorityId=retest.authority_id,
        retestAuthorityDigest=retest.authority_digest,
        retestRunId=retest_run_id,
        retestRootDigest=retest_root_digest,
        candidateId=baseline.decision.candidate_id,
        findingId=baseline.confirmed_finding.finding_id,
        claimId=baseline.decision.validity_claim_id,
        claimDigest=baseline.decision.validity_claim_digest,
        baselineExecutionRunId=baseline_replay.execution.run_id,
        baselineRequestId=baseline_replay.execution.request.request_id,
        retestExecutionRunId=retest.execution.run_id,
        retestRequestId=retest.execution.request.request_id,
        assessedAt=retest.execution.terminal_event.occurred_at,
    )


def _render_retest_report(authority: WalkingMCPRetestAuthority) -> str:
    assessment = authority.assessment
    lines = [
        "# PAJIN Walking MCP Remediation Retest",
        "",
        f"- Assessment ID: {markdown_code_span(assessment.assessment_id)}",
        f"- Baseline authority: {markdown_code_span(assessment.baseline_authority_id)}",
        f"- Remediation Plan: {markdown_code_span(assessment.remediation_id)}",
        f"- Retest authority: {markdown_code_span(assessment.retest_authority_id)}",
        f"- Candidate ID: {markdown_code_span(assessment.candidate_id)}",
        f"- Finding ID: {markdown_code_span(assessment.finding_id)}",
        f"- Validity Claim: {markdown_code_span(assessment.claim_id)}",
        f"- Status: {markdown_code_span(assessment.status)}",
        f"- Fixed eligible: {markdown_code_span(str(assessment.fixed_eligible))}",
        "- Remediation applied attested: "
        + markdown_code_span(str(assessment.remediation_applied_attested)),
        f"- Regression: {markdown_code_span(assessment.regression_status)}",
        "",
        escape_markdown_text(assessment.rationale),
        "",
        "The Retest reused the exact Plan semantics with fresh execution identities. It does not "
        "attest that remediation was applied, does not claim fixed, and does not report regression "
        "coverage.",
        "",
    ]
    return "\n".join(lines)


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)
