"""MCP-specific confirmation and remediation baseline for WALK-005C1."""

from __future__ import annotations

from dataclasses import dataclass
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
