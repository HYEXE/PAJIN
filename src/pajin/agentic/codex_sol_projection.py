"""Target-neutral Sol advisory inputs from admitted or strictly reloaded sources.

These contracts do not dispatch Codex, create Findings, or authorize a report.
"""

from __future__ import annotations

from hashlib import sha256
from typing import Final, Literal, Self

from pydantic import Field, model_validator

from pajin.agentic.codex_recon_draft import CodexReconDraft, parse_codex_recon_draft
from pajin.agentic.codex_recon_projection import CodexReconProjection
from pajin.agentic.codex_routing import CodexAdvisoryStage, CodexAdvisoryWireModel
from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import FindingSeverity
from pajin.web_assessment.governed_campaign_evidence import (
    VerifiedGovernedWebCompletedCampaign,
    load_verified_governed_web_completed_campaign_evidence,
)
from pajin.web_assessment.governed_reporting import GovernedWebPromotion

CODEX_SOL_PENETRATION_INPUT_API_VERSION: Final = "pajin.dev/codex-sol-penetration-input/v1alpha1"
CODEX_SOL_VERIFIED_INPUT_API_VERSION: Final = "pajin.dev/codex-sol-verified-input/v1alpha1"
_PENETRATION_DOMAIN: Final = "pajin.codex-sol-penetration-input/v1alpha1"
_VERIFIED_DOMAIN: Final = "pajin.codex-sol-verified-input/v1alpha1"
_FINDING_REF_DOMAIN: Final = "pajin.codex-sol-finding-reference/v1alpha1"


class CodexSolPenetrationInput(CodexAdvisoryWireModel):
    """No live action recipe; only closed recon choices and opaque Evidence refs."""

    api_version: Literal["pajin.dev/codex-sol-penetration-input/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["CodexSolPenetrationInput"]
    stage: Literal[CodexAdvisoryStage.PENETRATION_REVIEW]
    recon_projection: CodexReconProjection = Field(alias="reconProjection")
    recon_draft: CodexReconDraft = Field(alias="reconDraft")
    target_content_embedded: Literal[False] = Field(alias="targetContentEmbedded")
    source_anchors_embedded: Literal[False] = Field(alias="sourceAnchorsEmbedded")
    action_recipe_embedded: Literal[False] = Field(alias="actionRecipeEmbedded")
    target_execution_authorized: Literal[False] = Field(alias="targetExecutionAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    report_delivery_authorized: Literal[False] = Field(alias="reportDeliveryAuthorized")
    input_digest: str = Field(alias="inputDigest", pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def bind_admitted_recon(self) -> Self:
        parse_codex_recon_draft(
            self.recon_draft.model_dump_json(by_alias=True).encode(),
            expected_projection=self.recon_projection,
        )
        material = self.model_dump(mode="json", by_alias=True, exclude={"input_digest"})
        if self.input_digest != discovery_digest(_PENETRATION_DOMAIN, material):
            raise ValueError("Sol penetration input digest differs")
        return self


class CodexSolFindingSignal(CodexAdvisoryWireModel):
    """A verified Finding reduced to a stable opaque ref and safe enums."""

    finding_ref: str = Field(alias="findingRef", pattern=r"^csf_[a-f0-9]{32}$")
    severity: FindingSeverity = Field(strict=False)
    threat_class: str = Field(alias="threatClass", pattern=r"^CWE-[0-9]{1,5}$")
    independently_verified: Literal[True] = Field(alias="independentlyVerified")


class CodexSolVerifiedInput(CodexAdvisoryWireModel):
    """Vulnerability or report draft facts from a sealed verified campaign."""

    api_version: Literal["pajin.dev/codex-sol-verified-input/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["CodexSolVerifiedInput"]
    stage: Literal[CodexAdvisoryStage.VULNERABILITY_ANALYSIS, CodexAdvisoryStage.REPORT_DRAFT]
    promotion_digest: str = Field(alias="promotionDigest", pattern=r"^[a-f0-9]{64}$")
    finding_signals: tuple[CodexSolFindingSignal, ...] = Field(
        alias="findingSignals", min_length=1, max_length=3, strict=False
    )
    target_content_embedded: Literal[False] = Field(alias="targetContentEmbedded")
    source_anchors_embedded: Literal[False] = Field(alias="sourceAnchorsEmbedded")
    raw_evidence_embedded: Literal[False] = Field(alias="rawEvidenceEmbedded")
    report_delivery_authorized: Literal[False] = Field(alias="reportDeliveryAuthorized")
    finding_authorized: Literal[False] = Field(alias="findingAuthorized")
    input_digest: str = Field(alias="inputDigest", pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def bind_verified_projection(self) -> Self:
        refs = tuple(signal.finding_ref for signal in self.finding_signals)
        if refs != tuple(sorted(set(refs))):
            raise ValueError("Sol Finding references must be unique and sorted")
        material = self.model_dump(mode="json", by_alias=True, exclude={"input_digest"})
        if self.input_digest != discovery_digest(_VERIFIED_DOMAIN, material):
            raise ValueError("Sol verified input digest differs")
        return self


def build_codex_sol_penetration_input(
    projection: CodexReconProjection,
    draft: CodexReconDraft,
) -> CodexSolPenetrationInput:
    """Revalidate the inert Luna result before exposing it to a later Sol route."""

    projection = CodexReconProjection.model_validate(projection.model_dump(mode="json"))
    draft = parse_codex_recon_draft(
        draft.model_dump_json(by_alias=True).encode(), expected_projection=projection
    )
    payload = {
        "apiVersion": CODEX_SOL_PENETRATION_INPUT_API_VERSION,
        "kind": "CodexSolPenetrationInput",
        "stage": CodexAdvisoryStage.PENETRATION_REVIEW.value,
        "reconProjection": projection.model_dump(mode="json", by_alias=True),
        "reconDraft": draft.model_dump(mode="json", by_alias=True),
        "targetContentEmbedded": False,
        "sourceAnchorsEmbedded": False,
        "actionRecipeEmbedded": False,
        "targetExecutionAuthorized": False,
        "findingAuthorized": False,
        "reportDeliveryAuthorized": False,
    }
    return CodexSolPenetrationInput.model_validate(
        {**payload, "inputDigest": discovery_digest(_PENETRATION_DOMAIN, payload)}
    )


def build_codex_sol_verified_input(
    source: VerifiedGovernedWebCompletedCampaign,
    *,
    stage: CodexAdvisoryStage,
) -> CodexSolVerifiedInput:
    """Strictly reload sealed Findings and export only bounded, target-neutral facts."""

    if type(source) is not VerifiedGovernedWebCompletedCampaign:
        raise ValueError("Sol verified input requires a strictly loaded completed campaign")
    if stage not in (
        CodexAdvisoryStage.VULNERABILITY_ANALYSIS,
        CodexAdvisoryStage.REPORT_DRAFT,
    ):
        raise ValueError("Sol verified input has an invalid stage")
    reloaded = load_verified_governed_web_completed_campaign_evidence(
        source.parent_run_path,
        expected_parent_run_id=source.parent_run_id,
        expected_parent_root_digest=source.parent_root_digest,
        expected_campaign_plan_digest=source.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=source.deployment_trust_anchor_digest,
    )
    promotion = GovernedWebPromotion.model_validate(reloaded.evidence.promotion)
    if not promotion.findings:
        raise ValueError("Sol verified input has no independently confirmed Findings")
    finding_signals = sorted(
        (
            {
                "findingRef": "csf_"
                + sha256(f"{_FINDING_REF_DOMAIN}:{finding.finding_id}".encode()).hexdigest()[:32],
                "severity": finding.severity.value,
                "threatClass": finding.threat_class,
                "independentlyVerified": True,
            }
            for finding in promotion.findings
        ),
        key=lambda item: item["findingRef"],
    )
    payload = {
        "apiVersion": CODEX_SOL_VERIFIED_INPUT_API_VERSION,
        "kind": "CodexSolVerifiedInput",
        "stage": stage.value,
        "promotionDigest": promotion.promotion_digest,
        "findingSignals": finding_signals,
        "targetContentEmbedded": False,
        "sourceAnchorsEmbedded": False,
        "rawEvidenceEmbedded": False,
        "reportDeliveryAuthorized": False,
        "findingAuthorized": False,
    }
    return CodexSolVerifiedInput.model_validate(
        {**payload, "inputDigest": discovery_digest(_VERIFIED_DOMAIN, payload)}
    )
