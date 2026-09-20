"""Runnable, non-authoritative WEB-004 observation bridge for local Juice Shop.

This module deliberately separates two facts that are easy to conflate:

* WEB-003 can be run directly under its exact, operator-attested local-lab
  authorization; and
* the registered browser Capability is not lifecycle activated and has no
  ActionPermit, Gateway route, or executor attestation yet.

The bridge provisions one disposable account outside the registered Capability,
runs and strictly reloads WEB-003, applies the code-owned semantic oracle, opens a
fresh authenticated context for passive discovery, and performs two fixed GET-only
diagnostics.  Its sealed output is therefore useful local observation material, but
it cannot mint Findings, admit proposals into the Graph, export SARIF, or deliver
externally.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.web_browser_assessment import (
    WEB_BROWSER_ASSESSMENT_ORIGIN,
    WebBrowserAssessmentProfile,
    WebBrowserAssessmentTool,
    WebBrowserProvisionedAccountReceipt,
    registered_web_browser_assessment_plan,
    registered_web_browser_assessment_profile,
    web_browser_assessment_capability_bundle,
)
from pajin.capabilities.web_browser_assessment import (
    WebBrowserAssessmentPlan as RegisteredWebBrowserAssessmentPlan,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import StrictModel
from pajin.runtime.store import (
    RunIntegrityError,
    RunIntegrityVerification,
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
    verify_run_integrity,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.tools.base import ToolRegistry
from pajin.web_assessment.browser import PlaywrightAssessmentBrowser
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignDraft,
    LocalWebAssessmentCampaignPreparation,
    LocalWebAssessmentRunReference,
    build_local_web_assessment_campaign_draft,
    local_web_assessment_run_reference,
    prepare_local_web_assessment_campaign,
)
from pajin.web_assessment.discovery import (
    BrowserDiscoveryPlan,
    BrowserDiscoveryResult,
    browser_discovery_plan,
)
from pajin.web_assessment.discovery_runtime import (
    BrowserDiscoverySessionFactory,
    PlaywrightAuthenticatedDiscoverySession,
    run_authenticated_browser_discovery,
)
from pajin.web_assessment.extra_diagnostics import (
    FTPDirectoryListingResult,
    SecurityHeaderPostureResult,
    diagnose_ftp_directory_listing,
    diagnose_security_header_posture,
)
from pajin.web_assessment.graph_projection import (
    LocalWebNeutralGraphProjection,
    build_local_web_neutral_graph_projection,
    build_local_web_sealed_source_authority,
)
from pajin.web_assessment.models import (
    LocalWebAssessmentAuthorization,
    RequestEvidence,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import (
    BrowserFactory,
    LocalWebAssessmentArtifacts,
    NetworkFactory,
    ProvisionedLocalWebAssessmentAccount,
    assessment_policy,
    provision_local_web_assessment_account,
    run_local_web_assessment,
)
from pajin.web_assessment.semantic import ValidatedLocalWebSemanticClaims
from pajin.web_assessment.verification import (
    VerifiedLocalWebAssessmentSourceIntegrity,
    load_verified_local_web_assessment_source_integrity,
)

LOCAL_WEB_CAMPAIGN_OBSERVATION_API_VERSION: Literal[
    "pajin.dev/local-web-campaign-observation/v1alpha1"
] = "pajin.dev/local-web-campaign-observation/v1alpha1"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_RUN_ID_PATTERN = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_EXPECTED_ARTIFACTS = frozenset(
    {
        "campaign-draft.json",
        "campaign-preparation.json",
        "capability-account-receipt.json",
        "capability-plan.json",
        "capability-profile.json",
        "discovery-plan.json",
        "discovery-result.json",
        "extra-ftp-directory-listing.json",
        "extra-security-header-posture.json",
        "graph-projection.json",
        "report.md",
        "result.json",
        "semantic-claims.json",
        "source-reference.json",
    }
)
_JSON_ARTIFACT_LIMIT = 16 * 1024 * 1024
_REPORT_ARTIFACT_LIMIT = 16 * 1024 * 1024


class LocalWebCampaignObservationError(RuntimeError):
    """The local-only WEB-004 observation could not be completed safely."""


class LocalWebCampaignObservationIntegrityError(ValueError):
    """A sealed local-only WEB-004 observation failed strict reloading."""


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class LocalWebCampaignObservationResult(_FrozenStrictModel):
    """One sealed direct local observation with every authority upgrade disabled."""

    api_version: Literal["pajin.dev/local-web-campaign-observation/v1alpha1"] = Field(
        default=LOCAL_WEB_CAMPAIGN_OBSERVATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LocalWebCampaignObservationResult"] = "LocalWebCampaignObservationResult"
    result_digest: str = Field(default="", alias="resultDigest", max_length=64)
    run_id: str = Field(alias="runId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    semantics: Literal["local-observation-only"] = "local-observation-only"
    assessment_plan: WebAssessmentPlan = Field(alias="assessmentPlan")
    authorization: LocalWebAssessmentAuthorization
    campaign_draft: LocalWebAssessmentCampaignDraft = Field(alias="campaignDraft")
    campaign_draft_digest: str = Field(
        alias="campaignDraftDigest",
        pattern=_SHA256_PATTERN,
    )
    campaign_preparation: LocalWebAssessmentCampaignPreparation = Field(alias="campaignPreparation")
    account_receipt: WebBrowserProvisionedAccountReceipt = Field(alias="accountReceipt")
    capability_profile: WebBrowserAssessmentProfile = Field(alias="capabilityProfile")
    capability_plan: RegisteredWebBrowserAssessmentPlan = Field(alias="capabilityPlan")
    source: LocalWebAssessmentRunReference
    neutral_graph_projection: LocalWebNeutralGraphProjection = Field(alias="neutralGraphProjection")
    discovery_plan: BrowserDiscoveryPlan = Field(alias="discoveryPlan")
    discovery: BrowserDiscoveryResult
    discovery_requests: tuple[RequestEvidence, ...] = Field(
        default=(), alias="discoveryRequests", max_length=500
    )
    extra_diagnostics: tuple[SecurityHeaderPostureResult, FTPDirectoryListingResult] = Field(
        alias="extraDiagnostics"
    )
    extra_diagnostic_requests: tuple[RequestEvidence, ...] = Field(
        alias="extraDiagnosticRequests", min_length=6, max_length=6
    )
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    account_provisioned_outside_capability: Literal[True] = Field(
        default=True,
        alias="accountProvisionedOutsideCapability",
    )
    account_retained_in_local_lab: Literal[True] = Field(
        default=True,
        alias="accountRetainedInLocalLab",
    )
    source_integrity_verified: Literal[True] = Field(
        default=True,
        alias="sourceIntegrityVerified",
    )
    semantic_validation_applied: Literal[True] = Field(
        default=True,
        alias="semanticValidationApplied",
    )
    authenticated_passive_discovery_completed: Literal[True] = Field(
        default=True,
        alias="authenticatedPassiveDiscoveryCompleted",
    )
    passive_extra_diagnostics_completed: Literal[True] = Field(
        default=True,
        alias="passiveExtraDiagnosticsCompleted",
    )
    neutral_graph_proposals_built: Literal[True] = Field(
        default=True,
        alias="neutralGraphProposalsBuilt",
    )
    source_identity_pin_independently_supplied: Literal[False] = Field(
        default=False,
        alias="sourceIdentityPinIndependentlySupplied",
    )
    action_permit_issued: Literal[False] = Field(default=False, alias="actionPermitIssued")
    lifecycle_activated: Literal[False] = Field(default=False, alias="lifecycleActivated")
    gateway_dispatched: Literal[False] = Field(default=False, alias="gatewayDispatched")
    independent_execution_attested: Literal[False] = Field(
        default=False,
        alias="independentExecutionAttested",
    )
    graph_admission: Literal[False] = Field(default=False, alias="graphAdmission")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    sarif_export: Literal[False] = Field(default=False, alias="sarifExport")
    external_delivery: Literal[False] = Field(default=False, alias="externalDelivery")
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    query_values_persisted: Literal[False] = Field(default=False, alias="queryValuesPersisted")
    raw_dom_persisted: Literal[False] = Field(default=False, alias="rawDomPersisted")
    extra_response_bodies_persisted: Literal[False] = Field(
        default=False,
        alias="extraResponseBodiesPersisted",
    )
    absolute_paths_persisted: Literal[False] = Field(
        default=False,
        alias="absolutePathsPersisted",
    )

    @field_validator("started_at", "finished_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("local observation times require an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "account_provisioned_outside_capability",
        "account_retained_in_local_lab",
        "source_integrity_verified",
        "semantic_validation_applied",
        "authenticated_passive_discovery_completed",
        "passive_extra_diagnostics_completed",
        "neutral_graph_proposals_built",
        mode="before",
    )
    @classmethod
    def require_observed_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("completed local observation markers must be boolean true")
        return value

    @field_validator(
        "action_permit_issued",
        "source_identity_pin_independently_supplied",
        "lifecycle_activated",
        "gateway_dispatched",
        "independent_execution_attested",
        "graph_admission",
        "finding_authority",
        "sarif_export",
        "external_delivery",
        "credentials_persisted",
        "query_values_persisted",
        "raw_dom_persisted",
        "extra_response_bodies_persisted",
        "absolute_paths_persisted",
        mode="before",
    )
    @classmethod
    def prohibit_authority_or_retention_escalation(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "local observation authority and sensitive-retention markers must be false"
            )
        return value

    @model_validator(mode="after")
    def bind_local_observation(self) -> Self:
        expected_plan = juice_shop_plan(WEB_BROWSER_ASSESSMENT_ORIGIN)
        if self.assessment_plan != expected_plan:
            raise ValueError("local observation requires the exact code-owned Juice Shop Plan")
        try:
            self.authorization.require_current(
                plan=expected_plan,
                now=self.source.result.started_at,
            )
            self.authorization.require_current(plan=expected_plan, now=self.finished_at)
        except ValueError as exc:
            raise ValueError("local observation differs from its exact authorization") from exc
        if not self.started_at <= self.account_receipt.issued_at <= self.finished_at:
            raise ValueError("local observation chronology differs from account provisioning")
        if self.source.result.finished_at > self.finished_at:
            raise ValueError("local observation finished before its WEB-003 source")
        if (
            self.source.role != "source"
            or self.source.plan != expected_plan
            or self.source.authorization != self.authorization
        ):
            raise ValueError("local observation source differs from its exact local assertion")
        expected_draft = build_local_web_assessment_campaign_draft(
            expected_plan,
            self.authorization,
            evaluated_at=self.source.result.started_at,
        )
        expected_profile, expected_capability_plan = _registration_only_material(
            self.account_receipt
        )
        expected_preparation = prepare_local_web_assessment_campaign(
            role="source",
            source_plan=expected_plan,
            authorization=self.authorization,
            capability_plan=expected_capability_plan,
            evaluated_at=self.source.result.started_at,
        )
        if (
            self.campaign_draft != expected_draft
            or self.campaign_draft_digest != expected_draft.draft_digest
            or self.campaign_preparation != expected_preparation
            or self.capability_profile != expected_profile
            or self.capability_plan != expected_capability_plan
            or self.account_receipt.issued_at > self.source.result.started_at
            or self.account_receipt.expires_at != self.authorization.expires_at
        ):
            raise ValueError("local observation draft or Capability preparation differs")
        source_authority = self.neutral_graph_projection.source_authority
        if (
            source_authority.campaign_draft_id != self.campaign_draft.draft_id
            or source_authority.campaign_draft_digest != self.campaign_draft.draft_digest
            or source_authority.run_role != self.source.role
            or source_authority.run_id != self.source.run_id
            or source_authority.run_reference_digest != self.source.reference_digest
            or source_authority.source_root_digest != self.source.root_digest
            or source_authority.result_digest != self.source.result_digest
            or source_authority.source_plan_digest != self.source.plan.plan_digest
            or source_authority.authorization_id != self.source.authorization_id
            or source_authority.semantic_claims_digest != self.source.semantic_claims.claims_digest
            or source_authority.source_identity_pin_independently_supplied
            or self.neutral_graph_projection.graph_admission_performed
            or self.neutral_graph_projection.finding_authority
            or self.neutral_graph_projection.sarif_authority
            or self.neutral_graph_projection.independent_execution_attested
        ):
            raise ValueError("local observation neutral Graph projection differs")
        if (
            self.discovery_plan
            != browser_discovery_plan(
                WEB_BROWSER_ASSESSMENT_ORIGIN,
                seed_routes=("/#/",),
            )
            or self.discovery.plan_digest != self.discovery_plan.plan_digest
            or self.discovery.origin != WEB_BROWSER_ASSESSMENT_ORIGIN
        ):
            raise ValueError("local observation passive discovery differs from its Plan")
        _require_unique_request_evidence(self.discovery_requests, label="discovery")
        _require_unique_request_evidence(
            self.extra_diagnostic_requests,
            label="extra diagnostic",
        )
        referenced_extra_evidence = tuple(
            evidence_id
            for diagnostic in self.extra_diagnostics
            for trial in diagnostic.trials
            for evidence_id in trial.evidence_ids
        )
        if referenced_extra_evidence != tuple(
            item.evidence_id for item in self.extra_diagnostic_requests
        ):
            raise ValueError("local observation extra diagnostics differ from HTTP Evidence")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
        )
        expected_digest = discovery_digest(
            "pajin.web-assessment.local-campaign-observation/v1",
            material,
        )
        if self.result_digest and self.result_digest != expected_digest:
            raise ValueError("local observation Result Digest differs")
        object.__setattr__(self, "result_digest", expected_digest)
        return self


@dataclass(frozen=True, slots=True)
class LocalWebCampaignObservationArtifacts:
    result: LocalWebCampaignObservationResult
    run_path: Path
    result_path: Path
    report_path: Path
    root_digest: str
    source_artifacts: LocalWebAssessmentArtifacts


@dataclass(frozen=True, slots=True)
class VerifiedLocalWebCampaignObservation:
    run_path: Path
    verification: RunIntegrityVerification
    result: LocalWebCampaignObservationResult
    report_markdown: str


def _require_unique_request_evidence(
    evidence: tuple[RequestEvidence, ...],
    *,
    label: str,
) -> None:
    evidence_ids = [item.evidence_id for item in evidence]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError(f"local observation {label} Evidence IDs must be unique")


def _registration_only_material(
    receipt: WebBrowserProvisionedAccountReceipt,
) -> tuple[WebBrowserAssessmentProfile, RegisteredWebBrowserAssessmentPlan]:
    tools = ToolRegistry()
    tools.register(WebBrowserAssessmentTool())
    bundle = web_browser_assessment_capability_bundle(tools)
    return (
        registered_web_browser_assessment_profile(bundle, receipt),
        registered_web_browser_assessment_plan(bundle, receipt),
    )


def build_registration_only_account_receipt(
    account: ProvisionedLocalWebAssessmentAccount,
    *,
    authorization: LocalWebAssessmentAuthorization,
) -> WebBrowserProvisionedAccountReceipt:
    """Convert secret-free provisioning metadata into an unauthenticated opaque receipt."""

    if account.origin != WEB_BROWSER_ASSESSMENT_ORIGIN:
        raise LocalWebCampaignObservationError(
            "registration-only receipt requires the exact Juice Shop origin"
        )
    account.require_current(
        plan=juice_shop_plan(WEB_BROWSER_ASSESSMENT_ORIGIN),
        authorization=authorization,
        now=account.provisioned_at,
    )
    safe_receipt = account.receipt()
    account_reference_digest = discovery_digest(
        "pajin.web-assessment.nonsecret-account-reference/v1",
        {
            "authorizationId": account.authorization_id,
            "origin": account.origin,
            "planDigest": account.plan_digest,
            "provisionedAt": account.provisioned_at.isoformat(),
            "targetVersion": account.target_version,
        },
    )
    provisioning_evidence_digest = discovery_digest(
        "pajin.web-assessment.secret-free-provisioning-receipt/v1",
        safe_receipt,
    )
    issuer_authority_digest = discovery_digest(
        "pajin.web-assessment.unauthenticated-local-authorization-reference/v1",
        authorization.model_dump(mode="json", by_alias=True),
    )
    return WebBrowserProvisionedAccountReceipt(
        accountReferenceDigest=account_reference_digest,
        provisioningEvidenceDigest=provisioning_evidence_digest,
        issuerAuthorityDigest=issuer_authority_digest,
        issuedAt=account.provisioned_at,
        expiresAt=authorization.expires_at,
    )


def _source_reference(
    *,
    source_artifacts: LocalWebAssessmentArtifacts,
) -> tuple[
    VerifiedLocalWebAssessmentSourceIntegrity,
    LocalWebAssessmentRunReference,
]:
    verified = load_verified_local_web_assessment_source_integrity(
        source_artifacts.run_path,
        expected_run_id=source_artifacts.result.run_id,
        expected_root_digest=source_artifacts.root_digest,
    )
    return (
        verified,
        local_web_assessment_run_reference(
            role="source",
            verified_source=verified,
        ),
    )


async def run_local_web_campaign_observation(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    output_root: Path,
    headless: bool = True,
    browser_factory: BrowserFactory = PlaywrightAssessmentBrowser,
    network_factory: NetworkFactory = AssessmentNetwork,
    discovery_session_factory: BrowserDiscoverySessionFactory = (
        PlaywrightAuthenticatedDiscoverySession
    ),
) -> LocalWebCampaignObservationArtifacts:
    """Run the direct local bridge without manufacturing Capability authority."""

    canonical_plan = WebAssessmentPlan.model_validate(plan.model_dump(mode="json", by_alias=True))
    exact_plan = juice_shop_plan(WEB_BROWSER_ASSESSMENT_ORIGIN)
    if canonical_plan != exact_plan:
        raise LocalWebCampaignObservationError(
            "WEB-004 observation requires the exact 127.0.0.1:3000 Juice Shop Plan"
        )
    canonical_authorization = LocalWebAssessmentAuthorization.model_validate(
        authorization.model_dump(mode="json", by_alias=True)
    )
    started_at = datetime.now(UTC)
    canonical_authorization.require_current(plan=canonical_plan, now=started_at)
    store = RunStore.create(output_root, canonical_plan.name + "-local-observation")
    store.append_event(
        "local-web-campaign-observation.started",
        {
            "origin": canonical_plan.origin,
            "planDigest": canonical_plan.plan_digest,
            "semantics": "local-observation-only",
        },
        occurred_at=started_at,
    )
    account: ProvisionedLocalWebAssessmentAccount | None = None
    source_artifacts: LocalWebAssessmentArtifacts | None = None
    try:
        account = await provision_local_web_assessment_account(
            plan=canonical_plan,
            authorization=canonical_authorization,
            network_factory=network_factory,
        )
        account_receipt = build_registration_only_account_receipt(
            account,
            authorization=canonical_authorization,
        )
        capability_profile, capability_plan = _registration_only_material(account_receipt)
        source_artifacts = await run_local_web_assessment(
            plan=canonical_plan,
            authorization=canonical_authorization,
            output_root=output_root,
            headless=headless,
            browser_factory=browser_factory,
            network_factory=network_factory,
            provisioned_account=account,
        )
        verified_source, source = _source_reference(source_artifacts=source_artifacts)
        campaign_draft = build_local_web_assessment_campaign_draft(
            canonical_plan,
            canonical_authorization,
            evaluated_at=source.result.started_at,
        )
        campaign_preparation = prepare_local_web_assessment_campaign(
            role="source",
            source_plan=canonical_plan,
            authorization=canonical_authorization,
            capability_plan=capability_plan,
            evaluated_at=source.result.started_at,
        )
        source_authority = build_local_web_sealed_source_authority(
            draft=campaign_draft,
            run_reference=source,
            source=verified_source,
            source_identity_pin_independently_supplied=False,
        )
        graph_projection = build_local_web_neutral_graph_projection(
            source_authority=source_authority,
            draft=campaign_draft,
            run_reference=source,
            source=verified_source,
        )
        selected_discovery_plan = browser_discovery_plan(
            WEB_BROWSER_ASSESSMENT_ORIGIN,
            seed_routes=("/#/",),
        )

        discovery_network = network_factory(canonical_plan)
        discovery_network.bind_authorization_deadline(canonical_authorization.expires_at)
        try:
            discovery = await run_authenticated_browser_discovery(
                assessment_plan=canonical_plan,
                discovery_plan=selected_discovery_plan,
                network=discovery_network,
                credentials=account.credentials,
                navigation_policy=assessment_policy(canonical_plan, max_requests=100),
                headless=headless,
                session_factory=discovery_session_factory,
            )
            discovery_requests = tuple(discovery_network.evidence)
        finally:
            await discovery_network.close()

        diagnostic_network = network_factory(canonical_plan)
        diagnostic_network.bind_authorization_deadline(canonical_authorization.expires_at)
        try:
            security_headers = await diagnose_security_header_posture(network=diagnostic_network)
            ftp_listing = await diagnose_ftp_directory_listing(network=diagnostic_network)
            diagnostic_requests = tuple(diagnostic_network.evidence)
        finally:
            await diagnostic_network.close()

        finished_at = datetime.now(UTC)
        canonical_authorization.require_current(plan=canonical_plan, now=finished_at)
        result = LocalWebCampaignObservationResult(
            runId=store.run_id,
            assessmentPlan=canonical_plan,
            authorization=canonical_authorization,
            campaignDraft=campaign_draft,
            campaignDraftDigest=campaign_draft.draft_digest,
            campaignPreparation=campaign_preparation,
            accountReceipt=account_receipt,
            capabilityProfile=capability_profile,
            capabilityPlan=capability_plan,
            source=source,
            neutralGraphProjection=graph_projection,
            discoveryPlan=selected_discovery_plan,
            discovery=discovery,
            discoveryRequests=discovery_requests,
            extraDiagnostics=(security_headers, ftp_listing),
            extraDiagnosticRequests=diagnostic_requests,
            startedAt=started_at,
            finishedAt=finished_at,
        )
        _write_observation_artifacts(store, result)
        store.append_event(
            "local-web-campaign-observation.completed",
            {
                "resultDigest": result.result_digest,
                "sourceRunId": result.source.run_id,
                "semantics": result.semantics,
            },
            occurred_at=finished_at,
        )
        seal = store.seal()
        verification = verify_run_integrity(store.path)
        if verification.root_digest != seal.root_digest:
            raise LocalWebCampaignObservationError("sealed local observation verification differs")
        return LocalWebCampaignObservationArtifacts(
            result=result,
            run_path=store.path,
            result_path=store.path / "result.json",
            report_path=store.path / "report.md",
            root_digest=seal.root_digest,
            source_artifacts=source_artifacts,
        )
    except (Exception, asyncio.CancelledError):
        try:
            store.write_json_create_only(
                "failure.json",
                {
                    "accountRetainedInLocalLab": account is not None,
                    "credentialsPersisted": False,
                    "actionPermitIssued": False,
                    "gatewayDispatched": False,
                    "findingAuthority": False,
                    "externalDelivery": False,
                },
            )
            store.append_event(
                "local-web-campaign-observation.failed",
                {"semantics": "local-observation-only"},
            )
            store.seal()
        except Exception:
            pass
        raise
    finally:
        account = None


def _write_observation_artifacts(
    store: RunStore,
    result: LocalWebCampaignObservationResult,
) -> None:
    artifacts: tuple[tuple[str, StrictModel], ...] = (
        ("campaign-draft.json", result.campaign_draft),
        ("campaign-preparation.json", result.campaign_preparation),
        ("capability-account-receipt.json", result.account_receipt),
        ("capability-plan.json", result.capability_plan),
        ("capability-profile.json", result.capability_profile),
        ("discovery-plan.json", result.discovery_plan),
        ("discovery-result.json", result.discovery),
        ("extra-ftp-directory-listing.json", result.extra_diagnostics[1]),
        ("extra-security-header-posture.json", result.extra_diagnostics[0]),
        ("graph-projection.json", result.neutral_graph_projection),
        ("semantic-claims.json", result.source.semantic_claims),
        ("source-reference.json", result.source),
    )
    for path, artifact in artifacts:
        store.write_json_create_only(
            path,
            artifact.model_dump(mode="json", by_alias=True, exclude_none=True),
        )
    store.write_json_create_only(
        "result.json",
        result.model_dump(mode="json", by_alias=True, exclude_none=True),
    )
    store.write_text_create_only(
        "report.md",
        render_local_web_campaign_observation_report(result),
    )


def render_local_web_campaign_observation_report(
    result: LocalWebCampaignObservationResult,
) -> str:
    """Render only code-owned, deterministic statements from the strict Result."""

    canonical = LocalWebCampaignObservationResult.model_validate(
        result.model_dump(mode="json", by_alias=True)
    )
    lines = [
        "# WEB-004 Local Web Campaign Observation",
        "",
        "## Scope and authority",
        "",
        f"- Origin: `{canonical.assessment_plan.origin}`",
        f"- Semantics: `{canonical.semantics}`",
        "- Disposable account: provisioned outside the registered Capability and retained "
        "in the approved local lab",
        "- Campaign state: inert local draft; no core CampaignManifest compiled",
        "- Capability state: irreversible-write, cleanup-required, registered, not activated",
        "- Credential delivery, login-state mutation, and cleanup authority: absent",
        "- ActionPermit issued: no",
        "- Gateway dispatch: no",
        "- Independent execution attestation: no",
        "- Graph admission, Finding authority, SARIF export, and external delivery: no",
        "",
        "## Source-integrity and semantic checks",
        "",
        f"- WEB-003 source Run: `{canonical.source.run_id}`",
        f"- Source root digest: `{canonical.source.root_digest}`",
        "- Verification scope: sealed source integrity plus code-owned fact semantics; "
        "not independent replay",
        "- Source identity pin in this CLI flow: producer-derived, not independently supplied",
        "",
        "| Check | Local status |",
        "| --- | --- |",
    ]
    for claim in canonical.source.semantic_claims.claims:
        lines.append(f"| `{claim.check}` | `{claim.status}` |")
    lines.extend(
        [
            "",
            "## Bounded attack paths",
            "",
            "| Path | Local status | Stages |",
            "| --- | --- | ---: |",
        ]
    )
    for path in canonical.source.result.attack_paths:
        lines.append(f"| {path.title} | `{path.status}` | {len(path.stages)} |")
    lines.extend(
        [
            "",
            "## Authenticated passive discovery",
            "",
            f"- Query-free routes retained: {len(canonical.discovery.routes)}",
            f"- Value-free forms retained: {len(canonical.discovery.forms)}",
            f"- HTTP Evidence records: {len(canonical.discovery_requests)}",
            "- Raw DOM, screenshots, form values, and submissions retained/performed: no",
            "",
            "## Neutral Graph proposal material",
            "",
            "- Authority kind: `sealed-source-authority`",
            "- Observation proposals: 1",
            "- Hypothesis proposals: "
            f"{len(canonical.neutral_graph_projection.hypothesis_proposals)}",
            "- Capability Grant, ActionPermit, approval receipt, Graph admission, and Finding "
            "authority: absent",
            "",
            "## Additional passive diagnostics",
            "",
            "| Check | Local status | Impact boundary |",
            "| --- | --- | --- |",
        ]
    )
    for diagnostic in canonical.extra_diagnostics:
        lines.append(
            f"| `{diagnostic.check}` | `{diagnostic.status}` | {diagnostic.observed_impact} |"
        )
    lines.extend(
        [
            "",
            "## Retention and output boundary",
            "",
            "Credentials, query values, raw DOM, extra response bodies, and absolute local "
            "paths were not persisted in this outer Run.",
            "",
            "This report is local observation material only. Matching local outcomes do not "
            "create executor or target attestation and must not be promoted to a PAJIN "
            "Finding or SARIF result.",
            "",
            f"Result digest: `{canonical.result_digest}`",
            "",
        ]
    )
    return "\n".join(lines)


def _artifact_paths(snapshot: VerifiedRunSnapshot) -> set[str]:
    return {artifact.path for seal in snapshot.seals for artifact in seal.artifacts}


def _strict_model[T: StrictModel](
    snapshot: VerifiedRunSnapshot,
    path: str,
    model: type[T],
) -> T:
    raw = strict_json(
        snapshot,
        path,
        label=f"local observation {path}",
        max_bytes=_JSON_ARTIFACT_LIMIT,
        expected_type=dict,
    )
    return model.model_validate(raw)


def _require_separate_artifacts(
    snapshot: VerifiedRunSnapshot,
    result: LocalWebCampaignObservationResult,
) -> None:
    expected: Mapping[str, StrictModel] = {
        "campaign-draft.json": result.campaign_draft,
        "campaign-preparation.json": result.campaign_preparation,
        "capability-account-receipt.json": result.account_receipt,
        "capability-plan.json": result.capability_plan,
        "capability-profile.json": result.capability_profile,
        "discovery-plan.json": result.discovery_plan,
        "discovery-result.json": result.discovery,
        "extra-ftp-directory-listing.json": result.extra_diagnostics[1],
        "extra-security-header-posture.json": result.extra_diagnostics[0],
        "graph-projection.json": result.neutral_graph_projection,
        "semantic-claims.json": result.source.semantic_claims,
        "source-reference.json": result.source,
    }
    model_types: Mapping[str, type[StrictModel]] = {
        "campaign-draft.json": LocalWebAssessmentCampaignDraft,
        "campaign-preparation.json": LocalWebAssessmentCampaignPreparation,
        "capability-account-receipt.json": WebBrowserProvisionedAccountReceipt,
        "capability-plan.json": RegisteredWebBrowserAssessmentPlan,
        "capability-profile.json": WebBrowserAssessmentProfile,
        "discovery-plan.json": BrowserDiscoveryPlan,
        "discovery-result.json": BrowserDiscoveryResult,
        "extra-ftp-directory-listing.json": FTPDirectoryListingResult,
        "extra-security-header-posture.json": SecurityHeaderPostureResult,
        "graph-projection.json": LocalWebNeutralGraphProjection,
        "semantic-claims.json": ValidatedLocalWebSemanticClaims,
        "source-reference.json": LocalWebAssessmentRunReference,
    }
    for path, expected_value in expected.items():
        if _strict_model(snapshot, path, model_types[path]) != expected_value:
            raise LocalWebCampaignObservationIntegrityError(
                f"local observation separate artifact differs from Result: {path}"
            )


def load_verified_local_web_campaign_observation(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> VerifiedLocalWebCampaignObservation:
    """Strictly reload one pinned outer Run without upgrading its authority."""

    if _RUN_ID_PATTERN.fullmatch(expected_run_id) is None:
        raise LocalWebCampaignObservationIntegrityError(
            "expected local observation Run ID is invalid"
        )
    if re.fullmatch(_SHA256_PATTERN, expected_root_digest) is None:
        raise LocalWebCampaignObservationIntegrityError(
            "expected local observation root digest is invalid"
        )
    try:
        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        if (
            initial.verification.root_digest != expected_root_digest
            or initial.verification.seal_count != 1
            or initial.verification.event_count != 2
            or tuple(event.event_type for event in initial.events)
            != (
                "local-web-campaign-observation.started",
                "local-web-campaign-observation.completed",
            )
            or _artifact_paths(initial) != set(_EXPECTED_ARTIFACTS)
            or initial.verification.artifact_count != len(_EXPECTED_ARTIFACTS)
        ):
            raise LocalWebCampaignObservationIntegrityError(
                "sealed local observation Run shape differs"
            )
        requests = {
            path: (_REPORT_ARTIFACT_LIMIT if path == "report.md" else _JSON_ARTIFACT_LIMIT)
            for path in _EXPECTED_ARTIFACTS
        }
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests=requests,
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed local observation changed while artifacts were loaded",
        )
        result = _strict_model(
            loaded,
            "result.json",
            LocalWebCampaignObservationResult,
        )
        if result.run_id != expected_run_id:
            raise LocalWebCampaignObservationIntegrityError(
                "local observation Result differs from the expected Run"
            )
        _require_separate_artifacts(loaded, result)
        expected_report = render_local_web_campaign_observation_report(result).encode("utf-8")
        if loaded.artifact_bytes("report.md") != expected_report:
            raise LocalWebCampaignObservationIntegrityError(
                "local observation report differs from deterministic Result rendering"
            )
        started, completed = loaded.events
        if (
            started.occurred_at != result.started_at
            or started.payload
            != {
                "origin": result.assessment_plan.origin,
                "planDigest": result.assessment_plan.plan_digest,
                "semantics": result.semantics,
            }
            or completed.occurred_at != result.finished_at
            or completed.payload
            != {
                "resultDigest": result.result_digest,
                "sourceRunId": result.source.run_id,
                "semantics": result.semantics,
            }
        ):
            raise LocalWebCampaignObservationIntegrityError(
                "local observation audit events differ from Result"
            )
        final = load_verified_run_snapshot(
            initial.run_path,
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            final,
            message="sealed local observation changed during strict reload",
        )
        return VerifiedLocalWebCampaignObservation(
            run_path=initial.run_path,
            verification=initial.verification.model_copy(deep=True),
            result=result,
            report_markdown=expected_report.decode("utf-8"),
        )
    except LocalWebCampaignObservationIntegrityError:
        raise
    except (RunIntegrityError, UnicodeError, ValidationError, ValueError) as exc:
        raise LocalWebCampaignObservationIntegrityError(
            "sealed local observation failed strict verification"
        ) from exc


__all__ = [
    "LOCAL_WEB_CAMPAIGN_OBSERVATION_API_VERSION",
    "LocalWebCampaignObservationArtifacts",
    "LocalWebCampaignObservationError",
    "LocalWebCampaignObservationIntegrityError",
    "LocalWebCampaignObservationResult",
    "VerifiedLocalWebCampaignObservation",
    "build_registration_only_account_receipt",
    "load_verified_local_web_campaign_observation",
    "render_local_web_campaign_observation_report",
    "run_local_web_campaign_observation",
]
