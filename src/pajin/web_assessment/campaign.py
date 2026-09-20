"""Strict, inert WEB-004 draft and local reconciliation contracts.

The local WEB-003 authorization is an exact loopback assertion. It is never
compiled into a core Campaign, Capability grant, ActionPermit, or execution
authority here. A draft previews the exact requested scope and names the
governed prerequisites that a later, authenticated deployment must satisfy.

Run references are built only from caller-pinned, source-integrity-verified
WEB-003 content. Reconciliation can report local corroboration, mismatch, or
inconclusive evidence, but it cannot attest independent execution, mint a
Finding, authorize SARIF export, or perform external delivery.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.capabilities.models import CapabilityDefinitionRef, CapabilitySideEffectClass
from pajin.capabilities.web_browser_assessment import (
    WEB_BROWSER_ASSESSMENT_METHODS,
    WEB_BROWSER_ASSESSMENT_ORIGIN,
    WEB_BROWSER_ASSESSMENT_REQUEST_UNITS,
    WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST,
    WEB_BROWSER_ASSESSMENT_TOOL_ID,
    WebBrowserAssessmentPlanRef,
    WebBrowserAssessmentProfileRef,
    registered_web_browser_assessment_capability_definition,
)
from pajin.capabilities.web_browser_assessment import (
    WebBrowserAssessmentPlan as CapabilityWebBrowserAssessmentPlan,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import StrictModel, ToolRiskTier
from pajin.web_assessment.models import (
    AttackPath,
    IssueCheck,
    IssueStatus,
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentResult,
    WebAssessmentPlan,
)
from pajin.web_assessment.semantic import (
    ValidatedLocalWebSemanticClaims,
    ValidatedWebIssueClaim,
    validate_local_web_assessment_semantics,
)
from pajin.web_assessment.verification import VerifiedLocalWebAssessmentSourceIntegrity

WEB_ASSESSMENT_CAMPAIGN_DRAFT_API_VERSION: Final[
    Literal["pajin.dev/local-web-campaign-draft/v1alpha1"]
] = "pajin.dev/local-web-campaign-draft/v1alpha1"
WEB_ASSESSMENT_CAMPAIGN_PREPARATION_API_VERSION: Final[
    Literal["pajin.dev/local-web-campaign-preparation/v1alpha1"]
] = "pajin.dev/local-web-campaign-preparation/v1alpha1"
WEB_ASSESSMENT_RUN_REF_API_VERSION: Final[Literal["pajin.dev/local-web-run-ref/v1alpha1"]] = (
    "pajin.dev/local-web-run-ref/v1alpha1"
)
WEB_ASSESSMENT_CAMPAIGN_RESULT_API_VERSION: Final[
    Literal["pajin.dev/local-web-campaign-result/v1alpha1"]
] = "pajin.dev/local-web-campaign-result/v1alpha1"

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"

RunRole = Literal["source", "validation"]
ReconciliationOutcome = Literal["local-corroborated", "mismatch", "inconclusive"]


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class LocalWebAssessmentScopePreview(_FrozenStrictModel):
    """Non-authoritative preview derived only from the exact WEB-003 plan."""

    origin: Literal["http://127.0.0.1:3000"] = WEB_BROWSER_ASSESSMENT_ORIGIN
    allow: tuple[Literal["http://127.0.0.1:3000"], ...] = (WEB_BROWSER_ASSESSMENT_ORIGIN,)
    deny: tuple[str, ...] = Field(max_length=20)
    allowed_methods: tuple[Literal["GET", "HEAD", "POST"], ...] = Field(
        alias="allowedMethods",
        min_length=3,
        max_length=3,
    )
    allowed_post_paths: tuple[str, ...] = Field(
        alias="allowedPostPaths",
        min_length=1,
        max_length=10,
    )
    allow_private_networks: Literal[True] = Field(
        default=True,
        alias="allowPrivateNetworks",
    )
    request_unit_ceiling: Literal[100] = Field(
        default=100,
        alias="requestUnitCeiling",
    )

    @field_validator("allow_private_networks", mode="before")
    @classmethod
    def require_private_network_preview(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-004 scope preview must disclose private-network scope")
        return value

    @model_validator(mode="after")
    def bind_fixed_scope_shape(self) -> Self:
        if (
            self.allow != (self.origin,)
            or self.allowed_methods != WEB_BROWSER_ASSESSMENT_METHODS
            or self.request_unit_ceiling != WEB_BROWSER_ASSESSMENT_REQUEST_UNITS
        ):
            raise ValueError("WEB-004 scope preview differs from the registered boundary")
        return self


class LocalWebAssessmentCampaignDraft(_FrozenStrictModel):
    """Content-addressed local intent that deliberately is not a core Campaign."""

    api_version: Literal["pajin.dev/local-web-campaign-draft/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_CAMPAIGN_DRAFT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LocalWebAssessmentCampaignDraft"] = "LocalWebAssessmentCampaignDraft"
    draft_id: str = Field(default="", alias="draftId", max_length=100)
    draft_digest: str = Field(default="", alias="draftDigest", max_length=64)
    source_plan: WebAssessmentPlan = Field(alias="sourcePlan")
    source_plan_digest: str = Field(alias="sourcePlanDigest", pattern=_SHA256_PATTERN)
    local_authorization: LocalWebAssessmentAuthorization = Field(alias="localAuthorization")
    authorization_id: str = Field(alias="authorizationId", min_length=1, max_length=110)
    evaluated_at: datetime = Field(alias="evaluatedAt")
    origin: Literal["http://127.0.0.1:3000"] = WEB_BROWSER_ASSESSMENT_ORIGIN
    scope_preview: LocalWebAssessmentScopePreview = Field(alias="scopePreview")
    required_capability: CapabilityDefinitionRef = Field(alias="requiredCapability")
    required_risk_tier: Literal["T2"] = Field(default="T2", alias="requiredRiskTier")
    fresh_action_approval_required: Literal[True] = Field(
        default=True,
        alias="freshActionApprovalRequired",
    )
    signed_lifecycle_activation_required: Literal[True] = Field(
        default=True,
        alias="signedLifecycleActivationRequired",
    )
    durable_action_permit_required: Literal[True] = Field(
        default=True,
        alias="durableActionPermitRequired",
    )
    gateway_worker_execution_required: Literal[True] = Field(
        default=True,
        alias="gatewayWorkerExecutionRequired",
    )
    account_receipt_authentication_required: Literal[True] = Field(
        default=True,
        alias="accountReceiptAuthenticationRequired",
    )
    credential_delivery_authority_required: Literal[True] = Field(
        default=True,
        alias="credentialDeliveryAuthorityRequired",
    )
    login_state_mutation_authority_required: Literal[True] = Field(
        default=True,
        alias="loginStateMutationAuthorityRequired",
    )
    cleanup_authority_and_permit_required: Literal[True] = Field(
        default=True,
        alias="cleanupAuthorityAndPermitRequired",
    )
    local_authorization_semantics: Literal["local-assertion-not-core-approval"] = Field(
        default="local-assertion-not-core-approval",
        alias="localAuthorizationSemantics",
    )
    campaign_manifest_compiled: Literal[False] = Field(
        default=False,
        alias="campaignManifestCompiled",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    lifecycle_activated: Literal[False] = Field(default=False, alias="lifecycleActivated")
    action_permit_issued: Literal[False] = Field(default=False, alias="actionPermitIssued")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    gateway_dispatched: Literal[False] = Field(default=False, alias="gatewayDispatched")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")

    @field_validator("evaluated_at")
    @classmethod
    def normalize_evaluation_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("WEB-004 draft evaluation requires an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "fresh_action_approval_required",
        "signed_lifecycle_activation_required",
        "durable_action_permit_required",
        "gateway_worker_execution_required",
        "account_receipt_authentication_required",
        "credential_delivery_authority_required",
        "login_state_mutation_authority_required",
        "cleanup_authority_and_permit_required",
        mode="before",
    )
    @classmethod
    def require_governed_prerequisite(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-004 draft cannot remove a governed execution prerequisite")
        return value

    @field_validator(
        "campaign_manifest_compiled",
        "capability_granted",
        "lifecycle_activated",
        "action_permit_issued",
        "execution_authorized",
        "gateway_dispatched",
        "finding_authority",
        mode="before",
    )
    @classmethod
    def prohibit_draft_authority(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-004 local draft cannot assert core or execution authority")
        return value

    @model_validator(mode="after")
    def bind_draft(self) -> Self:
        canonical_plan = _canonical_source_plan(self.source_plan)
        canonical_authorization = _canonical_local_authorization(self.local_authorization)
        definition = registered_web_browser_assessment_capability_definition()
        canonical_authorization.require_current(plan=canonical_plan, now=self.evaluated_at)
        if (
            self.source_plan != canonical_plan
            or self.local_authorization != canonical_authorization
            or self.source_plan_digest != canonical_plan.plan_digest
            or self.authorization_id != canonical_authorization.authorization_id
            or self.origin != canonical_plan.origin
            or self.origin != canonical_authorization.origin
            or self.scope_preview != _scope_preview(canonical_plan)
            or self.required_capability != definition.reference()
            or self.required_risk_tier != "T2"
            or definition.risk_tier != ToolRiskTier.T2
            or definition.tool.tool_id != WEB_BROWSER_ASSESSMENT_TOOL_ID
            or definition.side_effect_class != CapabilitySideEffectClass.IRREVERSIBLE_WRITE
            or not definition.approval_required
            or not definition.cleanup_required
            or definition.request_unit_cost != WEB_BROWSER_ASSESSMENT_REQUEST_UNITS
        ):
            raise ValueError(
                "WEB-004 draft differs from the exact plan, local assertion, scope, "
                "or registered Capability"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"draft_id", "draft_digest"},
        )
        expected_digest = discovery_digest(
            "pajin.web-assessment.campaign-draft/v1",
            material,
        )
        expected_id = f"local-web-campaign-draft_{expected_digest}"
        if self.draft_digest and self.draft_digest != expected_digest:
            raise ValueError("WEB-004 Campaign draft digest differs")
        if self.draft_id and self.draft_id != expected_id:
            raise ValueError("WEB-004 Campaign draft ID differs")
        object.__setattr__(self, "draft_digest", expected_digest)
        object.__setattr__(self, "draft_id", expected_id)
        return self


class LocalWebAssessmentCampaignPreparation(_FrozenStrictModel):
    """Inert draft plus exact registration-only Capability plan and references."""

    api_version: Literal["pajin.dev/local-web-campaign-preparation/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_CAMPAIGN_PREPARATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LocalWebAssessmentCampaignPreparation"] = "LocalWebAssessmentCampaignPreparation"
    preparation_digest: str = Field(default="", alias="preparationDigest", max_length=64)
    role: RunRole
    draft: LocalWebAssessmentCampaignDraft
    capability_plan: CapabilityWebBrowserAssessmentPlan = Field(alias="capabilityPlan")
    capability: CapabilityDefinitionRef
    profile: WebBrowserAssessmentProfileRef
    plan: WebBrowserAssessmentPlanRef
    campaign_manifest_compiled: Literal[False] = Field(
        default=False,
        alias="campaignManifestCompiled",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    lifecycle_activated: Literal[False] = Field(default=False, alias="lifecycleActivated")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    action_permit_issued: Literal[False] = Field(default=False, alias="actionPermitIssued")
    gateway_dispatched: Literal[False] = Field(default=False, alias="gatewayDispatched")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")

    @field_validator(
        "campaign_manifest_compiled",
        "capability_granted",
        "lifecycle_activated",
        "execution_authorized",
        "action_permit_issued",
        "gateway_dispatched",
        "finding_authority",
        mode="before",
    )
    @classmethod
    def prohibit_preparation_authority(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-004 preparation cannot assert core or execution authority")
        return value

    @model_validator(mode="after")
    def bind_preparation(self) -> Self:
        definition = registered_web_browser_assessment_capability_definition()
        receipt = self.capability_plan.parameters.account_receipt
        if (
            self.capability != definition.reference()
            or self.capability_plan.profile.capability.capability != self.capability
            or self.profile != self.capability_plan.profile.reference()
            or self.plan != self.capability_plan.reference()
            or self.capability_plan.profile.source_plan_digest != self.draft.source_plan_digest
            or self.capability_plan.parameters.source_plan_digest != self.draft.source_plan_digest
            or self.capability_plan.profile.origin != self.draft.origin
            or self.capability_plan.parameters.origin != self.draft.origin
            or receipt.origin != self.draft.origin
            or receipt.source_plan_digest != self.draft.source_plan_digest
            or not self.draft.local_authorization.approved_at
            <= receipt.issued_at
            <= self.draft.evaluated_at
            < receipt.expires_at
            <= self.draft.local_authorization.expires_at
        ):
            raise ValueError("WEB-004 preparation differs from its draft or exact Capability plan")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"preparation_digest"},
        )
        expected = discovery_digest(
            "pajin.web-assessment.campaign-preparation/v1",
            material,
        )
        if self.preparation_digest and self.preparation_digest != expected:
            raise ValueError("WEB-004 Campaign preparation digest differs")
        object.__setattr__(self, "preparation_digest", expected)
        return self


class LocalWebAssessmentRunReference(_FrozenStrictModel):
    """Content pin for one verified WEB-003 source, without Permit semantics."""

    api_version: Literal["pajin.dev/local-web-run-ref/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_RUN_REF_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LocalWebAssessmentRunReference"] = "LocalWebAssessmentRunReference"
    reference_digest: str = Field(default="", alias="referenceDigest", max_length=64)
    role: RunRole
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    root_digest: str = Field(alias="rootDigest", pattern=_SHA256_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_SHA256_PATTERN)
    authorization_id: str = Field(alias="authorizationId", min_length=1, max_length=110)
    plan: WebAssessmentPlan
    authorization: LocalWebAssessmentAuthorization
    result: LocalWebAssessmentResult
    semantic_claims: ValidatedLocalWebSemanticClaims = Field(alias="semanticClaims")
    source_integrity_semantics: Literal["source-integrity-only"] = Field(
        default="source-integrity-only",
        alias="sourceIntegritySemantics",
    )
    source_integrity_verified: Literal[True] = Field(
        default=True,
        alias="sourceIntegrityVerified",
    )
    execution_permit_attested: Literal[False] = Field(
        default=False,
        alias="executionPermitAttested",
    )
    independent: Literal[False] = False
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")

    @field_validator("source_integrity_verified", mode="before")
    @classmethod
    def require_source_integrity_marker(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-004 Run reference requires verified source integrity")
        return value

    @field_validator(
        "execution_permit_attested",
        "independent",
        "finding_authority",
        mode="before",
    )
    @classmethod
    def prohibit_run_authority(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("WEB-004 Run reference cannot assert Permit or independent authority")
        return value

    @model_validator(mode="after")
    def bind_reference(self) -> Self:
        canonical_plan = _canonical_source_plan(self.plan)
        canonical_authorization = _canonical_local_authorization(self.authorization)
        canonical_result = _canonical_result(self.result)
        try:
            canonical_authorization.require_current(
                plan=canonical_plan,
                now=canonical_result.started_at,
            )
        except ValueError as exc:
            raise ValueError(
                "WEB-004 Run reference differs from its exact local assertion"
            ) from exc
        expected_claims = validate_local_web_assessment_semantics(canonical_result)
        if (
            self.plan != canonical_plan
            or self.authorization != canonical_authorization
            or self.result != canonical_result
            or self.run_id != canonical_result.run_id
            or self.result_digest != canonical_result.result_digest
            or self.authorization_id != canonical_authorization.authorization_id
            or canonical_result.plan_name != canonical_plan.name
            or canonical_result.plan_digest != canonical_plan.plan_digest
            or canonical_result.authorization_id != canonical_authorization.authorization_id
            or canonical_result.origin != canonical_plan.origin
            or canonical_result.origin != canonical_authorization.origin
            or canonical_result.target_product != canonical_plan.target_product
            or canonical_result.finished_at > canonical_authorization.expires_at
            or self.semantic_claims != expected_claims
        ):
            raise ValueError(
                "WEB-004 Run reference differs from its verified plan, assertion, Result, "
                "or semantic claims"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"reference_digest"},
        )
        expected = discovery_digest("pajin.web-assessment.run-reference/v1", material)
        if self.reference_digest and self.reference_digest != expected:
            raise ValueError("WEB-004 Run reference digest differs")
        object.__setattr__(self, "reference_digest", expected)
        return self


class WebAssessmentClaimReconciliation(_FrozenStrictModel):
    check: IssueCheck
    source_status: IssueStatus = Field(alias="sourceStatus")
    validation_status: IssueStatus = Field(alias="validationStatus")
    source_claim_digest: str = Field(alias="sourceClaimDigest", pattern=_SHA256_PATTERN)
    validation_claim_digest: str = Field(
        alias="validationClaimDigest",
        pattern=_SHA256_PATTERN,
    )
    source_semantic_digest: str = Field(
        alias="sourceSemanticDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_semantic_digest: str = Field(
        alias="validationSemanticDigest",
        pattern=_SHA256_PATTERN,
    )
    outcome: ReconciliationOutcome


class WebAssessmentAttackPathReconciliation(_FrozenStrictModel):
    ordinal: int = Field(strict=True, ge=1, le=20)
    source_path_id: str = Field(
        alias="sourcePathId",
        pattern=r"^web-attack-path:[a-f0-9]{64}$",
    )
    validation_path_id: str = Field(
        alias="validationPathId",
        pattern=r"^web-attack-path:[a-f0-9]{64}$",
    )
    source_stage_ids: tuple[str, ...] = Field(
        alias="sourceStageIds",
        min_length=2,
        max_length=8,
    )
    validation_stage_ids: tuple[str, ...] = Field(
        alias="validationStageIds",
        min_length=2,
        max_length=8,
    )
    source_status: Literal["locally-validated", "incomplete"] = Field(alias="sourceStatus")
    validation_status: Literal["locally-validated", "incomplete"] = Field(alias="validationStatus")
    source_semantic_digest: str = Field(
        alias="sourceSemanticDigest",
        pattern=_SHA256_PATTERN,
    )
    validation_semantic_digest: str = Field(
        alias="validationSemanticDigest",
        pattern=_SHA256_PATTERN,
    )
    outcome: ReconciliationOutcome


class LocalWebAssessmentCampaignResult(_FrozenStrictModel):
    """Deterministic local comparison with every external authority marker off."""

    api_version: Literal["pajin.dev/local-web-campaign-result/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_CAMPAIGN_RESULT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LocalWebAssessmentCampaignResult"] = "LocalWebAssessmentCampaignResult"
    result_digest: str = Field(default="", alias="resultDigest", max_length=64)
    plan: WebAssessmentPlan
    source: LocalWebAssessmentRunReference
    validation: LocalWebAssessmentRunReference
    claim_reconciliations: tuple[WebAssessmentClaimReconciliation, ...] = Field(
        alias="claimReconciliations",
        min_length=3,
        max_length=3,
    )
    attack_path_reconciliations: tuple[WebAssessmentAttackPathReconciliation, ...] = Field(
        alias="attackPathReconciliations",
        min_length=1,
        max_length=20,
    )
    outcome: ReconciliationOutcome
    reconciled_at: datetime = Field(alias="reconciledAt")
    reconciliation_semantics: Literal["local-corroboration-only"] = Field(
        default="local-corroboration-only",
        alias="reconciliationSemantics",
    )
    local_reconciliation_only: Literal[True] = Field(
        default=True,
        alias="localReconciliationOnly",
    )
    campaign_manifest_compiled: Literal[False] = Field(
        default=False,
        alias="campaignManifestCompiled",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    action_permit_issued: Literal[False] = Field(default=False, alias="actionPermitIssued")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    execution_permit_attested: Literal[False] = Field(
        default=False,
        alias="executionPermitAttested",
    )
    gateway_dispatched: Literal[False] = Field(default=False, alias="gatewayDispatched")
    web_executor_attested: Literal[False] = Field(
        default=False,
        alias="webExecutorAttested",
    )
    target_attested: Literal[False] = Field(default=False, alias="targetAttested")
    independent_execution_attested: Literal[False] = Field(
        default=False,
        alias="independentExecutionAttested",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    sarif_export_authorized: Literal[False] = Field(
        default=False,
        alias="sarifExportAuthorized",
    )
    external_delivery_performed: Literal[False] = Field(
        default=False,
        alias="externalDeliveryPerformed",
    )

    @field_validator("reconciled_at")
    @classmethod
    def normalize_reconciliation_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("WEB-004 reconciliation time requires an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("local_reconciliation_only", mode="before")
    @classmethod
    def require_local_only(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("WEB-004 must disclose its local-only reconciliation scope")
        return value

    @field_validator(
        "campaign_manifest_compiled",
        "capability_granted",
        "action_permit_issued",
        "execution_authorized",
        "execution_permit_attested",
        "gateway_dispatched",
        "web_executor_attested",
        "target_attested",
        "independent_execution_attested",
        "finding_authority",
        "sarif_export_authorized",
        "external_delivery_performed",
        mode="before",
    )
    @classmethod
    def prohibit_authority_escalation(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "WEB-004 reconciliation cannot assert execution, Finding, SARIF, "
                "or delivery authority"
            )
        return value

    @model_validator(mode="after")
    def bind_campaign_result(self) -> Self:
        canonical_plan = _canonical_source_plan(self.plan)
        if self.plan != canonical_plan:
            raise ValueError("WEB-004 reconciliation plan is not canonical")
        self._require_distinct_sources(canonical_plan)
        expected_claims = _claim_reconciliations(self.source, self.validation)
        expected_paths = _attack_path_reconciliations(self.source, self.validation)
        if self.claim_reconciliations != expected_claims:
            raise ValueError("WEB-004 typed claim reconciliation differs")
        if self.attack_path_reconciliations != expected_paths:
            raise ValueError("WEB-004 attack-path shape or status reconciliation differs")
        expected_outcome = _overall_outcome((*expected_claims, *expected_paths))
        if self.outcome != expected_outcome:
            raise ValueError("WEB-004 campaign outcome differs from its reconciliations")
        if self.reconciled_at < max(
            self.source.result.finished_at,
            self.validation.result.finished_at,
        ):
            raise ValueError("WEB-004 reconciliation predates a source Result")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_digest"},
        )
        expected_digest = discovery_digest(
            "pajin.web-assessment.campaign-result/v1",
            material,
        )
        if self.result_digest and self.result_digest != expected_digest:
            raise ValueError("WEB-004 Campaign Result digest differs")
        object.__setattr__(self, "result_digest", expected_digest)
        return self

    def _require_distinct_sources(self, canonical_plan: WebAssessmentPlan) -> None:
        source = self.source
        validation = self.validation
        if source.role != "source" or validation.role != "validation":
            raise ValueError("WEB-004 Run roles differ from source and validation")
        if source.plan != canonical_plan or validation.plan != canonical_plan:
            raise ValueError("WEB-004 Run references belong to another plan")
        for source_value, validation_value, label in (
            (source.run_id, validation.run_id, "Run IDs"),
            (source.root_digest, validation.root_digest, "Run root digests"),
            (source.result_digest, validation.result_digest, "Result digests"),
            (
                source.authorization_id,
                validation.authorization_id,
                "local authorization IDs",
            ),
        ):
            if source_value == validation_value:
                raise ValueError(f"WEB-004 source and validation require distinct {label}")
        if source.result.target_version != validation.result.target_version:
            raise ValueError("WEB-004 Run references observed different target versions")


def build_local_web_assessment_campaign_draft(
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    *,
    evaluated_at: datetime | None = None,
) -> LocalWebAssessmentCampaignDraft:
    """Build local intent without compiling or authorizing a core Campaign."""

    canonical_plan = _canonical_source_plan(plan)
    canonical_authorization = _canonical_local_authorization(authorization)
    now = evaluated_at or datetime.now(UTC)
    canonical_authorization.require_current(plan=canonical_plan, now=now)
    definition = registered_web_browser_assessment_capability_definition()
    return LocalWebAssessmentCampaignDraft(
        sourcePlan=canonical_plan,
        sourcePlanDigest=canonical_plan.plan_digest,
        localAuthorization=canonical_authorization,
        authorizationId=canonical_authorization.authorization_id,
        evaluatedAt=now,
        origin=WEB_BROWSER_ASSESSMENT_ORIGIN,
        scopePreview=_scope_preview(canonical_plan),
        requiredCapability=definition.reference(),
    )


def prepare_local_web_assessment_campaign(
    *,
    role: RunRole,
    source_plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    capability_plan: CapabilityWebBrowserAssessmentPlan,
    evaluated_at: datetime | None = None,
) -> LocalWebAssessmentCampaignPreparation:
    """Bind an inert local draft to an exact registration-only Capability plan."""

    draft = build_local_web_assessment_campaign_draft(
        source_plan,
        authorization,
        evaluated_at=evaluated_at,
    )
    canonical_capability_plan = CapabilityWebBrowserAssessmentPlan.model_validate(
        capability_plan.model_dump(mode="json", by_alias=True)
    )
    definition = registered_web_browser_assessment_capability_definition()
    return LocalWebAssessmentCampaignPreparation(
        role=role,
        draft=draft,
        capabilityPlan=canonical_capability_plan,
        capability=definition.reference(),
        profile=canonical_capability_plan.profile.reference(),
        plan=canonical_capability_plan.reference(),
    )


def local_web_assessment_run_reference(
    *,
    role: RunRole,
    verified_source: VerifiedLocalWebAssessmentSourceIntegrity,
) -> LocalWebAssessmentRunReference:
    """Pin one verified WEB-003 source without inventing execution authority."""

    if type(verified_source) is not VerifiedLocalWebAssessmentSourceIntegrity:
        raise TypeError("WEB-004 Run reference requires caller-pinned verified WEB-003 source")
    verification = verified_source.verification
    canonical_plan = _canonical_source_plan(verified_source.plan)
    canonical_authorization = _canonical_local_authorization(verified_source.authorization)
    canonical_result = _canonical_result(verified_source.result)
    expected_screenshots = tuple(
        page.screenshot_reference for page in canonical_result.browser.pages
    )
    if (
        type(verification.valid) is not bool
        or verification.valid is not True
        or verification.run_id != canonical_result.run_id
        or verification.seal_count != 1
        or verification.event_count != 2
        or verification.artifact_count < 4 + len(expected_screenshots)
        or verified_source.semantics != "source-integrity-only"
        or type(verified_source.independent_replay_verified) is not bool
        or verified_source.independent_replay_verified is not False
        or type(verified_source.finding_authority) is not bool
        or verified_source.finding_authority is not False
        or verified_source.screenshot_references != expected_screenshots
    ):
        raise ValueError("caller-pinned WEB-003 source integrity or artifact identity differs")
    return LocalWebAssessmentRunReference(
        role=role,
        runId=canonical_result.run_id,
        rootDigest=verification.root_digest,
        resultDigest=canonical_result.result_digest,
        authorizationId=canonical_authorization.authorization_id,
        plan=canonical_plan,
        authorization=canonical_authorization,
        result=canonical_result,
        semanticClaims=validate_local_web_assessment_semantics(canonical_result),
    )


def reconcile_local_web_assessment_runs(
    *,
    plan: WebAssessmentPlan,
    source: LocalWebAssessmentRunReference,
    validation: LocalWebAssessmentRunReference,
    reconciled_at: datetime,
) -> LocalWebAssessmentCampaignResult:
    """Compare two distinct source-integrity pins without upgrading authority."""

    canonical_plan = _canonical_source_plan(plan)
    canonical_source = LocalWebAssessmentRunReference.model_validate(
        source.model_dump(mode="json", by_alias=True)
    )
    canonical_validation = LocalWebAssessmentRunReference.model_validate(
        validation.model_dump(mode="json", by_alias=True)
    )
    claims = _claim_reconciliations(canonical_source, canonical_validation)
    paths = _attack_path_reconciliations(canonical_source, canonical_validation)
    return LocalWebAssessmentCampaignResult(
        plan=canonical_plan,
        source=canonical_source,
        validation=canonical_validation,
        claimReconciliations=claims,
        attackPathReconciliations=paths,
        outcome=_overall_outcome((*claims, *paths)),
        reconciledAt=reconciled_at,
    )


def _canonical_source_plan(plan: WebAssessmentPlan) -> WebAssessmentPlan:
    canonical = WebAssessmentPlan.model_validate(plan.model_dump(mode="json", by_alias=True))
    if (
        canonical.origin != WEB_BROWSER_ASSESSMENT_ORIGIN
        or canonical.plan_digest != WEB_BROWSER_ASSESSMENT_SOURCE_PLAN_DIGEST
    ):
        raise ValueError("WEB-004 requires the exact registered WEB-003 source plan")
    return canonical


def _canonical_local_authorization(
    authorization: LocalWebAssessmentAuthorization,
) -> LocalWebAssessmentAuthorization:
    return LocalWebAssessmentAuthorization.model_validate(
        authorization.model_dump(mode="json", by_alias=True)
    )


def _canonical_result(result: LocalWebAssessmentResult) -> LocalWebAssessmentResult:
    return LocalWebAssessmentResult.model_validate(result.model_dump(mode="json", by_alias=True))


def _scope_preview(plan: WebAssessmentPlan) -> LocalWebAssessmentScopePreview:
    return LocalWebAssessmentScopePreview(
        origin=WEB_BROWSER_ASSESSMENT_ORIGIN,
        allow=(WEB_BROWSER_ASSESSMENT_ORIGIN,),
        deny=tuple(plan.origin + path for path in plan.deny_paths),
        allowedMethods=WEB_BROWSER_ASSESSMENT_METHODS,
        allowedPostPaths=plan.allowed_post_paths,
    )


def _claim_reconciliations(
    source: LocalWebAssessmentRunReference,
    validation: LocalWebAssessmentRunReference,
) -> tuple[WebAssessmentClaimReconciliation, ...]:
    comparisons: list[WebAssessmentClaimReconciliation] = []
    for source_claim, validation_claim in zip(
        source.semantic_claims.claims,
        validation.semantic_claims.claims,
        strict=True,
    ):
        source_digest = _claim_semantic_digest(source_claim)
        validation_digest = _claim_semantic_digest(validation_claim)
        outcome: ReconciliationOutcome
        if "inconclusive" in (source_claim.status, validation_claim.status):
            outcome = "inconclusive"
        elif source_digest == validation_digest:
            outcome = "local-corroborated"
        else:
            outcome = "mismatch"
        comparisons.append(
            WebAssessmentClaimReconciliation(
                check=source_claim.check,
                sourceStatus=source_claim.status,
                validationStatus=validation_claim.status,
                sourceClaimDigest=source_claim.claim_digest,
                validationClaimDigest=validation_claim.claim_digest,
                sourceSemanticDigest=source_digest,
                validationSemanticDigest=validation_digest,
                outcome=outcome,
            )
        )
    return tuple(comparisons)


def _claim_semantic_digest(claim: ValidatedWebIssueClaim) -> str:
    material = {
        "check": claim.check,
        "cwe": claim.cwe,
        "severity": claim.severity,
        "status": claim.status,
        "trials": [
            {
                "repetition": trial.repetition,
                "reproduced": trial.reproduced,
                "controlsPassed": trial.controls_passed,
                "codeOwnedOraclePassed": trial.code_owned_oracle_passed,
            }
            for trial in claim.trials
        ],
    }
    return discovery_digest("pajin.web-assessment.claim-semantics/v1", material)


def _attack_path_reconciliations(
    source: LocalWebAssessmentRunReference,
    validation: LocalWebAssessmentRunReference,
) -> tuple[WebAssessmentAttackPathReconciliation, ...]:
    comparisons: list[WebAssessmentAttackPathReconciliation] = []
    source_checks = {issue.issue_id: issue.check for issue in source.result.issues}
    validation_checks = {issue.issue_id: issue.check for issue in validation.result.issues}
    for ordinal, (source_path, validation_path) in enumerate(
        zip(source.result.attack_paths, validation.result.attack_paths, strict=True),
        start=1,
    ):
        source_digest = _attack_path_semantic_digest(source_path, source_checks)
        validation_digest = _attack_path_semantic_digest(
            validation_path,
            validation_checks,
        )
        if source_path.status == validation_path.status == "incomplete":
            outcome: ReconciliationOutcome = "inconclusive"
        elif source_digest == validation_digest:
            outcome = "local-corroborated"
        else:
            outcome = "mismatch"
        comparisons.append(
            WebAssessmentAttackPathReconciliation(
                ordinal=ordinal,
                sourcePathId=source_path.path_id,
                validationPathId=validation_path.path_id,
                sourceStageIds=tuple(stage.stage_id for stage in source_path.stages),
                validationStageIds=tuple(stage.stage_id for stage in validation_path.stages),
                sourceStatus=source_path.status,
                validationStatus=validation_path.status,
                sourceSemanticDigest=source_digest,
                validationSemanticDigest=validation_digest,
                outcome=outcome,
            )
        )
    return tuple(comparisons)


def _attack_path_semantic_digest(
    path: AttackPath,
    issue_checks: dict[str, IssueCheck],
) -> str:
    material = {
        "status": path.status,
        "stages": [
            {
                "ordinal": stage.ordinal,
                "stageId": stage.stage_id,
                "state": stage.state,
                "issueCheck": (
                    issue_checks[stage.issue_id] if stage.issue_id is not None else None
                ),
            }
            for stage in path.stages
        ],
    }
    return discovery_digest("pajin.web-assessment.attack-path-semantics/v1", material)


def _overall_outcome(
    reconciliations: tuple[
        WebAssessmentClaimReconciliation | WebAssessmentAttackPathReconciliation,
        ...,
    ],
) -> ReconciliationOutcome:
    outcomes = {item.outcome for item in reconciliations}
    if "mismatch" in outcomes:
        return "mismatch"
    if "inconclusive" in outcomes:
        return "inconclusive"
    return "local-corroborated"
