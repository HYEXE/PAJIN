"""Read-only Control Plane projection for local Campaign Builder drafts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from hmac import compare_digest
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, field_validator

from pajin.control_plane.errors import ResourceNotFound, StateConflict
from pajin.domain.models import StrictModel
from pajin.workflow.campaign_builder import (
    CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME,
    CampaignBuilderArtifactError,
    CampaignBuilderGate,
    CampaignBuilderSourceKind,
    CampaignProfileScopeDraft,
    load_campaign_profile_scope_draft,
)

CAMPAIGN_DRAFT_VIEW_API_VERSION: Literal[
    "pajin.control-plane/campaign-draft-view/v1alpha1"
] = "pajin.control-plane/campaign-draft-view/v1alpha1"
CAMPAIGN_DRAFT_DIGEST_PATTERN = r"^[a-f0-9]{64}$"

_CAMPAIGN_DRAFT_DIGEST = re.compile(CAMPAIGN_DRAFT_DIGEST_PATTERN)


class CampaignDraftView(StrictModel):
    """Bounded projection that deliberately excludes the embedded typed source."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.control-plane/campaign-draft-view/v1alpha1"
    ] = Field(default=CAMPAIGN_DRAFT_VIEW_API_VERSION, alias="apiVersion")
    kind: Literal["CampaignDraftView"] = "CampaignDraftView"
    draft_id: str = Field(
        alias="draftId",
        pattern=r"^campaign-builder-draft:[a-f0-9]{64}$",
    )
    draft_digest: str = Field(alias="draftDigest", pattern=CAMPAIGN_DRAFT_DIGEST_PATTERN)
    profile_id: str = Field(
        alias="profileId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    profile_version: Literal["1.0.0"] = Field(alias="profileVersion")
    source_kind: CampaignBuilderSourceKind = Field(alias="sourceKind")
    allow_rule_count: int = Field(alias="allowRuleCount", strict=True, ge=1, le=1_000)
    deny_rule_count: int = Field(alias="denyRuleCount", strict=True, ge=0, le=1_000)
    target_input_count: int = Field(alias="targetInputCount", strict=True, ge=1, le=1_000)
    review_only_source_count: int = Field(
        alias="reviewOnlySourceCount",
        strict=True,
        ge=0,
        le=1_000,
    )
    required_gates: tuple[CampaignBuilderGate, ...] = Field(
        alias="requiredGates",
        min_length=1,
        max_length=2,
    )
    draft_state: Literal["input-validated-not-compiled"] = Field(alias="draftState")
    scope_authorized: Literal[False] = Field(alias="scopeAuthorized")
    campaign_manifest_compiled: Literal[False] = Field(alias="campaignManifestCompiled")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")

    @field_validator(
        "scope_authorized",
        "campaign_manifest_compiled",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Campaign draft view authority markers must be boolean false")
        return value

    @classmethod
    def from_draft(cls, draft: CampaignProfileScopeDraft) -> CampaignDraftView:
        preview = draft.scope_preview
        return cls(
            draftId=draft.draft_id,
            draftDigest=draft.draft_digest,
            profileId=draft.selected_profile.profile_id,
            profileVersion=draft.selected_profile.profile_version,
            sourceKind=draft.source_kind,
            allowRuleCount=len(preview.allow),
            denyRuleCount=len(preview.deny),
            targetInputCount=len(preview.target_inputs),
            reviewOnlySourceCount=len(preview.review_only_source_ids),
            requiredGates=draft.required_gates,
            draftState=draft.draft_state,
            scopeAuthorized=preview.scope_authorized,
            campaignManifestCompiled=draft.campaign_manifest_compiled,
            capabilityGranted=draft.capability_granted,
            permitGranted=draft.permit_granted,
            executionAuthorized=draft.execution_authorized,
        )


@dataclass(frozen=True, slots=True)
class ControlPlaneCampaignDraftReader:
    """Resolve only exact digest keys under one server-configured draft root."""

    root: Path | None

    def get(self, draft_digest: str) -> CampaignDraftView:
        if self.root is None:
            raise StateConflict("Campaign Builder draft root is not configured")
        if _CAMPAIGN_DRAFT_DIGEST.fullmatch(draft_digest) is None:
            raise ResourceNotFound("Campaign Builder draft was not found or failed verification")

        artifact_path = (
            self.root / draft_digest / CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME
        )
        try:
            draft = load_campaign_profile_scope_draft(artifact_path)
        except CampaignBuilderArtifactError as exc:
            raise ResourceNotFound(
                "Campaign Builder draft was not found or failed verification"
            ) from exc
        if not compare_digest(draft.draft_digest, draft_digest):
            raise ResourceNotFound(
                "Campaign Builder draft was not found or failed verification"
            )
        return CampaignDraftView.from_draft(draft)
