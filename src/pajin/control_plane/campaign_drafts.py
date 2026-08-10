"""Read-only Control Plane projection for local Campaign Builder drafts."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hmac import compare_digest
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.control_plane.errors import ResourceNotFound, StateConflict
from pajin.domain.models import (
    CampaignManifest,
    CampaignMode,
    StrictModel,
    campaign_manifest_digest,
)
from pajin.modes.bug_bounty.models import (
    BugBountyProgramManifest,
    BugBountyScopeApproval,
)
from pajin.modes.bug_bounty.service import BugBountyScopeService
from pajin.modes.ctf.models import CTFChallengeManifest
from pajin.modes.ctf.service import CTFChallengeService
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
CAMPAIGN_DRAFT_COMPILATION_API_VERSION: Literal[
    "pajin.control-plane/campaign-draft-compilation/v1alpha1"
] = "pajin.control-plane/campaign-draft-compilation/v1alpha1"

_CAMPAIGN_DRAFT_DIGEST = re.compile(CAMPAIGN_DRAFT_DIGEST_PATTERN)
_CAMPAIGN_DRAFT_NOT_FOUND = "Campaign Builder draft was not found or failed verification"


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


class CampaignDraftCompilationRequest(StrictModel):
    """Explicit compiler handoff input with no caller-controlled evaluation time."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_kind: CampaignBuilderSourceKind = Field(alias="sourceKind")
    scope_approval: BugBountyScopeApproval | None = Field(
        default=None,
        alias="scopeApproval",
    )

    @model_validator(mode="after")
    def require_source_specific_approval(self) -> CampaignDraftCompilationRequest:
        has_approval = self.scope_approval is not None
        requires_approval = (
            self.source_kind is CampaignBuilderSourceKind.BUG_BOUNTY_PROGRAM
        )
        if has_approval != requires_approval:
            raise ValueError(
                "Bug Bounty compilation requires one separate Scope Approval and CTF forbids it"
            )
        return self


class CampaignDraftCompilationView(StrictModel):
    """One compiled Campaign with no persistence, execution, or delegated authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.control-plane/campaign-draft-compilation/v1alpha1"
    ] = Field(default=CAMPAIGN_DRAFT_COMPILATION_API_VERSION, alias="apiVersion")
    kind: Literal["CampaignDraftCompilation"] = "CampaignDraftCompilation"
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
    compiled_at: datetime = Field(alias="compiledAt")
    campaign_digest: str = Field(
        alias="campaignDigest",
        pattern=CAMPAIGN_DRAFT_DIGEST_PATTERN,
    )
    campaign: CampaignManifest
    campaign_manifest_compiled: Literal[True] = Field(alias="campaignManifestCompiled")
    campaign_persisted: Literal[False] = Field(alias="campaignPersisted")
    capability_granted: Literal[False] = Field(alias="capabilityGranted")
    permit_granted: Literal[False] = Field(alias="permitGranted")
    run_submitted: Literal[False] = Field(alias="runSubmitted")
    execution_authorized: Literal[False] = Field(alias="executionAuthorized")

    @field_validator("campaign_manifest_compiled", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Campaign compilation marker must be boolean true")
        return value

    @field_validator(
        "campaign_persisted",
        "capability_granted",
        "permit_granted",
        "run_submitted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Campaign compilation authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_compilation(self) -> CampaignDraftCompilationView:
        expected_profile_id, expected_mode = {
            CampaignBuilderSourceKind.BUG_BOUNTY_PROGRAM: (
                "pajin.profile.bug-hunt",
                CampaignMode.BUG_BOUNTY,
            ),
            CampaignBuilderSourceKind.CTF_CHALLENGE: (
                "pajin.profile.ctf",
                CampaignMode.CTF,
            ),
        }[self.source_kind]
        if (
            self.draft_id != f"campaign-builder-draft:{self.draft_digest}"
            or self.profile_id != expected_profile_id
            or self.campaign.spec.mode is not expected_mode
            or not compare_digest(
                self.campaign_digest,
                campaign_manifest_digest(self.campaign),
            )
            or self.compiled_at.tzinfo is None
            or self.compiled_at.utcoffset() is None
        ):
            raise ValueError("Campaign draft compilation binding is inconsistent")
        return self


def _utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class ControlPlaneCampaignDraftReader:
    """Resolve only exact digest keys under one server-configured draft root."""

    root: Path | None

    def get(self, draft_digest: str) -> CampaignDraftView:
        return CampaignDraftView.from_draft(self.load(draft_digest))

    def load(self, draft_digest: str) -> CampaignProfileScopeDraft:
        """Load one exact complete draft for an internal compiler handoff."""

        if self.root is None:
            raise StateConflict("Campaign Builder draft root is not configured")
        if _CAMPAIGN_DRAFT_DIGEST.fullmatch(draft_digest) is None:
            raise ResourceNotFound(_CAMPAIGN_DRAFT_NOT_FOUND)

        artifact_path = (
            self.root / draft_digest / CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME
        )
        try:
            draft = load_campaign_profile_scope_draft(artifact_path)
        except CampaignBuilderArtifactError as exc:
            raise ResourceNotFound(_CAMPAIGN_DRAFT_NOT_FOUND) from exc
        if not compare_digest(draft.draft_digest, draft_digest):
            raise ResourceNotFound(_CAMPAIGN_DRAFT_NOT_FOUND)
        return draft


@dataclass(frozen=True, slots=True)
class ControlPlaneCampaignDraftCompiler:
    """Hand one verified typed source and independent approval to an existing compiler."""

    reader: ControlPlaneCampaignDraftReader
    clock: Callable[[], datetime] = _utc_now

    def compile(
        self,
        draft_digest: str,
        request: CampaignDraftCompilationRequest,
    ) -> CampaignDraftCompilationView:
        draft = self.reader.load(draft_digest)
        if request.source_kind is not draft.source_kind:
            raise StateConflict("Campaign draft source kind does not match the compiler handoff")

        compiled_at = self.clock()
        if (
            not isinstance(compiled_at, datetime)
            or compiled_at.tzinfo is None
            or compiled_at.utcoffset() is None
        ):
            raise StateConflict("Campaign draft compiler clock is invalid")
        compiled_at = compiled_at.astimezone(UTC)

        try:
            campaign = self._compile_existing(draft, request, compiled_at=compiled_at)
        except ValueError as exc:
            raise StateConflict("Campaign draft compiler rejected the handoff") from exc

        try:
            canonical_campaign = CampaignManifest.model_validate_json(
                campaign.model_dump_json(by_alias=True)
            )
            return CampaignDraftCompilationView(
                draftId=draft.draft_id,
                draftDigest=draft.draft_digest,
                profileId=draft.selected_profile.profile_id,
                profileVersion=draft.selected_profile.profile_version,
                sourceKind=draft.source_kind,
                compiledAt=compiled_at,
                campaignDigest=campaign_manifest_digest(canonical_campaign),
                campaign=canonical_campaign,
                campaignManifestCompiled=True,
                campaignPersisted=False,
                capabilityGranted=False,
                permitGranted=False,
                runSubmitted=False,
                executionAuthorized=False,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise StateConflict("Campaign draft compiler produced an invalid Campaign") from exc

    @staticmethod
    def _compile_existing(
        draft: CampaignProfileScopeDraft,
        request: CampaignDraftCompilationRequest,
        *,
        compiled_at: datetime,
    ) -> CampaignManifest:
        if draft.source_kind is CampaignBuilderSourceKind.BUG_BOUNTY_PROGRAM:
            if not isinstance(draft.source, BugBountyProgramManifest):
                raise ValueError("Campaign draft typed source differs")
            if request.scope_approval is None:
                raise ValueError("Campaign draft Scope Approval is missing")
            return BugBountyScopeService().compile_campaign(
                draft.source,
                request.scope_approval,
                evaluated_at=compiled_at,
            )
        if not isinstance(draft.source, CTFChallengeManifest):
            raise ValueError("Campaign draft typed source differs")
        return CTFChallengeService().compile_campaign(
            draft.source,
            evaluated_at=compiled_at,
        )
