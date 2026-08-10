"""UX-001A/B1 non-executable Campaign, Profile, and Scope builder draft."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from hmac import compare_digest
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    ConfigDict,
    Field,
    StrictBool,
    ValidationError,
    field_validator,
    model_validator,
)

from pajin.domain.models import StrictModel
from pajin.modes.bug_bounty.models import (
    BugBountyProbeProfile,
    BugBountyProgramManifest,
)
from pajin.modes.bug_bounty.service import BugBountyScopeService
from pajin.modes.ctf.models import CTFCategory, CTFChallengeManifest
from pajin.runtime.safe_files import atomic_write_text_no_follow, load_bounded_strict_json
from pajin.tools.ctf import crypto_artifact_target
from pajin.workflow.campaign_profile import (
    CampaignProfileError,
    RegisteredCampaignProfile,
    registered_campaign_profile_catalog,
    resolve_registered_campaign_profile,
)
from pajin.workflow.common_engine import _common_engine_digest

CAMPAIGN_BUILDER_DRAFT_API_VERSION: Literal["pajin.dev/campaign-builder-draft/v1alpha1"] = (
    "pajin.dev/campaign-builder-draft/v1alpha1"
)
CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME = "campaign-profile-scope-draft.json"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_SOURCE_BYTES = 2 * 1024 * 1024
_MAX_DRAFT_BYTES = 512 * 1024
_MAX_DRAFT_ARTIFACT_BYTES = 4 * 1024 * 1024
_MAX_DRAFT_ARTIFACT_NODES = 50_000

_BUG_HUNT_PROFILE_ID = "pajin.profile.bug-hunt"
_CTF_PROFILE_ID = "pajin.profile.ctf"


class CampaignBuilderError(RuntimeError):
    """Raised when a typed builder source and selected Profile do not match."""


class CampaignBuilderArtifactError(CampaignBuilderError):
    """Raised when a local builder draft artifact cannot be stored or verified."""


class CampaignBuilderSourceKind(StrEnum):
    BUG_BOUNTY_PROGRAM = "bug-bounty-program"
    CTF_CHALLENGE = "ctf-challenge"


class CampaignBuilderGate(StrEnum):
    SCOPE_DIGEST_APPROVAL = "scope-digest-approval"
    AUTHORIZATION_WINDOW_RECHECK = "authorization-window-recheck"


def _require_literal_false(value: object) -> object:
    if type(value) is not bool or value is not False:
        raise ValueError("Campaign Builder authority markers must be boolean false")
    return value


class CampaignBuilderTargetInput(StrictModel):
    """One compiler-facing target input preview with no execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_id: str = Field(
        alias="sourceId",
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    target_type: Literal["bug-bounty-api", "http", "ctf-web", "ctf-crypto"] = Field(
        alias="targetType"
    )
    endpoint: str = Field(min_length=1, max_length=2_000)
    compiler_supported: StrictBool = Field(alias="compilerSupported")
    target_execution_authorized: Literal[False] = Field(
        default=False,
        alias="targetExecutionAuthorized",
    )

    @field_validator("target_execution_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_false(value)


class CampaignBuilderScopePreview(StrictModel):
    """Derived Scope and target preview; never an approved Campaign Scope."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    allow: tuple[str, ...] = Field(min_length=1, max_length=1_000)
    deny: tuple[str, ...] = Field(default=(), max_length=1_000)
    target_inputs: tuple[CampaignBuilderTargetInput, ...] = Field(
        alias="targetInputs",
        min_length=1,
        max_length=1_000,
    )
    review_only_source_ids: tuple[str, ...] = Field(
        default=(),
        alias="reviewOnlySourceIds",
        max_length=1_000,
    )
    approval_digest: _Sha256 | None = Field(default=None, alias="approvalDigest")
    scope_authorized: Literal[False] = Field(default=False, alias="scopeAuthorized")

    @field_validator("scope_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_false(value)


type CampaignBuilderSource = BugBountyProgramManifest | CTFChallengeManifest


class CampaignProfileScopeDraft(StrictModel):
    """Content-addressed builder draft that cannot authorize Campaign execution."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/campaign-builder-draft/v1alpha1"] = Field(
        default=CAMPAIGN_BUILDER_DRAFT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CampaignProfileScopeDraft"] = "CampaignProfileScopeDraft"
    draft_id: str = Field(default="", alias="draftId", max_length=100)
    draft_digest: str = Field(default="", alias="draftDigest", max_length=64)
    profile_catalog_digest: _Sha256 = Field(alias="profileCatalogDigest")
    selected_profile: RegisteredCampaignProfile = Field(alias="selectedProfile")
    source_kind: CampaignBuilderSourceKind = Field(alias="sourceKind")
    source_digest: _Sha256 = Field(alias="sourceDigest")
    source: CampaignBuilderSource
    scope_preview: CampaignBuilderScopePreview = Field(alias="scopePreview")
    compiler_entrypoint: Literal[
        "pajin.modes.bug_bounty.service.BugBountyScopeService.compile_campaign",
        "pajin.modes.ctf.service.CTFChallengeService.compile_campaign",
    ] = Field(alias="compilerEntrypoint")
    required_gates: tuple[CampaignBuilderGate, ...] = Field(
        alias="requiredGates",
        min_length=1,
        max_length=2,
    )
    draft_state: Literal["input-validated-not-compiled"] = Field(
        default="input-validated-not-compiled",
        alias="draftState",
    )
    campaign_manifest_compiled: Literal[False] = Field(
        default=False,
        alias="campaignManifestCompiled",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "campaign_manifest_compiled",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_false(value)

    @model_validator(mode="after")
    def bind_draft(self) -> Self:
        catalog = registered_campaign_profile_catalog()
        expected_profile = resolve_registered_campaign_profile(
            self.selected_profile.profile_id,
            self.selected_profile.profile_version,
        )
        source = _detached_source(self.source)
        projection = _project_source(source)
        if (
            self.profile_catalog_digest != catalog.catalog_digest
            or self.selected_profile != expected_profile
            or self.selected_profile.profile_id != projection.profile_id
            or self.source_kind is not projection.source_kind
            or not compare_digest(self.source_digest, projection.source_digest)
            or self.source != source
            or self.scope_preview != projection.scope_preview
            or self.compiler_entrypoint != projection.compiler_entrypoint
            or self.required_gates != projection.required_gates
        ):
            raise ValueError("Campaign builder draft differs from its typed source")

        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"draft_id", "draft_digest", "source"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.campaign-builder-draft/v1",
            material,
            max_bytes=_MAX_DRAFT_BYTES,
        )
        draft_id = f"campaign-builder-draft:{digest}"
        if self.draft_digest and not compare_digest(self.draft_digest, digest):
            raise ValueError("Campaign Builder Draft Digest differs")
        if self.draft_id and self.draft_id != draft_id:
            raise ValueError("Campaign Builder Draft ID differs")
        object.__setattr__(self, "draft_digest", digest)
        object.__setattr__(self, "draft_id", draft_id)
        return self


@dataclass(frozen=True, slots=True)
class CampaignBuilderDraftArtifact:
    """One verified local artifact for a non-executable builder draft."""

    path: Path
    draft: CampaignProfileScopeDraft


class _CampaignBuilderProjection(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    profile_id: str
    source_kind: CampaignBuilderSourceKind
    source_digest: _Sha256
    scope_preview: CampaignBuilderScopePreview
    compiler_entrypoint: Literal[
        "pajin.modes.bug_bounty.service.BugBountyScopeService.compile_campaign",
        "pajin.modes.ctf.service.CTFChallengeService.compile_campaign",
    ]
    required_gates: tuple[CampaignBuilderGate, ...]


def build_campaign_profile_scope_draft(
    source: CampaignBuilderSource,
    *,
    profile_id: str,
    profile_version: str = "1.0.0",
) -> CampaignProfileScopeDraft:
    """Validate one existing compiler input and create a non-executable builder draft."""

    authoritative_source = _detached_source(source)
    projection = _project_source(authoritative_source)
    profile = resolve_registered_campaign_profile(profile_id, profile_version)
    if profile.profile_id != projection.profile_id:
        raise CampaignBuilderError("selected Campaign Profile does not match the builder source")
    catalog = registered_campaign_profile_catalog()
    return CampaignProfileScopeDraft(
        profileCatalogDigest=catalog.catalog_digest,
        selectedProfile=profile,
        sourceKind=projection.source_kind,
        sourceDigest=projection.source_digest,
        source=authoritative_source,
        scopePreview=projection.scope_preview,
        compilerEntrypoint=projection.compiler_entrypoint,
        requiredGates=projection.required_gates,
    )


def write_campaign_profile_scope_draft(
    draft: CampaignProfileScopeDraft,
    output_root: Path,
) -> CampaignBuilderDraftArtifact:
    """Write one canonical draft to its content-addressed local artifact path."""

    try:
        canonical = CampaignProfileScopeDraft.model_validate(
            draft.model_dump(mode="json", by_alias=True)
        )
        payload = _canonical_draft_artifact_payload(canonical)
        content = (
            json.dumps(
                payload,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        if len(content.encode("utf-8")) > _MAX_DRAFT_ARTIFACT_BYTES:
            raise ValueError("Campaign Builder draft exceeds its artifact byte limit")
        path = output_root / canonical.draft_digest / CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME
        atomic_write_text_no_follow(
            path,
            content,
            label="Campaign Builder draft artifact",
        )
        persisted = load_campaign_profile_scope_draft(path)
    except (
        AttributeError,
        CampaignBuilderError,
        CampaignProfileError,
        OSError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        if isinstance(exc, CampaignBuilderArtifactError):
            raise
        raise CampaignBuilderArtifactError("Campaign Builder draft artifact write failed") from exc
    if persisted != canonical:
        raise CampaignBuilderArtifactError(
            "Campaign Builder draft artifact differs after write verification"
        )
    return CampaignBuilderDraftArtifact(path=path, draft=persisted)


def load_campaign_profile_scope_draft(path: Path) -> CampaignProfileScopeDraft:
    """Load and fully revalidate one bounded, no-follow local draft artifact."""

    try:
        decoded = load_bounded_strict_json(
            path,
            max_bytes=_MAX_DRAFT_ARTIFACT_BYTES,
            label="Campaign Builder draft artifact",
            require_single_link=True,
            max_depth=64,
            max_nodes=_MAX_DRAFT_ARTIFACT_NODES,
        )
        return CampaignProfileScopeDraft.model_validate(decoded)
    except (
        CampaignBuilderError,
        CampaignProfileError,
        OSError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CampaignBuilderArtifactError("Campaign Builder draft artifact is invalid") from exc


def _canonical_draft_artifact_payload(draft: CampaignProfileScopeDraft) -> dict[str, object]:
    payload = draft.model_dump(mode="json", by_alias=True)
    if draft.source_kind is CampaignBuilderSourceKind.BUG_BOUNTY_PROGRAM:
        source = payload["source"]
        assert isinstance(source, dict)
        spec = source["spec"]
        assert isinstance(spec, dict)
        rules = spec["rules"]
        assert isinstance(rules, dict)
        for field_name in (
            "allowedMethods",
            "allowedToolCategories",
            "prohibitedTechniques",
            "stopOn",
        ):
            values = rules[field_name]
            assert isinstance(values, list)
            rules[field_name] = sorted(values)
        windows = rules["testingWindows"]
        assert isinstance(windows, list)
        for window in windows:
            assert isinstance(window, dict)
            days = window["days"]
            assert isinstance(days, list)
            window["days"] = sorted(days)
        reporting = spec["reporting"]
        assert isinstance(reporting, dict)
        required_fields = reporting["requiredFields"]
        assert isinstance(required_fields, list)
        reporting["requiredFields"] = sorted(required_fields)
    return payload


def _detached_source(source: CampaignBuilderSource) -> CampaignBuilderSource:
    if isinstance(source, BugBountyProgramManifest):
        return BugBountyProgramManifest.model_validate_json(source.model_dump_json(by_alias=True))
    if isinstance(source, CTFChallengeManifest):
        return CTFChallengeManifest.model_validate_json(source.model_dump_json(by_alias=True))
    raise CampaignBuilderError("Campaign builder source kind is not supported")


def _project_source(source: CampaignBuilderSource) -> _CampaignBuilderProjection:
    if isinstance(source, BugBountyProgramManifest):
        return _project_bug_bounty_source(source)
    if isinstance(source, CTFChallengeManifest):
        return _project_ctf_source(source)
    raise CampaignBuilderError("Campaign builder source kind is not supported")


def _project_bug_bounty_source(
    source: BugBountyProgramManifest,
) -> _CampaignBuilderProjection:
    review = BugBountyScopeService().review(source, generated_at=source.spec.policy.retrieved_at)
    targets: list[CampaignBuilderTargetInput] = []
    review_only = {asset.asset_id for asset in source.spec.scope.in_scope if not asset.entry_points}
    for asset in source.spec.scope.in_scope:
        supported = asset.probe_profile is not BugBountyProbeProfile.GENERIC_HTTP
        if asset.entry_points and not supported:
            review_only.add(asset.asset_id)
        for index, entry_point in enumerate(asset.entry_points, start=1):
            suffix = "" if len(asset.entry_points) == 1 else f"-{index}"
            targets.append(
                CampaignBuilderTargetInput(
                    sourceId=f"{asset.asset_id}{suffix}",
                    targetType="bug-bounty-api" if supported else "http",
                    endpoint=entry_point,
                    compilerSupported=supported,
                )
            )
    return _CampaignBuilderProjection(
        profile_id=_BUG_HUNT_PROFILE_ID,
        source_kind=CampaignBuilderSourceKind.BUG_BOUNTY_PROGRAM,
        source_digest=_bug_bounty_source_digest(source),
        scope_preview=CampaignBuilderScopePreview(
            allow=tuple(review.allow),
            deny=tuple(review.deny),
            targetInputs=tuple(targets),
            reviewOnlySourceIds=tuple(sorted(review_only)),
            approvalDigest=review.scope_digest,
        ),
        compiler_entrypoint=(
            "pajin.modes.bug_bounty.service.BugBountyScopeService.compile_campaign"
        ),
        required_gates=(
            CampaignBuilderGate.SCOPE_DIGEST_APPROVAL,
            CampaignBuilderGate.AUTHORIZATION_WINDOW_RECHECK,
        ),
    )


def _bug_bounty_source_digest(source: BugBountyProgramManifest) -> str:
    payload = source.model_dump(mode="json", by_alias=True)
    spec = payload["spec"]
    rules = spec["rules"]
    for field_name in (
        "allowedMethods",
        "allowedToolCategories",
        "prohibitedTechniques",
        "stopOn",
    ):
        rules[field_name] = sorted(rules[field_name])
    for window in rules["testingWindows"]:
        window["days"] = sorted(window["days"])
    spec["reporting"]["requiredFields"] = sorted(spec["reporting"]["requiredFields"])
    return _common_engine_digest(
        "pajin.workflow.campaign-builder-bug-bounty-source/v1",
        payload,
        max_bytes=_MAX_SOURCE_BYTES,
    )


def _project_ctf_source(source: CTFChallengeManifest) -> _CampaignBuilderProjection:
    if source.spec.category is CTFCategory.WEB:
        assert source.spec.scope is not None
        target_type: Literal["ctf-web", "ctf-crypto"] = "ctf-web"
        endpoint = source.spec.scope.entry_point
    else:
        assert source.spec.artifact is not None
        target_type = "ctf-crypto"
        endpoint = crypto_artifact_target(
            source.metadata.name,
            source.spec.artifact.sha256,
        )
    source_payload = source.model_dump(mode="json", by_alias=True)
    source_digest = _common_engine_digest(
        "pajin.workflow.campaign-builder-ctf-source/v1",
        source_payload,
        max_bytes=_MAX_SOURCE_BYTES,
    )
    return _CampaignBuilderProjection(
        profile_id=_CTF_PROFILE_ID,
        source_kind=CampaignBuilderSourceKind.CTF_CHALLENGE,
        source_digest=source_digest,
        scope_preview=CampaignBuilderScopePreview(
            allow=(endpoint,),
            targetInputs=(
                CampaignBuilderTargetInput(
                    sourceId=source.metadata.name,
                    targetType=target_type,
                    endpoint=endpoint,
                    compilerSupported=True,
                ),
            ),
        ),
        compiler_entrypoint=("pajin.modes.ctf.service.CTFChallengeService.compile_campaign"),
        required_gates=(CampaignBuilderGate.AUTHORIZATION_WINDOW_RECHECK,),
    )
