"""PROF-002 deterministic, non-executable legacy Mode Profile compilation."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import (
    CampaignManifest,
    CampaignMode,
    StrictModel,
    campaign_manifest_digest,
)
from pajin.workflow.campaign_profile import (
    CampaignProfileCatalog,
    RegisteredCampaignProfile,
    registered_campaign_profile_catalog,
    resolve_registered_campaign_profile,
)
from pajin.workflow.common_engine import _common_engine_digest

LEGACY_MODE_PROFILE_COMPILER_API_VERSION: Literal[
    "pajin.dev/legacy-mode-profile-compiler/v1alpha1"
] = "pajin.dev/legacy-mode-profile-compiler/v1alpha1"
LEGACY_CAMPAIGN_PROFILE_PROJECTION_API_VERSION: Literal[
    "pajin.dev/legacy-campaign-profile-projection/v1alpha1"
] = "pajin.dev/legacy-campaign-profile-projection/v1alpha1"
LEGACY_CAMPAIGN_PROFILE_COMPILATION_API_VERSION: Literal[
    "pajin.dev/legacy-campaign-profile-compilation/v1alpha1"
] = "pajin.dev/legacy-campaign-profile-compilation/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_MAPPING_BYTES = 64 * 1024
_MAX_COMPILER_BYTES = 512 * 1024
_MAX_PROJECTION_BYTES = 256 * 1024
_MAX_COMPILATION_BYTES = 2 * 1024 * 1024

_MODE_PROFILE_IDS = {
    CampaignMode.AI_REDTEAM: "pajin.profile.ai-assessment",
    CampaignMode.BUG_BOUNTY: "pajin.profile.bug-hunt",
    CampaignMode.CTF: "pajin.profile.ctf",
}


class CampaignProfileCompatibilityError(RuntimeError):
    """Raised when a legacy Campaign cannot be projected exactly."""


class LegacyModeProfileMapping(StrictModel):
    """One exact legacy Mode to registered Profile mapping."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_mode: CampaignMode = Field(alias="sourceMode")
    profile_id: _Identifier = Field(alias="profileId")
    profile_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="profileVersion",
    )
    profile_digest: _Sha256 = Field(alias="profileDigest")
    mapping_digest: str = Field(default="", alias="mappingDigest", max_length=64)

    @model_validator(mode="after")
    def bind_mapping_digest(self) -> Self:
        expected_profile_id = _MODE_PROFILE_IDS[self.source_mode]
        profile = resolve_registered_campaign_profile(expected_profile_id, "1.0.0")
        if (
            self.profile_id != profile.profile_id
            or self.profile_version != profile.profile_version
            or self.profile_digest != profile.profile_digest
        ):
            raise ValueError("Legacy Mode Profile mapping differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"mapping_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.legacy-mode-profile-mapping/v1",
            material,
            max_bytes=_MAX_MAPPING_BYTES,
        )
        if self.mapping_digest and self.mapping_digest != digest:
            raise ValueError("Legacy Mode Profile Mapping Digest differs")
        object.__setattr__(self, "mapping_digest", digest)
        return self


class LegacyModeProfileCompiler(StrictModel):
    """Code-owned compatibility compiler identity with no execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/legacy-mode-profile-compiler/v1alpha1"
    ] = Field(
        default=LEGACY_MODE_PROFILE_COMPILER_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LegacyModeProfileCompiler"] = "LegacyModeProfileCompiler"
    compiler_id: Literal["pajin.profile.compiler.legacy-mode-v1"] = Field(
        default="pajin.profile.compiler.legacy-mode-v1",
        alias="compilerId",
    )
    compiler_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="compilerVersion",
    )
    compiler_digest: str = Field(default="", alias="compilerDigest", max_length=64)
    accepted_campaign_api_versions: tuple[Literal["pajin.dev/v1alpha1"], ...] = Field(
        alias="acceptedCampaignApiVersions",
        min_length=1,
        max_length=1,
    )
    profile_catalog_id: _Identifier = Field(alias="profileCatalogId")
    profile_catalog_digest: _Sha256 = Field(alias="profileCatalogDigest")
    mappings: tuple[LegacyModeProfileMapping, ...] = Field(
        min_length=3,
        max_length=3,
    )
    campaign_mutation_allowed: Literal[False] = Field(
        default=False,
        alias="campaignMutationAllowed",
    )
    roe_defaults_application_authorized: Literal[False] = Field(
        default=False,
        alias="roeDefaultsApplicationAuthorized",
    )
    pentest_auto_selection_authorized: Literal[False] = Field(
        default=False,
        alias="pentestAutoSelectionAuthorized",
    )
    mission_envelope_compilation_authorized: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompilationAuthorized",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @field_validator("accepted_campaign_api_versions")
    @classmethod
    def require_exact_campaign_api_versions(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if value != ("pajin.dev/v1alpha1",):
            raise ValueError("Legacy Profile compiler Campaign API versions differ")
        return value

    @model_validator(mode="after")
    def bind_compiler_digest(self) -> Self:
        catalog = registered_campaign_profile_catalog()
        expected_mappings = _registered_mode_profile_mappings()
        if (
            self.profile_catalog_id != catalog.catalog_id
            or self.profile_catalog_digest != catalog.catalog_digest
            or self.mappings != expected_mappings
        ):
            raise ValueError("Legacy Mode Profile Compiler differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"compiler_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.legacy-mode-profile-compiler/v1",
            material,
            max_bytes=_MAX_COMPILER_BYTES,
        )
        if self.compiler_digest and self.compiler_digest != digest:
            raise ValueError("Legacy Mode Profile Compiler Digest differs")
        object.__setattr__(self, "compiler_digest", digest)
        return self


class LegacyCampaignProfileProjection(StrictModel):
    """Pure semantic output that preserves the exact legacy Campaign input."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/legacy-campaign-profile-projection/v1alpha1"
    ] = Field(
        default=LEGACY_CAMPAIGN_PROFILE_PROJECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LegacyCampaignProfileProjection"] = (
        "LegacyCampaignProfileProjection"
    )
    projection_digest: str = Field(default="", alias="projectionDigest", max_length=64)
    source_campaign_digest: _Sha256 = Field(alias="sourceCampaignDigest")
    source_mode: CampaignMode = Field(alias="sourceMode")
    profile_id: _Identifier = Field(alias="profileId")
    profile_version: Literal["1.0.0"] = Field(alias="profileVersion")
    profile_digest: _Sha256 = Field(alias="profileDigest")
    compiler_id: _Identifier = Field(alias="compilerId")
    compiler_version: _Identifier = Field(alias="compilerVersion")
    compiler_digest: _Sha256 = Field(alias="compilerDigest")
    profile_catalog_digest: _Sha256 = Field(alias="profileCatalogDigest")
    legacy_input_preserved: Literal[True] = Field(
        default=True,
        alias="legacyInputPreserved",
    )
    campaign_mutation_applied: Literal[False] = Field(
        default=False,
        alias="campaignMutationApplied",
    )
    roe_defaults_applied: Literal[False] = Field(
        default=False,
        alias="roeDefaultsApplied",
    )
    mission_envelope_compiled: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompiled",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_projection_digest(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"projection_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.legacy-campaign-profile-projection/v1",
            material,
            max_bytes=_MAX_PROJECTION_BYTES,
        )
        if self.projection_digest and self.projection_digest != digest:
            raise ValueError("Legacy Campaign Profile Projection Digest differs")
        object.__setattr__(self, "projection_digest", digest)
        return self


class LegacyCampaignProfileCompilationAuthority(StrictModel):
    """Complete input/compiler/output audit authority without runtime activation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/legacy-campaign-profile-compilation/v1alpha1"
    ] = Field(
        default=LEGACY_CAMPAIGN_PROFILE_COMPILATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["LegacyCampaignProfileCompilationAuthority"] = (
        "LegacyCampaignProfileCompilationAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    source_campaign: CampaignManifest = Field(alias="sourceCampaign")
    input_digest: _Sha256 = Field(alias="inputDigest")
    source_mode: CampaignMode = Field(alias="sourceMode")
    compiler: LegacyModeProfileCompiler
    compiler_digest: _Sha256 = Field(alias="compilerDigest")
    profile_catalog: CampaignProfileCatalog = Field(alias="profileCatalog")
    profile_catalog_digest: _Sha256 = Field(alias="profileCatalogDigest")
    profile: RegisteredCampaignProfile
    profile_digest: _Sha256 = Field(alias="profileDigest")
    projection: LegacyCampaignProfileProjection
    output_digest: _Sha256 = Field(alias="outputDigest")
    compilation_state: Literal["profile-projected-not-executable"] = Field(
        default="profile-projected-not-executable",
        alias="compilationState",
    )
    mission_envelope_compiled: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompiled",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_compilation_authority(self) -> Self:
        campaign = CampaignManifest.model_validate_json(
            self.source_campaign.model_dump_json(by_alias=True)
        )
        compiler = registered_legacy_mode_profile_compiler()
        catalog = registered_campaign_profile_catalog()
        profile = _profile_for_mode(campaign.spec.mode)
        projection = _compile_projection(campaign, compiler, catalog, profile)
        if campaign.api_version not in compiler.accepted_campaign_api_versions:
            raise ValueError(
                "Legacy Campaign API version is not accepted by the Profile compiler"
            )
        if (
            self.source_campaign != campaign
            or self.input_digest != campaign_manifest_digest(campaign)
            or self.source_mode != campaign.spec.mode
            or self.compiler != compiler
            or self.compiler_digest != compiler.compiler_digest
            or self.profile_catalog != catalog
            or self.profile_catalog_digest != catalog.catalog_digest
            or self.profile != profile
            or self.profile_digest != profile.profile_digest
            or self.projection != projection
            or self.output_digest != projection.projection_digest
        ):
            raise ValueError("Legacy Campaign Profile Compilation authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest", "source_campaign"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.legacy-campaign-profile-compilation/v1",
            material,
            max_bytes=_MAX_COMPILATION_BYTES,
        )
        authority_id = f"legacy-campaign-profile-compilation:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Legacy Campaign Profile Compilation Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Legacy Campaign Profile Compilation Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_legacy_mode_profile_compiler() -> LegacyModeProfileCompiler:
    """Return the exact PROF-002 compatibility compiler identity."""

    catalog = registered_campaign_profile_catalog()
    return LegacyModeProfileCompiler(
        acceptedCampaignApiVersions=("pajin.dev/v1alpha1",),
        profileCatalogId=catalog.catalog_id,
        profileCatalogDigest=catalog.catalog_digest,
        mappings=_registered_mode_profile_mappings(),
    )


def compile_legacy_campaign_profile(
    campaign: CampaignManifest,
) -> LegacyCampaignProfileCompilationAuthority:
    """Project one exact legacy Campaign to a Profile without modifying authority."""

    authoritative_campaign = CampaignManifest.model_validate_json(
        campaign.model_dump_json(by_alias=True)
    )
    compiler = registered_legacy_mode_profile_compiler()
    if authoritative_campaign.api_version not in compiler.accepted_campaign_api_versions:
        raise CampaignProfileCompatibilityError(
            "legacy Campaign API version is not accepted by the Profile compiler"
        )
    catalog = registered_campaign_profile_catalog()
    profile = _profile_for_mode(authoritative_campaign.spec.mode)
    projection = _compile_projection(authoritative_campaign, compiler, catalog, profile)
    return LegacyCampaignProfileCompilationAuthority(
        sourceCampaign=authoritative_campaign,
        inputDigest=campaign_manifest_digest(authoritative_campaign),
        sourceMode=authoritative_campaign.spec.mode,
        compiler=compiler,
        compilerDigest=compiler.compiler_digest,
        profileCatalog=catalog,
        profileCatalogDigest=catalog.catalog_digest,
        profile=profile,
        profileDigest=profile.profile_digest,
        projection=projection,
        outputDigest=projection.projection_digest,
    )


def _registered_mode_profile_mappings() -> tuple[LegacyModeProfileMapping, ...]:
    return tuple(
        LegacyModeProfileMapping(
            sourceMode=mode,
            profileId=profile.profile_id,
            profileVersion=profile.profile_version,
            profileDigest=profile.profile_digest,
        )
        for mode in tuple(CampaignMode)
        for profile in (resolve_registered_campaign_profile(_MODE_PROFILE_IDS[mode], "1.0.0"),)
    )


def _profile_for_mode(mode: CampaignMode) -> RegisteredCampaignProfile:
    try:
        profile_id = _MODE_PROFILE_IDS[mode]
    except KeyError as exc:
        raise CampaignProfileCompatibilityError(
            "legacy Campaign Mode has no registered Profile mapping"
        ) from exc
    return resolve_registered_campaign_profile(profile_id, "1.0.0")


def _compile_projection(
    campaign: CampaignManifest,
    compiler: LegacyModeProfileCompiler,
    catalog: CampaignProfileCatalog,
    profile: RegisteredCampaignProfile,
) -> LegacyCampaignProfileProjection:
    return LegacyCampaignProfileProjection(
        sourceCampaignDigest=campaign_manifest_digest(campaign),
        sourceMode=campaign.spec.mode,
        profileId=profile.profile_id,
        profileVersion=profile.profile_version,
        profileDigest=profile.profile_digest,
        compilerId=compiler.compiler_id,
        compilerVersion=compiler.compiler_version,
        compilerDigest=compiler.compiler_digest,
        profileCatalogDigest=catalog.catalog_digest,
    )
