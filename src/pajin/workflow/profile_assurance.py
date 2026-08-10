"""VAL-003 Profile-specific minimum Validation depth requirements."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.validation_depth import (
    ValidationDepth,
    ValidationDepthPolicy,
    ValidationDepthPolicyError,
    ValidationDepthRequirement,
    registered_validation_depth_policy,
    resolve_validation_depth_requirement,
)
from pajin.domain.models import StrictModel
from pajin.workflow.campaign_profile import (
    CampaignProfileCatalog,
    CampaignProfileError,
    RegisteredCampaignProfile,
    registered_campaign_profile_catalog,
    resolve_registered_campaign_profile,
)
from pajin.workflow.common_engine import _common_engine_digest

PROFILE_ASSURANCE_FLOOR_API_VERSION: Literal["pajin.dev/profile-assurance-floor/v1alpha1"] = (
    "pajin.dev/profile-assurance-floor/v1alpha1"
)
PROFILE_ASSURANCE_FLOOR_POLICY_API_VERSION: Literal[
    "pajin.dev/profile-assurance-floor-policy/v1alpha1"
] = "pajin.dev/profile-assurance-floor-policy/v1alpha1"

_MAX_FLOOR_BYTES = 256 * 1024
_MAX_POLICY_BYTES = 1024 * 1024
_PROFILE_DEPTHS: tuple[tuple[str, ValidationDepth], ...] = (
    (
        "pajin.profile.ai-assessment",
        ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY,
    ),
    (
        "pajin.profile.bug-hunt",
        ValidationDepth.CONTROLLED_VALIDITY_REPLAY,
    ),
    (
        "pajin.profile.ctf",
        ValidationDepth.SINGLE_VALIDITY_REPLAY,
    ),
    (
        "pajin.profile.pentest",
        ValidationDepth.CONTROLLED_VALIDITY_REPLAY,
    ),
)


class ProfileAssuranceFloorError(ValueError):
    """Raised when a Profile or Validation depth is outside VAL-003."""


class ProfileAssuranceFloor(StrictModel):
    """Exact minimum depth for one registered Profile without Campaign authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/profile-assurance-floor/v1alpha1"] = Field(
        default=PROFILE_ASSURANCE_FLOOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ProfileAssuranceFloor"] = "ProfileAssuranceFloor"
    floor_id: str = Field(default="", alias="floorId", max_length=200)
    floor_digest: str = Field(default="", alias="floorDigest", max_length=64)
    profile_id: str = Field(alias="profileId", min_length=1, max_length=200)
    profile_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="profileVersion",
    )
    profile_digest: str = Field(alias="profileDigest", pattern=r"^[a-f0-9]{64}$")
    profile: RegisteredCampaignProfile
    minimum_depth: ValidationDepth = Field(alias="minimumDepth")
    minimum_depth_ordinal: int = Field(alias="minimumDepthOrdinal", ge=1, le=3)
    minimum_requirement_digest: str = Field(
        alias="minimumRequirementDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    minimum_requirement: ValidationDepthRequirement = Field(alias="minimumRequirement")
    floor_registered: Literal[True] = Field(default=True, alias="floorRegistered")
    higher_depth_requirement_acceptable: Literal[True] = Field(
        default=True,
        alias="higherDepthRequirementAcceptable",
    )
    profile_selection_authorized: Literal[False] = Field(
        default=False,
        alias="profileSelectionAuthorized",
    )
    campaign_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="campaignMutationAuthorized",
    )
    evidence_evaluation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceEvaluationAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator(
        "floor_registered",
        "higher_depth_requirement_acceptable",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Profile assurance registration markers must be boolean true")
        return value

    @field_validator(
        "profile_selection_authorized",
        "campaign_mutation_authorized",
        "evidence_evaluation_authorized",
        "execution_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Profile assurance authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_floor_identity(self) -> Self:
        registered_profile = resolve_registered_campaign_profile(
            self.profile_id,
            self.profile_version,
        )
        expected_depth = _profile_depth(self.profile_id)
        registered_requirement = resolve_validation_depth_requirement(expected_depth)
        if (
            self.profile != registered_profile
            or self.profile_digest != registered_profile.profile_digest
        ):
            raise ValueError("Profile Assurance Floor differs from the registered Profile")
        if (
            self.minimum_depth is not expected_depth
            or self.minimum_requirement != registered_requirement
            or self.minimum_depth_ordinal != registered_requirement.depth_ordinal
            or self.minimum_requirement_digest != registered_requirement.requirement_digest
        ):
            raise ValueError("Profile Assurance Floor differs from the code-owned depth mapping")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"floor_id", "floor_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.profile-assurance-floor/v1",
            material,
            max_bytes=_MAX_FLOOR_BYTES,
        )
        floor_id = f"profile-assurance-floor:{self.profile_id}:1.0.0"
        if self.floor_digest and self.floor_digest != digest:
            raise ValueError("Profile Assurance Floor Digest differs")
        if self.floor_id and self.floor_id != floor_id:
            raise ValueError("Profile Assurance Floor ID differs")
        object.__setattr__(self, "floor_digest", digest)
        object.__setattr__(self, "floor_id", floor_id)
        return self


class ProfileAssuranceFloorPolicy(StrictModel):
    """Complete PROF-001 to VAL-002 floor mapping without evidence authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/profile-assurance-floor-policy/v1alpha1"] = Field(
        default=PROFILE_ASSURANCE_FLOOR_POLICY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ProfileAssuranceFloorPolicy"] = "ProfileAssuranceFloorPolicy"
    policy_id: Literal["val-003:profile-assurance-floor"] = Field(
        default="val-003:profile-assurance-floor",
        alias="policyId",
    )
    policy_version: Literal["1.0.0"] = Field(default="1.0.0", alias="policyVersion")
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    profile_catalog_id: Literal["campaign-profile-catalog:common-engine-v1"] = Field(
        default="campaign-profile-catalog:common-engine-v1",
        alias="profileCatalogId",
    )
    profile_catalog_digest: str = Field(
        alias="profileCatalogDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    profile_catalog: CampaignProfileCatalog = Field(alias="profileCatalog")
    validation_depth_policy_id: Literal["val-002:validation-depth-policy"] = Field(
        default="val-002:validation-depth-policy",
        alias="validationDepthPolicyId",
    )
    validation_depth_policy_digest: str = Field(
        alias="validationDepthPolicyDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    validation_depth_policy: ValidationDepthPolicy = Field(alias="validationDepthPolicy")
    floors: tuple[ProfileAssuranceFloor, ...] = Field(min_length=4, max_length=4)
    floor_mapping_registered: Literal[True] = Field(
        default=True,
        alias="floorMappingRegistered",
    )
    profile_selection_authorized: Literal[False] = Field(
        default=False,
        alias="profileSelectionAuthorized",
    )
    campaign_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="campaignMutationAuthorized",
    )
    evidence_evaluation_authorized: Literal[False] = Field(
        default=False,
        alias="evidenceEvaluationAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator("floor_mapping_registered", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Profile assurance mapping marker must be boolean true")
        return value

    @field_validator(
        "profile_selection_authorized",
        "campaign_mutation_authorized",
        "evidence_evaluation_authorized",
        "execution_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Profile assurance Policy authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_policy_identity(self) -> Self:
        profile_catalog = registered_campaign_profile_catalog()
        depth_policy = registered_validation_depth_policy()
        expected_floors = _profile_assurance_floors(profile_catalog)
        if (
            self.profile_catalog != profile_catalog
            or self.profile_catalog_digest != profile_catalog.catalog_digest
        ):
            raise ValueError("Profile Assurance Policy Profile Catalog differs")
        if (
            self.validation_depth_policy != depth_policy
            or self.validation_depth_policy_digest != depth_policy.policy_digest
        ):
            raise ValueError("Profile Assurance Policy Validation Depth Policy differs")
        if self.floors != expected_floors:
            raise ValueError("Profile Assurance Floors differ from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.profile-assurance-floor-policy/v1",
            material,
            max_bytes=_MAX_POLICY_BYTES,
        )
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Profile Assurance Floor Policy Digest differs")
        object.__setattr__(self, "policy_digest", digest)
        return self


def registered_profile_assurance_floor_policy() -> ProfileAssuranceFloorPolicy:
    """Return the exact VAL-003 Profile-to-depth floor mapping."""

    profile_catalog = registered_campaign_profile_catalog()
    depth_policy = registered_validation_depth_policy()
    return ProfileAssuranceFloorPolicy(
        profileCatalogDigest=profile_catalog.catalog_digest,
        profileCatalog=profile_catalog,
        validationDepthPolicyDigest=depth_policy.policy_digest,
        validationDepthPolicy=depth_policy,
        floors=_profile_assurance_floors(profile_catalog),
    )


def resolve_profile_assurance_floor(
    profile_id: str,
    profile_version: str,
) -> ProfileAssuranceFloor:
    """Resolve one exact registered Profile floor without selecting it for a Campaign."""

    try:
        resolve_registered_campaign_profile(profile_id, profile_version)
        for floor in registered_profile_assurance_floor_policy().floors:
            if floor.profile_id == profile_id and floor.profile_version == profile_version:
                return floor.model_copy(deep=True)
    except (
        CampaignProfileError,
        TypeError,
        ValidationError,
        ValidationDepthPolicyError,
        ValueError,
    ) as exc:
        raise ProfileAssuranceFloorError("Profile Assurance Floor is not registered") from exc
    raise ProfileAssuranceFloorError("Profile Assurance Floor is not registered")


def validation_depth_requirement_meets_profile_floor(
    profile_id: str,
    profile_version: str,
    depth: ValidationDepth | str,
) -> bool:
    """Compare registered requirements only; this does not evaluate Campaign evidence."""

    try:
        floor = resolve_profile_assurance_floor(profile_id, profile_version)
        offered = resolve_validation_depth_requirement(depth)
        return offered.depth_ordinal >= floor.minimum_depth_ordinal
    except (ProfileAssuranceFloorError, ValidationDepthPolicyError) as exc:
        raise ProfileAssuranceFloorError("Profile or Validation depth is not registered") from exc


def _profile_assurance_floors(
    profile_catalog: CampaignProfileCatalog,
) -> tuple[ProfileAssuranceFloor, ...]:
    expected_profile_ids = tuple(profile_id for profile_id, _depth in _PROFILE_DEPTHS)
    if tuple(profile.profile_id for profile in profile_catalog.profiles) != expected_profile_ids:
        raise ValueError("Profile Assurance mapping differs from the Profile Catalog order")
    return tuple(
        _profile_assurance_floor(profile, _profile_depth(profile.profile_id))
        for profile in profile_catalog.profiles
    )


def _profile_assurance_floor(
    profile: RegisteredCampaignProfile,
    depth: ValidationDepth,
) -> ProfileAssuranceFloor:
    requirement = resolve_validation_depth_requirement(depth)
    return ProfileAssuranceFloor(
        profileId=profile.profile_id,
        profileVersion=profile.profile_version,
        profileDigest=profile.profile_digest,
        profile=profile,
        minimumDepth=depth,
        minimumDepthOrdinal=requirement.depth_ordinal,
        minimumRequirementDigest=requirement.requirement_digest,
        minimumRequirement=requirement,
    )


def _profile_depth(profile_id: str) -> ValidationDepth:
    for registered_profile_id, depth in _PROFILE_DEPTHS:
        if profile_id == registered_profile_id:
            return depth
    raise ProfileAssuranceFloorError("Profile Assurance Floor is not registered")
