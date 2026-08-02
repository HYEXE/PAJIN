"""PROF-001 code-owned, non-executable Campaign Profile authority."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.workflow.common_engine import (
    CommonCampaignEngineContract,
    _common_engine_digest,
    registered_common_campaign_engine_contract,
)

CAMPAIGN_PROFILE_API_VERSION: Literal[
    "pajin.dev/campaign-profile/v1alpha1"
] = "pajin.dev/campaign-profile/v1alpha1"
CAMPAIGN_PROFILE_CATALOG_API_VERSION: Literal[
    "pajin.dev/campaign-profile-catalog/v1alpha1"
] = "pajin.dev/campaign-profile-catalog/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_PROFILE_BYTES = 128 * 1024
_MAX_CATALOG_BYTES = 1024 * 1024

_AUTHORITY_CONSTRAINTS = (
    "campaign-authorization-window",
    "campaign-budget-ceiling",
    "campaign-risk-ceiling",
    "campaign-scope-intersection",
    "registered-capability-subset",
)


class CampaignProfileError(RuntimeError):
    """Raised when a code-owned Profile cannot be resolved exactly."""


class CampaignProfilePurpose(StrEnum):
    PENTEST = "pentest"
    BUG_HUNT = "bug-hunt"
    CTF = "ctf"
    AI_ASSESSMENT = "ai-assessment"


class CampaignProfileReportingSemantics(StrEnum):
    TECHNICAL_ASSESSMENT = "technical-assessment"
    PROGRAM_SUBMISSION_DRAFT = "program-submission-draft"
    FIXED_LAB_RESULT = "fixed-lab-result"
    AI_THREAT_ASSESSMENT = "ai-threat-assessment"


class CampaignProfileBenchmarkExpectation(StrEnum):
    AUTHORIZED_TARGET_ASSESSMENT = "authorized-target-assessment"
    PROGRAM_SCOPE_FINDING = "program-scope-finding"
    FIXED_LAB_GROUND_TRUTH = "fixed-lab-ground-truth"
    THREAT_CLASS_COVERAGE = "threat-class-coverage"


class RegisteredCampaignProfile(StrictModel):
    """One content-addressed operating Profile that carries no Campaign authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/campaign-profile/v1alpha1"] = Field(
        default=CAMPAIGN_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredCampaignProfile"] = "RegisteredCampaignProfile"
    profile_id: _Identifier = Field(alias="profileId")
    profile_version: Literal["1.0.0"] = Field(
        default="1.0.0",
        alias="profileVersion",
    )
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    purpose: CampaignProfilePurpose
    reporting_semantics: CampaignProfileReportingSemantics = Field(
        alias="reportingSemantics"
    )
    benchmark_expectation: CampaignProfileBenchmarkExpectation = Field(
        alias="benchmarkExpectation"
    )
    required_operating_controls: tuple[_Identifier, ...] = Field(
        alias="requiredOperatingControls",
        min_length=3,
        max_length=3,
    )
    authority_constraints: tuple[_Identifier, ...] = Field(
        alias="authorityConstraints",
        min_length=5,
        max_length=5,
    )
    common_engine_contract_id: _Identifier = Field(alias="commonEngineContractId")
    common_engine_contract_digest: _Sha256 = Field(
        alias="commonEngineContractDigest"
    )
    roe_defaults_policy: Literal["campaign-authority-only"] = Field(
        default="campaign-authority-only",
        alias="roeDefaultsPolicy",
    )
    legacy_compatibility_adapter_bound: Literal[False] = Field(
        default=False,
        alias="legacyCompatibilityAdapterBound",
    )
    mission_envelope_compiler_bound: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompilerBound",
    )
    benchmark_measurement_authorized: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementAuthorized",
    )
    external_submission_authorized: Literal[False] = Field(
        default=False,
        alias="externalSubmissionAuthorized",
    )
    profile_execution_authorized: Literal[False] = Field(
        default=False,
        alias="profileExecutionAuthorized",
    )

    @field_validator("required_operating_controls", "authority_constraints")
    @classmethod
    def require_canonical_controls(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != tuple(sorted(set(value))):
            raise ValueError("Campaign Profile controls must be unique and sorted")
        return value

    @model_validator(mode="after")
    def bind_profile_digest(self) -> Self:
        contract = registered_common_campaign_engine_contract()
        if (
            self.authority_constraints != _AUTHORITY_CONSTRAINTS
            or self.common_engine_contract_id != contract.contract_id
            or self.common_engine_contract_digest != contract.contract_digest
        ):
            raise ValueError("Campaign Profile authority constraints differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.campaign-profile/v1",
            material,
            max_bytes=_MAX_PROFILE_BYTES,
        )
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("Campaign Profile Digest differs")
        object.__setattr__(self, "profile_digest", digest)
        return self


class CampaignProfileCatalog(StrictModel):
    """Exact code-owned Profile set without Mode compilation or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/campaign-profile-catalog/v1alpha1"
    ] = Field(
        default=CAMPAIGN_PROFILE_CATALOG_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CampaignProfileCatalog"] = "CampaignProfileCatalog"
    catalog_id: Literal["campaign-profile-catalog:common-engine-v1"] = Field(
        default="campaign-profile-catalog:common-engine-v1",
        alias="catalogId",
    )
    catalog_revision: Literal[1] = Field(default=1, alias="catalogRevision")
    catalog_digest: str = Field(default="", alias="catalogDigest", max_length=64)
    common_engine_contract: CommonCampaignEngineContract = Field(
        alias="commonEngineContract"
    )
    common_engine_contract_digest: _Sha256 = Field(
        alias="commonEngineContractDigest"
    )
    profiles: tuple[RegisteredCampaignProfile, ...] = Field(
        min_length=4,
        max_length=4,
    )
    legacy_mode_compilation_authorized: Literal[False] = Field(
        default=False,
        alias="legacyModeCompilationAuthorized",
    )
    mission_envelope_compilation_authorized: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeCompilationAuthorized",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_catalog_digest(self) -> Self:
        contract = registered_common_campaign_engine_contract()
        expected_profiles = _registered_campaign_profiles()
        if (
            self.common_engine_contract != contract
            or self.common_engine_contract_digest != contract.contract_digest
            or self.profiles != expected_profiles
        ):
            raise ValueError("Campaign Profile Catalog differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"catalog_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.campaign-profile-catalog/v1",
            material,
            max_bytes=_MAX_CATALOG_BYTES,
        )
        if self.catalog_digest and self.catalog_digest != digest:
            raise ValueError("Campaign Profile Catalog Digest differs")
        object.__setattr__(self, "catalog_digest", digest)
        return self


def registered_campaign_profile_catalog() -> CampaignProfileCatalog:
    """Return the exact PROF-001 Profile catalog."""

    contract = registered_common_campaign_engine_contract()
    return CampaignProfileCatalog(
        commonEngineContract=contract,
        commonEngineContractDigest=contract.contract_digest,
        profiles=_registered_campaign_profiles(),
    )


def resolve_registered_campaign_profile(
    profile_id: str,
    profile_version: str,
) -> RegisteredCampaignProfile:
    """Resolve one exact Profile version without selecting it for a Campaign."""

    for profile in registered_campaign_profile_catalog().profiles:
        if (
            profile.profile_id == profile_id
            and profile.profile_version == profile_version
        ):
            return profile.model_copy(deep=True)
    raise CampaignProfileError("Campaign Profile ID and version are not registered")


def _registered_campaign_profiles() -> tuple[RegisteredCampaignProfile, ...]:
    contract = registered_common_campaign_engine_contract()
    specs = (
        (
            "pajin.profile.ai-assessment",
            CampaignProfilePurpose.AI_ASSESSMENT,
            CampaignProfileReportingSemantics.AI_THREAT_ASSESSMENT,
            CampaignProfileBenchmarkExpectation.THREAT_CLASS_COVERAGE,
            ("claim-validation", "independent-replay", "threat-class-catalog"),
        ),
        (
            "pajin.profile.bug-hunt",
            CampaignProfilePurpose.BUG_HUNT,
            CampaignProfileReportingSemantics.PROGRAM_SUBMISSION_DRAFT,
            CampaignProfileBenchmarkExpectation.PROGRAM_SCOPE_FINDING,
            ("duplicate-triage", "program-policy", "submission-draft-only"),
        ),
        (
            "pajin.profile.ctf",
            CampaignProfilePurpose.CTF,
            CampaignProfileReportingSemantics.FIXED_LAB_RESULT,
            CampaignProfileBenchmarkExpectation.FIXED_LAB_GROUND_TRUTH,
            ("fixed-lab", "flag-validator", "no-external-submission"),
        ),
        (
            "pajin.profile.pentest",
            CampaignProfilePurpose.PENTEST,
            CampaignProfileReportingSemantics.TECHNICAL_ASSESSMENT,
            CampaignProfileBenchmarkExpectation.AUTHORIZED_TARGET_ASSESSMENT,
            ("authorization-evidence", "explicit-scope", "remediation-report"),
        ),
    )
    return tuple(
        RegisteredCampaignProfile(
            profileId=profile_id,
            purpose=purpose,
            reportingSemantics=reporting,
            benchmarkExpectation=benchmark,
            requiredOperatingControls=controls,
            authorityConstraints=_AUTHORITY_CONSTRAINTS,
            commonEngineContractId=contract.contract_id,
            commonEngineContractDigest=contract.contract_digest,
        )
        for profile_id, purpose, reporting, benchmark, controls in specs
    )
