"""ENG-001 non-executable contract for the common Campaign engine boundary."""

from __future__ import annotations

import json
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import (
    CampaignManifest,
    CampaignMode,
    StrictModel,
    campaign_manifest_digest,
)

COMMON_CAMPAIGN_ENGINE_CONTRACT_API_VERSION: Literal[
    "pajin.dev/common-campaign-engine-contract/v1alpha1"
] = "pajin.dev/common-campaign-engine-contract/v1alpha1"
COMMON_CAMPAIGN_EXECUTION_PLAN_API_VERSION: Literal[
    "pajin.dev/common-campaign-execution-plan/v1alpha1"
] = "pajin.dev/common-campaign-execution-plan/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_PLAN_BYTES = 2 * 1024 * 1024

_SOURCE_MODES = (
    CampaignMode.AI_REDTEAM,
    CampaignMode.BUG_BOUNTY,
    CampaignMode.CTF,
)
_SHARED_BOUNDARIES = (
    "campaign-authority-snapshot",
    "budget-and-rate-limit",
    "capability-and-policy",
    "worker-dispatch",
    "candidate-validation",
    "sealed-run-audit",
)
_PARITY_DIMENSIONS = (
    "scope",
    "capability",
    "tool-request",
    "outcome",
)


def _common_engine_digest(domain: str, value: object, *, max_bytes: int) -> str:
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError("Common Campaign Engine authority is not canonical JSON") from exc
    if len(encoded) > max_bytes:
        raise ValueError("Common Campaign Engine authority exceeds its byte limit")
    return sha256(domain.encode("ascii") + b"\x00" + encoded).hexdigest()


class CommonCampaignEngineContract(StrictModel):
    """Code-owned shared boundary inventory that grants no execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-campaign-engine-contract/v1alpha1"
    ] = Field(
        default=COMMON_CAMPAIGN_ENGINE_CONTRACT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonCampaignEngineContract"] = "CommonCampaignEngineContract"
    contract_id: Literal["common-campaign-engine:multi-agent-v1"] = Field(
        default="common-campaign-engine:multi-agent-v1",
        alias="contractId",
    )
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    implementation_id: Literal[
        "pajin.workflow.multi_agent.MultiAgentCampaignRunner"
    ] = Field(
        default="pajin.workflow.multi_agent.MultiAgentCampaignRunner",
        alias="implementationId",
    )
    implementation_version: Literal["legacy-shared-boundary-v1"] = Field(
        default="legacy-shared-boundary-v1",
        alias="implementationVersion",
    )
    accepted_source_modes: tuple[CampaignMode, ...] = Field(
        alias="acceptedSourceModes",
        min_length=3,
        max_length=3,
    )
    shared_boundaries: tuple[str, ...] = Field(
        alias="sharedBoundaries",
        min_length=6,
        max_length=6,
    )
    required_parity_dimensions: tuple[str, ...] = Field(
        alias="requiredParityDimensions",
        min_length=4,
        max_length=4,
    )
    campaign_profile_required: Literal[True] = Field(
        default=True,
        alias="campaignProfileRequired",
    )
    mission_envelope_required: Literal[True] = Field(
        default=True,
        alias="missionEnvelopeRequired",
    )
    legacy_wire_compatibility_required: Literal[True] = Field(
        default=True,
        alias="legacyWireCompatibilityRequired",
    )
    legacy_default_path_preserved: Literal[True] = Field(
        default=True,
        alias="legacyDefaultPathPreserved",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @field_validator("accepted_source_modes")
    @classmethod
    def require_exact_source_modes(
        cls,
        value: tuple[CampaignMode, ...],
    ) -> tuple[CampaignMode, ...]:
        if value != _SOURCE_MODES:
            raise ValueError("Common Campaign Engine source Modes differ from the contract")
        return value

    @field_validator("shared_boundaries")
    @classmethod
    def require_exact_shared_boundaries(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _SHARED_BOUNDARIES:
            raise ValueError("Common Campaign Engine shared boundaries differ")
        return value

    @field_validator("required_parity_dimensions")
    @classmethod
    def require_exact_parity_dimensions(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if value != _PARITY_DIMENSIONS:
            raise ValueError("Common Campaign Engine parity dimensions differ")
        return value

    @model_validator(mode="after")
    def bind_contract_digest(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-campaign-engine-contract/v1",
            material,
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Common Campaign Engine Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        return self


class CommonCampaignExecutionPlanAuthority(StrictModel):
    """Exact legacy Campaign projection awaiting Profile and parity authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/common-campaign-execution-plan/v1alpha1"
    ] = Field(
        default=COMMON_CAMPAIGN_EXECUTION_PLAN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CommonCampaignExecutionPlanAuthority"] = (
        "CommonCampaignExecutionPlanAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    campaign: CampaignManifest
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source_mode: CampaignMode = Field(alias="sourceMode")
    engine_contract: CommonCampaignEngineContract = Field(alias="engineContract")
    engine_contract_digest: _Sha256 = Field(alias="engineContractDigest")
    plan_state: Literal["profile-required-not-executable"] = Field(
        default="profile-required-not-executable",
        alias="planState",
    )
    profile_compilation_bound: Literal[False] = Field(
        default=False,
        alias="profileCompilationBound",
    )
    mission_envelope_bound: Literal[False] = Field(
        default=False,
        alias="missionEnvelopeBound",
    )
    parity_evidence_bound: Literal[False] = Field(
        default=False,
        alias="parityEvidenceBound",
    )
    common_execution_authorized: Literal[False] = Field(
        default=False,
        alias="commonExecutionAuthorized",
    )

    @model_validator(mode="after")
    def bind_plan_authority(self) -> Self:
        canonical_campaign = CampaignManifest.model_validate_json(
            self.campaign.model_dump_json(by_alias=True)
        )
        registered_contract = registered_common_campaign_engine_contract()
        if (
            self.campaign != canonical_campaign
            or self.campaign_digest != campaign_manifest_digest(canonical_campaign)
            or self.source_mode != canonical_campaign.spec.mode
            or self.engine_contract != registered_contract
            or self.engine_contract_digest != registered_contract.contract_digest
        ):
            raise ValueError("Common Campaign Execution Plan authority differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest", "campaign"},
        )
        digest = _common_engine_digest(
            "pajin.workflow.common-campaign-execution-plan/v1",
            material,
            max_bytes=_MAX_PLAN_BYTES,
        )
        authority_id = f"common-campaign-execution-plan:{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Common Campaign Execution Plan Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Common Campaign Execution Plan Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        return self


def registered_common_campaign_engine_contract() -> CommonCampaignEngineContract:
    """Return the exact code-owned ENG-001 contract."""

    return CommonCampaignEngineContract(
        acceptedSourceModes=_SOURCE_MODES,
        sharedBoundaries=_SHARED_BOUNDARIES,
        requiredParityDimensions=_PARITY_DIMENSIONS,
    )


def plan_legacy_campaign_common_execution(
    campaign: CampaignManifest,
) -> CommonCampaignExecutionPlanAuthority:
    """Bind a legacy Campaign to the common boundary without authorizing it."""

    authoritative_campaign = CampaignManifest.model_validate_json(
        campaign.model_dump_json(by_alias=True)
    )
    contract = registered_common_campaign_engine_contract()
    return CommonCampaignExecutionPlanAuthority(
        campaign=authoritative_campaign,
        campaignDigest=campaign_manifest_digest(authoritative_campaign),
        sourceMode=authoritative_campaign.spec.mode,
        engineContract=contract,
        engineContractDigest=contract.contract_digest,
    )
