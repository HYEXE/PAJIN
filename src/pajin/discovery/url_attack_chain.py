"""CHAIN-003 Snapshot-bound Prompt, URL Tool, and Internal API hypothesis."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.attack_chain import AttackChainEdgeContract, AttackChainStageContract
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.hypothesis import (
    HypothesisWaveError,
    SurfaceSnapshotAuthority,
    load_recon_surface_authority,
)
from pajin.discovery.models import (
    AttackSurface,
    HTTPInternalAPISurfaceLocator,
    MCPPromptSurfaceLocator,
    MCPURLToolSurfaceLocator,
)
from pajin.discovery.recon import ReconWaveOutcome
from pajin.domain.models import CampaignManifest, StrictModel

MODE_NEUTRAL_URL_ATTACK_CHAIN_API_VERSION: Literal[
    "pajin.dev/mode-neutral-url-attack-chain/v1alpha1"
] = "pajin.dev/mode-neutral-url-attack-chain/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_AUTHORITY_BYTES = 1024 * 1024

URLAttackChainLocator = Annotated[
    MCPPromptSurfaceLocator | MCPURLToolSurfaceLocator | HTTPInternalAPISurfaceLocator,
    Field(discriminator="kind"),
]


class ModeNeutralURLAttackChainError(ValueError):
    """Raised when CHAIN-003 cannot be derived from exact sealed authority."""


def _chain003_stage_contracts() -> tuple[AttackChainStageContract, ...]:
    return (
        AttackChainStageContract(
            ordinal=1,
            stageId="prompt-injection",
            semantic="prompt-injection-hypothesis",
            requiredAuthorityKind="SurfaceSnapshotAuthority",
            requiredExecutionState="discovered-not-authorized",
        ),
        AttackChainStageContract(
            ordinal=2,
            stageId="url-tool-control",
            semantic="mcp-url-argument-control-hypothesis",
            requiredAuthorityKind="SurfaceSnapshotAuthority",
            requiredExecutionState="discovered-not-authorized",
        ),
        AttackChainStageContract(
            ordinal=3,
            stageId="internal-api",
            semantic="target-declared-internal-api-surface",
            requiredAuthorityKind="SurfaceSnapshotAuthority",
            requiredExecutionState="discovered-not-authorized",
        ),
    )


def _chain003_edge_contracts() -> tuple[AttackChainEdgeContract, ...]:
    return (
        AttackChainEdgeContract(
            ordinal=1,
            edgeId="prompt-injection-enables-url-tool-control",
            sourceStageId="prompt-injection",
            targetStageId="url-tool-control",
        ),
        AttackChainEdgeContract(
            ordinal=2,
            edgeId="url-tool-control-enables-internal-api",
            sourceStageId="url-tool-control",
            targetStageId="internal-api",
        ),
    )


class ModeNeutralURLAttackChainContract(StrictModel):
    """Code-owned CHAIN-003 topology without reachability or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-url-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_URL_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralURLAttackChainContract"] = "ModeNeutralURLAttackChainContract"
    chain_id: Literal["chain-003:prompt-injection-url-tool-internal-api"] = Field(
        default="chain-003:prompt-injection-url-tool-internal-api",
        alias="chainId",
    )
    chain_version: Literal["1.0.0"] = Field(default="1.0.0", alias="chainVersion")
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    stages: tuple[AttackChainStageContract, ...] = Field(
        default_factory=_chain003_stage_contracts,
        min_length=3,
        max_length=3,
    )
    edges: tuple[AttackChainEdgeContract, ...] = Field(
        default_factory=_chain003_edge_contracts,
        min_length=2,
        max_length=2,
    )
    prompt_url_binding: Literal["same-mcp-server-and-campaign-target"] = Field(
        default="same-mcp-server-and-campaign-target",
        alias="promptURLBinding",
    )
    cross_target_binding: Literal["same-campaign-hypothesis-only"] = Field(
        default="same-campaign-hypothesis-only",
        alias="crossTargetBinding",
    )
    internal_api_declaration: Literal["openapi-x-pajin-internal-api"] = Field(
        default="openapi-x-pajin-internal-api",
        alias="internalAPIDeclaration",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    chain_state: Literal["hypothesized-not-validated"] = Field(
        default="hypothesized-not-validated",
        alias="chainState",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    claim_replay_authorized: Literal[False] = Field(
        default=False,
        alias="claimReplayAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator(
        "capability_granted",
        "execution_authorized",
        "claim_replay_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("URL Attack Chain Contract authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_contract_identity(self) -> Self:
        if self.stages != _chain003_stage_contracts():
            raise ValueError("CHAIN-003 Stage order or semantics differ from code authority")
        if self.edges != _chain003_edge_contracts():
            raise ValueError("CHAIN-003 Edge topology differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-url-attack-chain-contract/v1",
            material,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Mode-neutral URL Attack Chain Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral URL Attack Chain Contract",
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        return self


class URLAttackChainSurfaceReference(StrictModel):
    """Exact bounded reference to one Surface in a CHAIN-003 Snapshot."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    surface_id: str = Field(
        alias="surfaceId",
        pattern=r"^attack-surface_[a-f0-9]{64}$",
    )
    target_id: str = Field(
        alias="targetId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    locator_kind: Literal["mcp-prompt", "mcp-url-tool", "http-internal-api"] = Field(
        alias="locatorKind"
    )
    locator: URLAttackChainLocator
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    observation_count: int = Field(alias="observationCount", ge=1, le=1_000)

    @model_validator(mode="after")
    def bind_locator(self) -> Self:
        expected = discovery_digest(
            "pajin.discovery.mode-neutral-url-attack-chain-locator/v1",
            self.locator.model_dump(mode="json"),
        )
        if self.locator_kind != self.locator.kind or self.locator_digest != expected:
            raise ValueError("URL Attack Chain Surface locator identity differs")
        return self


class URLAttackChainStageReference(StrictModel):
    """One ordered CHAIN-003 stage bound to an exact Snapshot Surface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ordinal: int = Field(ge=1, le=3)
    stage_id: str = Field(alias="stageId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    semantic: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    authority_kind: Literal["SurfaceSnapshotAuthority"] = Field(alias="authorityKind")
    surface_snapshot_id: str = Field(
        alias="surfaceSnapshotId",
        pattern=r"^surface-snapshot_[a-f0-9]{64}$",
    )
    surface_snapshot_digest: _Sha256 = Field(alias="surfaceSnapshotDigest")
    surface: URLAttackChainSurfaceReference
    execution_state: Literal["discovered-not-authorized"] = Field(alias="executionState")


class ModeNeutralURLAttackChainAuthority(StrictModel):
    """Exact Snapshot-bound CHAIN-003 hypothesis with no reachability authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-url-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_URL_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralURLAttackChainAuthority"] = "ModeNeutralURLAttackChainAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    contract: ModeNeutralURLAttackChainContract
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    mcp_surface_snapshot: SurfaceSnapshotAuthority = Field(alias="mcpSurfaceSnapshot")
    internal_api_surface_snapshot: SurfaceSnapshotAuthority = Field(
        alias="internalAPISurfaceSnapshot"
    )
    stages: tuple[URLAttackChainStageReference, ...] = Field(min_length=3, max_length=3)
    edges: tuple[AttackChainEdgeContract, ...] = Field(min_length=2, max_length=2)
    chain_state: Literal["hypothesized-not-validated"] = Field(
        default="hypothesized-not-validated",
        alias="chainState",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    cross_target_binding: Literal["same-campaign-hypothesis-only"] = Field(
        default="same-campaign-hypothesis-only",
        alias="crossTargetBinding",
    )
    surface_evidence_only: Literal[True] = Field(default=True, alias="surfaceEvidenceOnly")
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )
    claim_replay_authorized: Literal[False] = Field(
        default=False,
        alias="claimReplayAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator("surface_evidence_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("URL Attack Chain Surface evidence marker must be boolean true")
        return value

    @field_validator(
        "capability_granted",
        "execution_authorized",
        "claim_replay_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("URL Attack Chain authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority_identity(self) -> Self:
        registered = registered_prompt_url_internal_api_chain_contract()
        snapshots = (self.mcp_surface_snapshot, self.internal_api_surface_snapshot)
        if self.contract != registered:
            raise ValueError("CHAIN-003 Contract differs from code authority")
        if any(
            snapshot.campaign != self.campaign_id
            or snapshot.campaign_digest != self.campaign_digest
            for snapshot in snapshots
        ):
            raise ValueError("CHAIN-003 belongs to another Campaign authority")
        if self.stages != _chain003_stage_references(
            self.mcp_surface_snapshot,
            self.internal_api_surface_snapshot,
            *(stage.surface for stage in self.stages),
        ):
            raise ValueError("CHAIN-003 Stage lineage is missing, reordered, or substituted")
        if self.edges != registered.edges:
            raise ValueError("CHAIN-003 Edge topology differs from code authority")
        prompt = self.stages[0].surface.locator
        url_tool = self.stages[1].surface.locator
        internal_api = self.stages[2].surface.locator
        if (
            not isinstance(prompt, MCPPromptSurfaceLocator)
            or not prompt.arguments
            or not isinstance(url_tool, MCPURLToolSurfaceLocator)
            or not isinstance(internal_api, HTTPInternalAPISurfaceLocator)
            or self.stages[0].surface.target_id != self.stages[1].surface.target_id
            or prompt.server_id != url_tool.server_id
        ):
            raise ValueError("CHAIN-003 Surface roles or MCP binding differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-url-attack-chain-authority/v1",
            material,
        )
        authority_id = f"mode-neutral-url-attack-chain_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Mode-neutral URL Attack Chain Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Mode-neutral URL Attack Chain Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral URL Attack Chain Authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


def registered_prompt_url_internal_api_chain_contract() -> ModeNeutralURLAttackChainContract:
    """Return the exact code-owned CHAIN-003 stage and edge topology."""

    return ModeNeutralURLAttackChainContract()


def compile_prompt_url_internal_api_chain(
    campaign: CampaignManifest,
    mcp_recon: ReconWaveOutcome,
    internal_api_recon: ReconWaveOutcome,
    *,
    prompt_surface_id: str,
    url_tool_surface_id: str,
    internal_api_surface_id: str,
) -> ModeNeutralURLAttackChainAuthority:
    """Derive CHAIN-003 from exact sealed Surface authority without executing it."""

    try:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        mcp_set, mcp_snapshot = load_recon_surface_authority(
            authoritative_campaign,
            mcp_recon,
        )
        internal_set, internal_snapshot = load_recon_surface_authority(
            authoritative_campaign,
            internal_api_recon,
        )
        prompt = _surface_by_id(mcp_set.surfaces, prompt_surface_id)
        url_tool = _surface_by_id(mcp_set.surfaces, url_tool_surface_id)
        internal_api = _surface_by_id(internal_set.surfaces, internal_api_surface_id)
        prompt_locator = prompt.locator
        url_tool_locator = url_tool.locator
        internal_api_locator = internal_api.locator
        if not isinstance(prompt_locator, MCPPromptSurfaceLocator) or not prompt_locator.arguments:
            raise ValueError("CHAIN-003 prompt has no declared input boundary")
        if not isinstance(url_tool_locator, MCPURLToolSurfaceLocator):
            raise ValueError("CHAIN-003 URL Tool is not an explicit URL argument boundary")
        if not isinstance(internal_api_locator, HTTPInternalAPISurfaceLocator):
            raise ValueError("CHAIN-003 target is not an explicitly declared Internal API")
        if (
            prompt.target_id != url_tool.target_id
            or prompt_locator.server_id != url_tool_locator.server_id
        ):
            raise ValueError("CHAIN-003 MCP Prompt and URL Tool belong to different boundaries")
        _require_declared_target(authoritative_campaign, prompt.target_id)
        _require_declared_target(authoritative_campaign, internal_api.target_id)
        campaign_digest = mcp_snapshot.campaign_digest
        if (
            campaign_digest is None
            or internal_snapshot.campaign_digest is None
            or internal_snapshot.campaign_digest != campaign_digest
        ):
            raise ValueError("CHAIN-003 requires one Campaign-bound Snapshot authority")
        prompt_reference = _surface_reference(prompt)
        url_tool_reference = _surface_reference(url_tool)
        internal_api_reference = _surface_reference(internal_api)
        contract = registered_prompt_url_internal_api_chain_contract()
        return ModeNeutralURLAttackChainAuthority(
            contract=contract,
            campaignId=authoritative_campaign.metadata.name,
            campaignDigest=campaign_digest,
            mcpSurfaceSnapshot=mcp_snapshot.model_copy(deep=True),
            internalAPISurfaceSnapshot=internal_snapshot.model_copy(deep=True),
            stages=_chain003_stage_references(
                mcp_snapshot,
                internal_snapshot,
                prompt_reference,
                url_tool_reference,
                internal_api_reference,
            ),
            edges=contract.edges,
        )
    except ModeNeutralURLAttackChainError:
        raise
    except (AttributeError, HypothesisWaveError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralURLAttackChainError(
            "CHAIN-003 could not be compiled from sealed Surface authority"
        ) from exc


def verify_prompt_url_internal_api_chain(
    authority: ModeNeutralURLAttackChainAuthority,
    campaign: CampaignManifest,
    mcp_recon: ReconWaveOutcome,
    internal_api_recon: ReconWaveOutcome,
) -> ModeNeutralURLAttackChainAuthority:
    """Rebuild and exact-match CHAIN-003 against both sealed Recon authorities."""

    try:
        canonical = ModeNeutralURLAttackChainAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        expected = compile_prompt_url_internal_api_chain(
            campaign,
            mcp_recon,
            internal_api_recon,
            prompt_surface_id=canonical.stages[0].surface.surface_id,
            url_tool_surface_id=canonical.stages[1].surface.surface_id,
            internal_api_surface_id=canonical.stages[2].surface.surface_id,
        )
        if canonical != expected:
            raise ValueError("CHAIN-003 differs from sealed Surface authority")
        return canonical
    except ModeNeutralURLAttackChainError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralURLAttackChainError(
            "CHAIN-003 could not be verified against sealed Surface authority"
        ) from exc


def _surface_by_id(surfaces: list[AttackSurface], surface_id: str) -> AttackSurface:
    matches = [surface for surface in surfaces if surface.surface_id == surface_id]
    if len(matches) != 1:
        raise ValueError("CHAIN-003 Surface is missing or ambiguous")
    return matches[0]


def _surface_reference(surface: AttackSurface) -> URLAttackChainSurfaceReference:
    locator = surface.locator
    if not isinstance(
        locator,
        (MCPPromptSurfaceLocator, MCPURLToolSurfaceLocator, HTTPInternalAPISurfaceLocator),
    ):
        raise ValueError("CHAIN-003 Surface reference uses an unsupported locator")
    return URLAttackChainSurfaceReference(
        surfaceId=surface.surface_id,
        targetId=surface.target_id,
        locatorKind=locator.kind,
        locator=locator.model_copy(deep=True),
        locatorDigest=discovery_digest(
            "pajin.discovery.mode-neutral-url-attack-chain-locator/v1",
            locator.model_dump(mode="json"),
        ),
        surfaceDigest=discovery_digest(
            "pajin.discovery.mode-neutral-url-attack-chain-surface/v1",
            surface.model_dump(mode="json"),
        ),
        observationCount=len(surface.observation_ids),
    )


def _chain003_stage_references(
    mcp_snapshot: SurfaceSnapshotAuthority,
    internal_api_snapshot: SurfaceSnapshotAuthority,
    prompt: URLAttackChainSurfaceReference,
    url_tool: URLAttackChainSurfaceReference,
    internal_api: URLAttackChainSurfaceReference,
) -> tuple[URLAttackChainStageReference, ...]:
    stage_contracts = _chain003_stage_contracts()
    bindings = (
        (stage_contracts[0], mcp_snapshot, prompt),
        (stage_contracts[1], mcp_snapshot, url_tool),
        (stage_contracts[2], internal_api_snapshot, internal_api),
    )
    return tuple(
        URLAttackChainStageReference(
            ordinal=stage.ordinal,
            stageId=stage.stage_id,
            semantic=stage.semantic,
            authorityKind=snapshot.kind,
            surfaceSnapshotId=snapshot.snapshot_id,
            surfaceSnapshotDigest=snapshot.snapshot_digest,
            surface=surface,
            executionState="discovered-not-authorized",
        )
        for stage, snapshot, surface in bindings
    )


def _require_declared_target(campaign: CampaignManifest, target_id: str) -> None:
    if len([target for target in campaign.spec.targets if target.id == target_id]) != 1:
        raise ValueError("CHAIN-003 target is not declared exactly once by the Campaign")
