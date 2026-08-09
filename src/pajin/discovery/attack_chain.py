"""CHAIN-001 mode-neutral, non-executable attack-chain contract."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.hypothesis import (
    HypothesisWaveError,
    SurfaceSnapshotAuthority,
    load_recon_surface_authority,
)
from pajin.discovery.models import (
    AttackSurface,
    HTTPAuthenticationSurfaceLocator,
    HTTPRAGSurfaceLocator,
)
from pajin.discovery.recon import ReconWaveOutcome
from pajin.domain.models import CampaignManifest, StrictModel

MODE_NEUTRAL_ATTACK_CHAIN_API_VERSION: Literal["pajin.dev/mode-neutral-attack-chain/v1alpha1"] = (
    "pajin.dev/mode-neutral-attack-chain/v1alpha1"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_AUTHORITY_BYTES = 1024 * 1024

AttackChainLocator = Annotated[
    HTTPAuthenticationSurfaceLocator | HTTPRAGSurfaceLocator,
    Field(discriminator="kind"),
]


class ModeNeutralAttackChainError(ValueError):
    """Raised when CHAIN-001 cannot be derived from exact sealed authority."""


class ModeNeutralAttackChainContract(StrictModel):
    """Code-owned CHAIN-001 semantics without Campaign or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralAttackChainContract"] = "ModeNeutralAttackChainContract"
    chain_id: Literal["chain-001:auth-bypass-to-ai-admin-surface"] = Field(
        default="chain-001:auth-bypass-to-ai-admin-surface",
        alias="chainId",
    )
    chain_version: Literal["1.0.0"] = Field(default="1.0.0", alias="chainVersion")
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    source_semantic: Literal["authentication-enforcement-boundary"] = Field(
        default="authentication-enforcement-boundary",
        alias="sourceSemantic",
    )
    source_locator_kind: Literal["http-authentication"] = Field(
        default="http-authentication",
        alias="sourceLocatorKind",
    )
    attack_condition: Literal["authentication-enforcement-bypass"] = Field(
        default="authentication-enforcement-bypass",
        alias="attackCondition",
    )
    target_semantic: Literal["ai-admin-surface"] = Field(
        default="ai-admin-surface",
        alias="targetSemantic",
    )
    target_locator_kind: Literal["http-rag"] = Field(
        default="http-rag",
        alias="targetLocatorKind",
    )
    target_rag_boundary: Literal["index-management"] = Field(
        default="index-management",
        alias="targetRagBoundary",
    )
    route_binding: Literal["exact-same-route"] = Field(
        default="exact-same-route",
        alias="routeBinding",
    )
    target_binding: Literal["same-campaign-target"] = Field(
        default="same-campaign-target",
        alias="targetBinding",
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
            raise ValueError("Attack Chain Contract authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_contract_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        digest = discovery_digest("pajin.discovery.mode-neutral-attack-chain-contract/v1", material)
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Mode-neutral Attack Chain Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Attack Chain Contract",
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        return self


class AttackChainSurfaceReference(StrictModel):
    """Exact bounded reference to one Surface inside the bound Snapshot."""

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
    locator_kind: Literal["http-authentication", "http-rag"] = Field(alias="locatorKind")
    locator: AttackChainLocator
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    observation_count: int = Field(alias="observationCount", ge=1, le=1_000)

    @model_validator(mode="after")
    def bind_locator(self) -> Self:
        expected = discovery_digest(
            "pajin.discovery.mode-neutral-attack-chain-locator/v1",
            self.locator.model_dump(mode="json"),
        )
        if self.locator_kind != self.locator.kind or self.locator_digest != expected:
            raise ValueError("Attack Chain Surface locator identity differs")
        return self


class ModeNeutralAttackChainAuthority(StrictModel):
    """Snapshot-bound CHAIN-001 hypothesis that grants no validation or execution."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralAttackChainAuthority"] = "ModeNeutralAttackChainAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    contract: ModeNeutralAttackChainContract
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    surface_snapshot: SurfaceSnapshotAuthority = Field(alias="surfaceSnapshot")
    source_surface: AttackChainSurfaceReference = Field(alias="sourceSurface")
    target_surface: AttackChainSurfaceReference = Field(alias="targetSurface")
    route_digest: _Sha256 = Field(alias="routeDigest")
    chain_state: Literal["hypothesized-not-validated"] = Field(
        default="hypothesized-not-validated",
        alias="chainState",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    surface_evidence_only: Literal[True] = Field(
        default=True,
        alias="surfaceEvidenceOnly",
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

    @field_validator("surface_evidence_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Attack Chain Surface evidence marker must be boolean true")
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
            raise ValueError("Attack Chain authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority_identity(self) -> Self:
        registered = registered_auth_bypass_ai_admin_chain_contract()
        snapshot = self.surface_snapshot
        if self.contract != registered:
            raise ValueError("Attack Chain Contract differs from code authority")
        if (
            snapshot.campaign_digest is None
            or self.campaign_id != snapshot.campaign
            or self.campaign_digest != snapshot.campaign_digest
        ):
            raise ValueError("Attack Chain belongs to another Campaign authority")
        if (
            self.source_surface.locator_kind != registered.source_locator_kind
            or self.target_surface.locator_kind != registered.target_locator_kind
            or self.source_surface.surface_id == self.target_surface.surface_id
            or self.source_surface.target_id != self.target_surface.target_id
        ):
            raise ValueError("Attack Chain Surface roles or target binding differ")
        source_locator = self.source_surface.locator
        target_locator = self.target_surface.locator
        if (
            not isinstance(source_locator, HTTPAuthenticationSurfaceLocator)
            or source_locator.allows_anonymous
            or not isinstance(target_locator, HTTPRAGSurfaceLocator)
            or target_locator.boundary != registered.target_rag_boundary
            or source_locator.route != target_locator.route
        ):
            raise ValueError("Attack Chain locator semantics differ from the registered contract")
        expected_route_digest = discovery_digest(
            "pajin.discovery.mode-neutral-attack-chain-route/v1",
            source_locator.route.model_dump(mode="json"),
        )
        if self.route_digest != expected_route_digest:
            raise ValueError("Attack Chain route Digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-attack-chain-authority/v1",
            material,
        )
        authority_id = f"mode-neutral-attack-chain_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Mode-neutral Attack Chain Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Mode-neutral Attack Chain Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Attack Chain Authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


def registered_auth_bypass_ai_admin_chain_contract() -> ModeNeutralAttackChainContract:
    """Return the exact code-owned CHAIN-001 contract."""

    return ModeNeutralAttackChainContract()


def compile_auth_bypass_ai_admin_chain(
    campaign: CampaignManifest,
    recon: ReconWaveOutcome,
    *,
    source_surface_id: str,
    target_surface_id: str,
) -> ModeNeutralAttackChainAuthority:
    """Derive CHAIN-001 from one exact sealed Surface Snapshot without executing it."""

    try:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        surface_set, snapshot = load_recon_surface_authority(authoritative_campaign, recon)
        source = _surface_by_id(surface_set.surfaces, source_surface_id)
        target = _surface_by_id(surface_set.surfaces, target_surface_id)
        source_locator = source.locator
        target_locator = target.locator
        if not isinstance(source_locator, HTTPAuthenticationSurfaceLocator):
            raise ValueError("CHAIN-001 source is not an authentication boundary")
        if source_locator.allows_anonymous:
            raise ValueError("CHAIN-001 source allows anonymous access")
        if not isinstance(target_locator, HTTPRAGSurfaceLocator):
            raise ValueError("CHAIN-001 target is not an AI/RAG boundary")
        if target_locator.boundary != "index-management":
            raise ValueError("CHAIN-001 target is not an AI administration boundary")
        if source.target_id != target.target_id:
            raise ValueError("CHAIN-001 Surfaces belong to different Campaign targets")
        matching_targets = [
            item for item in authoritative_campaign.spec.targets if item.id == source.target_id
        ]
        if len(matching_targets) != 1:
            raise ValueError("CHAIN-001 target is not declared exactly once by the Campaign")
        if source_locator.route != target_locator.route:
            raise ValueError("CHAIN-001 authentication and AI administration routes differ")
        route_digest = discovery_digest(
            "pajin.discovery.mode-neutral-attack-chain-route/v1",
            source_locator.route.model_dump(mode="json"),
        )
        campaign_digest = snapshot.campaign_digest
        if campaign_digest is None:
            raise ValueError("CHAIN-001 requires Campaign-bound Surface Snapshot authority")
        return ModeNeutralAttackChainAuthority(
            contract=registered_auth_bypass_ai_admin_chain_contract(),
            campaignId=authoritative_campaign.metadata.name,
            campaignDigest=campaign_digest,
            surfaceSnapshot=snapshot.model_copy(deep=True),
            sourceSurface=_surface_reference(source),
            targetSurface=_surface_reference(target),
            routeDigest=route_digest,
        )
    except ModeNeutralAttackChainError:
        raise
    except (AttributeError, HypothesisWaveError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralAttackChainError(
            "CHAIN-001 could not be compiled from sealed Surface authority"
        ) from exc


def verify_auth_bypass_ai_admin_chain(
    authority: ModeNeutralAttackChainAuthority,
    campaign: CampaignManifest,
    recon: ReconWaveOutcome,
) -> ModeNeutralAttackChainAuthority:
    """Rebuild and exact-match CHAIN-001 against its sealed predecessor authority."""

    try:
        canonical = ModeNeutralAttackChainAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        expected = compile_auth_bypass_ai_admin_chain(
            campaign,
            recon,
            source_surface_id=canonical.source_surface.surface_id,
            target_surface_id=canonical.target_surface.surface_id,
        )
        if canonical != expected:
            raise ValueError("CHAIN-001 differs from sealed Surface authority")
        return canonical
    except ModeNeutralAttackChainError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralAttackChainError(
            "CHAIN-001 could not be verified against sealed Surface authority"
        ) from exc


def _surface_by_id(surfaces: list[AttackSurface], surface_id: str) -> AttackSurface:
    matches = [surface for surface in surfaces if surface.surface_id == surface_id]
    if len(matches) != 1:
        raise ValueError("CHAIN-001 Surface is missing or ambiguous")
    return matches[0]


def _surface_reference(surface: AttackSurface) -> AttackChainSurfaceReference:
    locator = surface.locator
    if not isinstance(locator, (HTTPAuthenticationSurfaceLocator, HTTPRAGSurfaceLocator)):
        raise ValueError("CHAIN-001 Surface reference uses an unsupported locator")
    return AttackChainSurfaceReference(
        surfaceId=surface.surface_id,
        targetId=surface.target_id,
        locatorKind=locator.kind,
        locator=locator.model_copy(deep=True),
        locatorDigest=discovery_digest(
            "pajin.discovery.mode-neutral-attack-chain-locator/v1",
            locator.model_dump(mode="json"),
        ),
        surfaceDigest=discovery_digest(
            "pajin.discovery.mode-neutral-attack-chain-surface/v1",
            surface.model_dump(mode="json"),
        ),
        observationCount=len(surface.observation_ids),
    )
