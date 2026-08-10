"""CHAIN-004 Snapshot-bound cross-tenant retrieval and data-response hypothesis."""

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
    HTTPDataResponseSurfaceLocator,
    HTTPTenantRetrievalSurfaceLocator,
)
from pajin.discovery.recon import ReconWaveOutcome
from pajin.domain.models import CampaignManifest, StrictModel

MODE_NEUTRAL_TENANT_ATTACK_CHAIN_API_VERSION: Literal[
    "pajin.dev/mode-neutral-tenant-attack-chain/v1alpha1"
] = "pajin.dev/mode-neutral-tenant-attack-chain/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_AUTHORITY_BYTES = 1024 * 1024

TenantAttackChainLocator = Annotated[
    HTTPTenantRetrievalSurfaceLocator | HTTPDataResponseSurfaceLocator,
    Field(discriminator="kind"),
]


class ModeNeutralTenantAttackChainError(ValueError):
    """Raised when CHAIN-004 cannot be derived from exact sealed authority."""


def _chain004_stage_contracts() -> tuple[AttackChainStageContract, ...]:
    return (
        AttackChainStageContract(
            ordinal=1,
            stageId="cross-tenant-retrieval",
            semantic="cross-tenant-retrieval-hypothesis",
            requiredAuthorityKind="SurfaceSnapshotAuthority",
            requiredExecutionState="discovered-not-authorized",
        ),
        AttackChainStageContract(
            ordinal=2,
            stageId="data-exposure",
            semantic="declared-data-response-surface",
            requiredAuthorityKind="SurfaceSnapshotAuthority",
            requiredExecutionState="discovered-not-authorized",
        ),
    )


def _chain004_edge_contracts() -> tuple[AttackChainEdgeContract, ...]:
    return (
        AttackChainEdgeContract(
            ordinal=1,
            edgeId="cross-tenant-retrieval-enables-data-exposure",
            sourceStageId="cross-tenant-retrieval",
            targetStageId="data-exposure",
        ),
    )


class ModeNeutralTenantAttackChainContract(StrictModel):
    """Code-owned CHAIN-004 topology without access or exposure authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-tenant-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_TENANT_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralTenantAttackChainContract"] = "ModeNeutralTenantAttackChainContract"
    chain_id: Literal["chain-004:cross-tenant-retrieval-data-exposure"] = Field(
        default="chain-004:cross-tenant-retrieval-data-exposure",
        alias="chainId",
    )
    chain_version: Literal["1.0.0"] = Field(default="1.0.0", alias="chainVersion")
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    stages: tuple[AttackChainStageContract, ...] = Field(
        default_factory=_chain004_stage_contracts,
        min_length=2,
        max_length=2,
    )
    edges: tuple[AttackChainEdgeContract, ...] = Field(
        default_factory=_chain004_edge_contracts,
        min_length=1,
        max_length=1,
    )
    route_binding: Literal["exact-same-route"] = Field(
        default="exact-same-route",
        alias="routeBinding",
    )
    target_binding: Literal["same-campaign-target"] = Field(
        default="same-campaign-target",
        alias="targetBinding",
    )
    tenant_declaration: Literal["openapi-x-pajin-tenant-retrieval"] = Field(
        default="openapi-x-pajin-tenant-retrieval",
        alias="tenantDeclaration",
    )
    data_declaration: Literal["openapi-x-pajin-data-response"] = Field(
        default="openapi-x-pajin-data-response",
        alias="dataDeclaration",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    chain_state: Literal["hypothesized-not-validated"] = Field(
        default="hypothesized-not-validated",
        alias="chainState",
    )
    tenant_values_retained: Literal[False] = Field(default=False, alias="tenantValuesRetained")
    cross_tenant_access_confirmed: Literal[False] = Field(
        default=False,
        alias="crossTenantAccessConfirmed",
    )
    data_exposure_confirmed: Literal[False] = Field(
        default=False,
        alias="dataExposureConfirmed",
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
        "tenant_values_retained",
        "cross_tenant_access_confirmed",
        "data_exposure_confirmed",
        "capability_granted",
        "execution_authorized",
        "claim_replay_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Tenant Attack Chain Contract markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_contract_identity(self) -> Self:
        if self.stages != _chain004_stage_contracts():
            raise ValueError("CHAIN-004 Stage order or semantics differ from code authority")
        if self.edges != _chain004_edge_contracts():
            raise ValueError("CHAIN-004 Edge topology differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-tenant-attack-chain-contract/v1",
            material,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Mode-neutral Tenant Attack Chain Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Tenant Attack Chain Contract",
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        return self


class TenantAttackChainSurfaceReference(StrictModel):
    """Exact bounded reference to one CHAIN-004 Surface."""

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
    locator_kind: Literal["http-tenant-retrieval", "http-data-response"] = Field(
        alias="locatorKind"
    )
    locator: TenantAttackChainLocator
    locator_digest: _Sha256 = Field(alias="locatorDigest")
    surface_digest: _Sha256 = Field(alias="surfaceDigest")
    observation_count: int = Field(alias="observationCount", ge=1, le=1_000)

    @model_validator(mode="after")
    def bind_locator(self) -> Self:
        expected = discovery_digest(
            "pajin.discovery.mode-neutral-tenant-attack-chain-locator/v1",
            self.locator.model_dump(mode="json"),
        )
        if self.locator_kind != self.locator.kind or self.locator_digest != expected:
            raise ValueError("Tenant Attack Chain Surface locator identity differs")
        return self


class TenantAttackChainStageReference(StrictModel):
    """One ordered CHAIN-004 stage bound to an exact Snapshot Surface."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ordinal: int = Field(ge=1, le=2)
    stage_id: str = Field(alias="stageId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    semantic: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    authority_kind: Literal["SurfaceSnapshotAuthority"] = Field(alias="authorityKind")
    surface_snapshot_id: str = Field(
        alias="surfaceSnapshotId",
        pattern=r"^surface-snapshot_[a-f0-9]{64}$",
    )
    surface_snapshot_digest: _Sha256 = Field(alias="surfaceSnapshotDigest")
    surface: TenantAttackChainSurfaceReference
    execution_state: Literal["discovered-not-authorized"] = Field(alias="executionState")


class ModeNeutralTenantAttackChainAuthority(StrictModel):
    """Exact Snapshot-bound CHAIN-004 hypothesis with no access authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-tenant-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_TENANT_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralTenantAttackChainAuthority"] = "ModeNeutralTenantAttackChainAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    contract: ModeNeutralTenantAttackChainContract
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    surface_snapshot: SurfaceSnapshotAuthority = Field(alias="surfaceSnapshot")
    stages: tuple[TenantAttackChainStageReference, ...] = Field(min_length=2, max_length=2)
    edges: tuple[AttackChainEdgeContract, ...] = Field(min_length=1, max_length=1)
    route_digest: _Sha256 = Field(alias="routeDigest")
    chain_state: Literal["hypothesized-not-validated"] = Field(
        default="hypothesized-not-validated",
        alias="chainState",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    surface_evidence_only: Literal[True] = Field(default=True, alias="surfaceEvidenceOnly")
    cross_tenant_access_confirmed: Literal[False] = Field(
        default=False,
        alias="crossTenantAccessConfirmed",
    )
    data_exposure_confirmed: Literal[False] = Field(
        default=False,
        alias="dataExposureConfirmed",
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
            raise ValueError("Tenant Attack Chain Surface evidence marker must be boolean true")
        return value

    @field_validator(
        "cross_tenant_access_confirmed",
        "data_exposure_confirmed",
        "capability_granted",
        "execution_authorized",
        "claim_replay_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Tenant Attack Chain authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority_identity(self) -> Self:
        registered = registered_cross_tenant_data_exposure_chain_contract()
        snapshot = self.surface_snapshot
        if self.contract != registered:
            raise ValueError("CHAIN-004 Contract differs from code authority")
        if (
            snapshot.campaign_digest is None
            or snapshot.campaign != self.campaign_id
            or snapshot.campaign_digest != self.campaign_digest
        ):
            raise ValueError("CHAIN-004 belongs to another Campaign authority")
        if self.stages != _chain004_stage_references(
            snapshot,
            self.stages[0].surface,
            self.stages[1].surface,
        ):
            raise ValueError("CHAIN-004 Stage lineage is missing, reordered, or substituted")
        if self.edges != registered.edges:
            raise ValueError("CHAIN-004 Edge topology differs from code authority")
        tenant = self.stages[0].surface
        data = self.stages[1].surface
        tenant_locator = tenant.locator
        data_locator = data.locator
        if (
            not isinstance(tenant_locator, HTTPTenantRetrievalSurfaceLocator)
            or not isinstance(data_locator, HTTPDataResponseSurfaceLocator)
            or tenant.surface_id == data.surface_id
            or tenant.target_id != data.target_id
            or tenant_locator.retrieval.route != data_locator.route
        ):
            raise ValueError("CHAIN-004 Surface roles, target, or route binding differ")
        expected_route_digest = discovery_digest(
            "pajin.discovery.mode-neutral-tenant-attack-chain-route/v1",
            tenant_locator.retrieval.route.model_dump(mode="json"),
        )
        if self.route_digest != expected_route_digest:
            raise ValueError("CHAIN-004 route Digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-tenant-attack-chain-authority/v1",
            material,
        )
        authority_id = f"mode-neutral-tenant-attack-chain_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Mode-neutral Tenant Attack Chain Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Mode-neutral Tenant Attack Chain Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Tenant Attack Chain Authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


def registered_cross_tenant_data_exposure_chain_contract() -> ModeNeutralTenantAttackChainContract:
    """Return the exact code-owned CHAIN-004 topology."""

    return ModeNeutralTenantAttackChainContract()


def compile_cross_tenant_data_exposure_chain(
    campaign: CampaignManifest,
    recon: ReconWaveOutcome,
    *,
    tenant_retrieval_surface_id: str,
    data_response_surface_id: str,
) -> ModeNeutralTenantAttackChainAuthority:
    """Derive CHAIN-004 from exact sealed Surface authority without executing it."""

    try:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        surface_set, snapshot = load_recon_surface_authority(authoritative_campaign, recon)
        tenant = _surface_by_id(surface_set.surfaces, tenant_retrieval_surface_id)
        data = _surface_by_id(surface_set.surfaces, data_response_surface_id)
        tenant_locator = tenant.locator
        data_locator = data.locator
        if not isinstance(tenant_locator, HTTPTenantRetrievalSurfaceLocator):
            raise ValueError("CHAIN-004 source is not an explicit tenant retrieval boundary")
        if not isinstance(data_locator, HTTPDataResponseSurfaceLocator):
            raise ValueError("CHAIN-004 target is not an explicit data response boundary")
        if tenant.target_id != data.target_id:
            raise ValueError("CHAIN-004 Surfaces belong to different Campaign targets")
        if tenant_locator.retrieval.route != data_locator.route:
            raise ValueError("CHAIN-004 tenant retrieval and data response routes differ")
        if (
            len(
                [
                    target
                    for target in authoritative_campaign.spec.targets
                    if target.id == tenant.target_id
                ]
            )
            != 1
        ):
            raise ValueError("CHAIN-004 target is not declared exactly once by the Campaign")
        campaign_digest = snapshot.campaign_digest
        if campaign_digest is None:
            raise ValueError("CHAIN-004 requires Campaign-bound Surface Snapshot authority")
        tenant_reference = _surface_reference(tenant)
        data_reference = _surface_reference(data)
        contract = registered_cross_tenant_data_exposure_chain_contract()
        route_digest = discovery_digest(
            "pajin.discovery.mode-neutral-tenant-attack-chain-route/v1",
            tenant_locator.retrieval.route.model_dump(mode="json"),
        )
        return ModeNeutralTenantAttackChainAuthority(
            contract=contract,
            campaignId=authoritative_campaign.metadata.name,
            campaignDigest=campaign_digest,
            surfaceSnapshot=snapshot.model_copy(deep=True),
            stages=_chain004_stage_references(
                snapshot,
                tenant_reference,
                data_reference,
            ),
            edges=contract.edges,
            routeDigest=route_digest,
        )
    except ModeNeutralTenantAttackChainError:
        raise
    except (AttributeError, HypothesisWaveError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralTenantAttackChainError(
            "CHAIN-004 could not be compiled from sealed Surface authority"
        ) from exc


def verify_cross_tenant_data_exposure_chain(
    authority: ModeNeutralTenantAttackChainAuthority,
    campaign: CampaignManifest,
    recon: ReconWaveOutcome,
) -> ModeNeutralTenantAttackChainAuthority:
    """Rebuild and exact-match CHAIN-004 against its sealed Recon authority."""

    try:
        canonical = ModeNeutralTenantAttackChainAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        expected = compile_cross_tenant_data_exposure_chain(
            campaign,
            recon,
            tenant_retrieval_surface_id=canonical.stages[0].surface.surface_id,
            data_response_surface_id=canonical.stages[1].surface.surface_id,
        )
        if canonical != expected:
            raise ValueError("CHAIN-004 differs from sealed Surface authority")
        return canonical
    except ModeNeutralTenantAttackChainError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralTenantAttackChainError(
            "CHAIN-004 could not be verified against sealed Surface authority"
        ) from exc


def _surface_by_id(surfaces: list[AttackSurface], surface_id: str) -> AttackSurface:
    matches = [surface for surface in surfaces if surface.surface_id == surface_id]
    if len(matches) != 1:
        raise ValueError("CHAIN-004 Surface is missing or ambiguous")
    return matches[0]


def _surface_reference(surface: AttackSurface) -> TenantAttackChainSurfaceReference:
    locator = surface.locator
    if not isinstance(
        locator,
        (HTTPTenantRetrievalSurfaceLocator, HTTPDataResponseSurfaceLocator),
    ):
        raise ValueError("CHAIN-004 Surface reference uses an unsupported locator")
    return TenantAttackChainSurfaceReference(
        surfaceId=surface.surface_id,
        targetId=surface.target_id,
        locatorKind=locator.kind,
        locator=locator.model_copy(deep=True),
        locatorDigest=discovery_digest(
            "pajin.discovery.mode-neutral-tenant-attack-chain-locator/v1",
            locator.model_dump(mode="json"),
        ),
        surfaceDigest=discovery_digest(
            "pajin.discovery.mode-neutral-tenant-attack-chain-surface/v1",
            surface.model_dump(mode="json"),
        ),
        observationCount=len(surface.observation_ids),
    )


def _chain004_stage_references(
    snapshot: SurfaceSnapshotAuthority,
    tenant: TenantAttackChainSurfaceReference,
    data: TenantAttackChainSurfaceReference,
) -> tuple[TenantAttackChainStageReference, ...]:
    stage_contracts = _chain004_stage_contracts()
    return tuple(
        TenantAttackChainStageReference(
            ordinal=stage.ordinal,
            stageId=stage.stage_id,
            semantic=stage.semantic,
            authorityKind=snapshot.kind,
            surfaceSnapshotId=snapshot.snapshot_id,
            surfaceSnapshotDigest=snapshot.snapshot_digest,
            surface=surface,
            executionState="discovered-not-authorized",
        )
        for stage, surface in zip(stage_contracts, (tenant, data), strict=True)
    )
