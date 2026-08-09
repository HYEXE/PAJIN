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
from pajin.discovery.walking import (
    RAGInjectionHypothesisAuthority,
    default_rag_injection_hypothesis_rule,
    walking_campaign_digest,
)
from pajin.discovery.walking_mcp import (
    MCPToolAuthorizationHypothesisAuthority,
    MCPToolAuthorizationHypothesisOutcome,
    mcp_tool_authorization_rule,
)
from pajin.discovery.walking_replanning import (
    SealedMCPAuthorizationHypothesisDependency,
    WalkingObservationReplanError,
    load_sealed_mcp_authorization_hypothesis_dependency,
)
from pajin.domain.models import (
    CampaignManifest,
    StrictModel,
    campaign_manifest_digest,
)

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


class AttackChainStageContract(StrictModel):
    """Reusable code-owned meaning and predecessor state for one chain stage."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ordinal: int = Field(ge=1, le=8)
    stage_id: str = Field(
        alias="stageId",
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    semantic: str = Field(
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    required_authority_kind: str = Field(
        alias="requiredAuthorityKind",
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z][A-Za-z0-9]+$",
    )
    required_execution_state: str = Field(
        alias="requiredExecutionState",
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )


class AttackChainEdgeContract(StrictModel):
    """Reusable ordered relationship between two exact chain stages."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ordinal: int = Field(ge=1, le=7)
    edge_id: str = Field(
        alias="edgeId",
        min_length=1,
        max_length=160,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    source_stage_id: str = Field(
        alias="sourceStageId",
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    target_stage_id: str = Field(
        alias="targetStageId",
        min_length=1,
        max_length=100,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    relationship: Literal["enables"] = "enables"

    @model_validator(mode="after")
    def reject_self_edge(self) -> Self:
        if self.source_stage_id == self.target_stage_id:
            raise ValueError("Attack Chain Edge cannot reference one stage twice")
        return self


def _chain002_stage_contracts() -> tuple[AttackChainStageContract, ...]:
    return (
        AttackChainStageContract(
            ordinal=1,
            stageId="file-upload",
            semantic="untrusted-document-admission",
            requiredAuthorityKind="RAGInjectionHypothesisAuthority",
            requiredExecutionState="not-authorized",
        ),
        AttackChainStageContract(
            ordinal=2,
            stageId="rag-injection",
            semantic="indirect-prompt-injection",
            requiredAuthorityKind="RAGInjectionHypothesisAuthority",
            requiredExecutionState="not-authorized",
        ),
        AttackChainStageContract(
            ordinal=3,
            stageId="tool-abuse",
            semantic="mcp-tool-authorization-failure",
            requiredAuthorityKind="MCPToolAuthorizationHypothesisAuthority",
            requiredExecutionState="registered-not-authorized",
        ),
    )


def _chain002_edge_contracts() -> tuple[AttackChainEdgeContract, ...]:
    return (
        AttackChainEdgeContract(
            ordinal=1,
            edgeId="file-upload-enables-rag-injection",
            sourceStageId="file-upload",
            targetStageId="rag-injection",
        ),
        AttackChainEdgeContract(
            ordinal=2,
            edgeId="rag-injection-enables-tool-abuse",
            sourceStageId="rag-injection",
            targetStageId="tool-abuse",
        ),
    )


class ModeNeutralWalkingAttackChainContract(StrictModel):
    """Code-owned CHAIN-002 stage topology without Campaign or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralWalkingAttackChainContract"] = "ModeNeutralWalkingAttackChainContract"
    chain_id: Literal["chain-002:file-upload-rag-injection-tool-abuse"] = Field(
        default="chain-002:file-upload-rag-injection-tool-abuse",
        alias="chainId",
    )
    chain_version: Literal["1.0.0"] = Field(default="1.0.0", alias="chainVersion")
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    stages: tuple[AttackChainStageContract, ...] = Field(
        default_factory=_chain002_stage_contracts,
        min_length=3,
        max_length=3,
    )
    edges: tuple[AttackChainEdgeContract, ...] = Field(
        default_factory=_chain002_edge_contracts,
        min_length=2,
        max_length=2,
    )
    lineage_source: Literal["walk-002-walk-003"] = Field(
        default="walk-002-walk-003",
        alias="lineageSource",
    )
    semantic_cross_check: Literal[
        "p0-d2b:ai-rag-mcp.docker.file-upload-rag-tool-authorization@1.0.0"
    ] = Field(
        default=("p0-d2b:ai-rag-mcp.docker.file-upload-rag-tool-authorization@1.0.0"),
        alias="semanticCrossCheck",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    chain_state: Literal["hypothesized-not-validated"] = Field(
        default="hypothesized-not-validated",
        alias="chainState",
    )
    fixture_evidence_admitted: Literal[False] = Field(
        default=False,
        alias="fixtureEvidenceAdmitted",
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
        "fixture_evidence_admitted",
        "capability_granted",
        "execution_authorized",
        "claim_replay_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Walking Attack Chain authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_contract_identity(self) -> Self:
        if self.stages != _chain002_stage_contracts():
            raise ValueError("CHAIN-002 Stage order or semantics differ from code authority")
        if self.edges != _chain002_edge_contracts():
            raise ValueError("CHAIN-002 Edge topology differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-walking-attack-chain-contract/v1",
            material,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Mode-neutral Walking Attack Chain Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Walking Attack Chain Contract",
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        return self


class AttackChainStageReference(StrictModel):
    """Exact sealed predecessor coordinates for one ordered chain stage."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ordinal: int = Field(ge=1, le=8)
    stage_id: str = Field(alias="stageId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    semantic: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    authority_kind: str = Field(
        alias="authorityKind",
        pattern=r"^[A-Za-z][A-Za-z0-9]+$",
    )
    authority_id: str = Field(alias="authorityId", min_length=1, max_length=200)
    authority_digest: _Sha256 = Field(alias="authorityDigest")
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: str = Field(
        alias="sourceArtifactPath",
        min_length=1,
        max_length=2_000,
    )
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    target_id: str = Field(
        alias="targetId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    surface_snapshot_id: str = Field(
        alias="surfaceSnapshotId",
        min_length=1,
        max_length=200,
    )
    surface_snapshot_digest: _Sha256 = Field(alias="surfaceSnapshotDigest")
    surface_ids: tuple[str, ...] = Field(alias="surfaceIds", min_length=1, max_length=2)
    execution_state: str = Field(
        alias="executionState",
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )

    @field_validator("surface_ids")
    @classmethod
    def require_distinct_surface_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value) or any(
            not item.startswith("attack-surface_") for item in value
        ):
            raise ValueError("Attack Chain Stage Surface identities are invalid or repeated")
        return value


class ModeNeutralWalkingAttackChainAuthority(StrictModel):
    """Exact WALK-bound CHAIN-002 hypothesis with no execution or validation authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralWalkingAttackChainAuthority"] = (
        "ModeNeutralWalkingAttackChainAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    contract: ModeNeutralWalkingAttackChainContract
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source_campaign_digest: _Sha256 = Field(alias="sourceCampaignDigest")
    source: SealedMCPAuthorizationHypothesisDependency
    stages: tuple[AttackChainStageReference, ...] = Field(min_length=3, max_length=3)
    edges: tuple[AttackChainEdgeContract, ...] = Field(min_length=2, max_length=2)
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    chain_state: Literal["hypothesized-not-validated"] = Field(
        default="hypothesized-not-validated",
        alias="chainState",
    )
    hypothesis_evidence_only: Literal[True] = Field(
        default=True,
        alias="hypothesisEvidenceOnly",
    )
    fixture_evidence_admitted: Literal[False] = Field(
        default=False,
        alias="fixtureEvidenceAdmitted",
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

    @field_validator("hypothesis_evidence_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Walking Attack Chain hypothesis marker must be boolean true")
        return value

    @field_validator(
        "fixture_evidence_admitted",
        "capability_granted",
        "execution_authorized",
        "claim_replay_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Walking Attack Chain authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority_identity(self) -> Self:
        registered = registered_file_upload_rag_tool_abuse_chain_contract()
        hypothesis = self.source.hypothesis
        if self.contract != registered:
            raise ValueError("CHAIN-002 Contract differs from code authority")
        if (
            self.campaign_id != hypothesis.campaign
            or self.campaign_digest != hypothesis.campaign_digest
            or self.source_campaign_digest != hypothesis.source_campaign_digest
        ):
            raise ValueError("CHAIN-002 belongs to another Campaign authority")
        if self.stages != _chain002_stage_references(self.source):
            raise ValueError("CHAIN-002 Stage lineage is missing, reordered, or substituted")
        if self.edges != registered.edges:
            raise ValueError("CHAIN-002 Edge topology differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-walking-attack-chain-authority/v1",
            material,
        )
        authority_id = f"mode-neutral-walking-attack-chain_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Mode-neutral Walking Attack Chain Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Mode-neutral Walking Attack Chain Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Walking Attack Chain Authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
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


def registered_file_upload_rag_tool_abuse_chain_contract() -> ModeNeutralWalkingAttackChainContract:
    """Return the exact code-owned CHAIN-002 stage and edge topology."""

    return ModeNeutralWalkingAttackChainContract()


def compile_file_upload_rag_tool_abuse_chain(
    campaign: CampaignManifest,
    outcome: MCPToolAuthorizationHypothesisOutcome,
) -> ModeNeutralWalkingAttackChainAuthority:
    """Derive CHAIN-002 from the exact sealed WALK-002/003 lineage without executing it."""

    try:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        source = load_sealed_mcp_authorization_hypothesis_dependency(
            authoritative_campaign,
            outcome,
        )
        hypothesis = source.hypothesis
        rag = hypothesis.rag_dependency.hypothesis
        if not isinstance(hypothesis, MCPToolAuthorizationHypothesisAuthority) or not isinstance(
            rag,
            RAGInjectionHypothesisAuthority,
        ):
            raise ValueError("CHAIN-002 predecessor authority kinds differ")
        expected_campaign_digest = walking_campaign_digest(authoritative_campaign)
        expected_source_campaign_digest = campaign_manifest_digest(authoritative_campaign)
        if (
            hypothesis.campaign != authoritative_campaign.metadata.name
            or hypothesis.campaign_digest != expected_campaign_digest
            or hypothesis.source_campaign_digest != expected_source_campaign_digest
            or rag.campaign != hypothesis.campaign
            or rag.campaign_digest != expected_campaign_digest
            or rag.source_campaign_digest != expected_source_campaign_digest
        ):
            raise ValueError("CHAIN-002 predecessor Campaign authority differs")
        _require_declared_chain_target(authoritative_campaign, rag.target_id)
        _require_declared_chain_target(authoritative_campaign, hypothesis.mcp_target_id)

        rag_rule = default_rag_injection_hypothesis_rule()
        if rag.rule_id != rag_rule.rule_id or rag.rule_digest != rag_rule.rule_digest:
            raise ValueError("CHAIN-002 RAG stage differs from the registered WALK-002 rule")
        mcp_rule = mcp_tool_authorization_rule(
            server_id=hypothesis.tool_locator.server_id,
            tool_name=hypothesis.tool_locator.tool_name,
            capability=hypothesis.capability.reference(),
        )
        if hypothesis.rule_id != mcp_rule.rule_id or hypothesis.rule_digest != mcp_rule.rule_digest:
            raise ValueError("CHAIN-002 Tool stage differs from the registered WALK-003 rule")
        if (
            rag.execution_state != "not-authorized"
            or hypothesis.execution_state != "registered-not-authorized"
        ):
            raise ValueError("CHAIN-002 predecessor execution state is not closed")

        contract = registered_file_upload_rag_tool_abuse_chain_contract()
        return ModeNeutralWalkingAttackChainAuthority(
            contract=contract,
            campaignId=authoritative_campaign.metadata.name,
            campaignDigest=expected_campaign_digest,
            sourceCampaignDigest=expected_source_campaign_digest,
            source=source,
            stages=_chain002_stage_references(source),
            edges=contract.edges,
        )
    except ModeNeutralAttackChainError:
        raise
    except (
        AttributeError,
        TypeError,
        ValidationError,
        ValueError,
        WalkingObservationReplanError,
    ) as exc:
        raise ModeNeutralAttackChainError(
            "CHAIN-002 could not be compiled from sealed WALK authority"
        ) from exc


def verify_file_upload_rag_tool_abuse_chain(
    authority: ModeNeutralWalkingAttackChainAuthority,
    campaign: CampaignManifest,
    outcome: MCPToolAuthorizationHypothesisOutcome,
) -> ModeNeutralWalkingAttackChainAuthority:
    """Rebuild and exact-match CHAIN-002 against its sealed WALK predecessor authority."""

    try:
        canonical = ModeNeutralWalkingAttackChainAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        expected = compile_file_upload_rag_tool_abuse_chain(campaign, outcome)
        if canonical != expected:
            raise ValueError("CHAIN-002 differs from sealed WALK authority")
        return canonical
    except ModeNeutralAttackChainError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralAttackChainError(
            "CHAIN-002 could not be verified against sealed WALK authority"
        ) from exc


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


def _chain002_stage_references(
    source: SealedMCPAuthorizationHypothesisDependency,
) -> tuple[AttackChainStageReference, ...]:
    hypothesis = source.hypothesis
    rag_dependency = hypothesis.rag_dependency
    rag = rag_dependency.hypothesis
    rag_snapshot = rag.surface_snapshot
    mcp_snapshot = hypothesis.mcp_surface_snapshot
    return (
        AttackChainStageReference(
            ordinal=1,
            stageId="file-upload",
            semantic="untrusted-document-admission",
            authorityKind=rag.kind,
            authorityId=rag.hypothesis_id,
            authorityDigest=rag.hypothesis_digest,
            sourceRunId=rag_dependency.run_id,
            sourceRootDigest=rag_dependency.root_digest,
            sourceArtifactPath=rag_dependency.artifact_path,
            sourceArtifactSha256=rag_dependency.artifact_sha256,
            targetId=rag.target_id,
            surfaceSnapshotId=rag_snapshot.snapshot_id,
            surfaceSnapshotDigest=rag_snapshot.snapshot_digest,
            surfaceIds=(rag.upload_surface_id,),
            executionState=rag.execution_state,
        ),
        AttackChainStageReference(
            ordinal=2,
            stageId="rag-injection",
            semantic="indirect-prompt-injection",
            authorityKind=rag.kind,
            authorityId=rag.hypothesis_id,
            authorityDigest=rag.hypothesis_digest,
            sourceRunId=rag_dependency.run_id,
            sourceRootDigest=rag_dependency.root_digest,
            sourceArtifactPath=rag_dependency.artifact_path,
            sourceArtifactSha256=rag_dependency.artifact_sha256,
            targetId=rag.target_id,
            surfaceSnapshotId=rag_snapshot.snapshot_id,
            surfaceSnapshotDigest=rag_snapshot.snapshot_digest,
            surfaceIds=(rag.rag_surface_id,),
            executionState=rag.execution_state,
        ),
        AttackChainStageReference(
            ordinal=3,
            stageId="tool-abuse",
            semantic="mcp-tool-authorization-failure",
            authorityKind=hypothesis.kind,
            authorityId=hypothesis.hypothesis_id,
            authorityDigest=hypothesis.hypothesis_digest,
            sourceRunId=source.run_id,
            sourceRootDigest=source.root_digest,
            sourceArtifactPath=source.artifact_path,
            sourceArtifactSha256=source.artifact_sha256,
            targetId=hypothesis.mcp_target_id,
            surfaceSnapshotId=mcp_snapshot.snapshot_id,
            surfaceSnapshotDigest=mcp_snapshot.snapshot_digest,
            surfaceIds=(hypothesis.server_surface_id, hypothesis.tool_surface_id),
            executionState=hypothesis.execution_state,
        ),
    )


def _require_declared_chain_target(campaign: CampaignManifest, target_id: str) -> None:
    if len([target for target in campaign.spec.targets if target.id == target_id]) != 1:
        raise ValueError("CHAIN-002 target is not declared exactly once by the Campaign")
