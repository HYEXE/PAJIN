"""CHAIN-005 sealed MCP authorization to privileged-action coverage hypothesis."""

from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.attack_chain import AttackChainEdgeContract, AttackChainStageContract
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.walking import walking_campaign_digest
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
from pajin.domain.models import CampaignManifest, StrictModel, campaign_manifest_digest

MODE_NEUTRAL_MCP_PRIVILEGE_ATTACK_CHAIN_API_VERSION: Literal[
    "pajin.dev/mode-neutral-mcp-privilege-attack-chain/v1alpha1"
] = "pajin.dev/mode-neutral-mcp-privilege-attack-chain/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_AUTHORITY_BYTES = 2 * 1024 * 1024


class ModeNeutralMCPPrivilegeAttackChainError(ValueError):
    """Raised when CHAIN-005 cannot be derived from sealed WALK-003 authority."""


def _chain005_stage_contracts() -> tuple[AttackChainStageContract, ...]:
    return (
        AttackChainStageContract(
            ordinal=1,
            stageId="mcp-authorization-failure",
            semantic="independent-approval-failure-hypothesis",
            requiredAuthorityKind="MCPToolAuthorizationHypothesisAuthority",
            requiredExecutionState="registered-not-authorized",
        ),
        AttackChainStageContract(
            ordinal=2,
            stageId="privileged-action",
            semantic="registered-approval-gated-mcp-capability",
            requiredAuthorityKind="CapabilityDefinition",
            requiredExecutionState="registered-not-activated",
        ),
    )


def _chain005_edge_contracts() -> tuple[AttackChainEdgeContract, ...]:
    return (
        AttackChainEdgeContract(
            ordinal=1,
            edgeId="mcp-authorization-failure-enables-privileged-action",
            sourceStageId="mcp-authorization-failure",
            targetStageId="privileged-action",
        ),
    )


class ModeNeutralMCPPrivilegeAttackChainContract(StrictModel):
    """Code-owned CHAIN-005 topology without approval or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-mcp-privilege-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_MCP_PRIVILEGE_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralMCPPrivilegeAttackChainContract"] = (
        "ModeNeutralMCPPrivilegeAttackChainContract"
    )
    chain_id: Literal["chain-005:mcp-authorization-failure-privileged-action"] = Field(
        default="chain-005:mcp-authorization-failure-privileged-action",
        alias="chainId",
    )
    chain_version: Literal["1.0.0"] = Field(default="1.0.0", alias="chainVersion")
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    stages: tuple[AttackChainStageContract, ...] = Field(
        default_factory=_chain005_stage_contracts,
        min_length=2,
        max_length=2,
    )
    edges: tuple[AttackChainEdgeContract, ...] = Field(
        default_factory=_chain005_edge_contracts,
        min_length=1,
        max_length=1,
    )
    lineage_source: Literal["walk-003"] = Field(default="walk-003", alias="lineageSource")
    privileged_action_basis: Literal["registered-capability-requiring-independent-approval"] = (
        Field(
            default="registered-capability-requiring-independent-approval",
            alias="privilegedActionBasis",
        )
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    chain_state: Literal["hypothesized-not-validated"] = Field(
        default="hypothesized-not-validated",
        alias="chainState",
    )
    authorization_failure_confirmed: Literal[False] = Field(
        default=False,
        alias="authorizationFailureConfirmed",
    )
    approval_granted: Literal[False] = Field(default=False, alias="approvalGranted")
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    privileged_action_executed: Literal[False] = Field(
        default=False,
        alias="privilegedActionExecuted",
    )
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
        "authorization_failure_confirmed",
        "approval_granted",
        "capability_granted",
        "privileged_action_executed",
        "execution_authorized",
        "claim_replay_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("MCP Privilege Attack Chain Contract markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_contract_identity(self) -> Self:
        if self.stages != _chain005_stage_contracts():
            raise ValueError("CHAIN-005 Stage order or semantics differ from code authority")
        if self.edges != _chain005_edge_contracts():
            raise ValueError("CHAIN-005 Edge topology differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-mcp-privilege-attack-chain-contract/v1",
            material,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Mode-neutral MCP Privilege Attack Chain Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral MCP Privilege Attack Chain Contract",
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        return self


class MCPPrivilegeAttackChainStageReference(StrictModel):
    """One exact CHAIN-005 stage projected from a sealed WALK-003 hypothesis."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ordinal: int = Field(ge=1, le=2)
    stage_id: str = Field(alias="stageId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    semantic: str = Field(pattern=r"^[a-z0-9][a-z0-9-]*$")
    authority_kind: Literal[
        "MCPToolAuthorizationHypothesisAuthority",
        "CapabilityDefinition",
    ] = Field(alias="authorityKind")
    execution_state: Literal[
        "registered-not-authorized",
        "registered-not-activated",
    ] = Field(alias="executionState")
    source_run_id: str = Field(alias="sourceRunId", min_length=1, max_length=200)
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    source_artifact_path: str = Field(alias="sourceArtifactPath", min_length=1, max_length=2_000)
    source_artifact_sha256: _Sha256 = Field(alias="sourceArtifactSha256")
    source_hypothesis_id: str = Field(
        alias="sourceHypothesisId",
        pattern=r"^mcp-tool-authorization-hypothesis_[a-f0-9]{64}$",
    )
    source_hypothesis_digest: _Sha256 = Field(alias="sourceHypothesisDigest")
    subject_kind: Literal[
        "MCPToolAuthorizationHypothesisAuthority",
        "CapabilityDefinition",
    ] = Field(alias="subjectKind")
    subject_id: str = Field(alias="subjectId", min_length=1, max_length=420)
    subject_digest: _Sha256 = Field(alias="subjectDigest")


class ModeNeutralMCPPrivilegeAttackChainAuthority(StrictModel):
    """Exact WALK-003-bound CHAIN-005 hypothesis with a closed execution ceiling."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-mcp-privilege-attack-chain/v1alpha1"] = Field(
        default=MODE_NEUTRAL_MCP_PRIVILEGE_ATTACK_CHAIN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralMCPPrivilegeAttackChainAuthority"] = (
        "ModeNeutralMCPPrivilegeAttackChainAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    contract: ModeNeutralMCPPrivilegeAttackChainContract
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source_campaign_digest: _Sha256 = Field(alias="sourceCampaignDigest")
    source: SealedMCPAuthorizationHypothesisDependency
    stages: tuple[MCPPrivilegeAttackChainStageReference, ...] = Field(
        min_length=2,
        max_length=2,
    )
    edges: tuple[AttackChainEdgeContract, ...] = Field(min_length=1, max_length=1)
    privileged_action_digest: _Sha256 = Field(alias="privilegedActionDigest")
    privileged_action_state: Literal["registered-not-activated"] = Field(
        default="registered-not-activated",
        alias="privilegedActionState",
    )
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
    authorization_failure_confirmed: Literal[False] = Field(
        default=False,
        alias="authorizationFailureConfirmed",
    )
    approval_granted: Literal[False] = Field(default=False, alias="approvalGranted")
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    privileged_action_executed: Literal[False] = Field(
        default=False,
        alias="privilegedActionExecuted",
    )
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
            raise ValueError("MCP Privilege Attack Chain evidence marker must be boolean true")
        return value

    @field_validator(
        "authorization_failure_confirmed",
        "approval_granted",
        "capability_granted",
        "privileged_action_executed",
        "execution_authorized",
        "claim_replay_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("MCP Privilege Attack Chain authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority_identity(self) -> Self:
        registered = registered_mcp_authorization_privileged_action_chain_contract()
        hypothesis = self.source.hypothesis
        if self.contract != registered:
            raise ValueError("CHAIN-005 Contract differs from code authority")
        if (
            self.campaign_id != hypothesis.campaign
            or self.campaign_digest != hypothesis.campaign_digest
            or self.source_campaign_digest != hypothesis.source_campaign_digest
        ):
            raise ValueError("CHAIN-005 belongs to another Campaign authority")
        _validate_chain005_hypothesis(hypothesis)
        if self.stages != _chain005_stage_references(self.source):
            raise ValueError("CHAIN-005 Stage lineage is missing, reordered, or substituted")
        if self.edges != registered.edges:
            raise ValueError("CHAIN-005 Edge topology differs from code authority")
        expected_action_digest = _privileged_action_digest(hypothesis)
        if self.privileged_action_digest != expected_action_digest:
            raise ValueError("CHAIN-005 privileged action Digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest(
            "pajin.discovery.mode-neutral-mcp-privilege-attack-chain-authority/v1",
            material,
        )
        authority_id = f"mode-neutral-mcp-privilege-chain_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Mode-neutral MCP Privilege Attack Chain Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Mode-neutral MCP Privilege Attack Chain Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral MCP Privilege Attack Chain Authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


def registered_mcp_authorization_privileged_action_chain_contract() -> (
    ModeNeutralMCPPrivilegeAttackChainContract
):
    """Return the exact code-owned CHAIN-005 topology."""

    return ModeNeutralMCPPrivilegeAttackChainContract()


def compile_mcp_authorization_privileged_action_chain(
    campaign: CampaignManifest,
    outcome: MCPToolAuthorizationHypothesisOutcome,
) -> ModeNeutralMCPPrivilegeAttackChainAuthority:
    """Derive CHAIN-005 from exact sealed WALK-003 authority without executing it."""

    try:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        source = load_sealed_mcp_authorization_hypothesis_dependency(
            authoritative_campaign,
            outcome,
        )
        hypothesis = source.hypothesis
        if not isinstance(hypothesis, MCPToolAuthorizationHypothesisAuthority):
            raise ValueError("CHAIN-005 predecessor authority kind differs")
        expected_campaign_digest = walking_campaign_digest(authoritative_campaign)
        expected_source_campaign_digest = campaign_manifest_digest(authoritative_campaign)
        if (
            hypothesis.campaign != authoritative_campaign.metadata.name
            or hypothesis.campaign_digest != expected_campaign_digest
            or hypothesis.source_campaign_digest != expected_source_campaign_digest
        ):
            raise ValueError("CHAIN-005 predecessor Campaign authority differs")
        _require_declared_mcp_target(authoritative_campaign, hypothesis.mcp_target_id)
        _validate_chain005_hypothesis(hypothesis)
        contract = registered_mcp_authorization_privileged_action_chain_contract()
        return ModeNeutralMCPPrivilegeAttackChainAuthority(
            contract=contract,
            campaignId=authoritative_campaign.metadata.name,
            campaignDigest=expected_campaign_digest,
            sourceCampaignDigest=expected_source_campaign_digest,
            source=source,
            stages=_chain005_stage_references(source),
            edges=contract.edges,
            privilegedActionDigest=_privileged_action_digest(hypothesis),
        )
    except ModeNeutralMCPPrivilegeAttackChainError:
        raise
    except (
        AttributeError,
        TypeError,
        ValidationError,
        ValueError,
        WalkingObservationReplanError,
    ) as exc:
        raise ModeNeutralMCPPrivilegeAttackChainError(
            "CHAIN-005 could not be compiled from sealed WALK-003 authority"
        ) from exc


def verify_mcp_authorization_privileged_action_chain(
    authority: ModeNeutralMCPPrivilegeAttackChainAuthority,
    campaign: CampaignManifest,
    outcome: MCPToolAuthorizationHypothesisOutcome,
) -> ModeNeutralMCPPrivilegeAttackChainAuthority:
    """Rebuild and exact-match CHAIN-005 against its sealed WALK-003 predecessor."""

    try:
        canonical = ModeNeutralMCPPrivilegeAttackChainAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        expected = compile_mcp_authorization_privileged_action_chain(campaign, outcome)
        if canonical != expected:
            raise ValueError("CHAIN-005 differs from sealed WALK-003 authority")
        return canonical
    except ModeNeutralMCPPrivilegeAttackChainError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralMCPPrivilegeAttackChainError(
            "CHAIN-005 could not be verified against sealed WALK-003 authority"
        ) from exc


def _validate_chain005_hypothesis(
    hypothesis: MCPToolAuthorizationHypothesisAuthority,
) -> None:
    capability = hypothesis.capability
    rule = mcp_tool_authorization_rule(
        server_id=hypothesis.tool_locator.server_id,
        tool_name=hypothesis.tool_locator.tool_name,
        capability=capability.reference(),
    )
    if (
        hypothesis.rule_id != rule.rule_id
        or hypothesis.rule_digest != rule.rule_digest
        or hypothesis.threat_class != "mcp-tool-authorization-failure"
        or hypothesis.authorization_control != "independent-user-approval"
        or hypothesis.execution_state != "registered-not-authorized"
        or not capability.approval_required
        or "mcp-tool" not in capability.supported_surface_types
        or hypothesis.threat_class not in capability.threat_classes
    ):
        raise ValueError("CHAIN-005 predecessor is not an approval-gated MCP hypothesis")


def _privileged_action_digest(
    hypothesis: MCPToolAuthorizationHypothesisAuthority,
) -> str:
    return discovery_digest(
        "pajin.discovery.mode-neutral-mcp-privileged-action/v1",
        {
            "basis": "registered-capability-requiring-independent-approval",
            "mcpTargetId": hypothesis.mcp_target_id,
            "serverSurfaceId": hypothesis.server_surface_id,
            "serverLocator": hypothesis.server_locator.model_dump(mode="json"),
            "toolSurfaceId": hypothesis.tool_surface_id,
            "toolLocator": hypothesis.tool_locator.model_dump(mode="json"),
            "capability": hypothesis.capability.model_dump(mode="json", by_alias=True),
            "invocation": hypothesis.invocation.model_dump(mode="json", by_alias=True),
            "authorizationControl": hypothesis.authorization_control,
            "actionState": "registered-not-activated",
        },
    )


def _chain005_stage_references(
    source: SealedMCPAuthorizationHypothesisDependency,
) -> tuple[MCPPrivilegeAttackChainStageReference, ...]:
    hypothesis = source.hypothesis
    capability = hypothesis.capability
    stage_contracts = _chain005_stage_contracts()
    common = {
        "sourceRunId": source.run_id,
        "sourceRootDigest": source.root_digest,
        "sourceArtifactPath": source.artifact_path,
        "sourceArtifactSha256": source.artifact_sha256,
        "sourceHypothesisId": hypothesis.hypothesis_id,
        "sourceHypothesisDigest": hypothesis.hypothesis_digest,
    }
    return (
        MCPPrivilegeAttackChainStageReference(
            ordinal=stage_contracts[0].ordinal,
            stageId=stage_contracts[0].stage_id,
            semantic=stage_contracts[0].semantic,
            authorityKind="MCPToolAuthorizationHypothesisAuthority",
            executionState="registered-not-authorized",
            subjectKind="MCPToolAuthorizationHypothesisAuthority",
            subjectId=hypothesis.hypothesis_id,
            subjectDigest=hypothesis.hypothesis_digest,
            **common,
        ),
        MCPPrivilegeAttackChainStageReference(
            ordinal=stage_contracts[1].ordinal,
            stageId=stage_contracts[1].stage_id,
            semantic=stage_contracts[1].semantic,
            authorityKind="CapabilityDefinition",
            executionState="registered-not-activated",
            subjectKind="CapabilityDefinition",
            subjectId=f"{capability.capability_id}@{capability.capability_version}",
            subjectDigest=capability.capability_digest,
            **common,
        ),
    )


def _require_declared_mcp_target(campaign: CampaignManifest, target_id: str) -> None:
    if len([target for target in campaign.spec.targets if target.id == target_id]) != 1:
        raise ValueError("CHAIN-005 MCP target is not declared exactly once by the Campaign")
