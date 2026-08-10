"""VAL-001 mode-neutral Claim Replay projection over sealed WALK-005B2 evidence."""

from __future__ import annotations

from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.attack_chain import (
    ModeNeutralAttackChainError,
    ModeNeutralWalkingAttackChainAuthority,
    verify_file_upload_rag_tool_abuse_chain,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.mcp_privilege_attack_chain import (
    ModeNeutralMCPPrivilegeAttackChainAuthority,
    ModeNeutralMCPPrivilegeAttackChainError,
    verify_mcp_authorization_privileged_action_chain,
)
from pajin.discovery.walking_mcp import MCPToolAuthorizationHypothesisOutcome
from pajin.discovery.walking_replay import (
    WalkingMCPClaimReplayAuthority,
    WalkingMCPClaimReplayError,
    WalkingMCPClaimReplayOutcome,
    load_walking_mcp_claim_replay_authority,
)
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.domain.validation import (
    AtomicClaim,
    AtomicClaimType,
    ClaimReplayStatus,
    candidate_claim_digest,
)
from pajin.runtime.store import RunIntegrityError, load_verified_run_artifacts

MODE_NEUTRAL_CLAIM_REPLAY_API_VERSION: Literal["pajin.dev/mode-neutral-claim-replay/v1alpha1"] = (
    "pajin.dev/mode-neutral-claim-replay/v1alpha1"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_SupportedChainId = Literal[
    "chain-002:file-upload-rag-injection-tool-abuse",
    "chain-005:mcp-authorization-failure-privileged-action",
]
_SUPPORTED_CHAIN_IDS: tuple[_SupportedChainId, ...] = (
    "chain-002:file-upload-rag-injection-tool-abuse",
    "chain-005:mcp-authorization-failure-privileged-action",
)
_ChainAuthority = Annotated[
    ModeNeutralWalkingAttackChainAuthority | ModeNeutralMCPPrivilegeAttackChainAuthority,
    Field(discriminator="kind"),
]
_MAX_CONTRACT_BYTES = 128 * 1024
_MAX_REPLAY_ARTIFACT_BYTES = 4 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 12 * 1024 * 1024


class ModeNeutralClaimReplayError(ValueError):
    """Raised when VAL-001 cannot bind a chain to sealed WALK-005B2 evidence."""


class ModeNeutralClaimReplayContract(StrictModel):
    """Code-owned VAL-001 boundary without new execution or confirmation authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-claim-replay/v1alpha1"] = Field(
        default=MODE_NEUTRAL_CLAIM_REPLAY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralClaimReplayContract"] = "ModeNeutralClaimReplayContract"
    contract_id: Literal["val-001:mode-neutral-claim-replay"] = Field(
        default="val-001:mode-neutral-claim-replay",
        alias="contractId",
    )
    contract_version: Literal["1.0.0"] = Field(default="1.0.0", alias="contractVersion")
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    supported_chain_ids: tuple[_SupportedChainId, ...] = Field(
        default=_SUPPORTED_CHAIN_IDS,
        alias="supportedChainIds",
        min_length=2,
        max_length=2,
    )
    claim_type: Literal[AtomicClaimType.VALIDITY] = Field(
        default=AtomicClaimType.VALIDITY,
        alias="claimType",
    )
    replay_authority_kind: Literal["WalkingMCPClaimReplayAuthority"] = Field(
        default="WalkingMCPClaimReplayAuthority",
        alias="replayAuthorityKind",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    validation_state: Literal["validity-reproduced-not-confirmed"] = Field(
        default="validity-reproduced-not-confirmed",
        alias="validationState",
    )
    requires_verified_claim_replay: Literal[True] = Field(
        default=True,
        alias="requiresVerifiedClaimReplay",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )
    additional_replay_authorized: Literal[False] = Field(
        default=False,
        alias="additionalReplayAuthorized",
    )
    confirmation_eligible: Literal[False] = Field(
        default=False,
        alias="confirmationEligible",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator("requires_verified_claim_replay", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mode-neutral Claim Replay requirement marker must be boolean true")
        return value

    @field_validator(
        "additional_execution_authorized",
        "additional_replay_authorized",
        "confirmation_eligible",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Mode-neutral Claim Replay Contract markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_contract_identity(self) -> Self:
        if self.supported_chain_ids != _SUPPORTED_CHAIN_IDS:
            raise ValueError(
                "VAL-001 supported Chain order or identity differs from code authority"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"contract_digest"},
        )
        digest = discovery_digest(
            "pajin.validation.mode-neutral-claim-replay-contract/v1",
            material,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Mode-neutral Claim Replay Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Claim Replay Contract",
            max_bytes=_MAX_CONTRACT_BYTES,
        )
        return self


class SealedWalkingMCPClaimReplayDependency(StrictModel):
    """Exact sealed WALK-005B2 publication retained by VAL-001."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    run_id: str = Field(alias="runId", min_length=1, max_length=200)
    root_digest: _Sha256 = Field(alias="rootDigest")
    artifact_path: Literal["walking-mcp-claim-replay-authority.json"] = Field(
        default="walking-mcp-claim-replay-authority.json",
        alias="artifactPath",
    )
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")
    authority: WalkingMCPClaimReplayAuthority

    @model_validator(mode="after")
    def require_distinct_publication_and_execution_runs(self) -> Self:
        if self.run_id == self.authority.execution.run_id:
            raise ValueError("WALK-005B2 publication Run must differ from replay execution Run")
        return self


class ModeNeutralClaimReplayAuthority(StrictModel):
    """Verified Claim Replay evidence bound to one exact mode-neutral chain."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-claim-replay/v1alpha1"] = Field(
        default=MODE_NEUTRAL_CLAIM_REPLAY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralClaimReplayAuthority"] = "ModeNeutralClaimReplayAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    contract: ModeNeutralClaimReplayContract
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    source_campaign_digest: _Sha256 = Field(alias="sourceCampaignDigest")
    chain_id: _SupportedChainId = Field(alias="chainId")
    chain: _ChainAuthority
    replay: SealedWalkingMCPClaimReplayDependency
    claim: AtomicClaim
    replay_binding_digest: _Sha256 = Field(alias="replayBindingDigest")
    validation_state: Literal["validity-reproduced-not-confirmed"] = Field(
        default="validity-reproduced-not-confirmed",
        alias="validationState",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    claim_replay_verified: Literal[True] = Field(
        default=True,
        alias="claimReplayVerified",
    )
    freshness_verified: Literal[True] = Field(default=True, alias="freshnessVerified")
    independent_execution_attested: Literal[True] = Field(
        default=True,
        alias="independentExecutionAttested",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )
    additional_replay_authorized: Literal[False] = Field(
        default=False,
        alias="additionalReplayAuthorized",
    )
    confirmation_eligible: Literal[False] = Field(
        default=False,
        alias="confirmationEligible",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator(
        "claim_replay_verified",
        "freshness_verified",
        "independent_execution_attested",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Mode-neutral Claim Replay evidence markers must be boolean true")
        return value

    @field_validator(
        "additional_execution_authorized",
        "additional_replay_authorized",
        "confirmation_eligible",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Mode-neutral Claim Replay authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority_identity(self) -> Self:
        registered = registered_mode_neutral_claim_replay_contract()
        chain_id = _chain_id(self.chain)
        replay = self.replay.authority
        if self.contract != registered:
            raise ValueError("VAL-001 Contract differs from code authority")
        if self.chain_id != chain_id:
            raise ValueError("VAL-001 Chain identity differs from the embedded authority")
        if (
            self.campaign_id != self.chain.campaign_id
            or self.campaign_digest != self.chain.campaign_digest
            or self.source_campaign_digest != self.chain.source_campaign_digest
            or replay.campaign_digest != self.campaign_digest
        ):
            raise ValueError("VAL-001 belongs to another Campaign authority")
        _validate_claim_replay_lineage(self.chain, replay, self.claim)
        expected_binding_digest = _claim_replay_binding_digest(
            self.chain,
            self.replay,
            self.claim,
        )
        if self.replay_binding_digest != expected_binding_digest:
            raise ValueError("VAL-001 Claim Replay binding Digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest(
            "pajin.validation.mode-neutral-claim-replay-authority/v1",
            material,
        )
        authority_id = f"mode-neutral-claim-replay_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Mode-neutral Claim Replay Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Mode-neutral Claim Replay Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Claim Replay Authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


def registered_mode_neutral_claim_replay_contract() -> ModeNeutralClaimReplayContract:
    """Return the exact code-owned VAL-001 contract."""

    return ModeNeutralClaimReplayContract()


def compile_mode_neutral_claim_replay(
    campaign: CampaignManifest,
    chain: ModeNeutralWalkingAttackChainAuthority | ModeNeutralMCPPrivilegeAttackChainAuthority,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    replay_outcome: WalkingMCPClaimReplayOutcome,
) -> ModeNeutralClaimReplayAuthority:
    """Bind one exact chain to an already executed and sealed WALK-005B2 validity Replay."""

    try:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        verified_chain = _verify_chain(chain, authoritative_campaign, chain_source)
        replay = _load_sealed_replay_dependency(authoritative_campaign, replay_outcome)
        claim = replay.authority.plan.claim
        _validate_claim_replay_lineage(verified_chain, replay.authority, claim)
        contract = registered_mode_neutral_claim_replay_contract()
        return ModeNeutralClaimReplayAuthority(
            contract=contract,
            campaignId=verified_chain.campaign_id,
            campaignDigest=verified_chain.campaign_digest,
            sourceCampaignDigest=verified_chain.source_campaign_digest,
            chainId=_chain_id(verified_chain),
            chain=verified_chain,
            replay=replay,
            claim=claim,
            replayBindingDigest=_claim_replay_binding_digest(
                verified_chain,
                replay,
                claim,
            ),
        )
    except ModeNeutralClaimReplayError:
        raise
    except (
        AttributeError,
        ModeNeutralAttackChainError,
        ModeNeutralMCPPrivilegeAttackChainError,
        OSError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
        WalkingMCPClaimReplayError,
    ) as exc:
        raise ModeNeutralClaimReplayError(
            "VAL-001 could not be compiled from verified Chain and sealed WALK-005B2 authority"
        ) from exc


def verify_mode_neutral_claim_replay(
    authority: ModeNeutralClaimReplayAuthority,
    campaign: CampaignManifest,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    replay_outcome: WalkingMCPClaimReplayOutcome,
) -> ModeNeutralClaimReplayAuthority:
    """Rebuild and exact-match VAL-001 against its Chain and sealed replay predecessors."""

    try:
        canonical = ModeNeutralClaimReplayAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        expected = compile_mode_neutral_claim_replay(
            campaign,
            canonical.chain,
            chain_source,
            replay_outcome,
        )
        if canonical != expected:
            raise ValueError("VAL-001 differs from verified Chain or sealed Replay authority")
        return canonical
    except ModeNeutralClaimReplayError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralClaimReplayError(
            "VAL-001 could not be verified against its Chain and Replay predecessors"
        ) from exc


def _verify_chain(
    chain: ModeNeutralWalkingAttackChainAuthority | ModeNeutralMCPPrivilegeAttackChainAuthority,
    campaign: CampaignManifest,
    source: MCPToolAuthorizationHypothesisOutcome,
) -> ModeNeutralWalkingAttackChainAuthority | ModeNeutralMCPPrivilegeAttackChainAuthority:
    if isinstance(chain, ModeNeutralWalkingAttackChainAuthority):
        return verify_file_upload_rag_tool_abuse_chain(chain, campaign, source)
    if isinstance(chain, ModeNeutralMCPPrivilegeAttackChainAuthority):
        return verify_mcp_authorization_privileged_action_chain(chain, campaign, source)
    raise TypeError("VAL-001 does not support this Chain authority kind")


def _chain_id(
    chain: ModeNeutralWalkingAttackChainAuthority | ModeNeutralMCPPrivilegeAttackChainAuthority,
) -> _SupportedChainId:
    chain_id = chain.contract.chain_id
    if chain_id not in _SUPPORTED_CHAIN_IDS:
        raise ValueError("VAL-001 Chain ID is not registered")
    return chain_id


def _load_sealed_replay_dependency(
    campaign: CampaignManifest,
    outcome: WalkingMCPClaimReplayOutcome,
) -> SealedWalkingMCPClaimReplayDependency:
    authority = load_walking_mcp_claim_replay_authority(campaign, outcome)
    if outcome.artifact_path != "walking-mcp-claim-replay-authority.json":
        raise ValueError("VAL-001 WALK-005B2 artifact path differs")
    snapshot = load_verified_run_artifacts(
        outcome.run_path,
        requests={outcome.artifact_path: _MAX_REPLAY_ARTIFACT_BYTES},
        expected_run_id=outcome.run_id,
    )
    artifact = snapshot.artifact_bytes(outcome.artifact_path)
    return SealedWalkingMCPClaimReplayDependency(
        runId=snapshot.verification.run_id,
        rootDigest=snapshot.verification.root_digest,
        artifactPath="walking-mcp-claim-replay-authority.json",
        artifactSha256=sha256(artifact).hexdigest(),
        authority=authority,
    )


def _validate_claim_replay_lineage(
    chain: ModeNeutralWalkingAttackChainAuthority | ModeNeutralMCPPrivilegeAttackChainAuthority,
    replay: WalkingMCPClaimReplayAuthority,
    claim: AtomicClaim,
) -> None:
    source = replay.plan.source
    projection = replay.projection
    if replay.plan.source.replan.source != chain.source:
        raise ValueError("VAL-001 Chain and Replay do not share one exact WALK-003 authority")
    if (
        source.campaign_digest != chain.campaign_digest
        or replay.plan.campaign_digest != chain.campaign_digest
        or claim != replay.plan.claim
        or claim.claim_type is not AtomicClaimType.VALIDITY
        or claim.candidate_id != source.candidate.candidate_id
        or claim.candidate_claim_digest != candidate_claim_digest(source.candidate)
        or projection.candidate_id != claim.candidate_id
        or projection.claim_id != claim.claim_id
        or projection.claim_digest != claim.claim_digest
        or projection.claim_type is not AtomicClaimType.VALIDITY
        or projection.status is not ClaimReplayStatus.REPRODUCED
        or projection.replay_run_id != replay.execution.run_id
        or projection.replay_request_id != replay.execution.request.request_id
        or projection.replay_execution_digest != replay.execution.execution_digest
        or projection.independent_execution_attested is not True
        or projection.confirmation_eligible is not False
        or replay.validation_state != "validity-reproduced-not-confirmed"
    ):
        raise ValueError("VAL-001 Replay does not reproduce the exact Chain-bound validity Claim")


def _claim_replay_binding_digest(
    chain: ModeNeutralWalkingAttackChainAuthority | ModeNeutralMCPPrivilegeAttackChainAuthority,
    replay: SealedWalkingMCPClaimReplayDependency,
    claim: AtomicClaim,
) -> str:
    authority = replay.authority
    execution = authority.execution
    return discovery_digest(
        "pajin.validation.mode-neutral-claim-replay-binding/v1",
        {
            "chain": {
                "chainId": _chain_id(chain),
                "authorityKind": chain.kind,
                "authorityId": chain.authority_id,
                "authorityDigest": chain.authority_digest,
            },
            "walk003Source": {
                "runId": chain.source.run_id,
                "rootDigest": chain.source.root_digest,
                "artifactPath": chain.source.artifact_path,
                "artifactSha256": chain.source.artifact_sha256,
                "hypothesisId": chain.source.hypothesis.hypothesis_id,
                "hypothesisDigest": chain.source.hypothesis.hypothesis_digest,
            },
            "claim": claim.model_dump(mode="json", by_alias=True),
            "replayPublication": {
                "runId": replay.run_id,
                "rootDigest": replay.root_digest,
                "artifactPath": replay.artifact_path,
                "artifactSha256": replay.artifact_sha256,
            },
            "replayAuthority": {
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "planId": authority.plan.plan_id,
                "planDigest": authority.plan.plan_digest,
                "approvalReceiptId": authority.approval.receipt_id,
                "approvalReceiptDigest": authority.approval.receipt_digest,
            },
            "freshExecution": {
                "runId": execution.run_id,
                "rootDigest": execution.root_digest,
                "executionDigest": execution.execution_digest,
                "requestId": execution.request.request_id,
                "grantId": execution.grant.grant_id,
                "permitId": execution.permit.permit_id,
                "dispatchId": execution.permit.dispatch_id,
                "workerExecutionId": execution.worker_result.execution_id,
            },
            "projection": authority.projection.model_dump(mode="json", by_alias=True),
            "validationState": authority.validation_state,
        },
    )
