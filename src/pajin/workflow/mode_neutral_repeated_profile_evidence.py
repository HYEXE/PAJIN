"""VAL-004C repeated Replay evidence for stateless VAL-001 WALK Claims."""

from __future__ import annotations

from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.claim_replay import (
    ModeNeutralClaimReplayAuthority,
    ModeNeutralClaimReplayContract,
    ModeNeutralClaimReplayError,
    compile_mode_neutral_claim_replay,
    registered_mode_neutral_claim_replay_contract,
    verify_mode_neutral_claim_replay,
)
from pajin.discovery.validation_depth import (
    ValidationDepth,
    ValidationDepthRequirement,
    resolve_validation_depth_requirement,
)
from pajin.discovery.walking_mcp import MCPToolAuthorizationHypothesisOutcome
from pajin.discovery.walking_replay import WalkingMCPClaimReplayOutcome
from pajin.discovery.walking_validation import SealedWalkingCapabilityExecution
from pajin.domain.models import CampaignManifest, StrictModel, ToolRequest
from pajin.domain.replay import ReplaySessionPolicy
from pajin.domain.validation import AtomicClaim, AtomicClaimType
from pajin.workflow.mode_neutral_profile_evidence import (
    ModeNeutralClaimControlAuthority,
    ModeNeutralClaimControlOutcome,
    ModeNeutralProfileEvidenceError,
    load_mode_neutral_claim_control_authority,
)
from pajin.workflow.profile_assurance import (
    ProfileAssuranceFloor,
    ProfileAssuranceFloorError,
    resolve_profile_assurance_floor,
)

MODE_NEUTRAL_REPEATED_CLAIM_REPLAY_API_VERSION: Literal[
    "pajin.dev/mode-neutral-repeated-claim-replay/v1alpha1"
] = "pajin.dev/mode-neutral-repeated-claim-replay/v1alpha1"
MODE_NEUTRAL_REPEATED_PROFILE_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/mode-neutral-repeated-profile-validation-evidence/v1alpha1"
] = "pajin.dev/mode-neutral-repeated-profile-validation-evidence/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_REPLAY_REPETITION_COUNT = 2
_COMPLETE_EXECUTION_COUNT = 6
_MAX_AUTHORITY_BYTES = 32 * 1024 * 1024


class ModeNeutralRepeatedProfileEvidenceError(ValueError):
    """Raised when VAL-004C cannot verify one exact repeated WALK evidence set."""


class ModeNeutralRepeatedClaimReplayContract(StrictModel):
    """Code-owned VAL-004C boundary that reuses existing VAL-001 Replay authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-repeated-claim-replay/v1alpha1"] = Field(
        default=MODE_NEUTRAL_REPEATED_CLAIM_REPLAY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralRepeatedClaimReplayContract"] = (
        "ModeNeutralRepeatedClaimReplayContract"
    )
    contract_id: Literal["val-004c:mode-neutral-repeated-claim-replay"] = Field(
        default="val-004c:mode-neutral-repeated-claim-replay",
        alias="contractId",
    )
    contract_version: Literal["1.0.0"] = Field(default="1.0.0", alias="contractVersion")
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    claim_replay_contract: ModeNeutralClaimReplayContract = Field(alias="claimReplayContract")
    claim_type: Literal[AtomicClaimType.VALIDITY] = Field(
        default=AtomicClaimType.VALIDITY,
        alias="claimType",
    )
    replay_repetition_count: Literal[2] = Field(
        default=2,
        alias="replayRepetitionCount",
    )
    session_policy: Literal[ReplaySessionPolicy.STATELESS] = Field(
        default=ReplaySessionPolicy.STATELESS,
        alias="sessionPolicy",
    )
    control_anchor_replay_index: Literal[0] = Field(
        default=0,
        alias="controlAnchorReplayIndex",
    )
    independence_scope: Literal["source-repeated-replay-execution-lineage"] = Field(
        default="source-repeated-replay-execution-lineage",
        alias="independenceScope",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )
    additional_replay_authorized: Literal[False] = Field(
        default=False,
        alias="additionalReplayAuthorized",
    )
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator(
        "additional_execution_authorized",
        "additional_replay_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Repeated Claim Replay Contract markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_contract(self) -> Self:
        if self.claim_replay_contract != registered_mode_neutral_claim_replay_contract():
            raise ValueError("VAL-004C VAL-001 Contract differs from code authority")
        material = self.model_dump(mode="json", by_alias=True, exclude={"contract_digest"})
        digest = discovery_digest(
            "pajin.validation.mode-neutral-repeated-claim-replay-contract/v1",
            material,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Repeated Claim Replay Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Repeated Claim Replay Contract",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


class StatelessRepeatedReplayIndependenceEvidence(StrictModel):
    """Pairwise-disjoint source and two-Replay execution coordinates."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    session_policy: Literal[ReplaySessionPolicy.STATELESS] = Field(
        default=ReplaySessionPolicy.STATELESS,
        alias="sessionPolicy",
    )
    session_argument_absent: Literal[True] = Field(
        default=True,
        alias="sessionArgumentAbsent",
    )
    execution_run_ids: tuple[str, ...] = Field(alias="executionRunIds", min_length=3, max_length=3)
    root_digests: tuple[_Sha256, ...] = Field(alias="rootDigests", min_length=3, max_length=3)
    execution_digests: tuple[_Sha256, ...] = Field(
        alias="executionDigests",
        min_length=3,
        max_length=3,
    )
    request_ids: tuple[str, ...] = Field(alias="requestIds", min_length=3, max_length=3)
    grant_ids: tuple[str, ...] = Field(alias="grantIds", min_length=3, max_length=3)
    permit_ids: tuple[str, ...] = Field(alias="permitIds", min_length=3, max_length=3)
    dispatch_ids: tuple[str, ...] = Field(alias="dispatchIds", min_length=3, max_length=3)
    approval_ids: tuple[str, ...] = Field(alias="approvalIds", min_length=3, max_length=3)
    worker_execution_ids: tuple[str, ...] = Field(
        alias="workerExecutionIds",
        min_length=3,
        max_length=3,
    )
    evidence_references: tuple[str, ...] = Field(
        alias="evidenceReferences",
        min_length=3,
        max_length=3,
    )
    replay_publication_run_ids: tuple[str, ...] = Field(
        alias="replayPublicationRunIds",
        min_length=2,
        max_length=2,
    )
    replay_publication_root_digests: tuple[_Sha256, ...] = Field(
        alias="replayPublicationRootDigests",
        min_length=2,
        max_length=2,
    )
    replay_publication_references: tuple[str, ...] = Field(
        alias="replayPublicationReferences",
        min_length=2,
        max_length=2,
    )
    replay_authority_digests: tuple[_Sha256, ...] = Field(
        alias="replayAuthorityDigests",
        min_length=2,
        max_length=2,
    )
    independent_execution_lineage_verified: Literal[True] = Field(
        default=True,
        alias="independentExecutionLineageVerified",
    )

    @field_validator(
        "session_argument_absent",
        "independent_execution_lineage_verified",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Repeated Replay independence markers must be boolean true")
        return value

    @model_validator(mode="after")
    def require_unique_lineages(self) -> Self:
        _require_unique_lineages(
            (
                self.execution_run_ids,
                self.root_digests,
                self.execution_digests,
                self.request_ids,
                self.grant_ids,
                self.permit_ids,
                self.dispatch_ids,
                self.approval_ids,
                self.worker_execution_ids,
                self.evidence_references,
            ),
            expected=3,
            message="Source and repeated Replay execution lineage must be disjoint",
        )
        _require_unique_lineages(
            (
                self.replay_publication_run_ids,
                self.replay_publication_root_digests,
                self.replay_publication_references,
                self.replay_authority_digests,
            ),
            expected=2,
            message="Repeated Replay publications must be disjoint",
        )
        return self


class ModeNeutralRepeatedClaimReplayAuthority(StrictModel):
    """Two verified VAL-001 Replays bound to one exact Claim and Chain."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-repeated-claim-replay/v1alpha1"] = Field(
        default=MODE_NEUTRAL_REPEATED_CLAIM_REPLAY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralRepeatedClaimReplayAuthority"] = (
        "ModeNeutralRepeatedClaimReplayAuthority"
    )
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    contract: ModeNeutralRepeatedClaimReplayContract
    campaign_id: str = Field(alias="campaignId", min_length=3, max_length=80)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    claim: AtomicClaim
    claim_replays: tuple[ModeNeutralClaimReplayAuthority, ...] = Field(
        alias="claimReplays",
        min_length=2,
        max_length=2,
    )
    independence: StatelessRepeatedReplayIndependenceEvidence
    replay_repetition_count: Literal[2] = Field(
        default=2,
        alias="replayRepetitionCount",
    )
    validation_state: Literal["repeated-validity-reproduced-not-confirmed"] = Field(
        default="repeated-validity-reproduced-not-confirmed",
        alias="validationState",
    )
    evidence_verified: Literal[True] = Field(default=True, alias="evidenceVerified")
    profile_selection_attested: Literal[False] = Field(
        default=False,
        alias="profileSelectionAttested",
    )
    campaign_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="campaignMutationAuthorized",
    )
    additional_execution_authorized: Literal[False] = Field(
        default=False,
        alias="additionalExecutionAuthorized",
    )
    additional_replay_authorized: Literal[False] = Field(
        default=False,
        alias="additionalReplayAuthorized",
    )
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator("evidence_verified", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Repeated Claim Replay evidence marker must be boolean true")
        return value

    @field_validator(
        "profile_selection_attested",
        "campaign_mutation_authorized",
        "additional_execution_authorized",
        "additional_replay_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Repeated Claim Replay authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        if self.contract != registered_mode_neutral_repeated_claim_replay_contract():
            raise ValueError("VAL-004C Contract differs from code authority")
        primary, additional = self.claim_replays
        if (
            self.campaign_id != primary.campaign_id
            or self.campaign_digest != primary.campaign_digest
            or additional.campaign_id != primary.campaign_id
            or additional.campaign_digest != primary.campaign_digest
            or additional.chain != primary.chain
            or additional.claim != primary.claim
            or self.claim != primary.claim
        ):
            raise ValueError("Repeated Claim Replays do not share one exact Claim and Chain")
        expected_independence = _repeated_replay_independence(self.claim_replays)
        if self.independence != expected_independence:
            raise ValueError("Repeated Claim Replay independence evidence differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest(
            "pajin.validation.mode-neutral-repeated-claim-replay-authority/v1",
            material,
        )
        authority_id = f"mode-neutral-repeated-claim-replay_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Repeated Claim Replay Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Repeated Claim Replay Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Repeated Claim Replay Authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


class StatelessRepeatedControlIndependenceEvidence(StrictModel):
    """Pairwise-disjoint source, two Replays, and three Control executions."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    session_policy: Literal[ReplaySessionPolicy.STATELESS] = Field(
        default=ReplaySessionPolicy.STATELESS,
        alias="sessionPolicy",
    )
    session_argument_absent: Literal[True] = Field(
        default=True,
        alias="sessionArgumentAbsent",
    )
    execution_run_ids: tuple[str, ...] = Field(alias="executionRunIds", min_length=6, max_length=6)
    root_digests: tuple[_Sha256, ...] = Field(alias="rootDigests", min_length=6, max_length=6)
    execution_digests: tuple[_Sha256, ...] = Field(
        alias="executionDigests",
        min_length=6,
        max_length=6,
    )
    request_ids: tuple[str, ...] = Field(alias="requestIds", min_length=6, max_length=6)
    grant_ids: tuple[str, ...] = Field(alias="grantIds", min_length=6, max_length=6)
    permit_ids: tuple[str, ...] = Field(alias="permitIds", min_length=6, max_length=6)
    dispatch_ids: tuple[str, ...] = Field(alias="dispatchIds", min_length=6, max_length=6)
    approval_ids: tuple[str, ...] = Field(alias="approvalIds", min_length=6, max_length=6)
    worker_execution_ids: tuple[str, ...] = Field(
        alias="workerExecutionIds",
        min_length=6,
        max_length=6,
    )
    evidence_references: tuple[str, ...] = Field(
        alias="evidenceReferences",
        min_length=6,
        max_length=6,
    )
    independent_execution_lineage_verified: Literal[True] = Field(
        default=True,
        alias="independentExecutionLineageVerified",
    )

    @field_validator(
        "session_argument_absent",
        "independent_execution_lineage_verified",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Repeated Control independence markers must be boolean true")
        return value

    @model_validator(mode="after")
    def require_unique_lineages(self) -> Self:
        _require_unique_lineages(
            (
                self.execution_run_ids,
                self.root_digests,
                self.execution_digests,
                self.request_ids,
                self.grant_ids,
                self.permit_ids,
                self.dispatch_ids,
                self.approval_ids,
                self.worker_execution_ids,
                self.evidence_references,
            ),
            expected=_COMPLETE_EXECUTION_COUNT,
            message="Source, repeated Replay, and Control execution lineage must be disjoint",
        )
        return self


class ModeNeutralRepeatedProfileValidationEvidenceAssessment(StrictModel):
    """Repeated-controlled Profile-floor satisfaction from sealed WALK evidence."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-repeated-profile-validation-evidence/v1alpha1"] = (
        Field(
            default=MODE_NEUTRAL_REPEATED_PROFILE_EVIDENCE_API_VERSION,
            alias="apiVersion",
        )
    )
    kind: Literal["ModeNeutralRepeatedProfileValidationEvidenceAssessment"] = (
        "ModeNeutralRepeatedProfileValidationEvidenceAssessment"
    )
    assessment_id: str = Field(default="", alias="assessmentId", max_length=320)
    assessment_digest: str = Field(default="", alias="assessmentDigest", max_length=64)
    profile_floor: ProfileAssuranceFloor = Field(alias="profileFloor")
    claim: AtomicClaim
    repeated_claim_replay: ModeNeutralRepeatedClaimReplayAuthority = Field(
        alias="repeatedClaimReplay"
    )
    control_evidence: ModeNeutralClaimControlAuthority = Field(alias="controlEvidence")
    independence: StatelessRepeatedControlIndependenceEvidence
    achieved_depth: Literal[ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY] = Field(
        default=ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY,
        alias="achievedDepth",
    )
    achieved_requirement: ValidationDepthRequirement = Field(alias="achievedRequirement")
    replay_repetition_count: Literal[2] = Field(
        default=2,
        alias="replayRepetitionCount",
    )
    validation_state: Literal["profile-floor-satisfied-not-confirmed"] = Field(
        default="profile-floor-satisfied-not-confirmed",
        alias="validationState",
    )
    evidence_source_constraint: Literal["val-004c-repeated-walking-mcp-v1"] = Field(
        default="val-004c-repeated-walking-mcp-v1",
        alias="evidenceSourceConstraint",
    )
    evidence_evaluation_performed: Literal[True] = Field(
        default=True,
        alias="evidenceEvaluationPerformed",
    )
    floor_satisfied: Literal[True] = Field(default=True, alias="floorSatisfied")
    profile_selection_attested: Literal[False] = Field(
        default=False,
        alias="profileSelectionAttested",
    )
    campaign_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="campaignMutationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator("evidence_evaluation_performed", "floor_satisfied", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Repeated Profile evidence markers must be boolean true")
        return value

    @field_validator(
        "profile_selection_attested",
        "campaign_mutation_authorized",
        "execution_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Repeated Profile authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_assessment(self) -> Self:
        floor = resolve_profile_assurance_floor(
            self.profile_floor.profile_id,
            self.profile_floor.profile_version,
        )
        requirement = resolve_validation_depth_requirement(
            ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY
        )
        control_kinds = tuple(
            item.definition.control_kind for item in self.control_evidence.executions
        )
        expected_independence = _repeated_control_independence(
            self.repeated_claim_replay,
            self.control_evidence,
        )
        if (
            self.profile_floor != floor
            or self.claim != self.repeated_claim_replay.claim
            or self.achieved_requirement != requirement
            or requirement.depth_ordinal < floor.minimum_depth_ordinal
            or requirement.minimum_replay_repetitions != self.replay_repetition_count
            or requirement.required_control_kinds != control_kinds
            or requirement.minimum_control_executions_per_kind != 1
            or requirement.required_control_contrast is not self.control_evidence.contrast
            or ReplaySessionPolicy.STATELESS not in requirement.allowed_replay_session_policies
            or self.control_evidence.plan.claim_replay
            != self.repeated_claim_replay.claim_replays[0]
            or self.independence != expected_independence
        ):
            raise ValueError("Repeated WALK evidence does not satisfy the registered Floor")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"assessment_id", "assessment_digest"},
        )
        digest = discovery_digest(
            "pajin.validation.mode-neutral-repeated-profile-evidence/v1",
            material,
        )
        assessment_id = f"mode-neutral-repeated-profile-evidence:{floor.profile_id}:{digest}"
        if self.assessment_digest and self.assessment_digest != digest:
            raise ValueError("Repeated Profile Evidence Digest differs")
        if self.assessment_id and self.assessment_id != assessment_id:
            raise ValueError("Repeated Profile Evidence ID differs")
        object.__setattr__(self, "assessment_digest", digest)
        object.__setattr__(self, "assessment_id", assessment_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Repeated Profile Evidence",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


def registered_mode_neutral_repeated_claim_replay_contract() -> (
    ModeNeutralRepeatedClaimReplayContract
):
    """Return the exact code-owned VAL-004C contract."""

    return ModeNeutralRepeatedClaimReplayContract(
        claimReplayContract=registered_mode_neutral_claim_replay_contract()
    )


def compile_mode_neutral_repeated_claim_replay(
    campaign: CampaignManifest,
    primary_claim_replay: ModeNeutralClaimReplayAuthority,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    primary_replay_outcome: WalkingMCPClaimReplayOutcome,
    additional_replay_outcome: WalkingMCPClaimReplayOutcome,
) -> ModeNeutralRepeatedClaimReplayAuthority:
    """Bind one additional sealed WALK-005B2 Replay to the exact VAL-001 authority."""

    try:
        primary = verify_mode_neutral_claim_replay(
            primary_claim_replay,
            campaign,
            chain_source,
            primary_replay_outcome,
        )
        additional = compile_mode_neutral_claim_replay(
            campaign,
            primary.chain,
            chain_source,
            additional_replay_outcome,
        )
        claim_replays = (primary, additional)
        return ModeNeutralRepeatedClaimReplayAuthority(
            contract=registered_mode_neutral_repeated_claim_replay_contract(),
            campaignId=primary.campaign_id,
            campaignDigest=primary.campaign_digest,
            claim=primary.claim,
            claimReplays=claim_replays,
            independence=_repeated_replay_independence(claim_replays),
        )
    except ModeNeutralRepeatedProfileEvidenceError:
        raise
    except (
        AttributeError,
        ModeNeutralClaimReplayError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise ModeNeutralRepeatedProfileEvidenceError(
            "VAL-004C could not bind two independent sealed WALK Replays"
        ) from exc


def verify_mode_neutral_repeated_claim_replay(
    authority: ModeNeutralRepeatedClaimReplayAuthority,
    campaign: CampaignManifest,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    primary_replay_outcome: WalkingMCPClaimReplayOutcome,
    additional_replay_outcome: WalkingMCPClaimReplayOutcome,
) -> ModeNeutralRepeatedClaimReplayAuthority:
    """Rebuild and exact-match VAL-004C against both sealed Replay predecessors."""

    try:
        canonical = ModeNeutralRepeatedClaimReplayAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        expected = compile_mode_neutral_repeated_claim_replay(
            campaign,
            canonical.claim_replays[0],
            chain_source,
            primary_replay_outcome,
            additional_replay_outcome,
        )
        if canonical != expected:
            raise ValueError("VAL-004C differs from sealed Replay predecessors")
        return canonical
    except ModeNeutralRepeatedProfileEvidenceError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralRepeatedProfileEvidenceError(
            "VAL-004C repeated Replay authority could not be verified"
        ) from exc


def evaluate_mode_neutral_repeated_profile_validation_evidence(
    profile_id: str,
    profile_version: str,
    campaign: CampaignManifest,
    repeated_claim_replay: ModeNeutralRepeatedClaimReplayAuthority,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    primary_replay_outcome: WalkingMCPClaimReplayOutcome,
    additional_replay_outcome: WalkingMCPClaimReplayOutcome,
    control_outcome: ModeNeutralClaimControlOutcome,
) -> ModeNeutralRepeatedProfileValidationEvidenceAssessment:
    """Evaluate two exact Replays and three Controls against one registered Profile floor."""

    try:
        repeated = verify_mode_neutral_repeated_claim_replay(
            repeated_claim_replay,
            campaign,
            chain_source,
            primary_replay_outcome,
            additional_replay_outcome,
        )
        controls = load_mode_neutral_claim_control_authority(
            campaign,
            chain_source,
            primary_replay_outcome,
            control_outcome,
        )
        floor = resolve_profile_assurance_floor(profile_id, profile_version)
        requirement = resolve_validation_depth_requirement(
            ValidationDepth.REPEATED_CONTROLLED_VALIDITY_REPLAY
        )
        return ModeNeutralRepeatedProfileValidationEvidenceAssessment(
            profileFloor=floor,
            claim=repeated.claim,
            repeatedClaimReplay=repeated,
            controlEvidence=controls,
            independence=_repeated_control_independence(repeated, controls),
            achievedRequirement=requirement,
        )
    except ModeNeutralRepeatedProfileEvidenceError:
        raise
    except (
        AttributeError,
        ModeNeutralProfileEvidenceError,
        ProfileAssuranceFloorError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise ModeNeutralRepeatedProfileEvidenceError(
            "VAL-004C could not verify repeated WALK evidence against the registered Floor"
        ) from exc


def verify_mode_neutral_repeated_profile_validation_evidence(
    assessment: ModeNeutralRepeatedProfileValidationEvidenceAssessment,
    campaign: CampaignManifest,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    primary_replay_outcome: WalkingMCPClaimReplayOutcome,
    additional_replay_outcome: WalkingMCPClaimReplayOutcome,
    control_outcome: ModeNeutralClaimControlOutcome,
) -> ModeNeutralRepeatedProfileValidationEvidenceAssessment:
    """Rebuild and exact-match one VAL-004C Profile-floor assessment."""

    try:
        canonical = ModeNeutralRepeatedProfileValidationEvidenceAssessment.model_validate(
            assessment.model_dump(mode="json", by_alias=True)
        )
        expected = evaluate_mode_neutral_repeated_profile_validation_evidence(
            canonical.profile_floor.profile_id,
            canonical.profile_floor.profile_version,
            campaign,
            canonical.repeated_claim_replay,
            chain_source,
            primary_replay_outcome,
            additional_replay_outcome,
            control_outcome,
        )
        if canonical != expected:
            raise ValueError("Repeated Profile assessment differs from sealed predecessors")
        return canonical
    except ModeNeutralRepeatedProfileEvidenceError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralRepeatedProfileEvidenceError(
            "VAL-004C Profile assessment could not be verified against sealed predecessors"
        ) from exc


def _repeated_replay_executions(
    claim_replays: tuple[ModeNeutralClaimReplayAuthority, ...],
) -> tuple[
    SealedWalkingCapabilityExecution,
    SealedWalkingCapabilityExecution,
    SealedWalkingCapabilityExecution,
]:
    primary, additional = claim_replays
    primary_replay = primary.replay.authority
    additional_replay = additional.replay.authority
    source = primary_replay.plan.source.execution
    if additional_replay.plan != primary_replay.plan:
        raise ValueError("VAL-004C Replays do not share one exact WALK-005B1 Plan")
    if additional_replay.plan.source.execution != source:
        raise ValueError("VAL-004C Replays do not share one exact source execution")
    executions = (source, primary_replay.execution, additional_replay.execution)
    for execution in executions:
        _require_stateless_text_request(execution.request)
    arguments = tuple(execution.request.arguments for execution in executions)
    if any(item != arguments[0] for item in arguments[1:]):
        raise ValueError("VAL-004C source and Replay stateless arguments differ")
    return executions


def _repeated_replay_independence(
    claim_replays: tuple[ModeNeutralClaimReplayAuthority, ...],
) -> StatelessRepeatedReplayIndependenceEvidence:
    executions = _repeated_replay_executions(claim_replays)
    dependencies = tuple(item.replay for item in claim_replays)
    return StatelessRepeatedReplayIndependenceEvidence(
        executionRunIds=tuple(item.run_id for item in executions),
        rootDigests=tuple(item.root_digest for item in executions),
        executionDigests=tuple(item.execution_digest for item in executions),
        requestIds=tuple(item.request.request_id for item in executions),
        grantIds=tuple(item.grant.grant_id for item in executions),
        permitIds=tuple(item.permit.permit_id for item in executions),
        dispatchIds=tuple(item.permit.dispatch_id for item in executions),
        approvalIds=tuple(item.approval.approval.approval_id for item in executions),
        workerExecutionIds=tuple(item.worker_result.execution_id for item in executions),
        evidenceReferences=tuple(
            f"{item.run_id}:{item.evidence_path}:{item.evidence_sha256}" for item in executions
        ),
        replayPublicationRunIds=tuple(item.run_id for item in dependencies),
        replayPublicationRootDigests=tuple(item.root_digest for item in dependencies),
        replayPublicationReferences=tuple(
            f"{item.run_id}:{item.artifact_path}:{item.artifact_sha256}" for item in dependencies
        ),
        replayAuthorityDigests=tuple(item.authority.authority_digest for item in dependencies),
    )


def _repeated_control_independence(
    repeated: ModeNeutralRepeatedClaimReplayAuthority,
    controls: ModeNeutralClaimControlAuthority,
) -> StatelessRepeatedControlIndependenceEvidence:
    replay_executions = _repeated_replay_executions(repeated.claim_replays)
    executions = (*replay_executions, *(item.execution for item in controls.executions))
    if len(executions) != _COMPLETE_EXECUTION_COUNT:
        raise ValueError("VAL-004C requires source, two Replays, and exactly three Controls")
    for execution in executions:
        _require_stateless_text_request(execution.request)
    return StatelessRepeatedControlIndependenceEvidence(
        executionRunIds=tuple(item.run_id for item in executions),
        rootDigests=tuple(item.root_digest for item in executions),
        executionDigests=tuple(item.execution_digest for item in executions),
        requestIds=tuple(item.request.request_id for item in executions),
        grantIds=tuple(item.grant.grant_id for item in executions),
        permitIds=tuple(item.permit.permit_id for item in executions),
        dispatchIds=tuple(item.permit.dispatch_id for item in executions),
        approvalIds=tuple(item.approval.approval.approval_id for item in executions),
        workerExecutionIds=tuple(item.worker_result.execution_id for item in executions),
        evidenceReferences=tuple(
            f"{item.run_id}:{item.evidence_path}:{item.evidence_sha256}" for item in executions
        ),
    )


def _require_stateless_text_request(request: ToolRequest) -> None:
    arguments = cast(dict[str, object], request.arguments)
    if set(arguments) != {"text"} or not isinstance(arguments.get("text"), str):
        raise ValueError("VAL-004C WALK request must use the exact stateless text schema")


def _require_unique_lineages(
    identities: tuple[tuple[str, ...], ...],
    *,
    expected: int,
    message: str,
) -> None:
    if any(len(set(items)) != expected for items in identities):
        raise ValueError(message)
