"""VAL-004B Profile-floor evidence for stateless VAL-001 WALK Claims."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.capabilities.activation import capability_tool_request_digest
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.claim_replay import (
    ModeNeutralClaimReplayAuthority,
    ModeNeutralClaimReplayError,
    verify_mode_neutral_claim_replay,
)
from pajin.discovery.validation_depth import (
    ValidationDepth,
    ValidationDepthRequirement,
    resolve_validation_depth_requirement,
)
from pajin.discovery.walking_mcp import MCPToolAuthorizationHypothesisOutcome
from pajin.discovery.walking_replay import WalkingMCPClaimReplayOutcome
from pajin.discovery.walking_validation import (
    SealedWalkingCapabilityExecution,
    WalkingCandidateAdmissionError,
    WalkingExecutionEvidence,
    WalkingIndependentApprovalReceipt,
    load_sealed_walking_capability_execution,
    walking_independent_approval_receipt,
)
from pajin.domain.models import CampaignManifest, CapabilityGrant, StrictModel, ToolRequest
from pajin.domain.replay import ReplaySessionPolicy
from pajin.domain.validation import AtomicClaim, AtomicClaimType
from pajin.domain.validation_controls import (
    ValidationControlContrast,
    ValidationControlKind,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_artifacts
from pajin.workflow.profile_assurance import (
    ProfileAssuranceFloor,
    ProfileAssuranceFloorError,
    resolve_profile_assurance_floor,
)
from pajin.workflow.tool_loop import PendingToolIntent, ToolLoopApproval

MODE_NEUTRAL_CLAIM_CONTROL_API_VERSION: Literal["pajin.dev/mode-neutral-claim-control/v1alpha1"] = (
    "pajin.dev/mode-neutral-claim-control/v1alpha1"
)
MODE_NEUTRAL_PROFILE_EVIDENCE_API_VERSION: Literal[
    "pajin.dev/mode-neutral-profile-validation-evidence/v1alpha1"
] = "pajin.dev/mode-neutral-profile-validation-evidence/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_CONTROL_KINDS = tuple(ValidationControlKind)
_SUPPORTED_CHAIN_IDS = (
    "chain-002:file-upload-rag-injection-tool-abuse",
    "chain-005:mcp-authorization-failure-privileged-action",
)
_COUNTERFACTUAL_TEXT = "Summarize the supplied public document."
_INSTRUCTION_OBSERVATION: Literal["untrusted text contains an instruction-hijacking pattern"] = (
    "untrusted text contains an instruction-hijacking pattern"
)
_BENIGN_OBSERVATION: Literal["text contains no instruction-hijacking pattern"] = (
    "text contains no instruction-hijacking pattern"
)
_MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
_MAX_AUTHORITY_BYTES = 16 * 1024 * 1024
_ARTIFACT_PATH = "mode-neutral-claim-control-authority.json"


class ModeNeutralProfileEvidenceError(ValueError):
    """Raised when VAL-004B cannot verify one exact WALK evidence set."""


class WalkingClaimControlCondition(StrEnum):
    """Code-owned causal condition represented by one exact Control request/result pair."""

    SOURCE_REQUEST = "source-request"
    ABSENT_CONTENT_CANARY = "absent-content-canary"
    BENIGN_INPUT = "benign-input"


class WalkingClaimControlOracle(StrEnum):
    """Code-owned observation function applied to one exact Tool result."""

    VULNERABILITY_OBSERVED = "vulnerability-observed"
    MCP_CONTENT_CONTAINS = "mcp-content-contains"


class WalkingClaimControlExpectation(StrictModel):
    """Exact observable required from one stateless WALK Control execution."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    observed: bool
    vulnerable: bool
    authorization_enforced: bool = Field(alias="authorizationEnforced")
    internal_data_accessed: bool = Field(alias="internalDataAccessed")
    observation: Literal[
        "untrusted text contains an instruction-hijacking pattern",
        "text contains no instruction-hijacking pattern",
    ]
    content_required: bool = Field(alias="contentRequired")
    oracle: WalkingClaimControlOracle
    oracle_value: str | None = Field(
        default=None,
        alias="oracleValue",
        min_length=1,
        max_length=200,
    )

    @field_validator(
        "observed",
        "vulnerable",
        "authorization_enforced",
        "internal_data_accessed",
        "content_required",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Walking Control expectation markers must be boolean")
        return value

    @model_validator(mode="after")
    def bind_oracle(self) -> Self:
        if (self.oracle is WalkingClaimControlOracle.MCP_CONTENT_CONTAINS) is (
            self.oracle_value is None
        ):
            raise ValueError("Walking Control Oracle value differs from its kind")
        return self


class WalkingClaimControlDefinition(StrictModel):
    """One deterministic, non-authorizing Control materialization."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    control_id: str = Field(alias="controlId", min_length=1, max_length=200)
    control_kind: ValidationControlKind = Field(alias="controlKind")
    condition: WalkingClaimControlCondition
    request: ToolRequest
    request_digest: _Sha256 = Field(alias="requestDigest")
    expectation: WalkingClaimControlExpectation

    @model_validator(mode="after")
    def bind_request(self) -> Self:
        if self.request_digest != capability_tool_request_digest(self.request):
            raise ValueError("Walking Control request Digest differs")
        return self


class ModeNeutralClaimControlContract(StrictModel):
    """Code-owned VAL-004B Control boundary without execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-claim-control/v1alpha1"] = Field(
        default=MODE_NEUTRAL_CLAIM_CONTROL_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralClaimControlContract"] = "ModeNeutralClaimControlContract"
    contract_id: Literal["val-004b:mode-neutral-claim-control"] = Field(
        default="val-004b:mode-neutral-claim-control",
        alias="contractId",
    )
    contract_version: Literal["1.0.0"] = Field(default="1.0.0", alias="contractVersion")
    contract_digest: str = Field(default="", alias="contractDigest", max_length=64)
    supported_chain_ids: tuple[str, ...] = Field(
        default=_SUPPORTED_CHAIN_IDS,
        alias="supportedChainIds",
        min_length=2,
        max_length=2,
    )
    claim_type: Literal[AtomicClaimType.VALIDITY] = Field(
        default=AtomicClaimType.VALIDITY,
        alias="claimType",
    )
    control_kinds: tuple[ValidationControlKind, ...] = Field(
        default=_CONTROL_KINDS,
        alias="controlKinds",
        min_length=3,
        max_length=3,
    )
    session_policy: Literal[ReplaySessionPolicy.STATELESS] = Field(
        default=ReplaySessionPolicy.STATELESS,
        alias="sessionPolicy",
    )
    independence_scope: Literal["source-replay-control-execution-lineage"] = Field(
        default="source-replay-control-execution-lineage",
        alias="independenceScope",
    )
    campaign_mode_constraint: Literal["none"] = Field(
        default="none",
        alias="campaignModeConstraint",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    confirmation_authorized: Literal[False] = Field(
        default=False,
        alias="confirmationAuthorized",
    )
    finding_confirmed: Literal[False] = Field(default=False, alias="findingConfirmed")

    @field_validator(
        "execution_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Walking Claim Control Contract markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_contract(self) -> Self:
        if self.supported_chain_ids != _SUPPORTED_CHAIN_IDS or self.control_kinds != _CONTROL_KINDS:
            raise ValueError("VAL-004B registered Chain or Control order differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"contract_digest"})
        digest = discovery_digest(
            "pajin.validation.mode-neutral-claim-control-contract/v1",
            material,
        )
        if self.contract_digest and self.contract_digest != digest:
            raise ValueError("Walking Claim Control Contract Digest differs")
        object.__setattr__(self, "contract_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Claim Control Contract",
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        return self


class ModeNeutralClaimControlPlan(StrictModel):
    """Exact stateless Control plan derived from one VAL-001 authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-claim-control/v1alpha1"] = Field(
        default=MODE_NEUTRAL_CLAIM_CONTROL_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralClaimControlPlan"] = "ModeNeutralClaimControlPlan"
    plan_id: str = Field(default="", alias="planId", max_length=110)
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    contract: ModeNeutralClaimControlContract
    claim_replay: ModeNeutralClaimReplayAuthority = Field(alias="claimReplay")
    controls: tuple[WalkingClaimControlDefinition, ...] = Field(min_length=3, max_length=3)
    execution_state: Literal["planned-not-authorized"] = Field(
        default="planned-not-authorized",
        alias="executionState",
    )
    profile_selection_authorized: Literal[False] = Field(
        default=False,
        alias="profileSelectionAuthorized",
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

    @field_validator(
        "profile_selection_authorized",
        "campaign_mutation_authorized",
        "execution_authorized",
        "confirmation_authorized",
        "finding_confirmed",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Walking Claim Control Plan markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        if self.contract != registered_mode_neutral_claim_control_contract():
            raise ValueError("VAL-004B Control Contract differs from code authority")
        if self.claim_replay.chain_id not in self.contract.supported_chain_ids:
            raise ValueError("VAL-004B Claim Replay Chain is not supported")
        if self.controls != _materialize_controls(self.claim_replay):
            raise ValueError("VAL-004B Controls differ from code-owned materialization")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"plan_id", "plan_digest"},
        )
        digest = discovery_digest("pajin.validation.mode-neutral-claim-control-plan/v1", material)
        plan_id = f"mode-neutral-claim-control-plan_{digest}"
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("Walking Claim Control Plan Digest differs")
        if self.plan_id and self.plan_id != plan_id:
            raise ValueError("Walking Claim Control Plan ID differs")
        object.__setattr__(self, "plan_digest", digest)
        object.__setattr__(self, "plan_id", plan_id)
        return self


class WalkingClaimControlApprovalReceipt(StrictModel):
    """Pre-dispatch receipt binding one explicit approval to one VAL-004B Control."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    plan_id: str = Field(alias="planId", min_length=1, max_length=110)
    plan_digest: _Sha256 = Field(alias="planDigest")
    control_id: str = Field(alias="controlId", min_length=1, max_length=200)
    control_kind: ValidationControlKind = Field(alias="controlKind")
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: _Sha256 = Field(alias="requestDigest")
    approval: WalkingIndependentApprovalReceipt

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        if (
            self.request_id != self.approval.request_id
            or self.request_digest != self.approval.request_digest
        ):
            raise ValueError("Walking Claim Control approval differs from exact request")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = discovery_digest("pajin.validation.walking-claim-control-approval/v1", material)
        receipt_id = f"walking-claim-control-approval_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Walking Claim Control approval receipt Digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Walking Claim Control approval receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class _WalkingClaimControlContent(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    type: Literal["text"]
    text: str = Field(min_length=1, max_length=20_000)


class _WalkingClaimControlOutput(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    vulnerable: bool
    authorization_enforced: bool = Field(alias="authorizationEnforced")
    internal_data_accessed: bool = Field(alias="internalDataAccessed")
    observation: Literal[
        "untrusted text contains an instruction-hijacking pattern",
        "text contains no instruction-hijacking pattern",
    ]
    target: str = Field(min_length=1, max_length=2_000)
    mcp_server_id: str = Field(alias="mcpServerId", min_length=1, max_length=200)
    mcp_tool_name: str = Field(alias="mcpToolName", min_length=1, max_length=200)
    mcp_content: tuple[_WalkingClaimControlContent, ...] = Field(alias="mcpContent", max_length=1)

    @field_validator(
        "vulnerable",
        "authorization_enforced",
        "internal_data_accessed",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Walking Claim Control output markers must be boolean")
        return value


class WalkingClaimControlExecution(StrictModel):
    """One exact approved and sealed Control execution retained by VAL-004B."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    plan_id: str = Field(alias="planId", min_length=1, max_length=110)
    plan_digest: _Sha256 = Field(alias="planDigest")
    definition: WalkingClaimControlDefinition
    approval: WalkingClaimControlApprovalReceipt
    execution: SealedWalkingCapabilityExecution
    output: _WalkingClaimControlOutput
    observed: bool
    publication_evidence_path: str = Field(
        alias="publicationEvidencePath",
        min_length=1,
        max_length=2_000,
    )
    publication_evidence_sha256: _Sha256 = Field(alias="publicationEvidenceSha256")

    @field_validator("observed", mode="before")
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Walking Claim Control observation must be boolean")
        return value

    @model_validator(mode="after")
    def bind_execution(self) -> Self:
        expected_path = f"control-evidence/{self.definition.control_kind.value}.json"
        if (
            self.execution.request != self.definition.request
            or self.approval.plan_id != self.plan_id
            or self.approval.plan_digest != self.plan_digest
            or self.approval.control_id != self.definition.control_id
            or self.approval.control_kind is not self.definition.control_kind
            or self.approval.approval != self.execution.approval
            or self.observed is not self.definition.expectation.observed
            or self.publication_evidence_path != expected_path
            or self.publication_evidence_sha256 != self.execution.evidence_sha256
        ):
            raise ValueError("Walking Claim Control execution differs from its Plan")
        return self


class StatelessControlIndependenceEvidence(StrictModel):
    """Explicit proof that stateless source, Replay, and Controls use fresh lineages."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    session_policy: Literal[ReplaySessionPolicy.STATELESS] = Field(
        default=ReplaySessionPolicy.STATELESS,
        alias="sessionPolicy",
    )
    session_argument_absent: Literal[True] = Field(
        default=True,
        alias="sessionArgumentAbsent",
    )
    execution_run_ids: tuple[str, ...] = Field(alias="executionRunIds", min_length=5, max_length=5)
    root_digests: tuple[_Sha256, ...] = Field(alias="rootDigests", min_length=5, max_length=5)
    execution_digests: tuple[_Sha256, ...] = Field(
        alias="executionDigests",
        min_length=5,
        max_length=5,
    )
    request_ids: tuple[str, ...] = Field(alias="requestIds", min_length=5, max_length=5)
    grant_ids: tuple[str, ...] = Field(alias="grantIds", min_length=5, max_length=5)
    permit_ids: tuple[str, ...] = Field(alias="permitIds", min_length=5, max_length=5)
    approval_ids: tuple[str, ...] = Field(alias="approvalIds", min_length=5, max_length=5)
    worker_execution_ids: tuple[str, ...] = Field(
        alias="workerExecutionIds",
        min_length=5,
        max_length=5,
    )
    evidence_references: tuple[str, ...] = Field(
        alias="evidenceReferences",
        min_length=5,
        max_length=5,
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
            raise ValueError("Stateless Control independence markers must be boolean true")
        return value

    @model_validator(mode="after")
    def require_unique_lineages(self) -> Self:
        identities = (
            self.execution_run_ids,
            self.root_digests,
            self.execution_digests,
            self.request_ids,
            self.grant_ids,
            self.permit_ids,
            self.approval_ids,
            self.worker_execution_ids,
            self.evidence_references,
        )
        if any(len(set(items)) != 5 for items in identities):
            raise ValueError("Source, Replay, and Control execution lineage must be disjoint")
        return self


class ModeNeutralClaimControlAuthority(StrictModel):
    """Verified three-Control contrast for one exact VAL-001 Claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-claim-control/v1alpha1"] = Field(
        default=MODE_NEUTRAL_CLAIM_CONTROL_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralClaimControlAuthority"] = "ModeNeutralClaimControlAuthority"
    authority_id: str = Field(default="", alias="authorityId", max_length=110)
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)
    plan: ModeNeutralClaimControlPlan
    executions: tuple[WalkingClaimControlExecution, ...] = Field(min_length=3, max_length=3)
    independence: StatelessControlIndependenceEvidence
    contrast: Literal[ValidationControlContrast.OBSERVED] = ValidationControlContrast.OBSERVED
    validation_state: Literal["controlled-validity-reproduced-not-confirmed"] = Field(
        default="controlled-validity-reproduced-not-confirmed",
        alias="validationState",
    )
    informational_only: Literal[True] = Field(default=True, alias="informationalOnly")
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

    @field_validator("informational_only", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Walking Claim Control informational marker must be boolean true")
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
            raise ValueError("Walking Claim Control authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_authority(self) -> Self:
        if tuple(item.definition for item in self.executions) != self.plan.controls:
            raise ValueError("Walking Claim Control executions differ from canonical Control order")
        for definition, item in zip(self.plan.controls, self.executions, strict=True):
            _validate_control_output(self.plan, definition, item.output)
        expected_independence = _independence_evidence(self.plan, self.executions)
        if self.independence != expected_independence:
            raise ValueError("Walking Claim Control independence evidence differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_id", "authority_digest"},
        )
        digest = discovery_digest(
            "pajin.validation.mode-neutral-claim-control-authority/v1",
            material,
        )
        authority_id = f"mode-neutral-claim-control_{digest}"
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Walking Claim Control Authority Digest differs")
        if self.authority_id and self.authority_id != authority_id:
            raise ValueError("Walking Claim Control Authority ID differs")
        object.__setattr__(self, "authority_digest", digest)
        object.__setattr__(self, "authority_id", authority_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Mode-neutral Claim Control Authority",
            max_bytes=_MAX_AUTHORITY_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class ModeNeutralClaimControlOutcome:
    run_id: str
    run_path: Path
    artifact_path: str
    authority: ModeNeutralClaimControlAuthority
    execution_evidence: tuple[WalkingExecutionEvidence, ...]


class ModeNeutralProfileValidationEvidenceAssessment(StrictModel):
    """Profile-floor satisfaction derived from verified VAL-001 and optional Controls."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mode-neutral-profile-validation-evidence/v1alpha1"] = Field(
        default=MODE_NEUTRAL_PROFILE_EVIDENCE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ModeNeutralProfileValidationEvidenceAssessment"] = (
        "ModeNeutralProfileValidationEvidenceAssessment"
    )
    assessment_id: str = Field(default="", alias="assessmentId", max_length=320)
    assessment_digest: str = Field(default="", alias="assessmentDigest", max_length=64)
    profile_floor: ProfileAssuranceFloor = Field(alias="profileFloor")
    claim: AtomicClaim
    claim_replay: ModeNeutralClaimReplayAuthority = Field(alias="claimReplay")
    control_evidence: ModeNeutralClaimControlAuthority | None = Field(
        default=None,
        alias="controlEvidence",
    )
    achieved_depth: ValidationDepth = Field(alias="achievedDepth")
    achieved_requirement: ValidationDepthRequirement = Field(alias="achievedRequirement")
    validation_state: Literal["profile-floor-satisfied-not-confirmed"] = Field(
        default="profile-floor-satisfied-not-confirmed",
        alias="validationState",
    )
    evidence_source_constraint: Literal["val-001-walking-mcp-v1"] = Field(
        default="val-001-walking-mcp-v1",
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
            raise ValueError("Mode-neutral Profile evidence markers must be boolean true")
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
            raise ValueError("Mode-neutral Profile authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_assessment(self) -> Self:
        floor = resolve_profile_assurance_floor(
            self.profile_floor.profile_id,
            self.profile_floor.profile_version,
        )
        depth = (
            ValidationDepth.SINGLE_VALIDITY_REPLAY
            if self.control_evidence is None
            else ValidationDepth.CONTROLLED_VALIDITY_REPLAY
        )
        requirement = resolve_validation_depth_requirement(depth)
        _validate_stateless_claim_replay(self.claim_replay)
        if (
            self.profile_floor != floor
            or self.claim != self.claim_replay.claim
            or self.achieved_depth is not depth
            or self.achieved_requirement != requirement
            or ReplaySessionPolicy.STATELESS not in requirement.allowed_replay_session_policies
            or requirement.depth_ordinal < floor.minimum_depth_ordinal
        ):
            raise ValueError("Mode-neutral WALK evidence does not satisfy the registered Floor")
        if (
            self.control_evidence is not None
            and self.control_evidence.plan.claim_replay != self.claim_replay
        ):
            raise ValueError("Mode-neutral Control evidence belongs to another VAL-001 Claim")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"assessment_id", "assessment_digest"},
        )
        digest = discovery_digest("pajin.validation.mode-neutral-profile-evidence/v1", material)
        assessment_id = f"mode-neutral-profile-evidence:{floor.profile_id}:{digest}"
        if self.assessment_digest and self.assessment_digest != digest:
            raise ValueError("Mode-neutral Profile Evidence Digest differs")
        if self.assessment_id and self.assessment_id != assessment_id:
            raise ValueError("Mode-neutral Profile Evidence ID differs")
        object.__setattr__(self, "assessment_digest", digest)
        object.__setattr__(self, "assessment_id", assessment_id)
        return self


def registered_mode_neutral_claim_control_contract() -> ModeNeutralClaimControlContract:
    """Return the exact code-owned VAL-004B Control contract."""

    return ModeNeutralClaimControlContract()


def compile_mode_neutral_claim_control_plan(
    claim_replay: ModeNeutralClaimReplayAuthority,
) -> ModeNeutralClaimControlPlan:
    """Materialize the exact three stateless Controls without authorizing execution."""

    canonical = ModeNeutralClaimReplayAuthority.model_validate(
        claim_replay.model_dump(mode="json", by_alias=True)
    )
    return ModeNeutralClaimControlPlan(
        contract=registered_mode_neutral_claim_control_contract(),
        claimReplay=canonical,
        controls=_materialize_controls(canonical),
    )


def walking_claim_control_approval_receipt(
    plan: ModeNeutralClaimControlPlan,
    definition: WalkingClaimControlDefinition,
    request: ToolRequest,
    intent: PendingToolIntent,
    approval: ToolLoopApproval,
    grant: CapabilityGrant,
) -> WalkingClaimControlApprovalReceipt:
    """Bind one existing approval to an exact Control Plan before dispatch."""

    canonical_plan = ModeNeutralClaimControlPlan.model_validate(
        plan.model_dump(mode="json", by_alias=True)
    )
    matches = [item for item in canonical_plan.controls if item.control_id == definition.control_id]
    if len(matches) != 1 or matches[0] != definition or definition.request != request:
        raise ModeNeutralProfileEvidenceError("Walking Control approval differs from its Plan")
    replan = canonical_plan.claim_replay.replay.authority.plan.source.replan
    base = walking_independent_approval_receipt(replan, request, intent, approval, grant)
    return WalkingClaimControlApprovalReceipt(
        planId=canonical_plan.plan_id,
        planDigest=canonical_plan.plan_digest,
        controlId=definition.control_id,
        controlKind=definition.control_kind,
        requestId=request.request_id,
        requestDigest=capability_tool_request_digest(request),
        approval=base,
    )


class ModeNeutralClaimControlRunner:
    """Verify three already executed Controls and seal their non-confirming authority."""

    def __init__(self, *, output_root: Path) -> None:
        self._output_root = output_root

    def run(
        self,
        campaign: CampaignManifest,
        plan: ModeNeutralClaimControlPlan,
        chain_source: MCPToolAuthorizationHypothesisOutcome,
        replay_outcome: WalkingMCPClaimReplayOutcome,
        execution_evidence: tuple[WalkingExecutionEvidence, ...],
    ) -> ModeNeutralClaimControlOutcome:
        try:
            authoritative_campaign = CampaignManifest.model_validate(
                campaign.model_dump(mode="json", by_alias=True)
            )
            verified_claim = verify_mode_neutral_claim_replay(
                plan.claim_replay,
                authoritative_campaign,
                chain_source,
                replay_outcome,
            )
            expected_plan = compile_mode_neutral_claim_control_plan(verified_claim)
            if plan != expected_plan or len(execution_evidence) != 3:
                raise ValueError("Walking Claim Control Plan or execution count differs")
            built = tuple(
                _build_control_execution(expected_plan, definition, evidence)
                for definition, evidence in zip(
                    expected_plan.controls,
                    execution_evidence,
                    strict=True,
                )
            )
            executions = tuple(item[0] for item in built)
            authority = ModeNeutralClaimControlAuthority(
                plan=expected_plan,
                executions=executions,
                independence=_independence_evidence(expected_plan, executions),
            )
        except ModeNeutralProfileEvidenceError:
            raise
        except (
            AttributeError,
            ModeNeutralClaimReplayError,
            OSError,
            RunIntegrityError,
            TypeError,
            ValidationError,
            ValueError,
            WalkingCandidateAdmissionError,
        ) as exc:
            raise ModeNeutralProfileEvidenceError(
                "VAL-004B could not verify the stateless WALK Control executions"
            ) from exc

        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        if store.run_id in authority.independence.execution_run_ids:
            raise ModeNeutralProfileEvidenceError(
                "VAL-004B publication Run must differ from execution Runs"
            )
        store.append_event(
            "campaign.started",
            {
                "campaign": authoritative_campaign.metadata.name,
                "mode": authoritative_campaign.spec.mode.value,
                "purpose": "mode-neutral-claim-controls",
            },
        )
        store.write_json(
            "campaign.json",
            authoritative_campaign.model_dump(mode="json", by_alias=True),
        )
        for execution, raw_evidence in built:
            store.write_json(
                execution.publication_evidence_path,
                parse_strict_json_bytes(
                    raw_evidence,
                    label="Walking Claim Control copied evidence",
                    max_bytes=_MAX_ARTIFACT_BYTES,
                ),
            )
        artifact_path = store.write_json(
            _ARTIFACT_PATH,
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "walking.claim-control-authority.created",
            {
                "artifact": artifact_path,
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "planId": authority.plan.plan_id,
                "claimId": authority.plan.claim_replay.claim.claim_id,
                "controlKinds": [item.value for item in _CONTROL_KINDS],
                "contrast": authority.contrast.value,
                "sessionPolicy": authority.independence.session_policy,
                "informationalOnly": True,
            },
        )
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": "completed",
                "stage": "mode-neutral-claim-controls-sealed",
                "authorityId": authority.authority_id,
                "validationState": authority.validation_state,
                "informationalOnly": True,
            },
        )
        store.append_event(
            "campaign.completed",
            {
                "purpose": "mode-neutral-claim-controls",
                "artifact": artifact_path,
                "controlCount": 3,
                "informationalOnly": True,
            },
        )
        store.seal()
        return ModeNeutralClaimControlOutcome(
            run_id=store.run_id,
            run_path=store.path,
            artifact_path=artifact_path,
            authority=authority.model_copy(deep=True),
            execution_evidence=execution_evidence,
        )


def load_mode_neutral_claim_control_authority(
    campaign: CampaignManifest,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    replay_outcome: WalkingMCPClaimReplayOutcome,
    outcome: ModeNeutralClaimControlOutcome,
) -> ModeNeutralClaimControlAuthority:
    """Reopen publication and execution Runs and exact-match one VAL-004B authority."""

    try:
        if outcome.artifact_path != _ARTIFACT_PATH:
            raise ValueError("Walking Claim Control artifact path differs")
        paths = tuple(item.publication_evidence_path for item in outcome.authority.executions)
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_ARTIFACT_BYTES,
                "run.json": _MAX_ARTIFACT_BYTES,
                outcome.artifact_path: _MAX_AUTHORITY_BYTES,
                **{path: _MAX_ARTIFACT_BYTES for path in paths},
            },
            expected_run_id=outcome.run_id,
        )
        sealed_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        authority = ModeNeutralClaimControlAuthority.model_validate_json(
            snapshot.artifact_bytes(outcome.artifact_path)
        )
        if sealed_campaign != campaign or authority != outcome.authority:
            raise ValueError("Walking Claim Control publication differs from outcome")
        if outcome.run_id in authority.independence.execution_run_ids:
            raise ValueError("Walking Claim Control publication reuses an execution Run")
        run_summary = parse_strict_json_bytes(
            snapshot.artifact_bytes("run.json"),
            label="Walking Claim Control run summary",
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        expected_summary = {
            "runId": outcome.run_id,
            "status": "completed",
            "stage": "mode-neutral-claim-controls-sealed",
            "authorityId": authority.authority_id,
            "validationState": authority.validation_state,
            "informationalOnly": True,
        }
        if (
            type(run_summary) is not dict
            or type(run_summary.get("informationalOnly")) is not bool
            or run_summary != expected_summary
        ):
            raise ValueError("Walking Claim Control run summary differs")
        verified_claim = verify_mode_neutral_claim_replay(
            authority.plan.claim_replay,
            sealed_campaign,
            chain_source,
            replay_outcome,
        )
        expected_plan = compile_mode_neutral_claim_control_plan(verified_claim)
        if authority.plan != expected_plan or len(outcome.execution_evidence) != 3:
            raise ValueError("Walking Claim Control Plan differs from sealed predecessors")
        rebuilt = tuple(
            _build_control_execution(expected_plan, definition, evidence)
            for definition, evidence in zip(
                expected_plan.controls,
                outcome.execution_evidence,
                strict=True,
            )
        )
        executions = tuple(item[0] for item in rebuilt)
        expected_authority = ModeNeutralClaimControlAuthority(
            plan=expected_plan,
            executions=executions,
            independence=_independence_evidence(expected_plan, executions),
        )
        if authority != expected_authority:
            raise ValueError("Walking Claim Control authority differs from execution Runs")
        for item, (_, source_bytes) in zip(authority.executions, rebuilt, strict=True):
            copied = snapshot.artifact_bytes(item.publication_evidence_path)
            if (
                copied != source_bytes
                or sha256(copied).hexdigest() != item.publication_evidence_sha256
            ):
                raise ValueError("Walking Claim Control copied evidence differs from execution")
        created = [
            event
            for event in snapshot.events
            if event.event_type == "walking.claim-control-authority.created"
        ]
        expected_event = {
            "artifact": outcome.artifact_path,
            "authorityId": authority.authority_id,
            "authorityDigest": authority.authority_digest,
            "planId": authority.plan.plan_id,
            "claimId": authority.plan.claim_replay.claim.claim_id,
            "controlKinds": [item.value for item in _CONTROL_KINDS],
            "contrast": authority.contrast.value,
            "sessionPolicy": authority.independence.session_policy,
            "informationalOnly": True,
        }
        if len(created) != 1 or created[0].payload != expected_event:
            raise ValueError("Walking Claim Control publication event differs")
        completed = [event for event in snapshot.events if event.event_type == "campaign.completed"]
        expected_completed = {
            "purpose": "mode-neutral-claim-controls",
            "artifact": outcome.artifact_path,
            "controlCount": 3,
            "informationalOnly": True,
        }
        if (
            len(completed) != 1
            or type(completed[0].payload.get("informationalOnly")) is not bool
            or type(completed[0].payload.get("controlCount")) is not int
            or completed[0].payload != expected_completed
        ):
            raise ValueError("Walking Claim Control completion event differs")
        return authority.model_copy(deep=True)
    except ModeNeutralProfileEvidenceError:
        raise
    except (
        AttributeError,
        KeyError,
        ModeNeutralClaimReplayError,
        OSError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
        WalkingCandidateAdmissionError,
    ) as exc:
        raise ModeNeutralProfileEvidenceError(
            "VAL-004B Control authority could not be rebuilt from sealed predecessors"
        ) from exc


def evaluate_mode_neutral_profile_validation_evidence(
    profile_id: str,
    profile_version: str,
    campaign: CampaignManifest,
    claim_replay: ModeNeutralClaimReplayAuthority,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    replay_outcome: WalkingMCPClaimReplayOutcome,
    control_outcome: ModeNeutralClaimControlOutcome | None = None,
) -> ModeNeutralProfileValidationEvidenceAssessment:
    """Evaluate verified VAL-001 evidence against one exact registered Profile floor."""

    try:
        verified_claim = verify_mode_neutral_claim_replay(
            claim_replay,
            campaign,
            chain_source,
            replay_outcome,
        )
        controls = (
            None
            if control_outcome is None
            else load_mode_neutral_claim_control_authority(
                campaign,
                chain_source,
                replay_outcome,
                control_outcome,
            )
        )
        if controls is not None and controls.plan.claim_replay != verified_claim:
            raise ValueError("Walking Control evidence belongs to another VAL-001 authority")
        depth = (
            ValidationDepth.SINGLE_VALIDITY_REPLAY
            if controls is None
            else ValidationDepth.CONTROLLED_VALIDITY_REPLAY
        )
        floor = resolve_profile_assurance_floor(profile_id, profile_version)
        requirement = resolve_validation_depth_requirement(depth)
        _validate_stateless_claim_replay(verified_claim)
        if ReplaySessionPolicy.STATELESS not in requirement.allowed_replay_session_policies:
            raise ValueError("VAL-002 does not accept stateless Replay isolation")
        if requirement.depth_ordinal < floor.minimum_depth_ordinal:
            raise ValueError("VAL-001 WALK evidence is below the registered Profile floor")
        return ModeNeutralProfileValidationEvidenceAssessment(
            profileFloor=floor,
            claim=verified_claim.claim,
            claimReplay=verified_claim,
            controlEvidence=controls,
            achievedDepth=depth,
            achievedRequirement=requirement,
        )
    except ModeNeutralProfileEvidenceError:
        raise
    except (
        AttributeError,
        ModeNeutralClaimReplayError,
        OSError,
        ProfileAssuranceFloorError,
        RunIntegrityError,
        TypeError,
        ValidationError,
        ValueError,
        WalkingCandidateAdmissionError,
    ) as exc:
        raise ModeNeutralProfileEvidenceError(
            "VAL-004B could not verify VAL-001 evidence against the registered Profile floor"
        ) from exc


def verify_mode_neutral_profile_validation_evidence(
    assessment: ModeNeutralProfileValidationEvidenceAssessment,
    campaign: CampaignManifest,
    chain_source: MCPToolAuthorizationHypothesisOutcome,
    replay_outcome: WalkingMCPClaimReplayOutcome,
    control_outcome: ModeNeutralClaimControlOutcome | None = None,
) -> ModeNeutralProfileValidationEvidenceAssessment:
    """Rebuild and exact-match one VAL-004B Profile-floor assessment."""

    try:
        canonical = ModeNeutralProfileValidationEvidenceAssessment.model_validate(
            assessment.model_dump(mode="json", by_alias=True)
        )
        expected = evaluate_mode_neutral_profile_validation_evidence(
            canonical.profile_floor.profile_id,
            canonical.profile_floor.profile_version,
            campaign,
            canonical.claim_replay,
            chain_source,
            replay_outcome,
            control_outcome,
        )
        if canonical != expected:
            raise ValueError("Mode-neutral Profile assessment differs from sealed predecessors")
        return canonical
    except ModeNeutralProfileEvidenceError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ModeNeutralProfileEvidenceError(
            "VAL-004B Profile assessment could not be verified against sealed predecessors"
        ) from exc


def _materialize_controls(
    authority: ModeNeutralClaimReplayAuthority,
) -> tuple[WalkingClaimControlDefinition, ...]:
    replay = authority.replay.authority
    original = replay.plan.source.execution
    replay_execution = replay.execution
    _require_stateless_text_request(original.request)
    _require_stateless_text_request(replay_execution.request)
    if original.request.arguments != replay_execution.request.arguments:
        raise ValueError("VAL-001 original and Replay arguments differ")
    # Keep sealed evidence paths below common Windows path ceilings; the Plan retains the
    # complete Claim Replay Authority and Digest, so this suffix is only a portable ID nonce.
    nonce = authority.authority_digest[:24]
    negative_canary = f"PAJIN_CONTROL_ABSENT_{nonce.upper()}"
    source_output = _WalkingClaimControlOutput.model_validate(original.result.data)
    if any(negative_canary in item.text for item in source_output.mcp_content):
        raise ValueError("VAL-004B negative Control canary is present in source content")
    specs = (
        (
            ValidationControlKind.BASELINE,
            WalkingClaimControlCondition.SOURCE_REQUEST,
            original.request.arguments,
            WalkingClaimControlExpectation(
                observed=True,
                vulnerable=True,
                authorizationEnforced=False,
                internalDataAccessed=True,
                observation=_INSTRUCTION_OBSERVATION,
                contentRequired=True,
                oracle=WalkingClaimControlOracle.VULNERABILITY_OBSERVED,
            ),
        ),
        (
            ValidationControlKind.NEGATIVE_CONTROL,
            WalkingClaimControlCondition.ABSENT_CONTENT_CANARY,
            original.request.arguments,
            WalkingClaimControlExpectation(
                observed=False,
                vulnerable=True,
                authorizationEnforced=False,
                internalDataAccessed=True,
                observation=_INSTRUCTION_OBSERVATION,
                contentRequired=True,
                oracle=WalkingClaimControlOracle.MCP_CONTENT_CONTAINS,
                oracleValue=negative_canary,
            ),
        ),
        (
            ValidationControlKind.COUNTERFACTUAL,
            WalkingClaimControlCondition.BENIGN_INPUT,
            {"text": _COUNTERFACTUAL_TEXT},
            WalkingClaimControlExpectation(
                observed=False,
                vulnerable=False,
                authorizationEnforced=False,
                internalDataAccessed=False,
                observation=_BENIGN_OBSERVATION,
                contentRequired=False,
                oracle=WalkingClaimControlOracle.VULNERABILITY_OBSERVED,
            ),
        ),
    )
    result = []
    for kind, condition, arguments, expectation in specs:
        portable = kind.value.replace("-", "_")
        request = ToolRequest(
            request_id=f"tool_val004b_{nonce}_{portable}",
            agent_id="agent:walking-validation-control",
            tool_id=original.request.tool_id,
            target=original.request.target,
            method=original.request.method,
            arguments=dict(arguments),
        )
        result.append(
            WalkingClaimControlDefinition(
                controlId=f"control_val004b_{nonce}_{portable}",
                controlKind=kind,
                condition=condition,
                request=request,
                requestDigest=capability_tool_request_digest(request),
                expectation=expectation,
            )
        )
    return tuple(result)


def _build_control_execution(
    plan: ModeNeutralClaimControlPlan,
    definition: WalkingClaimControlDefinition,
    evidence: WalkingExecutionEvidence,
) -> tuple[WalkingClaimControlExecution, bytes]:
    replan = plan.claim_replay.replay.authority.plan.source.replan
    execution = load_sealed_walking_capability_execution(replan, evidence)
    capability = replan.source.hypothesis.capability
    permit_capability = execution.permit.capability
    if execution.request != definition.request:
        raise ValueError("Walking Control execution request differs from materialization")
    if (
        execution.grant.campaign != plan.claim_replay.campaign_id
        or permit_capability.capability_id != capability.capability_id
        or permit_capability.capability_version != capability.capability_version
        or permit_capability.definition_digest != capability.capability_digest
        or permit_capability.tool_id != capability.tool.tool_id
        or permit_capability.tool_version != capability.tool.tool_version
        or permit_capability.tool_digest != capability.tool.tool_digest
        or permit_capability.risk_tier != capability.risk_tier
    ):
        raise ValueError("Walking Control execution substitutes Capability authority")
    receipt = walking_claim_control_approval_receipt(
        plan,
        definition,
        execution.request,
        evidence.intent,
        evidence.approval,
        execution.grant,
    )
    snapshot = load_verified_run_artifacts(
        evidence.run_path,
        requests={execution.evidence_path: _MAX_ARTIFACT_BYTES},
        expected_run_id=execution.run_id,
    )
    approved = [
        event
        for event in snapshot.events
        if event.event_type == "walking.claim-control-plan.approved"
        and event.payload == receipt.model_dump(mode="json", by_alias=True)
    ]
    claimed = [
        event
        for event in snapshot.events
        if event.event_type == "capability.dispatch.claimed"
        and event.payload.get("permitId") == execution.permit.permit_id
    ]
    if (
        len(approved) != 1
        or len(claimed) != 1
        or approved[0].occurred_at != evidence.approval.approved_at
        or approved[0].sequence >= claimed[0].sequence
    ):
        raise ValueError("Walking Control Plan approval was not sealed before dispatch")
    output = _WalkingClaimControlOutput.model_validate(execution.result.data)
    _validate_control_output(plan, definition, output)
    raw = snapshot.artifact_bytes(execution.evidence_path)
    return (
        WalkingClaimControlExecution(
            planId=plan.plan_id,
            planDigest=plan.plan_digest,
            definition=definition,
            approval=receipt,
            execution=execution,
            output=output,
            observed=definition.expectation.observed,
            publicationEvidencePath=f"control-evidence/{definition.control_kind.value}.json",
            publicationEvidenceSha256=sha256(raw).hexdigest(),
        ),
        raw,
    )


def _validate_control_output(
    plan: ModeNeutralClaimControlPlan,
    definition: WalkingClaimControlDefinition,
    output: _WalkingClaimControlOutput,
) -> None:
    source = plan.claim_replay.replay.authority.plan.source.execution
    source_output = _WalkingClaimControlOutput.model_validate(source.result.data)
    expectation = definition.expectation
    content_present = len(output.mcp_content) == 1
    observed = _observe_control(expectation, output)
    if (
        observed is not expectation.observed
        or output.vulnerable is not expectation.vulnerable
        or output.authorization_enforced is not expectation.authorization_enforced
        or output.internal_data_accessed is not expectation.internal_data_accessed
        or output.observation != expectation.observation
        or content_present is not expectation.content_required
        or output.target != source_output.target
        or output.mcp_server_id != source_output.mcp_server_id
        or output.mcp_tool_name != source_output.mcp_tool_name
    ):
        raise ValueError("Walking Claim Control output differs from expected observable")
    if expectation.content_required and output.mcp_content != source_output.mcp_content:
        raise ValueError("Walking Claim Control content differs from source observation")


def _observe_control(
    expectation: WalkingClaimControlExpectation,
    output: _WalkingClaimControlOutput,
) -> bool:
    if expectation.oracle is WalkingClaimControlOracle.VULNERABILITY_OBSERVED:
        return (
            output.vulnerable
            and not output.authorization_enforced
            and output.internal_data_accessed
        )
    if expectation.oracle is WalkingClaimControlOracle.MCP_CONTENT_CONTAINS:
        assert expectation.oracle_value is not None
        return any(expectation.oracle_value in item.text for item in output.mcp_content)
    raise ValueError("Walking Claim Control Oracle is not registered")


def _independence_evidence(
    plan: ModeNeutralClaimControlPlan,
    executions: tuple[WalkingClaimControlExecution, ...],
) -> StatelessControlIndependenceEvidence:
    replay = plan.claim_replay.replay.authority
    sealed = (
        replay.plan.source.execution,
        replay.execution,
        *(item.execution for item in executions),
    )
    if len(sealed) != 5:
        raise ValueError("VAL-004B requires source, Replay, and exactly three Controls")
    for item in sealed:
        _require_stateless_text_request(item.request)
    return StatelessControlIndependenceEvidence(
        executionRunIds=tuple(item.run_id for item in sealed),
        rootDigests=tuple(item.root_digest for item in sealed),
        executionDigests=tuple(item.execution_digest for item in sealed),
        requestIds=tuple(item.request.request_id for item in sealed),
        grantIds=tuple(item.grant.grant_id for item in sealed),
        permitIds=tuple(item.permit.permit_id for item in sealed),
        approvalIds=tuple(item.approval.approval.approval_id for item in sealed),
        workerExecutionIds=tuple(item.worker_result.execution_id for item in sealed),
        evidenceReferences=tuple(
            f"{item.run_id}:{item.evidence_path}:{item.evidence_sha256}" for item in sealed
        ),
    )


def _require_stateless_text_request(request: ToolRequest) -> None:
    arguments = cast(dict[str, object], request.arguments)
    if set(arguments) != {"text"} or not isinstance(arguments.get("text"), str):
        raise ValueError("VAL-004B WALK request must use the exact stateless text schema")


def _validate_stateless_claim_replay(authority: ModeNeutralClaimReplayAuthority) -> None:
    replay = authority.replay.authority
    source_execution = replay.plan.source.execution
    _require_stateless_text_request(source_execution.request)
    _require_stateless_text_request(replay.execution.request)
    if source_execution.request.arguments != replay.execution.request.arguments:
        raise ValueError("VAL-004B source and Replay stateless arguments differ")
