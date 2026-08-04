"""Deterministic, non-executable Supervisor proposal compiler for SUP-003."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.snapshots import CollaborationSnapshot, SharedArtifactSource
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.discovery.walking_shadow import walking_shadow_supervisor_policy
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.graph.projection import GraphSnapshotStore
from pajin.providers.models import ProviderRegistration
from pajin.supervision.model_binding import (
    SUPERVISOR_SHADOW_PROPOSAL_DRAFT_API_VERSION,
    SupervisorModelBinding,
    SupervisorModelConfiguration,
    SupervisorShadowProposalDraft,
    SupervisorShadowProposalKind,
)
from pajin.supervision.snapshot_input import (
    SUPERVISOR_SNAPSHOT_INPUT_API_VERSION,
    SupervisorSnapshotInput,
    SupervisorSnapshotInputError,
    verify_supervisor_snapshot_input,
)

SUPERVISOR_TYPED_PROPOSAL_API_VERSION: Literal["pajin.dev/supervisor-typed-proposal/v1alpha1"] = (
    "pajin.dev/supervisor-typed-proposal/v1alpha1"
)

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_COMPONENT_BYTES = 4 * 1024 * 1024
_MAX_PROPOSAL_BYTES = 1024 * 1024
_ALLOWED_PROPOSAL_KINDS = (
    SupervisorShadowProposalKind.TASK,
    SupervisorShadowProposalKind.REPLAN,
    SupervisorShadowProposalKind.STOP,
    SupervisorShadowProposalKind.ESCALATE,
)


class SupervisorProposalCompilerError(RuntimeError):
    """Raised when a model draft cannot become an exact non-executable proposal."""


class SupervisorProposalCompilationPolicy(StrictModel):
    """Code-owned policy for compiling the first SUP-002 projection safely."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    policy_id: Literal["pajin.supervision.shadow-proposal-compiler.v1"] = Field(
        default="pajin.supervision.shadow-proposal-compiler.v1",
        alias="policyId",
    )
    policy_version: Literal["1.0.0"] = Field(default="1.0.0", alias="policyVersion")
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    source_input_schema_id: Literal["pajin.dev/supervisor-snapshot-input/v1alpha1"] = Field(
        default=SUPERVISOR_SNAPSHOT_INPUT_API_VERSION,
        alias="sourceInputSchemaId",
    )
    source_input_schema_digest: _Sha256 = Field(alias="sourceInputSchemaDigest")
    source_draft_schema_id: Literal["pajin.dev/supervisor-shadow-proposal-draft/v1alpha1"] = Field(
        default=SUPERVISOR_SHADOW_PROPOSAL_DRAFT_API_VERSION,
        alias="sourceDraftSchemaId",
    )
    source_draft_schema_digest: _Sha256 = Field(alias="sourceDraftSchemaDigest")
    output_schema_id: Literal["pajin.dev/supervisor-typed-proposal/v1alpha1"] = Field(
        default=SUPERVISOR_TYPED_PROPOSAL_API_VERSION,
        alias="outputSchemaId",
    )
    output_schema_digest: _Sha256 = Field(alias="outputSchemaDigest")
    shadow_policy_id: Literal["pajin.walk.shadow-supervisor.still-vulnerable.v1"] = Field(
        default="pajin.walk.shadow-supervisor.still-vulnerable.v1",
        alias="shadowPolicyId",
    )
    shadow_policy_digest: _Sha256 = Field(alias="shadowPolicyDigest")
    policy_state: Literal["current-collaboration-shadow"] = Field(
        default="current-collaboration-shadow",
        alias="policyState",
    )
    required_input_state: Literal["snapshot-projected-not-invoked"] = Field(
        default="snapshot-projected-not-invoked",
        alias="requiredInputState",
    )
    required_binding_state: Literal["shadow-model-bound-not-invocable"] = Field(
        default="shadow-model-bound-not-invocable",
        alias="requiredBindingState",
    )
    allowed_proposal_kinds: tuple[SupervisorShadowProposalKind, ...] = Field(
        default=_ALLOWED_PROPOSAL_KINDS,
        alias="allowedProposalKinds",
        min_length=4,
        max_length=4,
    )
    output_state: Literal["compiled-not-authorized"] = Field(
        default="compiled-not-authorized",
        alias="outputState",
    )
    rationale_authoritative: Literal[False] = Field(
        default=False,
        alias="rationaleAuthoritative",
    )
    model_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="modelInvocationAuthorized",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    activation_eligible: Literal[False] = Field(default=False, alias="activationEligible")

    @field_validator(
        "rationale_authoritative",
        "model_invocation_authorized",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "activation_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_policy(self) -> Self:
        expected_schema_digest = _snapshot_input_schema_digest()
        expected_draft_schema_digest = _draft_schema_digest()
        expected_output_schema_digest = _typed_proposal_schema_digest()
        shadow_policy = walking_shadow_supervisor_policy()
        if (
            self.source_input_schema_digest != expected_schema_digest
            or self.source_draft_schema_digest != expected_draft_schema_digest
            or self.output_schema_digest != expected_output_schema_digest
            or self.shadow_policy_id != shadow_policy.policy_id
            or self.shadow_policy_digest != shadow_policy.policy_digest
            or self.allowed_proposal_kinds != _ALLOWED_PROPOSAL_KINDS
        ):
            raise ValueError("Supervisor proposal policy differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_digest"},
        )
        digest = _proposal_digest(
            "pajin.supervision.proposal-compilation-policy/v1",
            material,
        )
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Supervisor Proposal Policy Digest differs")
        object.__setattr__(self, "policy_digest", digest)
        return self


class _SupervisorCompiledProposalBase(StrictModel):
    """Common false-authority markers for every typed proposal."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    proposal_state: Literal["proposed-not-authorized"] = Field(
        default="proposed-not-authorized",
        alias="proposalState",
    )
    instruction_authorized: Literal[False] = Field(
        default=False,
        alias="instructionAuthorized",
    )
    task_graph_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="taskGraphMutationAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "instruction_authorized",
        "task_graph_mutation_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)


class SupervisorTaskProposal(_SupervisorCompiledProposalBase):
    """Human-review Task request that cannot be scheduled or delegated."""

    kind: Literal["task"] = "task"
    task_kind: Literal["human-supervisor-review"] = Field(
        default="human-supervisor-review",
        alias="taskKind",
    )
    assigned_role: Literal["human:supervisor-reviewer"] = Field(
        default="human:supervisor-reviewer",
        alias="assignedRole",
    )
    required_capabilities: tuple[str, ...] = Field(
        default=(),
        alias="requiredCapabilities",
        max_length=0,
    )
    scheduling_authorized: Literal[False] = Field(
        default=False,
        alias="schedulingAuthorized",
    )

    @field_validator("scheduling_authorized", mode="before")
    @classmethod
    def require_task_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)


class SupervisorReplanProposal(_SupervisorCompiledProposalBase):
    """Request for deterministic replan review without changing a Plan or Scope."""

    kind: Literal["replan"] = "replan"
    replan_mode: Literal["deterministic-review-only"] = Field(
        default="deterministic-review-only",
        alias="replanMode",
    )
    scope_expansion_allowed: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAllowed",
    )
    plan_mutation_applied: Literal[False] = Field(
        default=False,
        alias="planMutationApplied",
    )
    scheduling_authorized: Literal[False] = Field(
        default=False,
        alias="schedulingAuthorized",
    )

    @field_validator(
        "scope_expansion_allowed",
        "plan_mutation_applied",
        "scheduling_authorized",
        mode="before",
    )
    @classmethod
    def require_replan_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)


class SupervisorStopProposal(_SupervisorCompiledProposalBase):
    """Advisory stop request that does not revoke or interrupt execution."""

    kind: Literal["stop"] = "stop"
    action: Literal["recommend-stop-autonomous-execution"] = "recommend-stop-autonomous-execution"
    permit_revocation_applied: Literal[False] = Field(
        default=False,
        alias="permitRevocationApplied",
    )
    execution_interrupted: Literal[False] = Field(
        default=False,
        alias="executionInterrupted",
    )

    @field_validator(
        "permit_revocation_applied",
        "execution_interrupted",
        mode="before",
    )
    @classmethod
    def require_stop_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)


class SupervisorEscalationProposal(_SupervisorCompiledProposalBase):
    """Human escalation request that sends no notification and grants no approval."""

    kind: Literal["escalate"] = "escalate"
    escalation_target: Literal["human:supervisor-reviewer"] = Field(
        default="human:supervisor-reviewer",
        alias="escalationTarget",
    )
    notification_dispatched: Literal[False] = Field(
        default=False,
        alias="notificationDispatched",
    )
    approval_granted: Literal[False] = Field(default=False, alias="approvalGranted")

    @field_validator("notification_dispatched", "approval_granted", mode="before")
    @classmethod
    def require_escalation_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)


SupervisorCompiledProposal = Annotated[
    SupervisorTaskProposal
    | SupervisorReplanProposal
    | SupervisorStopProposal
    | SupervisorEscalationProposal,
    Field(discriminator="kind"),
]


class SupervisorTypedProposal(StrictModel):
    """Content-addressed audit proposal with no model text or executable authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-typed-proposal/v1alpha1"] = Field(
        default=SUPERVISOR_TYPED_PROPOSAL_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorTypedProposal"] = "SupervisorTypedProposal"
    proposal_id: str = Field(default="", alias="proposalId", max_length=110)
    proposal_digest: str = Field(default="", alias="proposalDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    compilation_policy: SupervisorProposalCompilationPolicy = Field(alias="compilationPolicy")
    compilation_policy_digest: _Sha256 = Field(alias="compilationPolicyDigest")
    shadow_policy_digest: _Sha256 = Field(alias="shadowPolicyDigest")
    model_binding_id: str = Field(alias="modelBindingId", min_length=1, max_length=110)
    model_binding_digest: _Sha256 = Field(alias="modelBindingDigest")
    snapshot_input_id: str = Field(alias="snapshotInputId", min_length=1, max_length=110)
    snapshot_input_digest: _Sha256 = Field(alias="snapshotInputDigest")
    source_snapshot_id: str = Field(alias="sourceSnapshotId", min_length=1, max_length=110)
    source_snapshot_digest: _Sha256 = Field(alias="sourceSnapshotDigest")
    source_input_schema_digest: _Sha256 = Field(alias="sourceInputSchemaDigest")
    taint_digest: _Sha256 = Field(alias="taintDigest")
    source_draft_digest: _Sha256 = Field(alias="sourceDraftDigest")
    source_proposal_kind: SupervisorShadowProposalKind = Field(alias="sourceProposalKind")
    rationale_digest: _Sha256 = Field(alias="rationaleDigest")
    rationale_bytes: int = Field(alias="rationaleBytes", ge=1, le=20_000)
    rationale_content_embedded: Literal[False] = Field(
        default=False,
        alias="rationaleContentEmbedded",
    )
    proposal: SupervisorCompiledProposal
    compilation_state: Literal["compiled-not-authorized"] = Field(
        default="compiled-not-authorized",
        alias="compilationState",
    )
    model_rationale_authoritative: Literal[False] = Field(
        default=False,
        alias="modelRationaleAuthoritative",
    )
    provider_response_verified: Literal[False] = Field(
        default=False,
        alias="providerResponseVerified",
    )
    model_output_attested: Literal[False] = Field(
        default=False,
        alias="modelOutputAttested",
    )
    baseline_mutated: Literal[False] = Field(default=False, alias="baselineMutated")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    scheduling_authorized: Literal[False] = Field(
        default=False,
        alias="schedulingAuthorized",
    )
    model_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="modelInvocationAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    activation_eligible: Literal[False] = Field(default=False, alias="activationEligible")

    @field_validator("rationale_bytes", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Supervisor proposal byte count must be an integer")
        return value

    @field_validator(
        "rationale_content_embedded",
        "model_rationale_authoritative",
        "provider_response_verified",
        "model_output_attested",
        "baseline_mutated",
        "scope_expansion_authorized",
        "scheduling_authorized",
        "model_invocation_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "activation_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_proposal(self) -> Self:
        expected_policy = registered_supervisor_proposal_compilation_policy()
        expected_proposal = _typed_proposal(self.source_proposal_kind)
        if (
            self.compilation_policy != expected_policy
            or self.compilation_policy_digest != expected_policy.policy_digest
            or self.source_input_schema_digest != expected_policy.source_input_schema_digest
            or self.shadow_policy_digest != expected_policy.shadow_policy_digest
            or self.source_proposal_kind not in expected_policy.allowed_proposal_kinds
            or self.proposal != expected_proposal
        ):
            raise ValueError("Supervisor typed proposal differs from compiler authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"proposal_id", "proposal_digest"},
        )
        digest = _proposal_digest("pajin.supervision.typed-proposal/v1", material)
        proposal_id = f"supervisor-typed-proposal:{digest}"
        if self.proposal_digest and self.proposal_digest != digest:
            raise ValueError("Supervisor Typed Proposal Digest differs")
        if self.proposal_id and self.proposal_id != proposal_id:
            raise ValueError("Supervisor Typed Proposal ID differs")
        object.__setattr__(self, "proposal_digest", digest)
        object.__setattr__(self, "proposal_id", proposal_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Supervisor typed proposal",
            max_bytes=_MAX_PROPOSAL_BYTES,
        )
        return self


def registered_supervisor_proposal_compilation_policy() -> SupervisorProposalCompilationPolicy:
    """Return the single code-owned SUP-003 compilation policy."""

    return SupervisorProposalCompilationPolicy(
        sourceInputSchemaDigest=_snapshot_input_schema_digest(),
        sourceDraftSchemaDigest=_draft_schema_digest(),
        outputSchemaDigest=_typed_proposal_schema_digest(),
        shadowPolicyDigest=walking_shadow_supervisor_policy().policy_digest,
    )


def compile_supervisor_shadow_proposal(
    snapshot_input: SupervisorSnapshotInput,
    draft: SupervisorShadowProposalDraft,
    binding: SupervisorModelBinding,
    campaign: CampaignManifest,
    provider_registration: ProviderRegistration,
    *,
    model_revision: str,
    configuration: SupervisorModelConfiguration,
    collaboration_snapshot: CollaborationSnapshot,
    graph_snapshot_store: GraphSnapshotStore,
    shared_artifact_sources: Iterable[SharedArtifactSource] = (),
) -> SupervisorTypedProposal:
    """Compile an exact untrusted draft into a content-free advisory proposal."""

    try:
        verified_input = verify_supervisor_snapshot_input(
            snapshot_input,
            binding,
            campaign,
            provider_registration,
            model_revision=model_revision,
            configuration=configuration,
            collaboration_snapshot=collaboration_snapshot,
            graph_snapshot_store=graph_snapshot_store,
            shared_artifact_sources=shared_artifact_sources,
        )
        canonical_draft = SupervisorShadowProposalDraft.model_validate(
            draft.model_dump(mode="json", by_alias=True)
        )
        if (
            canonical_draft.snapshot_id != verified_input.source_snapshot_id
            or canonical_draft.snapshot_digest != verified_input.source_snapshot_digest
        ):
            raise ValueError("Supervisor draft refers to another Snapshot")
        policy = registered_supervisor_proposal_compilation_policy()
        if (
            verified_input.input_state != policy.required_input_state
            or verified_input.model_binding.binding_state != policy.required_binding_state
            or canonical_draft.proposal_kind not in policy.allowed_proposal_kinds
        ):
            raise ValueError("Supervisor draft kind is not allowed for current state")
        rationale_bytes = canonical_draft.rationale.encode("utf-8", errors="strict")
        return SupervisorTypedProposal(
            campaignDigest=verified_input.campaign_digest,
            compilationPolicy=policy,
            compilationPolicyDigest=policy.policy_digest,
            shadowPolicyDigest=verified_input.model_binding.walking_shadow_policy_digest,
            modelBindingId=verified_input.model_binding.binding_id,
            modelBindingDigest=verified_input.model_binding_digest,
            snapshotInputId=verified_input.input_id,
            snapshotInputDigest=verified_input.input_digest,
            sourceSnapshotId=verified_input.source_snapshot_id,
            sourceSnapshotDigest=verified_input.source_snapshot_digest,
            sourceInputSchemaDigest=policy.source_input_schema_digest,
            taintDigest=_taint_digest(verified_input),
            sourceDraftDigest=_draft_digest(canonical_draft),
            sourceProposalKind=canonical_draft.proposal_kind,
            rationaleDigest=sha256(rationale_bytes).hexdigest(),
            rationaleBytes=len(rationale_bytes),
            proposal=_typed_proposal(canonical_draft.proposal_kind),
        )
    except (
        AttributeError,
        SupervisorSnapshotInputError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorProposalCompilerError(
            "Supervisor proposal compilation failed closed"
        ) from exc


def verify_supervisor_typed_proposal(
    value: SupervisorTypedProposal,
    snapshot_input: SupervisorSnapshotInput,
    draft: SupervisorShadowProposalDraft,
    binding: SupervisorModelBinding,
    campaign: CampaignManifest,
    provider_registration: ProviderRegistration,
    *,
    model_revision: str,
    configuration: SupervisorModelConfiguration,
    collaboration_snapshot: CollaborationSnapshot,
    graph_snapshot_store: GraphSnapshotStore,
    shared_artifact_sources: Iterable[SharedArtifactSource] = (),
) -> SupervisorTypedProposal:
    """Rebuild and exact-match one SUP-003 proposal against current authorities."""

    try:
        canonical = SupervisorTypedProposal.model_validate(
            value.model_dump(mode="json", by_alias=True)
        )
        expected = compile_supervisor_shadow_proposal(
            snapshot_input,
            draft,
            binding,
            campaign,
            provider_registration,
            model_revision=model_revision,
            configuration=configuration,
            collaboration_snapshot=collaboration_snapshot,
            graph_snapshot_store=graph_snapshot_store,
            shared_artifact_sources=shared_artifact_sources,
        )
        if canonical != expected:
            raise ValueError("Supervisor typed proposal differs from current authority")
        return canonical.model_copy(deep=True)
    except (
        AttributeError,
        SupervisorProposalCompilerError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorProposalCompilerError(
            "Supervisor typed proposal verification failed closed"
        ) from exc


def _typed_proposal(
    kind: SupervisorShadowProposalKind,
) -> SupervisorCompiledProposal:
    if kind is SupervisorShadowProposalKind.TASK:
        return SupervisorTaskProposal()
    if kind is SupervisorShadowProposalKind.REPLAN:
        return SupervisorReplanProposal()
    if kind is SupervisorShadowProposalKind.STOP:
        return SupervisorStopProposal()
    if kind is SupervisorShadowProposalKind.ESCALATE:
        return SupervisorEscalationProposal()
    raise ValueError("Supervisor proposal kind is not registered")


def _snapshot_input_schema_digest() -> str:
    schema = SupervisorSnapshotInput.model_json_schema(mode="validation", by_alias=True)
    return _proposal_digest(
        "pajin.supervision.schema/supervisor-snapshot-input/v1",
        schema,
    )


def _draft_digest(draft: SupervisorShadowProposalDraft) -> str:
    return _proposal_digest(
        "pajin.supervision.shadow-proposal-draft/v1",
        draft.model_dump(mode="json", by_alias=True),
    )


def _draft_schema_digest() -> str:
    schema = SupervisorShadowProposalDraft.model_json_schema(
        mode="validation",
        by_alias=True,
    )
    return _proposal_digest(
        "pajin.supervision.schema/shadow-proposal-draft/v1",
        schema,
    )


def _typed_proposal_schema_digest() -> str:
    schema = SupervisorTypedProposal.model_json_schema(mode="validation", by_alias=True)
    return _proposal_digest(
        "pajin.supervision.schema/supervisor-typed-proposal/v1",
        schema,
    )


def _taint_digest(snapshot_input: SupervisorSnapshotInput) -> str:
    material = {
        "snapshotInputId": snapshot_input.input_id,
        "snapshotInputDigest": snapshot_input.input_digest,
        "targetTaintComplete": snapshot_input.target_taint_complete,
        "modelVisibleText": [
            item.model_dump(
                mode="json",
                by_alias=True,
                exclude={"text"},
            )
            for item in snapshot_input.model_visible_text
        ],
        "safeReferences": [
            item.model_dump(mode="json", by_alias=True) for item in snapshot_input.safe_references
        ],
    }
    return _proposal_digest("pajin.supervision.snapshot-taint/v1", material)


def _proposal_digest(domain: str, value: object) -> str:
    encoded = canonical_json_bytes(
        value,
        label="Supervisor proposal authority",
        max_bytes=_MAX_COMPONENT_BYTES,
    )
    return sha256(domain.encode("ascii", errors="strict") + b"\x00" + encoded).hexdigest()


def _require_literal_bool(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError("Supervisor proposal boolean must be literal and exact")
    return expected
