"""PERMIT-001 general attack ActionProposal predecessor authority."""

from __future__ import annotations

from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, JsonValue, ValidationError, field_validator, model_validator

from pajin.capabilities.models import (
    CapabilityDefinition,
    CapabilityDefinitionRef,
    CapabilityDefinitionRegistry,
    CapabilitySideEffectClass,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.hypothesis import (
    AttackHypothesis,
    AttackHypothesisSet,
    SurfaceBoundPlan,
    SurfaceBoundTask,
)
from pajin.domain.models import (
    CampaignManifest,
    StrictModel,
    Target,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.policy.scope import InvalidScopeURL, scope_matches

GENERAL_ATTACK_ACTION_PROPOSAL_API_VERSION: Literal[
    "pajin.dev/general-attack-action-proposal/v1alpha1"
] = "pajin.dev/general-attack-action-proposal/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_ARGUMENT_BYTES = 1024 * 1024
_MAX_PROPOSAL_BYTES = 4 * 1024 * 1024
_WRITE_SIDE_EFFECTS = frozenset(
    {
        CapabilitySideEffectClass.REVERSIBLE_WRITE,
        CapabilitySideEffectClass.IRREVERSIBLE_WRITE,
    }
)


class GeneralAttackActionProposalError(RuntimeError):
    """Raised when PERMIT-001 cannot bind an exact non-executable proposal."""


class GeneralAttackTargetRef(StrictModel):
    """Content-free reference to one exact Campaign Target."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    target_id: str = Field(alias="targetId", min_length=1, max_length=100)
    target_type: str = Field(alias="targetType", min_length=1, max_length=50)
    endpoint_digest: _Sha256 = Field(alias="endpointDigest")
    target_digest: str = Field(default="", alias="targetDigest", max_length=64)

    @model_validator(mode="after")
    def bind_target(self) -> Self:
        digest = _action_digest(
            "pajin.action.general-attack-target/v1",
            {
                "targetId": self.target_id,
                "targetType": self.target_type,
                "endpointDigest": self.endpoint_digest,
            },
        )
        if self.target_digest and self.target_digest != digest:
            raise ValueError("General attack Target Digest differs")
        object.__setattr__(self, "target_digest", digest)
        return self


class GeneralAttackExpectedEvidence(StrictModel):
    """Static evidence requirements copied only from a registered Capability definition."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_definition_digest: _Sha256 = Field(alias="sourceDefinitionDigest")
    evidence_types: tuple[_Identifier, ...] = Field(
        alias="evidenceTypes",
        min_length=1,
        max_length=100,
    )
    evidence_state: Literal["required-not-observed"] = Field(
        default="required-not-observed",
        alias="evidenceState",
    )
    success_oracle_bound: Literal[False] = Field(
        default=False,
        alias="successOracleBound",
    )

    @field_validator("success_oracle_bound", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def require_canonical_evidence(self) -> Self:
        if self.evidence_types != tuple(sorted(set(self.evidence_types))):
            raise ValueError("General attack expected evidence types must be unique and sorted")
        return self


class GeneralAttackCleanupRequirement(StrictModel):
    """Capability metadata only; no cleanup command, request, or Permit exists yet."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_definition_digest: _Sha256 = Field(alias="sourceDefinitionDigest")
    side_effect_class: CapabilitySideEffectClass = Field(alias="sideEffectClass")
    cleanup_required: bool = Field(alias="cleanupRequired")
    cleanup_state: Literal["metadata-only-not-planned"] = Field(
        default="metadata-only-not-planned",
        alias="cleanupState",
    )
    cleanup_handler_bound: Literal[False] = Field(
        default=False,
        alias="cleanupHandlerBound",
    )
    cleanup_plan_created: Literal[False] = Field(
        default=False,
        alias="cleanupPlanCreated",
    )
    cleanup_permit_issued: Literal[False] = Field(
        default=False,
        alias="cleanupPermitIssued",
    )

    @field_validator(
        "cleanup_required",
        "cleanup_handler_bound",
        "cleanup_plan_created",
        "cleanup_permit_issued",
        mode="before",
    )
    @classmethod
    def require_literal_booleans(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("General attack cleanup booleans must be literal")
        return value

    @model_validator(mode="after")
    def reject_unrecoverable_write_metadata(self) -> Self:
        if self.side_effect_class in _WRITE_SIDE_EFFECTS and not self.cleanup_required:
            raise ValueError("General attack write actions require cleanup metadata")
        return self


class GeneralAttackActionProposal(StrictModel):
    """Content-addressed action meaning with no executable authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/general-attack-action-proposal/v1alpha1"] = Field(
        default=GENERAL_ATTACK_ACTION_PROPOSAL_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["GeneralAttackActionProposal"] = "GeneralAttackActionProposal"
    proposal_id: str = Field(default="", alias="proposalId", max_length=110)
    proposal_digest: str = Field(default="", alias="proposalDigest", max_length=64)
    action_semantics_digest: str = Field(
        default="",
        alias="actionSemanticsDigest",
        max_length=64,
    )
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    surface_snapshot_id: str = Field(alias="surfaceSnapshotId", min_length=1, max_length=100)
    surface_snapshot_revision: int = Field(alias="surfaceSnapshotRevision", ge=1)
    surface_snapshot_digest: _Sha256 = Field(alias="surfaceSnapshotDigest")
    source_plan_id: str = Field(alias="sourcePlanId", min_length=1, max_length=100)
    source_plan_digest: _Sha256 = Field(alias="sourcePlanDigest")
    source_wave_plan_id: str = Field(alias="sourceWavePlanId", min_length=1, max_length=100)
    source_task_digest: _Sha256 = Field(alias="sourceTaskDigest")
    source_hypothesis_set_id: str = Field(
        alias="sourceHypothesisSetId",
        min_length=1,
        max_length=100,
    )
    source_hypothesis_id: str = Field(
        alias="sourceHypothesisId",
        min_length=1,
        max_length=100,
    )
    source_surface_id: str = Field(alias="sourceSurfaceId", min_length=1, max_length=100)
    action_definition: CapabilityDefinitionRef = Field(alias="actionDefinition")
    action_kind: _Identifier = Field(alias="actionKind")
    action_kind_version: _Identifier = Field(alias="actionKindVersion")
    action_kind_digest: _Sha256 = Field(alias="actionKindDigest")
    target: GeneralAttackTargetRef
    action_method: str = Field(
        alias="actionMethod",
        min_length=1,
        max_length=20,
        pattern=r"^[A-Z0-9!#$%&'*+.^_`|~-]+$",
    )
    arguments: dict[str, JsonValue]
    arguments_digest: str = Field(default="", alias="argumentsDigest", max_length=64)
    expected_evidence: GeneralAttackExpectedEvidence = Field(alias="expectedEvidence")
    cleanup: GeneralAttackCleanupRequirement
    risk_tier: ToolRiskTier = Field(alias="riskTier")
    proposal_state: Literal["proposed-not-compiled"] = Field(
        default="proposed-not-compiled",
        alias="proposalState",
    )
    supervisor_action_fields_authoritative: Literal[False] = Field(
        default=False,
        alias="supervisorActionFieldsAuthoritative",
    )
    action_compiler_applied: Literal[False] = Field(
        default=False,
        alias="actionCompilerApplied",
    )
    tool_request_compiled: Literal[False] = Field(
        default=False,
        alias="toolRequestCompiled",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )

    @field_validator("surface_snapshot_revision", mode="before")
    @classmethod
    def require_literal_revision(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("General attack Snapshot revision must be a JSON integer")
        return value

    @field_validator("risk_tier", mode="before")
    @classmethod
    def parse_strict_risk_tier(cls, value: object) -> ToolRiskTier:
        if isinstance(value, ToolRiskTier):
            return value
        if type(value) is not int:
            raise ValueError("General attack risk tier must be a canonical JSON integer")
        return ToolRiskTier(value)

    @field_validator("action_method", mode="before")
    @classmethod
    def require_canonical_method(cls, value: object) -> object:
        if type(value) is not str or value != value.upper():
            raise ValueError("General attack method must be a canonical uppercase string")
        return value

    @field_validator("arguments", mode="before")
    @classmethod
    def require_bounded_arguments(cls, value: object) -> object:
        if type(value) is not dict:
            raise ValueError("General attack arguments must be a JSON object")
        if any(type(key) is not str for key in value):
            raise ValueError("General attack argument keys must be strings")
        canonical_json_bytes(
            value,
            label="General attack arguments",
            max_bytes=_MAX_ARGUMENT_BYTES,
        )
        return value

    @field_validator(
        "supervisor_action_fields_authoritative",
        "action_compiler_applied",
        "tool_request_compiled",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "scope_expansion_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_proposal(self) -> Self:
        if self.source_plan_id != _surface_bound_plan_id(self.source_plan_digest):
            raise ValueError("General attack source Plan ID differs from its Digest")
        if (
            self.action_kind != self.action_definition.capability_id
            or self.action_kind_version != self.action_definition.capability_version
            or self.action_kind_digest != self.action_definition.capability_digest
            or self.expected_evidence.source_definition_digest != self.action_kind_digest
            or self.cleanup.source_definition_digest != self.action_kind_digest
        ):
            raise ValueError("General attack semantics differ from Action definition lineage")
        arguments_digest = _action_digest(
            "pajin.action.general-attack-arguments/v1",
            self.arguments,
        )
        if self.arguments_digest and self.arguments_digest != arguments_digest:
            raise ValueError("General attack Arguments Digest differs")
        object.__setattr__(self, "arguments_digest", arguments_digest)
        semantics_material = {
            "actionDefinition": self.action_definition.model_dump(mode="json", by_alias=True),
            "actionKind": self.action_kind,
            "actionKindVersion": self.action_kind_version,
            "actionKindDigest": self.action_kind_digest,
            "target": self.target.model_dump(mode="json", by_alias=True),
            "actionMethod": self.action_method,
            "arguments": self.arguments,
            "argumentsDigest": arguments_digest,
            "expectedEvidence": self.expected_evidence.model_dump(mode="json", by_alias=True),
            "cleanup": self.cleanup.model_dump(mode="json", by_alias=True),
            "riskTier": self.risk_tier.value,
        }
        semantics_digest = _action_digest(
            "pajin.action.general-attack-semantics/v1",
            semantics_material,
        )
        if self.action_semantics_digest and self.action_semantics_digest != semantics_digest:
            raise ValueError("General attack Action Semantics Digest differs")
        object.__setattr__(self, "action_semantics_digest", semantics_digest)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"proposal_id", "proposal_digest"},
        )
        digest = _action_digest("pajin.action.general-attack-proposal/v1", material)
        proposal_id = f"general-attack-action-proposal:{digest}"
        if self.proposal_digest and self.proposal_digest != digest:
            raise ValueError("General Attack Action Proposal Digest differs")
        if self.proposal_id and self.proposal_id != proposal_id:
            raise ValueError("General Attack Action Proposal ID differs")
        object.__setattr__(self, "proposal_digest", digest)
        object.__setattr__(self, "proposal_id", proposal_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="General Attack Action Proposal",
            max_bytes=_MAX_PROPOSAL_BYTES,
        )
        return self


def build_general_attack_action_proposal(
    campaign: CampaignManifest,
    hypothesis_set: AttackHypothesisSet,
    plan: SurfaceBoundPlan,
    task_digest: str,
    action_definition: CapabilityDefinitionRef,
    definitions: CapabilityDefinitionRegistry,
) -> GeneralAttackActionProposal:
    """Bind one exact ORCH task to registry metadata without compiling a ToolRequest."""

    try:
        canonical_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="json", by_alias=True)
        )
        canonical_hypotheses = AttackHypothesisSet.model_validate(
            hypothesis_set.model_dump(mode="json", by_alias=True)
        )
        canonical_plan = SurfaceBoundPlan.model_validate(
            plan.model_dump(mode="json", by_alias=True)
        )
        canonical_reference = CapabilityDefinitionRef.model_validate(
            action_definition.model_dump(mode="json", by_alias=True)
        )
        if not isinstance(definitions, CapabilityDefinitionRegistry):
            raise TypeError("General attack proposal requires a Capability Definition Registry")
        definition = definitions.resolve(canonical_reference)
        task, hypothesis, target = _verify_source_authorities(
            canonical_campaign,
            canonical_hypotheses,
            canonical_plan,
            task_digest,
            definition,
        )
        campaign_digest = campaign_manifest_digest(canonical_campaign)
        endpoint_digest = sha256(target.endpoint.encode("utf-8", errors="strict")).hexdigest()
        snapshot = canonical_plan.surface_snapshot
        request = task.step.request
        return GeneralAttackActionProposal(
            campaignId=canonical_campaign.metadata.name,
            campaignDigest=campaign_digest,
            surfaceSnapshotId=snapshot.snapshot_id,
            surfaceSnapshotRevision=snapshot.revision,
            surfaceSnapshotDigest=snapshot.snapshot_digest,
            sourcePlanId=_surface_bound_plan_id(canonical_plan.plan_digest),
            sourcePlanDigest=canonical_plan.plan_digest,
            sourceWavePlanId=canonical_plan.wave_plan_id,
            sourceTaskDigest=task.task_digest,
            sourceHypothesisSetId=canonical_hypotheses.hypothesis_set_id,
            sourceHypothesisId=hypothesis.hypothesis_id,
            sourceSurfaceId=hypothesis.surface_id,
            actionDefinition=definition.reference(),
            actionKind=definition.capability_id,
            actionKindVersion=definition.capability_version,
            actionKindDigest=definition.capability_digest,
            target=GeneralAttackTargetRef(
                targetId=target.id,
                targetType=target.type,
                endpointDigest=endpoint_digest,
            ),
            actionMethod=request.method,
            arguments=request.arguments,
            expectedEvidence=GeneralAttackExpectedEvidence(
                sourceDefinitionDigest=definition.capability_digest,
                evidenceTypes=definition.evidence_types,
            ),
            cleanup=GeneralAttackCleanupRequirement(
                sourceDefinitionDigest=definition.capability_digest,
                sideEffectClass=definition.side_effect_class,
                cleanupRequired=definition.cleanup_required,
            ),
            riskTier=definition.risk_tier,
        )
    except GeneralAttackActionProposalError:
        raise
    except (
        AttributeError,
        InvalidScopeURL,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise GeneralAttackActionProposalError(
            "General attack Action Proposal binding failed closed"
        ) from exc


def verify_general_attack_action_proposal(
    value: GeneralAttackActionProposal,
    campaign: CampaignManifest,
    hypothesis_set: AttackHypothesisSet,
    plan: SurfaceBoundPlan,
    task_digest: str,
    action_definition: CapabilityDefinitionRef,
    definitions: CapabilityDefinitionRegistry,
) -> GeneralAttackActionProposal:
    """Rebuild and exact-match PERMIT-001 against the caller's current authorities."""

    try:
        canonical = GeneralAttackActionProposal.model_validate(
            value.model_dump(mode="json", by_alias=True)
        )
        expected = build_general_attack_action_proposal(
            campaign,
            hypothesis_set,
            plan,
            task_digest,
            action_definition,
            definitions,
        )
        if canonical != expected:
            raise ValueError("General attack Action Proposal differs from current authorities")
        return canonical.model_copy(deep=True)
    except GeneralAttackActionProposalError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise GeneralAttackActionProposalError(
            "General attack Action Proposal verification failed closed"
        ) from exc


def _verify_source_authorities(
    campaign: CampaignManifest,
    hypothesis_set: AttackHypothesisSet,
    plan: SurfaceBoundPlan,
    task_digest: str,
    definition: CapabilityDefinition,
) -> tuple[SurfaceBoundTask, AttackHypothesis, Target]:
    snapshot = plan.surface_snapshot
    if (
        snapshot.campaign != campaign.metadata.name
        or snapshot.campaign_digest != campaign_manifest_digest(campaign)
    ):
        raise ValueError("Surface Snapshot belongs to another Campaign")
    if (
        hypothesis_set.campaign != campaign.metadata.name
        or hypothesis_set.hypothesis_set_id != plan.hypothesis_set_id
        or hypothesis_set.source_projection_run_id != snapshot.projection_run_id
        or hypothesis_set.source_projection_root_digest != snapshot.projection_root_digest
        or hypothesis_set.source_surface_artifact_sha256 != snapshot.artifact_sha256
        or hypothesis_set.surface_set_id != snapshot.surface_set_id
    ):
        raise ValueError("Hypothesis Set differs from Surface Snapshot or Plan authority")
    tasks = tuple(item for item in plan.tasks if item.task_digest == task_digest)
    if len(tasks) != 1:
        raise ValueError("General attack source Task is absent or ambiguous")
    task = tasks[0]
    hypotheses = tuple(
        item for item in hypothesis_set.hypotheses if item.hypothesis_id == task.hypothesis_id
    )
    if len(hypotheses) != 1:
        raise ValueError("General attack source Hypothesis is absent or ambiguous")
    hypothesis = hypotheses[0]
    targets = tuple(item for item in campaign.spec.targets if item.id == hypothesis.target_id)
    if len(targets) != 1:
        raise ValueError("General attack Campaign Target is absent or ambiguous")
    target = targets[0]
    request = task.step.request
    if (
        task.surface_id != hypothesis.surface_id
        or request.target != target.endpoint
        or request.tool_id != hypothesis.required_tool_id
        or definition.tool.tool_id != request.tool_id
        or definition.tool.tool_version != hypothesis.required_tool_version
        or definition.risk_tier != hypothesis.risk_tier
        or definition.domain != campaign.spec.mode.value
        or target.type not in definition.supported_surface_types
        or hypothesis.threat_class not in definition.threat_classes
        or request.method not in campaign.spec.rules_of_engagement.allowed_methods
        or definition.risk_tier > campaign.spec.rules_of_engagement.max_tool_risk_tier
    ):
        raise ValueError("General attack semantics differ from Plan, Campaign, or definition")
    if campaign.spec.threat_classes and hypothesis.threat_class not in campaign.spec.threat_classes:
        raise ValueError("General attack threat class is outside the Campaign")
    if any(scope_matches(rule, target.endpoint) for rule in campaign.spec.scope.deny):
        raise ValueError("General attack Target matches a Campaign deny rule")
    if not any(scope_matches(rule, target.endpoint) for rule in campaign.spec.scope.allow):
        raise ValueError("General attack Target is outside Campaign allow Scope")
    if definition.side_effect_class in _WRITE_SIDE_EFFECTS and not definition.cleanup_required:
        raise ValueError("General attack write definition has no cleanup requirement")
    return task, hypothesis, target


def _action_digest(domain: str, value: object) -> str:
    canonical_json_bytes(
        value,
        label="General attack Action authority",
        max_bytes=_MAX_PROPOSAL_BYTES,
    )
    return discovery_digest(domain, value)


def _surface_bound_plan_id(plan_digest: str) -> str:
    return f"surface-bound-plan:{plan_digest}"


def _require_literal_bool(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError("General attack authority boolean must be literal and exact")
    return expected
