"""Proposal-only Skill qualification, deterministic selection, and instruction projection.

This module never selects targets or performs actions.  A caller supplies an exact installed
registry plus a code-owned policy.  Selection is a metadata intersection and the resulting
instruction projection remains inert input for a later, separately versioned model boundary.
"""

from __future__ import annotations

from collections.abc import Sequence
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import StrictModel
from pajin.domain.orchestration import AgentRole
from pajin.domain.security_domain import (
    SecurityDomainClassificationRef,
    resolve_registered_security_domain,
)
from pajin.skills.models import (
    RegisteredSkill,
    SkillDefinitionError,
    SkillDefinitionRef,
    SkillDefinitionRegistry,
    SkillLifecycleStage,
    SkillRegistryRef,
    canonical_skill_contract,
    canonical_skill_json,
    skill_definition_digest,
)

PROPOSAL_ONLY_SKILL_QUALIFICATION_API_VERSION: Literal[
    "pajin.dev/proposal-only-skill-qualification/v1alpha1"
] = "pajin.dev/proposal-only-skill-qualification/v1alpha1"
ANALYSIS_SKILL_SELECTION_POLICY_API_VERSION: Literal[
    "pajin.dev/analysis-skill-selection-policy/v1alpha1"
] = "pajin.dev/analysis-skill-selection-policy/v1alpha1"
ANALYSIS_SKILL_SELECTION_RECEIPT_API_VERSION: Literal[
    "pajin.dev/analysis-skill-selection-receipt/v1alpha1"
] = "pajin.dev/analysis-skill-selection-receipt/v1alpha1"
ANALYSIS_SKILL_INSTRUCTION_PROJECTION_API_VERSION: Literal[
    "pajin.dev/analysis-skill-instruction-projection/v1alpha1"
] = "pajin.dev/analysis-skill-instruction-projection/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Instruction = Annotated[str, Field(min_length=1, max_length=2_000)]
_MAX_PROJECTION_BYTES = 64 * 1024


class SkillSelectionError(ValueError):
    """Raised when proposal qualification, selection, or projection fails closed."""


def _literal_false(value: object) -> Literal[False]:
    if type(value) is not bool or value is not False:
        raise ValueError("Skill selection authority markers must be literal false")
    return False


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("Skill selection trust-boundary markers must be literal true")
    return True


def _canonical_strings(value: Sequence[str], *, label: str) -> tuple[str, ...]:
    canonical = tuple(value)
    if canonical != tuple(sorted(set(canonical))):
        raise ValueError(f"{label} must be unique and sorted")
    return canonical


def _reference_key(reference: SkillDefinitionRef) -> tuple[str, str]:
    return reference.skill_id, reference.skill_version


class ProposalOnlySkillQualificationBinding(StrictModel):
    """Exact catalogued predecessor and proposal-only successor identity."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    predecessor: SkillDefinitionRef
    qualified: SkillDefinitionRef
    transition: Literal["catalogued-to-proposal-only"] = "catalogued-to-proposal-only"
    instruction_semantics_changed: Literal[False] = Field(
        default=False,
        alias="instructionSemanticsChanged",
    )
    schema_identity_changed: Literal[False] = Field(
        default=False,
        alias="schemaIdentityChanged",
    )

    @field_validator("instruction_semantics_changed", "schema_identity_changed", mode="before")
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if self.predecessor.skill_id != self.qualified.skill_id:
            raise ValueError("Skill qualification cannot change the Skill ID")
        if self.predecessor.skill_version == self.qualified.skill_version:
            raise ValueError("Skill qualification requires a new exact Skill version")
        return self


class ProposalOnlySkillQualificationSet(StrictModel):
    """Code-owned evidence that exact catalogued content may enter proposal projection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/proposal-only-skill-qualification/v1alpha1"] = Field(
        default=PROPOSAL_ONLY_SKILL_QUALIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ProposalOnlySkillQualificationSet"] = "ProposalOnlySkillQualificationSet"
    qualification_id: str = Field(default="", alias="qualificationId", max_length=110)
    qualification_digest: str = Field(default="", alias="qualificationDigest", max_length=64)
    predecessor_registry: SkillRegistryRef = Field(alias="predecessorRegistry")
    qualified_registry: SkillRegistryRef = Field(alias="qualifiedRegistry")
    bindings: tuple[ProposalOnlySkillQualificationBinding, ...] = Field(
        min_length=1,
        max_length=32,
    )
    qualification_profile: Literal["pajin.analysis-skill.proposal-only-semantic-equivalence/v1"] = (
        Field(alias="qualificationProfile")
    )
    selection_policy_schema_digest: _Sha256 = Field(alias="selectionPolicySchemaDigest")
    instruction_projection_schema_digest: _Sha256 = Field(alias="instructionProjectionSchemaDigest")
    qualification_state: Literal["reviewed-content-equivalent-proposal-only"] = Field(
        alias="qualificationState"
    )
    target_neutrality_required: Literal[True] = Field(alias="targetNeutralityRequired")
    selected_only_projection_required: Literal[True] = Field(alias="selectedOnlyProjectionRequired")
    recipe_binding_qualified: Literal[False] = Field(alias="recipeBindingQualified")
    lab_execution_qualified: Literal[False] = Field(alias="labExecutionQualified")
    independent_validation_qualified: Literal[False] = Field(alias="independentValidationQualified")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    target_selection_authority: Literal[False] = Field(alias="targetSelectionAuthority")
    tool_request_authority: Literal[False] = Field(alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    execution_authority: Literal[False] = Field(alias="executionAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    report_delivery_authority: Literal[False] = Field(alias="reportDeliveryAuthority")

    @field_validator(
        "target_neutrality_required", "selected_only_projection_required", mode="before"
    )
    @classmethod
    def require_true_markers(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator(
        "recipe_binding_qualified",
        "lab_execution_qualified",
        "independent_validation_qualified",
        "scope_expansion_authority",
        "target_selection_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        "graph_admission_authority",
        "finding_authority",
        "report_delivery_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @model_validator(mode="after")
    def bind_qualification(self) -> Self:
        keys = tuple(_reference_key(item.predecessor) for item in self.bindings)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("Skill qualification bindings must be unique and sorted")
        if self.predecessor_registry == self.qualified_registry:
            raise ValueError("Skill qualification requires a distinct successor registry")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"qualification_id", "qualification_digest"},
        )
        digest = skill_definition_digest(
            "pajin.analysis-skill.proposal-only-qualification/v1",
            material,
        )
        qualification_id = f"proposal-skill-qualification:{digest}"
        if self.qualification_digest and self.qualification_digest != digest:
            raise ValueError("Skill qualification digest differs")
        if self.qualification_id and self.qualification_id != qualification_id:
            raise ValueError("Skill qualification ID differs")
        object.__setattr__(self, "qualification_digest", digest)
        object.__setattr__(self, "qualification_id", qualification_id)
        return self


class AnalysisSkillSelectionPolicy(StrictModel):
    """Exact allowlist and metadata context for one deterministic selection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/analysis-skill-selection-policy/v1alpha1"] = Field(
        default=ANALYSIS_SKILL_SELECTION_POLICY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AnalysisSkillSelectionPolicy"] = "AnalysisSkillSelectionPolicy"
    policy_id: str = Field(default="", alias="policyId", max_length=110)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    registry: SkillRegistryRef
    qualification_id: str = Field(alias="qualificationId", min_length=1, max_length=110)
    qualification_digest: _Sha256 = Field(alias="qualificationDigest")
    allowed_skill_refs: tuple[SkillDefinitionRef, ...] = Field(
        alias="allowedSkillRefs",
        min_length=1,
        max_length=32,
    )
    agent_role: AgentRole = Field(alias="agentRole")
    domain_classification: SecurityDomainClassificationRef = Field(alias="domainClassification")
    surface_type: _Identifier = Field(alias="surfaceType")
    allowed_hypothesis_ids: tuple[_Identifier, ...] = Field(
        alias="allowedHypothesisIds",
        min_length=1,
        max_length=100,
    )
    max_selected_skills: int = Field(alias="maxSelectedSkills", strict=True, ge=1, le=32)
    max_projected_instruction_bytes: int = Field(
        alias="maxProjectedInstructionBytes",
        strict=True,
        ge=1,
        le=_MAX_PROJECTION_BYTES,
    )
    selection_basis: Literal["code-owned-metadata-intersection"] = Field(alias="selectionBasis")
    target_content_used_for_selection: Literal[False] = Field(alias="targetContentUsedForSelection")
    model_selected_skills: Literal[False] = Field(alias="modelSelectedSkills")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    recipe_binding_authority: Literal[False] = Field(alias="recipeBindingAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    execution_authority: Literal[False] = Field(alias="executionAuthority")

    @field_validator(
        "target_content_used_for_selection",
        "model_selected_skills",
        "scope_expansion_authority",
        "recipe_binding_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("max_selected_skills", "max_projected_instruction_bytes", mode="before")
    @classmethod
    def require_integer_budget(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Skill selection budgets must use JSON integers")
        return value

    @field_validator("allowed_hypothesis_ids")
    @classmethod
    def require_canonical_hypotheses(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_strings(value, label="Skill selection Hypothesis IDs")

    @model_validator(mode="after")
    def bind_policy(self) -> Self:
        resolve_registered_security_domain(self.domain_classification)
        reference_keys = tuple(_reference_key(item) for item in self.allowed_skill_refs)
        if reference_keys != tuple(sorted(set(reference_keys))):
            raise ValueError("Skill selection allowlist must be unique and sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = skill_definition_digest("pajin.analysis-skill.selection-policy/v1", material)
        policy_id = f"analysis-skill-selection-policy:{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Skill selection policy digest differs")
        if self.policy_id and self.policy_id != policy_id:
            raise ValueError("Skill selection policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", policy_id)
        return self


class AnalysisSkillSelectionReceipt(StrictModel):
    """Content-addressed result of one code-owned metadata intersection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/analysis-skill-selection-receipt/v1alpha1"] = Field(
        default=ANALYSIS_SKILL_SELECTION_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AnalysisSkillSelectionReceipt"] = "AnalysisSkillSelectionReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    registry: SkillRegistryRef
    qualification_id: str = Field(alias="qualificationId", min_length=1, max_length=110)
    qualification_digest: _Sha256 = Field(alias="qualificationDigest")
    policy_id: str = Field(alias="policyId", min_length=1, max_length=110)
    policy_digest: _Sha256 = Field(alias="policyDigest")
    considered_skill_count: int = Field(alias="consideredSkillCount", strict=True, ge=1, le=32)
    selected_skill_count: int = Field(alias="selectedSkillCount", strict=True, ge=1, le=32)
    selected_skill_refs: tuple[SkillDefinitionRef, ...] = Field(
        alias="selectedSkillRefs",
        min_length=1,
        max_length=32,
    )
    projected_instruction_bytes: int = Field(
        alias="projectedInstructionBytes",
        strict=True,
        ge=1,
        le=_MAX_PROJECTION_BYTES,
    )
    selection_state: Literal["selected-for-proposal-projection-not-authority"] = Field(
        alias="selectionState"
    )
    required_evidence_satisfaction_claimed: Literal[False] = Field(
        alias="requiredEvidenceSatisfactionClaimed"
    )
    target_content_used_for_selection: Literal[False] = Field(alias="targetContentUsedForSelection")
    model_selected_skills: Literal[False] = Field(alias="modelSelectedSkills")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    recipe_binding_authority: Literal[False] = Field(alias="recipeBindingAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    execution_authority: Literal[False] = Field(alias="executionAuthority")

    @field_validator(
        "required_evidence_satisfaction_claimed",
        "target_content_used_for_selection",
        "model_selected_skills",
        "scope_expansion_authority",
        "recipe_binding_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator(
        "considered_skill_count",
        "selected_skill_count",
        "projected_instruction_bytes",
        mode="before",
    )
    @classmethod
    def require_integer_counts(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Skill selection counts must use JSON integers")
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        reference_keys = tuple(_reference_key(item) for item in self.selected_skill_refs)
        if reference_keys != tuple(sorted(set(reference_keys))):
            raise ValueError("Selected Skill references must be unique and sorted")
        if self.selected_skill_count != len(self.selected_skill_refs):
            raise ValueError("Selected Skill count differs from the exact references")
        if self.selected_skill_count > self.considered_skill_count:
            raise ValueError("Selected Skill count exceeds considered Skills")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = skill_definition_digest("pajin.analysis-skill.selection-receipt/v1", material)
        receipt_id = f"analysis-skill-selection:{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Skill selection receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Skill selection receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


class ProjectedAnalysisSkill(StrictModel):
    """One exact selected Skill body, with requirements explicitly not satisfied here."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    skill_ref: SkillDefinitionRef = Field(alias="skillRef")
    lifecycle_stage: Literal["proposal-only"] = Field(alias="lifecycleStage")
    title: str = Field(min_length=1, max_length=200)
    objective: str = Field(min_length=1, max_length=2_000)
    workflow_steps: tuple[_Instruction, ...] = Field(
        alias="workflowSteps", min_length=1, max_length=32
    )
    evidence_requirements: tuple[_Instruction, ...] = Field(
        alias="evidenceRequirements",
        min_length=1,
        max_length=32,
    )
    false_positive_controls: tuple[_Instruction, ...] = Field(
        alias="falsePositiveControls",
        min_length=1,
        max_length=32,
    )
    safety_constraints: tuple[_Instruction, ...] = Field(
        alias="safetyConstraints",
        min_length=1,
        max_length=32,
    )
    applicable_hypothesis_ids: tuple[_Identifier, ...] = Field(
        alias="applicableHypothesisIds",
        min_length=1,
        max_length=100,
    )
    required_evidence_types: tuple[_Identifier, ...] = Field(
        alias="requiredEvidenceTypes",
        min_length=1,
        max_length=100,
    )
    required_evidence_satisfied: Literal[False] = Field(alias="requiredEvidenceSatisfied")
    target_content_is_untrusted: Literal[True] = Field(alias="targetContentIsUntrusted")
    ground_truth_embedded: Literal[False] = Field(alias="groundTruthEmbedded")
    secret_material_embedded: Literal[False] = Field(alias="secretMaterialEmbedded")
    action_material_embedded: Literal[False] = Field(alias="actionMaterialEmbedded")

    @field_validator("target_content_is_untrusted", mode="before")
    @classmethod
    def require_true_marker(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator(
        "required_evidence_satisfied",
        "ground_truth_embedded",
        "secret_material_embedded",
        "action_material_embedded",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("applicable_hypothesis_ids", "required_evidence_types")
    @classmethod
    def require_canonical_types(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return _canonical_strings(value, label="Projected Skill types")


class AnalysisSkillInstructionProjection(StrictModel):
    """Selected code-owned instructions for a future developer-message projection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/analysis-skill-instruction-projection/v1alpha1"] = Field(
        default=ANALYSIS_SKILL_INSTRUCTION_PROJECTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AnalysisSkillInstructionProjection"] = "AnalysisSkillInstructionProjection"
    projection_id: str = Field(default="", alias="projectionId", max_length=110)
    projection_digest: str = Field(default="", alias="projectionDigest", max_length=64)
    registry: SkillRegistryRef
    qualification_id: str = Field(alias="qualificationId", min_length=1, max_length=110)
    qualification_digest: _Sha256 = Field(alias="qualificationDigest")
    policy_id: str = Field(alias="policyId", min_length=1, max_length=110)
    policy_digest: _Sha256 = Field(alias="policyDigest")
    selection_receipt_id: str = Field(alias="selectionReceiptId", min_length=1, max_length=110)
    selection_receipt_digest: _Sha256 = Field(alias="selectionReceiptDigest")
    selected_skills: tuple[ProjectedAnalysisSkill, ...] = Field(
        alias="selectedSkills",
        min_length=1,
        max_length=32,
    )
    selected_skill_count: int = Field(alias="selectedSkillCount", strict=True, ge=1, le=32)
    projected_instruction_bytes: int = Field(
        alias="projectedInstructionBytes",
        strict=True,
        ge=1,
        le=_MAX_PROJECTION_BYTES,
    )
    projection_state: Literal["code-owned-selected-instructions-not-authority"] = Field(
        alias="projectionState"
    )
    developer_message_eligible: Literal[True] = Field(alias="developerMessageEligible")
    user_evidence_message_embedded: Literal[False] = Field(alias="userEvidenceMessageEmbedded")
    target_content_embedded: Literal[False] = Field(alias="targetContentEmbedded")
    scope_expansion_authority: Literal[False] = Field(alias="scopeExpansionAuthority")
    tool_request_authority: Literal[False] = Field(alias="toolRequestAuthority")
    capability_authority: Literal[False] = Field(alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(alias="permitAuthority")
    execution_authority: Literal[False] = Field(alias="executionAuthority")
    graph_admission_authority: Literal[False] = Field(alias="graphAdmissionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    report_delivery_authority: Literal[False] = Field(alias="reportDeliveryAuthority")

    @field_validator("developer_message_eligible", mode="before")
    @classmethod
    def require_true_marker(cls, value: object) -> Literal[True]:
        return _literal_true(value)

    @field_validator(
        "user_evidence_message_embedded",
        "target_content_embedded",
        "scope_expansion_authority",
        "tool_request_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        "graph_admission_authority",
        "finding_authority",
        "report_delivery_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> Literal[False]:
        return _literal_false(value)

    @field_validator("selected_skill_count", "projected_instruction_bytes", mode="before")
    @classmethod
    def require_integer_counts(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Skill projection counts must use JSON integers")
        return value

    @model_validator(mode="after")
    def bind_projection(self) -> Self:
        references = tuple(item.skill_ref for item in self.selected_skills)
        keys = tuple(_reference_key(item) for item in references)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("Projected Skills must be unique and sorted")
        if self.selected_skill_count != len(self.selected_skills):
            raise ValueError("Projected Skill count differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"projection_id", "projection_digest"},
        )
        digest = skill_definition_digest(
            "pajin.analysis-skill.instruction-projection/v1",
            material,
        )
        projection_id = f"analysis-skill-instructions:{digest}"
        if self.projection_digest and self.projection_digest != digest:
            raise ValueError("Skill instruction projection digest differs")
        if self.projection_id and self.projection_id != projection_id:
            raise ValueError("Skill instruction projection ID differs")
        object.__setattr__(self, "projection_digest", digest)
        object.__setattr__(self, "projection_id", projection_id)
        canonical_skill_json(
            self.model_dump(mode="json", by_alias=True),
            label="AnalysisSkillInstructionProjection",
        )
        return self


def qualify_proposal_only_skill_registry(
    *,
    predecessor_registry: SkillDefinitionRegistry,
    qualified_registry: SkillDefinitionRegistry,
) -> ProposalOnlySkillQualificationSet:
    """Bind exact semantically equivalent successors; never perform a generic stage mutation."""

    try:
        predecessor_registry = _require_installed_registry(predecessor_registry)
        qualified_registry = _require_installed_registry(qualified_registry)
        predecessor_by_id = {
            item.skill_id: predecessor_registry.resolve(item)
            for item in predecessor_registry.references()
        }
        qualified = tuple(
            qualified_registry.resolve(item)
            for item in qualified_registry.references()
            if qualified_registry.resolve(item).definition.lifecycle_stage
            is SkillLifecycleStage.PROPOSAL_ONLY
        )
        if not qualified:
            raise ValueError("qualified registry has no proposal-only Skill")
        bindings: list[ProposalOnlySkillQualificationBinding] = []
        for successor in qualified:
            predecessor = predecessor_by_id.get(successor.definition.skill_id)
            if predecessor is None:
                raise ValueError("proposal-only Skill has no exact catalogued predecessor")
            _require_proposal_successor(predecessor, successor)
            bindings.append(
                ProposalOnlySkillQualificationBinding(
                    predecessor=predecessor.definition.reference(),
                    qualified=successor.definition.reference(),
                    transition="catalogued-to-proposal-only",
                    instructionSemanticsChanged=False,
                    schemaIdentityChanged=False,
                )
            )
        return ProposalOnlySkillQualificationSet(
            qualificationId="",
            qualificationDigest="",
            predecessorRegistry=predecessor_registry.reference(),
            qualifiedRegistry=qualified_registry.reference(),
            bindings=tuple(sorted(bindings, key=lambda item: _reference_key(item.predecessor))),
            qualificationProfile=("pajin.analysis-skill.proposal-only-semantic-equivalence/v1"),
            selectionPolicySchemaDigest=skill_definition_digest(
                "pajin.analysis-skill.selection-policy-schema/v1",
                AnalysisSkillSelectionPolicy.model_json_schema(
                    mode="validation",
                    by_alias=True,
                ),
            ),
            instructionProjectionSchemaDigest=skill_definition_digest(
                "pajin.analysis-skill.instruction-projection-schema/v1",
                AnalysisSkillInstructionProjection.model_json_schema(
                    mode="validation",
                    by_alias=True,
                ),
            ),
            qualificationState="reviewed-content-equivalent-proposal-only",
            targetNeutralityRequired=True,
            selectedOnlyProjectionRequired=True,
            recipeBindingQualified=False,
            labExecutionQualified=False,
            independentValidationQualified=False,
            scopeExpansionAuthority=False,
            targetSelectionAuthority=False,
            toolRequestAuthority=False,
            capabilityAuthority=False,
            permitAuthority=False,
            executionAuthority=False,
            graphAdmissionAuthority=False,
            findingAuthority=False,
            reportDeliveryAuthority=False,
        )
    except (AttributeError, SkillDefinitionError, TypeError, ValueError) as exc:
        if isinstance(exc, SkillSelectionError):
            raise
        raise SkillSelectionError("proposal-only Skill qualification failed closed") from exc


def select_analysis_skills_from_code_owned_policy(
    *,
    registry: SkillDefinitionRegistry,
    qualification: ProposalOnlySkillQualificationSet,
    policy: AnalysisSkillSelectionPolicy,
) -> tuple[AnalysisSkillSelectionReceipt, tuple[RegisteredSkill, ...]]:
    """Apply an already code-owned policy; this pure helper does not authenticate its caller."""

    try:
        registry = _require_installed_registry(registry)
        qualification = _require_installed_qualification(
            qualified_registry=registry,
            qualification=qualification,
        )
        policy = canonical_skill_contract(policy, AnalysisSkillSelectionPolicy)
        if (
            registry.reference() != policy.registry
            or registry.reference() != qualification.qualified_registry
        ):
            raise ValueError("Skill selector registry differs from policy or qualification")
        if (
            qualification.qualification_id != policy.qualification_id
            or qualification.qualification_digest != policy.qualification_digest
        ):
            raise ValueError("Skill selection policy differs from qualification")
        qualified_refs = {item.qualified for item in qualification.bindings}
        candidates: list[RegisteredSkill] = []
        for reference in policy.allowed_skill_refs:
            if reference not in qualified_refs:
                raise ValueError("Skill selection allowlist contains an unqualified reference")
            skill = registry.resolve(reference)
            definition = skill.definition
            if (
                definition.lifecycle_stage is not SkillLifecycleStage.PROPOSAL_ONLY
                or definition.selection_available is not True
                or definition.model_projection_available is not True
                or definition.recipe_binding_available is not False
            ):
                raise ValueError("Skill selection candidate is not proposal-only")
            domain_match = policy.domain_classification in definition.domain_classifications
            role_match = policy.agent_role in definition.allowed_agent_roles
            surface_match = policy.surface_type in definition.supported_surface_types
            hypothesis_match = set(definition.hypothesis_types).issubset(
                policy.allowed_hypothesis_ids
            )
            if domain_match and role_match and surface_match and hypothesis_match:
                candidates.append(skill)
        selected = tuple(
            sorted(candidates, key=lambda item: _reference_key(item.definition.reference()))
        )
        if not selected:
            raise ValueError("Skill selection produced no proposal guidance")
        if len(selected) > policy.max_selected_skills:
            raise ValueError("Skill selection exceeds the count budget")
        instruction_bytes = sum(
            len(
                canonical_skill_json(
                    item.instructions.model_dump(mode="json", by_alias=True),
                    label="selected Skill instructions",
                )
            )
            for item in selected
        )
        if instruction_bytes > policy.max_projected_instruction_bytes:
            raise ValueError("Skill selection exceeds the instruction byte budget")
        receipt = AnalysisSkillSelectionReceipt(
            receiptId="",
            receiptDigest="",
            registry=registry.reference(),
            qualificationId=qualification.qualification_id,
            qualificationDigest=qualification.qualification_digest,
            policyId=policy.policy_id,
            policyDigest=policy.policy_digest,
            consideredSkillCount=len(policy.allowed_skill_refs),
            selectedSkillCount=len(selected),
            selectedSkillRefs=tuple(item.definition.reference() for item in selected),
            projectedInstructionBytes=instruction_bytes,
            selectionState="selected-for-proposal-projection-not-authority",
            requiredEvidenceSatisfactionClaimed=False,
            targetContentUsedForSelection=False,
            modelSelectedSkills=False,
            scopeExpansionAuthority=False,
            recipeBindingAuthority=False,
            capabilityAuthority=False,
            permitAuthority=False,
            executionAuthority=False,
        )
        return receipt, tuple(item.model_copy(deep=True) for item in selected)
    except (AttributeError, SkillDefinitionError, TypeError, ValueError) as exc:
        if isinstance(exc, SkillSelectionError):
            raise
        raise SkillSelectionError("analysis Skill selection failed closed") from exc


def build_analysis_skill_instruction_projection_from_code_owned_policy(
    *,
    registry: SkillDefinitionRegistry,
    qualification: ProposalOnlySkillQualificationSet,
    policy: AnalysisSkillSelectionPolicy,
    receipt: AnalysisSkillSelectionReceipt,
) -> AnalysisSkillInstructionProjection:
    """Project an already code-owned selection; production adapters must pin the policy."""

    try:
        registry = _require_installed_registry(registry)
        qualification = _require_installed_qualification(
            qualified_registry=registry,
            qualification=qualification,
        )
        policy = canonical_skill_contract(policy, AnalysisSkillSelectionPolicy)
        receipt = canonical_skill_contract(receipt, AnalysisSkillSelectionReceipt)
        expected_receipt, selected = select_analysis_skills_from_code_owned_policy(
            registry=registry,
            qualification=qualification,
            policy=policy,
        )
        if receipt != expected_receipt:
            raise ValueError("Skill selection receipt differs from deterministic selection")
        entries = tuple(
            ProjectedAnalysisSkill(
                skillRef=skill.definition.reference(),
                lifecycleStage="proposal-only",
                title=skill.instructions.title,
                objective=skill.instructions.objective,
                workflowSteps=skill.instructions.workflow_steps,
                evidenceRequirements=skill.instructions.evidence_requirements,
                falsePositiveControls=skill.instructions.false_positive_controls,
                safetyConstraints=skill.instructions.safety_constraints,
                applicableHypothesisIds=skill.definition.hypothesis_types,
                requiredEvidenceTypes=skill.definition.required_evidence_types,
                requiredEvidenceSatisfied=False,
                targetContentIsUntrusted=True,
                groundTruthEmbedded=False,
                secretMaterialEmbedded=False,
                actionMaterialEmbedded=False,
            )
            for skill in selected
        )
        projection = AnalysisSkillInstructionProjection(
            projectionId="",
            projectionDigest="",
            registry=registry.reference(),
            qualificationId=qualification.qualification_id,
            qualificationDigest=qualification.qualification_digest,
            policyId=policy.policy_id,
            policyDigest=policy.policy_digest,
            selectionReceiptId=receipt.receipt_id,
            selectionReceiptDigest=receipt.receipt_digest,
            selectedSkills=entries,
            selectedSkillCount=len(entries),
            projectedInstructionBytes=receipt.projected_instruction_bytes,
            projectionState="code-owned-selected-instructions-not-authority",
            developerMessageEligible=True,
            userEvidenceMessageEmbedded=False,
            targetContentEmbedded=False,
            scopeExpansionAuthority=False,
            toolRequestAuthority=False,
            capabilityAuthority=False,
            permitAuthority=False,
            executionAuthority=False,
            graphAdmissionAuthority=False,
            findingAuthority=False,
            reportDeliveryAuthority=False,
        )
        encoded = canonical_skill_json(
            projection.model_dump(mode="json", by_alias=True),
            label="analysis Skill instruction projection",
        )
        if len(encoded) > _MAX_PROJECTION_BYTES:
            raise ValueError("Skill instruction projection exceeds the total byte limit")
        return projection
    except (AttributeError, SkillDefinitionError, TypeError, ValueError) as exc:
        if isinstance(exc, SkillSelectionError):
            raise
        raise SkillSelectionError("analysis Skill instruction projection failed closed") from exc


def _require_proposal_successor(predecessor: RegisteredSkill, successor: RegisteredSkill) -> None:
    predecessor_definition = predecessor.definition
    successor_definition = successor.definition
    if (
        predecessor_definition.lifecycle_stage is not SkillLifecycleStage.CATALOGUED
        or successor_definition.lifecycle_stage is not SkillLifecycleStage.PROPOSAL_ONLY
        or predecessor_definition.skill_id != successor_definition.skill_id
        or predecessor_definition.skill_version == successor_definition.skill_version
        or predecessor_definition.domain_classifications
        != successor_definition.domain_classifications
        or predecessor_definition.allowed_agent_roles != successor_definition.allowed_agent_roles
        or predecessor_definition.supported_surface_types
        != successor_definition.supported_surface_types
        or predecessor_definition.hypothesis_types != successor_definition.hypothesis_types
        or predecessor_definition.required_evidence_types
        != successor_definition.required_evidence_types
        or predecessor_definition.input_schema_digest != successor_definition.input_schema_digest
        or predecessor_definition.output_schema_digest != successor_definition.output_schema_digest
        or predecessor_definition.provenance.source_kind
        is not successor_definition.provenance.source_kind
        or predecessor_definition.provenance.source_id != successor_definition.provenance.source_id
        or predecessor_definition.provenance.license_id
        != successor_definition.provenance.license_id
        or predecessor_definition.provenance.upstream_uri
        != successor_definition.provenance.upstream_uri
    ):
        raise ValueError("proposal-only Skill metadata differs from its catalogued predecessor")
    predecessor_instructions = predecessor.instructions.model_dump(
        mode="json",
        by_alias=True,
        exclude={"skill_version", "instruction_digest"},
    )
    successor_instructions = successor.instructions.model_dump(
        mode="json",
        by_alias=True,
        exclude={"skill_version", "instruction_digest"},
    )
    if predecessor_instructions != successor_instructions:
        raise ValueError("proposal-only Skill instruction semantics changed during qualification")


def _require_installed_registry(
    registry: SkillDefinitionRegistry,
) -> SkillDefinitionRegistry:
    from pajin.skills.catalog import resolve_installed_analysis_skill_registry

    if type(registry) is not SkillDefinitionRegistry:
        raise SkillDefinitionError("Skill registry has a non-canonical runtime type")
    installed = resolve_installed_analysis_skill_registry(registry.reference())
    if registry.references() != installed.references():
        raise SkillDefinitionError("Skill registry differs from the installed exact records")
    for reference in installed.references():
        if registry.resolve(reference) != installed.resolve(reference):
            raise SkillDefinitionError("Skill registry content differs from the installed identity")
    return installed


def _require_installed_qualification(
    *,
    qualified_registry: SkillDefinitionRegistry,
    qualification: ProposalOnlySkillQualificationSet,
) -> ProposalOnlySkillQualificationSet:
    from pajin.skills.catalog import resolve_installed_analysis_skill_registry

    qualification = canonical_skill_contract(
        qualification,
        ProposalOnlySkillQualificationSet,
    )
    if qualification.qualified_registry != qualified_registry.reference():
        raise SkillDefinitionError(
            "Skill qualification successor differs from the installed exact registry"
        )
    predecessor_registry = resolve_installed_analysis_skill_registry(
        qualification.predecessor_registry
    )
    expected = qualify_proposal_only_skill_registry(
        predecessor_registry=predecessor_registry,
        qualified_registry=qualified_registry,
    )
    if qualification != expected:
        raise SkillDefinitionError(
            "Skill qualification differs from the installed exact qualification"
        )
    return qualification


def selection_material_digest(value: object) -> str:
    """Small helper for code-owned selection profiles and tests."""

    encoded = canonical_skill_json(value, label="Skill selection material")
    return sha256(b"PAJIN-SKILL-SELECTION-MATERIAL\0" + encoded).hexdigest()


__all__ = [
    "ANALYSIS_SKILL_INSTRUCTION_PROJECTION_API_VERSION",
    "ANALYSIS_SKILL_SELECTION_POLICY_API_VERSION",
    "ANALYSIS_SKILL_SELECTION_RECEIPT_API_VERSION",
    "PROPOSAL_ONLY_SKILL_QUALIFICATION_API_VERSION",
    "AnalysisSkillInstructionProjection",
    "AnalysisSkillSelectionPolicy",
    "AnalysisSkillSelectionReceipt",
    "ProjectedAnalysisSkill",
    "ProposalOnlySkillQualificationBinding",
    "ProposalOnlySkillQualificationSet",
    "SkillSelectionError",
    "build_analysis_skill_instruction_projection_from_code_owned_policy",
    "qualify_proposal_only_skill_registry",
    "select_analysis_skills_from_code_owned_policy",
    "selection_material_digest",
]
