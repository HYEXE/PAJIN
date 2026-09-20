"""Versioned, non-authoritative analysis Skill definitions."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from pydantic_core import PydanticSerializationError

from pajin.domain.models import StrictModel
from pajin.domain.orchestration import AgentRole
from pajin.domain.security_domain import (
    SecurityDomainClassificationRef,
    resolve_registered_security_domain,
)

SKILL_INSTRUCTION_BUNDLE_API_VERSION: Literal[
    "pajin.dev/analysis-skill-instruction-bundle/v1alpha1"
] = "pajin.dev/analysis-skill-instruction-bundle/v1alpha1"
SKILL_DEFINITION_API_VERSION: Literal["pajin.dev/analysis-skill-definition/v1alpha1"] = (
    "pajin.dev/analysis-skill-definition/v1alpha1"
)
SKILL_REGISTRY_API_VERSION: Literal["pajin.dev/analysis-skill-registry/v1alpha1"] = (
    "pajin.dev/analysis-skill-registry/v1alpha1"
)

_MAX_SKILL_CANONICAL_BYTES = 1024 * 1024
_MAX_SKILL_CONTRACT_DEPTH = 64
_MAX_SKILL_CONTRACT_NODES = 100_000
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_SEMANTIC_VERSION_CORE = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
_SEMANTIC_VERSION_PRERELEASE = r"(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
_SEMANTIC_VERSION_BUILD = r"[0-9A-Za-z-]+"
_SEMANTIC_VERSION_PATTERN = (
    rf"^{_SEMANTIC_VERSION_CORE}"
    rf"(?:-{_SEMANTIC_VERSION_PRERELEASE}"
    rf"(?:\.{_SEMANTIC_VERSION_PRERELEASE})*)?"
    rf"(?:\+{_SEMANTIC_VERSION_BUILD}(?:\.{_SEMANTIC_VERSION_BUILD})*)?$"
)
_SkillVersion = Annotated[
    str,
    Field(min_length=5, max_length=100, pattern=_SEMANTIC_VERSION_PATTERN),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Instruction = Annotated[str, Field(min_length=1, max_length=2_000)]
_IMMUTABLE_SOURCE_REVISION = re.compile(
    rf"(?:{_SEMANTIC_VERSION_PATTERN[1:-1]}|[a-f0-9]{{40}}|[a-f0-9]{{64}})"
)
_VENDORED_SOURCE_REVISION = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})")


class SkillDefinitionError(ValueError):
    """Raised when an analysis Skill definition or registry is invalid or drifted."""


class SkillLifecycleStage(StrEnum):
    """Evidence maturity of a Skill; no stage grants execution authority."""

    CATALOGUED = "catalogued"
    PROPOSAL_ONLY = "proposal-only"
    RECIPE_BACKED = "recipe-backed"
    LAB_EXECUTABLE = "lab-executable"
    INDEPENDENTLY_VERIFIED = "independently-verified"


class SkillSourceKind(StrEnum):
    """Reviewable origin of one instruction bundle."""

    REPOSITORY_OWNED = "repository-owned"
    VENDORED = "vendored"


def canonical_skill_json(value: object, *, label: str) -> bytes:
    """Encode bounded canonical UTF-8 JSON for Skill identities."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise SkillDefinitionError(f"{label} is not canonical UTF-8 JSON") from exc
    if len(encoded) > _MAX_SKILL_CANONICAL_BYTES:
        raise SkillDefinitionError(f"{label} exceeds the canonical byte limit")
    return encoded


def skill_definition_digest(domain: str, value: object) -> str:
    """Return a domain-separated digest for one Skill object."""

    try:
        domain_bytes = domain.encode("ascii")
    except UnicodeEncodeError as exc:
        raise SkillDefinitionError("Skill digest domain must be ASCII") from exc
    encoded = canonical_skill_json(value, label=domain)
    return sha256(
        b"PAJIN-ANALYSIS-SKILL\0"
        + len(domain_bytes).to_bytes(4, "big")
        + domain_bytes
        + len(encoded).to_bytes(8, "big")
        + encoded
    ).hexdigest()


def skill_schema_digest(schema: object) -> str:
    """Bind a code-owned Skill input or output schema without making it authoritative."""

    return skill_definition_digest("pajin.analysis-skill.schema/v1", schema)


def canonical_skill_contract[T: BaseModel](value: T, model: type[T]) -> T:
    """Reject validation-bypassing runtime types and undeclared nested model state."""

    if type(value) is not model:
        raise SkillDefinitionError("Skill contract object has a non-canonical runtime type")
    stack: list[tuple[object, int, bool]] = [(value, 0, False)]
    active: set[int] = set()
    completed: set[int] = set()
    node_count = 0
    while stack:
        item, depth, exiting = stack.pop()
        node_count += 1
        if node_count > _MAX_SKILL_CONTRACT_NODES:
            raise SkillDefinitionError("Skill contract exceeds the runtime node limit")
        if depth > _MAX_SKILL_CONTRACT_DEPTH:
            raise SkillDefinitionError("Skill contract exceeds the runtime depth limit")
        is_container = isinstance(item, (BaseModel, Mapping, list, tuple))
        if is_container:
            identity = id(item)
            if exiting:
                active.remove(identity)
                completed.add(identity)
                continue
            if identity in active:
                raise SkillDefinitionError("Skill contract contains cyclic runtime state")
            if identity in completed:
                continue
            active.add(identity)
            stack.append((item, depth, True))
        if isinstance(item, BaseModel):
            declared = set(type(item).model_fields)
            stored = vars(item)
            if not set(stored).issubset(declared) or getattr(item, "__pydantic_extra__", None):
                raise SkillDefinitionError("Skill contract contains undeclared model state")
            stack.extend((stored[name], depth + 1, False) for name in declared if name in stored)
        elif isinstance(item, Mapping):
            stack.extend((child, depth + 1, False) for pair in item.items() for child in pair)
        elif isinstance(item, (list, tuple)):
            stack.extend((child, depth + 1, False) for child in item)
    try:
        canonical = model.model_validate(
            value.model_dump(mode="json", by_alias=True, warnings="error")
        )
    except (PydanticSerializationError, TypeError, ValidationError, ValueError) as exc:
        raise SkillDefinitionError("Skill contract is not canonical") from exc
    if not _same_canonical_runtime_shape(value, canonical):
        raise SkillDefinitionError("Skill contract contains non-canonical runtime state")
    return canonical


def _same_canonical_runtime_shape(left: object, right: object) -> bool:
    if type(left) is not type(right):
        return False
    if isinstance(left, BaseModel) and isinstance(right, BaseModel):
        fields = type(left).model_fields
        return all(
            _same_canonical_runtime_shape(getattr(left, name), getattr(right, name))
            for name in fields
        )
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        if len(left) != len(right):
            return False
        unmatched = list(right.items())
        for left_key, left_value in left.items():
            for index, (right_key, right_value) in enumerate(unmatched):
                if type(left_key) is type(right_key) and left_key == right_key:
                    if not _same_canonical_runtime_shape(left_value, right_value):
                        return False
                    unmatched.pop(index)
                    break
            else:
                return False
        return not unmatched
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(
            _same_canonical_runtime_shape(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    return left == right


class SkillProvenance(StrictModel):
    """Pinned source and license metadata for reviewed Skill content."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_kind: SkillSourceKind = Field(alias="sourceKind")
    source_id: _Identifier = Field(alias="sourceId")
    source_revision: str = Field(alias="sourceRevision", min_length=1, max_length=200)
    license_id: str = Field(
        alias="licenseId",
        min_length=1,
        max_length=100,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,99}$",
    )
    upstream_uri: str | None = Field(default=None, alias="upstreamUri", max_length=2_000)

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        if self.source_kind is SkillSourceKind.REPOSITORY_OWNED and self.upstream_uri is not None:
            raise ValueError("repository-owned Skill provenance cannot declare an upstream URI")
        if self.source_kind is SkillSourceKind.VENDORED and self.upstream_uri is None:
            raise ValueError("vendored Skill provenance requires an upstream URI")
        if self.source_kind is SkillSourceKind.VENDORED:
            if _VENDORED_SOURCE_REVISION.fullmatch(self.source_revision) is None:
                raise ValueError("vendored Skill provenance requires a pinned source revision")
        elif _IMMUTABLE_SOURCE_REVISION.fullmatch(self.source_revision) is None:
            raise ValueError("repository-owned Skill provenance requires an immutable revision")
        return self


class SkillInstructionBundle(StrictModel):
    """Concise target-neutral instructions that may later be projected to a model."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/analysis-skill-instruction-bundle/v1alpha1"] = Field(
        default=SKILL_INSTRUCTION_BUNDLE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SkillInstructionBundle"] = "SkillInstructionBundle"
    skill_id: _Identifier = Field(alias="skillId")
    skill_version: _SkillVersion = Field(alias="skillVersion")
    instruction_digest: str = Field(default="", alias="instructionDigest", max_length=64)
    title: str = Field(min_length=1, max_length=200)
    objective: str = Field(min_length=1, max_length=2_000)
    workflow_steps: tuple[_Instruction, ...] = Field(
        alias="workflowSteps",
        min_length=1,
        max_length=32,
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
    target_content_is_untrusted: Literal[True] = Field(
        default=True,
        alias="targetContentIsUntrusted",
    )
    ground_truth_embedded: Literal[False] = Field(
        default=False,
        alias="groundTruthEmbedded",
    )
    secret_material_embedded: Literal[False] = Field(
        default=False,
        alias="secretMaterialEmbedded",
    )
    action_material_embedded: Literal[False] = Field(
        default=False,
        alias="actionMaterialEmbedded",
    )

    @field_validator(
        "target_content_is_untrusted",
        "ground_truth_embedded",
        "secret_material_embedded",
        "action_material_embedded",
        mode="before",
    )
    @classmethod
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Skill instruction markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_instruction_digest(self) -> Self:
        for field_name, label in (
            ("workflow_steps", "workflow steps"),
            ("evidence_requirements", "evidence requirements"),
            ("false_positive_controls", "false-positive controls"),
            ("safety_constraints", "safety constraints"),
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"Skill {label} must be unique")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"instruction_digest"},
        )
        digest = skill_definition_digest("pajin.analysis-skill.instructions/v1", material)
        if self.instruction_digest and self.instruction_digest != digest:
            raise ValueError("Skill instruction digest differs from canonical content")
        object.__setattr__(self, "instruction_digest", digest)
        canonical_skill_json(
            self.model_dump(mode="json", by_alias=True),
            label="SkillInstructionBundle",
        )
        return self


class SkillDefinitionRef(StrictModel):
    """Exact Skill and content/schema identity used by later proposal contracts."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    skill_id: _Identifier = Field(alias="skillId")
    skill_version: _SkillVersion = Field(alias="skillVersion")
    skill_digest: _Sha256 = Field(alias="skillDigest")
    instruction_digest: _Sha256 = Field(alias="instructionDigest")
    input_schema_digest: _Sha256 = Field(alias="inputSchemaDigest")
    output_schema_digest: _Sha256 = Field(alias="outputSchemaDigest")


class SkillDefinition(StrictModel):
    """Immutable analysis metadata with explicit denial of every authority transition."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/analysis-skill-definition/v1alpha1"] = Field(
        default=SKILL_DEFINITION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SkillDefinition"] = "SkillDefinition"
    skill_id: _Identifier = Field(alias="skillId")
    skill_version: _SkillVersion = Field(alias="skillVersion")
    skill_digest: str = Field(default="", alias="skillDigest", max_length=64)
    lifecycle_stage: SkillLifecycleStage = Field(alias="lifecycleStage")
    domain_classifications: tuple[SecurityDomainClassificationRef, ...] = Field(
        alias="domainClassifications",
        min_length=1,
        max_length=9,
    )
    allowed_agent_roles: tuple[AgentRole, ...] = Field(
        alias="allowedAgentRoles",
        min_length=1,
        max_length=len(AgentRole),
    )
    supported_surface_types: tuple[_Identifier, ...] = Field(
        alias="supportedSurfaceTypes",
        min_length=1,
        max_length=100,
    )
    hypothesis_types: tuple[_Identifier, ...] = Field(
        alias="hypothesisTypes",
        min_length=1,
        max_length=100,
    )
    required_evidence_types: tuple[_Identifier, ...] = Field(
        alias="requiredEvidenceTypes",
        min_length=1,
        max_length=100,
    )
    instruction_digest: _Sha256 = Field(alias="instructionDigest")
    input_schema_digest: _Sha256 = Field(alias="inputSchemaDigest")
    output_schema_digest: _Sha256 = Field(alias="outputSchemaDigest")
    provenance: SkillProvenance
    selection_available: bool = Field(alias="selectionAvailable")
    model_projection_available: bool = Field(alias="modelProjectionAvailable")
    recipe_binding_available: bool = Field(alias="recipeBindingAvailable")
    lab_execution_evidence_available: bool = Field(alias="labExecutionEvidenceAvailable")
    independent_validation_evidence_available: bool = Field(
        alias="independentValidationEvidenceAvailable"
    )
    knowledge_only: Literal[True] = Field(default=True, alias="knowledgeOnly")
    scope_expansion_authority: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthority",
    )
    target_selection_authority: Literal[False] = Field(
        default=False,
        alias="targetSelectionAuthority",
    )
    tool_request_authority: Literal[False] = Field(
        default=False,
        alias="toolRequestAuthority",
    )
    capability_authority: Literal[False] = Field(
        default=False,
        alias="capabilityAuthority",
    )
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthority",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    report_delivery_authority: Literal[False] = Field(
        default=False,
        alias="reportDeliveryAuthority",
    )

    @field_validator(
        "selection_available",
        "model_projection_available",
        "recipe_binding_available",
        "lab_execution_evidence_available",
        "independent_validation_evidence_available",
        "knowledge_only",
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
    def require_exact_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("Skill definition markers must be booleans")
        return value

    @model_validator(mode="after")
    def bind_definition(self) -> Self:
        for reference in self.domain_classifications:
            resolve_registered_security_domain(reference)
        domain_keys = tuple(
            (reference.domain.value, reference.classification_id)
            for reference in self.domain_classifications
        )
        if domain_keys != tuple(sorted(set(domain_keys))):
            raise ValueError("Skill domain classifications must be unique and sorted")
        role_values = tuple(role.value for role in self.allowed_agent_roles)
        if role_values != tuple(sorted(set(role_values))):
            raise ValueError("Skill allowed Agent roles must be unique and sorted")
        for field_name, label in (
            ("supported_surface_types", "supported Surface types"),
            ("hypothesis_types", "Hypothesis types"),
            ("required_evidence_types", "required Evidence types"),
        ):
            values = getattr(self, field_name)
            if values != tuple(sorted(set(values))):
                raise ValueError(f"Skill {label} must be unique and sorted")
        expected_stage_markers = {
            SkillLifecycleStage.CATALOGUED: (False, False, False, False, False),
            SkillLifecycleStage.PROPOSAL_ONLY: (True, True, False, False, False),
            SkillLifecycleStage.RECIPE_BACKED: (True, True, True, False, False),
            SkillLifecycleStage.LAB_EXECUTABLE: (True, True, True, True, False),
            SkillLifecycleStage.INDEPENDENTLY_VERIFIED: (True, True, True, True, True),
        }[self.lifecycle_stage]
        actual_stage_markers = (
            self.selection_available,
            self.model_projection_available,
            self.recipe_binding_available,
            self.lab_execution_evidence_available,
            self.independent_validation_evidence_available,
        )
        if actual_stage_markers != expected_stage_markers:
            raise ValueError("Skill lifecycle markers differ from the declared stage")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"skill_digest"},
        )
        digest = skill_definition_digest("pajin.analysis-skill.definition/v1", material)
        if self.skill_digest and self.skill_digest != digest:
            raise ValueError("Skill definition digest differs from canonical identity")
        object.__setattr__(self, "skill_digest", digest)
        canonical_skill_json(
            self.model_dump(mode="json", by_alias=True),
            label="SkillDefinition",
        )
        return self

    def reference(self) -> SkillDefinitionRef:
        """Return the exact definition and content/schema identity."""

        return SkillDefinitionRef(
            skillId=self.skill_id,
            skillVersion=self.skill_version,
            skillDigest=self.skill_digest,
            instructionDigest=self.instruction_digest,
            inputSchemaDigest=self.input_schema_digest,
            outputSchemaDigest=self.output_schema_digest,
        )


class RegisteredSkill(StrictModel):
    """One reviewed definition paired with its exact instruction content."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    definition: SkillDefinition
    instructions: SkillInstructionBundle

    @model_validator(mode="after")
    def bind_instructions(self) -> Self:
        if (
            self.definition.skill_id,
            self.definition.skill_version,
            self.definition.instruction_digest,
        ) != (
            self.instructions.skill_id,
            self.instructions.skill_version,
            self.instructions.instruction_digest,
        ):
            raise ValueError("Skill definition and instruction identity differ")
        return self


class SkillRegistryRef(StrictModel):
    """Content-addressed reference to one complete installed Skill registry."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    registry_id: Literal["pajin.analysis-skills"] = Field(alias="registryId")
    registry_version: _SkillVersion = Field(alias="registryVersion")
    registry_digest: _Sha256 = Field(alias="registryDigest")


class SkillDefinitionRegistry:
    """Immutable exact-version registry with no implicit latest or runtime activation."""

    __slots__ = ("_records", "_registry_digest", "_registry_version")

    registry_id: Literal["pajin.analysis-skills"] = "pajin.analysis-skills"

    _records: Mapping[tuple[str, str], RegisteredSkill]
    _registry_digest: str
    _registry_version: str

    def __init__(
        self,
        skills: Iterable[RegisteredSkill],
        *,
        registry_version: str = "1.0.0",
    ) -> None:
        try:
            canonical_reference = SkillRegistryRef(
                registryId=self.registry_id,
                registryVersion=registry_version,
                registryDigest="0" * 64,
            )
        except ValidationError as exc:
            raise SkillDefinitionError(
                "Skill registry version is not exact semantic version"
            ) from exc
        records: dict[tuple[str, str], RegisteredSkill] = {}
        for skill in skills:
            canonical = self._canonical_skill(skill)
            key = (canonical.definition.skill_id, canonical.definition.skill_version)
            if key in records:
                raise SkillDefinitionError("Skill registry contains a duplicate ID and version")
            records[key] = canonical
        if not records:
            raise SkillDefinitionError("Skill registry cannot be empty")
        object.__setattr__(self, "_records", MappingProxyType(records))
        object.__setattr__(self, "_registry_version", canonical_reference.registry_version)
        object.__setattr__(
            self,
            "_registry_digest",
            skill_definition_digest(
                "pajin.analysis-skill.registry/v1",
                {
                    "apiVersion": SKILL_REGISTRY_API_VERSION,
                    "registryId": self.registry_id,
                    "registryVersion": self.registry_version,
                    "skills": [
                        records[key].model_dump(mode="json", by_alias=True)
                        for key in sorted(records)
                    ],
                },
            ),
        )

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("Skill registry is immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("Skill registry is immutable")

    @property
    def registry_digest(self) -> str:
        return self._registry_digest

    @property
    def registry_version(self) -> str:
        return self._registry_version

    def reference(self) -> SkillRegistryRef:
        """Return the exact installed registry identity."""

        return SkillRegistryRef(
            registryId=self.registry_id,
            registryVersion=self.registry_version,
            registryDigest=self.registry_digest,
        )

    def resolve(self, reference: SkillDefinitionRef) -> RegisteredSkill:
        """Resolve an exact Skill ID, version, definition, content, and schema tuple."""

        try:
            skill = self._records[(reference.skill_id, reference.skill_version)]
        except KeyError as exc:
            raise SkillDefinitionError("Skill definition is not registered") from exc
        if skill.definition.reference() != reference:
            raise SkillDefinitionError("Skill definition or content/schema digest differs")
        return skill.model_copy(deep=True)

    def definitions(self) -> tuple[SkillDefinition, ...]:
        """Return metadata only; instruction content requires exact resolution."""

        return tuple(
            self._records[key].definition.model_copy(deep=True) for key in sorted(self._records)
        )

    def references(self) -> tuple[SkillDefinitionRef, ...]:
        """Return exact references in canonical ID/version order."""

        return tuple(self._records[key].definition.reference() for key in sorted(self._records))

    @staticmethod
    def _canonical_skill(skill: RegisteredSkill) -> RegisteredSkill:
        try:
            return RegisteredSkill.model_validate(skill.model_dump(mode="json", by_alias=True))
        except (AttributeError, ValidationError) as exc:
            raise SkillDefinitionError("Skill registry input is not canonical") from exc
