"""Typed contracts for bounded agentic security campaigns.

The contracts in this module deliberately separate model-authored hypotheses from
trusted scheduling metadata and from every external execution authority.
"""

from __future__ import annotations

import json
from enum import StrEnum
from re import fullmatch
from typing import Annotated, Any, Literal, NoReturn, Self
from unicodedata import category, name

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.domain.models import StrictModel

AGENTIC_CAMPAIGN_API_VERSION: Literal["pajin.dev/agentic-campaign/v1alpha1"] = (
    "pajin.dev/agentic-campaign/v1alpha1"
)
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_MAX_TEXT_BYTES = 8 * 1024
_MAX_ARTIFACT_REFS = 32
_MAX_SPECIALISTS = 32
_MAX_WIRE_INPUT_DEPTH = 32
_MAX_WIRE_INPUT_NODES = 8_192
_MAX_WIRE_JSON_BYTES = 1024 * 1024
_DEFAULT_IGNORABLE_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)

Identifier = Annotated[str, Field(min_length=1, max_length=200, pattern=_IDENTIFIER_PATTERN)]
Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]
BasisPoints = Annotated[int, Field(strict=True, ge=0, le=10_000)]
SkillVersion = Annotated[
    str,
    Field(pattern=r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"),
]


def _canonicalize_nested_model_instances(value: Any) -> Any:
    """Return a bounded, acyclic, alias-based JSON wire projection.

    Pydantic accepts already-created model instances without necessarily
    revalidating every nested value.  Agentic public inputs therefore round-trip
    all models through their wire representation.  The traversal is deliberately
    bounded so a cyclic or adversarially deep caller object fails as validation,
    never as an unhandled ``RecursionError``.
    """

    active: set[int] = set()
    nodes = 0

    def canonicalize(item: Any, *, depth: int) -> Any:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_WIRE_INPUT_NODES:
            raise ValueError("agentic wire input exceeds its node limit")
        if depth > _MAX_WIRE_INPUT_DEPTH:
            raise ValueError("agentic wire input exceeds its depth limit")
        if isinstance(item, StrEnum):
            return item.value
        if item is None or type(item) in {bool, int, float, str}:
            return item
        if isinstance(item, BaseModel):
            identity = id(item)
            if identity in active:
                raise ValueError("agentic wire input contains a cycle")
            active.add(identity)
            try:
                try:
                    wire = item.model_dump(mode="json", by_alias=True)
                except (RecursionError, TypeError, ValueError) as exc:
                    raise ValueError(
                        "agentic wire model cannot be projected safely"
                    ) from exc
                return canonicalize(wire, depth=depth + 1)
            finally:
                active.remove(identity)
        if type(item) is dict:
            identity = id(item)
            if identity in active:
                raise ValueError("agentic wire input contains a cycle")
            if any(type(key) is not str for key in item):
                raise ValueError("agentic wire input object keys must be strings")
            active.add(identity)
            try:
                return {
                    key: canonicalize(nested, depth=depth + 1)
                    for key, nested in item.items()
                }
            finally:
                active.remove(identity)
        if type(item) in {list, tuple}:
            identity = id(item)
            if identity in active:
                raise ValueError("agentic wire input contains a cycle")
            active.add(identity)
            try:
                return [
                    canonicalize(nested, depth=depth + 1) for nested in item
                ]
            finally:
                active.remove(identity)
        raise ValueError("agentic wire input contains an unsupported value type")

    return canonicalize(value, depth=0)


def _load_strict_agentic_json(value: str | bytes | bytearray) -> Any:
    if type(value) not in {str, bytes, bytearray}:
        raise TypeError("agentic JSON input must be exact str, bytes, or bytearray")
    if type(value) is str:
        encoded = value.encode("utf-8")
        text = value
    else:
        assert isinstance(value, (bytes, bytearray))
        encoded = bytes(value)
        try:
            text = encoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("agentic JSON input must be valid UTF-8") from exc
    if len(encoded) > _MAX_WIRE_JSON_BYTES:
        raise ValueError("agentic JSON input exceeds its byte limit")

    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("agentic JSON input contains a duplicate object key")
            result[key] = item
        return result

    def reject_constant(value: str) -> NoReturn:
        raise ValueError(f"agentic JSON input contains non-finite number {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=object_pairs,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("agentic JSON input is malformed or too deeply nested") from exc


class AgenticStrictModel(StrictModel):
    """Agentic wire base that recursively revalidates existing model instances."""

    @model_validator(mode="before")
    @classmethod
    def canonicalize_nested_model_instances(cls, value: Any) -> Any:
        return _canonicalize_nested_model_instances(value)

    @classmethod
    def model_validate(
        cls,
        obj: Any,
        *,
        strict: bool | None = None,
        extra: Any = None,
        from_attributes: bool | None = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        if isinstance(obj, BaseModel):
            obj = _canonicalize_nested_model_instances(obj)
        return super().model_validate(
            obj,
            strict=strict,
            extra=extra,
            from_attributes=from_attributes,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )

    @classmethod
    def model_validate_json(
        cls,
        json_data: str | bytes | bytearray,
        *,
        strict: bool | None = None,
        extra: Any = None,
        context: Any | None = None,
        by_alias: bool | None = None,
        by_name: bool | None = None,
    ) -> Self:
        """Strict-load JSON so duplicate keys cannot be normalized away."""

        return cls.model_validate(
            _load_strict_agentic_json(json_data),
            strict=strict,
            extra=extra,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )


def _safe_text(value: str, *, label: str | None) -> str:
    label = label or "field"
    if value != value.strip():
        raise ValueError(f"{label} cannot contain surrounding whitespace")
    if any(
        category(character).startswith("C")
        or any(start <= ord(character) <= end for start, end in _DEFAULT_IGNORABLE_RANGES)
        or "BLANK" in name(character, "")
        or "FILLER" in name(character, "")
        for character in value
    ):
        raise ValueError(
            f"{label} cannot contain Unicode control, format, private-use, unassigned, "
            "default-ignorable, blank, or filler characters"
        )
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{label} must be valid UTF-8") from exc
    if len(encoded) > _MAX_TEXT_BYTES:
        raise ValueError(f"{label} exceeds the byte limit")
    return value


def _literal_false(value: object, *, label: str | None) -> object:
    label = label or "field"
    if type(value) is not bool or value is not False:
        raise ValueError(f"{label} must be literal false")
    return value


def _literal_true(value: object, *, label: str | None) -> object:
    label = label or "field"
    if type(value) is not bool or value is not True:
        raise ValueError(f"{label} must be literal true")
    return value


def _canonical_identifiers(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if values != tuple(sorted(set(values))):
        raise ValueError(f"{label} must be unique and canonically sorted")
    if any(fullmatch(_IDENTIFIER_PATTERN, item) is None for item in values):
        raise ValueError(f"{label} contains a malformed identifier")
    return values


class PentestSpecialization(StrEnum):
    """Closed initial role vocabulary for one Web exploitation group."""

    ATTACK_PATH_STRATEGIST = "attack-path-strategist"
    RECON = "recon-specialist"
    XSS = "xss-specialist"
    SQL_INJECTION = "sql-injection-specialist"
    SSRF = "ssrf-specialist"
    AUTHORIZATION = "authorization-specialist"
    AUTH_SESSION = "auth-session-specialist"
    API = "api-specialist"
    VALIDATOR = "independent-validator"
    REPORTER = "evidence-reporter"


class AgentSessionState(StrEnum):
    SPAWNED = "spawned"
    IDLE = "idle"
    ASSIGNED = "assigned"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AgentControlCommandKind(StrEnum):
    SPAWN = "spawn"
    ASSIGN = "assign"
    FOLLOW_UP = "follow-up"
    CANCEL = "cancel"
    PAUSE = "pause"
    RESUME = "resume"
    REQUEST_STATUS = "request-status"
    REQUEST_FINAL = "request-final"


class AgentEventKind(StrEnum):
    ACKNOWLEDGED = "acknowledged"
    PROGRESS = "progress"
    ARTIFACT_READY = "artifact-ready"
    NEEDS_INPUT = "needs-input"
    NEEDS_CAPABILITY = "needs-capability"
    BLOCKED = "blocked"
    FAILED = "failed"
    FINAL = "final"


class ArtifactReference(AgenticStrictModel):
    """Content-free pointer to a sealed artifact; artifact bytes are never a command."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    artifact_id: Identifier = Field(alias="artifactId")
    artifact_sha256: Sha256 = Field(alias="artifactSha256")
    media_type: str = Field(alias="mediaType", min_length=1, max_length=100)
    source_run_id: Identifier = Field(alias="sourceRunId")
    content_origin: Literal["sealed-artifact-untrusted"] = Field(
        default="sealed-artifact-untrusted",
        alias="contentOrigin",
    )
    content_is_untrusted: Literal[True] = Field(default=True, alias="contentIsUntrusted")
    content_included: Literal[False] = Field(default=False, alias="contentIncluded")
    instruction_authority: Literal[False] = Field(default=False, alias="instructionAuthority")

    @field_validator("media_type")
    @classmethod
    def validate_media_type(cls, value: str) -> str:
        return _safe_text(value, label="Artifact media type")

    @field_validator("content_included", "instruction_authority", mode="before")
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @field_validator("content_is_untrusted", mode="before")
    @classmethod
    def require_true_marker(cls, value: object, info: ValidationInfo) -> object:
        return _literal_true(value, label=info.field_name)


class ModelPathEstimate(AgenticStrictModel):
    """Bounded model opinion that can influence attention but is never evidence."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    success_likelihood_bps: BasisPoints = Field(alias="successLikelihoodBps")
    estimate_origin: Literal["model-advisory"] = Field(
        default="model-advisory",
        alias="estimateOrigin",
    )
    evidence_authority: Literal[False] = Field(default=False, alias="evidenceAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scheduling_authority: Literal[False] = Field(default=False, alias="schedulingAuthority")

    @field_validator(
        "evidence_authority",
        "finding_authority",
        "scheduling_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)


class TrustedPathFeatures(AgenticStrictModel):
    """Code-derived scheduling features kept separate from the model estimate."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    feature_set_id: str = Field(default="", alias="featureSetId", max_length=96)
    source_snapshot_id: Identifier = Field(alias="sourceSnapshotId")
    source_snapshot_digest: Sha256 = Field(alias="sourceSnapshotDigest")
    source_evidence_ids: tuple[Identifier, ...] = Field(
        alias="sourceEvidenceIds",
        min_length=1,
        max_length=_MAX_ARTIFACT_REFS,
    )
    expected_impact_bps: BasisPoints = Field(alias="expectedImpactBps")
    privilege_gain_bps: BasisPoints = Field(alias="privilegeGainBps")
    reachability_gain_bps: BasisPoints = Field(alias="reachabilityGainBps")
    evidence_quality_bps: BasisPoints = Field(alias="evidenceQualityBps")
    novelty_bps: BasisPoints = Field(alias="noveltyBps")
    execution_cost_bps: BasisPoints = Field(alias="executionCostBps")
    safety_risk_bps: BasisPoints = Field(alias="safetyRiskBps")
    feature_origin: Literal["trusted-code-derived"] = Field(
        default="trusted-code-derived",
        alias="featureOrigin",
    )

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        _canonical_identifiers(self.source_evidence_ids, label="source Evidence IDs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"feature_set_id"},
        )
        expected = "path-features_" + discovery_digest(
            "pajin.agentic.trusted-path-features/v1",
            material,
        )
        if self.feature_set_id and self.feature_set_id != expected:
            raise ValueError("Path Feature Set ID differs from canonical identity")
        object.__setattr__(self, "feature_set_id", expected)
        return self


class HypothesisProposal(AgenticStrictModel):
    """LLM-authored successor hypothesis with no scheduling or execution authority."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["HypothesisProposal"] = "HypothesisProposal"
    proposal_id: str = Field(default="", alias="proposalId", max_length=96)
    proposal_digest: str = Field(default="", alias="proposalDigest", max_length=64)
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    source_snapshot_id: Identifier = Field(alias="sourceSnapshotId")
    source_snapshot_digest: Sha256 = Field(alias="sourceSnapshotDigest")
    parent_hypothesis_id: Identifier = Field(alias="parentHypothesisId")
    ancestor_hypothesis_ids: tuple[Identifier, ...] = Field(
        alias="ancestorHypothesisIds",
        min_length=1,
        max_length=8,
    )
    target_id: Identifier = Field(alias="targetId")
    threat_class: str = Field(
        alias="threatClass",
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9.-]*$",
    )
    specialization: PentestSpecialization
    depth: int = Field(strict=True, ge=1, le=8)
    statement: str = Field(min_length=1, max_length=2_000)
    expected_observable: str = Field(alias="expectedObservable", min_length=1, max_length=2_000)
    required_evidence_types: tuple[Identifier, ...] = Field(
        alias="requiredEvidenceTypes",
        min_length=1,
        max_length=16,
    )
    estimate: ModelPathEstimate
    content_origin: Literal["model-derived-untrusted"] = Field(
        default="model-derived-untrusted",
        alias="contentOrigin",
    )
    model_content_is_untrusted: Literal[True] = Field(
        default=True,
        alias="modelContentIsUntrusted",
    )
    instruction_authority: Literal[False] = Field(default=False, alias="instructionAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(
        default=False,
        alias="graphAdmissionAuthority",
    )

    @field_validator("statement", "expected_observable")
    @classmethod
    def validate_text(cls, value: str, info: ValidationInfo) -> str:
        return _safe_text(value, label=info.field_name)

    @field_validator(
        "instruction_authority",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "finding_authority",
        "graph_admission_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @field_validator("model_content_is_untrusted", mode="before")
    @classmethod
    def require_true_marker(cls, value: object, info: ValidationInfo) -> object:
        return _literal_true(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        ancestors = _canonical_path(
            self.ancestor_hypothesis_ids,
            label="ancestor Hypothesis IDs",
        )
        if len(ancestors) != self.depth:
            raise ValueError("Hypothesis depth differs from its ancestor path")
        if ancestors[-1] != self.parent_hypothesis_id:
            raise ValueError("parent Hypothesis must be the final ancestor")
        _canonical_identifiers(
            self.required_evidence_types,
            label="required Evidence types",
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"proposal_id", "proposal_digest"},
        )
        digest = discovery_digest("pajin.agentic.hypothesis-proposal/v1", material)
        expected_id = f"hypothesis-proposal_{digest}"
        if self.proposal_digest and self.proposal_digest != digest:
            raise ValueError("Hypothesis Proposal Digest differs")
        if self.proposal_id and self.proposal_id != expected_id:
            raise ValueError("Hypothesis Proposal ID differs")
        object.__setattr__(self, "proposal_digest", digest)
        object.__setattr__(self, "proposal_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Hypothesis Proposal",
            max_bytes=64 * 1024,
        )
        return self


def _canonical_path(values: tuple[str, ...], *, label: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not repeat a node")
    if any(fullmatch(_IDENTIFIER_PATTERN, item) is None for item in values):
        raise ValueError(f"{label} contains a malformed identifier")
    return values


class AnalysisSkillReference(AgenticStrictModel):
    """Exact inert Skill identity supplied by the sole installed-registry consumer."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    skill_id: Identifier = Field(alias="skillId")
    skill_version: SkillVersion = Field(alias="skillVersion")
    skill_digest: Sha256 = Field(alias="skillDigest")
    instruction_digest: Sha256 = Field(alias="instructionDigest")
    input_schema_digest: Sha256 = Field(alias="inputSchemaDigest")
    output_schema_digest: Sha256 = Field(alias="outputSchemaDigest")


class SpecialistDefinition(AgenticStrictModel):
    """Code-owned routing metadata for one reusable campaign specialist."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    specialization: PentestSpecialization
    accepted_threat_classes: tuple[str, ...] = Field(
        alias="acceptedThreatClasses",
        min_length=1,
        max_length=16,
    )
    skill_refs: tuple[AnalysisSkillReference, ...] = Field(alias="skillRefs", max_length=16)
    max_sessions: int = Field(alias="maxSessions", strict=True, ge=1, le=16)
    scope_authority: Literal[False] = Field(default=False, alias="scopeAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("scope_authority", "execution_authority", mode="before")
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def validate_lists(self) -> Self:
        if self.accepted_threat_classes != tuple(sorted(set(self.accepted_threat_classes))):
            raise ValueError("accepted threat classes must be unique and sorted")
        if any(
            fullmatch(r"^[a-z0-9][a-z0-9.-]{1,79}$", item) is None
            for item in self.accepted_threat_classes
        ):
            raise ValueError("accepted threat class is malformed")
        skill_keys = tuple((item.skill_id, item.skill_version) for item in self.skill_refs)
        if skill_keys != tuple(sorted(set(skill_keys))):
            raise ValueError("Skill references must be unique and canonically sorted")
        return self


class ExploitGroupDefinition(AgenticStrictModel):
    """Immutable role roster; it grants no Campaign or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ExploitGroupDefinition"] = "ExploitGroupDefinition"
    group_id: str = Field(default="", alias="groupId", max_length=96)
    group_digest: str = Field(default="", alias="groupDigest", max_length=64)
    name: str = Field(min_length=3, max_length=100)
    specialists: tuple[SpecialistDefinition, ...] = Field(
        min_length=3,
        max_length=_MAX_SPECIALISTS,
    )
    max_active_sessions: int = Field(alias="maxActiveSessions", strict=True, ge=1, le=64)
    scope_authority: Literal[False] = Field(default=False, alias="scopeAuthority")
    capability_authority: Literal[False] = Field(default=False, alias="capabilityAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        return _safe_text(value, label="Exploit Group name")

    @field_validator(
        "scope_authority",
        "capability_authority",
        "permit_authority",
        "execution_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        order = tuple(item.specialization.value for item in self.specialists)
        if order != tuple(sorted(set(order))):
            raise ValueError("Exploit Group specialists must be unique and sorted")
        required = {
            PentestSpecialization.ATTACK_PATH_STRATEGIST,
            PentestSpecialization.VALIDATOR,
        }
        if not required <= {item.specialization for item in self.specialists}:
            raise ValueError("Exploit Group requires a strategist and independent validator")
        if self.max_active_sessions > sum(item.max_sessions for item in self.specialists):
            raise ValueError("Exploit Group active session limit exceeds its specialist capacity")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"group_id", "group_digest"},
        )
        digest = discovery_digest("pajin.agentic.exploit-group/v1", material)
        expected_id = f"exploit-group_{digest}"
        if self.group_digest and self.group_digest != digest:
            raise ValueError("Exploit Group Digest differs")
        if self.group_id and self.group_id != expected_id:
            raise ValueError("Exploit Group ID differs")
        object.__setattr__(self, "group_digest", digest)
        object.__setattr__(self, "group_id", expected_id)
        return self

    def specialist_for(
        self,
        specialization: PentestSpecialization,
        threat_class: str,
    ) -> SpecialistDefinition | None:
        for specialist in self.specialists:
            if (
                specialist.specialization is specialization
                and threat_class in specialist.accepted_threat_classes
            ):
                return specialist
        return None


class AgentSessionSnapshot(AgenticStrictModel):
    """Serializable campaign-local logical agent state."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    session_id: Identifier = Field(alias="sessionId")
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    parent_agent_id: Identifier = Field(alias="parentAgentId")
    specialization: PentestSpecialization
    state: AgentSessionState
    current_candidate_id: str | None = Field(
        default=None,
        alias="currentCandidateId",
        pattern=r"^frontier-candidate_[a-f0-9]{64}$",
    )
    current_task_id: Identifier | None = Field(default=None, alias="currentTaskId")
    completed_tasks: int = Field(default=0, alias="completedTasks", strict=True, ge=0)
    context_refs: tuple[ArtifactReference, ...] = Field(
        default=(),
        alias="contextRefs",
        max_length=_MAX_ARTIFACT_REFS,
    )

    @model_validator(mode="after")
    def validate_assignment(self) -> Self:
        assigned = self.current_candidate_id is not None or self.current_task_id is not None
        if (self.current_candidate_id is None) != (self.current_task_id is None):
            raise ValueError("agent assignment requires both Candidate and Task identities")
        if self.state is AgentSessionState.ASSIGNED and not assigned:
            raise ValueError("assigned agent session lacks an assignment")
        if self.state is not AgentSessionState.ASSIGNED and assigned:
            raise ValueError("only assigned agent sessions may retain an assignment")
        return self


class AgentControlCommand(AgenticStrictModel):
    """Trusted agent-lifecycle command that carries no external execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgentControlCommand"] = "AgentControlCommand"
    command_id: str = Field(default="", alias="commandId", max_length=96)
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    supervisor_agent_id: Identifier = Field(alias="supervisorAgentId")
    source_snapshot_id: Identifier = Field(alias="sourceSnapshotId")
    source_snapshot_digest: Sha256 = Field(alias="sourceSnapshotDigest")
    supervisor_policy_digest: Sha256 = Field(alias="supervisorPolicyDigest")
    sequence: int = Field(strict=True, ge=1)
    command: AgentControlCommandKind
    target_agent_id: Identifier = Field(alias="targetAgentId")
    specialization: PentestSpecialization
    task_id: Identifier | None = Field(default=None, alias="taskId")
    candidate_id: str | None = Field(
        default=None,
        alias="candidateId",
        pattern=r"^frontier-candidate_[a-f0-9]{64}$",
    )
    context_refs: tuple[ArtifactReference, ...] = Field(
        default=(),
        alias="contextRefs",
        max_length=_MAX_ARTIFACT_REFS,
    )
    command_state: Literal["compiled-agent-control-only"] = Field(
        default="compiled-agent-control-only",
        alias="commandState",
    )
    direct_peer_command: Literal[False] = Field(default=False, alias="directPeerCommand")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    tool_execution_authorized: Literal[False] = Field(
        default=False,
        alias="toolExecutionAuthorized",
    )

    @field_validator(
        "direct_peer_command",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "tool_execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        assignment = self.command in {
            AgentControlCommandKind.ASSIGN,
            AgentControlCommandKind.FOLLOW_UP,
        }
        if (self.task_id is None) != (self.candidate_id is None):
            raise ValueError(
                "Agent Control Command Task and Candidate identities must appear together"
            )
        if assignment != (self.task_id is not None):
            raise ValueError("assignment commands require exact Task and Candidate identities")
        material = self.model_dump(mode="json", by_alias=True, exclude={"command_id"})
        expected = "agent-command_" + discovery_digest(
            "pajin.agentic.agent-control-command/v1",
            material,
        )
        if self.command_id and self.command_id != expected:
            raise ValueError("Agent Control Command ID differs")
        object.__setattr__(self, "command_id", expected)
        return self


class AgentEvent(AgenticStrictModel):
    """Upward status/result envelope; text never becomes a command."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-campaign/v1alpha1"] = Field(
        default=AGENTIC_CAMPAIGN_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgentEvent"] = "AgentEvent"
    event_id: str = Field(default="", alias="eventId", max_length=96)
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    sequence: int = Field(strict=True, ge=1)
    agent_id: Identifier = Field(alias="agentId")
    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    event: AgentEventKind
    task_id: Identifier | None = Field(default=None, alias="taskId")
    candidate_id: str | None = Field(
        default=None,
        alias="candidateId",
        pattern=r"^frontier-candidate_[a-f0-9]{64}$",
    )
    summary: str = Field(min_length=1, max_length=1_000)
    summary_origin: Literal["agent-derived-untrusted"] = Field(
        default="agent-derived-untrusted",
        alias="summaryOrigin",
    )
    summary_is_untrusted: Literal[True] = Field(default=True, alias="summaryIsUntrusted")
    artifact_refs: tuple[ArtifactReference, ...] = Field(
        default=(),
        alias="artifactRefs",
        max_length=_MAX_ARTIFACT_REFS,
    )
    summary_authority: Literal[False] = Field(default=False, alias="summaryAuthority")
    instruction_authority: Literal[False] = Field(default=False, alias="instructionAuthority")
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("summary")
    @classmethod
    def validate_summary(cls, value: str) -> str:
        return _safe_text(value, label="Agent Event summary")

    @field_validator(
        "summary_authority",
        "instruction_authority",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @field_validator("summary_is_untrusted", mode="before")
    @classmethod
    def require_true_marker(cls, value: object, info: ValidationInfo) -> object:
        return _literal_true(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if (self.task_id is None) != (self.candidate_id is None):
            raise ValueError("Agent Event Task and Candidate identities must appear together")
        if self.event is AgentEventKind.ARTIFACT_READY and not self.artifact_refs:
            raise ValueError("artifact-ready Event requires at least one Artifact reference")
        material = self.model_dump(mode="json", by_alias=True, exclude={"event_id"})
        expected = "agent-event_" + discovery_digest(
            "pajin.agentic.agent-event/v1",
            material,
        )
        if self.event_id and self.event_id != expected:
            raise ValueError("Agent Event ID differs")
        object.__setattr__(self, "event_id", expected)
        return self


def build_web_exploit_group(
    *,
    attack_path_skill_ref: AnalysisSkillReference,
    authorization_skill_ref: AnalysisSkillReference,
    reporting_skill_ref: AnalysisSkillReference,
    sqli_skill_ref: AnalysisSkillReference,
    xss_skill_ref: AnalysisSkillReference,
) -> ExploitGroupDefinition:
    """Build the immutable roster from exact externally verified Skill references."""

    supplied = {
        "attack-path": attack_path_skill_ref,
        "authorization": authorization_skill_ref,
        "reporting": reporting_skill_ref,
        "sql-injection": sqli_skill_ref,
        "xss": xss_skill_ref,
    }
    expected = {
        "attack-path": ("pajin.skill.web.compose-attack-path", "1.1.0"),
        "authorization": ("pajin.skill.web.assess-object-access", "1.1.0"),
        "reporting": ("pajin.skill.web.write-security-finding", "1.0.0"),
        "sql-injection": ("pajin.skill.web.assess-sqli", "1.1.0"),
        "xss": ("pajin.skill.web.assess-xss", "1.1.0"),
    }
    canonical_refs: dict[str, AnalysisSkillReference] = {}
    for role, reference in supplied.items():
        canonical = AnalysisSkillReference.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
        if (canonical.skill_id, canonical.skill_version) != expected[role]:
            raise ValueError(f"{role} Skill reference differs from the installed roster")
        canonical_refs[role] = canonical
    if len({reference.skill_digest for reference in canonical_refs.values()}) != len(
        canonical_refs
    ):
        raise ValueError("Web Exploit Group Skill definitions must be distinct")

    definitions = (
        SpecialistDefinition(
            specialization=PentestSpecialization.API,
            acceptedThreatClasses=("api",),
            skillRefs=(),
            maxSessions=2,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.ATTACK_PATH_STRATEGIST,
            acceptedThreatClasses=("attack-path",),
            skillRefs=(canonical_refs["attack-path"],),
            maxSessions=1,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.AUTH_SESSION,
            acceptedThreatClasses=("authentication", "session"),
            skillRefs=(),
            maxSessions=2,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.AUTHORIZATION,
            acceptedThreatClasses=("authorization",),
            skillRefs=(canonical_refs["authorization"],),
            maxSessions=2,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.REPORTER,
            acceptedThreatClasses=("reporting",),
            skillRefs=(canonical_refs["reporting"],),
            maxSessions=1,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.VALIDATOR,
            acceptedThreatClasses=("validation",),
            skillRefs=(),
            maxSessions=2,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.RECON,
            acceptedThreatClasses=("recon",),
            skillRefs=(),
            maxSessions=1,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.SQL_INJECTION,
            acceptedThreatClasses=("sql-injection",),
            skillRefs=(canonical_refs["sql-injection"],),
            maxSessions=2,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.SSRF,
            acceptedThreatClasses=("ssrf",),
            skillRefs=(),
            maxSessions=2,
        ),
        SpecialistDefinition(
            specialization=PentestSpecialization.XSS,
            acceptedThreatClasses=("xss",),
            skillRefs=(canonical_refs["xss"],),
            maxSessions=2,
        ),
    )
    return ExploitGroupDefinition(
        name="Bounded Web Pentest Exploit Group",
        specialists=definitions,
        maxActiveSessions=8,
    )
