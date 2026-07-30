"""Evidence-bound observation graphs and one bounded deterministic replan."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from re import fullmatch
from typing import Literal, cast

from pydantic import Field, JsonValue, TypeAdapter, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.discovery.hypothesis import (
    AttackHypothesis,
    AttackHypothesisSet,
    DynamicHypothesisWaveRunner,
    HypothesisWaveError,
    HypothesisWaveOutcome,
    HypothesisWavePlan,
    SurfaceBoundPlan,
    SurfaceSnapshotAuthority,
)
from pajin.discovery.recon import ReconWaveOutcome
from pajin.domain.models import CampaignManifest, StrictModel, ToolResult
from pajin.runtime.control import (
    BudgetController,
    BudgetExceeded,
    ExecutionCancellationContext,
)
from pajin.runtime.error_safety import audit_safe_exception_type
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    load_verified_run_artifacts,
)
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.workflow.cancellation import (
    await_with_campaign_deadline,
    ensure_cancellation_context,
    record_engine_cleanup,
)

REPLANNING_API_VERSION = "pajin.dev/discovery-replanning/v1alpha1"
MULTI_WAVE_API_VERSION = "pajin.dev/deterministic-multi-wave/v1alpha1"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_OBSERVATION_ID_PATTERN = r"^hypothesis-observation_[a-f0-9]{64}$"
_RELATIONSHIP_ID_PATTERN = r"^observation-relationship_[a-f0-9]{64}$"
_GRAPH_ID_PATTERN = r"^observation-graph_[a-f0-9]{64}$"
_DECISION_ID_PATTERN = r"^replan-decision_[a-f0-9]{64}$"
_POLICY_ID_PATTERN = r"^bounded-replanning-policy_[a-f0-9]{64}$"
_COMPILER_STATE_ID_PATTERN = r"^deterministic-compiler-state_[a-f0-9]{64}$"
_MULTI_WAVE_AUTHORITY_ID_PATTERN = r"^deterministic-multi-wave-authority_[a-f0-9]{64}$"
_MAX_VALUE_BYTES = 64 * 1024
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
_MAX_GRAPH_ITEMS = 400

ObservationRelation = Literal[
    "new-surface",
    "supports",
    "contradicts",
    "enables",
    "depends-on",
]
HypothesisOutcomeRelation = Literal["supports", "contradicts"]
ReplanAction = Literal["execute-next-wave", "stop"]
ReplanReason = Literal[
    "transition-selected",
    "no-transition",
    "novelty-below-threshold",
    "repeated-state",
    "cycle-detected",
    "max-waves-reached",
]


class BoundedReplanningError(RuntimeError):
    """Raised when a bounded replan cannot preserve its fail-closed authority."""


def _safe_text(value: str, *, label: str) -> str:
    if value != value.strip():
        raise ValueError(f"{label} cannot contain surrounding whitespace")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError(f"{label} cannot contain control characters")
    return value


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _utc_wire(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _bounded_json_value(value: object) -> JsonValue:
    try:
        encoded = canonical_json_bytes(
            value,
            label="Observation rule expected value",
            max_bytes=_MAX_VALUE_BYTES,
        )
        return cast(JsonValue, json.loads(encoded))
    except (RecursionError, TypeError, ValueError) as exc:
        raise ValueError("Observation rule expected value must be bounded JSON") from exc


class RegisteredObservationRule(StrictModel):
    """Code-registered exact-field interpretation of one Hypothesis Tool result."""

    rule_id: str = Field(
        alias="ruleId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    source_hypothesis_rule_id: str = Field(
        alias="sourceHypothesisRuleId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    field_path: list[str] = Field(alias="fieldPath", min_length=1, max_length=10)
    expected_value: JsonValue = Field(alias="expectedValue")
    match_relation: HypothesisOutcomeRelation = Field(
        default="supports",
        alias="matchRelation",
    )
    mismatch_relation: HypothesisOutcomeRelation = Field(
        default="contradicts",
        alias="mismatchRelation",
    )

    @field_validator("field_path")
    @classmethod
    def validate_field_path(cls, value: list[str]) -> list[str]:
        if any(fullmatch(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$", part) is None for part in value):
            raise ValueError("Observation rule field path is malformed")
        return value

    @field_validator("expected_value", mode="before")
    @classmethod
    def validate_expected_value(cls, value: object) -> JsonValue:
        return _bounded_json_value(value)

    @model_validator(mode="after")
    def validate_relations(self) -> RegisteredObservationRule:
        if self.match_relation == self.mismatch_relation:
            raise ValueError("Observation rule match and mismatch relations must differ")
        return self

    def classify(
        self,
        hypothesis: AttackHypothesis,
        result: ToolResult,
    ) -> HypothesisOutcomeRelation:
        """Classify an exact registered result field without caller or LLM authority."""

        if hypothesis.rule_id != self.source_hypothesis_rule_id:
            raise BoundedReplanningError("Observation rule belongs to another Hypothesis rule")
        if result.tool_id != hypothesis.required_tool_id:
            raise BoundedReplanningError("Tool result differs from its Hypothesis authority")
        current: object = result.model_dump(mode="json")
        for part in self.field_path:
            if not isinstance(current, Mapping) or part not in current:
                raise BoundedReplanningError(
                    "registered Observation field is absent from the Tool result"
                )
            current = current[part]
        try:
            actual = canonical_json_bytes(
                current,
                label="Observed result field",
                max_bytes=_MAX_VALUE_BYTES,
            )
            expected = canonical_json_bytes(
                self.expected_value,
                label="Expected result field",
                max_bytes=_MAX_VALUE_BYTES,
            )
        except (RecursionError, TypeError, ValueError) as exc:
            raise BoundedReplanningError(
                "registered Observation field is not bounded JSON"
            ) from exc
        return self.match_relation if actual == expected else self.mismatch_relation


class RegisteredReplanTransition(StrictModel):
    """Code-registered mapping from one observed relation to one next Compiler."""

    transition_id: str = Field(
        alias="transitionId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    source_hypothesis_rule_id: str = Field(
        alias="sourceHypothesisRuleId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    required_relation: Literal["new-surface", "supports", "contradicts"] = Field(
        alias="requiredRelation"
    )
    next_compiler_id: str = Field(
        alias="nextCompilerId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    next_rule_ids: list[str] = Field(
        alias="nextRuleIds",
        min_length=1,
        max_length=100,
    )
    rationale: str = Field(min_length=1, max_length=2_000)

    @field_validator("next_rule_ids")
    @classmethod
    def validate_next_rule_ids(cls, value: list[str]) -> list[str]:
        if value != sorted(value) or len(value) != len(set(value)):
            raise ValueError("Replan transition rule IDs must be unique and sorted")
        if any(fullmatch(_IDENTIFIER_PATTERN, item) is None for item in value):
            raise ValueError("Replan transition rule ID is malformed")
        return value

    @field_validator("rationale")
    @classmethod
    def validate_rationale(cls, value: str) -> str:
        return _safe_text(value, label="Replan transition rationale")


class BoundedReplanningPolicy(StrictModel):
    """Runtime-owned limits for the deterministic two-or-three-wave baseline."""

    api_version: Literal["pajin.dev/discovery-replanning/v1alpha1"] = Field(
        default="pajin.dev/discovery-replanning/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["BoundedReplanningPolicy"] = "BoundedReplanningPolicy"
    policy_id: str = Field(default="", alias="policyId")
    max_waves: Literal[2, 3] = Field(default=2, alias="maxWaves")
    max_replans: Literal[1, 2] = Field(default=1, alias="maxReplans")
    novelty_threshold: float = Field(
        default=1.0,
        alias="noveltyThreshold",
        gt=0,
        le=1,
        allow_inf_nan=False,
    )

    @model_validator(mode="after")
    def validate_identity(self) -> BoundedReplanningPolicy:
        if self.max_replans != self.max_waves - 1:
            raise ValueError("Bounded Replanning max replans must equal max waves minus one")
        expected = "bounded-replanning-policy_" + discovery_digest(
            "pajin.discovery.bounded-replanning-policy/v1",
            {
                "maxWaves": self.max_waves,
                "maxReplans": self.max_replans,
                "noveltyThreshold": self.novelty_threshold,
            },
        )
        if not self.policy_id:
            self.policy_id = expected
        elif self.policy_id != expected:
            raise ValueError("Bounded Replanning Policy ID differs from canonical authority")
        if fullmatch(_POLICY_ID_PATTERN, self.policy_id) is None:
            raise ValueError("Bounded Replanning Policy ID is malformed")
        return self


class DeterministicCompilerState(StrictModel):
    """One fully compiled ORCH-001 Plan state eligible for a bounded follow-up."""

    api_version: Literal["pajin.dev/deterministic-multi-wave/v1alpha1"] = Field(
        default="pajin.dev/deterministic-multi-wave/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["DeterministicCompilerState"] = "DeterministicCompilerState"
    state_id: str = Field(default="", alias="stateId")
    compiler_id: str = Field(
        alias="compilerId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    rule_ids: list[str] = Field(alias="ruleIds", min_length=1, max_length=100)
    hypothesis_set_id: str = Field(
        alias="hypothesisSetId",
        pattern=r"^attack-hypothesis-set_[a-f0-9]{64}$",
    )
    wave_plan_id: str = Field(
        alias="wavePlanId",
        pattern=r"^hypothesis-wave-plan_[a-f0-9]{64}$",
    )
    surface_bound_plan: SurfaceBoundPlan = Field(alias="surfaceBoundPlan")

    @model_validator(mode="after")
    def validate_identity(self) -> DeterministicCompilerState:
        if self.rule_ids != sorted(self.rule_ids) or len(self.rule_ids) != len(set(self.rule_ids)):
            raise ValueError("Compiler State rule IDs must be unique and sorted")
        if any(fullmatch(_IDENTIFIER_PATTERN, item) is None for item in self.rule_ids):
            raise ValueError("Compiler State rule ID is malformed")
        if (
            self.surface_bound_plan.hypothesis_set_id != self.hypothesis_set_id
            or self.surface_bound_plan.wave_plan_id != self.wave_plan_id
        ):
            raise ValueError("Compiler State ORCH-001 Plan differs from its Hypothesis authority")
        expected = "deterministic-compiler-state_" + discovery_digest(
            "pajin.discovery.deterministic-compiler-state/v1",
            {
                "compilerId": self.compiler_id,
                "ruleIds": self.rule_ids,
                "hypothesisSetId": self.hypothesis_set_id,
                "wavePlanId": self.wave_plan_id,
                "surfaceBoundPlan": self.surface_bound_plan.model_dump(
                    mode="json",
                    by_alias=True,
                ),
            },
        )
        if not self.state_id:
            self.state_id = expected
        elif self.state_id != expected:
            raise ValueError("Compiler State ID differs from canonical authority")
        if fullmatch(_COMPILER_STATE_ID_PATTERN, self.state_id) is None:
            raise ValueError("Compiler State ID is malformed")
        return self


class DeterministicMultiWaveAuthority(StrictModel):
    """Complete immutable authority for one deterministic two-or-three-wave Run."""

    api_version: Literal["pajin.dev/deterministic-multi-wave/v1alpha1"] = Field(
        default="pajin.dev/deterministic-multi-wave/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["DeterministicMultiWaveAuthority"] = "DeterministicMultiWaveAuthority"
    authority_id: str = Field(default="", alias="authorityId")
    authority_digest: str = Field(default="", alias="authorityDigest")
    campaign_authority: CampaignManifest = Field(alias="campaignAuthority")
    surface_snapshot: SurfaceSnapshotAuthority = Field(alias="surfaceSnapshot")
    policy: BoundedReplanningPolicy
    compiler_states: list[DeterministicCompilerState] = Field(
        alias="compilerStates",
        min_length=1,
        max_length=3,
    )
    observation_rules: list[RegisteredObservationRule] = Field(
        alias="observationRules",
        min_length=1,
        max_length=100,
    )
    transitions: list[RegisteredReplanTransition] = Field(
        min_length=1,
        max_length=100,
    )

    @model_validator(mode="after")
    def validate_authority(self) -> DeterministicMultiWaveAuthority:
        if self.surface_snapshot.campaign != self.campaign_authority.metadata.name:
            raise ValueError("Multi-wave Surface Snapshot belongs to another Campaign")
        compiler_order = [item.compiler_id for item in self.compiler_states]
        if compiler_order != sorted(compiler_order) or len(compiler_order) != len(
            set(compiler_order)
        ):
            raise ValueError("Multi-wave Compiler States must be unique and sorted")
        observation_order = [item.source_hypothesis_rule_id for item in self.observation_rules]
        if observation_order != sorted(observation_order) or len(observation_order) != len(
            set(observation_order)
        ):
            raise ValueError("Multi-wave Observation rules must be unique and sorted")
        transition_order = [item.transition_id for item in self.transitions]
        if transition_order != sorted(transition_order) or len(transition_order) != len(
            set(transition_order)
        ):
            raise ValueError("Multi-wave transitions must be unique and sorted")

        states_by_compiler = {item.compiler_id: item for item in self.compiler_states}
        if any(
            item.surface_bound_plan.surface_snapshot != self.surface_snapshot
            for item in self.compiler_states
        ):
            raise ValueError("Multi-wave Compiler State expands or replaces the Surface Snapshot")
        known_rule_ids = {rule_id for state in self.compiler_states for rule_id in state.rule_ids}
        if not known_rule_ids <= set(observation_order):
            raise ValueError(
                "every Multi-wave Compiler rule requires Observation authority"
            )
        for transition in self.transitions:
            next_state = states_by_compiler.get(transition.next_compiler_id)
            if (
                transition.source_hypothesis_rule_id not in known_rule_ids
                or next_state is None
                or transition.next_rule_ids != next_state.rule_ids
            ):
                raise ValueError("Multi-wave transition differs from its Compiler State authority")

        payload = {
            "campaignAuthority": self.campaign_authority.model_dump(
                mode="json",
                by_alias=True,
            ),
            "surfaceSnapshot": self.surface_snapshot.model_dump(
                mode="json",
                by_alias=True,
            ),
            "policy": self.policy.model_dump(mode="json", by_alias=True),
            "compilerStates": [
                item.model_dump(mode="json", by_alias=True) for item in self.compiler_states
            ],
            "observationRules": [
                item.model_dump(mode="json", by_alias=True) for item in self.observation_rules
            ],
            "transitions": [
                item.model_dump(mode="json", by_alias=True) for item in self.transitions
            ],
        }
        expected_digest = discovery_digest(
            "pajin.discovery.deterministic-multi-wave-authority/v1",
            payload,
        )
        expected_id = f"deterministic-multi-wave-authority_{expected_digest}"
        if not self.authority_digest:
            self.authority_digest = expected_digest
        elif self.authority_digest != expected_digest:
            raise ValueError("Multi-wave Authority Digest differs from canonical authority")
        if not self.authority_id:
            self.authority_id = expected_id
        elif self.authority_id != expected_id:
            raise ValueError("Multi-wave Authority ID differs from canonical authority")
        if fullmatch(_MULTI_WAVE_AUTHORITY_ID_PATTERN, self.authority_id) is None:
            raise ValueError("Multi-wave Authority ID is malformed")
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Deterministic Multi-wave authority",
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        return self


class HypothesisObservation(StrictModel):
    """One sealed Tool result promoted into a deterministic graph observation."""

    api_version: Literal["pajin.dev/discovery-replanning/v1alpha1"] = Field(
        default="pajin.dev/discovery-replanning/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["HypothesisObservation"] = "HypothesisObservation"
    observation_id: str = Field(default="", alias="observationId")
    observation_rule_id: str = Field(
        alias="observationRuleId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    wave_index: int = Field(alias="waveIndex", ge=1, le=3)
    source_run_id: str = Field(
        alias="sourceRunId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    source_run_root_digest: str = Field(
        alias="sourceRunRootDigest",
        pattern=_SHA256_PATTERN,
    )
    hypothesis_set_id: str = Field(
        alias="hypothesisSetId",
        pattern=r"^attack-hypothesis-set_[a-f0-9]{64}$",
    )
    hypothesis_id: str = Field(
        alias="hypothesisId",
        pattern=r"^attack-hypothesis_[a-f0-9]{64}$",
    )
    surface_id: str = Field(
        alias="surfaceId",
        pattern=r"^attack-surface_[a-f0-9]{64}$",
    )
    request_id: str = Field(
        alias="requestId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$",
    )
    tool_id: str = Field(
        alias="toolId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    result_digest: str = Field(alias="resultDigest", pattern=_SHA256_PATTERN)
    relation: HypothesisOutcomeRelation
    observed_at: datetime = Field(alias="observedAt")

    @field_validator("observed_at")
    @classmethod
    def normalize_observed_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Hypothesis Observation observed_at")

    @model_validator(mode="after")
    def validate_identity(self) -> HypothesisObservation:
        expected = "hypothesis-observation_" + discovery_digest(
            "pajin.discovery.hypothesis-observation/v1",
            {
                "observationRuleId": self.observation_rule_id,
                "waveIndex": self.wave_index,
                "sourceRunId": self.source_run_id,
                "sourceRunRootDigest": self.source_run_root_digest,
                "hypothesisSetId": self.hypothesis_set_id,
                "hypothesisId": self.hypothesis_id,
                "surfaceId": self.surface_id,
                "requestId": self.request_id,
                "toolId": self.tool_id,
                "resultDigest": self.result_digest,
                "relation": self.relation,
                "observedAt": _utc_wire(self.observed_at),
            },
        )
        if not self.observation_id:
            self.observation_id = expected
        elif self.observation_id != expected:
            raise ValueError("Hypothesis Observation ID differs from canonical authority")
        if fullmatch(_OBSERVATION_ID_PATTERN, self.observation_id) is None:
            raise ValueError("Hypothesis Observation ID is malformed")
        return self


class ObservationRelationship(StrictModel):
    """A typed, code-attributed edge in one Observation Graph snapshot."""

    api_version: Literal["pajin.dev/discovery-replanning/v1alpha1"] = Field(
        default="pajin.dev/discovery-replanning/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ObservationRelationship"] = "ObservationRelationship"
    relationship_id: str = Field(default="", alias="relationshipId")
    source_id: str = Field(alias="sourceId", min_length=1, max_length=200)
    target_id: str = Field(alias="targetId", min_length=1, max_length=200)
    relation: ObservationRelation
    authority_id: str = Field(
        alias="authorityId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )

    @model_validator(mode="after")
    def validate_identity(self) -> ObservationRelationship:
        if self.source_id == self.target_id:
            raise ValueError("Observation relationship cannot be a self-edge")
        expected = "observation-relationship_" + discovery_digest(
            "pajin.discovery.observation-relationship/v1",
            {
                "sourceId": self.source_id,
                "targetId": self.target_id,
                "relation": self.relation,
                "authorityId": self.authority_id,
            },
        )
        if not self.relationship_id:
            self.relationship_id = expected
        elif self.relationship_id != expected:
            raise ValueError("Observation Relationship ID differs from canonical authority")
        if fullmatch(_RELATIONSHIP_ID_PATTERN, self.relationship_id) is None:
            raise ValueError("Observation Relationship ID is malformed")
        return self


class ObservationGraphSnapshot(StrictModel):
    """Append-only canonical graph state after one to three Hypothesis waves."""

    api_version: Literal["pajin.dev/discovery-replanning/v1alpha1"] = Field(
        default="pajin.dev/discovery-replanning/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ObservationGraphSnapshot"] = "ObservationGraphSnapshot"
    snapshot_id: str = Field(default="", alias="snapshotId")
    campaign: str = Field(
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    surface_set_id: str = Field(
        alias="surfaceSetId",
        pattern=r"^attack-surface-set_[a-f0-9]{64}$",
    )
    wave_count: int = Field(alias="waveCount", ge=1, le=3)
    previous_snapshot_id: str | None = Field(
        default=None,
        alias="previousSnapshotId",
        pattern=_GRAPH_ID_PATTERN,
    )
    surface_ids: list[str] = Field(
        alias="surfaceIds",
        min_length=1,
        max_length=_MAX_GRAPH_ITEMS,
    )
    hypothesis_set_ids: list[str] = Field(
        alias="hypothesisSetIds",
        min_length=1,
        max_length=3,
    )
    surface_bound_plan_digests: list[str] = Field(
        default_factory=list,
        alias="surfaceBoundPlanDigests",
        max_length=3,
    )
    hypothesis_ids: list[str] = Field(
        alias="hypothesisIds",
        min_length=1,
        max_length=_MAX_GRAPH_ITEMS,
    )
    observations: list[HypothesisObservation] = Field(
        min_length=1,
        max_length=_MAX_GRAPH_ITEMS,
    )
    relationships: list[ObservationRelationship] = Field(
        min_length=1,
        max_length=_MAX_GRAPH_ITEMS,
    )
    generated_at: datetime = Field(alias="generatedAt")

    @field_validator("generated_at")
    @classmethod
    def normalize_generated_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Observation Graph generated_at")

    @model_validator(mode="after")
    def validate_graph(self) -> ObservationGraphSnapshot:
        self._validate_collections()
        self._validate_relationships()
        payload = {
            "campaign": self.campaign,
            "surfaceSetId": self.surface_set_id,
            "waveCount": self.wave_count,
            "previousSnapshotId": self.previous_snapshot_id,
            "surfaceIds": self.surface_ids,
            "hypothesisSetIds": self.hypothesis_set_ids,
            "hypothesisIds": self.hypothesis_ids,
            "observations": [
                item.model_dump(mode="json", by_alias=True) for item in self.observations
            ],
            "relationships": [
                item.model_dump(mode="json", by_alias=True) for item in self.relationships
            ],
            "generatedAt": _utc_wire(self.generated_at),
        }
        identity_domain = "pajin.discovery.observation-graph-snapshot/v1"
        if self.surface_bound_plan_digests:
            payload["surfaceBoundPlanDigests"] = self.surface_bound_plan_digests
            identity_domain = "pajin.discovery.observation-graph-snapshot/v2"
        expected = "observation-graph_" + discovery_digest(identity_domain, payload)
        if not self.snapshot_id:
            self.snapshot_id = expected
        elif self.snapshot_id != expected:
            raise ValueError("Observation Graph ID differs from canonical authority")
        if fullmatch(_GRAPH_ID_PATTERN, self.snapshot_id) is None:
            raise ValueError("Observation Graph ID is malformed")
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Observation Graph",
            max_bytes=_MAX_ARTIFACT_BYTES,
        )
        return self

    def _validate_collections(self) -> None:
        if self.surface_ids != sorted(self.surface_ids) or len(self.surface_ids) != len(
            set(self.surface_ids)
        ):
            raise ValueError("Observation Graph Surface IDs must be unique and sorted")
        if self.hypothesis_ids != sorted(self.hypothesis_ids) or len(self.hypothesis_ids) != len(
            set(self.hypothesis_ids)
        ):
            raise ValueError("Observation Graph Hypothesis IDs must be unique and sorted")
        if len(self.hypothesis_set_ids) != self.wave_count or len(self.hypothesis_set_ids) != len(
            set(self.hypothesis_set_ids)
        ):
            raise ValueError("Observation Graph must bind one unique Hypothesis Set per wave")
        if self.surface_bound_plan_digests and (
            len(self.surface_bound_plan_digests) != self.wave_count
            or len(self.surface_bound_plan_digests) != len(set(self.surface_bound_plan_digests))
            or any(
                fullmatch(_SHA256_PATTERN, item) is None for item in self.surface_bound_plan_digests
            )
        ):
            raise ValueError("Observation Graph must bind one unique Surface-bound Plan per wave")
        if (self.wave_count == 1) != (self.previous_snapshot_id is None):
            raise ValueError("Observation Graph previous snapshot lineage is invalid")

        observation_order = [
            (observation.wave_index, observation.observation_id)
            for observation in self.observations
        ]
        if observation_order != sorted(observation_order) or len(
            {item.observation_id for item in self.observations}
        ) != len(self.observations):
            raise ValueError("Observation Graph observations must be unique and sorted")
        if {item.wave_index for item in self.observations} != set(range(1, self.wave_count + 1)):
            raise ValueError("Observation Graph must contain observations for every wave")
        if any(
            item.hypothesis_id not in self.hypothesis_ids
            or item.hypothesis_set_id not in self.hypothesis_set_ids
            or item.surface_id not in self.surface_ids
            or item.hypothesis_set_id != self.hypothesis_set_ids[item.wave_index - 1]
            for item in self.observations
        ):
            raise ValueError("Observation belongs outside the Graph authority")
        if self.generated_at != max(item.observed_at for item in self.observations):
            raise ValueError("Observation Graph time must equal its latest Observation")

    def _validate_relationships(self) -> None:
        relationship_ids = [item.relationship_id for item in self.relationships]
        if relationship_ids != sorted(relationship_ids) or len(relationship_ids) != len(
            set(relationship_ids)
        ):
            raise ValueError("Observation Graph relationships must be unique and sorted")
        observation_ids = {item.observation_id for item in self.observations}
        observations_by_id = {item.observation_id: item for item in self.observations}
        hypothesis_ids = set(self.hypothesis_ids)
        surface_ids = set(self.surface_ids)
        for relationship in self.relationships:
            if relationship.relation in {"supports", "contradicts", "enables"}:
                if (
                    relationship.source_id not in observation_ids
                    or relationship.target_id not in hypothesis_ids
                ):
                    raise ValueError("Observation-to-Hypothesis relationship is malformed")
                if relationship.relation in {"supports", "contradicts"}:
                    observation = observations_by_id[relationship.source_id]
                    if (
                        relationship.target_id != observation.hypothesis_id
                        or relationship.relation != observation.relation
                    ):
                        raise ValueError(
                            "Hypothesis outcome relationship differs from its Observation"
                        )
            elif relationship.relation == "new-surface":
                if (
                    relationship.source_id not in observation_ids
                    or relationship.target_id not in surface_ids
                ):
                    raise ValueError("new-surface relationship is malformed")
            elif (
                relationship.source_id not in hypothesis_ids
                or relationship.target_id not in hypothesis_ids
            ):
                raise ValueError("depends-on relationship is malformed")
        for observation in self.observations:
            outcome_edges = [
                item
                for item in self.relationships
                if item.source_id == observation.observation_id
                and item.relation in {"supports", "contradicts"}
            ]
            if len(outcome_edges) != 1:
                raise ValueError(
                    "Observation Graph requires one exact outcome edge per Observation"
                )


class ReplanDecision(StrictModel):
    """Canonical runtime decision to execute one next wave or stop."""

    api_version: Literal["pajin.dev/discovery-replanning/v1alpha1"] = Field(
        default="pajin.dev/discovery-replanning/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["ReplanDecision"] = "ReplanDecision"
    decision_id: str = Field(default="", alias="decisionId")
    policy_id: str = Field(alias="policyId", pattern=_POLICY_ID_PATTERN)
    graph_snapshot_id: str = Field(alias="graphSnapshotId", pattern=_GRAPH_ID_PATTERN)
    action: ReplanAction
    reason: ReplanReason
    completed_waves: int = Field(alias="completedWaves", ge=1, le=3)
    replan_count: int = Field(alias="replanCount", ge=0, le=2)
    novelty_score: float = Field(
        alias="noveltyScore",
        ge=0,
        le=1,
        allow_inf_nan=False,
    )
    novelty_threshold: float = Field(
        alias="noveltyThreshold",
        gt=0,
        le=1,
        allow_inf_nan=False,
    )
    max_waves: Literal[2, 3] = Field(default=2, alias="maxWaves")
    max_replans: Literal[1, 2] = Field(default=1, alias="maxReplans")
    transition_id: str | None = Field(
        default=None,
        alias="transitionId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    next_compiler_id: str | None = Field(
        default=None,
        alias="nextCompilerId",
        min_length=1,
        max_length=200,
        pattern=_IDENTIFIER_PATTERN,
    )
    next_rule_ids: list[str] = Field(
        default_factory=list,
        alias="nextRuleIds",
        max_length=100,
    )
    state_digest: str = Field(alias="stateDigest", pattern=_SHA256_PATTERN)
    multi_wave_authority_id: str | None = Field(
        default=None,
        alias="multiWaveAuthorityId",
        pattern=_MULTI_WAVE_AUTHORITY_ID_PATTERN,
    )
    multi_wave_authority_digest: str | None = Field(
        default=None,
        alias="multiWaveAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    decided_at: datetime = Field(alias="decidedAt")

    @field_validator("decided_at")
    @classmethod
    def normalize_decided_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Replan Decision decided_at")

    @model_validator(mode="after")
    def validate_decision(self) -> ReplanDecision:
        self._validate_semantics()
        payload = {
            "policyId": self.policy_id,
            "graphSnapshotId": self.graph_snapshot_id,
            "action": self.action,
            "reason": self.reason,
            "completedWaves": self.completed_waves,
            "replanCount": self.replan_count,
            "noveltyScore": self.novelty_score,
            "noveltyThreshold": self.novelty_threshold,
            "maxWaves": self.max_waves,
            "maxReplans": self.max_replans,
            "transitionId": self.transition_id,
            "nextCompilerId": self.next_compiler_id,
            "nextRuleIds": self.next_rule_ids,
            "stateDigest": self.state_digest,
            "decidedAt": _utc_wire(self.decided_at),
        }
        identity_domain = "pajin.discovery.replan-decision/v1"
        if self.multi_wave_authority_id is not None:
            payload["multiWaveAuthorityId"] = self.multi_wave_authority_id
            payload["multiWaveAuthorityDigest"] = self.multi_wave_authority_digest
            identity_domain = "pajin.discovery.replan-decision/v2"
        expected = "replan-decision_" + discovery_digest(identity_domain, payload)
        if not self.decision_id:
            self.decision_id = expected
        elif self.decision_id != expected:
            raise ValueError("Replan Decision ID differs from canonical authority")
        if fullmatch(_DECISION_ID_PATTERN, self.decision_id) is None:
            raise ValueError("Replan Decision ID is malformed")
        return self

    def _validate_semantics(self) -> None:
        if self.max_replans != self.max_waves - 1:
            raise ValueError("Replan Decision wave and replan limits disagree")
        if (self.multi_wave_authority_id is None) != (self.multi_wave_authority_digest is None):
            raise ValueError("Replan Decision Multi-wave authority is only partially bound")
        if self.next_rule_ids != sorted(self.next_rule_ids) or len(self.next_rule_ids) != len(
            set(self.next_rule_ids)
        ):
            raise ValueError("Replan Decision next rule IDs must be unique and sorted")
        if any(fullmatch(_IDENTIFIER_PATTERN, item) is None for item in self.next_rule_ids):
            raise ValueError("Replan Decision next rule ID is malformed")
        has_transition = (
            self.transition_id is not None
            and self.next_compiler_id is not None
            and bool(self.next_rule_ids)
        )
        if self.action == "execute-next-wave":
            self._validate_execute_shape(has_transition)
        elif self.reason == "max-waves-reached":
            self._validate_max_wave_stop(has_transition)
        elif self.reason == "no-transition":
            self._validate_no_transition_stop(has_transition)
        elif (
            self.reason not in {"novelty-below-threshold", "repeated-state", "cycle-detected"}
            or self.completed_waves >= self.max_waves
            or self.replan_count != self.completed_waves - 1
            or not has_transition
            or (
                self.reason == "novelty-below-threshold"
                and self.novelty_score >= self.novelty_threshold
            )
        ):
            raise ValueError("bounded Replan stop decision is malformed")

    def _validate_execute_shape(self, has_transition: bool) -> None:
        if (
            self.reason != "transition-selected"
            or not has_transition
            or self.completed_waves >= self.max_waves
            or self.replan_count != self.completed_waves
            or self.novelty_score < self.novelty_threshold
        ):
            raise ValueError("executable Replan Decision is not novel and bounded")

    def _validate_max_wave_stop(self, has_transition: bool) -> None:
        if (
            self.completed_waves != self.max_waves
            or self.replan_count != self.max_replans
            or has_transition
            or self.novelty_score != 0
        ):
            raise ValueError("final Replan stop decision is malformed")

    def _validate_no_transition_stop(self, has_transition: bool) -> None:
        if (
            self.completed_waves >= self.max_waves
            or self.replan_count != self.completed_waves - 1
            or has_transition
            or self.novelty_score != 0
        ):
            raise ValueError("no-transition Replan stop decision is malformed")


@dataclass(frozen=True, slots=True)
class BoundedReplanningOutcome:
    """Sealed deterministic multi-wave control result and follow-up waves."""

    run_id: str
    run_path: Path
    graphs: tuple[ObservationGraphSnapshot, ...]
    decisions: tuple[ReplanDecision, ...]
    next_wave: HypothesisWaveOutcome | None
    follow_up_waves: tuple[HypothesisWaveOutcome, ...] = ()
    authority: DeterministicMultiWaveAuthority | None = None


@dataclass(frozen=True, slots=True)
class _VerifiedHypothesisWave:
    root_digest: str
    hypothesis_set: AttackHypothesisSet
    plan: HypothesisWavePlan
    surface_bound_plan: SurfaceBoundPlan
    results: tuple[ToolResult, ...]


@dataclass(frozen=True, slots=True)
class _TransitionMatch:
    observation: HypothesisObservation
    source_hypothesis: AttackHypothesis
    transition: RegisteredReplanTransition


@dataclass(slots=True)
class _ReplanningState:
    budget: BudgetController
    rate_limits: RequestRateLimitLedger
    stage: str = "initialization"
    terminalized: bool = False


def _load_hypothesis_wave_authority(
    campaign: CampaignManifest,
    outcome: HypothesisWaveOutcome,
) -> _VerifiedHypothesisWave:
    if not isinstance(outcome, HypothesisWaveOutcome):
        raise BoundedReplanningError("Replanner requires a Hypothesis Wave outcome")
    try:
        snapshot = load_verified_run_artifacts(
            outcome.run_path,
            requests={
                "campaign.json": _MAX_ARTIFACT_BYTES,
                "hypothesis-set.json": _MAX_ARTIFACT_BYTES,
                "hypothesis-wave-plan.json": _MAX_ARTIFACT_BYTES,
                "surface-bound-plan.json": _MAX_ARTIFACT_BYTES,
                "hypothesis-results.json": _MAX_ARTIFACT_BYTES,
                "run.json": _MAX_ARTIFACT_BYTES,
            },
            expected_run_id=outcome.run_id,
        )
        stored_campaign = CampaignManifest.model_validate_json(
            snapshot.artifact_bytes("campaign.json")
        )
        hypothesis_set = AttackHypothesisSet.model_validate_json(
            snapshot.artifact_bytes("hypothesis-set.json")
        )
        plan = HypothesisWavePlan.model_validate_json(
            snapshot.artifact_bytes("hypothesis-wave-plan.json")
        )
        surface_bound_plan = SurfaceBoundPlan.model_validate_json(
            snapshot.artifact_bytes("surface-bound-plan.json")
        )
        results = tuple(
            TypeAdapter(list[ToolResult]).validate_json(
                snapshot.artifact_bytes("hypothesis-results.json")
            )
        )
        run_state = json.loads(snapshot.artifact_bytes("run.json"))
    except (KeyError, OSError, RunIntegrityError, TypeError, ValueError) as exc:
        raise BoundedReplanningError("Hypothesis Wave Run is not a valid sealed authority") from exc
    if stored_campaign != campaign:
        raise BoundedReplanningError("Hypothesis Wave belongs to another Campaign")
    if not isinstance(run_state, dict) or (
        run_state.get("runId") != outcome.run_id
        or run_state.get("status") != "completed"
        or run_state.get("purpose") != "dynamic-hypothesis-wave"
        or run_state.get("hypothesisSetId") != hypothesis_set.hypothesis_set_id
        or run_state.get("wavePlanId") != plan.wave_plan_id
        or run_state.get("surfaceSnapshotId") != surface_bound_plan.surface_snapshot.snapshot_id
        or run_state.get("surfaceSnapshotRevision") != surface_bound_plan.surface_snapshot.revision
        or run_state.get("surfaceSnapshotDigest")
        != surface_bound_plan.surface_snapshot.snapshot_digest
        or run_state.get("surfaceBoundPlanDigest") != surface_bound_plan.plan_digest
    ):
        raise BoundedReplanningError("Hypothesis Wave terminal state is not authoritative")
    if (
        hypothesis_set.compiler_id != plan.compiler_id
        or hypothesis_set.hypothesis_set_id != plan.hypothesis_set_id
        or surface_bound_plan.hypothesis_set_id != hypothesis_set.hypothesis_set_id
        or surface_bound_plan.wave_plan_id != plan.wave_plan_id
        or surface_bound_plan.surface_snapshot.campaign != hypothesis_set.campaign
        or surface_bound_plan.surface_snapshot.surface_set_id != hypothesis_set.surface_set_id
        or [item.hypothesis_id for item in hypothesis_set.hypotheses]
        != [item.hypothesis_id for item in plan.steps]
        or len(results) != len(plan.steps)
        or any(
            result.request_id != step.request.request_id
            or result.tool_id != step.request.tool_id
            or not result.success
            or result.error is not None
            or result.started_at.tzinfo is None
            or result.started_at.utcoffset() is None
            or result.finished_at.tzinfo is None
            or result.finished_at.utcoffset() is None
            or result.finished_at < result.started_at
            for step, result in zip(plan.steps, results, strict=True)
        )
    ):
        raise BoundedReplanningError("Hypothesis Wave artifacts disagree")
    compiled_events = [
        event
        for event in snapshot.events
        if event.event_type == "discovery.hypothesis-set.compiled"
        and event.payload.get("hypothesisSetId") == hypothesis_set.hypothesis_set_id
    ]
    completed_events = [
        event
        for event in snapshot.events
        if event.event_type == "discovery.hypothesis-wave.completed"
        and event.payload.get("wavePlanId") == plan.wave_plan_id
    ]
    if len(compiled_events) != 1 or len(completed_events) != 1:
        raise BoundedReplanningError("Hypothesis Wave audit authority is missing or ambiguous")
    expected_task_digests = [item.task_digest for item in surface_bound_plan.tasks]
    for event in (compiled_events[0], completed_events[0]):
        if (
            event.payload.get("surfaceSnapshotId")
            != surface_bound_plan.surface_snapshot.snapshot_id
            or event.payload.get("surfaceSnapshotRevision")
            != surface_bound_plan.surface_snapshot.revision
            or event.payload.get("surfaceSnapshotDigest")
            != surface_bound_plan.surface_snapshot.snapshot_digest
            or event.payload.get("surfaceBoundPlanDigest") != surface_bound_plan.plan_digest
            or event.payload.get("surfaceBoundTaskDigests") != expected_task_digests
        ):
            raise BoundedReplanningError("Hypothesis Wave ORCH-001 audit authority disagrees")
    if (
        outcome.run_path.resolve() != snapshot.run_path
        or outcome.hypothesis_set != hypothesis_set
        or outcome.plan != plan
        or outcome.surface_bound_plan != surface_bound_plan
        or outcome.tool_results != results
    ):
        raise BoundedReplanningError("Hypothesis Wave outcome differs from its sealed Run")
    return _VerifiedHypothesisWave(
        root_digest=snapshot.verification.root_digest,
        hypothesis_set=hypothesis_set.model_copy(deep=True),
        plan=plan.model_copy(deep=True),
        surface_bound_plan=surface_bound_plan.model_copy(deep=True),
        results=tuple(result.model_copy(deep=True) for result in results),
    )


class BoundedReplanningRunner:
    """Promote observations through a deterministic two-or-three-wave baseline."""

    def __init__(
        self,
        *,
        observation_rules: Sequence[RegisteredObservationRule],
        transitions: Sequence[RegisteredReplanTransition],
        next_wave: DynamicHypothesisWaveRunner | None = None,
        next_waves: Sequence[DynamicHypothesisWaveRunner] | None = None,
        output_root: Path,
        policy: BoundedReplanningPolicy | None = None,
    ) -> None:
        rules = [
            RegisteredObservationRule.model_validate(item.model_dump(mode="python"))
            for item in observation_rules
        ]
        if not rules:
            raise ValueError("Bounded Replanner requires registered Observation rules")
        source_rule_ids = [item.source_hypothesis_rule_id for item in rules]
        if len(source_rule_ids) != len(set(source_rule_ids)):
            raise ValueError("Observation rules must map each Hypothesis rule exactly once")
        registered_transitions = [
            RegisteredReplanTransition.model_validate(item.model_dump(mode="python"))
            for item in transitions
        ]
        if not registered_transitions:
            raise ValueError("Bounded Replanner requires registered transitions")
        transition_ids = [item.transition_id for item in registered_transitions]
        if len(transition_ids) != len(set(transition_ids)):
            raise ValueError("Replan transition IDs must be unique")
        if next_wave is not None and next_waves is not None:
            raise ValueError("configure either next_wave or next_waves, not both")
        configured_waves = (
            tuple(next_waves)
            if next_waves is not None
            else (() if next_wave is None else (next_wave,))
        )
        if not configured_waves or any(
            not isinstance(item, DynamicHypothesisWaveRunner) for item in configured_waves
        ):
            raise TypeError("Bounded Replanner requires one or two Dynamic Hypothesis Wave runners")
        resolved_policy = (
            policy.model_copy(deep=True) if policy is not None else BoundedReplanningPolicy()
        )
        if len(configured_waves) > resolved_policy.max_replans:
            raise ValueError("configured follow-up Waves exceed the Replanning policy")
        compiler_ids = [item.compiler_id for item in configured_waves]
        if len(compiler_ids) != len(set(compiler_ids)):
            raise ValueError("follow-up Wave Compiler IDs must be unique")
        waves_by_compiler = {item.compiler_id: item for item in configured_waves}
        if any(
            transition.next_compiler_id not in waves_by_compiler
            or transition.next_rule_ids
            != list(waves_by_compiler[transition.next_compiler_id].registered_rule_ids)
            for transition in registered_transitions
        ):
            raise ValueError("Replan transitions must match a configured next Compiler authority")
        if set(waves_by_compiler) != {item.next_compiler_id for item in registered_transitions}:
            raise ValueError("every configured follow-up Compiler must be transition-bound")
        observed_rule_ids = set(source_rule_ids)
        follow_up_rule_ids = {
            rule_id for wave in configured_waves for rule_id in wave.registered_rule_ids
        }
        transition_source_rule_ids = {
            item.source_hypothesis_rule_id for item in registered_transitions
        }
        if not (follow_up_rule_ids | transition_source_rule_ids) <= observed_rule_ids:
            raise ValueError(
                "every follow-up and transition source rule requires Observation authority"
            )
        self._observation_rules = tuple(
            sorted(rules, key=lambda item: item.source_hypothesis_rule_id)
        )
        self._transitions = tuple(
            sorted(registered_transitions, key=lambda item: item.transition_id)
        )
        self._next_waves = tuple(configured_waves)
        self._next_wave_by_compiler = waves_by_compiler
        self._output_root = output_root
        self._policy = resolved_policy

    async def run(
        self,
        campaign: CampaignManifest,
        recon: ReconWaveOutcome,
        initial_wave: HypothesisWaveOutcome,
        *,
        cancellation: ExecutionCancellationContext | None = None,
        budget: BudgetController | None = None,
        rate_limits: RequestRateLimitLedger | None = None,
    ) -> BoundedReplanningOutcome:
        authoritative_campaign = CampaignManifest.model_validate(
            campaign.model_dump(mode="python", by_alias=True)
        )
        if budget is not None and budget.budgets != authoritative_campaign.spec.budgets:
            raise ValueError("shared budget does not match the Campaign budget contract")
        if cancellation is not None and cancellation.binding is not None:
            raise ValueError("execution cancellation context is already bound to another Run")
        budget = budget or BudgetController(authoritative_campaign.spec.budgets)
        rate_limits = rate_limits or RequestRateLimitLedger()
        store = RunStore.create(self._output_root, authoritative_campaign.metadata.name)
        run_cancellation = (
            cancellation.fork_for_run(
                engine="bounded-replanning",
                run_id=store.run_id,
                path=store.path,
            )
            if cancellation is not None
            else None
        )
        state = _ReplanningState(budget=budget, rate_limits=rate_limits)
        try:
            (
                graphs,
                decisions,
                follow_up_waves,
                authority,
            ) = await await_with_campaign_deadline(
                self._execute(
                    authoritative_campaign,
                    recon,
                    initial_wave,
                    store,
                    state,
                    cancellation,
                ),
                budget,
                run_cancellation,
            )
        except asyncio.CancelledError as exc:
            context = ensure_cancellation_context(
                run_cancellation,
                engine="bounded-replanning",
                store=store,
            )
            receipt = record_engine_cleanup(store, context)
            self._terminalize(
                store,
                state,
                status="cancelled",
                error_type=audit_safe_exception_type(exc),
                cancellation_receipt=receipt,
            )
            raise
        except BudgetExceeded as exc:
            self._terminalize(
                store,
                state,
                status="budget-exhausted",
                error_type=audit_safe_exception_type(exc),
            )
            raise
        except Exception as exc:
            self._terminalize(
                store,
                state,
                status="failed",
                error_type=audit_safe_exception_type(exc),
            )
            raise
        return BoundedReplanningOutcome(
            run_id=store.run_id,
            run_path=store.path,
            graphs=tuple(item.model_copy(deep=True) for item in graphs),
            decisions=tuple(item.model_copy(deep=True) for item in decisions),
            next_wave=follow_up_waves[0] if follow_up_waves else None,
            follow_up_waves=tuple(follow_up_waves),
            authority=authority.model_copy(deep=True),
        )

    async def _execute(
        self,
        campaign: CampaignManifest,
        recon: ReconWaveOutcome,
        initial_wave: HypothesisWaveOutcome,
        store: RunStore,
        state: _ReplanningState,
        cancellation: ExecutionCancellationContext | None,
    ) -> tuple[
        list[ObservationGraphSnapshot],
        list[ReplanDecision],
        list[HypothesisWaveOutcome],
        DeterministicMultiWaveAuthority,
    ]:
        store.append_event(
            "campaign.started",
            {
                "campaign": campaign.metadata.name,
                "mode": campaign.spec.mode.value,
                "purpose": "bounded-replanning",
            },
        )
        store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
        store.write_json(
            "replanning-policy.json",
            self._policy.model_dump(mode="json", by_alias=True),
        )
        store.write_json(
            "observation-rules.json",
            [item.model_dump(mode="json", by_alias=True) for item in self._observation_rules],
        )
        store.write_json(
            "replan-transitions.json",
            [item.model_dump(mode="json", by_alias=True) for item in self._transitions],
        )

        state.stage = "initial-wave-verification"
        initial = _load_hypothesis_wave_authority(campaign, initial_wave)
        if initial.hypothesis_set.surface_set_id != recon.surface_set.surface_set_id:
            raise BoundedReplanningError("initial Hypothesis Wave and Recon projection disagree")
        authority = self._build_authority(campaign, recon, initial)
        self._record_authority(store, authority)
        graph = self._graph_for_wave(
            campaign=campaign,
            verified=initial,
            run_id=initial_wave.run_id,
            wave_index=1,
            previous=None,
        )
        self._record_graph(store, graph)

        graphs = [graph]
        decisions: list[ReplanDecision] = []
        follow_up_waves: list[HypothesisWaveOutcome] = []
        verified = initial
        seen_run_ids = {initial_wave.run_id}
        seen_state_digests = [
            self._next_plan_state_digest(
                authority.surface_snapshot,
                self._compiler_state(
                    authority,
                    initial.hypothesis_set.compiler_id,
                    sorted({item.rule_id for item in initial.hypothesis_set.hypotheses}),
                ),
            )
        ]

        while True:
            graph = graphs[-1]
            state.stage = "replan-decision"
            self._require_current_authority(campaign, recon, initial, authority)
            if graph.wave_count == self._policy.max_waves:
                decision = self._decision(
                    authority=authority,
                    graph=graph,
                    action="stop",
                    reason="max-waves-reached",
                    replan_count=len(follow_up_waves),
                    novelty_score=0,
                    state_digest=self._graph_state_digest(graph),
                )
                self._record_decision(store, decision)
                decisions.append(decision)
                self._complete(
                    store,
                    state,
                    authority,
                    graphs,
                    decisions,
                    follow_up_waves,
                )
                return graphs, decisions, follow_up_waves, authority

            match = self._select_transition(verified, graph)
            if match is None:
                decision = self._decision(
                    authority=authority,
                    graph=graph,
                    action="stop",
                    reason="no-transition",
                    replan_count=len(follow_up_waves),
                    novelty_score=0,
                    state_digest=self._graph_state_digest(graph),
                )
                self._record_decision(store, decision)
                decisions.append(decision)
                self._complete(
                    store,
                    state,
                    authority,
                    graphs,
                    decisions,
                    follow_up_waves,
                )
                return graphs, decisions, follow_up_waves, authority

            transition = match.transition
            novelty_score = self._novelty_score(verified, transition)
            next_compiler_state = self._compiler_state(
                authority,
                transition.next_compiler_id,
                transition.next_rule_ids,
            )
            next_state_digest = self._next_plan_state_digest(
                authority.surface_snapshot,
                next_compiler_state,
            )
            if next_state_digest == seen_state_digests[-1]:
                stop_reason: ReplanReason = "repeated-state"
            elif next_state_digest in seen_state_digests:
                stop_reason = "cycle-detected"
            elif novelty_score < self._policy.novelty_threshold:
                stop_reason = "novelty-below-threshold"
            else:
                stop_reason = "transition-selected"

            if stop_reason != "transition-selected":
                decision = self._decision(
                    authority=authority,
                    graph=graph,
                    action="stop",
                    reason=stop_reason,
                    replan_count=len(follow_up_waves),
                    novelty_score=novelty_score,
                    state_digest=next_state_digest,
                    transition=transition,
                )
                self._record_decision(store, decision)
                decisions.append(decision)
                self._complete(
                    store,
                    state,
                    authority,
                    graphs,
                    decisions,
                    follow_up_waves,
                )
                return graphs, decisions, follow_up_waves, authority

            next_runner = self._next_wave_by_compiler[transition.next_compiler_id]
            if list(next_runner.registered_rule_ids) != transition.next_rule_ids:
                raise BoundedReplanningError("next Compiler drifted from the Multi-wave authority")
            execute_decision = self._decision(
                authority=authority,
                graph=graph,
                action="execute-next-wave",
                reason="transition-selected",
                replan_count=len(follow_up_waves) + 1,
                novelty_score=novelty_score,
                state_digest=next_state_digest,
                transition=transition,
            )
            self._record_decision(store, execute_decision)
            decisions.append(execute_decision)
            store.append_event(
                "discovery.replan.wave-dispatched",
                {
                    "decisionId": execute_decision.decision_id,
                    "multiWaveAuthorityId": authority.authority_id,
                    "multiWaveAuthorityDigest": authority.authority_digest,
                    "sourceSurfaceBoundPlanDigest": (verified.surface_bound_plan.plan_digest),
                    "transitionId": transition.transition_id,
                    "nextCompilerId": transition.next_compiler_id,
                    "nextRuleIds": transition.next_rule_ids,
                    "nextSurfaceBoundPlanDigest": (
                        next_compiler_state.surface_bound_plan.plan_digest
                    ),
                    "waveIndex": graph.wave_count + 1,
                },
            )

            state.stage = f"wave-{graph.wave_count + 1}-execution"
            next_outcome = await next_runner.run(
                campaign,
                recon,
                cancellation=cancellation,
                budget=state.budget,
                rate_limits=state.rate_limits,
            )
            state.stage = f"wave-{graph.wave_count + 1}-verification"
            next_verified = _load_hypothesis_wave_authority(campaign, next_outcome)
            next_rules = sorted({item.rule_id for item in next_verified.hypothesis_set.hypotheses})
            if (
                next_verified.hypothesis_set.compiler_id != transition.next_compiler_id
                or next_rules != transition.next_rule_ids
                or next_verified.surface_bound_plan.surface_snapshot != authority.surface_snapshot
                or next_verified.hypothesis_set.hypothesis_set_id
                != next_compiler_state.hypothesis_set_id
                or next_verified.plan.wave_plan_id != next_compiler_state.wave_plan_id
                or next_verified.surface_bound_plan != next_compiler_state.surface_bound_plan
                or next_outcome.run_id in seen_run_ids
            ):
                raise BoundedReplanningError(
                    "next Hypothesis Wave expands or differs from the Replan authority"
                )

            next_graph = self._graph_for_wave(
                campaign=campaign,
                verified=next_verified,
                run_id=next_outcome.run_id,
                wave_index=graph.wave_count + 1,
                previous=graph,
                transition_match=match,
            )
            self._record_graph(store, next_graph)
            graphs.append(next_graph)
            follow_up_waves.append(next_outcome)
            seen_run_ids.add(next_outcome.run_id)
            seen_state_digests.append(next_state_digest)
            verified = next_verified

    def _build_authority(
        self,
        campaign: CampaignManifest,
        recon: ReconWaveOutcome,
        initial: _VerifiedHypothesisWave,
    ) -> DeterministicMultiWaveAuthority:
        states_by_compiler: dict[str, DeterministicCompilerState] = {}

        def add_state(
            hypothesis_set: AttackHypothesisSet,
            plan: HypothesisWavePlan,
            surface_bound_plan: SurfaceBoundPlan,
        ) -> None:
            if surface_bound_plan.surface_snapshot != initial.surface_bound_plan.surface_snapshot:
                raise BoundedReplanningError(
                    "follow-up Compiler expands or replaces the Surface Snapshot"
                )
            state = DeterministicCompilerState(
                compilerId=hypothesis_set.compiler_id,
                ruleIds=sorted({item.rule_id for item in hypothesis_set.hypotheses}),
                hypothesisSetId=hypothesis_set.hypothesis_set_id,
                wavePlanId=plan.wave_plan_id,
                surfaceBoundPlan=surface_bound_plan.model_copy(deep=True),
            )
            current = states_by_compiler.get(hypothesis_set.compiler_id)
            if current is not None and current != state:
                raise BoundedReplanningError(
                    "one Compiler ID maps to multiple deterministic states"
                )
            states_by_compiler[hypothesis_set.compiler_id] = state

        add_state(
            initial.hypothesis_set,
            initial.plan,
            initial.surface_bound_plan,
        )
        try:
            for wave in self._next_waves:
                compiled = wave.compile_authority(campaign, recon)
                if compiled.hypothesis_set.compiler_id != wave.compiler_id or sorted(
                    {item.rule_id for item in compiled.hypothesis_set.hypotheses}
                ) != list(wave.registered_rule_ids):
                    raise BoundedReplanningError(
                        "follow-up Compiler preview differs from its registration"
                    )
                add_state(
                    compiled.hypothesis_set,
                    compiled.plan,
                    compiled.surface_bound_plan,
                )
            return DeterministicMultiWaveAuthority(
                campaignAuthority=campaign.model_copy(deep=True),
                surfaceSnapshot=(initial.surface_bound_plan.surface_snapshot.model_copy(deep=True)),
                policy=self._policy.model_copy(deep=True),
                compilerStates=sorted(
                    states_by_compiler.values(),
                    key=lambda item: item.compiler_id,
                ),
                observationRules=[item.model_copy(deep=True) for item in self._observation_rules],
                transitions=[item.model_copy(deep=True) for item in self._transitions],
            )
        except (HypothesisWaveError, TypeError, ValueError) as exc:
            raise BoundedReplanningError("deterministic Multi-wave authority is invalid") from exc

    def _require_current_authority(
        self,
        campaign: CampaignManifest,
        recon: ReconWaveOutcome,
        initial: _VerifiedHypothesisWave,
        authority: DeterministicMultiWaveAuthority,
    ) -> None:
        if self._build_authority(campaign, recon, initial) != authority:
            raise BoundedReplanningError(
                "deterministic Multi-wave authority changed before decision"
            )

    @staticmethod
    def _compiler_state(
        authority: DeterministicMultiWaveAuthority,
        compiler_id: str,
        rule_ids: Sequence[str],
    ) -> DeterministicCompilerState:
        matches = [
            item
            for item in authority.compiler_states
            if item.compiler_id == compiler_id and item.rule_ids == list(rule_ids)
        ]
        if len(matches) != 1:
            raise BoundedReplanningError(
                "Compiler state is absent or ambiguous in Multi-wave authority"
            )
        return matches[0]

    @staticmethod
    def _record_authority(
        store: RunStore,
        authority: DeterministicMultiWaveAuthority,
    ) -> None:
        store.write_json(
            "deterministic-multi-wave-authority.json",
            authority.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "discovery.multi-wave.authority-bound",
            {
                "authorityId": authority.authority_id,
                "authorityDigest": authority.authority_digest,
                "policyId": authority.policy.policy_id,
                "maxWaves": authority.policy.max_waves,
                "maxReplans": authority.policy.max_replans,
                "surfaceSnapshotId": authority.surface_snapshot.snapshot_id,
                "surfaceSnapshotRevision": authority.surface_snapshot.revision,
                "surfaceSnapshotDigest": authority.surface_snapshot.snapshot_digest,
                "compilerStateIds": [item.state_id for item in authority.compiler_states],
                "artifact": "deterministic-multi-wave-authority.json",
            },
        )

    def _observations(
        self,
        verified: _VerifiedHypothesisWave,
        *,
        run_id: str,
        wave_index: int,
    ) -> list[HypothesisObservation]:
        rules = {item.source_hypothesis_rule_id: item for item in self._observation_rules}
        hypotheses = {item.hypothesis_id: item for item in verified.hypothesis_set.hypotheses}
        observations: list[HypothesisObservation] = []
        for step, result in zip(verified.plan.steps, verified.results, strict=True):
            hypothesis = hypotheses[step.hypothesis_id]
            rule = rules.get(hypothesis.rule_id)
            if rule is None:
                raise BoundedReplanningError("Hypothesis result has no registered Observation rule")
            result_payload = result.model_dump(mode="json")
            observations.append(
                HypothesisObservation(
                    observationRuleId=rule.rule_id,
                    waveIndex=wave_index,
                    sourceRunId=run_id,
                    sourceRunRootDigest=verified.root_digest,
                    hypothesisSetId=verified.hypothesis_set.hypothesis_set_id,
                    hypothesisId=hypothesis.hypothesis_id,
                    surfaceId=hypothesis.surface_id,
                    requestId=result.request_id,
                    toolId=result.tool_id,
                    resultDigest=discovery_digest(
                        "pajin.discovery.hypothesis-tool-result/v1",
                        result_payload,
                    ),
                    relation=rule.classify(hypothesis, result),
                    observedAt=result.finished_at,
                )
            )
        return sorted(observations, key=lambda item: (item.wave_index, item.observation_id))

    def _graph_for_wave(
        self,
        *,
        campaign: CampaignManifest,
        verified: _VerifiedHypothesisWave,
        run_id: str,
        wave_index: int,
        previous: ObservationGraphSnapshot | None,
        transition_match: _TransitionMatch | None = None,
    ) -> ObservationGraphSnapshot:
        new_observations = self._observations(
            verified,
            run_id=run_id,
            wave_index=wave_index,
        )
        new_relationships = [
            ObservationRelationship(
                sourceId=observation.observation_id,
                targetId=observation.hypothesis_id,
                relation=observation.relation,
                authorityId=observation.observation_rule_id,
            )
            for observation in new_observations
        ]
        if previous is None:
            observations = new_observations
            relationships = new_relationships
            hypothesis_set_ids = [verified.hypothesis_set.hypothesis_set_id]
            surface_bound_plan_digests = [verified.surface_bound_plan.plan_digest]
            hypothesis_ids = [item.hypothesis_id for item in verified.hypothesis_set.hypotheses]
            surface_ids = [item.surface_id for item in verified.hypothesis_set.hypotheses]
        else:
            if transition_match is None:
                raise BoundedReplanningError(
                    "follow-up Observation Graph requires its transition authority"
                )
            observations = [
                item.model_copy(deep=True) for item in previous.observations
            ] + new_observations
            relationships = [
                item.model_copy(deep=True) for item in previous.relationships
            ] + new_relationships
            for hypothesis in verified.hypothesis_set.hypotheses:
                relationships.extend(
                    [
                        ObservationRelationship(
                            sourceId=transition_match.observation.observation_id,
                            targetId=hypothesis.hypothesis_id,
                            relation="enables",
                            authorityId=transition_match.transition.transition_id,
                        ),
                        ObservationRelationship(
                            sourceId=hypothesis.hypothesis_id,
                            targetId=transition_match.source_hypothesis.hypothesis_id,
                            relation="depends-on",
                            authorityId=transition_match.transition.transition_id,
                        ),
                    ]
                )
            hypothesis_set_ids = [
                *previous.hypothesis_set_ids,
                verified.hypothesis_set.hypothesis_set_id,
            ]
            surface_bound_plan_digests = [
                *previous.surface_bound_plan_digests,
                verified.surface_bound_plan.plan_digest,
            ]
            hypothesis_ids = previous.hypothesis_ids + [
                item.hypothesis_id for item in verified.hypothesis_set.hypotheses
            ]
            surface_ids = previous.surface_ids + [
                item.surface_id for item in verified.hypothesis_set.hypotheses
            ]
        return ObservationGraphSnapshot(
            campaign=campaign.metadata.name,
            surfaceSetId=verified.hypothesis_set.surface_set_id,
            waveCount=wave_index,
            previousSnapshotId=previous.snapshot_id if previous is not None else None,
            surfaceIds=sorted(set(surface_ids)),
            hypothesisSetIds=hypothesis_set_ids,
            surfaceBoundPlanDigests=surface_bound_plan_digests,
            hypothesisIds=sorted(set(hypothesis_ids)),
            observations=sorted(
                observations,
                key=lambda item: (item.wave_index, item.observation_id),
            ),
            relationships=sorted(
                relationships,
                key=lambda item: item.relationship_id,
            ),
            generatedAt=max(item.observed_at for item in observations),
        )

    def _select_transition(
        self,
        verified: _VerifiedHypothesisWave,
        graph: ObservationGraphSnapshot,
    ) -> _TransitionMatch | None:
        hypotheses = {item.hypothesis_id: item for item in verified.hypothesis_set.hypotheses}
        matches: list[_TransitionMatch] = []
        for observation in graph.observations:
            if observation.wave_index != graph.wave_count:
                continue
            hypothesis = hypotheses[observation.hypothesis_id]
            for transition in self._transitions:
                if (
                    transition.source_hypothesis_rule_id == hypothesis.rule_id
                    and transition.required_relation == observation.relation
                ):
                    matches.append(
                        _TransitionMatch(
                            observation=observation,
                            source_hypothesis=hypothesis,
                            transition=transition,
                        )
                    )
        if len(matches) > 1:
            raise BoundedReplanningError("Replan transition authority is ambiguous")
        return matches[0] if matches else None

    @staticmethod
    def _novelty_score(
        verified: _VerifiedHypothesisWave,
        transition: RegisteredReplanTransition,
    ) -> float:
        current_rule_ids = {item.rule_id for item in verified.hypothesis_set.hypotheses}
        novel_count = sum(item not in current_rule_ids for item in transition.next_rule_ids)
        return novel_count / len(transition.next_rule_ids)

    @staticmethod
    def _next_plan_state_digest(
        surface_snapshot: SurfaceSnapshotAuthority,
        compiler_state: DeterministicCompilerState,
    ) -> str:
        return discovery_digest(
            "pajin.discovery.replan-plan-state/v2",
            {
                "surfaceSnapshotId": surface_snapshot.snapshot_id,
                "surfaceSnapshotRevision": surface_snapshot.revision,
                "surfaceSnapshotDigest": surface_snapshot.snapshot_digest,
                "compilerStateId": compiler_state.state_id,
                "surfaceBoundPlanDigest": (compiler_state.surface_bound_plan.plan_digest),
            },
        )

    @staticmethod
    def _graph_state_digest(graph: ObservationGraphSnapshot) -> str:
        return discovery_digest(
            "pajin.discovery.replan-graph-state/v1",
            {"snapshotId": graph.snapshot_id},
        )

    def _decision(
        self,
        *,
        authority: DeterministicMultiWaveAuthority,
        graph: ObservationGraphSnapshot,
        action: ReplanAction,
        reason: ReplanReason,
        replan_count: int,
        novelty_score: float,
        state_digest: str,
        transition: RegisteredReplanTransition | None = None,
    ) -> ReplanDecision:
        return ReplanDecision(
            policyId=self._policy.policy_id,
            graphSnapshotId=graph.snapshot_id,
            action=action,
            reason=reason,
            completedWaves=graph.wave_count,
            replanCount=replan_count,
            noveltyScore=novelty_score,
            noveltyThreshold=self._policy.novelty_threshold,
            maxWaves=self._policy.max_waves,
            maxReplans=self._policy.max_replans,
            transitionId=transition.transition_id if transition is not None else None,
            nextCompilerId=(transition.next_compiler_id if transition is not None else None),
            nextRuleIds=transition.next_rule_ids if transition is not None else [],
            stateDigest=state_digest,
            multiWaveAuthorityId=authority.authority_id,
            multiWaveAuthorityDigest=authority.authority_digest,
            decidedAt=graph.generated_at,
        )

    @staticmethod
    def _record_graph(store: RunStore, graph: ObservationGraphSnapshot) -> None:
        path = f"observation-graph-wave-{graph.wave_count}.json"
        store.write_json(path, graph.model_dump(mode="json", by_alias=True))
        store.append_event(
            "discovery.observation-graph.snapshotted",
            {
                "snapshotId": graph.snapshot_id,
                "previousSnapshotId": graph.previous_snapshot_id,
                "waveCount": graph.wave_count,
                "surfaceBoundPlanDigests": graph.surface_bound_plan_digests,
                "observationCount": len(graph.observations),
                "relationshipCount": len(graph.relationships),
                "artifact": path,
            },
        )

    @staticmethod
    def _record_decision(store: RunStore, decision: ReplanDecision) -> None:
        path = f"replan-decision-wave-{decision.completed_waves}.json"
        store.write_json(path, decision.model_dump(mode="json", by_alias=True))
        store.append_event(
            "discovery.replan.decided",
            {
                "decisionId": decision.decision_id,
                "graphSnapshotId": decision.graph_snapshot_id,
                "action": decision.action,
                "reason": decision.reason,
                "completedWaves": decision.completed_waves,
                "replanCount": decision.replan_count,
                "noveltyScore": decision.novelty_score,
                "stateDigest": decision.state_digest,
                "multiWaveAuthorityId": decision.multi_wave_authority_id,
                "multiWaveAuthorityDigest": decision.multi_wave_authority_digest,
                "artifact": path,
            },
        )

    def _complete(
        self,
        store: RunStore,
        state: _ReplanningState,
        authority: DeterministicMultiWaveAuthority,
        graphs: Sequence[ObservationGraphSnapshot],
        decisions: Sequence[ReplanDecision],
        follow_up_waves: Sequence[HypothesisWaveOutcome],
    ) -> None:
        state.stage = "replanning-finalization"
        self._write_state(
            store,
            state,
            status="completed",
            extra={
                "waveCount": graphs[-1].wave_count,
                "replanCount": sum(item.action == "execute-next-wave" for item in decisions),
                "finalGraphSnapshotId": graphs[-1].snapshot_id,
                "finalDecisionId": decisions[-1].decision_id,
                "nextWaveRunId": (follow_up_waves[0].run_id if follow_up_waves else None),
                "followUpWaveRunIds": [item.run_id for item in follow_up_waves],
                "multiWaveAuthorityId": authority.authority_id,
                "multiWaveAuthorityDigest": authority.authority_digest,
                "surfaceSnapshotId": authority.surface_snapshot.snapshot_id,
                "surfaceSnapshotRevision": authority.surface_snapshot.revision,
                "surfaceSnapshotDigest": authority.surface_snapshot.snapshot_digest,
                "surfaceBoundPlanDigests": (graphs[-1].surface_bound_plan_digests),
            },
        )
        store.append_event(
            "discovery.replanning.completed",
            {
                "waveCount": graphs[-1].wave_count,
                "replanCount": sum(item.action == "execute-next-wave" for item in decisions),
                "finalDecisionId": decisions[-1].decision_id,
                "multiWaveAuthorityId": authority.authority_id,
                "multiWaveAuthorityDigest": authority.authority_digest,
                "surfaceBoundPlanDigests": (graphs[-1].surface_bound_plan_digests),
            },
        )
        store.append_event(
            "campaign.completed",
            {
                "purpose": "bounded-replanning",
                "finalDecisionId": decisions[-1].decision_id,
                "multiWaveAuthorityId": authority.authority_id,
            },
        )
        state.terminalized = True
        store.seal()

    @staticmethod
    def _write_state(
        store: RunStore,
        state: _ReplanningState,
        *,
        status: str,
        extra: dict[str, object] | None = None,
    ) -> None:
        store.write_json("budget.json", state.budget.snapshot())
        store.write_json("rate-limits.json", state.rate_limits.snapshot())
        store.write_json(
            "run.json",
            {
                "runId": store.run_id,
                "status": status,
                "stage": state.stage,
                "purpose": "bounded-replanning",
                **(extra or {}),
            },
        )

    def _terminalize(
        self,
        store: RunStore,
        state: _ReplanningState,
        *,
        status: str,
        error_type: str,
        cancellation_receipt: str | None = None,
    ) -> None:
        if state.terminalized:
            return
        payload: dict[str, object] = {
            "stage": state.stage,
            "errorType": error_type,
            "purpose": "bounded-replanning",
        }
        extra: dict[str, object] = {"errorType": error_type}
        if cancellation_receipt is not None:
            payload["cancellationReceipt"] = cancellation_receipt
            extra["cancellationReceipt"] = cancellation_receipt
        self._write_state(store, state, status=status, extra=extra)
        store.append_event(f"campaign.{status}", payload)
        store.seal()
        state.terminalized = True
