"""Deterministic, target-neutral context compaction for logical agents.

The compactor never reads Artifact content, accepts a caller-authored summary, or
asks a model to summarize anything. Exact Artifact references remain in the
verified source checkpoint. The compact wire contains only digest projections,
counts, applied limits, and explicit non-authority markers.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from typing import Any, Literal, Self, cast

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.agentic.durable import (
    AgenticCoordinationError,
    AgenticCoordinationStore,
    VerifiedAgenticDurableHead,
)
from pajin.agentic.durable_graph import CurrentGraphHeadResolver, VerifiedCurrentGraphHead
from pajin.agentic.models import (
    AgenticStrictModel,
    AgentSessionSnapshot,
    ArtifactReference,
    Sha256,
    _literal_false,
    _literal_true,
)
from pajin.agentic.supervisor import DynamicSupervisorCheckpoint
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest

AGENTIC_CONTEXT_COMPACTION_API_VERSION: Literal["pajin.dev/agentic-context-compaction/v1alpha1"] = (
    "pajin.dev/agentic-context-compaction/v1alpha1"
)

_MAX_SOURCE_ITEMS = 64
_MAX_RETAINED_ITEMS = 32
_MAX_SOURCE_REFERENCE_BYTES = 512 * 1024
_MAX_CONTEXT_BYTES = 256 * 1024
_MAX_CONTEXT_NODES = 4096
_MAX_COMPACTION_DEPTH = 8
_MAX_WIRE_INPUT_NODES = 8192
_MAX_WIRE_INPUT_DEPTH = 32


def _artifact_wire(reference: ArtifactReference) -> dict[str, object]:
    return reference.model_dump(mode="json", by_alias=True)


def _artifact_reference_digest(reference: ArtifactReference) -> str:
    return discovery_digest(
        "pajin.agentic.exact-artifact-reference/v1",
        _artifact_wire(reference),
    )


class TargetNeutralArtifactRef(AgenticStrictModel):
    """Digest-only projection of an exact Artifact reference."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    kind: Literal["TargetNeutralArtifactRef"] = "TargetNeutralArtifactRef"
    artifact_reference_digest: Sha256 = Field(alias="artifactReferenceDigest")
    content_origin: Literal["sealed-artifact-untrusted"] = Field(
        default="sealed-artifact-untrusted",
        alias="contentOrigin",
    )
    content_is_untrusted: Literal[True] = Field(default=True, alias="contentIsUntrusted")
    artifact_identifier_included: Literal[False] = Field(
        default=False,
        alias="artifactIdentifierIncluded",
    )
    source_run_identifier_included: Literal[False] = Field(
        default=False,
        alias="sourceRunIdentifierIncluded",
    )
    media_type_included: Literal[False] = Field(default=False, alias="mediaTypeIncluded")
    raw_content_included: Literal[False] = Field(default=False, alias="rawContentIncluded")
    target_identity_included: Literal[False] = Field(
        default=False,
        alias="targetIdentityIncluded",
    )
    target_locator_included: Literal[False] = Field(
        default=False,
        alias="targetLocatorIncluded",
    )
    instruction_authority: Literal[False] = Field(default=False, alias="instructionAuthority")
    retrieval_authority: Literal[False] = Field(default=False, alias="retrievalAuthority")

    @field_validator(
        "artifact_identifier_included",
        "source_run_identifier_included",
        "media_type_included",
        "raw_content_included",
        "target_identity_included",
        "target_locator_included",
        "instruction_authority",
        "retrieval_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @field_validator("content_is_untrusted", mode="before")
    @classmethod
    def require_true_marker(cls, value: object, info: ValidationInfo) -> object:
        return _literal_true(value, label=info.field_name)


def _target_neutral_reference(reference: ArtifactReference) -> TargetNeutralArtifactRef:
    return TargetNeutralArtifactRef(artifactReferenceDigest=_artifact_reference_digest(reference))


def _reference_sequence_digest(
    domain: str,
    references: tuple[TargetNeutralArtifactRef, ...],
) -> str:
    return discovery_digest(
        domain,
        {
            "artifactReferenceDigests": [
                reference.artifact_reference_digest for reference in references
            ]
        },
    )


def _canonical_artifact_sequence(
    references: tuple[ArtifactReference, ...],
    *,
    label: str,
) -> tuple[ArtifactReference, ...]:
    if type(references) is not tuple:
        raise ValueError(f"{label} must be an exact tuple")
    canonical = tuple(
        ArtifactReference.model_validate(reference.model_dump(mode="json", by_alias=True))
        for reference in references
    )
    artifact_ids = tuple(reference.artifact_id for reference in canonical)
    if len(artifact_ids) != len(set(artifact_ids)):
        raise ValueError(f"{label} Artifact IDs must be unique")
    return canonical


def _latest_unique_references(
    references: tuple[TargetNeutralArtifactRef, ...],
) -> tuple[TargetNeutralArtifactRef, ...]:
    seen: set[str] = set()
    latest_reversed: list[TargetNeutralArtifactRef] = []
    for reference in reversed(references):
        if reference.artifact_reference_digest in seen:
            continue
        seen.add(reference.artifact_reference_digest)
        latest_reversed.append(reference)
    return tuple(reversed(latest_reversed))


def _json_node_count(value: object, *, max_nodes: int) -> int:
    count = 0
    active: set[int] = set()

    def visit(item: object) -> None:
        nonlocal count
        count += 1
        if count > max_nodes:
            raise ValueError("compact context exceeds its canonical node budget")
        if item is None or type(item) in {bool, int, float, str}:
            return
        if type(item) is list:
            identity = id(item)
            if identity in active:
                raise ValueError("compact context wire contains a cycle")
            active.add(identity)
            try:
                for nested in item:
                    visit(nested)
            finally:
                active.remove(identity)
            return
        if type(item) is dict:
            identity = id(item)
            if identity in active:
                raise ValueError("compact context wire contains a cycle")
            active.add(identity)
            try:
                for key, nested in item.items():
                    visit(key)
                    visit(nested)
            finally:
                active.remove(identity)
            return
        raise ValueError("compact context wire contains a non-JSON value")

    visit(value)
    return count


def _validate_bounded_wire_input(value: object) -> None:
    active: set[int] = set()
    nodes = 0

    def visit(item: object, *, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > _MAX_WIRE_INPUT_NODES:
            raise ValueError("compact context input exceeds its node limit")
        if depth > _MAX_WIRE_INPUT_DEPTH:
            raise ValueError("compact context input exceeds its depth limit")
        if item is None or type(item) in {bool, int, float, str} or isinstance(item, StrEnum):
            return
        if isinstance(item, BaseModel):
            _visit_container(item, item.__dict__.values(), depth=depth)
            return
        if type(item) in {list, tuple}:
            _visit_container(item, cast(Iterable[object], item), depth=depth)
            return
        if type(item) is dict:
            for key in item:
                if type(key) is not str:
                    raise ValueError("compact context input object key must be a string")
            _visit_container(item, item.values(), depth=depth)
            return
        raise ValueError("compact context input contains an unsupported value type")

    def _visit_container(
        item: object,
        values: Iterable[object],
        *,
        depth: int,
    ) -> None:
        identity = id(item)
        if identity in active:
            raise ValueError("compact context input contains a cycle")
        active.add(identity)
        try:
            for nested in values:
                visit(nested, depth=depth + 1)
        finally:
            active.remove(identity)

    visit(value, depth=0)


class ContextCompactionPolicy(AgenticStrictModel):
    """Code-owned budgets and a closed selection algorithm for context compaction."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-context-compaction/v1alpha1"] = Field(
        default=AGENTIC_CONTEXT_COMPACTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ContextCompactionPolicy"] = "ContextCompactionPolicy"
    policy_id: str = Field(default="", alias="policyId", max_length=96)
    policy_digest: str = Field(default="", alias="policyDigest", max_length=64)
    max_source_items: int = Field(
        default=64,
        alias="maxSourceItems",
        strict=True,
        ge=1,
        le=_MAX_SOURCE_ITEMS,
    )
    max_retained_items: int = Field(
        default=16,
        alias="maxRetainedItems",
        strict=True,
        ge=0,
        le=_MAX_RETAINED_ITEMS,
    )
    max_source_reference_bytes: int = Field(
        default=128 * 1024,
        alias="maxSourceReferenceBytes",
        strict=True,
        ge=1,
        le=_MAX_SOURCE_REFERENCE_BYTES,
    )
    max_context_bytes: int = Field(
        default=32 * 1024,
        alias="maxContextBytes",
        strict=True,
        ge=1024,
        le=_MAX_CONTEXT_BYTES,
    )
    max_context_nodes: int = Field(
        default=2048,
        alias="maxContextNodes",
        strict=True,
        ge=64,
        le=_MAX_CONTEXT_NODES,
    )
    max_compaction_depth: int = Field(
        default=4,
        alias="maxCompactionDepth",
        strict=True,
        ge=1,
        le=_MAX_COMPACTION_DEPTH,
    )
    selection_strategy: Literal["latest-exact-reference-digest-suffix/v1"] = Field(
        default="latest-exact-reference-digest-suffix/v1",
        alias="selectionStrategy",
    )
    model_summarization_allowed: Literal[False] = Field(
        default=False,
        alias="modelSummarizationAllowed",
    )
    raw_artifact_content_allowed: Literal[False] = Field(
        default=False,
        alias="rawArtifactContentAllowed",
    )
    authority_material_compaction_allowed: Literal[False] = Field(
        default=False,
        alias="authorityMaterialCompactionAllowed",
    )

    @field_validator(
        "model_summarization_allowed",
        "raw_artifact_content_allowed",
        "authority_material_compaction_allowed",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if self.max_retained_items > self.max_source_items:
            raise ValueError("context retained-item budget exceeds its source-item budget")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"policy_id", "policy_digest"},
        )
        digest = discovery_digest("pajin.agentic.context-compaction-policy/v1", material)
        expected_id = f"context-compaction-policy_{digest}"
        if self.policy_digest and self.policy_digest != digest:
            raise ValueError("Context Compaction Policy Digest differs")
        if self.policy_id and self.policy_id != expected_id:
            raise ValueError("Context Compaction Policy ID differs")
        object.__setattr__(self, "policy_digest", digest)
        object.__setattr__(self, "policy_id", expected_id)
        return self


class CompactedAgentContext(AgenticStrictModel):
    """Provider-safe advisory reference view over one exact checkpoint."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-context-compaction/v1alpha1"] = Field(
        default=AGENTIC_CONTEXT_COMPACTION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CompactedAgentContext"] = "CompactedAgentContext"
    context_id: str = Field(default="", alias="contextId", max_length=96)
    context_digest: str = Field(default="", alias="contextDigest", max_length=64)
    source_checkpoint_id: str = Field(
        alias="sourceCheckpointId",
        pattern=r"^agentic-checkpoint_[a-f0-9]{64}$",
    )
    source_checkpoint_digest: Sha256 = Field(alias="sourceCheckpointDigest")
    source_checkpoint_revision: int = Field(
        alias="sourceCheckpointRevision",
        strict=True,
        ge=0,
    )
    source_snapshot_digest: Sha256 = Field(alias="sourceSnapshotDigest")
    policy_digest: Sha256 = Field(alias="policyDigest")
    applied_max_source_items: int = Field(alias="appliedMaxSourceItems", strict=True, ge=1)
    applied_max_retained_items: int = Field(
        alias="appliedMaxRetainedItems",
        strict=True,
        ge=0,
    )
    applied_max_source_reference_bytes: int = Field(
        alias="appliedMaxSourceReferenceBytes",
        strict=True,
        ge=1,
    )
    applied_max_context_bytes: int = Field(
        alias="appliedMaxContextBytes",
        strict=True,
        ge=1024,
    )
    applied_max_context_nodes: int = Field(
        alias="appliedMaxContextNodes",
        strict=True,
        ge=64,
    )
    applied_max_compaction_depth: int = Field(
        alias="appliedMaxCompactionDepth",
        strict=True,
        ge=1,
    )
    parent_context_digest: Sha256 | None = Field(default=None, alias="parentContextDigest")
    ancestor_context_digests: tuple[Sha256, ...] = Field(
        default=(),
        alias="ancestorContextDigests",
        max_length=_MAX_COMPACTION_DEPTH - 1,
    )
    compaction_depth: int = Field(
        alias="compactionDepth",
        strict=True,
        ge=1,
        le=_MAX_COMPACTION_DEPTH,
    )
    source_artifact_count: int = Field(alias="sourceArtifactCount", strict=True, ge=0)
    source_artifact_reference_bytes: int = Field(
        alias="sourceArtifactReferenceBytes",
        strict=True,
        ge=2,
    )
    source_artifact_sequence_digest: Sha256 = Field(alias="sourceArtifactSequenceDigest")
    input_artifact_count: int = Field(alias="inputArtifactCount", strict=True, ge=0)
    input_artifact_sequence_digest: Sha256 = Field(alias="inputArtifactSequenceDigest")
    unique_artifact_count: int = Field(alias="uniqueArtifactCount", strict=True, ge=0)
    unique_artifact_sequence_digest: Sha256 = Field(alias="uniqueArtifactSequenceDigest")
    retained_artifact_refs: tuple[TargetNeutralArtifactRef, ...] = Field(
        alias="retainedArtifactRefs",
        max_length=_MAX_RETAINED_ITEMS,
    )
    retained_artifact_count: int = Field(alias="retainedArtifactCount", strict=True, ge=0)
    retained_artifact_sequence_digest: Sha256 = Field(alias="retainedArtifactSequenceDigest")
    omitted_artifact_count: int = Field(alias="omittedArtifactCount", strict=True, ge=0)
    omitted_artifact_sequence_digest: Sha256 = Field(alias="omittedArtifactSequenceDigest")
    context_node_count: int = Field(alias="contextNodeCount", strict=True, ge=1)
    context_state: Literal["deterministic-target-neutral-advisory"] = Field(
        default="deterministic-target-neutral-advisory",
        alias="contextState",
    )
    content_is_untrusted: Literal[True] = Field(default=True, alias="contentIsUntrusted")
    source_content_embedded: Literal[False] = Field(
        default=False,
        alias="sourceContentEmbedded",
    )
    model_summary_used: Literal[False] = Field(default=False, alias="modelSummaryUsed")
    target_identity_included: Literal[False] = Field(
        default=False,
        alias="targetIdentityIncluded",
    )
    target_locator_included: Literal[False] = Field(
        default=False,
        alias="targetLocatorIncluded",
    )
    authority_material_compacted: Literal[False] = Field(
        default=False,
        alias="authorityMaterialCompacted",
    )
    ledger_material_compacted: Literal[False] = Field(
        default=False,
        alias="ledgerMaterialCompacted",
    )
    event_material_compacted: Literal[False] = Field(
        default=False,
        alias="eventMaterialCompacted",
    )
    budget_material_compacted: Literal[False] = Field(
        default=False,
        alias="budgetMaterialCompacted",
    )
    graph_material_compacted: Literal[False] = Field(
        default=False,
        alias="graphMaterialCompacted",
    )
    summary_authority: Literal[False] = Field(default=False, alias="summaryAuthority")
    evidence_authority: Literal[False] = Field(default=False, alias="evidenceAuthority")
    instruction_authority: Literal[False] = Field(default=False, alias="instructionAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_write_authorized: Literal[False] = Field(
        default=False,
        alias="graphWriteAuthorized",
    )

    @field_validator("content_is_untrusted", mode="before")
    @classmethod
    def require_true_marker(cls, value: object, info: ValidationInfo) -> object:
        return _literal_true(value, label=info.field_name)

    @field_validator(
        "source_content_embedded",
        "model_summary_used",
        "target_identity_included",
        "target_locator_included",
        "authority_material_compacted",
        "ledger_material_compacted",
        "event_material_compacted",
        "budget_material_compacted",
        "graph_material_compacted",
        "summary_authority",
        "evidence_authority",
        "instruction_authority",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "finding_authority",
        "graph_write_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="before")
    @classmethod
    def reject_cyclic_or_unbounded_input(cls, value: object) -> object:
        _validate_bounded_wire_input(value)
        return value

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
        _validate_bounded_wire_input(obj)
        return super().model_validate(
            obj,
            strict=strict,
            extra=extra,
            from_attributes=from_attributes,
            context=context,
            by_alias=by_alias,
            by_name=by_name,
        )

    @model_validator(mode="after")
    def bind_identity_and_budgets(self) -> Self:
        _validate_context_lineage(self)
        _validate_context_accounting(self)
        _validate_applied_limits(self)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"context_id", "context_digest"},
        )
        digest = discovery_digest("pajin.agentic.compacted-context/v1", material)
        expected_id = f"agent-context_{digest}"
        if self.context_digest and self.context_digest != digest:
            raise ValueError("Compacted Agent Context Digest differs")
        if self.context_id and self.context_id != expected_id:
            raise ValueError("Compacted Agent Context ID differs")
        if digest in self.ancestor_context_digests:
            raise ValueError("compact context ancestry contains a cycle")
        object.__setattr__(self, "context_digest", digest)
        object.__setattr__(self, "context_id", expected_id)
        wire = self.model_dump(mode="json", by_alias=True)
        nodes = _json_node_count(wire, max_nodes=self.applied_max_context_nodes)
        if nodes != self.context_node_count:
            raise ValueError("compact context node count differs")
        canonical_json_bytes(
            wire,
            label="Compacted Agent Context",
            max_bytes=self.applied_max_context_bytes,
        )
        return self


def _validate_context_lineage(context: CompactedAgentContext) -> None:
    if context.compaction_depth != len(context.ancestor_context_digests) + 1:
        raise ValueError("compact context depth differs from its ancestor chain")
    if len(set(context.ancestor_context_digests)) != len(context.ancestor_context_digests):
        raise ValueError("compact context ancestors repeat a context")
    if context.parent_context_digest is None:
        if context.ancestor_context_digests:
            raise ValueError("root compact context cannot contain ancestors")
    elif (
        not context.ancestor_context_digests
        or context.ancestor_context_digests[-1] != context.parent_context_digest
    ):
        raise ValueError("compact context parent differs from its final ancestor")


def _validate_context_accounting(context: CompactedAgentContext) -> None:
    if context.retained_artifact_count != len(context.retained_artifact_refs):
        raise ValueError("compact context retained Artifact count differs")
    if context.unique_artifact_count != (
        context.retained_artifact_count + context.omitted_artifact_count
    ):
        raise ValueError("compact context retained and omitted counts differ")
    if not (
        context.source_artifact_count <= context.input_artifact_count
        and context.unique_artifact_count <= context.input_artifact_count
    ):
        raise ValueError("compact context source accounting differs")
    retained_digests = tuple(
        reference.artifact_reference_digest for reference in context.retained_artifact_refs
    )
    if len(retained_digests) != len(set(retained_digests)):
        raise ValueError("compact context retained Artifact references must be unique")
    expected = _reference_sequence_digest(
        "pajin.agentic.context-retained-artifact-sequence/v1",
        context.retained_artifact_refs,
    )
    if expected != context.retained_artifact_sequence_digest:
        raise ValueError("compact context retained Artifact sequence digest differs")


def _validate_applied_limits(context: CompactedAgentContext) -> None:
    if context.applied_max_source_items > _MAX_SOURCE_ITEMS:
        raise ValueError("compact context source-item limit is unsupported")
    if context.applied_max_retained_items > _MAX_RETAINED_ITEMS:
        raise ValueError("compact context retained-item limit is unsupported")
    if context.applied_max_source_reference_bytes > _MAX_SOURCE_REFERENCE_BYTES:
        raise ValueError("compact context source-reference byte limit is unsupported")
    if context.applied_max_context_bytes > _MAX_CONTEXT_BYTES:
        raise ValueError("compact context byte limit is unsupported")
    if context.applied_max_context_nodes > _MAX_CONTEXT_NODES:
        raise ValueError("compact context node limit is unsupported")
    if context.applied_max_compaction_depth > _MAX_COMPACTION_DEPTH:
        raise ValueError("compact context depth limit is unsupported")
    if context.input_artifact_count > context.applied_max_source_items:
        raise ValueError("compact context exceeds its source-item budget")
    if context.retained_artifact_count > context.applied_max_retained_items:
        raise ValueError("compact context exceeds its retained-item budget")
    if context.source_artifact_reference_bytes > context.applied_max_source_reference_bytes:
        raise ValueError("compact context exceeds its source-reference byte budget")
    if context.compaction_depth > context.applied_max_compaction_depth:
        raise ValueError("compact context exceeds its depth budget")


def compact_agent_context(
    coordination_store: AgenticCoordinationStore,
    durable_head: VerifiedAgenticDurableHead,
    *,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
    agent_id: str,
    source_artifacts: tuple[ArtifactReference, ...],
    policy: ContextCompactionPolicy,
    ancestor_contexts: tuple[CompactedAgentContext, ...] = (),
) -> CompactedAgentContext:
    """Build advisory context from an exact current durable coordination head."""

    canonical_checkpoint = _verified_current_checkpoint(
        coordination_store,
        durable_head,
        graph_resolver=graph_resolver,
        graph_head=graph_head,
    )
    canonical_policy = ContextCompactionPolicy.model_validate(
        policy.model_dump(mode="json", by_alias=True)
    )
    canonical_source = _canonical_artifact_sequence(
        source_artifacts,
        label="context compaction source",
    )
    canonical_ancestors = _rebuild_ancestor_contexts(
        coordination_store,
        durable_head,
        graph_resolver=graph_resolver,
        graph_head=graph_head,
        ancestor_contexts=ancestor_contexts,
        current_checkpoint=canonical_checkpoint,
        agent_id=agent_id,
        policy=canonical_policy,
    )
    canonical_parent = canonical_ancestors[-1] if canonical_ancestors else None
    result = _compact_checkpoint_context(
        canonical_checkpoint,
        agent_id=agent_id,
        source_artifacts=canonical_source,
        policy=canonical_policy,
        parent=canonical_parent,
    )
    _require_unchanged_authorities(
        coordination_store,
        durable_head,
        graph_resolver=graph_resolver,
        graph_head=graph_head,
    )
    return result


def _compact_checkpoint_context(
    checkpoint: DynamicSupervisorCheckpoint,
    *,
    agent_id: str,
    source_artifacts: tuple[ArtifactReference, ...],
    policy: ContextCompactionPolicy,
    parent: CompactedAgentContext | None,
) -> CompactedAgentContext:
    """Internal deterministic projection from already verified sources."""

    if parent is not None:
        if parent.policy_digest != policy.policy_digest or _applied_policy(parent) != _policy_pin(
            policy
        ):
            raise ValueError("context compaction parent uses another policy")
        if parent.source_checkpoint_revision >= checkpoint.revision:
            raise ValueError("context compaction parent checkpoint is not older")
        if parent.compaction_depth >= policy.max_compaction_depth:
            raise ValueError("context compaction parent exhausts the depth budget")
    session = _checkpoint_session(checkpoint, agent_id)
    if source_artifacts != session.context_refs:
        raise ValueError(
            "context compaction source membership or order differs from the checkpoint"
        )
    source_wire = [_artifact_wire(reference) for reference in source_artifacts]
    source_bytes = len(
        canonical_json_bytes(
            source_wire,
            label="context compaction source references",
            max_bytes=policy.max_source_reference_bytes,
        )
    )
    current_refs = tuple(_target_neutral_reference(item) for item in source_artifacts)
    parent_refs = parent.retained_artifact_refs if parent is not None else ()
    input_refs = (*parent_refs, *current_refs)
    if len(input_refs) > policy.max_source_items:
        raise ValueError("context compaction input exceeds its source-item budget")
    unique_refs = _latest_unique_references(input_refs)

    max_retain = min(policy.max_retained_items, len(unique_refs))
    node_budget_exceeded = False
    for retained_count in range(max_retain, -1, -1):
        retained = unique_refs[len(unique_refs) - retained_count :] if retained_count else ()
        omitted = unique_refs[: len(unique_refs) - retained_count]
        raw = _context_wire(
            checkpoint=checkpoint,
            policy=policy,
            parent=parent,
            source=current_refs,
            source_bytes=source_bytes,
            input_refs=input_refs,
            unique_refs=unique_refs,
            retained=retained,
            omitted=omitted,
        )
        try:
            _json_node_count(raw, max_nodes=policy.max_context_nodes)
        except ValueError:
            node_budget_exceeded = True
            continue
        encoded = canonical_json_bytes(raw, label="Compacted Agent Context candidate")
        if len(encoded) <= policy.max_context_bytes:
            return CompactedAgentContext.model_validate(raw)
    if node_budget_exceeded:
        raise ValueError("context compaction envelope exceeds its canonical node budget")
    raise ValueError("context compaction envelope exceeds its canonical byte budget")


def verify_compacted_agent_context(
    context: CompactedAgentContext,
    *,
    coordination_store: AgenticCoordinationStore,
    durable_head: VerifiedAgenticDurableHead,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
    agent_id: str,
    source_artifacts: tuple[ArtifactReference, ...],
    policy: ContextCompactionPolicy,
    ancestor_contexts: tuple[CompactedAgentContext, ...] = (),
) -> CompactedAgentContext:
    """Rebuild and exact-match one compact context from its bound sources."""

    canonical = CompactedAgentContext.model_validate(context.model_dump(mode="json", by_alias=True))
    expected = compact_agent_context(
        coordination_store,
        durable_head,
        graph_resolver=graph_resolver,
        graph_head=graph_head,
        agent_id=agent_id,
        source_artifacts=source_artifacts,
        policy=policy,
        ancestor_contexts=ancestor_contexts,
    )
    if canonical != expected:
        raise ValueError("Compacted Agent Context differs from its exact source projection")
    return canonical


def _checkpoint_session(
    checkpoint: DynamicSupervisorCheckpoint,
    agent_id: str,
) -> AgentSessionSnapshot:
    session = next(
        (item for item in checkpoint.sessions if item.session_id == agent_id),
        None,
    )
    if session is None:
        raise ValueError("context compaction agent is absent from the source checkpoint")
    return session


def _verified_current_checkpoint(
    coordination_store: AgenticCoordinationStore,
    durable_head: VerifiedAgenticDurableHead,
    *,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
) -> DynamicSupervisorCheckpoint:
    if type(coordination_store) is not AgenticCoordinationStore:
        raise TypeError("context compaction requires an exact coordination store")
    if type(durable_head) is not VerifiedAgenticDurableHead:
        raise TypeError("context compaction requires a verified durable head handle")
    observed = coordination_store.current_head(
        graph_resolver=graph_resolver,
        graph_head=graph_head,
    )
    if observed != durable_head:
        raise AgenticCoordinationError("context compaction durable head handle is foreign or stale")
    snapshot = graph_resolver.snapshot_for_planning(graph_head)
    checkpoint = observed.checkpoint
    if (
        checkpoint.campaign_id != snapshot.campaign_id
        or checkpoint.source_snapshot_id != snapshot.snapshot_id
        or checkpoint.source_snapshot_digest != snapshot.snapshot_digest
    ):
        raise AgenticCoordinationError(
            "context compaction checkpoint differs from the verified Graph head"
        )
    return checkpoint


def _require_unchanged_authorities(
    coordination_store: AgenticCoordinationStore,
    durable_head: VerifiedAgenticDurableHead,
    *,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
) -> None:
    _verified_current_checkpoint(
        coordination_store,
        durable_head,
        graph_resolver=graph_resolver,
        graph_head=graph_head,
    )


def _rebuild_ancestor_contexts(
    coordination_store: AgenticCoordinationStore,
    durable_head: VerifiedAgenticDurableHead,
    *,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
    ancestor_contexts: tuple[CompactedAgentContext, ...],
    current_checkpoint: DynamicSupervisorCheckpoint,
    agent_id: str,
    policy: ContextCompactionPolicy,
) -> tuple[CompactedAgentContext, ...]:
    if type(ancestor_contexts) is not tuple:
        raise ValueError("context compaction ancestors must be an exact tuple")
    if len(ancestor_contexts) >= policy.max_compaction_depth:
        raise ValueError("context compaction ancestors exhaust the depth budget")
    rebuilt: list[CompactedAgentContext] = []
    previous_revision = -1
    for supplied in ancestor_contexts:
        if type(supplied) is not CompactedAgentContext:
            raise TypeError("context compaction ancestors require exact compact contexts")
        canonical = CompactedAgentContext.model_validate(
            supplied.model_dump(mode="json", by_alias=True)
        )
        historical = coordination_store.verified_checkpoint(
            durable_head,
            checkpoint_id=canonical.source_checkpoint_id,
            checkpoint_digest=canonical.source_checkpoint_digest,
            graph_resolver=graph_resolver,
            graph_head=graph_head,
        )
        checkpoint = historical.checkpoint
        if checkpoint.revision <= previous_revision:
            raise ValueError("context compaction ancestors are not revision ordered")
        if checkpoint.revision >= current_checkpoint.revision:
            raise ValueError("context compaction ancestor checkpoint is not older")
        session = _checkpoint_session(checkpoint, agent_id)
        expected = _compact_checkpoint_context(
            checkpoint,
            agent_id=agent_id,
            source_artifacts=session.context_refs,
            policy=policy,
            parent=rebuilt[-1] if rebuilt else None,
        )
        if canonical != expected:
            raise ValueError(
                "context compaction ancestor differs from its verified checkpoint lineage"
            )
        rebuilt.append(expected)
        previous_revision = checkpoint.revision
    return tuple(rebuilt)


def _policy_pin(policy: ContextCompactionPolicy) -> tuple[int, ...]:
    return (
        policy.max_source_items,
        policy.max_retained_items,
        policy.max_source_reference_bytes,
        policy.max_context_bytes,
        policy.max_context_nodes,
        policy.max_compaction_depth,
    )


def _applied_policy(context: CompactedAgentContext) -> tuple[int, ...]:
    return (
        context.applied_max_source_items,
        context.applied_max_retained_items,
        context.applied_max_source_reference_bytes,
        context.applied_max_context_bytes,
        context.applied_max_context_nodes,
        context.applied_max_compaction_depth,
    )


def _context_wire(
    *,
    checkpoint: DynamicSupervisorCheckpoint,
    policy: ContextCompactionPolicy,
    parent: CompactedAgentContext | None,
    source: tuple[TargetNeutralArtifactRef, ...],
    source_bytes: int,
    input_refs: tuple[TargetNeutralArtifactRef, ...],
    unique_refs: tuple[TargetNeutralArtifactRef, ...],
    retained: tuple[TargetNeutralArtifactRef, ...],
    omitted: tuple[TargetNeutralArtifactRef, ...],
) -> dict[str, object]:
    ancestor_digests = (
        () if parent is None else (*parent.ancestor_context_digests, parent.context_digest)
    )
    material: dict[str, object] = {
        "apiVersion": AGENTIC_CONTEXT_COMPACTION_API_VERSION,
        "kind": "CompactedAgentContext",
        "contextId": "",
        "contextDigest": "",
        "sourceCheckpointId": checkpoint.checkpoint_id,
        "sourceCheckpointDigest": checkpoint.checkpoint_digest,
        "sourceCheckpointRevision": checkpoint.revision,
        "sourceSnapshotDigest": checkpoint.source_snapshot_digest,
        "policyDigest": policy.policy_digest,
        "appliedMaxSourceItems": policy.max_source_items,
        "appliedMaxRetainedItems": policy.max_retained_items,
        "appliedMaxSourceReferenceBytes": policy.max_source_reference_bytes,
        "appliedMaxContextBytes": policy.max_context_bytes,
        "appliedMaxContextNodes": policy.max_context_nodes,
        "appliedMaxCompactionDepth": policy.max_compaction_depth,
        "parentContextDigest": parent.context_digest if parent is not None else None,
        "ancestorContextDigests": list(ancestor_digests),
        "compactionDepth": len(ancestor_digests) + 1,
        "sourceArtifactCount": len(source),
        "sourceArtifactReferenceBytes": source_bytes,
        "sourceArtifactSequenceDigest": _reference_sequence_digest(
            "pajin.agentic.context-source-artifact-sequence/v1",
            source,
        ),
        "inputArtifactCount": len(input_refs),
        "inputArtifactSequenceDigest": _reference_sequence_digest(
            "pajin.agentic.context-input-artifact-sequence/v1",
            input_refs,
        ),
        "uniqueArtifactCount": len(unique_refs),
        "uniqueArtifactSequenceDigest": _reference_sequence_digest(
            "pajin.agentic.context-unique-artifact-sequence/v1",
            unique_refs,
        ),
        "retainedArtifactRefs": [
            reference.model_dump(mode="json", by_alias=True) for reference in retained
        ],
        "retainedArtifactCount": len(retained),
        "retainedArtifactSequenceDigest": _reference_sequence_digest(
            "pajin.agentic.context-retained-artifact-sequence/v1",
            retained,
        ),
        "omittedArtifactCount": len(omitted),
        "omittedArtifactSequenceDigest": _reference_sequence_digest(
            "pajin.agentic.context-omitted-artifact-sequence/v1",
            omitted,
        ),
        "contextNodeCount": 0,
        "contextState": "deterministic-target-neutral-advisory",
        "contentIsUntrusted": True,
        "sourceContentEmbedded": False,
        "modelSummaryUsed": False,
        "targetIdentityIncluded": False,
        "targetLocatorIncluded": False,
        "authorityMaterialCompacted": False,
        "ledgerMaterialCompacted": False,
        "eventMaterialCompacted": False,
        "budgetMaterialCompacted": False,
        "graphMaterialCompacted": False,
        "summaryAuthority": False,
        "evidenceAuthority": False,
        "instructionAuthority": False,
        "scopeExpansionAuthorized": False,
        "capabilityGranted": False,
        "permitGranted": False,
        "executionAuthorized": False,
        "findingAuthority": False,
        "graphWriteAuthorized": False,
    }
    material["contextNodeCount"] = _json_node_count(material, max_nodes=_MAX_CONTEXT_NODES)
    identity_material = {
        key: value for key, value in material.items() if key not in {"contextId", "contextDigest"}
    }
    digest = discovery_digest("pajin.agentic.compacted-context/v1", identity_material)
    material["contextId"] = f"agent-context_{digest}"
    material["contextDigest"] = digest
    return material


__all__ = [
    "AGENTIC_CONTEXT_COMPACTION_API_VERSION",
    "CompactedAgentContext",
    "ContextCompactionPolicy",
    "TargetNeutralArtifactRef",
    "compact_agent_context",
    "verify_compacted_agent_context",
]
