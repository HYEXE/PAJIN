"""Bounded collaboration views over one exact Canonical Graph Snapshot."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from re import fullmatch
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.artifacts import (
    SharedArtifactRef,
    SharedArtifactRefError,
    verify_shared_artifact_ref,
)
from pajin.domain.models import StrictModel
from pajin.graph.models import (
    CampaignFactValidationState,
    GraphCampaignFact,
    GraphEvidence,
    GraphNodeKind,
    GraphNodeRef,
    canonical_graph_json,
    graph_digest,
    graph_node_ref,
    parse_graph_node,
)
from pajin.graph.projection import (
    GraphSnapshot,
    GraphSnapshotError,
    GraphSnapshotRef,
    GraphSnapshotStore,
    graph_snapshot_ref,
)

COLLABORATION_SNAPSHOT_API_VERSION = "pajin.dev/collaboration-snapshot/v1alpha1"
MAX_COLLABORATION_FACTS = 256
MAX_COLLABORATION_ARTIFACTS = 256
_MAX_COLLABORATION_SNAPSHOT_BYTES = 1024 * 1024
_SNAPSHOT_ID_PATTERN = r"^collaboration-snapshot_[a-f0-9]{64}$"


class CollaborationSnapshotError(ValueError):
    """Raised when collaboration membership is not an exact current Graph view."""


@dataclass(frozen=True, slots=True)
class SharedArtifactSource:
    """Process-local verification inputs that never enter the collaboration wire form."""

    reference: SharedArtifactRef
    evidence: GraphEvidence
    source_run_path: Path


class CollaborationSnapshot(StrictModel):
    """Non-executable membership projection over one authoritative Graph Snapshot."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/collaboration-snapshot/v1alpha1"] = Field(
        default="pajin.dev/collaboration-snapshot/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CollaborationSnapshot"] = "CollaborationSnapshot"
    collaboration_snapshot_id: str = Field(
        default="",
        alias="collaborationSnapshotId",
        max_length=87,
    )
    collaboration_snapshot_digest: str = Field(
        default="",
        alias="collaborationSnapshotDigest",
        max_length=64,
    )
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    graph_snapshot: GraphSnapshotRef = Field(alias="graphSnapshot")
    campaign_facts: tuple[GraphNodeRef, ...] = Field(
        alias="campaignFacts",
        max_length=MAX_COLLABORATION_FACTS,
    )
    shared_artifacts: tuple[SharedArtifactRef, ...] = Field(
        alias="sharedArtifacts",
        max_length=MAX_COLLABORATION_ARTIFACTS,
    )
    content_embedded: Literal[False] = Field(default=False, alias="contentEmbedded")
    prompt_relay_authorized: Literal[False] = Field(
        default=False,
        alias="promptRelayAuthorized",
    )
    receiver_authority_granted: Literal[False] = Field(
        default=False,
        alias="receiverAuthorityGranted",
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "content_embedded",
        "prompt_relay_authorized",
        "receiver_authority_granted",
        "scope_expansion_authorized",
        "capability_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_boolean_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Collaboration Snapshot authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_membership_and_identity(self) -> Self:
        if self.graph_snapshot.campaign_id != self.campaign_id:
            raise ValueError("Collaboration Snapshot belongs to another Campaign")
        fact_ids = [reference.node_id for reference in self.campaign_facts]
        artifact_ids = [reference.shared_artifact_id for reference in self.shared_artifacts]
        evidence_ids = [reference.evidence.node_id for reference in self.shared_artifacts]
        if fact_ids != sorted(set(fact_ids)):
            raise ValueError("Collaboration Snapshot Facts must be unique and sorted")
        if artifact_ids != sorted(set(artifact_ids)):
            raise ValueError("Collaboration Snapshot Artifacts must be unique and sorted")
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("Collaboration Snapshot Evidence membership must be unique")
        if any(
            reference.kind is not GraphNodeKind.CAMPAIGN_FACT
            or reference.campaign_id != self.campaign_id
            for reference in self.campaign_facts
        ):
            raise ValueError("Collaboration Snapshot contains a foreign or non-Fact member")
        if any(
            reference.campaign_id != self.campaign_id
            or reference.evidence.campaign_id != self.campaign_id
            for reference in self.shared_artifacts
        ):
            raise ValueError("Collaboration Snapshot contains a foreign Artifact member")

        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"collaboration_snapshot_id", "collaboration_snapshot_digest"},
        )
        digest = graph_digest(
            "pajin.collaboration.snapshot/v1",
            material,
            max_bytes=_MAX_COLLABORATION_SNAPSHOT_BYTES,
        )
        snapshot_id = f"collaboration-snapshot_{digest}"
        if self.collaboration_snapshot_digest and self.collaboration_snapshot_digest != digest:
            raise ValueError("Collaboration Snapshot digest differs from canonical identity")
        if self.collaboration_snapshot_id and self.collaboration_snapshot_id != snapshot_id:
            raise ValueError("Collaboration Snapshot ID differs from canonical identity")
        object.__setattr__(self, "collaboration_snapshot_digest", digest)
        object.__setattr__(self, "collaboration_snapshot_id", snapshot_id)
        if fullmatch(_SNAPSHOT_ID_PATTERN, self.collaboration_snapshot_id) is None:
            raise ValueError("Collaboration Snapshot ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="CollaborationSnapshot",
            max_bytes=_MAX_COLLABORATION_SNAPSHOT_BYTES,
        )
        return self


def create_collaboration_snapshot(
    graph_snapshot: GraphSnapshotRef,
    *,
    graph_snapshot_store: GraphSnapshotStore,
    shared_artifact_sources: Iterable[SharedArtifactSource] = (),
) -> CollaborationSnapshot:
    """Build one bounded membership view from the current stored Graph Snapshot."""

    try:
        resolved = _resolve_current_graph_snapshot(
            graph_snapshot,
            graph_snapshot_store=graph_snapshot_store,
        )
        facts = _campaign_fact_refs(resolved)
        artifacts = _shared_artifact_refs(
            resolved,
            shared_artifact_sources=shared_artifact_sources,
        )
        if graph_snapshot_store.head_digest() != resolved.snapshot_digest:
            raise ValueError("Collaboration Snapshot Graph authority became stale")
        return CollaborationSnapshot(
            campaignId=resolved.campaign_id,
            graphSnapshot=graph_snapshot_ref(resolved),
            campaignFacts=facts,
            sharedArtifacts=artifacts,
        )
    except CollaborationSnapshotError:
        raise
    except (
        AttributeError,
        GraphSnapshotError,
        SharedArtifactRefError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise CollaborationSnapshotError(
            "Collaboration Snapshot could not be created"
        ) from exc


def verify_collaboration_snapshot(
    snapshot: CollaborationSnapshot,
    *,
    graph_snapshot_store: GraphSnapshotStore,
    shared_artifact_sources: Iterable[SharedArtifactSource] = (),
) -> CollaborationSnapshot:
    """Rebuild and exact-match one collaboration view against current authorities."""

    try:
        canonical = CollaborationSnapshot.model_validate(
            snapshot.model_dump(mode="json", by_alias=True)
        )
        expected = create_collaboration_snapshot(
            canonical.graph_snapshot,
            graph_snapshot_store=graph_snapshot_store,
            shared_artifact_sources=shared_artifact_sources,
        )
        if canonical != expected:
            raise ValueError("Collaboration Snapshot differs from current authority")
        return canonical
    except CollaborationSnapshotError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise CollaborationSnapshotError(
            "Collaboration Snapshot could not be verified"
        ) from exc


def _resolve_current_graph_snapshot(
    reference: GraphSnapshotRef,
    *,
    graph_snapshot_store: GraphSnapshotStore,
) -> GraphSnapshot:
    canonical_reference = GraphSnapshotRef.model_validate(
        reference.model_dump(mode="json", by_alias=True)
    )
    head_before = graph_snapshot_store.head_digest()
    if head_before != canonical_reference.snapshot_digest:
        raise ValueError("Collaboration Snapshot Graph authority is stale")
    resolved = graph_snapshot_store.resolve(canonical_reference)
    head_after = graph_snapshot_store.head_digest()
    if head_after != head_before:
        raise ValueError("Collaboration Snapshot Graph authority changed during resolution")
    return resolved


def _campaign_fact_refs(snapshot: GraphSnapshot) -> tuple[GraphNodeRef, ...]:
    facts = tuple(
        sorted(
            (
                graph_node_ref(node)
                for node in snapshot.projection.nodes
                if isinstance(node, GraphCampaignFact)
                and node.validation_state is CampaignFactValidationState.ADMITTED
            ),
            key=lambda reference: reference.node_id,
        )
    )
    if len(facts) > MAX_COLLABORATION_FACTS:
        raise ValueError("Collaboration Snapshot Fact count exceeds the configured limit")
    return facts


def _shared_artifact_refs(
    snapshot: GraphSnapshot,
    *,
    shared_artifact_sources: Iterable[SharedArtifactSource],
) -> tuple[SharedArtifactRef, ...]:
    sources = tuple(islice(shared_artifact_sources, MAX_COLLABORATION_ARTIFACTS + 1))
    if len(sources) > MAX_COLLABORATION_ARTIFACTS:
        raise ValueError("Collaboration Snapshot Artifact count exceeds the configured limit")
    evidence = {
        node.node_id: node
        for node in snapshot.projection.nodes
        if isinstance(node, GraphEvidence)
    }
    verified: list[SharedArtifactRef] = []
    for source in sources:
        canonical_evidence = _canonical_evidence(source.evidence)
        admitted = evidence.get(canonical_evidence.node_id)
        if admitted is None or admitted != canonical_evidence:
            raise ValueError("shared Artifact Evidence is not admitted in the Graph Snapshot")
        reference = verify_shared_artifact_ref(
            source.reference,
            canonical_evidence,
            source_run_path=source.source_run_path,
        )
        if reference.campaign_id != snapshot.campaign_id:
            raise ValueError("shared Artifact belongs to another Graph Campaign")
        verified.append(reference)
    return tuple(sorted(verified, key=lambda reference: reference.shared_artifact_id))


def _canonical_evidence(evidence: GraphEvidence) -> GraphEvidence:
    node = parse_graph_node(evidence.model_dump(mode="json", by_alias=True))
    if not isinstance(node, GraphEvidence):
        raise ValueError("Collaboration Snapshot Artifact source requires Graph Evidence")
    return node
