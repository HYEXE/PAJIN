"""Snapshot-only, target-taint-preserving Supervisor input for SUP-002."""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.snapshots import (
    CollaborationSnapshot,
    CollaborationSnapshotError,
    SharedArtifactSource,
    verify_collaboration_snapshot,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.graph.models import (
    GraphCampaignFact,
    GraphContentOrigin,
    GraphNodeKind,
    parse_graph_node,
)
from pajin.graph.projection import GraphSnapshotError, GraphSnapshotStore
from pajin.providers.models import ProviderRegistration
from pajin.supervision.model_binding import (
    SupervisorModelBinding,
    SupervisorModelBindingError,
    SupervisorModelConfiguration,
    SupervisorModelSchemaBinding,
    SupervisorModelSchemaKind,
    verify_supervisor_model_binding,
)

SUPERVISOR_SNAPSHOT_INPUT_API_VERSION: Literal[
    "pajin.dev/supervisor-snapshot-input/v1alpha1"
] = "pajin.dev/supervisor-snapshot-input/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_TEXT_ITEMS = 256
_MAX_REFERENCE_ITEMS = 512


class SupervisorSnapshotInputError(RuntimeError):
    """Raised when a model-visible Snapshot projection cannot be proven exact."""


class SupervisorTargetTaint(StrEnum):
    TRUSTED_METADATA = "trusted-metadata"
    TARGET_TAINTED_UNTRUSTED = "target-tainted-untrusted"


class SupervisorInputReferenceKind(StrEnum):
    CAMPAIGN_FACT = "campaign-fact"
    SHARED_ARTIFACT = "shared-artifact"


class SupervisorModelVisibleText(StrictModel):
    """One exact Fact statement with immutable origin and taint provenance."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    source_node_id: str = Field(
        alias="sourceNodeId",
        pattern=r"^graph-node_[a-f0-9]{64}$",
    )
    source_value_digest: _Sha256 = Field(alias="sourceValueDigest")
    text: str = Field(min_length=1, max_length=4_000)
    text_digest: str = Field(default="", alias="textDigest", max_length=64)
    origin: GraphContentOrigin
    target_taint: SupervisorTargetTaint = Field(alias="targetTaint")
    instruction_authorized: Literal[False] = Field(
        default=False,
        alias="instructionAuthorized",
    )

    @field_validator("instruction_authorized", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_text_and_taint(self) -> Self:
        digest = sha256(self.text.encode("utf-8", errors="strict")).hexdigest()
        if self.text_digest and self.text_digest != digest:
            raise ValueError("Supervisor visible text digest differs")
        if self.target_taint is not _taint_for_origin(self.origin):
            raise ValueError("Supervisor visible text taint differs from origin")
        object.__setattr__(self, "text_digest", digest)
        return self


class SupervisorInputReference(StrictModel):
    """Content-free Snapshot member reference with explicit taint provenance."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    reference_kind: SupervisorInputReferenceKind = Field(alias="referenceKind")
    reference_id: str = Field(alias="referenceId", min_length=1, max_length=200)
    reference_digest: _Sha256 = Field(alias="referenceDigest")
    origin: GraphContentOrigin
    target_taint: SupervisorTargetTaint = Field(alias="targetTaint")
    content_embedded: Literal[False] = Field(default=False, alias="contentEmbedded")
    instruction_authorized: Literal[False] = Field(
        default=False,
        alias="instructionAuthorized",
    )
    execution_authorized: Literal[False] = Field(
        default=False,
        alias="executionAuthorized",
    )

    @field_validator(
        "content_embedded",
        "instruction_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_reference_taint(self) -> Self:
        if self.target_taint is not _taint_for_origin(self.origin):
            raise ValueError("Supervisor input reference taint differs from origin")
        return self


class SupervisorSnapshotInput(StrictModel):
    """Complete current Collaboration Snapshot projection; never a model request."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-snapshot-input/v1alpha1"] = Field(
        default=SUPERVISOR_SNAPSHOT_INPUT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorSnapshotInput"] = "SupervisorSnapshotInput"
    input_id: str = Field(default="", alias="inputId", max_length=110)
    input_digest: str = Field(default="", alias="inputDigest", max_length=64)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    model_binding: SupervisorModelBinding = Field(alias="modelBinding")
    model_binding_digest: _Sha256 = Field(alias="modelBindingDigest")
    input_schema: SupervisorModelSchemaBinding = Field(alias="inputSchema")
    source_snapshot: CollaborationSnapshot = Field(alias="sourceSnapshot")
    source_snapshot_id: str = Field(alias="sourceSnapshotId", min_length=1, max_length=110)
    source_snapshot_digest: _Sha256 = Field(alias="sourceSnapshotDigest")
    model_visible_text: tuple[SupervisorModelVisibleText, ...] = Field(
        alias="modelVisibleText",
        max_length=_MAX_TEXT_ITEMS,
    )
    safe_references: tuple[SupervisorInputReference, ...] = Field(
        alias="safeReferences",
        max_length=_MAX_REFERENCE_ITEMS,
    )
    input_state: Literal["snapshot-projected-not-invoked"] = Field(
        default="snapshot-projected-not-invoked",
        alias="inputState",
    )
    target_taint_complete: Literal[True] = Field(default=True, alias="targetTaintComplete")
    raw_prompt_relay_authorized: Literal[False] = Field(
        default=False,
        alias="rawPromptRelayAuthorized",
    )
    model_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="modelInvocationAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("target_taint_complete", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        return _require_literal_bool(value, expected=True)

    @field_validator(
        "raw_prompt_relay_authorized",
        "model_invocation_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_input(self) -> Self:
        expected_schema = next(
            (
                item
                for item in self.model_binding.allowed_input_schemas
                if item.schema_kind is SupervisorModelSchemaKind.COLLABORATION_SNAPSHOT
            ),
            None,
        )
        campaign = self.model_binding.profile_compilation.source_campaign
        fact_ids = tuple(item.node_id for item in self.source_snapshot.campaign_facts)
        text_ids = tuple(item.source_node_id for item in self.model_visible_text)
        reference_keys = tuple(
            (item.reference_kind.value, item.reference_id) for item in self.safe_references
        )
        text_by_id = {item.source_node_id: item for item in self.model_visible_text}
        reference_by_key = {
            (item.reference_kind, item.reference_id): item
            for item in self.safe_references
        }
        expected_reference_keys = tuple(
            sorted(
                (
                    *(
                        (SupervisorInputReferenceKind.CAMPAIGN_FACT.value, item.node_id)
                        for item in self.source_snapshot.campaign_facts
                    ),
                    *(
                        (
                            SupervisorInputReferenceKind.SHARED_ARTIFACT.value,
                            item.shared_artifact_id,
                        )
                        for item in self.source_snapshot.shared_artifacts
                    ),
                )
            )
        )
        if (
            self.model_binding_digest != self.model_binding.binding_digest
            or self.campaign_digest != self.model_binding.campaign_digest
            or self.source_snapshot.campaign_id != campaign.metadata.name
            or expected_schema is None
            or self.input_schema != expected_schema
            or self.source_snapshot_id != self.source_snapshot.collaboration_snapshot_id
            or self.source_snapshot_digest
            != self.source_snapshot.collaboration_snapshot_digest
            or text_ids != fact_ids
            or reference_keys != expected_reference_keys
        ):
            raise ValueError("Supervisor Snapshot input differs from bound Snapshot authority")
        for fact in self.source_snapshot.campaign_facts:
            text = text_by_id[fact.node_id]
            reference = reference_by_key[
                (SupervisorInputReferenceKind.CAMPAIGN_FACT, fact.node_id)
            ]
            if (
                reference.reference_digest
                != fact.node_id.removeprefix("graph-node_")
                or reference.origin is not text.origin
                or reference.target_taint is not text.target_taint
            ):
                raise ValueError("Supervisor Fact text and reference provenance differ")
        for artifact in self.source_snapshot.shared_artifacts:
            reference = reference_by_key[
                (
                    SupervisorInputReferenceKind.SHARED_ARTIFACT,
                    artifact.shared_artifact_id,
                )
            ]
            if (
                reference.reference_digest != artifact.shared_artifact_digest
                or reference.origin is not GraphContentOrigin.TARGET_DERIVED
                or reference.target_taint
                is not SupervisorTargetTaint.TARGET_TAINTED_UNTRUSTED
            ):
                raise ValueError("Supervisor Artifact reference provenance differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"input_id", "input_digest"},
        )
        digest = _snapshot_input_digest(material)
        input_id = f"supervisor-snapshot-input:{digest}"
        if self.input_digest and self.input_digest != digest:
            raise ValueError("Supervisor Snapshot Input Digest differs")
        if self.input_id and self.input_id != input_id:
            raise ValueError("Supervisor Snapshot Input ID differs")
        object.__setattr__(self, "input_digest", digest)
        object.__setattr__(self, "input_id", input_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Supervisor Snapshot input",
            max_bytes=_MAX_INPUT_BYTES,
        )
        return self


def create_supervisor_snapshot_input(
    binding: SupervisorModelBinding,
    campaign: CampaignManifest,
    provider_registration: ProviderRegistration,
    *,
    model_revision: str,
    configuration: SupervisorModelConfiguration,
    collaboration_snapshot: CollaborationSnapshot,
    graph_snapshot_store: GraphSnapshotStore,
    shared_artifact_sources: Iterable[SharedArtifactSource] = (),
) -> SupervisorSnapshotInput:
    """Project one exact current Collaboration Snapshot without invoking a model."""

    try:
        verified_binding = verify_supervisor_model_binding(
            binding,
            campaign,
            provider_registration,
            model_revision=model_revision,
            configuration=configuration,
        )
        verified_snapshot = verify_collaboration_snapshot(
            collaboration_snapshot,
            graph_snapshot_store=graph_snapshot_store,
            shared_artifact_sources=shared_artifact_sources,
        )
        head = graph_snapshot_store.head_digest()
        if head != verified_snapshot.graph_snapshot.snapshot_digest:
            raise ValueError("Supervisor Snapshot input Graph authority is stale")
        graph_snapshot = graph_snapshot_store.resolve(verified_snapshot.graph_snapshot)
        facts = _resolve_facts(verified_snapshot, graph_snapshot.projection.nodes)
        if graph_snapshot_store.head_digest() != head:
            raise ValueError("Supervisor Snapshot input Graph authority changed")
        schema = next(
            item
            for item in verified_binding.allowed_input_schemas
            if item.schema_kind is SupervisorModelSchemaKind.COLLABORATION_SNAPSHOT
        )
        texts = tuple(_visible_text(fact) for fact in facts)
        references = tuple(
            sorted(
                (
                    *(_fact_reference(fact) for fact in facts),
                    *(
                        SupervisorInputReference(
                            referenceKind=SupervisorInputReferenceKind.SHARED_ARTIFACT,
                            referenceId=item.shared_artifact_id,
                            referenceDigest=item.shared_artifact_digest,
                            origin=GraphContentOrigin.TARGET_DERIVED,
                            targetTaint=SupervisorTargetTaint.TARGET_TAINTED_UNTRUSTED,
                        )
                        for item in verified_snapshot.shared_artifacts
                    ),
                ),
                key=lambda item: (item.reference_kind.value, item.reference_id),
            )
        )
        return SupervisorSnapshotInput.model_validate(
            {
                "campaignDigest": verified_binding.campaign_digest,
                "modelBinding": verified_binding.model_dump(mode="json", by_alias=True),
                "modelBindingDigest": verified_binding.binding_digest,
                "inputSchema": schema.model_dump(mode="json", by_alias=True),
                "sourceSnapshot": verified_snapshot.model_dump(mode="json", by_alias=True),
                "sourceSnapshotId": verified_snapshot.collaboration_snapshot_id,
                "sourceSnapshotDigest": verified_snapshot.collaboration_snapshot_digest,
                "modelVisibleText": [
                    item.model_dump(mode="json", by_alias=True) for item in texts
                ],
                "safeReferences": [
                    item.model_dump(mode="json", by_alias=True) for item in references
                ],
            }
        )
    except (
        AttributeError,
        CollaborationSnapshotError,
        GraphSnapshotError,
        StopIteration,
        SupervisorModelBindingError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorSnapshotInputError(
            "Supervisor Snapshot input creation failed closed"
        ) from exc


def verify_supervisor_snapshot_input(
    value: SupervisorSnapshotInput,
    binding: SupervisorModelBinding,
    campaign: CampaignManifest,
    provider_registration: ProviderRegistration,
    *,
    model_revision: str,
    configuration: SupervisorModelConfiguration,
    collaboration_snapshot: CollaborationSnapshot,
    graph_snapshot_store: GraphSnapshotStore,
    shared_artifact_sources: Iterable[SharedArtifactSource] = (),
) -> SupervisorSnapshotInput:
    """Rebuild and exact-match one current taint-preserving input."""

    try:
        canonical = SupervisorSnapshotInput.model_validate(
            value.model_dump(mode="json", by_alias=True)
        )
        expected = create_supervisor_snapshot_input(
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
            raise ValueError("Supervisor Snapshot input differs from current authority")
        return canonical.model_copy(deep=True)
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise SupervisorSnapshotInputError(
            "Supervisor Snapshot input verification failed closed"
        ) from exc


def _resolve_facts(
    snapshot: CollaborationSnapshot,
    nodes: tuple[object, ...],
) -> tuple[GraphCampaignFact, ...]:
    parsed = {node.node_id: node for raw in nodes for node in (parse_graph_node(raw),)}
    facts: list[GraphCampaignFact] = []
    for reference in snapshot.campaign_facts:
        node = parsed.get(reference.node_id)
        if (
            reference.kind is not GraphNodeKind.CAMPAIGN_FACT
            or not isinstance(node, GraphCampaignFact)
            or node.campaign_id != snapshot.campaign_id
        ):
            raise ValueError("Supervisor input Fact reference is unresolved")
        facts.append(node)
    return tuple(facts)


def _visible_text(fact: GraphCampaignFact) -> SupervisorModelVisibleText:
    return SupervisorModelVisibleText(
        sourceNodeId=fact.node_id,
        sourceValueDigest=fact.value_digest,
        text=fact.statement,
        origin=fact.origin,
        targetTaint=_taint_for_origin(fact.origin),
    )


def _fact_reference(fact: GraphCampaignFact) -> SupervisorInputReference:
    return SupervisorInputReference(
        referenceKind=SupervisorInputReferenceKind.CAMPAIGN_FACT,
        referenceId=fact.node_id,
        referenceDigest=fact.node_id.removeprefix("graph-node_"),
        origin=fact.origin,
        targetTaint=_taint_for_origin(fact.origin),
    )


def _taint_for_origin(origin: GraphContentOrigin) -> SupervisorTargetTaint:
    if origin in {GraphContentOrigin.AGENT_DERIVED, GraphContentOrigin.TARGET_DERIVED}:
        return SupervisorTargetTaint.TARGET_TAINTED_UNTRUSTED
    return SupervisorTargetTaint.TRUSTED_METADATA


def _snapshot_input_digest(value: object) -> str:
    encoded = canonical_json_bytes(
        value,
        label="Supervisor Snapshot input identity",
        max_bytes=_MAX_INPUT_BYTES,
    )
    return sha256(b"pajin.supervision.snapshot-input/v1\x00" + encoded).hexdigest()


def _require_literal_bool(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError("Supervisor Snapshot input boolean must be literal and exact")
    return expected
