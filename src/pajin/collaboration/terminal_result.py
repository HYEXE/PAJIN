"""Terminal result handoffs bound to existing collaboration authorities."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from re import fullmatch
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.artifacts import SharedArtifactRef
from pajin.collaboration.handoff import (
    AgentHandoffAuthority,
    AgentHandoffError,
    HandoffAgentRef,
    HandoffTaskRef,
    SupervisorMediatedAgentHandoff,
    handoff_agent_ref,
    handoff_task_ref,
)
from pajin.collaboration.snapshots import (
    CollaborationSnapshot,
    CollaborationSnapshotError,
    SharedArtifactSource,
    verify_collaboration_snapshot,
)
from pajin.domain.models import StrictModel
from pajin.domain.orchestration import AgentNode, AgentStatus, TaskNode, TaskStatus
from pajin.graph.models import canonical_graph_json, graph_digest
from pajin.graph.projection import GraphSnapshotStore

TERMINAL_RESULT_HANDOFF_API_VERSION = "pajin.dev/terminal-result-handoff/v1alpha1"
_MAX_RESULT_BYTES = 128 * 1024
_RESULT_ID_PATTERN = r"^terminal-result-handoff_[a-f0-9]{64}$"


class TerminalResultHandoffError(ValueError):
    """Raised when terminal result authority cannot be reconstructed exactly."""


class TerminalResultStatus(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class TerminalResultHandoff(StrictModel):
    """Metadata-only terminal result bound to one admitted Agent Handoff."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/terminal-result-handoff/v1alpha1"] = Field(
        default="pajin.dev/terminal-result-handoff/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["TerminalResultHandoff"] = "TerminalResultHandoff"
    result_handoff_id: str = Field(default="", alias="resultHandoffId", max_length=88)
    result_handoff_digest: str = Field(
        default="", alias="resultHandoffDigest", max_length=64
    )
    authority_id: str = Field(
        alias="authorityId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    authority_digest: str = Field(alias="authorityDigest", pattern=r"^[a-f0-9]{64}$")
    handoff_id: str = Field(alias="handoffId", pattern=r"^agent-handoff_[a-f0-9]{64}$")
    handoff_digest: str = Field(alias="handoffDigest", pattern=r"^[a-f0-9]{64}$")
    campaign_id: str = Field(alias="campaignId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    collaboration_snapshot_id: str = Field(
        alias="collaborationSnapshotId",
        pattern=r"^collaboration-snapshot_[a-f0-9]{64}$",
    )
    collaboration_snapshot_digest: str = Field(
        alias="collaborationSnapshotDigest", pattern=r"^[a-f0-9]{64}$"
    )
    receiver: HandoffAgentRef
    destination_task: HandoffTaskRef = Field(alias="destinationTask")
    status: TerminalResultStatus
    result_artifact: SharedArtifactRef = Field(alias="resultArtifact")
    completed_at: datetime = Field(alias="completedAt")
    content_embedded: Literal[False] = Field(default=False, alias="contentEmbedded")
    prompt_relay_authorized: Literal[False] = Field(
        default=False, alias="promptRelayAuthorized"
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthorized"
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("completed_at")
    @classmethod
    def normalize_completed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("terminal result time requires an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "content_embedded",
        "prompt_relay_authorized",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("terminal result authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if self.result_artifact.campaign_id != self.campaign_id:
            raise ValueError("terminal result Artifact belongs to another Campaign")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"result_handoff_id", "result_handoff_digest"},
        )
        digest = graph_digest(
            "pajin.collaboration.terminal-result-handoff/v1",
            material,
            max_bytes=_MAX_RESULT_BYTES,
        )
        result_id = f"terminal-result-handoff_{digest}"
        if self.result_handoff_digest and self.result_handoff_digest != digest:
            raise ValueError("terminal result Handoff digest differs")
        if self.result_handoff_id and self.result_handoff_id != result_id:
            raise ValueError("terminal result Handoff ID differs")
        object.__setattr__(self, "result_handoff_digest", digest)
        object.__setattr__(self, "result_handoff_id", result_id)
        if fullmatch(_RESULT_ID_PATTERN, self.result_handoff_id) is None:
            raise ValueError("terminal result Handoff ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="TerminalResultHandoff",
            max_bytes=_MAX_RESULT_BYTES,
        )
        return self


class TerminalResultHandoffAuthority:
    """Single process-local writer for exact terminal Handoff results."""

    def __init__(self, *, authority_id: str, authority_digest: str) -> None:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", authority_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", authority_digest) is None
        ):
            raise ValueError("terminal result Handoff authority identity is invalid")
        self._authority_id = authority_id
        self._authority_digest = authority_digest
        self._by_handoff: dict[str, TerminalResultHandoff] = {}

    def admit(
        self,
        *,
        handoff_authority: AgentHandoffAuthority,
        handoff: SupervisorMediatedAgentHandoff,
        original_receiver: AgentNode,
        original_destination_task: TaskNode,
        terminal_receiver: AgentNode,
        terminal_task: TaskNode,
        historical_collaboration_snapshot: CollaborationSnapshot,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_sources: Iterable[SharedArtifactSource],
        result_artifact: SharedArtifactRef,
        completed_at: datetime,
    ) -> TerminalResultHandoff:
        try:
            admitted = handoff_authority.resolve(handoff)
            historical = CollaborationSnapshot.model_validate(
                historical_collaboration_snapshot.model_dump(mode="json", by_alias=True)
            )
            snapshot = verify_collaboration_snapshot(
                collaboration_snapshot,
                graph_snapshot_store=graph_snapshot_store,
                shared_artifact_sources=shared_artifact_sources,
            )
            _require_graph_successor(
                historical,
                snapshot,
                graph_snapshot_store=graph_snapshot_store,
            )
            _require_terminal_lineage(
                admitted,
                original_receiver=original_receiver,
                original_destination_task=original_destination_task,
                terminal_receiver=terminal_receiver,
                terminal_task=terminal_task,
            )
            if (
                historical.collaboration_snapshot_id
                != admitted.proposal.collaboration_snapshot_id
                or historical.collaboration_snapshot_digest
                != admitted.proposal.collaboration_snapshot_digest
                or historical.campaign_id != admitted.proposal.campaign_id
                or snapshot.campaign_id != admitted.proposal.campaign_id
                or result_artifact not in snapshot.shared_artifacts
                or result_artifact.campaign_id != snapshot.campaign_id
                or completed_at < admitted.admitted_at
            ):
                raise ValueError("terminal result differs from current Handoff authority")
            status = _terminal_status(terminal_task, terminal_receiver)
            record = TerminalResultHandoff(
                authorityId=self._authority_id,
                authorityDigest=self._authority_digest,
                handoffId=admitted.handoff_id,
                handoffDigest=admitted.handoff_digest,
                campaignId=snapshot.campaign_id,
                collaborationSnapshotId=snapshot.collaboration_snapshot_id,
                collaborationSnapshotDigest=snapshot.collaboration_snapshot_digest,
                receiver=handoff_agent_ref(terminal_receiver),
                destinationTask=handoff_task_ref(terminal_task),
                status=status,
                resultArtifact=result_artifact,
                completedAt=completed_at,
            )
            existing = self._by_handoff.get(admitted.handoff_id)
            if existing is not None:
                if _result_semantics(existing) != _result_semantics(record):
                    raise ValueError("terminal result Handoff has equivocated")
                return existing
            self._by_handoff[admitted.handoff_id] = record
            return record
        except (
            AgentHandoffError,
            AttributeError,
            CollaborationSnapshotError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise TerminalResultHandoffError(
                "terminal result Handoff could not be admitted"
            ) from exc

    def verify(
        self,
        result: TerminalResultHandoff,
        *,
        handoff_authority: AgentHandoffAuthority,
        handoff: SupervisorMediatedAgentHandoff,
        original_receiver: AgentNode,
        original_destination_task: TaskNode,
        terminal_receiver: AgentNode,
        terminal_task: TaskNode,
        historical_collaboration_snapshot: CollaborationSnapshot,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_sources: Iterable[SharedArtifactSource],
        result_artifact: SharedArtifactRef,
    ) -> TerminalResultHandoff:
        """Reconstruct one stored result from the same named admission inputs."""

        try:
            canonical = TerminalResultHandoff.model_validate(
                result.model_dump(mode="json", by_alias=True)
            )
            stored = self._by_handoff.get(canonical.handoff_id)
            if (
                canonical.authority_id != self._authority_id
                or canonical.authority_digest != self._authority_digest
                or stored != canonical
            ):
                raise ValueError("terminal result was not admitted by this authority")
            rebuilt = self.admit(
                handoff_authority=handoff_authority,
                handoff=handoff,
                original_receiver=original_receiver,
                original_destination_task=original_destination_task,
                terminal_receiver=terminal_receiver,
                terminal_task=terminal_task,
                historical_collaboration_snapshot=historical_collaboration_snapshot,
                collaboration_snapshot=collaboration_snapshot,
                graph_snapshot_store=graph_snapshot_store,
                shared_artifact_sources=shared_artifact_sources,
                result_artifact=result_artifact,
                completed_at=canonical.completed_at,
            )
            if rebuilt != canonical:
                raise ValueError("terminal result differs from current authority")
            return canonical
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise TerminalResultHandoffError(
                "terminal result Handoff could not be verified"
            ) from exc

    def resolve(self, result: TerminalResultHandoff) -> TerminalResultHandoff:
        """Resolve one admitted result without claiming its Snapshot remains current."""

        try:
            canonical = TerminalResultHandoff.model_validate(
                result.model_dump(mode="json", by_alias=True)
            )
            stored = self._by_handoff.get(canonical.handoff_id)
            if (
                canonical.authority_id != self._authority_id
                or canonical.authority_digest != self._authority_digest
                or stored != canonical
            ):
                raise ValueError("terminal result was not admitted by this authority")
            return canonical
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise TerminalResultHandoffError(
                "terminal result Handoff could not be resolved"
            ) from exc


def _require_terminal_lineage(
    handoff: SupervisorMediatedAgentHandoff,
    *,
    original_receiver: AgentNode,
    original_destination_task: TaskNode,
    terminal_receiver: AgentNode,
    terminal_task: TaskNode,
) -> None:
    originals = (
        handoff_agent_ref(original_receiver),
        handoff_task_ref(original_destination_task),
    )
    if originals != (handoff.proposal.receiver, handoff.proposal.destination_task):
        raise ValueError("terminal result source differs from admitted Handoff")
    if (
        _agent_stable_material(original_receiver) != _agent_stable_material(terminal_receiver)
        or _task_stable_material(original_destination_task)
        != _task_stable_material(terminal_task)
    ):
        raise ValueError("terminal result Agent or Task identity changed")


def _require_graph_successor(
    historical: CollaborationSnapshot,
    current: CollaborationSnapshot,
    *,
    graph_snapshot_store: GraphSnapshotStore,
) -> None:
    chain = graph_snapshot_store.snapshots()
    positions = {item.snapshot_id: index for index, item in enumerate(chain)}
    historical_index = positions.get(historical.graph_snapshot.snapshot_id)
    current_index = positions.get(current.graph_snapshot.snapshot_id)
    if (
        historical_index is None
        or current_index is None
        or historical_index >= current_index
        or chain[historical_index].snapshot_digest
        != historical.graph_snapshot.snapshot_digest
        or chain[current_index].snapshot_digest != current.graph_snapshot.snapshot_digest
    ):
        raise ValueError("terminal result Graph Snapshot is not a later authority in one chain")
    for previous, following in zip(
        chain[historical_index:current_index],
        chain[historical_index + 1 : current_index + 1],
        strict=True,
    ):
        if following.previous_snapshot_digest != previous.snapshot_digest:
            raise ValueError("terminal result Graph Snapshot chain is discontinuous")


def _terminal_status(task: TaskNode, agent: AgentNode) -> TerminalResultStatus:
    expected = {
        TaskStatus.SUCCEEDED: (AgentStatus.COMPLETED, TerminalResultStatus.SUCCEEDED),
        TaskStatus.FAILED: (AgentStatus.FAILED, TerminalResultStatus.FAILED),
        TaskStatus.CANCELLED: (AgentStatus.CANCELLED, TerminalResultStatus.CANCELLED),
    }.get(task.status)
    if expected is None or agent.status is not expected[0]:
        raise ValueError("terminal result Task and Agent states are inconsistent")
    return expected[1]


def _agent_stable_material(agent: AgentNode) -> object:
    return agent.model_dump(mode="json", exclude={"status", "error"})


def _task_stable_material(task: TaskNode) -> object:
    return task.model_dump(mode="json", exclude={"status", "error", "attempts"})


def _result_semantics(result: TerminalResultHandoff) -> object:
    return result.model_dump(
        mode="json",
        exclude={"result_handoff_id", "result_handoff_digest", "completed_at"},
    )
