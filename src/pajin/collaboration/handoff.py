"""Supervisor-mediated, non-executable Agent handoff records."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import UTC, datetime
from enum import StrEnum
from re import fullmatch
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.snapshots import (
    CollaborationSnapshot,
    CollaborationSnapshotError,
    SharedArtifactSource,
    verify_collaboration_snapshot,
)
from pajin.domain.models import StrictModel
from pajin.domain.orchestration import AgentNode, AgentRole, AgentStatus, TaskNode, TaskStatus
from pajin.graph.models import canonical_graph_json, graph_digest
from pajin.graph.projection import GraphSnapshotStore

AGENT_HANDOFF_API_VERSION = "pajin.dev/agent-handoff/v1alpha1"
_MAX_HANDOFF_BYTES = 64 * 1024
_HANDOFF_ID_PATTERN = r"^agent-handoff_[a-f0-9]{64}$"
_PROPOSAL_ID_PATTERN = r"^agent-handoff-proposal_[a-f0-9]{64}$"


class AgentHandoffError(ValueError):
    """Raised when a handoff is not an exact Supervisor-mediated transition."""


class AgentHandoffPurpose(StrEnum):
    CONTINUE_TASK = "continue-task"
    INDEPENDENT_REVIEW = "independent-review"
    VALIDATE_RESULT = "validate-result"
    PREPARE_REPORT = "prepare-report"


class HandoffAgentRef(StrictModel):
    agent_id: str = Field(
        alias="agentId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    role: AgentRole
    identity_digest: str = Field(alias="identityDigest", pattern=r"^[a-f0-9]{64}$")


class HandoffTaskRef(StrictModel):
    task_id: str = Field(
        alias="taskId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    task_digest: str = Field(alias="taskDigest", pattern=r"^[a-f0-9]{64}$")


class AgentHandoffProposal(StrictModel):
    """Unprivileged request for one already-defined Task transition."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agent-handoff-proposal/v1alpha1"] = Field(
        default="pajin.dev/agent-handoff-proposal/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["AgentHandoffProposal"] = "AgentHandoffProposal"
    proposal_id: str = Field(default="", alias="proposalId", max_length=87)
    proposal_digest: str = Field(default="", alias="proposalDigest", max_length=64)
    campaign_id: str = Field(alias="campaignId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    collaboration_snapshot_id: str = Field(
        alias="collaborationSnapshotId",
        pattern=r"^collaboration-snapshot_[a-f0-9]{64}$",
    )
    collaboration_snapshot_digest: str = Field(
        alias="collaborationSnapshotDigest", pattern=r"^[a-f0-9]{64}$"
    )
    sender: HandoffAgentRef
    receiver: HandoffAgentRef
    source_task: HandoffTaskRef = Field(alias="sourceTask")
    destination_task: HandoffTaskRef = Field(alias="destinationTask")
    purpose: AgentHandoffPurpose
    proposed_at: datetime = Field(alias="proposedAt")
    direct_agent_command: Literal[False] = Field(default=False, alias="directAgentCommand")

    @field_validator("proposed_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Agent Handoff proposal time requires an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("direct_agent_command", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Agent Handoff cannot carry a direct Agent command")
        return value

    @model_validator(mode="after")
    def bind_proposal(self) -> Self:
        if self.sender.agent_id == self.receiver.agent_id:
            raise ValueError("Agent Handoff cannot target the sender")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"proposal_id", "proposal_digest"}
        )
        digest = graph_digest(
            "pajin.collaboration.agent-handoff-proposal/v1",
            material,
            max_bytes=_MAX_HANDOFF_BYTES,
        )
        proposal_id = f"agent-handoff-proposal_{digest}"
        if self.proposal_digest and self.proposal_digest != digest:
            raise ValueError("Agent Handoff Proposal digest differs")
        if self.proposal_id and self.proposal_id != proposal_id:
            raise ValueError("Agent Handoff Proposal ID differs")
        object.__setattr__(self, "proposal_digest", digest)
        object.__setattr__(self, "proposal_id", proposal_id)
        if fullmatch(_PROPOSAL_ID_PATTERN, self.proposal_id) is None:
            raise ValueError("Agent Handoff Proposal ID is malformed")
        return self


class SupervisorMediatedAgentHandoff(StrictModel):
    """Authority-owned admission record that grants no read or execution authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agent-handoff/v1alpha1"] = Field(
        default="pajin.dev/agent-handoff/v1alpha1", alias="apiVersion"
    )
    kind: Literal["SupervisorMediatedAgentHandoff"] = "SupervisorMediatedAgentHandoff"
    handoff_id: str = Field(default="", alias="handoffId", max_length=78)
    handoff_digest: str = Field(default="", alias="handoffDigest", max_length=64)
    supervisor_id: str = Field(
        alias="supervisorId",
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    supervisor_digest: str = Field(alias="supervisorDigest", pattern=r"^[a-f0-9]{64}$")
    proposal: AgentHandoffProposal
    admitted_at: datetime = Field(alias="admittedAt")
    admission_state: Literal["admitted-non-executable"] = Field(
        default="admitted-non-executable", alias="admissionState"
    )
    supervisor_mediated: Literal[True] = Field(default=True, alias="supervisorMediated")
    content_read_authorized: Literal[False] = Field(default=False, alias="contentReadAuthorized")
    prompt_interpretation_authorized: Literal[False] = Field(
        default=False, alias="promptInterpretationAuthorized"
    )
    scope_expansion_authorized: Literal[False] = Field(
        default=False, alias="scopeExpansionAuthorized"
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("admitted_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Agent Handoff admission time requires an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "content_read_authorized", "prompt_interpretation_authorized",
        "scope_expansion_authorized", "capability_granted", "permit_granted",
        "execution_authorized", mode="before"
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Agent Handoff authority markers must be boolean false")
        return value

    @field_validator("supervisor_mediated", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Agent Handoff must be Supervisor mediated")
        return value

    @model_validator(mode="after")
    def bind_record(self) -> Self:
        if self.admitted_at < self.proposal.proposed_at:
            raise ValueError("Agent Handoff admission predates its Proposal")
        material = self.model_dump(
            mode="json", by_alias=True, exclude={"handoff_id", "handoff_digest"}
        )
        digest = graph_digest(
            "pajin.collaboration.agent-handoff/v1",
            material,
            max_bytes=_MAX_HANDOFF_BYTES,
        )
        handoff_id = f"agent-handoff_{digest}"
        if self.handoff_digest and self.handoff_digest != digest:
            raise ValueError("Agent Handoff digest differs")
        if self.handoff_id and self.handoff_id != handoff_id:
            raise ValueError("Agent Handoff ID differs")
        object.__setattr__(self, "handoff_digest", digest)
        object.__setattr__(self, "handoff_id", handoff_id)
        if fullmatch(_HANDOFF_ID_PATTERN, self.handoff_id) is None:
            raise ValueError("Agent Handoff ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="SupervisorMediatedAgentHandoff", max_bytes=_MAX_HANDOFF_BYTES,
        )
        return self


class AgentHandoffAuthority:
    """Single process-local Supervisor compiler for non-executable handoff records."""

    def __init__(self, *, supervisor_id: str, supervisor_digest: str) -> None:
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", supervisor_id) is None
            or fullmatch(r"^[a-f0-9]{64}$", supervisor_digest) is None
        ):
            raise ValueError("Agent Handoff Supervisor identity is invalid")
        self._supervisor_id = supervisor_id
        self._supervisor_digest = supervisor_digest
        self._records: dict[str, SupervisorMediatedAgentHandoff] = {}
        self._by_proposal: dict[str, SupervisorMediatedAgentHandoff] = {}

    def admit(
        self, proposal: AgentHandoffProposal, *, sender: AgentNode, receiver: AgentNode,
        source_task: TaskNode, destination_task: TaskNode,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_sources: Iterable[SharedArtifactSource] = (),
        admitted_at: datetime,
    ) -> SupervisorMediatedAgentHandoff:
        try:
            proposal = AgentHandoffProposal.model_validate(
                proposal.model_dump(mode="json", by_alias=True)
            )
            snapshot = verify_collaboration_snapshot(
                collaboration_snapshot, graph_snapshot_store=graph_snapshot_store,
                shared_artifact_sources=shared_artifact_sources,
            )
            expected = create_agent_handoff_proposal(
                campaign_id=snapshot.campaign_id, collaboration_snapshot=snapshot,
                sender=sender, receiver=receiver, source_task=source_task,
                destination_task=destination_task, purpose=proposal.purpose,
                proposed_at=proposal.proposed_at,
            )
            if proposal != expected:
                raise ValueError("Agent Handoff Proposal differs from verified lineage")
            if (
                sender.parent_agent_id != self._supervisor_id
                or receiver.parent_agent_id != self._supervisor_id
            ):
                raise ValueError("Agent Handoff parties are not owned by this Supervisor")
            existing = self._by_proposal.get(proposal.proposal_id)
            if existing is not None:
                return existing
            record = SupervisorMediatedAgentHandoff(
                supervisorId=self._supervisor_id, supervisorDigest=self._supervisor_digest,
                proposal=proposal, admittedAt=admitted_at,
            )
            existing = self._records.get(record.handoff_id)
            if existing is not None:
                return existing
            self._records[record.handoff_id] = record
            self._by_proposal[proposal.proposal_id] = record
            return record
        except (
            AttributeError,
            CollaborationSnapshotError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgentHandoffError("Agent Handoff could not be admitted") from exc

    def verify(
        self,
        record: SupervisorMediatedAgentHandoff,
        *,
        sender: AgentNode,
        receiver: AgentNode,
        source_task: TaskNode,
        destination_task: TaskNode,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_sources: Iterable[SharedArtifactSource] = (),
    ) -> SupervisorMediatedAgentHandoff:
        """Exact-match one already admitted record against current source authorities."""

        try:
            canonical = SupervisorMediatedAgentHandoff.model_validate(
                record.model_dump(mode="json", by_alias=True)
            )
            stored = self._records.get(canonical.handoff_id)
            if (
                canonical.supervisor_id != self._supervisor_id
                or canonical.supervisor_digest != self._supervisor_digest
                or stored != canonical
            ):
                raise ValueError("Agent Handoff was not admitted by this Supervisor")
            snapshot = verify_collaboration_snapshot(
                collaboration_snapshot,
                graph_snapshot_store=graph_snapshot_store,
                shared_artifact_sources=shared_artifact_sources,
            )
            expected = create_agent_handoff_proposal(
                campaign_id=snapshot.campaign_id,
                collaboration_snapshot=snapshot,
                sender=sender,
                receiver=receiver,
                source_task=source_task,
                destination_task=destination_task,
                purpose=canonical.proposal.purpose,
                proposed_at=canonical.proposal.proposed_at,
            )
            if canonical.proposal != expected:
                raise ValueError("Agent Handoff differs from verified lineage")
            return canonical
        except (
            AttributeError,
            CollaborationSnapshotError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgentHandoffError("Agent Handoff could not be verified") from exc

    def resolve(
        self,
        record: SupervisorMediatedAgentHandoff,
    ) -> SupervisorMediatedAgentHandoff:
        """Resolve one historical admission without claiming its Snapshot is still current."""

        try:
            canonical = SupervisorMediatedAgentHandoff.model_validate(
                record.model_dump(mode="json", by_alias=True)
            )
            stored = self._records.get(canonical.handoff_id)
            if (
                canonical.supervisor_id != self._supervisor_id
                or canonical.supervisor_digest != self._supervisor_digest
                or stored != canonical
            ):
                raise ValueError("Agent Handoff was not admitted by this Supervisor")
            return canonical
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise AgentHandoffError("Agent Handoff could not be resolved") from exc


def create_agent_handoff_proposal(
    *, campaign_id: str, collaboration_snapshot: CollaborationSnapshot,
    sender: AgentNode, receiver: AgentNode, source_task: TaskNode,
    destination_task: TaskNode, purpose: AgentHandoffPurpose, proposed_at: datetime,
) -> AgentHandoffProposal:
    sender = AgentNode.model_validate(sender.model_dump(mode="json"))
    receiver = AgentNode.model_validate(receiver.model_dump(mode="json"))
    source_task = TaskNode.model_validate(source_task.model_dump(mode="json"))
    destination_task = TaskNode.model_validate(destination_task.model_dump(mode="json"))
    if (
        sender.agent_id == receiver.agent_id
        or sender.role is AgentRole.SUPERVISOR
        or receiver.role is AgentRole.SUPERVISOR
        or sender.status is not AgentStatus.COMPLETED
        or receiver.status not in {AgentStatus.SPAWNED, AgentStatus.RUNNING}
        or source_task.status is not TaskStatus.SUCCEEDED
        or destination_task.status is not TaskStatus.WAITING
        or source_task.assigned_agent_id != sender.agent_id
        or destination_task.assigned_agent_id != receiver.agent_id
        or source_task.task_id not in destination_task.depends_on
    ):
        raise AgentHandoffError(
            "Agent Handoff lineage is not an exact completed-to-waiting transition"
        )
    return AgentHandoffProposal(
        campaignId=campaign_id,
        collaborationSnapshotId=collaboration_snapshot.collaboration_snapshot_id,
        collaborationSnapshotDigest=collaboration_snapshot.collaboration_snapshot_digest,
        sender=handoff_agent_ref(sender),
        receiver=handoff_agent_ref(receiver),
        sourceTask=handoff_task_ref(source_task),
        destinationTask=handoff_task_ref(destination_task),
        purpose=purpose,
        proposedAt=proposed_at,
    )


def handoff_agent_ref(agent: AgentNode) -> HandoffAgentRef:
    material = agent.model_dump(mode="json")
    return HandoffAgentRef(
        agentId=agent.agent_id, role=agent.role,
        identityDigest=graph_digest(
            "pajin.collaboration.handoff-agent/v1",
            material,
            max_bytes=_MAX_HANDOFF_BYTES,
        ),
    )


def handoff_task_ref(task: TaskNode) -> HandoffTaskRef:
    return HandoffTaskRef(
        taskId=task.task_id,
        taskDigest=graph_digest(
            "pajin.collaboration.handoff-task/v1",
            task.model_dump(mode="json"),
            max_bytes=_MAX_HANDOFF_BYTES,
        ),
    )
