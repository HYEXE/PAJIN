"""Deterministic, sealed, non-invocable Supervisor checkpoint scheduling."""

from __future__ import annotations

import threading
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.snapshots import CollaborationSnapshot, SharedArtifactSource
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import CampaignManifest, StrictModel
from pajin.graph.projection import GraphSnapshotReason, GraphSnapshotStore
from pajin.providers.models import ProviderRegistration
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    SealedArtifact,
    load_verified_run_artifacts,
)
from pajin.supervision.invocation import (
    SupervisorDedicatedBudgetPolicy,
    SupervisorInvocationPlanError,
    SupervisorInvocationRequestBinding,
    build_supervisor_invocation_request,
)
from pajin.supervision.model_binding import (
    SupervisorModelBinding,
    SupervisorModelConfiguration,
)
from pajin.supervision.snapshot_input import (
    SupervisorSnapshotInput,
    SupervisorSnapshotInputError,
    verify_supervisor_snapshot_input,
)

SUPERVISOR_CHECKPOINT_SCHEDULE_API_VERSION: Literal[
    "pajin.dev/supervisor-checkpoint-schedule/v1alpha1"
] = "pajin.dev/supervisor-checkpoint-schedule/v1alpha1"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_PLAN_ARTIFACT_PATH = "supervision/supervisor-checkpoint-schedule.json"
_MAX_PLAN_BYTES = 8 * 1024 * 1024


class SupervisorCheckpointScheduleError(RuntimeError):
    """Raised when a checkpoint cannot be scheduled without invocation."""


class SupervisorCheckpointSchedule(StrictModel):
    """One content-addressed checkpoint plan with no Provider dispatch authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/supervisor-checkpoint-schedule/v1alpha1"] = Field(
        default=SUPERVISOR_CHECKPOINT_SCHEDULE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorCheckpointSchedule"] = "SupervisorCheckpointSchedule"
    schedule_id: str = Field(default="", alias="scheduleId", max_length=110)
    schedule_digest: str = Field(default="", alias="scheduleDigest", max_length=64)
    checkpoint_key: _Sha256 = Field(alias="checkpointKey")
    planned_call_index: int = Field(alias="plannedCallIndex", ge=1, le=32)
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    graph_snapshot_id: str = Field(alias="graphSnapshotId", min_length=1, max_length=100)
    graph_snapshot_digest: _Sha256 = Field(alias="graphSnapshotDigest")
    graph_snapshot_revision: int = Field(alias="graphSnapshotRevision", ge=0)
    graph_snapshot_reason: GraphSnapshotReason = Field(alias="graphSnapshotReason")
    source_snapshot_id: str = Field(alias="sourceSnapshotId", min_length=1, max_length=110)
    source_snapshot_digest: _Sha256 = Field(alias="sourceSnapshotDigest")
    snapshot_input_id: str = Field(alias="snapshotInputId", min_length=1, max_length=110)
    snapshot_input_digest: _Sha256 = Field(alias="snapshotInputDigest")
    request_binding: SupervisorInvocationRequestBinding = Field(alias="requestBinding")
    request_binding_digest: _Sha256 = Field(alias="requestBindingDigest")
    dedicated_budget_policy: SupervisorDedicatedBudgetPolicy = Field(
        alias="dedicatedBudgetPolicy"
    )
    dedicated_budget_policy_digest: _Sha256 = Field(alias="dedicatedBudgetPolicyDigest")
    campaign_budget_attenuated: Literal[True] = Field(
        default=True,
        alias="campaignBudgetAttenuated",
    )
    schedule_state: Literal["scheduled-not-invoked"] = Field(
        default="scheduled-not-invoked",
        alias="scheduleState",
    )
    single_flight_scope: Literal["process-local"] = Field(
        default="process-local",
        alias="singleFlightScope",
    )
    audit_state: Literal["sealed-separate-run"] = Field(
        default="sealed-separate-run",
        alias="auditState",
    )
    task_created: Literal[False] = Field(default=False, alias="taskCreated")
    plan_mutated: Literal[False] = Field(default=False, alias="planMutated")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    model_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="modelInvocationAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    activation_eligible: Literal[False] = Field(default=False, alias="activationEligible")

    @field_validator("planned_call_index", "graph_snapshot_revision", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Supervisor checkpoint counts must be JSON integers")
        return value

    @field_validator("campaign_budget_attenuated", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        return _require_literal_bool(value, expected=True)

    @field_validator(
        "task_created",
        "plan_mutated",
        "scope_expansion_authorized",
        "model_invocation_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "activation_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        return _require_literal_bool(value, expected=False)

    @model_validator(mode="after")
    def bind_schedule(self) -> Self:
        expected_checkpoint_key = _checkpoint_key(
            self.campaign_digest,
            self.graph_snapshot_id,
            self.graph_snapshot_digest,
            self.graph_snapshot_reason,
        )
        if (
            self.checkpoint_key != expected_checkpoint_key
            or self.snapshot_input_id != self.request_binding.snapshot_input_id
            or self.snapshot_input_digest != self.request_binding.snapshot_input_digest
            or self.source_snapshot_id != self.request_binding.source_snapshot_id
            or self.source_snapshot_digest != self.request_binding.source_snapshot_digest
            or self.campaign_digest != self.request_binding.campaign_digest
            or self.request_binding_digest != self.request_binding.request_binding_digest
            or self.dedicated_budget_policy_digest
            != self.dedicated_budget_policy.policy_digest
            or self.request_binding.dedicated_budget_policy_id
            != self.dedicated_budget_policy.policy_id
            or self.request_binding.dedicated_budget_policy_digest
            != self.dedicated_budget_policy.policy_digest
            or self.planned_call_index > self.dedicated_budget_policy.max_model_calls
        ):
            raise ValueError("Supervisor checkpoint schedule differs from bound authorities")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"schedule_id", "schedule_digest"},
        )
        digest = _schedule_digest("pajin.supervision.checkpoint-schedule/v1", material)
        schedule_id = f"supervisor-checkpoint-schedule:{digest}"
        if self.schedule_digest and self.schedule_digest != digest:
            raise ValueError("Supervisor Checkpoint Schedule Digest differs")
        if self.schedule_id and self.schedule_id != schedule_id:
            raise ValueError("Supervisor Checkpoint Schedule ID differs")
        object.__setattr__(self, "schedule_digest", digest)
        object.__setattr__(self, "schedule_id", schedule_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Supervisor checkpoint schedule",
            max_bytes=_MAX_PLAN_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class SupervisorCheckpointSchedulePublication:
    """Sealed Run receipt for one non-invocable checkpoint schedule."""

    schedule: SupervisorCheckpointSchedule
    run_id: str
    root_digest: str
    artifact_path: str
    artifact_sha256: str
    run_path: Path


class SupervisorCheckpointScheduler:
    """Process-local exact-idempotent scheduler that never calls a Provider."""

    def __init__(
        self,
        *,
        output_root: Path,
        budget_policy: SupervisorDedicatedBudgetPolicy,
    ) -> None:
        self._output_root = Path(output_root)
        self._budget_policy = SupervisorDedicatedBudgetPolicy.model_validate(
            budget_policy.model_dump(mode="json", by_alias=True)
        )
        self._lock = threading.RLock()
        self._campaign_digest: str | None = None
        self._publications: dict[str, SupervisorCheckpointSchedulePublication] = {}

    def schedule(
        self,
        snapshot_input: SupervisorSnapshotInput,
        binding: SupervisorModelBinding,
        campaign: CampaignManifest,
        provider_registration: ProviderRegistration,
        *,
        model_revision: str,
        configuration: SupervisorModelConfiguration,
        collaboration_snapshot: CollaborationSnapshot,
        graph_snapshot_store: GraphSnapshotStore,
        shared_artifact_sources: Iterable[SharedArtifactSource] = (),
    ) -> SupervisorCheckpointSchedulePublication:
        """Seal one exact schedule or return the existing identical publication."""

        sources = tuple(shared_artifact_sources)
        with self._lock:
            try:
                verified_input = verify_supervisor_snapshot_input(
                    snapshot_input,
                    binding,
                    campaign,
                    provider_registration,
                    model_revision=model_revision,
                    configuration=configuration,
                    collaboration_snapshot=collaboration_snapshot,
                    graph_snapshot_store=graph_snapshot_store,
                    shared_artifact_sources=sources,
                )
                graph_snapshot = graph_snapshot_store.resolve(
                    verified_input.source_snapshot.graph_snapshot
                )
                if graph_snapshot_store.head_digest() != graph_snapshot.snapshot_digest:
                    raise ValueError("Supervisor checkpoint Graph Snapshot is stale")
                self._budget_policy.require_attenuated_by(campaign.spec.budgets)
                _chat, request_binding = build_supervisor_invocation_request(
                    verified_input,
                    verified_input.model_binding,
                    campaign,
                    provider_registration,
                    configuration,
                    self._budget_policy,
                    model_revision=model_revision,
                )
                checkpoint_key = _checkpoint_key(
                    verified_input.campaign_digest,
                    graph_snapshot.snapshot_id,
                    graph_snapshot.snapshot_digest,
                    graph_snapshot.reason,
                )
                existing = self._publications.get(checkpoint_key)
                if existing is not None:
                    if existing.schedule.request_binding != request_binding:
                        raise SupervisorCheckpointScheduleError(
                            "Supervisor checkpoint request equivocation was rejected"
                        )
                    return existing
                if (
                    self._campaign_digest is not None
                    and self._campaign_digest != verified_input.campaign_digest
                ):
                    raise SupervisorCheckpointScheduleError(
                        "Supervisor scheduler cannot cross Campaign authority"
                    )
                planned_call_index = len(self._publications) + 1
                if planned_call_index > self._budget_policy.max_model_calls:
                    raise SupervisorCheckpointScheduleError(
                        "Supervisor dedicated model-call ceiling was exceeded"
                    )
                schedule = SupervisorCheckpointSchedule(
                    checkpointKey=checkpoint_key,
                    plannedCallIndex=planned_call_index,
                    campaignDigest=verified_input.campaign_digest,
                    graphSnapshotId=graph_snapshot.snapshot_id,
                    graphSnapshotDigest=graph_snapshot.snapshot_digest,
                    graphSnapshotRevision=graph_snapshot.revision,
                    graphSnapshotReason=graph_snapshot.reason,
                    sourceSnapshotId=verified_input.source_snapshot_id,
                    sourceSnapshotDigest=verified_input.source_snapshot_digest,
                    snapshotInputId=verified_input.input_id,
                    snapshotInputDigest=verified_input.input_digest,
                    requestBinding=request_binding,
                    requestBindingDigest=request_binding.request_binding_digest,
                    dedicatedBudgetPolicy=self._budget_policy,
                    dedicatedBudgetPolicyDigest=self._budget_policy.policy_digest,
                )
                publication = self._publish(schedule, campaign)
                self._campaign_digest = verified_input.campaign_digest
                self._publications[checkpoint_key] = publication
                return publication
            except SupervisorCheckpointScheduleError:
                raise
            except (
                AttributeError,
                RunIntegrityError,
                SupervisorInvocationPlanError,
                SupervisorSnapshotInputError,
                TypeError,
                ValidationError,
                ValueError,
            ) as exc:
                raise SupervisorCheckpointScheduleError(
                    "Supervisor checkpoint scheduling failed closed"
                ) from exc

    def _publish(
        self,
        schedule: SupervisorCheckpointSchedule,
        campaign: CampaignManifest,
    ) -> SupervisorCheckpointSchedulePublication:
        store = RunStore.create(self._output_root, campaign.metadata.name)
        artifact_path = store.write_json_create_only(
            _PLAN_ARTIFACT_PATH,
            schedule.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "supervisor.checkpoint.scheduled",
            {
                "scheduleId": schedule.schedule_id,
                "scheduleDigest": schedule.schedule_digest,
                "checkpointKey": schedule.checkpoint_key,
                "sourceSnapshotId": schedule.source_snapshot_id,
                "sourceSnapshotDigest": schedule.source_snapshot_digest,
                "requestBindingId": schedule.request_binding.request_binding_id,
                "requestBindingDigest": schedule.request_binding_digest,
                "state": schedule.schedule_state,
                "artifact": artifact_path,
            },
        )
        seal = store.seal()
        artifact = _published_artifact(seal.artifacts, artifact_path)
        return SupervisorCheckpointSchedulePublication(
            schedule=schedule.model_copy(deep=True),
            run_id=store.run_id,
            root_digest=seal.root_digest,
            artifact_path=artifact.path,
            artifact_sha256=artifact.sha256,
            run_path=store.path.resolve(),
        )


def verify_supervisor_checkpoint_schedule_publication(
    publication: SupervisorCheckpointSchedulePublication,
    snapshot_input: SupervisorSnapshotInput,
    binding: SupervisorModelBinding,
    campaign: CampaignManifest,
    provider_registration: ProviderRegistration,
    *,
    model_revision: str,
    configuration: SupervisorModelConfiguration,
    budget_policy: SupervisorDedicatedBudgetPolicy,
    collaboration_snapshot: CollaborationSnapshot,
    graph_snapshot_store: GraphSnapshotStore,
    shared_artifact_sources: Iterable[SharedArtifactSource] = (),
) -> SupervisorCheckpointSchedule:
    """Rebuild one plan and exact-match its separate sealed Run publication."""

    try:
        if publication.artifact_path != _PLAN_ARTIFACT_PATH:
            raise ValueError("Supervisor schedule artifact path differs")
        canonical_schedule = SupervisorCheckpointSchedule.model_validate(
            publication.schedule.model_dump(mode="json", by_alias=True)
        )
        snapshot = load_verified_run_artifacts(
            publication.run_path,
            requests={publication.artifact_path: _MAX_PLAN_BYTES},
            expected_run_id=publication.run_id,
        )
        if snapshot.verification.root_digest != publication.root_digest:
            raise ValueError("Supervisor schedule Run root differs")
        if (
            snapshot.verification.seal_count != 1
            or snapshot.verification.artifact_count != 1
            or snapshot.verification.event_count != 1
            or len(snapshot.seals) != 1
            or len(snapshot.events) != 1
        ):
            raise ValueError("Supervisor schedule Run shape differs")
        artifact = snapshot.artifact_bytes(publication.artifact_path)
        if sha256(artifact).hexdigest() != publication.artifact_sha256:
            raise ValueError("Supervisor schedule artifact digest differs")
        sealed_schedule = SupervisorCheckpointSchedule.model_validate(
            parse_strict_json_bytes(
                artifact,
                label="sealed Supervisor checkpoint schedule",
                max_bytes=_MAX_PLAN_BYTES,
            )
        )
        if sealed_schedule != canonical_schedule:
            raise ValueError("Supervisor schedule differs from its sealed artifact")
        expected_event_payload: dict[str, object] = {
            "scheduleId": sealed_schedule.schedule_id,
            "scheduleDigest": sealed_schedule.schedule_digest,
            "checkpointKey": sealed_schedule.checkpoint_key,
            "sourceSnapshotId": sealed_schedule.source_snapshot_id,
            "sourceSnapshotDigest": sealed_schedule.source_snapshot_digest,
            "requestBindingId": sealed_schedule.request_binding.request_binding_id,
            "requestBindingDigest": sealed_schedule.request_binding_digest,
            "state": sealed_schedule.schedule_state,
            "artifact": publication.artifact_path,
        }
        matching_events = [
            event
            for event in snapshot.events
            if event.event_type == "supervisor.checkpoint.scheduled"
            and event.payload == expected_event_payload
        ]
        if len(matching_events) != 1:
            raise ValueError("Supervisor schedule audit event differs")

        sources = tuple(shared_artifact_sources)
        verified_input = verify_supervisor_snapshot_input(
            snapshot_input,
            binding,
            campaign,
            provider_registration,
            model_revision=model_revision,
            configuration=configuration,
            collaboration_snapshot=collaboration_snapshot,
            graph_snapshot_store=graph_snapshot_store,
            shared_artifact_sources=sources,
        )
        graph_snapshot = graph_snapshot_store.resolve(
            verified_input.source_snapshot.graph_snapshot
        )
        if graph_snapshot_store.head_digest() != graph_snapshot.snapshot_digest:
            raise ValueError("Supervisor schedule Graph Snapshot is stale")
        expected_budget_policy = SupervisorDedicatedBudgetPolicy.model_validate(
            budget_policy.model_dump(mode="json", by_alias=True)
        )
        expected_budget_policy.require_attenuated_by(campaign.spec.budgets)
        if canonical_schedule.dedicated_budget_policy != expected_budget_policy:
            raise ValueError("Supervisor schedule dedicated budget differs from expected authority")
        _chat, request_binding = build_supervisor_invocation_request(
            verified_input,
            verified_input.model_binding,
            campaign,
            provider_registration,
            configuration,
            expected_budget_policy,
            model_revision=model_revision,
        )
        expected = SupervisorCheckpointSchedule(
            checkpointKey=_checkpoint_key(
                verified_input.campaign_digest,
                graph_snapshot.snapshot_id,
                graph_snapshot.snapshot_digest,
                graph_snapshot.reason,
            ),
            plannedCallIndex=canonical_schedule.planned_call_index,
            campaignDigest=verified_input.campaign_digest,
            graphSnapshotId=graph_snapshot.snapshot_id,
            graphSnapshotDigest=graph_snapshot.snapshot_digest,
            graphSnapshotRevision=graph_snapshot.revision,
            graphSnapshotReason=graph_snapshot.reason,
            sourceSnapshotId=verified_input.source_snapshot_id,
            sourceSnapshotDigest=verified_input.source_snapshot_digest,
            snapshotInputId=verified_input.input_id,
            snapshotInputDigest=verified_input.input_digest,
            requestBinding=request_binding,
            requestBindingDigest=request_binding.request_binding_digest,
            dedicatedBudgetPolicy=expected_budget_policy,
            dedicatedBudgetPolicyDigest=expected_budget_policy.policy_digest,
        )
        if expected != canonical_schedule:
            raise ValueError("Supervisor schedule differs from current authorities")
        return canonical_schedule.model_copy(deep=True)
    except SupervisorCheckpointScheduleError:
        raise
    except (
        AttributeError,
        RunIntegrityError,
        SupervisorInvocationPlanError,
        SupervisorSnapshotInputError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorCheckpointScheduleError(
            "Supervisor checkpoint schedule verification failed closed"
        ) from exc


def _checkpoint_key(
    campaign_digest: str,
    graph_snapshot_id: str,
    graph_snapshot_digest: str,
    reason: GraphSnapshotReason,
) -> str:
    return _schedule_digest(
        "pajin.supervision.checkpoint-key/v1",
        {
            "campaignDigest": campaign_digest,
            "graphSnapshotId": graph_snapshot_id,
            "graphSnapshotDigest": graph_snapshot_digest,
            "reason": reason.value,
        },
    )


def _published_artifact(
    artifacts: list[SealedArtifact],
    path: str,
) -> SealedArtifact:
    matches = [artifact for artifact in artifacts if artifact.path == path]
    if len(matches) != 1:
        raise SupervisorCheckpointScheduleError(
            "Supervisor checkpoint schedule artifact was not sealed exactly once"
        )
    return matches[0]


def _schedule_digest(domain: str, value: object) -> str:
    domain_bytes = domain.encode("ascii", errors="strict")
    payload = canonical_json_bytes(
        value,
        label="Supervisor checkpoint identity",
        max_bytes=_MAX_PLAN_BYTES,
    )
    return sha256(domain_bytes + b"\x00" + payload).hexdigest()


def _require_literal_bool(value: object, *, expected: bool) -> bool:
    if type(value) is not bool or value is not expected:
        raise ValueError(f"Supervisor checkpoint authority marker must be {expected}")
    return expected
