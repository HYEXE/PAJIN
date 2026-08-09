"""Trusted Job-kind bindings for the Control Plane Worker daemon."""

from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Awaitable, Callable
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from inspect import Parameter, signature
from pathlib import Path
from re import fullmatch
from typing import Any, Literal, Protocol

from pydantic import Field, ValidationError, model_validator

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.capabilities import (
    CAPABILITY_DISPATCH_RECONCILIATION_EVENT_TYPE,
    CapabilityDefinition,
    CapabilityDispatchAuditEvent,
    CapabilityDispatchReconciliationError,
    CapabilityDispatchReconciliationObservation,
    CapabilityDispatchStage,
    CapabilityReleaseRef,
    CapabilitySideEffectClass,
    ExistingModeCapabilityActivationError,
    ExistingModeCapabilityGatewayDispatcher,
    PreparedCapabilityAction,
    capability_gateway_outcome_digest,
    reconcile_capability_dispatch,
)
from pajin.control_plane.capability_deployment import (
    CapabilityGraphDeploymentRuntime,
)
from pajin.control_plane.models import ApprovalIntent, JobKind, JobView
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolRiskTier,
)
from pajin.domain.validation import FindingDisposition
from pajin.graph import (
    ActionApprovalAuthorization,
    ActionApprovalBatchCompletion,
    ActionApprovalBatchEnvelope,
    ActionApprovalBatchError,
    ActionApprovalBatchItemState,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionPermit,
    ActionProposal,
    ApprovalBoundActionDispatchResult,
    GraphActionPermitDispatcher,
    GraphApprovalBoundActionPermitDispatcher,
    GraphDecision,
    MissionEnvelope,
)
from pajin.policy.engine import PolicyEngine
from pajin.providers import OpenAICompatibleChatTool, ProviderRegistration
from pajin.providers.models import NormalizedToolCall, ProviderChatResult, ProviderUsage
from pajin.runtime.control import ExecutionCancellationContext
from pajin.runtime.error_safety import audit_safe_exception_diagnostic
from pajin.runtime.execution_context import (
    WorkerEvidenceScope,
    WorkerExecutionContext,
    worker_execution_context,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.worker import (
    SimulatedWorkerBackend,
    WorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, ToolGateway
from pajin.tools.mock import ApprovalCheckTool, MockAgentProbe, SleepCheckTool
from pajin.workflow.cancellation import seal_executor_quiescence
from pajin.workflow.local import LocalCampaignRunner, LocalToolExecutionError
from pajin.workflow.tool_loop import (
    PolicyToolLoopRunner,
    ToolLoopApproval,
    ToolLoopBinding,
    ToolLoopCheckpoint,
    ToolLoopOutcome,
    ToolLoopStatus,
)

_MAX_TOOL_LOOP_CHECKPOINT_BYTES = 64 * 1024 * 1024
_MAX_TOOL_LOOP_RUN_SUMMARY_BYTES = 1 * 1024 * 1024
_MAX_EXECUTION_CONTEXT_BYTES = 16 * 1024


class ExecutionError(RuntimeError):
    """Base class for bounded Job execution errors."""


class PermanentExecutionError(ExecutionError):
    pass


class TransientExecutionError(ExecutionError):
    pass


class CompletedExecution(StrictModel):
    result: dict[str, Any]


class ApprovalCheckpointExecution(StrictModel):
    state: dict[str, Any]
    pending_intent: ApprovalIntent


type ExecutionOutcome = CompletedExecution | ApprovalCheckpointExecution


def _secure_resume_platform_available(*, platform_name: str | None = None) -> bool:
    """Return whether checkpoint leaves can be anchored without path re-resolution."""

    required_dir_fd_operations = (os.open, os.mkdir, os.unlink)
    return bool(
        (os.name if platform_name is None else platform_name) == "posix"
        and hasattr(os, "fchmod")
        and hasattr(os, "O_DIRECTORY")
        and hasattr(os, "O_NOFOLLOW")
        and all(operation in os.supports_dir_fd for operation in required_dir_fd_operations)
    )


def _require_secure_resume_platform() -> None:
    if _secure_resume_platform_available():
        return
    raise PermanentExecutionError(
        "continuation checkpoints require a POSIX dirfd platform; "
        "run the Worker in the Linux container or WSL"
    )


class JobExecutor(Protocol):
    kind: JobKind

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ExecutionOutcome:
        """Execute only the typed payload bound to this trusted kind."""


class CampaignJobInput(StrictModel):
    manifest: CampaignManifest
    profile: Literal["deterministic-local"] = "deterministic-local"

    @model_validator(mode="after")
    def restrict_local_targets(self) -> CampaignJobInput:
        supported = {"mock-agent", "mock-sleep"}
        unknown = {target.type for target in self.manifest.spec.targets} - supported
        if unknown:
            raise ValueError(f"deterministic-local profile rejects target types: {sorted(unknown)}")
        return self


class CapabilityGraphCampaignJobInput(StrictModel):
    """One exact Graph decision dispatched through a startup-pinned deployment."""

    profile: Literal["capability-graph-v1"]
    proposal: ActionProposal
    decision: GraphDecision
    release: CapabilityReleaseRef
    request: ToolRequest
    grant: CapabilityGrant
    approval: ActionApprovalEnvelope | None = None

    @model_validator(mode="after")
    def bind_job_authority(self) -> CapabilityGraphCampaignJobInput:
        if self.proposal.campaign_id != self.decision.campaign_id:
            raise ValueError("Capability Graph Job authority belongs to another Campaign or Run")
        if self.approval is not None and (
            self.approval.proposal != self.proposal
            or self.approval.graph_decision != self.decision
            or self.approval.release.release_id != self.release.release_id
            or self.approval.release.release_digest != self.release.release_digest
        ):
            raise ValueError("Capability Graph Job approval differs from its exact action")
        return self


class CapabilityGraphBatchCampaignJobInput(StrictModel):
    """One exact deployment-pinned batch item selected by an opt-in Job profile."""

    profile: Literal["capability-graph-batch-v1"]
    batch_id: str = Field(
        alias="batchId",
        pattern=r"^action-approval-batch_[a-f0-9]{64}$",
    )
    batch_digest: str = Field(alias="batchDigest", pattern=r"^[a-f0-9]{64}$")
    item_ordinal: int = Field(alias="itemOrdinal", ge=1, le=8)
    proposal: ActionProposal
    decision: GraphDecision
    release: CapabilityReleaseRef
    request: ToolRequest
    grant: CapabilityGrant

    @model_validator(mode="after")
    def bind_job_authority(self) -> CapabilityGraphBatchCampaignJobInput:
        if self.proposal.campaign_id != self.decision.campaign_id:
            raise ValueError(
                "Capability Graph batch Job authority belongs to another Campaign or Run"
            )
        return self


class _CapabilityGraphBatchPermitDispatcher:
    """Adapt one pinned batch item to the existing Capability Gateway permit protocol."""

    def __init__(
        self,
        *,
        runtime: CapabilityGraphDeploymentRuntime,
        batch: ActionApprovalBatchEnvelope,
        ordinal: int,
        store: RunStore,
    ) -> None:
        self._runtime = runtime
        self._batch = batch
        self._ordinal = ordinal
        self._store = store

    async def dispatch_once(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        dispatch: Callable[[ActionPermit], Awaitable[GatewayOutcome]],
    ) -> ApprovalBoundActionDispatchResult[GatewayOutcome]:
        coordinator = self._runtime.approval_batch_dispatcher
        if coordinator is None:
            raise PermanentExecutionError(
                "capability-graph-batch-v1 requires a deployment-pinned coordinator"
            )
        approval = self._batch.approval_at(self._ordinal)
        if (
            envelope != approval.mission_envelope
            or proposal != approval.proposal
            or decision != approval.graph_decision
            or self._batch.cleanup_request_at(self._ordinal) is not None
        ):
            raise PermanentExecutionError(
                "capability-graph-batch-v1 item differs from the Gateway dispatch"
            )
        observed: GatewayOutcome | None = None

        async def consume(
            permit: ActionPermit,
            receipt: ActionApprovalConsumptionReceipt,
        ) -> ActionApprovalBatchCompletion:
            nonlocal observed
            observed = await dispatch(permit)
            self._store.seal()
            return ActionApprovalBatchCompletion(
                batchId=self._batch.batch_id,
                batchDigest=self._batch.batch_digest,
                itemOrdinal=self._ordinal,
                approvalId=approval.approval_id,
                approvalDigest=approval.approval_digest,
                permitId=permit.permit_id,
                permitDigest=permit.permit_digest,
                receiptId=receipt.receipt_id,
                receiptDigest=receipt.receipt_digest,
                outcome="succeeded",
                source="worker-completion",
                evidenceDigest=capability_gateway_outcome_digest(observed),
                completedAt=self._runtime.clock(),
            )

        try:
            result = await coordinator.dispatch_item_once(
                self._batch,
                self._ordinal,
                consume,
            )
        except ActionApprovalBatchError as exc:
            raise PermanentExecutionError(
                "capability-graph-batch-v1 coordination failed closed"
            ) from exc
        authorization = result.authorization
        if (
            not result.dispatched
            and result.item.state is not ActionApprovalBatchItemState.TERMINAL_SUCCEEDED
        ):
            raise PermanentExecutionError(
                "capability-graph-batch-v1 item requires manual review; redispatch is prohibited"
            )
        if isinstance(authorization, ActionApprovalAuthorization):
            permit = authorization.action.permit
            receipt = authorization.receipt
        else:
            permit = self._stored_permit(result.item.permit_id, result.item.permit_digest)
            receipt = self._stored_receipt(
                result.item.receipt_id,
                result.item.receipt_digest,
            )
        return ApprovalBoundActionDispatchResult(
            permit=permit,
            approval_receipt=receipt,
            dispatched=result.dispatched,
            result=observed if result.dispatched else None,
        )

    def _stored_permit(self, permit_id: str | None, permit_digest: str | None) -> ActionPermit:
        matches = tuple(
            item
            for item in self._runtime.graph_store.permit_store.permits()
            if item.permit_id == permit_id and item.permit_digest == permit_digest
        )
        if len(matches) != 1:
            raise PermanentExecutionError(
                "capability-graph-batch-v1 durable Permit is absent or equivocated"
            )
        return matches[0]

    def _stored_receipt(
        self,
        receipt_id: str | None,
        receipt_digest: str | None,
    ) -> ActionApprovalConsumptionReceipt:
        matches = tuple(
            item
            for item in self._runtime.graph_store.permit_store.approval_consumptions()
            if item.receipt_id == receipt_id and item.receipt_digest == receipt_digest
        )
        if len(matches) != 1:
            raise PermanentExecutionError(
                "capability-graph-batch-v1 durable approval receipt is absent or equivocated"
            )
        return matches[0]


class ToolLoopJobInput(StrictModel):
    manifest: CampaignManifest
    prompt: str = Field(min_length=1, max_length=32_768)
    profile: Literal["deterministic-approval-lab"] = "deterministic-approval-lab"

    @model_validator(mode="after")
    def restrict_lab_target(self) -> ToolLoopJobInput:
        if len(self.manifest.spec.targets) != 1:
            raise ValueError("deterministic tool-loop profile requires exactly one target")
        if self.manifest.spec.targets[0].type != "mock-agent":
            raise ValueError("deterministic tool-loop profile requires a mock-agent target")
        return self


class _ToolLoopRunSummary(StrictModel):
    run_id: str = Field(alias="runId")
    loop_id: str = Field(alias="loopId")
    status: ToolLoopStatus
    error: str | None = Field(default=None, max_length=2_000)
    checkpoint: str
    execution_context: Literal["execution-context.json"] = Field(alias="executionContext")
    worker_backend: Literal["docker", "simulated", "custom"] = Field(alias="workerBackend")
    simulated: bool
    evidence_scope: WorkerEvidenceScope = Field(alias="evidenceScope")


class _CampaignRunSummary(StrictModel):
    run_id: str = Field(alias="runId")
    status: Literal["completed"]
    stage: Literal["finalization"]
    execution_context: Literal["execution-context.json"] = Field(alias="executionContext")
    worker_backend: Literal["docker", "simulated", "custom"] = Field(alias="workerBackend")
    simulated: bool
    evidence_scope: WorkerEvidenceScope = Field(alias="evidenceScope")
    report: str


class ToolLoopResumeState(StrictModel):
    job_input: ToolLoopJobInput
    tool_loop_checkpoint: ToolLoopCheckpoint


class ConsumedApproval(StrictModel):
    call_fingerprint: str = Field(alias="callFingerprint", pattern=r"^[0-9a-f]{64}$")
    tool_id: str = Field(alias="toolId")
    target: str
    risk_tier: int = Field(alias="riskTier", ge=3, le=4)
    approved_by: str = Field(alias="approvedBy", min_length=1)
    approved_at: datetime = Field(alias="approvedAt")
    expires_at: datetime = Field(alias="expiresAt")


class ExecutorRegistry:
    """Fail closed when a Job kind has no trusted, pre-registered adapter."""

    def __init__(self, executors: list[JobExecutor]) -> None:
        self._executors: dict[str, JobExecutor] = {}
        for executor in executors:
            cancellation_parameter = signature(executor.execute).parameters.get("cancellation")
            if cancellation_parameter is None or cancellation_parameter.kind not in {
                Parameter.POSITIONAL_OR_KEYWORD,
                Parameter.KEYWORD_ONLY,
            }:
                raise ValueError(
                    f"Job executor {executor.kind.value} must accept a cancellation context"
                )
            if executor.kind.value in self._executors:
                raise ValueError(f"duplicate Job executor: {executor.kind.value}")
            self._executors[executor.kind.value] = executor
        if not self._executors:
            raise ValueError("Worker daemon requires at least one Job executor")

    @property
    def kinds(self) -> list[str]:
        return sorted(self._executors)

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ExecutionOutcome:
        executor = self._executors.get(job.kind)
        if executor is None:
            raise PermanentExecutionError(f"unregistered Job kind: {job.kind}")
        # Keep the daemon's claimed Job identity private.  Executors are pluggable
        # components and may retain or mutate their input; finalization must always
        # remain bound to the original claim and lease held by the daemon.
        return await executor.execute(job.model_copy(deep=True), cancellation=cancellation)


class CampaignJobExecutor:
    kind = JobKind.CAMPAIGN

    def __init__(
        self,
        *,
        output_root: Path,
        worker: WorkerBackend | None = None,
        capability_deployment: CapabilityGraphDeploymentRuntime | None = None,
    ) -> None:
        self._output_root = output_root
        self._worker = worker or SimulatedWorkerBackend()
        self._capability_deployment = capability_deployment

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> CompletedExecution:
        raw_input = self._input(job)
        if raw_input.get("profile") in {
            "capability-graph-v1",
            "capability-graph-batch-v1",
        }:
            return await self._execute_capability_graph(
                job,
                raw_input,
                cancellation=cancellation,
            )
        job_input = CampaignJobInput.model_validate(raw_input)
        self._require_legacy_profile_risk_policy(job_input)
        tools = ToolRegistry()
        tools.register(MockAgentProbe())
        tools.register(SleepCheckTool())
        runner = LocalCampaignRunner(
            agents=DeterministicAgentRuntime(),
            tools=tools,
            policy=PolicyEngine(),
            worker=self._worker,
            output_root=self._output_root,
        )
        try:
            outcome = await runner.run(job_input.manifest, cancellation=cancellation)
        except asyncio.CancelledError:
            if cancellation is not None and cancellation.active:
                seal_executor_quiescence(cancellation)
            raise
        except LocalToolExecutionError as exc:
            raise PermanentExecutionError("local campaign Tool execution failed") from exc
        needs_review = sum(
            decision.disposition is FindingDisposition.NEEDS_REVIEW
            for decision in outcome.validation.decisions
        )
        execution_context = self._verified_execution_context(
            outcome.run_path,
            run_id=outcome.run_id,
            expected=worker_execution_context(self._worker),
        )
        return CompletedExecution(
            result={
                "engine": "local-campaign",
                "executionProfile": job_input.profile,
                "executionContext": execution_context.model_dump(mode="json", by_alias=True),
                "engineRunId": outcome.run_id,
                "runPath": str(outcome.run_path.resolve()),
                "reportPath": str(outcome.report_path.resolve()),
                "toolCalls": len(outcome.tool_results),
                "failedToolCalls": 0,
                "validatedFindings": len(outcome.findings),
                "confirmedFindings": len(outcome.findings),
                "needsReviewCandidates": needs_review,
            }
        )

    async def _execute_capability_graph(
        self,
        job: JobView,
        raw_input: dict[str, Any],
        *,
        cancellation: ExecutionCancellationContext | None,
    ) -> CompletedExecution:
        runtime = self._capability_deployment
        if runtime is None:
            raise PermanentExecutionError(
                "capability-graph-v1 requires a startup-pinned Worker deployment"
            )
        batch_profile = raw_input.get("profile") == "capability-graph-batch-v1"
        try:
            job_input: CapabilityGraphCampaignJobInput | CapabilityGraphBatchCampaignJobInput = (
                CapabilityGraphBatchCampaignJobInput.model_validate(raw_input)
                if batch_profile
                else CapabilityGraphCampaignJobInput.model_validate(raw_input)
            )
        except ValidationError as exc:
            raise PermanentExecutionError(
                f"{raw_input.get('profile')} Job input is invalid"
            ) from exc
        deployment = runtime.deployment
        campaign = deployment.campaign
        envelope = deployment.mission_envelope
        if (
            job_input.proposal.campaign_id != campaign.metadata.name
            or job_input.proposal.run_id != envelope.run_id
        ):
            raise PermanentExecutionError(
                "capability-graph-v1 Job differs from its deployed Campaign authority"
            )
        batch: ActionApprovalBatchEnvelope | None = None
        if isinstance(job_input, CapabilityGraphBatchCampaignJobInput):
            batch = runtime.approval_batch(job_input.batch_id)
            if (
                batch.batch_digest != job_input.batch_digest
                or batch.approval_at(job_input.item_ordinal).proposal != job_input.proposal
                or batch.approval_at(job_input.item_ordinal).graph_decision != job_input.decision
            ):
                raise PermanentExecutionError(
                    "capability-graph-batch-v1 Job differs from its deployment-pinned item"
                )
        try:
            prepared = runtime.activation.prepare_action(
                release=job_input.release,
                request=job_input.request,
                parameters=job_input.request.arguments,
            )
        except ExistingModeCapabilityActivationError as exc:
            raise PermanentExecutionError(
                "capability-graph-v1 request preparation failed closed"
            ) from exc
        store = runtime.open_run_store(envelope.run_id)
        permits = self._capability_graph_permits(
            runtime,
            job_input,
            prepared,
            store=store,
            batch=batch,
        )
        used_calls = sum(
            permit.run_id == envelope.run_id
            for permit in runtime.graph_store.permit_store.permits()
        )
        gateway = ToolGateway(
            policy=PolicyEngine(),
            tools=runtime.tools,
            worker=self._worker,
            store=store,
            allow_secret_requests=False,
            clock=runtime.clock,
        )
        dispatcher = ExistingModeCapabilityGatewayDispatcher(
            activation=runtime.activation,
            permits=permits,
            gateway=gateway,
            audit_store=store,
            clock=runtime.clock,
        )
        try:
            dispatched = await dispatcher.dispatch_once(
                envelope,
                job_input.proposal,
                job_input.decision,
                prepared,
                campaign=campaign,
                grant=job_input.grant,
                used_calls=used_calls,
            )
        except asyncio.CancelledError:
            self._seal_failed_dispatch(store)
            if cancellation is not None and cancellation.active:
                seal_executor_quiescence(cancellation)
            raise
        except Exception:
            self._seal_failed_dispatch(store)
            raise
        if dispatched.dispatched and not batch_profile:
            store.seal()
        reconciliation = self._verified_dispatch_reconciliation(
            store,
            dispatched.permit,
        )
        terminal = reconciliation.terminal_event
        if terminal is None:
            self._record_incomplete_dispatch_reconciliation(
                store,
                dispatched.permit,
                reconciliation,
            )
            raise PermanentExecutionError(
                "Capability dispatch is permanently consumed with reconciliation status "
                f"{reconciliation.record.status.value}; automatic redispatch is prohibited"
            )
        outcome = dispatched.result
        if outcome is not None:
            observed_digest = capability_gateway_outcome_digest(outcome)
            if (
                terminal.stage is not CapabilityDispatchStage.COMPLETED
                or terminal.gateway_outcome_digest != observed_digest
            ):
                raise PermanentExecutionError(
                    "Capability Gateway outcome differs from its sealed dispatch audit"
                )
        return self._capability_graph_result(
            job,
            dispatched.permit,
            terminal,
            execution_profile=job_input.profile,
            outcome=outcome,
            dispatched=dispatched.dispatched,
            approval_receipt=(
                dispatched.approval_receipt
                if isinstance(dispatched, ApprovalBoundActionDispatchResult)
                else None
            ),
        )

    @staticmethod
    def _capability_graph_permits(
        runtime: CapabilityGraphDeploymentRuntime,
        job_input: CapabilityGraphCampaignJobInput | CapabilityGraphBatchCampaignJobInput,
        prepared: PreparedCapabilityAction,
        *,
        store: RunStore,
        batch: ActionApprovalBatchEnvelope | None,
    ) -> (
        GraphActionPermitDispatcher
        | GraphApprovalBoundActionPermitDispatcher
        | _CapabilityGraphBatchPermitDispatcher
    ):
        approval = (
            batch.approval_at(job_input.item_ordinal)
            if isinstance(job_input, CapabilityGraphBatchCampaignJobInput) and batch is not None
            else job_input.approval
            if isinstance(job_input, CapabilityGraphCampaignJobInput)
            else None
        )
        if approval is not None and (
            approval.release.release_id != prepared.release.release_id
            or approval.release.release_digest != prepared.release.release_digest
            or approval.release.capability_id != prepared.capability.capability_id
            or approval.release.capability_version != prepared.capability.capability_version
            or approval.release.capability_digest != prepared.capability.definition_digest
        ):
            raise PermanentExecutionError(
                "capability-graph-v1 approval differs from the prepared release"
            )
        binding = next(
            (
                item
                for item in runtime.activation.activation_set.bindings
                if item.release == prepared.release
                and item.action_capability.reference() == prepared.capability
            ),
            None,
        )
        if binding is None:
            raise PermanentExecutionError(
                "capability-graph-v1 prepared Capability is not in the activation set"
            )
        definition = runtime.activation.rollout.bundle.definitions.resolve(
            binding.capability.capability
        )
        CampaignJobExecutor._require_capability_graph_definition_policy(definition)
        if prepared.capability.risk_tier >= ToolRiskTier.T3:
            raise PermanentExecutionError(
                "capability-graph-v1 T3 or higher action is not executable"
            )
        requires_approval = (
            prepared.capability.risk_tier is ToolRiskTier.T2 or definition.approval_required
        )
        if requires_approval:
            if approval is None or runtime.approved_permits is None:
                raise PermanentExecutionError(
                    "capability-graph-v1 action requires deployment-pinned approval"
                )
            if isinstance(job_input, CapabilityGraphBatchCampaignJobInput):
                if batch is None or runtime.approval_batch_dispatcher is None:
                    raise PermanentExecutionError(
                        "capability-graph-batch-v1 coordinator is not deployment-pinned"
                    )
                return _CapabilityGraphBatchPermitDispatcher(
                    runtime=runtime,
                    batch=batch,
                    ordinal=job_input.item_ordinal,
                    store=store,
                )
            return GraphApprovalBoundActionPermitDispatcher(
                runtime.approved_permits,
                approval,
            )
        if approval is not None:
            raise PermanentExecutionError(
                "capability-graph-v1 Job supplies an approval outside current policy"
            )
        return runtime.permits

    @staticmethod
    def _require_legacy_profile_risk_policy(job_input: CampaignJobInput) -> None:
        target_tools = {
            "mock-agent": MockAgentProbe.spec,
            "mock-sleep": SleepCheckTool.spec,
        }
        elevated_tools = sorted(
            {
                target_tools[target.type].tool_id
                for target in job_input.manifest.spec.targets
                if target_tools[target.type].risk_tier >= ToolRiskTier.T2
            }
        )
        if elevated_tools:
            raise PermanentExecutionError(
                "deterministic-local T2 action requires an approval-aware execution profile: "
                + ", ".join(elevated_tools)
            )

    @staticmethod
    def _require_capability_graph_definition_policy(
        definition: CapabilityDefinition,
    ) -> None:
        if definition.cleanup_required or definition.side_effect_class not in {
            CapabilitySideEffectClass.NONE,
            CapabilitySideEffectClass.READ_ONLY,
        }:
            raise PermanentExecutionError(
                "capability-graph-v1 write or cleanup action requires a cleanup-aware authority"
            )

    @staticmethod
    def _seal_failed_dispatch(store: RunStore) -> None:
        try:
            store.seal()
        except (OSError, RunIntegrityError, ValueError):
            # The original dispatch failure remains authoritative. A retry must
            # verify a sealed terminal audit before it can finish.
            return

    @staticmethod
    def _verified_dispatch_reconciliation(
        store: RunStore,
        permit: ActionPermit,
    ) -> CapabilityDispatchReconciliationObservation:
        try:
            snapshot = load_verified_run_snapshot(
                store.path,
                expected_run_id=store.run_id,
            )
            return reconcile_capability_dispatch(snapshot, permit)
        except (
            AttributeError,
            CapabilityDispatchReconciliationError,
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
        ) as exc:
            raise PermanentExecutionError(
                "Capability dispatch does not have a reconcilable sealed audit"
            ) from exc

    def _record_incomplete_dispatch_reconciliation(
        self,
        store: RunStore,
        permit: ActionPermit,
        observation: CapabilityDispatchReconciliationObservation,
    ) -> None:
        if observation.already_recorded:
            return
        runtime = self._capability_deployment
        assert runtime is not None
        try:
            store.append_unique_event(
                CAPABILITY_DISPATCH_RECONCILIATION_EVENT_TYPE,
                observation.record.model_dump(mode="json", by_alias=True),
                occurred_at=runtime.clock(),
                unique_by="permitId",
            )
            store.seal()
            verified = reconcile_capability_dispatch(
                load_verified_run_snapshot(
                    store.path,
                    expected_run_id=store.run_id,
                ),
                permit,
            )
        except (
            CapabilityDispatchReconciliationError,
            OSError,
            RunIntegrityError,
            ValidationError,
            ValueError,
        ) as exc:
            raise PermanentExecutionError(
                "Capability dispatch reconciliation record could not be sealed"
            ) from exc
        if (
            not verified.already_recorded
            or verified.record != observation.record
            or verified.terminal_event is not None
        ):
            raise PermanentExecutionError(
                "Capability dispatch reconciliation record changed after sealing"
            )

    def _capability_graph_result(
        self,
        job: JobView,
        permit: ActionPermit,
        terminal: CapabilityDispatchAuditEvent,
        *,
        execution_profile: Literal[
            "capability-graph-v1",
            "capability-graph-batch-v1",
        ],
        outcome: GatewayOutcome | None,
        dispatched: bool,
        approval_receipt: ActionApprovalConsumptionReceipt | None,
    ) -> CompletedExecution:
        runtime = self._capability_deployment
        assert runtime is not None
        execution_context = worker_execution_context(self._worker)
        result: dict[str, object] = {
            "engine": "capability-graph-gateway",
            "executionProfile": execution_profile,
            "deploymentId": runtime.deployment.deployment_id,
            "releaseSetDigest": runtime.deployment.release_set_digest,
            "activationSetDigest": runtime.deployment.activation_set_digest,
            "controlPlaneRunId": job.run_id,
            "graphRunId": permit.run_id,
            "permitId": permit.permit_id,
            "permitDigest": permit.permit_digest,
            "dispatchId": permit.dispatch_id,
            "dispatched": dispatched,
            "dispatchStatus": terminal.stage.value,
            "gatewayOutcomeDigest": terminal.gateway_outcome_digest,
            "gatewayExecutionId": terminal.gateway_execution_id,
            "executed": terminal.executed,
            "policyAllowed": terminal.policy_allowed,
            "toolSuccess": terminal.tool_success,
            "evidence": list(terminal.evidence),
            "executionContext": execution_context.model_dump(
                mode="json",
                by_alias=True,
            ),
            "outcomeAvailableInProcess": outcome is not None,
        }
        if approval_receipt is not None:
            result.update(
                {
                    "approvalId": approval_receipt.approval.approval_id,
                    "approvalDigest": approval_receipt.approval.approval_digest,
                    "approvalReceiptId": approval_receipt.receipt_id,
                    "approvalReceiptDigest": approval_receipt.receipt_digest,
                }
            )
        return CompletedExecution(result=result)

    @staticmethod
    def _verified_execution_context(
        run_path: Path,
        *,
        run_id: str,
        expected: WorkerExecutionContext,
    ) -> WorkerExecutionContext:
        """Reload the context that the completed sealed Run actually attests."""

        try:
            snapshot = load_verified_run_artifacts(
                run_path,
                requests={
                    "execution-context.json": _MAX_EXECUTION_CONTEXT_BYTES,
                    "run.json": _MAX_TOOL_LOOP_RUN_SUMMARY_BYTES,
                },
                expected_run_id=run_id,
            )
            context = WorkerExecutionContext.model_validate(
                parse_strict_json_bytes(
                    snapshot.artifact_bytes("execution-context.json"),
                    label="sealed campaign execution context",
                    max_bytes=_MAX_EXECUTION_CONTEXT_BYTES,
                )
            )
            summary = _CampaignRunSummary.model_validate(
                parse_strict_json_bytes(
                    snapshot.artifact_bytes("run.json"),
                    label="sealed campaign run summary",
                    max_bytes=_MAX_TOOL_LOOP_RUN_SUMMARY_BYTES,
                )
            )
        except (KeyError, OSError, RunIntegrityError, TypeError, UnicodeError, ValueError) as exc:
            raise PermanentExecutionError(
                "campaign execution context is not bound to an exact sealed Run"
            ) from exc
        if (
            summary.run_id != run_id
            or summary.execution_context != "execution-context.json"
            or summary.worker_backend != context.backend
            or summary.simulated is not context.simulated
            or summary.evidence_scope is not context.evidence_scope
            or context != expected
        ):
            raise PermanentExecutionError(
                "campaign execution context differs from its sealed Run summary"
            )
        return context

    @staticmethod
    def _input(job: JobView) -> dict[str, Any]:
        value = job.payload.get("input")
        if not isinstance(value, dict):
            raise PermanentExecutionError("campaign Job payload.input must be an object")
        return value


class ToolLoopJobExecutor:
    """Bridge durable Control Plane checkpoints to the existing Tool Loop runner."""

    kind = JobKind.TOOL_LOOP

    def __init__(
        self,
        *,
        output_root: Path,
        runner_factory: Callable[[CampaignManifest], PolicyToolLoopRunner] | None = None,
    ) -> None:
        self._output_root = output_root
        self._runner_factory = runner_factory or self._deterministic_runner

    async def execute(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None = None,
    ) -> ExecutionOutcome:
        if "resumeFromCheckpointId" in job.payload:
            return await self._resume(job, cancellation=cancellation)
        value = job.payload.get("input")
        if not isinstance(value, dict):
            raise PermanentExecutionError("tool-loop Job payload.input must be an object")
        job_input = ToolLoopJobInput.model_validate(value)
        runner = self._runner_factory(job_input.manifest)
        try:
            outcome = await runner.run(
                job_input.manifest,
                prompt=job_input.prompt,
                cancellation=cancellation,
            )
        except asyncio.CancelledError:
            if cancellation is not None and cancellation.active:
                seal_executor_quiescence(cancellation)
            raise
        return self._translate_outcome(outcome, job_input=job_input)

    async def _resume(
        self,
        job: JobView,
        *,
        cancellation: ExecutionCancellationContext | None,
    ) -> ExecutionOutcome:
        raw_state = job.payload.get("state")
        raw_approval = job.payload.get("approval")
        approval_id = job.payload.get("approvalId")
        if not isinstance(raw_state, dict) or not isinstance(raw_approval, dict):
            raise PermanentExecutionError("continuation Job lacks signed state or approval")
        if not isinstance(approval_id, str):
            raise PermanentExecutionError("continuation Job lacks approval ID")
        state = ToolLoopResumeState.model_validate(raw_state)
        approval = ConsumedApproval.model_validate(raw_approval)
        pending = state.tool_loop_checkpoint.pending_call
        if pending is None:
            raise PermanentExecutionError("tool-loop checkpoint lacks a pending call")
        tool_approval = ToolLoopApproval(
            approval_id=approval_id,
            call_fingerprint=approval.call_fingerprint,
            tool_id=approval.tool_id,
            target=approval.target,
            approved_by=approval.approved_by,
            approved_at=approval.approved_at,
            expires_at=approval.expires_at,
        )
        resume_dir, resume_dir_fd = self._open_resume_directory(job.job_id)
        checkpoint_name = f"attempt-{job.attempts}.json"
        checkpoint_path = resume_dir / checkpoint_name
        try:
            self._write_resume_checkpoint(
                resume_dir_fd,
                checkpoint_name,
                state.tool_loop_checkpoint.model_dump_json(),
            )
            runner = self._runner_factory(state.job_input.manifest)
            try:
                outcome = await runner.resume(
                    state.job_input.manifest,
                    checkpoint_path=checkpoint_path,
                    approvals=[tool_approval],
                    cancellation=cancellation,
                )
            except asyncio.CancelledError:
                if cancellation is not None and cancellation.active:
                    seal_executor_quiescence(cancellation)
                raise
        finally:
            os.close(resume_dir_fd)
        return self._translate_outcome(outcome, job_input=state.job_input)

    def _safe_resume_directory(self, job_id: str) -> Path:
        if fullmatch(r"job_[0-9a-f]{32}", job_id) is None:
            raise PermanentExecutionError("continuation Job ID escapes the resume output root")
        base = (self._output_root / "_control-plane-resume").absolute()
        return base / job_id

    def _open_resume_directory(self, job_id: str) -> tuple[Path, int]:
        _require_secure_resume_platform()
        resume_dir = self._safe_resume_directory(job_id)
        base = resume_dir.parent
        try:
            base.mkdir(parents=True, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise PermanentExecutionError(
                "continuation resume root could not be created safely"
            ) from exc
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        base_fd = -1
        resume_fd = -1
        try:
            base_fd = os.open(base, directory_flags)
            os.fchmod(base_fd, 0o700)
            try:
                os.mkdir(job_id, mode=0o700, dir_fd=base_fd)
                os.fsync(base_fd)
            except FileExistsError:
                pass
            resume_fd = os.open(job_id, directory_flags, dir_fd=base_fd)
            os.fchmod(resume_fd, 0o700)
            return resume_dir, resume_fd
        except OSError as exc:
            if resume_fd >= 0:
                os.close(resume_fd)
            raise PermanentExecutionError(
                "continuation resume directory could not be opened safely"
            ) from exc
        finally:
            if base_fd >= 0:
                os.close(base_fd)

    @staticmethod
    def _write_resume_checkpoint(directory_fd: int, filename: str, payload: str) -> None:
        _require_secure_resume_platform()
        if fullmatch(r"attempt-[0-9]+\.json", filename) is None:
            raise PermanentExecutionError("continuation checkpoint filename is invalid")
        descriptor = -1
        created = False
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
        )
        try:
            descriptor = os.open(filename, flags, 0o600, dir_fd=directory_fd)
            created = True
            os.fchmod(descriptor, 0o600)
            handle = os.fdopen(descriptor, "w", encoding="utf-8", newline="\n")
            descriptor = -1
            with handle:
                handle.write(payload)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.fsync(directory_fd)
        except FileExistsError as exc:
            raise PermanentExecutionError("continuation checkpoint leaf already exists") from exc
        except OSError as exc:
            if created:
                with suppress(OSError):
                    os.unlink(filename, dir_fd=directory_fd)
                    os.fsync(directory_fd)
            raise PermanentExecutionError(
                "continuation checkpoint could not be written safely"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _translate_outcome(
        self,
        outcome: ToolLoopOutcome,
        *,
        job_input: ToolLoopJobInput,
    ) -> ExecutionOutcome:
        if outcome.status is ToolLoopStatus.AWAITING_APPROVAL:
            if outcome.pending_call is None:
                raise PermanentExecutionError("approval outcome lacks a pending Tool intent")
            checkpoint = self._verified_outcome_checkpoint(outcome)
            return ApprovalCheckpointExecution(
                state=ToolLoopResumeState(
                    job_input=job_input,
                    tool_loop_checkpoint=checkpoint,
                ).model_dump(mode="json"),
                pending_intent=ApprovalIntent(
                    call_fingerprint=outcome.pending_call.fingerprint,
                    tool_id=outcome.pending_call.tool_id,
                    target=outcome.pending_call.target,
                    risk_tier=outcome.pending_call.risk_tier,
                    expires_at=datetime.now(UTC).replace(microsecond=0) + _APPROVAL_WINDOW,
                ),
            )
        if outcome.status is not ToolLoopStatus.COMPLETED:
            raise PermanentExecutionError(
                f"tool-loop engine ended with {outcome.status.value}: {outcome.error}"
            )
        self._verified_outcome_checkpoint(outcome)
        return CompletedExecution(
            result={
                "engine": "policy-tool-loop",
                "executionProfile": job_input.profile,
                "executionContext": outcome.execution_context.model_dump(
                    mode="json", by_alias=True
                ),
                "engineRunId": outcome.run_id,
                "runPath": str(outcome.run_path.resolve()),
                "checkpointPath": str(outcome.checkpoint_path.resolve()),
                "toolCalls": len(outcome.tool_results),
                "finalContent": outcome.final_content,
            }
        )

    @staticmethod
    def _verified_outcome_checkpoint(outcome: ToolLoopOutcome) -> ToolLoopCheckpoint:
        """Bind a returned checkpoint to the exact sealed terminal Run snapshot."""

        try:
            relative = outcome.checkpoint_path.relative_to(outcome.run_path).as_posix()
            snapshot = load_verified_run_artifacts(
                outcome.run_path,
                requests={
                    relative: _MAX_TOOL_LOOP_CHECKPOINT_BYTES,
                    "run.json": _MAX_TOOL_LOOP_RUN_SUMMARY_BYTES,
                    "execution-context.json": _MAX_EXECUTION_CONTEXT_BYTES,
                },
                expected_run_id=outcome.run_id,
            )
            checkpoint = ToolLoopCheckpoint.model_validate(
                parse_strict_json_bytes(
                    snapshot.artifact_bytes(relative),
                    label="sealed Tool Loop approval checkpoint",
                    max_bytes=_MAX_TOOL_LOOP_CHECKPOINT_BYTES,
                )
            )
            summary = _ToolLoopRunSummary.model_validate(
                parse_strict_json_bytes(
                    snapshot.artifact_bytes("run.json"),
                    label="sealed Tool Loop run summary",
                    max_bytes=_MAX_TOOL_LOOP_RUN_SUMMARY_BYTES,
                )
            )
            execution_context = WorkerExecutionContext.model_validate(
                parse_strict_json_bytes(
                    snapshot.artifact_bytes("execution-context.json"),
                    label="sealed Tool Loop execution context",
                    max_bytes=_MAX_EXECUTION_CONTEXT_BYTES,
                )
            )
        except (KeyError, OSError, RunIntegrityError, TypeError, UnicodeError, ValueError) as exc:
            raise PermanentExecutionError(
                "tool-loop approval checkpoint is not an exact sealed Run artifact"
            ) from exc

        if (
            summary.run_id != outcome.run_id
            or summary.loop_id != checkpoint.loop_id
            or summary.status is not outcome.status
            or summary.error != outcome.error
            or summary.checkpoint != relative
            or summary.execution_context != "execution-context.json"
            or summary.worker_backend != execution_context.backend
            or summary.simulated is not execution_context.simulated
            or summary.evidence_scope is not execution_context.evidence_scope
            or execution_context != outcome.execution_context
            or checkpoint.run_id != outcome.run_id
            or checkpoint.status is not outcome.status
            or checkpoint.pending_call != outcome.pending_call
            or checkpoint.tool_results != outcome.tool_results
            or checkpoint.final_content != outcome.final_content
            or checkpoint.error != outcome.error
        ):
            raise PermanentExecutionError(
                "tool-loop approval checkpoint differs from its terminal Run outcome"
            )
        return checkpoint

    def _deterministic_runner(self, campaign: CampaignManifest) -> PolicyToolLoopRunner:
        registration = ProviderRegistration.model_validate(
            {
                "provider_id": "daemon-lab",
                "endpoint": "https://deterministic-provider.invalid/v1/chat/completions",
                "model": "pajin-daemon-deterministic",
                "secret_ref": "provider/daemon-lab/api-key",
                "allowed_function_tools": {"probe_mock_agent"},
            }
        )
        tools = ToolRegistry()
        tools.register(ApprovalCheckTool())
        tools.register(OpenAICompatibleChatTool(registration))
        secrets = SecretBroker()
        secrets.register(registration.secret_ref, "deterministic-provider-lab-fixture")
        target = campaign.spec.targets[0]
        binding = ToolLoopBinding(
            function_name="probe_mock_agent",
            description="Run the approval-gated deterministic mock probe.",
            parameters={
                "type": "object",
                "properties": {
                    "simulation": {
                        "type": "object",
                        "properties": {"unauthorizedToolCall": {"type": "boolean"}},
                        "required": ["unauthorizedToolCall"],
                        "additionalProperties": False,
                    }
                },
                "required": ["simulation"],
                "additionalProperties": False,
            },
            tool_id="mock.approval-probe",
            target=target.endpoint,
            method="POST",
        )
        return PolicyToolLoopRunner(
            registration=registration,
            bindings=[binding],
            tools=tools,
            policy=PolicyEngine(),
            worker=DeterministicToolLoopBackend(),
            secrets=secrets,
            output_root=self._output_root,
        )


class DeterministicToolLoopBackend(SimulatedWorkerBackend):
    """No-network lab backend that still exercises the real Provider and Tool gateways."""

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "pajin.deterministic-tool-loop-worker/v1",
            "providerId": "daemon-lab",
            "providerModel": "pajin-daemon-deterministic",
            "supportedCommands": ["mock-agent-probe", "openai-chat-completion"],
        }

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        now = datetime.now(UTC)
        try:
            payload = json.loads(job.stdin)
            if job.command == ["openai-chat-completion"]:
                if not secrets or {item.binding for item in secrets} != {"provider-api-key"}:
                    raise ValueError("deterministic provider requires one bound credential")
                provider_request = payload["request"]
                messages = provider_request["messages"]
                has_tool_result = any(message.get("role") == "tool" for message in messages)
                output = self._provider_result(payload, has_tool_result=has_tool_result)
            elif job.command == ["mock-agent-probe"]:
                if secrets:
                    raise ValueError("mock probe does not accept secrets")
                output = {
                    "target": payload["target"],
                    "vulnerable": bool(
                        payload.get("simulation", {}).get("unauthorizedToolCall", False)
                    ),
                    "observation": "bounded approval probe completed",
                }
            else:
                raise ValueError("deterministic backend rejects unregistered action")
            return WorkerResult(
                execution_id=job.execution_id,
                backend="deterministic-tool-loop",
                status=WorkerStatus.SUCCEEDED,
                exit_code=0,
                stdout=json.dumps(output, separators=(",", ":")),
                started_at=now,
                finished_at=datetime.now(UTC),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            return WorkerResult(
                execution_id=job.execution_id,
                backend="deterministic-tool-loop",
                status=WorkerStatus.FAILED,
                exit_code=2,
                stderr=(
                    "invalid deterministic worker input: "
                    + audit_safe_exception_diagnostic(
                        exc,
                        stage="deterministic-worker-input",
                    )
                ),
                started_at=now,
                finished_at=datetime.now(UTC),
            )

    @staticmethod
    def _provider_result(payload: dict[str, Any], *, has_tool_result: bool) -> dict[str, Any]:
        target = str(payload["target"])
        result = ProviderChatResult(
            provider_id="daemon-lab",
            response_id=f"chatcmpl-daemon-{int(has_tool_result)}",
            model="pajin-daemon-deterministic",
            content=(
                "Authorized specialist result was received and summarized."
                if has_tool_result
                else None
            ),
            finish_reason="stop" if has_tool_result else "tool_calls",
            tool_calls=(
                []
                if has_tool_result
                else [
                    NormalizedToolCall(
                        call_id="call_daemon_probe",
                        name="probe_mock_agent",
                        arguments_json='{"simulation":{"unauthorizedToolCall":true}}',
                        arguments={"simulation": {"unauthorizedToolCall": True}},
                        arguments_valid=True,
                    )
                ]
            ),
            usage=ProviderUsage(prompt_tokens=3, completion_tokens=2, total_tokens=5),
            streamed=False,
            chunks=1,
            target=target,
        )
        return result.model_dump(mode="json")


_APPROVAL_WINDOW = timedelta(minutes=5)
