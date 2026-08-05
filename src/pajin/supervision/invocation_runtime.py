"""Durable two-seal Shadow Supervisor invocation and SUP-003 admission."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self, cast
from urllib.parse import urlsplit, urlunsplit

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.collaboration.snapshots import CollaborationSnapshot, SharedArtifactSource
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolResult,
)
from pajin.graph.projection import GraphSnapshotStore
from pajin.policy.capability import CapabilityLedger
from pajin.policy.engine import PolicyDecision, PolicyEngine
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderRegistration
from pajin.providers.openai_compatible import OpenAICompatibleChatTool
from pajin.providers.receipts import (
    ProviderBoundChatOutcome,
    ProviderChargedUsage,
    verify_provider_bound_chat_outcome,
)
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.control import BudgetController, DualModelUsageBudget
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import SecretBroker, SecretLease, SecretLeaseStatus
from pajin.runtime.store import (
    RunIntegrityError,
    RunIntegritySeal,
    RunStore,
    SealedArtifact,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)
from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerBackend, WorkerJob, WorkerResult
from pajin.supervision.checkpoint_scheduler import (
    SupervisorCheckpointSchedule,
    SupervisorCheckpointSchedulePublication,
    verify_supervisor_checkpoint_schedule_publication,
)
from pajin.supervision.invocation import (
    SupervisorDedicatedBudgetPolicy,
    SupervisorInvocationPlanError,
    build_supervisor_invocation_request,
)
from pajin.supervision.invocation_journal import (
    SUPERVISOR_CONTEXT_BOUND_INVOCATION_INTENT_API_VERSION,
    SUPERVISOR_INVOCATION_INTENT_API_VERSION,
    SupervisorBenchmarkRequestContext,
    SupervisorInvocationJournal,
    SupervisorInvocationJournalEntry,
    SupervisorInvocationJournalError,
)
from pajin.supervision.model_binding import (
    SupervisorModelBinding,
    SupervisorModelBindingError,
    SupervisorModelConfiguration,
    SupervisorShadowProposalDraft,
    parse_supervisor_shadow_proposal_draft,
)
from pajin.supervision.proposal_compiler import (
    SupervisorProposalCompilerError,
    SupervisorTypedProposal,
    compile_supervisor_shadow_proposal,
    verify_supervisor_typed_proposal,
)
from pajin.supervision.snapshot_input import SupervisorSnapshotInput
from pajin.tools.base import ToolRegistry
from pajin.tools.execution_receipts import safe_job_metadata
from pajin.tools.gateway import GatewayOutcome, RequestRateLimitLedger, ToolGateway

SUPERVISOR_INVOCATION_RECEIPT_API_VERSION: Literal[
    "pajin.dev/supervisor-invocation-receipt/v1alpha1"
] = "pajin.dev/supervisor-invocation-receipt/v1alpha1"
SUPERVISOR_CONTEXT_BOUND_INVOCATION_RECEIPT_API_VERSION: Literal[
    "pajin.dev/supervisor-invocation-receipt/v1alpha2"
] = "pajin.dev/supervisor-invocation-receipt/v1alpha2"

_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_RECEIPT_PATH = "supervision/supervisor-invocation-receipt.json"
_MAX_REQUEST_RESERVATION_BYTES = 16_384
_MAX_GATEWAY_EVIDENCE_BYTES = 32 * 1024 * 1024
_MAX_RECEIPT_BYTES = 8 * 1024 * 1024


class SupervisorInvocationRuntimeError(RuntimeError):
    """Raised when a durable Supervisor invocation cannot be proven safe."""


@dataclass(frozen=True, slots=True)
class SupervisorInvocationAuthorities:
    """Current authorities required to rebuild a SUP-004A checkpoint."""

    snapshot_input: SupervisorSnapshotInput
    binding: SupervisorModelBinding
    campaign: CampaignManifest
    provider_registration: ProviderRegistration
    provider_grant: CapabilityGrant
    model_revision: str
    configuration: SupervisorModelConfiguration
    budget_policy: SupervisorDedicatedBudgetPolicy
    collaboration_snapshot: CollaborationSnapshot
    graph_snapshot_store: GraphSnapshotStore
    shared_artifact_sources: tuple[SharedArtifactSource, ...] = ()


@dataclass(frozen=True, slots=True)
class SupervisorProviderRuntime:
    """Existing execution authorities used to construct one dedicated Provider Run."""

    grant: CapabilityGrant
    ledger: CapabilityLedger
    campaign_budget: BudgetController
    dedicated_budget: BudgetController
    dual_model_usage_budget: DualModelUsageBudget
    policy: PolicyEngine
    tools: ToolRegistry
    worker: WorkerBackend
    secrets: SecretBroker | None = None
    rate_limits: RequestRateLimitLedger | None = None


class SupervisorInvocationReceipt(StrictModel):
    """Content-addressed receipt anchored to one first-seal Provider execution."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/supervisor-invocation-receipt/v1alpha1",
        "pajin.dev/supervisor-invocation-receipt/v1alpha2",
    ] = Field(
        default=SUPERVISOR_INVOCATION_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["SupervisorInvocationReceipt"] = "SupervisorInvocationReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    invocation_intent_id: str = Field(alias="invocationIntentId", min_length=1, max_length=110)
    invocation_intent_digest: _Sha256 = Field(alias="invocationIntentDigest")
    request_context: SupervisorBenchmarkRequestContext | None = Field(
        default=None,
        alias="requestContext",
        exclude_if=lambda value: value is None,
    )
    dispatch_event_digest: _Sha256 = Field(alias="dispatchEventDigest")
    schedule_id: str = Field(alias="scheduleId", min_length=1, max_length=110)
    schedule_digest: _Sha256 = Field(alias="scheduleDigest")
    checkpoint_key: _Sha256 = Field(alias="checkpointKey")
    planned_call_index: int = Field(alias="plannedCallIndex", ge=1, le=32)
    schedule_run_id: str = Field(alias="scheduleRunId", min_length=1, max_length=100)
    schedule_root_digest: _Sha256 = Field(alias="scheduleRootDigest")
    schedule_artifact_path: str = Field(
        alias="scheduleArtifactPath",
        min_length=1,
        max_length=1_000,
    )
    schedule_artifact_sha256: _Sha256 = Field(alias="scheduleArtifactSha256")
    request_binding_id: str = Field(
        alias="requestBindingId",
        min_length=1,
        max_length=110,
    )
    request_binding_digest: _Sha256 = Field(alias="requestBindingDigest")
    provider_chat_request_digest: _Sha256 = Field(alias="providerChatRequestDigest")
    source_snapshot_id: str = Field(alias="sourceSnapshotId", min_length=1, max_length=110)
    source_snapshot_digest: _Sha256 = Field(alias="sourceSnapshotDigest")
    response_schema_id: str = Field(alias="responseSchemaId", min_length=1, max_length=110)
    response_schema_digest: _Sha256 = Field(alias="responseSchemaDigest")
    stable_request_id: str = Field(
        alias="stableRequestId",
        pattern=r"^supervisor_[a-f0-9]{64}$",
    )
    provider_run_id: str = Field(alias="providerRunId", min_length=1, max_length=100)
    evidence_seal_root_digest: _Sha256 = Field(alias="evidenceSealRootDigest")
    evidence_artifact_root_digest: _Sha256 = Field(alias="evidenceArtifactRootDigest")
    evidence_event_head_hash: _Sha256 = Field(alias="evidenceEventHeadHash")
    evidence_event_count: int = Field(alias="evidenceEventCount", ge=1)
    request_reservation_path: str = Field(
        alias="requestReservationPath",
        min_length=1,
        max_length=1_000,
    )
    request_reservation_sha256: _Sha256 = Field(alias="requestReservationSha256")
    gateway_evidence_path: str = Field(
        alias="gatewayEvidencePath",
        min_length=1,
        max_length=1_000,
    )
    gateway_evidence_sha256: _Sha256 = Field(alias="gatewayEvidenceSha256")
    provider_outcome: ProviderBoundChatOutcome = Field(alias="providerOutcome")
    provider_outcome_digest: _Sha256 = Field(alias="providerOutcomeDigest")
    draft: SupervisorShadowProposalDraft
    response_state: Literal["untrusted-draft-sealed-not-admitted"] = Field(
        default="untrusted-draft-sealed-not-admitted",
        alias="responseState",
    )
    budget_scope: Literal["campaign-and-dedicated"] = Field(
        default="campaign-and-dedicated",
        alias="budgetScope",
    )
    model_invocation_observed: Literal[True] = Field(
        default=True,
        alias="modelInvocationObserved",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    task_created: Literal[False] = Field(default=False, alias="taskCreated")
    plan_mutated: Literal[False] = Field(default=False, alias="planMutated")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    activation_eligible: Literal[False] = Field(default=False, alias="activationEligible")

    @field_validator("planned_call_index", "evidence_event_count", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Supervisor invocation receipt counts must use JSON integers")
        return value

    @field_validator("model_invocation_observed", mode="before")
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Supervisor invocation observation marker must be true")
        return value

    @field_validator(
        "automatic_redispatch_authorized",
        "task_created",
        "plan_mutated",
        "scope_expansion_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        "activation_eligible",
        mode="before",
    )
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Supervisor invocation authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        expected_api_version = (
            SUPERVISOR_CONTEXT_BOUND_INVOCATION_RECEIPT_API_VERSION
            if self.request_context is not None
            else SUPERVISOR_INVOCATION_RECEIPT_API_VERSION
        )
        if (
            self.api_version != expected_api_version
            or self.provider_outcome_digest != self.provider_outcome.outcome_digest
            or self.provider_outcome.request_id != self.stable_request_id
            or self.provider_outcome.charged_usage.budget_scope != "campaign-and-dedicated"
            or self.draft.snapshot_id != self.source_snapshot_id
            or self.draft.snapshot_digest != self.source_snapshot_digest
        ):
            raise ValueError("Supervisor invocation receipt differs from its bound outcome")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = _invocation_receipt_digest(
            "pajin.supervision.invocation-receipt/v1",
            material,
        )
        receipt_id = f"supervisor-invocation-receipt:{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Supervisor Invocation Receipt Digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Supervisor Invocation Receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Supervisor invocation receipt",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class SupervisorInvocationPublication:
    """Final two-seal Provider Run plus its terminal durable journal anchor."""

    receipt: SupervisorInvocationReceipt
    journal_entry: SupervisorInvocationJournalEntry
    run_path: Path
    final_root_digest: str
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class SupervisorInvocationCompletion:
    """Verified receipt consumed directly into one non-executable SUP-003 proposal."""

    publication: SupervisorInvocationPublication
    proposal: SupervisorTypedProposal


class SupervisorCheckpointInvoker:
    """Own one intent-before-dispatch Provider Run and its terminal receipt."""

    def __init__(
        self,
        *,
        output_root: Path,
        journal: SupervisorInvocationJournal,
        provider_runtime: SupervisorProviderRuntime,
    ) -> None:
        self._output_root = Path(output_root).resolve()
        self._journal = journal
        self._provider_runtime = provider_runtime

    @property
    def journal(self) -> SupervisorInvocationJournal:
        """Return the exact durable journal consumed by this invoker."""

        return self._journal

    async def invoke(
        self,
        schedule_publication: SupervisorCheckpointSchedulePublication,
        authorities: SupervisorInvocationAuthorities,
        *,
        request_context: SupervisorBenchmarkRequestContext | None = None,
    ) -> SupervisorInvocationCompletion:
        """Dispatch at most once per journal and return only a verified SUP-003 proposal."""

        try:
            schedule, chat = _verify_and_rebuild_schedule(
                schedule_publication,
                authorities,
            )
            entry = self._journal.claim(
                schedule_publication,
                request_context=request_context,
            )
            if entry.state == "terminal-success":
                publication = self._terminal_publication(entry, authorities.campaign)
            elif entry.state == "dispatch-started-outcome-unknown":
                publication = self._recover_terminal_publication(
                    entry,
                    schedule_publication,
                    authorities,
                    chat,
                )
            elif entry.state == "intent-recorded":
                self._verify_provider_runtime(authorities, schedule)
                publication = await self._dispatch_once(
                    entry,
                    schedule_publication,
                    schedule,
                    authorities,
                    chat,
                )
            else:  # pragma: no cover - journal model closes the state set
                raise SupervisorInvocationRuntimeError(
                    "Supervisor invocation journal state is unsupported"
                )
            proposal = consume_supervisor_invocation(
                publication,
                journal=self._journal,
                schedule_publication=schedule_publication,
                authorities=authorities,
            )
            return SupervisorInvocationCompletion(
                publication=publication,
                proposal=proposal,
            )
        except SupervisorInvocationRuntimeError:
            raise
        except (
            AttributeError,
            RunIntegrityError,
            OSError,
            SupervisorInvocationJournalError,
            SupervisorInvocationPlanError,
            SupervisorProposalCompilerError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise SupervisorInvocationRuntimeError("Supervisor invocation failed closed") from exc

    def _verify_provider_runtime(
        self,
        authorities: SupervisorInvocationAuthorities,
        schedule: SupervisorCheckpointSchedule,
    ) -> None:
        runtime = self._provider_runtime
        if (
            type(runtime.ledger) is not CapabilityLedger
            or type(runtime.campaign_budget) is not BudgetController
            or type(runtime.dedicated_budget) is not BudgetController
            or type(runtime.dual_model_usage_budget) is not DualModelUsageBudget
            or type(runtime.policy) is not PolicyEngine
            or type(runtime.tools) is not ToolRegistry
            or (runtime.secrets is not None and type(runtime.secrets) is not SecretBroker)
            or (
                runtime.rate_limits is not None
                and type(runtime.rate_limits) is not RequestRateLimitLedger
            )
        ):
            raise SupervisorInvocationRuntimeError(
                "Supervisor Provider runtime uses a foreign authority implementation"
            )
        campaign = CampaignManifest.model_validate(
            authorities.campaign.model_dump(mode="json", by_alias=True)
        )
        registration = ProviderRegistration.model_validate(
            authorities.provider_registration.model_dump(mode="python")
        )
        grant = CapabilityGrant.model_validate(runtime.grant.model_dump(mode="python"))
        expected_grant = CapabilityGrant.model_validate(
            authorities.provider_grant.model_dump(mode="python")
        )
        authoritative_grant = runtime.ledger.record(grant.grant_id).grant
        tool_id = f"provider.{registration.provider_id}.chat"
        tool = runtime.tools.tool(tool_id)
        if (
            runtime.campaign_budget.budgets != campaign.spec.budgets
            or not runtime.dual_model_usage_budget.binds_campaign_budget(runtime.campaign_budget)
            or not runtime.dual_model_usage_budget.binds_dedicated_budget(runtime.dedicated_budget)
            or authoritative_grant != grant
            or grant != expected_grant
            or grant.campaign != campaign.metadata.name
            or grant.subject == ""
            or tool_id not in grant.tools
            or str(registration.endpoint) not in grant.targets
            or type(tool) is not OpenAICompatibleChatTool
            or tool.registration != registration
        ):
            raise SupervisorInvocationRuntimeError(
                "Supervisor Provider runtime differs from the expected authorities"
            )
        dedicated = runtime.dedicated_budget.budgets
        policy = schedule.dedicated_budget_policy
        if (
            dedicated.max_tool_calls != policy.max_model_calls
            or dedicated.max_model_calls != policy.max_model_calls
            or dedicated.max_model_tokens != policy.max_model_tokens
            or dedicated.duration_seconds != policy.max_duration_seconds
            or dedicated.max_cost_usd != policy.max_cost_usd
        ):
            raise SupervisorInvocationRuntimeError(
                "Supervisor dedicated runtime budget differs from its schedule"
            )

    async def _dispatch_once(
        self,
        entry: SupervisorInvocationJournalEntry,
        schedule_publication: SupervisorCheckpointSchedulePublication,
        schedule: SupervisorCheckpointSchedule,
        authorities: SupervisorInvocationAuthorities,
        chat: ProviderChatRequest,
    ) -> SupervisorInvocationPublication:
        runtime = self._provider_runtime
        entry = self._journal.begin_dispatch(entry)
        try:
            store = RunStore.create(
                self._output_root,
                authorities.campaign.metadata.name,
                run_id=entry.intent.provider_run_id,
            )
            gateway = ToolGateway(
                policy=runtime.policy,
                tools=runtime.tools,
                worker=runtime.worker,
                store=store,
                secrets=runtime.secrets,
                rate_limits=runtime.rate_limits,
            )
            port = PolicyBoundProviderPort(
                registration=authorities.provider_registration,
                campaign=authorities.campaign,
                grant=runtime.grant,
                ledger=runtime.ledger,
                budget=runtime.campaign_budget,
                gateway=gateway,
                store=store,
                dual_model_usage_budget=runtime.dual_model_usage_budget,
            )
            bound_call = await port.chat_bound(
                role="supervisor",
                attempt=schedule.planned_call_index,
                chat=chat,
                request_id=entry.intent.stable_request_id,
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise SupervisorInvocationRuntimeError(
                "Supervisor dispatch started but its outcome is unknown"
            ) from exc

        evidence_seal = store.seal()
        draft = _parse_supervisor_draft(bound_call.result, schedule)
        receipt = _build_receipt(
            entry=entry,
            schedule_publication=schedule_publication,
            schedule=schedule,
            evidence_seal=evidence_seal,
            provider_outcome=bound_call.outcome,
            draft=draft,
        )
        receipt_path = store.write_json_create_only(
            entry.intent.receipt_path,
            receipt.model_dump(mode="json", by_alias=True),
        )
        store.append_event(
            "supervisor.invocation.receipt.created",
            {
                "receiptId": receipt.receipt_id,
                "receiptDigest": receipt.receipt_digest,
                "invocationIntentId": entry.intent.intent_id,
                "requestId": entry.intent.stable_request_id,
                "state": receipt.response_state,
                "artifact": receipt_path,
            },
        )
        final_seal = store.seal()
        receipt_artifact = _only_artifact(final_seal, receipt_path)
        provisional = SupervisorInvocationPublication(
            receipt=receipt,
            journal_entry=entry,
            run_path=store.path.resolve(),
            final_root_digest=final_seal.root_digest,
            receipt_sha256=receipt_artifact.sha256,
        )
        _verify_invocation_run(
            provisional,
            schedule_publication=schedule_publication,
            authorities=authorities,
            chat=chat,
            expected_journal_state="dispatch-started-outcome-unknown",
        )
        terminal = self._journal.finalize_success(
            entry,
            final_root_digest=final_seal.root_digest,
            receipt_path=receipt_path,
            receipt_sha256=receipt_artifact.sha256,
        )
        return SupervisorInvocationPublication(
            receipt=receipt,
            journal_entry=terminal,
            run_path=store.path.resolve(),
            final_root_digest=final_seal.root_digest,
            receipt_sha256=receipt_artifact.sha256,
        )

    def _recover_terminal_publication(
        self,
        entry: SupervisorInvocationJournalEntry,
        schedule_publication: SupervisorCheckpointSchedulePublication,
        authorities: SupervisorInvocationAuthorities,
        chat: ProviderChatRequest,
    ) -> SupervisorInvocationPublication:
        """Recover only a fully sealed receipt; never redispatch an uncertain call."""

        provisional = _load_publication_from_run(
            entry,
            output_root=self._output_root,
            campaign=authorities.campaign,
        )
        _verify_invocation_run(
            provisional,
            schedule_publication=schedule_publication,
            authorities=authorities,
            chat=chat,
            expected_journal_state="dispatch-started-outcome-unknown",
        )
        terminal = self._journal.finalize_success(
            entry,
            final_root_digest=provisional.final_root_digest,
            receipt_path=entry.intent.receipt_path,
            receipt_sha256=provisional.receipt_sha256,
        )
        return SupervisorInvocationPublication(
            receipt=provisional.receipt,
            journal_entry=terminal,
            run_path=provisional.run_path,
            final_root_digest=provisional.final_root_digest,
            receipt_sha256=provisional.receipt_sha256,
        )

    def _terminal_publication(
        self,
        entry: SupervisorInvocationJournalEntry,
        campaign: CampaignManifest,
    ) -> SupervisorInvocationPublication:
        publication = _load_publication_from_run(
            entry,
            output_root=self._output_root,
            campaign=campaign,
        )
        if (
            entry.final_root_digest != publication.final_root_digest
            or entry.receipt_path != entry.intent.receipt_path
            or entry.receipt_sha256 != publication.receipt_sha256
        ):
            raise SupervisorInvocationRuntimeError(
                "terminal Supervisor journal differs from its sealed receipt"
            )
        return publication


def consume_supervisor_invocation(
    publication: SupervisorInvocationPublication,
    *,
    journal: SupervisorInvocationJournal,
    schedule_publication: SupervisorCheckpointSchedulePublication,
    authorities: SupervisorInvocationAuthorities,
) -> SupervisorTypedProposal:
    """Verify journal and both seals, then pass the draft directly to SUP-003."""

    try:
        current = journal.inspect(publication.journal_entry.intent.intent_id)
        if current != publication.journal_entry or current.state != "terminal-success":
            raise ValueError("Supervisor invocation journal is not exact terminal authority")
        _schedule, chat = _verify_and_rebuild_schedule(
            schedule_publication,
            authorities,
        )
        draft = _verify_invocation_run(
            publication,
            schedule_publication=schedule_publication,
            authorities=authorities,
            chat=chat,
            expected_journal_state="terminal-success",
        )
        proposal = compile_supervisor_shadow_proposal(
            authorities.snapshot_input,
            draft,
            authorities.binding,
            authorities.campaign,
            authorities.provider_registration,
            model_revision=authorities.model_revision,
            configuration=authorities.configuration,
            collaboration_snapshot=authorities.collaboration_snapshot,
            graph_snapshot_store=authorities.graph_snapshot_store,
            shared_artifact_sources=authorities.shared_artifact_sources,
        )
        return verify_supervisor_typed_proposal(
            proposal,
            authorities.snapshot_input,
            draft,
            authorities.binding,
            authorities.campaign,
            authorities.provider_registration,
            model_revision=authorities.model_revision,
            configuration=authorities.configuration,
            collaboration_snapshot=authorities.collaboration_snapshot,
            graph_snapshot_store=authorities.graph_snapshot_store,
            shared_artifact_sources=authorities.shared_artifact_sources,
        )
    except SupervisorInvocationRuntimeError:
        raise
    except (
        AttributeError,
        RunIntegrityError,
        OSError,
        SupervisorInvocationJournalError,
        SupervisorInvocationPlanError,
        SupervisorProposalCompilerError,
        TypeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorInvocationRuntimeError(
            "sealed Supervisor invocation could not be admitted"
        ) from exc


def _verify_and_rebuild_schedule(
    publication: SupervisorCheckpointSchedulePublication,
    authorities: SupervisorInvocationAuthorities,
) -> tuple[SupervisorCheckpointSchedule, ProviderChatRequest]:
    schedule = verify_supervisor_checkpoint_schedule_publication(
        publication,
        authorities.snapshot_input,
        authorities.binding,
        authorities.campaign,
        authorities.provider_registration,
        model_revision=authorities.model_revision,
        configuration=authorities.configuration,
        budget_policy=authorities.budget_policy,
        collaboration_snapshot=authorities.collaboration_snapshot,
        graph_snapshot_store=authorities.graph_snapshot_store,
        shared_artifact_sources=authorities.shared_artifact_sources,
    )
    chat, request_binding = build_supervisor_invocation_request(
        authorities.snapshot_input,
        authorities.binding,
        authorities.campaign,
        authorities.provider_registration,
        authorities.configuration,
        authorities.budget_policy,
        model_revision=authorities.model_revision,
    )
    if request_binding != schedule.request_binding:
        raise SupervisorInvocationRuntimeError(
            "Supervisor schedule request differs from the rebuilt Provider chat"
        )
    return schedule, chat


def _build_receipt(
    *,
    entry: SupervisorInvocationJournalEntry,
    schedule_publication: SupervisorCheckpointSchedulePublication,
    schedule: SupervisorCheckpointSchedule,
    evidence_seal: RunIntegritySeal,
    provider_outcome: ProviderBoundChatOutcome,
    draft: SupervisorShadowProposalDraft,
) -> SupervisorInvocationReceipt:
    request_path = f"requests/{entry.intent.stable_request_id}.json"
    evidence_path = f"evidence/{entry.intent.stable_request_id}.json"
    if evidence_seal.sequence != 1 or {artifact.path for artifact in evidence_seal.artifacts} != {
        request_path,
        evidence_path,
    }:
        raise SupervisorInvocationRuntimeError("Supervisor Provider evidence seal shape differs")
    request_artifact = _only_artifact(evidence_seal, request_path)
    evidence_artifact = _only_artifact(evidence_seal, evidence_path)
    return SupervisorInvocationReceipt(
        apiVersion=(
            SUPERVISOR_CONTEXT_BOUND_INVOCATION_RECEIPT_API_VERSION
            if entry.intent.request_context is not None
            else SUPERVISOR_INVOCATION_RECEIPT_API_VERSION
        ),
        invocationIntentId=entry.intent.intent_id,
        invocationIntentDigest=entry.intent.intent_digest,
        requestContext=entry.intent.request_context,
        dispatchEventDigest=entry.last_event_digest,
        scheduleId=schedule.schedule_id,
        scheduleDigest=schedule.schedule_digest,
        checkpointKey=schedule.checkpoint_key,
        plannedCallIndex=schedule.planned_call_index,
        scheduleRunId=schedule_publication.run_id,
        scheduleRootDigest=schedule_publication.root_digest,
        scheduleArtifactPath=schedule_publication.artifact_path,
        scheduleArtifactSha256=schedule_publication.artifact_sha256,
        requestBindingId=schedule.request_binding.request_binding_id,
        requestBindingDigest=schedule.request_binding_digest,
        providerChatRequestDigest=schedule.request_binding.request_digest,
        sourceSnapshotId=schedule.source_snapshot_id,
        sourceSnapshotDigest=schedule.source_snapshot_digest,
        responseSchemaId=schedule.request_binding.response_schema_id,
        responseSchemaDigest=schedule.request_binding.response_schema_digest,
        stableRequestId=entry.intent.stable_request_id,
        providerRunId=entry.intent.provider_run_id,
        evidenceSealRootDigest=evidence_seal.root_digest,
        evidenceArtifactRootDigest=evidence_seal.artifact_root_digest,
        evidenceEventHeadHash=evidence_seal.event_head_hash,
        evidenceEventCount=evidence_seal.event_count,
        requestReservationPath=request_path,
        requestReservationSha256=request_artifact.sha256,
        gatewayEvidencePath=evidence_path,
        gatewayEvidenceSha256=evidence_artifact.sha256,
        providerOutcome=provider_outcome,
        providerOutcomeDigest=provider_outcome.outcome_digest,
        draft=draft,
    )


def _parse_supervisor_draft(
    result: ProviderChatResult,
    schedule: SupervisorCheckpointSchedule,
) -> SupervisorShadowProposalDraft:
    try:
        canonical = ProviderChatResult.model_validate(result.model_dump(mode="python"))
        if (
            canonical.content is None
            or canonical.refusal is not None
            or canonical.tool_calls
            or canonical.streamed
            or canonical.chunks != 1
        ):
            raise ValueError("Supervisor Provider result is not one strict draft")
        content = canonical.content.encode("utf-8", errors="strict")
        draft = parse_supervisor_shadow_proposal_draft(content)
        if (
            draft.snapshot_id != schedule.source_snapshot_id
            or draft.snapshot_digest != schedule.source_snapshot_digest
        ):
            raise ValueError("Supervisor draft refers to another source Snapshot")
        return draft
    except (
        AttributeError,
        SupervisorModelBindingError,
        TypeError,
        UnicodeError,
        ValidationError,
        ValueError,
    ) as exc:
        raise SupervisorInvocationRuntimeError(
            "Supervisor Provider response is not an admissible draft"
        ) from exc


def _load_publication_from_run(
    entry: SupervisorInvocationJournalEntry,
    *,
    output_root: Path,
    campaign: CampaignManifest,
) -> SupervisorInvocationPublication:
    run_path = Path(output_root).resolve() / campaign.metadata.name / entry.intent.provider_run_id
    request_path = f"requests/{entry.intent.stable_request_id}.json"
    evidence_path = f"evidence/{entry.intent.stable_request_id}.json"
    snapshot = load_verified_run_artifacts(
        run_path,
        requests={
            request_path: _MAX_REQUEST_RESERVATION_BYTES,
            evidence_path: _MAX_GATEWAY_EVIDENCE_BYTES,
            entry.intent.receipt_path: _MAX_RECEIPT_BYTES,
        },
        expected_run_id=entry.intent.provider_run_id,
    )
    receipt_bytes = snapshot.artifact_bytes(entry.intent.receipt_path)
    receipt = SupervisorInvocationReceipt.model_validate(
        parse_strict_json_bytes(
            receipt_bytes,
            label="sealed Supervisor invocation receipt",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
    )
    receipt_artifact = _snapshot_artifact(snapshot, entry.intent.receipt_path)
    return SupervisorInvocationPublication(
        receipt=receipt,
        journal_entry=entry,
        run_path=snapshot.run_path,
        final_root_digest=snapshot.verification.root_digest,
        receipt_sha256=receipt_artifact.sha256,
    )


def _verify_invocation_run(
    publication: SupervisorInvocationPublication,
    *,
    schedule_publication: SupervisorCheckpointSchedulePublication,
    authorities: SupervisorInvocationAuthorities,
    chat: ProviderChatRequest,
    expected_journal_state: Literal[
        "dispatch-started-outcome-unknown",
        "terminal-success",
    ],
) -> SupervisorShadowProposalDraft:
    entry = publication.journal_entry
    receipt = SupervisorInvocationReceipt.model_validate(
        publication.receipt.model_dump(mode="json", by_alias=True)
    )
    schedule = SupervisorCheckpointSchedule.model_validate(
        schedule_publication.schedule.model_dump(mode="json", by_alias=True)
    )
    request_path = f"requests/{entry.intent.stable_request_id}.json"
    evidence_path = f"evidence/{entry.intent.stable_request_id}.json"
    if (
        entry.state != expected_journal_state
        or receipt.invocation_intent_id != entry.intent.intent_id
        or receipt.invocation_intent_digest != entry.intent.intent_digest
        or receipt.request_context != entry.intent.request_context
        or (entry.intent.api_version == SUPERVISOR_CONTEXT_BOUND_INVOCATION_INTENT_API_VERSION)
        != (receipt.request_context is not None)
        or (entry.intent.api_version == SUPERVISOR_INVOCATION_INTENT_API_VERSION)
        != (receipt.request_context is None)
        or receipt.dispatch_event_digest != entry.dispatch_event_digest
        or receipt.stable_request_id != entry.intent.stable_request_id
        or receipt.provider_run_id != entry.intent.provider_run_id
        or receipt.schedule_id != schedule.schedule_id
        or receipt.schedule_digest != schedule.schedule_digest
        or receipt.checkpoint_key != schedule.checkpoint_key
        or receipt.planned_call_index != schedule.planned_call_index
        or receipt.schedule_run_id != schedule_publication.run_id
        or receipt.schedule_root_digest != schedule_publication.root_digest
        or receipt.schedule_artifact_path != schedule_publication.artifact_path
        or receipt.schedule_artifact_sha256 != schedule_publication.artifact_sha256
        or receipt.request_binding_id != schedule.request_binding.request_binding_id
        or receipt.request_binding_digest != schedule.request_binding_digest
        or receipt.provider_chat_request_digest != schedule.request_binding.request_digest
        or receipt.source_snapshot_id != schedule.source_snapshot_id
        or receipt.source_snapshot_digest != schedule.source_snapshot_digest
        or receipt.response_schema_id != schedule.request_binding.response_schema_id
        or receipt.response_schema_digest != schedule.request_binding.response_schema_digest
        or receipt.request_reservation_path != request_path
        or receipt.gateway_evidence_path != evidence_path
    ):
        raise SupervisorInvocationRuntimeError(
            "Supervisor receipt differs from schedule or journal authority"
        )
    if expected_journal_state == "terminal-success" and (
        entry.final_root_digest != publication.final_root_digest
        or entry.receipt_path != entry.intent.receipt_path
        or entry.receipt_sha256 != publication.receipt_sha256
    ):
        raise SupervisorInvocationRuntimeError(
            "terminal journal does not bind the exact Supervisor receipt"
        )
    snapshot = load_verified_run_artifacts(
        publication.run_path,
        requests={
            request_path: _MAX_REQUEST_RESERVATION_BYTES,
            evidence_path: _MAX_GATEWAY_EVIDENCE_BYTES,
            entry.intent.receipt_path: _MAX_RECEIPT_BYTES,
        },
        expected_run_id=entry.intent.provider_run_id,
    )
    if (
        snapshot.verification.root_digest != publication.final_root_digest
        or snapshot.verification.seal_count != 2
        or snapshot.verification.artifact_count != 3
        or len(snapshot.seals) != 2
        or publication.receipt_sha256
        != _snapshot_artifact(snapshot, entry.intent.receipt_path).sha256
    ):
        raise SupervisorInvocationRuntimeError(
            "Supervisor invocation Run shape or terminal root differs"
        )
    first, second = snapshot.seals
    if (
        first.sequence != 1
        or first.previous_root_digest is not None
        or {artifact.path for artifact in first.artifacts} != {request_path, evidence_path}
        or second.sequence != 2
        or second.previous_root_digest != first.root_digest
        or {artifact.path for artifact in second.artifacts} != {entry.intent.receipt_path}
        or receipt.evidence_seal_root_digest != first.root_digest
        or receipt.evidence_artifact_root_digest != first.artifact_root_digest
        or receipt.evidence_event_head_hash != first.event_head_hash
        or receipt.evidence_event_count != first.event_count
        or receipt.request_reservation_sha256 != _only_artifact(first, request_path).sha256
        or receipt.gateway_evidence_sha256 != _only_artifact(first, evidence_path).sha256
        or publication.receipt_sha256 != _only_artifact(second, entry.intent.receipt_path).sha256
    ):
        raise SupervisorInvocationRuntimeError(
            "Supervisor invocation seals differ from the receipt"
        )
    sealed_receipt = SupervisorInvocationReceipt.model_validate(
        parse_strict_json_bytes(
            snapshot.artifact_bytes(entry.intent.receipt_path),
            label="sealed Supervisor invocation receipt",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
    )
    if sealed_receipt != receipt:
        raise SupervisorInvocationRuntimeError(
            "Supervisor receipt differs from its sealed artifact"
        )
    request, gateway, result, dispatched_metadata, leases = _rebuild_gateway_sources(
        snapshot,
        receipt,
        chat,
        authorities,
    )
    _verify_invocation_events(
        snapshot,
        receipt,
        second,
        chat=chat,
        request=request,
        gateway=gateway,
        result=result,
        dispatched_metadata=dispatched_metadata,
        leases=leases,
    )
    charged = ProviderChargedUsage.model_validate(
        receipt.provider_outcome.charged_usage.model_dump(mode="json", by_alias=True)
    )
    verified_outcome = verify_provider_bound_chat_outcome(
        receipt.provider_outcome,
        registration=authorities.provider_registration,
        grant=authorities.provider_grant,
        chat=chat,
        request=request,
        result=result,
        gateway_outcome=gateway,
        charged_usage=charged,
        expected_budget_scope="campaign-and-dedicated",
    )
    if verified_outcome != receipt.provider_outcome:
        raise SupervisorInvocationRuntimeError(
            "Supervisor Provider outcome differs after full reconstruction"
        )
    draft = _parse_supervisor_draft(result, schedule)
    if draft != receipt.draft:
        raise SupervisorInvocationRuntimeError(
            "Supervisor draft differs from the sealed Provider response"
        )
    return draft


def _verify_invocation_events(
    snapshot: VerifiedRunSnapshot,
    receipt: SupervisorInvocationReceipt,
    final_seal: RunIntegritySeal,
    *,
    chat: ProviderChatRequest,
    request: ToolRequest,
    gateway: GatewayOutcome,
    result: ProviderChatResult,
    dispatched_metadata: dict[str, object],
    leases: tuple[SecretLease, ...],
) -> None:
    critical_types = (
        "model.call.started",
        "tool.request_reserved",
        "tool.policy_evaluated",
        "secret.lease.issued",
        "worker.dispatched",
        "secret.lease.revoked",
        "worker.completed",
        "tool.completed",
        "model.call.completed",
        "supervisor.invocation.receipt.created",
    )
    if tuple(event.event_type for event in snapshot.events) != critical_types:
        raise SupervisorInvocationRuntimeError(
            "Supervisor invocation contains an unexpected lifecycle event"
        )
    critical = []
    for event_type in critical_types:
        matches = [event for event in snapshot.events if event.event_type == event_type]
        if len(matches) != 1:
            raise SupervisorInvocationRuntimeError(
                "Supervisor invocation lifecycle is missing or duplicated"
            )
        critical.append(matches[0])
    if tuple(event.sequence for event in critical) != tuple(
        sorted(event.sequence for event in critical)
    ):
        raise SupervisorInvocationRuntimeError(
            "Supervisor invocation lifecycle event order differs"
        )
    model_completed = critical[-2]
    receipt_created = critical[-1]
    request_id = receipt.stable_request_id
    charged = receipt.provider_outcome.charged_usage
    worker_result = gateway.worker_result
    if worker_result is None or len(leases) != 1:
        raise SupervisorInvocationRuntimeError("Supervisor Worker result is missing")
    lease = leases[0]
    lease_json = lease.model_dump(mode="json")
    schema_name = (
        chat.response_format.json_schema.name if chat.response_format is not None else None
    )
    reported = receipt.provider_outcome.reported_usage
    expected_payloads = (
        {
            "role": "supervisor",
            "attempt": receipt.planned_call_index,
            "agentId": receipt.provider_outcome.agent_id,
            "providerId": receipt.provider_outcome.provider_id,
            "model": receipt.provider_outcome.model,
            "schema": schema_name,
            "functionTools": [tool.function.name for tool in chat.tools],
            "reservedPromptTokens": charged.prompt_tokens,
            "reservedCompletionTokens": charged.completion_tokens,
            "reservedCostUsd": charged.cost_usd,
        },
        {
            "requestId": request_id,
            "requestSha256": receipt.provider_outcome.tool_request_digest,
            "reservation": receipt.request_reservation_path,
        },
        {
            "requestId": request_id,
            "toolId": request.tool_id,
            "allowed": gateway.decision.allowed,
            "policy": gateway.decision.policy,
            "reason": gateway.decision.reason,
        },
        {
            "leaseId": lease.lease_id,
            "scope": lease.scope,
            "binding": lease.binding,
            "secretRefFingerprint": lease.secret_ref_fingerprint,
            "expiresAt": lease_json["expires_at"],
        },
        dispatched_metadata,
        {
            "leaseId": lease.lease_id,
            "scope": lease.scope,
            "binding": lease.binding,
            "reason": lease.revoked_reason,
        },
        {
            "requestId": request_id,
            "executionId": worker_result.execution_id,
            "backend": worker_result.backend,
            "status": worker_result.status.value,
            "exitCode": worker_result.exit_code,
            "stdoutTruncated": worker_result.stdout_truncated,
            "stderrTruncated": worker_result.stderr_truncated,
        },
        {
            "requestId": request_id,
            "toolId": request.tool_id,
            "success": True,
            "evidence": receipt.gateway_evidence_path,
        },
        {
            "role": "supervisor",
            "attempt": receipt.planned_call_index,
            "agentId": receipt.provider_outcome.agent_id,
            "providerId": receipt.provider_outcome.provider_id,
            "model": receipt.provider_outcome.model,
            "reportedModel": result.model,
            "responseId": result.response_id,
            "promptTokens": reported.prompt_tokens,
            "completionTokens": reported.completion_tokens,
            "totalTokens": reported.total_tokens,
            "costUsd": reported.cost_usd,
            "usageTrust": reported.trust,
            "chargedPromptTokens": charged.prompt_tokens,
            "chargedCompletionTokens": charged.completion_tokens,
            "chargedCostUsd": charged.cost_usd,
            "evidence": [receipt.gateway_evidence_path],
            "boundOutcomeId": receipt.provider_outcome.outcome_id,
            "boundOutcomeDigest": receipt.provider_outcome.outcome_digest,
        },
        {
            "receiptId": receipt.receipt_id,
            "receiptDigest": receipt.receipt_digest,
            "invocationIntentId": receipt.invocation_intent_id,
            "requestId": request_id,
            "state": receipt.response_state,
            "artifact": _RECEIPT_PATH,
        },
    )
    if (
        any(
            canonical_json_bytes(
                event.payload,
                label=f"Supervisor {event.event_type} event",
                max_bytes=64 * 1024,
            )
            != canonical_json_bytes(
                expected,
                label=f"expected Supervisor {event.event_type} event",
                max_bytes=64 * 1024,
            )
            for event, expected in zip(critical, expected_payloads, strict=True)
        )
        or model_completed.sequence != receipt.evidence_event_count
        or receipt_created.sequence != final_seal.event_count
        or final_seal.event_count != receipt.evidence_event_count + 1
    ):
        raise SupervisorInvocationRuntimeError("Supervisor invocation lifecycle payload differs")


def _rebuild_gateway_sources(
    snapshot: VerifiedRunSnapshot,
    receipt: SupervisorInvocationReceipt,
    chat: ProviderChatRequest,
    authorities: SupervisorInvocationAuthorities,
) -> tuple[
    ToolRequest,
    GatewayOutcome,
    ProviderChatResult,
    dict[str, object],
    tuple[SecretLease, ...],
]:
    reservation_raw = parse_strict_json_bytes(
        snapshot.artifact_bytes(receipt.request_reservation_path),
        label="sealed Supervisor Tool request reservation",
        max_bytes=_MAX_REQUEST_RESERVATION_BYTES,
    )
    if type(reservation_raw) is not dict:
        raise SupervisorInvocationRuntimeError(
            "Supervisor Tool request reservation must be an object"
        )
    reservation = cast(dict[str, object], reservation_raw)
    if set(reservation) != {
        "apiVersion",
        "kind",
        "requestId",
        "requestSha256",
    } or reservation != {
        "apiVersion": "pajin.dev/tool-request-reservation/v1",
        "kind": "ToolRequestReservation",
        "requestId": receipt.stable_request_id,
        "requestSha256": receipt.provider_outcome.tool_request_digest,
    }:
        raise SupervisorInvocationRuntimeError("Supervisor Tool request reservation differs")
    evidence_raw = parse_strict_json_bytes(
        snapshot.artifact_bytes(receipt.gateway_evidence_path),
        label="sealed Supervisor Gateway evidence",
        max_bytes=_MAX_GATEWAY_EVIDENCE_BYTES,
    )
    if type(evidence_raw) is not dict:
        raise SupervisorInvocationRuntimeError("Supervisor Gateway evidence must be an object")
    evidence = cast(dict[str, object], evidence_raw)
    allowed_keys = {
        "request",
        "policyDecision",
        "result",
        "networkLogTrusted",
        "workerJob",
        "workerResult",
        "secretLeases",
    }
    if (
        not set(evidence) <= allowed_keys
        or not {
            "request",
            "policyDecision",
            "result",
            "networkLogTrusted",
            "workerJob",
            "workerResult",
            "secretLeases",
        }
        <= set(evidence)
        or type(evidence["networkLogTrusted"]) is not bool
    ):
        raise SupervisorInvocationRuntimeError("Supervisor Gateway evidence shape differs")
    request = ToolRequest.model_validate(evidence["request"])
    decision = PolicyDecision.model_validate(evidence["policyDecision"])
    sealed_result = ToolResult.model_validate(evidence["result"])
    worker_result = WorkerResult.model_validate(evidence["workerResult"])
    if sealed_result.evidence:
        raise SupervisorInvocationRuntimeError(
            "sealed Gateway evidence unexpectedly contains its own path"
        )
    actual_result = sealed_result.model_copy(
        update={"evidence": [receipt.gateway_evidence_path]},
        deep=True,
    )
    result = ProviderChatResult.model_validate(actual_result.data)
    gateway = GatewayOutcome(
        decision=decision,
        result=actual_result,
        worker_result=worker_result,
        network_log_trusted=evidence["networkLogTrusted"],
        result_identity_valid=True,
        executed=True,
    )
    expected_request = ToolRequest(
        request_id=receipt.stable_request_id,
        agent_id=request.agent_id,
        tool_id=request.tool_id,
        target=request.target,
        method="POST",
        arguments=chat.model_dump(mode="json", by_alias=True),
    )
    if request != expected_request:
        raise SupervisorInvocationRuntimeError(
            "Supervisor Gateway request differs from the rebuilt Provider chat"
        )
    tool, job, evidence_job_metadata = _rebuild_provider_worker_job(
        evidence["workerJob"],
        request=expected_request,
        authorities=authorities,
    )
    if worker_result.execution_id != job.execution_id:
        raise SupervisorInvocationRuntimeError(
            "Supervisor Worker result differs from the sealed Worker job"
        )
    leases = _verify_secret_leases(
        evidence["secretLeases"],
        request=request,
        job=job,
        provider_run_id=receipt.provider_run_id,
    )
    lease_ids = tuple(lease.lease_id for lease in leases)
    dispatched_metadata = safe_job_metadata(
        request,
        job,
        lease_ids=list(lease_ids),
    )
    expected_job_metadata = safe_job_metadata(request, job)
    if canonical_json_bytes(
        evidence_job_metadata,
        label="sealed Supervisor Worker job metadata",
        max_bytes=64 * 1024,
    ) != canonical_json_bytes(
        expected_job_metadata,
        label="expected Supervisor Worker job metadata",
        max_bytes=64 * 1024,
    ):
        differing_fields = sorted(
            key
            for key in set(evidence_job_metadata) | set(expected_job_metadata)
            if evidence_job_metadata.get(key) != expected_job_metadata.get(key)
        )
        raise SupervisorInvocationRuntimeError(
            "Supervisor Worker job differs from the expected Provider execution: "
            + ", ".join(differing_fields)
        )
    expected_tool_result = tool.interpret(expected_request, worker_result)
    if canonical_json_bytes(
        sealed_result.model_dump(mode="json"),
        label="sealed Supervisor Tool result",
        max_bytes=_MAX_GATEWAY_EVIDENCE_BYTES,
    ) != canonical_json_bytes(
        expected_tool_result.model_dump(mode="json"),
        label="reconstructed Supervisor Tool result",
        max_bytes=_MAX_GATEWAY_EVIDENCE_BYTES,
    ):
        raise SupervisorInvocationRuntimeError(
            "Supervisor Tool result differs from the sealed Worker output"
        )
    return request, gateway, result, dispatched_metadata, leases


def _rebuild_provider_worker_job(
    raw_metadata: object,
    *,
    request: ToolRequest,
    authorities: SupervisorInvocationAuthorities,
) -> tuple[OpenAICompatibleChatTool, WorkerJob, dict[str, object]]:
    if type(raw_metadata) is not dict:
        raise SupervisorInvocationRuntimeError("Supervisor Worker job must be an object")
    metadata = cast(dict[str, object], raw_metadata)
    execution_id = metadata.get("executionId")
    if type(execution_id) is not str:
        raise SupervisorInvocationRuntimeError("Supervisor Worker execution identity is invalid")
    registration = authorities.provider_registration
    tool = OpenAICompatibleChatTool(registration)
    prepared = tool.prepare(request).model_copy(
        update={"execution_id": execution_id},
        deep=True,
    )
    request_cost = tool.network_request_cost(request)
    endpoint = str(registration.endpoint)
    allow = [endpoint]
    if registration.endpoint.scheme == "https":
        parsed = urlsplit(endpoint)
        allow.append(urlunsplit((parsed.scheme, parsed.netloc, "/**", "", "")))
    job = WorkerJob.model_validate(
        prepared.model_copy(
            update={
                "network": NetworkMode.EGRESS_PROXY,
                "egress_policy": EgressPolicy(
                    allow=allow,
                    deny=[],
                    allowed_methods={"POST"},
                    allow_private_networks=registration.allow_private_networks,
                    max_requests=request_cost,
                ),
            },
            deep=True,
        ).model_dump(mode="python")
    )
    return tool, job, metadata


def _verify_secret_leases(
    raw_leases: object,
    *,
    request: ToolRequest,
    job: WorkerJob,
    provider_run_id: str,
) -> tuple[SecretLease, ...]:
    if type(raw_leases) is not list or len(raw_leases) != len(job.secret_requests):
        raise SupervisorInvocationRuntimeError("Supervisor secret lease set differs")
    leases: list[SecretLease] = []
    for raw in cast(list[object], raw_leases):
        if type(raw) is not dict:
            raise SupervisorInvocationRuntimeError("Supervisor secret lease must be an object")
        lease = SecretLease.model_validate(raw)
        if canonical_json_bytes(
            raw,
            label="sealed Supervisor secret lease",
            max_bytes=64 * 1024,
        ) != canonical_json_bytes(
            lease.model_dump(mode="json"),
            label="validated Supervisor secret lease",
            max_bytes=64 * 1024,
        ):
            raise SupervisorInvocationRuntimeError("Supervisor secret lease was coerced")
        leases.append(lease)
    if len({lease.lease_id for lease in leases}) != len(leases):
        raise SupervisorInvocationRuntimeError("Supervisor secret lease IDs are duplicated")
    for lease, secret_request in zip(leases, job.secret_requests, strict=True):
        if (
            lease.binding != secret_request.binding
            or lease.secret_ref_fingerprint != SecretBroker.fingerprint(secret_request.secret_ref)
            or lease.audience != f"{request.agent_id}:{job.execution_id}"
            or lease.scope != provider_run_id
            or lease.max_uses != 1
            or lease.remaining_uses != 0
            or lease.status is not SecretLeaseStatus.REVOKED
            or lease.revoked_reason != "Worker execution finished"
            or (lease.expires_at - lease.issued_at).total_seconds() != secret_request.ttl_seconds
        ):
            raise SupervisorInvocationRuntimeError(
                "Supervisor secret lease differs from the expected Worker job"
            )
    return tuple(leases)


def _only_artifact(seal: RunIntegritySeal, path: str) -> SealedArtifact:
    matches = [artifact for artifact in seal.artifacts if artifact.path == path]
    if len(matches) != 1:
        raise SupervisorInvocationRuntimeError(
            "Supervisor invocation artifact was not sealed exactly once"
        )
    return matches[0]


def _snapshot_artifact(snapshot: VerifiedRunSnapshot, path: str) -> SealedArtifact:
    matches = [
        artifact for seal in snapshot.seals for artifact in seal.artifacts if artifact.path == path
    ]
    if len(matches) != 1:
        raise SupervisorInvocationRuntimeError(
            "Supervisor invocation snapshot artifact is missing or duplicated"
        )
    return matches[0]


def _invocation_receipt_digest(domain: str, value: object) -> str:
    payload = canonical_json_bytes(
        value,
        label="Supervisor invocation receipt identity",
        max_bytes=_MAX_RECEIPT_BYTES,
    )
    return sha256(domain.encode("ascii", errors="strict") + b"\x00" + payload).hexdigest()
