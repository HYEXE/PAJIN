"""Pinned deployment authority for the Worker-side Graph/Capability bridge."""

from __future__ import annotations

import hmac
import os
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from re import fullmatch

from pydantic import Field, ValidationError, field_validator, model_validator

from pajin.capabilities import (
    CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
    CapabilityDispatchReconciliationStatus,
    CapabilityGraphRunAuditAnchor,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityUseProfile,
    ExistingModeCapabilityActivation,
    activate_existing_mode_capabilities,
    admit_existing_mode_capability_releases,
    existing_mode_capability_bundle,
    reconcile_capability_dispatch,
)
from pajin.domain.models import (
    CampaignManifest,
    StrictModel,
    campaign_manifest_digest,
)
from pajin.graph import (
    ActionApprovalAuthorization,
    ActionApprovalBatchAuthorization,
    ActionApprovalBatchCancellation,
    ActionApprovalBatchCompletion,
    ActionApprovalBatchEnvelope,
    ActionApprovalBatchError,
    ActionApprovalBatchPublication,
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalEnvelope,
    ActionApprovalError,
    ActionApprovalInputAuthority,
    ActionProposal,
    GraphActionPermitAuthority,
    GraphActionPermitDispatcher,
    GraphApprovedActionBatchDispatcher,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
    GraphDecision,
    MissionEnvelope,
    SQLiteActionApprovalBatchJournal,
    SQLiteGraphStore,
)
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    load_verified_run_events,
    load_verified_run_snapshot,
)
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.mock import MockAgentProbe

CAPABILITY_GRAPH_DEPLOYMENT_API_VERSION = "pajin.dev/capability-graph-worker-deployment/v1alpha1"
CAPABILITY_GRAPH_BATCH_DEPLOYMENT_API_VERSION = (
    "pajin.dev/capability-graph-worker-deployment/v1alpha2"
)
_MAX_DEPLOYMENT_BYTES = 8 * 1024 * 1024
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"


class CapabilityGraphDeploymentError(RuntimeError):
    """Raised when Worker deployment authority cannot be established safely."""


class CapabilityGraphCompilerIdentity(StrictModel):
    """Exact compiler identity already pinned by the durable Graph Permit Store."""

    compiler_id: str = Field(
        alias="compilerId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    compiler_version: str = Field(
        alias="compilerVersion",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    compiler_digest: str = Field(
        alias="compilerDigest",
        pattern=r"^[a-f0-9]{64}$",
    )


class CapabilityGraphWorkerDeployment(StrictModel):
    """Out-of-band, digest-pinned authority admitted when the Worker starts."""

    api_version: str = Field(
        default=CAPABILITY_GRAPH_DEPLOYMENT_API_VERSION,
        alias="apiVersion",
        pattern=(
            r"^pajin\.dev/capability-graph-worker-deployment/"
            r"(?:v1alpha1|v1alpha2)$"
        ),
    )
    kind: str = Field(
        default="CapabilityGraphWorkerDeployment",
        pattern=r"^CapabilityGraphWorkerDeployment$",
    )
    deployment_id: str = Field(
        alias="deploymentId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    campaign: CampaignManifest
    campaign_digest: str = Field(
        alias="campaignDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    mission_envelope: MissionEnvelope = Field(alias="missionEnvelope")
    action_approvals: tuple[ActionApprovalEnvelope, ...] = Field(
        default=(),
        alias="actionApprovals",
        max_length=1_024,
    )
    action_approval_batches: tuple[ActionApprovalBatchEnvelope, ...] = Field(
        default=(),
        alias="actionApprovalBatches",
        max_length=128,
    )
    action_approval_batch_cancellations: tuple[ActionApprovalBatchCancellation, ...] = Field(
        default=(),
        alias="actionApprovalBatchCancellations",
        max_length=128,
    )
    action_approval_batch_journal: str | None = Field(
        default=None,
        alias="actionApprovalBatchJournal",
        max_length=4_096,
    )
    lifecycle_policy: CapabilityLifecyclePolicy = Field(alias="lifecyclePolicy")
    trust_keys: tuple[CapabilityLifecycleTrustKey, ...] = Field(
        alias="trustKeys",
        min_length=2,
        max_length=32,
    )
    releases: tuple[CapabilityReleaseBundle, ...] = Field(
        min_length=7,
        max_length=7,
    )
    activated_releases: tuple[CapabilityReleaseRef, ...] = Field(
        alias="activatedReleases",
        min_length=1,
        max_length=7,
    )
    profile: CapabilityUseProfile
    release_set_digest: str = Field(
        alias="releaseSetDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    activation_set_digest: str = Field(
        alias="activationSetDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    graph_database: str = Field(alias="graphDatabase", min_length=1, max_length=4_096)
    run_root: str = Field(alias="runRoot", min_length=1, max_length=4_096)
    compiler: CapabilityGraphCompilerIdentity
    permit_ttl_seconds: int = Field(
        default=30,
        alias="permitTtlSeconds",
        strict=True,
        ge=1,
        le=300,
    )

    @field_validator("graph_database", "run_root")
    @classmethod
    def require_absolute_state_path(cls, value: str) -> str:
        supplied = Path(value)
        if not supplied.is_absolute():
            raise ValueError(
                "Capability Graph deployment state paths must be bounded absolute paths"
            )
        path = Path(os.path.abspath(supplied))
        if path == Path(path.anchor):
            raise ValueError(
                "Capability Graph deployment state paths must be bounded absolute paths"
            )
        return str(path)

    @field_validator("action_approval_batch_journal")
    @classmethod
    def require_absolute_batch_journal_path(cls, value: str | None) -> str | None:
        if value is None:
            return None
        supplied = Path(value)
        if not supplied.is_absolute():
            raise ValueError("Capability Graph batch journal must be a bounded absolute path")
        path = Path(os.path.abspath(supplied))
        if path == Path(path.anchor):
            raise ValueError("Capability Graph batch journal must be a bounded absolute path")
        return str(path)

    @model_validator(mode="after")
    def bind_campaign_and_state_roots(self) -> CapabilityGraphWorkerDeployment:
        if capability_graph_campaign_digest(self.campaign) != self.campaign_digest:
            raise ValueError("Capability Graph deployment Campaign digest differs")
        if (
            self.mission_envelope.campaign_id != self.campaign.metadata.name
            or self.mission_envelope.source_campaign_digest != self.campaign_digest
            or (
                self.mission_envelope.compiler_id,
                self.mission_envelope.compiler_version,
                self.mission_envelope.compiler_digest,
            )
            != (
                self.compiler.compiler_id,
                self.compiler.compiler_version,
                self.compiler.compiler_digest,
            )
        ):
            raise ValueError("Capability Graph deployment MissionEnvelope authority differs")
        approval_ids: set[str] = set()
        approval_proposals: set[str] = set()
        approval_requests: set[str] = set()
        release_capabilities = {
            (
                bundle.release.statement.release_id,
                bundle.release.statement.release_digest,
            ): bundle.release.statement.capability.capability
            for bundle in self.releases
        }
        activated_release_bindings = {
            (
                item.release_id,
                item.release_digest,
                capability.capability_id,
                capability.capability_version,
                capability.capability_digest,
            )
            for item in self.activated_releases
            for capability in (release_capabilities.get((item.release_id, item.release_digest)),)
            if capability is not None
        }
        if len(activated_release_bindings) != len(self.activated_releases):
            raise ValueError("Capability Graph activated release is absent from signed inventory")
        for approval in self.action_approvals:
            if (
                approval.approval_id in approval_ids
                or approval.proposal.proposal_id in approval_proposals
                or approval.proposal.request_id in approval_requests
            ):
                raise ValueError("Capability Graph deployment approvals are not unique")
            if (
                approval.campaign_id != self.campaign.metadata.name
                or approval.campaign_digest != self.campaign_digest
                or approval.run_id != self.mission_envelope.run_id
                or approval.mission_envelope != self.mission_envelope
                or approval.activation_set_digest != self.activation_set_digest
                or approval.proposal.capability not in self.mission_envelope.allowed_capabilities
                or (
                    approval.release.release_id,
                    approval.release.release_digest,
                    approval.release.capability_id,
                    approval.release.capability_version,
                    approval.release.capability_digest,
                )
                not in activated_release_bindings
                or approval.issuer.context_digest != self.campaign_digest
            ):
                raise ValueError(
                    "Capability Graph deployment approval differs from deployment authority"
                )
            approval_ids.add(approval.approval_id)
            approval_proposals.add(approval.proposal.proposal_id)
            approval_requests.add(approval.proposal.request_id)
        _validate_capability_graph_batch_inventory(self)
        graph_database = Path(self.graph_database)
        run_root = Path(self.run_root)
        if _path_is_within(graph_database, run_root):
            raise ValueError("Capability Graph database must be separated from the Run audit root")
        _validate_capability_graph_batch_state_paths(self, graph_database, run_root)
        release_keys = [(item.release_id, item.release_digest) for item in self.activated_releases]
        if release_keys != sorted(set(release_keys)):
            raise ValueError(
                "Capability Graph activated releases must be unique and canonically sorted"
            )
        return self


def _validate_capability_graph_batch_inventory(
    deployment: CapabilityGraphWorkerDeployment,
) -> None:
    batches = deployment.action_approval_batches
    if batches:
        if deployment.api_version != CAPABILITY_GRAPH_BATCH_DEPLOYMENT_API_VERSION:
            raise ValueError("Capability Graph approval batches require deployment v1alpha2")
        if deployment.action_approval_batch_journal is None:
            raise ValueError("Capability Graph approval batches require a host-local journal")
    elif (
        deployment.action_approval_batch_cancellations
        or deployment.action_approval_batch_journal is not None
    ):
        raise ValueError("Capability Graph batch controls require an approval batch inventory")
    batch_ids: set[str] = set()
    batched_approval_ids: set[str] = set()
    approval_inventory = {item.approval_id: item for item in deployment.action_approvals}
    for batch in batches:
        if batch.batch_id in batch_ids:
            raise ValueError("Capability Graph deployment reuses an approval batch")
        if (
            batch.campaign_id != deployment.campaign.metadata.name
            or batch.campaign_digest != deployment.campaign_digest
            or batch.run_id != deployment.mission_envelope.run_id
            or batch.issuer.context_digest != deployment.campaign_digest
            or any(item.mission_envelope != deployment.mission_envelope for item in batch.approvals)
        ):
            raise ValueError("Capability Graph approval batch differs from deployment authority")
        for approval, cleanup_request in zip(
            batch.approvals,
            batch.cleanup_requests,
            strict=True,
        ):
            if (
                approval_inventory.get(approval.approval_id) != approval
                or approval.approval_id in batched_approval_ids
                or cleanup_request is not None
                or approval.side_effect_class.endswith("write")
            ):
                raise ValueError("Capability Graph batch item is absent, reused, or not no-write")
            batched_approval_ids.add(approval.approval_id)
        batch_ids.add(batch.batch_id)
    cancellations: set[str] = set()
    batch_inventory = {item.batch_id: item for item in batches}
    for cancellation in deployment.action_approval_batch_cancellations:
        target_batch = batch_inventory.get(cancellation.batch_id)
        if (
            cancellation.cancellation_id in cancellations
            or target_batch is None
            or cancellation.batch_digest != target_batch.batch_digest
            or cancellation.cancelled_at < target_batch.approved_at
            or cancellation.cancelled_at >= target_batch.expires_at
            or any(ordinal > len(target_batch.approvals) for ordinal in cancellation.item_ordinals)
        ):
            raise ValueError(
                "Capability Graph batch cancellation differs from deployment inventory"
            )
        cancellations.add(cancellation.cancellation_id)


def _validate_capability_graph_batch_state_paths(
    deployment: CapabilityGraphWorkerDeployment,
    graph_database: Path,
    run_root: Path,
) -> None:
    if deployment.action_approval_batch_journal is None:
        return
    batch_journal = Path(deployment.action_approval_batch_journal)
    graph_sidecars = {Path(f"{graph_database}{suffix}") for suffix in ("-journal", "-shm", "-wal")}
    if (
        batch_journal == graph_database
        or batch_journal in graph_sidecars
        or _path_is_within(batch_journal, run_root)
    ):
        raise ValueError(
            "Capability Graph batch journal must be separated from Graph and Run state"
        )


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


@dataclass(frozen=True, slots=True)
class CapabilityGraphDeploymentRuntime:
    """Verified in-process objects; Jobs can select inputs but not runtime code."""

    deployment: CapabilityGraphWorkerDeployment
    activation: ExistingModeCapabilityActivation
    tools: ToolRegistry
    graph_store: SQLiteGraphStore
    permits: GraphActionPermitDispatcher
    approved_permits: GraphApprovedActionPermitDispatcher | None
    approval_input_authority: ActionApprovalInputAuthority | None
    approval_batch_journal: SQLiteActionApprovalBatchJournal | None
    approval_batch_dispatcher: GraphApprovedActionBatchDispatcher | None
    clock: Callable[[], datetime]

    def approval_batch(self, batch_id: str) -> ActionApprovalBatchEnvelope:
        """Resolve one exact startup-pinned opt-in batch."""

        matches = tuple(
            item for item in self.deployment.action_approval_batches if item.batch_id == batch_id
        )
        if len(matches) != 1:
            raise CapabilityGraphDeploymentError(
                "Capability Graph approval batch is not deployment-pinned"
            )
        return matches[0].model_copy(deep=True)

    def deliver_batch_cancellation(
        self,
        cancellation_id: str,
    ) -> ActionApprovalBatchPublication:
        """Apply one startup-pinned cancellation to still-pending items only."""

        journal = self.approval_batch_journal
        if journal is None:
            raise CapabilityGraphDeploymentError(
                "Capability Graph approval batch journal is not configured"
            )
        matches = tuple(
            item
            for item in self.deployment.action_approval_batch_cancellations
            if item.cancellation_id == cancellation_id
        )
        if len(matches) != 1:
            raise CapabilityGraphDeploymentError(
                "Capability Graph batch cancellation is not deployment-pinned"
            )
        cancellation = matches[0]
        batch = self.approval_batch(cancellation.batch_id)
        journal.register(batch)
        return journal.cancel_pending(
            batch,
            cancellation,
        )

    def open_run_store(self, run_id: str) -> RunStore:
        """Create or reopen the exact Graph Run audit directory."""

        if fullmatch(_RUN_ID_PATTERN, run_id) is None:
            raise CapabilityGraphDeploymentError(
                "Capability Graph Run ID is not a generated RunStore identifier"
            )
        if run_id != self.deployment.mission_envelope.run_id:
            raise CapabilityGraphDeploymentError(
                "Capability Graph Run differs from the deployed MissionEnvelope"
            )
        root = Path(self.deployment.run_root)
        campaign = self.deployment.campaign.metadata.name
        campaign_path = root / campaign
        run_path = campaign_path / run_id
        self._reject_linked_run_path(root, campaign_path, run_path)
        if run_path.exists():
            store = RunStore(run_id, run_path)
        else:
            try:
                store = RunStore.create(root, campaign, run_id=run_id)
            except FileExistsError:
                self._reject_linked_run_path(root, campaign_path, run_path)
                store = RunStore(run_id, run_path)
        self._ensure_run_audit_anchor(store)
        return store

    def _ensure_run_audit_anchor(self, store: RunStore) -> None:
        deployment = self.deployment
        anchor = CapabilityGraphRunAuditAnchor(
            deploymentId=deployment.deployment_id,
            campaignId=deployment.campaign.metadata.name,
            campaignDigest=deployment.campaign_digest,
            runId=store.run_id,
            envelopeId=deployment.mission_envelope.envelope_id,
            envelopeDigest=deployment.mission_envelope.envelope_digest,
            releaseSetDigest=deployment.release_set_digest,
            activationSetDigest=deployment.activation_set_digest,
            compilerId=deployment.compiler.compiler_id,
            compilerVersion=deployment.compiler.compiler_version,
            compilerDigest=deployment.compiler.compiler_digest,
        )
        try:
            store.append_unique_event(
                CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE,
                anchor.model_dump(mode="json", by_alias=True),
                occurred_at=self.clock(),
            )
            with suppress(RunIntegrityError):
                store.seal()
            events = load_verified_run_events(
                store.path,
                expected_run_id=store.run_id,
            )
            anchors = tuple(
                event
                for event in events
                if event.event_type == CAPABILITY_GRAPH_RUN_AUDIT_ANCHOR_EVENT_TYPE
            )
            if len(anchors) != 1 or anchors[0].payload != anchor.model_dump(
                mode="json",
                by_alias=True,
            ):
                raise CapabilityGraphDeploymentError(
                    "Capability Graph Run audit anchor differs from deployment"
                )
        except CapabilityGraphDeploymentError:
            raise
        except (OSError, RunIntegrityError, ValidationError, ValueError) as exc:
            raise CapabilityGraphDeploymentError(
                "Capability Graph Run audit anchor could not be verified"
            ) from exc

    @staticmethod
    def _reject_linked_run_path(*paths: Path) -> None:
        for path in paths:
            if path.is_symlink() or path.is_junction():
                raise CapabilityGraphDeploymentError(
                    "Capability Graph Run audit path cannot contain a link boundary"
                )


class _DeploymentActionApprovalInputAuthority:
    """Authenticate approvals against the exact digest-pinned deployment inventory."""

    def __init__(self, approvals: tuple[ActionApprovalEnvelope, ...]) -> None:
        self._approvals = {item.approval_id: item for item in approvals}

    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        expected = self._approvals.get(approval.approval_id)
        if (
            expected is None
            or expected != approval
            or approval.mission_envelope != envelope
            or approval.proposal != proposal
            or approval.graph_decision != decision
        ):
            raise ActionApprovalError("Action approval is not pinned by the Worker deployment")


class _DeploymentActionApprovalBatchAuthority:
    """Authenticate batch inventory, completion audit, and delivered cancellation."""

    def __init__(self, deployment: CapabilityGraphWorkerDeployment) -> None:
        self._batches = {item.batch_id: item for item in deployment.action_approval_batches}
        self._cancellations = {
            item.cancellation_id: item for item in deployment.action_approval_batch_cancellations
        }
        self._campaign_id = deployment.campaign.metadata.name
        self._run_root = Path(deployment.run_root)

    def verify_action_approval_batch(self, batch: ActionApprovalBatchEnvelope) -> None:
        if self._batches.get(batch.batch_id) != batch:
            raise ActionApprovalBatchError(
                "Action approval batch is not pinned by the Worker deployment"
            )

    def verify_action_approval_batch_completion(
        self,
        batch: ActionApprovalBatchEnvelope,
        approval: ActionApprovalEnvelope,
        authorization: ActionApprovalBatchAuthorization,
        completion: ActionApprovalBatchCompletion,
    ) -> None:
        self.verify_action_approval_batch(batch)
        if (
            not isinstance(authorization, ActionApprovalAuthorization)
            or batch.approval_at(completion.item_ordinal) != approval
            or completion.source != "worker-completion"
            or completion.outcome != "succeeded"
            or completion.cleanup_reservation_id is not None
            or completion.restored_state_evidence_digest is not None
        ):
            raise ActionApprovalBatchError(
                "Capability Graph batch completion is outside the no-write Worker profile"
            )
        permit = authorization.action.permit
        run_path = self._run_root / self._campaign_id / permit.run_id
        try:
            snapshot = load_verified_run_snapshot(
                run_path,
                expected_run_id=permit.run_id,
            )
            reconciliation = reconcile_capability_dispatch(snapshot, permit)
        except Exception as exc:
            raise ActionApprovalBatchError(
                "Capability Graph batch completion audit is not sealed and verified"
            ) from exc
        terminal = reconciliation.terminal_event
        if (
            reconciliation.record.status is not CapabilityDispatchReconciliationStatus.COMPLETED
            or terminal is None
            or terminal.gateway_outcome_digest != completion.evidence_digest
            or completion.completed_at < terminal.occurred_at
        ):
            raise ActionApprovalBatchError(
                "Capability Graph batch completion differs from sealed Gateway evidence"
            )

    def verify_action_approval_batch_cancellation(
        self,
        batch: ActionApprovalBatchEnvelope,
        cancellation: ActionApprovalBatchCancellation,
    ) -> None:
        self.verify_action_approval_batch(batch)
        if self._cancellations.get(cancellation.cancellation_id) != cancellation:
            raise ActionApprovalBatchError(
                "Action approval batch cancellation is not pinned by the Worker deployment"
            )


def capability_graph_campaign_digest(campaign: CampaignManifest) -> str:
    """Fingerprint one canonical Campaign used by the deployment and envelope."""

    return campaign_manifest_digest(campaign)


def load_capability_graph_deployment(
    path: Path,
    *,
    expected_sha256: str,
    clock: Callable[[], datetime] | None = None,
) -> CapabilityGraphDeploymentRuntime:
    """Load, pin, verify, and activate one organization-issued deployment."""

    if fullmatch(r"^[a-f0-9]{64}$", expected_sha256) is None:
        raise CapabilityGraphDeploymentError("Capability Graph deployment SHA-256 is malformed")
    try:
        content = read_bounded_regular_bytes(
            path,
            max_bytes=_MAX_DEPLOYMENT_BYTES,
            label="Capability Graph Worker deployment",
            require_single_link=True,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise CapabilityGraphDeploymentError(
            "Capability Graph Worker deployment could not be read safely"
        ) from exc
    observed_sha256 = sha256(content).hexdigest()
    if not hmac.compare_digest(observed_sha256, expected_sha256):
        raise CapabilityGraphDeploymentError("Capability Graph Worker deployment SHA-256 differs")
    try:
        decoded = parse_strict_json_bytes(
            content,
            label="Capability Graph Worker deployment",
            max_bytes=_MAX_DEPLOYMENT_BYTES,
            max_depth=64,
            max_nodes=100_000,
        )
        deployment = CapabilityGraphWorkerDeployment.model_validate(decoded)
    except (TypeError, ValueError, ValidationError) as exc:
        raise CapabilityGraphDeploymentError(
            "Capability Graph Worker deployment contract is invalid"
        ) from exc

    selected_clock = clock or (lambda: datetime.now(UTC))
    try:
        tools = _existing_mode_tool_registry()
        rollout = admit_existing_mode_capability_releases(
            bundle=existing_mode_capability_bundle(tools),
            policy=deployment.lifecycle_policy,
            trust_keys=deployment.trust_keys,
            releases=deployment.releases,
            clock=selected_clock,
        )
        if rollout.release_set.release_set_digest != deployment.release_set_digest:
            raise CapabilityGraphDeploymentError("Capability Graph release-set digest differs")
        activation = activate_existing_mode_capabilities(
            rollout=rollout,
            releases=deployment.activated_releases,
            profile=deployment.profile,
        )
        if activation.activation_set.activation_set_digest != deployment.activation_set_digest:
            raise CapabilityGraphDeploymentError("Capability Graph activation-set digest differs")
        activated_capabilities = {
            item.action_capability.reference() for item in activation.activation_set.bindings
        }
        if set(deployment.mission_envelope.allowed_capabilities) != activated_capabilities:
            raise CapabilityGraphDeploymentError(
                "Capability Graph MissionEnvelope differs from the activated Capability set"
            )
        graph_store = SQLiteGraphStore(
            Path(deployment.graph_database),
            campaign_id=deployment.campaign.metadata.name,
        )
        compiler = deployment.compiler
        approval_policies = ActionApprovalCapabilityPolicyRegistry(
            tuple(
                ActionApprovalCapabilityPolicy(
                    capability=binding.action_capability.reference(),
                    sideEffectClass=definition.side_effect_class.value,
                    approvalRequired=definition.approval_required,
                    cleanupRequired=definition.cleanup_required,
                )
                for binding in activation.activation_set.bindings
                for definition in (
                    rollout.bundle.definitions.resolve(binding.capability.capability),
                )
            )
        )
        authority = GraphActionPermitAuthority(
            campaign_id=deployment.campaign.metadata.name,
            compiler_id=compiler.compiler_id,
            compiler_version=compiler.compiler_version,
            compiler_digest=compiler.compiler_digest,
            capabilities=activation.action_registry(),
            policies=approval_policies,
            permit_store=graph_store.permit_store,
            clock=selected_clock,
            permit_ttl=timedelta(seconds=deployment.permit_ttl_seconds),
        )
        approval_input_authority = (
            _DeploymentActionApprovalInputAuthority(deployment.action_approvals)
            if deployment.action_approvals
            else None
        )
        approved_authority = (
            GraphApprovedActionPermitAuthority(
                campaign_id=deployment.campaign.metadata.name,
                compiler_id=compiler.compiler_id,
                compiler_version=compiler.compiler_version,
                compiler_digest=compiler.compiler_digest,
                capabilities=activation.action_registry(),
                policies=approval_policies,
                permit_store=graph_store.permit_store,
                input_authority=approval_input_authority,
                clock=selected_clock,
                permit_ttl=timedelta(seconds=deployment.permit_ttl_seconds),
            )
            if approval_input_authority is not None
            else None
        )
        approved_dispatcher = (
            GraphApprovedActionPermitDispatcher(approved_authority)
            if approved_authority is not None
            else None
        )
        approval_batch_journal: SQLiteActionApprovalBatchJournal | None = None
        approval_batch_dispatcher: GraphApprovedActionBatchDispatcher | None = None
        if deployment.action_approval_batches:
            if approved_authority is None or deployment.action_approval_batch_journal is None:
                raise CapabilityGraphDeploymentError(
                    "Capability Graph batch authority is incomplete"
                )
            batch_authority = _DeploymentActionApprovalBatchAuthority(deployment)
            approval_batch_journal = SQLiteActionApprovalBatchJournal(
                Path(deployment.action_approval_batch_journal),
                input_authority=batch_authority,
                completion_authority=batch_authority,
                cancellation_authority=batch_authority,
                clock=selected_clock,
            )
            approval_batch_dispatcher = GraphApprovedActionBatchDispatcher(
                approved_authority,
                approval_batch_journal,
            )
    except CapabilityGraphDeploymentError:
        raise
    except Exception as exc:
        raise CapabilityGraphDeploymentError(
            "Capability Graph Worker deployment authority failed verification"
        ) from exc
    return CapabilityGraphDeploymentRuntime(
        deployment=deployment,
        activation=activation,
        tools=tools,
        graph_store=graph_store,
        permits=GraphActionPermitDispatcher(authority),
        approved_permits=approved_dispatcher,
        approval_input_authority=approval_input_authority,
        approval_batch_journal=approval_batch_journal,
        approval_batch_dispatcher=approval_batch_dispatcher,
        clock=selected_clock,
    )


def _existing_mode_tool_registry() -> ToolRegistry:
    """Build the closed CAP-005 Tool inventory without plugin discovery."""

    tools = ToolRegistry()
    for tool in (
        MockAgentProbe(),
        AIChatProbeTool(),
        BooleanSQLiProbeTool(),
        CTFWebBackupProbeTool(),
        CTFCryptoXORTool(),
    ):
        tools.register(tool)
    return tools
