from __future__ import annotations

import json
import sqlite3
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Literal, cast
from uuid import uuid4

import pytest
from pydantic import ValidationError

import pajin.web_assessment.governed_models as governed_models
from pajin.capabilities.activation import (
    capability_grant_digest,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.adapters import registered_action_capability
from pajin.capabilities.authorities import (
    CapabilityAuthorityRole,
    CapabilityOracleDecision,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import CapabilityMaturity, CapabilitySideEffectClass
from pajin.capabilities.web_authenticated_assessment import (
    WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_ID,
    WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
    WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID,
    WebAuthenticatedAssessmentCapabilityActivation,
    WebAuthenticatedAssessmentParameters,
    WebAuthenticatedAssessmentTool,
    activate_web_authenticated_assessment_capability,
    registered_web_authenticated_assessment_capability_definition,
    web_authenticated_assessment_capability_bundle,
)
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CampaignMode,
    CapabilityGrant,
    ToolRequest,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalEnvelope,
    ActionApprovalInputAuthority,
    ActionApprovalReleaseRef,
    ApprovedActionDispatchResult,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
    build_action_approval_consumption_receipt,
)
from pajin.graph.authority import (
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionCapabilityRegistry,
    ActionPermitAuthorization,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
    action_permit_attempt_id,
    build_action_permit,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.graph.projection import (
    GraphProjectionCoordinator,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    GraphSnapshotRef,
    graph_snapshot_ref,
)
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.policy.capability import CapabilityLedger
from pajin.runtime.worker import (
    NetworkMode,
    WorkerJob,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.tools.base import ToolRegistry
from pajin.web_assessment.governed_models import (
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    GovernedWebAssessmentModelError,
    ProvisionedWebAccountReceipt,
    ProvisionedWebAccountReceiptRef,
    ProvisionedWebAccountReceiptRegistry,
    SignedWebActionApproval,
    WebActionApprovalAuthoritySet,
    WebActionApprovalInputAuthority,
    WebAssessmentAdapterManifest,
    WebAssessmentAdapterRegistry,
    WebAssessmentApprovedActionDispatcher,
    WebAssessmentCapabilityGrantConsumptionStore,
    WebAssessmentCapabilityGrantReservation,
    WebAssessmentDispatchAuthority,
    WebAssessmentDispatchBinding,
    WebAssessmentDispatchBindingRegistry,
    WebAssessmentSigningKeyState,
    WebAssessmentSigningRole,
    WebAssessmentVerificationKey,
    WebAuthenticatedAssessmentWorkerOutput,
    sign_provisioned_web_account_receipt,
    sign_web_action_approval,
    sign_web_assessment_adapter,
    web_action_approval_issuer_binding,
    web_assessment_public_key_base64url,
)
from pajin.web_assessment.recipes import juice_shop_plan

NOW = datetime.now(UTC).replace(microsecond=0)
ORIGIN = "http://127.0.0.1:3000"
_TEST_GRANT_STORE_ROOT = TemporaryDirectory(prefix="pajin-web-grant-tests-")


@pytest.fixture(autouse=True)
def _freeze_dispatch_authority_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(governed_models, "_system_utc_now", lambda: NOW)


def _seed(label: str) -> bytes:
    return sha256(f"web-005:{label}".encode()).digest()


def _digest(label: str) -> str:
    return sha256(f"web-005-digest:{label}".encode()).hexdigest()


def _adversarial_setattr(target: object, name: str, value: object) -> None:
    setattr(target, name, value)


def _verification_key(
    label: str,
    role: WebAssessmentSigningRole,
) -> WebAssessmentVerificationKey:
    return WebAssessmentVerificationKey(
        keyId=f"web.{label}",
        principalId=f"principal.{label}",
        role=role,
        publicKeyBase64url=web_assessment_public_key_base64url(_seed(label)),
        state=WebAssessmentSigningKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=1),
        notAfter=NOW + timedelta(days=1),
    )


def _manifest(**changes: object) -> WebAssessmentAdapterManifest:
    values: dict[str, object] = {
        "adapterId": "pajin.adapter.juice-shop.local",
        "adapterVersion": "1.0.0",
        "origin": ORIGIN,
        "implementationId": JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        "implementationDigest": JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        "recipeDigest": juice_shop_plan(ORIGIN).plan_digest,
        "issuedAt": NOW - timedelta(minutes=2),
        "expiresAt": NOW + timedelta(hours=1),
    }
    values.update(changes)
    return WebAssessmentAdapterManifest.model_validate(values)


def _adapter_registry(
    manifest: WebAssessmentAdapterManifest | None = None,
) -> WebAssessmentAdapterRegistry:
    key = _verification_key("adapter", WebAssessmentSigningRole.ADAPTER_PUBLISHER)
    signed = sign_web_assessment_adapter(
        manifest or _manifest(),
        key_id=key.key_id,
        private_key=_seed("adapter"),
    )
    return WebAssessmentAdapterRegistry(keys=(key,), adapters=(signed,), clock=lambda: NOW)


def _receipt(adapter: WebAssessmentAdapterManifest) -> ProvisionedWebAccountReceipt:
    return ProvisionedWebAccountReceipt(
        adapter=adapter.reference(),
        origin=ORIGIN,
        accountReferenceDigest="a" * 64,
        provisioningEvidenceDigest="b" * 64,
        targetFingerprintResponseSha256=_digest("target-fingerprint-response"),
        targetIdentityDigest="c" * 64,
        authorizationIds=("authorization:source", "authorization:validation"),
        identityMaterialRef="secret:web-account-name",
        proofMaterialRef="secret:web-account-proof",
        issuedAt=NOW - timedelta(minutes=1),
        expiresAt=NOW + timedelta(minutes=10),
    )


def _receipt_registry(
    receipt: ProvisionedWebAccountReceipt,
) -> ProvisionedWebAccountReceiptRegistry:
    key = _verification_key("account", WebAssessmentSigningRole.ACCOUNT_ISSUER)
    signed = sign_provisioned_web_account_receipt(
        receipt,
        key_id=key.key_id,
        private_key=_seed("account"),
    )
    return ProvisionedWebAccountReceiptRegistry(
        keys=(key,),
        receipts=(signed,),
        clock=lambda: NOW,
    )


class _JobCompiler:
    def __init__(self) -> None:
        self.compile_calls = 0

    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.web-job-compiler/v1"}

    def compile_job(
        self,
        *,
        request: ToolRequest,
        adapter: WebAssessmentAdapterManifest,
        account_receipt: ProvisionedWebAccountReceipt,
        dispatch: WebAssessmentDispatchBinding,
    ) -> WorkerJob:
        self.compile_calls += 1
        del request, adapter
        return WorkerJob(
            execution_id=dispatch.worker_execution_id,
            image="pajin-web-assessment-worker:host-local-v1",
            command=["web-assessment-executor"],
            stdin=json.dumps(
                {
                    "dispatch": dispatch.worker_binding(),
                    "receipt": account_receipt.worker_receipt(),
                },
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
            secret_requests=[
                WorkerSecretRequest(
                    secret_ref=account_receipt.identity_material_ref,
                    binding="account-name",
                ),
                WorkerSecretRequest(
                    secret_ref=account_receipt.proof_material_ref,
                    binding="account-proof",
                ),
                WorkerSecretRequest(
                    secret_ref=dispatch.target_observer_signing_material_ref,
                    binding="target-observer-signing-key",
                ),
                WorkerSecretRequest(
                    secret_ref=dispatch.worker_signing_material_ref,
                    binding="worker-signing-key",
                ),
            ],
        )


class _OutputVerifier:
    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.signed-web-output-verifier/v1"}

    def verify_output(
        self,
        *,
        request: ToolRequest,
        dispatch: WebAssessmentDispatchBinding,
        worker_result: WorkerResult,
    ) -> WebAuthenticatedAssessmentWorkerOutput:
        if (
            worker_result.status is not WorkerStatus.SUCCEEDED
            or worker_result.execution_id != dispatch.worker_execution_id
        ):
            raise ValueError("test verifier rejects Worker identity")
        return WebAuthenticatedAssessmentWorkerOutput(
            adapter=dispatch.adapter,
            accountReceipt=dispatch.account_receipt,
            dispatchBindingDigest=dispatch.binding_digest,
            workerExecutionId=dispatch.worker_execution_id,
            origin=request.target,
            runId="run_20260914T060000Z_deadbeef",
            rootDigest="d" * 64,
            resultDigest="e" * 64,
            attestationDigest="f" * 64,
            workerAttestation={"signed": True},
            authenticated=True,
            browserClosed=True,
            targetMutated=False,
            serverSessionMaterialPersisted=False,
        )


class _AtomicApprovalStore:
    def __init__(self) -> None:
        self.writer = object()
        self.authorization: ActionApprovalAuthorization | None = None
        self.input_authority: ActionApprovalInputAuthority | None = None
        self.lookup_calls = 0
        self.authorize_calls = 0

    def claim_approved_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        policies: ActionApprovalCapabilityPolicyRegistry,
        input_authority: ActionApprovalInputAuthority,
    ) -> object:
        del compiler_id, compiler_version, compiler_digest, policies
        self.input_authority = input_authority
        return self.writer

    def approved_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ActionApprovalAuthorization | None:
        self.lookup_calls += 1
        authorization = self.authorization
        if (
            authorization is None
            or authorization.approval.approval_id != approval_id
            or authorization.action.permit.permit_id != permit_id
        ):
            return None
        return ActionApprovalAuthorization(
            approval=authorization.approval,
            action=ActionPermitAuthorization(
                permit=authorization.action.permit,
                newlyConsumed=False,
            ),
            receipt=authorization.receipt,
        )

    def authorize_approved_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        capability: RegisteredActionCapability,
        approval: ActionApprovalEnvelope,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ActionApprovalAuthorization:
        assert writer is self.writer
        assert capability.reference() == proposal.capability
        assert approval.mission_envelope == envelope
        assert approval.proposal == proposal
        assert approval.graph_decision == decision
        self.authorize_calls += 1
        if self.authorization is None:
            permit = build_action_permit(
                envelope,
                proposal,
                decision,
                evaluated_at=evaluated_at,
                permit_ttl=permit_ttl,
            )
            receipt = build_action_approval_consumption_receipt(approval, permit)
            self.authorization = ActionApprovalAuthorization(
                approval=approval,
                action=ActionPermitAuthorization(
                    permit=permit,
                    newlyConsumed=True,
                ),
                receipt=receipt,
            )
            return self.authorization
        return ActionApprovalAuthorization(
            approval=self.authorization.approval,
            action=ActionPermitAuthorization(
                permit=self.authorization.action.permit,
                newlyConsumed=False,
            ),
            receipt=self.authorization.receipt,
        )


def _tool(
    store: SQLiteGraphStore | None = None,
    *,
    dispatch_authority: WebAssessmentDispatchAuthority | None = None,
    grant_store_path: Path | None = None,
) -> tuple[
    WebAuthenticatedAssessmentTool,
    WebAssessmentAdapterManifest,
    ProvisionedWebAccountReceipt,
]:
    manifest = _manifest()
    adapters = _adapter_registry(manifest)
    receipt = _receipt(manifest)
    authority = dispatch_authority
    if authority is None:
        graph_store = store or _graph_store()
        capability_ledger, source_grant, validation_grant = _grant_lineage()
        grant_store = WebAssessmentCapabilityGrantConsumptionStore(
            grant_store_path
            or Path(_TEST_GRANT_STORE_ROOT.name).resolve() / f"{uuid4().hex}.sqlite3",
            campaign_id="web-governed",
        )
        authority = WebAssessmentDispatchAuthority.create(
            graph_store=graph_store,
            capability_ledger=capability_ledger,
            grant_consumption_store=grant_store,
            source_grant=source_grant,
            validation_grant=validation_grant,
        )
    elif store is not None and authority._graph_store is not store:
        raise ValueError("test Tool Graph store differs from its dispatch authority")
    tool = WebAuthenticatedAssessmentTool(
        adapters=adapters,
        account_receipts=_receipt_registry(receipt),
        dispatch_bindings=WebAssessmentDispatchBindingRegistry(
            authority=authority,
        ),
        job_compiler=_JobCompiler(),
        output_verifier=_OutputVerifier(),
    )
    return tool, manifest, receipt


def _request(
    manifest: WebAssessmentAdapterManifest,
    receipt: ProvisionedWebAccountReceipt,
    **changes: object,
) -> ToolRequest:
    values: dict[str, object] = {
        "request_id": "tool_web_authenticated_source",
        "agent_id": "agent:web-assessment",
        "tool_id": WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID,
        "target": ORIGIN,
        "method": "POST",
        "arguments": WebAuthenticatedAssessmentParameters(
            adapter=manifest.reference(),
            accountReceipt=receipt.reference(),
        ).model_dump(mode="json", by_alias=True),
    }
    values.update(changes)
    return ToolRequest.model_validate(values)


def _campaign(*, at: datetime = NOW) -> CampaignManifest:
    return CampaignManifest.model_validate(
        {
            "apiVersion": "pajin.dev/v1alpha1",
            "kind": "Campaign",
            "metadata": {"name": "web-governed"},
            "spec": {
                "mode": CampaignMode.BUG_BOUNTY,
                "autonomy": AutonomyLevel.SUPERVISED,
                "authorization": {
                    "approvedBy": "local-owner",
                    "approvedAt": at - timedelta(minutes=10),
                    "expiresAt": at + timedelta(minutes=10),
                    "evidence": "approved local Juice Shop assessment",
                },
                "targets": [
                    {
                        "type": "web-application",
                        "id": "juice-shop-local",
                        "endpoint": ORIGIN,
                    }
                ],
                "scope": {"allow": [ORIGIN], "deny": []},
                "objectives": ["Validate the governed local assessment flow"],
                "rulesOfEngagement": {
                    "maxToolRiskTier": ToolRiskTier.T2,
                    "allowedMethods": ["POST"],
                    "allowPrivateNetworks": True,
                },
                "budgets": {
                    "durationSeconds": 600,
                    "maxCostUsd": 0,
                    "maxAgents": 1,
                    "maxSpawnDepth": 1,
                    "maxToolCalls": 2,
                    "maxModelCalls": 0,
                    "maxModelTokens": 0,
                },
            },
        }
    )


def _grant_lineage(
    *,
    campaign: CampaignManifest | None = None,
    at: datetime = NOW,
) -> tuple[CapabilityLedger, CapabilityGrant, CapabilityGrant]:
    selected_campaign = campaign or _campaign(at=at)
    ledger = CapabilityLedger(max_depth=1, clock=lambda: at - timedelta(minutes=5))
    root = ledger.issue_root(
        selected_campaign,
        subject="agent:web-assessment-root",
        tools={WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
        targets={ORIGIN},
    )
    source = ledger.delegate(
        root.grant_id,
        subject="agent:web-assessment",
        tools={WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
        targets={ORIGIN},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=at + timedelta(minutes=5),
    )
    validation = ledger.delegate(
        root.grant_id,
        subject="agent:web-assessment-validation",
        tools={WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
        targets={ORIGIN},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=1,
        expires_at=at + timedelta(minutes=5),
    )
    return ledger, source, validation


def _graph_store(path: Path | None = None) -> SQLiteGraphStore:
    return SQLiteGraphStore(
        path or Path(_TEST_GRANT_STORE_ROOT.name).resolve() / f"graph-{uuid4().hex}.sqlite3",
        campaign_id="web-governed",
    )


def _graph_snapshot(store: SQLiteGraphStore, *, at: datetime = NOW) -> GraphSnapshotRef:
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    snapshot = GraphSnapshotAuthority(
        creator_id="pajin.web.test.snapshot-authority",
        creator_digest=_digest("snapshot-authority"),
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: at - timedelta(minutes=3),
    ).capture(GraphSnapshotReason.CHECKPOINT)
    return graph_snapshot_ref(snapshot)


def _reconstructed_ledger(
    root: CapabilityGrant,
    source: CapabilityGrant,
    validation: CapabilityGrant,
) -> CapabilityLedger:
    ledger = CapabilityLedger(max_depth=1, clock=lambda: NOW - timedelta(minutes=5))
    for grant in (root, source, validation):
        CapabilityLedger._store_grant(ledger, grant)
    return ledger


def _grant(
    tool: WebAuthenticatedAssessmentTool,
    request: ToolRequest,
    *,
    role: Literal["source", "validation"],
) -> CapabilityGrant:
    grant = tool.dispatch_bindings.authorized_grant(role)
    assert grant.subject == request.agent_id
    assert request.tool_id in grant.tools
    assert request.target in grant.targets
    return grant


def _worker_result(execution_id: str) -> WorkerResult:
    return WorkerResult(
        execution_id=execution_id,
        backend="host-loopback-browser",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        stdout="{}",
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
    )


def _signed_approval_leg(
    role: Literal["source", "validation"],
    key: WebAssessmentVerificationKey,
    *,
    private_key_label: str | None = None,
    campaign_digest: str | None = None,
    request_id: str | None = None,
    request_digest: str | None = None,
    normalized_parameters_digest: str | None = None,
    target_digest: str | None = None,
    snapshot: GraphSnapshotRef | None = None,
    at: datetime = NOW,
) -> tuple[
    MissionEnvelope,
    ActionProposal,
    GraphDecision,
    ActionApprovalEnvelope,
    SignedWebActionApproval,
]:
    tool, _manifest_value, _receipt_value = _tool()
    capability = registered_action_capability(
        registered_web_authenticated_assessment_capability_definition(tool)
    )
    campaign_id = "web-governed"
    snapshot_digest = _digest(f"snapshot:{role}")
    resolved_snapshot = snapshot or GraphSnapshotRef(
        snapshotId=f"graph-snapshot_{snapshot_digest}",
        snapshotDigest=snapshot_digest,
        campaignId=campaign_id,
        revision=1,
        eventLogHeadDigest=_digest(f"event-log:{role}"),
        projectionDigest=_digest(f"projection:{role}"),
    )
    decision = GraphDecision(
        campaignId=campaign_id,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=_digest(f"source-intent:{role}"),
        snapshot=resolved_snapshot,
        actorId=f"pajin.web.{role}.planner",
        actorDigest=_digest(f"planner:{role}"),
        createdAt=at - timedelta(minutes=2),
    )
    resolved_target_digest = target_digest or _digest(f"target:{role}")
    resolved_request_id = request_id or f"tool_web_authenticated_{role}"
    resolved_request_digest = request_digest or _digest(f"request:{role}")
    resolved_parameters_digest = normalized_parameters_digest or _digest(f"parameters:{role}")
    resolved_campaign_digest = campaign_digest or _digest("campaign")
    envelope = MissionEnvelope(
        campaignId=campaign_id,
        runId="run:web-governed",
        profileId="range-web-assessment",
        profileVersion="1.0.0",
        profileDigest=_digest("profile"),
        compilerId="pajin.web-assessment.compiler",
        compilerVersion="1.0.0",
        compilerDigest=_digest("compiler"),
        sourceCampaignDigest=resolved_campaign_digest,
        allowedCapabilities=(capability.reference(),),
        allowedTargetDigests=(resolved_target_digest,),
        maxRiskTier=ToolRiskTier.T2,
        budget=ActionBudgetLimit(
            toolCallLimit=2,
            requestUnitLimit=2 * WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
            costLimitMicrousd=0,
        ),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=at - timedelta(minutes=10),
        notBefore=at - timedelta(minutes=10),
        expiresAt=at + timedelta(minutes=10),
    )
    reservation = ActionBudgetReservation(
        requestUnits=WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS,
        costMicrousd=0,
    )
    proposal = ActionProposal(
        campaignId=campaign_id,
        runId=envelope.run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=resolved_snapshot,
        proposerId=f"pajin.web.{role}.planner",
        proposerDigest=_digest(f"planner:{role}"),
        capability=capability.reference(),
        targetDigest=resolved_target_digest,
        requestId=resolved_request_id,
        requestDigest=resolved_request_digest,
        normalizedParametersDigest=resolved_parameters_digest,
        riskTier=ToolRiskTier.T2,
        reservation=reservation,
        createdAt=at - timedelta(minutes=1),
    )
    release_digest = _digest("release")
    approved_at = at - timedelta(seconds=30)
    approval = ActionApprovalEnvelope(
        issuer=web_action_approval_issuer_binding(key, role=role),
        requestedBy="principal.web-planner",
        approvedBy=key.principal_id,
        campaignId=campaign_id,
        campaignDigest=envelope.source_campaign_digest,
        runId=envelope.run_id,
        missionEnvelope=envelope,
        sourceIntentDigest=decision.decision_payload_digest,
        activationSetDigest=_digest("activation-set"),
        release=ActionApprovalReleaseRef(
            releaseId=f"capability-release_{release_digest}",
            releaseDigest=release_digest,
            capabilityId=capability.capability_id,
            capabilityVersion=capability.capability_version,
            capabilityDigest=capability.definition_digest,
        ),
        graphDecision=decision,
        proposal=proposal,
        expectedActionPermitId=action_permit_attempt_id(envelope, proposal, decision),
        sideEffectClass="read-only",
        cleanupRequired=False,
        reservation=reservation,
        approvedAt=approved_at,
        notBefore=approved_at + timedelta(seconds=1),
        expiresAt=at + timedelta(minutes=2),
    )
    signed = sign_web_action_approval(
        approval,
        role=role,
        key=key,
        private_key=_seed(private_key_label or f"approval-{role}"),
    )
    return envelope, proposal, decision, approval, signed


def _approved_authority(
    tool: WebAuthenticatedAssessmentTool,
    store: SQLiteGraphStore,
    key: WebAssessmentVerificationKey,
    leg: tuple[
        MissionEnvelope,
        ActionProposal,
        GraphDecision,
        ActionApprovalEnvelope,
        SignedWebActionApproval,
    ],
    *,
    at: datetime = NOW,
) -> GraphApprovedActionPermitAuthority:
    envelope, _proposal, _decision, _approval, signed = leg
    capability = registered_action_capability(
        registered_web_authenticated_assessment_capability_definition(tool)
    )
    input_authority = WebActionApprovalInputAuthority(
        role=signed.role,
        key=key,
        signed=signed,
        clock=lambda: at,
    )
    return GraphApprovedActionPermitAuthority(
        campaign_id="web-governed",
        compiler_id=envelope.compiler_id,
        compiler_version=envelope.compiler_version,
        compiler_digest=envelope.compiler_digest,
        capabilities=ActionCapabilityRegistry((capability,)),
        policies=ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=capability.reference(),
                    sideEffectClass="read-only",
                    approvalRequired=True,
                    cleanupRequired=False,
                ),
            )
        ),
        permit_store=store.permit_store,
        input_authority=input_authority,
        clock=lambda: at,
        permit_ttl=timedelta(seconds=30),
    )


def _approved_dispatcher(
    tool: WebAuthenticatedAssessmentTool,
    store: SQLiteGraphStore,
    key: WebAssessmentVerificationKey,
    leg: tuple[
        MissionEnvelope,
        ActionProposal,
        GraphDecision,
        ActionApprovalEnvelope,
        SignedWebActionApproval,
    ],
    *,
    at: datetime = NOW,
) -> GraphApprovedActionPermitDispatcher:
    return GraphApprovedActionPermitDispatcher(_approved_authority(tool, store, key, leg, at=at))


def _registered_tools(tool: WebAuthenticatedAssessmentTool) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(tool)
    return registry


async def _dispatch_leg[DispatchResultT](
    *,
    tool: WebAuthenticatedAssessmentTool,
    leg: tuple[
        MissionEnvelope,
        ActionProposal,
        GraphDecision,
        ActionApprovalEnvelope,
        SignedWebActionApproval,
    ],
    campaign: CampaignManifest,
    grant: CapabilityGrant,
    request: ToolRequest,
    dispatch: Callable[[WebAssessmentDispatchBinding], Awaitable[DispatchResultT]],
) -> ApprovedActionDispatchResult[DispatchResultT]:
    return await tool.dispatch_approved_once(
        envelope=leg[0],
        proposal=leg[1],
        decision=leg[2],
        approval=leg[3],
        campaign=campaign,
        grant=grant,
        request=request,
        worker_execution_id="exec_web_source",
        target_observer_execution_id="exec_web_source_observer",
        output_root_reference="web-output:source",
        worker_signing_material_ref="secret:web-source-signing-key",
        target_observer_signing_material_ref="secret:web-source-observer-key",
        dispatch=dispatch,
    )


def test_signed_registries_bind_exact_origin_code_and_secret_free_receipt() -> None:
    manifest = _manifest()
    adapters = _adapter_registry(manifest)
    receipt = _receipt(manifest)
    receipts = _receipt_registry(receipt)

    assert adapters.resolve(manifest.reference()) == manifest
    assert receipts.resolve(receipt.reference()) == receipt
    serialized = receipt.model_dump_json(by_alias=True)
    assert "account-name@example" not in serialized
    assert "password" not in serialized.lower()
    assert receipt.material_values_included is False
    assert receipt.account_creation_authorized is False


@pytest.mark.parametrize(
    "changes",
    (
        {"authenticationState": "server-stateful"},
        {"recipeSideEffect": "reversible-write"},
        {"recipeSideEffect": "irreversible-write"},
        {"targetMutationAllowed": True},
        {"accountCreationAllowed": True},
        {"callerAuthoredRoutesAllowed": True},
        {"callerAuthoredPayloadsAllowed": True},
    ),
)
def test_adapter_registry_fails_closed_for_stateful_or_mutating_recipe(
    changes: dict[str, object],
) -> None:
    with pytest.raises(GovernedWebAssessmentModelError, match="stateful or mutating"):
        _adapter_registry(_manifest(**changes))


def test_adapter_registry_rejects_unknown_code_and_signature_tampering() -> None:
    with pytest.raises(GovernedWebAssessmentModelError, match="not code-owned"):
        _adapter_registry(
            _manifest(
                implementationId="pajin.web-assessment.caller-code.v1",
                implementationDigest="9" * 64,
            )
        )

    key = _verification_key("adapter", WebAssessmentSigningRole.ADAPTER_PUBLISHER)
    signed = sign_web_assessment_adapter(
        _manifest(), key_id=key.key_id, private_key=_seed("adapter")
    )
    raw = signed.model_dump(mode="json", by_alias=True)
    raw["signatureBase64url"] = "A" * 86
    with pytest.raises(GovernedWebAssessmentModelError, match="signature verification"):
        WebAssessmentAdapterRegistry(
            keys=(key,),
            adapters=(type(signed).model_validate(raw),),
            clock=lambda: NOW,
        )


def test_signed_adapter_and_account_require_live_keys_covering_artifact_expiry() -> None:
    manifest = _manifest()
    adapter_key = _verification_key(
        "adapter",
        WebAssessmentSigningRole.ADAPTER_PUBLISHER,
    )
    retired_adapter_key = adapter_key.model_copy(
        update={"state": WebAssessmentSigningKeyState.RETIRED}
    )
    retired_adapter = sign_web_assessment_adapter(
        manifest,
        key_id=retired_adapter_key.key_id,
        private_key=_seed("adapter"),
    )
    with pytest.raises(GovernedWebAssessmentModelError, match="key is not trusted"):
        WebAssessmentAdapterRegistry(
            keys=(retired_adapter_key,),
            adapters=(retired_adapter,),
            clock=lambda: NOW,
        )

    short_adapter_key = adapter_key.model_copy(update={"not_after": NOW + timedelta(minutes=30)})
    short_adapter = sign_web_assessment_adapter(
        manifest,
        key_id=short_adapter_key.key_id,
        private_key=_seed("adapter"),
    )
    with pytest.raises(GovernedWebAssessmentModelError, match="not current"):
        WebAssessmentAdapterRegistry(
            keys=(short_adapter_key,),
            adapters=(short_adapter,),
            clock=lambda: NOW,
        )

    receipt = _receipt(manifest)
    account_key = _verification_key("account", WebAssessmentSigningRole.ACCOUNT_ISSUER)
    short_account_key = account_key.model_copy(update={"not_after": NOW + timedelta(minutes=5)})
    short_receipt = sign_provisioned_web_account_receipt(
        receipt,
        key_id=short_account_key.key_id,
        private_key=_seed("account"),
    )
    with pytest.raises(GovernedWebAssessmentModelError, match="not current"):
        ProvisionedWebAccountReceiptRegistry(
            keys=(short_account_key,),
            receipts=(short_receipt,),
            clock=lambda: NOW,
        )


def test_parameters_forbid_caller_routes_payloads_origins_and_material_values() -> None:
    _tool_value, manifest, receipt = _tool()
    expected = WebAuthenticatedAssessmentParameters(
        adapter=manifest.reference(),
        accountReceipt=receipt.reference(),
    ).model_dump(mode="json", by_alias=True)
    for field in ("origin", "routes", "selectors", "payload", "password", "credentials"):
        with pytest.raises(ValidationError):
            WebAuthenticatedAssessmentParameters.model_validate(
                {**expected, field: "caller-controlled"}
            )


def test_capability_is_t2_read_only_fresh_approval_and_all_seven_roles() -> None:
    tool, _manifest_value, _receipt_value = _tool()
    registry = ToolRegistry()
    registry.register(tool)
    bundle = web_authenticated_assessment_capability_bundle(registry)
    definition = bundle.definitions.definitions()[0]

    assert definition == registered_web_authenticated_assessment_capability_definition(tool)
    assert definition.capability_id == WEB_AUTHENTICATED_ASSESSMENT_CAPABILITY_ID
    assert definition.risk_tier is ToolRiskTier.T2
    assert definition.side_effect_class is CapabilitySideEffectClass.READ_ONLY
    assert definition.approval_required is True
    assert definition.cleanup_required is False
    assert definition.request_unit_cost == WEB_AUTHENTICATED_ASSESSMENT_REQUEST_UNITS
    assert [item.role.value for item in bundle.capability.authorities] == sorted(
        role.value for role in CapabilityAuthorityRole
    )
    assert "fresh-action-approval-required" in definition.preconditions
    assert "one-use-action-permit" in definition.preconditions


def test_signed_action_approval_verifies_fresh_exact_graph_authority() -> None:
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    envelope, proposal, decision, approval, signed = _signed_approval_leg("source", key)
    authority = WebActionApprovalInputAuthority(
        role="source",
        key=key,
        signed=signed,
        clock=lambda: NOW,
    )

    authority.verify_action_approval(envelope, proposal, decision, approval)

    assert approval.requested_by != approval.approved_by
    assert authority.stable_execution_context()["signedApprovalDigest"] == (
        approval.approval_digest
    )


def test_signed_action_approval_rejects_tamper_stale_and_wrong_public_key() -> None:
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    _envelope, _proposal, _decision, _approval, signed = _signed_approval_leg("source", key)
    raw = signed.model_dump(mode="json", by_alias=True)
    raw["signatureBase64url"] = "A" * 86
    tampered = SignedWebActionApproval.model_validate(raw)
    with pytest.raises(GovernedWebAssessmentModelError, match="signature verification"):
        WebActionApprovalInputAuthority(
            role="source",
            key=key,
            signed=tampered,
            clock=lambda: NOW,
        )

    with pytest.raises(GovernedWebAssessmentModelError, match="not current"):
        WebActionApprovalInputAuthority(
            role="source",
            key=key,
            signed=signed,
            clock=lambda: NOW + timedelta(minutes=3),
        )

    wrong_public_key = key.model_copy(
        update={
            "public_key_base64url": web_assessment_public_key_base64url(
                _seed("approval-source-wrong-public-key")
            )
        }
    )
    with pytest.raises(
        GovernedWebAssessmentModelError,
        match="fresh separated read-only approval",
    ):
        WebActionApprovalInputAuthority(
            role="source",
            key=wrong_public_key,
            signed=signed,
            clock=lambda: NOW,
        )


def test_composite_action_approval_authority_selects_two_distinct_signed_legs() -> None:
    source_key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    validation_key = _verification_key(
        "approval-validation", WebAssessmentSigningRole.ACTION_APPROVER
    )
    source = _signed_approval_leg("source", source_key)
    validation = _signed_approval_leg("validation", validation_key)
    authority = WebActionApprovalAuthoritySet(
        keys=(source_key, validation_key),
        approvals=(source[4], validation[4]),
        clock=lambda: NOW,
    )

    authority.verify_action_approval(*source[:4])
    authority.verify_action_approval(*validation[:4])

    assert source[3].approval_digest != validation[3].approval_digest
    assert authority.authority("source").key.key_id != (
        authority.authority("validation").key.key_id
    )
    assert set(authority.stable_execution_context()) == {
        "implementationVersion",
        "source",
        "validation",
    }


def test_composite_action_approval_authority_rejects_reused_action() -> None:
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    source = _signed_approval_leg("source", key)[4]
    reused = source.model_copy(update={"role": "validation"})

    with pytest.raises(GovernedWebAssessmentModelError, match="distinct actions"):
        WebActionApprovalAuthoritySet(
            keys=(key,),
            approvals=(source, reused),
            clock=lambda: NOW,
        )


def test_composite_action_approval_authority_rejects_same_signing_key() -> None:
    shared_key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    source = _signed_approval_leg("source", shared_key)[4]
    validation = _signed_approval_leg(
        "validation",
        shared_key,
        private_key_label="approval-source",
    )[4]

    with pytest.raises(GovernedWebAssessmentModelError, match="distinct key IDs"):
        WebActionApprovalAuthoritySet(
            keys=(shared_key,),
            approvals=(source, validation),
            clock=lambda: NOW,
        )


def test_composite_action_approval_authority_rejects_same_public_key() -> None:
    source_key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    validation_key = _verification_key(
        "approval-validation", WebAssessmentSigningRole.ACTION_APPROVER
    ).model_copy(update={"public_key_base64url": source_key.public_key_base64url})
    source = _signed_approval_leg("source", source_key)[4]
    validation = _signed_approval_leg(
        "validation",
        validation_key,
        private_key_label="approval-source",
    )[4]

    with pytest.raises(GovernedWebAssessmentModelError, match="public keys"):
        WebActionApprovalAuthoritySet(
            keys=(source_key, validation_key),
            approvals=(source, validation),
            clock=lambda: NOW,
        )


def test_composite_action_approval_authority_rejects_same_principal() -> None:
    source_key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    validation_key = _verification_key(
        "approval-validation", WebAssessmentSigningRole.ACTION_APPROVER
    ).model_copy(update={"principal_id": source_key.principal_id})
    source = _signed_approval_leg("source", source_key)[4]
    validation = _signed_approval_leg("validation", validation_key)[4]

    with pytest.raises(GovernedWebAssessmentModelError, match="principal IDs"):
        WebActionApprovalAuthoritySet(
            keys=(source_key, validation_key),
            approvals=(source, validation),
            clock=lambda: NOW,
        )


def test_live_action_approval_rejects_backdated_retired_or_expired_key() -> None:
    active_key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    retired_key = active_key.model_copy(update={"state": WebAssessmentSigningKeyState.RETIRED})
    retired_signed = _signed_approval_leg("source", retired_key)[4]
    with pytest.raises(GovernedWebAssessmentModelError, match="key is not active"):
        WebActionApprovalInputAuthority(
            role="source",
            key=retired_key,
            signed=retired_signed,
            clock=lambda: NOW,
        )

    expired_key = active_key.model_copy(update={"not_after": NOW - timedelta(seconds=1)})
    expired_signed = _signed_approval_leg("source", expired_key)[4]
    with pytest.raises(GovernedWebAssessmentModelError, match="current approval window"):
        WebActionApprovalInputAuthority(
            role="source",
            key=expired_key,
            signed=expired_signed,
            clock=lambda: NOW,
        )


@pytest.mark.asyncio
async def test_executor_consumes_one_live_dispatch_and_verifies_signed_output(
    tmp_path: Path,
) -> None:
    store = _graph_store(tmp_path / "graph.sqlite3")
    tool, manifest, receipt = _tool(store)
    registry = ToolRegistry()
    registry.register(tool)
    bundle = web_authenticated_assessment_capability_bundle(registry)
    request = _request(manifest, receipt)
    campaign = _campaign()
    grant = _grant(tool, request, role="source")
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=request.request_id,
        request_digest=capability_tool_request_digest(request),
        normalized_parameters_digest=capability_normalized_parameters_digest(request.arguments),
        target_digest=receipt.target_identity_digest,
        snapshot=_graph_snapshot(store),
    )
    tool.dispatch_bindings.install_dispatcher(_approved_dispatcher(tool, store, key, leg))
    assert tool.network_response_byte_limit(request) == 8_000_000
    reference = bundle.capability.reference()
    executor = bundle.authorities.authority(reference, CapabilityAuthorityRole.EXECUTOR_ADAPTER)
    normalizer = bundle.authorities.authority(reference, CapabilityAuthorityRole.RESULT_NORMALIZER)
    oracle = bundle.authorities.authority(reference, CapabilityAuthorityRole.SUCCESS_ORACLE)
    replay = bundle.authorities.authority(reference, CapabilityAuthorityRole.REPLAY_STRATEGY)
    cleanup = bundle.authorities.authority(reference, CapabilityAuthorityRole.CLEANUP_HANDLER)
    dispatch_calls = 0
    with pytest.raises(
        GovernedWebAssessmentModelError,
        match="unavailable or already consumed",
    ):
        executor.prepare(request)
    assert cast(_JobCompiler, tool.job_compiler).compile_calls == 0

    async def execute(
        binding: WebAssessmentDispatchBinding,
    ) -> WebAssessmentDispatchBinding:
        nonlocal dispatch_calls
        dispatch_calls += 1
        assert binding.role == "source"
        assert binding.expected_run_id == leg[0].run_id
        assert binding.capability_grant_id == grant.grant_id
        assert binding.capability_grant_digest == capability_grant_digest(grant)
        grant_receipt = tool.dispatch_bindings.capability_grant_consumption_receipt(grant.grant_id)
        assert grant_receipt is not None
        assert binding.capability_grant_consumption_receipt_id == grant_receipt.receipt_id
        assert binding.capability_grant_consumption_receipt_digest == grant_receipt.receipt_digest
        assert grant_receipt.permit_id == binding.permit_id
        assert grant_receipt.request_id == request.request_id
        authorization = store.permit_store.approved_authorization(
            binding.approval_id,
            binding.permit_id,
        )
        assert authorization is not None
        assert binding.approval_receipt_id == authorization.receipt.receipt_id
        assert binding.approval_receipt_digest == authorization.receipt.receipt_digest
        job = executor.prepare(request)
        assert job.execution_id == binding.worker_execution_id
        assert job.network is NetworkMode.NONE
        assert {item.binding for item in job.secret_requests} == {
            "account-name",
            "account-proof",
            "target-observer-signing-key",
            "worker-signing-key",
        }
        assert all(item.secret_ref not in job.stdin for item in job.secret_requests)
        with pytest.raises(
            GovernedWebAssessmentModelError,
            match="unavailable or already consumed",
        ):
            executor.prepare(request)

        worker_result = _worker_result(job.execution_id)
        result = normalizer.normalize(request, worker_result)
        assert result.success is True
        assert result.evidence == []
        assert result.data["workerOutput"] == _OutputVerifier().verify_output(
            request=request,
            dispatch=binding,
            worker_result=worker_result,
        ).model_dump(mode="json", by_alias=True)
        assert oracle.evaluate(request, result) is CapabilityOracleDecision.SUCCEEDED
        replay_plan = replay.plan_replay(request, result)
        assert replay_plan is not None
        assert replay_plan["executionAuthorized"] is False
        assert cleanup.plan_cleanup(request, result) is None
        tool.validate_trusted_execution(
            request,
            result,
            worker_result,
            network_log_trusted=False,
        )
        with pytest.raises(GovernedWebAssessmentModelError, match="was not prepared"):
            tool.validate_trusted_execution(
                request,
                result,
                worker_result,
                network_log_trusted=False,
            )
        return binding

    first = await tool.dispatch_approved_once(
        envelope=leg[0],
        proposal=leg[1],
        decision=leg[2],
        approval=leg[3],
        campaign=campaign,
        grant=grant,
        request=request,
        worker_execution_id="exec_web_source",
        target_observer_execution_id="exec_web_source_observer",
        output_root_reference="web-output:source",
        worker_signing_material_ref="secret:web-source-signing-key",
        target_observer_signing_material_ref="secret:web-source-observer-key",
        dispatch=execute,
    )
    retry = await tool.dispatch_approved_once(
        envelope=leg[0],
        proposal=leg[1],
        decision=leg[2],
        approval=leg[3],
        campaign=campaign,
        grant=grant,
        request=request,
        worker_execution_id="exec_web_source",
        target_observer_execution_id="exec_web_source_observer",
        output_root_reference="web-output:source",
        worker_signing_material_ref="secret:web-source-signing-key",
        target_observer_signing_material_ref="secret:web-source-observer-key",
        dispatch=execute,
    )

    assert first.dispatched is True
    assert isinstance(first.result, WebAssessmentDispatchBinding)
    assert first.result.approval_receipt_id != first.result.approval_id
    assert first.result.approval_receipt_digest != first.result.approval_digest
    tampered_binding = first.result.model_dump(mode="json", by_alias=True)
    tampered_binding["approvalReceiptDigest"] = "9" * 64
    with pytest.raises(ValidationError, match="binding digest differs"):
        WebAssessmentDispatchBinding.model_validate(tampered_binding)
    tampered_grant_receipt = first.result.model_dump(mode="json", by_alias=True)
    tampered_grant_receipt["capabilityGrantConsumptionReceiptDigest"] = "8" * 64
    with pytest.raises(ValidationError, match="binding digest differs"):
        WebAssessmentDispatchBinding.model_validate(tampered_grant_receipt)
    assert retry.dispatched is False
    assert retry.result is None
    assert dispatch_calls == 1
    assert (
        store.permit_store.approved_authorization(
            first.result.approval_id,
            first.result.permit_id,
        )
        is not None
    )
    assert cast(_JobCompiler, tool.job_compiler).compile_calls == 1


@pytest.mark.asyncio
async def test_structurally_valid_unissued_grant_fails_before_callback_or_worker(
    tmp_path: Path,
) -> None:
    store = _graph_store(tmp_path / "graph.sqlite3")
    tool, manifest, receipt = _tool(store)
    request = _request(manifest, receipt)
    campaign = _campaign()
    issued = _grant(tool, request, role="source")
    forged = CapabilityGrant.model_validate(
        {
            **issued.model_dump(mode="python"),
            "grant_id": "grant_web_structurally_valid_but_unissued",
        }
    )
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=request.request_id,
        request_digest=capability_tool_request_digest(request),
        normalized_parameters_digest=capability_normalized_parameters_digest(request.arguments),
        target_digest=receipt.target_identity_digest,
        snapshot=_graph_snapshot(store),
    )
    tool.dispatch_bindings.install_dispatcher(_approved_dispatcher(tool, store, key, leg))
    callback_calls = 0

    async def must_not_dispatch(_binding: WebAssessmentDispatchBinding) -> str:
        nonlocal callback_calls
        callback_calls += 1
        return "must-not-run"

    with pytest.raises(
        GovernedWebAssessmentModelError,
        match="differs from its ledger-issued execution role",
    ):
        await _dispatch_leg(
            tool=tool,
            leg=leg,
            campaign=campaign,
            grant=forged,
            request=request,
            dispatch=must_not_dispatch,
        )

    assert callback_calls == 0
    assert cast(_JobCompiler, tool.job_compiler).compile_calls == 0
    assert (
        store.permit_store.approved_authorization(
            leg[3].approval_id,
            leg[3].expected_action_permit_id,
        )
        is not None
    )
    assert tool.dispatch_bindings.capability_grant_consumption_receipt(issued.grant_id) is None


@pytest.mark.asyncio
async def test_durable_grant_receipt_blocks_recreated_registry_with_fresh_permit(
    tmp_path: Path,
) -> None:
    grant_store_path = tmp_path / "grant-consumptions.sqlite3"
    ledger, source_grant, validation_grant = _grant_lineage()
    first_graph_store = _graph_store(tmp_path / "first-graph.sqlite3")
    first_grant_store = WebAssessmentCapabilityGrantConsumptionStore(
        grant_store_path,
        campaign_id="web-governed",
    )
    first_authority = WebAssessmentDispatchAuthority.create(
        graph_store=first_graph_store,
        capability_ledger=ledger,
        grant_consumption_store=first_grant_store,
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    first_tool, manifest, receipt = _tool(
        first_graph_store,
        dispatch_authority=first_authority,
    )
    first_request = _request(manifest, receipt)
    campaign = _campaign()
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    first_leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=first_request.request_id,
        request_digest=capability_tool_request_digest(first_request),
        normalized_parameters_digest=capability_normalized_parameters_digest(
            first_request.arguments
        ),
        target_digest=receipt.target_identity_digest,
        snapshot=_graph_snapshot(first_graph_store),
    )
    first_tool.dispatch_bindings.install_dispatcher(
        _approved_dispatcher(first_tool, first_graph_store, key, first_leg)
    )

    async def record_first(binding: WebAssessmentDispatchBinding) -> str:
        return binding.capability_grant_consumption_receipt_id

    first = await _dispatch_leg(
        tool=first_tool,
        leg=first_leg,
        campaign=campaign,
        grant=source_grant,
        request=first_request,
        dispatch=record_first,
    )
    assert first.dispatched is True
    persisted = first_grant_store.receipt_for_grant(source_grant.grant_id)
    assert persisted is not None
    assert first.result == persisted.receipt_id
    assert not hasattr(first_grant_store, "record")

    with sqlite3.connect(grant_store_path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                UPDATE web_capability_grant_consumptions
                SET receipt_json = receipt_json
                WHERE capability_grant_id = ?
                """,
                (source_grant.grant_id,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                DELETE FROM web_capability_grant_consumptions
                WHERE capability_grant_id = ?
                """,
                (source_grant.grant_id,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                UPDATE web_capability_grant_reservations
                SET reservation_json = reservation_json
                WHERE capability_grant_id = ?
                """,
                (source_grant.grant_id,),
            )
        connection.rollback()
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                """
                DELETE FROM web_capability_grant_reservations
                WHERE capability_grant_id = ?
                """,
                (source_grant.grant_id,),
            )
        connection.rollback()

    assert source_grant.parent_grant_id is not None
    root_grant = ledger.record(source_grant.parent_grant_id).grant
    restarted_ledger = _reconstructed_ledger(
        root_grant,
        source_grant,
        validation_grant,
    )
    restarted_graph_store = _graph_store(tmp_path / "restarted-graph.sqlite3")
    reopened_grant_store = WebAssessmentCapabilityGrantConsumptionStore(
        grant_store_path,
        campaign_id="web-governed",
    )
    restarted_authority = WebAssessmentDispatchAuthority.create(
        graph_store=restarted_graph_store,
        capability_ledger=restarted_ledger,
        grant_consumption_store=reopened_grant_store,
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    restarted_tool, restarted_manifest, restarted_receipt = _tool(
        restarted_graph_store,
        dispatch_authority=restarted_authority,
    )
    restarted_request = _request(
        restarted_manifest,
        restarted_receipt,
        request_id="tool_web_authenticated_source_fresh_attempt",
    )
    restarted_leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=restarted_request.request_id,
        request_digest=capability_tool_request_digest(restarted_request),
        normalized_parameters_digest=capability_normalized_parameters_digest(
            restarted_request.arguments
        ),
        target_digest=restarted_receipt.target_identity_digest,
        snapshot=_graph_snapshot(restarted_graph_store),
    )
    restarted_tool.dispatch_bindings.install_dispatcher(
        _approved_dispatcher(
            restarted_tool,
            restarted_graph_store,
            key,
            restarted_leg,
        )
    )
    callback_calls = 0

    async def must_not_dispatch(_binding: WebAssessmentDispatchBinding) -> str:
        nonlocal callback_calls
        callback_calls += 1
        return "must-not-run"

    with pytest.raises(
        GovernedWebAssessmentModelError,
        match="revoked, exhausted, or already consumed",
    ):
        await _dispatch_leg(
            tool=restarted_tool,
            leg=restarted_leg,
            campaign=campaign,
            grant=source_grant,
            request=restarted_request,
            dispatch=must_not_dispatch,
        )

    assert callback_calls == 0
    assert cast(_JobCompiler, restarted_tool.job_compiler).compile_calls == 0
    assert (
        restarted_graph_store.permit_store.approved_authorization(
            restarted_leg[3].approval_id,
            restarted_leg[3].expected_action_permit_id,
        )
        is not None
    )
    assert reopened_grant_store.receipt_for_grant(source_grant.grant_id) == persisted


@pytest.mark.asyncio
@pytest.mark.parametrize("crash_phase", ("after-reservation", "after-ledger"))
async def test_incomplete_grant_reservation_blocks_replay_after_restart(
    crash_phase: str,
    tmp_path: Path,
) -> None:
    grant_store_path = tmp_path / f"grant-{crash_phase}.sqlite3"
    graph_store = _graph_store(tmp_path / f"graph-{crash_phase}.sqlite3")
    ledger, source_grant, validation_grant = _grant_lineage()
    assert source_grant.parent_grant_id is not None
    root_grant = ledger.record(source_grant.parent_grant_id).grant
    grant_store = WebAssessmentCapabilityGrantConsumptionStore(
        grant_store_path,
        campaign_id="web-governed",
    )
    authority = WebAssessmentDispatchAuthority.create(
        graph_store=graph_store,
        capability_ledger=ledger,
        grant_consumption_store=grant_store,
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    tool, manifest, receipt = _tool(graph_store, dispatch_authority=authority)
    request = _request(manifest, receipt)
    campaign = _campaign()
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=request.request_id,
        request_digest=capability_tool_request_digest(request),
        normalized_parameters_digest=capability_normalized_parameters_digest(request.arguments),
        target_digest=receipt.target_identity_digest,
        snapshot=_graph_snapshot(graph_store),
    )
    graph_authority = _approved_authority(tool, graph_store, key, leg)
    authorization = graph_authority.authorize_for_dispatch(*leg[:4])
    assert authorization.action.newly_consumed is True
    permit = authorization.action.permit
    approval_receipt = authorization.receipt
    reservation = WebAssessmentCapabilityGrantReservation(
        campaignId="web-governed",
        grantAuthorityDigest=authority._grant_authority_digest,
        capabilityGrantId=source_grant.grant_id,
        capabilityGrantDigest=capability_grant_digest(source_grant),
        requestId=request.request_id,
        requestDigest=capability_tool_request_digest(request),
        permitId=permit.permit_id,
        permitDigest=permit.permit_digest,
        approvalReceiptId=approval_receipt.receipt_id,
        approvalReceiptDigest=approval_receipt.receipt_digest,
        reservedAt=NOW,
    )
    WebAssessmentCapabilityGrantConsumptionStore._reserve_with_writer(
        grant_store,
        authority._grant_consumption_writer,
        reservation,
    )
    if crash_phase == "after-ledger":
        CapabilityLedger.consume(ledger, source_grant.grant_id)
    assert grant_store.reservation_for_grant(source_grant.grant_id) == reservation
    assert grant_store.receipt_for_grant(source_grant.grant_id) is None

    restarted_ledger = _reconstructed_ledger(
        root_grant,
        source_grant,
        validation_grant,
    )
    restarted_graph = _graph_store(tmp_path / f"restarted-graph-{crash_phase}.sqlite3")
    reopened_grant_store = WebAssessmentCapabilityGrantConsumptionStore(
        grant_store_path,
        campaign_id="web-governed",
    )
    restarted_authority = WebAssessmentDispatchAuthority.create(
        graph_store=restarted_graph,
        capability_ledger=restarted_ledger,
        grant_consumption_store=reopened_grant_store,
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    restarted_tool, restarted_manifest, restarted_receipt = _tool(
        restarted_graph,
        dispatch_authority=restarted_authority,
    )
    restarted_request = _request(
        restarted_manifest,
        restarted_receipt,
        request_id=f"tool_web_authenticated_source_{crash_phase}",
    )
    restarted_leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=restarted_request.request_id,
        request_digest=capability_tool_request_digest(restarted_request),
        normalized_parameters_digest=capability_normalized_parameters_digest(
            restarted_request.arguments
        ),
        target_digest=restarted_receipt.target_identity_digest,
        snapshot=_graph_snapshot(restarted_graph),
    )
    restarted_tool.dispatch_bindings.install_dispatcher(
        _approved_dispatcher(
            restarted_tool,
            restarted_graph,
            key,
            restarted_leg,
        )
    )
    callback_calls = 0

    async def must_not_dispatch(_binding: WebAssessmentDispatchBinding) -> str:
        nonlocal callback_calls
        callback_calls += 1
        return "must-not-run"

    with pytest.raises(
        GovernedWebAssessmentModelError,
        match="revoked, exhausted, or already consumed",
    ):
        await _dispatch_leg(
            tool=restarted_tool,
            leg=restarted_leg,
            campaign=campaign,
            grant=source_grant,
            request=restarted_request,
            dispatch=must_not_dispatch,
        )

    assert callback_calls == 0
    assert cast(_JobCompiler, restarted_tool.job_compiler).compile_calls == 0
    assert reopened_grant_store.reservation_for_grant(source_grant.grant_id) == reservation
    assert reopened_grant_store.receipt_for_grant(source_grant.grant_id) is None


def test_fake_approval_store_cannot_create_production_dispatch_authority(
    tmp_path: Path,
) -> None:
    fake_store = _AtomicApprovalStore()
    ledger, source_grant, validation_grant = _grant_lineage()
    grant_store = WebAssessmentCapabilityGrantConsumptionStore(
        tmp_path / "fake-store-grants.sqlite3",
        campaign_id="web-governed",
    )
    compiler = _JobCompiler()

    with pytest.raises(TypeError, match="exact SQLite Graph store"):
        WebAssessmentDispatchAuthority.create(
            graph_store=cast(SQLiteGraphStore, fake_store),
            capability_ledger=ledger,
            grant_consumption_store=grant_store,
            source_grant=source_grant,
            validation_grant=validation_grant,
        )

    assert fake_store.authorize_calls == 0
    assert compiler.compile_calls == 0
    assert grant_store.reservation_for_grant(source_grant.grant_id) is None
    assert grant_store.receipt_for_grant(source_grant.grant_id) is None


@pytest.mark.asyncio
async def test_backdated_graph_clock_cannot_revive_expired_web_authority(
    tmp_path: Path,
) -> None:
    backdated = NOW - timedelta(hours=2)
    expired_campaign = _campaign(at=backdated)
    ledger, source_grant, validation_grant = _grant_lineage(
        campaign=expired_campaign,
        at=backdated,
    )
    graph_store = _graph_store(tmp_path / "expired-graph.sqlite3")
    grant_store = WebAssessmentCapabilityGrantConsumptionStore(
        tmp_path / "expired-grants.sqlite3",
        campaign_id="web-governed",
    )
    authority = WebAssessmentDispatchAuthority.create(
        graph_store=graph_store,
        capability_ledger=ledger,
        grant_consumption_store=grant_store,
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    tool, manifest, receipt = _tool(graph_store, dispatch_authority=authority)
    request = _request(manifest, receipt)
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(expired_campaign),
        request_id=request.request_id,
        request_digest=capability_tool_request_digest(request),
        normalized_parameters_digest=capability_normalized_parameters_digest(request.arguments),
        target_digest=receipt.target_identity_digest,
        snapshot=_graph_snapshot(graph_store, at=backdated),
        at=backdated,
    )
    tool.dispatch_bindings.install_dispatcher(
        _approved_dispatcher(tool, graph_store, key, leg, at=backdated)
    )
    callback_calls = 0

    async def must_not_dispatch(_binding: WebAssessmentDispatchBinding) -> str:
        nonlocal callback_calls
        callback_calls += 1
        return "must-not-run"

    with pytest.raises(
        GovernedWebAssessmentModelError,
        match="Campaign or capability Grant is not active",
    ):
        await _dispatch_leg(
            tool=tool,
            leg=leg,
            campaign=expired_campaign,
            grant=source_grant,
            request=request,
            dispatch=must_not_dispatch,
        )

    assert callback_calls == 0
    assert cast(_JobCompiler, tool.job_compiler).compile_calls == 0
    assert (
        graph_store.permit_store.approved_authorization(
            leg[3].approval_id,
            leg[3].expected_action_permit_id,
        )
        is not None
    )
    assert grant_store.reservation_for_grant(source_grant.grant_id) is None
    assert grant_store.receipt_for_grant(source_grant.grant_id) is None


@pytest.mark.asyncio
async def test_terminal_models_cannot_rebind_after_registry_recreation(
    tmp_path: Path,
) -> None:
    store = _graph_store(tmp_path / "graph.sqlite3")
    tool, manifest, receipt = _tool(store)
    request = _request(manifest, receipt)
    campaign = _campaign()
    grant = _grant(tool, request, role="source")
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=request.request_id,
        request_digest=capability_tool_request_digest(request),
        normalized_parameters_digest=capability_normalized_parameters_digest(request.arguments),
        target_digest=receipt.target_identity_digest,
        snapshot=_graph_snapshot(store),
    )
    tool.dispatch_bindings.install_dispatcher(_approved_dispatcher(tool, store, key, leg))
    bundle = web_authenticated_assessment_capability_bundle(_registered_tools(tool))
    executor = bundle.authorities.authority(
        bundle.capability.reference(),
        CapabilityAuthorityRole.EXECUTOR_ADAPTER,
    )

    async def first_dispatch(_binding: WebAssessmentDispatchBinding) -> str:
        executor.prepare(request)
        return "first"

    first = await _dispatch_leg(
        tool=tool,
        leg=leg,
        campaign=campaign,
        grant=grant,
        request=request,
        dispatch=first_dispatch,
    )
    assert first.dispatched is True
    authorization = store.permit_store.approved_authorization(
        leg[3].approval_id,
        leg[3].expected_action_permit_id,
    )
    assert authorization is not None
    terminal_permit = authorization.action.permit.model_copy(deep=True)
    terminal_receipt = authorization.receipt.model_copy(deep=True)

    restarted_store = SQLiteGraphStore(
        store.path,
        campaign_id="web-governed",
        initialize=False,
    )
    restarted_tool, restarted_manifest, restarted_receipt = _tool(restarted_store)
    restarted_request = _request(restarted_manifest, restarted_receipt)
    restarted_tool.dispatch_bindings.install_dispatcher(
        _approved_dispatcher(restarted_tool, restarted_store, key, leg)
    )
    restarted_compiler = cast(_JobCompiler, restarted_tool.job_compiler)
    callback_calls = 0

    async def must_not_dispatch(_binding: WebAssessmentDispatchBinding) -> str:
        nonlocal callback_calls
        callback_calls += 1
        return "replayed"

    retry = await _dispatch_leg(
        tool=restarted_tool,
        leg=leg,
        campaign=campaign,
        grant=grant,
        request=restarted_request,
        dispatch=must_not_dispatch,
    )

    assert retry.dispatched is False
    assert callback_calls == 0
    assert restarted_compiler.compile_calls == 0
    restarted_authorization = restarted_store.permit_store.approved_authorization(
        leg[3].approval_id,
        leg[3].expected_action_permit_id,
    )
    assert restarted_authorization is not None
    assert restarted_authorization.action.permit == terminal_permit
    assert restarted_authorization.receipt == terminal_receipt
    assert not hasattr(restarted_tool, "bind_dispatch")
    assert not hasattr(restarted_tool, "bind_approved_dispatch")


@pytest.mark.asyncio
async def test_dispatcher_subclass_cannot_mint_a_live_claim(tmp_path: Path) -> None:
    store = _graph_store(tmp_path / "graph.sqlite3")
    tool, manifest, receipt = _tool(store)
    request = _request(manifest, receipt)
    campaign = _campaign()
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=request.request_id,
        request_digest=capability_tool_request_digest(request),
        normalized_parameters_digest=capability_normalized_parameters_digest(request.arguments),
        target_digest=receipt.target_identity_digest,
    )

    class EvilDispatcher(GraphApprovedActionPermitDispatcher):
        pass

    evil = EvilDispatcher(_approved_authority(tool, store, key, leg))
    with pytest.raises(
        GovernedWebAssessmentModelError,
        match="exact Graph authority and durable store identity",
    ):
        tool.dispatch_bindings.install_dispatcher(evil)

    assert cast(_JobCompiler, tool.job_compiler).compile_calls == 0
    assert (
        store.permit_store.approved_authorization(
            leg[3].approval_id,
            leg[3].expected_action_permit_id,
        )
        is None
    )


def test_dispatch_registry_rejects_authority_subclass_and_identity_replacement(
    tmp_path: Path,
) -> None:
    store = _graph_store(tmp_path / "graph.sqlite3")

    class EvilAuthority(WebAssessmentDispatchAuthority):
        pass

    evil_ledger, evil_source, evil_validation = _grant_lineage()
    with pytest.raises(TypeError, match="cannot construct subclasses"):
        EvilAuthority.create(
            graph_store=store,
            capability_ledger=evil_ledger,
            grant_consumption_store=WebAssessmentCapabilityGrantConsumptionStore(
                tmp_path / "evil-grants.sqlite3",
                campaign_id="web-governed",
            ),
            source_grant=evil_source,
            validation_grant=evil_validation,
        )

    ledger, source_grant, validation_grant = _grant_lineage()
    authority = WebAssessmentDispatchAuthority.create(
        graph_store=store,
        capability_ledger=ledger,
        grant_consumption_store=WebAssessmentCapabilityGrantConsumptionStore(
            tmp_path / "exact-grants.sqlite3",
            campaign_id="web-governed",
        ),
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    tool, _manifest_value, _receipt_value = _tool(
        store,
        dispatch_authority=authority,
    )
    with pytest.raises(AttributeError, match="immutable"):
        _adversarial_setattr(tool.dispatch_bindings, "_authority", object())
    with pytest.raises(AttributeError):
        _adversarial_setattr(
            tool.dispatch_bindings,
            "_approved_dispatcher",
            object(),
        )
    with pytest.raises(AttributeError, match="immutable"):
        _adversarial_setattr(authority, "_sealed", False)
    with pytest.raises(AttributeError, match="immutable"):
        _adversarial_setattr(authority, "_capability_ledger", CapabilityLedger(max_depth=1))
    grant_store = authority._grant_consumption_store
    with pytest.raises(AttributeError, match="immutable"):
        _adversarial_setattr(grant_store, "_sealed", False)
    with pytest.raises(AttributeError, match="immutable"):
        _adversarial_setattr(grant_store, "_campaign_id", "other-campaign")
    assert cast(_JobCompiler, tool.job_compiler).compile_calls == 0
    assert store.permit_store.permits() == ()


@pytest.mark.parametrize(
    "mutation",
    ("ledger-records", "ledger-clock", "grant-material", "graph-permit-store"),
)
def test_dispatch_authority_rejects_runtime_identity_substitution(
    mutation: str,
    tmp_path: Path,
) -> None:
    graph_store = _graph_store(tmp_path / f"graph-{mutation}.sqlite3")
    ledger, source_grant, validation_grant = _grant_lineage()
    grant_store = WebAssessmentCapabilityGrantConsumptionStore(
        tmp_path / f"grant-{mutation}.sqlite3",
        campaign_id="web-governed",
    )
    authority = WebAssessmentDispatchAuthority.create(
        graph_store=graph_store,
        capability_ledger=ledger,
        grant_consumption_store=grant_store,
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    tool, _manifest_value, _receipt_value = _tool(
        graph_store,
        dispatch_authority=authority,
    )

    if mutation == "ledger-records":
        ledger._records = dict(ledger._records)
    elif mutation == "ledger-clock":
        ledger._clock = lambda: NOW - timedelta(days=1)
    elif mutation == "grant-material":
        ledger._records[source_grant.grant_id].grant = source_grant.model_copy(
            update={"subject": "agent:substituted"}
        )
    else:
        foreign_graph = _graph_store(tmp_path / "foreign-graph.sqlite3")
        graph_store.permit_store = foreign_graph.permit_store

    with pytest.raises(GovernedWebAssessmentModelError, match=r"changed|differs"):
        tool.dispatch_bindings.authorized_grant("source")

    assert cast(_JobCompiler, tool.job_compiler).compile_calls == 0
    assert grant_store.reservation_for_grant(source_grant.grant_id) is None
    assert grant_store.receipt_for_grant(source_grant.grant_id) is None


@pytest.mark.asyncio
@pytest.mark.parametrize("shadow", ("authority", "approved-dispatcher"))
async def test_instance_method_shadow_fails_before_graph_or_worker(
    shadow: str,
    tmp_path: Path,
) -> None:
    store = _graph_store(tmp_path / f"graph-{shadow}.sqlite3")
    ledger, source_grant, validation_grant = _grant_lineage()
    authority = WebAssessmentDispatchAuthority.create(
        graph_store=store,
        capability_ledger=ledger,
        grant_consumption_store=WebAssessmentCapabilityGrantConsumptionStore(
            tmp_path / f"shadow-{shadow}.sqlite3",
            campaign_id="web-governed",
        ),
        source_grant=source_grant,
        validation_grant=validation_grant,
    )
    tool, manifest, receipt = _tool(store, dispatch_authority=authority)
    request = _request(manifest, receipt)
    campaign = _campaign()
    grant = _grant(tool, request, role="source")
    key = _verification_key("approval-source", WebAssessmentSigningRole.ACTION_APPROVER)
    leg = _signed_approval_leg(
        "source",
        key,
        campaign_digest=campaign_manifest_digest(campaign),
        request_id=request.request_id,
        request_digest=capability_tool_request_digest(request),
        normalized_parameters_digest=capability_normalized_parameters_digest(request.arguments),
        target_digest=receipt.target_identity_digest,
    )
    tool.dispatch_bindings.install_dispatcher(_approved_dispatcher(tool, store, key, leg))
    if shadow == "authority":
        _adversarial_setattr(authority, "authorize_binding", lambda **_kwargs: None)
    else:
        approved_dispatcher = cast(
            WebAssessmentApprovedActionDispatcher,
            object.__getattribute__(
                tool.dispatch_bindings,
                "_WebAssessmentDispatchBindingRegistry__approved_dispatcher",
            ),
        )
        _adversarial_setattr(
            approved_dispatcher,
            "dispatch_once",
            lambda **_kwargs: None,
        )
    callback_calls = 0

    async def must_not_dispatch(_binding: WebAssessmentDispatchBinding) -> str:
        nonlocal callback_calls
        callback_calls += 1
        return "must-not-run"

    with pytest.raises(
        GovernedWebAssessmentModelError,
        match="identity or implementation changed",
    ):
        await _dispatch_leg(
            tool=tool,
            leg=leg,
            campaign=campaign,
            grant=grant,
            request=request,
            dispatch=must_not_dispatch,
        )

    assert callback_calls == 0
    assert cast(_JobCompiler, tool.job_compiler).compile_calls == 0
    assert store.permit_store.permits() == ()


def _lifecycle_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"web.lifecycle.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=2),
        notAfter=NOW + timedelta(days=2),
    )


def _activation() -> tuple[
    WebAuthenticatedAssessmentCapabilityActivation,
    WebAuthenticatedAssessmentTool,
    WebAssessmentAdapterManifest,
    ProvisionedWebAccountReceipt,
]:
    tool, manifest, receipt = _tool()
    tools = ToolRegistry()
    tools.register(tool)
    bundle = web_authenticated_assessment_capability_bundle(tools)
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _lifecycle_key(
        "publisher",
        principal="web.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _lifecycle_key(
        "reviewer",
        principal="web.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=_seed("publisher"),
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=_seed("reviewer"),
    )
    review = CapabilityReviewStatement(
        capability=bundle.capability.reference(),
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"web-authenticated-assessment-review").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(minutes=10),
        expiresAt=NOW + timedelta(hours=1),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=bundle.capability.reference(),
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(signed_review.statement.review_digest,),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=NOW - timedelta(minutes=5),
    )
    release_bundle = CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(release_bundle,),
        clock=lambda: NOW,
    )
    return (
        activate_web_authenticated_assessment_capability(
            bundle=bundle,
            lifecycle=lifecycle,
            release=release_bundle.release.statement.reference(),
        ),
        tool,
        manifest,
        receipt,
    )


def test_formal_lifecycle_activation_resolves_range_and_prepares_references_only() -> None:
    activation, _tool_value, manifest, receipt = _activation()
    definition = activation.definition()
    request = _request(
        manifest,
        receipt,
        request_id="tool_web_activation",
    )
    prepared = activation.prepare_action(
        release=activation.activation_set.binding.release,
        request=request,
        parameters=request.arguments,
    )

    assert activation.action_registry().resolve(prepared.capability) == (
        activation.activation_set.binding.action_capability
    )
    assert prepared.request == request
    assert prepared.request_digest == capability_tool_request_digest(request)
    assert definition.cleanup_required is False


def test_wrong_target_and_unknown_refs_fail_before_dispatch() -> None:
    tool, manifest, receipt = _tool()
    request = _request(manifest, receipt, target="http://127.0.0.1:3001")
    with pytest.raises(ValueError, match="target, adapter, and account differ"):
        tool.validate_request(request)

    raw = receipt.reference().model_dump(mode="json", by_alias=True)
    raw["receiptDigest"] = "9" * 64
    unknown = WebAuthenticatedAssessmentParameters(
        adapter=manifest.reference(),
        accountReceipt=ProvisionedWebAccountReceiptRef.model_validate(raw),
    )
    with pytest.raises(ValueError, match="untrusted deployment material"):
        tool.validate_request(
            _request(manifest, receipt, arguments=unknown.model_dump(mode="json", by_alias=True))
        )


def test_worker_output_rejects_session_material_persistence_claim() -> None:
    with pytest.raises(ValidationError):
        WebAuthenticatedAssessmentWorkerOutput.model_validate(
            {
                "adapter": _manifest().reference(),
                "accountReceipt": _receipt(_manifest()).reference(),
                "dispatchBindingDigest": "1" * 64,
                "workerExecutionId": "exec_web_source",
                "origin": ORIGIN,
                "runId": "run_20260914T060000Z_deadbeef",
                "rootDigest": "2" * 64,
                "resultDigest": "3" * 64,
                "attestationDigest": "4" * 64,
                "workerAttestation": {"signed": True},
                "authenticated": True,
                "browserClosed": True,
                "targetMutated": False,
                "serverSessionMaterialPersisted": True,
            }
        )
