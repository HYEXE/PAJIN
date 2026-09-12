"""SYS-004 signed activation, operator approval, durable Permit and real Tool Gateway dispatch."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field, JsonValue

from pajin.capabilities.activation import capability_normalized_parameters_digest
from pajin.capabilities.adapters import registered_action_capability
from pajin.capabilities.authorities import CapabilityAuthorityRole
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleRegistry,
    CapabilityReleaseRef,
    CapabilityUseProfile,
)
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    campaign_manifest_digest,
)
from pajin.graph import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    ActionApprovalReleaseRef,
    ActionBudgetLimit,
    ActionBudgetReservation,
    ActionCapabilityRegistry,
    ActionPermit,
    ActionProposal,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
    GraphDecision,
    GraphDecisionKind,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    MissionEnvelope,
    SQLiteGraphStore,
    action_permit_attempt_id,
    graph_snapshot_ref,
)
from pajin.policy.engine import PolicyEngine
from pajin.runtime.safe_files import load_bounded_strict_json
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend
from pajin.system_aslr.capability import AslrBundle, aslr_capability_bundle
from pajin.system_aslr.models import SECRET_REF, TOOL_ID, AslrInput, digest
from pajin.system_aslr.tool import AslrReadTool
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import GatewayOutcome, ToolGateway, canonical_tool_request_digest

COMPILER_ID = "pajin.sys-004.compiler"
COMPILER_DIGEST = digest(
    {
        "compiler": COMPILER_ID,
        "version": 1,
        "input": "exact-current-scope-and-authenticated-agent",
        "approval": "separate-ed25519-operator",
        "calls": 1,
    }
)
APPROVAL_DOMAIN = b"pajin.sys-004.operator-approval/v1\x00"


class AslrGateway(ToolGateway):
    """Own the exact authenticated Tool, Docker/proxy images and one-use credential broker."""

    def __init__(self, tool: AslrReadTool, store: RunStore, credentials: str) -> None:
        if type(tool) is not AslrReadTool:
            raise TypeError("SYS-004 Gateway requires its exact Tool implementation")
        self.bound_tool = tool
        self.bound_run_id = store.run_id
        registry = ToolRegistry()
        registry.register(tool)
        broker = SecretBroker()
        broker.register(SECRET_REF, credentials)
        super().__init__(
            policy=PolicyEngine(),
            tools=registry,
            worker=DockerWorkerBackend(
                allowed_images={tool.deployment.image_id},
                egress_proxy_image=tool.deployment.proxy_image_id,
            ),
            store=store,
            secrets=broker,
        )


class SignedAslrApproval(StrictModel):
    approval: ActionApprovalEnvelope
    signature: str = Field(pattern=r"^[a-f0-9]{128}$")


def approval_message(approval: ActionApprovalEnvelope) -> bytes:
    return (
        APPROVAL_DOMAIN
        + json.dumps(
            approval.model_dump(mode="json", by_alias=True), sort_keys=True, separators=(",", ":")
        ).encode()
    )


def operator_binding(public_key: bytes) -> ActionApprovalIssuerAuthorityBinding:
    Ed25519PublicKey.from_public_bytes(public_key)
    return ActionApprovalIssuerAuthorityBinding(
        authorityId="pajin.sys-004.operator",
        authorityVersion="1.0.0",
        implementationType="pajin.system_aslr.runtime.AslrOperatorAuthority",
        contextDigest=digest({"publicKey": public_key.hex(), "domain": APPROVAL_DOMAIN.hex()}),
    )


@dataclass(frozen=True)
class AslrActivation:
    bundle: AslrBundle
    lifecycle: CapabilityLifecycleRegistry
    release: CapabilityReleaseRef

    def require_current(self, now: datetime) -> None:
        # Reconstruct from the registry's current public key/release material, so elapsed time,
        # revoked keys and code drift cannot be hidden by an earlier successful activation.
        policy, keys, releases = self.lifecycle.verification_material()
        registry = CapabilityLifecycleRegistry(
            definitions=self.bundle.definitions,
            authorities=self.bundle.authorities,
            policy=policy,
            trust_keys=keys,
            releases=releases,
            clock=lambda: now,
        )
        resolved = registry.resolve_for_use(self.release, CapabilityUseProfile.RANGE)
        if resolved.capability.reference() != self.bundle.reference:
            raise ValueError("System activation has a different complete code authority set")

    def require_tool(self, tool: AslrReadTool) -> None:
        if aslr_capability_bundle(tool).reference != self.bundle.reference:
            raise ValueError("System Tool differs from the activated code authority")

    @property
    def activation_digest(self) -> str:
        return digest(
            {
                "version": "pajin.sys-004.activation/v1",
                "release": self.release.model_dump(mode="json", by_alias=True),
                "capability": self.bundle.reference.model_dump(mode="json", by_alias=True),
            }
        )


@dataclass(frozen=True)
class AslrAction:
    request: ToolRequest
    envelope: MissionEnvelope
    decision: GraphDecision
    proposal: ActionProposal


def prepare_aslr_action(
    *,
    activation: AslrActivation,
    tool: AslrReadTool,
    value: AslrInput,
    campaign: CampaignManifest,
    grant: CapabilityGrant,
    graph: SQLiteGraphStore,
    store: RunStore,
    now: datetime | None = None,
) -> AslrAction:
    """Create reviewable unsigned intent; no agent is contacted and no Worker is selected."""
    now = now or datetime.now(UTC)
    activation.require_current(now)
    activation.require_tool(tool)
    manifest = activation.bundle.reference
    materializer = activation.bundle.authorities.authority(
        manifest, CapabilityAuthorityRole.MATERIALIZER
    )
    compiler = activation.bundle.authorities.authority(
        manifest, CapabilityAuthorityRole.ACTION_COMPILER
    )
    arguments = materializer.materialize(
        cast(dict[str, JsonValue], value.model_dump(mode="json", by_alias=True))
    )
    request = compiler.compile(
        ToolRequest(agent_id=grant.subject, tool_id=TOOL_ID, target=value.target), arguments
    )
    if (
        value.target not in campaign.spec.scope.allow
        or value.scope_authority not in campaign.spec.scope.allow
        or "CONNECT" not in campaign.spec.rules_of_engagement.allowed_methods
    ):
        raise ValueError("System execution requires an explicit exact Scope rule")
    decision = PolicyEngine().evaluate_tool_request(
        campaign, grant, request, tool.spec, used_calls=0, now=now
    )
    if not decision.allowed:
        raise ValueError("System execution Policy denied: " + decision.policy)
    store.write_json_create_only(
        "sys-004-plan-reservation.json",
        {
            "request": request.model_dump(mode="json"),
            "campaignDigest": campaign_manifest_digest(campaign),
            "grantDigest": digest(grant.model_dump(mode="json")),
        },
    )
    snapshot = GraphSnapshotAuthority(
        creator_id=COMPILER_ID,
        creator_digest=COMPILER_DIGEST,
        projection_store=graph.projection_store,
        snapshot_store=graph.snapshot_store,
        clock=lambda: now,
    ).capture(GraphSnapshotReason.CHECKPOINT)
    request_digest = canonical_tool_request_digest(request)
    graph_decision = GraphDecision(
        campaignId=campaign.metadata.name,
        decisionKind=GraphDecisionKind.ACTION_PROPOSAL,
        decisionPayloadDigest=request_digest,
        snapshot=graph_snapshot_ref(snapshot),
        actorId=COMPILER_ID,
        actorDigest=COMPILER_DIGEST,
        createdAt=now,
    )
    capability = registered_action_capability(activation.bundle.definition)
    envelope = MissionEnvelope(
        campaignId=campaign.metadata.name,
        runId=store.run_id,
        profileId="sys-004-authenticated-range",
        profileVersion="1.0.0",
        profileDigest=activation.activation_digest,
        compilerId=COMPILER_ID,
        compilerVersion="1.0.0",
        compilerDigest=COMPILER_DIGEST,
        sourceCampaignDigest=campaign_manifest_digest(campaign),
        allowedCapabilities=(capability.reference(),),
        allowedTargetDigests=(digest(request.target),),
        maxRiskTier=tool.spec.risk_tier,
        budget=ActionBudgetLimit(toolCallLimit=1, requestUnitLimit=1, costLimitMicrousd=0),
        autonomy=AutonomyLevel.SUPERVISED,
        authorizedAt=now,
        notBefore=now,
        expiresAt=min(campaign.spec.authorization.expires_at, now + timedelta(minutes=5)),
    )
    proposal = ActionProposal(
        campaignId=campaign.metadata.name,
        runId=store.run_id,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        decisionId=graph_decision.decision_id,
        decisionDigest=graph_decision.decision_digest,
        snapshot=graph_decision.snapshot,
        proposerId=COMPILER_ID,
        proposerDigest=COMPILER_DIGEST,
        capability=capability.reference(),
        targetDigest=digest(request.target),
        requestId=request.request_id,
        requestDigest=request_digest,
        normalizedParametersDigest=capability_normalized_parameters_digest(arguments),
        riskTier=tool.spec.risk_tier,
        reservation=ActionBudgetReservation(requestUnits=1, costMicrousd=0),
        createdAt=now,
    )
    return AslrAction(request, envelope, graph_decision, proposal)


def approval_for_review(
    action: AslrAction,
    activation: AslrActivation,
    *,
    public_key: bytes,
    approved_by: str,
    now: datetime | None = None,
) -> ActionApprovalEnvelope:
    """Return unsigned approval material; a separate operator signer must approve these bytes."""
    now = now or datetime.now(UTC)
    return ActionApprovalEnvelope(
        issuer=operator_binding(public_key),
        requestedBy=COMPILER_ID,
        approvedBy=approved_by,
        campaignId=action.envelope.campaign_id,
        campaignDigest=action.envelope.source_campaign_digest,
        runId=action.envelope.run_id,
        missionEnvelope=action.envelope,
        sourceIntentDigest=action.decision.decision_payload_digest,
        activationSetDigest=activation.activation_digest,
        release=ActionApprovalReleaseRef(
            releaseId=activation.release.release_id,
            releaseDigest=activation.release.release_digest,
            capabilityId=action.proposal.capability.capability_id,
            capabilityVersion=action.proposal.capability.capability_version,
            capabilityDigest=action.proposal.capability.definition_digest,
        ),
        graphDecision=action.decision,
        proposal=action.proposal,
        expectedActionPermitId=action_permit_attempt_id(
            action.envelope, action.proposal, action.decision
        ),
        sideEffectClass="read-only",
        reservation=action.proposal.reservation,
        approvedAt=now,
        notBefore=now,
        expiresAt=action.envelope.expires_at,
    )


class AslrOperatorAuthority:
    """Deployment-pinned operator key and current execution inputs, never Worker metadata."""

    def __init__(
        self,
        *,
        activation: AslrActivation,
        public_key: bytes,
        operator_id: str,
        signed: SignedAslrApproval,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        request: ToolRequest,
        tool: AslrReadTool,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.activation, self.public_key, self.operator_id = (
            activation,
            public_key,
            operator_id,
        )
        self.signed = SignedAslrApproval.model_validate_json(signed.model_dump_json())
        self.campaign = CampaignManifest.model_validate_json(campaign.model_dump_json())
        self.grant = CapabilityGrant.model_validate_json(grant.model_dump_json())
        self.request = ToolRequest.model_validate_json(request.model_dump_json())
        self.tool, self.clock = tool, clock or (lambda: datetime.now(UTC))

    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        now = self.clock()
        self.activation.require_current(now)
        self.activation.require_tool(self.tool)
        try:
            Ed25519PublicKey.from_public_bytes(self.public_key).verify(
                bytes.fromhex(self.signed.signature), approval_message(approval)
            )
        except InvalidSignature as exc:
            raise ValueError("System operator approval signature is invalid") from exc
        self.tool.validate_request(self.request)
        reference = registered_action_capability(self.activation.bundle.definition).reference()
        if (
            approval != self.signed.approval
            or approval.issuer != operator_binding(self.public_key)
            or approval.approved_by != self.operator_id
            or approval.requested_by != COMPILER_ID
            or approval.mission_envelope != envelope
            or approval.proposal != proposal
            or approval.graph_decision != decision
            or proposal.capability != reference
            or proposal.request_digest != canonical_tool_request_digest(self.request)
            or proposal.request_id != self.request.request_id
            or proposal.normalized_parameters_digest
            != capability_normalized_parameters_digest(self.request.arguments)
            or proposal.target_digest != digest(self.request.target)
            or proposal.reservation.request_units != 1
            or proposal.reservation.cost_microusd != 0
            or approval.campaign_digest != campaign_manifest_digest(self.campaign)
            or approval.activation_set_digest != self.activation.activation_digest
            or approval.release.release_id != self.activation.release.release_id
            or approval.release.release_digest != self.activation.release.release_digest
            or self.request.target not in self.campaign.spec.scope.allow
            or self.tool.deployment.value.scope_authority not in self.campaign.spec.scope.allow
            or "CONNECT" not in self.campaign.spec.rules_of_engagement.allowed_methods
            or not approval.not_before <= now < approval.expires_at
        ):
            raise ValueError("System operator approval differs from current exact execution inputs")
        policy = PolicyEngine().evaluate_tool_request(
            self.campaign,
            self.grant,
            self.request,
            self.tool.spec,
            used_calls=0,
            now=now,
        )
        if not policy.allowed:
            raise ValueError("System operator approval current Policy denied: " + policy.policy)


async def dispatch_aslr_action(
    *,
    action: AslrAction,
    authority: AslrOperatorAuthority,
    graph: SQLiteGraphStore,
    gateway: AslrGateway,
    store: RunStore,
) -> GatewayOutcome | None:
    """Durably consume exact approval/Permit before the Gateway contacts the agent."""
    if (
        type(gateway) is not AslrGateway
        or gateway.bound_tool is not authority.tool
        or gateway.bound_run_id != store.run_id
    ):
        raise ValueError("System Gateway differs from the activation Tool or Run")
    capability = registered_action_capability(authority.activation.bundle.definition)
    dispatcher = GraphApprovedActionPermitDispatcher(
        GraphApprovedActionPermitAuthority(
            campaign_id=authority.campaign.metadata.name,
            compiler_id=COMPILER_ID,
            compiler_version="1.0.0",
            compiler_digest=COMPILER_DIGEST,
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
            permit_store=graph.permit_store,
            input_authority=authority,
            clock=authority.clock,
        )
    )
    if action.request != authority.request or store.run_id != action.envelope.run_id:
        raise ValueError("System dispatch request or Run differs from the approved intent")
    reservation = load_bounded_strict_json(
        store.path / "sys-004-plan-reservation.json",
        max_bytes=32_768,
        label="SYS-004 single-action Run reservation",
    )
    if reservation != {
        "request": authority.request.model_dump(mode="json"),
        "campaignDigest": campaign_manifest_digest(authority.campaign),
        "grantDigest": digest(authority.grant.model_dump(mode="json")),
    }:
        raise ValueError("System Run is reserved for a different request, Campaign or grant")

    async def dispatch(
        permit: ActionPermit, receipt: ActionApprovalConsumptionReceipt
    ) -> GatewayOutcome:
        now = authority.clock()
        authority.verify_action_approval(
            action.envelope, action.proposal, action.decision, authority.signed.approval
        )
        if now >= permit.expires_at or permit.request_digest != canonical_tool_request_digest(
            authority.request
        ):
            raise ValueError("System consumed Permit expired or changed before Gateway dispatch")
        store.write_json_create_only(
            "authorization.json",
            {
                "campaign": authority.campaign.model_dump(mode="json", by_alias=True),
                "grant": authority.grant.model_dump(mode="json"),
                "request": authority.request.model_dump(mode="json"),
                "signedApproval": authority.signed.model_dump(mode="json", by_alias=True),
                "operatorPublicKey": authority.public_key.hex(),
                "operatorId": authority.operator_id,
                "permit": permit.model_dump(mode="json", by_alias=True),
                "approvalReceipt": receipt.model_dump(mode="json", by_alias=True),
            },
        )
        store.append_event("sys-004.permit-consumed", {"permitId": permit.permit_id})
        return await gateway.execute(
            authority.campaign, authority.grant, authority.request, used_calls=0
        )

    result = await dispatcher.dispatch_once(
        action.envelope, action.proposal, action.decision, authority.signed.approval, dispatch
    )
    return result.result if result.dispatched else None
