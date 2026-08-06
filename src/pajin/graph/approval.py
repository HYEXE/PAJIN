"""Single-action approval envelopes bound to the existing ActionPermit authority."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from inspect import iscoroutinefunction
from re import fullmatch
from typing import Annotated, Any, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import StrictModel, ToolRiskTier
from pajin.graph.authority import (
    ActionBudgetReservation,
    ActionCapabilityRef,
    ActionCapabilityRegistry,
    ActionDispatchResult,
    ActionPermit,
    ActionPermitAuthorization,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
    action_permit_attempt_id,
    validate_action_authority,
)
from pajin.graph.consistency import GraphDecision
from pajin.graph.models import canonical_graph_json, graph_digest

ACTION_APPROVAL_ENVELOPE_API_VERSION: Literal["pajin.dev/action-approval-envelope/v1alpha1"] = (
    "pajin.dev/action-approval-envelope/v1alpha1"
)
ACTION_APPROVAL_CONSUMPTION_RECEIPT_API_VERSION: Literal[
    "pajin.dev/action-approval-consumption-receipt/v1alpha1"
] = "pajin.dev/action-approval-consumption-receipt/v1alpha1"

_MAX_APPROVAL_BYTES = 1024 * 1024
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_CampaignIdentifier = Annotated[
    str,
    Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class ActionApprovalError(RuntimeError):
    """Raised when an approval cannot be bound to an ActionPermit safely."""


class ActionApprovalIssuerAuthorityBinding(StrictModel):
    """Content-addressed identity of the deployment/operator approval issuer."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    authority_id: _Identifier = Field(alias="authorityId")
    authority_version: _Identifier = Field(alias="authorityVersion")
    implementation_type: str = Field(alias="implementationType", min_length=1, max_length=500)
    context_digest: _Sha256 = Field(alias="contextDigest")
    authority_digest: str = Field(default="", alias="authorityDigest", max_length=64)

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authority_digest"},
        )
        digest = graph_digest(
            "pajin.action.approval-issuer-authority/v1",
            material,
            max_bytes=_MAX_APPROVAL_BYTES,
        )
        if self.authority_digest and self.authority_digest != digest:
            raise ValueError("Action approval issuer authority digest differs")
        object.__setattr__(self, "authority_digest", digest)
        return self


class ActionApprovalReleaseRef(StrictModel):
    """Graph-local exact release identity without a Graph-to-Capability import edge."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release_id: str = Field(
        alias="releaseId",
        pattern=r"^capability-release_[a-f0-9]{64}$",
    )
    release_digest: _Sha256 = Field(alias="releaseDigest")
    capability_id: _Identifier = Field(alias="capabilityId")
    capability_version: _Identifier = Field(alias="capabilityVersion")
    capability_digest: _Sha256 = Field(alias="capabilityDigest")

    @model_validator(mode="after")
    def require_content_addressed_release(self) -> Self:
        if self.release_id != f"capability-release_{self.release_digest}":
            raise ValueError("Action approval Capability release ID differs from its digest")
        return self


class ActionApprovalCapabilityPolicy(StrictModel):
    """Deployment-pinned approval semantics for one exact Graph Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability: ActionCapabilityRef
    side_effect_class: Literal[
        "none",
        "read-only",
        "reversible-write",
        "irreversible-write",
    ] = Field(alias="sideEffectClass")
    approval_required: bool = Field(alias="approvalRequired")
    cleanup_required: bool = Field(alias="cleanupRequired")


class ActionApprovalCapabilityPolicyRegistry:
    """Immutable exact policy registry supplied by the deployment trust boundary."""

    def __init__(self, policies: tuple[ActionApprovalCapabilityPolicy, ...]) -> None:
        records: dict[tuple[str, str, str], ActionApprovalCapabilityPolicy] = {}
        for policy in policies:
            canonical = ActionApprovalCapabilityPolicy.model_validate(
                policy.model_dump(mode="json", by_alias=True)
            )
            key = (
                canonical.capability.capability_id,
                canonical.capability.capability_version,
                canonical.capability.capability_digest,
            )
            if key in records:
                raise ValueError("Action approval policy registry contains a duplicate")
            records[key] = canonical
        self._records = records
        self._policies = tuple(records[key] for key in sorted(records))
        self._registry_digest = graph_digest(
            "pajin.action.approval-capability-policy-registry/v1",
            {
                "policies": [
                    policy.model_dump(mode="json", by_alias=True)
                    for policy in self._policies
                ]
            },
            max_bytes=_MAX_APPROVAL_BYTES,
        )

    @property
    def registry_digest(self) -> str:
        return self._registry_digest

    def policies(self) -> tuple[ActionApprovalCapabilityPolicy, ...]:
        """Return a detached canonical snapshot for deployment pinning."""

        return tuple(policy.model_copy(deep=True) for policy in self._policies)

    def resolve(self, capability: ActionCapabilityRef) -> ActionApprovalCapabilityPolicy:
        key = (
            capability.capability_id,
            capability.capability_version,
            capability.capability_digest,
        )
        try:
            policy = self._records[key]
        except KeyError as exc:
            raise ActionApprovalError(
                "Action approval Capability policy is not registered"
            ) from exc
        if policy.capability != capability:
            raise ActionApprovalError("Action approval Capability policy differs")
        return policy.model_copy(deep=True)


class ActionApprovalEnvelope(StrictModel):
    """One exact operator-approved action; it is not a bearer execution Permit."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-approval-envelope/v1alpha1"] = Field(
        default=ACTION_APPROVAL_ENVELOPE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ActionApprovalEnvelope"] = "ActionApprovalEnvelope"
    approval_id: str = Field(default="", alias="approvalId", max_length=80)
    approval_digest: str = Field(default="", alias="approvalDigest", max_length=64)
    mode: Literal["single"] = "single"
    max_actions: Literal[1] = Field(default=1, alias="maxActions")
    issuer: ActionApprovalIssuerAuthorityBinding
    requested_by: _Identifier = Field(alias="requestedBy")
    approved_by: _Identifier = Field(alias="approvedBy")
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    campaign_digest: _Sha256 = Field(alias="campaignDigest")
    run_id: _Identifier = Field(alias="runId")
    mission_envelope: MissionEnvelope = Field(alias="missionEnvelope")
    source_intent_digest: _Sha256 = Field(alias="sourceIntentDigest")
    activation_set_digest: _Sha256 = Field(alias="activationSetDigest")
    release: ActionApprovalReleaseRef
    graph_decision: GraphDecision = Field(alias="graphDecision")
    proposal: ActionProposal
    expected_action_permit_id: str = Field(
        alias="expectedActionPermitId",
        pattern=r"^action-permit_[a-f0-9]{64}$",
    )
    side_effect_class: Literal["none", "read-only"] = Field(alias="sideEffectClass")
    cleanup_required: Literal[False] = Field(default=False, alias="cleanupRequired")
    reservation: ActionBudgetReservation
    approved_at: datetime = Field(alias="approvedAt")
    not_before: datetime = Field(alias="notBefore")
    expires_at: datetime = Field(alias="expiresAt")

    @field_validator("max_actions", mode="before")
    @classmethod
    def require_exact_single_action_limit(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("Action approval maxActions must be the JSON integer 1")
        return value

    @field_validator("cleanup_required", mode="before")
    @classmethod
    def require_exact_cleanup_flag(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Action approval cleanupRequired must be the JSON boolean false")
        return value

    @field_validator("approved_at", "not_before", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="Action approval time")

    @model_validator(mode="after")
    def bind_approved_action(self) -> Self:
        envelope = self.mission_envelope
        proposal = self.proposal
        decision = self.graph_decision
        if self.requested_by == self.approved_by:
            raise ValueError("Action approval requester cannot approve their own request")
        if not self.approved_at <= self.not_before < self.expires_at:
            raise ValueError("Action approval window is invalid")
        if (
            envelope.campaign_id != self.campaign_id
            or envelope.source_campaign_digest != self.campaign_digest
            or envelope.run_id != self.run_id
            or proposal.campaign_id != self.campaign_id
            or proposal.run_id != self.run_id
            or decision.campaign_id != self.campaign_id
        ):
            raise ValueError("Action approval Campaign or Run lineage differs")
        if (
            proposal.envelope_id != envelope.envelope_id
            or proposal.envelope_digest != envelope.envelope_digest
            or proposal.decision_id != decision.decision_id
            or proposal.decision_digest != decision.decision_digest
            or proposal.snapshot != decision.snapshot
        ):
            raise ValueError("Action approval Envelope, Decision, or Proposal differs")
        if decision.decision_payload_digest != self.source_intent_digest:
            raise ValueError("Action approval Decision names another source intent")
        if (
            self.release.capability_id != proposal.capability.capability_id
            or self.release.capability_version != proposal.capability.capability_version
            or self.release.capability_digest != proposal.capability.definition_digest
        ):
            raise ValueError("Action approval Capability release differs from its Proposal")
        if proposal.reservation != self.reservation:
            raise ValueError("Action approval reservation differs from its Proposal")
        if proposal.risk_tier > ToolRiskTier.T2:
            raise ValueError("Action approval is restricted to T2 or below")
        if (
            envelope.authorized_at > self.approved_at
            or envelope.not_before > self.not_before
            or envelope.expires_at < self.expires_at
            or decision.created_at > self.approved_at
            or proposal.created_at > self.approved_at
        ):
            raise ValueError("Action approval exceeds its authority timeline")
        expected_permit_id = action_permit_attempt_id(envelope, proposal, decision)
        if self.expected_action_permit_id != expected_permit_id:
            raise ValueError("Action approval expected ActionPermit ID differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"approval_id", "approval_digest"},
        )
        digest = graph_digest(
            "pajin.action.approval-envelope/v1",
            material,
            max_bytes=_MAX_APPROVAL_BYTES,
        )
        approval_id = f"action-approval_{digest}"
        if self.approval_digest and self.approval_digest != digest:
            raise ValueError("Action approval Envelope digest differs")
        if self.approval_id and self.approval_id != approval_id:
            raise ValueError("Action approval Envelope ID differs")
        object.__setattr__(self, "approval_digest", digest)
        object.__setattr__(self, "approval_id", approval_id)
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="ActionApprovalEnvelope",
            max_bytes=_MAX_APPROVAL_BYTES,
        )
        return self


class ActionApprovalConsumptionReceipt(StrictModel):
    """Non-reusable proof that one approval and one ActionPermit were consumed together."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-approval-consumption-receipt/v1alpha1"] = Field(
        default=ACTION_APPROVAL_CONSUMPTION_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ActionApprovalConsumptionReceipt"] = "ActionApprovalConsumptionReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=96)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    approval: ActionApprovalEnvelope
    action_permit: ActionPermit = Field(alias="actionPermit")
    dispatch_id: str = Field(alias="dispatchId", pattern=r"^action-dispatch_[a-f0-9]{64}$")
    proposal_id: str = Field(alias="proposalId", pattern=r"^action-proposal_[a-f0-9]{64}$")
    proposal_digest: _Sha256 = Field(alias="proposalDigest")
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    reusable: Literal[False] = False
    redispatch_authority: Literal[False] = Field(default=False, alias="redispatchAuthority")

    @field_validator("reusable", "redispatch_authority", mode="before")
    @classmethod
    def require_exact_non_reusable_flag(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Approval receipt reuse flags must be the JSON boolean false")
        return value

    @model_validator(mode="after")
    def bind_consumption(self) -> Self:
        approval = self.approval
        permit = self.action_permit
        proposal = approval.proposal
        if (
            permit.permit_id != approval.expected_action_permit_id
            or permit.campaign_id != approval.campaign_id
            or permit.run_id != approval.run_id
            or permit.envelope_id != approval.mission_envelope.envelope_id
            or permit.envelope_digest != approval.mission_envelope.envelope_digest
            or permit.proposal_id != proposal.proposal_id
            or permit.proposal_digest != proposal.proposal_digest
            or permit.decision_id != approval.graph_decision.decision_id
            or permit.decision_digest != approval.graph_decision.decision_digest
            or permit.snapshot != approval.graph_decision.snapshot
            or permit.capability != proposal.capability
            or permit.target_digest != proposal.target_digest
            or permit.reservation != approval.reservation
            or self.dispatch_id != permit.dispatch_id
            or self.proposal_id != permit.proposal_id
            or self.proposal_digest != permit.proposal_digest
            or self.request_id != permit.request_id
            or self.request_digest != permit.request_digest
            or self.normalized_parameters_digest != permit.normalized_parameters_digest
            or not approval.not_before <= permit.consumed_at < approval.expires_at
            or permit.expires_at > approval.expires_at
        ):
            raise ValueError("Action approval receipt differs from its exact approved Permit")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = graph_digest(
            "pajin.action.approval-consumption-receipt/v1",
            material,
            max_bytes=_MAX_APPROVAL_BYTES,
        )
        receipt_id = f"action-approval-receipt_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Action approval consumption receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Action approval consumption receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="ActionApprovalConsumptionReceipt",
            max_bytes=_MAX_APPROVAL_BYTES,
        )
        return self


def build_action_approval_consumption_receipt(
    approval: ActionApprovalEnvelope,
    permit: ActionPermit,
) -> ActionApprovalConsumptionReceipt:
    """Build the exact non-reusable proof for one atomic approval consumption."""

    try:
        canonical_approval = ActionApprovalEnvelope.model_validate(
            approval.model_dump(mode="json", by_alias=True)
        )
        canonical_permit = ActionPermit.model_validate(
            permit.model_dump(mode="json", by_alias=True)
        )
        return ActionApprovalConsumptionReceipt(
            approval=canonical_approval,
            actionPermit=canonical_permit,
            dispatchId=canonical_permit.dispatch_id,
            proposalId=canonical_permit.proposal_id,
            proposalDigest=canonical_permit.proposal_digest,
            requestId=canonical_permit.request_id,
            requestDigest=canonical_permit.request_digest,
            normalizedParametersDigest=canonical_permit.normalized_parameters_digest,
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ActionApprovalError("Action approval consumption receipt could not be built") from exc


class ActionApprovalAuthorization(StrictModel):
    """Atomic store result for one approval, Permit, and consumption receipt."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    approval: ActionApprovalEnvelope
    action: ActionPermitAuthorization
    receipt: ActionApprovalConsumptionReceipt

    @model_validator(mode="after")
    def require_one_atomic_result(self) -> Self:
        if (
            self.receipt.approval != self.approval
            or self.receipt.action_permit != self.action.permit
        ):
            raise ValueError("approved Action authorization contains unrelated authority")
        return self


class GraphApprovedActionPermitStore(Protocol):
    """Storage-neutral atomic ApprovalEnvelope plus ActionPermit plus receipt transaction."""

    def claim_approved_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        policies: ActionApprovalCapabilityPolicyRegistry,
        input_authority: ActionApprovalInputAuthority,
    ) -> object: ...

    def approved_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ActionApprovalAuthorization | None: ...

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
    ) -> ActionApprovalAuthorization: ...


class ActionApprovalInputAuthority(Protocol):
    """Authenticate operator issuance and current release/Definition approval semantics."""

    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None: ...


class GraphApprovedActionPermitAuthority:
    """Consume one exact approval with the existing ActionPermit in one store transaction."""

    def __init__(
        self,
        *,
        campaign_id: str,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        capabilities: ActionCapabilityRegistry,
        policies: ActionApprovalCapabilityPolicyRegistry,
        permit_store: GraphApprovedActionPermitStore,
        input_authority: ActionApprovalInputAuthority,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None:
            raise ValueError("approved ActionPermit authority Campaign ID is invalid")
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", compiler_id) is None
            or fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", compiler_version) is None
            or fullmatch(r"^[a-f0-9]{64}$", compiler_digest) is None
        ):
            raise ValueError("approved ActionPermit compiler identity is invalid")
        if not timedelta(seconds=1) <= permit_ttl <= timedelta(minutes=5):
            raise ValueError("approved ActionPermit TTL must be from 1 second through 5 minutes")
        if not callable(getattr(input_authority, "verify_action_approval", None)):
            raise TypeError("approved ActionPermit requires an approval input authority")
        self._campaign_id = campaign_id
        self._compiler_identity = (compiler_id, compiler_version, compiler_digest)
        self._capabilities = capabilities
        if not isinstance(policies, ActionApprovalCapabilityPolicyRegistry):
            raise TypeError("approved ActionPermit requires a Capability policy registry")
        self._policies = policies
        self._permit_store = permit_store
        self._input_authority = input_authority
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_ttl = permit_ttl
        self._writer = permit_store.claim_approved_writer(
            *self._compiler_identity,
            policies,
            input_authority,
        )

    def authorize_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> ActionApprovalAuthorization:
        canonical_envelope = _canonical(MissionEnvelope, envelope, label="MissionEnvelope")
        canonical_proposal = _canonical(ActionProposal, proposal, label="ActionProposal")
        canonical_decision = _canonical(GraphDecision, decision, label="GraphDecision")
        canonical_approval = _canonical(
            ActionApprovalEnvelope,
            approval,
            label="ActionApprovalEnvelope",
        )
        if (
            canonical_envelope.campaign_id != self._campaign_id
            or canonical_proposal.campaign_id != self._campaign_id
            or canonical_decision.campaign_id != self._campaign_id
            or canonical_approval.campaign_id != self._campaign_id
        ):
            raise ActionApprovalError("approved Action input belongs to another Campaign")
        if self._compiler_identity != (
            canonical_envelope.compiler_id,
            canonical_envelope.compiler_version,
            canonical_envelope.compiler_digest,
        ):
            raise ActionApprovalError("approved Action MissionEnvelope compiler differs")
        capability = self._capabilities.resolve(canonical_proposal.capability)
        policy = self._policies.resolve(capability.reference())
        evaluated_at = _normalize_utc(self._clock(), label="Action approval evaluation time")
        _validate_action_approval_binding(
            canonical_envelope,
            canonical_proposal,
            canonical_decision,
            capability,
            policy,
            canonical_approval,
        )
        existing = self._permit_store.approved_authorization(
            canonical_approval.approval_id,
            canonical_approval.expected_action_permit_id,
        )
        if existing is not None:
            self._verify_input(
                canonical_envelope,
                canonical_proposal,
                canonical_decision,
                canonical_approval,
            )
            canonical_existing = self._canonical_authorization(existing)
            if canonical_existing.approval != canonical_approval:
                raise ActionApprovalError(
                    "approved Action store returned another approval"
                )
            if canonical_existing.action.newly_consumed:
                raise ActionApprovalError(
                    "approved Action terminal lookup granted new consumption"
                )
            self._verify_input(
                canonical_envelope,
                canonical_proposal,
                canonical_decision,
                canonical_approval,
            )
            return canonical_existing
        validate_action_approval_authority(
            canonical_envelope,
            canonical_proposal,
            canonical_decision,
            capability,
            policy,
            canonical_approval,
            evaluated_at=evaluated_at,
        )
        remaining = canonical_approval.expires_at - evaluated_at
        self._verify_input(
            canonical_envelope,
            canonical_proposal,
            canonical_decision,
            canonical_approval,
        )
        authorization = self._permit_store.authorize_approved_for_dispatch(
            canonical_envelope,
            canonical_proposal,
            canonical_decision,
            capability,
            canonical_approval,
            writer=self._writer,
            evaluated_at=evaluated_at,
            permit_ttl=(
                min(self._permit_ttl, remaining)
                if remaining > timedelta(0)
                else self._permit_ttl
            ),
        )
        self._verify_input(
            canonical_envelope,
            canonical_proposal,
            canonical_decision,
            canonical_approval,
        )
        canonical_authorization = self._canonical_authorization(authorization)
        if canonical_authorization.approval != canonical_approval:
            raise ActionApprovalError("approved Action store returned another approval")
        return canonical_authorization

    @staticmethod
    def _canonical_authorization(
        authorization: ActionApprovalAuthorization,
    ) -> ActionApprovalAuthorization:
        try:
            return ActionApprovalAuthorization.model_validate(
                authorization.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise ActionApprovalError("approved Action store returned invalid authority") from exc

    def _verify_input(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        try:
            self._input_authority.verify_action_approval(
                envelope.model_copy(deep=True),
                proposal.model_copy(deep=True),
                decision.model_copy(deep=True),
                approval.model_copy(deep=True),
            )
        except ActionApprovalError:
            raise
        except Exception as exc:
            raise ActionApprovalError("approval input authority rejected the claim") from exc


@dataclass(frozen=True)
class ApprovedActionDispatchResult[DispatchResultT]:
    """Observation of an approval-bound Action dispatch attempt."""

    authorization: ActionApprovalAuthorization
    dispatched: bool
    result: DispatchResultT | None = None


@dataclass(frozen=True, kw_only=True)
class ApprovalBoundActionDispatchResult[DispatchResultT](
    ActionDispatchResult[DispatchResultT]
):
    """Gateway-compatible result retaining the exact durable approval receipt."""

    approval_receipt: ActionApprovalConsumptionReceipt


class GraphApprovedActionPermitDispatcher:
    """Invoke a callback only for the first atomic approval and Permit consumption."""

    def __init__(self, authority: GraphApprovedActionPermitAuthority) -> None:
        if not isinstance(authority, GraphApprovedActionPermitAuthority):
            raise TypeError("approved Action dispatcher requires its exact authority")
        self._authority = authority

    async def dispatch_once[DispatchResultT](
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
        dispatch: Callable[
            [ActionPermit, ActionApprovalConsumptionReceipt],
            Awaitable[DispatchResultT],
        ],
    ) -> ApprovedActionDispatchResult[DispatchResultT]:
        if not _is_async_callable(dispatch):
            raise TypeError("approved Action dispatch callback must be async")
        authorization = self._authority.authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            approval,
        )
        if not authorization.action.newly_consumed:
            return ApprovedActionDispatchResult(
                authorization=authorization,
                dispatched=False,
            )
        result = await dispatch(authorization.action.permit, authorization.receipt)
        return ApprovedActionDispatchResult(
            authorization=authorization,
            dispatched=True,
            result=result,
        )


class GraphApprovalBoundActionPermitDispatcher:
    """Adapt one deployment-pinned approval to the existing Gateway dispatcher protocol."""

    def __init__(
        self,
        dispatcher: GraphApprovedActionPermitDispatcher,
        approval: ActionApprovalEnvelope,
    ) -> None:
        if not isinstance(dispatcher, GraphApprovedActionPermitDispatcher):
            raise TypeError("approval-bound dispatcher requires its approved dispatcher")
        self._dispatcher = dispatcher
        self._approval = _canonical(
            ActionApprovalEnvelope,
            approval,
            label="ActionApprovalEnvelope",
        )

    async def dispatch_once[DispatchResultT](
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        dispatch: Callable[[ActionPermit], Awaitable[DispatchResultT]],
    ) -> ApprovalBoundActionDispatchResult[DispatchResultT]:
        if not _is_async_callable(dispatch):
            raise TypeError("approval-bound Action dispatch callback must be async")

        async def consume(
            permit: ActionPermit,
            receipt: ActionApprovalConsumptionReceipt,
        ) -> DispatchResultT:
            return await dispatch(permit)

        result = await self._dispatcher.dispatch_once(
            envelope,
            proposal,
            decision,
            self._approval,
            consume,
        )
        return ApprovalBoundActionDispatchResult(
            permit=result.authorization.action.permit,
            dispatched=result.dispatched,
            result=result.result,
            approval_receipt=result.authorization.receipt,
        )


def validate_action_approval_authority(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    capability: RegisteredActionCapability,
    policy: ActionApprovalCapabilityPolicy,
    approval: ActionApprovalEnvelope,
    *,
    evaluated_at: datetime,
) -> None:
    """Validate the exact single-action approval intersection before durable consumption."""

    evaluated_at = _normalize_utc(evaluated_at, label="Action approval evaluation time")
    validate_action_authority(
        envelope,
        proposal,
        decision,
        capability,
        evaluated_at=evaluated_at,
    )
    _validate_action_approval_binding(
        envelope,
        proposal,
        decision,
        capability,
        policy,
        approval,
    )
    if not approval.not_before <= evaluated_at < approval.expires_at:
        raise ActionApprovalError("Action approval is not currently active")


def _validate_action_approval_binding(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    capability: RegisteredActionCapability,
    policy: ActionApprovalCapabilityPolicy,
    approval: ActionApprovalEnvelope,
) -> None:
    if (
        capability.reference() != proposal.capability
        or policy.capability != capability.reference()
        or approval.mission_envelope != envelope
        or approval.graph_decision != decision
        or approval.proposal != proposal
        or approval.expected_action_permit_id
        != action_permit_attempt_id(envelope, proposal, decision)
        or approval.reservation != proposal.reservation
    ):
        raise ActionApprovalError("Action approval differs from current action authority")
    if proposal.risk_tier > ToolRiskTier.T2:
        raise ActionApprovalError("T3 or higher Actions cannot use this approval authority")
    if (
        policy.side_effect_class not in {"none", "read-only"}
        or policy.cleanup_required
        or approval.side_effect_class != policy.side_effect_class
        or approval.cleanup_required != policy.cleanup_required
    ):
        raise ActionApprovalError("Action approval is restricted to cleanup-free no-write actions")
    if capability.risk_tier is not ToolRiskTier.T2 and not policy.approval_required:
        raise ActionApprovalError("Action approval is not required by current Capability policy")


def _canonical[ModelT: StrictModel](
    model_type: type[ModelT],
    value: ModelT,
    *,
    label: str,
) -> ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="json", by_alias=True))
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ActionApprovalError(f"{label} is not canonical") from exc


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _is_async_callable(value: Any) -> bool:
    return iscoroutinefunction(value) or (callable(value) and iscoroutinefunction(value.__call__))
