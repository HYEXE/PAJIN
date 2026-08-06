"""Atomic operator approval plus reversible-action cleanup-hold authority."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from re import fullmatch
from typing import Any, Protocol, Self

from pydantic import ConfigDict, ValidationError, model_validator

from pajin.domain.models import StrictModel, ToolRiskTier
from pajin.graph.approval import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalInputAuthority,
    build_action_approval_consumption_receipt,
    validate_action_approval_binding,
)
from pajin.graph.authority import (
    ActionCapabilityRegistry,
    ActionPermit,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
)
from pajin.graph.cleanup import (
    ActionCleanupReservationRequest,
    ReversibleActionPermitAuthorization,
    ReversibleActionPermitInputAuthority,
    build_action_cleanup_reservation,
    validate_action_cleanup_reservation_binding,
)
from pajin.graph.consistency import GraphDecision


class ApprovedReversibleActionError(RuntimeError):
    """Raised when approval and cleanup capacity cannot be consumed together safely."""


class ApprovedReversibleActionPermitAuthorization(StrictModel):
    """One atomic approval, ActionPermit, receipt, and cleanup-hold result."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    approval: ActionApprovalEnvelope
    reversible: ReversibleActionPermitAuthorization
    receipt: ActionApprovalConsumptionReceipt

    @model_validator(mode="after")
    def require_one_atomic_result(self) -> Self:
        permit = self.reversible.action.permit
        reservation = self.reversible.cleanup_reservation
        if (
            self.receipt.approval != self.approval
            or self.receipt.action_permit != permit
            or reservation.source_action_permit_id != permit.permit_id
            or reservation.source_action_permit_digest != permit.permit_digest
            or reservation.source_action_dispatch_id != permit.dispatch_id
        ):
            raise ValueError(
                "approved reversible Action authorization contains unrelated authority"
            )
        return self


class GraphApprovedReversibleActionPermitStore(Protocol):
    """Storage-neutral four-record approval plus cleanup-hold transaction."""

    def claim_approved_reversible_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        policies: ActionApprovalCapabilityPolicyRegistry,
        approval_input_authority: ActionApprovalInputAuthority,
        reversible_input_authority: ReversibleActionPermitInputAuthority,
        approval_claim_authority: object,
        cleanup_claim_authority: object,
    ) -> object: ...

    def approved_reversible_authorization(
        self,
        approval_id: str,
        permit_id: str,
    ) -> ApprovedReversibleActionPermitAuthorization | None: ...

    def authorize_approved_reversible_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        action_capability: RegisteredActionCapability,
        approval: ActionApprovalEnvelope,
        cleanup_request: ActionCleanupReservationRequest,
        cleanup_capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ApprovedReversibleActionPermitAuthorization: ...


class GraphApprovedReversibleActionPermitAuthority:
    """Consume one approval with one ActionPermit and its mandatory cleanup hold."""

    def __init__(
        self,
        *,
        campaign_id: str,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        capabilities: ActionCapabilityRegistry,
        policies: ActionApprovalCapabilityPolicyRegistry,
        permit_store: GraphApprovedReversibleActionPermitStore,
        approval_input_authority: ActionApprovalInputAuthority,
        reversible_input_authority: ReversibleActionPermitInputAuthority,
        approval_claim_authority: object | None = None,
        cleanup_claim_authority: object | None = None,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None:
            raise ValueError("approved reversible authority Campaign ID is invalid")
        if (
            fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", compiler_id) is None
            or fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", compiler_version)
            is None
            or fullmatch(r"^[a-f0-9]{64}$", compiler_digest) is None
        ):
            raise ValueError("approved reversible compiler identity is invalid")
        if not timedelta(seconds=1) <= permit_ttl <= timedelta(minutes=5):
            raise ValueError(
                "approved reversible ActionPermit TTL must be from 1 second through 5 minutes"
            )
        if not isinstance(policies, ActionApprovalCapabilityPolicyRegistry):
            raise TypeError("approved reversible authority requires a Capability policy registry")
        if not callable(
            getattr(approval_input_authority, "verify_action_approval", None)
        ):
            raise TypeError("approved reversible authority requires an approval verifier")
        if not callable(
            getattr(reversible_input_authority, "verify_reversible_action", None)
        ):
            raise TypeError("approved reversible authority requires a cleanup-hold verifier")
        self._campaign_id = campaign_id
        self._compiler_identity = (compiler_id, compiler_version, compiler_digest)
        self._capabilities = capabilities
        self._policies = policies
        self._permit_store = permit_store
        self._approval_input_authority = approval_input_authority
        self._reversible_input_authority = reversible_input_authority
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_ttl = permit_ttl
        self._writer = permit_store.claim_approved_reversible_writer(
            *self._compiler_identity,
            policies,
            approval_input_authority,
            reversible_input_authority,
            (
                approval_claim_authority
                if approval_claim_authority is not None
                else approval_input_authority
            ),
            (
                cleanup_claim_authority
                if cleanup_claim_authority is not None
                else reversible_input_authority
            ),
        )

    def authorize_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
        cleanup_request: ActionCleanupReservationRequest,
    ) -> ApprovedReversibleActionPermitAuthorization:
        envelope = _canonical(MissionEnvelope, envelope, label="MissionEnvelope")
        proposal = _canonical(ActionProposal, proposal, label="ActionProposal")
        decision = _canonical(GraphDecision, decision, label="GraphDecision")
        approval = _canonical(
            ActionApprovalEnvelope,
            approval,
            label="ActionApprovalEnvelope",
        )
        cleanup_request = _canonical(
            ActionCleanupReservationRequest,
            cleanup_request,
            label="ActionCleanupReservationRequest",
        )
        if (
            envelope.campaign_id != self._campaign_id
            or proposal.campaign_id != self._campaign_id
            or decision.campaign_id != self._campaign_id
            or approval.campaign_id != self._campaign_id
            or cleanup_request.campaign_id != self._campaign_id
        ):
            raise ApprovedReversibleActionError(
                "approved reversible input belongs to another Campaign"
            )
        if self._compiler_identity != (
            envelope.compiler_id,
            envelope.compiler_version,
            envelope.compiler_digest,
        ):
            raise ApprovedReversibleActionError(
                "approved reversible MissionEnvelope compiler differs"
            )
        action_capability = self._capabilities.resolve(proposal.capability)
        cleanup_capability = self._capabilities.resolve(
            cleanup_request.cleanup_capability
        )
        policy = self._policies.resolve(action_capability.reference())
        validate_approved_reversible_action_binding(
            envelope,
            proposal,
            decision,
            action_capability,
            policy,
            approval,
        )
        existing = self._permit_store.approved_reversible_authorization(
            approval.approval_id,
            approval.expected_action_permit_id,
        )
        if existing is not None:
            self._verify_inputs(
                envelope,
                proposal,
                decision,
                approval,
                cleanup_request,
            )
            existing = self._validated_authorization(
                existing,
                envelope=envelope,
                approval=approval,
                cleanup_request=cleanup_request,
                cleanup_capability=cleanup_capability,
            )
            if existing.reversible.action.newly_consumed:
                raise ApprovedReversibleActionError(
                    "approved reversible terminal lookup granted new consumption"
                )
            self._verify_inputs(
                envelope,
                proposal,
                decision,
                approval,
                cleanup_request,
            )
            return existing

        evaluated_at = _normalize_utc(
            self._clock(),
            label="approved reversible evaluation time",
        )
        validate_approved_reversible_action_authority(
            envelope,
            proposal,
            decision,
            action_capability,
            policy,
            approval,
            cleanup_request,
            cleanup_capability,
            evaluated_at=evaluated_at,
        )
        self._verify_inputs(
            envelope,
            proposal,
            decision,
            approval,
            cleanup_request,
        )
        remaining = approval.expires_at - evaluated_at
        authorization = self._permit_store.authorize_approved_reversible_for_dispatch(
            envelope,
            proposal,
            decision,
            action_capability,
            approval,
            cleanup_request,
            cleanup_capability,
            writer=self._writer,
            evaluated_at=evaluated_at,
            permit_ttl=(
                min(self._permit_ttl, remaining)
                if remaining > timedelta(0)
                else self._permit_ttl
            ),
        )
        self._verify_inputs(
            envelope,
            proposal,
            decision,
            approval,
            cleanup_request,
        )
        return self._validated_authorization(
            authorization,
            envelope=envelope,
            approval=approval,
            cleanup_request=cleanup_request,
            cleanup_capability=cleanup_capability,
        )

    def _validated_authorization(
        self,
        authorization: ApprovedReversibleActionPermitAuthorization,
        *,
        envelope: MissionEnvelope,
        approval: ActionApprovalEnvelope,
        cleanup_request: ActionCleanupReservationRequest,
        cleanup_capability: RegisteredActionCapability,
    ) -> ApprovedReversibleActionPermitAuthorization:
        authorization = self._canonical_authorization(authorization)
        self._require_exact_result(
            authorization,
            envelope=envelope,
            approval=approval,
            cleanup_request=cleanup_request,
            cleanup_capability=cleanup_capability,
        )
        return authorization

    @staticmethod
    def _canonical_authorization(
        authorization: ApprovedReversibleActionPermitAuthorization,
    ) -> ApprovedReversibleActionPermitAuthorization:
        try:
            return ApprovedReversibleActionPermitAuthorization.model_validate(
                authorization.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise ApprovedReversibleActionError(
                "approved reversible store returned invalid authority"
            ) from exc

    @staticmethod
    def _require_exact_result(
        authorization: ApprovedReversibleActionPermitAuthorization,
        *,
        envelope: MissionEnvelope,
        approval: ActionApprovalEnvelope,
        cleanup_request: ActionCleanupReservationRequest,
        cleanup_capability: RegisteredActionCapability,
    ) -> None:
        permit = authorization.reversible.action.permit
        expected_reservation = build_action_cleanup_reservation(
            envelope,
            permit,
            cleanup_request,
            evaluated_at=permit.consumed_at,
        )
        if (
            authorization.approval != approval
            or authorization.receipt
            != build_action_approval_consumption_receipt(approval, permit)
            or authorization.reversible.cleanup_reservation != expected_reservation
            or expected_reservation.cleanup_capability
            != cleanup_capability.reference()
        ):
            raise ApprovedReversibleActionError(
                "approved reversible store returned different authority"
            )

    def _verify_inputs(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
        cleanup_request: ActionCleanupReservationRequest,
    ) -> None:
        try:
            self._approval_input_authority.verify_action_approval(
                envelope.model_copy(deep=True),
                proposal.model_copy(deep=True),
                decision.model_copy(deep=True),
                approval.model_copy(deep=True),
            )
            self._reversible_input_authority.verify_reversible_action(
                envelope.model_copy(deep=True),
                proposal.model_copy(deep=True),
                decision.model_copy(deep=True),
                cleanup_request.model_copy(deep=True),
            )
        except ApprovedReversibleActionError:
            raise
        except Exception as exc:
            raise ApprovedReversibleActionError(
                "approved reversible input authority rejected the claim"
            ) from exc


@dataclass(frozen=True)
class ApprovedReversibleActionDispatchResult[DispatchResultT]:
    """Observation of one approved reversible dispatch attempt."""

    authorization: ApprovedReversibleActionPermitAuthorization
    dispatched: bool
    result: DispatchResultT | None = None


class GraphApprovedReversibleActionPermitDispatcher:
    """Dispatch only after approval, Permit, receipt, and cleanup hold commit together."""

    def __init__(self, authority: GraphApprovedReversibleActionPermitAuthority) -> None:
        if not isinstance(authority, GraphApprovedReversibleActionPermitAuthority):
            raise TypeError(
                "approved reversible dispatcher requires its exact authority"
            )
        self._authority = authority

    async def dispatch_once[DispatchResultT](
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
        cleanup_request: ActionCleanupReservationRequest,
        dispatch: Callable[
            [ActionPermit, ActionApprovalConsumptionReceipt],
            Awaitable[DispatchResultT],
        ],
    ) -> ApprovedReversibleActionDispatchResult[DispatchResultT]:
        if not _is_async_callable(dispatch):
            raise TypeError("approved reversible dispatch callback must be async")
        authorization = self._authority.authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            approval,
            cleanup_request,
        )
        if not authorization.reversible.action.newly_consumed:
            return ApprovedReversibleActionDispatchResult(
                authorization=authorization,
                dispatched=False,
            )
        result = await dispatch(
            authorization.reversible.action.permit,
            authorization.receipt,
        )
        return ApprovedReversibleActionDispatchResult(
            authorization=authorization,
            dispatched=True,
            result=result,
        )


def validate_approved_reversible_action_authority(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    action_capability: RegisteredActionCapability,
    policy: ActionApprovalCapabilityPolicy,
    approval: ActionApprovalEnvelope,
    cleanup_request: ActionCleanupReservationRequest,
    cleanup_capability: RegisteredActionCapability,
    *,
    evaluated_at: datetime,
) -> None:
    """Validate the active intersection of operator approval and cleanup capacity."""

    evaluated_at = _normalize_utc(
        evaluated_at,
        label="approved reversible evaluation time",
    )
    validate_approved_reversible_action_binding(
        envelope,
        proposal,
        decision,
        action_capability,
        policy,
        approval,
    )
    validate_action_cleanup_reservation_binding(
        envelope,
        proposal,
        decision,
        action_capability,
        cleanup_request,
        cleanup_capability,
        evaluated_at=evaluated_at,
    )
    if not approval.not_before <= evaluated_at < approval.expires_at:
        raise ApprovedReversibleActionError(
            "approved reversible Action approval is not currently active"
        )


def validate_approved_reversible_action_binding(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    action_capability: RegisteredActionCapability,
    policy: ActionApprovalCapabilityPolicy,
    approval: ActionApprovalEnvelope,
) -> None:
    """Require the exact reversible-write policy supported by APPROVAL-001B."""

    validate_action_approval_binding(
        envelope,
        proposal,
        decision,
        action_capability,
        approval,
    )
    if (
        policy.capability != action_capability.reference()
        or policy.side_effect_class != "reversible-write"
        or not policy.cleanup_required
        or approval.side_effect_class != policy.side_effect_class
        or approval.cleanup_required != policy.cleanup_required
    ):
        raise ApprovedReversibleActionError(
            "approved reversible Action requires reversible-write with cleanup"
        )
    if action_capability.risk_tier >= ToolRiskTier.T3:
        raise ApprovedReversibleActionError(
            "T3 or higher Actions cannot use approved reversible authority"
        )
    if (
        action_capability.risk_tier is not ToolRiskTier.T2
        and not policy.approval_required
    ):
        raise ApprovedReversibleActionError(
            "reversible Action approval is not required by current Capability policy"
        )


def _canonical[ModelT: StrictModel](
    model_type: type[ModelT],
    value: ModelT,
    *,
    label: str,
) -> ModelT:
    try:
        return model_type.model_validate(value.model_dump(mode="json", by_alias=True))
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise ApprovedReversibleActionError(f"{label} is not canonical") from exc


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _is_async_callable(value: Any) -> bool:
    from inspect import iscoroutinefunction

    return iscoroutinefunction(value) or (
        callable(value) and iscoroutinefunction(value.__call__)
    )
