"""Deterministic MissionEnvelope and single-use ActionPermit authority."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from re import fullmatch
from typing import Annotated, Literal, Protocol, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.domain.models import AutonomyLevel, StrictModel, ToolRiskTier
from pajin.graph.consistency import GraphDecision
from pajin.graph.models import canonical_graph_json, graph_digest
from pajin.graph.projection import GraphSnapshotRef

REGISTERED_ACTION_CAPABILITY_API_VERSION: Literal[
    "pajin.dev/registered-action-capability/v1alpha1"
] = "pajin.dev/registered-action-capability/v1alpha1"
MISSION_ENVELOPE_API_VERSION: Literal["pajin.dev/mission-envelope/v1alpha1"] = (
    "pajin.dev/mission-envelope/v1alpha1"
)
ACTION_PROPOSAL_API_VERSION: Literal["pajin.dev/action-proposal/v1alpha1"] = (
    "pajin.dev/action-proposal/v1alpha1"
)
ACTION_PERMIT_API_VERSION: Literal["pajin.dev/action-permit/v1alpha1"] = (
    "pajin.dev/action-permit/v1alpha1"
)

_MAX_CAPABILITY_BYTES = 64 * 1024
_MAX_ENVELOPE_BYTES = 512 * 1024
_MAX_ACTION_PROPOSAL_BYTES = 256 * 1024
_MAX_ACTION_PERMIT_BYTES = 512 * 1024
_CAPABILITY_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_MISSION_ENVELOPE_ID_PATTERN = r"^mission-envelope_[a-f0-9]{64}$"
_ACTION_PROPOSAL_ID_PATTERN = r"^action-proposal_[a-f0-9]{64}$"
_ACTION_PERMIT_ID_PATTERN = r"^action-permit_[a-f0-9]{64}$"
_ACTION_DISPATCH_ID_PATTERN = r"^action-dispatch_[a-f0-9]{64}$"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_PortableIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$"),
]
_CampaignIdentifier = Annotated[
    str,
    Field(min_length=3, max_length=80, pattern=r"^[a-z0-9][a-z0-9-]*$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class ActionPermitError(RuntimeError):
    """Raised when an ActionPermit cannot be issued and consumed safely."""


class ActionPermitConflict(ActionPermitError):
    """Raised when a request identity or deterministic attempt equivocates."""


class ActionPermitStaleDecision(ActionPermitError):
    """Raised when durable Graph authority no longer matches the decision Snapshot."""


class ActionPermitBudgetExceeded(ActionPermitError):
    """Raised when an envelope budget or rolling-window rate would be exceeded."""


class ActionCapabilityRef(StrictModel):
    """Exact reference to one immutable registered execution Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    capability_id: _Identifier = Field(alias="capabilityId")
    capability_version: _Identifier = Field(alias="capabilityVersion")
    capability_digest: _Sha256 = Field(alias="capabilityDigest")
    tool_id: _Identifier = Field(alias="toolId")
    tool_version: _Identifier = Field(alias="toolVersion")
    tool_digest: _Sha256 = Field(alias="toolDigest")
    risk_tier: ToolRiskTier = Field(alias="riskTier")

    @field_validator("risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)


class RegisteredActionCapability(StrictModel):
    """One versioned execution contract pinned by a canonical digest."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/registered-action-capability/v1alpha1"] = Field(
        default=REGISTERED_ACTION_CAPABILITY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["RegisteredActionCapability"] = "RegisteredActionCapability"
    capability_id: str = Field(
        alias="capabilityId",
        pattern=_CAPABILITY_ID_PATTERN,
        max_length=200,
    )
    capability_version: _Identifier = Field(alias="capabilityVersion")
    capability_digest: str = Field(default="", alias="capabilityDigest", max_length=64)
    tool_id: _Identifier = Field(alias="toolId")
    tool_version: _Identifier = Field(alias="toolVersion")
    tool_digest: _Sha256 = Field(alias="toolDigest")
    risk_tier: ToolRiskTier = Field(alias="riskTier")

    @field_validator("risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @model_validator(mode="after")
    def bind_capability_digest(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"capability_digest"},
        )
        digest = graph_digest(
            "pajin.action.registered-capability/v1",
            material,
            max_bytes=_MAX_CAPABILITY_BYTES,
        )
        if self.capability_digest and self.capability_digest != digest:
            raise ValueError("Registered Action Capability digest differs from identity")
        object.__setattr__(self, "capability_digest", digest)
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="RegisteredActionCapability",
            max_bytes=_MAX_CAPABILITY_BYTES,
        )
        return self

    def reference(self) -> ActionCapabilityRef:
        return ActionCapabilityRef(
            capabilityId=self.capability_id,
            capabilityVersion=self.capability_version,
            capabilityDigest=self.capability_digest,
            toolId=self.tool_id,
            toolVersion=self.tool_version,
            toolDigest=self.tool_digest,
            riskTier=self.risk_tier,
        )


class ActionCapabilityRegistry:
    """Immutable exact-version registry used by the deterministic Permit compiler."""

    def __init__(self, capabilities: Iterable[RegisteredActionCapability]) -> None:
        records: dict[tuple[str, str], RegisteredActionCapability] = {}
        for capability in capabilities:
            canonical = _canonical_capability(capability)
            key = (canonical.capability_id, canonical.capability_version)
            if key in records:
                raise ValueError("Action Capability registry contains a duplicate version")
            records[key] = canonical
        self._records = records

    def resolve(self, reference: ActionCapabilityRef) -> RegisteredActionCapability:
        try:
            capability = self._records[(reference.capability_id, reference.capability_version)]
        except KeyError as exc:
            raise ActionPermitError("Action Capability is not registered") from exc
        if capability.reference() != reference:
            raise ActionPermitError(
                "Action Capability version, digest, Tool, or risk contract differs"
            )
        return capability.model_copy(deep=True)


class ActionBudgetLimit(StrictModel):
    """Durable upper bounds carried by one MissionEnvelope."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    tool_call_limit: int = Field(alias="toolCallLimit", ge=1, le=1_000_000)
    request_unit_limit: int = Field(alias="requestUnitLimit", ge=1, le=100_000_000)
    cost_limit_microusd: int = Field(
        default=0,
        alias="costLimitMicrousd",
        ge=0,
        le=10_000_000_000,
    )
    rolling_window_seconds: int | None = Field(
        default=None,
        alias="rollingWindowSeconds",
        ge=1,
        le=86_400,
    )
    rolling_request_unit_limit: int | None = Field(
        default=None,
        alias="rollingRequestUnitLimit",
        ge=1,
        le=100_000_000,
    )

    @model_validator(mode="after")
    def require_complete_rate_limit(self) -> Self:
        if (self.rolling_window_seconds is None) is not (self.rolling_request_unit_limit is None):
            raise ValueError("MissionEnvelope rolling-window limit is incomplete")
        return self


class ActionBudgetReservation(StrictModel):
    """Exact capacity consumed by one ActionPermit dispatch claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    tool_calls: Literal[1] = Field(default=1, alias="toolCalls")
    request_units: int = Field(alias="requestUnits", ge=1, le=1_000_000)
    cost_microusd: int = Field(
        default=0,
        alias="costMicrousd",
        ge=0,
        le=10_000_000_000,
    )


class MissionEnvelope(StrictModel):
    """Immutable Campaign authority ceiling used by the Permit compiler."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/mission-envelope/v1alpha1"] = Field(
        default=MISSION_ENVELOPE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["MissionEnvelope"] = "MissionEnvelope"
    envelope_id: str = Field(default="", alias="envelopeId", max_length=81)
    envelope_digest: str = Field(default="", alias="envelopeDigest", max_length=64)
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    profile_id: _Identifier = Field(alias="profileId")
    profile_version: _Identifier = Field(alias="profileVersion")
    profile_digest: _Sha256 = Field(alias="profileDigest")
    compiler_id: _Identifier = Field(alias="compilerId")
    compiler_version: _Identifier = Field(alias="compilerVersion")
    compiler_digest: _Sha256 = Field(alias="compilerDigest")
    source_campaign_digest: _Sha256 = Field(alias="sourceCampaignDigest")
    allowed_capabilities: tuple[ActionCapabilityRef, ...] = Field(
        alias="allowedCapabilities",
        min_length=1,
        max_length=1_000,
    )
    allowed_target_digests: tuple[_Sha256, ...] = Field(
        alias="allowedTargetDigests",
        min_length=1,
        max_length=10_000,
    )
    max_risk_tier: ToolRiskTier = Field(alias="maxRiskTier")
    budget: ActionBudgetLimit
    autonomy: AutonomyLevel
    authorized_at: datetime = Field(alias="authorizedAt")
    not_before: datetime = Field(alias="notBefore")
    expires_at: datetime = Field(alias="expiresAt")

    @field_validator("max_risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @field_validator("authorized_at", "not_before", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="MissionEnvelope time")

    @model_validator(mode="after")
    def bind_envelope_identity(self) -> Self:
        if not self.authorized_at <= self.not_before < self.expires_at:
            raise ValueError("MissionEnvelope authorization window is invalid")
        capability_keys = [
            (
                item.capability_id,
                item.capability_version,
                item.capability_digest,
            )
            for item in self.allowed_capabilities
        ]
        if capability_keys != sorted(set(capability_keys)):
            raise ValueError("MissionEnvelope Capabilities must be unique and sorted")
        if list(self.allowed_target_digests) != sorted(set(self.allowed_target_digests)):
            raise ValueError("MissionEnvelope target digests must be unique and sorted")
        if any(item.risk_tier > self.max_risk_tier for item in self.allowed_capabilities):
            raise ValueError("MissionEnvelope includes a Capability above its risk ceiling")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"envelope_id", "envelope_digest"},
        )
        digest = graph_digest(
            "pajin.action.mission-envelope/v1",
            material,
            max_bytes=_MAX_ENVELOPE_BYTES,
        )
        envelope_id = f"mission-envelope_{digest}"
        if self.envelope_digest and self.envelope_digest != digest:
            raise ValueError("MissionEnvelope digest differs from canonical identity")
        if self.envelope_id and self.envelope_id != envelope_id:
            raise ValueError("MissionEnvelope ID differs from canonical identity")
        object.__setattr__(self, "envelope_digest", digest)
        object.__setattr__(self, "envelope_id", envelope_id)
        if fullmatch(_MISSION_ENVELOPE_ID_PATTERN, self.envelope_id) is None:
            raise ValueError("MissionEnvelope ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="MissionEnvelope",
            max_bytes=_MAX_ENVELOPE_BYTES,
        )
        return self


class ActionProposal(StrictModel):
    """Non-executable intent bound to one Graph decision and exact request."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-proposal/v1alpha1"] = Field(
        default=ACTION_PROPOSAL_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ActionProposal"] = "ActionProposal"
    proposal_id: str = Field(default="", alias="proposalId", max_length=80)
    proposal_digest: str = Field(default="", alias="proposalDigest", max_length=64)
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    envelope_id: str = Field(alias="envelopeId", pattern=_MISSION_ENVELOPE_ID_PATTERN)
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    decision_id: _Identifier = Field(alias="decisionId")
    decision_digest: _Sha256 = Field(alias="decisionDigest")
    snapshot: GraphSnapshotRef
    proposer_id: _Identifier = Field(alias="proposerId")
    proposer_digest: _Sha256 = Field(alias="proposerDigest")
    capability: ActionCapabilityRef
    target_digest: _Sha256 = Field(alias="targetDigest")
    request_id: _PortableIdentifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    risk_tier: ToolRiskTier = Field(alias="riskTier")
    reservation: ActionBudgetReservation
    created_at: datetime = Field(alias="createdAt")

    @field_validator("risk_tier", mode="before")
    @classmethod
    def parse_risk_tier(cls, value: ToolRiskTier | str | int) -> ToolRiskTier:
        return ToolRiskTier.parse(value)

    @field_validator("created_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="ActionProposal time")

    @model_validator(mode="after")
    def bind_proposal_identity(self) -> Self:
        if self.snapshot.campaign_id != self.campaign_id:
            raise ValueError("ActionProposal Snapshot belongs to another Campaign")
        if self.risk_tier != self.capability.risk_tier:
            raise ValueError("ActionProposal risk differs from registered Capability risk")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"proposal_id", "proposal_digest"},
        )
        digest = graph_digest(
            "pajin.action.proposal/v1",
            material,
            max_bytes=_MAX_ACTION_PROPOSAL_BYTES,
        )
        proposal_id = f"action-proposal_{digest}"
        if self.proposal_digest and self.proposal_digest != digest:
            raise ValueError("ActionProposal digest differs from canonical identity")
        if self.proposal_id and self.proposal_id != proposal_id:
            raise ValueError("ActionProposal ID differs from canonical identity")
        object.__setattr__(self, "proposal_digest", digest)
        object.__setattr__(self, "proposal_id", proposal_id)
        if fullmatch(_ACTION_PROPOSAL_ID_PATTERN, self.proposal_id) is None:
            raise ValueError("ActionProposal ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="ActionProposal",
            max_bytes=_MAX_ACTION_PROPOSAL_BYTES,
        )
        return self


class ActionPermit(StrictModel):
    """Consumed-on-issuance, non-bearer proof for one exact dispatch claim."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/action-permit/v1alpha1"] = Field(
        default=ACTION_PERMIT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ActionPermit"] = "ActionPermit"
    permit_id: str = Field(default="", alias="permitId", max_length=78)
    permit_digest: str = Field(default="", alias="permitDigest", max_length=64)
    dispatch_id: str = Field(default="", alias="dispatchId", max_length=80)
    status: Literal["consumed"] = "consumed"
    campaign_id: _CampaignIdentifier = Field(alias="campaignId")
    run_id: _Identifier = Field(alias="runId")
    compiler_id: _Identifier = Field(alias="compilerId")
    compiler_version: _Identifier = Field(alias="compilerVersion")
    compiler_digest: _Sha256 = Field(alias="compilerDigest")
    envelope_id: str = Field(alias="envelopeId", pattern=_MISSION_ENVELOPE_ID_PATTERN)
    envelope_digest: _Sha256 = Field(alias="envelopeDigest")
    proposal_id: str = Field(alias="proposalId", pattern=_ACTION_PROPOSAL_ID_PATTERN)
    proposal_digest: _Sha256 = Field(alias="proposalDigest")
    decision_id: _Identifier = Field(alias="decisionId")
    decision_digest: _Sha256 = Field(alias="decisionDigest")
    snapshot: GraphSnapshotRef
    capability: ActionCapabilityRef
    target_digest: _Sha256 = Field(alias="targetDigest")
    request_id: _PortableIdentifier = Field(alias="requestId")
    request_digest: _Sha256 = Field(alias="requestDigest")
    normalized_parameters_digest: _Sha256 = Field(alias="normalizedParametersDigest")
    reservation: ActionBudgetReservation
    issued_at: datetime = Field(alias="issuedAt")
    consumed_at: datetime = Field(alias="consumedAt")
    expires_at: datetime = Field(alias="expiresAt")

    @field_validator("issued_at", "consumed_at", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _normalize_utc(value, label="ActionPermit time")

    @model_validator(mode="after")
    def bind_permit_identity(self) -> Self:
        if self.snapshot.campaign_id != self.campaign_id:
            raise ValueError("ActionPermit Snapshot belongs to another Campaign")
        if not self.issued_at <= self.consumed_at < self.expires_at:
            raise ValueError("ActionPermit issuance, consumption, or expiry is invalid")
        stable_material = {
            "campaignId": self.campaign_id,
            "runId": self.run_id,
            "compilerId": self.compiler_id,
            "compilerVersion": self.compiler_version,
            "compilerDigest": self.compiler_digest,
            "envelopeId": self.envelope_id,
            "envelopeDigest": self.envelope_digest,
            "proposalId": self.proposal_id,
            "proposalDigest": self.proposal_digest,
            "decisionId": self.decision_id,
            "decisionDigest": self.decision_digest,
            "snapshot": self.snapshot.model_dump(mode="json", by_alias=True),
            "requestId": self.request_id,
            "requestDigest": self.request_digest,
        }
        permit_identity = graph_digest(
            "pajin.action.permit-id/v1",
            stable_material,
            max_bytes=_MAX_ACTION_PERMIT_BYTES,
        )
        permit_id = f"action-permit_{permit_identity}"
        dispatch_id = "action-dispatch_" + graph_digest(
            "pajin.action.dispatch-id/v1",
            {"permitId": permit_id, "requestId": self.request_id},
            max_bytes=_MAX_ACTION_PERMIT_BYTES,
        )
        if self.permit_id and self.permit_id != permit_id:
            raise ValueError("ActionPermit ID differs from canonical identity")
        if self.dispatch_id and self.dispatch_id != dispatch_id:
            raise ValueError("ActionPermit dispatch ID differs from canonical identity")
        object.__setattr__(self, "permit_id", permit_id)
        object.__setattr__(self, "dispatch_id", dispatch_id)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"permit_digest"},
        )
        digest = graph_digest(
            "pajin.action.permit/v1",
            material,
            max_bytes=_MAX_ACTION_PERMIT_BYTES,
        )
        if self.permit_digest and self.permit_digest != digest:
            raise ValueError("ActionPermit digest differs from canonical identity")
        object.__setattr__(self, "permit_digest", digest)
        if fullmatch(_ACTION_PERMIT_ID_PATTERN, self.permit_id) is None:
            raise ValueError("ActionPermit ID is malformed")
        if fullmatch(_ACTION_DISPATCH_ID_PATTERN, self.dispatch_id) is None:
            raise ValueError("ActionPermit dispatch ID is malformed")
        canonical_graph_json(
            self.model_dump(mode="json", by_alias=True),
            label="ActionPermit",
            max_bytes=_MAX_ACTION_PERMIT_BYTES,
        )
        return self


class ActionPermitAuthorization(StrictModel):
    """Result of the final authority transaction; retries never redispatch."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    permit: ActionPermit
    newly_consumed: bool = Field(alias="newlyConsumed")


class GraphActionPermitStore(Protocol):
    """Storage-neutral final authority transaction required by the compiler."""

    def claim_writer(
        self,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
    ) -> object: ...

    def authorize_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        capability: RegisteredActionCapability,
        *,
        writer: object,
        evaluated_at: datetime,
        permit_ttl: timedelta,
    ) -> ActionPermitAuthorization: ...

    def permit(self, permit_id: str) -> ActionPermit | None: ...

    def permits(self) -> tuple[ActionPermit, ...]: ...


class GraphActionPermitAuthority:
    """Compile and consume one permit at the durable dispatch-claim boundary."""

    def __init__(
        self,
        *,
        campaign_id: str,
        compiler_id: str,
        compiler_version: str,
        compiler_digest: str,
        capabilities: ActionCapabilityRegistry,
        permit_store: GraphActionPermitStore,
        clock: Callable[[], datetime] | None = None,
        permit_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        if fullmatch(r"^[a-z0-9][a-z0-9-]{2,79}$", campaign_id) is None:
            raise ValueError("ActionPermit authority Campaign ID is invalid")
        if (
            fullmatch(_CAPABILITY_ID_PATTERN, compiler_id) is None
            or fullmatch(_CAPABILITY_ID_PATTERN, compiler_version) is None
            or fullmatch(r"^[a-f0-9]{64}$", compiler_digest) is None
        ):
            raise ValueError("ActionPermit compiler identity is invalid")
        if not timedelta(seconds=1) <= permit_ttl <= timedelta(minutes=5):
            raise ValueError("ActionPermit TTL must be from 1 second through 5 minutes")
        self._campaign_id = campaign_id
        self._compiler_identity = (compiler_id, compiler_version, compiler_digest)
        self._capabilities = capabilities
        self._permit_store = permit_store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._permit_ttl = permit_ttl
        self._writer = permit_store.claim_writer(
            compiler_id,
            compiler_version,
            compiler_digest,
        )

    def authorize_for_dispatch(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
    ) -> ActionPermitAuthorization:
        envelope = _canonical_envelope(envelope)
        proposal = _canonical_action_proposal(proposal)
        decision = _canonical_graph_decision(decision)
        if (
            envelope.campaign_id != self._campaign_id
            or proposal.campaign_id != self._campaign_id
            or decision.campaign_id != self._campaign_id
        ):
            raise ActionPermitError("ActionPermit input belongs to another Campaign")
        if self._compiler_identity != (
            envelope.compiler_id,
            envelope.compiler_version,
            envelope.compiler_digest,
        ):
            raise ActionPermitError("MissionEnvelope compiler identity differs")
        capability = self._capabilities.resolve(proposal.capability)
        evaluated_at = _normalize_utc(
            self._clock(),
            label="ActionPermit evaluation time",
        )
        return self._permit_store.authorize_for_dispatch(
            envelope,
            proposal,
            decision,
            capability,
            writer=self._writer,
            evaluated_at=evaluated_at,
            permit_ttl=self._permit_ttl,
        )


@dataclass(frozen=True)
class ActionDispatchResult[DispatchResultT]:
    """Non-authoritative observation of whether this call started the Worker."""

    permit: ActionPermit
    dispatched: bool
    result: DispatchResultT | None = None


class GraphActionPermitDispatcher:
    """Invoke a Worker callback only for the transaction's first consumption."""

    def __init__(self, authority: GraphActionPermitAuthority) -> None:
        self._authority = authority

    async def dispatch_once[DispatchResultT](
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        dispatch: Callable[[ActionPermit], Awaitable[DispatchResultT]],
    ) -> ActionDispatchResult[DispatchResultT]:
        authorization = self._authority.authorize_for_dispatch(
            envelope,
            proposal,
            decision,
        )
        if not authorization.newly_consumed:
            return ActionDispatchResult(
                permit=authorization.permit,
                dispatched=False,
            )
        result = await dispatch(authorization.permit)
        return ActionDispatchResult(
            permit=authorization.permit,
            dispatched=True,
            result=result,
        )


def validate_action_authority(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    capability: RegisteredActionCapability,
    *,
    evaluated_at: datetime,
) -> None:
    """Validate immutable authority algebra before durable budget consumption."""

    if (
        proposal.campaign_id != envelope.campaign_id
        or decision.campaign_id != envelope.campaign_id
        or proposal.run_id != envelope.run_id
    ):
        raise ActionPermitError("Action authority lineage belongs to another Campaign or Run")
    if (
        proposal.envelope_id != envelope.envelope_id
        or proposal.envelope_digest != envelope.envelope_digest
    ):
        raise ActionPermitError("ActionProposal MissionEnvelope binding differs")
    if (
        proposal.decision_id != decision.decision_id
        or proposal.decision_digest != decision.decision_digest
        or proposal.snapshot != decision.snapshot
    ):
        raise ActionPermitError("ActionProposal Graph decision binding differs")
    if proposal.created_at < envelope.not_before or proposal.created_at > evaluated_at:
        raise ActionPermitError("ActionProposal is outside the evaluated authority timeline")
    if not envelope.not_before <= evaluated_at < envelope.expires_at:
        raise ActionPermitError("MissionEnvelope authorization is not active")
    if capability.reference() != proposal.capability:
        raise ActionPermitError("ActionProposal Capability binding differs")
    if proposal.capability not in envelope.allowed_capabilities:
        raise ActionPermitError("Action Capability is outside the MissionEnvelope")
    if proposal.target_digest not in envelope.allowed_target_digests:
        raise ActionPermitError("Action target is outside the MissionEnvelope")
    if proposal.risk_tier > envelope.max_risk_tier:
        raise ActionPermitError("Action risk exceeds the MissionEnvelope")
    if (
        proposal.reservation.tool_calls > envelope.budget.tool_call_limit
        or proposal.reservation.request_units > envelope.budget.request_unit_limit
        or proposal.reservation.cost_microusd > envelope.budget.cost_limit_microusd
    ):
        raise ActionPermitBudgetExceeded("Action reservation exceeds the MissionEnvelope")


def build_action_permit(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
    *,
    evaluated_at: datetime,
    permit_ttl: timedelta,
) -> ActionPermit:
    """Build one canonical consumed-on-issuance Permit after all durable checks."""

    expires_at = min(envelope.expires_at, evaluated_at + permit_ttl)
    return ActionPermit(
        campaignId=envelope.campaign_id,
        runId=envelope.run_id,
        compilerId=envelope.compiler_id,
        compilerVersion=envelope.compiler_version,
        compilerDigest=envelope.compiler_digest,
        envelopeId=envelope.envelope_id,
        envelopeDigest=envelope.envelope_digest,
        proposalId=proposal.proposal_id,
        proposalDigest=proposal.proposal_digest,
        decisionId=decision.decision_id,
        decisionDigest=decision.decision_digest,
        snapshot=decision.snapshot,
        capability=proposal.capability,
        targetDigest=proposal.target_digest,
        requestId=proposal.request_id,
        requestDigest=proposal.request_digest,
        normalizedParametersDigest=proposal.normalized_parameters_digest,
        reservation=proposal.reservation,
        issuedAt=evaluated_at,
        consumedAt=evaluated_at,
        expiresAt=expires_at,
    )


def action_permit_attempt_id(
    envelope: MissionEnvelope,
    proposal: ActionProposal,
    decision: GraphDecision,
) -> str:
    """Return the deterministic Permit ID without introducing a clock value."""

    material = {
        "campaignId": envelope.campaign_id,
        "runId": envelope.run_id,
        "compilerId": envelope.compiler_id,
        "compilerVersion": envelope.compiler_version,
        "compilerDigest": envelope.compiler_digest,
        "envelopeId": envelope.envelope_id,
        "envelopeDigest": envelope.envelope_digest,
        "proposalId": proposal.proposal_id,
        "proposalDigest": proposal.proposal_digest,
        "decisionId": decision.decision_id,
        "decisionDigest": decision.decision_digest,
        "snapshot": decision.snapshot.model_dump(mode="json", by_alias=True),
        "requestId": proposal.request_id,
        "requestDigest": proposal.request_digest,
    }
    return "action-permit_" + graph_digest(
        "pajin.action.permit-id/v1",
        material,
        max_bytes=_MAX_ACTION_PERMIT_BYTES,
    )


def _normalize_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires an explicit UTC offset or Z")
    return value.astimezone(UTC)


def _canonical_capability(
    capability: RegisteredActionCapability,
) -> RegisteredActionCapability:
    try:
        return RegisteredActionCapability.model_validate(
            capability.model_dump(mode="json", by_alias=True)
        )
    except ValidationError as exc:
        raise ActionPermitError("Registered Action Capability is not canonical") from exc


def _canonical_envelope(envelope: MissionEnvelope) -> MissionEnvelope:
    try:
        return MissionEnvelope.model_validate(envelope.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("MissionEnvelope is not canonical") from exc


def _canonical_action_proposal(proposal: ActionProposal) -> ActionProposal:
    try:
        return ActionProposal.model_validate(proposal.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("ActionProposal is not canonical") from exc


def _canonical_graph_decision(decision: GraphDecision) -> GraphDecision:
    try:
        return GraphDecision.model_validate(decision.model_dump(mode="json", by_alias=True))
    except ValidationError as exc:
        raise ActionPermitError("GraphDecision is not canonical") from exc
