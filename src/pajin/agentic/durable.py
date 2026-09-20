"""Single-host durable coordination for the bounded agentic campaign runtime.

This module is deliberately narrower than a distributed queue.  It provides one
SQLite authority for an immutable deployment binding, a compare-and-swap
Dynamic Supervisor head, transactional command outbox publication, and an exact
Hypothesis-expansion invocation claim.  Once delivery or model dispatch starts,
the durable state is outcome-unknown until an exact terminal receipt arrives;
there is no lease expiry and no automatic redispatch.

Raw ``DynamicSupervisorCheckpoint`` values remain audit-only.  A caller must
obtain an opaque current-head handle from this store and independently reverify
the current Graph Snapshot before asking this module to restore a Supervisor.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
import sys
import threading
import uuid
import weakref
from _thread import RLock as RLockType
from collections.abc import Awaitable, Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Final, Literal, Never, Self, SupportsIndex, cast, final
from urllib.parse import quote

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.agentic.durable_graph import (
    AgenticGraphHeadError,
    CurrentGraphHeadResolver,
    VerifiedCurrentGraphHead,
)
from pajin.agentic.frontier import FrontierCandidate, PathScoringPolicy
from pajin.agentic.models import (
    AgentControlCommand,
    AgentControlCommandKind,
    AgentEvent,
    AgenticStrictModel,
    AgentSessionSnapshot,
    AgentSessionState,
    ExploitGroupDefinition,
    Identifier,
    PentestSpecialization,
    Sha256,
    SpecialistDefinition,
    _canonical_identifiers,
    _literal_false,
)
from pajin.agentic.runtime import (
    HypothesisExpansionContext,
    HypothesisExpansionDraft,
    HypothesisModelProjection,
    _build_expansion_chat,
    build_hypothesis_model_projection,
)
from pajin.agentic.specialist_attempts import (
    AgenticSpecialistJobAttempt,
    AgenticSpecialistJobAttemptState,
    AgenticSpecialistTargetIOState,
    AgenticSpecialistTerminalKind,
    AgenticSpecialistTerminalReceipt,
    build_specialist_claim_verification,
    build_specialist_dispatch_verification,
)
from pajin.agentic.specialist_backend_v2 import SignedSpecialistBackendResultV2
from pajin.agentic.specialist_gateway_v2 import (
    _DEPLOYMENT_CLAIM_AUTHORITY,
    _MINT_LEASE_IDENTITY_IMPLEMENTATION,
    _MINT_LEASE_INIT_IMPLEMENTATION,
    _VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION,
    _VERIFIED_COMPLETION_INIT_IMPLEMENTATION,
    _VERIFIED_DEPLOYMENT_CLAIM_OBSERVATION_IMPLEMENTATION,
    _VERIFIED_DEPLOYMENT_CLAIM_SCOPE_IMPLEMENTATION,
    _VERIFIED_DEPLOYMENT_EXECUTE_CLAIM_IMPLEMENTATION,
    _VERIFIED_DEPLOYMENT_INVOCATION_COUNT_PROPERTY,
    _VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION,
    _VERIFIED_DEPLOYMENT_SNAPSHOT_PROPERTY,
    _VERIFIED_DEPLOYMENT_WORKER_JOB_IMPLEMENTATION,
    SpecialistGatewayDeploymentV2Error,
    SpecialistWorkerJobRefV2,
    VerifiedSpecialistGatewayDeploymentV2,
    _SpecialistGatewayDeploymentClaimObservationV2,
    _VerifiedSpecialistGatewayCompletionV2,
    _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
)
from pajin.agentic.supervisor import (
    DynamicSupervisor,
    DynamicSupervisorCheckpoint,
    DynamicSupervisorCycle,
    DynamicSupervisorPolicy,
    FrontierDecision,
    FrontierDisposition,
    IssuedCommandBinding,
)
from pajin.capabilities.activation import (
    PreparedCapabilityAction,
    capability_grant_digest,
)
from pajin.capabilities.adapters import registered_action_capability
from pajin.capabilities.lifecycle import CapabilityReleaseRef
from pajin.capabilities.models import CapabilityDefinition
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.domain.models import (
    AutonomyLevel,
    CampaignManifest,
    CapabilityGrant,
    ToolRiskTier,
    campaign_manifest_digest,
)
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalCapabilityPolicy,
    ActionApprovalCapabilityPolicyRegistry,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ApprovedActionDispatchResult,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
)
from pajin.graph.authority import (
    ActionCapabilityRegistry,
    ActionPermit,
    ActionPermitAuthorization,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
)
from pajin.graph.consistency import GraphDecision, GraphDecisionKind
from pajin.graph.projection import GraphSnapshot, graph_snapshot_ref
from pajin.graph.sqlite_store import SQLiteGraphActionPermitStore, SQLiteGraphStore
from pajin.policy.capability import CapabilityLedger
from pajin.providers.models import ProviderChatRequest
from pajin.runtime.store import load_verified_run_artifacts, validate_run_artifact_path
from pajin.web_assessment.governed_models import (
    ProvisionedWebAccountReceiptRef,
    SignedWebActionApproval,
    WebActionApprovalInputAuthority,
    WebAssessmentSigningRole,
    WebAssessmentVerificationKey,
)

if TYPE_CHECKING:
    from pajin.agentic.specialist_preparation import AgenticSpecialistPreparation
    from pajin.capabilities.agentic_web_specialist import WebSpecialistCapabilityActivation
    from pajin.capabilities.agentic_web_specialist_v2 import (
        WebSQLSpecialistCapabilityActivationV2,
    )

AGENTIC_COORDINATION_API_VERSION: Literal["pajin.dev/agentic-coordination/v1alpha1"] = (
    "pajin.dev/agentic-coordination/v1alpha1"
)

_SCHEMA_VERSION = 6
AGENTIC_COORDINATION_SCHEMA_V5_DIGEST = (
    "dc32a91970da8cddd0bd6a4d2c02cffcbe9bcba484676eb18072e0fb8f52c314"
)
AGENTIC_COORDINATION_SCHEMA_V6_DIGEST = (
    "0a20a2ffbd8d5bb07519ec95c62382303ef9fca20595657851f84d994eccf6ee"
)
_APPLICATION_ID = 0x50414A41  # ASCII "PAJA"
_BUSY_TIMEOUT_MS = 30_000
_MAX_BINDING_BYTES = 64 * 1024
_MAX_CHECKPOINT_BYTES = 16 * 1024 * 1024
_MAX_CYCLE_BYTES = 32 * 1024 * 1024
_MAX_COMMAND_BYTES = 512 * 1024
_MAX_EVENT_BYTES = 512 * 1024
_MAX_INTENT_BYTES = 4 * 1024 * 1024
_MAX_REQUEST_BINDING_BYTES = 2 * 1024 * 1024
_MAX_RECEIPT_BYTES = 512 * 1024
_MAX_SPECIALIST_DISPATCH_PLAN_BYTES = 2 * 1024 * 1024
_MAX_SPECIALIST_JOB_ATTEMPT_BYTES = 512 * 1024
_AGENTIC_SPECIALIST_PERMIT_TTL = timedelta(seconds=30)
_STORE_ID_PATTERN = r"^agentic-store:[a-f0-9]{32}$"
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_INVOCATION_RECEIPT_PATH = "agentic/hypothesis-invocation-receipt.json"
_SQLITE_DESCRIPTOR_OPEN_LOCK = threading.RLock()
_CAPABILITY_LEDGER_RECORD_IMPLEMENTATION = CapabilityLedger.record
_CAPABILITY_LEDGER_CAN_CONSUME_IMPLEMENTATION = CapabilityLedger.can_consume
_CAPABILITY_LEDGER_CONSUME_IMPLEMENTATION = CapabilityLedger.consume
_GRAPH_APPROVED_DISPATCH_IMPLEMENTATION = GraphApprovedActionPermitDispatcher.dispatch_once
_GRAPH_APPROVED_AUTHORIZE_IMPLEMENTATION = GraphApprovedActionPermitAuthority.authorize_for_dispatch
_GRAPH_APPROVED_LOOKUP_IMPLEMENTATION = SQLiteGraphActionPermitStore.approved_authorization
_GRAPH_APPROVED_CLAIM_WRITER_IMPLEMENTATION = SQLiteGraphActionPermitStore.claim_approved_writer
_GRAPH_APPROVED_STORE_AUTHORIZE_IMPLEMENTATION = (
    SQLiteGraphActionPermitStore.authorize_approved_for_dispatch
)
_WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION = WebActionApprovalInputAuthority.verify_action_approval
_EXECUTABLE_SPECIALIST_CAPABILITY_ID = "pajin.bug-bounty.web-specialist.sql-login"
_EXECUTABLE_SPECIALIST_CAPABILITY_VERSION = "2.0.0"
_EXECUTABLE_SPECIALIST_TOOL_ID = "web.specialist.sql-login.v2"
_EXECUTABLE_SPECIALIST_TOOL_VERSION = "2.0.0"
_SPECIALIST_CLAIM_VERIFICATION_BUILD_IMPLEMENTATION = build_specialist_claim_verification
_SPECIALIST_DISPATCH_VERIFICATION_BUILD_IMPLEMENTATION = build_specialist_dispatch_verification
_PROVEN_TERMINAL_INSERT_AUTHORITY: Final = object()
class AgenticCoordinationError(RuntimeError):
    """Raised when durable agentic coordination cannot remain exact."""


class AgenticModelInvocationState(StrEnum):
    """Closed lifecycle for one model request that must not be redispatched."""

    CLAIMED = "claimed"
    DISPATCH_STARTED_OUTCOME_UNKNOWN = "dispatch-started-outcome-unknown"
    TERMINAL_SUCCESS = "terminal-success"
    TERMINAL_FAILURE = "terminal-failure"


class AgenticOutboxState(StrEnum):
    """Closed delivery lifecycle without timeout-based claim recycling."""

    PENDING = "pending"
    DELIVERY_STARTED_OUTCOME_UNKNOWN = "delivery-started-outcome-unknown"
    ACKNOWLEDGED = "acknowledged"


class AgenticSpecialistExecutionState(StrEnum):
    """Durable one-way state before a governed specialist callback exists."""

    RESERVED = "reserved"
    DISPATCH_STARTED_OUTCOME_UNKNOWN = "dispatch-started-outcome-unknown"


class AgenticSpecialistDispatchPlanState(StrEnum):
    """Closed durable state for one specialist approval-to-dispatch handoff."""

    AWAITING_PERMIT = "awaiting-permit"
    DISPATCH_STARTED_OUTCOME_UNKNOWN = "dispatch-started-outcome-unknown"
    PERMIT_CONSUMED_ENTRY_UNKNOWN = "permit-consumed-entry-unknown"


class AgenticSpecialistRuntimeGeneration(StrEnum):
    """Durable deployment generation pin for mutually exclusive Permit runtimes."""

    LEGACY_V1 = "legacy-v1"
    SQL_SPECIALIST_V2 = "sql-specialist-v2"


def _require_sql_specialist_v2_activation_implementations(
    activation: WebSQLSpecialistCapabilityActivationV2,
) -> None:
    from pajin.capabilities.agentic_web_specialist_v2 import (
        _WEB_SQL_SPECIALIST_V2_ACTION_REGISTRY_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_BUNDLE_CAPABILITY_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_COMPILE_REQUEST_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_DEFINITION_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_PREPARE_ACTION_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_RESOLVE_FOR_DISPATCH_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_RESOLVE_PARAMETERS_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION,
        WebSQLSpecialistAuthorizationToolV2,
        WebSQLSpecialistCapabilityActivationV2,
        WebSQLSpecialistCapabilityBundleV2,
    )

    tool = activation.bundle.tool
    activation_shadows = getattr(activation, "__dict__", {})
    tool_shadows = getattr(tool, "__dict__", {})
    if (
        type(activation) is not WebSQLSpecialistCapabilityActivationV2
        or type(tool) is not WebSQLSpecialistAuthorizationToolV2
        or type(activation.bundle) is not WebSQLSpecialistCapabilityBundleV2
        or WebSQLSpecialistCapabilityActivationV2.action_registry
        is not _WEB_SQL_SPECIALIST_V2_ACTION_REGISTRY_IMPLEMENTATION
        or WebSQLSpecialistCapabilityActivationV2.definition
        is not _WEB_SQL_SPECIALIST_V2_DEFINITION_IMPLEMENTATION
        or WebSQLSpecialistCapabilityActivationV2.prepare_action
        is not _WEB_SQL_SPECIALIST_V2_PREPARE_ACTION_IMPLEMENTATION
        or WebSQLSpecialistCapabilityActivationV2.resolve_for_dispatch
        is not _WEB_SQL_SPECIALIST_V2_RESOLVE_FOR_DISPATCH_IMPLEMENTATION
        or WebSQLSpecialistAuthorizationToolV2.compile_request
        is not _WEB_SQL_SPECIALIST_V2_COMPILE_REQUEST_IMPLEMENTATION
        or WebSQLSpecialistAuthorizationToolV2._require_identity
        is not _WEB_SQL_SPECIALIST_V2_REQUIRE_IDENTITY_IMPLEMENTATION
        or WebSQLSpecialistAuthorizationToolV2._resolve_parameters
        is not _WEB_SQL_SPECIALIST_V2_RESOLVE_PARAMETERS_IMPLEMENTATION
        or WebSQLSpecialistAuthorizationToolV2.validate_request
        is not _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION
        or WebSQLSpecialistCapabilityBundleV2.capability
        is not _WEB_SQL_SPECIALIST_V2_BUNDLE_CAPABILITY_IMPLEMENTATION
        or any(
            name in activation_shadows
            for name in ("action_registry", "definition", "prepare_action")
        )
        or any(
            name in tool_shadows
            for name in (
                "compile_request",
                "validate_request",
                "_require_identity",
                "_resolve_parameters",
            )
        )
    ):
        raise AgenticCoordinationError("SQL specialist v2 activation implementation changed")


def _sql_specialist_v2_definition_and_registry(
    activation: WebSQLSpecialistCapabilityActivationV2,
) -> tuple[CapabilityDefinition, ActionCapabilityRegistry]:
    from pajin.capabilities.agentic_web_specialist_v2 import (
        _WEB_SQL_SPECIALIST_V2_ACTION_REGISTRY_IMPLEMENTATION,
        _WEB_SQL_SPECIALIST_V2_DEFINITION_IMPLEMENTATION,
    )

    _require_sql_specialist_v2_activation_implementations(activation)
    return (
        _WEB_SQL_SPECIALIST_V2_DEFINITION_IMPLEMENTATION(activation),
        _WEB_SQL_SPECIALIST_V2_ACTION_REGISTRY_IMPLEMENTATION(activation),
    )


def _prepare_current_sql_specialist_v2_action(
    activation: WebSQLSpecialistCapabilityActivationV2,
    *,
    release: CapabilityReleaseRef,
    preparation_id: str,
    preparation_digest: str,
    account_receipt_ref: ProvisionedWebAccountReceiptRef,
) -> PreparedCapabilityAction:
    from pajin.capabilities.agentic_web_specialist_v2 import (
        _WEB_SQL_SPECIALIST_V2_PREPARE_ACTION_IMPLEMENTATION,
    )

    _require_sql_specialist_v2_activation_implementations(activation)
    return _WEB_SQL_SPECIALIST_V2_PREPARE_ACTION_IMPLEMENTATION(
        activation,
        release=release,
        preparation_id=preparation_id,
        preparation_digest=preparation_digest,
        account_receipt_ref=account_receipt_ref,
    )


def _validate_current_sql_specialist_v2_request(
    activation: WebSQLSpecialistCapabilityActivationV2,
    request: object,
) -> None:
    from pajin.capabilities.agentic_web_specialist_v2 import (
        _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION,
    )
    from pajin.domain.models import ToolRequest

    _require_sql_specialist_v2_activation_implementations(activation)
    if type(request) is not ToolRequest:
        raise AgenticCoordinationError("SQL specialist v2 request is not exact")
    _WEB_SQL_SPECIALIST_V2_VALIDATE_REQUEST_IMPLEMENTATION(
        activation.bundle.tool,
        request,
    )


def _utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    normalized = value.astimezone(UTC)
    offset = normalized.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError(f"{label} must normalize to UTC")
    return normalized


def _format_timestamp(value: datetime) -> str:
    return (
        _utc(value, label="coordination timestamp")
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _parse_timestamp(value: str, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise AgenticCoordinationError(f"{label} is not canonical UTC")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise AgenticCoordinationError(f"{label} is invalid") from exc
    parsed = _utc(parsed, label=label)
    if _format_timestamp(parsed) != value:
        raise AgenticCoordinationError(f"{label} is not canonical UTC")
    return parsed


class AgenticCoordinationBinding(AgenticStrictModel):
    """Immutable deployment and Supervisor configuration accepted by one store."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-coordination/v1alpha1"] = Field(
        default=AGENTIC_COORDINATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticCoordinationBinding"] = "AgenticCoordinationBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=96)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    control_plane_run_id: Identifier = Field(alias="controlPlaneRunId")
    campaign_id: str = Field(
        alias="campaignId",
        min_length=3,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    campaign_manifest_digest: Sha256 = Field(alias="campaignManifestDigest")
    deployment_digest: Sha256 = Field(alias="deploymentDigest")
    supervisor_agent_id: Identifier = Field(alias="supervisorAgentId")
    source_snapshot_id: Identifier = Field(alias="sourceSnapshotId")
    source_snapshot_digest: Sha256 = Field(alias="sourceSnapshotDigest")
    initial_checkpoint_id: str = Field(
        alias="initialCheckpointId",
        pattern=r"^agentic-checkpoint_[a-f0-9]{64}$",
    )
    initial_checkpoint_digest: Sha256 = Field(alias="initialCheckpointDigest")
    exploit_group_id: str = Field(
        alias="exploitGroupId",
        pattern=r"^exploit-group_[a-f0-9]{64}$",
    )
    exploit_group_digest: Sha256 = Field(alias="exploitGroupDigest")
    exploit_group: ExploitGroupDefinition = Field(alias="exploitGroup")
    supervisor_policy_id: str = Field(
        alias="supervisorPolicyId",
        pattern=r"^dynamic-supervisor-policy_[a-f0-9]{64}$",
    )
    supervisor_policy_digest: Sha256 = Field(alias="supervisorPolicyDigest")
    supervisor_policy: DynamicSupervisorPolicy = Field(alias="supervisorPolicy")
    scoring_policy_id: str = Field(
        alias="scoringPolicyId",
        pattern=r"^path-scoring-policy_[a-f0-9]{64}$",
    )
    scoring_policy_digest: Sha256 = Field(alias="scoringPolicyDigest")
    scoring_policy: PathScoringPolicy = Field(alias="scoringPolicy")
    allowed_target_ids: tuple[Identifier, ...] = Field(
        alias="allowedTargetIds",
        min_length=1,
    )

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        _canonical_identifiers(self.allowed_target_ids, label="allowed Target IDs")
        if (
            self.exploit_group.group_id != self.exploit_group_id
            or self.exploit_group.group_digest != self.exploit_group_digest
            or self.supervisor_policy.policy_id != self.supervisor_policy_id
            or self.supervisor_policy.policy_digest != self.supervisor_policy_digest
            or self.scoring_policy.policy_id != self.scoring_policy_id
            or self.scoring_policy.policy_digest != self.scoring_policy_digest
        ):
            raise ValueError("Agentic Coordination Binding configuration differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = discovery_digest("pajin.agentic.coordination-binding/v1", material)
        expected_id = f"agentic-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("Agentic Coordination Binding Digest differs")
        if self.binding_id and self.binding_id != expected_id:
            raise ValueError("Agentic Coordination Binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", expected_id)
        return self

    @classmethod
    def from_checkpoint(
        cls,
        checkpoint: DynamicSupervisorCheckpoint,
        *,
        control_plane_run_id: str,
        campaign_manifest_digest: str,
        deployment_digest: str,
        exploit_group: ExploitGroupDefinition,
        supervisor_policy: DynamicSupervisorPolicy,
        scoring_policy: PathScoringPolicy,
    ) -> AgenticCoordinationBinding:
        canonical = DynamicSupervisorCheckpoint.model_validate(
            checkpoint.model_dump(mode="json", by_alias=True)
        )
        _require_initial_checkpoint_shape(canonical)
        return cls(
            controlPlaneRunId=control_plane_run_id,
            campaignId=canonical.campaign_id,
            campaignManifestDigest=campaign_manifest_digest,
            deploymentDigest=deployment_digest,
            supervisorAgentId=canonical.supervisor_agent_id,
            sourceSnapshotId=canonical.source_snapshot_id,
            sourceSnapshotDigest=canonical.source_snapshot_digest,
            initialCheckpointId=canonical.checkpoint_id,
            initialCheckpointDigest=canonical.checkpoint_digest,
            exploitGroupId=canonical.exploit_group_id,
            exploitGroupDigest=canonical.exploit_group_digest,
            exploitGroup=exploit_group,
            supervisorPolicyId=canonical.supervisor_policy_id,
            supervisorPolicyDigest=canonical.supervisor_policy_digest,
            supervisorPolicy=supervisor_policy,
            scoringPolicyId=canonical.scoring_policy_id,
            scoringPolicyDigest=canonical.scoring_policy_digest,
            scoringPolicy=scoring_policy,
            allowedTargetIds=canonical.allowed_target_ids,
        )

    def require_checkpoint(self, checkpoint: DynamicSupervisorCheckpoint) -> None:
        canonical = DynamicSupervisorCheckpoint.model_validate(
            checkpoint.model_dump(mode="json", by_alias=True)
        )
        observed = (
            canonical.campaign_id,
            canonical.supervisor_agent_id,
            canonical.source_snapshot_id,
            canonical.source_snapshot_digest,
            canonical.exploit_group_id,
            canonical.exploit_group_digest,
            canonical.supervisor_policy_id,
            canonical.supervisor_policy_digest,
            canonical.scoring_policy_id,
            canonical.scoring_policy_digest,
            canonical.allowed_target_ids,
        )
        expected = (
            self.campaign_id,
            self.supervisor_agent_id,
            self.source_snapshot_id,
            self.source_snapshot_digest,
            self.exploit_group_id,
            self.exploit_group_digest,
            self.supervisor_policy_id,
            self.supervisor_policy_digest,
            self.scoring_policy_id,
            self.scoring_policy_digest,
            self.allowed_target_ids,
        )
        if observed != expected:
            raise ValueError("Dynamic Supervisor checkpoint differs from deployment binding")


class AgenticHypothesisRequestBinding(AgenticStrictModel):
    """Full content-addressed model request and every execution-relevant pin."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-coordination/v1alpha1"] = Field(
        default=AGENTIC_COORDINATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticHypothesisRequestBinding"] = "AgenticHypothesisRequestBinding"
    request_binding_id: str = Field(default="", alias="requestBindingId", max_length=110)
    request_binding_digest: str = Field(
        default="",
        alias="requestBindingDigest",
        max_length=64,
    )
    projection: HypothesisModelProjection
    chat: ProviderChatRequest
    provider_id: str = Field(
        alias="providerId",
        min_length=2,
        max_length=64,
        pattern=r"^[a-z0-9][a-z0-9-]*$",
    )
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    provider_model_digest: Sha256 = Field(alias="providerModelDigest")
    model_configuration_digest: Sha256 = Field(alias="modelConfigurationDigest")
    provider_runtime_digest: Sha256 = Field(alias="providerRuntimeDigest")
    capability_grant_digest: Sha256 = Field(alias="capabilityGrantDigest")
    campaign_budget_policy_digest: Sha256 = Field(alias="campaignBudgetPolicyDigest")
    campaign_budget_state_digest: Sha256 = Field(alias="campaignBudgetStateDigest")
    dedicated_budget_policy_digest: Sha256 = Field(alias="dedicatedBudgetPolicyDigest")
    request_schema_digest: Sha256 = Field(alias="requestSchemaDigest")
    response_schema_digest: Sha256 = Field(alias="responseSchemaDigest")
    provider_chat_request_digest: Sha256 = Field(alias="providerChatRequestDigest")
    max_completion_tokens: int = Field(
        alias="maxCompletionTokens",
        strict=True,
        ge=1,
        le=131_072,
    )
    planned_provider_run_id: Identifier = Field(alias="plannedProviderRunId")
    planned_provider_run_path: str = Field(
        alias="plannedProviderRunPath",
        min_length=2,
        max_length=4_096,
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    target_request_authorized: Literal[False] = Field(
        default=False,
        alias="targetRequestAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("max_completion_tokens", mode="before")
    @classmethod
    def require_literal_integer(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("Hypothesis request token bound must be a JSON integer")
        return value

    @field_validator(
        "automatic_redispatch_authorized",
        "target_request_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_request(self) -> Self:
        projection = HypothesisModelProjection.model_validate(
            self.projection.model_dump(mode="json", by_alias=True)
        )
        chat = ProviderChatRequest.model_validate(
            self.chat.model_dump(mode="json", by_alias=True, exclude_none=False)
        )
        expected_chat = _build_expansion_chat(
            projection,
            max_completion_tokens=self.max_completion_tokens,
        )
        if chat != expected_chat:
            raise ValueError("Hypothesis request chat differs from its exact projection")
        if (
            chat.stream
            or chat.tools
            or chat.tool_choice != "none"
            or chat.parallel_tool_calls is not False
            or chat.max_completion_tokens != self.max_completion_tokens
        ):
            raise ValueError("Hypothesis request chat execution boundary differs")
        request_schema = _provider_request_schema_digest()
        response_schema = _hypothesis_response_schema_digest()
        chat_digest = _provider_chat_request_digest(chat)
        if (
            self.request_schema_digest != request_schema
            or self.response_schema_digest != response_schema
            or self.provider_chat_request_digest != chat_digest
        ):
            raise ValueError("Hypothesis request schema or chat digest differs")
        planned_path = Path(self.planned_provider_run_path)
        if (
            not planned_path.is_absolute()
            or str(Path(os.path.abspath(planned_path))) != self.planned_provider_run_path
            or planned_path.name != self.planned_provider_run_id
        ):
            raise ValueError("Hypothesis request preplanned Run path differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"request_binding_id", "request_binding_digest"},
        )
        digest = discovery_digest("pajin.agentic.hypothesis-request-binding/v1", material)
        expected_id = f"agentic-hypothesis-request_{digest}"
        if self.request_binding_digest and self.request_binding_digest != digest:
            raise ValueError("Agentic Hypothesis Request Binding Digest differs")
        if self.request_binding_id and self.request_binding_id != expected_id:
            raise ValueError("Agentic Hypothesis Request Binding ID differs")
        object.__setattr__(self, "request_binding_digest", digest)
        object.__setattr__(self, "request_binding_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Agentic Hypothesis Request Binding",
            max_bytes=_MAX_REQUEST_BINDING_BYTES,
        )
        return self


def build_agentic_hypothesis_request_binding(
    projection: HypothesisModelProjection,
    *,
    provider_id: str,
    model_id: str,
    provider_model_digest: str,
    model_configuration_digest: str,
    provider_runtime_digest: str,
    capability_grant_digest: str,
    campaign_budget_policy_digest: str,
    campaign_budget_state_digest: str,
    dedicated_budget_policy_digest: str,
    max_completion_tokens: int,
    planned_provider_run_id: str,
    planned_provider_run_path: Path,
) -> AgenticHypothesisRequestBinding:
    """Compile one exact inert request; this does not authorize model dispatch."""

    canonical_projection = HypothesisModelProjection.model_validate(
        projection.model_dump(mode="json", by_alias=True)
    )
    chat = _build_expansion_chat(
        canonical_projection,
        max_completion_tokens=max_completion_tokens,
    )
    return AgenticHypothesisRequestBinding(
        projection=canonical_projection,
        chat=chat,
        providerId=provider_id,
        modelId=model_id,
        providerModelDigest=provider_model_digest,
        modelConfigurationDigest=model_configuration_digest,
        providerRuntimeDigest=provider_runtime_digest,
        capabilityGrantDigest=capability_grant_digest,
        campaignBudgetPolicyDigest=campaign_budget_policy_digest,
        campaignBudgetStateDigest=campaign_budget_state_digest,
        dedicatedBudgetPolicyDigest=dedicated_budget_policy_digest,
        requestSchemaDigest=_provider_request_schema_digest(),
        responseSchemaDigest=_hypothesis_response_schema_digest(),
        providerChatRequestDigest=_provider_chat_request_digest(chat),
        maxCompletionTokens=max_completion_tokens,
        plannedProviderRunId=planned_provider_run_id,
        plannedProviderRunPath=str(Path(os.path.abspath(planned_provider_run_path))),
    )


def build_agentic_hypothesis_invocation_receipt(
    entry: AgenticModelInvocationEntry,
    *,
    succeeded: bool,
    outcome_digest: str,
    recorded_at: datetime,
) -> AgenticHypothesisInvocationReceipt:
    """Build the terminal claim that must then be written and sealed by a RunStore."""

    if type(succeeded) is not bool:
        raise TypeError("invocation success marker must be a JSON boolean")
    canonical = AgenticModelInvocationEntry.model_validate(
        entry.model_dump(mode="json", by_alias=True)
    )
    if canonical.state is not AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN:
        raise ValueError("only an exact started invocation can produce a terminal receipt")
    _require_digest(outcome_digest, label="invocation outcome digest")
    binding = canonical.intent.request_binding
    return AgenticHypothesisInvocationReceipt(
        intentId=canonical.intent.intent_id,
        intentDigest=canonical.intent.intent_digest,
        stableRequestId=canonical.intent.stable_request_id,
        requestBindingId=binding.request_binding_id,
        requestBindingDigest=binding.request_binding_digest,
        providerRunId=binding.planned_provider_run_id,
        providerId=binding.provider_id,
        modelId=binding.model_id,
        providerModelDigest=binding.provider_model_digest,
        modelConfigurationDigest=binding.model_configuration_digest,
        providerRuntimeDigest=binding.provider_runtime_digest,
        capabilityGrantDigest=binding.capability_grant_digest,
        campaignBudgetPolicyDigest=binding.campaign_budget_policy_digest,
        campaignBudgetStateDigest=binding.campaign_budget_state_digest,
        dedicatedBudgetPolicyDigest=binding.dedicated_budget_policy_digest,
        providerChatRequestDigest=binding.provider_chat_request_digest,
        terminalState="success" if succeeded else "failure",
        outcomeDigest=outcome_digest,
        recordedAt=cast(datetime, _format_timestamp(recorded_at)),
    )


class AgenticHypothesisInvocationIntent(AgenticStrictModel):
    """Exact durable claim for one target-neutral Hypothesis model request."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-coordination/v1alpha1"] = Field(
        default=AGENTIC_COORDINATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticHypothesisInvocationIntent"] = "AgenticHypothesisInvocationIntent"
    intent_id: str = Field(default="", alias="intentId", max_length=96)
    intent_digest: str = Field(default="", alias="intentDigest", max_length=64)
    stable_request_id: str = Field(
        alias="stableRequestId",
        pattern=r"^hypothesis-request_[a-f0-9]{64}$",
    )
    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_id: str = Field(
        alias="coordinationBindingId",
        pattern=r"^agentic-binding_[a-f0-9]{64}$",
    )
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    source_checkpoint_id: str = Field(
        alias="sourceCheckpointId",
        pattern=r"^agentic-checkpoint_[a-f0-9]{64}$",
    )
    source_checkpoint_digest: Sha256 = Field(alias="sourceCheckpointDigest")
    context_id: str = Field(
        alias="contextId",
        pattern=r"^hypothesis-context_[a-f0-9]{64}$",
    )
    context_digest: Sha256 = Field(alias="contextDigest")
    context: HypothesisExpansionContext
    projection_id: str = Field(
        alias="projectionId",
        pattern=r"^hypothesis-projection_[a-f0-9]{64}$",
    )
    projection_digest: Sha256 = Field(alias="projectionDigest")
    request_binding_id: str = Field(
        alias="requestBindingId",
        pattern=r"^agentic-hypothesis-request_[a-f0-9]{64}$",
    )
    request_binding_digest: Sha256 = Field(alias="requestBindingDigest")
    request_binding: AgenticHypothesisRequestBinding = Field(alias="requestBinding")
    provider_run_id: Identifier = Field(alias="providerRunId")
    claimed_at: datetime = Field(alias="claimedAt")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    capability_granted: Literal[False] = Field(default=False, alias="capabilityGranted")
    permit_granted: Literal[False] = Field(default=False, alias="permitGranted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(
        "automatic_redispatch_authorized",
        "capability_granted",
        "permit_granted",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        field_name = cast(str | None, getattr(info, "field_name", None))
        return _literal_false(value, label=field_name)

    @field_validator("claimed_at")
    @classmethod
    def require_utc_claim(cls, value: datetime) -> datetime:
        return _utc(value, label="invocation claimed_at")

    @model_validator(mode="after")
    def bind_identity(self) -> Self:
        if (
            self.context_id != self.context.context_id
            or self.context_digest != self.context.context_digest
            or self.request_binding_id != self.request_binding.request_binding_id
            or self.request_binding_digest != self.request_binding.request_binding_digest
            or self.projection_id != self.request_binding.projection.projection_id
            or self.projection_digest != self.request_binding.projection.projection_digest
            or self.provider_run_id != self.request_binding.planned_provider_run_id
        ):
            raise ValueError("Hypothesis invocation differs from its full request binding")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"intent_id", "intent_digest"},
        )
        digest = discovery_digest("pajin.agentic.hypothesis-invocation-intent/v1", material)
        expected_id = f"agentic-invocation_{digest}"
        if self.intent_digest and self.intent_digest != digest:
            raise ValueError("Agentic Hypothesis Invocation Intent Digest differs")
        if self.intent_id and self.intent_id != expected_id:
            raise ValueError("Agentic Hypothesis Invocation Intent ID differs")
        object.__setattr__(self, "intent_digest", digest)
        object.__setattr__(self, "intent_id", expected_id)
        return self


class AgenticModelInvocationEntry(AgenticStrictModel):
    """Verified mutable head for one immutable invocation intent."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    intent: AgenticHypothesisInvocationIntent
    state: AgenticModelInvocationState
    state_digest: str = Field(default="", alias="stateDigest", max_length=64)
    dispatch_started_at: datetime | None = Field(default=None, alias="dispatchStartedAt")
    terminal_at: datetime | None = Field(default=None, alias="terminalAt")
    outcome_digest: Sha256 | None = Field(default=None, alias="outcomeDigest")
    receipt_reference: Identifier | None = Field(default=None, alias="receiptReference")
    receipt_digest: Sha256 | None = Field(default=None, alias="receiptDigest")
    receipt_run_path: str | None = Field(default=None, alias="receiptRunPath")
    receipt_run_id: Identifier | None = Field(default=None, alias="receiptRunId")
    receipt_root_digest: Sha256 | None = Field(default=None, alias="receiptRootDigest")
    receipt_artifact_path: str | None = Field(default=None, alias="receiptArtifactPath")
    receipt_artifact_sha256: Sha256 | None = Field(
        default=None,
        alias="receiptArtifactSha256",
    )
    manual_review_required: bool = Field(alias="manualReviewRequired")
    redispatch_allowed: Literal[False] = Field(default=False, alias="redispatchAllowed")

    @field_validator("manual_review_required", "redispatch_allowed", mode="before")
    @classmethod
    def require_boolean(cls, value: object, info: object) -> object:
        if type(value) is not bool:
            field_name = getattr(info, "field_name", "invocation flag")
            raise ValueError(f"{field_name} must be a JSON boolean")
        return value

    @field_validator("dispatch_started_at", "terminal_at")
    @classmethod
    def require_utc_optional(cls, value: datetime | None) -> datetime | None:
        return _utc(value, label="invocation timestamp") if value is not None else None

    @model_validator(mode="after")
    def bind_state(self) -> Self:
        terminal = self.state in {
            AgenticModelInvocationState.TERMINAL_SUCCESS,
            AgenticModelInvocationState.TERMINAL_FAILURE,
        }
        if self.state is AgenticModelInvocationState.CLAIMED:
            expected = (False, False, False, False, False)
        elif self.state is AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN:
            expected = (True, False, False, False, True)
        else:
            expected = (True, True, True, True, False)
        receipt_publication = (
            self.receipt_run_path,
            self.receipt_run_id,
            self.receipt_root_digest,
            self.receipt_artifact_path,
            self.receipt_artifact_sha256,
        )
        receipt_publication_present = all(item is not None for item in receipt_publication)
        if any(item is not None for item in receipt_publication) != receipt_publication_present:
            raise ValueError("Agentic invocation receipt publication fields are partial")
        observed = (
            self.dispatch_started_at is not None,
            self.terminal_at is not None,
            self.outcome_digest is not None,
            self.receipt_reference is not None
            and self.receipt_digest is not None
            and receipt_publication_present,
            self.manual_review_required,
        )
        if observed != expected or (
            (self.receipt_reference is None) != (self.receipt_digest is None)
        ):
            raise ValueError("Agentic model invocation state differs")
        if (
            self.dispatch_started_at is not None
            and self.dispatch_started_at < self.intent.claimed_at
        ):
            raise ValueError("Agentic model invocation dispatch predates its claim")
        if terminal and (
            self.dispatch_started_at is None
            or self.terminal_at is None
            or self.terminal_at < self.dispatch_started_at
        ):
            raise ValueError("Agentic model invocation terminal timestamp differs")
        digest = _invocation_state_digest(
            intent_digest=self.intent.intent_digest,
            state=self.state,
            dispatch_started_at=self.dispatch_started_at,
            terminal_at=self.terminal_at,
            outcome_digest=self.outcome_digest,
            receipt_reference=self.receipt_reference,
            receipt_digest=self.receipt_digest,
            receipt_run_path=self.receipt_run_path,
            receipt_run_id=self.receipt_run_id,
            receipt_root_digest=self.receipt_root_digest,
            receipt_artifact_path=self.receipt_artifact_path,
            receipt_artifact_sha256=self.receipt_artifact_sha256,
        )
        if self.state_digest and self.state_digest != digest:
            raise ValueError("Agentic model invocation State Digest differs")
        object.__setattr__(self, "state_digest", digest)
        return self


class AgenticOutboxEntry(AgenticStrictModel):
    """Verified command publication and its one-shot delivery state."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    cycle_id: str = Field(alias="cycleId", pattern=r"^agentic-cycle_[a-f0-9]{64}$")
    cycle_digest: Sha256 = Field(alias="cycleDigest")
    ordinal: int = Field(strict=True, ge=1)
    command: AgentControlCommand
    command_digest: Sha256 = Field(alias="commandDigest")
    state: AgenticOutboxState
    state_digest: str = Field(default="", alias="stateDigest", max_length=64)
    claimed_at: datetime | None = Field(default=None, alias="claimedAt")
    claim_id: str | None = Field(
        default=None,
        alias="claimId",
        pattern=r"^agentic-delivery-claim_[a-f0-9]{64}$",
    )
    claim_digest: Sha256 | None = Field(default=None, alias="claimDigest")
    acknowledged_at: datetime | None = Field(default=None, alias="acknowledgedAt")
    acknowledgement_id: Identifier | None = Field(default=None, alias="acknowledgementId")
    acknowledgement_digest: Sha256 | None = Field(
        default=None,
        alias="acknowledgementDigest",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )

    @field_validator("automatic_redispatch_authorized", mode="before")
    @classmethod
    def require_false_marker(cls, value: object) -> object:
        return _literal_false(value, label="automatic_redispatch_authorized")

    @field_validator("claimed_at", "acknowledged_at")
    @classmethod
    def require_utc_optional(cls, value: datetime | None) -> datetime | None:
        return _utc(value, label="outbox timestamp") if value is not None else None

    @model_validator(mode="after")
    def bind_state(self) -> Self:
        command_digest = _command_digest(self.command)
        if self.command_digest != command_digest:
            raise ValueError("Agentic outbox Command Digest differs")
        claim_present = all(
            item is not None for item in (self.claimed_at, self.claim_id, self.claim_digest)
        )
        ack_present = all(
            item is not None
            for item in (
                self.acknowledged_at,
                self.acknowledgement_id,
                self.acknowledgement_digest,
            )
        )
        if (
            any(item is not None for item in (self.claimed_at, self.claim_id, self.claim_digest))
            != claim_present
        ):
            raise ValueError("Agentic outbox claim fields are partial")
        if (
            any(
                item is not None
                for item in (
                    self.acknowledged_at,
                    self.acknowledgement_id,
                    self.acknowledgement_digest,
                )
            )
            != ack_present
        ):
            raise ValueError("Agentic outbox acknowledgement fields are partial")
        expected = {
            AgenticOutboxState.PENDING: (False, False),
            AgenticOutboxState.DELIVERY_STARTED_OUTCOME_UNKNOWN: (True, False),
            AgenticOutboxState.ACKNOWLEDGED: (True, True),
        }[self.state]
        if (claim_present, ack_present) != expected:
            raise ValueError("Agentic outbox state differs")
        if self.acknowledged_at is not None and (
            self.claimed_at is None or self.acknowledged_at < self.claimed_at
        ):
            raise ValueError("Agentic outbox acknowledgement predates delivery")
        if claim_present:
            assert self.claimed_at is not None
            expected_claim = _delivery_claim_digest(
                store_id=self.store_id,
                coordination_binding_digest=self.coordination_binding_digest,
                cycle_digest=self.cycle_digest,
                command_id=self.command.command_id,
                command_digest=self.command_digest,
                claimed_at=self.claimed_at,
            )
            if self.claim_digest != expected_claim or self.claim_id != (
                f"agentic-delivery-claim_{expected_claim}"
            ):
                raise ValueError("Agentic outbox delivery claim differs")
        digest = _outbox_state_digest(
            cycle_digest=self.cycle_digest,
            command_digest=self.command_digest,
            state=self.state,
            claimed_at=self.claimed_at,
            claim_digest=self.claim_digest,
            acknowledged_at=self.acknowledged_at,
            acknowledgement_id=self.acknowledgement_id,
            acknowledgement_digest=self.acknowledgement_digest,
        )
        if self.state_digest and self.state_digest != digest:
            raise ValueError("Agentic outbox State Digest differs")
        object.__setattr__(self, "state_digest", digest)
        return self


class AgenticOutboxDeliveryClaim(AgenticStrictModel):
    """Opaque-by-identity claim returned exactly once before delivery."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    cycle_id: str = Field(alias="cycleId", pattern=r"^agentic-cycle_[a-f0-9]{64}$")
    cycle_digest: Sha256 = Field(alias="cycleDigest")
    command: AgentControlCommand
    command_digest: Sha256 = Field(alias="commandDigest")
    claimed_at: datetime = Field(alias="claimedAt")
    claim_id: str = Field(alias="claimId", pattern=r"^agentic-delivery-claim_[a-f0-9]{64}$")
    claim_digest: Sha256 = Field(alias="claimDigest")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )

    @field_validator("automatic_redispatch_authorized", mode="before")
    @classmethod
    def require_false_marker(cls, value: object) -> object:
        return _literal_false(value, label="automatic_redispatch_authorized")

    @field_validator("claimed_at")
    @classmethod
    def require_utc_claim(cls, value: datetime) -> datetime:
        return _utc(value, label="delivery claimed_at")

    @model_validator(mode="after")
    def bind_claim(self) -> Self:
        if self.command_digest != _command_digest(self.command):
            raise ValueError("Agentic delivery Command Digest differs")
        digest = _delivery_claim_digest(
            store_id=self.store_id,
            coordination_binding_digest=self.coordination_binding_digest,
            cycle_digest=self.cycle_digest,
            command_id=self.command.command_id,
            command_digest=self.command_digest,
            claimed_at=self.claimed_at,
        )
        if self.claim_digest != digest or self.claim_id != f"agentic-delivery-claim_{digest}":
            raise ValueError("Agentic delivery claim identity differs")
        return self


class AgenticCommandAdmissionReceipt(AgenticStrictModel):
    """Same-store durable receiver admission and dedupe receipt.

    This receipt proves only durable receiver admission.  It is not evidence that
    the child consumed, executed, or completed the command.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    claim_id: str = Field(alias="claimId", pattern=r"^agentic-delivery-claim_[a-f0-9]{64}$")
    claim_digest: Sha256 = Field(alias="claimDigest")
    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    command_digest: Sha256 = Field(alias="commandDigest")
    receiver_agent_id: Identifier = Field(alias="receiverAgentId")
    admitted_at: datetime = Field(alias="admittedAt")
    receiver_durable_admission: Literal[True] = Field(
        default=True,
        alias="receiverDurableAdmission",
    )
    command_consumed: Literal[False] = Field(default=False, alias="commandConsumed")
    task_completed: Literal[False] = Field(default=False, alias="taskCompleted")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("admitted_at")
    @classmethod
    def require_utc_admission(cls, value: datetime) -> datetime:
        return _utc(value, label="command admission timestamp")

    @field_validator("receiver_durable_admission", mode="before")
    @classmethod
    def require_true_marker(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("receiver durable admission marker must be true")
        return value

    @field_validator(
        "command_consumed",
        "task_completed",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = discovery_digest("pajin.agentic.command-admission-receipt/v1", material)
        expected_id = f"agentic-command-admission_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Agentic Command Admission Receipt Digest differs")
        if self.receipt_id and self.receipt_id != expected_id:
            raise ValueError("Agentic Command Admission Receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", expected_id)
        return self


class AgenticSpecialistExecutionEntry(AgenticStrictModel):
    """Audit-only durable reservation; this value is never dispatch authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    reservation_id: str = Field(
        default="",
        alias="reservationId",
        max_length=110,
    )
    reservation_digest: str = Field(
        default="",
        alias="reservationDigest",
        max_length=64,
    )
    state_digest: str = Field(default="", alias="stateDigest", max_length=64)
    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    source_head_checkpoint_id: str = Field(
        alias="sourceHeadCheckpointId",
        pattern=r"^agentic-checkpoint_[a-f0-9]{64}$",
    )
    source_head_checkpoint_digest: Sha256 = Field(alias="sourceHeadCheckpointDigest")
    graph_snapshot_id: Identifier = Field(alias="graphSnapshotId")
    graph_snapshot_digest: Sha256 = Field(alias="graphSnapshotDigest")
    cycle_id: str = Field(alias="cycleId", pattern=r"^agentic-cycle_[a-f0-9]{64}$")
    cycle_digest: Sha256 = Field(alias="cycleDigest")
    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    command_digest: Sha256 = Field(alias="commandDigest")
    admission_receipt_id: str = Field(
        alias="admissionReceiptId",
        pattern=r"^agentic-command-admission_[a-f0-9]{64}$",
    )
    admission_receipt_digest: Sha256 = Field(alias="admissionReceiptDigest")
    target_agent_id: Identifier = Field(alias="targetAgentId")
    task_id: Identifier = Field(alias="taskId")
    candidate_id: str = Field(
        alias="candidateId",
        pattern=r"^frontier-candidate_[a-f0-9]{64}$",
    )
    candidate_digest: Sha256 = Field(alias="candidateDigest")
    proposal_digest: Sha256 = Field(alias="proposalDigest")
    target_id: Identifier = Field(alias="targetId")
    threat_class: str = Field(
        alias="threatClass",
        min_length=2,
        max_length=80,
        pattern=r"^[a-z0-9][a-z0-9.-]{1,79}$",
    )
    specialization: PentestSpecialization
    specialist_definition_digest: Sha256 = Field(alias="specialistDefinitionDigest")
    state: AgenticSpecialistExecutionState
    reserved_at: datetime = Field(alias="reservedAt")
    dispatch_started_at: datetime | None = Field(default=None, alias="dispatchStartedAt")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")

    @field_validator("reserved_at", "dispatch_started_at")
    @classmethod
    def require_utc_times(cls, value: datetime | None) -> datetime | None:
        return _utc(value, label="specialist execution timestamp") if value is not None else None

    @field_validator(
        "automatic_redispatch_authorized",
        "execution_authorized",
        "finding_authority",
        "graph_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_identity_and_state(self) -> Self:
        expected_dispatch = (
            self.state is AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        )
        if expected_dispatch != (self.dispatch_started_at is not None):
            raise ValueError("specialist execution state timestamp differs")
        if self.dispatch_started_at is not None and self.dispatch_started_at < self.reserved_at:
            raise ValueError("specialist dispatch predates its reservation")
        identity_material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "reservation_id",
                "reservation_digest",
                "state",
                "state_digest",
                "dispatch_started_at",
            },
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-execution-reservation/v1",
            identity_material,
        )
        expected_id = f"agentic-specialist-reservation_{digest}"
        if self.reservation_digest and self.reservation_digest != digest:
            raise ValueError("specialist execution Reservation Digest differs")
        if self.reservation_id and self.reservation_id != expected_id:
            raise ValueError("specialist execution Reservation ID differs")
        state_digest = discovery_digest(
            "pajin.agentic.specialist-execution-state/v1",
            {
                "reservationDigest": digest,
                "state": self.state.value,
                "dispatchStartedAt": (
                    _format_timestamp(self.dispatch_started_at)
                    if self.dispatch_started_at is not None
                    else None
                ),
            },
        )
        if self.state_digest and self.state_digest != state_digest:
            raise ValueError("specialist execution State Digest differs")
        object.__setattr__(self, "reservation_digest", digest)
        object.__setattr__(self, "reservation_id", expected_id)
        object.__setattr__(self, "state_digest", state_digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist execution reservation",
            max_bytes=_MAX_COMMAND_BYTES,
        )
        return self


class AgenticSpecialistCapabilityGrantBinding(AgenticStrictModel):
    """Canonical audit binding for one live task-scoped Grant reservation."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    grant_id: str = Field(alias="grantId", min_length=1, max_length=200)
    grant_digest: Sha256 = Field(alias="grantDigest")
    parent_grant_id: str = Field(alias="parentGrantId", min_length=1, max_length=200)
    subject: Identifier
    campaign: str = Field(min_length=3, max_length=80)
    tools: tuple[Identifier, ...] = Field(min_length=1, max_length=1)
    targets: tuple[str, ...] = Field(min_length=1, max_length=1)
    max_risk_tier: Literal[ToolRiskTier.T2] = Field(alias="maxRiskTier")
    max_calls: Literal[1] = Field(alias="maxCalls")
    remaining_calls: Literal[1] = Field(alias="remainingCalls")
    expires_at: datetime = Field(alias="expiresAt")
    delegable: Literal[False] = False
    issued_at: datetime = Field(alias="issuedAt")
    depth: int = Field(ge=1, le=100)
    revoked: Literal[False] = False
    grant_authority: Literal[False] = Field(default=False, alias="grantAuthority")

    @field_validator("issued_at", "expires_at")
    @classmethod
    def require_utc_times(cls, value: datetime) -> datetime:
        return _utc(value, label="specialist Capability Grant timestamp")

    @field_validator("max_calls", "remaining_calls", mode="before")
    @classmethod
    def require_one_call(cls, value: object, info: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError(
                f"specialist Capability {getattr(info, 'field_name', 'call limit')} must be one"
            )
        return value

    @field_validator("delegable", "revoked", "grant_authority", mode="before")
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_grant(self) -> Self:
        if self.tools != tuple(sorted(set(self.tools))):
            raise ValueError("specialist Capability Grant Tools must be unique and sorted")
        if self.targets != tuple(sorted(set(self.targets))):
            raise ValueError("specialist Capability Grant Targets must be unique and sorted")
        grant = CapabilityGrant(
            grant_id=self.grant_id,
            parent_grant_id=self.parent_grant_id,
            subject=self.subject,
            campaign=self.campaign,
            tools=set(self.tools),
            targets=set(self.targets),
            max_risk_tier=self.max_risk_tier,
            max_calls=self.max_calls,
            expires_at=self.expires_at,
            delegable=self.delegable,
            issued_at=self.issued_at,
            depth=self.depth,
        )
        if capability_grant_digest(grant) != self.grant_digest:
            raise ValueError("specialist Capability Grant binding digest differs")
        return self


class AgenticSpecialistCapabilityGrantConsumptionReceipt(AgenticStrictModel):
    """Durable proof that the exact task-scoped Grant entered the crash fence."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/agentic-specialist-capability-grant-consumption-receipt/v1alpha1"
    ] = Field(
        default=("pajin.dev/agentic-specialist-capability-grant-consumption-receipt/v1alpha1"),
        alias="apiVersion",
    )
    kind: Literal["AgenticSpecialistCapabilityGrantConsumptionReceipt"] = (
        "AgenticSpecialistCapabilityGrantConsumptionReceipt"
    )
    receipt_id: str = Field(default="", alias="receiptId", max_length=120)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    plan_id: str = Field(
        alias="planId",
        pattern=r"^agentic-specialist-plan_[a-f0-9]{64}$",
    )
    plan_digest: Sha256 = Field(alias="planDigest")
    reservation_id: str = Field(
        alias="reservationId",
        pattern=r"^agentic-specialist-reservation_[a-f0-9]{64}$",
    )
    reservation_digest: Sha256 = Field(alias="reservationDigest")
    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    command_digest: Sha256 = Field(alias="commandDigest")
    capability_grant_id: str = Field(alias="capabilityGrantId", min_length=1, max_length=200)
    capability_grant_digest: Sha256 = Field(alias="capabilityGrantDigest")
    action_permit_id: str = Field(
        alias="actionPermitId",
        pattern=r"^action-permit_[a-f0-9]{64}$",
    )
    action_permit_digest: Sha256 = Field(alias="actionPermitDigest")
    approval_consumption_receipt_id: str = Field(
        alias="approvalConsumptionReceiptId",
        min_length=1,
        max_length=120,
    )
    approval_consumption_receipt_digest: Sha256 = Field(alias="approvalConsumptionReceiptDigest")
    consumed_calls: Literal[1] = Field(default=1, alias="consumedCalls")
    consumed_at: datetime = Field(alias="consumedAt")

    @field_validator("consumed_at")
    @classmethod
    def require_utc_time(cls, value: datetime) -> datetime:
        return _utc(value, label="specialist Capability Grant consumption timestamp")

    @field_validator("consumed_calls", mode="before")
    @classmethod
    def require_one_call(cls, value: object) -> object:
        if type(value) is not int or value != 1:
            raise ValueError("specialist Capability Grant receipt must consume one call")
        return value

    @model_validator(mode="after")
    def bind_receipt_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-capability-grant-consumption-receipt/v1",
            material,
        )
        expected_id = f"agentic-specialist-grant-consumption_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("specialist Capability Grant consumption receipt digest differs")
        if self.receipt_id and self.receipt_id != expected_id:
            raise ValueError("specialist Capability Grant consumption receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist Capability Grant consumption receipt",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        return self


class AgenticSpecialistDispatchPlanEntry(AgenticStrictModel):
    """Audit-only durable binding awaiting one independently verified Permit."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-specialist-dispatch-plan/v1alpha1"] = Field(
        default="pajin.dev/agentic-specialist-dispatch-plan/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["AgenticSpecialistDispatchPlan"] = "AgenticSpecialistDispatchPlan"
    plan_id: str = Field(default="", alias="planId", max_length=110)
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    state_digest: str = Field(default="", alias="stateDigest", max_length=64)
    state: AgenticSpecialistDispatchPlanState

    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    control_plane_run_id: Identifier = Field(alias="controlPlaneRunId")
    reservation_id: str = Field(alias="reservationId", max_length=110)
    reservation_digest: Sha256 = Field(alias="reservationDigest")
    reservation_state_digest: Sha256 = Field(alias="reservationStateDigest")
    reservation_reserved_at: datetime = Field(alias="reservationReservedAt")
    source_head_checkpoint_id: str = Field(
        alias="sourceHeadCheckpointId",
        pattern=r"^agentic-checkpoint_[a-f0-9]{64}$",
    )
    source_head_checkpoint_digest: Sha256 = Field(alias="sourceHeadCheckpointDigest")
    graph_snapshot_id: Identifier = Field(alias="graphSnapshotId")
    graph_snapshot_digest: Sha256 = Field(alias="graphSnapshotDigest")
    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    command_digest: Sha256 = Field(alias="commandDigest")
    target_agent_id: Identifier = Field(alias="targetAgentId")
    task_id: Identifier = Field(alias="taskId")
    specialization: PentestSpecialization

    preparation_id: str = Field(alias="preparationId", max_length=110)
    preparation_digest: Sha256 = Field(alias="preparationDigest")
    target_id: Identifier = Field(alias="targetId")
    target_endpoint: str = Field(alias="targetEndpoint", min_length=1, max_length=2_000)
    target_digest: Sha256 = Field(alias="targetDigest")
    profile_id: Identifier = Field(alias="profileId")
    profile_version: str = Field(alias="profileVersion", min_length=1, max_length=40)
    profile_digest: Sha256 = Field(alias="profileDigest")
    executor_id: Identifier = Field(alias="executorId")
    executor_digest: Sha256 = Field(alias="executorDigest")

    campaign_id: str = Field(alias="campaignId", min_length=3, max_length=80)
    campaign_manifest_digest: Sha256 = Field(alias="campaignManifestDigest")
    activation_set_digest: Sha256 = Field(alias="activationSetDigest")
    release_id: str = Field(alias="releaseId", max_length=100)
    release_digest: Sha256 = Field(alias="releaseDigest")
    capability_id: Identifier = Field(alias="capabilityId")
    capability_version: str = Field(alias="capabilityVersion", min_length=1, max_length=40)
    capability_digest: Sha256 = Field(alias="capabilityDigest")
    tool_id: Identifier = Field(alias="toolId")
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    prepared_action_digest: Sha256 = Field(alias="preparedActionDigest")
    request_units: int = Field(alias="requestUnits", ge=1, le=1_000_000)
    grant: AgenticSpecialistCapabilityGrantBinding
    approval_envelope: ActionApprovalEnvelope = Field(alias="approvalEnvelope")
    expected_action_permit_id: str = Field(
        alias="expectedActionPermitId",
        pattern=r"^action-permit_[a-f0-9]{64}$",
    )
    planned_at: datetime = Field(alias="plannedAt")

    action_permit: ActionPermit | None = Field(default=None, alias="actionPermit")
    approval_consumption_receipt: ActionApprovalConsumptionReceipt | None = Field(
        default=None,
        alias="approvalConsumptionReceipt",
    )
    grant_consumption_receipt: AgenticSpecialistCapabilityGrantConsumptionReceipt | None = Field(
        default=None, alias="grantConsumptionReceipt"
    )
    callback_entered_at: datetime | None = Field(default=None, alias="callbackEnteredAt")
    reconciled_at: datetime | None = Field(default=None, alias="reconciledAt")

    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    gateway_authority: Literal[False] = Field(default=False, alias="gatewayAuthority")
    worker_authority: Literal[False] = Field(default=False, alias="workerAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )

    @field_validator(
        "reservation_reserved_at",
        "planned_at",
        "callback_entered_at",
        "reconciled_at",
    )
    @classmethod
    def require_utc_times(cls, value: datetime | None) -> datetime | None:
        return _utc(value, label="specialist dispatch plan timestamp") if value else None

    @field_validator(
        "approval_authority",
        "permit_authority",
        "gateway_authority",
        "worker_authority",
        "execution_authority",
        "finding_authority",
        "graph_authority",
        "automatic_redispatch_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_identity_and_state(self) -> Self:
        action = self.prepared_action
        approval = self.approval_envelope
        proposal = approval.proposal
        envelope = approval.mission_envelope
        decision = approval.graph_decision
        if self.preparation_id != f"agentic-specialist-preparation_{self.preparation_digest}":
            raise ValueError("specialist dispatch plan preparation identity differs")
        if (
            action.activation_set_digest != self.activation_set_digest
            or action.release.release_id != self.release_id
            or action.release.release_digest != self.release_digest
            or action.capability.capability_id != self.capability_id
            or action.capability.capability_version != self.capability_version
            or action.capability.definition_digest != self.capability_digest
            or action.capability.tool_id != self.tool_id
            or action.request.tool_id != self.tool_id
            or action.request.agent_id != self.target_agent_id
            or action.request.target != self.target_endpoint
            or action.request.arguments.get("preparationId") != self.preparation_id
            or action.request.arguments.get("preparationDigest") != self.preparation_digest
            or _prepared_capability_action_digest(action) != self.prepared_action_digest
        ):
            raise ValueError("specialist dispatch plan Prepared Capability Action differs")
        if (
            approval.campaign_id != self.campaign_id
            or approval.campaign_digest != self.campaign_manifest_digest
            or approval.run_id != self.control_plane_run_id
            or envelope.run_id != self.control_plane_run_id
            or approval.activation_set_digest != self.activation_set_digest
            or approval.release.release_id != self.release_id
            or approval.release.release_digest != self.release_digest
            or approval.release.capability_id != self.capability_id
            or approval.release.capability_version != self.capability_version
            or approval.release.capability_digest != self.capability_digest
            or proposal.capability != action.capability
            or proposal.request_id != action.request.request_id
            or proposal.request_digest != action.request_digest
            or proposal.normalized_parameters_digest != action.normalized_parameters_digest
            or proposal.target_digest != self.target_digest
            or proposal.reservation.tool_calls != 1
            or proposal.reservation.request_units != self.request_units
            or proposal.reservation.cost_microusd != 0
            or approval.expected_action_permit_id != self.expected_action_permit_id
            or approval.side_effect_class != "read-only"
            or approval.cleanup_required
            or envelope.allowed_capabilities != (action.capability,)
            or envelope.allowed_target_digests != (self.target_digest,)
            or envelope.source_campaign_digest != self.campaign_manifest_digest
            or envelope.profile_id != self.profile_id
            or envelope.profile_version != self.profile_version
            or envelope.profile_digest != self.profile_digest
            or envelope.max_risk_tier is not ToolRiskTier.T2
            or envelope.autonomy is not AutonomyLevel.SUPERVISED
            or envelope.budget.tool_call_limit != 1
            or envelope.budget.request_unit_limit != self.request_units
            or envelope.budget.cost_limit_microusd != 0
            or approval.source_intent_digest != self.preparation_digest
            or decision.decision_kind is not GraphDecisionKind.ACTION_PROPOSAL
            or decision.snapshot.snapshot_id != self.graph_snapshot_id
            or decision.snapshot.snapshot_digest != self.graph_snapshot_digest
            or decision.snapshot.campaign_id != self.campaign_id
        ):
            raise ValueError("specialist dispatch plan approval tuple differs")
        if (
            self.grant.subject != self.target_agent_id
            or self.grant.campaign != self.campaign_id
            or self.grant.tools != (self.tool_id,)
            or self.grant.targets != (self.target_endpoint,)
        ):
            raise ValueError("specialist dispatch plan Capability Grant differs")
        if self.planned_at < self.reservation_reserved_at:
            raise ValueError("specialist dispatch plan predates its reservation")
        if (
            not self.grant.issued_at <= self.planned_at < self.grant.expires_at
            or not envelope.not_before <= self.planned_at < envelope.expires_at
            or not approval.not_before <= self.planned_at < approval.expires_at
            or approval.expires_at > envelope.expires_at
            or approval.expires_at > self.grant.expires_at
        ):
            raise ValueError("specialist dispatch plan authority window differs")

        identity_material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "plan_id",
                "plan_digest",
                "state",
                "state_digest",
                "action_permit",
                "approval_consumption_receipt",
                "grant_consumption_receipt",
                "callback_entered_at",
                "reconciled_at",
            },
        )
        digest = discovery_digest("pajin.agentic.specialist-dispatch-plan/v1", identity_material)
        expected_id = f"agentic-specialist-plan_{digest}"
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("specialist dispatch Plan Digest differs")
        if self.plan_id and self.plan_id != expected_id:
            raise ValueError("specialist dispatch Plan ID differs")
        object.__setattr__(self, "plan_digest", digest)
        object.__setattr__(self, "plan_id", expected_id)

        _validate_specialist_dispatch_plan_state(self)

        state_digest = discovery_digest(
            "pajin.agentic.specialist-dispatch-plan-state/v1",
            {
                "planDigest": digest,
                "state": self.state.value,
                "actionPermitDigest": (
                    self.action_permit.permit_digest if self.action_permit else None
                ),
                "approvalConsumptionReceiptDigest": (
                    self.approval_consumption_receipt.receipt_digest
                    if self.approval_consumption_receipt
                    else None
                ),
                "grantConsumptionReceiptDigest": (
                    self.grant_consumption_receipt.receipt_digest
                    if self.grant_consumption_receipt
                    else None
                ),
                "callbackEnteredAt": (
                    _format_timestamp(self.callback_entered_at)
                    if self.callback_entered_at
                    else None
                ),
                "reconciledAt": (
                    _format_timestamp(self.reconciled_at) if self.reconciled_at else None
                ),
            },
        )
        if self.state_digest and self.state_digest != state_digest:
            raise ValueError("specialist dispatch Plan State Digest differs")
        object.__setattr__(self, "state_digest", state_digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist dispatch plan",
            max_bytes=_MAX_SPECIALIST_DISPATCH_PLAN_BYTES,
        )
        return self


class AgenticSQLSpecialistDispatchPlanEntryV2(AgenticStrictModel):
    """Explicit SQL-specialist v2 wire plan; never upgrades a v1 plan."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-sql-specialist-dispatch-plan/v2alpha1"] = Field(
        default="pajin.dev/agentic-sql-specialist-dispatch-plan/v2alpha1",
        alias="apiVersion",
    )
    kind: Literal["AgenticSQLSpecialistDispatchPlanV2"] = "AgenticSQLSpecialistDispatchPlanV2"
    runtime_generation: Literal[AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2] = Field(
        default=AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2,
        alias="runtimeGeneration",
    )
    scheduler_task_token_digest: Sha256 = Field(alias="schedulerTaskTokenDigest")
    plan_id: str = Field(default="", alias="planId", max_length=110)
    plan_digest: str = Field(default="", alias="planDigest", max_length=64)
    state_digest: str = Field(default="", alias="stateDigest", max_length=64)
    state: AgenticSpecialistDispatchPlanState

    store_id: str = Field(alias="storeId", pattern=_STORE_ID_PATTERN)
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    control_plane_run_id: Identifier = Field(alias="controlPlaneRunId")
    reservation_id: str = Field(alias="reservationId", max_length=110)
    reservation_digest: Sha256 = Field(alias="reservationDigest")
    reservation_state_digest: Sha256 = Field(alias="reservationStateDigest")
    reservation_reserved_at: datetime = Field(alias="reservationReservedAt")
    source_head_checkpoint_id: str = Field(
        alias="sourceHeadCheckpointId",
        pattern=r"^agentic-checkpoint_[a-f0-9]{64}$",
    )
    source_head_checkpoint_digest: Sha256 = Field(alias="sourceHeadCheckpointDigest")
    graph_snapshot_id: Identifier = Field(alias="graphSnapshotId")
    graph_snapshot_digest: Sha256 = Field(alias="graphSnapshotDigest")
    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    command_digest: Sha256 = Field(alias="commandDigest")
    target_agent_id: Identifier = Field(alias="targetAgentId")
    task_id: Identifier = Field(alias="taskId")
    specialization: PentestSpecialization

    preparation_id: str = Field(alias="preparationId", max_length=110)
    preparation_digest: Sha256 = Field(alias="preparationDigest")
    target_id: Identifier = Field(alias="targetId")
    target_endpoint: str = Field(alias="targetEndpoint", min_length=1, max_length=2_000)
    target_digest: Sha256 = Field(alias="targetDigest")
    profile_id: Identifier = Field(alias="profileId")
    profile_version: str = Field(alias="profileVersion", min_length=1, max_length=40)
    profile_digest: Sha256 = Field(alias="profileDigest")
    executor_id: Identifier = Field(alias="executorId")
    executor_digest: Sha256 = Field(alias="executorDigest")

    campaign_id: str = Field(alias="campaignId", min_length=3, max_length=80)
    campaign_manifest_digest: Sha256 = Field(alias="campaignManifestDigest")
    activation_set_digest: Sha256 = Field(alias="activationSetDigest")
    release_id: str = Field(alias="releaseId", max_length=100)
    release_digest: Sha256 = Field(alias="releaseDigest")
    capability_id: Identifier = Field(alias="capabilityId")
    capability_version: str = Field(alias="capabilityVersion", min_length=1, max_length=40)
    capability_digest: Sha256 = Field(alias="capabilityDigest")
    tool_id: Identifier = Field(alias="toolId")
    prepared_action: PreparedCapabilityAction = Field(alias="preparedAction")
    prepared_action_digest: Sha256 = Field(alias="preparedActionDigest")
    request_units: int = Field(alias="requestUnits", ge=1, le=1_000_000)
    grant: AgenticSpecialistCapabilityGrantBinding
    approval_envelope: ActionApprovalEnvelope = Field(alias="approvalEnvelope")
    expected_action_permit_id: str = Field(
        alias="expectedActionPermitId",
        pattern=r"^action-permit_[a-f0-9]{64}$",
    )
    planned_at: datetime = Field(alias="plannedAt")

    action_permit: ActionPermit | None = Field(default=None, alias="actionPermit")
    approval_consumption_receipt: ActionApprovalConsumptionReceipt | None = Field(
        default=None,
        alias="approvalConsumptionReceipt",
    )
    grant_consumption_receipt: AgenticSpecialistCapabilityGrantConsumptionReceipt | None = Field(
        default=None,
        alias="grantConsumptionReceipt",
    )
    callback_entered_at: datetime | None = Field(default=None, alias="callbackEnteredAt")
    reconciled_at: datetime | None = Field(default=None, alias="reconciledAt")

    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_authority: Literal[False] = Field(default=False, alias="permitAuthority")
    gateway_authority: Literal[False] = Field(default=False, alias="gatewayAuthority")
    worker_authority: Literal[False] = Field(default=False, alias="workerAuthority")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )

    @field_validator(
        "reservation_reserved_at",
        "planned_at",
        "callback_entered_at",
        "reconciled_at",
    )
    @classmethod
    def require_utc_times(cls, value: datetime | None) -> datetime | None:
        return _utc(value, label="SQL specialist v2 plan timestamp") if value else None

    @field_validator(
        "approval_authority",
        "permit_authority",
        "gateway_authority",
        "worker_authority",
        "execution_authority",
        "finding_authority",
        "graph_authority",
        "automatic_redispatch_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_identity_and_state(self) -> Self:
        action = self.prepared_action
        approval = self.approval_envelope
        proposal = approval.proposal
        envelope = approval.mission_envelope
        decision = approval.graph_decision
        capability = action.capability
        if self.preparation_id != f"agentic-specialist-preparation_{self.preparation_digest}":
            raise ValueError("SQL specialist v2 dispatch plan preparation identity differs")
        if (
            self.runtime_generation is not AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
            or self.specialization is not PentestSpecialization.SQL_INJECTION
            or self.capability_id != _EXECUTABLE_SPECIALIST_CAPABILITY_ID
            or self.capability_version != _EXECUTABLE_SPECIALIST_CAPABILITY_VERSION
            or self.tool_id != _EXECUTABLE_SPECIALIST_TOOL_ID
            or capability.capability_id != _EXECUTABLE_SPECIALIST_CAPABILITY_ID
            or capability.capability_version != _EXECUTABLE_SPECIALIST_CAPABILITY_VERSION
            or capability.tool_id != _EXECUTABLE_SPECIALIST_TOOL_ID
            or capability.tool_version != _EXECUTABLE_SPECIALIST_TOOL_VERSION
        ):
            raise ValueError("SQL specialist v2 dispatch plan generation differs")
        if (
            action.activation_set_digest != self.activation_set_digest
            or action.release.release_id != self.release_id
            or action.release.release_digest != self.release_digest
            or capability.capability_id != self.capability_id
            or capability.capability_version != self.capability_version
            or capability.definition_digest != self.capability_digest
            or capability.tool_id != self.tool_id
            or action.request.tool_id != self.tool_id
            or action.request.agent_id != self.target_agent_id
            or action.request.target != self.target_endpoint
            or action.request.arguments.get("preparationId") != self.preparation_id
            or action.request.arguments.get("preparationDigest") != self.preparation_digest
            or _prepared_capability_action_digest(action) != self.prepared_action_digest
        ):
            raise ValueError("SQL specialist v2 dispatch plan Prepared Capability Action differs")
        if (
            approval.campaign_id != self.campaign_id
            or approval.campaign_digest != self.campaign_manifest_digest
            or approval.run_id != self.control_plane_run_id
            or envelope.run_id != self.control_plane_run_id
            or approval.activation_set_digest != self.activation_set_digest
            or approval.release.release_id != self.release_id
            or approval.release.release_digest != self.release_digest
            or approval.release.capability_id != self.capability_id
            or approval.release.capability_version != self.capability_version
            or approval.release.capability_digest != self.capability_digest
            or proposal.capability != capability
            or proposal.request_id != action.request.request_id
            or proposal.request_digest != action.request_digest
            or proposal.normalized_parameters_digest != action.normalized_parameters_digest
            or proposal.target_digest != self.target_digest
            or proposal.reservation.tool_calls != 1
            or proposal.reservation.request_units != self.request_units
            or proposal.reservation.cost_microusd != 0
            or approval.expected_action_permit_id != self.expected_action_permit_id
            or approval.side_effect_class != "read-only"
            or approval.cleanup_required
            or envelope.allowed_capabilities != (capability,)
            or envelope.allowed_target_digests != (self.target_digest,)
            or envelope.source_campaign_digest != self.campaign_manifest_digest
            or envelope.profile_id != self.profile_id
            or envelope.profile_version != self.profile_version
            or envelope.profile_digest != self.profile_digest
            or envelope.max_risk_tier is not ToolRiskTier.T2
            or envelope.autonomy is not AutonomyLevel.SUPERVISED
            or envelope.budget.tool_call_limit != 1
            or envelope.budget.request_unit_limit != self.request_units
            or envelope.budget.cost_limit_microusd != 0
            or approval.source_intent_digest != self.preparation_digest
            or decision.decision_kind is not GraphDecisionKind.ACTION_PROPOSAL
            or decision.snapshot.snapshot_id != self.graph_snapshot_id
            or decision.snapshot.snapshot_digest != self.graph_snapshot_digest
            or decision.snapshot.campaign_id != self.campaign_id
        ):
            raise ValueError("SQL specialist v2 dispatch plan approval tuple differs")
        if (
            self.grant.subject != self.target_agent_id
            or self.grant.campaign != self.campaign_id
            or self.grant.tools != (self.tool_id,)
            or self.grant.targets != (self.target_endpoint,)
        ):
            raise ValueError("SQL specialist v2 dispatch plan Capability Grant differs")
        if self.planned_at < self.reservation_reserved_at:
            raise ValueError("SQL specialist v2 dispatch plan predates its reservation")
        if (
            not self.grant.issued_at <= self.planned_at < self.grant.expires_at
            or not envelope.not_before <= self.planned_at < envelope.expires_at
            or not approval.not_before <= self.planned_at < approval.expires_at
            or approval.expires_at > envelope.expires_at
            or approval.expires_at > self.grant.expires_at
        ):
            raise ValueError("SQL specialist v2 dispatch plan authority window differs")

        identity_material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "plan_id",
                "plan_digest",
                "state",
                "state_digest",
                "action_permit",
                "approval_consumption_receipt",
                "grant_consumption_receipt",
                "callback_entered_at",
                "reconciled_at",
            },
        )
        digest = discovery_digest(
            "pajin.agentic.sql-specialist-dispatch-plan/v2",
            identity_material,
        )
        expected_id = f"agentic-specialist-plan_{digest}"
        if self.plan_digest and self.plan_digest != digest:
            raise ValueError("SQL specialist v2 dispatch Plan Digest differs")
        if self.plan_id and self.plan_id != expected_id:
            raise ValueError("SQL specialist v2 dispatch Plan ID differs")
        object.__setattr__(self, "plan_digest", digest)
        object.__setattr__(self, "plan_id", expected_id)

        _validate_specialist_dispatch_plan_state(self)

        state_digest = discovery_digest(
            "pajin.agentic.sql-specialist-dispatch-plan-state/v2",
            {
                "planDigest": digest,
                "runtimeGeneration": self.runtime_generation.value,
                "state": self.state.value,
                "actionPermitDigest": (
                    self.action_permit.permit_digest if self.action_permit else None
                ),
                "approvalConsumptionReceiptDigest": (
                    self.approval_consumption_receipt.receipt_digest
                    if self.approval_consumption_receipt
                    else None
                ),
                "grantConsumptionReceiptDigest": (
                    self.grant_consumption_receipt.receipt_digest
                    if self.grant_consumption_receipt
                    else None
                ),
                "callbackEnteredAt": (
                    _format_timestamp(self.callback_entered_at)
                    if self.callback_entered_at
                    else None
                ),
                "reconciledAt": (
                    _format_timestamp(self.reconciled_at) if self.reconciled_at else None
                ),
            },
        )
        if self.state_digest and self.state_digest != state_digest:
            raise ValueError("SQL specialist v2 dispatch Plan State Digest differs")
        object.__setattr__(self, "state_digest", state_digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="SQL specialist v2 dispatch plan",
            max_bytes=_MAX_SPECIALIST_DISPATCH_PLAN_BYTES,
        )
        return self


def _validate_specialist_dispatch_plan_state(
    entry: AgenticSpecialistDispatchPlanEntry | AgenticSQLSpecialistDispatchPlanEntryV2,
) -> None:
    if entry.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT:
        if any(
            item is not None
            for item in (
                entry.action_permit,
                entry.approval_consumption_receipt,
                entry.grant_consumption_receipt,
                entry.callback_entered_at,
                entry.reconciled_at,
            )
        ):
            raise ValueError("awaiting specialist dispatch plan contains callback authority")
        return
    if entry.state is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN:
        if (
            entry.action_permit is None
            or entry.approval_consumption_receipt is None
            or entry.grant_consumption_receipt is None
            or entry.callback_entered_at is None
            or entry.reconciled_at is not None
        ):
            raise ValueError("dispatch-started specialist plan state evidence differs")
        permit = entry.action_permit
        receipt = entry.approval_consumption_receipt
        grant_receipt = entry.grant_consumption_receipt
        callback_at = entry.callback_entered_at
        if (
            permit.permit_id != entry.expected_action_permit_id
            or receipt.approval != entry.approval_envelope
            or receipt.action_permit != permit
            or grant_receipt.store_id != entry.store_id
            or grant_receipt.coordination_binding_digest != entry.coordination_binding_digest
            or grant_receipt.plan_id != entry.plan_id
            or grant_receipt.plan_digest != entry.plan_digest
            or grant_receipt.reservation_id != entry.reservation_id
            or grant_receipt.reservation_digest != entry.reservation_digest
            or grant_receipt.command_id != entry.command_id
            or grant_receipt.command_digest != entry.command_digest
            or grant_receipt.capability_grant_id != entry.grant.grant_id
            or grant_receipt.capability_grant_digest != entry.grant.grant_digest
            or grant_receipt.action_permit_id != permit.permit_id
            or grant_receipt.action_permit_digest != permit.permit_digest
            or grant_receipt.approval_consumption_receipt_id != receipt.receipt_id
            or grant_receipt.approval_consumption_receipt_digest != receipt.receipt_digest
            or permit.issued_at < entry.planned_at
            or permit.consumed_at < permit.issued_at
            or callback_at < permit.consumed_at
            or grant_receipt.consumed_at < callback_at
            or grant_receipt.consumed_at >= permit.expires_at
            or grant_receipt.consumed_at >= entry.grant.expires_at
            or callback_at >= permit.expires_at
        ):
            raise ValueError("specialist Grant consumption receipt differs")
        return
    if (
        entry.action_permit is None
        or entry.approval_consumption_receipt is None
        or entry.grant_consumption_receipt is not None
        or entry.callback_entered_at is not None
        or entry.reconciled_at is None
    ):
        raise ValueError("reconciled specialist plan state evidence differs")
    permit = entry.action_permit
    receipt = entry.approval_consumption_receipt
    reconciled_at = entry.reconciled_at
    if (
        permit.permit_id != entry.expected_action_permit_id
        or receipt.approval != entry.approval_envelope
        or receipt.action_permit != permit
        or reconciled_at < permit.consumed_at
        or reconciled_at < entry.planned_at
    ):
        raise ValueError("reconciled specialist plan timestamp differs")


AgenticSpecialistDispatchPlanAuditEntry = (
    AgenticSpecialistDispatchPlanEntry | AgenticSQLSpecialistDispatchPlanEntryV2
)


class AgenticHypothesisInvocationReceipt(AgenticStrictModel):
    """Content-addressed terminal claim stored inside one sealed Run.

    The enclosing Run proves integrity and retention of this claim.  The model
    intentionally does not call the claim independent proof of Provider work.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    receipt_id: str = Field(default="", alias="receiptId", max_length=110)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    intent_id: str = Field(alias="intentId", pattern=r"^agentic-invocation_[a-f0-9]{64}$")
    intent_digest: Sha256 = Field(alias="intentDigest")
    stable_request_id: str = Field(
        alias="stableRequestId",
        pattern=r"^hypothesis-request_[a-f0-9]{64}$",
    )
    request_binding_id: str = Field(
        alias="requestBindingId",
        pattern=r"^agentic-hypothesis-request_[a-f0-9]{64}$",
    )
    request_binding_digest: Sha256 = Field(alias="requestBindingDigest")
    provider_run_id: Identifier = Field(alias="providerRunId")
    provider_id: str = Field(alias="providerId", min_length=2, max_length=64)
    model_id: str = Field(alias="modelId", min_length=1, max_length=200)
    provider_model_digest: Sha256 = Field(alias="providerModelDigest")
    model_configuration_digest: Sha256 = Field(alias="modelConfigurationDigest")
    provider_runtime_digest: Sha256 = Field(alias="providerRuntimeDigest")
    capability_grant_digest: Sha256 = Field(alias="capabilityGrantDigest")
    campaign_budget_policy_digest: Sha256 = Field(alias="campaignBudgetPolicyDigest")
    campaign_budget_state_digest: Sha256 = Field(alias="campaignBudgetStateDigest")
    dedicated_budget_policy_digest: Sha256 = Field(alias="dedicatedBudgetPolicyDigest")
    provider_chat_request_digest: Sha256 = Field(alias="providerChatRequestDigest")
    terminal_state: Literal["success", "failure"] = Field(alias="terminalState")
    outcome_digest: Sha256 = Field(alias="outcomeDigest")
    recorded_at: datetime = Field(alias="recordedAt")
    evidence_state: Literal["sealed-terminal-claim-not-provider-dispatch-proof"] = Field(
        default="sealed-terminal-claim-not-provider-dispatch-proof",
        alias="evidenceState",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("recorded_at")
    @classmethod
    def require_utc_recorded(cls, value: datetime) -> datetime:
        return _utc(value, label="invocation receipt timestamp")

    @field_validator(
        "automatic_redispatch_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = discovery_digest("pajin.agentic.hypothesis-terminal-receipt/v1", material)
        expected_id = f"agentic-hypothesis-receipt_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Agentic Hypothesis Invocation Receipt Digest differs")
        if self.receipt_id and self.receipt_id != expected_id:
            raise ValueError("Agentic Hypothesis Invocation Receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="Agentic Hypothesis Invocation Receipt",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        return self


@dataclass(frozen=True, slots=True)
class AgenticHypothesisReceiptPublication:
    """Exact sealed Run coordinates for one terminal invocation receipt."""

    run_path: Path
    run_id: str
    root_digest: str
    artifact_path: str
    artifact_sha256: str
    receipt: AgenticHypothesisInvocationReceipt


@dataclass(frozen=True, slots=True)
class _VerifiedAgenticHypothesisReceiptPublication:
    run_path: Path
    run_id: str
    root_digest: str
    artifact_path: str
    artifact_sha256: str
    receipt: AgenticHypothesisInvocationReceipt


def verify_agentic_hypothesis_receipt_publication(
    publication: AgenticHypothesisReceiptPublication,
    *,
    expected_entry: AgenticModelInvocationEntry,
) -> AgenticHypothesisInvocationReceipt:
    """Strict-reload one exact sealed receipt and bind it to an invocation intent."""

    return _verified_hypothesis_receipt_publication(
        publication,
        expected_entry=expected_entry,
    ).receipt


def _verified_hypothesis_receipt_publication(
    publication: AgenticHypothesisReceiptPublication,
    *,
    expected_entry: AgenticModelInvocationEntry,
) -> _VerifiedAgenticHypothesisReceiptPublication:
    """Materialize and verify immutable coordinates once for durable publication."""

    if type(publication) is not AgenticHypothesisReceiptPublication:
        raise TypeError("invocation finalization requires an exact receipt publication")
    run_path_value = publication.run_path
    run_id = publication.run_id
    root_digest = publication.root_digest
    artifact_path_value = publication.artifact_path
    artifact_sha256 = publication.artifact_sha256
    publication_receipt = publication.receipt
    if (
        type(run_path_value) is not type(Path())
        or type(run_id) is not str
        or type(root_digest) is not str
        or type(artifact_path_value) is not str
        or type(artifact_sha256) is not str
        or type(publication_receipt) is not AgenticHypothesisInvocationReceipt
    ):
        raise TypeError("invocation receipt publication fields require exact wire types")
    run_path = Path(os.path.abspath(os.fspath(run_path_value)))
    expected = AgenticModelInvocationEntry.model_validate(
        expected_entry.model_dump(mode="json", by_alias=True)
    )
    if expected.state not in {
        AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
        AgenticModelInvocationState.TERMINAL_SUCCESS,
        AgenticModelInvocationState.TERMINAL_FAILURE,
    }:
        raise ValueError("invocation receipt requires a started durable intent")
    artifact_path = validate_run_artifact_path(artifact_path_value)
    if artifact_path != _INVOCATION_RECEIPT_PATH:
        raise ValueError("invocation receipt artifact path differs")
    _require_identifier(run_id, label="receipt Run ID")
    _require_digest(root_digest, label="receipt Run root digest")
    _require_digest(artifact_sha256, label="receipt artifact sha256")
    intent = expected.intent
    binding = intent.request_binding
    publication_path = str(run_path)
    if (
        run_id != binding.planned_provider_run_id
        or publication_path != binding.planned_provider_run_path
    ):
        raise ValueError("sealed invocation receipt differs from the exact preplanned Run")
    loaded = load_verified_run_artifacts(
        run_path,
        requests={artifact_path: _MAX_RECEIPT_BYTES},
        expected_run_id=run_id,
    )
    if loaded.verification.root_digest != root_digest:
        raise ValueError("sealed invocation receipt Run root differs")
    raw = loaded.artifact_bytes(artifact_path)
    if sha256(raw).hexdigest() != artifact_sha256:
        raise ValueError("sealed invocation receipt artifact hash differs")
    receipt = AgenticHypothesisInvocationReceipt.model_validate_json(raw)
    if raw != canonical_json_bytes(
        receipt.model_dump(mode="json", by_alias=True),
        label="Agentic Hypothesis Invocation Receipt",
        max_bytes=_MAX_RECEIPT_BYTES,
    ):
        raise ValueError("sealed invocation receipt bytes are not canonical")
    if receipt != AgenticHypothesisInvocationReceipt.model_validate(
        publication_receipt.model_dump(mode="json", by_alias=True)
    ):
        raise ValueError("sealed invocation receipt differs from publication")
    observed = (
        receipt.intent_id,
        receipt.intent_digest,
        receipt.stable_request_id,
        receipt.request_binding_id,
        receipt.request_binding_digest,
        receipt.provider_run_id,
        receipt.provider_id,
        receipt.model_id,
        receipt.provider_model_digest,
        receipt.model_configuration_digest,
        receipt.provider_runtime_digest,
        receipt.capability_grant_digest,
        receipt.campaign_budget_policy_digest,
        receipt.campaign_budget_state_digest,
        receipt.dedicated_budget_policy_digest,
        receipt.provider_chat_request_digest,
    )
    required = (
        intent.intent_id,
        intent.intent_digest,
        intent.stable_request_id,
        binding.request_binding_id,
        binding.request_binding_digest,
        binding.planned_provider_run_id,
        binding.provider_id,
        binding.model_id,
        binding.provider_model_digest,
        binding.model_configuration_digest,
        binding.provider_runtime_digest,
        binding.capability_grant_digest,
        binding.campaign_budget_policy_digest,
        binding.campaign_budget_state_digest,
        binding.dedicated_budget_policy_digest,
        binding.provider_chat_request_digest,
    )
    if observed != required:
        raise ValueError("sealed invocation receipt differs from the durable request")
    if expected.dispatch_started_at is None or receipt.recorded_at < expected.dispatch_started_at:
        raise ValueError("sealed invocation receipt predates dispatch")
    terminal_events = tuple(
        event
        for event in loaded.events
        if event.event_type == "agentic.hypothesis-invocation-terminal"
        and event.payload
        == {
            "artifactPath": artifact_path,
            "receiptDigest": receipt.receipt_digest,
            "receiptId": receipt.receipt_id,
        }
    )
    if len(terminal_events) != 1:
        raise ValueError("sealed invocation receipt lacks exact terminal event provenance")
    if expected.state in {
        AgenticModelInvocationState.TERMINAL_SUCCESS,
        AgenticModelInvocationState.TERMINAL_FAILURE,
    }:
        expected_terminal = (
            "success"
            if expected.state is AgenticModelInvocationState.TERMINAL_SUCCESS
            else "failure"
        )
        if (
            receipt.terminal_state != expected_terminal
            or receipt.outcome_digest != expected.outcome_digest
            or receipt.receipt_id != expected.receipt_reference
            or receipt.receipt_digest != expected.receipt_digest
            or expected.terminal_at is None
            or receipt.recorded_at > expected.terminal_at
        ):
            raise ValueError("sealed invocation receipt differs from terminal journal state")
    return _VerifiedAgenticHypothesisReceiptPublication(
        run_path=run_path,
        run_id=run_id,
        root_digest=root_digest,
        artifact_path=artifact_path,
        artifact_sha256=artifact_sha256,
        receipt=receipt,
    )


@dataclass(frozen=True, slots=True)
class VerifiedAgenticDurableHead:
    """Store-local proof that a checkpoint was the verified CAS head when read."""

    store_id: str
    binding_digest: str
    checkpoint: DynamicSupervisorCheckpoint
    _authority: object


@dataclass(frozen=True, slots=True)
class VerifiedAgenticCheckpoint:
    """Store-issued proof that one historical checkpoint belongs to current history."""

    store_id: str
    binding_digest: str
    current_head_digest: str
    checkpoint: DynamicSupervisorCheckpoint
    _authority: object


class _UncopyableAgenticAuthority:
    """Common process-local protection for one-use execution authority handles."""

    __slots__ = ()

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("agentic execution authority handles are immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("agentic execution authority handles are immutable")

    def __copy__(self) -> Never:
        raise TypeError("agentic execution authority handles cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("agentic execution authority handles cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("agentic execution authority handles cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("agentic execution authority handles cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("agentic execution authority handles cannot be serialized")


@dataclass(frozen=True, slots=True)
class _AgenticSpecialistApprovalRuntimeIdentity:
    """Exact process-local internals of one deployment approval trust root."""

    authority: object
    trusted_mapping: object
    trust_anchor_digest: str
    clock: object
    lock: object
    registered_authorities: object


@dataclass(frozen=True, slots=True)
class _AgenticSpecialistDeploymentRuntimeIdentity:
    """Exact process-local objects that may authorize one specialist callback."""

    deployment: object
    runtime_generation: AgenticSpecialistRuntimeGeneration
    campaign_id: str
    graph_store: SQLiteGraphStore
    permit_store: SQLiteGraphActionPermitStore
    graph_file_identity: tuple[tuple[int, int], tuple[int, int]]
    capability_ledger: CapabilityLedger
    ledger_max_depth: object
    ledger_records: object
    ledger_lock: object
    ledger_clock: object
    approval: _AgenticSpecialistApprovalRuntimeIdentity
    lock: object


@dataclass(frozen=True, slots=True)
class _AgenticSpecialistConfiguredRuntimeIdentity:
    """One-way identity of the shared Permit writer installed on first bind."""

    deployment: object
    runtime_generation: AgenticSpecialistRuntimeGeneration
    capability_records: object
    capabilities: ActionCapabilityRegistry
    policies: ActionApprovalCapabilityPolicyRegistry
    compiler_identity: tuple[str, str, str]
    graph_authority: GraphApprovedActionPermitAuthority
    dispatcher: GraphApprovedActionPermitDispatcher
    clock: object
    permit_ttl: timedelta
    writer: object


def _same_specialist_approval_runtime_identity(
    left: _AgenticSpecialistApprovalRuntimeIdentity,
    right: _AgenticSpecialistApprovalRuntimeIdentity,
) -> bool:
    return (
        left.authority is right.authority
        and left.trusted_mapping is right.trusted_mapping
        and left.trust_anchor_digest == right.trust_anchor_digest
        and left.clock is right.clock
        and left.lock is right.lock
        and left.registered_authorities is right.registered_authorities
    )


def _same_specialist_deployment_runtime_identity(
    left: _AgenticSpecialistDeploymentRuntimeIdentity,
    right: _AgenticSpecialistDeploymentRuntimeIdentity,
) -> bool:
    return (
        left.deployment is right.deployment
        and left.runtime_generation is right.runtime_generation
        and left.campaign_id == right.campaign_id
        and left.graph_store is right.graph_store
        and left.permit_store is right.permit_store
        and left.graph_file_identity == right.graph_file_identity
        and left.capability_ledger is right.capability_ledger
        and left.ledger_max_depth == right.ledger_max_depth
        and left.ledger_records is right.ledger_records
        and left.ledger_lock is right.ledger_lock
        and left.ledger_clock is right.ledger_clock
        and _same_specialist_approval_runtime_identity(left.approval, right.approval)
        and left.lock is right.lock
    )


def _same_specialist_configured_runtime_identity(
    left: _AgenticSpecialistConfiguredRuntimeIdentity,
    right: _AgenticSpecialistConfiguredRuntimeIdentity,
) -> bool:
    return (
        left.deployment is right.deployment
        and left.runtime_generation is right.runtime_generation
        and left.capability_records is right.capability_records
        and left.capabilities is right.capabilities
        and left.policies is right.policies
        and left.compiler_identity == right.compiler_identity
        and left.graph_authority is right.graph_authority
        and left.dispatcher is right.dispatcher
        and left.clock is right.clock
        and left.permit_ttl == right.permit_ttl
        and left.writer is right.writer
    )


class VerifiedAdmittedSpecialistAssignment(_UncopyableAgenticAuthority):
    """Store-local one-use proof of one current receiver-acknowledged assignment."""

    __slots__ = (
        "__admission",
        "__authority",
        "__candidate",
        "__command",
        "__consumed",
        "__cycle",
        "__decision",
        "__source_head_digest",
        "__specialist",
    )
    __admission: AgenticCommandAdmissionReceipt
    __authority: object
    __candidate: FrontierCandidate
    __command: AgentControlCommand
    __consumed: bool
    __cycle: DynamicSupervisorCycle
    __decision: FrontierDecision
    __source_head_digest: str
    __specialist: SpecialistDefinition

    def __init__(
        self,
        *,
        command: AgentControlCommand,
        candidate: FrontierCandidate,
        decision: FrontierDecision,
        specialist: SpecialistDefinition,
        admission: AgenticCommandAdmissionReceipt,
        cycle: DynamicSupervisorCycle,
        source_head_digest: str,
        _authority: object,
    ) -> None:
        prefix = "_VerifiedAdmittedSpecialistAssignment__"
        object.__setattr__(self, prefix + "command", command)
        object.__setattr__(self, prefix + "candidate", candidate)
        object.__setattr__(self, prefix + "decision", decision)
        object.__setattr__(self, prefix + "specialist", specialist)
        object.__setattr__(self, prefix + "admission", admission)
        object.__setattr__(self, prefix + "cycle", cycle)
        object.__setattr__(self, prefix + "source_head_digest", source_head_digest)
        object.__setattr__(self, prefix + "authority", _authority)
        object.__setattr__(self, prefix + "consumed", False)

    @property
    def command(self) -> AgentControlCommand:
        return self.__command

    @property
    def candidate(self) -> FrontierCandidate:
        return self.__candidate

    @property
    def decision(self) -> FrontierDecision:
        return self.__decision

    @property
    def specialist(self) -> SpecialistDefinition:
        return self.__specialist

    @property
    def admission(self) -> AgenticCommandAdmissionReceipt:
        return self.__admission

    @property
    def source_head_digest(self) -> str:
        return self.__source_head_digest

    @property
    def cycle(self) -> DynamicSupervisorCycle:
        return self.__cycle

    def _consume(self, authority: object) -> None:
        if (
            type(self) is not VerifiedAdmittedSpecialistAssignment
            or self.__authority is not authority
            or self.__consumed
        ):
            raise AgenticCoordinationError(
                "verified specialist assignment handle belongs to another store or is consumed"
            )
        object.__setattr__(
            self,
            "_VerifiedAdmittedSpecialistAssignment__consumed",
            True,
        )


class VerifiedSpecialistExecutionReservation(_UncopyableAgenticAuthority):
    """One-use store-local authority returned only for a newly inserted reservation."""

    __slots__ = ("__authority", "__consumed", "__entry")
    __authority: object
    __consumed: bool
    __entry: AgenticSpecialistExecutionEntry

    def __init__(self, entry: AgenticSpecialistExecutionEntry, *, _authority: object) -> None:
        object.__setattr__(
            self,
            "_VerifiedSpecialistExecutionReservation__entry",
            entry,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistExecutionReservation__authority",
            _authority,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistExecutionReservation__consumed",
            False,
        )

    @property
    def entry(self) -> AgenticSpecialistExecutionEntry:
        return self.__entry

    def _consume(self, authority: object) -> None:
        if (
            type(self) is not VerifiedSpecialistExecutionReservation
            or self.__authority is not authority
            or self.__consumed
        ):
            raise AgenticCoordinationError(
                "specialist execution reservation handle belongs to another store or is consumed"
            )
        object.__setattr__(
            self,
            "_VerifiedSpecialistExecutionReservation__consumed",
            True,
        )

    def _require(self, authority: object) -> None:
        """Authenticate this live reservation without consuming dispatch authority."""

        if (
            type(self) is not VerifiedSpecialistExecutionReservation
            or self.__authority is not authority
            or self.__consumed
        ):
            raise AgenticCoordinationError(
                "specialist execution reservation handle belongs to another store or is consumed"
            )


class VerifiedSpecialistDispatchStarted(_UncopyableAgenticAuthority):
    """Opaque proof that dispatch entered outcome-unknown exactly once."""

    __slots__ = ("__authority", "__consumed", "__entry")
    __authority: object
    __consumed: bool
    __entry: AgenticSpecialistExecutionEntry

    def __init__(self, entry: AgenticSpecialistExecutionEntry, *, _authority: object) -> None:
        object.__setattr__(self, "_VerifiedSpecialistDispatchStarted__entry", entry)
        object.__setattr__(self, "_VerifiedSpecialistDispatchStarted__authority", _authority)
        object.__setattr__(self, "_VerifiedSpecialistDispatchStarted__consumed", False)

    @property
    def entry(self) -> AgenticSpecialistExecutionEntry:
        return self.__entry

    def _consume(self, authority: object) -> None:
        """Consume the store-local proof at a future governed callback boundary."""

        if (
            type(self) is not VerifiedSpecialistDispatchStarted
            or self.__authority is not authority
            or self.__consumed
        ):
            raise AgenticCoordinationError(
                "specialist dispatch-started handle belongs to another store or is consumed"
            )
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchStarted__consumed",
            True,
        )


class VerifiedSpecialistDispatchPlan(_UncopyableAgenticAuthority):
    """One-use store-local callback authority transferred from a live reservation.

    This handle is not a Permit or execution bearer.  A future plan-specific
    callback must consume it while atomically advancing both durable rows.
    """

    __slots__ = (
        "__activation",
        "__approval_envelope",
        "__authority",
        "__callback_claimed",
        "__campaign",
        "__capability_grant",
        "__capability_ledger",
        "__consumed",
        "__entry",
        "__ledger_clock",
        "__ledger_lock",
        "__ledger_max_depth",
        "__ledger_records",
        "__preparation",
        "__prepared_action",
        "__specialist_deployment",
        "__specialist_deployment_runtime_identity",
        "__state_lock",
    )
    __activation: WebSpecialistCapabilityActivation
    __approval_envelope: ActionApprovalEnvelope
    __authority: object
    __capability_grant: CapabilityGrant
    __capability_ledger: CapabilityLedger
    __campaign: CampaignManifest
    __callback_claimed: bool
    __consumed: bool
    __entry: AgenticSpecialistDispatchPlanEntry
    __ledger_clock: object
    __ledger_lock: object
    __ledger_max_depth: object
    __ledger_records: object
    __preparation: AgenticSpecialistPreparation
    __prepared_action: PreparedCapabilityAction
    __specialist_deployment: _AgenticSpecialistPermitDeployment
    __specialist_deployment_runtime_identity: _AgenticSpecialistDeploymentRuntimeIdentity
    __state_lock: RLockType

    def __init__(
        self,
        entry: AgenticSpecialistDispatchPlanEntry,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSpecialistCapabilityActivation,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        specialist_deployment: _AgenticSpecialistPermitDeployment,
        _authority: object,
    ) -> None:
        object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__entry", entry)
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__campaign",
            campaign,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__preparation",
            preparation,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__capability_ledger",
            capability_ledger,
        )
        max_depth, records, ledger_lock, ledger_clock = _capability_ledger_runtime_identity(
            capability_ledger
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__ledger_max_depth",
            max_depth,
        )
        object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__ledger_records", records)
        object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__ledger_lock", ledger_lock)
        object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__ledger_clock", ledger_clock)
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__capability_grant",
            capability_grant,
        )
        object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__activation", activation)
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__prepared_action",
            prepared_action,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__approval_envelope",
            approval_envelope,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__specialist_deployment",
            specialist_deployment,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__specialist_deployment_runtime_identity",
            _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(specialist_deployment),
        )
        object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__authority", _authority)
        object.__setattr__(
            self,
            "_VerifiedSpecialistDispatchPlan__state_lock",
            threading.RLock(),
        )
        object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__callback_claimed", False)
        object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__consumed", False)

    @property
    def entry(self) -> AgenticSpecialistDispatchPlanEntry:
        return self.__entry

    def _require(self, authority: object) -> None:
        if type(self) is not VerifiedSpecialistDispatchPlan or self.__authority is not authority:
            raise AgenticCoordinationError(
                "specialist dispatch plan handle belongs to another store or is consumed"
            )
        with self.__state_lock:
            if self.__consumed or self.__callback_claimed:
                raise AgenticCoordinationError(
                    "specialist dispatch plan handle belongs to another store or is consumed"
                )

    def _consume(self, authority: object) -> None:
        self._require(authority)
        with self.__state_lock:
            object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__consumed", True)

    def _require_runtime(
        self,
        authority: object,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSpecialistCapabilityActivation,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        specialist_deployment: _AgenticSpecialistPermitDeployment,
    ) -> None:
        """Pin future callback inputs to the exact process-local planned authority."""

        self._require(authority)
        max_depth, records, ledger_lock, ledger_clock = _capability_ledger_runtime_identity(
            capability_ledger
        )
        if (
            capability_ledger is not self.__capability_ledger
            or max_depth != self.__ledger_max_depth
            or records is not self.__ledger_records
            or ledger_lock is not self.__ledger_lock
            or ledger_clock is not self.__ledger_clock
            or campaign != self.__campaign
            or preparation != self.__preparation
            or capability_grant != self.__capability_grant
            or activation is not self.__activation
            or prepared_action != self.__prepared_action
            or approval_envelope != self.__approval_envelope
            or specialist_deployment is not self.__specialist_deployment
            or _AgenticSpecialistPermitDeployment.runtime_identity
            is not _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION
            or not _same_specialist_deployment_runtime_identity(
                _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(
                    specialist_deployment
                ),
                self.__specialist_deployment_runtime_identity,
            )
        ):
            raise AgenticCoordinationError(
                "specialist dispatch runtime authority differs from its sealed plan"
            )

    def _claim_callback(
        self,
        authority: object,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSpecialistCapabilityActivation,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        specialist_deployment: _AgenticSpecialistPermitDeployment,
    ) -> None:
        self._require_runtime(
            authority,
            campaign=campaign,
            preparation=preparation,
            capability_ledger=capability_ledger,
            capability_grant=capability_grant,
            activation=activation,
            prepared_action=prepared_action,
            approval_envelope=approval_envelope,
            specialist_deployment=specialist_deployment,
        )
        with self.__state_lock:
            if self.__consumed or self.__callback_claimed:
                raise AgenticCoordinationError(
                    "specialist dispatch plan callback was already claimed"
                )
            object.__setattr__(
                self,
                "_VerifiedSpecialistDispatchPlan__callback_claimed",
                True,
            )

    def _require_claimed_callback(self, authority: object) -> None:
        if type(self) is not VerifiedSpecialistDispatchPlan or self.__authority is not authority:
            raise AgenticCoordinationError(
                "specialist dispatch plan callback belongs to another store"
            )
        with self.__state_lock:
            if self.__consumed or not self.__callback_claimed:
                raise AgenticCoordinationError("specialist dispatch plan callback is not live")

    def _release_callback(self, authority: object) -> None:
        self._require_claimed_callback(authority)
        with self.__state_lock:
            object.__setattr__(
                self,
                "_VerifiedSpecialistDispatchPlan__callback_claimed",
                False,
            )

    def _consume_callback(self, authority: object) -> None:
        self._require_claimed_callback(authority)
        with self.__state_lock:
            object.__setattr__(self, "_VerifiedSpecialistDispatchPlan__consumed", True)
            object.__setattr__(
                self,
                "_VerifiedSpecialistDispatchPlan__callback_claimed",
                False,
            )


class VerifiedSQLSpecialistDispatchPlanV2(_UncopyableAgenticAuthority):
    """Task-owned one-use live authority for one explicit SQL v2 wire plan."""

    __slots__ = (
        "__activation",
        "__approval_envelope",
        "__authority",
        "__callback_claimed",
        "__campaign",
        "__capability_grant",
        "__capability_ledger",
        "__consumed",
        "__entry",
        "__ledger_clock",
        "__ledger_lock",
        "__ledger_max_depth",
        "__ledger_records",
        "__owner_task",
        "__owner_token",
        "__preparation",
        "__prepared_action",
        "__specialist_deployment",
        "__specialist_deployment_runtime_identity",
        "__state_lock",
    )
    __activation: WebSQLSpecialistCapabilityActivationV2
    __approval_envelope: ActionApprovalEnvelope
    __authority: object
    __callback_claimed: bool
    __campaign: CampaignManifest
    __capability_grant: CapabilityGrant
    __capability_ledger: CapabilityLedger
    __consumed: bool
    __entry: AgenticSQLSpecialistDispatchPlanEntryV2
    __ledger_clock: object
    __ledger_lock: object
    __ledger_max_depth: object
    __ledger_records: object
    __owner_task: asyncio.Task[object]
    __owner_token: object
    __preparation: AgenticSpecialistPreparation
    __prepared_action: PreparedCapabilityAction
    __specialist_deployment: _AgenticSpecialistPermitDeployment
    __specialist_deployment_runtime_identity: _AgenticSpecialistDeploymentRuntimeIdentity
    __state_lock: RLockType

    def __init__(
        self,
        entry: AgenticSQLSpecialistDispatchPlanEntryV2,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSQLSpecialistCapabilityActivationV2,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        specialist_deployment: _AgenticSpecialistPermitDeployment,
        owner_task: asyncio.Task[object],
        owner_token: object,
        _authority: object,
    ) -> None:
        prefix = "_VerifiedSQLSpecialistDispatchPlanV2__"
        object.__setattr__(self, prefix + "entry", entry)
        object.__setattr__(self, prefix + "campaign", campaign)
        object.__setattr__(self, prefix + "preparation", preparation)
        object.__setattr__(self, prefix + "capability_ledger", capability_ledger)
        max_depth, records, ledger_lock, ledger_clock = _capability_ledger_runtime_identity(
            capability_ledger
        )
        object.__setattr__(self, prefix + "ledger_max_depth", max_depth)
        object.__setattr__(self, prefix + "ledger_records", records)
        object.__setattr__(self, prefix + "ledger_lock", ledger_lock)
        object.__setattr__(self, prefix + "ledger_clock", ledger_clock)
        object.__setattr__(self, prefix + "capability_grant", capability_grant)
        object.__setattr__(self, prefix + "activation", activation)
        object.__setattr__(self, prefix + "prepared_action", prepared_action)
        object.__setattr__(self, prefix + "approval_envelope", approval_envelope)
        object.__setattr__(self, prefix + "specialist_deployment", specialist_deployment)
        object.__setattr__(
            self,
            prefix + "specialist_deployment_runtime_identity",
            _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(specialist_deployment),
        )
        object.__setattr__(self, prefix + "owner_task", owner_task)
        object.__setattr__(self, prefix + "owner_token", owner_token)
        object.__setattr__(self, prefix + "authority", _authority)
        object.__setattr__(self, prefix + "state_lock", threading.RLock())
        object.__setattr__(self, prefix + "callback_claimed", False)
        object.__setattr__(self, prefix + "consumed", False)

    @property
    def entry(self) -> AgenticSQLSpecialistDispatchPlanEntryV2:
        return self.__entry

    def _require(self, authority: object, owner_task: asyncio.Task[object], token: object) -> None:
        if (
            type(self) is not VerifiedSQLSpecialistDispatchPlanV2
            or self.__authority is not authority
            or self.__owner_task is not owner_task
            or self.__owner_token is not token
            or owner_task.done()
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 plan is foreign, retired, or owned by another Task"
            )
        with self.__state_lock:
            if self.__consumed or self.__callback_claimed:
                raise AgenticCoordinationError(
                    "SQL specialist v2 plan is foreign, retired, or consumed"
                )

    def _retire(self, authority: object, token: object) -> None:
        if (
            type(self) is not VerifiedSQLSpecialistDispatchPlanV2
            or self.__authority is not authority
            or self.__owner_token is not token
        ):
            raise AgenticCoordinationError("SQL specialist v2 plan retirement is foreign")
        with self.__state_lock:
            object.__setattr__(self, "_VerifiedSQLSpecialistDispatchPlanV2__consumed", True)
            object.__setattr__(
                self,
                "_VerifiedSQLSpecialistDispatchPlanV2__callback_claimed",
                False,
            )

    def _require_runtime(
        self,
        authority: object,
        owner_task: asyncio.Task[object],
        token: object,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSQLSpecialistCapabilityActivationV2,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        specialist_deployment: _AgenticSpecialistPermitDeployment,
    ) -> None:
        _SQL_SPECIALIST_V2_PLAN_REQUIRE_IMPLEMENTATION(
            self,
            authority,
            owner_task,
            token,
        )
        max_depth, records, ledger_lock, ledger_clock = _capability_ledger_runtime_identity(
            capability_ledger
        )
        if (
            capability_ledger is not self.__capability_ledger
            or max_depth != self.__ledger_max_depth
            or records is not self.__ledger_records
            or ledger_lock is not self.__ledger_lock
            or ledger_clock is not self.__ledger_clock
            or campaign != self.__campaign
            or preparation != self.__preparation
            or capability_grant != self.__capability_grant
            or activation is not self.__activation
            or prepared_action != self.__prepared_action
            or approval_envelope != self.__approval_envelope
            or specialist_deployment is not self.__specialist_deployment
            or not _same_specialist_deployment_runtime_identity(
                _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(
                    specialist_deployment
                ),
                self.__specialist_deployment_runtime_identity,
            )
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 runtime authority differs from its sealed plan"
            )

    def _claim_callback(
        self,
        authority: object,
        owner_task: asyncio.Task[object],
        token: object,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSQLSpecialistCapabilityActivationV2,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        specialist_deployment: _AgenticSpecialistPermitDeployment,
    ) -> None:
        _SQL_SPECIALIST_V2_PLAN_REQUIRE_RUNTIME_IMPLEMENTATION(
            self,
            authority,
            owner_task,
            token,
            campaign=campaign,
            preparation=preparation,
            capability_ledger=capability_ledger,
            capability_grant=capability_grant,
            activation=activation,
            prepared_action=prepared_action,
            approval_envelope=approval_envelope,
            specialist_deployment=specialist_deployment,
        )
        with self.__state_lock:
            if self.__consumed or self.__callback_claimed:
                raise AgenticCoordinationError(
                    "SQL specialist v2 plan callback was already claimed"
                )
            object.__setattr__(
                self,
                "_VerifiedSQLSpecialistDispatchPlanV2__callback_claimed",
                True,
            )

    def _require_claimed_callback(
        self,
        authority: object,
        owner_task: asyncio.Task[object],
        token: object,
    ) -> None:
        if (
            type(self) is not VerifiedSQLSpecialistDispatchPlanV2
            or self.__authority is not authority
            or self.__owner_task is not owner_task
            or self.__owner_token is not token
            or owner_task.done()
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 plan callback belongs to another Task or Store"
            )
        with self.__state_lock:
            if self.__consumed or not self.__callback_claimed:
                raise AgenticCoordinationError("SQL specialist v2 plan callback is not live")

    def _release_callback(
        self,
        authority: object,
        owner_task: asyncio.Task[object],
        token: object,
    ) -> None:
        _SQL_SPECIALIST_V2_PLAN_REQUIRE_CLAIMED_CALLBACK_IMPLEMENTATION(
            self,
            authority,
            owner_task,
            token,
        )
        with self.__state_lock:
            object.__setattr__(
                self,
                "_VerifiedSQLSpecialistDispatchPlanV2__callback_claimed",
                False,
            )

    def _consume_callback(
        self,
        authority: object,
        owner_task: asyncio.Task[object],
        token: object,
    ) -> None:
        _SQL_SPECIALIST_V2_PLAN_REQUIRE_CLAIMED_CALLBACK_IMPLEMENTATION(
            self,
            authority,
            owner_task,
            token,
        )
        with self.__state_lock:
            object.__setattr__(self, "_VerifiedSQLSpecialistDispatchPlanV2__consumed", True)
            object.__setattr__(
                self,
                "_VerifiedSQLSpecialistDispatchPlanV2__callback_claimed",
                False,
            )


_SQL_SPECIALIST_V2_PLAN_REQUIRE_IMPLEMENTATION = VerifiedSQLSpecialistDispatchPlanV2._require
_SQL_SPECIALIST_V2_PLAN_RETIRE_IMPLEMENTATION = VerifiedSQLSpecialistDispatchPlanV2._retire
_SQL_SPECIALIST_V2_PLAN_REQUIRE_RUNTIME_IMPLEMENTATION = (
    VerifiedSQLSpecialistDispatchPlanV2._require_runtime
)
_SQL_SPECIALIST_V2_PLAN_CLAIM_CALLBACK_IMPLEMENTATION = (
    VerifiedSQLSpecialistDispatchPlanV2._claim_callback
)
_SQL_SPECIALIST_V2_PLAN_REQUIRE_CLAIMED_CALLBACK_IMPLEMENTATION = (
    VerifiedSQLSpecialistDispatchPlanV2._require_claimed_callback
)
_SQL_SPECIALIST_V2_PLAN_RELEASE_CALLBACK_IMPLEMENTATION = (
    VerifiedSQLSpecialistDispatchPlanV2._release_callback
)
_SQL_SPECIALIST_V2_PLAN_CONSUME_CALLBACK_IMPLEMENTATION = (
    VerifiedSQLSpecialistDispatchPlanV2._consume_callback
)


class _AgenticSpecialistApprovalInputAuthority(_UncopyableAgenticAuthority):
    """One deployment keyring and many exact signed specialist approvals."""

    __slots__ = (
        "__authorities",
        "__clock",
        "__lock",
        "__trust_anchor_digest",
        "__trusted",
    )
    __authorities: dict[tuple[str, str], WebActionApprovalInputAuthority]
    __clock: Callable[[], datetime]
    __lock: RLockType
    __trust_anchor_digest: str
    __trusted: MappingProxyType[str, WebAssessmentVerificationKey]

    def __init__(
        self,
        *,
        keys: Iterable[WebAssessmentVerificationKey],
        clock: Callable[[], datetime],
    ) -> None:
        trusted: dict[str, WebAssessmentVerificationKey] = {}
        for raw in keys:
            try:
                key = WebAssessmentVerificationKey.model_validate(
                    raw.model_dump(mode="json", by_alias=True)
                )
            except (AttributeError, TypeError, ValidationError, ValueError) as exc:
                raise AgenticCoordinationError("specialist approval trust key is invalid") from exc
            if key.role is not WebAssessmentSigningRole.ACTION_APPROVER:
                raise AgenticCoordinationError("specialist approval trust key has the wrong role")
            if key.key_id in trusted:
                raise AgenticCoordinationError("specialist approval trust key is duplicated")
            trusted[key.key_id] = key
        if not trusted:
            raise AgenticCoordinationError(
                "specialist approval deployment requires a trusted keyring"
            )
        trusted_mapping = MappingProxyType(trusted)
        lock = threading.RLock()
        authorities: dict[tuple[str, str], WebActionApprovalInputAuthority] = {}
        trust_anchor_digest = discovery_digest(
            "pajin.agentic.specialist-approval-keyring/v1",
            {
                "keys": [
                    key.model_dump(mode="json", by_alias=True)
                    for key in sorted(trusted.values(), key=lambda item: item.key_id)
                ]
            },
        )
        prefix = "_AgenticSpecialistApprovalInputAuthority__"
        object.__setattr__(self, prefix + "trusted", trusted_mapping)
        object.__setattr__(self, prefix + "clock", clock)
        object.__setattr__(self, prefix + "lock", lock)
        object.__setattr__(self, prefix + "authorities", authorities)
        object.__setattr__(self, prefix + "trust_anchor_digest", trust_anchor_digest)

    @property
    def trust_anchor_digest(self) -> str:
        return self.__trust_anchor_digest

    def runtime_identity(self) -> _AgenticSpecialistApprovalRuntimeIdentity:
        """Recompute the keyring anchor and expose only exact process-local identity."""

        trusted = self.__trusted
        if (
            type(self) is not _AgenticSpecialistApprovalInputAuthority
            or type(trusted) is not MappingProxyType
            or type(self.__lock) is not RLockType
            or type(self.__authorities) is not dict
            or not callable(self.__clock)
        ):
            raise AgenticCoordinationError("specialist approval deployment runtime changed")
        try:
            keys = tuple(sorted(trusted.values(), key=lambda item: item.key_id))
        except (AttributeError, TypeError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist approval deployment keyring changed"
            ) from exc
        if not keys or any(
            type(key) is not WebAssessmentVerificationKey
            or trusted.get(key.key_id) is not key
            or key.role is not WebAssessmentSigningRole.ACTION_APPROVER
            for key in keys
        ):
            raise AgenticCoordinationError("specialist approval deployment keyring changed")
        recomputed_digest = discovery_digest(
            "pajin.agentic.specialist-approval-keyring/v1",
            {"keys": [key.model_dump(mode="json", by_alias=True) for key in keys]},
        )
        if recomputed_digest != self.__trust_anchor_digest:
            raise AgenticCoordinationError("specialist approval deployment keyring changed")
        return _AgenticSpecialistApprovalRuntimeIdentity(
            authority=self,
            trusted_mapping=trusted,
            trust_anchor_digest=recomputed_digest,
            clock=self.__clock,
            lock=self.__lock,
            registered_authorities=self.__authorities,
        )

    def verifier_for(
        self,
        signed_approval: SignedWebActionApproval,
        *,
        expected_approval: ActionApprovalEnvelope,
    ) -> WebActionApprovalInputAuthority:
        """Build a verifier only from a signature and this deployment's pinned key."""

        try:
            signed = SignedWebActionApproval.model_validate(
                signed_approval.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist signed approval artifact is invalid"
            ) from exc
        key = self.__trusted.get(signed.key_id)
        if signed.role != "source" or signed.approval != expected_approval or key is None:
            raise AgenticCoordinationError(
                "specialist signed approval is outside the deployment trust root"
            )
        try:
            verifier = WebActionApprovalInputAuthority(
                role="source",
                key=key,
                signed=signed,
                clock=self.__clock,
            )
            _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION(
                verifier,
                expected_approval.mission_envelope,
                expected_approval.proposal,
                expected_approval.graph_decision,
                expected_approval,
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist signed approval failed deployment verification"
            ) from exc
        return verifier

    def register(
        self,
        verifier: WebActionApprovalInputAuthority,
    ) -> WebActionApprovalInputAuthority:
        trusted_key = self.__trusted.get(verifier.key.key_id)
        if (
            type(verifier) is not WebActionApprovalInputAuthority
            or verifier.role != "source"
            or trusted_key != verifier.key
            or verifier.signed.key_id != verifier.key.key_id
            or WebActionApprovalInputAuthority.verify_action_approval
            is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
            or "verify_action_approval" in vars(verifier)
        ):
            raise AgenticCoordinationError("specialist approval verifier implementation changed")
        identity = (
            verifier.signed.approval.approval_id,
            verifier.signed.approval.approval_digest,
        )
        with self.__lock:
            existing = self.__authorities.get(identity)
            if existing is not None and (
                existing.signed != verifier.signed or existing.key != verifier.key
            ):
                raise AgenticCoordinationError("specialist signed approval identity is ambiguous")
            if existing is not None:
                return existing
            self.__authorities[identity] = verifier
            return verifier

    def require_registered(self, verifier: WebActionApprovalInputAuthority) -> None:
        identity = (
            verifier.signed.approval.approval_id,
            verifier.signed.approval.approval_digest,
        )
        with self.__lock:
            if (
                self.__authorities.get(identity) is not verifier
                or self.__trusted.get(verifier.key.key_id) != verifier.key
                or verifier.signed.key_id != verifier.key.key_id
            ):
                raise AgenticCoordinationError(
                    "specialist approval verifier is not deployment registered"
                )

    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        try:
            canonical = ActionApprovalEnvelope.model_validate(
                approval.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("specialist approval selection is invalid") from exc
        identity = (canonical.approval_id, canonical.approval_digest)
        with self.__lock:
            verifier = self.__authorities.get(identity)
            trusted_key = self.__trusted.get(verifier.key.key_id) if verifier is not None else None
        if (
            verifier is None
            or type(verifier) is not WebActionApprovalInputAuthority
            or verifier.role != "source"
            or verifier.signed.approval != canonical
            or trusted_key != verifier.key
            or verifier.signed.key_id != verifier.key.key_id
            or WebActionApprovalInputAuthority.verify_action_approval
            is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
            or "verify_action_approval" in vars(verifier)
        ):
            raise AgenticCoordinationError("specialist approval is not trusted by the deployment")
        _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION(
            verifier,
            envelope,
            proposal,
            decision,
            canonical,
        )


_AGENTIC_SPECIALIST_APPROVAL_VERIFY_IMPLEMENTATION = (
    _AgenticSpecialistApprovalInputAuthority.verify_action_approval
)
_AGENTIC_SPECIALIST_APPROVAL_VERIFIER_FOR_IMPLEMENTATION = (
    _AgenticSpecialistApprovalInputAuthority.verifier_for
)
_AGENTIC_SPECIALIST_APPROVAL_REGISTER_IMPLEMENTATION = (
    _AgenticSpecialistApprovalInputAuthority.register
)
_AGENTIC_SPECIALIST_APPROVAL_REQUIRE_REGISTERED_IMPLEMENTATION = (
    _AgenticSpecialistApprovalInputAuthority.require_registered
)
_AGENTIC_SPECIALIST_APPROVAL_RUNTIME_IDENTITY_IMPLEMENTATION = (
    _AgenticSpecialistApprovalInputAuthority.runtime_identity
)


class _AgenticSpecialistPermitDeployment(_UncopyableAgenticAuthority):
    """Process-local trust root pinned when the coordination store is created."""

    __slots__ = (
        "__approval_input",
        "__campaign_id",
        "__capabilities",
        "__capability_ledger",
        "__capability_records",
        "__compiler_identity",
        "__dispatcher",
        "__graph_authority",
        "__graph_authority_clock",
        "__graph_authority_permit_ttl",
        "__graph_file_identity",
        "__graph_store",
        "__ledger_identity",
        "__lock",
        "__permit_store",
        "__policies",
        "__runtime_generation",
    )
    __approval_input: _AgenticSpecialistApprovalInputAuthority
    __campaign_id: str
    __capabilities: ActionCapabilityRegistry | None
    __capability_ledger: CapabilityLedger
    __capability_records: tuple[RegisteredActionCapability, ...] | None
    __compiler_identity: tuple[str, str, str] | None
    __dispatcher: GraphApprovedActionPermitDispatcher | None
    __graph_authority: GraphApprovedActionPermitAuthority | None
    __graph_authority_clock: object | None
    __graph_authority_permit_ttl: timedelta | None
    __graph_file_identity: tuple[tuple[int, int], tuple[int, int]]
    __graph_store: SQLiteGraphStore
    __ledger_identity: tuple[object, object, object, object]
    __lock: RLockType
    __permit_store: SQLiteGraphActionPermitStore
    __policies: ActionApprovalCapabilityPolicyRegistry | None
    __runtime_generation: AgenticSpecialistRuntimeGeneration

    def __init__(
        self,
        *,
        campaign_id: str,
        graph_store: SQLiteGraphStore,
        capability_ledger: CapabilityLedger,
        approval_keys: Iterable[WebAssessmentVerificationKey],
        approval_clock: Callable[[], datetime],
        runtime_generation: AgenticSpecialistRuntimeGeneration,
    ) -> None:
        if type(runtime_generation) is not AgenticSpecialistRuntimeGeneration:
            raise AgenticCoordinationError("specialist deployment runtime generation is invalid")
        if type(graph_store) is not SQLiteGraphStore:
            raise AgenticCoordinationError("specialist deployment requires its exact Graph Store")
        permit_store = graph_store.permit_store
        if (
            graph_store.campaign_id != campaign_id
            or type(permit_store) is not SQLiteGraphActionPermitStore
            or graph_store.approved_permit_store is not permit_store
            or permit_store.path != graph_store.path
            or getattr(permit_store, "_campaign_id", None) != campaign_id
        ):
            raise AgenticCoordinationError("specialist deployment Graph and Permit stores differ")
        ledger_identity = _capability_ledger_runtime_identity(capability_ledger)
        approval_input = _AgenticSpecialistApprovalInputAuthority(
            keys=approval_keys,
            clock=approval_clock,
        )
        prefix = "_AgenticSpecialistPermitDeployment__"
        object.__setattr__(self, prefix + "graph_store", graph_store)
        object.__setattr__(self, prefix + "permit_store", permit_store)
        object.__setattr__(
            self,
            prefix + "graph_file_identity",
            SQLiteGraphStore.runtime_file_identity(graph_store),
        )
        object.__setattr__(self, prefix + "capability_ledger", capability_ledger)
        object.__setattr__(self, prefix + "ledger_identity", ledger_identity)
        object.__setattr__(self, prefix + "approval_input", approval_input)
        object.__setattr__(self, prefix + "campaign_id", campaign_id)
        object.__setattr__(self, prefix + "runtime_generation", runtime_generation)
        object.__setattr__(self, prefix + "lock", threading.RLock())
        object.__setattr__(self, prefix + "capability_records", None)
        object.__setattr__(self, prefix + "capabilities", None)
        object.__setattr__(self, prefix + "policies", None)
        object.__setattr__(self, prefix + "compiler_identity", None)
        object.__setattr__(self, prefix + "graph_authority", None)
        object.__setattr__(self, prefix + "graph_authority_clock", None)
        object.__setattr__(self, prefix + "graph_authority_permit_ttl", None)
        object.__setattr__(self, prefix + "dispatcher", None)

    @property
    def graph_store(self) -> SQLiteGraphStore:
        return self.__graph_store

    @property
    def approval_input(self) -> _AgenticSpecialistApprovalInputAuthority:
        return self.__approval_input

    def runtime_identity(self) -> _AgenticSpecialistDeploymentRuntimeIdentity:
        """Return a recomputed identity for every deployment-owned trust root."""

        if (
            type(self) is not _AgenticSpecialistPermitDeployment
            or type(self.__runtime_generation) is not AgenticSpecialistRuntimeGeneration
            or type(self.__graph_store) is not SQLiteGraphStore
            or type(self.__permit_store) is not SQLiteGraphActionPermitStore
            or type(self.__approval_input) is not _AgenticSpecialistApprovalInputAuthority
            or type(self.__lock) is not RLockType
            or _AgenticSpecialistApprovalInputAuthority.runtime_identity
            is not _AGENTIC_SPECIALIST_APPROVAL_RUNTIME_IDENTITY_IMPLEMENTATION
        ):
            raise AgenticCoordinationError(
                "specialist deployment Graph, Permit, or Ledger authority changed"
            )
        approval_identity = _AGENTIC_SPECIALIST_APPROVAL_RUNTIME_IDENTITY_IMPLEMENTATION(
            self.__approval_input
        )
        max_depth, records, ledger_lock, ledger_clock = _capability_ledger_runtime_identity(
            self.__capability_ledger
        )
        return _AgenticSpecialistDeploymentRuntimeIdentity(
            deployment=self,
            runtime_generation=self.__runtime_generation,
            campaign_id=self.__campaign_id,
            graph_store=self.__graph_store,
            permit_store=self.__permit_store,
            graph_file_identity=SQLiteGraphStore.runtime_file_identity(self.__graph_store),
            capability_ledger=self.__capability_ledger,
            ledger_max_depth=max_depth,
            ledger_records=records,
            ledger_lock=ledger_lock,
            ledger_clock=ledger_clock,
            approval=approval_identity,
            lock=self.__lock,
        )

    def configured_runtime_identity(
        self,
    ) -> _AgenticSpecialistConfiguredRuntimeIdentity | None:
        """Recompute the shared writer identity after its first valid bind."""

        configured = (
            self.__capability_records,
            self.__capabilities,
            self.__policies,
            self.__compiler_identity,
            self.__graph_authority,
            self.__dispatcher,
            self.__graph_authority_clock,
            self.__graph_authority_permit_ttl,
        )
        if all(item is None for item in configured):
            return None
        writer = (
            getattr(self.__graph_authority, "_writer", None)
            if self.__graph_authority is not None
            else None
        )
        if (
            type(self.__capability_records) is not tuple
            or type(self.__capabilities) is not ActionCapabilityRegistry
            or type(self.__policies) is not ActionApprovalCapabilityPolicyRegistry
            or type(self.__compiler_identity) is not tuple
            or len(self.__compiler_identity) != 3
            or not all(type(item) is str for item in self.__compiler_identity)
            or type(self.__graph_authority) is not GraphApprovedActionPermitAuthority
            or type(self.__dispatcher) is not GraphApprovedActionPermitDispatcher
            or getattr(self.__dispatcher, "_authority", None) is not self.__graph_authority
            or not callable(self.__graph_authority_clock)
            or self.__graph_authority_permit_ttl != _AGENTIC_SPECIALIST_PERMIT_TTL
            or getattr(self.__graph_authority, "_clock", None) is not self.__graph_authority_clock
            or getattr(self.__graph_authority, "_permit_ttl", None)
            != self.__graph_authority_permit_ttl
            or writer is None
        ):
            raise AgenticCoordinationError("specialist deployment Graph writer authority changed")
        return _AgenticSpecialistConfiguredRuntimeIdentity(
            deployment=self,
            runtime_generation=self.__runtime_generation,
            capability_records=self.__capability_records,
            capabilities=self.__capabilities,
            policies=self.__policies,
            compiler_identity=self.__compiler_identity,
            graph_authority=cast(
                GraphApprovedActionPermitAuthority,
                self.__graph_authority,
            ),
            dispatcher=self.__dispatcher,
            clock=self.__graph_authority_clock,
            permit_ttl=self.__graph_authority_permit_ttl,
            writer=writer,
        )

    def require_runtime(
        self,
        *,
        graph_store: SQLiteGraphStore | None = None,
        capability_ledger: CapabilityLedger | None = None,
        expected_identity: _AgenticSpecialistDeploymentRuntimeIdentity | None = None,
        expected_configured_identity: (_AgenticSpecialistConfiguredRuntimeIdentity | None) = None,
    ) -> None:
        if (
            _AgenticSpecialistPermitDeployment.runtime_identity
            is not _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION
        ):
            raise AgenticCoordinationError(
                "specialist deployment Graph, Permit, or Ledger authority changed"
            )
        observed_runtime_identity = _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(
            self
        )
        if (
            _AgenticSpecialistPermitDeployment.configured_runtime_identity
            is not _AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION
        ):
            raise AgenticCoordinationError("specialist deployment Graph writer authority changed")
        observed_configured_identity = (
            _AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION(self)
        )
        observed_ledger = (
            self.__capability_ledger if capability_ledger is None else capability_ledger
        )
        observed_identity = _capability_ledger_runtime_identity(observed_ledger)
        pinned_max_depth, pinned_records, pinned_lock, pinned_clock = self.__ledger_identity
        max_depth, records, ledger_lock, ledger_clock = observed_identity
        if (
            (
                expected_identity is not None
                and not _same_specialist_deployment_runtime_identity(
                    observed_runtime_identity,
                    expected_identity,
                )
            )
            or (graph_store is not None and graph_store is not self.__graph_store)
            or self.__graph_store.campaign_id != self.__campaign_id
            or self.__graph_store.permit_store is not self.__permit_store
            or self.__graph_store.approved_permit_store is not self.__permit_store
            or self.__permit_store.path != self.__graph_store.path
            or getattr(self.__permit_store, "_campaign_id", None) != self.__campaign_id
            or SQLiteGraphStore.runtime_file_identity(self.__graph_store)
            != self.__graph_file_identity
            or observed_ledger is not self.__capability_ledger
            or max_depth != pinned_max_depth
            or records is not pinned_records
            or ledger_lock is not pinned_lock
            or ledger_clock is not pinned_clock
            or type(self.__approval_input) is not _AgenticSpecialistApprovalInputAuthority
            or _AgenticSpecialistApprovalInputAuthority.verify_action_approval
            is not _AGENTIC_SPECIALIST_APPROVAL_VERIFY_IMPLEMENTATION
            or _AgenticSpecialistApprovalInputAuthority.verifier_for
            is not _AGENTIC_SPECIALIST_APPROVAL_VERIFIER_FOR_IMPLEMENTATION
            or _AgenticSpecialistApprovalInputAuthority.register
            is not _AGENTIC_SPECIALIST_APPROVAL_REGISTER_IMPLEMENTATION
            or _AgenticSpecialistApprovalInputAuthority.require_registered
            is not _AGENTIC_SPECIALIST_APPROVAL_REQUIRE_REGISTERED_IMPLEMENTATION
            or _AgenticSpecialistApprovalInputAuthority.runtime_identity
            is not _AGENTIC_SPECIALIST_APPROVAL_RUNTIME_IDENTITY_IMPLEMENTATION
        ):
            raise AgenticCoordinationError(
                "specialist deployment Graph, Permit, or Ledger authority changed"
            )
        if expected_configured_identity is not None and (
            observed_configured_identity is None
            or not _same_specialist_configured_runtime_identity(
                observed_configured_identity,
                expected_configured_identity,
            )
        ):
            raise AgenticCoordinationError("specialist deployment Graph writer authority changed")
        if self.__graph_authority is not None and (
            self.__capabilities is None
            or self.__policies is None
            or self.__compiler_identity is None
            or self.__dispatcher is None
            or self.__graph_authority_clock is None
            or self.__graph_authority_permit_ttl != _AGENTIC_SPECIALIST_PERMIT_TTL
            or getattr(self.__graph_authority, "_clock", None) is not self.__graph_authority_clock
            or getattr(self.__graph_authority, "_permit_ttl", None)
            != self.__graph_authority_permit_ttl
            or getattr(self.__permit_store, "_approved_input_authority", None)
            is not self.__approval_input
            or type(getattr(self.__permit_store, "_approved_policies", None))
            is not ActionApprovalCapabilityPolicyRegistry
            or getattr(self.__permit_store, "_approved_policy_digest", None)
            != self.__policies.registry_digest
            or getattr(self.__permit_store, "_approved_writer", None)
            is not getattr(self.__graph_authority, "_writer", None)
            or getattr(self.__permit_store, "_writer_identity", None) != self.__compiler_identity
        ):
            raise AgenticCoordinationError("specialist deployment Graph writer authority changed")

    @staticmethod
    def _registry_for_activation(
        activation: WebSpecialistCapabilityActivation,
    ) -> tuple[
        tuple[RegisteredActionCapability, ...],
        ActionCapabilityRegistry,
        ActionApprovalCapabilityPolicyRegistry,
    ]:
        from pajin.capabilities.agentic_web_specialist import (
            WebSpecialistCapabilityActivation,
            WebSpecialistCapabilityEntry,
        )

        if type(activation) is not WebSpecialistCapabilityActivation:
            raise AgenticCoordinationError("specialist deployment activation is invalid")
        expected_specializations = {
            PentestSpecialization.XSS,
            PentestSpecialization.SQL_INJECTION,
            PentestSpecialization.AUTHORIZATION,
        }
        entries = activation.bundle.entries
        if (
            len(entries) != len(expected_specializations)
            or {entry.specialization for entry in entries} != expected_specializations
            or any(type(entry) is not WebSpecialistCapabilityEntry for entry in entries)
        ):
            raise AgenticCoordinationError(
                "specialist deployment Capability inventory is incomplete"
            )
        records: list[RegisteredActionCapability] = []
        for entry in entries:
            definition = activation.bundle.definitions.resolve(entry.definition.reference())
            code_reference = activation.bundle.capability(entry.specialization).reference()
            registered = registered_action_capability(definition)
            if (
                definition != entry.definition
                or code_reference.capability != definition.reference()
                or registered.reference().definition_digest
                != code_reference.capability.capability_digest
            ):
                raise AgenticCoordinationError("specialist deployment Capability inventory drifted")
            records.append(registered)
        canonical_records = tuple(
            sorted(records, key=lambda item: (item.capability_id, item.capability_version))
        )
        capabilities = ActionCapabilityRegistry(canonical_records)
        policies = ActionApprovalCapabilityPolicyRegistry(
            tuple(
                ActionApprovalCapabilityPolicy(
                    capability=record.reference(),
                    sideEffectClass="read-only",
                    approvalRequired=True,
                    cleanupRequired=False,
                )
                for record in canonical_records
            )
        )
        return canonical_records, capabilities, policies

    @staticmethod
    def _registry_for_sql_specialist_v2_activation(
        activation: WebSQLSpecialistCapabilityActivationV2,
    ) -> tuple[
        tuple[RegisteredActionCapability, ...],
        ActionCapabilityRegistry,
        ActionApprovalCapabilityPolicyRegistry,
    ]:
        from pajin.capabilities.agentic_web_specialist_v2 import (
            WebSQLSpecialistCapabilityActivationV2,
        )

        if type(activation) is not WebSQLSpecialistCapabilityActivationV2:
            raise AgenticCoordinationError("SQL specialist v2 deployment activation is invalid")
        definition, action_registry = _sql_specialist_v2_definition_and_registry(activation)
        code_reference = activation.activation_set.binding.capability
        registered = registered_action_capability(definition)
        resolved = action_registry.resolve(registered.reference())
        if (
            definition != activation.bundle.definition
            or code_reference.capability != definition.reference()
            or registered.reference() != resolved.reference()
            or registered.reference().definition_digest
            != code_reference.capability.capability_digest
            or registered.capability_id != _EXECUTABLE_SPECIALIST_CAPABILITY_ID
            or registered.capability_version != _EXECUTABLE_SPECIALIST_CAPABILITY_VERSION
            or registered.tool_id != _EXECUTABLE_SPECIALIST_TOOL_ID
            or registered.tool_version != _EXECUTABLE_SPECIALIST_TOOL_VERSION
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 deployment Capability inventory drifted"
            )
        records = (registered,)
        capabilities = ActionCapabilityRegistry(records)
        policies = ActionApprovalCapabilityPolicyRegistry(
            (
                ActionApprovalCapabilityPolicy(
                    capability=registered.reference(),
                    sideEffectClass="read-only",
                    approvalRequired=True,
                    cleanupRequired=False,
                ),
            )
        )
        return records, capabilities, policies

    def configure_plan(
        self,
        *,
        activation: WebSpecialistCapabilityActivation,
        approval: ActionApprovalEnvelope,
        verifier: WebActionApprovalInputAuthority,
        clock: Callable[[], datetime],
    ) -> tuple[
        ActionCapabilityRegistry,
        ActionApprovalCapabilityPolicyRegistry,
        GraphApprovedActionPermitAuthority,
        GraphApprovedActionPermitDispatcher,
        WebActionApprovalInputAuthority,
    ]:
        if self.__runtime_generation is not AgenticSpecialistRuntimeGeneration.LEGACY_V1:
            raise AgenticCoordinationError(
                "specialist deployment is not pinned to the legacy-v1 runtime"
            )
        records, candidate_capabilities, candidate_policies = self._registry_for_activation(
            activation
        )
        compiler_identity = (
            approval.mission_envelope.compiler_id,
            approval.mission_envelope.compiler_version,
            approval.mission_envelope.compiler_digest,
        )
        with self.__lock:
            _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(self)
            if self.__graph_authority is None:
                graph_authority = GraphApprovedActionPermitAuthority(
                    campaign_id=self.__campaign_id,
                    compiler_id=compiler_identity[0],
                    compiler_version=compiler_identity[1],
                    compiler_digest=compiler_identity[2],
                    capabilities=candidate_capabilities,
                    policies=candidate_policies,
                    permit_store=self.__permit_store,
                    input_authority=self.__approval_input,
                    clock=clock,
                    permit_ttl=_AGENTIC_SPECIALIST_PERMIT_TTL,
                )
                prefix = "_AgenticSpecialistPermitDeployment__"
                object.__setattr__(self, prefix + "capability_records", records)
                object.__setattr__(self, prefix + "capabilities", candidate_capabilities)
                object.__setattr__(self, prefix + "policies", candidate_policies)
                object.__setattr__(self, prefix + "compiler_identity", compiler_identity)
                object.__setattr__(self, prefix + "graph_authority", graph_authority)
                object.__setattr__(self, prefix + "graph_authority_clock", clock)
                object.__setattr__(
                    self,
                    prefix + "graph_authority_permit_ttl",
                    _AGENTIC_SPECIALIST_PERMIT_TTL,
                )
                object.__setattr__(
                    self,
                    prefix + "dispatcher",
                    GraphApprovedActionPermitDispatcher(graph_authority),
                )
            elif (
                self.__capability_records != records
                or self.__compiler_identity != compiler_identity
                or self.__policies is None
                or self.__policies.registry_digest != candidate_policies.registry_digest
                or clock is not self.__graph_authority_clock
            ):
                raise AgenticCoordinationError(
                    "specialist deployment Capability or compiler authority changed"
                )
            assert self.__capabilities is not None
            assert self.__policies is not None
            assert self.__graph_authority is not None
            assert self.__dispatcher is not None
            self.__capabilities.resolve(approval.proposal.capability)
            canonical_verifier = _AGENTIC_SPECIALIST_APPROVAL_REGISTER_IMPLEMENTATION(
                self.__approval_input,
                verifier,
            )
            return (
                self.__capabilities,
                self.__policies,
                self.__graph_authority,
                self.__dispatcher,
                canonical_verifier,
            )

    def configure_sql_specialist_v2_plan(
        self,
        *,
        activation: WebSQLSpecialistCapabilityActivationV2,
        approval: ActionApprovalEnvelope,
        verifier: WebActionApprovalInputAuthority,
        clock: Callable[[], datetime],
    ) -> tuple[
        ActionCapabilityRegistry,
        ActionApprovalCapabilityPolicyRegistry,
        GraphApprovedActionPermitAuthority,
        GraphApprovedActionPermitDispatcher,
        WebActionApprovalInputAuthority,
    ]:
        if self.__runtime_generation is not AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2:
            raise AgenticCoordinationError(
                "specialist deployment is not pinned to the SQL-specialist-v2 runtime"
            )
        records, candidate_capabilities, candidate_policies = (
            self._registry_for_sql_specialist_v2_activation(activation)
        )
        compiler_identity = (
            approval.mission_envelope.compiler_id,
            approval.mission_envelope.compiler_version,
            approval.mission_envelope.compiler_digest,
        )
        with self.__lock:
            _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(self)
            if self.__graph_authority is None:
                graph_authority = GraphApprovedActionPermitAuthority(
                    campaign_id=self.__campaign_id,
                    compiler_id=compiler_identity[0],
                    compiler_version=compiler_identity[1],
                    compiler_digest=compiler_identity[2],
                    capabilities=candidate_capabilities,
                    policies=candidate_policies,
                    permit_store=self.__permit_store,
                    input_authority=self.__approval_input,
                    clock=clock,
                    permit_ttl=_AGENTIC_SPECIALIST_PERMIT_TTL,
                )
                prefix = "_AgenticSpecialistPermitDeployment__"
                object.__setattr__(self, prefix + "capability_records", records)
                object.__setattr__(self, prefix + "capabilities", candidate_capabilities)
                object.__setattr__(self, prefix + "policies", candidate_policies)
                object.__setattr__(self, prefix + "compiler_identity", compiler_identity)
                object.__setattr__(self, prefix + "graph_authority", graph_authority)
                object.__setattr__(self, prefix + "graph_authority_clock", clock)
                object.__setattr__(
                    self,
                    prefix + "graph_authority_permit_ttl",
                    _AGENTIC_SPECIALIST_PERMIT_TTL,
                )
                object.__setattr__(
                    self,
                    prefix + "dispatcher",
                    GraphApprovedActionPermitDispatcher(graph_authority),
                )
            elif (
                self.__capability_records != records
                or self.__compiler_identity != compiler_identity
                or self.__policies is None
                or self.__policies.registry_digest != candidate_policies.registry_digest
                or clock is not self.__graph_authority_clock
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 deployment Capability or compiler authority changed"
                )
            assert self.__capabilities is not None
            assert self.__policies is not None
            assert self.__graph_authority is not None
            assert self.__dispatcher is not None
            self.__capabilities.resolve(approval.proposal.capability)
            canonical_verifier = _AGENTIC_SPECIALIST_APPROVAL_REGISTER_IMPLEMENTATION(
                self.__approval_input,
                verifier,
            )
            return (
                self.__capabilities,
                self.__policies,
                self.__graph_authority,
                self.__dispatcher,
                canonical_verifier,
            )


_AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION = (
    _AgenticSpecialistPermitDeployment.runtime_identity
)
_AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION = (
    _AgenticSpecialistPermitDeployment.require_runtime
)
_AGENTIC_SPECIALIST_DEPLOYMENT_CONFIGURE_V2_IMPLEMENTATION = (
    _AgenticSpecialistPermitDeployment.configure_sql_specialist_v2_plan
)
_AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION = (
    _AgenticSpecialistPermitDeployment.configured_runtime_identity
)


class VerifiedSpecialistPermitDispatcher(_UncopyableAgenticAuthority):
    """Factory-only deployment authority for one exact planned Permit callback."""

    __slots__ = (
        "__activation",
        "__approval_authority",
        "__approval_envelope",
        "__authority",
        "__campaign",
        "__capabilities",
        "__capability_grant",
        "__capability_ledger",
        "__configured_runtime_identity",
        "__deployment",
        "__deployment_runtime_identity",
        "__dispatcher",
        "__graph_authority",
        "__graph_file_identity",
        "__graph_store",
        "__permit_store",
        "__plan_digest",
        "__plan_id",
        "__policies",
        "__preparation",
        "__prepared_action",
    )
    __activation: WebSpecialistCapabilityActivation
    __approval_authority: WebActionApprovalInputAuthority
    __approval_envelope: ActionApprovalEnvelope
    __authority: object
    __campaign: CampaignManifest
    __capabilities: ActionCapabilityRegistry
    __capability_grant: CapabilityGrant
    __capability_ledger: CapabilityLedger
    __configured_runtime_identity: _AgenticSpecialistConfiguredRuntimeIdentity
    __dispatcher: GraphApprovedActionPermitDispatcher
    __deployment: _AgenticSpecialistPermitDeployment
    __deployment_runtime_identity: _AgenticSpecialistDeploymentRuntimeIdentity
    __graph_authority: GraphApprovedActionPermitAuthority
    __graph_file_identity: tuple[tuple[int, int], tuple[int, int]]
    __graph_store: SQLiteGraphStore
    __permit_store: SQLiteGraphActionPermitStore
    __policies: ActionApprovalCapabilityPolicyRegistry
    __plan_digest: str
    __plan_id: str
    __preparation: AgenticSpecialistPreparation
    __prepared_action: PreparedCapabilityAction

    def __init__(
        self,
        *,
        plan: VerifiedSpecialistDispatchPlan,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSpecialistCapabilityActivation,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        deployment: _AgenticSpecialistPermitDeployment,
        graph_store: SQLiteGraphStore,
        approval_authority: WebActionApprovalInputAuthority,
        capabilities: ActionCapabilityRegistry,
        policies: ActionApprovalCapabilityPolicyRegistry,
        graph_authority: GraphApprovedActionPermitAuthority,
        dispatcher: GraphApprovedActionPermitDispatcher,
        _authority: object,
    ) -> None:
        configured_runtime_identity = (
            _AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION(deployment)
        )
        if configured_runtime_identity is None:
            raise AgenticCoordinationError(
                "specialist Permit dispatcher has no configured deployment writer"
            )
        object.__setattr__(self, "_VerifiedSpecialistPermitDispatcher__plan_id", plan.entry.plan_id)
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__plan_digest",
            plan.entry.plan_digest,
        )
        object.__setattr__(self, "_VerifiedSpecialistPermitDispatcher__campaign", campaign)
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__preparation",
            preparation,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__capability_ledger",
            capability_ledger,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__capability_grant",
            capability_grant,
        )
        object.__setattr__(self, "_VerifiedSpecialistPermitDispatcher__activation", activation)
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__prepared_action",
            prepared_action,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__approval_envelope",
            approval_envelope,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__graph_store",
            graph_store,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__deployment",
            deployment,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__deployment_runtime_identity",
            _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(deployment),
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__configured_runtime_identity",
            configured_runtime_identity,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__graph_file_identity",
            graph_store.runtime_file_identity(),
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__permit_store",
            graph_store.permit_store,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__approval_authority",
            approval_authority,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__capabilities",
            capabilities,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__policies",
            policies,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__graph_authority",
            graph_authority,
        )
        object.__setattr__(
            self,
            "_VerifiedSpecialistPermitDispatcher__dispatcher",
            dispatcher,
        )
        object.__setattr__(self, "_VerifiedSpecialistPermitDispatcher__authority", _authority)

    def _runtime_inputs(
        self,
        authority: object,
        plan: VerifiedSpecialistDispatchPlan,
        *,
        callback_claimed: bool = False,
    ) -> tuple[
        CampaignManifest,
        AgenticSpecialistPreparation,
        CapabilityLedger,
        CapabilityGrant,
        WebSpecialistCapabilityActivation,
        PreparedCapabilityAction,
        ActionApprovalEnvelope,
        SQLiteGraphStore,
        WebActionApprovalInputAuthority,
    ]:
        graph_authority = getattr(self.__dispatcher, "_authority", None)
        _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
            self.__deployment,
            graph_store=self.__graph_store,
            capability_ledger=self.__capability_ledger,
            expected_identity=self.__deployment_runtime_identity,
            expected_configured_identity=self.__configured_runtime_identity,
        )
        _AGENTIC_SPECIALIST_APPROVAL_REQUIRE_REGISTERED_IMPLEMENTATION(
            self.__deployment.approval_input,
            self.__approval_authority,
        )
        if (
            type(self) is not VerifiedSpecialistPermitDispatcher
            or self.__authority is not authority
            or type(plan) is not VerifiedSpecialistDispatchPlan
            or plan.entry.plan_id != self.__plan_id
            or plan.entry.plan_digest != self.__plan_digest
            or type(self.__graph_store) is not SQLiteGraphStore
            or SQLiteGraphStore.runtime_file_identity(self.__graph_store)
            != self.__graph_file_identity
            or type(self.__permit_store) is not SQLiteGraphActionPermitStore
            or self.__graph_store.permit_store is not self.__permit_store
            or self.__graph_store.approved_permit_store is not self.__permit_store
            or self.__permit_store.path != self.__graph_store.path
            or getattr(self.__permit_store, "_campaign_id", None) != self.__campaign.metadata.name
            or type(self.__approval_authority) is not WebActionApprovalInputAuthority
            or self.__approval_authority.role != "source"
            or self.__approval_authority.signed.approval != self.__approval_envelope
            or type(self.__capabilities) is not ActionCapabilityRegistry
            or type(self.__policies) is not ActionApprovalCapabilityPolicyRegistry
            or type(self.__dispatcher) is not GraphApprovedActionPermitDispatcher
            or type(graph_authority) is not GraphApprovedActionPermitAuthority
            or graph_authority is not self.__graph_authority
            or getattr(graph_authority, "_campaign_id", None) != self.__campaign.metadata.name
            or getattr(graph_authority, "_capabilities", None) is not self.__capabilities
            or getattr(graph_authority, "_policies", None) is not self.__policies
            or getattr(graph_authority, "_permit_store", None) is not self.__permit_store
            or getattr(graph_authority, "_input_authority", None)
            is not self.__deployment.approval_input
            or GraphApprovedActionPermitDispatcher.dispatch_once
            is not _GRAPH_APPROVED_DISPATCH_IMPLEMENTATION
            or GraphApprovedActionPermitAuthority.authorize_for_dispatch
            is not _GRAPH_APPROVED_AUTHORIZE_IMPLEMENTATION
            or SQLiteGraphActionPermitStore.approved_authorization
            is not _GRAPH_APPROVED_LOOKUP_IMPLEMENTATION
            or SQLiteGraphActionPermitStore.claim_approved_writer
            is not _GRAPH_APPROVED_CLAIM_WRITER_IMPLEMENTATION
            or SQLiteGraphActionPermitStore.authorize_approved_for_dispatch
            is not _GRAPH_APPROVED_STORE_AUTHORIZE_IMPLEMENTATION
            or WebActionApprovalInputAuthority.verify_action_approval
            is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
            or "dispatch_once" in vars(self.__dispatcher)
            or "authorize_for_dispatch" in vars(graph_authority)
            or "approved_authorization" in vars(self.__permit_store)
            or "claim_approved_writer" in vars(self.__permit_store)
            or "authorize_approved_for_dispatch" in vars(self.__permit_store)
            or "verify_action_approval" in vars(self.__approval_authority)
        ):
            raise AgenticCoordinationError(
                "specialist Permit dispatcher differs from its deployment authority"
            )
        if callback_claimed:
            plan._require_claimed_callback(authority)
        else:
            plan._require_runtime(
                authority,
                campaign=self.__campaign,
                preparation=self.__preparation,
                capability_ledger=self.__capability_ledger,
                capability_grant=self.__capability_grant,
                activation=self.__activation,
                prepared_action=self.__prepared_action,
                approval_envelope=self.__approval_envelope,
                specialist_deployment=self.__deployment,
            )
        return (
            self.__campaign,
            self.__preparation,
            self.__capability_ledger,
            self.__capability_grant,
            self.__activation,
            self.__prepared_action,
            self.__approval_envelope,
            self.__graph_store,
            self.__approval_authority,
        )

    async def _dispatch_once[DispatchResultT](
        self,
        authority: object,
        plan: VerifiedSpecialistDispatchPlan,
        dispatch: Callable[
            [ActionPermit, ActionApprovalConsumptionReceipt],
            Awaitable[DispatchResultT],
        ],
    ) -> ApprovedActionDispatchResult[DispatchResultT]:
        self._runtime_inputs(authority, plan, callback_claimed=True)
        approval = self.__approval_envelope
        return await _GRAPH_APPROVED_DISPATCH_IMPLEMENTATION(
            self.__dispatcher,
            approval.mission_envelope,
            approval.proposal,
            approval.graph_decision,
            approval,
            dispatch,
        )

    def _terminal_authorization(
        self,
        authority: object,
        plan: VerifiedSpecialistDispatchPlan,
    ) -> ActionApprovalAuthorization | None:
        self._runtime_inputs(authority, plan, callback_claimed=True)
        raw = _GRAPH_APPROVED_LOOKUP_IMPLEMENTATION(
            self.__permit_store,
            self.__approval_envelope.approval_id,
            self.__approval_envelope.expected_action_permit_id,
        )
        if raw is None:
            return None
        try:
            terminal = ActionApprovalAuthorization.model_validate(
                raw.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist Permit terminal authorization is invalid"
            ) from exc
        if (
            terminal.action.newly_consumed
            or terminal.approval != self.__approval_envelope
            or terminal.action.permit != terminal.receipt.action_permit
        ):
            raise AgenticCoordinationError(
                "specialist Permit terminal authorization differs from the sealed plan"
            )
        return terminal


class VerifiedSQLSpecialistPermitDispatcherV2(_UncopyableAgenticAuthority):
    """Task-owned deployment authority for one exact SQL v2 Permit callback."""

    __slots__ = (
        "__activation",
        "__approval_authority",
        "__approval_envelope",
        "__authority",
        "__campaign",
        "__capabilities",
        "__capability_grant",
        "__capability_ledger",
        "__configured_runtime_identity",
        "__deployment",
        "__deployment_runtime_identity",
        "__dispatcher",
        "__graph_authority",
        "__graph_file_identity",
        "__graph_store",
        "__owner_task",
        "__owner_token",
        "__permit_store",
        "__plan_digest",
        "__plan_id",
        "__policies",
        "__preparation",
        "__prepared_action",
    )
    __activation: WebSQLSpecialistCapabilityActivationV2
    __approval_authority: WebActionApprovalInputAuthority
    __approval_envelope: ActionApprovalEnvelope
    __authority: object
    __campaign: CampaignManifest
    __capabilities: ActionCapabilityRegistry
    __capability_grant: CapabilityGrant
    __capability_ledger: CapabilityLedger
    __configured_runtime_identity: _AgenticSpecialistConfiguredRuntimeIdentity
    __deployment: _AgenticSpecialistPermitDeployment
    __deployment_runtime_identity: _AgenticSpecialistDeploymentRuntimeIdentity
    __dispatcher: GraphApprovedActionPermitDispatcher
    __graph_authority: GraphApprovedActionPermitAuthority
    __graph_file_identity: tuple[tuple[int, int], tuple[int, int]]
    __graph_store: SQLiteGraphStore
    __owner_task: asyncio.Task[object]
    __owner_token: object
    __permit_store: SQLiteGraphActionPermitStore
    __plan_digest: str
    __plan_id: str
    __policies: ActionApprovalCapabilityPolicyRegistry
    __preparation: AgenticSpecialistPreparation
    __prepared_action: PreparedCapabilityAction

    def __init__(
        self,
        *,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSQLSpecialistCapabilityActivationV2,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        deployment: _AgenticSpecialistPermitDeployment,
        graph_store: SQLiteGraphStore,
        approval_authority: WebActionApprovalInputAuthority,
        capabilities: ActionCapabilityRegistry,
        policies: ActionApprovalCapabilityPolicyRegistry,
        graph_authority: GraphApprovedActionPermitAuthority,
        dispatcher: GraphApprovedActionPermitDispatcher,
        owner_task: asyncio.Task[object],
        owner_token: object,
        _authority: object,
    ) -> None:
        configured_runtime_identity = (
            _AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION(deployment)
        )
        if (
            configured_runtime_identity is None
            or configured_runtime_identity.runtime_generation
            is not AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit dispatcher has no configured deployment writer"
            )
        prefix = "_VerifiedSQLSpecialistPermitDispatcherV2__"
        object.__setattr__(self, prefix + "plan_id", plan.entry.plan_id)
        object.__setattr__(self, prefix + "plan_digest", plan.entry.plan_digest)
        object.__setattr__(self, prefix + "campaign", campaign)
        object.__setattr__(self, prefix + "preparation", preparation)
        object.__setattr__(self, prefix + "capability_ledger", capability_ledger)
        object.__setattr__(self, prefix + "capability_grant", capability_grant)
        object.__setattr__(self, prefix + "activation", activation)
        object.__setattr__(self, prefix + "prepared_action", prepared_action)
        object.__setattr__(self, prefix + "approval_envelope", approval_envelope)
        object.__setattr__(self, prefix + "graph_store", graph_store)
        object.__setattr__(self, prefix + "deployment", deployment)
        object.__setattr__(
            self,
            prefix + "deployment_runtime_identity",
            _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(deployment),
        )
        object.__setattr__(
            self,
            prefix + "configured_runtime_identity",
            configured_runtime_identity,
        )
        object.__setattr__(
            self,
            prefix + "graph_file_identity",
            graph_store.runtime_file_identity(),
        )
        object.__setattr__(self, prefix + "permit_store", graph_store.permit_store)
        object.__setattr__(self, prefix + "approval_authority", approval_authority)
        object.__setattr__(self, prefix + "capabilities", capabilities)
        object.__setattr__(self, prefix + "policies", policies)
        object.__setattr__(self, prefix + "graph_authority", graph_authority)
        object.__setattr__(self, prefix + "dispatcher", dispatcher)
        object.__setattr__(self, prefix + "owner_task", owner_task)
        object.__setattr__(self, prefix + "owner_token", owner_token)
        object.__setattr__(self, prefix + "authority", _authority)

    def _runtime_inputs(
        self,
        authority: object,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        owner_task: asyncio.Task[object],
        owner_token: object,
        *,
        callback_claimed: bool = False,
    ) -> tuple[
        CampaignManifest,
        AgenticSpecialistPreparation,
        CapabilityLedger,
        CapabilityGrant,
        WebSQLSpecialistCapabilityActivationV2,
        PreparedCapabilityAction,
        ActionApprovalEnvelope,
        SQLiteGraphStore,
        WebActionApprovalInputAuthority,
    ]:
        graph_authority = getattr(self.__dispatcher, "_authority", None)
        _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
            self.__deployment,
            graph_store=self.__graph_store,
            capability_ledger=self.__capability_ledger,
            expected_identity=self.__deployment_runtime_identity,
            expected_configured_identity=self.__configured_runtime_identity,
        )
        _AGENTIC_SPECIALIST_APPROVAL_REQUIRE_REGISTERED_IMPLEMENTATION(
            self.__deployment.approval_input,
            self.__approval_authority,
        )
        if (
            type(self) is not VerifiedSQLSpecialistPermitDispatcherV2
            or self.__authority is not authority
            or self.__owner_task is not owner_task
            or self.__owner_token is not owner_token
            or owner_task.done()
            or type(plan) is not VerifiedSQLSpecialistDispatchPlanV2
            or plan.entry.plan_id != self.__plan_id
            or plan.entry.plan_digest != self.__plan_digest
            or type(self.__graph_store) is not SQLiteGraphStore
            or SQLiteGraphStore.runtime_file_identity(self.__graph_store)
            != self.__graph_file_identity
            or type(self.__permit_store) is not SQLiteGraphActionPermitStore
            or self.__graph_store.permit_store is not self.__permit_store
            or self.__graph_store.approved_permit_store is not self.__permit_store
            or self.__permit_store.path != self.__graph_store.path
            or getattr(self.__permit_store, "_campaign_id", None) != self.__campaign.metadata.name
            or type(self.__approval_authority) is not WebActionApprovalInputAuthority
            or self.__approval_authority.role != "source"
            or self.__approval_authority.signed.approval != self.__approval_envelope
            or type(self.__capabilities) is not ActionCapabilityRegistry
            or type(self.__policies) is not ActionApprovalCapabilityPolicyRegistry
            or type(self.__dispatcher) is not GraphApprovedActionPermitDispatcher
            or type(graph_authority) is not GraphApprovedActionPermitAuthority
            or graph_authority is not self.__graph_authority
            or getattr(graph_authority, "_campaign_id", None) != self.__campaign.metadata.name
            or getattr(graph_authority, "_capabilities", None) is not self.__capabilities
            or getattr(graph_authority, "_policies", None) is not self.__policies
            or getattr(graph_authority, "_permit_store", None) is not self.__permit_store
            or getattr(graph_authority, "_input_authority", None)
            is not self.__deployment.approval_input
            or GraphApprovedActionPermitDispatcher.dispatch_once
            is not _GRAPH_APPROVED_DISPATCH_IMPLEMENTATION
            or GraphApprovedActionPermitAuthority.authorize_for_dispatch
            is not _GRAPH_APPROVED_AUTHORIZE_IMPLEMENTATION
            or SQLiteGraphActionPermitStore.approved_authorization
            is not _GRAPH_APPROVED_LOOKUP_IMPLEMENTATION
            or SQLiteGraphActionPermitStore.claim_approved_writer
            is not _GRAPH_APPROVED_CLAIM_WRITER_IMPLEMENTATION
            or SQLiteGraphActionPermitStore.authorize_approved_for_dispatch
            is not _GRAPH_APPROVED_STORE_AUTHORIZE_IMPLEMENTATION
            or WebActionApprovalInputAuthority.verify_action_approval
            is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
            or "dispatch_once" in vars(self.__dispatcher)
            or "authorize_for_dispatch" in vars(graph_authority)
            or "approved_authorization" in vars(self.__permit_store)
            or "claim_approved_writer" in vars(self.__permit_store)
            or "authorize_approved_for_dispatch" in vars(self.__permit_store)
            or "verify_action_approval" in vars(self.__approval_authority)
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit dispatcher differs from its deployment authority"
            )
        if callback_claimed:
            _SQL_SPECIALIST_V2_PLAN_REQUIRE_CLAIMED_CALLBACK_IMPLEMENTATION(
                plan,
                authority,
                owner_task,
                owner_token,
            )
        else:
            _SQL_SPECIALIST_V2_PLAN_REQUIRE_RUNTIME_IMPLEMENTATION(
                plan,
                authority,
                owner_task,
                owner_token,
                campaign=self.__campaign,
                preparation=self.__preparation,
                capability_ledger=self.__capability_ledger,
                capability_grant=self.__capability_grant,
                activation=self.__activation,
                prepared_action=self.__prepared_action,
                approval_envelope=self.__approval_envelope,
                specialist_deployment=self.__deployment,
            )
        return (
            self.__campaign,
            self.__preparation,
            self.__capability_ledger,
            self.__capability_grant,
            self.__activation,
            self.__prepared_action,
            self.__approval_envelope,
            self.__graph_store,
            self.__approval_authority,
        )

    async def _dispatch_once[DispatchResultT](
        self,
        authority: object,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        owner_task: asyncio.Task[object],
        owner_token: object,
        dispatch: Callable[
            [ActionPermit, ActionApprovalConsumptionReceipt],
            Awaitable[DispatchResultT],
        ],
    ) -> ApprovedActionDispatchResult[DispatchResultT]:
        _SQL_SPECIALIST_V2_DISPATCHER_RUNTIME_INPUTS_IMPLEMENTATION(
            self,
            authority,
            plan,
            owner_task,
            owner_token,
            callback_claimed=True,
        )
        approval = self.__approval_envelope
        return await _GRAPH_APPROVED_DISPATCH_IMPLEMENTATION(
            self.__dispatcher,
            approval.mission_envelope,
            approval.proposal,
            approval.graph_decision,
            approval,
            dispatch,
        )

    def _terminal_authorization(
        self,
        authority: object,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        owner_task: asyncio.Task[object],
        owner_token: object,
    ) -> ActionApprovalAuthorization | None:
        _SQL_SPECIALIST_V2_DISPATCHER_RUNTIME_INPUTS_IMPLEMENTATION(
            self,
            authority,
            plan,
            owner_task,
            owner_token,
            callback_claimed=True,
        )
        raw = _GRAPH_APPROVED_LOOKUP_IMPLEMENTATION(
            self.__permit_store,
            self.__approval_envelope.approval_id,
            self.__approval_envelope.expected_action_permit_id,
        )
        if raw is None:
            return None
        try:
            terminal = ActionApprovalAuthorization.model_validate(
                raw.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit terminal authorization is invalid"
            ) from exc
        if (
            terminal.action.newly_consumed
            or terminal.approval != self.__approval_envelope
            or terminal.action.permit != terminal.receipt.action_permit
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 terminal authorization differs from the sealed plan"
            )
        return terminal


_SQL_SPECIALIST_V2_DISPATCHER_RUNTIME_INPUTS_IMPLEMENTATION = (
    VerifiedSQLSpecialistPermitDispatcherV2._runtime_inputs
)
_SQL_SPECIALIST_V2_DISPATCHER_DISPATCH_ONCE_IMPLEMENTATION = (
    VerifiedSQLSpecialistPermitDispatcherV2._dispatch_once
)
_SQL_SPECIALIST_V2_DISPATCHER_TERMINAL_AUTHORIZATION_IMPLEMENTATION = (
    VerifiedSQLSpecialistPermitDispatcherV2._terminal_authorization
)


class _AgenticSpecialistDispatchRuntimeCapsule(_UncopyableAgenticAuthority):
    """Non-serializable exact runtime objects retained only for one C3C transfer."""

    __slots__ = (
        "__activation",
        "__approval_envelope",
        "__campaign",
        "__capability_grant",
        "__capability_ledger",
        "__identity_token",
        "__preparation",
        "__prepared_action",
        "__weakref__",
    )
    __activation: WebSpecialistCapabilityActivation
    __approval_envelope: ActionApprovalEnvelope
    __campaign: CampaignManifest
    __capability_grant: CapabilityGrant
    __capability_ledger: CapabilityLedger
    __identity_token: object
    __preparation: AgenticSpecialistPreparation
    __prepared_action: PreparedCapabilityAction

    def __init__(
        self,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSpecialistCapabilityActivation,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
    ) -> None:
        prefix = "_AgenticSpecialistDispatchRuntimeCapsule__"
        object.__setattr__(self, prefix + "campaign", campaign)
        object.__setattr__(self, prefix + "preparation", preparation)
        object.__setattr__(self, prefix + "capability_ledger", capability_ledger)
        object.__setattr__(self, prefix + "capability_grant", capability_grant)
        object.__setattr__(self, prefix + "identity_token", object())
        object.__setattr__(self, prefix + "activation", activation)
        object.__setattr__(self, prefix + "prepared_action", prepared_action)
        object.__setattr__(self, prefix + "approval_envelope", approval_envelope)

    @property
    def campaign(self) -> CampaignManifest:
        return self.__campaign

    @property
    def preparation(self) -> AgenticSpecialistPreparation:
        return self.__preparation

    @property
    def capability_ledger(self) -> CapabilityLedger:
        return self.__capability_ledger

    @property
    def capability_grant(self) -> CapabilityGrant:
        return self.__capability_grant

    @property
    def activation(self) -> WebSpecialistCapabilityActivation:
        return self.__activation

    @property
    def prepared_action(self) -> PreparedCapabilityAction:
        return self.__prepared_action

    @property
    def approval_envelope(self) -> ActionApprovalEnvelope:
        return self.__approval_envelope

    def _binding_identity_token(self) -> object:
        return self.__identity_token


class VerifiedPlannedSpecialistDispatchStarted(_UncopyableAgenticAuthority):
    """Audit view of one Store-issued plan-bound callback crash fence.

    Constructing an equal object is never authority.  Only the exact object
    registered by its issuing :class:`AgenticCoordinationStore` can transfer
    the private runtime capsule, and that transfer is restricted to the
    ``asyncio.Task`` that entered the Permit callback.
    """

    __slots__ = (
        "__execution",
        "__grant_receipt",
        "__permit",
        "__plan",
        "__receipt",
    )
    __execution: AgenticSpecialistExecutionEntry
    __grant_receipt: AgenticSpecialistCapabilityGrantConsumptionReceipt
    __permit: ActionPermit
    __plan: AgenticSpecialistDispatchPlanEntry
    __receipt: ActionApprovalConsumptionReceipt

    def __init__(
        self,
        *,
        plan: AgenticSpecialistDispatchPlanEntry,
        execution: AgenticSpecialistExecutionEntry,
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
        grant_receipt: AgenticSpecialistCapabilityGrantConsumptionReceipt,
    ) -> None:
        object.__setattr__(self, "_VerifiedPlannedSpecialistDispatchStarted__plan", plan)
        object.__setattr__(
            self,
            "_VerifiedPlannedSpecialistDispatchStarted__execution",
            execution,
        )
        object.__setattr__(self, "_VerifiedPlannedSpecialistDispatchStarted__permit", permit)
        object.__setattr__(self, "_VerifiedPlannedSpecialistDispatchStarted__receipt", receipt)
        object.__setattr__(
            self,
            "_VerifiedPlannedSpecialistDispatchStarted__grant_receipt",
            grant_receipt,
        )

    @property
    def plan(self) -> AgenticSpecialistDispatchPlanEntry:
        return self.__plan

    @property
    def execution(self) -> AgenticSpecialistExecutionEntry:
        return self.__execution

    @property
    def permit(self) -> ActionPermit:
        return self.__permit

    @property
    def approval_receipt(self) -> ActionApprovalConsumptionReceipt:
        return self.__receipt

    @property
    def grant_consumption_receipt(
        self,
    ) -> AgenticSpecialistCapabilityGrantConsumptionReceipt:
        return self.__grant_receipt


class _AgenticSQLSpecialistDispatchRuntimeCapsuleV2(_UncopyableAgenticAuthority):
    """Non-serializable SQL v2 runtime retained for one same-Task transfer."""

    __slots__ = (
        "__activation",
        "__approval_authority",
        "__approval_envelope",
        "__campaign",
        "__capability_grant",
        "__capability_ledger",
        "__claimed",
        "__configured_runtime_identity",
        "__deployment_runtime_identity",
        "__graph_store",
        "__identity_token",
        "__owner_task",
        "__owner_token",
        "__preparation",
        "__prepared_action",
        "__retired",
        "__state_lock",
        "__token_digest",
        "__weakref__",
    )
    __activation: WebSQLSpecialistCapabilityActivationV2
    __approval_authority: WebActionApprovalInputAuthority
    __approval_envelope: ActionApprovalEnvelope
    __campaign: CampaignManifest
    __capability_grant: CapabilityGrant
    __capability_ledger: CapabilityLedger
    __claimed: bool
    __configured_runtime_identity: _AgenticSpecialistConfiguredRuntimeIdentity
    __deployment_runtime_identity: _AgenticSpecialistDeploymentRuntimeIdentity
    __graph_store: SQLiteGraphStore
    __identity_token: object
    __owner_task: asyncio.Task[object]
    __owner_token: object
    __preparation: AgenticSpecialistPreparation
    __prepared_action: PreparedCapabilityAction
    __retired: bool
    __state_lock: RLockType
    __token_digest: str

    def __init__(
        self,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSQLSpecialistCapabilityActivationV2,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        graph_store: SQLiteGraphStore,
        approval_authority: WebActionApprovalInputAuthority,
        deployment_runtime_identity: _AgenticSpecialistDeploymentRuntimeIdentity,
        configured_runtime_identity: _AgenticSpecialistConfiguredRuntimeIdentity,
        owner_task: asyncio.Task[object],
        owner_token: object,
    ) -> None:
        prefix = "_AgenticSQLSpecialistDispatchRuntimeCapsuleV2__"
        object.__setattr__(self, prefix + "campaign", campaign)
        object.__setattr__(self, prefix + "preparation", preparation)
        object.__setattr__(self, prefix + "capability_ledger", capability_ledger)
        object.__setattr__(self, prefix + "capability_grant", capability_grant)
        object.__setattr__(self, prefix + "identity_token", object())
        object.__setattr__(self, prefix + "activation", activation)
        object.__setattr__(self, prefix + "prepared_action", prepared_action)
        object.__setattr__(self, prefix + "approval_envelope", approval_envelope)
        object.__setattr__(self, prefix + "graph_store", graph_store)
        object.__setattr__(self, prefix + "approval_authority", approval_authority)
        object.__setattr__(
            self,
            prefix + "deployment_runtime_identity",
            deployment_runtime_identity,
        )
        object.__setattr__(
            self,
            prefix + "configured_runtime_identity",
            configured_runtime_identity,
        )
        object.__setattr__(self, prefix + "owner_task", owner_task)
        object.__setattr__(self, prefix + "owner_token", owner_token)
        object.__setattr__(self, prefix + "claimed", False)
        object.__setattr__(self, prefix + "retired", False)
        object.__setattr__(self, prefix + "state_lock", threading.RLock())
        object.__setattr__(
            self,
            prefix + "token_digest",
            discovery_digest(
                "pajin.agentic.sql-specialist-runtime-capsule-token/v1",
                {"nonce": uuid.uuid4().hex},
            ),
        )

    @property
    def campaign(self) -> CampaignManifest:
        return self.__campaign

    @property
    def preparation(self) -> AgenticSpecialistPreparation:
        return self.__preparation

    @property
    def capability_ledger(self) -> CapabilityLedger:
        return self.__capability_ledger

    @property
    def capability_grant(self) -> CapabilityGrant:
        return self.__capability_grant

    @property
    def activation(self) -> WebSQLSpecialistCapabilityActivationV2:
        return self.__activation

    @property
    def prepared_action(self) -> PreparedCapabilityAction:
        return self.__prepared_action

    @property
    def approval_envelope(self) -> ActionApprovalEnvelope:
        return self.__approval_envelope

    @property
    def graph_store(self) -> SQLiteGraphStore:
        return self.__graph_store

    @property
    def approval_authority(self) -> WebActionApprovalInputAuthority:
        return self.__approval_authority

    @property
    def deployment_runtime_identity(
        self,
    ) -> _AgenticSpecialistDeploymentRuntimeIdentity:
        return self.__deployment_runtime_identity

    @property
    def configured_runtime_identity(
        self,
    ) -> _AgenticSpecialistConfiguredRuntimeIdentity:
        return self.__configured_runtime_identity

    def _require_owner(
        self,
        owner_task: asyncio.Task[object],
        owner_token: object,
    ) -> None:
        with self.__state_lock:
            if (
                type(self) is not _AgenticSQLSpecialistDispatchRuntimeCapsuleV2
                or type(self.__state_lock) is not RLockType
                or self.__owner_task is not owner_task
                or self.__owner_token is not owner_token
                or owner_task.done()
                or self.__claimed
                or self.__retired
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 capsule belongs to another scheduler Task"
                )

    def _require_current_owner_task(self, owner_task: asyncio.Task[object]) -> None:
        with self.__state_lock:
            if (
                type(self) is not _AgenticSQLSpecialistDispatchRuntimeCapsuleV2
                or type(self.__state_lock) is not RLockType
                or self.__owner_task is not owner_task
                or owner_task.done()
                or self.__claimed
                or self.__retired
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 capsule belongs to another scheduler Task"
                )

    def _claim(
        self,
        owner_task: asyncio.Task[object],
        owner_token: object,
    ) -> None:
        with self.__state_lock:
            if (
                type(self) is not _AgenticSQLSpecialistDispatchRuntimeCapsuleV2
                or type(self.__state_lock) is not RLockType
                or self.__owner_task is not owner_task
                or self.__owner_token is not owner_token
                or owner_task.done()
                or self.__claimed
                or self.__retired
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 capsule is foreign, consumed, or retired"
                )
            object.__setattr__(
                self,
                "_AgenticSQLSpecialistDispatchRuntimeCapsuleV2__claimed",
                True,
            )

    def _runtime_inputs(
        self,
        owner_task: asyncio.Task[object],
        owner_token: object,
        *,
        claimed: bool,
    ) -> tuple[
        CampaignManifest,
        AgenticSpecialistPreparation,
        CapabilityLedger,
        CapabilityGrant,
        WebSQLSpecialistCapabilityActivationV2,
        PreparedCapabilityAction,
        ActionApprovalEnvelope,
        SQLiteGraphStore,
        WebActionApprovalInputAuthority,
        _AgenticSpecialistDeploymentRuntimeIdentity,
        _AgenticSpecialistConfiguredRuntimeIdentity,
    ]:
        with self.__state_lock:
            if (
                type(self) is not _AgenticSQLSpecialistDispatchRuntimeCapsuleV2
                or type(self.__state_lock) is not RLockType
                or type(claimed) is not bool
                or self.__owner_task is not owner_task
                or self.__owner_token is not owner_token
                or owner_task.done()
                or self.__claimed is not claimed
                or self.__retired
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 capsule runtime is foreign or retired"
                )
            return (
                self.__campaign,
                self.__preparation,
                self.__capability_ledger,
                self.__capability_grant,
                self.__activation,
                self.__prepared_action,
                self.__approval_envelope,
                self.__graph_store,
                self.__approval_authority,
                self.__deployment_runtime_identity,
                self.__configured_runtime_identity,
            )

    def _retire(self, owner_token: object) -> None:
        with self.__state_lock:
            if (
                type(self) is not _AgenticSQLSpecialistDispatchRuntimeCapsuleV2
                or type(self.__state_lock) is not RLockType
                or self.__owner_token is not owner_token
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 capsule retirement authority changed"
                )
            object.__setattr__(
                self,
                "_AgenticSQLSpecialistDispatchRuntimeCapsuleV2__retired",
                True,
            )

    def _token_digest(
        self,
        owner_task: asyncio.Task[object],
        owner_token: object,
        *,
        claimed: bool,
    ) -> str:
        with self.__state_lock:
            if (
                type(self) is not _AgenticSQLSpecialistDispatchRuntimeCapsuleV2
                or type(self.__state_lock) is not RLockType
                or type(claimed) is not bool
                or self.__owner_task is not owner_task
                or self.__owner_token is not owner_token
                or owner_task.done()
                or self.__claimed is not claimed
                or self.__retired
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 capsule token is foreign or retired"
                )
            return self.__token_digest

    def _binding_identity_token(self) -> object:
        return self.__identity_token


_SQL_SPECIALIST_V2_CAPSULE_REQUIRE_OWNER_IMPLEMENTATION = (
    _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._require_owner
)
_SQL_SPECIALIST_V2_CAPSULE_CLAIM_IMPLEMENTATION = (
    _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._claim
)
_SQL_SPECIALIST_V2_CAPSULE_RUNTIME_INPUTS_IMPLEMENTATION = (
    _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._runtime_inputs
)
_SQL_SPECIALIST_V2_CAPSULE_RETIRE_IMPLEMENTATION = (
    _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._retire
)
_SQL_SPECIALIST_V2_CAPSULE_TOKEN_DIGEST_IMPLEMENTATION = (
    _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._token_digest
)
_SQL_SPECIALIST_V2_CAPSULE_BINDING_TOKEN_IMPLEMENTATION = (
    _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._binding_identity_token
)


class VerifiedPlannedSQLSpecialistDispatchStartedV2(_UncopyableAgenticAuthority):
    """Audit view of one Store-issued, Task-owned SQL v2 callback fence."""

    __slots__ = (
        "__execution",
        "__grant_receipt",
        "__permit",
        "__plan",
        "__receipt",
    )
    __execution: AgenticSpecialistExecutionEntry
    __grant_receipt: AgenticSpecialistCapabilityGrantConsumptionReceipt
    __permit: ActionPermit
    __plan: AgenticSQLSpecialistDispatchPlanEntryV2
    __receipt: ActionApprovalConsumptionReceipt

    def __init__(
        self,
        *,
        plan: AgenticSQLSpecialistDispatchPlanEntryV2,
        execution: AgenticSpecialistExecutionEntry,
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
        grant_receipt: AgenticSpecialistCapabilityGrantConsumptionReceipt,
    ) -> None:
        prefix = "_VerifiedPlannedSQLSpecialistDispatchStartedV2__"
        object.__setattr__(self, prefix + "plan", plan)
        object.__setattr__(self, prefix + "execution", execution)
        object.__setattr__(self, prefix + "permit", permit)
        object.__setattr__(self, prefix + "receipt", receipt)
        object.__setattr__(self, prefix + "grant_receipt", grant_receipt)

    @property
    def plan(self) -> AgenticSQLSpecialistDispatchPlanEntryV2:
        return self.__plan

    @property
    def execution(self) -> AgenticSpecialistExecutionEntry:
        return self.__execution

    @property
    def permit(self) -> ActionPermit:
        return self.__permit

    @property
    def approval_receipt(self) -> ActionApprovalConsumptionReceipt:
        return self.__receipt

    @property
    def grant_consumption_receipt(
        self,
    ) -> AgenticSpecialistCapabilityGrantConsumptionReceipt:
        return self.__grant_receipt


@dataclass(frozen=True, slots=True)
class _SQLSpecialistV2ClaimedRuntimeContext:
    """Exact live inputs observed while one private capsule is claimed."""

    started: VerifiedPlannedSQLSpecialistDispatchStartedV2
    plan: AgenticSQLSpecialistDispatchPlanEntryV2
    execution: AgenticSpecialistExecutionEntry
    campaign: CampaignManifest
    preparation: AgenticSpecialistPreparation
    capability_ledger: CapabilityLedger
    capability_grant: CapabilityGrant
    activation: WebSQLSpecialistCapabilityActivationV2
    prepared_action: PreparedCapabilityAction
    approval_envelope: ActionApprovalEnvelope
    graph_store: SQLiteGraphStore
    approval_authority: WebActionApprovalInputAuthority
    deployment_runtime_identity: _AgenticSpecialistDeploymentRuntimeIdentity
    configured_runtime_identity: _AgenticSpecialistConfiguredRuntimeIdentity
    snapshot: GraphSnapshot
    owner_task: asyncio.Task[object]
    database: _LinuxPinnedCoordinationDatabase
    runtime_capsule_token_digest: str
    grant_lineage_state_digest: str
    claimed_at: datetime

    def __copy__(self) -> Never:
        raise TypeError("SQL specialist v2 claimed runtime context cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("SQL specialist v2 claimed runtime context cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("SQL specialist v2 claimed runtime context cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("SQL specialist v2 claimed runtime context cannot be serialized")


@final
class VerifiedSQLSpecialistJobAttemptClaimV2(_UncopyableAgenticAuthority):
    """Store-owned, same-Task successor to one consumed private capsule.

    The detached :attr:`attempt` value is audit-only.  Only this exact object,
    while retained in its issuing Store live-set, can be consumed by the future
    specialist Gateway.
    """

    __slots__ = (
        "__attempt",
        "__consumed",
        "__factory_token",
        "__identity_token",
        "__owner_task",
        "__retired",
        "__state_lock",
    )
    __attempt: AgenticSpecialistJobAttempt
    __consumed: bool
    __factory_token: object
    __identity_token: object
    __owner_task: asyncio.Task[object]
    __retired: bool
    __state_lock: RLockType

    def __init__(
        self,
        *,
        attempt: AgenticSpecialistJobAttempt,
        owner_task: asyncio.Task[object],
        identity_token: object,
        _factory_token: object,
    ) -> None:
        if _factory_token is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_FACTORY_TOKEN:
            raise TypeError("SQL specialist v2 JobAttempt claim requires its Store factory")
        prefix = "_VerifiedSQLSpecialistJobAttemptClaimV2__"
        object.__setattr__(self, prefix + "attempt", attempt)
        object.__setattr__(self, prefix + "owner_task", owner_task)
        object.__setattr__(self, prefix + "identity_token", identity_token)
        object.__setattr__(self, prefix + "factory_token", _factory_token)
        object.__setattr__(self, prefix + "consumed", False)
        object.__setattr__(self, prefix + "retired", False)
        object.__setattr__(self, prefix + "state_lock", threading.RLock())

    @property
    def attempt(self) -> AgenticSpecialistJobAttempt:
        return AgenticSpecialistJobAttempt.model_validate(
            self.__attempt.model_dump(mode="json", by_alias=True)
        )

    def _require(
        self,
        *,
        owner_task: asyncio.Task[object],
        identity_token: object,
        consumed: bool,
    ) -> None:
        with self.__state_lock:
            if (
                type(self) is not VerifiedSQLSpecialistJobAttemptClaimV2
                or type(self.__state_lock) is not RLockType
                or type(consumed) is not bool
                or self.__factory_token is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_FACTORY_TOKEN
                or self.__identity_token is not identity_token
                or self.__owner_task is not owner_task
                or owner_task is not asyncio.current_task()
                or owner_task.done()
                or self.__consumed is not consumed
                or self.__retired
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 JobAttempt claim is foreign, consumed, or retired"
                )

    def _consume(
        self,
        *,
        owner_task: asyncio.Task[object],
        identity_token: object,
    ) -> None:
        with self.__state_lock:
            _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_REQUIRE_IMPLEMENTATION(
                self,
                owner_task=owner_task,
                identity_token=identity_token,
                consumed=False,
            )
            object.__setattr__(
                self,
                "_VerifiedSQLSpecialistJobAttemptClaimV2__consumed",
                True,
            )

    def _retire(
        self,
        *,
        identity_token: object,
    ) -> None:
        with self.__state_lock:
            if (
                type(self) is not VerifiedSQLSpecialistJobAttemptClaimV2
                or type(self.__state_lock) is not RLockType
                or self.__factory_token is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_FACTORY_TOKEN
                or self.__identity_token is not identity_token
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 JobAttempt retirement authority changed"
                )
            object.__setattr__(
                self,
                "_VerifiedSQLSpecialistJobAttemptClaimV2__retired",
                True,
            )


_SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_FACTORY_TOKEN: Final = object()
_SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_INIT_IMPLEMENTATION = (
    VerifiedSQLSpecialistJobAttemptClaimV2.__init__
)
_SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_REQUIRE_IMPLEMENTATION = (
    VerifiedSQLSpecialistJobAttemptClaimV2._require
)
_SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_CONSUME_IMPLEMENTATION = (
    VerifiedSQLSpecialistJobAttemptClaimV2._consume
)
_SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_RETIRE_IMPLEMENTATION = (
    VerifiedSQLSpecialistJobAttemptClaimV2._retire
)
_SQL_SPECIALIST_V2_JOB_ATTEMPT_PROPERTY = cast(
    property,
    vars(VerifiedSQLSpecialistJobAttemptClaimV2)["attempt"],
)

type _IssuedSQLSpecialistV2JobAttemptClaim = tuple[
    VerifiedSQLSpecialistJobAttemptClaimV2,
    asyncio.Task[object],
    object,
    VerifiedSpecialistGatewayDeploymentV2,
    _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
    _LinuxPinnedCoordinationDatabase,
    _SQLSpecialistV2ClaimedRuntimeContext,
    object,
]


@dataclass(frozen=True, slots=True)
class AgenticCyclePublication:
    """Atomic result of one checkpoint CAS and command outbox publication."""

    head: VerifiedAgenticDurableHead
    outbox_entries: tuple[AgenticOutboxEntry, ...]


@dataclass(frozen=True, slots=True)
class AgenticEventPublication:
    """Atomic result of one typed Agent Event checkpoint transition."""

    head: VerifiedAgenticDurableHead
    event: AgentEvent
    event_digest: str


@dataclass(frozen=True, slots=True)
class AgenticRecoverySnapshot:
    """Read-only crash classification; it performs no dispatch or delivery."""

    head: VerifiedAgenticDurableHead
    pending_outbox: tuple[AgenticOutboxEntry, ...]
    unknown_outbox: tuple[AgenticOutboxEntry, ...]
    acknowledged_outbox: tuple[AgenticOutboxEntry, ...]
    claimed_invocations: tuple[AgenticModelInvocationEntry, ...]
    unknown_invocations: tuple[AgenticModelInvocationEntry, ...]
    terminal_invocations: tuple[AgenticModelInvocationEntry, ...]
    reserved_specialist_executions: tuple[AgenticSpecialistExecutionEntry, ...]
    unknown_specialist_executions: tuple[AgenticSpecialistExecutionEntry, ...]
    awaiting_specialist_dispatch_plans: tuple[AgenticSpecialistDispatchPlanAuditEntry, ...]
    terminal_specialist_dispatch_plans: tuple[AgenticSpecialistDispatchPlanAuditEntry, ...]
    claimed_specialist_job_attempts: tuple[AgenticSpecialistJobAttempt, ...]
    unknown_specialist_job_attempts: tuple[AgenticSpecialistJobAttempt, ...]
    specialist_terminal_receipts: tuple[AgenticSpecialistTerminalReceipt, ...]
    automatic_redispatch_authorized: Literal[False] = False


@dataclass(frozen=True, slots=True)
class AgenticSpecialistJobRecoverySnapshot:
    """Audit-only specialist classification that never restores live authority."""

    store_id: str
    coordination_binding_digest: str
    claimed_job_attempts: tuple[AgenticSpecialistJobAttempt, ...]
    unknown_job_attempts: tuple[AgenticSpecialistJobAttempt, ...]
    terminal_receipts: tuple[AgenticSpecialistTerminalReceipt, ...]
    automatic_redispatch_authorized: Literal[False] = False
    execution_authority: Literal[False] = False


@dataclass(frozen=True, slots=True)
class _SpecialistAssignmentMaterial:
    outbox: AgenticOutboxEntry
    admission: AgenticCommandAdmissionReceipt
    cycle: DynamicSupervisorCycle
    command: AgentControlCommand
    candidate: FrontierCandidate
    decision: FrontierDecision
    specialist: SpecialistDefinition


_METADATA_TABLE_SQL = """
CREATE TABLE agentic_coordination_metadata (
    key TEXT PRIMARY KEY NOT NULL,
    value TEXT NOT NULL
) STRICT
"""
_CHECKPOINTS_TABLE_SQL = """
CREATE TABLE agentic_checkpoints (
    checkpoint_id TEXT PRIMARY KEY NOT NULL,
    checkpoint_digest TEXT NOT NULL UNIQUE,
    revision INTEGER NOT NULL UNIQUE CHECK(revision >= 0),
    predecessor_digest TEXT,
    canonical_checkpoint BLOB NOT NULL,
    recorded_at TEXT NOT NULL
) STRICT
"""
_HEAD_TABLE_SQL = """
CREATE TABLE agentic_checkpoint_head (
    slot INTEGER PRIMARY KEY NOT NULL CHECK(slot = 1),
    checkpoint_digest TEXT NOT NULL REFERENCES agentic_checkpoints(checkpoint_digest),
    revision INTEGER NOT NULL CHECK(revision >= 0)
) STRICT
"""
_CYCLES_TABLE_SQL = """
CREATE TABLE agentic_cycles (
    cycle_id TEXT PRIMARY KEY NOT NULL,
    cycle_digest TEXT NOT NULL UNIQUE,
    source_checkpoint_digest TEXT NOT NULL REFERENCES agentic_checkpoints(checkpoint_digest),
    resulting_checkpoint_digest TEXT NOT NULL UNIQUE
        REFERENCES agentic_checkpoints(checkpoint_digest),
    canonical_cycle BLOB NOT NULL,
    recorded_at TEXT NOT NULL
) STRICT
"""
_EVENTS_TABLE_SQL = """
CREATE TABLE agentic_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    event_digest TEXT NOT NULL UNIQUE,
    command_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    event_sequence INTEGER NOT NULL CHECK(event_sequence >= 1),
    source_checkpoint_digest TEXT NOT NULL REFERENCES agentic_checkpoints(checkpoint_digest),
    resulting_checkpoint_digest TEXT NOT NULL UNIQUE
        REFERENCES agentic_checkpoints(checkpoint_digest),
    canonical_event BLOB NOT NULL,
    recorded_at TEXT NOT NULL,
    UNIQUE(command_id, event_sequence)
) STRICT
"""
_OUTBOX_TABLE_SQL = """
CREATE TABLE agentic_command_outbox (
    command_id TEXT PRIMARY KEY NOT NULL,
    command_digest TEXT NOT NULL UNIQUE,
    cycle_id TEXT NOT NULL REFERENCES agentic_cycles(cycle_id),
    cycle_digest TEXT NOT NULL,
    ordinal INTEGER NOT NULL CHECK(ordinal >= 1),
    target_agent_id TEXT NOT NULL,
    command_sequence INTEGER NOT NULL CHECK(command_sequence >= 1),
    canonical_command BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'pending', 'delivery-started-outcome-unknown', 'acknowledged'
    )),
    claimed_at TEXT,
    claim_id TEXT,
    claim_digest TEXT,
    acknowledged_at TEXT,
    acknowledgement_id TEXT,
    acknowledgement_digest TEXT,
    state_digest TEXT NOT NULL,
    UNIQUE(cycle_digest, ordinal),
    CHECK(
        (state = 'pending' AND claimed_at IS NULL AND claim_id IS NULL
         AND claim_digest IS NULL AND acknowledged_at IS NULL
         AND acknowledgement_id IS NULL AND acknowledgement_digest IS NULL)
        OR
        (state = 'delivery-started-outcome-unknown' AND claimed_at IS NOT NULL
         AND claim_id IS NOT NULL AND claim_digest IS NOT NULL
         AND acknowledged_at IS NULL AND acknowledgement_id IS NULL
         AND acknowledgement_digest IS NULL)
        OR
        (state = 'acknowledged' AND claimed_at IS NOT NULL AND claim_id IS NOT NULL
         AND claim_digest IS NOT NULL AND acknowledged_at IS NOT NULL
         AND acknowledgement_id IS NOT NULL AND acknowledgement_digest IS NOT NULL)
    )
) STRICT
"""
_INBOX_TABLE_SQL = """
CREATE TABLE agentic_command_inbox (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE,
    command_id TEXT NOT NULL UNIQUE REFERENCES agentic_command_outbox(command_id),
    claim_id TEXT NOT NULL UNIQUE,
    claim_digest TEXT NOT NULL UNIQUE,
    receiver_agent_id TEXT NOT NULL,
    canonical_receipt BLOB NOT NULL,
    admitted_at TEXT NOT NULL
) STRICT
"""
_SPECIALIST_EXECUTIONS_TABLE_SQL = """
CREATE TABLE agentic_specialist_executions (
    reservation_id TEXT PRIMARY KEY NOT NULL,
    reservation_digest TEXT NOT NULL UNIQUE,
    state_digest TEXT NOT NULL,
    store_id TEXT NOT NULL,
    coordination_binding_digest TEXT NOT NULL,
    source_head_checkpoint_id TEXT NOT NULL,
    source_head_checkpoint_digest TEXT NOT NULL
        REFERENCES agentic_checkpoints(checkpoint_digest),
    graph_snapshot_id TEXT NOT NULL,
    graph_snapshot_digest TEXT NOT NULL,
    cycle_id TEXT NOT NULL REFERENCES agentic_cycles(cycle_id),
    cycle_digest TEXT NOT NULL,
    command_id TEXT NOT NULL UNIQUE REFERENCES agentic_command_outbox(command_id),
    command_digest TEXT NOT NULL,
    admission_receipt_id TEXT NOT NULL UNIQUE
        REFERENCES agentic_command_inbox(receipt_id),
    admission_receipt_digest TEXT NOT NULL,
    target_agent_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    candidate_id TEXT NOT NULL,
    candidate_digest TEXT NOT NULL,
    proposal_digest TEXT NOT NULL,
    target_id TEXT NOT NULL,
    threat_class TEXT NOT NULL,
    specialization TEXT NOT NULL,
    specialist_definition_digest TEXT NOT NULL,
    canonical_entry BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'reserved', 'dispatch-started-outcome-unknown'
    )),
    reserved_at TEXT NOT NULL,
    dispatch_started_at TEXT,
    CHECK(
        (state = 'reserved' AND dispatch_started_at IS NULL)
        OR
        (state = 'dispatch-started-outcome-unknown'
         AND dispatch_started_at IS NOT NULL)
    )
) STRICT
"""
_SPECIALIST_DISPATCH_PLANS_TABLE_SQL = """
CREATE TABLE agentic_specialist_dispatch_plans (
    plan_id TEXT PRIMARY KEY NOT NULL,
    plan_digest TEXT NOT NULL UNIQUE,
    state_digest TEXT NOT NULL,
    store_id TEXT NOT NULL,
    coordination_binding_digest TEXT NOT NULL,
    reservation_id TEXT NOT NULL UNIQUE
        REFERENCES agentic_specialist_executions(reservation_id),
    reservation_digest TEXT NOT NULL UNIQUE,
    command_id TEXT NOT NULL UNIQUE REFERENCES agentic_command_outbox(command_id),
    command_digest TEXT NOT NULL,
    preparation_id TEXT NOT NULL UNIQUE,
    preparation_digest TEXT NOT NULL UNIQUE,
    prepared_action_digest TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    grant_id TEXT NOT NULL UNIQUE,
    grant_digest TEXT NOT NULL UNIQUE,
    approval_id TEXT NOT NULL UNIQUE,
    approval_digest TEXT NOT NULL UNIQUE,
    action_proposal_id TEXT NOT NULL UNIQUE,
    action_proposal_digest TEXT NOT NULL UNIQUE,
    expected_action_permit_id TEXT NOT NULL UNIQUE,
    canonical_entry BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'awaiting-permit', 'dispatch-started-outcome-unknown',
        'permit-consumed-entry-unknown'
    )),
    planned_at TEXT NOT NULL,
    action_permit_id TEXT UNIQUE,
    action_permit_digest TEXT UNIQUE,
    approval_receipt_id TEXT UNIQUE,
    approval_receipt_digest TEXT UNIQUE,
    grant_consumption_receipt_id TEXT UNIQUE,
    grant_consumption_receipt_digest TEXT UNIQUE,
    grant_consumed_at TEXT,
    callback_entered_at TEXT,
    reconciled_at TEXT,
    CHECK(
        (state = 'awaiting-permit'
         AND action_permit_id IS NULL AND action_permit_digest IS NULL
         AND approval_receipt_id IS NULL AND approval_receipt_digest IS NULL
         AND grant_consumption_receipt_id IS NULL
         AND grant_consumption_receipt_digest IS NULL
         AND grant_consumed_at IS NULL
         AND callback_entered_at IS NULL AND reconciled_at IS NULL)
        OR
        (state = 'dispatch-started-outcome-unknown'
         AND action_permit_id IS NOT NULL AND action_permit_digest IS NOT NULL
         AND approval_receipt_id IS NOT NULL AND approval_receipt_digest IS NOT NULL
         AND grant_consumption_receipt_id IS NOT NULL
         AND grant_consumption_receipt_digest IS NOT NULL
         AND grant_consumed_at IS NOT NULL
         AND callback_entered_at IS NOT NULL AND reconciled_at IS NULL)
        OR
        (state = 'permit-consumed-entry-unknown'
         AND action_permit_id IS NOT NULL AND action_permit_digest IS NOT NULL
         AND approval_receipt_id IS NOT NULL AND approval_receipt_digest IS NOT NULL
         AND grant_consumption_receipt_id IS NULL
         AND grant_consumption_receipt_digest IS NULL
         AND grant_consumed_at IS NULL
         AND callback_entered_at IS NULL AND reconciled_at IS NOT NULL)
    )
) STRICT
"""
_SPECIALIST_JOB_ATTEMPTS_TABLE_SQL = """
CREATE TABLE agentic_specialist_job_attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL,
    attempt_digest TEXT NOT NULL UNIQUE,
    state_digest TEXT NOT NULL,
    store_id TEXT NOT NULL,
    coordination_binding_digest TEXT NOT NULL,
    database_identity_digest TEXT NOT NULL,
    deployment_digest TEXT NOT NULL,
    control_plane_run_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    campaign_manifest_digest TEXT NOT NULL,
    plan_id TEXT NOT NULL UNIQUE
        REFERENCES agentic_specialist_dispatch_plans(plan_id),
    plan_digest TEXT NOT NULL UNIQUE,
    plan_state_digest TEXT NOT NULL UNIQUE,
    reservation_id TEXT NOT NULL UNIQUE
        REFERENCES agentic_specialist_executions(reservation_id),
    reservation_digest TEXT NOT NULL UNIQUE,
    reservation_state_digest TEXT NOT NULL UNIQUE,
    command_id TEXT NOT NULL UNIQUE REFERENCES agentic_command_outbox(command_id),
    command_digest TEXT NOT NULL,
    target_agent_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    scheduler_task_name TEXT NOT NULL,
    scheduler_task_token_digest TEXT NOT NULL UNIQUE,
    runtime_capsule_token_digest TEXT NOT NULL UNIQUE,
    specialization TEXT NOT NULL CHECK(specialization IN (
        'attack-path-strategist', 'recon-specialist', 'xss-specialist',
        'sql-injection-specialist', 'ssrf-specialist',
        'authorization-specialist', 'auth-session-specialist',
        'api-specialist', 'independent-validator', 'evidence-reporter'
    )),
    dispatch_binding_id TEXT NOT NULL UNIQUE,
    dispatch_binding_digest TEXT NOT NULL UNIQUE,
    claim_verification_id TEXT NOT NULL UNIQUE,
    claim_verification_digest TEXT NOT NULL,
    dispatch_verification_id TEXT UNIQUE,
    dispatch_verification_digest TEXT,
    dispatch_event_digest TEXT,
    graph_snapshot_id TEXT NOT NULL,
    graph_snapshot_digest TEXT NOT NULL,
    preparation_id TEXT NOT NULL,
    preparation_digest TEXT NOT NULL,
    profile_registry_digest TEXT NOT NULL,
    profile_id TEXT NOT NULL,
    profile_version TEXT NOT NULL,
    profile_digest TEXT NOT NULL,
    executor_catalog_digest TEXT NOT NULL,
    executor_id TEXT NOT NULL,
    executor_version TEXT NOT NULL,
    executor_digest TEXT NOT NULL,
    prepared_action_digest TEXT NOT NULL UNIQUE,
    activation_set_digest TEXT NOT NULL,
    release_id TEXT NOT NULL,
    release_digest TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    capability_version TEXT NOT NULL,
    capability_definition_digest TEXT NOT NULL,
    capability_digest TEXT NOT NULL,
    capability_authority_set_id TEXT NOT NULL,
    capability_authority_set_digest TEXT NOT NULL,
    tool_id TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    tool_digest TEXT NOT NULL,
    request_id TEXT NOT NULL UNIQUE,
    request_digest TEXT NOT NULL UNIQUE,
    capability_grant_id TEXT NOT NULL,
    capability_grant_digest TEXT NOT NULL,
    grant_lineage_state_digest TEXT NOT NULL,
    capability_grant_expires_at TEXT NOT NULL,
    grant_consumption_receipt_id TEXT NOT NULL UNIQUE,
    grant_consumption_receipt_digest TEXT NOT NULL UNIQUE,
    action_permit_id TEXT NOT NULL UNIQUE,
    action_permit_digest TEXT NOT NULL UNIQUE,
    action_permit_expires_at TEXT NOT NULL,
    approval_id TEXT NOT NULL,
    approval_digest TEXT NOT NULL,
    approval_expires_at TEXT NOT NULL,
    approval_consumption_receipt_id TEXT NOT NULL UNIQUE,
    approval_consumption_receipt_digest TEXT NOT NULL UNIQUE,
    dispatch_id TEXT NOT NULL UNIQUE,
    target_id TEXT NOT NULL,
    target_digest TEXT NOT NULL,
    gateway_id TEXT NOT NULL,
    gateway_version TEXT NOT NULL,
    gateway_digest TEXT NOT NULL,
    execution_inventory_id TEXT NOT NULL,
    execution_inventory_digest TEXT NOT NULL,
    worker_backend_id TEXT NOT NULL,
    worker_backend_version TEXT NOT NULL,
    worker_backend_digest TEXT NOT NULL,
    worker_job_id TEXT NOT NULL UNIQUE,
    worker_job_digest TEXT NOT NULL UNIQUE,
    worker_command_digest TEXT NOT NULL,
    worker_compiler_id TEXT NOT NULL,
    worker_compiler_version TEXT NOT NULL,
    worker_compiler_digest TEXT NOT NULL,
    worker_image_reference TEXT NOT NULL,
    worker_image_digest TEXT NOT NULL,
    worker_verifier_id TEXT NOT NULL,
    worker_verifier_version TEXT NOT NULL,
    worker_verifier_digest TEXT NOT NULL,
    worker_verification_key_id TEXT NOT NULL,
    worker_verification_key_digest TEXT NOT NULL,
    canonical_entry BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'claimed-before-backend', 'dispatch-started-outcome-unknown'
    )),
    claimed_at TEXT NOT NULL,
    backend_dispatch_started_at TEXT,
    CHECK(
        (state = 'claimed-before-backend'
         AND backend_dispatch_started_at IS NULL
         AND dispatch_verification_id IS NULL
         AND dispatch_verification_digest IS NULL
         AND dispatch_event_digest IS NULL)
        OR
        (state = 'dispatch-started-outcome-unknown'
         AND backend_dispatch_started_at IS NOT NULL
         AND dispatch_verification_id IS NOT NULL
         AND dispatch_verification_digest IS NOT NULL
         AND dispatch_event_digest IS NOT NULL)
    )
) STRICT
"""
_SPECIALIST_TERMINAL_RECEIPTS_TABLE_SQL = """
CREATE TABLE agentic_specialist_terminal_receipts (
    receipt_id TEXT PRIMARY KEY NOT NULL,
    receipt_digest TEXT NOT NULL UNIQUE,
    store_id TEXT NOT NULL,
    coordination_binding_digest TEXT NOT NULL,
    attempt_id TEXT NOT NULL UNIQUE
        REFERENCES agentic_specialist_job_attempts(attempt_id),
    attempt_digest TEXT NOT NULL UNIQUE,
    attempt_state TEXT NOT NULL,
    attempt_state_digest TEXT NOT NULL UNIQUE,
    plan_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    worker_job_id TEXT NOT NULL UNIQUE,
    terminal_kind TEXT NOT NULL CHECK(terminal_kind IN (
        'abandoned-before-backend', 'failed-before-target-io',
        'completed-verified', 'failed-after-dispatch-proven-terminal',
        'started-outcome-unknown'
    )),
    terminal_reason_digest TEXT NOT NULL,
    target_io_state TEXT NOT NULL CHECK(target_io_state IN (
        'not-started', 'performed', 'unknown'
    )),
    succeeded INTEGER CHECK(succeeded IN (0, 1)),
    backend_terminal_proven INTEGER NOT NULL CHECK(backend_terminal_proven IN (0, 1)),
    canonical_receipt BLOB NOT NULL,
    recorded_at TEXT NOT NULL,
    backend_finished_at TEXT,
    worker_result_digest TEXT,
    backend_terminal_proof_digest TEXT,
    CHECK(
        (terminal_kind = 'abandoned-before-backend'
         AND attempt_state = 'claimed-before-backend'
         AND target_io_state = 'not-started' AND succeeded = 0
         AND backend_terminal_proven = 0 AND backend_finished_at IS NULL
         AND worker_result_digest IS NULL
         AND backend_terminal_proof_digest IS NULL)
        OR
        (terminal_kind = 'started-outcome-unknown'
         AND attempt_state = 'dispatch-started-outcome-unknown'
         AND target_io_state = 'unknown' AND succeeded IS NULL
         AND backend_terminal_proven = 0 AND backend_finished_at IS NULL
         AND worker_result_digest IS NULL
         AND backend_terminal_proof_digest IS NULL)
        OR
        (terminal_kind = 'failed-before-target-io'
         AND attempt_state = 'dispatch-started-outcome-unknown'
         AND target_io_state = 'not-started' AND succeeded = 0
         AND backend_terminal_proven = 1 AND backend_finished_at IS NOT NULL
         AND worker_result_digest IS NOT NULL
         AND backend_terminal_proof_digest IS NOT NULL)
        OR
        (terminal_kind = 'completed-verified'
         AND attempt_state = 'dispatch-started-outcome-unknown'
         AND target_io_state = 'performed' AND succeeded = 1
         AND backend_terminal_proven = 1 AND backend_finished_at IS NOT NULL
         AND worker_result_digest IS NOT NULL
         AND backend_terminal_proof_digest IS NOT NULL)
        OR
        (terminal_kind = 'failed-after-dispatch-proven-terminal'
         AND attempt_state = 'dispatch-started-outcome-unknown'
         AND target_io_state = 'performed' AND succeeded = 0
         AND backend_terminal_proven = 1 AND backend_finished_at IS NOT NULL
         AND worker_result_digest IS NOT NULL
         AND backend_terminal_proof_digest IS NOT NULL)
    )
) STRICT
"""
_INVOCATIONS_TABLE_SQL = """
CREATE TABLE agentic_model_invocations (
    intent_id TEXT PRIMARY KEY NOT NULL,
    intent_digest TEXT NOT NULL UNIQUE,
    stable_request_id TEXT NOT NULL UNIQUE,
    provider_run_id TEXT NOT NULL UNIQUE,
    source_checkpoint_digest TEXT NOT NULL REFERENCES agentic_checkpoints(checkpoint_digest),
    context_digest TEXT NOT NULL,
    projection_digest TEXT NOT NULL,
    request_binding_digest TEXT NOT NULL,
    canonical_intent BLOB NOT NULL,
    state TEXT NOT NULL CHECK(state IN (
        'claimed', 'dispatch-started-outcome-unknown',
        'terminal-success', 'terminal-failure'
    )),
    dispatch_started_at TEXT,
    terminal_at TEXT,
    outcome_digest TEXT,
    receipt_reference TEXT,
    receipt_digest TEXT,
    receipt_run_path TEXT,
    receipt_run_id TEXT,
    receipt_root_digest TEXT,
    receipt_artifact_path TEXT,
    receipt_artifact_sha256 TEXT,
    state_digest TEXT NOT NULL,
    CHECK(
        (state = 'claimed' AND dispatch_started_at IS NULL AND terminal_at IS NULL
         AND outcome_digest IS NULL AND receipt_reference IS NULL AND receipt_digest IS NULL
         AND receipt_run_path IS NULL AND receipt_run_id IS NULL
         AND receipt_root_digest IS NULL AND receipt_artifact_path IS NULL
         AND receipt_artifact_sha256 IS NULL)
        OR
        (state = 'dispatch-started-outcome-unknown' AND dispatch_started_at IS NOT NULL
         AND terminal_at IS NULL AND outcome_digest IS NULL
         AND receipt_reference IS NULL AND receipt_digest IS NULL
         AND receipt_run_path IS NULL AND receipt_run_id IS NULL
         AND receipt_root_digest IS NULL AND receipt_artifact_path IS NULL
         AND receipt_artifact_sha256 IS NULL)
        OR
        (state IN ('terminal-success', 'terminal-failure')
         AND dispatch_started_at IS NOT NULL AND terminal_at IS NOT NULL
         AND outcome_digest IS NOT NULL AND receipt_reference IS NOT NULL
         AND receipt_digest IS NOT NULL AND receipt_run_path IS NOT NULL
         AND receipt_run_id IS NOT NULL AND receipt_root_digest IS NOT NULL
         AND receipt_artifact_path IS NOT NULL AND receipt_artifact_sha256 IS NOT NULL)
    )
) STRICT
"""
_METADATA_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_coordination_metadata_immutable
BEFORE UPDATE ON agentic_coordination_metadata
BEGIN SELECT RAISE(ABORT, 'agentic coordination metadata is immutable'); END
"""
_METADATA_NO_DELETE_SQL = """
CREATE TRIGGER agentic_coordination_metadata_no_delete
BEFORE DELETE ON agentic_coordination_metadata
BEGIN SELECT RAISE(ABORT, 'agentic coordination metadata is immutable'); END
"""
_CHECKPOINTS_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_checkpoints_immutable
BEFORE UPDATE ON agentic_checkpoints
BEGIN SELECT RAISE(ABORT, 'agentic checkpoints are immutable'); END
"""
_CHECKPOINTS_NO_DELETE_SQL = """
CREATE TRIGGER agentic_checkpoints_no_delete
BEFORE DELETE ON agentic_checkpoints
BEGIN SELECT RAISE(ABORT, 'agentic checkpoints are append-only'); END
"""
_HEAD_NO_DELETE_SQL = """
CREATE TRIGGER agentic_checkpoint_head_no_delete
BEFORE DELETE ON agentic_checkpoint_head
BEGIN SELECT RAISE(ABORT, 'agentic checkpoint head cannot be deleted'); END
"""
_HEAD_MONOTONIC_SQL = """
CREATE TRIGGER agentic_checkpoint_head_monotonic
BEFORE UPDATE ON agentic_checkpoint_head
WHEN NEW.revision != OLD.revision + 1
BEGIN SELECT RAISE(ABORT, 'agentic checkpoint head must advance exactly once'); END
"""
_CYCLES_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_cycles_immutable
BEFORE UPDATE ON agentic_cycles
BEGIN SELECT RAISE(ABORT, 'agentic cycles are immutable'); END
"""
_CYCLES_NO_DELETE_SQL = """
CREATE TRIGGER agentic_cycles_no_delete
BEFORE DELETE ON agentic_cycles
BEGIN SELECT RAISE(ABORT, 'agentic cycles are append-only'); END
"""
_EVENTS_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_events_immutable
BEFORE UPDATE ON agentic_events
BEGIN SELECT RAISE(ABORT, 'agentic events are immutable'); END
"""
_EVENTS_NO_DELETE_SQL = """
CREATE TRIGGER agentic_events_no_delete
BEFORE DELETE ON agentic_events
BEGIN SELECT RAISE(ABORT, 'agentic events are append-only'); END
"""
_OUTBOX_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_command_outbox_identity_immutable
BEFORE UPDATE OF command_id, command_digest, cycle_id, cycle_digest, ordinal,
    target_agent_id, command_sequence, canonical_command
ON agentic_command_outbox
BEGIN SELECT RAISE(ABORT, 'agentic outbox identity is immutable'); END
"""
_OUTBOX_NO_DELETE_SQL = """
CREATE TRIGGER agentic_command_outbox_no_delete
BEFORE DELETE ON agentic_command_outbox
BEGIN SELECT RAISE(ABORT, 'agentic outbox is append-only'); END
"""
_OUTBOX_MONOTONIC_SQL = """
CREATE TRIGGER agentic_command_outbox_monotonic
BEFORE UPDATE OF state, claimed_at, claim_id, claim_digest, acknowledged_at,
    acknowledgement_id, acknowledgement_digest, state_digest
ON agentic_command_outbox
WHEN NOT (
    (OLD.state = 'pending' AND NEW.state = 'delivery-started-outcome-unknown')
    OR
    (OLD.state = 'delivery-started-outcome-unknown' AND NEW.state = 'acknowledged')
)
BEGIN SELECT RAISE(ABORT, 'agentic outbox state must advance exactly once'); END
"""
_INBOX_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_command_inbox_immutable
BEFORE UPDATE ON agentic_command_inbox
BEGIN SELECT RAISE(ABORT, 'agentic command admission receipts are immutable'); END
"""
_INBOX_NO_DELETE_SQL = """
CREATE TRIGGER agentic_command_inbox_no_delete
BEFORE DELETE ON agentic_command_inbox
BEGIN SELECT RAISE(ABORT, 'agentic command admission receipts are append-only'); END
"""
_SPECIALIST_EXECUTION_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_specialist_execution_identity_immutable
BEFORE UPDATE OF reservation_id, reservation_digest, store_id,
    coordination_binding_digest, source_head_checkpoint_id,
    source_head_checkpoint_digest, graph_snapshot_id, graph_snapshot_digest,
    cycle_id, cycle_digest, command_id, command_digest, admission_receipt_id,
    admission_receipt_digest, target_agent_id, task_id, candidate_id,
    candidate_digest, proposal_digest, target_id, threat_class, specialization,
    specialist_definition_digest, reserved_at
ON agentic_specialist_executions
BEGIN SELECT RAISE(ABORT, 'agentic specialist execution identity is immutable'); END
"""
_SPECIALIST_EXECUTION_NO_DELETE_SQL = """
CREATE TRIGGER agentic_specialist_executions_no_delete
BEFORE DELETE ON agentic_specialist_executions
BEGIN SELECT RAISE(ABORT, 'agentic specialist executions are append-only'); END
"""
_SPECIALIST_EXECUTION_MONOTONIC_SQL = """
CREATE TRIGGER agentic_specialist_executions_monotonic
BEFORE UPDATE OF canonical_entry, state, dispatch_started_at, state_digest
ON agentic_specialist_executions
WHEN NOT (
    OLD.state = 'reserved'
    AND NEW.state = 'dispatch-started-outcome-unknown'
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist execution state must advance exactly once'); END
"""
_SPECIALIST_DISPATCH_PLAN_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_specialist_dispatch_plan_identity_immutable
BEFORE UPDATE OF plan_id, plan_digest, store_id, coordination_binding_digest,
    reservation_id, reservation_digest, command_id, command_digest,
    preparation_id, preparation_digest, prepared_action_digest, request_id,
    grant_id, grant_digest, approval_id, approval_digest,
    action_proposal_id, action_proposal_digest, expected_action_permit_id, planned_at
ON agentic_specialist_dispatch_plans
BEGIN SELECT RAISE(ABORT, 'agentic specialist dispatch plan identity is immutable'); END
"""
_SPECIALIST_DISPATCH_PLAN_NO_DELETE_SQL = """
CREATE TRIGGER agentic_specialist_dispatch_plans_no_delete
BEFORE DELETE ON agentic_specialist_dispatch_plans
BEGIN SELECT RAISE(ABORT, 'agentic specialist dispatch plans are append-only'); END
"""
_SPECIALIST_DISPATCH_PLAN_MONOTONIC_SQL = """
CREATE TRIGGER agentic_specialist_dispatch_plans_monotonic
BEFORE UPDATE OF canonical_entry, state, state_digest, action_permit_id,
    action_permit_digest, approval_receipt_id, approval_receipt_digest,
    grant_consumption_receipt_id, grant_consumption_receipt_digest,
    grant_consumed_at, callback_entered_at, reconciled_at
ON agentic_specialist_dispatch_plans
WHEN NOT (
    OLD.state = 'awaiting-permit'
    AND NEW.state IN (
        'dispatch-started-outcome-unknown', 'permit-consumed-entry-unknown'
    )
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist dispatch plan state must advance once'); END
"""
_SPECIALIST_JOB_ATTEMPT_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_specialist_job_attempt_identity_immutable
BEFORE UPDATE OF attempt_id, attempt_digest, store_id,
    coordination_binding_digest, database_identity_digest, deployment_digest,
    control_plane_run_id, campaign_id, campaign_manifest_digest,
    plan_id, plan_digest, plan_state_digest, reservation_id,
    reservation_digest, reservation_state_digest, command_id, command_digest,
    target_agent_id, task_id, scheduler_task_name,
    scheduler_task_token_digest, runtime_capsule_token_digest, specialization,
    dispatch_binding_id,
    dispatch_binding_digest, claim_verification_id, claim_verification_digest,
    graph_snapshot_id, graph_snapshot_digest, preparation_id, preparation_digest,
    profile_registry_digest, profile_id, profile_version, profile_digest,
    executor_catalog_digest, executor_id, executor_version, executor_digest,
    prepared_action_digest, activation_set_digest,
    release_id, release_digest, capability_id, capability_version,
    capability_definition_digest, capability_digest,
    capability_authority_set_id, capability_authority_set_digest,
    tool_id, tool_version,
    tool_digest, request_id, request_digest, capability_grant_id,
    capability_grant_digest, grant_lineage_state_digest,
    capability_grant_expires_at, grant_consumption_receipt_id,
    grant_consumption_receipt_digest, action_permit_id, action_permit_digest,
    action_permit_expires_at, approval_id, approval_digest, approval_expires_at,
    approval_consumption_receipt_id, approval_consumption_receipt_digest,
    dispatch_id, target_id, target_digest, gateway_id, gateway_version,
    gateway_digest, execution_inventory_id, execution_inventory_digest,
    worker_backend_id, worker_backend_version,
    worker_backend_digest, worker_job_id, worker_job_digest,
    worker_command_digest, worker_compiler_id, worker_compiler_version,
    worker_compiler_digest, worker_image_reference, worker_image_digest,
    worker_verifier_id, worker_verifier_version, worker_verifier_digest,
    worker_verification_key_id, worker_verification_key_digest, claimed_at
ON agentic_specialist_job_attempts
BEGIN SELECT RAISE(ABORT, 'agentic specialist job-attempt identity is immutable'); END
"""
_SPECIALIST_JOB_ATTEMPT_NO_DELETE_SQL = """
CREATE TRIGGER agentic_specialist_job_attempts_no_delete
BEFORE DELETE ON agentic_specialist_job_attempts
BEGIN SELECT RAISE(ABORT, 'agentic specialist job attempts are append-only'); END
"""
_SPECIALIST_JOB_ATTEMPT_INSERT_COLLISION_SQL = """
CREATE TRIGGER agentic_specialist_job_attempt_insert_collision
BEFORE INSERT ON agentic_specialist_job_attempts
WHEN EXISTS (
    SELECT 1 FROM agentic_specialist_job_attempts AS attempt
    WHERE attempt.attempt_id = NEW.attempt_id
       OR attempt.attempt_digest = NEW.attempt_digest
       OR attempt.plan_id = NEW.plan_id
       OR attempt.plan_digest = NEW.plan_digest
       OR attempt.plan_state_digest = NEW.plan_state_digest
       OR attempt.reservation_id = NEW.reservation_id
       OR attempt.reservation_digest = NEW.reservation_digest
       OR attempt.reservation_state_digest = NEW.reservation_state_digest
       OR attempt.command_id = NEW.command_id
       OR attempt.scheduler_task_token_digest = NEW.scheduler_task_token_digest
       OR attempt.runtime_capsule_token_digest = NEW.runtime_capsule_token_digest
       OR attempt.dispatch_binding_id = NEW.dispatch_binding_id
       OR attempt.dispatch_binding_digest = NEW.dispatch_binding_digest
       OR attempt.claim_verification_id = NEW.claim_verification_id
       OR (
           NEW.dispatch_verification_id IS NOT NULL
           AND attempt.dispatch_verification_id = NEW.dispatch_verification_id
       )
       OR attempt.prepared_action_digest = NEW.prepared_action_digest
       OR attempt.request_id = NEW.request_id
       OR attempt.request_digest = NEW.request_digest
       OR attempt.grant_consumption_receipt_id = NEW.grant_consumption_receipt_id
       OR attempt.grant_consumption_receipt_digest = NEW.grant_consumption_receipt_digest
       OR attempt.action_permit_id = NEW.action_permit_id
       OR attempt.action_permit_digest = NEW.action_permit_digest
       OR attempt.approval_consumption_receipt_id = NEW.approval_consumption_receipt_id
       OR attempt.approval_consumption_receipt_digest
          = NEW.approval_consumption_receipt_digest
       OR attempt.dispatch_id = NEW.dispatch_id
       OR attempt.worker_job_id = NEW.worker_job_id
       OR attempt.worker_job_digest = NEW.worker_job_digest
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist job attempt insert collision'); END
"""
_SPECIALIST_JOB_ATTEMPT_DISPATCH_VERIFICATION_COLLISION_SQL = """
CREATE TRIGGER agentic_specialist_job_attempt_dispatch_verification_collision
BEFORE UPDATE OF dispatch_verification_id ON agentic_specialist_job_attempts
WHEN NEW.dispatch_verification_id IS NOT NULL AND EXISTS (
    SELECT 1 FROM agentic_specialist_job_attempts AS attempt
    WHERE attempt.dispatch_verification_id = NEW.dispatch_verification_id
      AND attempt.attempt_id != OLD.attempt_id
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist dispatch verification collision'); END
"""
_SPECIALIST_JOB_ATTEMPT_PARENT_SQL = """
CREATE TRIGGER agentic_specialist_job_attempt_parent_exact
BEFORE INSERT ON agentic_specialist_job_attempts
WHEN NOT EXISTS (
    SELECT 1
    FROM agentic_specialist_dispatch_plans AS plan
    JOIN agentic_specialist_executions AS execution
      ON execution.reservation_id = plan.reservation_id
    WHERE plan.plan_id = NEW.plan_id
      AND plan.plan_digest = NEW.plan_digest
      AND plan.state_digest = NEW.plan_state_digest
      AND plan.state = 'dispatch-started-outcome-unknown'
      AND plan.store_id = NEW.store_id
      AND plan.coordination_binding_digest = NEW.coordination_binding_digest
      AND plan.reservation_id = NEW.reservation_id
      AND plan.reservation_digest = NEW.reservation_digest
      AND plan.command_id = NEW.command_id
      AND plan.command_digest = NEW.command_digest
      AND plan.preparation_id = NEW.preparation_id
      AND plan.preparation_digest = NEW.preparation_digest
      AND plan.prepared_action_digest = NEW.prepared_action_digest
      AND plan.request_id = NEW.request_id
      AND plan.grant_id = NEW.capability_grant_id
      AND plan.grant_digest = NEW.capability_grant_digest
      AND plan.approval_id = NEW.approval_id
      AND plan.approval_digest = NEW.approval_digest
      AND plan.grant_consumption_receipt_id = NEW.grant_consumption_receipt_id
      AND plan.grant_consumption_receipt_digest
          = NEW.grant_consumption_receipt_digest
      AND plan.action_permit_id = NEW.action_permit_id
      AND plan.action_permit_digest = NEW.action_permit_digest
      AND plan.approval_receipt_id = NEW.approval_consumption_receipt_id
      AND plan.approval_receipt_digest
          = NEW.approval_consumption_receipt_digest
      AND execution.reservation_digest = NEW.reservation_digest
      AND execution.state_digest = NEW.reservation_state_digest
      AND execution.state = 'dispatch-started-outcome-unknown'
      AND execution.store_id = NEW.store_id
      AND execution.coordination_binding_digest = NEW.coordination_binding_digest
      AND execution.command_id = NEW.command_id
      AND execution.command_digest = NEW.command_digest
      AND execution.target_agent_id = NEW.target_agent_id
      AND execution.task_id = NEW.task_id
      AND execution.target_id = NEW.target_id
      AND execution.specialization = NEW.specialization
      AND execution.graph_snapshot_id = NEW.graph_snapshot_id
      AND execution.graph_snapshot_digest = NEW.graph_snapshot_digest
      AND plan.callback_entered_at = execution.dispatch_started_at
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist job attempt parent differs'); END
"""
_SPECIALIST_JOB_ATTEMPT_MONOTONIC_SQL = """
CREATE TRIGGER agentic_specialist_job_attempts_monotonic
BEFORE UPDATE OF canonical_entry, state, state_digest,
    dispatch_verification_id, dispatch_verification_digest, dispatch_event_digest,
    backend_dispatch_started_at
ON agentic_specialist_job_attempts
WHEN NOT (
    OLD.state = 'claimed-before-backend'
    AND NEW.state = 'dispatch-started-outcome-unknown'
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist job-attempt state must advance once'); END
"""
_SPECIALIST_JOB_ATTEMPT_TERMINAL_FENCE_SQL = """
CREATE TRIGGER agentic_specialist_job_attempt_terminal_fence
BEFORE UPDATE OF canonical_entry, state, state_digest,
    dispatch_verification_id, dispatch_verification_digest, dispatch_event_digest,
    backend_dispatch_started_at
ON agentic_specialist_job_attempts
WHEN EXISTS (
    SELECT 1 FROM agentic_specialist_terminal_receipts AS receipt
    WHERE receipt.attempt_id = OLD.attempt_id
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist job attempt is terminal'); END
"""
_SPECIALIST_TERMINAL_RECEIPT_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_specialist_terminal_receipts_immutable
BEFORE UPDATE ON agentic_specialist_terminal_receipts
BEGIN SELECT RAISE(ABORT, 'agentic specialist terminal receipts are immutable'); END
"""
_SPECIALIST_TERMINAL_RECEIPT_NO_DELETE_SQL = """
CREATE TRIGGER agentic_specialist_terminal_receipts_no_delete
BEFORE DELETE ON agentic_specialist_terminal_receipts
BEGIN SELECT RAISE(ABORT, 'agentic specialist terminal receipts are append-only'); END
"""
_SPECIALIST_TERMINAL_RECEIPT_INSERT_COLLISION_SQL = """
CREATE TRIGGER agentic_specialist_terminal_receipt_insert_collision
BEFORE INSERT ON agentic_specialist_terminal_receipts
WHEN EXISTS (
    SELECT 1 FROM agentic_specialist_terminal_receipts AS receipt
    WHERE receipt.receipt_id = NEW.receipt_id
       OR receipt.receipt_digest = NEW.receipt_digest
       OR receipt.attempt_id = NEW.attempt_id
       OR receipt.attempt_digest = NEW.attempt_digest
       OR receipt.attempt_state_digest = NEW.attempt_state_digest
       OR receipt.plan_id = NEW.plan_id
       OR receipt.request_id = NEW.request_id
       OR receipt.worker_job_id = NEW.worker_job_id
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist terminal receipt insert collision'); END
"""
_SPECIALIST_TERMINAL_RECEIPT_PARENT_SQL = """
CREATE TRIGGER agentic_specialist_terminal_receipt_parent_exact
BEFORE INSERT ON agentic_specialist_terminal_receipts
WHEN NOT EXISTS (
    SELECT 1 FROM agentic_specialist_job_attempts AS attempt
    WHERE attempt.attempt_id = NEW.attempt_id
      AND attempt.attempt_digest = NEW.attempt_digest
      AND attempt.state = NEW.attempt_state
      AND attempt.state_digest = NEW.attempt_state_digest
      AND attempt.store_id = NEW.store_id
      AND attempt.coordination_binding_digest = NEW.coordination_binding_digest
      AND attempt.plan_id = NEW.plan_id
      AND attempt.request_id = NEW.request_id
      AND attempt.worker_job_id = NEW.worker_job_id
)
BEGIN SELECT RAISE(ABORT, 'agentic specialist terminal receipt parent differs'); END
"""
_INVOCATION_IMMUTABLE_SQL = """
CREATE TRIGGER agentic_model_invocation_identity_immutable
BEFORE UPDATE OF intent_id, intent_digest, stable_request_id, provider_run_id,
    source_checkpoint_digest, context_digest, projection_digest,
    request_binding_digest, canonical_intent
ON agentic_model_invocations
BEGIN SELECT RAISE(ABORT, 'agentic invocation intent is immutable'); END
"""
_INVOCATION_NO_DELETE_SQL = """
CREATE TRIGGER agentic_model_invocations_no_delete
BEFORE DELETE ON agentic_model_invocations
BEGIN SELECT RAISE(ABORT, 'agentic invocation journal is append-only'); END
"""
_INVOCATION_MONOTONIC_SQL = """
CREATE TRIGGER agentic_model_invocations_monotonic
BEFORE UPDATE OF state, dispatch_started_at, terminal_at, outcome_digest,
    receipt_reference, receipt_digest, receipt_run_path, receipt_run_id,
    receipt_root_digest, receipt_artifact_path, receipt_artifact_sha256, state_digest
ON agentic_model_invocations
WHEN NOT (
    (OLD.state = 'claimed' AND NEW.state = 'dispatch-started-outcome-unknown')
    OR
    (OLD.state = 'dispatch-started-outcome-unknown'
     AND NEW.state IN ('terminal-success', 'terminal-failure'))
)
BEGIN SELECT RAISE(ABORT, 'agentic invocation state must advance exactly once'); END
"""

_SCHEMA_OBJECTS: dict[tuple[str, str], str] = {
    ("table", "agentic_coordination_metadata"): _METADATA_TABLE_SQL,
    ("table", "agentic_checkpoints"): _CHECKPOINTS_TABLE_SQL,
    ("table", "agentic_checkpoint_head"): _HEAD_TABLE_SQL,
    ("table", "agentic_cycles"): _CYCLES_TABLE_SQL,
    ("table", "agentic_events"): _EVENTS_TABLE_SQL,
    ("table", "agentic_command_outbox"): _OUTBOX_TABLE_SQL,
    ("table", "agentic_command_inbox"): _INBOX_TABLE_SQL,
    ("table", "agentic_specialist_executions"): _SPECIALIST_EXECUTIONS_TABLE_SQL,
    ("table", "agentic_specialist_dispatch_plans"): _SPECIALIST_DISPATCH_PLANS_TABLE_SQL,
    ("table", "agentic_specialist_job_attempts"): _SPECIALIST_JOB_ATTEMPTS_TABLE_SQL,
    (
        "table",
        "agentic_specialist_terminal_receipts",
    ): _SPECIALIST_TERMINAL_RECEIPTS_TABLE_SQL,
    ("table", "agentic_model_invocations"): _INVOCATIONS_TABLE_SQL,
    ("trigger", "agentic_coordination_metadata_immutable"): _METADATA_IMMUTABLE_SQL,
    ("trigger", "agentic_coordination_metadata_no_delete"): _METADATA_NO_DELETE_SQL,
    ("trigger", "agentic_checkpoints_immutable"): _CHECKPOINTS_IMMUTABLE_SQL,
    ("trigger", "agentic_checkpoints_no_delete"): _CHECKPOINTS_NO_DELETE_SQL,
    ("trigger", "agentic_checkpoint_head_no_delete"): _HEAD_NO_DELETE_SQL,
    ("trigger", "agentic_checkpoint_head_monotonic"): _HEAD_MONOTONIC_SQL,
    ("trigger", "agentic_cycles_immutable"): _CYCLES_IMMUTABLE_SQL,
    ("trigger", "agentic_cycles_no_delete"): _CYCLES_NO_DELETE_SQL,
    ("trigger", "agentic_events_immutable"): _EVENTS_IMMUTABLE_SQL,
    ("trigger", "agentic_events_no_delete"): _EVENTS_NO_DELETE_SQL,
    ("trigger", "agentic_command_outbox_identity_immutable"): _OUTBOX_IMMUTABLE_SQL,
    ("trigger", "agentic_command_outbox_no_delete"): _OUTBOX_NO_DELETE_SQL,
    ("trigger", "agentic_command_outbox_monotonic"): _OUTBOX_MONOTONIC_SQL,
    ("trigger", "agentic_command_inbox_immutable"): _INBOX_IMMUTABLE_SQL,
    ("trigger", "agentic_command_inbox_no_delete"): _INBOX_NO_DELETE_SQL,
    (
        "trigger",
        "agentic_specialist_execution_identity_immutable",
    ): _SPECIALIST_EXECUTION_IMMUTABLE_SQL,
    (
        "trigger",
        "agentic_specialist_executions_no_delete",
    ): _SPECIALIST_EXECUTION_NO_DELETE_SQL,
    (
        "trigger",
        "agentic_specialist_executions_monotonic",
    ): _SPECIALIST_EXECUTION_MONOTONIC_SQL,
    (
        "trigger",
        "agentic_specialist_dispatch_plan_identity_immutable",
    ): _SPECIALIST_DISPATCH_PLAN_IMMUTABLE_SQL,
    (
        "trigger",
        "agentic_specialist_dispatch_plans_no_delete",
    ): _SPECIALIST_DISPATCH_PLAN_NO_DELETE_SQL,
    (
        "trigger",
        "agentic_specialist_dispatch_plans_monotonic",
    ): _SPECIALIST_DISPATCH_PLAN_MONOTONIC_SQL,
    (
        "trigger",
        "agentic_specialist_job_attempt_identity_immutable",
    ): _SPECIALIST_JOB_ATTEMPT_IMMUTABLE_SQL,
    (
        "trigger",
        "agentic_specialist_job_attempts_no_delete",
    ): _SPECIALIST_JOB_ATTEMPT_NO_DELETE_SQL,
    (
        "trigger",
        "agentic_specialist_job_attempt_insert_collision",
    ): _SPECIALIST_JOB_ATTEMPT_INSERT_COLLISION_SQL,
    (
        "trigger",
        "agentic_specialist_job_attempt_dispatch_verification_collision",
    ): _SPECIALIST_JOB_ATTEMPT_DISPATCH_VERIFICATION_COLLISION_SQL,
    (
        "trigger",
        "agentic_specialist_job_attempt_parent_exact",
    ): _SPECIALIST_JOB_ATTEMPT_PARENT_SQL,
    (
        "trigger",
        "agentic_specialist_job_attempts_monotonic",
    ): _SPECIALIST_JOB_ATTEMPT_MONOTONIC_SQL,
    (
        "trigger",
        "agentic_specialist_job_attempt_terminal_fence",
    ): _SPECIALIST_JOB_ATTEMPT_TERMINAL_FENCE_SQL,
    (
        "trigger",
        "agentic_specialist_terminal_receipts_immutable",
    ): _SPECIALIST_TERMINAL_RECEIPT_IMMUTABLE_SQL,
    (
        "trigger",
        "agentic_specialist_terminal_receipts_no_delete",
    ): _SPECIALIST_TERMINAL_RECEIPT_NO_DELETE_SQL,
    (
        "trigger",
        "agentic_specialist_terminal_receipt_insert_collision",
    ): _SPECIALIST_TERMINAL_RECEIPT_INSERT_COLLISION_SQL,
    (
        "trigger",
        "agentic_specialist_terminal_receipt_parent_exact",
    ): _SPECIALIST_TERMINAL_RECEIPT_PARENT_SQL,
    ("trigger", "agentic_model_invocation_identity_immutable"): _INVOCATION_IMMUTABLE_SQL,
    ("trigger", "agentic_model_invocations_no_delete"): _INVOCATION_NO_DELETE_SQL,
    ("trigger", "agentic_model_invocations_monotonic"): _INVOCATION_MONOTONIC_SQL,
}
_SCHEMA_V6_ADDITION_KEYS = (
    ("table", "agentic_specialist_job_attempts"),
    ("table", "agentic_specialist_terminal_receipts"),
    ("trigger", "agentic_specialist_job_attempt_identity_immutable"),
    ("trigger", "agentic_specialist_job_attempts_no_delete"),
    ("trigger", "agentic_specialist_job_attempt_insert_collision"),
    (
        "trigger",
        "agentic_specialist_job_attempt_dispatch_verification_collision",
    ),
    ("trigger", "agentic_specialist_job_attempt_parent_exact"),
    ("trigger", "agentic_specialist_job_attempts_monotonic"),
    ("trigger", "agentic_specialist_job_attempt_terminal_fence"),
    ("trigger", "agentic_specialist_terminal_receipts_immutable"),
    ("trigger", "agentic_specialist_terminal_receipts_no_delete"),
    ("trigger", "agentic_specialist_terminal_receipt_insert_collision"),
    ("trigger", "agentic_specialist_terminal_receipt_parent_exact"),
)
_SCHEMA_V6_ADDITION_KEY_SET = frozenset(_SCHEMA_V6_ADDITION_KEYS)
_SCHEMA_V5_OBJECTS = {
    key: value for key, value in _SCHEMA_OBJECTS.items() if key not in _SCHEMA_V6_ADDITION_KEY_SET
}
_TABLES = frozenset(name for (kind, name) in _SCHEMA_OBJECTS if kind == "table")
_SCHEMA_V5_TABLES = frozenset(name for (kind, name) in _SCHEMA_V5_OBJECTS if kind == "table")


def _normalize_sql(value: str) -> str:
    return " ".join(value.split())


_COMPUTED_SCHEMA_V6_DIGEST = sha256(
    canonical_json_bytes(
        {
            f"{kind}:{name}": _normalize_sql(statement)
            for (kind, name), statement in sorted(_SCHEMA_OBJECTS.items())
        },
        label="Agentic coordination schema",
    )
).hexdigest()
if _COMPUTED_SCHEMA_V6_DIGEST != AGENTIC_COORDINATION_SCHEMA_V6_DIGEST:
    raise RuntimeError("frozen agentic coordination schema v6 objects changed")
_SCHEMA_DIGEST = AGENTIC_COORDINATION_SCHEMA_V6_DIGEST
_COMPUTED_SCHEMA_V5_DIGEST = sha256(
    canonical_json_bytes(
        {
            f"{kind}:{name}": _normalize_sql(statement)
            for (kind, name), statement in sorted(_SCHEMA_V5_OBJECTS.items())
        },
        label="Agentic coordination schema",
    )
).hexdigest()
if _COMPUTED_SCHEMA_V5_DIGEST != AGENTIC_COORDINATION_SCHEMA_V5_DIGEST:
    raise RuntimeError("frozen agentic coordination schema v5 objects changed")


def _capability_ledger_runtime_identity(
    ledger: CapabilityLedger,
) -> tuple[object, object, object, object]:
    if (
        type(ledger) is not CapabilityLedger
        or CapabilityLedger.record is not _CAPABILITY_LEDGER_RECORD_IMPLEMENTATION
        or CapabilityLedger.can_consume is not _CAPABILITY_LEDGER_CAN_CONSUME_IMPLEMENTATION
        or CapabilityLedger.consume is not _CAPABILITY_LEDGER_CONSUME_IMPLEMENTATION
        or "record" in vars(ledger)
        or "can_consume" in vars(ledger)
        or "consume" in vars(ledger)
    ):
        raise AgenticCoordinationError(
            "specialist dispatch Capability Ledger implementation changed"
        )
    max_depth = getattr(ledger, "_max_depth", None)
    records = getattr(ledger, "_records", None)
    ledger_lock = getattr(ledger, "_lock", None)
    ledger_clock = getattr(ledger, "_clock", None)
    if (
        type(max_depth) is not int
        or type(records) is not dict
        or ledger_lock is None
        or not callable(ledger_clock)
    ):
        raise AgenticCoordinationError("specialist dispatch Capability Ledger runtime is invalid")
    return max_depth, records, ledger_lock, ledger_clock


def _specialist_capability_lineage_observation(
    ledger: CapabilityLedger,
    grant_id: str,
) -> tuple[tuple[CapabilityGrant, int, bool], ...]:
    """Read one detached child-to-root lineage while the pinned Ledger lock is held."""

    max_depth_raw, _, _, _ = _capability_ledger_runtime_identity(ledger)
    max_depth = cast(int, max_depth_raw)
    observed: list[tuple[CapabilityGrant, int, bool]] = []
    seen: set[str] = set()
    current_id: str | None = grant_id
    while current_id is not None:
        if current_id in seen or len(observed) > max_depth:
            raise AgenticCoordinationError(
                "specialist Capability Grant lineage is cyclic or exceeds its bound"
            )
        seen.add(current_id)
        record = _CAPABILITY_LEDGER_RECORD_IMPLEMENTATION(ledger, current_id)
        if record.grant.grant_id != current_id:
            raise AgenticCoordinationError("specialist Capability Grant lineage identity changed")
        observed.append((record.grant, record.remaining_calls, record.revoked))
        current_id = record.grant.parent_grant_id
    if not observed:
        raise AgenticCoordinationError("specialist Capability Grant lineage is empty")
    return tuple(observed)


def _specialist_capability_lineage_state_digest(
    lineage: tuple[tuple[CapabilityGrant, int, bool], ...],
) -> str:
    """Content-address one exact child-to-root Grant state observation."""

    if not lineage:
        raise AgenticCoordinationError("specialist Capability Grant lineage is empty")
    return discovery_digest(
        "pajin.agentic.specialist-capability-grant-lineage-state/v1",
        [
            {
                "grantId": grant.grant_id,
                "grantDigest": capability_grant_digest(grant),
                "remainingCalls": remaining_calls,
                "revoked": revoked,
            }
            for grant, remaining_calls, revoked in lineage
        ],
    )


_SPECIALIST_CAPABILITY_LINEAGE_STATE_DIGEST_IMPLEMENTATION = (
    _specialist_capability_lineage_state_digest
)


def _require_specialist_capability_consumption(
    *,
    before: tuple[tuple[CapabilityGrant, int, bool], ...],
    after: tuple[tuple[CapabilityGrant, int, bool], ...],
    expected_grant: CapabilityGrant,
) -> None:
    if (
        not before
        or before[0][0] != expected_grant
        or len(before) != len(after)
        or any(remaining <= 0 or revoked for _, remaining, revoked in before)
    ):
        raise AgenticCoordinationError("specialist Capability Grant lineage was not consumable")
    for before_item, after_item in zip(before, after, strict=True):
        before_grant, before_remaining, before_revoked = before_item
        after_grant, after_remaining, after_revoked = after_item
        if (
            after_grant != before_grant
            or after_remaining != before_remaining - 1
            or after_revoked != before_revoked
        ):
            raise AgenticCoordinationError(
                "specialist Capability Grant lineage consumption differs"
            )


def _canonical_specialist_dispatch_inputs(
    *,
    reservation: VerifiedSpecialistExecutionReservation,
    preparation: AgenticSpecialistPreparation,
    activation: WebSpecialistCapabilityActivation,
    prepared_action: PreparedCapabilityAction,
    campaign: CampaignManifest,
    capability_ledger: CapabilityLedger,
    capability_grant: CapabilityGrant,
    approval_envelope: ActionApprovalEnvelope,
    authority: object,
) -> tuple[CampaignManifest, PreparedCapabilityAction, CapabilityGrant, ActionApprovalEnvelope]:
    from pajin.agentic.specialist_preparation import AgenticSpecialistPreparation
    from pajin.capabilities.agentic_web_specialist import WebSpecialistCapabilityActivation

    required_types = (
        (reservation, VerifiedSpecialistExecutionReservation, "reservation authority"),
        (preparation, AgenticSpecialistPreparation, "inert preparation"),
        (activation, WebSpecialistCapabilityActivation, "Capability activation"),
        (prepared_action, PreparedCapabilityAction, "Prepared Capability Action"),
        (campaign, CampaignManifest, "Campaign Manifest"),
        (capability_ledger, CapabilityLedger, "Capability Ledger"),
        (capability_grant, CapabilityGrant, "Capability Grant"),
        (approval_envelope, ActionApprovalEnvelope, "approval envelope"),
    )
    for value, expected, label in required_types:
        if type(value) is not expected:
            raise AgenticCoordinationError(
                f"specialist dispatch planning requires an exact {label}"
            )
    reservation._require(authority)
    _capability_ledger_runtime_identity(capability_ledger)
    canonical_campaign = CampaignManifest.model_validate_json(
        campaign.model_dump_json(by_alias=True)
    )
    canonical_action = PreparedCapabilityAction.model_validate(
        prepared_action.model_dump(mode="json", by_alias=True)
    )
    canonical_grant = CapabilityGrant.model_validate(capability_grant.model_dump(mode="json"))
    canonical_approval = ActionApprovalEnvelope.model_validate(
        approval_envelope.model_dump(mode="json", by_alias=True)
    )
    if (
        canonical_campaign != campaign
        or canonical_action != prepared_action
        or canonical_grant != capability_grant
        or canonical_approval != approval_envelope
    ):
        raise AgenticCoordinationError(
            "specialist dispatch planning input differs after strict reload"
        )
    return canonical_campaign, canonical_action, canonical_grant, canonical_approval


def _canonical_sql_specialist_dispatch_v2_inputs(
    *,
    reservation: VerifiedSpecialistExecutionReservation,
    preparation: AgenticSpecialistPreparation,
    activation: WebSQLSpecialistCapabilityActivationV2,
    prepared_action: PreparedCapabilityAction,
    campaign: CampaignManifest,
    capability_ledger: CapabilityLedger,
    capability_grant: CapabilityGrant,
    approval_envelope: ActionApprovalEnvelope,
    authority: object,
) -> tuple[CampaignManifest, PreparedCapabilityAction, CapabilityGrant, ActionApprovalEnvelope]:
    from pajin.agentic.specialist_preparation import AgenticSpecialistPreparation
    from pajin.capabilities.agentic_web_specialist_v2 import (
        WebSQLSpecialistCapabilityActivationV2,
    )

    required_types = (
        (reservation, VerifiedSpecialistExecutionReservation, "reservation authority"),
        (preparation, AgenticSpecialistPreparation, "inert preparation"),
        (activation, WebSQLSpecialistCapabilityActivationV2, "SQL v2 activation"),
        (prepared_action, PreparedCapabilityAction, "Prepared Capability Action"),
        (campaign, CampaignManifest, "Campaign Manifest"),
        (capability_ledger, CapabilityLedger, "Capability Ledger"),
        (capability_grant, CapabilityGrant, "Capability Grant"),
        (approval_envelope, ActionApprovalEnvelope, "approval envelope"),
    )
    for value, expected, label in required_types:
        if type(value) is not expected:
            raise AgenticCoordinationError(f"SQL specialist v2 planning requires an exact {label}")
    reservation._require(authority)
    _capability_ledger_runtime_identity(capability_ledger)
    canonical_campaign = CampaignManifest.model_validate_json(
        campaign.model_dump_json(by_alias=True)
    )
    canonical_action = PreparedCapabilityAction.model_validate(
        prepared_action.model_dump(mode="json", by_alias=True)
    )
    canonical_grant = CapabilityGrant.model_validate(capability_grant.model_dump(mode="json"))
    canonical_approval = ActionApprovalEnvelope.model_validate(
        approval_envelope.model_dump(mode="json", by_alias=True)
    )
    if (
        canonical_campaign != campaign
        or canonical_action != prepared_action
        or canonical_grant != capability_grant
        or canonical_approval != approval_envelope
    ):
        raise AgenticCoordinationError(
            "SQL specialist v2 planning input differs after strict reload"
        )
    return canonical_campaign, canonical_action, canonical_grant, canonical_approval


def _reverify_specialist_preparation_and_action(
    *,
    store: AgenticCoordinationStore,
    reservation: VerifiedSpecialistExecutionReservation,
    preparation: AgenticSpecialistPreparation,
    activation: WebSpecialistCapabilityActivation,
    action: PreparedCapabilityAction,
    campaign: CampaignManifest,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
) -> int:
    from pajin.agentic.specialist_preparation import prepare_agentic_specialist_action
    from pajin.capabilities.agentic_web_specialist import WebSpecialistAssessmentParameters

    current_preparation = prepare_agentic_specialist_action(
        store=store,
        reservation=reservation,
        graph_resolver=graph_resolver,
        graph_head=graph_head,
        campaign=campaign,
    )
    if current_preparation != preparation:
        raise AgenticCoordinationError(
            "specialist dispatch preparation differs from current code authority"
        )
    parameters = WebSpecialistAssessmentParameters.model_validate(action.request.arguments)
    recompiled = activation.prepare_action(
        release=action.release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=parameters.account_receipt_ref,
    )
    definition = activation.definition()
    if (
        recompiled != action
        or activation.specialization is not preparation.specialization
        or definition.capability_id != action.capability.capability_id
        or definition.capability_version != action.capability.capability_version
        or definition.capability_digest != action.capability.definition_digest
        or definition.tool.tool_id != action.request.tool_id
        or definition.risk_tier is not ToolRiskTier.T2
        or definition.side_effect_class.value != "read-only"
        or not definition.approval_required
        or definition.cleanup_required
    ):
        raise AgenticCoordinationError(
            "specialist dispatch Capability action differs from current activation"
        )
    return definition.request_unit_cost


def _reverify_sql_specialist_v2_preparation_and_action(
    *,
    store: AgenticCoordinationStore,
    reservation: VerifiedSpecialistExecutionReservation,
    preparation: AgenticSpecialistPreparation,
    activation: WebSQLSpecialistCapabilityActivationV2,
    action: PreparedCapabilityAction,
    campaign: CampaignManifest,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
) -> int:
    from pajin.agentic.specialist_preparation import prepare_agentic_specialist_action
    from pajin.capabilities.agentic_web_specialist import WebSpecialistAssessmentParameters
    from pajin.capabilities.agentic_web_specialist_v2 import (
        WebSQLSpecialistCapabilityActivationV2,
    )

    if type(activation) is not WebSQLSpecialistCapabilityActivationV2:
        raise AgenticCoordinationError(
            "SQL specialist v2 planning requires its exact Capability activation"
        )
    current_preparation = prepare_agentic_specialist_action(
        store=store,
        reservation=reservation,
        graph_resolver=graph_resolver,
        graph_head=graph_head,
        campaign=campaign,
    )
    if current_preparation != preparation:
        raise AgenticCoordinationError(
            "SQL specialist v2 preparation differs from current code authority"
        )
    parameters = WebSpecialistAssessmentParameters.model_validate(action.request.arguments)
    recompiled = _prepare_current_sql_specialist_v2_action(
        activation,
        release=action.release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=parameters.account_receipt_ref,
    )
    definition, _ = _sql_specialist_v2_definition_and_registry(activation)
    _validate_current_sql_specialist_v2_request(activation, action.request)
    if (
        recompiled != action
        or preparation.specialization is not PentestSpecialization.SQL_INJECTION
        or definition.capability_id != _EXECUTABLE_SPECIALIST_CAPABILITY_ID
        or definition.capability_version != _EXECUTABLE_SPECIALIST_CAPABILITY_VERSION
        or definition.capability_id != action.capability.capability_id
        or definition.capability_version != action.capability.capability_version
        or definition.capability_digest != action.capability.definition_digest
        or definition.tool.tool_id != _EXECUTABLE_SPECIALIST_TOOL_ID
        or definition.tool.tool_id != action.request.tool_id
        or definition.tool.tool_version != _EXECUTABLE_SPECIALIST_TOOL_VERSION
        or definition.risk_tier is not ToolRiskTier.T2
        or definition.side_effect_class.value != "read-only"
        or not definition.approval_required
        or definition.cleanup_required
    ):
        raise AgenticCoordinationError("SQL specialist v2 action differs from current activation")
    return definition.request_unit_cost


def _reverify_planned_specialist_preparation(
    *,
    binding: AgenticCoordinationBinding,
    store_id: str,
    execution: AgenticSpecialistExecutionEntry,
    preparation: AgenticSpecialistPreparation,
    campaign: CampaignManifest,
) -> None:
    """Re-resolve code-owned C2 routing after reservation authority was transferred."""

    from pajin.agentic.specialist_preparation import (
        AgenticSpecialistPreparation,
        _resolve_profile_and_executor,
    )
    from pajin.web_assessment.governed_adapter_profile import (
        GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        GOVERNED_JUICE_SHOP_ORIGIN,
        production_governed_web_adapter_profile_registry,
    )

    if type(preparation) is not AgenticSpecialistPreparation:
        raise AgenticCoordinationError(
            "specialist dispatch runtime requires an exact inert preparation"
        )
    canonical = AgenticSpecialistPreparation.model_validate(
        preparation.model_dump(mode="json", by_alias=True)
    )
    if canonical != preparation:
        raise AgenticCoordinationError(
            "specialist dispatch preparation differs after strict reload"
        )
    target_registry = production_governed_web_adapter_profile_registry()
    target_profile = target_registry.resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=GOVERNED_JUICE_SHOP_ORIGIN,
    )
    profile_catalog, profile, descriptor = _resolve_profile_and_executor(execution)
    profile_snapshot = profile.snapshot()
    campaign_digest = campaign_manifest_digest(campaign)
    if len(campaign.spec.targets) != 1:
        raise AgenticCoordinationError(
            "specialist dispatch Campaign target set changed after planning"
        )
    target = campaign.spec.targets[0]
    target_digest = discovery_digest(
        "pajin.agentic.specialist-target/v1",
        target.model_dump(mode="json", by_alias=True),
    )
    scope_digest = discovery_digest(
        "pajin.agentic.specialist-scope/v1",
        campaign.spec.scope.model_dump(mode="json", by_alias=True),
    )
    budget_digest = discovery_digest(
        "pajin.agentic.specialist-budget/v1",
        campaign.spec.budgets.model_dump(mode="json", by_alias=True),
    )
    execution_values = {
        "reservation_id": execution.reservation_id,
        "reservation_digest": execution.reservation_digest,
        "reservation_state_digest": execution.state_digest,
        "source_head_checkpoint_id": execution.source_head_checkpoint_id,
        "source_head_checkpoint_digest": execution.source_head_checkpoint_digest,
        "graph_snapshot_id": execution.graph_snapshot_id,
        "graph_snapshot_digest": execution.graph_snapshot_digest,
        "cycle_id": execution.cycle_id,
        "cycle_digest": execution.cycle_digest,
        "command_id": execution.command_id,
        "command_digest": execution.command_digest,
        "admission_receipt_id": execution.admission_receipt_id,
        "admission_receipt_digest": execution.admission_receipt_digest,
        "target_agent_id": execution.target_agent_id,
        "task_id": execution.task_id,
        "candidate_id": execution.candidate_id,
        "candidate_digest": execution.candidate_digest,
        "proposal_digest": execution.proposal_digest,
        "specialist_definition_digest": execution.specialist_definition_digest,
        "specialization": execution.specialization,
        "threat_class": execution.threat_class,
    }
    if any(getattr(preparation, key) != value for key, value in execution_values.items()):
        raise AgenticCoordinationError(
            "specialist dispatch preparation differs from its durable execution"
        )
    if (
        execution.state is not AgenticSpecialistExecutionState.RESERVED
        or preparation.store_id != store_id
        or preparation.coordination_binding_id != binding.binding_id
        or preparation.coordination_binding_digest != binding.binding_digest
        or preparation.control_plane_run_id != binding.control_plane_run_id
        or preparation.deployment_digest != binding.deployment_digest
        or preparation.target_registry_digest != target_profile.registry_digest
        or preparation.target_profile_digest != target_profile.profile_digest
        or preparation.adapter_catalog_digest != target_profile.catalog_digest
        or preparation.adapter_reference != target_profile.adapter_reference
        or preparation.adapter_implementation_id != target_profile.implementation_id
        or preparation.adapter_implementation_digest != target_profile.implementation_digest
        or preparation.adapter_plan_digest != target_profile.plan_digest
        or preparation.target_id != target_profile.target_id
        or preparation.target_type != target_profile.target_type
        or preparation.target_endpoint != target_profile.origin
        or preparation.target_digest != target_digest
        or preparation.profile_registry_digest != profile_catalog.registry_digest
        or preparation.profile != profile.reference()
        or preparation.executor_catalog_digest != descriptor.catalog_digest
        or preparation.executor_id != descriptor.executor_id
        or preparation.executor_version != descriptor.executor_version
        or preparation.executor_digest != descriptor.executor_digest
        or preparation.browser_implementation_id != descriptor.browser_implementation_id
        or preparation.browser_implementation_version != descriptor.browser_implementation_version
        or preparation.browser_implementation_digest != descriptor.browser_implementation_digest
        or preparation.diagnostic_steps != profile_snapshot.diagnostic_steps
        or preparation.promotable_steps != profile_snapshot.promotable_steps
        or preparation.campaign_id != campaign.metadata.name
        or preparation.campaign_manifest_digest != campaign_digest
        or preparation.scope_digest != scope_digest
        or preparation.budget_digest != budget_digest
        or target.id != target_profile.target_id
        or target.type != target_profile.target_type
        or target.endpoint != target_profile.origin
        or target.simulation
    ):
        raise AgenticCoordinationError(
            "specialist dispatch code-owned route changed after planning"
        )


def _require_specialist_dispatch_campaign(
    *,
    binding: AgenticCoordinationBinding,
    preparation: AgenticSpecialistPreparation,
    campaign: CampaignManifest,
) -> str:
    digest = campaign_manifest_digest(campaign)
    if (
        digest != binding.campaign_manifest_digest
        or digest != preparation.campaign_manifest_digest
        or campaign.metadata.name != binding.campaign_id
        or campaign.metadata.name != preparation.campaign_id
    ):
        raise AgenticCoordinationError(
            "specialist dispatch Campaign differs from coordination authority"
        )
    return digest


def _specialist_dispatch_grant_binding(
    *,
    ledger: CapabilityLedger,
    grant: CapabilityGrant,
    preparation: AgenticSpecialistPreparation,
    action: PreparedCapabilityAction,
) -> AgenticSpecialistCapabilityGrantBinding:
    _capability_ledger_runtime_identity(ledger)
    record = _CAPABILITY_LEDGER_RECORD_IMPLEMENTATION(ledger, grant.grant_id)
    if (
        record.grant != grant
        or record.remaining_calls != 1
        or record.revoked
        or not _CAPABILITY_LEDGER_CAN_CONSUME_IMPLEMENTATION(ledger, grant.grant_id)
        or grant.parent_grant_id is None
        or grant.depth < 1
        or grant.subject != preparation.target_agent_id
        or grant.campaign != preparation.campaign_id
        or grant.tools != {action.request.tool_id}
        or grant.targets != {preparation.target_endpoint}
        or grant.max_risk_tier is not ToolRiskTier.T2
        or grant.max_calls != 1
        or grant.delegable
    ):
        raise AgenticCoordinationError(
            "specialist dispatch Capability Grant is not exact and consumable"
        )
    return AgenticSpecialistCapabilityGrantBinding(
        grantId=grant.grant_id,
        grantDigest=capability_grant_digest(grant),
        parentGrantId=grant.parent_grant_id,
        subject=grant.subject,
        campaign=grant.campaign,
        tools=tuple(sorted(grant.tools)),
        targets=tuple(sorted(grant.targets)),
        maxRiskTier=cast(Literal[ToolRiskTier.T2], grant.max_risk_tier.value),
        maxCalls=1,
        remainingCalls=1,
        expiresAt=cast(datetime, _format_timestamp(grant.expires_at)),
        delegable=grant.delegable,
        issuedAt=cast(datetime, _format_timestamp(grant.issued_at)),
        depth=grant.depth,
        revoked=record.revoked,
    )


def _require_specialist_dispatch_approval(
    *,
    preparation: AgenticSpecialistPreparation,
    action: PreparedCapabilityAction,
    campaign: CampaignManifest,
    campaign_digest: str,
    grant: CapabilityGrant,
    approval: ActionApprovalEnvelope,
    snapshot: GraphSnapshot,
    request_units: int,
    planned_at: datetime,
) -> None:
    proposal = approval.proposal
    envelope = approval.mission_envelope
    decision = approval.graph_decision
    if (
        approval.campaign_id != preparation.campaign_id
        or approval.campaign_digest != campaign_digest
        or approval.run_id != preparation.control_plane_run_id
        or envelope.run_id != preparation.control_plane_run_id
        or approval.activation_set_digest != action.activation_set_digest
        or approval.release.release_id != action.release.release_id
        or approval.release.release_digest != action.release.release_digest
        or proposal.capability != action.capability
        or proposal.target_digest != preparation.target_digest
        or proposal.request_id != action.request.request_id
        or proposal.request_digest != action.request_digest
        or proposal.normalized_parameters_digest != action.normalized_parameters_digest
        or proposal.reservation.tool_calls != 1
        or proposal.reservation.request_units != request_units
        or proposal.reservation.cost_microusd != 0
        or decision.decision_kind is not GraphDecisionKind.ACTION_PROPOSAL
        or decision.snapshot != graph_snapshot_ref(snapshot)
        or approval.source_intent_digest != preparation.preparation_digest
    ):
        raise AgenticCoordinationError(
            "specialist dispatch approval tuple differs from the prepared action"
        )
    if (
        envelope.profile_id != preparation.profile.profile_id
        or envelope.profile_version != preparation.profile.profile_version
        or envelope.profile_digest != preparation.profile.profile_digest
        or envelope.allowed_capabilities != (action.capability,)
        or envelope.allowed_target_digests != (preparation.target_digest,)
        or envelope.source_campaign_digest != campaign_digest
        or envelope.max_risk_tier is not ToolRiskTier.T2
        or envelope.autonomy is not AutonomyLevel.SUPERVISED
        or envelope.budget.tool_call_limit != 1
        or envelope.budget.request_unit_limit != request_units
        or envelope.budget.cost_limit_microusd != 0
        or approval.side_effect_class != "read-only"
        or approval.cleanup_required
    ):
        raise AgenticCoordinationError(
            "specialist dispatch approval exceeds the task-scoped authority"
        )
    if (
        not campaign.spec.authorization.is_active(planned_at)
        or not grant.issued_at <= planned_at < grant.expires_at
        or not envelope.not_before <= planned_at < envelope.expires_at
        or not approval.not_before <= planned_at < approval.expires_at
        or envelope.expires_at > campaign.spec.authorization.expires_at
        or approval.expires_at > envelope.expires_at
        or approval.expires_at > grant.expires_at
    ):
        raise AgenticCoordinationError(
            "specialist dispatch authority window is not currently valid"
        )


def _reverify_planned_specialist_action(
    *,
    preparation: AgenticSpecialistPreparation,
    activation: WebSpecialistCapabilityActivation,
    action: PreparedCapabilityAction,
) -> int:
    from pajin.capabilities.agentic_web_specialist import (
        WebSpecialistAssessmentParameters,
        WebSpecialistCapabilityActivation,
    )

    if type(activation) is not WebSpecialistCapabilityActivation:
        raise AgenticCoordinationError(
            "specialist dispatch runtime requires the exact Capability activation"
        )
    parameters = WebSpecialistAssessmentParameters.model_validate(action.request.arguments)
    recompiled = activation.prepare_action(
        release=action.release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=parameters.account_receipt_ref,
    )
    definition = activation.definition()
    if (
        recompiled != action
        or activation.specialization is not preparation.specialization
        or definition.capability_id != action.capability.capability_id
        or definition.capability_version != action.capability.capability_version
        or definition.capability_digest != action.capability.definition_digest
        or definition.tool.tool_id != action.request.tool_id
        or definition.risk_tier is not ToolRiskTier.T2
        or definition.side_effect_class.value != "read-only"
        or not definition.approval_required
        or definition.cleanup_required
    ):
        raise AgenticCoordinationError(
            "specialist dispatch Capability action changed after planning"
        )
    return definition.request_unit_cost


def _reverify_planned_sql_specialist_v2_action(
    *,
    preparation: AgenticSpecialistPreparation,
    activation: WebSQLSpecialistCapabilityActivationV2,
    action: PreparedCapabilityAction,
) -> int:
    from pajin.capabilities.agentic_web_specialist import WebSpecialistAssessmentParameters
    from pajin.capabilities.agentic_web_specialist_v2 import (
        WebSQLSpecialistCapabilityActivationV2,
    )

    if type(activation) is not WebSQLSpecialistCapabilityActivationV2:
        raise AgenticCoordinationError(
            "SQL specialist v2 runtime requires its exact Capability activation"
        )
    parameters = WebSpecialistAssessmentParameters.model_validate(action.request.arguments)
    recompiled = _prepare_current_sql_specialist_v2_action(
        activation,
        release=action.release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=parameters.account_receipt_ref,
    )
    definition, _ = _sql_specialist_v2_definition_and_registry(activation)
    _validate_current_sql_specialist_v2_request(activation, action.request)
    if (
        recompiled != action
        or preparation.specialization is not PentestSpecialization.SQL_INJECTION
        or definition.capability_id != _EXECUTABLE_SPECIALIST_CAPABILITY_ID
        or definition.capability_version != _EXECUTABLE_SPECIALIST_CAPABILITY_VERSION
        or definition.capability_id != action.capability.capability_id
        or definition.capability_version != action.capability.capability_version
        or definition.capability_digest != action.capability.definition_digest
        or definition.tool.tool_id != _EXECUTABLE_SPECIALIST_TOOL_ID
        or definition.tool.tool_id != action.request.tool_id
        or definition.tool.tool_version != _EXECUTABLE_SPECIALIST_TOOL_VERSION
        or definition.risk_tier is not ToolRiskTier.T2
        or definition.side_effect_class.value != "read-only"
        or not definition.approval_required
        or definition.cleanup_required
    ):
        raise AgenticCoordinationError("SQL specialist v2 action changed after planning")
    return definition.request_unit_cost


def _require_specialist_permit_authorization(
    *,
    plan: AgenticSpecialistDispatchPlanAuditEntry,
    authorization: ActionApprovalAuthorization,
    newly_consumed: bool,
) -> tuple[ActionPermit, ActionApprovalConsumptionReceipt]:
    if type(authorization) is not ActionApprovalAuthorization:
        raise AgenticCoordinationError(
            "specialist Permit callback requires exact authorization evidence"
        )
    try:
        canonical = ActionApprovalAuthorization.model_validate(
            authorization.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise AgenticCoordinationError(
            "specialist Permit authorization failed strict reload"
        ) from exc
    permit = canonical.action.permit
    receipt = canonical.receipt
    if (
        canonical != authorization
        or canonical.approval != plan.approval_envelope
        or canonical.action.newly_consumed is not newly_consumed
        or permit.permit_id != plan.expected_action_permit_id
        or receipt.approval != plan.approval_envelope
        or receipt.action_permit != permit
        or permit.request_id != plan.prepared_action.request.request_id
        or permit.request_digest != plan.prepared_action.request_digest
        or permit.normalized_parameters_digest != plan.prepared_action.normalized_parameters_digest
        or permit.capability != plan.prepared_action.capability
        or permit.target_digest != plan.target_digest
        or permit.snapshot.snapshot_id != plan.graph_snapshot_id
        or permit.snapshot.snapshot_digest != plan.graph_snapshot_digest
    ):
        raise AgenticCoordinationError(
            "specialist Permit authorization differs from the sealed dispatch plan"
        )
    return permit, receipt


def _sql_specialist_v2_authority_set_identity(
    activation: WebSQLSpecialistCapabilityActivationV2,
) -> tuple[str, str]:
    from pajin.capabilities.agentic_web_specialist_v2 import (
        _WEB_SQL_SPECIALIST_V2_BUNDLE_CAPABILITY_IMPLEMENTATION,
    )

    _require_sql_specialist_v2_activation_implementations(activation)
    capability = _WEB_SQL_SPECIALIST_V2_BUNDLE_CAPABILITY_IMPLEMENTATION(activation.bundle)
    if capability.capability != activation.activation_set.binding.capability.capability:
        raise AgenticCoordinationError(
            "SQL specialist v2 code-backed Capability differs from its activation"
        )
    return capability.authority_set_id, capability.authority_set_digest


def _sql_specialist_v2_scheduler_task_name(
    context: _SQLSpecialistV2ClaimedRuntimeContext,
) -> str:
    task_name = context.owner_task.get_name()
    if type(task_name) is not str:
        raise AgenticCoordinationError("SQL specialist v2 scheduler Task name is invalid")
    digest = discovery_digest(
        "pajin.agentic.sql-specialist-v2-scheduler-task/v1",
        {
            "taskName": task_name,
            "taskTokenDigest": context.plan.scheduler_task_token_digest,
            "planDigest": context.plan.plan_digest,
        },
    )
    return f"scheduler-task:{digest}"


def _sql_specialist_v2_job_dispatch_binding(
    context: _SQLSpecialistV2ClaimedRuntimeContext,
    deployment: _SpecialistGatewayDeploymentClaimObservationV2,
    *,
    store_id: str,
    coordination_binding_digest: str,
) -> tuple[str, str]:
    digest = discovery_digest(
        "pajin.agentic.sql-specialist-v2-job-dispatch-binding/v1",
        {
            "storeId": store_id,
            "coordinationBindingDigest": coordination_binding_digest,
            "planId": context.plan.plan_id,
            "planDigest": context.plan.plan_digest,
            "schedulerTaskTokenDigest": context.plan.scheduler_task_token_digest,
            "runtimeCapsuleTokenDigest": context.runtime_capsule_token_digest,
            "gatewayDeploymentId": deployment.snapshot.deployment_id,
            "gatewayDeploymentDigest": deployment.snapshot.deployment_digest,
        },
    )
    return f"agentic-specialist-dispatch-binding_{digest}", digest


def _sql_specialist_v2_attempt_timestamp(value: datetime) -> str:
    normalized = _SQL_SPECIALIST_V2_UTC_IMPLEMENTATION(
        value,
        label="SQL specialist v2 JobAttempt timestamp",
    )
    return normalized.isoformat().replace("+00:00", "Z")


def _require_sql_specialist_v2_job_attempt_publication(
    store: AgenticCoordinationStore,
    context: _SQLSpecialistV2ClaimedRuntimeContext,
    *,
    graph_resolver: CurrentGraphHeadResolver,
    graph_head: VerifiedCurrentGraphHead,
) -> None:
    if (
        type(store) is not AgenticCoordinationStore
        or type(context) is not _SQLSpecialistV2ClaimedRuntimeContext
        or context.owner_task is not asyncio.current_task()
        or context.owner_task.done()
        or context.database is not store._database
    ):
        raise AgenticCoordinationError("SQL specialist v2 JobAttempt publication authority changed")
    current_lineage = _SQL_SPECIALIST_V2_LINEAGE_OBSERVATION_IMPLEMENTATION(
        context.capability_ledger,
        context.capability_grant.grant_id,
    )
    current_grant, current_remaining, _ = current_lineage[0]
    current_lineage_digest = _SPECIALIST_CAPABILITY_LINEAGE_STATE_DIGEST_IMPLEMENTATION(
        current_lineage
    )
    publication_at = _SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(store)
    permit = context.started.permit
    if (
        current_grant != context.capability_grant
        or current_remaining != 0
        or any(revoked for _, _, revoked in current_lineage)
        or current_lineage_digest != context.grant_lineage_state_digest
        or not context.claimed_at <= publication_at
        or not publication_at
        < min(
            context.capability_grant.expires_at,
            permit.expires_at,
            context.approval_envelope.expires_at,
        )
    ):
        raise AgenticCoordinationError(
            "SQL specialist v2 JobAttempt publication authority is no longer active"
        )
    snapshot = _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION(
        store,
        graph_resolver,
        graph_head,
    )
    if snapshot != context.snapshot:
        raise AgenticCoordinationError(
            "SQL specialist v2 Graph changed before JobAttempt publication"
        )
    graph_resolver.require_runtime_store(context.graph_store, graph_head)


def _build_sql_specialist_v2_job_attempt(
    context: _SQLSpecialistV2ClaimedRuntimeContext,
    *,
    store_id: str,
    coordination_binding_digest: str,
    database_identity_digest: str,
    deployment_digest: str,
    control_plane_run_id: str,
    store_identity_token: object,
    gateway_deployment: VerifiedSpecialistGatewayDeploymentV2,
    gateway_claim: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
    gateway_observation: _SpecialistGatewayDeploymentClaimObservationV2,
    gateway_claim_owner_token: object,
) -> AgenticSpecialistJobAttempt:
    plan = context.plan
    execution = context.execution
    preparation = context.preparation
    action = context.prepared_action
    permit = context.started.permit
    approval_receipt = context.started.approval_receipt
    grant_receipt = context.started.grant_consumption_receipt
    approval = context.approval_envelope
    authority_set_id, authority_set_digest = (
        _SQL_SPECIALIST_V2_AUTHORITY_SET_IDENTITY_IMPLEMENTATION(context.activation)
    )
    if (
        action.capability.definition_digest
        != context.activation.activation_set.binding.capability.capability.capability_digest
        or action.release != context.activation.activation_set.binding.release
    ):
        raise AgenticCoordinationError(
            "SQL specialist v2 action differs from its current code-backed activation"
        )
    scheduler_task_name = _SQL_SPECIALIST_V2_SCHEDULER_TASK_NAME_IMPLEMENTATION(context)
    dispatch_binding_id, dispatch_binding_digest = (
        _SQL_SPECIALIST_V2_JOB_DISPATCH_BINDING_IMPLEMENTATION(
            context,
            gateway_observation,
            store_id=store_id,
            coordination_binding_digest=coordination_binding_digest,
        )
    )
    worker_job = _VERIFIED_DEPLOYMENT_WORKER_JOB_IMPLEMENTATION(
        gateway_deployment,
        gateway_claim,
        claim_authority=_DEPLOYMENT_CLAIM_AUTHORITY,
        store_identity_token=store_identity_token,
        owner_task=context.owner_task,
        owner_token=gateway_claim_owner_token,
        plan_id=plan.plan_id,
        plan_digest=plan.plan_digest,
        request_id=action.request.request_id,
        request_digest=action.request_digest,
        runtime_capsule_token_digest=context.runtime_capsule_token_digest,
        dispatch_binding_id=dispatch_binding_id,
        dispatch_binding_digest=dispatch_binding_digest,
    )
    if type(worker_job) is not SpecialistWorkerJobRefV2:
        raise AgenticCoordinationError("SQL specialist v2 WorkerJob identity is invalid")
    snapshot = gateway_observation.snapshot
    inventory = gateway_observation.execution_inventory
    values: dict[str, object] = {
        "state": AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND,
        "storeId": store_id,
        "coordinationBindingDigest": coordination_binding_digest,
        "databaseIdentityDigest": database_identity_digest,
        "deploymentDigest": deployment_digest,
        "controlPlaneRunId": control_plane_run_id,
        "campaignId": plan.campaign_id,
        "campaignManifestDigest": plan.campaign_manifest_digest,
        "planId": plan.plan_id,
        "planDigest": plan.plan_digest,
        "planStateDigest": plan.state_digest,
        "reservationId": execution.reservation_id,
        "reservationDigest": execution.reservation_digest,
        "reservationStateDigest": execution.state_digest,
        "commandId": execution.command_id,
        "commandDigest": execution.command_digest,
        "targetAgentId": execution.target_agent_id,
        "taskId": execution.task_id,
        "schedulerTaskName": scheduler_task_name,
        "schedulerTaskTokenDigest": plan.scheduler_task_token_digest,
        "runtimeCapsuleTokenDigest": context.runtime_capsule_token_digest,
        "specialization": execution.specialization,
        "dispatchBindingId": dispatch_binding_id,
        "dispatchBindingDigest": dispatch_binding_digest,
        "dispatchVerification": None,
        "dispatchVerificationDigest": None,
        "dispatchEventDigest": None,
        "graphSnapshotId": context.snapshot.snapshot_id,
        "graphSnapshotDigest": context.snapshot.snapshot_digest,
        "preparationId": preparation.preparation_id,
        "preparationDigest": preparation.preparation_digest,
        "profileRegistryDigest": preparation.profile_registry_digest,
        "profileId": preparation.profile.profile_id,
        "profileVersion": preparation.profile.profile_version,
        "profileDigest": preparation.profile.profile_digest,
        "executorCatalogDigest": preparation.executor_catalog_digest,
        "executorId": preparation.executor_id,
        "executorVersion": preparation.executor_version,
        "executorDigest": preparation.executor_digest,
        "preparedActionDigest": plan.prepared_action_digest,
        "activationSetDigest": action.activation_set_digest,
        "releaseId": action.release.release_id,
        "releaseDigest": action.release.release_digest,
        "capabilityId": action.capability.capability_id,
        "capabilityVersion": action.capability.capability_version,
        "capabilityDefinitionDigest": action.capability.definition_digest,
        "capabilityDigest": action.capability.capability_digest,
        "capabilityAuthoritySetId": authority_set_id,
        "capabilityAuthoritySetDigest": authority_set_digest,
        "toolId": action.capability.tool_id,
        "toolVersion": action.capability.tool_version,
        "toolDigest": action.capability.tool_digest,
        "requestId": action.request.request_id,
        "requestDigest": action.request_digest,
        "capabilityGrantId": context.capability_grant.grant_id,
        "capabilityGrantDigest": capability_grant_digest(context.capability_grant),
        "grantLineageStateDigest": context.grant_lineage_state_digest,
        "capabilityGrantExpiresAt": _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION(
            context.capability_grant.expires_at
        ),
        "grantConsumptionReceiptId": grant_receipt.receipt_id,
        "grantConsumptionReceiptDigest": grant_receipt.receipt_digest,
        "actionPermitId": permit.permit_id,
        "actionPermitDigest": permit.permit_digest,
        "actionPermitExpiresAt": _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION(
            permit.expires_at
        ),
        "approvalId": approval.approval_id,
        "approvalDigest": approval.approval_digest,
        "approvalExpiresAt": _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION(
            approval.expires_at
        ),
        "approvalConsumptionReceiptId": approval_receipt.receipt_id,
        "approvalConsumptionReceiptDigest": approval_receipt.receipt_digest,
        "dispatchId": permit.dispatch_id,
        "targetId": plan.target_id,
        "targetDigest": plan.target_digest,
        "gatewayId": snapshot.gateway_id,
        "gatewayVersion": snapshot.gateway_version,
        "gatewayDigest": snapshot.gateway_digest,
        "executionInventoryId": inventory.inventory_id,
        "executionInventoryDigest": inventory.inventory_digest,
        "workerBackendId": snapshot.worker_backend_id,
        "workerBackendVersion": snapshot.worker_backend_version,
        "workerBackendDigest": snapshot.worker_backend_digest,
        "workerJobId": worker_job.worker_job_id,
        "workerJobDigest": worker_job.worker_job_digest,
        "workerCommandDigest": snapshot.worker_command_digest,
        "workerCompilerId": snapshot.worker_compiler_id,
        "workerCompilerVersion": snapshot.worker_compiler_version,
        "workerCompilerDigest": snapshot.worker_compiler_digest,
        "workerImageReference": snapshot.worker_image_reference,
        "workerImageDigest": snapshot.worker_image_digest,
        "workerVerifierId": snapshot.worker_verifier_id,
        "workerVerifierVersion": snapshot.worker_verifier_version,
        "workerVerifierDigest": snapshot.worker_verifier_digest,
        "workerVerificationKeyId": snapshot.worker_verification_key_id,
        "workerVerificationKeyDigest": snapshot.worker_verification_key_digest,
        "claimedAt": _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION(context.claimed_at),
        "backendDispatchStartedAt": None,
    }
    values["claimVerification"] = _SPECIALIST_CLAIM_VERIFICATION_BUILD_IMPLEMENTATION(values)
    return AgenticSpecialistJobAttempt.model_validate(values)


_SQL_SPECIALIST_V2_AUTHORITY_SET_IDENTITY_IMPLEMENTATION = _sql_specialist_v2_authority_set_identity
_SQL_SPECIALIST_V2_SCHEDULER_TASK_NAME_IMPLEMENTATION = _sql_specialist_v2_scheduler_task_name
_SQL_SPECIALIST_V2_JOB_DISPATCH_BINDING_IMPLEMENTATION = _sql_specialist_v2_job_dispatch_binding
_SQL_SPECIALIST_V2_UTC_IMPLEMENTATION = _utc
_SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION = _sql_specialist_v2_attempt_timestamp
_SQL_SPECIALIST_V2_LINEAGE_OBSERVATION_IMPLEMENTATION = _specialist_capability_lineage_observation
_SQL_SPECIALIST_V2_LEDGER_RUNTIME_IDENTITY_IMPLEMENTATION = _capability_ledger_runtime_identity
_SQL_SPECIALIST_V2_JOB_ATTEMPT_PUBLICATION_IMPLEMENTATION = (
    _require_sql_specialist_v2_job_attempt_publication
)
_SQL_SPECIALIST_V2_JOB_ATTEMPT_BUILD_IMPLEMENTATION = _build_sql_specialist_v2_job_attempt


class AgenticCoordinationStore:
    """Durable, single-host authority for one exact agentic deployment binding."""

    def __init__(
        self,
        path: Path,
        *,
        binding: AgenticCoordinationBinding,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
        specialist_graph_store: SQLiteGraphStore | None = None,
        specialist_capability_ledger: CapabilityLedger | None = None,
        specialist_approval_keys: Iterable[WebAssessmentVerificationKey] | None = None,
        specialist_approval_clock: Callable[[], datetime] | None = None,
        specialist_runtime_generation: AgenticSpecialistRuntimeGeneration = (
            AgenticSpecialistRuntimeGeneration.LEGACY_V1
        ),
        clock: Callable[[], datetime] | None = None,
        store_id_factory: Callable[[], str] | None = None,
        allow_create: bool = True,
        expected_store_id: str | None = None,
    ) -> None:
        _require_linux_descriptor_backend()
        if type(specialist_runtime_generation) is not AgenticSpecialistRuntimeGeneration:
            raise AgenticCoordinationError(
                "coordination Store specialist runtime generation is invalid"
            )
        if expected_store_id is not None:
            import re

            if (
                type(expected_store_id) is not str
                or re.fullmatch(_STORE_ID_PATTERN, expected_store_id) is None
            ):
                raise AgenticCoordinationError("expected coordination store ID is invalid")
        self.path = Path(os.path.abspath(path))
        self.binding = AgenticCoordinationBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        )
        self._clock = clock or (lambda: datetime.now(UTC))
        self._store_id_factory = store_id_factory or (lambda: f"agentic-store:{uuid.uuid4().hex}")
        self._authority = object()
        self.__specialist_runtime_generation = specialist_runtime_generation
        if type(graph_resolver) is not CurrentGraphHeadResolver:
            raise AgenticCoordinationError(
                "coordination store requires its concrete deployment Graph resolver"
            )
        self._graph_resolver = graph_resolver
        snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
        specialist_values = (
            specialist_graph_store,
            specialist_capability_ledger,
            specialist_approval_keys,
        )
        if any(value is not None for value in specialist_values) and not all(
            value is not None for value in specialist_values
        ):
            raise AgenticCoordinationError(
                "specialist deployment Graph, Ledger, and approval keyring "
                "must be configured together"
            )
        self.__specialist_deployment: _AgenticSpecialistPermitDeployment | None = None
        self.__specialist_deployment_runtime_identity: (
            _AgenticSpecialistDeploymentRuntimeIdentity | None
        ) = None
        self.__specialist_configured_runtime_identity: (
            _AgenticSpecialistConfiguredRuntimeIdentity | None
        ) = None
        self.__specialist_configured_runtime_lock = threading.RLock()
        self.__specialist_binding_operation_lock = threading.RLock()
        self.__specialist_dispatch_lifecycle_lock = threading.RLock()
        self.__specialist_store_close_started = False
        self.__issued_specialist_dispatch_lock = threading.RLock()
        self.__specialist_dispatch_binding_registries: dict[
            object,
            weakref.ReferenceType[object],
        ] = {}
        self.__issued_specialist_dispatch_started: dict[
            str,
            tuple[
                VerifiedPlannedSpecialistDispatchStarted,
                _AgenticSpecialistDispatchRuntimeCapsule,
                asyncio.Task[object],
                object,
            ],
        ] = {}
        self.__issued_specialist_dispatch_owner_tasks: set[asyncio.Task[object]] = set()
        self.__issued_sql_specialist_v2_plans: dict[
            str,
            tuple[
                VerifiedSQLSpecialistDispatchPlanV2,
                asyncio.Task[object],
                object,
                object,
            ],
        ] = {}
        self.__issued_sql_specialist_v2_plan_owner_tasks: set[asyncio.Task[object]] = set()
        self.__issued_sql_specialist_v2_dispatch_started: dict[
            str,
            tuple[
                VerifiedPlannedSQLSpecialistDispatchStartedV2,
                _AgenticSQLSpecialistDispatchRuntimeCapsuleV2,
                asyncio.Task[object],
                object,
                object,
            ],
        ] = {}
        self.__transferred_sql_specialist_v2_dispatch_capsules: dict[
            str,
            tuple[
                _AgenticSQLSpecialistDispatchRuntimeCapsuleV2,
                VerifiedPlannedSQLSpecialistDispatchStartedV2,
                asyncio.Task[object],
                object,
                object,
            ],
        ] = {}
        self.__issued_sql_specialist_v2_dispatch_owner_tasks: set[asyncio.Task[object]] = set()
        self.__active_sql_specialist_v2_dispatch_operations: dict[
            object,
            tuple[asyncio.Task[object], _LinuxPinnedCoordinationDatabase],
        ] = {}
        self.__issued_sql_specialist_v2_job_attempt_claims: dict[
            str,
            _IssuedSQLSpecialistV2JobAttemptClaim,
        ] = {}
        self.__issued_sql_specialist_v2_job_attempt_owner_tasks: set[asyncio.Task[object]] = set()
        if specialist_graph_store is not None:
            assert specialist_capability_ledger is not None
            assert specialist_approval_keys is not None
            graph_resolver.require_runtime_store(specialist_graph_store, graph_head)
            self.__specialist_deployment = _AgenticSpecialistPermitDeployment(
                campaign_id=self.binding.campaign_id,
                graph_store=specialist_graph_store,
                capability_ledger=specialist_capability_ledger,
                approval_keys=specialist_approval_keys,
                approval_clock=specialist_approval_clock or self._clock,
                runtime_generation=specialist_runtime_generation,
            )
            self.__specialist_deployment_runtime_identity = (
                _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(
                    self.__specialist_deployment
                )
            )
        elif specialist_approval_clock is not None:
            raise AgenticCoordinationError(
                "specialist approval clock requires a configured deployment trust root"
            )
        self.__specialist_deployment_identity = self.__specialist_deployment
        self._database = _LinuxPinnedCoordinationDatabase.open(
            self.path,
            allow_create=allow_create,
        )
        self.__database_identity = self._database
        try:
            if self._database.existed and expected_store_id is None:
                raise AgenticCoordinationError(
                    "reopening coordination requires an independent expected store ID"
                )
            if not self._database.existed and expected_store_id is not None:
                raise AgenticCoordinationError(
                    "new coordination store cannot reuse an expected store ID"
                )
            _initialize(
                self._database,
                binding=self.binding,
                specialist_runtime_generation=specialist_runtime_generation,
                store_id_factory=self._store_id_factory,
                allow_create=allow_create,
                expected_store_id=expected_store_id,
            )
            with _read_transaction(self._database) as connection:
                _validate_schema(
                    connection,
                    binding=self.binding,
                    expected_specialist_runtime_generation=(self.__specialist_runtime_generation),
                    expected_store_id=expected_store_id,
                )
                self.store_id = _metadata(connection)["store_id"]
                self._validate_connection(connection)
                if (
                    connection.execute(
                        "SELECT 1 FROM agentic_checkpoint_head WHERE slot = 1"
                    ).fetchone()
                    is not None
                ):
                    snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                    self._validate_durable_history(connection, snapshot)
                    self._current_graph_snapshot(graph_resolver, graph_head)
        except AgenticCoordinationError:
            _LINUX_PINNED_COORDINATION_DATABASE_CLOSE_IMPLEMENTATION(self._database)
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            _LINUX_PINNED_COORDINATION_DATABASE_CLOSE_IMPLEMENTATION(self._database)
            raise AgenticCoordinationError(
                "coordination store reopen validation failed closed"
            ) from exc

    def close(self) -> None:
        """Zeroize process-local C3C authority, then release pinned descriptors."""

        cleanup_errors: list[BaseException] = []
        database = self._database
        if (
            type(database) is not _LinuxPinnedCoordinationDatabase
            or database is not self.__database_identity
        ):
            raise AgenticCoordinationError(
                "coordination Store database identity changed before close"
            )
        with self.__specialist_dispatch_lifecycle_lock:
            if self.__active_sql_specialist_v2_dispatch_operations:
                raise AgenticCoordinationError(
                    "coordination Store has an active SQL specialist v2 Permit dispatch"
                )
            self.__specialist_store_close_started = True
        with self.__specialist_binding_operation_lock:
            if self._database is not database:
                raise AgenticCoordinationError(
                    "coordination Store database identity changed before close"
                )
            with self.__issued_specialist_dispatch_lock:
                self.__issued_specialist_dispatch_started.clear()
                for owner_task in self.__issued_specialist_dispatch_owner_tasks:
                    with suppress(RuntimeError):
                        owner_task.get_loop().call_soon_threadsafe(
                            owner_task.remove_done_callback,
                            self._retire_issued_specialist_dispatch_started,
                        )
                self.__issued_specialist_dispatch_owner_tasks.clear()
                for (
                    plan,
                    _owner_task,
                    owner_token,
                    _issued_database,
                ) in self.__issued_sql_specialist_v2_plans.values():
                    with suppress(AgenticCoordinationError):
                        _SQL_SPECIALIST_V2_PLAN_RETIRE_IMPLEMENTATION(
                            plan,
                            self._authority,
                            owner_token,
                        )
                self.__issued_sql_specialist_v2_plans.clear()
                for owner_task in self.__issued_sql_specialist_v2_plan_owner_tasks:
                    with suppress(RuntimeError):
                        owner_task.get_loop().call_soon_threadsafe(
                            owner_task.remove_done_callback,
                            _SQL_SPECIALIST_V2_RETIRE_PLAN_CALLBACK_FACTORY_IMPLEMENTATION(self),
                        )
                self.__issued_sql_specialist_v2_plan_owner_tasks.clear()
                for (
                    _started,
                    capsule,
                    _owner_task,
                    owner_token,
                    _issued_database,
                ) in self.__issued_sql_specialist_v2_dispatch_started.values():
                    with suppress(AgenticCoordinationError):
                        _SQL_SPECIALIST_V2_CAPSULE_RETIRE_IMPLEMENTATION(
                            capsule,
                            owner_token,
                        )
                self.__issued_sql_specialist_v2_dispatch_started.clear()
                for (
                    capsule,
                    _started,
                    _owner_task,
                    owner_token,
                    _issued_database,
                ) in self.__transferred_sql_specialist_v2_dispatch_capsules.values():
                    with suppress(AgenticCoordinationError):
                        _SQL_SPECIALIST_V2_CAPSULE_RETIRE_IMPLEMENTATION(
                            capsule,
                            owner_token,
                        )
                self.__transferred_sql_specialist_v2_dispatch_capsules.clear()
                for owner_task in self.__issued_sql_specialist_v2_dispatch_owner_tasks:
                    with suppress(RuntimeError):
                        owner_task.get_loop().call_soon_threadsafe(
                            owner_task.remove_done_callback,
                            _SQL_SPECIALIST_V2_RETIRE_CALLBACK_FACTORY_IMPLEMENTATION(self),
                        )
                self.__issued_sql_specialist_v2_dispatch_owner_tasks.clear()
                for issued in self.__issued_sql_specialist_v2_job_attempt_claims.values():
                    cleanup_errors.extend(
                        _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_ENTRY_IMPLEMENTATION(
                            self,
                            issued,
                            abandonment_reason="store-close",
                        )
                    )
                self.__issued_sql_specialist_v2_job_attempt_claims.clear()
                for owner_task in self.__issued_sql_specialist_v2_job_attempt_owner_tasks:
                    with suppress(RuntimeError):
                        owner_task.get_loop().call_soon_threadsafe(
                            owner_task.remove_done_callback,
                            _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CALLBACK_FACTORY_IMPLEMENTATION(
                                self
                            ),
                        )
                self.__issued_sql_specialist_v2_job_attempt_owner_tasks.clear()
            try:
                _SQL_SPECIALIST_V2_ABANDON_BINDING_REGISTRIES_IMPLEMENTATION(self)
            except BaseException as exc:
                cleanup_errors.append(exc)
            try:
                _LINUX_PINNED_COORDINATION_DATABASE_CLOSE_IMPLEMENTATION(database)
            except BaseException as exc:
                cleanup_errors.append(exc)
        if cleanup_errors:
            raise AgenticCoordinationError(
                "coordination Store close completed with cleanup failures"
            ) from cleanup_errors[0]

    def _register_specialist_dispatch_binding_registry(self, registry: object) -> object:
        """Register one exact C3C registry for Store-wide shutdown zeroization."""

        from pajin.agentic.specialist_dispatch import (
            _REGISTRY_STORE_ABANDON_IMPLEMENTATION,
            AgenticSpecialistDispatchBindingRegistry,
        )

        if (
            type(self) is not AgenticCoordinationStore
            or type(registry) is not AgenticSpecialistDispatchBindingRegistry
            or AgenticSpecialistDispatchBindingRegistry._abandon_from_store
            is not _REGISTRY_STORE_ABANDON_IMPLEMENTATION
        ):
            raise AgenticCoordinationError(
                "specialist dispatch binding registry implementation changed"
            )
        with self.__specialist_binding_operation_lock:
            database = self._database
            if (
                type(database) is not _LinuxPinnedCoordinationDatabase
                or database is not self.__database_identity
            ):
                raise AgenticCoordinationError("specialist dispatch binding Store database changed")
            database.require_open()
            for registration, registry_ref in tuple(
                self.__specialist_dispatch_binding_registries.items()
            ):
                if type(registry_ref) is not weakref.ReferenceType:
                    raise AgenticCoordinationError(
                        "specialist dispatch binding registry reference changed"
                    )
                if registry_ref() is None:
                    del self.__specialist_dispatch_binding_registries[registration]
            registration = object()
            self.__specialist_dispatch_binding_registries[registration] = weakref.ref(registry)
            return registration

    def _abandon_specialist_dispatch_binding_registries(self) -> None:
        """Destroy every transferred C3C capsule before the Store closes."""

        if type(self) is not AgenticCoordinationStore:
            raise AgenticCoordinationError(
                "specialist dispatch binding abandon requires its exact Store"
            )
        registrations = self.__specialist_dispatch_binding_registries
        try:
            if registrations:
                from pajin.agentic.specialist_dispatch import (
                    _REGISTRY_STORE_ABANDON_IMPLEMENTATION,
                    AgenticSpecialistDispatchBindingRegistry,
                )

                if (
                    AgenticSpecialistDispatchBindingRegistry._abandon_from_store
                    is not _REGISTRY_STORE_ABANDON_IMPLEMENTATION
                ):
                    raise AgenticCoordinationError(
                        "specialist dispatch binding registry implementation changed"
                    )
                abandon_error: Exception | None = None
                for registration, registry_ref in tuple(registrations.items()):
                    try:
                        if type(registry_ref) is not weakref.ReferenceType:
                            raise AgenticCoordinationError(
                                "specialist dispatch binding registry reference changed"
                            )
                        registry = registry_ref()
                        if registry is None:
                            continue
                        if type(registry) is not AgenticSpecialistDispatchBindingRegistry:
                            raise AgenticCoordinationError(
                                "specialist dispatch binding registry identity changed"
                            )
                        _REGISTRY_STORE_ABANDON_IMPLEMENTATION(
                            registry,
                            self,
                            registration,
                        )
                    except Exception as exc:
                        if abandon_error is None:
                            abandon_error = exc
                if abandon_error is not None:
                    raise AgenticCoordinationError(
                        "specialist dispatch binding registry abandon failed closed"
                    ) from abandon_error
        finally:
            registrations.clear()

    @contextmanager
    def _specialist_dispatch_binding_operation(
        self,
        expected_database: object,
    ) -> Iterator[None]:
        """Serialize process-local C3C transitions with Store shutdown."""

        if type(self) is not AgenticCoordinationStore:
            raise AgenticCoordinationError(
                "specialist dispatch binding operation requires its exact Store"
            )
        with self.__specialist_binding_operation_lock:
            database = self._database
            if (
                type(database) is not _LinuxPinnedCoordinationDatabase
                or database is not expected_database
            ):
                raise AgenticCoordinationError("specialist dispatch binding Store database changed")
            database.require_open()
            yield
            if self._database is not database:
                raise AgenticCoordinationError("specialist dispatch binding Store database changed")
            database.require_open()

    def _begin_sql_specialist_v2_dispatch_operation(
        self,
    ) -> tuple[object, asyncio.Task[object]]:
        """Acquire a non-blocking lifecycle lease that makes Store close fail closed."""

        if type(self) is not AgenticCoordinationStore:
            raise AgenticCoordinationError(
                "SQL specialist v2 dispatch requires its exact coordination Store"
            )
        owner_task = asyncio.current_task()
        if owner_task is None or type(owner_task) is not asyncio.Task or owner_task.done():
            raise AgenticCoordinationError(
                "SQL specialist v2 dispatch requires an active scheduler Task"
            )
        owner_task = cast(asyncio.Task[object], owner_task)
        token = object()
        with self.__specialist_dispatch_lifecycle_lock:
            if self.__specialist_store_close_started:
                raise AgenticCoordinationError(
                    "SQL specialist v2 dispatch cannot begin after Store close"
                )
            database = self._database
            if (
                type(database) is not _LinuxPinnedCoordinationDatabase
                or database is not self.__database_identity
            ):
                raise AgenticCoordinationError("SQL specialist v2 dispatch Store database changed")
            database.require_open()
            self.__active_sql_specialist_v2_dispatch_operations[token] = (
                owner_task,
                database,
            )
        return token, owner_task

    def _require_sql_specialist_v2_dispatch_operation(
        self,
        token: object,
        owner_task: asyncio.Task[object],
    ) -> None:
        with self.__specialist_dispatch_lifecycle_lock:
            database = self._database
            issued = self.__active_sql_specialist_v2_dispatch_operations.get(token)
            if (
                issued is None
                or issued[0] is not owner_task
                or issued[1] is not database
                or owner_task is not asyncio.current_task()
                or owner_task.done()
                or type(database) is not _LinuxPinnedCoordinationDatabase
                or database is not self.__database_identity
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 dispatch lifecycle lease is foreign or retired"
                )
            database.require_open()

    def _release_sql_specialist_v2_dispatch_operation(
        self,
        token: object,
        owner_task: asyncio.Task[object],
    ) -> None:
        with self.__specialist_dispatch_lifecycle_lock:
            issued = self.__active_sql_specialist_v2_dispatch_operations.get(token)
            if (
                issued is None
                or issued[0] is not owner_task
                or issued[1] is not self._database
                or owner_task is not asyncio.current_task()
                or owner_task.done()
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 dispatch lifecycle lease is foreign or retired"
                )
            del self.__active_sql_specialist_v2_dispatch_operations[token]

    def __enter__(self) -> Self:
        self._database.require_open()
        return self

    def __exit__(self, *_args: object) -> None:
        _SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION(self)

    def __del__(self) -> None:
        database = getattr(self, "_database", None)
        if database is not None:
            with suppress(Exception):
                database.close()

    def _now(self) -> datetime:
        try:
            return _utc(self._clock(), label="coordination clock")
        except (TypeError, ValueError) as exc:
            raise AgenticCoordinationError("coordination clock is invalid") from exc

    @property
    def specialist_runtime_generation(self) -> AgenticSpecialistRuntimeGeneration:
        return self.__specialist_runtime_generation

    def _require_specialist_deployment(
        self,
        generation: AgenticSpecialistRuntimeGeneration = (
            AgenticSpecialistRuntimeGeneration.LEGACY_V1
        ),
    ) -> _AgenticSpecialistPermitDeployment:
        with self.__specialist_configured_runtime_lock:
            return _SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_LOCKED_IMPLEMENTATION(
                self,
                generation,
            )

    def _require_specialist_deployment_locked(
        self,
        generation: AgenticSpecialistRuntimeGeneration = (
            AgenticSpecialistRuntimeGeneration.LEGACY_V1
        ),
    ) -> _AgenticSpecialistPermitDeployment:
        deployment = self.__specialist_deployment
        runtime_identity = self.__specialist_deployment_runtime_identity
        if (
            type(generation) is not AgenticSpecialistRuntimeGeneration
            or self.__specialist_runtime_generation is not generation
            or deployment is None
            or deployment is not self.__specialist_deployment_identity
            or runtime_identity is None
            or runtime_identity.runtime_generation is not generation
            or _AgenticSpecialistPermitDeployment.runtime_identity
            is not _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION
            or _AgenticSpecialistPermitDeployment.require_runtime
            is not _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION
            or _AgenticSpecialistPermitDeployment.configure_sql_specialist_v2_plan
            is not _AGENTIC_SPECIALIST_DEPLOYMENT_CONFIGURE_V2_IMPLEMENTATION
            or any(
                name in getattr(deployment, "__dict__", {})
                for name in ("require_runtime", "configure_sql_specialist_v2_plan")
            )
        ):
            raise AgenticCoordinationError(
                "specialist Permit runtime is not pinned by this deployment"
            )
        _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
            deployment,
            expected_identity=runtime_identity,
        )
        configured_identity = self.__specialist_configured_runtime_identity
        observed_configured = _AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION(
            deployment
        )
        if configured_identity is None:
            if observed_configured is not None:
                raise AgenticCoordinationError(
                    "specialist Permit writer is not pinned by this deployment"
                )
        else:
            _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
                deployment,
                expected_identity=runtime_identity,
                expected_configured_identity=configured_identity,
            )
        return deployment

    def _pin_specialist_configured_runtime(
        self,
        deployment: _AgenticSpecialistPermitDeployment,
    ) -> _AgenticSpecialistConfiguredRuntimeIdentity:
        if (
            deployment is not self.__specialist_deployment_identity
            or _AgenticSpecialistPermitDeployment.configured_runtime_identity
            is not _AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION
        ):
            raise AgenticCoordinationError(
                "specialist Permit writer is not pinned by this deployment"
            )
        observed = _AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION(deployment)
        if observed is None:
            raise AgenticCoordinationError("specialist Permit writer was not configured")
        if observed.runtime_generation is not self.__specialist_runtime_generation:
            raise AgenticCoordinationError("specialist Permit writer runtime generation changed")
        with self.__specialist_configured_runtime_lock:
            pinned = self.__specialist_configured_runtime_identity
            if pinned is None:
                self.__specialist_configured_runtime_identity = observed
                pinned = observed
            elif not _same_specialist_configured_runtime_identity(observed, pinned):
                raise AgenticCoordinationError(
                    "specialist deployment Graph writer authority changed"
                )
        _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
            deployment,
            expected_identity=self.__specialist_deployment_runtime_identity,
            expected_configured_identity=pinned,
        )
        return pinned

    def _validate_connection(self, connection: sqlite3.Connection) -> None:
        _validate_schema(
            connection,
            binding=self.binding,
            expected_specialist_runtime_generation=self.__specialist_runtime_generation,
            expected_store_id=self.store_id,
        )

    def _validate_durable_history(
        self,
        connection: sqlite3.Connection,
        snapshot: GraphSnapshot,
    ) -> tuple[DynamicSupervisorCheckpoint, ...]:
        chain = _validate_structural_history(
            connection,
            store_id=self.store_id,
            binding=self.binding,
        )
        _validate_invocation_history(
            connection,
            binding=self.binding,
            snapshot=snapshot,
            store_id=self.store_id,
            chain=chain,
        )
        _validate_semantic_history(
            connection,
            binding=self.binding,
            snapshot=snapshot,
            chain=chain,
        )
        return chain

    def initialize_head(
        self,
        checkpoint: DynamicSupervisorCheckpoint,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedAgenticDurableHead:
        """Publish the exact revision-zero checkpoint or return its exact retry."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            canonical = _canonical_checkpoint(checkpoint)
            self.binding.require_checkpoint(canonical)
            _require_initial_checkpoint_shape(canonical)
            if (
                canonical.checkpoint_id != self.binding.initial_checkpoint_id
                or canonical.checkpoint_digest != self.binding.initial_checkpoint_digest
            ):
                raise ValueError("initial durable checkpoint differs from deployment binding")
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                existing = connection.execute(
                    "SELECT checkpoint_digest FROM agentic_checkpoint_head WHERE slot = 1"
                ).fetchone()
                if existing is not None:
                    self._validate_durable_history(connection, snapshot)
                    durable = _checkpoint_by_digest(connection, _required_text(existing, 0))
                    if durable != canonical:
                        raise AgenticCoordinationError(
                            "durable checkpoint head was already initialized differently"
                        )
                    return self._head(durable)
                _insert_checkpoint(
                    connection,
                    canonical,
                    predecessor_digest=None,
                    recorded_at=self._now(),
                )
                connection.execute(
                    "INSERT INTO agentic_checkpoint_head(slot, checkpoint_digest, revision) "
                    "VALUES (1, ?, ?)",
                    (canonical.checkpoint_digest, canonical.revision),
                )
                self._validate_durable_history(connection, snapshot)
                return self._head(canonical)
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "agentic durable head initialization failed closed"
            ) from exc

    def current_head(
        self,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedAgenticDurableHead:
        """Return an opaque handle for the currently verified CAS head."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                current = _current_checkpoint(connection)
                self._current_graph_snapshot(graph_resolver, graph_head)
                return self._head(current)
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("agentic durable head verification failed") from exc

    def verified_checkpoint(
        self,
        current_head: VerifiedAgenticDurableHead,
        *,
        checkpoint_id: str,
        checkpoint_digest: str,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedAgenticCheckpoint:
        """Issue a non-authorizing handle for one checkpoint on the current chain."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            self._require_local_handle(current_head)
            _require_identifier(checkpoint_id, label="historical checkpoint ID")
            _require_digest(checkpoint_digest, label="historical checkpoint digest")
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                durable_head = _current_checkpoint(connection)
                if durable_head != current_head.checkpoint:
                    raise AgenticCoordinationError("durable head handle is stale")
                chain = self._validate_durable_history(connection, snapshot)
                matches = tuple(
                    item
                    for item in chain
                    if item.checkpoint_id == checkpoint_id
                    and item.checkpoint_digest == checkpoint_digest
                )
                if len(matches) != 1:
                    raise AgenticCoordinationError(
                        "historical checkpoint is not on the exact current chain"
                    )
                self._current_graph_snapshot(graph_resolver, graph_head)
                return VerifiedAgenticCheckpoint(
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                    current_head_digest=durable_head.checkpoint_digest,
                    checkpoint=matches[0],
                    _authority=self._authority,
                )
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "historical checkpoint verification failed closed"
            ) from exc

    def publish_cycle(
        self,
        expected_head: VerifiedAgenticDurableHead,
        cycle: DynamicSupervisorCycle,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticCyclePublication:
        """Atomically CAS the checkpoint and publish every newly issued command."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            canonical = DynamicSupervisorCycle.model_validate(
                cycle.model_dump(mode="json", by_alias=True)
            )
            self._require_local_handle(expected_head)
            self.binding.require_checkpoint(canonical.source_checkpoint)
            self.binding.require_checkpoint(canonical.resulting_checkpoint)
            if canonical.source_checkpoint != expected_head.checkpoint:
                raise ValueError("cycle source differs from expected durable head")
            if canonical.source_snapshot != snapshot:
                raise ValueError("cycle Graph Snapshot differs from verified current head")
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                existing = connection.execute(
                    "SELECT * FROM agentic_cycles WHERE cycle_id = ?",
                    (canonical.cycle_id,),
                ).fetchone()
                if existing is not None:
                    stored = _cycle_from_row(existing)
                    if stored != canonical:
                        raise AgenticCoordinationError("durable cycle identity was equivocated")
                    current = _current_checkpoint(connection)
                    if current != canonical.resulting_checkpoint:
                        raise AgenticCoordinationError(
                            "durable cycle retry is no longer the current head"
                        )
                    entries = _outbox_for_cycle(
                        connection,
                        canonical.cycle_digest,
                        store_id=self.store_id,
                        binding_digest=self.binding.binding_digest,
                    )
                    return AgenticCyclePublication(self._head(current), entries)

                current = _current_checkpoint(connection)
                if current != expected_head.checkpoint:
                    raise AgenticCoordinationError("durable checkpoint compare-and-swap was stale")
                self._current_graph_snapshot(graph_resolver, graph_head)
                _insert_checkpoint(
                    connection,
                    canonical.resulting_checkpoint,
                    predecessor_digest=current.checkpoint_digest,
                    recorded_at=self._now(),
                )
                connection.execute(
                    """
                    INSERT INTO agentic_cycles(
                        cycle_id, cycle_digest, source_checkpoint_digest,
                        resulting_checkpoint_digest, canonical_cycle, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        canonical.cycle_id,
                        canonical.cycle_digest,
                        canonical.source_checkpoint_digest,
                        canonical.resulting_checkpoint.checkpoint_digest,
                        sqlite3.Binary(_cycle_bytes(canonical)),
                        _format_timestamp(self._now()),
                    ),
                )
                _insert_cycle_outbox(
                    connection,
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                    cycle=canonical,
                )
                cursor = connection.execute(
                    """
                    UPDATE agentic_checkpoint_head
                    SET checkpoint_digest = ?, revision = ?
                    WHERE slot = 1 AND checkpoint_digest = ? AND revision = ?
                    """,
                    (
                        canonical.resulting_checkpoint.checkpoint_digest,
                        canonical.resulting_checkpoint.revision,
                        current.checkpoint_digest,
                        current.revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgenticCoordinationError(
                        "durable checkpoint compare-and-swap lost its atomic race"
                    )
                entries = _outbox_for_cycle(
                    connection,
                    canonical.cycle_digest,
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                )
                return AgenticCyclePublication(
                    self._head(canonical.resulting_checkpoint),
                    entries,
                )
        except AgenticCoordinationError:
            raise
        except sqlite3.IntegrityError as exc:
            raise AgenticCoordinationError(
                "agentic cycle publication conflicted with durable authority"
            ) from exc
        except (
            OSError,
            RuntimeError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError("agentic cycle publication failed closed") from exc

    def publish_event(
        self,
        expected_head: VerifiedAgenticDurableHead,
        event: AgentEvent,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticEventPublication:
        """Atomically persist one typed Agent Event and its resulting checkpoint."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            self._require_local_handle(expected_head)
            canonical_event = AgentEvent.model_validate(
                event.model_dump(mode="json", by_alias=True)
            )
            event_digest = _agent_event_digest(canonical_event)
            supervisor = _restore_supervisor_instance(
                binding=self.binding,
                checkpoint=expected_head.checkpoint,
                snapshot=snapshot,
            )
            resulting = supervisor.accept_event(canonical_event)
            if resulting.revision != expected_head.checkpoint.revision + 1:
                raise ValueError("Agent Event checkpoint revision differs")
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                existing = connection.execute(
                    "SELECT * FROM agentic_events WHERE event_id = ?",
                    (canonical_event.event_id,),
                ).fetchone()
                if existing is not None:
                    stored_event, stored_digest, source_digest, result_digest = _event_from_row(
                        existing
                    )
                    current = _current_checkpoint(connection)
                    if (
                        stored_event != canonical_event
                        or stored_digest != event_digest
                        or source_digest != expected_head.checkpoint.checkpoint_digest
                        or result_digest != resulting.checkpoint_digest
                    ):
                        raise AgenticCoordinationError(
                            "durable Agent Event identity was equivocated"
                        )
                    if current != resulting:
                        raise AgenticCoordinationError(
                            "durable Agent Event retry is no longer the current head"
                        )
                    self._current_graph_snapshot(graph_resolver, graph_head)
                    return AgenticEventPublication(
                        head=self._head(current),
                        event=stored_event,
                        event_digest=stored_digest,
                    )
                current = _current_checkpoint(connection)
                if current != expected_head.checkpoint:
                    raise AgenticCoordinationError(
                        "Agent Event checkpoint compare-and-swap was stale"
                    )
                outbox = _outbox_from_row(
                    _outbox_row(connection, canonical_event.command_id),
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                )
                if outbox.state is not AgenticOutboxState.ACKNOWLEDGED:
                    raise AgenticCoordinationError(
                        "Agent Event requires durable receiver admission first"
                    )
                admission = _admission_receipt_from_row(
                    _inbox_row(connection, canonical_event.command_id)
                )
                if (
                    outbox.acknowledgement_id != admission.receipt_id
                    or outbox.acknowledgement_digest != admission.receipt_digest
                ):
                    raise AgenticCoordinationError("Agent Event command admission binding differs")
                self._current_graph_snapshot(graph_resolver, graph_head)
                _insert_checkpoint(
                    connection,
                    resulting,
                    predecessor_digest=current.checkpoint_digest,
                    recorded_at=self._now(),
                )
                connection.execute(
                    """
                    INSERT INTO agentic_events(
                        event_id, event_digest, command_id, agent_id, event_sequence,
                        source_checkpoint_digest, resulting_checkpoint_digest,
                        canonical_event, recorded_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        canonical_event.event_id,
                        event_digest,
                        canonical_event.command_id,
                        canonical_event.agent_id,
                        canonical_event.sequence,
                        current.checkpoint_digest,
                        resulting.checkpoint_digest,
                        sqlite3.Binary(_agent_event_bytes(canonical_event)),
                        _format_timestamp(self._now()),
                    ),
                )
                cursor = connection.execute(
                    """
                    UPDATE agentic_checkpoint_head
                    SET checkpoint_digest = ?, revision = ?
                    WHERE slot = 1 AND checkpoint_digest = ? AND revision = ?
                    """,
                    (
                        resulting.checkpoint_digest,
                        resulting.revision,
                        current.checkpoint_digest,
                        current.revision,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgenticCoordinationError(
                        "Agent Event checkpoint compare-and-swap lost its atomic race"
                    )
                self._validate_durable_history(connection, snapshot)
                self._current_graph_snapshot(graph_resolver, graph_head)
                return AgenticEventPublication(
                    head=self._head(resulting),
                    event=canonical_event,
                    event_digest=event_digest,
                )
        except AgenticCoordinationError:
            raise
        except sqlite3.IntegrityError as exc:
            raise AgenticCoordinationError(
                "Agent Event publication conflicted with durable authority"
            ) from exc
        except (
            AgenticGraphHeadError,
            OSError,
            RuntimeError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError("Agent Event publication failed closed") from exc

    def claim_next_delivery(
        self,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticOutboxDeliveryClaim | None:
        """Consume the next pending delivery claim exactly once."""

        try:
            self._current_graph_snapshot(graph_resolver, graph_head)
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                row = connection.execute(
                    """
                    SELECT outbox.*
                    FROM agentic_command_outbox AS outbox
                    JOIN agentic_cycles AS cycle ON cycle.cycle_id = outbox.cycle_id
                    JOIN agentic_checkpoints AS checkpoint
                      ON checkpoint.checkpoint_digest = cycle.resulting_checkpoint_digest
                    WHERE outbox.state = ?
                      AND NOT EXISTS (
                          SELECT 1
                          FROM agentic_command_outbox AS earlier
                          WHERE earlier.target_agent_id = outbox.target_agent_id
                            AND earlier.command_sequence < outbox.command_sequence
                            AND earlier.state != 'acknowledged'
                      )
                    ORDER BY checkpoint.revision, outbox.ordinal, outbox.command_id
                    LIMIT 1
                    """,
                    (AgenticOutboxState.PENDING.value,),
                ).fetchone()
                if row is None:
                    return None
                entry = _outbox_from_row(
                    row,
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                )
                claimed_at = self._now()
                claim_digest = _delivery_claim_digest(
                    store_id=self.store_id,
                    coordination_binding_digest=self.binding.binding_digest,
                    cycle_digest=entry.cycle_digest,
                    command_id=entry.command.command_id,
                    command_digest=entry.command_digest,
                    claimed_at=claimed_at,
                )
                claim_id = f"agentic-delivery-claim_{claim_digest}"
                state_digest = _outbox_state_digest(
                    cycle_digest=entry.cycle_digest,
                    command_digest=entry.command_digest,
                    state=AgenticOutboxState.DELIVERY_STARTED_OUTCOME_UNKNOWN,
                    claimed_at=claimed_at,
                    claim_digest=claim_digest,
                    acknowledged_at=None,
                    acknowledgement_id=None,
                    acknowledgement_digest=None,
                )
                cursor = connection.execute(
                    """
                    UPDATE agentic_command_outbox
                    SET state = ?, claimed_at = ?, claim_id = ?, claim_digest = ?,
                        state_digest = ?
                    WHERE command_id = ? AND state = ? AND state_digest = ?
                    """,
                    (
                        AgenticOutboxState.DELIVERY_STARTED_OUTCOME_UNKNOWN.value,
                        _format_timestamp(claimed_at),
                        claim_id,
                        claim_digest,
                        state_digest,
                        entry.command.command_id,
                        AgenticOutboxState.PENDING.value,
                        entry.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgenticCoordinationError("outbox delivery claim lost its atomic race")
                claimed = _outbox_from_row(
                    _outbox_row(connection, entry.command.command_id),
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                )
                return _claim_from_entry(claimed)
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("outbox delivery claim failed closed") from exc

    def admit_delivery(
        self,
        claim: AgenticOutboxDeliveryClaim,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticCommandAdmissionReceipt:
        """Durably admit one exact claim into the receiver inbox once."""

        try:
            self._current_graph_snapshot(graph_resolver, graph_head)
            canonical_claim = AgenticOutboxDeliveryClaim.model_validate(
                claim.model_dump(mode="json", by_alias=True)
            )
            self._require_claim(canonical_claim)
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                current = _outbox_from_row(
                    _outbox_row(connection, canonical_claim.command.command_id),
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                )
                if (
                    current.state is not AgenticOutboxState.DELIVERY_STARTED_OUTCOME_UNKNOWN
                    or _claim_from_entry(current) != canonical_claim
                ):
                    raise AgenticCoordinationError(
                        "receiver admission differs from the durable delivery claim"
                    )
                existing = connection.execute(
                    "SELECT * FROM agentic_command_inbox WHERE command_id = ?",
                    (canonical_claim.command.command_id,),
                ).fetchone()
                if existing is not None:
                    receipt = _admission_receipt_from_row(existing)
                    if (
                        receipt.claim_id != canonical_claim.claim_id
                        or receipt.claim_digest != canonical_claim.claim_digest
                    ):
                        raise AgenticCoordinationError("receiver admission receipt was equivocated")
                    return receipt
                admitted_at = self._now()
                if admitted_at < canonical_claim.claimed_at:
                    raise AgenticCoordinationError(
                        "receiver admission timestamp predates delivery claim"
                    )
                receipt = AgenticCommandAdmissionReceipt(
                    storeId=self.store_id,
                    coordinationBindingDigest=self.binding.binding_digest,
                    claimId=canonical_claim.claim_id,
                    claimDigest=canonical_claim.claim_digest,
                    commandId=canonical_claim.command.command_id,
                    commandDigest=canonical_claim.command_digest,
                    receiverAgentId=canonical_claim.command.target_agent_id,
                    admittedAt=cast(datetime, _format_timestamp(admitted_at)),
                )
                connection.execute(
                    """
                    INSERT INTO agentic_command_inbox(
                        receipt_id, receipt_digest, command_id, claim_id, claim_digest,
                        receiver_agent_id, canonical_receipt, admitted_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        receipt.receipt_id,
                        receipt.receipt_digest,
                        receipt.command_id,
                        receipt.claim_id,
                        receipt.claim_digest,
                        receipt.receiver_agent_id,
                        sqlite3.Binary(_admission_receipt_bytes(receipt)),
                        _format_timestamp(receipt.admitted_at),
                    ),
                )
                return _admission_receipt_from_row(
                    cast(
                        sqlite3.Row,
                        connection.execute(
                            "SELECT * FROM agentic_command_inbox WHERE command_id = ?",
                            (receipt.command_id,),
                        ).fetchone(),
                    )
                )
        except AgenticCoordinationError:
            raise
        except sqlite3.IntegrityError as exc:
            raise AgenticCoordinationError(
                "receiver admission conflicted with durable authority"
            ) from exc
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("receiver admission failed closed") from exc

    def acknowledge_delivery(
        self,
        claim: AgenticOutboxDeliveryClaim,
        admission: AgenticCommandAdmissionReceipt,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticOutboxEntry:
        """Record one exact terminal transport acknowledgement without redelivery."""

        try:
            self._current_graph_snapshot(graph_resolver, graph_head)
            canonical_claim = AgenticOutboxDeliveryClaim.model_validate(
                claim.model_dump(mode="json", by_alias=True)
            )
            canonical_admission = AgenticCommandAdmissionReceipt.model_validate(
                admission.model_dump(mode="json", by_alias=True)
            )
            self._require_claim(canonical_claim)
            if (
                canonical_admission.store_id != self.store_id
                or canonical_admission.coordination_binding_digest != self.binding.binding_digest
                or canonical_admission.claim_id != canonical_claim.claim_id
                or canonical_admission.claim_digest != canonical_claim.claim_digest
                or canonical_admission.command_id != canonical_claim.command.command_id
                or canonical_admission.command_digest != canonical_claim.command_digest
                or canonical_admission.receiver_agent_id != canonical_claim.command.target_agent_id
            ):
                raise AgenticCoordinationError(
                    "transport acknowledgement requires the exact receiver admission"
                )
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                stored_admission = _admission_receipt_from_row(
                    _inbox_row(connection, canonical_admission.command_id)
                )
                if stored_admission != canonical_admission:
                    raise AgenticCoordinationError(
                        "receiver admission differs from durable inbox authority"
                    )
                current = _outbox_from_row(
                    _outbox_row(connection, canonical_claim.command.command_id),
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                )
                if current.state is AgenticOutboxState.ACKNOWLEDGED:
                    if (
                        current.claim_digest == canonical_claim.claim_digest
                        and current.acknowledgement_id == canonical_admission.receipt_id
                        and current.acknowledgement_digest == canonical_admission.receipt_digest
                    ):
                        return current
                    raise AgenticCoordinationError("outbox acknowledgement was equivocated")
                if (
                    current.state is not AgenticOutboxState.DELIVERY_STARTED_OUTCOME_UNKNOWN
                    or _claim_from_entry(current) != canonical_claim
                ):
                    raise AgenticCoordinationError(
                        "outbox acknowledgement differs from the durable delivery claim"
                    )
                acknowledged_at = self._now()
                if acknowledged_at < canonical_admission.admitted_at:
                    raise AgenticCoordinationError(
                        "transport acknowledgement timestamp predates receiver admission"
                    )
                state_digest = _outbox_state_digest(
                    cycle_digest=current.cycle_digest,
                    command_digest=current.command_digest,
                    state=AgenticOutboxState.ACKNOWLEDGED,
                    claimed_at=current.claimed_at,
                    claim_digest=current.claim_digest,
                    acknowledged_at=acknowledged_at,
                    acknowledgement_id=canonical_admission.receipt_id,
                    acknowledgement_digest=canonical_admission.receipt_digest,
                )
                cursor = connection.execute(
                    """
                    UPDATE agentic_command_outbox
                    SET state = ?, acknowledged_at = ?, acknowledgement_id = ?,
                        acknowledgement_digest = ?, state_digest = ?
                    WHERE command_id = ? AND state = ? AND claim_digest = ?
                      AND state_digest = ?
                    """,
                    (
                        AgenticOutboxState.ACKNOWLEDGED.value,
                        _format_timestamp(acknowledged_at),
                        canonical_admission.receipt_id,
                        canonical_admission.receipt_digest,
                        state_digest,
                        current.command.command_id,
                        AgenticOutboxState.DELIVERY_STARTED_OUTCOME_UNKNOWN.value,
                        current.claim_digest,
                        current.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgenticCoordinationError("outbox acknowledgement lost its atomic race")
                return _outbox_from_row(
                    _outbox_row(connection, current.command.command_id),
                    store_id=self.store_id,
                    binding_digest=self.binding.binding_digest,
                )
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("outbox acknowledgement failed closed") from exc

    def verified_admitted_specialist_assignment(
        self,
        current_head: VerifiedAgenticDurableHead,
        *,
        command_id: str,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedAdmittedSpecialistAssignment:
        """Verify one current live assignment and its receiver-acknowledged transport."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            self._require_local_handle(current_head)
            _require_identifier(command_id, label="specialist assignment Command ID")
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                durable_head = _current_checkpoint(connection)
                if durable_head != current_head.checkpoint:
                    raise AgenticCoordinationError(
                        "specialist assignment requires the exact current durable head"
                    )
                material = _admitted_specialist_assignment_material(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                    checkpoint=durable_head,
                    command_id=command_id,
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                return VerifiedAdmittedSpecialistAssignment(
                    command=material.command,
                    candidate=material.candidate,
                    decision=material.decision,
                    specialist=material.specialist,
                    admission=material.admission,
                    cycle=material.cycle,
                    source_head_digest=durable_head.checkpoint_digest,
                    _authority=self._authority,
                )
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist assignment verification failed closed"
            ) from exc

    def reserve_specialist_execution(
        self,
        verified: VerifiedAdmittedSpecialistAssignment,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedSpecialistExecutionReservation:
        """Reserve one verified assignment exactly once without granting execution."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            if type(verified) is not VerifiedAdmittedSpecialistAssignment:
                raise AgenticCoordinationError(
                    "specialist reservation requires a verified store-issued assignment handle"
                )
            command_id = verified.command.command_id
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                durable_head = _current_checkpoint(connection)
                if durable_head.checkpoint_digest != verified.source_head_digest:
                    raise AgenticCoordinationError(
                        "verified specialist assignment is stale against the current head"
                    )
                material = _admitted_specialist_assignment_material(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                    checkpoint=durable_head,
                    command_id=command_id,
                )
                if (
                    material.command != verified.command
                    or material.candidate != verified.candidate
                    or material.decision != verified.decision
                    or material.specialist != verified.specialist
                    or material.admission != verified.admission
                    or material.cycle != verified.cycle
                ):
                    raise AgenticCoordinationError(
                        "verified specialist assignment differs after strict reload"
                    )
                existing = connection.execute(
                    "SELECT * FROM agentic_specialist_executions WHERE command_id = ?",
                    (command_id,),
                ).fetchone()
                if existing is not None:
                    stored = _specialist_execution_from_row(cast(sqlite3.Row, existing))
                    raise AgenticCoordinationError(
                        "specialist execution was already reserved in state "
                        f"{stored.state.value}; automatic redispatch is denied"
                    )
                self._current_graph_snapshot(graph_resolver, graph_head)
                reserved_at = self._now()
                if (
                    material.outbox.acknowledged_at is None
                    or reserved_at < material.admission.admitted_at
                    or reserved_at < material.outbox.acknowledged_at
                ):
                    raise AgenticCoordinationError(
                        "specialist reservation timestamp predates acknowledgement"
                    )
                proposal = material.candidate.proposal
                entry = AgenticSpecialistExecutionEntry(
                    storeId=self.store_id,
                    coordinationBindingDigest=self.binding.binding_digest,
                    sourceHeadCheckpointId=durable_head.checkpoint_id,
                    sourceHeadCheckpointDigest=durable_head.checkpoint_digest,
                    graphSnapshotId=snapshot.snapshot_id,
                    graphSnapshotDigest=snapshot.snapshot_digest,
                    cycleId=material.cycle.cycle_id,
                    cycleDigest=material.cycle.cycle_digest,
                    commandId=material.command.command_id,
                    commandDigest=material.outbox.command_digest,
                    admissionReceiptId=material.admission.receipt_id,
                    admissionReceiptDigest=material.admission.receipt_digest,
                    targetAgentId=material.command.target_agent_id,
                    taskId=cast(str, material.command.task_id),
                    candidateId=material.candidate.candidate_id,
                    candidateDigest=material.candidate.candidate_digest,
                    proposalDigest=proposal.proposal_digest,
                    targetId=proposal.target_id,
                    threatClass=proposal.threat_class,
                    specialization=material.command.specialization,
                    specialistDefinitionDigest=_specialist_definition_digest(material.specialist),
                    state=AgenticSpecialistExecutionState.RESERVED,
                    reservedAt=cast(datetime, _format_timestamp(reserved_at)),
                )
                verified._consume(self._authority)
                _insert_specialist_execution(connection, entry)
                self._validate_durable_history(connection, snapshot)
                self._current_graph_snapshot(graph_resolver, graph_head)
                stored = _specialist_execution_from_row(
                    _specialist_execution_row(connection, command_id)
                )
                if stored != entry:
                    raise AgenticCoordinationError(
                        "specialist execution reservation differs after insertion"
                    )
                return VerifiedSpecialistExecutionReservation(
                    stored,
                    _authority=self._authority,
                )
        except AgenticCoordinationError:
            raise
        except sqlite3.IntegrityError as exc:
            raise AgenticCoordinationError(
                "specialist execution reservation lost its one-use atomic race"
            ) from exc
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist execution reservation failed closed"
            ) from exc

    def begin_specialist_dispatch(
        self,
        reservation: VerifiedSpecialistExecutionReservation,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedSpecialistDispatchStarted:
        """Advance one unplanned reservation to the legacy outcome-unknown fence.

        This handle predates the awaiting-Permit plan and is not acceptable to a
        future Gateway bridge.  Planned callbacks require a distinct atomic
        plan-and-execution transition.
        """

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            if type(reservation) is not VerifiedSpecialistExecutionReservation:
                raise AgenticCoordinationError(
                    "specialist dispatch requires verified one-use reservation authority; "
                    "redispatch is denied"
                )
            requested = reservation.entry
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                durable_head = _current_checkpoint(connection)
                if durable_head.checkpoint_digest != requested.source_head_checkpoint_digest:
                    raise AgenticCoordinationError(
                        "specialist reservation is stale against the current head"
                    )
                stored = _specialist_execution_from_row(
                    _specialist_execution_row(connection, requested.command_id)
                )
                if (
                    stored != requested
                    or stored.state is not AgenticSpecialistExecutionState.RESERVED
                ):
                    raise AgenticCoordinationError(
                        "specialist dispatch was already started or its one-use reservation "
                        "changed; redispatch is denied"
                    )
                if (
                    connection.execute(
                        "SELECT 1 FROM agentic_specialist_dispatch_plans WHERE reservation_id = ?",
                        (stored.reservation_id,),
                    ).fetchone()
                    is not None
                ):
                    raise AgenticCoordinationError(
                        "specialist reservation authority was transferred to a Permit plan"
                    )
                material = _admitted_specialist_assignment_material(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                    checkpoint=durable_head,
                    command_id=stored.command_id,
                )
                if (
                    material.command.command_id != stored.command_id
                    or material.outbox.command_digest != stored.command_digest
                    or material.admission.receipt_digest != stored.admission_receipt_digest
                ):
                    raise AgenticCoordinationError(
                        "specialist reservation differs from the current admitted assignment"
                    )
                self._current_graph_snapshot(graph_resolver, graph_head)
                reservation._consume(self._authority)
                dispatch_started_at = self._now()
                started = AgenticSpecialistExecutionEntry.model_validate(
                    {
                        **stored.model_dump(mode="json", by_alias=True),
                        "state": (
                            AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value
                        ),
                        "stateDigest": "",
                        "dispatchStartedAt": _format_timestamp(dispatch_started_at),
                    }
                )
                cursor = connection.execute(
                    """
                    UPDATE agentic_specialist_executions
                    SET canonical_entry = ?, state = ?, dispatch_started_at = ?,
                        state_digest = ?
                    WHERE command_id = ? AND reservation_digest = ?
                      AND state = ? AND state_digest = ?
                    """,
                    (
                        sqlite3.Binary(_specialist_execution_bytes(started)),
                        started.state.value,
                        _format_timestamp(cast(datetime, started.dispatch_started_at)),
                        started.state_digest,
                        started.command_id,
                        started.reservation_digest,
                        AgenticSpecialistExecutionState.RESERVED.value,
                        stored.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgenticCoordinationError(
                        "specialist dispatch lost its one-use compare-and-swap; redispatch denied"
                    )
                self._validate_durable_history(connection, snapshot)
                self._current_graph_snapshot(graph_resolver, graph_head)
                reloaded = _specialist_execution_from_row(
                    _specialist_execution_row(connection, started.command_id)
                )
                if reloaded != started:
                    raise AgenticCoordinationError(
                        "specialist dispatch state differs after compare-and-swap"
                    )
                return VerifiedSpecialistDispatchStarted(
                    reloaded,
                    _authority=self._authority,
                )
        except AgenticCoordinationError:
            raise
        except sqlite3.IntegrityError as exc:
            raise AgenticCoordinationError(
                "specialist dispatch conflicted with durable one-use authority"
            ) from exc
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("specialist dispatch failed closed") from exc

    def specialist_preparation_entry(
        self,
        reservation: VerifiedSpecialistExecutionReservation,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSpecialistExecutionEntry:
        """Strictly reverify a live reserved assignment for inert action preparation.

        The returned value is an audit-only snapshot.  It cannot begin dispatch.
        The original process-local reservation remains live until it is either
        transferred to an awaiting-Permit plan or consumed by the legacy
        pre-bridge crash-fence transition.
        """

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            if type(reservation) is not VerifiedSpecialistExecutionReservation:
                raise AgenticCoordinationError(
                    "specialist preparation requires verified reservation authority"
                )
            reservation._require(self._authority)
            requested = reservation.entry
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                durable_head = _current_checkpoint(connection)
                if durable_head.checkpoint_digest != requested.source_head_checkpoint_digest:
                    raise AgenticCoordinationError(
                        "specialist preparation reservation is stale against the current head"
                    )
                stored = _specialist_execution_from_row(
                    _specialist_execution_row(connection, requested.command_id)
                )
                if (
                    stored != requested
                    or stored.state is not AgenticSpecialistExecutionState.RESERVED
                ):
                    raise AgenticCoordinationError(
                        "specialist preparation requires the exact live reserved execution"
                    )
                material = _admitted_specialist_assignment_material(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                    checkpoint=durable_head,
                    command_id=stored.command_id,
                )
                if (
                    material.command.command_id != stored.command_id
                    or material.outbox.command_digest != stored.command_digest
                    or material.admission.receipt_digest != stored.admission_receipt_digest
                    or material.candidate.candidate_digest != stored.candidate_digest
                    or _specialist_definition_digest(material.specialist)
                    != stored.specialist_definition_digest
                ):
                    raise AgenticCoordinationError(
                        "specialist preparation differs from the current admitted assignment"
                    )
                self._current_graph_snapshot(graph_resolver, graph_head)
                reservation._require(self._authority)
                return stored
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist execution preparation failed closed"
            ) from exc

    def plan_specialist_dispatch(
        self,
        reservation: VerifiedSpecialistExecutionReservation,
        *,
        preparation: AgenticSpecialistPreparation,
        activation: WebSpecialistCapabilityActivation,
        prepared_action: PreparedCapabilityAction,
        campaign: CampaignManifest,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        approval_envelope: ActionApprovalEnvelope,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedSpecialistDispatchPlan:
        """Transfer one live reservation into a durable, non-executing Permit plan."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            deployment = self._require_specialist_deployment()
            _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
                deployment,
                capability_ledger=capability_ledger,
            )
            (
                canonical_campaign,
                canonical_action,
                canonical_grant,
                canonical_approval,
            ) = _canonical_specialist_dispatch_inputs(
                reservation=reservation,
                preparation=preparation,
                activation=activation,
                prepared_action=prepared_action,
                campaign=campaign,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                approval_envelope=approval_envelope,
                authority=self._authority,
            )
            request_units = _reverify_specialist_preparation_and_action(
                store=self,
                reservation=reservation,
                preparation=preparation,
                activation=activation,
                action=canonical_action,
                campaign=canonical_campaign,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
            campaign_digest = _require_specialist_dispatch_campaign(
                binding=self.binding,
                preparation=preparation,
                campaign=canonical_campaign,
            )
            grant_binding = _specialist_dispatch_grant_binding(
                ledger=capability_ledger,
                grant=canonical_grant,
                preparation=preparation,
                action=canonical_action,
            )
            planned_at = self._now()
            _require_specialist_dispatch_approval(
                preparation=preparation,
                action=canonical_action,
                campaign=canonical_campaign,
                campaign_digest=campaign_digest,
                grant=canonical_grant,
                approval=canonical_approval,
                snapshot=snapshot,
                request_units=request_units,
                planned_at=planned_at,
            )
            requested = reservation.entry
            plan = AgenticSpecialistDispatchPlanEntry(
                state=AgenticSpecialistDispatchPlanState.AWAITING_PERMIT,
                storeId=self.store_id,
                coordinationBindingDigest=self.binding.binding_digest,
                controlPlaneRunId=preparation.control_plane_run_id,
                reservationId=requested.reservation_id,
                reservationDigest=requested.reservation_digest,
                reservationStateDigest=requested.state_digest,
                reservationReservedAt=cast(
                    datetime,
                    _format_timestamp(requested.reserved_at),
                ),
                sourceHeadCheckpointId=requested.source_head_checkpoint_id,
                sourceHeadCheckpointDigest=requested.source_head_checkpoint_digest,
                graphSnapshotId=requested.graph_snapshot_id,
                graphSnapshotDigest=requested.graph_snapshot_digest,
                commandId=requested.command_id,
                commandDigest=requested.command_digest,
                targetAgentId=requested.target_agent_id,
                taskId=requested.task_id,
                specialization=requested.specialization,
                preparationId=preparation.preparation_id,
                preparationDigest=preparation.preparation_digest,
                targetId=preparation.target_id,
                targetEndpoint=preparation.target_endpoint,
                targetDigest=preparation.target_digest,
                profileId=preparation.profile.profile_id,
                profileVersion=preparation.profile.profile_version,
                profileDigest=preparation.profile.profile_digest,
                executorId=preparation.executor_id,
                executorDigest=preparation.executor_digest,
                campaignId=preparation.campaign_id,
                campaignManifestDigest=campaign_digest,
                activationSetDigest=canonical_action.activation_set_digest,
                releaseId=canonical_action.release.release_id,
                releaseDigest=canonical_action.release.release_digest,
                capabilityId=canonical_action.capability.capability_id,
                capabilityVersion=canonical_action.capability.capability_version,
                capabilityDigest=canonical_action.capability.definition_digest,
                toolId=canonical_action.capability.tool_id,
                preparedAction=canonical_action,
                preparedActionDigest=_prepared_capability_action_digest(canonical_action),
                requestUnits=request_units,
                grant=grant_binding,
                approvalEnvelope=canonical_approval,
                expectedActionPermitId=canonical_approval.expected_action_permit_id,
                plannedAt=cast(datetime, _format_timestamp(planned_at)),
            )

            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                durable_head = _current_checkpoint(connection)
                if durable_head.checkpoint_digest != requested.source_head_checkpoint_digest:
                    raise AgenticCoordinationError(
                        "specialist dispatch plan reservation is stale against the current head"
                    )
                stored = _specialist_execution_from_row(
                    _specialist_execution_row(connection, requested.command_id)
                )
                if (
                    stored != requested
                    or stored.state is not AgenticSpecialistExecutionState.RESERVED
                ):
                    raise AgenticCoordinationError(
                        "specialist dispatch plan requires the exact live reservation"
                    )
                duplicates = connection.execute(
                    """
                    SELECT plan_id FROM agentic_specialist_dispatch_plans
                    WHERE reservation_id = ? OR command_id = ? OR preparation_id = ?
                       OR prepared_action_digest = ? OR request_id = ? OR grant_id = ?
                       OR grant_digest = ? OR approval_id = ? OR action_proposal_id = ?
                       OR expected_action_permit_id = ?
                    """,
                    (
                        plan.reservation_id,
                        plan.command_id,
                        plan.preparation_id,
                        plan.prepared_action_digest,
                        plan.prepared_action.request.request_id,
                        plan.grant.grant_id,
                        plan.grant.grant_digest,
                        plan.approval_envelope.approval_id,
                        plan.approval_envelope.proposal.proposal_id,
                        plan.expected_action_permit_id,
                    ),
                ).fetchone()
                if duplicates is not None:
                    raise AgenticCoordinationError(
                        "specialist dispatch plan authority was already reserved"
                    )
                reservation._require(self._authority)
                _capability_ledger_runtime_identity(capability_ledger)
                current_grant_record = _CAPABILITY_LEDGER_RECORD_IMPLEMENTATION(
                    capability_ledger,
                    canonical_grant.grant_id,
                )
                if (
                    current_grant_record.grant != canonical_grant
                    or current_grant_record.remaining_calls != 1
                    or current_grant_record.revoked
                    or not _CAPABILITY_LEDGER_CAN_CONSUME_IMPLEMENTATION(
                        capability_ledger,
                        canonical_grant.grant_id,
                    )
                ):
                    raise AgenticCoordinationError(
                        "specialist dispatch Capability Grant changed before planning"
                    )
                _require_specialist_dispatch_approval(
                    preparation=preparation,
                    action=canonical_action,
                    campaign=canonical_campaign,
                    campaign_digest=campaign_digest,
                    grant=canonical_grant,
                    approval=canonical_approval,
                    snapshot=snapshot,
                    request_units=request_units,
                    planned_at=self._now(),
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                _insert_specialist_dispatch_plan(connection, plan)
                self._validate_durable_history(connection, snapshot)
                self._current_graph_snapshot(graph_resolver, graph_head)
                reloaded = _specialist_dispatch_plan_from_row(
                    _specialist_dispatch_plan_row(connection, plan.plan_id)
                )
                if reloaded != plan:
                    raise AgenticCoordinationError(
                        "specialist dispatch plan differs after durable insertion"
                    )
            reservation._consume(self._authority)
            return VerifiedSpecialistDispatchPlan(
                reloaded,
                campaign=canonical_campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=canonical_grant,
                activation=activation,
                prepared_action=canonical_action,
                approval_envelope=canonical_approval,
                specialist_deployment=deployment,
                _authority=self._authority,
            )
        except AgenticCoordinationError:
            raise
        except sqlite3.IntegrityError as exc:
            raise AgenticCoordinationError(
                "specialist dispatch plan lost its one-use atomic race"
            ) from exc
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("specialist dispatch planning failed closed") from exc

    def bind_specialist_permit_dispatcher(
        self,
        plan: VerifiedSpecialistDispatchPlan,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSpecialistCapabilityActivation,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        signed_approval: SignedWebActionApproval,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedSpecialistPermitDispatcher:
        """Bind one awaiting plan to a deployment-owned signed Permit dispatcher.

        Binding claims no Permit and consumes no Capability budget.  It merely
        seals the deployment-pinned Graph store, approval keyring, activation,
        Ledger, and code-owned specialist route that a later callback may use.
        """

        from pajin.agentic.specialist_preparation import AgenticSpecialistPreparation
        from pajin.capabilities.agentic_web_specialist import (
            WebSpecialistCapabilityActivation,
        )

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            deployment = self._require_specialist_deployment()
            if (
                type(plan) is not VerifiedSpecialistDispatchPlan
                or type(campaign) is not CampaignManifest
                or type(preparation) is not AgenticSpecialistPreparation
                or type(capability_ledger) is not CapabilityLedger
                or type(capability_grant) is not CapabilityGrant
                or type(activation) is not WebSpecialistCapabilityActivation
                or type(prepared_action) is not PreparedCapabilityAction
                or type(approval_envelope) is not ActionApprovalEnvelope
                or type(signed_approval) is not SignedWebActionApproval
            ):
                raise AgenticCoordinationError(
                    "specialist Permit binding requires exact deployment authority"
                )
            _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
                deployment,
                capability_ledger=capability_ledger,
            )
            graph_store = deployment.graph_store
            candidate_approval_authority = _AGENTIC_SPECIALIST_APPROVAL_VERIFIER_FOR_IMPLEMENTATION(
                deployment.approval_input,
                signed_approval,
                expected_approval=approval_envelope,
            )
            plan._require_runtime(
                self._authority,
                campaign=campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                activation=activation,
                prepared_action=prepared_action,
                approval_envelope=approval_envelope,
                specialist_deployment=deployment,
            )
            graph_resolver.require_runtime_store(graph_store, graph_head)
            if (
                candidate_approval_authority.signed.approval != approval_envelope
                or WebActionApprovalInputAuthority.verify_action_approval
                is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
                or "verify_action_approval" in vars(candidate_approval_authority)
            ):
                raise AgenticCoordinationError(
                    "specialist signed approval authority differs from the sealed plan"
                )
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                self._require_current_specialist_dispatch_runtime(
                    connection,
                    requested_plan=plan.entry,
                    campaign=campaign,
                    preparation=preparation,
                    capability_ledger=capability_ledger,
                    capability_grant=capability_grant,
                    activation=activation,
                    prepared_action=prepared_action,
                    approval_envelope=approval_envelope,
                    approval_authority=candidate_approval_authority,
                    snapshot=snapshot,
                    evaluated_at=self._now(),
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                graph_resolver.require_runtime_store(graph_store, graph_head)

            with self.__specialist_configured_runtime_lock:
                (
                    capabilities,
                    policies,
                    graph_authority,
                    dispatcher,
                    approval_authority,
                ) = deployment.configure_plan(
                    activation=activation,
                    approval=approval_envelope,
                    verifier=candidate_approval_authority,
                    clock=self._clock,
                )
                self._pin_specialist_configured_runtime(deployment)
            resolved = capabilities.resolve(prepared_action.capability)
            if resolved.reference() != prepared_action.capability:
                raise AgenticCoordinationError(
                    "specialist Graph Capability changed during Permit binding"
                )
            runtime = VerifiedSpecialistPermitDispatcher(
                plan=plan,
                campaign=campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                activation=activation,
                prepared_action=prepared_action,
                approval_envelope=approval_envelope,
                deployment=deployment,
                graph_store=graph_store,
                approval_authority=approval_authority,
                capabilities=capabilities,
                policies=policies,
                graph_authority=graph_authority,
                dispatcher=dispatcher,
                _authority=self._authority,
            )
            runtime._runtime_inputs(self._authority, plan)
            return runtime
        except AgenticCoordinationError:
            raise
        except (
            AgenticGraphHeadError,
            OSError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError(
                "specialist Permit dispatcher binding failed closed"
            ) from exc

    def plan_sql_specialist_dispatch_v2(
        self,
        reservation: VerifiedSpecialistExecutionReservation,
        *,
        preparation: AgenticSpecialistPreparation,
        activation: WebSQLSpecialistCapabilityActivationV2,
        prepared_action: PreparedCapabilityAction,
        campaign: CampaignManifest,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        approval_envelope: ActionApprovalEnvelope,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedSQLSpecialistDispatchPlanV2:
        """Create one explicit SQL v2 plan owned by the current scheduler Task."""

        _require_sql_specialist_v2_store_implementations(self)
        try:
            owner_task = asyncio.current_task()
        except RuntimeError as exc:
            raise AgenticCoordinationError(
                "SQL specialist v2 planning requires an active scheduler Task"
            ) from exc
        if owner_task is None or owner_task.done():
            raise AgenticCoordinationError(
                "SQL specialist v2 planning requires an active scheduler Task"
            )
        owner_task = cast(asyncio.Task[object], owner_task)
        owner_token = object()
        scheduler_task_token_digest = discovery_digest(
            "pajin.agentic.sql-specialist-scheduler-task-token/v1",
            {
                "storeId": self.store_id,
                "nonce": uuid.uuid4().hex,
            },
        )
        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            deployment = self._require_specialist_deployment(
                AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
            )
            _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
                deployment,
                capability_ledger=capability_ledger,
            )
            (
                canonical_campaign,
                canonical_action,
                canonical_grant,
                canonical_approval,
            ) = _canonical_sql_specialist_dispatch_v2_inputs(
                reservation=reservation,
                preparation=preparation,
                activation=activation,
                prepared_action=prepared_action,
                campaign=campaign,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                approval_envelope=approval_envelope,
                authority=self._authority,
            )
            request_units = _reverify_sql_specialist_v2_preparation_and_action(
                store=self,
                reservation=reservation,
                preparation=preparation,
                activation=activation,
                action=canonical_action,
                campaign=canonical_campaign,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
            campaign_digest = _require_specialist_dispatch_campaign(
                binding=self.binding,
                preparation=preparation,
                campaign=canonical_campaign,
            )
            grant_binding = _specialist_dispatch_grant_binding(
                ledger=capability_ledger,
                grant=canonical_grant,
                preparation=preparation,
                action=canonical_action,
            )
            planned_at = self._now()
            _require_specialist_dispatch_approval(
                preparation=preparation,
                action=canonical_action,
                campaign=canonical_campaign,
                campaign_digest=campaign_digest,
                grant=canonical_grant,
                approval=canonical_approval,
                snapshot=snapshot,
                request_units=request_units,
                planned_at=planned_at,
            )
            requested = reservation.entry
            plan = AgenticSQLSpecialistDispatchPlanEntryV2(
                runtimeGeneration=AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2,
                schedulerTaskTokenDigest=scheduler_task_token_digest,
                state=AgenticSpecialistDispatchPlanState.AWAITING_PERMIT,
                storeId=self.store_id,
                coordinationBindingDigest=self.binding.binding_digest,
                controlPlaneRunId=preparation.control_plane_run_id,
                reservationId=requested.reservation_id,
                reservationDigest=requested.reservation_digest,
                reservationStateDigest=requested.state_digest,
                reservationReservedAt=cast(
                    datetime,
                    _format_timestamp(requested.reserved_at),
                ),
                sourceHeadCheckpointId=requested.source_head_checkpoint_id,
                sourceHeadCheckpointDigest=requested.source_head_checkpoint_digest,
                graphSnapshotId=requested.graph_snapshot_id,
                graphSnapshotDigest=requested.graph_snapshot_digest,
                commandId=requested.command_id,
                commandDigest=requested.command_digest,
                targetAgentId=requested.target_agent_id,
                taskId=requested.task_id,
                specialization=requested.specialization,
                preparationId=preparation.preparation_id,
                preparationDigest=preparation.preparation_digest,
                targetId=preparation.target_id,
                targetEndpoint=preparation.target_endpoint,
                targetDigest=preparation.target_digest,
                profileId=preparation.profile.profile_id,
                profileVersion=preparation.profile.profile_version,
                profileDigest=preparation.profile.profile_digest,
                executorId=preparation.executor_id,
                executorDigest=preparation.executor_digest,
                campaignId=preparation.campaign_id,
                campaignManifestDigest=campaign_digest,
                activationSetDigest=canonical_action.activation_set_digest,
                releaseId=canonical_action.release.release_id,
                releaseDigest=canonical_action.release.release_digest,
                capabilityId=canonical_action.capability.capability_id,
                capabilityVersion=canonical_action.capability.capability_version,
                capabilityDigest=canonical_action.capability.definition_digest,
                toolId=canonical_action.capability.tool_id,
                preparedAction=canonical_action,
                preparedActionDigest=_prepared_capability_action_digest(canonical_action),
                requestUnits=request_units,
                grant=grant_binding,
                approvalEnvelope=canonical_approval,
                expectedActionPermitId=canonical_approval.expected_action_permit_id,
                plannedAt=cast(datetime, _format_timestamp(planned_at)),
            )

            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                durable_head = _current_checkpoint(connection)
                if durable_head.checkpoint_digest != requested.source_head_checkpoint_digest:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 plan reservation is stale against the current head"
                    )
                stored = _specialist_execution_from_row(
                    _specialist_execution_row(connection, requested.command_id)
                )
                if (
                    stored != requested
                    or stored.state is not AgenticSpecialistExecutionState.RESERVED
                ):
                    raise AgenticCoordinationError(
                        "SQL specialist v2 plan requires the exact live reservation"
                    )
                duplicates = connection.execute(
                    """
                    SELECT plan_id FROM agentic_specialist_dispatch_plans
                    WHERE reservation_id = ? OR command_id = ? OR preparation_id = ?
                       OR prepared_action_digest = ? OR request_id = ? OR grant_id = ?
                       OR grant_digest = ? OR approval_id = ? OR action_proposal_id = ?
                       OR expected_action_permit_id = ?
                    """,
                    (
                        plan.reservation_id,
                        plan.command_id,
                        plan.preparation_id,
                        plan.prepared_action_digest,
                        plan.prepared_action.request.request_id,
                        plan.grant.grant_id,
                        plan.grant.grant_digest,
                        plan.approval_envelope.approval_id,
                        plan.approval_envelope.proposal.proposal_id,
                        plan.expected_action_permit_id,
                    ),
                ).fetchone()
                if duplicates is not None:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 plan authority was already reserved"
                    )
                reservation._require(self._authority)
                _capability_ledger_runtime_identity(capability_ledger)
                current_grant_record = _CAPABILITY_LEDGER_RECORD_IMPLEMENTATION(
                    capability_ledger,
                    canonical_grant.grant_id,
                )
                if (
                    current_grant_record.grant != canonical_grant
                    or current_grant_record.remaining_calls != 1
                    or current_grant_record.revoked
                    or not _CAPABILITY_LEDGER_CAN_CONSUME_IMPLEMENTATION(
                        capability_ledger,
                        canonical_grant.grant_id,
                    )
                ):
                    raise AgenticCoordinationError(
                        "SQL specialist v2 Grant changed before planning"
                    )
                _require_specialist_dispatch_approval(
                    preparation=preparation,
                    action=canonical_action,
                    campaign=canonical_campaign,
                    campaign_digest=campaign_digest,
                    grant=canonical_grant,
                    approval=canonical_approval,
                    snapshot=snapshot,
                    request_units=request_units,
                    planned_at=self._now(),
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                _insert_specialist_dispatch_plan(connection, plan)
                self._validate_durable_history(connection, snapshot)
                self._current_graph_snapshot(graph_resolver, graph_head)
                reloaded = _sql_specialist_dispatch_plan_v2_from_row(
                    _specialist_dispatch_plan_row(connection, plan.plan_id)
                )
                if reloaded != plan:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 plan differs after durable insertion"
                    )
            verified = VerifiedSQLSpecialistDispatchPlanV2(
                reloaded,
                campaign=canonical_campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=canonical_grant,
                activation=activation,
                prepared_action=canonical_action,
                approval_envelope=canonical_approval,
                specialist_deployment=deployment,
                owner_task=owner_task,
                owner_token=owner_token,
                _authority=self._authority,
            )
            _SQL_SPECIALIST_V2_REGISTER_PLAN_IMPLEMENTATION(
                self,
                verified,
                owner_task=owner_task,
                owner_token=owner_token,
            )
            reservation._consume(self._authority)
            return verified
        except AgenticCoordinationError:
            raise
        except sqlite3.IntegrityError as exc:
            raise AgenticCoordinationError(
                "SQL specialist v2 plan lost its one-use atomic race"
            ) from exc
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "SQL specialist v2 dispatch planning failed closed"
            ) from exc

    def bind_sql_specialist_v2_permit_dispatcher(
        self,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        *,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSQLSpecialistCapabilityActivationV2,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        signed_approval: SignedWebActionApproval,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedSQLSpecialistPermitDispatcherV2:
        """Bind one Task-owned SQL v2 plan to its exact deployment writer."""

        from pajin.agentic.specialist_preparation import AgenticSpecialistPreparation
        from pajin.capabilities.agentic_web_specialist_v2 import (
            WebSQLSpecialistCapabilityActivationV2,
        )

        _require_sql_specialist_v2_store_implementations(self)
        owner_task, owner_token = _SQL_SPECIALIST_V2_REQUIRE_PLAN_OWNER_IMPLEMENTATION(
            self,
            plan,
        )
        try:
            deployment = self._require_specialist_deployment(
                AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
            )
            if (
                type(campaign) is not CampaignManifest
                or type(preparation) is not AgenticSpecialistPreparation
                or type(capability_ledger) is not CapabilityLedger
                or type(capability_grant) is not CapabilityGrant
                or type(activation) is not WebSQLSpecialistCapabilityActivationV2
                or type(prepared_action) is not PreparedCapabilityAction
                or type(approval_envelope) is not ActionApprovalEnvelope
                or type(signed_approval) is not SignedWebActionApproval
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 Permit binding requires exact deployment authority"
                )
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
                deployment,
                capability_ledger=capability_ledger,
            )
            graph_store = deployment.graph_store
            candidate_approval_authority = _AGENTIC_SPECIALIST_APPROVAL_VERIFIER_FOR_IMPLEMENTATION(
                deployment.approval_input,
                signed_approval,
                expected_approval=approval_envelope,
            )
            plan._require_runtime(
                self._authority,
                owner_task,
                owner_token,
                campaign=campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                activation=activation,
                prepared_action=prepared_action,
                approval_envelope=approval_envelope,
                specialist_deployment=deployment,
            )
            graph_resolver.require_runtime_store(graph_store, graph_head)
            if (
                candidate_approval_authority.signed.approval != approval_envelope
                or WebActionApprovalInputAuthority.verify_action_approval
                is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
                or "verify_action_approval" in vars(candidate_approval_authority)
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 signed approval differs from the sealed plan"
                )
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                self._require_current_sql_specialist_v2_dispatch_runtime(
                    connection,
                    requested_plan=plan.entry,
                    campaign=campaign,
                    preparation=preparation,
                    capability_ledger=capability_ledger,
                    capability_grant=capability_grant,
                    activation=activation,
                    prepared_action=prepared_action,
                    approval_envelope=approval_envelope,
                    approval_authority=candidate_approval_authority,
                    snapshot=snapshot,
                    evaluated_at=self._now(),
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                graph_resolver.require_runtime_store(graph_store, graph_head)

            with self.__specialist_configured_runtime_lock:
                (
                    capabilities,
                    policies,
                    graph_authority,
                    dispatcher,
                    approval_authority,
                ) = _AGENTIC_SPECIALIST_DEPLOYMENT_CONFIGURE_V2_IMPLEMENTATION(
                    deployment,
                    activation=activation,
                    approval=approval_envelope,
                    verifier=candidate_approval_authority,
                    clock=self._clock,
                )
                _SQL_SPECIALIST_V2_PIN_CONFIGURED_RUNTIME_IMPLEMENTATION(
                    self,
                    deployment,
                )
            resolved = capabilities.resolve(prepared_action.capability)
            if resolved.reference() != prepared_action.capability:
                raise AgenticCoordinationError(
                    "SQL specialist v2 Graph Capability changed during Permit binding"
                )
            runtime = VerifiedSQLSpecialistPermitDispatcherV2(
                plan=plan,
                campaign=campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                activation=activation,
                prepared_action=prepared_action,
                approval_envelope=approval_envelope,
                deployment=deployment,
                graph_store=graph_store,
                approval_authority=approval_authority,
                capabilities=capabilities,
                policies=policies,
                graph_authority=graph_authority,
                dispatcher=dispatcher,
                owner_task=owner_task,
                owner_token=owner_token,
                _authority=self._authority,
            )
            runtime._runtime_inputs(
                self._authority,
                plan,
                owner_task,
                owner_token,
            )
            return runtime
        except AgenticCoordinationError:
            raise
        except (
            AgenticGraphHeadError,
            OSError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit dispatcher binding failed closed"
            ) from exc

    async def dispatch_specialist_permit_once(
        self,
        plan: VerifiedSpecialistDispatchPlan,
        runtime: VerifiedSpecialistPermitDispatcher,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> ApprovedActionDispatchResult[VerifiedPlannedSpecialistDispatchStarted]:
        """Consume one signed Permit and enter the plan-bound crash fence once."""

        if type(runtime) is not VerifiedSpecialistPermitDispatcher:
            raise AgenticCoordinationError(
                "specialist Permit dispatch requires its exact deployment runtime"
            )
        (
            campaign,
            preparation,
            capability_ledger,
            capability_grant,
            activation,
            prepared_action,
            approval_envelope,
            graph_store,
            approval_authority,
        ) = runtime._runtime_inputs(self._authority, plan)
        snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
        try:
            graph_resolver.require_runtime_store(graph_store, graph_head)
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                self._require_current_specialist_dispatch_runtime(
                    connection,
                    requested_plan=plan.entry,
                    campaign=campaign,
                    preparation=preparation,
                    capability_ledger=capability_ledger,
                    capability_grant=capability_grant,
                    activation=activation,
                    prepared_action=prepared_action,
                    approval_envelope=approval_envelope,
                    approval_authority=approval_authority,
                    snapshot=snapshot,
                    evaluated_at=self._now(),
                )
            self._current_graph_snapshot(graph_resolver, graph_head)
            graph_resolver.require_runtime_store(graph_store, graph_head)
            plan._claim_callback(
                self._authority,
                campaign=campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                activation=activation,
                prepared_action=prepared_action,
                approval_envelope=approval_envelope,
                specialist_deployment=self._require_specialist_deployment(),
            )
        except AgenticCoordinationError:
            raise
        except (
            AgenticGraphHeadError,
            OSError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError(
                "specialist Permit dispatch preflight failed closed"
            ) from exc

        async def enter_callback(
            permit: ActionPermit,
            receipt: ActionApprovalConsumptionReceipt,
        ) -> VerifiedPlannedSpecialistDispatchStarted:
            return self._enter_planned_specialist_dispatch(
                plan,
                runtime,
                permit=permit,
                receipt=receipt,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )

        try:
            result = await runtime._dispatch_once(
                self._authority,
                plan,
                enter_callback,
            )
            _require_specialist_permit_authorization(
                plan=plan.entry,
                authorization=result.authorization,
                newly_consumed=result.dispatched,
            )
            if result.dispatched:
                started = result.result
                if (
                    type(started) is not VerifiedPlannedSpecialistDispatchStarted
                    or started.plan.state
                    is not AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or started.execution.state
                    is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or started.plan.plan_id != plan.entry.plan_id
                    or started.plan.action_permit != result.authorization.action.permit
                    or started.approval_receipt != result.authorization.receipt
                    or started.plan.grant_consumption_receipt != started.grant_consumption_receipt
                ):
                    raise AgenticCoordinationError(
                        "specialist Permit callback returned invalid started authority"
                    )
                plan._consume_callback(self._authority)
                return result

            terminal = runtime._terminal_authorization(self._authority, plan)
            if terminal is None:
                raise AgenticCoordinationError(
                    "specialist Permit retry omitted its terminal authorization"
                )
            self._reconcile_specialist_permit_consumption(
                plan,
                runtime,
                terminal=terminal,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
            plan._consume_callback(self._authority)
            return result
        except BaseException as exc:
            self._resolve_specialist_dispatch_exception(
                plan,
                runtime,
                original=exc,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )

    async def dispatch_sql_specialist_v2_permit_once(
        self,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        runtime: VerifiedSQLSpecialistPermitDispatcherV2,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> ApprovedActionDispatchResult[VerifiedPlannedSQLSpecialistDispatchStartedV2]:
        """Consume one SQL v2 Permit on the scheduler Task that created the plan."""

        _require_sql_specialist_v2_store_implementations(self)
        operation_token, owner_task = _SQL_SPECIALIST_V2_BEGIN_OPERATION_IMPLEMENTATION(self)
        try:
            return await _SQL_SPECIALIST_V2_ACTIVE_DISPATCH_IMPLEMENTATION(
                self,
                operation_token,
                owner_task,
                plan,
                runtime,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
        finally:
            _SQL_SPECIALIST_V2_RELEASE_OPERATION_IMPLEMENTATION(
                self,
                operation_token,
                owner_task,
            )

    async def _dispatch_sql_specialist_v2_permit_once_active(
        self,
        operation_token: object,
        owner_task: asyncio.Task[object],
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        runtime: VerifiedSQLSpecialistPermitDispatcherV2,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> ApprovedActionDispatchResult[VerifiedPlannedSQLSpecialistDispatchStartedV2]:
        """Run one Permit callback while a Store-close exclusion lease is live."""

        _require_sql_specialist_v2_store_implementations(self)
        _SQL_SPECIALIST_V2_REQUIRE_OPERATION_IMPLEMENTATION(
            self,
            operation_token,
            owner_task,
        )
        current_owner_task, owner_token = _SQL_SPECIALIST_V2_REQUIRE_PLAN_OWNER_IMPLEMENTATION(
            self, plan
        )
        if current_owner_task is not owner_task:
            raise AgenticCoordinationError("SQL specialist v2 dispatch left its scheduler Task")
        if type(runtime) is not VerifiedSQLSpecialistPermitDispatcherV2:
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit dispatch requires its exact runtime"
            )
        (
            campaign,
            preparation,
            capability_ledger,
            capability_grant,
            activation,
            prepared_action,
            approval_envelope,
            graph_store,
            approval_authority,
        ) = _SQL_SPECIALIST_V2_DISPATCHER_RUNTIME_INPUTS_IMPLEMENTATION(
            runtime,
            self._authority,
            plan,
            owner_task,
            owner_token,
        )
        snapshot = _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION(
            self,
            graph_resolver,
            graph_head,
        )
        try:
            graph_resolver.require_runtime_store(graph_store, graph_head)
            with _read_transaction(self._database) as connection:
                _SQL_SPECIALIST_V2_VALIDATE_CONNECTION_IMPLEMENTATION(self, connection)
                _SQL_SPECIALIST_V2_VALIDATE_HISTORY_IMPLEMENTATION(
                    self,
                    connection,
                    snapshot,
                )
                _SQL_SPECIALIST_V2_REQUIRE_CURRENT_RUNTIME_IMPLEMENTATION(
                    self,
                    connection,
                    requested_plan=plan.entry,
                    campaign=campaign,
                    preparation=preparation,
                    capability_ledger=capability_ledger,
                    capability_grant=capability_grant,
                    activation=activation,
                    prepared_action=prepared_action,
                    approval_envelope=approval_envelope,
                    approval_authority=approval_authority,
                    snapshot=snapshot,
                    evaluated_at=_SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self),
                )
            _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION(
                self,
                graph_resolver,
                graph_head,
            )
            graph_resolver.require_runtime_store(graph_store, graph_head)
            _SQL_SPECIALIST_V2_PLAN_CLAIM_CALLBACK_IMPLEMENTATION(
                plan,
                self._authority,
                owner_task,
                owner_token,
                campaign=campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                activation=activation,
                prepared_action=prepared_action,
                approval_envelope=approval_envelope,
                specialist_deployment=_SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_IMPLEMENTATION(
                    self, AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
                ),
            )
        except AgenticCoordinationError:
            raise
        except (
            AgenticGraphHeadError,
            OSError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit dispatch preflight failed closed"
            ) from exc

        async def enter_callback(
            permit: ActionPermit,
            receipt: ActionApprovalConsumptionReceipt,
        ) -> VerifiedPlannedSQLSpecialistDispatchStartedV2:
            if asyncio.current_task() is not owner_task:
                raise AgenticCoordinationError("SQL specialist v2 callback left its scheduler Task")
            return _SQL_SPECIALIST_V2_ENTER_DISPATCH_IMPLEMENTATION(
                self,
                plan,
                runtime,
                owner_task=owner_task,
                owner_token=owner_token,
                permit=permit,
                receipt=receipt,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )

        try:
            result = await _SQL_SPECIALIST_V2_DISPATCHER_DISPATCH_ONCE_IMPLEMENTATION(
                runtime,
                self._authority,
                plan,
                owner_task,
                owner_token,
                enter_callback,
            )
            _require_specialist_permit_authorization(
                plan=plan.entry,
                authorization=result.authorization,
                newly_consumed=result.dispatched,
            )
            if result.dispatched:
                started = result.result
                if (
                    type(started) is not VerifiedPlannedSQLSpecialistDispatchStartedV2
                    or started.plan.runtime_generation
                    is not AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
                    or started.plan.state
                    is not AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or started.execution.state
                    is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or started.plan.plan_id != plan.entry.plan_id
                    or started.plan.action_permit != result.authorization.action.permit
                    or started.approval_receipt != result.authorization.receipt
                    or started.plan.grant_consumption_receipt != started.grant_consumption_receipt
                ):
                    raise AgenticCoordinationError(
                        "SQL specialist v2 callback returned invalid started authority"
                    )
                _SQL_SPECIALIST_V2_PLAN_CONSUME_CALLBACK_IMPLEMENTATION(
                    plan,
                    self._authority,
                    owner_task,
                    owner_token,
                )
                return result

            terminal = _SQL_SPECIALIST_V2_DISPATCHER_TERMINAL_AUTHORIZATION_IMPLEMENTATION(
                runtime,
                self._authority,
                plan,
                owner_task,
                owner_token,
            )
            if terminal is None:
                raise AgenticCoordinationError(
                    "SQL specialist v2 Permit retry omitted terminal authorization"
                )
            _SQL_SPECIALIST_V2_RECONCILE_IMPLEMENTATION(
                self,
                plan,
                runtime,
                owner_task=owner_task,
                owner_token=owner_token,
                terminal=terminal,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
            _SQL_SPECIALIST_V2_PLAN_CONSUME_CALLBACK_IMPLEMENTATION(
                plan,
                self._authority,
                owner_task,
                owner_token,
            )
            return result
        except BaseException as exc:
            _SQL_SPECIALIST_V2_RESOLVE_EXCEPTION_IMPLEMENTATION(
                self,
                plan,
                runtime,
                owner_task=owner_task,
                owner_token=owner_token,
                original=exc,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )

    def _transfer_planned_specialist_dispatch_started(
        self,
        started: VerifiedPlannedSpecialistDispatchStarted,
    ) -> _AgenticSpecialistDispatchRuntimeCapsule:
        with self._specialist_dispatch_binding_operation(self._database):
            return self._transfer_planned_specialist_dispatch_started_locked(started)

    def _transfer_planned_specialist_dispatch_started_locked(
        self,
        started: VerifiedPlannedSpecialistDispatchStarted,
    ) -> _AgenticSpecialistDispatchRuntimeCapsule:
        """Transfer one exact Store-issued C3B2 handle to its callback Task.

        Equal audit values and directly constructed handle objects are not
        authority.  The live-set is process-local by design: close/restart
        destroys it and never recreates C3C dispatch authority from SQLite.
        """

        if (
            type(self) is not AgenticCoordinationStore
            or type(started) is not VerifiedPlannedSpecialistDispatchStarted
        ):
            raise AgenticCoordinationError(
                "planned specialist dispatch-started handle is foreign or consumed"
            )
        owner_task = asyncio.current_task()
        if owner_task is None:
            raise AgenticCoordinationError(
                "planned specialist dispatch transfer requires an active asyncio Task"
            )
        deployment = self._require_specialist_deployment()
        plan_value = started.plan
        execution_value = started.execution
        permit = started.permit
        approval_receipt = started.approval_receipt
        grant_receipt = started.grant_consumption_receipt
        if (
            type(plan_value) is not AgenticSpecialistDispatchPlanEntry
            or type(execution_value) is not AgenticSpecialistExecutionEntry
            or type(permit) is not ActionPermit
            or type(approval_receipt) is not ActionApprovalConsumptionReceipt
            or type(grant_receipt) is not AgenticSpecialistCapabilityGrantConsumptionReceipt
        ):
            raise AgenticCoordinationError(
                "planned specialist dispatch transfer failed strict reload"
            )
        plan_id = plan_value.plan_id
        with self.__issued_specialist_dispatch_lock:
            issued = self.__issued_specialist_dispatch_started.get(plan_id)
            if issued is None:
                raise AgenticCoordinationError(
                    "planned specialist dispatch-started handle is foreign or consumed"
                )
            issued_handle, capsule, issued_task, issued_database = issued
            if (
                issued_handle is not started
                or issued_task is not owner_task
                or issued_database is not self._database
                or type(capsule) is not _AgenticSpecialistDispatchRuntimeCapsule
            ):
                raise AgenticCoordinationError(
                    "planned specialist dispatch-started handle is foreign or consumed"
                )
            self._database.require_open()
            _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
                deployment,
                capability_ledger=capsule.capability_ledger,
            )
            try:
                canonical_plan = AgenticSpecialistDispatchPlanEntry.model_validate(
                    plan_value.model_dump(mode="json", by_alias=True)
                )
                canonical_execution = AgenticSpecialistExecutionEntry.model_validate(
                    execution_value.model_dump(mode="json", by_alias=True)
                )
                with _read_transaction(self._database) as connection:
                    self._validate_connection(connection)
                    stored_plan = _specialist_dispatch_plan_from_row(
                        _specialist_dispatch_plan_row(connection, plan_id)
                    )
                    stored_execution = _specialist_execution_from_row(
                        _specialist_execution_row(connection, execution_value.command_id)
                    )
                _, _, ledger_lock, _ = _capability_ledger_runtime_identity(
                    capsule.capability_ledger
                )
            except (
                AttributeError,
                OSError,
                sqlite3.Error,
                TypeError,
                ValidationError,
                ValueError,
            ) as exc:
                raise AgenticCoordinationError(
                    "planned specialist dispatch transfer failed strict reload"
                ) from exc
            with cast(RLockType, ledger_lock):
                current_lineage = _specialist_capability_lineage_observation(
                    capsule.capability_ledger,
                    capsule.capability_grant.grant_id,
                )
                current_grant, current_remaining, _ = current_lineage[0]
                if (
                    canonical_plan != plan_value
                    or canonical_execution != execution_value
                    or stored_plan != canonical_plan
                    or stored_execution != canonical_execution
                    or stored_plan.state
                    is not AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or stored_execution.state
                    is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or stored_plan.action_permit != permit
                    or stored_plan.approval_consumption_receipt != approval_receipt
                    or stored_plan.grant_consumption_receipt != grant_receipt
                    or capsule.campaign.metadata.name != stored_plan.campaign_id
                    or campaign_manifest_digest(capsule.campaign)
                    != stored_plan.campaign_manifest_digest
                    or capsule.preparation.preparation_id != stored_plan.preparation_id
                    or capsule.preparation.preparation_digest != stored_plan.preparation_digest
                    or capsule.prepared_action != stored_plan.prepared_action
                    or capsule.approval_envelope != stored_plan.approval_envelope
                    or capability_grant_digest(capsule.capability_grant)
                    != stored_plan.grant.grant_digest
                    or current_grant != capsule.capability_grant
                    or current_remaining != 0
                    or any(revoked for _, _, revoked in current_lineage)
                ):
                    raise AgenticCoordinationError(
                        "planned specialist dispatch transfer differs from current authority"
                    )
                del self.__issued_specialist_dispatch_started[plan_id]
                owner = cast(asyncio.Task[object], owner_task)
                if not any(
                    issued[2] is owner
                    for issued in self.__issued_specialist_dispatch_started.values()
                ):
                    owner.remove_done_callback(self._retire_issued_specialist_dispatch_started)
                    self.__issued_specialist_dispatch_owner_tasks.discard(owner)
                return capsule

    def _transfer_planned_sql_specialist_v2_dispatch_started(
        self,
        started: VerifiedPlannedSQLSpecialistDispatchStartedV2,
    ) -> _AgenticSQLSpecialistDispatchRuntimeCapsuleV2:
        _require_sql_specialist_v2_store_implementations(self)
        with _SQL_SPECIALIST_V2_BINDING_OPERATION_IMPLEMENTATION(self, self._database):
            if (
                type(self) is not AgenticCoordinationStore
                or type(started) is not VerifiedPlannedSQLSpecialistDispatchStartedV2
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 started handle is foreign or consumed"
                )
            owner_task = asyncio.current_task()
            if owner_task is None:
                raise AgenticCoordinationError(
                    "SQL specialist v2 transfer requires an active scheduler Task"
                )
            owner_task = cast(asyncio.Task[object], owner_task)
            deployment = _SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_IMPLEMENTATION(
                self,
                AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2,
            )
            plan_value = started.plan
            execution_value = started.execution
            permit = started.permit
            approval_receipt = started.approval_receipt
            grant_receipt = started.grant_consumption_receipt
            if (
                type(plan_value) is not AgenticSQLSpecialistDispatchPlanEntryV2
                or type(execution_value) is not AgenticSpecialistExecutionEntry
                or type(permit) is not ActionPermit
                or type(approval_receipt) is not ActionApprovalConsumptionReceipt
                or type(grant_receipt) is not AgenticSpecialistCapabilityGrantConsumptionReceipt
            ):
                raise AgenticCoordinationError("SQL specialist v2 transfer failed strict reload")
            plan_id = plan_value.plan_id
            with self.__issued_specialist_dispatch_lock:
                issued = self.__issued_sql_specialist_v2_dispatch_started.get(plan_id)
                if issued is None:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 started handle is foreign or consumed"
                    )
                issued_handle, capsule, issued_task, owner_token, issued_database = issued
                if (
                    issued_handle is not started
                    or issued_task is not owner_task
                    or issued_database is not self._database
                    or type(capsule) is not _AgenticSQLSpecialistDispatchRuntimeCapsuleV2
                ):
                    raise AgenticCoordinationError(
                        "SQL specialist v2 started handle is foreign or consumed"
                    )
                _SQL_SPECIALIST_V2_CAPSULE_REQUIRE_OWNER_IMPLEMENTATION(
                    capsule,
                    owner_task,
                    owner_token,
                )
                (
                    campaign,
                    preparation,
                    capability_ledger,
                    capability_grant,
                    _activation,
                    prepared_action,
                    approval_envelope,
                    graph_store,
                    _approval_authority,
                    deployment_runtime_identity,
                    configured_runtime_identity,
                ) = _SQL_SPECIALIST_V2_CAPSULE_RUNTIME_INPUTS_IMPLEMENTATION(
                    capsule,
                    owner_task,
                    owner_token,
                    claimed=False,
                )
                self._database.require_open()
                _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
                    deployment,
                    graph_store=graph_store,
                    capability_ledger=capability_ledger,
                    expected_identity=deployment_runtime_identity,
                    expected_configured_identity=configured_runtime_identity,
                )
                try:
                    canonical_plan = AgenticSQLSpecialistDispatchPlanEntryV2.model_validate(
                        plan_value.model_dump(mode="json", by_alias=True)
                    )
                    canonical_execution = AgenticSpecialistExecutionEntry.model_validate(
                        execution_value.model_dump(mode="json", by_alias=True)
                    )
                    with _read_transaction(self._database) as connection:
                        _SQL_SPECIALIST_V2_VALIDATE_CONNECTION_IMPLEMENTATION(
                            self,
                            connection,
                        )
                        stored_plan = _sql_specialist_dispatch_plan_v2_from_row(
                            _specialist_dispatch_plan_row(connection, plan_id)
                        )
                        stored_execution = _specialist_execution_from_row(
                            _specialist_execution_row(
                                connection,
                                execution_value.command_id,
                            )
                        )
                    _, _, ledger_lock, _ = _capability_ledger_runtime_identity(capability_ledger)
                except (
                    AttributeError,
                    OSError,
                    sqlite3.Error,
                    TypeError,
                    ValidationError,
                    ValueError,
                ) as exc:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 transfer failed strict reload"
                    ) from exc
                with cast(RLockType, ledger_lock):
                    current_lineage = _specialist_capability_lineage_observation(
                        capability_ledger,
                        capability_grant.grant_id,
                    )
                    current_grant, current_remaining, _ = current_lineage[0]
                    if (
                        canonical_plan != plan_value
                        or canonical_execution != execution_value
                        or stored_plan != canonical_plan
                        or stored_execution != canonical_execution
                        or stored_plan.state
                        is not AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                        or stored_execution.state
                        is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                        or stored_plan.action_permit != permit
                        or stored_plan.approval_consumption_receipt != approval_receipt
                        or stored_plan.grant_consumption_receipt != grant_receipt
                        or campaign.metadata.name != stored_plan.campaign_id
                        or campaign_manifest_digest(campaign)
                        != stored_plan.campaign_manifest_digest
                        or preparation.preparation_id != stored_plan.preparation_id
                        or preparation.preparation_digest != stored_plan.preparation_digest
                        or prepared_action != stored_plan.prepared_action
                        or approval_envelope != stored_plan.approval_envelope
                        or capability_grant_digest(capability_grant)
                        != stored_plan.grant.grant_digest
                        or current_grant != capability_grant
                        or current_remaining != 0
                        or any(revoked for _, _, revoked in current_lineage)
                    ):
                        raise AgenticCoordinationError(
                            "SQL specialist v2 transfer differs from current authority"
                        )
                    if plan_id in self.__transferred_sql_specialist_v2_dispatch_capsules:
                        raise AgenticCoordinationError(
                            "SQL specialist v2 capsule was already transferred"
                        )
                    del self.__issued_sql_specialist_v2_dispatch_started[plan_id]
                    self.__transferred_sql_specialist_v2_dispatch_capsules[plan_id] = (
                        capsule,
                        started,
                        owner_task,
                        owner_token,
                        self._database,
                    )
                    return capsule

    def mint_sql_specialist_v2_job_attempt_claim(
        self,
        started: VerifiedPlannedSQLSpecialistDispatchStartedV2,
        *,
        gateway_deployment: VerifiedSpecialistGatewayDeploymentV2,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedSQLSpecialistJobAttemptClaimV2:
        """Consume one private capsule into a fresh Store-owned JobAttempt claim.

        This method performs no backend, Gateway, browser, network, or Target
        I/O.  A previously persisted equal attempt is audit-only and can never
        mint a new live claim.
        """

        _require_sql_specialist_v2_store_implementations(self)
        if (
            type(started) is not VerifiedPlannedSQLSpecialistDispatchStartedV2
            or type(gateway_deployment) is not VerifiedSpecialistGatewayDeploymentV2
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 JobAttempt mint requires exact live authorities"
            )
        current_task = asyncio.current_task()
        if type(current_task) is not asyncio.Task or current_task.done():
            raise AgenticCoordinationError(
                "SQL specialist v2 JobAttempt mint requires its scheduler Task"
            )
        owner_task = cast(asyncio.Task[object], current_task)
        claim_owner_token = object()
        claim_identity_token = object()
        claim: VerifiedSQLSpecialistJobAttemptClaimV2 | None = None
        recorded_attempt: AgenticSpecialistJobAttempt | None = None
        attempt_cleanup_attempted = False
        try:
            with _VERIFIED_DEPLOYMENT_CLAIM_SCOPE_IMPLEMENTATION(
                gateway_deployment,
                claim_authority=_DEPLOYMENT_CLAIM_AUTHORITY,
                store_identity_token=self._authority,
                owner_task=owner_task,
                owner_token=claim_owner_token,
            ) as gateway_claim:
                capsule = _SQL_SPECIALIST_V2_TRANSFER_IMPLEMENTATION(self, started)
                with _SQL_SPECIALIST_V2_RUNTIME_CLAIM_IMPLEMENTATION(
                    self,
                    capsule,
                    graph_resolver=graph_resolver,
                    graph_head=graph_head,
                ) as context:
                    if (
                        type(context) is not _SQLSpecialistV2ClaimedRuntimeContext
                        or context.started is not started
                        or context.owner_task is not owner_task
                        or context.database is not self._database
                    ):
                        raise AgenticCoordinationError(
                            "SQL specialist v2 claimed runtime changed during mint"
                        )
                    gateway_observation = _VERIFIED_DEPLOYMENT_CLAIM_OBSERVATION_IMPLEMENTATION(
                        gateway_deployment,
                        gateway_claim,
                        claim_authority=_DEPLOYMENT_CLAIM_AUTHORITY,
                        store_identity_token=self._authority,
                        owner_task=owner_task,
                        owner_token=claim_owner_token,
                    )
                    attempt = _SQL_SPECIALIST_V2_JOB_ATTEMPT_BUILD_IMPLEMENTATION(
                        context,
                        store_id=self.store_id,
                        coordination_binding_digest=self.binding.binding_digest,
                        database_identity_digest=(
                            _SQL_SPECIALIST_V2_JOB_ATTEMPT_DATABASE_IDENTITY_IMPLEMENTATION(self)
                        ),
                        deployment_digest=self.binding.deployment_digest,
                        control_plane_run_id=self.binding.control_plane_run_id,
                        store_identity_token=self._authority,
                        gateway_deployment=gateway_deployment,
                        gateway_claim=gateway_claim,
                        gateway_observation=gateway_observation,
                        gateway_claim_owner_token=claim_owner_token,
                    )
                    recorded = _SQL_SPECIALIST_V2_RECORD_JOB_ATTEMPT_IMPLEMENTATION(
                        self,
                        attempt,
                        authority=self._authority,
                        graph_resolver=graph_resolver,
                        graph_head=graph_head,
                        require_new=True,
                    )
                    recorded_attempt = recorded
                    try:
                        if recorded != attempt:
                            raise AgenticCoordinationError(
                                "SQL specialist v2 JobAttempt changed after fresh insertion"
                            )
                        _SQL_SPECIALIST_V2_JOB_ATTEMPT_PUBLICATION_IMPLEMENTATION(
                            self,
                            context,
                            graph_resolver=graph_resolver,
                            graph_head=graph_head,
                        )
                        candidate = object.__new__(VerifiedSQLSpecialistJobAttemptClaimV2)
                        _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_INIT_IMPLEMENTATION(
                            candidate,
                            attempt=recorded,
                            owner_task=owner_task,
                            identity_token=claim_identity_token,
                            _factory_token=(_SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_FACTORY_TOKEN),
                        )
                        claim = candidate
                        _SQL_SPECIALIST_V2_REGISTER_JOB_ATTEMPT_CLAIM_IMPLEMENTATION(
                            self,
                            claim,
                            owner_task=owner_task,
                            owner_token=claim_owner_token,
                            deployment=gateway_deployment,
                            deployment_claim=gateway_claim,
                            context=context,
                            claim_identity_token=claim_identity_token,
                        )
                    except BaseException as original_exc:
                        attempt_cleanup_attempted = True
                        cleanup_error = (
                            _SQL_SPECIALIST_V2_CLEANUP_FAILED_JOB_ATTEMPT_MINT_IMPLEMENTATION(
                                self,
                                claim=claim,
                                recorded_attempt=recorded,
                                cleanup_already_attempted=False,
                                retire_gateway=False,
                                owner_task=owner_task,
                                owner_token=claim_owner_token,
                                claim_identity_token=claim_identity_token,
                            )
                        )
                        if cleanup_error is not None:
                            if isinstance(original_exc, asyncio.CancelledError):
                                original_exc.add_note(
                                    "SQL specialist v2 mint cleanup also failed: "
                                    f"{type(cleanup_error).__name__}"
                                )
                                raise
                            raise AgenticCoordinationError(
                                "SQL specialist v2 JobAttempt mint failed and "
                                "cleanup did not complete"
                            ) from cleanup_error
                        raise
            if claim is None:
                raise AgenticCoordinationError(
                    "SQL specialist v2 JobAttempt claim was not registered"
                )
            return claim
        except BaseException as exc:
            cleanup_error = _SQL_SPECIALIST_V2_CLEANUP_FAILED_JOB_ATTEMPT_MINT_IMPLEMENTATION(
                self,
                claim=claim,
                recorded_attempt=recorded_attempt,
                cleanup_already_attempted=attempt_cleanup_attempted,
                retire_gateway=True,
                owner_task=owner_task,
                owner_token=claim_owner_token,
                claim_identity_token=claim_identity_token,
            )
            if cleanup_error is not None:
                if isinstance(exc, asyncio.CancelledError):
                    exc.add_note(
                        "SQL specialist v2 mint cleanup also failed: "
                        f"{type(cleanup_error).__name__}"
                    )
                else:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 JobAttempt mint failed and cleanup did not complete"
                    ) from cleanup_error
            if isinstance(exc, SpecialistGatewayDeploymentV2Error):
                raise AgenticCoordinationError(
                    f"SQL specialist v2 Gateway deployment failed exact claim verification: {exc}"
                ) from exc
            raise

    async def dispatch_sql_specialist_v2_job_attempt_once(
        self,
        claim: VerifiedSQLSpecialistJobAttemptClaimV2,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSpecialistTerminalReceipt:
        """Consume one live claim through the zero-target-I/O Gateway exactly once."""

        _require_sql_specialist_v2_store_implementations(self)
        if type(claim) is not VerifiedSQLSpecialistJobAttemptClaimV2:
            raise AgenticCoordinationError(
                "SQL specialist v2 backend dispatch requires an exact live claim"
            )
        operation_token, owner_task = _SQL_SPECIALIST_V2_BEGIN_OPERATION_IMPLEMENTATION(self)
        try:
            return await _SQL_SPECIALIST_V2_ACTIVE_JOB_ATTEMPT_DISPATCH_IMPLEMENTATION(
                self,
                claim,
                operation_token=operation_token,
                owner_task=owner_task,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
        finally:
            _SQL_SPECIALIST_V2_RELEASE_OPERATION_IMPLEMENTATION(
                self,
                operation_token,
                owner_task,
            )

    async def _dispatch_sql_specialist_v2_job_attempt_once_active(
        self,
        claim: VerifiedSQLSpecialistJobAttemptClaimV2,
        *,
        operation_token: object,
        owner_task: asyncio.Task[object],
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSpecialistTerminalReceipt:
        """Run the trusted marker, Gateway, verifier, and receipt pipeline."""

        _SQL_SPECIALIST_V2_REQUIRE_OPERATION_IMPLEMENTATION(
            self,
            operation_token,
            owner_task,
        )
        issued: _IssuedSQLSpecialistV2JobAttemptClaim | None = None
        started_attempt: AgenticSpecialistJobAttempt | None = None
        completion: _VerifiedSpecialistGatewayCompletionV2 | None = None
        terminal_receipt: AgenticSpecialistTerminalReceipt | None = None
        primary_failure: BaseException | None = None
        try:
            with self.__issued_specialist_dispatch_lock:
                self._database.require_open()
                detached_attempt = claim.attempt
                candidate = self.__issued_sql_specialist_v2_job_attempt_claims.get(
                    detached_attempt.attempt_id
                )
                if candidate is None:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 JobAttempt claim is retired or unavailable"
                    )
                (
                    issued_claim,
                    issued_task,
                    owner_token,
                    deployment,
                    deployment_claim,
                    issued_database,
                    context,
                    claim_identity_token,
                ) = candidate
                if (
                    issued_claim is not claim
                    or issued_task is not owner_task
                    or owner_task is not asyncio.current_task()
                    or owner_task.done()
                    or issued_database is not self._database
                    or context.owner_task is not owner_task
                    or context.database is not self._database
                ):
                    raise AgenticCoordinationError(
                        "SQL specialist v2 JobAttempt claim belongs to another scheduler Task"
                    )
                _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_REQUIRE_IMPLEMENTATION(
                    claim,
                    owner_task=owner_task,
                    identity_token=claim_identity_token,
                    consumed=False,
                )
                _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_CONSUME_IMPLEMENTATION(
                    claim,
                    owner_task=owner_task,
                    identity_token=claim_identity_token,
                )
                issued = candidate

            _SQL_SPECIALIST_V2_JOB_ATTEMPT_PUBLICATION_IMPLEMENTATION(
                self,
                context,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
            observation = _VERIFIED_DEPLOYMENT_CLAIM_OBSERVATION_IMPLEMENTATION(
                deployment,
                deployment_claim,
                claim_authority=_DEPLOYMENT_CLAIM_AUTHORITY,
                store_identity_token=self._authority,
                owner_task=owner_task,
                owner_token=owner_token,
            )
            _SQL_SPECIALIST_V2_REQUIRE_EXECUTION_OBSERVATION_IMPLEMENTATION(
                self,
                claim.attempt,
                context=context,
                observation=observation,
            )
            attempt = claim.attempt
            started_attempt = _SQL_SPECIALIST_V2_MARK_JOB_ATTEMPT_DISPATCHED_IMPLEMENTATION(
                self,
                authority=self._authority,
                attempt_id=attempt.attempt_id,
                attempt_digest=attempt.attempt_digest,
                state_digest=attempt.state_digest,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
            dispatch_verification = started_attempt.dispatch_verification
            dispatch_verification_digest = started_attempt.dispatch_verification_digest
            if (
                started_attempt.state
                is not AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                or dispatch_verification is None
                or dispatch_verification_digest is None
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 dispatch marker lacks typed verification"
                )
            completion = await _VERIFIED_DEPLOYMENT_EXECUTE_CLAIM_IMPLEMENTATION(
                deployment,
                deployment_claim,
                claim_authority=_DEPLOYMENT_CLAIM_AUTHORITY,
                store_identity_token=self._authority,
                owner_task=owner_task,
                owner_token=owner_token,
                attempt_digest=started_attempt.attempt_digest,
                dispatch_verification_digest=dispatch_verification_digest,
                backend_handoff_deadline=dispatch_verification.backend_handoff_deadline,
            )
            terminal_receipt = (
                _SQL_SPECIALIST_V2_BUILD_ZERO_IO_TERMINAL_RECEIPT_IMPLEMENTATION(
                    self,
                    started_attempt,
                    completion,
                    authority=self._authority,
                    deployment=deployment,
                    deployment_claim=deployment_claim,
                    owner_task=owner_task,
                    owner_token=owner_token,
                )
            )
            stored_receipt = _SQL_SPECIALIST_V2_RECORD_TERMINAL_RECEIPT_IMPLEMENTATION(
                self,
                terminal_receipt,
                authority=self._authority,
                proven_terminal_authority=_PROVEN_TERMINAL_INSERT_AUTHORITY,
            )
            if stored_receipt != terminal_receipt:
                raise AgenticCoordinationError(
                    "SQL specialist v2 terminal receipt changed after insertion"
                )
            return stored_receipt
        except BaseException as exc:
            primary_failure = exc
            if started_attempt is not None and completion is None:
                reason: Literal["backend-dispatch-failed", "backend-dispatch-cancelled"] = (
                    "backend-dispatch-cancelled"
                    if isinstance(exc, asyncio.CancelledError)
                    else "backend-dispatch-failed"
                )
                try:
                    unknown_receipt = (
                        _SQL_SPECIALIST_V2_BUILD_UNKNOWN_TERMINAL_RECEIPT_IMPLEMENTATION(
                            self,
                            started_attempt,
                            reason=reason,
                        )
                    )
                    _SQL_SPECIALIST_V2_RECORD_TERMINAL_RECEIPT_IMPLEMENTATION(
                        self,
                        unknown_receipt,
                        authority=self._authority,
                    )
                except BaseException as receipt_exc:
                    exc.add_note(
                        "SQL specialist v2 unknown-outcome receipt also failed: "
                        f"{type(receipt_exc).__name__}"
                    )
            raise
        finally:
            if issued is not None:
                cleanup_errors = (
                    _SQL_SPECIALIST_V2_FINALIZE_JOB_ATTEMPT_DISPATCH_IMPLEMENTATION(
                        self,
                        issued,
                        started=started_attempt is not None,
                    )
                )
                if cleanup_errors:
                    if primary_failure is not None:
                        primary_failure.add_note(
                            "SQL specialist v2 dispatch cleanup also failed: "
                            f"{type(cleanup_errors[0]).__name__}"
                        )
                    else:
                        raise AgenticCoordinationError(
                            "SQL specialist v2 dispatch completed but cleanup did not"
                        ) from cleanup_errors[0]

    def _retire_issued_specialist_dispatch_started(
        self,
        owner_task: asyncio.Future[object],
    ) -> None:
        """Drop every untransferred capsule owned by one terminated Task."""

        with self.__specialist_binding_operation_lock, self.__issued_specialist_dispatch_lock:
            for plan_id, issued in tuple(self.__issued_specialist_dispatch_started.items()):
                if issued[2] is owner_task:
                    del self.__issued_specialist_dispatch_started[plan_id]
            self.__issued_specialist_dispatch_owner_tasks.discard(
                cast(asyncio.Task[object], owner_task)
            )

    def _register_sql_specialist_v2_plan(
        self,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        *,
        owner_task: asyncio.Task[object],
        owner_token: object,
    ) -> None:
        if (
            type(plan) is not VerifiedSQLSpecialistDispatchPlanV2
            or type(owner_task) is not asyncio.Task
            or owner_task is not asyncio.current_task()
            or owner_task.done()
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 plan requires its creating scheduler Task"
            )
        with self.__issued_specialist_dispatch_lock:
            self._database.require_open()
            if plan.entry.plan_id in self.__issued_sql_specialist_v2_plans:
                raise AgenticCoordinationError(
                    "SQL specialist v2 plan authority was already issued"
                )
            self.__issued_sql_specialist_v2_plans[plan.entry.plan_id] = (
                plan,
                owner_task,
                owner_token,
                self._database,
            )
            if owner_task not in self.__issued_sql_specialist_v2_plan_owner_tasks:
                self.__issued_sql_specialist_v2_plan_owner_tasks.add(owner_task)
                owner_task.add_done_callback(
                    _SQL_SPECIALIST_V2_RETIRE_PLAN_CALLBACK_FACTORY_IMPLEMENTATION(self)
                )

    def _require_sql_specialist_v2_plan_owner(
        self,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
    ) -> tuple[asyncio.Task[object], object]:
        if type(plan) is not VerifiedSQLSpecialistDispatchPlanV2:
            raise AgenticCoordinationError("SQL specialist v2 plan authority is foreign")
        owner_task = asyncio.current_task()
        if owner_task is None:
            raise AgenticCoordinationError(
                "SQL specialist v2 plan requires an active scheduler Task"
            )
        with self.__issued_specialist_dispatch_lock:
            issued = self.__issued_sql_specialist_v2_plans.get(plan.entry.plan_id)
            if issued is None:
                raise AgenticCoordinationError(
                    "SQL specialist v2 plan authority is retired or unavailable"
                )
            issued_plan, issued_task, owner_token, issued_database = issued
            if (
                issued_plan is not plan
                or issued_task is not owner_task
                or issued_database is not self._database
                or owner_task.done()
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 plan belongs to another scheduler Task"
                )
            self._database.require_open()
            _SQL_SPECIALIST_V2_PLAN_REQUIRE_IMPLEMENTATION(
                plan,
                self._authority,
                cast(asyncio.Task[object], owner_task),
                owner_token,
            )
            return cast(asyncio.Task[object], owner_task), owner_token

    def _retire_issued_sql_specialist_v2_plans(
        self,
        owner_task: asyncio.Future[object],
    ) -> None:
        with self.__issued_specialist_dispatch_lock:
            for plan_id, issued in tuple(self.__issued_sql_specialist_v2_plans.items()):
                plan, _task, owner_token, _database = issued
                if issued[1] is owner_task:
                    with suppress(AgenticCoordinationError):
                        _SQL_SPECIALIST_V2_PLAN_RETIRE_IMPLEMENTATION(
                            plan,
                            self._authority,
                            owner_token,
                        )
                    del self.__issued_sql_specialist_v2_plans[plan_id]
            self.__issued_sql_specialist_v2_plan_owner_tasks.discard(
                cast(asyncio.Task[object], owner_task)
            )

    def _retire_issued_sql_specialist_v2_dispatch_started(
        self,
        owner_task: asyncio.Future[object],
    ) -> None:
        with self.__specialist_binding_operation_lock:
            with self.__issued_specialist_dispatch_lock:
                for plan_id, issued in tuple(
                    self.__issued_sql_specialist_v2_dispatch_started.items()
                ):
                    if issued[2] is owner_task:
                        with suppress(AgenticCoordinationError):
                            _SQL_SPECIALIST_V2_CAPSULE_RETIRE_IMPLEMENTATION(
                                issued[1],
                                issued[3],
                            )
                        del self.__issued_sql_specialist_v2_dispatch_started[plan_id]
                for plan_id, transferred in tuple(
                    self.__transferred_sql_specialist_v2_dispatch_capsules.items()
                ):
                    if transferred[2] is owner_task:
                        with suppress(AgenticCoordinationError):
                            _SQL_SPECIALIST_V2_CAPSULE_RETIRE_IMPLEMENTATION(
                                transferred[0],
                                transferred[3],
                            )
                        del self.__transferred_sql_specialist_v2_dispatch_capsules[plan_id]
                self.__issued_sql_specialist_v2_dispatch_owner_tasks.discard(
                    cast(asyncio.Task[object], owner_task)
                )
            with self.__specialist_dispatch_lifecycle_lock:
                for token, operation in tuple(
                    self.__active_sql_specialist_v2_dispatch_operations.items()
                ):
                    if operation[0] is owner_task:
                        del self.__active_sql_specialist_v2_dispatch_operations[token]

    def _drop_sql_specialist_v2_dispatch_owner_callback_if_unused(
        self,
        owner_task: asyncio.Task[object],
    ) -> None:
        if any(
            item[2] is owner_task
            for item in self.__issued_sql_specialist_v2_dispatch_started.values()
        ) or any(
            item[2] is owner_task
            for item in self.__transferred_sql_specialist_v2_dispatch_capsules.values()
        ):
            return
        owner_task.remove_done_callback(
            _SQL_SPECIALIST_V2_RETIRE_CALLBACK_FACTORY_IMPLEMENTATION(self)
        )
        self.__issued_sql_specialist_v2_dispatch_owner_tasks.discard(owner_task)

    def _require_sql_specialist_v2_execution_observation(
        self,
        attempt: AgenticSpecialistJobAttempt,
        *,
        context: _SQLSpecialistV2ClaimedRuntimeContext,
        observation: _SpecialistGatewayDeploymentClaimObservationV2,
    ) -> None:
        """Re-observe live runtime and deployment identity immediately before CAS."""

        if (
            type(attempt) is not AgenticSpecialistJobAttempt
            or type(context) is not _SQLSpecialistV2ClaimedRuntimeContext
            or type(observation) is not _SpecialistGatewayDeploymentClaimObservationV2
            or context.owner_task is not asyncio.current_task()
            or context.owner_task.done()
            or context.database is not self._database
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 execution observation lacks live authority"
            )
        deployment = _SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_IMPLEMENTATION(
            self,
            AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2,
        )
        _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
            deployment,
            graph_store=context.graph_store,
            capability_ledger=context.capability_ledger,
            expected_identity=context.deployment_runtime_identity,
            expected_configured_identity=context.configured_runtime_identity,
        )
        _AGENTIC_SPECIALIST_APPROVAL_REQUIRE_REGISTERED_IMPLEMENTATION(
            deployment.approval_input,
            context.approval_authority,
        )
        reserved_execution = AgenticSpecialistExecutionEntry.model_validate(
            {
                **context.execution.model_dump(mode="json", by_alias=True),
                "state": AgenticSpecialistExecutionState.RESERVED.value,
                "stateDigest": "",
                "dispatchStartedAt": None,
            }
        )
        _reverify_planned_specialist_preparation(
            binding=self.binding,
            store_id=self.store_id,
            execution=reserved_execution,
            preparation=context.preparation,
            campaign=context.campaign,
        )
        request_units = _reverify_planned_sql_specialist_v2_action(
            preparation=context.preparation,
            activation=context.activation,
            action=context.prepared_action,
        )
        campaign_digest = _require_specialist_dispatch_campaign(
            binding=self.binding,
            preparation=context.preparation,
            campaign=context.campaign,
        )
        _require_specialist_dispatch_approval(
            preparation=context.preparation,
            action=context.prepared_action,
            campaign=context.campaign,
            campaign_digest=campaign_digest,
            grant=context.capability_grant,
            approval=context.approval_envelope,
            snapshot=context.snapshot,
            request_units=request_units,
            planned_at=_SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self),
        )
        snapshot = observation.snapshot
        inventory = observation.execution_inventory
        if (
            attempt.store_id != self.store_id
            or attempt.coordination_binding_digest != self.binding.binding_digest
            or attempt.database_identity_digest
            != _SQL_SPECIALIST_V2_JOB_ATTEMPT_DATABASE_IDENTITY_IMPLEMENTATION(self)
            or attempt.plan_id != context.plan.plan_id
            or attempt.plan_digest != context.plan.plan_digest
            or attempt.plan_state_digest != context.plan.state_digest
            or attempt.graph_snapshot_id != context.snapshot.snapshot_id
            or attempt.graph_snapshot_digest != context.snapshot.snapshot_digest
            or attempt.runtime_capsule_token_digest != context.runtime_capsule_token_digest
            or attempt.grant_lineage_state_digest != context.grant_lineage_state_digest
            or attempt.gateway_id != snapshot.gateway_id
            or attempt.gateway_version != snapshot.gateway_version
            or attempt.gateway_digest != snapshot.gateway_digest
            or attempt.execution_inventory_id != inventory.inventory_id
            or attempt.execution_inventory_digest != inventory.inventory_digest
            or attempt.worker_backend_id != snapshot.worker_backend_id
            or attempt.worker_backend_version != snapshot.worker_backend_version
            or attempt.worker_backend_digest != snapshot.worker_backend_digest
            or attempt.worker_command_digest != snapshot.worker_command_digest
            or attempt.worker_compiler_id != snapshot.worker_compiler_id
            or attempt.worker_compiler_version != snapshot.worker_compiler_version
            or attempt.worker_compiler_digest != snapshot.worker_compiler_digest
            or attempt.worker_image_reference != snapshot.worker_image_reference
            or attempt.worker_image_digest != snapshot.worker_image_digest
            or attempt.worker_verifier_id != snapshot.worker_verifier_id
            or attempt.worker_verifier_version != snapshot.worker_verifier_version
            or attempt.worker_verifier_digest != snapshot.worker_verifier_digest
            or attempt.worker_verification_key_id != snapshot.worker_verification_key_id
            or attempt.worker_verification_key_digest
            != snapshot.worker_verification_key_digest
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 execution observation differs from its JobAttempt"
            )

    def _register_sql_specialist_v2_job_attempt_claim(
        self,
        claim: VerifiedSQLSpecialistJobAttemptClaimV2,
        *,
        owner_task: asyncio.Task[object],
        owner_token: object,
        deployment: VerifiedSpecialistGatewayDeploymentV2,
        deployment_claim: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
        context: _SQLSpecialistV2ClaimedRuntimeContext,
        claim_identity_token: object,
    ) -> None:
        if (
            type(claim) is not VerifiedSQLSpecialistJobAttemptClaimV2
            or type(owner_task) is not asyncio.Task
            or owner_task is not asyncio.current_task()
            or owner_task.done()
            or type(deployment) is not VerifiedSpecialistGatewayDeploymentV2
            or type(deployment_claim) is not _VerifiedSpecialistGatewayDeploymentMintLeaseV2
            or type(context) is not _SQLSpecialistV2ClaimedRuntimeContext
            or context.owner_task is not owner_task
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 JobAttempt claim requires its creating scheduler Task"
            )
        _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_REQUIRE_IMPLEMENTATION(
            claim,
            owner_task=owner_task,
            identity_token=claim_identity_token,
            consumed=False,
        )
        with self.__issued_specialist_dispatch_lock:
            self._database.require_open()
            attempt_id = claim.attempt.attempt_id
            if attempt_id in self.__issued_sql_specialist_v2_job_attempt_claims:
                raise AgenticCoordinationError(
                    "SQL specialist v2 JobAttempt authority was already issued"
                )
            self.__issued_sql_specialist_v2_job_attempt_claims[attempt_id] = (
                claim,
                owner_task,
                owner_token,
                deployment,
                deployment_claim,
                self._database,
                context,
                claim_identity_token,
            )
            if owner_task not in self.__issued_sql_specialist_v2_job_attempt_owner_tasks:
                self.__issued_sql_specialist_v2_job_attempt_owner_tasks.add(owner_task)
                owner_task.add_done_callback(
                    _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CALLBACK_FACTORY_IMPLEMENTATION(self)
                )

    def _retire_sql_specialist_v2_job_attempt_entry(
        self,
        issued: _IssuedSQLSpecialistV2JobAttemptClaim,
        *,
        abandonment_reason: Literal[
            "mint-failed",
            "owner-task-completed",
            "store-close",
            "claim-discarded",
        ],
    ) -> tuple[BaseException, ...]:
        """Retire every authority in one live entry, collecting independent failures."""

        (
            claim,
            _owner_task,
            owner_token,
            deployment,
            deployment_claim,
            _database,
            _context,
            claim_identity_token,
        ) = issued
        errors: list[BaseException] = []
        try:
            _SQL_SPECIALIST_V2_RECORD_ABANDONMENT_IMPLEMENTATION(
                self,
                claim.attempt,
                authority=self._authority,
                reason=abandonment_reason,
            )
        except BaseException as exc:
            errors.append(exc)
        try:
            _VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION(
                deployment,
                deployment_claim,
                claim_authority=_DEPLOYMENT_CLAIM_AUTHORITY,
                store_identity_token=self._authority,
                owner_token=owner_token,
            )
        except BaseException as exc:
            errors.append(exc)
        try:
            _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_RETIRE_IMPLEMENTATION(
                claim,
                identity_token=claim_identity_token,
            )
        except BaseException as exc:
            errors.append(exc)
        return tuple(errors)

    def _finalize_sql_specialist_v2_job_attempt_dispatch(
        self,
        issued: _IssuedSQLSpecialistV2JobAttemptClaim,
        *,
        started: bool,
    ) -> tuple[BaseException, ...]:
        """Retire one spent live entry without misclassifying a started attempt."""

        if type(started) is not bool:
            return (AgenticCoordinationError("specialist dispatch cleanup phase is invalid"),)
        (
            claim,
            owner_task,
            owner_token,
            deployment,
            deployment_claim,
            _database,
            _context,
            claim_identity_token,
        ) = issued
        errors: list[BaseException] = []
        with self.__specialist_binding_operation_lock, self.__issued_specialist_dispatch_lock:
            attempt_id = claim.attempt.attempt_id
            current = self.__issued_sql_specialist_v2_job_attempt_claims.get(attempt_id)
            if current is not issued:
                return (
                    AgenticCoordinationError(
                        "SQL specialist v2 dispatch cleanup authority changed"
                    ),
                )
            if not started:
                errors.extend(
                    _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_ENTRY_IMPLEMENTATION(
                        self,
                        issued,
                        abandonment_reason="claim-discarded",
                    )
                )
            else:
                try:
                    _VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION(
                        deployment,
                        deployment_claim,
                        claim_authority=_DEPLOYMENT_CLAIM_AUTHORITY,
                        store_identity_token=self._authority,
                        owner_token=owner_token,
                    )
                except BaseException as exc:
                    errors.append(exc)
                try:
                    _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_RETIRE_IMPLEMENTATION(
                        claim,
                        identity_token=claim_identity_token,
                    )
                except BaseException as exc:
                    errors.append(exc)
            del self.__issued_sql_specialist_v2_job_attempt_claims[attempt_id]
            if not any(
                item[1] is owner_task
                for item in self.__issued_sql_specialist_v2_job_attempt_claims.values()
            ):
                with suppress(RuntimeError):
                    owner_task.remove_done_callback(
                        _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CALLBACK_FACTORY_IMPLEMENTATION(self)
                    )
                self.__issued_sql_specialist_v2_job_attempt_owner_tasks.discard(owner_task)
        return tuple(errors)

    def _cleanup_failed_sql_specialist_v2_job_attempt_mint(
        self,
        *,
        claim: VerifiedSQLSpecialistJobAttemptClaimV2 | None,
        recorded_attempt: AgenticSpecialistJobAttempt | None,
        cleanup_already_attempted: bool,
        retire_gateway: bool,
        owner_task: asyncio.Task[object],
        owner_token: object,
        claim_identity_token: object,
    ) -> BaseException | None:
        """Best-effort cleanup after a JobAttempt mint scope starts unwinding."""

        if cleanup_already_attempted:
            return None
        try:
            if claim is not None:
                _SQL_SPECIALIST_V2_DISCARD_JOB_ATTEMPT_CLAIM_IMPLEMENTATION(
                    self,
                    claim,
                    owner_task=owner_task,
                    owner_token=owner_token,
                    claim_identity_token=claim_identity_token,
                    abandonment_reason="mint-failed",
                    retire_gateway=retire_gateway,
                )
            elif recorded_attempt is not None:
                _SQL_SPECIALIST_V2_RECORD_ABANDONMENT_IMPLEMENTATION(
                    self,
                    recorded_attempt,
                    authority=self._authority,
                    reason="mint-failed",
                )
        except BaseException as exc:
            return exc
        return None

    def _retire_issued_sql_specialist_v2_job_attempt_claims(
        self,
        owner_task: asyncio.Future[object],
    ) -> None:
        errors: list[BaseException] = []
        with self.__specialist_binding_operation_lock, self.__issued_specialist_dispatch_lock:
            for attempt_id, issued in tuple(
                self.__issued_sql_specialist_v2_job_attempt_claims.items()
            ):
                if issued[1] is owner_task:
                    errors.extend(
                        _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_ENTRY_IMPLEMENTATION(
                            self,
                            issued,
                            abandonment_reason="owner-task-completed",
                        )
                    )
                    del self.__issued_sql_specialist_v2_job_attempt_claims[attempt_id]
            self.__issued_sql_specialist_v2_job_attempt_owner_tasks.discard(
                cast(asyncio.Task[object], owner_task)
            )
        if errors:
            raise AgenticCoordinationError(
                "SQL specialist v2 owner-task cleanup did not complete"
            ) from errors[0]

    def _discard_sql_specialist_v2_job_attempt_claim(
        self,
        claim: VerifiedSQLSpecialistJobAttemptClaimV2,
        *,
        owner_task: asyncio.Task[object],
        owner_token: object,
        claim_identity_token: object,
        abandonment_reason: Literal["mint-failed", "claim-discarded"],
        retire_gateway: bool,
    ) -> None:
        if type(retire_gateway) is not bool:
            raise AgenticCoordinationError(
                "SQL specialist v2 JobAttempt discard retirement mode is invalid"
            )
        errors: list[BaseException] = []
        with self.__specialist_binding_operation_lock, self.__issued_specialist_dispatch_lock:
            issued = self.__issued_sql_specialist_v2_job_attempt_claims.get(
                claim.attempt.attempt_id
            )
            if issued is not None and (
                issued[0] is not claim
                or issued[1] is not owner_task
                or issued[2] is not owner_token
                or issued[7] is not claim_identity_token
            ):
                raise AgenticCoordinationError(
                    "SQL specialist v2 JobAttempt discard authority changed"
                )
            if issued is not None and retire_gateway:
                errors.extend(
                    _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_ENTRY_IMPLEMENTATION(
                        self,
                        issued,
                        abandonment_reason=abandonment_reason,
                    )
                )
                del self.__issued_sql_specialist_v2_job_attempt_claims[claim.attempt.attempt_id]
            else:
                try:
                    _SQL_SPECIALIST_V2_RECORD_ABANDONMENT_IMPLEMENTATION(
                        self,
                        claim.attempt,
                        authority=self._authority,
                        reason=abandonment_reason,
                    )
                except BaseException as exc:
                    errors.append(exc)
                if issued is not None:
                    del self.__issued_sql_specialist_v2_job_attempt_claims[claim.attempt.attempt_id]
                try:
                    _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_RETIRE_IMPLEMENTATION(
                        claim,
                        identity_token=claim_identity_token,
                    )
                except BaseException as exc:
                    errors.append(exc)
            if not any(
                item[1] is owner_task
                for item in self.__issued_sql_specialist_v2_job_attempt_claims.values()
            ):
                with suppress(RuntimeError):
                    owner_task.remove_done_callback(
                        _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CALLBACK_FACTORY_IMPLEMENTATION(self)
                    )
                self.__issued_sql_specialist_v2_job_attempt_owner_tasks.discard(owner_task)
        if errors:
            raise AgenticCoordinationError(
                "SQL specialist v2 JobAttempt discard cleanup did not complete"
            ) from errors[0]

    @contextmanager
    def _claim_transferred_specialist_dispatch_runtime(
        self,
        capsule: _AgenticSpecialistDispatchRuntimeCapsule,
    ) -> Iterator[None]:
        """Hold the exact Ledger lineage lock through one local dispatch claim."""

        if (
            type(self) is not AgenticCoordinationStore
            or type(capsule) is not _AgenticSpecialistDispatchRuntimeCapsule
        ):
            raise AgenticCoordinationError("transferred specialist dispatch runtime is foreign")
        deployment = self._require_specialist_deployment()
        _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
            deployment,
            capability_ledger=capsule.capability_ledger,
        )
        _, _, ledger_lock, _ = _capability_ledger_runtime_identity(capsule.capability_ledger)
        with cast(RLockType, ledger_lock):
            current_lineage = _specialist_capability_lineage_observation(
                capsule.capability_ledger,
                capsule.capability_grant.grant_id,
            )
            current_grant, current_remaining, _ = current_lineage[0]
            if (
                current_grant != capsule.capability_grant
                or current_remaining != 0
                or any(revoked for _, _, revoked in current_lineage)
            ):
                raise AgenticCoordinationError(
                    "transferred specialist dispatch runtime authority changed"
                )
            yield

    @contextmanager
    def _claim_transferred_sql_specialist_v2_dispatch_runtime(
        self,
        capsule: _AgenticSQLSpecialistDispatchRuntimeCapsuleV2,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> Iterator[_SQLSpecialistV2ClaimedRuntimeContext]:
        _require_sql_specialist_v2_store_implementations(self)
        operation_token, owner_task = _SQL_SPECIALIST_V2_BEGIN_OPERATION_IMPLEMENTATION(self)
        claimed = False
        owner_token: object | None = None
        try:
            database = self._database
            with _SQL_SPECIALIST_V2_BINDING_OPERATION_IMPLEMENTATION(self, database):
                if type(capsule) is not _AgenticSQLSpecialistDispatchRuntimeCapsuleV2:
                    raise AgenticCoordinationError(
                        "transferred SQL specialist v2 runtime is foreign"
                    )
                with self.__issued_specialist_dispatch_lock:
                    matches = tuple(
                        (plan_id, transferred)
                        for plan_id, transferred in (
                            self.__transferred_sql_specialist_v2_dispatch_capsules.items()
                        )
                        if transferred[0] is capsule
                    )
                    if len(matches) != 1:
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 runtime is foreign or consumed"
                        )
                    plan_id, transferred = matches[0]
                    (
                        issued_capsule,
                        started,
                        issued_task,
                        owner_token,
                        issued_database,
                    ) = transferred
                    if (
                        issued_capsule is not capsule
                        or type(started) is not VerifiedPlannedSQLSpecialistDispatchStartedV2
                        or issued_task is not owner_task
                        or issued_database is not database
                    ):
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 runtime is foreign or consumed"
                        )
                    _SQL_SPECIALIST_V2_CAPSULE_CLAIM_IMPLEMENTATION(
                        capsule,
                        owner_task,
                        owner_token,
                    )
                    claimed = True
                    (
                        campaign,
                        preparation,
                        capability_ledger,
                        capability_grant,
                        activation,
                        prepared_action,
                        approval_envelope,
                        graph_store,
                        approval_authority,
                        deployment_runtime_identity,
                        configured_runtime_identity,
                    ) = _SQL_SPECIALIST_V2_CAPSULE_RUNTIME_INPUTS_IMPLEMENTATION(
                        capsule,
                        owner_task,
                        owner_token,
                        claimed=True,
                    )
                    runtime_capsule_token_digest = (
                        _SQL_SPECIALIST_V2_CAPSULE_TOKEN_DIGEST_IMPLEMENTATION(
                            capsule,
                            owner_task,
                            owner_token,
                            claimed=True,
                        )
                    )

                deployment = _SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_IMPLEMENTATION(
                    self,
                    AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2,
                )
                _AGENTIC_SPECIALIST_DEPLOYMENT_REQUIRE_RUNTIME_IMPLEMENTATION(
                    deployment,
                    graph_store=graph_store,
                    capability_ledger=capability_ledger,
                    expected_identity=deployment_runtime_identity,
                    expected_configured_identity=configured_runtime_identity,
                )
                _AGENTIC_SPECIALIST_APPROVAL_REQUIRE_REGISTERED_IMPLEMENTATION(
                    deployment.approval_input,
                    approval_authority,
                )
                snapshot = _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION(
                    self,
                    graph_resolver,
                    graph_head,
                )
                graph_resolver.require_runtime_store(graph_store, graph_head)
                with _read_transaction(database) as connection:
                    _SQL_SPECIALIST_V2_VALIDATE_CONNECTION_IMPLEMENTATION(
                        self,
                        connection,
                    )
                    _SQL_SPECIALIST_V2_VALIDATE_HISTORY_IMPLEMENTATION(
                        self,
                        connection,
                        snapshot,
                    )
                    stored_plan = _sql_specialist_dispatch_plan_v2_from_row(
                        _specialist_dispatch_plan_row(connection, plan_id)
                    )
                    stored_execution = _specialist_execution_from_row(
                        _specialist_execution_row(connection, started.execution.command_id)
                    )
                    durable_head = _current_checkpoint(connection)
                    reserved_execution = AgenticSpecialistExecutionEntry.model_validate(
                        {
                            **stored_execution.model_dump(mode="json", by_alias=True),
                            "state": AgenticSpecialistExecutionState.RESERVED.value,
                            "stateDigest": "",
                            "dispatchStartedAt": None,
                        }
                    )
                    permit = stored_plan.action_permit
                    approval_receipt = stored_plan.approval_consumption_receipt
                    grant_receipt = stored_plan.grant_consumption_receipt
                    if (
                        stored_plan != started.plan
                        or stored_execution != started.execution
                        or stored_plan.runtime_generation
                        is not AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
                        or stored_plan.state
                        is not AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                        or stored_execution.state
                        is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                        or reserved_execution.state_digest != stored_plan.reservation_state_digest
                        or durable_head.checkpoint_digest
                        != stored_plan.source_head_checkpoint_digest
                        or stored_plan.graph_snapshot_id != snapshot.snapshot_id
                        or stored_plan.graph_snapshot_digest != snapshot.snapshot_digest
                        or type(permit) is not ActionPermit
                        or type(approval_receipt) is not ActionApprovalConsumptionReceipt
                        or type(grant_receipt)
                        is not AgenticSpecialistCapabilityGrantConsumptionReceipt
                        or permit != started.permit
                        or approval_receipt != started.approval_receipt
                        or grant_receipt != started.grant_consumption_receipt
                        or prepared_action != stored_plan.prepared_action
                        or approval_envelope != stored_plan.approval_envelope
                        or capability_grant.grant_id != stored_plan.grant.grant_id
                        or capability_grant_digest(capability_grant)
                        != stored_plan.grant.grant_digest
                    ):
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 runtime differs from durable authority"
                        )
                    _reverify_planned_specialist_preparation(
                        binding=self.binding,
                        store_id=self.store_id,
                        execution=reserved_execution,
                        preparation=preparation,
                        campaign=campaign,
                    )
                    request_units = _reverify_planned_sql_specialist_v2_action(
                        preparation=preparation,
                        activation=activation,
                        action=prepared_action,
                    )
                    campaign_digest = _require_specialist_dispatch_campaign(
                        binding=self.binding,
                        preparation=preparation,
                        campaign=campaign,
                    )
                    evaluated_at = _SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self)
                    _require_specialist_dispatch_approval(
                        preparation=preparation,
                        action=prepared_action,
                        campaign=campaign,
                        campaign_digest=campaign_digest,
                        grant=capability_grant,
                        approval=approval_envelope,
                        snapshot=snapshot,
                        request_units=request_units,
                        planned_at=evaluated_at,
                    )
                    if (
                        type(approval_authority) is not WebActionApprovalInputAuthority
                        or approval_authority.role != "source"
                        or approval_authority.signed.approval != approval_envelope
                        or WebActionApprovalInputAuthority.verify_action_approval
                        is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
                        or "verify_action_approval" in vars(approval_authority)
                    ):
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 approval authority changed"
                        )
                    _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION(
                        approval_authority,
                        approval_envelope.mission_envelope,
                        approval_envelope.proposal,
                        approval_envelope.graph_decision,
                        approval_envelope,
                    )
                    terminal = _GRAPH_APPROVED_LOOKUP_IMPLEMENTATION(
                        graph_store.approved_permit_store,
                        approval_envelope.approval_id,
                        permit.permit_id,
                    )
                    if terminal is None:
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 Permit terminal evidence is absent"
                        )
                    terminal = ActionApprovalAuthorization.model_validate(
                        terminal.model_dump(mode="json", by_alias=True)
                    )
                    terminal_permit, terminal_receipt = _require_specialist_permit_authorization(
                        plan=stored_plan,
                        authorization=terminal,
                        newly_consumed=False,
                    )
                    if (
                        terminal_permit != permit
                        or terminal_receipt != approval_receipt
                        or not grant_receipt.consumed_at <= evaluated_at
                        or not permit.consumed_at <= evaluated_at < permit.expires_at
                    ):
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 authority is no longer active"
                        )

                _, _, ledger_lock, _ = _SQL_SPECIALIST_V2_LEDGER_RUNTIME_IDENTITY_IMPLEMENTATION(
                    capability_ledger
                )
                with cast(RLockType, ledger_lock):
                    current_lineage = _SQL_SPECIALIST_V2_LINEAGE_OBSERVATION_IMPLEMENTATION(
                        capability_ledger,
                        capability_grant.grant_id,
                    )
                    current_grant, current_remaining, _ = current_lineage[0]
                    if (
                        current_grant != capability_grant
                        or current_remaining != 0
                        or any(revoked for _, _, revoked in current_lineage)
                    ):
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 Grant authority changed"
                        )
                    grant_lineage_state_digest = (
                        _SPECIALIST_CAPABILITY_LINEAGE_STATE_DIGEST_IMPLEMENTATION(current_lineage)
                    )
                    current_snapshot = _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION(
                        self,
                        graph_resolver,
                        graph_head,
                    )
                    if current_snapshot != snapshot:
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 Graph changed during claim"
                        )
                    graph_resolver.require_runtime_store(graph_store, graph_head)
                    claimed_context = _SQLSpecialistV2ClaimedRuntimeContext(
                        started=started,
                        plan=stored_plan,
                        execution=stored_execution,
                        campaign=campaign,
                        preparation=preparation,
                        capability_ledger=capability_ledger,
                        capability_grant=capability_grant,
                        activation=activation,
                        prepared_action=prepared_action,
                        approval_envelope=approval_envelope,
                        graph_store=graph_store,
                        approval_authority=approval_authority,
                        deployment_runtime_identity=deployment_runtime_identity,
                        configured_runtime_identity=configured_runtime_identity,
                        snapshot=snapshot,
                        owner_task=owner_task,
                        database=database,
                        runtime_capsule_token_digest=runtime_capsule_token_digest,
                        grant_lineage_state_digest=grant_lineage_state_digest,
                        claimed_at=evaluated_at,
                    )
                    yield claimed_context
        except AgenticCoordinationError:
            raise
        except (
            AgenticGraphHeadError,
            AttributeError,
            OSError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError(
                "transferred SQL specialist v2 runtime claim failed closed"
            ) from exc
        finally:
            _SQL_SPECIALIST_V2_REQUIRE_OPERATION_IMPLEMENTATION(
                self,
                operation_token,
                owner_task,
            )
            if claimed:
                assert owner_token is not None
                with self.__issued_specialist_dispatch_lock:
                    retained = self.__transferred_sql_specialist_v2_dispatch_capsules.get(plan_id)
                    if (
                        retained is None
                        or retained[0] is not capsule
                        or retained[1] is not started
                        or retained[2] is not owner_task
                        or retained[3] is not owner_token
                        or retained[4] is not database
                    ):
                        raise AgenticCoordinationError(
                            "transferred SQL specialist v2 runtime changed before retirement"
                        )
                    del self.__transferred_sql_specialist_v2_dispatch_capsules[plan_id]
                    with suppress(AgenticCoordinationError):
                        _SQL_SPECIALIST_V2_CAPSULE_RETIRE_IMPLEMENTATION(
                            capsule,
                            owner_token,
                        )
                    _SQL_SPECIALIST_V2_DROP_OWNER_CALLBACK_IMPLEMENTATION(
                        self,
                        owner_task,
                    )
            _SQL_SPECIALIST_V2_RELEASE_OPERATION_IMPLEMENTATION(
                self,
                operation_token,
                owner_task,
            )

    def _require_current_specialist_dispatch_runtime(
        self,
        connection: sqlite3.Connection,
        *,
        requested_plan: AgenticSpecialistDispatchPlanEntry,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSpecialistCapabilityActivation,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        approval_authority: WebActionApprovalInputAuthority,
        snapshot: GraphSnapshot,
        evaluated_at: datetime,
    ) -> tuple[AgenticSpecialistDispatchPlanEntry, AgenticSpecialistExecutionEntry]:
        stored_plan = _specialist_dispatch_plan_from_row(
            _specialist_dispatch_plan_row(connection, requested_plan.plan_id)
        )
        execution = _specialist_execution_from_row(
            _specialist_execution_row(connection, requested_plan.command_id)
        )
        durable_head = _current_checkpoint(connection)
        if (
            stored_plan != requested_plan
            or stored_plan.state is not AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
            or execution.state is not AgenticSpecialistExecutionState.RESERVED
            or durable_head.checkpoint_digest != stored_plan.source_head_checkpoint_digest
            or approval_envelope != stored_plan.approval_envelope
            or prepared_action != stored_plan.prepared_action
            or capability_grant.grant_id != stored_plan.grant.grant_id
            or capability_grant_digest(capability_grant) != stored_plan.grant.grant_digest
        ):
            raise AgenticCoordinationError(
                "specialist Permit runtime differs from the current awaiting plan"
            )
        _reverify_planned_specialist_preparation(
            binding=self.binding,
            store_id=self.store_id,
            execution=execution,
            preparation=preparation,
            campaign=campaign,
        )
        request_units = _reverify_planned_specialist_action(
            preparation=preparation,
            activation=activation,
            action=prepared_action,
        )
        campaign_digest = _require_specialist_dispatch_campaign(
            binding=self.binding,
            preparation=preparation,
            campaign=campaign,
        )
        grant_binding = _specialist_dispatch_grant_binding(
            ledger=capability_ledger,
            grant=capability_grant,
            preparation=preparation,
            action=prepared_action,
        )
        if grant_binding != stored_plan.grant:
            raise AgenticCoordinationError(
                "specialist Capability Grant changed after dispatch planning"
            )
        _require_specialist_dispatch_approval(
            preparation=preparation,
            action=prepared_action,
            campaign=campaign,
            campaign_digest=campaign_digest,
            grant=capability_grant,
            approval=approval_envelope,
            snapshot=snapshot,
            request_units=request_units,
            planned_at=evaluated_at,
        )
        if (
            type(approval_authority) is not WebActionApprovalInputAuthority
            or approval_authority.role != "source"
            or approval_authority.signed.approval != approval_envelope
            or WebActionApprovalInputAuthority.verify_action_approval
            is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
            or "verify_action_approval" in vars(approval_authority)
        ):
            raise AgenticCoordinationError(
                "specialist signed approval verifier changed after binding"
            )
        _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION(
            approval_authority,
            approval_envelope.mission_envelope,
            approval_envelope.proposal,
            approval_envelope.graph_decision,
            approval_envelope,
        )
        return stored_plan, execution

    def _require_current_sql_specialist_v2_dispatch_runtime(
        self,
        connection: sqlite3.Connection,
        *,
        requested_plan: AgenticSQLSpecialistDispatchPlanEntryV2,
        campaign: CampaignManifest,
        preparation: AgenticSpecialistPreparation,
        capability_ledger: CapabilityLedger,
        capability_grant: CapabilityGrant,
        activation: WebSQLSpecialistCapabilityActivationV2,
        prepared_action: PreparedCapabilityAction,
        approval_envelope: ActionApprovalEnvelope,
        approval_authority: WebActionApprovalInputAuthority,
        snapshot: GraphSnapshot,
        evaluated_at: datetime,
    ) -> tuple[AgenticSQLSpecialistDispatchPlanEntryV2, AgenticSpecialistExecutionEntry]:
        stored_plan = _sql_specialist_dispatch_plan_v2_from_row(
            _specialist_dispatch_plan_row(connection, requested_plan.plan_id)
        )
        execution = _specialist_execution_from_row(
            _specialist_execution_row(connection, requested_plan.command_id)
        )
        durable_head = _current_checkpoint(connection)
        if (
            stored_plan != requested_plan
            or stored_plan.runtime_generation
            is not AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
            or stored_plan.state is not AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
            or execution.state is not AgenticSpecialistExecutionState.RESERVED
            or durable_head.checkpoint_digest != stored_plan.source_head_checkpoint_digest
            or approval_envelope != stored_plan.approval_envelope
            or prepared_action != stored_plan.prepared_action
            or capability_grant.grant_id != stored_plan.grant.grant_id
            or capability_grant_digest(capability_grant) != stored_plan.grant.grant_digest
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit runtime differs from its awaiting plan"
            )
        _reverify_planned_specialist_preparation(
            binding=self.binding,
            store_id=self.store_id,
            execution=execution,
            preparation=preparation,
            campaign=campaign,
        )
        request_units = _reverify_planned_sql_specialist_v2_action(
            preparation=preparation,
            activation=activation,
            action=prepared_action,
        )
        campaign_digest = _require_specialist_dispatch_campaign(
            binding=self.binding,
            preparation=preparation,
            campaign=campaign,
        )
        grant_binding = _specialist_dispatch_grant_binding(
            ledger=capability_ledger,
            grant=capability_grant,
            preparation=preparation,
            action=prepared_action,
        )
        if grant_binding != stored_plan.grant:
            raise AgenticCoordinationError(
                "SQL specialist v2 Grant changed after dispatch planning"
            )
        _require_specialist_dispatch_approval(
            preparation=preparation,
            action=prepared_action,
            campaign=campaign,
            campaign_digest=campaign_digest,
            grant=capability_grant,
            approval=approval_envelope,
            snapshot=snapshot,
            request_units=request_units,
            planned_at=evaluated_at,
        )
        if (
            type(approval_authority) is not WebActionApprovalInputAuthority
            or approval_authority.role != "source"
            or approval_authority.signed.approval != approval_envelope
            or WebActionApprovalInputAuthority.verify_action_approval
            is not _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION
            or "verify_action_approval" in vars(approval_authority)
        ):
            raise AgenticCoordinationError(
                "SQL specialist v2 signed approval verifier changed after binding"
            )
        _WEB_ACTION_APPROVAL_VERIFY_IMPLEMENTATION(
            approval_authority,
            approval_envelope.mission_envelope,
            approval_envelope.proposal,
            approval_envelope.graph_decision,
            approval_envelope,
        )
        return stored_plan, execution

    def _enter_planned_specialist_dispatch(
        self,
        plan: VerifiedSpecialistDispatchPlan,
        runtime: VerifiedSpecialistPermitDispatcher,
        *,
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedPlannedSpecialistDispatchStarted:
        owner_task = asyncio.current_task()
        if owner_task is None:
            raise AgenticCoordinationError(
                "specialist Permit callback requires an active asyncio Task"
            )
        (
            campaign,
            preparation,
            capability_ledger,
            capability_grant,
            activation,
            prepared_action,
            approval_envelope,
            graph_store,
            approval_authority,
        ) = runtime._runtime_inputs(self._authority, plan, callback_claimed=True)
        try:
            authorization = ActionApprovalAuthorization(
                approval=approval_envelope,
                action=ActionPermitAuthorization(
                    permit=permit,
                    newlyConsumed=True,
                ),
                receipt=receipt,
            )
            canonical_permit, canonical_receipt = _require_specialist_permit_authorization(
                plan=plan.entry,
                authorization=authorization,
                newly_consumed=True,
            )
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            graph_resolver.require_runtime_store(graph_store, graph_head)
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                stored_plan, execution = self._require_current_specialist_dispatch_runtime(
                    connection,
                    requested_plan=plan.entry,
                    campaign=campaign,
                    preparation=preparation,
                    capability_ledger=capability_ledger,
                    capability_grant=capability_grant,
                    activation=activation,
                    prepared_action=prepared_action,
                    approval_envelope=approval_envelope,
                    approval_authority=approval_authority,
                    snapshot=snapshot,
                    evaluated_at=self._now(),
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                graph_resolver.require_runtime_store(graph_store, graph_head)
                _, _, ledger_lock, _ = _capability_ledger_runtime_identity(capability_ledger)
                with cast(RLockType, ledger_lock):
                    before_lineage = _specialist_capability_lineage_observation(
                        capability_ledger,
                        capability_grant.grant_id,
                    )
                    current_grant, current_remaining, current_revoked = before_lineage[0]
                    if (
                        current_grant != capability_grant
                        or current_remaining != 1
                        or current_revoked
                        or not _CAPABILITY_LEDGER_CAN_CONSUME_IMPLEMENTATION(
                            capability_ledger,
                            capability_grant.grant_id,
                        )
                    ):
                        raise AgenticCoordinationError(
                            "specialist Capability Grant changed before callback entry"
                        )
                    callback_entered_at = self._now()
                    if canonical_permit.issued_at < stored_plan.planned_at:
                        raise AgenticCoordinationError("specialist Permit predates its sealed plan")
                    if not (
                        canonical_permit.issued_at
                        <= canonical_permit.consumed_at
                        <= callback_entered_at
                        < canonical_permit.expires_at
                    ):
                        raise AgenticCoordinationError(
                            "specialist Permit is not active at callback entry"
                        )
                    _CAPABILITY_LEDGER_CONSUME_IMPLEMENTATION(
                        capability_ledger,
                        capability_grant.grant_id,
                    )
                    after_lineage = _specialist_capability_lineage_observation(
                        capability_ledger,
                        capability_grant.grant_id,
                    )
                    _require_specialist_capability_consumption(
                        before=before_lineage,
                        after=after_lineage,
                        expected_grant=capability_grant,
                    )
                    grant_consumed_at = self._now()
                    if not (
                        callback_entered_at <= grant_consumed_at < canonical_permit.expires_at
                        and grant_consumed_at < capability_grant.expires_at
                    ):
                        raise AgenticCoordinationError(
                            "specialist Capability Grant consumption time is outside authority"
                        )
                    grant_receipt = (
                        AgenticSpecialistCapabilityGrantConsumptionReceipt.model_validate(
                            {
                                "storeId": stored_plan.store_id,
                                "coordinationBindingDigest": (
                                    stored_plan.coordination_binding_digest
                                ),
                                "planId": stored_plan.plan_id,
                                "planDigest": stored_plan.plan_digest,
                                "reservationId": stored_plan.reservation_id,
                                "reservationDigest": stored_plan.reservation_digest,
                                "commandId": stored_plan.command_id,
                                "commandDigest": stored_plan.command_digest,
                                "capabilityGrantId": stored_plan.grant.grant_id,
                                "capabilityGrantDigest": stored_plan.grant.grant_digest,
                                "actionPermitId": canonical_permit.permit_id,
                                "actionPermitDigest": canonical_permit.permit_digest,
                                "approvalConsumptionReceiptId": canonical_receipt.receipt_id,
                                "approvalConsumptionReceiptDigest": (
                                    canonical_receipt.receipt_digest
                                ),
                                "consumedCalls": 1,
                                "consumedAt": _format_timestamp(grant_consumed_at),
                            }
                        )
                    )
                    started_execution_state = (
                        AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value
                    )
                    started_plan_state = (
                        AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value
                    )
                    started_execution = AgenticSpecialistExecutionEntry.model_validate(
                        {
                            **execution.model_dump(mode="json", by_alias=True),
                            "state": started_execution_state,
                            "stateDigest": "",
                            "dispatchStartedAt": _format_timestamp(callback_entered_at),
                        }
                    )
                    started_plan = AgenticSpecialistDispatchPlanEntry.model_validate(
                        {
                            **stored_plan.model_dump(mode="json", by_alias=True),
                            "state": started_plan_state,
                            "stateDigest": "",
                            "actionPermit": canonical_permit.model_dump(mode="json", by_alias=True),
                            "approvalConsumptionReceipt": canonical_receipt.model_dump(
                                mode="json", by_alias=True
                            ),
                            "grantConsumptionReceipt": grant_receipt.model_dump(
                                mode="json", by_alias=True
                            ),
                            "callbackEnteredAt": _format_timestamp(callback_entered_at),
                            "reconciledAt": None,
                        }
                    )
                    _cas_specialist_execution_started(
                        connection,
                        before=execution,
                        after=started_execution,
                    )
                    _cas_specialist_dispatch_plan_terminal(
                        connection,
                        before=stored_plan,
                        after=started_plan,
                    )
                self._validate_durable_history(connection, snapshot)
                self._current_graph_snapshot(graph_resolver, graph_head)
                graph_resolver.require_runtime_store(graph_store, graph_head)
                reloaded_execution = _specialist_execution_from_row(
                    _specialist_execution_row(connection, execution.command_id)
                )
                reloaded_plan = _specialist_dispatch_plan_from_row(
                    _specialist_dispatch_plan_row(connection, stored_plan.plan_id)
                )
                if reloaded_execution != started_execution or reloaded_plan != started_plan:
                    raise AgenticCoordinationError(
                        "specialist callback crash fence differs after atomic entry"
                    )
            capsule = _AgenticSpecialistDispatchRuntimeCapsule(
                campaign=campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                activation=activation,
                prepared_action=prepared_action,
                approval_envelope=approval_envelope,
            )
            started = VerifiedPlannedSpecialistDispatchStarted(
                plan=reloaded_plan,
                execution=reloaded_execution,
                permit=canonical_permit,
                receipt=canonical_receipt,
                grant_receipt=grant_receipt,
            )
            with self.__issued_specialist_dispatch_lock:
                self._database.require_open()
                if reloaded_plan.plan_id in self.__issued_specialist_dispatch_started:
                    raise AgenticCoordinationError(
                        "specialist dispatch-started authority was already issued"
                    )
                self.__issued_specialist_dispatch_started[reloaded_plan.plan_id] = (
                    started,
                    capsule,
                    cast(asyncio.Task[object], owner_task),
                    self._database,
                )
                cast_owner_task = cast(asyncio.Task[object], owner_task)
                if cast_owner_task not in self.__issued_specialist_dispatch_owner_tasks:
                    self.__issued_specialist_dispatch_owner_tasks.add(cast_owner_task)
                    cast_owner_task.add_done_callback(
                        self._retire_issued_specialist_dispatch_started
                    )
            return started
        except AgenticCoordinationError:
            raise
        except (
            AgenticGraphHeadError,
            OSError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError(
                "specialist Permit callback entry failed closed"
            ) from exc

    def _enter_planned_sql_specialist_v2_dispatch(
        self,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        runtime: VerifiedSQLSpecialistPermitDispatcherV2,
        *,
        owner_task: asyncio.Task[object],
        owner_token: object,
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> VerifiedPlannedSQLSpecialistDispatchStartedV2:
        if asyncio.current_task() is not owner_task or owner_task.done():
            raise AgenticCoordinationError("SQL specialist v2 callback requires its scheduler Task")
        (
            campaign,
            preparation,
            capability_ledger,
            capability_grant,
            activation,
            prepared_action,
            approval_envelope,
            graph_store,
            approval_authority,
        ) = _SQL_SPECIALIST_V2_DISPATCHER_RUNTIME_INPUTS_IMPLEMENTATION(
            runtime,
            self._authority,
            plan,
            owner_task,
            owner_token,
            callback_claimed=True,
        )
        try:
            authorization = ActionApprovalAuthorization(
                approval=approval_envelope,
                action=ActionPermitAuthorization(
                    permit=permit,
                    newlyConsumed=True,
                ),
                receipt=receipt,
            )
            canonical_permit, canonical_receipt = _require_specialist_permit_authorization(
                plan=plan.entry,
                authorization=authorization,
                newly_consumed=True,
            )
            snapshot = _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION(
                self,
                graph_resolver,
                graph_head,
            )
            graph_resolver.require_runtime_store(graph_store, graph_head)
            with _write_transaction(self._database) as connection:
                _SQL_SPECIALIST_V2_VALIDATE_CONNECTION_IMPLEMENTATION(self, connection)
                _SQL_SPECIALIST_V2_VALIDATE_HISTORY_IMPLEMENTATION(
                    self,
                    connection,
                    snapshot,
                )
                stored_plan, execution = _SQL_SPECIALIST_V2_REQUIRE_CURRENT_RUNTIME_IMPLEMENTATION(
                    self,
                    connection,
                    requested_plan=plan.entry,
                    campaign=campaign,
                    preparation=preparation,
                    capability_ledger=capability_ledger,
                    capability_grant=capability_grant,
                    activation=activation,
                    prepared_action=prepared_action,
                    approval_envelope=approval_envelope,
                    approval_authority=approval_authority,
                    snapshot=snapshot,
                    evaluated_at=_SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self),
                )
                _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION(
                    self,
                    graph_resolver,
                    graph_head,
                )
                graph_resolver.require_runtime_store(graph_store, graph_head)
                _, _, ledger_lock, _ = _capability_ledger_runtime_identity(capability_ledger)
                with cast(RLockType, ledger_lock):
                    before_lineage = _specialist_capability_lineage_observation(
                        capability_ledger,
                        capability_grant.grant_id,
                    )
                    current_grant, current_remaining, current_revoked = before_lineage[0]
                    if (
                        current_grant != capability_grant
                        or current_remaining != 1
                        or current_revoked
                        or not _CAPABILITY_LEDGER_CAN_CONSUME_IMPLEMENTATION(
                            capability_ledger,
                            capability_grant.grant_id,
                        )
                    ):
                        raise AgenticCoordinationError(
                            "SQL specialist v2 Grant changed before callback entry"
                        )
                    callback_entered_at = _SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self)
                    if canonical_permit.issued_at < stored_plan.planned_at:
                        raise AgenticCoordinationError(
                            "SQL specialist v2 Permit predates its sealed plan"
                        )
                    if not (
                        canonical_permit.issued_at
                        <= canonical_permit.consumed_at
                        <= callback_entered_at
                        < canonical_permit.expires_at
                    ):
                        raise AgenticCoordinationError(
                            "SQL specialist v2 Permit is inactive at callback entry"
                        )
                    _CAPABILITY_LEDGER_CONSUME_IMPLEMENTATION(
                        capability_ledger,
                        capability_grant.grant_id,
                    )
                    after_lineage = _specialist_capability_lineage_observation(
                        capability_ledger,
                        capability_grant.grant_id,
                    )
                    _require_specialist_capability_consumption(
                        before=before_lineage,
                        after=after_lineage,
                        expected_grant=capability_grant,
                    )
                    grant_consumed_at = _SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self)
                    if not (
                        callback_entered_at <= grant_consumed_at < canonical_permit.expires_at
                        and grant_consumed_at < capability_grant.expires_at
                    ):
                        raise AgenticCoordinationError(
                            "SQL specialist v2 Grant consumption time is outside authority"
                        )
                    grant_receipt = (
                        AgenticSpecialistCapabilityGrantConsumptionReceipt.model_validate(
                            {
                                "storeId": stored_plan.store_id,
                                "coordinationBindingDigest": (
                                    stored_plan.coordination_binding_digest
                                ),
                                "planId": stored_plan.plan_id,
                                "planDigest": stored_plan.plan_digest,
                                "reservationId": stored_plan.reservation_id,
                                "reservationDigest": stored_plan.reservation_digest,
                                "commandId": stored_plan.command_id,
                                "commandDigest": stored_plan.command_digest,
                                "capabilityGrantId": stored_plan.grant.grant_id,
                                "capabilityGrantDigest": stored_plan.grant.grant_digest,
                                "actionPermitId": canonical_permit.permit_id,
                                "actionPermitDigest": canonical_permit.permit_digest,
                                "approvalConsumptionReceiptId": canonical_receipt.receipt_id,
                                "approvalConsumptionReceiptDigest": (
                                    canonical_receipt.receipt_digest
                                ),
                                "consumedCalls": 1,
                                "consumedAt": _format_timestamp(grant_consumed_at),
                            }
                        )
                    )
                    started_execution = AgenticSpecialistExecutionEntry.model_validate(
                        {
                            **execution.model_dump(mode="json", by_alias=True),
                            "state": (
                                AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value
                            ),
                            "stateDigest": "",
                            "dispatchStartedAt": _format_timestamp(callback_entered_at),
                        }
                    )
                    started_plan = AgenticSQLSpecialistDispatchPlanEntryV2.model_validate(
                        {
                            **stored_plan.model_dump(mode="json", by_alias=True),
                            "state": (
                                AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value
                            ),
                            "stateDigest": "",
                            "actionPermit": canonical_permit.model_dump(
                                mode="json",
                                by_alias=True,
                            ),
                            "approvalConsumptionReceipt": canonical_receipt.model_dump(
                                mode="json",
                                by_alias=True,
                            ),
                            "grantConsumptionReceipt": grant_receipt.model_dump(
                                mode="json",
                                by_alias=True,
                            ),
                            "callbackEnteredAt": _format_timestamp(callback_entered_at),
                            "reconciledAt": None,
                        }
                    )
                    _cas_specialist_execution_started(
                        connection,
                        before=execution,
                        after=started_execution,
                    )
                    _cas_specialist_dispatch_plan_terminal(
                        connection,
                        before=stored_plan,
                        after=started_plan,
                    )
                _SQL_SPECIALIST_V2_VALIDATE_HISTORY_IMPLEMENTATION(
                    self,
                    connection,
                    snapshot,
                )
                _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION(
                    self,
                    graph_resolver,
                    graph_head,
                )
                graph_resolver.require_runtime_store(graph_store, graph_head)
                reloaded_execution = _specialist_execution_from_row(
                    _specialist_execution_row(connection, execution.command_id)
                )
                reloaded_plan = _sql_specialist_dispatch_plan_v2_from_row(
                    _specialist_dispatch_plan_row(connection, stored_plan.plan_id)
                )
                if reloaded_execution != started_execution or reloaded_plan != started_plan:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 crash fence differs after atomic entry"
                    )
            deployment = _SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_IMPLEMENTATION(
                self,
                AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2,
            )
            deployment_runtime_identity = (
                _AGENTIC_SPECIALIST_DEPLOYMENT_RUNTIME_IDENTITY_IMPLEMENTATION(deployment)
            )
            configured_runtime_identity = (
                _AGENTIC_SPECIALIST_CONFIGURED_RUNTIME_IDENTITY_IMPLEMENTATION(deployment)
            )
            if configured_runtime_identity is None:
                raise AgenticCoordinationError(
                    "SQL specialist v2 capsule lacks configured deployment authority"
                )
            capsule = _AgenticSQLSpecialistDispatchRuntimeCapsuleV2(
                campaign=campaign,
                preparation=preparation,
                capability_ledger=capability_ledger,
                capability_grant=capability_grant,
                activation=activation,
                prepared_action=prepared_action,
                approval_envelope=approval_envelope,
                graph_store=graph_store,
                approval_authority=approval_authority,
                deployment_runtime_identity=deployment_runtime_identity,
                configured_runtime_identity=configured_runtime_identity,
                owner_task=owner_task,
                owner_token=owner_token,
            )
            started = VerifiedPlannedSQLSpecialistDispatchStartedV2(
                plan=reloaded_plan,
                execution=reloaded_execution,
                permit=canonical_permit,
                receipt=canonical_receipt,
                grant_receipt=grant_receipt,
            )
            with self.__issued_specialist_dispatch_lock:
                self._database.require_open()
                if reloaded_plan.plan_id in self.__issued_sql_specialist_v2_dispatch_started:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 started authority was already issued"
                    )
                self.__issued_sql_specialist_v2_dispatch_started[reloaded_plan.plan_id] = (
                    started,
                    capsule,
                    owner_task,
                    owner_token,
                    self._database,
                )
                if owner_task not in self.__issued_sql_specialist_v2_dispatch_owner_tasks:
                    self.__issued_sql_specialist_v2_dispatch_owner_tasks.add(owner_task)
                    owner_task.add_done_callback(
                        _SQL_SPECIALIST_V2_RETIRE_CALLBACK_FACTORY_IMPLEMENTATION(self)
                    )
            return started
        except AgenticCoordinationError:
            raise
        except (
            AgenticGraphHeadError,
            OSError,
            sqlite3.Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit callback entry failed closed"
            ) from exc

    def _reconcile_specialist_permit_consumption(
        self,
        plan: VerifiedSpecialistDispatchPlan,
        runtime: VerifiedSpecialistPermitDispatcher,
        *,
        terminal: ActionApprovalAuthorization,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSpecialistDispatchPlanEntry:
        (
            _campaign,
            _preparation,
            _capability_ledger,
            _capability_grant,
            _activation,
            _prepared_action,
            _approval_envelope,
            graph_store,
            _approval_authority,
        ) = runtime._runtime_inputs(self._authority, plan, callback_claimed=True)
        permit, receipt = _require_specialist_permit_authorization(
            plan=plan.entry,
            authorization=terminal,
            newly_consumed=False,
        )
        snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
        graph_resolver.require_runtime_store(graph_store, graph_head)
        with _write_transaction(self._database) as connection:
            self._validate_connection(connection)
            self._validate_durable_history(connection, snapshot)
            stored_plan = _specialist_dispatch_plan_from_row(
                _specialist_dispatch_plan_row(connection, plan.entry.plan_id)
            )
            execution = _specialist_execution_from_row(
                _specialist_execution_row(connection, plan.entry.command_id)
            )
            if stored_plan.plan_digest != plan.entry.plan_digest:
                raise AgenticCoordinationError(
                    "specialist Permit reconciliation plan identity changed"
                )
            if stored_plan.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT:
                if execution.state is not AgenticSpecialistExecutionState.RESERVED:
                    raise AgenticCoordinationError(
                        "specialist Permit reconciliation cannot infer execution entry"
                    )
                reconciled_at = self._now()
                if reconciled_at < permit.consumed_at:
                    raise AgenticCoordinationError(
                        "specialist Permit reconciliation predates consumption"
                    )
                reconciled_state = (
                    AgenticSpecialistDispatchPlanState.PERMIT_CONSUMED_ENTRY_UNKNOWN.value
                )
                reconciled = AgenticSpecialistDispatchPlanEntry.model_validate(
                    {
                        **stored_plan.model_dump(mode="json", by_alias=True),
                        "state": reconciled_state,
                        "stateDigest": "",
                        "actionPermit": permit.model_dump(mode="json", by_alias=True),
                        "approvalConsumptionReceipt": receipt.model_dump(
                            mode="json", by_alias=True
                        ),
                        "grantConsumptionReceipt": None,
                        "callbackEnteredAt": None,
                        "reconciledAt": _format_timestamp(reconciled_at),
                    }
                )
                _cas_specialist_dispatch_plan_terminal(
                    connection,
                    before=stored_plan,
                    after=reconciled,
                )
                stored_plan = reconciled
            elif (
                stored_plan.state
                is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
            ):
                if (
                    execution.state
                    is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or stored_plan.action_permit != permit
                    or stored_plan.approval_consumption_receipt != receipt
                ):
                    raise AgenticCoordinationError(
                        "specialist started state differs from terminal Permit evidence"
                    )
            elif (
                stored_plan.state
                is AgenticSpecialistDispatchPlanState.PERMIT_CONSUMED_ENTRY_UNKNOWN
            ):
                if (
                    execution.state is not AgenticSpecialistExecutionState.RESERVED
                    or stored_plan.action_permit != permit
                    or stored_plan.approval_consumption_receipt != receipt
                ):
                    raise AgenticCoordinationError(
                        "specialist reconciled state differs from terminal Permit evidence"
                    )
            else:
                raise AgenticCoordinationError(
                    "specialist Permit reconciliation reached an unknown plan state"
                )
            self._validate_durable_history(connection, snapshot)
            self._current_graph_snapshot(graph_resolver, graph_head)
            graph_resolver.require_runtime_store(graph_store, graph_head)
            reloaded = _specialist_dispatch_plan_from_row(
                _specialist_dispatch_plan_row(connection, stored_plan.plan_id)
            )
            if reloaded != stored_plan:
                raise AgenticCoordinationError(
                    "specialist Permit reconciliation differs after durable commit"
                )
            return reloaded

    def _resolve_specialist_dispatch_exception(
        self,
        plan: VerifiedSpecialistDispatchPlan,
        runtime: VerifiedSpecialistPermitDispatcher,
        *,
        original: BaseException,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> Never:
        try:
            terminal = runtime._terminal_authorization(self._authority, plan)
        except BaseException as terminal_error:
            plan._consume_callback(self._authority)
            raise AgenticCoordinationError(
                "specialist Permit terminal state is unavailable; redispatch denied"
            ) from terminal_error
        if terminal is None:
            plan._release_callback(self._authority)
            raise original
        try:
            durable = self._reconcile_specialist_permit_consumption(
                plan,
                runtime,
                terminal=terminal,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
        except BaseException as reconciliation_error:
            plan._consume_callback(self._authority)
            raise AgenticCoordinationError(
                "specialist Permit was consumed but durable callback entry is unknown"
            ) from reconciliation_error
        plan._consume_callback(self._authority)
        if durable.state is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN:
            raise AgenticCoordinationError(
                "specialist callback entered durably but its returned authority was lost"
            ) from original
        raise AgenticCoordinationError(
            "specialist Permit was consumed but callback entry is unproven"
        ) from original

    def _reconcile_sql_specialist_v2_permit_consumption(
        self,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        runtime: VerifiedSQLSpecialistPermitDispatcherV2,
        *,
        owner_task: asyncio.Task[object],
        owner_token: object,
        terminal: ActionApprovalAuthorization,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSQLSpecialistDispatchPlanEntryV2:
        (
            _campaign,
            _preparation,
            _capability_ledger,
            _capability_grant,
            _activation,
            _prepared_action,
            _approval_envelope,
            graph_store,
            _approval_authority,
        ) = runtime._runtime_inputs(
            self._authority,
            plan,
            owner_task,
            owner_token,
            callback_claimed=True,
        )
        permit, receipt = _require_specialist_permit_authorization(
            plan=plan.entry,
            authorization=terminal,
            newly_consumed=False,
        )
        snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
        graph_resolver.require_runtime_store(graph_store, graph_head)
        with _write_transaction(self._database) as connection:
            self._validate_connection(connection)
            self._validate_durable_history(connection, snapshot)
            stored_plan = _sql_specialist_dispatch_plan_v2_from_row(
                _specialist_dispatch_plan_row(connection, plan.entry.plan_id)
            )
            execution = _specialist_execution_from_row(
                _specialist_execution_row(connection, plan.entry.command_id)
            )
            if stored_plan.plan_digest != plan.entry.plan_digest:
                raise AgenticCoordinationError(
                    "SQL specialist v2 Permit reconciliation plan identity changed"
                )
            if stored_plan.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT:
                if execution.state is not AgenticSpecialistExecutionState.RESERVED:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 reconciliation cannot infer execution entry"
                    )
                reconciled_at = self._now()
                if reconciled_at < permit.consumed_at:
                    raise AgenticCoordinationError(
                        "SQL specialist v2 reconciliation predates Permit consumption"
                    )
                reconciled = AgenticSQLSpecialistDispatchPlanEntryV2.model_validate(
                    {
                        **stored_plan.model_dump(mode="json", by_alias=True),
                        "state": (
                            AgenticSpecialistDispatchPlanState.PERMIT_CONSUMED_ENTRY_UNKNOWN.value
                        ),
                        "stateDigest": "",
                        "actionPermit": permit.model_dump(mode="json", by_alias=True),
                        "approvalConsumptionReceipt": receipt.model_dump(
                            mode="json",
                            by_alias=True,
                        ),
                        "grantConsumptionReceipt": None,
                        "callbackEnteredAt": None,
                        "reconciledAt": _format_timestamp(reconciled_at),
                    }
                )
                _cas_specialist_dispatch_plan_terminal(
                    connection,
                    before=stored_plan,
                    after=reconciled,
                )
                stored_plan = reconciled
            elif (
                stored_plan.state
                is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
            ):
                if (
                    execution.state
                    is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    or stored_plan.action_permit != permit
                    or stored_plan.approval_consumption_receipt != receipt
                ):
                    raise AgenticCoordinationError(
                        "SQL specialist v2 started state differs from Permit evidence"
                    )
            elif (
                stored_plan.state
                is AgenticSpecialistDispatchPlanState.PERMIT_CONSUMED_ENTRY_UNKNOWN
            ):
                if (
                    execution.state is not AgenticSpecialistExecutionState.RESERVED
                    or stored_plan.action_permit != permit
                    or stored_plan.approval_consumption_receipt != receipt
                ):
                    raise AgenticCoordinationError(
                        "SQL specialist v2 reconciled state differs from Permit evidence"
                    )
            else:
                raise AgenticCoordinationError(
                    "SQL specialist v2 reconciliation reached an unknown plan state"
                )
            self._validate_durable_history(connection, snapshot)
            self._current_graph_snapshot(graph_resolver, graph_head)
            graph_resolver.require_runtime_store(graph_store, graph_head)
            reloaded = _sql_specialist_dispatch_plan_v2_from_row(
                _specialist_dispatch_plan_row(connection, stored_plan.plan_id)
            )
            if reloaded != stored_plan:
                raise AgenticCoordinationError(
                    "SQL specialist v2 reconciliation differs after durable commit"
                )
            return reloaded

    def _resolve_sql_specialist_v2_dispatch_exception(
        self,
        plan: VerifiedSQLSpecialistDispatchPlanV2,
        runtime: VerifiedSQLSpecialistPermitDispatcherV2,
        *,
        owner_task: asyncio.Task[object],
        owner_token: object,
        original: BaseException,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> Never:
        try:
            terminal = runtime._terminal_authorization(
                self._authority,
                plan,
                owner_task,
                owner_token,
            )
        except BaseException as terminal_error:
            plan._consume_callback(self._authority, owner_task, owner_token)
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit terminal state is unavailable; redispatch denied"
            ) from terminal_error
        if terminal is None:
            plan._release_callback(self._authority, owner_task, owner_token)
            raise original
        try:
            durable = self._reconcile_sql_specialist_v2_permit_consumption(
                plan,
                runtime,
                owner_task=owner_task,
                owner_token=owner_token,
                terminal=terminal,
                graph_resolver=graph_resolver,
                graph_head=graph_head,
            )
        except BaseException as reconciliation_error:
            plan._consume_callback(self._authority, owner_task, owner_token)
            raise AgenticCoordinationError(
                "SQL specialist v2 Permit was consumed but callback entry is unknown"
            ) from reconciliation_error
        plan._consume_callback(self._authority, owner_task, owner_token)
        if durable.state is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN:
            raise AgenticCoordinationError(
                "SQL specialist v2 callback entered durably but its authority was lost"
            ) from original
        raise AgenticCoordinationError(
            "SQL specialist v2 Permit was consumed but callback entry is unproven"
        ) from original

    def specialist_dispatch_plan_entry(
        self,
        *,
        plan_id: str,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSpecialistDispatchPlanEntry:
        """Return one audit-only plan without reconstructing process-local authority."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            _require_identifier(plan_id, label="specialist dispatch Plan ID")
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                plan = _specialist_dispatch_plan_from_row(
                    _specialist_dispatch_plan_row(connection, plan_id)
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                return plan
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist dispatch plan audit read failed closed"
            ) from exc

    def sql_specialist_dispatch_plan_v2_entry(
        self,
        *,
        plan_id: str,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSQLSpecialistDispatchPlanEntryV2:
        """Return SQL v2 audit data without recreating Task or Permit authority."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            _require_identifier(plan_id, label="SQL specialist v2 dispatch Plan ID")
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                plan = _sql_specialist_dispatch_plan_v2_from_row(
                    _specialist_dispatch_plan_row(connection, plan_id)
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                return plan
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "SQL specialist v2 dispatch plan audit read failed closed"
            ) from exc

    def specialist_execution_entry(
        self,
        *,
        command_id: str,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSpecialistExecutionEntry:
        """Return an audit-only execution entry without reissuing dispatch authority."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            _require_identifier(command_id, label="specialist execution Command ID")
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                entry = _specialist_execution_from_row(
                    _specialist_execution_row(connection, command_id)
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                return entry
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("specialist execution audit read failed closed") from exc

    def claim_hypothesis_invocation(
        self,
        head: VerifiedAgenticDurableHead,
        context: HypothesisExpansionContext,
        projection: HypothesisModelProjection,
        *,
        request_binding: AgenticHypothesisRequestBinding,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticModelInvocationEntry:
        """Durably claim one exact projection/request coordinate before dispatch."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            self._require_local_handle(head)
            canonical_context = HypothesisExpansionContext.model_validate(
                context.model_dump(mode="json", by_alias=True)
            )
            canonical_projection = HypothesisModelProjection.model_validate(
                projection.model_dump(mode="json", by_alias=True)
            )
            canonical_request = AgenticHypothesisRequestBinding.model_validate(
                request_binding.model_dump(mode="json", by_alias=True)
            )
            expected_projection = build_hypothesis_model_projection(
                canonical_context,
                source_snapshot=snapshot,
            )
            if canonical_projection != expected_projection:
                raise ValueError("Hypothesis Projection differs from current Graph-bound Context")
            self._require_expansion_binding(
                head.checkpoint,
                canonical_context,
                canonical_projection,
            )
            if canonical_request.projection != canonical_projection:
                raise ValueError("request binding projection differs")
            stable_request_id = _stable_hypothesis_request_id(
                binding_digest=self.binding.binding_digest,
                source_checkpoint_digest=head.checkpoint.checkpoint_digest,
            )
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                current = _current_checkpoint(connection)
                if current != head.checkpoint:
                    raise AgenticCoordinationError(
                        "Hypothesis invocation source checkpoint is stale"
                    )
                existing = connection.execute(
                    "SELECT * FROM agentic_model_invocations WHERE stable_request_id = ?",
                    (stable_request_id,),
                ).fetchone()
                if existing is not None:
                    entry = _invocation_from_row(existing)
                    intent = entry.intent
                    if (
                        intent.provider_run_id != canonical_request.planned_provider_run_id
                        or intent.request_binding != canonical_request
                        or intent.context != canonical_context
                        or intent.context_id != canonical_context.context_id
                        or intent.context_digest != canonical_context.context_digest
                        or intent.projection_id != canonical_projection.projection_id
                        or intent.projection_digest != canonical_projection.projection_digest
                        or intent.source_checkpoint_digest != head.checkpoint.checkpoint_digest
                    ):
                        raise AgenticCoordinationError(
                            "Hypothesis invocation request was equivocated"
                        )
                    return entry
                claimed_at = self._now()
                intent = AgenticHypothesisInvocationIntent(
                    stableRequestId=stable_request_id,
                    storeId=self.store_id,
                    coordinationBindingId=self.binding.binding_id,
                    coordinationBindingDigest=self.binding.binding_digest,
                    sourceCheckpointId=head.checkpoint.checkpoint_id,
                    sourceCheckpointDigest=head.checkpoint.checkpoint_digest,
                    contextId=canonical_context.context_id,
                    contextDigest=canonical_context.context_digest,
                    context=canonical_context,
                    projectionId=canonical_projection.projection_id,
                    projectionDigest=canonical_projection.projection_digest,
                    requestBindingId=canonical_request.request_binding_id,
                    requestBindingDigest=canonical_request.request_binding_digest,
                    requestBinding=canonical_request,
                    providerRunId=canonical_request.planned_provider_run_id,
                    claimedAt=cast(datetime, _format_timestamp(claimed_at)),
                )
                state_digest = _invocation_state_digest(
                    intent_digest=intent.intent_digest,
                    state=AgenticModelInvocationState.CLAIMED,
                    dispatch_started_at=None,
                    terminal_at=None,
                    outcome_digest=None,
                    receipt_reference=None,
                    receipt_digest=None,
                    receipt_run_path=None,
                    receipt_run_id=None,
                    receipt_root_digest=None,
                    receipt_artifact_path=None,
                    receipt_artifact_sha256=None,
                )
                connection.execute(
                    """
                    INSERT INTO agentic_model_invocations(
                        intent_id, intent_digest, stable_request_id, provider_run_id,
                        source_checkpoint_digest, context_digest, projection_digest,
                        request_binding_digest, canonical_intent, state,
                        dispatch_started_at, terminal_at, outcome_digest,
                        receipt_reference, receipt_digest, receipt_run_path,
                        receipt_run_id, receipt_root_digest, receipt_artifact_path,
                        receipt_artifact_sha256, state_digest
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL,
                              NULL, NULL, NULL, NULL, NULL, ?)
                    """,
                    (
                        intent.intent_id,
                        intent.intent_digest,
                        intent.stable_request_id,
                        intent.provider_run_id,
                        intent.source_checkpoint_digest,
                        intent.context_digest,
                        intent.projection_digest,
                        intent.request_binding_digest,
                        sqlite3.Binary(_intent_bytes(intent)),
                        AgenticModelInvocationState.CLAIMED.value,
                        state_digest,
                    ),
                )
                return _invocation_from_row(_invocation_row(connection, intent.intent_id))
        except AgenticCoordinationError:
            raise
        except sqlite3.IntegrityError as exc:
            raise AgenticCoordinationError(
                "Hypothesis invocation claim conflicted with durable authority"
            ) from exc
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("Hypothesis invocation claim failed closed") from exc

    def begin_hypothesis_dispatch(
        self,
        entry: AgenticModelInvocationEntry,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticModelInvocationEntry:
        """Consume the only dispatch transition; retries remain outcome-unknown."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            expected = AgenticModelInvocationEntry.model_validate(
                entry.model_dump(mode="json", by_alias=True)
            )
            self._require_invocation_store(expected)
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                current = _invocation_from_row(
                    _invocation_row(connection, expected.intent.intent_id)
                )
                self._require_current_invocation_context(snapshot, current.intent)
                if current != expected:
                    raise AgenticCoordinationError(
                        "Hypothesis dispatch claim differs from durable state"
                    )
                if current.state is not AgenticModelInvocationState.CLAIMED:
                    raise AgenticCoordinationError(
                        "Hypothesis dispatch already started; redispatch denied"
                    )
                if (
                    _current_checkpoint(connection).checkpoint_digest
                    != current.intent.source_checkpoint_digest
                ):
                    raise AgenticCoordinationError(
                        "Hypothesis dispatch checkpoint is no longer current"
                    )
                started_at = self._now()
                if started_at < current.intent.claimed_at:
                    raise AgenticCoordinationError(
                        "Hypothesis dispatch timestamp predates its durable claim"
                    )
                state_digest = _invocation_state_digest(
                    intent_digest=current.intent.intent_digest,
                    state=AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
                    dispatch_started_at=started_at,
                    terminal_at=None,
                    outcome_digest=None,
                    receipt_reference=None,
                    receipt_digest=None,
                    receipt_run_path=None,
                    receipt_run_id=None,
                    receipt_root_digest=None,
                    receipt_artifact_path=None,
                    receipt_artifact_sha256=None,
                )
                cursor = connection.execute(
                    """
                    UPDATE agentic_model_invocations
                    SET state = ?, dispatch_started_at = ?, state_digest = ?
                    WHERE intent_id = ? AND state = ? AND state_digest = ?
                    """,
                    (
                        AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value,
                        _format_timestamp(started_at),
                        state_digest,
                        current.intent.intent_id,
                        AgenticModelInvocationState.CLAIMED.value,
                        current.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgenticCoordinationError("Hypothesis dispatch claim lost its atomic race")
                return _invocation_from_row(_invocation_row(connection, current.intent.intent_id))
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("Hypothesis dispatch claim failed closed") from exc

    def finalize_hypothesis_invocation(
        self,
        entry: AgenticModelInvocationEntry,
        *,
        publication: AgenticHypothesisReceiptPublication,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticModelInvocationEntry:
        """Strict-reload and bind one sealed terminal claim without redispatch."""

        try:
            self._current_graph_snapshot(graph_resolver, graph_head)
            expected = AgenticModelInvocationEntry.model_validate(
                entry.model_dump(mode="json", by_alias=True)
            )
            self._require_invocation_store(expected)
            verified_publication = _verified_hypothesis_receipt_publication(
                publication,
                expected_entry=expected,
            )
            receipt = verified_publication.receipt
            terminal_state = (
                AgenticModelInvocationState.TERMINAL_SUCCESS
                if receipt.terminal_state == "success"
                else AgenticModelInvocationState.TERMINAL_FAILURE
            )
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                current = _invocation_from_row(
                    _invocation_row(connection, expected.intent.intent_id)
                )
                self._require_current_invocation_context(snapshot, current.intent)
                if current.state in {
                    AgenticModelInvocationState.TERMINAL_SUCCESS,
                    AgenticModelInvocationState.TERMINAL_FAILURE,
                }:
                    if (
                        current.state is terminal_state
                        and current.outcome_digest == receipt.outcome_digest
                        and current.receipt_reference == receipt.receipt_id
                        and current.receipt_digest == receipt.receipt_digest
                        and current.receipt_run_path == str(verified_publication.run_path)
                        and current.receipt_run_id == verified_publication.run_id
                        and current.receipt_root_digest == verified_publication.root_digest
                        and current.receipt_artifact_path == verified_publication.artifact_path
                        and current.receipt_artifact_sha256 == verified_publication.artifact_sha256
                        and current.terminal_at is not None
                        and receipt.recorded_at <= current.terminal_at
                    ):
                        return current
                    raise AgenticCoordinationError(
                        "Hypothesis invocation terminal receipt was equivocated"
                    )
                if (
                    current != expected
                    or current.state
                    is not AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                ):
                    raise AgenticCoordinationError(
                        "only the exact started Hypothesis invocation may be finalized"
                    )
                terminal_at = self._now()
                if receipt.recorded_at > terminal_at:
                    raise AgenticCoordinationError(
                        "sealed invocation receipt postdates durable terminal publication"
                    )
                state_digest = _invocation_state_digest(
                    intent_digest=current.intent.intent_digest,
                    state=terminal_state,
                    dispatch_started_at=current.dispatch_started_at,
                    terminal_at=terminal_at,
                    outcome_digest=receipt.outcome_digest,
                    receipt_reference=receipt.receipt_id,
                    receipt_digest=receipt.receipt_digest,
                    receipt_run_path=str(verified_publication.run_path),
                    receipt_run_id=verified_publication.run_id,
                    receipt_root_digest=verified_publication.root_digest,
                    receipt_artifact_path=verified_publication.artifact_path,
                    receipt_artifact_sha256=verified_publication.artifact_sha256,
                )
                cursor = connection.execute(
                    """
                    UPDATE agentic_model_invocations
                    SET state = ?, terminal_at = ?, outcome_digest = ?,
                        receipt_reference = ?, receipt_digest = ?, receipt_run_path = ?,
                        receipt_run_id = ?, receipt_root_digest = ?, receipt_artifact_path = ?,
                        receipt_artifact_sha256 = ?, state_digest = ?
                    WHERE intent_id = ? AND state = ? AND state_digest = ?
                    """,
                    (
                        terminal_state.value,
                        _format_timestamp(terminal_at),
                        receipt.outcome_digest,
                        receipt.receipt_id,
                        receipt.receipt_digest,
                        str(verified_publication.run_path),
                        verified_publication.run_id,
                        verified_publication.root_digest,
                        verified_publication.artifact_path,
                        verified_publication.artifact_sha256,
                        state_digest,
                        current.intent.intent_id,
                        AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value,
                        current.state_digest,
                    ),
                )
                if cursor.rowcount != 1:
                    raise AgenticCoordinationError(
                        "Hypothesis invocation finalization lost its atomic race"
                    )
                return _invocation_from_row(_invocation_row(connection, current.intent.intent_id))
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "Hypothesis invocation finalization failed closed"
            ) from exc

    def _specialist_job_attempt_database_identity_digest(self) -> str:
        """Return a non-bearer digest of the pinned coordination database identity."""

        database = self._database
        if (
            type(database) is not _LinuxPinnedCoordinationDatabase
            or database is not self.__database_identity
        ):
            raise AgenticCoordinationError(
                "coordination Store database identity changed before job attempt"
            )
        database.require_open()
        return discovery_digest(
            "pajin.agentic.coordination-database-identity/v1",
            list(database.database_identity),
        )

    def _record_specialist_job_attempt(
        self,
        attempt: AgenticSpecialistJobAttempt,
        *,
        authority: object,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
        require_new: bool = False,
    ) -> AgenticSpecialistJobAttempt:
        """Insert one pre-backend attempt exactly once without dispatching it."""

        try:
            if authority is not self._authority or type(require_new) is not bool:
                raise AgenticCoordinationError(
                    "specialist job-attempt insertion lacks Store authority"
                )
            self._require_specialist_deployment(
                AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
            )
            canonical = AgenticSpecialistJobAttempt.model_validate(
                attempt.model_dump(mode="json", by_alias=True)
            )
            if canonical != attempt:
                raise AgenticCoordinationError("specialist job attempt differs after strict reload")
            if canonical.state is not AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND:
                raise AgenticCoordinationError(
                    "new specialist job attempt must precede backend dispatch"
                )
            if (
                canonical.specialization is not PentestSpecialization.SQL_INJECTION
                or canonical.capability_id != _EXECUTABLE_SPECIALIST_CAPABILITY_ID
                or canonical.capability_version != _EXECUTABLE_SPECIALIST_CAPABILITY_VERSION
                or canonical.tool_id != _EXECUTABLE_SPECIALIST_TOOL_ID
                or canonical.tool_version != _EXECUTABLE_SPECIALIST_TOOL_VERSION
            ):
                raise AgenticCoordinationError(
                    "specialist job attempt is not the exact executable v2 contract"
                )
            expected_database = self._specialist_job_attempt_database_identity_digest()
            if canonical.database_identity_digest != expected_database:
                raise AgenticCoordinationError(
                    "specialist job attempt references another coordination database"
                )
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            if (
                canonical.graph_snapshot_id != snapshot.snapshot_id
                or canonical.graph_snapshot_digest != snapshot.snapshot_digest
            ):
                raise AgenticCoordinationError(
                    "specialist job attempt references a stale Graph snapshot"
                )
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                self._current_graph_snapshot(graph_resolver, graph_head)
                plan = _sql_specialist_dispatch_plan_v2_from_row(
                    _specialist_dispatch_plan_row(connection, canonical.plan_id)
                )
                permit = plan.action_permit
                if (
                    permit is None
                    or plan.runtime_generation
                    is not AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
                    or canonical.scheduler_task_token_digest != plan.scheduler_task_token_digest
                    or canonical.preparation_id != plan.preparation_id
                    or canonical.preparation_digest != plan.preparation_digest
                    or canonical.capability_grant_id != plan.grant.grant_id
                    or canonical.capability_grant_digest != plan.grant.grant_digest
                    or canonical.capability_grant_expires_at != plan.grant.expires_at
                    or canonical.action_permit_id != permit.permit_id
                    or canonical.action_permit_digest != permit.permit_digest
                    or canonical.action_permit_expires_at != permit.expires_at
                    or canonical.approval_id != plan.approval_envelope.approval_id
                    or canonical.approval_digest != plan.approval_envelope.approval_digest
                    or canonical.approval_expires_at != plan.approval_envelope.expires_at
                ):
                    raise AgenticCoordinationError(
                        "specialist job attempt differs from its live authority lineage"
                    )
                existing = connection.execute(
                    "SELECT * FROM agentic_specialist_job_attempts "
                    "WHERE plan_id = ? OR attempt_id = ? OR dispatch_binding_id = ?",
                    (
                        canonical.plan_id,
                        canonical.attempt_id,
                        canonical.dispatch_binding_id,
                    ),
                ).fetchone()
                if existing is not None:
                    observed = _specialist_job_attempt_from_row(cast(sqlite3.Row, existing))
                    if (
                        observed.attempt_id != canonical.attempt_id
                        or observed.attempt_digest != canonical.attempt_digest
                        or observed.plan_id != canonical.plan_id
                        or observed.dispatch_binding_id != canonical.dispatch_binding_id
                        or observed.dispatch_binding_digest != canonical.dispatch_binding_digest
                    ):
                        raise AgenticCoordinationError(
                            "specialist dispatch plan job attempt was equivocated"
                        )
                    if require_new:
                        raise AgenticCoordinationError(
                            "existing specialist JobAttempt cannot mint live authority"
                        )
                    return observed
                _insert_specialist_job_attempt(connection, canonical)
                self._validate_durable_history(connection, snapshot)
                reloaded = _specialist_job_attempt_from_row(
                    _specialist_job_attempt_row(connection, canonical.attempt_id)
                )
                if reloaded != canonical:
                    raise AgenticCoordinationError(
                        "specialist job attempt differs after durable insertion"
                    )
                self._current_graph_snapshot(graph_resolver, graph_head)
                return reloaded
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist job-attempt insertion failed closed"
            ) from exc

    def _mark_specialist_job_attempt_dispatched(
        self,
        *,
        authority: object,
        attempt_id: str,
        attempt_digest: str,
        state_digest: str,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticSpecialistJobAttempt:
        """Commit the dispatch marker synchronously before any backend await."""

        try:
            if authority is not self._authority:
                raise AgenticCoordinationError(
                    "specialist backend dispatch marking lacks Store authority"
                )
            self._require_specialist_deployment(
                AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
            )
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                self._validate_durable_history(connection, snapshot)
                current = _specialist_job_attempt_from_row(
                    _specialist_job_attempt_row(connection, attempt_id)
                )
                if (
                    current.attempt_digest != attempt_digest
                    or current.state_digest != state_digest
                    or current.state is not AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
                ):
                    raise AgenticCoordinationError(
                        "specialist job attempt is not the exact pre-backend claim"
                    )
                if _specialist_terminal_receipt_row(connection, attempt_id) is not None:
                    raise AgenticCoordinationError(
                        "specialist job attempt already has a terminal receipt"
                    )
                plan = _sql_specialist_dispatch_plan_v2_from_row(
                    _specialist_dispatch_plan_row(connection, current.plan_id)
                )
                permit = plan.action_permit
                started_at = self._now()
                if (
                    permit is None
                    or current.capability_grant_id != plan.grant.grant_id
                    or current.capability_grant_digest != plan.grant.grant_digest
                    or current.capability_grant_expires_at != plan.grant.expires_at
                    or current.action_permit_id != permit.permit_id
                    or current.action_permit_digest != permit.permit_digest
                    or current.action_permit_expires_at != permit.expires_at
                    or current.approval_id != plan.approval_envelope.approval_id
                    or current.approval_digest != plan.approval_envelope.approval_digest
                    or current.approval_expires_at != plan.approval_envelope.expires_at
                ):
                    raise AgenticCoordinationError(
                        "specialist job-attempt authority lineage changed before dispatch"
                    )
                handoff_deadline = min(
                    deadline
                    for deadline in (
                        permit.expires_at,
                        plan.grant.expires_at,
                        plan.approval_envelope.expires_at,
                    )
                )
                if not started_at < handoff_deadline:
                    raise AgenticCoordinationError(
                        "specialist job-attempt authority expired before backend dispatch"
                    )
                current_snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                if (
                    current.graph_snapshot_id != current_snapshot.snapshot_id
                    or current.graph_snapshot_digest != current_snapshot.snapshot_digest
                ):
                    raise AgenticCoordinationError(
                        "specialist job-attempt Graph changed before backend dispatch"
                    )
                dispatch_verification = _SPECIALIST_DISPATCH_VERIFICATION_BUILD_IMPLEMENTATION(
                    current,
                    verified_at=started_at,
                    backend_handoff_deadline=handoff_deadline,
                )
                started = AgenticSpecialistJobAttempt.model_validate(
                    {
                        **current.model_dump(mode="json", by_alias=True),
                        "state": (
                            AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value
                        ),
                        "stateDigest": "",
                        "dispatchVerification": dispatch_verification.model_dump(
                            mode="json",
                            by_alias=True,
                        ),
                        "dispatchVerificationDigest": (dispatch_verification.verification_digest),
                        "dispatchEventDigest": None,
                        "backendDispatchStartedAt": _format_timestamp(started_at),
                    }
                )
                _cas_specialist_job_attempt_started(
                    connection,
                    before=current,
                    after=started,
                )
                self._validate_durable_history(connection, snapshot)
                reloaded = _specialist_job_attempt_from_row(
                    _specialist_job_attempt_row(connection, current.attempt_id)
                )
                if reloaded != started:
                    raise AgenticCoordinationError(
                        "specialist backend dispatch marker differs after commit"
                    )
                self._current_graph_snapshot(graph_resolver, graph_head)
                return reloaded
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist backend dispatch marking failed closed"
            ) from exc

    def _build_sql_specialist_v2_zero_io_terminal_receipt(
        self,
        attempt: AgenticSpecialistJobAttempt,
        completion: _VerifiedSpecialistGatewayCompletionV2,
        *,
        authority: object,
        deployment: VerifiedSpecialistGatewayDeploymentV2,
        deployment_claim: _VerifiedSpecialistGatewayDeploymentMintLeaseV2,
        owner_task: asyncio.Task[object],
        owner_token: object,
    ) -> AgenticSpecialistTerminalReceipt:
        """Derive one proven terminal zero-I/O receipt from verified backend output."""

        try:
            if (
                authority is not self._authority
                or type(completion) is not _VerifiedSpecialistGatewayCompletionV2
                or type(deployment) is not VerifiedSpecialistGatewayDeploymentV2
                or type(deployment_claim)
                is not _VerifiedSpecialistGatewayDeploymentMintLeaseV2
                or type(owner_task) is not asyncio.Task
                or owner_task is not asyncio.current_task()
                or owner_task.done()
            ):
                raise AgenticCoordinationError(
                    "specialist proven terminal construction lacks Store authority"
                )
            canonical_attempt = AgenticSpecialistJobAttempt.model_validate(
                attempt.model_dump(mode="json", by_alias=True)
            )
            if (
                canonical_attempt != attempt
                or canonical_attempt.state
                is not AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                or canonical_attempt.dispatch_verification_digest is None
            ):
                raise AgenticCoordinationError(
                    "specialist proven terminal requires the exact started attempt"
                )
            envelope, signed_result, worker_result_digest = (
                _VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION(
                    completion,
                    claim_authority=_DEPLOYMENT_CLAIM_AUTHORITY,
                    deployment=deployment,
                    lease=deployment_claim,
                    store_identity_token=self._authority,
                    owner_task=owner_task,
                    owner_token=owner_token,
                    attempt_digest=canonical_attempt.attempt_digest,
                    dispatch_verification_digest=(
                        canonical_attempt.dispatch_verification_digest
                    ),
                )
            )
            canonical_result = SignedSpecialistBackendResultV2.model_validate(
                signed_result.model_dump(mode="json", by_alias=True)
            )
            statement = canonical_result.statement
            if (
                canonical_result != signed_result
                or envelope.attempt_digest != canonical_attempt.attempt_digest
                or envelope.dispatch_verification_digest
                != canonical_attempt.dispatch_verification_digest
                or statement.launch_envelope_id != envelope.envelope_id
                or statement.launch_envelope_digest != envelope.envelope_digest
                or statement.attempt_digest != canonical_attempt.attempt_digest
                or statement.dispatch_verification_digest
                != canonical_attempt.dispatch_verification_digest
                or statement.runtime_inventory_id != canonical_attempt.execution_inventory_id
                or statement.runtime_inventory_digest
                != canonical_attempt.execution_inventory_digest
                or statement.worker_backend_id != canonical_attempt.worker_backend_id
                or statement.worker_backend_version != canonical_attempt.worker_backend_version
                or statement.worker_backend_digest != canonical_attempt.worker_backend_digest
                or statement.worker_command_digest != canonical_attempt.worker_command_digest
                or statement.worker_compiler_id != canonical_attempt.worker_compiler_id
                or statement.worker_compiler_version != canonical_attempt.worker_compiler_version
                or statement.worker_compiler_digest != canonical_attempt.worker_compiler_digest
                or statement.worker_image_reference != canonical_attempt.worker_image_reference
                or statement.worker_image_digest != canonical_attempt.worker_image_digest
                or statement.worker_verifier_id != canonical_attempt.worker_verifier_id
                or statement.worker_verifier_version != canonical_attempt.worker_verifier_version
                or statement.worker_verifier_digest != canonical_attempt.worker_verifier_digest
                or statement.verification_key_id
                != canonical_attempt.worker_verification_key_id
                or statement.verification_key_digest
                != canonical_attempt.worker_verification_key_digest
                or statement.backend_terminal_proven is not True
                or statement.conformance_succeeded is not True
                or statement.backend_invoked is not True
                or statement.target_io_performed is not False
                or statement.network_mode != "none"
                or statement.production_authority_eligible is not False
                or statement.gateway_authority is not False
                or statement.execution_authority is not False
                or statement.independent_validation is not False
                or any(
                    marker is not False
                    for marker in (
                        statement.finding,
                        statement.graph,
                        statement.report,
                        statement.sarif,
                        statement.poc,
                    )
                )
            ):
                raise AgenticCoordinationError(
                    "verified specialist backend result differs from its started attempt"
                )
            terminal_reason_digest = discovery_digest(
                "pajin.agentic.sql-specialist-v2-zero-io-terminal-reason/v1",
                {
                    "attemptDigest": canonical_attempt.attempt_digest,
                    "attemptStateDigest": canonical_attempt.state_digest,
                    "terminalClassification": statement.terminal_classification,
                    "workerResultDigest": worker_result_digest,
                },
            )
            proof_digest = discovery_digest(
                "pajin.agentic.sql-specialist-v2-backend-terminal-proof/v1",
                {
                    "attemptDigest": canonical_attempt.attempt_digest,
                    "attemptStateDigest": canonical_attempt.state_digest,
                    "dispatchVerificationDigest": (
                        canonical_attempt.dispatch_verification_digest
                    ),
                    "launchEnvelopeDigest": statement.launch_envelope_digest,
                    "workerResultDigest": worker_result_digest,
                    "statementSha256": canonical_result.statement_sha256,
                    "signatureBase64url": canonical_result.signature_base64url,
                    "workerVerifierDigest": canonical_attempt.worker_verifier_digest,
                    "verificationKeyDigest": (
                        canonical_attempt.worker_verification_key_digest
                    ),
                    "executionInventoryDigest": (
                        canonical_attempt.execution_inventory_digest
                    ),
                },
            )
            recorded_at = max(
                _SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self),
                statement.finished_at,
            )
            receipt = AgenticSpecialistTerminalReceipt.model_validate(
                {
                    "storeId": self.store_id,
                    "coordinationBindingDigest": self.binding.binding_digest,
                    "attemptId": canonical_attempt.attempt_id,
                    "attemptDigest": canonical_attempt.attempt_digest,
                    "attemptState": canonical_attempt.state.value,
                    "attemptStateDigest": canonical_attempt.state_digest,
                    "planId": canonical_attempt.plan_id,
                    "requestId": canonical_attempt.request_id,
                    "workerJobId": canonical_attempt.worker_job_id,
                    "terminalKind": (
                        AgenticSpecialistTerminalKind.FAILED_BEFORE_TARGET_IO.value
                    ),
                    "terminalReasonDigest": terminal_reason_digest,
                    "targetIoState": AgenticSpecialistTargetIOState.NOT_STARTED.value,
                    "succeeded": False,
                    "backendTerminalProven": True,
                    "workerResultDigest": worker_result_digest,
                    "backendTerminalProofDigest": proof_digest,
                    "backendFinishedAt": (
                        _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION(
                            statement.finished_at
                        )
                    ),
                    "recordedAt": (
                        _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION(recorded_at)
                    ),
                }
            )
            canonical_receipt = AgenticSpecialistTerminalReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
            )
            if canonical_receipt != receipt:
                raise AgenticCoordinationError(
                    "specialist zero-I/O terminal receipt changed after strict reload"
                )
            return canonical_receipt
        except AgenticCoordinationError:
            raise
        except (
            SpecialistGatewayDeploymentV2Error,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise AgenticCoordinationError(
                "specialist zero-I/O terminal receipt construction failed closed"
            ) from exc

    def _build_sql_specialist_v2_unknown_terminal_receipt(
        self,
        attempt: AgenticSpecialistJobAttempt,
        *,
        reason: Literal["backend-dispatch-failed", "backend-dispatch-cancelled"],
    ) -> AgenticSpecialistTerminalReceipt:
        """Conservatively seal one started attempt without terminal proof."""

        if reason not in {"backend-dispatch-failed", "backend-dispatch-cancelled"}:
            raise AgenticCoordinationError(
                "specialist unknown-outcome terminal reason is invalid"
            )
        try:
            canonical = AgenticSpecialistJobAttempt.model_validate(
                attempt.model_dump(mode="json", by_alias=True)
            )
            if (
                canonical != attempt
                or canonical.state
                is not AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                or canonical.backend_dispatch_started_at is None
            ):
                raise AgenticCoordinationError(
                    "specialist unknown-outcome receipt requires a started attempt"
                )
            reason_digest = discovery_digest(
                "pajin.agentic.sql-specialist-v2-unknown-terminal-reason/v1",
                {
                    "attemptDigest": canonical.attempt_digest,
                    "attemptStateDigest": canonical.state_digest,
                    "reason": reason,
                },
            )
            recorded_at = max(
                _SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self),
                canonical.backend_dispatch_started_at,
            )
            return AgenticSpecialistTerminalReceipt.model_validate(
                {
                    "storeId": self.store_id,
                    "coordinationBindingDigest": self.binding.binding_digest,
                    "attemptId": canonical.attempt_id,
                    "attemptDigest": canonical.attempt_digest,
                    "attemptState": canonical.state.value,
                    "attemptStateDigest": canonical.state_digest,
                    "planId": canonical.plan_id,
                    "requestId": canonical.request_id,
                    "workerJobId": canonical.worker_job_id,
                    "terminalKind": (
                        AgenticSpecialistTerminalKind.STARTED_OUTCOME_UNKNOWN.value
                    ),
                    "terminalReasonDigest": reason_digest,
                    "targetIoState": AgenticSpecialistTargetIOState.UNKNOWN.value,
                    "succeeded": None,
                    "backendTerminalProven": False,
                    "workerResultDigest": None,
                    "backendTerminalProofDigest": None,
                    "backendFinishedAt": None,
                    "recordedAt": (
                        _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION(recorded_at)
                    ),
                }
            )
        except AgenticCoordinationError:
            raise
        except (TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist unknown-outcome receipt construction failed closed"
            ) from exc

    def _record_specialist_terminal_receipt(
        self,
        receipt: AgenticSpecialistTerminalReceipt,
        *,
        authority: object,
        proven_terminal_authority: object | None = None,
    ) -> AgenticSpecialistTerminalReceipt:
        """Append a classification receipt without requiring live Graph authority."""

        try:
            if (
                authority is not self._authority
                or (
                    proven_terminal_authority is not None
                    and proven_terminal_authority is not _PROVEN_TERMINAL_INSERT_AUTHORITY
                )
            ):
                raise AgenticCoordinationError(
                    "specialist terminal-receipt insertion lacks Store authority"
                )
            canonical = AgenticSpecialistTerminalReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
            )
            if canonical != receipt:
                raise AgenticCoordinationError(
                    "specialist terminal receipt differs after strict reload"
                )
            if (
                canonical.backend_terminal_proven
                and proven_terminal_authority is not _PROVEN_TERMINAL_INSERT_AUTHORITY
            ) or (
                not canonical.backend_terminal_proven
                and proven_terminal_authority is not None
            ):
                raise AgenticCoordinationError(
                    "specialist terminal receipt lacks exact proof provenance"
                )
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                _validate_structural_history(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                )
                attempt = _specialist_job_attempt_from_row(
                    _specialist_job_attempt_row(connection, canonical.attempt_id)
                )
                if (
                    canonical.store_id != self.store_id
                    or canonical.coordination_binding_digest != self.binding.binding_digest
                    or canonical.attempt_digest != attempt.attempt_digest
                    or canonical.attempt_state is not attempt.state
                    or canonical.attempt_state_digest != attempt.state_digest
                    or canonical.plan_id != attempt.plan_id
                    or canonical.request_id != attempt.request_id
                    or canonical.worker_job_id != attempt.worker_job_id
                ):
                    raise AgenticCoordinationError(
                        "specialist terminal receipt references another job attempt"
                    )
                existing_row = _specialist_terminal_receipt_row(
                    connection,
                    canonical.attempt_id,
                )
                if existing_row is not None:
                    existing = _specialist_terminal_receipt_from_row(existing_row)
                    if existing != canonical:
                        raise AgenticCoordinationError(
                            "specialist terminal receipt was equivocated"
                        )
                    return existing
                _insert_specialist_terminal_receipt(connection, canonical)
                _validate_structural_history(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                )
                stored_row = _specialist_terminal_receipt_row(
                    connection,
                    canonical.attempt_id,
                )
                if stored_row is None:
                    raise AgenticCoordinationError(
                        "specialist terminal receipt was not durably inserted"
                    )
                stored = _specialist_terminal_receipt_from_row(stored_row)
                if stored != canonical:
                    raise AgenticCoordinationError(
                        "specialist terminal receipt differs after durable insertion"
                    )
                return stored
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist terminal-receipt insertion failed closed"
            ) from exc

    def _record_specialist_abandonment_receipt(
        self,
        attempt: AgenticSpecialistJobAttempt,
        *,
        authority: object,
        reason: Literal[
            "mint-failed",
            "owner-task-completed",
            "store-close",
            "claim-discarded",
        ],
    ) -> AgenticSpecialistTerminalReceipt:
        """Build and append one trusted pre-backend abandonment classification."""

        allowed_reasons = {
            "mint-failed",
            "owner-task-completed",
            "store-close",
            "claim-discarded",
        }
        try:
            if (
                authority is not self._authority
                or type(reason) is not str
                or reason not in allowed_reasons
            ):
                raise AgenticCoordinationError(
                    "specialist abandonment receipt lacks Store authority"
                )
            canonical = AgenticSpecialistJobAttempt.model_validate(
                attempt.model_dump(mode="json", by_alias=True)
            )
            if (
                canonical != attempt
                or canonical.state is not AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
            ):
                raise AgenticCoordinationError(
                    "specialist abandonment requires the exact pre-backend attempt"
                )
            with _write_transaction(self._database) as connection:
                self._validate_connection(connection)
                _validate_structural_history(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                )
                current = _specialist_job_attempt_from_row(
                    _specialist_job_attempt_row(connection, canonical.attempt_id)
                )
                if current != canonical:
                    raise AgenticCoordinationError(
                        "specialist abandonment references another job attempt"
                    )
                reason_digest = discovery_digest(
                    "pajin.agentic.sql-specialist-v2-abandonment-reason/v1",
                    {
                        "storeId": self.store_id,
                        "coordinationBindingDigest": self.binding.binding_digest,
                        "attemptId": current.attempt_id,
                        "attemptDigest": current.attempt_digest,
                        "attemptStateDigest": current.state_digest,
                        "reason": reason,
                    },
                )
                existing_row = _specialist_terminal_receipt_row(
                    connection,
                    current.attempt_id,
                )
                if existing_row is not None:
                    existing = _specialist_terminal_receipt_from_row(existing_row)
                    if (
                        existing.terminal_kind
                        is not AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND
                        or existing.terminal_reason_digest != reason_digest
                        or existing.attempt_digest != current.attempt_digest
                        or existing.attempt_state is not current.state
                        or existing.attempt_state_digest != current.state_digest
                    ):
                        raise AgenticCoordinationError(
                            "specialist abandonment receipt was equivocated"
                        )
                    return existing
                recorded_at = _SQL_SPECIALIST_V2_NOW_IMPLEMENTATION(self)
                if recorded_at < current.claimed_at:
                    raise AgenticCoordinationError(
                        "specialist abandonment receipt predates its job attempt"
                    )
                receipt = AgenticSpecialistTerminalReceipt.model_validate(
                    {
                        "storeId": self.store_id,
                        "coordinationBindingDigest": self.binding.binding_digest,
                        "attemptId": current.attempt_id,
                        "attemptDigest": current.attempt_digest,
                        "attemptState": current.state.value,
                        "attemptStateDigest": current.state_digest,
                        "planId": current.plan_id,
                        "requestId": current.request_id,
                        "workerJobId": current.worker_job_id,
                        "terminalKind": (
                            AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND.value
                        ),
                        "terminalReasonDigest": reason_digest,
                        "targetIoState": AgenticSpecialistTargetIOState.NOT_STARTED.value,
                        "succeeded": False,
                        "backendTerminalProven": False,
                        "workerResultDigest": None,
                        "backendTerminalProofDigest": None,
                        "backendFinishedAt": None,
                        "recordedAt": (
                            _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION(recorded_at)
                        ),
                    }
                )
                _insert_specialist_terminal_receipt(connection, receipt)
                _validate_structural_history(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                )
                stored_row = _specialist_terminal_receipt_row(
                    connection,
                    current.attempt_id,
                )
                if stored_row is None:
                    raise AgenticCoordinationError(
                        "specialist abandonment receipt was not durably inserted"
                    )
                stored = _specialist_terminal_receipt_from_row(stored_row)
                if stored != receipt:
                    raise AgenticCoordinationError(
                        "specialist abandonment receipt differs after durable insertion"
                    )
                return stored
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist abandonment receipt insertion failed closed"
            ) from exc

    def specialist_job_recovery_snapshot(
        self,
    ) -> AgenticSpecialistJobRecoverySnapshot:
        """Classify specialist job attempts without recovering execution authority."""

        try:
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                _validate_structural_history(
                    connection,
                    store_id=self.store_id,
                    binding=self.binding,
                )
                attempts = tuple(
                    _specialist_job_attempt_from_row(row)
                    for row in connection.execute(
                        "SELECT * FROM agentic_specialist_job_attempts ORDER BY rowid"
                    )
                )
                receipts = tuple(
                    _specialist_terminal_receipt_from_row(row)
                    for row in connection.execute(
                        "SELECT * FROM agentic_specialist_terminal_receipts ORDER BY rowid"
                    )
                )
                terminal_attempt_ids = {receipt.attempt_id for receipt in receipts}
                return AgenticSpecialistJobRecoverySnapshot(
                    store_id=self.store_id,
                    coordination_binding_digest=self.binding.binding_digest,
                    claimed_job_attempts=tuple(
                        attempt
                        for attempt in attempts
                        if attempt.attempt_id not in terminal_attempt_ids
                        and attempt.state is AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
                    ),
                    unknown_job_attempts=tuple(
                        attempt
                        for attempt in attempts
                        if attempt.attempt_id not in terminal_attempt_ids
                        and attempt.state
                        is AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    ),
                    terminal_receipts=receipts,
                )
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "specialist job-attempt recovery scan failed closed"
            ) from exc

    def recovery_snapshot(
        self,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> AgenticRecoverySnapshot:
        """Classify durable work after restart without mutating or redispatching it."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            with _read_transaction(self._database) as connection:
                self._validate_connection(connection)
                snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
                self._validate_durable_history(connection, snapshot)
                outbox = tuple(
                    _outbox_from_row(
                        row,
                        store_id=self.store_id,
                        binding_digest=self.binding.binding_digest,
                    )
                    for row in connection.execute(
                        "SELECT * FROM agentic_command_outbox ORDER BY rowid"
                    )
                )
                invocations = tuple(
                    _invocation_from_row(row)
                    for row in connection.execute(
                        "SELECT * FROM agentic_model_invocations ORDER BY rowid"
                    )
                )
                specialist_executions = tuple(
                    _specialist_execution_from_row(row)
                    for row in connection.execute(
                        "SELECT * FROM agentic_specialist_executions ORDER BY rowid"
                    )
                )
                specialist_dispatch_plans = tuple(
                    _any_specialist_dispatch_plan_from_row(row)
                    for row in connection.execute(
                        "SELECT * FROM agentic_specialist_dispatch_plans ORDER BY rowid"
                    )
                )
                specialist_job_attempts = tuple(
                    _specialist_job_attempt_from_row(row)
                    for row in connection.execute(
                        "SELECT * FROM agentic_specialist_job_attempts ORDER BY rowid"
                    )
                )
                specialist_terminal_receipts = tuple(
                    _specialist_terminal_receipt_from_row(row)
                    for row in connection.execute(
                        "SELECT * FROM agentic_specialist_terminal_receipts ORDER BY rowid"
                    )
                )
                terminal_attempt_ids = {item.attempt_id for item in specialist_terminal_receipts}
                for invocation in invocations:
                    self._require_current_invocation_context(snapshot, invocation.intent)
                    if invocation.state in {
                        AgenticModelInvocationState.TERMINAL_SUCCESS,
                        AgenticModelInvocationState.TERMINAL_FAILURE,
                    }:
                        publication = _receipt_publication_from_entry(invocation)
                        verify_agentic_hypothesis_receipt_publication(
                            publication,
                            expected_entry=invocation,
                        )
                recovery = AgenticRecoverySnapshot(
                    head=self._head(_current_checkpoint(connection)),
                    pending_outbox=tuple(
                        item for item in outbox if item.state is AgenticOutboxState.PENDING
                    ),
                    unknown_outbox=tuple(
                        item
                        for item in outbox
                        if item.state is AgenticOutboxState.DELIVERY_STARTED_OUTCOME_UNKNOWN
                    ),
                    acknowledged_outbox=tuple(
                        item for item in outbox if item.state is AgenticOutboxState.ACKNOWLEDGED
                    ),
                    claimed_invocations=tuple(
                        item
                        for item in invocations
                        if item.state is AgenticModelInvocationState.CLAIMED
                    ),
                    unknown_invocations=tuple(
                        item
                        for item in invocations
                        if item.state
                        is AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    ),
                    terminal_invocations=tuple(
                        item
                        for item in invocations
                        if item.state
                        in {
                            AgenticModelInvocationState.TERMINAL_SUCCESS,
                            AgenticModelInvocationState.TERMINAL_FAILURE,
                        }
                    ),
                    reserved_specialist_executions=tuple(
                        item
                        for item in specialist_executions
                        if item.state is AgenticSpecialistExecutionState.RESERVED
                    ),
                    unknown_specialist_executions=tuple(
                        item
                        for item in specialist_executions
                        if item.state
                        is AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    ),
                    awaiting_specialist_dispatch_plans=tuple(
                        item
                        for item in specialist_dispatch_plans
                        if item.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
                    ),
                    terminal_specialist_dispatch_plans=tuple(
                        item
                        for item in specialist_dispatch_plans
                        if item.state is not AgenticSpecialistDispatchPlanState.AWAITING_PERMIT
                    ),
                    claimed_specialist_job_attempts=tuple(
                        item
                        for item in specialist_job_attempts
                        if item.attempt_id not in terminal_attempt_ids
                        and item.state is AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
                    ),
                    unknown_specialist_job_attempts=tuple(
                        item
                        for item in specialist_job_attempts
                        if item.attempt_id not in terminal_attempt_ids
                        and item.state
                        is AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                    ),
                    specialist_terminal_receipts=specialist_terminal_receipts,
                )
                self._current_graph_snapshot(graph_resolver, graph_head)
                return recovery
        except AgenticCoordinationError:
            raise
        except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("agentic recovery scan failed closed") from exc

    def restore_supervisor(
        self,
        head: VerifiedAgenticDurableHead,
        *,
        graph_resolver: CurrentGraphHeadResolver,
        graph_head: VerifiedCurrentGraphHead,
    ) -> DynamicSupervisor:
        """Restore only the exact current CAS head and current independent Graph head."""

        try:
            snapshot = self._current_graph_snapshot(graph_resolver, graph_head)
            self._require_current_handle(head, snapshot)
            self._current_graph_snapshot(graph_resolver, graph_head)
            return _restore_supervisor_instance(
                binding=self.binding,
                checkpoint=head.checkpoint,
                snapshot=snapshot,
            )
        except AgenticCoordinationError:
            raise
        except (TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError("Dynamic Supervisor restore failed closed") from exc

    def _head(self, checkpoint: DynamicSupervisorCheckpoint) -> VerifiedAgenticDurableHead:
        return VerifiedAgenticDurableHead(
            store_id=self.store_id,
            binding_digest=self.binding.binding_digest,
            checkpoint=_canonical_checkpoint(checkpoint),
            _authority=self._authority,
        )

    def _current_graph_snapshot(
        self,
        resolver: CurrentGraphHeadResolver,
        head: VerifiedCurrentGraphHead,
    ) -> GraphSnapshot:
        if type(resolver) is not CurrentGraphHeadResolver:
            raise AgenticCoordinationError(
                "agentic durability requires the concrete current Graph resolver"
            )
        if resolver is not self._graph_resolver:
            raise AgenticCoordinationError(
                "current Graph resolver differs from the deployment-fixed authority"
            )
        try:
            with _SQLITE_DESCRIPTOR_OPEN_LOCK:
                snapshot = resolver.snapshot_for_planning(head)
        except (AgenticGraphHeadError, OSError, TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "current durable Graph head verification failed"
            ) from exc
        if (
            snapshot.campaign_id != self.binding.campaign_id
            or snapshot.snapshot_id != self.binding.source_snapshot_id
            or snapshot.snapshot_digest != self.binding.source_snapshot_digest
        ):
            raise AgenticCoordinationError(
                "current durable Graph head differs from coordination binding"
            )
        return snapshot

    def _require_local_handle(self, head: VerifiedAgenticDurableHead) -> None:
        if (
            type(head) is not VerifiedAgenticDurableHead
            or head._authority is not self._authority
            or head.store_id != self.store_id
            or head.binding_digest != self.binding.binding_digest
        ):
            raise AgenticCoordinationError("durable head handle belongs to another store")
        canonical = _canonical_checkpoint(head.checkpoint)
        self.binding.require_checkpoint(canonical)
        if canonical != head.checkpoint:
            raise AgenticCoordinationError("durable head handle checkpoint is not canonical")

    def _require_current_handle(
        self,
        head: VerifiedAgenticDurableHead,
        snapshot: GraphSnapshot,
    ) -> None:
        self._require_local_handle(head)
        with _read_transaction(self._database) as connection:
            self._validate_connection(connection)
            self._validate_durable_history(connection, snapshot)
            if _current_checkpoint(connection) != head.checkpoint:
                raise AgenticCoordinationError("durable head handle is stale")

    def _require_claim(self, claim: AgenticOutboxDeliveryClaim) -> None:
        if (
            claim.store_id != self.store_id
            or claim.coordination_binding_digest != self.binding.binding_digest
        ):
            raise AgenticCoordinationError("delivery claim belongs to another store")

    def _require_invocation_store(self, entry: AgenticModelInvocationEntry) -> None:
        if (
            entry.intent.store_id != self.store_id
            or entry.intent.coordination_binding_id != self.binding.binding_id
            or entry.intent.coordination_binding_digest != self.binding.binding_digest
        ):
            raise AgenticCoordinationError("Hypothesis invocation belongs to another store")

    def _require_current_invocation_context(
        self,
        snapshot: GraphSnapshot,
        intent: AgenticHypothesisInvocationIntent,
    ) -> None:
        context = intent.context
        expected_projection = build_hypothesis_model_projection(
            context,
            source_snapshot=snapshot,
        )
        if (
            expected_projection != intent.request_binding.projection
            or context.campaign_id != self.binding.campaign_id
            or context.source_snapshot_id != self.binding.source_snapshot_id
            or context.source_snapshot_digest != self.binding.source_snapshot_digest
            or context.exploit_group != self.binding.exploit_group
            or context.allowed_target_ids != self.binding.allowed_target_ids
        ):
            raise AgenticCoordinationError(
                "Hypothesis invocation Context differs from current Graph authority"
            )

    def _require_expansion_binding(
        self,
        checkpoint: DynamicSupervisorCheckpoint,
        context: HypothesisExpansionContext,
        projection: HypothesisModelProjection,
    ) -> None:
        if (
            context.campaign_id != self.binding.campaign_id
            or context.source_snapshot_id != self.binding.source_snapshot_id
            or context.source_snapshot_digest != self.binding.source_snapshot_digest
            or context.exploit_group.group_id != self.binding.exploit_group_id
            or context.exploit_group.group_digest != self.binding.exploit_group_digest
            or context.allowed_target_ids != self.binding.allowed_target_ids
            or checkpoint.checkpoint_digest == ""
            or projection.path_depth != len(context.ancestor_hypothesis_ids)
            or projection.allowed_specializations != context.allowed_specializations
            or projection.max_proposals != context.max_proposals
            or tuple(item.signal_ids for item in projection.observations)
            != tuple(item.signal_ids for item in context.observations)
        ):
            raise ValueError("Hypothesis projection differs from private bound context")


_SQL_SPECIALIST_V2_PLAN_IMPLEMENTATION = AgenticCoordinationStore.plan_sql_specialist_dispatch_v2
_SQL_SPECIALIST_V2_BIND_IMPLEMENTATION = (
    AgenticCoordinationStore.bind_sql_specialist_v2_permit_dispatcher
)
_SQL_SPECIALIST_V2_PUBLIC_DISPATCH_IMPLEMENTATION = (
    AgenticCoordinationStore.dispatch_sql_specialist_v2_permit_once
)
_SQL_SPECIALIST_V2_MINT_JOB_ATTEMPT_CLAIM_IMPLEMENTATION = (
    AgenticCoordinationStore.mint_sql_specialist_v2_job_attempt_claim
)
_SQL_SPECIALIST_V2_JOB_ATTEMPT_DISPATCH_IMPLEMENTATION = (
    AgenticCoordinationStore.dispatch_sql_specialist_v2_job_attempt_once
)
_SQL_SPECIALIST_V2_ACTIVE_JOB_ATTEMPT_DISPATCH_IMPLEMENTATION = (
    AgenticCoordinationStore._dispatch_sql_specialist_v2_job_attempt_once_active
)
_SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION = AgenticCoordinationStore.close
_SQL_SPECIALIST_V2_STORE_EXIT_IMPLEMENTATION = AgenticCoordinationStore.__exit__
_SQL_SPECIALIST_V2_BEGIN_OPERATION_IMPLEMENTATION = (
    AgenticCoordinationStore._begin_sql_specialist_v2_dispatch_operation
)
_SQL_SPECIALIST_V2_REQUIRE_OPERATION_IMPLEMENTATION = (
    AgenticCoordinationStore._require_sql_specialist_v2_dispatch_operation
)
_SQL_SPECIALIST_V2_RELEASE_OPERATION_IMPLEMENTATION = (
    AgenticCoordinationStore._release_sql_specialist_v2_dispatch_operation
)
_SQL_SPECIALIST_V2_ACTIVE_DISPATCH_IMPLEMENTATION = (
    AgenticCoordinationStore._dispatch_sql_specialist_v2_permit_once_active
)
_SQL_SPECIALIST_V2_BINDING_OPERATION_IMPLEMENTATION = (
    AgenticCoordinationStore._specialist_dispatch_binding_operation
)
_SQL_SPECIALIST_V2_TRANSFER_IMPLEMENTATION = (
    AgenticCoordinationStore._transfer_planned_sql_specialist_v2_dispatch_started
)
_SQL_SPECIALIST_V2_RUNTIME_CLAIM_IMPLEMENTATION = (
    AgenticCoordinationStore._claim_transferred_sql_specialist_v2_dispatch_runtime
)
_SQL_SPECIALIST_V2_RETIRE_DISPATCH_STARTED_IMPLEMENTATION = (
    AgenticCoordinationStore._retire_issued_sql_specialist_v2_dispatch_started
)
_SQL_SPECIALIST_V2_RETIRE_PLANS_IMPLEMENTATION = (
    AgenticCoordinationStore._retire_issued_sql_specialist_v2_plans
)
_SQL_SPECIALIST_V2_DROP_OWNER_CALLBACK_IMPLEMENTATION = (
    AgenticCoordinationStore._drop_sql_specialist_v2_dispatch_owner_callback_if_unused
)
_SQL_SPECIALIST_V2_REGISTER_JOB_ATTEMPT_CLAIM_IMPLEMENTATION = (
    AgenticCoordinationStore._register_sql_specialist_v2_job_attempt_claim
)
_SQL_SPECIALIST_V2_REQUIRE_EXECUTION_OBSERVATION_IMPLEMENTATION = (
    AgenticCoordinationStore._require_sql_specialist_v2_execution_observation
)
_SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_ENTRY_IMPLEMENTATION = (
    AgenticCoordinationStore._retire_sql_specialist_v2_job_attempt_entry
)
_SQL_SPECIALIST_V2_FINALIZE_JOB_ATTEMPT_DISPATCH_IMPLEMENTATION = (
    AgenticCoordinationStore._finalize_sql_specialist_v2_job_attempt_dispatch
)
_SQL_SPECIALIST_V2_CLEANUP_FAILED_JOB_ATTEMPT_MINT_IMPLEMENTATION = (
    AgenticCoordinationStore._cleanup_failed_sql_specialist_v2_job_attempt_mint
)
_SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CLAIMS_IMPLEMENTATION = (
    AgenticCoordinationStore._retire_issued_sql_specialist_v2_job_attempt_claims
)
_SQL_SPECIALIST_V2_DISCARD_JOB_ATTEMPT_CLAIM_IMPLEMENTATION = (
    AgenticCoordinationStore._discard_sql_specialist_v2_job_attempt_claim
)
_SQL_SPECIALIST_V2_JOB_ATTEMPT_DATABASE_IDENTITY_IMPLEMENTATION = (
    AgenticCoordinationStore._specialist_job_attempt_database_identity_digest
)
_SQL_SPECIALIST_V2_RECORD_JOB_ATTEMPT_IMPLEMENTATION = (
    AgenticCoordinationStore._record_specialist_job_attempt
)
_SQL_SPECIALIST_V2_MARK_JOB_ATTEMPT_DISPATCHED_IMPLEMENTATION = (
    AgenticCoordinationStore._mark_specialist_job_attempt_dispatched
)
_SQL_SPECIALIST_V2_BUILD_ZERO_IO_TERMINAL_RECEIPT_IMPLEMENTATION = (
    AgenticCoordinationStore._build_sql_specialist_v2_zero_io_terminal_receipt
)
_SQL_SPECIALIST_V2_BUILD_UNKNOWN_TERMINAL_RECEIPT_IMPLEMENTATION = (
    AgenticCoordinationStore._build_sql_specialist_v2_unknown_terminal_receipt
)
_SQL_SPECIALIST_V2_RECORD_TERMINAL_RECEIPT_IMPLEMENTATION = (
    AgenticCoordinationStore._record_specialist_terminal_receipt
)
_SQL_SPECIALIST_V2_RECORD_ABANDONMENT_IMPLEMENTATION = (
    AgenticCoordinationStore._record_specialist_abandonment_receipt
)
_SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_IMPLEMENTATION = (
    AgenticCoordinationStore._require_specialist_deployment
)
_SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_LOCKED_IMPLEMENTATION = (
    AgenticCoordinationStore._require_specialist_deployment_locked
)
_SQL_SPECIALIST_V2_ABANDON_BINDING_REGISTRIES_IMPLEMENTATION = (
    AgenticCoordinationStore._abandon_specialist_dispatch_binding_registries
)
_SQL_SPECIALIST_V2_PIN_CONFIGURED_RUNTIME_IMPLEMENTATION = (
    AgenticCoordinationStore._pin_specialist_configured_runtime
)
_SQL_SPECIALIST_V2_REGISTER_PLAN_IMPLEMENTATION = (
    AgenticCoordinationStore._register_sql_specialist_v2_plan
)
_SQL_SPECIALIST_V2_REQUIRE_PLAN_OWNER_IMPLEMENTATION = (
    AgenticCoordinationStore._require_sql_specialist_v2_plan_owner
)
_SQL_SPECIALIST_V2_REQUIRE_CURRENT_RUNTIME_IMPLEMENTATION = (
    AgenticCoordinationStore._require_current_sql_specialist_v2_dispatch_runtime
)
_SQL_SPECIALIST_V2_ENTER_DISPATCH_IMPLEMENTATION = (
    AgenticCoordinationStore._enter_planned_sql_specialist_v2_dispatch
)
_SQL_SPECIALIST_V2_RECONCILE_IMPLEMENTATION = (
    AgenticCoordinationStore._reconcile_sql_specialist_v2_permit_consumption
)
_SQL_SPECIALIST_V2_RESOLVE_EXCEPTION_IMPLEMENTATION = (
    AgenticCoordinationStore._resolve_sql_specialist_v2_dispatch_exception
)
_SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION = (
    AgenticCoordinationStore._current_graph_snapshot
)
_SQL_SPECIALIST_V2_VALIDATE_CONNECTION_IMPLEMENTATION = (
    AgenticCoordinationStore._validate_connection
)
_SQL_SPECIALIST_V2_VALIDATE_HISTORY_IMPLEMENTATION = (
    AgenticCoordinationStore._validate_durable_history
)
_SQL_SPECIALIST_V2_NOW_IMPLEMENTATION = AgenticCoordinationStore._now


def _sql_specialist_v2_retire_plan_callback(
    store: AgenticCoordinationStore,
) -> Callable[[asyncio.Future[object]], None]:
    return cast(
        Callable[[asyncio.Future[object]], None],
        _SQL_SPECIALIST_V2_RETIRE_PLANS_IMPLEMENTATION.__get__(
            store,
            AgenticCoordinationStore,
        ),
    )


_SQL_SPECIALIST_V2_RETIRE_PLAN_CALLBACK_FACTORY_IMPLEMENTATION = (
    _sql_specialist_v2_retire_plan_callback
)


def _sql_specialist_v2_retire_dispatch_callback(
    store: AgenticCoordinationStore,
) -> Callable[[asyncio.Future[object]], None]:
    return cast(
        Callable[[asyncio.Future[object]], None],
        _SQL_SPECIALIST_V2_RETIRE_DISPATCH_STARTED_IMPLEMENTATION.__get__(
            store,
            AgenticCoordinationStore,
        ),
    )


_SQL_SPECIALIST_V2_RETIRE_CALLBACK_FACTORY_IMPLEMENTATION = (
    _sql_specialist_v2_retire_dispatch_callback
)


def _sql_specialist_v2_retire_job_attempt_callback(
    store: AgenticCoordinationStore,
) -> Callable[[asyncio.Future[object]], None]:
    return cast(
        Callable[[asyncio.Future[object]], None],
        _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CLAIMS_IMPLEMENTATION.__get__(
            store,
            AgenticCoordinationStore,
        ),
    )


_SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CALLBACK_FACTORY_IMPLEMENTATION = (
    _sql_specialist_v2_retire_job_attempt_callback
)


_SQL_SPECIALIST_V2_STORE_PINNED_METHODS = (
    ("plan_sql_specialist_dispatch_v2", _SQL_SPECIALIST_V2_PLAN_IMPLEMENTATION),
    ("bind_sql_specialist_v2_permit_dispatcher", _SQL_SPECIALIST_V2_BIND_IMPLEMENTATION),
    ("dispatch_sql_specialist_v2_permit_once", _SQL_SPECIALIST_V2_PUBLIC_DISPATCH_IMPLEMENTATION),
    (
        "mint_sql_specialist_v2_job_attempt_claim",
        _SQL_SPECIALIST_V2_MINT_JOB_ATTEMPT_CLAIM_IMPLEMENTATION,
    ),
    (
        "dispatch_sql_specialist_v2_job_attempt_once",
        _SQL_SPECIALIST_V2_JOB_ATTEMPT_DISPATCH_IMPLEMENTATION,
    ),
    ("close", _SQL_SPECIALIST_V2_STORE_CLOSE_IMPLEMENTATION),
    ("__exit__", _SQL_SPECIALIST_V2_STORE_EXIT_IMPLEMENTATION),
    (
        "_begin_sql_specialist_v2_dispatch_operation",
        _SQL_SPECIALIST_V2_BEGIN_OPERATION_IMPLEMENTATION,
    ),
    (
        "_require_sql_specialist_v2_dispatch_operation",
        _SQL_SPECIALIST_V2_REQUIRE_OPERATION_IMPLEMENTATION,
    ),
    (
        "_release_sql_specialist_v2_dispatch_operation",
        _SQL_SPECIALIST_V2_RELEASE_OPERATION_IMPLEMENTATION,
    ),
    (
        "_dispatch_sql_specialist_v2_permit_once_active",
        _SQL_SPECIALIST_V2_ACTIVE_DISPATCH_IMPLEMENTATION,
    ),
    (
        "_dispatch_sql_specialist_v2_job_attempt_once_active",
        _SQL_SPECIALIST_V2_ACTIVE_JOB_ATTEMPT_DISPATCH_IMPLEMENTATION,
    ),
    (
        "_specialist_dispatch_binding_operation",
        _SQL_SPECIALIST_V2_BINDING_OPERATION_IMPLEMENTATION,
    ),
    (
        "_transfer_planned_sql_specialist_v2_dispatch_started",
        _SQL_SPECIALIST_V2_TRANSFER_IMPLEMENTATION,
    ),
    (
        "_claim_transferred_sql_specialist_v2_dispatch_runtime",
        _SQL_SPECIALIST_V2_RUNTIME_CLAIM_IMPLEMENTATION,
    ),
    (
        "_retire_issued_sql_specialist_v2_dispatch_started",
        _SQL_SPECIALIST_V2_RETIRE_DISPATCH_STARTED_IMPLEMENTATION,
    ),
    (
        "_retire_issued_sql_specialist_v2_plans",
        _SQL_SPECIALIST_V2_RETIRE_PLANS_IMPLEMENTATION,
    ),
    (
        "_drop_sql_specialist_v2_dispatch_owner_callback_if_unused",
        _SQL_SPECIALIST_V2_DROP_OWNER_CALLBACK_IMPLEMENTATION,
    ),
    (
        "_register_sql_specialist_v2_job_attempt_claim",
        _SQL_SPECIALIST_V2_REGISTER_JOB_ATTEMPT_CLAIM_IMPLEMENTATION,
    ),
    (
        "_require_sql_specialist_v2_execution_observation",
        _SQL_SPECIALIST_V2_REQUIRE_EXECUTION_OBSERVATION_IMPLEMENTATION,
    ),
    (
        "_retire_sql_specialist_v2_job_attempt_entry",
        _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_ENTRY_IMPLEMENTATION,
    ),
    (
        "_finalize_sql_specialist_v2_job_attempt_dispatch",
        _SQL_SPECIALIST_V2_FINALIZE_JOB_ATTEMPT_DISPATCH_IMPLEMENTATION,
    ),
    (
        "_cleanup_failed_sql_specialist_v2_job_attempt_mint",
        _SQL_SPECIALIST_V2_CLEANUP_FAILED_JOB_ATTEMPT_MINT_IMPLEMENTATION,
    ),
    (
        "_retire_issued_sql_specialist_v2_job_attempt_claims",
        _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CLAIMS_IMPLEMENTATION,
    ),
    (
        "_discard_sql_specialist_v2_job_attempt_claim",
        _SQL_SPECIALIST_V2_DISCARD_JOB_ATTEMPT_CLAIM_IMPLEMENTATION,
    ),
    (
        "_specialist_job_attempt_database_identity_digest",
        _SQL_SPECIALIST_V2_JOB_ATTEMPT_DATABASE_IDENTITY_IMPLEMENTATION,
    ),
    (
        "_record_specialist_job_attempt",
        _SQL_SPECIALIST_V2_RECORD_JOB_ATTEMPT_IMPLEMENTATION,
    ),
    (
        "_mark_specialist_job_attempt_dispatched",
        _SQL_SPECIALIST_V2_MARK_JOB_ATTEMPT_DISPATCHED_IMPLEMENTATION,
    ),
    (
        "_build_sql_specialist_v2_zero_io_terminal_receipt",
        _SQL_SPECIALIST_V2_BUILD_ZERO_IO_TERMINAL_RECEIPT_IMPLEMENTATION,
    ),
    (
        "_build_sql_specialist_v2_unknown_terminal_receipt",
        _SQL_SPECIALIST_V2_BUILD_UNKNOWN_TERMINAL_RECEIPT_IMPLEMENTATION,
    ),
    (
        "_record_specialist_terminal_receipt",
        _SQL_SPECIALIST_V2_RECORD_TERMINAL_RECEIPT_IMPLEMENTATION,
    ),
    (
        "_record_specialist_abandonment_receipt",
        _SQL_SPECIALIST_V2_RECORD_ABANDONMENT_IMPLEMENTATION,
    ),
    ("_require_specialist_deployment", _SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_IMPLEMENTATION),
    (
        "_require_specialist_deployment_locked",
        _SQL_SPECIALIST_V2_REQUIRE_DEPLOYMENT_LOCKED_IMPLEMENTATION,
    ),
    (
        "_abandon_specialist_dispatch_binding_registries",
        _SQL_SPECIALIST_V2_ABANDON_BINDING_REGISTRIES_IMPLEMENTATION,
    ),
    (
        "_pin_specialist_configured_runtime",
        _SQL_SPECIALIST_V2_PIN_CONFIGURED_RUNTIME_IMPLEMENTATION,
    ),
    ("_register_sql_specialist_v2_plan", _SQL_SPECIALIST_V2_REGISTER_PLAN_IMPLEMENTATION),
    (
        "_require_sql_specialist_v2_plan_owner",
        _SQL_SPECIALIST_V2_REQUIRE_PLAN_OWNER_IMPLEMENTATION,
    ),
    (
        "_require_current_sql_specialist_v2_dispatch_runtime",
        _SQL_SPECIALIST_V2_REQUIRE_CURRENT_RUNTIME_IMPLEMENTATION,
    ),
    (
        "_enter_planned_sql_specialist_v2_dispatch",
        _SQL_SPECIALIST_V2_ENTER_DISPATCH_IMPLEMENTATION,
    ),
    (
        "_reconcile_sql_specialist_v2_permit_consumption",
        _SQL_SPECIALIST_V2_RECONCILE_IMPLEMENTATION,
    ),
    (
        "_resolve_sql_specialist_v2_dispatch_exception",
        _SQL_SPECIALIST_V2_RESOLVE_EXCEPTION_IMPLEMENTATION,
    ),
    ("_current_graph_snapshot", _SQL_SPECIALIST_V2_CURRENT_GRAPH_SNAPSHOT_IMPLEMENTATION),
    ("_validate_connection", _SQL_SPECIALIST_V2_VALIDATE_CONNECTION_IMPLEMENTATION),
    ("_validate_durable_history", _SQL_SPECIALIST_V2_VALIDATE_HISTORY_IMPLEMENTATION),
    ("_now", _SQL_SPECIALIST_V2_NOW_IMPLEMENTATION),
)


def _require_sql_specialist_v2_store_implementations(
    store: AgenticCoordinationStore,
) -> None:
    store_shadows = getattr(store, "__dict__", {})
    if (
        type(store) is not AgenticCoordinationStore
        or any(
            getattr(AgenticCoordinationStore, name, None) is not implementation
            for name, implementation in _SQL_SPECIALIST_V2_STORE_PINNED_METHODS
        )
        or any(name in store_shadows for name, _ in _SQL_SPECIALIST_V2_STORE_PINNED_METHODS)
        or _sql_specialist_v2_retire_dispatch_callback
        is not _SQL_SPECIALIST_V2_RETIRE_CALLBACK_FACTORY_IMPLEMENTATION
        or _sql_specialist_v2_retire_plan_callback
        is not _SQL_SPECIALIST_V2_RETIRE_PLAN_CALLBACK_FACTORY_IMPLEMENTATION
        or _sql_specialist_v2_retire_job_attempt_callback
        is not _SQL_SPECIALIST_V2_RETIRE_JOB_ATTEMPT_CALLBACK_FACTORY_IMPLEMENTATION
        or _LinuxPinnedCoordinationDatabase.close
        is not _LINUX_PINNED_COORDINATION_DATABASE_CLOSE_IMPLEMENTATION
        or _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._require_owner
        is not _SQL_SPECIALIST_V2_CAPSULE_REQUIRE_OWNER_IMPLEMENTATION
        or _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._claim
        is not _SQL_SPECIALIST_V2_CAPSULE_CLAIM_IMPLEMENTATION
        or _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._runtime_inputs
        is not _SQL_SPECIALIST_V2_CAPSULE_RUNTIME_INPUTS_IMPLEMENTATION
        or _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._retire
        is not _SQL_SPECIALIST_V2_CAPSULE_RETIRE_IMPLEMENTATION
        or _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._token_digest
        is not _SQL_SPECIALIST_V2_CAPSULE_TOKEN_DIGEST_IMPLEMENTATION
        or _AgenticSQLSpecialistDispatchRuntimeCapsuleV2._binding_identity_token
        is not _SQL_SPECIALIST_V2_CAPSULE_BINDING_TOKEN_IMPLEMENTATION
        or VerifiedSQLSpecialistJobAttemptClaimV2.__init__
        is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_INIT_IMPLEMENTATION
        or VerifiedSQLSpecialistJobAttemptClaimV2._require
        is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_REQUIRE_IMPLEMENTATION
        or VerifiedSQLSpecialistJobAttemptClaimV2._consume
        is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_CONSUME_IMPLEMENTATION
        or VerifiedSQLSpecialistJobAttemptClaimV2._retire
        is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_CLAIM_RETIRE_IMPLEMENTATION
        or vars(VerifiedSQLSpecialistJobAttemptClaimV2).get("attempt")
        is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_PROPERTY
        or _VerifiedSpecialistGatewayDeploymentMintLeaseV2._identity
        is not _MINT_LEASE_IDENTITY_IMPLEMENTATION
        or _VerifiedSpecialistGatewayDeploymentMintLeaseV2.__init__
        is not _MINT_LEASE_INIT_IMPLEMENTATION
        or _VerifiedSpecialistGatewayCompletionV2.__init__
        is not _VERIFIED_COMPLETION_INIT_IMPLEMENTATION
        or _VerifiedSpecialistGatewayCompletionV2._consume_for_terminal_receipt
        is not _VERIFIED_COMPLETION_CONSUME_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._claim_job_attempt_scope
        is not _VERIFIED_DEPLOYMENT_CLAIM_SCOPE_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._claim_observation
        is not _VERIFIED_DEPLOYMENT_CLAIM_OBSERVATION_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._worker_job_ref_from_claim
        is not _VERIFIED_DEPLOYMENT_WORKER_JOB_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._retire_job_attempt_claim
        is not _VERIFIED_DEPLOYMENT_RETIRE_CLAIM_IMPLEMENTATION
        or VerifiedSpecialistGatewayDeploymentV2._execute_job_attempt_claim
        is not _VERIFIED_DEPLOYMENT_EXECUTE_CLAIM_IMPLEMENTATION
        or vars(VerifiedSpecialistGatewayDeploymentV2).get("snapshot")
        is not _VERIFIED_DEPLOYMENT_SNAPSHOT_PROPERTY
        or vars(VerifiedSpecialistGatewayDeploymentV2).get("invocation_count")
        is not _VERIFIED_DEPLOYMENT_INVOCATION_COUNT_PROPERTY
        or build_specialist_claim_verification
        is not _SPECIALIST_CLAIM_VERIFICATION_BUILD_IMPLEMENTATION
        or build_specialist_dispatch_verification
        is not _SPECIALIST_DISPATCH_VERIFICATION_BUILD_IMPLEMENTATION
        or _specialist_capability_lineage_state_digest
        is not _SPECIALIST_CAPABILITY_LINEAGE_STATE_DIGEST_IMPLEMENTATION
        or _specialist_capability_lineage_observation
        is not _SQL_SPECIALIST_V2_LINEAGE_OBSERVATION_IMPLEMENTATION
        or _capability_ledger_runtime_identity
        is not _SQL_SPECIALIST_V2_LEDGER_RUNTIME_IDENTITY_IMPLEMENTATION
        or _sql_specialist_v2_authority_set_identity
        is not _SQL_SPECIALIST_V2_AUTHORITY_SET_IDENTITY_IMPLEMENTATION
        or _sql_specialist_v2_scheduler_task_name
        is not _SQL_SPECIALIST_V2_SCHEDULER_TASK_NAME_IMPLEMENTATION
        or _sql_specialist_v2_job_dispatch_binding
        is not _SQL_SPECIALIST_V2_JOB_DISPATCH_BINDING_IMPLEMENTATION
        or _utc is not _SQL_SPECIALIST_V2_UTC_IMPLEMENTATION
        or _sql_specialist_v2_attempt_timestamp
        is not _SQL_SPECIALIST_V2_ATTEMPT_TIMESTAMP_IMPLEMENTATION
        or _require_sql_specialist_v2_job_attempt_publication
        is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_PUBLICATION_IMPLEMENTATION
        or _build_sql_specialist_v2_job_attempt
        is not _SQL_SPECIALIST_V2_JOB_ATTEMPT_BUILD_IMPLEMENTATION
        or VerifiedSQLSpecialistDispatchPlanV2._require
        is not _SQL_SPECIALIST_V2_PLAN_REQUIRE_IMPLEMENTATION
        or VerifiedSQLSpecialistDispatchPlanV2._retire
        is not _SQL_SPECIALIST_V2_PLAN_RETIRE_IMPLEMENTATION
        or VerifiedSQLSpecialistDispatchPlanV2._require_runtime
        is not _SQL_SPECIALIST_V2_PLAN_REQUIRE_RUNTIME_IMPLEMENTATION
        or VerifiedSQLSpecialistDispatchPlanV2._claim_callback
        is not _SQL_SPECIALIST_V2_PLAN_CLAIM_CALLBACK_IMPLEMENTATION
        or VerifiedSQLSpecialistDispatchPlanV2._require_claimed_callback
        is not _SQL_SPECIALIST_V2_PLAN_REQUIRE_CLAIMED_CALLBACK_IMPLEMENTATION
        or VerifiedSQLSpecialistDispatchPlanV2._release_callback
        is not _SQL_SPECIALIST_V2_PLAN_RELEASE_CALLBACK_IMPLEMENTATION
        or VerifiedSQLSpecialistDispatchPlanV2._consume_callback
        is not _SQL_SPECIALIST_V2_PLAN_CONSUME_CALLBACK_IMPLEMENTATION
        or VerifiedSQLSpecialistPermitDispatcherV2._runtime_inputs
        is not _SQL_SPECIALIST_V2_DISPATCHER_RUNTIME_INPUTS_IMPLEMENTATION
        or VerifiedSQLSpecialistPermitDispatcherV2._dispatch_once
        is not _SQL_SPECIALIST_V2_DISPATCHER_DISPATCH_ONCE_IMPLEMENTATION
        or VerifiedSQLSpecialistPermitDispatcherV2._terminal_authorization
        is not _SQL_SPECIALIST_V2_DISPATCHER_TERMINAL_AUTHORIZATION_IMPLEMENTATION
    ):
        raise AgenticCoordinationError("SQL specialist v2 Store or capsule implementation changed")


def _canonical_checkpoint(
    checkpoint: DynamicSupervisorCheckpoint,
) -> DynamicSupervisorCheckpoint:
    return DynamicSupervisorCheckpoint.model_validate(
        checkpoint.model_dump(mode="json", by_alias=True)
    )


def _require_initial_checkpoint_shape(checkpoint: DynamicSupervisorCheckpoint) -> None:
    if (
        checkpoint.revision != 0
        or checkpoint.next_command_sequence != 1
        or checkpoint.total_assignments != 0
        or checkpoint.sessions
        or checkpoint.seen_candidate_ids
        or checkpoint.seen_semantic_digests
        or checkpoint.issued_commands
    ):
        raise ValueError("initial durable checkpoint contains non-initial Supervisor state")


def _checkpoint_bytes(checkpoint: DynamicSupervisorCheckpoint) -> bytes:
    return canonical_json_bytes(
        checkpoint.model_dump(mode="json", by_alias=True),
        label="durable Dynamic Supervisor checkpoint",
        max_bytes=_MAX_CHECKPOINT_BYTES,
    )


def _cycle_bytes(cycle: DynamicSupervisorCycle) -> bytes:
    return canonical_json_bytes(
        cycle.model_dump(mode="json", by_alias=True),
        label="durable Dynamic Supervisor cycle",
        max_bytes=_MAX_CYCLE_BYTES,
    )


def _command_bytes(command: AgentControlCommand) -> bytes:
    return canonical_json_bytes(
        command.model_dump(mode="json", by_alias=True),
        label="durable Agent Control Command",
        max_bytes=_MAX_COMMAND_BYTES,
    )


def _agent_event_bytes(event: AgentEvent) -> bytes:
    return canonical_json_bytes(
        event.model_dump(mode="json", by_alias=True),
        label="durable Agent Event",
        max_bytes=_MAX_EVENT_BYTES,
    )


def _agent_event_digest(event: AgentEvent) -> str:
    return discovery_digest(
        "pajin.agentic.durable-agent-event/v1",
        event.model_dump(mode="json", by_alias=True),
    )


def _admission_receipt_bytes(receipt: AgenticCommandAdmissionReceipt) -> bytes:
    return canonical_json_bytes(
        receipt.model_dump(mode="json", by_alias=True),
        label="Agentic Command Admission Receipt",
        max_bytes=_MAX_COMMAND_BYTES,
    )


def _specialist_definition_digest(specialist: SpecialistDefinition) -> str:
    return discovery_digest(
        "pajin.agentic.specialist-definition/v1",
        specialist.model_dump(mode="json", by_alias=True),
    )


def _specialist_execution_bytes(entry: AgenticSpecialistExecutionEntry) -> bytes:
    return canonical_json_bytes(
        entry.model_dump(mode="json", by_alias=True),
        label="durable specialist execution entry",
        max_bytes=_MAX_COMMAND_BYTES,
    )


def _prepared_capability_action_digest(action: PreparedCapabilityAction) -> str:
    return discovery_digest(
        "pajin.agentic.prepared-specialist-action/v1",
        action.model_dump(mode="json", by_alias=True),
    )


def _specialist_dispatch_plan_bytes(entry: AgenticSpecialistDispatchPlanAuditEntry) -> bytes:
    return canonical_json_bytes(
        entry.model_dump(mode="json", by_alias=True),
        label="durable specialist dispatch plan",
        max_bytes=_MAX_SPECIALIST_DISPATCH_PLAN_BYTES,
    )


def _specialist_job_attempt_bytes(entry: AgenticSpecialistJobAttempt) -> bytes:
    return canonical_json_bytes(
        entry.model_dump(mode="json", by_alias=True),
        label="durable specialist job attempt",
        max_bytes=_MAX_SPECIALIST_JOB_ATTEMPT_BYTES,
    )


def _specialist_terminal_receipt_bytes(
    receipt: AgenticSpecialistTerminalReceipt,
) -> bytes:
    return canonical_json_bytes(
        receipt.model_dump(mode="json", by_alias=True),
        label="durable specialist terminal receipt",
        max_bytes=_MAX_RECEIPT_BYTES,
    )


def _provider_request_schema_digest() -> str:
    return discovery_digest(
        "pajin.agentic.provider-chat-request-schema/v1",
        ProviderChatRequest.model_json_schema(mode="validation"),
    )


def _hypothesis_response_schema_digest() -> str:
    return discovery_digest(
        "pajin.agentic.hypothesis-response-schema/v1",
        HypothesisExpansionDraft.model_json_schema(mode="validation", by_alias=True),
    )


def _provider_chat_request_digest(chat: ProviderChatRequest) -> str:
    return discovery_digest(
        "pajin.provider.chat-request/v1",
        chat.model_dump(mode="json", by_alias=True, exclude_none=False),
    )


def _intent_bytes(intent: AgenticHypothesisInvocationIntent) -> bytes:
    return canonical_json_bytes(
        intent.model_dump(mode="json", by_alias=True),
        label="durable Hypothesis invocation intent",
        max_bytes=_MAX_INTENT_BYTES,
    )


def _command_digest(command: AgentControlCommand) -> str:
    return discovery_digest(
        "pajin.agentic.outbox-command/v1",
        command.model_dump(mode="json", by_alias=True),
    )


def _stable_hypothesis_request_id(
    *,
    binding_digest: str,
    source_checkpoint_digest: str,
) -> str:
    digest = discovery_digest(
        "pajin.agentic.hypothesis-request/v1",
        {
            "coordinationBindingDigest": binding_digest,
            "sourceCheckpointDigest": source_checkpoint_digest,
        },
    )
    return f"hypothesis-request_{digest}"


def _invocation_state_digest(
    *,
    intent_digest: str,
    state: AgenticModelInvocationState,
    dispatch_started_at: datetime | None,
    terminal_at: datetime | None,
    outcome_digest: str | None,
    receipt_reference: str | None,
    receipt_digest: str | None,
    receipt_run_path: str | None,
    receipt_run_id: str | None,
    receipt_root_digest: str | None,
    receipt_artifact_path: str | None,
    receipt_artifact_sha256: str | None,
) -> str:
    return discovery_digest(
        "pajin.agentic.hypothesis-invocation-state/v1",
        {
            "intentDigest": intent_digest,
            "state": state.value,
            "dispatchStartedAt": (
                _format_timestamp(dispatch_started_at) if dispatch_started_at is not None else None
            ),
            "terminalAt": _format_timestamp(terminal_at) if terminal_at is not None else None,
            "outcomeDigest": outcome_digest,
            "receiptReference": receipt_reference,
            "receiptDigest": receipt_digest,
            "receiptRunPath": receipt_run_path,
            "receiptRunId": receipt_run_id,
            "receiptRootDigest": receipt_root_digest,
            "receiptArtifactPath": receipt_artifact_path,
            "receiptArtifactSha256": receipt_artifact_sha256,
        },
    )


def _delivery_claim_digest(
    *,
    store_id: str,
    coordination_binding_digest: str,
    cycle_digest: str,
    command_id: str,
    command_digest: str,
    claimed_at: datetime,
) -> str:
    return discovery_digest(
        "pajin.agentic.outbox-delivery-claim/v1",
        {
            "storeId": store_id,
            "coordinationBindingDigest": coordination_binding_digest,
            "cycleDigest": cycle_digest,
            "commandId": command_id,
            "commandDigest": command_digest,
            "claimedAt": _format_timestamp(claimed_at),
        },
    )


def _outbox_state_digest(
    *,
    cycle_digest: str,
    command_digest: str,
    state: AgenticOutboxState,
    claimed_at: datetime | None,
    claim_digest: str | None,
    acknowledged_at: datetime | None,
    acknowledgement_id: str | None,
    acknowledgement_digest: str | None,
) -> str:
    return discovery_digest(
        "pajin.agentic.outbox-state/v1",
        {
            "cycleDigest": cycle_digest,
            "commandDigest": command_digest,
            "state": state.value,
            "claimedAt": _format_timestamp(claimed_at) if claimed_at is not None else None,
            "claimDigest": claim_digest,
            "acknowledgedAt": (
                _format_timestamp(acknowledged_at) if acknowledged_at is not None else None
            ),
            "acknowledgementId": acknowledgement_id,
            "acknowledgementDigest": acknowledgement_digest,
        },
    )


def _insert_checkpoint(
    connection: sqlite3.Connection,
    checkpoint: DynamicSupervisorCheckpoint,
    *,
    predecessor_digest: str | None,
    recorded_at: datetime,
) -> None:
    connection.execute(
        """
        INSERT INTO agentic_checkpoints(
            checkpoint_id, checkpoint_digest, revision, predecessor_digest,
            canonical_checkpoint, recorded_at
        ) VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            checkpoint.checkpoint_id,
            checkpoint.checkpoint_digest,
            checkpoint.revision,
            predecessor_digest,
            sqlite3.Binary(_checkpoint_bytes(checkpoint)),
            _format_timestamp(recorded_at),
        ),
    )


def _insert_cycle_outbox(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding_digest: str,
    cycle: DynamicSupervisorCycle,
) -> None:
    for ordinal, command in enumerate(cycle.commands, start=1):
        command_digest = _command_digest(command)
        state_digest = _outbox_state_digest(
            cycle_digest=cycle.cycle_digest,
            command_digest=command_digest,
            state=AgenticOutboxState.PENDING,
            claimed_at=None,
            claim_digest=None,
            acknowledged_at=None,
            acknowledgement_id=None,
            acknowledgement_digest=None,
        )
        connection.execute(
            """
            INSERT INTO agentic_command_outbox(
                command_id, command_digest, cycle_id, cycle_digest, ordinal,
                target_agent_id, command_sequence, canonical_command,
                state, claimed_at, claim_id, claim_digest,
                acknowledged_at, acknowledgement_id, acknowledgement_digest,
                state_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, NULL, ?)
            """,
            (
                command.command_id,
                command_digest,
                cycle.cycle_id,
                cycle.cycle_digest,
                ordinal,
                command.target_agent_id,
                command.sequence,
                sqlite3.Binary(_command_bytes(command)),
                AgenticOutboxState.PENDING.value,
                state_digest,
            ),
        )
    del store_id, binding_digest  # bound when rows are reconstructed from immutable metadata


def _insert_specialist_execution(
    connection: sqlite3.Connection,
    entry: AgenticSpecialistExecutionEntry,
) -> None:
    connection.execute(
        """
        INSERT INTO agentic_specialist_executions(
            reservation_id, reservation_digest, state_digest, store_id,
            coordination_binding_digest, source_head_checkpoint_id,
            source_head_checkpoint_digest, graph_snapshot_id, graph_snapshot_digest,
            cycle_id, cycle_digest, command_id, command_digest,
            admission_receipt_id, admission_receipt_digest, target_agent_id,
            task_id, candidate_id, candidate_digest, proposal_digest, target_id,
            threat_class, specialization, specialist_definition_digest,
            canonical_entry, state, reserved_at, dispatch_started_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?
        )
        """,
        (
            entry.reservation_id,
            entry.reservation_digest,
            entry.state_digest,
            entry.store_id,
            entry.coordination_binding_digest,
            entry.source_head_checkpoint_id,
            entry.source_head_checkpoint_digest,
            entry.graph_snapshot_id,
            entry.graph_snapshot_digest,
            entry.cycle_id,
            entry.cycle_digest,
            entry.command_id,
            entry.command_digest,
            entry.admission_receipt_id,
            entry.admission_receipt_digest,
            entry.target_agent_id,
            entry.task_id,
            entry.candidate_id,
            entry.candidate_digest,
            entry.proposal_digest,
            entry.target_id,
            entry.threat_class,
            entry.specialization.value,
            entry.specialist_definition_digest,
            sqlite3.Binary(_specialist_execution_bytes(entry)),
            entry.state.value,
            _format_timestamp(entry.reserved_at),
            (
                _format_timestamp(entry.dispatch_started_at)
                if entry.dispatch_started_at is not None
                else None
            ),
        ),
    )


def _insert_specialist_dispatch_plan(
    connection: sqlite3.Connection,
    entry: AgenticSpecialistDispatchPlanAuditEntry,
) -> None:
    permit = entry.action_permit
    receipt = entry.approval_consumption_receipt
    grant_receipt = entry.grant_consumption_receipt
    connection.execute(
        """
        INSERT INTO agentic_specialist_dispatch_plans(
            plan_id, plan_digest, state_digest, store_id,
            coordination_binding_digest, reservation_id, reservation_digest,
            command_id, command_digest, preparation_id, preparation_digest,
            prepared_action_digest, request_id, grant_id, grant_digest,
            approval_id, approval_digest, action_proposal_id,
            action_proposal_digest, expected_action_permit_id, canonical_entry,
            state, planned_at, action_permit_id, action_permit_digest,
            approval_receipt_id, approval_receipt_digest,
            grant_consumption_receipt_id, grant_consumption_receipt_digest,
            grant_consumed_at, callback_entered_at, reconciled_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            entry.plan_id,
            entry.plan_digest,
            entry.state_digest,
            entry.store_id,
            entry.coordination_binding_digest,
            entry.reservation_id,
            entry.reservation_digest,
            entry.command_id,
            entry.command_digest,
            entry.preparation_id,
            entry.preparation_digest,
            entry.prepared_action_digest,
            entry.prepared_action.request.request_id,
            entry.grant.grant_id,
            entry.grant.grant_digest,
            entry.approval_envelope.approval_id,
            entry.approval_envelope.approval_digest,
            entry.approval_envelope.proposal.proposal_id,
            entry.approval_envelope.proposal.proposal_digest,
            entry.expected_action_permit_id,
            sqlite3.Binary(_specialist_dispatch_plan_bytes(entry)),
            entry.state.value,
            _format_timestamp(entry.planned_at),
            permit.permit_id if permit is not None else None,
            permit.permit_digest if permit is not None else None,
            receipt.receipt_id if receipt is not None else None,
            receipt.receipt_digest if receipt is not None else None,
            grant_receipt.receipt_id if grant_receipt is not None else None,
            grant_receipt.receipt_digest if grant_receipt is not None else None,
            (_format_timestamp(grant_receipt.consumed_at) if grant_receipt is not None else None),
            (
                _format_timestamp(entry.callback_entered_at)
                if entry.callback_entered_at is not None
                else None
            ),
            _format_timestamp(entry.reconciled_at) if entry.reconciled_at is not None else None,
        ),
    )


def _cas_specialist_execution_started(
    connection: sqlite3.Connection,
    *,
    before: AgenticSpecialistExecutionEntry,
    after: AgenticSpecialistExecutionEntry,
) -> None:
    cursor = connection.execute(
        """
        UPDATE agentic_specialist_executions
        SET canonical_entry = ?, state = ?, dispatch_started_at = ?, state_digest = ?
        WHERE command_id = ? AND reservation_id = ? AND reservation_digest = ?
          AND state = ? AND state_digest = ?
        """,
        (
            sqlite3.Binary(_specialist_execution_bytes(after)),
            after.state.value,
            _format_timestamp(cast(datetime, after.dispatch_started_at)),
            after.state_digest,
            before.command_id,
            before.reservation_id,
            before.reservation_digest,
            AgenticSpecialistExecutionState.RESERVED.value,
            before.state_digest,
        ),
    )
    if cursor.rowcount != 1:
        raise AgenticCoordinationError("specialist execution lost its plan-bound compare-and-swap")


def _cas_specialist_dispatch_plan_terminal(
    connection: sqlite3.Connection,
    *,
    before: AgenticSpecialistDispatchPlanAuditEntry,
    after: AgenticSpecialistDispatchPlanAuditEntry,
) -> None:
    if type(before) is not type(after):
        raise AgenticCoordinationError("specialist dispatch terminal plan generation changed")
    permit = after.action_permit
    receipt = after.approval_consumption_receipt
    if permit is None or receipt is None:
        raise AgenticCoordinationError("specialist dispatch terminal plan lacks Permit evidence")
    grant_receipt = after.grant_consumption_receipt
    if (
        after.state is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        and grant_receipt is None
    ):
        raise AgenticCoordinationError(
            "specialist dispatch-started plan lacks Grant consumption evidence"
        )
    if (
        after.state is AgenticSpecialistDispatchPlanState.PERMIT_CONSUMED_ENTRY_UNKNOWN
        and grant_receipt is not None
    ):
        raise AgenticCoordinationError(
            "specialist reconciled plan cannot infer Grant consumption evidence"
        )
    cursor = connection.execute(
        """
        UPDATE agentic_specialist_dispatch_plans
        SET canonical_entry = ?, state = ?, state_digest = ?,
            action_permit_id = ?, action_permit_digest = ?,
            approval_receipt_id = ?, approval_receipt_digest = ?,
            grant_consumption_receipt_id = ?,
            grant_consumption_receipt_digest = ?, grant_consumed_at = ?,
            callback_entered_at = ?, reconciled_at = ?
        WHERE plan_id = ? AND plan_digest = ? AND reservation_id = ?
          AND state = ? AND state_digest = ?
        """,
        (
            sqlite3.Binary(_specialist_dispatch_plan_bytes(after)),
            after.state.value,
            after.state_digest,
            permit.permit_id,
            permit.permit_digest,
            receipt.receipt_id,
            receipt.receipt_digest,
            grant_receipt.receipt_id if grant_receipt is not None else None,
            grant_receipt.receipt_digest if grant_receipt is not None else None,
            (_format_timestamp(grant_receipt.consumed_at) if grant_receipt is not None else None),
            (
                _format_timestamp(after.callback_entered_at)
                if after.callback_entered_at is not None
                else None
            ),
            _format_timestamp(after.reconciled_at) if after.reconciled_at is not None else None,
            before.plan_id,
            before.plan_digest,
            before.reservation_id,
            AgenticSpecialistDispatchPlanState.AWAITING_PERMIT.value,
            before.state_digest,
        ),
    )
    if cursor.rowcount != 1:
        raise AgenticCoordinationError("specialist dispatch plan lost its one-use compare-and-swap")


def _insert_specialist_job_attempt(
    connection: sqlite3.Connection,
    entry: AgenticSpecialistJobAttempt,
) -> None:
    connection.execute(
        """
        INSERT INTO agentic_specialist_job_attempts(
            attempt_id, attempt_digest, state_digest, store_id,
            coordination_binding_digest, database_identity_digest,
            deployment_digest, control_plane_run_id, campaign_id,
            campaign_manifest_digest, plan_id, plan_digest, plan_state_digest,
            reservation_id, reservation_digest, reservation_state_digest,
            command_id, command_digest, target_agent_id, task_id,
            scheduler_task_name, scheduler_task_token_digest,
            runtime_capsule_token_digest, specialization,
            dispatch_binding_id, dispatch_binding_digest,
            claim_verification_id, claim_verification_digest,
            dispatch_verification_id, dispatch_verification_digest,
            dispatch_event_digest, graph_snapshot_id, graph_snapshot_digest,
            preparation_id, preparation_digest, profile_registry_digest,
            profile_id, profile_version, profile_digest,
            executor_catalog_digest, executor_id, executor_version,
            executor_digest, prepared_action_digest,
            activation_set_digest, release_id, release_digest, capability_id,
            capability_version, capability_definition_digest, capability_digest,
            capability_authority_set_id, capability_authority_set_digest,
            tool_id, tool_version, tool_digest, request_id, request_digest,
            capability_grant_id, capability_grant_digest,
            grant_lineage_state_digest, capability_grant_expires_at,
            grant_consumption_receipt_id, grant_consumption_receipt_digest,
            action_permit_id, action_permit_digest, action_permit_expires_at,
            approval_id, approval_digest, approval_expires_at,
            approval_consumption_receipt_id,
            approval_consumption_receipt_digest, dispatch_id, target_id,
            target_digest, gateway_id, gateway_version, gateway_digest,
            execution_inventory_id, execution_inventory_digest,
            worker_backend_id, worker_backend_version, worker_backend_digest,
            worker_job_id, worker_job_digest, worker_command_digest,
            worker_compiler_id, worker_compiler_version, worker_compiler_digest,
            worker_image_reference,
            worker_image_digest, worker_verifier_id, worker_verifier_version,
            worker_verifier_digest, worker_verification_key_id,
            worker_verification_key_digest, canonical_entry, state, claimed_at,
            backend_dispatch_started_at
        ) VALUES (
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
        )
        """,
        (
            entry.attempt_id,
            entry.attempt_digest,
            entry.state_digest,
            entry.store_id,
            entry.coordination_binding_digest,
            entry.database_identity_digest,
            entry.deployment_digest,
            entry.control_plane_run_id,
            entry.campaign_id,
            entry.campaign_manifest_digest,
            entry.plan_id,
            entry.plan_digest,
            entry.plan_state_digest,
            entry.reservation_id,
            entry.reservation_digest,
            entry.reservation_state_digest,
            entry.command_id,
            entry.command_digest,
            entry.target_agent_id,
            entry.task_id,
            entry.scheduler_task_name,
            entry.scheduler_task_token_digest,
            entry.runtime_capsule_token_digest,
            entry.specialization.value,
            entry.dispatch_binding_id,
            entry.dispatch_binding_digest,
            entry.claim_verification.verification_id,
            entry.claim_verification_digest,
            (
                entry.dispatch_verification.verification_id
                if entry.dispatch_verification is not None
                else None
            ),
            entry.dispatch_verification_digest,
            entry.dispatch_event_digest,
            entry.graph_snapshot_id,
            entry.graph_snapshot_digest,
            entry.preparation_id,
            entry.preparation_digest,
            entry.profile_registry_digest,
            entry.profile_id,
            entry.profile_version,
            entry.profile_digest,
            entry.executor_catalog_digest,
            entry.executor_id,
            entry.executor_version,
            entry.executor_digest,
            entry.prepared_action_digest,
            entry.activation_set_digest,
            entry.release_id,
            entry.release_digest,
            entry.capability_id,
            entry.capability_version,
            entry.capability_definition_digest,
            entry.capability_digest,
            entry.capability_authority_set_id,
            entry.capability_authority_set_digest,
            entry.tool_id,
            entry.tool_version,
            entry.tool_digest,
            entry.request_id,
            entry.request_digest,
            entry.capability_grant_id,
            entry.capability_grant_digest,
            entry.grant_lineage_state_digest,
            _format_timestamp(entry.capability_grant_expires_at),
            entry.grant_consumption_receipt_id,
            entry.grant_consumption_receipt_digest,
            entry.action_permit_id,
            entry.action_permit_digest,
            _format_timestamp(entry.action_permit_expires_at),
            entry.approval_id,
            entry.approval_digest,
            _format_timestamp(entry.approval_expires_at),
            entry.approval_consumption_receipt_id,
            entry.approval_consumption_receipt_digest,
            entry.dispatch_id,
            entry.target_id,
            entry.target_digest,
            entry.gateway_id,
            entry.gateway_version,
            entry.gateway_digest,
            entry.execution_inventory_id,
            entry.execution_inventory_digest,
            entry.worker_backend_id,
            entry.worker_backend_version,
            entry.worker_backend_digest,
            entry.worker_job_id,
            entry.worker_job_digest,
            entry.worker_command_digest,
            entry.worker_compiler_id,
            entry.worker_compiler_version,
            entry.worker_compiler_digest,
            entry.worker_image_reference,
            entry.worker_image_digest,
            entry.worker_verifier_id,
            entry.worker_verifier_version,
            entry.worker_verifier_digest,
            entry.worker_verification_key_id,
            entry.worker_verification_key_digest,
            sqlite3.Binary(_specialist_job_attempt_bytes(entry)),
            entry.state.value,
            _format_timestamp(entry.claimed_at),
            (
                _format_timestamp(entry.backend_dispatch_started_at)
                if entry.backend_dispatch_started_at is not None
                else None
            ),
        ),
    )


def _cas_specialist_job_attempt_started(
    connection: sqlite3.Connection,
    *,
    before: AgenticSpecialistJobAttempt,
    after: AgenticSpecialistJobAttempt,
) -> None:
    cursor = connection.execute(
        """
        UPDATE agentic_specialist_job_attempts
        SET canonical_entry = ?, state = ?, state_digest = ?,
            dispatch_verification_id = ?, dispatch_verification_digest = ?,
            dispatch_event_digest = ?,
            backend_dispatch_started_at = ?
        WHERE attempt_id = ? AND attempt_digest = ?
          AND state = ? AND state_digest = ?
          AND NOT EXISTS (
              SELECT 1 FROM agentic_specialist_terminal_receipts AS receipt
              WHERE receipt.attempt_id = agentic_specialist_job_attempts.attempt_id
          )
        """,
        (
            sqlite3.Binary(_specialist_job_attempt_bytes(after)),
            after.state.value,
            after.state_digest,
            (
                after.dispatch_verification.verification_id
                if after.dispatch_verification is not None
                else None
            ),
            after.dispatch_verification_digest,
            after.dispatch_event_digest,
            _format_timestamp(cast(datetime, after.backend_dispatch_started_at)),
            before.attempt_id,
            before.attempt_digest,
            AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND.value,
            before.state_digest,
        ),
    )
    if cursor.rowcount != 1:
        raise AgenticCoordinationError(
            "specialist job attempt lost its pre-backend compare-and-swap"
        )


def _insert_specialist_terminal_receipt(
    connection: sqlite3.Connection,
    receipt: AgenticSpecialistTerminalReceipt,
) -> None:
    connection.execute(
        """
        INSERT INTO agentic_specialist_terminal_receipts(
            receipt_id, receipt_digest, store_id, coordination_binding_digest,
            attempt_id, attempt_digest, attempt_state, attempt_state_digest,
            plan_id, request_id, worker_job_id, terminal_kind,
            terminal_reason_digest, target_io_state, succeeded,
            backend_terminal_proven,
            canonical_receipt, recorded_at,
            backend_finished_at, worker_result_digest,
            backend_terminal_proof_digest
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            receipt.receipt_id,
            receipt.receipt_digest,
            receipt.store_id,
            receipt.coordination_binding_digest,
            receipt.attempt_id,
            receipt.attempt_digest,
            receipt.attempt_state.value,
            receipt.attempt_state_digest,
            receipt.plan_id,
            receipt.request_id,
            receipt.worker_job_id,
            receipt.terminal_kind.value,
            receipt.terminal_reason_digest,
            receipt.target_io_state.value,
            (int(receipt.succeeded) if receipt.succeeded is not None else None),
            int(receipt.backend_terminal_proven),
            sqlite3.Binary(_specialist_terminal_receipt_bytes(receipt)),
            _format_timestamp(receipt.recorded_at),
            (
                _format_timestamp(receipt.backend_finished_at)
                if receipt.backend_finished_at is not None
                else None
            ),
            receipt.worker_result_digest,
            receipt.backend_terminal_proof_digest,
        ),
    )


def _checkpoint_by_digest(
    connection: sqlite3.Connection,
    digest: str,
) -> DynamicSupervisorCheckpoint:
    row = connection.execute(
        "SELECT * FROM agentic_checkpoints WHERE checkpoint_digest = ?",
        (digest,),
    ).fetchone()
    if row is None:
        raise AgenticCoordinationError("durable checkpoint is missing")
    raw = _required_bytes(row, "canonical_checkpoint")
    checkpoint = DynamicSupervisorCheckpoint.model_validate_json(raw)
    if _checkpoint_bytes(checkpoint) != raw:
        raise AgenticCoordinationError("durable checkpoint bytes are not canonical")
    if (
        _required_text(row, "checkpoint_id") != checkpoint.checkpoint_id
        or _required_text(row, "checkpoint_digest") != checkpoint.checkpoint_digest
        or _required_int(row, "revision") != checkpoint.revision
    ):
        raise AgenticCoordinationError("durable checkpoint index columns differ")
    _parse_timestamp(_required_text(row, "recorded_at"), label="checkpoint recorded_at")
    predecessor = _optional_text(row, "predecessor_digest")
    if checkpoint.revision == 0:
        if predecessor is not None:
            raise AgenticCoordinationError("initial checkpoint has a predecessor")
    else:
        if predecessor is None:
            raise AgenticCoordinationError("non-initial checkpoint lacks a predecessor")
        parent = connection.execute(
            "SELECT revision FROM agentic_checkpoints WHERE checkpoint_digest = ?",
            (predecessor,),
        ).fetchone()
        if parent is None or _required_int(parent, 0) + 1 != checkpoint.revision:
            raise AgenticCoordinationError("checkpoint predecessor chain differs")
    return checkpoint


def _current_checkpoint(connection: sqlite3.Connection) -> DynamicSupervisorCheckpoint:
    row = connection.execute(
        "SELECT checkpoint_digest, revision FROM agentic_checkpoint_head WHERE slot = 1"
    ).fetchone()
    if row is None:
        raise AgenticCoordinationError("durable checkpoint head is not initialized")
    checkpoint = _checkpoint_by_digest(connection, _required_text(row, "checkpoint_digest"))
    if _required_int(row, "revision") != checkpoint.revision:
        raise AgenticCoordinationError("durable checkpoint head revision differs")
    return checkpoint


def _cycle_from_row(row: sqlite3.Row) -> DynamicSupervisorCycle:
    raw = _required_bytes(row, "canonical_cycle")
    cycle = DynamicSupervisorCycle.model_validate_json(raw)
    if _cycle_bytes(cycle) != raw:
        raise AgenticCoordinationError("durable cycle bytes are not canonical")
    if (
        _required_text(row, "cycle_id") != cycle.cycle_id
        or _required_text(row, "cycle_digest") != cycle.cycle_digest
        or _required_text(row, "source_checkpoint_digest") != cycle.source_checkpoint_digest
        or _required_text(row, "resulting_checkpoint_digest")
        != cycle.resulting_checkpoint.checkpoint_digest
    ):
        raise AgenticCoordinationError("durable cycle index columns differ")
    _parse_timestamp(_required_text(row, "recorded_at"), label="cycle recorded_at")
    return cycle


def _outbox_row(connection: sqlite3.Connection, command_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM agentic_command_outbox WHERE command_id = ?",
        (command_id,),
    ).fetchone()
    if row is None:
        raise AgenticCoordinationError("outbox command is missing")
    return cast(sqlite3.Row, row)


def _inbox_row(connection: sqlite3.Connection, command_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM agentic_command_inbox WHERE command_id = ?",
        (command_id,),
    ).fetchone()
    if row is None:
        raise AgenticCoordinationError("receiver admission receipt is missing")
    return cast(sqlite3.Row, row)


def _admission_receipt_from_row(row: sqlite3.Row) -> AgenticCommandAdmissionReceipt:
    raw = _required_bytes(row, "canonical_receipt")
    receipt = AgenticCommandAdmissionReceipt.model_validate_json(raw)
    if _admission_receipt_bytes(receipt) != raw:
        raise AgenticCoordinationError("receiver admission receipt bytes are not canonical")
    if (
        _required_text(row, "receipt_id") != receipt.receipt_id
        or _required_text(row, "receipt_digest") != receipt.receipt_digest
        or _required_text(row, "command_id") != receipt.command_id
        or _required_text(row, "claim_id") != receipt.claim_id
        or _required_text(row, "claim_digest") != receipt.claim_digest
        or _required_text(row, "receiver_agent_id") != receipt.receiver_agent_id
        or _parse_timestamp(
            _required_text(row, "admitted_at"),
            label="receiver admitted_at",
        )
        != receipt.admitted_at
    ):
        raise AgenticCoordinationError("receiver admission receipt index differs")
    return receipt


def _specialist_execution_row(
    connection: sqlite3.Connection,
    command_id: str,
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM agentic_specialist_executions WHERE command_id = ?",
        (command_id,),
    ).fetchone()
    if row is None:
        raise AgenticCoordinationError("specialist execution reservation is missing")
    return cast(sqlite3.Row, row)


def _specialist_execution_from_row(
    row: sqlite3.Row,
) -> AgenticSpecialistExecutionEntry:
    raw = _required_bytes(row, "canonical_entry")
    entry = AgenticSpecialistExecutionEntry.model_validate_json(raw)
    if _specialist_execution_bytes(entry) != raw:
        raise AgenticCoordinationError("specialist execution reservation bytes are not canonical")
    text_bindings = {
        "reservation_id": entry.reservation_id,
        "reservation_digest": entry.reservation_digest,
        "state_digest": entry.state_digest,
        "store_id": entry.store_id,
        "coordination_binding_digest": entry.coordination_binding_digest,
        "source_head_checkpoint_id": entry.source_head_checkpoint_id,
        "source_head_checkpoint_digest": entry.source_head_checkpoint_digest,
        "graph_snapshot_id": entry.graph_snapshot_id,
        "graph_snapshot_digest": entry.graph_snapshot_digest,
        "cycle_id": entry.cycle_id,
        "cycle_digest": entry.cycle_digest,
        "command_id": entry.command_id,
        "command_digest": entry.command_digest,
        "admission_receipt_id": entry.admission_receipt_id,
        "admission_receipt_digest": entry.admission_receipt_digest,
        "target_agent_id": entry.target_agent_id,
        "task_id": entry.task_id,
        "candidate_id": entry.candidate_id,
        "candidate_digest": entry.candidate_digest,
        "proposal_digest": entry.proposal_digest,
        "target_id": entry.target_id,
        "threat_class": entry.threat_class,
        "specialization": entry.specialization.value,
        "specialist_definition_digest": entry.specialist_definition_digest,
        "state": entry.state.value,
        "reserved_at": _format_timestamp(entry.reserved_at),
    }
    if any(_required_text(row, key) != value for key, value in text_bindings.items()):
        raise AgenticCoordinationError("specialist execution index columns differ")
    dispatch_started_at = _optional_text(row, "dispatch_started_at")
    expected_dispatch = (
        _format_timestamp(entry.dispatch_started_at)
        if entry.dispatch_started_at is not None
        else None
    )
    if dispatch_started_at != expected_dispatch:
        raise AgenticCoordinationError("specialist execution timestamp index differs")
    return entry


def _specialist_dispatch_plan_row(
    connection: sqlite3.Connection,
    plan_id: str,
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM agentic_specialist_dispatch_plans WHERE plan_id = ?",
        (plan_id,),
    ).fetchone()
    if row is None:
        raise AgenticCoordinationError("specialist dispatch plan is missing")
    return cast(sqlite3.Row, row)


def _specialist_dispatch_plan_from_row(
    row: sqlite3.Row,
) -> AgenticSpecialistDispatchPlanEntry:
    raw = _required_bytes(row, "canonical_entry")
    entry = AgenticSpecialistDispatchPlanEntry.model_validate_json(raw)
    if _specialist_dispatch_plan_bytes(entry) != raw:
        raise AgenticCoordinationError("specialist dispatch plan bytes are not canonical")
    _validate_specialist_dispatch_plan_row_bindings(row, entry)
    return entry


def _sql_specialist_dispatch_plan_v2_from_row(
    row: sqlite3.Row,
) -> AgenticSQLSpecialistDispatchPlanEntryV2:
    raw = _required_bytes(row, "canonical_entry")
    entry = AgenticSQLSpecialistDispatchPlanEntryV2.model_validate_json(raw)
    if _specialist_dispatch_plan_bytes(entry) != raw:
        raise AgenticCoordinationError("SQL specialist v2 dispatch plan bytes are not canonical")
    _validate_specialist_dispatch_plan_row_bindings(row, entry)
    return entry


def _any_specialist_dispatch_plan_from_row(
    row: sqlite3.Row,
) -> AgenticSpecialistDispatchPlanAuditEntry:
    raw = _required_bytes(row, "canonical_entry")
    try:
        decoded = json.loads(raw)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgenticCoordinationError("specialist dispatch plan discriminator is invalid") from exc
    if type(decoded) is not dict:
        raise AgenticCoordinationError("specialist dispatch plan discriminator is invalid")
    discriminator = (
        decoded.get("apiVersion"),
        decoded.get("kind"),
        decoded.get("runtimeGeneration", None),
    )
    if (
        discriminator
        == (
            "pajin.dev/agentic-specialist-dispatch-plan/v1alpha1",
            "AgenticSpecialistDispatchPlan",
            None,
        )
        and "runtimeGeneration" not in decoded
    ):
        return _specialist_dispatch_plan_from_row(row)
    if discriminator == (
        "pajin.dev/agentic-sql-specialist-dispatch-plan/v2alpha1",
        "AgenticSQLSpecialistDispatchPlanV2",
        AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2.value,
    ):
        return _sql_specialist_dispatch_plan_v2_from_row(row)
    raise AgenticCoordinationError(
        "specialist dispatch plan generation discriminator is unsupported"
    )


def _validate_specialist_dispatch_plan_row_bindings(
    row: sqlite3.Row,
    entry: AgenticSpecialistDispatchPlanAuditEntry,
) -> None:
    text_bindings = {
        "plan_id": entry.plan_id,
        "plan_digest": entry.plan_digest,
        "state_digest": entry.state_digest,
        "store_id": entry.store_id,
        "coordination_binding_digest": entry.coordination_binding_digest,
        "reservation_id": entry.reservation_id,
        "reservation_digest": entry.reservation_digest,
        "command_id": entry.command_id,
        "command_digest": entry.command_digest,
        "preparation_id": entry.preparation_id,
        "preparation_digest": entry.preparation_digest,
        "prepared_action_digest": entry.prepared_action_digest,
        "request_id": entry.prepared_action.request.request_id,
        "grant_id": entry.grant.grant_id,
        "grant_digest": entry.grant.grant_digest,
        "approval_id": entry.approval_envelope.approval_id,
        "approval_digest": entry.approval_envelope.approval_digest,
        "action_proposal_id": entry.approval_envelope.proposal.proposal_id,
        "action_proposal_digest": entry.approval_envelope.proposal.proposal_digest,
        "expected_action_permit_id": entry.expected_action_permit_id,
        "state": entry.state.value,
        "planned_at": _format_timestamp(entry.planned_at),
    }
    if any(_required_text(row, key) != value for key, value in text_bindings.items()):
        raise AgenticCoordinationError("specialist dispatch plan index columns differ")
    permit = entry.action_permit
    receipt = entry.approval_consumption_receipt
    grant_receipt = entry.grant_consumption_receipt
    optional_bindings = {
        "action_permit_id": permit.permit_id if permit is not None else None,
        "action_permit_digest": permit.permit_digest if permit is not None else None,
        "approval_receipt_id": receipt.receipt_id if receipt is not None else None,
        "approval_receipt_digest": receipt.receipt_digest if receipt is not None else None,
        "grant_consumption_receipt_id": (
            grant_receipt.receipt_id if grant_receipt is not None else None
        ),
        "grant_consumption_receipt_digest": (
            grant_receipt.receipt_digest if grant_receipt is not None else None
        ),
        "grant_consumed_at": (
            _format_timestamp(grant_receipt.consumed_at) if grant_receipt is not None else None
        ),
        "callback_entered_at": (
            _format_timestamp(entry.callback_entered_at)
            if entry.callback_entered_at is not None
            else None
        ),
        "reconciled_at": (
            _format_timestamp(entry.reconciled_at) if entry.reconciled_at is not None else None
        ),
    }
    if any(_optional_text(row, key) != value for key, value in optional_bindings.items()):
        raise AgenticCoordinationError("specialist dispatch plan state index differs")


def _specialist_job_attempt_row(
    connection: sqlite3.Connection,
    attempt_id: str,
) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM agentic_specialist_job_attempts WHERE attempt_id = ?",
        (attempt_id,),
    ).fetchone()
    if row is None:
        raise AgenticCoordinationError("specialist job attempt is missing")
    return cast(sqlite3.Row, row)


def _specialist_job_attempt_from_row(row: sqlite3.Row) -> AgenticSpecialistJobAttempt:
    raw = _required_bytes(row, "canonical_entry")
    entry = AgenticSpecialistJobAttempt.model_validate_json(raw)
    if _specialist_job_attempt_bytes(entry) != raw:
        raise AgenticCoordinationError("specialist job-attempt bytes are not canonical")
    text_bindings = {
        "attempt_id": entry.attempt_id,
        "attempt_digest": entry.attempt_digest,
        "state_digest": entry.state_digest,
        "store_id": entry.store_id,
        "coordination_binding_digest": entry.coordination_binding_digest,
        "database_identity_digest": entry.database_identity_digest,
        "deployment_digest": entry.deployment_digest,
        "control_plane_run_id": entry.control_plane_run_id,
        "campaign_id": entry.campaign_id,
        "campaign_manifest_digest": entry.campaign_manifest_digest,
        "plan_id": entry.plan_id,
        "plan_digest": entry.plan_digest,
        "plan_state_digest": entry.plan_state_digest,
        "reservation_id": entry.reservation_id,
        "reservation_digest": entry.reservation_digest,
        "reservation_state_digest": entry.reservation_state_digest,
        "command_id": entry.command_id,
        "command_digest": entry.command_digest,
        "target_agent_id": entry.target_agent_id,
        "task_id": entry.task_id,
        "scheduler_task_name": entry.scheduler_task_name,
        "scheduler_task_token_digest": entry.scheduler_task_token_digest,
        "runtime_capsule_token_digest": entry.runtime_capsule_token_digest,
        "specialization": entry.specialization.value,
        "dispatch_binding_id": entry.dispatch_binding_id,
        "dispatch_binding_digest": entry.dispatch_binding_digest,
        "claim_verification_id": entry.claim_verification.verification_id,
        "claim_verification_digest": entry.claim_verification_digest,
        "graph_snapshot_id": entry.graph_snapshot_id,
        "graph_snapshot_digest": entry.graph_snapshot_digest,
        "preparation_id": entry.preparation_id,
        "preparation_digest": entry.preparation_digest,
        "profile_registry_digest": entry.profile_registry_digest,
        "profile_id": entry.profile_id,
        "profile_version": entry.profile_version,
        "profile_digest": entry.profile_digest,
        "executor_catalog_digest": entry.executor_catalog_digest,
        "executor_id": entry.executor_id,
        "executor_version": entry.executor_version,
        "executor_digest": entry.executor_digest,
        "prepared_action_digest": entry.prepared_action_digest,
        "activation_set_digest": entry.activation_set_digest,
        "release_id": entry.release_id,
        "release_digest": entry.release_digest,
        "capability_id": entry.capability_id,
        "capability_version": entry.capability_version,
        "capability_definition_digest": entry.capability_definition_digest,
        "capability_digest": entry.capability_digest,
        "capability_authority_set_id": entry.capability_authority_set_id,
        "capability_authority_set_digest": entry.capability_authority_set_digest,
        "tool_id": entry.tool_id,
        "tool_version": entry.tool_version,
        "tool_digest": entry.tool_digest,
        "request_id": entry.request_id,
        "request_digest": entry.request_digest,
        "capability_grant_id": entry.capability_grant_id,
        "capability_grant_digest": entry.capability_grant_digest,
        "grant_lineage_state_digest": entry.grant_lineage_state_digest,
        "capability_grant_expires_at": _format_timestamp(entry.capability_grant_expires_at),
        "grant_consumption_receipt_id": entry.grant_consumption_receipt_id,
        "grant_consumption_receipt_digest": entry.grant_consumption_receipt_digest,
        "action_permit_id": entry.action_permit_id,
        "action_permit_digest": entry.action_permit_digest,
        "action_permit_expires_at": _format_timestamp(entry.action_permit_expires_at),
        "approval_id": entry.approval_id,
        "approval_digest": entry.approval_digest,
        "approval_expires_at": _format_timestamp(entry.approval_expires_at),
        "approval_consumption_receipt_id": entry.approval_consumption_receipt_id,
        "approval_consumption_receipt_digest": entry.approval_consumption_receipt_digest,
        "dispatch_id": entry.dispatch_id,
        "target_id": entry.target_id,
        "target_digest": entry.target_digest,
        "gateway_id": entry.gateway_id,
        "gateway_version": entry.gateway_version,
        "gateway_digest": entry.gateway_digest,
        "execution_inventory_id": entry.execution_inventory_id,
        "execution_inventory_digest": entry.execution_inventory_digest,
        "worker_backend_id": entry.worker_backend_id,
        "worker_backend_version": entry.worker_backend_version,
        "worker_backend_digest": entry.worker_backend_digest,
        "worker_job_id": entry.worker_job_id,
        "worker_job_digest": entry.worker_job_digest,
        "worker_command_digest": entry.worker_command_digest,
        "worker_compiler_id": entry.worker_compiler_id,
        "worker_compiler_version": entry.worker_compiler_version,
        "worker_compiler_digest": entry.worker_compiler_digest,
        "worker_image_reference": entry.worker_image_reference,
        "worker_image_digest": entry.worker_image_digest,
        "worker_verifier_id": entry.worker_verifier_id,
        "worker_verifier_version": entry.worker_verifier_version,
        "worker_verifier_digest": entry.worker_verifier_digest,
        "worker_verification_key_id": entry.worker_verification_key_id,
        "worker_verification_key_digest": entry.worker_verification_key_digest,
        "state": entry.state.value,
        "claimed_at": _format_timestamp(entry.claimed_at),
    }
    if any(_required_text(row, key) != value for key, value in text_bindings.items()):
        raise AgenticCoordinationError("specialist job-attempt index columns differ")
    optional_state_bindings = {
        "dispatch_verification_id": (
            entry.dispatch_verification.verification_id
            if entry.dispatch_verification is not None
            else None
        ),
        "dispatch_verification_digest": entry.dispatch_verification_digest,
        "dispatch_event_digest": entry.dispatch_event_digest,
        "backend_dispatch_started_at": (
            _format_timestamp(entry.backend_dispatch_started_at)
            if entry.backend_dispatch_started_at is not None
            else None
        ),
    }
    if any(_optional_text(row, key) != value for key, value in optional_state_bindings.items()):
        raise AgenticCoordinationError("specialist job-attempt state index differs")
    return entry


def _specialist_terminal_receipt_row(
    connection: sqlite3.Connection,
    attempt_id: str,
) -> sqlite3.Row | None:
    return cast(
        sqlite3.Row | None,
        connection.execute(
            "SELECT * FROM agentic_specialist_terminal_receipts WHERE attempt_id = ?",
            (attempt_id,),
        ).fetchone(),
    )


def _specialist_terminal_receipt_from_row(
    row: sqlite3.Row,
) -> AgenticSpecialistTerminalReceipt:
    raw = _required_bytes(row, "canonical_receipt")
    receipt = AgenticSpecialistTerminalReceipt.model_validate_json(raw)
    if _specialist_terminal_receipt_bytes(receipt) != raw:
        raise AgenticCoordinationError("specialist terminal-receipt bytes are not canonical")
    text_bindings = {
        "receipt_id": receipt.receipt_id,
        "receipt_digest": receipt.receipt_digest,
        "store_id": receipt.store_id,
        "coordination_binding_digest": receipt.coordination_binding_digest,
        "attempt_id": receipt.attempt_id,
        "attempt_digest": receipt.attempt_digest,
        "attempt_state": receipt.attempt_state.value,
        "attempt_state_digest": receipt.attempt_state_digest,
        "plan_id": receipt.plan_id,
        "request_id": receipt.request_id,
        "worker_job_id": receipt.worker_job_id,
        "terminal_kind": receipt.terminal_kind.value,
        "terminal_reason_digest": receipt.terminal_reason_digest,
        "target_io_state": receipt.target_io_state.value,
        "recorded_at": _format_timestamp(receipt.recorded_at),
    }
    if any(_required_text(row, key) != value for key, value in text_bindings.items()):
        raise AgenticCoordinationError("specialist terminal-receipt index columns differ")
    observed_succeeded = row["succeeded"]
    expected_succeeded = int(receipt.succeeded) if receipt.succeeded is not None else None
    if observed_succeeded != expected_succeeded or _required_int(
        row, "backend_terminal_proven"
    ) != int(receipt.backend_terminal_proven):
        raise AgenticCoordinationError("specialist terminal-receipt result markers differ")
    optional_bindings = {
        "backend_finished_at": (
            _format_timestamp(receipt.backend_finished_at)
            if receipt.backend_finished_at is not None
            else None
        ),
        "worker_result_digest": receipt.worker_result_digest,
        "backend_terminal_proof_digest": receipt.backend_terminal_proof_digest,
    }
    if any(_optional_text(row, key) != value for key, value in optional_bindings.items()):
        raise AgenticCoordinationError("specialist terminal-receipt evidence index differs")
    return receipt


def _event_from_row(row: sqlite3.Row) -> tuple[AgentEvent, str, str, str]:
    raw = _required_bytes(row, "canonical_event")
    event = AgentEvent.model_validate_json(raw)
    digest = _agent_event_digest(event)
    if _agent_event_bytes(event) != raw:
        raise AgenticCoordinationError("durable Agent Event bytes are not canonical")
    if (
        _required_text(row, "event_id") != event.event_id
        or _required_text(row, "event_digest") != digest
        or _required_text(row, "command_id") != event.command_id
        or _required_text(row, "agent_id") != event.agent_id
        or _required_int(row, "event_sequence") != event.sequence
    ):
        raise AgenticCoordinationError("durable Agent Event index differs")
    _parse_timestamp(_required_text(row, "recorded_at"), label="Agent Event recorded_at")
    return (
        event,
        digest,
        _required_text(row, "source_checkpoint_digest"),
        _required_text(row, "resulting_checkpoint_digest"),
    )


def _outbox_for_cycle(
    connection: sqlite3.Connection,
    cycle_digest: str,
    *,
    store_id: str,
    binding_digest: str,
) -> tuple[AgenticOutboxEntry, ...]:
    return tuple(
        _outbox_from_row(
            row,
            store_id=store_id,
            binding_digest=binding_digest,
        )
        for row in connection.execute(
            "SELECT * FROM agentic_command_outbox WHERE cycle_digest = ? ORDER BY ordinal",
            (cycle_digest,),
        )
    )


def _outbox_from_row(
    row: sqlite3.Row,
    *,
    store_id: str,
    binding_digest: str,
) -> AgenticOutboxEntry:
    raw = _required_bytes(row, "canonical_command")
    command = AgentControlCommand.model_validate_json(raw)
    if _command_bytes(command) != raw:
        raise AgenticCoordinationError("outbox Command bytes are not canonical")
    try:
        state = AgenticOutboxState(_required_text(row, "state"))
    except ValueError as exc:
        raise AgenticCoordinationError("outbox state is invalid") from exc
    entry = AgenticOutboxEntry(
        storeId=store_id,
        coordinationBindingDigest=binding_digest,
        cycleId=_required_text(row, "cycle_id"),
        cycleDigest=_required_text(row, "cycle_digest"),
        ordinal=_required_int(row, "ordinal"),
        command=command,
        commandDigest=_required_text(row, "command_digest"),
        state=state,
        stateDigest=_required_text(row, "state_digest"),
        claimedAt=cast(datetime | None, _optional_text(row, "claimed_at")),
        claimId=_optional_text(row, "claim_id"),
        claimDigest=_optional_text(row, "claim_digest"),
        acknowledgedAt=cast(datetime | None, _optional_text(row, "acknowledged_at")),
        acknowledgementId=_optional_text(row, "acknowledgement_id"),
        acknowledgementDigest=_optional_text(row, "acknowledgement_digest"),
    )
    if (
        command.command_id != _required_text(row, "command_id")
        or command.target_agent_id != _required_text(row, "target_agent_id")
        or command.sequence != _required_int(row, "command_sequence")
    ):
        raise AgenticCoordinationError("outbox Command index differs")
    return entry


def _claim_from_entry(entry: AgenticOutboxEntry) -> AgenticOutboxDeliveryClaim:
    if (
        entry.claimed_at is None
        or entry.claim_id is None
        or entry.claim_digest is None
        or entry.state is AgenticOutboxState.PENDING
    ):
        raise AgenticCoordinationError("outbox entry has no delivery claim")
    return AgenticOutboxDeliveryClaim(
        storeId=entry.store_id,
        coordinationBindingDigest=entry.coordination_binding_digest,
        cycleId=entry.cycle_id,
        cycleDigest=entry.cycle_digest,
        command=entry.command,
        commandDigest=entry.command_digest,
        claimedAt=cast(datetime, _format_timestamp(entry.claimed_at)),
        claimId=entry.claim_id,
        claimDigest=entry.claim_digest,
    )


def _acknowledged_specialist_transport(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding: AgenticCoordinationBinding,
    command_id: str,
) -> tuple[AgenticOutboxEntry, AgentControlCommand, AgenticCommandAdmissionReceipt]:
    outbox = _outbox_from_row(
        _outbox_row(connection, command_id),
        store_id=store_id,
        binding_digest=binding.binding_digest,
    )
    command = outbox.command
    if command.command not in {
        AgentControlCommandKind.ASSIGN,
        AgentControlCommandKind.FOLLOW_UP,
    }:
        raise AgenticCoordinationError("specialist execution requires an assignment command")
    if command.task_id is None or command.candidate_id is None:
        raise AgenticCoordinationError("specialist assignment identities are missing")
    if outbox.state is not AgenticOutboxState.ACKNOWLEDGED:
        raise AgenticCoordinationError(
            "specialist assignment transport is not durably acknowledged"
        )
    admission = _admission_receipt_from_row(_inbox_row(connection, command.command_id))
    if (
        outbox.claim_id != admission.claim_id
        or outbox.claim_digest != admission.claim_digest
        or outbox.acknowledgement_id != admission.receipt_id
        or outbox.acknowledgement_digest != admission.receipt_digest
        or admission.command_id != command.command_id
        or admission.command_digest != outbox.command_digest
        or admission.receiver_agent_id != command.target_agent_id
    ):
        raise AgenticCoordinationError(
            "specialist assignment receiver admission differs from transport authority"
        )
    return outbox, command, admission


def _selected_specialist_route(
    connection: sqlite3.Connection,
    *,
    binding: AgenticCoordinationBinding,
    outbox: AgenticOutboxEntry,
    command: AgentControlCommand,
) -> tuple[DynamicSupervisorCycle, FrontierCandidate, FrontierDecision, SpecialistDefinition]:
    cycle_row = connection.execute(
        "SELECT * FROM agentic_cycles WHERE cycle_id = ?",
        (outbox.cycle_id,),
    ).fetchone()
    if cycle_row is None:
        raise AgenticCoordinationError("specialist assignment cycle is missing")
    cycle = _cycle_from_row(cast(sqlite3.Row, cycle_row))
    if cycle.cycle_digest != outbox.cycle_digest or cycle.exploit_group != binding.exploit_group:
        raise AgenticCoordinationError("specialist assignment cycle binding differs")
    cycle_commands = tuple(item for item in cycle.commands if item.command_id == command.command_id)
    if len(cycle_commands) != 1 or cycle_commands[0] != command:
        raise AgenticCoordinationError("specialist assignment command differs from its cycle")
    candidates = tuple(
        item for item in cycle.candidates if item.candidate_id == command.candidate_id
    )
    decisions = tuple(item for item in cycle.decisions if item.candidate_id == command.candidate_id)
    if len(candidates) != 1 or len(decisions) != 1:
        raise AgenticCoordinationError("specialist assignment Candidate decision is missing")
    candidate = candidates[0]
    decision = decisions[0]
    if decision.disposition is not FrontierDisposition.SELECTED:
        raise AgenticCoordinationError("specialist assignment Candidate was not selected")
    proposal = candidate.proposal
    if (
        proposal.specialization is not command.specialization
        or proposal.target_id not in binding.allowed_target_ids
    ):
        raise AgenticCoordinationError("specialist assignment proposal binding differs")
    specialist = binding.exploit_group.specialist_for(
        command.specialization,
        proposal.threat_class,
    )
    if specialist is None:
        raise AgenticCoordinationError("specialist assignment has no exact specialist route")
    return cycle, candidate, decision, specialist


def _require_live_specialist_assignment(
    checkpoint: DynamicSupervisorCheckpoint,
    command: AgentControlCommand,
) -> None:
    issued = tuple(
        item for item in checkpoint.issued_commands if item.command_id == command.command_id
    )
    if len(issued) != 1:
        raise AgenticCoordinationError("specialist assignment is not in the current checkpoint")
    issued_command = issued[0]
    if (
        issued_command.terminal
        or issued_command.agent_id != command.target_agent_id
        or issued_command.command is not command.command
        or issued_command.command_sequence != command.sequence
        or issued_command.task_id != command.task_id
        or issued_command.candidate_id != command.candidate_id
    ):
        raise AgenticCoordinationError("specialist assignment is terminal or no longer live")
    sessions = tuple(
        item for item in checkpoint.sessions if item.session_id == command.target_agent_id
    )
    if len(sessions) != 1:
        raise AgenticCoordinationError("specialist assignment Agent Session is missing")
    session = sessions[0]
    if (
        session.state is not AgentSessionState.ASSIGNED
        or session.specialization is not command.specialization
        or session.current_task_id != command.task_id
        or session.current_candidate_id != command.candidate_id
    ):
        raise AgenticCoordinationError("specialist assignment is not current in its Agent Session")


def _admitted_specialist_assignment_material(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding: AgenticCoordinationBinding,
    checkpoint: DynamicSupervisorCheckpoint,
    command_id: str,
) -> _SpecialistAssignmentMaterial:
    try:
        binding.require_checkpoint(checkpoint)
    except ValueError as exc:
        raise AgenticCoordinationError(
            "specialist assignment checkpoint differs from its deployment binding"
        ) from exc
    outbox, command, admission = _acknowledged_specialist_transport(
        connection,
        store_id=store_id,
        binding=binding,
        command_id=command_id,
    )
    cycle, candidate, decision, specialist = _selected_specialist_route(
        connection,
        binding=binding,
        outbox=outbox,
        command=command,
    )
    _require_live_specialist_assignment(checkpoint, command)
    return _SpecialistAssignmentMaterial(
        outbox=outbox,
        admission=admission,
        cycle=cycle,
        command=command,
        candidate=candidate,
        decision=decision,
        specialist=specialist,
    )


def _invocation_row(connection: sqlite3.Connection, intent_id: str) -> sqlite3.Row:
    row = connection.execute(
        "SELECT * FROM agentic_model_invocations WHERE intent_id = ?",
        (intent_id,),
    ).fetchone()
    if row is None:
        raise AgenticCoordinationError("Hypothesis invocation is missing")
    return cast(sqlite3.Row, row)


def _invocation_from_row(row: sqlite3.Row) -> AgenticModelInvocationEntry:
    raw = _required_bytes(row, "canonical_intent")
    intent = AgenticHypothesisInvocationIntent.model_validate_json(raw)
    if _intent_bytes(intent) != raw:
        raise AgenticCoordinationError("Hypothesis invocation intent bytes are not canonical")
    if (
        _required_text(row, "intent_id") != intent.intent_id
        or _required_text(row, "intent_digest") != intent.intent_digest
        or _required_text(row, "stable_request_id") != intent.stable_request_id
        or _required_text(row, "provider_run_id") != intent.provider_run_id
        or _required_text(row, "source_checkpoint_digest") != intent.source_checkpoint_digest
        or _required_text(row, "context_digest") != intent.context_digest
        or _required_text(row, "projection_digest") != intent.projection_digest
        or _required_text(row, "request_binding_digest") != intent.request_binding_digest
    ):
        raise AgenticCoordinationError("Hypothesis invocation index columns differ")
    try:
        state = AgenticModelInvocationState(_required_text(row, "state"))
    except ValueError as exc:
        raise AgenticCoordinationError("Hypothesis invocation state is invalid") from exc
    return AgenticModelInvocationEntry(
        intent=intent,
        state=state,
        stateDigest=_required_text(row, "state_digest"),
        dispatchStartedAt=cast(datetime | None, _optional_text(row, "dispatch_started_at")),
        terminalAt=cast(datetime | None, _optional_text(row, "terminal_at")),
        outcomeDigest=_optional_text(row, "outcome_digest"),
        receiptReference=_optional_text(row, "receipt_reference"),
        receiptDigest=_optional_text(row, "receipt_digest"),
        receiptRunPath=_optional_text(row, "receipt_run_path"),
        receiptRunId=_optional_text(row, "receipt_run_id"),
        receiptRootDigest=_optional_text(row, "receipt_root_digest"),
        receiptArtifactPath=_optional_text(row, "receipt_artifact_path"),
        receiptArtifactSha256=_optional_text(row, "receipt_artifact_sha256"),
        manualReviewRequired=(
            state is AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        ),
    )


def _validate_structural_history(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding: AgenticCoordinationBinding,
) -> tuple[DynamicSupervisorCheckpoint, ...]:
    checkpoint_rows = connection.execute(
        "SELECT * FROM agentic_checkpoints ORDER BY revision"
    ).fetchall()
    if not checkpoint_rows:
        raise AgenticCoordinationError("durable checkpoint history is empty")
    chain = tuple(
        _checkpoint_by_digest(connection, _required_text(row, "checkpoint_digest"))
        for row in checkpoint_rows
    )
    try:
        _require_initial_checkpoint_shape(chain[0])
    except ValueError as exc:
        raise AgenticCoordinationError("durable genesis is not pristine") from exc
    if (
        chain[0].checkpoint_id != binding.initial_checkpoint_id
        or chain[0].checkpoint_digest != binding.initial_checkpoint_digest
    ):
        raise AgenticCoordinationError("durable genesis differs from deployment binding")
    if tuple(item.revision for item in chain) != tuple(range(len(chain))):
        raise AgenticCoordinationError("durable checkpoint revisions are not contiguous")
    for index, _checkpoint in enumerate(chain):
        predecessor = _optional_text(checkpoint_rows[index], "predecessor_digest")
        expected = None if index == 0 else chain[index - 1].checkpoint_digest
        if predecessor != expected:
            raise AgenticCoordinationError("durable checkpoint predecessor chain differs")
    if _current_checkpoint(connection) != chain[-1]:
        raise AgenticCoordinationError("durable checkpoint head is rewound or incomplete")
    cycles_by_result = _validated_cycles(
        connection,
        store_id=store_id,
        binding_digest=binding.binding_digest,
    )
    events_by_result = _validated_events(
        connection,
        store_id=store_id,
        binding_digest=binding.binding_digest,
    )
    _validate_transition_coverage(chain, cycles_by_result, events_by_result)
    _validate_delivery_history(
        connection,
        store_id=store_id,
        binding_digest=binding.binding_digest,
        covered_commands={
            command.command_id for cycle in cycles_by_result.values() for command in cycle.commands
        },
    )
    _validate_specialist_execution_history(
        connection,
        store_id=store_id,
        binding=binding,
        chain=chain,
    )
    _validate_specialist_dispatch_plan_history(
        connection,
        store_id=store_id,
        binding=binding,
    )
    _validate_specialist_job_attempt_history(
        connection,
        store_id=store_id,
        binding=binding,
    )
    checkpoint_digests = {item.checkpoint_digest for item in chain}
    for row in connection.execute("SELECT * FROM agentic_model_invocations ORDER BY rowid"):
        invocation = _invocation_from_row(row)
        if invocation.intent.source_checkpoint_digest not in checkpoint_digests:
            raise AgenticCoordinationError("Hypothesis invocation references a foreign checkpoint")
    return chain


def _validate_specialist_execution_history(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding: AgenticCoordinationBinding,
    chain: tuple[DynamicSupervisorCheckpoint, ...],
) -> None:
    checkpoints = {(item.checkpoint_id, item.checkpoint_digest): item for item in chain}
    for row in connection.execute("SELECT * FROM agentic_specialist_executions ORDER BY rowid"):
        entry = _specialist_execution_from_row(row)
        checkpoint = checkpoints.get(
            (
                entry.source_head_checkpoint_id,
                entry.source_head_checkpoint_digest,
            )
        )
        if checkpoint is None:
            raise AgenticCoordinationError(
                "specialist execution references a foreign durable checkpoint"
            )
        material = _admitted_specialist_assignment_material(
            connection,
            store_id=store_id,
            binding=binding,
            checkpoint=checkpoint,
            command_id=entry.command_id,
        )
        proposal = material.candidate.proposal
        expected = {
            "store_id": store_id,
            "coordination_binding_digest": binding.binding_digest,
            "graph_snapshot_id": binding.source_snapshot_id,
            "graph_snapshot_digest": binding.source_snapshot_digest,
            "cycle_id": material.cycle.cycle_id,
            "cycle_digest": material.cycle.cycle_digest,
            "command_digest": material.outbox.command_digest,
            "admission_receipt_id": material.admission.receipt_id,
            "admission_receipt_digest": material.admission.receipt_digest,
            "target_agent_id": material.command.target_agent_id,
            "task_id": material.command.task_id,
            "candidate_id": material.candidate.candidate_id,
            "candidate_digest": material.candidate.candidate_digest,
            "proposal_digest": proposal.proposal_digest,
            "target_id": proposal.target_id,
            "threat_class": proposal.threat_class,
            "specialization": material.command.specialization,
            "specialist_definition_digest": _specialist_definition_digest(material.specialist),
        }
        if any(getattr(entry, key) != value for key, value in expected.items()):
            raise AgenticCoordinationError(
                "specialist execution differs from its admitted assignment"
            )
        if (
            material.outbox.acknowledged_at is None
            or entry.reserved_at < material.admission.admitted_at
            or entry.reserved_at < material.outbox.acknowledged_at
        ):
            raise AgenticCoordinationError(
                "specialist execution reservation predates durable acknowledgement"
            )


def _validate_specialist_dispatch_plan_history(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding: AgenticCoordinationBinding,
) -> None:
    for row in connection.execute("SELECT * FROM agentic_specialist_dispatch_plans ORDER BY rowid"):
        plan = _any_specialist_dispatch_plan_from_row(row)
        execution = _specialist_execution_from_row(
            _specialist_execution_row(connection, plan.command_id)
        )
        expected = {
            "store_id": store_id,
            "coordination_binding_digest": binding.binding_digest,
            "control_plane_run_id": binding.control_plane_run_id,
            "campaign_id": binding.campaign_id,
            "campaign_manifest_digest": binding.campaign_manifest_digest,
            "reservation_id": execution.reservation_id,
            "reservation_digest": execution.reservation_digest,
            "reservation_state_digest": (
                AgenticSpecialistExecutionEntry.model_validate(
                    {
                        **execution.model_dump(mode="json", by_alias=True),
                        "state": AgenticSpecialistExecutionState.RESERVED.value,
                        "stateDigest": "",
                        "dispatchStartedAt": None,
                    }
                ).state_digest
                if execution.state
                is AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                else execution.state_digest
            ),
            "source_head_checkpoint_id": execution.source_head_checkpoint_id,
            "source_head_checkpoint_digest": execution.source_head_checkpoint_digest,
            "graph_snapshot_id": execution.graph_snapshot_id,
            "graph_snapshot_digest": execution.graph_snapshot_digest,
            "command_id": execution.command_id,
            "command_digest": execution.command_digest,
            "target_agent_id": execution.target_agent_id,
            "task_id": execution.task_id,
            "specialization": execution.specialization,
            "target_id": execution.target_id,
        }
        if any(getattr(plan, key) != value for key, value in expected.items()):
            raise AgenticCoordinationError(
                "specialist dispatch plan differs from its durable reservation"
            )
        if plan.planned_at < execution.reserved_at:
            raise AgenticCoordinationError(
                "specialist dispatch plan predates its durable reservation"
            )
        if plan.state is AgenticSpecialistDispatchPlanState.AWAITING_PERMIT:
            if execution.state is not AgenticSpecialistExecutionState.RESERVED:
                raise AgenticCoordinationError(
                    "awaiting specialist dispatch plan has already entered execution"
                )
        elif plan.state is AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN:
            if (
                execution.state
                is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
                or execution.dispatch_started_at != plan.callback_entered_at
            ):
                raise AgenticCoordinationError(
                    "specialist dispatch plan and execution crash fence differ"
                )
        elif execution.state is not AgenticSpecialistExecutionState.RESERVED:
            raise AgenticCoordinationError(
                "reconciled Permit consumption cannot imply specialist execution"
            )


def _validate_specialist_job_attempt_history(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding: AgenticCoordinationBinding,
) -> None:
    attempts: dict[str, AgenticSpecialistJobAttempt] = {}
    for row in connection.execute("SELECT * FROM agentic_specialist_job_attempts ORDER BY rowid"):
        attempt = _specialist_job_attempt_from_row(row)
        plan = _sql_specialist_dispatch_plan_v2_from_row(
            _specialist_dispatch_plan_row(connection, attempt.plan_id)
        )
        execution = _specialist_execution_from_row(
            _specialist_execution_row(connection, attempt.command_id)
        )
        permit = plan.action_permit
        approval_receipt = plan.approval_consumption_receipt
        grant_receipt = plan.grant_consumption_receipt
        action = plan.prepared_action
        capability = action.capability
        if (
            plan.runtime_generation is not AgenticSpecialistRuntimeGeneration.SQL_SPECIALIST_V2
            or plan.state is not AgenticSpecialistDispatchPlanState.DISPATCH_STARTED_OUTCOME_UNKNOWN
            or execution.state
            is not AgenticSpecialistExecutionState.DISPATCH_STARTED_OUTCOME_UNKNOWN
            or permit is None
            or approval_receipt is None
            or grant_receipt is None
        ):
            raise AgenticCoordinationError(
                "specialist job attempt lacks the durable Permit crash fence"
            )
        expected = {
            "store_id": store_id,
            "coordination_binding_digest": binding.binding_digest,
            "deployment_digest": binding.deployment_digest,
            "control_plane_run_id": binding.control_plane_run_id,
            "campaign_id": binding.campaign_id,
            "campaign_manifest_digest": binding.campaign_manifest_digest,
            "plan_digest": plan.plan_digest,
            "plan_state_digest": plan.state_digest,
            "reservation_id": execution.reservation_id,
            "reservation_digest": execution.reservation_digest,
            "reservation_state_digest": execution.state_digest,
            "command_id": execution.command_id,
            "command_digest": execution.command_digest,
            "target_agent_id": execution.target_agent_id,
            "task_id": execution.task_id,
            "specialization": execution.specialization,
            "graph_snapshot_id": plan.graph_snapshot_id,
            "graph_snapshot_digest": plan.graph_snapshot_digest,
            "scheduler_task_token_digest": plan.scheduler_task_token_digest,
            "prepared_action_digest": plan.prepared_action_digest,
            "activation_set_digest": action.activation_set_digest,
            "release_id": action.release.release_id,
            "release_digest": action.release.release_digest,
            "capability_id": capability.capability_id,
            "capability_version": capability.capability_version,
            "capability_definition_digest": capability.definition_digest,
            "capability_digest": capability.capability_digest,
            "tool_id": capability.tool_id,
            "tool_version": capability.tool_version,
            "tool_digest": capability.tool_digest,
            "request_id": action.request.request_id,
            "request_digest": action.request_digest,
            "grant_consumption_receipt_id": grant_receipt.receipt_id,
            "grant_consumption_receipt_digest": grant_receipt.receipt_digest,
            "action_permit_id": permit.permit_id,
            "action_permit_digest": permit.permit_digest,
            "approval_consumption_receipt_id": approval_receipt.receipt_id,
            "approval_consumption_receipt_digest": approval_receipt.receipt_digest,
            "dispatch_id": permit.dispatch_id,
            "target_id": plan.target_id,
            "target_digest": plan.target_digest,
        }
        if any(getattr(attempt, key) != value for key, value in expected.items()):
            raise AgenticCoordinationError("specialist job attempt differs from its sealed plan")
        if attempt.claimed_at < grant_receipt.consumed_at:
            raise AgenticCoordinationError("specialist job attempt predates Grant consumption")
        attempts[attempt.attempt_id] = attempt

    for row in connection.execute(
        "SELECT * FROM agentic_specialist_terminal_receipts ORDER BY rowid"
    ):
        receipt = _specialist_terminal_receipt_from_row(row)
        parent_attempt = attempts.get(receipt.attempt_id)
        if parent_attempt is None:
            raise AgenticCoordinationError(
                "specialist terminal receipt references a missing job attempt"
            )
        if (
            receipt.store_id != store_id
            or receipt.coordination_binding_digest != binding.binding_digest
            or receipt.attempt_digest != parent_attempt.attempt_digest
            or receipt.attempt_state is not parent_attempt.state
            or receipt.attempt_state_digest != parent_attempt.state_digest
            or receipt.plan_id != parent_attempt.plan_id
            or receipt.request_id != parent_attempt.request_id
            or receipt.worker_job_id != parent_attempt.worker_job_id
            or receipt.recorded_at < parent_attempt.claimed_at
            or (
                parent_attempt.backend_dispatch_started_at is not None
                and receipt.recorded_at < parent_attempt.backend_dispatch_started_at
            )
            or (
                receipt.backend_finished_at is not None
                and parent_attempt.backend_dispatch_started_at is not None
                and receipt.backend_finished_at < parent_attempt.backend_dispatch_started_at
            )
        ):
            raise AgenticCoordinationError(
                "specialist terminal receipt differs from its job attempt"
            )


def _validated_cycles(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding_digest: str,
) -> dict[str, DynamicSupervisorCycle]:
    cycles_by_result: dict[str, DynamicSupervisorCycle] = {}
    for row in connection.execute("SELECT * FROM agentic_cycles ORDER BY rowid"):
        cycle = _cycle_from_row(row)
        if cycle.resulting_checkpoint.checkpoint_digest in cycles_by_result:
            raise AgenticCoordinationError("durable cycle result repeats")
        cycles_by_result[cycle.resulting_checkpoint.checkpoint_digest] = cycle
        entries = _outbox_for_cycle(
            connection,
            cycle.cycle_digest,
            store_id=store_id,
            binding_digest=binding_digest,
        )
        if tuple(item.command for item in entries) != cycle.commands or tuple(
            item.ordinal for item in entries
        ) != tuple(range(1, len(cycle.commands) + 1)):
            raise AgenticCoordinationError("cycle command outbox coverage differs")
    return cycles_by_result


def _validated_events(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding_digest: str,
) -> dict[str, tuple[AgentEvent, str, str, str]]:
    events_by_result: dict[
        str,
        tuple[AgentEvent, str, str, str],
    ] = {}
    for row in connection.execute("SELECT * FROM agentic_events ORDER BY rowid"):
        parsed = _event_from_row(row)
        event = parsed[0]
        try:
            outbox = _outbox_from_row(
                _outbox_row(connection, event.command_id),
                store_id=store_id,
                binding_digest=binding_digest,
            )
            receipt = _admission_receipt_from_row(_inbox_row(connection, event.command_id))
        except AgenticCoordinationError as exc:
            raise AgenticCoordinationError(
                "durable Agent Event lacks exact acknowledged receiver admission"
            ) from exc
        recorded_at = _parse_timestamp(
            _required_text(row, "recorded_at"),
            label="Agent Event recorded_at",
        )
        if (
            outbox.state is not AgenticOutboxState.ACKNOWLEDGED
            or outbox.acknowledgement_id != receipt.receipt_id
            or outbox.acknowledgement_digest != receipt.receipt_digest
            or outbox.acknowledged_at is None
            or recorded_at < outbox.acknowledged_at
            or event.agent_id != outbox.command.target_agent_id
        ):
            raise AgenticCoordinationError(
                "durable Agent Event lacks exact acknowledged receiver admission"
            )
        result_digest = parsed[3]
        if result_digest in events_by_result:
            raise AgenticCoordinationError("durable Agent Event result repeats")
        events_by_result[result_digest] = parsed
    return events_by_result


def _validate_invocation_history(
    connection: sqlite3.Connection,
    *,
    binding: AgenticCoordinationBinding,
    snapshot: GraphSnapshot,
    store_id: str,
    chain: tuple[DynamicSupervisorCheckpoint, ...],
) -> None:
    checkpoints = {item.checkpoint_digest: item for item in chain}
    observed_slots: set[str] = set()
    for row in connection.execute("SELECT * FROM agentic_model_invocations ORDER BY rowid"):
        invocation = _invocation_from_row(row)
        intent = invocation.intent
        checkpoint = checkpoints.get(intent.source_checkpoint_digest)
        expected_stable_id = _stable_hypothesis_request_id(
            binding_digest=binding.binding_digest,
            source_checkpoint_digest=intent.source_checkpoint_digest,
        )
        try:
            expected_projection = build_hypothesis_model_projection(
                intent.context,
                source_snapshot=snapshot,
            )
        except (TypeError, ValidationError, ValueError) as exc:
            raise AgenticCoordinationError(
                "durable invocation Context is not bound to the current Graph"
            ) from exc
        if (
            checkpoint is None
            or intent.source_checkpoint_id != checkpoint.checkpoint_id
            or intent.stable_request_id != expected_stable_id
            or expected_stable_id in observed_slots
            or intent.store_id != store_id
            or intent.coordination_binding_id != binding.binding_id
            or intent.coordination_binding_digest != binding.binding_digest
            or intent.context.campaign_id != binding.campaign_id
            or intent.context.source_snapshot_id != snapshot.snapshot_id
            or intent.context.source_snapshot_digest != snapshot.snapshot_digest
            or expected_projection != intent.request_binding.projection
            or intent.context_id != intent.context.context_id
            or intent.context_digest != intent.context.context_digest
            or intent.projection_id != expected_projection.projection_id
            or intent.projection_digest != expected_projection.projection_digest
        ):
            raise AgenticCoordinationError(
                "durable invocation differs from its exact checkpoint and Graph slot"
            )
        observed_slots.add(expected_stable_id)
        if invocation.state in {
            AgenticModelInvocationState.TERMINAL_SUCCESS,
            AgenticModelInvocationState.TERMINAL_FAILURE,
        }:
            try:
                verify_agentic_hypothesis_receipt_publication(
                    _receipt_publication_from_entry(invocation),
                    expected_entry=invocation,
                )
            except (OSError, RuntimeError, TypeError, ValidationError, ValueError) as exc:
                raise AgenticCoordinationError(
                    "durable terminal invocation receipt failed strict reload"
                ) from exc


def _validate_transition_coverage(
    chain: tuple[DynamicSupervisorCheckpoint, ...],
    cycles_by_result: dict[str, DynamicSupervisorCycle],
    events_by_result: dict[str, tuple[AgentEvent, str, str, str]],
) -> None:
    for index, checkpoint in enumerate(chain[1:], start=1):
        cycle = cycles_by_result.get(checkpoint.checkpoint_digest)
        event = events_by_result.get(checkpoint.checkpoint_digest)
        if (cycle is None) == (event is None):
            raise AgenticCoordinationError(
                "checkpoint lacks exactly one typed cycle or Agent Event transition"
            )
        predecessor = chain[index - 1]
        if cycle is not None:
            if cycle.source_checkpoint != predecessor or cycle.resulting_checkpoint != checkpoint:
                raise AgenticCoordinationError("cycle checkpoint transition differs")
        else:
            assert event is not None
            if (
                event[2] != predecessor.checkpoint_digest
                or event[3] != checkpoint.checkpoint_digest
            ):
                raise AgenticCoordinationError("Agent Event checkpoint transition differs")
    if len(cycles_by_result) + len(events_by_result) != len(chain) - 1:
        raise AgenticCoordinationError("durable transition coverage contains extras")


def _validate_delivery_history(
    connection: sqlite3.Connection,
    *,
    store_id: str,
    binding_digest: str,
    covered_commands: set[str],
) -> None:
    stored_commands: set[str] = set()
    for row in connection.execute("SELECT * FROM agentic_command_outbox ORDER BY rowid"):
        entry = _outbox_from_row(
            row,
            store_id=store_id,
            binding_digest=binding_digest,
        )
        stored_commands.add(entry.command.command_id)
        inbox = connection.execute(
            "SELECT * FROM agentic_command_inbox WHERE command_id = ?",
            (entry.command.command_id,),
        ).fetchone()
        if inbox is not None:
            receipt = _admission_receipt_from_row(inbox)
            if (
                receipt.store_id != store_id
                or receipt.coordination_binding_digest != binding_digest
                or receipt.command_id != entry.command.command_id
                or receipt.command_digest != entry.command_digest
                or receipt.receiver_agent_id != entry.command.target_agent_id
                or entry.claimed_at is None
                or receipt.admitted_at < entry.claimed_at
                or entry.claim_id != receipt.claim_id
                or entry.claim_digest != receipt.claim_digest
            ):
                raise AgenticCoordinationError("receiver inbox differs from outbox claim")
        if entry.state is AgenticOutboxState.ACKNOWLEDGED:
            if inbox is None:
                raise AgenticCoordinationError(
                    "acknowledged outbox command lacks receiver admission"
                )
            receipt = _admission_receipt_from_row(inbox)
            if (
                entry.acknowledgement_id != receipt.receipt_id
                or entry.acknowledgement_digest != receipt.receipt_digest
                or entry.acknowledged_at is None
                or entry.acknowledged_at < receipt.admitted_at
            ):
                raise AgenticCoordinationError(
                    "outbox acknowledgement differs from receiver admission"
                )
    if stored_commands != covered_commands:
        raise AgenticCoordinationError("full command outbox coverage differs")
    inbox_commands = {
        _required_text(row, "command_id")
        for row in connection.execute("SELECT * FROM agentic_command_inbox")
    }
    if not inbox_commands <= stored_commands:
        raise AgenticCoordinationError("receiver inbox contains an unknown command")


def _validate_semantic_history(
    connection: sqlite3.Connection,
    *,
    binding: AgenticCoordinationBinding,
    snapshot: GraphSnapshot,
    chain: tuple[DynamicSupervisorCheckpoint, ...],
) -> None:
    supervisor = _restore_supervisor_instance(
        binding=binding,
        checkpoint=chain[0],
        snapshot=snapshot,
    )
    for checkpoint in chain[1:]:
        cycle_row = connection.execute(
            "SELECT * FROM agentic_cycles WHERE resulting_checkpoint_digest = ?",
            (checkpoint.checkpoint_digest,),
        ).fetchone()
        if cycle_row is not None:
            expected_cycle = _cycle_from_row(cycle_row)
            replayed_cycle = supervisor.plan_cycle(expected_cycle.candidates)
            if replayed_cycle != expected_cycle or supervisor.checkpoint() != checkpoint:
                raise AgenticCoordinationError("durable cycle semantic replay differs")
            continue
        event_row = connection.execute(
            "SELECT * FROM agentic_events WHERE resulting_checkpoint_digest = ?",
            (checkpoint.checkpoint_digest,),
        ).fetchone()
        if event_row is None:
            raise AgenticCoordinationError("durable semantic transition is missing")
        event, _digest, _source, _result = _event_from_row(event_row)
        replayed = supervisor.accept_event(event)
        if replayed != checkpoint:
            raise AgenticCoordinationError("durable Agent Event semantic replay differs")


def _restore_supervisor_instance(
    *,
    binding: AgenticCoordinationBinding,
    checkpoint: DynamicSupervisorCheckpoint,
    snapshot: GraphSnapshot,
) -> DynamicSupervisor:
    binding.require_checkpoint(checkpoint)
    if (
        snapshot.campaign_id != binding.campaign_id
        or snapshot.snapshot_id != binding.source_snapshot_id
        or snapshot.snapshot_digest != binding.source_snapshot_digest
    ):
        raise ValueError("current Graph Snapshot differs from durable binding")
    supervisor = DynamicSupervisor(
        campaign_id=binding.campaign_id,
        supervisor_agent_id=binding.supervisor_agent_id,
        source_snapshot=snapshot,
        allowed_target_ids=binding.allowed_target_ids,
        exploit_group=binding.exploit_group,
        policy=binding.supervisor_policy,
        scoring_policy=binding.scoring_policy,
    )
    supervisor._revision = checkpoint.revision
    supervisor._next_command_sequence = checkpoint.next_command_sequence
    supervisor._total_assignments = checkpoint.total_assignments
    supervisor._sessions = {
        item.session_id: AgentSessionSnapshot.model_validate(
            item.model_dump(mode="json", by_alias=True)
        )
        for item in checkpoint.sessions
    }
    supervisor._seen_candidate_ids = set(checkpoint.seen_candidate_ids)
    supervisor._seen_semantic_digests = set(checkpoint.seen_semantic_digests)
    supervisor._issued_commands = {
        item.command_id: IssuedCommandBinding.model_validate(
            item.model_dump(mode="json", by_alias=True)
        )
        for item in checkpoint.issued_commands
    }
    if supervisor.checkpoint() != checkpoint:
        raise ValueError("restored Dynamic Supervisor differs from durable checkpoint")
    return supervisor


def _receipt_publication_from_entry(
    entry: AgenticModelInvocationEntry,
) -> AgenticHypothesisReceiptPublication:
    if any(
        value is None
        for value in (
            entry.receipt_run_path,
            entry.receipt_run_id,
            entry.receipt_root_digest,
            entry.receipt_artifact_path,
            entry.receipt_artifact_sha256,
        )
    ):
        raise AgenticCoordinationError("terminal invocation receipt publication is incomplete")
    assert entry.receipt_run_path is not None
    assert entry.receipt_run_id is not None
    assert entry.receipt_root_digest is not None
    assert entry.receipt_artifact_path is not None
    assert entry.receipt_artifact_sha256 is not None
    loaded = load_verified_run_artifacts(
        Path(entry.receipt_run_path),
        requests={entry.receipt_artifact_path: _MAX_RECEIPT_BYTES},
        expected_run_id=entry.receipt_run_id,
    )
    receipt = AgenticHypothesisInvocationReceipt.model_validate_json(
        loaded.artifact_bytes(entry.receipt_artifact_path)
    )
    return AgenticHypothesisReceiptPublication(
        run_path=Path(entry.receipt_run_path),
        run_id=entry.receipt_run_id,
        root_digest=entry.receipt_root_digest,
        artifact_path=entry.receipt_artifact_path,
        artifact_sha256=entry.receipt_artifact_sha256,
        receipt=receipt,
    )


def _require_identifier(value: str, *, label: str) -> None:
    from re import fullmatch

    if (
        not isinstance(value, str)
        or fullmatch(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$", value) is None
    ):
        raise ValueError(f"{label} is invalid")


def _require_digest(value: str, *, label: str) -> None:
    from re import fullmatch

    if not isinstance(value, str) or fullmatch(r"^[a-f0-9]{64}$", value) is None:
        raise ValueError(f"{label} is invalid")


def _required_text(row: sqlite3.Row, key: str | int) -> str:
    value = row[key]
    if type(value) is not str:
        raise AgenticCoordinationError("durable text column is invalid")
    return value


def _optional_text(row: sqlite3.Row, key: str) -> str | None:
    value = row[key]
    if value is None:
        return None
    if type(value) is not str:
        raise AgenticCoordinationError("durable optional text column is invalid")
    return value


def _required_int(row: sqlite3.Row, key: str | int) -> int:
    value = row[key]
    if type(value) is not int:
        raise AgenticCoordinationError("durable integer column is invalid")
    return value


def _required_bytes(row: sqlite3.Row, key: str) -> bytes:
    value = row[key]
    if type(value) is not bytes:
        raise AgenticCoordinationError("durable blob column is invalid")
    return value


def _metadata(connection: sqlite3.Connection) -> dict[str, str]:
    rows = connection.execute(
        "SELECT key, value FROM agentic_coordination_metadata ORDER BY key"
    ).fetchall()
    result: dict[str, str] = {}
    for row in rows:
        key = _required_text(row, "key")
        value = _required_text(row, "value")
        if key in result:
            raise AgenticCoordinationError("coordination metadata repeats a key")
        result[key] = value
    return result


def _require_linux_descriptor_backend() -> None:
    if sys.platform != "linux" or os.name != "posix":
        raise AgenticCoordinationError(
            "durable agentic coordination requires the Linux descriptor SQLite backend"
        )
    proc = Path("/proc/self/fd")
    try:
        probe = os.open(
            "/",
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            opened = os.fstat(probe)
            resolved = os.stat(proc / str(probe))
        finally:
            os.close(probe)
    except OSError as exc:
        raise AgenticCoordinationError("Linux descriptor SQLite backend is unavailable") from exc
    if _stable_directory_identity(opened) != _stable_directory_identity(resolved):
        raise AgenticCoordinationError("Linux descriptor filesystem identity differs")


def _stable_file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        stat.S_IFMT(value.st_mode),
        value.st_nlink,
    )


def _stable_directory_identity(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_uid,
        value.st_mode,
    )


def _directory_fingerprint(
    value: os.stat_result,
) -> tuple[int, int, int, int, int, int, int]:
    stable = _stable_file_identity(value)
    return (*stable, value.st_mtime_ns, value.st_ctime_ns)


def _process_fd_snapshot() -> dict[int, tuple[tuple[int, int, int, int, int], str]]:
    observed: dict[int, tuple[tuple[int, int, int, int, int], str]] = {}
    try:
        names = os.listdir("/proc/self/fd")
    except OSError as exc:
        raise AgenticCoordinationError("process descriptor inventory is unavailable") from exc
    for name in names:
        try:
            descriptor = int(name)
            value = os.fstat(descriptor)
            link = os.readlink(f"/proc/self/fd/{descriptor}")
        except (OSError, ValueError):
            continue
        observed[descriptor] = (_stable_file_identity(value), link)
    return observed


class _LinuxPinnedCoordinationDatabase:
    """Store-lifetime Linux descriptors for one resumable SQLite authority."""

    def __init__(
        self,
        *,
        path: Path,
        parent_fd: int,
        database_fd: int,
        parent_identity: tuple[int, int, int, int],
        database_identity: tuple[int, int, int, int, int],
        existed: bool,
        initial_size: int,
    ) -> None:
        self.path = path
        self.parent_fd = parent_fd
        self.database_fd = database_fd
        self.parent_identity = parent_identity
        self.database_identity = database_identity
        self.existed = existed
        self.initial_size = initial_size
        self._allow_hot_journal_recovery = existed
        self._pid = os.getpid()
        self._operation_lock = threading.RLock()
        self._operation_active = False
        self._closed = False

    @classmethod
    def open(
        cls,
        path: Path,
        *,
        allow_create: bool,
    ) -> _LinuxPinnedCoordinationDatabase:
        _require_linux_descriptor_backend()
        if type(allow_create) is not bool:
            raise AgenticCoordinationError("coordination creation setting must be a boolean")
        path = Path(os.path.abspath(path))
        if path.name in {"", ".", ".."} or "/" in path.name or "\x00" in path.name:
            raise AgenticCoordinationError("coordination store leaf is invalid")
        if allow_create:
            _prepare_private_parent(path.parent)
        else:
            _require_plain_directory_components(path.parent)
        parent_fd = -1
        database_fd = -1
        try:
            parent_fd = os.open(
                path.parent,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            os.set_inheritable(parent_fd, False)
            parent_value = os.fstat(parent_fd)
            parent_identity = _stable_directory_identity(parent_value)
            if (
                not stat.S_ISDIR(parent_value.st_mode)
                or parent_value.st_uid != os.geteuid()
                or stat.S_IMODE(parent_value.st_mode) & 0o077
                or _stable_directory_identity(os.stat(path.parent, follow_symlinks=False))
                != parent_identity
                or _stable_directory_identity(os.stat(f"/proc/self/fd/{parent_fd}"))
                != parent_identity
            ):
                raise AgenticCoordinationError(
                    "coordination parent descriptor is not exact and owner-only"
                )
            hot_journal = _require_coordination_sidecars(
                parent_fd,
                path.name,
                allow_hot_journal=True,
            )
            existed = True
            try:
                database_fd = os.open(
                    path.name,
                    os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                if not allow_create:
                    raise AgenticCoordinationError("coordination store is missing") from None
                if hot_journal:
                    raise AgenticCoordinationError(
                        "missing coordination store has an unexpected journal"
                    ) from None
                existed = False
                database_fd = os.open(
                    path.name,
                    os.O_RDWR
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_NOFOLLOW", 0)
                    | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=parent_fd,
                )
            os.set_inheritable(database_fd, False)
            database_value = os.fstat(database_fd)
            database_identity = _stable_file_identity(database_value)
            entry_value = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _stable_file_identity(entry_value) != database_identity
                or not stat.S_ISREG(database_value.st_mode)
                or database_value.st_nlink != 1
                or database_value.st_uid != os.geteuid()
                or stat.S_IMODE(database_value.st_mode) & 0o077
            ):
                raise AgenticCoordinationError(
                    "coordination database descriptor is not exact and owner-only"
                )
            _require_coordination_sidecars(
                parent_fd,
                path.name,
                allow_hot_journal=existed,
            )
            return cls(
                path=path,
                parent_fd=parent_fd,
                database_fd=database_fd,
                parent_identity=parent_identity,
                database_identity=database_identity,
                existed=existed,
                initial_size=database_value.st_size,
            )
        except BaseException:
            if database_fd >= 0:
                os.close(database_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
            raise

    def require_open(self) -> None:
        if self._closed:
            raise AgenticCoordinationError("coordination descriptor authority is closed")
        if os.getpid() != self._pid:
            raise AgenticCoordinationError(
                "coordination descriptor authority cannot cross a process fork"
            )

    def start_operation(self) -> None:
        self.require_open()
        self._operation_lock.acquire()
        try:
            self.require_open()
            if self._operation_active:
                raise AgenticCoordinationError(
                    "coordination descriptor authority does not allow nested operations"
                )
            self._operation_active = True
        except BaseException:
            self._operation_lock.release()
            raise

    def finish_operation(self) -> None:
        if not self._operation_active:
            raise AgenticCoordinationError("coordination descriptor operation is not active")
        self._operation_active = False
        self._operation_lock.release()

    def require_idle_exact(
        self,
        *,
        allow_hot_journal: bool = False,
    ) -> tuple[tuple[int, int, int, int, int, int, int], bool]:
        self.require_open()
        try:
            parent_value = os.fstat(self.parent_fd)
            database_value = os.fstat(self.database_fd)
            parent_entry = os.stat(self.path.parent, follow_symlinks=False)
            database_entry = os.stat(
                self.path.name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
            proc_parent = os.stat(f"/proc/self/fd/{self.parent_fd}")
        except OSError as exc:
            raise AgenticCoordinationError(
                "coordination descriptor authority is unavailable"
            ) from exc
        if (
            _stable_directory_identity(parent_value) != self.parent_identity
            or _stable_directory_identity(parent_entry) != self.parent_identity
            or _stable_directory_identity(proc_parent) != self.parent_identity
            or not stat.S_ISDIR(parent_value.st_mode)
            or parent_value.st_uid != os.geteuid()
            or stat.S_IMODE(parent_value.st_mode) & 0o077
            or _stable_file_identity(database_value) != self.database_identity
            or _stable_file_identity(database_entry) != self.database_identity
            or database_value.st_nlink != 1
            or database_value.st_uid != os.geteuid()
            or stat.S_IMODE(database_value.st_mode) & 0o077
        ):
            raise AgenticCoordinationError(
                "coordination parent or database descriptor identity changed"
            )
        hot_journal = _require_coordination_sidecars(
            self.parent_fd,
            self.path.name,
            allow_hot_journal=allow_hot_journal,
        )
        return _directory_fingerprint(parent_value), hot_journal

    def open_connection(
        self,
        *,
        readonly: bool,
        allow_recovery: bool = False,
    ) -> tuple[
        sqlite3.Connection,
        tuple[int, ...],
        tuple[int, int, int, int, int, int, int],
    ]:
        may_recover = allow_recovery and self._allow_hot_journal_recovery
        before_parent, hot_journal = self.require_idle_exact(allow_hot_journal=may_recover)
        connection: sqlite3.Connection | None = None
        with _SQLITE_DESCRIPTOR_OPEN_LOCK:
            before = _process_fd_snapshot()
            uri = f"file:/proc/self/fd/{self.parent_fd}/{quote(self.path.name, safe='')}?mode=rw"
            try:
                connection = sqlite3.connect(
                    uri,
                    uri=True,
                    isolation_level=None,
                    timeout=_BUSY_TIMEOUT_MS / 1_000,
                )
                after_connect = _process_fd_snapshot()
                changed = {
                    descriptor: identity
                    for descriptor, identity in after_connect.items()
                    if before.get(descriptor) != identity
                }
                matches = tuple(
                    descriptor
                    for descriptor, (identity, _link) in changed.items()
                    if identity == self.database_identity
                )
                if len(changed) != 1 or len(matches) != 1:
                    raise AgenticCoordinationError(
                        "SQLite connection is not bound to the pinned database inode"
                    )
                self.require_connection_descriptors(matches)
                connection.execute("PRAGMA schema_version").fetchone()
                after_schema = _process_fd_snapshot()
                changed_after_schema = {
                    descriptor: identity
                    for descriptor, identity in after_schema.items()
                    if before.get(descriptor) != identity
                }
                schema_matches = tuple(
                    descriptor
                    for descriptor, (identity, _link) in changed_after_schema.items()
                    if identity == self.database_identity
                )
                if len(changed_after_schema) != 1 or len(schema_matches) != 1:
                    raise AgenticCoordinationError(
                        "SQLite connection descriptor set changed before attestation"
                    )
                matches = schema_matches
                self.require_connection_descriptors(matches)
                if hot_journal:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute("ROLLBACK")
                recovered_parent, remaining_hot_journal = self.require_idle_exact()
                if remaining_hot_journal:
                    raise AgenticCoordinationError("coordination hot journal was not recovered")
                if not hot_journal and recovered_parent != before_parent:
                    raise AgenticCoordinationError(
                        "coordination parent changed while SQLite opened"
                    )
                connection.row_factory = sqlite3.Row
                _configure_connection(connection, readonly=readonly)
                if allow_recovery:
                    self._allow_hot_journal_recovery = False
                return connection, matches, recovered_parent
            except BaseException:
                if connection is not None:
                    connection.close()
                raise

    def require_connection_descriptors(self, descriptors: tuple[int, ...]) -> None:
        if len(descriptors) != 1:
            raise AgenticCoordinationError("SQLite connection descriptor proof differs")
        try:
            value = os.fstat(descriptors[0])
        except OSError as exc:
            raise AgenticCoordinationError(
                "SQLite connection database descriptor was replaced"
            ) from exc
        if _stable_file_identity(value) != self.database_identity:
            raise AgenticCoordinationError(
                "SQLite connection database descriptor differs from pinned authority"
            )

    def finish_connection(
        self,
        *,
        write: bool,
        before_parent: tuple[int, int, int, int, int, int, int],
    ) -> None:
        after_parent, hot_journal = self.require_idle_exact()
        if hot_journal:
            raise AgenticCoordinationError("coordination journal remains after transaction closure")
        if not write and after_parent != before_parent:
            raise AgenticCoordinationError("coordination parent churned during a read transaction")

    def close(self) -> None:
        if os.getpid() != self._pid:
            if self._closed:
                return
            self._closed = True
            database_fd, self.database_fd = self.database_fd, -1
            parent_fd, self.parent_fd = self.parent_fd, -1
            os.close(database_fd)
            os.close(parent_fd)
            return
        with self._operation_lock:
            if self._closed:
                return
            if self._operation_active:
                raise AgenticCoordinationError(
                    "cannot close coordination descriptors during an active operation"
                )
            self._closed = True
            database_fd, self.database_fd = self.database_fd, -1
            parent_fd, self.parent_fd = self.parent_fd, -1
            os.close(database_fd)
            os.close(parent_fd)


_LINUX_PINNED_COORDINATION_DATABASE_CLOSE_IMPLEMENTATION = _LinuxPinnedCoordinationDatabase.close


def _require_coordination_sidecars(
    parent_fd: int,
    leaf: str,
    *,
    allow_hot_journal: bool,
) -> bool:
    hot_journal = False
    for suffix in ("-journal", "-wal", "-shm"):
        try:
            value = os.stat(leaf + suffix, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AgenticCoordinationError("coordination SQLite sidecar is unavailable") from exc
        if (
            suffix == "-journal"
            and allow_hot_journal
            and stat.S_ISREG(value.st_mode)
            and value.st_nlink == 1
            and value.st_uid == os.geteuid()
            and not stat.S_IMODE(value.st_mode) & 0o077
        ):
            hot_journal = True
            continue
        raise AgenticCoordinationError("coordination SQLite sidecar is unexpected")
    return hot_journal


def migrate_agentic_coordination_schema_v5_to_v6(
    path: Path,
    *,
    binding: AgenticCoordinationBinding,
    expected_store_id: str,
) -> None:
    """Explicitly migrate one exact offline v5 Store without inventing authority."""

    _require_linux_descriptor_backend()
    import re

    if (
        type(expected_store_id) is not str
        or re.fullmatch(_STORE_ID_PATTERN, expected_store_id) is None
    ):
        raise AgenticCoordinationError("expected coordination store ID is invalid")
    try:
        canonical_binding = AgenticCoordinationBinding.model_validate(
            binding.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise AgenticCoordinationError("coordination schema migration binding is invalid") from exc
    if canonical_binding != binding:
        raise AgenticCoordinationError(
            "coordination schema migration binding differs after strict reload"
        )

    database = _LinuxPinnedCoordinationDatabase.open(Path(path), allow_create=False)
    connection: sqlite3.Connection | None = None
    before_parent: tuple[int, int, int, int, int, int, int] | None = None
    database.start_operation()
    try:
        connection, descriptors, before_parent = database.open_connection(
            readonly=False,
            allow_recovery=True,
        )
        connection.execute("BEGIN EXCLUSIVE")
        database.require_connection_descriptors(descriptors)
        version = connection.execute("PRAGMA user_version").fetchone()
        if (
            version is not None
            and len(version) == 1
            and type(version[0]) is int
            and version[0] == _SCHEMA_VERSION
        ):
            _validate_schema(
                connection,
                binding=canonical_binding,
                expected_specialist_runtime_generation=(
                    AgenticSpecialistRuntimeGeneration.LEGACY_V1
                ),
                expected_store_id=expected_store_id,
            )
        else:
            _validate_schema_v5(
                connection,
                binding=canonical_binding,
                expected_store_id=expected_store_id,
            )
            connection.execute("DROP TRIGGER agentic_coordination_metadata_immutable")
            for key in _SCHEMA_V6_ADDITION_KEYS:
                connection.execute(_SCHEMA_OBJECTS[key])
            connection.execute(
                "UPDATE agentic_coordination_metadata SET value = ? WHERE key = ?",
                (str(_SCHEMA_VERSION), "schema_version"),
            )
            connection.execute(
                "UPDATE agentic_coordination_metadata SET value = ? WHERE key = ?",
                (_SCHEMA_DIGEST, "schema_digest"),
            )
            connection.execute(
                "INSERT INTO agentic_coordination_metadata(key, value) VALUES (?, ?)",
                (
                    "specialist_runtime_generation",
                    AgenticSpecialistRuntimeGeneration.LEGACY_V1.value,
                ),
            )
            connection.execute(_METADATA_IMMUTABLE_SQL)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            if any(
                connection.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone() is not None
                for table in (
                    "agentic_specialist_job_attempts",
                    "agentic_specialist_terminal_receipts",
                )
            ):
                raise AgenticCoordinationError(
                    "coordination schema migration invented specialist authority"
                )
            _validate_schema(
                connection,
                binding=canonical_binding,
                expected_specialist_runtime_generation=(
                    AgenticSpecialistRuntimeGeneration.LEGACY_V1
                ),
                expected_store_id=expected_store_id,
            )
        database.require_connection_descriptors(descriptors)
        connection.execute("COMMIT")
    except AgenticCoordinationError:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    except (OSError, sqlite3.Error, TypeError, ValidationError, ValueError) as exc:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise AgenticCoordinationError(
            "coordination schema v5 to v6 migration failed closed"
        ) from exc
    finally:
        try:
            if connection is not None:
                connection.close()
            if before_parent is not None:
                database.finish_connection(write=True, before_parent=before_parent)
        finally:
            database.finish_operation()
            _LINUX_PINNED_COORDINATION_DATABASE_CLOSE_IMPLEMENTATION(database)


def _initialize(
    database: _LinuxPinnedCoordinationDatabase,
    *,
    binding: AgenticCoordinationBinding,
    specialist_runtime_generation: AgenticSpecialistRuntimeGeneration,
    store_id_factory: Callable[[], str],
    allow_create: bool,
    expected_store_id: str | None,
) -> None:
    if type(allow_create) is not bool:
        raise AgenticCoordinationError("coordination creation setting must be a boolean")
    if type(specialist_runtime_generation) is not AgenticSpecialistRuntimeGeneration:
        raise AgenticCoordinationError("coordination specialist runtime generation is invalid")
    connection: sqlite3.Connection | None = None
    descriptors: tuple[int, ...] = ()
    before_parent: tuple[int, int, int, int, int, int, int] | None = None
    database.start_operation()
    try:
        connection, descriptors, before_parent = database.open_connection(
            readonly=not allow_create,
            allow_recovery=True,
        )
        connection.execute("BEGIN IMMEDIATE" if allow_create else "BEGIN")
        database.require_connection_descriptors(descriptors)
        tables = _application_tables(connection)
        if not tables:
            if not allow_create:
                raise AgenticCoordinationError("existing coordination store has no trusted schema")
            if database.existed:
                raise AgenticCoordinationError("existing coordination store has no trusted schema")
            mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
            if mode is None or str(mode[0]).lower() != "delete":
                raise AgenticCoordinationError("coordination store requires DELETE journal mode")
            store_id = store_id_factory()
            if not isinstance(store_id, str):
                raise AgenticCoordinationError("coordination store ID factory is invalid")
            import re

            if re.fullmatch(_STORE_ID_PATTERN, store_id) is None:
                raise AgenticCoordinationError("coordination store ID is invalid")
            for statement in _SCHEMA_OBJECTS.values():
                connection.execute(statement)
            binding_wire = canonical_json_bytes(
                binding.model_dump(mode="json", by_alias=True),
                label="Agentic coordination binding",
                max_bytes=_MAX_BINDING_BYTES,
            ).decode("utf-8")
            connection.executemany(
                "INSERT INTO agentic_coordination_metadata(key, value) VALUES (?, ?)",
                (
                    ("schema_version", str(_SCHEMA_VERSION)),
                    ("schema_digest", _SCHEMA_DIGEST),
                    ("store_id", store_id),
                    ("binding", binding_wire),
                    ("binding_digest", binding.binding_digest),
                    (
                        "specialist_runtime_generation",
                        specialist_runtime_generation.value,
                    ),
                ),
            )
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.execute(f"PRAGMA application_id = {_APPLICATION_ID}")
        _validate_schema(
            connection,
            binding=binding,
            expected_specialist_runtime_generation=specialist_runtime_generation,
            expected_store_id=expected_store_id,
        )
        database.require_connection_descriptors(descriptors)
        connection.execute("COMMIT")
    except BaseException:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        try:
            if connection is not None:
                connection.close()
            if before_parent is not None:
                database.finish_connection(write=allow_create, before_parent=before_parent)
        finally:
            database.finish_operation()


def _configure_connection(connection: sqlite3.Connection, *, readonly: bool) -> None:
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA foreign_keys = ON")
    foreign_keys = connection.execute("PRAGMA foreign_keys").fetchone()
    if (
        foreign_keys is None
        or len(foreign_keys) != 1
        or type(foreign_keys[0]) is not int
        or foreign_keys[0] != 1
    ):
        raise AgenticCoordinationError("coordination connection requires foreign keys")
    connection.execute("PRAGMA recursive_triggers = ON")
    recursive_triggers = connection.execute("PRAGMA recursive_triggers").fetchone()
    if (
        recursive_triggers is None
        or len(recursive_triggers) != 1
        or type(recursive_triggers[0]) is not int
        or recursive_triggers[0] != 1
    ):
        raise AgenticCoordinationError("coordination connection requires recursive triggers")
    connection.execute("PRAGMA trusted_schema = OFF")
    if readonly:
        connection.execute("PRAGMA query_only = ON")
    else:
        connection.execute("PRAGMA synchronous = FULL")


def _application_tables(connection: sqlite3.Connection) -> frozenset[str]:
    return frozenset(
        str(row[0])
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
        )
    )


def _observed_schema_objects(
    connection: sqlite3.Connection,
) -> dict[tuple[str, str], str]:
    rows = connection.execute(
        """
        SELECT type, name, sql FROM sqlite_master
        WHERE name NOT LIKE 'sqlite_%' AND type IN ('table', 'trigger')
        ORDER BY type, name
        """
    ).fetchall()
    observed: dict[tuple[str, str], str] = {}
    for row in rows:
        kind = _required_text(row, "type")
        name = _required_text(row, "name")
        sql = _required_text(row, "sql")
        observed[(kind, name)] = _normalize_sql(sql)
    return observed


def _validate_schema_v5(
    connection: sqlite3.Connection,
    *,
    binding: AgenticCoordinationBinding,
    expected_store_id: str,
) -> None:
    if _application_tables(connection) != _SCHEMA_V5_TABLES:
        raise AgenticCoordinationError("coordination schema v5 table set differs")
    expected = {key: _normalize_sql(value) for key, value in _SCHEMA_V5_OBJECTS.items()}
    if _observed_schema_objects(connection) != expected:
        raise AgenticCoordinationError("coordination schema v5 objects differ")
    application_id = connection.execute("PRAGMA application_id").fetchone()
    user_version = connection.execute("PRAGMA user_version").fetchone()
    if (
        application_id is None
        or type(application_id[0]) is not int
        or application_id[0] != _APPLICATION_ID
        or user_version is None
        or type(user_version[0]) is not int
        or user_version[0] != 5
    ):
        raise AgenticCoordinationError("coordination schema v5 SQLite identity differs")
    metadata = _metadata(connection)
    if set(metadata) != {
        "schema_version",
        "schema_digest",
        "store_id",
        "binding",
        "binding_digest",
    }:
        raise AgenticCoordinationError("coordination schema v5 metadata set differs")
    if (
        metadata["schema_version"] != "5"
        or metadata["schema_digest"] != AGENTIC_COORDINATION_SCHEMA_V5_DIGEST
        or metadata["binding_digest"] != binding.binding_digest
        or metadata["store_id"] != expected_store_id
    ):
        raise AgenticCoordinationError("coordination schema v5 metadata differs")
    try:
        stored_binding = AgenticCoordinationBinding.model_validate_json(
            metadata["binding"].encode("utf-8")
        )
    except ValidationError as exc:
        raise AgenticCoordinationError("coordination schema v5 binding is invalid") from exc
    expected_binding_bytes = canonical_json_bytes(
        binding.model_dump(mode="json", by_alias=True),
        label="Agentic coordination binding",
        max_bytes=_MAX_BINDING_BYTES,
    )
    if stored_binding != binding or metadata["binding"].encode("utf-8") != expected_binding_bytes:
        raise AgenticCoordinationError("coordination schema v5 deployment binding differs")
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    if journal_mode is None or len(journal_mode) != 1 or str(journal_mode[0]).lower() != "delete":
        raise AgenticCoordinationError("coordination schema v5 requires DELETE journal mode")
    check = connection.execute("PRAGMA quick_check").fetchall()
    if check != [sqlite3.Row] and not (
        len(check) == 1 and len(check[0]) == 1 and check[0][0] == "ok"
    ):
        raise AgenticCoordinationError("coordination schema v5 integrity check failed")


def _validate_schema(
    connection: sqlite3.Connection,
    *,
    binding: AgenticCoordinationBinding,
    expected_specialist_runtime_generation: AgenticSpecialistRuntimeGeneration,
    expected_store_id: str | None = None,
) -> None:
    if type(expected_specialist_runtime_generation) is not AgenticSpecialistRuntimeGeneration:
        raise AgenticCoordinationError("expected specialist runtime generation is invalid")
    observed_user_version = connection.execute("PRAGMA user_version").fetchone()
    if (
        observed_user_version is not None
        and len(observed_user_version) == 1
        and type(observed_user_version[0]) is int
        and observed_user_version[0] == 5
    ):
        raise AgenticCoordinationError(
            "coordination schema v5 requires an explicit offline migration; "
            "automatic migration is forbidden"
        )
    if _application_tables(connection) != _TABLES:
        raise AgenticCoordinationError("coordination store table set differs")
    expected = {key: _normalize_sql(value) for key, value in _SCHEMA_OBJECTS.items()}
    if _observed_schema_objects(connection) != expected:
        raise AgenticCoordinationError("coordination store schema objects differ")
    application_id = connection.execute("PRAGMA application_id").fetchone()
    user_version = observed_user_version
    if (
        application_id is None
        or type(application_id[0]) is not int
        or application_id[0] != _APPLICATION_ID
        or user_version is None
        or type(user_version[0]) is not int
        or user_version[0] != _SCHEMA_VERSION
    ):
        raise AgenticCoordinationError("coordination store SQLite identity differs")
    metadata = _metadata(connection)
    if set(metadata) != {
        "schema_version",
        "schema_digest",
        "store_id",
        "binding",
        "binding_digest",
        "specialist_runtime_generation",
    }:
        raise AgenticCoordinationError("coordination store metadata set differs")
    if (
        metadata["schema_version"] != str(_SCHEMA_VERSION)
        or metadata["schema_digest"] != _SCHEMA_DIGEST
        or metadata["binding_digest"] != binding.binding_digest
        or metadata["specialist_runtime_generation"] != expected_specialist_runtime_generation.value
    ):
        raise AgenticCoordinationError("coordination store binding metadata differs")
    try:
        stored_binding = AgenticCoordinationBinding.model_validate_json(
            metadata["binding"].encode("utf-8")
        )
    except ValidationError as exc:
        raise AgenticCoordinationError("coordination store binding is invalid") from exc
    expected_binding_bytes = canonical_json_bytes(
        binding.model_dump(mode="json", by_alias=True),
        label="Agentic coordination binding",
        max_bytes=_MAX_BINDING_BYTES,
    )
    if stored_binding != binding or metadata["binding"].encode("utf-8") != expected_binding_bytes:
        raise AgenticCoordinationError("coordination store deployment binding differs")
    import re

    if re.fullmatch(_STORE_ID_PATTERN, metadata["store_id"]) is None:
        raise AgenticCoordinationError("coordination store ID is invalid")
    if expected_store_id is not None and metadata["store_id"] != expected_store_id:
        raise AgenticCoordinationError("coordination store ID differs from pinned authority")
    journal_mode = connection.execute("PRAGMA journal_mode").fetchone()
    if journal_mode is None or len(journal_mode) != 1 or str(journal_mode[0]).lower() != "delete":
        raise AgenticCoordinationError("coordination store requires DELETE journal mode")
    check = connection.execute("PRAGMA quick_check").fetchall()
    if check != [sqlite3.Row] and not (
        len(check) == 1 and len(check[0]) == 1 and check[0][0] == "ok"
    ):
        raise AgenticCoordinationError("coordination store integrity check failed")


@contextmanager
def _write_transaction(
    database: _LinuxPinnedCoordinationDatabase,
) -> Iterator[sqlite3.Connection]:
    database.start_operation()
    connection: sqlite3.Connection | None = None
    before_parent: tuple[int, int, int, int, int, int, int] | None = None
    try:
        connection, descriptors, before_parent = database.open_connection(readonly=False)
        connection.execute("BEGIN IMMEDIATE")
        database.require_connection_descriptors(descriptors)
        yield connection
        database.require_connection_descriptors(descriptors)
        connection.execute("COMMIT")
    except BaseException:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        try:
            if connection is not None:
                connection.close()
            if before_parent is not None:
                database.finish_connection(write=True, before_parent=before_parent)
        finally:
            database.finish_operation()


@contextmanager
def _read_transaction(
    database: _LinuxPinnedCoordinationDatabase,
) -> Iterator[sqlite3.Connection]:
    database.start_operation()
    connection: sqlite3.Connection | None = None
    before_parent: tuple[int, int, int, int, int, int, int] | None = None
    try:
        connection, descriptors, before_parent = database.open_connection(readonly=True)
        connection.execute("BEGIN")
        database.require_connection_descriptors(descriptors)
        yield connection
        database.require_connection_descriptors(descriptors)
        connection.execute("COMMIT")
    except BaseException:
        if connection is not None and connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    finally:
        try:
            if connection is not None:
                connection.close()
            if before_parent is not None:
                database.finish_connection(write=False, before_parent=before_parent)
        finally:
            database.finish_operation()


def _require_plain_directory_components(directory: Path) -> None:
    current = Path(directory.anchor)
    components = directory.parts[1:] if directory.is_absolute() else directory.parts
    for component in components:
        current /= component
        try:
            value = current.lstat()
        except OSError as exc:
            raise AgenticCoordinationError(
                "coordination directory component is unavailable"
            ) from exc
        is_junction = getattr(current, "is_junction", lambda: False)()
        if current.is_symlink() or is_junction or not stat.S_ISDIR(value.st_mode):
            raise AgenticCoordinationError(
                "coordination path contains a symbolic-link or non-directory component"
            )


def _prepare_private_parent(directory: Path) -> None:
    missing: list[Path] = []
    cursor = directory
    while not cursor.exists():
        missing.append(cursor)
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    _require_plain_directory_components(cursor)
    for component in reversed(missing):
        component.mkdir(mode=0o700)
        if os.name == "posix":
            component.chmod(0o700)
    _require_plain_directory_components(directory)
