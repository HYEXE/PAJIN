"""Typed contracts for the PAJIN durable Control Plane."""

from __future__ import annotations

import json
import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from enum import Enum, StrEnum
from hashlib import sha256
from typing import Annotated, Any, Literal

from pydantic import BeforeValidator, ConfigDict, Field, field_validator, model_validator

from pajin.control_plane.artifact_transfer import (
    PortableArtifactBundle,
    PortableArtifactTransportReceipt,
)
from pajin.control_plane.execution_attestation import ExecutorExecutionAttestation
from pajin.domain.models import CampaignManifest, CampaignMode, StrictModel, ToolRiskTier
from pajin.domain.replay import ReplayClaimBinding, ReplayCompilation, ReplayPurpose
from pajin.domain.validation import AtomicClaimType, ValidationDecision
from pajin.modes.ai_redteam.models import KISAScenarioDefinition
from pajin.replay.target_attestation import (
    TargetExecutionChallenge,
    TargetExecutionVerificationSummary,
    derive_target_execution_challenge,
)
from pajin.replay.tickets import canonical_replay_compilation_bytes, replay_context_digest
from pajin.tools.base import ToolSpec

KISA_EXACT_REPLAY_EXECUTOR_PROFILE: Literal["kisa-exact-v1"] = "kisa-exact-v1"


@dataclass(frozen=True, slots=True)
class JsonResourcePolicy:
    """One explicit resource budget for an untrusted Control Plane JSON object."""

    max_bytes: int
    max_depth: int
    max_nodes: int
    max_keys: int
    max_string_bytes: int
    max_key_bytes: int = 1_024

    def __post_init__(self) -> None:
        values = (
            self.max_bytes,
            self.max_depth,
            self.max_nodes,
            self.max_keys,
            self.max_string_bytes,
            self.max_key_bytes,
        )
        if any(type(value) is not int or value < 1 for value in values):
            raise ValueError("Control Plane JSON policy limits must be positive integers")
        if self.max_string_bytes > self.max_bytes or self.max_key_bytes > self.max_bytes:
            raise ValueError("Control Plane JSON text limits cannot exceed the byte limit")


SUBMIT_RUN_INPUT_JSON_POLICY = JsonResourcePolicy(
    max_bytes=1_000_000,
    max_depth=24,
    max_nodes=20_000,
    max_keys=10_000,
    max_string_bytes=1_000_000,
)
COMPLETE_JOB_RESULT_JSON_POLICY = JsonResourcePolicy(
    max_bytes=1_000_000,
    max_depth=32,
    max_nodes=50_000,
    max_keys=25_000,
    max_string_bytes=1_000_000,
)
CHECKPOINT_STATE_JSON_POLICY = JsonResourcePolicy(
    max_bytes=1_000_000,
    max_depth=32,
    max_nodes=50_000,
    max_keys=25_000,
    max_string_bytes=1_000_000,
)
CONTROL_PLANE_STORED_JSON_POLICY = JsonResourcePolicy(
    max_bytes=2 * 1_024 * 1_024,
    max_depth=40,
    max_nodes=100_000,
    max_keys=50_000,
    max_string_bytes=2 * 1_024 * 1_024,
)


def _json_utf8_length(value: str, *, key: bool = False) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        label = "an invalid UTF-8 key" if key else "invalid UTF-8 text"
        raise ValueError(f"Control Plane JSON contains {label}") from exc


@dataclass(slots=True)
class _BoundedJSONWalker:
    policy: JsonResourcePolicy
    active_containers: set[int] = field(default_factory=set)
    node_count: int = 0
    key_count: int = 0

    def visit(self, item: object, *, depth: int) -> None:
        self._count_node(depth=depth)
        if item is None or isinstance(item, bool):
            return
        if isinstance(item, str):
            if _json_utf8_length(item) > self.policy.max_string_bytes:
                raise ValueError("Control Plane JSON exceeds the string byte limit")
            return
        if isinstance(item, int):
            self._require_bounded_integer(item)
            return
        if isinstance(item, float):
            self._require_finite_number(item)
            return
        if not isinstance(item, (dict, list)):
            raise ValueError("Control Plane JSON contains a non-JSON value")
        self._visit_container(item, depth=depth)

    def _count_node(self, *, depth: int) -> None:
        self.node_count += 1
        if self.node_count > self.policy.max_nodes:
            raise ValueError("Control Plane JSON exceeds the node-count limit")
        if depth > self.policy.max_depth:
            raise ValueError("Control Plane JSON exceeds the nesting-depth limit")

    @staticmethod
    def _require_bounded_integer(value: int) -> None:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValueError("Control Plane JSON integer is outside the signed 64-bit range")

    @staticmethod
    def _require_finite_number(value: float) -> None:
        if not math.isfinite(value):
            raise ValueError("Control Plane JSON numbers must be finite")

    def _visit_container(self, item: dict[Any, Any] | list[Any], *, depth: int) -> None:
        identity = id(item)
        if identity in self.active_containers:
            raise ValueError("Control Plane JSON cannot contain cycles")
        self.active_containers.add(identity)
        try:
            if isinstance(item, dict):
                self._visit_object(item, depth=depth)
            else:
                for nested in item:
                    self.visit(nested, depth=depth + 1)
        finally:
            self.active_containers.remove(identity)

    def _visit_object(self, item: dict[Any, Any], *, depth: int) -> None:
        for key, nested in item.items():
            self._count_key()
            if not isinstance(key, str):
                raise ValueError("Control Plane JSON object keys must be strings")
            if _json_utf8_length(key, key=True) > self.policy.max_key_bytes:
                raise ValueError("Control Plane JSON exceeds the key byte limit")
            self.visit(nested, depth=depth + 1)

    def _count_key(self) -> None:
        self.key_count += 1
        if self.key_count > self.policy.max_keys:
            raise ValueError("Control Plane JSON exceeds the key-count limit")


def canonical_control_plane_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError("Control Plane JSON is not canonical UTF-8 JSON") from exc


def validate_bounded_json_object(
    value: object,
    *,
    policy: JsonResourcePolicy = CONTROL_PLANE_STORED_JSON_POLICY,
) -> dict[str, Any]:
    """Reject non-JSON, non-finite, cyclic, or resource-unbounded object graphs."""

    if not isinstance(value, dict):
        raise ValueError("Control Plane JSON value must be an object")
    _BoundedJSONWalker(policy=policy).visit(value, depth=0)
    canonical = canonical_control_plane_json(value)
    if len(canonical) > policy.max_bytes:
        raise ValueError("Control Plane JSON exceeds the canonical byte limit")
    return value


def owned_bounded_json_object(
    value: object,
    *,
    policy: JsonResourcePolicy = CONTROL_PLANE_STORED_JSON_POLICY,
) -> dict[str, Any]:
    """Return a strict decoded snapshot with no aliases to the caller's graph."""

    validated = validate_bounded_json_object(value, policy=policy)
    decoded = json.loads(canonical_control_plane_json(validated))
    if not isinstance(decoded, dict):  # pragma: no cover - canonical object invariant
        raise ValueError("Control Plane JSON snapshot is not an object")
    return decoded


def _validate_stored_json_object(value: object) -> dict[str, Any]:
    return validate_bounded_json_object(value, policy=CONTROL_PLANE_STORED_JSON_POLICY)


def _validate_submit_run_input(value: object) -> dict[str, Any]:
    return validate_bounded_json_object(value, policy=SUBMIT_RUN_INPUT_JSON_POLICY)


def _validate_complete_job_result(value: object) -> dict[str, Any]:
    return validate_bounded_json_object(value, policy=COMPLETE_JOB_RESULT_JSON_POLICY)


def _validate_checkpoint_state(value: object) -> dict[str, Any]:
    return validate_bounded_json_object(value, policy=CHECKPOINT_STATE_JSON_POLICY)


BoundedJsonObject = Annotated[dict[str, Any], BeforeValidator(_validate_stored_json_object)]
SubmitRunInputJsonObject = Annotated[dict[str, Any], BeforeValidator(_validate_submit_run_input)]
CompleteJobResultJsonObject = Annotated[
    dict[str, Any], BeforeValidator(_validate_complete_job_result)
]
CheckpointStateJsonObject = Annotated[dict[str, Any], BeforeValidator(_validate_checkpoint_state)]


def submission_authority_digest(
    *,
    actor: str,
    campaign_name: str,
    input_value: object,
    idempotency_key: str,
    job_kind: str,
    max_attempts: int,
) -> str:
    """Bind one idempotency key's non-secret submission authority inputs."""

    input_object = validate_bounded_json_object(
        input_value,
        policy=SUBMIT_RUN_INPUT_JSON_POLICY,
    )
    if not all(
        isinstance(value, str) and value
        for value in (actor, campaign_name, idempotency_key, job_kind)
    ):
        raise ValueError("submission authority string fields must not be empty")
    if type(max_attempts) is not int or not 1 <= max_attempts <= 20:
        raise ValueError("submission authority retry limit is invalid")
    material = canonical_control_plane_json(
        {
            "actor": actor,
            "campaignName": campaign_name,
            "idempotencyKey": idempotency_key,
            "input": input_object,
            "jobKind": job_kind,
            "maxAttempts": max_attempts,
        }
    )
    return sha256(b"pajin.control-plane.submission-authority/v1\0" + material).hexdigest()


def non_replayable_submission_authority_digest(*, run_id: str, authority_kind: str) -> str:
    """Fence a non-public or incompletely proven Run from public idempotent replay."""

    if not run_id or not authority_kind:
        raise ValueError("non-replayable Run authority identity must not be empty")
    material = canonical_control_plane_json({"authorityKind": authority_kind, "runId": run_id})
    return sha256(
        b"pajin.control-plane.non-replayable-submission-authority/v1\0" + material
    ).hexdigest()


def job_submission_authority_digest(
    *,
    job_id: str,
    run_id: str,
    job_kind: str,
    payload: object,
    max_attempts: int,
    idempotency_key: str,
) -> str:
    """Bind every immutable field that determines one dispatchable Job."""

    payload_object = validate_bounded_json_object(
        payload,
        policy=CONTROL_PLANE_STORED_JSON_POLICY,
    )
    if not all(
        isinstance(value, str) and value for value in (job_id, run_id, job_kind, idempotency_key)
    ):
        raise ValueError("Job submission authority string fields must not be empty")
    if job_kind not in {"campaign", "tool-loop", "internal-replay"}:
        raise ValueError("Job submission authority kind is invalid")
    if type(max_attempts) is not int or not 1 <= max_attempts <= 20:
        raise ValueError("Job submission authority retry limit is invalid")
    material = canonical_control_plane_json(
        {
            "idempotencyKey": idempotency_key,
            "jobId": job_id,
            "jobKind": job_kind,
            "maxAttempts": max_attempts,
            "payload": payload_object,
            "runId": run_id,
        }
    )
    return sha256(b"pajin.control-plane.job-submission-authority/v1\0" + material).hexdigest()


class RunState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_APPROVAL = "awaiting-approval"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobState(StrEnum):
    QUEUED = "queued"
    LEASED = "leased"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DEAD_LETTER = "dead-letter"
    CANCELLED = "cancelled"


class JobKind(StrEnum):
    CAMPAIGN = "campaign"
    TOOL_LOOP = "tool-loop"


class InternalJobKind(StrEnum):
    """Job kinds that may only be created and claimed through trusted services."""

    REPLAY = "internal-replay"


class ReplayBatchState(StrEnum):
    PLANNED = "planned"
    RUNNING = "running"
    GATING = "gating"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReplayItemState(StrEnum):
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    VERIFIED = "verified"
    GATED = "gated"
    RETRY_PENDING = "retry-pending"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ReplayTicketState(StrEnum):
    ISSUED = "issued"
    CLAIMED = "claimed"
    FINALIZED = "finalized"
    ABANDONED = "abandoned"


class ApprovalState(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"
    EXPIRED = "expired"
    REVOKED = "revoked"


class PrincipalRole(StrEnum):
    OPERATOR = "operator"
    APPROVER = "approver"
    WORKER = "worker"
    AUDITOR = "auditor"


class ControlPlaneConflictCode(StrEnum):
    """Stable machine-readable causes for Control Plane HTTP 409 responses."""

    RUN_CANCELLED = "run_cancelled"
    LEASE_LOST = "lease_lost"


class ControlPlaneConflictResponse(StrictModel):
    """Shared JSON body for typed and legacy-compatible conflict responses."""

    detail: str = Field(min_length=1, max_length=500)
    code: ControlPlaneConflictCode | None = None


class Principal(StrictModel):
    subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    roles: frozenset[PrincipalRole] = Field(min_length=1)


class ApprovalIntent(StrictModel):
    call_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    tool_id: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=2_000)
    risk_tier: ToolRiskTier
    expires_at: datetime

    @model_validator(mode="after")
    def require_high_risk(self) -> ApprovalIntent:
        if self.risk_tier < ToolRiskTier.T3:
            raise ValueError("Control Plane approvals are reserved for T3/T4 intents")
        if self.expires_at.tzinfo is None:
            raise ValueError("approval expiry must be timezone-aware")
        return self


class SubmitRunRequest(StrictModel):
    campaign_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    input: SubmitRunInputJsonObject = Field(default_factory=dict)
    idempotency_key: str = Field(min_length=8, max_length=200)
    max_attempts: int = Field(default=3, ge=1, le=20)
    job_kind: JobKind = JobKind.CAMPAIGN


class ClaimJobRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    kinds: list[JobKind] = Field(
        default_factory=lambda: [JobKind.CAMPAIGN], min_length=1, max_length=20
    )
    lease_seconds: int = Field(default=30, ge=5, le=300)
    wait_seconds: int = Field(default=0, ge=0, le=20)


class ArtifactLocator(StrictModel):
    """Opaque exact-version lookup key for one managed source artifact."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    artifact_id: str = Field(pattern=r"^artifact_[0-9a-f]{32}$")
    repository_version: int = Field(strict=True, ge=1, le=2_147_483_647)


class ArtifactRef(StrictModel):
    """Immutable repository identity for a sealed Run artifact."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    artifact_id: str = Field(pattern=r"^artifact_[0-9a-f]{32}$")
    repository_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    media_type: str = Field(
        min_length=3,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9.+-]*/[A-Za-z0-9][A-Za-z0-9.+-]*$",
    )
    schema_kind: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    byte_length: int = Field(strict=True, ge=1, le=2_147_483_647)
    content_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    producer_run_id: str = Field(pattern=r"^run_[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    integrity_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    created_by: str = Field(min_length=1, max_length=200)


class ReplayExecutionContext(StrictModel):
    """Exact, server-owned inputs released to the dedicated KISA replay executor."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    context_id: str = Field(pattern=r"^replay-context_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    compilation_id: str = Field(pattern=r"^replay-compilation_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    source: ArtifactRef
    source_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    campaign: CampaignManifest
    campaign_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    scenario: KISAScenarioDefinition
    scenario_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool_spec: ToolSpec
    tool_spec_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    policy_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
    required_executor_profile: Literal["kisa-exact-v1"] = KISA_EXACT_REPLAY_EXECUTOR_PROFILE
    secret_policy: Literal["forbidden"] = "forbidden"
    secret_lease_ids: tuple[str, ...] = Field(default=(), max_length=0)
    output_staging_id: str = Field(pattern=r"^stage_[0-9a-f]{32}$")
    created_at: datetime

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Replay execution context created_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_exact_trusted_inputs(self) -> ReplayExecutionContext:
        campaign_digest = replay_execution_component_digest(self.campaign)
        scenario_digest = replay_execution_component_digest(self.scenario)
        tool_spec_digest = replay_execution_component_digest(self.tool_spec)
        if self.source_root_digest != self.source.integrity_root_digest:
            raise ValueError("Replay execution source digest must match its ArtifactRef")
        if campaign_digest != self.campaign_digest:
            raise ValueError("Replay execution Campaign digest does not match the Campaign")
        if scenario_digest != self.scenario_digest:
            raise ValueError("Replay execution Scenario digest does not match the Scenario")
        if tool_spec_digest != self.tool_spec_digest:
            raise ValueError("Replay execution ToolSpec digest does not match the ToolSpec")
        if self.campaign.spec.mode is not CampaignMode.AI_REDTEAM:
            raise ValueError("KISA replay execution requires an AI Red Team Campaign")
        if self.scenario.tool_id != self.tool_spec.tool_id:
            raise ValueError("Replay execution Scenario and ToolSpec IDs must match")
        if self.tool_spec.risk_tier > ToolRiskTier.T2:
            raise ValueError("KISA replay execution is restricted to T0-T2 ToolSpecs")
        if self.tool_spec.risk_tier > self.campaign.spec.rules_of_engagement.max_tool_risk_tier:
            raise ValueError("Replay execution ToolSpec exceeds the Campaign risk ceiling")
        allowed_methods = self.campaign.spec.rules_of_engagement.allowed_methods
        if self.scenario.method.upper() not in allowed_methods:
            raise ValueError("Replay execution Scenario method is not allowed by the Campaign")
        return self


def canonical_replay_execution_context_bytes(context: ReplayExecutionContext) -> bytes:
    """Serialize one typed execution context with deterministic set ordering."""

    trusted = ReplayExecutionContext.model_validate(
        context.model_dump(mode="python", by_alias=True)
    )
    payload = _canonical_replay_execution_context_value(trusted)
    if not isinstance(payload, dict):  # pragma: no cover - the model is a mapping
        raise TypeError("canonical Replay execution context must be a JSON object")
    return json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()


def replay_execution_context_digest(context: ReplayExecutionContext) -> str:
    """Fingerprint the exact canonical bytes persisted for one execution context."""

    return sha256(canonical_replay_execution_context_bytes(context)).hexdigest()


def replay_execution_component_digest(value: object) -> str:
    """Deterministically fingerprint one typed Campaign, Scenario, or Tool component."""

    payload = _canonical_replay_execution_context_value(value)
    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()
    return sha256(canonical).hexdigest()


def _canonical_replay_execution_context_value(value: object) -> object:
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        return _canonical_replay_execution_context_value(model_dump(mode="python", by_alias=True))
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError("canonical Replay execution context mapping keys must be strings")
        return {
            key: _canonical_replay_execution_context_value(item)
            for key, item in sorted(value.items())
        }
    if isinstance(value, (set, frozenset)):
        items = [_canonical_replay_execution_context_value(item) for item in value]
        return sorted(
            items,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ),
        )
    if isinstance(value, (list, tuple)):
        return [_canonical_replay_execution_context_value(item) for item in value]
    if isinstance(value, Enum):
        return _canonical_replay_execution_context_value(value.value)
    if isinstance(value, datetime):
        normalized = (
            value.astimezone(UTC) if value.tzinfo is not None else value.replace(tzinfo=UTC)
        )
        return normalized.isoformat()
    if isinstance(value, time):
        return value.isoformat()
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError(f"unsupported Replay execution context type: {type(value).__name__}")


class AdmitSourceArtifactRequest(StrictModel):
    """Opaque request to admit one producer-owned sealed Run snapshot.

    The caller cannot choose a filesystem path, Artifact identity, sealed Run
    identity, digest, Candidate, or Replay authority.  The Control Plane derives
    and verifies all of those values from the server-controlled staging handoff and
    the completed producer Job.
    """

    staging_id: str = Field(
        strict=True,
        pattern=r"^stage_[0-9a-f]{32}$",
    )
    producer_run_id: str = Field(pattern=r"^run_[0-9a-f]{32}$")
    producer_job_id: str = Field(pattern=r"^job_[0-9a-f]{32}$")
    idempotency_key: str = Field(min_length=8, max_length=200)


class ReplayRateAccountAuthority(StrictModel):
    """Rate-account authority reconstructed from immutable source evidence."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    rate_limits_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    ledger_id: str = Field(pattern=r"^rate-ledger_[0-9a-f]{32}$")
    max_requests_per_minute: int | None = Field(ge=1, le=60_000)
    observed_request_units: int = Field(strict=True, ge=0, le=1_000_000)
    observed_at: datetime
    window_seconds: Literal[60]

    @field_validator("observed_at")
    @classmethod
    def normalize_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Replay rate authority observed_at must be timezone-aware")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def require_observed_units_within_cap(self) -> ReplayRateAccountAuthority:
        if (
            self.max_requests_per_minute is not None
            and self.observed_request_units > self.max_requests_per_minute
        ):
            raise ValueError("Replay rate authority observed units exceed its cap")
        return self


class ReplayRateLimitSnapshot(StrictModel):
    """Typed contents of the sealed source ``rate-limits.json`` artifact."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ledger_id: str = Field(
        alias="ledgerId",
        pattern=r"^rate-ledger_[0-9a-f]{32}$",
    )
    reservation_counts: dict[str, int] = Field(
        alias="reservationCounts",
        max_length=1_000,
    )

    @model_validator(mode="after")
    def require_bounded_counts(self) -> ReplayRateLimitSnapshot:
        if any(
            not campaign
            or len(campaign) > 128
            or type(count) is not int
            or count < 0
            or count > 1_000_000
            for campaign, count in self.reservation_counts.items()
        ):
            raise ValueError("sealed Replay rate-limit reservations are invalid")
        return self


class ReplayJobPayload(StrictModel):
    """Canonical, non-executable authority envelope for one internal Replay Job."""

    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    compilation_id: str = Field(pattern=r"^replay-compilation_[0-9a-f]{32}$")
    execution_context_id: str = Field(pattern=r"^replay-context_[0-9a-f]{32}$")
    execution_context_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    budget_reservation_id: str = Field(pattern=r"^budget-reservation_[0-9a-f]{32}$")
    rate_reservation_id: str = Field(pattern=r"^rate-reservation_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    source: ArtifactRef
    mode: CampaignMode
    purpose: ReplayPurpose
    policy_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
    candidate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    claim: ReplayClaimBinding | None = None
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    contract_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    grant_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    attempt: int = Field(strict=True, ge=1, le=100)
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)


class CreateReplayBatchRequest(StrictModel):
    """Locator-only request for server-owned sealed-source Replay derivation."""

    source: ArtifactLocator
    retest_source: ArtifactLocator | None = None
    claim_projection: bool = False
    portable_attestation: bool = False
    target_attestation: bool = False
    idempotency_key: str = Field(min_length=8, max_length=200)

    @model_validator(mode="after")
    def require_distinct_retest_source(self) -> CreateReplayBatchRequest:
        if self.retest_source == self.source:
            raise ValueError("baseline and parent Retest Artifacts must be distinct")
        if self.retest_source is not None and self.claim_projection:
            raise ValueError("Claim projection is not supported for remediation Retest batches")
        if self.portable_attestation and not self.claim_projection:
            raise ValueError("portable attestation requires a Claim projection")
        if self.target_attestation and not self.portable_attestation:
            raise ValueError("target attestation requires portable Replay attestation")
        return self


class ReplayClaimRequest(StrictModel):
    """Internal Replay claim parameters; the Worker principal comes from authentication."""

    executor_profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_seconds: int = Field(default=30, strict=True, ge=5, le=300)
    wait_seconds: int = Field(default=0, strict=True, ge=0, le=20)


class ReplayLeaseRequest(StrictModel):
    """Heartbeat parameters bound to an already burned Replay ticket."""

    executor_profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    lease_seconds: int = Field(default=30, strict=True, ge=5, le=300)
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)


class ReplayToolPermitRequest(StrictModel):
    """Exact lease identity plus one 1-based canonical Tool-call ordinal."""

    executor_profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)
    call_ordinal: int = Field(strict=True, ge=1, le=20)


class ReplayFinalizeRequest(StrictModel):
    """Lease/fence plus one server-owned output capability.

    The legacy form references a shared staging reservation. The portable form
    carries a bounded content-addressed tree plus an independently keyed executor
    receipt. Both forms remain untrusted until the Control Plane imports and
    re-verifies the sealed Run; neither accepts a Worker-authored verdict.
    """

    executor_profile: Literal["kisa-exact-v1"] = KISA_EXACT_REPLAY_EXECUTOR_PROFILE
    lease_token: str = Field(min_length=32, max_length=300)
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)
    output_staging_id: str = Field(pattern=r"^stage_[0-9a-f]{32}$")
    artifact_bundle: PortableArtifactBundle | None = None
    executor_attestation: ExecutorExecutionAttestation | None = None

    @model_validator(mode="after")
    def require_complete_portable_transport(self) -> ReplayFinalizeRequest:
        if (self.artifact_bundle is None) != (self.executor_attestation is None):
            raise ValueError(
                "portable Replay Artifact bundle and executor attestation must be supplied together"
            )
        return self


class LeaseRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    lease_seconds: int = Field(default=30, ge=5, le=300)


class CompleteJobRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    result: CompleteJobResultJsonObject = Field(default_factory=dict)


class FailJobRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    error: str = Field(min_length=1, max_length=2_000)
    retryable: bool = True


class CreateCheckpointRequest(StrictModel):
    worker_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    lease_token: str = Field(min_length=32, max_length=300)
    state: CheckpointStateJsonObject
    pending_intent: ApprovalIntent


class DecideApprovalRequest(StrictModel):
    approve: bool
    reason: str = Field(min_length=1, max_length=1_000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        reason = value.strip()
        if not reason:
            raise ValueError("approval decision reason must not be blank")
        return reason


class CancelRunRequest(StrictModel):
    reason: str = Field(min_length=1, max_length=1_000)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        reason = value.strip()
        if not reason:
            raise ValueError("cancellation reason must not be blank")
        return reason


class ResumeCheckpointRequest(StrictModel):
    approval_id: str = Field(pattern=r"^approval_[0-9a-f]{32}$")


class RunView(StrictModel):
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    campaign_name: str
    state: RunState
    input: BoundedJsonObject
    current_checkpoint_id: str | None
    created_at: datetime
    updated_at: datetime


class RunSummaryView(StrictModel):
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    campaign_name: str
    state: RunState
    current_checkpoint_id: str | None
    created_at: datetime
    updated_at: datetime


class RunListView(StrictModel):
    items: list[RunSummaryView]
    total: int = Field(ge=0)
    limit: int = Field(ge=1, le=100)
    offset: int = Field(ge=0, le=10_000)


class JobView(StrictModel):
    job_id: str = Field(pattern=r"^job_[0-9a-f]{32}$")
    run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    kind: JobKind | InternalJobKind
    state: JobState
    payload: BoundedJsonObject
    priority: int = Field(strict=True, ge=-2_147_483_648, le=2_147_483_647)
    attempts: int = Field(strict=True, ge=0, le=2_147_483_647)
    max_attempts: int = Field(strict=True, ge=1, le=2_147_483_647)
    available_at: datetime
    lease_owner: str | None
    lease_expires_at: datetime | None
    heartbeat_at: datetime | None
    result: BoundedJsonObject | None
    error: str | None
    created_at: datetime
    updated_at: datetime


class ClaimedJob(StrictModel):
    job: JobView
    lease_token: str


class ReplayBatchView(StrictModel):
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    campaign_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    source: ArtifactRef
    retest_source: ArtifactRef | None = None
    mode: CampaignMode
    purpose: ReplayPurpose
    policy_version: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
    state: ReplayBatchState
    cas_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    created_by: str = Field(min_length=1, max_length=200)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def require_purpose_sources(self) -> ReplayBatchView:
        if self.purpose is ReplayPurpose.CONFIRMATION:
            if self.retest_source is not None:
                raise ValueError("confirmation Replay batch cannot contain a Retest source")
            return self
        if (
            self.retest_source is None
            or self.retest_source == self.source
            or self.retest_source.run_id == self.source.run_id
            or self.retest_source.integrity_root_digest == self.source.integrity_root_digest
        ):
            raise ValueError("remediation Retest batch requires a distinct parent Retest source")
        return self


class ReplayItemView(StrictModel):
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    state: ReplayItemState
    candidate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    claim: ReplayClaimBinding | None = None
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    contract_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    grant_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    required_attempts: int = Field(strict=True, ge=1, le=100)
    max_attempts: int = Field(strict=True, ge=1, le=100)
    attempts: int = Field(strict=True, ge=0, le=100)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def require_valid_attempt_counts(self) -> ReplayItemView:
        if self.max_attempts < self.required_attempts:
            raise ValueError("max_attempts must be greater than or equal to required_attempts")
        if self.attempts > self.max_attempts:
            raise ValueError("attempts must not exceed max_attempts")
        return self


class ReplayTicketView(StrictModel):
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    job_id: str = Field(pattern=r"^job_[0-9a-f]{32}$")
    compilation_id: str = Field(pattern=r"^replay-compilation_[0-9a-f]{32}$")
    budget_reservation_id: str = Field(pattern=r"^budget-reservation_[0-9a-f]{32}$")
    rate_reservation_id: str = Field(pattern=r"^rate-reservation_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    state: ReplayTicketState
    attempt: int = Field(strict=True, ge=1, le=100)
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)
    executor_profile: str | None = Field(
        default=None, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
    )
    claimed_by: str | None = Field(default=None, min_length=1, max_length=200)
    lease_expires_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def require_claim_binding(self) -> ReplayTicketView:
        claim_fields = (self.executor_profile, self.claimed_by, self.lease_expires_at)
        if self.state is ReplayTicketState.CLAIMED and any(value is None for value in claim_fields):
            raise ValueError("claimed Replay ticket requires principal, profile, and lease expiry")
        return self


class ReplayBatchIssuanceView(StrictModel):
    """One idempotent view of the Jobs/tickets issued for a Replay batch."""

    batch: ReplayBatchView
    items: list[ReplayItemView] = Field(min_length=1, max_length=1_000)
    tickets: list[ReplayTicketView] = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def require_exact_item_ticket_binding(self) -> ReplayBatchIssuanceView:
        if len(self.items) != len(self.tickets):
            raise ValueError("Replay issuance requires exactly one ticket per item")
        items_by_id = {item.item_id: item for item in self.items}
        tickets_by_item_id = {ticket.item_id: ticket for ticket in self.tickets}
        self._require_unique_issuance_ids(items_by_id, tickets_by_item_id)
        if set(items_by_id) != set(tickets_by_item_id):
            raise ValueError("Replay issuance tickets must cover the exact item set")
        for item_id, item in items_by_id.items():
            self._require_item_ticket_binding(item, tickets_by_item_id[item_id])
        return self

    def _require_unique_issuance_ids(
        self,
        items_by_id: dict[str, ReplayItemView],
        tickets_by_item_id: dict[str, ReplayTicketView],
    ) -> None:
        if len(items_by_id) != len(self.items):
            raise ValueError("Replay issuance item IDs must be unique")
        if len(tickets_by_item_id) != len(self.tickets):
            raise ValueError("Replay issuance ticket item IDs must be unique")
        if len({ticket.ticket_id for ticket in self.tickets}) != len(self.tickets):
            raise ValueError("Replay issuance ticket IDs must be unique")
        if len({ticket.job_id for ticket in self.tickets}) != len(self.tickets):
            raise ValueError("Replay issuance Job IDs must be unique")
        if len({ticket.compilation_id for ticket in self.tickets}) != len(self.tickets):
            raise ValueError("Replay issuance compilation IDs must be unique")

    def _require_item_ticket_binding(
        self,
        item: ReplayItemView,
        ticket: ReplayTicketView,
    ) -> None:
        if item.batch_id != self.batch.batch_id or ticket.batch_id != self.batch.batch_id:
            raise ValueError("Replay issuance item and ticket batch IDs must match")
        if ticket.replay_run_id != item.replay_run_id:
            raise ValueError("Replay issuance ticket and item Replay Run IDs must match")
        if ticket.attempt != item.attempts:
            raise ValueError("Replay issuance ticket attempt must match the item attempt count")


class ReplayClaimView(StrictModel):
    job: JobView
    batch: ReplayBatchView
    item: ReplayItemView
    ticket: ReplayTicketView
    lease_token: str = Field(min_length=32, max_length=300)

    @model_validator(mode="before")
    @classmethod
    def require_strict_job_attempt_authority(cls, value: Any) -> Any:
        """Keep generic JobView coercion out of the Replay authority boundary."""

        if isinstance(value, Mapping):
            job = value.get("job")
            if isinstance(job, Mapping):
                for field_name in ("priority", "attempts", "max_attempts"):
                    field_value = job.get(field_name)
                    if not isinstance(field_value, int) or isinstance(field_value, bool):
                        raise ValueError(f"Replay claim Job {field_name} must be a strict integer")
        return value

    @model_validator(mode="after")
    def require_burned_ticket_binding(self) -> ReplayClaimView:
        self._require_live_claim_states()
        self._require_job_attempt_authority()
        self._require_claim_graph_binding()
        payload = self._canonical_replay_job_payload()
        self._require_payload_authority_binding(payload)
        return self

    def _require_live_claim_states(self) -> None:
        state_requirements = (
            (
                self.job.kind == InternalJobKind.REPLAY.value,
                "Replay claim must contain an internal Replay Job",
            ),
            (self.job.state is JobState.LEASED, "Replay claim Job must be leased"),
            (
                self.ticket.state is ReplayTicketState.CLAIMED,
                "Replay claim ticket must be claimed",
            ),
            (
                self.batch.state is ReplayBatchState.RUNNING,
                "Replay claim batch must be running",
            ),
            (
                self.item.state is ReplayItemState.RUNNING,
                "Replay claim item must be running",
            ),
        )
        for satisfied, message in state_requirements:
            if not satisfied:
                raise ValueError(message)

    def _require_job_attempt_authority(self) -> None:
        job_integer_fields = {
            "priority": self.job.priority,
            "attempts": self.job.attempts,
            "max_attempts": self.job.max_attempts,
        }
        if any(
            not isinstance(value, int) or isinstance(value, bool)
            for value in job_integer_fields.values()
        ):
            raise ValueError("Replay claim Job authority fields must be strict integers")
        if not -2_147_483_648 <= self.job.priority <= 2_147_483_647:
            raise ValueError("Replay claim Job priority must fit PostgreSQL INT4")
        if self.job.lease_owner != self.ticket.claimed_by:
            raise ValueError("Replay claim Job and ticket principals must match")
        if self.job.lease_expires_at != self.ticket.lease_expires_at:
            raise ValueError("Replay claim Job and ticket lease deadlines must match")
        if self.job.attempts != 1:
            raise ValueError("Replay claim Job attempts must equal one")
        if self.job.max_attempts != 1:
            raise ValueError("Replay claim Job max attempts must equal one")

    def _require_claim_graph_binding(self) -> None:
        binding_requirements = (
            (
                self.item.batch_id == self.batch.batch_id,
                "Replay claim item and batch IDs must match",
            ),
            (
                self.ticket.batch_id == self.batch.batch_id,
                "Replay claim ticket and batch IDs must match",
            ),
            (
                self.ticket.item_id == self.item.item_id,
                "Replay claim ticket and item IDs must match",
            ),
            (
                self.ticket.job_id == self.job.job_id,
                "Replay claim ticket and Job IDs must match",
            ),
            (
                self.job.run_id == self.item.replay_run_id,
                "Replay claim Job and item Replay Run IDs must match",
            ),
            (
                self.ticket.replay_run_id == self.item.replay_run_id,
                "Replay claim ticket and item Replay Run IDs must match",
            ),
            (
                self.ticket.attempt == self.item.attempts,
                "Replay claim ticket attempt must match the item attempt count",
            ),
        )
        for satisfied, message in binding_requirements:
            if not satisfied:
                raise ValueError(message)

    def _canonical_replay_job_payload(self) -> ReplayJobPayload:
        try:
            return ReplayJobPayload.model_validate(self.job.payload)
        except ValueError as exc:
            raise ValueError("Replay claim Job payload must be canonical") from exc

    def _require_payload_authority_binding(self, payload: ReplayJobPayload) -> None:
        expected_fields = {
            "batch_id": self.batch.batch_id,
            "item_id": self.item.item_id,
            "ticket_id": self.ticket.ticket_id,
            "compilation_id": self.ticket.compilation_id,
            "budget_reservation_id": self.ticket.budget_reservation_id,
            "rate_reservation_id": self.ticket.rate_reservation_id,
            "replay_run_id": self.job.run_id,
            "source": self.batch.source,
            "mode": self.batch.mode,
            "purpose": self.batch.purpose,
            "policy_version": self.batch.policy_version,
            "candidate_id": self.item.candidate_id,
            "claim": self.item.claim,
            "candidate_digest": self.item.candidate_digest,
            "contract_digest": self.item.contract_digest,
            "compilation_digest": self.item.compilation_digest,
            "grant_digest": self.item.grant_digest,
            "attempt": self.ticket.attempt,
            "fencing_value": self.ticket.fencing_value,
        }
        inconsistent = any(
            getattr(payload, field_name) != expected
            for field_name, expected in expected_fields.items()
        )
        if inconsistent or payload.replay_run_id != self.item.replay_run_id:
            raise ValueError("Replay claim Job payload authority binding is inconsistent")


class ReplayExecutionClaimView(ReplayClaimView):
    """Worker claim envelope containing exact compilation and execution context."""

    compilation: ReplayCompilation
    execution_context: ReplayExecutionContext
    execution_context_digest: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def require_compilation_authority_binding(self) -> ReplayExecutionClaimView:
        compilation = self.compilation
        candidate = compilation.validation_packet.candidate
        binding = compilation.spec.binding
        context = self.execution_context
        context_digest = replay_execution_context_digest(context)
        compilation_digest = sha256(canonical_replay_compilation_bytes(compilation)).hexdigest()
        grant_digest = replay_context_digest(compilation.grant)
        payload = ReplayJobPayload.model_validate(self.job.payload)
        matching_targets = [
            target for target in context.campaign.spec.targets if target.id == binding.target_id
        ]
        retest_context = compilation.validation_packet.retest_context
        retest_source = self.batch.retest_source
        if (
            candidate.candidate_id != self.item.candidate_id
            or replay_context_digest(candidate) != self.item.candidate_digest
            or replay_context_digest(compilation.contract) != self.item.contract_digest
            or compilation_digest != self.item.compilation_digest
            or grant_digest != self.item.grant_digest
            or binding.candidate_id != self.item.candidate_id
            or binding.claim != self.item.claim
            or payload.claim != self.item.claim
            or binding.candidate_run_id != self.batch.source.run_id
            or binding.replay_run_id != self.item.replay_run_id
            or binding.campaign != self.batch.campaign_name
            or binding.mode is not self.batch.mode
            or binding.purpose is not self.batch.purpose
            or context_digest != self.execution_context_digest
            or payload.execution_context_id != context.context_id
            or payload.execution_context_digest != context_digest
            or context.batch_id != self.batch.batch_id
            or context.item_id != self.item.item_id
            or context.compilation_id != self.ticket.compilation_id
            or context.replay_run_id != self.item.replay_run_id
            or context.source != self.batch.source
            or context.source_root_digest != self.batch.source.integrity_root_digest
            or context.policy_version != self.batch.policy_version
            or context.required_executor_profile != self.ticket.executor_profile
            or context.campaign.metadata.name != binding.campaign
            or context.campaign.spec.mode is not binding.mode
            or len(matching_targets) != 1
            or matching_targets[0].endpoint != binding.target
            or matching_targets[0].type not in context.scenario.target_types
            or binding.threat_class not in context.campaign.spec.threat_classes
            or context.scenario.scenario_id != binding.scenario_id
            or context.scenario.threat_classes != {binding.threat_class}
            or context.scenario.tool_id != binding.tool_id
            or context.scenario.method.upper() != compilation.spec.method
            or context.tool_spec.tool_id != binding.tool_id
            or (self.batch.purpose is ReplayPurpose.CONFIRMATION and retest_context is not None)
            or (
                self.batch.purpose is ReplayPurpose.REMEDIATION_RETEST
                and (
                    retest_context is None
                    or retest_source is None
                    or retest_context.retest_run_id != retest_source.run_id
                    or retest_context.retest_source_root_digest
                    != retest_source.integrity_root_digest
                )
            )
            or context.tool_spec.version != binding.tool_version
            or context.tool_spec.risk_tier != compilation.spec.risk_tier
            or bool(compilation.spec.secret_lease_ids)
            or bool(context.secret_lease_ids)
            or context.created_at < compilation.spec.compiled_at
            or context.created_at >= compilation.spec.expires_at
            or context.created_at >= compilation.grant.expires_at
        ):
            raise ValueError("Replay execution context authority binding is inconsistent")
        return self


class ReplayToolPermitView(StrictModel):
    """Immutable, non-bearer proof of one durably consumed Replay Tool call."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    permit_id: str = Field(pattern=r"^replay-permit_[0-9a-f]{32}$")
    permit_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    replay_request_id: str = Field(pattern=r"^tool_replay_[0-9a-f]{32}$")
    job_id: str = Field(pattern=r"^job_[0-9a-f]{32}$")
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    compilation_id: str = Field(pattern=r"^replay-compilation_[0-9a-f]{32}$")
    budget_reservation_id: str = Field(pattern=r"^budget-reservation_[0-9a-f]{32}$")
    rate_reservation_id: str = Field(pattern=r"^rate-reservation_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    attempt: int = Field(strict=True, ge=1, le=100)
    fencing_value: int = Field(strict=True, ge=1, le=2_147_483_647)
    call_ordinal: int = Field(strict=True, ge=1, le=20)
    issued_to: str = Field(min_length=1, max_length=200)
    executor_profile: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    source_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    grant_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    original_request_id: str = Field(min_length=1, max_length=200)
    tool_id: str = Field(min_length=1, max_length=200)
    tool_version: str = Field(min_length=1, max_length=100)
    target_id: str = Field(min_length=1, max_length=200)
    target: str = Field(min_length=1, max_length=2_000)
    method: str = Field(min_length=1, max_length=20)
    compiled_argument_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool_call_units: int = Field(default=1, strict=True, ge=1, le=1)
    request_units: int = Field(strict=True, ge=1, le=100)
    issued_at: datetime
    expires_at: datetime
    target_execution_challenge: TargetExecutionChallenge | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        return value.upper()

    @model_validator(mode="after")
    def require_short_aware_lifetime(self) -> ReplayToolPermitView:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("Replay Tool permit timestamps must be timezone-aware")
        if self.expires_at <= self.issued_at:
            raise ValueError("Replay Tool permit must expire after issuance")
        if self.expires_at > self.issued_at + timedelta(seconds=30):
            raise ValueError("Replay Tool permit exceeds the 30-second TTL ceiling")
        if self.target_execution_challenge is not None:
            expected = derive_target_execution_challenge(
                permit_digest=self.permit_digest,
                replay_request_id=self.replay_request_id,
                batch_id=self.batch_id,
                item_id=self.item_id,
                ticket_id=self.ticket_id,
                fencing_value=self.fencing_value,
                call_ordinal=self.call_ordinal,
                target=self.target,
                method=self.method,
                compiled_argument_digest=self.compiled_argument_digest,
                issued_at=self.issued_at,
                expires_at=self.expires_at,
            )
            if self.target_execution_challenge != expected:
                raise ValueError("Replay Tool permit target execution challenge is inconsistent")
        return self


class ReplayFinalizationView(StrictModel):
    """Authoritative server-derived result of one finalized Replay attempt."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    finalization_id: str = Field(pattern=r"^replay-finalization_[0-9a-f]{32}$")
    job: JobView
    batch: ReplayBatchView
    item: ReplayItemView
    ticket: ReplayTicketView
    artifact: ArtifactRef
    artifact_set_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    receipt_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_transport: PortableArtifactTransportReceipt | None = None
    executor_attestation: ExecutorExecutionAttestation | None = None
    target_execution_verification: TargetExecutionVerificationSummary | None = None
    gate_decision: ValidationDecision
    result_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    finalized_by: str = Field(min_length=1, max_length=200)
    finalized_at: datetime

    @model_validator(mode="after")
    def require_terminal_authority_binding(self) -> ReplayFinalizationView:
        if (
            self.job.state is not JobState.SUCCEEDED
            or self.ticket.state is not ReplayTicketState.FINALIZED
            or self.item.state not in {ReplayItemState.VERIFIED, ReplayItemState.GATED}
            or self.batch.state
            not in {
                ReplayBatchState.RUNNING,
                ReplayBatchState.GATING,
                ReplayBatchState.COMPLETED,
            }
            or self.job.job_id != self.ticket.job_id
            or self.item.item_id != self.ticket.item_id
            or self.batch.batch_id != self.ticket.batch_id
            or self.artifact.producer_run_id != self.job.run_id
            or self.artifact.run_id != self.job.run_id
            or self.gate_decision.candidate_id != self.item.candidate_id
            or ((self.artifact_transport is None) != (self.executor_attestation is None))
            or (
                self.artifact_transport is not None
                and self.executor_attestation is not None
                and self.artifact_transport.manifest_sha256
                != self.executor_attestation.statement.artifact_bundle_manifest_sha256
            )
            or (
                (
                    self.executor_attestation is not None
                    and self.executor_attestation.statement.target_execution_proofs is not None
                )
                != (self.target_execution_verification is not None)
            )
        ):
            raise ValueError("Replay finalization view authority binding is inconsistent")
        return self


class ReplayProjectionItemAuthority(StrictModel):
    """Exact finalized Replay input snapshotted for one projection publication."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    ordinal: int = Field(strict=True, ge=0, le=999)
    item_id: str = Field(pattern=r"^replay-item_[0-9a-f]{32}$")
    ticket_id: str = Field(pattern=r"^replay-ticket_[0-9a-f]{32}$")
    finalization_id: str = Field(pattern=r"^replay-finalization_[0-9a-f]{32}$")
    replay_run_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
    compilation_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    output: ArtifactRef
    artifact_set_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    receipt_seal_root_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    gate_decision_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    result_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    artifact_transport_digest: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        exclude_if=lambda value: value is None,
    )
    executor_attestation_digest: str | None = Field(
        default=None,
        pattern=r"^[a-f0-9]{64}$",
        exclude_if=lambda value: value is None,
    )
    finalized_at: datetime

    @model_validator(mode="after")
    def require_aware_finalization_time(self) -> ReplayProjectionItemAuthority:
        if self.finalized_at.tzinfo is None or self.finalized_at.utcoffset() is None:
            raise ValueError("Replay projection finalization time must be timezone-aware")
        if self.output.run_id != self.replay_run_id:
            raise ValueError("Replay projection output belongs to another Replay Run")
        if (self.artifact_transport_digest is None) != (self.executor_attestation_digest is None):
            raise ValueError(
                "Replay projection portable transport and executor attestation "
                "digests must be supplied together"
            )
        return self


class ReplayProjectionInputAuthority(StrictModel):
    """Canonical immutable input set evaluated outside the database transaction."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.replay-projection-inputs/v1"] = (
        "pajin.control-plane.replay-projection-inputs/v1"
    )
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    source: ArtifactRef
    batch_cas_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    items: list[ReplayProjectionItemAuthority] = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def require_sorted_unique_items(self) -> ReplayProjectionInputAuthority:
        order = [(item.ordinal, item.item_id) for item in self.items]
        if order != sorted(order) or len(order) != len(set(order)):
            raise ValueError("Replay projection items must be uniquely sorted by ordinal")
        for attribute in ("ticket_id", "finalization_id", "replay_run_id"):
            values = [getattr(item, attribute) for item in self.items]
            if len(values) != len(set(values)):
                raise ValueError(f"Replay projection {attribute} values must be unique")
        return self


class ReplayRetestProjectionInputAuthority(StrictModel):
    """Canonical two-source authority for a remediation-retest projection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.replay-projection-inputs/v2"] = (
        "pajin.control-plane.replay-projection-inputs/v2"
    )
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    source: ArtifactRef
    retest_source: ArtifactRef
    batch_cas_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    items: list[ReplayProjectionItemAuthority] = Field(min_length=1, max_length=1_000)

    @model_validator(mode="after")
    def require_sorted_unique_items(self) -> ReplayRetestProjectionInputAuthority:
        if self.source == self.retest_source:
            raise ValueError("Replay retest projection requires distinct source Artifacts")
        order = [(item.ordinal, item.item_id) for item in self.items]
        if order != sorted(order) or len(order) != len(set(order)):
            raise ValueError("Replay projection items must be uniquely sorted by ordinal")
        for attribute in ("ticket_id", "finalization_id", "replay_run_id"):
            values = [getattr(item, attribute) for item in self.items]
            if len(values) != len(set(values)):
                raise ValueError(f"Replay projection {attribute} values must be unique")
        return self


class ReplayClaimProjectionItemAuthority(ReplayProjectionItemAuthority):
    """Exact Claim-specific finalized input for a Control Plane projection."""

    candidate_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    candidate_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    claim: ReplayClaimBinding


class ReplayClaimProjectionInputAuthority(StrictModel):
    """Canonical exact-Claim input set for one immutable confirmation projection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.replay-projection-inputs/v3"] = (
        "pajin.control-plane.replay-projection-inputs/v3"
    )
    batch_id: str = Field(pattern=r"^replay-batch_[0-9a-f]{32}$")
    source: ArtifactRef
    batch_cas_version: int = Field(strict=True, ge=1, le=2_147_483_647)
    items: list[ReplayClaimProjectionItemAuthority] = Field(min_length=1, max_length=3_000)

    @model_validator(mode="after")
    def require_complete_claim_authority(self) -> ReplayClaimProjectionInputAuthority:
        order = [(item.ordinal, item.item_id) for item in self.items]
        if order != sorted(order) or len(order) != len(set(order)):
            raise ValueError("Replay Claim projection items must be uniquely sorted by ordinal")
        for attribute in (
            "ticket_id",
            "finalization_id",
            "replay_run_id",
        ):
            values = [getattr(item, attribute) for item in self.items]
            if len(values) != len(set(values)):
                raise ValueError(f"Replay Claim projection {attribute} values must be unique")
        claim_ids = [item.claim.claim_id for item in self.items]
        claim_digests = [item.claim.claim_digest for item in self.items]
        if len(claim_ids) != len(set(claim_ids)) or len(claim_digests) != len(set(claim_digests)):
            raise ValueError("Replay Claim projection must bind unique Atomic Claims")

        grouped: dict[str, list[ReplayClaimProjectionItemAuthority]] = {}
        for item in self.items:
            grouped.setdefault(item.candidate_id, []).append(item)
        for candidate_items in grouped.values():
            if {item.claim.claim_type for item in candidate_items} != set(AtomicClaimType):
                raise ValueError("Replay Claim projection must cover every Candidate Atomic Claim")
            if len({item.candidate_digest for item in candidate_items}) != 1:
                raise ValueError("Replay Claim projection changed its Candidate digest")
            if len({item.claim.candidate_claim_digest for item in candidate_items}) != 1:
                raise ValueError("Replay Claim projection changed its Candidate Claim digest")
        return self


class ReplayProjectionView(StrictModel):
    """Published immutable validation projection for one complete Replay batch."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    projection_id: str = Field(pattern=r"^replay-projection_[0-9a-f]{32}$")
    batch: ReplayBatchView
    artifact: ArtifactRef
    input_authority: (
        ReplayProjectionInputAuthority
        | ReplayRetestProjectionInputAuthority
        | ReplayClaimProjectionInputAuthority
    )
    input_authority_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    published_by: str = Field(min_length=1, max_length=200)
    published_at: datetime

    @model_validator(mode="after")
    def require_publication_binding(self) -> ReplayProjectionView:
        authority_digest = replay_context_digest(
            self.input_authority.model_dump(mode="json", by_alias=True)
        )
        if isinstance(self.input_authority, ReplayRetestProjectionInputAuthority):
            purpose_binding = (
                self.batch.purpose is ReplayPurpose.REMEDIATION_RETEST
                and self.batch.retest_source == self.input_authority.retest_source
            )
            projection_source = self.input_authority.retest_source
        else:
            purpose_binding = (
                self.batch.purpose is ReplayPurpose.CONFIRMATION
                and self.batch.retest_source is None
            )
            projection_source = self.input_authority.source
        if (
            self.batch.state is not ReplayBatchState.COMPLETED
            or self.input_authority.batch_id != self.batch.batch_id
            or self.input_authority.source != self.batch.source
            or not purpose_binding
            or self.batch.cas_version != self.input_authority.batch_cas_version + 1
            or self.input_authority_digest != authority_digest
            or self.artifact.producer_run_id != projection_source.producer_run_id
            or self.artifact.run_id != projection_source.run_id
            or self.artifact.created_by != self.published_by
            or self.published_at.tzinfo is None
            or self.published_at.utcoffset() is None
        ):
            raise ValueError("Replay projection publication binding is inconsistent")
        return self


class CheckpointView(StrictModel):
    checkpoint_id: str
    run_id: str
    sequence: int
    schema_version: int
    state: BoundedJsonObject
    pending_intent: ApprovalIntent
    payload_sha256: str
    signature: str
    key_id: str
    created_at: datetime
    claimed_at: datetime | None
    claimed_by: str | None
    continuation_job_id: str | None


class ApprovalView(StrictModel):
    approval_id: str
    run_id: str
    checkpoint_id: str
    intent: ApprovalIntent
    state: ApprovalState
    requested_by: str
    requested_at: datetime
    decided_by: str | None
    decided_at: datetime | None
    decision_reason: str | None
    consumed_by: str | None
    consumed_at: datetime | None


class SubmissionView(StrictModel):
    run: RunView
    job: JobView
    created: bool


class CancelRunView(StrictModel):
    run: RunView
    applied: bool
    cancelled_job_ids: list[str]
    revoked_approval_ids: list[str]


class CheckpointCreationView(StrictModel):
    checkpoint: CheckpointView
    approval: ApprovalView


class ResumeView(StrictModel):
    run: RunView
    job: JobView
    checkpoint: CheckpointView
    approval: ApprovalView


class AuditEventView(StrictModel):
    model_config = ConfigDict(extra="forbid")

    event_id: str
    run_id: str
    sequence: int
    event_type: str
    actor: str
    payload: BoundedJsonObject
    occurred_at: datetime
