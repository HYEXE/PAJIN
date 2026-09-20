"""Durable, non-authorizing records for one governed specialist job attempt."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.agentic.models import (
    AgenticStrictModel,
    Identifier,
    PentestSpecialization,
    Sha256,
    _literal_false,
)
from pajin.agentic.specialist_verifications import (
    AgenticSpecialistClaimVerification,
    AgenticSpecialistDispatchVerification,
)
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest

AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION: Literal[
    "pajin.dev/agentic-specialist-job-attempt/v1alpha1"
] = "pajin.dev/agentic-specialist-job-attempt/v1alpha1"
AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION: Literal[
    "pajin.dev/agentic-specialist-terminal-receipt/v1alpha1"
] = "pajin.dev/agentic-specialist-terminal-receipt/v1alpha1"

_MAX_ATTEMPT_BYTES = 512 * 1024
_MAX_RECEIPT_BYTES = 256 * 1024

_CLAIM_SUBJECT_EXCLUDED_FIELDS = frozenset(
    {
        "attempt_id",
        "attempt_digest",
        "state_digest",
        "state",
        "claim_verification",
        "claim_verification_digest",
        "dispatch_verification",
        "dispatch_verification_digest",
        "dispatch_event_digest",
        "backend_dispatch_started_at",
    }
)


class AgenticSpecialistJobAttemptState(StrEnum):
    """One-way durable state around the first backend await boundary."""

    CLAIMED_BEFORE_BACKEND = "claimed-before-backend"
    DISPATCH_STARTED_OUTCOME_UNKNOWN = "dispatch-started-outcome-unknown"


class AgenticSpecialistTerminalKind(StrEnum):
    """Closed recovery grammar for one non-repeatable specialist attempt."""

    ABANDONED_BEFORE_BACKEND = "abandoned-before-backend"
    FAILED_BEFORE_TARGET_IO = "failed-before-target-io"
    COMPLETED_VERIFIED = "completed-verified"
    FAILED_AFTER_DISPATCH_PROVEN_TERMINAL = "failed-after-dispatch-proven-terminal"
    STARTED_OUTCOME_UNKNOWN = "started-outcome-unknown"


class AgenticSpecialistTargetIOState(StrEnum):
    """Host-verifiable target-I/O classification without carrying target data."""

    NOT_STARTED = "not-started"
    PERFORMED = "performed"
    UNKNOWN = "unknown"


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
        _utc(value, label="specialist attempt timestamp")
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


class AgenticSpecialistJobAttempt(AgenticStrictModel):
    """Content-addressed job identity and its pre-await dispatch marker."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-specialist-job-attempt/v1alpha1"] = Field(
        default=AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticSpecialistJobAttempt"] = "AgenticSpecialistJobAttempt"
    attempt_id: str = Field(default="", alias="attemptId", max_length=120)
    attempt_digest: str = Field(default="", alias="attemptDigest", max_length=64)
    state_digest: str = Field(default="", alias="stateDigest", max_length=64)
    state: AgenticSpecialistJobAttemptState

    store_id: str = Field(alias="storeId", pattern=r"^agentic-store:[a-f0-9]{32}$")
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    database_identity_digest: Sha256 = Field(alias="databaseIdentityDigest")
    deployment_digest: Sha256 = Field(alias="deploymentDigest")
    control_plane_run_id: Identifier = Field(alias="controlPlaneRunId")
    campaign_id: str = Field(alias="campaignId", min_length=3, max_length=80)
    campaign_manifest_digest: Sha256 = Field(alias="campaignManifestDigest")

    plan_id: str = Field(
        alias="planId",
        pattern=r"^agentic-specialist-plan_[a-f0-9]{64}$",
    )
    plan_digest: Sha256 = Field(alias="planDigest")
    plan_state_digest: Sha256 = Field(alias="planStateDigest")
    reservation_id: str = Field(
        alias="reservationId",
        pattern=r"^agentic-specialist-reservation_[a-f0-9]{64}$",
    )
    reservation_digest: Sha256 = Field(alias="reservationDigest")
    reservation_state_digest: Sha256 = Field(alias="reservationStateDigest")
    command_id: str = Field(alias="commandId", pattern=r"^agent-command_[a-f0-9]{64}$")
    command_digest: Sha256 = Field(alias="commandDigest")
    target_agent_id: Identifier = Field(alias="targetAgentId")
    task_id: Identifier = Field(alias="taskId")
    scheduler_task_name: Identifier = Field(alias="schedulerTaskName")
    scheduler_task_token_digest: Sha256 = Field(alias="schedulerTaskTokenDigest")
    runtime_capsule_token_digest: Sha256 = Field(alias="runtimeCapsuleTokenDigest")
    specialization: PentestSpecialization
    dispatch_binding_id: str = Field(
        alias="dispatchBindingId",
        pattern=r"^agentic-specialist-dispatch-binding_[a-f0-9]{64}$",
    )
    dispatch_binding_digest: Sha256 = Field(alias="dispatchBindingDigest")
    claim_verification: AgenticSpecialistClaimVerification = Field(alias="claimVerification")
    claim_verification_digest: str = Field(
        default="",
        alias="claimVerificationDigest",
        max_length=64,
    )
    dispatch_verification: AgenticSpecialistDispatchVerification | None = Field(
        default=None,
        alias="dispatchVerification",
    )
    dispatch_verification_digest: Sha256 | None = Field(
        default=None,
        alias="dispatchVerificationDigest",
    )
    dispatch_event_digest: Sha256 | None = Field(
        default=None,
        alias="dispatchEventDigest",
    )

    graph_snapshot_id: Identifier = Field(alias="graphSnapshotId")
    graph_snapshot_digest: Sha256 = Field(alias="graphSnapshotDigest")
    preparation_id: str = Field(
        alias="preparationId",
        pattern=r"^agentic-specialist-preparation_[a-f0-9]{64}$",
    )
    preparation_digest: Sha256 = Field(alias="preparationDigest")
    profile_registry_digest: Sha256 = Field(alias="profileRegistryDigest")
    profile_id: Identifier = Field(alias="profileId")
    profile_version: str = Field(alias="profileVersion", min_length=1, max_length=40)
    profile_digest: Sha256 = Field(alias="profileDigest")
    executor_catalog_digest: Sha256 = Field(alias="executorCatalogDigest")
    executor_id: Identifier = Field(alias="executorId")
    executor_version: str = Field(alias="executorVersion", min_length=1, max_length=40)
    executor_digest: Sha256 = Field(alias="executorDigest")
    prepared_action_digest: Sha256 = Field(alias="preparedActionDigest")
    activation_set_digest: Sha256 = Field(alias="activationSetDigest")
    release_id: str = Field(alias="releaseId", min_length=1, max_length=100)
    release_digest: Sha256 = Field(alias="releaseDigest")
    capability_id: Identifier = Field(alias="capabilityId")
    capability_version: str = Field(alias="capabilityVersion", min_length=1, max_length=40)
    capability_definition_digest: Sha256 = Field(alias="capabilityDefinitionDigest")
    capability_digest: Sha256 = Field(alias="capabilityDigest")
    capability_authority_set_id: str = Field(
        alias="capabilityAuthoritySetId",
        pattern=r"^capability-authority-set_[a-f0-9]{64}$",
    )
    capability_authority_set_digest: Sha256 = Field(alias="capabilityAuthoritySetDigest")
    tool_id: Identifier = Field(alias="toolId")
    tool_version: str = Field(alias="toolVersion", min_length=1, max_length=40)
    tool_digest: Sha256 = Field(alias="toolDigest")
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    request_digest: Sha256 = Field(alias="requestDigest")

    capability_grant_id: str = Field(
        alias="capabilityGrantId",
        min_length=1,
        max_length=200,
    )
    capability_grant_digest: Sha256 = Field(alias="capabilityGrantDigest")
    grant_lineage_state_digest: Sha256 = Field(alias="grantLineageStateDigest")
    capability_grant_expires_at: datetime = Field(alias="capabilityGrantExpiresAt")
    grant_consumption_receipt_id: str = Field(
        alias="grantConsumptionReceiptId",
        pattern=r"^agentic-specialist-grant-consumption_[a-f0-9]{64}$",
    )
    grant_consumption_receipt_digest: Sha256 = Field(alias="grantConsumptionReceiptDigest")
    action_permit_id: str = Field(
        alias="actionPermitId",
        pattern=r"^action-permit_[a-f0-9]{64}$",
    )
    action_permit_digest: Sha256 = Field(alias="actionPermitDigest")
    action_permit_expires_at: datetime = Field(alias="actionPermitExpiresAt")
    approval_id: str = Field(alias="approvalId", min_length=1, max_length=120)
    approval_digest: Sha256 = Field(alias="approvalDigest")
    approval_expires_at: datetime = Field(alias="approvalExpiresAt")
    approval_consumption_receipt_id: str = Field(
        alias="approvalConsumptionReceiptId",
        min_length=1,
        max_length=120,
    )
    approval_consumption_receipt_digest: Sha256 = Field(alias="approvalConsumptionReceiptDigest")
    dispatch_id: str = Field(
        alias="dispatchId",
        pattern=r"^action-dispatch_[a-f0-9]{64}$",
    )
    target_id: Identifier = Field(alias="targetId")
    target_digest: Sha256 = Field(alias="targetDigest")

    gateway_id: Identifier = Field(alias="gatewayId")
    gateway_version: str = Field(alias="gatewayVersion", min_length=1, max_length=40)
    gateway_digest: Sha256 = Field(alias="gatewayDigest")
    execution_inventory_id: str = Field(
        alias="executionInventoryId",
        pattern=r"^agentic-specialist-execution-inventory_[a-f0-9]{64}$",
    )
    execution_inventory_digest: Sha256 = Field(alias="executionInventoryDigest")
    worker_backend_id: Identifier = Field(alias="workerBackendId")
    worker_backend_version: str = Field(
        alias="workerBackendVersion",
        min_length=1,
        max_length=40,
    )
    worker_backend_digest: Sha256 = Field(alias="workerBackendDigest")
    worker_job_id: Identifier = Field(alias="workerJobId")
    worker_job_digest: Sha256 = Field(alias="workerJobDigest")
    worker_command_digest: Sha256 = Field(alias="workerCommandDigest")
    worker_compiler_id: Identifier = Field(alias="workerCompilerId")
    worker_compiler_version: str = Field(
        alias="workerCompilerVersion",
        min_length=1,
        max_length=40,
    )
    worker_compiler_digest: Sha256 = Field(alias="workerCompilerDigest")
    worker_image_reference: Identifier = Field(alias="workerImageReference")
    worker_image_digest: Sha256 = Field(alias="workerImageDigest")
    worker_verifier_id: Identifier = Field(alias="workerVerifierId")
    worker_verifier_version: str = Field(
        alias="workerVerifierVersion",
        min_length=1,
        max_length=40,
    )
    worker_verifier_digest: Sha256 = Field(alias="workerVerifierDigest")
    worker_verification_key_id: Identifier = Field(alias="workerVerificationKeyId")
    worker_verification_key_digest: Sha256 = Field(alias="workerVerificationKeyDigest")

    claimed_at: datetime = Field(alias="claimedAt")
    backend_dispatch_started_at: datetime | None = Field(
        default=None,
        alias="backendDispatchStartedAt",
    )
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")
    report_authority: Literal[False] = Field(default=False, alias="reportAuthority")

    @field_validator(
        "capability_grant_expires_at",
        "action_permit_expires_at",
        "approval_expires_at",
        "claimed_at",
        "backend_dispatch_started_at",
    )
    @classmethod
    def require_utc_times(cls, value: datetime | None) -> datetime | None:
        return _utc(value, label="specialist job-attempt timestamp") if value else None

    @field_validator(
        "automatic_redispatch_authorized",
        "execution_authority",
        "finding_authority",
        "graph_authority",
        "report_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_identity_and_state(self) -> Self:
        dispatch_started = (
            self.state is AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
        )
        if dispatch_started != (self.backend_dispatch_started_at is not None):
            raise ValueError("specialist job-attempt state timestamp differs")
        if dispatch_started != (self.dispatch_verification is not None):
            raise ValueError("specialist job-attempt dispatch verification record differs")
        if dispatch_started != (self.dispatch_verification_digest is not None):
            raise ValueError("specialist job-attempt dispatch verification differs")
        if not dispatch_started and self.dispatch_event_digest is not None:
            raise ValueError("specialist job-attempt dispatch event differs")
        if (
            self.backend_dispatch_started_at is not None
            and self.backend_dispatch_started_at < self.claimed_at
        ):
            raise ValueError("specialist backend dispatch predates its durable claim")
        if not self.claimed_at < min(
            self.capability_grant_expires_at,
            self.action_permit_expires_at,
            self.approval_expires_at,
        ):
            raise ValueError("specialist job-attempt authority expired before its claim")
        claim_subject_material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude=set(_CLAIM_SUBJECT_EXCLUDED_FIELDS),
        )
        claim_subject_digest = discovery_digest(
            "pajin.agentic.specialist-job-claim-subject/v1",
            claim_subject_material,
        )
        _require_claim_verification_matches_attempt(
            self,
            subject_digest=claim_subject_digest,
        )
        if (
            self.claim_verification_digest
            and self.claim_verification_digest != self.claim_verification.verification_digest
        ):
            raise ValueError("specialist claim-verification Digest differs")
        object.__setattr__(
            self,
            "claim_verification_digest",
            self.claim_verification.verification_digest,
        )
        identity_material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "attempt_id",
                "attempt_digest",
                "state",
                "state_digest",
                "claim_verification",
                "backend_dispatch_started_at",
                "dispatch_verification",
                "dispatch_verification_digest",
                "dispatch_event_digest",
            },
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-job-attempt/v1",
            identity_material,
        )
        expected_id = f"agentic-specialist-job-attempt_{digest}"
        if self.attempt_digest and self.attempt_digest != digest:
            raise ValueError("specialist job-attempt Digest differs")
        if self.attempt_id and self.attempt_id != expected_id:
            raise ValueError("specialist job-attempt ID differs")
        dispatch_event_digest: str | None = None
        if dispatch_started:
            assert self.dispatch_verification is not None
            assert self.dispatch_verification_digest is not None
            assert self.backend_dispatch_started_at is not None
            claimed_state_digest = _specialist_job_attempt_state_digest(
                attempt_digest=digest,
                state=AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND,
                dispatch_verification_digest=None,
                dispatch_event_digest=None,
                backend_dispatch_started_at=None,
            )
            _require_dispatch_verification_matches_attempt(
                self,
                attempt_digest=digest,
                claimed_state_digest=claimed_state_digest,
            )
            if self.dispatch_verification_digest != self.dispatch_verification.verification_digest:
                raise ValueError("specialist dispatch-verification Digest differs")
            dispatch_event_digest = discovery_digest(
                "pajin.agentic.specialist-worker-dispatched-event/v1",
                {
                    "attemptDigest": digest,
                    "workerJobDigest": self.worker_job_digest,
                    "dispatchVerificationDigest": self.dispatch_verification_digest,
                    "backendDispatchStartedAt": _format_timestamp(self.backend_dispatch_started_at),
                },
            )
            if (
                self.dispatch_event_digest is not None
                and self.dispatch_event_digest != dispatch_event_digest
            ):
                raise ValueError("specialist dispatch event Digest differs")
            object.__setattr__(self, "dispatch_event_digest", dispatch_event_digest)
        state_digest = _specialist_job_attempt_state_digest(
            attempt_digest=digest,
            state=self.state,
            dispatch_verification_digest=self.dispatch_verification_digest,
            dispatch_event_digest=dispatch_event_digest,
            backend_dispatch_started_at=self.backend_dispatch_started_at,
        )
        if self.state_digest and self.state_digest != state_digest:
            raise ValueError("specialist job-attempt State Digest differs")
        object.__setattr__(self, "attempt_digest", digest)
        object.__setattr__(self, "attempt_id", expected_id)
        object.__setattr__(self, "state_digest", state_digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist job attempt",
            max_bytes=_MAX_ATTEMPT_BYTES,
        )
        return self


def _wire_value(value: object) -> object:
    if isinstance(value, datetime):
        return _format_timestamp(value)
    if isinstance(value, StrEnum):
        return value.value
    return value


def specialist_job_claim_subject_digest(values: Mapping[str, object]) -> str:
    """Derive the pre-verification subject digest from alias or field-name values."""

    material: dict[str, object] = {}
    for field_name, field in AgenticSpecialistJobAttempt.model_fields.items():
        if field_name in _CLAIM_SUBJECT_EXCLUDED_FIELDS:
            continue
        alias = field.alias or field_name
        if alias in values:
            value = values[alias]
        elif field_name in values:
            value = values[field_name]
        elif not field.is_required():
            value = field.get_default(call_default_factory=True)
        else:
            raise ValueError(f"specialist claim subject lacks {alias}")
        material[alias] = _wire_value(value)
    return discovery_digest(
        "pajin.agentic.specialist-job-claim-subject/v1",
        material,
    )


def specialist_authority_lineage_digest(values: Mapping[str, object]) -> str:
    """Bind the complete serialized authorization lineage without granting authority."""

    aliases = (
        "planId",
        "planDigest",
        "planStateDigest",
        "reservationId",
        "reservationDigest",
        "reservationStateDigest",
        "commandId",
        "commandDigest",
        "preparationId",
        "preparationDigest",
        "profileRegistryDigest",
        "profileId",
        "profileVersion",
        "profileDigest",
        "executorCatalogDigest",
        "executorId",
        "executorVersion",
        "executorDigest",
        "activationSetDigest",
        "releaseId",
        "releaseDigest",
        "capabilityId",
        "capabilityVersion",
        "capabilityDefinitionDigest",
        "capabilityDigest",
        "capabilityAuthoritySetId",
        "capabilityAuthoritySetDigest",
        "toolId",
        "toolVersion",
        "toolDigest",
        "preparedActionDigest",
        "requestId",
        "requestDigest",
        "capabilityGrantId",
        "capabilityGrantDigest",
        "grantLineageStateDigest",
        "capabilityGrantExpiresAt",
        "grantConsumptionReceiptId",
        "grantConsumptionReceiptDigest",
        "actionPermitId",
        "actionPermitDigest",
        "actionPermitExpiresAt",
        "approvalId",
        "approvalDigest",
        "approvalExpiresAt",
        "approvalConsumptionReceiptId",
        "approvalConsumptionReceiptDigest",
        "dispatchId",
        "targetId",
        "targetDigest",
    )
    material = _required_alias_material(values, aliases)
    return discovery_digest(
        "pajin.agentic.specialist-authority-lineage/v1",
        material,
    )


def specialist_runtime_inventory_digest(values: Mapping[str, object]) -> str:
    """Bind the executable authority set and exact backend deployment inventory."""

    aliases = (
        "runtimeCapsuleTokenDigest",
        "capabilityAuthoritySetId",
        "capabilityAuthoritySetDigest",
        "executionInventoryId",
        "executionInventoryDigest",
        "gatewayId",
        "gatewayVersion",
        "gatewayDigest",
        "workerBackendId",
        "workerBackendVersion",
        "workerBackendDigest",
        "workerJobId",
        "workerJobDigest",
        "workerCommandDigest",
        "workerCompilerId",
        "workerCompilerVersion",
        "workerCompilerDigest",
        "workerImageReference",
        "workerImageDigest",
        "workerVerifierId",
        "workerVerifierVersion",
        "workerVerifierDigest",
        "workerVerificationKeyId",
        "workerVerificationKeyDigest",
    )
    material = _required_alias_material(values, aliases)
    return discovery_digest(
        "pajin.agentic.specialist-runtime-inventory/v1",
        material,
    )


def build_specialist_claim_verification(
    values: Mapping[str, object],
) -> AgenticSpecialistClaimVerification:
    """Build canonical detached evidence from one complete claimed-attempt subject."""

    def required(alias: str) -> object:
        return _required_alias_material(values, (alias,))[alias]

    return AgenticSpecialistClaimVerification.model_validate(
        {
            "subjectDigest": specialist_job_claim_subject_digest(values),
            "storeId": required("storeId"),
            "coordinationBindingDigest": required("coordinationBindingDigest"),
            "databaseIdentityDigest": required("databaseIdentityDigest"),
            "deploymentDigest": required("deploymentDigest"),
            "controlPlaneRunId": required("controlPlaneRunId"),
            "planId": required("planId"),
            "planDigest": required("planDigest"),
            "planStateDigest": required("planStateDigest"),
            "graphSnapshotId": required("graphSnapshotId"),
            "graphSnapshotDigest": required("graphSnapshotDigest"),
            "schedulerTaskName": required("schedulerTaskName"),
            "schedulerTaskTokenDigest": required("schedulerTaskTokenDigest"),
            "runtimeCapsuleTokenDigest": required("runtimeCapsuleTokenDigest"),
            "dispatchBindingId": required("dispatchBindingId"),
            "dispatchBindingDigest": required("dispatchBindingDigest"),
            "authorityLineageDigest": specialist_authority_lineage_digest(values),
            "runtimeInventoryDigest": specialist_runtime_inventory_digest(values),
            "verifiedAt": required("claimedAt"),
        }
    )


def build_specialist_dispatch_verification(
    attempt: AgenticSpecialistJobAttempt,
    *,
    verified_at: datetime,
    backend_handoff_deadline: datetime,
) -> AgenticSpecialistDispatchVerification:
    """Derive fresh pre-handoff evidence from one exact claimed attempt."""

    if (
        type(attempt) is not AgenticSpecialistJobAttempt
        or attempt.state is not AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
    ):
        raise ValueError("dispatch verification requires an exact claimed job attempt")
    values = attempt.model_dump(mode="json", by_alias=True)
    return AgenticSpecialistDispatchVerification.model_validate(
        {
            "storeId": attempt.store_id,
            "coordinationBindingDigest": attempt.coordination_binding_digest,
            "databaseIdentityDigest": attempt.database_identity_digest,
            "deploymentDigest": attempt.deployment_digest,
            "claimVerificationId": attempt.claim_verification.verification_id,
            "claimVerificationDigest": attempt.claim_verification.verification_digest,
            "attemptId": attempt.attempt_id,
            "attemptDigest": attempt.attempt_digest,
            "claimedStateDigest": attempt.state_digest,
            "graphSnapshotId": attempt.graph_snapshot_id,
            "graphSnapshotDigest": attempt.graph_snapshot_digest,
            "schedulerTaskName": attempt.scheduler_task_name,
            "schedulerTaskTokenDigest": attempt.scheduler_task_token_digest,
            "runtimeCapsuleTokenDigest": attempt.runtime_capsule_token_digest,
            "dispatchBindingId": attempt.dispatch_binding_id,
            "dispatchBindingDigest": attempt.dispatch_binding_digest,
            "authorityLineageDigest": specialist_authority_lineage_digest(values),
            "runtimeInventoryDigest": specialist_runtime_inventory_digest(values),
            "backendHandoffDeadline": _format_timestamp(backend_handoff_deadline),
            "verifiedAt": _format_timestamp(verified_at),
        }
    )


def _required_alias_material(
    values: Mapping[str, object],
    aliases: tuple[str, ...],
) -> dict[str, object]:
    material: dict[str, object] = {}
    field_names_by_alias = {
        (field.alias or name): name
        for name, field in AgenticSpecialistJobAttempt.model_fields.items()
    }
    for alias in aliases:
        field_name = field_names_by_alias.get(alias)
        if alias in values:
            value = values[alias]
        elif field_name is not None and field_name in values:
            value = values[field_name]
        else:
            raise ValueError(f"specialist verification material lacks {alias}")
        material[alias] = _wire_value(value)
    return material


def _require_claim_verification_matches_attempt(
    attempt: AgenticSpecialistJobAttempt,
    *,
    subject_digest: str,
) -> None:
    verification = attempt.claim_verification
    values = attempt.model_dump(mode="json", by_alias=True)
    if (
        verification.subject_digest != subject_digest
        or verification.store_id != attempt.store_id
        or verification.coordination_binding_digest != attempt.coordination_binding_digest
        or verification.database_identity_digest != attempt.database_identity_digest
        or verification.deployment_digest != attempt.deployment_digest
        or verification.control_plane_run_id != attempt.control_plane_run_id
        or verification.plan_id != attempt.plan_id
        or verification.plan_digest != attempt.plan_digest
        or verification.plan_state_digest != attempt.plan_state_digest
        or verification.graph_snapshot_id != attempt.graph_snapshot_id
        or verification.graph_snapshot_digest != attempt.graph_snapshot_digest
        or verification.scheduler_task_name != attempt.scheduler_task_name
        or verification.scheduler_task_token_digest != attempt.scheduler_task_token_digest
        or verification.runtime_capsule_token_digest != attempt.runtime_capsule_token_digest
        or verification.dispatch_binding_id != attempt.dispatch_binding_id
        or verification.dispatch_binding_digest != attempt.dispatch_binding_digest
        or verification.authority_lineage_digest != specialist_authority_lineage_digest(values)
        or verification.runtime_inventory_digest != specialist_runtime_inventory_digest(values)
        or verification.verified_at != attempt.claimed_at
    ):
        raise ValueError("specialist claim verification differs from job-attempt subject")


def _require_dispatch_verification_matches_attempt(
    attempt: AgenticSpecialistJobAttempt,
    *,
    attempt_digest: str,
    claimed_state_digest: str,
) -> None:
    verification = attempt.dispatch_verification
    assert verification is not None
    values = attempt.model_dump(mode="json", by_alias=True)
    if (
        verification.store_id != attempt.store_id
        or verification.coordination_binding_digest != attempt.coordination_binding_digest
        or verification.database_identity_digest != attempt.database_identity_digest
        or verification.deployment_digest != attempt.deployment_digest
        or verification.claim_verification_id != attempt.claim_verification.verification_id
        or verification.claim_verification_digest != attempt.claim_verification.verification_digest
        or verification.attempt_id != f"agentic-specialist-job-attempt_{attempt_digest}"
        or verification.attempt_digest != attempt_digest
        or verification.claimed_state_digest != claimed_state_digest
        or verification.graph_snapshot_id != attempt.graph_snapshot_id
        or verification.graph_snapshot_digest != attempt.graph_snapshot_digest
        or verification.scheduler_task_name != attempt.scheduler_task_name
        or verification.scheduler_task_token_digest != attempt.scheduler_task_token_digest
        or verification.runtime_capsule_token_digest != attempt.runtime_capsule_token_digest
        or verification.dispatch_binding_id != attempt.dispatch_binding_id
        or verification.dispatch_binding_digest != attempt.dispatch_binding_digest
        or verification.authority_lineage_digest != specialist_authority_lineage_digest(values)
        or verification.runtime_inventory_digest != specialist_runtime_inventory_digest(values)
        or verification.verified_at != attempt.backend_dispatch_started_at
        or verification.backend_handoff_deadline
        != min(
            attempt.capability_grant_expires_at,
            attempt.action_permit_expires_at,
            attempt.approval_expires_at,
        )
    ):
        raise ValueError("specialist dispatch verification differs from job attempt")


def _specialist_job_attempt_state_digest(
    *,
    attempt_digest: str,
    state: AgenticSpecialistJobAttemptState,
    dispatch_verification_digest: str | None,
    dispatch_event_digest: str | None,
    backend_dispatch_started_at: datetime | None,
) -> str:
    return discovery_digest(
        "pajin.agentic.specialist-job-attempt-state/v1",
        {
            "attemptDigest": attempt_digest,
            "state": state.value,
            "dispatchVerificationDigest": dispatch_verification_digest,
            "dispatchEventDigest": dispatch_event_digest,
            "backendDispatchStartedAt": (
                _format_timestamp(backend_dispatch_started_at)
                if backend_dispatch_started_at is not None
                else None
            ),
        },
    )


class AgenticSpecialistTerminalReceipt(AgenticStrictModel):
    """Append-only final classification for one non-repeatable job attempt."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-specialist-terminal-receipt/v1alpha1"] = Field(
        default=AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticSpecialistTerminalReceipt"] = "AgenticSpecialistTerminalReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=120)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    store_id: str = Field(alias="storeId", pattern=r"^agentic-store:[a-f0-9]{32}$")
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    attempt_id: str = Field(
        alias="attemptId",
        pattern=r"^agentic-specialist-job-attempt_[a-f0-9]{64}$",
    )
    attempt_digest: Sha256 = Field(alias="attemptDigest")
    attempt_state: AgenticSpecialistJobAttemptState = Field(alias="attemptState")
    attempt_state_digest: Sha256 = Field(alias="attemptStateDigest")
    plan_id: str = Field(
        alias="planId",
        pattern=r"^agentic-specialist-plan_[a-f0-9]{64}$",
    )
    request_id: str = Field(alias="requestId", min_length=1, max_length=200)
    worker_job_id: Identifier = Field(alias="workerJobId")
    terminal_kind: AgenticSpecialistTerminalKind = Field(alias="terminalKind")
    terminal_reason_digest: Sha256 = Field(alias="terminalReasonDigest")
    target_io_state: AgenticSpecialistTargetIOState = Field(alias="targetIoState")
    succeeded: bool | None = None
    backend_terminal_proven: bool = Field(alias="backendTerminalProven")
    worker_result_digest: Sha256 | None = Field(default=None, alias="workerResultDigest")
    backend_terminal_proof_digest: Sha256 | None = Field(
        default=None,
        alias="backendTerminalProofDigest",
    )
    backend_finished_at: datetime | None = Field(default=None, alias="backendFinishedAt")
    recorded_at: datetime = Field(alias="recordedAt")
    automatic_redispatch_authorized: Literal[False] = Field(
        default=False,
        alias="automaticRedispatchAuthorized",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")
    report_authority: Literal[False] = Field(default=False, alias="reportAuthority")
    poc_authority: Literal[False] = Field(default=False, alias="pocAuthority")

    @field_validator("backend_finished_at", "recorded_at")
    @classmethod
    def require_utc_times(cls, value: datetime | None) -> datetime | None:
        return _utc(value, label="specialist terminal-receipt timestamp") if value else None

    @field_validator("succeeded", mode="before")
    @classmethod
    def require_optional_exact_bool(cls, value: object) -> object:
        if value is None or isinstance(value, bool):
            return value
        raise ValueError("succeeded must be an exact boolean or null")

    @field_validator("backend_terminal_proven", mode="before")
    @classmethod
    def require_exact_bool(cls, value: object) -> object:
        if isinstance(value, bool):
            return value
        raise ValueError("backendTerminalProven must be an exact boolean")

    @field_validator(
        "automatic_redispatch_authorized",
        "execution_authority",
        "finding_authority",
        "graph_authority",
        "report_authority",
        "poc_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: object) -> object:
        return _literal_false(value, label=cast(str, getattr(info, "field_name", "marker")))

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        _validate_terminal_shape(self)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-terminal-receipt/v1",
            material,
        )
        expected_id = f"agentic-specialist-terminal_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("specialist terminal receipt Digest differs")
        if self.receipt_id and self.receipt_id != expected_id:
            raise ValueError("specialist terminal receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist terminal receipt",
            max_bytes=_MAX_RECEIPT_BYTES,
        )
        return self


def _validate_terminal_shape(receipt: AgenticSpecialistTerminalReceipt) -> None:
    kind = receipt.terminal_kind
    has_terminal_material = (
        receipt.worker_result_digest is not None
        and receipt.backend_terminal_proof_digest is not None
        and receipt.backend_finished_at is not None
    )
    if (
        receipt.backend_finished_at is not None
        and receipt.backend_finished_at > receipt.recorded_at
    ):
        raise ValueError("specialist terminal receipt predates backend completion")
    if kind is AgenticSpecialistTerminalKind.ABANDONED_BEFORE_BACKEND:
        if (
            receipt.attempt_state is not AgenticSpecialistJobAttemptState.CLAIMED_BEFORE_BACKEND
            or receipt.target_io_state is not AgenticSpecialistTargetIOState.NOT_STARTED
            or receipt.succeeded is not False
            or receipt.backend_terminal_proven
            or has_terminal_material
            or any(
                value is not None
                for value in (
                    receipt.worker_result_digest,
                    receipt.backend_terminal_proof_digest,
                    receipt.backend_finished_at,
                )
            )
        ):
            raise ValueError("abandoned specialist receipt evidence differs")
        return
    if (
        receipt.attempt_state
        is not AgenticSpecialistJobAttemptState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    ):
        raise ValueError("post-dispatch specialist receipt lacks the dispatch marker")
    if kind is AgenticSpecialistTerminalKind.STARTED_OUTCOME_UNKNOWN:
        if (
            receipt.target_io_state is not AgenticSpecialistTargetIOState.UNKNOWN
            or receipt.succeeded is not None
            or receipt.backend_terminal_proven
            or any(
                value is not None
                for value in (
                    receipt.worker_result_digest,
                    receipt.backend_terminal_proof_digest,
                    receipt.backend_finished_at,
                )
            )
        ):
            raise ValueError("outcome-unknown specialist receipt evidence differs")
        return
    if not receipt.backend_terminal_proven or not has_terminal_material:
        raise ValueError("terminal specialist receipt lacks backend proof")
    if kind is AgenticSpecialistTerminalKind.FAILED_BEFORE_TARGET_IO:
        if (
            receipt.target_io_state is not AgenticSpecialistTargetIOState.NOT_STARTED
            or receipt.succeeded is not False
        ):
            raise ValueError("pre-target-I/O failure receipt evidence differs")
        return
    if receipt.target_io_state is not AgenticSpecialistTargetIOState.PERFORMED:
        raise ValueError("post-target-I/O receipt evidence differs")
    expected_success = kind is AgenticSpecialistTerminalKind.COMPLETED_VERIFIED
    if receipt.succeeded is not expected_success:
        raise ValueError("specialist terminal success marker differs")


__all__ = [
    "AGENTIC_SPECIALIST_JOB_ATTEMPT_API_VERSION",
    "AGENTIC_SPECIALIST_TERMINAL_RECEIPT_API_VERSION",
    "AgenticSpecialistJobAttempt",
    "AgenticSpecialistJobAttemptState",
    "AgenticSpecialistTargetIOState",
    "AgenticSpecialistTerminalKind",
    "AgenticSpecialistTerminalReceipt",
]
