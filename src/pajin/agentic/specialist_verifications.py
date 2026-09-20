"""Canonical, non-authorizing verification records for specialist dispatch.

The records in this module are detached audit evidence.  They never recreate a
scheduler task, a runtime capsule, a Permit, Gateway authority, or backend
authority.  Their digest order is deliberately acyclic:

``claim subject -> claim verification -> attempt -> dispatch verification``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.agentic.models import AgenticStrictModel, Identifier, Sha256, _literal_false
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest

AGENTIC_SPECIALIST_CLAIM_VERIFICATION_API_VERSION: Literal[
    "pajin.dev/agentic-specialist-claim-verification/v1alpha1"
] = "pajin.dev/agentic-specialist-claim-verification/v1alpha1"
AGENTIC_SPECIALIST_DISPATCH_VERIFICATION_API_VERSION: Literal[
    "pajin.dev/agentic-specialist-dispatch-verification/v1alpha1"
] = "pajin.dev/agentic-specialist-dispatch-verification/v1alpha1"

_MAX_VERIFICATION_BYTES = 256 * 1024


def _utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError(f"{label} must be timezone-aware")
    normalized = value.astimezone(UTC)
    offset = normalized.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError(f"{label} must normalize to UTC")
    return normalized


class AgenticSpecialistClaimVerification(AgenticStrictModel):
    """Canonical verification of the immutable pre-attempt subject.

    ``subjectDigest`` is computed from the future JobAttempt identity material
    before either the claim-verification digest or attempt digest exists.  This
    record intentionally has no attempt identifier, avoiding a digest cycle.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-specialist-claim-verification/v1alpha1"] = Field(
        default=AGENTIC_SPECIALIST_CLAIM_VERIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticSpecialistClaimVerification"] = "AgenticSpecialistClaimVerification"
    verification_id: str = Field(default="", alias="verificationId", max_length=120)
    verification_digest: str = Field(
        default="",
        alias="verificationDigest",
        max_length=64,
    )
    subject_digest: Sha256 = Field(alias="subjectDigest")
    store_id: str = Field(alias="storeId", pattern=r"^agentic-store:[a-f0-9]{32}$")
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    database_identity_digest: Sha256 = Field(alias="databaseIdentityDigest")
    deployment_digest: Sha256 = Field(alias="deploymentDigest")
    control_plane_run_id: Identifier = Field(alias="controlPlaneRunId")
    plan_id: str = Field(
        alias="planId",
        pattern=r"^agentic-specialist-plan_[a-f0-9]{64}$",
    )
    plan_digest: Sha256 = Field(alias="planDigest")
    plan_state_digest: Sha256 = Field(alias="planStateDigest")
    graph_snapshot_id: Identifier = Field(alias="graphSnapshotId")
    graph_snapshot_digest: Sha256 = Field(alias="graphSnapshotDigest")
    scheduler_task_name: Identifier = Field(alias="schedulerTaskName")
    scheduler_task_token_digest: Sha256 = Field(alias="schedulerTaskTokenDigest")
    runtime_capsule_token_digest: Sha256 = Field(alias="runtimeCapsuleTokenDigest")
    dispatch_binding_id: str = Field(
        alias="dispatchBindingId",
        pattern=r"^agentic-specialist-dispatch-binding_[a-f0-9]{64}$",
    )
    dispatch_binding_digest: Sha256 = Field(alias="dispatchBindingDigest")
    authority_lineage_digest: Sha256 = Field(alias="authorityLineageDigest")
    runtime_inventory_digest: Sha256 = Field(alias="runtimeInventoryDigest")
    verified_at: datetime = Field(alias="verifiedAt")
    target_io_state: Literal["not-started"] = Field(
        default="not-started",
        alias="targetIoState",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")
    report_authority: Literal[False] = Field(default=False, alias="reportAuthority")
    poc_authority: Literal[False] = Field(default=False, alias="pocAuthority")

    @field_validator("verified_at")
    @classmethod
    def require_utc_time(cls, value: datetime) -> datetime:
        return _utc(value, label="specialist claim verification timestamp")

    @field_validator(
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
    def bind_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"verification_id", "verification_digest"},
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-claim-verification/v1",
            material,
        )
        expected_id = f"agentic-specialist-claim-verification_{digest}"
        if self.verification_digest and self.verification_digest != digest:
            raise ValueError("specialist claim-verification Digest differs")
        if self.verification_id and self.verification_id != expected_id:
            raise ValueError("specialist claim-verification ID differs")
        object.__setattr__(self, "verification_digest", digest)
        object.__setattr__(self, "verification_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist claim verification",
            max_bytes=_MAX_VERIFICATION_BYTES,
        )
        return self


class AgenticSpecialistDispatchVerification(AgenticStrictModel):
    """Fresh pre-handoff verification bound to one immutable attempt.

    The record binds only the already-existing attempt and claimed state.  It
    never includes the later dispatch event or started-state digest.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/agentic-specialist-dispatch-verification/v1alpha1"] = Field(
        default=AGENTIC_SPECIALIST_DISPATCH_VERIFICATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticSpecialistDispatchVerification"] = "AgenticSpecialistDispatchVerification"
    verification_id: str = Field(default="", alias="verificationId", max_length=120)
    verification_digest: str = Field(
        default="",
        alias="verificationDigest",
        max_length=64,
    )
    store_id: str = Field(alias="storeId", pattern=r"^agentic-store:[a-f0-9]{32}$")
    coordination_binding_digest: Sha256 = Field(alias="coordinationBindingDigest")
    database_identity_digest: Sha256 = Field(alias="databaseIdentityDigest")
    deployment_digest: Sha256 = Field(alias="deploymentDigest")
    claim_verification_id: str = Field(
        alias="claimVerificationId",
        pattern=r"^agentic-specialist-claim-verification_[a-f0-9]{64}$",
    )
    claim_verification_digest: Sha256 = Field(alias="claimVerificationDigest")
    attempt_id: str = Field(
        alias="attemptId",
        pattern=r"^agentic-specialist-job-attempt_[a-f0-9]{64}$",
    )
    attempt_digest: Sha256 = Field(alias="attemptDigest")
    claimed_state_digest: Sha256 = Field(alias="claimedStateDigest")
    graph_snapshot_id: Identifier = Field(alias="graphSnapshotId")
    graph_snapshot_digest: Sha256 = Field(alias="graphSnapshotDigest")
    scheduler_task_name: Identifier = Field(alias="schedulerTaskName")
    scheduler_task_token_digest: Sha256 = Field(alias="schedulerTaskTokenDigest")
    runtime_capsule_token_digest: Sha256 = Field(alias="runtimeCapsuleTokenDigest")
    dispatch_binding_id: str = Field(
        alias="dispatchBindingId",
        pattern=r"^agentic-specialist-dispatch-binding_[a-f0-9]{64}$",
    )
    dispatch_binding_digest: Sha256 = Field(alias="dispatchBindingDigest")
    authority_lineage_digest: Sha256 = Field(alias="authorityLineageDigest")
    runtime_inventory_digest: Sha256 = Field(alias="runtimeInventoryDigest")
    idempotency_key: str = Field(
        default="",
        alias="idempotencyKey",
        max_length=96,
    )
    backend_handoff_deadline: datetime = Field(alias="backendHandoffDeadline")
    verified_at: datetime = Field(alias="verifiedAt")
    target_io_state: Literal["not-started"] = Field(
        default="not-started",
        alias="targetIoState",
    )
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    graph_authority: Literal[False] = Field(default=False, alias="graphAuthority")
    report_authority: Literal[False] = Field(default=False, alias="reportAuthority")
    poc_authority: Literal[False] = Field(default=False, alias="pocAuthority")

    @field_validator("backend_handoff_deadline", "verified_at")
    @classmethod
    def require_utc_times(cls, value: datetime) -> datetime:
        return _utc(value, label="specialist dispatch verification timestamp")

    @field_validator(
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
    def bind_identity(self) -> Self:
        if not self.verified_at < self.backend_handoff_deadline:
            raise ValueError("specialist dispatch verification deadline is not fresh")
        expected_key_digest = discovery_digest(
            "pajin.agentic.specialist-backend-idempotency-key/v1",
            {
                "attemptDigest": self.attempt_digest,
                "runtimeInventoryDigest": self.runtime_inventory_digest,
            },
        )
        expected_key = f"specialist-job:{expected_key_digest}"
        if self.idempotency_key and self.idempotency_key != expected_key:
            raise ValueError("specialist backend idempotency key differs")
        object.__setattr__(self, "idempotency_key", expected_key)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"verification_id", "verification_digest"},
        )
        digest = discovery_digest(
            "pajin.agentic.specialist-dispatch-verification/v1",
            material,
        )
        expected_id = f"agentic-specialist-dispatch-verification_{digest}"
        if self.verification_digest and self.verification_digest != digest:
            raise ValueError("specialist dispatch-verification Digest differs")
        if self.verification_id and self.verification_id != expected_id:
            raise ValueError("specialist dispatch-verification ID differs")
        object.__setattr__(self, "verification_digest", digest)
        object.__setattr__(self, "verification_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist dispatch verification",
            max_bytes=_MAX_VERIFICATION_BYTES,
        )
        return self
